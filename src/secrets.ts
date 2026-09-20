/**
 * What a secret written into a string looks like.
 *
 * Two kinds of evidence, in order of how much they can be trusted. A value in
 * a known format — an OpenAI key, a GitHub token, an AWS access key id — is a
 * secret wherever it appears: in the middle of a Code node, and inside an n8n
 * expression too, because a key pasted between `{{ }}` is still a key. A value
 * under a name like `password` or `apiKey` — a field, a header, a query
 * parameter — is one only if it is a literal: a placeholder, an empty string
 * or an expression that reads the value from somewhere else is exactly what a
 * well-built workflow should contain.
 *
 * n8n expressions deserve a note. `={{ $credentials.token }}` is a reference
 * and its name never makes it a finding; the literal text around the `{{ }}`
 * blocks is still read, and an expression with no `{{ }}` at all (`=hunter2`)
 * is just a literal typed in expression mode.
 */

export type SecretKind =
  | "privateKey"
  | "anthropic"
  | "openai"
  | "github"
  | "slack"
  | "slackWebhook"
  | "discordWebhook"
  | "aws"
  | "google"
  | "stripe"
  | "telegram"
  | "jwt"
  | "urlPassword"
  | "authHeader"
  | "cookie"
  | "named";

export interface SecretHit {
  kind: SecretKind;
  /** The secret's range inside the scanned string. */
  start: number;
  end: number;
  /** What a report shows instead of the value. */
  masked: string;
}

interface Pattern {
  kind: SecretKind;
  re: RegExp;
  /** Capture group holding the secret; the whole match when absent. */
  group?: number;
  /** Capture group holding the name the secret sits under, for the patterns that judge by it. */
  name?: number;
  /** Characters that must not touch the match on the left / right. */
  left?: RegExp;
  right?: RegExp;
  check?: (secret: string, name: string) => boolean;
}

const ALNUM = /[A-Za-z0-9]/;
const TOKEN_CHAR = /[A-Za-z0-9_-]/;

/**
 * Vendor formats: specific enough to trust anywhere, expressions included.
 * Most specific first — an overlapping later match is dropped.
 */
const FORMATS: Pattern[] = [
  {
    kind: "privateKey",
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*-----|$)/g,
  },
  { kind: "anthropic", re: /sk-ant-[A-Za-z0-9_-]{20,}/g, left: ALNUM },
  {
    kind: "openai",
    re: /sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g,
    left: ALNUM,
    check: (key) => !key.startsWith("sk-ant-") && looksRandom(key.slice(3)),
  },
  { kind: "github", re: /(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g, left: ALNUM },
  { kind: "slack", re: /xox[abprs]-[A-Za-z0-9-]{10,}/g, left: ALNUM },
  { kind: "slackWebhook", re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_\/-]{20,}/g },
  {
    kind: "discordWebhook",
    re: /https:\/\/(?:(?:ptb|canary)\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]{20,}/g,
  },
  { kind: "aws", re: /(?:AKIA|ASIA)[A-Z0-9]{16}/g, left: ALNUM, right: ALNUM },
  { kind: "google", re: /AIza[0-9A-Za-z_-]{35}/g, left: ALNUM, right: TOKEN_CHAR },
  { kind: "stripe", re: /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, left: ALNUM },
  // `bot123456789:AA…` in an API URL: letters may touch it on the left, digits may not.
  { kind: "telegram", re: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/g, left: /[0-9]/, right: TOKEN_CHAR },
  // The lookbehind keeps a long base64 run from being tried at every "eyJ" inside it.
  { kind: "jwt", re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
];

/**
 * Secrets recognised by what surrounds them. Read only outside `{{ }}`, where
 * `Bearer {{ $json.token }}` or `?key={{ $env.KEY }}` is a reference.
 *
 * The patterns that start with a character class carry a lookbehind: without
 * it a long run of letters and digits — a hex blob in a Code node — would be
 * tried from every position in it, which is quadratic.
 */
const CONTEXTS: Pattern[] = [
  {
    kind: "urlPassword",
    // A `#` in the password is allowed: connection strings are rarely percent-encoded.
    re: /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:@\/?#"'<>]+:([^\s@\/?"'<>]+)@/g,
    group: 1,
    check: (password) => !isPlaceholder(password) && !password.startsWith("$"),
  },
  {
    kind: "authHeader",
    re: /\b(?:[Bb]earer|Token)\s+([A-Za-z0-9._~+\/-]{16,}=*)/g,
    group: 1,
    right: /[A-Za-z0-9._~+\/=-]/,
    check: (token) => !isPlaceholder(token) && (/[0-9]/.test(token) || token.length >= 32),
  },
  {
    kind: "authHeader",
    re: /\bBasic\s+([A-Za-z0-9+\/]{8,}={0,2})/g,
    group: 1,
    right: /[A-Za-z0-9+\/=]/,
    check: (encoded) => decodesToCredentials(encoded),
  },
  {
    // `?api_key=…&`, `&token=…` in a URL or a form body.
    kind: "named",
    re: /[?&;]([A-Za-z_][A-Za-z0-9_.[\]-]*)=([^&#\s"'`<>{}]+)/g,
    group: 2,
    name: 1,
    check: (value, name) => plausibleSecret(value, nameStrength(name)),
  },
  {
    // `apiKey: "…"`, `"password": "…"`, `const token = '…'` inside code or a JSON body.
    kind: "named",
    re: /(?<![A-Za-z0-9_$-])(["']?)([A-Za-z_][A-Za-z0-9_-]*)\1\s*[:=]\s*(["'`])([^"'`\s]+)\3/g,
    group: 4,
    name: 2,
    check: (value, name) => {
      const strength = nameStrength(name);
      return strength !== "weak" && plausibleSecret(value, strength);
    },
  },
  {
    // An unquoted value: a header line in a curl command (`X-Api-Key: 5f4d…`) or
    // `API_TOKEN=…` in a shell line. Unquoted, a value could as well be a
    // variable, so only something that reads as key material counts.
    kind: "named",
    re: /(?<![A-Za-z0-9_$.-])([A-Za-z_][A-Za-z0-9_-]*)[ \t]*[:=][ \t]*([A-Za-z0-9._~+\/-][A-Za-z0-9._~+\/=-]{11,})/g,
    group: 2,
    name: 1,
    right: /[(]/,
    check: (value, name) => {
      const strength = nameStrength(name);
      return (strength === "password" || strength === "secret") && keyMaterial(value) && plausibleSecret(value, strength);
    },
  },
];

/**
 * Finds the secrets in one string. `name` is the key the string sits under —
 * or, for n8n's `{ name, value }` pairs, the pair's name.
 */
export function scanString(value: string, name: string | null): SecretHit[] {
  const reference = value.includes("{{") && value.includes("}}");
  // References are blanked, not removed, so every offset still points into `value`.
  const hits = scanPatterns(value, FORMATS, []);
  scanPatterns(reference ? blankExpressions(value) : value, CONTEXTS, hits);
  hits.sort((a, b) => a.start - b.start);
  if (hits.length > 0 || reference || name === null) return hits;

  const literal = value.startsWith("=") ? 1 : 0;
  const body = value.slice(literal);
  const normalized = normalizeName(name);

  if (normalized === "authorization" || normalized === "proxyauthorization") {
    const scheme = /^(?:Bearer|Basic|Token|Bot|Digest|ApiKey)\s+/i.exec(body);
    const secret = scheme ? body.slice(scheme[0].length) : body;
    if (secret.length >= 6 && !isPlaceholder(secret) && !NOT_SECRETS.has(secret.toLowerCase()) && !/\s/.test(secret)) {
      const start = literal + (scheme ? scheme[0].length : 0);
      return [{ kind: "authHeader", start, end: value.length, masked: mask(secret) }];
    }
    return [];
  }

  // A session cookie is a login: whoever holds it is signed in.
  if (normalized === "cookie") {
    if (body.length >= 8 && !isPlaceholder(body) && !NOT_SECRETS.has(body.toLowerCase())) {
      return [{ kind: "cookie", start: literal, end: value.length, masked: mask(body) }];
    }
    return [];
  }

  const strength = nameStrength(name);
  if (strength !== null && plausibleSecret(body, strength)) {
    return [{ kind: "named", start: literal, end: value.length, masked: mask(body) }];
  }
  return [];
}

/** Adds the matches of `patterns` that do not overlap a hit already in `hits`. */
function scanPatterns(text: string, patterns: Pattern[], hits: SecretHit[]): SecretHit[] {
  for (const pattern of patterns) {
    pattern.re.lastIndex = 0;
    for (let match = pattern.re.exec(text); match !== null; match = pattern.re.exec(text)) {
      const group = pattern.group ?? 0;
      const secret = match[group]!;
      // Every grouped pattern ends with its secret (or with one delimiter after it).
      const start = match.index + (group === 0 ? 0 : match[0].lastIndexOf(secret));
      const end = start + secret.length;
      if (pattern.left && match.index > 0 && pattern.left.test(text[match.index - 1]!)) continue;
      if (pattern.right && end < text.length && pattern.right.test(text[end]!)) continue;
      if (pattern.check && !pattern.check(secret, pattern.name === undefined ? "" : match[pattern.name]!)) continue;
      if (hits.some((hit) => start < hit.end && end > hit.start)) continue;
      hits.push({
        kind: pattern.kind,
        start,
        end,
        masked: pattern.kind === "privateKey" ? maskPem(secret) : mask(secret),
      });
    }
  }
  return hits;
}

/** Replaces each hit with a placeholder that says what used to be there. */
export function redact(value: string, hits: readonly SecretHit[]): string {
  let out = value;
  for (const hit of [...hits].sort((a, b) => b.start - a.start)) {
    out = out.slice(0, hit.start) + placeholder(hit.kind) + out.slice(hit.end);
  }
  return out;
}

const PLACEHOLDER_NAMES: Record<SecretKind, string> = {
  privateKey: "private-key",
  anthropic: "anthropic-api-key",
  openai: "openai-api-key",
  github: "github-token",
  slack: "slack-token",
  slackWebhook: "slack-webhook-url",
  discordWebhook: "discord-webhook-url",
  aws: "aws-access-key-id",
  google: "google-api-key",
  stripe: "stripe-key",
  telegram: "telegram-bot-token",
  jwt: "jwt",
  urlPassword: "password",
  authHeader: "token",
  cookie: "cookie",
  named: "secret",
};

export function placeholder(kind: SecretKind): string {
  return `<redacted:${PLACEHOLDER_NAMES[kind]}>`;
}

/**
 * The first few characters and a fixed row of dots — enough to recognise which
 * key it is, never its length. A short value shows fewer characters: four of an
 * eight-letter password is half of it.
 */
export function mask(value: string): string {
  const shown = Math.min(4, Math.floor(value.length / 4));
  return `${value.slice(0, shown)}••••••••`;
}

/** A PEM block is recognised by its header, which is not secret; the body is. */
function maskPem(block: string): string {
  const header = /-----BEGIN [A-Z0-9 ]+-----/.exec(block);
  return `${header ? header[0] : "-----BEGIN"} ••••••••`;
}

/**
 * How strongly a name promises a secret. Judged by its last word, so
 * `clientSecret`, `access_token` and `X-Api-Key` count and `tokenizer`,
 * `token_type_hint`, `passwordRegex` and `secretName` do not. A `password`
 * may be short or have spaces in it; a bare `key` or `appid` holds a secret
 * only when the value looks like one.
 */
export type NameStrength = "password" | "secret" | "weak";

const PASSWORD_WORDS = new Set(["password", "passwd", "passphrase", "pwd", "pass", "sifre", "parola"]);
const SECRET_WORD = /(?:password|passwd|passphrase|secret|token|apikey|accesskey|secretkey|privatekey|authorization|bearer)$/;
/** `apiKey`, `secret_key`, `Ocp-Apim-Subscription-Key`: a key word that makes `key` mean a credential. */
const KEY_PREFIXES = new Set(["api", "access", "secret", "private", "subscription", "master", "auth", "signing", "encryption"]);
/** Tokens that are cursors, not credentials. */
const CURSOR_PREFIXES = new Set(["page", "next", "continuation", "sync", "cursor"]);
const WEAK_NAMES = new Set(["key", "appid", "appkey", "subscriptionkey", "ocpapimsubscriptionkey"]);

export function nameStrength(name: string): NameStrength | null {
  const words = splitWords(name);
  if (words.length > 1 && (words[words.length - 1] === "value" || words[words.length - 1] === "string")) words.pop();
  const last = words[words.length - 1];
  if (last === undefined) return null;
  const previous = words[words.length - 2];
  if (PASSWORD_WORDS.has(last) || /(?:password|passwd|passphrase)$/.test(last)) return "password";
  if (last === "key" && previous !== undefined && KEY_PREFIXES.has(previous)) return "secret";
  if (SECRET_WORD.test(last) && !(previous !== undefined && CURSOR_PREFIXES.has(previous))) return "secret";
  return WEAK_NAMES.has(words.join("")) ? "weak" : null;
}

/** Names that hold a secret — and not the look-alikes that hold its URL, type or length. */
export function isSecretName(name: string): boolean {
  const strength = nameStrength(name);
  return strength === "password" || strength === "secret";
}

/** `clientSecret` → client, secret; `X-API-KEY` → x, api, key; `dbŞifre` → db, sifre. */
function splitWords(name: string): string[] {
  return name
    .replace(/(\p{Ll}|\p{N})(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu}+)(\p{Lu}\p{Ll})/gu, "$1 $2")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .split(/[^\p{L}\p{N}]+/u)
    .filter((word) => word !== "");
}

/** Words that sit under a secret-sounding name without being a secret. */
const NOT_SECRETS = new Set([
  "true",
  "false",
  "null",
  "none",
  "undefined",
  "bearer",
  "basic",
  "string",
  "number",
  "boolean",
  "object",
  "password",
  "secret",
  "token",
  "header",
  "query",
  "body",
  "default",
  "required",
  "optional",
  "oauth2",
  "apikey",
  "api_key",
]);

function plausibleSecret(value: string, strength: NameStrength | null): boolean {
  if (strength === null || isPlaceholder(value) || NOT_SECRETS.has(value.toLowerCase())) return false;
  // A plain URL is where a secret goes, not the secret; one with credentials is caught above.
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)) return false;
  // A passphrase may have spaces; a paragraph under a password-ish name is prose.
  if (strength === "password") return value.length >= 4 && !/[\r\n]/.test(value) && (!/\s/.test(value) || value.length <= 64);
  if (/\s/.test(value)) return false;
  if (strength === "weak") return value.length >= 16 && /^[A-Za-z0-9_-]+$/.test(value) && looksRandom(value);
  return value.length >= 6;
}

/**
 * Values that stand in for a secret: `<token>`, `[API_KEY]`, `${SECRET}`,
 * `$OPENAI_KEY`, `YOUR_API_KEY`, `xxxxxxxx`, `****`, and this tool's own
 * `<redacted:…>` — so a sanitised copy checks clean.
 */
export function isPlaceholder(value: string): boolean {
  if (/^(?:<[^<>]*>|\[[^[\]]*\]|\{[^{}]*\}|\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$/.test(value)) {
    return true;
  }
  if (/^(?:x+|X+|\*+|•+|\.+|-+|_+|0+)$/.test(value)) return true;
  return /^(?:your|my|insert|enter|replace|put)[\s_-]|redacted|placeholder|changeme|change_me/i.test(value);
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Random key material: letters and digits mixed, which prose and slugs rarely are. */
function looksRandom(body: string): boolean {
  return /[0-9]/.test(body) && /[A-Za-z]/.test(body);
}

/**
 * Stricter, for values without quotes: several digits and several letters, and
 * not the shape of a reference — `process.env.API_KEY`, `API_KEY_2024`.
 */
function keyMaterial(value: string): boolean {
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value) || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) return false;
  return (value.match(/[0-9]/g)?.length ?? 0) >= 3 && (value.match(/[A-Za-z]/g)?.length ?? 0) >= 3;
}

/** `Basic dXNlcjpwYXNz` is a credential only if it decodes to `user:pass`. */
function decodesToCredentials(encoded: string): boolean {
  try {
    const decoded = atob(encoded);
    const colon = decoded.indexOf(":");
    return colon > 0 && colon < decoded.length - 1 && !/[\x00-\x1f\x7f]/.test(decoded);
  } catch {
    return false;
  }
}

/** `={{ $json.x }}` → `=` and the braces' contents become spaces; literal text stays. */
function blankExpressions(value: string): string {
  const blanked = value.replace(/\{\{[\s\S]*?\}\}/g, (block) => " ".repeat(block.length));
  return blanked.startsWith("=") ? ` ${blanked.slice(1)}` : blanked;
}
