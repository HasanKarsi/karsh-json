/**
 * Turns the near-JSON people actually paste into JSON: what a JavaScript
 * object literal, a JSON5 config, a Python dict printout or a chat message
 * does differently.
 *
 * Every fix here is one whose intent is unambiguous — a comma before a closing
 * bracket, a comment, a key without quotes, a quote style. Nothing is guessed:
 * a string whose closing quote cannot be found cleanly is left exactly as it
 * was, so the parser can point at it. Valid JSON passes through byte for byte
 * (fuzzed), which is what makes it safe to offer the button at all.
 */

export type RepairFix =
  | "trailingComma"
  | "comment"
  | "quote"
  | "unquotedKey"
  | "literal"
  | "invisible"
  | "controlChar";

export interface RepairResult {
  text: string;
  changed: boolean;
  fixes: Record<RepairFix, number>;
}

/** Words that mean a JSON literal in some other language, looked up in lower case: True, NULL, nil, NaN. */
const LITERALS: Record<string, string> = {
  true: "true",
  false: "false",
  null: "null",
  none: "null",
  nil: "null",
  undefined: "null",
  nan: "null",
  infinity: "null",
};

const INVISIBLE = new Set([
  0x00a0, 0x1680, 0x180e, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x200b, 0x200c, 0x200d, 0x2028, 0x2029, 0x202f, 0x205f, 0x2060, 0x3000, 0xfeff,
]);

/**
 * Opening quote → the characters that may close it, most likely first. A
 * curly string closes on a curly quote when it can — “say "hi"” keeps its
 * straight quotes as content — and on a straight one only when it cannot.
 */
const QUOTES: Record<string, string[]> = {
  "'": ["'"],
  "“": ["”“", '"'],
  "”": ["”“", '"'],
  "„": ["”“", '"'],
  "‘": ["’‘", "'"],
  "’": ["’‘", "'"],
  "‚": ["’‘", "'"],
};

export function repairJson(input: string): RepairResult {
  const fixes: Record<RepairFix, number> = {
    trailingComma: 0,
    comment: 0,
    quote: 0,
    unquotedKey: 0,
    literal: 0,
    invisible: 0,
    controlChar: 0,
  };
  const text = removeTrailingCommas(rewrite(input, fixes), fixes);
  return { text, changed: text !== input, fixes };
}

/** Everything but trailing commas, in one pass that knows where strings are. */
function rewrite(text: string, fixes: Record<RepairFix, number>): string {
  const n = text.length;
  const out: string[] = [];
  /** The last structural character written outside a string; "v" after any value. */
  let last = "";
  let i = 0;

  while (i < n) {
    const char = text[i]!;
    const code = text.charCodeAt(i);

    if (char === '"') {
      const end = findClose(text, i, '"');
      if (end === -1) {
        out.push(text.slice(i));
        break;
      }
      const body = text.slice(i + 1, end);
      if (hasControl(body) && closesCleanly(text, end + 1)) {
        out.push(`"${escapeControls(body, fixes)}"`);
      } else {
        out.push(text.slice(i, end + 1));
      }
      last = "v";
      i = end + 1;
      continue;
    }

    if (QUOTES[char] !== undefined) {
      const end = QUOTES[char]
        .map((closers) => findClose(text, i, closers))
        .find((at) => at !== -1 && closesCleanly(text, at + 1));
      if (end !== undefined) {
        out.push(`"${requote(text.slice(i + 1, end), fixes)}"`);
        fixes.quote += 1;
        last = "v";
        i = end + 1;
        continue;
      }
    }

    if (char === "/" && text[i + 1] === "/") {
      while (i < n && text[i] !== "\n" && text[i] !== "\r") i += 1;
      fixes.comment += 1;
      continue;
    }
    if (char === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
      // A space, so `1/* x */2` does not become 12.
      out.push(" ");
      fixes.comment += 1;
      continue;
    }

    if (INVISIBLE.has(code)) {
      if (!(code === 0xfeff && i === 0)) out.push(" ");
      fixes.invisible += 1;
      i += 1;
      continue;
    }

    const keyPosition = last === "{" || last === ",";
    const wordStart = isWordStart(text.codePointAt(i)!);
    if (wordStart || (keyPosition && isDigit(code))) {
      // A key may be anything up to its colon that holds no JSON punctuation:
      // şehir, content-type, a.b, 1st. In a value only a plain word is a word.
      if (keyPosition) {
        const keyEnd = wordEnd(text, i, true);
        if (text[skipSpaceAndComments(text, keyEnd)] === ":") {
          out.push(`"${text.slice(i, keyEnd)}"`);
          fixes.unquotedKey += 1;
          last = "v";
          i = keyEnd;
          continue;
        }
      }
      let end = wordStart ? wordEnd(text, i, false) : i + 1;
      if (!wordStart) while (end < n && isDigit(text.charCodeAt(end))) end += 1;
      const word = text.slice(i, end);
      const literal = wordStart ? LITERALS[word.toLowerCase()] : undefined;
      // `true` maps to itself: valid JSON must come out untouched and uncounted.
      if (literal !== undefined && literal !== word && (last === "" || last === "[" || last === "," || last === ":")) {
        out.push(literal);
        fixes.literal += 1;
      } else {
        out.push(word);
      }
      last = "v";
      i = end;
      continue;
    }

    if (char === "-" && text.startsWith("Infinity", i + 1) && !isWordPart(text.codePointAt(i + 9) ?? 0)) {
      out.push("null");
      fixes.literal += 1;
      last = "v";
      i += 9;
      continue;
    }

    out.push(char);
    if (char === "{" || char === "[" || char === "," || char === ":") last = char;
    else if (char !== " " && char !== "\t" && char !== "\n" && char !== "\r") last = "v";
    i += 1;
  }

  return out.join("");
}

/** Drops every comma that only whitespace (or other commas) separates from a closing bracket. */
function removeTrailingCommas(text: string, fixes: Record<RepairFix, number>): string {
  const out: string[] = [];
  let from = 0;
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!;
    if (inString) {
      if (char === "\\") i += 1;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
    } else if (char === ",") {
      let j = i + 1;
      while (j < text.length && " \t\r\n,".includes(text[j]!)) j += 1;
      if (text[j] === "}" || text[j] === "]") {
        out.push(text.slice(from, i));
        from = i + 1;
        fixes.trailingComma += 1;
      }
    }
  }
  out.push(text.slice(from));
  return out.join("");
}

/** Index of the quote that closes the one at `start`, skipping escapes; -1 if none. */
function findClose(text: string, start: number, closers: string): number {
  for (let i = start + 1; i < text.length; i += 1) {
    const char = text[i]!;
    if (char === "\\") i += 1;
    else if (closers.includes(char)) return i;
  }
  return -1;
}

/**
 * Whether a string that ended at `at` is followed by what may follow a string.
 * A "string" that runs into a letter was not closed where we thought it was.
 */
function closesCleanly(text: string, at: number): boolean {
  const next = skipSpace(text, at);
  if (next >= text.length) return true;
  const char = text[next]!;
  return ",:}]".includes(char) || (char === "/" && (text[next + 1] === "/" || text[next + 1] === "*"));
}

function skipSpace(text: string, at: number): number {
  let i = at;
  while (i < text.length && " \t\r\n".includes(text[i]!)) i += 1;
  return i;
}

/** Past whitespace and comments too: a key with a comment before its colon is still a key. */
function skipSpaceAndComments(text: string, at: number): number {
  let i = skipSpace(text, at);
  while (text[i] === "/" && (text[i + 1] === "/" || text[i + 1] === "*")) {
    if (text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n" && text[i] !== "\r") i += 1;
    } else {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
    }
    i = skipSpace(text, i);
  }
  return i;
}

/** The inside of a single- or curly-quoted string, rewritten for double quotes. */
function requote(body: string, fixes: Record<RepairFix, number>): string {
  let out = "";
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i]!;
    if (char === "\\") {
      const next = body[i + 1] ?? "";
      // \' means nothing in JSON; the quote it protected no longer needs protecting.
      out += next === "'" ? "'" : `\\${next}`;
      i += 1;
    } else if (char === '"') {
      out += '\\"';
    } else {
      out += escapeControls(char, fixes);
    }
  }
  return out;
}

const SHORT_ESCAPES: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f" };

function hasControl(body: string): boolean {
  for (let i = 0; i < body.length; i += 1) if (body.charCodeAt(i) < 0x20) return true;
  return false;
}

/** Raw control characters inside a string, written as the escapes JSON requires. */
function escapeControls(body: string, fixes: Record<RepairFix, number>): string {
  let out = "";
  for (const char of body) {
    const code = char.charCodeAt(0);
    if (code >= 0x20) {
      out += char;
      continue;
    }
    fixes.controlChar += 1;
    out += SHORT_ESCAPES[char] ?? `\\u${code.toString(16).padStart(4, "0")}`;
  }
  return out;
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

const ID_START = /[\p{ID_Start}$_]/u;
const ID_CONTINUE = /[\p{ID_Continue}$]/u;

/** A letter in any script, `$` or `_` — what a JavaScript identifier may begin with. */
function isWordStart(point: number): boolean {
  if (point < 0x80) return (point >= 0x61 && point <= 0x7a) || (point >= 0x41 && point <= 0x5a) || point === 0x5f || point === 0x24;
  return ID_START.test(String.fromCodePoint(point));
}

function isWordPart(point: number): boolean {
  if (point < 0x80) return isWordStart(point) || isDigit(point);
  return ID_CONTINUE.test(String.fromCodePoint(point));
}

/** End of the word at `start`; a key word may also hold `-` and `.`. */
function wordEnd(text: string, start: number, key: boolean): number {
  let end = start;
  while (end < text.length) {
    const point = text.codePointAt(end)!;
    if (!(isWordPart(point) || (key && (point === 0x2d || point === 0x2e)))) break;
    end += point > 0xffff ? 2 : 1;
  }
  return end;
}
