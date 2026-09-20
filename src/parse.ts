/**
 * A JSON parser that says what is wrong, where, and why.
 *
 * `JSON.parse` knows exactly as much as this one does, but it reports it in a
 * parser's terms: a trailing comma is "Expected double-quoted property name",
 * pointed at the bracket after it, and a single quote and an unquoted key get
 * the same "Expected property name or '}'". This parser accepts precisely the
 * language `JSON.parse` accepts (fuzzed against it) and, where it stops, names
 * the mistake the way a person would: the line and column, the offending
 * text, and which bracket is still open.
 *
 * It also keeps what `JSON.parse` throws away. Scalars stay as the raw text
 * they were written as, so formatting never turns 12345678901234567890 into
 * 12345678901234567000, `1.0` into `1`, or an escaped letter into a plain one; members
 * stay in document order with duplicates intact, where a JavaScript object
 * would hoist integer-like keys to the front and keep only the last duplicate.
 *
 * The parser is iterative — an explicit stack, no recursion — because
 * `JSON.parse` in V8 accepts nesting far deeper than the call stack allows, and
 * "accepts exactly what JSON.parse accepts" has to hold there too.
 */

/** Scalars are kept as their source text: `"a\n"`, `-0.5e3`, `true`. */
export type JsonNode = string | JsonObject | JsonArray;

export interface JsonObject {
  type: "object";
  members: JsonMember[];
}

export interface JsonMember {
  /** The decoded key, for sorting and duplicate detection. */
  key: string;
  /** The key as written, quotes and escapes included. */
  raw: string;
  value: JsonNode;
}

export interface JsonArray {
  type: "array";
  items: JsonNode[];
}

export interface JsonStats {
  /** Deepest container nesting: `1` for `{}`, `0` for a lone scalar. */
  depth: number;
  objects: number;
  arrays: number;
  keys: number;
  strings: number;
  numbers: number;
  booleans: number;
  nulls: number;
}

export interface DuplicateKey {
  key: string;
  /** Path of the object holding the key twice. */
  path: (string | number)[];
  offset: number;
  line: number;
  column: number;
}

export type JsonErrorCode =
  | "empty"
  | "bom"
  | "invisibleSpace"
  | "comment"
  | "singleQuote"
  | "smartQuote"
  | "unquotedKey"
  | "unquotedValue"
  | "keyExpected"
  | "valueExpected"
  | "missingColon"
  | "missingComma"
  | "commaOrClose"
  | "trailingComma"
  | "doubleComma"
  | "mismatchedBracket"
  | "unterminatedString"
  | "lineBreakInString"
  | "controlChar"
  | "invalidEscape"
  | "invalidUnicodeEscape"
  | "leadingZero"
  | "plusSign"
  | "leadingDot"
  | "numberDigit"
  | "invalidNumber"
  | "nonJsonLiteral"
  | "wrongLiteral"
  | "badLiteral"
  | "unexpectedEnd"
  | "extraData"
  | "secondValue";

export interface JsonError {
  code: JsonErrorCode;
  /** UTF-16 offset into the text — what `setSelectionRange` takes. */
  offset: number;
  /** 1-based. */
  line: number;
  /** 1-based, in code points, so an emoji earlier on the line counts once. */
  column: number;
  /** The offending text, shortened for display: `NaN`, `'`, `U+00A0`. */
  found?: string;
  /** What should stand there instead: `true`, `0.5`, `]`. */
  expected?: string;
  /** The innermost bracket still open, for the errors that are about one. */
  open?: { char: "{" | "["; close: "}" | "]"; line: number; column: number };
}

export type ParseResult =
  | { ok: true; root: JsonNode; stats: JsonStats; duplicates: DuplicateKey[]; duplicateCount: number }
  | { ok: false; error: JsonError };

interface Frame {
  node: JsonObject | JsonArray;
  /** Offset of the opening bracket. */
  open: number;
  /** Offset of the most recent comma, for "trailing comma" and "two commas". */
  comma: number;
  /** The key whose value is being read (objects only). */
  key: string;
  seen: Set<string> | null;
}

/** What the parser is waiting for next. */
const ROOT = 0;
const ARRAY_FIRST = 1;
const ARRAY_NEXT = 2;
const OBJECT_FIRST = 3;
const OBJECT_NEXT = 4;
const OBJECT_VALUE = 5;
const AFTER = 6;
type State = typeof ROOT | typeof ARRAY_FIRST | typeof ARRAY_NEXT | typeof OBJECT_FIRST | typeof OBJECT_NEXT | typeof OBJECT_VALUE | typeof AFTER;

/** Kept, but not all listed: past this many the warning is about the file, not the keys. */
const DUPLICATES_KEPT = 50;

/**
 * Characters that look like a space and are not one to JSON. They arrive with
 * text copied out of web pages, word processors and chat apps.
 */
const INVISIBLE = new Set([
  0x00a0, 0x1680, 0x180e, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x200b, 0x200c, 0x200d, 0x2028, 0x2029, 0x202f, 0x205f, 0x2060, 0x3000, 0xfeff,
]);

const SMART_QUOTES = new Set([0x201c, 0x201d, 0x201e, 0x201f, 0x2018, 0x2019, 0x201a, 0x201b]);

const HEX = /^[0-9a-fA-F]{4}$/;

export function parseJson(text: string): ParseResult {
  const n = text.length;
  let i = 0;
  // Asserted so the checker does not narrow it to ROOT: the helpers below move it.
  let state = ROOT as State;
  let root: JsonNode | undefined;
  const stack: Frame[] = [];
  const stats: JsonStats = { depth: 0, objects: 0, arrays: 0, keys: 0, strings: 0, numbers: 0, booleans: 0, nulls: 0 };
  const duplicates: DuplicateKey[] = [];
  let duplicateCount = 0;

  const fail = (code: JsonErrorCode, offset: number, extra: Partial<JsonError> = {}): ParseResult => {
    const { line, column } = locate(text, offset);
    return { ok: false, error: { code, offset, line, column, ...extra } };
  };

  const openInfo = (frame: Frame): JsonError["open"] => {
    const { line, column } = locate(text, frame.open);
    const object = frame.node.type === "object";
    return { char: object ? "{" : "[", close: object ? "}" : "]", line, column };
  };

  /** Hangs a finished scalar, or a container just opened, on its parent. */
  const attach = (node: JsonNode) => {
    const top = stack[stack.length - 1];
    if (!top) root = node;
    else if (top.node.type === "array") top.node.items.push(node);
    else top.node.members[top.node.members.length - 1]!.value = node;
  };

  /**
   * Everything that can stand where a value, a key or a separator was expected
   * and deserves its own explanation. Returns null for "just a wrong character".
   */
  const stray = (at: number): ParseResult | null => {
    const code = text.charCodeAt(at);
    if (code === 0x2f /* / */) {
      const next = text.charCodeAt(at + 1);
      if (next === 0x2f || next === 0x2a) return fail("comment", at);
    }
    if (code === 0xfeff && at === 0) return fail("bom", at, { found: "U+FEFF" });
    if (INVISIBLE.has(code)) return fail("invisibleSpace", at, { found: codePoint(code) });
    if (SMART_QUOTES.has(code)) return fail("smartQuote", at, { found: text[at] });
    return null;
  };

  /** A value was expected at `at` and something else is there. */
  const valueError = (at: number): ParseResult => {
    const special = stray(at);
    if (special) return special;
    const code = text.charCodeAt(at);
    const char = text[at]!;
    if (char === "'") return fail("singleQuote", at, { found: "'" });
    if (char === "+") return fail("plusSign", at, { found: word(text, at) });
    if (char === "." && isDigit(text.charCodeAt(at + 1))) {
      return fail("leadingDot", at, { found: word(text, at), expected: `0${word(text, at)}` });
    }
    if (isIdentStart(code)) return literalError(at);
    if (code > 0x7f) return fail("unquotedValue", at, { found: word(text, at) });
    const top = stack[stack.length - 1];
    if ((char === "}" || char === "]") && top) {
      const expected = top.node.type === "object" ? "}" : "]";
      if (char !== expected) return fail("mismatchedBracket", at, { found: char, open: openInfo(top) });
    }
    return fail("valueExpected", at, { found: printable(text, at) });
  };

  /** A letter where a value belongs: a misspelt literal or unquoted text. */
  const literalError = (at: number): ParseResult => {
    let end = at;
    while (end < n && isIdentPart(text.charCodeAt(end))) end += 1;
    const ident = text.slice(at, end);
    if (ident === "NaN" || ident === "Infinity" || ident === "undefined") {
      return fail("nonJsonLiteral", at, { found: ident });
    }
    const lower = ident.toLowerCase();
    if (lower === "true" || lower === "false" || lower === "null") {
      return fail("wrongLiteral", at, { found: ident, expected: lower });
    }
    if (lower === "none" || lower === "nil") return fail("wrongLiteral", at, { found: ident, expected: "null" });
    for (const literal of ["true", "false", "null"]) {
      if (literal.startsWith(ident)) return fail("badLiteral", at, { found: ident, expected: literal });
    }
    return fail("unquotedValue", at, { found: word(text, at) });
  };

  /** Something other than a double-quoted key where a key belongs. */
  const keyError = (at: number, frame: Frame): ParseResult => {
    const special = stray(at);
    if (special) return special;
    const code = text.charCodeAt(at);
    const char = text[at]!;
    if (char === "'") return fail("singleQuote", at, { found: "'" });
    if (isIdentStart(code) || isDigit(code) || code > 0x7f) return fail("unquotedKey", at, { found: word(text, at) });
    if (char === "]") return fail("mismatchedBracket", at, { found: char, open: openInfo(frame) });
    return fail("keyExpected", at, { found: printable(text, at) });
  };

  /**
   * Reads a string starting at the quote at `start`. Returns the offset just
   * past the closing quote, or the failure.
   */
  const scanString = (start: number): number | ParseResult => {
    let j = start + 1;
    while (j < n) {
      const code = text.charCodeAt(j);
      if (code === 0x22 /* " */) return j + 1;
      if (code === 0x5c /* \ */) {
        if (j + 1 >= n) break;
        const next = text[j + 1]!;
        if (next === "u") {
          if (!HEX.test(text.slice(j + 2, j + 6))) {
            const escape = text.slice(j, j + 6);
            const cut = escape.search(/["\r\n]/);
            return fail("invalidUnicodeEscape", j, { found: cut === -1 ? escape : escape.slice(0, cut) });
          }
          j += 6;
          continue;
        }
        if ('"\\/bfnrt'.includes(next)) {
          j += 2;
          continue;
        }
        return fail("invalidEscape", j, { found: `\\${printable(text, j + 1)}` });
      }
      if (code < 0x20) {
        if (code === 0x0a || code === 0x0d) return fail("lineBreakInString", j);
        return fail("controlChar", j, { found: codePoint(code) });
      }
      j += 1;
    }
    return fail("unterminatedString", start);
  };

  /** Reads a number at `start`; returns the offset past it, or the failure. */
  const scanNumber = (start: number): number | ParseResult => {
    let j = start;
    if (text.charCodeAt(j) === 0x2d /* - */) {
      j += 1;
      if (text.startsWith("Infinity", j)) return fail("nonJsonLiteral", start, { found: "-Infinity" });
    }
    const first = text.charCodeAt(j);
    if (first === 0x30 /* 0 */) {
      j += 1;
      if (isDigit(text.charCodeAt(j))) return fail("leadingZero", j - 1, { found: word(text, start) });
    } else if (isDigit(first)) {
      while (isDigit(text.charCodeAt(j))) j += 1;
    } else {
      if (first === 0x2e && isDigit(text.charCodeAt(j + 1))) {
        return fail("leadingDot", j, { found: word(text, start), expected: `-0${word(text, j)}` });
      }
      return fail("numberDigit", j);
    }
    if (text.charCodeAt(j) === 0x2e /* . */) {
      j += 1;
      if (!isDigit(text.charCodeAt(j))) return fail("numberDigit", j);
      while (isDigit(text.charCodeAt(j))) j += 1;
    }
    const e = text.charCodeAt(j);
    if (e === 0x65 || e === 0x45 /* e E */) {
      j += 1;
      const sign = text.charCodeAt(j);
      if (sign === 0x2b || sign === 0x2d) j += 1;
      if (!isDigit(text.charCodeAt(j))) return fail("numberDigit", j);
      while (isDigit(text.charCodeAt(j))) j += 1;
    }
    // "0x1F", "1.2.3", "12px": the number ended but the word did not.
    const after = text.charCodeAt(j);
    if (isIdentPart(after) || after === 0x2e) return fail("invalidNumber", start, { found: word(text, start) });
    return j;
  };

  /** Reads any value at `i`; containers are opened and left on the stack. */
  const readValue = (): ParseResult | null => {
    const code = text.charCodeAt(i);
    if (code === 0x7b /* { */ || code === 0x5b /* [ */) {
      const object = code === 0x7b;
      const node: JsonObject | JsonArray = object ? { type: "object", members: [] } : { type: "array", items: [] };
      attach(node);
      stack.push({ node, open: i, comma: -1, key: "", seen: null });
      if (object) stats.objects += 1;
      else stats.arrays += 1;
      if (stack.length > stats.depth) stats.depth = stack.length;
      i += 1;
      state = object ? OBJECT_FIRST : ARRAY_FIRST;
      return null;
    }
    let end: number | ParseResult;
    if (code === 0x22) {
      end = scanString(i);
      if (typeof end !== "number") return end;
      stats.strings += 1;
    } else if (code === 0x2d || isDigit(code)) {
      end = scanNumber(i);
      if (typeof end !== "number") return end;
      stats.numbers += 1;
    } else if (text.startsWith("true", i) || text.startsWith("false", i) || text.startsWith("null", i)) {
      end = i + (text.charCodeAt(i) === 0x66 ? 5 : 4);
      // "trueish" is not `true` followed by garbage; it is one wrong word.
      if (isIdentPart(text.charCodeAt(end))) return literalError(i);
      if (code === 0x6e) stats.nulls += 1;
      else stats.booleans += 1;
    } else {
      return valueError(i);
    }
    attach(text.slice(i, end));
    i = end;
    state = AFTER;
    return null;
  };

  /** Reads a key and its colon; leaves the parser waiting for the value. */
  const readKey = (frame: Frame): ParseResult | null => {
    const start = i;
    const end = scanString(start);
    if (typeof end !== "number") return end;
    const raw = text.slice(start, end);
    const key = raw.includes("\\") ? (JSON.parse(raw) as string) : raw.slice(1, -1);
    const object = frame.node as JsonObject;

    if (frame.seen === null) frame.seen = new Set();
    if (frame.seen.has(key)) {
      duplicateCount += 1;
      if (duplicates.length < DUPLICATES_KEPT) {
        const { line, column } = locate(text, start);
        duplicates.push({ key, path: pathOf(stack), offset: start, line, column });
      }
    } else {
      frame.seen.add(key);
    }

    object.members.push({ key, raw, value: "null" });
    frame.key = key;
    stats.keys += 1;
    i = end;
    skipSpace();
    if (i >= n) return fail("unexpectedEnd", i, { open: openInfo(frame) });
    if (text.charCodeAt(i) !== 0x3a /* : */) {
      return stray(i) ?? fail("missingColon", i, { found: printable(text, i) });
    }
    i += 1;
    state = OBJECT_VALUE;
    return null;
  };

  const skipSpace = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) i += 1;
      else break;
    }
  };

  for (;;) {
    skipSpace();
    const top = stack[stack.length - 1];

    if (i >= n) {
      if (state === AFTER && !top) {
        return { ok: true, root: root!, stats, duplicates, duplicateCount };
      }
      if (!top) return fail("empty", i);
      return fail("unexpectedEnd", i, { open: openInfo(top) });
    }

    const code = text.charCodeAt(i);
    let failure: ParseResult | null = null;

    switch (state) {
      case ROOT:
        failure = readValue();
        break;

      case ARRAY_FIRST:
        if (code === 0x5d /* ] */) {
          stack.pop();
          i += 1;
          state = AFTER;
        } else if (code === 0x2c /* , */) {
          failure = fail("valueExpected", i, { found: "," });
        } else {
          failure = readValue();
        }
        break;

      case ARRAY_NEXT:
        if (code === 0x5d) failure = fail("trailingComma", top!.comma, { expected: "]" });
        else if (code === 0x2c) failure = fail("doubleComma", i);
        else failure = readValue();
        break;

      case OBJECT_FIRST:
        if (code === 0x7d /* } */) {
          stack.pop();
          i += 1;
          state = AFTER;
        } else if (code === 0x22) {
          failure = readKey(top!);
        } else {
          failure = keyError(i, top!);
        }
        break;

      case OBJECT_NEXT:
        if (code === 0x7d) failure = fail("trailingComma", top!.comma, { expected: "}" });
        else if (code === 0x2c) failure = fail("doubleComma", i);
        else if (code === 0x22) failure = readKey(top!);
        else failure = keyError(i, top!);
        break;

      case OBJECT_VALUE:
        failure = readValue();
        break;

      case AFTER: {
        if (!top) {
          const special = stray(i);
          if (special) return special;
          const char = text[i]!;
          if (char === "{" || char === "[" || char === '"') return fail("secondValue", i, { found: char });
          return fail("extraData", i, { found: printable(text, i) });
        }
        const object = top.node.type === "object";
        const close = object ? 0x7d : 0x5d;
        if (code === 0x2c) {
          top.comma = i;
          i += 1;
          state = object ? OBJECT_NEXT : ARRAY_NEXT;
        } else if (code === close) {
          stack.pop();
          i += 1;
        } else if (code === 0x7d || code === 0x5d) {
          failure = fail("mismatchedBracket", i, { found: text[i], open: openInfo(top) });
        } else {
          failure = stray(i);
          if (!failure) {
            // Something that could begin the next item: the comma before it is missing.
            const startsItem =
              code === 0x22 ||
              code === 0x7b ||
              code === 0x5b ||
              code === 0x2d ||
              code === 0x27 ||
              isDigit(code) ||
              isIdentStart(code);
            failure = startsItem
              ? fail("missingComma", i)
              : fail("commaOrClose", i, { found: printable(text, i), expected: object ? "}" : "]" });
          }
        }
        break;
      }
    }

    if (failure) return failure;
  }
}

/** 1-based line and code-point column of a UTF-16 offset. CRLF is one break. */
export function locate(text: string, offset: number): { line: number; column: number; lineStart: number } {
  let line = 1;
  let lineStart = 0;
  const end = Math.min(offset, text.length);
  for (let i = 0; i < end; i += 1) {
    const c = text.charCodeAt(i);
    if (c === 0x0a || (c === 0x0d && text.charCodeAt(i + 1) !== 0x0a)) {
      line += 1;
      lineStart = i + 1;
    }
  }
  return { line, column: codePointLength(text, lineStart, offset) + 1, lineStart };
}

/**
 * The line an error is on, cut to `width` characters around the error when
 * the line is long — a minified file is one line of two megabytes. `before`
 * ends just before the offending character and `after` starts with it, so the
 * interface can draw the caret row from `before` itself and let the font
 * decide how wide an emoji or a CJK character is. Tabs and invisible
 * characters become one visible cell each.
 *
 * Only the neighbourhood of the offset is read, never the whole line: this
 * runs on every render of a broken two-megabyte file.
 */
export function errorExcerpt(
  text: string,
  offset: number,
  width = 72,
): { before: string; after: string; clippedStart: boolean; clippedEnd: boolean } {
  // Four UTF-16 units per cell on each side is at least two code points per cell: more than the window needs.
  const reach = width * 4;

  // Back to the start of the line — the same breaks locate() counts — or as far as reach.
  const floor = Math.max(0, offset - reach);
  let from = offset;
  while (from > floor) {
    const c = text.charCodeAt(from - 1);
    if (c === 0x0a || (c === 0x0d && text.charCodeAt(from) !== 0x0a)) break;
    from -= 1;
  }
  const lineStartSeen = from === 0 || from > floor || isBreakBefore(text, from);
  if (isLowSurrogate(text.charCodeAt(from)) && isHighSurrogate(text.charCodeAt(from - 1))) from += 1;

  const ceiling = Math.min(text.length, offset + reach);
  // An offset on the LF of a CRLF belongs to the line the CR ends.
  let to = offset > from && text.charCodeAt(offset - 1) === 0x0d ? offset - 1 : offset;
  while (to < ceiling) {
    const c = text.charCodeAt(to);
    if (c === 0x0a || c === 0x0d) break;
    to += 1;
  }
  const lineEndSeen = to === text.length || text.charCodeAt(to) === 0x0a || text.charCodeAt(to) === 0x0d;
  if (isLowSurrogate(text.charCodeAt(to)) && isHighSurrogate(text.charCodeAt(to - 1))) to += 1;

  const cells = Array.from(text.slice(from, to), (char) => {
    const code = char.codePointAt(0)!;
    if (code === 0x09) return " ";
    if (code < 0x20 || INVISIBLE.has(code)) return "·";
    return char;
  });
  const at = codePointLength(text, from, Math.min(offset, to));
  const lead = Math.floor(width * 0.6);
  const first = Math.max(0, Math.min(at - lead, cells.length - width));
  const last = Math.min(cells.length, first + width);
  return {
    before: cells.slice(first, at).join(""),
    after: cells.slice(at, last).join(""),
    clippedStart: !lineStartSeen || first > 0,
    clippedEnd: !lineEndSeen || last < cells.length,
  };
}

/** Whether a line break ends just before `at`: LF, a lone CR, or the LF of a CRLF. */
function isBreakBefore(text: string, at: number): boolean {
  const c = text.charCodeAt(at - 1);
  return c === 0x0a || (c === 0x0d && text.charCodeAt(at) !== 0x0a);
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/** `a.b[3]["odd key"]` — how a path reads in the messages and the leak report. */
export function formatPath(path: readonly (string | number)[]): string {
  let out = "";
  for (const segment of path) {
    if (typeof segment === "number") out += `[${segment}]`;
    else if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(segment)) out += out === "" ? segment : `.${segment}`;
    else out += `[${JSON.stringify(segment)}]`;
  }
  return out === "" ? "$" : out;
}

/** Bytes the text takes as UTF-8 — what the file will weigh on disk. */
export function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else {
        bytes += 3;
      }
    } else bytes += 3;
  }
  return bytes;
}

export function countLines(text: string): number {
  if (text === "") return 0;
  let lines = 1;
  for (let at = text.indexOf("\n"); at !== -1; at = text.indexOf("\n", at + 1)) lines += 1;
  return lines;
}

function pathOf(stack: Frame[]): (string | number)[] {
  const path: (string | number)[] = [];
  for (let f = 0; f < stack.length - 1; f += 1) {
    const frame = stack[f]!;
    path.push(frame.node.type === "array" ? frame.node.items.length - 1 : frame.key);
  }
  return path;
}

function codePointLength(text: string, from: number, to: number): number {
  let count = 0;
  for (let i = from; i < to; i += 1) {
    const c = text.charCodeAt(i);
    // A low surrogate that completes a pair was already counted with its high half.
    if (c >= 0xdc00 && c <= 0xdfff && i > from) {
      const prev = text.charCodeAt(i - 1);
      if (prev >= 0xd800 && prev <= 0xdbff) continue;
    }
    count += 1;
  }
  return count;
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function isIdentStart(code: number): boolean {
  return (code >= 0x61 && code <= 0x7a) || (code >= 0x41 && code <= 0x5a) || code === 0x5f || code === 0x24;
}

function isIdentPart(code: number): boolean {
  return isIdentStart(code) || isDigit(code);
}

function codePoint(code: number): string {
  return `U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
}

/** The character at `at` as something a person can read, even when it is invisible. */
function printable(text: string, at: number): string {
  const code = text.codePointAt(at);
  if (code === undefined) return "";
  if (code < 0x20 || code === 0x7f || INVISIBLE.has(code)) return codePoint(code);
  return String.fromCodePoint(code);
}

/** The run of non-delimiter text starting at `at`, shortened for a message. */
function word(text: string, at: number): string {
  let end = at;
  while (end < text.length && end - at < 40) {
    const c = text[end]!;
    if (" \t\r\n,:[]{}\"'".includes(c)) break;
    end += 1;
  }
  const run = text.slice(at, Math.max(end, at + 1));
  return end - at >= 40 ? `${run}…` : run;
}
