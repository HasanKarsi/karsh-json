/**
 * One pass over the text as the interface needs it: the parse, the numbers
 * around it, and — only for something shaped like an n8n export — the
 * workflow analysis. Kept apart from the component so it can be run and timed
 * outside a browser.
 */

import { analyseN8n, mightBeN8n, type N8nReport } from "./n8n";
import { countLines, parseJson, utf8Length, type JsonError, type ParseResult } from "./parse";
import { repairJson, type RepairResult } from "./repair";

export interface Checked {
  text: string;
  result: ParseResult;
  bytes: number;
  lines: number;
  /** An n8n export: the document as objects (for the sanitised copy) and what was found in it. */
  n8n: { value: unknown; report: N8nReport } | null;
  /**
   * For broken text, what Repair would make of it and whether that parses —
   * so the interface promises a fix only when there is one. Null for valid
   * text, and past REPAIR_PREVIEW_LIMIT.
   */
  repair: { result: RepairResult; valid: boolean } | null;
}

/**
 * Past this size broken text is not repaired in advance just to label the
 * button; a repair is a second full pass, and the button still works.
 */
const REPAIR_PREVIEW_LIMIT = 500_000;

export function check(text: string): Checked {
  const result = parseJson(text);
  let n8n: Checked["n8n"] = null;
  if (result.ok && mightBeN8n(result.root)) {
    // Parsed a second time as objects only here; the tree is what everything else reads.
    const value: unknown = JSON.parse(text);
    const report = analyseN8n(value);
    if (report) n8n = { value, report };
  }
  let repair: Checked["repair"] = null;
  if (!result.ok && result.error.code !== "empty" && text.length <= REPAIR_PREVIEW_LIMIT) {
    const repaired = repairJson(text);
    repair = { result: repaired, valid: repaired.changed && parseJson(repaired.text).ok };
  }
  return { text, result, bytes: utf8Length(text), lines: countLines(text), n8n, repair };
}

/**
 * Whether `next` reads as an edit of `previous` rather than another text:
 * together, what the two share at the start and at the end is at least half
 * of the shorter one. Typing, deleting a block or pasting over part of it
 * passes; selecting everything and pasting something else does not.
 */
export function isEditOf(previous: string, next: string): boolean {
  const shorter = Math.min(previous.length, next.length);
  let prefix = 0;
  while (prefix < shorter && previous.charCodeAt(prefix) === next.charCodeAt(prefix)) prefix += 1;
  let suffix = 0;
  while (
    suffix < shorter - prefix &&
    previous.charCodeAt(previous.length - 1 - suffix) === next.charCodeAt(next.length - 1 - suffix)
  ) {
    suffix += 1;
  }
  return (prefix + suffix) * 2 >= shorter;
}

const BACKSLASH = String.fromCharCode(92);

/**
 * The values an error message's slots are filled with. The escape sequences
 * are built here rather than written in the copy, where every backslash would
 * be one more thing to get wrong in two languages.
 */
export function errorSlots(error: JsonError): Record<string, string> {
  const slots: Record<string, string> = {};
  if (error.found !== undefined) slots.found = error.found;
  if (error.expected !== undefined) slots.expected = error.expected;
  if (error.open) {
    slots.openChar = error.open.char;
    slots.close = error.open.close;
    slots.openLine = String(error.open.line);
    slots.openColumn = String(error.open.column);
  }
  if (error.code === "lineBreakInString") slots.escape = `${BACKSLASH}n`;
  if (error.code === "controlChar" && error.found) {
    const code = parseInt(error.found.slice(2), 16);
    slots.escape = code === 9 ? `${BACKSLASH}t` : `${BACKSLASH}u${code.toString(16).padStart(4, "0")}`;
  }
  if (error.code === "invalidEscape") {
    slots.allowed = ['"', BACKSLASH, "/", "b", "f", "n", "r", "t", "uXXXX"].map((c) => BACKSLASH + c).join(" ");
  }
  if (error.code === "invalidUnicodeEscape") slots.example = `${BACKSLASH}u00e7`;
  return slots;
}
