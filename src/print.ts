/**
 * Writes a parsed tree back out, indented or on one line.
 *
 * Scalars are printed exactly as they were written (see parse.ts), so the only
 * thing formatting ever changes is whitespace — and, when asked, the order of
 * object members. Iterative for the same reason the parser is.
 */

import type { JsonMember, JsonNode } from "./parse";

export interface PrintOptions {
  /** Two spaces, four spaces or a tab; `null` for no whitespace at all. */
  indent: string | null;
  /** Orders members by key at every level. Stable, so duplicate keys keep their order. */
  sortKeys: boolean;
}

/**
 * A ceiling on the output, in UTF-16 units. Indentation grows with depth, so a
 * pathological input (ten thousand nested arrays) formats to gigabytes; this
 * stops that with an error the interface can explain instead of a dead tab.
 */
export const PRINT_LIMIT = 64_000_000;

export class OutputTooLargeError extends Error {
  constructor() {
    super("formatted output exceeds the size limit");
    this.name = "OutputTooLargeError";
  }
}

interface Frame {
  object: boolean;
  entries: readonly (JsonMember | JsonNode)[];
  index: number;
}

export function printJson(root: JsonNode, { indent, sortKeys }: PrintOptions): string {
  if (typeof root === "string") return root;

  const pretty = indent !== null && indent !== "";
  const colon = pretty ? ": " : ":";
  const pads: string[] = [""];
  const pad = (depth: number) => {
    while (pads.length <= depth) pads.push(pads[pads.length - 1]! + indent);
    return pads[depth]!;
  };

  const out: string[] = [];
  let length = 0;
  const write = (chunk: string) => {
    length += chunk.length;
    if (length > PRINT_LIMIT) throw new OutputTooLargeError();
    out.push(chunk);
  };

  const stack: Frame[] = [];
  const open = (node: Exclude<JsonNode, string>) => {
    const object = node.type === "object";
    const entries = object ? (sortKeys ? [...node.members].sort(byKey) : node.members) : node.items;
    if (entries.length === 0) {
      write(object ? "{}" : "[]");
      return;
    }
    write(object ? "{" : "[");
    stack.push({ object, entries, index: 0 });
  };

  open(root);
  while (stack.length > 0) {
    const frame = stack[stack.length - 1]!;
    const depth = stack.length;
    if (frame.index === frame.entries.length) {
      stack.pop();
      if (pretty) write(`\n${pad(depth - 1)}`);
      write(frame.object ? "}" : "]");
      continue;
    }
    if (frame.index > 0) write(",");
    if (pretty) write(`\n${pad(depth)}`);

    const entry = frame.entries[frame.index]!;
    frame.index += 1;
    let value: JsonNode;
    if (frame.object) {
      const member = entry as JsonMember;
      write(member.raw + colon);
      value = member.value;
    } else {
      value = entry as JsonNode;
    }
    if (typeof value === "string") write(value);
    else open(value);
  }

  return out.join("");
}

/** Code-unit order, as `jq -S` and most sorted diffs use; independent of locale. */
function byKey(a: JsonMember, b: JsonMember): number {
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}
