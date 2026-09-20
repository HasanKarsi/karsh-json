/**
 * Reads an n8n workflow export: what it is made of, how it starts, and what
 * it gives away if it is shared as it is.
 *
 * The shape is n8n's own export (Workflow → Download, the public API, or
 * `n8n export:workflow`): `nodes`, and `connections` keyed by the source
 * node's *name*, each output a list of lanes, each lane a list of targets. A
 * canvas selection copied with Ctrl+C has the same shape without a name, and
 * `export:workflow --all` writes an array of them — all three are read here.
 *
 * Credentials in an export are references — a type, an id, a display name —
 * and the secret itself stays encrypted in n8n's database. What leaks is what
 * people type into parameters instead: the key pasted into a header field,
 * the token in a Code node, the password in a connection string. That, pinned
 * execution data, and the instance id are what the sanitised copy removes.
 */

import { formatPath, type JsonNode } from "./parse";
import { redact, scanString, type SecretKind } from "./secrets";

export type TriggerKind = "webhook" | "schedule" | "cron" | "manual" | "other";

export interface N8nTrigger {
  node: string;
  kind: TriggerKind;
  type: string;
  /** `POST /orders` for a webhook, the cron expression for a schedule. */
  detail: string | null;
}

export interface N8nCredential {
  type: string;
  id: string | null;
  name: string | null;
  nodes: string[];
}

export interface N8nFinding {
  /** The node's name, or `staticData` for what the workflow keeps between runs. */
  node: string;
  /** Where in the node, from `parameters` or `notes` down; or from `staticData` down. */
  path: string;
  /** The `name` of an n8n `{ name, value }` pair — a header, a query parameter, a field. */
  field: string | null;
  kind: SecretKind;
  masked: string;
}

/** One arrow on the canvas. */
export interface N8nConnection {
  from: string;
  to: string;
  /** `main`, or the sub-node kind: `ai_languageModel`, `ai_tool`, `ai_memory`… */
  type: string;
  /** 0-based output of the source: an IF node's false branch is output 1. */
  output: number;
}

export interface N8nWebhook {
  node: string;
  method: string | null;
  path: string | null;
  /** A Webhook node that accepts calls without any authentication. */
  open: boolean;
}

export interface N8nWorkflow {
  name: string | null;
  id: string | null;
  /** Sticky notes excluded: they are annotations, not steps. */
  nodes: number;
  stickies: number;
  edges: number;
  connections: N8nConnection[];
  /** Connections from or to a node name that is not in the workflow. */
  dangling: number;
  types: { type: string; count: number }[];
  triggers: N8nTrigger[];
  disabled: string[];
  /** Nodes with no connection in or out. */
  isolated: string[];
  credentials: N8nCredential[];
  findings: N8nFinding[];
  /** Nodes with pinned execution data. */
  pinned: string[];
  instanceId: boolean;
  webhooks: N8nWebhook[];
}

type Path = (string | number)[];

type Edit = { path: Path; value: string } | { path: Path; remove: true };

export interface N8nReport {
  workflows: N8nWorkflow[];
  /** What the sanitised copy changes, as paths into the parsed document. */
  edits: Edit[];
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonRecord = { [key: string]: Json };

const N8N_TYPE = /^(?:n8n-nodes-base\.|@n8n\/|n8n-nodes-|@[^/]+\/n8n-nodes-)/;
const STICKY = "n8n-nodes-base.stickyNote";

/**
 * A cheap look at the parsed tree before the document is turned into objects:
 * only something with `nodes` and `connections` at the top (or in one of the
 * first items of a list) is worth a second parse.
 */
export function mightBeN8n(root: JsonNode): boolean {
  const candidates = typeof root !== "string" && root.type === "array" ? root.items.slice(0, 50) : [root];
  return candidates.some((candidate) => {
    if (typeof candidate === "string" || candidate.type !== "object") return false;
    const keys = new Set(candidate.members.map((member) => member.key));
    return keys.has("nodes") && keys.has("connections");
  });
}

export function isWorkflow(value: unknown): value is JsonRecord {
  if (!isRecord(value) || !Array.isArray(value.nodes) || !isRecord(value.connections)) return false;
  return value.nodes.some((node) => isRecord(node) && typeof node.type === "string" && N8N_TYPE.test(node.type));
}

/** Null when the value is not an n8n workflow or a list of them. */
export function analyseN8n(value: unknown): N8nReport | null {
  const found: { workflow: JsonRecord; base: Path }[] = [];
  if (isWorkflow(value)) found.push({ workflow: value, base: [] });
  else if (Array.isArray(value)) {
    value.forEach((item, index) => {
      if (isWorkflow(item)) found.push({ workflow: item, base: [index] });
    });
  }
  if (found.length === 0) return null;

  const edits: Edit[] = [];
  const workflows = found.map(({ workflow, base }) => analyseWorkflow(workflow, base, edits));
  return { workflows, edits };
}

function analyseWorkflow(workflow: JsonRecord, base: Path, edits: Edit[]): N8nWorkflow {
  // A node without a name is broken, but it is still a node; it is called by its position.
  const nodes = (workflow.nodes as Json[]).flatMap((node, index) =>
    isRecord(node) ? [{ node, index, name: typeof node.name === "string" ? node.name : `#${index + 1}` }] : [],
  );

  const names = new Set(nodes.map(({ name }) => name));
  const types = new Map<string, number>();
  const triggers: N8nTrigger[] = [];
  const disabled: string[] = [];
  const credentials = new Map<string, N8nCredential>();
  const findings: N8nFinding[] = [];
  const webhooks: N8nWebhook[] = [];
  let stickies = 0;

  for (const { node, index, name } of nodes) {
    const type = typeof node.type === "string" ? node.type : "";
    const parameters = isRecord(node.parameters) ? node.parameters : {};
    const nodePath: Path = [...base, "nodes", index];

    const scanned: Root[] = [];
    if (typeof node.notes === "string") scanned.push({ value: node.notes, path: ["notes"] });
    if (node.parameters !== undefined) scanned.push({ value: node.parameters, path: ["parameters"] });
    scanTree(scanned, name, nodePath, findings, edits);

    if (type === STICKY) {
      stickies += 1;
      continue;
    }
    types.set(type, (types.get(type) ?? 0) + 1);
    if (node.disabled === true) disabled.push(name);

    const kind = triggerKind(type);
    const webhook = webhookOf(node, type, parameters, name);
    if (webhook) webhooks.push(webhook);
    if (kind) {
      const detail =
        kind === "webhook" && webhook
          ? [webhook.method, webhook.path ? `/${webhook.path.replace(/^\//, "")}` : null].filter(Boolean).join(" ") || null
          : kind === "schedule"
            ? cronOf(parameters)
            : null;
      triggers.push({ node: name, kind, type, detail });
    }

    if (isRecord(node.credentials)) {
      for (const [credentialType, ref] of Object.entries(node.credentials)) {
        const id = isRecord(ref) && typeof ref.id === "string" ? ref.id : null;
        const label = isRecord(ref) && typeof ref.name === "string" ? ref.name : typeof ref === "string" ? ref : null;
        const key = JSON.stringify([credentialType, id, label]);
        const entry = credentials.get(key) ?? { type: credentialType, id, name: label, nodes: [] };
        entry.nodes.push(name);
        credentials.set(key, entry);
      }
    }
  }

  // Connections: { source: { outputType: [ lane: [ { node, type, index } ] ] } }
  const incoming = new Set<string>();
  const outgoing = new Set<string>();
  const connections: N8nConnection[] = [];
  let dangling = 0;
  for (const [source, outputs] of Object.entries(workflow.connections as JsonRecord)) {
    if (!isRecord(outputs)) continue;
    for (const [type, lanes] of Object.entries(outputs)) {
      if (!Array.isArray(lanes)) continue;
      lanes.forEach((lane, output) => {
        if (!Array.isArray(lane)) return;
        for (const target of lane) {
          if (!isRecord(target) || typeof target.node !== "string") continue;
          connections.push({ from: source, to: target.node, type, output });
          outgoing.add(source);
          incoming.add(target.node);
          if (!names.has(source) || !names.has(target.node)) dangling += 1;
        }
      });
    }
  }

  const isolated = nodes
    .filter(({ node, name }) => node.type !== STICKY && !incoming.has(name) && !outgoing.has(name))
    .map(({ name }) => name);

  // Trigger nodes keep state here between runs; a Stripe Trigger keeps its webhook signing secret here.
  if (workflow.staticData !== undefined && workflow.staticData !== null) {
    scanTree([{ value: workflow.staticData, path: ["staticData"] }], "staticData", base, findings, edits);
  }

  const pinned = isRecord(workflow.pinData) ? Object.keys(workflow.pinData) : [];
  if (workflow.pinData !== undefined) edits.push({ path: [...base, "pinData"], remove: true });

  const instanceId = isRecord(workflow.meta) && workflow.meta.instanceId !== undefined;
  if (instanceId) edits.push({ path: [...base, "meta", "instanceId"], remove: true });

  return {
    name: typeof workflow.name === "string" ? workflow.name : null,
    id: typeof workflow.id === "string" || typeof workflow.id === "number" ? String(workflow.id) : null,
    nodes: nodes.length - stickies,
    stickies,
    edges: connections.length,
    connections,
    dangling,
    types: [...types]
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count || (a.type < b.type ? -1 : a.type > b.type ? 1 : 0)),
    triggers,
    disabled,
    isolated,
    credentials: [...credentials.values()],
    findings,
    pinned,
    instanceId,
    webhooks,
  };
}

/** A value to scan and its path from the node (or the workflow) it belongs to. */
interface Root {
  value: Json;
  path: Path;
}

/**
 * Every string under the roots — a node's `parameters` and `notes`, the
 * workflow's `staticData` — walked with an explicit stack (a parameter can
 * nest arbitrarily deep). A string's "name" is its key, or — inside n8n's
 * `{ name, value }` pairs, which is how headers, query parameters and Set
 * fields are stored — the pair's name.
 */
function scanTree(roots: Root[], label: string, basePath: Path, findings: N8nFinding[], edits: Edit[]) {
  const stack: { value: Json; path: Path; name: string | null; field: string | null }[] = roots.map(({ value, path }) => ({
    value,
    path,
    name: null,
    field: null,
  }));

  while (stack.length > 0) {
    const { value, path, name, field } = stack.pop()!;
    if (typeof value === "string") {
      const hits = scanString(value, name);
      if (hits.length === 0) continue;
      for (const hit of hits) {
        findings.push({ node: label, path: formatPath(path), field, kind: hit.kind, masked: hit.masked });
      }
      edits.push({ path: [...basePath, ...path], value: redact(value, hits) });
    } else if (Array.isArray(value)) {
      // Pushed in reverse so findings come out in document order.
      for (let i = value.length - 1; i >= 0; i -= 1) {
        stack.push({ value: value[i]!, path: [...path, i], name: null, field: null });
      }
    } else if (isRecord(value)) {
      const pair = typeof value.name === "string" && value.value !== undefined ? value.name : null;
      const entries = Object.entries(value);
      for (let i = entries.length - 1; i >= 0; i -= 1) {
        const [key, child] = entries[i]!;
        const inPair = key === "value" && pair !== null;
        stack.push({ value: child, path: [...path, key], name: inPair ? pair : key, field: inPair ? pair : null });
      }
    }
  }
}

function triggerKind(type: string): TriggerKind | null {
  switch (type) {
    case "n8n-nodes-base.webhook":
      return "webhook";
    case "n8n-nodes-base.scheduleTrigger":
    case "n8n-nodes-base.interval":
      return "schedule";
    case "n8n-nodes-base.cron":
      return "cron";
    case "n8n-nodes-base.manualTrigger":
    case "n8n-nodes-base.start":
      return "manual";
    // "Email Trigger (IMAP)" is the one trigger whose type does not say so.
    case "n8n-nodes-base.emailReadImap":
      return "other";
  }
  return /trigger$/i.test(type.slice(type.lastIndexOf(".") + 1)) ? "other" : null;
}

/** Nodes that open a public URL: the Webhook and Form nodes, and anything n8n gave a webhookId. */
function webhookOf(node: JsonRecord, type: string, parameters: JsonRecord, name: string): N8nWebhook | null {
  const isWebhook = type === "n8n-nodes-base.webhook";
  if (!isWebhook && type !== "n8n-nodes-base.formTrigger" && typeof node.webhookId !== "string") return null;

  const rawPath = typeof parameters.path === "string" && !parameters.path.startsWith("=") ? parameters.path : null;
  const path = rawPath || (typeof node.webhookId === "string" ? node.webhookId : null);
  let method: string | null = null;
  if (isWebhook) {
    const httpMethod = parameters.httpMethod;
    method = Array.isArray(httpMethod)
      ? httpMethod.filter((m): m is string => typeof m === "string").join(", ")
      : typeof httpMethod === "string"
        ? httpMethod
        : "GET";
  }
  const auth = parameters.authentication;
  return { node: name, method, path, open: isWebhook && (auth === undefined || auth === "none") };
}

/** The cron expression of a Schedule Trigger, when it was given one. */
function cronOf(parameters: JsonRecord): string | null {
  const rule = parameters.rule;
  if (!isRecord(rule) || !Array.isArray(rule.interval)) return null;
  for (const interval of rule.interval) {
    if (isRecord(interval) && typeof interval.expression === "string") return interval.expression;
  }
  return null;
}

/**
 * The workflow with every detected secret replaced by a placeholder, pinned
 * data and the instance id removed — the version that can be posted in a
 * forum thread or sent to a freelancer. Node ids, webhook paths and credential
 * references stay: n8n needs them to import it.
 */
export function sanitise(value: unknown, report: N8nReport, indent: string | number): string {
  const copy = structuredClone(value) as Json;
  for (const edit of report.edits) {
    const parent = walk(copy, edit.path.slice(0, -1));
    const key = edit.path[edit.path.length - 1]!;
    if (parent === undefined || parent === null || typeof parent !== "object") continue;
    if ("remove" in edit) {
      if (Array.isArray(parent)) continue;
      delete parent[key as string];
    } else if (Array.isArray(parent)) {
      parent[key as number] = edit.value;
    } else {
      parent[key as string] = edit.value;
    }
  }
  return JSON.stringify(copy, null, indent);
}

function walk(value: Json, path: Path): Json | undefined {
  let current: Json | undefined = value;
  for (const segment of path) {
    if (current === null || typeof current !== "object") return undefined;
    current = Array.isArray(current) ? current[segment as number] : current[segment as string];
  }
  return current;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
