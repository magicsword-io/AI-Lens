import { parse } from "yaml";
import defaultYAML from "../../../examples/rules/default.yaml?raw";
import credentialYAML from "../../../examples/rules/credential-stores.yaml?raw";
import destructiveYAML from "../../../examples/rules/destructive-operations.yaml?raw";
import executionYAML from "../../../examples/rules/execution-and-network.yaml?raw";
import integrityYAML from "../../../examples/rules/agent-config-integrity.yaml?raw";
import toolsYAML from "../../../examples/rules/restricted-tools.yaml?raw";

export const repository = "https://github.com/magicsword-io/AI-Lens";
export const source = (path: string) => `${repository}/blob/main/${path}`;
export const href = (path = "") =>
  `${import.meta.env.BASE_URL.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;

const catalog = [
  {
    slug: "default",
    title: "The essentials",
    category: "Default policy",
    description:
      "Direct .env and credential paths, shell references, a demo marker, and shell auditing.",
    number: "01",
  },
  {
    slug: "credential-stores",
    title: "Credential stores",
    category: "Optional pack",
    description:
      "Common cloud, Kubernetes, registry, Git, and SSH credential paths.",
    number: "02",
  },
  {
    slug: "destructive-operations",
    title: "Destructive operations",
    category: "Optional pack",
    description:
      "Explicit root deletion, hard resets, forced cleans and pushes, and raw-disk writes.",
    number: "03",
  },
  {
    slug: "execution-and-network",
    title: "Execution & network",
    category: "Optional pack",
    description:
      "Download-to-shell pipelines, uploads, remote access, and permission changes.",
    number: "04",
  },
  {
    slug: "agent-config-integrity",
    title: "Configuration integrity",
    category: "Optional pack",
    description:
      "Illustrated agent settings, instructions, hook files, and AI Lens policy writes.",
    number: "05",
  },
  {
    slug: "restricted-tools",
    title: "Named tool controls",
    category: "Optional pack",
    description:
      "Selected MCP network, browser scripting, and delegation tool names.",
    number: "06",
  },
];
const documents: Record<string, string> = {
  default: defaultYAML,
  "credential-stores": credentialYAML,
  "destructive-operations": destructiveYAML,
  "execution-and-network": executionYAML,
  "agent-config-integrity": integrityYAML,
  "restricted-tools": toolsYAML,
};

// Read the shipped policies at build time so the site inventory follows the repo.
export const packs = catalog.map((pack) => {
  const yaml = documents[pack.slug];
  const parsed = parse(yaml);
  if (parsed?.version !== 1 || !Array.isArray(parsed.rules))
    throw new Error(`Invalid policy document: ${pack.slug}`);
  const ids: string[] = parsed.rules.map((rule: { id?: unknown }) => {
    if (typeof rule?.id !== "string" || !rule.id)
      throw new Error(`Missing rule ID: ${pack.slug}`);
    return rule.id;
  });
  return {
    ...pack,
    yaml,
    ids,
    count: ids.length,
    url: source(`examples/rules/${pack.slug}.yaml`),
  };
});
export const ruleCount = packs.reduce((sum, pack) => sum + pack.count, 0);
