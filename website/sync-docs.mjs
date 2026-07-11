// Sync the repo's docs/ tree into Starlight's content directory at build time.
// docs/ stays the single source of truth: nothing here is committed (see .gitignore).
//
// Per file: inject frontmatter (title = the first H1, which is then stripped — Starlight
// renders its own), normalize the filename to a stable slug, and rewrite links:
//   - links between docs pages (X.md, sub/X.md, ../X.md) -> root-absolute site URLs
//   - links out of docs/ into the repo (../examples/..., ../crates/...) -> GitHub URLs
//   - repo-relative images -> raw.githubusercontent URLs
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, posix, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const docsDir = join(here, "..", "docs");
const outDir = join(here, "src", "content", "docs");
const repoWeb = "https://github.com/xyzzylabs/dent8/tree/main";
const repoRaw = "https://raw.githubusercontent.com/xyzzylabs/dent8/main";
const base = "/dent8";

// docs/paper is a working draft outline, not user documentation.
const EXCLUDE = new Set(["paper"]);

// Sidebar labels for pages whose H1 is too wordy for a nav column; everything else uses
// its title. Keyed by slug.
const SIDEBAR_LABELS = new Map([
  ["status", "Implementation status"],
  ["belief-revision", "Belief revision"],
  ["context-capture", "Context & capture"],
  ["formal-verification", "Formal verification"],
  ["dogfooding-notes", "Dogfooding notes"],
  ["dogfood", "Dogfood workflow"],
  ["native-memory", "Native memory"],
  ["mcp-clients", "MCP clients"],
  ["agent-adapters", "Agent adapters"],
  ["content-check", "Content-check hook"],
  ["witness", "Witness runbook"],
  ["upgrading-to-v0-3", "Upgrading to v0.3"],
]);

function walk(dir, prefix = "") {
  const entries = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (EXCLUDE.has(entry.name)) continue;
      entries.push(...walk(join(dir, entry.name), posix.join(prefix, entry.name)));
    } else if (entry.name.endsWith(".md")) {
      entries.push(posix.join(prefix, entry.name));
    }
  }
  return entries;
}

// A doc's site slug: lowercased path, dots-in-name flattened, no extension.
function slugOf(relPath) {
  const noExt = relPath.replace(/\.md$/, "");
  return noExt
    .split("/")
    .map((part) => part.toLowerCase().replaceAll(".", "-"))
    .join("/");
}

const files = walk(docsDir);
const slugs = new Map(files.map((file) => [file, slugOf(file)]));

function rewriteLink(sourceRel, target) {
  const [path, frag = ""] = target.split("#");
  const anchor = frag ? `#${frag}` : "";
  if (/^[a-z]+:/i.test(path) || path === "") return null; // absolute URL or pure anchor
  const resolved = posix.normalize(posix.join(posix.dirname(sourceRel), path));
  if (resolved.startsWith("..")) {
    // Points out of docs/ into the repo.
    const repoPath = posix.normalize(posix.join("docs", posix.dirname(sourceRel), path));
    return { href: `${repoWeb}/${repoPath}${anchor}`, raw: `${repoRaw}/${repoPath}` };
  }
  if (slugs.has(resolved)) {
    return { href: `${base}/${slugs.get(resolved)}/${anchor}`, raw: null };
  }
  // A non-markdown file inside docs/ (none today) — link to it on GitHub.
  return { href: `${repoWeb}/docs/${resolved}${anchor}`, raw: `${repoRaw}/docs/${resolved}` };
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

for (const file of files) {
  let text = readFileSync(join(docsDir, file), "utf8");

  // Title from the first H1; strip it (Starlight renders the title itself).
  const h1 = text.match(/^# (.+)$/m);
  const title = h1 ? h1[1].trim() : slugOf(file);
  if (h1) text = text.replace(h1[0] + "\n", "").replace(/^\n/, "");

  // Rewrite markdown links and images.
  text = text.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)\)/g, (whole, bang, label, target) => {
    const rewritten = rewriteLink(file, target);
    if (!rewritten) return whole;
    const href = bang === "!" && rewritten.raw ? rewritten.raw : rewritten.href;
    return `${bang}[${label}](${href})`;
  });

  const slug = slugOf(file);
  const label = SIDEBAR_LABELS.get(slug);
  const sidebar = label ? `sidebar:\n  label: "${label}"\n` : "";
  const front = `---\ntitle: "${title.replaceAll('"', '\\"')}"\n${sidebar}---\n\n`;
  const dest = join(outDir, slug + ".md");
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, front + text);
}

// The hand-written landing page lives beside this script, outside the synced tree.
cpSync(join(here, "index.mdx"), join(outDir, "index.mdx"));
// The mark doubles as the favicon.
cpSync(join(here, "..", "assets", "logo.svg"), join(here, "public", "favicon.svg"));
cpSync(join(here, "..", "assets", "logo.svg"), join(here, "src", "assets", "logo.svg"));

console.log(`synced ${files.length} docs pages -> ${relative(process.cwd(), outDir)}`);
