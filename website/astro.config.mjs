// The dent8 docs site: Astro Starlight over the repo's docs/ tree.
// Pages are synced (not vendored) by sync-docs.mjs at build time, so docs/ stays the
// single source of truth and the site can never drift from the repo.
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: "https://xyzzylabs.github.io",
  base: "/dent8",
  integrations: [
    starlight({
      title: "dent8",
      description: "A memory firewall for coding agents.",
      logo: { src: "./src/assets/logo.svg", alt: "dent8" },
      favicon: "/favicon.svg",
      customCss: ["./src/styles/custom.css"],
      lastUpdated: true,
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/xyzzylabs/dent8" },
      ],
      editLink: {
        baseUrl: "https://github.com/xyzzylabs/dent8/edit/main/docs/",
      },
      sidebar: [
        {
          label: "Start here",
          items: [
            { slug: "getting-started" },
            { slug: "installation" },
            { slug: "configuration" },
          ],
        },
        {
          label: "Using dent8",
          items: [
            { slug: "interfaces" },
            { slug: "context-capture" },
            { slug: "agent-adapters" },
            { slug: "mcp-clients" },
            { slug: "native-memory" },
            { slug: "content-check" },
            { slug: "witness" },
            { slug: "dogfood" },
          ],
        },
        {
          label: "Understanding dent8",
          items: [
            { slug: "status" },
            { slug: "architecture" },
            { slug: "domain-model" },
            { slug: "storage" },
            { slug: "threat-model" },
            { slug: "evals" },
            { slug: "belief-revision" },
            { slug: "formal-verification" },
            { slug: "naming" },
          ],
        },
        {
          label: "Project",
          items: [
            { slug: "roadmap" },
            { slug: "project-brief" },
            { slug: "related-work" },
            { slug: "release" },
            { slug: "dogfooding-notes" },
            { slug: "upgrading-to-v0-3" },
          ],
        },
        {
          label: "Decisions (ADRs)",
          collapsed: true,
          items: [{ autogenerate: { directory: "decisions" } }],
        },
        {
          label: "Research",
          collapsed: true,
          items: [{ autogenerate: { directory: "research" } }],
        },
      ],
    }),
  ],
});
