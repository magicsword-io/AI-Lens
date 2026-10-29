# AI Lens website

Four static Astro pages: overview, getting started, rule reference, and hooks &
telemetry. Pages and local assets use `/AI-Lens/` under
`https://magicsword-io.github.io`. The site has no API, analytics or remote fonts.
Rule IDs and counts come from the shipped YAML at build time.

Use Node 24 or later from this directory:

```sh
npm ci
npm run check
npm run build
npm run dev
```

Open `http://localhost:4321/AI-Lens/`. `npm run preview` serves the built output
at the same path. Generated `dist/`, `.astro/` and `node_modules/` are ignored.

The Website workflow checks the site and uploads its Pages artifact. Deployment
is skipped for pull requests and while the repository is private. To publish,
choose GitHub Actions in Settings → Pages, then run the Website workflow on main
when repository visibility and plan permit. Verify the workflow's deployment URL
and all four routes before calling it live.

Download cards use the version and platform assets in `src/data/project.ts`.
Update that release data together with the published ZIPs and `SHA256SUMS`.
The getting-started guide covers extraction, platform prerequisites and a source-build fallback. The executable and engine filenames retain `agent-lens` for
compatibility. Native hook coverage and observation-only telemetry have separate
limits; the site links to the full adapter and verification guides.

Brand reference: [LOLSkills](https://github.com/magicsword-io/lolskills).
`public/magicsword-logo.svg` is the MagicSword brand asset reused from that
repository. The site uses the same black and mint palette with an AI Lens
wordmark. Project code is Apache-2.0; MagicSword branding remains its owner's
identity.
