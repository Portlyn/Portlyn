# Docs site

The [docs.portlyn.dev](https://docs.portlyn.dev) site. Astro + Starlight.

```bash
npm install
npm run dev      # local preview on http://localhost:4321
npm run build    # static output in dist/
```

Pages are Markdown/MDX under `src/content/docs`. The sidebar is generated from the folder structure (`start`, `guides`, `operations`, `reference`) — drop a file in and it shows up.

## Deploy

Cloudflare Pages, pointed at this repo:

- Root directory: `website`
- Build command: `npm run build`
- Output directory: `dist`

Add `docs.portlyn.dev` as a custom domain in the Pages project. No API tokens or secrets needed.
