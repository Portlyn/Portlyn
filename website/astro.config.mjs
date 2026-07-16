import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightOpenAPI, { openAPISidebarGroups } from "starlight-openapi";

export default defineConfig({
  site: "https://docs.portlyn.dev",
  integrations: [
    starlight({
      title: "Portlyn",
      description: "Self-hosted reverse proxy and access gateway.",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/portlyn/Portlyn" }],
      editLink: {
        baseUrl: "https://github.com/portlyn/Portlyn/edit/main/website/",
      },
      plugins: [
        starlightOpenAPI([
          { base: "api", label: "API reference", schema: "../docs/openapi.yaml" },
        ]),
      ],
      sidebar: [
        { label: "Start here", items: [{ autogenerate: { directory: "start" } }] },
        { label: "Guides", items: [{ autogenerate: { directory: "guides" } }] },
        { label: "Running it", items: [{ autogenerate: { directory: "operations" } }] },
        { label: "Reference", items: [{ autogenerate: { directory: "reference" } }] },
        ...openAPISidebarGroups,
      ],
    }),
  ],
});
