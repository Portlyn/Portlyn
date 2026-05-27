import type { AccessMethod, AccessMode } from "@/lib/types";

export interface ServiceTemplate {
  id: string;
  name: string;
  category: ServiceTemplateCategory;
  description: string;
  icon: string;
  defaultPort: number;
  defaultPath: string;
  protocol: "http" | "https";
  recommendedAccessMode: AccessMode;
  recommendedAccessMethod: AccessMethod;
  notes?: string;
  docsUrl?: string;
}

export type ServiceTemplateCategory =
  | "development"
  | "media"
  | "monitoring"
  | "productivity"
  | "security"
  | "smart-home"
  | "storage"
  | "automation"
  | "infrastructure"
  | "custom";

export const customTemplate: ServiceTemplate = {
  id: "custom",
  name: "Custom service",
  category: "custom",
  description: "Configure everything manually.",
  icon: "S",
  defaultPort: 8080,
  defaultPath: "/",
  protocol: "http",
  recommendedAccessMode: "authenticated",
  recommendedAccessMethod: "session",
};

export const serviceTemplates: ServiceTemplate[] = [
  {
    id: "gitea",
    name: "Gitea",
    category: "development",
    description: "Self-hosted Git service with web UI, issues and pull requests.",
    icon: "G",
    defaultPort: 3000,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    notes: "Gitea has its own user system. Protect with Portlyn auth or expose anonymously for public repositories.",
    docsUrl: "https://docs.gitea.com/",
  },
  {
    id: "grafana",
    name: "Grafana",
    category: "monitoring",
    description: "Observability dashboards. Frequently the keys to your kingdom — protect aggressively.",
    icon: "F",
    defaultPort: 3000,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "restricted",
    recommendedAccessMethod: "session",
    notes: "Grafana often shows production metrics. Lock down to admins only and require MFA.",
    docsUrl: "https://grafana.com/docs/grafana/latest/",
  },
  {
    id: "immich",
    name: "Immich",
    category: "media",
    description: "Self-hosted photo and video backup. Replaces Google Photos.",
    icon: "I",
    defaultPort: 2283,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    notes: "Immich has its own login. You can stack Portlyn auth on top for a second factor.",
    docsUrl: "https://immich.app/",
  },
  {
    id: "jellyfin",
    name: "Jellyfin",
    category: "media",
    description: "Free media server for movies, TV shows and music.",
    icon: "J",
    defaultPort: 8096,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    notes: "Native apps may struggle with extra auth. Consider using public access for the streaming endpoints only.",
    docsUrl: "https://jellyfin.org/",
  },
  {
    id: "home-assistant",
    name: "Home Assistant",
    category: "smart-home",
    description: "Home automation platform for lights, sensors and integrations.",
    icon: "H",
    defaultPort: 8123,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    notes: "Home Assistant supports its own authentication. Disable trusted_networks if exposed via Portlyn.",
    docsUrl: "https://www.home-assistant.io/",
  },
  {
    id: "n8n",
    name: "n8n",
    category: "automation",
    description: "Workflow automation. Connect APIs, run jobs.",
    icon: "N",
    defaultPort: 5678,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "restricted",
    recommendedAccessMethod: "session",
    notes: "n8n can run code on your server. Restrict to admins only.",
    docsUrl: "https://docs.n8n.io/",
  },
  {
    id: "vaultwarden",
    name: "Vaultwarden",
    category: "security",
    description: "Self-hosted Bitwarden-compatible password manager.",
    icon: "V",
    defaultPort: 80,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "public",
    recommendedAccessMethod: "session",
    notes: "Vaultwarden has its own strong authentication. Keep as public so native clients work. Enforce HTTPS + HSTS.",
    docsUrl: "https://github.com/dani-garcia/vaultwarden/wiki",
  },
  {
    id: "portainer",
    name: "Portainer",
    category: "infrastructure",
    description: "Docker, Swarm and Kubernetes management UI.",
    icon: "P",
    defaultPort: 9000,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "restricted",
    recommendedAccessMethod: "session",
    notes: "Portainer can spawn containers as root. Admins only, MFA required, IP allowlist for the office.",
    docsUrl: "https://docs.portainer.io/",
  },
  {
    id: "nextcloud",
    name: "Nextcloud",
    category: "productivity",
    description: "Files, calendar, contacts and more.",
    icon: "C",
    defaultPort: 80,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "public",
    recommendedAccessMethod: "session",
    notes: "Nextcloud handles auth itself. Keep public for client sync.",
    docsUrl: "https://docs.nextcloud.com/",
  },
  {
    id: "uptime-kuma",
    name: "Uptime Kuma",
    category: "monitoring",
    description: "Self-hosted status pages and uptime monitoring.",
    icon: "U",
    defaultPort: 3001,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    notes: "Internal Kuma instances should be auth-protected. Public status pages can be on a separate route.",
    docsUrl: "https://github.com/louislam/uptime-kuma",
  },
  {
    id: "excalidraw",
    name: "Excalidraw",
    category: "productivity",
    description: "Virtual whiteboard for sketches and diagrams.",
    icon: "E",
    defaultPort: 80,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    docsUrl: "https://docs.excalidraw.com/",
  },
  {
    id: "plex",
    name: "Plex",
    category: "media",
    description: "Media server with native clients.",
    icon: "X",
    defaultPort: 32400,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "public",
    recommendedAccessMethod: "session",
    notes: "Plex uses its own account system; keep public so the apps work.",
    docsUrl: "https://www.plex.tv/",
  },
  {
    id: "photoprism",
    name: "PhotoPrism",
    category: "media",
    description: "AI-powered photo library.",
    icon: "M",
    defaultPort: 2342,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    docsUrl: "https://docs.photoprism.app/",
  },
  {
    id: "vikunja",
    name: "Vikunja",
    category: "productivity",
    description: "Self-hosted to-do and project management.",
    icon: "K",
    defaultPort: 3456,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "authenticated",
    recommendedAccessMethod: "session",
    docsUrl: "https://vikunja.io/docs/",
  },
  {
    id: "adguard",
    name: "AdGuard Home",
    category: "infrastructure",
    description: "Network-wide DNS-based ad and tracker blocker.",
    icon: "A",
    defaultPort: 3000,
    defaultPath: "/",
    protocol: "http",
    recommendedAccessMode: "restricted",
    recommendedAccessMethod: "session",
    notes: "Admin UI manages DNS for the whole network — restrict tightly.",
    docsUrl: "https://github.com/AdguardTeam/AdGuardHome",
  },
];

export function findTemplate(id: string): ServiceTemplate | undefined {
  if (id === customTemplate.id) return customTemplate;
  return serviceTemplates.find((template) => template.id === id);
}

export function templatesByCategory(): Record<ServiceTemplateCategory, ServiceTemplate[]> {
  const grouped: Record<string, ServiceTemplate[]> = {};
  for (const template of serviceTemplates) {
    (grouped[template.category] ||= []).push(template);
  }
  return grouped as Record<ServiceTemplateCategory, ServiceTemplate[]>;
}

export const categoryLabels: Record<ServiceTemplateCategory, string> = {
  development: "Development",
  media: "Media",
  monitoring: "Monitoring",
  productivity: "Productivity",
  security: "Security",
  "smart-home": "Smart Home",
  storage: "Storage",
  automation: "Automation",
  infrastructure: "Infrastructure",
  custom: "Custom",
};

export function buildTargetURL(template: ServiceTemplate, host: string): string {
  const trimmedHost = host.trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (!trimmedHost) {
    return "";
  }
  return `${template.protocol}://${trimmedHost}:${template.defaultPort}${template.defaultPath}`;
}
