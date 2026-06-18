/** @type {import('next').NextConfig} */
const staticExport = process.env.PORTLYN_STATIC_EXPORT === "1";
const isProd = process.env.NODE_ENV === "production";
const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";
const connectExtra = apiBase ? ` ${apiBase}` : "";

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  isProd ? "script-src 'self' 'unsafe-inline'" : "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  isProd ? `connect-src 'self'${connectExtra}` : `connect-src 'self' ws: wss:${connectExtra}`,
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: contentSecurityPolicy },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
];

const baseConfig = {
  reactStrictMode: true,
};

const devConfig = {
  ...baseConfig,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  async rewrites() {
    const target = process.env.INTERNAL_API_BASE_URL?.replace(/\/$/, "") || "http://localhost:8080";
    return [
      {
        source: "/api/:path*",
        destination: `${target}/api/:path*`,
      },
    ];
  },
};

const exportConfig = {
  ...baseConfig,
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
};

export default staticExport ? exportConfig : devConfig;
