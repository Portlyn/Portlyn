/** @type {import('next').NextConfig} */
const staticExport = process.env.PORTLYN_STATIC_EXPORT === "1";

const baseConfig = {
  reactStrictMode: true,
};

const devConfig = {
  ...baseConfig,
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
