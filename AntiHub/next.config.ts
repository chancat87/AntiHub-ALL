import type { NextConfig } from "next";

function getInternalBackendBaseUrl(): string {
  const raw =
    process.env.INTERNAL_API_BASE_URL ||
    process.env.BACKEND_INTERNAL_URL ||
    "http://antihub-backend:8000";

  // Next rewrites 需要绝对 URL，否则会被当成站内路径处理
  if (!/^https?:\/\//i.test(raw)) return "http://antihub-backend:8000";

  return raw.replace(/\/+$/, "");
}

const nextConfig: NextConfig = {
  // Docker 多阶段构建需要
  output: "standalone",

  async rewrites() {
    const backendBaseUrl = getInternalBackendBaseUrl();
    return [
      {
        source: "/backend/:path*",
        destination: `${backendBaseUrl}/:path*`,
      },
      // 兼容桌面端 AntiHook：域名只需要指向 web，由 web 代转发到 backend
      {
        source: "/api/plugin-api/:path*",
        destination: `${backendBaseUrl}/api/plugin-api/:path*`,
      },
      {
        source: "/api/kiro/oauth/callback",
        destination: `${backendBaseUrl}/api/kiro/oauth/callback`,
      },
    ];
  },
};

export default nextConfig;
