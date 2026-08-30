import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1"],
  output: "standalone",
  reactStrictMode: true,
  typedRoutes: true,
  poweredByHeader: false,
  async rewrites() {
    const controlPlaneUrl = process.env.IPMS_CONTROL_PLANE_URL?.replace(
      /\/$/,
      "",
    );
    if (!controlPlaneUrl) {
      return [];
    }
    return [
      {
        source: "/api/v1/:path*",
        destination: `${controlPlaneUrl}/api/v1/:path*/`,
      },
    ];
  },
};

export default nextConfig;
