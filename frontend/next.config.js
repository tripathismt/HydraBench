/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    const apiHostPort = process.env.HYDRABENCH_API_HOSTPORT;
    if (!apiHostPort) return [];
    return [{ source: "/api/hydrabench/:path*", destination: `http://${apiHostPort}/:path*` }];
  },
};

module.exports = nextConfig;
