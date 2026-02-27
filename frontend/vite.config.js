import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        timeout: 60000,
        proxyTimeout: 60000,
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq, req) => {
            console.log("proxying:", req.method, req.url, "->", proxyReq.path);
          });
          proxy.on("error", (err, req) => {
            console.log("proxy error:", req.url, err.message);
          });
        },
      },
    },
  },
});
