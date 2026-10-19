import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiPort = env.PORT || '5174';
  const webPort = Number(env.WEB_PORT || '5173');
  return {
    plugins: [react()],
    server: {
      port: webPort,
      strictPort: false,
      proxy: {
        '/api': {
          target: `http://localhost:${apiPort}`,
          changeOrigin: true,
        },
      },
    },
    build: { outDir: 'dist/web' },
  };
});
