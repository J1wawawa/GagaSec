import { defineConfig } from 'vite';

// Keep the UI framework cache separate as analysis workspaces grow.
export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/node_modules\/(react|react-dom|scheduler)\//.test(id))
            return 'react-vendor';
        },
      },
    },
  },
});
