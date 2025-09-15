import { defineConfig } from "vite"

// Vite config tuned for Streamlit component build
// - outputs to ./build to match Python component path
// - uses relative base so assets resolve when served by Streamlit
// - disables publicDir to avoid copying CRA's public/index.html
export default defineConfig({
  base: './',
  publicDir: false,
  build: {
    outDir: 'build',
    emptyOutDir: true,
    target: 'es2015',
    rollupOptions: {
      input: 'index.html'
    }
  }
})

