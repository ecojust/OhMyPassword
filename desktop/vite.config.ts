import { defineConfig } from 'vite';
export default defineConfig({ clearScreen:false, server:{port:1421,strictPort:true}, envPrefix:['VITE_','TAURI_ENV_*'], build:{target:'es2022',minify:'esbuild',sourcemap:false} });
