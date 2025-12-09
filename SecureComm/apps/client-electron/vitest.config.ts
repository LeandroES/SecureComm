import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path'; // <--- Importar path

export default defineConfig({
    plugins: [react()],
    // --- AGREGAR ESTO ---
    resolve: {
        alias: {
            // Apunta directo al index.ts para evitar ambigüedades
            '@securecomm/crypto-sdk': path.resolve(__dirname, '../../packages/crypto-sdk/src/index.ts')
        }
    },
    // --------------------
    test: {
        environment: 'jsdom',
        setupFiles: ['./vitest.setup.ts']
    }
});