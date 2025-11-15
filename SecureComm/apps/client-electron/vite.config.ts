import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@securecomm/crypto-sdk': path.resolve(__dirname, '../packages/crypto-sdk/src')
        }
    },
    build: {
        sourcemap: true
    }
});