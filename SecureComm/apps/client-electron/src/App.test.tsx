import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import App from './App';

vi.mock('./cryptoClient', () => ({
    initCrypto: () => Promise.resolve(),
    loadIdentity: () => null,
    shortAuthCode: (v: string) => v,
    toBase64: (b: Uint8Array) => Buffer.from(b).toString('base64'),
    generateBundle: vi.fn(),
    ensureIdentity: vi.fn(),
}));

vi.mock('./api', () => ({
    openSocket: () => ({ close() {}, send() {} }),
}));
//asasdasd
describe('App shell', () => {
    it('renders headers and sections', () => {
        render(<App />);
        expect(screen.getByText(/SecureComm/i)).toBeTruthy();
        expect(screen.getByText(/Registro \/ Login/i)).toBeTruthy();
        expect(screen.getByText(/Verificación de identidad/i)).toBeTruthy();
    });
});