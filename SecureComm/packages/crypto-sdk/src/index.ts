export type KeyPair = {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
};

export interface CryptoProvider {
    init(): Promise<void>;
    generateIdentityKeyPair(): Promise<KeyPair>;
}

class SodiumCryptoProvider implements CryptoProvider {
    private initialized = false;
    private sodium!: typeof import('libsodium-wrappers');

    async init(): Promise<void> {
        if (this.initialized) return;
        const sodium = await import('libsodium-wrappers');
        await sodium.default.ready;
        this.sodium = sodium.default;
        this.initialized = true;
    }

    async generateIdentityKeyPair(): Promise<KeyPair> {
        if (!this.initialized) {
            throw new Error('SodiumCryptoProvider not initialized');
        }
        const { publicKey, privateKey } = this.sodium.crypto_sign_keypair();
        return {
            publicKey,
            secretKey: privateKey,
        };
    }
}

export const cryptoProvider = new SodiumCryptoProvider();