import { describe, expect, it } from 'vitest';
import { cryptoProvider } from './index';

describe('cryptoProvider', () => {
    it('throws when generating keys before init', async () => {
        await expect(cryptoProvider.generateIdentityKeyPair()).rejects.toThrowError(
            /not initialized/i,
        );
    });
});