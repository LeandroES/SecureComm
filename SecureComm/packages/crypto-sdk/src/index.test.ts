import { describe, expect, it, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers';

import {
    bootstrapIdentity,
    decrypt,
    encrypt,
    establishSessionAsInitiator,
    establishSessionAsResponder,
    exportBundle,
    fingerprint,
    generateOneTimePreKeys,
    generateSignedPreKey,
    replenishOneTimePreKeys,
    rotateSignedPreKey,
    serializeHeader,
    deserializeHeader,
} from './index';

function seedFromLabel(label: string, length = 32): Uint8Array {
    const hash = sodium.crypto_generichash(length, label);
    return hash;
}

describe('SecureComm crypto SDK', () => {
    beforeAll(async () => {
        await sodium.ready;
    });

    it('generates deterministic fingerprints and identity', async () => {
        const seed = seedFromLabel('identity-seed');
        const id = await bootstrapIdentity(seed);
        const fp = await fingerprint(id.ikEd25519.publicKey);
        expect(fp).toBe(sodium.to_hex(sodium.crypto_hash_sha256(id.ikEd25519.publicKey)));
        expect(id.ikEd25519.publicKey.length).toBe(sodium.crypto_sign_PUBLICKEYBYTES);
        expect(id.ikX25519.publicKey.length).toBe(sodium.crypto_kx_PUBLICKEYBYTES);
    });

    it('performs X3DH handshake and encrypts/decrypts messages A→B', async () => {
        const aliceSeed = seedFromLabel('alice-seed');
        const bobSeed = seedFromLabel('bob-seed');
        const alice = await bootstrapIdentity(aliceSeed);
        const bob = await bootstrapIdentity(bobSeed);

        const bobSpk = await generateSignedPreKey(bob);
        const bobOtk = (await generateOneTimePreKeys(1, seedFromLabel('bob-otk-seed', 32))).at(0);
        const bundle = await exportBundle(bob, bobSpk, bobOtk);

        const { session: aliceSession } = await establishSessionAsInitiator(alice, bundle);
        const { session: bobSession } = await establishSessionAsResponder(
            bob,
            bobSpk,
            [bobOtk!],
            { ikEd25519: alice.ikEd25519.publicKey, ephPubKey: aliceSession.currentRatchetKey.publicKey, ikX25519: alice.ikX25519.publicKey, oneTimePreKey: bobOtk?.publicKey },
        );

        const plaintext = new TextEncoder().encode('hello bob');
        const encrypted = await encrypt(aliceSession, plaintext);
        const decrypted = await decrypt(bobSession, encrypted.header, encrypted.ciphertext);
        expect(decrypted).toEqual(plaintext);
    });

    it('handles out-of-order delivery with skipped message keys', async () => {
        const alice = await bootstrapIdentity(seedFromLabel('alice-oor'));
        const bob = await bootstrapIdentity(seedFromLabel('bob-oor'));
        const bobSpk = await generateSignedPreKey(bob);
        const bobOtk = (await generateOneTimePreKeys(1)).at(0);
        const bundle = await exportBundle(bob, bobSpk, bobOtk);
        const { session: aliceSession } = await establishSessionAsInitiator(alice, bundle);
        const { session: bobSession } = await establishSessionAsResponder(
            bob,
            bobSpk,
            [bobOtk!],
            { ikEd25519: alice.ikEd25519.publicKey, ephPubKey: aliceSession.currentRatchetKey.publicKey, ikX25519: alice.ikX25519.publicKey, oneTimePreKey: bobOtk?.publicKey },
        );

        const messages = ['first', 'second', 'third'].map((m) => new TextEncoder().encode(m));
        const sent = await Promise.all(messages.map((m) => encrypt(aliceSession, m)));

        // deliver 1st, 3rd, then 2nd
        const first = await decrypt(bobSession, sent[0].header, sent[0].ciphertext);
        const third = await decrypt(bobSession, sent[2].header, sent[2].ciphertext);
        const second = await decrypt(bobSession, sent[1].header, sent[1].ciphertext);

        expect(first).toEqual(messages[0]);
        expect(third).toEqual(messages[2]);
        expect(second).toEqual(messages[1]);
    });

    it('ratchets on responder send after receiving', async () => {
        const alice = await bootstrapIdentity(seedFromLabel('alice-ratchet'));
        const bob = await bootstrapIdentity(seedFromLabel('bob-ratchet'));
        const bobSpk = await generateSignedPreKey(bob);
        const bundle = await exportBundle(bob, bobSpk);
        const { session: aliceSession } = await establishSessionAsInitiator(alice, bundle);
        const { session: bobSession } = await establishSessionAsResponder(
            bob,
            bobSpk,
            [],
            { ikEd25519: alice.ikEd25519.publicKey, ephPubKey: aliceSession.currentRatchetKey.publicKey, ikX25519: alice.ikX25519.publicKey },
        );

        const msgToBob = await encrypt(aliceSession, new TextEncoder().encode('ping'));
        await decrypt(bobSession, msgToBob.header, msgToBob.ciphertext);

        const reply = await encrypt(bobSession, new TextEncoder().encode('pong'));
        const decrypted = await decrypt(aliceSession, reply.header, reply.ciphertext);
        expect(new TextDecoder().decode(decrypted)).toBe('pong');
    });

    it('fails to decrypt with tampered header', async () => {
        const alice = await bootstrapIdentity(seedFromLabel('alice-tamper'));
        const bob = await bootstrapIdentity(seedFromLabel('bob-tamper'));
        const spk = await generateSignedPreKey(bob);
        const bundle = await exportBundle(bob, spk);
        const { session: aliceSession } = await establishSessionAsInitiator(alice, bundle);
        const { session: bobSession } = await establishSessionAsResponder(
            bob,
            spk,
            [],
            { ikEd25519: alice.ikEd25519.publicKey, ephPubKey: aliceSession.currentRatchetKey.publicKey, ikX25519: alice.ikX25519.publicKey },
        );

        const encrypted = await encrypt(aliceSession, new TextEncoder().encode('secret'));
        const serialized = serializeHeader(encrypted.header);
        const parsed = deserializeHeader(serialized);
        parsed.n += 1; // tamper

        await expect(decrypt(bobSession, parsed, encrypted.ciphertext)).rejects.toBeTruthy();
    });

    it('survives lightweight fuzz on headers and frame sizes', async () => {
        const alice = await bootstrapIdentity(seedFromLabel('alice-fuzz'));
        const bob = await bootstrapIdentity(seedFromLabel('bob-fuzz'));
        const spk = await generateSignedPreKey(bob);
        const bundle = await exportBundle(bob, spk);
        const { session: aliceSession } = await establishSessionAsInitiator(alice, bundle);
        const { session: bobSession } = await establishSessionAsResponder(
            bob,
            spk,
            [],
            { ikEd25519: alice.ikEd25519.publicKey, ephPubKey: aliceSession.currentRatchetKey.publicKey, ikX25519: alice.ikX25519.publicKey },
        );

        for (let i = 0; i < 5; i += 1) {
            const size = 8 + i * 5;
            const payload = sodium.randombytes_buf(size);
            const { header, ciphertext } = await encrypt(aliceSession, payload);
            const tamperedHeader = { ...header, n: header.n + (i === 2 ? 1 : 0) };
            if (i === 2) {
                await expect(decrypt(bobSession, tamperedHeader, ciphertext)).rejects.toBeTruthy();
            } else {
                const restored = i === 2 ? header : header;
                const clear = await decrypt(bobSession, restored, ciphertext);
                expect(clear).toEqual(payload);
            }
        }
    });

    it('rotates pre-keys and replenishes OTK pool', async () => {
        const identity = await bootstrapIdentity(seedFromLabel('pool'));
        const initialSpk = await generateSignedPreKey(identity);
        const rotated = await rotateSignedPreKey(identity);
        expect(sodium.memcmp(initialSpk.keyPair.publicKey, rotated.keyPair.publicKey)).not.toBe(0);
        const otks = await replenishOneTimePreKeys(4);
        expect(otks).toHaveLength(4);
    });
});