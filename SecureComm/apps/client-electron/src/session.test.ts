import { describe, expect, it } from 'vitest';
import {
    bootstrapIdentity,
    generateSignedPreKey,
    generateOneTimePreKeys,
    exportBundle,
    establishSessionAsInitiator,
    establishSessionAsResponder,
    encrypt,
    decrypt,
} from '@securecomm/crypto-sdk';

function text(bytes: Uint8Array) {
    return new TextDecoder().decode(bytes);
}

describe('E2E crypto handshake', () => {
    it('performs X3DH + Double Ratchet with reorder tolerance', async () => {
        const alice = await bootstrapIdentity();
        const bob = await bootstrapIdentity();

        const bobSpk = await generateSignedPreKey(bob);
        const bobOtks = await generateOneTimePreKeys(2);
        const bundle = await exportBundle(bob, bobSpk, bobOtks[0]);

        const { session: aliceSession } = await establishSessionAsInitiator(alice, bundle);
        const { session: bobSession } = await establishSessionAsResponder(bob, bobSpk, bobOtks, {
            ikEd25519: alice.ikEd25519.publicKey,
            ikX25519: alice.ikX25519.publicKey,
            ephPubKey: aliceSession.currentRatchetKey.publicKey,
            oneTimePreKey: bundle.oneTimePreKey,
        });

        const first = await encrypt(aliceSession, new TextEncoder().encode('hola'));
        const second = await encrypt(aliceSession, new TextEncoder().encode('mundo'));

        // deliver out of order
        const msg2 = await decrypt(bobSession, second.header, second.ciphertext);
        const msg1 = await decrypt(bobSession, first.header, first.ciphertext);

        expect(text(msg1)).toBe('hola');
        expect(text(msg2)).toBe('mundo');
    });
});

describe('Envelope fuzzing', () => {
    it('ignores malformed frames', () => {
        const badFrames = [null, 42, { type: 'nope' }, { ciphertext: 1, ts: 'now' }];
        const ok = { id: '1', to_user: 'bob', ciphertext: 'aa', ts: new Date().toISOString(), ratchet_header: { dh: 'x' } };
        const parsed = badFrames.map((f) => serializeMaybe(f));
        expect(parsed.filter(Boolean).length).toBe(0);
        expect(serializeMaybe(ok)).not.toBeNull();
    });
});

function serializeMaybe(frame: any) {
    try {
        const json = JSON.stringify(frame);
        const parsed = JSON.parse(json);
        if (typeof parsed.ciphertext !== 'string' || typeof parsed.ts !== 'string') return null;
        return parsed;
    } catch {
        return null;
    }
}