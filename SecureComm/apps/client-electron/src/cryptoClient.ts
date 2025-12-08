import {
    bootstrapIdentity,
    decrypt,
    deserializeHeader,
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
    type Identity,
    type OneTimePreKey,
    type PreKeyBundle,
    type SessionHeader,
    type SessionState,
    type SignedPreKey,
} from '@securecomm/crypto-sdk';
import sodium from 'libsodium-wrappers';

export type StoredIdentity = {
    ikEd25519: string;
    ikX25519: string;
    ikSecret: string;
};

export type SessionRecord = {
    peer: string;
    peerDevice: string;
    state: SessionState;
    fingerprint: string;
    verified: boolean;
};

export async function initCrypto() {
    await sodium.ready;
}

export function toBase64(data: Uint8Array) {
    return Buffer.from(data).toString('base64');
}

export function fromBase64(data: string) {
    return Uint8Array.from(Buffer.from(data, 'base64'));
}

export function storeIdentity(id: Identity) {
    const payload: StoredIdentity = {
        ikEd25519: toBase64(id.ikEd25519.publicKey),
        ikX25519: toBase64(id.ikX25519.publicKey),
        ikSecret: toBase64(id.ikEd25519.secretKey),
    };
    localStorage.setItem('securecomm.identity', JSON.stringify(payload));
}

export function loadIdentity(): Identity | null {
    const raw = localStorage.getItem('securecomm.identity');
    if (!raw) return null;
    try {
        const parsed = JSON.parse(raw) as StoredIdentity;
        return {
            ikEd25519: {
                publicKey: fromBase64(parsed.ikEd25519),
                secretKey: fromBase64(parsed.ikSecret),
            },
            ikX25519: {
                publicKey: fromBase64(parsed.ikX25519),
                secretKey: sodium.crypto_sign_ed25519_sk_to_curve25519(fromBase64(parsed.ikSecret)),
            },
        };
    } catch (err) {
        console.error('Failed to parse identity', err);
        return null;
    }
}

export async function createIdentity(seed?: Uint8Array) {
    const identity = await bootstrapIdentity(seed);
    storeIdentity(identity);
    return identity;
}

export async function generateBundle(identity: Identity, otkCount = 5) {
    const spk = await generateSignedPreKey(identity);
    const otks = await generateOneTimePreKeys(otkCount);
    const bundle = await exportBundle(identity, spk, otks[0]);
    return { spk, otks, bundle };
}

export async function refreshPreKeys(identity: Identity, otkCount = 5) {
    const spk = await rotateSignedPreKey(identity);
    const otks = await replenishOneTimePreKeys(otkCount);
    return { spk, otks };
}

export async function initiatorSession(identity: Identity, peer: PreKeyBundle) {
    const { session, headerState } = await establishSessionAsInitiator(identity, peer);
    return { session, headerState };
}

export async function responderSession(
    identity: Identity,
    signedPreKey: SignedPreKey,
    otks: OneTimePreKey[],
    peerIdentity: { ikEd25519: Uint8Array; ikX25519: Uint8Array; ephPubKey: Uint8Array; oneTimePreKey?: Uint8Array },
) {
    const { session, usedOneTime } = await establishSessionAsResponder(identity, signedPreKey, otks, peerIdentity);
    return { session, usedOneTime };
}

export async function encryptMessage(state: SessionState, text: string) {
    const { header, ciphertext } = await encrypt(state, new TextEncoder().encode(text));
    return {
        header,
        ciphertextHex: Buffer.from(ciphertext).toString('hex'),
        serializedHeader: serializeHeader(header),
    };
}

export async function decryptMessage(state: SessionState, headerPayload: Record<string, unknown> | string, ciphertextHex: string) {
    const header: SessionHeader =
        typeof headerPayload === 'string' ? deserializeHeader(headerPayload) : (headerPayload as SessionHeader);
    const plaintext = await decrypt(state, header, Uint8Array.from(Buffer.from(ciphertextHex, 'hex')));
    return new TextDecoder().decode(plaintext);
}

export async function keyFingerprint(pub: Uint8Array) {
    return fingerprint(pub);
}

export function shortAuthCode(fp: string) {
    // 60 bits ~ 10 chars base32; use first 15 hex chars grouped
    const short = fp.replace(/[^a-f0-9]/gi, '').slice(0, 15).toUpperCase();
    return short.match(/.{1,5}/g)?.join('-') ?? short;
}