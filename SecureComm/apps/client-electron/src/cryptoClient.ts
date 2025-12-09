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
    serializeSession,
    deserializeSession,
    type Identity,
    type OneTimePreKey,
    type PreKeyBundle,
    type SessionHeader,
    type SessionState,
    type SignedPreKey,
} from '@securecomm/crypto-sdk';
import sodium from 'libsodium-wrappers';

// --- Storage Types ---
export type StoredIdentity = {
    ikEd25519: string;
    ikX25519: string;
    ikSecret: string;
};

// Tipos para guardar llaves privadas localmente
export type StoredKeys = {
    spk: {
        keyPair: { publicKey: string; privateKey: string };
        signature: string;
        id: number;
    };
    otks: Array<{
        keyPair: { publicKey: string; privateKey: string };
        id: number;
    }>;
};

// --- Helpers ---
export async function initCrypto() {
    await sodium.ready;
}

export function toBase64(data: Uint8Array): string {
    return sodium.to_base64(data, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(data: string): Uint8Array {
    return sodium.from_base64(data, sodium.base64_variants.ORIGINAL);
}

// --- Identity Management ---
export function storeIdentity(id: Identity) {
    const payload: StoredIdentity = {
        ikEd25519: toBase64(id.ikEd25519.publicKey),
        ikX25519: toBase64(id.ikX25519.publicKey),
        ikSecret: toBase64(id.ikEd25519.privateKey),
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
                privateKey: fromBase64(parsed.ikSecret),
            },
            ikX25519: {
                publicKey: fromBase64(parsed.ikX25519),
                privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(fromBase64(parsed.ikSecret)),
            },
        };
    } catch (err) {
        console.error('Failed to parse identity', err);
        return null;
    }
}

export async function createIdentity(seed?: Uint8Array) {
    await sodium.ready;
    const id = await bootstrapIdentity(seed);
    storeIdentity(id);
    return id;
}

// --- Local Key Management ---

export function storeLocalKeys(spk: SignedPreKey, otks: OneTimePreKey[]) {
    const payload: StoredKeys = {
        spk: {
            id: spk.id,
            signature: toBase64(spk.signature),
            keyPair: {
                publicKey: toBase64(spk.keyPair.publicKey),
                privateKey: toBase64(spk.keyPair.privateKey)
            }
        },
        otks: otks.map(k => ({
            id: k.id,
            keyPair: {
                publicKey: toBase64(k.keyPair.publicKey),
                privateKey: toBase64(k.keyPair.privateKey)
            }
        }))
    };
    localStorage.setItem('securecomm.keys', JSON.stringify(payload));
}

export function loadLocalKeys(): { spk: SignedPreKey, otks: OneTimePreKey[] } | null {
    const raw = localStorage.getItem('securecomm.keys');
    if (!raw) return null;
    try {
        const parsed = JSON.parse(raw) as StoredKeys;
        return {
            spk: {
                id: parsed.spk.id,
                signature: fromBase64(parsed.spk.signature),
                keyPair: {
                    publicKey: fromBase64(parsed.spk.keyPair.publicKey),
                    privateKey: fromBase64(parsed.spk.keyPair.privateKey)
                }
            },
            otks: parsed.otks.map(k => ({
                id: k.id,
                keyPair: {
                    publicKey: fromBase64(k.keyPair.publicKey),
                    privateKey: fromBase64(k.keyPair.privateKey)
                }
            }))
        };
    } catch (e) {
        console.error("Failed to load local keys", e);
        return null;
    }
}

export async function generateBundle(identity: Identity, otkCount = 5) {
    const spk = await generateSignedPreKey(identity);
    const otks = await generateOneTimePreKeys(otkCount);
    storeLocalKeys(spk, otks);
    const bundle = await exportBundle(identity, spk, otks[0]);
    return { spk, otks, bundle };
}

export async function refreshPreKeys(identity: Identity, otkCount = 5) {
    const spk = await rotateSignedPreKey(identity);
    const otks = await replenishOneTimePreKeys(otkCount);
    storeLocalKeys(spk, otks);
    return { spk, otks };
}

// --- Session Wrappers ---

export async function initiatorSession(identity: Identity, peer: PreKeyBundle) {
    const { session, header } = await establishSessionAsInitiator(identity, peer);
    return { session, headerState: header };
}

export async function autoResponderSession(
    identity: Identity,
    peerIdentity: { ikEd25519: Uint8Array; ikX25519: Uint8Array; ephPubKey: Uint8Array; oneTimePreKey?: Uint8Array }
) {
    const keys = loadLocalKeys();
    if (!keys) throw new Error("No local pre-keys found! Cannot establish session.");

    const { session, usedOneTime } = await establishSessionAsResponder(
        identity,
        keys.spk,
        keys.otks,
        peerIdentity
    );

    if (usedOneTime) {
        const remainingOtks = keys.otks.filter(k => toBase64(k.keyPair.publicKey) !== toBase64(usedOneTime));
        storeLocalKeys(keys.spk, remainingOtks);
    }

    return { session, usedOneTime };
}

// --- Messaging ---

export async function encryptMessage(state: SessionState, text: string) {
    const { header, ciphertext } = await encrypt(state, new TextEncoder().encode(text));
    return {
        header,
        ciphertextHex: Buffer.from(ciphertext).toString('hex'),
        serializedHeader: JSON.parse(new TextDecoder().decode(serializeHeader(header))),
    };
}

export async function decryptMessage(state: SessionState, headerPayload: Record<string, unknown> | string, ciphertextHex: string) {
    const headerStr = typeof headerPayload === 'string' ? headerPayload : JSON.stringify(headerPayload);
    const header = deserializeHeader(headerStr);

    const ciphertext = Uint8Array.from(Buffer.from(ciphertextHex, 'hex'));

    const plaintext = await decrypt(state, header, ciphertext);
    return new TextDecoder().decode(plaintext);
}

export async function keyFingerprint(pub: Uint8Array) {
    return fingerprint(pub);
}

export function shortAuthCode(fp: string) {
    const short = fp.replace(/[^a-f0-9]/gi, '').slice(0, 15).toUpperCase();
    return short.match(/.{1,5}/g)?.join('-') ?? short;
}

// --- Session Storage ---

export function saveSessionToStorage(peerUsername: string, session: SessionState) {
    const serialized = serializeSession(session);
    localStorage.setItem(`securecomm.session.${peerUsername}`, serialized);
}

export function loadSessionFromStorage(peerUsername: string): SessionState | null {
    const raw = localStorage.getItem(`securecomm.session.${peerUsername}`);
    if (!raw) return null;
    try {
        return deserializeSession(raw);
    } catch (e) {
        console.error("Error loading session", e);
        return null;
    }
}