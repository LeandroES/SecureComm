import SessionState, {
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
    serializeSession,   // <--- Nuevo
    deserializeSession, // <--- Nuevo
    type Identity,
    type OneTimePreKey,
    type PreKeyBundle,
    type SessionHeader, // antes Header
    // antes Session
    type SignedPreKey,
} from '@securecomm/crypto-sdk';
import sodium from 'libsodium-wrappers';
import {raw} from "concurrently/dist/src/defaults";

// Tipos para almacenamiento local
export type StoredIdentity = {
    ikEd25519: string;
    ikX25519: string;
    ikSecret: string;
};

// Crypto Init Wrapper
export async function initCrypto() {
    await sodium.ready;
}

// Helpers de conversión
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

// --- PreKeys & Bundle ---

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

// --- Session Wrappers ---

// NOTA: El SDK actualizado devuelve session + header en initiator
export async function initiatorSession(identity: Identity, peer: PreKeyBundle) {
    const { session, header } = await establishSessionAsInitiator(identity, peer);
    // header no es el estado del header, es un fake header inicial, lo ignoramos aqui si no lo usamos inmediatamente
    return { session, headerState: header };
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

// --- Messaging ---

export async function encryptMessage(state: SessionState, text: string) {
    const { header, ciphertext } = await encrypt(state, new TextEncoder().encode(text));
    return {
        header,
        ciphertextHex: Buffer.from(ciphertext).toString('hex'),
        // Usamos el serializador JSON del header para el transporte
        serializedHeader: JSON.parse(new TextDecoder().decode(serializeHeader(header))),
    };
}

export async function decryptMessage(state: SessionState, headerPayload: Record<string, unknown> | string, ciphertextHex: string) {
    // Si viene como objeto del websocket, lo convertimos a string para deserializeHeader
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

// --- Session Storage Utilities ---
// Estos son vitales para guardar el estado complejo (Uint8Array anidados) en localStorage

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