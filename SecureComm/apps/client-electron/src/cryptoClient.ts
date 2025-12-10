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
    // FIX: Usar URLSAFE_NO_PADDING para coincidir con el nuevo estándar del SDK
    return sodium.to_base64(data, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function fromBase64(data: string): Uint8Array {
    // FIX: Usar URLSAFE_NO_PADDING para el formato
    // FIX TEST: Envolver en new Uint8Array() para que JSDOM/Vitest reconozcan el tipo
    return new Uint8Array(sodium.from_base64(data, sodium.base64_variants.URLSAFE_NO_PADDING));
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

    // FIX: Devolver la identidad recargada desde el storage.
    // Esto asegura que las llaves pasen por el "lavado" de fromBase64
    // y sean 100% compatibles con los tests y el resto de la app.
    return loadIdentity()!;
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
    handshake: {
        ikX25519: Uint8Array;
        ikEd25519: Uint8Array;
        ephPubKey: Uint8Array;
        oneTimePreKey?: Uint8Array;
    }
) {
    // FIX: Cargar las llaves PRIVADAS del almacenamiento local
    // (Antes fallaba porque intentábamos usar la llave pública del mensaje)
    const storedKeysJson = localStorage.getItem('securecomm.keys');
    if (!storedKeysJson) {
        throw new Error("No se encontraron llaves privadas (securecomm.keys) para descifrar el handshake.");
    }

    const storedKeys = JSON.parse(storedKeysJson) as StoredKeys;

    // Reconstruir SPK con clave privada
    const mySpk: SignedPreKey = {
        id: storedKeys.spk.id,
        signature: fromBase64(storedKeys.spk.signature),
        keyPair: {
            publicKey: fromBase64(storedKeys.spk.keyPair.publicKey),
            privateKey: fromBase64(storedKeys.spk.keyPair.privateKey)
        }
    };

    // Buscar la OTK privada correspondiente
    let myOtk: OneTimePreKey | undefined = undefined;

    if (handshake.oneTimePreKey) {
        // Convertimos a Base64 para buscar en la lista
        const targetPub = toBase64(handshake.oneTimePreKey);
        const found = storedKeys.otks.find(k => k.keyPair.publicKey === targetPub);

        if (found) {
            myOtk = {
                id: found.id,
                keyPair: {
                    publicKey: fromBase64(found.keyPair.publicKey),
                    privateKey: fromBase64(found.keyPair.privateKey)
                }
            };
        } else {
            console.warn(`[X3DH] OTK pública recibida (${targetPub}) no encontrada localmente.`);
        }
    }

    // Establecer sesión con las llaves privadas correctas
    const { session, usedOneTime } = await establishSessionAsResponder(
        identity,
        mySpk,
        myOtk ? [myOtk] : [],
        {
            // ✅ CORRECCIÓN: Pasar los Uint8Array directamente, no objetos anidados
            ikEd25519: handshake.ikEd25519,
            ikX25519: handshake.ikX25519,
            // ✅ CORRECCIÓN: Pasar ephPubKey DENTRO de este objeto
            ephPubKey: handshake.ephPubKey,
            oneTimePreKey: handshake.oneTimePreKey
        }
    );

    // Si se usó una OTK, la borramos del almacenamiento para evitar reuso (Forward Secrecy)
    if (usedOneTime) {
        const remainingOtks = storedKeys.otks.filter(k => k.keyPair.publicKey !== toBase64(usedOneTime));
        // Guardamos de nuevo sin la llave usada
        const newPayload: StoredKeys = {
            ...storedKeys,
            otks: remainingOtks
        };
        localStorage.setItem('securecomm.keys', JSON.stringify(newPayload));
    }

    return { session };
}

// --- Messaging ---

export async function encryptMessage(state: SessionState, text: string) {
    // FIX: Envolvemos en new Uint8Array() para compatibilidad estricta con libsodium en tests
    const plaintextBytes = new Uint8Array(sodium.from_string(text));

    const { header, ciphertext } = await encrypt(state, plaintextBytes);

    // Serializamos header para transporte
    const headerJson = sodium.to_string(serializeHeader(header));

    return {
        header,
        ciphertextHex: Buffer.from(ciphertext).toString('hex'),
        serializedHeader: JSON.parse(headerJson),
    };
}

export async function decryptMessage(state: SessionState, headerPayload: Record<string, unknown> | string, ciphertextHex: string) {
    const headerStr = typeof headerPayload === 'string' ? headerPayload : JSON.stringify(headerPayload);
    const header = deserializeHeader(headerStr);

    const ciphertext = new Uint8Array(Buffer.from(ciphertextHex, 'hex'));

    const plaintext = await decrypt(state, header, ciphertext);

    // FIX: U  samos utilidades de sodium para decodificar
    return sodium.to_string(plaintext);
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