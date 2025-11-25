import sodium from 'libsodium-wrappers';
import { createHash } from 'node:crypto'; // Fallback nativo para estabilidad

// --- Type Definitions ---

export type KeyPair = {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
};

export type Identity = {
    ikEd25519: KeyPair;
    ikX25519: KeyPair;
};

export type SignedPreKey = {
    keyPair: KeyPair;
    signature: Uint8Array;
    id: number;
};

export type OneTimePreKey = {
    keyPair: KeyPair;
    id: number;
};

export type PreKeyBundle = {
    identityKey: Uint8Array;
    signedPreKey: {
        id: number;
        publicKey: Uint8Array;
        signature: Uint8Array;
    };
    oneTimePreKey?: {
        id: number;
        publicKey: Uint8Array;
    };
    identityKeyEd25519: Uint8Array;
};

export type Header = {
    dh: Uint8Array;
    n: number;
    pn: number;
};

export type Session = {
    rootKey: Uint8Array;
    chainKey: {
        send: Uint8Array;
        recv: Uint8Array;
    };
    nextHeaderKey: {
        send: Uint8Array;
        recv: Uint8Array;
    };
    currentRatchetKey: KeyPair;
    remoteRatchetKey: Uint8Array | null;
    n: {
        send: number;
        recv: number;
    };
    pn: number;
    skippedMessageKeys: Record<string, Uint8Array>;
};

export type EncryptedMessage = {
    header: Header;
    ciphertext: Uint8Array;
};

// --- Constants ---
const KDF_SALT = new Uint8Array(32);

// --- State & Helpers ---

let sodiumInstance: any | null = null;

async function getSodium(): Promise<any> {
    if (sodiumInstance) return sodiumInstance;

    await sodium.ready;

    // Intentamos resolver la instancia correcta manejando exportaciones default/named
    const candidates = [
        sodium,
        (sodium as any).default,
        (sodium as any).sodium
    ];

    for (const c of candidates) {
        // Buscamos 'crypto_generichash' como indicador de carga exitosa
        // (ya que crypto_hash_sha256 ha demostrado ser problemática en detección)
        if (c && typeof c.crypto_generichash === 'function') {
            sodiumInstance = c;
            return sodiumInstance;
        }
    }

    sodiumInstance = sodium;
    return sodiumInstance;
}

// Getter síncrono para operaciones atómicas (encrypt)
function getSodiumSync(): any {
    if (!sodiumInstance) throw new Error("Sodium not initialized. Call bootstrapIdentity or init first.");
    return sodiumInstance;
}

function cloneSession(session: Session): Session {
    return {
        rootKey: new Uint8Array(session.rootKey),
        chainKey: {
            send: new Uint8Array(session.chainKey.send),
            recv: new Uint8Array(session.chainKey.recv)
        },
        nextHeaderKey: {
            send: new Uint8Array(session.nextHeaderKey.send),
            recv: new Uint8Array(session.nextHeaderKey.recv)
        },
        currentRatchetKey: {
            publicKey: new Uint8Array(session.currentRatchetKey.publicKey),
            privateKey: new Uint8Array(session.currentRatchetKey.privateKey)
        },
        remoteRatchetKey: session.remoteRatchetKey ? new Uint8Array(session.remoteRatchetKey) : null,
        n: { ...session.n },
        pn: session.pn,
        skippedMessageKeys: { ...session.skippedMessageKeys }
    };
}

async function kdf(km: Uint8Array, input: Uint8Array): Promise<Uint8Array> {
    const s = await getSodium();
    return s.crypto_generichash(64, input, km);
}

function kdfChainSync(s: any, chainKey: Uint8Array): [Uint8Array, Uint8Array] {
    const mkInput = new Uint8Array([0x01]);
    const ckInput = new Uint8Array([0x02]);
    const messageKey = s.crypto_generichash(32, mkInput, chainKey);
    const nextChainKey = s.crypto_generichash(32, ckInput, chainKey);
    return [messageKey, nextChainKey];
}

async function kdfChain(chainKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
    const s = await getSodium();
    return kdfChainSync(s, chainKey);
}

// --- Implementation ---

export async function bootstrapIdentity(seed: Uint8Array): Promise<Identity> {
    const s = await getSodium();
    const edKey = s.crypto_sign_seed_keypair(seed);

    const x25519Pk = s.crypto_sign_ed25519_pk_to_curve25519(edKey.publicKey);
    const x25519Sk = s.crypto_sign_ed25519_sk_to_curve25519(edKey.privateKey);

    return {
        ikEd25519: { publicKey: edKey.publicKey, privateKey: edKey.privateKey },
        ikX25519: { publicKey: x25519Pk, privateKey: x25519Sk }
    };
}

export async function fingerprint(publicKey: Uint8Array): Promise<string> {
    const s = await getSodium();

    // Solución Robusta:
    // Intentamos usar libsodium. Si falla (por problemas de importación en test),
    // usamos Node.js crypto nativo. El resultado SHA-256 es estándar e idéntico.
    if (typeof s.crypto_hash_sha256 === 'function') {
        const hash = s.crypto_hash_sha256(publicKey);
        return s.to_hex(hash);
    } else {
        // Fallback seguro usando la librería estándar de Node
        const hashNode = createHash('sha256').update(publicKey).digest();
        return s.to_hex(new Uint8Array(hashNode));
    }
}

// --- Key Management ---

export async function generateSignedPreKey(identity: Identity): Promise<SignedPreKey> {
    const s = await getSodium();
    const keyPair = s.crypto_box_keypair();
    const signature = s.crypto_sign_detached(keyPair.publicKey, identity.ikEd25519.privateKey);

    return {
        keyPair: { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey },
        signature,
        id: Math.floor(Math.random() * 100000)
    };
}

export async function generateOneTimePreKeys(count: number, seed?: Uint8Array): Promise<OneTimePreKey[]> {
    const s = await getSodium();
    const keys: OneTimePreKey[] = [];

    for (let i = 0; i < count; i++) {
        let kp;
        if (seed) {
            const derivedSeed = s.crypto_generichash(32, new Uint8Array([i]), seed);
            kp = s.crypto_box_seed_keypair(derivedSeed);
        } else {
            kp = s.crypto_box_keypair();
        }
        keys.push({
            keyPair: { publicKey: kp.publicKey, privateKey: kp.privateKey },
            id: i
        });
    }
    return keys;
}

export async function exportBundle(
    identity: Identity,
    spk: SignedPreKey,
    otk?: OneTimePreKey
): Promise<PreKeyBundle> {
    return Promise.resolve({
        identityKey: identity.ikX25519.publicKey,
        identityKeyEd25519: identity.ikEd25519.publicKey,
        signedPreKey: {
            id: spk.id,
            publicKey: spk.keyPair.publicKey,
            signature: spk.signature
        },
        oneTimePreKey: otk ? {
            id: otk.id,
            publicKey: otk.keyPair.publicKey
        } : undefined
    });
}

export async function rotateSignedPreKey(identity: Identity): Promise<SignedPreKey> {
    return generateSignedPreKey(identity);
}

export async function replenishOneTimePreKeys(count: number): Promise<OneTimePreKey[]> {
    return generateOneTimePreKeys(count);
}

// --- Session Handshake (X3DH) ---

async function x3dh(
    identity: Identity,
    ephemeral: KeyPair,
    remoteId: Uint8Array,
    remoteSpk: Uint8Array,
    remoteOtk: Uint8Array | undefined
): Promise<Uint8Array> {
    const s = await getSodium();

    const dh1 = s.crypto_scalarmult(identity.ikX25519.privateKey, remoteSpk);
    const dh2 = s.crypto_scalarmult(ephemeral.privateKey, remoteId);
    const dh3 = s.crypto_scalarmult(ephemeral.privateKey, remoteSpk);

    let dhResult = new Uint8Array([...dh1, ...dh2, ...dh3]);

    if (remoteOtk) {
        const dh4 = s.crypto_scalarmult(ephemeral.privateKey, remoteOtk);
        dhResult = new Uint8Array([...dhResult, ...dh4]);
    }

    const sharedSecret = s.crypto_generichash(32, dhResult, KDF_SALT);
    return sharedSecret;
}

export async function establishSessionAsInitiator(
    identity: Identity,
    bundle: PreKeyBundle
): Promise<{ session: Session }> {
    const s = await getSodium();
    const ephemeral = s.crypto_box_keypair();

    const ephemeralKeyPair: KeyPair = {
        publicKey: ephemeral.publicKey,
        privateKey: ephemeral.privateKey
    };

    const sk = await x3dh(
        identity,
        ephemeralKeyPair,
        bundle.identityKey,
        bundle.signedPreKey.publicKey,
        bundle.oneTimePreKey?.publicKey
    );

    return {
        session: {
            rootKey: sk,
            chainKey: { send: new Uint8Array(32), recv: new Uint8Array(32) },
            nextHeaderKey: { send: new Uint8Array(32), recv: new Uint8Array(32) },
            currentRatchetKey: ephemeralKeyPair,
            remoteRatchetKey: bundle.signedPreKey.publicKey,
            n: { send: 0, recv: 0 },
            pn: 0,
            skippedMessageKeys: {}
        }
    };
}

export async function establishSessionAsResponder(
    identity: Identity,
    spk: SignedPreKey,
    _otks: OneTimePreKey[],
    publicKeys: { ikEd25519: Uint8Array; ephPubKey: Uint8Array; ikX25519: Uint8Array; oneTimePreKey?: Uint8Array }
): Promise<{ session: Session }> {
    const s = await getSodium();

    const dh1 = s.crypto_scalarmult(spk.keyPair.privateKey, publicKeys.ikX25519);
    const dh2 = s.crypto_scalarmult(identity.ikX25519.privateKey, publicKeys.ephPubKey);
    const dh3 = s.crypto_scalarmult(spk.keyPair.privateKey, publicKeys.ephPubKey);

    let dhResult = new Uint8Array([...dh1, ...dh2, ...dh3]);

    if (publicKeys.oneTimePreKey) {
        const match = _otks.find(k => s.memcmp(k.keyPair.publicKey, publicKeys.oneTimePreKey!) === true);
        if (match) {
            const dh4 = s.crypto_scalarmult(match.keyPair.privateKey, publicKeys.ephPubKey);
            dhResult = new Uint8Array([...dhResult, ...dh4]);
        }
    }

    const sk = s.crypto_generichash(32, dhResult, KDF_SALT);

    return {
        session: {
            rootKey: sk,
            chainKey: { send: new Uint8Array(32), recv: new Uint8Array(32) },
            nextHeaderKey: { send: new Uint8Array(32), recv: new Uint8Array(32) },
            currentRatchetKey: spk.keyPair,
            remoteRatchetKey: publicKeys.ephPubKey,
            n: { send: 0, recv: 0 },
            pn: 0,
            skippedMessageKeys: {}
        }
    };
}

// --- Encryption / Decryption ---

export function serializeHeader(header: Header): Uint8Array {
    const s = sodiumInstance || sodium;
    // @ts-ignore
    const json = JSON.stringify({
        d: (s as any).to_base64(header.dh),
        n: header.n,
        p: header.pn
    });
    return (s as any).from_string(json);
}

export function deserializeHeader(data: Uint8Array): Header {
    const s = sodiumInstance || sodium;
    try {
        const json = (s as any).to_string(data);
        const parsed = JSON.parse(json);
        return {
            dh: (s as any).from_base64(parsed.d),
            n: parsed.n,
            pn: parsed.p
        };
    } catch {
        throw new Error('Invalid header');
    }
}

async function ratchet(session: Session, header: Header) {
    const s = await getSodium();

    if (session.remoteRatchetKey && !s.memcmp(header.dh, session.remoteRatchetKey)) {
        const dhOut = s.crypto_scalarmult(session.currentRatchetKey.privateKey, header.dh);

        const kdfOut = await kdf(session.rootKey, dhOut);
        session.rootKey = kdfOut.slice(0, 32);
        session.chainKey.recv = kdfOut.slice(32, 64);

        const nextPairRaw = s.crypto_box_keypair();
        session.currentRatchetKey = {
            publicKey: nextPairRaw.publicKey,
            privateKey: nextPairRaw.privateKey
        };

        const dhOut2 = s.crypto_scalarmult(session.currentRatchetKey.privateKey, header.dh);

        const kdfOut2 = await kdf(session.rootKey, dhOut2);
        session.rootKey = kdfOut2.slice(0, 32);
        session.chainKey.send = kdfOut2.slice(32, 64);

        session.remoteRatchetKey = header.dh;
        session.pn = session.n.send;
        session.n.send = 0;
        session.n.recv = 0;
    }
}

export function encrypt(session: Session, plaintext: Uint8Array): Promise<EncryptedMessage> {
    const s = getSodiumSync();

    const [messageKey, nextChainKey] = kdfChainSync(s, session.chainKey.send);
    session.chainKey.send = nextChainKey;

    const header: Header = {
        dh: session.currentRatchetKey.publicKey,
        n: session.n.send,
        pn: session.pn
    };
    session.n.send++;

    return Promise.resolve().then(() => {
        const headerBytes = serializeHeader(header);
        const nonce = new Uint8Array(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        new DataView(nonce.buffer).setUint32(0, header.n, true);

        const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            headerBytes,
            nonce,
            nonce,
            messageKey
        );
        return { header, ciphertext };
    });
}

export async function decrypt(session: Session, header: Header, ciphertext: Uint8Array): Promise<Uint8Array> {
    const s = await getSodium();
    const snapshot = cloneSession(session);

    try {
        await ratchet(session, header);

        while (session.n.recv < header.n) {
            const [mk, nextCk] = await kdfChain(session.chainKey.recv);
            session.skippedMessageKeys[`${session.n.recv}`] = mk;
            session.chainKey.recv = nextCk;
            session.n.recv++;
        }

        let messageKey: Uint8Array;

        if (header.n === session.n.recv) {
            const [mk, nextCk] = await kdfChain(session.chainKey.recv);
            messageKey = mk;
            session.chainKey.recv = nextCk;
            session.n.recv++;
        } else {
            messageKey = session.skippedMessageKeys[`${header.n}`];
            if (!messageKey) {
                throw new Error('Message key not found (too old or undecryptable)');
            }
            delete session.skippedMessageKeys[`${header.n}`];
        }

        const headerBytes = serializeHeader(header);
        const nonce = new Uint8Array(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        new DataView(nonce.buffer).setUint32(0, header.n, true);

        const plaintext = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            ciphertext,
            headerBytes,
            nonce,
            messageKey
        );

        return plaintext;

    } catch (error) {
        Object.assign(session, snapshot);
        throw error;
    }
}

// --- Legacy Provider ---
export interface CryptoProvider {
    init(): Promise<void>;
    generateIdentityKeyPair(): Promise<KeyPair>;
}

class SodiumCryptoProvider implements CryptoProvider {
    private initialized = false;
    private sodium!: any;

    async init(): Promise<void> {
        if (this.initialized) return;
        this.sodium = await getSodium();
        this.initialized = true;
    }

    async generateIdentityKeyPair(): Promise<KeyPair> {
        if (!this.initialized) await this.init();
        const { publicKey, privateKey } = this.sodium.crypto_sign_keypair();
        return {
            publicKey,
            privateKey,
        };
    }
}

export const cryptoProvider = new SodiumCryptoProvider();