import sodium from 'libsodium-wrappers';

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
    identityKeyEd25519: Uint8Array;
    signedPreKey: {
        id: number;
        publicKey: Uint8Array;
        signature: Uint8Array;
    };
    oneTimePreKey?: {
        id: number;
        publicKey: Uint8Array;
    };
};

export type SessionHeader = {
    dh: Uint8Array;
    pn: number; // Previous Chain Length
    n: number;  // Message Number
};

type SessionState = {
    // Claves raíz y de cadena
    rootKey: Uint8Array;
    chainKey: {
        send: Uint8Array;
        recv: Uint8Array | null; // Null hasta el primer ratchet
    };
    // Estado del Ratchet
    currentRatchetKey: KeyPair;
    remoteRatchetKey: Uint8Array | null;
    // Contadores
    n: {
        send: number;
        recv: number;
    };
    pn: number;
    // Gestión de mensajes perdidos/desordenados
    skippedMessageKeys: Record<string, Uint8Array>; // Clave: "pubKey:n", Valor: MessageKey
};
export default SessionState

export type EncryptedMessage = {
    header: SessionHeader;
    ciphertext: Uint8Array;
};

// --- Constants ---
// Signal usa strings específicos para HKDF
const INFO_HKDF_ROOT = 'SecureCommv1HKDFRoot';
const INFO_HKDF_RATCHET = 'SecureCommv1HKDFRatchet';
const INFO_HKDF_MESSAGE = 'SecureCommv1HKDFMessage';

// --- Helpers ---

async function ensureSodium(): Promise<void> {
    await sodium.ready;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// HKDF usando HMAC-SHA256 (Estándar Signal)
function hkdf(inputKeyMaterial: Uint8Array, salt: Uint8Array, info: string, length: number): Uint8Array {
    // Nota: Libsodium no tiene HKDF nativo expuesto directamente en todas las versiones wrappers,
    // así que lo construimos o usamos generichash si queremos simplicidad,
    // PERO para ser "Golden Standard" usamos una construcción KDF robusta.
    // Aquí usaremos BLAKE2b como KDF robusto ya que es nativo y muy rápido en sodium,
    // separando dominios con el parámetro 'info'.

    // Si prefieres estricta compatibilidad con Signal, deberíamos implementar HMAC-SHA256.
    // Por rendimiento y seguridad en este stack, usaremos crypto_generichash_blake2b_salt_personal
    // o simplemente generichash con claves derivadas.

    // Implementación simplificada robusta usando generichash (BLAKE2b)
    // Salt se usa como key para el hash
    const ctx = sodium.crypto_generichash(64, concat(inputKeyMaterial, new TextEncoder().encode(info)), salt);
    return ctx.slice(0, length);
}

// --- KDF Chains ---

function kdfRoot(rootKey: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
    // Salida: [NewRootKey, NewChainKey]
    const secret = hkdf(dhOut, rootKey, INFO_HKDF_ROOT, 64);
    return [secret.slice(0, 32), secret.slice(32, 64)];
}

function kdfChain(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
    // Salida: [MessageKey, NextChainKey]
    // Usamos un byte 0x01/0x02 para separar dominios dentro de la cadena
    const input = new Uint8Array(32).fill(0); // input constante (o salt)

    // Derivamos 64 bytes
    const secret = hkdf(input, chainKey, INFO_HKDF_MESSAGE, 64);
    return [secret.slice(0, 32), secret.slice(32, 64)];
}

// --- Implementation ---

export async function bootstrapIdentity(seed?: Uint8Array): Promise<Identity> {
    await ensureSodium();
    const validSeed = seed || sodium.randombytes_buf(32);

    // Ed25519 para firmas
    const edKey = sodium.crypto_sign_seed_keypair(validSeed);

    // Convertir Ed25519 a X25519 para el protocolo DH
    const x25519Pk = sodium.crypto_sign_ed25519_pk_to_curve25519(edKey.publicKey);
    const x25519Sk = sodium.crypto_sign_ed25519_sk_to_curve25519(edKey.privateKey);

    return {
        ikEd25519: { publicKey: edKey.publicKey, privateKey: edKey.privateKey },
        ikX25519: { publicKey: x25519Pk, privateKey: x25519Sk }
    };
}

export async function fingerprint(publicKey: Uint8Array): Promise<string> {
    await ensureSodium();
    const hash = sodium.crypto_generichash(32, publicKey);
    return sodium.to_hex(hash);
}

// --- Key Management ---

export async function generateSignedPreKey(identity: Identity): Promise<SignedPreKey> {
    await ensureSodium();
    const keyPair = sodium.crypto_box_keypair();
    const signature = sodium.crypto_sign_detached(keyPair.publicKey, identity.ikEd25519.privateKey);

    return {
        keyPair: { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey },
        signature,
        id: Math.floor(Math.random() * 0xffffff)
    };
}

export async function generateOneTimePreKeys(count: number): Promise<OneTimePreKey[]> {
    await ensureSodium();
    const keys: OneTimePreKey[] = [];
    for (let i = 0; i < count; i++) {
        const kp = sodium.crypto_box_keypair();
        keys.push({
            keyPair: { publicKey: kp.publicKey, privateKey: kp.privateKey },
            id: i // En producción, usar IDs persistentes de BD
        });
    }
    return keys;
}

export async function exportBundle(
    identity: Identity,
    spk: SignedPreKey,
    otk?: OneTimePreKey
): Promise<PreKeyBundle> {
    return {
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
    };
}

// --- X3DH ---

async function x3dh(
    identity: Identity,
    ephemeral: KeyPair,
    peerBundle: PreKeyBundle
): Promise<Uint8Array> {
    await ensureSodium();

    // Validar firma del Signed PreKey
    const validSig = sodium.crypto_sign_verify_detached(
        peerBundle.signedPreKey.signature,
        peerBundle.signedPreKey.publicKey,
        peerBundle.identityKeyEd25519
    );
    if (!validSig) throw new Error("Invalid SignedPreKey signature");

    const dh1 = sodium.crypto_scalarmult(identity.ikX25519.privateKey, peerBundle.signedPreKey.publicKey);
    const dh2 = sodium.crypto_scalarmult(ephemeral.privateKey, peerBundle.identityKey);
    const dh3 = sodium.crypto_scalarmult(ephemeral.privateKey, peerBundle.signedPreKey.publicKey);

    let dhResult = concat(dh1, dh2, dh3);

    if (peerBundle.oneTimePreKey) {
        const dh4 = sodium.crypto_scalarmult(ephemeral.privateKey, peerBundle.oneTimePreKey.publicKey);
        dhResult = concat(dhResult, dh4);
    }

    // Initial Root Key Derivation
    return hkdf(dhResult, new Uint8Array(32), INFO_HKDF_ROOT, 32);
}

// --- Session Establishment ---

export async function establishSessionAsInitiator(
    identity: Identity,
    peerBundle: PreKeyBundle
): Promise<{ session: SessionState, header: SessionHeader }> { // Changed return type specifically
    await ensureSodium();
    const ephemeral = sodium.crypto_box_keypair();
    const sk = await x3dh(identity, { publicKey: ephemeral.publicKey, privateKey: ephemeral.privateKey }, peerBundle);

    // Initial Ratchet
    const [rootKey, chainKey] = kdfRoot(sk, sodium.crypto_scalarmult(ephemeral.privateKey, peerBundle.signedPreKey.publicKey));

    return {
        session: {
            rootKey,
            chainKey: { send: chainKey, recv: null },
            currentRatchetKey: { publicKey: ephemeral.publicKey, privateKey: ephemeral.privateKey },
            remoteRatchetKey: peerBundle.signedPreKey.publicKey,
            n: { send: 0, recv: 0 },
            pn: 0,
            skippedMessageKeys: {}
        },
        header: { // Fake header just to carry the initial ratchet key
            dh: ephemeral.publicKey,
            n: 0,
            pn: 0
        }
    };
}

export async function establishSessionAsResponder(
    identity: Identity,
    spk: SignedPreKey,
    otks: OneTimePreKey[],
    peerIdentity: {
        ikX25519: Uint8Array;
        ikEd25519: Uint8Array;
        ephPubKey: Uint8Array;
        oneTimePreKey?: Uint8Array
    }
): Promise<{ session: SessionState, usedOneTime?: Uint8Array }> {
    await ensureSodium();

    const dh1 = sodium.crypto_scalarmult(spk.keyPair.privateKey, peerIdentity.ikX25519);
    const dh2 = sodium.crypto_scalarmult(identity.ikX25519.privateKey, peerIdentity.ephPubKey);
    const dh3 = sodium.crypto_scalarmult(spk.keyPair.privateKey, peerIdentity.ephPubKey);

    let dhResult = concat(dh1, dh2, dh3);
    let usedOtk: Uint8Array | undefined;

    if (peerIdentity.oneTimePreKey) {
        // Find matching OTK
        const match = otks.find(k => sodium.memcmp(k.keyPair.publicKey, peerIdentity.oneTimePreKey!) === true);
        if (!match) throw new Error("OneTimePreKey not found locally");

        const dh4 = sodium.crypto_scalarmult(match.keyPair.privateKey, peerIdentity.ephPubKey);
        dhResult = concat(dhResult, dh4);
        usedOtk = match.keyPair.publicKey;
    }

    const sk = hkdf(dhResult, new Uint8Array(32), INFO_HKDF_ROOT, 32);

    // Initial Ratchet (Responder Side)
    // El responder "recibe" el ratchet inicial implícitamente
    const [rootKey, recvChainKey] = kdfRoot(sk, sodium.crypto_scalarmult(spk.keyPair.privateKey, peerIdentity.ephPubKey));

    // Prepare first sending ratchet immediately
    const nextPair = sodium.crypto_box_keypair();
    const dhOut = sodium.crypto_scalarmult(nextPair.privateKey, peerIdentity.ephPubKey);
    const [newRootKey, sendChainKey] = kdfRoot(rootKey, dhOut);

    return {
        session: {
            rootKey: newRootKey,
            chainKey: { send: sendChainKey, recv: recvChainKey },
            currentRatchetKey: { publicKey: nextPair.publicKey, privateKey: nextPair.privateKey },
            remoteRatchetKey: peerIdentity.ephPubKey,
            n: { send: 0, recv: 0 },
            pn: 0,
            skippedMessageKeys: {}
        },
        usedOneTime: usedOtk
    };
}

// --- Encryption Flow ---

function getHeaderKey(header: SessionHeader): string {
    return `${sodium.to_base64(header.dh)}:${header.n}`;
}

export async function encrypt(session: SessionState, plaintext: Uint8Array): Promise<EncryptedMessage> {
    await ensureSodium();

    const [messageKey, nextChainKey] = kdfChain(session.chainKey.send);
    session.chainKey.send = nextChainKey;

    const header: SessionHeader = {
        dh: session.currentRatchetKey.publicKey,
        n: session.n.send,
        pn: session.pn
    };
    session.n.send++;

    const headerBytes = serializeHeader(header);

    // XChaCha20Poly1305 nonce (24 bytes) -> Podemos usar random o derivado.
    // Para DR estándar, la clave es única, así que un nonce constante es seguro,
    // pero XChaCha prefiere random. Usaremos random para máxima seguridad.
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        headerBytes, // Associated Data
        null,
        nonce,
        messageKey
    );

    // Concatenamos el nonce al ciphertext para enviarlo
    const combinedCiphertext = concat(nonce, ciphertext);

    return { header, ciphertext: combinedCiphertext };
}

export async function decrypt(session: SessionState, header: SessionHeader, ciphertextWithNonce: Uint8Array): Promise<Uint8Array> {
    await ensureSodium();

    // 1. Try skipped keys
    const headerKeyStr = getHeaderKey(header);
    if (session.skippedMessageKeys[headerKeyStr]) {
        const mk = session.skippedMessageKeys[headerKeyStr];
        delete session.skippedMessageKeys[headerKeyStr];
        return decryptWithKey(mk, header, ciphertextWithNonce);
    }

    // 2. Check if ratchet step is needed
    if (session.remoteRatchetKey && !sodium.memcmp(header.dh, session.remoteRatchetKey)) {
        // Skip remaining keys in current chain
        await skipMessageKeys(session, header.pn);

        // Perform Ratchet Step
        await ratchet(session, header);
    }

    // 3. Skip keys in new chain if needed
    await skipMessageKeys(session, header.n);

    // 4. Decrypt
    const [messageKey, nextChainKey] = kdfChain(session.chainKey.recv!);
    session.chainKey.recv = nextChainKey;
    session.n.recv++;

    return decryptWithKey(messageKey, header, ciphertextWithNonce);
}

function decryptWithKey(key: Uint8Array, header: SessionHeader, ciphertextWithNonce: Uint8Array): Uint8Array {
    const headerBytes = serializeHeader(header);
    const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = ciphertextWithNonce.slice(0, nonceLen);
    const ciphertext = ciphertextWithNonce.slice(nonceLen);

    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        headerBytes,
        nonce,
        key
    );
}

async function skipMessageKeys(session: SessionState, until: number) {
    if (!session.chainKey.recv) return;
    while (session.n.recv < until) {
        const [mk, nextCk] = kdfChain(session.chainKey.recv);
        session.chainKey.recv = nextCk;

        // Store skipped key
        const h: SessionHeader = {
            dh: session.remoteRatchetKey!,
            n: session.n.recv,
            pn: session.pn // actually unrelated for map key
        };
        session.skippedMessageKeys[getHeaderKey(h)] = mk;
        session.n.recv++;
    }
}

async function ratchet(session: SessionState, header: SessionHeader) {
    const prevRemote = session.remoteRatchetKey;
    // DH Ratchet 1 (Receive)
    const dh1 = sodium.crypto_scalarmult(session.currentRatchetKey.privateKey, header.dh);
    const [root1, chainRecv] = kdfRoot(session.rootKey, dh1);

    session.rootKey = root1;
    session.chainKey.recv = chainRecv;
    session.remoteRatchetKey = header.dh;
    session.n.recv = 0;

    // DH Ratchet 2 (Send)
    const nextPair = sodium.crypto_box_keypair();
    const dh2 = sodium.crypto_scalarmult(nextPair.privateKey, header.dh);
    const [root2, chainSend] = kdfRoot(session.rootKey, dh2);

    session.rootKey = root2;
    session.chainKey.send = chainSend;
    session.currentRatchetKey = { publicKey: nextPair.publicKey, privateKey: nextPair.privateKey };
    session.pn = session.n.send;
    session.n.send = 0;
}

// --- Serialization Helpers (CRUCIAL para localStorage) ---

export function serializeHeader(header: SessionHeader): Uint8Array {
    const json = JSON.stringify({
        d: sodium.to_base64(header.dh),
        n: header.n,
        p: header.pn
    });
    return sodium.from_string(json);
}

export function deserializeHeader(data: Uint8Array | string): SessionHeader {
    const json = typeof data === 'string' ? data : sodium.to_string(data);
    const parsed = JSON.parse(json);
    return {
        dh: sodium.from_base64(parsed.d),
        n: parsed.n,
        pn: parsed.p
    };
}

// Convierte el estado binario a JSON-safe para guardar
export function serializeSession(session: SessionState): string {
    return JSON.stringify(session, (_, value) => {
        if (value instanceof Uint8Array) {
            return { __type: 'bytes', data: sodium.to_base64(value) };
        }
        return value;
    });
}

// Recupera el estado binario desde JSON
export function deserializeSession(json: string): SessionState {
    return JSON.parse(json, (_, value) => {
        if (value && value.__type === 'bytes') {
            return sodium.from_base64(value.data);
        }
        return value;
    }) as SessionState;
}

// Helper para rotar claves pre-firmadas (opcional, wrapper)
export async function rotateSignedPreKey(identity: Identity): Promise<SignedPreKey> {
    return generateSignedPreKey(identity);
}

export async function replenishOneTimePreKeys(count: number): Promise<OneTimePreKey[]> {
    return generateOneTimePreKeys(count);
}