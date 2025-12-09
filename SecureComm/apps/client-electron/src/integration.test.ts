import { describe, it, expect, beforeAll } from 'vitest';
import {
    initCrypto,
    createIdentity,
    generateBundle,
    initiatorSession,
    encryptMessage,
    autoResponderSession,
    decryptMessage,
    toBase64,
    fromBase64
} from './cryptoClient';

describe('Test de Integración: Flujo Completo X3DH', () => {
    beforeAll(async () => {
        await initCrypto();
    });

    it('Debe permitir a Alice enviar el primer mensaje y a Bob desencriptarlo', async () => {
        // -------------------------------------------------------------------
        // 1. PREPARACIÓN (Identidades)
        // -------------------------------------------------------------------
        console.log('1. Generando identidades...');
        const aliceId = await createIdentity();
        const bobId = await createIdentity();

        // Bob genera sus llaves para subir al servidor (Bundle)
        const bobGen = await generateBundle(bobId, 1);
        const bobSPK = bobGen.spk;
        const bobOTK = bobGen.otks[0]; // Usamos la primera One-Time Key

        // Simulamos que Alice descarga el bundle de Bob
        const peerBundleForAlice = {
            identityKey: bobId.ikX25519.publicKey,
            identityKeyEd25519: bobId.ikEd25519.publicKey,
            signedPreKey: {
                id: 1,
                publicKey: bobSPK.keyPair.publicKey,
                signature: bobSPK.signature
            },
            oneTimePreKey: {
                id: 1,
                publicKey: bobOTK.keyPair.publicKey
            }
        };

        // -------------------------------------------------------------------
        // 2. INICIO DE SESIÓN (Alice)
        // -------------------------------------------------------------------
        console.log('2. Alice iniciando sesión...');
        const { session: aliceSession } = await initiatorSession(aliceId, peerBundleForAlice);

        // Verificamos que la sesión se creó
        expect(aliceSession).toBeDefined();

        // -------------------------------------------------------------------
        // 3. ENCRIPTADO (El paso donde fallaba App.tsx)
        // -------------------------------------------------------------------
        console.log('3. Alice encriptando mensaje "Hola"...');
        const messageText = "Hola, esto es una prueba";
        const { header, ciphertextHex, serializedHeader } = await encryptMessage(aliceSession, messageText);

        // --- SIMULACIÓN DE TU LÓGICA DE APP.TSX ---
        let finalHeader: any = { ...serializedHeader };

        // Esta es la corrección que hicimos: verificar header.n, NO session.n
        if (header.n === 0) {
            console.log('   -> Detectado mensaje 0, adjuntando cabecera X3DH');
            finalHeader.x3dh = {
                otk: toBase64(bobOTK.keyPair.publicKey) // Simulamos el OTK usado
            };
        }
        // -------------------------------------------

        // ASEVERACIÓN CRÍTICA: El mensaje final DEBE tener x3dh
        expect(header.n).toBe(0);
        expect(finalHeader.x3dh).toBeDefined();
        expect(finalHeader.x3dh.otk).toBeDefined();

        // -------------------------------------------------------------------
        // 4. RECEPCIÓN (Bob)
        // -------------------------------------------------------------------
        console.log('4. Bob recibiendo mensaje...');

        const senderIkX = aliceId.ikX25519.publicKey;
        const senderIkEd = aliceId.ikEd25519.publicKey;

        // CORRECCIÓN: Usar 'd' en lugar de 'dh' porque estamos leyendo el formato serializado (Wire Format)
        // finalHeader viene de serializedHeader, donde las claves están minificadas.
        const ephKey = fromBase64(finalHeader.d);

        const usedOtk = fromBase64(finalHeader.x3dh.otk);

        const { session: bobSession } = await autoResponderSession(bobId, {
            ikX25519: senderIkX,
            ikEd25519: senderIkEd,
            ephPubKey: ephKey,
            oneTimePreKey: usedOtk
        });

        expect(bobSession).toBeDefined();

        // -------------------------------------------------------------------
        // 5. DESENCRIPTADO
        // -------------------------------------------------------------------
        console.log('5. Bob desencriptando...');
        const decryptedText = await decryptMessage(bobSession, finalHeader, ciphertextHex);

        console.log(`   -> Texto Descifrado: "${decryptedText}"`);
        expect(decryptedText).toBe(messageText);
    });
});