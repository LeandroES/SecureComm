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

describe('Test de Integración: Diagnóstico X3DH', () => {
    beforeAll(async () => {
        await initCrypto();
    });

    it('Debe coincidir todas las llaves entre Alice y Bob', async () => {
        // 1. Identidades
        const aliceId = await createIdentity();
        const bobId = await createIdentity();

        // 2. Bundle de Bob
        const bobGen = await generateBundle(bobId, 1);
        const bobSPK = bobGen.spk;
        const bobOTK = bobGen.otks[0];

        // 3. Alice inicia sesión
        const peerBundleForAlice = {
            identityKey: bobId.ikX25519.publicKey,
            identityKeyEd25519: bobId.ikEd25519.publicKey,
            signedPreKey: {
                id: bobSPK.id,
                publicKey: bobSPK.keyPair.publicKey,
                signature: bobSPK.signature
            },
            oneTimePreKey: {
                id: bobOTK.id,
                publicKey: bobOTK.keyPair.publicKey
            }
        };

        const { session: aliceSession } = await initiatorSession(aliceId, peerBundleForAlice);

        // 4. Alice Encripta
        const messageText = "Hola Mundo";
        const { header, ciphertextHex, serializedHeader } = await encryptMessage(aliceSession, messageText);

        let finalHeader: any = { ...serializedHeader };
        if (header.n === 0) {
            finalHeader.x3dh = {
                otk: toBase64(bobOTK.keyPair.publicKey)
            };
        }

        // 5. Bob prepara su sesión
        const ephKeyFromMsg = fromBase64(finalHeader.d);
        const otkFromMsg = fromBase64(finalHeader.x3dh.otk);

        // --- DIAGNÓSTICO: COMPARACIÓN DE LLAVES ---
        console.log('\n--- REPORTE DE LLAVES ---');

        console.log('1. Clave Efímera (EK):');
        console.log('   Alice Generó:', toBase64(aliceSession.currentRatchetKey.publicKey));
        console.log('   Bob Recibió :', toBase64(ephKeyFromMsg));

        console.log('2. Clave Identidad Alice (IK_A):');
        console.log('   Alice Tiene :', toBase64(aliceId.ikX25519.publicKey));
        console.log('   Bob Recibe  :', toBase64(aliceId.ikX25519.publicKey)); // Simulamos lo que pasamos

        console.log('3. Clave Identidad Bob (IK_B):');
        console.log('   Bob Tiene   :', toBase64(bobId.ikX25519.publicKey));
        console.log('   Alice Usó   :', toBase64(peerBundleForAlice.identityKey));

        console.log('4. Signed PreKey Bob (SPK_B):');
        console.log('   Bob Tiene   :', toBase64(bobSPK.keyPair.publicKey));
        console.log('   Alice Usó   :', toBase64(peerBundleForAlice.signedPreKey.publicKey));

        console.log('5. One-Time Key Bob (OTK_B):');
        console.log('   Bob Tiene   :', toBase64(bobOTK.keyPair.publicKey));
        console.log('   Alice Usó   :', toBase64(peerBundleForAlice.oneTimePreKey.publicKey));
        console.log('   En Mensaje  :', toBase64(otkFromMsg));

        console.log('-------------------------\n');

        // 6. Intento de sesión de Bob
        const { session: bobSession } = await autoResponderSession(bobId, {
            ikX25519: aliceId.ikX25519.publicKey,
            ikEd25519: aliceId.ikEd25519.publicKey,
            ephPubKey: ephKeyFromMsg,
            oneTimePreKey: otkFromMsg
        });

        // 7. Desencriptado
        const decrypted = await decryptMessage(bobSession, finalHeader, ciphertextHex);
        expect(decrypted).toBe(messageText);
    });
});