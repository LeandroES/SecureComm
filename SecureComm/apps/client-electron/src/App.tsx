import { useEffect, useMemo, useRef, useState } from 'react';
import type { SessionState } from '@securecomm/crypto-sdk';
import {
    createIdentity,
    decryptMessage,
    encryptMessage,
    generateBundle,
    initCrypto,
    keyFingerprint,
    loadIdentity,
    initiatorSession,
    autoResponderSession,
    shortAuthCode,
    toBase64,
    fromBase64,
    refreshPreKeys,
    saveSessionToStorage,
    loadSessionFromStorage
} from './cryptoClient';
import {
    fetchBundle,
    login,
    openSocket,
    parseEnvelopeFrame,
    register,
    rotatePreKeys,
    type BundleResponse,
    type EnvelopeFrame,
} from './api';
import QRCode from 'qrcode';

const DEFAULT_OTKS = 5;
const CHATS_STORAGE_KEY = 'securecomm.chats';

type Chat = {
    peer: string;
    messages: Array<{ sender: 'me' | 'them'; text: string; ts: string; error?: boolean }>;
    verified: boolean;
    fingerprint?: string;
    pendingOtk?: string;
};

type SessionBook = Record<string, SessionState>;
type PendingBundle = { bundle: BundleResponse; fingerprint: string; otkPub?: string };
type WsStatus = 'disconnected' | 'connecting' | 'connected';

function useQRCode(data: string): string | null {
    const [uri, setUri] = useState<string | null>(null);
    useEffect(() => {
        if (!data) return;
        let disposed = false;
        void (async () => {
            try {
                const url = await QRCode.toDataURL(data, { width: 200, margin: 1 });
                if (!disposed) setUri(url);
            } catch (err) {
                console.error('QR encode failed', err);
            }
        })();
        return () => { disposed = true; };
    }, [data]);
    return uri;
}

export default function App() {
    const [status, setStatus] = useState<'idle' | 'ready' | 'auth'>('idle');
    const [token, setToken] = useState<string>('');
    const [deviceId, setDeviceId] = useState<string>(() => localStorage.getItem('securecomm.device') || '');
    const [username, setUsername] = useState(() => localStorage.getItem('securecomm.username') || '');
    const [password, setPassword] = useState('');
    const [peerToStart, setPeerToStart] = useState('');

    const [sessions, setSessions] = useState<SessionBook>({});
    const sessionsRef = useRef(sessions);

    const [chats, setChats] = useState<Record<string, Chat>>(() => {
        try {
            const saved = localStorage.getItem(CHATS_STORAGE_KEY);
            return saved ? JSON.parse(saved) : {};
        } catch { return {}; }
    });

    const [pendingBundle, setPendingBundle] = useState<PendingBundle | null>(null);
    const [wsStatus, setWsStatus] = useState<WsStatus>('disconnected');
    const [log, setLog] = useState<string[]>([]);
    const wsRef = useRef<WebSocket | null>(null);

    // @ts-ignore
    const rotationMinutes = Number(import.meta.env.VITE_ROTATION_INTERVAL_MINUTES ?? '30');

    // --- EFFECTS ---

    useEffect(() => {
        void initCrypto().then(() => setStatus('ready'));
    }, []);

    useEffect(() => {
        Object.entries(sessions).forEach(([peer, session]) => {
            saveSessionToStorage(peer, session);
        });
        sessionsRef.current = sessions;
    }, [sessions]);

    useEffect(() => {
        localStorage.setItem(CHATS_STORAGE_KEY, JSON.stringify(chats));
    }, [chats]);

    useEffect(() => {
        if (!token) return;
        const ws = openSocket(token);
        wsRef.current = ws;
        setWsStatus('connecting');
        ws.onopen = () => {
            setWsStatus('connected');
            ws.send(JSON.stringify({ action: 'recv' }));
        };
        ws.onclose = () => setWsStatus('disconnected');
        ws.onerror = () => setWsStatus('disconnected');
        ws.onmessage = (ev) => handleEnvelope(ev.data);
        return () => ws.close();
    }, [token]);

    useEffect(() => {
        if (wsStatus !== 'connected' || !wsRef.current) return;
        const intervalId = setInterval(() => {
            if (wsRef.current?.readyState === WebSocket.OPEN) {
                wsRef.current.send(JSON.stringify({ action: 'recv' }));
            }
        }, 2000);
        return () => clearInterval(intervalId);
    }, [wsStatus]);

    useEffect(() => {
        if (!token || rotationMinutes <= 0) return;
        const id = setInterval(() => { void rotatePreKeysFlow(); }, rotationMinutes * 60 * 1000);
        return () => clearInterval(id);
    }, [token, rotationMinutes]);

    function appendLog(entry: string) {
        setLog((l) => [`[${new Date().toISOString()}] ${entry}`, ...l].slice(0, 50));
    }

    const qrPayload = useMemo(() => {
        if (status !== 'ready') return '';
        const identity = loadIdentity();
        if (!identity) return '';
        return JSON.stringify({ ik: toBase64(identity.ikEd25519.publicKey) });
    }, [status]);

    const qrData = useQRCode(qrPayload);

    // --- ACTIONS ---

    async function ensureIdentity() {
        const existing = loadIdentity();
        if (existing) return existing;
        const id = await createIdentity();
        appendLog('Nueva identidad generada');
        return id;
    }

    async function handleRegister() {
        try {
            const identity = await ensureIdentity();
            const { spk, otks } = await generateBundle(identity, DEFAULT_OTKS);
            const newDeviceId = crypto.randomUUID();

            const payload = {
                username,
                password,
                ik_pub: toBase64(identity.ikX25519.publicKey),
                sig_pub: toBase64(identity.ikEd25519.publicKey),
                spk_pub: toBase64(spk.keyPair.publicKey),
                spk_sig: toBase64(spk.signature),
                otk_pubs: otks.map((k) => toBase64(k.keyPair.publicKey)),
                device_id: newDeviceId,
            };
            const res = await register(payload);
            setToken(res.access_token);
            setStatus('auth');
            setDeviceId(newDeviceId);
            localStorage.setItem('securecomm.device', newDeviceId);
            localStorage.setItem('securecomm.username', username);
            appendLog('Registro completado');
        } catch (err) {
            appendLog(`Error registrando: ${err}`);
        }
    }

    async function handleLogin() {
        try {
            const identity = loadIdentity();
            if (!identity) {
                appendLog('No hay identidad local. Registra primero.');
                return;
            }
            const rememberedDevice = localStorage.getItem('securecomm.device') || crypto.randomUUID();
            const res = await login({ username, password, device_id: rememberedDevice });
            setToken(res.access_token);
            setStatus('auth');
            setDeviceId(rememberedDevice);
            localStorage.setItem('securecomm.device', rememberedDevice);
            localStorage.setItem('securecomm.username', username);
            appendLog('Login OK');
        } catch (err) {
            appendLog(`Login fallido: ${err}`);
        }
    }

    async function fetchPeerBundle() {
        if (!peerToStart || !token) return;
        if (chats[peerToStart]?.fingerprint) {
            appendLog(`Chat existente recuperado para ${peerToStart}`);
            return;
        }
        try {
            const bundle = await fetchBundle(peerToStart, token);
            const fp = await keyFingerprint(fromBase64(bundle.ik_pub));
            setPendingBundle({
                bundle,
                fingerprint: fp,
                otkPub: bundle.otk_pub || undefined
            });
            appendLog(`Bundle recibido para ${peerToStart}`);
        } catch (err) {
            appendLog(`Error obteniendo bundle: ${err}`);
        }
    }

    async function startSessionWithPending() {
        if (!pendingBundle) return;
        const identity = loadIdentity();
        if (!identity) return;
        try {
            const bundle: BundleResponse = pendingBundle.bundle;
            const peerBundle = {
                identityKey: fromBase64(bundle.ik_pub),
                identityKeyEd25519: fromBase64(bundle.sig_pub),
                signedPreKey: {
                    id: 0,
                    publicKey: fromBase64(bundle.spk_pub),
                    signature: fromBase64(bundle.spk_sig),
                },
                oneTimePreKey: bundle.otk_pub ? {
                    id: 0,
                    publicKey: fromBase64(bundle.otk_pub)
                } : undefined,
            };

            const { session } = await initiatorSession(identity, peerBundle);
            setSessions((prev) => ({ ...prev, [bundle.username]: session }));

            setChats((prev) => ({
                ...prev,
                [bundle.username]: {
                    peer: bundle.username,
                    messages: prev[bundle.username]?.messages ?? [],
                    verified: false,
                    fingerprint: pendingBundle.fingerprint,
                    pendingOtk: bundle.otk_pub || undefined // GUARDAR OTK
                },
            }));

            setPendingBundle(null);
            appendLog(`Sesión iniciada con ${bundle.username}`);
        } catch (err) {
            appendLog(`Error creando sesión: ${err}`);
        }
    }

    async function rotatePreKeysFlow() {
        const identity = loadIdentity();
        if (!identity || !deviceId || !token) return;
        const { spk, otks } = await refreshPreKeys(identity, DEFAULT_OTKS);
        await rotatePreKeys(deviceId, token, {
            spk_pub: toBase64(spk.keyPair.publicKey),
            spk_sig: toBase64(spk.signature),
            otk_pubs: otks.map((k: any) => toBase64(k.keyPair.publicKey)),
        });
        appendLog('Rotación de pre-keys completada');
    }

    function handleEnvelope(raw: any) {
        try {
            const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
            const frame = parseEnvelopeFrame(parsed);
            if (!frame) return;
            void processEnvelope(frame);
        } catch (err) {
            appendLog(`Frame inválido: ${err}`);
        }
    }

    async function resolveFingerprintIfNeeded(peerName: string, currentFp?: string) {
        if (currentFp) return currentFp;
        try {
            const bundle = await fetchBundle(peerName, token);
            return await keyFingerprint(fromBase64(bundle.ik_pub));
        } catch (e) {
            console.error("No se pudo resolver fingerprint del remitente", e);
            return undefined;
        }
    }

    async function processEnvelope(frame: EnvelopeFrame) {
        const hintedPeer = typeof (frame.ratchet_header as any)?.peer === 'string'
            ? ((frame.ratchet_header as any).peer as string)
            : 'desconocido';

        let chatKey = hintedPeer;

        if (!sessionsRef.current[chatKey]) {
            const loaded = loadSessionFromStorage(chatKey);
            if(loaded) {
                setSessions(prev => ({...prev, [chatKey]: loaded}));
                sessionsRef.current[chatKey] = loaded;
            }
        }

        let session = sessionsRef.current[chatKey];
        const headerAny = frame.ratchet_header as any;

        // --- LÓGICA DE AUTO-HANDSHAKE ---
        const tryEstablishSession = async () => {
            // Verificamos si hay x3dh (ahora siempre se enviará)
            if (!headerAny.x3dh) return null;

            appendLog(`Detectado handshake X3DH de ${chatKey}. Estableciendo sesión...`);
            const identity = loadIdentity();
            if (!identity) throw new Error("Sin identidad local");

            const senderBundle = await fetchBundle(chatKey, token);
            const senderIkX = fromBase64(senderBundle.ik_pub);
            const senderIkEd = fromBase64(senderBundle.sig_pub);

            const ephKey = fromBase64(headerAny.dh);
            // Manejamos OTK opcional
            const usedOtk = headerAny.x3dh.otk ? fromBase64(headerAny.x3dh.otk) : undefined;

            const { session: newSession } = await autoResponderSession(identity, {
                ikX25519: senderIkX,
                ikEd25519: senderIkEd,
                ephPubKey: ephKey,
                oneTimePreKey: usedOtk
            });
            return newSession;
        };

        try {
            if (!session) {
                const newSession = await tryEstablishSession();
                if (newSession) {
                    setSessions(prev => ({ ...prev, [chatKey]: newSession }));
                    sessionsRef.current[chatKey] = newSession;
                    session = newSession;
                } else {
                    // Si no hay sesión y no es un handshake, fallará abajo
                }
            }

            if (!session) throw new Error("No hay sesión y no es un handshake válido");

            try {
                const text = await decryptMessage(session, frame.ratchet_header, frame.ciphertext);
                await handleSuccess(chatKey, text, frame);
            } catch (decryptErr) {
                // Recuperación: Si falla y es un handshake, intentamos renegociar
                if (headerAny.x3dh) {
                    appendLog(`La sesión actual con ${chatKey} es inválida. Re-negociando...`);
                    const newSession = await tryEstablishSession();
                    if (newSession) {
                        setSessions(prev => ({ ...prev, [chatKey]: newSession }));
                        sessionsRef.current[chatKey] = newSession;
                        const text = await decryptMessage(newSession, frame.ratchet_header, frame.ciphertext);
                        await handleSuccess(chatKey, text, frame);
                        return;
                    }
                }
                throw decryptErr;
            }

        } catch (err) {
            handleError(chatKey, err, frame);
        }
    }

    async function handleSuccess(chatKey: string, text: string, frame: EnvelopeFrame) {
        let fingerprint = chats[chatKey]?.fingerprint;
        if (!fingerprint && chatKey !== 'desconocido') {
            fingerprint = await resolveFingerprintIfNeeded(chatKey, fingerprint);
        }

        setChats((prev) => ({
            ...prev,
            [chatKey]: {
                peer: chatKey,
                verified: prev[chatKey]?.verified ?? false,
                fingerprint: fingerprint,
                messages: [...(prev[chatKey]?.messages ?? []), { sender: 'them', text, ts: frame.ts }],
            },
        }));
        wsRef.current?.send(JSON.stringify({ action: 'receipt', id: frame.id }));
    }

    async function handleError(chatKey: string, err: any, frame: EnvelopeFrame) {
        let fingerprint = chats[chatKey]?.fingerprint;
        if (!fingerprint && chatKey !== 'desconocido') {
            try { fingerprint = await resolveFingerprintIfNeeded(chatKey); } catch {}
        }

        appendLog(`Error final procesando mensaje de ${chatKey}: ${err}`);
        setChats((prev) => ({
            ...prev,
            [chatKey]: {
                peer: chatKey,
                verified: prev[chatKey]?.verified ?? false,
                fingerprint: fingerprint || 'Error (Refresh Bundle)',
                messages: [...(prev[chatKey]?.messages ?? []), {
                    sender: 'them',
                    text: '⚠️ Mensaje indescifrable (Conflicto de llaves)',
                    ts: frame.ts,
                    error: true
                }],
            },
        }));
    }

    async function sendMessage(peer: string, message: string) {
        const session = sessions[peer];
        if (!session || !wsRef.current) {
            appendLog('No hay sesión o socket');
            return;
        }
        const { header, ciphertextHex, serializedHeader } = await encryptMessage(session, message);

        let finalHeader = { ...serializedHeader, peer: username };

        // CORRECCIÓN CRUCIAL: Enviar siempre x3dh en mensaje 0, aunque otk sea null
        if (session.n.send === 0) {
            const usedOtk = chats[peer]?.pendingOtk;
            (finalHeader as any).x3dh = {
                otk: usedOtk || undefined
            };
            // Solo borramos si existía, o simplemente limpiamos la flag del chat
            setChats(prev => ({
                ...prev,
                [peer]: { ...prev[peer], pendingOtk: undefined }
            }));
        }

        const frame = {
            action: 'send',
            to_user: peer,
            ratchet_header: finalHeader,
            ciphertext: ciphertextHex,
            msg_id: crypto.randomUUID(),
            ts: new Date().toISOString(),
        } as const;

        wsRef.current.send(JSON.stringify(frame));

        setChats((prev) => ({
            ...prev,
            [peer]: {
                ...prev[peer],
                messages: [...(prev[peer]?.messages ?? []), { sender: 'me', text: message, ts: frame.ts }],
            },
        }));
    }

    function markVerified(peer: string) {
        setChats((prev) => ({
            ...prev,
            [peer]: prev[peer] ? { ...prev[peer], verified: true } : prev[peer],
        }));
    }

    return (
        <div className="app-shell">
            <header>
                <h1>SecureComm</h1>
                <p>Mensajería E2E con X3DH + Double Ratchet.</p>
            </header>

            <section className="auth-panel">
                <h2>Registro / Login</h2>
                <div className="auth-form">
                    <input placeholder="usuario" value={username} onChange={(e) => setUsername(e.target.value)} />
                    <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    <div className="auth-buttons">
                        <button onClick={handleRegister}>Registrar</button>
                        <button onClick={handleLogin}>Login</button>
                    </div>
                    <div className="status">
                        SDK: {status === 'ready' || status === 'auth' ? 'OK' : 'cargando...'} | WS: {wsStatus}
                    </div>
                </div>
            </section>

            <section className="verification">
                <h2>Verificación de identidad</h2>
                <div className="verification-row">
                    <div>
                        <p>Escanea o comparte tu QR:</p>
                        {qrData ? <img src={qrData} alt="qr" /> : <span>{status === 'ready' ? 'Listo' : '...'}</span>}
                    </div>
                    <div>
                        <p>Código corto (60 bits):</p>
                        <code>{qrPayload ? shortAuthCode(qrPayload) : '...'}</code>
                    </div>
                </div>
                <p className="note">Marca la conversación como verificada cuando tu contacto confirme el código corto o fingerprint.</p>
            </section>

            <section className="session-panel">
                <h2>Inicio de chat</h2>
                <div className="bundle-fetch">
                    <input
                        placeholder="usuario destino"
                        value={peerToStart}
                        onChange={(e) => setPeerToStart(e.target.value)}
                    />
                    <button onClick={fetchPeerBundle}>Obtener bundle</button>
                </div>
                {pendingBundle ? (
                    <div className="bundle-info">
                        <p>
                            Bundle para <strong>{pendingBundle.bundle.username}</strong> (FP: {pendingBundle.fingerprint.slice(0, 10)}...)
                        </p>
                        <button onClick={startSessionWithPending}>Iniciar sesión X3DH</button>
                    </div>
                ) : null}
            </section>

            <section className="chat-list">
                <h2>Chats</h2>
                {Object.values(chats).length === 0 ? <p>Sin conversaciones activas.</p> : null}
                {Object.values(chats).map((chat) => (
                    <div key={chat.peer} className="chat-card">
                        <div className="chat-header">
                            <h3>{chat.peer}</h3>
                            <div className="meta">
                                <span>Fingerprint: {chat.fingerprint ?? 'Recuperando...'}</span>
                                <span className={chat.verified ? 'verified' : 'unverified'}>
                  {chat.verified ? 'Verificada' : 'No verificada'}
                </span>
                                {!chat.verified && <button onClick={() => markVerified(chat.peer)}>Marcar como verificada</button>}
                            </div>
                        </div>
                        <div className="messages">
                            {chat.messages.map((m, idx) => (
                                <div key={idx} className={`msg ${m.sender} ${m.error ? 'error' : ''}`}>
                                    {m.text} <small>{m.ts}</small>
                                </div>
                            ))}
                        </div>
                        <ChatComposer onSend={(text) => sendMessage(chat.peer, text)} />
                    </div>
                ))}
            </section>

            <section className="log-panel">
                <h2>Bitácora</h2>
                <pre>{log.join('\n')}</pre>
            </section>
        </div>
    );
}

function ChatComposer({ onSend }: { onSend: (text: string) => void }) {
    const [text, setText] = useState('');
    return (
        <div className="composer">
            <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Mensaje..." />
            <button
                onClick={() => {
                    if (text.trim().length === 0) return;
                    onSend(text);
                    setText('');
                }}
            >
                Enviar
            </button>
        </div>
    );
}