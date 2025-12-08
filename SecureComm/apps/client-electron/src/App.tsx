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
    shortAuthCode,
    toBase64,
    fromBase64,
    refreshPreKeys,
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

type Chat = {
    peer: string;
    messages: Array<{ sender: 'me' | 'them'; text: string; ts: string }>;
    verified: boolean;
    fingerprint?: string;
};

type SessionBook = Record<string, SessionState>;

type PendingBundle = { bundle: BundleResponse; fingerprint: string };

type WsStatus = 'disconnected' | 'connecting' | 'connected';

function useQRCode(data: string): string | null {
    const [uri, setUri] = useState<string | null>(null);
    useEffect(() => {
        let disposed = false;
        void (async () => {
            try {
                const url = await QRCode.toDataURL(data, { width: 200, margin: 1 });
                if (!disposed) setUri(url);
            } catch (err) {
                console.error('QR encode failed', err);
            }
        })();
        return () => {
            disposed = true;
        };
    }, [data]);
    return uri;
}

export default function App() {
    const [status, setStatus] = useState<'idle' | 'ready' | 'auth'>('idle');
    const [token, setToken] = useState<string>('');
    const [deviceId, setDeviceId] = useState<string>(() => localStorage.getItem('securecomm.device') || '');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [peerToStart, setPeerToStart] = useState('');
    const [sessions, setSessions] = useState<SessionBook>({});
    const [chats, setChats] = useState<Record<string, Chat>>({});
    const [pendingBundle, setPendingBundle] = useState<PendingBundle | null>(null);
    const [wsStatus, setWsStatus] = useState<WsStatus>('disconnected');
    const [log, setLog] = useState<string[]>([]);
    const wsRef = useRef<WebSocket | null>(null);
    const rotationMinutes = Number(import.meta.env.VITE_ROTATION_INTERVAL_MINUTES ?? '30');
    const qrPayload = useMemo(() => {
        const identity = loadIdentity();
        if (!identity) return 'no-identity';
        return JSON.stringify({
            ik: toBase64(identity.ikEd25519.publicKey),
        });
    }, [status]);
    const qrData = useQRCode(qrPayload);

    useEffect(() => {
        void initCrypto().then(() => setStatus('ready'));
    }, []);

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
        if (!token || rotationMinutes <= 0) return;
        const id = setInterval(() => {
            void rotatePreKeysFlow();
        }, rotationMinutes * 60 * 1000);
        return () => clearInterval(id);
    }, [token, rotationMinutes]);

    function appendLog(entry: string) {
        setLog((l) => [`[${new Date().toISOString()}] ${entry}`, ...l].slice(0, 50));
    }

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
                otk_pubs: otks.map((k) => toBase64(k.publicKey)),
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
        try {
            const bundle = await fetchBundle(peerToStart, token);
            const fp = await keyFingerprint(fromBase64(bundle.ik_pub));
            setPendingBundle({ bundle, fingerprint: fp });
            appendLog(`Bundle recibido para ${peerToStart}`);
        } catch (err) {
            appendLog(`Error obteniendo bundle: ${err}`);
        }
    }

    function fromB64(value: string) {
        return Uint8Array.from(Buffer.from(value, 'base64'));
    }

    async function startSessionWithPending() {
        if (!pendingBundle) return;
        const identity = loadIdentity();
        if (!identity) return;
        try {
            const bundle: BundleResponse = pendingBundle.bundle;
            const peerBundle = {
                ikEd25519: fromBase64(bundle.sig_pub),
                ikX25519: fromBase64(bundle.ik_pub),
                signedPreKey: fromBase64(bundle.spk_pub),
                signedPreKeySignature: fromBase64(bundle.spk_sig),
                oneTimePreKey: bundle.otk_pub ? fromBase64(bundle.otk_pub) : undefined,
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
            otk_pubs: otks.map((k) => toBase64(k.publicKey)),
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

    async function processEnvelope(frame: EnvelopeFrame) {
        const hintedPeer =
            typeof (frame.ratchet_header as any)?.peer === 'string' ? ((frame.ratchet_header as any).peer as string) : 'desconocido';
        const chatKey = hintedPeer;
        const session = sessions[chatKey];
        if (!session) {
            appendLog(`No hay sesión para ${chatKey}, ignorando`);
            return;
        }
        try {
            const text = await decryptMessage(session, frame.ratchet_header, frame.ciphertext);
            setChats((prev) => ({
                ...prev,
                [chatKey]: {
                    peer: chatKey,
                    verified: prev[chatKey]?.verified ?? false,
                    fingerprint: prev[chatKey]?.fingerprint,
                    messages: [...(prev[chatKey]?.messages ?? []), { sender: 'them', text, ts: frame.ts }],
                },
            }));
            wsRef.current?.send(JSON.stringify({ action: 'receipt', id: frame.id }));
        } catch (err) {
            appendLog(`Fallo descifrando mensaje de ${chatKey}: ${err}`);
        }
    }

    async function sendMessage(peer: string, message: string) {
        const session = sessions[peer];
        if (!session || !wsRef.current) {
            appendLog('No hay sesión o socket');
            return;
        }
        const { header, ciphertextHex } = await encryptMessage(session, message);
        const frame = {
            action: 'send',
            to_user: peer,
            ratchet_header: { ...header, peer: username },
            ciphertext: ciphertextHex,
            msg_id: crypto.randomUUID(),
            ts: new Date().toISOString(),
        } as const;
        wsRef.current.send(JSON.stringify(frame));
        setChats((prev) => ({
            ...prev,
            [peer]: {
                peer,
                verified: prev[peer]?.verified ?? false,
                fingerprint: prev[peer]?.fingerprint,
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
                        {qrData ? <img src={qrData} alt="qr" /> : <span>Generando QR...</span>}
                    </div>
                    <div>
                        <p>Código corto (60 bits):</p>
                        <code>{shortAuthCode(qrPayload)}</code>
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
                            Bundle para <strong>{pendingBundle.bundle.username}</strong> (fingerprint {pendingBundle.fingerprint})
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
                                <span>Fingerprint: {chat.fingerprint ?? 'N/A'}</span>
                                <span className={chat.verified ? 'verified' : 'unverified'}>
                  {chat.verified ? 'Verificada' : 'No verificada'}
                </span>
                                {!chat.verified && <button onClick={() => markVerified(chat.peer)}>Marcar como verificada</button>}
                            </div>
                        </div>
                        <div className="messages">
                            {chat.messages.map((m, idx) => (
                                <div key={idx} className={`msg ${m.sender}`}> {m.text} <small>{m.ts}</small></div>
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