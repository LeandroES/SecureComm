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
        if (!data) return setUri(null);
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
    const sessionsHydratedRef = useRef(false);

    // @ts-ignore
    const rotationMinutes = Number(import.meta.env.VITE_ROTATION_INTERVAL_MINUTES ?? '30');

    // --- EFFECTS ---

    useEffect(() => {
        void initCrypto().then(() => setStatus('ready'));
    }, []);

    // Hidratación de sesiones (Lógica del Diff + Full File)
    useEffect(() => {
        if (sessionsHydratedRef.current) return;
        if (status !== 'ready' && status !== 'auth') return;

        const restored: SessionBook = {};
        Object.keys(chats).forEach((peer) => {
            if (sessionsRef.current[peer]) return;
            const loaded = loadSessionFromStorage(peer);
            if (loaded) {
                restored[peer] = loaded;
                sessionsRef.current[peer] = loaded;
                appendLog(`Sesión restaurada para ${peer}`);
            }
        });

        if (Object.keys(restored).length > 0) {
            setSessions((prev) => ({ ...restored, ...prev }));
        }

        sessionsHydratedRef.current = true;
    }, [status, chats]);

    useEffect(() => {
        Object.entries(sessions).forEach(([peer, session]) => {
            saveSessionToStorage(peer, session);
        });
        sessionsRef.current = sessions;
    }, [sessions]);

    function persistSession(peer: string, session: SessionState) {
        sessionsRef.current = { ...sessionsRef.current, [peer]: session };
        setSessions((prev) => ({ ...prev, [peer]: session }));
    }

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
        ws.onclose = () => {
            setWsStatus('disconnected');
            appendLog('Socket cerrado. Inicia sesión nuevamente si expiró el token.');
            setStatus('ready');
            setToken('');
        };
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
        setLog((l) => [`[${new Date().toISOString()}] ${entry}`, ...l].slice(0, 200));
    }

    function clearStoredSessions() {
        Object.keys(localStorage)
            .filter((k) => k.startsWith('securecomm.session.'))
            .forEach((k) => localStorage.removeItem(k));
    }

    function handleLogout() {
        wsRef.current?.close();
        setToken('');
        setStatus('ready');
        setChats({});
        setSessions({});
        sessionsRef.current = {};
        clearStoredSessions();
        localStorage.removeItem(CHATS_STORAGE_KEY);
        appendLog('Sesión cerrada y datos locales limpiados');
    }

    function copyToClipboard(text: string, label: string) {
        if (!text) return;
        navigator.clipboard?.writeText(text).then(
            () => appendLog(`${label} copiado al portapapeles`),
            () => appendLog(`No se pudo copiar ${label}`)
        );
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
            persistSession(bundle.username, session);

            setChats((prev) => ({
                ...prev,
                [bundle.username]: {
                    peer: bundle.username,
                    messages: prev[bundle.username]?.messages ?? [],
                    verified: false,
                    fingerprint: pendingBundle.fingerprint,
                    pendingOtk: bundle.otk_pub || undefined
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
            if (loaded) {
                persistSession(chatKey, loaded);
            }
        }

        let session = sessionsRef.current[chatKey];
        const headerAny = frame.ratchet_header as any;

        const tryEstablishSession = async () => {
            if (!headerAny.x3dh) return null;

            appendLog(`Detectado handshake X3DH de ${chatKey}. Estableciendo sesión...`);
            const identity = loadIdentity();
            if (!identity) throw new Error("Sin identidad local");

            const senderBundle = await fetchBundle(chatKey, token);
            const senderIkX = fromBase64(senderBundle.ik_pub);
            const senderIkEd = fromBase64(senderBundle.sig_pub);

            const ephKey = fromBase64(headerAny.d);
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
                    persistSession(chatKey, newSession);
                    session = newSession;
                }
            }

            if (!session) throw new Error("No hay sesión y no es un handshake válido");

            try {
                const text = await decryptMessage(session, frame.ratchet_header, frame.ciphertext);
                persistSession(chatKey, session);
                await handleSuccess(chatKey, text, frame);
            } catch (decryptErr) {
                if (headerAny.x3dh) {
                    appendLog(`La sesión actual con ${chatKey} es inválida. Re-negociando...`);
                    const newSession = await tryEstablishSession();
                    if (newSession) {
                        persistSession(chatKey, newSession);
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
        // Opcional: enviar receipt
        // wsRef.current?.send(JSON.stringify({ action: 'receipt', id: frame.id }));
    }

    async function handleError(chatKey: string, err: any, frame: EnvelopeFrame) {
        let fingerprint = chats[chatKey]?.fingerprint;
        if (!fingerprint && chatKey !== 'desconocido') {
            try { fingerprint = await resolveFingerprintIfNeeded(chatKey); } catch { }
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
        let session = sessions[peer];

        // --- FIX CRITICO: Cargar del disco si no está en memoria ---
        if (!session) {
            const loaded = loadSessionFromStorage(peer);
            if (loaded) {
                persistSession(peer, loaded); // Usamos el helper centralizado
                session = loaded;
                appendLog(`Sesión restaurada para ${peer} al intentar enviar`);
            }
        }
        // ----------------------------------------------------------

        if (!session || !wsRef.current) {
            appendLog('No hay sesión o socket');
            return;
        }
        const { header, ciphertextHex, serializedHeader } = await encryptMessage(session, message);
        persistSession(peer, session);

        let finalHeader = { ...serializedHeader, peer: username };

        if (header.n === 0) {
            const usedOtk = chats[peer]?.pendingOtk;
            (finalHeader as any).x3dh = {
                otk: usedOtk || undefined
            };
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

    // Configuración para el UI moderno del Diff
    const statusBlocks = [
        { label: 'SDK', value: status === 'auth' || status === 'ready' ? 'OK' : 'Cargando...', tone: status === 'auth' || status === 'ready' ? 'pill-ok' : 'pill-warn' },
        { label: 'WebSocket', value: wsStatus, tone: wsStatus === 'connected' ? 'pill-ok' : wsStatus === 'connecting' ? 'pill-warn' : 'pill-bad' },
        { label: 'Device', value: deviceId ? deviceId.slice(0, 8) : 'sin registrar', tone: deviceId ? 'pill-quiet' : 'pill-warn' },
    ];

    return (
        <div className="app-shell">
            <nav className="topbar">
                <div className="brand">🔐 SecureComm</div>
                <div className="topbar-actions">
                    <button className="ghost" onClick={() => copyToClipboard(qrPayload, 'Fingerprint local')}>Copiar fingerprint</button>
                    <button className="ghost" onClick={() => copyToClipboard(shortAuthCode(qrPayload || ''), 'Código corto')}>Copiar código</button>
                    <button className="ghost" onClick={handleLogout}>Cerrar sesión</button>
                </div>
            </nav>
            <header className="hero">
                <div>
                    <p className="eyebrow">SecureComm</p>
                    <h1>Mensajería E2E con X3DH + Double Ratchet</h1>
                    <p className="lede">
                        Gestiona identidades, comparte llaves y conversa con mayor claridad visual. Todo el flujo seguro en una sola vista.
                    </p>
                    <div className="status-grid">
                        {statusBlocks.map((item) => (
                            <div key={item.label} className="status-card">
                                <p className="label">{item.label}</p>
                                <div className="status-row">
                                    <strong>{item.value}</strong>
                                    <span className={`pill ${item.tone}`}>{item.tone === 'pill-quiet' ? 'Listo' : item.value}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
                <div className="hero-qr">
                    <div className="qr-card">
                        <p className="label">Tu identidad</p>
                        {qrData ? <img src={qrData} alt="Código QR de identidad" /> : <div className="qr-placeholder">{status === 'ready' ? 'Listo' : '...'}</div>}
                        <div className="short-code">
                            <span>Código corto</span>
                            <strong>{qrPayload ? shortAuthCode(qrPayload) : '...'}</strong>
                            <button className="pill ghost" onClick={() => copyToClipboard(qrPayload || '', 'QR payload')}>Copiar</button>
                        </div>
                    </div>
                </div>
            </header>

            <section className="grid two">
                <div className="panel">
                    <div className="panel-head">
                        <div>
                            <p className="label">Acceso</p>
                            <h2>Registro / Login</h2>
                        </div>
                        <div className="pill pill-quiet subtle">Persistimos identidad y device_id en localStorage.</div>
                    </div>
                    <div className="auth-form">
                        <input placeholder="usuario" value={username} onChange={(e) => setUsername(e.target.value)} />
                        <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                        <div className="auth-buttons">
                            <button onClick={handleRegister}>Registrar</button>
                            <button onClick={handleLogin}>Login</button>
                            <button className="ghost" onClick={handleLogout}>Cerrar sesión</button>
                        </div>
                        <div className="helper-text">Tus credenciales se guardan localmente para agilizar el reingreso.</div>
                    </div>
                </div>

                <div className="panel">
                    <p className="label">Verificación de identidad</p>
                    <h2>Confirma con tu contacto</h2>
                    <p className="helper-text">Comparte el QR o valida el código corto para marcar el chat como verificado.</p>
                    <div className="identity-callout">
                        <div>
                            <p className="muted">Fingerprint local</p>
                            <code>{qrPayload ? qrPayload : '...'}</code>
                            <div className="tiny-actions">
                                <button className="ghost" onClick={() => copyToClipboard(qrPayload || '', 'Fingerprint local')}>Copiar</button>
                                <button className="ghost" onClick={() => copyToClipboard(shortAuthCode(qrPayload || ''), 'Código corto')}>Copiar código</button>
                            </div>
                        </div>
                        <div className="badge-grid">
                            <div className="badge">Seguro</div>
                            <div className="badge secondary">E2E</div>
                        </div>
                    </div>
                </div>
            </section>

            <section className="panel">
                <div className="panel-head">
                    <div>
                        <p className="label">Sesión</p>
                        <h2>Inicio de chat</h2>
                        <p className="helper-text">Obtén el bundle de tu contacto y arranca el handshake X3DH.</p>
                    </div>
                    <div className="micro-guide">
                        <span>1) Busca a tu contacto</span>
                        <span>2) Inicia X3DH</span>
                        <span>3) Envía un mensaje</span>
                    </div>
                </div>
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
                        <div className="bundle-actions">
                            <button onClick={startSessionWithPending}>Iniciar sesión X3DH</button>
                            <span className="pill pill-warn">OTK: {pendingBundle.bundle.otk_pub ? 'Incluye' : 'No enviado'}</span>
                        </div>
                    </div>
                ) : null}
            </section>

            <section className="grid two stretch">
                <div className="panel">
                    <div className="panel-head">
                        <div>
                            <p className="label">Conversaciones</p>
                            <h2>Chats</h2>
                        </div>
                        <span className="pill pill-quiet">{Object.values(chats).length} activos</span>
                    </div>
                    {Object.values(chats).length === 0 ? (
                        <div className="empty">
                            <p className="muted">Sin conversaciones activas.</p>
                            <p className="helper-text">Obtén el bundle de un contacto y luego envía tu primer mensaje.</p>
                        </div>
                    ) : null}
                    <div className="chat-grid">
                        {Object.values(chats).map((chat) => (
                            <div key={chat.peer} className="chat-card">
                                <div className="chat-header">
                                    <div>
                                        <h3>{chat.peer}</h3>
                                        <p className="muted">Fingerprint: {chat.fingerprint ?? 'Recuperando...'}</p>
                                    </div>
                                    <div className="meta">
                                        <span className={`pill ${chat.verified ? 'pill-ok' : 'pill-warn'}`}>
                                            {chat.verified ? 'Verificada' : 'No verificada'}
                                        </span>
                                        {!chat.verified && <button className="ghost" onClick={() => markVerified(chat.peer)}>Marcar verificada</button>}
                                    </div>
                                </div>
                                <div className="messages">
                                    {chat.messages.map((m, idx) => (
                                        <div key={idx} className={`msg ${m.sender} ${m.error ? 'error' : ''}`}>
                                            <div>
                                                <p>{m.text}</p>
                                                <small>{new Date(m.ts).toLocaleString()}</small>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                <ChatComposer onSend={(text) => sendMessage(chat.peer, text)} />
                            </div>
                        ))}
                    </div>
                </div>

                <div className="panel log-panel">
                    <div className="panel-head">
                        <div>
                            <p className="label">Monitoreo</p>
                            <h2>Bitácora</h2>
                        </div>
                        <div className="log-actions">
                            <span className="pill pill-quiet">Últimos {log.length} eventos</span>
                            <button className="ghost" onClick={() => setLog([])}>Limpiar</button>
                        </div>
                    </div>
                    <pre>{log.join('\n')}</pre>
                </div>
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