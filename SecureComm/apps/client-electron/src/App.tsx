import {useEffect, useMemo, useRef, useState} from 'react';
import type {SessionState} from '@securecomm/crypto-sdk';
import {
    autoResponderSession,
    createIdentity,
    decryptMessage,
    encryptMessage,
    fromBase64,
    generateBundle,
    initCrypto,
    initiatorSession,
    keyFingerprint,
    loadIdentity,
    loadSessionFromStorage,
    refreshPreKeys,
    saveSessionToStorage,
    shortAuthCode,
    toBase64
} from './cryptoClient';
import {
    type BundleResponse,
    type EnvelopeFrame,
    fetchBundle,
    login,
    openSocket,
    parseEnvelopeFrame,
    register,
    rotatePreKeys,
} from './api';
import QRCode from 'qrcode';

const DEFAULT_OTKS = 5;
const CHAT_PREFIX = 'securecomm.chats.';
const TOKEN_KEY = 'securecomm.token';

function chatsKey(owner: string) {
    return `${CHAT_PREFIX}${owner || 'anon'}`;
}

function loadChatsFor(user: string): Record<string, Chat> {
    try {
        const saved = localStorage.getItem(chatsKey(user));
        return saved ? JSON.parse(saved) : {};
    } catch {
        return {};
    }
}

function usernameIsValid(value: string) {
    return /^[A-Za-z0-9._-]{5,32}$/.test(value);
}

function passwordIsValid(value: string) {
    return /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=.?,]{8,64}$/.test(value);
}

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
    const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) || '');
    const [deviceId, setDeviceId] = useState<string>(() => localStorage.getItem('securecomm.device') || '');
    const [username, setUsername] = useState(() => localStorage.getItem('securecomm.username') || '');
    const [peerToStart, setPeerToStart] = useState('');

    const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
    const [loginUser, setLoginUser] = useState(() => localStorage.getItem('securecomm.username') || '');
    const [loginPass, setLoginPass] = useState('');
    const [registerUser, setRegisterUser] = useState('');
    const [registerPass, setRegisterPass] = useState('');
    const [authMessage, setAuthMessage] = useState('');

    const [sessions, setSessions] = useState<SessionBook>({});
    const sessionsRef = useRef(sessions);

    const [chats, setChats] = useState<Record<string, Chat>>(() => loadChatsFor(localStorage.getItem('securecomm.username') || ''));
    const [activeChat, setActiveChat] = useState<string | null>(null);

    const [pendingBundle, setPendingBundle] = useState<PendingBundle | null>(null);
    const [wsStatus, setWsStatus] = useState<WsStatus>('disconnected');
    const [log, setLog] = useState<string[]>([]);
    const wsRef = useRef<WebSocket | null>(null);
    const sessionsHydratedRef = useRef(false);

    const [reconnectTick, setReconnectTick] = useState(0); // Para forzar reconexión del WS
    const inactivityTimer = useRef<number | null>(null);   // Para el logout automático

    // @ts-ignore
    const rotationMinutes = Number(import.meta.env.VITE_ROTATION_INTERVAL_MINUTES ?? '30');

    // --- EFFECTS ---

    useEffect(() => {
        void initCrypto().then(() => {
            if (token && username) {
                setStatus('auth');
            } else {
                setStatus('ready');
            }
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        if (status === 'auth' && username) {
            const restoredChats = loadChatsFor(username);
            setChats(restoredChats);
            sessionsHydratedRef.current = false;
        }
        if (status !== 'auth') {
            setActiveChat(null);
        }
    }, [status, username]);

    useEffect(() => {
        if (sessionsHydratedRef.current) return;
        if ((status !== 'ready' && status !== 'auth') || !username) return;

        const restored: SessionBook = {};
        Object.keys(chats).forEach((peer) => {
            if (sessionsRef.current[peer]) return;
            const loaded = loadSessionFromStorage(sessionKey(peer));
            if (loaded) {
                restored[peer] = loaded as any;
                sessionsRef.current[peer] = loaded as any;
                appendLog(`Sesión restaurada para ${peer}`);
            }
        });

        if (Object.keys(restored).length > 0) {
            setSessions((prev) => ({ ...restored, ...prev }));
        }

        sessionsHydratedRef.current = true;
    }, [status, chats, username]);

    useEffect(() => {
        Object.entries(sessions).forEach(([peer, session]) => {
            saveSessionToStorage(sessionKey(peer), session as any);
        });
        sessionsRef.current = sessions;
    }, [sessions]);

    const sessionKey = (peer: string) => `${username || 'anon'}::${peer}`;

    function persistSession(peer: string, session: SessionState) {
        sessionsRef.current = { ...sessionsRef.current, [peer]: session };
        setSessions((prev) => ({ ...prev, [peer]: session }));
    }

    useEffect(() => {
        if (!username || status !== 'auth') return;
        localStorage.setItem(chatsKey(username), JSON.stringify(chats));
    }, [chats, username, status]);

    useEffect(() => {
        const peers = Object.keys(chats);
        if (peers.length === 0) {
            setActiveChat(null);
            return;
        }
        if (!activeChat || !chats[activeChat]) {
            setActiveChat(peers[0]);
        }
    }, [chats, activeChat]);

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
            appendLog('Socket cerrado, reintentando...');
            setTimeout(() => setReconnectTick((v) => v + 1), 1200);
        };
        ws.onerror = () => setWsStatus('disconnected');
        ws.onmessage = (ev) => handleEnvelope(ev.data);
        return () => ws.close();
    }, [token, reconnectTick]);

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
        if (status !== 'auth') {
            if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
            return;
        }

        const resetTimer = () => {
            if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
            inactivityTimer.current = window.setTimeout(() => {
                handleLogout('Sesión cerrada por inactividad (10 minutos)');
            }, 10 * 60 * 1000);
        };

        resetTimer();
        window.addEventListener('pointerdown', resetTimer);
        window.addEventListener('keydown', resetTimer);

        return () => {
            window.removeEventListener('pointerdown', resetTimer);
            window.removeEventListener('keydown', resetTimer);
            if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
        };
    }, [status]);

    useEffect(() => {
        if (!token || rotationMinutes <= 0) return;
        const id = setInterval(() => { void rotatePreKeysFlow(); }, rotationMinutes * 60 * 1000);
        return () => clearInterval(id);
    }, [token, rotationMinutes]);

    function appendLog(entry: string) {
        setLog((l) => [`[${new Date().toISOString()}] ${entry}`, ...l].slice(0, 200));
    }

    function handleLogout(message = 'Sesión cerrada') {
        wsRef.current?.close();
        setToken('');
        localStorage.removeItem(TOKEN_KEY);
        setStatus('ready');
        setWsStatus('disconnected');
        setChats({});
        setSessions({});
        sessionsRef.current = {};
        sessionsHydratedRef.current = false;
        setActiveChat(null);
        appendLog(message);
    }

    function copyToClipboard(text: string, label: string) {
        if (!text) return;
        navigator.clipboard?.writeText(text).then(
            () => appendLog(`${label} copiado al portapapeles`),
            () => appendLog(`No se pudo copiar ${label}`)
        );
    }

    const qrPayload = useMemo(() => {
        if (status !== 'ready' && status !== 'auth') return '';
        const identity = loadIdentity() as any;
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
        if (!usernameIsValid(registerUser) || !passwordIsValid(registerPass)) {
            setAuthMessage('Usuario o contraseña no cumplen las reglas mínimas.');
            return;
        }
        try {
            const identity = await ensureIdentity() as any;
            const { spk, otks } = await generateBundle(identity, DEFAULT_OTKS);
            const newDeviceId = crypto.randomUUID();

            const payload = {
                username: registerUser,
                password: registerPass,
                ik_pub: toBase64(identity.ikX25519.publicKey),
                sig_pub: toBase64(identity.ikEd25519.publicKey),
                spk_pub: toBase64(spk.keyPair.publicKey),
                spk_sig: toBase64(spk.signature),
                otk_pubs: otks.map((k) => toBase64(k.keyPair.publicKey)),
                device_id: newDeviceId,
            };
            await register(payload);
            setDeviceId(newDeviceId);
            localStorage.setItem('securecomm.device', newDeviceId);
            localStorage.setItem('securecomm.username', registerUser);
            setLoginUser(registerUser);
            setAuthMode('login');
            setAuthMessage('Registro completado. Inicia sesión para continuar.');
            appendLog('Registro completado');
        } catch (err) {
            appendLog(`Error registrando: ${err}`);
            setAuthMessage('No se pudo completar el registro.');
        }
    }

    async function handleLogin() {
        if (!usernameIsValid(loginUser) || !passwordIsValid(loginPass)) {
            setAuthMessage('Credenciales inválidas: usa mínimo 5 caracteres para usuario y 8 con números para la contraseña.');
            return;
        }
        try {
            const identity = loadIdentity();
            if (!identity) {
                appendLog('No hay identidad local. Registra primero.');
                setAuthMessage('Registra tu identidad antes de iniciar sesión.');
                return;
            }
            const rememberedDevice = localStorage.getItem('securecomm.device') || crypto.randomUUID();
            const res = await login({ username: loginUser, password: loginPass, device_id: rememberedDevice });
            setToken(res.access_token);
            localStorage.setItem(TOKEN_KEY, res.access_token);
            setStatus('auth');
            setUsername(loginUser);
            setDeviceId(rememberedDevice);
            localStorage.setItem('securecomm.device', rememberedDevice);
            localStorage.setItem('securecomm.username', loginUser);
            setAuthMessage('Login correcto.');
            setLoginPass('');
            appendLog('Login OK');
        } catch (err) {
            appendLog(`Login fallido: ${err}`);
            setAuthMessage('No se pudo iniciar sesión.');
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

            const { session } = await initiatorSession(identity, peerBundle as any);
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
            setActiveChat(bundle.username);

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
        let chatKey = typeof (frame.ratchet_header as any)?.peer === 'string'
            ? ((frame.ratchet_header as any).peer as string)
            : 'desconocido';

        if (!sessionsRef.current[chatKey]) {
            const loaded = loadSessionFromStorage(sessionKey(chatKey));
            if (loaded) {
                persistSession(chatKey, loaded as any);
            }
        }

        let session = sessionsRef.current[chatKey];
        const headerAny = frame.ratchet_header as any;
        // --- LÓGICA DE AUTO-HANDSHAKE ---
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
                } else {
                    // Si no hay sesión y no es un handshake, fallará abajo
                }
            }

            if (!session) throw new Error("No hay sesión y no es un handshake válido");

            try {
                const text = await decryptMessage(session as any, frame.ratchet_header, frame.ciphertext);
                persistSession(chatKey, session);
                await handleSuccess(chatKey, text, frame);
            } catch (decryptErr) {
                // Recuperación: Si falla y es un handshake, intentamos renegociar
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
            const loaded = loadSessionFromStorage(sessionKey(peer)) as SessionState;
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
        const { header, ciphertextHex, serializedHeader } = await encryptMessage(session as any, message);
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

    const isAuth = status === 'auth';
    const activeChatData = activeChat ? chats[activeChat] : null;

    return (
        <div className="app-shell">
            <nav className="topbar">
                <div className="brand">SecureComm</div>
                <div className="topbar-actions">
                    <span className={`pill ${statusBlocks[1].tone}`}>WS: {wsStatus}</span>
                    {isAuth && <button className="ghost" onClick={() => handleLogout()}>Cerrar sesión</button>}
                </div>
            </nav>
            {!isAuth ? (
                <main className="auth-screen">
                    <section className="auth-hero">
                        <div>
                            <h1>Mensajería cifrada</h1>
                            <p className="muted">Regístrate o inicia sesión para empezar. No mezclamos vistas.</p>
                            <div className="pill-row">
                                {statusBlocks.map((b) => (
                                    <span key={b.label} className={`pill ${b.tone}`}>{b.label}: {b.value}</span>
                                ))}
                            </div>
                            {authMessage && <p className="status-hint">{authMessage}</p>}
                        </div>
                        <div className="auth-switch">
                            <button className={authMode === 'login' ? 'primary' : 'ghost'} onClick={() => setAuthMode('login')}>Iniciar sesión</button>
                            <button className={authMode === 'register' ? 'primary' : 'ghost'} onClick={() => setAuthMode('register')}>Crear cuenta</button>
                        </div>
                    </section>

                    {authMode === 'login' ? (
                        <section className="auth-card">
                            <h2>Iniciar sesión</h2>
                            <input placeholder="usuario" value={loginUser} onChange={(e) => setLoginUser(e.target.value)} />
                            <input placeholder="contraseña" type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} />
                            <button
                                disabled={!usernameIsValid(loginUser) || !passwordIsValid(loginPass)}
                                onClick={handleLogin}
                            >
                                Entrar
                            </button>
                            <p className="helper-text">Contraseña mínima: 8 caracteres, letras y números.</p>
                        </section>
                    ) : (
                        <section className="auth-card">
                            <h2>Crear cuenta</h2>
                            <input placeholder="usuario nuevo" value={registerUser} onChange={(e) => setRegisterUser(e.target.value)} />
                            <input placeholder="contraseña segura" type="password" value={registerPass} onChange={(e) => setRegisterPass(e.target.value)} />
                            <button
                                disabled={!usernameIsValid(registerUser) || !passwordIsValid(registerPass)}
                                onClick={handleRegister}
                            >
                                Registrar
                            </button>
                            <p className="helper-text">Después de registrarte inicia sesión manualmente.</p>
                        </section>
                    )}
                </main>
            ) : (
                <main className="chat-shell">
                    <aside className="sidebar">
                        <div className="card">
                            <p className="label">Tu identidad</p>
                            <h3>{username}</h3>
                            <p className="muted">FP corto: {qrPayload ? shortAuthCode(qrPayload) : '...'}</p>
                            <div className="mini-buttons">
                                <button className="ghost" onClick={() => copyToClipboard(qrPayload, 'Fingerprint local')}>Copiar fingerprint</button>
                                <button className="ghost" onClick={() => copyToClipboard(shortAuthCode(qrPayload || ''), 'Código corto')}>Copiar código</button>
                            </div>
                            {qrData && <img className="mini-qr" src={qrData} alt="Código QR de identidad" />}
                        </div>

                        <div className="card">
                            <p className="label">Nuevo chat</p>
                            <div className="stacked">
                                <input
                                    placeholder="usuario destino"
                                    value={peerToStart}
                                    onChange={(e) => setPeerToStart(e.target.value)}
                                />
                                <button onClick={fetchPeerBundle} disabled={!peerToStart || !token}>Obtener bundle</button>
                            </div>
                            {pendingBundle ? (
                                <div className="bundle-info">
                                    <p>Objetivo: <strong>{pendingBundle.bundle.username}</strong></p>
                                    <p className="muted">FP {pendingBundle.fingerprint.slice(0, 10)}...</p>
                                    <div className="bundle-actions">
                                        <button onClick={startSessionWithPending}>Iniciar X3DH</button>
                                        <span className="pill pill-quiet">OTK: {pendingBundle.bundle.otk_pub ? 'Incluye' : 'No enviado'}</span>
                                    </div>
                                </div>
                            ) : null}
                        </div>

                        <div className="card chat-list">
                            <div className="panel-head">
                                <h3>Chats ({Object.values(chats).length})</h3>
                            </div>
                            {Object.values(chats).length === 0 ? (
                                <p className="muted">Aún no hay chats.</p>
                            ) : (
                                <ul>
                                    {Object.values(chats).map((chat) => (
                                        <li key={chat.peer} className={activeChat === chat.peer ? 'active' : ''}>
                                            <button onClick={() => setActiveChat(chat.peer)}>
                                                <div className="chat-meta">
                                                    <span>{chat.peer}</span>
                                                    <span className={`pill ${chat.verified ? 'pill-ok' : 'pill-warn'}`}>
                                                        {chat.verified ? 'Verificada' : 'Sin verificar'}
                                                    </span>
                                                </div>
                                                <small className="muted">{chat.messages.length} mensajes</small>
                                            </button>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </aside>
                    <section className="conversation">
                        {activeChatData ? (
                            <div className="conversation-card">
                                <header className="conversation-head">
                                    <div>
                                        <h2>{activeChatData.peer}</h2>
                                        <p className="muted">FP: {activeChatData.fingerprint ?? 'Resolviendo...'}</p>
                                    </div>
                                    <div className="mini-buttons">
                                        {!activeChatData.verified && (
                                            <button className="ghost" onClick={() => markVerified(activeChatData!.peer)}>Marcar verificada</button>
                                        )}
                                        <span className={`pill ${activeChatData.verified ? 'pill-ok' : 'pill-warn'}`}>
                                            {activeChatData.verified ? 'Seguro' : 'Pendiente'}
                                        </span>
                                    </div>
                                </header>
                                <div className="messages">
                                    {activeChatData.messages.map((m, idx) => (
                                        <div key={idx} className={`msg ${m.sender} ${m.error ? 'error' : ''}`}>
                                            <div>
                                                <p>{m.text}</p>
                                                <small>{new Date(m.ts).toLocaleString()}</small>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                <ChatComposer onSend={(text) => sendMessage(activeChatData!.peer, text)} />
                            </div>
                        ) : (
                            <div className="empty">
                                <p className="muted">Selecciona o crea un chat para comenzar.</p>
                            </div>
                        )}
                    </section>

                    <aside className="log-rail">
                        <div className="panel-head">
                            <h3>Bitácora</h3>
                            <button className="ghost" onClick={() => setLog([])}>Limpiar</button>
                        </div>
                        <pre>{log.slice(0, 50).join('\n')}</pre>
                    </aside>
                </main>
            )}
        </div>
    );
}

function ChatComposer({ onSend }: { onSend: (text: string) => void }) {
    const [text, setText] = useState('');
    return (
        <div className="composer">
            <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Mensaje..."/>
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