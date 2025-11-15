import { useEffect, useState } from 'react';
import { cryptoProvider } from '@securecomm/crypto-sdk';

const placeholderChats: Array<{ id: string; name: string }> = [];

export default function App() {
    const [initialized, setInitialized] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;
        void (async () => {
            try {
                await cryptoProvider.init();
                if (!cancelled) {
                    setInitialized(true);
                }
            } catch (err) {
                if (!cancelled) {
                    setError(err instanceof Error ? err.message : 'Initialization failed');
                }
            }
        })();
        return () => {
            cancelled = true;
        };
    }, []);

    return (
        <div className="app-shell">
            <header>
                <h1>SecureComm</h1>
                <p>Secure messaging reinvented.</p>
            </header>
            <main>
                <section className="auth-panel">
                    <h2>Login / Registro</h2>
                    <p>Interfaz en construcción. Mantente atento.</p>
                    <div className="status">
                        <span>SDK: {initialized ? 'Inicializado' : 'Cargando...'}</span>
                        {error ? <span className="error">Error: {error}</span> : null}
                    </div>
                </section>
                <section className="chat-list">
                    <h2>Chats</h2>
                    {placeholderChats.length === 0 ? (
                        <p>No hay conversaciones disponibles todavía.</p>
                    ) : (
                        <ul>
                            {placeholderChats.map((chat) => (
                                <li key={chat.id}>{chat.name}</li>
                            ))}
                        </ul>
                    )}
                </section>
            </main>
        </div>
    );
}