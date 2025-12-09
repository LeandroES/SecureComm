import type { SessionHeader } from '@securecomm/crypto-sdk';

const API_BASE =
    import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') || `${window.location.origin}/api`;
const WS_BASE = import.meta.env.VITE_WS_URL || `${window.location.origin.replace('http', 'ws')}/ws/secure`;

export type RegisterPayload = {
    username: string;
    password: string;
    device_id?: string;
    ik_pub: string;
    sig_pub: string;
    spk_pub: string;
    spk_sig: string;
    otk_pubs: string[];
};

export type LoginPayload = {
    username: string;
    password: string;
    device_id?: string;
};

export type BundleResponse = {
    username: string;
    ik_pub: string;
    sig_pub: string;
    spk_pub: string;
    spk_sig: string;
    otk_pub?: string | null;
    device_id: string;
};

export type PreKeyUpdate = {
    spk_pub: string;
    spk_sig: string;
    otk_pubs: string[];
};

export type EnvelopeFrame = {
    id: string;
    to_user: string;
    to_device: string | null;
    ratchet_header: Record<string, unknown>;
    ciphertext: string;
    ts: string;
};

async function jsonRequest<T>(path: string, opts: RequestInit = {}): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
        ...opts,
        headers: {
            'Content-Type': 'application/json',
            ...(opts.headers || {}),
        },
    });
    if (!res.ok) {
        const detail = await res.text();
        throw new Error(`API ${res.status}: ${detail || res.statusText}`);
    }
    return (await res.json()) as T;
}

export function apiBaseUrl() {
    return API_BASE;
}

export function wsUrl(token: string) {
    const sep = WS_BASE.includes('?') ? '&' : '?';
    return `${WS_BASE}${token ? `${sep}token=${encodeURIComponent(token)}` : ''}`;
}

export async function register(payload: RegisterPayload) {
    return jsonRequest<{ access_token: string }>(`/v1/register`, {
        method: 'POST',
        body: JSON.stringify(payload),
    });
}

export async function login(payload: LoginPayload) {
    return jsonRequest<{ access_token: string }>(`/v1/login`, {
        method: 'POST',
        body: JSON.stringify(payload),
    });
}

export async function fetchBundle(username: string, token: string) {
    return jsonRequest<BundleResponse>(`/v1/users/${encodeURIComponent(username)}/bundle`, {
        headers: { Authorization: `Bearer ${token}` },
    });
}

export async function rotatePreKeys(deviceId: string, token: string, update: PreKeyUpdate) {
    return jsonRequest<{ status: string }>(`/v1/devices/${deviceId}/prekeys`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify(update),
    });
}

export function openSocket(token: string): WebSocket {
    return new WebSocket(wsUrl(token));
}

export type SendFrame = {
    action: 'send';
    to_user: string;
    to_device?: string | null;
    ratchet_header: SessionHeader;
    ciphertext: string; // hex
    msg_id: string;
    ts: string;
};

export type RecvFrame = { action: 'recv' };
export type ReceiptFrame = { action: 'receipt'; id: string };
export type CloseFrame = { action: 'close' };

export type OutgoingFrame = SendFrame | RecvFrame | ReceiptFrame | CloseFrame;

export function parseEnvelopeFrame(input: unknown): EnvelopeFrame | null {
    if (!input || typeof input !== 'object') return null;
    const maybe = input as Record<string, unknown>;
    if (maybe.type && maybe.type !== 'envelope') return null;
    if (typeof maybe.ciphertext !== 'string' || typeof maybe.ts !== 'string') return null;
    return {
        id: String(maybe.id ?? ''),
        to_user: String(maybe.to_user ?? ''),
        to_device: maybe.to_device ? String(maybe.to_device) : null,
        ratchet_header: (maybe.ratchet_header as Record<string, unknown>) || {},
        ciphertext: maybe.ciphertext,
        ts: maybe.ts,
    };
}