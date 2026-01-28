const form = document.getElementById('login-form');
const statusBox = document.getElementById('login-status');

function resolveApiBase() {
    const explicit = document.body?.dataset?.apiBase || window.__SECURECYBER_API__;
    if (explicit) {
        return explicit.replace(/\/$/, '');
    }
    const hostname = location.hostname || '127.0.0.1';
    const isSecure = location.protocol === 'https:';
    const scheme = isSecure ? 'https' : 'http';
    const defaultPort = isSecure ? '443' : '80';
    const currentPort = location.port || defaultPort;

    if (currentPort === '8000') {
        return location.origin && location.origin !== 'null'
            ? location.origin
            : `${scheme}://${hostname}:8000`;
    }

    return `${scheme}://${hostname}:8000`;
}

function setStatus(message, state) {
    if (!statusBox) return;
    statusBox.textContent = message;
    statusBox.classList.remove('ok', 'warn', 'blocked');
    if (state) {
        statusBox.classList.add(state);
    }
}

async function submitLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username')?.value || '';
    const password = document.getElementById('password')?.value || '';

    setStatus('Submitting login request...', 'warn');

    try {
        const response = await fetch(`${resolveApiBase()}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.alert_detected) {
            setStatus('Attack detected and reported to IDS dashboard.', 'blocked');
            return;
        }

        if (data.status === 'ok') {
            setStatus('Login accepted. No attack detected.', 'ok');
        } else {
            setStatus('Login rejected. No attack detected.', 'warn');
        }
    } catch (error) {
        setStatus('Login failed to reach IDS backend. Check server status.', 'warn');
        console.warn('[Login]', error);
    }
}

form?.addEventListener('submit', submitLogin);
