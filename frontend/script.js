/* eslint-disable no-console */
const $ = id => document.getElementById(id);

const dom = {
    datetime: $('datetime'),
    totalPackets: $('total-packets'),
    threatsBlocked: $('threats-blocked'),
    activeHosts: $('active-hosts'),
    attackRate: $('attack-rate'),
    timelineCanvas: $('threat-timeline'),
    alertsContainer: $('alerts-container'),
    alertCount: $('alert-count'),
    inspectorStatus: $('inspector-status'),
    inspectorContent: $('inspector-content'),
    nodeDetails: $('node-details-content'),
    networkViewport: $('network-viewport'),
    speedSlider: $('speed-slider'),
    alertModal: $('alert-modal'),
    modalBody: $('modal-body')
};

const uiControls = {
    pause: $('pause-btn'),
    step: $('step-btn'),
    togglePackets: $('toggle-packets'),
    closeNode: $('close-node-details'),
    closeModal: $('close-modal')
};

const QUICK_ATTACKS = [
    {
        type: 'SQL Injection',
        payload: "GET /search?q=' OR '1'='1' -- HTTP/1.1",
        description: 'SQL keyword injection against a form endpoint.'
    },
    {
        type: 'Cross-Site Scripting',
        payload: "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
        description: 'Script tag payload targeting reflected XSS.'
    },
    {
        type: 'Command Injection',
        payload: 'POST /api/backup;rm -rf / HTTP/1.1',
        description: 'OS command execution attempt detected.'
    },
    {
        type: 'FTP Brute Force',
        payload: 'USER admin\r\nPASS invalid\r\n',
        description: 'Credential stuffing against an FTP service.'
    },
    {
        type: 'DDoS Flood',
        payload: 'UDP flood at 50k pps',
        description: 'Volumetric traffic spike on edge interface.'
    }
];

const NETWORK_DEFINITION = {
    nodes: [
        { id: 'router-1', label: 'Edge Router', type: 'router', ip: '198.51.100.1', data: ['internet-gateway'], position: { x: 0, y: 0, z: 0 } },
        { id: 'fw-1', label: 'Perimeter FW', type: 'firewall', ip: '198.51.100.2', data: [], position: { x: 0, y: 0, z: 2 } },
        { id: 'switch-1', label: 'Core Switch', type: 'switch', ip: '10.0.0.1', data: [], position: { x: 0, y: 0, z: 4 } },
        { id: 'web-01', label: 'Web Server', type: 'server', ip: '10.0.1.10', data: ['public-website'], position: { x: -3, y: 0, z: 6 } },
        { id: 'web-02', label: 'Web Server', type: 'server', ip: '10.0.1.11', data: ['public-website'], position: { x: 3, y: 0, z: 6 } },
        { id: 'app-01', label: 'App Server', type: 'server', ip: '10.0.2.20', data: ['application-logic'], position: { x: -1.5, y: 0, z: 8 } },
        { id: 'app-02', label: 'App Server', type: 'server', ip: '10.0.2.21', data: ['application-logic'], position: { x: 1.5, y: 0, z: 8 } },
        { id: 'db-01', label: 'DB Server', type: 'storage', ip: '10.0.3.30', data: ['customers', 'orders'], position: { x: 0, y: 0, z: 10 } },
        { id: 'storage-01', label: 'Storage SAN', type: 'storage', ip: '10.0.4.40', data: ['backups', 'archives'], position: { x: 0, y: 2, z: 8 } },
        { id: 'wap-1', label: 'WAP-Floor2', type: 'wap', ip: '10.0.5.50', data: [], position: { x: -4, y: 0, z: 4 } },
        { id: 'host-01', label: 'Workstation', type: 'host', ip: '10.0.6.60', data: [], position: { x: -5, y: 0, z: 6 } },
        { id: 'host-02', label: 'Workstation', type: 'host', ip: '10.0.6.61', data: [], position: { x: -5, y: 0, z: 8 } }
    ],
    connections: [
        ['router-1', 'fw-1'],
        ['fw-1', 'switch-1'],
        ['switch-1', 'web-01'],
        ['switch-1', 'web-02'],
        ['web-01', 'app-01'],
        ['web-02', 'app-02'],
        ['app-01', 'db-01'],
        ['app-02', 'db-01'],
        ['db-01', 'storage-01'],
        ['switch-1', 'wap-1'],
        ['wap-1', 'host-01'],
        ['wap-1', 'host-02']
    ]
};

const TYPE_COLORS = {
    router: 0x00ffff,
    firewall: 0xff0040,
    switch: 0x9d4edd,
    server: 0x00ff88,
    storage: 0x9d4edd,
    wap: 0xffbe0b,
    host: 0xa0a0b8
};

const NODE_GEOMETRIES = {
    router: () => new THREE.BoxGeometry(1, 0.5, 1),
    firewall: () => new THREE.BoxGeometry(0.8, 1.2, 0.3),
    switch: () => new THREE.BoxGeometry(1.5, 0.3, 0.8),
    server: () => new THREE.BoxGeometry(0.8, 1.5, 0.8),
    storage: () => new THREE.CylinderGeometry(0.6, 0.6, 0.4, 16),
    wap: () => new THREE.ConeGeometry(0.5, 1, 8),
    host: () => new THREE.BoxGeometry(0.6, 0.8, 0.6)
};

const PACKET_SPEED = { min: 0.003, max: 0.01 };
const PACKET_COLORS = {
    normal: 0x00ffff,
    alternate: 0x00ff88,
    attack: 0xff0040
};

const RANDOM_ATTACKERS = [
    '203.0.113.45',
    '198.51.100.77',
    '192.0.2.123',
    '203.0.113.88',
    '198.51.100.99',
    '192.0.2.200',
    '203.0.113.101',
    '198.51.100.42'
];

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
const formatNumber = value => Number(value || 0).toLocaleString('en-US');
const randomItem = (arr, fallback = null) => (arr.length ? arr[Math.floor(Math.random() * arr.length)] : fallback);
const toPercent = value => {
    const numeric = Number(value ?? 0);
    return `${numeric > 1 ? Math.round(numeric) : Math.round(numeric * 100)}%`;
};

const state = {
    alerts: [],
    selectedAlert: null,
    stats: { packets: 0, blocked: 0, hosts: 0, attackRate: 0 },
    timeline: [],
    timelineCtx: null,
    nodes: new Map(),
    sceneObjects: [],
    linesGroup: null,
    packetsGroup: null,
    packetTrails: [],
    connections: [],
    scene: null,
    camera: null,
    renderer: null,
    cameraTarget: new THREE.Vector3(0, 1.5, 4),
    cameraSpherical: new THREE.Spherical(),
    isDragging: false,
    dragButton: 0,
    lastPointer: { x: 0, y: 0 },
    webSocket: null,
    paused: false,
    speedMultiplier: 1,
    simulationEnabled: false,
    llmVerdicts: {}
};

function updateClock() {
    if (!dom.datetime) return;
    const now = new Date();
    dom.datetime.textContent = now.toLocaleDateString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function formatTime(date) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function drawTimeline() {
    if (!state.timelineCtx) return;
    const ctx = state.timelineCtx;
    const { width, height } = ctx.canvas;
    ctx.clearRect(0, 0, width, height);
    if (!state.timeline.length) return;

    const maxVal = Math.max(...state.timeline, 1);
    const barWidth = width / state.timeline.length;

    ctx.fillStyle = 'rgba(255, 59, 130, 0.18)';
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = '#ff3b82';
    state.timeline.forEach((value, index) => {
        const barHeight = (value / maxVal) * height;
        const x = index * barWidth;
        ctx.fillRect(x, height - barHeight, barWidth * 0.8, barHeight);
    });
}

function pushTimeline(value) {
    state.timeline.push(value);
    while (state.timeline.length > 40) {
        state.timeline.shift();
    }
    drawTimeline();
}

function applyStats(nextStats) {
    state.stats = {
        packets: Number(nextStats.packets ?? state.stats.packets ?? 0),
        blocked: Number(nextStats.blocked ?? state.stats.blocked ?? 0),
        hosts: Number(nextStats.hosts ?? state.stats.hosts ?? 0),
        attackRate: Number(nextStats.attackRate ?? state.stats.attackRate ?? 0)
    };

    if (dom.totalPackets) dom.totalPackets.textContent = formatNumber(state.stats.packets);
    if (dom.threatsBlocked) dom.threatsBlocked.textContent = formatNumber(state.stats.blocked);
    if (dom.activeHosts) dom.activeHosts.textContent = formatNumber(state.stats.hosts);
    if (dom.attackRate) dom.attackRate.textContent = `${state.stats.attackRate.toFixed(1)}/min`;
    pushTimeline(state.stats.attackRate);
}

function buildDetail(label, value, extraClass = '') {
    const row = document.createElement('div');
    row.className = extraClass || 'packet-detail';

    const lbl = document.createElement('span');
    lbl.className = extraClass === 'node-detail' ? 'node-label' : 'packet-label';
    lbl.textContent = label;

    const val = document.createElement('span');
    val.className = extraClass === 'node-detail' ? 'node-value' : 'packet-value';
    val.textContent = value;

    row.appendChild(lbl);
    row.appendChild(val);
    return row;
}

const CRITICAL_ATTACK_TYPES = ['Kill Chain Detected', 'Ransomware C2 Callback', 'Log4Shell Exploit', 'C2 Beacon Communication', 'Credential Dumping'];
const HIGH_ATTACK_TYPES = ['SQL Injection', 'Command Injection', 'SMB Exploitation', 'SSH Brute Force', 'Lateral Movement', 'Data Exfiltration'];

function classifySeverity(attackType, confidence) {
    if (CRITICAL_ATTACK_TYPES.some(t => attackType.includes(t)) || confidence >= 95) return 'critical';
    if (HIGH_ATTACK_TYPES.some(t => attackType.includes(t)) || confidence >= 85) return 'high';
    if (confidence >= 70) return 'medium';
    return 'low';
}

function normalizeAlert(alert) {
    const attackType = (alert.attack_types || alert.attacks || [alert.attack || alert.type || 'Threat'])[0] || 'Threat';
    const timestamp = alert.timestamp ? new Date(alert.timestamp * 1000) : new Date();
    const sourceIP = alert.source_ip || alert.sourceIP || 'Unknown';
    const targetId = alert.target_node || alert.targetId || alert.target_id || alert.dest_ip || 'unknown';
    const targetNode = state.nodes.get(targetId);
    const targetLabel = targetNode?.label || alert.dest_ip || targetId || 'Unknown';
    const rawConfidence = alert.confidence ?? 0.8;
    const confidence = Number(rawConfidence) > 1 ? Math.round(Number(rawConfidence)) : Math.round(Number(rawConfidence) * 100);
    const action = alert.mitigation?.action || alert.action || 'Flagged';
    const flags = alert.flags?.join(', ') || alert.packet_flags || '[ ]';
    const payloadSnippet = alert.payload_snippet || alert.payload || '';
    const targetData = targetNode?.data?.join(', ') || (alert.targeted_data || []).join(', ');
    const severity = alert.severity || classifySeverity(attackType, confidence);
    return {
        attackType,
        timestamp,
        sourceIP,
        targetId,
        targetLabel,
        targetData,
        confidence,
        action,
        flags,
        payloadSnippet,
        severity,
        cve: alert.cve,
        description: alert.description
    };
}

function renderAlerts() {
    if (!dom.alertsContainer) return;
    dom.alertsContainer.innerHTML = '';

    const filter = document.getElementById('severity-filter')?.value || 'all';
    let filtered = state.alerts;
    if (filter !== 'all') {
        filtered = state.alerts.filter(a => {
            const v = normalizeAlert(a);
            return v.severity === filter;
        });
    }

    if (!filtered.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = state.alerts.length ? `No ${filter} alerts.` : 'No alerts detected yet.';
        dom.alertsContainer.appendChild(empty);
        if (dom.alertCount) dom.alertCount.textContent = state.alerts.length.toString();
        return;
    }

    if (dom.alertCount) dom.alertCount.textContent = state.alerts.length.toString();

    // Update critical banner
    const critCount = state.alerts.filter(a => normalizeAlert(a).severity === 'critical').length;
    const banner = document.getElementById('critical-banner');
    const bannerText = document.getElementById('critical-banner-text');
    if (banner && bannerText) {
        if (critCount > 0) {
            banner.style.display = 'flex';
            bannerText.textContent = `${critCount} CRITICAL ALERT${critCount > 1 ? 'S' : ''} ACTIVE`;
        } else {
            banner.style.display = 'none';
        }
    }

    filtered.slice(0, 15).forEach(alert => {
        const view = normalizeAlert(alert);
        const item = document.createElement('div');
        item.className = `alert-item severity-${view.severity}`;
        if (state.selectedAlert?.id === alert.id) {
            item.classList.add('highlighted');
        }

        const header = document.createElement('div');
        header.className = 'alert-header';
        const type = document.createElement('span');
        type.className = 'alert-type';
        const llmVerdict = alert.llm_verdict || state.llmVerdicts?.[alert.id];
        const llmBadgeHtml = llmVerdict
            ? `<span class="llm-badge ${llmVerdict.verdict}" title="LLM: ${llmVerdict.reasoning || llmVerdict.verdict}">${llmVerdict.verdict === 'true_positive' ? 'TP' : llmVerdict.verdict === 'false_positive' ? 'FP' : '??'}</span>`
            : '';
        type.innerHTML = `${view.attackType}<span class="alert-severity-badge ${view.severity}">${view.severity.toUpperCase()}</span>${llmBadgeHtml}`;
        const time = document.createElement('span');
        time.className = 'alert-time';
        time.textContent = formatTime(view.timestamp);
        header.appendChild(type);
        header.appendChild(time);

        const details = document.createElement('div');
        details.className = 'alert-details';
        details.innerHTML = `
            <div>Source: <span class="alert-source">${view.sourceIP}</span></div>
            <div>Target: ${view.targetLabel}</div>
            <div>Confidence: ${view.confidence}% | Action: ${view.action}</div>
        `;

        item.appendChild(header);
        item.appendChild(details);
        item.addEventListener('click', () => {
            const shouldOpenModal = view.confidence >= 90;
            selectAlert(alert, { openModal: shouldOpenModal, highlightScene: true });
        });
        dom.alertsContainer.appendChild(item);
    });
}

function updateInspector(alert) {
    if (!dom.inspectorContent || !dom.inspectorStatus) return;
    dom.inspectorContent.innerHTML = '';

    if (!alert) {
        dom.inspectorStatus.textContent = 'No packet selected';
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = 'Select an alert to inspect packet details';
        dom.inspectorContent.appendChild(empty);
        return;
    }

    const view = normalizeAlert(alert);
    const targetNode = state.nodes.get(view.targetId);
    const targetIp = targetNode?.ip || alert.dest_ip || 'Unknown';

    dom.inspectorStatus.textContent = `Inspecting ${view.attackType} attack`;
    const fields = [
        ['Source IP', view.sourceIP],
        ['Target IP', targetIp],
        ['Attack Type', view.attackType],
        ['Flags', view.flags],
        ['Confidence', `${view.confidence}%`],
        ['Action', view.action]
    ];
    if (view.cve) {
        fields.push(['CVE', view.cve]);
    }
    fields.forEach(([label, value]) => {
        dom.inspectorContent.appendChild(buildDetail(label, value));
    });

    if (view.payloadSnippet) {
        const payload = document.createElement('div');
        payload.className = 'packet-payload';
        payload.textContent = view.payloadSnippet;
        dom.inspectorContent.appendChild(payload);
    }
}

function updateNodeInspector(node) {
    if (!dom.nodeDetails) return;
    dom.nodeDetails.innerHTML = '';
    if (!node) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = 'Click a node to view details';
        dom.nodeDetails.appendChild(empty);
        return;
    }

    const rows = [
        ['Name', node.label],
        ['Type', node.type.toUpperCase()],
        ['IP Address', node.ip],
        ['Data', node.data?.join(', ') || 'None'],
        ['Status', node.status || 'Online'],
        ['Last Seen', node.lastSeen || new Date().toLocaleTimeString()]
    ];
    rows.forEach(([label, value]) => dom.nodeDetails.appendChild(buildDetail(label, value, 'node-detail')));

    const actions = document.createElement('div');
    actions.className = 'node-actions';
    actions.style.marginTop = '10px';
    [
        { label: 'Isolate', className: 'modal-btn', handler: () => console.log('[Action] Isolate', node.id) },
        { label: 'Block Traffic', className: 'modal-btn block', handler: () => console.log('[Action] Block', node.ip) }
    ].forEach(action => {
        const btn = document.createElement('button');
        btn.className = action.className;
        btn.textContent = action.label;
        btn.addEventListener('click', action.handler);
        actions.appendChild(btn);
    });
    dom.nodeDetails.appendChild(actions);
}

function populateModal(alert) {
    if (!dom.modalBody) return;
    dom.modalBody.innerHTML = '';
    if (!alert) return;

    const view = normalizeAlert(alert);
    const targetNode = state.nodes.get(view.targetId);
    const targetIp = targetNode?.ip || alert.dest_ip || 'Unknown';

    dom.modalBody.innerHTML = `
        <div class="modal-section">
            <div class="modal-detail">
                <span class="modal-label">Attack Type:</span>
                <span class="modal-value highlight">${view.attackType}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Source IP:</span>
                <span class="modal-value highlight">${view.sourceIP}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Target Asset:</span>
                <span class="modal-value">${view.targetLabel} (${targetIp})</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Targeted Data:</span>
                <span class="modal-value">${view.targetData || 'None'}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Confidence:</span>
                <span class="modal-value">${view.confidence}%</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Action Taken:</span>
                <span class="modal-value ${view.action === 'Blocked' || view.action === 'block' ? 'highlight' : ''}">${view.action}</span>
            </div>
        </div>
        ${view.cve ? `
        <div class="modal-section">
            <div class="modal-section-title">VULNERABILITY DETAILS</div>
            <div class="modal-detail">
                <span class="modal-label">CVE ID:</span>
                <span class="modal-value cve">${view.cve}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Description:</span>
                <span class="modal-value">${view.description || 'Not provided'}</span>
            </div>
        </div>
        ` : ''}
        <div class="modal-section">
            <div class="modal-section-title">PACKET ANALYSIS</div>
            <div class="modal-detail">
                <span class="modal-label">Flags:</span>
                <span class="modal-value">${view.flags}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Payload Snippet:</span>
            </div>
            <div class="packet-payload">${view.payloadSnippet || 'Not captured'}</div>
        </div>
        <div class="modal-actions">
            <button class="modal-btn block">Block Source IP</button>
            <button class="modal-btn block">Isolate Target</button>
            <button class="modal-btn">Add to Watchlist</button>
            <button class="modal-btn">False Positive</button>
        </div>
    `;
}

function openModal(alert) {
    populateModal(alert);
    if (dom.alertModal) {
        dom.alertModal.classList.add('active');
        dom.alertModal.setAttribute('aria-hidden', 'false');
    }
}

function closeModal() {
    if (dom.alertModal) {
        dom.alertModal.classList.remove('active');
        dom.alertModal.setAttribute('aria-hidden', 'true');
    }
}

function selectAlert(alert, options = {}) {
    state.selectedAlert = alert;
    updateInspector(alert);
    renderAlerts();
    if (options.highlightScene) {
        const view = normalizeAlert(alert);
        if (view.targetId) {
            highlightNode(view.targetId);
        }
    }
    if (options.openModal) {
        openModal(alert);
    }
}

function clearNodeSelection() {
    state.sceneObjects.forEach(obj => { obj.material.emissiveIntensity = 0.25; });
    updateNodeInspector(null);
}

function highlightNode(nodeId) {
    state.sceneObjects.forEach(obj => {
        obj.material.emissiveIntensity = obj.userData.id === nodeId ? 1 : 0.25;
    });
    const node = state.nodes.get(nodeId);
    if (node) {
        updateNodeInspector(node);
    }
}

function addAlert(alert) {
    state.alerts.unshift(alert);
    if (state.alerts.length > 10) {
        state.alerts.pop();
    }
    renderAlerts();
    if (!state.selectedAlert) {
        updateInspector(alert);
    }
}

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

function baseApiUrl() {
    return resolveApiBase();
}

function baseWsUrl() {
    try {
        const apiBase = resolveApiBase();
        const apiUrl = new URL(apiBase);
        const protocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:';
        const token = getAuthToken();
        const query = token ? `?token=${encodeURIComponent(token)}` : '';
        return `${protocol}//${apiUrl.host}/ws${query}`;
    } catch (error) {
        const token = getAuthToken();
        const query = token ? `?token=${encodeURIComponent(token)}` : '';
        return `ws://127.0.0.1:8000/ws${query}`;
    }
}

function getAuthToken() {
    const explicit = window.__IDS_CONFIG__?.apiToken;
    return explicit || localStorage.getItem('ids_token') || '';
}

function authHeaders() {
    const token = getAuthToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
}

function attemptFetch(url, options = {}) {
    const headers = { ...(options.headers || {}), ...authHeaders() };
    return fetch(url, { ...options, headers }).then(resp => {
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
    });
}

function parseAlert(data) {
    const timestamp = data.timestamp ?? Math.floor(Date.now() / 1000);
    return {
        id: data.id || `alert-${timestamp}-${Math.random().toString(16).slice(2, 6)}`,
        timestamp,
        source_ip: data.source_ip,
        dest_ip: data.dest_ip,
        target_node: data.target_node || data.dest_ip,
        attack_types: data.attack_types || data.attacks || [data.type || 'Anomaly'],
        targeted_data: data.targeted_data || [],
        confidence: data.confidence ?? 0.85,
        mitigation: data.mitigation || { action: 'Flagged' },
        cve: data.cve,
        description: data.description,
        flags: data.flags,
        payload_snippet: data.payload_snippet || data.payload
    };
}

function connectWebSocket() {
    const url = baseWsUrl();
    try {
        const socket = new WebSocket(url);
        state.webSocket = socket;

        socket.onopen = () => {
            console.log('[WS] connected', url);
        };

        socket.onmessage = event => {
            try {
                const payload = JSON.parse(event.data);
                if (payload.type === 'attack_detected') {
                    addAlert(parseAlert(payload.data));
                } else if (payload.type === 'stats_update') {
                    applyStats({
                        packets: payload.data.packets_analyzed,
                        blocked: payload.data.threats_detected,
                        hosts: payload.data.active_hosts,
                        attackRate: payload.data.attack_rate ?? payload.data.threats_detected ?? 0
                    });
                } else if (payload.type === 'llm_update') {
                    // Phase 5: patch LLM verdict onto existing alerts
                    const alertId = payload.alert_id;
                    const verdict = payload.llm_verdict;
                    if (alertId && verdict) {
                        state.llmVerdicts[alertId] = verdict;
                        const existing = state.alerts.find(a => a.id === alertId);
                        if (existing) existing.llm_verdict = verdict;
                        renderAlerts();
                        console.log(`[LLM] verdict for ${alertId}: ${verdict.verdict}`);
                    }
                }
            } catch (error) {
                console.warn('[WS] invalid payload', error);
            }
        };

        socket.onclose = () => {
            console.warn('[WS] disconnected, retrying in 6s');
            state.webSocket = null;
            setTimeout(connectWebSocket, 6000);
        };

        socket.onerror = error => {
            console.warn('[WS] error', error);
            socket.close();
        };
    } catch (error) {
        console.warn('[WS] failed to connect', error);
    }
}

function setSimulationAvailability(enabled) {
    state.simulationEnabled = Boolean(enabled);
}

function buildScene() {
    if (!dom.networkViewport || typeof THREE === 'undefined') return;
    const width = dom.networkViewport.clientWidth || 800;
    const height = dom.networkViewport.clientHeight || 600;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a12);
    scene.fog = new THREE.Fog(0x0a0a12, 10, 50);

    const camera = new THREE.PerspectiveCamera(75, width / height, 0.1, 1000);
    camera.position.set(0, 10, 15);
    camera.lookAt(0, 0, 5);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(window.devicePixelRatio || 1);
    renderer.setSize(width, height);

    dom.networkViewport.innerHTML = '';
    dom.networkViewport.appendChild(renderer.domElement);

    const ambient = new THREE.AmbientLight(0x333333);
    scene.add(ambient);

    const directional = new THREE.DirectionalLight(0x00ffff, 0.5);
    directional.position.set(0, 10, 5);
    scene.add(directional);

    const gridHelper = new THREE.GridHelper(20, 20, 0x00ffff, 0x004444);
    gridHelper.position.y = -2;
    scene.add(gridHelper);

    const linesGroup = new THREE.Group();
    scene.add(linesGroup);

    const packetsGroup = new THREE.Group();
    scene.add(packetsGroup);

    state.scene = scene;
    state.camera = camera;
    state.renderer = renderer;
    state.linesGroup = linesGroup;
    state.packetsGroup = packetsGroup;
    state.cameraTarget.set(0, 1.5, 4);
    state.cameraSpherical.setFromVector3(camera.position.clone().sub(state.cameraTarget));

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();

    renderer.domElement.addEventListener('pointerdown', event => {
        if (event.button !== 0) return;
        const rect = renderer.domElement.getBoundingClientRect();
        pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        raycaster.setFromCamera(pointer, camera);
        const intersects = raycaster.intersectObjects(state.sceneObjects);
        if (intersects.length > 0) {
            const mesh = intersects[0].object;
            highlightNode(mesh.userData.id);
        }
    });


    window.addEventListener('resize', () => {
        const newWidth = dom.networkViewport.clientWidth || 800;
        const newHeight = dom.networkViewport.clientHeight || 600;
        renderer.setSize(newWidth, newHeight);
        camera.aspect = newWidth / newHeight;
        camera.updateProjectionMatrix();
        syncCameraPosition();
    });

    setupManualCameraControls();
}

function populateScene() {
    if (!state.scene) return;
    if (state.sceneObjects.length) {
        seedPacketTrails();
        return;
    }
    state.connections = [];
    NETWORK_DEFINITION.nodes.forEach(node => {
        state.nodes.set(node.id, {
            ...node,
            status: 'Online',
            data: Array.isArray(node.data) ? node.data : [],
            lastSeen: new Date().toLocaleTimeString()
        });

        const geometryFactory = NODE_GEOMETRIES[node.type] || NODE_GEOMETRIES.router;
        const geometry = geometryFactory();
        const color = TYPE_COLORS[node.type] || 0x00ffff;
        const material = new THREE.MeshPhongMaterial({
            color,
            emissive: color,
            emissiveIntensity: 0.2,
            transparent: true,
            opacity: 0.8
        });
        const mesh = new THREE.Mesh(geometry, material);
        const baseHeight = node.position?.y || 0;
        const lift = 0;
        const finalHeight = baseHeight + lift;
        mesh.position.set(node.position.x, finalHeight, node.position.z);
        mesh.userData = { id: node.id, baseY: finalHeight };
        state.scene.add(mesh);
        state.sceneObjects.push(mesh);

        const labelCanvas = document.createElement('canvas');
        const ctx = labelCanvas.getContext('2d');
        labelCanvas.width = 256;
        labelCanvas.height = 64;
        ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
        ctx.fillRect(0, 0, 256, 64);
        ctx.font = '20px Orbitron';
        ctx.fillStyle = '#00ffff';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, 128, 36);
        const texture = new THREE.CanvasTexture(labelCanvas);
        const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
        const sprite = new THREE.Sprite(spriteMaterial);
        sprite.scale.set(2, 0.5, 1);
        sprite.position.set(node.position.x, baseHeight + lift + 1.5, node.position.z);
        state.scene.add(sprite);
    });

    NETWORK_DEFINITION.connections.forEach(([sourceId, targetId]) => {
        const sourceNode = state.nodes.get(sourceId);
        const targetNode = state.nodes.get(targetId);
        if (!sourceNode || !targetNode) return;

        const sourceBase = sourceNode.position?.y || 0;
        const targetBase = targetNode.position?.y || 0;
        const sourceLift = 0.1;
        const targetLift = 0.1;
        const start = new THREE.Vector3(
            sourceNode.position.x,
            sourceBase + sourceLift,
            sourceNode.position.z
        );
        const end = new THREE.Vector3(
            targetNode.position.x,
            targetBase + targetLift,
            targetNode.position.z
        );
        const points = [start, end];
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const material = new THREE.LineBasicMaterial({ color: 0x00ffff, transparent: true, opacity: 0.5 });
        const line = new THREE.Line(geometry, material);
        state.linesGroup.add(line);

        state.connections.push({ start, end });
    });

    seedPacketTrails();
}

function seedPacketTrails() {
    if (!state.packetsGroup) return;
    state.packetTrails.forEach(packet => {
        state.packetsGroup.remove(packet.mesh);
    });
    state.packetTrails = [];

    const totalPackets = Math.min(30, Math.max(state.connections.length * 2, 10));
    for (let i = 0; i < totalPackets; i += 1) {
        const connection = randomItem(state.connections);
        if (!connection) break;
        const size = 0.1 + Math.random() * 0.1;
        const geometry = new THREE.SphereGeometry(size, 8, 8);
        const isAttackPacket = Math.random() < 0.3;
        const packetColor = isAttackPacket
            ? PACKET_COLORS.attack
            : (Math.random() > 0.5 ? PACKET_COLORS.normal : PACKET_COLORS.alternate);
        const material = new THREE.MeshBasicMaterial({
            color: packetColor,
            transparent: true,
            opacity: 0.8
        });
        const mesh = new THREE.Mesh(geometry, material);
        state.packetsGroup.add(mesh);
        const progress = Math.random();
        mesh.position.lerpVectors(connection.start, connection.end, progress);
        state.packetTrails.push({
            mesh,
            connection,
            progress,
            speed: Math.random() * (PACKET_SPEED.max - PACKET_SPEED.min) + PACKET_SPEED.min,
            isAttack: isAttackPacket
        });
    }
}

function animateScene() {
    if (!state.renderer || !state.scene || !state.camera) return;
    const tick = () => {
        if (!state.paused) {
            state.sceneObjects.forEach((mesh, index) => {
                mesh.rotation.y += 0.0015 * state.speedMultiplier;
                const baseY = mesh.userData?.baseY ?? 0.6;
                mesh.position.y = baseY + Math.sin((Date.now() * 0.0015 + index) * state.speedMultiplier) * 0.03;
            });
            state.packetTrails.forEach(packet => {
                packet.progress += packet.speed * (state.speedMultiplier || 1);
                if (packet.progress > 1) {
                    packet.progress = 0;
                }
                packet.mesh.position.lerpVectors(packet.connection.start, packet.connection.end, packet.progress);
            });
        }
        state.renderer.render(state.scene, state.camera);
        requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
}

function syncCameraPosition() {
    if (!state.camera) return;
    const offset = new THREE.Vector3().setFromSpherical(state.cameraSpherical);
    state.camera.position.copy(state.cameraTarget.clone().add(offset));
    state.camera.lookAt(state.cameraTarget);
}

function panCamera(deltaX, deltaY) {
    if (!state.camera) return;
    const panOffset = new THREE.Vector3();
    const panLeft = distance => {
        const v = new THREE.Vector3().setFromMatrixColumn(state.camera.matrix, 0);
        v.multiplyScalar(-distance);
        panOffset.add(v);
    };
    const panUp = distance => {
        const v = new THREE.Vector3().setFromMatrixColumn(state.camera.matrix, 1);
        v.multiplyScalar(distance);
        panOffset.add(v);
    };
    const rect = dom.networkViewport.getBoundingClientRect();
    const scale = state.cameraSpherical.radius * 0.002;
    panLeft((deltaX / rect.width) * scale * rect.width);
    panUp((deltaY / rect.height) * scale * rect.height);
    state.cameraTarget.add(panOffset);
    state.camera.position.add(panOffset);
    state.cameraSpherical.setFromVector3(state.camera.position.clone().sub(state.cameraTarget));
}

function setupManualCameraControls() {
    const viewport = dom.networkViewport;
    if (!viewport) return;
    viewport.addEventListener('contextmenu', event => event.preventDefault());

    viewport.addEventListener('pointerdown', event => {
        if (!state.camera) return;
        state.isDragging = true;
        state.dragButton = event.button;
        state.lastPointer = { x: event.clientX, y: event.clientY };
        viewport.setPointerCapture?.(event.pointerId);
        viewport.classList.add('is-dragging');
        viewport.style.cursor = 'grabbing';
    });

    viewport.addEventListener('pointermove', event => {
        if (!state.isDragging) return;
        const dx = event.clientX - state.lastPointer.x;
        const dy = event.clientY - state.lastPointer.y;
        state.lastPointer = { x: event.clientX, y: event.clientY };
        if (state.dragButton === 2) {
            panCamera(dx, dy);
            return;
        }
        const ROTATE_SPEED = 0.005;
        state.cameraSpherical.theta -= dx * ROTATE_SPEED;
        state.cameraSpherical.phi -= dy * ROTATE_SPEED;
        state.cameraSpherical.phi = clamp(state.cameraSpherical.phi, 0.2, Math.PI / 2.05);
        syncCameraPosition();
    });

    const stopDragging = event => {
        if (!state.isDragging) return;
        state.isDragging = false;
        viewport.classList.remove('is-dragging');
        viewport.style.cursor = 'grab';
        if (event.pointerId != null && viewport.hasPointerCapture?.(event.pointerId)) {
            viewport.releasePointerCapture(event.pointerId);
        }
    };

    viewport.addEventListener('pointerup', stopDragging);
    viewport.addEventListener('pointerleave', stopDragging);
    viewport.addEventListener('pointercancel', stopDragging);

    viewport.addEventListener('wheel', event => {
        event.preventDefault();
        const zoomFactor = 1 + Math.abs(event.deltaY) * 0.0008;
        if (event.deltaY < 0) {
            state.cameraSpherical.radius = Math.max(4, state.cameraSpherical.radius / zoomFactor);
        } else {
            state.cameraSpherical.radius = Math.min(80, state.cameraSpherical.radius * zoomFactor);
        }
        syncCameraPosition();
    }, { passive: false });
}

async function triggerSimulation(attackType) {
    try {
        if (!state.simulationEnabled) {
            console.warn('[Simulate] Simulation disabled');
            return;
        }
        const attackDef = QUICK_ATTACKS.find(item => item.type === attackType) || QUICK_ATTACKS[0];
        const victims = NETWORK_DEFINITION.nodes.filter(node => node.ip);
        const payload = {
            attack_type: attackDef.type,
            source_ip: randomItem(RANDOM_ATTACKERS),
            target_ip: randomItem(victims)?.ip || '10.0.1.10',
            payload: attackDef.payload
        };
        const response = await fetch(`${baseApiUrl()}/api/simulate-attack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...authHeaders() },
            body: JSON.stringify(payload)
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        console.log('[Simulate] Attack dispatched', attackDef.type);
    } catch (error) {
        console.warn('[Simulate] Failed to trigger simulation', error);
    }
}

function wireControls() {
    const pauseIcon = '\u23F8';
    const playIcon = '\u25B6';

    uiControls.pause?.addEventListener('click', () => {
        state.paused = !state.paused;
        uiControls.pause.innerHTML = `<span class="icon">${state.paused ? playIcon : pauseIcon}</span>`;
    });

    uiControls.step?.addEventListener('click', () => {
        if (!state.paused) return;
        state.sceneObjects.forEach(mesh => { mesh.rotation.y += 0.05; });
    });

    uiControls.togglePackets?.addEventListener('click', () => {
        if (!state.linesGroup) return;
        const willHide = state.linesGroup.visible;
        state.linesGroup.visible = !willHide;
        if (state.packetsGroup) {
            state.packetsGroup.visible = !willHide;
        }
        uiControls.togglePackets.style.opacity = willHide ? '0.5' : '1';
    });

    if (dom.speedSlider) {
        state.speedMultiplier = parseFloat(dom.speedSlider.value) || 1;
        dom.speedSlider.addEventListener('input', event => {
            const value = parseFloat(event.target.value);
            state.speedMultiplier = Number.isFinite(value) ? value : 1;
        });
    }

    uiControls.closeNode?.addEventListener('click', () => clearNodeSelection());
    uiControls.closeModal?.addEventListener('click', () => closeModal());
    dom.alertModal?.addEventListener('click', event => {
        if (event.target === dom.alertModal) {
            closeModal();
        }
    });
}

function bootstrapDashboard() {
    state.timelineCtx = dom.timelineCanvas?.getContext('2d') || null;
    updateClock();
    setInterval(updateClock, 1000);
    applyStats({ packets: 0, blocked: 0, hosts: 0, attackRate: 0 });
    updateInspector(null);
    updateNodeInspector(null);
    renderAlerts();
}

/* ================================================================
   CATEGORY 1 UPGRADES — Analytics, Incidents, MITRE, Model Health
   ================================================================ */

let attackDistChart = null;
let attackTimelineChart = null;

const CHART_COLORS = [
    '#ff0040', '#00ffff', '#9d4edd', '#00ff88', '#ffbe0b',
    '#ff006e', '#3a86ff', '#fb5607', '#8338ec', '#06d6a0'
];

function initCharts() {
    if (typeof Chart === 'undefined') return;

    Chart.defaults.color = '#a0a0b8';
    Chart.defaults.font.family = "'Roboto Mono', monospace";
    Chart.defaults.font.size = 10;

    // Attack Distribution Donut
    const distCtx = document.getElementById('attack-distribution-chart');
    if (distCtx) {
        attackDistChart = new Chart(distCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: CHART_COLORS,
                    borderColor: 'rgba(10, 10, 18, 0.8)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 10,
                            padding: 8,
                            font: { size: 9 }
                        }
                    }
                },
                cutout: '60%'
            }
        });
    }

    // Attack Timeline Bar Chart
    const timeCtx = document.getElementById('attack-timeline-chart');
    if (timeCtx) {
        attackTimelineChart = new Chart(timeCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attacks',
                    data: [],
                    backgroundColor: 'rgba(0, 255, 255, 0.4)',
                    borderColor: '#00ffff',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { color: 'rgba(0, 255, 255, 0.05)' },
                        ticks: { maxRotation: 45, font: { size: 8 } }
                    },
                    y: {
                        grid: { color: 'rgba(0, 255, 255, 0.05)' },
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        });
    }
}

function updateAttackDistChart(distribution) {
    if (!attackDistChart) return;
    const labels = Object.keys(distribution);
    const data = Object.values(distribution);
    attackDistChart.data.labels = labels;
    attackDistChart.data.datasets[0].data = data;
    attackDistChart.update('none');
}

function updateTimelineChart(hourly) {
    if (!attackTimelineChart) return;
    const entries = Object.entries(hourly).sort();
    const labels = entries.map(([k]) => k.split(' ')[1] || k);
    const data = entries.map(([, v]) => v);
    attackTimelineChart.data.labels = labels;
    attackTimelineChart.data.datasets[0].data = data;
    attackTimelineChart.update('none');
}

function renderMitreGrid(coverage, hits) {
    const grid = document.getElementById('mitre-grid');
    if (!grid || !coverage) return;

    const tactics = coverage.tactics || [];
    const techniques = coverage.techniques || {};
    const hitMap = hits || {};

    // Build tactic→technique hit count map
    const tacticHits = {};
    Object.values(techniques).forEach(t => {
        const tid = t.tactic_id;
        const techId = t.technique_id;
        tacticHits[tid] = (tacticHits[tid] || 0) + (hitMap[techId] || 0);
    });

    grid.innerHTML = '';
    tactics.forEach(tactic => {
        const count = tacticHits[tactic.id] || 0;
        const div = document.createElement('div');
        div.className = `mitre-tactic${count > 0 ? ' active' : ''}`;
        div.title = `${tactic.id}: ${tactic.name}`;
        div.innerHTML = `
            <div class="mitre-tactic-name">${tactic.name}</div>
            <div class="mitre-tactic-count">${count}</div>
        `;
        grid.appendChild(div);
    });
}

function renderTopIPs(ipList) {
    const tbody = document.getElementById('ip-table-body');
    if (!tbody) return;

    if (!ipList || !ipList.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No data yet</td></tr>';
        return;
    }

    const total = ipList.reduce((sum, item) => sum + item.count, 0);
    tbody.innerHTML = ipList.slice(0, 10).map(item => {
        const pct = total > 0 ? ((item.count / total) * 100).toFixed(1) : '0.0';
        return `<tr><td>${item.ip}</td><td>${item.count}</td><td>${pct}%</td></tr>`;
    }).join('');
}

function renderIncidents(incidents) {
    const list = document.getElementById('incident-list');
    const badge = document.getElementById('incident-badge');
    const headerCount = document.getElementById('incident-count-header');
    if (!list) return;

    if (badge) badge.textContent = incidents.length.toString();
    if (headerCount) headerCount.textContent = incidents.length.toString();

    if (!incidents.length) {
        list.innerHTML = '<div class="empty-state">No active incidents</div>';
        return;
    }

    list.innerHTML = incidents.slice(0, 8).map(inc => `
        <div class="incident-card severity-${inc.severity}">
            <div class="incident-card-header">
                <span class="incident-id">${inc.id}</span>
                <span class="severity-tag ${inc.severity}">${inc.severity.toUpperCase()}</span>
            </div>
            <div class="incident-narrative">${inc.narrative || inc.attack_type}</div>
            <div class="playbook-steps">
                ${(inc.playbook_steps || []).slice(0, 4).map(s =>
        `<span class="playbook-step${s.automated ? ' automated' : ''}">${s.action}</span>`
    ).join('')}
            </div>
        </div>
    `).join('');
}

function updateModelPerf(modelStatus, rlStatus) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

    if (modelStatus) {
        set('perf-model-version', `v${modelStatus.model_version || '1.0.0'}`);
        set('perf-drift-count', modelStatus.drift_events_1h ?? 0);
        set('perf-shadow-status', modelStatus.shadow_active ? `Active (${modelStatus.shadow_progress})` : 'Inactive');

        const healthEl = document.getElementById('perf-model-health');
        if (healthEl) {
            const h = modelStatus.health || 'green';
            healthEl.innerHTML = `<span class="health-badge ${h}">${h.toUpperCase()}</span>`;
        }

        // Header indicator
        const dot = document.getElementById('model-health-dot');
        const text = document.getElementById('model-health-text');
        if (dot) { dot.className = `indicator-dot ${modelStatus.health || 'green'}`; }
        if (text) { text.textContent = `v${modelStatus.model_version || '1.0.0'}`; }
    }

    if (rlStatus) {
        set('perf-rl-threshold', rlStatus.current_threshold?.toFixed(4) ?? '—');
        set('perf-rl-evals', rlStatus.total_evaluations ?? 0);
        set('perf-rl-action', rlStatus.last_action || '—');
        set('perf-rl-adjustments', rlStatus.total_adjustments ?? 0);

        // Header indicator
        const rlDot = document.getElementById('rl-status-dot');
        const rlText = document.getElementById('rl-status-text');
        if (rlDot) { rlDot.className = `indicator-dot ${rlStatus.enabled ? 'green' : 'yellow'}`; }
        if (rlText) { rlText.textContent = rlStatus.enabled ? 'Active' : 'Disabled'; }
    }
}

function fetchAnalytics() {
    attemptFetch(`${baseApiUrl()}/api/analytics`).then(data => {
        if (data.attack_type_distribution) updateAttackDistChart(data.attack_type_distribution);
        if (data.hourly_attack_counts) updateTimelineChart(data.hourly_attack_counts);
        if (data.mitre_coverage) renderMitreGrid(data.mitre_coverage, data.mitre_technique_hits);
        if (data.top_source_ips) renderTopIPs(data.top_source_ips);
        updateModelPerf(data.model_status, data.rl_status);
    }).catch(err => console.warn('[Analytics] fetch failed:', err));

    attemptFetch(`${baseApiUrl()}/api/incidents`).then(data => {
        if (data.incidents) renderIncidents(data.incidents);
    }).catch(err => console.warn('[Incidents] fetch failed:', err));
}

function startAnalyticsPolling() {
    initCharts();
    fetchAnalytics();
    setInterval(fetchAnalytics, 10000); // refresh every 10s
}

/* ================================================================
   CATEGORY 2 UPGRADES — Pages, Kill Chain, Signatures, Severity
   ================================================================ */

const KC_STAGE_NAMES = [
    'reconnaissance', 'weaponization', 'exploitation',
    'credential_access', 'lateral_movement', 'command_and_control', 'exfiltration'
];

let severityChart = null;
let trendsChart = null;
let sigEffChart = null;

function initCat2Charts() {
    if (typeof Chart === 'undefined') return;

    const sevCtx = document.getElementById('severity-chart');
    if (sevCtx) {
        severityChart = new Chart(sevCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{ data: [0, 0, 0, 0], backgroundColor: ['#ff0040', '#ff6b35', '#ffbe0b', '#00ff88'], borderColor: 'rgba(10,10,18,0.8)', borderWidth: 2 }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: '55%', plugins: { legend: { position: 'right', labels: { boxWidth: 10, font: { size: 9 } } } } }
        });
    }

    const trendCtx = document.getElementById('trends-chart');
    if (trendCtx) {
        trendsChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attack Count', data: [], borderColor: '#00ffff', backgroundColor: 'rgba(0,255,255,0.1)',
                    fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(0,255,255,0.05)' }, ticks: { font: { size: 8 }, maxRotation: 45 } },
                    y: { grid: { color: 'rgba(0,255,255,0.05)' }, beginAtZero: true }
                }
            }
        });
    }

    const sigCtx = document.getElementById('sig-effectiveness-chart');
    if (sigCtx) {
        sigEffChart = new Chart(sigCtx, {
            type: 'bar',
            data: { labels: [], datasets: [{ label: 'Matches', data: [], backgroundColor: 'rgba(157,78,221,0.5)', borderColor: '#9d4edd', borderWidth: 1 }] },
            options: {
                responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(0,255,255,0.05)' }, beginAtZero: true },
                    y: { grid: { color: 'rgba(0,255,255,0.05)' }, ticks: { font: { size: 9 } } }
                }
            }
        });
    }
}

// Page Navigation
function setupPageNavigation() {
    const navBtns = document.querySelectorAll('.nav-btn');
    const pages = document.querySelectorAll('.page-content');
    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.page;
            navBtns.forEach(b => b.classList.remove('active'));
            pages.forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const page = document.getElementById(`page-${target}`);
            if (page) page.classList.add('active');
            if (target === 'analytics') refreshAnalyticsPage();
            if (target === 'incidents') refreshIncidentsPage();
            if (target === 'models') refreshModelsPage();
            if (target === 'settings') refreshSettingsPage();
        });
    });

    // Severity filter
    const sevFilter = document.getElementById('severity-filter');
    if (sevFilter) sevFilter.addEventListener('change', () => renderAlerts());

    // Critical banner dismiss
    const dismiss = document.getElementById('critical-banner-dismiss');
    if (dismiss) dismiss.addEventListener('click', () => {
        const banner = document.getElementById('critical-banner');
        if (banner) banner.style.display = 'none';
    });
}

// Kill Chain Visualization
function renderKillChains(chains) {
    const container = document.getElementById('kill-chain-container');
    if (!container) return;
    if (!chains || !chains.length) {
        container.innerHTML = '<div class="empty-state">No kill chains detected</div>';
        return;
    }
    container.innerHTML = chains.map(chain => {
        const pct = Math.round(chain.completeness * 100);
        const scoreClass = pct >= 60 ? 'high' : pct >= 30 ? 'medium' : 'low';
        const stagesHtml = KC_STAGE_NAMES.map((stage, i) => {
            const isHit = chain.stages && chain.stages[stage];
            const label = stage.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            return `${i > 0 ? '<span class="kc-arrow">→</span>' : ''}<span class="kc-stage${isHit ? ' hit' : ''}" title="${label}">${label}</span>`;
        }).join('');
        return `<div class="kill-chain-row">
            <span class="kill-chain-ip">${chain.source_ip}</span>
            <div class="kill-chain-stages">${stagesHtml}</div>
            <span class="kill-chain-score ${scoreClass}">${pct}%</span>
        </div>`;
    }).join('');
}

// Signature Page
function renderSignatureList(sigs) {
    const list = document.getElementById('sig-list');
    const sigCount = document.getElementById('sig-count-text');
    if (sigCount) sigCount.textContent = sigs?.length ?? 0;
    if (!list) return;
    if (!sigs || !sigs.length) {
        list.innerHTML = '<div class="empty-state">No signatures loaded</div>';
        return;
    }
    list.innerHTML = sigs.map(s => {
        const sevColors = { critical: 'background:rgba(255,0,64,0.25);color:#ff0040', high: 'background:rgba(255,107,53,0.25);color:#ff6b35', medium: 'background:rgba(255,190,11,0.25);color:#ffbe0b', low: 'background:rgba(0,255,136,0.25);color:#00ff88' };
        return `<div class="sig-item">
            <span class="sig-item-name">${s.name}</span>
            <span class="sig-item-severity" style="${sevColors[s.severity] || ''}">${s.severity}</span>
            <span style="color:var(--text-secondary);min-width:40px;text-align:right">${s.match_count || 0}</span>
        </div>`;
    }).join('');
}

function renderSignatureStats(stats) {
    if (!stats) return;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('sig-total', stats.total_signatures || 0);
    set('sig-crit', stats.severity_breakdown?.critical || 0);
    set('sig-high', stats.severity_breakdown?.high || 0);
    set('sig-med', stats.severity_breakdown?.medium || 0);
    set('sig-low', stats.severity_breakdown?.low || 0);

    if (sigEffChart && stats.top_signatures) {
        const top = stats.top_signatures.slice(0, 8);
        sigEffChart.data.labels = top.map(s => s.name);
        sigEffChart.data.datasets[0].data = top.map(s => s.matches);
        sigEffChart.update('none');
    }
}

// Incident Timeline Page
function renderIncidentTimeline(incidents) {
    const tl = document.getElementById('incidents-timeline');
    if (!tl) return;
    if (!incidents || !incidents.length) {
        tl.innerHTML = '<div class="empty-state">No incidents recorded yet</div>';
        return;
    }
    tl.innerHTML = incidents.map(inc => {
        const time = inc.created_at ? new Date(inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
        return `<div class="incident-timeline-card severity-${inc.severity}">
            <div class="incident-time">${time}</div>
            <div class="incident-detail">
                <div class="incident-detail-title">${inc.id} — ${inc.attack_type || 'Unknown'}</div>
                <div class="incident-detail-desc">${inc.narrative || ''}</div>
                <div class="playbook-steps" style="margin-top:4px">
                    ${(inc.playbook_steps || []).slice(0, 3).map(s => `<span class="playbook-step${s.automated ? ' automated' : ''}">${s.action}</span>`).join('')}
                </div>
            </div>
        </div>`;
    }).join('');
}

function renderPlaybookLibrary(playbooks) {
    const lib = document.getElementById('playbook-library');
    if (!lib) return;
    if (!playbooks || !playbooks.length) {
        lib.innerHTML = '<div class="empty-state">No playbooks available</div>';
        return;
    }
    lib.innerHTML = playbooks.map(pb => `
        <div class="playbook-card">
            <div class="playbook-card-title">${pb.name || pb.attack_type}</div>
            <div class="playbook-card-steps">${(pb.steps || []).length} steps | Severity: ${pb.severity || '—'}</div>
        </div>
    `).join('');
}

function renderIncidentStats(stats) {
    if (!stats) return;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('inc-total', stats.active_incidents || 0);
    const bySev = stats.by_severity || {};
    set('inc-critical', bySev.critical || 0);
    set('inc-high', bySev.high || 0);
    set('inc-medium', bySev.medium || 0);
}

// Model Page
function renderRetrainHistory(status) {
    const container = document.getElementById('retrain-history');
    if (!container || !status) return;
    const history = status.retrain_history || [];
    if (!history.length) {
        container.innerHTML = '<div class="empty-state">No retraining events</div>';
        return;
    }
    container.innerHTML = history.map(h => `
        <div class="sig-item">
            <span class="sig-item-name">v${h.version} → v${h.new_version || '?'}</span>
            <span style="color:var(--text-secondary)">${h.timestamp ? new Date(h.timestamp * 1000).toLocaleString() : '—'}</span>
        </div>
    `).join('');
}

function renderRLQTable(rlStatus) {
    const container = document.getElementById('rl-qtable');
    if (!container || !rlStatus) return;
    const adjustments = rlStatus.adjustment_history || [];
    if (!adjustments.length) {
        container.innerHTML = `<div class="sig-item"><span class="sig-item-name">State</span><span style="color:var(--accent-cyan)">${rlStatus.current_state || '—'}</span></div>
        <div class="sig-item"><span class="sig-item-name">Epsilon</span><span style="color:var(--accent-cyan)">${rlStatus.epsilon?.toFixed(3) ?? '—'}</span></div>
        <div class="sig-item"><span class="sig-item-name">Q-Table Size</span><span style="color:var(--accent-cyan)">${rlStatus.q_table_size ?? '—'}</span></div>`;
        return;
    }
    container.innerHTML = adjustments.slice(-8).reverse().map(a => `
        <div class="sig-item"><span class="sig-item-name">${a.action || '?'}</span><span style="color:var(--accent-yellow)">${a.threshold?.toFixed(4) ?? ''}</span></div>
    `).join('');
}

// Severity Chart Update
function updateSeverityChart(dist) {
    if (!severityChart || !dist) return;
    severityChart.data.datasets[0].data = [dist.critical || 0, dist.high || 0, dist.medium || 0, dist.low || 0];
    severityChart.update('none');
}

// Trends Chart Update
function updateTrendsChart(hourly) {
    if (!trendsChart || !hourly) return;
    const entries = Object.entries(hourly).sort();
    trendsChart.data.labels = entries.map(([k]) => k.split(' ')[1] || k);
    trendsChart.data.datasets[0].data = entries.map(([, v]) => v);
    trendsChart.update('none');
}

// Page Refresh Functions
function refreshAnalyticsPage() {
    attemptFetch(`${baseApiUrl()}/api/analytics`).then(data => {
        if (data.severity_distribution) updateSeverityChart(data.severity_distribution);
        if (data.hourly_attack_counts) updateTrendsChart(data.hourly_attack_counts);
        if (data.mitre_coverage) renderMitreGrid(data.mitre_coverage, data.mitre_technique_hits);
        if (data.top_source_ips) renderTopIPs(data.top_source_ips);
    }).catch(() => { });

    attemptFetch(`${baseApiUrl()}/api/signatures`).then(data => {
        renderSignatureStats(data.stats);
    }).catch(() => { });

    attemptFetch(`${baseApiUrl()}/api/kill-chains`).then(data => {
        renderKillChains(data.active_chains);
    }).catch(() => { });
}

function refreshIncidentsPage() {
    attemptFetch(`${baseApiUrl()}/api/incidents`).then(data => {
        renderIncidentTimeline(data.incidents);
        renderIncidentStats(data.stats);
    }).catch(() => { });

    attemptFetch(`${baseApiUrl()}/api/playbooks`).then(data => {
        renderPlaybookLibrary(data.playbooks);
    }).catch(() => { });
}

function refreshModelsPage() {
    attemptFetch(`${baseApiUrl()}/api/model-status`).then(data => {
        updateModelPerf(data, null);
        renderRetrainHistory(data);
    }).catch(() => { });

    attemptFetch(`${baseApiUrl()}/api/rl-status`).then(data => {
        updateModelPerf(null, data);
        renderRLQTable(data);
    }).catch(() => { });
}

function refreshSettingsPage() {
    attemptFetch(`${baseApiUrl()}/api/signatures`).then(data => {
        renderSignatureList(data.signatures);
        renderSignatureStats(data.stats);
    }).catch(() => { });

    fetchLLMStatus();
}

function fetchLLMStatus() {
    attemptFetch(`${baseApiUrl()}/api/llm-status`).then(data => {
        // Header indicator
        const dot = document.getElementById('llm-status-dot');
        const text = document.getElementById('llm-status-text');
        if (dot) dot.className = `indicator-dot ${data.online ? 'green' : data.enabled ? 'yellow' : 'red'}`;
        if (text) text.textContent = data.online ? data.model : (data.enabled ? 'Fallback' : 'Disabled');

        // Settings panel
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('llm-panel-status', data.online ? '🟢 Online' : (data.enabled ? '🟡 Fallback (Heuristic)' : '🔴 Disabled'));
        set('llm-panel-model', data.model || '—');
        set('llm-panel-requests', data.total_requests ?? 0);
        set('llm-panel-cache', data.cache_hits ?? 0);
        set('llm-panel-latency', data.avg_latency ? `${(data.avg_latency * 1000).toFixed(0)}ms` : '—');
        set('llm-panel-fallback', data.online ? 'Inactive' : 'Active (heuristic classification)');
    }).catch(() => {
        const dot = document.getElementById('llm-status-dot');
        const text = document.getElementById('llm-status-text');
        if (dot) dot.className = 'indicator-dot red';
        if (text) text.textContent = 'Error';
    });
}

// Enhanced fetchAnalytics to include Cat 2 data
const _origFetchAnalytics = fetchAnalytics;
fetchAnalytics = function () {
    _origFetchAnalytics();

    attemptFetch(`${baseApiUrl()}/api/signatures`).then(data => {
        if (data.stats) {
            const ct = document.getElementById('sig-count-text');
            if (ct) ct.textContent = data.stats.total_signatures || 0;
        }
    }).catch(() => { });

    attemptFetch(`${baseApiUrl()}/api/kill-chains`).then(data => {
        if (data.active_chains?.length) renderKillChains(data.active_chains);
    }).catch(() => { });
};

/* ================================================================ */

function initialise() {
    bootstrapDashboard();
    wireControls();
    setupPageNavigation();
    initCat2Charts();
    if (dom.networkViewport && typeof THREE !== 'undefined') {
        buildScene();
        populateScene();
        animateScene();
    }
    connectWebSocket();
    attemptFetch(`${baseApiUrl()}/api/stats`).then(data => {
        setSimulationAvailability(data.simulation_enabled);
        applyStats({
            packets: data.packets_analyzed ?? 0,
            blocked: data.threats_detected ?? 0,
            hosts: data.active_hosts ?? 0,
            attackRate: data.attack_rate ?? data.threats_detected ?? 0
        });
    }).catch(() => {
        setSimulationAvailability(false);
    });
    startAnalyticsPolling();
    fetchLLMStatus();
    setInterval(fetchLLMStatus, 15000);
}

document.addEventListener('DOMContentLoaded', initialise);

