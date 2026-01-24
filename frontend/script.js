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
        { id: 'router-1', label: 'Edge Router', type: 'router', ip: '198.51.100.1', position: { x: 0, y: 0, z: -2 } },
        { id: 'fw-1', label: 'Perimeter FW', type: 'firewall', ip: '198.51.100.2', position: { x: -3.5, y: 0, z: 0.5 } },
        { id: 'fw-2', label: 'Perimeter FW', type: 'firewall', ip: '198.51.100.3', position: { x: 3.5, y: 0, z: 0.5 } },
        { id: 'switch-1', label: 'Core Switch', type: 'server', ip: '10.0.0.1', position: { x: 0, y: 0, z: 3.5 } },
        { id: 'web-01', label: 'Web Server', type: 'server', ip: '10.0.1.10', position: { x: -3.5, y: 0, z: 6.5 } },
        { id: 'web-02', label: 'Web Server', type: 'server', ip: '10.0.1.11', position: { x: 3.5, y: 0, z: 6.5 } },
        { id: 'app-01', label: 'App Server', type: 'server', ip: '10.0.2.20', position: { x: -2.5, y: 0, z: 8.2 } },
        { id: 'app-02', label: 'App Server', type: 'server', ip: '10.0.2.21', position: { x: 2.5, y: 0, z: 8.2 } },
        { id: 'db-01', label: 'DB Server', type: 'storage', ip: '10.0.3.30', position: { x: 0, y: 2.5, z: 10.2 } },
        { id: 'storage-01', label: 'Storage SAN', type: 'storage', ip: '10.0.4.40', position: { x: 0, y: 4.5, z: 11.8 } },
        { id: 'wap-01', label: 'WAP Floor 2', type: 'wap', ip: '10.0.5.50', position: { x: -5.5, y: 0, z: 5.5 } },
        { id: 'host-01', label: 'Workstation', type: 'host', ip: '10.0.6.60', position: { x: -6.5, y: 0, z: 7.5 } },
        { id: 'host-02', label: 'Workstation', type: 'host', ip: '10.0.6.61', position: { x: -6.5, y: 0, z: 9.5 } }
    ],
    connections: [
        ['router-1', 'fw-1'],
        ['router-1', 'fw-2'],
        ['fw-1', 'switch-1'],
        ['fw-2', 'switch-1'],
        ['switch-1', 'web-01'],
        ['switch-1', 'web-02'],
        ['web-01', 'app-01'],
        ['web-02', 'app-02'],
        ['app-01', 'db-01'],
        ['app-02', 'db-01'],
        ['db-01', 'storage-01'],
        ['switch-1', 'wap-01'],
        ['wap-01', 'host-01'],
        ['wap-01', 'host-02']
    ]
};

const TYPE_COLORS = {
    router: 0x00d4ff,
    firewall: 0xff5f7e,
    server: 0x3dffb8,
    storage: 0xb964ff,
    wap: 0xffd447,
    host: 0xff8e3c
};

const NODE_GEOMETRIES = {
    router: () => new THREE.BoxGeometry(1.6, 0.9, 1.6),
    firewall: () => new THREE.CylinderGeometry(0.7, 0.7, 1.6, 6),
    server: () => new THREE.CylinderGeometry(0.9, 0.9, 2.2, 16),
    storage: () => new THREE.CylinderGeometry(1.2, 1.2, 0.6, 32),
    wap: () => new THREE.OctahedronGeometry(0.85),
    host: () => new THREE.BoxGeometry(1.1, 0.55, 1.3)
};

const PACKET_SPEED = { min: 0.00045, max: 0.0012 };
const PACKET_COLORS = {
    normal: 0x00b7ff,
    attack: 0xff3b5f
};

const RANDOM_ATTACKERS = ['203.0.113.45', '198.51.100.77', '192.0.2.123', '45.12.90.5'];

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
    simulationEnabled: false
};

function updateClock() {
    if (!dom.datetime) return;
    const now = new Date();
    dom.datetime.textContent = now.toLocaleString(undefined, {
        weekday: 'short',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
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
    lbl.className = 'packet-label';
    lbl.textContent = label;

    const val = document.createElement('span');
    val.className = 'packet-value';
    val.textContent = value;

    row.appendChild(lbl);
    row.appendChild(val);
    return row;
}

function renderAlerts() {
    if (!dom.alertsContainer) return;
    dom.alertsContainer.innerHTML = '';

    if (!state.alerts.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = 'No alerts detected yet.';
        dom.alertsContainer.appendChild(empty);
        if (dom.alertCount) dom.alertCount.textContent = '0';
        return;
    }

    if (dom.alertCount) dom.alertCount.textContent = state.alerts.length.toString();

    state.alerts.slice(0, 15).forEach(alert => {
        const item = document.createElement('div');
        item.className = 'alert-item';
        if (state.selectedAlert?.id === alert.id) {
            item.classList.add('highlighted');
        }

        const header = document.createElement('div');
        header.className = 'alert-header';
        const type = document.createElement('span');
        type.className = 'alert-type';
        type.textContent = alert.attack_types?.[0] || alert.attack || 'Threat';
        const time = document.createElement('span');
        time.className = 'alert-time';
        time.textContent = new Date(alert.timestamp * 1000).toLocaleTimeString();
        header.appendChild(type);
        header.appendChild(time);

        const details = document.createElement('div');
        details.className = 'alert-details';
        const source = document.createElement('span');
        source.className = 'alert-source';
        source.textContent = alert.source_ip || 'Unknown';
        details.appendChild(source);
        const route = document.createElement('span');
        route.textContent = ` -> ${alert.dest_ip || alert.target_node || 'Unknown'}`;
        details.appendChild(route);

        const meta = document.createElement('div');
        meta.className = 'alert-details';
        meta.textContent = alert.description || 'Suspicious behavior detected';

        item.appendChild(header);
        item.appendChild(details);
        item.appendChild(meta);
        item.addEventListener('click', () => {
            selectAlert(alert, { openModal: true, highlightScene: true });
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

    dom.inspectorStatus.textContent = `Inspecting ${alert.attack_types?.[0] || 'Alert'}`;
    const fields = [
        ['Source', alert.source_ip || 'Unknown'],
        ['Destination', alert.dest_ip || alert.target_node || 'Unknown'],
        ['Attack', (alert.attack_types || alert.attacks || []).join(', ') || 'Unknown'],
        ['Flags', alert.flags?.join(', ') || alert.packet_flags || '[ ]'],
        ['Confidence', toPercent(alert.confidence ?? 0.8)],
        ['Action', alert.mitigation?.action || alert.action || 'Flagged']
    ];
    fields.forEach(([label, value]) => {
        dom.inspectorContent.appendChild(buildDetail(label, value));
    });

    if (alert.payload_snippet || alert.payload) {
        const payload = document.createElement('div');
        payload.className = 'packet-payload';
        payload.textContent = alert.payload_snippet || alert.payload;
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
        ['Node', node.label],
        ['Type', node.type.toUpperCase()],
        ['IP', node.ip],
        ['Status', node.status || 'Online'],
        ['Data', node.data?.join(', ') || 'None'],
        ['Last Seen', node.lastSeen || new Date().toLocaleTimeString()]
    ];
    rows.forEach(([label, value]) => dom.nodeDetails.appendChild(buildDetail(label, value, 'node-detail')));
}

function populateModal(alert) {
    if (!dom.modalBody) return;
    dom.modalBody.innerHTML = '';
    if (!alert) return;

    const sections = [
        {
            title: 'Attack Summary',
            data: [
                ['Attack Type', (alert.attack_types || alert.attacks || ['Unknown']).join(', ')],
                ['Source IP', alert.source_ip || 'Unknown'],
                ['Target Asset', alert.target_node || alert.dest_ip || 'Unknown'],
                ['Targeted Data', (alert.targeted_data || []).join(', ') || 'None'],
                ['Confidence', toPercent(alert.confidence ?? 0.8)],
                ['Action Taken', alert.mitigation?.action || 'Flagged']
            ]
        },
        {
            title: 'Packet Snapshot',
            data: [
                ['Flags', alert.flags?.join(', ') || alert.packet_flags || '[ ]'],
                ['Payload', alert.payload_snippet || alert.payload || 'Not captured']
            ]
        }
    ];

    if (alert.cve || alert.description) {
        sections.splice(1, 0, {
            title: 'Vulnerability Intel',
            data: [
                ['CVE', alert.cve || 'N/A'],
                ['Description', alert.description || 'Not provided']
            ]
        });
    }

    sections.forEach(section => {
        const block = document.createElement('div');
        block.className = 'modal-section';

        const title = document.createElement('div');
        title.className = 'modal-section-title';
        title.textContent = section.title;
        block.appendChild(title);

        section.data.forEach(([label, value]) => {
            const detail = document.createElement('div');
            detail.className = 'modal-detail';

            const lbl = document.createElement('span');
            lbl.className = 'modal-label';
            lbl.textContent = label;

            const val = document.createElement('span');
            val.className = 'modal-value';
            val.textContent = value;

            detail.appendChild(lbl);
            detail.appendChild(val);
            block.appendChild(detail);
        });

        dom.modalBody.appendChild(block);
    });

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    [
        { label: 'Block Source', className: 'modal-btn block', handler: () => console.log('[Action] Block', alert.source_ip) },
        { label: 'Isolate Target', className: 'modal-btn', handler: () => console.log('[Action] Isolate', alert.target_node || alert.dest_ip) },
        { label: 'Watch Asset', className: 'modal-btn', handler: () => console.log('[Action] Watchlist', alert.target_node || alert.dest_ip) },
        { label: 'Mark False Positive', className: 'modal-btn', handler: () => console.log('[Action] False positive', alert.id) }
    ].forEach(action => {
        const btn = document.createElement('button');
        btn.className = action.className;
        btn.textContent = action.label;
        btn.addEventListener('click', () => {
            action.handler();
            closeModal();
        });
        actions.appendChild(btn);
    });

    dom.modalBody.appendChild(actions);
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
    if (options.highlightScene && alert?.target_node) {
        highlightNode(alert.target_node);
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
    if (state.alerts.length > 30) {
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
    scene.background = new THREE.Color(0x02060f);

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
    renderer.domElement.style.cursor = 'grab';

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
            data: node.type === 'server' ? ['public-service'] : node.type === 'storage' ? ['backups'] : [],
            lastSeen: new Date().toLocaleTimeString()
        });

        const geometryFactory = NODE_GEOMETRIES[node.type] || NODE_GEOMETRIES.router;
        const geometry = geometryFactory();
        const material = new THREE.MeshStandardMaterial({
            color: TYPE_COLORS[node.type] || 0x00ffff,
            emissive: TYPE_COLORS[node.type] || 0x00ffff,
            emissiveIntensity: 0.25
        });
        const mesh = new THREE.Mesh(geometry, material);
        const baseHeight = node.position?.y || 0;
        const lift = 0.6;
        const finalHeight = baseHeight + lift;
        mesh.position.set(node.position.x, finalHeight, node.position.z);
        mesh.userData = { id: node.id, baseY: finalHeight };
        state.scene.add(mesh);
        state.sceneObjects.push(mesh);

        const labelCanvas = document.createElement('canvas');
        const ctx = labelCanvas.getContext('2d');
        labelCanvas.width = 256;
        labelCanvas.height = 64;
        ctx.fillStyle = 'rgba(3, 8, 18, 0.6)';
        ctx.fillRect(0, 0, 256, 64);
        ctx.font = '20px "Roboto Mono"';
        ctx.fillStyle = '#00f5ff';
        ctx.fillText(node.label, 16, 36);
        const texture = new THREE.CanvasTexture(labelCanvas);
        const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
        const sprite = new THREE.Sprite(spriteMaterial);
        sprite.scale.set(3, 1, 1);
        sprite.position.set(node.position.x, baseHeight + lift + 1.5, node.position.z);
        state.scene.add(sprite);
    });

    NETWORK_DEFINITION.connections.forEach(([sourceId, targetId]) => {
        const sourceNode = state.nodes.get(sourceId);
        const targetNode = state.nodes.get(targetId);
        if (!sourceNode || !targetNode) return;

        const sourceBase = sourceNode.position?.y || 0;
        const targetBase = targetNode.position?.y || 0;
        const sourceLift = 0.6;
        const targetLift = 0.6;
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
        const material = new THREE.LineBasicMaterial({ color: 0x00a8ff, transparent: true, opacity: 0.35 });
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
        const geometry = new THREE.SphereGeometry(0.15, 12, 12);
        const isAttackPacket = Math.random() < 0.25;
        const packetColor = isAttackPacket ? PACKET_COLORS.attack : PACKET_COLORS.normal;
        const material = new THREE.MeshBasicMaterial({
            color: packetColor,
            transparent: true,
            opacity: 0.9
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
    uiControls.pause?.addEventListener('click', () => {
        state.paused = !state.paused;
        uiControls.pause.classList.toggle('is-active', state.paused);
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
        uiControls.togglePackets.classList.toggle('is-active', willHide);
    });

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

function initialise() {
    bootstrapDashboard();
    wireControls();
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
}

document.addEventListener('DOMContentLoaded', initialise);
