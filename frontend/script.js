/* eslint-disable no-console */
const dom = {
    clock: document.getElementById('clock'),
    lastSync: document.getElementById('last-sync'),
    sensorCount: document.getElementById('sensor-count'),
    statPackets: document.getElementById('stat-packets'),
    statBlocked: document.getElementById('stat-blocked'),
    statHosts: document.getElementById('stat-hosts'),
    statAttackRate: document.getElementById('stat-attack-rate'),
    timelineCanvas: document.getElementById('threat-timeline'),
    alertFeed: document.getElementById('alert-feed'),
    alertCount: document.getElementById('alert-count'),
    alertsEmpty: document.getElementById('alerts-empty'),
    inspectorState: document.getElementById('inspector-state'),
    inspector: {
        source: document.getElementById('inspect-source'),
        target: document.getElementById('inspect-target'),
        attack: document.getElementById('inspect-attack'),
        flags: document.getElementById('inspect-flags'),
        confidence: document.getElementById('inspect-confidence'),
        action: document.getElementById('inspect-action'),
        payload: document.getElementById('inspect-payload')
    },
    node: {
        name: document.getElementById('node-name'),
        type: document.getElementById('node-type'),
        ip: document.getElementById('node-ip'),
        status: document.getElementById('node-status'),
        data: document.getElementById('node-data'),
        lastSeen: document.getElementById('node-last-seen')
    },
    modal: document.getElementById('alert-modal'),
    modalSummary: document.getElementById('modal-summary'),
    modalVulnSection: document.getElementById('modal-vuln-section'),
    modalVuln: document.getElementById('modal-vuln'),
    modalPacket: document.getElementById('modal-packet'),
    networkStage: document.getElementById('network-stage')
};

const buttons = {
    pause: document.getElementById('btn-pause'),
    step: document.getElementById('btn-step'),
    toggleTrails: document.getElementById('btn-toggle-trails'),
    closeNode: document.getElementById('btn-close-node'),
    closeModal: document.getElementById('btn-close-modal'),
    blockSource: document.getElementById('btn-block-source'),
    isolateTarget: document.getElementById('btn-isolate-target'),
    addWatch: document.getElementById('btn-add-watch'),
    falsePositive: document.getElementById('btn-false-positive'),
    speedSlider: document.getElementById('speed-slider')
};

const state = {
    alerts: [],
    selectedAlert: null,
    nodes: new Map(),
    meshes: new Map(),
    timeline: [],
    stats: {
        packets: 0,
        blocked: 0,
        hosts: 0,
        attackRate: 0
    },
    sensors: 0,
    webSocket: null,
    syntheticFeed: null,
    timelineCtx: null,
    scene: null,
    camera: null,
    renderer: null,
    linesGroup: null,
    sceneObjects: [],
    speedMultiplier: 1,
    paused: false
};

const NETWORK_DEFINITION = {
    nodes: [
        { id: 'router-1', label: 'Edge Router', type: 'router', ip: '198.51.100.1', position: { x: 0, y: 0, z: 0 } },
        { id: 'fw-1', label: 'Perimeter FW', type: 'firewall', ip: '198.51.100.2', position: { x: -2, y: 0, z: 2 } },
        { id: 'fw-2', label: 'Perimeter FW', type: 'firewall', ip: '198.51.100.3', position: { x: 2, y: 0, z: 2 } },
        { id: 'switch-1', label: 'Core Switch', type: 'server', ip: '10.0.0.1', position: { x: 0, y: 0, z: 4 } },
        { id: 'web-01', label: 'Web Server', type: 'server', ip: '10.0.1.10', position: { x: -3, y: 0, z: 6 } },
        { id: 'web-02', label: 'Web Server', type: 'server', ip: '10.0.1.11', position: { x: 3, y: 0, z: 6 } },
        { id: 'app-01', label: 'App Server', type: 'server', ip: '10.0.2.20', position: { x: -1.5, y: 0, z: 8 } },
        { id: 'app-02', label: 'App Server', type: 'server', ip: '10.0.2.21', position: { x: 1.5, y: 0, z: 8 } },
        { id: 'db-01', label: 'DB Server', type: 'storage', ip: '10.0.3.30', position: { x: 0, y: 0, z: 10 } },
        { id: 'storage-01', label: 'Storage SAN', type: 'storage', ip: '10.0.4.40', position: { x: 0, y: 2, z: 8 } },
        { id: 'wap-01', label: 'WAP Floor 2', type: 'wap', ip: '10.0.5.50', position: { x: -4, y: 0, z: 4 } },
        { id: 'host-01', label: 'Workstation', type: 'host', ip: '10.0.6.60', position: { x: -5, y: 0, z: 6 } },
        { id: 'host-02', label: 'Workstation', type: 'host', ip: '10.0.6.61', position: { x: -5, y: 0, z: 8 } }
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

const formatNumber = value => Number(value || 0).toLocaleString('en-US');
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

function updateClock() {
    const now = new Date();
    dom.clock.textContent = now.toUTCString();
}

function setLastSync(ts) {
    dom.lastSync.textContent = ts;
}

function updateSensorCount(count) {
    state.sensors = count;
    dom.sensorCount.textContent = count;
}

function drawTimeline() {
    if (!state.timelineCtx) return;
    const ctx = state.timelineCtx;
    const { width, height } = ctx.canvas;
    ctx.clearRect(0, 0, width, height);

    const data = state.timeline;
    if (!data.length) return;

    const maxVal = Math.max(...data, 1);
    const barWidth = width / data.length;

    ctx.fillStyle = 'rgba(255, 59, 130, 0.18)';
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = '#ff3b82';
    data.forEach((value, index) => {
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

function applyStats(newStats) {
    const packets = Number(newStats.packets ?? state.stats.packets ?? 0);
    const blocked = Number(newStats.blocked ?? state.stats.blocked ?? 0);
    const hosts = Number(newStats.hosts ?? state.stats.hosts ?? 0);
    const attackRateRaw = newStats.attackRate ?? state.stats.attackRate ?? 0;
    const attackRate = Number.isFinite(Number(attackRateRaw)) ? Number(attackRateRaw) : 0;

    state.stats = { packets, blocked, hosts, attackRate };

    dom.statPackets.textContent = formatNumber(packets);
    dom.statBlocked.textContent = formatNumber(blocked);
    dom.statHosts.textContent = formatNumber(hosts);
    dom.statAttackRate.textContent = `${attackRate.toFixed(1)}/min`;
    pushTimeline(attackRate);
}

function renderAlerts() {
    dom.alertFeed.innerHTML = '';
    if (!state.alerts.length) {
        dom.alertsEmpty.style.display = 'block';
        dom.alertCount.textContent = '0';
        return;
    }
    dom.alertsEmpty.style.display = 'none';
    dom.alertCount.textContent = state.alerts.length.toString();

    state.alerts.slice(0, 10).forEach(alert => {
        const item = document.createElement('li');
        item.className = 'alert-item';
        item.dataset.id = alert.id;

        const type = document.createElement('div');
        type.className = 'alert-item__type';
        type.textContent = alert.attack_types?.[0] || alert.attack || 'Unknown Threat';

        const meta = document.createElement('div');
        meta.className = 'alert-item__meta';
        meta.innerHTML = `<span>${alert.source_ip || 'Unknown source'}</span><span>${new Date(alert.timestamp * 1000).toLocaleTimeString()}</span>`;

        const detail = document.createElement('div');
        detail.className = 'alert-item__detail';
        detail.textContent = `Target: ${alert.dest_ip || alert.target_node || 'Unknown target'}`;

        item.appendChild(type);
        item.appendChild(meta);
        item.appendChild(detail);

        item.addEventListener('click', () => selectAlert(alert, { highlightInScene: true, openModal: true }));
        dom.alertFeed.appendChild(item);
    });
}

function updateInspector(alert) {
    if (!alert) {
        dom.inspectorState.textContent = 'Select an alert to inspect';
        Object.values(dom.inspector).forEach(el => { el.textContent = '-'; });
        return;
    }
    dom.inspectorState.textContent = `Inspecting ${alert.attack_types?.[0] || alert.attack || 'Alert'}`;
    dom.inspector.source.textContent = alert.source_ip || 'Unknown';
    dom.inspector.target.textContent = alert.dest_ip || 'Unknown';
    dom.inspector.attack.textContent = (alert.attack_types || alert.attacks || []).join(', ') || 'Unknown';
    dom.inspector.flags.textContent = alert.flags?.join(', ') || alert.packet_flags || '[ ]';
    dom.inspector.confidence.textContent = `${Math.round((alert.confidence ?? 0) * 100) / 100}%`;
    dom.inspector.action.textContent = alert.mitigation?.action || alert.action || 'Observed';
    dom.inspector.payload.textContent = alert.payload_snippet || alert.payload || 'No payload captured';
}

function updateNodeInspector(node) {
    if (!node) {
        dom.node.name.textContent = '-';
        dom.node.type.textContent = '-';
        dom.node.ip.textContent = '-';
        dom.node.status.textContent = '-';
        dom.node.data.textContent = '-';
        dom.node.lastSeen.textContent = '-';
        return;
    }
    dom.node.name.textContent = node.label;
    dom.node.type.textContent = node.type.toUpperCase();
    dom.node.ip.textContent = node.ip;
    dom.node.status.textContent = node.status || 'Online';
    dom.node.data.textContent = node.data?.join(', ') || node.data || 'None';
    dom.node.lastSeen.textContent = node.lastSeen || new Date().toLocaleTimeString();
}

function buildModalField(def) {
    const dt = document.createElement('dt');
    dt.textContent = def.label;
    const dd = document.createElement('dd');
    dd.textContent = def.value;
    return { dt, dd };
}

function populateModal(alert) {
    dom.modalSummary.innerHTML = '';
    const summaryFields = [
        { label: 'Attack Type', value: (alert.attack_types || alert.attacks || ['Unknown']).join(', ') },
        { label: 'Source IP', value: alert.source_ip || 'Unknown' },
        { label: 'Target Asset', value: alert.target_node || `${alert.dest_ip || 'Unknown'} (${alert.target_asset || 'Asset'})` },
        { label: 'Targeted Data', value: (alert.targeted_data || []).join(', ') || 'None' },
        { label: 'Confidence', value: `${Math.round((alert.confidence ?? 0) * 100) / 100}%` },
        { label: 'Action Taken', value: alert.mitigation?.action || 'Flagged' }
    ];
    summaryFields.forEach(field => {
        const { dt, dd } = buildModalField(field);
        dom.modalSummary.appendChild(dt);
        dom.modalSummary.appendChild(dd);
    });

    dom.modalVuln.innerHTML = '';
    if (alert.cve || alert.description) {
        dom.modalVulnSection.style.display = 'block';
        const vulnFields = [
            { label: 'CVE ID', value: alert.cve || 'N/A' },
            { label: 'Description', value: alert.description || 'Not provided' }
        ];
        vulnFields.forEach(field => {
            const { dt, dd } = buildModalField(field);
            dom.modalVuln.appendChild(dt);
            dom.modalVuln.appendChild(dd);
        });
    } else {
        dom.modalVulnSection.style.display = 'none';
    }

    dom.modalPacket.innerHTML = '';
    const packetFields = [
        { label: 'Flags', value: alert.flags?.join(', ') || alert.packet_flags || '[ ]' },
        { label: 'Payload Snippet', value: alert.payload_snippet || alert.payload || 'Not captured' }
    ];
    packetFields.forEach(field => {
        const { dt, dd } = buildModalField(field);
        dom.modalPacket.appendChild(dt);
        dom.modalPacket.appendChild(dd);
    });
}

function openModal(alert) {
    populateModal(alert);
    dom.modal.classList.add('is-active');
    dom.modal.setAttribute('aria-hidden', 'false');
}

function closeModal() {
    dom.modal.classList.remove('is-active');
    dom.modal.setAttribute('aria-hidden', 'true');
}

function selectAlert(alert, options = {}) {
    state.selectedAlert = alert;
    updateInspector(alert);
    if (options.highlightInScene && alert.target_node) {
        highlightNode(alert.target_node);
    }
    if (options.openModal) {
        openModal(alert);
    }
}

function clearNodeSelection() {
    state.sceneObjects.forEach(obj => { obj.material.emissiveIntensity = 0.2; });
    updateNodeInspector(null);
}

function highlightNode(nodeId) {
    state.sceneObjects.forEach(obj => {
        const intensity = obj.userData.id === nodeId ? 1.0 : 0.2;
        obj.material.emissiveIntensity = intensity;
    });
    const node = state.nodes.get(nodeId);
    if (node) {
        updateNodeInspector(node);
    }
}

function addAlert(alert) {
    state.alerts.unshift(alert);
    if (state.alerts.length > 25) {
        state.alerts.pop();
    }
    renderAlerts();
    updateInspector(alert);
}

function attemptFetch(url, options = {}) {
    return fetch(url, options).then(resp => {
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
    });
}

function baseApiUrl() {
    if (location.origin && location.origin !== 'null') {
        return location.origin;
    }
    return 'http://localhost:8000';
}

function baseWsUrl() {
    if (location.hostname) {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${protocol}//${location.host}/ws`;
    }
    return 'ws://localhost:8000/ws';
}

function connectWebSocket() {
    const wsUrl = baseWsUrl();
    try {
        const socket = new WebSocket(wsUrl);
        state.webSocket = socket;

        socket.onopen = () => {
            console.log('[WS] connected', wsUrl);
            if (state.syntheticFeed) {
                clearInterval(state.syntheticFeed);
                state.syntheticFeed = null;
            }
        };

        socket.onmessage = event => {
            let payload;
            try {
                payload = JSON.parse(event.data);
            } catch (error) {
                console.warn('Invalid websocket payload', error);
                return;
            }
            if (payload.type === 'attack_detected') {
                addAlert(parseAlert(payload.data));
                setLastSync(new Date().toLocaleTimeString());
            }
            if (payload.type === 'stats_update') {
                applyStats({
                    packets: payload.data.packets_analyzed,
                    blocked: payload.data.threats_detected,
                    hosts: payload.data.active_hosts,
                    attackRate: payload.data.attack_rate ?? payload.data.threats_detected
                });
                updateSensorCount(Object.keys(payload.data.sensor_status || {}).length);
                setLastSync(new Date().toLocaleTimeString());
            }
        };

        socket.onclose = event => {
            console.warn('[WS] closed', event.code, event.reason);
            startSyntheticFeed();
            setTimeout(connectWebSocket, 6000);
        };

        socket.onerror = error => {
            console.warn('[WS] error', error);
            socket.close();
        };
    } catch (error) {
        console.warn('[WS] failed to connect', error);
        startSyntheticFeed();
    }
}

function parseAlert(data) {
    const timestamp = data.timestamp ?? Math.floor(Date.now() / 1000);
    return {
        id: data.id || `sim-${timestamp}-${Math.random().toString(16).slice(2, 6)}`,
        timestamp,
        source_ip: data.source_ip,
        dest_ip: data.dest_ip,
        attack_types: data.attack_types || data.attacks || [data.type || 'Anomaly'],
        target_node: data.target_node || data.dest_ip,
        targeted_data: data.targeted_data || [],
        confidence: data.confidence ?? 0.8,
        mitigation: data.mitigation || { action: 'Flagged' },
        cve: data.cve,
        description: data.description,
        flags: data.flags,
        payload_snippet: data.payload_snippet || data.payload
    };
}

function startSyntheticFeed() {
    if (state.syntheticFeed) return;
    console.log('[Demo] starting synthetic feed');
    const ATTACK_TYPES = [
        { name: 'SQL Injection', cve: 'CVE-2021-44228', description: 'Injected SQL payload detected' },
        { name: 'Command Injection', cve: 'CVE-2021-43297', description: 'OS command attempt via input field' },
        { name: 'DDoS', cve: null, description: 'High request volume detected' },
        { name: 'XSS', cve: 'CVE-2020-26870', description: 'Reflected script injection attempt' },
        { name: 'RCE Attempt', cve: null, description: 'Remote execution payload detected' }
    ];

    state.syntheticFeed = setInterval(() => {
        const attack = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
        const attacker = ['203.0.113.45', '198.51.100.77', '192.0.2.123'][Math.floor(Math.random() * 3)];
        const targets = ['web-01', 'web-02', 'app-01', 'db-01', 'host-01', 'host-02'];
        const targetNode = targets[Math.floor(Math.random() * targets.length)];
        const nodeInfo = state.nodes.get(targetNode);

        const alert = parseAlert({
            attack_types: [attack.name],
            source_ip: attacker,
            dest_ip: nodeInfo?.ip,
            target_node: targetNode,
            targeted_data: nodeInfo?.data || ['public-website'],
            confidence: clamp(Math.random() * 20 + 80, 70, 99),
            mitigation: { action: Math.random() > 0.6 ? 'Blocked' : 'Flagged' },
            cve: attack.cve,
            description: attack.description,
            payload_snippet: attack.name === 'SQL Injection' ? "' OR '1'='1" : 'Suspicious payload'
        });

        addAlert(alert);
        selectAlert(alert, { highlightInScene: true });
        applyStats({
            packets: state.stats.packets + Math.floor(Math.random() * 200 + 50),
            blocked: state.stats.blocked + (alert.mitigation?.action === 'Blocked' ? 1 : 0),
            hosts: 6,
            attackRate: clamp(Math.random() * 15, 0.5, 20)
        });
        updateSensorCount(2);
        setLastSync(new Date().toLocaleTimeString());
    }, 6000);
}

function buildScene() {
    const width = dom.networkStage.clientWidth || dom.networkStage.offsetWidth || 800;
    const height = dom.networkStage.clientHeight || dom.networkStage.offsetHeight || 600;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x02060f);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(12, 14, 18);
    camera.lookAt(0, 0, 6);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(width, height);
    dom.networkStage.innerHTML = '';
    dom.networkStage.appendChild(renderer.domElement);

    const ambient = new THREE.AmbientLight(0x446688, 0.6);
    scene.add(ambient);

    const directional = new THREE.DirectionalLight(0x55ffff, 0.8);
    directional.position.set(10, 20, 10);
    scene.add(directional);

    const floorGeometry = new THREE.PlaneGeometry(40, 40, 10, 10);
    const floorMaterial = new THREE.MeshBasicMaterial({
        color: 0x061224,
        wireframe: true,
        transparent: true,
        opacity: 0.25
    });
    const floor = new THREE.Mesh(floorGeometry, floorMaterial);
    floor.rotation.x = -Math.PI / 2;
    scene.add(floor);

    state.scene = scene;
    state.camera = camera;
    state.renderer = renderer;

    const linesGroup = new THREE.Group();
    state.linesGroup = linesGroup;
    scene.add(linesGroup);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();

    renderer.domElement.addEventListener('pointerdown', event => {
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
        const newWidth = dom.networkStage.clientWidth || 800;
        const newHeight = dom.networkStage.clientHeight || 600;
        renderer.setSize(newWidth, newHeight);
        camera.aspect = newWidth / newHeight;
        camera.updateProjectionMatrix();
    });
}

function populateScene() {
    if (!state.scene) return;

    NETWORK_DEFINITION.nodes.forEach(node => {
        state.nodes.set(node.id, {
            ...node,
            status: 'Online',
            data: node.type === 'server' ? ['public-website'] : node.type === 'storage' ? ['backups'] : [],
            lastSeen: new Date().toLocaleTimeString()
        });

        const geometry = new THREE.BoxGeometry(1.1, 1.1, 1.1);
        const material = new THREE.MeshStandardMaterial({
            color: TYPE_COLORS[node.type] || 0x00ffff,
            emissive: TYPE_COLORS[node.type] || 0x00ffff,
            emissiveIntensity: 0.2
        });
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.set(node.position.x, node.position.y + 0.6, node.position.z);
        mesh.userData = { id: node.id };
        state.scene.add(mesh);
        state.sceneObjects.push(mesh);

        const labelCanvas = document.createElement('canvas');
        const labelCtx = labelCanvas.getContext('2d');
        labelCanvas.width = 256;
        labelCanvas.height = 64;
        labelCtx.fillStyle = 'rgba(3, 8, 18, 0.6)';
        labelCtx.fillRect(0, 0, 256, 64);
        labelCtx.font = '20px "Roboto Mono"';
        labelCtx.fillStyle = '#00f5ff';
        labelCtx.fillText(node.label, 16, 36);
        const texture = new THREE.CanvasTexture(labelCanvas);
        const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
        const sprite = new THREE.Sprite(spriteMaterial);
        sprite.scale.set(3, 1, 1);
        sprite.position.set(node.position.x, node.position.y + 2.1, node.position.z);
        state.scene.add(sprite);
    });

    NETWORK_DEFINITION.connections.forEach(([sourceId, targetId]) => {
        const sourceNode = state.nodes.get(sourceId);
        const targetNode = state.nodes.get(targetId);
        if (!sourceNode || !targetNode) return;

        const points = [];
        points.push(new THREE.Vector3(sourceNode.position.x, sourceNode.position.y + 0.6, sourceNode.position.z));
        points.push(new THREE.Vector3(targetNode.position.x, targetNode.position.y + 0.6, targetNode.position.z));
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const material = new THREE.LineBasicMaterial({ color: 0x00a8ff, transparent: true, opacity: 0.35 });
        const line = new THREE.Line(geometry, material);
        state.linesGroup.add(line);
    });
}

function animateScene() {
    if (!state.renderer || !state.scene || !state.camera) return;
    const tick = () => {
        if (!state.paused) {
            state.sceneObjects.forEach((mesh, index) => {
                mesh.rotation.y += 0.002 * state.speedMultiplier;
                mesh.position.y = 0.6 + Math.sin((Date.now() * 0.002 + index) * state.speedMultiplier) * 0.08;
            });
            state.linesGroup.rotation.y += 0.0005 * state.speedMultiplier;
        }
        state.renderer.render(state.scene, state.camera);
        requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
}

function wireControls() {
    buttons.pause.addEventListener('click', () => {
        state.paused = !state.paused;
        buttons.pause.classList.toggle('is-active', state.paused);
        buttons.pause.querySelector('span').textContent = state.paused ? '>' : 'II';
    });

    buttons.step.addEventListener('click', () => {
        if (!state.paused) return;
        state.sceneObjects.forEach(mesh => { mesh.rotation.y += 0.05; });
    });

    buttons.toggleTrails.addEventListener('click', () => {
        if (!state.linesGroup) return;
        state.linesGroup.visible = !state.linesGroup.visible;
    });

    buttons.closeNode.addEventListener('click', () => {
        clearNodeSelection();
    });

    buttons.closeModal.addEventListener('click', () => closeModal());
    dom.modal.addEventListener('click', event => {
        if (event.target === dom.modal) {
            closeModal();
        }
    });

    buttons.speedSlider.addEventListener('input', event => {
        const value = Number(event.target.value) || 1;
        state.speedMultiplier = value;
    });

    buttons.blockSource.addEventListener('click', () => {
        if (!state.selectedAlert) return;
        console.log('[Action] Block source', state.selectedAlert.source_ip);
        closeModal();
    });
    buttons.isolateTarget.addEventListener('click', () => {
        if (!state.selectedAlert) return;
        console.log('[Action] Isolate target', state.selectedAlert.target_node || state.selectedAlert.dest_ip);
        closeModal();
    });
    buttons.addWatch.addEventListener('click', () => {
        if (!state.selectedAlert) return;
        console.log('[Action] Watchlist', state.selectedAlert.id);
        closeModal();
    });
    buttons.falsePositive.addEventListener('click', () => {
        if (!state.selectedAlert) return;
        console.log('[Action] Mark false positive', state.selectedAlert.id);
        closeModal();
    });
}

function bootstrapDashboard() {
    state.timelineCtx = dom.timelineCanvas.getContext('2d');
    updateClock();
    setInterval(updateClock, 1000);
    applyStats({ packets: 0, blocked: 0, hosts: 0, attackRate: 0 });
    updateNodeInspector(null);
}

function initialise() {
    bootstrapDashboard();
    wireControls();
    buildScene();
    populateScene();
    animateScene();
    connectWebSocket();
    attemptFetch(`${baseApiUrl()}/api/stats`).then(data => {
        applyStats({
            packets: data.packets_analyzed ?? 0,
            blocked: data.threats_detected ?? 0,
            hosts: data.active_hosts ?? 0,
            attackRate: data.attack_rate ?? (data.threats_detected ?? 0)
        });
        updateSensorCount(Object.keys(data.sensor_status || {}).length);
    }).catch(() => {
        startSyntheticFeed();
    });
}

document.addEventListener('DOMContentLoaded', initialise);
