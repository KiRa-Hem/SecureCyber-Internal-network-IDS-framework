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
let ws = null;

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

// Initialize the scene
function init() {
    // Check if user is authenticated
    if (!Auth.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }
    
    // Get username from token (in a real app, you would decode the JWT)
    const username = localStorage.getItem('username') || 'User';
    document.getElementById('username').textContent = username;
    
    // Set up logout button
    document.getElementById('logout-btn').addEventListener('click', () => {
        Auth.logout();
    });
    
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
    
    // Connect to WebSocket
    connectWebSocket();
    
    // Update datetime
    updateDateTime();
    setInterval(updateDateTime, 1000);
    
    // Initialize threat timeline
    initThreatTimeline();
}

// Connect to WebSocket with authentication
function connectWebSocket() {
    ws = Auth.createWebSocketWithAuth();
    
    if (!ws) {
        return;
    }
    
    ws.onopen = () => {
        console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        
        if (message.type === 'attack_detected') {
            handleAttackDetected(message.data);
        } else if (message.type === 'stats_update') {
            handleStatsUpdate(message.data);
        }
    };
    
    ws.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        
        // If not due to authentication error, try to reconnect
        if (event.code !== 1008) {
            setTimeout(() => {
                connectWebSocket();
            }, 3000);
        }
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

// Handle attack detected message
function handleAttackDetected(data) {
    // Add to alerts
    alerts.unshift(data);
    if (alerts.length > 10) alerts.pop();
    
    // Update UI
    updateAlerts();
    
    // Show attack in 3D view
    showAttackIn3DView(data.dest_ip);
    
    // Update stats
    if (data.mitigation.action === 'Blocked') {
        stats.threatsBlocked += 1;
    }
    updateStats();
    
    // Show modal for high confidence alerts
    if (data.confidence >= 90) {
        setTimeout(() => {
            showAlertModal(data);
        }, 500);
    }
}

// Handle stats update message
function handleStatsUpdate(data) {
    stats.totalPackets = data.packets_analyzed;
    stats.threats_detected = data.threats_detected;
    stats.activeHosts = data.active_hosts;
    updateStats();
}

// Fetch alerts from API
async function fetchAlerts() {
    try {
        const response = await Auth.fetchWithAuth('http://localhost:8765/api/alerts');
        const data = await response.json();
        
        if (response.ok) {
            alerts = data.alerts;
            updateAlerts();
        }
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

// Fetch blocklist from API
async function fetchBlocklist() {
    try {
        const response = await Auth.fetchWithAuth('http://localhost:8765/api/blocklist');
        const data = await response.json();
        
        if (response.ok) {
            console.log('Blocklist:', data.blocklist);
        }
    } catch (error) {
        console.error('Error fetching blocklist:', error);
    }
}

// Block IP via API
async function blockIP(ip, reason) {
    try {
        const response = await Auth.fetchWithAuth('http://localhost:8765/api/block-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip, reason })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('IP blocked:', data.message);
            return true;
        } else {
            console.error('Error blocking IP:', data.detail);
            return false;
        }
    } catch (error) {
        console.error('Error blocking IP:', error);
        return false;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', init);