// CAN Bus Security Dashboard - JavaScript (FIXED VERSION)

// Chart instances
let charts = {};

// Update interval
const UPDATE_INTERVAL = 1000; // 1 second

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initializing...');
    
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.error('Chart.js not loaded!');
        alert('Error: Chart.js library not loaded. Please refresh the page.');
        return;
    }
    
    console.log('Chart.js loaded successfully');
    
    // Initialize charts
    initializeCharts();
    
    // Set up event listeners
    setupEventListeners();
    
    // Start update loop
    startUpdateLoop();
    
    console.log('Dashboard initialized successfully');
});

// Initialize all charts
function initializeCharts() {
    console.log('Initializing charts...');
    
    // Set default Chart.js options
    Chart.defaults.color = '#ecf0f1';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
    
    try {
        // Message Rate Chart
        const ctx1 = document.getElementById('chart-message-rate');
        if (!ctx1) {
            console.error('chart-message-rate canvas not found');
            return;
        }
        
        charts.messageRate = new Chart(ctx1.getContext('2d'), {
            type: 'line',
            data: {
                labels: Array(60).fill(''),
                datasets: [{
                    label: 'Messages/s',
                    data: Array(60).fill(0),
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: 2,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ecf0f1' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    x: {
                        display: false
                    }
                },
                animation: false
            }
        });
        console.log('Message Rate chart created');

        // Block Rate Chart
        charts.blockRate = new Chart(
            document.getElementById('chart-block-rate').getContext('2d'),
            {
                type: 'line',
                data: {
                    labels: Array(60).fill(''),
                    datasets: [{
                        label: 'Blocks/s',
                        data: Array(60).fill(0),
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 2,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#ecf0f1' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        },
                        x: {
                            display: false
                        }
                    },
                    animation: false
                }
            }
        );
        console.log('Block Rate chart created');

        // Attack Types Chart
        charts.attackTypes = new Chart(
            document.getElementById('chart-attack-types').getContext('2d'),
            {
                type: 'doughnut',
                data: {
                    labels: ['DoS', 'Fuzzing', 'Spoofing', 'Other'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            '#e74c3c',
                            '#f39c12',
                            '#9b59b6',
                            '#95a5a6'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 1.5,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#ecf0f1', padding: 15 }
                        }
                    }
                }
            }
        );
        console.log('Attack Types chart created');

        // CAN IDs Chart
        charts.canIds = new Chart(
            document.getElementById('chart-can-ids').getContext('2d'),
            {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Message Count',
                        data: [],
                        backgroundColor: '#2ecc71'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 1.5,
                    indexAxis: 'y',
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            ticks: { color: '#ecf0f1' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        },
                        x: {
                            ticks: { color: '#ecf0f1' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        }
                    }
                }
            }
        );
        console.log('CAN IDs chart created');

        // Latency Chart
        charts.latency = new Chart(
            document.getElementById('chart-latency').getContext('2d'),
            {
                type: 'line',
                data: {
                    labels: Array(100).fill(''),
                    datasets: [{
                        label: 'Latency (ms)',
                        data: Array(100).fill(0),
                        borderColor: '#9b59b6',
                        backgroundColor: 'rgba(155, 89, 182, 0.1)',
                        tension: 0.1,
                        fill: true,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    aspectRatio: 3,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#ecf0f1' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        },
                        x: {
                            display: false
                        }
                    },
                    animation: false
                }
            }
        );
        console.log('Latency chart created');
        
        console.log('All charts initialized successfully');
        
    } catch (error) {
        console.error('Error initializing charts:', error);
    }
}

// Set up event listeners
function setupEventListeners() {
    // Start button
    document.getElementById('btn-start').addEventListener('click', async () => {
        console.log('Start button clicked');
        try {
            const response = await fetch('/api/control/start', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                showNotification('System started successfully', 'success');
            } else {
                showNotification('Failed to start: ' + data.error, 'error');
            }
        } catch (error) {
            showNotification('Error: ' + error.message, 'error');
        }
    });

    // Stop button
    document.getElementById('btn-stop').addEventListener('click', async () => {
        console.log('Stop button clicked');
        try {
            const response = await fetch('/api/control/stop', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                showNotification('System stopped', 'success');
            } else {
                showNotification('Failed to stop: ' + data.error, 'error');
            }
        } catch (error) {
            showNotification('Error: ' + error.message, 'error');
        }
    });

    // Reset button
    document.getElementById('btn-reset').addEventListener('click', async () => {
        if (confirm('Are you sure you want to reset all statistics?')) {
            try {
                const response = await fetch('/api/reset', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    showNotification('Statistics reset', 'success');
                    // Refresh page
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showNotification('Failed to reset: ' + data.error, 'error');
                }
            } catch (error) {
                showNotification('Error: ' + error.message, 'error');
            }
        }
    });

    // Attack buttons
    document.querySelectorAll('.btn-attack').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const attackType = e.target.dataset.attack;
            
            if (confirm(`Simulate ${attackType.toUpperCase()} attack for 3 seconds?`)) {
                try {
                    const response = await fetch('/api/attack/simulate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ type: attackType, duration: 3 })
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        showNotification(data.message, 'warning');
                    } else {
                        showNotification('Failed to start attack: ' + data.error, 'error');
                    }
                } catch (error) {
                    showNotification('Error: ' + error.message, 'error');
                }
            }
        });
    });
}

// Start update loop
function startUpdateLoop() {
    // Update status
    updateStatus();
    setInterval(updateStatus, UPDATE_INTERVAL);
    
    // Update stats
    updateStats();
    setInterval(updateStats, UPDATE_INTERVAL);
    
    // Update messages
    updateMessages();
    setInterval(updateMessages, UPDATE_INTERVAL);
    
    // Update blocks
    updateBlocks();
    setInterval(updateBlocks, UPDATE_INTERVAL);
}

// Update system status
async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        // Update status badge
        const statusBadge = document.getElementById('system-status');
        if (data.monitoring) {
            statusBadge.textContent = 'ACTIVE';
            statusBadge.className = 'status-badge status-active';
        } else {
            statusBadge.textContent = 'INACTIVE';
            statusBadge.className = 'status-badge status-inactive';
        }
        
        // Update uptime
        const uptime = formatUptime(data.uptime);
        document.getElementById('uptime').textContent = uptime;
        
    } catch (error) {
        console.error('Error updating status:', error);
    }
}

// Update statistics
async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        console.log('Stats received:', data); // DEBUG
        
        // Update stat cards
        document.getElementById('stat-processed').textContent = data.total_processed.toLocaleString();
        document.getElementById('stat-allowed').textContent = data.total_allowed.toLocaleString();
        document.getElementById('stat-blocked').textContent = data.total_blocked.toLocaleString();
        document.getElementById('stat-block-rate').textContent = data.block_rate.toFixed(2) + '%';
        document.getElementById('stat-latency').textContent = data.avg_latency.toFixed(3);
        document.getElementById('stat-p95').textContent = data.p95_latency.toFixed(3);
        
        // Update message rate chart
        if (data.message_rate.length > 0) {
            charts.messageRate.data.datasets[0].data = data.message_rate;
            charts.messageRate.update('none');
        }
        
        // Update block rate chart
        if (data.block_rate_history.length > 0) {
            charts.blockRate.data.datasets[0].data = data.block_rate_history;
            charts.blockRate.update('none');
        }
        
        // Update attack types chart
        const attackData = [
            data.attack_types.DoS,
            data.attack_types.Fuzzing,
            data.attack_types.Spoofing,
            data.attack_types.Other
        ];
        charts.attackTypes.data.datasets[0].data = attackData;
        charts.attackTypes.update('none');
        
        // Update CAN IDs chart
        if (data.top_can_ids && data.top_can_ids.length > 0) {
            charts.canIds.data.labels = data.top_can_ids.map(item => item.id);
            charts.canIds.data.datasets[0].data = data.top_can_ids.map(item => item.count);
            charts.canIds.update('none');
        }
        
        // Update latency chart
        if (data.recent_latencies && data.recent_latencies.length > 0) {
            charts.latency.data.datasets[0].data = data.recent_latencies;
            charts.latency.update('none');
        }
        
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

// Update recent messages table
async function updateMessages() {
    try {
        const response = await fetch('/api/messages/recent');
        const data = await response.json();
        
        const tbody = document.querySelector('#table-messages tbody');
        
        if (data.messages.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="no-data">No data yet. Start the system to begin monitoring.</td></tr>';
            return;
        }
        
        // Show last 20 messages
        const messages = data.messages.slice(-20).reverse();
        
        tbody.innerHTML = messages.map(msg => `
            <tr>
                <td>${msg.timestamp}</td>
                <td><code>${msg.can_id}</code></td>
                <td>${msg.dlc}</td>
                <td><code style="font-size: 11px;">${msg.data}</code></td>
                <td class="status-${msg.status.toLowerCase()}">${msg.status}</td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('Error updating messages:', error);
    }
}

// Update recent blocks table
async function updateBlocks() {
    try {
        const response = await fetch('/api/blocks/recent');
        const data = await response.json();
        
        const tbody = document.querySelector('#table-blocks tbody');
        
        if (data.blocks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="no-data">No blocks yet.</td></tr>';
            return;
        }
        
        // Show last 20 blocks
        const blocks = data.blocks.slice(-20).reverse();
        
        tbody.innerHTML = blocks.map(block => `
            <tr>
                <td>${block.timestamp}</td>
                <td><code>${block.can_id}</code></td>
                <td style="font-size: 12px;">${block.reason}</td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('Error updating blocks:', error);
    }
}

// Helper: Format uptime
function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

// Helper: Show notification
function showNotification(message, type) {
    console.log(`[${type.toUpperCase()}] ${message}`);
    alert(message);  // Simple alert for now
}
