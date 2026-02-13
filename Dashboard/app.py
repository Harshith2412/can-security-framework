"""
Flask Web Dashboard for CAN Bus Security Framework
Real-time monitoring and visualization - MAC COMPATIBLE VERSION
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import can
import threading
import time
import numpy as np
from collections import deque
from datetime import datetime
import queue  # For message passing

from ecu_simulator import VehicleSimulator, ECU, ECUConfig
from attack_simulator import AttackSimulator, AttackType
from security_framework import CANSecurityFramework, SecurityConfig
from dataset_loader import HCRLDataset

app = Flask(__name__)
CORS(app)

# Global state
bus = None
vehicle_sim = None
security_framework = None
monitor_thread = None
monitoring = False

# Message queue for passing messages from ECUs to monitor
message_queue = queue.Queue(maxsize=10000)

# Statistics storage
stats = {
    'total_processed': 0,
    'total_blocked': 0,
    'total_allowed': 0,
    'recent_messages': deque(maxlen=100),
    'recent_blocks': deque(maxlen=50),
    'latencies': deque(maxlen=1000),
    'message_rate': deque(maxlen=60),
    'block_rate': deque(maxlen=60),
    'attack_types': {'DoS': 0, 'Fuzzing': 0, 'Spoofing': 0, 'Other': 0},
    'can_id_distribution': {},
    'start_time': None
}

# Configuration
app.config['SECRET_KEY'] = 'can-security-dashboard-2025'


class InterceptedBus:
    """Wrapper around CAN bus that intercepts messages"""
    
    def __init__(self, real_bus):
        self.real_bus = real_bus
    
    def send(self, msg):
        """Send message and also add to queue for monitoring"""
        try:
            # Add to monitoring queue
            if monitoring:
                try:
                    message_queue.put_nowait(msg)
                except queue.Full:
                    pass  # Drop message if queue is full
            
            # Send to real bus
            self.real_bus.send(msg)
        except Exception as e:
            pass
    
    def recv(self, timeout=None):
        """Receive from real bus"""
        return self.real_bus.recv(timeout)


def initialize_system():
    """Initialize CAN bus and security framework"""
    global bus, vehicle_sim, security_framework, stats
    
    try:
        # Create virtual CAN bus
        real_bus = can.interface.Bus('test', bustype='virtual')
        
        # Wrap it with our interceptor
        bus = InterceptedBus(real_bus)
        
        # Initialize vehicle simulator
        vehicle_sim = VehicleSimulator(bus)
        
        # Initialize security framework
        config = SecurityConfig(
            rate_limit_window=1.0,
            max_messages_per_window=500,
            ml_enabled=False,  # Disabled for performance
            log_blocked=False,  # Disabled for performance
            log_allowed=False
        )
        security_framework = CANSecurityFramework(config)
        
        stats['start_time'] = time.time()
        
        print("✓ System initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def monitor_can_bus():
    """Monitor CAN bus in background thread"""
    global monitoring, stats
    
    last_rate_update = time.time()
    messages_in_window = 0
    blocks_in_window = 0
    
    print("Starting CAN bus monitoring...")
    
    while monitoring:
        try:
            # Get message from queue (with timeout)
            try:
                msg = message_queue.get(timeout=0.1)
            except queue.Empty:
                # Check if we need to update rate stats
                current_time = time.time()
                if current_time - last_rate_update >= 1.0:
                    stats['message_rate'].append(messages_in_window)
                    stats['block_rate'].append(blocks_in_window)
                    messages_in_window = 0
                    blocks_in_window = 0
                    last_rate_update = current_time
                continue
            
            # Measure processing latency
            start_time = time.perf_counter()
            
            # Process through security framework
            allowed, reason = security_framework.process_message(msg)
            
            latency = (time.perf_counter() - start_time) * 1000  # Convert to ms
            
            # Update statistics
            stats['total_processed'] += 1
            messages_in_window += 1
            
            if allowed:
                stats['total_allowed'] += 1
            else:
                stats['total_blocked'] += 1
                blocks_in_window += 1
                
                # Store block event
                stats['recent_blocks'].append({
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'can_id': f"0x{msg.arbitration_id:03X}",
                    'reason': reason
                })
                
                # Categorize attack type
                if 'rate limit' in reason.lower() or 'dos' in reason.lower():
                    stats['attack_types']['DoS'] += 1
                elif 'pattern' in reason.lower() or 'fuzzing' in reason.lower():
                    stats['attack_types']['Fuzzing'] += 1
                elif 'domain' in reason.lower() or 'spoofing' in reason.lower():
                    stats['attack_types']['Spoofing'] += 1
                else:
                    stats['attack_types']['Other'] += 1
            
            # Store recent message
            stats['recent_messages'].append({
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'can_id': f"0x{msg.arbitration_id:03X}",
                'dlc': msg.dlc,
                'data': ' '.join(f'{b:02X}' for b in msg.data),
                'status': 'ALLOWED' if allowed else 'BLOCKED'
            })
            
            # Store latency
            stats['latencies'].append(latency)
            
            # Update CAN ID distribution
            can_id_str = f"0x{msg.arbitration_id:03X}"
            stats['can_id_distribution'][can_id_str] = \
                stats['can_id_distribution'].get(can_id_str, 0) + 1
            
            # Update rate statistics every second
            current_time = time.time()
            if current_time - last_rate_update >= 1.0:
                stats['message_rate'].append(messages_in_window)
                stats['block_rate'].append(blocks_in_window)
                
                messages_in_window = 0
                blocks_in_window = 0
                last_rate_update = current_time
        
        except Exception as e:
            print(f"Error in monitoring thread: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(0.1)
    
    print("Monitoring stopped")


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Get system status"""
    return jsonify({
        'monitoring': monitoring,
        'vehicle_running': vehicle_sim is not None and len([ecu for ecu in vehicle_sim.ecus if ecu.running]) > 0,
        'framework_active': security_framework is not None,
        'uptime': time.time() - stats['start_time'] if stats['start_time'] else 0
    })


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    
    # Calculate additional metrics
    block_rate = (stats['total_blocked'] / max(stats['total_processed'], 1)) * 100
    avg_latency = np.mean(stats['latencies']) if stats['latencies'] else 0
    p95_latency = np.percentile(stats['latencies'], 95) if len(stats['latencies']) > 0 else 0
    
    # Get top 10 CAN IDs
    top_can_ids = sorted(
        stats['can_id_distribution'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    return jsonify({
        'total_processed': stats['total_processed'],
        'total_allowed': stats['total_allowed'],
        'total_blocked': stats['total_blocked'],
        'block_rate': round(block_rate, 2),
        'avg_latency': round(avg_latency, 3),
        'p95_latency': round(p95_latency, 3),
        'message_rate': list(stats['message_rate']),
        'block_rate_history': list(stats['block_rate']),
        'attack_types': stats['attack_types'],
        'top_can_ids': [{'id': id, 'count': count} for id, count in top_can_ids],
        'recent_latencies': list(stats['latencies'])[-100:]
    })


@app.route('/api/messages/recent')
def get_recent_messages():
    """Get recent CAN messages"""
    return jsonify({
        'messages': list(stats['recent_messages'])
    })


@app.route('/api/blocks/recent')
def get_recent_blocks():
    """Get recent blocked messages"""
    return jsonify({
        'blocks': list(stats['recent_blocks'])
    })


@app.route('/api/control/start', methods=['POST'])
def start_system():
    """Start vehicle simulation and monitoring"""
    global monitoring, monitor_thread
    
    if not vehicle_sim:
        return jsonify({'success': False, 'error': 'System not initialized'}), 400
    
    try:
        # Start vehicle simulation
        vehicle_sim.start_all()
        
        # Start monitoring
        monitoring = True
        monitor_thread = threading.Thread(target=monitor_can_bus, daemon=True)
        monitor_thread.start()
        
        return jsonify({'success': True, 'message': 'System started'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/control/stop', methods=['POST'])
def stop_system():
    """Stop vehicle simulation and monitoring"""
    global monitoring
    
    try:
        # Stop monitoring
        monitoring = False
        if monitor_thread:
            monitor_thread.join(timeout=2.0)
        
        # Stop vehicle simulation
        if vehicle_sim:
            vehicle_sim.stop_all()
        
        return jsonify({'success': True, 'message': 'System stopped'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/attack/simulate', methods=['POST'])
def simulate_attack():
    """Simulate a specific attack"""
    
    if not bus:
        return jsonify({'success': False, 'error': 'System not initialized'}), 400
    
    data = request.json
    attack_type = data.get('type', 'dos')
    duration = float(data.get('duration', 3.0))
    
    try:
        attacker = AttackSimulator(bus)
        
        # Run attack in background thread
        def run_attack():
            if attack_type == 'dos':
                attacker.dos_attack(target_id=0x200, duration=duration, rate=1000)
            elif attack_type == 'fuzzing':
                attacker.fuzzing_attack(target_id=0x760, duration=duration, rate=100)
            elif attack_type == 'spoofing':
                attacker.spoofing_attack(spoof_id=0x760, duration=duration, rate=50)
        
        attack_thread = threading.Thread(target=run_attack, daemon=True)
        attack_thread.start()
        
        return jsonify({
            'success': True,
            'message': f'{attack_type.upper()} attack started for {duration}s'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reset', methods=['POST'])
def reset_stats():
    """Reset statistics"""
    global stats
    
    stats['total_processed'] = 0
    stats['total_blocked'] = 0
    stats['total_allowed'] = 0
    stats['recent_messages'].clear()
    stats['recent_blocks'].clear()
    stats['latencies'].clear()
    stats['message_rate'].clear()
    stats['block_rate'].clear()
    stats['attack_types'] = {'DoS': 0, 'Fuzzing': 0, 'Spoofing': 0, 'Other': 0}
    stats['can_id_distribution'].clear()
    stats['start_time'] = time.time()
    
    # Clear message queue
    while not message_queue.empty():
        try:
            message_queue.get_nowait()
        except queue.Empty:
            break
    
    return jsonify({'success': True, 'message': 'Statistics reset'})


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("CAN BUS SECURITY FRAMEWORK - WEB DASHBOARD")
    print("="*60)
    
    # Initialize system
    if initialize_system():
        print("\n✓ System ready")
        print("\nStarting web server...")
        print("Dashboard URL: http://localhost:5000")
        print("\nPress Ctrl+C to stop\n")
        
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    else:
        print("\n✗ Failed to initialize system")
        sys.exit(1)