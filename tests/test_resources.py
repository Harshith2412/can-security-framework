"""
Resource Usage Testing - Monitor CPU and memory usage
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import can
import time
import psutil
import threading
import pytest
import matplotlib.pyplot as plt
from security_framework import CANSecurityFramework, SecurityConfig
from ecu_simulator import VehicleSimulator


class ResourceMonitor:
    """Monitor system resource usage"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.cpu_samples = []
        self.memory_samples = []
        self.timestamps = []
        self.monitoring = False
        self.start_time = None
    
    def start(self):
        """Start monitoring"""
        self.monitoring = True
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def _monitor_loop(self):
        """Monitoring loop"""
        while self.monitoring:
            # CPU usage
            cpu = self.process.cpu_percent(interval=0.1)
            self.cpu_samples.append(cpu)
            
            # Memory usage (MB)
            memory = self.process.memory_info().rss / 1024 / 1024
            self.memory_samples.append(memory)
            
            # Timestamp
            elapsed = time.time() - self.start_time
            self.timestamps.append(elapsed)
            
            time.sleep(0.1)
    
    def stop(self):
        """Stop monitoring"""
        self.monitoring = False
        time.sleep(0.2)
    
    def get_stats(self):
        """Get statistics"""
        import numpy as np
        
        return {
            'cpu_mean': np.mean(self.cpu_samples) if self.cpu_samples else 0,
            'cpu_max': np.max(self.cpu_samples) if self.cpu_samples else 0,
            'cpu_min': np.min(self.cpu_samples) if self.cpu_samples else 0,
            'memory_mean': np.mean(self.memory_samples) if self.memory_samples else 0,
            'memory_max': np.max(self.memory_samples) if self.memory_samples else 0,
            'memory_min': np.min(self.memory_samples) if self.memory_samples else 0,
            'duration': time.time() - self.start_time if self.start_time else 0
        }


class TestResources:
    """Test suite for resource usage"""
    
    @pytest.fixture
    def bus(self):
        """Create virtual CAN bus"""
        return can.interface.Bus('test', bustype='virtual')
    
    @pytest.fixture
    def framework(self):
        """Create security framework"""
        config = SecurityConfig(
            rate_limit_window=1.0,
            max_messages_per_window=1000,
            ml_enabled=False,
            log_blocked=False,
            log_allowed=False
        )
        return CANSecurityFramework(config)
    
    def test_idle_resource_usage(self, framework):
        """Test resource usage when idle"""
        monitor = ResourceMonitor()
        monitor.start()
        
        print("\n" + "="*60)
        print("IDLE RESOURCE USAGE TEST")
        print("="*60)
        print("Monitoring for 10 seconds...")
        
        time.sleep(10)
        
        monitor.stop()
        stats = monitor.get_stats()
        
        print(f"\nCPU Usage:")
        print(f"  Mean:  {stats['cpu_mean']:.2f}%")
        print(f"  Max:   {stats['cpu_max']:.2f}%")
        print(f"  Min:   {stats['cpu_min']:.2f}%")
        print(f"\nMemory Usage:")
        print(f"  Mean:  {stats['memory_mean']:.2f} MB")
        print(f"  Max:   {stats['memory_max']:.2f} MB")
        print(f"  Min:   {stats['memory_min']:.2f} MB")
        print("="*60)
        
        # Assert reasonable idle usage
        assert stats['cpu_mean'] < 5.0, f"Idle CPU usage too high: {stats['cpu_mean']:.2f}%"
        assert stats['memory_mean'] < 200, f"Idle memory usage too high: {stats['memory_mean']:.2f} MB"
    
    def test_active_processing_resources(self, bus, framework):
        """Test resource usage during active processing"""
        monitor = ResourceMonitor()
        
        # Generate messages in background
        generating = True
        
        def generate_messages():
            count = 0
            while generating:
                msg = can.Message(
                    arbitration_id=0x7E0 + (count % 5),
                    data=[count % 256] + [0] * 7
                )
                framework.process_message(msg)
                count += 1
                time.sleep(0.001)  # ~1000 msg/s
        
        print("\n" + "="*60)
        print("ACTIVE PROCESSING RESOURCE TEST")
        print("="*60)
        print("Processing ~1000 messages/second for 30 seconds...")
        
        # Start monitoring and generation
        monitor.start()
        gen_thread = threading.Thread(target=generate_messages, daemon=True)
        gen_thread.start()
        
        time.sleep(30)
        
        # Stop
        generating = False
        gen_thread.join(timeout=1.0)
        monitor.stop()
        
        stats = monitor.get_stats()
        
        print(f"\nCPU Usage:")
        print(f"  Mean:  {stats['cpu_mean']:.2f}%")
        print(f"  Max:   {stats['cpu_max']:.2f}%")
        print(f"\nMemory Usage:")
        print(f"  Mean:  {stats['memory_mean']:.2f} MB")
        print(f"  Max:   {stats['memory_max']:.2f} MB")
        print("="*60)
        
        # Visualize resource usage
        self._plot_resources(monitor, 'test_results_resources_active.png')
        
        # Assert acceptable usage
        assert stats['cpu_mean'] < 50.0, f"CPU usage too high: {stats['cpu_mean']:.2f}%"
        assert stats['memory_max'] < 500, f"Memory usage too high: {stats['memory_max']:.2f} MB"
    
    def test_resource_usage_under_attack(self, bus, framework):
        """Test resource usage during attack"""
        monitor = ResourceMonitor()
        
        print("\n" + "="*60)
        print("RESOURCE USAGE UNDER ATTACK TEST")
        print("="*60)
        print("Simulating DoS attack for 20 seconds...")
        
        monitor.start()
        
        # Simulate DoS attack (flood)
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < 20:
            msg = can.Message(
                arbitration_id=0x200,
                data=[0xFF] * 8
            )
            framework.process_message(msg)
            count += 1
        
        monitor.stop()
        stats = monitor.get_stats()
        
        print(f"\nProcessed {count:,} attack messages")
        print(f"\nCPU Usage:")
        print(f"  Mean:  {stats['cpu_mean']:.2f}%")
        print(f"  Max:   {stats['cpu_max']:.2f}%")
        print(f"\nMemory Usage:")
        print(f"  Mean:  {stats['memory_mean']:.2f} MB")
        print(f"  Max:   {stats['memory_max']:.2f} MB")
        print("="*60)
        
        # Visualize
        self._plot_resources(monitor, 'test_results_resources_attack.png')
        
        # Assert framework handles attack efficiently
        assert stats['cpu_mean'] < 60.0, f"CPU usage during attack too high: {stats['cpu_mean']:.2f}%"
    
    def test_memory_leak(self, framework):
        """Test for memory leaks over extended operation"""
        monitor = ResourceMonitor()
        
        print("\n" + "="*60)
        print("MEMORY LEAK TEST")
        print("="*60)
        print("Running for 60 seconds to detect memory leaks...")
        
        monitor.start()
        
        # Process messages for 60 seconds
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < 60:
            msg = can.Message(
                arbitration_id=0x7E0 + (count % 10),
                data=[count % 256] + [0] * 7
            )
            framework.process_message(msg)
            count += 1
            
            if count % 10 == 0:
                time.sleep(0.001)
        
        monitor.stop()
        stats = monitor.get_stats()
        
        # Calculate memory growth
        import numpy as np
        first_quarter = monitor.memory_samples[:len(monitor.memory_samples)//4]
        last_quarter = monitor.memory_samples[-len(monitor.memory_samples)//4:]
        
        memory_growth = np.mean(last_quarter) - np.mean(first_quarter)
        
        print(f"\nProcessed {count:,} messages")
        print(f"\nMemory Statistics:")
        print(f"  Initial (avg first 25%): {np.mean(first_quarter):.2f} MB")
        print(f"  Final (avg last 25%):    {np.mean(last_quarter):.2f} MB")
        print(f"  Growth:                  {memory_growth:+.2f} MB")
        print(f"  Max:                     {stats['memory_max']:.2f} MB")
        print("="*60)
        
        # Visualize memory over time
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.plot(monitor.timestamps, monitor.memory_samples, linewidth=2)
        ax.set_xlabel('Time (seconds)')
        ax.set_ylabel('Memory Usage (MB)')
        ax.set_title('Memory Usage Over Time (Memory Leak Test)')
        ax.grid(alpha=0.3)
        
        # Add trend line
        z = np.polyfit(monitor.timestamps, monitor.memory_samples, 1)
        p = np.poly1d(z)
        ax.plot(monitor.timestamps, p(monitor.timestamps), "r--", 
                linewidth=2, label=f'Trend (slope: {z[0]:.4f} MB/s)')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig('test_results_memory_leak.png', dpi=300, bbox_inches='tight')
        print("\n✓ Memory leak plot saved to test_results_memory_leak.png")
        
        # Assert no significant memory leak (< 20MB growth)
        assert memory_growth < 20, f"Possible memory leak detected: {memory_growth:.2f} MB growth"
    
    def test_concurrent_processing_resources(self, bus, framework):
        """Test resource usage with multiple concurrent operations"""
        monitor = ResourceMonitor()
        
        print("\n" + "="*60)
        print("CONCURRENT PROCESSING RESOURCE TEST")
        print("="*60)
        print("Running multiple concurrent message streams...")
        
        running = True
        
        def message_stream(stream_id):
            count = 0
            while running:
                msg = can.Message(
                    arbitration_id=0x700 + stream_id,
                    data=[count % 256] + [stream_id] * 7
                )
                framework.process_message(msg)
                count += 1
                time.sleep(0.005)  # 200 msg/s per stream
        
        monitor.start()
        
        # Start 5 concurrent streams
        threads = []
        for i in range(5):
            t = threading.Thread(target=message_stream, args=(i,), daemon=True)
            t.start()
            threads.append(t)
        
        time.sleep(30)
        
        running = False
        for t in threads:
            t.join(timeout=1.0)
        
        monitor.stop()
        stats = monitor.get_stats()
        
        print(f"\nCPU Usage (5 concurrent streams):")
        print(f"  Mean:  {stats['cpu_mean']:.2f}%")
        print(f"  Max:   {stats['cpu_max']:.2f}%")
        print(f"\nMemory Usage:")
        print(f"  Mean:  {stats['memory_mean']:.2f} MB")
        print(f"  Max:   {stats['memory_max']:.2f} MB")
        print("="*60)
        
        # Visualize
        self._plot_resources(monitor, 'test_results_resources_concurrent.png')
        
        # Assert reasonable resource usage
        assert stats['cpu_mean'] < 100.0, f"CPU usage too high: {stats['cpu_mean']:.2f}%"
    
    def _plot_resources(self, monitor, filename):
        """Helper to plot resource usage"""
        fig, axes = plt.subplots(2, 1, figsize=(12, 8))
        
        # CPU usage
        axes[0].plot(monitor.timestamps, monitor.cpu_samples, 
                    linewidth=2, color='steelblue')
        axes[0].set_xlabel('Time (seconds)')
        axes[0].set_ylabel('CPU Usage (%)')
        axes[0].set_title('CPU Usage Over Time')
        axes[0].grid(alpha=0.3)
        axes[0].axhline(y=50, color='orange', linestyle='--', 
                       linewidth=1, alpha=0.7, label='50% threshold')
        axes[0].legend()
        
        # Memory usage
        axes[1].plot(monitor.timestamps, monitor.memory_samples, 
                    linewidth=2, color='green')
        axes[1].set_xlabel('Time (seconds)')
        axes[1].set_ylabel('Memory Usage (MB)')
        axes[1].set_title('Memory Usage Over Time')
        axes[1].grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"\n✓ Resource usage plot saved to {filename}")


def run_resource_tests():
    """Run all resource tests"""
    print("\n" + "="*60)
    print("STARTING RESOURCE USAGE TESTS")
    print("="*60)
    
    pytest.main([__file__, '-v', '-s'])
    
    print("\n" + "="*60)
    print("RESOURCE TESTS COMPLETE")
    print("="*60)


if __name__ == '__main__':
    run_resource_tests()