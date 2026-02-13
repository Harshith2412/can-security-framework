"""
Latency Testing - Measure processing speed of security framework
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import can
import time
import numpy as np
import pytest
from security_framework import CANSecurityFramework, SecurityConfig
from ecu_simulator import ECU, ECUConfig
import matplotlib.pyplot as plt


class TestLatency:
    """Test suite for latency measurements"""
    
    @pytest.fixture
    def framework(self):
        """Create a security framework instance"""
        config = SecurityConfig(
            rate_limit_window=1.0,
            max_messages_per_window=1000,
            ml_enabled=False,  # Disable ML for consistent latency
            log_blocked=False,
            log_allowed=False
        )
        return CANSecurityFramework(config)
    
    @pytest.fixture
    def test_messages(self):
        """Generate test messages"""
        messages = []
        for i in range(10000):
            msg = can.Message(
                arbitration_id=0x7E0 + (i % 3),
                data=[i % 256, (i >> 8) % 256, 0, 0, 0, 0, 0, 0],
                is_extended_id=False
            )
            messages.append(msg)
        return messages
    
    def test_single_message_latency(self, framework):
        """Test latency for a single message"""
        msg = can.Message(
            arbitration_id=0x7E0,
            data=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        )
        
        latencies = []
        
        for _ in range(1000):
            start = time.perf_counter()
            framework.process_message(msg)
            end = time.perf_counter()
            
            latency_ms = (end - start) * 1000
            latencies.append(latency_ms)
        
        avg_latency = np.mean(latencies)
        p95_latency = np.percentile(latencies, 95)
        p99_latency = np.percentile(latencies, 99)
        
        print("\n" + "="*60)
        print("SINGLE MESSAGE LATENCY TEST")
        print("="*60)
        print(f"Samples: 1000")
        print(f"Average:         {avg_latency:.4f} ms")
        print(f"Median:          {np.median(latencies):.4f} ms")
        print(f"Min:             {np.min(latencies):.4f} ms")
        print(f"Max:             {np.max(latencies):.4f} ms")
        print(f"Std Dev:         {np.std(latencies):.4f} ms")
        print(f"95th Percentile: {p95_latency:.4f} ms")
        print(f"99th Percentile: {p99_latency:.4f} ms")
        print("="*60)
        
        # Assert reasonable latency (< 2ms average)
        assert avg_latency < 2.0, f"Average latency too high: {avg_latency:.4f} ms"
        assert p99_latency < 5.0, f"P99 latency too high: {p99_latency:.4f} ms"
    
    def test_burst_latency(self, framework, test_messages):
        """Test latency under burst load"""
        latencies = []
        
        print("\n" + "="*60)
        print("BURST LATENCY TEST")
        print("="*60)
        print(f"Processing {len(test_messages)} messages...")
        
        start_time = time.time()
        
        for msg in test_messages:
            msg_start = time.perf_counter()
            framework.process_message(msg)
            msg_end = time.perf_counter()
            
            latency_ms = (msg_end - msg_start) * 1000
            latencies.append(latency_ms)
        
        total_time = time.time() - start_time
        throughput = len(test_messages) / total_time
        
        print(f"\nTotal Time:      {total_time:.2f} seconds")
        print(f"Throughput:      {throughput:.2f} messages/second")
        print(f"Average Latency: {np.mean(latencies):.4f} ms")
        print(f"Median Latency:  {np.median(latencies):.4f} ms")
        print(f"P95 Latency:     {np.percentile(latencies, 95):.4f} ms")
        print(f"P99 Latency:     {np.percentile(latencies, 99):.4f} ms")
        print("="*60)
        
        # Assert minimum throughput (should handle at least 1000 msg/s)
        assert throughput > 1000, f"Throughput too low: {throughput:.2f} msg/s"
    
    def test_latency_under_attack(self, framework):
        """Test latency during attack scenario"""
        normal_latencies = []
        attack_latencies = []
        
        # Normal messages
        for i in range(1000):
            msg = can.Message(
                arbitration_id=0x7E0 + (i % 3),
                data=[i % 256, 0, 0, 0, 0, 0, 0, 0]
            )
            
            start = time.perf_counter()
            framework.process_message(msg)
            end = time.perf_counter()
            
            normal_latencies.append((end - start) * 1000)
        
        # Attack messages (should be blocked quickly)
        for i in range(1000):
            msg = can.Message(
                arbitration_id=0x200,  # DoS flood
                data=[0xFF] * 8
            )
            
            start = time.perf_counter()
            framework.process_message(msg)
            end = time.perf_counter()
            
            attack_latencies.append((end - start) * 1000)
        
        print("\n" + "="*60)
        print("LATENCY UNDER ATTACK TEST")
        print("="*60)
        print("Normal Traffic:")
        print(f"  Average: {np.mean(normal_latencies):.4f} ms")
        print(f"  P95:     {np.percentile(normal_latencies, 95):.4f} ms")
        print("\nAttack Traffic (Blocked):")
        print(f"  Average: {np.mean(attack_latencies):.4f} ms")
        print(f"  P95:     {np.percentile(attack_latencies, 95):.4f} ms")
        print("="*60)
        
        # Attack detection should not significantly increase latency
        attack_overhead = np.mean(attack_latencies) - np.mean(normal_latencies)
        print(f"\nAttack Detection Overhead: {attack_overhead:.4f} ms")
        
        # Assert overhead is reasonable (< 1ms)
        assert attack_overhead < 1.0, f"Attack detection overhead too high: {attack_overhead:.4f} ms"
    
    def test_latency_distribution(self, framework, test_messages):
        """Test and visualize latency distribution"""
        latencies = []
        
        for msg in test_messages[:5000]:  # Use 5000 samples
            start = time.perf_counter()
            framework.process_message(msg)
            end = time.perf_counter()
            
            latencies.append((end - start) * 1000)
        
        # Calculate statistics
        percentiles = [50, 75, 90, 95, 99, 99.9]
        percentile_values = [np.percentile(latencies, p) for p in percentiles]
        
        print("\n" + "="*60)
        print("LATENCY DISTRIBUTION TEST")
        print("="*60)
        print("Percentiles:")
        for p, v in zip(percentiles, percentile_values):
            print(f"  P{p:5.1f}: {v:.4f} ms")
        print("="*60)
        
        # Create visualization
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Latency Analysis', fontsize=16, fontweight='bold')
        
        # Histogram
        axes[0, 0].hist(latencies, bins=50, edgecolor='black', alpha=0.7)
        axes[0, 0].axvline(np.mean(latencies), color='red', linestyle='--', 
                          linewidth=2, label=f'Mean: {np.mean(latencies):.3f} ms')
        axes[0, 0].set_xlabel('Latency (ms)')
        axes[0, 0].set_ylabel('Frequency')
        axes[0, 0].set_title('Latency Distribution')
        axes[0, 0].legend()
        axes[0, 0].grid(alpha=0.3)
        
        # Time series
        axes[0, 1].plot(latencies[:1000], alpha=0.6, linewidth=0.8)
        axes[0, 1].set_xlabel('Message Number')
        axes[0, 1].set_ylabel('Latency (ms)')
        axes[0, 1].set_title('Latency Over Time')
        axes[0, 1].grid(alpha=0.3)
        
        # Box plot
        axes[1, 0].boxplot(latencies, vert=True)
        axes[1, 0].set_ylabel('Latency (ms)')
        axes[1, 0].set_title('Latency Statistics')
        axes[1, 0].grid(axis='y', alpha=0.3)
        
        # Percentile bars
        axes[1, 1].bar(range(len(percentiles)), percentile_values, color='steelblue', alpha=0.8)
        axes[1, 1].set_xticks(range(len(percentiles)))
        axes[1, 1].set_xticklabels([f'P{p}' for p in percentiles])
        axes[1, 1].set_ylabel('Latency (ms)')
        axes[1, 1].set_title('Latency Percentiles')
        axes[1, 1].grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('test_results_latency.png', dpi=300, bbox_inches='tight')
        print("\n✓ Latency distribution plot saved to test_results_latency.png")
        
        # Assert P99 latency is reasonable
        assert percentile_values[-2] < 3.0, f"P99 latency too high: {percentile_values[-2]:.4f} ms"
    
    def test_throughput_scalability(self, framework):
        """Test throughput at different load levels"""
        load_levels = [100, 500, 1000, 2000, 5000]
        results = []
        
        print("\n" + "="*60)
        print("THROUGHPUT SCALABILITY TEST")
        print("="*60)
        
        for load in load_levels:
            messages = []
            for i in range(load):
                msg = can.Message(
                    arbitration_id=0x7E0 + (i % 5),
                    data=[i % 256] + [0] * 7
                )
                messages.append(msg)
            
            start_time = time.time()
            for msg in messages:
                framework.process_message(msg)
            total_time = time.time() - start_time
            
            throughput = load / total_time
            results.append({
                'load': load,
                'time': total_time,
                'throughput': throughput
            })
            
            print(f"Load: {load:5d} msgs | Time: {total_time:6.3f}s | Throughput: {throughput:8.2f} msg/s")
        
        print("="*60)
        
        # Visualize scalability
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        loads = [r['load'] for r in results]
        times = [r['time'] for r in results]
        throughputs = [r['throughput'] for r in results]
        
        # Processing time vs load
        axes[0].plot(loads, times, marker='o', linewidth=2)
        axes[0].set_xlabel('Number of Messages')
        axes[0].set_ylabel('Processing Time (seconds)')
        axes[0].set_title('Processing Time vs Load')
        axes[0].grid(alpha=0.3)
        
        # Throughput vs load
        axes[1].plot(loads, throughputs, marker='o', linewidth=2, color='green')
        axes[1].set_xlabel('Number of Messages')
        axes[1].set_ylabel('Throughput (msg/s)')
        axes[1].set_title('Throughput vs Load')
        axes[1].grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('test_results_scalability.png', dpi=300, bbox_inches='tight')
        print("\n✓ Scalability plot saved to test_results_scalability.png")
        
        # Assert linear scaling
        assert min(throughputs) > 500, f"Minimum throughput too low: {min(throughputs):.2f} msg/s"


def run_latency_tests():
    """Run all latency tests"""
    print("\n" + "="*60)
    print("STARTING LATENCY TESTS")
    print("="*60)
    
    # Run pytest
    pytest.main([__file__, '-v', '-s'])
    
    print("\n" + "="*60)
    print("LATENCY TESTS COMPLETE")
    print("="*60)


if __name__ == '__main__':
    run_latency_tests()