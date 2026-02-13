"""
Utility Functions - Helper functions for the CAN security framework
"""

import can
import time
import csv
import json
from datetime import datetime
from typing import List, Optional
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


class CANMessageLogger:
    """Log CAN messages to file"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.file = None
        self.writer = None
        
    def __enter__(self):
        self.file = open(self.filename, 'w', newline='')
        self.writer = csv.writer(self.file)
        self.writer.writerow(['Timestamp', 'CAN_ID', 'DLC', 'Data', 'Direction'])
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
    
    def log_message(self, msg: can.Message, direction: str = 'RX'):
        """Log a single message"""
        data_hex = ' '.join(f'{b:02X}' for b in msg.data)
        self.writer.writerow([
            time.time(),
            f'0x{msg.arbitration_id:03X}',
            msg.dlc,
            data_hex,
            direction
        ])


class PerformanceMonitor:
    """Monitor performance metrics"""
    
    def __init__(self):
        self.latencies = []
        self.start_time = None
        self.message_count = 0
        
    def start(self):
        """Start monitoring"""
        self.start_time = time.time()
        self.message_count = 0
        self.latencies = []
    
    def record_latency(self, latency_ms: float):
        """Record a latency measurement"""
        self.latencies.append(latency_ms)
        self.message_count += 1
    
    def get_stats(self) -> dict:
        """Get performance statistics"""
        if not self.latencies:
            return {}
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        return {
            'message_count': self.message_count,
            'elapsed_time': elapsed,
            'throughput': self.message_count / elapsed if elapsed > 0 else 0,
            'avg_latency': np.mean(self.latencies),
            'median_latency': np.median(self.latencies),
            'min_latency': np.min(self.latencies),
            'max_latency': np.max(self.latencies),
            'p95_latency': np.percentile(self.latencies, 95),
            'p99_latency': np.percentile(self.latencies, 99),
            'std_latency': np.std(self.latencies)
        }
    
    def print_stats(self):
        """Print performance statistics"""
        stats = self.get_stats()
        
        if not stats:
            print("No performance data collected")
            return
        
        print("\n" + "="*60)
        print("PERFORMANCE STATISTICS")
        print("="*60)
        print(f"Messages Processed:  {stats['message_count']:,}")
        print(f"Elapsed Time:        {stats['elapsed_time']:.2f} seconds")
        print(f"Throughput:          {stats['throughput']:.2f} msg/s")
        print(f"\nLatency Statistics (ms):")
        print(f"  Mean:              {stats['avg_latency']:.4f}")
        print(f"  Median:            {stats['median_latency']:.4f}")
        print(f"  Min:               {stats['min_latency']:.4f}")
        print(f"  Max:               {stats['max_latency']:.4f}")
        print(f"  Std Dev:           {stats['std_latency']:.4f}")
        print(f"  95th Percentile:   {stats['p95_latency']:.4f}")
        print(f"  99th Percentile:   {stats['p99_latency']:.4f}")
        print("="*60 + "\n")


class Visualizer:
    """Create visualizations for CAN bus data"""
    
    @staticmethod
    def plot_latency_distribution(latencies: List[float], title: str = "Latency Distribution"):
        """Plot latency distribution"""
        plt.figure(figsize=(12, 5))
        
        # Histogram
        plt.subplot(1, 2, 1)
        plt.hist(latencies, bins=50, edgecolor='black', alpha=0.7)
        plt.xlabel('Latency (ms)')
        plt.ylabel('Frequency')
        plt.title(f'{title} - Histogram')
        plt.grid(alpha=0.3)
        
        # Time series
        plt.subplot(1, 2, 2)
        plt.plot(latencies, alpha=0.6)
        plt.xlabel('Message #')
        plt.ylabel('Latency (ms)')
        plt.title(f'{title} - Time Series')
        plt.grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(f'{title.replace(" ", "_")}.png', dpi=150)
        plt.show()
    
    @staticmethod
    def plot_attack_detection_results(true_labels: np.ndarray, predicted_labels: np.ndarray):
        """Plot confusion matrix and detection metrics"""
        from sklearn.metrics import confusion_matrix, classification_report
        
        # Confusion matrix
        cm = confusion_matrix(true_labels, predicted_labels)
        
        plt.figure(figsize=(10, 5))
        
        # Heatmap
        plt.subplot(1, 2, 1)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        
        # Metrics
        report = classification_report(true_labels, predicted_labels, output_dict=True)
        metrics = ['precision', 'recall', 'f1-score']
        values = [report['1'][m] for m in metrics]
        
        plt.subplot(1, 2, 2)
        plt.bar(metrics, values)
        plt.ylim([0, 1])
        plt.ylabel('Score')
        plt.title('Attack Detection Metrics')
        plt.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('attack_detection_results.png', dpi=150)
        plt.show()
        
        # Print detailed report
        print("\nClassification Report:")
        print(classification_report(true_labels, predicted_labels))
    
    @staticmethod
    def plot_message_timeline(timestamps: List[float], can_ids: List[int], 
                            labels: Optional[List[int]] = None):
        """Plot CAN message timeline"""
        plt.figure(figsize=(15, 6))
        
        # Normalize timestamps
        timestamps = np.array(timestamps)
        timestamps = timestamps - timestamps[0]
        
        if labels is not None:
            # Color by attack/normal
            colors = ['green' if l == 0 else 'red' for l in labels]
            plt.scatter(timestamps, can_ids, c=colors, alpha=0.5, s=1)
            plt.legend(['Normal', 'Attack'])
        else:
            plt.scatter(timestamps, can_ids, alpha=0.5, s=1)
        
        plt.xlabel('Time (seconds)')
        plt.ylabel('CAN ID')
        plt.title('CAN Message Timeline')
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig('message_timeline.png', dpi=150)
        plt.show()


def format_can_message(msg: can.Message) -> str:
    """Format CAN message for pretty printing"""
    data_hex = ' '.join(f'{b:02X}' for b in msg.data)
    return f"ID: 0x{msg.arbitration_id:03X} | DLC: {msg.dlc} | Data: [{data_hex}]"


def save_results_to_json(results: dict, filename: str):
    """Save results dictionary to JSON file"""
    # Convert numpy types to native Python types
    def convert(obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj
    
    results_converted = {k: convert(v) for k, v in results.items()}
    
    with open(filename, 'w') as f:
        json.dump(results_converted, f, indent=2)
    
    print(f"Results saved to {filename}")


def create_test_report(framework_stats: dict, performance_stats: dict, 
                      detection_metrics: dict, output_file: str = 'test_report.md'):
    """Create a markdown test report"""
    
    report = f"""# CAN Bus Security Framework - Test Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Framework Statistics

- **Total Messages Processed**: {framework_stats.get('total_processed', 0):,}
- **Messages Allowed**: {framework_stats.get('total_allowed', 0):,}
- **Messages Blocked**: {framework_stats.get('total_blocked', 0):,}
- **Block Rate**: {framework_stats.get('block_rate', 0)*100:.2f}%

## Performance Metrics

- **Throughput**: {performance_stats.get('throughput', 0):.2f} msg/s
- **Average Latency**: {performance_stats.get('avg_latency', 0):.4f} ms
- **P95 Latency**: {performance_stats.get('p95_latency', 0):.4f} ms
- **P99 Latency**: {performance_stats.get('p99_latency', 0):.4f} ms

## Detection Accuracy

- **Precision**: {detection_metrics.get('precision', 0):.4f}
- **Recall**: {detection_metrics.get('recall', 0):.4f}
- **F1-Score**: {detection_metrics.get('f1_score', 0):.4f}

## Block Reasons

"""
    
    for reason, count in framework_stats.get('blocked_reasons', {}).items():
        report += f"- {reason}: {count}\n"
    
    # Save report
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"\nTest report saved to {output_file}")


# Example usage
if __name__ == "__main__":
    # Test logger
    with CANMessageLogger('test_log.csv') as logger:
        msg = can.Message(arbitration_id=0x123, data=[1, 2, 3, 4, 5, 6, 7, 8])
        logger.log_message(msg)
    
    # Test performance monitor
    monitor = PerformanceMonitor()
    monitor.start()
    
    for i in range(1000):
        monitor.record_latency(random.uniform(0.1, 2.0))
    
    monitor.print_stats()
    
    # Test visualizer
    latencies = [random.uniform(0.1, 2.0) for _ in range(1000)]
    Visualizer.plot_latency_distribution(latencies)