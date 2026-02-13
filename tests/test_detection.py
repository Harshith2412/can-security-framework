"""
Detection Testing - Test attack detection accuracy
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import can
import pytest
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

from security_framework import CANSecurityFramework, SecurityConfig
from attack_simulator import AttackSimulator
from dataset_loader import HCRLDataset


class TestDetection:
    """Test suite for detection accuracy"""
    
    @pytest.fixture
    def framework(self):
        """Create security framework"""
        config = SecurityConfig(
            rate_limit_window=1.0,
            max_messages_per_window=500,
            ml_enabled=True,
            log_blocked=False,
            log_allowed=False
        )
        return CANSecurityFramework(config)
    
    @pytest.fixture
    def bus(self):
        """Create virtual CAN bus"""
        return can.interface.Bus('test', bustype='virtual')
    
    def test_normal_traffic_detection(self, framework):
        """Test detection on normal traffic (should not block)"""
        print("\n" + "="*60)
        print("NORMAL TRAFFIC DETECTION TEST")
        print("="*60)
        
        normal_messages = []
        results = []
        
        # Generate normal messages
        for i in range(1000):
            msg = can.Message(
                arbitration_id=0x7E0 + (i % 5),
                data=[i % 256, (i >> 8) % 256, 0, 0, 0, 0, 0, 0]
            )
            normal_messages.append(msg)
        
        # Process messages
        for msg in normal_messages:
            allowed, reason = framework.process_message(msg)
            results.append(allowed)
        
        # Calculate metrics
        total = len(results)
        allowed_count = sum(results)
        blocked_count = total - allowed_count
        false_positive_rate = (blocked_count / total) * 100
        
        print(f"\nTotal Messages:      {total}")
        print(f"Allowed:             {allowed_count} ({(allowed_count/total)*100:.2f}%)")
        print(f"Blocked (FP):        {blocked_count} ({false_positive_rate:.2f}%)")
        print("="*60)
        
        # Assert low false positive rate
        assert false_positive_rate < 5.0, f"False positive rate too high: {false_positive_rate:.2f}%"
    
    def test_dos_attack_detection(self, framework, bus):
        """Test DoS attack detection"""
        print("\n" + "="*60)
        print("DOS ATTACK DETECTION TEST")
        print("="*60)
        
        attacker = AttackSimulator(bus)
        detected_attacks = []
        
        # Generate DoS attack messages
        attack_messages = []
        for i in range(1000):
            msg = can.Message(
                arbitration_id=0x200,  # Low ID for high priority
                data=[0xFF] * 8
            )
            attack_messages.append(msg)
        
        # Process attack messages
        for msg in attack_messages:
            allowed, reason = framework.process_message(msg)
            if not allowed:
                detected_attacks.append(True)
            else:
                detected_attacks.append(False)
        
        # Calculate detection rate
        total_attacks = len(attack_messages)
        detected_count = sum(detected_attacks)
        detection_rate = (detected_count / total_attacks) * 100
        
        print(f"\nAttack Messages:     {total_attacks}")
        print(f"Detected (Blocked):  {detected_count} ({detection_rate:.2f}%)")
        print(f"Missed:              {total_attacks - detected_count} ({100-detection_rate:.2f}%)")
        print("="*60)
        
        # Assert high detection rate
        assert detection_rate > 90.0, f"Detection rate too low: {detection_rate:.2f}%"
    
    def test_fuzzing_attack_detection(self, framework):
        """Test fuzzing attack detection"""
        print("\n" + "="*60)
        print("FUZZING ATTACK DETECTION TEST")
        print("="*60)
        
        detected_attacks = []
        
        # Generate fuzzing attack (random data)
        for i in range(1000):
            msg = can.Message(
                arbitration_id=0x760,
                data=np.random.randint(0, 256, 8, dtype=np.uint8).tolist()
            )
            
            allowed, reason = framework.process_message(msg)
            detected_attacks.append(not allowed)
        
        detection_rate = (sum(detected_attacks) / len(detected_attacks)) * 100
        
        print(f"\nFuzzing Messages:    {len(detected_attacks)}")
        print(f"Detected (Blocked):  {sum(detected_attacks)} ({detection_rate:.2f}%)")
        print("="*60)
        
        # Assert reasonable detection (fuzzing is harder to detect)
        assert detection_rate > 70.0, f"Fuzzing detection rate too low: {detection_rate:.2f}%"
    
    def test_spoofing_attack_detection(self, framework):
        """Test spoofing/impersonation attack detection"""
        print("\n" + "="*60)
        print("SPOOFING ATTACK DETECTION TEST")
        print("="*60)
        
        # Simulate infotainment trying to send brake commands
        detected_attacks = []
        
        for i in range(500):
            msg = can.Message(
                arbitration_id=0x760,  # Brake system ID
                data=[0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]
            )
            
            # Mark as coming from infotainment domain
            allowed, reason = framework.process_message(msg, source_domain='infotainment')
            detected_attacks.append(not allowed)
        
        detection_rate = (sum(detected_attacks) / len(detected_attacks)) * 100
        
        print(f"\nSpoofing Attempts:   {len(detected_attacks)}")
        print(f"Detected (Blocked):  {sum(detected_attacks)} ({detection_rate:.2f}%)")
        print("="*60)
        
        # Domain isolation should block these
        assert detection_rate > 95.0, f"Spoofing detection rate too low: {detection_rate:.2f}%"
    
    def test_mixed_traffic_detection(self, framework):
        """Test detection on mixed normal and attack traffic"""
        print("\n" + "="*60)
        print("MIXED TRAFFIC DETECTION TEST")
        print("="*60)
        
        messages = []
        labels = []  # 0 = normal, 1 = attack
        
        # Generate mixed traffic (70% normal, 30% attacks)
        for i in range(1000):
            if np.random.random() < 0.7:
                # Normal message
                msg = can.Message(
                    arbitration_id=0x7E0 + (i % 5),
                    data=[i % 256] + [0] * 7
                )
                labels.append(0)
            else:
                # Attack message (DoS)
                msg = can.Message(
                    arbitration_id=0x200,
                    data=[0xFF] * 8
                )
                labels.append(1)
            
            messages.append(msg)
        
        # Process messages
        predictions = []
        for msg in messages:
            allowed, reason = framework.process_message(msg)
            predictions.append(0 if allowed else 1)  # 0 = normal, 1 = blocked
        
        # Calculate metrics
        labels = np.array(labels)
        predictions = np.array(predictions)
        
        tn, fp, fn, tp = confusion_matrix(labels, predictions).ravel()
        
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"\nTotal Messages:      {len(messages)}")
        print(f"Normal:              {np.sum(labels == 0)}")
        print(f"Attack:              {np.sum(labels == 1)}")
        print(f"\nConfusion Matrix:")
        print(f"  TN: {tn:4d}  FP: {fp:4d}")
        print(f"  FN: {fn:4d}  TP: {tp:4d}")
        print(f"\nMetrics:")
        print(f"  Accuracy:            {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  Precision:           {precision:.4f}")
        print(f"  Recall (TPR):        {recall:.4f}")
        print(f"  F1-Score:            {f1:.4f}")
        print(f"  False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
        print("="*60)
        
        # Visualize confusion matrix
        self._plot_confusion_matrix(labels, predictions, 'test_results_confusion_matrix.png')
        
        # Assert good performance
        assert accuracy > 0.90, f"Accuracy too low: {accuracy:.4f}"
        assert fpr < 0.10, f"False positive rate too high: {fpr:.4f}"
    
    def test_detection_with_dataset(self):
        """Test detection using HCRL dataset (if available)"""
        print("\n" + "="*60)
        print("DATASET-BASED DETECTION TEST")
        print("="*60)
        
        # Try to load HCRL dataset
        try:
            dataset_path = os.path.join('..', 'datasets', 'CAN-intrusion-dataset')
            
            if not os.path.exists(dataset_path):
                print("HCRL dataset not found. Skipping test.")
                pytest.skip("HCRL dataset not available")
                return
            
            loader = HCRLDataset(dataset_path)
            
            # Load small samples
            normal_df = loader.load_dataset('normal')
            dos_df = loader.load_dataset('dos')
            
            # Take small samples
            normal_sample = normal_df.sample(min(500, len(normal_df)))
            dos_sample = dos_df.sample(min(500, len(dos_df)))



          
            
            framework = CANSecurityFramework(SecurityConfig(
                rate_limit_window=1.0,
                max_messages_per_window=500,
                ml_enabled=True,
                log_blocked=False,
                log_allowed=False
            ))
            
            labels = []
            predictions = []

            
            # Test normal messages
            for _, row in normal_sample.iterrows():
                msg = can.Message(
                    arbitration_id=int(row['CAN_ID']),
                    data=[int(row[f'Data{i}']) for i in range(8)]
                )
                allowed, _ = framework.process_message(msg)
                labels.append(0)
                predictions.append(0 if allowed else 1)
            
            # Test attack messages
            for _, row in dos_sample.iterrows():
                msg = can.Message(
                    arbitration_id=int(row['CAN_ID']),
                    data=[int(row[f'Data{i}']) for i in range(8)]
                )
                allowed, _ = framework.process_message(msg)
                labels.append(1)
                predictions.append(0 if allowed else 1)


            # Calculate metrics
            labels = np.array(labels)
            predictions = np.array(predictions)
            
            print(classification_report(labels, predictions, 
                                       target_names=['Normal', 'Attack']))
            
            accuracy = np.mean(labels == predictions)
            print(f"\nOverall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
            print("="*60)
            
        except Exception as e:
            print(f"Error loading dataset: {e}")
            pytest.skip("Could not load HCRL dataset")
    
    def _plot_confusion_matrix(self, y_true, y_pred, filename):
        """Helper to plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Normal', 'Attack'],
                   yticklabels=['Normal', 'Attack'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix - Detection Performance')
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"\n✓ Confusion matrix saved to {filename}")


def run_detection_tests():
    """Run all detection tests"""
    print("\n" + "="*60)
    print("STARTING DETECTION ACCURACY TESTS")
    print("="*60)
    
    pytest.main([__file__, '-v', '-s'])
    
    print("\n" + "="*60)
    print("DETECTION TESTS COMPLETE")
    print("="*60)


if __name__ == '__main__':
    run_detection_tests()

