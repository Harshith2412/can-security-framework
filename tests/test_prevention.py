"""
Prevention Testing - Test attack prevention effectiveness
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import can
import time
import pytest
import numpy as np
import matplotlib.pyplot as plt

from security_framework import CANSecurityFramework, SecurityConfig
from attack_simulator import AttackSimulator


class TestPrevention:
    """Test suite for prevention effectiveness"""
    
    @pytest.fixture
    def framework(self):
        """Create security framework"""
        config = SecurityConfig(
            rate_limit_window=1.0,
            max_messages_per_window=500,
            ml_enabled=True,
            stateful_enabled=False,
            log_blocked=True,
            log_allowed=False
        )
        return CANSecurityFramework(config)
    
    @pytest.fixture
    def bus(self):
        """Create virtual CAN bus"""
        return can.interface.Bus('test', bustype='virtual')
    
    def test_dos_prevention(self, framework):
        """Test prevention of DoS attacks"""
        print("\n" + "="*60)
        print("DOS ATTACK PREVENTION TEST")
        print("="*60)
        
        blocked_count = 0
        total_count = 0
        
        # Simulate DoS flood (10,000 messages to same ID)
        print("Simulating DoS flood attack...")
        
        for i in range(10000):
            msg = can.Message(
                arbitration_id=0x200,
                data=[0xFF] * 8
            )
            
            allowed, reason = framework.process_message(msg)
            total_count += 1
            
            if not allowed:
                blocked_count += 1
        
        prevention_rate = (blocked_count / total_count) * 100
        
        print(f"\nAttack Messages:     {total_count:,}")
        print(f"Blocked:             {blocked_count:,} ({prevention_rate:.2f}%)")
        print(f"Allowed (leaked):    {total_count - blocked_count:,} ({100-prevention_rate:.2f}%)")
        print("="*60)
        
        # Assert high prevention rate
        assert prevention_rate >= 95.0, f"DoS prevention rate too low: {prevention_rate:.2f}%"
    
    def test_rate_limiting_effectiveness(self, framework):
        """Test rate limiting prevents message flooding"""
        print("\n" + "="*60)
        print("RATE LIMITING EFFECTIVENESS TEST")
        print("="*60)
        
        # Send burst of messages
        allowed_counts = []
        blocked_counts = []
        
        for window in range(5):
            allowed = 0
            blocked = 0
            
            # Send 1000 messages in 1 second window
            for i in range(1000):
                msg = can.Message(
                    arbitration_id=0x7E0,
                    data=[i % 256] + [0] * 7
                )
                
                is_allowed, reason = framework.process_message(msg)
                
                if is_allowed:
                    allowed += 1
                else:
                    blocked += 1
            
            allowed_counts.append(allowed)
            blocked_counts.append(blocked)
            
            print(f"Window {window + 1}: Allowed={allowed:4d}, Blocked={blocked:4d}")
            
            time.sleep(1.1)  # Wait for rate limit window to reset
        
        print("="*60)
        
        # Visualize rate limiting
        fig, ax = plt.subplots(figsize=(10, 6))
        x = range(1, 6)
        ax.bar([i - 0.2 for i in x], allowed_counts, 0.4, label='Allowed', color='green', alpha=0.7)
        ax.bar([i + 0.2 for i in x], blocked_counts, 0.4, label='Blocked', color='red', alpha=0.7)
        ax.set_xlabel('Time Window')
        ax.set_ylabel('Message Count')
        ax.set_title('Rate Limiting Effectiveness')
        ax.legend()
        ax.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig('test_results_rate_limiting.png', dpi=300, bbox_inches='tight')
        print("\n✓ Rate limiting plot saved to test_results_rate_limiting.png")
        
        # Assert rate limiting is working
        max_allowed = max(allowed_counts)
        assert max_allowed <= 600, f"Rate limit not enforced: {max_allowed} messages allowed"
    
    def test_domain_isolation_prevention(self, framework):
        """Test domain isolation prevents unauthorized access"""
        print("\n" + "="*60)
        print("DOMAIN ISOLATION PREVENTION TEST")
        print("="*60)
        
        test_scenarios = [
            {
                'name': 'Infotainment → Engine Control',
                'source': 'infotainment',
                'target_id': 0x7E0,
                'should_block': True
            },
            {
                'name': 'Infotainment → Brakes',
                'source': 'infotainment',
                'target_id': 0x760,
                'should_block': True
            },
            {
                'name': 'Infotainment → Own Domain',
                'source': 'infotainment',
                'target_id': 0x3C0,
                'should_block': False
            },
            {
                'name': 'Powertrain → Chassis',
                'source': 'powertrain',
                'target_id': 0x760,
                'should_block': False
            }
        ]
        
        results = []
        
        for scenario in test_scenarios:
            blocked_count = 0
            total_count = 100
            
            for i in range(total_count):
                msg = can.Message(
                    arbitration_id=scenario['target_id'],
                    data=[i % 256] + [0] * 7
                )
                
                allowed, reason = framework.process_message(msg, source_domain=scenario['source'])
                
                if not allowed:
                    blocked_count += 1
            
            prevention_rate = (blocked_count / total_count) * 100
            results.append({
                'scenario': scenario['name'],
                'prevention_rate': prevention_rate,
                'should_block': scenario['should_block']
            })
            
            status = "✓ PASS" if (prevention_rate >= 90 and scenario['should_block']) or \
                                 (prevention_rate <= 10 and not scenario['should_block']) else "✗ FAIL"
            
            print(f"\n{scenario['name']:30s}")
            print(f"  Expected: {'BLOCK' if scenario['should_block'] else 'ALLOW'}")
            print(f"  Prevention Rate: {prevention_rate:.1f}%")
            print(f"  Status: {status}")
        
        print("="*60)
        
        # Assert domain isolation is working
        for result in results:
            if result['should_block']:
                assert result['prevention_rate'] >= 90, \
                    f"{result['scenario']}: Should block but prevention rate only {result['prevention_rate']:.1f}%"
            else:
                assert result['prevention_rate'] < 10, \
                    f"{result['scenario']}: Should allow but prevention rate {result['prevention_rate']:.1f}%"
    
    def test_prevention_without_false_positives(self, framework):
        """Test prevention doesn't block legitimate traffic"""
        print("\n" + "="*60)
        print("PREVENTION FALSE POSITIVE TEST")
        print("="*60)
        
        # Generate legitimate traffic patterns
        legitimate_patterns = [
            {'id': 0x7E0, 'rate': 100, 'name': 'Engine Control'},
            {'id': 0x7E1, 'rate': 50, 'name': 'Transmission'},
            {'id': 0x760, 'rate': 100, 'name': 'Brakes'},
            {'id': 0x761, 'rate': 50, 'name': 'Steering'},
            {'id': 0x3C0, 'rate': 20, 'name': 'Infotainment'}
        ]
        
        results = []
        
        for pattern in legitimate_patterns:
            blocked = 0
            total = pattern['rate']
            
            for i in range(total):
                msg = can.Message(
                    arbitration_id=pattern['id'],
                    data=[i % 256, (i >> 8) % 256, 0, 0, 0, 0, 0, 0]
                )
                
                allowed, reason = framework.process_message(msg)
                
                if not allowed:
                    blocked += 1
                
                # Simulate realistic timing
                time.sleep(0.01)
            
            false_positive_rate = (blocked / total) * 100
            results.append({
                'name': pattern['name'],
                'id': f"0x{pattern['id']:03X}",
                'total': total,
                'blocked': blocked,
                'fpr': false_positive_rate
            })
            
            print(f"\n{pattern['name']:20s} (ID: 0x{pattern['id']:03X})")
            print(f"  Messages: {total}")
            print(f"  Blocked:  {blocked} ({false_positive_rate:.2f}%)")
        
        print("="*60)
        
        # Visualize false positive rates
        fig, ax = plt.subplots(figsize=(10, 6))
        names = [r['name'] for r in results]
        fprs = [r['fpr'] for r in results]
        
        bars = ax.bar(names, fprs, color='orange', alpha=0.7)
        ax.axhline(y=5.0, color='red', linestyle='--', linewidth=2, 
                  label='5% Threshold', alpha=0.7)
        ax.set_ylabel('False Positive Rate (%)')
        ax.set_title('False Positive Rates for Legitimate Traffic')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        plt.xticks(rotation=15, ha='right')
        plt.tight_layout()
        plt.savefig('test_results_false_positives.png', dpi=300, bbox_inches='tight')
        print("\n✓ False positive plot saved to test_results_false_positives.png")
        
        # Assert low false positive rates
        max_fpr = max(fprs)
        assert max_fpr < 5.0, f"False positive rate too high: {max_fpr:.2f}%"
    
    def test_multi_attack_prevention(self, framework, bus):
        """Test prevention against multiple simultaneous attacks"""
        print("\n" + "="*60)
        print("MULTI-ATTACK PREVENTION TEST")
        print("="*60)
        
        attacker = AttackSimulator(bus)
        
        attack_results = []
        
        # Simulate multiple attack types
        attack_types = [
            {'name': 'DoS', 'func': lambda: self._simulate_dos(framework), 'expected_prevention': 50},
            {'name': 'Fuzzing', 'func': lambda: self._simulate_fuzzing(framework), 'expected_prevention': 50},
            {'name': 'Spoofing', 'func': lambda: self._simulate_spoofing(framework), 'expected_prevention': 95}
        ]
        
        for attack in attack_types:
            blocked, total = attack['func']()
            prevention_rate = (blocked / total) * 100
            
            attack_results.append({
                'type': attack['name'],
                'total': total,
                'blocked': blocked,
                'prevention_rate': prevention_rate,
                'expected': attack['expected_prevention']
            })
            
            status = "✓ PASS" if prevention_rate >= attack['expected_prevention'] else "✗ FAIL"
            
            print(f"\n{attack['name']} Attack:")
            print(f"  Total:      {total}")
            print(f"  Blocked:    {blocked} ({prevention_rate:.1f}%)")
            print(f"  Expected:   >{attack['expected_prevention']}%")
            print(f"  Status:     {status}")
        
        print("="*60)
        
        # Visualize multi-attack prevention
        fig, ax = plt.subplots(figsize=(10, 6))
        types = [r['type'] for r in attack_results]
        rates = [r['prevention_rate'] for r in attack_results]
        expected = [r['expected'] for r in attack_results]
        
        x = range(len(types))
        ax.bar([i - 0.2 for i in x], rates, 0.4, label='Actual', color='steelblue', alpha=0.8)
        ax.bar([i + 0.2 for i in x], expected, 0.4, label='Expected', color='green', alpha=0.6)
        ax.set_xticks(x)
        ax.set_xticklabels(types)
        ax.set_ylabel('Prevention Rate (%)')
        ax.set_title('Multi-Attack Prevention Effectiveness')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        ax.set_ylim([0, 105])
        plt.tight_layout()
        plt.savefig('test_results_multi_attack.png', dpi=300, bbox_inches='tight')
        print("\n✓ Multi-attack prevention plot saved to test_results_multi_attack.png")
        
        # Assert all attacks are prevented at expected rates
        for result in attack_results:
            assert result['prevention_rate'] >= result['expected'], \
                f"{result['type']} prevention rate {result['prevention_rate']:.1f}% below expected {result['expected']}%"
    def _simulate_dos(self, framework):
        """Simulate DoS attack"""
        framework.reset_statistics()
        
        blocked = 0
        total = 10000
        
        for i in range(total):
            msg = can.Message(arbitration_id=0x200, data=[0xFF] * 8)
            allowed, _ = framework.process_message(msg)
            if not allowed:
                blocked += 1
        
        return blocked, total
    
    def _simulate_fuzzing(self, framework):
        """Simulate fuzzing attack"""
        framework.reset_statistics()
        
        blocked = 0
        total = 5000
        
        for i in range(total):
            msg = can.Message(
                arbitration_id=0x760,
                data=np.random.randint(0, 256, 8, dtype=np.uint8).tolist()
            )
            allowed, _ = framework.process_message(msg)
            if not allowed:
                blocked += 1
        
        return blocked, total
    
    def _simulate_spoofing(self, framework):
        """Simulate spoofing attack"""
        framework.reset_statistics()
        
        blocked = 0
        total = 1000
        
        for i in range(total):
            msg = can.Message(
                arbitration_id=0x760,
                data=[0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]
            )
            allowed, _ = framework.process_message(msg, source_domain='infotainment')
            if not allowed:
                blocked += 1
        
        return blocked, total


def run_prevention_tests():
    """Run all prevention tests"""
    print("\n" + "="*60)
    print("STARTING PREVENTION EFFECTIVENESS TESTS")
    print("="*60)
    
    pytest.main([__file__, '-v', '-s'])
    
    print("\n" + "="*60)
    print("PREVENTION TESTS COMPLETE")
    print("="*60)


if __name__ == '__main__':
    run_prevention_tests()