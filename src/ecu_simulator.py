"""
ECU Simulator - Simulates multiple ECUs sending periodic CAN messages
"""

import can
import time
import random
from threading import Thread
from dataclasses import dataclass
from typing import List, Callable, Optional


@dataclass
class ECUConfig:
    """Configuration for an ECU"""
    name: str
    can_id: int
    interval: float  # seconds between messages
    data_generator: Optional[Callable] = None
    

class ECU:
    """Simulates a single ECU sending periodic CAN messages"""
    
    def __init__(self, bus: can.Bus, config: ECUConfig):
        self.bus = bus
        self.config = config
        self.running = False
        self.thread = None
        self.message_count = 0
        
    def generate_message(self) -> can.Message:
        """Generate a CAN message based on ECU type"""
        
        if self.config.data_generator:
            data = self.config.data_generator()
        else:
            data = self._default_data_generator()
        
        return can.Message(
            arbitration_id=self.config.can_id,
            data=data,
            is_extended_id=False
        )
    
    def _default_data_generator(self) -> List[int]:
        """Default data generator - creates realistic-looking data"""
        
        # Simulate sensor readings with some variation
        if self.config.can_id in [0x7E0, 0x7E1, 0x7E2]:  # Powertrain
            # Engine/transmission data
            data = [
                random.randint(0, 255),      # byte 0: varies
                random.randint(80, 120),     # byte 1: temperature-like
                random.randint(0, 100),      # byte 2: percentage
                0x00,                         # byte 3: reserved
                random.randint(0, 50),       # byte 4: low range value
                0x00, 0x00, 0x00
            ]
        elif self.config.can_id in [0x760, 0x761, 0x762]:  # Chassis
            # Brake/steering/airbag data
            data = [
                0xFF if random.random() > 0.9 else 0x00,  # byte 0: status flag
                random.randint(0, 255),                    # byte 1: sensor value
                random.randint(50, 150),                   # byte 2: pressure/angle
                0x00,
                random.randint(0, 100),
                0x00, 0x00, 0x00
            ]
        else:  # Body/Infotainment
            # Less critical data, more variation
            data = [random.randint(0, 255) for _ in range(8)]
        
        return data[:8]  # Ensure 8 bytes
    
    def start(self):
        """Start sending messages"""
        if self.running:
            print(f"[{self.config.name}] Already running")
            return
        
        self.running = True
        self.thread = Thread(target=self._send_loop, daemon=True)
        self.thread.start()
        print(f"[{self.config.name}] Started (ID: 0x{self.config.can_id:03X}, Interval: {self.config.interval}s)")
    
    def _send_loop(self):
        """Continuously send messages at specified interval"""
        while self.running:
            try:
                msg = self.generate_message()
                self.bus.send(msg)
                self.message_count += 1
                time.sleep(self.config.interval)
            except Exception as e:
                print(f"[{self.config.name}] Error sending message: {e}")
                time.sleep(0.1)
    
    def stop(self):
        """Stop sending messages"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        print(f"[{self.config.name}] Stopped (sent {self.message_count} messages)")


class VehicleSimulator:
    """Simulates a complete vehicle with multiple ECUs"""
    
    def __init__(self, bus: can.Bus):
        self.bus = bus
        self.ecus: List[ECU] = []
        self._create_default_ecus()
    
    def _create_default_ecus(self):
        """Create a standard set of ECUs mimicking a real vehicle"""
        
        # Powertrain ECUs (High frequency, critical)
        configs = [
            ECUConfig("Engine_Control", 0x7E0, 0.010),      # 100 Hz
            ECUConfig("Transmission", 0x7E1, 0.020),         # 50 Hz
            ECUConfig("Hybrid_Control", 0x7E2, 0.020),       # 50 Hz
            
            # Chassis ECUs (High frequency, safety-critical)
            ECUConfig("ABS_Brakes", 0x760, 0.010),          # 100 Hz
            ECUConfig("Steering", 0x761, 0.020),             # 50 Hz
            ECUConfig("Airbag", 0x762, 0.050),               # 20 Hz
            
            # Body ECUs (Medium frequency, comfort)
            ECUConfig("Body_Control", 0x510, 0.100),         # 10 Hz
            ECUConfig("Door_Left", 0x511, 0.200),            # 5 Hz
            ECUConfig("Door_Right", 0x512, 0.200),           # 5 Hz
            
            # Infotainment ECUs (Variable frequency, non-critical)
            ECUConfig("Radio_HMI", 0x3C0, 0.050),           # 20 Hz
            ECUConfig("Telematics", 0x3C1, 0.500),          # 2 Hz
            ECUConfig("ADAS_Cameras", 0x3C2, 0.033),        # 30 Hz
        ]
        
        for config in configs:
            self.ecus.append(ECU(self.bus, config))
    
    def add_ecu(self, config: ECUConfig):
        """Add a custom ECU to the simulator"""
        ecu = ECU(self.bus, config)
        self.ecus.append(ecu)
        return ecu
    
    def start_all(self):
        """Start all ECUs"""
        print("\n" + "="*60)
        print("STARTING VEHICLE SIMULATION")
        print("="*60)
        for ecu in self.ecus:
            ecu.start()
        print("="*60 + "\n")
    
    def stop_all(self):
        """Stop all ECUs"""
        print("\n" + "="*60)
        print("STOPPING VEHICLE SIMULATION")
        print("="*60)
        for ecu in self.ecus:
            ecu.stop()
        print("="*60 + "\n")
    
    def get_statistics(self):
        """Get statistics about message generation"""
        total_messages = sum(ecu.message_count for ecu in self.ecus)
        stats = {
            'total_ecus': len(self.ecus),
            'total_messages': total_messages,
            'ecus': [(ecu.config.name, ecu.message_count) for ecu in self.ecus]
        }
        return stats
    
    def print_statistics(self):
        """Print simulation statistics"""
        stats = self.get_statistics()
        print("\n" + "="*60)
        print("VEHICLE SIMULATION STATISTICS")
        print("="*60)
        print(f"Total ECUs: {stats['total_ecus']}")
        print(f"Total Messages Sent: {stats['total_messages']}")
        print("\nPer-ECU Breakdown:")
        for name, count in stats['ecus']:
            print(f"  {name:20s}: {count:6d} messages")
        print("="*60 + "\n")


# Example usage
if __name__ == "__main__":
    # Create virtual CAN bus
    bus = can.interface.Bus('test', bustype='virtual')
    
    # Create vehicle simulator
    vehicle = VehicleSimulator(bus)
    
    # Start simulation
    vehicle.start_all()
    
    # Run for 10 seconds
    print("Simulation running for 10 seconds...")
    time.sleep(10)
    
    # Stop simulation
    vehicle.stop_all()
    vehicle.print_statistics()