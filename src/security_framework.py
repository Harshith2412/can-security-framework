"""
CAN Bus Security Framework - Multi-layer Detection and Prevention
"""

import can
import time
import numpy as np
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Optional, Tuple
from sklearn.ensemble import IsolationForest
import threading


@dataclass
class SecurityConfig:
    """Configuration for security framework"""
    # Rate limiting
    rate_limit_window: float = 1.0  # seconds
    max_messages_per_window: int = 1500
    
    # Domain isolation
    critical_ids: list = None  # IDs that require extra protection
    allowed_source_domains: dict = None  # Which domains can send to which IDs
    
    # ML detection
    ml_enabled: bool = False
    ml_confidence_threshold: float = 0.85
    stateful_enabled: bool = True
    
    # Logging
    log_blocked: bool = True
    log_allowed: bool = False


class MessageStatistics:
    """Track statistics for a CAN ID"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.timestamps = deque(maxlen=window_size)
        self.data_values = deque(maxlen=window_size)
        self.count = 0
        
    def add_message(self, timestamp: float, data: list):
        """Add a message to statistics"""
        self.timestamps.append(timestamp)
        self.data_values.append(tuple(data))
        self.count += 1
    
    def get_frequency(self) -> float:
        """Calculate current message frequency"""
        if len(self.timestamps) < 2:
            return 0.0
        
        time_span = self.timestamps[-1] - self.timestamps[0]
        if time_span == 0:
            return 0.0
        
        return len(self.timestamps) / time_span
    
    def get_avg_interval(self) -> float:
        """Calculate average time between messages"""
        if len(self.timestamps) < 2:
            return 0.0
        
        intervals = [self.timestamps[i] - self.timestamps[i-1] 
                    for i in range(1, len(self.timestamps))]
        return np.mean(intervals) if intervals else 0.0


class RuleBasedFilter:
    """Rule-based filtering (Layer 1)"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.message_stats = defaultdict(lambda: MessageStatistics())
        self.rate_limit_counters = defaultdict(int)
        self.rate_limit_reset_time = defaultdict(float)
        
        # Define critical system IDs (safety-critical)
        if config.critical_ids is None:
            self.critical_ids = {
                0x7E0, 0x7E1, 0x7E2,  # Powertrain
                0x760, 0x761, 0x762   # Chassis (brakes, steering, airbag)
            }
        else:
            self.critical_ids = set(config.critical_ids)
        
        # Define allowed domains
        if config.allowed_source_domains is None:
            self.allowed_domains = {
                'infotainment': {0x3C0, 0x3C1, 0x3C2, 0x3C3, 0x3C4, 0x3C5},  # Infotainment can only send these
                'body': {0x510, 0x511, 0x512, 0x513, 0x514},         # Body control
                'powertrain': {0x7E0, 0x7E1, 0x7E2},     # Powertrain
                'chassis': {0x760, 0x761, 0x762}         # Chassis
            }
        else:
            self.allowed_domains = config.allowed_source_domains
    
    def should_block(self, msg: can.Message, source_domain: str = 'unknown') -> Tuple[bool, Optional[str]]:
        """Check if message should be blocked based on rules"""
    
    # Rule 1: Domain isolation - ONLY block if infotainment tries to access CRITICAL systems
        if source_domain == 'infotainment':
            if msg.arbitration_id in self.critical_ids:
                return True, "Domain isolation: Infotainment cannot access critical systems"
        # REMOVED: Don't block infotainment from sending to its own domain
    
    # Rule 2: Rate limiting
        current_time = time.time()
        can_id = msg.arbitration_id
    
    # Reset counter if window expired
        if can_id in self.rate_limit_reset_time:
            if current_time - self.rate_limit_reset_time[can_id] > self.config.rate_limit_window:
                self.rate_limit_counters[can_id] = 0
                self.rate_limit_reset_time[can_id] = current_time
        else:
            self.rate_limit_reset_time[can_id] = current_time
    
    # Check rate limit
        self.rate_limit_counters[can_id] += 1
        if self.rate_limit_counters[can_id] > self.config.max_messages_per_window:
            return True, f"Rate limit exceeded: {self.rate_limit_counters[can_id]} msgs in {self.config.rate_limit_window}s"
    
    # Rule 3: Data validation (basic sanity checks)
        if msg.dlc > 8:
            return True, f"Invalid DLC: {msg.dlc} (max 8)"
    
    # Rule 4: Known malicious patterns - BE LESS AGGRESSIVE
    # Only block all 0xFF if it's to a CRITICAL system AND frequent
        if all(b == 0xFF for b in msg.data):
            if msg.arbitration_id in self.critical_ids:
                # Check if this is happening frequently (potential attack)
                recent_count = sum(1 for _ in range(min(10, len(list(self.message_stats[can_id].timestamps)))))
                if recent_count > 5:  # Only block if we've seen 5+ in recent history
                    return True, "Suspicious data pattern: Repeated 0xFF in critical system"
    
    # Update statistics
        self.message_stats[can_id].add_message(current_time, list(msg.data))
    
        return False, None

class MLBasedFilter:
    """ML-based anomaly detection (Layer 2)"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.model = None
        self.is_trained = False
        self.feature_history = deque(maxlen=10)  # Last 10 messages for context
        
    def train(self, normal_messages: list):
        """Train the ML model on normal traffic"""
        print("[ML FILTER] Training anomaly detection model...")
        
        # Extract features from normal messages
        features = []
        for msg in normal_messages:
            feature_vec = self._extract_features(msg)
            features.append(feature_vec)
        
        if len(features) < 10:
            print("[ML FILTER] Not enough training data")
            return False
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        X = np.array(features)
        self.model.fit(X)
        self.is_trained = True
        
        print(f"[ML FILTER] Training complete ({len(features)} samples)")
        return True
    
    def _extract_features(self, msg: can.Message) -> list:
        """Extract features from a CAN message"""
        features = [
            msg.arbitration_id,
            msg.dlc,
            np.mean(msg.data) if msg.data else 0,
            np.std(msg.data) if len(msg.data) > 1 else 0,
            np.max(msg.data) if msg.data else 0,
            np.min(msg.data) if msg.data else 0,
        ]
        
        # Add temporal features if we have history
        if len(self.feature_history) > 0:
            last_msg = self.feature_history[-1]
            features.append(abs(msg.arbitration_id - last_msg[0]))  # ID difference
        else:
            features.append(0)
        
        return features
    
    def should_block(self, msg: can.Message) -> Tuple[bool, Optional[str]]:
        """Check if message is anomalous using ML"""
        
        if not self.is_trained or not self.config.ml_enabled:
            return False, None
        
        # Extract features
        feature_vec = self._extract_features(msg)
        self.feature_history.append(feature_vec)
        
        # Predict
        X = np.array([feature_vec])
        prediction = self.model.predict(X)[0]
        score = self.model.score_samples(X)[0]
        
        # -1 = anomaly, 1 = normal
        if prediction == -1:
            confidence = abs(score)
            if confidence > self.config.ml_confidence_threshold:
                return True, f"ML detected anomaly (confidence: {confidence:.2f})"
        
        return False, None


class StatefulFilter:
    """Stateful pattern matching (Layer 3)"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.message_history = deque(maxlen=100)
        self.attack_patterns = self._load_attack_patterns()
    
    def _load_attack_patterns(self) -> list:
        """Load known attack patterns"""
        patterns = [
            {
                'name': 'DoS Flooding',
                'condition': lambda history: self._check_dos_pattern(history)
            },
            {
                'name': 'Rapid ID Switching',
                'condition': lambda history: self._check_rapid_switching(history)
            },
            {
                'name': 'Replay Attack',
                'condition': lambda history: self._check_replay_pattern(history)
            }
        ]
        return patterns
    
    def _check_dos_pattern(self, history: deque) -> bool:
        """Check for DoS flooding pattern"""
        if len(history) < 100:
            return False
    
    # Check if last 50 messages are mostly same ID
        recent = list(history)[-50:]
        id_counts = defaultdict(int)
        for msg in recent:
            id_counts[msg.arbitration_id] += 1
    
        max_count = max(id_counts.values())
    
    # CHANGED: More aggressive threshold
    # AND check if messages are coming too fast
        if max_count > 98:  # Changed from 45 to 48 (96% threshold)
        # Also verify rapid timing (DoS is FAST)
            time_span = recent[-1].timestamp - recent[0].timestamp if hasattr(recent[0], 'timestamp') else 1.0
        
        # If 50 messages in < 0.1 seconds, that's suspicious
        # Normal traffic wouldn't send 50 messages in 0.1s
            if time_span < 0.1:
                return True
    
        return False
    
    def _check_rapid_switching(self, history: deque) -> bool:
        """Check for rapid ID switching (fuzzing)"""
        if len(history) < 20:
            return False
        
        recent = list(history)[-20:]
        unique_ids = len(set(msg.arbitration_id for msg in recent))
        
        return unique_ids > 15  # Too many different IDs too quickly
    
    def _check_replay_pattern(self, history: deque) -> bool:
        """Check for replay attack pattern"""
        if len(history) < 10:
            return False
        
        recent = list(history)[-10:]
        
        # Check for exact duplicates
        for i in range(len(recent) - 1):
            duplicates = sum(1 for j in range(i+1, len(recent)) 
                           if recent[i].arbitration_id == recent[j].arbitration_id 
                           and recent[i].data == recent[j].data)
            if duplicates > 3:  # Same message repeated >3 times
                return True
        
        return False
    
    def should_block(self, msg: can.Message) -> Tuple[bool, Optional[str]]:
        """Check if message matches known attack pattern"""
        
        self.message_history.append(msg)
        
        for pattern in self.attack_patterns:
            if pattern['condition'](self.message_history):
                return True, f"Pattern detected: {pattern['name']}"
        
        return False, None
class CANSecurityFramework:
    """Complete multi-layer security framework"""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        if config is None:
            config = SecurityConfig()
        
        self.config = config
        
        # Initialize filters
        self.rule_filter = RuleBasedFilter(config)
        self.ml_filter = MLBasedFilter(config)
        self.stateful_filter = StatefulFilter(config)
        
        # Statistics
        self.total_processed = 0
        self.total_blocked = 0
        self.total_allowed = 0
        self.blocked_reasons = defaultdict(int)
        
        # Thread safety
        self.lock = threading.Lock()
        
        print("[SECURITY FRAMEWORK] Initialized")
    
    def train_ml_model(self, normal_messages: list):
        """Train the ML component"""
        return self.ml_filter.train(normal_messages)
    
    def process_message(self, msg: can.Message, source_domain: str = 'unknown') -> Tuple[bool, Optional[str]]:
        """
        Process a CAN message through all security layers
        
        Args:
            msg: CAN message to process
            source_domain: Source domain of the message ('infotainment', 'powertrain', 'chassis', 'body', 'unknown')
        
        Returns:
            Tuple of (should_allow: bool, block_reason: Optional[str])
            - should_allow: True if message should be forwarded, False if blocked
            - block_reason: Reason for blocking (None if allowed)
        """
        with self.lock:
            self.total_processed += 1
            
            # Layer 1: Rule-based filtering (fast, deterministic)
            block, reason = self.rule_filter.should_block(msg, source_domain)
            if block:
                self._handle_blocked(msg, reason, 'rule-based')
                return False, reason
            
            # Layer 2: ML-based detection (adaptive)
            if self.config.ml_enabled:
                block, reason = self.ml_filter.should_block(msg)
                if block:
                    self._handle_blocked(msg, reason, 'ml-based')
                    return False, reason
            
            # Layer 3: Stateful pattern matching
            # Check if stateful is enabled (with backward compatibility)
            stateful_enabled = getattr(self.config, 'stateful_enabled', True)
            if stateful_enabled:
                block, reason = self.stateful_filter.should_block(msg)
                if block:
                    self._handle_blocked(msg, reason, 'stateful')
                    return False, reason
            
            # All checks passed - allow message
            self._handle_allowed(msg)
            return True, None
    
    def _handle_blocked(self, msg: can.Message, reason: str, layer: str):
        """Handle a blocked message"""
        self.total_blocked += 1
        self.blocked_reasons[reason] += 1
        
        if self.config.log_blocked:
            print(f"[BLOCKED] ID: 0x{msg.arbitration_id:03X} | Layer: {layer} | Reason: {reason}")
    
    def _handle_allowed(self, msg: can.Message):
        """Handle an allowed message"""
        self.total_allowed += 1
        
        if self.config.log_allowed:
            print(f"[ALLOWED] ID: 0x{msg.arbitration_id:03X}")
    
    def get_statistics(self) -> dict:
        """Get security statistics"""
        with self.lock:
            return {
                'total_processed': self.total_processed,
                'total_blocked': self.total_blocked,
                'total_allowed': self.total_allowed,
                'block_rate': self.total_blocked / max(self.total_processed, 1),
                'blocked_reasons': dict(self.blocked_reasons)
            }
    
    def print_statistics(self):
        """Print security statistics"""
        stats = self.get_statistics()
        
        print("\n" + "="*60)
        print("SECURITY FRAMEWORK STATISTICS")
        print("="*60)
        print(f"Total Messages Processed: {stats['total_processed']:,}")
        print(f"Messages Allowed:         {stats['total_allowed']:,} ({(1-stats['block_rate'])*100:.2f}%)")
        print(f"Messages Blocked:         {stats['total_blocked']:,} ({stats['block_rate']*100:.2f}%)")
        
        if stats['blocked_reasons']:
            print("\nBlock Reasons:")
            for reason, count in sorted(stats['blocked_reasons'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {reason[:50]:50s}: {count:5d}")
        
        print("="*60 + "\n")
    
    def reset_statistics(self):
        """Reset all statistics counters"""
        with self.lock:
            self.total_processed = 0
            self.total_blocked = 0
            self.total_allowed = 0
            self.blocked_reasons.clear()
            
            # Reset filter statistics
            self.rule_filter.message_stats.clear()
            self.rule_filter.rate_limit_counters.clear()
            self.rule_filter.rate_limit_reset_time.clear()
            self.stateful_filter.message_history.clear()
            self.ml_filter.feature_history.clear()
        
        print("[SECURITY FRAMEWORK] Statistics reset")


# Example usage
if __name__ == "__main__":
    # Create security framework
    config = SecurityConfig(
        rate_limit_window=1.0,
        max_messages_per_window=500,
        ml_enabled=True,
        log_blocked=True,
        log_allowed=False
    )
    
    framework = CANSecurityFramework(config)
    
    # Simulate some messages
    test_messages = [
        can.Message(arbitration_id=0x7E0, data=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        can.Message(arbitration_id=0x760, data=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),  # Suspicious
        can.Message(arbitration_id=0x3C0, data=[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    ]
    
    for msg in test_messages:
        allowed, reason = framework.process_message(msg)
        if not allowed:
            print(f"Blocked: {reason}")
    
    framework.print_statistics()