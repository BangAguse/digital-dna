"""
Test Agent Module

Unit tests untuk agent/agent.py module
"""

import unittest
import logging
from datetime import datetime
from agent.agent import (
    BehavioralCapture, BehaviorType, AnomalyLevel, 
    generate_mock_entities
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestBehavioralCapture(unittest.TestCase):
    """Test cases untuk BehavioralCapture class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.agent = BehavioralCapture("test_user_001", entity_type="user")
    
    def test_initialization(self):
        """Test BehavioralCapture initialization"""
        self.assertEqual(self.agent.entity_id, "test_user_001")
        self.assertEqual(self.agent.entity_type, "user")
        self.assertEqual(len(self.agent.vectors), 0)
    
    def test_capture_keystroke_dynamics(self):
        """Test keystroke dynamics capture"""
        vector = self.agent.capture_keystroke_dynamics()
        
        self.assertIsNotNone(vector)
        self.assertEqual(vector.behavior_type, BehaviorType.KEYSTROKE.value)
        self.assertGreater(vector.value, 0)
        self.assertIn("inter_keystroke_time_ms", vector.metadata)
        self.assertIn("dwell_time_ms", vector.metadata)
    
    def test_capture_cpu_memory_usage(self):
        """Test CPU/memory usage capture"""
        vector = self.agent.capture_cpu_memory_usage()
        
        self.assertIsNotNone(vector)
        self.assertEqual(vector.behavior_type, BehaviorType.CPU_USAGE.value)
        self.assertGreater(vector.value, 0)
        self.assertIn("cpu_percent", vector.metadata)
        self.assertIn("memory_percent", vector.metadata)
    
    def test_capture_api_calls(self):
        """Test API calls capture"""
        vector = self.agent.capture_api_calls()
        
        self.assertIsNotNone(vector)
        self.assertEqual(vector.behavior_type, BehaviorType.API_CALL.value)
        self.assertGreater(vector.value, 0)
        self.assertIn("request_count", vector.metadata)
        self.assertIn("endpoints", vector.metadata)
    
    def test_capture_network_patterns(self):
        """Test network patterns capture"""
        vector = self.agent.capture_network_patterns()
        
        self.assertIsNotNone(vector)
        self.assertEqual(vector.behavior_type, BehaviorType.NETWORK_PATTERN.value)
        self.assertGreater(vector.value, 0)
        self.assertIn("source_ip", vector.metadata)
        self.assertIn("data_transfer_mb", vector.metadata)
    
    def test_capture_login_patterns(self):
        """Test login patterns capture"""
        vector = self.agent.capture_login_patterns()
        
        self.assertIsNotNone(vector)
        self.assertEqual(vector.behavior_type, BehaviorType.LOGIN_PATTERN.value)
        self.assertGreater(vector.value, 0)
        self.assertIn("login_hour", vector.metadata)
        self.assertIn("device_fingerprint", vector.metadata)
    
    def test_capture_file_access_patterns(self):
        """Test file access patterns capture"""
        vector = self.agent.capture_file_access_patterns()
        
        self.assertIsNotNone(vector)
        self.assertEqual(vector.behavior_type, BehaviorType.FILE_ACCESS.value)
        self.assertGreater(vector.value, 0)
        self.assertIn("files_accessed_count", vector.metadata)
        self.assertIn("read_operations", vector.metadata)
    
    def test_vector_storage(self):
        """Test vector storage"""
        initial_count = len(self.agent.vectors)
        
        self.agent.capture_keystroke_dynamics()
        self.agent.capture_cpu_memory_usage()
        
        self.assertEqual(len(self.agent.vectors), initial_count + 2)
    
    def test_get_vectors_as_dict(self):
        """Test getting vectors as dictionary"""
        self.agent.capture_keystroke_dynamics()
        vectors_dict = self.agent.get_vectors_as_dict()
        
        self.assertEqual(len(vectors_dict), 1)
        self.assertIn("vector_id", vectors_dict[0])
        self.assertIn("behavior_type", vectors_dict[0])
    
    def test_clear_vectors(self):
        """Test clearing vectors"""
        self.agent.capture_keystroke_dynamics()
        self.agent.capture_cpu_memory_usage()
        
        self.assertGreater(len(self.agent.vectors), 0)
        
        self.agent.clear_vectors()
        self.assertEqual(len(self.agent.vectors), 0)
    
    def test_generate_mock_profile(self):
        """Test generating mock behavioral profile"""
        profile = self.agent.generate_mock_profile()
        
        self.assertIn("entity_id", profile)
        self.assertIn("entity_type", profile)
        self.assertIn("vectors", profile)
        self.assertEqual(len(profile["vectors"]), 6)  # All 6 behavior types
    
    def test_anomaly_detection(self):
        """Test anomaly detection in vectors"""
        self.agent.capture_keystroke_dynamics()
        vector = self.agent.vectors[0]
        
        self.assertIn(vector.anomaly_level, ["NORMAL", "SUSPICIOUS", "CRITICAL"])
    
    def test_mock_entities_generation(self):
        """Test generating mock entities"""
        entities = generate_mock_entities()
        
        self.assertGreater(len(entities), 0)
        self.assertIn("user_alice", entities)
        self.assertIsInstance(entities["user_alice"], BehavioralCapture)


if __name__ == "__main__":
    unittest.main()
