"""
Test Local Verification Module

Unit tests untuk verification/local_verifier.py module
"""

import unittest
import logging
from datetime import datetime
from verification.local_verifier import (
    LocalVerifier, BehavioralBaseline, VerificationResult, ThreatLevel
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestLocalVerifier(unittest.TestCase):
    """Test cases untuk LocalVerifier class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.verifier = LocalVerifier("test_user_001", entity_type="user")
        self.baseline_vectors = [
            {"behavior_type": "keystroke", "value": 65.0, "metadata": {"ikt": 120}},
            {"behavior_type": "keystroke", "value": 67.5, "metadata": {"ikt": 125}},
            {"behavior_type": "cpu_usage", "value": 45.0, "metadata": {"cpu": 45}},
            {"behavior_type": "cpu_usage", "value": 46.0, "metadata": {"cpu": 46}},
            {"behavior_type": "api_call", "value": 35.0, "metadata": {"requests": 25}},
            {"behavior_type": "login_pattern", "value": 40.0, "metadata": {"hour": 14}},
        ]
        
        self.mock_dna = {
            "dna_id": "DNA_test_001",
            "dna_hash": "a" * 64,
            "dna_signature": "b" * 64,
            "entropy_score": 0.8,
            "vector_count": 6
        }
    
    def test_initialization(self):
        """Test LocalVerifier initialization"""
        self.assertEqual(self.verifier.entity_id, "test_user_001")
        self.assertEqual(self.verifier.entity_type, "user")
        self.assertIsNone(self.verifier.baseline)
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        
        self.assertIsNotNone(baseline)
        self.assertIsInstance(baseline, BehavioralBaseline)
        self.assertEqual(baseline.entity_id, "test_user_001")
        self.assertGreater(len(baseline.vector_profiles), 0)
    
    def test_baseline_statistics(self):
        """Test baseline statistics calculation"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        
        for behavior_type, profile in baseline.vector_profiles.items():
            self.assertIn("mean", profile)
            self.assertIn("std_dev", profile)
            self.assertIn("variance", profile)
            self.assertGreater(profile["mean"], 0)
    
    def test_verify_dna_format(self):
        """Test DNA format verification"""
        is_valid, reason = self.verifier._verify_dna_format(self.mock_dna)
        self.assertTrue(is_valid)
        
        # Invalid DNA
        invalid_dna = {"dna_hash": "short"}
        is_valid, reason = self.verifier._verify_dna_format(invalid_dna)
        self.assertFalse(is_valid)
    
    def test_detect_behavioral_anomalies(self):
        """Test anomaly detection"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        
        current_vectors = [
            {"behavior_type": "keystroke", "value": 150.0}  # High deviation
        ]
        
        anomalies = self.verifier._detect_behavioral_anomalies(current_vectors)
        self.assertGreater(len(anomalies), 0)
    
    def test_spoofing_detection(self):
        """Test spoofing detection"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        
        vectors_with_spoofing = [
            {"behavior_type": "keystroke", "value": 20.0, "metadata": {"ikt": 50}},
            {"behavior_type": "keystroke", "value": 80.0, "metadata": {"ikt": 150}},
        ]
        
        risk = self.verifier._detect_spoofing(vectors_with_spoofing)
        self.assertGreaterEqual(risk, 0.0)
        self.assertLessEqual(risk, 1.0)
    
    def test_insider_threat_detection(self):
        """Test insider threat detection"""
        vectors_with_threat = [
            {
                "behavior_type": "file_access",
                "value": 90.0,
                "metadata": {"files_accessed_count": 300}  # High threshold
            }
        ]
        
        risk = self.verifier._detect_insider_threat(vectors_with_threat)
        self.assertGreater(risk, 0)
    
    def test_credential_theft_detection(self):
        """Test credential theft detection"""
        vectors_with_theft = [
            {
                "behavior_type": "api_call",
                "value": 80.0,
                "metadata": {"request_count": 600}  # High frequency
            }
        ]
        
        risk = self.verifier._detect_credential_theft(vectors_with_theft)
        self.assertGreater(risk, 0)
    
    def test_behavioral_drift_detection(self):
        """Test behavioral drift detection"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        
        drifted_vectors = [
            {"behavior_type": "keystroke", "value": 100.0}  # Different from baseline mean of ~66
        ]
        
        drift = self.verifier._detect_behavioral_drift(drifted_vectors)
        self.assertGreaterEqual(drift, 0.0)
        self.assertLessEqual(drift, 1.0)
    
    def test_verify_dna(self):
        """Test full DNA verification"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        
        current_vectors = [
            {"behavior_type": "keystroke", "value": 65.0}
        ]
        
        result = self.verifier.verify_dna(self.mock_dna, current_vectors)
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, VerificationResult)
        self.assertGreaterEqual(result.confidence_score, 0.0)
        self.assertLessEqual(result.confidence_score, 1.0)
    
    def test_verification_history(self):
        """Test verification history tracking"""
        baseline = self.verifier.establish_baseline(self.baseline_vectors)
        current_vectors = [{"behavior_type": "keystroke", "value": 65.0}]
        
        result1 = self.verifier.verify_dna(self.mock_dna, current_vectors)
        self.assertEqual(len(self.verifier.verification_history), 1)
        
        result2 = self.verifier.verify_dna(self.mock_dna, current_vectors)
        self.assertEqual(len(self.verifier.verification_history), 2)
    
    def test_threat_level_calculation(self):
        """Test threat level calculation"""
        threat_level = self.verifier._calculate_threat_level([], 0.95)
        self.assertEqual(threat_level, ThreatLevel.SAFE)
        
        threat_level = self.verifier._calculate_threat_level(["SPOOFING"], 0.5)
        self.assertGreaterEqual(threat_level.value, ThreatLevel.MEDIUM.value)
        
        threat_level = self.verifier._calculate_threat_level(
            ["SPOOFING", "INSIDER_THREAT", "CREDENTIAL_THEFT"],
            0.2
        )
        self.assertEqual(threat_level, ThreatLevel.CRITICAL)
    
    def test_recommendations_generation(self):
        """Test recommendations generation"""
        threats = ["SPOOFING_DETECTED"]
        threat_level = ThreatLevel.HIGH
        
        recommendations = self.verifier._generate_recommendations(threats, threat_level)
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("verify" in r.lower() for r in recommendations))


if __name__ == "__main__":
    unittest.main()
