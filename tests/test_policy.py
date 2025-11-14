"""
Test Policy Engine Module

Unit tests untuk policy/access_control.py module
"""

import unittest
import logging
from datetime import datetime
from policy.access_control import (
    PolicyEngine, AccessDecision, PolicyRuleType, AccessControlDecision
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestPolicyEngine(unittest.TestCase):
    """Test cases untuk PolicyEngine class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = PolicyEngine()
        
        self.mock_verification_safe = {
            "is_valid": True,
            "confidence_score": 0.95,
            "threat_level": "SAFE",
            "detected_threats": [],
            "verification_id": "VER_001"
        }
        
        self.mock_verification_suspicious = {
            "is_valid": True,
            "confidence_score": 0.75,
            "threat_level": "MEDIUM",
            "detected_threats": [],
            "verification_id": "VER_002"
        }
        
        self.mock_verification_critical = {
            "is_valid": False,
            "confidence_score": 0.2,
            "threat_level": "CRITICAL",
            "detected_threats": ["SPOOFING_DETECTED", "INSIDER_THREAT_DETECTED"],
            "verification_id": "VER_003"
        }
    
    def test_initialization(self):
        """Test PolicyEngine initialization"""
        self.assertGreater(len(self.engine.rules), 0)
        self.assertEqual(len(self.engine.decisions_history), 0)
    
    def test_add_rule(self):
        """Test adding custom rule"""
        initial_count = len(self.engine.rules)
        
        self.engine.add_rule(
            rule_name="Test Rule",
            rule_type=PolicyRuleType.CUSTOM,
            conditions={"test_condition": True},
            actions=["allow"],
            priority=5
        )
        
        self.assertEqual(len(self.engine.rules), initial_count + 1)
    
    def test_safe_access_decision(self):
        """Test safe/high confidence access decision"""
        decision = self.engine.evaluate_access("user_001", self.mock_verification_safe)
        
        self.assertEqual(decision.decision, AccessDecision.ALLOW.value)
        self.assertGreater(decision.confidence_score, 0.9)
    
    def test_suspicious_access_decision(self):
        """Test suspicious/medium confidence access decision"""
        decision = self.engine.evaluate_access("user_002", self.mock_verification_suspicious)
        
        self.assertEqual(decision.decision, AccessDecision.CHALLENGE.value)
        self.assertGreater(decision.confidence_score, 0.6)
    
    def test_critical_access_decision(self):
        """Test critical threat access decision"""
        decision = self.engine.evaluate_access("user_003", self.mock_verification_critical)
        
        self.assertIn(decision.decision, [AccessDecision.QUARANTINE.value, AccessDecision.DENY.value])
        self.assertLess(decision.confidence_score, 0.5)
    
    def test_decision_audit_trail(self):
        """Test decision audit trail"""
        initial_count = len(self.engine.decisions_history)
        
        self.engine.evaluate_access("user_001", self.mock_verification_safe)
        self.engine.evaluate_access("user_002", self.mock_verification_suspicious)
        
        self.assertEqual(len(self.engine.decisions_history), initial_count + 2)
    
    def test_rule_matching(self):
        """Test rule matching logic"""
        matching_rules = self.engine._find_matching_rules(
            is_valid=True,
            confidence_score=0.95,
            threat_level="SAFE",
            detected_threats=[]
        )
        
        self.assertGreater(len(matching_rules), 0)
    
    def test_enable_disable_rule(self):
        """Test enabling/disabling rules"""
        rule = self.engine.get_all_rules()[0]
        rule_id = rule.rule_id
        
        self.engine.disable_rule(rule_id)
        self.assertFalse(self.engine.rules[rule_id].is_enabled)
        
        self.engine.enable_rule(rule_id)
        self.assertTrue(self.engine.rules[rule_id].is_enabled)
    
    def test_override_decision(self):
        """Test decision override"""
        decision = self.engine.evaluate_access("user_001", self.mock_verification_suspicious)
        original_decision = decision.decision
        
        self.engine.override_decision(
            decision.decision_id,
            AccessDecision.ALLOW,
            "Admin override for testing"
        )
        
        # Verify override was recorded
        overridden_decision = self.engine.decisions_history[-1]
        self.assertIn("override", overridden_decision.decision_details)
    
    def test_challenge_method_assignment(self):
        """Test challenge method assignment"""
        decision = self.engine.evaluate_access("user_002", self.mock_verification_suspicious)
        
        if decision.decision == AccessDecision.CHALLENGE.value:
            self.assertIsNotNone(decision.challenge_method)
    
    def test_quarantine_reason_assignment(self):
        """Test quarantine reason assignment"""
        decision = self.engine.evaluate_access("user_003", self.mock_verification_critical)
        
        if decision.decision == AccessDecision.QUARANTINE.value:
            self.assertIsNotNone(decision.quarantine_reason)
    
    def test_with_consensus_result(self):
        """Test access evaluation with federated consensus"""
        consensus_result = {
            "confidence_score": 0.85,
            "consensus_reached": True
        }
        
        decision = self.engine.evaluate_access(
            "user_001",
            self.mock_verification_safe,
            consensus_result
        )
        
        self.assertEqual(decision.decision, AccessDecision.ALLOW.value)
        self.assertGreater(decision.confidence_score, 0.85)
    
    def test_decision_statistics(self):
        """Test decision statistics"""
        self.engine.evaluate_access("user_001", self.mock_verification_safe)
        self.engine.evaluate_access("user_002", self.mock_verification_suspicious)
        self.engine.evaluate_access("user_003", self.mock_verification_critical)
        
        stats = self.engine.get_decision_statistics()
        
        self.assertIn("total_decisions", stats)
        self.assertEqual(stats["total_decisions"], 3)
        self.assertIn("decisions_by_type", stats)
        self.assertGreater(stats["avg_confidence"], 0)
    
    def test_get_all_rules(self):
        """Test getting all rules"""
        rules = self.engine.get_all_rules()
        
        self.assertGreater(len(rules), 0)
        for rule in rules:
            self.assertIsNotNone(rule.rule_id)
            self.assertIsNotNone(rule.rule_name)
    
    def test_confidence_combination(self):
        """Test confidence score combination with consensus"""
        verification_result = {
            "is_valid": True,
            "confidence_score": 0.7,
            "threat_level": "LOW",
            "detected_threats": []
        }
        
        consensus_result = {
            "confidence_score": 0.9,
            "consensus_reached": True
        }
        
        decision = self.engine.evaluate_access(
            "user_001",
            verification_result,
            consensus_result
        )
        
        # Combined confidence should be average of local and federated
        expected_confidence = (0.7 + 0.9) / 2
        self.assertAlmostEqual(decision.confidence_score, expected_confidence, places=1)
    
    def test_multiple_threats_decision(self):
        """Test decision with multiple threats"""
        verification_with_threats = {
            "is_valid": False,
            "confidence_score": 0.3,
            "threat_level": "HIGH",
            "detected_threats": ["SPOOFING_DETECTED", "INSIDER_THREAT_DETECTED"],
            "verification_id": "VER_MULTI"
        }
        
        decision = self.engine.evaluate_access("user_multi", verification_with_threats)
        
        self.assertNotEqual(decision.decision, AccessDecision.ALLOW.value)
        self.assertGreater(len(decision.decision_details["verification_result"]["detected_threats"]), 1)


if __name__ == "__main__":
    unittest.main()
