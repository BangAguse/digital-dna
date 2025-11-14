"""
Test DNA Generator Module

Unit tests untuk generator/dna_generator.py module
"""

import unittest
import logging
from datetime import datetime, timedelta
from generator.dna_generator import (
    DNAGenerator, DigitalDNA, DNAAlgorithm, DNAFactory
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestDNAGenerator(unittest.TestCase):
    """Test cases untuk DNAGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.generator = DNAGenerator("test_user_001", entity_type="user")
        self.mock_vectors = [
            {
                "behavior_type": "keystroke",
                "value": 65.5,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": {"ikt": 120}
            },
            {
                "behavior_type": "cpu_usage",
                "value": 45.3,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": {"cpu": 45}
            },
            {
                "behavior_type": "api_call",
                "value": 32.1,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": {"requests": 25}
            }
        ]
    
    def test_initialization(self):
        """Test DNAGenerator initialization"""
        self.assertEqual(self.generator.entity_id, "test_user_001")
        self.assertEqual(self.generator.entity_type, "user")
        self.assertEqual(len(self.generator.dna_history), 0)
    
    def test_normalize_vectors(self):
        """Test vector normalization"""
        normalized = self.generator._normalize_vectors(self.mock_vectors)
        
        self.assertEqual(len(normalized), len(self.mock_vectors))
        for vector in normalized:
            self.assertIn("normalized_value", vector)
            self.assertGreaterEqual(vector["normalized_value"], 0)
            self.assertLessEqual(vector["normalized_value"], 1)
    
    def test_calculate_entropy(self):
        """Test entropy calculation"""
        normalized = self.generator._normalize_vectors(self.mock_vectors)
        entropy = self.generator._calculate_entropy(normalized)
        
        self.assertGreaterEqual(entropy, 0.0)
        self.assertLessEqual(entropy, 1.0)
    
    def test_create_composite_hash(self):
        """Test composite hash creation"""
        normalized = self.generator._normalize_vectors(self.mock_vectors)
        hash_value = self.generator._create_composite_hash(
            normalized,
            DNAAlgorithm.SHA256_COMPOSITE
        )
        
        self.assertIsNotNone(hash_value)
        self.assertEqual(len(hash_value), 64)  # SHA256 hex length
        self.assertTrue(all(c in '0123456789abcdef' for c in hash_value))
    
    def test_generate_dna(self):
        """Test DNA generation"""
        dna = self.generator.generate_dna(self.mock_vectors)
        
        self.assertIsNotNone(dna)
        self.assertIsInstance(dna, DigitalDNA)
        self.assertEqual(dna.entity_id, "test_user_001")
        self.assertTrue(dna.is_valid)
        self.assertGreater(dna.entropy_score, 0)
        self.assertEqual(len(dna.dna_hash), 64)
    
    def test_dna_expiration(self):
        """Test DNA expiration timestamp"""
        dna = self.generator.generate_dna(self.mock_vectors)
        
        expiration = datetime.fromisoformat(dna.expiration_timestamp)
        now = datetime.utcnow()
        
        self.assertGreater(expiration, now)
        self.assertLess((expiration - now).days, 31)
    
    def test_dna_validity_check(self):
        """Test DNA validity verification"""
        dna = self.generator.generate_dna(self.mock_vectors)
        is_valid, reason = self.generator.verify_dna_validity(dna)
        
        self.assertTrue(is_valid)
    
    def test_dna_expiration_validity(self):
        """Test expired DNA validity"""
        dna = self.generator.generate_dna(self.mock_vectors)
        dna.expiration_timestamp = (datetime.utcnow() - timedelta(days=1)).isoformat()
        
        is_valid, reason = self.generator.verify_dna_validity(dna)
        self.assertFalse(is_valid)
        self.assertIn("expired", reason.lower())
    
    def test_dna_history(self):
        """Test DNA history tracking"""
        initial_count = len(self.generator.dna_history)
        
        self.generator.generate_dna(self.mock_vectors)
        self.assertEqual(len(self.generator.dna_history), initial_count + 1)
        
        self.generator.generate_dna(self.mock_vectors)
        self.assertEqual(len(self.generator.dna_history), initial_count + 2)
    
    def test_dna_rotation(self):
        """Test DNA rotation"""
        dna_1 = self.generator.generate_dna(self.mock_vectors)
        initial_valid = dna_1.is_valid
        
        dna_2 = self.generator.rotate_dna(self.mock_vectors)
        
        self.assertFalse(dna_1.is_valid)  # Old DNA invalidated
        self.assertTrue(dna_2.is_valid)
        self.assertNotEqual(dna_1.dna_id, dna_2.dna_id)
    
    def test_dna_similarity(self):
        """Test DNA similarity comparison"""
        dna_1 = self.generator.generate_dna(self.mock_vectors)
        dna_2 = self.generator.generate_dna(self.mock_vectors)
        
        similarity = self.generator.compare_dna_similarity(dna_1, dna_2)
        
        self.assertGreaterEqual(similarity, 0.0)
        self.assertLessEqual(similarity, 1.0)
    
    def test_different_algorithms(self):
        """Test DNA generation with different algorithms"""
        dna_sha256 = self.generator.generate_dna(
            self.mock_vectors,
            DNAAlgorithm.SHA256_COMPOSITE
        )
        self.assertEqual(dna_sha256.algorithm, DNAAlgorithm.SHA256_COMPOSITE.value)
        
        dna_sha512 = self.generator.generate_dna(
            self.mock_vectors,
            DNAAlgorithm.SHA512_COMPOSITE
        )
        self.assertEqual(dna_sha512.algorithm, DNAAlgorithm.SHA512_COMPOSITE.value)
    
    def test_empty_vectors(self):
        """Test DNA generation with empty vectors"""
        dna = self.generator.generate_dna([])
        
        self.assertIsNotNone(dna)
        self.assertEqual(dna.vector_count, 0)


class TestDNAFactory(unittest.TestCase):
    """Test cases untuk DNAFactory class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.factory = DNAFactory()
    
    def test_create_generator(self):
        """Test creating generator through factory"""
        generator = self.factory.create_generator("test_user_001")
        
        self.assertIsNotNone(generator)
        self.assertEqual(generator.entity_id, "test_user_001")
    
    def test_generator_caching(self):
        """Test generator caching in factory"""
        generator1 = self.factory.create_generator("test_user_001")
        generator2 = self.factory.create_generator("test_user_001")
        
        self.assertIs(generator1, generator2)
    
    def test_multiple_generators(self):
        """Test factory with multiple generators"""
        gen1 = self.factory.create_generator("user_001")
        gen2 = self.factory.create_generator("user_002")
        
        self.assertNotEqual(gen1.entity_id, gen2.entity_id)
        self.assertEqual(len(self.factory.get_all_generators()), 2)


if __name__ == "__main__":
    unittest.main()
