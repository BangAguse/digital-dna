"""
Test Federated Node Module

Unit tests untuk federated/node.py module
"""

import unittest
import logging
from datetime import datetime
from federated.node import (
    FederatedNode, FederatedNetwork, ZKProofStub, ConsensusType
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestZKProofStub(unittest.TestCase):
    """Test cases untuk ZKProofStub class"""
    
    def test_create_commitment(self):
        """Test commitment creation"""
        data = "test_dna_hash"
        commitment = ZKProofStub.create_commitment(data)
        
        self.assertIsNotNone(commitment)
        self.assertEqual(len(commitment), 64)  # SHA256 hex
    
    def test_create_challenge(self):
        """Test challenge creation"""
        challenge = ZKProofStub.create_challenge()
        
        self.assertIsNotNone(challenge)
        self.assertEqual(len(challenge), 32)  # 16 bytes hex
    
    def test_generate_response(self):
        """Test response generation"""
        commitment = ZKProofStub.create_commitment("test")
        challenge = ZKProofStub.create_challenge()
        response = ZKProofStub.generate_response(commitment, challenge, "test_dna")
        
        self.assertIsNotNone(response)
        self.assertEqual(len(response), 64)  # SHA256 hex
    
    def test_verify_proof(self):
        """Test proof verification"""
        commitment = ZKProofStub.create_commitment("test")
        challenge = ZKProofStub.create_challenge()
        response = ZKProofStub.generate_response(commitment, challenge, "test_dna")
        
        is_valid = ZKProofStub.verify_proof(commitment, challenge, response)
        self.assertTrue(is_valid)
    
    def test_verify_invalid_proof(self):
        """Test invalid proof verification"""
        is_valid = ZKProofStub.verify_proof("", "", "")
        self.assertFalse(is_valid)


class TestFederatedNode(unittest.TestCase):
    """Test cases untuk FederatedNode class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.node1 = FederatedNode("node_01", node_type="verifier")
        self.node2 = FederatedNode("node_02", node_type="verifier")
        
        self.mock_dna = {
            "entity_id": "test_user_001",
            "dna_hash": "a" * 64,
            "dna_signature": "b" * 64,
            "entropy_score": 0.8
        }
    
    def test_initialization(self):
        """Test FederatedNode initialization"""
        self.assertEqual(self.node1.node_id, "node_01")
        self.assertEqual(self.node1.node_type, "verifier")
        self.assertEqual(len(self.node1.peer_nodes), 0)
    
    def test_register_peer_node(self):
        """Test peer node registration"""
        self.node1.register_peer_node(self.node2)
        
        self.assertIn("node_02", self.node1.peer_nodes)
        self.assertEqual(self.node1.peer_nodes["node_02"], self.node2)
    
    def test_send_verification_request(self):
        """Test sending verification request"""
        self.node1.register_peer_node(self.node2)
        
        message = self.node1.send_verification_request(
            "node_02",
            "test_user_001",
            "a" * 64,
            self.mock_dna
        )
        
        self.assertIsNotNone(message)
        self.assertEqual(message.destination_node_id, "node_02")
        self.assertEqual(message.message_type, "VERIFICATION_REQUEST")
    
    def test_message_routing(self):
        """Test message routing between nodes"""
        self.node1.register_peer_node(self.node2)
        
        initial_messages = len(self.node2.received_messages)
        
        self.node1.send_verification_request(
            "node_02",
            "test_user_001",
            "a" * 64,
            self.mock_dna
        )
        
        self.assertEqual(len(self.node2.received_messages), initial_messages + 1)
    
    def test_create_zk_proof(self):
        """Test ZK-proof creation"""
        proof = self.node1._create_zk_proof("test_user_001", "a" * 64)
        
        self.assertIsNotNone(proof)
        self.assertEqual(proof.entity_id, "test_user_001")
        self.assertTrue(proof.is_valid)
    
    def test_consensus_majority(self):
        """Test majority consensus"""
        self.node1.register_peer_node(self.node2)
        
        consensus = self.node1.initiate_consensus(
            "test_user_001",
            "a" * 64,
            ConsensusType.MAJORITY
        )
        
        self.assertIsNotNone(consensus)
        self.assertIn("node_02", consensus.participating_nodes)
        self.assertGreaterEqual(consensus.confidence_score, 0.0)
        self.assertLessEqual(consensus.confidence_score, 1.0)
    
    def test_consensus_quorum(self):
        """Test quorum consensus"""
        self.node1.register_peer_node(self.node2)
        
        consensus = self.node1.initiate_consensus(
            "test_user_001",
            "a" * 64,
            ConsensusType.QUORUM
        )
        
        self.assertIsNotNone(consensus)
        self.assertEqual(consensus.consensus_type, ConsensusType.QUORUM.value)
    
    def test_consensus_unanimous(self):
        """Test unanimous consensus"""
        self.node1.register_peer_node(self.node2)
        
        consensus = self.node1.initiate_consensus(
            "test_user_001",
            "a" * 64,
            ConsensusType.UNANIMOUS
        )
        
        self.assertIsNotNone(consensus)
        self.assertEqual(consensus.consensus_type, ConsensusType.UNANIMOUS.value)
    
    def test_received_messages_storage(self):
        """Test received messages storage"""
        self.node1.register_peer_node(self.node2)
        
        initial_count = len(self.node2.received_messages)
        
        self.node1.send_verification_request("node_02", "user_001", "hash", self.mock_dna)
        self.node1.send_verification_request("node_02", "user_002", "hash", self.mock_dna)
        
        self.assertEqual(len(self.node2.received_messages), initial_count + 2)
    
    def test_verification_records_storage(self):
        """Test verification records storage"""
        self.node1.register_peer_node(self.node2)
        
        initial_count = len(self.node1.verification_records)
        
        self.node1.initiate_consensus("user_001", "hash_001", ConsensusType.MAJORITY)
        
        self.assertEqual(len(self.node1.verification_records), initial_count + 1)


class TestFederatedNetwork(unittest.TestCase):
    """Test cases untuk FederatedNetwork class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.network = FederatedNetwork()
    
    def test_initialization(self):
        """Test FederatedNetwork initialization"""
        self.assertEqual(len(self.network.nodes), 0)
    
    def test_add_node(self):
        """Test adding node to network"""
        node = FederatedNode("node_01")
        self.network.add_node(node)
        
        self.assertEqual(len(self.network.nodes), 1)
        self.assertIn("node_01", self.network.nodes)
    
    def test_connect_all_nodes(self):
        """Test connecting all nodes in mesh topology"""
        node1 = FederatedNode("node_01")
        node2 = FederatedNode("node_02")
        node3 = FederatedNode("node_03")
        
        self.network.add_node(node1)
        self.network.add_node(node2)
        self.network.add_node(node3)
        
        self.network.connect_all_nodes()
        
        # Each node should have 2 peers (all except itself)
        self.assertEqual(len(node1.peer_nodes), 2)
        self.assertEqual(len(node2.peer_nodes), 2)
        self.assertEqual(len(node3.peer_nodes), 2)
    
    def test_get_node(self):
        """Test getting node from network"""
        node = FederatedNode("node_01")
        self.network.add_node(node)
        
        retrieved_node = self.network.get_node("node_01")
        self.assertEqual(retrieved_node, node)
    
    def test_get_all_nodes(self):
        """Test getting all nodes"""
        node1 = FederatedNode("node_01")
        node2 = FederatedNode("node_02")
        
        self.network.add_node(node1)
        self.network.add_node(node2)
        
        all_nodes = self.network.get_all_nodes()
        self.assertEqual(len(all_nodes), 2)
        self.assertIn("node_01", all_nodes)
        self.assertIn("node_02", all_nodes)
    
    def test_mesh_network_communication(self):
        """Test mesh network communication"""
        node1 = FederatedNode("node_01")
        node2 = FederatedNode("node_02")
        
        self.network.add_node(node1)
        self.network.add_node(node2)
        self.network.connect_all_nodes()
        
        mock_dna = {
            "entity_id": "user_001",
            "dna_hash": "a" * 64,
            "dna_signature": "b" * 64
        }
        
        node1.send_verification_request("node_02", "user_001", "a" * 64, mock_dna)
        
        self.assertGreater(len(node2.received_messages), 0)


if __name__ == "__main__":
    unittest.main()
