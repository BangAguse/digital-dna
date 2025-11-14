"""
Digital DNA - Verification Module
"""

from verification.local_verifier import (
    LocalVerifier,
    VerificationResult,
    BehavioralBaseline,
    ThreatLevel,
    ThreatType
)

__all__ = [
    'LocalVerifier',
    'VerificationResult',
    'BehavioralBaseline',
    'ThreatLevel',
    'ThreatType'
]

__version__ = '0.1.0'
