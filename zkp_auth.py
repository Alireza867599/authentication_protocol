"""
Zero Knowledge Proof Authentication Protocol Implementation

This module demonstrates a Schnorr-based Zero Knowledge Proof authentication system.
The protocol allows a prover to demonstrate knowledge of a secret without revealing it.
"""

import hashlib
import random
from typing import Tuple, Optional


class ZKPAuth:
    """
    Zero Knowledge Proof Authentication System based on Schnorr's protocol
    """
    
    def __init__(self, prime: int, generator: int, secret: Optional[int] = None):
        """
        Initialize ZKP Authentication
        
        Args:
            prime: A large prime number for the finite field
            generator: Generator for the subgroup
            secret: Secret value (private key), if not provided, it will be generated
        """
        self.prime = prime
        self.generator = generator
        self.secret = secret or random.randint(1, prime - 2)
        self.public_key = pow(generator, self.secret, prime)
        
    def generate_public_key(self) -> int:
        """Generate public key based on secret"""
        return pow(self.generator, self.secret, self.prime)
    
    def prove_knowledge(self) -> Tuple[int, int, int]:
        """
        Prover generates proof of knowledge of secret
        
        Returns:
            Tuple of (commitment, challenge_response, random_value)
        """
        # Generate random value
        r = random.randint(1, self.prime - 2)
        
        # Commitment: g^r mod p
        commitment = pow(self.generator, r, self.prime)
        
        # Create challenge by hashing commitment and public key
        challenge_input = f"{commitment}{self.public_key}".encode()
        challenge = int(hashlib.sha256(challenge_input).hexdigest(), 16) % (self.prime - 1)
        
        # Response: r + secret * challenge mod (p-1)
        response = (r + self.secret * challenge) % (self.prime - 1)
        
        return commitment, response, challenge
    
    def verify_proof(self, commitment: int, response: int, challenge: int, public_key: int) -> bool:
        """
        Verify the zero knowledge proof
        
        Args:
            commitment: The commitment value from prover
            response: The response value from prover
            challenge: The challenge value
            public_key: Public key of the prover
            
        Returns:
            True if proof is valid, False otherwise
        """
        # Calculate g^response mod p
        left_side = pow(self.generator, response, self.prime)
        
        # Calculate commitment * public_key^challenge mod p
        right_side = (commitment * pow(public_key, challenge, self.prime)) % self.prime
        
        # The proof is valid if both sides are equal
        return left_side == right_side
    
    def authenticate(self) -> bool:
        """
        Perform complete authentication protocol
        
        Returns:
            True if authentication successful, False otherwise
        """
        commitment, response, challenge = self.prove_knowledge()
        return self.verify_proof(commitment, response, challenge, self.public_key)


def demonstrate_zkp_auth():
    """Demonstrate the ZKP authentication protocol"""
    print("=== Zero Knowledge Proof Authentication Demo ===\n")
    
    # Use a safe prime (commonly used in cryptographic applications)
    # This is a 256-bit safe prime
    SAFE_PRIME = 115792089237316195423570985008687907853269984665640564039457584007913129639747
    GENERATOR = 2
    
    # Create prover with secret
    prover = ZKPAuth(SAFE_PRIME, GENERATOR)
    print(f"Prover's secret: {prover.secret}")
    print(f"Prover's public key: {prover.public_key}\n")
    
    # Create verifier (same prime and generator, but doesn't know secret)
    verifier = ZKPAuth(SAFE_PRIME, GENERATOR, secret=42)  # Different secret for verifier
    
    # Prover generates proof
    commitment, response, challenge = prover.prove_knowledge()
    print(f"Commitment (g^r mod p): {commitment}")
    print(f"Challenge: {challenge}")
    print(f"Response: {response}\n")
    
    # Verifier checks the proof
    is_valid = verifier.verify_proof(commitment, response, challenge, prover.public_key)
    print(f"Proof verification result: {is_valid}")
    
    if is_valid:
        print("✓ Authentication successful - prover demonstrated knowledge of secret!")
    else:
        print("✗ Authentication failed - proof not valid")
    
    print("\n=== Security Note ===")
    print("The verifier learns nothing about the prover's secret,")
    print("but is convinced that the prover knows it.")


if __name__ == "__main__":
    demonstrate_zkp_auth()