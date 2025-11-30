"""
Man-in-the-Middle Attack on Zero Knowledge Proof Authentication

This module demonstrates how a Man-in-the-Middle attack could potentially
compromise a Zero Knowledge Proof authentication system if not properly secured.
"""

import hashlib
import random
from typing import Tuple, Optional
from zkp_auth import ZKPAuth


class MaliciousProver:
    """
    A malicious prover that tries to fool the verifier by intercepting communication
    """
    
    def __init__(self, prime: int, generator: int):
        self.prime = prime
        self.generator = generator
        # Malicious prover doesn't know the real secret but tries to impersonate
        self.fake_secret = random.randint(1, prime - 2)
        self.fake_public_key = pow(generator, self.fake_secret, prime)
    
    def attempt_impersonation(self, original_public_key: int) -> Tuple[int, int, int]:
        """
        Attempt to impersonate the real prover by intercepting and modifying the protocol
        
        Args:
            original_public_key: The real prover's public key
            
        Returns:
            Tuple of (commitment, response, challenge) - potentially fraudulent
        """
        # Generate a random commitment
        fake_r = random.randint(1, self.prime - 2)
        fake_commitment = pow(self.generator, fake_r, self.prime)
        
        # The malicious prover tries to guess or manipulate the challenge
        # In a real MITM, they would intercept the communication
        challenge_input = f"{fake_commitment}{original_public_key}".encode()
        challenge = int(hashlib.sha256(challenge_input).hexdigest(), 16) % (self.prime - 1)
        
        # Since malicious prover doesn't know the real secret, they can't compute a valid response
        # They might try to guess or use their own fake secret
        fake_response = (fake_r + self.fake_secret * challenge) % (self.prime - 1)
        
        return fake_commitment, fake_response, challenge


class ManInTheMiddle:
    """
    Demonstrates a Man-in-the-Middle attack on the ZKP protocol
    """
    
    def __init__(self, prime: int, generator: int):
        self.prime = prime
        self.generator = generator
        # Attacker creates their own ZKP system to intercept communications
        self.malicious_auth = ZKPAuth(prime, generator)
    
    def intercept_authentication(self, real_prover: ZKPAuth, verifier: ZKPAuth) -> bool:
        """
        Simulate a Man-in-the-Middle attack on the authentication process
        
        Args:
            real_prover: The legitimate prover
            verifier: The legitimate verifier
            
        Returns:
            True if attack succeeds (which it shouldn't with proper protocol), False otherwise
        """
        print("=== Man-in-the-Middle Attack Simulation ===\n")
        
        # In a real MITM attack, the attacker would intercept the communication
        # between prover and verifier, but for this demo we'll simulate the interception
        
        print("Real prover generates proof...")
        commitment, response, challenge = real_prover.prove_knowledge()
        print(f"Original commitment: {commitment}")
        print(f"Original challenge: {challenge}")
        print(f"Original response: {response}")
        
        # The MITM attacker tries to modify the communication
        # In a real scenario, they would intercept and potentially modify the values
        print(f"\nMITM intercepts communication...")
        print(f"MITM doesn't know real prover's secret: {real_prover.secret}")
        
        # The attacker tries to create a different proof
        fake_r = random.randint(1, self.prime - 2)
        fake_commitment = pow(self.generator, fake_r, self.prime)
        fake_challenge_input = f"{fake_commitment}{real_prover.public_key}".encode()
        fake_challenge = int(hashlib.sha256(fake_challenge_input).hexdigest(), 16) % (self.prime - 1)
        fake_response = (fake_r + self.malicious_auth.secret * fake_challenge) % (self.prime - 1)
        
        print(f"MITM sends fake commitment: {fake_commitment}")
        print(f"MITM sends fake response: {fake_response}")
        print(f"MITM uses fake challenge: {fake_challenge}")
        
        # Verifier tries to validate the potentially intercepted/faked proof
        is_valid = verifier.verify_proof(fake_commitment, fake_response, fake_challenge, real_prover.public_key)
        print(f"\nVerification result with fake data: {is_valid}")
        
        if is_valid:
            print("✗ ATTACK SUCCESSFUL - MITM fooled the verifier!")
            return True
        else:
            print("✓ ATTACK FAILED - Verifier detected fraudulent proof")
            return False


def demonstrate_mitm_attack():
    """Demonstrate the Man-in-the-Middle attack on ZKP authentication"""
    print("=== Man-in-the-Middle Attack on ZKP Authentication ===\n")
    
    # Use a safe prime (commonly used in cryptographic applications)
    SAFE_PRIME = 115792089237316195423570985008687907853269984665640564039457584007913129639747
    GENERATOR = 2
    
    # Create legitimate prover and verifier
    real_prover = ZKPAuth(SAFE_PRIME, GENERATOR)
    verifier = ZKPAuth(SAFE_PRIME, GENERATOR, secret=42)  # Verifier doesn't know prover's secret
    
    print(f"Real prover's secret: {real_prover.secret}")
    print(f"Real prover's public key: {real_prover.public_key}\n")
    
    # Create MITM attacker
    mitm = ManInTheMiddle(SAFE_PRIME, GENERATOR)
    
    # Attempt the MITM attack
    attack_successful = mitm.intercept_authentication(real_prover, verifier)
    
    print(f"\n=== Attack Result ===")
    if attack_successful:
        print("The MITM attack succeeded - this shows why additional security measures are needed!")
    else:
        print("The MITM attack failed - the ZKP protocol is secure against this type of attack!")
    
    print("\n=== Security Notes ===")
    print("1. Proper ZKP implementations include additional security measures")
    print("2. Secure channel establishment (like TLS) prevents MITM attacks")
    print("3. Certificate authorities verify identities in real systems")
    print("4. This demo shows why authentication protocols need multiple security layers")


def demonstrate_zkp_security():
    """Demonstrate that basic ZKP is resistant to simple MITM attacks"""
    print("\n=== ZKP Protocol Security Analysis ===\n")
    
    SAFE_PRIME = 115792089237316195423570985008687907853269984665640564039457584007913129639747
    GENERATOR = 2
    
    # Create prover and verifier
    prover = ZKPAuth(SAFE_PRIME, GENERATOR)
    verifier = ZKPAuth(SAFE_PRIME, GENERATOR, secret=42)
    
    print("Testing ZKP resistance to simple impersonation attacks...")
    
    # An attacker who doesn't know the secret tries to create a valid proof
    # This should fail because they can't satisfy the equation g^response = commitment * public_key^challenge
    fake_secret = random.randint(1, SAFE_PRIME - 2)
    fake_public_key = pow(GENERATOR, fake_secret, SAFE_PRIME)
    
    # Generate fake proof
    fake_r = random.randint(1, SAFE_PRIME - 2)
    fake_commitment = pow(GENERATOR, fake_r, SAFE_PRIME)
    challenge_input = f"{fake_commitment}{fake_public_key}".encode()
    challenge = int(hashlib.sha256(challenge_input).hexdigest(), 16) % (SAFE_PRIME - 1)
    # The attacker doesn't know the real secret, so they can't create a valid response
    fake_response = (fake_r + fake_secret * challenge) % (SAFE_PRIME - 1)
    
    # Try to verify with the real prover's public key (this should fail)
    is_valid = verifier.verify_proof(fake_commitment, fake_response, challenge, prover.public_key)
    print(f"Can fake prover impersonate real prover? {is_valid}")
    
    # Try to verify with fake prover's own public key (this should work, but not against real prover)
    is_valid_own = verifier.verify_proof(fake_commitment, fake_response, challenge, fake_public_key)
    print(f"Can fake prover prove knowledge of their own (fake) secret? {is_valid_own}")
    
    print("\nThis demonstrates that ZKP protocols are inherently secure against")
    print("simple impersonation attacks when implemented correctly.")


if __name__ == "__main__":
    demonstrate_mitm_attack()
    demonstrate_zkp_security()