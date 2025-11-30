"""
Main script to demonstrate Zero Knowledge Proof authentication and Man-in-the-Middle attacks
"""

from zkp_auth import demonstrate_zkp_auth
from mitm_attack import demonstrate_mitm_attack, demonstrate_zkp_security


def main():
    """Run all demonstrations"""
    print("# Zero Knowledge Proof Authentication and Security Analysis")
    print("=" * 60)
    
    # First demonstrate the proper ZKP authentication
    demonstrate_zkp_auth()
    
    print("\n" + "=" * 60)
    
    # Then demonstrate the MITM attack
    demonstrate_mitm_attack()
    
    print("\n" + "=" * 60)
    
    # Finally demonstrate ZKP security properties
    demonstrate_zkp_security()


if __name__ == "__main__":
    main()