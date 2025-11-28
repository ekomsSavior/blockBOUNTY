#!/usr/bin/env python3
"""
BlockBounty - Blockchain Bug Bounty & Vulnerability Scanner
A modular tool for security researchers conducting blockchain audits
"""

import sys
import argparse
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from utils.banner import print_banner
from utils.logger import setup_logger
from modules import contract_analyzer, transaction_analyzer, wallet_inspector

__version__ = "0.1.0"

def interactive_mode(logger):
    """Interactive menu mode for BlockBounty"""
    
    print("\n" + "=" * 70)
    print("              INTERACTIVE MODE - BLOCKCHAIN BUG BOUNTY")
    print("=" * 70)
    print("\nWhat would you like to analyze?\n")
    print("  [1] Smart Contract Vulnerability Scan")
    print("  [2] Wallet Address Inspector")
    print("  [3] Transaction Pattern Analysis")
    print("  [4] Exit")
    print("\n" + "=" * 70)
    
    try:
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            interactive_contract_scan(logger)
        elif choice == '2':
            interactive_wallet_scan(logger)
        elif choice == '3':
            interactive_transaction_scan(logger)
        elif choice == '4':
            print("\n[*] Exiting BlockBounty. Happy hunting!")
            sys.exit(0)
        else:
            print("\n[!] Invalid choice. Please enter 1-4.")
            interactive_mode(logger)
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit(0)

def interactive_contract_scan(logger):
    """Interactive contract analysis"""
    
    print("\n" + "-" * 70)
    print("SMART CONTRACT VULNERABILITY SCANNER")
    print("-" * 70)
    
    print("\nHow would you like to analyze the contract?\n")
    print("  [1] Analyze local .sol file")
    print("  [2] Fetch from blockchain (requires API key)")
    print("  [3] Back to main menu")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == '1':
        file_path = input("\nEnter the path to your Solidity contract: ").strip()
        
        if not file_path:
            print("[!] No file path provided.")
            interactive_contract_scan(logger)
            return
        
        # Create a simple args object
        class Args:
            def __init__(self):
                self.file = file_path
                self.address = None
                self.network = 'ethereum'
                self.api_key = None
        
        args = Args()
        logger.info("Starting Contract Analyzer...")
        contract_analyzer.run(args)
        
        # Ask if user wants to continue
        again = input("\n\nAnalyze another contract? (y/n): ").strip().lower()
        if again == 'y':
            interactive_contract_scan(logger)
        else:
            interactive_mode(logger)
            
    elif choice == '2':
        print("\n[!] Blockchain fetching coming soon!")
        print("[i] You'll need an Etherscan/BSCScan API key for this feature.")
        
        address = input("\nContract address (0x...): ").strip()
        network = input("Network (ethereum/bsc/polygon): ").strip() or 'ethereum'
        
        print(f"\n[*] Would fetch contract from {network}: {address}")
        print("[!] This feature requires API integration (Phase 2)")
        
        input("\nPress Enter to continue...")
        interactive_mode(logger)
        
    elif choice == '3':
        interactive_mode(logger)
    else:
        print("\n[!] Invalid choice.")
        interactive_contract_scan(logger)

def interactive_wallet_scan(logger):
    """Interactive wallet inspection"""
    
    print("\n" + "-" * 70)
    print("WALLET ADDRESS INSPECTOR")
    print("-" * 70)
    
    address = input("\nEnter wallet address to inspect: ").strip()
    
    if not address:
        print("[!] No address provided.")
        interactive_mode(logger)
        return
    
    network = input("Network (ethereum/bsc/polygon/bitcoin) [ethereum]: ").strip() or 'ethereum'
    
    deep_input = input("Enable deep analysis? (y/n) [n]: ").strip().lower()
    deep = True if deep_input == 'y' else False
    
    # Create args object
    class Args:
        def __init__(self):
            self.address = address
            self.network = network
            self.deep = deep
    
    args = Args()
    logger.info("Starting Wallet Inspector...")
    wallet_inspector.run(args)
    
    # Ask if user wants to continue
    again = input("\n\nInspect another wallet? (y/n): ").strip().lower()
    if again == 'y':
        interactive_wallet_scan(logger)
    else:
        interactive_mode(logger)

def interactive_transaction_scan(logger):
    """Interactive transaction analysis"""
    
    print("\n" + "-" * 70)
    print("TRANSACTION PATTERN ANALYZER")
    print("-" * 70)
    
    print("\nWhat would you like to analyze?\n")
    print("  [1] Specific transaction (by hash)")
    print("  [2] All transactions from an address")
    print("  [3] Back to main menu")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == '1':
        txhash = input("\nEnter transaction hash (0x...): ").strip()
        network = input("Network (ethereum/bsc/polygon) [ethereum]: ").strip() or 'ethereum'
        
        class Args:
            def __init__(self):
                self.txhash = txhash
                self.address = None
                self.network = network
                self.limit = 100
        
        args = Args()
        logger.info("Starting Transaction Analyzer...")
        transaction_analyzer.run(args)
        
    elif choice == '2':
        address = input("\nEnter address (0x...): ").strip()
        network = input("Network (ethereum/bsc/polygon) [ethereum]: ").strip() or 'ethereum'
        limit = input("Number of transactions to analyze [100]: ").strip() or '100'
        
        class Args:
            def __init__(self):
                self.txhash = None
                self.address = address
                self.network = network
                self.limit = int(limit)
        
        args = Args()
        logger.info("Starting Transaction Analyzer...")
        transaction_analyzer.run(args)
        
    elif choice == '3':
        interactive_mode(logger)
        return
    else:
        print("\n[!] Invalid choice.")
        interactive_transaction_scan(logger)
        return
    
    # Ask if user wants to continue
    again = input("\n\nAnalyze more transactions? (y/n): ").strip().lower()
    if again == 'y':
        interactive_transaction_scan(logger)
    else:
        interactive_mode(logger)

def main():
    """Main entry point for BlockBounty"""
    
    # Print the banner
    print_banner()
    
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description='BlockBounty - Blockchain Security Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-v', '--version', action='version', version=f'BlockBounty {__version__}')
    
    # Create subparsers for different modules
    subparsers = parser.add_subparsers(dest='module', help='Module to run')
    
    # Smart Contract Analyzer
    contract_parser = subparsers.add_parser('contract', help='Analyze smart contracts for vulnerabilities')
    contract_parser.add_argument('-f', '--file', help='Solidity contract file path')
    contract_parser.add_argument('-a', '--address', help='Contract address on blockchain')
    contract_parser.add_argument('-n', '--network', default='ethereum', help='Network (ethereum, bsc, polygon, etc.)')
    contract_parser.add_argument('--api-key', help='Blockchain explorer API key')
    
    # Transaction Analyzer
    tx_parser = subparsers.add_parser('transaction', help='Analyze transactions for suspicious patterns')
    tx_parser.add_argument('-t', '--txhash', help='Transaction hash to analyze')
    tx_parser.add_argument('-a', '--address', help='Address to analyze transactions from')
    tx_parser.add_argument('-n', '--network', default='ethereum', help='Network name')
    tx_parser.add_argument('--limit', type=int, default=100, help='Number of transactions to analyze')
    
    # Wallet Inspector
    wallet_parser = subparsers.add_parser('wallet', help='Inspect wallet and find vulnerabilities')
    wallet_parser.add_argument('-a', '--address', required=True, help='Wallet address to inspect')
    wallet_parser.add_argument('-n', '--network', default='ethereum', help='Network name')
    wallet_parser.add_argument('--deep', action='store_true', help='Deep analysis mode')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger()
    
    # If no module specified, enter interactive mode
    if not args.module:
        interactive_mode(logger)
        return
    
    # Route to appropriate module
    if args.module == 'contract':
        logger.info("Starting Contract Analyzer...")
        contract_analyzer.run(args)
    elif args.module == 'transaction':
        logger.info("Starting Transaction Analyzer...")
        transaction_analyzer.run(args)
    elif args.module == 'wallet':
        logger.info("Starting Wallet Inspector...")
        wallet_inspector.run(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
