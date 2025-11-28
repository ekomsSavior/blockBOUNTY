"""
Wallet Inspector Module
Inspects wallet addresses for security issues and suspicious activity
"""

import logging
import re
import requests
import json
from pathlib import Path

logger = logging.getLogger('BlockBounty')

# Blockchain explorer API endpoints (V2 for Etherscan)
EXPLORER_APIS = {
    'ethereum': {
        'base_url': 'https://api.etherscan.io/v2/api',  # V2 endpoint
        'name': 'Etherscan'
    },
    'bsc': {
        'base_url': 'https://api.bscscan.com/api',
        'name': 'BSCScan'
    },
    'polygon': {
        'base_url': 'https://api.polygonscan.com/api',
        'name': 'PolygonScan'
    }
}

def load_api_key(network):
    """Load API key from config file"""
    config_path = Path(__file__).parent.parent / 'config' / 'api_keys.json'
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get(network.lower())
        except:
            pass
    
    return None

def validate_address(address, network='ethereum'):
    """Validate blockchain address format"""
    
    if network.lower() in ['ethereum', 'bsc', 'polygon', 'avalanche', 'arbitrum']:
        # Ethereum-style address (0x + 40 hex chars)
        pattern = r'^0x[a-fA-F0-9]{40}$'
        if re.match(pattern, address):
            logger.info("✓ Valid Ethereum-style address format")
            return True
        else:
            logger.error("✗ Invalid address format")
            return False
    
    elif network.lower() == 'bitcoin':
        # Bitcoin address validation (simplified)
        if address.startswith(('1', '3', 'bc1')):
            logger.info("✓ Valid Bitcoin address format")
            return True
        else:
            logger.error("✗ Invalid Bitcoin address format")
            return False
    
    return False

def check_address_security(address):
    """Check for common address security issues"""
    
    issues = []
    
    # Check for vanity address (suspicious pattern)
    if re.search(r'0{8,}', address) or re.search(r'([a-fA-F0-9])\1{7,}', address):
        issues.append({
            'type': 'Vanity Address',
            'severity': 'INFO',
            'description': 'Address contains repetitive patterns. May be a vanity address.'
        })
    
    # Check for known address patterns
    if address.lower() == '0x0000000000000000000000000000000000000000':
        issues.append({
            'type': 'Null Address',
            'severity': 'CRITICAL',
            'description': 'This is the null/burn address. Tokens sent here are permanently lost.'
        })
    
    return issues

def fetch_balance(address, network='ethereum'):
    """Fetch ETH balance for address"""
    
    if network not in EXPLORER_APIS:
        return None
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    params = {
        'chainid': '1',  # V2 requires chainid
        'module': 'account',
        'action': 'balance',
        'address': address,
        'tag': 'latest'
    }
    
    if api_key:
        params['apikey'] = api_key
        logger.info(f"Using API key for {explorer['name']} ✓")
    
    try:
        response = requests.get(explorer['base_url'], params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == '1':
                balance_wei = int(data.get('result', '0'))
                balance_eth = balance_wei / 1e18
                return balance_eth
            else:
                logger.warning(f"API error: {data.get('message', 'Unknown')}")
                
    except Exception as e:
        logger.error(f"Error fetching balance: {e}")
    
    return None

def fetch_transaction_count(address, network='ethereum'):
    """Fetch transaction count for address"""
    
    if network not in EXPLORER_APIS:
        return None
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    params = {
        'chainid': '1',
        'module': 'proxy',
        'action': 'eth_getTransactionCount',
        'address': address,
        'tag': 'latest'
    }
    
    if api_key:
        params['apikey'] = api_key
    
    try:
        response = requests.get(explorer['base_url'], params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('result') and data.get('status') == '1':
                return int(data['result'], 16)
    except Exception as e:
        logger.error(f"Error fetching transaction count: {e}")
    
    return None

def check_if_contract(address, network='ethereum'):
    """Check if address is a smart contract"""
    
    if network not in EXPLORER_APIS:
        return False
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    params = {
        'chainid': '1',
        'module': 'proxy',
        'action': 'eth_getCode',
        'address': address,
        'tag': 'latest'
    }
    
    if api_key:
        params['apikey'] = api_key
    
    try:
        response = requests.get(explorer['base_url'], params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            code = data.get('result', '0x')
            return code != '0x' and len(code) > 2
    except Exception as e:
        logger.error(f"Error checking contract: {e}")
    
    return False

def fetch_token_balance(address, network='ethereum'):
    """Fetch ERC20 token holdings"""
    
    if network not in EXPLORER_APIS:
        return []
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    params = {
        'chainid': '1',
        'module': 'account',
        'action': 'tokentx',
        'address': address,
        'page': 1,
        'offset': 100,
        'sort': 'desc'
    }
    
    if api_key:
        params['apikey'] = api_key
    
    try:
        response = requests.get(explorer['base_url'], params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == '1' and data.get('result'):
                # Get unique tokens
                tokens = {}
                for tx in data['result']:
                    token_symbol = tx.get('tokenSymbol', 'UNKNOWN')
                    token_name = tx.get('tokenName', 'Unknown Token')
                    if token_symbol not in tokens:
                        tokens[token_symbol] = token_name
                return list(tokens.items())[:10]  # Return top 10
    except Exception as e:
        logger.error(f"Error fetching tokens: {e}")
    
    return []

def analyze_wallet_activity(address, network='ethereum'):
    """Perform comprehensive wallet analysis"""
    
    findings = []
    
    logger.info(f"\n{'='*70}")
    logger.info("WALLET ANALYSIS")
    logger.info(f"{'='*70}")
    
    # Check if contract
    is_contract = check_if_contract(address, network)
    if is_contract:
        logger.info("Address Type: Smart Contract")
        findings.append({
            'type': 'Smart Contract Address',
            'severity': 'INFO',
            'description': 'This is a smart contract, not an EOA (Externally Owned Account)',
            'recommendation': 'Analyze contract code before interacting.'
        })
    else:
        logger.info("Address Type: Externally Owned Account (EOA)")
    
    # Fetch balance
    balance = fetch_balance(address, network)
    if balance is not None:
        logger.info(f"Balance: {balance:.6f} ETH")
        
        if balance > 100:
            findings.append({
                'type': 'High Balance Wallet',
                'severity': 'INFO',
                'description': f'Wallet holds {balance:.2f} ETH',
                'recommendation': 'High-value wallet - use hardware wallet for security.'
            })
        elif balance == 0:
            findings.append({
                'type': 'Empty Wallet',
                'severity': 'INFO',
                'description': 'Wallet has zero ETH balance',
                'recommendation': 'May be inactive or freshly created.'
            })
    else:
        logger.warning("Could not fetch balance")
    
    # Fetch transaction count
    tx_count = fetch_transaction_count(address, network)
    if tx_count is not None:
        logger.info(f"Transaction Count: {tx_count:,}")
        
        if tx_count > 1000:
            findings.append({
                'type': 'High Activity Wallet',
                'severity': 'INFO',
                'description': f'Wallet has {tx_count:,} transactions',
                'recommendation': 'Very active wallet - likely bot, exchange, or power user.'
            })
        elif tx_count == 0:
            findings.append({
                'type': 'Unused Address',
                'severity': 'INFO',
                'description': 'No transactions recorded',
                'recommendation': 'Brand new or never-used address.'
            })
    
    return findings

def deep_wallet_analysis(address, network='ethereum'):
    """Perform deep analysis with token holdings"""
    
    logger.info(f"\n{'='*70}")
    logger.info("DEEP ANALYSIS - TOKEN HOLDINGS")
    logger.info(f"{'='*70}")
    
    tokens = fetch_token_balance(address, network)
    
    if tokens:
        logger.info(f"Found {len(tokens)} token interactions:")
        for symbol, name in tokens:
            logger.info(f"  • {symbol} - {name}")
    else:
        logger.info("No token transactions found")
    
    findings = []
    
    if len(tokens) > 20:
        findings.append({
            'type': 'Token Collector',
            'severity': 'INFO',
            'description': f'Wallet has interacted with {len(tokens)}+ different tokens',
            'recommendation': 'Heavy DeFi user or airdrop hunter.'
        })
    
    return findings

def run(args):
    """Main entry point for wallet inspector"""
    
    logger.info("Wallet Inspector Module")
    logger.info("-" * 50)
    
    address = args.address
    network = args.network
    
    logger.info(f"Inspecting wallet: {address}")
    logger.info(f"Network: {network}")
    
    # Validate address format
    if not validate_address(address, network):
        return
    
    # Check for security issues
    issues = check_address_security(address)
    
    if issues:
        logger.warning(f"Found {len(issues)} potential issues:")
        for issue in issues:
            logger.warning(f"  [{issue['severity']}] {issue['type']}: {issue['description']}")
    else:
        logger.info("No immediate security issues detected with address format.")
    
    # Perform wallet analysis
    try:
        findings = analyze_wallet_activity(address, network)
        
        if args.deep:
            deep_findings = deep_wallet_analysis(address, network)
            findings.extend(deep_findings)
        
        # Print all findings
        if findings:
            logger.info(f"\n{'='*70}")
            logger.info(f"ANALYSIS FINDINGS ({len(findings)} items)")
            logger.info(f"{'='*70}")
            
            for i, finding in enumerate(findings, 1):
                logger.info(f"\n[{i}] {finding['type']}")
                logger.info(f"Severity: {finding['severity']}")
                logger.info(f"Description: {finding['description']}")
                logger.info(f"Recommendation: {finding['recommendation']}")
        
        logger.info("\n✓ Analysis complete!")
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
