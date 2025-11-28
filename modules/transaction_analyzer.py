"""
Transaction Analyzer Module
Analyzes blockchain transactions for suspicious patterns
"""

import logging
import requests
import json
from pathlib import Path

logger = logging.getLogger('BlockBounty')

# Blockchain explorer API endpoints
EXPLORER_APIS = {
    'ethereum': {
        'base_url_v2': 'https://api.etherscan.io/v2/api',  # V2 for account queries
        'base_url_v1': 'https://api.etherscan.io/api',     # V1 for proxy queries
        'name': 'Etherscan'
    },
    'bsc': {
        'base_url_v2': 'https://api.bscscan.com/api',
        'base_url_v1': 'https://api.bscscan.com/api',
        'name': 'BSCScan'
    },
    'polygon': {
        'base_url_v2': 'https://api.polygonscan.com/api',
        'base_url_v1': 'https://api.polygonscan.com/api',
        'name': 'PolygonScan'
    },
    'arbitrum': {
        'base_url_v2': 'https://api.arbiscan.io/api',
        'base_url_v1': 'https://api.arbiscan.io/api',
        'name': 'Arbiscan'
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

def fetch_transaction_details(txhash, network='ethereum'):
    """Fetch transaction details from blockchain explorer (uses V1 proxy)"""
    
    if network not in EXPLORER_APIS:
        logger.error(f"Unsupported network: {network}")
        return None
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    # Use V1 endpoint for proxy calls (single transaction lookup)
    params = {
        'module': 'proxy',
        'action': 'eth_getTransactionByHash',
        'txhash': txhash
    }
    
    if api_key:
        params['apikey'] = api_key
        logger.info(f"Using API key for {explorer['name']} ✓")
    else:
        logger.info(f"Using public endpoint (no API key) - rate limited")
    
    try:
        logger.info(f"Fetching transaction from {explorer['name']}...")
        # Use V1 endpoint for this call
        response = requests.get(explorer['base_url_v1'], params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            # V1 proxy returns result directly without status field
            if data.get('result'):
                return data['result']
            else:
                logger.warning("Transaction not found")
                return None
        else:
            logger.error(f"API request failed: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error: {e}")
        return None

def fetch_transaction_receipt(txhash, network='ethereum'):
    """Fetch transaction receipt (uses V1 proxy)"""
    
    if network not in EXPLORER_APIS:
        return None
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    params = {
        'module': 'proxy',
        'action': 'eth_getTransactionReceipt',
        'txhash': txhash
    }
    
    if api_key:
        params['apikey'] = api_key
    
    try:
        # Use V1 endpoint for proxy calls
        response = requests.get(explorer['base_url_v1'], params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('result')
    except:
        pass
    
    return None

def analyze_transaction(tx_data, receipt_data):
    """Analyze transaction for suspicious patterns"""
    
    findings = []
    
    if not tx_data:
        return findings
    
    # Convert hex values to integers
    value_wei = int(tx_data.get('value', '0x0'), 16)
    gas_price = int(tx_data.get('gasPrice', '0x0'), 16)
    gas_limit = int(tx_data.get('gas', '0x0'), 16)
    
    value_eth = value_wei / 1e18
    gas_price_gwei = gas_price / 1e9
    
    logger.info(f"\n{'='*70}")
    logger.info("TRANSACTION DETAILS")
    logger.info(f"{'='*70}")
    logger.info(f"From: {tx_data.get('from', 'N/A')}")
    logger.info(f"To: {tx_data.get('to', 'Contract Creation')}")
    logger.info(f"Value: {value_eth:.6f} ETH")
    logger.info(f"Gas Price: {gas_price_gwei:.2f} Gwei")
    logger.info(f"Gas Limit: {gas_limit:,}")
    
    if receipt_data:
        status = receipt_data.get('status', '0x0')
        gas_used = int(receipt_data.get('gasUsed', '0x0'), 16)
        logger.info(f"Status: {'✓ Success' if status == '0x1' else '✗ Failed'}")
        logger.info(f"Gas Used: {gas_used:,} ({(gas_used/gas_limit)*100:.1f}% of limit)")
    
    # ANALYSIS PATTERNS
    logger.info(f"\n{'='*70}")
    logger.info("SECURITY ANALYSIS")
    logger.info(f"{'='*70}")
    
    # High value transaction
    if value_eth > 10:
        findings.append({
            'type': 'High Value Transaction',
            'severity': 'INFO',
            'description': f'Transaction value: {value_eth:.2f} ETH (>10 ETH threshold)',
            'recommendation': 'Verify recipient address carefully for large transfers.'
        })
    
    # High gas price (potential MEV)
    if gas_price_gwei > 100:
        findings.append({
            'type': 'Unusually High Gas Price',
            'severity': 'MEDIUM',
            'description': f'Gas price: {gas_price_gwei:.2f} Gwei (may indicate MEV or urgency)',
            'recommendation': 'High gas could indicate front-running attempt or time-sensitive operation.'
        })
    
    # Contract interaction
    input_data = tx_data.get('input', '0x')
    if input_data and input_data != '0x':
        findings.append({
            'type': 'Contract Interaction',
            'severity': 'INFO',
            'description': f'Transaction includes {len(input_data)//2} bytes of data',
            'recommendation': 'Decode function call to verify the operation.'
        })
        
        # Check for common dangerous functions
        if input_data.startswith('0xa9059cbb'):
            findings.append({
                'type': 'ERC20 Transfer',
                'severity': 'INFO',
                'description': 'Function: transfer(address,uint256)',
                'recommendation': 'Standard ERC20 token transfer.'
            })
        elif input_data.startswith('0x095ea7b3'):
            findings.append({
                'type': 'ERC20 Approval',
                'severity': 'MEDIUM',
                'description': 'Function: approve(address,uint256)',
                'recommendation': 'Verify approval amount - unlimited approvals are risky.'
            })
    
    # Failed transaction
    if receipt_data and receipt_data.get('status') == '0x0':
        findings.append({
            'type': 'Transaction Failed',
            'severity': 'HIGH',
            'description': 'Transaction reverted - gas was consumed but operation failed',
            'recommendation': 'Check contract logic, may indicate attempted exploit or error.'
        })
    
    # Contract creation
    if not tx_data.get('to'):
        findings.append({
            'type': 'Contract Creation',
            'severity': 'INFO',
            'description': 'This transaction deploys a new smart contract',
            'recommendation': 'Review deployed contract code for vulnerabilities.'
        })
    
    return findings

def analyze_address_transactions(address, network='ethereum', limit=100):
    """Fetch and analyze recent transactions for an address (uses V2)"""
    
    if network not in EXPLORER_APIS:
        logger.error(f"Unsupported network: {network}")
        return []
    
    explorer = EXPLORER_APIS[network]
    api_key = load_api_key(network)
    
    params = {
        'chainid': '1',  # V2 requires chainid
        'module': 'account',
        'action': 'txlist',
        'address': address,
        'startblock': 0,
        'endblock': 99999999,
        'page': 1,
        'offset': min(limit, 100),
        'sort': 'desc'
    }
    
    if api_key:
        params['apikey'] = api_key
        logger.info(f"Using API key for {explorer['name']} ✓")
    else:
        logger.info(f"Using public endpoint - add API key for better results")
    
    try:
        logger.info(f"Fetching transactions from {explorer['name']}...")
        # Use V2 endpoint for account queries
        response = requests.get(explorer['base_url_v2'], params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == '1' and data.get('result'):
                transactions = data['result']
                logger.info(f"Found {len(transactions)} recent transactions")
                return transactions
            else:
                logger.warning("No transactions found or API error")
                return []
        else:
            logger.error(f"API request failed: {response.status_code}")
            return []
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error: {e}")
        return []

def analyze_transaction_patterns(transactions):
    """Analyze multiple transactions for patterns"""
    
    if not transactions:
        return []
    
    findings = []
    
    logger.info(f"\n{'='*70}")
    logger.info("TRANSACTION PATTERN ANALYSIS")
    logger.info(f"{'='*70}")
    
    # Calculate statistics
    total_value = sum(int(tx.get('value', '0')) for tx in transactions) / 1e18
    failed_txs = sum(1 for tx in transactions if tx.get('isError') == '1')
    contract_calls = sum(1 for tx in transactions if tx.get('input', '0x') != '0x')
    
    logger.info(f"Total Transactions: {len(transactions)}")
    logger.info(f"Total Value Moved: {total_value:.4f} ETH")
    logger.info(f"Failed Transactions: {failed_txs}")
    logger.info(f"Contract Interactions: {contract_calls}")
    
    # High failure rate
    if failed_txs > len(transactions) * 0.2:
        findings.append({
            'type': 'High Transaction Failure Rate',
            'severity': 'MEDIUM',
            'description': f'{failed_txs}/{len(transactions)} transactions failed ({failed_txs/len(transactions)*100:.1f}%)',
            'recommendation': 'May indicate bot activity or attempted exploits.'
        })
    
    # Rapid transactions
    if len(transactions) >= 10:
        timestamps = [int(tx.get('timeStamp', 0)) for tx in transactions[:10]]
        if timestamps:
            time_diff = max(timestamps) - min(timestamps)
            if time_diff < 3600:  # Less than 1 hour
                findings.append({
                    'type': 'Rapid Transaction Activity',
                    'severity': 'MEDIUM',
                    'description': f'10 transactions within {time_diff//60} minutes',
                    'recommendation': 'May indicate automated trading or bot activity.'
                })
    
    # High volume
    if total_value > 100:
        findings.append({
            'type': 'High Volume Activity',
            'severity': 'INFO',
            'description': f'Total value: {total_value:.2f} ETH across {len(transactions)} transactions',
            'recommendation': 'Significant wallet activity detected.'
        })
    
    return findings

def print_findings(findings):
    """Print analysis findings"""
    
    if not findings:
        logger.info("\n✓ No suspicious patterns detected")
        return
    
    logger.info(f"\n{'='*70}")
    logger.info(f"FINDINGS ({len(findings)} issues detected)")
    logger.info(f"{'='*70}")
    
    for i, finding in enumerate(findings, 1):
        severity_color = {
            'CRITICAL': '[CRITICAL]',
            'HIGH': '[HIGH]',
            'MEDIUM': '[MEDIUM]',
            'LOW': '[LOW]',
            'INFO': '[INFO]'
        }
        
        logger.info(f"\n[{i}] {finding['type']}")
        logger.warning(f"Severity: {severity_color.get(finding['severity'], finding['severity'])}")
        logger.info(f"Description: {finding['description']}")
        logger.info(f"Recommendation: {finding['recommendation']}")

def run(args):
    """Main entry point for transaction analyzer"""
    
    logger.info("Transaction Analyzer Module")
    logger.info("-" * 50)
    
    if args.txhash:
        # Analyze single transaction
        logger.info(f"Analyzing transaction: {args.txhash}")
        logger.info(f"Network: {args.network}")
        
        tx_data = fetch_transaction_details(args.txhash, args.network)
        receipt_data = fetch_transaction_receipt(args.txhash, args.network)
        
        if tx_data:
            findings = analyze_transaction(tx_data, receipt_data)
            print_findings(findings)
        else:
            logger.error("Could not fetch transaction data")
            logger.info("\n💡 Tip: Verify the transaction hash is correct!")
        
    elif args.address:
        # Analyze address transactions
        logger.info(f"Analyzing transactions for address: {args.address}")
        logger.info(f"Network: {args.network}")
        logger.info(f"Transaction limit: {args.limit}")
        
        transactions = analyze_address_transactions(args.address, args.network, args.limit)
        
        if transactions:
            findings = analyze_transaction_patterns(transactions)
            print_findings(findings)
            
            # Show recent transaction summary
            logger.info(f"\n{'='*70}")
            logger.info("RECENT TRANSACTIONS (Latest 5)")
            logger.info(f"{'='*70}")
            for i, tx in enumerate(transactions[:5], 1):
                value = int(tx.get('value', '0')) / 1e18
                status = '✓' if tx.get('isError') == '0' else '✗'
                logger.info(f"{i}. {status} {value:.6f} ETH - {tx.get('hash', 'N/A')[:20]}...")
        else:
            logger.error("Could not fetch transaction data")
            logger.info("\n💡 Tip: Make sure your API key is valid!")
    
    else:
        logger.error("Please specify either --txhash or --address")
