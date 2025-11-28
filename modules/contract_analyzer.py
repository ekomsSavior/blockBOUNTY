"""
Smart Contract Analyzer Module
Analyzes smart contracts for common vulnerabilities
"""

import re
import logging
from pathlib import Path

logger = logging.getLogger('BlockBounty')

class VulnerabilityPattern:
    """Represents a vulnerability pattern to search for"""
    
    def __init__(self, name, severity, pattern, description, recommendation):
        self.name = name
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.pattern = pattern
        self.description = description
        self.recommendation = recommendation

# Define vulnerability patterns
VULNERABILITY_PATTERNS = [
    VulnerabilityPattern(
        name="Reentrancy Vulnerability",
        severity="CRITICAL",
        pattern=r'\.call\{value:\s*\w+\}|\.call\.value\(|\.transfer\(.*\)\s*;(?!.*require)',
        description="Potential reentrancy vulnerability detected. External call before state change.",
        recommendation="Use Checks-Effects-Interactions pattern. Update state before external calls."
    ),
    VulnerabilityPattern(
        name="Unchecked Return Value",
        severity="HIGH",
        pattern=r'\.call\(|\.delegatecall\((?!.*require)',
        description="Low-level call without checking return value.",
        recommendation="Always check return values of .call(), .delegatecall(), and .send()."
    ),
    VulnerabilityPattern(
        name="tx.origin Authentication",
        severity="HIGH",
        pattern=r'tx\.origin\s*==',
        description="Using tx.origin for authentication is insecure.",
        recommendation="Use msg.sender instead of tx.origin for authentication."
    ),
    VulnerabilityPattern(
        name="Unprotected Self-Destruct",
        severity="CRITICAL",
        pattern=r'selfdestruct\(|suicide\(',
        description="Self-destruct function may be unprotected.",
        recommendation="Ensure selfdestruct is properly protected with access controls."
    ),
    VulnerabilityPattern(
        name="Outdated Compiler Version",
        severity="MEDIUM",
        pattern=r'pragma\s+solidity\s*[\^<]?\s*0\.[0-4]\.',
        description="Using outdated Solidity compiler version.",
        recommendation="Update to Solidity 0.8.0 or higher for built-in overflow protection."
    ),
    VulnerabilityPattern(
        name="Delegatecall to Untrusted Contract",
        severity="CRITICAL",
        pattern=r'delegatecall\(',
        description="Delegatecall can be dangerous if called on untrusted contracts.",
        recommendation="Ensure delegatecall only targets trusted, immutable contracts."
    ),
    VulnerabilityPattern(
        name="Unprotected Ether Withdrawal",
        severity="HIGH",
        pattern=r'function\s+withdraw.*public|function\s+withdraw.*external',
        description="Withdrawal function may be unprotected.",
        recommendation="Add access controls and withdrawal limits to withdrawal functions."
    ),
    VulnerabilityPattern(
        name="Integer Overflow/Underflow",
        severity="HIGH",
        pattern=r'[\+\-\*]\s*=(?!.*SafeMath)',
        description="Arithmetic operations without SafeMath (pre-0.8.0).",
        recommendation="Use SafeMath library or upgrade to Solidity 0.8.0+."
    ),
    VulnerabilityPattern(
        name="Block Timestamp Dependency",
        severity="MEDIUM",
        pattern=r'block\.timestamp|now\s',
        description="Relying on block.timestamp can be manipulated by miners.",
        recommendation="Avoid using block.timestamp for critical logic or random number generation."
    ),
    VulnerabilityPattern(
        name="Uninitialized Storage Pointer",
        severity="HIGH",
        pattern=r'struct\s+\w+\s+\w+\s*;(?!.*memory|.*storage)',
        description="Uninitialized storage pointer can point to unexpected storage slot.",
        recommendation="Always initialize storage pointers or use memory keyword."
    ),
    VulnerabilityPattern(
        name="Missing Access Control",
        severity="CRITICAL",
        pattern=r'function\s+(?!initialize|constructor|supportsInterface|name|symbol|decimals|totalSupply|balanceOf|approve|allowance|transfer|transferFrom)\w+\s*\([^)]*\)\s*external(?!.*view|.*pure|.*onlyOwner|.*onlyRole|.*onlyAdmin|.*require\s*\(msg\.sender)',
        description="Public/external function without access control modifiers.",
        recommendation="Add appropriate access control (onlyOwner, onlyAdmin, etc.)."
    ),
    VulnerabilityPattern(
        name="Arbitrary Jump/Delegatecall",
        severity="CRITICAL",
        pattern=r'assembly\s*\{[^}]*jump|assembly\s*\{[^}]*delegatecall',
        description="Arbitrary jump or delegatecall in assembly can be exploited.",
        recommendation="Avoid arbitrary jumps and validate delegatecall destinations."
    ),
    VulnerabilityPattern(
        name="Unprotected Initialization",
        severity="HIGH",
        pattern=r'function\s+initialize\s*\([^)]*\)\s*(public|external)(?!.*initializer)',
        description="Initialization function without proper protection.",
        recommendation="Use OpenZeppelin's initializer modifier or add require(!initialized)."
    ),
    VulnerabilityPattern(
        name="Denial of Service - Gas Limit",
        severity="MEDIUM",
        pattern=r'for\s*\([^)]*\)\s*\{[^}]*\.(call|transfer|send)',
        description="Loop with external calls can hit gas limit causing DoS.",
        recommendation="Avoid unbounded loops with external calls. Use pull over push pattern."
    ),
    VulnerabilityPattern(
        name="Front-Running Vulnerability",
        severity="HIGH",
        pattern=r'function\s+\w*(swap|trade|buy|sell)\w*\s*\([^)]*\)\s*(public|external)',
        description="Trading function susceptible to front-running attacks.",
        recommendation="Implement commit-reveal scheme or use private mempools."
    ),
    VulnerabilityPattern(
        name="Unsafe Type Casting",
        severity="MEDIUM",
        pattern=r'uint\d+\s*\([^)]*int\d+|int\d+\s*\([^)]*uint\d+',
        description="Unsafe type casting between signed and unsigned integers.",
        recommendation="Validate ranges before casting or use SafeCast library."
    ),
    VulnerabilityPattern(
        name="Weak Randomness",
        severity="HIGH",
        pattern=r'block\.(timestamp|number|difficulty|blockhash).*random|keccak256.*block\.',
        description="Using block properties for randomness is predictable.",
        recommendation="Use Chainlink VRF or commit-reveal schemes for randomness."
    ),
    VulnerabilityPattern(
        name="Oracle Manipulation",
        severity="CRITICAL",
        pattern=r'getPrice|price\s*=|oracle\.(?!.*require)',
        description="Price oracle usage without validation or manipulation checks.",
        recommendation="Use TWAP, multiple oracles, or circuit breakers for price feeds."
    ),
    VulnerabilityPattern(
        name="Flash Loan Attack Vector",
        severity="CRITICAL",
        pattern=r'function\s+\w*(flash|loan)\w*|executeOperation',
        description="Flash loan function without proper validation.",
        recommendation="Add reentrancy guards, check balances before/after, validate caller."
    ),
    VulnerabilityPattern(
        name="Signature Replay Attack",
        severity="HIGH",
        pattern=r'ecrecover\(|verify.*signature(?!.*nonce|.*timestamp)',
        description="Signature verification without nonce or timestamp.",
        recommendation="Include nonce, timestamp, and chainId in signed messages."
    ),
    VulnerabilityPattern(
        name="Unchecked External Call",
        severity="HIGH",
        pattern=r'\.call\{value:|\.call\((?!.*require|.*assert|.*if\s*\()',
        description="External call without checking success return value.",
        recommendation="Always check return value: require(success, 'call failed')."
    ),
    VulnerabilityPattern(
        name="Missing Zero Address Check",
        severity="MEDIUM",
        pattern=r'=\s*_\w+;(?!.*require.*!=.*address\(0\))',
        description="Address assignment without zero address validation.",
        recommendation="Add require(addr != address(0), 'zero address') checks."
    ),
    VulnerabilityPattern(
        name="Unprotected Approve",
        severity="MEDIUM",
        pattern=r'function\s+approve\s*\([^)]*\)\s*(public|external)(?!.*return)',
        description="ERC20 approve without return value or race condition protection.",
        recommendation="Use increaseAllowance/decreaseAllowance pattern."
    ),
    VulnerabilityPattern(
        name="Hardcoded Address",
        severity="LOW",
        pattern=r'address\(0x[a-fA-F0-9]{40}\)|0x[a-fA-F0-9]{40}(?!.*constant|.*immutable)',
        description="Hardcoded address without constant/immutable keyword.",
        recommendation="Use constant or immutable for hardcoded addresses."
    ),
    VulnerabilityPattern(
        name="Centralization Risk",
        severity="MEDIUM",
        pattern=r'onlyOwner|owner\s*==\s*msg\.sender(?!.*timelock|.*multisig)',
        description="Centralized control without timelock or multisig.",
        recommendation="Implement timelock, multisig, or DAO governance."
    ),
    VulnerabilityPattern(
        name="Unsafe External Call in Loop",
        severity="HIGH",
        pattern=r'for\s*\([^}]*\)[\s\S]*?\.call\{|while\s*\([^}]*\)[\s\S]*?\.call\{',
        description="External call inside loop can cause reentrancy or DoS.",
        recommendation="Avoid external calls in loops. Use pull payment pattern."
    ),
    VulnerabilityPattern(
        name="Missing Event Emission",
        severity="LOW",
        pattern=r'function\s+set\w+\s*\([^)]*\)\s*(public|external)(?!.*emit)',
        description="State-changing function without event emission.",
        recommendation="Emit events for all important state changes."
    ),
    VulnerabilityPattern(
        name="Unsafe ERC20 Transfer",
        severity="MEDIUM",
        pattern=r'\.transfer\((?!.*require|.*safeTransfer)',
        description="ERC20 transfer without checking return value.",
        recommendation="Use SafeERC20.safeTransfer() instead of transfer()."
    ),
    VulnerabilityPattern(
        name="Division Before Multiplication",
        severity="MEDIUM",
        pattern=r'\w+\s*/\s*\w+\s*\*',
        description="Division before multiplication causes precision loss.",
        recommendation="Always multiply before dividing to maintain precision."
    ),
    
    # ==================== DEFI-SPECIFIC VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="AMM Price Manipulation",
        severity="CRITICAL",
        pattern=r'getReserves|balanceOf.*pair|token0.*token1',
        description="AMM reserves used for pricing without TWAP protection.",
        recommendation="Use time-weighted average price (TWAP) or Chainlink oracles."
    ),
    VulnerabilityPattern(
        name="Unchecked Slippage",
        severity="HIGH",
        pattern=r'swap.*(?!.*amountOutMin|.*minAmount)',
        description="Swap function without slippage protection.",
        recommendation="Add amountOutMin parameter to prevent sandwich attacks."
    ),
    VulnerabilityPattern(
        name="Flash Loan Reentrancy",
        severity="CRITICAL",
        pattern=r'flashLoan|onFlashLoan|executeOperation(?!.*nonReentrant)',
        description="Flash loan callback without reentrancy protection.",
        recommendation="Add nonReentrant modifier to flash loan functions."
    ),
    VulnerabilityPattern(
        name="Liquidity Pool Manipulation",
        severity="CRITICAL",
        pattern=r'mint\(|burn\((?!.*require.*deadline)',
        description="Liquidity operations without deadline protection.",
        recommendation="Add deadline parameter to prevent transaction delay exploitation."
    ),
    VulnerabilityPattern(
        name="Yield Farming Exploit",
        severity="HIGH",
        pattern=r'updatePool|getReward(?!.*checkpoint|.*updateReward)',
        description="Reward distribution without proper checkpoint mechanism.",
        recommendation="Implement checkpoint system to prevent reward manipulation."
    ),
    
    # ==================== NFT VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="NFT Reentrancy (ERC721)",
        severity="CRITICAL",
        pattern=r'safeTransferFrom.*onERC721Received(?!.*nonReentrant)',
        description="ERC721 transfer with callback susceptible to reentrancy.",
        recommendation="Add reentrancy guard or use pull payment pattern."
    ),
    VulnerabilityPattern(
        name="NFT Metadata Manipulation",
        severity="MEDIUM",
        pattern=r'tokenURI.*(?!.*immutable|.*constant)',
        description="Mutable tokenURI can lead to metadata manipulation.",
        recommendation="Make baseURI immutable or use decentralized storage (IPFS)."
    ),
    VulnerabilityPattern(
        name="Unlimited NFT Minting",
        severity="HIGH",
        pattern=r'function\s+mint.*(?!.*maxSupply|.*totalSupply)',
        description="NFT minting without supply cap.",
        recommendation="Implement maxSupply check to prevent unlimited minting."
    ),
    VulnerabilityPattern(
        name="NFT Ownership Bypass",
        severity="CRITICAL",
        pattern=r'ownerOf\(|_owners\[(?!.*require)',
        description="NFT ownership check without validation.",
        recommendation="Always validate ownership before sensitive operations."
    ),
    VulnerabilityPattern(
        name="ERC721 Approval Race Condition",
        severity="MEDIUM",
        pattern=r'approve\(.*tokenId(?!.*getApproved)',
        description="ERC721 approval without checking existing approval.",
        recommendation="Check and clear previous approvals to prevent race conditions."
    ),
    
    # ==================== BRIDGE/CROSS-CHAIN VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="Bridge Signature Verification",
        severity="CRITICAL",
        pattern=r'bridge|withdraw.*signature(?!.*ecrecover.*chainId)',
        description="Bridge signature without chain ID validation.",
        recommendation="Include chain ID in signature to prevent replay across chains."
    ),
    VulnerabilityPattern(
        name="Cross-Chain Message Replay",
        severity="CRITICAL",
        pattern=r'executeMessage|processMessage(?!.*nonce|.*messageId)',
        description="Cross-chain message without replay protection.",
        recommendation="Implement nonce or message ID tracking to prevent replays."
    ),
    VulnerabilityPattern(
        name="Bridge Liquidity Drain",
        severity="CRITICAL",
        pattern=r'deposit.*bridge|lock.*bridge(?!.*maxDeposit|.*depositLimit)',
        description="Bridge deposit without limits can drain liquidity.",
        recommendation="Add deposit limits and circuit breakers."
    ),
    VulnerabilityPattern(
        name="Oracle Finality Issue",
        severity="HIGH",
        pattern=r'block\.number.*bridge|confirmations(?!.*finality)',
        description="Bridge relying on block confirmations without finality check.",
        recommendation="Wait for proper finality (>12 blocks for Ethereum)."
    ),
    
    # ==================== ACCESS CONTROL DEEP DIVE ====================
    
    VulnerabilityPattern(
        name="Role-Based Access Control Bypass",
        severity="CRITICAL",
        pattern=r'hasRole|checkRole(?!.*_checkRole|.*require)',
        description="RBAC check without enforcement.",
        recommendation="Always use _checkRole() or require() for role validation."
    ),
    VulnerabilityPattern(
        name="Admin Key Compromise Risk",
        severity="HIGH",
        pattern=r'setAdmin|transferAdmin(?!.*timelock|.*2fa|.*multisig)',
        description="Admin transfer without timelock or multisig.",
        recommendation="Implement 2-step admin transfer with timelock."
    ),
    VulnerabilityPattern(
        name="Modifier Bypass",
        severity="CRITICAL",
        pattern=r'_;.*_;',
        description="Multiple modifier placeholders can cause bypass.",
        recommendation="Use single modifier placeholder per function."
    ),
    VulnerabilityPattern(
        name="Constructor Access Control",
        severity="MEDIUM",
        pattern=r'constructor\s*\([^)]*\)(?!.*require|.*msg\.sender)',
        description="Constructor without access control.",
        recommendation="Validate deployer or use factory pattern."
    ),
    
    # ==================== GOVERNANCE VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="Governance Vote Manipulation",
        severity="CRITICAL",
        pattern=r'propose|vote(?!.*getVotes.*timestamp)',
        description="Governance without snapshot-based voting.",
        recommendation="Use historical balance snapshots for voting power."
    ),
    VulnerabilityPattern(
        name="Timelock Bypass",
        severity="CRITICAL",
        pattern=r'executeTransaction(?!.*timestamp.*delay)',
        description="Timelock execution without delay validation.",
        recommendation="Enforce minimum delay for all governance actions."
    ),
    VulnerabilityPattern(
        name="Quorum Manipulation",
        severity="HIGH",
        pattern=r'quorum|threshold(?!.*totalSupply)',
        description="Quorum calculation vulnerable to supply manipulation.",
        recommendation="Calculate quorum based on total supply at proposal time."
    ),
    
    # ==================== STAKING/REWARDS VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="Reward Calculation Overflow",
        severity="HIGH",
        pattern=r'reward\s*\*|rewardPerToken(?!.*div|.*SafeMath)',
        description="Reward multiplication without overflow protection.",
        recommendation="Use SafeMath or Solidity 0.8+ for reward calculations."
    ),
    VulnerabilityPattern(
        name="Staking Reentrancy",
        severity="CRITICAL",
        pattern=r'function\s+stake|function\s+withdraw(?!.*nonReentrant)',
        description="Staking functions without reentrancy protection.",
        recommendation="Add nonReentrant modifier to staking operations."
    ),
    VulnerabilityPattern(
        name="Emergency Withdraw Exploit",
        severity="MEDIUM",
        pattern=r'emergencyWithdraw(?!.*penality|.*burnRewards)',
        description="Emergency withdraw without penalty or reward forfeiture.",
        recommendation="Implement penalty or burn unclaimed rewards on emergency exit."
    ),
    
    # ==================== PROXY/UPGRADEABLE VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="Uninitialized Proxy",
        severity="CRITICAL",
        pattern=r'contract\s+\w+.*(?:is|:).*(?:Upgradeable|Proxy)(?!.*\{[\s\S]{0,1000}function\s+initialize)',
        description="Upgradeable contract without initialization function.",
        recommendation="Add initialize() function with initializer modifier."
    ),
    VulnerabilityPattern(
        name="Storage Collision",
        severity="CRITICAL",
        pattern=r'contract\s+\w+.*(?:Upgradeable|Proxy).*\{\s*(?:uint256|address)\s+(?!_)',
        description="Potential storage collision in upgradeable contract.",
        recommendation="Use storage gaps and follow EIP-1967 storage patterns."
    ),
    VulnerabilityPattern(
        name="Delegatecall to Unverified Implementation",
        severity="CRITICAL",
        pattern=r'delegatecall\(implementation(?!.*verify|.*check)',
        description="Proxy delegatecall without implementation verification.",
        recommendation="Verify implementation contract before delegatecall."
    ),
    VulnerabilityPattern(
        name="Upgrade Authority Missing",
        severity="HIGH",
        pattern=r'function\s+\w*upgradeTo(?:AndCall)?\s*\([^)]*\)\s*(?:external|public)(?!.*onlyOwner|.*onlyAdmin|.*onlyRole)',
        description="Upgrade function without proper access control.",
        recommendation="Restrict upgrades to authorized addresses only."
    ),
    
    # ==================== TOKEN-SPECIFIC VULNERABILITIES ====================
    
    VulnerabilityPattern(
        name="Fee-on-Transfer Token Issue",
        severity="MEDIUM",
        pattern=r'transferFrom.*balanceOf(?!.*actualReceived)',
        description="Not handling fee-on-transfer tokens correctly.",
        recommendation="Calculate actual received amount after transfer."
    ),
    VulnerabilityPattern(
        name="Rebasing Token Issue",
        severity="HIGH",
        pattern=r'balanceOf.*require(?!.*shares|.*scaled)',
        description="Balance check incompatible with rebasing tokens.",
        recommendation="Use share-based accounting for rebasing tokens."
    ),
    VulnerabilityPattern(
        name="ERC777 Reentrancy",
        severity="CRITICAL",
        pattern=r'ERC777|tokensReceived(?!.*nonReentrant)',
        description="ERC777 hook susceptible to reentrancy.",
        recommendation="Use nonReentrant or Checks-Effects-Interactions pattern."
    ),
    
    # ==================== GAS OPTIMIZATION & DOS ====================
    
    VulnerabilityPattern(
        name="Unbounded Loop",
        severity="MEDIUM",
        pattern=r'for\s*\(.*\.length\)(?!.*break|.*maxIterations)',
        description="Loop without bounds can cause out-of-gas DoS.",
        recommendation="Add maximum iteration limit or use pagination."
    ),
    VulnerabilityPattern(
        name="Expensive Operation in Loop",
        severity="MEDIUM",
        pattern=r'for\s*\([^}]*\)[\s\S]*?sstore|for\s*\([^}]*\)[\s\S]*?call',
        description="Storage writes or calls in loop can exceed gas limit.",
        recommendation="Batch operations or use events for gas-intensive loops."
    ),
    
    # ==================== ARITHMETIC & LOGIC ====================
    
    VulnerabilityPattern(
        name="Precision Loss",
        severity="MEDIUM",
        pattern=r'/\s*\d+\s*\*|\*.*\d+.*/',
        description="Division before multiplication causes precision loss.",
        recommendation="Always multiply before dividing in financial calculations."
    ),
    VulnerabilityPattern(
        name="Rounding Error Exploitation",
        severity="MEDIUM",
        pattern=r'totalShares|totalDebt(?!.*1e18|.*WAD|.*RAY)',
        description="Missing precision multiplier in financial calculations.",
        recommendation="Use fixed-point math with 1e18 multiplier (WAD/RAY pattern)."
    ),
    VulnerabilityPattern(
        name="Unchecked Math in Assembly",
        severity="HIGH",
        pattern=r'assembly\s*\{[\s\S]*?(add|sub|mul|div)(?!.*overflow)',
        description="Arithmetic in assembly without overflow checks.",
        recommendation="Add overflow checks or use Solidity 0.8+ checked math."
    ),
]

def analyze_solidity_code(code):
    """Analyze Solidity code for vulnerabilities"""
    
    vulnerabilities = []
    lines = code.split('\n')
    
    logger.info(f"Analyzing {len(lines)} lines of Solidity code...")
    
    for pattern in VULNERABILITY_PATTERNS:
        matches = re.finditer(pattern.pattern, code, re.MULTILINE)
        
        for match in matches:
            # Find line number
            line_num = code[:match.start()].count('\n') + 1
            line_content = lines[line_num - 1].strip()
            
            vulnerability = {
                'name': pattern.name,
                'severity': pattern.severity,
                'line': line_num,
                'code': line_content,
                'description': pattern.description,
                'recommendation': pattern.recommendation
            }
            vulnerabilities.append(vulnerability)
            
            logger.warning(f"Found {pattern.severity} issue at line {line_num}: {pattern.name}")
    
    return vulnerabilities

def analyze_contract_structure(code):
    """Analyze contract structure for security issues"""
    
    issues = []
    
    # Check for missing access modifiers
    if re.search(r'function\s+\w+\s*\([^)]*\)\s*{', code):
        issues.append({
            'type': 'Missing Visibility Modifier',
            'severity': 'MEDIUM',
            'description': 'Functions without explicit visibility modifiers default to public.'
        })
    
    # Check for floating pragma
    if re.search(r'pragma\s+solidity\s*\^', code):
        issues.append({
            'type': 'Floating Pragma',
            'severity': 'LOW',
            'description': 'Contract uses floating pragma. Lock to specific version for production.'
        })
    
    # Check for proper use of view/pure
    view_pure_funcs = re.findall(r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|private|internal)?\s*(view|pure)', code)
    if len(view_pure_funcs) == 0:
        issues.append({
            'type': 'No View/Pure Functions',
            'severity': 'INFO',
            'description': 'Consider marking read-only functions as view or pure.'
        })
    
    return issues

def generate_report(vulnerabilities, structure_issues, filename):
    """Generate a vulnerability report"""
    
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("BLOCKBOUNTY SMART CONTRACT SECURITY ANALYSIS REPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"\nContract: {filename}")
    report_lines.append(f"Total Vulnerabilities Found: {len(vulnerabilities)}")
    report_lines.append(f"Total Structure Issues: {len(structure_issues)}")
    
    # Severity breakdown
    severity_count = {}
    for vuln in vulnerabilities:
        sev = vuln['severity']
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    report_lines.append("\nSeverity Breakdown:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_count.get(severity, 0)
        if count > 0:
            report_lines.append(f"  {severity}: {count}")
    
    # Detailed vulnerabilities
    if vulnerabilities:
        report_lines.append("\n" + "=" * 70)
        report_lines.append("DETAILED VULNERABILITY REPORT")
        report_lines.append("=" * 70)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report_lines.append(f"\n[{i}] {vuln['name']}")
            report_lines.append(f"Severity: {vuln['severity']}")
            report_lines.append(f"Line: {vuln['line']}")
            report_lines.append(f"Code: {vuln['code']}")
            report_lines.append(f"Description: {vuln['description']}")
            report_lines.append(f"Recommendation: {vuln['recommendation']}")
            report_lines.append("-" * 70)
    
    # Structure issues
    if structure_issues:
        report_lines.append("\n" + "=" * 70)
        report_lines.append("CONTRACT STRUCTURE ISSUES")
        report_lines.append("=" * 70)
        
        for i, issue in enumerate(structure_issues, 1):
            report_lines.append(f"\n[{i}] {issue['type']}")
            report_lines.append(f"Severity: {issue['severity']}")
            report_lines.append(f"Description: {issue['description']}")
    
    report_lines.append("\n" + "=" * 70)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 70)
    
    return "\n".join(report_lines)

def run(args):
    """Main entry point for contract analyzer"""
    
    logger.info("Smart Contract Analyzer Module")
    logger.info("-" * 50)
    
    if args.file:
        # Analyze local file
        file_path = Path(args.file)
        
        if not file_path.exists():
            logger.error(f"File not found: {args.file}")
            return
        
        logger.info(f"Analyzing contract file: {file_path.name}")
        
        try:
            with open(file_path, 'r') as f:
                contract_code = f.read()
            
            # Run analysis
            vulnerabilities = analyze_solidity_code(contract_code)
            structure_issues = analyze_contract_structure(contract_code)
            
            # Generate report
            report = generate_report(vulnerabilities, structure_issues, file_path.name)
            print("\n" + report)
            
            # Save report
            report_dir = Path(__file__).parent.parent / 'reports'
            report_dir.mkdir(exist_ok=True)
            report_file = report_dir / f'contract_analysis_{file_path.stem}.txt'
            
            with open(report_file, 'w') as f:
                f.write(report)
            
            logger.info(f"Report saved to: {report_file}")
            
            # Summary
            critical = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
            high = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
            
            if critical > 0:
                logger.critical(f"Found {critical} CRITICAL vulnerabilities!")
            if high > 0:
                logger.error(f"Found {high} HIGH severity vulnerabilities!")
            
            logger.info("Analysis complete!")
            
        except Exception as e:
            logger.error(f"Error analyzing contract: {e}")
    
    elif args.address:
        # Fetch and analyze contract from blockchain
        logger.info(f"Fetching contract from {args.network}...")
        logger.info(f"Address: {args.address}")
        logger.warning("Blockchain fetching requires API key. Use --api-key parameter.")
        logger.info("This feature will be implemented in the next iteration.")
    
    else:
        logger.error("Please specify either --file or --address")
