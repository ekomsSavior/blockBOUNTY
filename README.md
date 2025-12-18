# blockBOUNTY

![Screenshot_2025-11-28_16_22_40](https://github.com/user-attachments/assets/fca21e64-d89f-4b7e-a882-968551db3ab9)


Blockchain bug bounty and vulnerability scanner for smart contracts, DeFi and wallet activity

BlockBOUNTY is a CLI framework for security engineers who live in web / infra / app land but need a foothold in web3.
It gives you a first-pass view of:

* how an EVM contract is likely to fail,
* how a wallet is being used,
* and whether transaction flows look clean or hostile.

It is built for red teams, bug bounty hunters and auditors who want fast signal without having to become Solidity devs or chain analysts first.

---

## Features

**Smart Contract Vulnerability Scanner**

* Analyze local Solidity source (`.sol`) or pull verified contracts from the chain via explorer APIs.
* Pattern-based checks for common EVM issues and antipatterns, including things like:

  * reentrancy-style external calls before state change,
  * `tx.origin` authentication misuse,
  * unprotected `selfdestruct`,
  * outdated compiler pragmas and unsafe defaults,
  * missing or weak access control on admin functions.
* Generates a readable report with severity breakdown (CRITICAL / HIGH / MEDIUM) and remediation notes.

**Wallet Address Inspector**

* Classifies an address (externally owned vs contract) and fetches on-chain balance.
* Enumerates token interactions and holdings via explorer APIs.
* Surfaces airdropped junk / obvious scam tokens and reward-bait text so you can quickly see what kind of ecosystem the wallet is sitting in.
* Summarizes findings in a short “analysis” section for triage.

**Transaction Pattern Analysis**

* Pulls recent transaction history and applies simple heuristics to highlight:

  * suspicious outbound drainage patterns,
  * repetitive self-transfers and washing loops,
  * interactions with multiple unverified contracts,
  * bursts of approvals or privileged calls.
* Intended as a quick reconnaissance pass for bounty targets, compromised wallets and “is this ecosystem sketchy” questions.

**Reporting**

* Interactive terminal output for live use during an engagement.
* Text reports written under the `reports/` directory for later diffing, note-taking or attaching to bounty writeups.

BlockBOUNTY is read-only: it does not hold private keys or send transactions. It talks to public blockchain explorer APIs and parses local files.

---

## Installation


### 1. Clone the repository

```bash
git clone https://github.com/ekomsSavior/blockBOUNTY.git
cd blockBOUNTY
```

### 2. Make sure Python and pip are present

```bash
sudo apt update
sudo apt install -y python3 python3-pip
```

### 3. Install Python dependencies

You can use the provided requirements file:

```bash
pip3 install -r requirements.txt
```


BlockBOUNTY also expects `web3` to be available; install it explicitly:

```bash
pip3 install web3 --break-system-packages 
```

---

## API keys and configuration

Deep wallet / transaction analysis uses blockchain explorer APIs (Etherscan-style).

* Create API keys (https://etherscan.io for eth) for the chains you care about (Ethereum mainnet, testnets, BSC, Polygon, etc.) on the relevant explorers.
* Drop those keys into the files under the `config/api_keys.json` directory.
  The layout in that directory is intentionally simple and documented in comments; adjust it to match your setup.
* Without keys, BlockBOUNTY can still run local contract analysis on `.sol` files, but wallet and transaction modules will be limited.

---

## Usage

From inside the project directory:

```bash
python3 blockbounty.py
```

You’ll be dropped into the interactive menu:

![Screenshot_2025-11-28_16_23_27](https://github.com/user-attachments/assets/8c507891-9d02-4f22-8bb7-460571062fb1)



### 1. Smart Contract Vulnerability Scan


**Option A – Local Solidity file**

1. Choose `1` from the main menu.
2. Select the option to analyze a local `.sol` file.
3. Provide the path to the contract source file (for example, `examples/vulnerable_contract.sol`).
4. BlockBOUNTY parses the source, runs its checks and prints a structured report, including:

   * total vulnerabilities,
   * severity breakdown,
   * per-issue description, line numbers and recommendations.
5. A copy of the report is written to `reports/` with a timestamped filename.

This mode is ideal for:

* bounty programs that share source files,
* local proof-of-concept contracts,
* quickly reviewing forks and modified versions before deployment.

**Option B – Fetch from blockchain**

1. Choose `1` from the main menu.
2. Select the option to fetch a contract from the chain.
3. Enter:

   * contract address,
   * network (for example `ethereum`, `bsc`, `polygon`),
   * and make sure the corresponding explorer API key is configured.
4. BlockBOUNTY pulls the verified contract source, then runs the same static checks as in local mode and writes a report to `reports/`.

Use this during on-chain bounties when you want a first-pass read of deployed contracts without manually downloading their source.

---

### 2. Wallet Address Inspector

![Screenshot_2025-11-28_16_23_38](https://github.com/user-attachments/assets/e35b1865-dbb0-4ad9-bf6a-46025d07d2c9)


1. Choose `2` from the main menu.
2. Paste the wallet address you want to inspect.
3. Select the network (Ethereum / BSC / Polygon / etc.).
4. Choose whether to enable deep analysis when prompted.

The module will:

* validate the address format,
* identify the address type (EOA vs contract),
* fetch balance via the configured explorer API,
* enumerate tokens the address has interacted with,
* highlight noisy or suspicious airdrops and obvious promo tokens,
* print a short “analysis findings” section at the bottom.

This is useful for:

* mapping target teams’ operational wallets during a bounty,
* sanity-checking addresses that report as “compromised”,
* separating real activity from spammy token noise.

---

### 3. Transaction Pattern Analysis

1. Choose `3` from the main menu.
2. Provide an address or list of transaction hashes, depending on the prompt.
3. Set the analysis depth when asked (recent transactions vs longer history).

The module pulls transaction data from the relevant explorer APIs and applies simple heuristics to surface:

* large or sudden outflows,
* repeated circular transfers and washing behaviour,
* dense clusters of calls into unverified contracts,
* unusual approval / revoke patterns.

The goal is not perfect behavioral detection but a fast map you can pivot from into your own tooling, notes and manual review.

Reports are again written to `reports/` for later reference.

---

## Typical workflows

Some practical ways to use BlockBOUNTY:

* **New blockchain bug bounty target**

  * Enumerate the contracts in scope.
  * Run each through the Smart Contract Vulnerability Scanner for a baseline list of red flags.
  * Inspect team wallets and treasury addresses with the Wallet Inspector to understand how they move money.
  * Use Transaction Pattern Analysis to map suspicious flows to and from those contracts.

* **Incident response on a compromised wallet**

  * Run the Wallet Inspector to separate legitimate holdings from scam airdrops.
  * Use Transaction Pattern Analysis to understand where stolen funds moved and which contracts were involved.

* **Solidity code review primer**

  * Run local `.sol` files through the scanner while you review them manually.
  * Treat BlockBOUNTY’s output as a checklist of areas to focus on, not as a replacement for full manual analysis.

---

## Limitations

* Heuristic, pattern-based checks only. This is not a formal verification engine or a full audit suite.
* Focused on EVM-compatible chains and Solidity contracts.
* Wallet and transaction analysis are limited by what the upstream explorer APIs expose and rate-limit.
* Findings should always be validated manually before filing bounties, escalating incidents, or making trading decisions.

---

## Disclaimer

BlockBOUNTY is provided for educational use, internal security testing and authorized bug bounty work only.

* Only analyze contracts, wallets and infrastructure that you own or have explicit permission to test.
* The tool is read-only and does not send transactions or manage private keys, but misuse can still violate laws, platform terms, or bounty rules.
* There is no warranty of accuracy or fitness for any particular purpose. You are responsible for how you use the results and for any impact on external systems.

Use this framework as a starting point for understanding blockchain targets, not as the final word on their security posture.

![Screenshot 2025-10-14 111008](https://github.com/user-attachments/assets/4993cfcf-62b9-4c2b-b564-f7bdb6b71ef7)

