# Protocol Checker & Solana Program Checker

**The Protocol Checker & Solana Program Checker** is an open-source tool to enhance security  
in the use and development of Web3 smart contracts.  
Integrated into the **Cometix Security Web Extension**, it leverages artificial intelligence (AI)  
to analyze smart contracts on Ethereum and Solana blockchains.  
The tool identifies vulnerabilities, logical errors, and Solana-specific weaknesses,  
providing detailed warnings to help developers and auditors create and maintain  
secure decentralized applications.

## Key Features

- **AI-Driven Vulnerability Detection** *(Open Source)*  
  Scans smart contracts in real time to identify risks like reentrancy bugs or  
  overflow vulnerabilities, providing instant warnings.

- **Solana Program Analysis** *(Open Source)*  
  Detects Solana program weaknesses, such as improper account validation,  
  using AI tailored for Solana’s architecture, with precise alerts for developers.

- **Logical Error Detection** *(Open Source)*  
  Analyzes contract logic to uncover errors, like unintended fund locks,  
  generating detailed reports for secure development and auditing.

- **Exploit Pattern Recognition** *(Open Source)*  
  Uses proprietary AI to identify malicious code patterns, such as backdoors,  
  offering proactive notifications to mitigate threats.

- **Real-Time Code Analysis**  
  Examines contract syntax and structure with AI, flagging issues like deprecated functions  
  for immediate feedback.

- **Detailed Warning Reports**  
  Compiles AI-driven scan results into a dashboard, presenting vulnerabilities and  
  mitigation steps to support contract development.

---

## Architecture

```
                  ┌────────────────────────────┐
                  │    Cometix Web Extension   │
                  └────────────┬───────────────┘
                               │
      ┌────────────────────────▼────────────────────────┐
      │ Protocol Checker & Solana Program Checker (WASM)│
      │  - AI Vulnerability Detection                       │
      │  - Solana/ETH Program Analyzer                      │
      │  - Logic Error Detector                         │
      │  - Exploit Pattern Matcher                      │
      │  - AI Engine                                    │
      └────────────────────────┬────────────────────────┘
                               │
              ┌────────────────▼─────────────────┐
              │      Ethereum / Solana RPC       │
              └──────────────────────────────────┘
```

---

### Requirements

| Tool                     | Version      |
|--------------------------|--------------|
| cometix-sdk              | 1.0.16       |
| solana-instruction       | >=2.2.1      |
| eth-instruction          | >=3.143.1    |
| cometix-security         | 1.0.52       |
| cometix-utils            | 1.1.12       |
| wasm-pack                | >=0.10.2     |
| Rust                     | >=1.70.0     |
| Node.js                  | >=18.0.0     |
| Vite                     | >=4.0.0      |

---

## Local Development

Install Rust toolchain:

```bash
curl https://sh.rustup.rs -sSf | sh
cargo install wasm-pack
```

Install frontend deps:

```bash
cd frontend/
npm install
```

## Building the WASM Module

```bash
cd protocol-checker/
wasm-pack build --target web --out-dir ../output/out
```

Flags:
- `--target web`: for browser-based WASM  
- `--out-dir`: exports to frontend for integration
