# ReserveProof

**Daily, blockchain-verified proof that a fintech still holds every rupee it owes its customers.**

Capstone prototype — Digital Finance, BBA (FIA), Shaheed Sukhdev College of Business Studies, University of Delhi.

## Live prototype
Open: https://anshgautamin-glitch.github.io/reserveproof/

## What it does
Every night:
1. The fintech commits a Merkle-sum root of all customer balances (its liabilities).
2. The escrow bank signs and posts the money it actually holds (its reserves).
3. A smart contract compares the two and raises a public `ShortfallAlert` if reserves fall short.
4. Any customer can verify their own balance was counted, without seeing anyone else's.

The prototype includes four fraud scenarios based on real cases (Synapse, FTX, PhonePe escrow shortfall): draining the escrow, hiding a hole with a fake negative account, leaving a customer out, and rewriting past records.

## Files
- `index.html` — the interactive prototype (runs in any browser; SHA-256 hashing and ECDSA signatures are real, the blockchain network is simulated)
- `ReserveProof.sol` — the Solidity smart contract (compiles with Solidity 0.8.24)

*Wallet and bank names in the demo are fictional.*
