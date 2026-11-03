// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ReserveProof — daily, tamper-proof proof of solvency for a custodial fintech
/// @notice The fintech commits a Merkle-sum root of all customer balances (its liabilities).
///         The independent escrow bank attests the money it actually holds (the reserves).
///         The contract compares the two and raises an alert the moment reserves < liabilities.
///         Only hashes and totals go on-chain — no names, no account numbers (DPDP-friendly).
contract ReserveProof {
    struct Snapshot {
        bytes32 liabilitiesRoot;   // Merkle-sum root of all customer balances
        uint256 totalLiabilities;  // sum of all balances, in paise
        uint256 attestedReserves;  // escrow balance signed off by the bank, in paise
        uint64  committedAt;
        bool    liabilitiesCommitted;
        bool    reservesAttested;
        bool    checked;
        bool    solvent;
    }

    address public immutable fintech;     // e.g. a wallet / PPI issuer
    address public immutable escrowBank;  // the bank holding customer money
    address public immutable regulator;   // e.g. RBI (read access + alerts)

    mapping(uint256 => Snapshot) public snapshots; // key: day as yyyymmdd
    uint256 public latestDay;

    event LiabilitiesCommitted(uint256 indexed day, bytes32 root, uint256 totalLiabilities);
    event ReservesAttested(uint256 indexed day, uint256 reserves);
    event SolvencyChecked(uint256 indexed day, uint256 reserveRatioBps, bool solvent);
    event ShortfallAlert(uint256 indexed day, uint256 shortfall);

    modifier only(address who) {
        require(msg.sender == who, "ReserveProof: not authorised");
        _;
    }

    constructor(address _fintech, address _escrowBank, address _regulator) {
        fintech = _fintech;
        escrowBank = _escrowBank;
        regulator = _regulator;
    }

    /// @notice Fintech publishes today's liabilities. Past days can never be rewritten.
    function commitLiabilities(uint256 day, bytes32 root, uint256 totalLiabilities) external only(fintech) {
        require(day > latestDay, "ReserveProof: day already committed");
        require(root != bytes32(0), "ReserveProof: empty root");
        Snapshot storage s = snapshots[day];
        s.liabilitiesRoot = root;
        s.totalLiabilities = totalLiabilities;
        s.committedAt = uint64(block.timestamp);
        s.liabilitiesCommitted = true;
        latestDay = day;
        emit LiabilitiesCommitted(day, root, totalLiabilities);
        if (s.reservesAttested) _check(day);
    }

    /// @notice Escrow bank attests the end-of-day balance it actually holds. Once only.
    function attestReserves(uint256 day, uint256 reserves) external only(escrowBank) {
        Snapshot storage s = snapshots[day];
        require(!s.reservesAttested, "ReserveProof: already attested");
        s.attestedReserves = reserves;
        s.reservesAttested = true;
        emit ReservesAttested(day, reserves);
        if (s.liabilitiesCommitted) _check(day);
    }

    function _check(uint256 day) internal {
        Snapshot storage s = snapshots[day];
        s.checked = true;
        s.solvent = s.attestedReserves >= s.totalLiabilities;
        uint256 ratioBps = s.totalLiabilities == 0 ? 10000 : (s.attestedReserves * 10000) / s.totalLiabilities;
        emit SolvencyChecked(day, ratioBps, s.solvent);
        if (!s.solvent) {
            // Fires instantly and publicly — no one can "forget" to report a shortfall.
            emit ShortfallAlert(day, s.totalLiabilities - s.attestedReserves);
        }
    }

    /// @notice Any customer can check their balance was counted, without revealing anyone else's.
    /// @param leafHash  sha256 of the customer's (id | balance | private salt), computed in their app
    /// @param leafSum   the customer's balance in paise
    /// @param siblingHashes / siblingSums  the Merkle-sum proof path given by the fintech
    /// @param siblingIsLeft  true if the sibling sits on the left at that level
    function verifyInclusion(
        uint256 day,
        bytes32 leafHash,
        uint256 leafSum,
        bytes32[] calldata siblingHashes,
        uint256[] calldata siblingSums,
        bool[] calldata siblingIsLeft
    ) external view returns (bool) {
        require(
            siblingHashes.length == siblingSums.length && siblingSums.length == siblingIsLeft.length,
            "ReserveProof: bad proof"
        );
        bytes32 h = leafHash;
        uint256 sum = leafSum;
        for (uint256 i = 0; i < siblingHashes.length; i++) {
            if (siblingIsLeft[i]) {
                h = sha256(abi.encodePacked(siblingHashes[i], siblingSums[i], h, sum));
            } else {
                h = sha256(abi.encodePacked(h, sum, siblingHashes[i], siblingSums[i]));
            }
            sum += siblingSums[i];
        }
        Snapshot storage s = snapshots[day];
        return h == s.liabilitiesRoot && sum == s.totalLiabilities;
    }
}
