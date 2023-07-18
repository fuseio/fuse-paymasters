// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

struct PaymasterData {
    address sponsorId;
    bytes signature;
    uint256 signatureLength;
}

struct PaymasterContext {
    address sponsorId;
    uint256 gasPrice;
}

/**
 * @title PaymasterHelpers - helper functions for paymasters
 */
library PaymasterHelpers {
    using ECDSA for bytes32;

    /**
     * @dev Encodes the paymaster context: paymasterId and gasPrice
     * @param op UserOperation object
     * @param data PaymasterData passed
     * @param prefundedAmount Prefunded amount
     * @param costOfPost Cost of post
     */
    function paymasterContext(
        UserOperation calldata op,
        PaymasterData memory data,
        uint256 prefundedAmount,
        uint256 costOfPost
    ) internal pure returns (bytes memory context) {
        return
            abi.encode(data.sponsorId, op.sender, prefundedAmount, costOfPost);
    }

    /**
     * @dev Decodes paymaster data assuming it follows PaymasterData
     */
    function _decodePaymasterData(
        UserOperation calldata op
    ) internal pure returns (PaymasterData memory) {
        bytes calldata paymasterAndData = op.paymasterAndData;
        (address sponsorId, bytes memory signature) = abi.decode(
            paymasterAndData[20:],
            (address, bytes)
        );
        return PaymasterData(sponsorId, signature, signature.length);
    }

    /**
     * @dev Decodes paymaster context assuming it follows PaymasterContext
     */
    function _decodePaymasterContext(
        bytes memory context
    ) internal pure returns (PaymasterContext memory) {
        (address sponsorId, uint256 gasPrice) = abi.decode(
            context,
            (address, uint256)
        );
        return PaymasterContext(sponsorId, gasPrice);
    }
}
