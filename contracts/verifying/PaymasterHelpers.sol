// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

struct PaymasterData {
    uint48 validUntil;
    uint48 validAfter;
    address sponsorId;
    bytes signature;
    uint256 signatureLength;
}

struct PaymasterContext {
    address sponsorId;
    uint256 gasPrice;
}

/**
 * returned data from validateUserOp.
 * validateUserOp returns a uint256, with is created by `_packedValidationData` and parsed by `_parseValidationData`
 * @param aggregator - address(0) - the account validated the signature by itself.
 *              address(1) - the account failed to validate the signature.
 *              otherwise - this is an address of a signature aggregator that must be used to validate the signature.
 * @param validAfter - this UserOp is valid only after this timestamp.
 * @param validaUntil - this UserOp is valid only up to this timestamp.
 */
struct ValidationData {
    address aggregator;
    uint48 validAfter;
    uint48 validUntil;
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
        (
            uint48 validUntil,
            uint48 validAfter,
            address sponsorId,
            bytes memory signature
        ) = abi.decode(paymasterAndData[20:], (uint48, uint48, address, bytes));
        return
            PaymasterData(
                validUntil,
                validAfter,
                sponsorId,
                signature,
                signature.length
            );
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
