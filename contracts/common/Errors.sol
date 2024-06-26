// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

contract BasePaymasterErrors {
    /**
     * @notice Throws at onlyEntryPoint when msg.sender is not an EntryPoint set for this paymaster
     * @param caller address that tried to call protected method
     */
    error CallerIsNotAnEntryPoint(address caller);
}

contract VerifyingPaymasterErrors {
    /**
     * @notice Throws when the Entrypoint address provided is address(0)
     */
    error EntryPointCannotBeZero();

    /**
     * @notice Throws when the verifiying signer address provided is address(0)
     */
    error VerifyingSignerCannotBeZero();

    /**
     * @notice Throws when the sponsor address provided is address(0)
     */
    error SponsorIdCannotBeZero();

    /**
     * @notice Throws when the 0 has been provided as deposit
     */
    error DepositCanNotBeZero();

    /**
     * @notice Throws when trying to withdraw to address(0)
     */
    error CanNotWithdrawToZeroAddress();

    /**
     * @notice Throws when trying to withdraw from a sponsor that is owned by someone else
     */
    error CannotWithdrawFromNotOwnedSponsor();

    /**
     * @notice Throws when trying to deposit to a sponsor that is owned by someone else
     */
    error CannotDepositToNotOwnedSponsor();

    /**
     * @notice Throws when trying to withdraw more than balance available
     * @param amountRequired required balance
     * @param currentBalance available balance
     */
    error InsufficientBalance(uint256 amountRequired, uint256 currentBalance);

    /**
     * @notice Throws when signature provided has invalid length
     * @param sigLength length oif the signature provided
     */
    error InvalidPaymasterSignatureLength(uint256 sigLength);
}
