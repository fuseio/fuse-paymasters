// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

/* solhint-disable reason-string */
/* solhint-disable no-inline-assembly */
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {UserOperation, UserOperationLib} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import {BasePaymaster, IEntryPoint} from "../BasePaymaster.sol";
import {PaymasterHelpers, PaymasterData, PaymasterContext} from "./PaymasterHelpers.sol";
import {VerifyingPaymasterErrors} from "../common/Errors.sol";

/**
 * @title A sample paymaster that uses external service to decide whether to pay for the UserOp.
 * @dev The paymaster trusts an external signer to sign the transaction.
 * The calling user must pass the UserOp to that external signer first, which performs whatever
 * off-chain verification before signing the UserOp.
 * @notice That this signature is NOT a replacement for wallet signature:
 *  - The paymaster signs to agree to PAY for GAS.
 *  - The wallet signs to prove identity and wallet ownership.
 */
contract FuseVerifyingSingletonPaymaster is
    BasePaymaster,
    ReentrancyGuard,
    VerifyingPaymasterErrors
{
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using PaymasterHelpers for UserOperation;
    using PaymasterHelpers for bytes;
    using PaymasterHelpers for PaymasterData;

    // calculated cost of the postOp
    uint256 private constant COST_OF_POST = 40000;

    mapping(bytes12 => address) public sponsorOwners;
    mapping(bytes12 => uint256) public sponsorBalances;

    address public verifyingSigner;

    event VerifyingSignerChanged(
        address indexed _oldSigner,
        address indexed _newSigner,
        address indexed _actor
    );
    event DepositedFunds(bytes12 indexed _sponsorId, uint256 indexed _value);
    event WithdrawnFunds(bytes12 indexed _sponsorId, uint256 indexed _value);
    event BalanceDeducted(bytes12 indexed _sponsorId, uint256 indexed _charge);
    event SponsorCreated(bytes12 indexed _sponsorId, address indexed _owner);
    event SponsorSuccessful(
        bytes12 indexed _sponsorId,
        address indexed _sender
    );
    event SponsorUnsuccessful(
        bytes12 indexed _sponsorId,
        address indexed _sender
    );

    constructor(
        address _owner,
        IEntryPoint _entryPoint,
        address _verifyingSigner
    ) payable BasePaymaster(_owner, _entryPoint) {
        if (address(_entryPoint) == address(0)) revert EntryPointCannotBeZero();
        if (_verifyingSigner == address(0))
            revert VerifyingSignerCannotBeZero();
        assembly {
            sstore(verifyingSigner.slot, _verifyingSigner)
        }
    }

    /**
     * @dev Add a deposit for this sponsor and given sponsorId (Project's identifier), used for paying for transaction fees
     * @param sponsorId project's identifier for which deposit is being made
     */
    function depositFor(bytes12 sponsorId) external payable nonReentrant {
        if (sponsorId == bytes12(0)) revert SponsorIdCannotBeZero();
        if (msg.value == 0) revert DepositCanNotBeZero();
        // If it's the first time deposit for a sponsorId, set the owner of the sponsorId to msg.sender
        if (sponsorOwners[sponsorId] == address(0)) {
            sponsorOwners[sponsorId] = address(msg.sender);
            emit SponsorCreated(sponsorId, msg.sender);
        }
        if (sponsorOwners[sponsorId] != msg.sender)
            revert CannotDepositToNotOwnedSponsor();
        sponsorBalances[sponsorId] = sponsorBalances[sponsorId] + msg.value;
        entryPoint.depositTo{value: msg.value}(address(this));
        emit DepositedFunds(sponsorId, msg.value);
    }

    /**
     * @dev get the current deposit for sponsorId (Project's identifier)
     * @param sponsorId project identifier
     */
    function getBalance(
        bytes12 sponsorId
    ) external view returns (uint256 balance) {
        balance = sponsorBalances[sponsorId];
    }

    function getOwner(bytes12 sponsorId) external view returns (address owner) {
        owner = sponsorOwners[sponsorId];
    }

    /**
     @dev Override the default implementation.
     */
    function deposit() public payable virtual override {
        revert("user DepositFor instead");
    }

    /**
     * @dev Withdraws the specified amount of gas tokens from the sponsorId's balance and transfers them to the msg.sender
     * if the msg.sender is the owner of sponsorId.
     * @param sponsorId The sponsorId from which the funds are withdrawn
     * @param amount The amount of gas tokens to withdraw.
     */
    function withdrawTo(
        bytes12 sponsorId,
        uint256 amount
    ) public override nonReentrant {
        if (sponsorOwners[sponsorId] != msg.sender)
            revert CannotWithdrawFromNotOwnedSponsor();
        uint256 currentBalance = sponsorBalances[sponsorId];
        if (amount > currentBalance)
            revert InsufficientBalance(amount, currentBalance);
        sponsorBalances[sponsorId] = sponsorBalances[sponsorId] - amount;
        entryPoint.withdrawTo(payable(msg.sender), amount);
        emit WithdrawnFunds(sponsorId, amount);
    }

    /**
     * @dev Set a new verifying signer address.
     * Can only be called by the owner of the contract.
     * @param _newVerifyingSigner The new address to be set as the verifying signer.
     * @notice If _newVerifyingSigner is set to zero address, it will revert with an error.
     * After setting the new signer address, it will emit an event VerifyingSignerChanged.
     */
    function setVerifyingSigner(
        address _newVerifyingSigner
    ) external payable onlyOwner {
        if (_newVerifyingSigner == address(0))
            revert VerifyingSignerCannotBeZero();
        address oldSigner = verifyingSigner;
        assembly {
            sstore(verifyingSigner.slot, _newVerifyingSigner)
        }
        emit VerifyingSignerChanged(oldSigner, _newVerifyingSigner, msg.sender);
    }

    /**
     * @dev This method is called by the off-chain service, to sign the request.
     * It is called on-chain from the validatePaymasterUserOp, to validate the signature.
     * @notice That this signature covers all fields of the UserOperation, except the "paymasterAndData",
     * which will carry the signature itself.
     * @return hash we're going to sign off-chain (and validate on-chain)
     */
    function getHash(
        UserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter,
        bytes12 sponsorId
    ) public view returns (bytes32) {
        //can't use userOp.hash(), since it contains also the paymasterAndData itself.

        return
            keccak256(
                abi.encode(
                    _pack(userOp),
                    block.chainid,
                    address(this),
                    validUntil,
                    validAfter,
                    sponsorId
                )
            );
    }

    function _debitSponsor(bytes12 _sponsorId, uint256 _amount) internal {
        sponsorBalances[_sponsorId] -= _amount;
    }

    function _creditSponsor(bytes12 _sponsorId, uint256 _amount) internal {
        sponsorBalances[_sponsorId] += _amount;
    }

    function _pack(
        UserOperation calldata userOp
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    userOp.getSender(),
                    userOp.nonce,
                    keccak256(userOp.initCode),
                    keccak256(userOp.callData),
                    userOp.callGasLimit,
                    userOp.verificationGasLimit,
                    userOp.preVerificationGas,
                    userOp.maxFeePerGas,
                    userOp.maxPriorityFeePerGas
                )
            );
    }

    /**
     * @dev Verify that an external signer signed the paymaster data of a user operation.
     * The paymaster data is expected to be the paymaster and a signature over the entire request parameters.
     * @param userOp The UserOperation struct that represents the current user operation.
     * userOpHash The hash of the UserOperation struct.
     * @param requiredPreFund The required amount of pre-funding for the paymaster.
     * @return context A context string returned by the entry point after successful validation.
     * @return validationData An integer returned by the entry point after successful validation.
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 requiredPreFund
    ) internal override returns (bytes memory context, uint256 validationData) {
        (requiredPreFund);

        PaymasterData memory paymasterData = userOp._decodePaymasterData();
        uint256 sigLength = paymasterData.signatureLength;

        // ECDSA library supports both 64 and 65-byte long signatures.
        // we only "require" it here so that the revert reason on invalid signature will be of "EtherspotPaymaster", and not "ECDSA"
        require(
            sigLength == 64 || sigLength == 65,
            "Paymaster:: invalid signature length in paymasterAndData"
        );

        bytes32 hash = getHash(
            userOp,
            paymasterData.validUntil,
            paymasterData.validAfter,
            paymasterData.sponsorId
        );

        // don't revert on signature failure: return SIG_VALIDATION_FAILED
        if (
            verifyingSigner !=
            hash.toEthSignedMessageHash().recover(paymasterData.signature)
        ) {
            // empty context and sigTimeRange 1
            return (
                "",
                _packValidationData(
                    true,
                    paymasterData.validUntil,
                    paymasterData.validAfter
                )
            );
        }

        // check sponsor has enough funds deposited to pay for gas
        require(
            sponsorBalances[paymasterData.sponsorId] >= requiredPreFund,
            "Paymaster:: Sponsor paymaster funds too low"
        );

        uint256 costOfPost = userOp.maxFeePerGas * COST_OF_POST;

        // debit requiredPreFund amount
        _debitSponsor(paymasterData.sponsorId, requiredPreFund);

        // no need for other on-chain validation: entire UserOp should have been checked
        // by the external service prior to signing it.
        return (
            userOp.paymasterContext(paymasterData, requiredPreFund, costOfPost),
            _packValidationData(
                false,
                paymasterData.validUntil,
                paymasterData.validAfter
            )
        );
    }

    function _postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) internal override {
        (
            bytes12 sponsorId,
            address sender,
            uint256 prefundedAmount,
            uint256 costOfPost
        ) = abi.decode(context, (bytes12, address, uint256, uint256));
        if (mode == PostOpMode.postOpReverted) {
            _creditSponsor(sponsorId, prefundedAmount);
            emit SponsorUnsuccessful(sponsorId, sender);
        } else {
            _creditSponsor(
                sponsorId,
                prefundedAmount - (actualGasCost + costOfPost)
            );
            emit SponsorSuccessful(sponsorId, sender);
        }
    }
}
