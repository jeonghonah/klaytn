pragma solidity ^0.4.24;

import "../externals/openzeppelin-solidity/contracts/math/SafeMath.sol";

import "../externals/openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";
import "../externals/openzeppelin-solidity/contracts/token/ERC20/ERC20Mintable.sol";
import "../externals/openzeppelin-solidity/contracts/token/ERC20/ERC20Burnable.sol";

import "../externals/openzeppelin-solidity/contracts/token/ERC721/IERC721.sol";
import "../externals/openzeppelin-solidity/contracts/token/ERC721/ERC721Metadata.sol";
import "../externals/openzeppelin-solidity/contracts/token/ERC721/ERC721MetadataMintable.sol";
import "../externals/openzeppelin-solidity/contracts/token/ERC721/ERC721Burnable.sol";

import "../externals/openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "../sc_erc721/IERC721BridgeReceiver.sol";
import "../sc_erc20/IERC20BridgeReceiver.sol";
import "./BridgeFee.sol";

contract Bridge is IERC20BridgeReceiver, IERC721BridgeReceiver, Ownable, BridgeFee {
    uint64 public constant VERSION = 1;
    bool public modeMintBurn = false;
    address public counterpartBridge;
    bool public isRunning;

    mapping (address => address) public allowedTokens; // <token, counterpart token>

    using SafeMath for uint256;

    enum TokenKind {
        KLAY,
        ERC20,
        ERC721
    }

    enum TransactionType {
        ValueTransfer,
        Governance
    }

    mapping (uint64 => uint64) public requestNonces; // <tx type, nonce>
    mapping (uint64 => uint64) public handleNonces;  // <tx type, nonce>
    mapping (address => bool) public signers;    // <signer, nonce>
    mapping (bytes32 => mapping (address => uint64)) public signedTxs; // <sha3(type, args, nonce), <singer, vote>>
    mapping (bytes32 => uint64) public signedTxsCount; // <sha3(type, args, nonce)>
    mapping (bytes32 => uint64) public committedTxs; // <sha3(type, nonce)>
    uint64 public signerThreshold = 1;

    uint64 public lastHandledRequestBlockNumber;

    // TODO-Klaytn-Service FeeReceiver should be passed by argument of constructor.
    constructor (bool _modeMintBurn) BridgeFee(address(0)) public payable {
        isRunning = true;
        modeMintBurn = _modeMintBurn;
    }

    /**
     * Event to log the withdrawal of a token from the Bridge.
     * @param kind The type of token withdrawn (KLAY/TOKEN/NFT).
     * @param from is the requester of the request value transfer event.
     * @param contractAddress Address of token contract the token belong to.
     * @param amount is the amount for KLAY/TOKEN and the NFT ID for NFT.
     * @param requestNonce is the order number of the request value transfer.
     * @param uri is uri of ERC721 token.
     */
    event RequestValueTransfer(TokenKind kind,
        address from,
        uint256 amount,
        address contractAddress,
        address to,
        uint64 requestNonce,
        string uri,
        uint256 fee
    );

    /**
     * Event to log the withdrawal of a token from the Bridge.
     * @param owner Address of the entity that made the withdrawal.ga
     * @param kind The type of token withdrawn (KLAY/TOKEN/NFT).
     * @param contractAddress Address of token contract the token belong to.
     * @param value For KLAY/TOKEN this is the amount.
     * @param handleNonce is the order number of the handle value transfer.
     */
    event HandleValueTransfer(
        address owner,
        TokenKind kind,
        address contractAddress,
        uint256 value,
        uint64 handleNonce);

    modifier onlySigners()
    {
        require(msg.sender == owner() || signers[msg.sender], "invalid signer");
        _;
    }

    modifier onlySequentialNonce(uint64 _txType, uint64 _requestNonce)
    {
        require(requestNonces[_txType] == _requestNonce, "mismatched handle / request nonce");
        _;
    }

    // voteValueTransfer votes value transfer transaction with the signer.
    function voteValueTransfer(bytes32 _txKey, bytes32 _voteKey, address _signer) internal returns(bool) {
        if (committedTxs[_txKey] != 0 || signedTxs[_voteKey][_signer] != 0) {
            return false;
        }

        signedTxs[_voteKey][_signer] = 1;
        signedTxsCount[_voteKey]++;

        if (signedTxsCount[_voteKey] == signerThreshold) {
            committedTxs[_txKey] = 1;
            return true;
        }

        return false;
    }

    // voteGovernance votes contract governance transaction with the signer.
    // It does not need to check committedTxs since onlySequentialNonce checks it already with harder condition.
    function voteGovernance(bytes32 _voteKey, address _signer) internal returns(bool) {
        if (signedTxs[_voteKey][_signer] != 0) {
            return false;
        }

        signedTxs[_voteKey][_signer] = 1;
        signedTxsCount[_voteKey]++;

        if (signedTxsCount[_voteKey] == signerThreshold) {
            return true;
        }

        return false;
    }

    // start allows the value transfer request.
    function start() external onlySigners {
        isRunning = true;
    }

    // stop prevent the value transfer request.
    function stop() external onlySigners {
        isRunning = false;
    }

    // stop prevent the value transfer request.
    function setCounterPartBridge(address _bridge) external onlySigners {
        counterpartBridge = _bridge;
    }

    // setSignerThreshold sets signer threshold.
    function setSignerThreshold(uint64 _threshold, uint64 _requestNonce)
        external
        onlySigners
        onlySequentialNonce(uint64(TransactionType.Governance), _requestNonce)
    {
        bytes32 voteKey = keccak256(abi.encodePacked(TransactionType.Governance, _threshold, _requestNonce));
        if (!voteGovernance(voteKey, msg.sender)) {
            return;
        }
        signerThreshold = _threshold;
        requestNonces[uint64(TransactionType.Governance)]++;
    }

    // registerSigner registers new signer.
    function registerSigner(address _signer) external onlySigners {
        signers[_signer] = true;
    }

    // deregisterSigner deregisters a signer.
    function deregisterSigner(address _signer) external onlySigners {
        delete signers[_signer];
    }

    // registerToken can update the allowed token with the counterpart token.
    function registerToken(address _token, address _cToken) external onlySigners {
        allowedTokens[_token] = _cToken;
    }

    // deregisterToken can remove the token in allowedToken list.
    function deregisterToken(address _token) external onlySigners {
        delete allowedTokens[_token];
    }

    // handleKLAYTransfer sends the KLAY by the request.
    function handleKLAYTransfer(
        uint256 _amount,
        address _to,
        uint64 _requestNonce,
        uint64 _requestBlockNumber
    )
        external
        onlySigners
    {
        bytes32 txKey = keccak256(abi.encodePacked(TransactionType.ValueTransfer, _requestNonce));
        bytes32 voteKey = keccak256(abi.encodePacked(TransactionType.ValueTransfer, _amount, _to, _requestNonce, _requestBlockNumber));
        if (!voteValueTransfer(txKey, voteKey, msg.sender)) {
            return;
        }

        emit HandleValueTransfer(_to, TokenKind.KLAY, address(0), _amount, handleNonces[uint64(TransactionType.ValueTransfer)]);
        _to.transfer(_amount);

        // need to be global min.
        lastHandledRequestBlockNumber = _requestBlockNumber;
        handleNonces[uint64(TransactionType.ValueTransfer)]++;
    }

    // handleERC20Transfer sends the token by the request.
    function handleERC20Transfer(
        uint256 _amount,
        address _to,
        address _contractAddress,
        uint64 _requestNonce,
        uint64 _requestBlockNumber
    )
        external
        onlySigners
    {
        bytes32 txKey = keccak256(abi.encodePacked(TransactionType.ValueTransfer, _requestNonce));
        bytes32 voteKey = keccak256(abi.encodePacked(TransactionType.ValueTransfer, _amount, _to, _contractAddress, _requestNonce, _requestBlockNumber));
        if (!voteValueTransfer(txKey, voteKey, msg.sender)) {
            return;
        }

        emit HandleValueTransfer(_to, TokenKind.ERC20, _contractAddress, _amount, handleNonces[uint64(TransactionType.ValueTransfer)]);
        lastHandledRequestBlockNumber = _requestBlockNumber;
        handleNonces[uint64(TransactionType.ValueTransfer)]++;

        if (modeMintBurn) {
            ERC20Mintable(_contractAddress).mint(_to, _amount);
        } else {
            IERC20(_contractAddress).transfer(_to, _amount);
        }
    }

    // handleERC721Transfer sends the NFT by the request.
    function handleERC721Transfer(
        uint256 _uid,
        address _to,
        address _contractAddress,
        uint64 _requestNonce,
        uint64 _requestBlockNumber,
        string _tokenURI
    )
        external
        onlySigners
    {
        bytes32 txKey = keccak256(abi.encodePacked(TransactionType.ValueTransfer, _requestNonce));
        bytes32 voteKey = keccak256(abi.encodePacked(TransactionType.ValueTransfer, _uid, _to, _contractAddress, _requestNonce, _requestBlockNumber, _tokenURI));
        if (!voteValueTransfer(txKey, voteKey, msg.sender)) {
            return;
        }

        emit HandleValueTransfer(_to, TokenKind.ERC721, _contractAddress, _uid, handleNonces[uint64(TransactionType.ValueTransfer)]);
        lastHandledRequestBlockNumber = _requestBlockNumber;
        handleNonces[uint64(TransactionType.ValueTransfer)]++;

        if (modeMintBurn) {
            ERC721MetadataMintable(_contractAddress).mintWithTokenURI(_to, _uid, _tokenURI);
        } else {
            IERC721(_contractAddress).safeTransferFrom(address(this), _to, _uid);
        }
    }

    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function _requestKLAYTransfer(address _to, uint256 _feeLimit) internal {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");

        uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);

        emit RequestValueTransfer(
            TokenKind.KLAY,
            msg.sender,
            msg.value.sub(_feeLimit),
            address(0),
            _to,
            requestNonces[uint64(TransactionType.ValueTransfer)],
            "",
            fee
        );
        requestNonces[uint64(TransactionType.ValueTransfer)]++;
    }

    // () requests transfer KLAY to msg.sender address on relative chain.
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY);
    }

    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _amount) external payable {
        uint256 feeLimit = msg.value.sub(_amount);
        _requestKLAYTransfer(_to, feeLimit);
    }

    // _requestERC20Transfer requests transfer ERC20 to _to on relative chain.
    function _requestERC20Transfer(address _contractAddress, address _from, address _to, uint256 _amount, uint256 _feeLimit) internal {
        require(isRunning, "stopped bridge");
        require(_amount > 0, "zero msg.value");
        require(allowedTokens[_contractAddress] != address(0), "Not a valid token");

        uint256 fee = _payERC20FeeAndRefundChange(_from, _contractAddress, _feeLimit);

        if (modeMintBurn) {
            ERC20Burnable(_contractAddress).burn(_amount);
        }

        emit RequestValueTransfer(
            TokenKind.ERC20,
            _from,
            _amount,
            _contractAddress,
            _to,
            requestNonces[uint64(TransactionType.ValueTransfer)],
            "",
            fee
        );
        requestNonces[uint64(TransactionType.ValueTransfer)]++;
    }

    // Receiver function of ERC20 token for 1-step deposits to the Bridge
    function onERC20Received(
        address _from,
        uint256 _amount,
        address _to,
        uint256 _feeLimit
    )
    public
    {
        _requestERC20Transfer(msg.sender, _from, _to, _amount, _feeLimit);
    }

    // requestERC20Transfer requests transfer ERC20 to _to on relative chain.
    function requestERC20Transfer(address _contractAddress, address _to, uint256 _amount, uint256 _feeLimit) external {
        IERC20(_contractAddress).transferFrom(msg.sender, address(this), _amount.add(_feeLimit));
        _requestERC20Transfer(_contractAddress, msg.sender, _to, _amount, _feeLimit);
    }

    // _requestERC721Transfer requests transfer ERC721 to _to on relative chain.
    function _requestERC721Transfer(address _contractAddress, address _from, address _to, uint256 _uid) internal {
        require(isRunning, "stopped bridge");
        require(allowedTokens[_contractAddress] != address(0), "Not a valid token");

        string memory uri = ERC721Metadata(_contractAddress).tokenURI(_uid);

        if (modeMintBurn) {
            ERC721Burnable(_contractAddress).burn(_uid);
        }

        emit RequestValueTransfer(
            TokenKind.ERC721,
            _from,
            _uid,
            _contractAddress,
            _to,
            requestNonces[uint64(TransactionType.ValueTransfer)],
            uri,
            0
        );
        requestNonces[uint64(TransactionType.ValueTransfer)]++;
    }

    // Receiver function of ERC721 token for 1-step deposits to the Bridge
    function onERC721Received(
        address _from,
        uint256 _tokenId,
        address _to
    )
    public
    {
        _requestERC721Transfer(msg.sender, _from, _to, _tokenId);
    }

    // requestERC721Transfer requests transfer ERC721 to _to on relative chain.
    function requestERC721Transfer(address _contractAddress, address _to, uint256 _uid) external {
        IERC721(_contractAddress).transferFrom(msg.sender, address(this), _uid);
        _requestERC721Transfer(_contractAddress, msg.sender, _to, _uid);
    }

    // chargeWithoutEvent sends KLAY to this contract without event for increasing
    // the withdrawal limit.
    function chargeWithoutEvent() external payable {}

    // setKLAYFee set the fee of KLAY tranfser
    function setKLAYFee(uint256 _fee) external onlyOwner {
        _setKLAYFee(_fee);
    }

    // setERC20Fee set the fee of the token transfer
    function setERC20Fee(address _token, uint256 _fee) external onlyOwner {
        _setERC20Fee(_token, _fee);
    }

    // setFeeReceiver set fee receiver.
    function setFeeReceiver(address _feeReceiver) external onlyOwner {
        _setFeeReceiver(_feeReceiver);
    }
}
