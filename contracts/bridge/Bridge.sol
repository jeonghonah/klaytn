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

    enum TransactionKind {
        ValueTransfer,
        FeeUpdate,
        OwnershipTransfer,
        RegisterSigner,
        DeregisterSigner,
        RegisterToken,
        DeregisterToken,
        Start,
        Stop,
        SetCounterPartBridge
    }

    mapping (uint64 => uint64) public requestNonces; // <tx kind, nonce>
    mapping (uint64 => uint64) public handleNonces;  // <tx kind, nonce>
    mapping (address => bool) public signers;    // <signer, nonce>
    mapping (bytes32 => mapping (address => uint64)) public signedTxs; // <sha3(kind, nonce), <singer, vote>>
    mapping (bytes32 => uint64) public signedTxsCount; // <sha3(kind, nonce), nonce>
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

    // start allows the value transfer request.
    function start() external onlyOwner {
        isRunning = true;
    }

    // stop prevent the value transfer request.
    function stop() external onlyOwner {
        isRunning = false;
    }

    // stop prevent the value transfer request.
    function setCounterPartBridge(address _bridge) external onlyOwner {
        counterpartBridge = _bridge;
    }

    // setSignerThreshold sets signer threshold.
    function setSignerThreshold(uint64 threshold) external onlyOwner {
        signerThreshold = threshold;
    }

    // registerSigner registers new signer.
    function registerSigner(address signer) external onlyOwner {
        signers[signer] = true;
    }

    // deregisterSigner deregisters a signer.
    function deregisterSigner(address signer) external onlyOwner {
        delete signers[signer];
    }

    // registerToken can update the allowed token with the counterpart token.
    function registerToken(address _token, address _cToken) external onlyOwner {
        allowedTokens[_token] = _cToken;
    }

    // deregisterToken can remove the token in allowedToken list.
    function deregisterToken(address _token) external onlyOwner {
        delete allowedTokens[_token];
    }

    modifier multiSigners()
    {
        require(tx.origin == owner() || signers[tx.origin], "invalid signer");
//        if (tx.origin != owner() && !signers[tx.origin]) {
//            revert();
//        }
        _;
    }

    // FIXME: need to accept hash for checking tx contents
    // do not process request nonce sequentially.
    function isFirstSigners(TransactionKind kind, uint64 requestNonce) internal returns(bool) {
        //require(handleNonces[uint64(TransactionKind.ValueTransfer)] == requestNonce, "mismatched handle / request nonce");
        bytes32 hash = keccak256(abi.encodePacked(uint(kind), requestNonce));

        if (signedTxs[hash][tx.origin] != 0) {
            return false;
        }

        signedTxs[hash][tx.origin] = requestNonce;
        signedTxsCount[hash]++;

        if (signedTxsCount[hash] == signerThreshold) {
            return true;
        }

        return false;
    }

    // handleKLAYTransfer sends the KLAY by the request.
    function handleKLAYTransfer(
        uint256 _amount,
        address _to,
        uint64 _requestNonce,
        uint64 _requestBlockNumber
    )
        external
        multiSigners
    {
        if (!isFirstSigners(TransactionKind.ValueTransfer, _requestNonce)) {
            return;
        }

        emit HandleValueTransfer(_to, TokenKind.KLAY, address(0), _amount, handleNonces[uint64(TransactionKind.ValueTransfer)]);
        _to.transfer(_amount);

        // need to be global min.
        lastHandledRequestBlockNumber = _requestBlockNumber;
        handleNonces[uint64(TransactionKind.ValueTransfer)]++;
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
        multiSigners
    {
        if (!isFirstSigners(TransactionKind.ValueTransfer, _requestNonce)) {
            return;
        }

        emit HandleValueTransfer(_to, TokenKind.ERC20, _contractAddress, _amount, handleNonces[uint64(TransactionKind.ValueTransfer)]);
        lastHandledRequestBlockNumber = _requestBlockNumber;
        handleNonces[uint64(TransactionKind.ValueTransfer)]++;

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
        multiSigners
    {
        if (!isFirstSigners(TransactionKind.ValueTransfer, _requestNonce)) {
            return;
        }

        emit HandleValueTransfer(_to, TokenKind.ERC721, _contractAddress, _uid, handleNonces[uint64(TransactionKind.ValueTransfer)]);
        lastHandledRequestBlockNumber = _requestBlockNumber;
        handleNonces[uint64(TransactionKind.ValueTransfer)]++;

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
            requestNonces[uint64(TransactionKind.ValueTransfer)],
            "",
            fee
        );
        requestNonces[uint64(TransactionKind.ValueTransfer)]++;
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
            requestNonces[uint64(TransactionKind.ValueTransfer)],
            "",
            fee
        );
        requestNonces[uint64(TransactionKind.ValueTransfer)]++;
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
            requestNonces[uint64(TransactionKind.ValueTransfer)],
            uri,
            0
        );
        requestNonces[uint64(TransactionKind.ValueTransfer)]++;
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
