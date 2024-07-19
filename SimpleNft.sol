// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC1155.sol";
import "@openzeppelin/contracts@4.6.0/access/Ownable.sol";

contract SimpleNFT is ERC1155, Ownable {
    string public name;
    string public symbol;
    address private whitelistSigningKey;
    mapping(uint256 => string) public uris;
    uint256 nftCounter = 0;

    event NFTsMinted(uint256[] mintedtokenIds, string[] mintedUris);
    event NFTsBurned(
        address indexed owner,
        uint256[] burnedTokenIds,
        address indexed contractAddress
    );

    constructor(
        string memory _collectionName,
        string memory _collectionSymbol,
        address _whitelistSigner,
        address _collectionOwner
    ) {
        name = _collectionName;
        symbol = _collectionSymbol;
        whitelistSigningKey = _whitelistSigner;
        transferOwnership(_collectionOwner);
    }

    function uri(uint256 id) public view override returns (string memory) {
        return uris[id];
    }

    function addItems(
        string[] memory _batchURIs,
        address[] memory recipientAddresses,
        bytes memory _signature,
        string memory _message
    ) public requiresWhitelist(_message, _signature) {
        uint256 idsLength = _batchURIs.length; // Saves MLOADs.
        require(
            idsLength == recipientAddresses.length,
            "Address and ids length mismatch"
        );

        uint256[] memory mintedIds = new uint256[](idsLength);
        string[] memory mintedUris = new string[](idsLength);
        for (uint256 i = 0; i < idsLength; i++) {
            uint256 newItemId = getNextItemId();
            uris[newItemId] = _batchURIs[i];
            _mint(recipientAddresses[i], newItemId, 1, "0x12");
            mintedIds[i] = newItemId;
            mintedUris[i] = _batchURIs[i];
        }
        emit NFTsMinted(mintedIds, mintedUris);
    }

    function getNextItemId() private returns (uint256) {
        nftCounter++;
        return nftCounter;
    }

    function burnBatch(
        address account,
        uint256[] memory tokenIds,
        bytes memory _signature,
        string memory _message
    ) public requiresWhitelist(_message, _signature) {
        uint256[] memory amounts = new uint256[](tokenIds.length);
        for (uint256 i = 0; i < tokenIds.length; i++) {
            amounts[i] = 1;
        }
        _batchBurn(account, tokenIds, amounts);
        emit NFTsBurned(account, tokenIds, address(this));
    }

    function getEthSignedMessageHash(string memory _messageHash)
        public
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    _messageHash
                )
            );
    }

    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    modifier requiresWhitelist(
        string memory _messageHash,
        bytes memory signature
    ) {
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(_messageHash);
        address recoveredAddress = recoverSigner(
            ethSignedMessageHash,
            signature
        );
        require(recoveredAddress == whitelistSigningKey, "Not Whitelisted");
        _;
    }
}