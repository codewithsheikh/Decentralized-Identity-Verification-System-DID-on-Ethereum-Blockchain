// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DecentralizedIdentitySystem {
    struct DIDDocument {
        string id;
        string publicKey;
        string serviceEndpoint;
        bool isKYCVerified;
    }

    mapping(string => DIDDocument) private didDocuments;

    event DIDRegistered(string indexed id, string publicKey, string serviceEndpoint);
    event KYCVerified(string indexed id, bool status);

    function registerDID(
        string memory _id,
        string memory _publicKey,
        string memory _serviceEndpoint
    ) public {
        require(bytes(didDocuments[_id].id).length == 0, "DID already registered");

        didDocuments[_id] = DIDDocument({
            id: _id,
            publicKey: _publicKey,
            serviceEndpoint: _serviceEndpoint,
            isKYCVerified: false
        });

        emit DIDRegistered(_id, _publicKey, _serviceEndpoint);
    }

    function resolveDID(string memory _id) public view returns (DIDDocument memory) {
        require(bytes(didDocuments[_id].id).length != 0, "DID not registered");
        return didDocuments[_id];
    }

    function verifyKYC(string memory _id) public {
        require(bytes(didDocuments[_id].id).length != 0, "DID not registered");

        // Simulate KYC verification (In practice, this would involve external API integration)
        didDocuments[_id].isKYCVerified = true;

        emit KYCVerified(_id, true);
    }

    function verifySignature(
        bytes32 messageHash,
        bytes memory signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(messageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        return (r, s, v);
    }
}
