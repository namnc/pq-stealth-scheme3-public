// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @notice The ERC-5564 announcer, as deployed.
///
/// Reproduced here verbatim in shape so that gas measurements are taken against
/// the real interface rather than a bespoke contract. Both payload fields are
/// unbounded `bytes`, which is the reason a post-quantum ciphertext can be
/// carried without any protocol change: the cost is data availability, not type.
///
/// Canonical deployment: ERC-5564 defines this at a singleton address. Nothing
/// here needs redeploying for any schemeId.
contract ERC5564Announcer {
    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata
    ) external {
        emit Announcement(schemeId, stealthAddress, msg.sender, ephemeralPubKey, metadata);
    }
}
