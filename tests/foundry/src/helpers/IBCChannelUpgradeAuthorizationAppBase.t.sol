// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Channel, UpgradeFields, Timeout} from "../../../../contracts/proto/Channel.sol";
import {IIBCHandler} from "../../../../contracts/core/25-handler/IIBCHandler.sol";
import {IIBCModuleUpgrade} from "../../../../contracts/core/26-router/IIBCModuleUpgrade.sol";
import {AppBase} from "../../../../contracts/apps/commons/IBCAppBase.sol";

interface IIBCChannelUpgradeAuthorizationErrors {
    // ------------------- Errors ------------------- //

    error IBCChannelUpgradeAuthorizationUnauthorizedUpgrader();
    error IBCChannelUpgradeAuthorizationInvalidTimeout();
    error IBCChannelUpgradeAuthorizationInvalidConnectionHops();
    error IBCChannelUpgradeAuthorizationUpgradeAlreadyExists();
    error IBCChannelUpgradeAuthorizationUpgradeNotFound();
    error IBCChannelUpgradeAuthorizationUnauthorizedUpgrade();

    error IBCChannelUpgradeAuthorizationCannotRemoveInProgressUpgrade();
    /// @param state The current state of the channel
    error IBCChannelUpgradeAuthorizationChannelNotFlushingState(Channel.State state);
    /// @param actual The actual upgrade sequence
    error IBCChannelUpgradeAuthorizationSequenceMismatch(uint64 actual);

    error IBCChannelUpgradeAuthorizationChannelNotFound();
    error IBCChannelUpgradeAuthorizationCannotOverwriteUpgrade();
}

interface IIBCChannelUpgradeAuthorization {
    // ------------------- Data Structures ------------------- //

    /**
     * @dev Authorized upgrade data
     * @param fields Upgrade fields
     * @param timeout Absolute timeout for the upgrade
     */
    struct AuthorizedUpgrade {
        UpgradeFields.Data fields;
        Timeout.Data timeout;
    }

    /**
     * @dev Authorized transition
     * @param flushComplete Whether the upgrade is allowed to transition to the flush complete state
     */
    struct AuthorizedTransition {
        bool flushComplete;
    }

    // ------------------- Functions ------------------- //

    /**
     * @dev Returns the authorized upgrade for the given port, channel, and sequence
     */
    function getAuthorizedUpgrade(string calldata portId, string calldata channelId)
        external
        view
        returns (AuthorizedUpgrade memory);

    /**
     * @dev Authorizes an upgrade for the given port, channel, and sequence
     * @notice This function is only callable by an authorized upgrader
     * The upgrader must call this function before calling `channelUpgradeInit` or `channelUpgradeTry` of the IBC handler
     */
    function authorizeUpgrade(
        string calldata portId,
        string calldata channelId,
        UpgradeFields.Data calldata upgradeFields,
        Timeout.Data calldata timeout
    ) external;

    /**
     * @dev Authorizes the upgrade to transition to the flush complete state
     * @notice This function is only callable by an authorized upgrader
     * WARNING: Before calling this function, the upgrader must ensure that all inflight packets have been received on the receiving chain,
     * and all acknowledgements written have been acknowledged on the sending chain
     */
    function authorizeUpgradeTransitionToFlushComplete(
        string calldata portId,
        string calldata channelId,
        uint64 upgradeSequence
    ) external;

    /**
     * @dev Removes the authorized upgrade for the given port and channel
     * @notice This function is only callable by an authorized upgrader
     * @param portId Port identifier
     * @param channelId Channel identifier
     */
    function removeAuthorizedUpgrade(string calldata portId, string calldata channelId) external;
}

abstract contract IBCChannelUpgradeAuthorizationAppBase is
    AppBase,
    IIBCModuleUpgrade,
    IIBCChannelUpgradeAuthorization,
    IIBCChannelUpgradeAuthorizationErrors
{
    // ------------------- Storage ------------------- //

    /**
     * @dev Authorized upgrades for each channel
     */
    mapping(string portId => mapping(string channelId => AuthorizedUpgrade)) internal authorizedUpgrades;
    /**
     * @dev Authorized transitions for each upgrade sequence
     */
    mapping(string portId => mapping(string channelId => mapping(uint64 upgradeSequence => AuthorizedTransition)))
        internal authorizedTransitions;

    // ------------------- Modifiers ------------------- //

    /**
     * @dev Throws if the sender is not an authorized upgrader
     * @param portId Port identifier
     * @param channelId Channel identifier
     */
    modifier onlyAuthorizedUpgrader(string calldata portId, string calldata channelId) {
        if (!_isAuthorizedUpgrader(portId, channelId, _msgSender())) {
            revert IBCChannelUpgradeAuthorizationUnauthorizedUpgrader();
        }
        _;
    }

    // ------------------- Upgrade Authorization ------------------- //

    /**
     * @dev See {IIBCChannelUpgradeAuthorization-getAuthorizedUpgrade}
     */
    function getAuthorizedUpgrade(string calldata portId, string calldata channelId)
        public
        view
        virtual
        override
        returns (AuthorizedUpgrade memory)
    {
        return authorizedUpgrades[portId][channelId];
    }

    /**
     * @dev See {IIBCChannelUpgradeAuthorization-authorizeUpgrade}
     */
    function authorizeUpgrade(
        string calldata portId,
        string calldata channelId,
        UpgradeFields.Data calldata upgradeFields,
        Timeout.Data calldata timeout
    ) public virtual override onlyAuthorizedUpgrader(portId, channelId) {
        if (timeout.height.revision_number == 0 && timeout.height.revision_height == 0 && timeout.timestamp == 0) {
            revert IBCChannelUpgradeAuthorizationInvalidTimeout();
        }
        if (upgradeFields.ordering == Channel.Order.ORDER_NONE_UNSPECIFIED || upgradeFields.connection_hops.length == 0)
        {
            revert IBCChannelUpgradeAuthorizationInvalidConnectionHops();
        }
        (Channel.Data memory channel, bool found) = IIBCHandler(ibcAddress()).getChannel(portId, channelId);
        if (!found) {
            revert IBCChannelUpgradeAuthorizationChannelNotFound();
        }
        AuthorizedUpgrade storage upgrade = authorizedUpgrades[portId][channelId];
        if (upgrade.fields.connection_hops.length != 0) {
            // re-proposal is allowed as long as it does not transition to FLUSHING state yet
            if (channel.state != Channel.State.STATE_OPEN) {
                revert IBCChannelUpgradeAuthorizationCannotOverwriteUpgrade();
            }
        }
        upgrade.fields = upgradeFields;
        upgrade.timeout = timeout;
    }

    /**
     * @dev See {IIBCChannelUpgradeAuthorization-authorizeUpgradeTransitionToFlushComplete}
     */
    function authorizeUpgradeTransitionToFlushComplete(
        string calldata portId,
        string calldata channelId,
        uint64 upgradeSequence
    ) public virtual override onlyAuthorizedUpgrader(portId, channelId) {
        AuthorizedUpgrade storage upgrade = authorizedUpgrades[portId][channelId];
        if (upgrade.fields.connection_hops.length == 0) {
            revert IBCChannelUpgradeAuthorizationUpgradeNotFound();
        }
        (, bool found) = IIBCHandler(ibcAddress()).getChannelUpgrade(portId, channelId);
        if (!found) {
            revert IBCChannelUpgradeAuthorizationUpgradeNotFound();
        }
        (Channel.Data memory channel,) = IIBCHandler(ibcAddress()).getChannel(portId, channelId);
        if (channel.state != Channel.State.STATE_FLUSHING) {
            revert IBCChannelUpgradeAuthorizationChannelNotFlushingState(channel.state);
        }
        if (channel.upgrade_sequence != upgradeSequence) {
            revert IBCChannelUpgradeAuthorizationSequenceMismatch(channel.upgrade_sequence);
        }
        authorizedTransitions[portId][channelId][upgradeSequence].flushComplete = true;
    }

    /**
     * @dev See {IIBCChannelUpgradeAuthorization-removeAuthorizedUpgrade}
     */
    function removeAuthorizedUpgrade(string calldata portId, string calldata channelId)
        public
        virtual
        onlyAuthorizedUpgrader(portId, channelId)
    {
        _removeAuthorizedUpgrade(portId, channelId);
    }

    // ------------------- IIBCModuleUpgrade ------------------- //

    /**
     * @dev See {IIBCModuleUpgrade-isAuthorizedUpgrader}
     */
    function isAuthorizedUpgrader(string calldata portId, string calldata channelId, address msgSender)
        public
        view
        virtual
        override
        returns (bool)
    {
        return _isAuthorizedUpgrader(portId, channelId, msgSender);
    }

    /**
     * @dev See {IIBCModuleUpgrade-canTransitionToFlushComplete}
     */
    function canTransitionToFlushComplete(
        string calldata portId,
        string calldata channelId,
        uint64 upgradeSequence,
        address
    ) public view virtual override returns (bool) {
        return authorizedTransitions[portId][channelId][upgradeSequence].flushComplete;
    }

    /**
     * @dev See {IIBCModuleUpgrade-getUpgradeTimeout}
     */
    function getUpgradeTimeout(string calldata portId, string calldata channelId)
        public
        view
        virtual
        override
        returns (Timeout.Data memory)
    {
        if (authorizedUpgrades[portId][channelId].fields.connection_hops.length == 0) {
            revert IBCChannelUpgradeAuthorizationUpgradeNotFound();
        }
        return authorizedUpgrades[portId][channelId].timeout;
    }

    /**
     * @dev See {IIBCModuleUpgrade-onChanUpgradeInit}
     */
    function onChanUpgradeInit(
        string calldata portId,
        string calldata channelId,
        uint64,
        UpgradeFields.Data calldata proposedUpgradeFields
    ) public view virtual override onlyIBC returns (string calldata version) {
        AuthorizedUpgrade storage upgrade = authorizedUpgrades[portId][channelId];
        if (upgrade.fields.connection_hops.length == 0) {
            revert IBCChannelUpgradeAuthorizationUpgradeNotFound();
        }
        if (!equals(upgrade.fields, proposedUpgradeFields)) {
            revert IBCChannelUpgradeAuthorizationUnauthorizedUpgrade();
        }
        return proposedUpgradeFields.version;
    }

    /**
     * @dev See {IIBCModuleUpgrade-onChanUpgradeTry}
     */
    function onChanUpgradeTry(
        string calldata portId,
        string calldata channelId,
        uint64,
        UpgradeFields.Data calldata proposedUpgradeFields
    ) public view virtual override onlyIBC returns (string calldata version) {
        AuthorizedUpgrade storage upgrade = authorizedUpgrades[portId][channelId];
        if (upgrade.fields.connection_hops.length == 0) {
            revert IBCChannelUpgradeAuthorizationUpgradeNotFound();
        }
        if (!equals(upgrade.fields, proposedUpgradeFields)) {
            revert IBCChannelUpgradeAuthorizationUnauthorizedUpgrade();
        }
        return proposedUpgradeFields.version;
    }

    /**
     * @dev See {IIBCModuleUpgrade-onChanUpgradeAck}
     */
    function onChanUpgradeAck(string calldata, string calldata, uint64, string calldata counterpartyVersion)
        public
        view
        virtual
        override
        onlyIBC
    {}

    /**
     * @dev See {IIBCModuleUpgrade-onChanUpgradeOpen}
     */
    function onChanUpgradeOpen(string calldata portId, string calldata channelId, uint64 upgradeSequence)
        public
        virtual
        override
        onlyIBC
    {
        delete authorizedUpgrades[portId][channelId];
        delete authorizedTransitions[portId][channelId][upgradeSequence];
    }

    // ------------------- Internal Functions ------------------- //

    /**
     * @dev Returns whether the given address is authorized to upgrade the channel
     */
    function _isAuthorizedUpgrader(string calldata portId, string calldata channelId, address msgSender)
        internal
        view
        virtual
        returns (bool);

    /**
     * @dev Removes the authorized upgrade for the given port and channel
     */
    function _removeAuthorizedUpgrade(string calldata portId, string calldata channelId) internal {
        if (authorizedUpgrades[portId][channelId].fields.connection_hops.length == 0) {
            revert IBCChannelUpgradeAuthorizationUpgradeNotFound();
        }
        IIBCHandler handler = IIBCHandler(ibcAddress());
        (, bool found) = handler.getChannelUpgrade(portId, channelId);
        if (found) {
            Channel.Data memory channel;
            (channel, found) = handler.getChannel(portId, channelId);
            if (!found) {
                revert IBCChannelUpgradeAuthorizationChannelNotFound();
            }
            if (channel.state != Channel.State.STATE_OPEN) {
                revert IBCChannelUpgradeAuthorizationCannotRemoveInProgressUpgrade();
            }
        }
        delete authorizedUpgrades[portId][channelId];
    }

    /**
     * @dev Compares two UpgradeFields structs
     */
    function equals(UpgradeFields.Data storage a, UpgradeFields.Data calldata b) internal view returns (bool) {
        if (a.ordering != b.ordering) {
            return false;
        }
        if (a.connection_hops.length != b.connection_hops.length) {
            return false;
        }
        for (uint256 i = 0; i < a.connection_hops.length; i++) {
            if (keccak256(abi.encodePacked(a.connection_hops[i])) != keccak256(abi.encodePacked(b.connection_hops[i])))
            {
                return false;
            }
        }
        return keccak256(abi.encodePacked(a.version)) == keccak256(abi.encodePacked(b.version));
    }
}
