// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Upgrade, UpgradeFields, Timeout} from "../../../../contracts/proto/Channel.sol";
import {IIBCChannelUpgrade} from "../../../../contracts/core/04-channel/IIBCChannelUpgrade.sol";
import {IIBCHandler} from "../../../../contracts/core/25-handler/IIBCHandler.sol";
import {IBCMockApp} from "../../../../contracts/apps/mock/IBCMockApp.sol";
import {IBCChannelUpgradeAuthorizationAppBase} from "./IBCChannelUpgradeAuthorizationAppBase.t.sol";

contract TestIBCChannelUpgradableMockApp is IBCMockApp, IBCChannelUpgradeAuthorizationAppBase {
    constructor(IIBCHandler ibcHandler_) IBCMockApp(ibcHandler_) {}

    function authorizeAndInitUpgrade(
        string calldata portId,
        string calldata channelId,
        UpgradeFields.Data calldata proposedUpgradeFields,
        Timeout.Data calldata timeout
    ) public virtual returns (uint64) {
        authorizeUpgrade(portId, channelId, proposedUpgradeFields, timeout);
        return IIBCHandler(ibcHandler).channelUpgradeInit(
            IIBCChannelUpgrade.MsgChannelUpgradeInit({
                portId: portId,
                channelId: channelId,
                proposedUpgradeFields: proposedUpgradeFields
            })
        );
    }

    function _isAuthorizedUpgrader(string calldata, string calldata, address msgSender)
        internal
        view
        override
        returns (bool)
    {
        return msgSender == owner() || msgSender == address(this);
    }
}
