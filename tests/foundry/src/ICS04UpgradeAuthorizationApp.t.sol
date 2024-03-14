// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./helpers/IBCTestHelper.t.sol";
import {Vm} from "forge-std/Test.sol";
import {Upgrade, UpgradeFields, Timeout} from "../../../contracts/proto/Channel.sol";
import {LocalhostClientLib} from "../../../contracts/clients/LocalhostClient.sol";
import {LocalhostHelper} from "../../../contracts/helpers/LocalhostHelper.sol";
import {IIBCChannelUpgrade} from "../../../contracts/core/04-channel/IIBCChannelUpgrade.sol";
import {TestIBCChannelUpgradableMockApp} from "./helpers/TestIBCChannelUpgradableMockApp.t.sol";
import {
    IIBCChannelUpgradeAuthorization,
    IIBCChannelUpgradeAuthorizationErrors
} from "./helpers/IBCChannelUpgradeAuthorizationAppBase.t.sol";
import {ICS04UpgradeTestHelper} from "./helpers/ICS04UpgradeTestHelper.t.sol";

contract TestICS04UpgradeAuthorizationApp is ICS04UpgradeTestHelper {
    using LocalhostHelper for TestableIBCHandler;

    string internal constant MOCK_APP_PORT = "mockapp";
    string internal constant MOCK_APP_VERSION_1 = "mockapp-1";
    string internal constant MOCK_APP_VERSION_2 = "mockapp-2";

    TestableIBCHandler ibcHandler;
    TestIBCChannelUpgradableMockApp mockApp;

    struct ChannelInfo {
        string connectionId;
        string portId;
        string channelId;
    }

    function setUp() public {
        ibcHandler = defaultIBCHandler();
        mockApp = new TestIBCChannelUpgradableMockApp(ibcHandler);
        ibcHandler.bindPort(MOCK_APP_PORT, mockApp);
        ibcHandler.registerLocalhostClient();
        ibcHandler.createLocalhostClient();
    }

    // ------------------------------ Test Cases ------------------------------ //

    function testUpgradeAuthorizationChanneNotFound() public {
        vm.expectRevert();
        mockApp.authorizeUpgrade(
            MOCK_APP_PORT,
            "channel-0",
            UpgradeFields.Data({
                ordering: Channel.Order.ORDER_UNORDERED,
                connection_hops: IBCChannelLib.buildConnectionHops("connection-0"),
                version: MOCK_APP_VERSION_1
            }),
            Timeout.Data({height: H(10), timestamp: 0})
        );
    }

    function testUpgradeAuthorizationRePropose() public {
        (ChannelInfo memory channel0,) = createMockAppLocalhostChannel(Channel.Order.ORDER_UNORDERED);
        mockApp.authorizeUpgrade(
            channel0.portId,
            channel0.channelId,
            UpgradeFields.Data({
                ordering: Channel.Order.ORDER_UNORDERED,
                connection_hops: IBCChannelLib.buildConnectionHops(channel0.connectionId),
                version: MOCK_APP_VERSION_1
            }),
            Timeout.Data({height: H(10), timestamp: 0})
        );
        mockApp.authorizeUpgrade(
            channel0.portId,
            channel0.channelId,
            UpgradeFields.Data({
                ordering: Channel.Order.ORDER_ORDERED,
                connection_hops: IBCChannelLib.buildConnectionHops(channel0.connectionId),
                version: MOCK_APP_VERSION_2
            }),
            Timeout.Data({height: H(10), timestamp: 0})
        );
        assertEq(
            abi.encode(
                UpgradeFields.Data({
                    ordering: Channel.Order.ORDER_ORDERED,
                    connection_hops: IBCChannelLib.buildConnectionHops(channel0.connectionId),
                    version: MOCK_APP_VERSION_2
                })
            ),
            abi.encode(mockApp.getAuthorizedUpgrade(channel0.portId, channel0.channelId).fields)
        );
        assertEq(
            abi.encode(Timeout.Data({height: H(10), timestamp: 0})),
            abi.encode(mockApp.getAuthorizedUpgrade(channel0.portId, channel0.channelId).timeout)
        );
    }

    function testUpgradeAuthorizationRemove() public {
        (ChannelInfo memory channel0,) = createMockAppLocalhostChannel(Channel.Order.ORDER_UNORDERED);
        vm.expectRevert(IIBCChannelUpgradeAuthorizationErrors.IBCChannelUpgradeAuthorizationUpgradeNotFound.selector);
        mockApp.removeAuthorizedUpgrade(channel0.portId, channel0.channelId);
        mockApp.authorizeUpgrade(
            channel0.portId,
            channel0.channelId,
            UpgradeFields.Data({
                ordering: Channel.Order.ORDER_UNORDERED,
                connection_hops: IBCChannelLib.buildConnectionHops(channel0.connectionId),
                version: MOCK_APP_VERSION_2
            }),
            Timeout.Data({height: H(10), timestamp: 0})
        );
        mockApp.removeAuthorizedUpgrade(channel0.portId, channel0.channelId);
        IIBCChannelUpgradeAuthorization.AuthorizedUpgrade memory upgrade =
            mockApp.getAuthorizedUpgrade(channel0.portId, channel0.channelId);
        assertEq(upgrade.fields.connection_hops.length, 0);
    }

    // ------------------------------ Helper Functions ------------------------------ //

    function createMockAppLocalhostChannel(Channel.Order ordering)
        internal
        returns (ChannelInfo memory, ChannelInfo memory)
    {
        (string memory connectionId0, string memory connectionId1) = ibcHandler.createLocalhostConnection();
        (string memory channelId0, string memory channelId1) = ibcHandler.createLocalhostChannel(
            LocalhostHelper.MsgCreateChannel({
                connectionId0: connectionId0,
                connectionId1: connectionId1,
                portId0: MOCK_APP_PORT,
                portId1: MOCK_APP_PORT,
                ordering: ordering,
                version: MOCK_APP_VERSION_1
            })
        );
        return (
            ChannelInfo({connectionId: connectionId0, portId: MOCK_APP_PORT, channelId: channelId0}),
            ChannelInfo({connectionId: connectionId1, portId: MOCK_APP_PORT, channelId: channelId1})
        );
    }
}
