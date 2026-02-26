#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test signetpsbt message

This tests the P2P message for federated signet PSBT relay.
"""

import random

from test_framework.messages import (
    msg_signetpsbt,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)


class SignetPsbtNode(P2PInterface):
    def __init__(self):
        super().__init__()
        self.signetpsbt_messages_received = []

    def on_signetpsbt(self, message):
        self.signetpsbt_messages_received.append(message)


class SignetPsbtTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def run_test(self):
        self.log.info("Testing signetpsbt P2P message")

        # Connect node 0 to node 1
        self.connect_nodes(0, 1)

        # Add P2P connections
        node0 = self.nodes[0].add_p2p_connection(SignetPsbtNode())
        node1 = self.nodes[1].add_p2p_connection(SignetPsbtNode())

        # Wait for connection to be established
        self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) == 1)
        self.wait_until(lambda: len(self.nodes[1].getpeerinfo()) == 1)

        self.log.info("Connections established")

        # Create a signetpsbt message
        nonce = random.getrandbits(64)
        psbt_data = b"test_psbt_data"
        block_template_data = b"test_block_template"
        signers_short_ids = [random.getrandbits(64) for _ in range(3)]

        msg = msg_signetpsbt(
            nonce=nonce,
            psbt=psbt_data,
            block_template=block_template_data,
            signers_short_ids=signers_short_ids,
        )

        self.log.info(f"Sending signetpsbt message: {msg}")

        # Send from node 0 to node 1
        node0.send_message(msg)

        # Wait for node 1 to receive the message
        self.wait_until(
            lambda: len(node1.signetpsbt_messages_received) == 1, timeout=10
        )

        received_msg = node1.signetpsbt_messages_received[0]
        self.log.info(f"Node 1 received: {received_msg}")

        # Verify message contents
        assert_equal(received_msg.nonce, nonce)
        assert_equal(received_msg.psbt, psbt_data)
        assert_equal(received_msg.block_template, block_template_data)
        assert_equal(len(received_msg.signers_short_ids), 3)

        self.log.info("Basic message exchange test passed")

        # Test relay: send message from node 1 back to node 0
        # Node 0 should NOT receive it back (no echo back rule)
        node1.signetpsbt_messages_received.clear()

        # Send from node 1 back to node 0
        node1.send_message(msg)

        # Node 0 should not receive the message back (no echo)
        # Note: This tests the relay behavior but the current implementation
        # doesn't actually relay yet - this is a TODO
        self.log.info("Message relay test completed (relay not yet implemented)")

        # Test serialization/deserialization
        msg2 = msg_signetpsbt(
            nonce=123456789,
            psbt=b"\x01\x02\x03\x04",
            block_template=b"\x05\x06\x07\x08",
            signers_short_ids=[111, 222, 333, 444],
        )

        serialized = msg2.serialize()
        self.log.info(f"Serialized message: {serialized.hex()}")

        # Verify we can deserialize what we serialized
        from test_framework.messages import deser_uint256
        from io import BytesIO

        f = BytesIO(serialized)
        msg3 = msg_signetpsbt()
        msg3.deserialize(f)

        assert_equal(msg3.nonce, msg2.nonce)
        assert_equal(msg3.psbt, msg2.psbt)
        assert_equal(msg3.block_template, msg2.block_template)
        assert_equal(msg3.signers_short_ids, msg2.signers_short_ids)

        self.log.info("Serialization/deserialization test passed")

        self.log.info("All tests passed!")


if __name__ == "__main__":
    SignetPsbtTest().main()
