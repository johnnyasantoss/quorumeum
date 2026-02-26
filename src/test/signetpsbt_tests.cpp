// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signetpsbt.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(signetpsbt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signetpsbt_serialization)
{
    SignetPsbtMessage msg;
    msg.nonce = 0x1234567890ABCDEFULL;
    msg.psbt = {0x01, 0x02, 0x03, 0x04};
    msg.block_template = {0x05, 0x06, 0x07, 0x08};
    msg.signers_short_ids = {0x1111111111111111ULL, 0x2222222222222222ULL, 0x3333333333333333ULL};

    // Serialize
    DataStream ss;
    ss << msg;

    // Deserialize
    SignetPsbtMessage msg2;
    ss >> msg2;

    BOOST_CHECK_EQUAL(msg2.nonce, msg.nonce);
    BOOST_CHECK_EQUAL(msg2.psbt.size(), msg.psbt.size());
    BOOST_CHECK_EQUAL(msg2.block_template.size(), msg.block_template.size());
    BOOST_CHECK_EQUAL(msg2.signers_short_ids.size(), msg.signers_short_ids.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(msg2.psbt.begin(), msg2.psbt.end(), msg.psbt.begin(), msg.psbt.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(msg2.block_template.begin(), msg2.block_template.end(), msg.block_template.begin(), msg.block_template.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(msg2.signers_short_ids.begin(), msg2.signers_short_ids.end(), msg.signers_short_ids.begin(), msg.signers_short_ids.end());
}

BOOST_AUTO_TEST_CASE(signetpsbt_empty_data)
{
    SignetPsbtMessage msg;
    msg.nonce = 0;
    msg.psbt = {};
    msg.block_template = {};
    msg.signers_short_ids = {};

    // Serialize
    DataStream ss;
    ss << msg;

    // Deserialize
    SignetPsbtMessage msg2;
    ss >> msg2;

    BOOST_CHECK_EQUAL(msg2.nonce, 0);
    BOOST_CHECK(msg2.psbt.empty());
    BOOST_CHECK(msg2.block_template.empty());
    BOOST_CHECK(msg2.signers_short_ids.empty());
}

BOOST_AUTO_TEST_CASE(signetpsbt_large_data)
{
    SignetPsbtMessage msg;
    msg.nonce = 0xFFFFFFFFFFFFFFFFULL;
    msg.psbt = std::vector<uint8_t>(1000, 0xAB);
    msg.block_template = std::vector<uint8_t>(2000, 0xCD);
    msg.signers_short_ids = std::vector<uint64_t>(100, 0xEEEEEEEEEEEEEEEEULL);

    // Serialize
    DataStream ss;
    ss << msg;

    // Deserialize
    SignetPsbtMessage msg2;
    ss >> msg2;

    BOOST_CHECK_EQUAL(msg2.nonce, msg.nonce);
    BOOST_CHECK_EQUAL(msg2.psbt.size(), 1000);
    BOOST_CHECK_EQUAL(msg2.block_template.size(), 2000);
    BOOST_CHECK_EQUAL(msg2.signers_short_ids.size(), 100);

    BOOST_CHECK_EQUAL(msg2.psbt[0], 0xAB);
    BOOST_CHECK_EQUAL(msg2.psbt[999], 0xAB);
    BOOST_CHECK_EQUAL(msg2.block_template[0], 0xCD);
    BOOST_CHECK_EQUAL(msg2.block_template[1999], 0xCD);
    BOOST_CHECK_EQUAL(msg2.signers_short_ids[0], 0xEEEEEEEEEEEEEEEEULL);
    BOOST_CHECK_EQUAL(msg2.signers_short_ids[99], 0xEEEEEEEEEEEEEEEEULL);
}

BOOST_AUTO_TEST_SUITE_END()
