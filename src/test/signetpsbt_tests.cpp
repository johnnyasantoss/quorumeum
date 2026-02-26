// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signetpsbt.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>
#include <cstdint>
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

BOOST_AUTO_TEST_CASE(grind_block_finds_valid_nonce)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& consensus = chainParams->GetConsensus();

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256{1};
    block.hashMerkleRoot = uint256{2};
    block.nTime = 1234567890;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();

    BOOST_CHECK(GrindBlock(block, consensus));
    BOOST_CHECK(CheckProofOfWork(block.GetHash(), block.nBits, consensus));
}

BOOST_AUTO_TEST_CASE(embed_signet_solution_modifies_coinbase)
{
    // Build a block with a coinbase containing a witness commitment output
    CBlock block;
    CMutableTransaction cb;
    cb.vin.emplace_back(COutPoint(), CScript{}, 0);

    std::vector<uint8_t> wc{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) wc.push_back(0xff);
    cb.vout.emplace_back(0, CScript{} << OP_RETURN << wc);
    block.vtx.push_back(MakeTransactionRef(cb));

    BOOST_CHECK_NE(GetWitnessCommitmentIndex(block), NO_WITNESS_COMMITMENT);

    size_t script_len_before = block.vtx[0]->vout[0].scriptPubKey.size();

    std::vector<uint8_t> dummy_solution{0xde, 0xad, 0xbe, 0xef};
    BOOST_CHECK(EmbedSignetSolution(block, dummy_solution));

    // Witness commitment still present
    BOOST_CHECK_NE(GetWitnessCommitmentIndex(block), NO_WITNESS_COMMITMENT);

    // scriptPubKey grew (signet header 4 bytes + solution 4 bytes + pushdata overhead)
    size_t script_len_after = block.vtx[0]->vout[0].scriptPubKey.size();
    BOOST_CHECK_GT(script_len_after, script_len_before);

    // Verify the signet header bytes are present in the output script
    const CScript& spk = block.vtx[0]->vout[0].scriptPubKey;
    std::vector<uint8_t> spk_bytes(spk.begin(), spk.end());
    bool found_header = false;
    for (size_t i = 0; i + 4 <= spk_bytes.size(); ++i) {
        if (spk_bytes[i] == 0xec && spk_bytes[i+1] == 0xc7 &&
            spk_bytes[i+2] == 0xda && spk_bytes[i+3] == 0xa2) {
            found_header = true;
            break;
        }
    }
    BOOST_CHECK(found_header);

    // Merkle root was recomputed correctly
    BOOST_CHECK_EQUAL(block.hashMerkleRoot, BlockMerkleRoot(block));
}

BOOST_AUTO_TEST_CASE(embed_signet_solution_fails_without_witness_commitment)
{
    CBlock block;
    CMutableTransaction cb;
    cb.vin.emplace_back(COutPoint(), CScript{}, 0);
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));

    BOOST_CHECK_EQUAL(GetWitnessCommitmentIndex(block), NO_WITNESS_COMMITMENT);

    uint256 merkle_before = BlockMerkleRoot(block);
    std::vector<uint8_t> dummy_solution{0xde, 0xad};
    BOOST_CHECK(!EmbedSignetSolution(block, dummy_solution));

    // Block unchanged
    BOOST_CHECK_EQUAL(BlockMerkleRoot(block), merkle_before);
}

BOOST_AUTO_TEST_CASE(extract_signet_solution_roundtrip)
{
    // Construct a PSBT with manually-set final scripts on input 0
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256{1}), 0), CScript{}, 0);
    tx.vout.emplace_back(0, CScript{} << OP_RETURN);

    PartiallySignedTransaction psbtx;
    psbtx.tx = tx;
    psbtx.inputs.resize(1);
    psbtx.outputs.resize(1);

    CScript original_script_sig = CScript{} << OP_TRUE;
    std::vector<std::vector<uint8_t>> original_stack = {{0xab, 0xcd}, {0x01, 0x02, 0x03}};

    psbtx.inputs[0].final_script_sig = original_script_sig;
    psbtx.inputs[0].final_script_witness.stack = original_stack;

    std::vector<uint8_t> solution = ExtractSignetSolution(psbtx);
    BOOST_CHECK(!solution.empty());

    // Deserialize using the same pattern as SignetTxs::Create (src/signet.cpp:102-104)
    SpanReader v{solution};
    CScript recovered_script_sig;
    std::vector<std::vector<uint8_t>> recovered_stack;
    v >> recovered_script_sig;
    v >> recovered_stack;

    BOOST_CHECK(recovered_script_sig == original_script_sig);
    BOOST_CHECK(recovered_stack == original_stack);
    BOOST_CHECK(v.empty());
}

BOOST_AUTO_TEST_SUITE_END()
