// Copyright (c) 2026-present Quorumeum Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signetpsbt.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/siphash.h>
#include <logging.h>
#include <net.h>
#include <pow.h>
#include <primitives/block.h>
#include <protocol.h>
#include <psbt.h>
#include <script/script.h>
#include <validation.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

/**
 * Serialize the signet solution from a finalized PSBT.
 * Format: length-prefixed scriptSig followed by the witness stack.
 * This is the inverse of the deserialization in SignetTxs::Create (src/signet.cpp).
 */
std::vector<uint8_t> ExtractSignetSolution(const PartiallySignedTransaction& psbtx)
{
    const PSBTInput& input = psbtx.inputs.at(0);

    std::vector<uint8_t> solution;
    VectorWriter writer{solution, 0};
    writer << input.final_script_sig;
    writer << input.final_script_witness.stack;
    return solution;
}

/**
 * Embed the signet solution into the block's coinbase witness commitment
 * output and recompute the merkle root.
 * Mirrors contrib/signet/miner finish_block().
 */
bool EmbedSignetSolution(CBlock& block, const std::vector<uint8_t>& signet_solution)
{
    if (block.vtx.empty()) return false;

    const int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error,
            "signetpsbt: no witness commitment in coinbase\n");
        return false;
    }

    CMutableTransaction coinbase(*block.vtx[0]);

    std::vector<uint8_t> pushdata;
    pushdata.reserve(sizeof(SIGNET_HEADER) + signet_solution.size());
    pushdata.insert(pushdata.end(), std::begin(SIGNET_HEADER), std::end(SIGNET_HEADER));
    pushdata.insert(pushdata.end(), signet_solution.begin(), signet_solution.end());

    coinbase.vout.at(cidx).scriptPubKey << std::span<const uint8_t>{pushdata};

    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return true;
}

/**
 * Grind the block header nonce until proof-of-work is satisfied.
 * Signet difficulty is low, so a single-threaded sweep is sufficient.
 */
bool GrindBlock(CBlock& block, const Consensus::Params& consensus_params)
{
    block.nNonce = 0;
    while (block.nNonce < std::numeric_limits<uint32_t>::max()) {
        if (CheckProofOfWork(block.GetHash(), block.nBits, consensus_params)) {
            return true;
        }
        ++block.nNonce;
    }
    return CheckProofOfWork(block.GetHash(), block.nBits, consensus_params);
}

/**
 * Deserialize the block template and PSBT from a signetpsbt message,
 * finalize signatures, embed the signet solution, grind PoW, and
 * submit the block to the network via ProcessNewBlock.
 */
static bool MineAndSubmitBlock(const SignetPsbtMessage& msg, ChainstateManager& chainman)
{
    CBlock block;
    try {
        DataStream block_stream{msg.block_template};
        block_stream >> TX_WITH_WITNESS(block);
    } catch (const std::exception& e) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error,
            "signetpsbt: failed to deserialize block template: %s\n", e.what());
        return false;
    }

    PartiallySignedTransaction psbtx;
    std::string psbt_error;
    auto raw_psbt = MakeByteSpan(msg.psbt);
    if (!DecodeRawPSBT(psbtx, raw_psbt, psbt_error)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error,
            "signetpsbt: failed to decode PSBT: %s\n", psbt_error);
        return false;
    }

    if (!FinalizePSBT(psbtx)) {
        LogDebug(BCLog::NET, "signetpsbt: PSBT not yet finalizable, continuing relay\n");
        return false;
    }

    std::vector<uint8_t> signet_solution = ExtractSignetSolution(psbtx);

    if (!EmbedSignetSolution(block, signet_solution)) {
        return false;
    }

    const Consensus::Params& consensus_params = chainman.GetConsensus();

    LogPrintLevel(BCLog::NET, BCLog::Level::Info,
        "signetpsbt: grinding block nonce (height from template, nBits=0x%08x)\n", block.nBits);

    if (!GrindBlock(block, consensus_params)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error,
            "signetpsbt: nonce space exhausted without finding valid PoW\n");
        return false;
    }

    LogPrintLevel(BCLog::NET, BCLog::Level::Info,
        "signetpsbt: block solved with nNonce=%u, hash=%s\n",
        block.nNonce, block.GetHash().ToString());

    auto block_ptr = std::make_shared<const CBlock>(block);
    bool new_block{false};
    if (!chainman.ProcessNewBlock(block_ptr, /*force_processing=*/true,
            /*min_pow_checked=*/true, &new_block)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "signetpsbt: ProcessNewBlock failed\n");
        return false;
    }

    LogPrintLevel(BCLog::NET, BCLog::Level::Info,
        "signetpsbt: block submitted successfully (new=%s)\n", new_block ? "true" : "false");
    return true;
}

void ProcessSignetPsbt(CNode& pfrom, DataStream& vRecv, ChainstateManager& chainman)
{
    SignetPsbtMessage msg;
    vRecv >> msg;

    LogDebug(BCLog::NET,
        "signetpsbt: received nonce=%llu, psbt=%lu, tmpl=%lu, signers=%lu from peer=%d\n",
        msg.nonce, msg.psbt.size(), msg.block_template.size(),
        msg.signers_short_ids.size(), pfrom.GetId());

    // TODO: Implement signing session management
    // For now, we only handle relay and validation

    // 1. Check if already signed - if our short_id is in the list, drop the message
    // TODO: Get our pubkey from g_descriptor, compute short_id, check if in signers_short_ids

    // 2. Validate signers: Verify every short ID matches a known federation member
    // TODO: Get federation pubkeys from g_descriptor, compute expected short_ids, validate

    // 3. Basic signature validation: Check signature count matches short_id count
    // TODO: Parse PSBT to count signatures, compare with signers_short_ids.size()
    // For now, just log a warning about the missing validation
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning,
        "signetpsbt: Full signature-to-short_id mapping validation not implemented\n");

    // 4. Relay to other peers (flood-fill, exclude sender)
    // TODO: Implement proper relay with g_connman

    // 5. TODO: Sign PSBT and append short ID (requires signing infrastructure)

    // 6. Block publication when script is satisfiable (PSBT finalizes)
    MineAndSubmitBlock(msg, chainman);

    // 7. TODO: Surrender - drop sessions when block found
}
