// Copyright (c) 2026-present Quorumeum Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNETPSBT_H
#define BITCOIN_SIGNETPSBT_H

#include <net.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class SignetPsbtMessage {
public:
    uint64_t nonce;
    std::vector<uint8_t> psbt;
    std::vector<uint8_t> block_template;
    std::vector<uint64_t> signers_short_ids;

    SignetPsbtMessage() = default;

    SERIALIZE_METHODS(SignetPsbtMessage, obj)
    {
        READWRITE(obj.nonce);
        READWRITE(obj.psbt);
        READWRITE(obj.block_template);
        READWRITE(Using<VectorFormatter<DefaultFormatter>>(obj.signers_short_ids));
    }
};

class CBlock;
class ChainstateManager;
namespace Consensus { struct Params; }

std::vector<uint8_t> ExtractSignetSolution(const PartiallySignedTransaction& psbtx);
bool EmbedSignetSolution(CBlock& block, const std::vector<uint8_t>& signet_solution);
bool GrindBlock(CBlock& block, const Consensus::Params& consensus_params);

void ProcessSignetPsbt(CNode& pfrom, DataStream& vRecv, ChainstateManager& chainman);

#endif // BITCOIN_SIGNETPSBT_H
