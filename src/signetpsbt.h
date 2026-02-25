// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNETPSBT_H
#define BITCOIN_SIGNETPSBT_H

#include <primitives/transaction.h>
#include <psbt.h>
#include <serialize.h>
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

#endif // BITCOIN_SIGNETPSBT_H
