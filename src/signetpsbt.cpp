// Copyright (c) 2026-present Quorumeum Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signetpsbt.h>

#include <crypto/siphash.h>
#include <net.h>
#include <protocol.h>

#include <logging.h>

void ProcessSignetPsbt(CNode& pfrom, DataStream& vRecv)
{
    SignetPsbtMessage msg;
    vRecv >> msg;

    LogDebug(BCLog::NET, "signetpsbt: received nonce=%llu, psbt_size=%lu, block_template_size=%lu, signers_count=%lu from peer=%d\n",
        msg.nonce, msg.psbt.size(), msg.block_template.size(), msg.signers_short_ids.size(), pfrom.GetId());

    // TODO: Implement signing session management
    // For now, we only handle relay and validation

    // 1. Check if already signed - if our short_id is in the list, drop the message
    // TODO: Get our pubkey from g_descriptor, compute short_id, check if in signers_short_ids

    // 2. Validate signers: Verify every short ID matches a known federation member
    // TODO: Get federation pubkeys from g_descriptor, compute expected short_ids, validate

    // 3. Basic signature validation: Check signature count matches short_id count
    // TODO: Parse PSBT to count signatures, compare with signers_short_ids.size()
    // For now, just log a warning about the missing validation
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "signetpsbt: Full signature-to-short_id mapping validation not implemented\n");

    // 4. Relay to other peers (flood-fill, exclude sender)
    // TODO: Implement proper relay with g_connman

    // 5. TODO: Sign PSBT and append short ID (requires signing infrastructure)
    // 6. TODO: Block publication when threshold (10) reached
    // 7. TODO: Surrender - drop sessions when block found
}