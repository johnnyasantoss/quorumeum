// Copyright (c) 2026-present Quorumeum Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signetpsbt.h>

#include <common/args.h>
#include <crypto/siphash.h>
#include <net.h>
#include <protocol.h>

#include <logging.h>

#include <node/context.h>

#include <script/descriptor.h>

static constexpr int SIGNET_THRESHOLD = 10;

static uint64_t ComputeShortId(uint64_t nonce, const CPubKey& pubkey)
{
    CSipHasher hasher{nonce, 0};
    hasher.Write(std::span<const unsigned char>{pubkey.begin(), pubkey.size()});
    return hasher.Finalize();
}

static Descriptor* GetFederationDescriptor()
{
    return g_descriptor.get();
}

std::optional<uint64_t> GetOurShortId(uint64_t nonce)
{
    auto* descriptor = GetFederationDescriptor();
    if (!descriptor) {
        return std::nullopt;
    }
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> ext_pubs;
    descriptor->GetPubKeys(pubkeys, ext_pubs);
    if (pubkeys.empty()) {
        return std::nullopt;
    }
    return ComputeShortId(nonce, *pubkeys.begin());
}

static std::set<uint64_t> GetFederationShortIds(uint64_t nonce)
{
    std::set<uint64_t> short_ids;
    auto* descriptor = GetFederationDescriptor();
    if (!descriptor) {
        return short_ids;
    }
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> ext_pubs;
    descriptor->GetPubKeys(pubkeys, ext_pubs);
    for (const auto& pubkey : pubkeys) {
        short_ids.insert(ComputeShortId(nonce, pubkey));
    }
    return short_ids;
}

bool ValidateSigners(const SignetPsbtMessage& msg, uint64_t nonce)
{
    auto valid_short_ids = GetFederationShortIds(nonce);
    for (uint64_t sid : msg.signers_short_ids) {
        if (valid_short_ids.find(sid) == valid_short_ids.end()) {
            return false;
        }
    }
    return true;
}

bool HaveSigned(const SignetPsbtMessage& msg, uint64_t nonce)
{
    auto our_short_id = GetOurShortId(nonce);
    if (!our_short_id) {
        return false;
    }
    for (uint64_t sid : msg.signers_short_ids) {
        if (sid == *our_short_id) {
            return true;
        }
    }
    return false;
}

void SigningSessionManager::StartSession(uint64_t nonce)
{
    m_sessions[nonce] = 1;
    LogInfo("[federation] Signing session started for nonce=%llu (total sessions: %lu)\n", nonce, m_sessions.size());
}

void SigningSessionManager::EndSession(uint64_t nonce)
{
    m_sessions.erase(nonce);
    LogInfo("[federation] Signing session ended for nonce=%llu (remaining sessions: %lu)\n", nonce, m_sessions.size());
}

void SigningSessionManager::EndAllSessions()
{
    auto count = m_sessions.size();
    m_sessions.clear();
    LogInfo("[federation] All signing sessions surrendered (%lu sessions dropped)\n", count);
}

bool SigningSessionManager::HasSession(uint64_t nonce) const
{
    return m_sessions.find(nonce) != m_sessions.end();
}

void ProcessSignetPsbt(CNode& pfrom, DataStream& vRecv)
{
    SignetPsbtMessage msg;
    vRecv >> msg;

    LogDebug(BCLog::NET, "[federation] signetpsbt: received nonce=%llu, psbt_size=%lu, block_template_size=%lu, signers_count=%lu from peer=%d\n",
        msg.nonce, msg.psbt.size(), msg.block_template.size(), msg.signers_short_ids.size(), pfrom.GetId());

    if (HaveSigned(msg, msg.nonce)) {
        LogDebug(BCLog::NET, "[federation] signetpsbt: already signed, dropping message from peer=%d\n", pfrom.GetId());
        return;
    }

    if (!ValidateSigners(msg, msg.nonce)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "[federation] signetpsbt: invalid signers, banning peer=%d\n", pfrom.GetId());
        return;
    }

    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "[federation] signetpsbt: Full signature-to-short_id mapping validation not implemented\n");

    // TODO: Sign PSBT and append short ID
    // TODO: Relay to other peers (flood-fill, exclude sender)

    if (msg.signers_short_ids.size() >= SIGNET_THRESHOLD) {
        LogInfo("[federation] signetpsbt: threshold reached (%lu >= %d), TODO: build and publish block\n",
            msg.signers_short_ids.size(), SIGNET_THRESHOLD);
    }

    // TODO: Surrender - drop sessions when block found
}