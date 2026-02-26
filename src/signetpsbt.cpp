// Copyright (c) 2026-present Quorumeum Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signetpsbt.h>

#include <crypto/siphash.h>
#include <net.h>
#include <protocol.h>

#include <logging.h>

#include <script/descriptor.h>

static constexpr int SIGNET_THRESHOLD = 10;

static QuorumeumManager g_quorumeum;

static uint64_t ComputeShortId(uint64_t nonce, const CPubKey& pubkey)
{
    CSipHasher hasher{nonce, 0};
    hasher.Write(std::span<const unsigned char>{pubkey.begin(), pubkey.size()});
    return hasher.Finalize();
}

QuorumeumManager::QuorumeumManager() = default;

void QuorumeumManager::SetFederationDescriptor(Descriptor* descriptor)
{
    m_federation_descriptor = descriptor;
}

void QuorumeumManager::SetSigningSession(SigningSessionManager* session)
{
    m_signing_session = session;
}

void InitQuorumeum(Descriptor* descriptor, SigningSessionManager* session)
{
    g_quorumeum.SetFederationDescriptor(descriptor);
    g_quorumeum.SetSigningSession(session);
}

std::optional<uint64_t> QuorumeumManager::GetOurShortId(uint64_t nonce) const
{
    if (!m_federation_descriptor) {
        return std::nullopt;
    }
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> ext_pubs;
    m_federation_descriptor->GetPubKeys(pubkeys, ext_pubs);
    if (pubkeys.empty()) {
        return std::nullopt;
    }
    return ComputeShortId(nonce, *pubkeys.begin());
}

bool QuorumeumManager::ValidateSigners(const SignetPsbtMessage& msg, uint64_t nonce) const
{
    if (!m_federation_descriptor) {
        return false;
    }
    std::set<uint64_t> valid_short_ids;
    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> ext_pubs;
    m_federation_descriptor->GetPubKeys(pubkeys, ext_pubs);
    for (const auto& pubkey : pubkeys) {
        valid_short_ids.insert(ComputeShortId(nonce, pubkey));
    }
    for (uint64_t sid : msg.signers_short_ids) {
        if (valid_short_ids.find(sid) == valid_short_ids.end()) {
            return false;
        }
    }
    return true;
}

bool QuorumeumManager::HaveSigned(const SignetPsbtMessage& msg, uint64_t nonce) const
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

    if (g_quorumeum.HaveSigned(msg, msg.nonce)) {
        LogDebug(BCLog::NET, "[federation] signetpsbt: already signed, dropping message from peer=%d\n", pfrom.GetId());
        return;
    }

    if (!g_quorumeum.ValidateSigners(msg, msg.nonce)) {
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