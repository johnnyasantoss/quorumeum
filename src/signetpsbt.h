// Copyright (c) 2026-present Quorumeum Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNETPSBT_H
#define BITCOIN_SIGNETPSBT_H

#include <crypto/siphash.h>
#include <net.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
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

class SigningSessionManager {
public:
    void StartSession(uint64_t nonce);
    void EndSession(uint64_t nonce);
    void EndAllSessions();
    bool HasSession(uint64_t nonce) const;

private:
    std::map<uint64_t, int> m_sessions;
};

class QuorumeumManager {
public:
    QuorumeumManager();

    void SetFederationDescriptor(Descriptor* descriptor);
    void SetSigningSession(SigningSessionManager* session);

    Descriptor* federation_descriptor() { return m_federation_descriptor; }
    SigningSessionManager* signing_session() { return m_signing_session; }

    std::optional<uint64_t> GetOurShortId(uint64_t nonce) const;
    bool ValidateSigners(const SignetPsbtMessage& msg, uint64_t nonce) const;
    bool HaveSigned(const SignetPsbtMessage& msg, uint64_t nonce) const;

private:
    Descriptor* m_federation_descriptor{nullptr};
    SigningSessionManager* m_signing_session{nullptr};
};

void InitQuorumeum(Descriptor* descriptor, SigningSessionManager* session);
void ProcessSignetPsbt(CNode& pfrom, DataStream& vRecv);

#endif // BITCOIN_SIGNETPSBT_H
