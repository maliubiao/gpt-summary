Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request asks for a functional overview of the provided C++ code, its relation to JavaScript, examples of logic, common errors, debugging information, and a summary of its functions.

2. **Initial Scan for Keywords and Headers:**  Quickly look through the `#include` statements and prominent function names. This immediately tells us:
    * **Networking:**  Headers like `<cstddef>`, `<string>`, `<vector>` are general, but `openssl/*`, and the `quiche/quic/core/...` paths strongly indicate network-related cryptographic operations. Specifically, QUIC (Quick UDP Internet Connections) is the focus.
    * **Cryptography:** `openssl/bytestring.h`, `openssl/err.h`, `openssl/hkdf.h`, `openssl/mem.h`, `openssl/sha.h`, and the `quic/core/crypto` directory are clear indicators. Look for terms like "encrypt," "decrypt," "key," "IV," "HKDF," "nonce," "salt."
    * **Versioning:**  References to `ParsedQuicVersion` and `SupportedVersions()` suggest handling different versions of the QUIC protocol.
    * **Error Handling:** `QUIC_LOG(ERROR)`, `QUIC_BUG`, `QuicErrorCode` point to error and debugging mechanisms.
    * **Data Structures:** `QuicDataWriter`, `CrypterPair`, `CryptoHandshakeMessage`.

3. **Deconstruct Key Components and Their Roles:** Now, go through the code more deliberately, function by function, or by logical blocks.

    * **HKDF (HkdfExpandLabel):**  Notice this function is central and used repeatedly. Recognize that HKDF is a key derivation function. The code implements the TLS 1.3 variant. Its purpose is to securely derive cryptographic keys from a shared secret.
    * **`getLabelForVersion`:**  This function creates labels used in the HKDF process, incorporating the QUIC version. This ties the derived keys to specific protocol versions.
    * **`InitializeCrypterSecrets`, `SetKeyAndIV`, `GenerateHeaderProtectionKey`, `GenerateNextKeyPhaseSecret`:** These functions use `HkdfExpandLabel` to derive specific cryptographic materials (keys, IVs, header protection keys, key update secrets) for encryption and decryption. The consistent pattern of using labels like "key," "iv," "hp," "ku" is important.
    * **Initial Secrets and Salts:** The `kDraft29InitialSalt`, `kRFCv1InitialSalt`, etc., are constants used as initial entropy for key derivation, especially in the early stages of the QUIC handshake. The `InitialSaltForVersion` function selects the correct salt based on the QUIC version.
    * **Retry Integrity:**  The `kDraft29RetryIntegrityKey`, `kDraft29RetryIntegrityNonce`, etc., and the `ValidateRetryIntegrityTag` function are related to the QUIC retry mechanism, providing protection against certain attacks.
    * **`CreateInitialObfuscators`:**  This function sets up the initial encryption and decryption contexts using the initial secrets derived from the connection ID and salt. It uses `Aes128GcmEncrypter` and `Aes128GcmDecrypter`.
    * **`GenerateNonce`:** This function creates a nonce value, incorporating a timestamp and random data, for cryptographic purposes.
    * **`DeriveKeys`:** This is a major function for deriving cryptographic keys and setting up crypters after the initial handshake. It handles pre-shared keys (PSK) and different diversification modes. The use of `QuicHKDF` is key here.
    * **Validation Functions (`ValidateServerHello`, `ValidateClientHello`, etc.):** These functions are crucial for verifying the integrity of the QUIC handshake process and detecting potential downgrade attacks or protocol mismatches.
    * **Error Handling and Logging:** Note the consistent use of `QUIC_LOG`, `QUIC_BUG`, and `QuicErrorCode`. These are important for understanding how errors are reported.

4. **Relate to JavaScript (if applicable):**  Think about where these cryptographic operations might surface in a web browser or Node.js environment. Since QUIC is a transport protocol used by web browsers, the *effects* of this code would be visible in JavaScript, even if the implementation is in C++. Examples:
    * **`window.fetch()` or `XMLHttpRequest`:**  When these APIs are used to make HTTPS requests over QUIC, the underlying encryption/decryption handled by this C++ code ensures secure communication.
    * **WebSockets over QUIC:**  Similar to HTTPS, if WebSockets use QUIC, this code is part of the security layer.
    * **Service Workers:** If a service worker intercepts a QUIC-based request, this code is implicitly involved in securing that request.

5. **Illustrate with Logic Examples (Hypothetical):** Choose a key function, like `HkdfExpandLabel`, and provide a simple scenario. Focus on inputs and outputs.

6. **Identify Potential User/Programming Errors:**  Think about common mistakes when dealing with cryptography or networking:
    * Incorrect key sizes or IV lengths.
    * Using the wrong version.
    * Not handling handshake failures properly.
    * Mismatched client/server configurations.

7. **Outline Debugging Steps:**  Imagine you're a developer encountering an issue. How would you use this code to troubleshoot? Look for logging, error codes, and the flow of execution.

8. **Summarize the Functions:** Condense the detailed analysis into a concise list of key responsibilities.

9. **Address the "Part 1" Aspect:**  Since this is part 1 of 2, explicitly acknowledge that this part focuses on core cryptographic utilities and initial handshake elements. Anticipate that part 2 might deal with higher-level handshake logic or state management.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks complicated." **Refinement:** Break it down into smaller, manageable chunks (functions, logical blocks).
* **Initial thought:** "How does this *directly* relate to JavaScript code?" **Refinement:** Focus on the *effects* and how the security provided by this C++ code enables secure communication for web technologies accessed through JavaScript.
* **Ensuring Clarity:**  Use clear and concise language. Avoid overly technical jargon where possible, or explain it briefly. Use bullet points and formatting to improve readability.
* **Double-checking for Accuracy:**  Make sure the explanations of cryptographic concepts like HKDF are correct. Refer back to the code to verify function names and parameters.
```cpp
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/crypto_utils.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bytestring.h"
#include "openssl/err.h"
#include "openssl/hkdf.h"
#include "openssl/mem.h"
#include "openssl/sha.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_decrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_decrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_encrypter.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_hkdf.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/quiche_endian.h"

namespace quic {

namespace {

// Implements the HKDF-Expand-Label function as defined in section 7.1 of RFC
// 8446. The HKDF-Expand-Label function takes 4 explicit arguments (Secret,
// Label, Context, and Length), as well as implicit PRF which is the hash
// function negotiated by TLS. Its use in QUIC (as needed by the QUIC stack,
// instead of as used internally by the TLS stack) is only for deriving initial
// secrets for obfuscation, for calculating packet protection keys and IVs from
// the corresponding packet protection secret and key update in the same quic
// session. None of these uses need a Context (a zero-length context is
// provided), so this argument is omitted here.
//
// The implicit PRF is explicitly passed into HkdfExpandLabel as |prf|; the
// Secret, Label, and Length are passed in as |secret|, |label|, and
// |out_len|, respectively. The resulting expanded secret is returned.
std::vector<uint8_t> HkdfExpandLabel(const EVP_MD* prf,
                                     absl::Span<const uint8_t> secret,
                                     const std::string& label, size_t out_len) {
  bssl::ScopedCBB quic_hkdf_label;
  CBB inner_label;
  const char label_prefix[] = "tls13 ";
  // 20 = size(u16) + size(u8) + len("tls13 ") +
  //      max_len("client in", "server in", "quicv2 key", ... ) +
  //      size(u8);
  static const size_t max_quic_hkdf_label_length = 20;
  if (!CBB_init(quic_hkdf_label.get(), max_quic_hkdf_label_length) ||
      !CBB_add_u16(quic_hkdf_label.get(), out_len) ||
      !CBB_add_u8_length_prefixed(quic_hkdf_label.get(), &inner_label) ||
      !CBB_add_bytes(&inner_label,
                     reinterpret_cast<const uint8_t*>(label_prefix),
                     ABSL_ARRAYSIZE(label_prefix) - 1) ||
      !CBB_add_bytes(&inner_label,
                     reinterpret_cast<const uint8_t*>(label.data()),
                     label.size()) ||
      // Zero length |Context|.
      !CBB_add_u8(quic_hkdf_label.get(), 0) ||
      !CBB_flush(quic_hkdf_label.get())) {
    QUIC_LOG(ERROR) << "Building HKDF label failed";
    return std::vector<uint8_t>();
  }
  std::vector<uint8_t> out;
  out.resize(out_len);
  if (!HKDF_expand(out.data(), out_len, prf, secret.data(), secret.size(),
                   CBB_data(quic_hkdf_label.get()),
                   CBB_len(quic_hkdf_label.get()))) {
    QUIC_LOG(ERROR) << "Running HKDF-Expand-Label failed";
    return std::vector<uint8_t>();
  }
  return out;
}

}  // namespace

const std::string getLabelForVersion(const ParsedQuicVersion& version,
                                     const absl::string_view& predicate) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync with HKDF labels");
  if (version == ParsedQuicVersion::RFCv2()) {
    return absl::StrCat("quicv2 ", predicate);
  } else {
    return absl::StrCat("quic ", predicate);
  }
}

void CryptoUtils::InitializeCrypterSecrets(
    const EVP_MD* prf, const std::vector<uint8_t>& pp_secret,
    const ParsedQuicVersion& version, QuicCrypter* crypter) {
  SetKeyAndIV(prf, pp_secret, version, crypter);
  std::vector<uint8_t> header_protection_key = GenerateHeaderProtectionKey(
      prf, pp_secret, version, crypter->GetKeySize());
  crypter->SetHeaderProtectionKey(
      absl::string_view(reinterpret_cast<char*>(header_protection_key.data()),
                        header_protection_key.size()));
}

void CryptoUtils::SetKeyAndIV(const EVP_MD* prf,
                              absl::Span<const uint8_t> pp_secret,
                              const ParsedQuicVersion& version,
                              QuicCrypter* crypter) {
  std::vector<uint8_t> key =
      HkdfExpandLabel(prf, pp_secret, getLabelForVersion(version, "key"),
                      crypter->GetKeySize());
  std::vector<uint8_t> iv = HkdfExpandLabel(
      prf, pp_secret, getLabelForVersion(version, "iv"), crypter->GetIVSize());
  crypter->SetKey(
      absl::string_view(reinterpret_cast<char*>(key.data()), key.size()));
  crypter->SetIV(
      absl::string_view(reinterpret_cast<char*>(iv.data()), iv.size()));
}

std::vector<uint8_t> CryptoUtils::GenerateHeaderProtectionKey(
    const EVP_MD* prf, absl::Span<const uint8_t> pp_secret,
    const ParsedQuicVersion& version, size_t out_len) {
  return HkdfExpandLabel(prf, pp_secret, getLabelForVersion(version, "hp"),
                         out_len);
}

std::vector<uint8_t> CryptoUtils::GenerateNextKeyPhaseSecret(
    const EVP_MD* prf, const ParsedQuicVersion& version,
    const std::vector<uint8_t>& current_secret) {
  return HkdfExpandLabel(prf, current_secret, getLabelForVersion(version, "ku"),
                         current_secret.size());
}

namespace {

// Salt from https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
const uint8_t kDraft29InitialSalt[] = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2,
                                       0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                                       0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
const uint8_t kRFCv1InitialSalt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                     0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                     0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
const uint8_t kRFCv2InitialSalt[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

// Salts used by deployed versions of QUIC. When introducing a new version,
// generate a new salt by running `openssl rand -hex 20`.

// Salt to use for initial obfuscators in
// ParsedQuicVersion::ReservedForNegotiation().
const uint8_t kReservedForNegotiationSalt[] = {
    0xf9, 0x64, 0xbf, 0x45, 0x3a, 0x1f, 0x1b, 0x80, 0xa5, 0xf8,
    0x82, 0x03, 0x77, 0xd4, 0xaf, 0xca, 0x58, 0x0e, 0xe7, 0x43};

const uint8_t* InitialSaltForVersion(const ParsedQuicVersion& version,
                                     size_t* out_len) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync with initial encryption salts");
  if (version == ParsedQuicVersion::RFCv2()) {
    *out_len = ABSL_ARRAYSIZE(kRFCv2InitialSalt);
    return kRFCv2InitialSalt;
  } else if (version == ParsedQuicVersion::RFCv1()) {
    *out_len = ABSL_ARRAYSIZE(kRFCv1InitialSalt);
    return kRFCv1InitialSalt;
  } else if (version == ParsedQuicVersion::Draft29()) {
    *out_len = ABSL_ARRAYSIZE(kDraft29InitialSalt);
    return kDraft29InitialSalt;
  } else if (version == ParsedQuicVersion::ReservedForNegotiation()) {
    *out_len = ABSL_ARRAYSIZE(kReservedForNegotiationSalt);
    return kReservedForNegotiationSalt;
  }
  QUIC_BUG(quic_bug_10699_1)
      << "No initial obfuscation salt for version " << version;
  *out_len = ABSL_ARRAYSIZE(kReservedForNegotiationSalt);
  return kReservedForNegotiationSalt;
}

const char kPreSharedKeyLabel[] = "QUIC PSK";

// Retry Integrity Protection Keys and Nonces.
// https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
// When introducing a new Google version, generate a new key by running
// `openssl rand -hex 16`.
const uint8_t kDraft29RetryIntegrityKey[] = {0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a,
                                             0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a,
                                             0x6c, 0xb9, 0x6b, 0xe1};
const uint8_t kDraft29RetryIntegrityNonce[] = {
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c};
const uint8_t kRFCv1RetryIntegrityKey[] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66,
                                           0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54,
                                           0xe3, 0x68, 0xc8, 0x4e};
const uint8_t kRFCv1RetryIntegrityNonce[] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};
const uint8_t kRFCv2RetryIntegrityKey[] = {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac,
                                           0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce,
                                           0xad, 0x7c, 0xcc, 0x92};
const uint8_t kRFCv2RetryIntegrityNonce[] = {
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a};
// Retry integrity key used by ParsedQuicVersion::ReservedForNegotiation().
const uint8_t kReservedForNegotiationRetryIntegrityKey[] = {
    0xf2, 0xcd, 0x8f, 0xe0, 0x36, 0xd0, 0x25, 0x35,
    0x03, 0xe6, 0x7c, 0x7b, 0xd2, 0x44, 0xca, 0xd9};
// When introducing a new Google version, generate a new nonce by running
// `openssl rand -hex 12`.
// Retry integrity nonce used by ParsedQuicVersion::ReservedForNegotiation().
const uint8_t kReservedForNegotiationRetryIntegrityNonce[] = {
    0x35, 0x9f, 0x16, 0xd1, 0xed, 0x80, 0x90, 0x8e, 0xec, 0x85, 0xc4, 0xd6};

bool RetryIntegrityKeysForVersion(const ParsedQuicVersion& version,
                                  absl::string_view* key,
                                  absl::string_view* nonce) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync with retry integrity keys");
  if (!version.UsesTls()) {
    QUIC_BUG(quic_bug_10699_2)
        << "Attempted to get retry integrity keys for invalid version "
        << version;
    return false;
  } else if (version == ParsedQuicVersion::RFCv2()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kRFCv2RetryIntegrityKey),
        ABSL_ARRAYSIZE(kRFCv2RetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(kRFCv2RetryIntegrityNonce),
        ABSL_ARRAYSIZE(kRFCv2RetryIntegrityNonce));
    return true;
  } else if (version == ParsedQuicVersion::RFCv1()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kRFCv1RetryIntegrityKey),
        ABSL_ARRAYSIZE(kRFCv1RetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(kRFCv1RetryIntegrityNonce),
        ABSL_ARRAYSIZE(kRFCv1RetryIntegrityNonce));
    return true;
  } else if (version == ParsedQuicVersion::Draft29()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kDraft29RetryIntegrityKey),
        ABSL_ARRAYSIZE(kDraft29RetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(kDraft29RetryIntegrityNonce),
        ABSL_ARRAYSIZE(kDraft29RetryIntegrityNonce));
    return true;
  } else if (version == ParsedQuicVersion::ReservedForNegotiation()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kReservedForNegotiationRetryIntegrityKey),
        ABSL_ARRAYSIZE(kReservedForNegotiationRetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(
            kReservedForNegotiationRetryIntegrityNonce),
        ABSL_ARRAYSIZE(kReservedForNegotiationRetryIntegrityNonce));
    return true;
  }
  QUIC_BUG(quic_bug_10699_3)
      << "Attempted to get retry integrity keys for version " << version;
  return false;
}

}  // namespace

// static
void CryptoUtils::CreateInitialObfuscators(Perspective perspective,
                                           ParsedQuicVersion version,
                                           QuicConnectionId connection_id,
                                           CrypterPair* crypters) {
  QUIC_DLOG(INFO) << "Creating "
                  << (perspective == Perspective::IS_CLIENT ? "client"
                                                            : "server")
                  << " crypters for version " << version << " with CID "
                  << connection_id;
  if (!version.UsesInitialObfuscators()) {
    crypters->encrypter = std::make_unique<NullEncrypter>(perspective);
    crypters->decrypter = std::make_unique<NullDecrypter>(perspective);
    return;
  }
  QUIC_BUG_IF(quic_bug_12871_1, !QuicUtils::IsConnectionIdValidForVersion(
                                    connection_id, version.transport_version))
      << "CreateTlsInitialCrypters: attempted to use connection ID "
      << connection_id << " which is invalid with version " << version;
  const EVP_MD* hash = EVP_sha256();

  size_t salt_len;
  const uint8_t* salt = InitialSaltForVersion(version, &salt_len);
  std::vector<uint8_t> handshake_secret;
  handshake_secret.resize(EVP_MAX_MD_SIZE);
  size_t handshake_secret_len;
  const bool hkdf_extract_success =
      HKDF_extract(handshake_secret.data(), &handshake_secret_len, hash,
                   reinterpret_cast<const uint8_t*>(connection_id.data()),
                   connection_id.length(), salt, salt_len);
  QUIC_BUG_IF(quic_bug_12871_2, !hkdf_extract_success)
      << "HKDF_extract failed when creating initial crypters";
  handshake_secret.resize(handshake_secret_len);

  const std::string client_label = "client in";
  const std::string server_label = "server in";
  std::string encryption_label, decryption_label;
  if (perspective == Perspective::IS_CLIENT) {
    encryption_label = client_label;
    decryption_label = server_label;
  } else {
    encryption_label = server_label;
    decryption_label = client_label;
  }
  std::vector<uint8_t> encryption_secret = HkdfExpandLabel(
      hash, handshake_secret, encryption_label, EVP_MD_size(hash));
  crypters->encrypter = std::make_unique<Aes128GcmEncrypter>();
  InitializeCrypterSecrets(hash, encryption_secret, version,
                           crypters->encrypter.get());

  std::vector<uint8_t> decryption_secret = HkdfExpandLabel(
      hash, handshake_secret, decryption_label, EVP_MD_size(hash));
  crypters->decrypter = std::make_unique<Aes128GcmDecrypter>();
  InitializeCrypterSecrets(hash, decryption_secret, version,
                           crypters->decrypter.get());
}

// static
bool CryptoUtils::ValidateRetryIntegrityTag(
    ParsedQuicVersion version, QuicConnectionId original_connection_id,
    absl::string_view retry_without_tag, absl::string_view integrity_tag) {
  unsigned char computed_integrity_tag[kRetryIntegrityTagLength];
  if (integrity_tag.length() != ABSL_ARRAYSIZE(computed_integrity_tag)) {
    QUIC_BUG(quic_bug_10699_4)
        << "Invalid retry integrity tag length " << integrity_tag.length();
    return false;
  }
  char retry_pseudo_packet[kMaxIncomingPacketSize + 256];
  QuicDataWriter writer(ABSL_ARRAYSIZE(retry_pseudo_packet),
                        retry_pseudo_packet);
  if (!writer.WriteLengthPrefixedConnectionId(original_connection_id)) {
    QUIC_BUG(quic_bug_10699_5)
        << "Failed to write original connection ID in retry pseudo packet";
    return false;
  }
  if (!writer.WriteStringPiece(retry_without_tag)) {
    QUIC_BUG(quic_bug_10699_6)
        << "Failed to write retry without tag in retry pseudo packet";
    return false;
  }
  absl::string_view key;
  absl::string_view nonce;
  if (!RetryIntegrityKeysForVersion(version, &key, &nonce)) {
    // RetryIntegrityKeysForVersion already logs failures.
    return false;
  }
  Aes128GcmEncrypter crypter;
  crypter.SetKey(key);
  absl::string_view associated_data(writer.data(), writer.length());
  absl::string_view plaintext;  // Plaintext is empty.
  if (!crypter.Encrypt(nonce, associated_data, plaintext,
                       computed_integrity_tag)) {
    QUIC_BUG(quic_bug_10699_7) << "Failed to compute retry integrity tag";
    return false;
  }
  if (CRYPTO_memcmp(computed_integrity_tag, integrity_tag.data(),
                    ABSL_ARRAYSIZE(computed_integrity_tag)) != 0) {
    QUIC_DLOG(ERROR) << "Failed to validate retry integrity tag";
    return false;
  }
  return true;
}

// static
void CryptoUtils::GenerateNonce(QuicWallTime now, QuicRandom* random_generator,
                                absl::string_view orbit, std::string* nonce) {
  // a 4-byte timestamp + 28 random bytes.
  nonce->reserve(kNonceSize);
  nonce->resize(kNonceSize);

  uint32_t gmt_unix_time = static_cast<uint32_t>(now.ToUNIXSeconds());
  // The time in the nonce must be encoded in big-endian because the
  // strike-register depends on the nonces being ordered by time.
  (*nonce)[0] = static_cast<char>(gmt_unix_time >> 24);
  (*nonce)[1] = static_cast<char>(gmt_unix_time >> 16);
  (*nonce)[2] = static_cast<char>(gmt_unix_time >> 8);
  (*nonce)[3] = static_cast<char>(gmt_unix_time);
  size_t bytes_written = 4;

  if (orbit.size() == 8) {
    memcpy(&(*nonce)[bytes_written], orbit.data(), orbit.size());
    bytes_written += orbit.size();
  }

  random_generator->RandBytes(&(*nonce)[bytes_written],
                              kNonceSize - bytes_written);
}

// static
bool CryptoUtils::DeriveKeys(
    const ParsedQuicVersion& version, absl::string_view premaster_secret,
    QuicTag aead, absl::string_view client_nonce,
    absl::string_view server_nonce, absl::string_view pre_shared_key,
    const std::string& hkdf_input, Perspective perspective,
    Diversification diversification, CrypterPair* crypters,
    std::string* subkey_secret) {
  // If the connection is using PSK, concatenate it with the pre-master secret.
  std::unique_ptr<char[]> psk_premaster_secret;
  if (!pre_shared_key.empty()) {
    const absl::string_view label(kPreSharedKeyLabel);
    const size_t psk_premaster_secret_size = label.size() + 1 +
                                             pre_shared_key.size() + 8 +
                                             premaster_secret.size() + 8;

    psk_premaster_secret = std::make_unique<char[]>(psk_premaster_secret_size);
    QuicDataWriter writer(psk_premaster_secret_size, psk_premaster_secret.get(),
                          quiche::HOST_BYTE_ORDER);

    if (!writer.WriteStringPiece(label) || !writer.WriteUInt8(0) ||
        !writer.WriteStringPiece(pre_shared_key) ||
        !writer.WriteUInt64(pre_shared_key.size()) ||
        !writer.WriteStringPiece(premaster_secret) ||
        !writer.WriteUInt6
Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/crypto_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/crypto_utils.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bytestring.h"
#include "openssl/err.h"
#include "openssl/hkdf.h"
#include "openssl/mem.h"
#include "openssl/sha.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_decrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_decrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_encrypter.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_hkdf.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/quiche_endian.h"

namespace quic {

namespace {

// Implements the HKDF-Expand-Label function as defined in section 7.1 of RFC
// 8446. The HKDF-Expand-Label function takes 4 explicit arguments (Secret,
// Label, Context, and Length), as well as implicit PRF which is the hash
// function negotiated by TLS. Its use in QUIC (as needed by the QUIC stack,
// instead of as used internally by the TLS stack) is only for deriving initial
// secrets for obfuscation, for calculating packet protection keys and IVs from
// the corresponding packet protection secret and key update in the same quic
// session. None of these uses need a Context (a zero-length context is
// provided), so this argument is omitted here.
//
// The implicit PRF is explicitly passed into HkdfExpandLabel as |prf|; the
// Secret, Label, and Length are passed in as |secret|, |label|, and
// |out_len|, respectively. The resulting expanded secret is returned.
std::vector<uint8_t> HkdfExpandLabel(const EVP_MD* prf,
                                     absl::Span<const uint8_t> secret,
                                     const std::string& label, size_t out_len) {
  bssl::ScopedCBB quic_hkdf_label;
  CBB inner_label;
  const char label_prefix[] = "tls13 ";
  // 20 = size(u16) + size(u8) + len("tls13 ") +
  //      max_len("client in", "server in", "quicv2 key", ... ) +
  //      size(u8);
  static const size_t max_quic_hkdf_label_length = 20;
  if (!CBB_init(quic_hkdf_label.get(), max_quic_hkdf_label_length) ||
      !CBB_add_u16(quic_hkdf_label.get(), out_len) ||
      !CBB_add_u8_length_prefixed(quic_hkdf_label.get(), &inner_label) ||
      !CBB_add_bytes(&inner_label,
                     reinterpret_cast<const uint8_t*>(label_prefix),
                     ABSL_ARRAYSIZE(label_prefix) - 1) ||
      !CBB_add_bytes(&inner_label,
                     reinterpret_cast<const uint8_t*>(label.data()),
                     label.size()) ||
      // Zero length |Context|.
      !CBB_add_u8(quic_hkdf_label.get(), 0) ||
      !CBB_flush(quic_hkdf_label.get())) {
    QUIC_LOG(ERROR) << "Building HKDF label failed";
    return std::vector<uint8_t>();
  }
  std::vector<uint8_t> out;
  out.resize(out_len);
  if (!HKDF_expand(out.data(), out_len, prf, secret.data(), secret.size(),
                   CBB_data(quic_hkdf_label.get()),
                   CBB_len(quic_hkdf_label.get()))) {
    QUIC_LOG(ERROR) << "Running HKDF-Expand-Label failed";
    return std::vector<uint8_t>();
  }
  return out;
}

}  // namespace

const std::string getLabelForVersion(const ParsedQuicVersion& version,
                                     const absl::string_view& predicate) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync with HKDF labels");
  if (version == ParsedQuicVersion::RFCv2()) {
    return absl::StrCat("quicv2 ", predicate);
  } else {
    return absl::StrCat("quic ", predicate);
  }
}

void CryptoUtils::InitializeCrypterSecrets(
    const EVP_MD* prf, const std::vector<uint8_t>& pp_secret,
    const ParsedQuicVersion& version, QuicCrypter* crypter) {
  SetKeyAndIV(prf, pp_secret, version, crypter);
  std::vector<uint8_t> header_protection_key = GenerateHeaderProtectionKey(
      prf, pp_secret, version, crypter->GetKeySize());
  crypter->SetHeaderProtectionKey(
      absl::string_view(reinterpret_cast<char*>(header_protection_key.data()),
                        header_protection_key.size()));
}

void CryptoUtils::SetKeyAndIV(const EVP_MD* prf,
                              absl::Span<const uint8_t> pp_secret,
                              const ParsedQuicVersion& version,
                              QuicCrypter* crypter) {
  std::vector<uint8_t> key =
      HkdfExpandLabel(prf, pp_secret, getLabelForVersion(version, "key"),
                      crypter->GetKeySize());
  std::vector<uint8_t> iv = HkdfExpandLabel(
      prf, pp_secret, getLabelForVersion(version, "iv"), crypter->GetIVSize());
  crypter->SetKey(
      absl::string_view(reinterpret_cast<char*>(key.data()), key.size()));
  crypter->SetIV(
      absl::string_view(reinterpret_cast<char*>(iv.data()), iv.size()));
}

std::vector<uint8_t> CryptoUtils::GenerateHeaderProtectionKey(
    const EVP_MD* prf, absl::Span<const uint8_t> pp_secret,
    const ParsedQuicVersion& version, size_t out_len) {
  return HkdfExpandLabel(prf, pp_secret, getLabelForVersion(version, "hp"),
                         out_len);
}

std::vector<uint8_t> CryptoUtils::GenerateNextKeyPhaseSecret(
    const EVP_MD* prf, const ParsedQuicVersion& version,
    const std::vector<uint8_t>& current_secret) {
  return HkdfExpandLabel(prf, current_secret, getLabelForVersion(version, "ku"),
                         current_secret.size());
}

namespace {

// Salt from https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
const uint8_t kDraft29InitialSalt[] = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2,
                                       0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                                       0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
const uint8_t kRFCv1InitialSalt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                     0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                     0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
const uint8_t kRFCv2InitialSalt[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

// Salts used by deployed versions of QUIC. When introducing a new version,
// generate a new salt by running `openssl rand -hex 20`.

// Salt to use for initial obfuscators in
// ParsedQuicVersion::ReservedForNegotiation().
const uint8_t kReservedForNegotiationSalt[] = {
    0xf9, 0x64, 0xbf, 0x45, 0x3a, 0x1f, 0x1b, 0x80, 0xa5, 0xf8,
    0x82, 0x03, 0x77, 0xd4, 0xaf, 0xca, 0x58, 0x0e, 0xe7, 0x43};

const uint8_t* InitialSaltForVersion(const ParsedQuicVersion& version,
                                     size_t* out_len) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync with initial encryption salts");
  if (version == ParsedQuicVersion::RFCv2()) {
    *out_len = ABSL_ARRAYSIZE(kRFCv2InitialSalt);
    return kRFCv2InitialSalt;
  } else if (version == ParsedQuicVersion::RFCv1()) {
    *out_len = ABSL_ARRAYSIZE(kRFCv1InitialSalt);
    return kRFCv1InitialSalt;
  } else if (version == ParsedQuicVersion::Draft29()) {
    *out_len = ABSL_ARRAYSIZE(kDraft29InitialSalt);
    return kDraft29InitialSalt;
  } else if (version == ParsedQuicVersion::ReservedForNegotiation()) {
    *out_len = ABSL_ARRAYSIZE(kReservedForNegotiationSalt);
    return kReservedForNegotiationSalt;
  }
  QUIC_BUG(quic_bug_10699_1)
      << "No initial obfuscation salt for version " << version;
  *out_len = ABSL_ARRAYSIZE(kReservedForNegotiationSalt);
  return kReservedForNegotiationSalt;
}

const char kPreSharedKeyLabel[] = "QUIC PSK";

// Retry Integrity Protection Keys and Nonces.
// https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
// When introducing a new Google version, generate a new key by running
// `openssl rand -hex 16`.
const uint8_t kDraft29RetryIntegrityKey[] = {0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a,
                                             0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a,
                                             0x6c, 0xb9, 0x6b, 0xe1};
const uint8_t kDraft29RetryIntegrityNonce[] = {
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c};
const uint8_t kRFCv1RetryIntegrityKey[] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66,
                                           0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54,
                                           0xe3, 0x68, 0xc8, 0x4e};
const uint8_t kRFCv1RetryIntegrityNonce[] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};
const uint8_t kRFCv2RetryIntegrityKey[] = {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac,
                                           0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce,
                                           0xad, 0x7c, 0xcc, 0x92};
const uint8_t kRFCv2RetryIntegrityNonce[] = {
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a};
// Retry integrity key used by ParsedQuicVersion::ReservedForNegotiation().
const uint8_t kReservedForNegotiationRetryIntegrityKey[] = {
    0xf2, 0xcd, 0x8f, 0xe0, 0x36, 0xd0, 0x25, 0x35,
    0x03, 0xe6, 0x7c, 0x7b, 0xd2, 0x44, 0xca, 0xd9};
// When introducing a new Google version, generate a new nonce by running
// `openssl rand -hex 12`.
// Retry integrity nonce used by ParsedQuicVersion::ReservedForNegotiation().
const uint8_t kReservedForNegotiationRetryIntegrityNonce[] = {
    0x35, 0x9f, 0x16, 0xd1, 0xed, 0x80, 0x90, 0x8e, 0xec, 0x85, 0xc4, 0xd6};

bool RetryIntegrityKeysForVersion(const ParsedQuicVersion& version,
                                  absl::string_view* key,
                                  absl::string_view* nonce) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync with retry integrity keys");
  if (!version.UsesTls()) {
    QUIC_BUG(quic_bug_10699_2)
        << "Attempted to get retry integrity keys for invalid version "
        << version;
    return false;
  } else if (version == ParsedQuicVersion::RFCv2()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kRFCv2RetryIntegrityKey),
        ABSL_ARRAYSIZE(kRFCv2RetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(kRFCv2RetryIntegrityNonce),
        ABSL_ARRAYSIZE(kRFCv2RetryIntegrityNonce));
    return true;
  } else if (version == ParsedQuicVersion::RFCv1()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kRFCv1RetryIntegrityKey),
        ABSL_ARRAYSIZE(kRFCv1RetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(kRFCv1RetryIntegrityNonce),
        ABSL_ARRAYSIZE(kRFCv1RetryIntegrityNonce));
    return true;
  } else if (version == ParsedQuicVersion::Draft29()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kDraft29RetryIntegrityKey),
        ABSL_ARRAYSIZE(kDraft29RetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(kDraft29RetryIntegrityNonce),
        ABSL_ARRAYSIZE(kDraft29RetryIntegrityNonce));
    return true;
  } else if (version == ParsedQuicVersion::ReservedForNegotiation()) {
    *key = absl::string_view(
        reinterpret_cast<const char*>(kReservedForNegotiationRetryIntegrityKey),
        ABSL_ARRAYSIZE(kReservedForNegotiationRetryIntegrityKey));
    *nonce = absl::string_view(
        reinterpret_cast<const char*>(
            kReservedForNegotiationRetryIntegrityNonce),
        ABSL_ARRAYSIZE(kReservedForNegotiationRetryIntegrityNonce));
    return true;
  }
  QUIC_BUG(quic_bug_10699_3)
      << "Attempted to get retry integrity keys for version " << version;
  return false;
}

}  // namespace

// static
void CryptoUtils::CreateInitialObfuscators(Perspective perspective,
                                           ParsedQuicVersion version,
                                           QuicConnectionId connection_id,
                                           CrypterPair* crypters) {
  QUIC_DLOG(INFO) << "Creating "
                  << (perspective == Perspective::IS_CLIENT ? "client"
                                                            : "server")
                  << " crypters for version " << version << " with CID "
                  << connection_id;
  if (!version.UsesInitialObfuscators()) {
    crypters->encrypter = std::make_unique<NullEncrypter>(perspective);
    crypters->decrypter = std::make_unique<NullDecrypter>(perspective);
    return;
  }
  QUIC_BUG_IF(quic_bug_12871_1, !QuicUtils::IsConnectionIdValidForVersion(
                                    connection_id, version.transport_version))
      << "CreateTlsInitialCrypters: attempted to use connection ID "
      << connection_id << " which is invalid with version " << version;
  const EVP_MD* hash = EVP_sha256();

  size_t salt_len;
  const uint8_t* salt = InitialSaltForVersion(version, &salt_len);
  std::vector<uint8_t> handshake_secret;
  handshake_secret.resize(EVP_MAX_MD_SIZE);
  size_t handshake_secret_len;
  const bool hkdf_extract_success =
      HKDF_extract(handshake_secret.data(), &handshake_secret_len, hash,
                   reinterpret_cast<const uint8_t*>(connection_id.data()),
                   connection_id.length(), salt, salt_len);
  QUIC_BUG_IF(quic_bug_12871_2, !hkdf_extract_success)
      << "HKDF_extract failed when creating initial crypters";
  handshake_secret.resize(handshake_secret_len);

  const std::string client_label = "client in";
  const std::string server_label = "server in";
  std::string encryption_label, decryption_label;
  if (perspective == Perspective::IS_CLIENT) {
    encryption_label = client_label;
    decryption_label = server_label;
  } else {
    encryption_label = server_label;
    decryption_label = client_label;
  }
  std::vector<uint8_t> encryption_secret = HkdfExpandLabel(
      hash, handshake_secret, encryption_label, EVP_MD_size(hash));
  crypters->encrypter = std::make_unique<Aes128GcmEncrypter>();
  InitializeCrypterSecrets(hash, encryption_secret, version,
                           crypters->encrypter.get());

  std::vector<uint8_t> decryption_secret = HkdfExpandLabel(
      hash, handshake_secret, decryption_label, EVP_MD_size(hash));
  crypters->decrypter = std::make_unique<Aes128GcmDecrypter>();
  InitializeCrypterSecrets(hash, decryption_secret, version,
                           crypters->decrypter.get());
}

// static
bool CryptoUtils::ValidateRetryIntegrityTag(
    ParsedQuicVersion version, QuicConnectionId original_connection_id,
    absl::string_view retry_without_tag, absl::string_view integrity_tag) {
  unsigned char computed_integrity_tag[kRetryIntegrityTagLength];
  if (integrity_tag.length() != ABSL_ARRAYSIZE(computed_integrity_tag)) {
    QUIC_BUG(quic_bug_10699_4)
        << "Invalid retry integrity tag length " << integrity_tag.length();
    return false;
  }
  char retry_pseudo_packet[kMaxIncomingPacketSize + 256];
  QuicDataWriter writer(ABSL_ARRAYSIZE(retry_pseudo_packet),
                        retry_pseudo_packet);
  if (!writer.WriteLengthPrefixedConnectionId(original_connection_id)) {
    QUIC_BUG(quic_bug_10699_5)
        << "Failed to write original connection ID in retry pseudo packet";
    return false;
  }
  if (!writer.WriteStringPiece(retry_without_tag)) {
    QUIC_BUG(quic_bug_10699_6)
        << "Failed to write retry without tag in retry pseudo packet";
    return false;
  }
  absl::string_view key;
  absl::string_view nonce;
  if (!RetryIntegrityKeysForVersion(version, &key, &nonce)) {
    // RetryIntegrityKeysForVersion already logs failures.
    return false;
  }
  Aes128GcmEncrypter crypter;
  crypter.SetKey(key);
  absl::string_view associated_data(writer.data(), writer.length());
  absl::string_view plaintext;  // Plaintext is empty.
  if (!crypter.Encrypt(nonce, associated_data, plaintext,
                       computed_integrity_tag)) {
    QUIC_BUG(quic_bug_10699_7) << "Failed to compute retry integrity tag";
    return false;
  }
  if (CRYPTO_memcmp(computed_integrity_tag, integrity_tag.data(),
                    ABSL_ARRAYSIZE(computed_integrity_tag)) != 0) {
    QUIC_DLOG(ERROR) << "Failed to validate retry integrity tag";
    return false;
  }
  return true;
}

// static
void CryptoUtils::GenerateNonce(QuicWallTime now, QuicRandom* random_generator,
                                absl::string_view orbit, std::string* nonce) {
  // a 4-byte timestamp + 28 random bytes.
  nonce->reserve(kNonceSize);
  nonce->resize(kNonceSize);

  uint32_t gmt_unix_time = static_cast<uint32_t>(now.ToUNIXSeconds());
  // The time in the nonce must be encoded in big-endian because the
  // strike-register depends on the nonces being ordered by time.
  (*nonce)[0] = static_cast<char>(gmt_unix_time >> 24);
  (*nonce)[1] = static_cast<char>(gmt_unix_time >> 16);
  (*nonce)[2] = static_cast<char>(gmt_unix_time >> 8);
  (*nonce)[3] = static_cast<char>(gmt_unix_time);
  size_t bytes_written = 4;

  if (orbit.size() == 8) {
    memcpy(&(*nonce)[bytes_written], orbit.data(), orbit.size());
    bytes_written += orbit.size();
  }

  random_generator->RandBytes(&(*nonce)[bytes_written],
                              kNonceSize - bytes_written);
}

// static
bool CryptoUtils::DeriveKeys(
    const ParsedQuicVersion& version, absl::string_view premaster_secret,
    QuicTag aead, absl::string_view client_nonce,
    absl::string_view server_nonce, absl::string_view pre_shared_key,
    const std::string& hkdf_input, Perspective perspective,
    Diversification diversification, CrypterPair* crypters,
    std::string* subkey_secret) {
  // If the connection is using PSK, concatenate it with the pre-master secret.
  std::unique_ptr<char[]> psk_premaster_secret;
  if (!pre_shared_key.empty()) {
    const absl::string_view label(kPreSharedKeyLabel);
    const size_t psk_premaster_secret_size = label.size() + 1 +
                                             pre_shared_key.size() + 8 +
                                             premaster_secret.size() + 8;

    psk_premaster_secret = std::make_unique<char[]>(psk_premaster_secret_size);
    QuicDataWriter writer(psk_premaster_secret_size, psk_premaster_secret.get(),
                          quiche::HOST_BYTE_ORDER);

    if (!writer.WriteStringPiece(label) || !writer.WriteUInt8(0) ||
        !writer.WriteStringPiece(pre_shared_key) ||
        !writer.WriteUInt64(pre_shared_key.size()) ||
        !writer.WriteStringPiece(premaster_secret) ||
        !writer.WriteUInt64(premaster_secret.size()) ||
        writer.remaining() != 0) {
      return false;
    }

    premaster_secret = absl::string_view(psk_premaster_secret.get(),
                                         psk_premaster_secret_size);
  }

  crypters->encrypter = QuicEncrypter::Create(version, aead);
  crypters->decrypter = QuicDecrypter::Create(version, aead);

  size_t key_bytes = crypters->encrypter->GetKeySize();
  size_t nonce_prefix_bytes = crypters->encrypter->GetNoncePrefixSize();
  if (version.UsesInitialObfuscators()) {
    nonce_prefix_bytes = crypters->encrypter->GetIVSize();
  }
  size_t subkey_secret_bytes =
      subkey_secret == nullptr ? 0 : premaster_secret.length();

  absl::string_view nonce = client_nonce;
  std::string nonce_storage;
  if (!server_nonce.empty()) {
    nonce_storage = std::string(client_nonce) + std::string(server_nonce);
    nonce = nonce_storage;
  }

  QuicHKDF hkdf(premaster_secret, nonce, hkdf_input, key_bytes,
                nonce_prefix_bytes, subkey_secret_bytes);

  // Key derivation depends on the key diversification method being employed.
  // both the client and the server support never doing key diversification.
  // The server also supports immediate diversification, and the client
  // supports pending diversification.
  switch (diversification.mode()) {
    case Diversification::NEVER: {
      if (perspective == Perspective::IS_SERVER) {
        if (!crypters->encrypter->SetKey(hkdf.server_write_key()) ||
            !crypters->encrypter->SetNoncePrefixOrIV(version,
                                                     hkdf.server_write_iv()) ||
            !crypters->encrypter->SetHeaderProtectionKey(
                hkdf.server_hp_key()) ||
            !crypters->decrypter->SetKey(hkdf.client_write_key()) ||
            !crypters->decrypter->SetNoncePrefixOrIV(version,
                                                     hkdf.client_write_iv()) ||
            !crypters->decrypter->SetHeaderProtectionKey(
                hkdf.client_hp_key())) {
          return false;
        }
      } else {
        if (!crypters->encrypter->SetKey(hkdf.client_write_key()) ||
            !crypters->encrypter->SetNoncePrefixOrIV(version,
                                                     hkdf.client_write_iv()) ||
            !crypters->encrypter->SetHeaderProtectionKey(
                hkdf.client_hp_key()) ||
            !crypters->decrypter->SetKey(hkdf.server_write_key()) ||
            !crypters->decrypter->SetNoncePrefixOrIV(version,
                                                     hkdf.server_write_iv()) ||
            !crypters->decrypter->SetHeaderProtectionKey(
                hkdf.server_hp_key())) {
          return false;
        }
      }
      break;
    }
    case Diversification::PENDING: {
      if (perspective == Perspective::IS_SERVER) {
        QUIC_BUG(quic_bug_10699_8)
            << "Pending diversification is only for clients.";
        return false;
      }

      if (!crypters->encrypter->SetKey(hkdf.client_write_key()) ||
          !crypters->encrypter->SetNoncePrefixOrIV(version,
                                                   hkdf.client_write_iv()) ||
          !crypters->encrypter->SetHeaderProtectionKey(hkdf.client_hp_key()) ||
          !crypters->decrypter->SetPreliminaryKey(hkdf.server_write_key()) ||
          !crypters->decrypter->SetNoncePrefixOrIV(version,
                                                   hkdf.server_write_iv()) ||
          !crypters->decrypter->SetHeaderProtectionKey(hkdf.server_hp_key())) {
        return false;
      }
      break;
    }
    case Diversification::NOW: {
      if (perspective == Perspective::IS_CLIENT) {
        QUIC_BUG(quic_bug_10699_9)
            << "Immediate diversification is only for servers.";
        return false;
      }

      std::string key, nonce_prefix;
      QuicDecrypter::DiversifyPreliminaryKey(
          hkdf.server_write_key(), hkdf.server_write_iv(),
          *diversification.nonce(), key_bytes, nonce_prefix_bytes, &key,
          &nonce_prefix);
      if (!crypters->decrypter->SetKey(hkdf.client_write_key()) ||
          !crypters->decrypter->SetNoncePrefixOrIV(version,
                                                   hkdf.client_write_iv()) ||
          !crypters->decrypter->SetHeaderProtectionKey(hkdf.client_hp_key()) ||
          !crypters->encrypter->SetKey(key) ||
          !crypters->encrypter->SetNoncePrefixOrIV(version, nonce_prefix) ||
          !crypters->encrypter->SetHeaderProtectionKey(hkdf.server_hp_key())) {
        return false;
      }
      break;
    }
    default:
      QUICHE_DCHECK(false);
  }

  if (subkey_secret != nullptr) {
    *subkey_secret = std::string(hkdf.subkey_secret());
  }

  return true;
}

// static
uint64_t CryptoUtils::ComputeLeafCertHash(absl::string_view cert) {
  return QuicUtils::FNV1a_64_Hash(cert);
}

QuicErrorCode CryptoUtils::ValidateServerHello(
    const CryptoHandshakeMessage& server_hello,
    const ParsedQuicVersionVector& negotiated_versions,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);

  if (server_hello.tag() != kSHLO) {
    *error_details = "Bad tag";
    return QUIC_INVALID_CRYPTO_MESSAGE_TYPE;
  }

  QuicVersionLabelVector supported_version_labels;
  if (server_hello.GetVersionLabelList(kVER, &supported_version_labels) !=
      QUIC_NO_ERROR) {
    *error_details = "server hello missing version list";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  return ValidateServerHelloVersions(supported_version_labels,
                                     negotiated_versions, error_details);
}

QuicErrorCode CryptoUtils::ValidateServerHelloVersions(
    const QuicVersionLabelVector& server_versions,
    const ParsedQuicVersionVector& negotiated_versions,
    std::string* error_details) {
  if (!negotiated_versions.empty()) {
    bool mismatch = server_versions.size() != negotiated_versions.size();
    for (size_t i = 0; i < server_versions.size() && !mismatch; ++i) {
      mismatch =
          server_versions[i] != CreateQuicVersionLabel(negotiated_versions[i]);
    }
    // The server sent a list of supported versions, and the connection
    // reports that there was a version negotiation during the handshake.
    // Ensure that these two lists are identical.
    if (mismatch) {
      *error_details = absl::StrCat(
          "Downgrade attack detected: ServerVersions(", server_versions.size(),
          ")[", QuicVersionLabelVectorToString(server_versions, ",", 30),
          "] NegotiatedVersions(", negotiated_versions.size(), ")[",
          ParsedQuicVersionVectorToString(negotiated_versions, ",", 30), "]");
      return QUIC_VERSION_NEGOTIATION_MISMATCH;
    }
  }
  return QUIC_NO_ERROR;
}

QuicErrorCode CryptoUtils::ValidateClientHello(
    const CryptoHandshakeMessage& client_hello, ParsedQuicVersion version,
    const ParsedQuicVersionVector& supported_versions,
    std::string* error_details) {
  if (client_hello.tag() != kCHLO) {
    *error_details = "Bad tag";
    return QUIC_INVALID_CRYPTO_MESSAGE_TYPE;
  }

  // If the client's preferred version is not the version we are currently
  // speaking, then the client went through a version negotiation.  In this
  // case, we need to make sure that we actually do not support this version
  // and that it wasn't a downgrade attack.
  QuicVersionLabel client_version_label;
  if (client_hello.GetVersionLabel(kVER, &client_version_label) !=
      QUIC_NO_ERROR) {
    *error_details = "client hello missing version list";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }
  return ValidateClientHelloVersion(client_version_label, version,
                                    supported_versions, error_details);
}

QuicErrorCode CryptoUtils::ValidateClientHelloVersion(
    QuicVersionLabel client_version, ParsedQuicVersion connection_version,
    const ParsedQuicVersionVector& supported_versions,
    std::string* error_details) {
  if (client_version != CreateQuicVersionLabel(connection_version)) {
    // Check to see if |client_version| is actually on the supported versions
    // list. If not, the server doesn't support that version and it's not a
    // downgrade attack.
    for (size_t i = 0; i < supported_versions.size(); ++i) {
      if (client_version == CreateQuicVersionLabel(supported_versions[i])) {
        *error_details = absl::StrCat(
            "Downgrade attack detected: ClientVersion[",
            QuicVersionLabelToString(client_version), "] ConnectionVersion[",
            ParsedQuicVersionToString(connection_version),
            "] SupportedVersions(", supported_versions.size(), ")[",
            ParsedQuicVersionVectorToString(supported_versions, ",", 30), "]");
        return QUIC_VERSION_NEGOTIATION_MISMATCH;
      }
    }
  }
  return QUIC_NO_ERROR;
}

// static
bool CryptoUtils::ValidateChosenVersion(
    const QuicVersionLabel& version_information_chosen_version,
    const ParsedQuicVersion& session_version, std::string* error_details) {
  if (version_information_chosen_version !=
      CreateQuicVersionLabel(session_version)) {
    *error_details = absl::StrCat(
        "Detected version mismatch: version_information contained ",
        QuicVersionLabelToString(version_information_chosen_version),
        " instead of ", ParsedQuicVersionToString(session_version));
    return false;
  }
  return true;
}

// static
bool CryptoUtils::ValidateServerVersions(
    const QuicVersionLabelVector& version_information_other_versions,
    const ParsedQuicVersion& session_version,
    const ParsedQuicVersionVector& client_original_supported_versions,
    std::string* error_details) {
  if (client_original_supported_versions.empty()) {
    // We did not receive a version negotiation packet.
    return true;
  }
  // Parse the server's other versions.
  ParsedQuicVersionVector parsed_other_versions =
      ParseQuicVersionLabelVector(version_information_other_versions);
  // Find the first version that we originally supported that is listed in the
  // server's other versions.
  ParsedQuicVersion expected_version = ParsedQuicVersion::Unsupported();
  for (const ParsedQuicVersion& client_version :
       client_original_supported_versions) {
    if (std::find(parsed_other_versions.begin(), parsed_other_versions.end(),
                  client_version) != parsed_other_versions.end()) {
      expected_version = client_version;
      break;
    }
  }
  if (expected_version != session_version) {
    *error_details = absl::StrCat(
        "Downgrade attack detected: used ",
        ParsedQuicVersionToString(session_version), " but ServerVersions(",
        version_information_other_versions.size(), ")[",
        QuicVersionLabelVectorToString(version_information_other_versions, ",",
                                       30),
        "] ClientOriginalVersions(", client_original_supported_versions.size(),
        ")[",
        ParsedQuicVersionVectorToString(client_original_supported_versions, ",",
                                        30),
        "]");
    return false;
  }
  return true;
}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x

// Returns the name of the HandshakeFailureReason as a char*
// static
const char* CryptoUtils::HandshakeFailureReasonToString(
    HandshakeFailureReason reason) {
  switch (reason) {
    RETURN_STRING_LITERAL(HANDSHAKE_OK);
    RETURN_STRING_LITERAL(CLIENT_NONCE_UNKNOWN_FAILURE);
    RETURN_STRING_LITERAL(CLIENT_NONCE_INVALID_FAILURE);
    RETURN_STRING_LITERAL(CLIENT_NONCE_NOT_UNIQUE_FAILURE);
    RETURN_STRING_LITERAL(CLIENT_NONCE_INVALID_ORBIT_FAILURE);
    RETURN_STRING_LITERAL(CLIENT_NONCE_INVALID_TIME_FAILURE);
    RETURN_STRING_LITERAL(CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT);
    RETURN_STRING_LITERAL(CLIENT_NONCE_STRIKE_REGISTER_FAILURE);

    RETURN_STRING_LITERAL(SERVER_NONCE_DECRYPTION_FAILURE);
    RETURN_STRING_LITERAL(SERVER_NONCE_INVALID_FAILURE);
    RETURN_STRING_LITERAL(SERVER_NONCE_NOT_UNIQUE_FAILURE);
    RETURN_STRING_LITERAL(SERVER_NONCE_INVALID_TIME_FAILURE);
    RETURN_STRING_LITERAL(SERVER_NONCE_REQUIRED_FAILURE);

    RETURN_STRING_LITERAL(SERVER_CONFIG_INCHOATE_HELLO_FAILURE);
    RETURN_STRING_LITERAL(SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE);

    RETURN_STRING_LITERAL(SOURCE_ADDRESS_TOKEN_INVALID_FAILURE);
    RETURN_STRING_LITERAL(SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE);
    RETURN_STRING_LITERAL(SOURCE_ADDRESS_TOKEN_PARSE_FAILURE);
    RETURN_STRING_LITERAL(SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE);
    RETURN_STRING_LITERAL(SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE);
    RETURN_STRING_LITERAL(SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE);

    RETURN_STRING_LITERAL(INVALID_EXPECTED_LEAF_CERTIFICATE);
    RETURN_STRING_LITERAL(MAX_FAILURE_REASON);
  }
  // Return a default value so that we return this when |reason| doesn't match
  // any HandshakeFailureReason.. This can happen when the message by the peer
  // (attacker) has invalid reason.
  return "INVALID_HANDSHAKE_FAILURE_REASON";
}

#undef RETURN_STRING_LITERAL  // undef for jumbo builds

// static
std::string CryptoUtils::EarlyDataReasonToString(
    ssl_early_data_reason_t reason) {
  const char* reason_string = SSL_early_data_reason_string(reason);
  if (reason_string != nullptr) {
    return std::string("ssl_early_data_") + reason_string;
  }
  QUIC_BUG_IF(quic_
"""


```