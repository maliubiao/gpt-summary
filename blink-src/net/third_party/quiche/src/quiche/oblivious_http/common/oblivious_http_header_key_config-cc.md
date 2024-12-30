Response:
Let's break down the thought process for analyzing this C++ code.

**1. Understanding the Request:**

The core request is to understand the functionality of the given C++ file within the Chromium network stack, specifically concerning Oblivious HTTP. Key points to address are: its purpose, potential relation to JavaScript, logical reasoning examples (input/output), common user errors, and debugging tips.

**2. Initial Code Scan and Keyword Identification:**

I started by quickly scanning the code for prominent keywords and patterns. This immediately highlighted:

* **`ObliviousHttpHeaderKeyConfig` and `ObliviousHttpKeyConfigs`:**  These are clearly the central data structures. The names suggest configuration related to keys for Oblivious HTTP headers.
* **`EVP_HPKE_*`:** This points to the use of OpenSSL's Hybrid Public Key Encryption (HPKE) library.
* **`kem_id`, `kdf_id`, `aead_id`:** These likely represent identifiers for different cryptographic algorithms within HPKE (Key Encapsulation Mechanism, Key Derivation Function, Authenticated Encryption with Associated Data).
* **`Serialize...`, `Parse...`:**  Indicates serialization and deserialization of data, crucial for network communication.
* **`absl::StatusOr`:**  Signals functions that can return either a successful value or an error status, a common practice in modern C++.
* **`QuicheDataWriter`, `QuicheDataReader`:** These are likely utility classes for efficient byte manipulation within the Quiche library (the underlying QUIC implementation).
* **Comments referencing IETF drafts:**  This is a strong indicator of adherence to the Oblivious HTTP standardization process.

**3. Dissecting `ObliviousHttpHeaderKeyConfig`:**

This class seems to represent a single, specific configuration for an Oblivious HTTP key. I analyzed its members and methods:

* **Constructor and `Create`:**  How an instance is created, taking `key_id`, `kem_id`, `kdf_id`, and `aead_id` as parameters.
* **`ValidateKeyConfig`:**  Crucial for ensuring the provided crypto algorithms are supported. The `CheckKemId`, `CheckKdfId`, and `CheckAeadId` helper functions confirm this.
* **`GetHpkeKem`, `GetHpkeKdf`, `GetHpkeAead`:** Accessors to retrieve the OpenSSL HPKE algorithm objects based on the IDs.
* **`SerializeRecipientContextInfo`:**  Creates a byte string containing configuration information, likely used in the HPKE encapsulation process. The inclusion of `request_label` suggests its use on the server side.
* **`ParseOhttpPayloadHeader`:**  Examines the initial bytes of an OHTTP payload to verify the key configuration. This is essential for the recipient to know how to decrypt the message.
* **`SerializeOhttpPayloadHeader`:** Creates the header part of the OHTTP payload, containing the key configuration identifiers.
* **`ParseKeyIdFromObliviousHttpRequestPayload`:**  A helper function to quickly extract the `key_id` from the payload.

**4. Dissecting `ObliviousHttpKeyConfigs`:**

This class manages a *collection* of `ObliviousHttpHeaderKeyConfig` objects.

* **`ConfigMap` and `PublicKeyMap`:**  The internal storage, mapping `key_id` to a vector of configurations and to the raw public key. Using `std::greater` for `ConfigMap`'s key might suggest a preference for newer keys.
* **`ParseConcatenatedKeys`:**  Parses a serialized string containing multiple key configurations. This is how the client might receive the server's supported configurations.
* **`Create` (multiple overloads):**  Ways to create `ObliviousHttpKeyConfigs` from different input formats (a set of `OhttpKeyConfig` structs, or a single `ObliviousHttpHeaderKeyConfig` and public key).
* **`GenerateConcatenatedKeys`:**  The reverse of `ParseConcatenatedKeys`, serializing the stored configurations.
* **`PreferredConfig`:** Returns the "best" or default configuration, likely the one with the highest `key_id`.
* **`GetPublicKeyForId`:** Retrieves the public key associated with a specific `key_id`.
* **`ReadSingleKeyConfig`:**  A helper function for parsing individual key configurations from a byte stream. The structure of the serialized data is key here (key_id, kem_id, public key, length of symmetric algorithms, then the kdf/aead pairs).

**5. Identifying Relationships and Functionality:**

By analyzing the classes and their methods, I could deduce the main functionalities:

* **Configuration Management:**  Storing and managing different possible configurations for Oblivious HTTP encryption.
* **Serialization/Deserialization:** Converting configuration data to and from byte streams for network transmission.
* **Validation:** Ensuring the cryptographic parameters are valid and supported.
* **Key Management:**  Associating `key_id`s with specific crypto algorithm combinations and public keys.
* **Header Handling:**  Creating and parsing the OHTTP payload header to identify the encryption parameters used.

**6. Addressing Specific Request Points:**

* **JavaScript Relationship:**  Considered how these C++ configurations would be used in a browser context. JavaScript would likely interact with a lower-level API (provided by Chromium) that uses these configurations under the hood. The browser fetches the key configuration from the server and uses it to encrypt OHTTP requests.
* **Logical Reasoning (Input/Output):**  Developed a simple example of how `SerializeOhttpPayloadHeader` would work, taking a known configuration and demonstrating the output byte sequence.
* **User/Programming Errors:** Thought about common mistakes, like providing unsupported algorithm IDs or mismatched public key lengths.
* **Debugging:**  Imagined a scenario where an OHTTP request fails and traced back the steps, highlighting the importance of the key configuration and the checks performed by this code.

**7. Structuring the Answer:**

Finally, I organized the findings into a clear and structured answer, addressing each point of the original request. Using headings, bullet points, and code examples helps with readability and comprehension. I made sure to highlight the role of each class and its methods in the overall Oblivious HTTP process.

**Self-Correction/Refinement:**

During the process, I might have initially overlooked some details. For instance, I could have initially focused only on `ObliviousHttpHeaderKeyConfig` and missed the significance of `ObliviousHttpKeyConfigs`. Reviewing the code and noticing the interaction between these classes would lead to a more complete understanding. Similarly, double-checking the IETF draft references helped confirm the correctness of the interpretation regarding the serialization format. The `static_assert` was a helpful clue about the expected sizes of the IDs.
This C++ source file, `oblivious_http_header_key_config.cc`, within the Chromium network stack's QUIC implementation (specifically for Oblivious HTTP), defines classes and functions for managing and handling key configurations used in encrypting and decrypting HTTP headers in Oblivious HTTP (OHTTP).

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **`ObliviousHttpHeaderKeyConfig` Class:**
   - **Represents a single OHTTP key configuration:** This configuration includes:
     - `key_id_`: A single byte identifier for this key configuration.
     - `kem_id_`:  The identifier for the Key Encapsulation Mechanism (KEM) algorithm used for key exchange (e.g., X25519).
     - `kdf_id_`: The identifier for the Key Derivation Function (KDF) algorithm (e.g., HKDF-SHA256).
     - `aead_id_`: The identifier for the Authenticated Encryption with Associated Data (AEAD) algorithm (e.g., AES-128-GCM, ChaCha20-Poly1305).
   - **Creation and Validation:** Provides a `Create` method to instantiate the configuration, validating that the specified KEM, KDF, and AEAD algorithms are supported using `CheckKemId`, `CheckKdfId`, and `CheckAeadId` helper functions.
   - **Accessors for HPKE Primitives:**  Provides methods like `GetHpkeKem`, `GetHpkeKdf`, and `GetHpkeAead` to retrieve the actual OpenSSL EVP_* structures corresponding to the configured algorithms.
   - **Serialization:**
     - `SerializeRecipientContextInfo`:  Serializes the key configuration into a byte string used as part of the HPKE "info" parameter during encryption by the server. This includes the request label, key ID, and algorithm IDs.
     - `SerializeOhttpPayloadHeader`: Serializes the key configuration identifiers (`key_id`, `kem_id`, `kdf_id`, `aead_id`) into the header of an Oblivious HTTP request payload.
   - **Parsing:**
     - `ParseOhttpPayloadHeader`: Parses the header of an Oblivious HTTP request payload to extract and validate the key configuration identifiers against the expected values.
     - `ParseKeyIdFromObliviousHttpRequestPayload`: Extracts only the `key_id` from the beginning of an OHTTP request payload.

2. **`ObliviousHttpKeyConfigs` Class:**
   - **Manages a collection of OHTTP key configurations:** This is crucial because a server might support multiple key configurations, allowing clients to choose a preferred one or gracefully handle key rotation.
   - **Storage:** Uses a `ConfigMap` (a `btree_map`) to store key configurations, indexed by `key_id`, and a `PublicKeyMap` (a `flat_hash_map`) to store the raw public keys associated with each `key_id`.
   - **Parsing from Concatenated Keys:**  The `ParseConcatenatedKeys` method parses a byte string containing multiple serialized OHTTP key configurations. This is how a client learns about the server's supported configurations.
   - **Creation from Individual Configurations:** Provides `Create` methods to build the collection from a set of `OhttpKeyConfig` structs or a single configuration and its public key.
   - **Serialization to Concatenated Keys:**  The `GenerateConcatenatedKeys` method serializes all the managed key configurations into a single byte string, suitable for transmission (e.g., in an `Alt-Svc` header).
   - **Retrieval:**
     - `PreferredConfig`: Returns the preferred key configuration (likely the one with the highest `key_id`, suggesting the newest).
     - `GetPublicKeyForId`: Retrieves the public key associated with a given `key_id`.
   - **Internal Parsing Logic:** The `ReadSingleKeyConfig` method handles the parsing of a single serialized key configuration, including the public key and the list of supported symmetric algorithms.

**Relationship with JavaScript Functionality:**

This C++ code is part of the underlying network stack and is not directly written in JavaScript. However, it plays a crucial role in how JavaScript code running in a browser can utilize Oblivious HTTP. Here's the connection:

1. **Fetching Key Configurations:** When a browser initiates an OHTTP request to a server, the server needs to provide its supported key configurations. This information is often conveyed through an HTTP header like `Alt-Svc` (Alternative Services). The value of this header might contain the serialized concatenated keys generated by `ObliviousHttpKeyConfigs::GenerateConcatenatedKeys`.
2. **JavaScript API:**  JavaScript code (e.g., using the `fetch` API or a dedicated OHTTP library) would interact with browser-provided APIs that internally handle the OHTTP protocol.
3. **Internal Processing:**  The browser's network stack (where this C++ code resides) would:
   - Parse the `Alt-Svc` header (or similar mechanism) to extract the serialized key configurations using `ObliviousHttpKeyConfigs::ParseConcatenatedKeys`.
   - Store these configurations.
   - When making an OHTTP request, JavaScript would likely provide the target URL and request headers/body.
   - The browser's OHTTP implementation would use the parsed key configurations from `ObliviousHttpKeyConfigs` to:
     - Select a suitable key configuration.
     - Encapsulate the HTTP request using HPKE based on the chosen configuration (using the OpenSSL primitives accessed through this code).
     - Construct the Oblivious HTTP request payload with the appropriate header (serialized by `ObliviousHttpHeaderKeyConfig::SerializeOhttpPayloadHeader`).
4. **Server-Side Processing (Similar):** The server would also have analogous code to parse the OHTTP request header, identify the key configuration used by the client, and decrypt the encapsulated request.

**Example Illustrating JavaScript Interaction (Conceptual):**

```javascript
// (Conceptual JavaScript - actual API might differ)

async function makeObliviousRequest(url, headers, body) {
  try {
    const response = await fetch(url, {
      method: 'POST', // Or other methods
      headers: {
        'Content-Type': 'application/ohttp-req',
        // ... other headers
      },
      body: body, // The encapsulated OHTTP request body
      // ... other fetch options
    });
    // ... process the response
  } catch (error) {
    console.error("OHTTP request failed:", error);
  }
}

// (Browser's internal logic - using the C++ code)
// 1. Fetch Alt-Svc header from the server (if present).
// 2. Parse the key configurations using ObliviousHttpKeyConfigs::ParseConcatenatedKeys.
// 3. When makeObliviousRequest is called:
//    - Select a key configuration.
//    - Get the public key for that config.
//    - Use HPKE (via OpenSSL bindings) with the chosen KEM, KDF, and AEAD.
//    - Serialize the OHTTP payload header using ObliviousHttpHeaderKeyConfig.
//    - Construct the full OHTTP request body.
//    - Send the request.
```

**Logical Reasoning with Input and Output:**

**Scenario:**  A client wants to send an OHTTP request to a server. The server has advertised a single key configuration.

**Hypothetical Input (for `SerializeOhttpPayloadHeader` on the client-side):**

- `ObliviousHttpHeaderKeyConfig` object with:
  - `key_id_ = 1`
  - `kem_id_ = EVP_HPKE_DHKEM_X25519_HKDF_SHA256` (represented internally as its numerical value, let's say `0x0010`)
  - `kdf_id_ = EVP_HPKE_HKDF_SHA256` (let's say `0x0001`)
  - `aead_id_ = EVP_HPKE_AES_128_GCM` (let's say `0x0001`)

**Expected Output (from `SerializeOhttpPayloadHeader`):**

A byte string representing the serialized header:

- Byte 1: `0x01` (key_id)
- Bytes 2-3: `0x00 0x10` (kem_id, big-endian)
- Bytes 4-5: `0x00 0x01` (kdf_id, big-endian)
- Bytes 6-7: `0x00 0x01` (aead_id, big-endian)

So, the output would be the byte sequence: `0x01 0x00 0x10 0x00 0x01 0x00 0x01`.

**Hypothetical Input (for `ParseOhttpPayloadHeader` on the server-side):**

- `payload_bytes`: A byte string starting with the OHTTP header: `0x01 0x00 0x10 0x00 0x01 0x00 0x01 ... (rest of the payload)`
- The server's `ObliviousHttpHeaderKeyConfig` object corresponding to `key_id = 1` has the same algorithm IDs as above.

**Expected Output (from `ParseOhttpPayloadHeader`):**

- `absl::OkStatus()` because the parsed `key_id`, `kem_id`, `kdf_id`, and `aead_id` from the payload match the server's configuration.

**User or Programming Common Usage Errors:**

1. **Mismatched Key Configurations:**
   - **Client-side error:** If the client doesn't correctly parse or store the server's key configurations and tries to use a configuration not advertised by the server, the server's `ParseOhttpPayloadHeader` will return an error due to mismatched IDs.
   - **Server-side error:** If the server is misconfigured and advertises an incorrect key configuration or fails to handle requests with the advertised configuration, clients will be unable to establish an OHTTP connection.
2. **Incorrect Public Key:**
   - If the server provides an incorrect public key in its key configuration, the client's HPKE encapsulation will fail, or the server's decryption will fail even if the algorithm IDs match.
3. **Unsupported Algorithms:**
   - If the client or server attempts to use a KEM, KDF, or AEAD algorithm that is not supported by the other party (not listed in the `Check...Id` functions), the `Create` or parsing methods will return an error.
4. **Incorrect Serialization/Parsing:**
   - If there are bugs in the serialization or parsing logic (e.g., incorrect byte order, wrong sizes), the key configurations will not be interpreted correctly.
5. **Providing an Empty Payload:**
   - Calling `ParseOhttpPayloadHeader` with an empty `payload_bytes` will result in an `absl::InvalidArgumentError`.

**Example of a User Operation Leading to this Code (as a Debugging Clue):**

1. **User types a URL in the browser address bar that targets a website using Oblivious HTTP.**
2. **The browser's network stack initiates a connection to the server.**
3. **The server responds with an `Alt-Svc` header (or similar) advertising its OHTTP endpoint and key configurations (serialized).**
4. **The browser's OHTTP implementation in C++ (including this file) parses the `Alt-Svc` value using `ObliviousHttpKeyConfigs::ParseConcatenatedKeys`.**
5. **The user attempts to navigate to a resource on that website, triggering an OHTTP request.**
6. **The browser's OHTTP implementation selects a key configuration from the parsed `ObliviousHttpKeyConfigs`.**
7. **The `ObliviousHttpHeaderKeyConfig` object for the chosen configuration is used to serialize the OHTTP payload header using `SerializeOhttpPayloadHeader`.**
8. **The HPKE encapsulation process uses the KEM, KDF, and AEAD algorithms specified in the `ObliviousHttpHeaderKeyConfig`.**
9. **The encapsulated request is sent to the server.**
10. **On the server side, when the OHTTP request is received:**
    - The server's OHTTP implementation (also likely using similar code) extracts the initial bytes of the payload.
    - `ObliviousHttpHeaderKeyConfig::ParseKeyIdFromObliviousHttpRequestPayload` is called to quickly determine the `key_id` used by the client.
    - Based on the `key_id`, the server retrieves its corresponding `ObliviousHttpHeaderKeyConfig`.
    - `ObliviousHttpHeaderKeyConfig::ParseOhttpPayloadHeader` is called to validate that the client used a key configuration that the server supports.**
11. **If there's a mismatch in the key configuration, `ParseOhttpPayloadHeader` will return an error, which would be a point of investigation during debugging.**

By stepping through the network stack's code during an OHTTP request, a debugger would eventually reach this `oblivious_http_header_key_config.cc` file when dealing with the OHTTP header processing and key configuration management.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/oblivious_http/common/oblivious_http_header_key_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_data_writer.h"
#include "quiche/common/quiche_endian.h"

namespace quiche {
namespace {

// Size of KEM ID is 2 bytes. Refer to OHTTP Key Config in the spec,
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-06.html#name-a-single-key-configuration
constexpr size_t kSizeOfHpkeKemId = 2;

// Size of Symmetric algorithms is 2 bytes(16 bits) each.
// Refer to HPKE Symmetric Algorithms configuration in the spec,
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-06.html#name-a-single-key-configuration
constexpr size_t kSizeOfSymmetricAlgorithmHpkeKdfId = 2;
constexpr size_t kSizeOfSymmetricAlgorithmHpkeAeadId = 2;

absl::StatusOr<const EVP_HPKE_KEM*> CheckKemId(uint16_t kem_id) {
  switch (kem_id) {
    case EVP_HPKE_DHKEM_X25519_HKDF_SHA256:
      return EVP_hpke_x25519_hkdf_sha256();
    default:
      return absl::UnimplementedError("No support for this KEM ID.");
  }
}

absl::StatusOr<const EVP_HPKE_KDF*> CheckKdfId(uint16_t kdf_id) {
  switch (kdf_id) {
    case EVP_HPKE_HKDF_SHA256:
      return EVP_hpke_hkdf_sha256();
    default:
      return absl::UnimplementedError("No support for this KDF ID.");
  }
}

absl::StatusOr<const EVP_HPKE_AEAD*> CheckAeadId(uint16_t aead_id) {
  switch (aead_id) {
    case EVP_HPKE_AES_128_GCM:
      return EVP_hpke_aes_128_gcm();
    case EVP_HPKE_AES_256_GCM:
      return EVP_hpke_aes_256_gcm();
    case EVP_HPKE_CHACHA20_POLY1305:
      return EVP_hpke_chacha20_poly1305();
    default:
      return absl::UnimplementedError("No support for this AEAD ID.");
  }
}

}  // namespace

ObliviousHttpHeaderKeyConfig::ObliviousHttpHeaderKeyConfig(uint8_t key_id,
                                                           uint16_t kem_id,
                                                           uint16_t kdf_id,
                                                           uint16_t aead_id)
    : key_id_(key_id), kem_id_(kem_id), kdf_id_(kdf_id), aead_id_(aead_id) {}

absl::StatusOr<ObliviousHttpHeaderKeyConfig>
ObliviousHttpHeaderKeyConfig::Create(uint8_t key_id, uint16_t kem_id,
                                     uint16_t kdf_id, uint16_t aead_id) {
  ObliviousHttpHeaderKeyConfig instance(key_id, kem_id, kdf_id, aead_id);
  auto is_config_ok = instance.ValidateKeyConfig();
  if (!is_config_ok.ok()) {
    return is_config_ok;
  }
  return instance;
}

absl::Status ObliviousHttpHeaderKeyConfig::ValidateKeyConfig() const {
  auto supported_kem = CheckKemId(kem_id_);
  if (!supported_kem.ok()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unsupported KEM ID:", kem_id_));
  }
  auto supported_kdf = CheckKdfId(kdf_id_);
  if (!supported_kdf.ok()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unsupported KDF ID:", kdf_id_));
  }
  auto supported_aead = CheckAeadId(aead_id_);
  if (!supported_aead.ok()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unsupported AEAD ID:", aead_id_));
  }
  return absl::OkStatus();
}

const EVP_HPKE_KEM* ObliviousHttpHeaderKeyConfig::GetHpkeKem() const {
  auto kem = CheckKemId(kem_id_);
  QUICHE_CHECK_OK(kem.status());
  return kem.value();
}
const EVP_HPKE_KDF* ObliviousHttpHeaderKeyConfig::GetHpkeKdf() const {
  auto kdf = CheckKdfId(kdf_id_);
  QUICHE_CHECK_OK(kdf.status());
  return kdf.value();
}
const EVP_HPKE_AEAD* ObliviousHttpHeaderKeyConfig::GetHpkeAead() const {
  auto aead = CheckAeadId(aead_id_);
  QUICHE_CHECK_OK(aead.status());
  return aead.value();
}

std::string ObliviousHttpHeaderKeyConfig::SerializeRecipientContextInfo(
    absl::string_view request_label) const {
  uint8_t zero_byte = 0x00;
  int buf_len = request_label.size() + kHeaderLength + sizeof(zero_byte);
  std::string info(buf_len, '\0');
  QuicheDataWriter writer(info.size(), info.data());
  QUICHE_CHECK(writer.WriteStringPiece(request_label));
  QUICHE_CHECK(writer.WriteUInt8(zero_byte));  // Zero byte.
  QUICHE_CHECK(writer.WriteUInt8(key_id_));
  QUICHE_CHECK(writer.WriteUInt16(kem_id_));
  QUICHE_CHECK(writer.WriteUInt16(kdf_id_));
  QUICHE_CHECK(writer.WriteUInt16(aead_id_));
  return info;
}

/**
 * Follows IETF Ohttp spec, section 4.1 (Encapsulation of Requests).
 * https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.1-10
 */
absl::Status ObliviousHttpHeaderKeyConfig::ParseOhttpPayloadHeader(
    absl::string_view payload_bytes) const {
  if (payload_bytes.empty()) {
    return absl::InvalidArgumentError("Empty request payload.");
  }
  QuicheDataReader reader(payload_bytes);
  return ParseOhttpPayloadHeader(reader);
}

absl::Status ObliviousHttpHeaderKeyConfig::ParseOhttpPayloadHeader(
    QuicheDataReader& reader) const {
  uint8_t key_id;
  if (!reader.ReadUInt8(&key_id)) {
    return absl::InvalidArgumentError("Failed to read key_id from header.");
  }
  if (key_id != key_id_) {
    return absl::InvalidArgumentError(
        absl::StrCat("KeyID in request:", static_cast<uint16_t>(key_id),
                     " doesn't match with server's public key "
                     "configuration KeyID:",
                     static_cast<uint16_t>(key_id_)));
  }
  uint16_t kem_id;
  if (!reader.ReadUInt16(&kem_id)) {
    return absl::InvalidArgumentError("Failed to read kem_id from header.");
  }
  if (kem_id != kem_id_) {
    return absl::InvalidArgumentError(
        absl::StrCat("Received Invalid kemID:", kem_id, " Expected:", kem_id_));
  }
  uint16_t kdf_id;
  if (!reader.ReadUInt16(&kdf_id)) {
    return absl::InvalidArgumentError("Failed to read kdf_id from header.");
  }
  if (kdf_id != kdf_id_) {
    return absl::InvalidArgumentError(
        absl::StrCat("Received Invalid kdfID:", kdf_id, " Expected:", kdf_id_));
  }
  uint16_t aead_id;
  if (!reader.ReadUInt16(&aead_id)) {
    return absl::InvalidArgumentError("Failed to read aead_id from header.");
  }
  if (aead_id != aead_id_) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Received Invalid aeadID:", aead_id, " Expected:", aead_id_));
  }
  return absl::OkStatus();
}

absl::StatusOr<uint8_t>
ObliviousHttpHeaderKeyConfig::ParseKeyIdFromObliviousHttpRequestPayload(
    absl::string_view payload_bytes) {
  if (payload_bytes.empty()) {
    return absl::InvalidArgumentError("Empty request payload.");
  }
  QuicheDataReader reader(payload_bytes);
  uint8_t key_id;
  if (!reader.ReadUInt8(&key_id)) {
    return absl::InvalidArgumentError("Failed to read key_id from payload.");
  }
  return key_id;
}

std::string ObliviousHttpHeaderKeyConfig::SerializeOhttpPayloadHeader() const {
  int buf_len =
      sizeof(key_id_) + sizeof(kem_id_) + sizeof(kdf_id_) + sizeof(aead_id_);
  std::string hdr(buf_len, '\0');
  QuicheDataWriter writer(hdr.size(), hdr.data());
  QUICHE_CHECK(writer.WriteUInt8(key_id_));
  QUICHE_CHECK(writer.WriteUInt16(kem_id_));   // kemID
  QUICHE_CHECK(writer.WriteUInt16(kdf_id_));   // kdfID
  QUICHE_CHECK(writer.WriteUInt16(aead_id_));  // aeadID
  return hdr;
}

namespace {
// https://www.rfc-editor.org/rfc/rfc9180#section-7.1
absl::StatusOr<uint16_t> KeyLength(uint16_t kem_id) {
  auto supported_kem = CheckKemId(kem_id);
  if (!supported_kem.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Unsupported KEM ID:", kem_id, ". public key length is unknown."));
  }
  return EVP_HPKE_KEM_public_key_len(supported_kem.value());
}

absl::StatusOr<std::string> SerializeOhttpKeyWithPublicKey(
    uint8_t key_id, absl::string_view public_key,
    const std::vector<ObliviousHttpHeaderKeyConfig>& ohttp_configs) {
  auto ohttp_config = ohttp_configs[0];
  // Check if `ohttp_config` match spec's encoding guidelines.
  static_assert(sizeof(ohttp_config.GetHpkeKemId()) == kSizeOfHpkeKemId &&
                    sizeof(ohttp_config.GetHpkeKdfId()) ==
                        kSizeOfSymmetricAlgorithmHpkeKdfId &&
                    sizeof(ohttp_config.GetHpkeAeadId()) ==
                        kSizeOfSymmetricAlgorithmHpkeAeadId,
                "Size of HPKE IDs should match RFC specification.");

  uint16_t symmetric_algs_length =
      ohttp_configs.size() * (kSizeOfSymmetricAlgorithmHpkeKdfId +
                              kSizeOfSymmetricAlgorithmHpkeAeadId);
  int buf_len = sizeof(key_id) + kSizeOfHpkeKemId + public_key.size() +
                sizeof(symmetric_algs_length) + symmetric_algs_length;
  std::string ohttp_key_configuration(buf_len, '\0');
  QuicheDataWriter writer(ohttp_key_configuration.size(),
                          ohttp_key_configuration.data());
  if (!writer.WriteUInt8(key_id)) {
    return absl::InternalError("Failed to serialize OHTTP key.[key_id]");
  }
  if (!writer.WriteUInt16(ohttp_config.GetHpkeKemId())) {
    return absl::InternalError(
        "Failed to serialize OHTTP key.[kem_id]");  // kemID.
  }
  if (!writer.WriteStringPiece(public_key)) {
    return absl::InternalError(
        "Failed to serialize OHTTP key.[public_key]");  // Raw public key.
  }
  if (!writer.WriteUInt16(symmetric_algs_length)) {
    return absl::InternalError(
        "Failed to serialize OHTTP key.[symmetric_algs_length]");
  }
  for (const auto& item : ohttp_configs) {
    // Check if KEM ID is the same for all the configs stored in `this` for
    // given `key_id`.
    if (item.GetHpkeKemId() != ohttp_config.GetHpkeKemId()) {
      QUICHE_BUG(ohttp_key_configs_builder_parser)
          << "ObliviousHttpKeyConfigs object cannot hold ConfigMap of "
             "different KEM IDs:[ "
          << item.GetHpkeKemId() << "," << ohttp_config.GetHpkeKemId()
          << " ]for a given key_id:" << static_cast<uint16_t>(key_id);
    }
    if (!writer.WriteUInt16(item.GetHpkeKdfId())) {
      return absl::InternalError(
          "Failed to serialize OHTTP key.[kdf_id]");  // kdfID.
    }
    if (!writer.WriteUInt16(item.GetHpkeAeadId())) {
      return absl::InternalError(
          "Failed to serialize OHTTP key.[aead_id]");  // aeadID.
    }
  }
  QUICHE_DCHECK_EQ(writer.remaining(), 0u);
  return ohttp_key_configuration;
}

std::string GetDebugStringForFailedKeyConfig(
    const ObliviousHttpKeyConfigs::OhttpKeyConfig& failed_key_config) {
  std::string debug_string = "[ ";
  absl::StrAppend(&debug_string,
                  "key_id:", static_cast<uint16_t>(failed_key_config.key_id),
                  " , kem_id:", failed_key_config.kem_id,
                  ". Printing HEX formatted public_key:",
                  absl::BytesToHexString(failed_key_config.public_key));
  absl::StrAppend(&debug_string, ", symmetric_algorithms: { ");
  for (const auto& symmetric_config : failed_key_config.symmetric_algorithms) {
    absl::StrAppend(&debug_string, "{kdf_id: ", symmetric_config.kdf_id,
                    ", aead_id:", symmetric_config.aead_id, " }");
  }
  absl::StrAppend(&debug_string, " } ]");
  return debug_string;
}

// Verifies if the `key_config` contains all valid combinations of [kem_id,
// kdf_id, aead_id] that comprises Single Key configuration encoding as
// specified in
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#name-a-single-key-configuration.
absl::Status StoreKeyConfigIfValid(
    ObliviousHttpKeyConfigs::OhttpKeyConfig key_config,
    absl::btree_map<uint8_t, std::vector<ObliviousHttpHeaderKeyConfig>,
                    std::greater<uint8_t>>& configs,
    absl::flat_hash_map<uint8_t, std::string>& keys) {
  if (!CheckKemId(key_config.kem_id).ok() ||
      key_config.public_key.size() != KeyLength(key_config.kem_id).value()) {
    QUICHE_LOG(ERROR) << "Failed to process: "
                      << GetDebugStringForFailedKeyConfig(key_config);
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid key_config! [KEM ID:", key_config.kem_id, "]"));
  }
  for (const auto& symmetric_config : key_config.symmetric_algorithms) {
    if (!CheckKdfId(symmetric_config.kdf_id).ok() ||
        !CheckAeadId(symmetric_config.aead_id).ok()) {
      QUICHE_LOG(ERROR) << "Failed to process: "
                        << GetDebugStringForFailedKeyConfig(key_config);
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid key_config! [KDF ID:", symmetric_config.kdf_id,
                       ", AEAD ID:", symmetric_config.aead_id, "]"));
    }
    auto ohttp_config = ObliviousHttpHeaderKeyConfig::Create(
        key_config.key_id, key_config.kem_id, symmetric_config.kdf_id,
        symmetric_config.aead_id);
    if (ohttp_config.ok()) {
      configs[key_config.key_id].emplace_back(std::move(ohttp_config.value()));
    }
  }
  keys.emplace(key_config.key_id, std::move(key_config.public_key));
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<ObliviousHttpKeyConfigs>
ObliviousHttpKeyConfigs::ParseConcatenatedKeys(absl::string_view key_config) {
  ConfigMap configs;
  PublicKeyMap keys;
  auto reader = QuicheDataReader(key_config);
  while (!reader.IsDoneReading()) {
    absl::Status status = ReadSingleKeyConfig(reader, configs, keys);
    if (!status.ok()) return status;
  }
  return ObliviousHttpKeyConfigs(std::move(configs), std::move(keys));
}

absl::StatusOr<ObliviousHttpKeyConfigs> ObliviousHttpKeyConfigs::Create(
    absl::flat_hash_set<ObliviousHttpKeyConfigs::OhttpKeyConfig>
        ohttp_key_configs) {
  if (ohttp_key_configs.empty()) {
    return absl::InvalidArgumentError("Empty input.");
  }
  ConfigMap configs_map;
  PublicKeyMap keys_map;
  for (auto& ohttp_key_config : ohttp_key_configs) {
    auto result = StoreKeyConfigIfValid(std::move(ohttp_key_config),
                                        configs_map, keys_map);
    if (!result.ok()) {
      return result;
    }
  }
  auto oblivious_configs =
      ObliviousHttpKeyConfigs(std::move(configs_map), std::move(keys_map));
  return oblivious_configs;
}

absl::StatusOr<ObliviousHttpKeyConfigs> ObliviousHttpKeyConfigs::Create(
    const ObliviousHttpHeaderKeyConfig& single_key_config,
    absl::string_view public_key) {
  if (public_key.empty()) {
    return absl::InvalidArgumentError("Empty input.");
  }

  if (auto key_length = KeyLength(single_key_config.GetHpkeKemId());
      public_key.size() != key_length.value()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid key. Key size mismatch. Expected:", key_length.value(),
        " Actual:", public_key.size()));
  }

  ConfigMap configs;
  PublicKeyMap keys;
  uint8_t key_id = single_key_config.GetKeyId();
  keys.emplace(key_id, public_key);
  configs[key_id].emplace_back(std::move(single_key_config));
  return ObliviousHttpKeyConfigs(std::move(configs), std::move(keys));
}

absl::StatusOr<std::string> ObliviousHttpKeyConfigs::GenerateConcatenatedKeys()
    const {
  std::string concatenated_keys;
  for (const auto& [key_id, ohttp_configs] : configs_) {
    auto key = public_keys_.find(key_id);
    if (key == public_keys_.end()) {
      return absl::InternalError(
          "Failed to serialize. No public key found for key_id");
    }
    auto serialized =
        SerializeOhttpKeyWithPublicKey(key_id, key->second, ohttp_configs);
    if (!serialized.ok()) {
      return absl::InternalError("Failed to serialize OHTTP key configs.");
    }
    absl::StrAppend(&concatenated_keys, serialized.value());
  }
  return concatenated_keys;
}

ObliviousHttpHeaderKeyConfig ObliviousHttpKeyConfigs::PreferredConfig() const {
  // configs_ is forced to have at least one object during construction.
  return configs_.begin()->second.front();
}

absl::StatusOr<absl::string_view> ObliviousHttpKeyConfigs::GetPublicKeyForId(
    uint8_t key_id) const {
  auto key = public_keys_.find(key_id);
  if (key == public_keys_.end()) {
    return absl::NotFoundError("No public key found for key_id");
  }
  return key->second;
}

absl::Status ObliviousHttpKeyConfigs::ReadSingleKeyConfig(
    QuicheDataReader& reader, ConfigMap& configs, PublicKeyMap& keys) {
  uint8_t key_id;
  uint16_t kem_id;
  // First byte: key_id; next two bytes: kem_id.
  if (!reader.ReadUInt8(&key_id) || !reader.ReadUInt16(&kem_id)) {
    return absl::InvalidArgumentError("Invalid key_config!");
  }

  // Public key length depends on the kem_id.
  auto maybe_key_length = KeyLength(kem_id);
  if (!maybe_key_length.ok()) {
    return maybe_key_length.status();
  }
  const int key_length = maybe_key_length.value();
  std::string key_str(key_length, '\0');
  if (!reader.ReadBytes(key_str.data(), key_length)) {
    return absl::InvalidArgumentError("Invalid key_config!");
  }
  if (!keys.insert({key_id, std::move(key_str)}).second) {
    return absl::InvalidArgumentError("Duplicate key_id's in key_config!");
  }

  // Extract the algorithms for this public key.
  absl::string_view alg_bytes;
  // Read the 16-bit length, then read that many bytes into alg_bytes.
  if (!reader.ReadStringPiece16(&alg_bytes)) {
    return absl::InvalidArgumentError("Invalid key_config!");
  }
  QuicheDataReader sub_reader(alg_bytes);
  while (!sub_reader.IsDoneReading()) {
    uint16_t kdf_id;
    uint16_t aead_id;
    if (!sub_reader.ReadUInt16(&kdf_id) || !sub_reader.ReadUInt16(&aead_id)) {
      return absl::InvalidArgumentError("Invalid key_config!");
    }

    absl::StatusOr<ObliviousHttpHeaderKeyConfig> maybe_cfg =
        ObliviousHttpHeaderKeyConfig::Create(key_id, kem_id, kdf_id, aead_id);
    if (!maybe_cfg.ok()) {
      // TODO(kmg): Add support to ignore key types in the server response that
      // aren't supported by the client.
      return maybe_cfg.status();
    }
    configs[key_id].emplace_back(std::move(maybe_cfg.value()));
  }
  return absl::OkStatus();
}

}  // namespace quiche

"""

```