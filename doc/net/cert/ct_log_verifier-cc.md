Response:
Let's break down the thought process for analyzing the `ct_log_verifier.cc` file and answering the prompt.

**1. Understanding the Core Functionality:**

The first step is to read the code and understand its purpose. Keywords like `CTLogVerifier`, `Verify`, `SignedTreeHead`, `ConsistencyProof`, `AuditProof`, and the inclusion of crypto-related headers (like `crypto/openssl_util.h`) immediately suggest this file is responsible for verifying cryptographic signatures and proofs related to Certificate Transparency (CT) logs.

**2. Identifying Key Functions and Their Roles:**

Next, I'd go through the public methods of the `CTLogVerifier` class:

*   `Create()`:  This is a factory method for creating `CTLogVerifier` instances. It takes the log's public key as input, which is crucial for verification.
*   `Verify()`: This function checks if a Signed Certificate Timestamp (SCT) is valid for a given log entry. This involves verifying the signature against the log's public key.
*   `VerifySignedTreeHead()`: This verifies the signature on a Signed Tree Head (STH), which represents the state of the log at a particular point in time.
*   `VerifyConsistencyProof()`:  This crucial function verifies that two different STHs from the same log are consistent with each other. It checks that the earlier tree is indeed a prefix of the later tree.
*   `VerifyAuditProof()`:  This verifies that a specific certificate (or pre-certificate) has been included in the log represented by a given STH.

**3. Examining Supporting Private Functions:**

The private methods provide insights into the implementation details:

*   `SignatureParametersMatch()`: This checks if the hash and signature algorithms used in a signature match what's expected for the log.
*   `Init()`: This initializes the `CTLogVerifier` by parsing the public key and determining the supported signature algorithms.
*   `VerifySignature()`: This is the core signature verification function using OpenSSL.

**4. Connecting to Certificate Transparency Concepts:**

At this stage, it's important to connect the code to the broader concept of Certificate Transparency. The file's purpose is to ensure the integrity and authenticity of CT logs. This involves verifying:

*   That a log entry was indeed signed by the correct log (`Verify()`).
*   That the log's state (STH) is signed by the correct log (`VerifySignedTreeHead()`).
*   That the log's history is consistent (`VerifyConsistencyProof()`).
*   That a specific certificate is present in the log (`VerifyAuditProof()`).

**5. Identifying Potential Interactions with JavaScript:**

This is where understanding how Chrome uses the network stack comes in. JavaScript in web browsers doesn't directly interact with C++ code like this. The interaction is through the browser's internal APIs. The key connection is:

*   **Fetching SCTs:** When a website presents a certificate with embedded or provided SCTs, the browser (likely through its network stack) will need to verify those SCTs. This `CTLogVerifier` code is part of that verification process.
*   **Fetching STHs and Proofs:** Similarly, for features like CT enforcement, the browser might fetch STHs and consistency/audit proofs, which would be verified by this code.

**6. Constructing Examples and Use Cases:**

To illustrate the functionality, I'd think of concrete scenarios:

*   **SCT Verification:**  Imagine a website with an embedded SCT. The browser fetches the website, parses the certificate and SCT, and then calls the verification logic in `ct_log_verifier.cc`.
*   **Consistency Proof:** Consider a browser checking the consistency of a CT log over time. It might fetch two STHs and a consistency proof, and then use `VerifyConsistencyProof()` to validate it.
*   **Audit Proof:** When enforcing CT policy, a browser might request an audit proof for a specific certificate to confirm its inclusion in a log.

**7. Considering Potential Errors and Debugging:**

Think about common mistakes and how a developer might end up in this code:

*   **Incorrect Public Key:** Providing the wrong public key to `Create()` will lead to verification failures.
*   **Malformed SCT/STH/Proofs:** If the data received from a CT log is corrupt or malformed, the parsing or verification steps will fail.
*   **Unsupported Algorithms:** If the log uses a signature algorithm not supported by this code, verification will fail.

Debugging scenarios would involve:

*   Examining network logs to see how SCTs, STHs, and proofs are being fetched.
*   Using debugging tools to step through the `Verify*` functions and see where the verification is failing.
*   Checking the log messages (using `base/logging.h`) for error information.

**8. Structuring the Answer:**

Finally, organize the information logically, addressing each point in the prompt:

*   Start with a clear summary of the file's core purpose.
*   List the key functions and their specific roles.
*   Explain the relationship to JavaScript (through browser APIs and fetching/verifying CT data).
*   Provide concrete examples with assumptions, inputs, and expected outputs.
*   Discuss common user/programming errors.
*   Outline a debugging scenario, tracing user actions to the relevant code.

**Self-Correction/Refinement during the process:**

*   Initially, I might focus too much on the cryptographic details. I need to remember the prompt also asks about the *user* and *JavaScript* aspects.
*   I should avoid jargon where possible, or at least explain technical terms clearly.
*   The examples should be simple and illustrative, not overly complex.
*   When discussing debugging, focus on the *flow* of user interaction and how that leads to this code.

By following this thought process, I can construct a comprehensive and accurate answer to the prompt, covering all the requested aspects.
这个 `net/cert/ct_log_verifier.cc` 文件是 Chromium 网络栈中负责验证 **Certificate Transparency (CT) 日志** 的关键组件。它的主要功能是确保从 CT 日志收到的信息是可信的，并且来自已知的、可信的 CT 日志服务器。

以下是其功能的详细列表：

**核心功能：验证 CT 日志数据的真实性和完整性**

1. **验证签名 (VerifySignature):**  使用 CT 日志的公钥，验证从日志服务器接收到的数据的数字签名，例如 Signed Certificate Timestamp (SCT) 和 Signed Tree Head (STH)。这确保了数据是由对应的日志服务器签名，而不是伪造的。
2. **验证签名参数 (SignatureParametersMatch):** 检查签名中使用的哈希算法和签名算法是否与日志的公钥类型匹配。这有助于防止使用错误的公钥进行验证。
3. **验证已签名证书时间戳 (Verify):** 验证 SCT 的有效性，包括日志 ID 是否匹配，签名是否正确，以及时间戳是否在合理范围内。
4. **验证已签名树头 (VerifySignedTreeHead):** 验证 STH 的有效性，包括签名是否正确，以及根哈希是否与树的大小一致（对于空树的情况）。STH 提供了日志当前状态的加密摘要。
5. **验证一致性证明 (VerifyConsistencyProof):**  验证两个不同大小的树头之间的一致性证明。这确保了日志的历史是一致的，没有发生回滚或其他恶意操作。它证明了较小的树是较大树的前缀。
6. **验证审计证明 (VerifyAuditProof):** 验证一个特定的证书（或预证书）是否被包含在由特定树头代表的日志中。这允许客户端确认证书是否已成功提交到 CT 日志。

**辅助功能:**

7. **创建 CTLogVerifier 对象 (Create):** 提供一个静态方法来创建 `CTLogVerifier` 对象，需要提供 CT 日志的公钥和描述信息。
8. **初始化 (Init):**  解析提供的公钥，并确定其类型（RSA 或 ECDSA）和相应的哈希和签名算法。
9. **内部哈希计算 (ct::internal::HashNodes):**  用于在验证一致性证明和审计证明时计算 Merkle 树的节点哈希值。
10. **处理空树根哈希:** 特殊处理树大小为 0 的情况，验证其根哈希是否为预定义的空字符串的 SHA-256 哈希。

**与 JavaScript 功能的关系：间接关联**

`ct_log_verifier.cc` 是 C++ 代码，JavaScript 本身无法直接调用它。但是，它在浏览器安全机制中扮演着至关重要的角色，而这些机制最终会影响到 JavaScript 代码的行为。

**举例说明:**

当一个网站使用 HTTPS 连接时，浏览器会检查服务器提供的证书是否满足 Certificate Transparency 的要求。这可能涉及到：

1. **获取 SCTs:** 浏览器可能会从服务器的 TLS 握手中，或者通过 OCSP Stapling 或 TLS 扩展获取 SCTs。
2. **验证 SCTs:**  浏览器内部的网络栈会使用 `CTLogVerifier` 来验证这些 SCTs 的签名，确保它们来自可信的 CT 日志。
3. **CT Policy 执行:**  如果浏览器配置了强制执行 CT 策略，那么 `CTLogVerifier` 的验证结果将决定连接是否被允许。

**如果验证失败:**

*   **JavaScript 可见的影响:**  如果 SCT 验证失败，浏览器可能会显示警告信息，甚至阻止网站的加载。这会直接影响到网页的 JavaScript 代码的执行，因为它可能根本无法运行。
*   **开发者工具:** 开发者可以通过浏览器的开发者工具（例如 Chrome 的 "Security" 面板）查看 CT 相关的错误信息，这些信息可能源自 `CTLogVerifier` 的验证失败。

**假设输入与输出 (逻辑推理):**

**场景：验证一个 SCT**

*   **假设输入:**
    *   `entry`: 一个 `ct::SignedEntryData` 对象，代表被记录的证书信息。
    *   `sct`: 一个 `ct::SignedCertificateTimestamp` 对象，包含日志 ID、时间戳、扩展和签名信息。
    *   `public_key`:  对应 CT 日志的公钥（在 `CTLogVerifier` 初始化时加载）。

*   **内部处理步骤:**
    1. `CTLogVerifier::Verify()` 被调用。
    2. 检查 `sct.log_id` 是否与 `CTLogVerifier` 实例关联的日志 ID 匹配。
    3. 检查 `sct.signature` 的哈希算法和签名算法是否与日志的公钥类型匹配。
    4. 序列化 `entry` 和 `sct` 的相关数据，形成待签名的数据。
    5. 调用 `VerifySignature()`，使用日志的公钥验证 `sct.signature.signature_data` 是否是待签名数据的有效签名。

*   **可能输出:**
    *   `true`: 如果签名验证成功，所有参数匹配，则返回 `true`，表示 SCT 有效。
    *   `false`: 如果日志 ID 不匹配，签名参数不匹配，或者签名验证失败，则返回 `false`，表示 SCT 无效。

**场景：验证一致性证明**

*   **假设输入:**
    *   `proof`: 一个 `ct::MerkleConsistencyProof` 对象，包含日志 ID、第一个树的大小、第二个树的大小和证明节点列表。
    *   `old_tree_hash`: 第一个树的根哈希值。
    *   `new_tree_hash`: 第二个树的根哈希值。
    *   `public_key`: 对应 CT 日志的公钥。

*   **内部处理步骤:**
    1. `CTLogVerifier::VerifyConsistencyProof()` 被调用。
    2. 检查 `proof.log_id` 是否与 `CTLogVerifier` 实例关联的日志 ID 匹配。
    3. 检查 `proof.first_tree_size` 是否小于或等于 `proof.second_tree_size`。
    4. 根据一致性证明算法，使用提供的证明节点和哈希函数，逐步计算出预期的新旧树的根哈希。
    5. 将计算出的根哈希与 `old_tree_hash` 和 `new_tree_hash` 进行比较。

*   **可能输出:**
    *   `true`: 如果日志 ID 匹配，树大小顺序正确，并且计算出的根哈希与提供的根哈希一致，则返回 `true`。
    *   `false`:  在任何验证步骤失败时返回 `false`。

**用户或编程常见的使用错误：**

1. **使用了错误的日志公钥:**  如果创建 `CTLogVerifier` 对象时使用了错误的公钥，所有后续的签名验证都会失败。
    *   **例子:** 从一个非官方的来源获取了日志的公钥。
    *   **结果:** 浏览器会认为来自该日志的所有 SCTs 和 STHs 都是无效的。

2. **CT 日志本身存在问题:**  虽然 `CTLogVerifier` 负责验证，但如果 CT 日志服务器本身存在漏洞或者被攻击，可能会产生无效的签名或证明。
    *   **例子:**  一个恶意的日志服务器尝试提供伪造的一致性证明。
    *   **结果:** 如果 `CTLogVerifier` 的实现存在缺陷，可能无法检测到这种伪造。

3. **处理 SCTs 或证明数据的错误:** 在浏览器或其他客户端代码中，如果解析或处理从服务器接收到的 SCTs、STHs 或证明数据的过程中出现错误，会导致验证失败。
    *   **例子:**  在解析 SCT 的二进制数据时，长度字段读取错误。
    *   **结果:**  `CTLogVerifier` 接收到的是损坏的数据，验证自然会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户访问一个启用了 Certificate Transparency 的 HTTPS 网站，并且浏览器需要验证该网站提供的 SCT。以下是可能的操作步骤和调试线索：

1. **用户在浏览器地址栏输入 URL 并回车，或点击一个 HTTPS 链接。**
2. **浏览器发起与服务器的 TLS 握手。**
3. **服务器在 TLS 握手过程中提供证书和 SCTs (例如，通过 TLS 扩展)。**
4. **浏览器接收到服务器的响应，包括证书和 SCTs。**
5. **网络栈的 CT 相关代码开始工作：**
    *   **SCT 解析:**  解析从服务器接收到的 SCTs 的二进制数据。
    *   **获取日志公钥:**  根据 SCT 中包含的日志 ID，查找对应的已知可信 CT 日志的公钥。这些公钥通常硬编码在浏览器中或通过配置文件加载。
    *   **创建 `CTLogVerifier` 对象 (如果尚未创建):**  使用找到的公钥创建一个 `CTLogVerifier` 实例。
    *   **调用 `CTLogVerifier::Verify()`:**  将解析后的 SCT 数据和对应的证书信息传递给 `Verify()` 方法进行验证。
6. **如果 `Verify()` 返回 `false`，表示 SCT 验证失败。**
7. **浏览器根据 CT 策略采取行动：**
    *   **显示安全警告:**  例如，在地址栏显示警告标志，或弹出警告信息。
    *   **阻止网站加载:**  如果策略要求强制执行 CT，可能会直接阻止连接。
8. **作为调试线索，开发者或用户可以：**
    *   **查看浏览器开发者工具的 "Security" 面板:**  该面板会显示 CT 相关的状态和错误信息，例如 "Invalid Signed Certificate Timestamp"。
    *   **使用 `chrome://net-internals/#ssl` 查看 SSL 连接的详细信息:**  这里可以看到 SCT 的具体数据和验证结果。
    *   **启用 Chromium 的网络日志 (NetLog):**  NetLog 可以记录更底层的网络事件，包括 CT 相关的操作和错误，例如 `net::CTVerifier::Verify` 的调用和返回值。
    *   **使用调试器逐步跟踪 Chromium 的网络栈代码:**  可以设置断点在 `net/cert/ct_log_verifier.cc` 中的关键函数，例如 `Verify()` 和 `VerifySignature()`，来查看具体的验证过程和失败原因。

总而言之，`net/cert/ct_log_verifier.cc` 是 Chromium 中确保 Certificate Transparency 安全性的核心模块，它通过密码学验证来保障用户信任的 CT 日志数据的真实性和完整性。虽然 JavaScript 代码不能直接调用它，但它的验证结果直接影响着浏览器的安全行为，最终会影响到网页的加载和 JavaScript 代码的执行。

### 提示词
```
这是目录为net/cert/ct_log_verifier.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_log_verifier.h"

#include <string.h>

#include <bit>
#include <string_view>
#include <vector>

#include "base/logging.h"
#include "base/notreached.h"
#include "crypto/openssl_util.h"
#include "crypto/sha2.h"
#include "net/cert/ct_log_verifier_util.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/merkle_audit_proof.h"
#include "net/cert/merkle_consistency_proof.h"
#include "net/cert/signed_tree_head.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/evp.h"

namespace net {

namespace {

// The SHA-256 hash of the empty string.
const unsigned char kSHA256EmptyStringHash[ct::kSthRootHashLength] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

const EVP_MD* GetEvpAlg(ct::DigitallySigned::HashAlgorithm alg) {
  switch (alg) {
    case ct::DigitallySigned::HASH_ALGO_MD5:
      return EVP_md5();
    case ct::DigitallySigned::HASH_ALGO_SHA1:
      return EVP_sha1();
    case ct::DigitallySigned::HASH_ALGO_SHA224:
      return EVP_sha224();
    case ct::DigitallySigned::HASH_ALGO_SHA256:
      return EVP_sha256();
    case ct::DigitallySigned::HASH_ALGO_SHA384:
      return EVP_sha384();
    case ct::DigitallySigned::HASH_ALGO_SHA512:
      return EVP_sha512();
    case ct::DigitallySigned::HASH_ALGO_NONE:
    default:
      NOTREACHED();
  }
}

}  // namespace

// static
scoped_refptr<const CTLogVerifier> CTLogVerifier::Create(
    std::string_view public_key,
    std::string description) {
  auto result = base::WrapRefCounted(new CTLogVerifier(std::move(description)));
  if (!result->Init(public_key))
    return nullptr;
  return result;
}

CTLogVerifier::CTLogVerifier(std::string description)
    : description_(std::move(description)) {}

bool CTLogVerifier::Verify(const ct::SignedEntryData& entry,
                           const ct::SignedCertificateTimestamp& sct) const {
  std::string serialized_log_entry;
  std::string serialized_data;

  return sct.log_id == key_id_ && SignatureParametersMatch(sct.signature) &&
         ct::EncodeSignedEntry(entry, &serialized_log_entry) &&
         ct::EncodeV1SCTSignedData(sct.timestamp, serialized_log_entry,
                                   sct.extensions, &serialized_data) &&
         VerifySignature(serialized_data, sct.signature.signature_data);
}

bool CTLogVerifier::VerifySignedTreeHead(
    const ct::SignedTreeHead& signed_tree_head) const {
  std::string serialized_data;
  if (!SignatureParametersMatch(signed_tree_head.signature) ||
      !ct::EncodeTreeHeadSignature(signed_tree_head, &serialized_data) ||
      !VerifySignature(serialized_data,
                       signed_tree_head.signature.signature_data)) {
    return false;
  }

  if (signed_tree_head.tree_size == 0) {
    // Root hash must equate SHA256 hash of the empty string.
    return memcmp(signed_tree_head.sha256_root_hash, kSHA256EmptyStringHash,
                  ct::kSthRootHashLength) == 0;
  }

  return true;
}

bool CTLogVerifier::SignatureParametersMatch(
    const ct::DigitallySigned& signature) const {
  return signature.SignatureParametersMatch(hash_algorithm_,
                                            signature_algorithm_);
}

bool CTLogVerifier::VerifyConsistencyProof(
    const ct::MerkleConsistencyProof& proof,
    const std::string& old_tree_hash,
    const std::string& new_tree_hash) const {
  // Proof does not originate from this log.
  if (key_id_ != proof.log_id)
    return false;

  // Cannot prove consistency from a tree of a certain size to a tree smaller
  // than that - only the other way around.
  if (proof.first_tree_size > proof.second_tree_size)
    return false;

  // If the proof is between trees of the same size, then the 'proof'
  // is really just a statement that the tree hasn't changed. If this
  // is the case, there should be no proof nodes, and both the old
  // and new hash should be equivalent.
  if (proof.first_tree_size == proof.second_tree_size)
    return proof.nodes.empty() && old_tree_hash == new_tree_hash;

  // It is possible to call this method to prove consistency between the
  // initial state of a log (i.e. an empty tree) and a later root. In that
  // case, the only valid proof is an empty proof.
  if (proof.first_tree_size == 0)
    return proof.nodes.empty();

  // Implement the algorithm described in
  // https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-12#section-9.4.2
  //
  // It maintains a pair of hashes |fr| and |sr|, initialized to the same
  // value. Each node in |proof| will be hashed to the left of both |fr| and
  // |sr| or to the right of only |sr|. The proof is then valid if |fr| is
  // |old_tree_hash| and |sr| is |new_tree_hash|, proving that tree nodes which
  // make up |old_tree_hash| are a prefix of |new_tree_hash|.

  // At this point, the algorithm's preconditions must be satisfied.
  DCHECK_LT(0u, proof.first_tree_size);
  DCHECK_LT(proof.first_tree_size, proof.second_tree_size);

  // 1. If "first" is an exact power of 2, then prepend "first_hash" to the
  // "consistency_path" array.
  std::string_view first_proof_node = old_tree_hash;
  auto iter = proof.nodes.begin();
  if (!std::has_single_bit(proof.first_tree_size)) {
    if (iter == proof.nodes.end())
      return false;
    first_proof_node = *iter;
    ++iter;
  }
  // iter now points to the second node in the modified proof.nodes.

  // 2. Set "fn" to "first - 1" and "sn" to "second - 1".
  uint64_t fn = proof.first_tree_size - 1;
  uint64_t sn = proof.second_tree_size - 1;

  // 3. If "LSB(fn)" is set, then right-shift both "fn" and "sn" equally until
  // "LSB(fn)" is not set.
  while (fn & 1) {
    fn >>= 1;
    sn >>= 1;
  }

  // 4. Set both "fr" and "sr" to the first value in the "consistency_path"
  // array.
  std::string fr(first_proof_node);
  std::string sr(first_proof_node);

  // 5. For each subsequent value "c" in the "consistency_path" array:
  for (; iter != proof.nodes.end(); ++iter) {
    // If "sn" is 0, stop the iteration and fail the proof verification.
    if (sn == 0)
      return false;
    // If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
    if ((fn & 1) || fn == sn) {
      // 1. Set "fr" to "HASH(0x01 || c || fr)"
      //    Set "sr" to "HASH(0x01 || c || sr)"
      fr = ct::internal::HashNodes(*iter, fr);
      sr = ct::internal::HashNodes(*iter, sr);

      // 2. If "LSB(fn)" is not set, then right-shift both "fn" and "sn" equally
      // until either "LSB(fn)" is set or "fn" is "0".
      while (!(fn & 1) && fn != 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {  // Otherwise:
      // Set "sr" to "HASH(0x01 || sr || c)"
      sr = ct::internal::HashNodes(sr, *iter);
    }

    // Finally, right-shift both "fn" and "sn" one time.
    fn >>= 1;
    sn >>= 1;
  }

  // 6. After completing iterating through the "consistency_path" array as
  // described above, verify that the "fr" calculated is equal to the
  // "first_hash" supplied, that the "sr" calculated is equal to the
  // "second_hash" supplied and that "sn" is 0.
  return fr == old_tree_hash && sr == new_tree_hash && sn == 0;
}

bool CTLogVerifier::VerifyAuditProof(const ct::MerkleAuditProof& proof,
                                     const std::string& root_hash,
                                     const std::string& leaf_hash) const {
  // Implements the algorithm described in
  // https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-19#section-10.4.1
  //
  // It maintains a hash |r|, initialized to |leaf_hash|, and hashes nodes from
  // |proof| into it. The proof is then valid if |r| is |root_hash|, proving
  // that |root_hash| includes |leaf_hash|.

  // 1.  Compare "leaf_index" against "tree_size".  If "leaf_index" is
  //     greater than or equal to "tree_size" fail the proof verification.
  if (proof.leaf_index >= proof.tree_size)
    return false;

  // 2.  Set "fn" to "leaf_index" and "sn" to "tree_size - 1".
  uint64_t fn = proof.leaf_index;
  uint64_t sn = proof.tree_size - 1;
  // 3.  Set "r" to "hash".
  std::string r = leaf_hash;

  // 4.  For each value "p" in the "inclusion_path" array:
  for (const std::string& p : proof.nodes) {
    // If "sn" is 0, stop the iteration and fail the proof verification.
    if (sn == 0)
      return false;

    // If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
    if ((fn & 1) || fn == sn) {
      // 1.  Set "r" to "HASH(0x01 || p || r)"
      r = ct::internal::HashNodes(p, r);

      // 2.  If "LSB(fn)" is not set, then right-shift both "fn" and "sn"
      //     equally until either "LSB(fn)" is set or "fn" is "0".
      while (!(fn & 1) && fn != 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {  // Otherwise:
      // Set "r" to "HASH(0x01 || r || p)"
      r = ct::internal::HashNodes(r, p);
    }

    // Finally, right-shift both "fn" and "sn" one time.
    fn >>= 1;
    sn >>= 1;
  }

  // 5.  Compare "sn" to 0.  Compare "r" against the "root_hash".  If "sn"
  //     is equal to 0, and "r" and the "root_hash" are equal, then the
  //     log has proven the inclusion of "hash".  Otherwise, fail the
  //     proof verification.
  return sn == 0 && r == root_hash;
}

CTLogVerifier::~CTLogVerifier() = default;

bool CTLogVerifier::Init(std::string_view public_key) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key.data()),
           public_key.size());
  public_key_.reset(EVP_parse_public_key(&cbs));
  if (!public_key_ || CBS_len(&cbs) != 0)
    return false;

  key_id_ = crypto::SHA256HashString(public_key);

  // Right now, only RSASSA-PKCS1v15 with SHA-256 and ECDSA with SHA-256 are
  // supported.
  switch (EVP_PKEY_id(public_key_.get())) {
    case EVP_PKEY_RSA:
      hash_algorithm_ = ct::DigitallySigned::HASH_ALGO_SHA256;
      signature_algorithm_ = ct::DigitallySigned::SIG_ALGO_RSA;
      break;
    case EVP_PKEY_EC:
      hash_algorithm_ = ct::DigitallySigned::HASH_ALGO_SHA256;
      signature_algorithm_ = ct::DigitallySigned::SIG_ALGO_ECDSA;
      break;
    default:
      return false;
  }

  // Extra safety check: Require RSA keys of at least 2048 bits.
  // EVP_PKEY_size returns the size in bytes. 256 = 2048-bit RSA key.
  if (signature_algorithm_ == ct::DigitallySigned::SIG_ALGO_RSA &&
      EVP_PKEY_size(public_key_.get()) < 256) {
    return false;
  }

  return true;
}

bool CTLogVerifier::VerifySignature(std::string_view data_to_sign,
                                    std::string_view signature) const {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  const EVP_MD* hash_alg = GetEvpAlg(hash_algorithm_);
  bssl::ScopedEVP_MD_CTX ctx;
  return hash_alg &&
         EVP_DigestVerifyInit(ctx.get(), nullptr, hash_alg, nullptr,
                              public_key_.get()) &&
         EVP_DigestVerifyUpdate(ctx.get(), data_to_sign.data(),
                                data_to_sign.size()) &&
         EVP_DigestVerifyFinal(
             ctx.get(), reinterpret_cast<const uint8_t*>(signature.data()),
             signature.size());
}

}  // namespace net
```