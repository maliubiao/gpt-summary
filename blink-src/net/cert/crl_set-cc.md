Response:
Let's break down the thought process for analyzing the `crl_set.cc` file.

1. **Understand the Core Purpose:** The filename `crl_set.cc` and the initial comments immediately point to Certificate Revocation Lists (CRLs). The code manages a *set* of these CRLs, suggesting efficient storage and lookup. The copyright and license information confirm this is part of the Chromium project's network stack.

2. **Identify Key Data Structures:**  The code defines a `CRLSet` class. A quick scan reveals member variables like `crls_`, `blocked_spkis_`, `limited_subjects_`, etc. These represent the core data held by a `CRLSet`.

3. **Analyze the File Format:** The detailed comment block at the beginning describing the "CRLSet format" is crucial. It explains how the CRL data is serialized: a header (length-prefixed JSON) followed by repeated entries of parent SPKI hashes and lists of revoked serial numbers. This is the key to understanding how the data is organized and how parsing works.

4. **Trace the Parsing Logic (`Parse` method):** The `Parse` method is the entry point for loading CRL data. Follow its steps:
    * Read the header using `ReadHeader`.
    * Validate the header (ContentType, Version).
    * Extract metadata (Sequence, NotAfter).
    * Loop through the remaining data, calling `ReadCRL` to extract individual CRL entries (parent SPKI and serials).
    * Extract lists of blocked SPKIs, limited subjects, and interception SPKIs using `CopyHashListFromHeader` and `CopyHashToHashesMapFromHeader`.
    * Incorporate built-in blocklists.
    * Sort the blocklists for efficient searching.

5. **Examine the Functionality Methods:**  After understanding parsing, look at the methods that use the parsed data:
    * `CheckSPKI`: Checks if an SPKI is globally blocked.
    * `CheckSubject`: Checks if an SPKI is allowed for a specific subject.
    * `CheckSerial`: Checks if a specific serial number issued by a given SPKI is revoked.
    * `IsKnownInterceptionKey`: Checks if an SPKI is known to be used for interception.
    * `IsExpired`: Checks if the CRLSet is past its validity date.
    * `sequence`: Returns the sequence number.

6. **Consider JavaScript Interaction:** Think about how a browser uses CRLs. JavaScript itself doesn't directly interact with the raw bytes of a CRLSet. However, JavaScript makes requests over HTTPS, and the *browser's internal network stack* (which includes this `crl_set.cc` code) performs certificate validation, which *includes* checking against CRLSets. Therefore, the connection is indirect: JavaScript triggers network requests that lead to this code being executed.

7. **Develop Scenarios and Examples:** Based on the functions, create hypothetical inputs and outputs to illustrate their behavior. For example, provide a blocked SPKI to `CheckSPKI` and expect `REVOKED`.

8. **Identify Potential Errors:** Think about what could go wrong during parsing or usage:
    * Invalid file format (corrupted data, incorrect header).
    * Expired CRLSets.
    * Incorrectly formatted serial numbers.
    * Mismatched data types in the JSON header.

9. **Trace User Actions:**  Consider how a user's actions in the browser might lead to this code being invoked. The most common scenario is visiting an HTTPS website. This triggers certificate verification, which involves checking CRLs.

10. **Structure the Explanation:** Organize the findings into logical sections: functionalities, JavaScript relationship, input/output examples, common errors, and user action tracing. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe JavaScript directly downloads and parses CRLSets.
* **Correction:** Realized that this is handled internally by the browser's network stack for security and efficiency. JavaScript triggers the *need* for CRL checks, but doesn't do the processing itself.
* **Initial Thought:** Focus only on the individual `Check...` methods.
* **Refinement:**  Recognized the importance of understanding the parsing process (`Parse` method) as the foundation for how the data is used.
* **Initial Thought:**  Provide highly technical details about ASN.1 encoding.
* **Refinement:**  Kept the explanation at a higher level, focusing on the purpose and general mechanisms, as the user prompt didn't specifically ask for in-depth cryptographic details. Mentioned ASN.1 only when relevant to the testing utilities.

By following this systematic approach, analyzing the code structure, understanding its purpose, and considering the context of its use within a browser,  a comprehensive explanation of the `crl_set.cc` file can be constructed.
这个 `net/cert/crl_set.cc` 文件是 Chromium 网络栈中负责处理 **证书吊销列表集合 (CRLSet)** 的核心组件。它的主要功能是高效地存储和查询证书吊销信息，用于判断服务器证书是否已被吊销，从而提高 HTTPS 连接的安全性。

以下是该文件的详细功能列表：

**核心功能:**

1. **CRLSet 的解析 (Parsing):**
   - `CRLSet::Parse(std::string_view data, scoped_refptr<CRLSet>* out_crl_set)`:  这个静态方法负责将二进制格式的 CRLSet 数据解析成可操作的 `CRLSet` 对象。它会读取头部信息（JSON 格式），包括版本、内容类型、序列号、过期时间以及各种哈希列表，然后读取吊销记录本身。
   - `ReadHeader(std::string_view* data)`:  读取 CRLSet 文件的头部信息，头部是一个包含元数据的 JSON 对象。
   - `ReadCRL(std::string_view* data, std::string* out_parent_spki_hash, std::vector<std::string>* out_serials)`: 读取单个 CRL 条目，包括颁发者公钥信息哈希 (SPKI hash) 和被吊销证书的序列号列表。
   - `CopyHashListFromHeader(...)`: 从头部 JSON 中解析 Base64 编码的 SHA-256 哈希列表。
   - `CopyHashToHashesMapFromHeader(...)`: 从头部 JSON 中解析 Base64 编码的 SHA-256 哈希到哈希列表的映射。

2. **证书吊销状态检查:**
   - `CRLSet::CheckSPKI(std::string_view spki_hash) const`: 检查给定的服务器公钥信息哈希 (SPKI hash) 是否在全局阻止的 SPKI 列表中。
   - `CRLSet::CheckSubject(std::string_view encoded_subject, std::string_view spki_hash) const`: 检查给定的主体 (Subject) 的证书，其 SPKI 哈希是否在允许的列表中。这用于限制某些主体的证书只能使用特定的公钥。
   - `CRLSet::CheckSerial(std::string_view serial_number, std::string_view issuer_spki_hash) const`:  检查给定的证书序列号和颁发者 SPKI 哈希是否在 CRLSet 中，以判断该证书是否已被吊销。

3. **拦截密钥检测:**
   - `CRLSet::IsKnownInterceptionKey(std::string_view spki_hash) const`: 检查给定的 SPKI 哈希是否是已知的中间人攻击 (MITM) 拦截代理使用的密钥。

4. **过期检查:**
   - `CRLSet::IsExpired() const`: 检查 CRLSet 是否已过期，过期时间在头部信息中指定。

5. **获取元数据:**
   - `CRLSet::sequence() const`: 获取 CRLSet 的序列号，用于判断哪个 CRLSet 是最新的。
   - `CRLSet::CrlsForTesting() const`: 用于测试，返回内部的 CRL 列表。

6. **测试辅助方法:**
   - `CRLSet::BuiltinCRLSet()`: 返回一个内置的、默认的 CRLSet。
   - `CRLSet::EmptyCRLSetForTesting()`: 返回一个空的 CRLSet，用于测试。
   - `CRLSet::ExpiredCRLSetForTesting()`: 返回一个已过期的 CRLSet，用于测试。
   - `CRLSet::ForTesting(...)`:  一个更通用的测试辅助方法，可以创建具有特定吊销信息的 CRLSet。

**与 JavaScript 功能的关系:**

`crl_set.cc` 本身并不直接与 JavaScript 代码交互。它属于浏览器内核的网络层，在幕后工作。然而，它的功能对 JavaScript 发起的网络请求至关重要：

- **HTTPS 安全性:** 当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起 HTTPS 请求时，浏览器会使用 `crl_set.cc` 中的逻辑来验证服务器证书的有效性，包括检查证书是否已被吊销。如果证书被吊销，浏览器会阻止连接，从而保护用户免受潜在的安全风险。

**举例说明:**

假设一个用户在浏览器中访问 `https://revoked.example.com`，而该网站的证书已被添加到 CRLSet 中：

1. **JavaScript 发起请求:** 网页上的 JavaScript 代码可能尝试通过 `fetch('https://revoked.example.com')` 发起一个请求。
2. **浏览器证书验证:** 浏览器网络栈在建立连接前，会获取服务器提供的证书。
3. **CRLSet 查询:**  浏览器会调用 `CRLSet::CheckSerial` 或 `CRLSet::CheckSPKI` (取决于 CRLSet 中记录的吊销信息) 来检查该证书是否在当前的 CRLSet 中。
4. **阻止连接:** 如果 `crl_set.cc` 判断证书已被吊销，浏览器会阻止与 `revoked.example.com` 的连接，并显示一个错误页面，例如 "此连接不是私密连接" 或类似的提示。

**逻辑推理、假设输入与输出:**

**假设输入:** 一个包含以下内容的 CRLSet 数据：

```
Header: {"ContentType": "CRLSet", "Sequence": 1, "Version": 0}
CRL Entry 1:
  Parent SPKI Hash: <hash_of_example_com_issuer_public_key>
  Revoked Serials:
    - <serial_number_of_revoked_example_com_cert>
```

**假设 JavaScript 操作:**

```javascript
fetch('https://example.com'); // 假设 example.com 的证书已被吊销
```

**逻辑推理与输出:**

1. 当 `fetch('https://example.com')` 被调用时，浏览器会尝试建立 HTTPS 连接。
2. 服务器会发送其证书，其中包含序列号和颁发者信息。
3. 浏览器会计算颁发者的 SPKI 哈希。
4. `CRLSet::CheckSerial(<serial_number_of_example_com_cert>, <hash_of_example_com_issuer_public_key>)` 会被调用。
5. 由于 CRLSet 中包含匹配的颁发者 SPKI 哈希和吊销的序列号，`CheckSerial` 将返回 `CRLSet::REVOKED`。
6. 浏览器会中断连接，并可能在控制台或页面上显示错误信息，指示证书已被吊销。

**用户或编程常见的使用错误:**

1. **CRLSet 数据损坏:** 如果 CRLSet 文件被损坏，`CRLSet::Parse` 可能会失败，导致无法加载吊销信息，从而可能允许连接到已被吊销证书的网站。
   - **用户操作:**  用户通常无法直接干预 CRLSet 数据的更新或加载。这通常由浏览器自动处理。但如果用户的磁盘出现错误或系统不稳定，可能导致文件损坏。
   - **编程错误 (Chromium 开发):**  在 Chromium 的开发过程中，如果生成或存储 CRLSet 的代码存在 bug，可能会导致生成无效的 CRLSet 数据。

2. **CRLSet 过期:** 如果当前使用的 CRLSet 已过期，它可能不包含最新的吊销信息，导致安全风险。
   - **用户操作:** 用户无法直接控制 CRLSet 的更新。浏览器会定期下载和更新 CRLSet。如果用户的网络连接不稳定或长时间离线，可能导致 CRLSet 没有及时更新。
   - **编程错误 (Chromium 开发):**  如果 CRLSet 的更新机制出现问题，可能导致浏览器无法获取最新的 CRLSet。

3. **错误的证书信息:**  如果传递给 `CheckSerial` 或 `CheckSPKI` 的证书序列号或 SPKI 哈希不正确，可能会导致错误的判断结果。
   - **编程错误 (Chromium 开发):**  在证书验证流程中，如果从服务器接收或解析证书信息的代码存在错误，可能会将错误的序列号或 SPKI 哈希传递给 CRLSet 的检查方法。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户报告访问某个 HTTPS 网站时遇到了证书错误，怀疑与 CRLSet 有关，以下是可能的调试线索：

1. **用户尝试访问 HTTPS 网站:** 用户在浏览器地址栏输入一个 `https://` 开头的网址并回车，或者点击了一个 HTTPS 链接。

2. **浏览器发起连接:** 浏览器开始与服务器建立 TCP 连接，并进行 TLS 握手。

3. **服务器提供证书:** 在 TLS 握手过程中，服务器会将它的数字证书发送给浏览器。

4. **证书路径构建和验证 (在 `net/cert` 目录下):** 浏览器会尝试构建从服务器证书到信任根证书的证书链，并对证书链进行一系列验证，包括：
   - **签名验证:** 确保证书的签名是有效的。
   - **有效期检查:** 确保证书在有效期内。
   - **吊销检查:**  **这是 `crl_set.cc` 发挥作用的地方。** 浏览器会查询本地缓存的 CRLSet，检查服务器证书的序列号和颁发者 SPKI 哈希是否存在于 CRLSet 中。

5. **`CRLSet::Parse` (如果需要加载新的 CRLSet):** 如果本地没有可用的 CRLSet 或需要更新，浏览器会从 Chromium 更新服务器下载新的 CRLSet 数据，并调用 `CRLSet::Parse` 进行解析。

6. **`CRLSet::CheckSerial` 或 `CRLSet::CheckSPKI`:**  浏览器会调用这些方法来判断服务器证书是否被吊销。

7. **错误处理:**
   - 如果 `crl_set.cc` 的检查结果表明证书已被吊销，浏览器会中断连接，并显示证书错误页面。
   - 如果 `crl_set.cc` 的检查没有发现吊销信息，但其他证书验证步骤失败（例如，签名无效或过期），也会显示相应的错误。

**调试线索:**

- **网络日志:** 检查浏览器的网络日志 (通常在开发者工具中) 可以查看证书链的信息以及是否有与 CRLSet 下载相关的请求。
- **`chrome://net-internals/#crlsets`:** 在 Chrome 浏览器中访问这个地址可以查看当前加载的 CRLSet 的信息，包括序列号和上次更新时间。这可以帮助判断 CRLSet 是否是最新的。
- **实验性标志:**  某些实验性标志可能会影响 CRLSet 的行为。检查 `chrome://flags` 中是否有相关的标志被启用或禁用。
- **系统时间:** 确保用户的系统时间是准确的，因为 CRLSet 的过期检查依赖于系统时间。
- **错误信息:** 仔细分析浏览器显示的证书错误信息，通常会提供一些关于错误原因的线索。

总而言之，`net/cert/crl_set.cc` 是 Chromium 网络安全的关键组成部分，它通过高效地管理证书吊销信息，为用户提供更安全的浏览体验。虽然 JavaScript 代码不直接操作这个文件，但它发起的网络请求会触发其中的逻辑，从而保障 HTTPS 连接的安全性。

Prompt: 
```
这是目录为net/cert/crl_set.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/crl_set.h"

#include <algorithm>
#include <string_view>

#include "base/base64.h"
#include "base/json/json_reader.h"
#include "base/time/time.h"
#include "base/values.h"
#include "crypto/sha2.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net {

namespace {

// CRLSet format:
//
// uint16le header_len
// byte[header_len] header_bytes
// repeated {
//   byte[32] parent_spki_sha256
//   uint32le num_serials
//   [num_serials] {
//     uint8_t serial_length;
//     byte[serial_length] serial;
//   }
//
// header_bytes consists of a JSON dictionary with the following keys:
//   Version (int): currently 0
//   ContentType (string): "CRLSet" (magic value)
//   Sequence (int32_t): the monotonic sequence number of this CRL set.
//   NotAfter (optional) (double/int64_t): The number of seconds since the
//     Unix epoch, after which, this CRLSet is expired.
//   BlockedSPKIs (array of string): An array of Base64 encoded, SHA-256 hashed
//     SubjectPublicKeyInfos that should be blocked.
//   LimitedSubjects (object/map of string -> array of string): A map between
//     the Base64-encoded SHA-256 hash of the DER-encoded Subject and the
//     Base64-encoded SHA-256 hashes of the SubjectPublicKeyInfos that are
//     allowed for that subject.
//   KnownInterceptionSPKIs (array of string): An array of Base64-encoded
//     SHA-256 hashed SubjectPublicKeyInfos known to be used for interception.
//   BlockedInterceptionSPKIs (array of string): An array of Base64-encoded
//     SHA-256 hashed SubjectPublicKeyInfos known to be used for interception
//     and that should be actively blocked.
//
// ReadHeader reads the header (including length prefix) from |data| and
// updates |data| to remove the header on return. Caller takes ownership of the
// returned pointer.
std::optional<base::Value> ReadHeader(std::string_view* data) {
  uint16_t header_len;
  if (data->size() < sizeof(header_len)) {
    return std::nullopt;
  }
  // Assumes little-endian.
  memcpy(&header_len, data->data(), sizeof(header_len));
  data->remove_prefix(sizeof(header_len));

  if (data->size() < header_len) {
    return std::nullopt;
  }

  const std::string_view header_bytes = data->substr(0, header_len);
  data->remove_prefix(header_len);

  std::optional<base::Value> header =
      base::JSONReader::Read(header_bytes, base::JSON_ALLOW_TRAILING_COMMAS);
  if (!header || !header->is_dict()) {
    return std::nullopt;
  }

  return header;
}

// kCurrentFileVersion is the version of the CRLSet file format that we
// currently implement.
static const int kCurrentFileVersion = 0;

bool ReadCRL(std::string_view* data,
             std::string* out_parent_spki_hash,
             std::vector<std::string>* out_serials) {
  if (data->size() < crypto::kSHA256Length)
    return false;
  *out_parent_spki_hash = std::string(data->substr(0, crypto::kSHA256Length));
  data->remove_prefix(crypto::kSHA256Length);

  uint32_t num_serials;
  if (data->size() < sizeof(num_serials))
    return false;
  // Assumes little endian.
  memcpy(&num_serials, data->data(), sizeof(num_serials));
  data->remove_prefix(sizeof(num_serials));

  if (num_serials > 32 * 1024 * 1024)  // Sanity check.
    return false;

  out_serials->reserve(num_serials);

  for (uint32_t i = 0; i < num_serials; ++i) {
    if (data->size() < sizeof(uint8_t))
      return false;

    uint8_t serial_length = (*data)[0];
    data->remove_prefix(sizeof(uint8_t));

    if (data->size() < serial_length)
      return false;

    out_serials->push_back(std::string());
    out_serials->back() = std::string(data->substr(0, serial_length));
    data->remove_prefix(serial_length);
  }

  return true;
}

// CopyHashListFromHeader parses a list of base64-encoded, SHA-256 hashes from
// the given |key| (without path expansion) in |header_dict| and sets |*out|
// to the decoded values. It's not an error if |key| is not found in
// |header_dict|.
bool CopyHashListFromHeader(const base::Value::Dict& header_dict,
                            const char* key,
                            std::vector<std::string>* out) {
  const base::Value::List* list = header_dict.FindList(key);
  if (!list) {
    // Hash lists are optional so it's not an error if not present.
    return true;
  }

  out->clear();
  out->reserve(list->size());

  std::string sha256_base64;

  for (const base::Value& i : *list) {
    sha256_base64.clear();

    if (!i.is_string())
      return false;
    sha256_base64 = i.GetString();

    out->push_back(std::string());
    if (!base::Base64Decode(sha256_base64, &out->back())) {
      out->pop_back();
      return false;
    }
  }

  return true;
}

// CopyHashToHashesMapFromHeader parse a map from base64-encoded, SHA-256
// hashes to lists of the same, from the given |key| in |header_dict|. It
// copies the map data into |out| (after base64-decoding).
bool CopyHashToHashesMapFromHeader(
    const base::Value::Dict& header_dict,
    const char* key,
    std::unordered_map<std::string, std::vector<std::string>>* out) {
  out->clear();

  const base::Value::Dict* dict = header_dict.FindDict(key);
  if (dict == nullptr) {
    // Maps are optional so it's not an error if not present.
    return true;
  }

  for (auto i : *dict) {
    if (!i.second.is_list()) {
      return false;
    }

    std::vector<std::string> allowed_spkis;
    for (const auto& j : i.second.GetList()) {
      allowed_spkis.emplace_back();
      if (!j.is_string() ||
          !base::Base64Decode(j.GetString(), &allowed_spkis.back())) {
        return false;
      }
    }

    std::string subject_hash;
    if (!base::Base64Decode(i.first, &subject_hash)) {
      return false;
    }

    (*out)[subject_hash] = allowed_spkis;
  }

  return true;
}

}  // namespace

CRLSet::CRLSet() = default;

CRLSet::~CRLSet() = default;

// static
bool CRLSet::Parse(std::string_view data, scoped_refptr<CRLSet>* out_crl_set) {
  TRACE_EVENT0(NetTracingCategory(), "CRLSet::Parse");
// Other parts of Chrome assume that we're little endian, so we don't lose
// anything by doing this.
#if defined(__BYTE_ORDER)
  // Linux check
  static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "assumes little endian");
#elif defined(__BIG_ENDIAN__)
// Mac check
#error assumes little endian
#endif

  std::optional<base::Value> header_value = ReadHeader(&data);
  if (!header_value) {
    return false;
  }

  const base::Value::Dict& header_dict = header_value->GetDict();

  const std::string* contents = header_dict.FindString("ContentType");
  if (!contents || (*contents != "CRLSet"))
    return false;

  if (header_dict.FindInt("Version") != kCurrentFileVersion)
    return false;

  std::optional<int> sequence = header_dict.FindInt("Sequence");
  if (!sequence)
    return false;

  // NotAfter is optional for now.
  double not_after = header_dict.FindDouble("NotAfter").value_or(0);
  if (not_after < 0)
    return false;

  auto crl_set = base::WrapRefCounted(new CRLSet());
  crl_set->sequence_ = static_cast<uint32_t>(*sequence);
  crl_set->not_after_ = static_cast<uint64_t>(not_after);
  crl_set->crls_.reserve(64);  // Value observed experimentally.

  while (!data.empty()) {
    std::string spki_hash;
    std::vector<std::string> blocked_serials;

    if (!ReadCRL(&data, &spki_hash, &blocked_serials)) {
      return false;
    }
    crl_set->crls_[std::move(spki_hash)] = std::move(blocked_serials);
  }

  std::vector<std::string> blocked_interception_spkis;
  if (!CopyHashListFromHeader(header_dict, "BlockedSPKIs",
                              &crl_set->blocked_spkis_) ||
      !CopyHashToHashesMapFromHeader(header_dict, "LimitedSubjects",
                                     &crl_set->limited_subjects_) ||
      !CopyHashListFromHeader(header_dict, "KnownInterceptionSPKIs",
                              &crl_set->known_interception_spkis_) ||
      !CopyHashListFromHeader(header_dict, "BlockedInterceptionSPKIs",
                              &blocked_interception_spkis)) {
    return false;
  }

  // Add the BlockedInterceptionSPKIs to both lists; these are provided as
  // a separate list to allow less data to be sent over the wire, even though
  // they are duplicated in-memory.
  crl_set->blocked_spkis_.insert(crl_set->blocked_spkis_.end(),
                                 blocked_interception_spkis.begin(),
                                 blocked_interception_spkis.end());
  crl_set->known_interception_spkis_.insert(
      crl_set->known_interception_spkis_.end(),
      blocked_interception_spkis.begin(), blocked_interception_spkis.end());

  // Defines kSPKIBlockList and kKnownInterceptionList
#include "net/cert/cert_verify_proc_blocklist.inc"
  for (const auto& hash : kSPKIBlockList) {
    crl_set->blocked_spkis_.emplace_back(reinterpret_cast<const char*>(hash),
                                         crypto::kSHA256Length);
  }

  for (const auto& hash : kKnownInterceptionList) {
    crl_set->known_interception_spkis_.emplace_back(
        reinterpret_cast<const char*>(hash), crypto::kSHA256Length);
  }

  // Sort, as these will be std::binary_search()'d.
  std::sort(crl_set->blocked_spkis_.begin(), crl_set->blocked_spkis_.end());
  std::sort(crl_set->known_interception_spkis_.begin(),
            crl_set->known_interception_spkis_.end());

  *out_crl_set = std::move(crl_set);
  return true;
}

CRLSet::Result CRLSet::CheckSPKI(std::string_view spki_hash) const {
  if (std::binary_search(blocked_spkis_.begin(), blocked_spkis_.end(),
                         spki_hash))
    return REVOKED;
  return GOOD;
}

CRLSet::Result CRLSet::CheckSubject(std::string_view encoded_subject,
                                    std::string_view spki_hash) const {
  const std::string digest(crypto::SHA256HashString(encoded_subject));
  const auto i = limited_subjects_.find(digest);
  if (i == limited_subjects_.end()) {
    return GOOD;
  }

  for (const auto& j : i->second) {
    if (spki_hash == j) {
      return GOOD;
    }
  }

  return REVOKED;
}

CRLSet::Result CRLSet::CheckSerial(std::string_view serial_number,
                                   std::string_view issuer_spki_hash) const {
  std::string_view serial(serial_number);

  if (!serial.empty() && (serial[0] & 0x80) != 0) {
    // This serial number is negative but the process which generates CRL sets
    // will reject any certificates with negative serial numbers as invalid.
    return UNKNOWN;
  }

  // Remove any leading zero bytes.
  while (serial.size() > 1 && serial[0] == 0x00)
    serial.remove_prefix(1);

  auto it = crls_.find(std::string(issuer_spki_hash));
  if (it == crls_.end())
    return UNKNOWN;

  for (const auto& issuer_serial : it->second) {
    if (issuer_serial == serial)
      return REVOKED;
  }

  return GOOD;
}

bool CRLSet::IsKnownInterceptionKey(std::string_view spki_hash) const {
  return std::binary_search(known_interception_spkis_.begin(),
                            known_interception_spkis_.end(), spki_hash);
}

bool CRLSet::IsExpired() const {
  if (not_after_ == 0)
    return false;

  uint64_t now = base::Time::Now().ToTimeT();
  return now > not_after_;
}

uint32_t CRLSet::sequence() const {
  return sequence_;
}

const CRLSet::CRLList& CRLSet::CrlsForTesting() const {
  return crls_;
}

// static
scoped_refptr<CRLSet> CRLSet::BuiltinCRLSet() {
  constexpr char kCRLSet[] =
      "\x31\x00{\"ContentType\":\"CRLSet\",\"Sequence\":0,\"Version\":0}";
  scoped_refptr<CRLSet> ret;
  bool parsed = CRLSet::Parse({kCRLSet, sizeof(kCRLSet) - 1}, &ret);
  DCHECK(parsed);
  return ret;
}

// static
scoped_refptr<CRLSet> CRLSet::EmptyCRLSetForTesting() {
  return ForTesting(false, nullptr, "", "", {});
}

// static
scoped_refptr<CRLSet> CRLSet::ExpiredCRLSetForTesting() {
  return ForTesting(true, nullptr, "", "", {});
}

// static
scoped_refptr<CRLSet> CRLSet::ForTesting(
    bool is_expired,
    const SHA256HashValue* issuer_spki,
    std::string_view serial_number,
    std::string_view utf8_common_name,
    const std::vector<std::string>& acceptable_spki_hashes_for_cn) {
  std::string subject_hash;
  if (!utf8_common_name.empty()) {
    CBB cbb, top_level, set, inner_seq, oid, cn;
    uint8_t* x501_data;
    size_t x501_len;
    static const uint8_t kCommonNameOID[] = {0x55, 0x04, 0x03};  // 2.5.4.3

    CBB_zero(&cbb);

    if (!CBB_init(&cbb, 32) ||
        !CBB_add_asn1(&cbb, &top_level, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&top_level, &set, CBS_ASN1_SET) ||
        !CBB_add_asn1(&set, &inner_seq, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&inner_seq, &oid, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&oid, kCommonNameOID, sizeof(kCommonNameOID)) ||
        !CBB_add_asn1(&inner_seq, &cn, CBS_ASN1_UTF8STRING) ||
        !CBB_add_bytes(
            &cn, reinterpret_cast<const uint8_t*>(utf8_common_name.data()),
            utf8_common_name.size()) ||
        !CBB_finish(&cbb, &x501_data, &x501_len)) {
      CBB_cleanup(&cbb);
      return nullptr;
    }

    subject_hash.assign(crypto::SHA256HashString(
        std::string_view(reinterpret_cast<char*>(x501_data), x501_len)));
    OPENSSL_free(x501_data);
  }

  auto crl_set = base::WrapRefCounted(new CRLSet());
  crl_set->sequence_ = 0;
  if (is_expired)
    crl_set->not_after_ = 1;

  if (issuer_spki) {
    std::string spki(reinterpret_cast<const char*>(issuer_spki->data),
                     sizeof(issuer_spki->data));
    std::vector<std::string> serials;
    if (!serial_number.empty()) {
      serials.push_back(std::string(serial_number));
      // |serial_number| is in DER-encoded form, which means it may have a
      // leading 0x00 to indicate it is a positive INTEGER. CRLSets are stored
      // without these leading 0x00, as handled in CheckSerial(), so remove
      // that here. As DER-encoding means that any sequences of leading zeroes
      // should be omitted, except to indicate sign, there should only ever
      // be one, and the next byte should have the high bit set.
      DCHECK_EQ(serials[0][0] & 0x80, 0);  // Negative serials are not allowed.
      if (serials[0][0] == 0x00) {
        serials[0].erase(0, 1);
        // If there was a leading 0x00, then the high-bit of the next byte
        // should have been set.
        DCHECK(!serials[0].empty() && serials[0][0] & 0x80);
      }
    }

    crl_set->crls_.emplace(std::move(spki), std::move(serials));
  }

  if (!subject_hash.empty())
    crl_set->limited_subjects_[subject_hash] = acceptable_spki_hashes_for_cn;

  return crl_set;
}

}  // namespace net

"""

```