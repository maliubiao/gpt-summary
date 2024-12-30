Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Initial Understanding of the Request:**

The user wants to understand the functionality of the `transport_security_state.cc` file in Chromium's network stack. The request also specifically asks about:

* Relationship to JavaScript.
* Logical reasoning with examples.
* Common user/programming errors.
* User actions leading to this code.

**2. High-Level Overview of the Code:**

My first step is to skim the code to get a general idea of its purpose. I see:

* Includes like `<string>`, `<vector>`, `<map>`, `<time>`, and Chromium-specific headers like `"net/http/transport_security_state.h"`, `"net/base/features.h"`, `"net/ssl/ssl_info.h"`. This strongly suggests it's dealing with network security.
* Mentions of "HSTS" (HTTP Strict Transport Security) and "HPKP" (HTTP Public Key Pinning). These are key security mechanisms.
* Functions like `ShouldUpgradeToSSL`, `CheckPublicKeyPins`, `AddHSTSHeader`, `AddHPKP`. These indicate management and enforcement of security policies.
* Preload data handling.
* Interaction with a `Delegate` interface.

Based on this initial scan, I can infer the file is responsible for managing the browser's knowledge of which websites should *always* be accessed over HTTPS (HSTS) and which cryptographic keys are expected for certain websites (HPKP).

**3. Detailed Examination and Function Identification:**

Now, I go through the code more systematically, focusing on the functions and their purpose. I start listing the functionalities as I encounter them:

* **HSTS Management:**
    * Storing and retrieving HSTS state (dynamic and static/preloaded).
    * Checking if a host should be upgraded to HTTPS (`ShouldUpgradeToSSL`).
    * Adding HSTS entries from headers (`AddHSTSHeader`).
    * Handling includeSubdomains.
    * Bypassing HSTS for localhost (with a feature flag).
* **HPKP (Public Key Pinning) Management:**
    * Storing and retrieving HPKP state (dynamic and static/preloaded).
    * Checking if the presented public keys match the pinned keys (`CheckPublicKeyPins`).
    * Handling includeSubdomains.
    * Bypassing pinning for locally trusted certificates.
* **Preload Data:**
    * Decoding preloaded HSTS and HPKP data.
    * Using a Huffman trie for efficient lookup.
* **Certificate Transparency (CT):**
    * Checking CT requirements (`CheckCTRequirements`).
    * Interaction with a `RequireCTDelegate`.
* **Data Persistence:**
    * Interaction with a `Delegate` interface for saving state.
    * Methods to clear and delete dynamic data.
* **Internal Utilities:**
    * Canonicalizing hostnames.
    * Hashing hostnames.
    * Parsing HSTS headers.
* **Metrics and Debugging:**
    * NetLog integration.

**4. Addressing Specific Questions:**

* **Relationship with JavaScript:**  I search for keywords like "JavaScript", "script", "DOM", "window". I don't see any direct interaction. The key insight is that this code operates at a lower level (network stack) than JavaScript. JavaScript *relies* on the decisions made by this code but doesn't directly call into it. I formulate the explanation focusing on this separation of concerns.

* **Logical Reasoning and Examples:**  For HSTS, the logic is straightforward: If a host has an active HSTS entry, upgrade HTTP requests to HTTPS. I provide an example with input (hostname) and output (upgrade decision). For HPKP, the logic is more complex. I provide an example of a pin violation.

* **Common Errors:** I think about what could go wrong:
    * **HSTS:** Users might expect HSTS to work immediately after setting it up, forgetting about the max-age. Developers might misuse the includeSubdomains directive.
    * **HPKP:** Incorrectly pinning keys can lock users out of their websites. This is a significant risk and a classic error.
    * **General:**  Clock skew can cause issues with expiry times.

* **User Actions Leading to This Code:** I trace the typical web browsing flow:
    1. User enters a URL.
    2. Browser checks HSTS status.
    3. If HSTS is present, an HTTPS connection is attempted.
    4. During the HTTPS handshake, HPKP is checked (if applicable).
    5. CT is also checked.
    6. When a server sends an HSTS header, this code processes it and updates the internal state.

**5. Refining and Structuring the Answer:**

I organize my findings into the requested categories. I use clear and concise language, avoiding overly technical jargon where possible. I provide code snippets where relevant but keep them focused on illustrating the point. I ensure the examples have clear inputs and expected outputs. I double-check that I've addressed all parts of the user's request.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the technical details of the data structures (maps, vectors). I realized the user needs a higher-level understanding of the functionality.
* I made sure to emphasize the *separation* between this C++ code and JavaScript, rather than implying direct interaction.
* I initially might have missed the nuances of static vs. dynamic HSTS/HPKP. I refined the explanation to clearly distinguish between them.
* I ensured the debugging section provides a realistic flow of user actions.

By following this structured approach, I can effectively analyze the code and provide a comprehensive and helpful answer to the user's request.
这个C++源代码文件 `net/http/transport_security_state.cc` 是 Chromium 网络栈中负责管理和执行**传输层安全状态**的核心组件。 它的主要功能是：

**1. HTTP 严格传输安全 (HSTS) 管理:**

* **存储和检索 HSTS 策略:**  维护一个内部数据结构（例如 `enabled_sts_hosts_`），用于存储已知的 HSTS 主机及其策略（例如，是否包含子域名，过期时间）。 这些策略可能来自预加载列表、服务器发送的 HTTP 头部，或者通过 API 手动添加。
* **检查是否需要升级到 HTTPS:**  根据存储的 HSTS 策略，判断对于给定的主机是否应该将 HTTP 请求升级到 HTTPS。
* **处理 HSTS 头部:**  解析服务器发送的 `Strict-Transport-Security` 头部，提取 `max-age` 和 `includeSubDomains` 指令，并更新内部的 HSTS 状态。
* **支持 HSTS 绕过列表:**  允许配置一个主机名列表，这些主机名即使在预加载列表中也不会强制使用 HTTPS。
* **区分静态 (预加载) 和动态 HSTS 状态:**  管理来自 Chromium 内置的 HSTS 预加载列表以及运行时学习到的 HSTS 策略。

**2. HTTP 公钥指纹 (HPKP) 管理 (已弃用，但代码仍然存在):**

* **存储和检索 HPKP 策略:**  维护一个内部数据结构（例如 `enabled_pkp_hosts_`），用于存储已知的 HPKP 主机及其公钥指纹（SPKI 哈希值）、是否包含子域名和过期时间。 类似于 HSTS，这些策略可能来自预加载列表或服务器发送的 HTTP 头部。
* **检查公钥指纹:**  在建立 HTTPS 连接时，验证服务器提供的证书链的公钥指纹是否与存储的 HPKP 策略匹配。 如果不匹配，则会阻止连接，防止中间人攻击。
* **处理 HPKP 头部:**  解析服务器发送的 `Public-Key-Pins` 和 `Public-Key-Pins-Report-Only` 头部，提取公钥指纹、`max-age` 和 `includeSubDomains` 指令。
* **区分静态 (预加载) 和动态 HPKP 状态:**  管理来自 Chromium 内置的 HPKP 预加载列表以及运行时学习到的 HPKP 策略。
* **允许针对本地信任锚绕过公钥指纹:**  在某些情况下，允许绕过对本地信任的证书颁发机构颁发的证书的公钥指纹检查。

**3. 证书透明度 (CT) 要求检查:**

* **检查是否需要证书透明度:**  根据配置和策略，判断对特定主机是否强制要求证书透明度。
* **与 `RequireCTDelegate` 交互:**  允许外部组件 (`RequireCTDelegate`) 自定义 CT 要求的逻辑。

**4. 数据持久化:**

* **使用 `Delegate` 接口:**  定义了一个 `Delegate` 接口，用于将传输层安全状态的更改通知给其他组件，以便进行持久化存储（例如，写入磁盘）。
* **提供清除动态数据的功能:**  允许清除运行时学习到的 HSTS 和 HPKP 策略。

**5. 内部工具函数:**

* **`CanonicalizeHost`:**  将主机名转换为 DNS 使用的规范化格式。
* **`HashHost`:**  计算规范化主机名的 SHA-256 哈希值，用于在内部数据结构中索引。
* **预加载数据解码:**  解码 Chromium 内置的 HSTS 和 HPKP 预加载列表。

**与 JavaScript 的关系:**

`transport_security_state.cc` 本身是 C++ 代码，**不直接与 JavaScript 交互**。 然而，它的功能对 Web 浏览器的安全至关重要，并间接地影响 JavaScript 代码的行为。

* **HTTPS 升级:**  当 JavaScript 代码尝试通过 HTTP 发起请求到一个具有 HSTS 策略的主机时，`transport_security_state.cc` 会指示网络栈将请求升级到 HTTPS。 这对 JavaScript 代码来说是透明的，它会像发起了一个 HTTPS 请求一样。
* **安全上下文:**  HSTS 策略的存在会影响页面的安全上下文。 例如，一个通过 HTTPS 加载的页面，如果其主机具有 HSTS 策略，那么即使页面内有指向 HTTP 资源的链接，浏览器也可能阻止加载或将其升级到 HTTPS。 这会影响 JavaScript 代码中处理资源加载的逻辑。
* **公钥指纹错误 (虽然 HPKP 已弃用):**  如果一个网站配置了 HPKP，并且 JavaScript 代码尝试连接到该网站，但证书的公钥指纹不匹配，`transport_security_state.cc` 会阻止连接。 这会导致网络请求失败，JavaScript 代码可能会接收到错误回调。

**举例说明 (HSTS 与 JavaScript):**

**假设输入:**

1. 用户在地址栏输入 `http://example.com`。
2. `example.com` 的 HSTS 预加载列表条目存在，指示必须使用 HTTPS。

**逻辑推理:**

1. 浏览器在请求之前会查询 `transport_security_state.cc` 以检查 `example.com` 的 HSTS 状态。
2. `transport_security_state.cc` 返回 `example.com` 具有 HSTS 策略。

**输出:**

1. 浏览器不会直接向 `http://example.com` 发送 HTTP 请求。
2. 浏览器会发起一个对 `https://example.com` 的 HTTPS 请求。
3. JavaScript 代码最终会与 `https://example.com` 建立连接，而用户可能甚至不知道最初输入的是 HTTP 地址。

**假设输入 (HPKP 与 JavaScript - 尽管已弃用，用于说明原理):**

1. 用户尝试访问 `https://pinned.example.com`。
2. `pinned.example.com` 的 HPKP 策略指示期望特定的公钥指纹。
3. 服务器提供的证书的公钥指纹与 HPKP 策略不匹配。

**逻辑推理:**

1. 浏览器在建立 HTTPS 连接时会调用 `transport_security_state.cc` 的公钥指纹检查功能。
2. `transport_security_state.cc` 检测到指纹不匹配。

**输出:**

1. 浏览器会阻止与 `pinned.example.com` 的连接。
2. JavaScript 代码中发起的网络请求会失败，可能会收到一个类似于 "NET::ERR_CERTIFICATE_PINNED_FAILED" 的错误。

**用户或编程常见的使用错误 (HSTS):**

* **`max-age` 设置过短:**  开发者可能将 `max-age` 设置得太短，导致 HSTS 策略频繁过期，用户在一段时间后可能会通过 HTTP 访问网站，从而容易受到中间人攻击。
    * **例子:**  `Strict-Transport-Security: max-age=60; includeSubDomains` (策略仅持续 60 秒)。
* **忘记 `includeSubDomains`:**  开发者可能忘记在 HSTS 头部中包含 `includeSubDomains` 指令，导致 HSTS 策略只应用于根域名，而其子域名仍然可以通过 HTTP 访问。
    * **例子:**  `Strict-Transport-Security: max-age=31536000` (只保护 `example.com`，不保护 `www.example.com` 或 `sub.example.com`)。
* **在开发环境中使用 HSTS 但没有 HTTPS 支持:**  开发者可能在开发环境中使用 HSTS，但没有配置 HTTPS，导致浏览器无法访问网站。

**用户或编程常见的使用错误 (HPKP - 尽管已弃用):**

* **错误地锁定公钥:**  开发者可能错误地配置 HPKP 策略，例如，锁定了过期的密钥或备份密钥丢失，导致网站无法访问，即使使用有效的证书也无法建立连接。这是一个非常严重的问题，被称为 "pinning 灾难"。
* **在没有充分理解的情况下使用 HPKP:**  由于 HPKP 的复杂性和风险，开发者可能在没有完全理解其工作原理的情况下就部署了它，导致配置错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户遇到了一个网站的 HSTS 问题，例如，他们期望网站使用 HTTPS，但浏览器仍然尝试通过 HTTP 连接。以下是用户操作如何触发 `transport_security_state.cc` 的相关逻辑：

1. **用户在地址栏输入 URL 或点击链接:**  例如，用户输入 `http://problematic-website.com`。
2. **浏览器解析 URL:**  浏览器确定需要请求的主机名是 `problematic-website.com`。
3. **网络栈查询 HSTS 状态:**  在发起网络请求之前，浏览器的网络栈会调用 `TransportSecurityState::ShouldUpgradeToSSL("problematic-website.com", ...)`。
4. **`GetSSLUpgradeDecision` 函数被调用:**  `ShouldUpgradeToSSL` 内部会调用 `GetSSLUpgradeDecision`。
5. **检查动态 HSTS 状态:**  `GetSSLUpgradeDecision` 首先会调用 `GetDynamicSTSState("problematic-website.com", ...)`，查看运行时是否学习到该主机的 HSTS 策略。
6. **检查静态 HSTS 状态 (预加载):** 如果没有找到动态策略，`GetSSLUpgradeDecision` 会调用 `GetStaticSTSState("problematic-website.com", ...)`，查看 HSTS 预加载列表是否包含该主机。
7. **根据 HSTS 状态决定是否升级:**  `GetSSLUpgradeDecision` 根据查询到的 HSTS 状态返回 `SSLUpgradeDecision::kStaticUpgrade`、`SSLUpgradeDecision::kDynamicUpgrade` 或 `SSLUpgradeDecision::kNoUpgrade`。
8. **浏览器发起请求:**  如果决定升级，浏览器会发起对 `https://problematic-website.com` 的请求；否则，会发起 HTTP 请求。

**作为调试线索，理解 `transport_security_state.cc` 的功能可以帮助开发者：**

* **验证 HSTS 策略是否生效:**  可以使用 Chromium 的内部页面 (例如 `net-internals/#hsts`) 查看当前存储的 HSTS 策略，确认网站的 HSTS 头部是否被正确解析和存储。
* **排查 HTTPS 升级问题:**  如果用户报告浏览器没有将 HTTP 请求升级到 HTTPS，可以检查该主机是否存在 HSTS 策略，以及策略是否过期或未包含 `includeSubDomains`。
* **理解公钥指纹错误 (如果涉及 HPKP):**  如果遇到 "NET::ERR_CERTIFICATE_PINNED_FAILED" 错误，可以检查该主机的 HPKP 策略，确认服务器提供的证书指纹是否与策略匹配。

总而言之，`transport_security_state.cc` 是 Chromium 中一个关键的安全组件，它通过管理 HSTS 和 (过去的) HPKP 策略，强制浏览器尽可能使用安全的 HTTPS 连接，并防止某些类型的中间人攻击。 理解它的功能对于 Web 开发者和网络安全研究人员来说都非常重要。

Prompt: 
```
这是目录为net/http/transport_security_state.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/transport_security_state.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/build_time.h"
#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_params.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/branding_buildflags.h"
#include "build/build_config.h"
#include "crypto/sha2.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/host_port_pair.h"
#include "net/base/url_util.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/x509_certificate.h"
#include "net/dns/dns_names_util.h"
#include "net/extras/preload_data/decoder.h"
#include "net/http/http_security_headers.h"
#include "net/net_buildflags.h"
#include "net/ssl/ssl_info.h"

namespace net {

namespace {

#if BUILDFLAG(INCLUDE_TRANSPORT_SECURITY_STATE_PRELOAD_LIST)
#include "net/http/transport_security_state_static.h"  // nogncheck
// Points to the active transport security state source.
const TransportSecurityStateSource* const kDefaultHSTSSource = &kHSTSSource;
#else
const TransportSecurityStateSource* const kDefaultHSTSSource = nullptr;
#endif

const TransportSecurityStateSource* g_hsts_source = kDefaultHSTSSource;

TransportSecurityState::HashedHost HashHost(
    base::span<const uint8_t> canonicalized_host) {
  return crypto::SHA256Hash(canonicalized_host);
}

// Returns true if the intersection of |a| and |b| is not empty. If either
// |a| or |b| is empty, returns false.
bool HashesIntersect(const HashValueVector& a, const HashValueVector& b) {
  for (const auto& hash : a) {
    if (base::Contains(b, hash))
      return true;
  }
  return false;
}

bool AddHash(const char* sha256_hash, HashValueVector* out) {
  HashValue hash(HASH_VALUE_SHA256);
  memcpy(hash.data(), sha256_hash, hash.size());
  out->push_back(hash);
  return true;
}

// Converts |hostname| from dotted form ("www.google.com") to the form
// used in DNS: "\x03www\x06google\x03com", lowercases that, and returns
// the result.
std::vector<uint8_t> CanonicalizeHost(std::string_view host) {
  // We cannot perform the operations as detailed in the spec here as `host`
  // has already undergone IDN processing before it reached us. Thus, we
  // lowercase the input (probably redudnant since most input here has been
  // lowercased through URL canonicalization) and check that there are no
  // invalid characters in the host (via DNSDomainFromDot()).
  std::string lowered_host = base::ToLowerASCII(host);

  std::optional<std::vector<uint8_t>> new_host =
      dns_names_util::DottedNameToNetwork(
          lowered_host,
          /*require_valid_internet_hostname=*/true);
  if (!new_host.has_value()) {
    // DNSDomainFromDot can fail if any label is > 63 bytes or if the whole
    // name is >255 bytes. However, search terms can have those properties.
    return std::vector<uint8_t>();
  }

  return std::move(new_host).value();
}

// PreloadResult is the result of resolving a specific name in the preloaded
// data.
struct PreloadResult {
  uint32_t pinset_id = 0;
  // hostname_offset contains the number of bytes from the start of the given
  // hostname where the name of the matching entry starts.
  size_t hostname_offset = 0;
  bool sts_include_subdomains = false;
  bool pkp_include_subdomains = false;
  bool force_https = false;
  bool has_pins = false;
};

using extras::PreloadDecoder;

// Extracts the current PreloadResult entry from the given Huffman encoded trie.
// If an "end of string" matches a period in the hostname then the information
// is remembered because, if no more specific node is found, then that
// information applies to the hostname.
class HSTSPreloadDecoder : public extras::PreloadDecoder {
 public:
  using extras::PreloadDecoder::PreloadDecoder;

  // extras::PreloadDecoder:
  bool ReadEntry(extras::PreloadDecoder::BitReader* reader,
                 const std::string& search,
                 size_t current_search_offset,
                 bool* out_found) override {
    bool is_simple_entry;
    if (!reader->Next(&is_simple_entry)) {
      return false;
    }
    PreloadResult tmp;
    // Simple entries only configure HSTS with IncludeSubdomains and use a
    // compact serialization format where the other policy flags are
    // omitted. The omitted flags are assumed to be 0 and the associated
    // policies are disabled.
    if (is_simple_entry) {
      tmp.force_https = true;
      tmp.sts_include_subdomains = true;
    } else {
      if (!reader->Next(&tmp.sts_include_subdomains) ||
          !reader->Next(&tmp.force_https) || !reader->Next(&tmp.has_pins)) {
        return false;
      }

      tmp.pkp_include_subdomains = tmp.sts_include_subdomains;

      if (tmp.has_pins) {
        if (!reader->Read(4, &tmp.pinset_id) ||
            (!tmp.sts_include_subdomains &&
             !reader->Next(&tmp.pkp_include_subdomains))) {
          return false;
        }
      }
    }

    tmp.hostname_offset = current_search_offset;

    if (current_search_offset == 0 ||
        search[current_search_offset - 1] == '.') {
      *out_found = tmp.sts_include_subdomains || tmp.pkp_include_subdomains;

      result_ = tmp;

      if (current_search_offset > 0) {
        result_.force_https &= tmp.sts_include_subdomains;
      } else {
        *out_found = true;
        return true;
      }
    }
    return true;
  }

  PreloadResult result() const { return result_; }

 private:
  PreloadResult result_;
};

bool DecodeHSTSPreload(const std::string& search_hostname, PreloadResult* out) {
#if !BUILDFLAG(INCLUDE_TRANSPORT_SECURITY_STATE_PRELOAD_LIST)
  if (g_hsts_source == nullptr)
    return false;
#endif
  bool found = false;

  // Ensure that |search_hostname| is a valid hostname before
  // processing.
  if (CanonicalizeHost(search_hostname).empty()) {
    return false;
  }
  // Normalize any trailing '.' used for DNS suffix searches.
  std::string hostname = search_hostname;
  size_t trailing_dot_found = hostname.find_last_not_of('.');
  if (trailing_dot_found != std::string::npos) {
    hostname.erase(trailing_dot_found + 1);
  } else {
    hostname.clear();
  }

  // |hostname| has already undergone IDN conversion, so should be
  // entirely A-Labels. The preload data is entirely normalized to
  // lower case.
  hostname = base::ToLowerASCII(hostname);
  if (hostname.empty()) {
    return false;
  }

  HSTSPreloadDecoder decoder(
      g_hsts_source->huffman_tree, g_hsts_source->huffman_tree_size,
      g_hsts_source->preloaded_data, g_hsts_source->preloaded_bits,
      g_hsts_source->root_position);
  if (!decoder.Decode(hostname, &found)) {
    DCHECK(false) << "Internal error in DecodeHSTSPreload for hostname "
                  << hostname;
    return false;
  }
  if (found)
    *out = decoder.result();
  return found;
}

}  // namespace

void SetTransportSecurityStateSourceForTesting(
    const TransportSecurityStateSource* source) {
  g_hsts_source = source ? source : kDefaultHSTSSource;
}

TransportSecurityState::TransportSecurityState()
    : TransportSecurityState(std::vector<std::string>()) {}

TransportSecurityState::TransportSecurityState(
    std::vector<std::string> hsts_host_bypass_list) {
// Static pinning is only enabled for official builds to make sure that
// others don't end up with pins that cannot be easily updated.
#if !BUILDFLAG(GOOGLE_CHROME_BRANDING) || BUILDFLAG(IS_IOS)
  enable_static_pins_ = false;
#endif
  // Check that there no invalid entries in the static HSTS bypass list.
  for (auto& host : hsts_host_bypass_list) {
    DCHECK(host.find('.') == std::string::npos);
    hsts_host_bypass_list_.insert(host);
  }
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

// Both HSTS and HPKP cause fatal SSL errors, so return true if a
// host has either.
bool TransportSecurityState::ShouldSSLErrorsBeFatal(const std::string& host) {
  STSState unused_sts;
  PKPState unused_pkp;
  return GetSTSState(host, &unused_sts) || GetPKPState(host, &unused_pkp);
}

base::Value::Dict TransportSecurityState::NetLogUpgradeToSSLParam(
    const std::string& host) {
  STSState sts_state;
  base::Value::Dict dict;
  dict.Set("host", host);
  dict.Set("get_sts_state_result", GetSTSState(host, &sts_state));
  dict.Set("should_upgrade_to_ssl", sts_state.ShouldUpgradeToSSL());
  dict.Set("host_found_in_hsts_bypass_list",
           hsts_host_bypass_list_.find(host) != hsts_host_bypass_list_.end());
  return dict;
}

SSLUpgradeDecision TransportSecurityState::GetSSLUpgradeDecision(
    const std::string& host,
    const NetLogWithSource& net_log) {
  net_log.AddEvent(
      NetLogEventType::TRANSPORT_SECURITY_STATE_SHOULD_UPGRADE_TO_SSL,
      [&] { return NetLogUpgradeToSSLParam(host); });
  STSState sts_state;
  // Check the dynamic list first (removing the entry if expired).
  if (GetDynamicSTSState(host, &sts_state)) {
    // [*.]localhost hosts now ignore Strict-Transport-Security response
    // headers, but an entry may have been stored before this restriction
    // was introduced (crbug.com/41251622).
    if (sts_state.ShouldUpgradeToSSL() &&
        !(net::IsLocalHostname(host) &&
          base::FeatureList::IsEnabled(features::kIgnoreHSTSForLocalhost))) {
      // If the static state also requires an upgrade, the dynamic state
      // didn't need to be used in the decision.
      STSState static_sts_state;
      if (GetStaticSTSState(host, &static_sts_state) &&
          static_sts_state.ShouldUpgradeToSSL()) {
        return SSLUpgradeDecision::kStaticUpgrade;
      }
      return SSLUpgradeDecision::kDynamicUpgrade;
    }
    return SSLUpgradeDecision::kNoUpgrade;
  }
  if (GetStaticSTSState(host, &sts_state) && sts_state.ShouldUpgradeToSSL()) {
    return SSLUpgradeDecision::kStaticUpgrade;
  }
  return SSLUpgradeDecision::kNoUpgrade;
}

bool TransportSecurityState::ShouldUpgradeToSSL(
    const std::string& host,
    const NetLogWithSource& net_log) {
  return GetSSLUpgradeDecision(host, net_log) != SSLUpgradeDecision::kNoUpgrade;
}

TransportSecurityState::PKPStatus TransportSecurityState::CheckPublicKeyPins(
    const HostPortPair& host_port_pair,
    bool is_issued_by_known_root,
    const HashValueVector& public_key_hashes) {
  // Perform pin validation only if the server actually has public key pins.
  if (!HasPublicKeyPins(host_port_pair.host())) {
    return PKPStatus::OK;
  }

  return CheckPublicKeyPinsImpl(host_port_pair, is_issued_by_known_root,
                                public_key_hashes);
}

bool TransportSecurityState::HasPublicKeyPins(const std::string& host) {
  PKPState pkp_state;
  return GetPKPState(host, &pkp_state) && pkp_state.HasPublicKeyPins();
}

TransportSecurityState::CTRequirementsStatus
TransportSecurityState::CheckCTRequirements(
    const HostPortPair& host_port_pair,
    bool is_issued_by_known_root,
    const HashValueVector& public_key_hashes,
    const X509Certificate* validated_certificate_chain,
    ct::CTPolicyCompliance policy_compliance) {
  using CTRequirementLevel = RequireCTDelegate::CTRequirementLevel;

  // If CT is emergency disabled, we don't require CT for any host.
  if (ct_emergency_disable_) {
    return CT_NOT_REQUIRED;
  }

  // CT is not required if the certificate does not chain to a publicly
  // trusted root certificate.
  if (!is_issued_by_known_root) {
    return CT_NOT_REQUIRED;
  }

  // A connection is considered compliant if it has sufficient SCTs or if the
  // build is outdated. Other statuses are not considered compliant; this
  // includes COMPLIANCE_DETAILS_NOT_AVAILABLE because compliance must have been
  // evaluated in order to determine that the connection is compliant.
  bool complies =
      (policy_compliance ==
           ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS ||
       policy_compliance == ct::CTPolicyCompliance::CT_POLICY_BUILD_NOT_TIMELY);

  CTRequirementLevel ct_required = CTRequirementLevel::NOT_REQUIRED;
  if (require_ct_delegate_) {
    // Allow the delegate to override the CT requirement state.
    ct_required = require_ct_delegate_->IsCTRequiredForHost(
        host_port_pair.host(), validated_certificate_chain, public_key_hashes);
  }
  switch (ct_required) {
    case CTRequirementLevel::REQUIRED:
      return complies ? CT_REQUIREMENTS_MET : CT_REQUIREMENTS_NOT_MET;
    case CTRequirementLevel::NOT_REQUIRED:
      return CT_NOT_REQUIRED;
  }
}

void TransportSecurityState::SetDelegate(
    TransportSecurityState::Delegate* delegate) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  delegate_ = delegate;
}

void TransportSecurityState::SetRequireCTDelegate(RequireCTDelegate* delegate) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  require_ct_delegate_ = delegate;
}

void TransportSecurityState::UpdatePinList(
    const std::vector<PinSet>& pinsets,
    const std::vector<PinSetInfo>& host_pins,
    base::Time update_time) {
  pinsets_ = pinsets;
  key_pins_list_last_update_time_ = update_time;
  host_pins_.emplace();
  std::map<std::string, PinSet const*> pinset_names_map;
  for (const auto& pinset : pinsets_) {
    pinset_names_map[pinset.name()] = &pinset;
  }
  for (const auto& pin : host_pins) {
    if (!base::Contains(pinset_names_map, pin.pinset_name_)) {
      // This should never happen, but if the component is bad and missing an
      // entry, we will ignore that particular pin.
      continue;
    }
    host_pins_.value()[pin.hostname_] =
        std::pair(pinset_names_map[pin.pinset_name_], pin.include_subdomains_);
  }
}

void TransportSecurityState::AddHSTSInternal(
    std::string_view host,
    TransportSecurityState::STSState::UpgradeMode upgrade_mode,
    const base::Time& expiry,
    bool include_subdomains) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const std::vector<uint8_t> canonicalized_host = CanonicalizeHost(host);
  if (canonicalized_host.empty())
    return;

  STSState sts_state;
  // No need to store |sts_state.domain| since it is redundant.
  // (|canonicalized_host| is the map key.)
  sts_state.last_observed = base::Time::Now();
  sts_state.include_subdomains = include_subdomains;
  sts_state.expiry = expiry;
  sts_state.upgrade_mode = upgrade_mode;

  // Only store new state when HSTS is explicitly enabled. If it is
  // disabled, remove the state from the enabled hosts.
  if (sts_state.ShouldUpgradeToSSL()) {
    enabled_sts_hosts_[HashHost(canonicalized_host)] = sts_state;
  } else {
    const HashedHost hashed_host = HashHost(canonicalized_host);
    enabled_sts_hosts_.erase(hashed_host);
  }

  DirtyNotify();
}

void TransportSecurityState::AddHPKPInternal(std::string_view host,
                                             const base::Time& last_observed,
                                             const base::Time& expiry,
                                             bool include_subdomains,
                                             const HashValueVector& hashes) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const std::vector<uint8_t> canonicalized_host = CanonicalizeHost(host);
  if (canonicalized_host.empty())
    return;

  PKPState pkp_state;
  // No need to store |pkp_state.domain| since it is redundant.
  // (|canonicalized_host| is the map key.)
  pkp_state.last_observed = last_observed;
  pkp_state.expiry = expiry;
  pkp_state.include_subdomains = include_subdomains;
  pkp_state.spki_hashes = hashes;

  // Only store new state when HPKP is explicitly enabled. If it is
  // disabled, remove the state from the enabled hosts.
  if (pkp_state.HasPublicKeyPins()) {
    enabled_pkp_hosts_[HashHost(canonicalized_host)] = pkp_state;
  } else {
    const HashedHost hashed_host = HashHost(canonicalized_host);
    enabled_pkp_hosts_.erase(hashed_host);
  }

  DirtyNotify();
}

void TransportSecurityState::
    SetEnablePublicKeyPinningBypassForLocalTrustAnchors(bool value) {
  enable_pkp_bypass_for_local_trust_anchors_ = value;
}

TransportSecurityState::PKPStatus TransportSecurityState::CheckPins(
    const HostPortPair& host_port_pair,
    bool is_issued_by_known_root,
    const TransportSecurityState::PKPState& pkp_state,
    const HashValueVector& hashes) {
  if (pkp_state.CheckPublicKeyPins(hashes)) {
    return PKPStatus::OK;
  }

  // Don't report violations for certificates that chain to local roots.
  if (!is_issued_by_known_root && enable_pkp_bypass_for_local_trust_anchors_)
    return PKPStatus::BYPASSED;

  return PKPStatus::VIOLATED;
}

bool TransportSecurityState::DeleteDynamicDataForHost(const std::string& host) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  const std::vector<uint8_t> canonicalized_host = CanonicalizeHost(host);
  if (canonicalized_host.empty())
    return false;

  const HashedHost hashed_host = HashHost(canonicalized_host);
  bool deleted = false;
  auto sts_interator = enabled_sts_hosts_.find(hashed_host);
  if (sts_interator != enabled_sts_hosts_.end()) {
    enabled_sts_hosts_.erase(sts_interator);
    deleted = true;
  }

  auto pkp_iterator = enabled_pkp_hosts_.find(hashed_host);
  if (pkp_iterator != enabled_pkp_hosts_.end()) {
    enabled_pkp_hosts_.erase(pkp_iterator);
    deleted = true;
  }

  if (deleted)
    DirtyNotify();
  return deleted;
}

void TransportSecurityState::ClearDynamicData() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  enabled_sts_hosts_.clear();
  enabled_pkp_hosts_.clear();
}

void TransportSecurityState::DeleteAllDynamicDataBetween(
    base::Time start_time,
    base::Time end_time,
    base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  bool dirtied = false;
  auto sts_iterator = enabled_sts_hosts_.begin();
  while (sts_iterator != enabled_sts_hosts_.end()) {
    if (sts_iterator->second.last_observed >= start_time &&
        sts_iterator->second.last_observed < end_time) {
      dirtied = true;
      enabled_sts_hosts_.erase(sts_iterator++);
      continue;
    }

    ++sts_iterator;
  }

  auto pkp_iterator = enabled_pkp_hosts_.begin();
  while (pkp_iterator != enabled_pkp_hosts_.end()) {
    if (pkp_iterator->second.last_observed >= start_time &&
        pkp_iterator->second.last_observed < end_time) {
      dirtied = true;
      enabled_pkp_hosts_.erase(pkp_iterator++);
      continue;
    }

    ++pkp_iterator;
  }

  if (dirtied && delegate_)
    delegate_->WriteNow(this, std::move(callback));
  else
    std::move(callback).Run();
}

TransportSecurityState::~TransportSecurityState() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void TransportSecurityState::DirtyNotify() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (delegate_)
    delegate_->StateIsDirty(this);
}

bool TransportSecurityState::AddHSTSHeader(std::string_view host,
                                           std::string_view value) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  base::Time now = base::Time::Now();
  base::TimeDelta max_age;
  bool include_subdomains;
  if (!ParseHSTSHeader(value, &max_age, &include_subdomains)) {
    return false;
  }

  // Handle max-age == 0.
  STSState::UpgradeMode upgrade_mode;
  if (max_age.InSeconds() == 0) {
    upgrade_mode = STSState::MODE_DEFAULT;
  } else {
    upgrade_mode = STSState::MODE_FORCE_HTTPS;
  }

  AddHSTSInternal(host, upgrade_mode, now + max_age, include_subdomains);
  return true;
}

void TransportSecurityState::AddHSTS(std::string_view host,
                                     const base::Time& expiry,
                                     bool include_subdomains) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  AddHSTSInternal(host, STSState::MODE_FORCE_HTTPS, expiry, include_subdomains);
}

void TransportSecurityState::AddHPKP(std::string_view host,
                                     const base::Time& expiry,
                                     bool include_subdomains,
                                     const HashValueVector& hashes) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  AddHPKPInternal(host, base::Time::Now(), expiry, include_subdomains, hashes);
}

size_t TransportSecurityState::num_sts_entries() const {
  return enabled_sts_hosts_.size();
}

// static
bool TransportSecurityState::IsBuildTimely() {
  const base::Time build_time = base::GetBuildTime();
  // We consider built-in information to be timely for 10 weeks.
  return (base::Time::Now() - build_time).InDays() < 70 /* 10 weeks */;
}

TransportSecurityState::PKPStatus
TransportSecurityState::CheckPublicKeyPinsImpl(
    const HostPortPair& host_port_pair,
    bool is_issued_by_known_root,
    const HashValueVector& hashes) {
  PKPState pkp_state;
  bool found_state = GetPKPState(host_port_pair.host(), &pkp_state);

  // HasPublicKeyPins should have returned true in order for this method to have
  // been called.
  DCHECK(found_state);
  return CheckPins(host_port_pair, is_issued_by_known_root, pkp_state, hashes);
}

bool TransportSecurityState::GetStaticSTSState(const std::string& host,
                                               STSState* sts_result) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!IsBuildTimely())
    return false;

  PreloadResult result;
  if (DecodeHSTSPreload(host, &result) &&
      hsts_host_bypass_list_.find(host) == hsts_host_bypass_list_.end() &&
      result.force_https) {
    sts_result->domain = host.substr(result.hostname_offset);
    sts_result->include_subdomains = result.sts_include_subdomains;
    sts_result->last_observed = base::GetBuildTime();
    sts_result->upgrade_mode = STSState::MODE_FORCE_HTTPS;
    return true;
  }

  return false;
}

bool TransportSecurityState::GetStaticPKPState(const std::string& host,
                                               PKPState* pkp_result) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!enable_static_pins_ || !IsStaticPKPListTimely() ||
      !base::FeatureList::IsEnabled(features::kStaticKeyPinningEnforcement)) {
    return false;
  }

  PreloadResult result;
  if (host_pins_.has_value()) {
    // Ensure that |host| is a valid hostname before processing.
    if (CanonicalizeHost(host).empty()) {
      return false;
    }
    // Normalize any trailing '.' used for DNS suffix searches.
    std::string normalized_host = host;
    size_t trailing_dot_found = normalized_host.find_last_not_of('.');
    if (trailing_dot_found == std::string::npos) {
      // Hostname is either empty or all dots
      return false;
    }
    normalized_host.erase(trailing_dot_found + 1);
    normalized_host = base::ToLowerASCII(normalized_host);

    std::string_view search_hostname = normalized_host;
    while (true) {
      auto iter = host_pins_->find(search_hostname);
      // Only consider this a match if either include_subdomains is set, or
      // this is an exact match of the full hostname.
      if (iter != host_pins_->end() &&
          (iter->second.second || search_hostname == normalized_host)) {
        pkp_result->domain = std::string(search_hostname);
        pkp_result->last_observed = key_pins_list_last_update_time_;
        pkp_result->include_subdomains = iter->second.second;
        const PinSet* pinset = iter->second.first;
        for (const auto& hash : pinset->static_spki_hashes()) {
          // If the update is malformed, it's preferable to skip the hash than
          // crash.
          if (hash.size() == 32) {
            AddHash(reinterpret_cast<const char*>(hash.data()),
                    &pkp_result->spki_hashes);
          }
        }
        for (const auto& hash : pinset->bad_static_spki_hashes()) {
          // If the update is malformed, it's preferable to skip the hash than
          // crash.
          if (hash.size() == 32) {
            AddHash(reinterpret_cast<const char*>(hash.data()),
                    &pkp_result->bad_spki_hashes);
          }
        }
        return true;
      }
      auto dot_pos = search_hostname.find(".");
      if (dot_pos == std::string::npos) {
        // If this was not a match, and there are no more dots in the string,
        // there are no more domains to try.
        return false;
      }
      // Try again in case this is a subdomain of a pinned domain that includes
      // subdomains.
      search_hostname = search_hostname.substr(dot_pos + 1);
    }
  } else if (DecodeHSTSPreload(host, &result) && result.has_pins) {
    if (result.pinset_id >= g_hsts_source->pinsets_count)
      return false;

    pkp_result->domain = host.substr(result.hostname_offset);
    pkp_result->include_subdomains = result.pkp_include_subdomains;
    pkp_result->last_observed = base::GetBuildTime();

    const TransportSecurityStateSource::Pinset* pinset =
        &g_hsts_source->pinsets[result.pinset_id];

    if (pinset->accepted_pins) {
      const char* const* sha256_hash = pinset->accepted_pins;
      while (*sha256_hash) {
        AddHash(*sha256_hash, &pkp_result->spki_hashes);
        sha256_hash++;
      }
    }
    if (pinset->rejected_pins) {
      const char* const* sha256_hash = pinset->rejected_pins;
      while (*sha256_hash) {
        AddHash(*sha256_hash, &pkp_result->bad_spki_hashes);
        sha256_hash++;
      }
    }
    return true;
  }

  return false;
}

bool TransportSecurityState::GetSTSState(const std::string& host,
                                         STSState* result) {
  return GetDynamicSTSState(host, result) || GetStaticSTSState(host, result);
}

bool TransportSecurityState::GetPKPState(const std::string& host,
                                         PKPState* result) {
  return GetDynamicPKPState(host, result) || GetStaticPKPState(host, result);
}

bool TransportSecurityState::GetDynamicSTSState(const std::string& host,
                                                STSState* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  const std::vector<uint8_t> canonicalized_host = CanonicalizeHost(host);
  if (canonicalized_host.empty())
    return false;

  base::Time current_time(base::Time::Now());

  for (size_t i = 0; canonicalized_host[i]; i += canonicalized_host[i] + 1) {
    base::span<const uint8_t> host_sub_chunk =
        base::make_span(canonicalized_host).subspan(i);
    auto j = enabled_sts_hosts_.find(HashHost(host_sub_chunk));
    if (j == enabled_sts_hosts_.end())
      continue;

    // If the entry is invalid, drop it.
    if (current_time > j->second.expiry) {
      enabled_sts_hosts_.erase(j);
      DirtyNotify();
      continue;
    }

    // An entry matches if it is either an exact match, or if it is a prefix
    // match and the includeSubDomains directive was included.
    if (i == 0 || j->second.include_subdomains) {
      std::optional<std::string> dotted_name =
          dns_names_util::NetworkToDottedName(host_sub_chunk);
      if (!dotted_name)
        return false;

      *result = j->second;
      result->domain = std::move(dotted_name).value();
      return true;
    }
  }

  return false;
}

bool TransportSecurityState::GetDynamicPKPState(const std::string& host,
                                                PKPState* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  const std::vector<uint8_t> canonicalized_host = CanonicalizeHost(host);
  if (canonicalized_host.empty())
    return false;

  base::Time current_time(base::Time::Now());

  for (size_t i = 0; canonicalized_host[i]; i += canonicalized_host[i] + 1) {
    base::span<const uint8_t> host_sub_chunk =
        base::make_span(canonicalized_host).subspan(i);
    auto j = enabled_pkp_hosts_.find(HashHost(host_sub_chunk));
    if (j == enabled_pkp_hosts_.end())
      continue;

    // If the entry is invalid, drop it.
    if (current_time > j->second.expiry) {
      enabled_pkp_hosts_.erase(j);
      DirtyNotify();
      continue;
    }

    // If this is the most specific PKP match, add it to the result. Note: a PKP
    // entry at a more specific domain overrides a less specific domain whether
    // or not |include_subdomains| is set.
    //
    // TODO(davidben): This does not match the HSTS behavior. We no longer
    // implement HPKP, so this logic is only used via AddHPKP(), reachable from
    // Cronet.
    if (i == 0 || j->second.include_subdomains) {
      std::optional<std::string> dotted_name =
          dns_names_util::NetworkToDottedName(host_sub_chunk);
      if (!dotted_name)
        return false;

      *result = j->second;
      result->domain = std::move(dotted_name).value();
      return true;
    }

    break;
  }

  return false;
}

void TransportSecurityState::AddOrUpdateEnabledSTSHosts(
    const HashedHost& hashed_host,
    const STSState& state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(state.ShouldUpgradeToSSL());
  enabled_sts_hosts_[hashed_host] = state;
}

TransportSecurityState::STSState::STSState() = default;

TransportSecurityState::STSState::~STSState() = default;

bool TransportSecurityState::STSState::ShouldUpgradeToSSL() const {
  return upgrade_mode == MODE_FORCE_HTTPS;
}

TransportSecurityState::STSStateIterator::STSStateIterator(
    const TransportSecurityState& state)
    : iterator_(state.enabled_sts_hosts_.begin()),
      end_(state.enabled_sts_hosts_.end()) {}

TransportSecurityState::STSStateIterator::~STSStateIterator() = default;

TransportSecurityState::PKPState::PKPState() = default;

TransportSecurityState::PKPState::PKPState(const PKPState& other) = default;

TransportSecurityState::PKPState::~PKPState() = default;

TransportSecurityState::PinSet::PinSet(
    std::string name,
    std::vector<std::vector<uint8_t>> static_spki_hashes,
    std::vector<std::vector<uint8_t>> bad_static_spki_hashes)
    : name_(std::move(name)),
      static_spki_hashes_(std::move(static_spki_hashes)),
      bad_static_spki_hashes_(std::move(bad_static_spki_hashes)) {}

TransportSecurityState::PinSet::PinSet(const PinSet& other) = default;
TransportSecurityState::PinSet::~PinSet() = default;

TransportSecurityState::PinSetInfo::PinSetInfo(std::string hostname,
                                               std::string pinset_name,
                                               bool include_subdomains)
    : hostname_(std::move(hostname)),
      pinset_name_(std::move(pinset_name)),
      include_subdomains_(std::move(include_subdomains)) {}

bool TransportSecurityState::PKPState::CheckPublicKeyPins(
    const HashValueVector& hashes) const {
  // Validate that hashes is not empty. By the time this code is called (in
  // production), that should never happen, but it's good to be defensive.
  // And, hashes *can* be empty in some test scenarios.
  if (hashes.empty()) {
    return false;
  }

  if (HashesIntersect(bad_spki_hashes, hashes)) {
    return false;
  }

  // If there are no pins, then any valid chain is acceptable.
  if (spki_hashes.empty())
    return true;

  if (HashesIntersect(spki_hashes, hashes)) {
    return true;
  }

  return false;
}

bool TransportSecurityState::PKPState::HasPublicKeyPins() const {
  return spki_hashes.size() > 0 || bad_spki_hashes.size() > 0;
}

bool TransportSecurityState::IsStaticPKPListTimely() const {
  if (pins_list_always_timely_for_testing_) {
    return true;
  }

  // If the list has not been updated via component updater, freshness depends
  // on the compiled-in list freshness.
  if (!host_pins_.has_value()) {
#if BUILDFLAG(INCLUDE_TRANSPORT_SECURITY_STATE_PRELOAD_LIST)
    return (base::Time::Now() - kPinsListTimestamp).InDays() < 70;
#else
    return false;
#endif
  }
  DCHECK(!key_pins_list_last_update_time_.is_null());
  // Else, we use the last update time.
  return (base::Time::Now() - key_pins_list_last_update_time_).InDays() <
         70 /* 10 weeks */;
}

}  // namespace net

"""

```