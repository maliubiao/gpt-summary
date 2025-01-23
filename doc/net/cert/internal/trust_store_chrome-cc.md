Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The request asks for a functional description of `trust_store_chrome.cc`, its relationship to JavaScript (if any), logical reasoning with inputs/outputs, common usage errors, and debugging context.

**2. Initial Scan and Keyword Identification:**

I first scanned the code for key terms and structures:

* `#include`:  Indicates dependencies on other parts of the Chromium codebase. Notable includes are related to `net/cert`, `crypto`, `base`, and protocol buffers (`.pb.h`). This immediately suggests the file is dealing with certificates, cryptography, and potentially data serialization.
* `ChromeRootCertConstraints`, `ChromeRootStoreData`, `TrustStoreChrome`:  These are the core classes, hinting at the file's purpose.
* `kChromeRootCertList`, `CompiledChromeRootStoreVersion`: These look like constants or data structures related to a built-in list of root certificates.
* `sct_not_after`, `sct_all_after`, `min_version`, `max_version_exclusive`, `permitted_dns_names`: These fields within `ChromeRootCertConstraints` suggest the file handles constraints or policies associated with root certificates. The names hint at security-related features like Signed Certificate Timestamps (SCTs) and versioning.
* `trust_store_`: A member variable of type `TrustStore`. This indicates delegation of core trust management logic to another class.
* `override_constraints_`:  Suggests a mechanism to temporarily modify or test certificate constraints.
* `CreateChromeRootStoreData`, `CreateTrustStoreForTesting`:  Factory methods for creating instances of the related classes.
* `GetConstraintsForCert`: A key function for retrieving constraints associated with a given certificate.
* `ParseCrsConstraintsSwitch`:  Indicates a command-line switch for configuring constraints, further reinforcing the testing and override functionality.

**3. Inferring Functionality:**

Based on the keywords and structure, I started inferring the file's primary responsibilities:

* **Managing a List of Trusted Root Certificates:** The "Chrome Root Store" in the names clearly indicates this. The `kChromeRootCertList` likely holds the actual certificate data.
* **Defining and Applying Constraints:**  The `ChromeRootCertConstraints` class and related methods strongly suggest the file enforces rules about how these root certificates can be used.
* **Providing an Interface for Trust Decisions:** The `TrustStoreChrome` class likely offers methods (`GetTrust`, `Contains`) used by other parts of the browser to determine if a certificate is trusted.
* **Supporting Testing and Overrides:** The command-line switch parsing and the `override_constraints_` member point to a testing mechanism.
* **Handling Updates (Implicit):**  While not explicitly managing the *update process*, the presence of protocol buffer usage (`chrome_root_store::RootStore`) and the `CreateChromeRootStoreData` function suggests this component might consume data from an update mechanism.

**4. Examining Key Methods and Data Structures:**

I looked at the implementations of crucial methods:

* **`CreateChromeRootStoreData`:**  This function parses a protobuf message to populate `ChromeRootStoreData`, solidifying the idea of consuming external data. The error handling during parsing is important.
* **`TrustStoreChrome` constructors:**  These handle loading the initial set of root certificates and potentially applying overrides. The distinction between static and non-static certificate loading is interesting.
* **`GetConstraintsForCert`:** This method implements the core logic of retrieving constraints, considering overrides first.
* **`ParseCrsConstraintsSwitch`:**  This confirms the command-line override mechanism and how to specify different constraint types.

**5. Addressing Specific Questions from the Prompt:**

* **Functionality:** Summarize the inferences made above in a clear and concise manner.
* **JavaScript Relationship:**  Actively look for connections. The file is C++, part of the network stack. It's *unlikely* to have direct JavaScript code. However, the *effects* of this code are relevant to web security, which directly impacts JavaScript. This led to the explanation about TLS/HTTPS and how JavaScript relies on trusted certificates.
* **Logical Reasoning (Input/Output):**  Focus on the `GetConstraintsForCert` method as it's the most direct place for demonstrating input and output. Hypothesize different scenarios (no override, matching override, no matching constraints) to illustrate the behavior.
* **Common User/Programming Errors:** Think about misuse or misunderstandings. Incorrect command-line switch syntax and assumptions about how overrides work are prime examples.
* **User Operation to Reach Here (Debugging):**  Trace the path of a user action that would involve certificate validation. Navigating to an HTTPS website is the most obvious example. Then, describe the chain of events in the browser's network stack.

**6. Refining and Organizing:**

Finally, I organized the information logically, using headings and bullet points for clarity. I double-checked for accuracy and completeness based on the code provided. I aimed for a balance between technical detail and clear explanation for someone who might not be deeply familiar with the Chromium network stack.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the internal data structures. I realized the importance of explaining the *purpose* and *impact* of this code, especially regarding its connection (or lack thereof) to JavaScript.
* I initially considered the possibility of the code *dynamically fetching* root certificates, but the provided code leans more towards a compiled-in list with override capabilities. I adjusted my description accordingly.
* When explaining the debugging context, I made sure to start with a user-facing action and work my way down to the code level, making it more relatable.

By following this thought process, which involves scanning, inferring, examining details, addressing specific questions, and refining the presentation, I could generate a comprehensive and accurate analysis of the provided C++ code.
这个文件 `net/cert/internal/trust_store_chrome.cc` 是 Chromium 网络栈中关于 **信任存储（Trust Store）** 的一个核心组件的实现。它专门负责管理和提供 Chromium 浏览器信任的根证书列表及其相关的约束。

**功能概览:**

1. **存储 Chromium 默认信任的根证书列表:**  该文件包含了硬编码的（或编译时包含的）一组被 Chromium 浏览器默认信任的根证书。这些证书用于验证 HTTPS 连接和其他安全连接的服务器证书链的有效性。这部分数据来源于 `net/data/ssl/chrome_root_store/chrome-root-store-inc.cc` 文件。

2. **管理根证书的约束 (Constraints):**  除了存储根证书本身，该文件还管理与这些根证书相关的约束信息。这些约束可以包括：
   - **SCT (Signed Certificate Timestamp) 相关约束:** `sct_not_after`, `sct_all_after`。用于强制要求证书在特定时间后必须包含有效的 SCT 信息，以提高安全性。
   - **版本约束:** `min_version`, `max_version_exclusive`。  允许针对特定的 Chromium 版本应用不同的信任策略。
   - **允许的 DNS 名称:** `permitted_dns_names`。 限制根证书可以颁发证书的域名范围。

3. **提供查询接口:**  `TrustStoreChrome` 类提供了接口，可以查询特定证书是否在信任列表中，以及该证书相关的约束信息。

4. **支持测试时的约束覆盖 (Override):**  允许通过命令行开关 (`kTestCrsConstraintsSwitch`) 在测试环境中覆盖默认的根证书约束，方便进行各种测试场景。

5. **支持从 Protobuf 格式加载根证书数据:**  `CreateChromeRootStoreData` 函数允许从 `chrome_root_store::RootStore` 类型的 Protobuf 消息中加载根证书数据，这可能是用于组件更新或其他动态加载场景。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它对 JavaScript 的功能至关重要，因为它直接影响了浏览器如何验证 HTTPS 连接，而 HTTPS 是现代 Web 应用的基础。

**举例说明:**

当 JavaScript 代码尝试通过 `fetch` 或 `XMLHttpRequest` 向一个 HTTPS 站点发起请求时，Chromium 的网络栈会使用 `TrustStoreChrome` 来验证服务器返回的证书链。

1. **假设输入:** 用户在浏览器的地址栏输入 `https://www.example.com` 并按下回车。
2. **逻辑推理:**
   - Chromium 的网络栈会尝试与 `www.example.com` 建立 TLS 连接。
   - 服务器会发送它的证书以及可能的一些中间证书。
   - Chromium 需要验证服务器证书是否由一个信任的根证书颁发。
   - `TrustStoreChrome` 会被调用，以查找是否存在一个与服务器证书链的根证书匹配的条目。
   - 如果找到匹配的根证书，并且服务器证书满足该根证书的所有约束（例如，SCT 要求，版本要求等），则连接被认为是安全的。
3. **输出:** 如果验证成功，JavaScript 代码的 `fetch` 请求会成功返回数据。如果验证失败（例如，根证书不在信任列表中，或不满足约束），则浏览器会阻止连接，JavaScript 代码会收到一个错误，通常会抛出一个网络错误。

**用户或编程常见的使用错误:**

1. **用户错误：安装了恶意的或过期的根证书:**  用户手动安装了一些不受信任的根证书到他们的操作系统中。虽然 `TrustStoreChrome` 主要管理 Chromium 自己的信任列表，但操作系统级别的信任存储也会被考虑在内。安装不安全的根证书会使得用户容易受到中间人攻击。

2. **编程错误：假设所有环境都使用相同的根证书:**  开发者可能会假设所有用户的浏览器都信任相同的根证书集。然而，企业环境或用户可能出于某些原因修改了他们的信任存储。因此，依赖于特定的非标准根证书可能会导致部分用户无法访问应用。

3. **编程错误：没有正确处理证书验证错误:**  当 HTTPS 连接的证书验证失败时，JavaScript 代码应该能够优雅地处理这些错误，而不是简单地崩溃或显示不友好的错误信息。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入一个 HTTPS 网址并访问。**
2. **浏览器发起网络请求，建立 TCP 连接。**
3. **浏览器和服务器进行 TLS 握手。**
4. **服务器发送它的证书链。**
5. **Chromium 的网络栈 (例如 `net::CertVerifier`) 开始进行证书链验证。**
6. **在证书链验证的过程中，`TrustStoreChrome` 组件会被调用，用于查找和获取可信的根证书。**
7. **`TrustStoreChrome::GetTrust()` 或 `TrustStoreChrome::Contains()` 方法会被调用，以判断证书链中的根证书是否在 Chromium 的信任列表中。**
8. **`TrustStoreChrome::GetConstraintsForCert()` 方法会被调用，以获取与该根证书相关的约束信息。**
9. **验证器会根据获取的根证书和约束信息，以及证书链的其他信息（如有效期，吊销状态等），判断服务器证书是否可信。**
10. **如果验证失败，浏览器会显示安全警告，并且 JavaScript 的网络请求可能会失败。**

**代码细节:**

* **`ChromeRootCertConstraints` 类:** 定义了根证书的约束信息，例如 SCT 要求、版本限制和允许的 DNS 名称。
* **`ChromeRootStoreData` 类:**  表示一组根证书及其约束的集合，可以从 Protobuf 数据中加载。
* **`TrustStoreChrome` 类:**  是主要的信任存储实现类。它维护了信任的根证书列表和相关的约束。
* **`kChromeRootCertList`:**  一个静态数组，包含了 Chromium 默认信任的根证书的信息（DER 编码和约束）。
* **`CompiledChromeRootStoreVersion()`:**  返回当前编译时包含的根证书列表的版本号。
* **`InitializeConstraintsOverrides()` 和 `ParseCrsConstraintsSwitch()`:**  用于处理命令行开关，允许在测试时覆盖根证书的约束。

总而言之，`net/cert/internal/trust_store_chrome.cc` 是 Chromium 网络安全的核心组成部分，它维护着浏览器信任的基础，确保用户与 HTTPS 网站的安全通信。它虽然不直接包含 JavaScript 代码，但其功能直接影响着基于 JavaScript 的 Web 应用的安全性和功能。

### 提示词
```
这是目录为net/cert/internal/trust_store_chrome.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_chrome.h"

#include <optional>

#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/containers/to_vector.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "crypto/sha2.h"
#include "net/cert/root_store_proto_lite/root_store.pb.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"

namespace net {

namespace {
#include "net/data/ssl/chrome_root_store/chrome-root-store-inc.cc"
}  // namespace

ChromeRootCertConstraints::ChromeRootCertConstraints() = default;
ChromeRootCertConstraints::ChromeRootCertConstraints(
    std::optional<base::Time> sct_not_after,
    std::optional<base::Time> sct_all_after,
    std::optional<base::Version> min_version,
    std::optional<base::Version> max_version_exclusive,
    std::vector<std::string> permitted_dns_names)
    : sct_not_after(sct_not_after),
      sct_all_after(sct_all_after),
      min_version(std::move(min_version)),
      max_version_exclusive(std::move(max_version_exclusive)),
      permitted_dns_names(std::move(permitted_dns_names)) {}

ChromeRootCertConstraints::ChromeRootCertConstraints(
    const StaticChromeRootCertConstraints& constraints)
    : sct_not_after(constraints.sct_not_after),
      sct_all_after(constraints.sct_all_after),
      min_version(constraints.min_version),
      max_version_exclusive(constraints.max_version_exclusive) {
  for (std::string_view name : constraints.permitted_dns_names) {
    permitted_dns_names.emplace_back(name);
  }
  if (min_version) {
    CHECK(min_version->IsValid());
  }
  if (max_version_exclusive) {
    CHECK(max_version_exclusive->IsValid());
  }
}

ChromeRootCertConstraints::~ChromeRootCertConstraints() = default;
ChromeRootCertConstraints::ChromeRootCertConstraints(
    const ChromeRootCertConstraints& other) = default;
ChromeRootCertConstraints::ChromeRootCertConstraints(
    ChromeRootCertConstraints&& other) = default;
ChromeRootCertConstraints& ChromeRootCertConstraints::operator=(
    const ChromeRootCertConstraints& other) = default;
ChromeRootCertConstraints& ChromeRootCertConstraints::operator=(
    ChromeRootCertConstraints&& other) = default;

ChromeRootStoreData::Anchor::Anchor(
    std::shared_ptr<const bssl::ParsedCertificate> certificate,
    std::vector<ChromeRootCertConstraints> constraints)
    : certificate(std::move(certificate)),
      constraints(std::move(constraints)) {}
ChromeRootStoreData::Anchor::~Anchor() = default;

ChromeRootStoreData::Anchor::Anchor(const Anchor& other) = default;
ChromeRootStoreData::Anchor::Anchor(Anchor&& other) = default;
ChromeRootStoreData::Anchor& ChromeRootStoreData::Anchor::operator=(
    const ChromeRootStoreData::Anchor& other) = default;
ChromeRootStoreData::Anchor& ChromeRootStoreData::Anchor::operator=(
    ChromeRootStoreData::Anchor&& other) = default;

ChromeRootStoreData::ChromeRootStoreData() = default;
ChromeRootStoreData::~ChromeRootStoreData() = default;

ChromeRootStoreData::ChromeRootStoreData(const ChromeRootStoreData& other) =
    default;
ChromeRootStoreData::ChromeRootStoreData(ChromeRootStoreData&& other) = default;
ChromeRootStoreData& ChromeRootStoreData::operator=(
    const ChromeRootStoreData& other) = default;
ChromeRootStoreData& ChromeRootStoreData::operator=(
    ChromeRootStoreData&& other) = default;

std::optional<ChromeRootStoreData>
ChromeRootStoreData::CreateChromeRootStoreData(
    const chrome_root_store::RootStore& proto) {
  ChromeRootStoreData root_store_data;

  for (auto& anchor : proto.trust_anchors()) {
    if (anchor.der().empty()) {
      LOG(ERROR) << "Error anchor with empty DER in update";
      return std::nullopt;
    }

    auto parsed = bssl::ParsedCertificate::Create(
        net::x509_util::CreateCryptoBuffer(anchor.der()),
        net::x509_util::DefaultParseCertificateOptions(), nullptr);
    if (!parsed) {
      LOG(ERROR) << "Error parsing cert for update";
      return std::nullopt;
    }

    std::vector<ChromeRootCertConstraints> constraints;
    for (const auto& constraint : anchor.constraints()) {
      std::optional<base::Version> min_version;
      if (constraint.has_min_version()) {
        min_version = base::Version(constraint.min_version());
        if (!min_version->IsValid()) {
          LOG(ERROR) << "Error parsing version";
          return std::nullopt;
        }
      }

      std::optional<base::Version> max_version_exclusive;
      if (constraint.has_max_version_exclusive()) {
        max_version_exclusive =
            base::Version(constraint.max_version_exclusive());
        if (!max_version_exclusive->IsValid()) {
          LOG(ERROR) << "Error parsing version";
          return std::nullopt;
        }
      }

      constraints.emplace_back(
          constraint.has_sct_not_after_sec()
              ? std::optional(base::Time::UnixEpoch() +
                              base::Seconds(constraint.sct_not_after_sec()))
              : std::nullopt,
          constraint.has_sct_all_after_sec()
              ? std::optional(base::Time::UnixEpoch() +
                              base::Seconds(constraint.sct_all_after_sec()))
              : std::nullopt,
          min_version, max_version_exclusive,
          base::ToVector(constraint.permitted_dns_names()));
    }
    root_store_data.anchors_.emplace_back(std::move(parsed),
                                          std::move(constraints));
  }

  root_store_data.version_ = proto.version_major();

  return root_store_data;
}

TrustStoreChrome::TrustStoreChrome()
    : TrustStoreChrome(
          kChromeRootCertList,
          /*certs_are_static=*/true,
          /*version=*/CompiledChromeRootStoreVersion(),
          /*override_constraints=*/InitializeConstraintsOverrides()) {}

TrustStoreChrome::TrustStoreChrome(base::span<const ChromeRootCertInfo> certs,
                                   bool certs_are_static,
                                   int64_t version,
                                   ConstraintOverrideMap override_constraints)
    : override_constraints_(std::move(override_constraints)) {
  std::vector<
      std::pair<std::string_view, std::vector<ChromeRootCertConstraints>>>
      constraints;

  // TODO(hchao, sleevi): Explore keeping a CRYPTO_BUFFER of just the DER
  // certificate and subject name. This would hopefully save memory compared
  // to keeping the full parsed representation in memory, especially when
  // there are multiple instances of TrustStoreChrome.
  for (const auto& cert_info : certs) {
    bssl::UniquePtr<CRYPTO_BUFFER> cert;
    if (certs_are_static) {
      // TODO(mattm,hchao): Ensure the static data crypto_buffers for the
      // compiled-in roots are kept alive, so that roots from the component
      // updater data will de-dupe against them. This currently works if the
      // new components roots are the same as the compiled in roots, but
      // fails if a component update drops a root and then the next component
      // update readds the root without a restart.
      cert = x509_util::CreateCryptoBufferFromStaticDataUnsafe(
          cert_info.root_cert_der);
    } else {
      cert = x509_util::CreateCryptoBuffer(cert_info.root_cert_der);
    }
    bssl::CertErrors errors;
    auto parsed = bssl::ParsedCertificate::Create(
        std::move(cert), x509_util::DefaultParseCertificateOptions(), &errors);
    // There should always be a valid cert, because we should be parsing Chrome
    // Root Store static data compiled in.
    CHECK(parsed);
    if (!cert_info.constraints.empty()) {
      std::vector<ChromeRootCertConstraints> cert_constraints;
      for (const auto& constraint : cert_info.constraints) {
        cert_constraints.emplace_back(constraint);
      }
      constraints.emplace_back(parsed->der_cert().AsStringView(),
                               std::move(cert_constraints));
    }
    trust_store_.AddTrustAnchor(std::move(parsed));
  }

  constraints_ = base::flat_map(std::move(constraints));
  version_ = version;
}

TrustStoreChrome::TrustStoreChrome(const ChromeRootStoreData& root_store_data)
    : override_constraints_(InitializeConstraintsOverrides()) {
  std::vector<
      std::pair<std::string_view, std::vector<ChromeRootCertConstraints>>>
      constraints;

  for (const auto& anchor : root_store_data.anchors()) {
    if (!anchor.constraints.empty()) {
      constraints.emplace_back(anchor.certificate->der_cert().AsStringView(),
                               anchor.constraints);
    }
    trust_store_.AddTrustAnchor(anchor.certificate);
  }

  constraints_ = base::flat_map(std::move(constraints));
  version_ = root_store_data.version();
}

TrustStoreChrome::~TrustStoreChrome() = default;

TrustStoreChrome::ConstraintOverrideMap
TrustStoreChrome::InitializeConstraintsOverrides() {
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  if (command_line->HasSwitch(kTestCrsConstraintsSwitch)) {
    return ParseCrsConstraintsSwitch(
        command_line->GetSwitchValueASCII(kTestCrsConstraintsSwitch));
  }

  return {};
}

TrustStoreChrome::ConstraintOverrideMap
TrustStoreChrome::ParseCrsConstraintsSwitch(std::string_view switch_value) {
  // This function constructs a flat_map on the fly rather than the more
  // efficient approach of creating a vector first and then constructing the
  // flat_map from that. It is expected that there will only be a small number
  // of elements in the map, and that this is only used for testing, therefore
  // simplicity of the implementation is weighted higher than theoretical
  // efficiency.
  ConstraintOverrideMap constraints;

  base::StringPairs roots_and_constraints_pairs;
  base::SplitStringIntoKeyValuePairs(switch_value, ':', '+',
                                     &roots_and_constraints_pairs);
  for (const auto& [root_hashes_hex, root_constraints] :
       roots_and_constraints_pairs) {
    std::vector<std::array<uint8_t, crypto::kSHA256Length>> root_hashes;
    for (std::string_view root_hash_hex :
         base::SplitStringPiece(root_hashes_hex, ",", base::TRIM_WHITESPACE,
                                base::SPLIT_WANT_NONEMPTY)) {
      std::array<uint8_t, crypto::kSHA256Length> root_hash;
      if (!base::HexStringToSpan(root_hash_hex, root_hash)) {
        LOG(ERROR) << "invalid root hash: " << root_hash_hex;
        continue;
      }
      root_hashes.push_back(std::move(root_hash));
    }
    if (root_hashes.empty()) {
      LOG(ERROR) << "skipped constraintset with no valid root hashes";
      continue;
    }
    ChromeRootCertConstraints constraint;
    base::StringPairs constraint_value_pairs;
    base::SplitStringIntoKeyValuePairs(root_constraints, '=', ',',
                                       &constraint_value_pairs);
    for (const auto& [constraint_name, constraint_value] :
         constraint_value_pairs) {
      std::string constraint_name_lower = base::ToLowerASCII(constraint_name);
      if (constraint_name_lower == "sctnotafter") {
        int64_t value;
        if (!base::StringToInt64(constraint_value, &value)) {
          LOG(ERROR) << "invalid sctnotafter: " << constraint_value;
          continue;
        }
        constraint.sct_not_after =
            base::Time::UnixEpoch() + base::Seconds(value);
      } else if (constraint_name_lower == "sctallafter") {
        int64_t value;
        if (!base::StringToInt64(constraint_value, &value)) {
          LOG(ERROR) << "invalid sctallafter: " << constraint_value;
          continue;
        }
        constraint.sct_all_after =
            base::Time::UnixEpoch() + base::Seconds(value);
      } else if (constraint_name_lower == "minversion") {
        base::Version version(constraint_value);
        if (!version.IsValid()) {
          LOG(ERROR) << "invalid minversion: " << constraint_value;
          continue;
        }
        constraint.min_version = version;
      } else if (constraint_name_lower == "maxversionexclusive") {
        base::Version version(constraint_value);
        if (!version.IsValid()) {
          LOG(ERROR) << "invalid maxversionexclusive: " << constraint_value;
          continue;
        }
        constraint.max_version_exclusive = version;
      } else if (constraint_name_lower == "dns") {
        constraint.permitted_dns_names.push_back(constraint_value);
      } else {
        LOG(ERROR) << "unrecognized constraint " << constraint_name_lower;
      }
      // TODO(crbug.com/40941039): add other constraint types here when they
      // are implemented
    }
    for (const auto& root_hash : root_hashes) {
      constraints[root_hash].push_back(constraint);
    }
  }

  return constraints;
}

void TrustStoreChrome::SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                                        bssl::ParsedCertificateList* issuers) {
  trust_store_.SyncGetIssuersOf(cert, issuers);
}

bssl::CertificateTrust TrustStoreChrome::GetTrust(
    const bssl::ParsedCertificate* cert) {
  return trust_store_.GetTrust(cert);
}

bool TrustStoreChrome::Contains(const bssl::ParsedCertificate* cert) const {
  return trust_store_.Contains(cert);
}

base::span<const ChromeRootCertConstraints>
TrustStoreChrome::GetConstraintsForCert(
    const bssl::ParsedCertificate* cert) const {
  if (!override_constraints_.empty()) {
    const std::array<uint8_t, crypto::kSHA256Length> cert_hash =
        crypto::SHA256Hash(cert->der_cert());
    auto it = override_constraints_.find(cert_hash);
    if (it != override_constraints_.end()) {
      return it->second;
    }
  }

  auto it = constraints_.find(cert->der_cert().AsStringView());
  if (it != constraints_.end()) {
    return it->second;
  }
  return {};
}

// static
std::unique_ptr<TrustStoreChrome> TrustStoreChrome::CreateTrustStoreForTesting(
    base::span<const ChromeRootCertInfo> certs,
    int64_t version,
    ConstraintOverrideMap override_constraints) {
  // Note: wrap_unique is used because the constructor is private.
  return base::WrapUnique(new TrustStoreChrome(
      certs,
      /*certs_are_static=*/false,
      /*version=*/version, std::move(override_constraints)));
}

int64_t CompiledChromeRootStoreVersion() {
  return kRootStoreVersion;
}

std::vector<ChromeRootStoreData::Anchor> CompiledChromeRootStoreAnchors() {
  std::vector<ChromeRootStoreData::Anchor> anchors;
  for (const auto& cert_info : kChromeRootCertList) {
    bssl::UniquePtr<CRYPTO_BUFFER> cert =
        x509_util::CreateCryptoBufferFromStaticDataUnsafe(
            cert_info.root_cert_der);
    bssl::CertErrors errors;
    auto parsed = bssl::ParsedCertificate::Create(
        std::move(cert), x509_util::DefaultParseCertificateOptions(), &errors);
    DCHECK(parsed);

    std::vector<ChromeRootCertConstraints> cert_constraints;
    for (const auto& constraint : cert_info.constraints) {
      cert_constraints.emplace_back(constraint);
    }
    anchors.emplace_back(std::move(parsed), std::move(cert_constraints));
  }

  return anchors;
}

}  // namespace net
```