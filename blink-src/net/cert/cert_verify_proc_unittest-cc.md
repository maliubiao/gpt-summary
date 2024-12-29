Response:
The user wants to understand the functionality of the `cert_verify_proc_unittest.cc` file in the Chromium network stack. I need to analyze the provided code snippet to:

1. **Summarize its purpose:** This file contains unit tests for the `CertVerifyProc` class and its implementations.
2. **Identify connections to JavaScript:** Determine if any of the tested functionalities directly relate to how JavaScript interacts with certificate verification in a browser.
3. **Illustrate logic with examples:** If the tests involve logical reasoning (e.g., expected verification outcomes based on certificate properties), create hypothetical inputs and their expected outputs.
4. **Point out potential user/programmer errors:** Identify common mistakes related to certificate handling that these tests might be uncovering.
5. **Explain how a user might reach this code:** Describe user actions that trigger certificate verification, leading to these tests being relevant during debugging.

**Plan:**

1. Read through the included headers to understand the dependencies and main areas of focus.
2. Analyze the helper functions and mock classes to grasp the testing methodologies.
3. Examine the test cases defined within the `CertVerifyProcInternalTest` fixture to identify the specific functionalities being tested.
4. Relate the tested functionalities to browser behavior and potential JavaScript interactions.
5. Formulate examples of inputs, outputs, common errors, and user scenarios.
这是Chromium网络栈中 `net/cert/cert_verify_proc_unittest.cc` 文件的第一部分，其主要功能是 **测试 `CertVerifyProc` 及其具体实现类的各种证书验证场景**。

**功能归纳:**

这个文件主要用于对 Chromium 的证书验证流程进行单元测试，具体包括：

* **测试不同 `CertVerifyProc` 实现:**  针对不同的平台 (Android, iOS, Fuchsia, 以及内置的 Chrome Root Store 版本) 测试其特定的证书验证逻辑。
* **测试证书链的验证:**  测试在各种情况下（例如，信任的根证书，不信任的中间证书）证书链的验证结果。
* **测试 EV 证书验证:**  测试对扩展验证 (EV) 证书的识别和验证逻辑，包括存在多个策略 OID 的情况。
* **测试被信任的证书:**  测试直接被信任的证书的验证行为，包括其是否会被识别为 EV 证书。
* **测试 Common Name 和 Subject Alternative Name (SAN):**  测试证书的 Common Name 和 SAN 字段中包含空字符时的验证行为。
* **测试无效的证书:**  测试当目标证书或中间证书本身存在错误时的验证行为。
* **测试过期证书:**  （虽然这部分代码片段没有直接展示过期证书的测试，但文件名 `cert_verify_proc_unittest.cc` 暗示了这类测试的存在，并且后续部分很可能会包含）。

**与 JavaScript 功能的关系 (推测):**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它测试的网络栈组件 `CertVerifyProc` **直接影响着浏览器中 JavaScript 发起的网络请求的安全性**。

当 JavaScript 代码 (例如，通过 `fetch` 或 `XMLHttpRequest`) 发起 HTTPS 请求时，浏览器底层会使用 `CertVerifyProc` 来验证服务器提供的证书。验证结果决定了连接是否安全，以及是否向 JavaScript 返回请求内容。

**举例说明:**

假设一个 JavaScript 代码尝试访问一个 HTTPS 网站：

```javascript
fetch('https://example.com')
  .then(response => {
    // 处理响应
  })
  .catch(error => {
    // 处理错误，例如证书验证失败
    console.error("网络请求错误:", error);
  });
```

* **假设输入:** 服务器 `example.com` 返回一个由 Chromium 信任的根证书签名的有效证书。
* **预期输出:** `CertVerifyProc` 验证成功，JavaScript 代码的 `then` 分支会被执行，并能正常处理来自 `example.com` 的响应。

* **假设输入:** 服务器 `example.com` 返回一个过期证书。
* **预期输出:** `CertVerifyProc` 验证失败，返回一个表示证书错误的错误码 (例如 `ERR_CERT_DATE_INVALID`)。JavaScript 代码的 `catch` 分支会被执行，并打印包含证书错误的 `error` 对象。

**逻辑推理的假设输入与输出 (基于已提供的代码):**

* **假设输入:**  一个证书链，其中根证书被信任，但中间证书被显式不信任 (通过 `ScopedTestRoot` 设置)。
* **预期输出:**  `Verify` 函数返回一个错误码，指示证书授权无效 (`ERR_CERT_AUTHORITY_INVALID`)，因为验证过程在遇到不信任的中间证书时会停止。

* **假设输入:** 一个证书，其 Common Name 中包含空字符，但拥有一个有效的 SAN。请求访问的域名与 SAN 匹配。
* **预期输出:** `Verify` 函数返回成功 (`IsOk()`)，因为现代浏览器主要依赖 SAN 进行域名匹配，而忽略 Common Name 中的问题。

* **假设输入:** 一个目标证书，其格式不符合规范，例如签名算法为空。
* **预期输出:** `Verify` 函数返回一个表示证书无效的错误码 (`ERR_CERT_INVALID`)，并且 `verify_result.cert_status` 会包含 `CERT_STATUS_INVALID` 标志。

**涉及用户或编程常见的使用错误 (推测):**

* **用户错误:**  用户可能会遇到证书错误，例如访问到一个使用了过期证书或由未知 CA 签名的网站。这些场景会触发底层的证书验证，而 `cert_verify_proc_unittest.cc` 中的测试确保了 Chromium 能正确处理这些情况并向用户显示合适的错误信息。
* **编程错误 (服务器配置):** 网站管理员可能会错误地配置其服务器的证书，例如使用了不完整的证书链，或配置了错误的中间证书。Chromium 的证书验证会检测到这些问题，并阻止用户访问不安全的网站。
* **编程错误 (测试代码):**  在开发或测试涉及 HTTPS 的应用时，开发者可能会使用自签名证书或测试证书。如果这些证书没有被正确信任，`CertVerifyProc` 会验证失败。开发者需要理解如何将测试证书添加到信任列表中。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，或点击一个 HTTPS 链接。**
2. **浏览器发起与服务器的 TLS 连接。**
3. **服务器在 TLS 握手过程中向浏览器发送其证书链。**
4. **Chromium 的网络栈接收到证书链后，会调用 `CertVerifyProc` 的 `Verify` 方法来验证证书的有效性。**
5. **`CertVerifyProc` 内部会执行一系列检查，包括:**
    * 检查证书签名是否有效。
    * 检查证书是否过期。
    * 检查证书的颁发者是否被信任。
    * 检查证书的域名是否与请求的域名匹配 (通过 Common Name 或 SAN)。
    * 检查证书是否被吊销 (例如，通过 CRL 或 OCSP)。
    * (对于 EV 证书) 检查证书是否符合 EV 标准。
6. **如果验证失败，`Verify` 方法会返回一个错误码，浏览器会根据错误码显示相应的安全警告或错误页面。**
7. **在开发或调试 Chromium 时，如果怀疑证书验证流程有问题，开发者可以运行 `cert_verify_proc_unittest` 中的测试用例来验证 `CertVerifyProc` 的行为是否符合预期。**  例如，如果用户报告了某个网站的证书错误，开发者可以尝试重现该错误并使用测试用例来隔离和修复问题。

总结来说，`cert_verify_proc_unittest.cc` 的第一部分定义了用于测试 Chromium 证书验证核心组件的基础框架和一些关键的测试用例，涵盖了证书链验证、EV 证书处理以及对错误证书的处理。 这些测试对于确保用户浏览 HTTPS 网站的安全性至关重要。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc.h"

#include <memory>
#include <string_view>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/message_loop/message_pump_type.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "crypto/sha2.h"
#include "net/base/cronet_buildflags.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc_builtin.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/cert_net/cert_net_fetcher_url_request.h"
#include "net/log/test_net_log.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/gtest_util.h"
#include "net/test/revocation_builder.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_context_getter.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/pki/extended_key_usage.h"
#include "third_party/boringssl/src/pki/input.h"
#include "third_party/boringssl/src/pki/ocsp_revocation_status.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "third_party/boringssl/src/pki/parser.h"
#include "third_party/boringssl/src/pki/pem.h"
#include "third_party/boringssl/src/pki/signature_algorithm.h"
#include "third_party/boringssl/src/pki/trust_store.h"

#if BUILDFLAG(IS_ANDROID)
#include "net/cert/cert_verify_proc_android.h"
#elif BUILDFLAG(IS_IOS)
#include "base/ios/ios_util.h"
#include "net/cert/cert_verify_proc_ios.h"
#elif BUILDFLAG(IS_MAC)
#include "base/mac/mac_util.h"
#endif

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif

using net::test::IsError;
using net::test::IsOk;

using base::HexEncode;

namespace net {

namespace {

const char kTrustAnchorVerifyHistogram[] = "Net.Certificate.TrustAnchor.Verify";
const char kTrustAnchorVerifyOutOfDateHistogram[] =
    "Net.Certificate.TrustAnchor.VerifyOutOfDate";

// Returns a TLV to use as an unknown signature algorithm when building a cert.
// The specific contents are as follows (the OID is from
// https://davidben.net/oid):
//
// SEQUENCE {
//   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.0 }
//   NULL {}
// }
std::string TestOid0SignatureAlgorithmTLV() {
  constexpr uint8_t kTestOid0SigAlgTLV[] = {0x30, 0x10, 0x06, 0x0c, 0x2a, 0x86,
                                            0x48, 0x86, 0xf7, 0x12, 0x04, 0x01,
                                            0x84, 0xb7, 0x09, 0x00, 0x05, 0x00};
  return std::string(std::begin(kTestOid0SigAlgTLV),
                     std::end(kTestOid0SigAlgTLV));
}

// An OID for use in tests, from https://davidben.net/oid
// OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.0 }
bssl::der::Input TestOid0() {
  static uint8_t kTestOid0[] = {0x06, 0x0c, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                0x12, 0x04, 0x01, 0x84, 0xb7, 0x09, 0x00};
  return bssl::der::Input(kTestOid0);
}

// Mock CertVerifyProc that sets the CertVerifyResult to a given value for
// all certificates that are Verify()'d
class MockCertVerifyProc : public CertVerifyProc {
 public:
  explicit MockCertVerifyProc(const CertVerifyResult& result)
      : CertVerifyProc(CRLSet::BuiltinCRLSet()), result_(result) {}
  MockCertVerifyProc(const CertVerifyResult& result, int error)
      : CertVerifyProc(CRLSet::BuiltinCRLSet()),
        result_(result),
        error_(error) {}

  MockCertVerifyProc(const MockCertVerifyProc&) = delete;
  MockCertVerifyProc& operator=(const MockCertVerifyProc&) = delete;

 protected:
  ~MockCertVerifyProc() override = default;

 private:
  int VerifyInternal(X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     const std::string& sct_list,
                     int flags,
                     CertVerifyResult* verify_result,
                     const NetLogWithSource& net_log) override;

  const CertVerifyResult result_;
  const int error_ = OK;
};

int MockCertVerifyProc::VerifyInternal(X509Certificate* cert,
                                       const std::string& hostname,
                                       const std::string& ocsp_response,
                                       const std::string& sct_list,
                                       int flags,
                                       CertVerifyResult* verify_result,
                                       const NetLogWithSource& net_log) {
  *verify_result = result_;
  verify_result->verified_cert = cert;
  return error_;
}

// This enum identifies a concrete implemenation of CertVerifyProc.
//
// The type is erased by CreateCertVerifyProc(), however needs to be known for
// some of the test expectations.
enum CertVerifyProcType {
  CERT_VERIFY_PROC_ANDROID,
  CERT_VERIFY_PROC_IOS,
  CERT_VERIFY_PROC_BUILTIN,
  CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS,
};

// Returns a textual description of the CertVerifyProc implementation
// that is being tested, used to give better names to parameterized
// tests.
std::string VerifyProcTypeToName(
    const testing::TestParamInfo<CertVerifyProcType>& params) {
  switch (params.param) {
    case CERT_VERIFY_PROC_ANDROID:
      return "CertVerifyProcAndroid";
    case CERT_VERIFY_PROC_IOS:
      return "CertVerifyProcIOS";
    case CERT_VERIFY_PROC_BUILTIN:
      return "CertVerifyProcBuiltin";
    case CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS:
      return "CertVerifyProcBuiltinChromeRoots";
  }

  return "";
}

scoped_refptr<CertVerifyProc> CreateCertVerifyProc(
    CertVerifyProcType type,
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    scoped_refptr<CRLSet> crl_set,
    CertificateList additional_trust_anchors,
    CertificateList additional_untrusted_authorities) {
  CertVerifyProc::InstanceParams instance_params;
  instance_params.additional_trust_anchors =
      net::x509_util::ParseAllValidCerts(additional_trust_anchors);
  instance_params.additional_untrusted_authorities =
      net::x509_util::ParseAllValidCerts(additional_untrusted_authorities);
  switch (type) {
#if BUILDFLAG(IS_ANDROID)
    case CERT_VERIFY_PROC_ANDROID:
      return base::MakeRefCounted<CertVerifyProcAndroid>(
          std::move(cert_net_fetcher), std::move(crl_set));
#elif BUILDFLAG(IS_IOS)
    case CERT_VERIFY_PROC_IOS:
      return base::MakeRefCounted<CertVerifyProcIOS>(std::move(crl_set));
#endif
#if BUILDFLAG(IS_FUCHSIA)
    case CERT_VERIFY_PROC_BUILTIN:
      return CreateCertVerifyProcBuiltin(
          std::move(cert_net_fetcher), std::move(crl_set),
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          CreateSslSystemTrustStore(), instance_params, std::nullopt);
#endif
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    case CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS:
      return CreateCertVerifyProcBuiltin(
          std::move(cert_net_fetcher), std::move(crl_set),
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          CreateSslSystemTrustStoreChromeRoot(
              std::make_unique<net::TrustStoreChrome>()),
          instance_params, std::nullopt);
#endif
    default:
      return nullptr;
  }
}

// The set of all CertVerifyProcTypes that tests should be parameterized on.
// This needs to be kept in sync with CertVerifyProc::CreateSystemVerifyProc()
// and the platforms where CreateSslSystemTrustStore() is not a dummy store.
constexpr CertVerifyProcType kAllCertVerifiers[] = {
#if BUILDFLAG(IS_ANDROID)
    CERT_VERIFY_PROC_ANDROID,
#elif BUILDFLAG(IS_IOS)
    CERT_VERIFY_PROC_IOS,
#elif BUILDFLAG(IS_FUCHSIA)
    CERT_VERIFY_PROC_BUILTIN,
#endif
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS,
#endif
};
static_assert(std::size(kAllCertVerifiers) != 0, "Unsupported platform");

// Returns true if a test root added through ScopedTestRoot can verify
// successfully as a target certificate with chain of length 1 on the given
// CertVerifyProcType.
bool ScopedTestRootCanTrustTargetCert(CertVerifyProcType verify_proc_type) {
  return verify_proc_type == CERT_VERIFY_PROC_IOS ||
         verify_proc_type == CERT_VERIFY_PROC_ANDROID;
}

// Returns true if a non-self-signed CA certificate added through
// ScopedTestRoot can verify successfully as the root of a chain by the given
// CertVerifyProcType.
bool ScopedTestRootCanTrustIntermediateCert(
    CertVerifyProcType verify_proc_type) {
  return verify_proc_type == CERT_VERIFY_PROC_IOS ||
         verify_proc_type == CERT_VERIFY_PROC_BUILTIN ||
         verify_proc_type == CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS ||
         verify_proc_type == CERT_VERIFY_PROC_ANDROID;
}

std::string MakeRandomHexString(size_t num_bytes) {
  std::vector<uint8_t> rand_bytes(num_bytes);
  base::RandBytes(rand_bytes);
  return base::HexEncode(rand_bytes);
}

}  // namespace

// This fixture is for tests that apply to concrete implementations of
// CertVerifyProc. It will be run for all of the concrete CertVerifyProc types.
//
// It is called "Internal" as it tests the internal methods like
// "VerifyInternal()".
class CertVerifyProcInternalTest
    : public testing::TestWithParam<CertVerifyProcType> {
 protected:
  void SetUp() override { SetUpCertVerifyProc(CRLSet::BuiltinCRLSet()); }

  // CertNetFetcher may be initialized by subclasses that want to use net
  // fetching by calling SetUpWithCertNetFetcher instead of SetUp.
  void SetUpWithCertNetFetcher(
      scoped_refptr<CertNetFetcher> cert_net_fetcher,
      scoped_refptr<CRLSet> crl_set,
      CertificateList additional_trust_anchors,
      CertificateList additional_untrusted_authorities) {
    CertVerifyProcType type = verify_proc_type();
    verify_proc_ = CreateCertVerifyProc(
        type, std::move(cert_net_fetcher), std::move(crl_set),
        additional_trust_anchors, additional_untrusted_authorities);
    ASSERT_TRUE(verify_proc_);
  }

  virtual void SetUpCertVerifyProc(scoped_refptr<CRLSet> crl_set) {
    SetUpWithCertNetFetcher(nullptr, std::move(crl_set),
                            /*additional_trust_anchors=*/{},
                            /*additional_untrusted_authorities=*/{});
  }

  virtual void SetUpWithAdditionalCerts(
      CertificateList additional_trust_anchors,
      CertificateList additional_untrusted_authorities) {
    SetUpWithCertNetFetcher(nullptr, CRLSet::BuiltinCRLSet(),
                            additional_trust_anchors,
                            additional_untrusted_authorities);
  }

  int Verify(X509Certificate* cert,
             const std::string& hostname,
             int flags,
             CertVerifyResult* verify_result,
             const NetLogWithSource& net_log) {
    return verify_proc_->Verify(cert, hostname, /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                verify_result, net_log);
  }

  int Verify(X509Certificate* cert,
             const std::string& hostname,
             int flags,
             CertVerifyResult* verify_result) {
    return Verify(cert, hostname, flags, verify_result, NetLogWithSource());
  }

  int Verify(X509Certificate* cert, const std::string& hostname) {
    CertVerifyResult verify_result;
    int flags = 0;
    return Verify(cert, hostname, flags, &verify_result);
  }

  CertVerifyProcType verify_proc_type() const { return GetParam(); }

  // Returns true if the RSA/DSA keysize will be considered weak on the current
  // platform. IsInvalidRsaDsaKeySize should be checked prior, since some very
  // weak keys may be considered invalid.
  bool IsWeakRsaDsaKeySize(int size) const {
#if BUILDFLAG(IS_IOS)
    // Beginning with iOS 13, the minimum key size for RSA/DSA algorithms is
    // 2048 bits. See https://support.apple.com/en-us/HT210176
    if (verify_proc_type() == CERT_VERIFY_PROC_IOS) {
      return size < 2048;
    }
#endif

    return size < 1024;
  }

  // Returns true if the RSA/DSA keysize will be considered invalid on the
  // current platform.
  bool IsInvalidRsaDsaKeySize(int size) const {
#if BUILDFLAG(IS_IOS)
    // On iOS using SecTrustEvaluateWithError it is not possible to
    // distinguish between weak and invalid key sizes.
    return IsWeakRsaDsaKeySize(size);
#else
    // This platform does not mark certificates with weak keys as invalid.
    return false;
#endif
  }

  static bool ParseKeyType(const std::string& key_type,
                           std::string* type,
                           int* size) {
    size_t pos = key_type.find("-");
    *type = key_type.substr(0, pos);
    std::string size_str = key_type.substr(pos + 1);
    return base::StringToInt(size_str, size);
  }

  // Some platforms may reject certificates with very weak keys as invalid.
  bool IsInvalidKeyType(const std::string& key_type) const {
    std::string type;
    int size = 0;
    if (!ParseKeyType(key_type, &type, &size))
      return false;

    if (type == "rsa" || type == "dsa")
      return IsInvalidRsaDsaKeySize(size);

    return false;
  }

  // Currently, only RSA and DSA keys are checked for weakness, and our example
  // weak size is 768. These could change in the future.
  //
  // Note that this means there may be false negatives: keys for other
  // algorithms and which are weak will pass this test.
  //
  // Also, IsInvalidKeyType should be checked prior, since some weak keys may be
  // considered invalid.
  bool IsWeakKeyType(const std::string& key_type) const {
    std::string type;
    int size = 0;
    if (!ParseKeyType(key_type, &type, &size))
      return false;

    if (type == "rsa" || type == "dsa")
      return IsWeakRsaDsaKeySize(size);

    return false;
  }

  bool SupportsCRLSet() const { return VerifyProcTypeIsBuiltin(); }

  bool SupportsCRLSetsInPathBuilding() const {
    return VerifyProcTypeIsBuiltin();
  }

  bool SupportsEV() const {
    // Android and iOS do not support EV.  See https://crbug.com/117478#7
#if defined(PLATFORM_USES_CHROMIUM_EV_METADATA)
    return true;
#else
    return false;
#endif
  }

  bool SupportsSoftFailRevChecking() const { return VerifyProcTypeIsBuiltin(); }

  bool SupportsRevCheckingRequiredLocalAnchors() const {
    return VerifyProcTypeIsBuiltin();
  }

  bool VerifyProcTypeIsBuiltin() const {
    return verify_proc_type() == CERT_VERIFY_PROC_BUILTIN ||
           verify_proc_type() == CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS;
  }

  bool VerifyProcTypeIsIOSAtMostOS14() const {
    return false;
  }

  bool VerifyProcTypeIsIOSAtMostOS15() const {
#if BUILDFLAG(IS_IOS)
    if (verify_proc_type() == CERT_VERIFY_PROC_IOS &&
        !base::ios::IsRunningOnIOS16OrLater()) {
      return true;
    }
#endif
    return false;
  }

  CertVerifyProc* verify_proc() const { return verify_proc_.get(); }

 private:
  scoped_refptr<CertVerifyProc> verify_proc_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         CertVerifyProcInternalTest,
                         testing::ValuesIn(kAllCertVerifiers),
                         VerifyProcTypeToName);

TEST_P(CertVerifyProcInternalTest, DistrustedIntermediate) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  constexpr char kHostname[] = "www.example.com";

  // Chain should not verify without any ScopedTestRoots.
  EXPECT_THAT(Verify(chain.get(), kHostname),
              IsError(ERR_CERT_AUTHORITY_INVALID));

  // Trusting root should cause chain to verify successfully.
  ScopedTestRoot trust_root(root->GetX509Certificate(),
                            bssl::CertificateTrust::ForTrustAnchor());
  EXPECT_THAT(Verify(chain.get(), kHostname), IsOk());

  ScopedTestRoot distrust_intermediate(intermediate->GetX509Certificate(),
                                       bssl::CertificateTrust::ForDistrusted());
  if (VerifyProcTypeIsBuiltin()) {
    // Distrusting intermediate should cause chain to not verify again.
    EXPECT_THAT(Verify(chain.get(), kHostname),
                IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    // Specifying trust types for the platform verifiers through ScopedTestRoot
    // is not supported, so this should still verify successfully.
    EXPECT_THAT(Verify(chain.get(), kHostname), IsOk());
  }
}

// Tests that a certificate is recognized as EV, when the valid EV policy OID
// for the trust anchor is the second candidate EV oid in the target
// certificate. This is a regression test for crbug.com/705285.
TEST_P(CertVerifyProcInternalTest, EVVerificationMultipleOID) {
  if (!SupportsEV()) {
    LOG(INFO) << "Skipping test as EV verification is not yet supported";
    return;
  }

  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  // The policies that target certificate asserts.
  static const char kOtherTestCertPolicy[] = "2.23.140.1.1";
  static const char kEVTestCertPolicy[] = "1.2.3.4";
  // Specify the extraneous policy first, then the actual policy.
  leaf->SetCertificatePolicies({kOtherTestCertPolicy, kEVTestCertPolicy});

  scoped_refptr<X509Certificate> cert = leaf->GetX509Certificate();
  ScopedTestRoot test_root(root->GetX509Certificate());

  // Build a CRLSet that covers the target certificate.
  //
  // This way CRLSet coverage will be sufficient for EV revocation checking,
  // so this test does not depend on online revocation checking.
  std::string_view spki;
  ASSERT_TRUE(asn1::ExtractSPKIFromDERCert(
      x509_util::CryptoBufferAsStringPiece(root->GetCertBuffer()), &spki));
  SHA256HashValue spki_sha256;
  crypto::SHA256HashString(spki, spki_sha256.data, sizeof(spki_sha256.data));
  SetUpCertVerifyProc(CRLSet::ForTesting(false, &spki_sha256, "", "", {}));

  // Consider the root of the test chain a valid EV root for the test policy.
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(root->GetCertBuffer()),
      kEVTestCertPolicy);
  ScopedTestEVPolicy scoped_test_other_policy(
      EVRootCAMetadata::GetInstance(), SHA256HashValue(), kOtherTestCertPolicy);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(cert.get(), "www.example.com", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
}

// Target cert has an EV policy, and verifies successfully, but has a chain of
// length 1 because the target cert was directly trusted in the trust store.
// Should verify OK but not with STATUS_IS_EV.
TEST_P(CertVerifyProcInternalTest, TrustedTargetCertWithEVPolicy) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  static const char kEVTestCertPolicy[] = "1.2.3.4";
  leaf->SetCertificatePolicies({kEVTestCertPolicy});
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(), SHA256HashValue(), kEVTestCertPolicy);

  scoped_refptr<X509Certificate> cert = leaf->GetX509Certificate();
  ScopedTestRoot scoped_test_root(cert);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(cert.get(), "www.example.com", flags, &verify_result);
  if (ScopedTestRootCanTrustTargetCert(verify_proc_type())) {
    EXPECT_THAT(error, IsOk());
    ASSERT_TRUE(verify_result.verified_cert);
    EXPECT_TRUE(verify_result.verified_cert->intermediate_buffers().empty());
  } else {
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  }
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_IS_EV);
}

// Target cert has an EV policy, and verifies successfully with a chain of
// length 1, and its fingerprint matches the cert fingerprint for that ev
// policy. This should never happen in reality, but just test that things don't
// explode if it does.
TEST_P(CertVerifyProcInternalTest,
       TrustedTargetCertWithEVPolicyAndEVFingerprint) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  static const char kEVTestCertPolicy[] = "1.2.3.4";
  leaf->SetCertificatePolicies({kEVTestCertPolicy});
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(leaf->GetCertBuffer()),
      kEVTestCertPolicy);
  scoped_refptr<X509Certificate> cert = leaf->GetX509Certificate();
  ScopedTestRoot scoped_test_root(cert);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(cert.get(), "www.example.com", flags, &verify_result);
  if (ScopedTestRootCanTrustTargetCert(verify_proc_type())) {
    EXPECT_THAT(error, IsOk());
    ASSERT_TRUE(verify_result.verified_cert);
    EXPECT_TRUE(verify_result.verified_cert->intermediate_buffers().empty());
  } else {
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  }
  // An EV Root certificate should never be used as an end-entity certificate.
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_IS_EV);
}

// Target cert has an EV policy, and has a valid path to the EV root, but the
// intermediate has been trusted directly. Should stop building the path at the
// intermediate and verify OK but not with STATUS_IS_EV.
// See https://crbug.com/979801
TEST_P(CertVerifyProcInternalTest, TrustedIntermediateCertWithEVPolicy) {
  if (!SupportsEV()) {
    LOG(INFO) << "Skipping test as EV verification is not yet supported";
    return;
  }
  if (!ScopedTestRootCanTrustIntermediateCert(verify_proc_type())) {
    LOG(INFO) << "Skipping test as intermediate cert cannot be trusted";
    return;
  }

  for (bool trust_the_intermediate : {false, true}) {
    SCOPED_TRACE(trust_the_intermediate);

    // Need to build unique certs for each try otherwise caching can break
    // things.
    auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

    static const char kEVTestCertPolicy[] = "1.2.3.4";
    leaf->SetCertificatePolicies({kEVTestCertPolicy});
    intermediate->SetCertificatePolicies({kEVTestCertPolicy});
    // Consider the root of the test chain a valid EV root for the test policy.
    ScopedTestEVPolicy scoped_test_ev_policy(
        EVRootCAMetadata::GetInstance(),
        X509Certificate::CalculateFingerprint256(root->GetCertBuffer()),
        kEVTestCertPolicy);

    scoped_refptr<X509Certificate> cert = leaf->GetX509CertificateChain();
    ASSERT_TRUE(cert.get());

    scoped_refptr<X509Certificate> intermediate_cert =
        intermediate->GetX509Certificate();
    ASSERT_TRUE(intermediate_cert.get());

    scoped_refptr<X509Certificate> root_cert = root->GetX509Certificate();
    ASSERT_TRUE(root_cert.get());

    if (!trust_the_intermediate) {
      // First trust just the root. This verifies that the test setup is
      // actually correct.
      ScopedTestRoot scoped_test_root({root_cert});
      CertVerifyResult verify_result;
      int flags = 0;
      int error = Verify(cert.get(), "www.example.com", flags, &verify_result);
      EXPECT_THAT(error, IsOk());
      ASSERT_TRUE(verify_result.verified_cert);
      // Verified chain should include the intermediate and the root.
      EXPECT_EQ(2U, verify_result.verified_cert->intermediate_buffers().size());
      // Should be EV.
      EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
    } else {
      // Now try with trusting both the intermediate and the root.
      ScopedTestRoot scoped_test_root({intermediate_cert, root_cert});
      CertVerifyResult verify_result;
      int flags = 0;
      int error = Verify(cert.get(), "www.example.com", flags, &verify_result);
      EXPECT_THAT(error, IsOk());
      ASSERT_TRUE(verify_result.verified_cert);
      // Verified chain should only go to the trusted intermediate, not the
      // root.
      EXPECT_EQ(1U, verify_result.verified_cert->intermediate_buffers().size());
      // Should not be EV.
      EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_IS_EV);
    }
  }
}

TEST_P(CertVerifyProcInternalTest, CertWithNullInCommonNameAndNoSAN) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  leaf->EraseExtension(bssl::der::Input(bssl::kSubjectAltNameOid));

  std::string common_name;
  common_name += "www.fake.com";
  common_name += '\0';
  common_name += "a" + MakeRandomHexString(12) + ".example.com";
  leaf->SetSubjectCommonName(common_name);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.fake.com", flags, &verify_result);

  // This actually fails because Chrome only looks for hostnames in
  // SubjectAltNames now and no SubjectAltName is present.
  EXPECT_THAT(error, IsError(ERR_CERT_COMMON_NAME_INVALID));
}

TEST_P(CertVerifyProcInternalTest, CertWithNullInCommonNameAndValidSAN) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  leaf->SetSubjectAltName("www.fake.com");

  std::string common_name;
  common_name += "www.fake.com";
  common_name += '\0';
  common_name += "a" + MakeRandomHexString(12) + ".example.com";
  leaf->SetSubjectCommonName(common_name);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.fake.com", flags, &verify_result);

  // SubjectAltName is valid and Chrome does not use the common name.
  EXPECT_THAT(error, IsOk());
}

TEST_P(CertVerifyProcInternalTest, CertWithNullInSAN) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  std::string hostname;
  hostname += "www.fake.com";
  hostname += '\0';
  hostname += "a" + MakeRandomHexString(12) + ".example.com";
  leaf->SetSubjectAltName(hostname);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.fake.com", flags, &verify_result);

  // SubjectAltName is invalid.
  EXPECT_THAT(error, IsError(ERR_CERT_COMMON_NAME_INVALID));
}

// Tests the case where the target certificate is accepted by
// X509CertificateBytes, but has errors that should cause verification to fail.
TEST_P(CertVerifyProcInternalTest, InvalidTarget) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");
  scoped_refptr<X509Certificate> bad_cert;
  if (VerifyProcTypeIsBuiltin()) {
    // Builtin verifier doesn't distinguish between invalid signature algorithm
    // and unknown signature algorithm, so use a different test file that will
    // fail in bssl::ParsedCertificate::Create. The other verifiers use a
    // different test file since the platform verifiers don't all consider empty
    // extensions sequence invalid.
    bad_cert = ImportCertFromFile(certs_dir, "extensions_empty_sequence.pem");
  } else {
    bad_cert = ImportCertFromFile(certs_dir, "signature_algorithm_null.pem");
  }
  ASSERT_TRUE(bad_cert);

  scoped_refptr<X509Certificate> ok_cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(ok_cert);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(ok_cert->cert_buffer()));
  scoped_refptr<X509Certificate> cert_with_bad_target(
      X509Certificate::CreateFromBuffer(bssl::UpRef(bad_cert->cert_buffer()),
                                        std::move(intermediates)));
  ASSERT_TRUE(cert_with_bad_target);
  EXPECT_EQ(1U, cert_with_bad_target->intermediate_buffers().size());

  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      Verify(cert_with_bad_target.get(), "127.0.0.1", flags, &verify_result);

  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

// Tests the case where an intermediate certificate is accepted by
// X509CertificateBytes, but has errors that should prevent using it during
// verification.  The verification should succeed, since the intermediate
// wasn't necessary.
TEST_P(CertVerifyProcInternalTest, UnnecessaryInvalidIntermediate) {
  ScopedTestRoot test_root(
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem"));

  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");
  bssl::UniquePtr<CRYPTO_BUFFER> bad_cert =
      x509_util::CreateCryptoBuffer(std::string_view("invalid"));
  ASSERT_TRUE(bad_cert);

  scoped_refptr<X509Certificate> ok_cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(ok_cert);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(std::move(bad_cert));
  scoped_refptr<X509Certificate> cert_with_bad_intermediate(
      X509Certificate::CreateFromBuffer(bssl::UpRef(ok_cert->cert_buffer()),
                                        std::move(intermediates)));
  ASSERT_TRUE(cert_with_bad_intermediate);
  EXPECT_EQ(1U, cert_with_bad_intermediate->intermediate_buffers().size());

  RecordingNetLogObserver net_log_observer(NetLogCaptureMode::kDefault);
  NetLogWithSource net_log(NetLogWithSource::Make(
      net::NetLog::Get(), net::NetLogSourceType::CERT_VERIFIER_TASK));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert_with_bad_intermediate.get(), "127.0.0.1", flags,
                     &verify_result, net_log);

  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0u, verify_result.cert_status);

  auto events = net_log_observer.GetEntriesForSource(net_log.source());
  EXPECT_FALSE(events.empty());

  auto event = base::ranges::find(events, NetLogEventType::CERT_VERIFY_PROC,
                                  &NetLogEntry::type);
  ASSERT_NE(event, events.end());
  EXPECT_EQ(net::NetLogEventPhase::BEGIN, event->phase);
  const std::string* host = event->params.FindString("host");
  ASSERT_TRUE(host);
  EXPECT_EQ("127.0.0.1", *host);

  if (VerifyProcTypeIsBuiltin()) {
    event =
        base::ranges::find(events, NetLogEventType::CERT_VERIFY_PROC_INPUT_CERT,
                           &NetLogEntry::type);
    ASSERT_NE(event, events.end());
    EXPECT_EQ(net::NetLogEventPhase::NONE, event->phase);
    const std::string* errors = event->params.FindString("errors");
    ASSERT_TRUE(errors);
    EXPECT_EQ(
        "ERROR: Failed parsing Certificate SEQUENCE\nERROR: Failed parsing "
        "Certificate\n",
        *errors);
  }
}

TEST_P(CertVerifyProcInternalTest, RejectExpiredCert) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  // Load root_ca_cert.pem into the test root store.
  ScopedTestRoot test_root(ImportCertFromFile(certs_dir, "root_ca_cert.pem"));

  scoped_refptr<X509Certificate> cert = CreateCertificateChai
"""


```