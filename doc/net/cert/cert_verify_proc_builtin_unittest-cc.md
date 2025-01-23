Response:
The user wants to understand the functionality of the `cert_verify_proc_builtin_unittest.cc` file in the Chromium network stack. I need to:

1. **Summarize the file's purpose:** Based on the filename and content, it's clearly a unit test file for `CertVerifyProcBuiltin`.
2. **Check for JavaScript relevance:**  Examine the code for any interactions with JavaScript concepts or APIs. Given it's a low-level network component, direct interaction is unlikely.
3. **Identify logical reasoning and provide examples:** Look for test cases that validate specific scenarios with clear inputs and expected outputs.
4. **Point out common user/programming errors:**  Analyze the test cases to see if any address potential mistakes developers might make when using the related APIs.
5. **Explain user actions to reach this code:** Describe how a user's web browsing actions could trigger the certificate verification process.
6. **Provide a concise summary of the file's function (as requested for Part 1).**
```
这是目录为net/cert/cert_verify_proc_builtin_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

**文件功能:**

`cert_verify_proc_builtin_unittest.cc` 是 Chromium 网络栈中 `net/cert/cert_verify_proc_builtin.cc` 文件的单元测试。它的主要功能是：

1. **测试 `CertVerifyProcBuiltin` 类的各种功能**:  这个类负责执行内置的证书验证逻辑，包括路径构建、撤销检查（CRL）、证书透明度（CT）验证、名称约束检查、以及处理额外的信任锚点和不信任证书等。
2. **验证证书验证过程的正确性**:  通过创建不同的证书链（包括有效和无效的链）和配置不同的验证参数，测试 `CertVerifyProcBuiltin` 能否按照预期返回验证结果（例如，成功、证书过期、证书被吊销、证书链无效等）。
3. **模拟和测试依赖组件的交互**:  该文件使用了 mock 对象 (例如 `MockCTVerifier`, `MockCTPolicyEnforcer`, `MockSystemTrustStore`) 来隔离 `CertVerifyProcBuiltin` 的测试，并验证它与其他组件的正确交互。
4. **测试特定的网络场景**: 例如，测试在启用 HSTS 的情况下，CRL 下载是否会受到影响。
5. **确保代码的健壮性**: 通过测试各种边界情况和错误场景，确保 `CertVerifyProcBuiltin` 在各种条件下都能稳定可靠地工作。

**与 JavaScript 的关系:**

虽然 `cert_verify_proc_builtin_unittest.cc` 本身是用 C++ 编写的，并且直接在 Chromium 的网络层运行，但它的功能与 JavaScript 的安全息息相关。当用户通过浏览器访问一个 HTTPS 网站时，浏览器会使用底层的证书验证机制来确保网站的身份是可信的。

**举例说明:**

假设一个 JavaScript 代码尝试通过 `fetch` API 访问一个 HTTPS 网站：

```javascript
fetch('https://example.com')
  .then(response => {
    // 处理响应
  })
  .catch(error => {
    // 处理错误
  });
```

当这个请求发送出去后，Chromium 的网络栈会执行以下步骤（部分）：

1. **获取服务器的证书链**: 服务器会提供其证书以及可能的中间证书。
2. **调用 `CertVerifyProcBuiltin` 进行验证**:  `CertVerifyProcBuiltin` 会执行各种检查，例如：
    * **证书链是否完整**:  是否能追溯到受信任的根证书。
    * **证书是否过期**: 检查证书的有效期。
    * **证书是否被吊销**:  查询 CRL 或 OCSP 来确认证书是否仍然有效。
    * **证书是否符合 CT 要求**: 检查证书是否已记录到证书透明度日志中。
3. **根据验证结果决定是否建立连接**: 如果 `CertVerifyProcBuiltin` 返回成功，则认为网站是可信的，连接建立。如果验证失败，则连接会被阻止，JavaScript 的 `fetch` API 会抛出一个错误，例如 `net::ERR_CERT_AUTHORITY_INVALID`。

**逻辑推理、假设输入与输出:**

**假设输入:**

* **被测试的函数:** `CertVerifyProcBuiltin::Verify`
* **输入证书链:** 一个包含叶子证书、中间证书和根证书的链。
* **主机名:** "www.example.com"
* **验证标志:**  `CertVerifyProc::VERIFY_REV_CHECKING_ENABLED` (启用吊销检查)
* **其他参数:**  空的 OCSP 响应和 SCT 列表。

**逻辑推理:**

测试会模拟以下场景：

1. 设置一个可信的根证书（通过 `CreateParams` 添加）。
2. 构建一个由该根证书签发的证书链。
3. 调用 `CertVerifyProcBuiltin::Verify` 来验证这个证书链。

**预期输出:**

* 如果证书链中的所有证书都有效且未被吊销，则 `Verify` 函数应该返回 `net::OK`。
* `CertVerifyResult` 应该包含成功的验证结果，例如 `cert_status` 不包含任何错误标志。

**用户或编程常见的使用错误 (以测试用例为例):**

* **未包含必要的中间证书:**  用户或开发者可能只提供了叶子证书，而没有提供将其连接到受信任根证书的中间证书。`CertVerifyProcBuiltin` 的测试用例中会创建这样的场景，预期会返回 `ERR_CERT_AUTHORITY_INVALID`。
* **信任锚点配置错误:** 用户或系统管理员可能没有正确配置受信任的根证书列表。测试用例通过 `CreateParams` 控制信任锚点，可以验证在缺少信任锚点的情况下，证书验证会失败。
* **忽略证书吊销:**  开发者可能没有启用吊销检查。测试用例会启用 `VERIFY_REV_CHECKING_ENABLED` 并提供吊销的证书，预期会返回 `ERR_CERT_REVOKED`。
* **CT 合规性问题:**  开发者部署的证书可能不符合证书透明度策略。测试用例会模拟 CT 验证失败的情况，并检查 `CertVerifyResult` 中的 `policy_compliance` 字段。

**用户操作到达这里的调试线索:**

一个用户在浏览器中访问一个 HTTPS 网站的过程，可能会触发 `CertVerifyProcBuiltin` 的执行：

1. **用户在地址栏输入 HTTPS URL 并回车，或点击 HTTPS 链接。**
2. **浏览器发起与服务器的 TLS 握手。**
3. **服务器向浏览器发送其证书链。**
4. **浏览器网络栈接收到证书链后，会创建 `CertVerifyProcBuiltin` 的实例 (或者使用现有的实例)。**
5. **浏览器调用 `CertVerifyProcBuiltin::Verify` 方法，传入服务器提供的证书链和目标主机名等参数。**
6. **`CertVerifyProcBuiltin` 执行各种验证步骤，如路径构建、吊销检查、CT 验证等。**
7. **验证结果返回给网络栈，决定是否建立安全的连接。**
8. **如果验证失败，浏览器会显示安全警告页面。**

作为调试线索，如果用户报告了证书相关的错误（例如 "您的连接不是私密连接"），开发者可能会检查 `CertVerifyProcBuiltin` 的行为，通过单元测试或者实际的调试来定位问题，例如：

* **检查提供的证书链是否有效。**
* **确认吊销信息是否可达且正确。**
* **验证证书是否满足证书透明度策略。**
* **检查系统或浏览器中配置的信任锚点是否正确。**

**归纳功能 (第 1 部分):**

总而言之，`cert_verify_proc_builtin_unittest.cc` 的主要功能是 **全面测试 `CertVerifyProcBuiltin` 类的证书验证逻辑，确保其在各种场景下都能正确、安全地执行证书验证，从而保障用户的网络安全。** 它通过模拟各种证书链、配置和网络环境，验证了 `CertVerifyProcBuiltin` 的核心功能和与其他组件的交互。
```
### 提示词
```
这是目录为net/cert/cert_verify_proc_builtin_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_builtin.h"

#include <optional>
#include <string_view>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "components/network_time/time_tracker/time_tracker.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/crl_set.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/sct_status_flags.h"
#include "net/cert/time_conversions.h"
#include "net/cert/x509_util.h"
#include "net/cert_net/cert_net_fetcher_url_request.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/request_handler_util.h"
#include "net/test/gtest_util.h"
#include "net/test/revocation_builder.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/pki/trust_store.h"
#include "third_party/boringssl/src/pki/trust_store_collection.h"
#include "third_party/boringssl/src/pki/trust_store_in_memory.h"

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "base/version_info/version_info.h"  // nogncheck
#endif

using net::test::IsError;
using net::test::IsOk;

using testing::_;

namespace net {

namespace {

std::unique_ptr<test_server::HttpResponse> HangRequestAndCallback(
    base::OnceClosure callback,
    const test_server::HttpRequest& request) {
  std::move(callback).Run();
  return std::make_unique<test_server::HungResponse>();
}

void FailTest(const std::string& message) {
  ADD_FAILURE() << message;
}

std::unique_ptr<test_server::HttpResponse> FailRequestAndFailTest(
    const std::string& message,
    scoped_refptr<base::TaskRunner> main_task_runner,
    const test_server::HttpRequest& request) {
  main_task_runner->PostTask(FROM_HERE, base::BindOnce(FailTest, message));
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_NOT_ACCEPTABLE);
  return response;
}

std::unique_ptr<test_server::HttpResponse> ServeResponse(
    HttpStatusCode status_code,
    const std::string& content_type,
    const std::string& content,
    const test_server::HttpRequest& request) {
  auto http_response = std::make_unique<test_server::BasicHttpResponse>();

  http_response->set_code(status_code);
  http_response->set_content_type(content_type);
  http_response->set_content(content);
  return http_response;
}

std::string MakeRandomHexString(size_t num_bytes) {
  std::vector<uint8_t> rand_bytes(num_bytes);
  base::RandBytes(rand_bytes);
  return base::HexEncode(rand_bytes);
}

static std::string MakeRandomPath(std::string_view suffix) {
  return "/" + MakeRandomHexString(12) + std::string(suffix);
}

int VerifyOnWorkerThread(const scoped_refptr<CertVerifyProc>& verify_proc,
                         scoped_refptr<X509Certificate> cert,
                         const std::string& hostname,
                         const std::string& ocsp_response,
                         const std::string& sct_list,
                         int flags,
                         CertVerifyResult* verify_result,
                         NetLogSource* out_source) {
  base::ScopedAllowBaseSyncPrimitivesForTesting scoped_allow_blocking;
  NetLogWithSource net_log(NetLogWithSource::Make(
      net::NetLog::Get(), net::NetLogSourceType::CERT_VERIFIER_TASK));
  int error = verify_proc->Verify(cert.get(), hostname, ocsp_response, sct_list,
                                  flags, verify_result, net_log);
  *out_source = net_log.source();
  return error;
}

class MockSystemTrustStore : public SystemTrustStore {
 public:
  bssl::TrustStore* GetTrustStore() override { return &trust_store_; }

  bool IsKnownRoot(const bssl::ParsedCertificate* trust_anchor) const override {
    return mock_is_known_root_;
  }

  void AddTrustStore(bssl::TrustStore* store) {
    trust_store_.AddTrustStore(store);
  }

  void SetMockIsKnownRoot(bool is_known_root) {
    mock_is_known_root_ = is_known_root;
  }

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  net::PlatformTrustStore* GetPlatformTrustStore() override { return nullptr; }

  void SetMockIsLocallyTrustedRoot(bool is_locally_trusted_root) {
    mock_is_locally_trusted_root_ = is_locally_trusted_root;
  }

  bool IsLocallyTrustedRoot(
      const bssl::ParsedCertificate* trust_anchor) override {
    return mock_is_locally_trusted_root_;
  }

  int64_t chrome_root_store_version() const override { return 0; }

  base::span<const ChromeRootCertConstraints> GetChromeRootConstraints(
      const bssl::ParsedCertificate* cert) const override {
    return mock_chrome_root_constraints_;
  }

  void SetMockChromeRootConstraints(
      std::vector<StaticChromeRootCertConstraints> chrome_root_constraints) {
    mock_chrome_root_constraints_.clear();
    for (const auto& constraint : chrome_root_constraints) {
      mock_chrome_root_constraints_.emplace_back(constraint);
    }
  }
#endif

 private:
  bssl::TrustStoreCollection trust_store_;
  bool mock_is_known_root_ = false;
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  bool mock_is_locally_trusted_root_ = false;
  std::vector<ChromeRootCertConstraints> mock_chrome_root_constraints_;
#endif
};

class BlockingTrustStore : public bssl::TrustStore {
 public:
  bssl::CertificateTrust GetTrust(
      const bssl::ParsedCertificate* cert) override {
    return backing_trust_store_.GetTrust(cert);
  }

  void SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                        bssl::ParsedCertificateList* issuers) override {
    sync_get_issuer_started_event_.Signal();
    sync_get_issuer_ok_to_finish_event_.Wait();

    backing_trust_store_.SyncGetIssuersOf(cert, issuers);
  }

  base::WaitableEvent sync_get_issuer_started_event_;
  base::WaitableEvent sync_get_issuer_ok_to_finish_event_;
  bssl::TrustStoreInMemory backing_trust_store_;
};

class MockCTVerifier : public CTVerifier {
 public:
  MOCK_CONST_METHOD6(Verify,
                     void(X509Certificate*,
                          std::string_view,
                          std::string_view,
                          base::Time current_time,
                          SignedCertificateTimestampAndStatusList*,
                          const NetLogWithSource&));
};

class MockCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  MOCK_CONST_METHOD4(CheckCompliance,
                     ct::CTPolicyCompliance(X509Certificate* cert,
                                            const ct::SCTList&,
                                            base::Time,
                                            const NetLogWithSource&));
  MOCK_CONST_METHOD1(GetLogDisqualificationTime,
                     std::optional<base::Time>(std::string_view log_id));
  MOCK_CONST_METHOD0(IsCtEnabled, bool());

 protected:
  ~MockCTPolicyEnforcer() override = default;
};

}  // namespace

class CertVerifyProcBuiltinTest : public ::testing::Test {
 public:
  void SetUp() override {
    cert_net_fetcher_ = base::MakeRefCounted<CertNetFetcherURLRequest>();

    InitializeVerifyProc(CreateParams({}));

    context_ = CreateTestURLRequestContextBuilder()->Build();

    cert_net_fetcher_->SetURLRequestContext(context_.get());
  }

  void TearDown() override { cert_net_fetcher_->Shutdown(); }

  CertVerifyProc::InstanceParams CreateParams(
      const CertificateList& additional_trust_anchors,
      const CertificateList&
          additional_trust_anchors_with_enforced_constraints = {},
      const CertificateList& additional_distrusted_certificates = {}) {
    CertVerifyProc::InstanceParams instance_params;
    instance_params.additional_trust_anchors =
        net::x509_util::ParseAllValidCerts(additional_trust_anchors);
    instance_params.additional_trust_anchors_with_enforced_constraints =
        net::x509_util::ParseAllValidCerts(
            additional_trust_anchors_with_enforced_constraints);
    std::vector<std::vector<uint8_t>> distrusted_spkis;
    for (const auto& x509_cert : additional_distrusted_certificates) {
      std::shared_ptr<const bssl::ParsedCertificate> cert =
          bssl::ParsedCertificate::Create(
              bssl::UpRef(x509_cert->cert_buffer()),
              net::x509_util::DefaultParseCertificateOptions(),
              /*errors=*/nullptr);
      EXPECT_TRUE(cert);
      std::string spki_string = cert->tbs().spki_tlv.AsString();
      distrusted_spkis.push_back(
          std::vector<uint8_t>(spki_string.begin(), spki_string.end()));
    }
    instance_params.additional_distrusted_spkis = distrusted_spkis;
    return instance_params;
  }

  void InitializeVerifyProc(
      const CertVerifyProc::InstanceParams& instance_params,
      std::optional<base::Time> current_time = std::nullopt) {
    auto mock_system_trust_store = std::make_unique<MockSystemTrustStore>();
    mock_system_trust_store_ = mock_system_trust_store.get();
    auto mock_ct_verifier = std::make_unique<MockCTVerifier>();
    mock_ct_verifier_ = mock_ct_verifier.get();
    mock_ct_policy_enforcer_ = base::MakeRefCounted<MockCTPolicyEnforcer>();
    std::optional<network_time::TimeTracker> time_tracker;
    if (current_time.has_value()) {
      time_tracker =
          network_time::TimeTracker(base::Time::Now(), base::TimeTicks::Now(),
                                    current_time.value(), base::TimeDelta());
    }
    verify_proc_ = CreateCertVerifyProcBuiltin(
        cert_net_fetcher_, CRLSet::EmptyCRLSetForTesting(),
        std::move(mock_ct_verifier), mock_ct_policy_enforcer_,
        std::move(mock_system_trust_store), instance_params, time_tracker);
  }

  void Verify(scoped_refptr<X509Certificate> cert,
              const std::string& hostname,
              int flags,
              CertVerifyResult* verify_result,
              NetLogSource* out_source,
              CompletionOnceCallback callback) {
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE,
        {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
        base::BindOnce(
            &VerifyOnWorkerThread, verify_proc_, std::move(cert), hostname,
            /*ocsp_response=*/std::string(),
            /*sct_list=*/std::string(), flags, verify_result, out_source),
        std::move(callback));
  }

  void Verify(scoped_refptr<X509Certificate> cert,
              const std::string& hostname,
              const std::string& ocsp_response,
              const std::string& sct_list,
              int flags,
              CertVerifyResult* verify_result,
              NetLogSource* out_source,
              CompletionOnceCallback callback) {
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE,
        {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
        base::BindOnce(&VerifyOnWorkerThread, verify_proc_, std::move(cert),
                       hostname, ocsp_response, sct_list, flags, verify_result,
                       out_source),
        std::move(callback));
  }

  base::test::TaskEnvironment& task_environment() { return task_environment_; }

  // Creates a CRL issued and signed by |crl_issuer|, marking |revoked_serials|
  // as revoked, and registers it to be served by the test server.
  // Returns the full URL to retrieve the CRL from the test server.
  GURL CreateAndServeCrl(EmbeddedTestServer* test_server,
                         CertBuilder* crl_issuer,
                         const std::vector<uint64_t>& revoked_serials,
                         std::optional<bssl::SignatureAlgorithm>
                             signature_algorithm = std::nullopt) {
    std::string crl = BuildCrl(crl_issuer->GetSubject(), crl_issuer->GetKey(),
                               revoked_serials, signature_algorithm);
    std::string crl_path = MakeRandomPath(".crl");
    test_server->RegisterRequestHandler(
        base::BindRepeating(&test_server::HandlePrefixedRequest, crl_path,
                            base::BindRepeating(ServeResponse, HTTP_OK,
                                                "application/pkix-crl", crl)));
    return test_server->GetURL(crl_path);
  }

  void AddTrustStore(bssl::TrustStore* store) {
    mock_system_trust_store_->AddTrustStore(store);
  }

  void SetMockIsKnownRoot(bool is_known_root) {
    mock_system_trust_store_->SetMockIsKnownRoot(is_known_root);
  }

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  void SetMockIsLocallyTrustedRoot(bool is_locally_trusted_root) {
    mock_system_trust_store_->SetMockIsLocallyTrustedRoot(
        is_locally_trusted_root);
  }

  void SetMockChromeRootConstraints(
      std::vector<StaticChromeRootCertConstraints> chrome_root_constraints) {
    mock_system_trust_store_->SetMockChromeRootConstraints(
        std::move(chrome_root_constraints));
  }
#endif

  net::URLRequestContext* context() { return context_.get(); }

  MockCTVerifier* mock_ct_verifier() { return mock_ct_verifier_; }
  MockCTPolicyEnforcer* mock_ct_policy_enforcer() {
    return mock_ct_policy_enforcer_.get();
  }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO,
  };

  CertVerifier::Config config_;
  std::unique_ptr<net::URLRequestContext> context_;

  // Must outlive `mock_ct_verifier_` and `mock_system_trust_store_`.
  scoped_refptr<CertVerifyProc> verify_proc_;

  raw_ptr<MockCTVerifier> mock_ct_verifier_ = nullptr;
  scoped_refptr<MockCTPolicyEnforcer> mock_ct_policy_enforcer_;
  raw_ptr<MockSystemTrustStore> mock_system_trust_store_ = nullptr;
  scoped_refptr<CertNetFetcherURLRequest> cert_net_fetcher_;
};

TEST_F(CertVerifyProcBuiltinTest, ShouldBypassHSTS) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTP);
  ASSERT_TRUE(test_server.InitializeAndListen());

  // CRL that marks leaf as revoked.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(&test_server, root.get(), {leaf->GetSerialNumber()}));

  test_server.StartAcceptingConnections();

  {
    scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
    ASSERT_TRUE(chain.get());

    NetLogSource verify_net_log_source;
    CertVerifyResult verify_result;
    TestCompletionCallback verify_callback;
    // Ensure HSTS upgrades for the domain which hosts the CRLs.
    context()->transport_security_state()->AddHSTS(
        test_server.base_url().host(), base::Time::Now() + base::Seconds(30),
        /*include_subdomains=*/true);
    ASSERT_TRUE(context()->transport_security_state()->ShouldUpgradeToSSL(
        test_server.base_url().host()));
    Verify(chain.get(), "www.example.com",
           CertVerifyProc::VERIFY_REV_CHECKING_ENABLED,
           &verify_result, &verify_net_log_source, verify_callback.callback());

    int error = verify_callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
    EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
  }
}

TEST_F(CertVerifyProcBuiltinTest, SimpleSuccess) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest, CallsCtVerifierAndReturnsSctStatus) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  const std::string kOcspResponse = "OCSP response";
  const std::string kSctList = "SCT list";
  const std::string kLogId = "CT log id";
  const ct::SCTVerifyStatus kSctVerifyStatus = ct::SCT_STATUS_LOG_UNKNOWN;

  SignedCertificateTimestampAndStatus sct_and_status;
  sct_and_status.sct = base::MakeRefCounted<ct::SignedCertificateTimestamp>();
  sct_and_status.sct->log_id = kLogId;
  sct_and_status.status = kSctVerifyStatus;
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.push_back(sct_and_status);
  EXPECT_CALL(*mock_ct_verifier(), Verify(_, kOcspResponse, kSctList, _, _, _))
      .WillOnce(testing::SetArgPointee<4>(sct_and_status_list));
  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_NOT_DIVERSE_SCTS));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", kOcspResponse, kSctList, /*flags=*/0,
         &verify_result, &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
  ASSERT_EQ(verify_result.scts.size(), 1u);
  EXPECT_EQ(verify_result.scts.front().status, kSctVerifyStatus);
  EXPECT_EQ(verify_result.scts.front().sct->log_id, kLogId);
  EXPECT_EQ(verify_result.policy_compliance,
            ct::CTPolicyCompliance::CT_POLICY_NOT_DIVERSE_SCTS);
}

#if defined(PLATFORM_USES_CHROMIUM_EV_METADATA)
TEST_F(CertVerifyProcBuiltinTest, EVCertStatusMaintainedForCompliantCert) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  static const char kEVTestCertPolicy[] = "1.2.3.4";
  leaf->SetCertificatePolicies({kEVTestCertPolicy});
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(root->GetCertBuffer()),
      kEVTestCertPolicy);
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, _, _, _, _));
  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(verify_result.policy_compliance,
            ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS);
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
}
#endif

TEST_F(CertVerifyProcBuiltinTest, DistrustedIntermediate) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()},
      /*additional_trust_anchors_with_enforced_constraints=*/{},
      /*additional_distrusted_certificates=*/
      {intermediate->GetX509Certificate()}));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(1u, verify_result.verified_cert->intermediate_buffers().size());
}

TEST_F(CertVerifyProcBuiltinTest, AddedRootWithConstraints) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetNameConstraintsDnsNames(/*permitted_dns_names=*/{"example.org"},
                                   /*excluded_dns_names=*/{});
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{},
      /*additional_trust_anchors_with_enforced_constraints=*/
      {root->GetX509Certificate()},
      /*additional_distrusted_certificates=*/{}));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  // Doesn't chain back to any valid root.
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest, AddedRootWithConstraintsNotEnforced) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetNameConstraintsDnsNames(/*permitted_dns_names=*/{"example.org"},
                                   /*excluded_dns_names=*/{});
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()},
      /*additional_trust_anchors_with_enforced_constraints=*/{},
      /*additional_distrusted_certificates=*/{}));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  // Constraint isn't enforced.
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest, AddedRootWithOutsideDNSConstraints) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  CertVerifyProc::InstanceParams instance_params;

  std::shared_ptr<const bssl::ParsedCertificate> root_cert =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(root->GetX509Certificate()->cert_buffer()),
          net::x509_util::DefaultParseCertificateOptions(), nullptr);
  ASSERT_TRUE(root_cert);
  CertVerifyProc::CertificateWithConstraints cert_with_constraints;
  cert_with_constraints.certificate = std::move(root_cert);
  cert_with_constraints.permitted_dns_names.push_back("example.com");

  instance_params.additional_trust_anchors_with_constraints.push_back(
      cert_with_constraints);

  InitializeVerifyProc(instance_params);

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest,
       AddedRootWithOutsideDNSConstraintsNotMatched) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  CertVerifyProc::InstanceParams instance_params;

  std::shared_ptr<const bssl::ParsedCertificate> root_cert =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(root->GetX509Certificate()->cert_buffer()),
          net::x509_util::DefaultParseCertificateOptions(), nullptr);
  ASSERT_TRUE(root_cert);
  CertVerifyProc::CertificateWithConstraints cert_with_constraints;
  cert_with_constraints.certificate = std::move(root_cert);
  cert_with_constraints.permitted_dns_names.push_back("foobar.com");

  instance_params.additional_trust_anchors_with_constraints.push_back(
      cert_with_constraints);

  InitializeVerifyProc(instance_params);

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest, AddedRootWithOutsideCIDRConstraints) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  CertVerifyProc::InstanceParams instance_params;

  std::shared_ptr<const bssl::ParsedCertificate> root_cert =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(root->GetX509Certificate()->cert_buffer()),
          net::x509_util::DefaultParseCertificateOptions(), nullptr);
  ASSERT_TRUE(root_cert);
  CertVerifyProc::CertificateWithConstraints cert_with_constraints;
  cert_with_constraints.certificate = std::move(root_cert);
  cert_with_constraints.permitted_cidrs.push_back(
      {net::IPAddress(192, 168, 1, 104), net::IPAddress(255, 255, 255, 0)});

  instance_params.additional_trust_anchors_with_constraints.push_back(
      cert_with_constraints);

  InitializeVerifyProc(instance_params);

  leaf->SetSubjectAltNames(/*dns_names=*/{"www.example.com"},
                           /*ip_addresses=*/{net::IPAddress(192, 168, 1, 254)});
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest,
       AddedRootWithOutsideCIDRConstraintsNotMatched) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  CertVerifyProc::InstanceParams instance_params = CreateParams({});

  std::shared_ptr<const bssl::ParsedCertificate> root_cert =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(root->GetX509Certificate()->cert_buffer()),
          net::x509_util::DefaultParseCertificateOptions(), nullptr);
  ASSERT_TRUE(root_cert);
  CertVerifyProc::CertificateWithConstraints cert_with_constraints;
  cert_with_constraints.certificate = std::move(root_cert);
  cert_with_constraints.permitted_cidrs.push_back(
      {net::IPAddress(192, 168, 1, 1), net::IPAddress(255, 255, 255, 0)});

  instance_params.additional_trust_anchors_with_constraints.push_back(
      cert_with_constraints);

  InitializeVerifyProc(instance_params);

  leaf->SetSubjectAltNames(/*dns_names=*/{"www.example.com"},
                           /*ip_addresses=*/{net::IPAddress(10, 2, 2, 2)});
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest, AddedRootWithBadTime) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetValidity(/*not_before=*/base::Time::Now() - base::Days(10),
                    /*not_after=*/base::Time::Now() - base::Days(5));
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{},
      /*additional_trust_anchors_with_enforced_constraints=*/
      {root->GetX509Certificate()},
      /*additional_distrusted_certificates=*/{}));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  // Root is valid but expired and we check it.
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest, AddedRootWithBadTimeButNotEnforced) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetValidity(/*not_before=*/base::Time::Now() - base::Days(10),
                    /*not_after=*/base::Time::Now() - base::Days(5));
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()},
      /*additional_trust_anchors_with_enforced_constraints=*/{},
      /*additional_distrusted_certificates=*/{}));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  // Root is valid but expired, but we don't check it.
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest, TimeTracker) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetValidity(/*not_before=*/base::Time::Now() - base::Days(10),
                    /*not_after=*/base::Time::Now() - base::Days(5));
  InitializeVerifyProc(
      CreateParams(
          /*additional_trust_anchors=*/{},
          /*additional_trust_anchors_with_enforced_constraints=*/
          {root->GetX509Certificate()},
          /*additional_distrusted_certificates=*/{}),
      base::Time::Now() - base::Days(7));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  // Root is expired when compared to base::Time::Now, but is valid in the
  // time provided by the time tracker.
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest, TimeTrackerFailureIsRetriedWithSystemTime) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetValidity(/*not_before=*/base::Time::Now() - base::Days(10),
                    /*not_after=*/base::Time::Now() + base::Days(10));
  InitializeVerifyProc(
      CreateParams(
          /*additional_trust_anchors=*/{},
          /*additional_trust_anchors_with_enforced_constraints=*/
          {root->GetX509Certificate()},
          /*additional_distrusted_certificates=*/{}),
      base::Time::Now() + base::Days(20));

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*flags=*/0, &verify_result,
         &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  // Root is expired when compared to the time tracker time, but valid when
  // compared to base::Time::Now.
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest,
       TimeTrackerRevocationFailureIsRetriedWithSystemTime) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  root->SetValidity(/*not_before=*/base::Time::Now() - base::Days(3),
                    /*not_after=*/base::Time::Now() + base::Days(2));
  // The CRL DP sets its this_update time to base::Time::Now() - 1 day. Use two
  // days before now as the current time to cause checks to fail with
  // UNABLE_TO_CHECK_REVOCATION, which then should be retried with the system
  // time a
```