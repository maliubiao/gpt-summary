Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the given Chromium network stack test file (`net/url_request/http_with_dns_over_https_unittest.cc`). It also prompts for connections to JavaScript, logical reasoning, common errors, and debugging steps.

2. **Identify the Core Subject:** The filename strongly suggests the file tests interactions between HTTP requests and DNS over HTTPS (DoH). The `#include` directives confirm this, particularly those related to `net/dns` and `net/url_request`.

3. **High-Level Functionality Extraction:**  A quick skim of the code reveals:
    * **Test Fixtures:** Classes like `DnsOverHttpsIntegrationTest` and `HttpsWithDnsOverHttpsTest` are set up to create controlled testing environments. They involve setting up DoH servers and regular HTTPS servers.
    * **Test Cases:** Functions starting with `TEST_F` are individual test cases focusing on specific scenarios.
    * **Mocking/Stubbing:** The `TestHostResolverProc` class provides a way to simulate DNS resolution.
    * **Assertions:** `EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_THAT` are used to verify expected outcomes.
    * **Feature Flags:** The code uses `base::test::ScopedFeatureList` to enable or disable specific network features during testing.

4. **Detailed Functionality Breakdown (Iterating through key components):**

    * **`TestHostResolverProc`:** This is clearly for simulating DNS resolution. It always returns `127.0.0.1`, and the `insecure_queries_served_` counter helps track how many times this mock resolver is used.

    * **`DohProber`:** This class deals with the automatic DoH probing mechanism. It waits for the system to discover and enable DoH servers.

    * **`DnsOverHttpsIntegrationTest`:**  This is the foundational fixture. It sets up a basic DoH server and configures a `URLRequestContext` to use it. Key aspects include:
        * Starting a `TestDohServer`.
        * Overriding the default DNS configuration to use the test DoH server.
        * Handling different `SecureDnsMode` settings (Secure, Automatic).
        * The `AddHostWithEch` function indicates testing Encrypted Client Hello (ECH).

    * **`HttpsWithDnsOverHttpsTest`:**  Extends the previous fixture by adding a regular HTTPS server. This allows testing end-to-end scenarios involving both DoH for DNS lookups and HTTPS for the actual web request.

    * **`TestHttpDelegate`:** This is a custom delegate to intercept and control `HttpStreamRequest` events, often used for pre-connecting or specific stream handling tests.

    * **`TEST_F(HttpsWithDnsOverHttpsTest, EndToEnd)`:**  This is a core test. It simulates a complete HTTP request where the DNS lookup is handled via DoH. It checks query counts and request success.

    * **`TEST_F(HttpsWithDnsOverHttpsTest, EndToEndFail)`:** This test verifies the behavior when DoH requests fail.

    * **`TEST_F(HttpsWithDnsOverHttpsTest, HttpsUpgrade)`:** This test checks if the browser correctly upgrades an HTTP request to HTTPS when an HTTPS DNS record (SVCB) is present.

    * **`TEST_F(HttpsWithDnsOverHttpsTest, HttpsMetadata)`:** Tests handling of basic HTTPS records and the connection logic around them.

    * **`TEST_F(DnsOverHttpsIntegrationTest, EncryptedClientHello)` and subsequent ECH tests:** These tests are specifically focused on Encrypted Client Hello. They test scenarios with ECH enabled/disabled, stale keys, and fallback mechanisms.

5. **Relating to JavaScript:**  The core functionality tested here is low-level networking. However, browsers expose these functionalities to JavaScript via APIs like `fetch()`. The key connection is that the *outcomes* of these tests (successful DNS resolution, HTTPS upgrades, ECH negotiation) directly affect how JavaScript `fetch()` requests behave.

6. **Logical Reasoning and Examples:**  Consider a test like `EndToEnd`.

    * **Hypothesis:** If DoH is correctly configured, a request to a hostname will resolve via the DoH server, and then the HTTPS request will proceed.
    * **Input:**  A URLRequest to an HTTPS site (`https_server_.GetURL(kHostname, "/test")`) when DoH is enabled.
    * **Output:**  The DoH server receives DNS queries, the test HTTPS server receives a request, and the `TestDelegate` receives the expected response.

7. **Common Errors:**  Think about what could go wrong in a real browser setting that these tests might cover:
    * **DoH Server Unreachable/Failing:** The `EndToEndFail` test directly addresses this.
    * **Incorrect DoH Configuration:**  If the DoH template is wrong, DNS resolution will fail.
    * **Stale or Mismatched ECH Configuration:** The ECH tests cover this.
    * **Network Connectivity Issues:** While not directly tested *in this file*, these tests rely on the underlying network being functional.

8. **Debugging Steps (User Perspective):**  Imagine a user experiencing a website failure that might be related to DoH. How could they end up in a state that triggers these code paths?
    * **Enabling DoH in Browser Settings:** The user explicitly turns on DoH.
    * **Automatic DoH Selection:** The browser automatically decides to use a discovered DoH server.
    * **Website Fails to Load:** The user navigates to a website, and it doesn't load, potentially showing a DNS resolution error.
    * **Checking Browser Network Logs:** The user (or a developer) might inspect the browser's network logs to see if DNS queries are being sent to the expected DoH server and if those requests are succeeding.

9. **Structure and Refinement:** Organize the findings into the requested categories (functionality, JavaScript relation, logic, errors, debugging). Use clear and concise language. Provide specific code examples where relevant.

10. **Review and Iterate:**  Read through the analysis to ensure accuracy and completeness. Are there any other key functionalities or connections that were missed?  For example, explicitly mentioning the role of feature flags is important.
This C++ source code file, `http_with_dns_over_https_unittest.cc`, is a **unit test file** within the Chromium project's network stack. Its primary function is to **test the integration of HTTP requests with DNS over HTTPS (DoH)**. It verifies that when DoH is enabled, the browser correctly uses it for DNS resolution before making HTTP or HTTPS connections.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Testing DoH Usage:**  The core purpose is to ensure that when a user attempts to connect to a website, and DoH is configured, the DNS lookup for that website's IP address is performed using the specified DoH server.
2. **Testing Different DoH Modes:** It tests various Secure DNS modes, including "Secure" (only use DoH) and "Automatic" (try DoH, fall back to regular DNS if it fails or is slow).
3. **Testing DoH Success and Failure Scenarios:** It simulates both successful DoH resolutions and scenarios where the DoH server is unavailable or returns errors, ensuring the browser handles these cases appropriately.
4. **Testing HTTPS Upgrade with SVCB Records:**  It verifies that if a DNS record (specifically an HTTPS or SVCB record) indicates that a domain should be accessed over HTTPS, the browser correctly upgrades an initial HTTP request.
5. **Testing Encrypted Client Hello (ECH):** It includes tests for Encrypted Client Hello, a privacy feature where the client sends part of the TLS handshake encrypted using keys obtained via DNS. It checks scenarios where ECH is enabled, disabled, and when there are issues with the ECH configuration.
6. **Simulating Network Conditions:** While not explicitly manipulating network traffic, the tests control the behavior of mock DoH servers and DNS resolvers to simulate various network scenarios.
7. **Verifying Network Stack Behavior:** It checks the interactions between different components of the network stack, such as the `HostResolver`, `URLRequest`, `HttpStreamFactory`, and `HttpNetworkSession`.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly contain JavaScript, it directly impacts the behavior of network requests initiated by JavaScript code running in a web page.

* **`fetch()` API:** When a JavaScript application uses the `fetch()` API to make an HTTP or HTTPS request, the browser's network stack (where this C++ code resides) handles the underlying operations, including DNS resolution. If DoH is enabled, this test file verifies that the DNS resolution step uses DoH.

**Example:**

Imagine a JavaScript snippet in a webpage:

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

This C++ test file ensures that **before** the HTTPS connection to `example.com` is established, the browser correctly uses the configured DoH server to resolve the IP address of `example.com`.

**Logical Reasoning and Examples:**

Let's take the `TEST_F(HttpsWithDnsOverHttpsTest, EndToEnd)` test case as an example of logical reasoning:

**Hypothesis:** If DoH is correctly configured and the DoH server is working, an HTTPS request to a domain should successfully resolve its IP address via DoH and then establish an HTTPS connection.

**Assumptions (Implicit):**
* A working embedded HTTPS server is set up to serve content for the target domain.
* A functional mock DoH server is configured to resolve the target domain's address.
* The `URLRequestContext` is configured to use the mock DoH server.

**Input (Simulated):**
* A `URLRequest` is created for `https://bar.example.com/test`.

**Steps (Internal to the Test):**
1. The `URLRequest` attempts to resolve the hostname `bar.example.com`.
2. Due to the DoH configuration, the `HostResolver` uses the configured DoH server to perform the DNS lookup.
3. The mock DoH server (simulated by `doh_server_`) responds with the IP address.
4. The `URLRequest` proceeds to establish an HTTPS connection to the resolved IP address.
5. The embedded HTTPS server handles the request and sends a response.

**Output (Observed and Asserted):**
* `doh_server_.QueriesServed()` is expected to be 3 (for A, AAAA, and HTTPS records).
* `host_resolver_proc_->insecure_queries_served()` is expected to be 1 (for resolving the DoH server's hostname itself).
* `test_https_requests_served_` is expected to be 1 (one successful HTTPS request to the target domain).
* `d.response_completed()` is `true`.
* `d.request_status()` is 0 (OK).
* `d.data_received()` matches `kTestBody`.

**User and Programming Common Usage Errors (and how these tests catch them):**

1. **Incorrect DoH Server Configuration:** If a user manually configures a DoH server URL that is invalid or unreachable, these tests simulate that scenario by failing the mock DoH server (`doh_server_.SetFailRequests(true)` in `EndToEndFail`). This helps ensure the browser gracefully falls back or reports an error.
2. **Assuming DoH is Always Active:** Developers might assume that enabling a DoH feature flag automatically means all DNS queries use DoH. However, in "Automatic" mode, the browser might fall back to regular DNS. These tests verify the behavior in different modes.
3. **Ignoring HTTPS Upgrade Signals:**  A website developer might not realize the importance of setting up HTTPS records (SVCB). The `HttpsUpgrade` test verifies that the browser correctly respects these records, improving security and performance.
4. **Misunderstanding ECH Requirements:** Implementing ECH requires both client and server support and proper configuration. The ECH tests ensure that the browser correctly handles different ECH configurations, including mismatches and fallback scenarios.

**User Operation Steps to Reach This Code (Debugging Context):**

Imagine a user reports a website loading issue, and a developer is trying to debug if DoH is involved. Here's a possible sequence leading to investigating this code:

1. **User Reports a Problem:** A user complains that a specific website isn't loading, or they are getting DNS resolution errors.
2. **Initial Investigation:** The developer starts by checking basic network connectivity, DNS settings, and browser configurations.
3. **Suspecting DoH Issues:** If the user has DoH enabled, the developer might suspect that DoH is causing the problem (e.g., the configured DoH server is down, slow, or blocking the domain).
4. **Checking Browser Internals:** The developer might use Chromium's internal tools (like `chrome://net-internals/#dns`) to inspect DNS resolution attempts and see if DoH was used and if it succeeded or failed.
5. **Examining Network Logs:** Detailed network logs might show communication with the DoH server and any errors encountered.
6. **Analyzing Unit Tests (like this file):** To understand the expected behavior of the browser's DoH implementation in various scenarios, the developer might look at unit tests like `http_with_dns_over_https_unittest.cc`. This helps them:
    * **Understand the different DoH modes and their implications.**
    * **See how the browser handles DoH server failures.**
    * **Verify the logic for HTTPS upgrades based on DNS records.**
    * **Investigate potential issues with ECH if the website uses it.**
7. **Reproducing the Issue (Potentially with Test Servers):**  To further isolate the problem, the developer might try to reproduce the issue using local test servers configured with specific DoH settings, similar to how the unit tests are structured.

In essence, this unit test file serves as a valuable resource for understanding the intricate details of Chromium's DoH implementation and how it interacts with other parts of the network stack. It helps developers ensure that DoH works correctly and robustly in various scenarios, ultimately leading to a better and more private browsing experience for users.

Prompt: 
```
这是目录为net/url_request/http_with_dns_over_https_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <vector>

#include "base/big_endian.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/base/network_change_notifier.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_server.h"
#include "net/dns/context_host_resolver.h"
#include "net/dns/dns_client.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_query.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/dns_transaction.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/host_resolver_proc.h"
#include "net/dns/public/dns_config_overrides.h"
#include "net/dns/public/dns_over_https_config.h"
#include "net/dns/public/secure_dns_mode.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/dns/public/util.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/log/net_log.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/gtest_util.h"
#include "net/test/ssl_test_util.h"
#include "net/test/test_doh_server.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {
namespace {

using net::test::IsError;
using net::test::IsOk;

const char kDohHostname[] = "doh-server.example";
const char kHostname[] = "bar.example.com";
const char kTestBody[] = "<html><body>TEST RESPONSE</body></html>";

class TestHostResolverProc : public HostResolverProc {
 public:
  TestHostResolverProc() : HostResolverProc(nullptr) {}

  int Resolve(const std::string& hostname,
              AddressFamily address_family,
              HostResolverFlags host_resolver_flags,
              AddressList* addrlist,
              int* os_error) override {
    insecure_queries_served_++;
    *addrlist = AddressList::CreateFromIPAddress(IPAddress(127, 0, 0, 1), 0);
    return OK;
  }

  uint32_t insecure_queries_served() { return insecure_queries_served_; }

 private:
  ~TestHostResolverProc() override = default;
  uint32_t insecure_queries_served_ = 0;
};

// Runs and waits for the DoH probe to complete in automatic mode. The resolver
// must have a single DoH server, and the DoH server must serve addresses for
// `kDohProbeHostname`.
class DohProber : public NetworkChangeNotifier::DNSObserver {
 public:
  explicit DohProber(ContextHostResolver* resolver) : resolver_(resolver) {}

  void ProbeAndWaitForCompletion() {
    std::unique_ptr<HostResolver::ProbeRequest> probe_request =
        resolver_->CreateDohProbeRequest();
    EXPECT_THAT(probe_request->Start(), IsError(ERR_IO_PENDING));
    if (NumAvailableDohServers() == 0) {
      NetworkChangeNotifier::AddDNSObserver(this);
      loop_.Run();
      NetworkChangeNotifier::RemoveDNSObserver(this);
    }
    EXPECT_GT(NumAvailableDohServers(), 0u);
  }

  void OnDNSChanged() override {
    if (NumAvailableDohServers() > 0) {
      loop_.Quit();
    }
  }

 private:
  size_t NumAvailableDohServers() {
    ResolveContext* context = resolver_->resolve_context_for_testing();
    return context->NumAvailableDohServers(
        context->current_session_for_testing());
  }

  raw_ptr<ContextHostResolver> resolver_;
  base::RunLoop loop_;
};

// A test fixture that creates a DoH server with a `URLRequestContext`
// configured to use it.
class DnsOverHttpsIntegrationTest : public TestWithTaskEnvironment {
 public:
  DnsOverHttpsIntegrationTest()
      : host_resolver_proc_(base::MakeRefCounted<TestHostResolverProc>()) {
    doh_server_.SetHostname(kDohHostname);
    EXPECT_TRUE(doh_server_.Start());

    // In `kAutomatic` mode, DoH support depends on a probe for
    // `kDohProbeHostname`.
    doh_server_.AddAddressRecord(kDohProbeHostname, IPAddress::IPv4Localhost());

    ResetContext();
  }

  URLRequestContext* context() { return request_context_.get(); }

  void ResetContext(SecureDnsMode mode = SecureDnsMode::kSecure) {
    // TODO(crbug.com/40198637): Simplify this.
    HostResolver::ManagerOptions manager_options;
    // Without a DnsConfig, HostResolverManager will not use DoH, even in
    // kSecure mode. See https://crbug.com/1251715. However,
    // DnsClient::BuildEffectiveConfig special-cases overrides that override
    // everything, so that gets around it. Ideally, we would instead mock out a
    // system DnsConfig via the usual pathway.
    manager_options.dns_config_overrides =
        DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
    manager_options.dns_config_overrides.secure_dns_mode = mode;
    manager_options.dns_config_overrides.dns_over_https_config =
        *DnsOverHttpsConfig::FromString(doh_server_.GetPostOnlyTemplate());
    manager_options.dns_config_overrides.use_local_ipv6 = true;
    auto resolver = HostResolver::CreateStandaloneContextResolver(
        /*net_log=*/nullptr, manager_options);

    // Configure `resolver_` to use `host_resolver_proc_` to resolve
    // `doh_server_` itself. Additionally, without an explicit HostResolverProc,
    // HostResolverManager::HaveTestProcOverride disables the built-in DNS
    // client.
    auto* resolver_raw = resolver.get();
    resolver->SetHostResolverSystemParamsForTest(
        HostResolverSystemTask::Params(host_resolver_proc_, 1));

    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_host_resolver(std::move(resolver));
    auto ssl_config_service =
        std::make_unique<TestSSLConfigService>(SSLContextConfig());
    ssl_config_service_ = ssl_config_service.get();
    context_builder->set_ssl_config_service(std::move(ssl_config_service));
    request_context_ = context_builder->Build();

    if (mode == SecureDnsMode::kAutomatic) {
      DohProber prober(resolver_raw);
      prober.ProbeAndWaitForCompletion();
    }
  }

  void AddHostWithEch(const url::SchemeHostPort& host,
                      const IPAddress& address,
                      base::span<const uint8_t> ech_config_list) {
    doh_server_.AddAddressRecord(host.host(), address);
    doh_server_.AddRecord(BuildTestHttpsServiceRecord(
        dns_util::GetNameForHttpsQuery(host),
        /*priority=*/1, /*service_name=*/host.host(),
        {BuildTestHttpsServiceEchConfigParam(ech_config_list)}));
  }

 protected:
  TestDohServer doh_server_;
  scoped_refptr<net::TestHostResolverProc> host_resolver_proc_;
  std::unique_ptr<URLRequestContext> request_context_;
  raw_ptr<TestSSLConfigService> ssl_config_service_;
};

// A convenience wrapper over `DnsOverHttpsIntegrationTest` that also starts an
// HTTPS server.
class HttpsWithDnsOverHttpsTest : public DnsOverHttpsIntegrationTest {
 public:
  HttpsWithDnsOverHttpsTest() {
    EmbeddedTestServer::ServerCertificateConfig cert_config;
    cert_config.dns_names = {kHostname};
    https_server_.SetSSLConfig(cert_config);
    https_server_.RegisterRequestHandler(
        base::BindRepeating(&HttpsWithDnsOverHttpsTest::HandleDefaultRequest,
                            base::Unretained(this)));
    EXPECT_TRUE(https_server_.Start());

    doh_server_.AddAddressRecord(kHostname, IPAddress(127, 0, 0, 1));
  }

  std::unique_ptr<test_server::HttpResponse> HandleDefaultRequest(
      const test_server::HttpRequest& request) {
    auto http_response = std::make_unique<test_server::BasicHttpResponse>();
    test_https_requests_served_++;
    http_response->set_content(kTestBody);
    http_response->set_content_type("text/html");
    return std::move(http_response);
  }

 protected:
  EmbeddedTestServer https_server_{EmbeddedTestServer::Type::TYPE_HTTPS};
  uint32_t test_https_requests_served_ = 0;
};

class TestHttpDelegate : public HttpStreamRequest::Delegate {
 public:
  explicit TestHttpDelegate(HttpNetworkSession* session) : session_(session) {}
  ~TestHttpDelegate() override = default;

  void WaitForCompletion(std::unique_ptr<HttpStreamRequest> request) {
    request_ = std::move(request);
    loop_.Run();
  }

  void OnStreamReady(const ProxyInfo& used_proxy_info,
                     std::unique_ptr<HttpStream> stream) override {
    stream->Close(false);
    loop_.Quit();
  }

  void OnWebSocketHandshakeStreamReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<WebSocketHandshakeStreamBase> stream) override {}

  void OnBidirectionalStreamImplReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<BidirectionalStreamImpl> stream) override {}

  void OnStreamFailed(int status,
                      const NetErrorDetails& net_error_details,
                      const ProxyInfo& used_proxy_info,
                      ResolveErrorInfo resolve_eror_info) override {}

  void OnCertificateError(int status, const SSLInfo& ssl_info) override {}

  void OnNeedsProxyAuth(const HttpResponseInfo& proxy_response,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller) override {}

  void OnNeedsClientAuth(SSLCertRequestInfo* cert_info) override {}

  void OnQuicBroken() override {}

  void OnSwitchesToHttpStreamPool(
      HttpStreamPoolRequestInfo request_info) override {
    CHECK(base::FeatureList::IsEnabled(features::kHappyEyeballsV3));
    request_ = session_->http_stream_pool()->RequestStream(
        this, std::move(request_info), DEFAULT_PRIORITY,
        /*allowed_bad_certs=*/{},
        /*enable_ip_based_pooling=*/false,
        /*enable_alternative_services=*/false, NetLogWithSource());
  }

 private:
  raw_ptr<HttpNetworkSession> session_;
  base::RunLoop loop_;
  std::unique_ptr<HttpStreamRequest> request_;
};

// This test sets up a request which will reenter the connection pools by
// triggering a DNS over HTTPS request. It also sets up an idle socket
// which was a precondition for the crash we saw in  https://crbug.com/830917.
TEST_F(HttpsWithDnsOverHttpsTest, EndToEnd) {
  // Create and start http server.
  EmbeddedTestServer http_server(EmbeddedTestServer::Type::TYPE_HTTP);
  http_server.RegisterRequestHandler(
      base::BindRepeating(&HttpsWithDnsOverHttpsTest::HandleDefaultRequest,
                          base::Unretained(this)));
  EXPECT_TRUE(http_server.Start());

  // Set up an idle socket.
  HttpTransactionFactory* transaction_factory =
      request_context_->http_transaction_factory();
  HttpStreamFactory::JobFactory default_job_factory;
  HttpNetworkSession* network_session = transaction_factory->GetSession();
  TestHttpDelegate request_delegate(network_session);

  HttpStreamFactory* factory = network_session->http_stream_factory();
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = http_server.GetURL("localhost", "/preconnect");

  std::unique_ptr<HttpStreamRequest> request(factory->RequestStream(
      request_info, DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
      &request_delegate, false, false, NetLogWithSource()));
  request_delegate.WaitForCompletion(std::move(request));

  size_t idle_socket_count = 0;
  ClientSocketPool::GroupId group_id(
      url::SchemeHostPort(request_info.url), PrivacyMode::PRIVACY_MODE_DISABLED,
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    idle_socket_count =
        network_session->http_stream_pool()
            ->GetOrCreateGroupForTesting(GroupIdToHttpStreamKey(group_id))
            .IdleStreamSocketCount();
  } else {
    idle_socket_count =
        network_session
            ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                            ProxyChain::Direct())
            ->IdleSocketCountInGroup(group_id);
  }
  EXPECT_EQ(idle_socket_count, 1u);

  // The domain "localhost" is resolved locally, so no DNS lookups should have
  // occurred.
  EXPECT_EQ(doh_server_.QueriesServed(), 0);
  EXPECT_EQ(host_resolver_proc_->insecure_queries_served(), 0u);
  // A stream was established, but no HTTPS request has been made yet.
  EXPECT_EQ(test_https_requests_served_, 0u);

  // Make a request that will trigger a DoH query as well.
  TestDelegate d;
  GURL main_url = https_server_.GetURL(kHostname, "/test");
  std::unique_ptr<URLRequest> req(context()->CreateRequest(
      main_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(https_server_.ShutdownAndWaitUntilComplete());
  EXPECT_TRUE(http_server.ShutdownAndWaitUntilComplete());
  EXPECT_TRUE(doh_server_.ShutdownAndWaitUntilComplete());

  // There should be three DoH lookups for kHostname (A, AAAA, and HTTPS).
  EXPECT_EQ(doh_server_.QueriesServed(), 3);
  // The requests to the DoH server are pooled, so there should only be one
  // insecure lookup for the DoH server hostname.
  EXPECT_EQ(host_resolver_proc_->insecure_queries_served(), 1u);
  // There should be one non-DoH HTTPS request for the connection to kHostname.
  EXPECT_EQ(test_https_requests_served_, 1u);

  EXPECT_TRUE(d.response_completed());
  EXPECT_EQ(d.request_status(), 0);
  EXPECT_EQ(d.data_received(), kTestBody);
}

TEST_F(HttpsWithDnsOverHttpsTest, EndToEndFail) {
  // Fail all DoH requests.
  doh_server_.SetFailRequests(true);

  // Make a request that will trigger a DoH query.
  TestDelegate d;
  GURL main_url = https_server_.GetURL(kHostname, "/test");
  std::unique_ptr<URLRequest> req(context()->CreateRequest(
      main_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(https_server_.ShutdownAndWaitUntilComplete());
  EXPECT_TRUE(doh_server_.ShutdownAndWaitUntilComplete());

  // No HTTPS connection to the test server will be attempted due to the
  // host resolution error.
  EXPECT_EQ(test_https_requests_served_, 0u);

  EXPECT_TRUE(d.response_completed());
  EXPECT_EQ(d.request_status(), net::ERR_NAME_NOT_RESOLVED);

  const auto& resolve_error_info = req->response_info().resolve_error_info;
  EXPECT_TRUE(resolve_error_info.is_secure_network_error);
  EXPECT_EQ(resolve_error_info.error, net::ERR_DNS_MALFORMED_RESPONSE);
}

// An end-to-end test of the HTTPS upgrade behavior.
TEST_F(HttpsWithDnsOverHttpsTest, HttpsUpgrade) {
  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});
  ResetContext();

  GURL https_url = https_server_.GetURL(kHostname, "/test");
  EXPECT_TRUE(https_url.SchemeIs(url::kHttpsScheme));
  GURL::Replacements replacements;
  replacements.SetSchemeStr(url::kHttpScheme);
  GURL http_url = https_url.ReplaceComponents(replacements);

  // `service_name` is `kHostname` rather than "." because "." specifies the
  // query name. For non-defaults ports, the query name uses port prefix naming
  // and does not match the A/AAAA records.
  doh_server_.AddRecord(BuildTestHttpsServiceRecord(
      dns_util::GetNameForHttpsQuery(url::SchemeHostPort(https_url)),
      /*priority=*/1, /*service_name=*/kHostname, /*params=*/{}));

  for (auto mode : {SecureDnsMode::kSecure, SecureDnsMode::kAutomatic}) {
    SCOPED_TRACE(kSecureDnsModes.at(mode));
    ResetContext(mode);

    // Fetch the http URL.
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context()->CreateRequest(
        http_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();
    ASSERT_THAT(d.request_status(), IsOk());

    // The request should have been redirected to https.
    EXPECT_EQ(d.received_redirect_count(), 1);
    EXPECT_EQ(req->url(), https_url);

    EXPECT_TRUE(d.response_completed());
    EXPECT_EQ(d.request_status(), 0);
    EXPECT_EQ(d.data_received(), kTestBody);
  }
}

// An end-to-end test for requesting a domain with a basic HTTPS record. Expect
// this to exercise connection logic for extra HostResolver results with
// metadata.
TEST_F(HttpsWithDnsOverHttpsTest, HttpsMetadata) {
  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});
  ResetContext();

  GURL main_url = https_server_.GetURL(kHostname, "/test");
  EXPECT_TRUE(main_url.SchemeIs(url::kHttpsScheme));

  doh_server_.AddRecord(BuildTestHttpsServiceRecord(
      dns_util::GetNameForHttpsQuery(url::SchemeHostPort(main_url)),
      /*priority=*/1, /*service_name=*/kHostname, /*params=*/{}));

  // Fetch the http URL.
  TestDelegate d;

  std::unique_ptr<URLRequest> req(context()->CreateRequest(
      main_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  ASSERT_THAT(d.request_status(), IsOk());

  // There should be three DoH lookups for kHostname (A, AAAA, and HTTPS).
  EXPECT_EQ(doh_server_.QueriesServed(), 3);

  EXPECT_TRUE(d.response_completed());
  EXPECT_EQ(d.request_status(), 0);
  EXPECT_EQ(d.data_received(), kTestBody);
}

TEST_F(DnsOverHttpsIntegrationTest, EncryptedClientHello) {
  base::test::ScopedFeatureList features;
  features.InitWithFeaturesAndParameters(
      /*enabled_features=*/{{features::kUseDnsHttpsSvcb,
                             {// Disable timeouts.
                              {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}}}},
      /*disabled_features=*/{});

  // Configure a test server that speaks ECH.
  static constexpr char kRealName[] = "secret.example";
  static constexpr char kPublicName[] = "public.example";
  EmbeddedTestServer::ServerCertificateConfig server_cert_config;
  server_cert_config.dns_names = {kRealName};

  SSLServerConfig ssl_server_config;
  std::vector<uint8_t> ech_config_list;
  ssl_server_config.ech_keys =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/128, &ech_config_list);
  ASSERT_TRUE(ssl_server_config.ech_keys);

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(server_cert_config, ssl_server_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  AddressList addr;
  ASSERT_TRUE(test_server.GetAddressList(&addr));
  GURL url = test_server.GetURL(kRealName, "/defaultresponse");
  AddHostWithEch(url::SchemeHostPort(url), addr.front().address(),
                 ech_config_list);

  for (bool ech_enabled : {true, false}) {
    SCOPED_TRACE(ech_enabled);

    // Create a new `URLRequestContext`, to ensure there are no cached
    // sockets, etc., from the previous loop iteration.
    ResetContext();

    SSLContextConfig config;
    config.ech_enabled = ech_enabled;
    ssl_config_service_->UpdateSSLConfigAndNotify(config);

    TestDelegate d;
    std::unique_ptr<URLRequest> r = context()->CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_EQ(ech_enabled, r->ssl_info().encrypted_client_hello);
  }
}

// Test that, if the DNS returns a stale ECHConfigList (or other key mismatch),
// the client can recover and connect to the server, provided the server can
// handshake as the public name.
TEST_F(DnsOverHttpsIntegrationTest, EncryptedClientHelloStaleKey) {
  base::test::ScopedFeatureList features;
  features.InitWithFeaturesAndParameters(
      /*enabled_features=*/{{features::kUseDnsHttpsSvcb,
                             {// Disable timeouts.
                              {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}}}},
      /*disabled_features=*/{});
  ResetContext();

  static constexpr char kRealNameStale[] = "secret1.example";
  static constexpr char kRealNameWrongPublicName[] = "secret2.example";
  static constexpr char kPublicName[] = "public.example";
  static constexpr char kWrongPublicName[] = "wrong-public.example";

  std::vector<uint8_t> ech_config_list, ech_config_list_stale,
      ech_config_list_wrong_public_name;
  bssl::UniquePtr<SSL_ECH_KEYS> ech_keys =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/128, &ech_config_list);
  ASSERT_TRUE(ech_keys);
  ASSERT_TRUE(MakeTestEchKeys(kPublicName, /*max_name_len=*/128,
                              &ech_config_list_stale));
  ASSERT_TRUE(MakeTestEchKeys(kWrongPublicName, /*max_name_len=*/128,
                              &ech_config_list_wrong_public_name));

  // Configure an ECH-supporting server that can speak for all names except
  // `kWrongPublicName`.
  EmbeddedTestServer::ServerCertificateConfig server_cert_config;
  server_cert_config.dns_names = {kRealNameStale, kRealNameWrongPublicName,
                                  kPublicName};
  SSLServerConfig ssl_server_config;
  ssl_server_config.ech_keys = std::move(ech_keys);
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(server_cert_config, ssl_server_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  AddressList addr;
  ASSERT_TRUE(test_server.GetAddressList(&addr));
  GURL url_stale = test_server.GetURL(kRealNameStale, "/defaultresponse");
  GURL url_wrong_public_name =
      test_server.GetURL(kRealNameWrongPublicName, "/defaultresponse");
  AddHostWithEch(url::SchemeHostPort(url_stale), addr.front().address(),
                 ech_config_list_stale);
  AddHostWithEch(url::SchemeHostPort(url_wrong_public_name),
                 addr.front().address(), ech_config_list_wrong_public_name);

  // Connecting to `url_stale` should succeed. Although the server will not
  // decrypt the ClientHello, it can handshake as `kPublicName` and provide new
  // keys for the client to use.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r = context()->CreateRequest(
        url_stale, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_TRUE(r->ssl_info().encrypted_client_hello);
  }

  // Connecting to `url_wrong_public_name` should fail. The server can neither
  // decrypt the ClientHello, nor handshake as `kWrongPublicName`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r =
        context()->CreateRequest(url_wrong_public_name, DEFAULT_PRIORITY, &d,
                                 TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_THAT(d.request_status(),
                IsError(ERR_ECH_FALLBACK_CERTIFICATE_INVALID));
  }
}

TEST_F(DnsOverHttpsIntegrationTest, EncryptedClientHelloFallback) {
  base::test::ScopedFeatureList features;
  features.InitWithFeaturesAndParameters(
      /*enabled_features=*/{{features::kUseDnsHttpsSvcb,
                             {// Disable timeouts.
                              {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}}}},
      /*disabled_features=*/{});
  ResetContext();

  static constexpr char kRealNameStale[] = "secret1.example";
  static constexpr char kRealNameWrongPublicName[] = "secret2.example";
  static constexpr char kPublicName[] = "public.example";
  static constexpr char kWrongPublicName[] = "wrong-public.example";

  std::vector<uint8_t> ech_config_list_stale, ech_config_list_wrong_public_name;
  ASSERT_TRUE(MakeTestEchKeys(kPublicName, /*max_name_len=*/128,
                              &ech_config_list_stale));
  ASSERT_TRUE(MakeTestEchKeys(kWrongPublicName, /*max_name_len=*/128,
                              &ech_config_list_wrong_public_name));

  // Configure a server, without ECH, that can speak for all names except
  // `kWrongPublicName`.
  EmbeddedTestServer::ServerCertificateConfig server_cert_config;
  server_cert_config.dns_names = {kRealNameStale, kRealNameWrongPublicName,
                                  kPublicName};
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(server_cert_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  AddressList addr;
  ASSERT_TRUE(test_server.GetAddressList(&addr));
  GURL url_stale = test_server.GetURL(kRealNameStale, "/defaultresponse");
  GURL url_wrong_public_name =
      test_server.GetURL(kRealNameWrongPublicName, "/defaultresponse");
  AddHostWithEch(url::SchemeHostPort(url_stale), addr.front().address(),
                 ech_config_list_stale);
  AddHostWithEch(url::SchemeHostPort(url_wrong_public_name),
                 addr.front().address(), ech_config_list_wrong_public_name);

  // Connecting to `url_stale` should succeed. Although the server will not
  // decrypt the ClientHello, it can handshake as `kPublicName` and trigger an
  // authenticated fallback.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r = context()->CreateRequest(
        url_stale, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_FALSE(r->ssl_info().encrypted_client_hello);
  }

  // Connecting to `url_wrong_public_name` should fail. The server can neither
  // decrypt the ClientHello, nor handshake as `kWrongPublicName`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r =
        context()->CreateRequest(url_wrong_public_name, DEFAULT_PRIORITY, &d,
                                 TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_THAT(d.request_status(),
                IsError(ERR_ECH_FALLBACK_CERTIFICATE_INVALID));
  }
}

TEST_F(DnsOverHttpsIntegrationTest, EncryptedClientHelloFallbackTLS12) {
  base::test::ScopedFeatureList features;
  features.InitWithFeaturesAndParameters(
      /*enabled_features=*/{{features::kUseDnsHttpsSvcb,
                             {// Disable timeouts.
                              {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
                              {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}}}},
      /*disabled_features=*/{});
  ResetContext();

  static constexpr char kRealNameStale[] = "secret1.example";
  static constexpr char kRealNameWrongPublicName[] = "secret2.example";
  static constexpr char kPublicName[] = "public.example";
  static constexpr char kWrongPublicName[] = "wrong-public.example";

  std::vector<uint8_t> ech_config_list_stale, ech_config_list_wrong_public_name;
  ASSERT_TRUE(MakeTestEchKeys(kPublicName, /*max_name_len=*/128,
                              &ech_config_list_stale));
  ASSERT_TRUE(MakeTestEchKeys(kWrongPublicName, /*max_name_len=*/128,
                              &ech_config_list_wrong_public_name));

  // Configure a server, without ECH or TLS 1.3, that can speak for all names
  // except `kWrongPublicName`.
  EmbeddedTestServer::ServerCertificateConfig server_cert_config;
  server_cert_config.dns_names = {kRealNameStale, kRealNameWrongPublicName,
                                  kPublicName};
  SSLServerConfig ssl_server_config;
  ssl_server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(server_cert_config, ssl_server_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  AddressList addr;
  ASSERT_TRUE(test_server.GetAddressList(&addr));
  GURL url_stale = test_server.GetURL(kRealNameStale, "/defaultresponse");
  GURL url_wrong_public_name =
      test_server.GetURL(kRealNameWrongPublicName, "/defaultresponse");
  AddHostWithEch(url::SchemeHostPort(url_stale), addr.front().address(),
                 ech_config_list_stale);
  AddHostWithEch(url::SchemeHostPort(url_wrong_public_name),
                 addr.front().address(), ech_config_list_wrong_public_name);

  // Connecting to `url_stale` should succeed. Although the server will not
  // decrypt the ClientHello, it can handshake as `kPublicName` and trigger an
  // authenticated fallback.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r = context()->CreateRequest(
        url_stale, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_FALSE(r->ssl_info().encrypted_client_hello);
  }

  // Connecting to `url_wrong_public_name` should fail. The server can neither
  // decrypt the ClientHello, nor handshake as `kWrongPublicName`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r =
        context()->CreateRequest(url_wrong_public_name, DEFAULT_PRIORITY, &d,
                                 TRAFFIC_ANNOTATION_FOR_TESTS);
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_THAT(d.request_status(),
                IsError(ERR_ECH_FALLBACK_CERTIFICATE_INVALID));
  }
}

}  // namespace
}  // namespace net

"""

```