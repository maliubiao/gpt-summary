Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The primary goal is to analyze `url_request_context_builder_unittest.cc` and explain its functionality, its relationship with JavaScript (if any), provide examples, highlight potential user errors, and describe how one might reach this code during debugging.

2. **Identify the Core Class Under Test:**  The filename itself gives a huge clue: `URLRequestContextBuilder`. The `#include "net/url_request/url_request_context_builder.h"` confirms this. The tests are focused on verifying the behavior of this builder class.

3. **Examine the Includes:** The included headers provide valuable context:
    * `base/...`:  Basic utilities from the Chromium base library (callbacks, threading, testing features).
    * `build/build_config.h`:  Platform-specific compilation flags.
    * `net/base/...`:  Fundamental networking concepts (network changes, priorities, DNS, proxies).
    * `net/dns/...`: DNS-related classes.
    * `net/http/...`: HTTP-specific classes (authentication).
    * `net/log/...`: Network logging.
    * `net/proxy_resolution/...`: Proxy resolution logic.
    * `net/socket/...`: Socket creation.
    * `net/ssl/...`: SSL information.
    * `net/test/...`:  Testing utilities (embedded server, gtest integration).
    * `net/traffic_annotation/...`: Traffic annotation for privacy.
    * `net/url_request/...`: Core URL request classes.
    * `testing/gtest/...`: Google Test framework.
    * `url/...`: URL parsing.

4. **Analyze the Test Structure:**  The code uses Google Test (`TEST_F`). Each `TEST_F` function represents a specific test case for the `URLRequestContextBuilder`. The tests generally follow this pattern:
    * **Setup:**  Create a `URLRequestContextBuilder` instance. Potentially configure it (e.g., setting user agent, custom auth handler).
    * **Action:** Call the `Build()` method of the builder to create a `URLRequestContext`. Sometimes, further actions are taken on the created context (e.g., creating and sending a `URLRequest`).
    * **Assertion:**  Use `EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_FALSE`, etc., to verify the expected behavior of the built context.

5. **Categorize the Test Cases:**  Group the tests based on what aspects of the `URLRequestContextBuilder` they are testing:
    * Basic functionality (default settings, user agent).
    * HTTP authentication.
    * Network error logging and reporting (including shutdown scenarios).
    * Host resolution.
    * Network binding (specific to Android).
    * QUIC configuration.

6. **Identify Connections to JavaScript (or Lack Thereof):** The core functionality is about configuring the *network stack*. While this stack is used by the browser (which runs JavaScript), this *specific* file isn't directly manipulating or interacting with JavaScript code. The requests initiated here could *load* JavaScript, but the focus of the *tests* is on the underlying network configuration. This leads to the conclusion that the connection is *indirect*.

7. **Develop Examples (Hypothetical Input/Output):** For each test category, consider what input is given to the builder and what the expected output (behavior of the built context) would be. This helps illustrate the functionality.

8. **Identify Potential User/Developer Errors:** Think about common mistakes developers might make when using the `URLRequestContextBuilder` or when debugging network issues. This often involves incorrect configuration or misunderstanding the behavior of certain settings.

9. **Trace User Actions to Reach the Code (Debugging Scenario):** Imagine a user experiencing a network issue. Trace the steps a developer might take to diagnose the problem, potentially leading them to inspect the creation of the `URLRequestContext`. Keywords here are "network problems," "debugging tools," "network stack configuration."

10. **Structure the Output:** Organize the findings logically with clear headings and bullet points. Start with a concise summary, then elaborate on each aspect (functionality, JavaScript relation, examples, errors, debugging).

11. **Refine and Review:** Read through the analysis to ensure clarity, accuracy, and completeness. Are the explanations easy to understand? Are the examples relevant?  Have all aspects of the prompt been addressed?  For instance, initially, I might have focused too much on the individual tests. Stepping back to see the *broader purpose* of the file (testing the builder) is important. Also, double-checking the connection to JavaScript is crucial to avoid overstating a direct link.

This structured approach allows for a comprehensive analysis of the code, addressing all aspects of the prompt systematically. The key is to understand the purpose of the code under test and how the individual tests contribute to verifying that purpose.
这个文件 `net/url_request/url_request_context_builder_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是 **测试 `URLRequestContextBuilder` 类**。 `URLRequestContextBuilder` 负责构建和配置 `URLRequestContext` 对象，而 `URLRequestContext` 是 Chromium 网络栈的核心组件，用于管理网络请求的上下文信息，例如 Cookie 管理、缓存、代理设置、HTTP 认证等。

以下是这个文件的具体功能分解：

**1. 测试 `URLRequestContextBuilder` 的各种配置选项:**

该文件包含了多个测试用例 (以 `TEST_F` 开头)，每个测试用例都针对 `URLRequestContextBuilder` 的不同配置选项进行验证，确保这些选项能够正确地被应用到最终创建的 `URLRequestContext` 对象上。  这些测试涵盖了：

* **默认设置 (`DefaultSettings`):** 验证在没有特殊配置的情况下，`URLRequestContext` 的默认行为是否符合预期，例如发送带有自定义 header 的 GET 请求。
* **用户代理 (`UserAgent`):**  测试设置用户代理字符串的功能。
* **HTTP 认证处理器工厂 (`DefaultHttpAuthHandlerFactory`, `CustomHttpAuthHandlerFactory`):** 验证默认和自定义的 HTTP 认证处理器的配置。
* **网络错误日志和 Reporting 服务 (`ShutDownNELAndReportingWithPendingUpload`, `ShutDownNELAndReportingWithPendingUploadAndPersistentStorage`, `BuilderSetEnterpriseReportingEndpointsWithFeatureEnabled`, `BuilderSetEnterpriseReportingEndpointsWithFeatureDisabled`):** 测试与网络错误日志 (NEL) 和 Reporting API 相关的配置，包括在有待处理上传时的正确关闭行为，以及企业级 Reporting 端点的设置。
* **Host 解析器 (`ShutdownHostResolverWithPendingRequest`, `DefaultHostResolver`, `CustomHostResolver`):** 测试不同 Host 解析器配置方式，包括使用默认的、自定义的，以及在有待处理请求时关闭 Host 解析器的行为。
* **网络绑定 (`BindToNetworkFinalConfiguration`, `BindToNetworkCustomManagerOptions`):** 测试将网络请求绑定到特定网络接口的功能（主要在 Android 平台上）。
* **QUIC 会话迁移 (`MigrateSessionsOnNetworkChangeV2Default`, `MigrateSessionsOnNetworkChangeV2Override`):** 测试 QUIC 协议在网络变化时的会话迁移行为。

**2. 模拟网络环境:**

为了进行有效的单元测试，该文件使用了 `net::EmbeddedTestServer` 来创建一个简单的本地 HTTP 服务器，用于测试网络请求。同时，它也使用了 `net::MockHostResolver` 来模拟 DNS 解析的行为。

**3. 使用 Google Test 框架:**

该文件使用 Google Test (gtest) 框架来编写和运行测试用例，提供了断言宏 (例如 `EXPECT_EQ`, `ASSERT_TRUE`) 来验证代码的预期行为。

**与 JavaScript 的关系:**

虽然 `URLRequestContextBuilder` 和 `URLRequestContext` 本身是用 C++ 编写的，并且直接运行在浏览器进程中，但它们 **间接地** 与 JavaScript 功能相关。

* **JavaScript 发起的网络请求:** 当 JavaScript 代码（例如通过 `fetch` API 或 `XMLHttpRequest`）发起网络请求时，浏览器底层会使用 `URLRequestContext` 来处理这些请求。`URLRequestContextBuilder` 的配置会影响这些 JavaScript 发起的请求的行为，例如使用的代理、发送的 User-Agent、处理 HTTP 认证的方式等。
* **Reporting API:** 一些测试用例涉及到 Reporting API，这是一个允许网站收集关于客户端错误的机制。JavaScript 可以使用 Reporting API 来发送报告，而 `URLRequestContextBuilder` 的配置会影响这些报告的发送和处理。

**举例说明与 JavaScript 的关系:**

假设 JavaScript 代码发起一个 `fetch` 请求：

```javascript
fetch('https://example.com/api/data', {
  headers: {
    'X-Custom-Header': 'From-Javascript'
  }
});
```

当浏览器处理这个 `fetch` 请求时，它会使用一个 `URLRequestContext` 实例。  `URLRequestContextBuilder` 的配置可能会影响：

* **User-Agent:** 如果 `URLRequestContextBuilder` 被配置了特定的 User-Agent，那么这个请求的 `User-Agent` header 将会是配置的值，而不是浏览器的默认值。
* **代理设置:** 如果 `URLRequestContextBuilder` 配置了代理服务器，那么这个请求将会通过配置的代理发送。
* **HTTP 认证:** 如果服务器需要认证，`URLRequestContext` 将会根据 `URLRequestContextBuilder` 中配置的 `HttpAuthHandlerFactory` 来处理认证挑战。
* **Reporting:** 如果 `example.com` 的服务器设置了 Reporting API，并且 `URLRequestContextBuilder` 启用了 Reporting 功能，那么浏览器可能会根据配置发送相关的报告。

**逻辑推理 (假设输入与输出):**

考虑 `TEST_F(URLRequestContextBuilderTest, UserAgent)` 这个测试用例：

* **假设输入:**  `URLRequestContextBuilder` 的 `set_user_agent()` 方法被调用，并传入字符串 "Bar"。
* **预期输出:**  当使用构建的 `URLRequestContext` 发起网络请求到 `test_server_.GetURL("/echoheader?User-Agent")` 时，服务器应该返回请求的 `User-Agent` header 的值，即 "Bar"。

**用户或编程常见的使用错误:**

* **未正确配置代理:**  用户可能在浏览器设置中配置了代理，但开发者在代码中没有使用 `URLRequestContextBuilder` 正确地集成这些代理设置，导致请求没有按预期通过代理发送。
* **错误的 HTTP 认证配置:**  开发者可能错误地配置了 `HttpAuthHandlerFactory`，导致无法处理特定类型的 HTTP 认证，或者意外地禁用了某些认证方式。例如，如果开发者自定义了一个 `HttpAuthHandlerFactory` 但没有包含处理 "basic" 认证的逻辑，那么依赖 "basic" 认证的网站可能无法正常访问。
* **在需要特定网络接口时没有绑定网络:** 在 Android 等平台上，如果应用需要通过特定的网络接口发送请求（例如 VPN 连接），但开发者没有使用 `BindToNetwork()` 方法来绑定网络，可能导致请求发送失败或使用了错误的接口。
* **误解 Reporting API 的配置:** 开发者可能错误地配置了 Reporting Policy，导致本应发送的错误报告没有被发送，或者发送到了错误的目标。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户报告某个网站的加载存在问题，或者在使用某个 Web 应用时遇到网络相关的错误。作为开发者，进行调试的步骤可能如下：

1. **用户报告问题:** 用户反馈无法访问某个网站，或者网站功能异常。
2. **初步排查:** 开发者尝试自己访问该网站，检查网络连接是否正常。
3. **使用浏览器开发者工具:** 开发者打开浏览器的开发者工具 (通常是 F12 键)，查看 "Network" 标签页，检查网络请求的状态、header 和响应内容。
4. **检查请求失败原因:** 如果请求失败，开发者会查看错误代码和详细信息，例如 DNS 解析错误、连接超时、HTTP 状态码错误等。
5. **怀疑网络栈配置问题:** 如果错误信息指向底层的网络问题，或者怀疑是浏览器自身的配置导致的问题，开发者可能会开始查看 Chromium 的网络栈源代码。
6. **搜索相关代码:** 开发者可能会搜索与 `URLRequestContext`、`URLRequest`、代理、认证等相关的代码，以了解请求是如何被创建和处理的。
7. **查看 `URLRequestContextBuilder` 的使用:** 开发者可能会查看浏览器或相关组件的代码，找到创建 `URLRequestContext` 的地方，并查看 `URLRequestContextBuilder` 是如何被配置的。
8. **分析单元测试:**  开发者可能会找到 `net/url_request/url_request_context_builder_unittest.cc` 这个文件，查看其中的测试用例，了解 `URLRequestContextBuilder` 的各种配置选项及其预期行为，以便更好地理解和调试实际运行时的网络栈配置。

总而言之，`net/url_request/url_request_context_builder_unittest.cc` 是一个至关重要的测试文件，它确保了 `URLRequestContextBuilder` 能够按照预期工作，从而保证了 Chromium 网络栈的稳定性和可靠性。虽然它不是直接与 JavaScript 交互的代码，但它的配置直接影响着 JavaScript 发起的网络请求的行为。在调试网络相关问题时，理解这个文件的作用和测试用例是非常有帮助的。

Prompt: 
```
这是目录为net/url_request/url_request_context_builder_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context_builder.h"

#include "base/functional/callback_helpers.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "net/base/cronet_buildflags.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_handler.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/socket/client_socket_factory.h"
#include "net/ssl/ssl_info.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) ||
        // BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#endif  // BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(ENABLE_REPORTING)
#include "base/files/scoped_temp_dir.h"

#if !BUILDFLAG(CRONET_BUILD)
// gn check does not account for BUILDFLAG(). So, for Cronet builds, it will
// complain about a missing dependency on the target exposing this header. Add a
// nogncheck to stop it from yelling.
#include "net/extras/sqlite/sqlite_persistent_reporting_and_nel_store.h"  // nogncheck
#endif  // !BUILDFLAG(CRONET_BUILD)

#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_service.h"
#include "net/reporting/reporting_uploader.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

namespace net {

namespace {

class MockHttpAuthHandlerFactory : public HttpAuthHandlerFactory {
 public:
  MockHttpAuthHandlerFactory(std::string supported_scheme, int return_code)
      : return_code_(return_code), supported_scheme_(supported_scheme) {}
  ~MockHttpAuthHandlerFactory() override = default;

  int CreateAuthHandler(
      HttpAuthChallengeTokenizer* challenge,
      HttpAuth::Target target,
      const SSLInfo& ssl_info,
      const NetworkAnonymizationKey& network_anonymization_key,
      const url::SchemeHostPort& scheme_host_port,
      CreateReason reason,
      int nonce_count,
      const NetLogWithSource& net_log,
      HostResolver* host_resolver,
      std::unique_ptr<HttpAuthHandler>* handler) override {
    handler->reset();

    return challenge->auth_scheme() == supported_scheme_
               ? return_code_
               : ERR_UNSUPPORTED_AUTH_SCHEME;
  }

 private:
  int return_code_;
  std::string supported_scheme_;
};

class URLRequestContextBuilderTest : public PlatformTest,
                                     public WithTaskEnvironment {
 protected:
  URLRequestContextBuilderTest() {
    test_server_.AddDefaultHandlers(
        base::FilePath(FILE_PATH_LITERAL("net/data/url_request_unittest")));
    SetUpURLRequestContextBuilder(builder_);
  }

  void SetUpURLRequestContextBuilder(URLRequestContextBuilder& builder) {
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
    builder.set_proxy_config_service(std::make_unique<ProxyConfigServiceFixed>(
        ProxyConfigWithAnnotation::CreateDirect()));
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) ||
        // BUILDFLAG(IS_ANDROID)
  }

  std::unique_ptr<HostResolver> host_resolver_ =
      std::make_unique<MockHostResolver>();
  EmbeddedTestServer test_server_;
  URLRequestContextBuilder builder_;
};

TEST_F(URLRequestContextBuilderTest, DefaultSettings) {
  ASSERT_TRUE(test_server_.Start());

  std::unique_ptr<URLRequestContext> context(builder_.Build());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      test_server_.GetURL("/echoheader?Foo"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->set_method("GET");
  request->SetExtraRequestHeaderByName("Foo", "Bar", false);
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_EQ("Bar", delegate.data_received());
}

TEST_F(URLRequestContextBuilderTest, UserAgent) {
  ASSERT_TRUE(test_server_.Start());

  builder_.set_user_agent("Bar");
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      test_server_.GetURL("/echoheader?User-Agent"), DEFAULT_PRIORITY,
      &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->set_method("GET");
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_EQ("Bar", delegate.data_received());
}

TEST_F(URLRequestContextBuilderTest, DefaultHttpAuthHandlerFactory) {
  url::SchemeHostPort scheme_host_port(GURL("https://www.google.com"));
  std::unique_ptr<HttpAuthHandler> handler;
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  SSLInfo null_ssl_info;

  // Verify that the default basic handler is present
  EXPECT_EQ(OK,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "basic", HttpAuth::AUTH_SERVER, null_ssl_info,
                NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
                host_resolver_.get(), &handler));
}

TEST_F(URLRequestContextBuilderTest, CustomHttpAuthHandlerFactory) {
  url::SchemeHostPort scheme_host_port(GURL("https://www.google.com"));
  const int kBasicReturnCode = OK;
  std::unique_ptr<HttpAuthHandler> handler;
  builder_.SetHttpAuthHandlerFactory(
      std::make_unique<MockHttpAuthHandlerFactory>("extrascheme",
                                                   kBasicReturnCode));
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  SSLInfo null_ssl_info;
  // Verify that a handler is returned for a custom scheme.
  EXPECT_EQ(kBasicReturnCode,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "ExtraScheme", HttpAuth::AUTH_SERVER, null_ssl_info,
                NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
                host_resolver_.get(), &handler));

  // Verify that the default basic handler isn't present
  EXPECT_EQ(ERR_UNSUPPORTED_AUTH_SCHEME,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "basic", HttpAuth::AUTH_SERVER, null_ssl_info,
                NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
                host_resolver_.get(), &handler));

  // Verify that a handler isn't returned for a bogus scheme.
  EXPECT_EQ(ERR_UNSUPPORTED_AUTH_SCHEME,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "Bogus", HttpAuth::AUTH_SERVER, null_ssl_info,
                NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
                host_resolver_.get(), &handler));
}

#if BUILDFLAG(ENABLE_REPORTING)
// See crbug.com/935209. This test ensures that shutdown occurs correctly and
// does not crash while destoying the NEL and Reporting services in the process
// of destroying the URLRequestContext whilst Reporting has a pending upload.
TEST_F(URLRequestContextBuilderTest, ShutDownNELAndReportingWithPendingUpload) {
  std::unique_ptr<MockHostResolver> host_resolver =
      std::make_unique<MockHostResolver>();
  host_resolver->set_ondemand_mode(true);
  MockHostResolver* mock_host_resolver = host_resolver.get();
  builder_.set_host_resolver(std::move(host_resolver));
  builder_.set_proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateDirect());
  builder_.set_reporting_policy(std::make_unique<ReportingPolicy>());
  builder_.set_network_error_logging_enabled(true);

  std::unique_ptr<URLRequestContext> context(builder_.Build());
  ASSERT_TRUE(context->network_error_logging_service());
  ASSERT_TRUE(context->reporting_service());

  // Queue a pending upload.
  GURL url("https://www.foo.test");
  context->reporting_service()->GetContextForTesting()->uploader()->StartUpload(
      url::Origin::Create(url), url, IsolationInfo::CreateTransient(),
      "report body", 0,
      /*eligible_for_credentials=*/false, base::DoNothing());
  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(1, context->reporting_service()
                   ->GetContextForTesting()
                   ->uploader()
                   ->GetPendingUploadCountForTesting());
  ASSERT_TRUE(mock_host_resolver->has_pending_requests());

  // This should shut down and destroy the NEL and Reporting services, including
  // the PendingUpload, and should not cause a crash.
  context.reset();
}

#if !BUILDFLAG(CRONET_BUILD)
// See crbug.com/935209. This test ensures that shutdown occurs correctly and
// does not crash while destoying the NEL and Reporting services in the process
// of destroying the URLRequestContext whilst Reporting has a pending upload.
TEST_F(URLRequestContextBuilderTest,
       ShutDownNELAndReportingWithPendingUploadAndPersistentStorage) {
  std::unique_ptr<MockHostResolver> host_resolver =
      std::make_unique<MockHostResolver>();
  host_resolver->set_ondemand_mode(true);
  MockHostResolver* mock_host_resolver = host_resolver.get();
  builder_.set_host_resolver(std::move(host_resolver));
  builder_.set_proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateDirect());
  builder_.set_reporting_policy(std::make_unique<ReportingPolicy>());
  builder_.set_network_error_logging_enabled(true);
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  builder_.set_persistent_reporting_and_nel_store(
      std::make_unique<SQLitePersistentReportingAndNelStore>(
          scoped_temp_dir.GetPath().Append(
              FILE_PATH_LITERAL("ReportingAndNelStore")),
          base::SingleThreadTaskRunner::GetCurrentDefault(),
          base::ThreadPool::CreateSequencedTaskRunner(
              {base::MayBlock(),
               net::GetReportingAndNelStoreBackgroundSequencePriority(),
               base::TaskShutdownBehavior::BLOCK_SHUTDOWN})));

  std::unique_ptr<URLRequestContext> context(builder_.Build());
  ASSERT_TRUE(context->network_error_logging_service());
  ASSERT_TRUE(context->reporting_service());
  ASSERT_TRUE(context->network_error_logging_service()
                  ->GetPersistentNelStoreForTesting());
  ASSERT_TRUE(context->reporting_service()->GetContextForTesting()->store());

  // Queue a pending upload.
  GURL url("https://www.foo.test");
  context->reporting_service()->GetContextForTesting()->uploader()->StartUpload(
      url::Origin::Create(url), url, IsolationInfo::CreateTransient(),
      "report body", 0,
      /*eligible_for_credentials=*/false, base::DoNothing());
  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(1, context->reporting_service()
                   ->GetContextForTesting()
                   ->uploader()
                   ->GetPendingUploadCountForTesting());
  ASSERT_TRUE(mock_host_resolver->has_pending_requests());

  // This should shut down and destroy the NEL and Reporting services, including
  // the PendingUpload, and should not cause a crash.
  context.reset();
}
#endif  // !BUILDFLAG(CRONET_BUILD)

TEST_F(URLRequestContextBuilderTest,
       BuilderSetEnterpriseReportingEndpointsWithFeatureEnabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      net::features::kReportingApiEnableEnterpriseCookieIssues);
  base::flat_map<std::string, GURL> test_enterprise_endpoints{
      {"endpoint-1", GURL("https://example.com/reports")},
      {"endpoint-2", GURL("https://reporting.example/cookie-issues")},
      {"endpoint-3", GURL("https://report-collector.example")},
  };
  builder_.set_reporting_policy(std::make_unique<ReportingPolicy>());
  builder_.set_enterprise_reporting_endpoints(test_enterprise_endpoints);
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  ASSERT_TRUE(context->reporting_service());
  std::vector<net::ReportingEndpoint> expected_enterprise_endpoints = {
      {net::ReportingEndpointGroupKey(net::NetworkAnonymizationKey(),
                                      /*reporting_source=*/std::nullopt,
                                      /*origin=*/std::nullopt, "endpoint-1",
                                      net::ReportingTargetType::kEnterprise),
       {.url = GURL("https://example.com/reports")}},
      {net::ReportingEndpointGroupKey(net::NetworkAnonymizationKey(),
                                      /*reporting_source=*/std::nullopt,
                                      /*origin=*/std::nullopt, "endpoint-2",
                                      net::ReportingTargetType::kEnterprise),
       {.url = GURL("https://reporting.example/cookie-issues")}},
      {net::ReportingEndpointGroupKey(net::NetworkAnonymizationKey(),
                                      /*reporting_source=*/std::nullopt,
                                      /*origin=*/std::nullopt, "endpoint-3",
                                      net::ReportingTargetType::kEnterprise),
       {.url = GURL("https://report-collector.example")}}};

  EXPECT_EQ(expected_enterprise_endpoints,
            context->reporting_service()
                ->GetContextForTesting()
                ->cache()
                ->GetEnterpriseEndpointsForTesting());
}

TEST_F(URLRequestContextBuilderTest,
       BuilderSetEnterpriseReportingEndpointsWithFeatureDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      net::features::kReportingApiEnableEnterpriseCookieIssues);
  base::flat_map<std::string, GURL> test_enterprise_endpoints{
      {"endpoint-1", GURL("https://example.com/reports")},
      {"endpoint-2", GURL("https://reporting.example/cookie-issues")},
      {"endpoint-3", GURL("https://report-collector.example")},
  };
  builder_.set_reporting_policy(std::make_unique<ReportingPolicy>());
  builder_.set_enterprise_reporting_endpoints(test_enterprise_endpoints);
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  ASSERT_TRUE(context->reporting_service());

  EXPECT_EQ(0u, context->reporting_service()
                    ->GetContextForTesting()
                    ->cache()
                    ->GetEnterpriseEndpointsForTesting()
                    .size());
}
#endif  // BUILDFLAG(ENABLE_REPORTING)

TEST_F(URLRequestContextBuilderTest, ShutdownHostResolverWithPendingRequest) {
  auto mock_host_resolver = std::make_unique<MockHostResolver>();
  mock_host_resolver->rules()->AddRule("example.com", "1.2.3.4");
  mock_host_resolver->set_ondemand_mode(true);
  auto state = mock_host_resolver->state();
  builder_.set_host_resolver(std::move(mock_host_resolver));
  std::unique_ptr<URLRequestContext> context(builder_.Build());

  std::unique_ptr<HostResolver::ResolveHostRequest> request =
      context->host_resolver()->CreateRequest(HostPortPair("example.com", 1234),
                                              NetworkAnonymizationKey(),
                                              NetLogWithSource(), std::nullopt);
  TestCompletionCallback callback;
  int rv = request->Start(callback.callback());
  ASSERT_TRUE(state->has_pending_requests());

  context.reset();

  EXPECT_FALSE(state->has_pending_requests());

  // Request should never complete.
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(rv, test::IsError(ERR_IO_PENDING));
  EXPECT_FALSE(callback.have_result());
}

TEST_F(URLRequestContextBuilderTest, DefaultHostResolver) {
  auto manager = std::make_unique<HostResolverManager>(
      HostResolver::ManagerOptions(), nullptr /* system_dns_config_notifier */,
      nullptr /* net_log */);

  // Use a stack allocated builder instead of `builder_` to avoid dangling
  // pointer of `manager`.
  URLRequestContextBuilder builder;
  SetUpURLRequestContextBuilder(builder);
  builder.set_host_resolver_manager(manager.get());
  std::unique_ptr<URLRequestContext> context = builder.Build();

  EXPECT_EQ(context.get(), context->host_resolver()->GetContextForTesting());
  EXPECT_EQ(manager.get(), context->host_resolver()->GetManagerForTesting());
}

TEST_F(URLRequestContextBuilderTest, CustomHostResolver) {
  std::unique_ptr<HostResolver> resolver =
      HostResolver::CreateStandaloneResolver(nullptr);
  ASSERT_FALSE(resolver->GetContextForTesting());

  builder_.set_host_resolver(std::move(resolver));
  std::unique_ptr<URLRequestContext> context = builder_.Build();

  EXPECT_EQ(context.get(), context->host_resolver()->GetContextForTesting());
}

TEST_F(URLRequestContextBuilderTest, BindToNetworkFinalConfiguration) {
#if BUILDFLAG(IS_ANDROID)
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_MARSHMALLOW) {
    GTEST_SKIP()
        << "BindToNetwork is supported starting from Android Marshmallow";
  }

  // The actual network handle doesn't really matter, this test just wants to
  // check that all the pieces are in place and configured correctly.
  constexpr handles::NetworkHandle network = 2;
  auto scoped_mock_network_change_notifier =
      std::make_unique<test::ScopedMockNetworkChangeNotifier>();
  test::MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();

  builder_.BindToNetwork(network);
  std::unique_ptr<URLRequestContext> context = builder_.Build();

  EXPECT_EQ(context->bound_network(), network);
  EXPECT_EQ(context->host_resolver()->GetTargetNetworkForTesting(), network);
  EXPECT_EQ(context->host_resolver()
                ->GetManagerForTesting()
                ->target_network_for_testing(),
            network);
  ASSERT_TRUE(context->GetNetworkSessionContext());
  // A special factory that bind sockets to `network` is needed. We don't need
  // to check exactly for that, the fact that we are not using the default one
  // should be good enough.
  EXPECT_NE(context->GetNetworkSessionContext()->client_socket_factory,
            ClientSocketFactory::GetDefaultFactory());

  const auto* quic_params = context->quic_context()->params();
  EXPECT_FALSE(quic_params->close_sessions_on_ip_change);
  EXPECT_FALSE(quic_params->goaway_sessions_on_ip_change);
  EXPECT_FALSE(quic_params->migrate_sessions_on_network_change_v2);

  const auto* network_session_params = context->GetNetworkSessionParams();
  EXPECT_TRUE(network_session_params->ignore_ip_address_changes);
#else   // !BUILDFLAG(IS_ANDROID)
  GTEST_SKIP() << "BindToNetwork is supported only on Android";
#endif  // BUILDFLAG(IS_ANDROID)
}

TEST_F(URLRequestContextBuilderTest, BindToNetworkCustomManagerOptions) {
#if BUILDFLAG(IS_ANDROID)
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_MARSHMALLOW) {
    GTEST_SKIP()
        << "BindToNetwork is supported starting from Android Marshmallow";
  }

  // The actual network handle doesn't really matter, this test just wants to
  // check that all the pieces are in place and configured correctly.
  constexpr handles::NetworkHandle network = 2;
  auto scoped_mock_network_change_notifier =
      std::make_unique<test::ScopedMockNetworkChangeNotifier>();
  test::MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();

  // Set non-default value for check_ipv6_on_wifi and check that this is what
  // HostResolverManager receives.
  HostResolver::ManagerOptions options;
  options.check_ipv6_on_wifi = !options.check_ipv6_on_wifi;
  builder_.BindToNetwork(network, options);
  std::unique_ptr<URLRequestContext> context = builder_.Build();
  EXPECT_EQ(context->host_resolver()
                ->GetManagerForTesting()
                ->check_ipv6_on_wifi_for_testing(),
            options.check_ipv6_on_wifi);
#else   // !BUILDFLAG(IS_ANDROID)
  GTEST_SKIP() << "BindToNetwork is supported only on Android";
#endif  // BUILDFLAG(IS_ANDROID)
}

TEST_F(URLRequestContextBuilderTest, MigrateSessionsOnNetworkChangeV2Default) {
  std::unique_ptr<URLRequestContext> context = builder_.Build();

  const QuicParams* quic_params = context->quic_context()->params();
#if BUILDFLAG(IS_ANDROID)
  EXPECT_TRUE(quic_params->migrate_sessions_on_network_change_v2);
#else   // !BUILDFLAG(IS_ANDROID)
  EXPECT_FALSE(quic_params->migrate_sessions_on_network_change_v2);
#endif  // BUILDFLAG(IS_ANDROID)
}

TEST_F(URLRequestContextBuilderTest, MigrateSessionsOnNetworkChangeV2Override) {
  base::test::ScopedFeatureList scoped_list;
  scoped_list.InitAndDisableFeature(
      net::features::kMigrateSessionsOnNetworkChangeV2);
  std::unique_ptr<URLRequestContext> context = builder_.Build();

  const QuicParams* quic_params = context->quic_context()->params();
  EXPECT_FALSE(quic_params->migrate_sessions_on_network_change_v2);
}

}  // namespace

}  // namespace net

"""

```