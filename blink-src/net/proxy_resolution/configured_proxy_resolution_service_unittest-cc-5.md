Response:
The user wants to understand the functionality of the `configured_proxy_resolution_service_unittest.cc` file in Chromium's networking stack. I need to analyze the provided code snippets to identify the features being tested.

Here's a breakdown of the tests and their functionalities:

1. **`TestPacScriptURLRetry`**: Tests retrying PAC script download on failure.
2. **`TestTwoPendingRequestsSamePacURL`**: Tests handling two concurrent proxy requests that rely on the same PAC script.
3. **`TestTwoPendingRequestsDifferentPacURL`**: Tests handling two concurrent proxy requests that rely on different PAC scripts.
4. **`DnsChangeNoopWithoutResolver`**: Tests that a DNS change notification has no effect when no proxy requests are active.
5. **`SanitizeUrlHelper` and `SanitizeUrlForPacScript`**: Tests that URLs are sanitized before being passed to the proxy resolver, ensuring PAC scripts don't see sensitive information.
6. **`OnShutdownWithLiveRequest`**: Tests the behavior of the service when it's shut down while a proxy resolution request is in progress.
7. **`OnShutdownFollowedByRequest`**: Tests the behavior of the service when a proxy resolution request is made after the service has been shut down.
8. **`ImplicitlyBypassWithManualSettings`**: Tests that certain local hostnames and IP addresses are automatically bypassed when using manual proxy settings.
9. **`ImplicitlyBypassWithPac`**: Tests that certain local hostnames and IP addresses are automatically bypassed even when using a PAC script for proxy configuration.
10. **`CastToConfiguredProxyResolutionService`**: Tests the ability to cast a `ProxyResolutionService` to a `ConfiguredProxyResolutionService`.

Now I need to address the user's specific requirements:

*   **List the functions:** I've done this in the breakdown above.
*   **Relationship with JavaScript:**  PAC scripts are written in JavaScript. The tests involving PAC scripts and URL sanitization are directly related to how JavaScript code in the PAC script interacts with the browser.
*   **Logical reasoning (input/output):**  I can provide examples for tests like `SanitizeUrlForPacScript`.
*   **User/programming errors:**  The `OnShutdown` tests and the PAC script retry test touch on potential error scenarios.
*   **User operations leading to this code:**  This involves proxy configuration and network requests.
*   **Summary of functionality:**  I need to provide a concise overview.
这是 `net/proxy_resolution/configured_proxy_resolution_service_unittest.cc` 文件（第 6 部分，共 6 部分）的功能归纳：

**核心功能：测试 `ConfiguredProxyResolutionService` 类的各种功能和边界情况。**

`ConfiguredProxyResolutionService` 是 Chromium 网络栈中负责代理解析的核心组件。它根据系统配置（例如，手动代理设置或 PAC 脚本）来决定如何为给定的 URL 请求选择代理服务器。

这个单元测试文件专注于验证 `ConfiguredProxyResolutionService` 的行为是否符合预期，涵盖了以下几个主要方面：

**1. PAC 脚本处理：**

*   **PAC 脚本下载和重试:** 测试当 PAC 脚本下载失败时，服务是否会按照策略进行重试 (`TestPacScriptURLRetry`)。
*   **并发请求处理:** 测试当多个并发请求依赖于相同的或不同的 PAC 脚本时，服务是否能正确处理 (`TestTwoPendingRequestsSamePacURL`, `TestTwoPendingRequestsDifferentPacURL`)。
*   **PAC 脚本内容的加载:** 验证 PAC 脚本内容是否被正确加载到代理解析器工厂 (`EXPECT_EQ(kValidPacScript216, factory_ptr->pending_requests()[0]->script_data()->utf16());`)。

**2. DNS 变更通知：**

*   **无操作行为:** 测试当没有待处理的代理请求时，收到 DNS 变更通知是否不会触发任何操作 (`DnsChangeNoopWithoutResolver`)。

**3. URL 安全处理 (Sanitization)：**

*   **发送到 PAC 脚本的 URL 的清理:** 测试发送到 PAC 脚本执行器（通常是一个 JavaScript 引擎）的 URL 是否被正确清理，以防止敏感信息泄露。例如，对于 HTTPS URL，路径和查询参数会被移除 (`SanitizeUrlForPacScript`)。

    *   **假设输入:** 一个包含敏感信息的 HTTPS URL，例如 `https://user:password@example.com/secret?query=data#hash`。
    *   **预期输出:**  发送到 PAC 脚本的清理后的 URL，例如 `https://example.com/`。

**4. 服务生命周期管理：**

*   **`OnShutdown` 方法:** 测试在有正在进行的代理请求时调用 `OnShutdown` 的行为 (`OnShutdownWithLiveRequest`)，以及在 `OnShutdown` 后发起请求的行为 (`OnShutdownFollowedByRequest`)。

**5. 隐式代理绕过：**

*   **手动配置下的绕过:** 测试在使用手动代理配置时，对于某些特殊的主机名（如 `localhost`，本地 IP 地址）是否会自动绕过代理 (`ImplicitlyBypassWithManualSettings`)。
*   **PAC 脚本配置下的绕过:** 测试在使用 PAC 脚本配置代理时，对于某些特殊的主机名是否仍然会自动绕过代理 (`ImplicitlyBypassWithPac`)。

**6. 类型转换：**

*   **向下转型:** 测试是否可以将 `ProxyResolutionService` 指针安全地转换为 `ConfiguredProxyResolutionService` 指针 (`CastToConfiguredProxyResolutionService`)。

**与 JavaScript 功能的关系：**

这个文件与 JavaScript 的主要关系在于 PAC 脚本。PAC 脚本是使用 JavaScript 编写的，用于动态决定特定 URL 请求应该使用哪个代理服务器。

*   **PAC 脚本内容:**  测试中会加载预定义的 PAC 脚本内容 (`kValidPacScript1`, `kValidPacScript2`)，这些内容本质上是 JavaScript 代码。
*   **URL 清理的重要性:**  由于 PAC 脚本是 JavaScript 代码，如果直接将用户输入的完整 URL 传递给 PAC 脚本，可能会导致安全问题。例如，恶意 PAC 脚本可能会尝试访问 URL 中的敏感信息（如用户名、密码或路径）。因此，`SanitizeUrlForPacScript` 测试验证了在将 URL 传递给 PAC 脚本执行器之前，会进行必要的清理。

**用户或编程常见的使用错误举例：**

*   **配置错误的 PAC 脚本 URL:** 用户可能会在系统代理设置中配置一个无法访问或返回错误的 PAC 脚本 URL。`TestPacScriptURLRetry` 测试了在这种情况下，服务是否会进行重试，避免因为一次临时的网络问题而永久失败。
*   **在服务关闭后发起请求:** 开发者可能会在 `ConfiguredProxyResolutionService` 对象被销毁或关闭后尝试发起代理解析请求。`OnShutdownFollowedByRequest` 测试了这种情况下的行为，通常会直接返回 `OK` 且不使用代理。
*   **没有考虑到隐式绕过:** 开发者在编写网络请求代码时，如果假设所有请求都会经过配置的代理，可能会在访问本地服务时遇到问题。`ImplicitlyBypassWithManualSettings` 和 `ImplicitlyBypassWithPac` 测试强调了 `localhost` 等特殊主机名会被自动绕过，开发者需要了解这一行为。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户修改系统代理设置:** 用户可能通过操作系统或浏览器设置界面，配置了手动代理服务器地址或一个 PAC 脚本 URL。
2. **应用程序发起网络请求:** 当应用程序（例如 Chromium 浏览器）需要访问一个 URL 时，它会调用网络栈的相应 API。
3. **`ConfiguredProxyResolutionService` 介入:**  网络栈会使用 `ConfiguredProxyResolutionService` 来解析该请求应该如何路由。
4. **PAC 脚本下载（如果配置了 PAC）：** 如果配置了 PAC 脚本，`ConfiguredProxyResolutionService` 会首先尝试下载该脚本。测试中的 `MockPacFileFetcher` 模拟了这个下载过程。
5. **PAC 脚本执行或直接使用手动配置:** 下载完成后，PAC 脚本会被执行，或者直接使用手动配置的代理服务器。`MockAsyncProxyResolverFactory` 和 `MockAsyncProxyResolver` 模拟了 PAC 脚本的执行过程。
6. **返回代理信息:**  `ConfiguredProxyResolutionService` 会返回一个 `ProxyInfo` 对象，指示应该使用哪个代理服务器（或直接连接）。

如果调试过程中发现代理行为异常，例如，应该使用代理的请求没有使用，或者 PAC 脚本下载失败，就可以参考这些单元测试来理解 `ConfiguredProxyResolutionService` 的预期行为，并定位问题所在。例如，如果怀疑是 PAC 脚本下载重试机制有问题，可以查看 `TestPacScriptURLRetry` 的相关逻辑。如果怀疑是 URL 清理导致 PAC 脚本行为异常，可以查看 `SanitizeUrlForPacScript` 的测试用例。

**总结 `ConfiguredProxyResolutionService` 的功能：**

`ConfiguredProxyResolutionService` 是 Chromium 网络栈中负责根据系统配置（手动代理或 PAC 脚本）为网络请求选择合适的代理服务器的关键组件。它负责下载和管理 PAC 脚本，处理并发请求，确保发送到 PAC 脚本的 URL 是安全的，并在服务生命周期内正确处理请求。同时，它也会根据规则自动绕过某些本地请求的代理。这个单元测试文件全面验证了这些核心功能及其边界情况。

Prompt: 
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能

"""
  GURL("http://request3"), std::string(), NetworkAnonymizationKey(), &info3,
      callback3.callback(), &request3, NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_THAT(factory_ptr->pending_requests(), testing::SizeIs(1));
  EXPECT_EQ(kValidPacScript216,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_THAT(resolver.pending_jobs(), testing::SizeIs(1));
  resolver.pending_jobs()[0]->CompleteNow(OK);
  ASSERT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(fetcher_ptr->has_pending_request());
}

TEST_F(ConfiguredProxyResolutionServiceTest, DnsChangeNoopWithoutResolver) {
  ImmediateAfterActivityPollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

  MockAsyncProxyResolver resolver;
  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(ProxyConfig::CreateAutoDetect()),
      std::make_unique<MockAsyncProxyResolverFactory>(
          /*resolvers_expect_pac_bytes=*/true),
      /*net_log=*/nullptr, /*quick_check_enabled=*/true);
  auto fetcher = std::make_unique<MockPacFileFetcher>();
  MockPacFileFetcher* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Expect DNS notification to do nothing because no proxy requests have yet
  // been made.
  NetworkChangeNotifier::NotifyObserversOfDNSChangeForTests();
  RunUntilIdle();
  EXPECT_FALSE(fetcher_ptr->has_pending_request());
}

// Helper class to exercise URL sanitization by submitting URLs to the
// ConfiguredProxyResolutionService and returning the URL passed to the
// ProxyResolver.
class SanitizeUrlHelper {
 public:
  SanitizeUrlHelper() {
    auto config_service =
        std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");
    auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
    auto* factory_ptr = factory.get();
    service_ = std::make_unique<ConfiguredProxyResolutionService>(
        std::move(config_service), std::move(factory), nullptr,
        /*quick_check_enabled=*/true);

    // Do an initial request to initialize the service (configure the PAC
    // script).
    GURL url("http://example.com");

    ProxyInfo info;
    TestCompletionCallback callback;
    std::unique_ptr<ProxyResolutionRequest> request;
    int rv = service_->ResolveProxy(
        url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    // First step is to download the PAC script.
    EXPECT_EQ(GURL("http://foopy/proxy.pac"),
              factory_ptr->pending_requests()[0]->script_data()->url());
    factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

    EXPECT_EQ(1u, resolver.pending_jobs().size());
    EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

    // Complete the request.
    resolver.pending_jobs()[0]->results()->UsePacString("DIRECT");
    resolver.pending_jobs()[0]->CompleteNow(OK);
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(info.is_direct());
  }

  // Makes a proxy resolution request through the
  // ConfiguredProxyResolutionService, and returns the URL that was submitted to
  // the Proxy Resolver.
  GURL SanitizeUrl(const GURL& raw_url) {
    // Issue a request and see what URL is sent to the proxy resolver.
    ProxyInfo info;
    TestCompletionCallback callback;
    std::unique_ptr<ProxyResolutionRequest> request1;
    int rv = service_->ResolveProxy(
        raw_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request1, NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    EXPECT_EQ(1u, resolver.pending_jobs().size());

    GURL sanitized_url = resolver.pending_jobs()[0]->url();

    // Complete the request.
    resolver.pending_jobs()[0]->results()->UsePacString("DIRECT");
    resolver.pending_jobs()[0]->CompleteNow(OK);
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(info.is_direct());

    return sanitized_url;
  }

 private:
  MockAsyncProxyResolver resolver;
  std::unique_ptr<ConfiguredProxyResolutionService> service_;
};

// Tests that input URLs to proxy resolution are sanitized before being passed
// on to the ProxyResolver (i.e. PAC script evaluator). For instance PAC
// scripts should not be able to see the path for https:// URLs.
TEST_F(ConfiguredProxyResolutionServiceTest, SanitizeUrlForPacScript) {
  const struct {
    const char* raw_url;
    const char* sanitized_url;
  } kTests[] = {
      // ---------------------------------
      // Sanitize cryptographic URLs.
      // ---------------------------------

      // Embedded identity is stripped.
      {
          "https://foo:bar@example.com/",
          "https://example.com/",
      },
      // Fragments and path are stripped.
      {
          "https://example.com/blah#hello",
          "https://example.com/",
      },
      // Query is stripped.
      {
          "https://example.com/?hello",
          "https://example.com/",
      },
      // The embedded identity and fragment are stripped.
      {
          "https://foo:bar@example.com/foo/bar/baz?hello#sigh",
          "https://example.com/",
      },
      // The URL's port should not be stripped.
      {
          "https://example.com:88/hi",
          "https://example.com:88/",
      },
      // Try a wss:// URL, to make sure it is treated as a cryptographic schemed
      // URL.
      {
          "wss://example.com:88/hi",
          "wss://example.com:88/",
      },

      // ---------------------------------
      // Sanitize non-cryptographic URLs.
      // ---------------------------------

      // Embedded identity is stripped.
      {
          "http://foo:bar@example.com/",
          "http://example.com/",
      },
      {
          "ftp://foo:bar@example.com/",
          "ftp://example.com/",
      },
      {
          "ftp://example.com/some/path/here",
          "ftp://example.com/some/path/here",
      },
      // Reference fragment is stripped.
      {
          "http://example.com/blah#hello",
          "http://example.com/blah",
      },
      // Query parameters are NOT stripped.
      {
          "http://example.com/foo/bar/baz?hello",
          "http://example.com/foo/bar/baz?hello",
      },
      // Fragment is stripped, but path and query are left intact.
      {
          "http://foo:bar@example.com/foo/bar/baz?hello#sigh",
          "http://example.com/foo/bar/baz?hello",
      },
      // Port numbers are not affected.
      {
          "http://example.com:88/hi",
          "http://example.com:88/hi",
      },
  };

  SanitizeUrlHelper helper;

  for (const auto& test : kTests) {
    GURL raw_url(test.raw_url);
    ASSERT_TRUE(raw_url.is_valid());

    EXPECT_EQ(GURL(test.sanitized_url), helper.SanitizeUrl(raw_url));
  }
}

TEST_F(ConfiguredProxyResolutionServiceTest, OnShutdownWithLiveRequest) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(true);

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  auto fetcher = std::make_unique<MockPacFileFetcher>();
  auto* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv = service.ResolveProxy(
      GURL("http://request/"), std::string(), NetworkAnonymizationKey(), &info,
      callback.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered download of PAC script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());

  service.OnShutdown();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback.have_result());
  EXPECT_FALSE(fetcher_ptr->has_pending_request());
}

TEST_F(ConfiguredProxyResolutionServiceTest, OnShutdownFollowedByRequest) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(true);

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  auto fetcher = std::make_unique<MockPacFileFetcher>();
  auto* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  service.OnShutdown();

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv = service.ResolveProxy(
      GURL("http://request/"), std::string(), NetworkAnonymizationKey(), &info,
      callback.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(fetcher_ptr->has_pending_request());
  EXPECT_TRUE(info.is_direct());
}

const char* kImplicityBypassedHosts[] = {
    "localhost",
    "localhost.",
    "foo.localhost",
    "127.0.0.1",
    "127.100.0.2",
    "[::1]",
    "169.254.3.2",
    "169.254.100.1",
    "[FE80::8]",
    "[feb8::1]",
};

const char* kUrlSchemes[] = {"http://", "https://", "ftp://"};

TEST_F(ConfiguredProxyResolutionServiceTest,
       ImplicitlyBypassWithManualSettings) {
  // Use manual proxy settings that specify a single proxy for all traffic.
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080");
  config.set_auto_detect(false);

  auto service = ConfiguredProxyResolutionService::CreateFixedForTest(
      ProxyConfigWithAnnotation(config, TRAFFIC_ANNOTATION_FOR_TESTS));

  // A normal request should use the proxy.
  std::unique_ptr<ProxyResolutionRequest> request1;
  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service->ResolveProxy(
      GURL("http://www.example.com"), std::string(), NetworkAnonymizationKey(),
      &info1, callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("[foopy1:8080]", info1.proxy_chain().ToDebugString());

  // Test that localhost and link-local URLs bypass the proxy (independent of
  // the URL scheme).
  for (auto* host : kImplicityBypassedHosts) {
    for (auto* scheme : kUrlSchemes) {
      auto url = GURL(std::string(scheme) + std::string(host));

      std::unique_ptr<ProxyResolutionRequest> request;
      ProxyInfo info;
      TestCompletionCallback callback;
      rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                 &info, callback.callback(), &request,
                                 NetLogWithSource());
      EXPECT_THAT(rv, IsOk());
      EXPECT_TRUE(info.is_direct());
    }
  }
}

// Test that the when using a PAC script (sourced via auto-detect) certain
// localhost names are implicitly bypassed.
TEST_F(ConfiguredProxyResolutionServiceTest, ImplicitlyBypassWithPac) {
  ProxyConfig config;
  config.set_auto_detect(true);

  auto config_service = std::make_unique<MockProxyConfigService>(config);
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(true);
  auto* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  auto fetcher = std::make_unique<MockPacFileFetcher>();
  auto* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Start 1 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://www.google.com"), std::string(), NetworkAnonymizationKey(),
      &info1, callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // This started auto-detect; complete it.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://www.google.com"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Verify that request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());

  // Test that localhost and link-local URLs bypass the use of PAC script
  // (independent of the URL scheme).
  for (auto* host : kImplicityBypassedHosts) {
    for (auto* scheme : kUrlSchemes) {
      auto url = GURL(std::string(scheme) + std::string(host));

      std::unique_ptr<ProxyResolutionRequest> request;
      ProxyInfo info;
      TestCompletionCallback callback;
      rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                &info, callback.callback(), &request,
                                NetLogWithSource());
      EXPECT_THAT(rv, IsOk());
      EXPECT_TRUE(info.is_direct());
    }
  }
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       CastToConfiguredProxyResolutionService) {
  auto config_service =
      std::make_unique<MockProxyConfigService>(ProxyConfig::CreateDirect());

  ConfiguredProxyResolutionService service(
      std::move(config_service),
      std::make_unique<MockAsyncProxyResolverFactory>(false), nullptr,
      /*quick_check_enabled=*/true);

  ConfiguredProxyResolutionService* casted_service = nullptr;
  EXPECT_TRUE(service.CastToConfiguredProxyResolutionService(&casted_service));
  EXPECT_EQ(&service, casted_service);
}

}  // namespace net

"""


```