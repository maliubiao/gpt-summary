Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test for `ConfiguredProxyResolutionService` in Chromium's networking stack.

Here's a breakdown of how to address each point:

1. **Functionality:**  The code snippet tests various scenarios related to how `ConfiguredProxyResolutionService` handles proxy configurations, especially those involving Proxy Auto-Config (PAC) files. It checks how the service behaves when:
    * PAC file download is in progress.
    * The PAC file fetcher is changed mid-download.
    * Requests are cancelled during PAC file fetching.
    * There's a fallback mechanism from auto-detection to a custom PAC URL.
    * There's a fallback mechanism from auto-detection to custom PAC to manual proxy settings.
    * Bypass rules are handled in conjunction with PAC.
    * The service is deleted during asynchronous operations (PAC fetch or proxy resolution).
    * The proxy configuration changes from requiring PAC to direct connection.
    * Network changes trigger PAC file refetch.
    * PAC script refetch occurs after an initial failure.

2. **Relationship with JavaScript:** PAC files are essentially JavaScript code that determines the proxy server to use for a given URL. The tests here indirectly relate to JavaScript functionality by ensuring the correct retrieval and application of these JavaScript-based proxy configurations. An example would be testing that a specific JavaScript function within the PAC script is correctly invoked.

3. **Logical Reasoning (Input/Output):**  Many of the tests involve setting up specific proxy configurations and network states, then making proxy resolution requests. The expected output is usually the `ProxyInfo` object containing the resolved proxy chain. I can illustrate this with a simple case.

4. **User/Programming Errors:** Common errors include incorrect PAC script syntax, wrong proxy server settings, or network issues preventing PAC file download. I can provide examples based on the tests.

5. **User Operations:** To reach this code, a user would typically be interacting with their browser, and the browser's network stack would be handling proxy resolution in the background. I can describe the steps.

6. **Overall Functionality Summary (Part 4):**  The provided snippet focuses on complex scenarios involving PAC file handling, particularly the robustness of the `ConfiguredProxyResolutionService` in the face of asynchronous operations, configuration changes, and network events. It emphasizes testing fallback mechanisms and proper resource management.

**Mental Sandbox:**

* **Scenario: Changing PacFileFetcher:** The code sets up a scenario where a PAC download is initiated, then the fetcher is replaced. The expectation is that the download restarts with the new fetcher.
* **Scenario: Fallback from Autodetect:** The code simulates a failure in auto-detecting the PAC file and checks that the service correctly falls back to the configured PAC URL.
* **JavaScript Relation:**  I need to make the connection between PAC scripts being JavaScript and the test verifying the service correctly uses the *results* of evaluating that JavaScript.
* **User Error Example:**  A user might manually enter an incorrect PAC URL in their browser settings. This could lead to download failures tested here.

Strategizing complete. I will now generate the response by elaborating on these points.
这是 `net/proxy_resolution/configured_proxy_resolution_service_unittest.cc` 文件的第 4 部分，延续了前几部分的功能，主要关注 `ConfiguredProxyResolutionService` 类在处理代理配置和解析过程中的各种复杂场景。

**归纳一下它的功能 (基于提供的代码片段):**

这部分主要测试了 `ConfiguredProxyResolutionService` 在以下情况下的行为：

* **动态更换 PAC 文件获取器:** 测试在 PAC 文件下载进行中更换 `PacFileFetcher` 时，服务是否能够正确地重新开始初始化过程。
* **取消正在获取 PAC 文件的请求:**  验证当 PAC 文件正在下载时，取消代理解析请求是否能够正确地释放资源并停止相关的操作。
* **从自动检测回退到自定义 PAC 文件:**  测试当代理自动检测失败后，服务是否能够正确地回退到使用用户指定的 PAC 文件。这包括了下载失败和脚本内容校验失败两种情况。
* **多级回退机制 (自动检测 -> 自定义 PAC -> 手动配置):**  验证当自动检测和自定义 PAC 文件都不可用时，服务是否能够最终回退到使用手动配置的代理设置。
* **Bypass 规则与 PAC 的交互:**  确认在使用 PAC 文件时，bypass 规则是否不会被应用，代理决策完全由 PAC 脚本决定。
* **在异步操作中删除服务:**  测试在 `InitProxyResolver` 仍在进行 PAC 文件获取或代理解析时，删除 `ConfiguredProxyResolutionService` 是否会导致内存错误。
* **配置更新 (从 PAC 到直接连接):**  验证当代理配置从需要 PAC 文件变为直接连接时，服务是否能够正确地清理状态，不再使用代理解析器。
* **网络变化触发 PAC 文件重新获取:**  测试当网络发生变化时，即使代理配置没有改变，服务也会重新获取 PAC 文件。
* **PAC 文件获取失败后的重试机制:** 验证在首次获取 PAC 文件失败后，服务会根据策略定期重试获取。

**与 Javascript 的功能关系及举例说明:**

PAC (Proxy Auto-Config) 文件本质上是 Javascript 代码。`ConfiguredProxyResolutionService` 的核心功能之一就是获取并执行这些 Javascript 代码来决定给定 URL 应该使用哪个代理服务器（或直接连接）。

**举例说明:**

假设 `kValidPacScript1` 中包含以下 Javascript 函数：

```javascript
function FindProxyForURL(url, host) {
  if (host == "www.example.com") {
    return "PROXY proxy1:80; PROXY proxy2:80";
  }
  return "DIRECT";
}
```

`ConfiguredProxyResolutionService` 的功能就是获取这个脚本，然后对于 `http://www.example.com` 的请求，它会调用 `FindProxyForURL` 函数，并根据返回的 `"PROXY proxy1:80; PROXY proxy2:80"` 来设置 `ProxyInfo`。

测试用例如 `Basic` 中，通过断言 `EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());` 来验证 PAC 脚本的执行结果是否符合预期。

**逻辑推理，假设输入与输出:**

**假设输入:**

* **URL:** `http://www.example.com`
* **PAC 脚本内容 (`kValidPacScript1`):**
  ```javascript
  function FindProxyForURL(url, host) {
    if (host == "www.example.com") {
      return "PROXY myproxy:80";
    }
    return "DIRECT";
  }
  ```

**输出:**

`ProxyInfo` 对象的 `proxy_chain().ToDebugString()` 将会是 `"[myproxy:80]"`.

**涉及用户或者编程常见的使用错误，举例说明:**

* **用户错误:**
    * **输入错误的 PAC 文件 URL:**  如果用户在浏览器或操作系统设置中输入了一个不存在或无法访问的 PAC 文件 URL (`http://invalid.example.com/proxy.pac`)，那么 `ConfiguredProxyResolutionService` 在尝试下载时会遇到错误，这正是测试用例中模拟的场景，例如 `PACScriptRefetchAfterFailure`。
    * **PAC 脚本语法错误:** 用户可能配置了一个包含语法错误的 PAC 文件。虽然测试用例主要关注下载和回退逻辑，但 `MockAsyncProxyResolverFactory` 会模拟解析 PAC 脚本的过程，如果脚本有严重错误，解析会失败。

* **编程错误:**
    * **资源泄漏:**  如果 `ConfiguredProxyResolutionService` 在异步操作中没有正确管理资源，例如在 PAC 文件下载过程中被删除，可能导致内存泄漏。测试用例 `DeleteWhileInitProxyResolverHasOutstandingFetch` 和 `DeleteWhileInitProxyResolverHasOutstandingSet` 就是为了防止这类错误。
    * **状态管理错误:** 在配置更新或网络变化时，如果没有正确更新内部状态，可能导致使用过期的 PAC 脚本或错误的代理设置。例如，`UpdateConfigFromPACToDirect` 检查了从使用 PAC 脚本切换到直接连接时，服务是否正确停止使用代理解析器。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户更改操作系统或浏览器的代理设置:** 用户可能会手动配置 PAC 文件的 URL，选择自动检测代理设置，或者设置固定的代理服务器。这些操作会影响到系统或浏览器底层的网络栈配置。
2. **应用程序 (例如 Chrome 浏览器) 获取代理配置:**  当应用程序需要建立网络连接时，它会查询系统的代理配置。在 Chromium 中，`ProxyConfigService` 负责获取这些配置信息。
3. **`ConfiguredProxyResolutionService` 初始化:**  `ConfiguredProxyResolutionService` 接收来自 `ProxyConfigService` 的代理配置信息，并根据配置类型（例如，使用 PAC 文件）初始化相应的组件，例如 `PacFileFetcher` 和 `ProxyResolver`。
4. **发起网络请求:** 当用户在浏览器中输入一个 URL 或应用程序尝试连接到网络时，会触发一个网络请求。
5. **代理解析:**  `ConfiguredProxyResolutionService` 接收到网络请求的 URL，并根据当前的代理配置进行代理解析。如果配置了 PAC 文件，它会请求 `PacFileFetcher` 下载 PAC 文件（如果尚未下载），然后使用 `ProxyResolver` 执行 PAC 脚本来确定代理服务器。
6. **测试用例模拟上述步骤:** `configured_proxy_resolution_service_unittest.cc` 中的测试用例通过模拟 `MockProxyConfigService` 和 `MockPacFileFetcher` 等组件，来模拟用户操作和网络请求的各个阶段，并验证 `ConfiguredProxyResolutionService` 在这些阶段的行为是否正确。

作为调试线索，当网络请求的代理设置出现问题时，开发人员可能会：

* **查看网络日志 (NetLog):** Chromium 提供了 NetLog 功能，可以记录网络请求的详细信息，包括代理解析的各个阶段，可以查看是否成功获取 PAC 文件，PAC 脚本的执行结果等。测试用例中也使用了 `RecordingNetLogObserver` 来验证日志输出是否符合预期。
* **单步调试 `ConfiguredProxyResolutionService`:**  开发人员可以使用调试器逐步执行 `ConfiguredProxyResolutionService` 的代码，查看其内部状态和执行流程，特别是在处理 PAC 文件下载和解析的逻辑中。测试用例可以帮助开发人员复现问题场景。
* **检查代理配置:**  确认系统或浏览器的代理配置是否正确，PAC 文件 URL 是否可访问等。

总而言之，这部分测试用例深入探讨了 `ConfiguredProxyResolutionService` 在处理基于 PAC 文件的代理配置时的各种复杂情况，确保了网络栈在不同场景下的稳定性和正确性。

Prompt: 
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
d_time());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
  EXPECT_FALSE(info2.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info2.proxy_resolve_end_time().is_null());
  EXPECT_LE(info2.proxy_resolve_start_time(), info2.proxy_resolve_end_time());

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ("[request3:80]", info3.proxy_chain().ToDebugString());
  EXPECT_FALSE(info3.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info3.proxy_resolve_end_time().is_null());
  EXPECT_LE(info3.proxy_resolve_start_time(), info3.proxy_resolve_end_time());
}

// Test changing the PacFileFetcher while PAC download is in progress.
TEST_F(ConfiguredProxyResolutionServiceTest,
       ChangeScriptFetcherWhilePACDownloadInProgress) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

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

  // Start 2 jobs.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(url1, std::string(), NetworkAnonymizationKey(),
                                &info1, callback1.callback(), &request1,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered download of PAC script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());

  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                            &info2, callback2.callback(), &request2,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // At this point the ConfiguredProxyResolutionService should be waiting for
  // the PacFileFetcher to invoke its completion callback, notifying it of PAC
  // script download completion.

  // We now change out the ConfiguredProxyResolutionService's script fetcher. We
  // should restart the initialization with the new fetcher.

  fetcher = std::make_unique<MockPacFileFetcher>();
  fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, it will have been sent to the proxy
  // resolver.
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  GetPendingJobsForURLs(resolver, url1, url2);
}

// Test cancellation of a request, while the PAC script is being fetched.
TEST_F(ConfiguredProxyResolutionServiceTest, CancelWhilePACFetching) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

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

  // Start 3 requests.
  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  RecordingNetLogObserver net_log_observer;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(),
                                NetworkAnonymizationKey(), &info1,
                                callback1.callback(), &request1,
                                NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered download of PAC script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());

  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info3;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(
      GURL("http://request3"), std::string(), NetworkAnonymizationKey(), &info3,
      callback3.callback(), &request3, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  // Cancel the first 2 jobs.
  request1.reset();
  request2.reset();

  // At this point the ConfiguredProxyResolutionService should be waiting for
  // the PacFileFetcher to invoke its completion callback, notifying it of PAC
  // script download completion.
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, it will have been sent to the
  // proxy resolver.
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request3"), resolver.pending_jobs()[0]->url());

  // Complete all the jobs.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request3:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ("[request3:80]", info3.proxy_chain().ToDebugString());

  EXPECT_TRUE(resolver.cancelled_jobs().empty());

  EXPECT_FALSE(callback1.have_result());  // Cancelled.
  EXPECT_FALSE(callback2.have_result());  // Cancelled.

  auto entries1 = net_log_observer.GetEntries();

  // Check the NetLog for request 1 (which was cancelled) got filled properly.
  EXPECT_EQ(4u, entries1.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries1, 0,
                                    NetLogEventType::PROXY_RESOLUTION_SERVICE));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries1, 1,
      NetLogEventType::PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC));
  // Note that PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC is never completed
  // before the cancellation occured.
  EXPECT_TRUE(LogContainsEvent(entries1, 2, NetLogEventType::CANCELLED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(entries1, 3,
                                  NetLogEventType::PROXY_RESOLUTION_SERVICE));
}

// Test that if auto-detect fails, we fall-back to the custom pac.
TEST_F(ConfiguredProxyResolutionServiceTest,
       FallbackFromAutodetectToCustomPac) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");  // Won't be used.

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

  // Start 2 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(url1, std::string(), NetworkAnonymizationKey(),
                                &info1, callback1.callback(), &request1,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                            &info2, callback2.callback(), &request2,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // It should be trying to auto-detect first -- FAIL the autodetect during
  // the script download.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Next it should be trying the custom PAC url.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // Now finally, the pending jobs should have been sent to the resolver
  // (which was initialized with custom PAC script).

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2);

  // Complete the pending jobs.
  jobs[url2]->results()->UseNamedProxy("request2:80");
  jobs[url2]->CompleteNow(OK);
  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  // Verify that jobs ran as expected.
  EXPECT_EQ(OK, callback1.WaitForResult());
  // ProxyResolver::GetProxyForURL() to take a std::unique_ptr<Request>* rather
  // than a RequestHandle* (patchset #11 id:200001 of
  // https://codereview.chromium.org/1439053002/ )
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());
  EXPECT_FALSE(info1.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info1.proxy_resolve_end_time().is_null());
  EXPECT_LE(info1.proxy_resolve_start_time(), info1.proxy_resolve_end_time());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
  EXPECT_FALSE(info2.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info2.proxy_resolve_end_time().is_null());
  EXPECT_LE(info2.proxy_resolve_start_time(), info2.proxy_resolve_end_time());
}

// This is the same test as FallbackFromAutodetectToCustomPac, except
// the auto-detect script fails parsing rather than downloading.
TEST_F(ConfiguredProxyResolutionServiceTest,
       FallbackFromAutodetectToCustomPac2) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");  // Won't be used.

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

  // Start 2 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(url1, std::string(), NetworkAnonymizationKey(),
                                &info1, callback1.callback(), &request1,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                            &info2, callback2.callback(), &request2,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // It should be trying to auto-detect first -- succeed the download.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, "invalid-script-contents");

  // The script contents passed failed basic verification step (since didn't
  // contain token FindProxyForURL), so it was never passed to the resolver.

  // Next it should be trying the custom PAC url.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // Now finally, the pending jobs should have been sent to the resolver
  // (which was initialized with custom PAC script).

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2);

  // Complete the pending jobs.
  jobs[url2]->results()->UseNamedProxy("request2:80");
  jobs[url2]->CompleteNow(OK);
  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  // Verify that jobs ran as expected.
  EXPECT_EQ(OK, callback1.WaitForResult());
  // ProxyResolver::GetProxyForURL() to take a std::unique_ptr<Request>* rather
  // than a RequestHandle* (patchset #11 id:200001 of
  // https://codereview.chromium.org/1439053002/ )
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
}

// Test that if all of auto-detect, a custom PAC script, and manual settings
// are given, then we will try them in that order.
TEST_F(ConfiguredProxyResolutionServiceTest,
       FallbackFromAutodetectToCustomToManual) {
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");

  auto config_service = std::make_unique<MockProxyConfigService>(config);
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(true);
  auto* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  auto fetcher = std::make_unique<MockPacFileFetcher>();
  auto* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Start 2 jobs.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://request1"), std::string(), NetworkAnonymizationKey(), &info1,
      callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // It should be trying to auto-detect first -- fail the download.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Next it should be trying the custom PAC url -- fail the download.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Since we never managed to initialize a resolver, nothing should have been
  // sent to it.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // Verify that jobs ran as expected -- they should have fallen back to
  // the manual proxy configuration for HTTP urls.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("[foopy:80]", info1.proxy_chain().ToDebugString());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[foopy:80]", info2.proxy_chain().ToDebugString());
}

// Test that the bypass rules are NOT applied when using autodetect.
TEST_F(ConfiguredProxyResolutionServiceTest, BypassDoesntApplyToPac) {
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");  // Not used.
  config.proxy_rules().bypass_rules.ParseFromString("www.google.com");

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

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // It should be trying to auto-detect first -- succeed the download.
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

  // Start another request, it should pickup the bypass item.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://www.google.com"), std::string(), NetworkAnonymizationKey(),
      &info2, callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://www.google.com"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
}

// Delete the ConfiguredProxyResolutionService while InitProxyResolver has an
// outstanding request to the script fetcher. When run under valgrind, should
// not have any memory errors (used to be that the PacFileFetcher was being
// deleted prior to the InitProxyResolver).
TEST_F(ConfiguredProxyResolutionServiceTest,
       DeleteWhileInitProxyResolverHasOutstandingFetch) {
  ProxyConfig config =
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac"));

  auto config_service = std::make_unique<MockProxyConfigService>(config);
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(true);
  auto* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  auto fetcher = std::make_unique<MockPacFileFetcher>();
  auto* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://www.google.com"), std::string(), NetworkAnonymizationKey(),
      &info1, callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // InitProxyResolver should have issued a request to the PacFileFetcher
  // and be waiting on that to complete.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
}

// Delete the ConfiguredProxyResolutionService while InitProxyResolver has an
// outstanding request to the proxy resolver. When run under valgrind, should
// not have any memory errors (used to be that the ProxyResolver was being
// deleted prior to the InitProxyResolver).
TEST_F(ConfiguredProxyResolutionServiceTest,
       DeleteWhileInitProxyResolverHasOutstandingSet) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
}

// Test that when going from a configuration that required PAC to one
// that does NOT, we unset the variable |should_use_proxy_resolver_|.
TEST_F(ConfiguredProxyResolutionServiceTest, UpdateConfigFromPACToDirect) {
  ProxyConfig config = ProxyConfig::CreateAutoDetect();

  auto config_service = std::make_unique<MockProxyConfigService>(config);
  auto* config_service_ptr = config_service.get();
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://www.google.com"), std::string(), NetworkAnonymizationKey(),
      &info1, callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Successfully set the autodetect script.
  EXPECT_EQ(PacFileData::TYPE_AUTO_DETECT,
            factory_ptr->pending_requests()[0]->script_data()->type());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // Complete the pending request.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Verify that request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());

  // Force the ConfiguredProxyResolutionService to pull down a new proxy
  // configuration. (Even though the configuration isn't old/bad).
  //
  // This new configuration no longer has auto_detect set, so
  // jobs should complete synchronously now as direct-connect.
  config_service_ptr->SetConfig(ProxyConfigWithAnnotation::CreateDirect());

  // Start another request -- the effective configuration has changed.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://www.google.com"), std::string(), NetworkAnonymizationKey(),
      &info2, callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(info2.is_direct());
}

TEST_F(ConfiguredProxyResolutionServiceTest, NetworkChangeTriggersPacRefetch) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(true);
  auto* factory_ptr = factory.get();

  RecordingNetLogObserver observer;

  ConfiguredProxyResolutionService service(
      std::move(config_service), std::move(factory), net::NetLog::Get(),
      /*quick_check_enabled=*/true);

  auto fetcher = std::make_unique<MockPacFileFetcher>();
  auto* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Disable the "wait after IP address changes" hack, so this unit-test can
  // complete quickly.
  service.set_stall_proxy_auto_config_delay(base::TimeDelta());

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://request1"), std::string(), NetworkAnonymizationKey(), &info1,
      callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  // At this point the ConfiguredProxyResolutionService should be waiting for
  // the PacFileFetcher to invoke its completion callback, notifying it of PAC
  // script download completion.
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, the request will have been sent to
  // the proxy resolver.
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request1"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());

  // Now simluate a change in the network. The ProxyConfigService is still
  // going to return the same PAC URL as before, but this URL needs to be
  // refetched on the new network.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // This second request should have triggered the re-download of the PAC
  // script (since we marked the network as having changed).
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  // Simulate the PAC script fetch as having completed (this time with
  // different data).
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript2);

  // Now that the PAC script is downloaded, the second request will have been
  // sent to the proxy resolver.
  EXPECT_EQ(kValidPacScript216,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());

  // Check that the expected events were output to the log stream. In particular
  // PROXY_CONFIG_CHANGED should have only been emitted once (for the initial
  // setup), and NOT a second time when the IP address changed.
  auto entries = observer.GetEntries();

  EXPECT_TRUE(LogContainsEntryWithType(entries, 0,
                                       NetLogEventType::PROXY_CONFIG_CHANGED));
  ASSERT_EQ(9u, entries.size());
  for (size_t i = 1; i < entries.size(); ++i)
    EXPECT_NE(NetLogEventType::PROXY_CONFIG_CHANGED, entries[i].type);
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch fails due
// to a network error, we will eventually re-configure the service to use the
// script once it becomes available.
TEST_F(ConfiguredProxyResolutionServiceTest, PACScriptRefetchAfterFailure) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

  auto config_service =
      std::make_unique
"""


```