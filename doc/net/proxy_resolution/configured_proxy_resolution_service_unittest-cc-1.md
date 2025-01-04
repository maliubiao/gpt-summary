Response:
The user wants me to analyze a C++ unit test file for Chromium's networking stack. Specifically, this is part 2 of a 6-part request. I need to summarize the functionality demonstrated in this specific code snippet. The snippet focuses on testing the `ConfiguredProxyResolutionService`'s behavior when using Proxy Auto-Config (PAC) scripts.

Here's a breakdown of the tests present in this part:

1. **`PACInit一次` (PACInitOnce):** Checks that initializing the PAC script happens only once for concurrent requests.
2. **`CallbackDeletesService`:** Tests the scenario where a proxy resolution callback deletes the service itself.
3. **`PAC`:**  A basic test for PAC functionality, verifying that the PAC script is fetched, executed, and the correct proxy is returned.
4. **`PAC_NoIdentityOrHash`:** Ensures that username/password and fragment identifiers are stripped from the URL before being passed to the PAC script.
5. **`PAC_FailoverWithoutDirect`:** Tests proxy failover when the PAC script doesn't include a `DIRECT` option.
6. **`PAC_RuntimeError`:** Verifies the behavior when a PAC script throws a runtime error, resulting in a fallback to DIRECT.
7. **`PAC_FailoverAfterDirect`:** Checks failover scenarios where `DIRECT` is present multiple times within the PAC script's result.
8. **`PAC_ConfigSourcePropagates`:** Confirms that the `ProxyConfigSource` from the `ProxyConfigService` is correctly applied to the `ProxyInfo`.
9. **`ProxyResolverFails`:** Tests the scenario where the `ProxyResolver` fails during `FindProxyForURL()`, leading to a fallback to `DIRECT`.
10. **`ProxyResolverTerminatedDuringRequest`:** Examines the case when the `ProxyResolver` terminates mid-request, causing a fallback to `DIRECT`.
11. **`ProxyResolverTerminatedDuringRequestWithConcurrentRequest`:** Similar to the previous test, but with multiple concurrent requests.
12. **`PacFileFetcherFailsDownloadingMandatoryPac`:**  Checks the behavior when downloading a mandatory PAC script fails.
13. **`ProxyResolverFailsParsingJavaScriptMandatoryPac`:** Tests the case where a mandatory PAC script is downloaded but contains invalid JavaScript.
14. **`ProxyResolverFailsInJavaScriptMandatoryPac`:** Examines the situation where a mandatory PAC script throws a JavaScript error during execution.
15. **`ProxyFallback`:** Tests proxy failover when multiple proxy servers are specified.

Based on these observations, I can now formulate the response.
这个代码片段主要测试了 `ConfiguredProxyResolutionService` 在处理代理自动配置（PAC）脚本时的各种场景。以下是其功能的归纳：

**主要功能：测试 `ConfiguredProxyResolutionService` 如何处理 PAC 脚本相关的代理解析。**

**具体测试点包括：**

1. **PAC 脚本的初始化时机：** 验证对于并发的代理解析请求，PAC 脚本只会初始化一次。这能提升性能，避免重复下载和解析 PAC 文件。
2. **回调函数删除服务实例：** 测试当代理解析的回调函数删除了 `ConfiguredProxyResolutionService` 实例时，服务能否正确处理，避免出现悬空指针等问题。
3. **基本的 PAC 功能：**  测试从指定的 URL 加载 PAC 脚本，并通过执行脚本来获取代理信息的基本流程。
4. **URL 规范化：** 验证传递给 PAC 脚本的 URL 不包含用户名、密码或片段标识符（#hash），以保护用户隐私。
5. **PAC 脚本返回结果的解析和应用：** 测试当 PAC 脚本返回代理列表时，`ConfiguredProxyResolutionService` 如何解析并应用这些代理，包括尝试连接首选代理以及在连接失败时的故障转移逻辑。
6. **没有 `DIRECT` 选项时的故障转移：** 测试当 PAC 脚本返回的代理列表中没有 `DIRECT` 选项时，如果所有代理都连接失败，则不会回退到直连。
7. **PAC 脚本运行时错误的处理：** 测试当 PAC 脚本执行过程中发生 JavaScript 运行时错误时，如果 PAC 配置不是强制性的，则会回退到直连。
8. **`DIRECT` 指令在 PAC 结果中的处理：** 测试 PAC 脚本结果中包含 `DIRECT` 指令时的行为，包括故障转移到 `DIRECT` 以及在 `DIRECT` 连接失败后继续尝试其他代理。
9. **代理配置源的传播：**  验证通过 `ProxyConfigService` 设置的 `ProxyConfigSource` 会被正确地应用到解析后的 `ProxyInfo` 中。
10. **代理解析器失败的处理：** 测试当底层的 `ProxyResolver` 在执行 `FindProxyForURL()` 时失败（例如，JavaScript 运行时错误）的情况，此时会回退到直连。
11. **请求期间代理解析器终止的处理：** 测试当 `ProxyResolver` 在代理解析请求进行中发生致命错误时，`ConfiguredProxyResolutionService` 如何处理，通常会回退到直连。
12. **并发请求期间代理解析器终止的处理：**  与上一点类似，但测试的是有多个并发请求时，如果一个请求导致代理解析器终止，其他请求如何被处理。
13. **下载强制性 PAC 文件失败的处理：** 测试当 PAC 配置被设置为强制性时，如果下载 PAC 文件失败，则代理解析也会失败，不会回退到直连。
14. **解析强制性 PAC 脚本失败的处理：** 测试当 PAC 配置为强制性时，如果下载的 PAC 脚本包含无效的 JavaScript 导致解析失败，代理解析也会失败。
15. **强制性 PAC 脚本执行失败的处理：** 测试当 PAC 配置为强制性时，即使 PAC 脚本下载成功，但在执行过程中发生 JavaScript 错误，代理解析也会失败。
16. **代理故障转移（多代理服务器）：** 测试当配置了多个代理服务器时，如果连接到首选代理失败，则会尝试连接到下一个代理。

**与 JavaScript 的关系及举例：**

PAC 脚本本身就是用 JavaScript 编写的。这个测试文件中的很多测试用例都直接或间接地与 JavaScript 功能有关。

* **PAC 脚本执行:** 测试中会模拟 PAC 脚本的执行结果，例如 `resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy");` 就模拟了 PAC 脚本返回使用名为 "foopy" 的代理服务器。
* **JavaScript 运行时错误:**  `TEST_F(ConfiguredProxyResolutionServiceTest, PAC_RuntimeError)` 就专门测试了当模拟的 PAC 脚本执行失败（即 JavaScript 运行时错误）时的行为。假设 PAC 脚本中存在 `throw "error";` 这样的语句，当执行到这段代码时就会抛出错误，这个测试会验证 `ConfiguredProxyResolutionService` 是否会回退到直连。
* **无效的 JavaScript:** `TEST_F(ConfiguredProxyResolutionServiceTest, ProxyResolverFailsParsingJavaScriptMandatoryPac)` 测试了下载了包含无效 JavaScript 的 PAC 脚本的情况。例如，PAC 文件内容可能是 `syntax error`，这会导致 JavaScript 解析器无法正常解析。

**逻辑推理的假设输入与输出：**

例如，在 `TEST_F(ConfiguredProxyResolutionServiceTest, PAC)` 测试中：

* **假设输入：**
    * `MockProxyConfigService` 返回 PAC 脚本 URL: `http://foopy/proxy.pac`
    * PAC 脚本执行后返回代理服务器: `PROXY foopy:80`
    * 请求的 URL: `http://www.google.com/`
* **预期输出：**
    * `info.is_direct()` 为 `false`
    * `info.proxy_chain().ToDebugString()` 为 `"[foopy:80]"`

在 `TEST_F(ConfiguredProxyResolutionServiceTest, PAC_RuntimeError)` 测试中：

* **假设输入：**
    * `MockProxyConfigService` 返回 PAC 脚本 URL: `http://foopy/proxy.pac`
    * 模拟的 `MockAsyncProxyResolver` 在执行 PAC 脚本时返回 `ERR_PAC_SCRIPT_FAILED`。
    * 请求的 URL: `http://this-causes-js-error/`
* **预期输出：**
    * `info.is_direct()` 为 `true` (由于 PAC 执行错误，回退到直连)

**用户或编程常见的使用错误：**

* **PAC 脚本语法错误：** 用户编写的 PAC 脚本可能存在语法错误，导致 JavaScript 解析失败。这个在 `ProxyResolverFailsParsingJavaScriptMandatoryPac` 测试中有所体现。如果 PAC 是强制性的，这会导致网络请求失败。
* **PAC 脚本运行时错误：** PAC 脚本可能在特定条件下抛出异常，例如访问未定义的变量。`PAC_RuntimeError` 和 `ProxyResolverFailsInJavaScriptMandatoryPac` 测试了这种情况。如果 PAC 不是强制性的，会回退到直连，但如果 PAC 是强制性的，则会导致网络请求失败。
* **配置了强制性 PAC 但 PAC 文件不可用或下载失败：** `PacFileFetcherFailsDownloadingMandatoryPac` 测试了这种情况。用户可能会错误地配置了强制性的 PAC URL，但该 URL 对应的文件不存在或者网络连接有问题导致下载失败。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器或应用程序中发起网络请求 (例如，访问 `http://www.google.com/`)。**
2. **系统检查代理设置。** 如果配置了使用 PAC 脚本，则会进入代理解析流程。
3. **`ConfiguredProxyResolutionService` 接收到代理解析请求。**
4. **如果 PAC 脚本尚未初始化，则会发起 PAC 脚本的下载请求。**
5. **下载完成后，PAC 脚本会被解析并执行。**
6. **PAC 脚本的 `FindProxyForURL()` 函数会被调用，传入请求的 URL。**
7. **`FindProxyForURL()` 函数返回代理服务器列表或 `DIRECT`。**
8. **`ConfiguredProxyResolutionService` 根据 PAC 脚本的返回结果，尝试连接指定的代理服务器。**

如果调试过程中发现代理解析出现问题，例如连接到了错误的代理，或者无法连接到任何代理，可以查看网络日志 (chrome://net-export/)，其中会记录 `ConfiguredProxyResolutionService` 的详细操作，包括 PAC 脚本的下载、执行结果等信息，从而定位问题。 观察日志中 `PROXY_RESOLUTION_SERVICE` 相关的事件可以帮助理解 `ConfiguredProxyResolutionService` 的行为。

**归纳功能：**

这段代码主要测试了 `ConfiguredProxyResolutionService` 在处理各种与 PAC 脚本相关的场景时的正确性和健壮性。它涵盖了 PAC 脚本的加载、解析、执行、错误处理以及与并发请求的交互等方面，确保在各种复杂的网络配置下，代理解析服务能够按照预期工作。

Prompt: 
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
XPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request->GetLoadState());

    ASSERT_EQ(1u, factory_ptr->pending_requests().size());
    EXPECT_EQ(GURL("http://foopy/proxy.pac"),
              factory_ptr->pending_requests()[0]->script_data()->url());
    factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
    ASSERT_EQ(1u, resolver.pending_jobs().size());
  }

  ASSERT_EQ(0u, resolver.pending_jobs().size());

  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Test that the ConfiguredProxyResolutionService correctly handles the case
// where a request callback deletes the service.
TEST_F(ConfiguredProxyResolutionServiceTest, CallbackDeletesService) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");
  auto* config_service_ptr = config_service.get();

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);

  std::unique_ptr<ConfiguredProxyResolutionService> service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::move(config_service), std::move(factory), nullptr,
          /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;

  DeletingCallback<ConfiguredProxyResolutionService> callback(&service);
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                 &info, callback.callback(), &request1,
                                 NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request1->GetLoadState());

  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                             &info, callback2.callback(), &request2,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service->ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                             &info, callback3.callback(), &request3,
                             NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  config_service_ptr->SetConfig(ProxyConfigWithAnnotation(
      ProxyConfig::CreateDirect(), TRAFFIC_ANNOTATION_FOR_TESTS));

  ASSERT_EQ(0u, resolver.pending_jobs().size());
  ASSERT_THAT(callback.WaitForResult(), IsOk());
  ASSERT_THAT(callback2.WaitForResult(), IsOk());
  ASSERT_THAT(callback3.WaitForResult(), IsOk());
}

TEST_F(ConfiguredProxyResolutionServiceTest, PAC) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  RecordingNetLogObserver net_log_observer;

  int rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                                &info, callback.callback(), &request,
                                NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request->GetLoadState());

  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy:80]", info.proxy_chain().ToDebugString());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // Check the NetLog was filled correctly.
  auto entries = net_log_observer.GetEntries();

  EXPECT_EQ(5u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::PROXY_RESOLUTION_SERVICE));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1,
      NetLogEventType::PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2,
      NetLogEventType::PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC));
  EXPECT_TRUE(LogContainsEndEvent(entries, 4,
                                  NetLogEventType::PROXY_RESOLUTION_SERVICE));
}

// Test that the proxy resolver does not see the URL's username/password
// or its reference section.
TEST_F(ConfiguredProxyResolutionServiceTest, PAC_NoIdentityOrHash) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://username:password@www.google.com/?ref#hash#hash");

  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  // The URL should have been simplified, stripping the username/password/hash.
  EXPECT_EQ(GURL("http://www.google.com/?ref"),
            resolver.pending_jobs()[0]->url());

  // We end here without ever completing the request -- destruction of
  // ConfiguredProxyResolutionService will cancel the outstanding request.
}

TEST_F(ConfiguredProxyResolutionServiceTest, PAC_FailoverWithoutDirect) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy:8080]", info.proxy_chain().ToDebugString());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // Now, imagine that connecting to foopy:8080 fails: there is nothing
  // left to fallback to, since our proxy list was NOT terminated by
  // DIRECT.
  EXPECT_FALSE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_TRUE(info.is_empty());
}

// Test that if the execution of the PAC script fails (i.e. javascript runtime
// error), and the PAC settings are non-mandatory, that we fall-back to direct.
TEST_F(ConfiguredProxyResolutionServiceTest, PAC_RuntimeError) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://this-causes-js-error/");

  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Simulate a failure in the PAC executor.
  resolver.pending_jobs()[0]->CompleteNow(ERR_PAC_SCRIPT_FAILED);

  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  // Since the PAC script was non-mandatory, we should have fallen-back to
  // DIRECT.
  EXPECT_TRUE(info.is_direct());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
}

// The proxy list could potentially contain the DIRECT fallback choice
// in a location other than the very end of the list, and could even
// specify it multiple times.
//
// This is not a typical usage, but we will obey it.
// (If we wanted to disallow this type of input, the right place to
// enforce it would be in parsing the PAC result string).
//
// This test will use the PAC result string:
//
//   "DIRECT ; PROXY foobar:10 ; DIRECT ; PROXY foobar:20"
//
// For which we expect it to try DIRECT, then foobar:10, then DIRECT again,
// then foobar:20, and then give up and error.
//
// The important check of this test is to make sure that DIRECT is not somehow
// cached as being a bad proxy.
TEST_F(ConfiguredProxyResolutionServiceTest, PAC_FailoverAfterDirect) {
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request1, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UsePacString(
      "DIRECT ; PROXY foobar:10 ; DIRECT ; PROXY foobar:20");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Fallback 1.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foobar:10]", info.proxy_chain().ToDebugString());

  // Fallback 2.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_TRUE(info.is_direct());

  // Fallback 3.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foobar:20]", info.proxy_chain().ToDebugString());

  // Fallback 4 -- Nothing to fall back to!
  EXPECT_FALSE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_TRUE(info.is_empty());
}

TEST_F(ConfiguredProxyResolutionServiceTest, PAC_ConfigSourcePropagates) {
  // Test whether the ProxyConfigSource set by the ProxyConfigService is applied
  // to ProxyInfo after the proxy is resolved via a PAC script.
  ProxyConfig config =
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac"));

  auto config_service = std::make_unique<MockProxyConfigService>(config);
  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Resolve something.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback.callback(), &request, NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS),
            info.traffic_annotation());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
}

TEST_F(ConfiguredProxyResolutionServiceTest, ProxyResolverFails) {
  // Test what happens when the ProxyResolver fails. The download and setting
  // of the PAC script have already succeeded, so this corresponds with a
  // javascript runtime error while calling FindProxyForURL().

  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Fail the first resolve request in MockAsyncProxyResolver.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // Although the proxy resolver failed the request,
  // ConfiguredProxyResolutionService implicitly falls-back to DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Failed PAC executions still have proxy resolution times.
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // The second resolve request will try to run through the proxy resolver,
  // regardless of whether the first request failed in it.
  TestCompletionCallback callback2;
  rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback2.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time we will have the resolver succeed (perhaps the PAC script has
  // a dependency on the current time).
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy_valid:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy_valid:8080]", info.proxy_chain().ToDebugString());
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       ProxyResolverTerminatedDuringRequest) {
  // Test what happens when the ProxyResolver fails with a fatal error while
  // a GetProxyForURL() call is in progress.

  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Fail the first resolve request in MockAsyncProxyResolver.
  resolver.pending_jobs()[0]->CompleteNow(ERR_PAC_SCRIPT_TERMINATED);

  // Although the proxy resolver failed the request,
  // ConfiguredProxyResolutionService implicitly falls-back to DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Failed PAC executions still have proxy resolution times.
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // With no other requests, the ConfiguredProxyResolutionService waits for a
  // new request before initializing a new ProxyResolver.
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  TestCompletionCallback callback2;
  rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback2.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time we will have the resolver succeed.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy_valid:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy_valid:8080]", info.proxy_chain().ToDebugString());
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       ProxyResolverTerminatedDuringRequestWithConcurrentRequest) {
  // Test what happens when the ProxyResolver fails with a fatal error while
  // a GetProxyForURL() call is in progress.

  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start two resolve requests.
  GURL url1("http://www.google.com/");
  GURL url2("https://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1, request2;
  int rv = service.ResolveProxy(url1, std::string(), NetworkAnonymizationKey(),
                                &info, callback1.callback(), &request1,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                            &info, callback2.callback(), &request2,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2);

  // Fail the first resolve request in MockAsyncProxyResolver.
  jobs[url1]->CompleteNow(ERR_PAC_SCRIPT_TERMINATED);

  // Although the proxy resolver failed the request,
  // ConfiguredProxyResolutionService implicitly falls-back to DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Failed PAC executions still have proxy resolution times.
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // The second request is cancelled when the proxy resolver terminates.
  jobs = GetCancelledJobsForURLs(resolver, url2);

  // Since a second request was in progress, the
  // ConfiguredProxyResolutionService starts initializating a new ProxyResolver.
  ASSERT_EQ(1u, factory_ptr->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  jobs = GetPendingJobsForURLs(resolver, url2);

  // This request succeeds.
  jobs[url2]->results()->UseNamedProxy("foopy_valid:8080");
  jobs[url2]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy_valid:8080]", info.proxy_chain().ToDebugString());
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       PacFileFetcherFailsDownloadingMandatoryPac) {
  // Test what happens when the ProxyResolver fails to download a mandatory PAC
  // script.

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));
  config.set_pac_mandatory(true);

  auto config_service = std::make_unique<MockProxyConfigService>(config);

  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNow(ERR_FAILED, nullptr);

  ASSERT_EQ(0u, factory_ptr->pending_requests().size());
  // As the proxy resolver factory failed the request and is configured for a
  // mandatory PAC script, ConfiguredProxyResolutionService must not implicitly
  // fall-back to DIRECT.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback1.WaitForResult());
  EXPECT_FALSE(info.is_direct());

  // As the proxy resolver factory failed the request and is configured for a
  // mandatory PAC script, ConfiguredProxyResolutionService must not implicitly
  // fall-back to DIRECT.
  TestCompletionCallback callback2;
  rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback2.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
  EXPECT_FALSE(info.is_direct());
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       ProxyResolverFailsParsingJavaScriptMandatoryPac) {
  // Test what happens when the ProxyResolver fails that is configured to use a
  // mandatory PAC script. The download of the PAC script has already
  // succeeded but the PAC script contains no valid javascript.

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));
  config.set_pac_mandatory(true);

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

  // Start resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // Downloading the PAC script succeeds.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, "invalid-script-contents");

  EXPECT_FALSE(fetcher_ptr->has_pending_request());
  ASSERT_EQ(0u, factory_ptr->pending_requests().size());

  // Since PacFileDecider failed to identify a valid PAC and PAC was
  // mandatory for this configuration, the ConfiguredProxyResolutionService must
  // not implicitly fall-back to DIRECT.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED, callback.WaitForResult());
  EXPECT_FALSE(info.is_direct());
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       ProxyResolverFailsInJavaScriptMandatoryPac) {
  // Test what happens when the ProxyResolver fails that is configured to use a
  // mandatory PAC script. The download and setting of the PAC script have
  // already succeeded, so this corresponds with a javascript runtime error
  // while calling FindProxyForURL().

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));
  config.set_pac_mandatory(true);

  auto config_service = std::make_unique<MockProxyConfigService>(config);

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Fail the first resolve request in MockAsyncProxyResolver.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // As the proxy resolver failed the request and is configured for a mandatory
  // PAC script, ConfiguredProxyResolutionService must not implicitly fall-back
  // to DIRECT.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback1.WaitForResult());
  EXPECT_FALSE(info.is_direct());

  // The second resolve request will try to run through the proxy resolver,
  // regardless of whether the first request failed in it.
  TestCompletionCallback callback2;
  rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback2.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time we will have the resolver succeed (perhaps the PAC script has
  // a dependency on the current time).
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy_valid:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy_valid:8080]", info.proxy_chain().ToDebugString());
}

TEST_F(ConfiguredProxyResolutionServiceTest, ProxyFallback) {
  // Test what happens when we specify multiple proxy servers and some of them
  // are bad.

  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  GURL url("http://www.google.com/");

  // Get the proxy information.
  ProxyInfo info;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request;
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callbac
"""


```