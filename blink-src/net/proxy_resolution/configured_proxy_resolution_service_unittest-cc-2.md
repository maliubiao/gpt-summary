Response:
The user wants a summary of the provided C++ code snippet from Chromium's networking stack. I need to explain its functionality, focusing on the following:

1. **Core Functionality:** What does this code do?
2. **JavaScript Relationship:** Does it interact with JavaScript? If so, how?
3. **Logical Inference:** Are there examples of input and output based on the code's logic?
4. **User/Programming Errors:** What common mistakes can users or programmers make related to this code?
5. **User Journey:** How does a user's action lead to this code being executed?
6. **Concise Summary:** A brief overview of the code's purpose.

Let's analyze the code step by step:

- The code is part of unit tests for `ConfiguredProxyResolutionService`. This suggests it's testing the logic of how Chromium determines which proxy server to use for a given URL.
- It uses `MockProxyConfigService` and `MockAsyncProxyResolver` which indicate it's simulating different proxy configurations and proxy resolution behaviors.
- Several tests focus on proxy fallback scenarios, where if one proxy fails, the system tries another. This likely involves PAC scripts (Proxy Auto-Configuration) which are written in JavaScript.
- There are tests for proxy bypass lists, per-protocol proxies (HTTP, HTTPS, FTP), and handling errors in PAC scripts.
- The code demonstrates how Chromium handles mandatory proxy configurations.
- There are tests for canceling in-progress proxy resolution requests and handling the initial download of PAC scripts.

**Relationship to JavaScript:** PAC scripts are JavaScript code that defines how to select a proxy server. The `MockAsyncProxyResolver` likely simulates the execution of these scripts.

**Logical Inference:** The tests set up different scenarios with specific proxy configurations and simulate failures. The expected output is the selection of a specific proxy or a direct connection.

**User/Programming Errors:** Common errors could involve incorrect PAC script syntax, misconfigured proxy bypass lists, or not handling proxy failures properly.

**User Journey:**  A user navigating to a website triggers the browser to determine the appropriate proxy. This involves fetching the proxy configuration (which could be a PAC script), executing the script (or applying manual proxy rules), and selecting a proxy server.

**Concise Summary:** This code tests the proxy resolution logic in Chromium, particularly focusing on how it handles different proxy configurations, fallback mechanisms, and errors, including those related to PAC scripts.
这是 Chromium 网络栈中 `net/proxy_resolution/configured_proxy_resolution_service_unittest.cc` 文件的一部分，主要功能是 **测试 `ConfiguredProxyResolutionService` 类在处理代理故障切换 (fallback) 时的行为**。

**归纳一下这部分的功能:**

这部分代码主要测试了当使用 PAC 脚本配置代理时，如果首选代理连接失败，`ConfiguredProxyResolutionService` 如何按照 PAC 脚本中提供的代理列表进行故障切换，以及如何处理直接连接 (DIRECT) 作为 fallback 选项的情况。  此外，还测试了当 PAC 脚本本身执行失败时 (例如 JavaScript 运行时错误) 的 fallback 行为，以及如何处理强制代理配置的情况。

**与 Javascript 的关系及举例说明:**

这段代码与 Javascript 的关系主要体现在 **PAC (Proxy Auto-Configuration) 脚本的执行和结果解析** 上。

* **PAC 脚本内容:**  在测试用例中，例如 `ProxyFallbackToDirect` 测试，模拟的 PAC 脚本内容为 `"PROXY foopy1:8080; PROXY foopy2:9090; DIRECT"`。 这段 Javascript 代码指示浏览器首先尝试使用 `foopy1:8080` 作为代理，如果失败则尝试 `foopy2:9090`，如果都失败则直接连接。
* **PAC 脚本执行模拟:**  `MockAsyncProxyResolver` 类用于模拟 PAC 脚本的执行结果。例如，在 `ProxyFallback` 测试中，通过 `resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy1:8080;foopy2:9090");`  模拟 PAC 脚本返回了一个包含两个代理服务器的列表。
* **PAC 脚本错误模拟:** 在 `ProxyFallback_BadConfig` 和 `ProxyFallback_BadConfigMandatory` 测试中，通过 `resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);`  模拟 PAC 脚本执行过程中发生错误（例如，JavaScript 运行时错误）。

**逻辑推理 (假设输入与输出):**

以 `ProxyFallback` 测试为例：

* **假设输入:**
    * URL: `http://www.google.com/`
    * PAC 脚本内容 (模拟): 返回代理列表 "foopy1:8080;foopy2:9090"
    * 模拟代理连接结果: `foopy1:8080` 连接失败 (通过 `info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource())` 模拟)
    * 模拟代理连接结果: `foopy2:9090` 连接成功 (通过 `service.ReportSuccess(info)` 模拟)
    * 再次请求相同的 URL

* **输出:**
    * 首次请求:  先尝试 `foopy1:8080`，由于模拟失败，fallback 到 `foopy2:9090`。最终 `info.proxy_chain().ToDebugString()` 为 `"[foopy2:9090]"`。
    * 再次请求: 由于 `foopy1:8080` 在之前的连接中被报告为失败，所以这次会优先尝试 `foopy2:9090`。如果 PAC 脚本返回的列表顺序不变，则 `info.proxy_chain().ToDebugString()` 将为 `"[foopy3:7070]"` （因为代码模拟了 PAC 返回 "foopy3:7070;foopy1:8080;foopy2:9090"，并且 `foopy1` 被标记为坏代理所以跳过）。

**涉及用户或编程常见的使用错误及举例说明:**

* **PAC 脚本编写错误:** 用户在配置代理时，如果编写的 PAC 脚本存在语法错误或逻辑错误，可能导致 `ConfiguredProxyResolutionService` 无法正确解析代理配置，或者在应该使用代理的时候直接连接，反之亦然。
    * **例子:** PAC 脚本中忘记使用引号包裹字符串，或者 `if` 语句的条件判断错误。
* **代理服务器配置错误:**  用户配置了代理服务器地址和端口，但是代理服务器本身无法访问或配置不正确，会导致连接失败，触发 `ConfiguredProxyResolutionService` 的 fallback 机制。
    * **例子:**  输入了错误的代理服务器 IP 地址或端口号。
* **网络环境问题:**  用户的网络环境不稳定，导致与代理服务器的连接中断，也会触发 fallback。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试访问一个网页 (例如 `http://www.google.com/`)。**
2. **操作系统或浏览器会检查代理设置。**  这可能包括手动配置的代理服务器地址、PAC 脚本 URL 或自动检测设置。
3. **如果配置了 PAC 脚本，浏览器会下载并执行该脚本。**
4. **`ConfiguredProxyResolutionService` 负责管理代理的解析和选择过程。** 它会与 `AsyncProxyResolver` 交互，后者负责实际执行 PAC 脚本或根据手动配置解析代理列表。
5. **如果 PAC 脚本返回一个代理列表，`ConfiguredProxyResolutionService` 会尝试连接列表中的第一个代理。**
6. **如果连接失败 (例如 `ERR_PROXY_CONNECTION_FAILED`)，`ConfiguredProxyResolutionService` 会调用 `info.Fallback()` 来尝试列表中的下一个代理或直接连接 (如果 PAC 脚本允许)。** 这正是这段测试代码所覆盖的核心逻辑。
7. **`service.ReportSuccess(info)`  用于告知 `ConfiguredProxyResolutionService` 某个代理连接成功，这会影响后续代理选择的优先级（例如，将失败的代理标记为坏代理）。**

**作为调试线索:**  当用户遇到代理连接问题时，可以通过以下方式进行调试，并可能触发到 `ConfiguredProxyResolutionService` 的相关逻辑：

* **检查浏览器的网络日志 (chrome://net-export/)**:  可以查看代理解析和连接的详细过程，包括 PAC 脚本的下载和执行结果，以及连接尝试的错误信息。
* **使用开发者工具的网络面板**: 可以查看请求使用的代理服务器以及连接状态。
* **检查操作系统的代理设置**: 确认代理配置是否正确。
* **如果使用了 PAC 脚本，可以尝试访问 PAC 脚本 URL，查看脚本内容是否正确。**
* **尝试手动配置代理服务器**:  绕过 PAC 脚本，看是否能够连接，以判断问题是否出在 PAC 脚本本身。

总而言之，这段测试代码覆盖了 `ConfiguredProxyResolutionService` 在代理故障切换场景下的关键行为，这对于保证用户在遇到代理问题时能够尽可能正常地访问网络至关重要。

Prompt: 
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
k1.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
  base::TimeTicks proxy_resolve_start_time = info.proxy_resolve_start_time();
  base::TimeTicks proxy_resolve_end_time = info.proxy_resolve_end_time();

  // Fake an error on the proxy.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));

  // Proxy times should not have been modified by fallback.
  EXPECT_EQ(proxy_resolve_start_time, info.proxy_resolve_start_time());
  EXPECT_EQ(proxy_resolve_end_time, info.proxy_resolve_end_time());

  // The second proxy should be specified.
  EXPECT_EQ("[foopy2:9090]", info.proxy_chain().ToDebugString());
  // Report back that the second proxy worked.  This will globally mark the
  // first proxy as bad.
  TestProxyFallbackProxyDelegate test_delegate;
  service.SetProxyDelegate(&test_delegate);
  service.ReportSuccess(info);
  EXPECT_EQ("[foopy1:8080]", test_delegate.proxy_chain().ToDebugString());
  EXPECT_EQ(ERR_PROXY_CONNECTION_FAILED,
            test_delegate.last_proxy_fallback_net_error());
  service.SetProxyDelegate(nullptr);
  EXPECT_EQ(1u, info.proxy_retry_info().size());
  EXPECT_TRUE(
      info.proxy_retry_info().contains(ProxyChain::FromSchemeHostAndPort(
          ProxyServer::SCHEME_HTTP, "foopy1", 8080)));

  TestCompletionCallback callback3;
  rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback3.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver -- the second result is already known
  // to be bad, so we will not try to use it initially.
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy3:7070;foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy3:7070]", info.proxy_chain().ToDebugString());

  // Proxy times should have been updated, so get them again.
  EXPECT_LE(proxy_resolve_end_time, info.proxy_resolve_start_time());
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
  proxy_resolve_start_time = info.proxy_resolve_start_time();
  proxy_resolve_end_time = info.proxy_resolve_end_time();

  // We fake another error. It should now try the third one.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_EQ("[foopy2:9090]", info.proxy_chain().ToDebugString());

  // We fake another error. At this point we have tried all of the
  // proxy servers we thought were valid; next we try the proxy server
  // that was in our bad proxies map (foopy1:8080).
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  // Fake another error, the last proxy is gone, the list should now be empty,
  // so there is nothing left to try.
  EXPECT_FALSE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
  EXPECT_FALSE(info.is_direct());
  EXPECT_TRUE(info.is_empty());

  // Proxy times should not have been modified by fallback.
  EXPECT_EQ(proxy_resolve_start_time, info.proxy_resolve_start_time());
  EXPECT_EQ(proxy_resolve_end_time, info.proxy_resolve_end_time());

  // Look up proxies again
  TestCompletionCallback callback7;
  rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback7.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time, the first 3 results have been found to be bad, but only the
  // first proxy has been confirmed ...
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy3:7070;foopy2:9090;foopy4:9091");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // ... therefore, we should see the second proxy first.
  EXPECT_THAT(callback7.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy3:7070]", info.proxy_chain().ToDebugString());

  EXPECT_LE(proxy_resolve_end_time, info.proxy_resolve_start_time());
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  // TODO(nsylvain): Test that the proxy can be retried after the delay.
}

// This test is similar to ProxyFallback, but this time we have an explicit
// fallback choice to DIRECT.
TEST_F(ConfiguredProxyResolutionServiceTest, ProxyFallbackToDirect) {
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
      "PROXY foopy1:8080; PROXY foopy2:9090; DIRECT");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Get the first result.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  // Fake an error on the proxy.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));

  // Now we get back the second proxy.
  EXPECT_EQ("[foopy2:9090]", info.proxy_chain().ToDebugString());

  // Fake an error on this proxy as well.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));

  // Finally, we get back DIRECT.
  EXPECT_TRUE(info.is_direct());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // Now we tell the proxy service that even DIRECT failed.
  // There was nothing left to try after DIRECT, so we are out of
  // choices.
  EXPECT_FALSE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));
}

TEST_F(ConfiguredProxyResolutionServiceTest, ProxyFallback_BadConfig) {
  // Test proxy failover when the configuration is bad.

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
  TestResolveProxyDelegate delegate;
  std::unique_ptr<ProxyResolutionRequest> request;
  service.SetProxyDelegate(&delegate);
  int rv =
      service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(), &info,
                           callback1.callback(), &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  // Fake a proxy error.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));

  // The first proxy is ignored, and the second one is selected.
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy2:9090]", info.proxy_chain().ToDebugString());

  // Persist foopy1's failure to |service|'s cache of bad proxies, so it will
  // be considered by subsequent calls to ResolveProxy().
  service.ReportSuccess(info);

  // Fake a PAC failure.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                            &info2, callback2.callback(), &request,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This simulates a javascript runtime error in the PAC script.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // Although the resolver failed, the ConfiguredProxyResolutionService will
  // implicitly fall-back to a DIRECT connection.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_TRUE(info2.is_direct());
  EXPECT_FALSE(info2.is_empty());

  // The PAC script will work properly next time and successfully return a
  // proxy list. Since we have not marked the configuration as bad, it should
  // "just work" the next time we call it.
  ProxyInfo info3;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                            &info3, callback3.callback(), &request3,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first proxy was deprioritized since it was added to the bad proxies
  // list by the earlier ReportSuccess().
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(info3.is_direct());
  EXPECT_EQ("[foopy2:9090]", info3.proxy_chain().ToDebugString());
  EXPECT_EQ(2u, info3.proxy_list().size());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  EXPECT_EQ(3, delegate.num_resolve_proxy_called());
}

TEST_F(ConfiguredProxyResolutionServiceTest, ProxyFallback_BadConfigMandatory) {
  // Test proxy failover when the configuration is bad.

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

  GURL url("http://www.google.com/");

  // Get the proxy information.
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

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());

  // Fake a proxy error.
  EXPECT_TRUE(info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource()));

  // The first proxy is ignored, and the second one is selected.
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("[foopy2:9090]", info.proxy_chain().ToDebugString());

  // Persist foopy1's failure to |service|'s cache of bad proxies, so it will
  // be considered by subsequent calls to ResolveProxy().
  service.ReportSuccess(info);

  // Fake a PAC failure.
  ProxyInfo info2;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                            &info2, callback3.callback(), &request3,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This simulates a javascript runtime error in the PAC script.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // Although the resolver failed, the ConfiguredProxyResolutionService will NOT
  // fall-back to a DIRECT connection as it is configured as mandatory.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback3.WaitForResult());
  EXPECT_FALSE(info2.is_direct());
  EXPECT_TRUE(info2.is_empty());

  // The PAC script will work properly next time and successfully return a
  // proxy list. Since we have not marked the configuration as bad, it should
  // "just work" the next time we call it.
  ProxyInfo info3;
  TestCompletionCallback callback4;
  std::unique_ptr<ProxyResolutionRequest> request4;
  rv = service.ResolveProxy(url, std::string(), NetworkAnonymizationKey(),
                            &info3, callback4.callback(), &request4,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first proxy was deprioritized since it was added to the bad proxies
  // list by the earlier ReportSuccess().
  EXPECT_THAT(callback4.WaitForResult(), IsOk());
  EXPECT_FALSE(info3.is_direct());
  EXPECT_EQ("[foopy2:9090]", info3.proxy_chain().ToDebugString());
  EXPECT_EQ(2u, info3.proxy_list().size());
}

TEST_F(ConfiguredProxyResolutionServiceTest, ProxyBypassList) {
  // Test that the proxy bypass rules are consulted.

  TestCompletionCallback callback[2];
  ProxyInfo info[2];
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080;foopy2:9090");
  config.set_auto_detect(false);
  config.proxy_rules().bypass_rules.ParseFromString("*.org");

  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
      /*quick_check_enabled=*/true);

  int rv;
  GURL url1("http://www.webkit.org");
  GURL url2("http://www.webkit.com");
  std::unique_ptr<ProxyResolutionRequest> request1;
  std::unique_ptr<ProxyResolutionRequest> request2;

  // Request for a .org domain should bypass proxy.
  rv = service.ResolveProxy(url1, std::string(), NetworkAnonymizationKey(),
                            &info[0], callback[0].callback(), &request1,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info[0].is_direct());

  // Request for a .com domain hits the proxy.
  rv = service.ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                            &info[1], callback[1].callback(), &request2,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("[foopy1:8080]", info[1].proxy_chain().ToDebugString());
}

TEST_F(ConfiguredProxyResolutionServiceTest, PerProtocolProxyTests) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("http=foopy1:8080;https=foopy2:8080");
  config.set_auto_detect(false);
  std::unique_ptr<ProxyResolutionRequest> request;
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("http://www.msn.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());
  }
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("ftp://ftp.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(info.is_direct());
    EXPECT_EQ("[direct://]", info.proxy_chain().ToDebugString());
  }
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("https://webbranch.techcu.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[foopy2:8080]", info.proxy_chain().ToDebugString());
  }
  {
    config.proxy_rules().ParseFromString("foopy1:8080");
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("http://www.microsoft.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());
  }
}

TEST_F(ConfiguredProxyResolutionServiceTest,
       ProxyConfigTrafficAnnotationPropagates) {
  // Test that the proxy config source is set correctly when resolving proxies
  // using manual proxy rules. Namely, the config source should only be set if
  // any of the rules were applied.
  std::unique_ptr<ProxyResolutionRequest> request;
  {
    ProxyConfig config;
    config.proxy_rules().ParseFromString("https=foopy2:8080");
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("http://www.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    ASSERT_THAT(rv, IsOk());
    // Should be test, even if there are no HTTP proxies configured.
    EXPECT_EQ(MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS),
              info.traffic_annotation());
  }
  {
    ProxyConfig config;
    config.proxy_rules().ParseFromString("https=foopy2:8080");
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("https://www.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    ASSERT_THAT(rv, IsOk());
    // Used the HTTPS proxy. So traffic annotation should test.
    EXPECT_EQ(MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS),
              info.traffic_annotation());
  }
  {
    ProxyConfig config;
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("http://www.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    ASSERT_THAT(rv, IsOk());
    // ProxyConfig is empty. Traffic annotation should still be TEST.
    EXPECT_EQ(MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS),
              info.traffic_annotation());
  }
}

// If only HTTP and a SOCKS proxy are specified, check if ftp/https queries
// fall back to the SOCKS proxy.
TEST_F(ConfiguredProxyResolutionServiceTest, DefaultProxyFallbackToSOCKS) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("http=foopy1:8080;socks=foopy2:1080");
  config.set_auto_detect(false);
  EXPECT_EQ(ProxyConfig::ProxyRules::Type::PROXY_LIST_PER_SCHEME,
            config.proxy_rules().type);

  std::unique_ptr<ProxyResolutionRequest> request;
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("http://www.msn.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[foopy1:8080]", info.proxy_chain().ToDebugString());
  }
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("ftp://ftp.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[socks4://foopy2:1080]", info.proxy_chain().ToDebugString());
  }
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("https://webbranch.techcu.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[socks4://foopy2:1080]", info.proxy_chain().ToDebugString());
  }
  {
    ConfiguredProxyResolutionService service(
        std::make_unique<MockProxyConfigService>(config), nullptr, nullptr,
        /*quick_check_enabled=*/true);
    GURL test_url("unknown://www.microsoft.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(
        test_url, std::string(), NetworkAnonymizationKey(), &info,
        callback.callback(), &request, NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("[socks4://foopy2:1080]", info.proxy_chain().ToDebugString());
  }
}

// Test cancellation of an in-progress request.
TEST_F(ConfiguredProxyResolutionServiceTest, CancelInProgressRequest) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  const GURL url3("http://request3");
  auto config_service =
      std::make_unique<MockProxyConfigService>("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* factory_ptr = factory.get();

  ConfiguredProxyResolutionService service(std::move(config_service),
                                           std::move(factory), nullptr,
                                           /*quick_check_enabled=*/true);

  // Start 3 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(url1, std::string(), NetworkAnonymizationKey(),
                                &info1, callback1.callback(), &request1,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Successfully initialize the PAC script.
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory_ptr->pending_requests()[0]->script_data()->url());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  GetPendingJobsForURLs(resolver, url1);

  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(url2, std::string(), NetworkAnonymizationKey(),
                            &info2, callback2.callback(), &request2,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  GetPendingJobsForURLs(resolver, url1, url2);

  ProxyInfo info3;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(url3, std::string(), NetworkAnonymizationKey(),
                            &info3, callback3.callback(), &request3,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  GetPendingJobsForURLs(resolver, url1, url2, url3);

  // Cancel the second request
  request2.reset();

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url3);

  // Complete the two un-cancelled jobs.
  // We complete the last one first, just to mix it up a bit.
  jobs[url3]->results()->UseNamedProxy("request3:80");
  jobs[url3]->CompleteNow(OK);  // dsaadsasd

  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  EXPECT_EQ(OK, callback1.WaitForResult());
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());

  EXPECT_FALSE(callback2.have_result());  // Cancelled.
  GetCancelledJobsForURLs(resolver, url2);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ("[request3:80]", info3.proxy_chain().ToDebugString());
}

// Test the initial PAC download for resolver that expects bytes.
TEST_F(ConfiguredProxyResolutionServiceTest, InitialPACScriptDownload) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  const GURL url3("http://request3");
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

  ProxyInfo info3;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(url3, std::string(), NetworkAnonymizationKey(),
                            &info3, callback3.callback(), &request3,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory_ptr->pending_requests().empty());

  EXPECT_EQ(LOAD_STATE_DOWNLOADING_PAC_FILE, request1->GetLoadState());
  EXPECT_EQ(LOAD_STATE_DOWNLOADING_PAC_FILE, request2->GetLoadState());
  EXPECT_EQ(LOAD_STATE_DOWNLOADING_PAC_FILE, request3->GetLoadState());

  // At this point the ConfiguredProxyResolutionService should be waiting for
  // the PacFileFetcher to invoke its completion callback, notifying it of PAC
  // script download completion.
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, it will have been sent to the proxy
  // resolver.
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2, url3);

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request1->GetLoadState());
  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request2->GetLoadState());
  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request3->GetLoadState());

  // Complete all the jobs (in some order).

  jobs[url3]->results()->UseNamedProxy("request3:80");
  jobs[url3]->CompleteNow(OK);

  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  jobs[url2]->results()->UseNamedProxy("request2:80");
  jobs[url2]->CompleteNow(OK);

  // Complete and verify that jobs ran as expected.
  EXPECT_EQ(OK, callback1.WaitForResult());
  // ProxyResolver::GetProxyForURL() to take a std::unique_ptr<Request>* rather
  // than a RequestHandle* (patchset #11 id:200001 of
  // https://codereview.chromium.org/1439053002/ )
  EXPECT_EQ("[request1:80]", info1.proxy_chain().ToDebugString());
  EXPECT_FALSE(info1.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info1.proxy_resolve_end_time().is_null());
  EXPECT_LE(info1.proxy_resolve_start_time(), info1.proxy_resolve_en
"""


```