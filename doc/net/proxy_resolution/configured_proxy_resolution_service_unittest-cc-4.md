Response:
The user wants a summary of the provided C++ code snippet, which is a part of a unit test for `ConfiguredProxyResolutionService` in Chromium's network stack.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Class Under Test:** The filename `configured_proxy_resolution_service_unittest.cc` and the test fixture names clearly indicate that the primary focus is testing the `ConfiguredProxyResolutionService` class.

2. **Understand the Purpose of Unit Tests:** Unit tests aim to verify the functionality of individual components in isolation. In this case, the tests are designed to ensure `ConfiguredProxyResolutionService` behaves as expected under various scenarios.

3. **Analyze the Test Cases:** Go through each `TEST_F` function and identify the specific functionality being tested. Look for patterns in the setup, actions performed, and assertions made.

    * **Initial PAC Script Download Failure, then Success:** The first test demonstrates how the service handles an initial failure to download the PAC script and then recovers when the download succeeds later. It verifies the fallback to DIRECT connection and the subsequent use of the PAC script.
    * **PAC Script Content Change:** The second test checks if the service correctly detects changes in the PAC script content during periodic re-fetches and updates the proxy resolver accordingly.
    * **PAC Script Content Unchanged:** The third test verifies that the service avoids unnecessary re-initialization of the proxy resolver if the PAC script content remains the same during re-fetches.
    * **PAC Script Fetch Succeeds, then Fails:**  The fourth test explores the scenario where the initial PAC script download is successful, but subsequent re-fetches fail. It confirms the service falls back to DIRECT connections.
    * **PAC Script Polling Policy:** This test directly examines the logic of the polling policy, verifying the delays and modes used for re-fetching the PAC script under success and failure conditions. It's not a full end-to-end test but rather focuses on a specific internal mechanism.
    * **PAC Script Refetch After Activity:** This test checks if user activity (represented by a new proxy resolution request) triggers a re-fetch of the PAC script based on a specific polling policy.
    * **IP Address Change Resets Proxy:** This test validates that a change in the IP address triggers a re-evaluation of the proxy configuration, including fetching the PAC script again. It also checks if pending proxy requests are blocked until the new configuration is available.
    * **DNS Change Triggers Poll:** The last test confirms that a DNS change event also triggers a re-fetch of the PAC script, but unlike IP address changes, existing proxy requests are not blocked.

4. **Identify Key Components and Interactions:** Note the interactions between `ConfiguredProxyResolutionService` and other mock objects:

    * `MockProxyConfigService`:  Provides the proxy configuration (e.g., the PAC script URL).
    * `MockAsyncProxyResolverFactory`:  Creates mock proxy resolvers.
    * `MockAsyncProxyResolver`:  Simulates the proxy resolution process based on the PAC script.
    * `MockPacFileFetcher`:  Simulates downloading the PAC script.
    * `DoNothingDhcpPacFileFetcher`: A placeholder for DHCP PAC script fetching (not actively used in these tests).
    * `TestCompletionCallback`: A utility for synchronizing asynchronous operations in the tests.
    * `NetworkChangeNotifier`: Used to simulate IP address and DNS changes.

5. **Relate to JavaScript (If Applicable):**  PAC scripts are written in JavaScript. The tests verify the correct handling of these scripts. Specifically, the tests check if the downloaded PAC script content is passed correctly to the `ProxyResolver` and if changes in the PAC script lead to different proxy resolutions.

6. **Identify Potential User/Programming Errors:**  Think about scenarios where things might go wrong from a user's or developer's perspective. This involves issues like incorrect PAC script URLs, network problems preventing PAC script download, and unexpected PAC script content.

7. **Describe User Actions Leading to These Tests:**  Consider how a user's actions might indirectly trigger the code being tested. This involves actions that influence proxy settings, such as configuring a PAC script URL in the browser settings or system settings.

8. **Synthesize the Summary:**  Combine the observations from the previous steps into a concise summary of the file's functionality. Group similar test cases and highlight the key aspects being verified.

9. **Address Specific Instructions:** Ensure all parts of the prompt are addressed, including:
    * Listing the file's functions.
    * Explaining the relationship to JavaScript.
    * Providing examples of logical reasoning (input/output).
    * Illustrating common user/programming errors.
    * Describing user steps to reach this code (as debugging clues).
    * Acknowledging the part number (5/6).

10. **Refine and Organize:** Review the generated summary for clarity, accuracy, and completeness. Organize the information logically using headings and bullet points for better readability. Ensure the language is precise and avoids jargon where possible.
好的，这是对 `net/proxy_resolution/configured_proxy_resolution_service_unittest.cc` 文件（第 5 部分，共 6 部分）功能的归纳总结：

**功能归纳:**

这部分单元测试主要集中在测试 `ConfiguredProxyResolutionService` 如何处理代理自动配置（PAC）脚本的定期刷新和更新。具体来说，它测试了以下几个关键场景：

* **PAC 脚本内容变更后的重新获取:**  测试验证了当初始 PAC 脚本下载成功后，如果其内容发生变化，`ConfiguredProxyResolutionService` 会在后续的定期检查中检测到变化，并重新配置代理解析器以使用新的脚本。
* **PAC 脚本内容未变更时的处理:** 测试验证了当定期检查发现 PAC 脚本内容没有变化时，`ConfiguredProxyResolutionService` 不会重新初始化代理解析器，从而避免不必要的开销。
* **PAC 脚本获取从成功到失败的转换:** 测试验证了如果初始 PAC 脚本下载成功，但在后续的定期检查中下载失败，`ConfiguredProxyResolutionService` 会回退到使用直接连接，不再依赖该 PAC 脚本。
* **PAC 脚本轮询策略:** 测试验证了 `ConfiguredProxyResolutionService` 使用的 PAC 脚本轮询策略是否符合预期。它测试了在下载成功和失败的不同情况下，下次轮询的时间间隔和模式。
* **用户活动触发 PAC 脚本重新获取:** 测试验证了用户网络活动（例如发起新的代理解析请求）会触发 PAC 脚本的重新获取，即使按照正常的定时策略可能还没到重新获取的时间。
* **IP 地址变化导致代理配置重置:** 测试验证了当网络 IP 地址发生变化时，`ConfiguredProxyResolutionService` 会触发代理配置的重新评估，包括重新获取 PAC 脚本。它还验证了在此期间，新的代理请求会被阻塞，直到新的配置加载完成。
* **DNS 变化触发 PAC 脚本轮询:** 测试验证了当 DNS 服务器发生变化时，`ConfiguredProxyResolutionService` 会触发 PAC 脚本的重新获取。与 IP 地址变化不同，DNS 变化不会阻塞正在进行的代理请求。

**与 JavaScript 的关系及举例:**

PAC 脚本本身是用 JavaScript 编写的，用于动态地决定给定 URL 的代理服务器。这些测试直接验证了 `ConfiguredProxyResolutionService` 如何下载、解析和应用这些 JavaScript 脚本。

* **举例:**  `kValidPacScript1` 和 `kValidPacScript2` 常量代表了不同的 PAC 脚本内容。测试用例模拟了下载这两个不同的脚本，并验证 `ConfiguredProxyResolutionService` 是否正确地将这些脚本的内容（转换为 UTF-16）传递给了 `MockAsyncProxyResolverFactory` 来创建代理解析器。例如，在 `PACScriptRefetchAfterContentChange` 测试中，先使用 `kValidPacScript1` 初始化，然后模拟下载 `kValidPacScript2`，并断言新的脚本内容 `kValidPacScript216` 被传递给了工厂。

**逻辑推理的假设输入与输出:**

以 `PACScriptRefetchAfterContentChange` 测试为例：

* **假设输入:**
    * 初始 PAC 脚本 URL: `http://foopy/proxy.pac`
    * 第一次下载成功，内容为 `kValidPacScript1`。
    * 用户发起一个请求 `http://request1`。
    * 定期轮询开始。
    * 第二次下载成功，内容为 `kValidPacScript2` (与第一次不同)。
    * 用户发起第二个请求 `http://request2`。
* **预期输出:**
    * 第一个请求 `http://request1` 使用基于 `kValidPacScript1` 解析的代理规则。
    * 当下载到 `kValidPacScript2` 后，`ConfiguredProxyResolutionService` 会更新代理配置。
    * 第二个请求 `http://request2` 将使用基于 `kValidPacScript2` 解析的代理规则。

**用户或编程常见的使用错误及举例:**

* **错误的 PAC 脚本 URL:** 用户在配置代理时，如果输入了错误的 PAC 脚本 URL，`ConfiguredProxyResolutionService` 在尝试下载时会失败。测试用例 `PACScriptDownloadFailure`  模拟了这种情况，并验证了服务会回退到直接连接。
* **PAC 脚本语法错误:** 虽然这些测试没有直接测试 PAC 脚本的解析错误，但可以想象，如果用户提供的 PAC 脚本包含语法错误，代理解析器可能无法正确初始化，导致代理功能异常。开发者在编写 PAC 脚本时需要仔细检查语法。
* **网络问题导致 PAC 脚本下载失败:**  用户的网络连接可能存在问题，导致 PAC 脚本无法下载。测试用例 `PACScriptRefetchAfterSuccess` 模拟了在初始下载成功后，后续下载失败的情况，展示了服务如何处理这类问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户配置代理设置:** 用户通常会在操作系统或浏览器的设置中配置代理。这可能包括选择“自动检测代理设置”或提供一个 PAC 脚本的 URL。
2. **浏览器或应用程序发起网络请求:** 当用户访问一个网站或应用程序需要进行网络连接时，网络栈开始工作。
3. **`ConfiguredProxyResolutionService` 被调用:**  网络栈中的代理解析机制会调用 `ConfiguredProxyResolutionService` 来确定应该使用哪个代理服务器来处理该请求。
4. **PAC 脚本的获取与解析:** 如果配置了 PAC 脚本，`ConfiguredProxyResolutionService` 会尝试下载该脚本。如果脚本是新的或需要更新，就会触发本部分测试所涵盖的逻辑，例如定期重新获取、处理内容变更等。
5. **代理规则的应用:** 下载并解析 PAC 脚本后，`ConfiguredProxyResolutionService` 会根据脚本中的 JavaScript 代码来判断当前请求应该使用哪个代理服务器（或直接连接）。

**总结:**

这部分测试全面地验证了 `ConfiguredProxyResolutionService` 在处理 PAC 脚本的生命周期，特别是其更新和刷新的逻辑方面的正确性和健壮性。它涵盖了成功、失败、内容变更以及由用户活动和网络状态变化触发的多种场景，确保了网络栈能够可靠地使用 PAC 脚本进行代理配置。

### 提示词
```
这是目录为net/proxy_resolution/configured_proxy_resolution_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
<MockProxyConfigService>("http://foopy/proxy.pac");

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
  //
  // We simulate a failed download attempt, the proxy service should now
  // fall-back to DIRECT connections.
  fetcher_ptr->NotifyFetchCompletion(ERR_FAILED, std::string());

  ASSERT_TRUE(factory_ptr->pending_requests().empty());

  // Wait for completion callback, and verify it used DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info1.is_direct());

  // At this point we have initialized the proxy service using a PAC script,
  // however it failed and fell-back to DIRECT.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher_ptr->WaitUntilFetch();

  ASSERT_TRUE(factory_ptr->pending_requests().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). This time we will simulate a successful
  // download of the script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  base::RunLoop().RunUntilIdle();

  // Now that the PAC script is downloaded, it should be used to initialize the
  // ProxyResolver. Simulate a successful parse.
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // At this point the ConfiguredProxyResolutionService should have
  // re-configured itself to use the PAC script (thereby recovering from the
  // initial fetch failure). We will verify that the next Resolve request uses
  // the resolver rather than DIRECT.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that it was sent to the resolver.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch succeeds,
// however at a later time its *contents* change, we will eventually
// re-configure the service to use the new script.
TEST_F(ConfiguredProxyResolutionServiceTest,
       PACScriptRefetchAfterContentChange) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

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

  // At this point we have initialized the proxy service using a PAC script.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher_ptr->WaitUntilFetch();

  ASSERT_TRUE(factory_ptr->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). This time we will simulate a successful
  // download of a DIFFERENT script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript2);

  base::RunLoop().RunUntilIdle();

  // Now that the PAC script is downloaded, it should be used to initialize the
  // ProxyResolver. Simulate a successful parse.
  EXPECT_EQ(kValidPacScript216,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // At this point the ConfiguredProxyResolutionService should have
  // re-configured itself to use the new PAC script.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that it was sent to the resolver.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch succeeds
// and so does the next poll, however the contents of the downloaded script
// have NOT changed, then we do not bother to re-initialize the proxy resolver.
TEST_F(ConfiguredProxyResolutionServiceTest,
       PACScriptRefetchAfterContentUnchanged) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

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

  // At this point we have initialized the proxy service using a PAC script.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher_ptr->WaitUntilFetch();

  ASSERT_TRUE(factory_ptr->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). We will simulate the same response as
  // last time (i.e. the script is unchanged).
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);

  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(factory_ptr->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // At this point the ConfiguredProxyResolutionService is still running the
  // same PAC script as before.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that it was sent to the resolver.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch succeeds,
// however at a later time it starts to fail, we should re-configure the
// ConfiguredProxyResolutionService to stop using that PAC script.
TEST_F(ConfiguredProxyResolutionServiceTest, PACScriptRefetchAfterSuccess) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

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

  // At this point we have initialized the proxy service using a PAC script.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher_ptr->WaitUntilFetch();

  ASSERT_TRUE(factory_ptr->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). This time we will simulate a failure
  // to download the script.
  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());
  fetcher_ptr->NotifyFetchCompletion(ERR_FAILED, std::string());

  base::RunLoop().RunUntilIdle();

  // At this point the ConfiguredProxyResolutionService should have
  // re-configured itself to use DIRECT connections rather than the given proxy
  // resolver.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info2.is_direct());
}

// Tests that the code which decides at what times to poll the PAC
// script follows the expected policy.
TEST_F(ConfiguredProxyResolutionServiceTest, PACScriptPollingPolicy) {
  // Retrieve the internal polling policy implementation used by
  // ConfiguredProxyResolutionService.
  std::unique_ptr<ConfiguredProxyResolutionService::PacPollPolicy> policy =
      ConfiguredProxyResolutionService::CreateDefaultPacPollPolicy();

  int error;
  ConfiguredProxyResolutionService::PacPollPolicy::Mode mode;
  const base::TimeDelta initial_delay = base::Milliseconds(-1);
  base::TimeDelta delay = initial_delay;

  // --------------------------------------------------
  // Test the poll sequence in response to a failure.
  // --------------------------------------------------
  error = ERR_NAME_NOT_RESOLVED;

  // Poll #0
  mode = policy->GetNextDelay(error, initial_delay, &delay);
  EXPECT_EQ(8, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::MODE_USE_TIMER,
            mode);

  // Poll #1
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(32, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);

  // Poll #2
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(120, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);

  // Poll #3
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(14400, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);

  // Poll #4
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(14400, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);

  // --------------------------------------------------
  // Test the poll sequence in response to a success.
  // --------------------------------------------------
  error = OK;

  // Poll #0
  mode = policy->GetNextDelay(error, initial_delay, &delay);
  EXPECT_EQ(43200, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);

  // Poll #1
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(43200, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);

  // Poll #2
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(43200, delay.InSeconds());
  EXPECT_EQ(ConfiguredProxyResolutionService::PacPollPolicy::
                MODE_START_AFTER_ACTIVITY,
            mode);
}

// This tests the polling of the PAC script. Specifically, it tests that
// polling occurs in response to user activity.
TEST_F(ConfiguredProxyResolutionServiceTest, PACScriptRefetchAfterActivity) {
  ImmediateAfterActivityPollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

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

  // At this point we have initialized the proxy service using a PAC script.
  // Our PAC poller is set to update ONLY in response to network activity,
  // (i.e. another call to ResolveProxy()).

  ASSERT_FALSE(fetcher_ptr->has_pending_request());
  ASSERT_TRUE(factory_ptr->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // This request should have sent work to the resolver; complete it.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("[request2:80]", info2.proxy_chain().ToDebugString());

  // In response to getting that resolve request, the poller should have
  // started the next poll, and made it as far as to request the download.

  EXPECT_TRUE(fetcher_ptr->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher_ptr->pending_request_url());

  // This time we will fail the download, to simulate a PAC script change.
  fetcher_ptr->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Drain the message loop, so ConfiguredProxyResolutionService is notified of
  // the change and has a chance to re-configure itself.
  base::RunLoop().RunUntilIdle();

  // Start a third request -- this time we expect to get a direct connection
  // since the PAC script poller experienced a failure.
  ProxyInfo info3;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(
      GURL("http://request3"), std::string(), NetworkAnonymizationKey(), &info3,
      callback3.callback(), &request3, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info3.is_direct());
}

TEST_F(ConfiguredProxyResolutionServiceTest, IpAddressChangeResetsProxy) {
  NeverPollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(
      /*resolvers_expect_pac_bytes=*/true);
  MockAsyncProxyResolverFactory* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(ProxyConfig::CreateAutoDetect()),
      std::move(factory),
      /*net_log=*/nullptr, /*quick_check_enabled=*/true);
  auto fetcher = std::make_unique<MockPacFileFetcher>();
  MockPacFileFetcher* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  const base::TimeDelta kConfigDelay = base::Seconds(5);
  service.set_stall_proxy_auto_config_delay(kConfigDelay);

  // Initialize by making and completing a proxy request.
  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://request1"), std::string(), NetworkAnonymizationKey(), &info1,
      callback1.callback(), &request1, NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_TRUE(fetcher_ptr->has_pending_request());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);
  ASSERT_THAT(factory_ptr->pending_requests(), testing::SizeIs(1));
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_THAT(resolver.pending_jobs(), testing::SizeIs(1));
  resolver.pending_jobs()[0]->CompleteNow(OK);
  ASSERT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(fetcher_ptr->has_pending_request());

  // Expect IP address notification to trigger a fetch after wait period.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  FastForwardBy(kConfigDelay - base::Milliseconds(2));
  EXPECT_FALSE(fetcher_ptr->has_pending_request());
  FastForwardBy(base::Milliseconds(2));
  EXPECT_TRUE(fetcher_ptr->has_pending_request());

  // Leave pending fetch hanging.

  // Expect proxy requests are blocked on completion of change-triggered fetch.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request1"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(resolver.pending_jobs(), testing::IsEmpty());

  // Finish pending fetch and expect proxy request to be able to complete.
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript2);
  ASSERT_THAT(factory_ptr->pending_requests(), testing::SizeIs(1));
  EXPECT_EQ(kValidPacScript216,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_THAT(resolver.pending_jobs(), testing::SizeIs(1));
  resolver.pending_jobs()[0]->CompleteNow(OK);
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(fetcher_ptr->has_pending_request());
}

TEST_F(ConfiguredProxyResolutionServiceTest, DnsChangeTriggersPoll) {
  ImmediateAfterActivityPollPolicy poll_policy;
  ConfiguredProxyResolutionService::set_pac_script_poll_policy(&poll_policy);

  MockAsyncProxyResolver resolver;
  auto factory = std::make_unique<MockAsyncProxyResolverFactory>(
      /*resolvers_expect_pac_bytes=*/true);
  MockAsyncProxyResolverFactory* factory_ptr = factory.get();
  ConfiguredProxyResolutionService service(
      std::make_unique<MockProxyConfigService>(ProxyConfig::CreateAutoDetect()),
      std::move(factory),
      /*net_log=*/nullptr, /*quick_check_enabled=*/true);
  auto fetcher = std::make_unique<MockPacFileFetcher>();
  MockPacFileFetcher* fetcher_ptr = fetcher.get();
  service.SetPacFileFetchers(std::move(fetcher),
                             std::make_unique<DoNothingDhcpPacFileFetcher>());

  // Initialize config and poller by making and completing a proxy request.
  ProxyInfo info1;
  TestCompletionCallback callback1;
  std::unique_ptr<ProxyResolutionRequest> request1;
  int rv = service.ResolveProxy(
      GURL("http://request1"), std::string(), NetworkAnonymizationKey(), &info1,
      callback1.callback(), &request1, NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_TRUE(fetcher_ptr->has_pending_request());
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript1);
  ASSERT_THAT(factory_ptr->pending_requests(), testing::SizeIs(1));
  EXPECT_EQ(kValidPacScript116,
            factory_ptr->pending_requests()[0]->script_data()->utf16());
  factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_THAT(resolver.pending_jobs(), testing::SizeIs(1));
  resolver.pending_jobs()[0]->CompleteNow(OK);
  ASSERT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(fetcher_ptr->has_pending_request());

  // Expect DNS notification to trigger a fetch.
  NetworkChangeNotifier::NotifyObserversOfDNSChangeForTests();
  fetcher_ptr->WaitUntilFetch();
  EXPECT_TRUE(fetcher_ptr->has_pending_request());

  // Leave pending fetch hanging.

  // Expect proxy requests are not blocked on completion of DNS-triggered fetch.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  std::unique_ptr<ProxyResolutionRequest> request2;
  rv = service.ResolveProxy(
      GURL("http://request2"), std::string(), NetworkAnonymizationKey(), &info2,
      callback2.callback(), &request2, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_THAT(resolver.pending_jobs(), testing::SizeIs(1));
  resolver.pending_jobs()[0]->CompleteNow(OK);
  EXPECT_THAT(callback2.WaitForResult(), IsOk());

  // Complete DNS-triggered fetch.
  fetcher_ptr->NotifyFetchCompletion(OK, kValidPacScript2);
  RunUntilIdle();

  // Expect further proxy requests to use the new fetch result.
  ProxyInfo info3;
  TestCompletionCallback callback3;
  std::unique_ptr<ProxyResolutionRequest> request3;
  rv = service.ResolveProxy(
```