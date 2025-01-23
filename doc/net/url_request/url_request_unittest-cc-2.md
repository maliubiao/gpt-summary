Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `net/url_request/url_request_unittest.cc`. They also want to know about:
1. **Relationship with JavaScript:** If any of the functionalities are related to JavaScript.
2. **Logical Reasoning (with examples):**  If the code performs any logical deductions, provide example inputs and expected outputs.
3. **Common User/Programming Errors:** Identify any potential mistakes users or programmers might make based on the code.
4. **User Steps to Reach the Code:** Describe how a user's actions could lead to the execution of this code.
5. **Functionality Summary:**  A concise summary of what the code does.

Let's break down the code section by section:

* **Priority Setting:**  Tests related to setting and getting the priority of a `URLRequest`. It checks if the priority is correctly set and if the priority updates are passed to the underlying `URLRequestJob`.
* **`OnConnected` Callback:** Tests related to the `OnConnected` callback of the `URLRequest::Delegate`. It verifies that the callback is called correctly (or not called in case of early failures) for both simple requests and redirects. It also checks how errors returned from this callback are handled.
* **Cookie Handling:** Tests involving cookie setting, sending, and blocking. It includes tests for delayed cookie callbacks and scenarios where cookies are not sent or saved due to explicit flags or network delegate policies.
* **SameSite Cookie Tests:** Tests specifically focused on how SameSite cookies are handled in different scenarios, including same-site, same-registrable-domain, and cross-site requests. It also tests the impact of redirects on SameSite cookie behavior based on a feature flag.

**JavaScript Relationship:**  Cookie handling is the most relevant aspect to JavaScript, as JavaScript running in a web page interacts with cookies through the `document.cookie` API. The SameSite attribute is particularly relevant to web security and how JavaScript might interact with cookies in cross-site scenarios.

**Logical Reasoning:** The code primarily performs assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`) to check if the actual state matches the expected state after certain operations. The logic is within the Chromium networking stack itself, and the tests verify that logic.

**User/Programming Errors:**  Common mistakes could involve:
    * Setting incorrect priorities without understanding their impact.
    * Not handling potential errors returned by `OnConnected`.
    * Misunderstanding the behavior of cookie flags like `LOAD_DO_NOT_SAVE_COOKIES`.
    * Incorrectly configuring network delegate policies, leading to unexpected cookie blocking.
    * Not being aware of how SameSite attributes affect cookie behavior in different contexts.

**User Steps to Reach the Code:**  A user browsing the web performs actions that trigger network requests. These requests are handled by the Chromium networking stack, including the `URLRequest` class. The code being tested is part of the unit tests for `URLRequest`, so these tests are run by developers during the development and testing phases of Chromium. A user action leading *to* this test code being run would be more about contributing to Chromium development and running the test suite.

**Functionality Summary (for this part):** This section of `url_request_unittest.cc` focuses on testing the functionalities related to:
    * **Request Prioritization:** Verifying that setting and updating request priorities work as expected and are correctly propagated.
    * **Connection Notifications:** Ensuring the `OnConnected` delegate method is invoked appropriately during the request lifecycle.
    * **Cookie Management:**  Testing various aspects of cookie handling, including setting, sending, and blocking cookies based on request flags and network delegate policies, with specific attention to asynchronous operations and SameSite attributes.

Now, let's generate the detailed response.

这是 `net/url_request/url_request_unittest.cc` 文件第三部分的功能归纳。 本部分主要集中在测试 `URLRequest` 的请求优先级设置、连接状态通知以及 Cookie 处理等核心功能。

**主要功能:**

1. **请求优先级测试:**
    *   **设置和获取优先级:** 验证可以通过 `SetPriority()` 方法设置 `URLRequest` 的优先级，并且可以通过 `priority()` 方法正确获取。
    *   **优先级传递给 Job:** 确保 `URLRequest` 的优先级设置会传递给底层的 `URLRequestJob`。
    *   **在 Job 启动前设置优先级:** 测试在 `URLRequestJob` 启动之前设置优先级是否有效。
    *   **与 `LOAD_IGNORE_LIMITS` Flag 的关系:** 验证当优先级设置为 `MAXIMUM_PRIORITY` 时，设置 `LOAD_IGNORE_LIMITS` Flag 不会产生问题。

2. **连接状态通知 (`OnConnected`) 测试:**
    *   **早期失败不通知:** 验证当请求在连接到远程端点之前失败时，`URLRequest::Delegate` 的 `OnConnected()` 回调不会被调用。
    *   **正常请求通知一次:** 验证对于简单的非重定向请求，`OnConnected()` 方法会被调用一次。
    *   **重定向请求多次通知:** 验证在发生重定向时，`OnConnected()` 方法会在每次重定向后被调用。
    *   **`OnConnected` 返回错误:** 测试当 `URLRequest::Delegate` 的 `OnConnected()` 方法返回错误时，整个请求会失败，并且错误码会被正确记录。
    *   **异步 `OnConnected`:** 测试 `OnConnected` 回调的异步执行情况，包括成功和失败的情况。

3. **Cookie 处理测试:**
    *   **延迟 Cookie 回调:** 测试在使用 `DelayedCookieMonster` 时，Cookie 的设置是否能够正常工作。
    *   **异步延迟 Cookie 回调:** 进一步测试异步场景下的 Cookie 设置，包括成功和由于安全原因等导致的设置失败情况。
    *   **阻止发送 Cookie:** 验证设置 `set_allow_credentials(false)` 后，Cookie 不会被发送。
    *   **阻止保存 Cookie (`LOAD_DO_NOT_SAVE_COOKIES`):** 测试使用 `LOAD_DO_NOT_SAVE_COOKIES` Flag 时，Cookie 是否不会被保存或更新。
    *   **通过策略阻止发送 Cookie:**  测试通过 `NetworkDelegate` 设置策略来阻止发送 Cookie。
    *   **通过策略阻止保存 Cookie:** 测试通过 `NetworkDelegate` 设置策略来阻止保存 Cookie。
    *   **不保存空 Cookie:** 验证对于空的 `set-cookie` 响应，不会进行 Cookie 保存操作。
    *   **异步策略阻止 Cookie 操作:** 测试在异步场景下，通过 `NetworkDelegate` 策略阻止发送和保存 Cookie 的情况。
    *   **SameSite Cookie 测试:**  详细测试了 SameSite Cookie 的行为，包括：
        *   在同站请求中发送 Strict 和 Lax 的 SameSite Cookie。
        *   在没有 initiator 的请求中发送 SameSite Cookie。
        *   在同注册域名请求中发送 SameSite Cookie。
        *   跨站请求中 Strict SameSite Cookie 不会被发送。
        *   跨站请求中 Lax SameSite Cookie 在顶级导航时会被发送。
        *   通过策略阻止获取 SameSite Cookie。
        *   通过策略阻止设置 SameSite Cookie。
        *   测试重定向链对 SameSite Cookie 的影响 (通过 `kCookieSameSiteConsidersRedirectChain` Feature Flag 控制)。

**与 JavaScript 的关系:**

本部分测试的功能与 JavaScript 在 Web 页面中的行为密切相关：

*   **请求优先级:** 虽然 JavaScript 本身不能直接控制网络请求的优先级，但浏览器内部的网络栈会根据一些启发式算法（可能受到页面行为的影响）和显式设置（如 Fetch API 中的 `priority` 属性，但这部分代码主要测试 C++ 层的实现）来处理请求优先级。
*   **`OnConnected` 回调:**  这个回调在 C++ 层处理连接建立后的逻辑，对于 JavaScript 来说，这部分发生在底层，JavaScript 通常通过 `fetch` API 或 `XMLHttpRequest` 的事件（如 `loadstart`，`readystatechange` 等）来感知连接状态。
*   **Cookie 处理:**  JavaScript 可以通过 `document.cookie` API 读取、设置和删除 Cookie。本部分测试确保了 C++ 网络栈的 Cookie 管理逻辑与 JavaScript 的预期行为一致，例如：
    *   **SameSite 属性:** JavaScript 设置的 SameSite Cookie，其发送行为会受到这里测试的逻辑的约束。例如，如果 JavaScript 设置了一个 `SameSite=Strict` 的 Cookie，那么在跨站请求中，按照这里的测试逻辑，这个 Cookie 不会被发送。

    **举例说明:**

    假设一个网页 `https://example.com` 中有一个 JavaScript 代码：

    ```javascript
    document.cookie = "myStrictCookie=value; SameSite=Strict";
    document.cookie = "myLaxCookie=value; SameSite=Lax";
    ```

    然后，该网页发起一个到 `https://another-site.com/api` 的 `fetch` 请求（非导航请求）：

    ```javascript
    fetch('https://another-site.com/api');
    ```

    根据本部分关于 SameSite Cookie 的测试，可以推断出：

    *   由于是跨站请求，`myStrictCookie` 不会被发送到 `https://another-site.com/api`。
    *   由于是非顶级导航请求，`myLaxCookie` 也不会被发送。

    如果网页发起一个到 `https://another-site.com` 的顶级导航：

    ```javascript
    window.location.href = 'https://another-site.com';
    ```

    那么 `myLaxCookie` 会被发送到 `https://another-site.com`，而 `myStrictCookie` 仍然不会被发送。

**逻辑推理与假设输入/输出:**

以下是一些基于代码的逻辑推理示例：

1. **假设输入:**  一个 `URLRequest` 的优先级被设置为 `LOW`，然后调用 `Start()`，之后又被设置为 `MEDIUM`。
    **输出:**  在整个过程中，`req->priority()` 的值会先是 `DEFAULT_PRIORITY`，然后变为 `LOW`，最后变为 `MEDIUM`。 底层的 `URLRequestJob` 的优先级也会同步更新。

2. **假设输入:** 一个请求的 URL 是无效的 (例如 "invalid url")。
    **输出:**  `URLRequest::Delegate` 的 `OnConnected()` 方法不会被调用，并且 `delegate.transports()` 将为空。

3. **假设输入:**  `URLRequest::Delegate` 的 `OnConnected()` 方法被设置为返回 `ERR_NOT_IMPLEMENTED`。
    **输出:** 请求会失败，`delegate.request_failed()` 为真，`delegate.request_status()` 将包含 `ERR_NOT_IMPLEMENTED` 错误码。

**用户或编程常见的使用错误:**

1. **错误地假设优先级会立即生效:**  用户可能认为设置了优先级后，请求会立即按照新的优先级进行处理。实际上，优先级的生效可能受到网络栈内部调度机制的影响。
2. **未处理 `OnConnected` 可能返回的错误:** 开发者可能忘记检查 `OnConnected` 的返回值，导致在连接建立后出现错误时未能正确处理。
3. **对 Cookie 的 `LOAD_DO_NOT_SAVE_COOKIES` 行为的误解:**  开发者可能错误地认为 `LOAD_DO_NOT_SAVE_COOKIES` 也会阻止发送 Cookie，但实际上它只阻止 Cookie 的保存。
4. **对 SameSite Cookie 行为的不了解:**  开发者可能不清楚不同 SameSite 属性值（Strict, Lax, None）对 Cookie 发送的影响，导致在跨站场景下出现 Cookie 丢失或意外发送的情况。

**用户操作如何到达这里 (作为调试线索):**

虽然用户不会直接执行这些单元测试代码，但用户的网络操作会触发 `URLRequest` 的创建和执行，而这些测试覆盖了 `URLRequest` 的核心功能。例如：

1. **设置请求优先级相关的代码:** 当用户在浏览器中进行某些操作，导致浏览器认为某个请求应该具有更高的或更低的优先级时（例如，用户主动点击链接加载主要内容 vs. 页面上的后台图片加载），浏览器内部可能会设置 `URLRequest` 的优先级。 开发者可以通过 Chrome 的 `chrome://net-export/` 功能抓取网络日志，查看请求的优先级信息。

2. **`OnConnected` 回调相关的代码:** 任何网络请求，无论是用户在地址栏输入 URL、点击链接、还是网页上的 JavaScript 发起的请求，都会经历连接建立的过程，从而触发 `OnConnected` 回调 (如果连接成功)。  如果连接失败，例如 DNS 解析失败或连接超时，则不会调用 `OnConnected`。 开发者可以使用 Chrome 的开发者工具的网络面板查看请求的状态和时间线，以此来推断 `OnConnected` 是否被调用以及何时调用。

3. **Cookie 处理相关的代码:**  用户浏览网页时，服务器可能会设置 Cookie，浏览器在后续请求中会根据 Cookie 的属性和请求的上下文来决定是否发送 Cookie。 例如：
    *   用户登录网站后，服务器会设置 Session Cookie。
    *   用户访问一个使用了第三方广告或分析服务的网站，可能会涉及到 SameSite Cookie 的处理。
    *   开发者可以通过浏览器开发者工具的 "Application" 或 "网络" 面板查看和调试 Cookie 的行为。

当 Chromium 开发者在调试网络相关问题时，可能会需要查看 `URLRequest` 的行为，这时这些单元测试可以作为理解代码逻辑和验证修复方案的参考。 例如，如果用户报告了一个 Cookie 没有按预期发送的问题，开发者可能会查看 SameSite Cookie 相关的测试用例，来理解 Chromium 的 Cookie 处理逻辑。

**本部分功能归纳:**

总而言之，本部分 `url_request_unittest.cc` 的代码主要用于测试 `URLRequest` 及其相关的核心功能，包括请求优先级管理、连接状态通知以及各种 Cookie 处理场景（包括通过策略进行控制）。 这些测试确保了 Chromium 网络栈在处理网络请求时能够正确地管理请求优先级，及时通知连接状态，并按照标准和策略正确地处理 Cookie。 这些功能对于保证 Web 应用的性能、安全性和用户体验至关重要。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(DEFAULT_PRIORITY, req->priority());

  req->SetPriority(LOW);
  EXPECT_EQ(LOW, req->priority());

  req->Start();
  EXPECT_EQ(LOW, req->priority());

  req->SetPriority(MEDIUM);
  EXPECT_EQ(MEDIUM, req->priority());
}

// Make sure that URLRequest calls SetPriority on a job before calling
// Start on it.
TEST_F(URLRequestTest, SetJobPriorityBeforeJobStart) {
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://test_intercept/foo"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(DEFAULT_PRIORITY, req->priority());

  RequestPriority job_priority;
  std::unique_ptr<URLRequestJob> job =
      std::make_unique<PriorityMonitoringURLRequestJob>(req.get(),
                                                        &job_priority);
  TestScopedURLInterceptor interceptor(req->url(), std::move(job));
  EXPECT_EQ(DEFAULT_PRIORITY, job_priority);

  req->SetPriority(LOW);

  req->Start();
  EXPECT_EQ(LOW, job_priority);
}

// Make sure that URLRequest passes on its priority updates to its
// job.
TEST_F(URLRequestTest, SetJobPriority) {
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://test_intercept/foo"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));

  RequestPriority job_priority;
  std::unique_ptr<URLRequestJob> job =
      std::make_unique<PriorityMonitoringURLRequestJob>(req.get(),
                                                        &job_priority);
  TestScopedURLInterceptor interceptor(req->url(), std::move(job));

  req->SetPriority(LOW);
  req->Start();
  EXPECT_EQ(LOW, job_priority);

  req->SetPriority(MEDIUM);
  EXPECT_EQ(MEDIUM, req->priority());
  EXPECT_EQ(MEDIUM, job_priority);
}

// Setting the IGNORE_LIMITS load flag should be okay if the priority
// is MAXIMUM_PRIORITY.
TEST_F(URLRequestTest, PriorityIgnoreLimits) {
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://test_intercept/foo"), MAXIMUM_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(MAXIMUM_PRIORITY, req->priority());

  RequestPriority job_priority;
  std::unique_ptr<URLRequestJob> job =
      std::make_unique<PriorityMonitoringURLRequestJob>(req.get(),
                                                        &job_priority);
  TestScopedURLInterceptor interceptor(req->url(), std::move(job));

  req->SetLoadFlags(LOAD_IGNORE_LIMITS);
  EXPECT_EQ(MAXIMUM_PRIORITY, req->priority());

  req->SetPriority(MAXIMUM_PRIORITY);
  EXPECT_EQ(MAXIMUM_PRIORITY, req->priority());

  req->Start();
  EXPECT_EQ(MAXIMUM_PRIORITY, req->priority());
  EXPECT_EQ(MAXIMUM_PRIORITY, job_priority);
}

// This test verifies that URLRequest::Delegate's OnConnected() callback is
// never called if the request fails before connecting to a remote endpoint.
TEST_F(URLRequestTest, NotifyDelegateConnectedSkippedOnEarlyFailure) {
  TestDelegate delegate;

  // The request will never connect to anything because the URL is invalid.
  auto request =
      default_context().CreateRequest(GURL("invalid url"), DEFAULT_PRIORITY,
                                      &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.transports(), IsEmpty());
}

// This test verifies that URLRequest::Delegate's OnConnected() method
// is called once for simple redirect-less requests.
TEST_F(URLRequestTest, OnConnected) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  TestDelegate delegate;

  auto request = default_context().CreateRequest(test_server.GetURL("/echo"),
                                                 DEFAULT_PRIORITY, &delegate,
                                                 TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  delegate.RunUntilComplete();

  TransportInfo expected_transport;
  expected_transport.endpoint =
      IPEndPoint(IPAddress::IPv4Localhost(), test_server.port());
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(delegate.transports(), ElementsAre(expected_transport));

  // Make sure URL_REQUEST_DELEGATE_CONNECTED is logged correctly.
  auto entries = net_log_observer_.GetEntries();
  size_t start_event_index = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/0,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::BEGIN);
  size_t end_event_index = ExpectLogContainsSomewhereAfter(
      entries, /*start_offset=*/start_event_index,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::END);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, end_event_index + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED));
  ASSERT_LT(end_event_index, entries.size());
  EXPECT_FALSE(GetOptionalNetErrorCodeFromParams(entries[end_event_index]));
}

// This test verifies that URLRequest::Delegate's OnConnected() method is
// called after each redirect.
TEST_F(URLRequestTest, OnConnectedRedirect) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  TestDelegate delegate;

  // Fetch a page that redirects us once.
  GURL url = test_server.GetURL("/server-redirect?" +
                                test_server.GetURL("/echo").spec());
  auto request = default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  delegate.RunUntilRedirect();

  TransportInfo expected_transport;
  expected_transport.endpoint =
      IPEndPoint(IPAddress::IPv4Localhost(), test_server.port());
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(delegate.transports(), ElementsAre(expected_transport));

  request->FollowDeferredRedirect(/*removed_headers=*/{},
                                  /*modified_headers=*/{});
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.transports(),
              ElementsAre(expected_transport, expected_transport));
}

// This test verifies that when the URLRequest Delegate returns an error from
// OnConnected(), the entire request fails with that error.
TEST_F(URLRequestTest, OnConnectedError) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  TestDelegate delegate;
  delegate.set_on_connected_result(ERR_NOT_IMPLEMENTED);

  auto request = default_context().CreateRequest(test_server.GetURL("/echo"),
                                                 DEFAULT_PRIORITY, &delegate,
                                                 TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  delegate.RunUntilComplete();

  TransportInfo expected_transport;
  expected_transport.endpoint =
      IPEndPoint(IPAddress::IPv4Localhost(), test_server.port());
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(delegate.transports(), ElementsAre(expected_transport));

  EXPECT_TRUE(delegate.request_failed());
  EXPECT_THAT(delegate.request_status(), IsError(ERR_NOT_IMPLEMENTED));

  // Make sure URL_REQUEST_DELEGATE_CONNECTED is logged correctly.
  auto entries = net_log_observer_.GetEntries();
  size_t start_event_index = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/0,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::BEGIN);
  size_t end_event_index = ExpectLogContainsSomewhereAfter(
      entries, /*start_offset=*/start_event_index,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::END);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, end_event_index + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED));
  ASSERT_LT(end_event_index, entries.size());
  EXPECT_EQ(ERR_NOT_IMPLEMENTED,
            GetOptionalNetErrorCodeFromParams(entries[end_event_index]));
}

TEST_F(URLRequestTest, OnConnectedAsync) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  TestDelegate d;
  d.set_on_connected_run_callback(true);
  d.set_on_connected_result(OK);
  std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
      default_context(), test_server.GetURL("/defaultresponse"), &d);
  req->Start();
  d.RunUntilComplete();
  EXPECT_THAT(d.request_status(), IsOk());

  // Make sure URL_REQUEST_DELEGATE_CONNECTED is logged correctly.
  auto entries = net_log_observer_.GetEntries();
  size_t start_event_index = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/0,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::BEGIN);
  size_t end_event_index = ExpectLogContainsSomewhereAfter(
      entries, /*start_offset=*/start_event_index,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::END);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, end_event_index + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED));
  ASSERT_LT(end_event_index, entries.size());
  EXPECT_FALSE(GetOptionalNetErrorCodeFromParams(entries[end_event_index]));
}

TEST_F(URLRequestTest, OnConnectedAsyncError) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  TestDelegate d;
  d.set_on_connected_run_callback(true);
  d.set_on_connected_result(ERR_NOT_IMPLEMENTED);
  std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
      default_context(), test_server.GetURL("/defaultresponse"), &d);
  req->Start();
  d.RunUntilComplete();
  EXPECT_THAT(d.request_status(), IsError(ERR_NOT_IMPLEMENTED));

  // Make sure URL_REQUEST_DELEGATE_CONNECTED is logged correctly.
  auto entries = net_log_observer_.GetEntries();
  size_t start_event_index = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/0,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::BEGIN);
  size_t end_event_index = ExpectLogContainsSomewhereAfter(
      entries, /*start_offset=*/start_event_index,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED, NetLogEventPhase::END);
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, end_event_index + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED));
  ASSERT_LT(end_event_index, entries.size());
  EXPECT_EQ(ERR_NOT_IMPLEMENTED,
            GetOptionalNetErrorCodeFromParams(entries[end_event_index]));
}

TEST_F(URLRequestTest, DelayedCookieCallback) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::make_unique<DelayedCookieMonster>());
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context, test_server.GetURL("/set-cookie?CookieToNotSend=1"), &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, network_delegate.blocked_annotate_cookies_count());
    EXPECT_EQ(0, network_delegate.blocked_set_cookie_count());
    EXPECT_EQ(1, network_delegate.set_cookie_count());
  }

  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context, test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSend=1") !=
                std::string::npos);
    EXPECT_EQ(0, network_delegate.blocked_annotate_cookies_count());
    EXPECT_EQ(0, network_delegate.blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, DelayedCookieCallbackAsync) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Add a secure cookie so we can try to set an insecure cookie and have
  // SetCanonicalCookie fail.
  GURL::Replacements replace_scheme;
  replace_scheme.SetSchemeStr("https");
  GURL url = test_server.base_url().ReplaceComponents(replace_scheme);

  auto cookie1 = CanonicalCookie::CreateForTesting(
      url, "AlreadySetCookie=1;Secure", base::Time::Now());
  auto delayed_cm = std::make_unique<DelayedCookieMonster>();
  delayed_cm->SetCanonicalCookieAsync(std::move(cookie1), url,
                                      net::CookieOptions::MakeAllInclusive(),
                                      CookieStore::SetCookiesCallback());

  auto cookie2 = CanonicalCookie::CreateForTesting(
      url, "AlreadySetCookie=1;Secure", base::Time::Now());
  auto cm = std::make_unique<CookieMonster>(nullptr, nullptr);
  cm->SetCanonicalCookieAsync(std::move(cookie2), url,
                              net::CookieOptions::MakeAllInclusive(),
                              CookieStore::SetCookiesCallback());

  auto async_context_builder = CreateTestURLRequestContextBuilder();
  async_context_builder->SetCookieStore(std::move(delayed_cm));
  auto& async_filter_network_delegate =
      *async_context_builder->set_network_delegate(
          std::make_unique<FilteringTestNetworkDelegate>());
  auto async_context = async_context_builder->Build();
  async_filter_network_delegate.SetCookieFilter("CookieBlockedOnCanGetCookie");
  TestDelegate async_delegate;

  auto sync_context_builder = CreateTestURLRequestContextBuilder();
  sync_context_builder->SetCookieStore(std::move(cm));
  auto& sync_filter_network_delegate =
      *sync_context_builder->set_network_delegate(
          std::make_unique<FilteringTestNetworkDelegate>());
  auto sync_context = sync_context_builder->Build();
  sync_filter_network_delegate.SetCookieFilter("CookieBlockedOnCanGetCookie");
  TestDelegate sync_delegate;

  std::vector<std::string> cookie_lines(
      {// Fails in SetCanonicalCookie for trying to set a secure cookie
       // on an insecure host.
       "CookieNotSet=1;Secure",
       // Fail in FilteringTestNetworkDelegate::CanGetCookie.
       "CookieBlockedOnCanGetCookie=1",
       // Fails in SetCanonicalCookie for trying to overwrite a secure cookie
       // with an insecure cookie.
       "AlreadySetCookie=1",
       // Succeeds and added cookie to store. Delayed (which makes the callback
       // run asynchronously) in DelayedCookieMonster.
       "CookieSet=1"});

  for (auto first_cookie_line : cookie_lines) {
    for (auto second_cookie_line : cookie_lines) {
      // Run with the delayed cookie monster.
      std::unique_ptr<URLRequest> request = CreateFirstPartyRequest(
          *async_context,
          test_server.GetURL("/set-cookie?" + first_cookie_line + "&" +
                             second_cookie_line),
          &async_delegate);

      request->Start();
      async_delegate.RunUntilComplete();
      EXPECT_THAT(async_delegate.request_status(), IsOk());

      // Run with the regular cookie monster.
      request = CreateFirstPartyRequest(
          *sync_context,
          test_server.GetURL("/set-cookie?" + first_cookie_line + "&" +
                             second_cookie_line),
          &sync_delegate);

      request->Start();
      sync_delegate.RunUntilComplete();
      EXPECT_THAT(sync_delegate.request_status(), IsOk());

      int expected_set_cookie_count = 0;
      int expected_blocked_cookie_count = 0;

      // 2 calls to the delegate's OnCanSetCookie method are expected, even if
      // the cookies don't end up getting set.
      expected_set_cookie_count += 2;

      if (first_cookie_line == "CookieBlockedOnCanGetCookie=1")
        ++expected_blocked_cookie_count;
      if (second_cookie_line == "CookieBlockedOnCanGetCookie=1")
        ++expected_blocked_cookie_count;

      EXPECT_EQ(expected_set_cookie_count,
                async_filter_network_delegate.set_cookie_called_count());
      EXPECT_EQ(expected_blocked_cookie_count,
                async_filter_network_delegate.blocked_set_cookie_count());

      EXPECT_EQ(expected_set_cookie_count,
                sync_filter_network_delegate.set_cookie_called_count());
      EXPECT_EQ(expected_blocked_cookie_count,
                sync_filter_network_delegate.blocked_set_cookie_count());

      async_filter_network_delegate.ResetSetCookieCalledCount();
      async_filter_network_delegate.ResetBlockedSetCookieCount();

      sync_filter_network_delegate.ResetSetCookieCalledCount();
      sync_filter_network_delegate.ResetBlockedSetCookieCount();
    }
  }
}

TEST_F(URLRequestTest, DoNotSendCookies) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/set-cookie?CookieToNotSend=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSend=1") !=
                std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie isn't sent when credentials are not allowed.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->set_allow_credentials(false);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("Cookie: CookieToNotSend=1") ==
                std::string::npos);

    // When credentials are blocked, OnAnnotateAndMoveUserBlockedCookies() is
    // not invoked.
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, DoNotSaveCookies) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL("/set-cookie?CookieToNotUpdate=2"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    EXPECT_EQ(1, default_network_delegate().set_cookie_count());
  }

  // Try to set-up another cookie and update the previous cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL("/set-cookie?CookieToNotSave=1&CookieToNotUpdate=1"),
        &d);
    req->SetLoadFlags(LOAD_DO_NOT_SAVE_COOKIES);
    req->Start();

    d.RunUntilComplete();

    // LOAD_DO_NOT_SAVE_COOKIES does not trigger OnSetCookie.
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    EXPECT_EQ(1, default_network_delegate().set_cookie_count());
  }

  // Verify the cookies weren't saved or updated.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSave=1") ==
                std::string::npos);
    EXPECT_TRUE(d.data_received().find("CookieToNotUpdate=2") !=
                std::string::npos);

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    EXPECT_EQ(1, default_network_delegate().set_cookie_count());
  }
}

TEST_F(URLRequestTest, DoNotSendCookies_ViaPolicy) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/set-cookie?CookieToNotSend=1"),
        &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSend=1") !=
                std::string::npos);

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    auto entries = net_log_observer_.GetEntries();
    for (const auto& entry : entries) {
      EXPECT_NE(entry.type,
                NetLogEventType::COOKIE_GET_BLOCKED_BY_NETWORK_DELEGATE);
    }
  }

  // Verify that the cookie isn't sent.
  {
    TestDelegate d;
    default_network_delegate().set_cookie_options(
        TestNetworkDelegate::NO_GET_COOKIES);
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("Cookie: CookieToNotSend=1") ==
                std::string::npos);

    EXPECT_EQ(1, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    auto entries = net_log_observer_.GetEntries();
    ExpectLogContainsSomewhereAfter(
        entries, 0, NetLogEventType::COOKIE_GET_BLOCKED_BY_NETWORK_DELEGATE,
        NetLogEventPhase::NONE);
  }
}

// TODO(crbug.com/41225288) This test is flaky on iOS.
#if BUILDFLAG(IS_IOS)
#define MAYBE_DoNotSaveCookies_ViaPolicy FLAKY_DoNotSaveCookies_ViaPolicy
#else
#define MAYBE_DoNotSaveCookies_ViaPolicy DoNotSaveCookies_ViaPolicy
#endif
TEST_F(URLRequestTest, MAYBE_DoNotSaveCookies_ViaPolicy) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL("/set-cookie?CookieToNotUpdate=2"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    auto entries = net_log_observer_.GetEntries();
    for (const auto& entry : entries) {
      EXPECT_NE(entry.type,
                NetLogEventType::COOKIE_SET_BLOCKED_BY_NETWORK_DELEGATE);
    }
  }

  // Try to set-up another cookie and update the previous cookie.
  {
    TestDelegate d;
    default_network_delegate().set_cookie_options(
        TestNetworkDelegate::NO_SET_COOKIE);
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL("/set-cookie?CookieToNotSave=1&CookieToNotUpdate=1"),
        &d);
    req->Start();

    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(2, default_network_delegate().blocked_set_cookie_count());
    auto entries = net_log_observer_.GetEntries();
    ExpectLogContainsSomewhereAfter(
        entries, 0, NetLogEventType::COOKIE_SET_BLOCKED_BY_NETWORK_DELEGATE,
        NetLogEventPhase::NONE);
  }

  // Verify the cookies weren't saved or updated.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSave=1") ==
                std::string::npos);
    EXPECT_TRUE(d.data_received().find("CookieToNotUpdate=2") !=
                std::string::npos);

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(2, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, DoNotSaveEmptyCookies) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up an empty cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/set-cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    EXPECT_EQ(0, default_network_delegate().set_cookie_count());
  }
}

TEST_F(URLRequestTest, DoNotSendCookies_ViaPolicy_Async) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/set-cookie?CookieToNotSend=1"),
        &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSend=1") !=
                std::string::npos);

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie isn't sent.
  {
    TestDelegate d;
    default_network_delegate().set_cookie_options(
        TestNetworkDelegate::NO_GET_COOKIES);
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("Cookie: CookieToNotSend=1") ==
                std::string::npos);

    EXPECT_EQ(1, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, DoNotSaveCookies_ViaPolicy_Async) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // Set up a cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL("/set-cookie?CookieToNotUpdate=2"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Try to set-up another cookie and update the previous cookie.
  {
    TestDelegate d;
    default_network_delegate().set_cookie_options(
        TestNetworkDelegate::NO_SET_COOKIE);
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL("/set-cookie?CookieToNotSave=1&CookieToNotUpdate=1"),
        &d);
    req->Start();

    d.RunUntilComplete();

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(2, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify the cookies weren't saved or updated.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("CookieToNotSave=1") ==
                std::string::npos);
    EXPECT_TRUE(d.data_received().find("CookieToNotUpdate=2") !=
                std::string::npos);

    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(2, default_network_delegate().blocked_set_cookie_count());
  }
}

// Tests for SameSite cookies. The test param indicates whether the same-site
// calculation considers redirect chains.
class URLRequestSameSiteCookiesTest
    : public URLRequestTest,
      public ::testing::WithParamInterface<bool> {
 public:
  URLRequestSameSiteCookiesTest() {
    if (DoesCookieSameSiteConsiderRedirectChain()) {
      feature_list_.InitAndEnableFeature(
          features::kCookieSameSiteConsidersRedirectChain);
    }
  }

  bool DoesCookieSameSiteConsiderRedirectChain() { return GetParam(); }

 private:
  base::test::ScopedFeatureList feature_list_;
};

TEST_P(URLRequestSameSiteCookiesTest, SameSiteCookies) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  const std::string kHost = "example.test";
  const std::string kSubHost = "subdomain.example.test";
  const std::string kCrossHost = "cross-origin.test";
  const url::Origin kOrigin =
      url::Origin::Create(test_server.GetURL(kHost, "/"));
  const url::Origin kSubOrigin =
      url::Origin::Create(test_server.GetURL(kSubHost, "/"));
  const url::Origin kCrossOrigin =
      url::Origin::Create(test_server.GetURL(kCrossHost, "/"));
  const SiteForCookies kSiteForCookies = SiteForCookies::FromOrigin(kOrigin);
  const SiteForCookies kCrossSiteForCookies =
      SiteForCookies::FromOrigin(kCrossOrigin);

  // Set up two 'SameSite' cookies on 'example.test'
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        test_server.GetURL(kHost,
                           "/set-cookie?StrictSameSiteCookie=1;SameSite=Strict&"
                           "LaxSameSiteCookie=1;SameSite=Lax"),
        &d);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
    EXPECT_EQ(2, default_network_delegate().set_cookie_count());
  }

  // Verify that both cookies are sent for same-site requests, whether they are
  // subresource requests, subframe navigations, or main frame navigations.
  for (IsolationInfo::RequestType request_type :
       {IsolationInfo::RequestType::kMainFrame,
        IsolationInfo::RequestType::kSubFrame,
        IsolationInfo::RequestType::kOther}) {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(request_type, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that both cookies are sent when the request has no initiator (can
  // happen for main frame browser-initiated navigations).
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(kSiteForCookies);
    req->Start();
    d.RunUntilComplete();

    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that both cookies are sent for same-registrable-domain requests.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(test_server.GetURL(kSubHost, "/")));
    req->set_initiator(kSubOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count()
```