Response:
Let's break down the thought process for analyzing this code snippet and generating the answer.

**1. Understanding the Goal:**

The primary goal is to analyze a C++ unit test file for Chromium's networking stack (`net/url_request/url_request_unittest.cc`). The request asks for:

* **Functionality Summary:** What does this code *do*?
* **JavaScript Relationship:** Is there any connection to how JavaScript works with networking?
* **Logical Reasoning (Hypothetical Input/Output):**  If we ran specific tests, what would we expect?
* **Common Usage Errors:**  What mistakes could developers make when using related features?
* **User Operation to Reach Here (Debugging Clues):** How does a user's action lead to this code being relevant?
* **Concise Summary:** A brief overview of the file's purpose.

**2. Initial Code Scan and Keyword Identification:**

I started by quickly scanning the code, looking for key terms and patterns. The dominant pattern is `TEST_F(URLRequestTestHTTP, ...)`. This immediately tells me:

* **Testing:** This is a unit test file.
* **Focus:** The tests are for `URLRequest` and related HTTP functionality.
* **Framework:**  It's using a testing framework (likely gtest, given the `TEST_F`).

Other recurring keywords like `NetworkDelegate`, `BlockingNetworkDelegate`, `proxy_chain`, `redirect_url`, `GetResponseCode`, `request_status`, `AuthCredentials`, `Content-Length`, `Content-Encoding`, and `ERR_...` provide clues about the specific areas being tested.

**3. Grouping Tests by Functionality:**

As I read through the tests, I started mentally grouping them based on the scenario they were testing. This involved identifying the core concept each test was verifying:

* **Network Delegate Interaction:** Several tests explicitly manipulate and assert behavior of `NetworkDelegate` (blocking, canceling, redirecting requests).
* **Proxy Handling:** Tests involving `proxy_resolution_service` and assertions on `proxy_chain` indicate testing of proxy configurations.
* **Error Handling:** Tests checking for specific `ERR_...` codes are focused on error scenarios.
* **Redirection:** Tests with `redirect_url` and `FollowDeferredRedirect` clearly test redirection logic.
* **Authentication:** Tests using `AuthCredentials` and the `/auth-basic` URL test authentication mechanisms.
* **Request Cancellation:** Tests explicitly calling `r->Cancel()` verify behavior when requests are cancelled.
* **Content Encoding (GZIP/Deflate):** The `GetZippedTest` is specifically about handling compressed content.
* **Basic HTTP GET:** Tests like `GetTest` and `GetTestLoadTiming` verify fundamental GET request functionality.

**4. Connecting to User Actions and Debugging:**

To understand how a user might trigger this code, I thought about the high-level user actions that involve networking in a browser:

* **Typing a URL and pressing Enter:** This is the most common way to initiate a network request.
* **Clicking on a link:**  Similar to typing a URL.
* **Website actions (e.g., submitting a form):**  These can trigger POST requests and other network interactions.
* **Browser configuration (e.g., setting proxy settings):**  This directly affects the `proxy_resolution_service`.
* **Experiencing network errors:** Issues like connection timeouts, proxy errors, or authentication failures would involve the error handling logic tested here.

For debugging, I considered what information a developer might look for when a network issue occurs. The test names and assertions provide clear indications of potential problem areas (e.g., "NetworkDelegateCancelRequest", "ERR_TUNNEL_CONNECTION_FAILED").

**5. Considering JavaScript's Role:**

I reflected on how JavaScript interacts with the network in a browser. Key points include:

* **`fetch()` API:** The modern standard for making network requests.
* **`XMLHttpRequest` (XHR):** The older, but still relevant, way to make requests.
* **JavaScript doesn't directly implement the *low-level* networking:** It relies on the browser's underlying network stack (like Chromium's).
* **JavaScript *can* be influenced by network delegates:**  If a network delegate blocks or modifies a request, JavaScript's `fetch()` or XHR will be affected.

This led to the example of a JavaScript `fetch()` call potentially being blocked or redirected by a `NetworkDelegate` as tested in the C++ code.

**6. Formulating Hypothetical Inputs and Outputs:**

For the logical reasoning, I selected a couple of representative tests:

* **`NetworkDelegateTunnelConnectionFailed`:**  I imagined a scenario where a proxy tunnel fails and predicted the error code and delegate interaction.
* **`NetworkDelegateRedirectRequest`:**  I visualized a redirect happening and anticipated the response code, URL changes, and delegate behavior.

**7. Identifying Common Usage Errors:**

I considered common mistakes developers might make when dealing with concepts like network delegates or proxies:

* **Incorrect Proxy Configuration:**  A frequent source of networking problems.
* **Misunderstanding Asynchronous Behavior:** Especially relevant for network delegates that can block asynchronously.
* **Incorrect Error Handling:** Not properly checking for and handling network errors.

**8. Structuring the Answer:**

Finally, I organized the information into the requested sections: Functionality, JavaScript Relationship, Logical Reasoning, Usage Errors, Debugging, and Summary. I tried to use clear and concise language, providing examples where necessary. I also made sure to explicitly state assumptions and interpretations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on individual test cases without seeing the bigger picture of what the file *as a whole* tests.
* **Correction:** Step back and look for recurring patterns and themes across the tests.
* **Initial thought:**  Overcomplicate the JavaScript connection.
* **Correction:**  Focus on the high-level interaction – JavaScript uses the underlying network stack, which is what this C++ code tests.
* **Initial thought:**  Provide overly detailed hypothetical input/output for every test.
* **Correction:** Select a few representative tests to illustrate the concept without making the answer too long.

By following these steps, and iteratively refining the analysis, I arrived at the comprehensive answer provided earlier.
好的，让我们来分析一下这个代码文件 `net/url_request/url_request_unittest.cc` 的第 6 部分，并尝试解答你的问题。

**功能归纳（第 6 部分）：**

这部分代码主要集中在测试 `URLRequest` 与 `NetworkDelegate` 之间的交互，特别是 `NetworkDelegate` 如何影响请求的生命周期，包括：

* **阻止请求并异步返回 OK：** 测试 `NetworkDelegate` 在不同阶段（`ON_BEFORE_URL_REQUEST`, `ON_BEFORE_SEND_HEADERS`, `ON_HEADERS_RECEIVED`）阻止请求，然后异步允许请求继续。
* **取消请求：** 测试 `NetworkDelegate` 在不同阶段同步或异步地取消请求，并验证请求状态和代理链的状态。
* **重定向请求：** 测试 `NetworkDelegate` 如何阻止请求并将其重定向到新的 URL，包括在 `OnBeforeURLRequest` 和 `OnHeadersReceived` 阶段进行重定向，并验证是否保留了 POST 数据。
* **处理身份验证请求：** 测试 `NetworkDelegate` 在 `OnAuthRequired` 阶段同步地不采取任何操作，将身份验证挑战传递给 `URLRequest::Delegate` 处理。
* **处理身份验证时的头部覆盖：** 测试在身份验证过程中，来自 401 响应的 `NetworkDelegate` 头部覆盖不会影响到后续 200 响应。
* **处理等待 `NetworkDelegate` 回调时请求被取消的情况：**  测试在等待 `NetworkDelegate` 的不同回调（`OnBeforeURLRequest`, `OnBeforeSendHeaders`, `OnHeadersReceived`）时，如果 `URLRequest` 被取消，`NetworkDelegate` 是否能正确处理。
* **处理意外的服务器身份验证请求：**  测试当作为代理服务器的 `EmbeddedTestServer` 返回 401 响应时，`URLRequest` 是否能正确处理。
* **基本的 HTTP GET 请求测试：**  测试无缓存和有缓存的 HTTP GET 请求的基本功能，包括响应状态、接收数据量、远程端点信息以及 `LoadTimingInfo`。
* **处理压缩内容 (gzip/deflate)：**  测试 `URLRequest` 如何处理带有 `Content-Encoding: deflate` 的响应，并验证在不同 `Content-Length` 设置下的行为，包括正确、不正确、过短和过长的 `Content-Length`。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它测试的网络栈是浏览器执行 JavaScript 网络请求的基础。

* **`fetch()` API 和 `XMLHttpRequest`:** JavaScript 中的 `fetch()` API 和 `XMLHttpRequest` 对象最终会调用浏览器底层的网络栈来发送和接收数据。这段代码测试的 `URLRequest` 就是网络栈中处理单个请求的核心组件。
* **网络拦截和修改:**  `NetworkDelegate` 提供的功能类似于浏览器扩展或开发者工具中的网络拦截功能。JavaScript 通过这些机制可以观察和修改网络请求。例如，一个浏览器扩展可以使用 `chrome.webRequest` API（基于类似的底层机制）来拦截请求，就像这里的 `NetworkDelegate` 一样，可以阻止、重定向或修改请求头。

**举例说明:**

假设一个 JavaScript 代码使用 `fetch()` 发起一个请求：

```javascript
fetch('https://www.example.com/api/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

如果有一个 `NetworkDelegate` 像代码中测试的那样被配置为在 `ON_BEFORE_URL_REQUEST` 阶段阻止并重定向请求，那么这个 JavaScript 的 `fetch()` 调用实际上可能不会请求 `https://www.example.com/api/data`，而是被重定向到另一个 URL，例如 `http://does.not.resolve.test/simple.html`（就像代码中的 `NetworkDelegateRedirectRequest` 测试所做的那样）。JavaScript 代码最终会接收到来自重定向 URL 的响应，或者由于重定向 URL 无法解析而失败。

**逻辑推理（假设输入与输出）：**

**示例 1: `NetworkDelegateTunnelConnectionFailed`**

* **假设输入:**
    *  一个 `URLRequest` 请求 `https://www.redirect.com/`。
    *  `NetworkDelegate` 配置为使用 HTTP 代理 `http_test_server()->host_port_pair().ToString()`。
    *  代理连接失败。
* **预期输出:**
    * `d.request_status()` 将会是 `ERR_TUNNEL_CONNECTION_FAILED`。
    * `d.response_started_count()` 将会是 1（因为连接尝试会开始）。
    * `d.received_redirect_count()` 将会是 0（因为连接失败，不会发生重定向）。
    * `network_delegate.error_count()` 将会是 1。
    * `network_delegate.last_error()` 将会是 `ERR_TUNNEL_CONNECTION_FAILED`。
    * `r->proxy_chain()` 将会是有效的，并包含代理服务器信息。

**示例 2: `NetworkDelegateRedirectRequestPost`**

* **假设输入:**
    * 一个 `URLRequest` 发起 POST 请求到 `http://does.not.resolve.test/defaultresponse`，包含数据 "hello world"。
    * `NetworkDelegate` 配置为在 `ON_BEFORE_URL_REQUEST` 阶段将请求重定向到 `http_test_server()->GetURL("/echo")`。
* **预期输出:**
    * 请求会被重定向。
    * `d.request_status()` 在最终完成时将会是 `OK`。
    * `r->url()` 将会是重定向后的 URL (`http_test_server()->GetURL("/echo")`)。
    * `r->original_url()` 将会是原始 URL (`http://does.not.resolve.test/defaultresponse`)。
    * `r->url_chain().size()` 将会是 2。
    * 发送到 `/echo` 的请求方法是 `POST`。
    * `d.data_received()` 将会是 "hello world"，表明 POST 数据在重定向后被保留。

**用户或编程常见的使用错误：**

* **不正确的代理配置:**  例如，在 `NetworkDelegateTunnelConnectionFailed` 测试中，如果代理服务器地址配置错误或者代理服务器不可用，用户可能会遇到 `ERR_TUNNEL_CONNECTION_FAILED` 错误。开发者在设置 `ProxyResolutionService` 时需要确保代理配置的正确性。
* **异步操作处理不当:**  在涉及 `BlockingNetworkDelegate` 的测试中，如果开发者不理解异步回调的机制，可能会导致程序逻辑错误或死锁。例如，如果期望在 `DoCallback` 被调用后立即获取结果，但实际操作是异步的，则可能会出错。
* **在 `NetworkDelegate` 中错误地修改请求:**  `NetworkDelegate` 提供了强大的请求修改能力，但如果使用不当，可能会导致意外的行为。例如，错误地设置 `redirect_url` 或修改请求头可能导致请求失败或被服务器拒绝。
* **未处理网络错误:**  开发者在实现 `URLRequest::Delegate` 时，需要正确处理各种可能的网络错误（如 `ERR_EMPTY_RESPONSE`, `ERR_BLOCKED_BY_CLIENT`, `ERR_CONTENT_LENGTH_MISMATCH` 等）。忽略这些错误可能导致程序崩溃或功能异常。
* **对压缩内容的 `Content-Length` 处理不当:**  在 `GetZippedTest` 中可以看到，服务器返回压缩内容时，`Content-Length` 的设置会影响浏览器的行为。开发者在处理压缩响应时需要注意 `Content-Length` 的含义，避免出现 `ERR_CONTENT_LENGTH_MISMATCH` 错误。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户输入 URL 并回车：** 用户在浏览器地址栏输入一个需要通过代理访问的 HTTPS 网站地址（例如，在 `NetworkDelegateTunnelConnectionFailed` 测试的场景中）。
2. **浏览器查找代理配置：** 浏览器会根据系统设置或扩展配置查找适用的代理服务器。
3. **创建 `URLRequest`：** 浏览器网络栈创建一个 `URLRequest` 对象来处理该请求。
4. **`ProxyResolutionService` 解析代理：** `ProxyResolutionService` 组件根据配置选择要使用的代理服务器（例如，`http_test_server()->host_port_pair().ToString()`）。
5. **`NetworkDelegate` 介入：**  配置的 `NetworkDelegate` (在测试中是 `TestNetworkDelegate` 或 `BlockingNetworkDelegate`) 会在请求的不同阶段被调用。
6. **尝试建立隧道连接：** 对于 HTTPS 请求通过 HTTP 代理，会尝试建立一个 CONNECT 隧道。
7. **隧道连接失败：** 如果代理服务器拒绝连接或发生网络错误，隧道连接会失败。
8. **`NetworkDelegate` 记录错误：** 在 `NetworkDelegateTunnelConnectionFailed` 测试中，`TestNetworkDelegate` 会记录这个错误。
9. **`URLRequest::Delegate` 收到通知：** `URLRequest` 的委托对象（在测试中是 `TestDelegate`）会收到请求失败的通知，状态码为 `ERR_TUNNEL_CONNECTION_FAILED`。

**调试线索：**

当用户遇到网络问题时，开发者可能会：

* **查看 NetLog:**  Chromium 的 NetLog 记录了详细的网络事件，可以帮助开发者追踪请求的整个生命周期，包括代理协商、连接建立、数据传输等。
* **使用开发者工具的网络面板：**  可以查看请求的状态、头部信息、响应内容等，帮助判断是哪个环节出现了问题。
* **断点调试 `URLRequest` 和 `NetworkDelegate` 的相关代码：**  通过断点可以逐步执行代码，查看变量的值，理解请求处理的流程，例如，在 `NetworkDelegate` 的回调函数中设置断点，查看 `redirect_url` 是否被设置，或者请求是否被取消。
* **检查代理配置：**  确认用户的代理设置是否正确，代理服务器是否可访问。
* **分析错误码：**  `ERR_TUNNEL_CONNECTION_FAILED` 这样的错误码直接指向了隧道连接失败的问题，可以缩小问题排查范围。

**总结这段代码的功能：**

这段代码是 `net/url_request/url_request_unittest.cc` 的一部分，专门用于测试 `URLRequest` 与 `NetworkDelegate` 之间的各种交互场景。它验证了 `NetworkDelegate` 如何影响请求的生命周期，包括阻止、取消、重定向请求，处理身份验证，以及处理各种网络错误和特殊情况（例如，等待回调时请求被取消，处理压缩内容等）。这些测试对于确保 Chromium 网络栈的稳定性和正确性至关重要。

Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共17部分，请归纳一下它的功能

"""
ks that the network delegate
// registers the error.
TEST_F(URLRequestTestHTTP, NetworkDelegateTunnelConnectionFailed) {
  ASSERT_TRUE(http_test_server()->Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        GURL("https://www.redirect.com/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    // The proxy chain should be set before failure.
    EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                         http_test_server()->host_port_pair()),
              r->proxy_chain());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(ERR_TUNNEL_CONNECTION_FAILED, d.request_status());
    // We should not have followed the redirect.
    EXPECT_EQ(0, d.received_redirect_count());

    EXPECT_EQ(1, network_delegate.error_count());
    EXPECT_THAT(network_delegate.last_error(),
                IsError(ERR_TUNNEL_CONNECTION_FAILED));
  }
}

// Tests that we can block and asynchronously return OK in various stages.
TEST_F(URLRequestTestHTTP, NetworkDelegateBlockAsynchronously) {
  static const BlockingNetworkDelegate::Stage blocking_stages[] = {
      BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST,
      BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS,
      BlockingNetworkDelegate::ON_HEADERS_RECEIVED};

  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::USER_CALLBACK));
  network_delegate.set_block_on(
      BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST |
      BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS |
      BlockingNetworkDelegate::ON_HEADERS_RECEIVED);
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    for (auto stage : blocking_stages) {
      network_delegate.RunUntilBlocked();
      EXPECT_EQ(stage, network_delegate.stage_blocked_for_callback());
      network_delegate.DoCallback(OK);
    }
    d.RunUntilComplete();
    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that the network delegate can block and cancel a request.
TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::AUTO_CALLBACK));
  auto context = context_builder->Build();

  network_delegate.set_block_on(BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST);
  network_delegate.set_retval(ERR_EMPTY_RESPONSE);
  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    d.RunUntilComplete();

    // The proxy chain is not set before cancellation.
    EXPECT_FALSE(r->proxy_chain().IsValid());
    EXPECT_EQ(ERR_EMPTY_RESPONSE, d.request_status());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Helper function for NetworkDelegateCancelRequestAsynchronously and
// NetworkDelegateCancelRequestSynchronously. Sets up a blocking network
// delegate operating in |block_mode| and a request for |url|. It blocks the
// request in |stage| and cancels it with ERR_BLOCKED_BY_CLIENT.
void NetworkDelegateCancelRequest(BlockingNetworkDelegate::BlockMode block_mode,
                                  BlockingNetworkDelegate::Stage stage,
                                  const GURL& url) {
  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(block_mode));
  network_delegate.set_retval(ERR_BLOCKED_BY_CLIENT);
  network_delegate.set_block_on(stage);

  auto context = context_builder->Build();
  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    d.RunUntilComplete();

    // The proxy chain is not set before cancellation.
    if (stage == BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST ||
        stage == BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS) {
      EXPECT_FALSE(r->proxy_chain().IsValid());
    } else if (stage == BlockingNetworkDelegate::ON_HEADERS_RECEIVED) {
      EXPECT_TRUE(r->proxy_chain().is_direct());
    } else {
      NOTREACHED();
    }
    EXPECT_EQ(ERR_BLOCKED_BY_CLIENT, d.request_status());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// The following 3 tests check that the network delegate can cancel a request
// synchronously in various stages of the request.
TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequestSynchronously1) {
  ASSERT_TRUE(http_test_server()->Start());
  NetworkDelegateCancelRequest(BlockingNetworkDelegate::SYNCHRONOUS,
                               BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST,
                               http_test_server()->GetURL("/"));
}

TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequestSynchronously2) {
  ASSERT_TRUE(http_test_server()->Start());
  NetworkDelegateCancelRequest(BlockingNetworkDelegate::SYNCHRONOUS,
                               BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS,
                               http_test_server()->GetURL("/"));
}

TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequestSynchronously3) {
  ASSERT_TRUE(http_test_server()->Start());
  NetworkDelegateCancelRequest(BlockingNetworkDelegate::SYNCHRONOUS,
                               BlockingNetworkDelegate::ON_HEADERS_RECEIVED,
                               http_test_server()->GetURL("/"));
}

// The following 3 tests check that the network delegate can cancel a request
// asynchronously in various stages of the request.
TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequestAsynchronously1) {
  ASSERT_TRUE(http_test_server()->Start());
  NetworkDelegateCancelRequest(BlockingNetworkDelegate::AUTO_CALLBACK,
                               BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST,
                               http_test_server()->GetURL("/"));
}

TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequestAsynchronously2) {
  ASSERT_TRUE(http_test_server()->Start());
  NetworkDelegateCancelRequest(BlockingNetworkDelegate::AUTO_CALLBACK,
                               BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS,
                               http_test_server()->GetURL("/"));
}

TEST_F(URLRequestTestHTTP, NetworkDelegateCancelRequestAsynchronously3) {
  ASSERT_TRUE(http_test_server()->Start());
  NetworkDelegateCancelRequest(BlockingNetworkDelegate::AUTO_CALLBACK,
                               BlockingNetworkDelegate::ON_HEADERS_RECEIVED,
                               http_test_server()->GetURL("/"));
}

// Tests that the network delegate can block and redirect a request to a new
// URL.
TEST_F(URLRequestTestHTTP, NetworkDelegateRedirectRequest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::AUTO_CALLBACK));
  auto context = context_builder->Build();

  GURL redirect_url("http://does.not.resolve.test/simple.html");
  network_delegate.set_redirect_url(redirect_url);
  {
    GURL original_url("http://does.not.resolve.test/defaultresponse");
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    // Quit after hitting the redirect, so can check the headers.
    r->Start();
    d.RunUntilRedirect();

    // Check headers from URLRequestJob.
    EXPECT_EQ(307, r->GetResponseCode());
    EXPECT_EQ(307, r->response_headers()->response_code());
    std::string location;
    ASSERT_TRUE(
        r->response_headers()->EnumerateHeader(nullptr, "Location", &location));
    EXPECT_EQ(redirect_url, GURL(location));

    // Let the request finish.
    r->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                              std::nullopt /* modified_headers */);
    d.RunUntilComplete();
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                         http_test_server()->host_port_pair()),
              r->proxy_chain());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(redirect_url, r->url());
    EXPECT_EQ(original_url, r->original_url());
    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that the network delegate can block and redirect a request to a new
// URL by setting a redirect_url and returning in OnBeforeURLRequest directly.
TEST_F(URLRequestTestHTTP, NetworkDelegateRedirectRequestSynchronously) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::SYNCHRONOUS));
  auto context = context_builder->Build();

  GURL redirect_url("http://does.not.resolve.test/simple.html");
  network_delegate.set_redirect_url(redirect_url);
  {
    GURL original_url("http://does.not.resolve.test/defaultresponse");
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    // Quit after hitting the redirect, so can check the headers.
    r->Start();
    d.RunUntilRedirect();

    // Check headers from URLRequestJob.
    EXPECT_EQ(307, r->GetResponseCode());
    EXPECT_EQ(307, r->response_headers()->response_code());
    std::string location;
    ASSERT_TRUE(
        r->response_headers()->EnumerateHeader(nullptr, "Location", &location));
    EXPECT_EQ(redirect_url, GURL(location));

    // Let the request finish.
    r->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                              std::nullopt /* modified_headers */);
    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                         http_test_server()->host_port_pair()),
              r->proxy_chain());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(redirect_url, r->url());
    EXPECT_EQ(original_url, r->original_url());
    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that redirects caused by the network delegate preserve POST data.
TEST_F(URLRequestTestHTTP, NetworkDelegateRedirectRequestPost) {
  ASSERT_TRUE(http_test_server()->Start());

  const char kData[] = "hello world";

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::AUTO_CALLBACK));
  network_delegate.set_block_on(BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST);
  GURL redirect_url(http_test_server()->GetURL("/echo"));
  network_delegate.set_redirect_url(redirect_url);

  auto context = context_builder->Build();

  {
    GURL original_url(http_test_server()->GetURL("/defaultresponse"));
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");
    r->set_upload(CreateSimpleUploadData(base::byte_span_from_cstring(kData)));
    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kContentLength,
                      base::NumberToString(std::size(kData) - 1));
    r->SetExtraRequestHeaders(headers);

    // Quit after hitting the redirect, so can check the headers.
    r->Start();
    d.RunUntilRedirect();

    // Check headers from URLRequestJob.
    EXPECT_EQ(307, r->GetResponseCode());
    EXPECT_EQ(307, r->response_headers()->response_code());
    std::string location;
    ASSERT_TRUE(
        r->response_headers()->EnumerateHeader(nullptr, "Location", &location));
    EXPECT_EQ(redirect_url, GURL(location));

    // Let the request finish.
    r->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                              std::nullopt /* modified_headers */);
    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(redirect_url, r->url());
    EXPECT_EQ(original_url, r->original_url());
    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
    EXPECT_EQ("POST", r->method());
    EXPECT_EQ(kData, d.data_received());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that the network delegate can block and redirect a request to a new
// URL during OnHeadersReceived.
TEST_F(URLRequestTestHTTP, NetworkDelegateRedirectRequestOnHeadersReceived) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::AUTO_CALLBACK));
  auto context = context_builder->Build();

  network_delegate.set_block_on(BlockingNetworkDelegate::ON_HEADERS_RECEIVED);
  GURL redirect_url("http://does.not.resolve.test/simple.html");
  network_delegate.set_redirect_on_headers_received_url(redirect_url);
  {
    GURL original_url("http://does.not.resolve.test/defaultresponse");
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                         http_test_server()->host_port_pair()),
              r->proxy_chain());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(redirect_url, r->url());
    EXPECT_EQ(original_url, r->original_url());
    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(2, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that the network delegate can synchronously complete OnAuthRequired
// by taking no action. This indicates that the NetworkDelegate does not want to
// handle the challenge, and is passing the buck along to the
// URLRequest::Delegate.
TEST_F(URLRequestTestHTTP, NetworkDelegateOnAuthRequiredSyncNoAction) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::SYNCHRONOUS));
  auto context = context_builder->Build();

  d.set_credentials(AuthCredentials(kUser, kSecret));

  {
    GURL url(http_test_server()->GetURL("/auth-basic"));
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();

    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_TRUE(d.auth_required_called());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that NetworkDelegate header overrides from the 401 response do not
// affect the 200 response. This is a regression test for
// https://crbug.com/801237.
TEST_F(URLRequestTestHTTP, NetworkDelegateOverrideHeadersWithAuth) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  d.set_credentials(AuthCredentials(kUser, kSecret));
  default_network_delegate().set_add_header_to_first_response(true);

  {
    GURL url(http_test_server()->GetURL("/auth-basic"));
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();

    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_TRUE(d.auth_required_called());
    EXPECT_FALSE(r->response_headers()->HasHeader("X-Network-Delegate"));
  }

  {
    GURL url(http_test_server()->GetURL("/defaultresponse"));
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();

    d.RunUntilComplete();

    // Check that set_add_header_to_first_response normally adds a header.
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_TRUE(r->response_headers()->HasHeader("X-Network-Delegate"));
  }
}

// Tests that we can handle when a network request was canceled while we were
// waiting for the network delegate.
// Part 1: Request is cancelled while waiting for OnBeforeURLRequest callback.
TEST_F(URLRequestTestHTTP, NetworkDelegateCancelWhileWaiting1) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::USER_CALLBACK));
  network_delegate.set_block_on(BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST);
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    network_delegate.RunUntilBlocked();
    EXPECT_EQ(BlockingNetworkDelegate::ON_BEFORE_URL_REQUEST,
              network_delegate.stage_blocked_for_callback());
    EXPECT_EQ(0, network_delegate.completed_requests());
    // Cancel before callback.
    r->Cancel();
    // Ensure that network delegate is notified.
    EXPECT_EQ(1, network_delegate.completed_requests());
    EXPECT_EQ(1, network_delegate.canceled_requests());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that we can handle when a network request was canceled while we were
// waiting for the network delegate.
// Part 2: Request is cancelled while waiting for OnBeforeStartTransaction
// callback.
TEST_F(URLRequestTestHTTP, NetworkDelegateCancelWhileWaiting2) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::USER_CALLBACK));
  network_delegate.set_block_on(
      BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS);
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    network_delegate.RunUntilBlocked();
    EXPECT_EQ(BlockingNetworkDelegate::ON_BEFORE_SEND_HEADERS,
              network_delegate.stage_blocked_for_callback());
    EXPECT_EQ(0, network_delegate.completed_requests());
    // Cancel before callback.
    r->Cancel();
    // Ensure that network delegate is notified.
    EXPECT_EQ(1, network_delegate.completed_requests());
    EXPECT_EQ(1, network_delegate.canceled_requests());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

// Tests that we can handle when a network request was canceled while we were
// waiting for the network delegate.
// Part 3: Request is cancelled while waiting for OnHeadersReceived callback.
TEST_F(URLRequestTestHTTP, NetworkDelegateCancelWhileWaiting3) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::USER_CALLBACK));
  network_delegate.set_block_on(BlockingNetworkDelegate::ON_HEADERS_RECEIVED);
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    network_delegate.RunUntilBlocked();
    EXPECT_EQ(BlockingNetworkDelegate::ON_HEADERS_RECEIVED,
              network_delegate.stage_blocked_for_callback());
    EXPECT_EQ(0, network_delegate.completed_requests());
    // Cancel before callback.
    r->Cancel();
    // Ensure that network delegate is notified.
    EXPECT_EQ(1, network_delegate.completed_requests());
    EXPECT_EQ(1, network_delegate.canceled_requests());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());
}

namespace {

std::unique_ptr<test_server::HttpResponse> HandleServerAuthConnect(
    const test_server::HttpRequest& request) {
  if (request.headers.find("Host") == request.headers.end() ||
      request.headers.at("Host") != "www.server-auth.com" ||
      request.method != test_server::METHOD_CONNECT) {
    return nullptr;
  }

  auto http_response = std::make_unique<test_server::BasicHttpResponse>();
  http_response->set_code(HTTP_UNAUTHORIZED);
  http_response->AddCustomHeader("WWW-Authenticate",
                                 "Basic realm=\"WallyWorld\"");
  return http_response;
}

}  // namespace

// In this unit test, we're using the EmbeddedTestServer as a proxy server and
// issuing a CONNECT request with the magic host name "www.server-auth.com".
// The EmbeddedTestServer will return a 401 response, which we should balk at.
TEST_F(URLRequestTestHTTP, UnexpectedServerAuthTest) {
  http_test_server()->RegisterRequestHandler(
      base::BindRepeating(&HandleServerAuthConnect));
  ASSERT_TRUE(http_test_server()->Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto context = context_builder->Build();

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        GURL("https://www.server-auth.com/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    // The proxy chain should be set before failure.
    EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                         http_test_server()->host_port_pair()),
              r->proxy_chain());
    EXPECT_EQ(ERR_TUNNEL_CONNECTION_FAILED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, GetTest_NoCache) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_EQ(http_test_server()->host_port_pair().host(),
              r->GetResponseRemoteEndpoint().ToStringWithoutPort());
    EXPECT_EQ(http_test_server()->host_port_pair().port(),
              r->GetResponseRemoteEndpoint().port());

    // TODO(eroman): Add back the NetLog tests...
  }
}

TEST_F(URLRequestTestHTTP, GetTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_EQ(http_test_server()->host_port_pair().host(),
              r->GetResponseRemoteEndpoint().ToStringWithoutPort());
    EXPECT_EQ(http_test_server()->host_port_pair().port(),
              r->GetResponseRemoteEndpoint().port());
  }
}

TEST_F(URLRequestTestHTTP, GetTestLoadTiming) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    LoadTimingInfo load_timing_info;
    r->GetLoadTimingInfo(&load_timing_info);
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    EXPECT_EQ(http_test_server()->host_port_pair().host(),
              r->GetResponseRemoteEndpoint().ToStringWithoutPort());
    EXPECT_EQ(http_test_server()->host_port_pair().port(),
              r->GetResponseRemoteEndpoint().port());
  }
}

namespace {

// Sends the correct Content-Length matching the compressed length.
const char kZippedContentLengthCompressed[] = "C";
// Sends an incorrect Content-Length matching the uncompressed length.
const char kZippedContentLengthUncompressed[] = "U";
// Sends an incorrect Content-Length shorter than the compressed length.
const char kZippedContentLengthShort[] = "S";
// Sends an incorrect Content-Length between the compressed and uncompressed
// lengths.
const char kZippedContentLengthMedium[] = "M";
// Sends an incorrect Content-Length larger than both compressed and
// uncompressed lengths.
const char kZippedContentLengthLong[] = "L";

// Sends |compressed_content| which, when decoded with deflate, should have
// length |uncompressed_length|. The Content-Length header will be sent based on
// which of the constants above is sent in the query string.
std::unique_ptr<test_server::HttpResponse> HandleZippedRequest(
    const std::string& compressed_content,
    size_t uncompressed_length,
    const test_server::HttpRequest& request) {
  GURL url = request.GetURL();
  if (url.path_piece() != "/compressedfiles/BullRunSpeech.txt")
    return nullptr;

  size_t length;
  if (url.query_piece() == kZippedContentLengthCompressed) {
    length = compressed_content.size();
  } else if (url.query_piece() == kZippedContentLengthUncompressed) {
    length = uncompressed_length;
  } else if (url.query_piece() == kZippedContentLengthShort) {
    length = compressed_content.size() / 2;
  } else if (url.query_piece() == kZippedContentLengthMedium) {
    length = (compressed_content.size() + uncompressed_length) / 2;
  } else if (url.query_piece() == kZippedContentLengthLong) {
    length = compressed_content.size() + uncompressed_length;
  } else {
    return nullptr;
  }

  std::string headers = "HTTP/1.1 200 OK\r\n";
  headers += "Content-Encoding: deflate\r\n";
  base::StringAppendF(&headers, "Content-Length: %zu\r\n", length);
  return std::make_unique<test_server::RawHttpResponse>(headers,
                                                        compressed_content);
}

}  // namespace

TEST_F(URLRequestTestHTTP, GetZippedTest) {
  base::FilePath file_path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &file_path);
  file_path = file_path.Append(kTestFilePath);
  std::string expected_content, compressed_content;
  ASSERT_TRUE(base::ReadFileToString(
      file_path.Append(FILE_PATH_LITERAL("BullRunSpeech.txt")),
      &expected_content));
  // This file is the output of the Python zlib.compress function on
  // |expected_content|.
  ASSERT_TRUE(base::ReadFileToString(
      file_path.Append(FILE_PATH_LITERAL("BullRunSpeech.txt.deflate")),
      &compressed_content));

  http_test_server()->RegisterRequestHandler(base::BindRepeating(
      &HandleZippedRequest, compressed_content, expected_content.size()));
  ASSERT_TRUE(http_test_server()->Start());

  static const struct {
    const char* parameter;
    bool expect_success;
  } kTests[] = {
      // Sending the compressed Content-Length is correct.
      {kZippedContentLengthCompressed, true},
      // Sending the uncompressed Content-Length is incorrect, but we accept it
      // to workaround some broken servers.
      {kZippedContentLengthUncompressed, true},
      // Sending too long of Content-Length is rejected.
      {kZippedContentLengthLong, false},
      {kZippedContentLengthMedium, false},
      // Sending too short of Content-Length successfully fetches a response
      // body, but it will be truncated.
      {kZippedContentLengthShort, true},
  };

  for (const auto& test : kTests) {
    SCOPED_TRACE(test.parameter);
    TestDelegate d;
    std::string test_file = base::StringPrintf(
        "/compressedfiles/BullRunSpeech.txt?%s", test.parameter);

    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_network_delegate(
        std::make_unique<TestNetworkDelegate>());
    auto context = context_builder->Build();

    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL(test_file), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    VLOG(1) << " Received " << d.bytes_received() << " bytes"
            << " error = " << d.request_status();
    if (test.expect_success) {
      EXPECT_EQ(OK, d.request_status())
          << " Parameter = \"" << test_file << "\"";
      if (strcmp(test.parameter, kZippedContentLengthShort) == 0) {
        // When content length is smaller than both compressed length and
        // uncompressed length, HttpStreamParser might not read the full
        // response body.
        EXPECT_EQ(expected_content.substr(0, d.data_received().size()),
                  d.data_received());
      } else {
        EXPECT_EQ(expected_content, d.data_received());
      }
    } else {
      EXPECT_EQ(ERR_CONTENT_LENGTH_MISMATCH, d.request_status())
     
"""


```