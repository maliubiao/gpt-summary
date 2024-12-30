Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `net/url_request/url_request_unittest.cc` file. They are interested in:

1. **General functionality:** What does this part of the code do?
2. **Relationship to JavaScript:** Does it interact with JavaScript, and if so, how?
3. **Logic and examples:**  Can logical scenarios be derived with example inputs and outputs?
4. **Common user/programming errors:** Are there common mistakes related to this code?
5. **Debugging context:** How might a user end up interacting with this code, providing debugging clues?
6. **Summary:** A concise summary of the code's purpose.

The code consists of various test cases (`TEST_F`) within a larger unit test file. These test cases focus on the `URLRequest` class and its behavior, particularly related to HTTP requests and redirects.

Here's a breakdown of the provided test cases:

*   `RedirectLoadTiming`: Tests the timing information associated with a redirect, ensuring a new socket is used and timing is recorded correctly.
*   `MultipleRedirectTest`: Checks the handling of multiple server-side redirects.
*   `RedirectEscaping`: Verifies that URLs in redirects are properly escaped.
*   `DelegateInfoBeforeStart`: Tests the logging of delegate information before a request is started.
*   `NetworkDelegateInfo`: Examines the logging of delegate information from a `NetworkDelegate`.
*   `NetworkDelegateInfoRedirect`: Similar to the previous one but focuses on redirects.
*   `URLRequestDelegateInfo`:  Tests logging delegate information from a `URLRequest::Delegate`.
*   `URLRequestDelegateInfoOnRedirect`: Checks delegate info logging during redirects.
*   `URLRequestDelegateOnRedirectCancelled`: Focuses on scenarios where a request is cancelled during redirects and how delegate information is handled.
*   `RedirectWithAdditionalHeadersTest`: Verifies the ability to add request headers during a redirect.
*   `RedirectWithHeaderRemovalTest`: Checks the removal of request headers during a redirect.
*   `CancelAfterStart`: Tests cancelling a request after it has been started.
*   `CancelInResponseStarted`: Tests cancelling a request within the `OnResponseStarted` callback.

Based on these observations, the core functionality is testing different aspects of `URLRequest`, especially how it handles HTTP redirects and interactions with delegates.

Let's address each of the user's requests:
这是 `net/url_request/url_request_unittest.cc` 文件的一部分，主要功能是 **测试 `URLRequest` 类的 HTTP 重定向行为以及与 `NetworkDelegate` 和 `URLRequest::Delegate` 的交互，特别是关于异步委托信息记录和取消请求的场景**。

由于这是第 7 部分，共 17 部分，我们可以推断出这个文件整体上涵盖了 `URLRequest` 类的各种功能测试，而这部分专注于 HTTP 特定的重定向和委托交互。

**1. 功能列举:**

*   **`RedirectLoadTiming`**: 测试重定向请求的加载时序信息，例如 DNS 查询、连接建立等，并验证重定向后是否使用了新的 socket 连接。
*   **`MultipleRedirectTest`**: 测试处理多个连续的服务器端重定向的能力。
*   **`RedirectEscaping`**: 验证在重定向过程中，URL 中的特殊字符是否被正确转义。
*   **`DelegateInfoBeforeStart`**: 测试在请求开始前记录委托信息的功能。
*   **`NetworkDelegateInfo`**: 测试 `NetworkDelegate` 在请求生命周期中记录委托信息的功能，例如在 `OnBeforeURLRequest`, `OnBeforeStartTransaction`, `OnHeadersReceived` 等阶段。
*   **`NetworkDelegateInfoRedirect`**: 类似于 `NetworkDelegateInfo`，但专注于在 HTTP 重定向场景下 `NetworkDelegate` 的委托信息记录。
*   **`URLRequestDelegateInfo`**: 测试 `URLRequest::Delegate` 在请求生命周期中记录委托信息的功能，例如在 `OnResponseStarted` 和 `OnReadCompleted` 等阶段。
*   **`URLRequestDelegateInfoOnRedirect`**: 类似于 `URLRequestDelegateInfo`，但专注于在 HTTP 重定向场景下 `URLRequest::Delegate` 的委托信息记录。
*   **`URLRequestDelegateOnRedirectCancelled`**: 测试在 HTTP 重定向过程中取消请求时，`URLRequest::Delegate` 的委托信息记录情况。
*   **`RedirectWithAdditionalHeadersTest`**: 测试在重定向发生时，通过 `URLRequest` 添加额外的请求头。
*   **`RedirectWithHeaderRemovalTest`**: 测试在重定向发生时，通过 `URLRequest` 移除请求头。
*   **`CancelAfterStart`**: 测试在 `URLRequest` 启动后立即取消请求的行为。
*   **`CancelInResponseStarted`**: 测试在 `URLRequest::Delegate` 的 `OnResponseStarted` 回调中取消请求的行为。

**2. 与 JavaScript 的关系举例说明:**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它测试的网络功能是 Web 浏览器的核心，与 JavaScript 的网络请求 API (例如 `fetch`, `XMLHttpRequest`) 息息相关。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` 发起一个请求到一个会发生重定向的 URL：

```javascript
fetch('https://example.com/redirect-me')
  .then(response => {
    console.log('请求完成:', response.url);
  });
```

当浏览器执行这段 JavaScript 代码时，底层的网络栈（包括这段 C++ 代码测试的 `URLRequest`）会处理这个请求。

*   **`RedirectLoadTiming`**:  C++ 代码的测试确保了浏览器能够正确记录重定向过程中的 DNS 查询、连接建立等时序信息，这对于 JavaScript 开发者分析网络性能至关重要。
*   **`MultipleRedirectTest`**:  测试保证了即使 `https://example.com/redirect-me` 经过多次服务器端跳转，浏览器也能正确处理，最终将用户导航到最终的目标 URL，并通知 JavaScript 请求已完成。
*   **`RedirectEscaping`**:  如果重定向 URL 包含特殊字符，C++ 代码的测试确保了这些字符被正确转义，避免了 JavaScript 应用程序接收到错误的 URL。
*   **`DelegateInfo` 相关的测试**: 虽然 JavaScript 不直接操作这些委托，但浏览器内部使用它们来处理各种网络事件。这些测试确保了浏览器内部逻辑的正确性，间接保证了 JavaScript 网络请求的可靠性。
*   **`RedirectWithAdditionalHeadersTest` 和 `RedirectWithHeaderRemovalTest`**: 一些高级的 JavaScript 网络请求 API 允许开发者在重定向时修改请求头。C++ 代码的测试验证了浏览器是否正确实现了这些功能。
*   **`CancelAfterStart` 和 `CancelInResponseStarted`**:  如果 JavaScript 使用 `AbortController` 来取消一个 `fetch` 请求，底层的 `URLRequest` 对象会被取消。C++ 的这些测试确保了取消操作的正确性。

**3. 逻辑推理、假设输入与输出:**

**示例：`RedirectLoadTiming`**

*   **假设输入:**
    *   HTTP 测试服务器运行在本地。
    *   一个 URL `/server-redirect?http://localhost:<port>/` 会返回一个 302 重定向到 `/`。
    *   发起一个对 `/server-redirect?http://localhost:<port>/` 的 HTTP GET 请求。
*   **预期输出:**
    *   `d.response_started_count()` 为 1 (最终响应开始)。
    *   `d.received_redirect_count()` 为 1 (收到一个重定向)。
    *   `req->url()` 为 `http://localhost:<port>/` (最终请求的 URL)。
    *   `req->original_url()` 为 `http://localhost:<port>/server-redirect?http://localhost:<port>/` (原始请求的 URL)。
    *   `req->url_chain()` 包含两个 URL，分别是原始 URL 和重定向后的 URL。
    *   `load_timing_info_before_redirect` 和 `load_timing_info` 包含正确的时序信息，且 `socket_log_id` 不同，表明重定向使用了新的 socket。
    *   `load_timing_info_before_redirect.receive_headers_end` 早于 `load_timing_info.connect_timing.connect_start`。

**示例：`MultipleRedirectTest`**

*   **假设输入:**
    *   HTTP 测试服务器运行在本地。
    *   一个 URL `/server-redirect?http://localhost:<port>/redirect-intermediate` 会重定向到 `/redirect-intermediate`。
    *   `/redirect-intermediate` 会重定向到 `/`。
    *   发起一个对 `/server-redirect?http://localhost:<port>/redirect-intermediate` 的 HTTP GET 请求。
*   **预期输出:**
    *   `d.response_started_count()` 为 1。
    *   `d.received_redirect_count()` 为 2。
    *   `req->url()` 为 `http://localhost:<port>/`.
    *   `req->original_url()` 为原始请求的 URL。
    *   `req->url_chain()` 包含三个 URL，分别是原始 URL 和两个重定向后的 URL。

**4. 涉及用户或编程常见的使用错误:**

*   **URL 重定向循环:**  服务器配置错误可能导致无限重定向循环。虽然这段代码主要测试客户端行为，但它确保了客户端能够正确处理并可能限制或报告这种循环。
*   **不正确的 URL 转义:** 如果服务器在重定向时没有正确转义 URL 中的特殊字符，可能会导致客户端请求失败或访问错误的资源。`RedirectEscaping` 测试确保了客户端能够处理这种情况。
*   **在不恰当的时机修改请求头:**  例如，在请求已经发出后尝试修改请求头。虽然 `RedirectWithAdditionalHeadersTest` 展示了在重定向时修改请求头的能力，但这需要在 `OnReceivedRedirect` 回调中进行。在其他时机修改可能会导致不可预测的行为。
*   **忘记处理重定向:**  某些情况下，开发者可能需要手动处理重定向（例如，获取中间的重定向 URL）。这段测试覆盖了 `URLRequest` 自动处理重定向的情况，也间接提醒开发者需要理解何时以及如何干预重定向过程。
*   **取消请求后继续操作:**  在 `CancelAfterStart` 和 `CancelInResponseStarted` 测试中，即使请求被取消，`OnResponseStarted` 仍然会被调用。常见的错误是在取消请求后没有正确处理后续的回调，导致程序出现错误状态。

**5. 用户操作如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个网页时遇到了网络问题，例如：

1. **用户输入一个 URL 并访问，但页面加载缓慢或卡住。**
2. **用户打开 Chrome 的开发者工具 (DevTools)。**
3. **在 "Network" (网络) 标签页中，用户可以看到请求的状态是 "Pending" (等待中) 或者看到多次重定向。**
4. **为了深入分析问题，用户可能会启用 DevTools 的 "Preserve log" (保留日志) 选项，以便在页面跳转时保留网络请求记录。**
5. **如果涉及到重定向，用户可能会看到一系列的请求，每个请求都有不同的 URL 和状态码 (例如 301, 302)。**
6. **如果怀疑是浏览器处理重定向的逻辑有问题，或者想了解重定向过程中的详细信息（例如请求头、时序），Chromium 的开发者可能会查看 `net/url_request/url_request.cc` 和相关的源代码，包括 `url_request_unittest.cc` 中的测试用例，来理解 `URLRequest` 的行为。**
7. **如果启用了 NetLog (通过 `chrome://net-export/`)，开发者可以捕获更详细的网络事件日志，其中包括 `DELEGATE_INFO` 等事件，这些事件对应于 `NetworkDelegate` 和 `URLRequest::Delegate` 的操作，与这里的 `DelegateInfoBeforeStart`, `NetworkDelegateInfo`, `URLRequestDelegateInfo` 等测试用例相关。**
8. **如果涉及到取消请求的情况，例如用户点击了 "停止" 按钮，或者网页使用了 JavaScript 的 `AbortController`，开发者可能会关注 `CancelAfterStart` 和 `CancelInResponseStarted` 相关的代码和测试用例。**

因此，当开发者调试与 Chrome 浏览器网络请求相关的 bug，特别是关于 HTTP 重定向、请求头修改、委托交互或请求取消的问题时，`net/url_request/url_request_unittest.cc` 中的这些测试用例可以作为理解代码行为和验证修复方案的重要参考。

**6. 功能归纳 (第 7 部分):**

这部分 `url_request_unittest.cc` 的主要功能是 **针对 `URLRequest` 类的 HTTP 重定向行为进行详细的单元测试，涵盖了重定向的时序、多次重定向的处理、URL 转义、与 `NetworkDelegate` 和 `URLRequest::Delegate` 的异步委托信息交互、以及请求取消等关键场景**。 这些测试确保了 `URLRequest` 在处理 HTTP 重定向时的正确性和健壮性。

Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共17部分，请归纳一下它的功能

"""
     << " Parameter = \"" << test_file << "\"";
    }
  }
}

TEST_F(URLRequestTestHTTP, RedirectLoadTiming) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL destination_url = http_test_server()->GetURL("/");
  GURL original_url =
      http_test_server()->GetURL("/server-redirect?" + destination_url.spec());
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_EQ(1, d.received_redirect_count());
  EXPECT_EQ(destination_url, req->url());
  EXPECT_EQ(original_url, req->original_url());
  ASSERT_EQ(2U, req->url_chain().size());
  EXPECT_EQ(original_url, req->url_chain()[0]);
  EXPECT_EQ(destination_url, req->url_chain()[1]);

  LoadTimingInfo load_timing_info_before_redirect;
  EXPECT_TRUE(default_network_delegate().GetLoadTimingInfoBeforeRedirect(
      &load_timing_info_before_redirect));
  TestLoadTimingNotReused(load_timing_info_before_redirect,
                          CONNECT_TIMING_HAS_DNS_TIMES);

  LoadTimingInfo load_timing_info;
  req->GetLoadTimingInfo(&load_timing_info);
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);

  // Check that a new socket was used on redirect, since the server does not
  // supposed keep-alive sockets, and that the times before the redirect are
  // before the ones recorded for the second request.
  EXPECT_NE(load_timing_info_before_redirect.socket_log_id,
            load_timing_info.socket_log_id);
  EXPECT_LE(load_timing_info_before_redirect.receive_headers_end,
            load_timing_info.connect_timing.connect_start);
}

TEST_F(URLRequestTestHTTP, MultipleRedirectTest) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL destination_url = http_test_server()->GetURL("/");
  GURL middle_redirect_url =
      http_test_server()->GetURL("/server-redirect?" + destination_url.spec());
  GURL original_url = http_test_server()->GetURL("/server-redirect?" +
                                                 middle_redirect_url.spec());
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_EQ(2, d.received_redirect_count());
  EXPECT_EQ(destination_url, req->url());
  EXPECT_EQ(original_url, req->original_url());
  ASSERT_EQ(3U, req->url_chain().size());
  EXPECT_EQ(original_url, req->url_chain()[0]);
  EXPECT_EQ(middle_redirect_url, req->url_chain()[1]);
  EXPECT_EQ(destination_url, req->url_chain()[2]);
}

// This is a regression test for https://crbug.com/942073.
TEST_F(URLRequestTestHTTP, RedirectEscaping) {
  ASSERT_TRUE(http_test_server()->Start());

  // Assemble the destination URL as a string so it is not escaped by GURL.
  GURL destination_base = http_test_server()->GetURL("/defaultresponse");
  // Add a URL fragment of U+2603 unescaped, U+2603 escaped, and then a UTF-8
  // encoding error.
  std::string destination_url =
      destination_base.spec() + "#\xE2\x98\x83_%E2%98%83_\xE0\xE0";
  // Redirect resolution should percent-escape bytes and preserve the UTF-8
  // error at the end.
  std::string destination_escaped =
      destination_base.spec() + "#%E2%98%83_%E2%98%83_%E0%E0";
  GURL original_url = http_test_server()->GetURL(
      "/server-redirect?" +
      base::EscapeQueryParamValue(destination_url, false));
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_EQ(1, d.received_redirect_count());
  EXPECT_EQ(destination_escaped, req->url().spec());
  EXPECT_EQ(original_url, req->original_url());
  ASSERT_EQ(2U, req->url_chain().size());
  EXPECT_EQ(original_url, req->url_chain()[0]);
  EXPECT_EQ(destination_escaped, req->url_chain()[1].spec());
}

// First and second pieces of information logged by delegates to URLRequests.
const char kFirstDelegateInfo[] = "Wonderful delegate";
const char16_t kFirstDelegateInfo16[] = u"Wonderful delegate";
const char kSecondDelegateInfo[] = "Exciting delegate";
const char16_t kSecondDelegateInfo16[] = u"Exciting delegate";

// Logs delegate information to a URLRequest.  The first string is logged
// synchronously on Start(), using DELEGATE_INFO_DEBUG_ONLY.  The second is
// logged asynchronously, using DELEGATE_INFO_DISPLAY_TO_USER.  Then
// another asynchronous call is used to clear the delegate information
// before calling a callback.  The object then deletes itself.
class AsyncDelegateLogger : public base::RefCounted<AsyncDelegateLogger> {
 public:
  using Callback = base::OnceCallback<void()>;

  AsyncDelegateLogger(const AsyncDelegateLogger&) = delete;
  AsyncDelegateLogger& operator=(const AsyncDelegateLogger&) = delete;

  // Each time delegate information is added to the URLRequest, the resulting
  // load state is checked.  The expected load state after each request is
  // passed in as an argument.
  static void Run(URLRequest* url_request,
                  LoadState expected_first_load_state,
                  LoadState expected_second_load_state,
                  LoadState expected_third_load_state,
                  Callback callback) {
    // base::MakeRefCounted<AsyncDelegateLogger> is unavailable here, since the
    // constructor of AsyncDelegateLogger is private.
    auto logger = base::WrapRefCounted(new AsyncDelegateLogger(
        url_request, expected_first_load_state, expected_second_load_state,
        expected_third_load_state, std::move(callback)));
    logger->Start();
  }

  // Checks that the log entries, starting with log_position, contain the
  // DELEGATE_INFO NetLog events that an AsyncDelegateLogger should have
  // recorded.  Returns the index of entry after the expected number of
  // events this logged, or entries.size() if there aren't enough entries.
  static size_t CheckDelegateInfo(const std::vector<NetLogEntry>& entries,
                                  size_t log_position) {
    // There should be 4 DELEGATE_INFO events: Two begins and two ends.
    if (log_position + 3 >= entries.size()) {
      ADD_FAILURE() << "Not enough log entries";
      return entries.size();
    }
    std::string delegate_info;
    EXPECT_EQ(NetLogEventType::DELEGATE_INFO, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::BEGIN, entries[log_position].phase);
    EXPECT_EQ(
        kFirstDelegateInfo,
        GetStringValueFromParams(entries[log_position], "delegate_blocked_by"));

    ++log_position;
    EXPECT_EQ(NetLogEventType::DELEGATE_INFO, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);

    ++log_position;
    EXPECT_EQ(NetLogEventType::DELEGATE_INFO, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::BEGIN, entries[log_position].phase);
    EXPECT_EQ(
        kSecondDelegateInfo,
        GetStringValueFromParams(entries[log_position], "delegate_blocked_by"));

    ++log_position;
    EXPECT_EQ(NetLogEventType::DELEGATE_INFO, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);

    return log_position + 1;
  }

 private:
  friend class base::RefCounted<AsyncDelegateLogger>;

  AsyncDelegateLogger(URLRequest* url_request,
                      LoadState expected_first_load_state,
                      LoadState expected_second_load_state,
                      LoadState expected_third_load_state,
                      Callback callback)
      : url_request_(url_request),
        expected_first_load_state_(expected_first_load_state),
        expected_second_load_state_(expected_second_load_state),
        expected_third_load_state_(expected_third_load_state),
        callback_(std::move(callback)) {}

  ~AsyncDelegateLogger() = default;

  void Start() {
    url_request_->LogBlockedBy(kFirstDelegateInfo);
    LoadStateWithParam load_state = url_request_->GetLoadState();
    EXPECT_EQ(expected_first_load_state_, load_state.state);
    EXPECT_NE(kFirstDelegateInfo16, load_state.param);
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&AsyncDelegateLogger::LogSecondDelegate, this));
  }

  void LogSecondDelegate() {
    url_request_->LogAndReportBlockedBy(kSecondDelegateInfo);
    LoadStateWithParam load_state = url_request_->GetLoadState();
    EXPECT_EQ(expected_second_load_state_, load_state.state);
    if (expected_second_load_state_ == LOAD_STATE_WAITING_FOR_DELEGATE) {
      EXPECT_EQ(kSecondDelegateInfo16, load_state.param);
    } else {
      EXPECT_NE(kSecondDelegateInfo16, load_state.param);
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AsyncDelegateLogger::LogComplete, this));
  }

  void LogComplete() {
    url_request_->LogUnblocked();
    LoadStateWithParam load_state = url_request_->GetLoadState();
    EXPECT_EQ(expected_third_load_state_, load_state.state);
    if (expected_second_load_state_ == LOAD_STATE_WAITING_FOR_DELEGATE)
      EXPECT_EQ(std::u16string(), load_state.param);
    std::move(callback_).Run();
  }

  raw_ptr<URLRequest> url_request_;
  const int expected_first_load_state_;
  const int expected_second_load_state_;
  const int expected_third_load_state_;
  Callback callback_;
};

// NetworkDelegate that logs delegate information before a request is started,
// before headers are sent, when headers are read, and when auth information
// is requested.  Uses AsyncDelegateLogger.
class AsyncLoggingNetworkDelegate : public TestNetworkDelegate {
 public:
  AsyncLoggingNetworkDelegate() = default;

  AsyncLoggingNetworkDelegate(const AsyncLoggingNetworkDelegate&) = delete;
  AsyncLoggingNetworkDelegate& operator=(const AsyncLoggingNetworkDelegate&) =
      delete;

  ~AsyncLoggingNetworkDelegate() override = default;

  // NetworkDelegate implementation.
  int OnBeforeURLRequest(URLRequest* request,
                         CompletionOnceCallback callback,
                         GURL* new_url) override {
    // TestNetworkDelegate always completes synchronously.
    CHECK_NE(ERR_IO_PENDING, TestNetworkDelegate::OnBeforeURLRequest(
                                 request, base::NullCallback(), new_url));
    return RunCallbackAsynchronously(request, std::move(callback));
  }

  int OnBeforeStartTransaction(
      URLRequest* request,
      const HttpRequestHeaders& headers,
      OnBeforeStartTransactionCallback callback) override {
    // TestNetworkDelegate always completes synchronously.
    CHECK_NE(ERR_IO_PENDING, TestNetworkDelegate::OnBeforeStartTransaction(
                                 request, headers, base::NullCallback()));
    return RunCallbackAsynchronously(
        request, base::BindOnce(
                     [](OnBeforeStartTransactionCallback callback, int result) {
                       std::move(callback).Run(result, std::nullopt);
                     },
                     std::move(callback)));
  }

  int OnHeadersReceived(
      URLRequest* request,
      CompletionOnceCallback callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      const IPEndPoint& endpoint,
      std::optional<GURL>* preserve_fragment_on_redirect_url) override {
    // TestNetworkDelegate always completes synchronously.
    CHECK_NE(ERR_IO_PENDING,
             TestNetworkDelegate::OnHeadersReceived(
                 request, base::NullCallback(), original_response_headers,
                 override_response_headers, endpoint,
                 preserve_fragment_on_redirect_url));
    return RunCallbackAsynchronously(request, std::move(callback));
  }

 private:
  static int RunCallbackAsynchronously(URLRequest* request,
                                       CompletionOnceCallback callback) {
    AsyncDelegateLogger::Run(request, LOAD_STATE_WAITING_FOR_DELEGATE,
                             LOAD_STATE_WAITING_FOR_DELEGATE,
                             LOAD_STATE_WAITING_FOR_DELEGATE,
                             base::BindOnce(std::move(callback), OK));
    return ERR_IO_PENDING;
  }
};

// URLRequest::Delegate that logs delegate information when the headers
// are received, when each read completes, and during redirects.  Uses
// AsyncDelegateLogger.  Can optionally cancel a request in any phase.
//
// Inherits from TestDelegate to reuse the TestDelegate code to handle
// advancing to the next step in most cases, as well as cancellation.
class AsyncLoggingUrlRequestDelegate : public TestDelegate {
 public:
  enum CancelStage {
    NO_CANCEL = 0,
    CANCEL_ON_RECEIVED_REDIRECT,
    CANCEL_ON_RESPONSE_STARTED,
    CANCEL_ON_READ_COMPLETED
  };

  explicit AsyncLoggingUrlRequestDelegate(CancelStage cancel_stage)
      : cancel_stage_(cancel_stage) {
    if (cancel_stage == CANCEL_ON_RECEIVED_REDIRECT)
      set_cancel_in_received_redirect(true);
    else if (cancel_stage == CANCEL_ON_RESPONSE_STARTED)
      set_cancel_in_response_started(true);
    else if (cancel_stage == CANCEL_ON_READ_COMPLETED)
      set_cancel_in_received_data(true);
  }

  AsyncLoggingUrlRequestDelegate(const AsyncLoggingUrlRequestDelegate&) =
      delete;
  AsyncLoggingUrlRequestDelegate& operator=(
      const AsyncLoggingUrlRequestDelegate&) = delete;

  ~AsyncLoggingUrlRequestDelegate() override = default;

  // URLRequest::Delegate implementation:
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    *defer_redirect = true;
    AsyncDelegateLogger::Run(
        request, LOAD_STATE_WAITING_FOR_DELEGATE,
        LOAD_STATE_WAITING_FOR_DELEGATE, LOAD_STATE_WAITING_FOR_DELEGATE,
        base::BindOnce(
            &AsyncLoggingUrlRequestDelegate::OnReceivedRedirectLoggingComplete,
            base::Unretained(this), request, redirect_info));
  }

  void OnResponseStarted(URLRequest* request, int net_error) override {
    AsyncDelegateLogger::Run(
        request, LOAD_STATE_WAITING_FOR_DELEGATE,
        LOAD_STATE_WAITING_FOR_DELEGATE, LOAD_STATE_WAITING_FOR_DELEGATE,
        base::BindOnce(
            &AsyncLoggingUrlRequestDelegate::OnResponseStartedLoggingComplete,
            base::Unretained(this), request, net_error));
  }

  void OnReadCompleted(URLRequest* request, int bytes_read) override {
    AsyncDelegateLogger::Run(
        request, LOAD_STATE_IDLE, LOAD_STATE_IDLE, LOAD_STATE_IDLE,
        base::BindOnce(
            &AsyncLoggingUrlRequestDelegate::AfterReadCompletedLoggingComplete,
            base::Unretained(this), request, bytes_read));
  }

 private:
  void OnReceivedRedirectLoggingComplete(URLRequest* request,
                                         const RedirectInfo& redirect_info) {
    bool defer_redirect = false;
    TestDelegate::OnReceivedRedirect(request, redirect_info, &defer_redirect);
    // FollowDeferredRedirect should not be called after cancellation.
    if (cancel_stage_ == CANCEL_ON_RECEIVED_REDIRECT)
      return;
    if (!defer_redirect) {
      request->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                                      std::nullopt /* modified_headers */);
    }
  }

  void OnResponseStartedLoggingComplete(URLRequest* request, int net_error) {
    // The parent class continues the request.
    TestDelegate::OnResponseStarted(request, net_error);
  }

  void AfterReadCompletedLoggingComplete(URLRequest* request, int bytes_read) {
    // The parent class continues the request.
    TestDelegate::OnReadCompleted(request, bytes_read);
  }

  const CancelStage cancel_stage_;
};

// Tests handling of delegate info before a request starts.
TEST_F(URLRequestTestHTTP, DelegateInfoBeforeStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate request_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_net_log(NetLog::Get());
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY,
        &request_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    LoadStateWithParam load_state = r->GetLoadState();
    EXPECT_EQ(LOAD_STATE_IDLE, load_state.state);
    EXPECT_EQ(std::u16string(), load_state.param);

    AsyncDelegateLogger::Run(
        r.get(), LOAD_STATE_WAITING_FOR_DELEGATE,
        LOAD_STATE_WAITING_FOR_DELEGATE, LOAD_STATE_IDLE,
        base::BindOnce(&URLRequest::Start, base::Unretained(r.get())));

    request_delegate.RunUntilComplete();

    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_EQ(OK, request_delegate.request_status());
  }

  auto entries = net_log_observer_.GetEntries();
  size_t log_position = ExpectLogContainsSomewhereAfter(
      entries, 0, NetLogEventType::DELEGATE_INFO, NetLogEventPhase::BEGIN);

  log_position = AsyncDelegateLogger::CheckDelegateInfo(entries, log_position);

  // Nothing else should add any delegate info to the request.
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(entries, log_position + 1,
                                             NetLogEventType::DELEGATE_INFO));
}

// Tests handling of delegate info from a network delegate.
TEST_F(URLRequestTestHTTP, NetworkDelegateInfo) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate request_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<AsyncLoggingNetworkDelegate>());
  context_builder->set_net_log(NetLog::Get());
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/simple.html"), DEFAULT_PRIORITY,
        &request_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    LoadStateWithParam load_state = r->GetLoadState();
    EXPECT_EQ(LOAD_STATE_IDLE, load_state.state);
    EXPECT_EQ(std::u16string(), load_state.param);

    r->Start();
    request_delegate.RunUntilComplete();

    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_EQ(OK, request_delegate.request_status());
    EXPECT_EQ(1, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());

  size_t log_position = 0;
  auto entries = net_log_observer_.GetEntries();
  static const NetLogEventType kExpectedEvents[] = {
      NetLogEventType::NETWORK_DELEGATE_BEFORE_URL_REQUEST,
      NetLogEventType::NETWORK_DELEGATE_BEFORE_START_TRANSACTION,
      NetLogEventType::NETWORK_DELEGATE_HEADERS_RECEIVED,
  };
  for (NetLogEventType event : kExpectedEvents) {
    SCOPED_TRACE(NetLogEventTypeToString(event));
    log_position = ExpectLogContainsSomewhereAfter(
        entries, log_position + 1, event, NetLogEventPhase::BEGIN);

    log_position =
        AsyncDelegateLogger::CheckDelegateInfo(entries, log_position + 1);

    ASSERT_LT(log_position, entries.size());
    EXPECT_EQ(event, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);
  }

  EXPECT_FALSE(LogContainsEntryWithTypeAfter(entries, log_position + 1,
                                             NetLogEventType::DELEGATE_INFO));
}

// Tests handling of delegate info from a network delegate in the case of an
// HTTP redirect.
TEST_F(URLRequestTestHTTP, NetworkDelegateInfoRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate request_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<AsyncLoggingNetworkDelegate>());
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/server-redirect?simple.html"),
        DEFAULT_PRIORITY, &request_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    LoadStateWithParam load_state = r->GetLoadState();
    EXPECT_EQ(LOAD_STATE_IDLE, load_state.state);
    EXPECT_EQ(std::u16string(), load_state.param);

    r->Start();
    request_delegate.RunUntilComplete();

    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_EQ(OK, request_delegate.request_status());
    EXPECT_EQ(2, network_delegate.created_requests());
    EXPECT_EQ(0, network_delegate.destroyed_requests());
  }
  EXPECT_EQ(1, network_delegate.destroyed_requests());

  size_t log_position = 0;
  auto entries = net_log_observer_.GetEntries();
  static const NetLogEventType kExpectedEvents[] = {
      NetLogEventType::NETWORK_DELEGATE_BEFORE_URL_REQUEST,
      NetLogEventType::NETWORK_DELEGATE_BEFORE_START_TRANSACTION,
      NetLogEventType::NETWORK_DELEGATE_HEADERS_RECEIVED,
  };
  for (NetLogEventType event : kExpectedEvents) {
    SCOPED_TRACE(NetLogEventTypeToString(event));
    log_position = ExpectLogContainsSomewhereAfter(
        entries, log_position + 1, event, NetLogEventPhase::BEGIN);

    log_position =
        AsyncDelegateLogger::CheckDelegateInfo(entries, log_position + 1);

    ASSERT_LT(log_position, entries.size());
    EXPECT_EQ(event, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);
  }

  // The URLRequest::Delegate then gets informed about the redirect.
  log_position = ExpectLogContainsSomewhereAfter(
      entries, log_position + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_RECEIVED_REDIRECT,
      NetLogEventPhase::BEGIN);

  // The NetworkDelegate logged information in the same three events as before.
  for (NetLogEventType event : kExpectedEvents) {
    SCOPED_TRACE(NetLogEventTypeToString(event));
    log_position = ExpectLogContainsSomewhereAfter(
        entries, log_position + 1, event, NetLogEventPhase::BEGIN);

    log_position =
        AsyncDelegateLogger::CheckDelegateInfo(entries, log_position + 1);

    ASSERT_LT(log_position, entries.size());
    EXPECT_EQ(event, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);
  }

  EXPECT_FALSE(LogContainsEntryWithTypeAfter(entries, log_position + 1,
                                             NetLogEventType::DELEGATE_INFO));
}

// Tests handling of delegate info from a URLRequest::Delegate.
TEST_F(URLRequestTestHTTP, URLRequestDelegateInfo) {
  ASSERT_TRUE(http_test_server()->Start());

  AsyncLoggingUrlRequestDelegate request_delegate(
      AsyncLoggingUrlRequestDelegate::NO_CANCEL);
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_net_log(NetLog::Get());
  auto context = context_builder->Build();

  {
    // A chunked response with delays between chunks is used to make sure that
    // attempts by the URLRequest delegate to log information while reading the
    // body are ignored.  Since they are ignored, this test is robust against
    // the possibility of multiple reads being combined in the unlikely event
    // that it occurs.
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/chunked?waitBetweenChunks=20"),
        DEFAULT_PRIORITY, &request_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    LoadStateWithParam load_state = r->GetLoadState();
    r->Start();
    request_delegate.RunUntilComplete();

    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_EQ(OK, request_delegate.request_status());
  }

  auto entries = net_log_observer_.GetEntries();

  size_t log_position = 0;

  // The delegate info should only have been logged on header complete.  Other
  // times it should silently be ignored.
  log_position = ExpectLogContainsSomewhereAfter(
      entries, log_position + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED,
      NetLogEventPhase::BEGIN);

  log_position =
      AsyncDelegateLogger::CheckDelegateInfo(entries, log_position + 1);

  ASSERT_LT(log_position, entries.size());
  EXPECT_EQ(NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED,
            entries[log_position].type);
  EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);

  EXPECT_FALSE(LogContainsEntryWithTypeAfter(entries, log_position + 1,
                                             NetLogEventType::DELEGATE_INFO));
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, log_position + 1,
      NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED));
}

// Tests handling of delegate info from a URLRequest::Delegate in the case of
// an HTTP redirect.
TEST_F(URLRequestTestHTTP, URLRequestDelegateInfoOnRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  AsyncLoggingUrlRequestDelegate request_delegate(
      AsyncLoggingUrlRequestDelegate::NO_CANCEL);
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_net_log(NetLog::Get());
  auto context = context_builder->Build();

  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        http_test_server()->GetURL("/server-redirect?simple.html"),
        DEFAULT_PRIORITY, &request_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    LoadStateWithParam load_state = r->GetLoadState();
    r->Start();
    request_delegate.RunUntilComplete();

    EXPECT_EQ(200, r->GetResponseCode());
    EXPECT_EQ(OK, request_delegate.request_status());
  }

  auto entries = net_log_observer_.GetEntries();

  // Delegate info should only have been logged in OnReceivedRedirect and
  // OnResponseStarted.
  size_t log_position = 0;
  static const NetLogEventType kExpectedEvents[] = {
      NetLogEventType::URL_REQUEST_DELEGATE_RECEIVED_REDIRECT,
      NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED,
  };
  for (NetLogEventType event : kExpectedEvents) {
    SCOPED_TRACE(NetLogEventTypeToString(event));
    log_position = ExpectLogContainsSomewhereAfter(entries, log_position, event,
                                                   NetLogEventPhase::BEGIN);

    log_position =
        AsyncDelegateLogger::CheckDelegateInfo(entries, log_position + 1);

    ASSERT_LT(log_position, entries.size());
    EXPECT_EQ(event, entries[log_position].type);
    EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);
  }

  EXPECT_FALSE(LogContainsEntryWithTypeAfter(entries, log_position + 1,
                                             NetLogEventType::DELEGATE_INFO));
}

// Tests handling of delegate info from a URLRequest::Delegate in the case of
// an HTTP redirect, with cancellation at various points.
TEST_F(URLRequestTestHTTP, URLRequestDelegateOnRedirectCancelled) {
  ASSERT_TRUE(http_test_server()->Start());

  const AsyncLoggingUrlRequestDelegate::CancelStage kCancelStages[] = {
      AsyncLoggingUrlRequestDelegate::CANCEL_ON_RECEIVED_REDIRECT,
      AsyncLoggingUrlRequestDelegate::CANCEL_ON_RESPONSE_STARTED,
      AsyncLoggingUrlRequestDelegate::CANCEL_ON_READ_COMPLETED,
  };

  for (auto cancel_stage : kCancelStages) {
    AsyncLoggingUrlRequestDelegate request_delegate(cancel_stage);
    RecordingNetLogObserver net_log_observer;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_net_log(NetLog::Get());
    auto context = context_builder->Build();

    {
      std::unique_ptr<URLRequest> r(context->CreateRequest(
          http_test_server()->GetURL("/server-redirect?simple.html"),
          DEFAULT_PRIORITY, &request_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
      LoadStateWithParam load_state = r->GetLoadState();
      r->Start();
      request_delegate.RunUntilComplete();
      EXPECT_EQ(ERR_ABORTED, request_delegate.request_status());

      // Spin the message loop to run AsyncDelegateLogger task(s) posted after
      // the |request_delegate| completion task.
      base::RunLoop().RunUntilIdle();
    }

    auto entries = net_log_observer.GetEntries();

    // Delegate info is always logged in both OnReceivedRedirect and
    // OnResponseStarted.  In the CANCEL_ON_RECEIVED_REDIRECT, the
    // OnResponseStarted delegate call is after cancellation, but logging is
    // still currently supported in that call.
    size_t log_position = 0;
    static const NetLogEventType kExpectedEvents[] = {
        NetLogEventType::URL_REQUEST_DELEGATE_RECEIVED_REDIRECT,
        NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED,
    };
    for (NetLogEventType event : kExpectedEvents) {
      SCOPED_TRACE(NetLogEventTypeToString(event));
      log_position = ExpectLogContainsSomewhereAfter(
          entries, log_position, event, NetLogEventPhase::BEGIN);

      log_position =
          AsyncDelegateLogger::CheckDelegateInfo(entries, log_position + 1);

      ASSERT_LT(log_position, entries.size());
      EXPECT_EQ(event, entries[log_position].type);
      EXPECT_EQ(NetLogEventPhase::END, entries[log_position].phase);
    }

    EXPECT_FALSE(LogContainsEntryWithTypeAfter(entries, log_position + 1,
                                               NetLogEventType::DELEGATE_INFO));
  }
}

namespace {

const char kExtraHeader[] = "Allow-Snafu";
const char kExtraValue[] = "fubar";

class RedirectWithAdditionalHeadersDelegate : public TestDelegate {
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    TestDelegate::OnReceivedRedirect(request, redirect_info, defer_redirect);
    request->SetExtraRequestHeaderByName(kExtraHeader, kExtraValue, false);
  }
};

}  // namespace

TEST_F(URLRequestTestHTTP, RedirectWithAdditionalHeadersTest) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL destination_url =
      http_test_server()->GetURL("/echoheader?" + std::string(kExtraHeader));
  GURL original_url =
      http_test_server()->GetURL("/server-redirect?" + destination_url.spec());
  RedirectWithAdditionalHeadersDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  const HttpRequestHeaders& headers = req->extra_request_headers();
  EXPECT_EQ(kExtraValue, headers.GetHeader(kExtraHeader));
  EXPECT_FALSE(req->is_pending());
  EXPECT_FALSE(req->is_redirecting());
  EXPECT_EQ(kExtraValue, d.data_received());
}

namespace {

const char kExtraHeaderToRemove[] = "To-Be-Removed";

class RedirectWithHeaderRemovalDelegate : public TestDelegate {
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    TestDelegate::OnReceivedRedirect(request, redirect_info, defer_redirect);
    request->RemoveRequestHeaderByName(kExtraHeaderToRemove);
  }
};

}  // namespace

TEST_F(URLRequestTestHTTP, RedirectWithHeaderRemovalTest) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL destination_url = http_test_server()->GetURL(
      "/echoheader?" + std::string(kExtraHeaderToRemove));
  GURL original_url =
      http_test_server()->GetURL("/server-redirect?" + destination_url.spec());
  RedirectWithHeaderRemovalDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetExtraRequestHeaderByName(kExtraHeaderToRemove, "dummy", false);
  req->Start();
  d.RunUntilComplete();

  const HttpRequestHeaders& headers = req->extra_request_headers();
  EXPECT_FALSE(headers.GetHeader(kExtraHeaderToRemove));
  EXPECT_FALSE(req->is_pending());
  EXPECT_FALSE(req->is_redirecting());
  EXPECT_EQ("None", d.data_received());
}

TEST_F(URLRequestTestHTTP, CancelAfterStart) {
  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        GURL("http://www.google.com/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    r->Cancel();

    d.RunUntilComplete();

    // We expect to receive OnResponseStarted even though the request has been
    // cancelled.
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
  }
}

TEST_F(URLRequestTestHTTP, CancelInResponseStarted) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    d.set_cancel_in_response_started(true);

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_start
"""


```