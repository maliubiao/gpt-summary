Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. They are specifically interested in:

1. **Overall Functionality:** What does this part of the code do?
2. **Relationship to JavaScript:**  Is there any connection to how JavaScript works with networking?
3. **Logical Reasoning:** Can I infer inputs and outputs based on the code?
4. **Common Errors:** What mistakes might users or programmers make that this code helps to catch or handle?
5. **User Journey:** How does a user's interaction eventually lead to this code being executed (for debugging)?
6. **Summary of Functionality (Part 3 of 4):**  Synthesize the functionality covered in this specific snippet.

Let's break down the code section by section to address these points:

* **`TEST_F(URLRequestHttpJobWithBrotliSupportTest, BrotliAdvertisementOverHttp)`:**  Tests that an HTTP request can handle a response with `Content-Length`.
* **`TEST_F(URLRequestHttpJobWithBrotliSupportTest, BrotliAdvertisement)`:** Tests that an HTTPS request sends an `Accept-Encoding` header including `br` (Brotli) and handles a response with `Content-Length`.
* **`TEST_F(URLRequestHttpJobWithBrotliSupportTest, DefaultAcceptEncodingOverriden)`:** Tests that the `Accept-Encoding` header can be overridden programmatically to specify which compression algorithms are acceptable.
* **`TEST_F(URLRequestHttpJobWithCheckClearTextPermittedTest, AndroidCleartextPermittedTest)`:** (Android-specific) Tests the enforcement of cleartext (HTTP) traffic policies on Android. It checks if HTTP is allowed based on the configured security policy.
* **`TEST_F(URLRequestHttpJobWebSocketTest, RejectedWithoutCreateHelper)`:** (WebSockets) Tests that a WebSocket connection attempt is rejected if a necessary helper object is not provided.
* **`TEST_F(URLRequestHttpJobWebSocketTest, CreateHelperPassedThrough)`:** (WebSockets) Tests that a WebSocket connection can be established successfully when the correct helper object and headers are set.
* **Cookie-related tests (`TEST_F(URLRequestHttpJobTest, CookieSchemeRequestSchemeHistogram)`, `TEST_F(URLRequestHttpJobTest, PrivacyMode_ExclusionReason)`, `TEST_F(URLRequestHttpJobTest, IndividuallyBlockedCookies)`, `TEST_F(URLRequestHttpJobTest, GetFirstPartySetsCacheFilterMatchInfo)`, `TEST_F(URLRequestHttpJobTest, SetPartitionedCookie)`, `TEST_F(URLRequestHttpJobTest, PartitionedCookiePrivacyMode)`)**:  These tests cover various aspects of cookie handling:
    * Logging cookie scheme and request scheme combinations.
    * How privacy mode affects cookie inclusion.
    * The ability of the network delegate to selectively block cookies.
    * Interaction with the First-Party Sets cache filter.
    * Functionality of partitioned cookies.
    * How privacy mode interacts with partitioned cookies.

**Planning the Response:**

I will structure the response to address each of the user's points explicitly, drawing information from the code snippets. I will highlight the testing nature of the code and its focus on verifying the correct behavior of the `URLRequestHttpJob` class.
这是chromium网络栈的源代码文件 `net/url_request/url_request_http_job_unittest.cc` 的一部分，主要功能是**测试 `URLRequestHttpJob` 类的各种HTTP请求处理逻辑**。 这是该文件测试的**第三部分**，集中在以下几个方面：

1. **Brotli 压缩支持测试:**  验证 `URLRequestHttpJob` 是否能正确处理服务器声明支持 Brotli 压缩的情况，包括通过 HTTP 和 HTTPS 连接，以及用户自定义 `Accept-Encoding` 头部。
2. **Android 明文 (Cleartext) 策略检查测试:**  （仅限 Android 平台）测试 `URLRequestHttpJob` 如何根据 Android 系统配置检查是否允许发起明文 HTTP 请求。
3. **WebSocket 支持测试:** 验证 `URLRequestHttpJob` 如何处理 WebSocket 连接请求，包括在缺少必要的辅助对象时拒绝连接，以及在提供正确配置时成功建立连接。
4. **Cookie 相关功能测试:**  涵盖了各种 cookie 相关的测试，包括：
    * 记录 cookie 设置来源协议和请求协议的组合情况（用于统计分析）。
    * 测试在隐私模式下，cookie 因为用户偏好而被排除的场景。
    * 测试网络层代理如何选择性地阻止某些 cookie 的发送。
    * 测试 First-Party Sets 缓存过滤器如何影响缓存命中。
    * 测试 `Partitioned` cookie 的设置和在不同 top-level site 下的行为。
    * 测试隐私模式下对 `Partitioned` cookie 的影响。

**与 JavaScript 功能的关系：**

`URLRequestHttpJob` 类是 Chromium 网络栈的核心组件，负责处理底层的 HTTP 请求。虽然这段 C++ 代码本身不包含 JavaScript 代码，但它直接支撑着浏览器中 JavaScript 发起的网络请求。

**举例说明:**

* 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 对象向服务器发起 HTTP 请求时，Chromium 浏览器最终会创建并使用 `URLRequestHttpJob` 对象来执行这个请求。
* 例如，如果 JavaScript 代码设置了 `credentials: 'include'` 选项，浏览器会尝试发送与当前域名相关的 cookie。 这部分 C++ 代码中的 cookie 测试就验证了 `URLRequestHttpJob` 是否正确地读取和附加 cookie 到请求头中。
* 再比如，如果 JavaScript 代码请求的资源支持 Brotli 压缩，浏览器会自动在请求头中添加 `Accept-Encoding: br`。  `BrotliAdvertisement` 测试就验证了 `URLRequestHttpJob` 在这种情况下是否能正确处理服务器的 Brotli 压缩响应。
* 对于 WebSocket，JavaScript 可以使用 `WebSocket` API 创建一个 WebSocket 连接。 `URLRequestHttpJobWebSocketTest` 就是在测试当 JavaScript 尝试建立 WebSocket 连接时，底层的网络栈是否按照协议正确工作。

**逻辑推理、假设输入与输出：**

**示例 1： `BrotliAdvertisementOverHttp` 测试**

* **假设输入:**
    * 请求的 URL 是 `http://www.example.com`。
    * 服务器返回的响应头包含 `Content-Length: 12`。
    * 服务器返回的响应体是 "Test Content"。
* **预期输出:**
    * `delegate.request_status()` 为 `OK` (请求成功)。
    * `request->received_response_content_length()` 等于 `12`。
    * `request->GetTotalSentBytes()` 等于发送请求头的字节数。
    * `request->GetTotalReceivedBytes()` 等于接收响应头和响应体的字节数。

**示例 2： `AndroidCleartextPermittedTest` 测试**

* **假设输入:**
    * 请求的 URL 是 `http://blocked.test/`。
    * Android 系统安全策略配置为不允许访问 `blocked.test` 的明文 HTTP 请求 (`cleartext_permitted` 为 `false`)。
* **预期输出:**
    * `delegate.request_status()` 为 `ERR_CLEARTEXT_NOT_PERMITTED` (请求被阻止)。

**示例 3： `CreateHelperPassedThrough` 测试 (WebSocket)**

* **假设输入:**
    * 请求的 URL 是 `ws://www.example.org`。
    * 请求头中设置了正确的 WebSocket 握手头部，例如 `Connection: Upgrade`, `Upgrade: websocket` 等。
    * 提供了正确的 `TestWebSocketHandshakeStreamCreateHelper` 辅助对象。
    * 服务器返回了 WebSocket 握手成功的响应。
* **预期输出:**
    * `delegate_.request_status()` 为 `OK` (WebSocket 连接建立成功)。
    * `delegate_.response_completed()` 为 `true`。

**用户或编程常见的使用错误：**

* **Brotli 支持：** 用户可能错误地认为所有服务器都支持 Brotli 压缩，或者编程时没有正确处理不支持 Brotli 的服务器返回的错误。这段代码的测试确保了在声明支持 Brotli 的情况下能够正常工作。
* **Android 明文策略：**  开发者在 Android 应用中可能会尝试发起明文 HTTP 请求，但如果设备的安全策略禁止了这种行为，请求将会失败。  这段测试模拟了这种情况，帮助开发者理解为什么他们的请求可能会被阻止。
* **WebSocket：** 开发者可能忘记在创建 WebSocket 请求时设置必要的头部信息 (如 `Upgrade`, `Connection`) 或者缺少建立连接所需的辅助对象。 `RejectedWithoutCreateHelper` 测试就模拟了这种错误。
* **Cookie：**
    * 开发者可能不理解 cookie 的作用域和安全性，错误地设置了 `Secure` 或 `HttpOnly` 等属性，导致 cookie 在某些情况下无法发送或访问。 `CookieSchemeRequestSchemeHistogram` 测试帮助监控这些设置是否符合预期。
    * 在隐私模式下，开发者可能期望所有 cookie 都能正常发送，但实际上某些 cookie 会因为用户偏好而被阻止。 `PrivacyMode_ExclusionReason` 测试展示了这种情况。
    * 开发者可能希望阻止某些 cookie 的发送，可以使用网络层代理来实现。 `IndividuallyBlockedCookies` 测试验证了这种机制。
    * 对 Partitioned cookie 的理解不足，可能导致在跨 top-level site 的场景下无法正确获取 cookie。 `SetPartitionedCookie` 和 `PartitionedCookiePrivacyMode` 测试帮助验证 Partitioned cookie 的行为。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTP 或 HTTPS 网址并回车，或者点击一个链接。** 这会触发浏览器发起一个网络请求。
2. **浏览器内核的网络栈开始处理该请求。**  对于 HTTP/HTTPS 请求，会创建 `URLRequestHttpJob` 对象。
3. **`URLRequestHttpJob` 对象根据请求的 URL 和其他参数，与服务器建立连接。**
4. **如果服务器在响应头中声明支持 Brotli 压缩 (例如，通过 `Content-Encoding: br`)，`URLRequestHttpJob` 会尝试解压响应内容。**  `BrotliAdvertisement` 测试模拟了这种情况，如果用户遇到页面加载缓慢或者内容显示异常，开发者可以检查是否是 Brotli 解压环节出现了问题。
5. **对于 Android 平台，如果用户访问的是一个 HTTP 网址，系统会检查是否允许该应用发起明文请求。** 如果策略不允许，请求会被阻止。 `AndroidCleartextPermittedTest` 相关的代码会在这个检查过程中被调用。
6. **如果用户尝试建立 WebSocket 连接 (例如，通过 JavaScript 的 `new WebSocket(...)`)，浏览器会创建一个 `URLRequest`，并将其标记为 WebSocket 请求。** `URLRequestHttpJobWebSocketTest` 覆盖了 WebSocket 连接建立过程中的各种情况，如果 WebSocket 连接失败，开发者可以查看网络日志，确认握手过程是否正确，或者是否缺少必要的头部信息。
7. **在发送请求前，`URLRequestHttpJob` 会根据 cookie 策略，从 CookieStore 中读取相关的 cookie，并添加到请求头中。**  cookie 相关的测试覆盖了各种 cookie 的读取和过滤场景，如果用户发现网站的 cookie 没有正确发送，或者隐私设置没有生效，开发者可以关注这部分代码的执行情况。
8. **如果使用了 First-Party Sets，并且启用了缓存过滤，`GetFirstPartySetsCacheFilterMatchInfo` 测试相关的逻辑会判断是否需要绕过缓存。** 如果用户发现某个网站的资源总是从网络加载而不是缓存，可以检查 First-Party Sets 的配置是否影响了缓存行为。
9. **如果网站设置了 `Partitioned` cookie，`SetPartitionedCookie` 和 `PartitionedCookiePrivacyMode` 测试相关的逻辑会确保 cookie 仅在相同的 top-level site 下发送。** 如果用户发现 Partitioned cookie 的行为不符合预期，可以检查这部分代码的执行。

**功能归纳（第 3 部分）：**

这部分 `net/url_request/url_request_http_job_unittest.cc` 代码主要测试了 `URLRequestHttpJob` 在以下方面的功能：

* **处理 Brotli 压缩的 HTTP 响应。**
* **在 Android 平台上遵守明文 HTTP 请求策略。**
* **处理 WebSocket 连接请求，包括握手过程。**
* **各种复杂的 Cookie 处理逻辑，包括来源协议记录、隐私模式下的排除、选择性阻止、与 First-Party Sets 的交互以及 Partitioned cookie 的行为。**

总而言之，这部分测试确保了 `URLRequestHttpJob` 能够正确、安全、有效地处理各种 HTTP 请求场景，并且与平台特性 (如 Android 的明文策略) 和新的 Web 标准 (如 WebSocket 和 Partitioned Cookie) 兼容。

Prompt: 
```
这是目录为net/url_request/url_request_http_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
isementOverHttp) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);
  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithBrotliSupportTest, BrotliAdvertisement) {
  net::SSLSocketDataProvider ssl_socket_data_provider(net::ASYNC, net::OK);
  ssl_socket_data_provider.next_proto = kProtoHTTP11;
  ssl_socket_data_provider.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
  ASSERT_TRUE(ssl_socket_data_provider.ssl_info.cert);
  socket_factory_.AddSSLSocketDataProvider(&ssl_socket_data_provider);

  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate, br\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("https://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);
  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithBrotliSupportTest, DefaultAcceptEncodingOverriden) {
  struct {
    base::flat_set<net::SourceStream::SourceType> accepted_types;
    const char* expected_request_headers;
  } kTestCases[] = {{{net::SourceStream::SourceType::TYPE_DEFLATE},
                     "GET / HTTP/1.1\r\n"
                     "Host: www.example.com\r\n"
                     "Connection: keep-alive\r\n"
                     "User-Agent: \r\n"
                     "Accept-Encoding: deflate\r\n"
                     "Accept-Language: en-us,fr\r\n\r\n"},
                    {{},
                     "GET / HTTP/1.1\r\n"
                     "Host: www.example.com\r\n"
                     "Connection: keep-alive\r\n"
                     "User-Agent: \r\n"
                     "Accept-Language: en-us,fr\r\n\r\n"},
                    {{net::SourceStream::SourceType::TYPE_GZIP},
                     "GET / HTTP/1.1\r\n"
                     "Host: www.example.com\r\n"
                     "Connection: keep-alive\r\n"
                     "User-Agent: \r\n"
                     "Accept-Encoding: gzip\r\n"
                     "Accept-Language: en-us,fr\r\n\r\n"},
                    {{net::SourceStream::SourceType::TYPE_GZIP,
                      net::SourceStream::SourceType::TYPE_DEFLATE},
                     "GET / HTTP/1.1\r\n"
                     "Host: www.example.com\r\n"
                     "Connection: keep-alive\r\n"
                     "User-Agent: \r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "Accept-Language: en-us,fr\r\n\r\n"},
                    {{net::SourceStream::SourceType::TYPE_BROTLI},
                     "GET / HTTP/1.1\r\n"
                     "Host: www.example.com\r\n"
                     "Connection: keep-alive\r\n"
                     "User-Agent: \r\n"
                     "Accept-Encoding: br\r\n"
                     "Accept-Language: en-us,fr\r\n\r\n"},
                    {{net::SourceStream::SourceType::TYPE_BROTLI,
                      net::SourceStream::SourceType::TYPE_GZIP,
                      net::SourceStream::SourceType::TYPE_DEFLATE},
                     "GET / HTTP/1.1\r\n"
                     "Host: www.example.com\r\n"
                     "Connection: keep-alive\r\n"
                     "User-Agent: \r\n"
                     "Accept-Encoding: gzip, deflate, br\r\n"
                     "Accept-Language: en-us,fr\r\n\r\n"}};

  for (auto test : kTestCases) {
    net::SSLSocketDataProvider ssl_socket_data_provider(net::ASYNC, net::OK);
    ssl_socket_data_provider.next_proto = kProtoHTTP11;
    ssl_socket_data_provider.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
    ASSERT_TRUE(ssl_socket_data_provider.ssl_info.cert);
    socket_factory_.AddSSLSocketDataProvider(&ssl_socket_data_provider);

    MockWrite writes[] = {MockWrite(test.expected_request_headers)};
    MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                 "Content-Length: 12\r\n\r\n"),
                        MockRead("Test Content")};
    StaticSocketDataProvider socket_data(reads, writes);
    socket_factory_.AddSocketDataProvider(&socket_data);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request = context_->CreateRequest(
        GURL("https://www.example.com"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS);
    request->set_accepted_stream_types(test.accepted_types);
    request->Start();
    delegate.RunUntilComplete();
    EXPECT_THAT(delegate.request_status(), IsOk());
    socket_factory_.ResetNextMockIndexes();
  }
}

#if BUILDFLAG(IS_ANDROID)
class URLRequestHttpJobWithCheckClearTextPermittedTest
    : public TestWithTaskEnvironment {
 protected:
  URLRequestHttpJobWithCheckClearTextPermittedTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->SetHttpTransactionFactoryForTesting(
        std::make_unique<MockNetworkLayer>());
    context_builder->set_check_cleartext_permitted(true);
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    context_ = context_builder->Build();
  }

  MockClientSocketFactory socket_factory_;
  std::unique_ptr<URLRequestContext> context_;
};

TEST_F(URLRequestHttpJobWithCheckClearTextPermittedTest,
       AndroidCleartextPermittedTest) {
  static constexpr struct TestCase {
    const char* url;
    bool cleartext_permitted;
    bool should_block;
    int expected_per_host_call_count;
    int expected_default_call_count;
  } kTestCases[] = {
      {"http://unblocked.test/", true, false, 1, 0},
      {"https://unblocked.test/", true, false, 0, 0},
      {"http://blocked.test/", false, true, 1, 0},
      {"https://blocked.test/", false, false, 0, 0},
      // If determining the per-host cleartext policy causes an
      // IllegalArgumentException (because the hostname is invalid),
      // the default configuration should be applied, and the
      // exception should not cause a JNI error.
      {"http://./", false, true, 1, 1},
      {"http://./", true, false, 1, 1},
      // Even if the host name would be considered invalid, https
      // schemes should not trigger cleartext policy checks.
      {"https://./", false, false, 0, 0},
  };

  JNIEnv* env = base::android::AttachCurrentThread();
  for (const TestCase& test : kTestCases) {
    Java_AndroidNetworkLibraryTestUtil_setUpSecurityPolicyForTesting(
        env, test.cleartext_permitted);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request =
        context_->CreateRequest(GURL(test.url), DEFAULT_PRIORITY, &delegate,
                                TRAFFIC_ANNOTATION_FOR_TESTS);
    request->Start();
    delegate.RunUntilComplete();

    if (test.should_block) {
      EXPECT_THAT(delegate.request_status(),
                  IsError(ERR_CLEARTEXT_NOT_PERMITTED));
    } else {
      // Should fail since there's no test server running
      EXPECT_THAT(delegate.request_status(), IsError(ERR_FAILED));
    }
    EXPECT_EQ(
        Java_AndroidNetworkLibraryTestUtil_getPerHostCleartextCheckCount(env),
        test.expected_per_host_call_count);
    EXPECT_EQ(
        Java_AndroidNetworkLibraryTestUtil_getDefaultCleartextCheckCount(env),
        test.expected_default_call_count);
  }
}
#endif

#if BUILDFLAG(ENABLE_WEBSOCKETS)

class URLRequestHttpJobWebSocketTest : public TestWithTaskEnvironment {
 protected:
  URLRequestHttpJobWebSocketTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    context_ = context_builder->Build();
    req_ =
        context_->CreateRequest(GURL("ws://www.example.org"), DEFAULT_PRIORITY,
                                &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS,
                                /*is_for_websockets=*/true);
  }

  std::unique_ptr<URLRequestContext> context_;
  MockClientSocketFactory socket_factory_;
  TestDelegate delegate_;
  std::unique_ptr<URLRequest> req_;
};

TEST_F(URLRequestHttpJobWebSocketTest, RejectedWithoutCreateHelper) {
  req_->Start();
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsError(ERR_DISALLOWED_URL_SCHEME));
}

TEST_F(URLRequestHttpJobWebSocketTest, CreateHelperPassedThrough) {
  HttpRequestHeaders headers;
  headers.SetHeader("Connection", "Upgrade");
  headers.SetHeader("Upgrade", "websocket");
  headers.SetHeader("Origin", "http://www.example.org");
  headers.SetHeader("Sec-WebSocket-Version", "13");
  req_->SetExtraRequestHeaders(headers);

  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead reads[] = {
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
      MockRead(ASYNC, 0)};

  StaticSocketDataProvider data(reads, writes);
  socket_factory_.AddSocketDataProvider(&data);

  auto websocket_stream_create_helper =
      std::make_unique<TestWebSocketHandshakeStreamCreateHelper>();

  req_->SetUserData(kWebSocketHandshakeUserDataKey,
                    std::move(websocket_stream_create_helper));
  req_->SetLoadFlags(LOAD_DISABLE_CACHE);
  req_->Start();
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsOk());
  EXPECT_TRUE(delegate_.response_completed());

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

bool SetAllCookies(CookieMonster* cm, const CookieList& list) {
  DCHECK(cm);
  ResultSavingCookieCallback<CookieAccessResult> callback;
  cm->SetAllCookiesAsync(list, callback.MakeCallback());
  callback.WaitUntilDone();
  return callback.result().status.IsInclude();
}

bool CreateAndSetCookie(CookieStore* cs,
                        const GURL& url,
                        const std::string& cookie_line) {
  auto cookie =
      CanonicalCookie::CreateForTesting(url, cookie_line, base::Time::Now());
  if (!cookie)
    return false;
  DCHECK(cs);
  ResultSavingCookieCallback<CookieAccessResult> callback;
  cs->SetCanonicalCookieAsync(std::move(cookie), url,
                              CookieOptions::MakeAllInclusive(),
                              callback.MakeCallback());
  callback.WaitUntilDone();
  return callback.result().status.IsInclude();
}

void RunRequest(URLRequestContext* context, const GURL& url) {
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context->CreateRequest(
      url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  // Make this a laxly same-site context to allow setting
  // SameSite=Lax-by-default cookies.
  request->set_site_for_cookies(SiteForCookies::FromUrl(url));
  request->Start();
  delegate.RunUntilComplete();
}

}  // namespace

TEST_F(URLRequestHttpJobTest, CookieSchemeRequestSchemeHistogram) {
  base::HistogramTester histograms;
  const std::string test_histogram = "Cookie.CookieSchemeRequestScheme";

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::make_unique<CookieMonster>(
      /*store=*/nullptr, /*net_log=*/nullptr));
  auto context = context_builder->Build();

  auto* cookie_store = static_cast<CookieMonster*>(context->cookie_store());

  // Secure set cookie marked as Unset source scheme.
  // Using port 7 because it fails the transaction without sending a request and
  // prevents a timeout due to the fake addresses. Because we only need the
  // headers to be generated (and thus the histogram filled) and not actually
  // sent this is acceptable.
  GURL nonsecure_url_for_unset1("http://unset1.example:7");
  GURL secure_url_for_unset1("https://unset1.example:7");

  // Normally the source scheme would be set by
  // CookieMonster::SetCanonicalCookie(), however we're using SetAllCookies() to
  // bypass the source scheme check in order to test the kUnset state which
  // would normally only happen during an existing cookie DB version upgrade.
  std::unique_ptr<CanonicalCookie> unset_cookie1 =
      CanonicalCookie::CreateForTesting(
          secure_url_for_unset1, "NoSourceSchemeHttps=val", base::Time::Now());
  unset_cookie1->SetSourceScheme(net::CookieSourceScheme::kUnset);

  CookieList list1 = {*unset_cookie1};
  EXPECT_TRUE(SetAllCookies(cookie_store, list1));
  RunRequest(context.get(), nonsecure_url_for_unset1);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kUnsetCookieScheme, 1);
  RunRequest(context.get(), secure_url_for_unset1);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kUnsetCookieScheme, 2);

  // Nonsecure set cookie marked as unset source scheme.
  GURL nonsecure_url_for_unset2("http://unset2.example:7");
  GURL secure_url_for_unset2("https://unset2.example:7");

  std::unique_ptr<CanonicalCookie> unset_cookie2 =
      CanonicalCookie::CreateForTesting(nonsecure_url_for_unset2,
                                        "NoSourceSchemeHttp=val",
                                        base::Time::Now());
  unset_cookie2->SetSourceScheme(net::CookieSourceScheme::kUnset);

  CookieList list2 = {*unset_cookie2};
  EXPECT_TRUE(SetAllCookies(cookie_store, list2));
  RunRequest(context.get(), nonsecure_url_for_unset2);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kUnsetCookieScheme, 3);
  RunRequest(context.get(), secure_url_for_unset2);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kUnsetCookieScheme, 4);

  // Secure set cookie with source scheme marked appropriately.
  GURL nonsecure_url_for_secure_set("http://secureset.example:7");
  GURL secure_url_for_secure_set("https://secureset.example:7");

  EXPECT_TRUE(CreateAndSetCookie(cookie_store, secure_url_for_secure_set,
                                 "SecureScheme=val"));
  RunRequest(context.get(), nonsecure_url_for_secure_set);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kSecureSetNonsecureRequest, 1);
  RunRequest(context.get(), secure_url_for_secure_set);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kSecureSetSecureRequest, 1);

  // Nonsecure set cookie with source scheme marked appropriately.
  GURL nonsecure_url_for_nonsecure_set("http://nonsecureset.example:7");
  GURL secure_url_for_nonsecure_set("https://nonsecureset.example:7");

  EXPECT_TRUE(CreateAndSetCookie(cookie_store, nonsecure_url_for_nonsecure_set,
                                 "NonSecureScheme=val"));
  RunRequest(context.get(), nonsecure_url_for_nonsecure_set);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kNonsecureSetNonsecureRequest, 1);
  RunRequest(context.get(), secure_url_for_nonsecure_set);
  histograms.ExpectBucketCount(
      test_histogram,
      URLRequestHttpJob::CookieRequestScheme::kNonsecureSetSecureRequest, 1);
}

// Test that cookies are annotated with the appropriate exclusion reason when
// privacy mode is enabled.
TEST_F(URLRequestHttpJobTest, PrivacyMode_ExclusionReason) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::make_unique<CookieMonster>(
      /*store=*/nullptr, /*net_log=*/nullptr));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<FilteringTestNetworkDelegate>());
  auto context = context_builder->Build();

  // Set cookies.
  {
    TestDelegate d;
    GURL test_url = test_server.GetURL(
        "/set-cookie?one=1&"
        "two=2&"
        "three=3");
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(*context, test_url, &d);
    req->Start();
    d.RunUntilComplete();
  }

  // Get cookies.
  network_delegate.ResetAnnotateCookiesCalledCount();
  ASSERT_EQ(0, network_delegate.annotate_cookies_called_count());
  // We want to fetch cookies from the cookie store, so we use the
  // NetworkDelegate to override the privacy mode (rather than setting it via
  // `allow_credentials`, since that skips querying the cookie store).
  network_delegate.set_force_privacy_mode(true);
  TestDelegate d;
  std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
      *context, test_server.GetURL("/echoheader?Cookie"), &d);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ("None", d.data_received());
  EXPECT_THAT(
      req->maybe_sent_cookies(),
      UnorderedElementsAre(
          MatchesCookieWithAccessResult(
              MatchesCookieWithNameSourceType("one", CookieSourceType::kHTTP),
              MatchesCookieAccessResult(
                  HasExactlyExclusionReasonsForTesting(
                      std::vector<CookieInclusionStatus::ExclusionReason>{
                          CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}),
                  _, _, _)),
          MatchesCookieWithAccessResult(
              MatchesCookieWithNameSourceType("two", CookieSourceType::kHTTP),
              MatchesCookieAccessResult(
                  HasExactlyExclusionReasonsForTesting(
                      std::vector<CookieInclusionStatus::ExclusionReason>{
                          CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}),
                  _, _, _)),
          MatchesCookieWithAccessResult(
              MatchesCookieWithNameSourceType("three", CookieSourceType::kHTTP),
              MatchesCookieAccessResult(
                  HasExactlyExclusionReasonsForTesting(
                      std::vector<CookieInclusionStatus::ExclusionReason>{
                          CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}),
                  _, _, _))));

  EXPECT_EQ(0, network_delegate.annotate_cookies_called_count());
}

// Test that cookies are allowed to be selectively blocked by the network
// delegate.
TEST_F(URLRequestHttpJobTest, IndividuallyBlockedCookies) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  auto network_delegate = std::make_unique<FilteringTestNetworkDelegate>();
  network_delegate->set_block_get_cookies_by_name(true);
  network_delegate->SetCookieFilter("blocked_");
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::make_unique<CookieMonster>(
      /*store=*/nullptr, /*net_log=*/nullptr));
  context_builder->set_network_delegate(std::move(network_delegate));
  auto context = context_builder->Build();

  // Set cookies.
  {
    TestDelegate d;
    GURL test_url = test_server.GetURL(
        "/set-cookie?blocked_one=1;SameSite=Lax;Secure&"
        "blocked_two=1;SameSite=Lax;Secure&"
        "allowed=1;SameSite=Lax;Secure");
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(*context, test_url, &d);
    req->Start();
    d.RunUntilComplete();
  }

  // Get cookies.
  TestDelegate d;
  std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
      *context, test_server.GetURL("/echoheader?Cookie"), &d);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ("allowed=1", d.data_received());
  EXPECT_THAT(
      req->maybe_sent_cookies(),
      UnorderedElementsAre(
          MatchesCookieWithAccessResult(
              MatchesCookieWithNameSourceType("blocked_one",
                                              CookieSourceType::kHTTP),
              MatchesCookieAccessResult(
                  HasExactlyExclusionReasonsForTesting(
                      std::vector<CookieInclusionStatus::ExclusionReason>{
                          CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}),
                  _, _, _)),
          MatchesCookieWithAccessResult(
              MatchesCookieWithNameSourceType("blocked_two",
                                              CookieSourceType::kHTTP),
              MatchesCookieAccessResult(
                  HasExactlyExclusionReasonsForTesting(
                      std::vector<CookieInclusionStatus::ExclusionReason>{
                          CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}),
                  _, _, _)),
          MatchesCookieWithAccessResult(
              MatchesCookieWithNameSourceType("allowed",
                                              CookieSourceType::kHTTP),
              MatchesCookieAccessResult(IsInclude(), _, _, _))));
}

namespace {

int content_count = 0;
std::unique_ptr<test_server::HttpResponse> IncreaseOnRequest(
    const test_server::HttpRequest& request) {
  auto http_response = std::make_unique<test_server::BasicHttpResponse>();
  http_response->set_content(base::NumberToString(content_count));
  content_count++;
  return std::move(http_response);
}

void ResetContentCount() {
  content_count = 0;
}

}  // namespace

TEST_F(URLRequestHttpJobTest, GetFirstPartySetsCacheFilterMatchInfo) {
  EmbeddedTestServer https_test(EmbeddedTestServer::TYPE_HTTPS);
  https_test.AddDefaultHandlers(base::FilePath());
  https_test.RegisterRequestHandler(base::BindRepeating(&IncreaseOnRequest));
  ASSERT_TRUE(https_test.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto cookie_access_delegate = std::make_unique<TestCookieAccessDelegate>();
  TestCookieAccessDelegate* raw_cookie_access_delegate =
      cookie_access_delegate.get();
  auto cm = std::make_unique<CookieMonster>(nullptr, nullptr);
  cm->SetCookieAccessDelegate(std::move(cookie_access_delegate));
  context_builder->SetCookieStore(std::move(cm));
  auto context = context_builder->Build();

  const GURL kTestUrl = https_test.GetURL("/");
  const IsolationInfo kTestIsolationInfo =
      IsolationInfo::CreateForInternalRequest(url::Origin::Create(kTestUrl));
  {
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        kTestUrl, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kTestIsolationInfo);
    req->set_allow_credentials(false);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("0", delegate.data_received());
  }
  {  // Test using the cached response.
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        kTestUrl, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetLoadFlags(LOAD_SKIP_CACHE_VALIDATION);
    req->set_allow_credentials(false);
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("0", delegate.data_received());
  }

  // Set cache filter and test cache is bypassed because the request site has a
  // matched entry in the filter and its response cache was stored before being
  // marked to clear.
  const int64_t kClearAtRunId = 3;
  const int64_t kBrowserRunId = 3;
  FirstPartySetsCacheFilter cache_filter(
      {{SchemefulSite(kTestUrl), kClearAtRunId}}, kBrowserRunId);
  raw_cookie_access_delegate->set_first_party_sets_cache_filter(
      std::move(cache_filter));
  {
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        kTestUrl, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetLoadFlags(LOAD_SKIP_CACHE_VALIDATION);
    req->set_allow_credentials(false);
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("1", delegate.data_received());
  }

  ResetContentCount();
}

TEST_F(URLRequestHttpJobTest, SetPartitionedCookie) {
  EmbeddedTestServer https_test(EmbeddedTestServer::TYPE_HTTPS);
  https_test.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(https_test.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::make_unique<CookieMonster>(
      /*store=*/nullptr, /*net_log=*/nullptr));
  auto context = context_builder->Build();

  const url::Origin kTopFrameOrigin =
      url::Origin::Create(GURL("https://www.toplevelsite.com"));
  const IsolationInfo kTestIsolationInfo =
      IsolationInfo::CreateForInternalRequest(kTopFrameOrigin);

  {
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL(
            "/set-cookie?__Host-foo=bar;SameSite=None;Secure;Path=/"
            ";Partitioned;"),
        DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));

    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    ASSERT_TRUE(req->is_pending());
    delegate.RunUntilComplete();
  }

  {  // Test request from the same top-level site.
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("__Host-foo=bar", delegate.data_received());
  }

  {  // Test request from a different top-level site.
    const url::Origin kOtherTopFrameOrigin =
        url::Origin::Create(GURL("https://www.anothertoplevelsite.com"));
    const IsolationInfo kOtherTestIsolationInfo =
        IsolationInfo::CreateForInternalRequest(kOtherTopFrameOrigin);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kOtherTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("None", delegate.data_received());
  }

  {  // Test request from same top-level eTLD+1 but different scheme. Note that
     // although the top-level site is insecure, the endpoint setting/receiving
     // the cookie is always secure.
    const url::Origin kHttpTopFrameOrigin =
        url::Origin::Create(GURL("http://www.toplevelsite.com"));
    const IsolationInfo kHttpTestIsolationInfo =
        IsolationInfo::CreateForInternalRequest(kHttpTopFrameOrigin);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kHttpTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("None", delegate.data_received());
  }
}

TEST_F(URLRequestHttpJobTest, PartitionedCookiePrivacyMode) {
  EmbeddedTestServer https_test(EmbeddedTestServer::TYPE_HTTPS);
  https_test.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(https_test.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(
      std::make_unique<CookieMonster>(/*store=*/nullptr, /*net_log=*/nullptr));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<FilteringTestNetworkDelegate>());
  auto context = context_builder->Build();

  const url::Origin kTopFrameOrigin =
      url::Origin::Create(GURL("https://www.toplevelsite.com"));
  const IsolationInfo kTestIsolationInfo =
      IsolationInfo::CreateForInternalRequest(kTopFrameOrigin);

  {
    // Set an unpartitioned and partitioned cookie.
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL(
            "/set-cookie?__Host-partitioned=0;SameSite=None;Secure;Path=/"
            ";Partitioned;&__Host-unpartitioned=1;SameSite=None;Secure;Path=/"),
        DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    ASSERT_TRUE(req->is_pending());
    delegate.RunUntilComplete();
  }

  {  // Get both cookies when privacy mode is disabled.
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("__Host-partitioned=0; __Host-unpartitioned=1",
              delegate.data_received());
  }

  {  // Get cookies with privacy mode enabled and partitioned state allowed.
    network_delegate.set_force_privacy_mode(true);
    network_delegate.set_partitioned_state_allowed(true);
    network_delegate.SetCookieFilter("unpartitioned");
    network_delegate.set_block_get_cookies_by_name(true);
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("__Host-partitioned=0", delegate.data_received());
    auto want_exclusion_reasons =
        std::vector<CookieInclusionStatus::ExclusionReason>{};

    EXPECT_THAT(
        req->maybe_sent_cookies(),
        UnorderedElementsAre(
            MatchesCookieWithAccessResult(
                MatchesCookieWithNameSourceType("__Host-partitioned",
                                                CookieSourceType::kHTTP),
                MatchesCookieAccessResult(HasExactlyExclusionReasonsForTesting(
                                              want_exclusion_reasons),
                                          _, _, _)),
            MatchesCookieWithAccessResult(
                MatchesCookieWithNameSourceType("__Host-unpartitioned",
                                                CookieSourceType::kHTTP),
                MatchesCookieAccessResult(
                    HasExactlyExclusionReasonsForTesting(
                        std::vector<CookieInclusionStatus::ExclusionReason>{
                            CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}),
                    _, _, _))));
  }

  {  // Get cookies with privacy mode enabled and partitioned state is not
     // allowed.
    network_delegate.set_force_privacy_mode(true);
    network_delegate.set_partitioned_state_allowed(false);
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(kTestIsolationInfo);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ("None", delegate.data_received());
    EXPECT_THAT(
        req->maybe_sent_cookies(),
        UnorderedElementsAre(
            MatchesCookieWithAccessResult(
                MatchesCookieWithNameSourceType("__Host-partitioned",
                                            
"""


```