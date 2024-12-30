Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding of the Goal:**

The request asks for an analysis of a Chromium network stack test file (`http_network_transaction_unittest.cc`). The key is to understand what it tests, its relation to JavaScript (if any), logical inferences (with input/output), common errors, debugging steps, and a summary of its function within the larger context. It's also specified as part 19 of 34, hinting at a focused area within a broader testing suite.

**2. High-Level Overview of the Code:**

Skimming the code reveals a pattern:

* **`TEST_P(HttpNetworkTransactionTest, ...)`:** This indicates parameterized tests using the Google Test framework. The `HttpNetworkTransactionTest` class is the fixture.
* **`HttpRequestInfo request;`:**  This structure likely holds information about the HTTP request being simulated.
* **`request.method = ...;`**, `request.url = ...;`**, `request.extra_headers.SetHeader(...)`**:  These lines set up the properties of the request.
* **`std::unique_ptr<HttpNetworkSession> session(...)`:** This creates an instance of `HttpNetworkSession`, a core class for managing network connections.
* **`HttpNetworkTransaction trans(...)`:** This creates the object being tested – the `HttpNetworkTransaction`.
* **`MockWrite data_writes[] = { ... };`** and **`MockRead data_reads[] = { ... };`**: This is crucial. It defines the simulated network interactions – what data the client sends (`data_writes`) and what data the server (or proxy) sends back (`data_reads`).
* **`StaticSocketDataProvider data(...)`:** This sets up the mock socket behavior.
* **`session_deps_.socket_factory->AddSocketDataProvider(&data);`:** Injects the mock socket data into the network session.
* **`TestCompletionCallback callback;`**: Used for asynchronous testing.
* **`int rv = trans.Start(...)`**:  Initiates the network transaction.
* **`EXPECT_THAT(rv, IsError(ERR_IO_PENDING));`** and **`rv = callback.WaitForResult(); EXPECT_THAT(rv, IsOk());`**:  These lines check that the transaction starts asynchronously and eventually completes successfully (or with an expected error).

**3. Identifying Key Functionality Through Test Names:**

The names of the test cases are highly informative:

* `BuildRequest_WithProxyUserAgent`: Tests building a CONNECT request with a specific User-Agent when using a proxy.
* `BuildRequest_Referer`: Tests setting the Referer header.
* `BuildRequest_PostContentLengthZero`, `BuildRequest_PutContentLengthZero`, `BuildRequest_HeadContentLengthZero`: Test requests with zero content length for different HTTP methods.
* `BuildRequest_CacheControlNoCache`, `BuildRequest_CacheControlValidateCache`: Test setting Cache-Control headers for cache invalidation.
* `BuildRequest_ExtraHeaders`, `BuildRequest_ExtraHeadersStripped`: Test adding custom headers.
* `SOCKS4_HTTP_GET`, `SOCKS4_SSL_GET`, `SOCKS4_HTTP_GET_no_PAC`, `SOCKS5_HTTP_GET`, `SOCKS5_SSL_GET`: Test requests through SOCKS proxies.
* `GroupIdOrHttpStreamKeyForDirectConnections`, `GroupIdForHTTPProxyConnections`: Test how connections are grouped for connection pooling.

**4. Analyzing Individual Tests (Example: `BuildRequest_WithProxyUserAgent`):**

* **Purpose:**  Verify that the `HttpNetworkTransaction` correctly builds a `CONNECT` request for a proxy, including the `User-Agent` header if provided.
* **Input (Implicit):**  `HttpRequestInfo` with a CONNECT method and proxy settings, and potentially a custom User-Agent.
* **Output (Verification):** The `MockWrite` array (`data_writes`) asserts the exact byte sequence of the generated HTTP request, including the `User-Agent` header when present.
* **Logical Inference:** The test uses conditional logic (`if (!setting_user_agent || ... )`) to construct the expected request, demonstrating the logic for including the `User-Agent`.

**5. Identifying Potential JavaScript Relevance:**

The `User-Agent` header is the most direct connection to JavaScript. JavaScript running in a browser can influence the `User-Agent` string. Therefore, this test indirectly verifies that the network stack correctly handles requests where JavaScript has potentially modified the `User-Agent`.

**6. Identifying Potential User/Programming Errors:**

* **Incorrect Proxy Configuration:**  The SOCKS proxy tests highlight the importance of correct proxy settings. A user might incorrectly configure the proxy address or port.
* **Cache Control Misunderstandings:** The cache-related tests show how developers can use `LOAD_BYPASS_CACHE` or `LOAD_VALIDATE_CACHE`. A common error is not understanding the implications of these flags or using them incorrectly.
* **Header Case Sensitivity (or Lack Thereof):**  `BuildRequest_ExtraHeadersStripped` shows that header names are treated case-insensitively. A programmer might assume case-sensitivity and be surprised by the behavior.

**7. Tracing User Actions (Debugging Clues):**

* **Direct Navigation:**  Typing a URL in the address bar leads to direct connections.
* **Clicking Links:**  Can lead to GET requests with or without Referer headers.
* **Submitting Forms:**  Often results in POST requests.
* **Using a Proxy Server:**  Explicitly configuring a proxy in the browser settings leads to proxy-related code paths being exercised.
* **Forcing Cache Revalidation/Bypass:**  Using browser developer tools or keyboard shortcuts (like Ctrl+Shift+R) triggers cache-control related logic.

**8. Synthesizing the Summary:**

Combine the understanding of the individual tests to form a coherent picture of the file's purpose. It focuses on the request building aspect of `HttpNetworkTransaction`, ensuring it generates correct HTTP requests for various scenarios (methods, headers, proxies, caching).

**9. Addressing the "Part 19 of 34" Aspect:**

This strongly suggests that this file focuses on a specific aspect of `HttpNetworkTransaction` testing, likely the initial request formation. Other parts would likely cover response handling, error conditions, data transfer, etc.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the specific SOCKS details. Realizing that the broader theme is *request building* helps in summarizing effectively.
* The "stripped headers" test might seem minor initially, but recognizing that it touches on HTTP header case-insensitivity makes it more relevant for potential programmer errors.
* The connection to JavaScript isn't direct function calls, but understanding the role of the `User-Agent` header bridges the gap.

By following these steps, combining detailed code analysis with a high-level understanding of the testing goals, one can arrive at a comprehensive and accurate analysis like the example provided in the prompt.
好的，让我们来分析一下 `net/http/http_network_transaction_unittest.cc` 文件的这段代码片段的功能。

**功能概要**

这段代码主要用于测试 `HttpNetworkTransaction` 类在构建 HTTP 请求头方面的功能，特别是针对不同的请求场景和配置，验证其生成的请求头是否符合预期。它涵盖了以下几个主要方面：

1. **CONNECT 请求 (代理场景):**  测试在使用 HTTP 代理时，`HttpNetworkTransaction` 是否能正确构建 `CONNECT` 请求，包括是否添加 `User-Agent` 头。
2. **Referer 头:** 验证是否能根据 `HttpRequestInfo` 中的设置，正确添加 `Referer` 请求头。
3. **Content-Length 头 (特定方法):** 测试 `POST`、`PUT` 和 `HEAD` 请求在内容长度为零时，请求头的生成情况。对于 `POST` 和 `PUT` 会显式添加 `Content-Length: 0`，而 `HEAD` 则不会添加。
4. **缓存控制头:** 测试当设置了 `LOAD_BYPASS_CACHE` 和 `LOAD_VALIDATE_CACHE` 加载标志时，是否会生成相应的 `Pragma: no-cache` 和 `Cache-Control: no-cache` 或 `Cache-Control: max-age=0` 头。
5. **自定义请求头:** 验证是否能根据 `HttpRequestInfo` 中的 `extra_headers` 正确添加自定义的请求头。
6. **自定义请求头的处理 (大小写):**  测试自定义请求头在添加时，虽然设置时大小写混合，但最终发送时会保持设置时的大小写。
7. **SOCKS 代理:** 测试通过 SOCKS4 和 SOCKS5 代理发送 HTTP 和 HTTPS 请求时，`HttpNetworkTransaction` 的行为，包括是否发送正确的 SOCKS 握手信息和后续的 HTTP 请求头。
8. **连接分组 (GroupId) 和 HttpStreamKey:**  测试在直接连接和通过 HTTP 代理连接的情况下，`HttpNetworkTransaction` 如何设置连接的 `GroupId` 和 `HttpStreamKey`，这对于连接池的管理至关重要。

**与 JavaScript 的关系及举例说明**

这段 C++ 代码本身并不直接与 JavaScript 交互。然而，它所测试的网络栈功能是 JavaScript 发起网络请求的基础。当 JavaScript 代码（例如，在浏览器中运行的脚本）使用 `fetch` API 或 `XMLHttpRequest` 发起 HTTP 请求时，Chromium 的网络栈（包括 `HttpNetworkTransaction`）会负责构建和发送这些请求。

**举例说明:**

假设 JavaScript 代码执行了以下操作：

```javascript
fetch('http://www.example.org/', {
  method: 'POST',
  headers: {
    'X-Custom-Header': 'JavaScriptValue',
    'Referer': 'http://previous.page.com'
  }
});
```

这段 JavaScript 代码最终会导致 Chromium 网络栈创建一个 `HttpRequestInfo` 对象，其中包含请求方法 (`POST`)，URL (`http://www.example.org/`) 以及自定义的请求头 (`X-Custom-Header: JavaScriptValue`, `Referer: http://previous.page.com`).

`HttpNetworkTransaction` 的相关测试 (例如 `BuildRequest_PostContentLengthZero` 和 `BuildRequest_ExtraHeaders`) 确保了在处理这个来自 JavaScript 的请求时，会生成如下的 HTTP 请求头（部分）：

```
POST / HTTP/1.1
Host: www.example.org
Connection: keep-alive
X-Custom-Header: JavaScriptValue
Referer: http://previous.page.com
Content-Length: 0  // 如果请求体为空
```

**逻辑推理 (假设输入与输出)**

**示例 1:  测试 `BuildRequest_WithProxyUserAgent`**

* **假设输入:**
    * `HttpRequestInfo` 对象配置为使用 HTTP 代理 `www.example.org:443` 进行 CONNECT 请求。
    * 可选的 `setting_user_agent` 变量，假设设置为 `"MyCustomUserAgent/1.0"`.
* **输出:**
    * 如果 `setting_user_agent` 为空或长度为 0，则 `expected_request` 为:
      ```
      CONNECT www.example.org:443 HTTP/1.1\r\n
      Host: www.example.org:443\r\n
      Proxy-Connection: keep-alive\r\n\r\n
      ```
    * 如果 `setting_user_agent` 为 `"MyCustomUserAgent/1.0"`，则 `expected_request` 为:
      ```
      CONNECT www.example.org:443 HTTP/1.1\r\n
      Host: www.example.org:443\r\n
      Proxy-Connection: keep-alive\r\n
      User-Agent: MyCustomUserAgent/1.0\r\n\r\n
      ```

**示例 2: 测试 `BuildRequest_Referer`**

* **假设输入:**
    * `HttpRequestInfo` 对象，方法为 `GET`，URL 为 `http://www.example.org/`，并且 `extra_headers` 中设置了 `Referer: http://the.previous.site.com/`.
* **输出:**
    * `data_writes` 中的预期请求头包含:
      ```
      GET / HTTP/1.1\r\n
      Host: www.example.org\r\n
      Connection: keep-alive\r\n
      Referer: http://the.previous.site.com/\r\n\r\n
      ```

**用户或编程常见的使用错误及举例说明**

1. **忘记设置 Content-Length (对于需要 Request Body 的方法):**
   * **错误:** 用户在使用 `POST` 或 `PUT` 方法发送数据时，没有设置 `Content-Length` 头，或者没有正确指示请求体的长度。
   * **这段测试的意义:**  `BuildRequest_PostContentLengthZero` 和 `BuildRequest_PutContentLengthZero` 虽然测试的是长度为零的情况，但也间接验证了 `HttpNetworkTransaction` 在需要时会处理 `Content-Length` 头。
   * **用户操作:**  在 JavaScript 中使用 `fetch` 或 `XMLHttpRequest` 发送 `POST` 请求时，如果 `body` 为空或未定义，则底层需要确保 `Content-Length: 0` 被正确添加。

2. **不理解缓存控制标志的作用:**
   * **错误:** 用户可能错误地使用了 `LOAD_BYPASS_CACHE` 或 `LOAD_VALIDATE_CACHE`，导致了非预期的缓存行为。
   * **这段测试的意义:** `BuildRequest_CacheControlNoCache` 和 `BuildRequest_CacheControlValidateCache` 验证了当设置这些标志时，会生成相应的 HTTP 请求头，从而影响浏览器的缓存策略。
   * **用户操作:** 用户在浏览器中强制刷新页面（通常会发送带有 `Cache-Control: no-cache` 或类似头的请求）或开发者在代码中设置了这些加载标志。

3. **代理配置错误:**
   * **错误:** 用户配置了错误的代理服务器地址或端口，或者代理服务器需要身份验证但未提供。
   * **这段测试的意义:** `SOCKS4_HTTP_GET`， `SOCKS5_HTTP_GET` 等测试模拟了通过不同 SOCKS 代理发送请求的情况，验证了握手和请求头的正确性。
   * **用户操作:** 用户在操作系统或浏览器设置中配置了代理服务器。

**用户操作如何一步步到达这里 (调试线索)**

假设用户在浏览器中访问一个需要通过 SOCKS5 代理访问的 HTTPS 网站 `https://www.example.org/`。

1. **用户输入 URL:** 用户在浏览器地址栏输入 `https://www.example.org/` 并按下回车。
2. **代理配置检查:** 浏览器检查用户的代理设置，发现配置了 SOCKS5 代理服务器。
3. **DNS 解析:** 浏览器可能需要解析 `www.example.org` 的 IP 地址。
4. **建立连接:**
   * **SOCKS 握手:**  `HttpNetworkTransaction` 会开始与 SOCKS5 代理服务器建立 TCP 连接，并发送 SOCKS5 握手请求（对应 `SOCKS5_SSL_GET` 测试中的 `kSOCKS5GreetRequest`）。
   * **SOCKS 认证 (如果需要):**  根据代理配置，可能需要进行身份验证。
   * **SOCKS CONNECT 请求:**  `HttpNetworkTransaction` 发送 SOCKS5 CONNECT 请求，告知代理需要连接到 `www.example.org:443`（对应 `kSOCKS5ExampleOkRequest`）。
5. **建立 TLS 连接 (通过代理):** 一旦与代理的 SOCKS 连接建立成功，并且代理允许连接目标服务器，浏览器会通过该代理与目标服务器 `www.example.org` 建立 TLS 连接。
6. **发送 HTTP 请求:** `HttpNetworkTransaction` 构建并发送实际的 HTTP 请求头（对应 `SOCKS5_SSL_GET` 测试中的 `MockWrite("GET / HTTP/1.1...")`）。
7. **接收响应:**  服务器通过代理发送 HTTP 响应。

**调试线索:**  当网络请求出现问题时，开发者可以：

* **查看 NetLog:** Chromium 的 NetLog 可以记录详细的网络事件，包括 DNS 查询、连接建立、发送和接收的数据包等，这可以帮助定位问题发生在哪个阶段。
* **使用网络抓包工具:**  如 Wireshark，可以捕获网络数据包，查看实际发送的请求头和代理握手信息，与测试中预期的 `data_writes` 进行对比。
* **断点调试:**  在 Chromium 源代码中设置断点，例如在 `HttpNetworkTransaction::Start()` 或构建请求头的相关代码中，可以逐步跟踪请求的构建过程。

**第 19 部分，共 34 部分的功能归纳**

作为 34 个测试文件中的第 19 个，这个文件 `http_network_transaction_unittest.cc` 的这段代码主要专注于 **`HttpNetworkTransaction` 类在构建各种类型的 HTTP 请求头方面的单元测试**。它验证了在不同场景下（例如，使用代理、设置特定请求头、缓存控制、SOCKS 代理），`HttpNetworkTransaction` 是否能够正确生成符合 HTTP 规范的请求头。这部分测试是确保 Chromium 网络栈正确发起网络请求的关键组成部分。后续的测试部分可能会涵盖请求体的发送、响应的接收和处理、错误处理等方面。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第19部分，共34部分，请归纳一下它的功能

"""
TRAFFIC_ANNOTATION_FOR_TESTS);

      HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

      std::string expected_request;
      if (!setting_user_agent || strlen(setting_user_agent) == 0) {
        expected_request =
            "CONNECT www.example.org:443 HTTP/1.1\r\n"
            "Host: www.example.org:443\r\n"
            "Proxy-Connection: keep-alive\r\n\r\n";
      } else {
        expected_request = base::StringPrintf(
            "CONNECT www.example.org:443 HTTP/1.1\r\n"
            "Host: www.example.org:443\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "User-Agent: %s\r\n\r\n",
            setting_user_agent);
      }
      MockWrite data_writes[] = {
          MockWrite(expected_request.c_str()),
      };
      MockRead data_reads[] = {
          // Return an error, so the transaction stops here (this test isn't
          // interested in the rest).
          MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
          MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
          MockRead("Proxy-Connection: close\r\n\r\n"),
      };

      StaticSocketDataProvider data(data_reads, data_writes);
      session_deps_.socket_factory->AddSocketDataProvider(&data);

      TestCompletionCallback callback;

      int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
      EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

      rv = callback.WaitForResult();
      EXPECT_THAT(rv, IsOk());
    }
  }
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_Referer) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kReferer,
                                  "http://the.previous.site.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Referer: http://the.previous.site.com/\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_PostContentLengthZero) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_PutContentLengthZero) {
  HttpRequestInfo request;
  request.method = "PUT";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("PUT / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_HeadContentLengthZero) {
  HttpRequestInfo request;
  request.method = "HEAD";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_CacheControlNoCache) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = LOAD_BYPASS_CACHE;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Pragma: no-cache\r\n"
                "Cache-Control: no-cache\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_CacheControlValidateCache) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = LOAD_VALIDATE_CACHE;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Cache-Control: max-age=0\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_ExtraHeaders) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader("FooHeader", "Bar");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "FooHeader: Bar\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_ExtraHeadersStripped) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader("referer", "www.foo.com");
  request.extra_headers.SetHeader("hEllo", "Kitty");
  request.extra_headers.SetHeader("FoO", "bar");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "referer: www.foo.com\r\n"
                "hEllo: Kitty\r\n"
                "FoO: bar\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, SOCKS4_HTTP_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "SOCKS myproxy:1080", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  char write_buffer[] = {0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0};
  char read_buffer[] = {0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0};

  MockWrite data_writes[] = {
      MockWrite(ASYNC, write_buffer, std::size(write_buffer)),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
      MockRead(ASYNC, read_buffer, std::size(read_buffer)),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
      MockRead("Payload"), MockRead(SYNCHRONOUS, OK)};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  ASSERT_EQ(1u, response->proxy_chain.length());
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS4,
            response->proxy_chain.GetProxyServer(0).scheme());
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_P(HttpNetworkTransactionTest, SOCKS4_SSL_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "SOCKS myproxy:1080", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  unsigned char write_buffer[] = {0x04, 0x01, 0x01, 0xBB, 127, 0, 0, 1, 0};
  unsigned char read_buffer[] = {0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0};

  MockWrite data_writes[] = {
      MockWrite(ASYNC, reinterpret_cast<char*>(write_buffer),
                std::size(write_buffer)),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
      MockRead(ASYNC, reinterpret_cast<char*>(read_buffer),
               std::size(read_buffer)),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
      MockRead("Payload"), MockRead(SYNCHRONOUS, OK)};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(1u, response->proxy_chain.length());
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS4,
            response->proxy_chain.GetProxyServer(0).scheme());

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_P(HttpNetworkTransactionTest, SOCKS4_HTTP_GET_no_PAC) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "socks4://myproxy:1080", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  char write_buffer[] = {0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0};
  char read_buffer[] = {0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0};

  MockWrite data_writes[] = {
      MockWrite(ASYNC, write_buffer, std::size(write_buffer)),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
      MockRead(ASYNC, read_buffer, std::size(read_buffer)),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
      MockRead("Payload"), MockRead(SYNCHRONOUS, OK)};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_P(HttpNetworkTransactionTest, SOCKS5_HTTP_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "SOCKS5 myproxy:1080", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  const char kSOCKS5ExampleOkRequest[] = {
      0x05,  // Version
      0x01,  // Command (CONNECT)
      0x00,  // Reserved.
      0x03,  // Address type (DOMAINNAME).
      0x0F,  // Length of domain (15)
      'w',  'w', 'w', '.', 'e',  'x',
      'a',  'm', 'p', 'l', 'e',         // Domain string
      '.',  'o', 'r', 'g', 0x00, 0x50,  // 16-bit port (80)
  };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
      MockWrite(ASYNC, kSOCKS5ExampleOkRequest,
                std::size(kSOCKS5ExampleOkRequest)),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
      MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
      MockRead(ASYNC, kSOCKS5OkResponse, kSOCKS5OkResponseLength),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
      MockRead("Payload"),
      MockRead(SYNCHRONOUS, OK)};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(1u, response->proxy_chain.length());
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS5,
            response->proxy_chain.GetProxyServer(0).scheme());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_P(HttpNetworkTransactionTest, SOCKS5_SSL_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "SOCKS5 myproxy:1080", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  const unsigned char kSOCKS5ExampleOkRequest[] = {
      0x05,  // Version
      0x01,  // Command (CONNECT)
      0x00,  // Reserved.
      0x03,  // Address type (DOMAINNAME).
      0x0F,  // Length of domain (15)
      'w',  'w', 'w', '.', 'e',  'x',
      'a',  'm', 'p', 'l', 'e',         // Domain string
      '.',  'o', 'r', 'g', 0x01, 0xBB,  // 16-bit port (443)
  };

  const char kSOCKS5SslOkResponse[] = {0x05, 0x00, 0x00, 0x01, 0,
                                       0,    0,    0,    0x00, 0x00};

  MockWrite data_writes[] = {
      MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
      MockWrite(ASYNC, reinterpret_cast<const char*>(kSOCKS5ExampleOkRequest),
                std::size(kSOCKS5ExampleOkRequest)),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
      MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
      MockRead(ASYNC, kSOCKS5SslOkResponse, std::size(kSOCKS5SslOkResponse)),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
      MockRead("Payload"),
      MockRead(SYNCHRONOUS, OK)};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(1u, response->proxy_chain.length());
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS5,
            response->proxy_chain.GetProxyServer(0).scheme());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

namespace {

// Tests that for connection endpoints the group ids are correctly set.

struct GroupIdTest {
  std::string proxy_chain;
  std::string url;
  ClientSocketPool::GroupId expected_group_id;
  HttpStreamKey expected_http_stream_key;
  bool ssl;
};

std::unique_ptr<HttpNetworkSession> SetupSessionForGroupIdTests(
    SpdySessionDependencies* session_deps_) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, "", 444);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort("https", "host.with.alternate", 443),
      NetworkAnonymizationKey(), alternative_service, expiration);

  return session;
}

int GroupIdTransactionHelper(const std::string& url,
                             HttpNetworkSession* session) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(url);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session);

  TestCompletionCallback callback;

  // We do not complete this request, the dtor will clean the transaction up.
  return trans.Start(&request, callback.callback(), NetLogWithSource());
}

int HttpStreamKeyTransactionHelper(std::string_view url,
                                   HttpNetworkSession* session) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(url);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session);

  TestCompletionCallback callback;

  // Unlike GroupIdTransactionHelper(), we complete the request because
  // HttpStreamKey is only set after the transaction switched to the
  // HttpStreamPool.
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  CHECK_EQ(rv, ERR_IO_PENDING);
  return callback.WaitForResult();
}

}  // namespace

TEST_P(HttpNetworkTransactionTest, GroupIdOrHttpStreamKeyForDirectConnections) {
  const GroupIdTest tests[] = {
      {
          "",  // unused
          "http://www.example.org/direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "www.example.org", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(
              url::SchemeHostPort(url::kHttpScheme, "www.example.org", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, SocketTag(),
              NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
              /*disable_cert_network_fetches=*/false),
          false,
      },
      {
          "",  // unused
          "http://[2001:1418:13:1::25]/direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "[2001:1418:13:1::25]", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(
              url::SchemeHostPort(url::kHttpScheme, "[2001:1418:13:1::25]", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, SocketTag(),
              NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
              /*disable_cert_network_fetches=*/false),
          false,
      },

      // SSL Tests
      {
          "",  // unused
          "https://www.example.org/direct_ssl",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "www.example.org", 443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(
              url::SchemeHostPort(url::kHttpsScheme, "www.example.org", 443),
              PrivacyMode::PRIVACY_MODE_DISABLED, SocketTag(),
              NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
              /*disable_cert_network_fetches=*/false),
          true,
      },
      {
          "",  // unused
          "https://[2001:1418:13:1::25]/direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "[2001:1418:13:1::25]",
                                  443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(url::SchemeHostPort(url::kHttpsScheme,
                                            "[2001:1418:13:1::25]", 443),
                        PrivacyMode::PRIVACY_MODE_DISABLED, SocketTag(),
                        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                        /*disable_cert_network_fetches=*/false),
          true,
      },
      {
          "",  // unused
          "https://host.with.alternate/direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "host.with.alternate",
                                  443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(url::SchemeHostPort(url::kHttpsScheme,
                                            "host.with.alternate", 443),
                        PrivacyMode::PRIVACY_MODE_DISABLED, SocketTag(),
                        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                        /*disable_cert_network_fetches=*/false),
          true,
      },
  };

  for (const auto& test : tests) {
    session_deps_.proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedForTest(
            test.proxy_chain, TRAFFIC_ANNOTATION_FOR_TESTS);
    std::unique_ptr<HttpNetworkSession> session(
        SetupSessionForGroupIdTests(&session_deps_));

    HttpNetworkSessionPeer peer(session.get());

    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      // The result doesn't matter, so just fail the connections (one for
      // origin, anothor for an alternative service).
      StaticSocketDataProvider data;
      data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_FAILED));
      session_deps_.socket_factory->AddSocketDataProvider(&data);
      StaticSocketDataProvider alt_data;
      alt_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_FAILED));
      session_deps_.socket_factory->AddSocketDataProvider(&alt_data);

      auto http_pool_delegate =
          std::make_unique<CaptureKeyHttpStreamPoolDelegate>();
      CaptureKeyHttpStreamPoolDelegate* http_pool_delegate_ptr =
          http_pool_delegate.get();
      session->http_stream_pool()->SetDelegateForTesting(
          std::move(http_pool_delegate));

      EXPECT_EQ(ERR_FAILED,
                HttpStreamKeyTransactionHelper(test.url, session.get()));
      EXPECT_EQ(test.expected_http_stream_key,
                http_pool_delegate_ptr->last_key());
    } else {
      auto transport_conn_pool =
          std::make_unique<CaptureGroupIdTransportSocketPool>(
              &dummy_connect_job_params_);
      auto* transport_conn_pool_ptr = transport_conn_pool.get();
      auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
      mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                       std::move(transport_conn_pool));
      peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

      EXPECT_EQ(ERR_IO_PENDING,
                GroupIdTransactionHelper(test.url, session.get()));
      EXPECT_EQ(test.expected_group_id,
                transport_conn_pool_ptr->last_group_id_received());
      EXPECT_TRUE(transport_conn_pool_ptr->socket_requested());
    }
  }
}

TEST_P(HttpNetworkTransactionTest, GroupIdForHTTPProxyConnections) {
  const GroupIdTest tests[] = {
      {
          "http_proxy",
          "http://www.example.org/http_proxy_normal",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "www.example.org", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          false,
      },

      // SSL Tests
      {
          "http_proxy",
          "https://www.example.org/http_connect_ssl",
          ClientSocketPool::GroupId(
              url::SchemeHo
"""


```