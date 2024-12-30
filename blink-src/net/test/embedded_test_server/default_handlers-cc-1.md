Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the request.

**1. Understanding the Core Request:**

The main goal is to understand the functionality of the provided C++ code snippet within the context of Chromium's network stack and its `embedded_test_server`. Key aspects include identifying its purpose, relating it to JavaScript if applicable, considering user errors, and outlining the steps to reach this code during debugging.

**2. Initial Code Scan and Keyword Recognition:**

I'd start by quickly scanning the code, looking for recognizable patterns and keywords:

* **Class Definition:** `DelayedChunkedHttpResponse` stands out as a custom response handler.
* **Inheritance:** It inherits from `HttpResponse`, indicating it's part of a response handling mechanism.
* **Chunking:**  Terms like "chunked", `chunk_size`, `num_chunks`, and the `CreateChunk` function clearly point to handling HTTP chunked transfer encoding.
* **Delays:** `delay_before_headers` and `delay_between_chunks` suggest the ability to simulate network latency.
* **HTTP Concepts:**  `HTTP_OK`, "Content-Type", "Transfer-Encoding", "Connection" are standard HTTP headers.
* **Function `HandleChunked`:** This function parses request parameters and creates a `DelayedChunkedHttpResponse` object.
* **`RegisterDefaultHandlers`:** This function is the entry point for registering various request handlers with the `EmbeddedTestServer`. It iterates through and registers several handlers for different URL paths (e.g., "/cachetime", "/echoheader", "/chunked").
* **Helper Functions:** Functions like `PrefixHandler`, `ServerRedirectHandler`, etc., are used to simplify the registration of common handler patterns.

**3. Deconstructing `DelayedChunkedHttpResponse`:**

* **Purpose:**  It's designed to send a chunked HTTP response with configurable delays before sending headers and between chunks. This is useful for testing how clients handle delayed or streaming responses.
* **Key Methods:**
    * `SendResponse`: Initiates the response process by delaying the sending of headers.
    * `SendHeaders`: Sends the initial headers, including `Transfer-Encoding: chunked`.
    * `PrepareToSendNextChunk`: Schedules the sending of the next chunk or the final empty chunk.
    * `SendNextChunk`:  Sends a data chunk with the specified size.
    * `CreateChunk`:  Formats a chunk according to the HTTP chunked encoding specification.

**4. Analyzing `HandleChunked`:**

* **Purpose:** This function acts as a factory for `DelayedChunkedHttpResponse`. It takes an `HttpRequest` and extracts query parameters to configure the delays, chunk size, and number of chunks.
* **Query Parameter Handling:** It parses query parameters like `waitBeforeHeaders`, `waitBetweenChunks`, `chunkSize`, and `chunksNumber`. This makes the behavior of the chunked response dynamic.
* **Default Values:**  It sets default values for the parameters if they are not provided in the request.

**5. Examining `RegisterDefaultHandlers`:**

* **Purpose:**  This is the central registration point for the default handlers the test server provides.
* **Pattern Recognition:**  Notice the repeated use of `PrefixHandler` and similar helper functions. This suggests a design pattern for registering handlers based on URL prefixes.
* **Specific Handlers:**  Quickly read through the registered handlers to get a sense of the server's capabilities (echoing headers, setting cookies, redirects, handling authentication, etc.).

**6. Connecting to JavaScript (if applicable):**

* **No Direct JavaScript:** This particular code snippet is C++ and doesn't directly contain JavaScript code.
* **Indirect Relation:** The handlers defined here *serve* content and behavior that JavaScript code running in a browser (or a test environment) would interact with. For example, a JavaScript `fetch` request to `/chunked` would receive the delayed, chunked response.

**7. Considering User/Programming Errors:**

* **Incorrect Query Parameters:** Users might provide non-numeric values or negative numbers for the delay or size parameters. The `CHECK` macros in `HandleChunked` are meant to catch some of these errors.
* **Misunderstanding Chunked Encoding:** Developers might not fully grasp how chunked encoding works, leading to incorrect assumptions about when data will be received.
* **Server-Side Errors:** While not directly in this code, other parts of the test server might have errors that could affect the chunked response (e.g., premature connection closure).

**8. Tracing User Operations (Debugging):**

* **Browser Interaction:** A user navigating to a URL handled by this code (e.g., `http://localhost:<port>/chunked?waitBeforeHeaders=100&chunkSize=10`) would trigger the `HandleChunked` function.
* **Automated Tests:**  Automated tests would often use the `EmbeddedTestServer` to simulate specific network conditions, including delayed chunked responses.
* **Debugging Steps:**
    1. **Set Breakpoints:**  A debugger could be used to set breakpoints within `HandleChunked`, `SendResponse`, `SendNextChunk`, etc., to step through the code execution.
    2. **Inspect Variables:**  Inspect the values of `delay_before_headers`, `chunk_size`, `remaining_chunks_`, and the contents of the chunks being sent.
    3. **Network Sniffing:** Tools like Wireshark or Chrome's DevTools Network tab can be used to observe the actual HTTP requests and responses, verifying the timing and chunking.

**9. Synthesizing the Summary (Part 2):**

Based on the analysis, the core functionality of this part of the code is to provide a configurable delayed chunked HTTP response mechanism for testing purposes. The `DelayedChunkedHttpResponse` class handles the low-level details of sending chunked data with delays, while `HandleChunked` acts as a factory based on request parameters. `RegisterDefaultHandlers` integrates this functionality into the test server.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this code deals with more complex network scenarios.
* **Correction:**  Focus on the explicit functionality related to delayed chunked responses.
* **Initial thought:**  Overemphasize potential JavaScript interactions.
* **Correction:**  Clarify that the interaction is indirect, through HTTP requests and responses.
* **Initial thought:**  Assume more complex error handling.
* **Correction:** Focus on the basic error checks present in the code (e.g., `CHECK` macros).

By following this structured approach, breaking down the code into smaller, manageable parts, and focusing on the key functionalities and relationships, it becomes easier to understand the code and generate a comprehensive and accurate answer.
这是目录为 `net/test/embedded_test_server/default_handlers.cc` 的 Chromium 网络栈源代码文件的第二部分，主要功能是**注册 `EmbeddedTestServer` 的默认请求处理器 (handlers)**。

**归纳其功能：**

这部分代码定义并注册了一系列预定义的 HTTP 请求处理器，这些处理器模拟了各种不同的服务器行为，主要用于网络栈的单元测试和集成测试。这些处理器可以模拟：

* **基本响应：**  返回特定的内容、状态码或头部。
* **延迟响应：**  在发送头部或内容之间引入延迟，用于测试客户端对超时和延迟的处理。
* **Chunked 响应：**  以分块传输编码的方式发送响应，用于测试客户端对分块数据的处理。
* **缓存控制：**  设置不同的缓存头，用于测试浏览器缓存行为。
* **Cookie 操作：**  设置和读取 Cookie，用于测试 Cookie 的处理。
* **重定向：**  模拟各种类型的服务器端重定向，包括 CORS 和非 CORS 的情况，以及带 Cookie 的重定向。
* **跨站请求：**  模拟跨站点请求和重定向。
* **客户端重定向：**  发送带有 `<meta refresh>` 标签的 HTML 页面，触发客户端重定向。
* **错误和特殊情况：**  返回 `204 No Content`，关闭 socket，模拟服务器挂起等情况。
* **认证：**  模拟基本的 HTTP Basic 和 Digest 认证。

**与 JavaScript 功能的关系及举例说明：**

虽然这段 C++ 代码本身不包含 JavaScript 代码，但它定义了测试服务器的行为，这些行为会直接影响到浏览器中运行的 JavaScript 代码的网络请求。

**举例说明 (针对 `/chunked` 处理器):**

假设 JavaScript 代码使用 `fetch` API 向测试服务器的 `/chunked` 路径发送请求：

```javascript
fetch('/chunked?waitBeforeHeaders=100&waitBetweenChunks=50&chunkSize=20&chunksNumber=3')
  .then(response => {
    const reader = response.body.getReader();
    let receivedData = '';

    function read() {
      reader.read().then(({ done, value }) => {
        if (done) {
          console.log('所有数据接收完毕:', receivedData);
          return;
        }
        receivedData += new TextDecoder().decode(value);
        console.log('接收到 chunk:', new TextDecoder().decode(value));
        read();
      });
    }

    read();
  });
```

在这个例子中：

* **JavaScript 发起请求:**  `fetch('/chunked?...')` 会向测试服务器发送一个 GET 请求到 `/chunked` 路径，并带有一些查询参数。
* **C++ 代码处理请求:**  `HandleChunked` 函数会被调用，根据查询参数创建 `DelayedChunkedHttpResponse` 对象。
* **模拟延迟和分块:**  `DelayedChunkedHttpResponse` 会按照参数指定的延迟（100ms 延迟发送头部，50ms 延迟发送每个 20 字节的 chunk）发送响应。
* **JavaScript 接收数据:**  `response.body.getReader()` 获取响应体的读取器，JavaScript 代码通过循环读取 chunks 来接收数据。

**假设输入与输出 (针对 `HandleChunked`):**

**假设输入:** 一个指向 `/chunked?waitBeforeHeaders=50&chunkSize=10&chunksNumber=2` 的 GET 请求。

**逻辑推理:**

1. `HandleChunked` 函数被调用。
2. 解析 URL 查询参数：
   * `waitBeforeHeaders` 解析为 50。
   * `chunkSize` 解析为 10。
   * `chunksNumber` 解析为 2。
   * `waitBetweenChunks` 没有指定，使用默认值 0。
3. 创建 `DelayedChunkedHttpResponse` 对象，构造函数参数为：`delay_before_headers = 50ms`, `delay_between_chunks = 0ms`, `chunk_size = 10`, `num_chunks = 2`。
4. `SendResponse` 被调用，会在 50ms 后发送头部。
5. 头部被发送：`Content-Type: text/plain`, `Connection: close`, `Transfer-Encoding: chunked`。
6. 准备发送第一个 chunk，没有延迟。
7. 发送第一个 chunk：`a\r\n**********\r\n` (10 个 '*')。
8. 准备发送第二个 chunk，没有延迟。
9. 发送第二个 chunk：`a\r\n**********\r\n` (10 个 '*')。
10. 准备发送最后一个空 chunk。
11. 发送空 chunk：`0\r\n\r\n`。

**假设输出 (通过网络抓包可以看到的 HTTP 响应):**

```
HTTP/1.1 200 OK
Content-Type: text/plain
Connection: close
Transfer-Encoding: chunked

a
**********
a
**********
0

```

**涉及用户或编程常见的使用错误及举例说明：**

* **URL 参数错误:** 用户在构造 `/chunked` 的 URL 时，可能会提供无效的参数值，例如非数字的值。`HandleChunked` 函数中使用了 `CHECK(base::StringToInt(query.GetValue(), &value));` 来进行基本的校验，如果解析失败会导致程序崩溃 (在测试环境中是可以接受的)。

   **错误示例 URL:** `/chunked?chunkSize=abc`

* **对 Chunked 编码理解不足:**  开发者在编写测试代码时，可能没有正确理解 Chunked 编码的格式，导致测试断言错误。Chunked 编码需要在每个数据块前加上表示块大小的十六进制数和 `\r\n`，数据块后也需要加上 `\r\n`，最后以一个大小为 0 的块标识结束。

* **过度依赖默认值:** 开发者可能没有注意到 `HandleChunked` 中参数的默认值，导致测试结果与预期不符。例如，如果想测试延迟发送 chunk 的情况，需要显式指定 `waitBetweenChunks` 参数。

**用户操作如何一步步到达这里，作为调试线索：**

1. **开发者编写或运行使用 `EmbeddedTestServer` 的单元测试或集成测试。**
2. **测试代码中会创建一个 `EmbeddedTestServer` 实例并启动。**
3. **`RegisterDefaultHandlers` 函数会被调用，注册本文件中定义的各种请求处理器。**
4. **测试代码发起一个 HTTP 请求，例如 `client->Get("/chunked?...")`。**
5. **`EmbeddedTestServer` 接收到请求，并根据请求的路径 `/chunked` 匹配到 `HandleChunked` 处理器。**
6. **`HandleChunked` 函数被执行，解析请求参数并创建相应的 `HttpResponse` 对象 (例如 `DelayedChunkedHttpResponse`)。**
7. **`HttpResponse` 对象的 `SendResponse` 方法被调用，开始发送 HTTP 响应。**

**调试线索:**

* **在 `RegisterDefaultHandlers` 函数中设置断点:**  确认默认的 handlers 是否被正确注册。
* **在 `HandleChunked` 函数入口设置断点:**  查看请求的 URL 和参数是否正确传递进来。
* **在 `DelayedChunkedHttpResponse` 的 `SendHeaders` 和 `SendNextChunk` 方法中设置断点:**  观察响应头和 chunk 的发送过程，验证延迟是否生效，chunk 的大小和数量是否正确。
* **使用网络抓包工具 (如 Wireshark) 或 Chrome 开发者工具的网络面板:**  查看实际发送的 HTTP 请求和响应，包括头部、chunk 的内容和时间戳，帮助理解服务器的实际行为。

总而言之，这部分代码是 `EmbeddedTestServer` 的核心组成部分，它通过提供各种可配置的默认请求处理器，极大地简化了 Chromium 网络栈相关功能的测试工作。它与 JavaScript 的联系在于，它模拟了 JavaScript 代码通过网络请求可能遇到的各种服务器行为，帮助开发者测试和验证 JavaScript 代码的网络处理逻辑。

Prompt: 
```
这是目录为net/test/embedded_test_server/default_handlers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ks() for argument details.
class DelayedChunkedHttpResponse : public HttpResponse {
 public:
  DelayedChunkedHttpResponse(base::TimeDelta delay_before_headers,
                             base::TimeDelta delay_between_chunks,
                             int chunk_size,
                             int num_chunks)
      : delay_before_headers_(delay_before_headers),
        delay_between_chunks_(delay_between_chunks),
        chunk_size_(chunk_size),
        remaining_chunks_(num_chunks) {}

  ~DelayedChunkedHttpResponse() override = default;

  DelayedChunkedHttpResponse(const DelayedChunkedHttpResponse&) = delete;
  DelayedChunkedHttpResponse& operator=(const DelayedChunkedHttpResponse&) =
      delete;

  void SendResponse(base::WeakPtr<HttpResponseDelegate> delegate) override {
    delegate_ = delegate;

    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&DelayedChunkedHttpResponse::SendHeaders,
                       weak_ptr_factory_.GetWeakPtr()),
        delay_before_headers_);
  }

 private:
  void SendHeaders() {
    base::StringPairs headers = {{"Content-Type", "text/plain"},
                                 {"Connection", "close"},
                                 {"Transfer-Encoding", "chunked"}};
    delegate_->SendResponseHeaders(HTTP_OK, "OK", headers);
    PrepareToSendNextChunk();
  }

  void PrepareToSendNextChunk() {
    if (remaining_chunks_ == 0) {
      delegate_->SendContentsAndFinish(CreateChunk(0 /* chunk_size */));
      return;
    }

    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&DelayedChunkedHttpResponse::SendNextChunk,
                       weak_ptr_factory_.GetWeakPtr()),
        delay_between_chunks_);
  }

  void SendNextChunk() {
    DCHECK_GT(remaining_chunks_, 0);
    remaining_chunks_--;

    delegate_->SendContents(
        CreateChunk(chunk_size_),
        base::BindOnce(&DelayedChunkedHttpResponse::PrepareToSendNextChunk,
                       weak_ptr_factory_.GetWeakPtr()));
  }

  static std::string CreateChunk(int chunk_size) {
    return base::StringPrintf(
        "%x\r\n"
        "%s"
        "\r\n",
        chunk_size, std::string(chunk_size, '*').c_str());
  }

  base::TimeDelta delay_before_headers_;
  base::TimeDelta delay_between_chunks_;
  int chunk_size_;
  int remaining_chunks_;

  base::WeakPtr<HttpResponseDelegate> delegate_ = nullptr;

  base::WeakPtrFactory<DelayedChunkedHttpResponse> weak_ptr_factory_{this};
};

// /chunked
// Returns a chunked response.
//
// Optional query parameters:
// * waitBeforeHeaders: Delays the specified number milliseconds before sending
// a response header. Defaults to 0.
// * waitBetweenChunks: Delays the specified number milliseconds before sending
// each chunk, except the last. Defaults to 0.
// * chunkSize: Size of each chunk, in bytes. Defaults to 5.
// * chunksNumber: Number of non-empty chunks. Defaults to 5.
std::unique_ptr<HttpResponse> HandleChunked(const HttpRequest& request) {
  GURL request_url = request.GetURL();

  base::TimeDelta delay_before_headers;
  base::TimeDelta delay_between_chunks;
  int chunk_size = 5;
  int num_chunks = 5;

  for (QueryIterator query(request_url); !query.IsAtEnd(); query.Advance()) {
    int value;
    CHECK(base::StringToInt(query.GetValue(), &value));
    CHECK_GE(value, 0);
    if (query.GetKey() == "waitBeforeHeaders") {
      delay_before_headers = base::Milliseconds(value);
    } else if (query.GetKey() == "waitBetweenChunks") {
      delay_between_chunks = base::Milliseconds(value);
    } else if (query.GetKey() == "chunkSize") {
      // A 0-size chunk indicates completion.
      CHECK_LT(0, value);
      chunk_size = value;
    } else if (query.GetKey() == "chunksNumber") {
      num_chunks = value;
    } else {
      NOTREACHED() << query.GetKey() << "Is not a valid argument of /chunked";
    }
  }

  return std::make_unique<DelayedChunkedHttpResponse>(
      delay_before_headers, delay_between_chunks, chunk_size, num_chunks);
}

EmbeddedTestServer::HandleRequestCallback PrefixHandler(
    const std::string& prefix,
    std::unique_ptr<HttpResponse> (*handler)(const HttpRequest& request)) {
  return base::BindRepeating(&HandlePrefixedRequest, prefix,
                             base::BindRepeating(handler));
}

EmbeddedTestServer::HandleRequestCallback ServerRedirectHandler(
    const std::string& prefix,
    std::unique_ptr<HttpResponse> (*handler)(HttpStatusCode redirect_code,
                                             bool allow_cors,
                                             const HttpRequest& request),
    HttpStatusCode redirect_code) {
  return base::BindRepeating(
      &HandlePrefixedRequest, prefix,
      base::BindRepeating(handler, redirect_code, /*allow_cors=*/true));
}

EmbeddedTestServer::HandleRequestCallback NoCorsServerRedirectHandler(
    const std::string& prefix,
    std::unique_ptr<HttpResponse> (*handler)(HttpStatusCode redirect_code,
                                             bool allow_cors,
                                             const HttpRequest& request),
    HttpStatusCode redirect_code) {
  return base::BindRepeating(
      &HandlePrefixedRequest, prefix,
      base::BindRepeating(handler, redirect_code, /*allow_cors=*/false));
}

EmbeddedTestServer::HandleRequestCallback ServerRedirectWithCookieHandler(
    const std::string& prefix,
    std::unique_ptr<HttpResponse> (*handler)(HttpStatusCode redirect_code,
                                             const HttpRequest& request),
    HttpStatusCode redirect_code) {
  return base::BindRepeating(&HandlePrefixedRequest, prefix,
                             base::BindRepeating(handler, redirect_code));
}

}  // anonymous namespace

void RegisterDefaultHandlers(EmbeddedTestServer* server) {
  server->RegisterDefaultHandler(base::BindRepeating(&HandleDefaultConnect));

  server->RegisterDefaultHandler(PrefixHandler("/cachetime", &HandleCacheTime));
  server->RegisterDefaultHandler(
      base::BindRepeating(&HandleEchoHeader, "/echoheader", "no-cache"));
  server->RegisterDefaultHandler(base::BindRepeating(
      &HandleEchoCookieWithStatus, "/echo-cookie-with-status"));
  server->RegisterDefaultHandler(base::BindRepeating(
      &HandleEchoHeader, "/echoheadercache", "max-age=60000"));
  server->RegisterDefaultHandler(PrefixHandler("/echo", &HandleEcho));
  server->RegisterDefaultHandler(PrefixHandler("/echotitle", &HandleEchoTitle));
  server->RegisterDefaultHandler(PrefixHandler("/echoall", &HandleEchoAll));
  server->RegisterDefaultHandler(PrefixHandler("/echo-raw", &HandleEchoRaw));
  server->RegisterDefaultHandler(
      PrefixHandler("/echocriticalheader", &HandleEchoCriticalHeader));
  server->RegisterDefaultHandler(
      PrefixHandler("/set-cookie", &HandleSetCookie));
  server->RegisterDefaultHandler(
      PrefixHandler("/set-invalid-cookie", &HandleSetInvalidCookie));
  server->RegisterDefaultHandler(
      PrefixHandler("/expect-and-set-cookie", &HandleExpectAndSetCookie));
  server->RegisterDefaultHandler(
      PrefixHandler("/set-header", &HandleSetHeader));
  server->RegisterDefaultHandler(
      base::BindRepeating(&HandleSetHeaderWithFile, "/set-header-with-file"));
  server->RegisterDefaultHandler(PrefixHandler("/iframe", &HandleIframe));
  server->RegisterDefaultHandler(PrefixHandler("/nocontent", &HandleNoContent));
  server->RegisterDefaultHandler(
      PrefixHandler("/close-socket", &HandleCloseSocket));
  server->RegisterDefaultHandler(
      PrefixHandler("/auth-basic", &HandleAuthBasic));
  server->RegisterDefaultHandler(
      PrefixHandler("/auth-digest", &HandleAuthDigest));

  server->RegisterDefaultHandler(ServerRedirectHandler(
      "/server-redirect", &HandleServerRedirect, HTTP_MOVED_PERMANENTLY));
  server->RegisterDefaultHandler(ServerRedirectHandler(
      "/server-redirect-301", &HandleServerRedirect, HTTP_MOVED_PERMANENTLY));
  server->RegisterDefaultHandler(ServerRedirectHandler(
      "/server-redirect-302", &HandleServerRedirect, HTTP_FOUND));
  server->RegisterDefaultHandler(ServerRedirectHandler(
      "/server-redirect-303", &HandleServerRedirect, HTTP_SEE_OTHER));
  server->RegisterDefaultHandler(ServerRedirectHandler(
      "/server-redirect-307", &HandleServerRedirect, HTTP_TEMPORARY_REDIRECT));
  server->RegisterDefaultHandler(ServerRedirectHandler(
      "/server-redirect-308", &HandleServerRedirect, HTTP_PERMANENT_REDIRECT));

  server->RegisterDefaultHandler(NoCorsServerRedirectHandler(
      "/no-cors-server-redirect", &HandleServerRedirect,
      HTTP_MOVED_PERMANENTLY));
  server->RegisterDefaultHandler(NoCorsServerRedirectHandler(
      "/no-cors-server-redirect-301", &HandleServerRedirect,
      HTTP_MOVED_PERMANENTLY));
  server->RegisterDefaultHandler(NoCorsServerRedirectHandler(
      "/no-cors-server-redirect-302", &HandleServerRedirect, HTTP_FOUND));
  server->RegisterDefaultHandler(NoCorsServerRedirectHandler(
      "/no-cors-server-redirect-303", &HandleServerRedirect, HTTP_SEE_OTHER));
  server->RegisterDefaultHandler(NoCorsServerRedirectHandler(
      "/no-cors-server-redirect-307", &HandleServerRedirect,
      HTTP_TEMPORARY_REDIRECT));
  server->RegisterDefaultHandler(NoCorsServerRedirectHandler(
      "/no-cors-server-redirect-308", &HandleServerRedirect,
      HTTP_PERMANENT_REDIRECT));

  server->RegisterDefaultHandler(ServerRedirectWithCookieHandler(
      "/server-redirect-with-cookie", &HandleServerRedirectWithCookie,
      HTTP_MOVED_PERMANENTLY));
  server->RegisterDefaultHandler(ServerRedirectWithCookieHandler(
      "/server-redirect-with-secure-cookie",
      &HandleServerRedirectWithSecureCookie, HTTP_MOVED_PERMANENTLY));

  server->RegisterDefaultHandler(base::BindRepeating(&HandleCrossSiteRedirect,
                                                     server, "/cross-site",
                                                     /*set_cookie=*/false));
  server->RegisterDefaultHandler(
      base::BindRepeating(&HandleCrossSiteRedirect, server,
                          "/cross-site-with-cookie", /*set_cookie=*/true));
  server->RegisterDefaultHandler(
      PrefixHandler("/client-redirect", &HandleClientRedirect));
  server->RegisterDefaultHandler(
      PrefixHandler("/defaultresponse", &HandleDefaultResponse));
  server->RegisterDefaultHandler(PrefixHandler("/slow", &HandleSlowServer));
  server->RegisterDefaultHandler(PrefixHandler("/hung", &HandleHungResponse));
  server->RegisterDefaultHandler(
      PrefixHandler("/hung-after-headers", &HandleHungAfterHeadersResponse));
  server->RegisterDefaultHandler(
      PrefixHandler("/exabyte_response", &HandleExabyteResponse));
  server->RegisterDefaultHandler(PrefixHandler("/gzip-body", &HandleGzipBody));
  server->RegisterDefaultHandler(PrefixHandler("/self.pac", &HandleSelfPac));
  server->RegisterDefaultHandler(PrefixHandler("/chunked", &HandleChunked));

  // TODO(svaldez): HandleDownload
  // TODO(svaldez): HandleDownloadFinish
  // TODO(svaldez): HandleZipFile
  // TODO(svaldez): HandleSSLManySmallRecords
  // TODO(svaldez): HandleGetSSLSessionCache
  // TODO(svaldez): HandleGetChannelID
  // TODO(svaldez): HandleGetClientCert
  // TODO(svaldez): HandleClientCipherList
  // TODO(svaldez): HandleEchoMultipartPost
}

}  // namespace net::test_server

"""


```