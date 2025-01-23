Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Context:** The prompt clearly states this is part of the Chromium networking stack, specifically the `net/http/http_network_transaction_unittest.cc` file. The "unittest" part is crucial – this file contains *tests* for the `HttpNetworkTransaction` class. The numbering (17/34) indicates it's a substantial file, likely covering many aspects of the class's functionality.

2. **Identify the Core Functionality Under Test:** The class name `HttpNetworkTransaction` suggests it's responsible for handling individual HTTP requests and responses. The tests within the snippet provide concrete examples of its behavior.

3. **Break Down the Tests:** I'll go through each `TEST_P` (parameterized test) or `TEST` function and try to understand what it's validating:

    * **`NoContentResponse`:**  Seems to test the handling of a 204 No Content response, ensuring no data is read.
    * **`ResendRequestOnWriteBodyError`:** This tests a retry mechanism. If writing the request body fails, the transaction should retry.
    * **`AuthIdentityInURL`:** Focuses on authentication. It checks if credentials embedded in the URL are used for basic authentication.
    * **`WrongAuthIdentityInURL`:** Similar to the previous one, but with incorrect credentials in the URL. It verifies that the incorrect credentials are tried once, and then the user is prompted.
    * **`AuthIdentityInURLSuppressed`:**  Tests the scenario where using embedded credentials is explicitly disabled (`LOAD_DO_NOT_USE_EMBEDDED_IDENTITY`).
    * **`BasicAuthCacheAndPreauth`:** A more complex test covering basic authentication caching and preemptive authentication (sending credentials before being challenged). It involves multiple requests and verifies the re-use of cached credentials.
    * **`DigestPreAuthNonceCount`:** This focuses on Digest authentication and specifically checks if the nonce count (`nc`) is correctly incremented across multiple requests within the same authentication session.
    * **`ResetStateForRestart`:**  Tests an internal method (`ResetStateForRestart`) used when a transaction needs to be restarted (likely during authentication or redirects). Since the provided snippet ends mid-test, I can infer the purpose but not the full testing logic.

4. **Categorize the Functionality:**  Based on the individual tests, I can group the functionalities being tested:

    * **Basic HTTP Functionality:** Handling basic requests and responses (like the 204 No Content case).
    * **Error Handling and Retries:** Recovering from write errors during request sending.
    * **Authentication (Basic and Digest):** Handling authentication challenges, using credentials from URLs, caching credentials, and preemptive authentication.
    * **Internal State Management:**  The `ResetStateForRestart` test suggests the file also covers internal mechanisms for managing the transaction lifecycle.

5. **Analyze Relationship with JavaScript:** Since this is a C++ networking component, its direct interaction with JavaScript is likely through the Chromium rendering engine (Blink). JavaScript uses APIs (like `fetch` or `XMLHttpRequest`) which internally rely on the network stack. I need to provide examples of how JavaScript actions would lead to this C++ code being executed.

6. **Consider User/Programming Errors:**  Based on the tests, I can identify common errors:

    * **Incorrect URLs (especially with embedded credentials).**
    * **Providing wrong credentials during authentication.**
    * **Not handling authentication challenges properly in application logic (though this is more relevant to the browser, the underlying network logic needs to be robust).**

7. **Trace User Operations (Debugging Clues):** I need to think about the sequence of user actions that would trigger these network requests and potentially lead to debugging within this C++ code. This involves web page navigation, form submissions, and interactions with resources requiring authentication.

8. **Address the "Assumptions and Outputs" Requirement:** For tests involving specific scenarios (like authentication), I can infer the expected input (request parameters, server responses) and output (transaction state, response data).

9. **Summarize the Functionality (Part 17 of 34):** Given that this is only part of the file, I need to focus on the functionalities covered in *this specific snippet*. The overall file likely covers even more.

10. **Structure the Response:** I'll organize my answer according to the prompt's requirements, covering functionality, JavaScript relationship, assumptions and outputs, common errors, debugging clues, and the summary. I'll use clear headings and examples to make the information accessible.

**(Self-Correction/Refinement during the process):**

* **Initial thought:** Focus heavily on the C++ implementation details.
* **Correction:**  Remember the prompt asks about the *functionality* and its relation to higher-level concepts like JavaScript. Shift the focus to the *what* rather than just the *how*.
* **Initial thought:** List all possible JavaScript APIs that *might* be related.
* **Correction:**  Focus on the most relevant and commonly used APIs like `fetch` and `XMLHttpRequest`.
* **Initial thought:**  Only describe the happy path for each test.
* **Correction:**  Also consider the error scenarios and how the tests validate error handling.

By following this structured approach, breaking down the code into smaller, understandable parts, and constantly relating it back to the prompt's questions, I can generate a comprehensive and accurate analysis of the provided C++ code snippet.
好的，让我们来分析一下 `net/http/http_network_transaction_unittest.cc` 文件的第 17 部分（共 34 部分）的功能。

**功能归纳 (基于提供的代码片段):**

这部分代码主要集中在测试 `HttpNetworkTransaction` 类在处理 HTTP 请求和响应过程中与 **身份验证 (Authentication)** 相关的各种场景，特别是 **Basic 认证** 和 **Digest 认证**。此外，还包含了一些其他方面的测试，例如处理 `204 No Content` 响应以及在写入请求体时发生错误时的重试机制。

更具体地说，这部分测试了以下功能：

1. **处理 `204 No Content` 响应:**  验证 `HttpNetworkTransaction` 能正确处理不包含任何响应体的 `204 No Content` 响应，并能正确管理连接池中的空闲套接字。
2. **请求体写入错误时的重试:** 测试当发送带有请求体的请求（例如 POST 请求）时，如果在写入请求体的过程中发生错误，`HttpNetworkTransaction` 是否能够正确地重新发送请求。
3. **URL 中包含身份信息的认证 (Basic Auth):**
   - 测试当 URL 中包含用户名和密码时，`HttpNetworkTransaction` 是否能自动提取并用于 Basic 认证。
   - 测试当 URL 中包含错误的用户名和密码时，`HttpNetworkTransaction` 会先尝试使用 URL 中的信息，然后在失败后提示用户或使用缓存的凭据。
   - 测试当设置了 `LOAD_DO_NOT_USE_EMBEDDED_IDENTITY` 标志时，即使 URL 中包含身份信息，`HttpNetworkTransaction` 也不会使用。
4. **Basic 认证的缓存和预认证:**
   - 测试 `HttpNetworkTransaction` 如何缓存成功的 Basic 认证凭据。
   - 测试在后续对相同保护空间的资源发起请求时，`HttpNetworkTransaction` 是否会尝试使用缓存的凭据进行预认证。
   - 测试当服务器拒绝缓存的凭据时，`HttpNetworkTransaction` 能否正确处理并重新进行认证。
5. **Digest 认证的 nonce 计数:**
   - 测试 `HttpNetworkTransaction` 在进行 Digest 认证时，是否能正确地递增 nonce 计数 (nc)。这对于防止重放攻击至关重要。
6. **重置状态以重新开始 (`ResetStateForRestart`):** 虽然代码片段在这里中断了，但从测试名称可以推断，它旨在测试 `HttpNetworkTransaction` 内部的 `ResetStateForRestart()` 方法，该方法可能用于在认证或其他需要重新开始请求的情况下重置事务的状态。

**与 Javascript 功能的关系及举例说明:**

尽管这段代码是 C++ 编写的，但它直接支持了 Web 浏览器中 JavaScript 发起的网络请求。以下是一些 JavaScript 功能与这段 C++ 代码交互的例子：

* **`fetch()` API:** 当 JavaScript 使用 `fetch()` API 发起一个需要身份验证的请求时，底层的网络栈会使用 `HttpNetworkTransaction` 来处理这个请求。如果服务器返回 `401 Unauthorized` 响应，`HttpNetworkTransaction` 中的逻辑（如本代码测试的）会处理认证质询。
   ```javascript
   fetch('http://www.example.org/api/data', {
     credentials: 'include' // 或者 'same-origin'，指示发送凭据
   })
   .then(response => {
     if (response.status === 401) {
       // 处理未授权情况，例如提示用户输入用户名密码
     } else {
       // 处理成功响应
     }
   });
   ```
* **`XMLHttpRequest` (XHR) API:**  类似于 `fetch()`，当使用 `XMLHttpRequest` 发起请求时，如果遇到需要身份验证的情况，`HttpNetworkTransaction` 会参与处理。
   ```javascript
   const xhr = new XMLHttpRequest();
   xhr.open('GET', 'http://www.example.org/secure/resource');
   xhr.withCredentials = true; // 指示发送凭据
   xhr.onload = function() {
     if (xhr.status === 401) {
       // 处理未授权
     } else {
       // 处理成功
     }
   };
   xhr.send();
   ```
* **URL 中包含用户名密码:**  虽然不推荐这样做，但用户可能会在 URL 中硬编码用户名和密码。这段 C++ 代码测试了浏览器如何处理这种情况。
   ```javascript
   // 不推荐的做法
   fetch('http://user:password@www.example.org/data');
   ```
   在这种情况下，JavaScript 引擎会将 URL 传递给底层的网络栈，而 `HttpNetworkTransaction` 的 `AuthIdentityInURL` 测试部分就验证了 C++ 代码如何解析和使用这些嵌入的凭据。

**逻辑推理 - 假设输入与输出:**

以 `AuthIdentityInURL` 测试为例：

* **假设输入:**
    * `HttpRequestInfo` 对象，其 `url` 属性为 `GURL("http://foo:b@r@www.example.org/")`，`method` 为 "GET"。
    * 服务器的第一个响应是 `HTTP/1.0 401 Unauthorized`，包含 `WWW-Authenticate: Basic realm="MyRealm1"` 头部。
    * 服务器的第二个响应（在提供凭据后）是 `HTTP/1.0 200 OK`。
* **预期输出:**
    * 第一次请求会收到 `ERR_IO_PENDING`，表示正在等待异步操作完成（认证）。
    * `trans.IsReadyToRestartForAuth()` 返回 `true`，表示可以重新发起认证请求。
    * 调用 `trans.RestartWithAuth()` 后，会使用从 URL 中提取的用户名 "foo" 和密码 "b@r"（经过 URL 解码）生成 `Authorization` 头部。
    * 第二次请求会成功，`callback2.WaitForResult()` 返回 `OK`。
    * `trans.GetResponseInfo()` 返回的 `HttpResponseInfo` 对象中，`auth_challenge` 为空（因为认证成功），`headers` 中包含 `Content-Length: 100`。

**用户或编程常见的使用错误及举例说明:**

1. **错误的 URL 格式:** 用户可能在 URL 中错误地添加了身份信息，例如使用了错误的用户名或密码，或者错误的 URL 编码。`WrongAuthIdentityInURL` 测试就模拟了这种情况，展示了浏览器如何先尝试使用错误的凭据，然后在失败后可能需要用户介入。
   ```javascript
   // 错误的密码
   fetch('http://myuser:wrongpassword@example.com/data');
   ```
2. **忘记设置 `withCredentials`:** 当使用 `fetch` 或 `XMLHttpRequest` 访问需要身份验证的跨域资源时，开发者可能会忘记设置 `credentials: 'include'` 或 `xhr.withCredentials = true`，导致浏览器不会发送凭据，从而导致认证失败。
3. **服务器配置错误:** 服务器可能没有正确配置认证方式或 realm，导致浏览器无法正确处理认证质询。这虽然不是用户直接的错误，但会导致浏览器端的认证逻辑被触发。
4. **对同一保护空间使用不同的认证方式:**  如果服务器在同一个保护空间内使用了不同的认证方案（例如 Basic 和 Digest），可能会导致浏览器缓存的凭据与当前请求不匹配，引发认证问题。`BasicAuthCacheAndPreauth` 和 `DigestPreAuthNonceCount` 测试部分覆盖了浏览器如何管理和使用不同认证方案的凭据。

**用户操作到达这里的步骤 (调试线索):**

当用户在浏览器中执行以下操作时，可能会触发这段 C++ 代码的执行，从而成为调试的线索：

1. **访问需要身份验证的网页:** 用户在地址栏输入一个需要 Basic 或 Digest 认证的 URL，或者点击了这样一个链接。
2. **提交包含身份验证信息的表单:** 用户在一个需要身份验证的网页上填写了用户名和密码，并提交了表单。
3. **JavaScript 发起需要身份验证的请求:** 网页上的 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 向需要身份验证的 API 端点发送请求。
4. **URL 中包含身份信息:** 用户点击了一个包含用户名和密码的 URL。

**作为调试线索:**

当网络请求出现认证问题时，开发人员可以关注以下几点：

* **检查请求头:** 查看浏览器发送的 `Authorization` 头部是否正确生成，包括用户名、密码（Base64 编码）、realm、nonce 等信息。
* **查看网络日志:**  Chromium 的 `net-internals` 工具 (chrome://net-internals/#events) 可以提供详细的网络请求日志，包括认证过程中的握手信息。
* **断点调试 C++ 代码:** 对于 Chromium 的开发人员，可以在 `HttpNetworkTransaction` 相关的代码中设置断点，例如在处理 `401` 响应、生成 `Authorization` 头部的地方，来深入了解认证流程。这段测试代码本身就提供了很多测试用例，可以帮助理解不同场景下的行为。

**总结第 17 部分的功能:**

总而言之，`net/http/http_network_transaction_unittest.cc` 文件的第 17 部分主要测试了 `HttpNetworkTransaction` 类在处理各种 HTTP 认证场景下的行为，特别是 Basic 和 Digest 认证。它涵盖了从最基本的认证流程到更复杂的场景，例如 URL 中包含身份信息、认证凭据的缓存和预认证、以及 Digest 认证中 nonce 计数的管理。这部分测试确保了 Chromium 网络栈在处理身份验证方面的正确性和健壮性，从而支持了 Web 浏览器中各种需要身份验证的功能。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第17部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 204 No Content", status_line);

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_P(HttpNetworkTransactionTest, ResendRequestOnWriteBodyError) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("foo")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request[2];
  // Transaction 1: a GET request that succeeds.  The socket is recycled
  // after use.
  request[0].method = "GET";
  request[0].url = GURL("http://www.google.com/");
  request[0].load_flags = 0;
  request[0].traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  // Transaction 2: a POST request.  Reuses the socket kept alive from
  // transaction 1.  The first attempts fails when writing the POST data.
  // This causes the transaction to retry with a new socket.  The second
  // attempt succeeds.
  request[1].method = "POST";
  request[1].url = GURL("http://www.google.com/login.cgi");
  request[1].upload_data_stream = &upload_data_stream;
  request[1].load_flags = 0;
  request[1].traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // The first socket is used for transaction 1 and the first attempt of
  // transaction 2.

  // The response of transaction 1.
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  // The mock write results of transaction 1 and the first attempt of
  // transaction 2.
  MockWrite data_writes1[] = {
      MockWrite(SYNCHRONOUS, 64),                      // GET
      MockWrite(SYNCHRONOUS, 93),                      // POST
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_ABORTED),  // POST data
  };
  StaticSocketDataProvider data1(data_reads1, data_writes1);

  // The second socket is used for the second attempt of transaction 2.

  // The response of transaction 2.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"),
      MockRead("welcome"),
      MockRead(SYNCHRONOUS, OK),
  };
  // The mock write results of the second attempt of transaction 2.
  MockWrite data_writes2[] = {
      MockWrite(SYNCHRONOUS, 93),  // POST
      MockWrite(SYNCHRONOUS, 3),   // POST data
  };
  StaticSocketDataProvider data2(data_reads2, data_writes2);

  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  const char* const kExpectedResponseData[] = {"hello world", "welcome"};

  for (int i = 0; i < 2; ++i) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    TestCompletionCallback callback;

    int rv = trans.Start(&request[i], callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(kExpectedResponseData[i], response_data);
  }
}

// Test the request-challenge-retry sequence for basic auth when there is
// an identity in the URL. The request should be sent as normal, but when
// it fails the identity from the URL is used to answer the challenge.
TEST_P(HttpNetworkTransactionTest, AuthIdentityInURL) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://foo:b@r@www.example.org/");
  request.load_flags = LOAD_NORMAL;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // The password contains an escaped character -- for this test to pass it
  // will need to be unescaped by HttpNetworkTransaction.
  EXPECT_EQ("b%40r", request.url.password());

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity from the url (foo, b@r) to answer the challenge.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJAcg==\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  TestCompletionCallback callback2;
  rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // There is no challenge info, since the identity in URL worked.
  EXPECT_FALSE(response->auth_challenge.has_value());

  EXPECT_EQ(100, response->headers->GetContentLength());

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
}

// Test the request-challenge-retry sequence for basic auth when there is an
// incorrect identity in the URL. The identity from the URL should be used only
// once.
TEST_P(HttpNetworkTransactionTest, WrongAuthIdentityInURL) {
  HttpRequestInfo request;
  request.method = "GET";
  // Note: the URL has a username:password in it.  The password "baz" is
  // wrong (should be "bar").
  request.url = GURL("http://foo:baz@www.example.org/");

  request.load_flags = LOAD_NORMAL;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity from the url (foo, baz) to answer the challenge.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJheg==\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity supplied by the user (foo, bar) to answer the challenge.
  MockWrite data_writes3[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads3[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  StaticSocketDataProvider data3(data_reads3, data_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  TestCompletionCallback callback2;
  rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // There is no challenge info, since the identity worked.
  EXPECT_FALSE(response->auth_challenge.has_value());

  EXPECT_EQ(100, response->headers->GetContentLength());

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
}

// Test the request-challenge-retry sequence for basic auth when there is a
// correct identity in the URL, but its use is being suppressed. The identity
// from the URL should never be used.
TEST_P(HttpNetworkTransactionTest, AuthIdentityInURLSuppressed) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://foo:bar@www.example.org/");
  request.load_flags = LOAD_DO_NOT_USE_EMBEDDED_IDENTITY;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity supplied by the user, not the one in the URL, to answer the
  // challenge.
  MockWrite data_writes3[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads3[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data3(data_reads3, data_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // There is no challenge info, since the identity worked.
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(100, response->headers->GetContentLength());

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
}

// Test that previously tried username/passwords for a realm get re-used.
TEST_P(HttpNetworkTransactionTest, BasicAuthCacheAndPreauth) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Transaction 1: authenticate (foo, bar) on MyRealm1
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/y/z");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite("GET /x/y/z HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 401 Unauthorized\r\n"),
        MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead("Content-Length: 10000\r\n\r\n"),
        MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization (username=foo, password=bar)
    MockWrite data_writes2[] = {
        MockWrite("GET /x/y/z HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 100\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    StaticSocketDataProvider data2(data_reads2, data_writes2);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                               callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 2: authenticate (foo2, bar2) on MyRealm2
  {
    HttpRequestInfo request;
    request.method = "GET";
    // Note that Transaction 1 was at /x/y/z, so this is in the same
    // protection space as MyRealm1.
    request.url = GURL("http://www.example.org/x/y/a/b");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite("GET /x/y/a/b HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  // Send preemptive authorization for MyRealm1
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // The server didn't like the preemptive authorization, and
    // challenges us for a different realm (MyRealm2).
    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 401 Unauthorized\r\n"),
        MockRead("WWW-Authenticate: Basic realm=\"MyRealm2\"\r\n"),
        MockRead("Content-Length: 10000\r\n\r\n"),
        MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization for MyRealm2 (username=foo2, password=bar2)
    MockWrite data_writes2[] = {
        MockWrite("GET /x/y/a/b HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 100\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    StaticSocketDataProvider data2(data_reads2, data_writes2);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->auth_challenge);
    EXPECT_FALSE(response->auth_challenge->is_proxy);
    EXPECT_EQ("http://www.example.org",
              response->auth_challenge->challenger.Serialize());
    EXPECT_EQ("MyRealm2", response->auth_challenge->realm);
    EXPECT_EQ(kBasicAuthScheme, response->auth_challenge->scheme);

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo2, kBar2),
                               callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 3: Resend a request in MyRealm's protection space --
  // succeed with preemptive authorization.
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/y/z2");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite("GET /x/y/z2 HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  // The authorization for MyRealm1 gets sent preemptively
                  // (since the url is in the same protection space)
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever accepts the preemptive authorization
    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 100\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_FALSE(response->auth_challenge.has_value());
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 4: request another URL in MyRealm (however the
  // url is not known to belong to the protection space, so no pre-auth).
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/1");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite("GET /x/1 HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 401 Unauthorized\r\n"),
        MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead("Content-Length: 10000\r\n\r\n"),
        MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization from MyRealm's cache.
    MockWrite data_writes2[] = {
        MockWrite("GET /x/1 HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 100\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    StaticSocketDataProvider data2(data_reads2, data_writes2);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    EXPECT_TRUE(trans.IsReadyToRestartForAuth());
    TestCompletionCallback callback2;
    rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(trans.IsReadyToRestartForAuth());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 5: request a URL in MyRealm, but the server rejects the
  // cached identity. Should invalidate and re-prompt.
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/p/q/t");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite("GET /p/q/t HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 401 Unauthorized\r\n"),
        MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead("Content-Length: 10000\r\n\r\n"),
        MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization from cache for MyRealm.
    MockWrite data_writes2[] = {
        MockWrite("GET /p/q/t HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever rejects the authorization.
    MockRead data_reads2[] = {
        MockRead("HTTP/1.0 401 Unauthorized\r\n"),
        MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead("Content-Length: 10000\r\n\r\n"),
        MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // At this point we should prompt for new credentials for MyRealm.
    // Restart with username=foo3, password=foo4.
    MockWrite data_writes3[] = {
        MockWrite("GET /p/q/t HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vMzpiYXIz\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads3[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 100\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    StaticSocketDataProvider data2(data_reads2, data_writes2);
    StaticSocketDataProvider data3(data_reads3, data_writes3);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);
    session_deps_.socket_factory->AddSocketDataProvider(&data3);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    EXPECT_TRUE(trans.IsReadyToRestartForAuth());
    TestCompletionCallback callback2;
    rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(trans.IsReadyToRestartForAuth());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

    TestCompletionCallback callback3;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo3, kBar3),
                               callback3.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback3.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
    EXPECT_EQ(100, response->headers->GetContentLength());
  }
}

// Tests that nonce count increments when multiple auth attempts
// are started with the same nonce.
TEST_P(HttpNetworkTransactionTest, DigestPreAuthNonceCount) {
  auto digest_factory = std::make_unique<HttpAuthHandlerDigest::Factory>();
  auto nonce_generator =
      std::make_unique<HttpAuthHandlerDigest::FixedNonceGenerator>(
          "0123456789abcdef");
  digest_factory->set_nonce_generator(std::move(nonce_generator));
  session_deps_.http_auth_handler_factory = std::move(digest_factory);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Transaction 1: authenticate (foo, bar) on MyRealm1
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/y/z");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite("GET /x/y/z HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 401 Unauthorized\r\n"),
        MockRead(
            "WWW-Authenticate: Digest realm=\"digestive\", nonce=\"OU812\", "
            "algorithm=MD5, qop=\"auth\"\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    // Resend with authorization (username=foo, password=bar)
    MockWrite data_writes2[] = {
        MockWrite(
            "GET /x/y/z HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Digest username=\"foo\", realm=\"digestive\", "
            "nonce=\"OU812\", uri=\"/x/y/z\", algorithm=MD5, "
            "response=\"03ffbcd30add722589c1de345d7a927f\", qop=auth, "
            "nc=00000001, cnonce=\"0123456789abcdef\"\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    StaticSocketDataProvider data2(data_reads2, data_writes2);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckDigestServerAuth(response->auth_challenge));

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                               callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
  }

  // ------------------------------------------------------------------------

  // Transaction 2: Request another resource in digestive's protection space.
  // This will preemptively add an Authorization header which should have an
  // "nc" value of 2 (as compared to 1 in the first use.
  {
    HttpRequestInfo request;
    request.method = "GET";
    // Note that Transaction 1 was at /x/y/z, so this is in the same
    // protection space as digest.
    request.url = GURL("http://www.example.org/x/y/a/b");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/y/a/b HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Digest username=\"foo\", realm=\"digestive\", "
            "nonce=\"OU812\", uri=\"/x/y/a/b\", algorithm=MD5, "
            "response=\"d6f9a2c07d1c5df7b89379dca1269b35\", qop=auth, "
            "nc=00000002, cnonce=\"0123456789abcdef\"\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads1[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 100\r\n\r\n"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, data_writes1);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
  }
}

// Test the ResetStateForRestart() private method.
TEST_P(HttpNetworkTransactionTest, ResetStateForRestart) {
  // Create a transaction (the dependencies aren't important).
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // S
```