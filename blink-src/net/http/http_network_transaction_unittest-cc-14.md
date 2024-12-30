Response:
The user is asking for an analysis of a C++ source code file related to network transactions in Chromium. They are particularly interested in the file's functionality, its relation to JavaScript, logical inferences with input/output examples, common user errors, debugging hints, and a summary of its purpose within the larger context.

**Plan:**

1. **Identify the core functionality:** Based on the file name (`http_network_transaction_unittest.cc`) and the code snippets provided, the file contains unit tests for `HttpNetworkTransaction`. The tests specifically focus on handling NTLM authentication scenarios, including retries with and without correct credentials, and interactions with HTTP/2 and WebSockets.
2. **JavaScript relevance:** Determine if the file directly interacts with or tests features directly used by JavaScript. While the network stack is used by the browser to fetch resources for JavaScript, this unit test focuses on the underlying protocol handling.
3. **Logical inferences:** Analyze specific test cases to identify assumptions, inputs (like HTTP requests and server responses), and expected outputs (like the final response body).
4. **User/programming errors:**  Consider common mistakes users or developers might make that these tests cover (e.g., incorrect passwords, protocol mismatches).
5. **Debugging hints:**  Think about how the tests themselves can serve as debugging guidance for developers working on authentication or network handling.
6. **Contextual summary:** Summarize the file's purpose as part of a larger series of test files.

**Mental Sandbox:**

* **NTLM Authentication Tests:** The code heavily features `NTLMAuthV2...` test cases. This confirms the focus on NTLM authentication scenarios.
* **Mocking:** The use of `MockWrite` and `MockRead` indicates that the tests simulate network interactions without actual network traffic.
* **HTTP/2 and WebSockets:**  Specific tests like `NTLMOverHttp2` and `NTLMOverHttp2WithWebsockets` show that the file also tests interactions between NTLM and these protocols.
* **Error Handling:**  The use of `EXPECT_THAT(rv, IsError(ERR_IO_PENDING))` and `EXPECT_THAT(rv, IsOk())` checks for expected error codes and successful completion.
* **JavaScript Connection:** While JavaScript uses the network stack, the tests focus on the underlying HTTP protocol and authentication mechanisms. There's no direct JavaScript interaction in these unit tests.

**Self-Correction:**

Initially, I might have considered if JavaScript APIs like `fetch()` are directly tested. However, the file is a *unit test* focusing on the C++ `HttpNetworkTransaction` class. While the behavior tested here *affects* JavaScript's ability to fetch resources, the tests are at a lower level of abstraction.

**Final Plan of Action:**

1. Describe the file's primary function as unit tests for `HttpNetworkTransaction`, specifically focusing on NTLM authentication.
2. Explain that while the functionality tested is essential for web browsing initiated by JavaScript, the file itself does not directly involve JavaScript code. Provide an example of how a JavaScript `fetch()` call might trigger the code being tested (NTLM authentication).
3. For the logical inference, select a clear test case like `NTLMAuthV2WrongThenRightPassword`. Detail the assumed initial request, the simulated server responses (including the authentication challenge), and the subsequent requests with incorrect and correct credentials, ultimately leading to a successful response.
4. Address user errors by focusing on incorrect password entry, leading to authentication failures and retries. Also, mention protocol mismatches (e.g., expecting NTLM to work over HTTP/2).
5. Explain how the test cases serve as debugging guidance by illustrating the expected sequence of requests and responses during NTLM authentication. Developers can compare their actual network traffic against these patterns.
6. Conclude with a summary stating that this part of the test suite focuses on NTLM authentication within `HttpNetworkTransaction`, including scenarios with retries, incorrect credentials, and interactions with different protocols.
这是 Chromium 网络栈中 `net/http/http_network_transaction_unittest.cc` 文件的第 15 部分，总共 34 部分。 从提供的代码片段来看，这部分的主要功能是 **测试 `HttpNetworkTransaction` 类在处理 NTLM 身份验证时的行为，特别是包括重试机制、错误密码处理以及与 HTTP/2 和 WebSocket 的交互。**

以下是更详细的分析：

**功能列举:**

1. **NTLM 身份验证流程测试:**  测试了 `HttpNetworkTransaction` 如何处理需要 NTLM 身份验证的请求。这包括接收服务器的 401 响应和 `WWW-Authenticate: NTLM` 头，然后构造并发送 NTLM 握手消息（Type 1 和 Type 3）。
2. **重试机制测试 (`RestartWithAuth`):** 验证了在收到身份验证质询后，通过 `RestartWithAuth` 方法重新发起请求的能力，并可以提供或不提供身份验证凭据。
3. **错误密码处理:**  `NTLMAuthV2WrongThenRightPassword` 测试用例专门测试了先使用错误密码，然后使用正确密码的情况，验证了 `HttpNetworkTransaction` 能否正确处理多次身份验证尝试。
4. **HTTP/2 协议下的 NTLM 处理:** `NTLMOverHttp2` 测试用例验证了当服务器要求 NTLM 身份验证时，`HttpNetworkTransaction` 如何回退到 HTTP/1.1，因为 NTLM 不被 HTTP/2 原生支持。
5. **带有 Host Mapping 的 HTTP/2 下的 NTLM 处理:** `NTLMOverHttp2WithHostMapping` 测试了在存在主机映射规则的情况下，NTLM 身份验证导致回退到 HTTP/1.1 时，哪个主机（原始主机还是映射后的主机）会被标记为需要 HTTP/1.1。
6. **WebSocket 协议下的 NTLM 处理:**  `NTLMOverHttp2WithWebsockets` 测试用例验证了当 WebSocket 连接需要 NTLM 身份验证时，`HttpNetworkTransaction` 如何处理。它模拟了先建立 HTTP/2 连接，然后尝试升级到 WebSocket 连接，并在遇到 NTLM 质询时回退到 HTTP/1.1。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不包含 JavaScript，但它测试的网络功能是 JavaScript 通过浏览器提供的 API（如 `fetch` 或 `XMLHttpRequest`，以及 WebSocket API）进行网络请求的基础。

**举例说明:**

假设一个 JavaScript 应用程序尝试使用 `fetch` API 访问一个需要 NTLM 身份验证的内部网站：

```javascript
fetch('https://server/kids/login.aspx', {
  method: 'GET'
})
.then(response => {
  if (response.status === 200) {
    return response.text();
  } else if (response.status === 401) {
    console.log('需要身份验证');
    // 在这里可能需要提示用户输入用户名和密码，并使用新的凭据重新发起请求
  }
})
.then(data => console.log(data))
.catch(error => console.error('请求失败:', error));
```

当 JavaScript 发起这个 `fetch` 请求时，Chromium 的网络栈会处理底层的 HTTP 交互。如果服务器返回 401 状态码和 `WWW-Authenticate: NTLM` 头，那么 `HttpNetworkTransaction` 就会按照这些测试用例中模拟的方式进行 NTLM 握手。如果用户提供了凭据，`RestartWithAuth` 方法（在 C++ 层面）会被调用来重新发起请求，包含 NTLM 的身份验证信息。

**逻辑推理 (假设输入与输出):**

以 `NTLMAuthV2WrongThenRightPassword` 测试用例为例：

**假设输入:**

1. **初始请求:**  `GET https://server/kids/login.aspx`，不带身份验证信息。
2. **服务器首次响应:** `HTTP/1.1 401 Access Denied`，带有 `WWW-Authenticate: NTLM` 和 NTLM challenge (Type 2 message)。
3. **第一次重试凭据:**  错误的用户名/密码。
4. **服务器第二次响应:** `HTTP/1.1 401 Access Denied`，指示身份验证失败。
5. **第二次重试凭据:** 正确的用户名/密码。
6. **服务器第三次响应:** `HTTP/1.1 401 Access Denied`，带有新的 NTLM challenge (Type 2 message)。
7. **第三次重试 (自动):**  使用正确凭据生成的 Type 3 消息。
8. **服务器最终响应:** `HTTP/1.1 200 OK`，带有请求的内容 "Please Login\r\n"。

**预期输出:**

* 初始请求会返回 401 状态码，并触发身份验证流程。
* 使用错误密码的重试也会返回 401 状态码。
* 使用正确密码的重试最终会成功，返回 200 状态码和 "Please Login\r\n" 内容。
* 测试会验证发送和接收的数据是否与预期的 NTLM 消息一致。

**用户或编程常见的使用错误:**

1. **用户输入错误的密码:** `NTLMAuthV2WrongThenRightPassword` 专门测试了这种情况。用户多次输入错误密码会导致多次身份验证失败，最终可能因尝试次数过多而被锁定。
2. **假设 NTLM 可以用于 HTTP/2:** `NTLMOverHttp2` 测试表明这是一个常见的误解。开发者可能会错误地期望 NTLM 身份验证可以在 HTTP/2 连接上工作。Chromium 的网络栈会回退到 HTTP/1.1 来处理这种情况。
3. **未正确配置身份验证凭据:** 开发者可能没有正确地配置用于 NTLM 身份验证的用户名、密码和域名。这会导致身份验证失败。
4. **WebSocket 连接期望 NTLM 直接工作在 HTTP/2 上:**  类似于 HTTP/2 的情况，开发者可能期望 WebSocket 在 HTTP/2 连接上进行 NTLM 身份验证，而实际上需要回退到 HTTP/1.1。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户尝试访问需要 NTLM 身份验证的网站或资源。**
2. **浏览器发送初始的 HTTP 请求，不带身份验证信息。**
3. **服务器返回 401 状态码和 `WWW-Authenticate: NTLM` 头。**
4. **Chromium 的网络栈中的 `HttpNetworkTransaction` 接收到这个响应。**
5. **`HttpNetworkTransaction` 检测到需要 NTLM 身份验证，并准备开始握手。**
6. **如果用户之前已保存了该站点的凭据，或者配置了自动身份验证，`HttpNetworkTransaction` 会自动构建并发送包含 NTLM Type 1 消息的请求。**
7. **服务器返回包含 NTLM challenge (Type 2 消息) 的响应。**
8. **`HttpNetworkTransaction` 使用用户的凭据（或尝试默认凭据）和服务器的 challenge 构建 NTLM Type 3 消息。**
9. **`RestartWithAuth` 方法被调用来重新发起请求，这次包含 `Authorization: NTLM <Type 3 消息>` 头。**
10. **服务器验证 Type 3 消息，如果成功，则返回 200 OK 和请求的内容；如果失败，则可能返回另一个 401 或其他错误状态码。**

在调试网络问题时，可以使用 Chromium 的开发者工具 (F12) 的 "Network" 标签来查看这些 HTTP 请求和响应的详细信息，包括请求头和响应头，从而跟踪 NTLM 握手的过程。 `net-internals` 工具 (在 Chrome 地址栏输入 `chrome://net-internals/#events`) 提供了更底层的网络事件日志，可以帮助诊断更复杂的问题。

**功能归纳 (针对第 15 部分):**

这部分测试用例主要集中在 **`HttpNetworkTransaction` 类处理 NTLM 身份验证的各种场景**，包括成功的身份验证、错误密码的重试、以及在 HTTP/2 和 WebSocket 协议下遇到 NTLM 时的回退机制。它确保了 Chromium 的网络栈能够正确地与需要 NTLM 身份验证的服务器进行交互，即使在面对错误或协议限制时也能做出合理的处理。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第15部分，共34部分，请归纳一下它的功能

"""
 "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      MockWrite("\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (using correct credentials).  The second request continues on the
      // same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(authenticate_msg.c_str()),
      MockWrite("\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      // The origin server responds with a Type 2 message.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM "),
      MockRead(challenge_msg.c_str()),
      MockRead("\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      MockRead("You are not authorized to view this page\r\n"),

      // Lastly we get the desired content.
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=utf-8\r\n"),
      MockRead("Content-Length: 14\r\n\r\n"),
      MockRead("Please Login\r\n"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  SSLSocketDataProvider ssl1(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, ntlm::test::kPassword),
      callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  TestCompletionCallback callback3;

  rv = trans.RestartWithAuth(AuthCredentials(), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(14, response->headers->GetContentLength());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Please Login\r\n", response_data);

  EXPECT_TRUE(data1.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllWriteDataConsumed());
  EXPECT_TRUE(data2.AllReadDataConsumed());
  EXPECT_TRUE(data2.AllWriteDataConsumed());
}

// Enter a wrong password, and then the correct one.
TEST_P(HttpNetworkTransactionTest, NTLMAuthV2WrongThenRightPassword) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://server/kids/login.aspx");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpAuthNtlmMechanism::ScopedProcSetter proc_setter(
      MockGetMSTime, MockGenerateRandom, MockGetHostName);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Generate the NTLM messages based on known test data.
  std::string negotiate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kExpectedNegotiateMsg),
      std::size(ntlm::test::kExpectedNegotiateMsg)));
  std::string challenge_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kChallengeMsgFromSpecV2),
      std::size(ntlm::test::kChallengeMsgFromSpecV2)));
  std::string authenticate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(
          ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2),
      std::size(ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2)));

  // The authenticate message when |kWrongPassword| is sent.
  std::string wrong_password_authenticate_msg(
      "TlRMTVNTUAADAAAAGAAYAFgAAACKAIoAcAAAAAwADAD6AAAACAAIAAYBAAAQABAADgEAAAAA"
      "AABYAAAAA4IIAAAAAAAAAAAAAPknEYqtJQtusopDRSfYzAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAOtVz38osnFdRRggUQHUJ3EBAQAAAAAAAIALyP0A1NIBqqqqqqqqqqoAAAAAAgAMAEQA"
      "bwBtAGEAaQBuAAEADABTAGUAcgB2AGUAcgAGAAQAAgAAAAoAEAAAAAAAAAAAAAAAAAAAAAAA"
      "CQAWAEgAVABUAFAALwBzAGUAcgB2AGUAcgAAAAAAAAAAAEQAbwBtAGEAaQBuAFUAcwBlAHIA"
      "QwBPAE0AUABVAFQARQBSAA==");

  // Sanity check that it's the same length as the correct authenticate message
  // and that it's different.
  ASSERT_EQ(authenticate_msg.length(),
            wrong_password_authenticate_msg.length());
  ASSERT_NE(authenticate_msg, wrong_password_authenticate_msg);

  MockWrite data_writes1[] = {
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      // Negotiate and NTLM are often requested together.  However, we only want
      // to test NTLM. Since Negotiate is preferred over NTLM, we have to skip
      // the header that requests Negotiate for this test.
      MockRead("WWW-Authenticate: NTLM\r\n"), MockRead("Connection: close\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      // Missing content -- won't matter, as connection will be reset.
  };

  MockWrite data_writes2[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      MockWrite("\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (using incorrect credentials).  The second request continues on the
      // same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(wrong_password_authenticate_msg.c_str()),
      MockWrite("\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      // The origin server responds with a Type 2 message.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM "), MockRead(challenge_msg.c_str()),
      MockRead("\r\n"), MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      MockRead("You are not authorized to view this page\r\n"),

      // Wrong password.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM\r\n"), MockRead("Connection: close\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      // Missing content -- won't matter, as connection will be reset.
  };

  MockWrite data_writes3[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      MockWrite("\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(authenticate_msg.c_str()),
      MockWrite("\r\n\r\n"),
  };

  MockRead data_reads3[] = {
      // The origin server responds with a Type 2 message.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM "),
      MockRead(challenge_msg.c_str()),
      MockRead("\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      MockRead("You are not authorized to view this page\r\n"),

      // Lastly we get the desired content.
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=utf-8\r\n"),
      MockRead("Content-Length: 14\r\n\r\n"),
      MockRead("Please Login\r\n"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  StaticSocketDataProvider data3(data_reads3, data_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  SSLSocketDataProvider ssl1(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  // Enter the wrong password.
  rv = trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, kWrongPassword),
      callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge));

  TestCompletionCallback callback4;

  // Now enter the right password.
  rv = trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, ntlm::test::kPassword),
      callback4.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback4.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  TestCompletionCallback callback5;

  // One more roundtrip
  rv = trans.RestartWithAuth(AuthCredentials(), callback5.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback5.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(14, response->headers->GetContentLength());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Please Login\r\n", response_data);

  EXPECT_TRUE(data1.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllWriteDataConsumed());
  EXPECT_TRUE(data2.AllReadDataConsumed());
  EXPECT_TRUE(data2.AllWriteDataConsumed());
  EXPECT_TRUE(data3.AllReadDataConsumed());
  EXPECT_TRUE(data3.AllWriteDataConsumed());
}

// Server requests NTLM authentication, which is not supported over HTTP/2.
// Subsequent request with authorization header should be sent over HTTP/1.1.
TEST_P(HttpNetworkTransactionTest, NTLMOverHttp2) {
  HttpAuthNtlmMechanism::ScopedProcSetter proc_setter(
      MockGetMSTime, MockGenerateRandom, MockGetHostName);

  const char kUrl[] = "https://server/kids/login.aspx";

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(kUrl);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // First request without credentials.
  quiche::HttpHeaderBlock request_headers0(
      spdy_util_.ConstructGetHeaderBlock(kUrl));
  spdy::SpdySerializedFrame request0(spdy_util_.ConstructSpdyHeaders(
      1, std::move(request_headers0), LOWEST, true));

  quiche::HttpHeaderBlock response_headers0;
  response_headers0[spdy::kHttp2StatusHeader] = "401";
  response_headers0["www-authenticate"] = "NTLM";
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(response_headers0), true));

  // Stream 1 is closed.
  spdy_util_.UpdateWithStreamDestruction(1);

  // Generate the NTLM messages based on known test data.
  std::string negotiate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kExpectedNegotiateMsg),
      std::size(ntlm::test::kExpectedNegotiateMsg)));
  std::string challenge_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kChallengeMsgFromSpecV2),
      std::size(ntlm::test::kChallengeMsgFromSpecV2)));
  std::string authenticate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(
          ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2),
      std::size(ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2)));

  MockWrite writes0[] = {CreateMockWrite(request0, 0)};
  MockRead reads0[] = {CreateMockRead(resp, 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};

  // Retry yet again using HTTP/1.1.
  MockWrite writes1[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      MockWrite("\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(authenticate_msg.c_str()),
      MockWrite("\r\n\r\n"),
  };

  MockRead reads1[] = {
      // The origin server responds with a Type 2 message.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM "),
      MockRead(challenge_msg.c_str()),
      MockRead("\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      MockRead("You are not authorized to view this page\r\n"),

      // Lastly we get the desired content.
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=utf-8\r\n"),
      MockRead("Content-Length: 14\r\n\r\n"),
      MockRead("Please Login\r\n"),
  };
  SequencedSocketData data0(reads0, writes0);
  StaticSocketDataProvider data1(reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl0(ASYNC, OK);
  ssl0.next_proto = kProtoHTTP2;
  ssl0.next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  SSLSocketDataProvider ssl1(ASYNC, OK);
  // When creating the second connection, only HTTP/1.1 should be allowed.
  ssl1.next_protos_expected_in_ssl_config = NextProtoVector{kProtoHTTP11};
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl0);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, ntlm::test::kPassword),
      callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  TestCompletionCallback callback3;

  rv = trans.RestartWithAuth(AuthCredentials(), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(14, response->headers->GetContentLength());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Please Login\r\n", response_data);

  EXPECT_TRUE(data0.AllReadDataConsumed());
  EXPECT_TRUE(data0.AllWriteDataConsumed());
  EXPECT_TRUE(data1.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllWriteDataConsumed());

  EXPECT_TRUE(session->http_server_properties()->RequiresHTTP11(
      url::SchemeHostPort(request.url), NetworkAnonymizationKey()));
}

// Same as above, but with a host mapping in place. The mapped host is the one
// that should be tagged as requiring HTTP11.
TEST_P(HttpNetworkTransactionTest, NTLMOverHttp2WithHostMapping) {
  HttpAuthNtlmMechanism::ScopedProcSetter proc_setter(
      MockGetMSTime, MockGenerateRandom, MockGetHostName);

  const char kUrl[] = "https://server/kids/login.aspx";
  const char kMappedUrl[] = "https://server2:12345/kids/login.aspx";
  session_deps_.host_mapping_rules.AddRuleFromString(
      "MAP server server2:12345");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(kUrl);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // First request without credentials.
  quiche::HttpHeaderBlock request_headers0(
      spdy_util_.ConstructGetHeaderBlock(kUrl));
  spdy::SpdySerializedFrame request0(spdy_util_.ConstructSpdyHeaders(
      1, std::move(request_headers0), LOWEST, true));

  quiche::HttpHeaderBlock response_headers0;
  response_headers0[spdy::kHttp2StatusHeader] = "401";
  response_headers0["www-authenticate"] = "NTLM";
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(response_headers0), true));

  // Stream 1 is closed.
  spdy_util_.UpdateWithStreamDestruction(1);

  // Generate the NTLM messages based on known test data.
  std::string negotiate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kExpectedNegotiateMsg),
      std::size(ntlm::test::kExpectedNegotiateMsg)));
  std::string challenge_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kChallengeMsgFromSpecV2),
      std::size(ntlm::test::kChallengeMsgFromSpecV2)));
  std::string authenticate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(
          ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2),
      std::size(ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2)));

  MockWrite writes0[] = {CreateMockWrite(request0, 0)};
  MockRead reads0[] = {CreateMockRead(resp, 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};

  // Retry yet again using HTTP/1.1.
  MockWrite writes1[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      MockWrite("\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "),
      MockWrite(authenticate_msg.c_str()),
      MockWrite("\r\n\r\n"),
  };

  MockRead reads1[] = {
      // The origin server responds with a Type 2 message.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM "),
      MockRead(challenge_msg.c_str()),
      MockRead("\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      MockRead("You are not authorized to view this page\r\n"),

      // Lastly we get the desired content.
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=utf-8\r\n"),
      MockRead("Content-Length: 14\r\n\r\n"),
      MockRead("Please Login\r\n"),
  };
  SequencedSocketData data0(reads0, writes0);
  StaticSocketDataProvider data1(reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl0(ASYNC, OK);
  ssl0.next_proto = kProtoHTTP2;
  ssl0.next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  SSLSocketDataProvider ssl1(ASYNC, OK);
  // When creating the second connection, only HTTP/1.1 should be allowed.
  ssl1.next_protos_expected_in_ssl_config = NextProtoVector{kProtoHTTP11};
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl0);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, ntlm::test::kPassword),
      callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  TestCompletionCallback callback3;

  rv = trans.RestartWithAuth(AuthCredentials(), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(14, response->headers->GetContentLength());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Please Login\r\n", response_data);

  EXPECT_TRUE(data0.AllReadDataConsumed());
  EXPECT_TRUE(data0.AllWriteDataConsumed());
  EXPECT_TRUE(data1.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllWriteDataConsumed());

  EXPECT_FALSE(session->http_server_properties()->RequiresHTTP11(
      url::SchemeHostPort(request.url), NetworkAnonymizationKey()));
  EXPECT_TRUE(session->http_server_properties()->RequiresHTTP11(
      url::SchemeHostPort(GURL(kMappedUrl)), NetworkAnonymizationKey()));
}

#if BUILDFLAG(ENABLE_WEBSOCKETS)

// Variant of above test using WebSockets.
TEST_P(HttpNetworkTransactionTest, NTLMOverHttp2WithWebsockets) {
  const GURL kInitialUrl("https://server/");
  const GURL kWebSocketUrl("wss://server/");
  HttpAuthNtlmMechanism::ScopedProcSetter proc_setter(
      MockGetMSTime, MockGenerateRandom, MockGetHostName);

  // Initial request establishes an H2 connection, which will then be reused for
  // WebSockets. This is needed since WebSockets will reuse H2 connections, but
  // it won't create a new one.
  quiche::HttpHeaderBlock initial_request_headers(
      spdy_util_.ConstructGetHeaderBlock(kInitialUrl.spec()));
  spdy::SpdySerializedFrame initial_request(spdy_util_.ConstructSpdyHeaders(
      1, std::move(initial_request_headers), DEFAULT_PRIORITY, true));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  // Settings frame, indicating WebSockets is supported.
  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));

  // Response headers for first request. Body is never received, but that
  // shouldn't matter for the purposes of this test.
  spdy::SpdySerializedFrame initial_response(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // First WebSocket request, which has no credentials.
  quiche::HttpHeaderBlock websocket_request_headers;
  websocket_request_headers[spdy::kHttp2MethodHeader] = "CONNECT";
  websocket_request_headers[spdy::kHttp2AuthorityHeader] = "server";
  websocket_request_headers[spdy::kHttp2SchemeHeader] = "https";
  websocket_request_headers[spdy::kHttp2PathHeader] = "/";
  websocket_request_headers[spdy::kHttp2ProtocolHeader] = "websocket";
  websocket_request_headers["origin"] = "http://server";
  websocket_request_headers["sec-websocket-version"] = "13";
  websocket_request_headers["sec-websocket-extensions"] =
      "permessage-deflate; client_max_window_bits";
  spdy::SpdySerializedFrame websocket_request(spdy_util_.ConstructSpdyHeaders(
      3, std::move(websocket_request_headers), MEDIUM, false));

  // Auth challenge to WebSocket request.
  quiche::HttpHeaderBlock auth_challenge_headers;
  auth_challenge_headers[spdy::kHttp2StatusHeader] = "401";
  auth_challenge_headers["www-authenticate"] = "NTLM";
  spdy::SpdySerializedFrame websocket_auth_challenge(
      spdy_util_.ConstructSpdyResponseHeaders(
          3, std::move(auth_challenge_headers), true));

  MockWrite writes0[] = {CreateMockWrite(initial_request, 0),
                         CreateMockWrite(settings_ack, 2),
                         CreateMockWrite(websocket_request, 4),
                         MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 7)};
  MockRead reads0[] = {CreateMockRead(settings_frame, 1),
                       CreateMockRead(initial_response, 3),
                       CreateMockRead(websocket_auth_challenge, 5),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6)};

  // Generate the NTLM messages based on known test data.
  std::string negotiate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kExpectedNegotiateMsg),
      std::size(ntlm::test::kExpectedNegotiateMsg)));
  std::string challenge_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kChallengeMsgFromSpecV2),
      std::size(ntlm::test::kChallengeMsgFromSpecV2)));
  std::string authenticate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(
          ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2),
      std::size(ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2)));

  // Retry yet again using HTTP/1.1.
  MockWrite writes1[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: Upgrade\r\n"
                "Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      MockWrite("\r\n"),
      MockWrite("Origin: http://server\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: Upgrade\r\n"
                "Authorization: NTLM "),
      MockWrite(authenticate_msg.c_str()),
      MockWrite("\r\n"),
      MockWrite("Origin: http://server\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n"),
  };

  MockRead reads1[] = {
      // The origin server responds with a Type 2 message.
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      MockRead("WWW-Authenticate: NTLM "),
      MockRead(challenge_msg.c_str()),
      MockRead("\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      MockRead("You are not authorized to view this page\r\n"),

      // Lastly we get the desired content.
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
  };
  SequencedSocketData data0(reads0, writes0);
  session_deps_.socket_factory->AddSocketDataProvider(&data0);
  SSLSocketDataProvider ssl0(ASYNC, OK);
  ssl0.next_proto = kProtoHTTP2;
  ssl0.next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl0);

  StaticSocketDataProvider data1(reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl1(ASYNC, OK);
  // When creating the second connection, only HTTP/1.1 should be allowed.
  ssl1.next_protos_expected_in_ssl_config = NextProtoVector{kProtoHTTP11};
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo initial_request_info;
  initial_request_info.method = "GET";
  initial_request_info.url = kInitialUrl;
  initial_request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction initial_trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback initial_callback;
  int rv = initial_trans.Start(&initial_request_info,
                               initial_callback.callback(), NetLogWithSource());
  EXPECT_THAT(initial_callback.GetResult(rv), IsOk());

  EXPECT_FALSE(session->http_server_properties()->RequiresHTTP11(
      url::SchemeHostPort(kInitialUrl), NetworkAnonymizationKey()));

  HttpRequestInfo websocket_request_info;
  websocket_request_info.method = "GET";
  websocket_request_info.url = kWebSocketUrl;
  websocket_request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(initial_request_info.url)
                  .Equals(HostPortPair::FromURL(websocket_request_info.url)));
  websocket_request_info.extra_headers.SetHeader("O
"""


```