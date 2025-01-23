Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Task:** The request asks for an analysis of a Chromium source code file (`http_network_transaction_unittest.cc`). The goal is to understand its functionality, its relationship to JavaScript, its testing logic, common usage errors, debugging insights, and a summary of its purpose, considering it's part 23 of 34.

2. **Identify Key Information in the Provided Snippet:** The provided code is primarily a large collection of test cases defined within a C++ unit test framework (likely Google Test, given the `TEST_P`, `SCOPED_TRACE`, `EXPECT_THAT`, `IsOk`, `IsError` syntax). Each test case seems to represent a specific scenario of HTTP communication, potentially involving proxies and authentication.

3. **Break Down the Test Case Structure:** I observe a consistent structure in the `test_configs` array. Each element represents a test and has fields like:
    * `line_number`: For debugging purposes.
    * `proxy_url`:  The URL of a proxy server (or `nullptr` for direct connection).
    * `proxy_auth_timing`: How proxy authentication is handled (e.g., synchronous, asynchronous, none).
    * `first_generate_proxy_token_rv`: The expected result of the first attempt to generate a proxy authentication token.
    * `server_url`: The URL of the target server.
    * `server_auth_timing`: How server authentication is handled.
    * `first_generate_server_token_rv`: The expected result of the first attempt to generate a server authentication token.
    * `num_auth_rounds`: The expected number of authentication rounds.
    * `first_ssl_round`:  When SSL/TLS is expected to be involved.
    * `rounds`: A nested array of `TestRound` structures.

4. **Analyze the `TestRound` Structure:**  Each `TestRound` seems to represent a single exchange in the HTTP communication. It contains:
    * `read`:  The expected data to be read from the socket (likely a `MockRead`).
    * `write`: The expected data to be written to the socket (likely a `MockWrite`).
    * `expected_rv`: The expected result code of the network operation.
    * `extra_read`/`extra_write`:  Additional read/write operations.

5. **Infer the Purpose of the File:** Based on the presence of numerous test cases covering different authentication scenarios (with and without proxies, different authentication schemes, success and failure cases, HTTPS), I can deduce that the primary function of `http_network_transaction_unittest.cc` is to **test the `HttpNetworkTransaction` class**. This class is a crucial component of Chromium's networking stack responsible for managing the lifecycle of an HTTP transaction, including handling authentication, proxies, and potentially TLS/SSL.

6. **Address the Specific Questions:**

    * **Functionality:** The file tests various aspects of `HttpNetworkTransaction`, especially how it handles different authentication scenarios in combination with proxies and HTTPS. It simulates network interactions using mock objects to verify the transaction's behavior.

    * **Relationship to JavaScript:**  While the C++ code doesn't directly *execute* JavaScript, the network requests it tests are often *initiated* by JavaScript code in a browser context. Examples include:
        * `fetch()` API calls.
        * `XMLHttpRequest` (XHR) requests.
        * Loading resources (images, CSS, scripts) initiated by the browser's rendering engine.

    * **Logical Inference (Input/Output):** The `test_configs` array provides the *input* to the tests (proxy settings, authentication methods, expected server responses). The *output* is the verification of the `HttpNetworkTransaction`'s behavior (the `EXPECT_THAT` assertions checking for expected error codes or the presence/absence of authentication challenges). I can construct examples like:
        * **Input:**  A request to a server requiring basic authentication.
        * **Expected Output:** The `HttpNetworkTransaction` should receive a 401 response, parse the `WWW-Authenticate` header, and be ready to restart with authentication credentials.

    * **User/Programming Errors:**  The tests implicitly cover common errors. For instance, tests with `ERR_INVALID_AUTH_CREDENTIALS` simulate scenarios where a user provides incorrect login details or a programmer incorrectly implements authentication logic. I can also provide examples like forgetting to handle authentication challenges in application code.

    * **User Operation to Reach This Code:**  I can trace back a user action to the network stack:
        1. User types a URL in the address bar or clicks a link.
        2. The browser's rendering engine needs to fetch resources.
        3. JavaScript (or the rendering engine itself) initiates a network request (using `fetch`, XHR, or internal mechanisms).
        4. The `HttpNetworkTransaction` class is involved in handling this request, including potential proxy negotiation and authentication.
        5. If there are issues (e.g., authentication failures), this unit test file contains tests that simulate and verify those scenarios.

    * **File's Purpose (as part 23/34):** Since it's part of a larger suite, this specific file likely focuses on a particular subset of `HttpNetworkTransaction`'s functionality, likely authentication and proxy interactions. Other parts of the test suite might cover other aspects like caching, connection management, or specific protocol features.

7. **Structure the Answer:**  I organize the answer to address each part of the request clearly and provide specific examples where needed. I start with the file's general functionality and then address each specific question in order.

8. **Refine and Review:** I review my answer for clarity, accuracy, and completeness, ensuring it addresses all aspects of the prompt. I make sure the examples are relevant and easy to understand. I pay attention to the "part 23 of 34" constraint when summarizing the file's specific contribution.
好的，让我们来分析一下 `net/http/http_network_transaction_unittest.cc` 的这个代码片段。

**功能归纳 (基于提供的代码片段):**

这段代码是 `HttpNetworkTransaction` 类的单元测试的一部分，专注于测试 **HTTP 身份验证 (Authentication)** 的各种场景，包括：

* **不同类型的服务器身份验证:**  测试与需要身份验证的 HTTP 服务器进行交互的情况（`AUTH_SYNC`, `AUTH_ASYNC`）。
* **通过代理服务器的身份验证:** 测试通过需要身份验证的 HTTP 代理服务器连接到目标服务器的情况。这包括代理服务器本身需要身份验证，以及目标服务器也需要身份验证的情况。
* **HTTPS 连接中的身份验证:**  测试通过 HTTPS 连接进行身份验证的情况，包括直接连接和通过代理服务器连接。
* **不同的身份验证结果:** 测试身份验证成功 (`OK`) 和失败 (`ERR_INVALID_AUTH_CREDENTIALS`) 的情况。
* **多轮身份验证:**  测试在一次请求中可能需要进行多次身份验证协商的情况。
* **不同的连接模式:**  测试直接连接和通过代理服务器连接的情况。
* **SSL/TLS 的使用:**  测试在 HTTPS 连接中身份验证的行为。
* **错误处理:** 测试当身份验证过程中发生错误时，`HttpNetworkTransaction` 的行为，例如无效的凭据、不支持的身份验证方案等。

**与 JavaScript 的关系及举例说明:**

`HttpNetworkTransaction` 类在 Chromium 的网络栈中负责处理底层的 HTTP 事务。JavaScript 代码通常通过以下 API 与网络进行交互，最终会触发 `HttpNetworkTransaction` 的使用：

* **`fetch()` API:** 这是现代 JavaScript 中发起网络请求的主要方式。
* **`XMLHttpRequest` (XHR):** 较旧的 API，仍然被广泛使用。
* **加载资源:**  当浏览器解析 HTML 并遇到需要加载的资源（例如图片、CSS、JavaScript 文件）时。

**举例说明:**

假设一个网站需要用户登录才能访问某些内容。当用户尝试访问受保护的页面时，服务器可能会返回一个 `401 Unauthorized` 响应，其中包含 `WWW-Authenticate` 头部，指示需要的身份验证方案（例如 Basic 或 Bearer）。

1. **JavaScript 发起请求:** 网站的 JavaScript 代码使用 `fetch()` 或 XHR 发起对受保护页面的请求。
   ```javascript
   fetch('/protected-resource')
     .then(response => {
       if (response.status === 401) {
         // 处理未授权的情况，例如提示用户登录
       } else if (response.ok) {
         return response.text();
       }
     })
     .then(data => {
       // 处理响应数据
     });
   ```

2. **`HttpNetworkTransaction` 处理身份验证:**
   * Chromium 的网络栈接收到这个请求。
   * `HttpNetworkTransaction` 尝试建立连接并发送请求。
   * 服务器返回 `401 Unauthorized` 响应。
   * `HttpNetworkTransaction` 解析 `WWW-Authenticate` 头部，识别出需要身份验证。
   * 如果用户之前已经登录，并且凭据可用，`HttpNetworkTransaction` 可能会自动使用这些凭据重新发送请求（这对应于测试用例中 `AUTH_SYNC` 或 `AUTH_ASYNC` 的成功情况）。
   * 如果凭据不可用，或者身份验证失败（例如用户输入了错误的密码），`HttpNetworkTransaction` 会返回相应的错误，例如 `ERR_INVALID_AUTH_CREDENTIALS`（对应于测试用例中的失败情况）。

3. **JavaScript 响应:**  JavaScript 代码根据 `fetch()` 或 XHR 的响应状态码和头部信息来处理身份验证流程。例如，如果收到 `401`，可能会跳转到登录页面或显示登录表单。

**逻辑推理、假设输入与输出:**

我们以代码中的一个测试用例为例进行逻辑推理：

```c++
      {__LINE__,
       kServer,
       AUTH_SYNC,
       OK,
       nullptr,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
```

**假设输入:**

* **目标服务器 (`kServer`):**  需要同步身份验证。
* **代理服务器:** 无代理 (`nullptr`).
* **代理身份验证:** 无 (`AUTH_NONE`).
* **服务器首次生成令牌结果:** 成功 (`OK`).
* **身份验证轮数:** 2 轮。
* **SSL:** 未使用 (`kNoSSL`).

**测试轮次 (`TestRound`):**

* **第一轮:**
    * **发送 (`kGet`):**  一个普通的 GET 请求，不带身份验证信息。
    * **接收 (`kServerChallenge`):** 服务器返回 `401 Unauthorized` 响应，包含身份验证挑战信息 (`WWW-Authenticate`).
    * **预期结果 (`OK`):**  网络操作成功（收到挑战）。
* **第二轮:**
    * **发送 (`kGetAuth`):**  带有身份验证信息的 GET 请求 (`Authorization` 头部)。
    * **接收 (`kSuccess`):** 服务器返回 `200 OK` 响应，表示身份验证成功。
    * **预期结果 (`OK`):**  网络操作成功（请求成功）。

**预期输出:**

这个测试用例期望 `HttpNetworkTransaction` 在收到服务器的身份验证挑战后，能够正确地生成身份验证令牌并重新发送请求，最终成功获取资源。

**用户或编程常见的使用错误及举例说明:**

* **用户错误:**
    * **输入错误的用户名或密码:** 这会导致身份验证失败，对应于测试用例中 `ERR_INVALID_AUTH_CREDENTIALS` 的场景。
    * **代理服务器需要身份验证但用户未配置或输入错误的代理凭据:**  会导致连接代理服务器失败或身份验证失败。

* **编程错误:**
    * **未正确处理 `401` 响应:**  开发者可能没有在 JavaScript 代码中正确地捕获 `401` 状态码并提示用户登录或重新尝试身份验证。
    * **在需要身份验证的请求中忘记添加 `Authorization` 头部:**  会导致服务器一直返回 `401`。
    * **错误地实现了身份验证逻辑:** 例如，错误地构建 `Authorization` 头部的内容。
    * **在通过需要身份验证的代理服务器访问资源时，没有配置代理服务器的身份验证信息。**

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中输入需要身份验证的网址或点击需要身份验证的链接。**
2. **浏览器解析 URL，确定需要发起网络请求。**
3. **Chromium 的网络栈开始处理请求。**
4. **如果需要代理服务器，则进行代理解析。**
5. **`HttpNetworkTransaction` 对象被创建，负责处理这个 HTTP 事务。**
6. **`HttpNetworkTransaction` 尝试建立到目标服务器（或代理服务器）的连接。**
7. **如果服务器返回 `401 Unauthorized` 或代理服务器返回 `407 Proxy Authentication Required` 响应，则触发身份验证流程。**
8. **`HttpNetworkTransaction` 会尝试找到合适的 `HttpAuthHandler` 来处理该身份验证方案。**
9. **`HttpAuthHandler` 会根据收到的挑战信息生成身份验证凭据。**
10. **`HttpNetworkTransaction` 使用生成的凭据重新发送请求。**
11. **如果在调试过程中遇到身份验证问题，开发者可能会查看网络日志 (chrome://net-internals/#events) 或使用网络抓包工具 (例如 Wireshark) 来查看 HTTP 请求和响应的详细信息，以便定位问题是否发生在身份验证环节。**  `http_network_transaction_unittest.cc` 中的测试用例覆盖了这些可能的场景，可以帮助开发者理解和修复相关问题。

**归纳其功能 (作为第 23 部分，共 34 部分):**

作为整个 `HttpNetworkTransaction` 单元测试套件的一部分，第 23 部分（基于您提供的代码片段）主要负责 **验证 `HttpNetworkTransaction` 类在各种 HTTP 身份验证场景下的正确行为**。它通过模拟不同的服务器和代理服务器的身份验证需求，以及不同的身份验证结果，来确保 `HttpNetworkTransaction` 能够可靠地处理身份验证协商过程，包括同步和异步的身份验证流程，以及在 HTTPS 连接中的身份验证。 这部分测试可能专注于身份验证逻辑的核心功能和各种边缘情况，为构建健壮的网络功能提供保障。 其他部分可能涵盖连接管理、数据传输、缓存、QUIC 等其他网络协议相关的测试。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第23部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetProxy, kSuccess, OK)}},
      // Non-authenticating HTTP server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_NONE,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      // Authenticating HTTP server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_ASYNC,
       OK,
       4,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       4,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      // Non-authenticating HTTPS server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       1,
       0,
       {TestRound(kGet, kSuccess, OK)}},
      // Authenticating HTTPS server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      // Non-authenticating HTTPS server with a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       1,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      // Authenticating HTTPS server through a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      // Non-Authenticating HTTPS server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_UNSUPPORTED_AUTH_SCHEME,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_UNEXPECTED,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, ERR_UNEXPECTED)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      // Authenticating HTTPS server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       4,
       2,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
  };

  for (const auto& test_config : test_configs) {
    SCOPED_TRACE(::testing::Message()
                 << "Test config at " << test_config.line_number);
    auto auth_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
    auto* auth_factory_ptr = auth_factory.get();
    session_deps_.http_auth_handler_factory = std::move(auth_factory);
    SSLInfo empty_ssl_info;

    // Set up authentication handlers as necessary.
    if (test_config.proxy_auth_timing != AUTH_NONE) {
      for (int n = 0; n < 3; n++) {
        auto auth_handler = std::make_unique<HttpAuthHandlerMock>();
        url::SchemeHostPort scheme_host_port(GURL(test_config.proxy_url));
        HttpAuthChallengeTokenizer tokenizer("Mock realm=proxy");
        auth_handler->InitFromChallenge(
            &tokenizer, HttpAuth::AUTH_PROXY, empty_ssl_info,
            NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource());
        auth_handler->SetGenerateExpectation(
            test_config.proxy_auth_timing == AUTH_ASYNC,
            n == 0 ? test_config.first_generate_proxy_token_rv : OK);
        auth_factory_ptr->AddMockHandler(std::move(auth_handler),
                                         HttpAuth::AUTH_PROXY);
      }
    }
    if (test_config.server_auth_timing != AUTH_NONE) {
      auto auth_handler = std::make_unique<HttpAuthHandlerMock>();
      url::SchemeHostPort scheme_host_port(GURL(test_config.server_url));
      HttpAuthChallengeTokenizer tokenizer("Mock realm=server");
      auth_handler->InitFromChallenge(&tokenizer, HttpAuth::AUTH_SERVER,
                                      empty_ssl_info, NetworkAnonymizationKey(),
                                      scheme_host_port, NetLogWithSource());
      auth_handler->SetGenerateExpectation(
          test_config.server_auth_timing == AUTH_ASYNC,
          test_config.first_generate_server_token_rv);
      auth_factory_ptr->AddMockHandler(std::move(auth_handler),
                                       HttpAuth::AUTH_SERVER);

      // The second handler always succeeds. It should only be used where there
      // are multiple auth sessions for server auth in the same network
      // transaction using the same auth scheme.
      std::unique_ptr<HttpAuthHandlerMock> second_handler =
          std::make_unique<HttpAuthHandlerMock>();
      second_handler->InitFromChallenge(
          &tokenizer, HttpAuth::AUTH_SERVER, empty_ssl_info,
          NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource());
      second_handler->SetGenerateExpectation(true, OK);
      auth_factory_ptr->AddMockHandler(std::move(second_handler),
                                       HttpAuth::AUTH_SERVER);
    }
    if (test_config.proxy_url) {
      session_deps_.proxy_resolution_service =
          ConfiguredProxyResolutionService::CreateFixedForTest(
              test_config.proxy_url, TRAFFIC_ANNOTATION_FOR_TESTS);
    } else {
      session_deps_.proxy_resolution_service =
          ConfiguredProxyResolutionService::CreateDirect();
    }

    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL(test_config.server_url);
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    SSLSocketDataProvider ssl_socket_data_provider(SYNCHRONOUS, OK);

    std::vector<std::vector<MockRead>> mock_reads(1);
    std::vector<std::vector<MockWrite>> mock_writes(1);
    for (int round = 0; round < test_config.num_auth_rounds; ++round) {
      SCOPED_TRACE(round);
      const TestRound& read_write_round = test_config.rounds[round];

      // Set up expected reads and writes.
      mock_reads.back().push_back(read_write_round.read);
      mock_writes.back().push_back(read_write_round.write);

      // kProxyChallenge uses Proxy-Connection: close which means that the
      // socket is closed and a new one will be created for the next request.
      if (read_write_round.read.data == kProxyChallenge.data) {
        mock_reads.emplace_back();
        mock_writes.emplace_back();
      }

      if (read_write_round.extra_read) {
        mock_reads.back().push_back(*read_write_round.extra_read);
      }
      if (read_write_round.extra_write) {
        mock_writes.back().push_back(*read_write_round.extra_write);
      }

      // Add an SSL sequence if necessary.
      if (round >= test_config.first_ssl_round) {
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            &ssl_socket_data_provider);
      }
    }

    std::vector<std::unique_ptr<StaticSocketDataProvider>> data_providers;
    for (size_t i = 0; i < mock_reads.size(); ++i) {
      data_providers.push_back(std::make_unique<StaticSocketDataProvider>(
          mock_reads[i], mock_writes[i]));
      session_deps_.socket_factory->AddSocketDataProvider(
          data_providers.back().get());
    }

    // Transaction must be created after DataProviders, so it's destroyed before
    // they are as well.
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    for (int round = 0; round < test_config.num_auth_rounds; ++round) {
      SCOPED_TRACE(round);
      const TestRound& read_write_round = test_config.rounds[round];
      // Start or restart the transaction.
      TestCompletionCallback callback;
      int rv;
      if (round == 0) {
        rv = trans.Start(&request, callback.callback(), NetLogWithSource());
      } else {
        rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                                   callback.callback());
      }
      if (rv == ERR_IO_PENDING) {
        rv = callback.WaitForResult();
      }

      // Compare results with expected data.
      EXPECT_THAT(rv, IsError(read_write_round.expected_rv));
      const HttpResponseInfo* response = trans.GetResponseInfo();
      if (read_write_round.expected_rv != OK) {
        EXPECT_EQ(round + 1, test_config.num_auth_rounds);
        continue;
      }
      if (round + 1 < test_config.num_auth_rounds) {
        EXPECT_TRUE(response->auth_challenge.has_value());
      } else {
        EXPECT_FALSE(response->auth_challenge.has_value());
        EXPECT_FALSE(trans.IsReadyToRestartForAuth());
      }
    }
  }
}

TEST_P(HttpNetworkTransactionTest, MultiRoundAuth) {
  // Do multi-round authentication and make sure it works correctly.
  auto auth_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auto* auth_factory_ptr = auth_factory.get();
  session_deps_.http_auth_handler_factory = std::move(auth_factory);
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateDirect();
  session_deps_.host_resolver->rules()->AddRule("www.example.com", "10.0.0.1");

  auto auth_handler = std::make_unique<HttpAuthHandlerMock>();
  auto* auth_handler_ptr = auth_handler.get();
  auth_handler->set_connection_based(true);
  GURL url("http://www.example.com");
  HttpAuthChallengeTokenizer tokenizer("Mock realm=server");
  SSLInfo empty_ssl_info;
  auth_handler->InitFromChallenge(&tokenizer, HttpAuth::AUTH_SERVER,
                                  empty_ssl_info, NetworkAnonymizationKey(),
                                  url::SchemeHostPort(url), NetLogWithSource());
  auth_factory_ptr->AddMockHandler(std::move(auth_handler),
                                   HttpAuth::AUTH_SERVER);

  int rv = OK;
  const HttpResponseInfo* response = nullptr;
  HttpRequestInfo request;
  request.method = "GET";
  request.url = url;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Use a TCP Socket Pool with only one connection per group. This is used
  // to validate that the TCP socket is not released to the pool between
  // each round of multi-round authentication.
  constexpr size_t kMaxSocketsPerPool = 50u;
  constexpr size_t kMaxSocketsPerGroup = 1u;
  HttpNetworkSessionPeer session_peer(session.get());
  CommonConnectJobParams common_connect_job_params(
      session->CreateCommonConnectJobParams());
  auto transport_pool = std::make_unique<TransportClientSocketPool>(
      kMaxSocketsPerPool,   // Max sockets for pool
      kMaxSocketsPerGroup,  // Max sockets per group
      /*unused_idle_socket_timeout=*/base::Seconds(10), ProxyChain::Direct(),
      /*is_for_websockets=*/false, &common_connect_job_params);
  auto* transport_pool_ptr = transport_pool.get();
  auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
  mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                   std::move(transport_pool));
  session_peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    session->http_stream_pool()->set_max_stream_sockets_per_group_for_testing(
        kMaxSocketsPerGroup);
    session->http_stream_pool()->set_max_stream_sockets_per_pool_for_testing(
        kMaxSocketsPerPool);
  }

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  const MockWrite kGet(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n\r\n");
  const MockWrite kGetAuth(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n"
      "Authorization: auth_token\r\n\r\n");

  const MockRead kServerChallenge(
      "HTTP/1.1 401 Unauthorized\r\n"
      "WWW-Authenticate: Mock realm=server\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 14\r\n\r\n"
      "Unauthorized\r\n");
  const MockRead kSuccess(
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 3\r\n\r\n"
      "Yes");

  MockWrite writes[] = {
      // First round
      kGet,
      // Second round
      kGetAuth,
      // Third round
      kGetAuth,
      // Fourth round
      kGetAuth,
      // Competing request
      kGet,
  };
  MockRead reads[] = {
      // First round
      kServerChallenge,
      // Second round
      kServerChallenge,
      // Third round
      kServerChallenge,
      // Fourth round
      kSuccess,
      // Competing response
      kSuccess,
  };
  StaticSocketDataProvider data_provider(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data_provider);

  const ClientSocketPool::GroupId kSocketGroup(
      url::SchemeHostPort(url::kHttpScheme, "www.example.com", 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  const HttpStreamKey kHttpStreamKey(GroupIdToHttpStreamKey(kSocketGroup));

  auto IdleSocketCountInGroup = [&] {
    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      return session->http_stream_pool()
          ->GetOrCreateGroupForTesting(kHttpStreamKey)
          .IdleStreamSocketCount();
    } else {
      return transport_pool_ptr->IdleSocketCountInGroup(kSocketGroup);
    }
  };

  // First round of authentication.
  auth_handler_ptr->SetGenerateExpectation(false, OK);
  rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->auth_challenge.has_value());
  EXPECT_EQ(0u, IdleSocketCountInGroup());
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_GENERATE_AUTH_TOKEN,
            auth_handler_ptr->state());

  // In between rounds, another request comes in for the same domain.
  // It should not be able to grab the TCP socket that trans has already
  // claimed.
  HttpNetworkTransaction trans_compete(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback_compete;
  rv = trans_compete.Start(&request, callback_compete.callback(),
                           NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // callback_compete.WaitForResult at this point would stall forever,
  // since the HttpNetworkTransaction does not release the request back to
  // the pool until after authentication completes.

  // Second round of authentication.
  auth_handler_ptr->SetGenerateExpectation(false, OK);
  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(0u, IdleSocketCountInGroup());
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_GENERATE_AUTH_TOKEN,
            auth_handler_ptr->state());

  // Third round of authentication.
  auth_handler_ptr->SetGenerateExpectation(false, OK);
  rv = trans.RestartWithAuth(AuthCredentials(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(0u, IdleSocketCountInGroup());
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_GENERATE_AUTH_TOKEN,
            auth_handler_ptr->state());

  // Fourth round of authentication, which completes successfully.
  auth_handler_ptr->SetGenerateExpectation(false, OK);
  rv = trans.RestartWithAuth(AuthCredentials(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(0u, IdleSocketCountInGroup());

  // In WAIT_FOR_CHALLENGE, although in reality the auth handler is done. A real
  // auth handler should transition to a DONE state in concert with the remote
  // server. But that's not something we can test here with a mock handler.
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_CHALLENGE,
            auth_handler_ptr->state());

  // Read the body since the fourth round was successful. This will also
  // release the socket back to the pool.
  scoped_refptr<IOBufferWithSize> io_buf =
      base::MakeRefCounted<IOBufferWithSize>(50);
  rv = trans.Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_EQ(3, rv);
  rv = trans.Read(io_buf.get(), io_buf->size(), callback.callback());
  EXPECT_EQ(0, rv);
  // There are still 0 idle sockets, since the trans_compete transaction
  // will be handed it immediately after trans releases it to the group.
  EXPECT_EQ(0u, IdleSocketCountInGroup());

  // The competing request can now finish. Wait for the headers and then
  // read the body.
  rv = callback_compete.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  rv = trans_compete.Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_EQ(3, rv);
  rv = trans_compete.Read(io_buf.get(), io_buf->size(), callback.callback());
  EXPECT_EQ(0, rv);

  // Finally, the socket is released to the group.
  EXPECT_EQ(1u, IdleSocketCountInGroup());
}

// This tests the case that a request is issued via http instead of spdy after
// npn is negotiated.
TEST_P(HttpNetworkTransactionTest, NpnWithHttpOverSSL) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;

  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
}

// Simulate the SSL handshake completing with a ALPN negotiation followed by an
// immediate server closing of the socket.
// Regression test for https://crbug.com/46369.
TEST_P(HttpNetworkTransactionTest, SpdyPostALPNServerHangup) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 1)};

  MockRead spdy_reads[] = {
      MockRead(SYNCHRONOUS, 0, 0)  // Not async - return 0 immediately.
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// A subclass of HttpAuthHandlerMock that records the request URL when
// it gets it. This is needed since the auth handler may get destroyed
// before we get a chance to query it.
class UrlRecordingHttpAuthHandlerMock : public HttpAuthHandlerMock {
 public:
  explicit UrlRecordingHttpAuthHandlerMock(GURL* url) : url_(url) {}

  ~UrlRecordingHttpAuthHandlerMock() override = default;

 protected:
  int GenerateAuthTokenImpl(const AuthCredentials* credentials,
                            const HttpRequestInfo* request,
                            CompletionOnceCallback callback,
                            std::string* auth_token) override {
    *url_ = request->url;
    return HttpAuthHandlerMock::GenerateAuthTokenImpl(
        credentials, request, std::move(callback), auth_token);
  }

 private:
  raw_ptr<GURL> url_ = nullptr;
};

// Test that if we cancel the transaction as the connection is completing, that
// everything tears down correctly.
TEST_P(HttpNetworkTransactionTest, SimpleCancel) {
  // Setup everything about the connection to complete synchronously, so that
  // after calling HttpNetworkTransaction::Start, the only thing we're waiting
  // for is the callback from the HttpStreamRequest.
  // Then cancel the transaction.
  // Verify that we don't crash.
  MockConnect mock_connect(SYNCHRONOUS, OK);
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, "HTTP/1.0 200 OK\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data(data_reads, base::span<MockWrite
```