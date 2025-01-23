Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The core request is to analyze a C++ unit test file for Chromium's network stack, specifically related to `net/url_request/url_request_unittest.cc`. The goal is to understand its functionality, identify connections to JavaScript (if any), analyze its logic with input/output examples, pinpoint potential user/programmer errors, suggest debugging steps, and summarize its overall function in the context of the larger file. The "part 14 of 17" is a strong hint that this snippet focuses on a specific set of functionalities within the broader unit test file.

2. **Initial Scan for Keywords and Structure:** Quickly skim the code looking for recurring patterns, class names, function names, and key terms. Notice the heavy use of:
    * `TEST_F`:  Indicates this is a Google Test framework file. Each `TEST_F` defines an individual test case.
    * Class names like `HTTPSOCSPTest`, `HTTPSOCSPVerifyTest`, `HTTPSAIATest`, `HTTPSHardFailTest`, `HTTPSCRLSetTest`, `HTTPSLocalCRLSetTest`. This immediately suggests the code is testing various aspects of HTTPS, particularly related to certificate validation and revocation.
    *  Terms like `OCSP`, `CRL`, `AIA`, `CertStatus`, `CertVerifier`, `EmbeddedTestServer`, `SSLInfo`, `URLRequest`. These are central to understanding the domain: certificate revocation, authority information access, certificate status codes, certificate verification mechanisms, a test server setup, SSL/TLS information, and URL requests.
    *  Assertions like `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_TRUE`, `ASSERT_EQ`. These confirm expected outcomes of the tests.
    *  Conditional logic based on system capabilities: `if (!SystemSupportsOCSP())`, `if (!SystemSupportsOCSPStapling())`, `if (!SystemSupportsHardFailRevocationChecking())`, `if (!SystemSupportsCRLSets())`. This indicates the tests are designed to be robust across different OS configurations and feature availability.

3. **Group Tests by Class:**  The class names provide a natural way to categorize the functionalities being tested.

    * `HTTPSOCSPTest`: Seems to be a base class for tests involving OCSP.
    * `HTTPSOCSPVerifyTest`:  Specifically tests the verification of OCSP responses based on different configurations (defined in `kOCSPVerifyData`).
    * `HTTPSAIATest`: Focuses on testing the fetching of intermediate certificates via AIA (Authority Information Access).
    * `HTTPSHardFailTest`: Tests scenarios where certificate revocation checks should result in a hard failure (connection refusal).
    * `HTTPSCRLSetTest`: Deals with testing certificate revocation using CRLSets (Certificate Revocation Lists Sets).
    * `HTTPSLocalCRLSetTest`:  Seems to test CRLSets in a more local or controlled environment, potentially focusing on specific interception scenarios.

4. **Analyze Individual Test Cases:**  For each test case, try to understand the scenario being set up and the expected outcome. Look at the configurations of `EmbeddedTestServer::ServerCertificateConfig`, especially the `ocsp_config`, `stapled_ocsp_config`, and `intermediate` settings. The assertions (`EXPECT_EQ`, `EXPECT_TRUE`) are crucial for understanding the expected behavior.

5. **Look for JavaScript Connections (and realize there aren't any direct ones in *this* snippet):**  While the *overall* Chromium network stack is heavily used by JavaScript in the browser, this specific *unit test* file is written in C++ and focuses on low-level network stack functionality. It's testing the *underlying mechanisms* that would be used when JavaScript makes network requests, but there's no direct JavaScript code here. The connection is *indirect*. JavaScript uses the network stack, and these tests ensure the network stack works correctly for scenarios that JavaScript might encounter.

6. **Identify Logic and Examples:** The `kOCSPVerifyData` array in `HTTPSOCSPVerifyTest` is a prime example of structured input and expected output. Each entry defines an `OCSPConfig` and the corresponding `expected_response_status` and `expected_cert_status`. This allows for concrete examples of the logic being tested. For other tests, the logic is embedded in the setup of the `EmbeddedTestServer::ServerCertificateConfig` and the assertions. Think about what conditions lead to different outcomes (e.g., an old OCSP response, a revoked certificate, an invalid OCSP response).

7. **Consider User/Programmer Errors:** Think about how someone might misuse these features or introduce bugs. Common errors might include:
    * Incorrectly configuring OCSP/CRL settings on a server.
    * Not handling certificate errors properly in application code.
    * Relying on outdated or invalid OCSP responses.
    * Misunderstanding the implications of hard-fail revocation checking.

8. **Outline Debugging Steps:**  Imagine a scenario where a test is failing. What steps would a developer take?
    * Examine the test setup (`EmbeddedTestServer` configuration).
    * Inspect the `CertStatus` values.
    * Use network debugging tools to examine the actual OCSP/CRL requests and responses.
    * Check the system's OCSP/CRL settings.
    * Run the tests with increased logging to get more detailed information.

9. **Synthesize the Summary:**  Based on the analysis, formulate a concise summary of the snippet's functionality, emphasizing its role in testing HTTPS certificate validation and revocation mechanisms within the Chromium network stack.

10. **Address the "Part 14 of 17" aspect:**  Recognize that this snippet is likely part of a larger file organized by feature area. The focus on OCSP, AIA, CRLSets, and hard-fail revocation indicates this section specifically tests certificate validation and revocation aspects of the network stack.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Maybe some of these tests directly interact with JavaScript testing frameworks."  **Correction:**  Upon closer inspection, it's clear these are low-level C++ unit tests. The connection to JavaScript is indirect, through the network stack APIs.
* **Initial thought:**  "Just list the test names." **Refinement:**  Need to explain *what* each test is actually doing and the scenarios it covers.
* **Initial thought:**  "Focus heavily on the technical details of OCSP and CRL." **Refinement:** Balance technical details with explanations that are understandable to someone who might not be a networking expert. Explain *why* these tests are important.

By following this structured approach, combining code examination with domain knowledge and logical reasoning, it's possible to generate a comprehensive analysis of the provided code snippet.
这是 `net/url_request/url_request_unittest.cc` 文件中的一部分，专门用于测试 Chromium 网络栈中与 HTTPS 证书验证相关的特性，特别是针对 **OCSP (Online Certificate Status Protocol)**, **AIA (Authority Information Access)** 和 **CRLSet (Certificate Revocation List Set)** 功能的单元测试。

**功能列表:**

1. **OCSP 功能测试:**
   - 测试在不同 OCSP 响应状态下（Good, Revoked, Unknown, Try Later, Invalid Response 等）连接的表现。
   - 测试 OCSP 响应的有效期（Valid, Old, Early, Long）。
   - 测试 Stapled OCSP (OCSP 装订) 功能，包括有效和无效的装订响应。
   - 测试 AIA 获取 OCSP 响应的功能。
   - 测试 Hard Fail OCSP 功能，即当 OCSP 检查失败时，连接是否会立即失败。
   - 测试在启用 Hard Fail 的情况下，不同 OCSP 响应状态和 Stapled OCSP 的行为。

2. **AIA 功能测试:**
   - 测试浏览器是否能通过 AIA 信息成功获取中间证书。

3. **CRLSet 功能测试:**
   - 测试当 CRLSet 过期时，连接的行为。
   - 测试 CRLSet 中标记为吊销的证书是否会被正确识别。
   - 测试通过证书的 SPKI Hash 和 Common Name 在 CRLSet 中进行吊销检查。
   - 测试 Known Interception Blocking 功能，当 CRLSet 标记某个根证书为已知的中间人攻击时，连接是否会被阻止。
   - 测试在 HSTS 站点上，即使已知拦截，是否可以通过某些机制进行覆盖。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不包含 JavaScript，但它测试的网络栈功能是 JavaScript 在浏览器环境中发起 HTTPS 请求的基础。当 JavaScript 代码使用 `fetch()` 或 `XMLHttpRequest` 等 API 发起 HTTPS 请求时，Chromium 的网络栈会执行证书验证，其中就包括这里测试的 OCSP 和 CRLSet 等功能。

**举例说明:**

假设一个 JavaScript 应用程序尝试访问一个使用了被吊销证书的 HTTPS 网站。

```javascript
fetch('https://revoked.example.com')
  .then(response => {
    console.log('请求成功', response);
  })
  .catch(error => {
    console.error('请求失败', error); // 这里会捕获到错误
  });
```

这段 C++ 代码中的测试会模拟 `revoked.example.com` 的服务器返回一个指示证书被吊销的 OCSP 响应，或者该证书被包含在活动的 CRLSet 中。网络栈会根据这些信息判断证书无效，从而阻止连接的建立，JavaScript 的 `fetch()` 操作最终会进入 `catch` 代码块，并抛出一个表示连接失败的错误，例如 `net::ERR_CERT_REVOKED`。

**逻辑推理 (假设输入与输出):**

**场景 1: 测试 OldStapledAndInvalidAIA (过期的装订 OCSP 响应和无效的 AIA OCSP)**

* **假设输入:**
    * 服务器配置为提供一个过期的装订 OCSP 响应 (表示证书良好但响应时间太旧)。
    * 服务器证书的 AIA 扩展指向一个 OCSP 服务器，但该服务器不返回成功的 OCSP 响应 (例如返回 "Try Later" 状态)。
    * 启用了 Hard Fail Revocation Checking。
* **预期输出:**
    * `cert_status` 将包含 `CERT_STATUS_UNABLE_TO_CHECK_REVOCATION` 标志，表示无法完成吊销检查。
    * `cert_status` 将包含 `CERT_STATUS_REV_CHECKING_ENABLED` 标志，表示已尝试进行吊销检查。

**场景 2: 测试 CRLSetRevoked (证书在 CRLSet 中被标记为吊销)**

* **假设输入:**
    * 服务器提供一个有效的证书。
    * 一个活动的 CRLSet 被加载，其中包含该服务器证书的序列号（或者 Subject 或 SPKI Hash）。
* **预期输出:**
    * `cert_status` 将包含 `CERT_STATUS_REVOKED` 标志，表示证书已被吊销。
    * `cert_status` 将不包含 `CERT_STATUS_REV_CHECKING_ENABLED` 标志，因为吊销状态直接从 CRLSet 获取，无需在线检查。

**用户或编程常见的使用错误:**

1. **服务器配置错误:**  服务器管理员可能错误地配置 OCSP 服务器或 AIA 信息，导致浏览器无法获取正确的吊销信息。例如，OCSP 服务器地址错误，或者 OCSP 响应格式不正确。
   * **调试线索:** 用户可能会看到证书错误页面，开发者可以通过浏览器控制台的网络面板查看证书信息和 OCSP 请求的状态。
2. **客户端系统时间不正确:**  OCSP 响应的有效期是基于时间的。如果用户的系统时间不正确，可能会导致有效的 OCSP 响应被认为过期。
   * **调试线索:** 用户可能会遇到间歇性的证书错误，尤其是在 OCSP 响应接近过期时间时。
3. **未处理证书错误:**  在开发网络应用程序时，开发者可能没有正确处理 HTTPS 连接可能出现的证书错误，例如忽略 `fetch()` 的 `catch` 块中的错误，导致用户无法得知连接失败的原因。
   * **调试线索:** 应用程序可能无法正常工作，但没有明显的错误提示。开发者需要检查浏览器的控制台日志。
4. **过度依赖 CRLSet 而忽略在线检查:**  虽然 CRLSet 可以提高性能，但它可能不是最新的。如果开发者或用户过于依赖 CRLSet，可能会忽略证书的最新吊销状态。
   * **调试线索:**  用户可能在某些情况下访问到已被吊销的证书，但浏览器没有发出警告。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏中输入一个 HTTPS 网址并按下回车键。**
2. **浏览器开始建立与服务器的 TCP 连接。**
3. **进行 TLS 握手。**
4. **在 TLS 握手期间，服务器会提供其证书。**
5. **Chromium 的网络栈接收到服务器证书后，会开始进行证书验证。**
6. **根据服务器的配置和浏览器的设置，网络栈可能会执行以下操作:**
   - **检查证书链的有效性。**
   - **检查证书是否在本地信任存储区中。**
   - **尝试获取 OCSP 响应:**
     - 如果服务器提供了 Stapled OCSP 响应，则直接使用。
     - 否则，根据证书的 AIA 扩展，向 OCSP 服务器发起请求。
   - **如果启用了 CRLSet，则检查证书是否在 CRLSet 中被标记为吊销。**
   - **如果启用了 Hard Fail Revocation Checking，并且 OCSP 检查失败，则立即终止连接。**
7. **这段代码中的单元测试模拟了各种 OCSP 响应和 CRLSet 的场景，以确保网络栈在这些步骤中的行为是正确的。**

**归纳一下它的功能 (作为第 14 部分，共 17 部分):**

作为 `net/url_request/url_request_unittest.cc` 文件的第 14 部分，这段代码主要负责 **测试 Chromium 网络栈中与 HTTPS 证书吊销状态检查相关的核心逻辑**。它通过模拟各种 OCSP 响应、AIA 配置和 CRLSet 的状态，验证网络栈在处理这些信息时的正确性和鲁棒性。这部分测试确保了浏览器能够安全可靠地处理 HTTPS 连接，防止用户连接到使用了被吊销证书的恶意网站。  考虑到它是 17 部分中的第 14 部分，可以推测之前的部分可能涉及更基础的 URLRequest 功能，而后续的部分可能会测试其他与网络请求相关的特性，例如缓存、代理或 QUIC 等。  这部分专注于安全相关的证书验证机制。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
CSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}});

  // AIA OCSP url is included, but does not return a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater);

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, OldStapledButValidAIA) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // Stapled response indicates good, but response is too old.
  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}});

  // AIA OCSP url is included, and returns a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

static const struct OCSPVerifyTestData {
  EmbeddedTestServer::OCSPConfig ocsp_config;
  bssl::OCSPVerifyResult::ResponseStatus expected_response_status;
  // |expected_cert_status| is only used if |expected_response_status| is
  // PROVIDED.
  bssl::OCSPRevocationStatus expected_cert_status;
} kOCSPVerifyData[] = {
    // 0
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::GOOD},

    // 1
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 2
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kEarly}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 3
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 4
    {EmbeddedTestServer::OCSPConfig(
         EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater),
     bssl::OCSPVerifyResult::ERROR_RESPONSE,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 5
    {EmbeddedTestServer::OCSPConfig(
         EmbeddedTestServer::OCSPConfig::ResponseType::kInvalidResponse),
     bssl::OCSPVerifyResult::PARSE_RESPONSE_ERROR,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 6
    {EmbeddedTestServer::OCSPConfig(
         EmbeddedTestServer::OCSPConfig::ResponseType::kInvalidResponseData),
     bssl::OCSPVerifyResult::PARSE_RESPONSE_DATA_ERROR,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 7
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::REVOKED,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kEarly}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 8
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::UNKNOWN,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::UNKNOWN},

    // 9
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::UNKNOWN,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 10
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::UNKNOWN,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kEarly}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 11
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kBeforeCert),
     bssl::OCSPVerifyResult::BAD_PRODUCED_AT,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 12
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kAfterCert),
     bssl::OCSPVerifyResult::BAD_PRODUCED_AT,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 13
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::GOOD},

    // 14
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kEarly},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::GOOD},

    // 15
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::GOOD},

    // 16
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kEarly},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 17
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::UNKNOWN,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid},
          {bssl::OCSPRevocationStatus::REVOKED,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::REVOKED},

    // 18
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::UNKNOWN,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::UNKNOWN},

    // 19
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::UNKNOWN,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid},
          {bssl::OCSPRevocationStatus::REVOKED,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong},
          {bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::UNKNOWN},

    // 20
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Serial::kMismatch}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::NO_MATCHING_RESPONSE,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 21
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::GOOD,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kEarly,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Serial::kMismatch}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::NO_MATCHING_RESPONSE,
     bssl::OCSPRevocationStatus::UNKNOWN},

    // 22
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::REVOKED,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::PROVIDED, bssl::OCSPRevocationStatus::REVOKED},

    // 23
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::REVOKED,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},

    // 24
    {EmbeddedTestServer::OCSPConfig(
         {{bssl::OCSPRevocationStatus::REVOKED,
           EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong}},
         EmbeddedTestServer::OCSPConfig::Produced::kValid),
     bssl::OCSPVerifyResult::INVALID_DATE, bssl::OCSPRevocationStatus::UNKNOWN},
};

class HTTPSOCSPVerifyTest
    : public HTTPSOCSPTest,
      public testing::WithParamInterface<OCSPVerifyTestData> {};

TEST_P(HTTPSOCSPVerifyTest, VerifyResult) {
  OCSPVerifyTestData test = GetParam();

  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root_cert);
  ScopedTestKnownRoot scoped_known_root(root_cert.get());

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.stapled_ocsp_config = test.ocsp_config;
  cert_config.dns_names = {"example.com"};

  SSLInfo ssl_info;
  OCSPErrorTestDelegate delegate;
  ASSERT_NO_FATAL_FAILURE(DoConnectionWithDelegate("example.com", cert_config,
                                                   &delegate, &ssl_info));

  // The SSLInfo must be extracted from |delegate| on error, due to how
  // URLRequest caches certificate errors.
  if (delegate.have_certificate_errors()) {
    ASSERT_TRUE(delegate.on_ssl_certificate_error_called());
    ssl_info = delegate.ssl_info();
  }

  EXPECT_EQ(test.expected_response_status,
            ssl_info.ocsp_result.response_status);

  if (test.expected_response_status == bssl::OCSPVerifyResult::PROVIDED) {
    EXPECT_EQ(test.expected_cert_status,
              ssl_info.ocsp_result.revocation_status);
  }
}

INSTANTIATE_TEST_SUITE_P(OCSPVerify,
                         HTTPSOCSPVerifyTest,
                         testing::ValuesIn(kOCSPVerifyData));

class HTTPSAIATest : public HTTPSCertNetFetchingTest {};

TEST_F(HTTPSAIATest, AIAFetching) {
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kByAIA;
  test_server.SetSSLConfig(cert_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  TestDelegate d;
  d.set_allow_certificate_errors(true);
  std::unique_ptr<URLRequest> r(context_->CreateRequest(
      test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));

  r->Start();
  EXPECT_TRUE(r->is_pending());

  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());

  CertStatus cert_status = r->ssl_info().cert_status;
  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  ASSERT_TRUE(r->ssl_info().cert);
  EXPECT_EQ(2u, r->ssl_info().cert->intermediate_buffers().size());
  ASSERT_TRUE(r->ssl_info().unverified_cert);
  EXPECT_EQ(0u, r->ssl_info().unverified_cert->intermediate_buffers().size());
}

class HTTPSHardFailTest : public HTTPSOCSPTest {
 protected:
  CertVerifier::Config GetCertVerifierConfig() override {
    CertVerifier::Config config;
    config.require_rev_checking_local_anchors = true;
    return config;
  }
};

TEST_F(HTTPSHardFailTest, Valid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, Revoked) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, FailsOnOCSPInvalid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kInvalidResponse);

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_UNABLE_TO_CHECK_REVOCATION,
            cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, IntermediateResponseOldButStillValid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  // Use an OCSP response for the intermediate that would be too old for a leaf
  // cert, but is still valid for an intermediate.
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, IntermediateResponseTooOld) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  // Use an OCSP response for the intermediate that is too old according to
  // BRs, but is fine for a locally trusted root.
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLonger}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, ValidStapled) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // AIA OCSP url is included, but does not return a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater);

  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, RevokedStapled) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // AIA OCSP url is included, but does not return a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater);

  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, OldStapledAndInvalidAIA) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // Stapled response indicates good, but is too old.
  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}});

  // AIA OCSP url is included, but does not return a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater);

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_UNABLE_TO_CHECK_REVOCATION,
            cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSHardFailTest, OldStapledButValidAIA) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  if (!SystemSupportsHardFailRevocationChecking()) {
    LOG(WARNING) << "Skipping test because system doesn't support hard fail "
                 << "revocation checking";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // Stapled response indicates good, but response is too old.
  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kOld}});

  // AIA OCSP url is included, and returns a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

class HTTPSCRLSetTest : public HTTPSCertNetFetchingTest {};

TEST_F(HTTPSCRLSetTest, ExpiredCRLSet) {
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kInvalidResponse);

  UpdateCertVerifier(CRLSet::ExpiredCRLSetForTesting());

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  // If we're not trying EV verification then, even if the CRLSet has expired,
  // we don't fall back to online revocation checks.
  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSCRLSetTest, ExpiredCRLSetAndRevoked) {
  // Test that when online revocation checking is disabled, and the leaf
  // certificate is not EV, that no revocation checking actually happens.
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  UpdateCertVerifier(CRLSet::ExpiredCRLSetForTesting());

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);

  EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSCRLSetTest, CRLSetRevoked) {
  if (!SystemSupportsCRLSets()) {
    LOG(WARNING) << "Skipping test because system doesn't support CRLSets";
    return;
  }

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  test_server.SetSSLConfig(cert_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  CertVerifier::Config cert_verifier_config = GetCertVerifierConfig();
  SHA256HashValue root_cert_spki_hash;
  ASSERT_TRUE(GetTestRootCertSPKIHash(&root_cert_spki_hash));
  auto crl_set =
      CRLSet::ForTesting(false, &root_cert_spki_hash,
                         test_server.GetCertificate()->serial_number(), "", {});
  ASSERT_TRUE(crl_set);
  UpdateCertVerifier(crl_set);

  TestDelegate d;
  d.set_allow_certificate_errors(true);
  std::unique_ptr<URLRequest> r(context_->CreateRequest(
      test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  r->Start();
  EXPECT_TRUE(r->is_pending());
  d.RunUntilComplete();
  EXPECT_EQ(1, d.response_started_count());
  CertStatus cert_status = r->ssl_info().cert_status;

  // If the certificate is recorded as revoked in the CRLSet, that should be
  // reflected without online revocation checking.
  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSCRLSetTest, CRLSetRevokedBySubject) {
  if (!SystemSupportsCRLSets()) {
    LOG(WARNING) << "Skipping test because system doesn't support CRLSets";
    return;
  }

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  test_server.SetSSLConfig(cert_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  std::string common_name = test_server.GetCertificate()->subject().common_name;

  {
    auto crl_set = CRLSet::ForTesting(false, nullptr, "", common_name, {});
    ASSERT_TRUE(crl_set);
    UpdateCertVerifier(crl_set);

    TestDelegate d;
    d.set_allow_certificate_errors(true);
    std::unique_ptr<URLRequest> r(context_->CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_EQ(1, d.response_started_count());
    CertStatus cert_status = r->ssl_info().cert_status;

    // If the certificate is recorded as revoked in the CRLSet, that should be
    // reflected without online revocation checking.
    EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
    EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
    EXPECT_FALSE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
  }

  HashValue spki_hash_value;
  ASSERT_TRUE(x509_util::CalculateSha256SpkiHash(
      test_server.GetCertificate()->cert_buffer(), &spki_hash_value));
  std::string spki_hash(spki_hash_value.data(),
                        spki_hash_value.data() + spki_hash_value.size());
  {
    auto crl_set =
        CRLSet::ForTesting(false, nullptr, "", common_name, {spki_hash});
    ASSERT_TRUE(crl_set);
    UpdateCertVerifier(crl_set);

    TestDelegate d;
    d.set_allow_certificate_errors(true);
    std::unique_ptr<URLRequest> r(context_->CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_EQ(1, d.response_started_count());
    CertStatus cert_status = r->ssl_info().cert_status;

    // When the correct SPKI hash is specified in
    // |acceptable_spki_hashes_for_cn|, the connection should succeed even
    // though the subject is listed in the CRLSet.
    EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  }
}

using HTTPSLocalCRLSetTest = TestWithTaskEnvironment;

// Use a real CertVerifier to attempt to connect to the TestServer, and ensure
// that when a CRLSet is provided that marks a given SPKI (the TestServer's
// root SPKI) as known for interception, that it's adequately flagged.
TEST_F(HTTPSLocalCRLSetTest, KnownInterceptionBlocked) {
  auto cert_verifier = CertVerifier::CreateDefaultWithoutCaching(
      /*cert_net_fetcher=*/nullptr);
  CertVerifierWithUpdatableProc* updatable_cert_verifier_ = cert_verifier.get();

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCertVerifier(std::make_unique<CachingCertVerifier>(
      std::make_unique<CoalescingCertVerifier>(std::move(cert_verifier))));
  auto context = context_builder->Build();

  // Verify the connection succeeds without being flagged.
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_server);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_OK_BY_INTERMEDIATE);
  ASSERT_TRUE(https_server.Start());

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(
        context->CreateRequest(https_server.GetURL("/"), DEFAULT_PRIORITY, &d,
                               TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.request_failed());
    EXPECT_FALSE(d.have_certificate_errors());
    EXPECT_FALSE(req->ssl_info().cert_status &
                 CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
  }

  // Configure a CRL that will mark |root_ca_cert| as a blocked interception
  // root.
  std::string crl_set_bytes;
  net::CertVerifyProc::ImplParams params;
  ASSERT_TRUE(
      base::ReadFileToString(GetTestCertsDirectory().AppendASCII(
                                 "crlset_blocked_interception_by_root.raw"),
                             &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &params.crl_set));

  updatable_cert_verifier_->UpdateVerifyProcData(
      /*cert_net_fetcher=*/nullptr, params, {});

  // Verify the connection fails as being a known interception root.
  {
    TestDelegate d;
    d.set_allow_certificate_errors(true);
    std::unique_ptr<URLRequest> req(
        context->CreateRequest(https_server.GetURL("/"), DEFAULT_PRIORITY, &d,
                               TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.request_failed());
    if (SystemSupportsCRLSets()) {
      EXPECT_TRUE(d.have_certificate_errors());
      EXPECT_FALSE(d.certificate_errors_are_fatal());
      EXPECT_EQ(ERR_CERT_KNOWN_INTERCEPTION_BLOCKED, d.certificate_net_error());
      EXPECT_TRUE(req->ssl_info().cert_status &
                  CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
    } else {
      EXPECT_FALSE(d.have_certificate_errors());
      EXPECT_TRUE(req->ssl_info().cert_status &
                  CERT_STATUS_KNOWN_INTERCEPTION_DETECTED);
    }
  }
}

TEST_F(HTTPSLocalCRLSetTest, InterceptionBlockedAllowOverrideOnHSTS) {
  constexpr char kHSTSHost[] = "include-subdomains-hsts-preloaded.test";
  constexpr char kHSTSSubdomainWithKnownInterception[] =
      "www.include-subdomains-hsts-preloaded.test";

  EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(net::EmbeddedTestServer::CERT_OK_BY_INTERMEDIATE);
  https_server.ServeFilesFromSourceDirectory(base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_server.Start());

  // Configure the CertVerifier to simulate:
  //   - For the test server host, that the certificate is issued by an
  //     unknown authority; this SHOULD NOT be a fatal error when signaled
  //     to the delegate.
  //   - For |kHSTSHost|, that the certificate is issued by an unknown
  //     authority; this SHOULD be a fatal error.
  // Combined, these two states represent the baseline: non-fatal for non-HSTS
  // hosts, fatal for HSTS host.
  //   - For |kHSTSSubdomainWithKnownInterception|, that the certificate is
  //     issued by a known interception cert. This SHOULD be an error, but
  //     SHOULD NOT be a fatal error
  auto cert_verifier = std::make_unique<MockCertVerifier>();

  scoped_refptr<X509Certificate> cert = https_server.GetCertificate();
  ASSERT_TRUE(cert);

  HashValue filler_hash;
```