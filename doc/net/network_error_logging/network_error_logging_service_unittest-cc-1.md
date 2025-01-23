Response:
My goal is to analyze the provided C++ code snippet and fulfill the user's request. Here's a breakdown of my thought process:

1. **Understand the Context:** The user explicitly states this is part of the `net/network_error_logging/network_error_logging_service_unittest.cc` file in Chromium's networking stack. This immediately tells me it's a unit test file for the `NetworkErrorLoggingService`.

2. **Identify the Core Functionality Under Test:** The file name and the repeated use of `service()` and methods like `OnHeader`, `OnRequest`, `QueueSignedExchangeReport`, etc., strongly indicate that this code tests the behavior of the `NetworkErrorLoggingService`. This service is responsible for collecting and reporting network errors.

3. **Break Down the Code by Test Case:**  Unit tests are typically structured as individual test cases. Each `TEST_P` block represents a distinct scenario being tested. I need to analyze each test case to understand its specific purpose.

4. **Analyze Individual Test Cases (Iterative Process):**  For each `TEST_P`:
    * **Identify Setup:** Look for calls to `service()->OnHeader(...)`. This sets up the NEL policy being tested.
    * **Identify Action:** Look for calls to `service()->OnRequest(...)` or `service()->QueueSignedExchangeReport(...)`. This is the action that triggers the potential error logging.
    * **Identify Assertion:** Look for `ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`. These statements verify the expected outcome (e.g., a report was generated, no report was generated, the report content is correct).
    * **Infer the Test's Purpose:** Based on the setup, action, and assertion, I can deduce what specific aspect of the `NetworkErrorLoggingService` is being tested. For example, a test with `ERR_CONNECTION_REFUSED` and an assertion that a report is generated likely tests error reporting. A test with `OK` and an assertion that *no* report is generated likely tests the success reporting logic or sampling.

5. **Look for Relationships to JavaScript:**  The Network Error Logging (NEL) specification is designed to be used by web pages. Therefore, there *must* be a relationship with JavaScript. The key connection is the `Report-To` header. This header, set by the server, instructs the browser to use the NEL mechanism. The tests demonstrating parsing of this header (via `OnHeader`) and the subsequent error reporting based on it directly relate to how a JavaScript-initiated request would trigger NEL reporting.

6. **Identify Logical Reasoning and Assumptions:** Some tests involve probabilistic behavior (e.g., `SuccessFractionHalf`). Here, the reasoning is statistical. The assumption is that over a large number of trials, the observed behavior will align with the probability. The input is the `Success-Fraction` header value, and the output is the presence or absence of reports within a certain range (not a fixed number).

7. **Identify User/Programming Errors:**  Tests like `InvalidHeaderData` explicitly check how the service handles malformed input. This directly relates to potential errors in server configuration or implementation of the `Report-To` header.

8. **Trace User Operations (Debugging Clues):** To understand how a user might reach this code, I need to think about the web request lifecycle:
    * A user navigates to a website.
    * The server sends an HTTP response with a `Report-To` header.
    * The browser parses this header, leading to the `OnHeader` method in the test.
    * The browser makes subsequent requests. If these requests encounter errors, the `OnRequest` method is called.
    * For Signed Exchanges, the browser might encounter issues during verification, leading to `QueueSignedExchangeReport`.

9. **Address the "归纳一下它的功能" (Summarize its functionality) part:**  After analyzing the individual test cases, I can synthesize a high-level description of the file's purpose: testing the core functionalities of the `NetworkErrorLoggingService`, including policy management, error reporting for regular requests and signed exchanges, handling of different header parameters, and interactions with persistent storage.

10. **Structure the Output:**  Organize the findings logically, addressing each point in the user's request:
    * Overall functionality.
    * Relationship with JavaScript (with examples).
    * Logical reasoning (with input/output).
    * User/programming errors (with examples).
    * User operation tracing (debugging).
    * Summary of functionality (for part 2).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on the C++ code details.
* **Correction:** Remember the context – this is a *networking* feature, so the connection to web standards (like the `Report-To` header) and thus JavaScript is crucial.
* **Initial thought:**  Treat every test case as completely independent.
* **Correction:** While mostly independent, they collectively test the same service, so the overarching purpose is consistent.
* **Initial thought:**  Simply list the methods being called.
* **Correction:** Explain *what* each test is verifying about those methods. Focus on the *behavior* being tested.

By following these steps, I can systematically analyze the code and generate a comprehensive answer that addresses all aspects of the user's request.
这是Chromium网络栈中 `net/network_error_logging/network_error_logging_service_unittest.cc` 文件的第二部分，延续了第一部分的测试用例，主要目的是测试 `NetworkErrorLoggingService` 类的各种功能。

**功能归纳（第2部分）：**

这部分主要测试了 `NetworkErrorLoggingService` 在以下方面的功能：

* **成功报告的队列处理 (Success Report Queued):** 测试当请求成功时，如果配置了 `success_fraction`，是否能够正确地将成功报告加入队列。包括对请求方法（POST）、请求阶段和报告类型的正确设置。
* **`max-age` 为 0 的处理 (MaxAge0):** 测试当接收到 `max-age` 为 0 的 NEL 头部时，是否能正确移除已有的策略，并阻止后续错误报告的生成。
* **`success_fraction` 为 0 的处理 (SuccessFraction0):** 测试当 `success_fraction` 为 0 时，即使请求成功，也不会生成报告。
* **`success_fraction` 为 0.5 的处理 (SuccessFractionHalf):** 测试当 `success_fraction` 为 0.5 时，成功报告会以一定的概率被生成。验证了随机采样逻辑的正确性，并检查了报告体中 `sampling_fraction` 的值。
* **`failure_fraction` 为 0 的处理 (FailureFraction0):** 测试当 `failure_fraction` 为 0 时，即使请求失败，也不会生成报告。
* **`failure_fraction` 为 0.5 的处理 (FailureFractionHalf):** 测试当 `failure_fraction` 为 0.5 时，失败报告会以一定的概率被生成。同样验证了随机采样逻辑，并检查了报告体中的 `sampling_fraction`。
* **`excludeSubdomains` 行为测试 (ExcludeSubdomainsDoesntMatchDifferentPort, ExcludeSubdomainsDoesntMatchSubdomain):** 测试默认情况下（`includeSubdomains` 为 false），NEL 策略不会匹配到不同端口或子域名的请求。
* **`includeSubdomains` 行为测试 (IncludeSubdomainsMatchesDifferentPort, IncludeSubdomainsMatchesSubdomain, IncludeSubdomainsDoesntMatchSuperdomain, IncludeSubdomainsDoesntReportConnectionError, IncludeSubdomainsDoesntReportApplicationError, IncludeSubdomainsDoesntReportSuccess, IncludeSubdomainsReportsSameOriginSuccess):**  详细测试了当 `includeSubdomains` 为 true 时，NEL 策略如何匹配不同端口、子域名，以及不匹配父域名的情况。同时验证了即使 `includeSubdomains` 为 true，默认情况下也只报告网络错误，不报告连接错误、应用层错误或成功请求（除非特别指定了 `success_fraction`）。
* **移除所有浏览数据 (RemoveAllBrowsingData):** 测试了 `RemoveAllBrowsingData` 方法是否能正确移除所有已存储的 NEL 策略，并阻止后续的错误报告。
* **移除部分浏览数据 (RemoveSomeBrowsingData):** 测试了 `RemoveBrowsingData` 方法，可以通过提供的过滤器选择性地删除特定的 NEL 策略。
* **嵌套报告深度测试 (Nested, NestedTooDeep):** 测试了 NEL 报告的嵌套深度限制。如果请求的嵌套深度超过最大值，则不会生成报告。
* **状态输出为 Value (StatusAsValue):** 测试了 `StatusAsValue` 方法能够正确地将当前 NEL 服务的状态（包括所有策略）以 `base::Value` 的形式输出，用于调试或监控。同时测试了当头部参数类型错误时，服务会忽略这些错误类型并使用默认值。
* **无效头部数据处理 (InvalidHeaderData):** 测试了服务如何处理格式错误的 NEL 头部，预期不会崩溃。
* **没有 ReportingService 的情况 (NoReportingService_SignedExchange):** 测试了在没有关联 `ReportingService` 的情况下，处理 Signed Exchange 报告请求不会导致崩溃。
* **Origin 没有策略的情况 (NoPolicyForOrigin_SignedExchange):** 测试了当某个 Origin 没有对应的 NEL 策略时，Signed Exchange 报告不会被处理。
* **`success_fraction` 为 0 的 Signed Exchange 报告 (SuccessFraction0_SignedExchange):** 测试了当 `success_fraction` 为 0 时，即使是成功的 Signed Exchange 请求也不会生成报告。
* **成功 Signed Exchange 报告队列处理 (SuccessReportQueued_SignedExchange):** 测试了成功的 Signed Exchange 请求如何生成报告，并验证了报告体的结构和内容，包括 Signed Exchange 特有的信息。
* **失败 Signed Exchange 报告队列处理 (FailureReportQueued_SignedExchange):** 测试了失败的 Signed Exchange 请求如何生成报告，并验证了报告体的结构和内容。
* **Signed Exchange 的子域名不匹配 (MismatchingSubdomain_SignedExchange):** 测试了当 `includeSubdomains` 为 false 时，Signed Exchange 请求的域名与策略域名不匹配时，不会生成报告。
* **Signed Exchange 的 IP 地址不匹配 (MismatchingIPAddress_SignedExchange):** 测试了 Signed Exchange 请求的服务器 IP 地址与策略记录的 IP 地址不匹配时，不会生成报告。
* **禁用 NetworkAnonymizationKey 的 Signed Exchange (SignedExchangeNetworkAnonymizationKeyDisabled):** 测试了当禁用 Network Partitioning 功能时，Signed Exchange 报告中使用的 Network Anonymization Key 会是默认值。
* **策略驱逐测试 (EvictAllExpiredPoliciesFirst, EvictLeastRecentlyUsedPolicy):** 测试了当 NEL 策略数量达到上限时，服务如何驱逐旧的策略。优先驱逐过期的策略，其次驱逐最近最少使用的未过期策略。
* **同步发送命令到存储 (SendsCommandsToStoreSynchronous):** 测试了 `NetworkErrorLoggingService` 与持久化存储之间的交互，验证了服务能够同步地发送添加、删除和更新 NEL 策略的命令到 `PersistentNelStore`。

**与 Javascript 的关系：**

`NetworkErrorLoggingService` 的主要功能是处理由服务器通过 HTTP 头部 (`Report-To`) 声明的 NEL 策略。这些策略指示浏览器在发生网络错误或某些成功事件时，将相关信息报告到指定的端点。

* **`Report-To` 头部解析：** `service()->OnHeader(...)` 方法模拟了浏览器接收并解析含有 NEL 策略的 `Report-To` 头部。这个头部是在服务器的 HTTP 响应中设置的，而这个响应通常是针对浏览器中 Javascript 发起的请求。

   **举例说明：**
   假设一个网页的 Javascript 发起了一个到 `https://example.com/api` 的请求。服务器的响应头部包含：
   ```
   Report-To: {"group":"endpoint-1","max_age":3600,"endpoints":[{"url":"https://report.example.com"}]}
   ```
   `NetworkErrorLoggingService` 会解析这个头部，并将 `group` 为 "endpoint-1" 的报告发送到 `https://report.example.com`。

* **错误报告触发：** 当 Javascript 发起的请求遇到网络错误（例如 DNS 解析失败、连接超时）或成功但符合 `success_fraction` 条件时，`service()->OnRequest(...)` 或 `service()->QueueSignedExchangeReport(...)` 会被调用，模拟生成并队列化 NEL 报告。

   **举例说明：**
   如果 Javascript 使用 `fetch()` 发起了一个到配置了 NEL 的服务器的请求，但由于网络问题导致请求失败（例如 `net::ERR_CONNECTION_REFUSED`），`NetworkErrorLoggingService` 会根据服务器设置的 NEL 策略生成一个错误报告。

**逻辑推理的假设输入与输出：**

很多测试用例都包含了逻辑推理，尤其是关于采样率 (`success_fraction`, `failure_fraction`) 的测试。

**假设输入 (SuccessFractionHalf 测试):**

* NEL 策略头部: `{"report_to":"group","max_age":86400,"success_fraction":0.5,"failure_fraction":0.25}`
* 多次成功的请求调用 `service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));`

**输出:**

由于 `success_fraction` 为 0.5，大约一半的成功请求会生成报告。测试用例使用 `EXPECT_FALSE(reports().empty());` 和 `EXPECT_GT(kReportCount, reports().size());` 来验证这一点，即报告数量不会为零，也不会等于请求总数。

**涉及用户或编程常见的使用错误：**

* **服务器配置错误的 `Report-To` 头部 (InvalidHeaderData 测试):**  如果服务器返回的 `Report-To` 头部格式不正确（例如，不是有效的 JSON），`NetworkErrorLoggingService` 需要能够处理这种情况而不会崩溃。这是服务器开发人员可能犯的错误。
* **未能考虑子域名 (ExcludeSubdomains* 测试):**  如果服务器希望为其所有子域名启用 NEL，但 `Report-To` 头部没有设置 `includeSubdomains: true`，那么子域名的错误将不会被报告。这是服务器配置方面的一个常见疏忽。
* **对成功事件的错误采样率配置 (SuccessFraction* 测试):** 如果服务器错误地设置了 `success_fraction`，可能会导致过多的或过少的成功事件被报告，影响监控数据的准确性。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户访问网页：** 用户在浏览器中输入 URL 或点击链接，访问一个配置了 NEL 的网站。
2. **服务器返回 `Report-To` 头部：**  服务器在响应用户的 HTTP 请求时，包含了 `Report-To` 头部，声明了 NEL 策略。
3. **浏览器解析并存储策略：** 浏览器接收到响应后，`NetworkErrorLoggingService` 解析 `Report-To` 头部，并将 NEL 策略存储起来 (对应 `OnHeader` 方法)。
4. **用户执行操作导致网络请求：** 用户在网页上进行操作，例如点击按钮、提交表单，这会导致浏览器发起新的网络请求。
5. **发生网络错误或成功事件：** 在这些新的网络请求过程中，可能会发生各种网络错误 (例如 DNS 解析失败、连接被拒绝) 或成功事件。
6. **触发错误报告逻辑：** 如果发生了与已存储的 NEL 策略匹配的错误或成功事件，`NetworkErrorLoggingService` 的 `OnRequest` 方法会被调用，并根据策略决定是否生成报告。
7. **Signed Exchange 相关操作：** 如果用户访问的页面使用了 Signed Exchange，浏览器在验证或处理 Signed Exchange 内容时可能会遇到问题，这会触发 `QueueSignedExchangeReport` 方法。

因此，调试 NEL 相关问题时，可以关注以下方面：

* **检查服务器返回的 `Report-To` 头部是否正确配置。**
* **确认浏览器是否成功解析并存储了 NEL 策略。**
* **在发生网络错误时，检查 `NetworkErrorLoggingService` 是否被正确调用，以及生成的报告内容是否符合预期。**
* **对于 Signed Exchange，检查其验证过程和可能出现的错误类型。**

总而言之，这部分测试用例深入地测试了 `NetworkErrorLoggingService` 在处理各种 NEL 策略、不同类型的网络请求（包括成功和失败）、以及 Signed Exchange 报告时的核心逻辑和边界情况，确保了 NEL 功能的健壮性和可靠性。

### 提示词
```
这是目录为net/network_error_logging/network_error_logging_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
GET", 0, kOtherServerIP_));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kOtherServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(1000, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("dns", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("dns.name_not_resolved", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessPOSTReportQueued) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK, "POST"));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("POST", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictStringValue("application", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("ok", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, MaxAge0) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_EQ(1u, PolicyCount());

  // Max_age of 0 removes the policy.
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderMaxAge0_);
  EXPECT_EQ(0u, PolicyCount());

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessFraction0) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction0_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Each network error has a 0% chance of being reported.  Fire off several and
  // verify that no reports are produced.
  constexpr size_t kReportCount = 100;
  for (size_t i = 0; i < kReportCount; ++i)
    service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessFractionHalf) {
  // Include a different value for failure_fraction to ensure that we copy the
  // right value into sampling_fraction.
  static const std::string kHeaderSuccessFractionHalf =
      "{\"report_to\":\"group\",\"max_age\":86400,\"success_fraction\":0.5,"
      "\"failure_fraction\":0.25}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFractionHalf);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Each network error has a 50% chance of being reported.  Fire off several
  // and verify that some requests were reported and some weren't.  (We can't
  // verify exact counts because each decision is made randomly.)
  constexpr size_t kReportCount = 100;
  for (size_t i = 0; i < kReportCount; ++i)
    service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));

  // If our random selection logic is correct, there is a 2^-100 chance that
  // every single report above was skipped.  If this check fails, it's much more
  // likely that our code is wrong.
  EXPECT_FALSE(reports().empty());

  // There's also a 2^-100 chance that every single report was logged.  Same as
  // above, that's much more likely to be a code error.
  EXPECT_GT(kReportCount, reports().size());

  for (const auto& report : reports()) {
    const base::Value::Dict* body_dict = report.body->GetIfDict();
    ASSERT_TRUE(body_dict);
    // Our header includes a different value for failure_fraction, so that this
    // check verifies that we copy the correct fraction into sampling_fraction.
    ExpectDictDoubleValue(0.5, *body_dict,
                          NetworkErrorLoggingService::kSamplingFractionKey);
  }
}

TEST_P(NetworkErrorLoggingServiceTest, FailureFraction0) {
  static const std::string kHeaderFailureFraction0 =
      "{\"report_to\":\"group\",\"max_age\":86400,\"failure_fraction\":0.0}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderFailureFraction0);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Each network error has a 0% chance of being reported.  Fire off several and
  // verify that no reports are produced.
  constexpr size_t kReportCount = 100;
  for (size_t i = 0; i < kReportCount; ++i)
    service()->OnRequest(
        MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, FailureFractionHalf) {
  // Include a different value for success_fraction to ensure that we copy the
  // right value into sampling_fraction.
  static const std::string kHeaderFailureFractionHalf =
      "{\"report_to\":\"group\",\"max_age\":86400,\"failure_fraction\":0.5,"
      "\"success_fraction\":0.25}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderFailureFractionHalf);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Each network error has a 50% chance of being reported.  Fire off several
  // and verify that some requests were reported and some weren't.  (We can't
  // verify exact counts because each decision is made randomly.)
  constexpr size_t kReportCount = 100;
  for (size_t i = 0; i < kReportCount; ++i)
    service()->OnRequest(
        MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  // If our random selection logic is correct, there is a 2^-100 chance that
  // every single report above was skipped.  If this check fails, it's much more
  // likely that our code is wrong.
  EXPECT_FALSE(reports().empty());

  // There's also a 2^-100 chance that every single report was logged.  Same as
  // above, that's much more likely to be a code error.
  EXPECT_GT(kReportCount, reports().size());

  for (const auto& report : reports()) {
    const base::Value::Dict* body_dict = report.body->GetIfDict();
    ASSERT_TRUE(body_dict);
    ExpectDictDoubleValue(0.5, *body_dict,
                          NetworkErrorLoggingService::kSamplingFractionKey);
  }
}

TEST_P(NetworkErrorLoggingServiceTest,
       ExcludeSubdomainsDoesntMatchDifferentPort) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlDifferentPort_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, ExcludeSubdomainsDoesntMatchSubdomain) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, IncludeSubdomainsMatchesDifferentPort) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlDifferentPort_, ERR_NAME_NOT_RESOLVED));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrlDifferentPort_, reports()[0].url);
}

TEST_P(NetworkErrorLoggingServiceTest, IncludeSubdomainsMatchesSubdomain) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_NAME_NOT_RESOLVED));

  ASSERT_EQ(1u, reports().size());
}

TEST_P(NetworkErrorLoggingServiceTest,
       IncludeSubdomainsDoesntMatchSuperdomain) {
  service()->OnHeader(kNak_, kOriginSubdomain_, kServerIP_,
                      kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, ERR_NAME_NOT_RESOLVED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest,
       IncludeSubdomainsDoesntReportConnectionError) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest,
       IncludeSubdomainsDoesntReportApplicationError) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_INVALID_HTTP_RESPONSE));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, IncludeSubdomainsDoesntReportSuccess) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrlSubdomain_, OK));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest,
       IncludeSubdomainsReportsSameOriginSuccess) {
  static const std::string kHeaderIncludeSubdomainsSuccess1 =
      "{\"report_to\":\"group\",\"max_age\":86400,"
      "\"include_subdomains\":true,\"success_fraction\":1.0}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_,
                      kHeaderIncludeSubdomainsSuccess1);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
}

TEST_P(NetworkErrorLoggingServiceTest, RemoveAllBrowsingData) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_EQ(1u, PolicyCount());
  EXPECT_TRUE(HasPolicy(kNak_, kOrigin_));

  service()->RemoveAllBrowsingData();

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  EXPECT_EQ(0u, PolicyCount());
  EXPECT_FALSE(HasPolicy(kNak_, kOrigin_));
  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, RemoveSomeBrowsingData) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnHeader(kNak_, kOriginDifferentHost_, kServerIP_, kHeader_);
  EXPECT_EQ(2u, PolicyCount());

  // Remove policy for kOrigin_ but not kOriginDifferentHost_
  service()->RemoveBrowsingData(
      base::BindRepeating([](const url::Origin& origin) -> bool {
        return origin.host() == "example.com";
      }));
  EXPECT_EQ(1u, PolicyCount());
  EXPECT_TRUE(HasPolicy(kNak_, kOriginDifferentHost_));
  EXPECT_FALSE(HasPolicy(kNak_, kOrigin_));

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlDifferentHost_, ERR_CONNECTION_REFUSED));

  ASSERT_EQ(1u, reports().size());
}

TEST_P(NetworkErrorLoggingServiceTest, Nested) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  NetworkErrorLoggingService::RequestDetails details =
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED);
  details.reporting_upload_depth =
      NetworkErrorLoggingService::kMaxNestedReportDepth;
  service()->OnRequest(details);

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(NetworkErrorLoggingService::kMaxNestedReportDepth,
            reports()[0].depth);
}

TEST_P(NetworkErrorLoggingServiceTest, NestedTooDeep) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  NetworkErrorLoggingService::RequestDetails details =
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED);
  details.reporting_upload_depth =
      NetworkErrorLoggingService::kMaxNestedReportDepth + 1;
  service()->OnRequest(details);

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, StatusAsValue) {
  // The expiration times will be bogus, but we need a reproducible value for
  // this test.
  base::SimpleTestClock clock;
  service()->SetClockForTesting(&clock);
  // The clock is initialized to the "zero" or origin point of the Time class.
  // This sets the clock's Time to the equivalent of the "zero" or origin point
  // of the TimeTicks class, so that the serialized value produced by
  // NetLog::TimeToString is consistent across restarts.
  base::TimeDelta delta_from_origin =
      base::Time::UnixEpoch().since_origin() -
      base::TimeTicks::UnixEpoch().since_origin();
  clock.Advance(delta_from_origin);

  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnHeader(kNak_, kOriginDifferentHost_, kServerIP_, kHeader_);
  service()->OnHeader(kOtherNak_, kOriginSubdomain_, kServerIP_,
                      kHeaderIncludeSubdomains_);
  const std::string kHeaderWrongTypes =
      ("{\"report_to\":\"group\","
       "\"max_age\":86400,"
       // We'll ignore each of these fields because they're the wrong type.
       // We'll use a default value instead.
       "\"include_subdomains\":\"true\","
       "\"success_fraction\": \"1.0\","
       "\"failure_fraction\": \"0.0\"}");
  service()->OnHeader(
      kNak_, url::Origin::Create(GURL("https://invalid-types.example.com")),
      kServerIP_, kHeaderWrongTypes);

  base::Value actual = service()->StatusAsValue();
  base::Value expected = base::test::ParseJson(R"json(
      {
        "originPolicies": [
          {
            "NetworkAnonymizationKey": "https://example.com same_site",
            "origin": "https://example.com",
            "includeSubdomains": false,
            "expires": "86400000",
            "reportTo": "group",
            "successFraction": 1.0,
            "failureFraction": 1.0,
          },
          {
            "NetworkAnonymizationKey": "https://example.com same_site",
            "origin": "https://invalid-types.example.com",
            "includeSubdomains": false,
            "expires": "86400000",
            "reportTo": "group",
            "successFraction": 0.0,
            "failureFraction": 1.0,
          },
          {
            "NetworkAnonymizationKey": "https://example.com same_site",
            "origin": "https://somewhere-else.com",
            "includeSubdomains": false,
            "expires": "86400000",
            "reportTo": "group",
            "successFraction": 0.0,
            "failureFraction": 1.0,
          },
          {
            "NetworkAnonymizationKey": "https://somewhere-else.com same_site",
            "origin": "https://subdomain.example.com",
            "includeSubdomains": true,
            "expires": "86400000",
            "reportTo": "group",
            "successFraction": 0.0,
            "failureFraction": 1.0,
          },
        ]
      }
      )json");
  EXPECT_EQ(expected, actual);
}

TEST_P(NetworkErrorLoggingServiceTest, InvalidHeaderData) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, "0");
}

TEST_P(NetworkErrorLoggingServiceTest, NoReportingService_SignedExchange) {
  service_ = NetworkErrorLoggingService::Create(store_.get());

  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Should not crash
  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kNak_, false, "sxg.failed", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));
}

TEST_P(NetworkErrorLoggingServiceTest, NoPolicyForOrigin_SignedExchange) {
  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kNak_, false, "sxg.failed", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessFraction0_SignedExchange) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction0_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Each network error has a 0% chance of being reported.  Fire off several and
  // verify that no reports are produced.
  constexpr size_t kReportCount = 100;
  for (size_t i = 0; i < kReportCount; ++i) {
    service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
        kNak_, true, "ok", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));
  }

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessReportQueued_SignedExchange) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kNak_, true, "ok", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));
  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("http/1.1", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(200, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(1234, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue(
      NetworkErrorLoggingService::kSignedExchangePhaseValue, body_dict,
      NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("ok", body_dict,
                              NetworkErrorLoggingService::kTypeKey);

  const base::Value::Dict* sxg_body =
      body_dict.FindDict(NetworkErrorLoggingService::kSignedExchangeBodyKey);
  ASSERT_TRUE(sxg_body);

  base::ExpectDictStringValue(kUrl_.spec(), *sxg_body,
                              NetworkErrorLoggingService::kOuterUrlKey);
  base::ExpectDictStringValue(kInnerUrl_.spec(), *sxg_body,
                              NetworkErrorLoggingService::kInnerUrlKey);
  base::ExpectStringValue(
      kCertUrl_.spec(),
      sxg_body->Find(NetworkErrorLoggingService::kCertUrlKey)->GetList()[0]);
}

TEST_P(NetworkErrorLoggingServiceTest, FailureReportQueued_SignedExchange) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kNak_, false, "sxg.failed", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));
  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("http/1.1", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(200, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(1234, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue(
      NetworkErrorLoggingService::kSignedExchangePhaseValue, body_dict,
      NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("sxg.failed", body_dict,
                              NetworkErrorLoggingService::kTypeKey);

  const base::Value::Dict* sxg_body =
      body_dict.FindDict(NetworkErrorLoggingService::kSignedExchangeBodyKey);
  ASSERT_TRUE(sxg_body);

  base::ExpectDictStringValue(kUrl_.spec(), *sxg_body,
                              NetworkErrorLoggingService::kOuterUrlKey);
  base::ExpectDictStringValue(kInnerUrl_.spec(), *sxg_body,
                              NetworkErrorLoggingService::kInnerUrlKey);
  base::ExpectStringValue(
      kCertUrl_.spec(),
      sxg_body->Find(NetworkErrorLoggingService::kCertUrlKey)->GetList()[0]);
}

TEST_P(NetworkErrorLoggingServiceTest, MismatchingSubdomain_SignedExchange) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kNak_, false, "sxg.failed", kUrlSubdomain_, kInnerUrl_, kCertUrl_,
      kServerIP_));
  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, MismatchingIPAddress_SignedExchange) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->QueueSignedExchangeReport(
      MakeSignedExchangeReportDetails(kNak_, false, "sxg.failed", kUrl_,
                                      kInnerUrl_, kCertUrl_, kOtherServerIP_));
  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest,
       SignedExchangeNetworkAnonymizationKeyDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Need to re-create the service, since it caches the feature value on
  // creation.
  service_ = NetworkErrorLoggingService::Create(store_.get());
  reporting_service_ = std::make_unique<TestReportingService>();
  service_->SetReportingService(reporting_service_.get());

  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Wrong NAK, but a report should be generated anyways.
  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kOtherNak_, true, "ok", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(NetworkAnonymizationKey(), reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);
}

// When the max number of policies is exceeded, first try to remove expired
// policies before evicting the least recently used unexpired policy.
TEST_P(NetworkErrorLoggingServiceTest, EvictAllExpiredPoliciesFirst) {
  base::SimpleTestClock clock;
  service()->SetClockForTesting(&clock);

  // Add 100 policies then make them expired.
  for (size_t i = 0; i < 100; ++i) {
    service()->OnHeader(MakeNetworkAnonymizationKey(i), MakeOrigin(i),
                        kServerIP_, kHeader_);
  }
  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_EQ(100u, PolicyCount());
  clock.Advance(base::Seconds(86401));  // max_age is 86400 sec
  // Expired policies are allowed to linger before hitting the policy limit.
  EXPECT_EQ(100u, PolicyCount());

  // Reach the max policy limit.
  for (size_t i = 100; i < NetworkErrorLoggingService::kMaxPolicies; ++i) {
    service()->OnHeader(MakeNetworkAnonymizationKey(i), MakeOrigin(i),
                        kServerIP_, kHeader_);
  }
  EXPECT_EQ(NetworkErrorLoggingService::kMaxPolicies, PolicyCount());

  // Add one more policy to trigger eviction of only the expired policies.
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);
  EXPECT_EQ(NetworkErrorLoggingService::kMaxPolicies - 100 + 1, PolicyCount());
}

TEST_P(NetworkErrorLoggingServiceTest, EvictLeastRecentlyUsedPolicy) {
  base::SimpleTestClock clock;
  service()->SetClockForTesting(&clock);

  // A policy's |last_used| is updated when it is added
  for (size_t i = 0; i < NetworkErrorLoggingService::kMaxPolicies; ++i) {
    service()->OnHeader(MakeNetworkAnonymizationKey(i), MakeOrigin(i),
                        kServerIP_, kHeader_);
    clock.Advance(base::Seconds(1));
  }
  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_EQ(PolicyCount(), NetworkErrorLoggingService::kMaxPolicies);

  // Set another policy which triggers eviction. None of the policies have
  // expired, so the least recently used (i.e. least recently added) policy
  // should be evicted.
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);
  clock.Advance(base::Seconds(1));
  EXPECT_EQ(PolicyCount(), NetworkErrorLoggingService::kMaxPolicies);

  EXPECT_FALSE(
      HasPolicy(MakeNetworkAnonymizationKey(0), MakeOrigin(0)));  // evicted
  std::set<NelPolicyKey> all_policy_keys = service()->GetPolicyKeysForTesting();
  for (size_t i = 1; i < NetworkErrorLoggingService::kMaxPolicies; ++i) {
    // Avoid n calls to HasPolicy(), which would be O(n^2).
    NelPolicyKey key(MakeNetworkAnonymizationKey(i), MakeOrigin(i));
    EXPECT_EQ(1u, all_policy_keys.count(key));
  }
  EXPECT_TRUE(HasPolicy(kNak_, kOrigin_));

  // Now use the policies in reverse order starting with kOrigin_, then add
  // another policy to trigger eviction, to check that the stalest policy is
  // identified correctly.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kOrigin_.GetURL(), ERR_CONNECTION_REFUSED));
  clock.Advance(base::Seconds(1));
  for (size_t i = NetworkErrorLoggingService::kMaxPolicies - 1; i >= 1; --i) {
    service()->OnRequest(MakeRequestDetails(MakeNetworkAnonymizationKey(i),
                                            MakeOrigin(i).GetURL(),
                                            ERR_CONNECTION_REFUSED));
    clock.Advance(base::Seconds(1));
  }
  service()->OnHeader(kNak_, kOriginSubdomain_, kServerIP_, kHeader_);
  EXPECT_EQ(PolicyCount(), NetworkErrorLoggingService::kMaxPolicies);

  EXPECT_FALSE(HasPolicy(kNak_, kOrigin_));  // evicted
  all_policy_keys = service()->GetPolicyKeysForTesting();
  for (size_t i = NetworkErrorLoggingService::kMaxPolicies - 1; i >= 1; --i) {
    // Avoid n calls to HasPolicy(), which would be O(n^2).
    NelPolicyKey key(MakeNetworkAnonymizationKey(i), MakeOrigin(i));
    EXPECT_EQ(1u, all_policy_keys.count(key));
  }
  EXPECT_TRUE(HasPolicy(kNak_, kOriginSubdomain_));  // most recently added

  // Note: This test advances the clock by ~2000 seconds, which is below the
  // specified max_age of 86400 seconds, so none of the policies expire during
  // this test.
}

TEST_P(NetworkErrorLoggingServiceTest, SendsCommandsToStoreSynchronous) {
  if (!store())
    return;

  MockPersistentNelStore::CommandList expected_commands;
  NetworkErrorLoggingService::NelPolicy policy1 = MakePolicy(kNak_, kOrigin_);
  NetworkErrorLoggingService::NelPolicy policy2 =
      MakePolicy(kNak_, kOriginDifferentHost_);
  std::vector<NetworkErrorLoggingService::NelPolicy> prestored_policies = {
      policy1, policy2};
  store()->SetPrestoredPolicies(std::move(prestored_policies));

  // The first call to any of the public methods triggers a load.
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);
  expected_commands.emplace_back(
      MockPersistentNelStore::Command::Type::LOAD_NEL_POLICIES);
  EXPECT_TRUE(store()->VerifyCommands(expected_commands));

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);
  // DoOnHeader() should now execute.
  expected_commands.emplace_back(
      MockPersistentNelStore::Command::Type::DELETE_NEL_POLICY, policy1);
  expected_commands.emplace_back(
      MockPersistentNelStore::Command::Type::ADD_NEL_POLICY, policy1);
  EXPECT_TRUE(store()->VerifyCommands(expected_commands));

  service()->OnRequest(
      MakeRequestDetails(kNak_, kOrigin_.GetURL(), ERR_CONNECTION_REFUSED));
  expected_commands.emplace_back(
      MockPersistentNelStore::Command::Type::UPDATE_NEL_POLICY, policy1);
  EXPECT_TRUE(store()->VerifyCommands(expected_commands));

  service()->QueueSignedExchangeReport(MakeSignedExchangeReportDetails(
      kNak_, false, "sxg.failed", kUrl_, kInnerUrl_, kCertUrl_, kServerIP_));
  expected_commands.emplace_back(
      MockPersistentNelStore::Command::Type::UPDATE_NEL_POLICY, policy1);
  EXPECT_TRUE(store()->VerifyCommands(expected_commands));

  // Removes policy1 but not policy2.
  EXPECT_EQ(2, store()->StoredPoliciesCount());
  service()->RemoveBrowsingData(
      base::BindRepeating([](const url::Origin& origin) -> bool {
        return origin.host() == "example.com";
      }));
  expected_commands.emplace_back(
      MockPersistentNelStore::Command::Type::DELETE_NEL_POLICY, policy1);
  expected_commands.emplace_back(MockPersiste
```