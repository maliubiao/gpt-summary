Response:
My thinking process to analyze the C++ code and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided C++ code snippet (`dns_transaction_unittest.cc`) within the Chromium network stack. The request also asks for connections to JavaScript, logical reasoning (input/output), common usage errors, debugging tips, and a summary of the functionality of this part of the file.

2. **Identify the Core Class:** The filename `dns_transaction_unittest.cc` and the presence of `TEST_F(DnsTransactionTest, ...)` immediately tell me that this code is a unit test file for the `DnsTransaction` class (or related classes). Unit tests are designed to verify the behavior of individual components in isolation.

3. **Analyze Individual Test Cases:**  I'll go through each `TEST_F` function to understand what specific functionality it's testing. I'll look for:
    * **Test Name:** The name often gives a good clue (e.g., `TCPServerFailure`, `TCPMalformed`, `TcpTimeout_UdpRetry`).
    * **Setup:** What is being configured before the core action? This often involves:
        * `AddAsyncQueryAndRcode`, `AddSyncQueryAndRcode`, `AddQueryAndResponse`:  These functions clearly simulate DNS server responses (both successful and erroneous).
        * `ConfigureFactory`, `ConfigureDohServers`: These likely set up different configurations for the DNS resolution process, including enabling/disabling DoH.
        * `std::make_unique<DnsSocketData>`: This suggests the creation of mock network socket data to control the responses.
    * **Action:** What is the main function being tested?  `helper0.StartTransaction(...)` is the key action, indicating the initiation of a DNS transaction.
    * **Assertions:** What is being checked after the action? `ASSERT_NE`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` are used to verify the expected outcome (e.g., specific error codes, response codes, completion status).

4. **Group Related Tests:** I'll look for patterns and group tests that are verifying similar aspects of `DnsTransaction`:
    * Handling of different DNS response codes (SERVFAIL, NOERROR, NXDOMAIN).
    * Behavior with TCP connections (malformed responses, timeouts, connection closed).
    * Fallback from TCP to UDP.
    * Handling of invalid queries.
    * Testing of DNS-over-HTTPS (DoH) functionality, including probing for server availability.
    * Cancellation scenarios.
    * Handling of network errors.

5. **Address Specific Request Points:** Now I'll explicitly address each part of the request:

    * **Functionality Listing:**  Based on the grouped test cases, I'll list the functionalities being tested.
    * **Relationship to JavaScript:**  I know that the Chromium network stack is responsible for handling network requests made by the browser, including those initiated by JavaScript. I'll connect DNS resolution (what this code tests) to JavaScript's use of hostnames in URLs (e.g., `fetch`, `XMLHttpRequest`, `<img>` tags). I'll provide a simple example.
    * **Logical Reasoning (Input/Output):** For specific tests, I'll pick a straightforward test case (like `TCPServerFailure`) and describe the simulated input (a SERVFAIL response) and the expected output (an error code).
    * **Common Usage Errors:** I'll think about how incorrect DNS configuration or server behavior could lead to the errors being tested (e.g., a misconfigured DNS server returning SERVFAIL).
    * **User Operations (Debugging):** I'll trace back how a user action in the browser (like typing a URL) leads to the network stack and potentially triggers the `DnsTransaction` logic.
    * **Functionality Summary (Part 5):** I'll summarize the functionalities covered in *this specific snippet* of the file, noting the focus on TCP error handling, retries, and initial DoH probing.

6. **Review and Refine:** I'll reread my analysis and the code to ensure accuracy and clarity. I'll make sure the examples are easy to understand and that I've addressed all aspects of the request. For example, I'll check if my input/output examples are concrete and if my explanation of user operations is logical. I also want to make sure the summary accurately reflects the content of the provided code *and* acknowledges it's part of a larger file.

By following these steps, I can systematically analyze the C++ code, extract its functionality, and connect it to the broader context of the Chromium network stack and its interaction with JavaScript. The decomposition of the request into smaller, manageable parts helps ensure that all aspects are addressed.
这是 `net/dns/dns_transaction_unittest.cc` 文件第 5 部分的代码，主要涵盖了以下功能：

**核心功能：DnsTransaction 类的单元测试，特别是针对 TCP 和 DoH (DNS over HTTPS) 场景下的错误处理、重试机制和探测功能。**

**详细功能列表：**

* **TCP 错误处理：**
    * **`TCPServerFailure`:** 测试当 DNS 服务器通过 TCP 返回 `SERVFAIL` 错误码时的处理逻辑。
    * **`TCPMalformed`:** 测试当接收到格式错误的 TCP 响应（长度过短）时的处理逻辑。
    * **`TCPReadReturnsZeroAsync` 和 `TCPReadReturnsZeroSynchronous`:** 测试在 TCP 连接中异步或同步读取到 0 字节时的处理逻辑（通常表示连接关闭）。
    * **`TCPConnectionClosedAsync` 和 `TCPConnectionClosedSynchronous`:** 测试 TCP 连接被异步或同步关闭时的处理逻辑。
* **TCP 超时与 UDP 重试：**
    * **`TcpTimeout_UdpRetry`:** 测试当 TCP 连接超时时，系统是否会回退到使用 UDP 进行重试。
    * **`TcpTimeout_LowEntropy`:** 测试当 UDP 源端口熵值较低（可能导致冲突）时，TCP 超时后的行为。
* **UDP 与 TCP 混合场景：**
    * **`MismatchedThenNxdomainThenTCP`:** 测试第一次 UDP 尝试返回不匹配的响应，然后收到 TCP 标志，第二次 UDP 尝试返回 `NXDOMAIN` 的情况。
    * **`MismatchedThenOkThenTCP`:** 测试第一次 UDP 尝试返回不匹配的响应，然后收到 TCP 标志，第二次 UDP 尝试返回有效响应的情况。
    * **`MismatchedThenRefusedThenTCP`:**  测试当第一次 UDP 尝试返回不匹配的响应，然后尝试读取时收到 TCP 标志，第二次 UDP 尝试返回连接被拒绝的情况，重点在于测试重试机制和取消逻辑。
* **无效查询处理：**
    * **`InvalidQuery`:** 测试当发起无效的 DNS 查询（例如，主机名包含非法字符）时的处理逻辑。
* **异步 DoH 查询检查：**
    * **`CheckAsync`:** 测试在使用 DoH 时，请求是否是异步发起的。
* **提前取消 DoH 查询：**
    * **`EarlyCancel`:** 测试在 DoH 查询进行中提前取消请求的处理逻辑。
* **DoH 探测功能：**
    * **`ProbeUntilSuccess`:** 测试 DoH 探测功能，当初始探测失败后，会进行重试，直到成功。
    * **`ProbeCreationTriggersSuccessMetric`:** 测试 DoH 探测成功后是否会触发相应的指标记录。
    * **`ProbeAttemptConnectionFailureAffectsHistograms`:** 测试 DoH 探测尝试连接失败时，是否会记录到相应的指标。
    * **`ProbeAttemptServFailAffectsHistograms`:** 测试 DoH 探测收到 `SERVFAIL` 错误码时，是否会记录到相应的指标。
    * **`ProbeAttemptEmptyResponseAffectsHistograms`:** 测试 DoH 探测收到空响应时，是否会记录到相应的指标。
    * **`HungProbe`:** 测试当一个 DoH 探测请求挂起时，后续的探测是否会按计划进行。
    * **`ProbeMultipleServers`:** 测试当配置了多个 DoH 服务器时，探测功能是否能正确处理。
    * **`MultipleProbeRunners` 和 `MultipleProbeRunners_SeparateContexts`:** 测试在同一或不同上下文中运行多个 DoH 探测器时的行为。
    * **`CancelDohProbeOnDestruction` 和 `CancelDohProbeOnContextDestruction`:** 测试在 `DnsProbeRunner` 对象或其关联的 `ResolveContext` 对象销毁时，DoH 探测是否会被取消。

**与 JavaScript 的关系：**

`DnsTransaction` 是 Chromium 网络栈中负责执行 DNS 查询的核心组件。当 JavaScript 代码（例如，在网页中）尝试访问一个域名时，浏览器会使用网络栈来解析该域名对应的 IP 地址。这个过程就涉及到了 `DnsTransaction`。

**举例说明：**

假设 JavaScript 代码发起一个 `fetch` 请求：

```javascript
fetch('https://www.example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **JavaScript 发起请求:**  `fetch` 函数被调用。
2. **URL 解析:** 浏览器解析 URL，提取出域名 `www.example.com`。
3. **DNS 查询:** Chromium 网络栈需要将 `www.example.com` 解析成 IP 地址。
4. **DnsTransaction 参与:**  `DnsTransaction` 类会被创建并启动，根据配置（例如，是否启用 DoH），它可能会发起 UDP 或 HTTPS 请求到 DNS 服务器。
5. **测试覆盖的场景:**  本测试文件中的测试用例涵盖了 `DnsTransaction` 在各种 DNS 查询场景下的行为，例如：
    * 如果 DNS 服务器返回 `SERVFAIL`（`TCPServerFailure` 测试），`fetch` 请求会失败。
    * 如果网络配置要求使用 DoH，但 DoH 服务器不可用，`ProbeUntilSuccess` 等测试用例模拟了探测 DoH 服务器的过程，最终可能导致 `fetch` 请求延迟或失败。
    * 如果 DNS 服务器指示需要使用 TCP (`kFlagTC`)，`DnsTransaction` 可能会切换到 TCP 进行重试。

**逻辑推理 (假设输入与输出):**

**示例 1: `TCPServerFailure`**

* **假设输入:**
    * 启动一个针对主机名 `kT0HostName`，查询类型 `kT0Qtype` 的 TCP DNS 事务。
    * 模拟的 DNS 服务器返回一个 `SERVFAIL` 响应。
* **预期输出:**
    * `TransactionHelper` 的 `response()` 方法返回一个非空指针。
    * `response()->rcode()` 返回 `dns_protocol::kRcodeSERVFAIL`。
    * `TransactionHelper` 最终完成，并可能返回一个表示 DNS 查询失败的错误码。

**示例 2: `TcpTimeout_UdpRetry`**

* **假设输入:**
    * 启动一个针对主机名 `kT0HostName`，查询类型 `kT0Qtype` 的 TCP DNS 事务。
    * 模拟的 TCP 连接超时。
* **预期输出:**
    * `TransactionHelper` 初始状态下 `has_completed()` 为 `false`。
    * 在 TCP 超时后，`DnsTransaction` 会尝试使用 UDP 进行重试（假设配置允许）。
    * 最终 `TransactionHelper` 完成，并可能返回一个成功的结果（如果 UDP 重试成功）或一个超时错误。

**用户或编程常见的使用错误：**

* **错误的 DNS 服务器配置:** 用户手动配置了错误的 DNS 服务器地址，导致连接超时 (`TcpTimeout_UdpRetry`) 或返回 `SERVFAIL` (`TCPServerFailure`)。
* **网络问题:**  用户的网络连接不稳定，导致 TCP 连接被关闭 (`TCPConnectionClosedAsync`/`Synchronous`) 或读取数据失败 (`TCPReadReturnsZeroAsync`/`Synchronous`)。
* **DoH 配置错误:**  用户启用了 DoH，但配置的 DoH 服务器地址错误或不可用，导致探测失败 (`ProbeUntilSuccess` 等相关测试覆盖的场景)。
* **程序逻辑错误 (针对 Chromium 开发人员):**  在实现或修改 DNS 相关代码时，没有正确处理各种 DNS 响应状态和网络错误，导致与这些测试用例覆盖的场景不符的行为。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入网址或点击链接:**  例如，输入 `www.example.com`。
2. **浏览器解析 URL:**  浏览器需要解析域名 `www.example.com` 对应的 IP 地址。
3. **发起 DNS 查询:**  网络栈的 DNS 解析器启动 DNS 查询。
4. **创建 DnsTransaction 对象:**  根据配置，可能会创建一个 `DnsTransaction` 对象来执行查询。
5. **选择传输协议:**  根据配置和网络情况，可能会优先尝试 UDP，或者如果配置了 DoH，则可能尝试 HTTPS。如果 DNS 服务器指示需要 TCP，则会切换到 TCP。
6. **模拟测试场景对应:**  如果在 TCP 查询过程中，服务器返回 `SERVFAIL`，则会触发 `TCPServerFailure` 测试所覆盖的代码路径。如果 TCP 连接超时，则会触发 `TcpTimeout_UdpRetry` 测试覆盖的代码路径。如果启用了 DoH，并且 DoH 服务器不可用，则会触发 `ProbeUntilSuccess` 等 DoH 探测相关的测试覆盖的代码路径.
7. **处理响应或错误:** `DnsTransaction` 对象接收到 DNS 响应或遇到错误（例如超时、连接关闭），并根据返回码或错误类型进行处理，例如重试、回退到其他协议或返回错误给上层调用者。

**第 5 部分功能归纳：**

这部分主要集中在 **`DnsTransaction` 类在 TCP 传输场景下的错误处理和重试机制，以及 DoH 探测功能的测试**。 它验证了在各种 TCP 连接异常情况（服务器错误、格式错误、连接关闭、超时）下 `DnsTransaction` 的行为，以及在 DoH 场景下如何探测服务器的可用性，并在探测过程中处理各种网络错误和响应状态。  这部分测试对于确保 `DnsTransaction` 在复杂和不可靠的网络环境下能够正确地解析域名至关重要。

Prompt: 
```
这是目录为net/dns/dns_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  ASSERT_NE(helper0.response(), nullptr);
  EXPECT_EQ(helper0.response()->rcode(), dns_protocol::kRcodeSERVFAIL);
}

TEST_F(DnsTransactionTest, TCPMalformed) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              ASYNC, Transport::TCP);
  // Valid response but length too short.
  // This must be truncated in the question section. The DnsResponse doesn't
  // examine the answer section until asked to parse it, so truncating it in
  // the answer section would result in the DnsTransaction itself succeeding.
  data->AddResponseWithLength(
      std::make_unique<DnsResponse>(kT0ResponseDatagram, 0), ASYNC,
      static_cast<uint16_t>(kT0QuerySize - 1));
  AddSocketData(std::move(data));

  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTestWithMockTime, TcpTimeout_UdpRetry) {
  ConfigureFactory();
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  AddSocketData(std::make_unique<DnsSocketData>(
      1 /* id */, kT0HostName, kT0Qtype, ASYNC, Transport::TCP));

  TransactionHelper helper0(ERR_DNS_TIMED_OUT);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(helper0.has_completed());
  FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(helper0.has_completed());
}

TEST_F(DnsTransactionTestWithMockTime, TcpTimeout_LowEntropy) {
  ConfigureFactory();
  socket_factory_->diverse_source_ports_ = false;

  for (int i = 0; i <= DnsUdpTracker::kPortReuseThreshold; ++i) {
    AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                        ASYNC, Transport::UDP);
  }

  AddSocketData(std::make_unique<DnsSocketData>(
      1 /* id */, kT0HostName, kT0Qtype, ASYNC, Transport::TCP));

  for (int i = 0; i <= DnsUdpTracker::kPortReuseThreshold; ++i) {
    TransactionHelper udp_helper(kT0RecordCount);
    udp_helper.StartTransaction(transaction_factory_.get(), kT0HostName,
                                kT0Qtype, false /* secure */,
                                resolve_context_.get());
    udp_helper.RunUntilComplete();
  }

  ASSERT_TRUE(session_->udp_tracker()->low_entropy());

  TransactionHelper helper0(ERR_DNS_TIMED_OUT);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(helper0.has_completed());
  FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(helper0.has_completed());
}

TEST_F(DnsTransactionTest, TCPReadReturnsZeroAsync) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              ASYNC, Transport::TCP);
  // Return all but the last byte of the response.
  auto response_data = base::span(kT0ResponseDatagram);
  data->AddResponseWithLength(
      std::make_unique<DnsResponse>(
          response_data.first(response_data.size() - 1), 0),
      ASYNC, static_cast<uint16_t>(response_data.size()));
  // Then return a 0-length read.
  data->AddReadError(0, ASYNC);
  AddSocketData(std::move(data));

  TransactionHelper helper0(ERR_CONNECTION_CLOSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, TCPReadReturnsZeroSynchronous) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              ASYNC, Transport::TCP);
  auto response_data = base::span(kT0ResponseDatagram);
  // Return all but the last byte of the response.
  data->AddResponseWithLength(
      std::make_unique<DnsResponse>(
          response_data.first(response_data.size() - 1), 0),
      SYNCHRONOUS, static_cast<uint16_t>(response_data.size()));
  // Then return a 0-length read.
  data->AddReadError(0, SYNCHRONOUS);
  AddSocketData(std::move(data));

  TransactionHelper helper0(ERR_CONNECTION_CLOSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, TCPConnectionClosedAsync) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              ASYNC, Transport::TCP);
  data->AddReadError(ERR_CONNECTION_CLOSED, ASYNC);
  AddSocketData(std::move(data));

  TransactionHelper helper0(ERR_CONNECTION_CLOSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, TCPConnectionClosedSynchronous) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              ASYNC, Transport::TCP);
  data->AddReadError(ERR_CONNECTION_CLOSED, SYNCHRONOUS);
  AddSocketData(std::move(data));

  TransactionHelper helper0(ERR_CONNECTION_CLOSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, MismatchedThenNxdomainThenTCP) {
  config_.attempts = 2;
  ConfigureFactory();
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              SYNCHRONOUS, Transport::UDP);
  // First attempt gets a mismatched response.
  data->AddResponseData(kT1ResponseDatagram, SYNCHRONOUS);
  // Second read from first attempt gets TCP required.
  data->AddRcode(dns_protocol::kFlagTC, ASYNC);
  AddSocketData(std::move(data));
  // Second attempt gets NXDOMAIN, which happens before the TCP required.
  AddSyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, MismatchedThenOkThenTCP) {
  config_.attempts = 2;
  ConfigureFactory();
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              SYNCHRONOUS, Transport::UDP);
  // First attempt gets a mismatched response.
  data->AddResponseData(kT1ResponseDatagram, SYNCHRONOUS);
  // Second read from first attempt gets TCP required.
  data->AddRcode(dns_protocol::kFlagTC, ASYNC);
  AddSocketData(std::move(data));
  // Second attempt gets a valid response, which happens before the TCP
  // required.
  AddSyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                          kT0ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, MismatchedThenRefusedThenTCP) {
  // Set up the expected sequence of events:
  // 1) First attempt (UDP) gets a synchronous mismatched response. On such
  //    malformed responses, DnsTransaction triggers an immediate retry to read
  //    again from the socket within the same "attempt".
  // 2) Second read (within the first attempt) starts. Test is configured to
  //    give an asynchronous TCP required response which will complete later.
  //    On asynchronous action after a malformed response, the attempt will
  //    immediately produce a retriable error result while the retry continues,
  //    thus forking the running attempts.
  // 3) Error result triggers a second attempt (UDP) which test gives a
  //    synchronous ERR_CONNECTION_REFUSED, which is a retriable error, but
  //    DnsTransaction has exhausted max retries (2 attempts), so this result
  //    gets posted as the result of the transaction and other running attempts
  //    should be cancelled.
  // 4) First attempt should be cancelled when the transaction result is posted,
  //    so first attempt's second read should never complete. If it did
  //    complete, it would complete with a TCP-required error, and
  //    DnsTransaction would start a TCP attempt and clear previous attempts. It
  //    would be very bad if that then cleared the attempt posted as the final
  //    result, as result handling does not expect that memory to go away.

  config_.attempts = 2;
  ConfigureFactory();

  // Attempt 1.
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              SYNCHRONOUS, Transport::UDP);
  data->AddResponseData(kT1ResponseDatagram, SYNCHRONOUS);
  data->AddRcode(dns_protocol::kFlagTC, ASYNC);
  AddSocketData(std::move(data));

  // Attempt 2.
  AddQueryAndErrorResponse(0 /* id */, kT0HostName, kT0Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS, Transport::UDP);

  TransactionHelper helper0(ERR_CONNECTION_REFUSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, InvalidQuery) {
  ConfigureFactory();

  TransactionHelper helper0(ERR_INVALID_ARGUMENT);
  helper0.StartTransaction(transaction_factory_.get(), ".",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  TransactionHelper helper1(ERR_INVALID_ARGUMENT);
  helper1.StartTransaction(transaction_factory_.get(), "foo,bar.com",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper1.RunUntilComplete();
}

TEST_F(DnsTransactionTest, CheckAsync) {
  ConfigureDohServers(false /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  bool started = false;
  SetUrlRequestStartedCallback(
      base::BindLambdaForTesting([&] { started = true; }));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  EXPECT_FALSE(started);
  EXPECT_FALSE(helper0.has_completed());
  helper0.RunUntilComplete();
  EXPECT_TRUE(started);
}

TEST_F(DnsTransactionTest, EarlyCancel) {
  ConfigureDohServers(false /* use_post */);
  TransactionHelper helper0(0);
  SetUrlRequestStartedCallback(base::BindRepeating([] { FAIL(); }));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  EXPECT_FALSE(helper0.has_completed());
  helper0.Cancel();
  base::RunLoop().RunUntilIdle();
}

TEST_F(DnsTransactionTestWithMockTime, ProbeUntilSuccess) {
  ConfigureDohServers(true /* use_post */, 1 /* num_doh_servers */,
                      false /* make_available */);
  ASSERT_EQ(kDohProbeHostname, kT4HostName);
  AddQueryAndErrorResponse(0 /* id */, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0 /* id */, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(false /* network_change */);

  // The first probe happens without any delay.
  RunUntilIdle();
  std::unique_ptr<DnsServerIterator> doh_itr = resolve_context_->GetDohIterator(
      session_->config(), SecureDnsMode::kAutomatic, session_.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());

  // Expect the server to still be unavailable after the second probe.
  FastForwardBy(runner->GetDelayUntilNextProbeForTest(0));
  EXPECT_FALSE(doh_itr->AttemptAvailable());

  // Expect the server to be available after the successful third probe.
  FastForwardBy(runner->GetDelayUntilNextProbeForTest(0));
  ASSERT_TRUE(doh_itr->AttemptAvailable());
  EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
}

TEST_F(DnsTransactionTestWithMockTime, ProbeCreationTriggersSuccessMetric) {
  config_.secure_dns_mode = SecureDnsMode::kAutomatic;
  ConfigureDohServers(/*use_post=*/true, /*num_doh_servers=*/1,
                      /*make_available=*/false);
  ASSERT_EQ(kDohProbeHostname, kT4HostName);
  AddQueryAndResponse(/*id=*/0, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS,
                      /*opt_rdata=*/nullptr,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      /*enqueue_transaction_id=*/false);

  // The metric timer should not have started yet.
  EXPECT_FALSE(
      resolve_context_->doh_autoupgrade_metrics_timer_is_running_for_testing());

  base::HistogramTester histogram_tester;
  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(/*network_change=*/false);

  // Ensure that calling `CreateDohProbeRunner()` causes metrics to be emitted
  // after the timeout.
  EXPECT_TRUE(
      resolve_context_->doh_autoupgrade_metrics_timer_is_running_for_testing());

  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));

  EXPECT_FALSE(
      resolve_context_->doh_autoupgrade_metrics_timer_is_running_for_testing());

  histogram_tester.ExpectUniqueSample(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kSuccessWithNoPriorFailures, 1);
}

TEST_F(DnsTransactionTestWithMockTime,
       ProbeAttemptConnectionFailureAffectsHistograms) {
  config_.secure_dns_mode = SecureDnsMode::kAutomatic;
  ConfigureDohServers(/*use_post=*/true, /*num_doh_servers=*/1,
                      /*make_available=*/false);
  ASSERT_EQ(kDohProbeHostname, kT4HostName);
  AddQueryAndErrorResponse(/*id=*/0, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, /*opt_rdata=*/nullptr,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           /*enqueue_transaction_id=*/false);

  base::HistogramTester histogram_tester;
  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(/*network_change=*/false);

  // Consume the one failure response and then destroy the probe so it doesn't
  // continue to make requests.
  RunUntilIdle();
  runner = nullptr;

  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectUniqueSample(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kFailureWithNoPriorSuccesses, 1);
  histogram_tester.ExpectUniqueSample(
      "Net.DNS.DnsTransaction.SecureNotValidated.Other.FailureError",
      std::abs(Error::ERR_CONNECTION_REFUSED), 1);
}

TEST_F(DnsTransactionTestWithMockTime, ProbeAttemptServFailAffectsHistograms) {
  config_.secure_dns_mode = SecureDnsMode::kAutomatic;
  ConfigureDohServers(/*use_post=*/true, /*num_doh_servers=*/1,
                      /*make_available=*/false);
  ASSERT_EQ(kDohProbeHostname, kT4HostName);
  AddQueryAndRcode(kT4HostName, kT4Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, /*id=*/0,
                   /*enqueue_transaction_id=*/false);

  base::HistogramTester histogram_tester;
  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(/*network_change=*/false);

  RunUntilIdle();
  runner = nullptr;

  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectUniqueSample(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kFailureWithNoPriorSuccesses, 1);
  histogram_tester.ExpectUniqueSample(
      "Net.DNS.DnsTransaction.SecureNotValidated.Other.FailureError",
      std::abs(Error::ERR_DNS_SERVER_FAILED), 1);
}

TEST_F(DnsTransactionTestWithMockTime,
       ProbeAttemptEmptyResponseAffectsHistograms) {
  config_.secure_dns_mode = SecureDnsMode::kAutomatic;
  ConfigureDohServers(/*use_post=*/true, /*num_doh_servers=*/1,
                      /*make_available=*/false);
  ASSERT_EQ(kDohProbeHostname, kT4HostName);
  auto response = std::make_unique<DnsResponse>(
      BuildTestDnsResponse(kT4HostName, dns_protocol::kTypeA,
                           /*answers=*/{}));
  auto data = std::make_unique<DnsSocketData>(
      /*id=*/0, kT4HostName, dns_protocol::kTypeA, SYNCHRONOUS,
      Transport::HTTPS, /*opt_rdata=*/nullptr,
      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponse(std::move(response), SYNCHRONOUS);
  AddSocketData(std::move(data), /*enqueue_transaction_id=*/false);

  base::HistogramTester histogram_tester;
  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(/*network_change=*/false);

  RunUntilIdle();
  runner = nullptr;

  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectUniqueSample(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kFailureWithNoPriorSuccesses, 1);
  histogram_tester.ExpectUniqueSample(
      "Net.DNS.DnsTransaction.SecureNotValidated.Other.FailureError",
      std::abs(Error::ERR_DNS_SECURE_PROBE_RECORD_INVALID), 1);
}

// Test that if a probe attempt hangs, additional probes will still run on
// schedule
TEST_F(DnsTransactionTestWithMockTime, HungProbe) {
  ConfigureDohServers(true /* use_post */, 1 /* num_doh_servers */,
                      false /* make_available */);

  // Create a socket data to first return ERR_IO_PENDING. This will pause the
  // probe and not return the error until SequencedSocketData::Resume() is
  // called.
  auto data = std::make_unique<DnsSocketData>(
      0 /* id */, kT4HostName, kT4Qtype, ASYNC, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddReadError(ERR_IO_PENDING, ASYNC);
  data->AddReadError(ERR_CONNECTION_REFUSED, ASYNC);
  data->AddResponseData(kT4ResponseDatagram, ASYNC);
  SequencedSocketData* sequenced_socket_data = data->GetProvider();
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);

  // Add success for second probe.
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(false /* network_change */);

  // The first probe starts without any delay, but doesn't finish.
  RunUntilIdle();
  EXPECT_FALSE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));

  // Second probe succeeds.
  FastForwardBy(runner->GetDelayUntilNextProbeForTest(0));
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));

  // Probe runner self-cancels on next cycle.
  FastForwardBy(runner->GetDelayUntilNextProbeForTest(0));
  EXPECT_EQ(runner->GetDelayUntilNextProbeForTest(0), base::TimeDelta());

  // Expect no effect when the hung probe wakes up and fails.
  sequenced_socket_data->Resume();
  RunUntilIdle();
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));
  EXPECT_EQ(runner->GetDelayUntilNextProbeForTest(0), base::TimeDelta());
}

TEST_F(DnsTransactionTestWithMockTime, ProbeMultipleServers) {
  ConfigureDohServers(true /* use_post */, 2 /* num_doh_servers */,
                      false /* make_available */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0 /* id */, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  ASSERT_FALSE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));
  ASSERT_FALSE(resolve_context_->GetDohServerAvailability(
      1u /* doh_server_index */, session_.get()));

  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(true /* network_change */);

  // The first probes happens without any delay and succeeds for only one server
  RunUntilIdle();
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));
  EXPECT_FALSE(resolve_context_->GetDohServerAvailability(
      1u /* doh_server_index */, session_.get()));

  // On second round of probing, probes for first server should self-cancel and
  // second server should become available.
  FastForwardBy(
      runner->GetDelayUntilNextProbeForTest(0u /* doh_server_index */));
  EXPECT_EQ(runner->GetDelayUntilNextProbeForTest(0u /* doh_server_index */),
            base::TimeDelta());
  FastForwardBy(
      runner->GetDelayUntilNextProbeForTest(1u /* doh_server_index */));
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(
      1u /* doh_server_index */, session_.get()));

  // Expect server 2 probes to self-cancel on next cycle.
  FastForwardBy(runner->GetDelayUntilNextProbeForTest(1u));
  EXPECT_EQ(runner->GetDelayUntilNextProbeForTest(1u), base::TimeDelta());
}

TEST_F(DnsTransactionTestWithMockTime, MultipleProbeRunners) {
  ConfigureDohServers(true /* use_post */, 1 /* num_doh_servers */,
                      false /* make_available */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  std::unique_ptr<DnsProbeRunner> runner1 =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  std::unique_ptr<DnsProbeRunner> runner2 =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner1->Start(true /* network_change */);
  runner2->Start(true /* network_change */);

  // The first two probes (one for each runner) happen without any delay
  // and mark the first server good.
  RunUntilIdle();
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  // Both probes expected to self-cancel on next scheduled run.
  FastForwardBy(runner1->GetDelayUntilNextProbeForTest(0));
  FastForwardBy(runner2->GetDelayUntilNextProbeForTest(0));
  EXPECT_EQ(runner1->GetDelayUntilNextProbeForTest(0), base::TimeDelta());
  EXPECT_EQ(runner2->GetDelayUntilNextProbeForTest(0), base::TimeDelta());
}

TEST_F(DnsTransactionTestWithMockTime, MultipleProbeRunners_SeparateContexts) {
  // Each RequestContext uses its own transient IsolationInfo. Since there's
  // typically only one RequestContext per URLRequestContext, there's no
  // advantage in using the same IsolationInfo across RequestContexts.
  set_expect_multiple_isolation_infos(true);

  ConfigureDohServers(true /* use_post */, 1 /* num_doh_servers */,
                      false /* make_available */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0 /* id */, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndResponse(0 /* id */, kT4HostName, kT4Qtype, kT4ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  auto request_context2 = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context2(request_context2.get(), false /* enable_caching */);
  context2.InvalidateCachesAndPerSessionData(session_.get(),
                                             false /* network_change */);

  std::unique_ptr<DnsProbeRunner> runner1 =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  std::unique_ptr<DnsProbeRunner> runner2 =
      transaction_factory_->CreateDohProbeRunner(&context2);
  runner1->Start(false /* network_change */);
  runner2->Start(false /* network_change */);

  // The first two probes (one for each runner) happen without any delay.
  // Probe for first context succeeds and second fails.
  RunUntilIdle();
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }
  {
    std::unique_ptr<DnsServerIterator> doh_itr2 = context2.GetDohIterator(
        session_->config(), SecureDnsMode::kAutomatic, session_.get());

    EXPECT_FALSE(doh_itr2->AttemptAvailable());
  }

  // First probe runner expected to be compete and self-cancel on next run.
  FastForwardBy(runner1->GetDelayUntilNextProbeForTest(0));
  EXPECT_EQ(runner1->GetDelayUntilNextProbeForTest(0), base::TimeDelta());

  // Expect second runner to succeed on its second probe.
  FastForwardBy(runner2->GetDelayUntilNextProbeForTest(0));
  {
    std::unique_ptr<DnsServerIterator> doh_itr2 = context2.GetDohIterator(
        session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr2->AttemptAvailable());
    EXPECT_EQ(doh_itr2->GetNextAttemptIndex(), 0u);
  }
  FastForwardBy(runner2->GetDelayUntilNextProbeForTest(0));
  EXPECT_EQ(runner2->GetDelayUntilNextProbeForTest(0), base::TimeDelta());
}

TEST_F(DnsTransactionTestWithMockTime, CancelDohProbeOnDestruction) {
  ConfigureDohServers(/*use_post=*/true, /*num_doh_servers=*/1,
                      /*make_available=*/false);
  AddQueryAndErrorResponse(/*id=*/0, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, /*opt_rdata=*/nullptr,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           /*enqueue_transaction_id=*/false);
  AddQueryAndErrorResponse(/*id=*/0, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, /*opt_rdata=*/nullptr,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           /* enqueue_transaction_id=*/false);

  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRunner(resolve_context_.get());
  runner->Start(/*network_change=*/false);

  // The first probe happens without any delay.
  RunUntilIdle();
  std::unique_ptr<DnsServerIterator> doh_itr = resolve_context_->GetDohIterator(
      session_->config(), SecureDnsMode::kAutomatic, session_.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());

  // Expect the server to still be unavailable after the second probe.
  FastForwardBy(runner->GetDelayUntilNextProbeForTest(0));

  EXPECT_FALSE(doh_itr->AttemptAvailable());

  base::TimeDelta next_delay = runner->GetDelayUntilNextProbeForTest(0);
  runner.reset();

  // Server stays unavailable because probe canceled before (non-existent)
  // success. No success result is added, so this FastForward will cause a
  // failure if probes attempt to run.
  FastForwardBy(next_delay);

  EXPECT_FALSE(doh_itr->AttemptAvailable());
}

TEST_F(DnsTransactionTestWithMockTime, CancelDohProbeOnContextDestruction) {
  ConfigureDohServers(/*use_post=*/true, /*num_doh_servers=*/1,
                      /*make_available=*/false);
  AddQueryAndErrorResponse(/*id=*/0, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, /*opt_rdata=*/nullptr,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           /*enqueue_transaction_id=*/false);
  AddQueryAndErrorResponse(/*id=*/0, kT4HostName, kT4Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, /*opt_rdata=*/nullptr,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           /* enqueue_transaction_id=*/false);

  std::unique_ptr<DnsProbeRunner> runner =
      transaction_factory_->CreateDohProbeRu
"""


```