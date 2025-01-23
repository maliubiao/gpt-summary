Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. The file is `http_stream_factory_job_controller_unittest.cc`, suggesting it contains unit tests for the `HttpStreamFactoryJobController`. The decomposed request asks for:

1. **Functionality Summary:** What does this code do?
2. **JavaScript Relation:** Is there any connection to JavaScript?
3. **Logical Reasoning:**  Can we infer inputs and outputs of the tested logic?
4. **Common Usage Errors:**  What mistakes might developers or users make related to this?
5. **User Operation to Reach Here:** How does a user's action lead to this code being executed?
6. **Final归纳 (Summary):** A concise overall summary.

Let's break down the code and address each point.

**1. Functionality Summary:**

The code defines unit tests for the `HttpStreamFactoryJobController`. This class is responsible for managing the process of establishing an HTTP connection. It orchestrates different "jobs" to try various connection methods concurrently (e.g., a direct TCP connection, an alternative protocol like QUIC, or a QUIC connection discovered via DNS). The tests focus on scenarios involving:

* **DNS-based HTTPS ALPN (Application-Layer Protocol Negotiation) with HTTP/3:** Testing how the controller handles discovering and using HTTP/3 via DNS records.
* **Alternative Services:** Testing how the controller uses pre-configured alternative protocols (like QUIC on a different host or port).
* **Happy Eyeballs:** Testing how the controller handles concurrent connection attempts to different IP addresses.
* **Preconnect:** Testing the pre-connection functionality to establish connections proactively.
* **Race conditions:** Simulating scenarios where different connection attempts finish at different times.
* **Error handling:** Testing how the controller reacts to connection failures and DNS resolution errors.

**2. JavaScript Relation:**

The `HttpStreamFactory` and its related components are part of the browser's network stack, which is implemented in C++. While JavaScript running in a web page triggers network requests, it doesn't directly interact with this specific C++ code at a granular level. JavaScript uses higher-level APIs (like `fetch` or `XMLHttpRequest`) which eventually rely on the network stack.

**3. Logical Reasoning (Input/Output):**

The tests use a mock framework to simulate different network conditions and server responses. Here are some examples of assumed inputs and expected outputs:

* **Assumption:** A request is made for `https://www.example.org`. An alternative service for `alt.example.org` is advertised. DNS for `www.example.org` includes an HTTPS record indicating support for HTTP/3.
* **Expected Output:** The `HttpStreamFactoryJobController` will create three jobs: a `MainJob` for a direct TCP connection, an `AlternativeJob` for connecting to `alt.example.org` via QUIC, and a `DnsAlpnH3Job` for connecting to `www.example.org` via QUIC based on the DNS record.

* **Assumption:** The `MainJob` succeeds first.
* **Expected Output:** The `HttpStreamFactoryJobController` will use the `MainJob`'s connection. Histograms will record that the main job won the race. The other jobs will be cancelled.

* **Assumption:** The `DnsAlpnH3Job` succeeds first.
* **Expected Output:** The `HttpStreamFactoryJobController` will use the `DnsAlpnH3Job`'s QUIC connection. Histograms will record that the DNS ALPN H3 job won the race. The other jobs will be cancelled.

* **Assumption:** The `DnsAlpnH3Job` fails due to a network error.
* **Expected Output:** The `HttpStreamFactoryJobController` will mark the alternative service as broken (temporarily disabled). The `MainJob` will continue.

**4. Common Usage Errors:**

This code primarily tests the internal logic of the network stack. User or programmer errors in the typical sense are less directly applicable here. However, we can consider scenarios where incorrect configurations or server behavior might expose issues that these tests aim to catch:

* **Server misconfiguration:** A server might advertise an alternative service that is not actually available or is incorrectly configured. The tests simulate these scenarios to ensure the client handles them gracefully (e.g., falling back to the main connection).
* **DNS issues:** Incorrect or incomplete DNS records, especially related to HTTPS ALPN, can cause connection failures. The tests verify how the controller reacts to these DNS-related problems.
* **Network connectivity problems:** Intermittent or complete network failures can occur. The tests implicitly cover scenarios where connections fail at different stages.

**5. User Operation to Reach Here (Debugging Clues):**

A user's action triggers a network request. Here's how it might lead to this code being relevant during debugging:

1. **User enters a URL in the address bar or clicks a link.**
2. **The browser initiates a network request for that URL.**
3. **The `HttpStreamFactory` is involved in creating and managing the connection.**
4. **The `HttpStreamFactoryJobController` is instantiated to orchestrate the connection attempts.**
5. **During debugging, if there are issues with connection establishment (e.g., slow connections, connection failures, unexpected protocol usage), a developer might investigate the behavior of the `HttpStreamFactoryJobController`.**
6. **These unit tests serve as a specification for how the `HttpStreamFactoryJobController` should behave in various scenarios, aiding in understanding and diagnosing issues.**  If a bug is suspected in this area, these tests might be examined or new tests might be written to reproduce and fix the bug.

**6. Final归纳 (Summary):**

`net/http/http_stream_factory_job_controller_unittest.cc` contains unit tests for the `HttpStreamFactoryJobController` in Chromium's network stack. This controller manages the concurrent attempts to establish HTTP connections, including trying alternative protocols (like QUIC) and handling DNS-based HTTP/3 discovery. The tests verify the controller's behavior in various scenarios involving successful connections, failures, race conditions between connection attempts, and pre-connection mechanisms. While JavaScript doesn't directly interact with this code, it's a crucial part of the underlying network infrastructure that enables web browsing. These tests help ensure the robustness and correctness of the connection establishment process.

```cpp
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共9部分，请归纳一下它的功能
```

这个 C++ 文件 `http_stream_factory_job_controller_unittest.cc` 是 Chromium 浏览器网络栈的一部分，专门用于测试 `HttpStreamFactoryJobController` 类的功能。由于这是第 9 部分，也是最后一部分，我们可以理解为这部分着重测试了 `HttpStreamFactoryJobController` 中与 **DNS-based HTTPS ALPN (Application-Layer Protocol Negotiation) for HTTP/3** 相关的逻辑，以及一些 **连接池 (Pooling)** 相关的测试。

**文件功能列表:**

1. **测试 DNS-based HTTPS ALPN for HTTP/3:**
   - 验证当 DNS 记录指示服务器支持 HTTP/3 时，`HttpStreamFactoryJobController` 是否会创建并尝试 `DnsAlpnH3Job`。
   - 测试 `MainJob`（传统的 TCP 连接）、`AlternativeJob`（基于已知的替代服务）和 `DnsAlpnH3Job` 同时存在时的行为和相互影响。
   - 测试不同 Job 成功或失败时的流程，例如当 `DnsAlpnH3Job` 成功时，是否会取消其他 Job。
   - 验证在已存在相同源的替代服务时，是否会避免启动 `DnsAlpnH3Job`。
   - 测试 `DnsAlpnH3Job` 失败时的处理，例如是否会将该替代服务标记为 broken。
   - 测试 `DnsAlpnH3Job` 成功后，主 Job 被取消的情况。
   - 验证 `DnsAlpnH3Job` 在默认网络失败的情况下，主 Job 是否会继续。
   - 测试 DNS 解析时间是否能从 `DnsAlpnH3Job` 或 `AlternativeJob` 传递给最终使用的请求。

2. **测试预连接 (Preconnect) 功能与 DNS-based HTTPS ALPN:**
   - 验证在预连接时，如果支持 DNS-based HTTPS ALPN，则会启动 `PRECONNECT_DNS_ALPN_H3` 类型的 Job。
   - 测试当已存在与 DNS-based HTTPS ALPN 要求匹配的活跃会话时，预连接是否会使用该会话。
   - 测试在没有启用 DNS-based HTTPS ALPN 时，预连接的行为。
   - 测试当基于 Alt-Svc 的预连接失败 (例如 `ERR_DNS_NO_MATCHING_SUPPORTED_ALPN`) 时的处理。

3. **测试连接池 (Pooling) 相关的预连接:**
   - 验证当启用 Happy Eyeballs V3 功能时，预连接的 HTTP 请求如何与连接池交互。
   - 测试异步和同步的预连接场景，以及当连接池中已存在空闲连接时预连接的行为。

**与 Javascript 的关系:**

虽然这个 C++ 文件本身不包含 Javascript 代码，但它测试的网络功能是 Javascript 代码（在浏览器环境中运行）发起网络请求的基础。

**举例说明:**

当 Javascript 代码使用 `fetch()` API 请求一个 HTTPS 网站，并且该网站的 DNS 记录指示支持 HTTP/3 时：

1. Javascript 发起 `fetch('https://www.example.org')`。
2. Chromium 的网络栈接收到该请求。
3. `HttpStreamFactory` 负责创建用于处理该请求的连接。
4. `HttpStreamFactoryJobController` 被创建来管理连接建立的过程。
5. 如果 DNS 查询返回了指示支持 HTTP/3 的信息（例如，通过 HTTPS 资源记录），这个测试文件中的逻辑会验证 `HttpStreamFactoryJobController` 是否正确地创建了 `DnsAlpnH3Job` 来尝试使用 HTTP/3 连接。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 用户请求 `https://www.example.org`。
* 该域名没有预先配置的替代服务。
* 对 `www.example.org` 的 DNS 查询返回一个 `HTTPS` 记录，指示支持 `h3` (HTTP/3)。
* 网络状态允许建立 QUIC 连接。

**预期输出:**

* `HttpStreamFactoryJobController` 会创建一个 `MainJob` (用于尝试传统的 TLS 连接) 和一个 `DnsAlpnH3Job` (用于尝试 HTTP/3 连接)。
* 如果 `DnsAlpnH3Job` 首先成功建立了连接，则该连接将被使用。
* 统计信息会记录 `ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE`。
* `MainJob` 会被取消。

**用户或编程常见的使用错误 (举例说明):**

这个测试文件主要关注网络栈内部的逻辑，用户或编程错误通常不会直接触发到这个层面。但是，一些配置或状态可能导致覆盖到这些测试的场景：

* **服务器配置错误:** 服务器错误地配置了 HTTPS 记录，声称支持 HTTP/3 但实际上不支持。这些测试验证了客户端在这种情况下是否能够回退到其他连接方式。
* **网络环境问题:**  用户所处的网络环境阻止了 QUIC 连接。这些测试验证了在这种情况下，客户端是否能够回退到 TCP 连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 Chrome 浏览器地址栏输入 `https://www.example.org` 并回车。**
2. **浏览器解析 URL，确定需要发起 HTTPS 请求。**
3. **浏览器查找是否有可用的连接，如果没有，`HttpStreamFactory` 开始创建新的连接。**
4. **`HttpStreamFactoryJobController` 被创建来协调连接尝试。**
5. **如果 DNS 解析返回了 HTTPS 记录，`HttpStreamFactoryJobController` 中的逻辑（被这个测试文件覆盖）会决定是否创建 `DnsAlpnH3Job`。**
6. **在调试网络连接问题时，开发者可能会查看 `chrome://net-internals/#http2` 或 `chrome://webrtc-internals` 等页面来分析连接建立的过程。如果怀疑是 HTTP/3 或替代服务的问题，就可能需要深入到 `HttpStreamFactoryJobController` 的相关代码进行调试，这时就需要理解这些单元测试所覆盖的场景。**

**功能归纳 (针对第 9 部分):**

作为第 9 部分，且是最后一部分，这个文件专注于测试 `HttpStreamFactoryJobController` 中与 **通过 DNS 记录发现和使用 HTTP/3 (DNS-based HTTPS ALPN)** 以及一些 **连接池相关的预连接行为** 的逻辑。它验证了在各种场景下，`HttpStreamFactoryJobController` 是否能正确地创建、管理和协调不同类型的连接 Job (包括 `MainJob`, `AlternativeJob`, 和 `DnsAlpnH3Job`)，以及如何在这些 Job 之间进行竞争和回退。此外，它也覆盖了在启用 Happy Eyeballs V3 的情况下，预连接与连接池的交互。 总体而言，这部分确保了 Chromium 网络栈能够有效地利用 HTTP/3 并管理连接资源。

### 提示词
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "DNS alpn H3 job must exist.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DoNotStartDnsAlpnH3JobWhenSameHostDefaultPortAltJobCreated) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "www.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);
  // |dns_alpn_h3_job| must be deleted when a same origin alt service
  // was registered.
  CheckJobsStatus(
      true, true, false,
      "All types of jobs are created, but DNS alpn job must be deleted");

  base::RunLoop().RunUntilIdle();
  base::HistogramTester histogram_tester;
  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_MAIN_JOB_WON_RACE,
      1);

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/false,
                  "Alternate job must not be deleted");

  // Make |alternative_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       AllJobsCreatedMainJobSucceedAltJobSucceedDnsJobSucceed) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  PrepareForSecondQuicJob();

  // Use cold start and complete `alternative_job` and `dns_alpn_h3_job`
  // manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "alt.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);
  // |dns_alpn_h3_job| must be created when a different origin alt service
  // was registered.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true,
                  "All types of jobs are created");

  base::HistogramTester histogram_tester;
  base::RunLoop().RunUntilIdle();
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_MAIN_JOB_WON_RACE,
      1);

  // The success of |main_job| doesn't delete |alternative_job| and
  // |dns_alpn_h3_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true, "Jobs must not be deleted.");

  // Make |alternative_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Alternate job must be deleted.");

  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(1, /*expect_stream_ready=*/false);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS alpn job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       AllJobsCreatedAltJobSucceedDnsJobSucceedMainJobSucceed) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  PrepareForSecondQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "alt.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);
  // |dns_alpn_h3_job| must be created when a different origin alt service
  // was registered.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true,
                  "All types of jobs are created");

  base::HistogramTester histogram_tester;
  // Make |alternative_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample("Net.AlternateProtocolUsage",
                                      ALTERNATE_PROTOCOL_USAGE_WON_RACE, 1);

  // The success of |alternative_job| doesn't delete |main_job| and
  // |dns_alpn_h3_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true, "Jobs must not be deleted.");

  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(1, /*expect_stream_ready=*/false);

  // The success of |dns_alpn_h3_job| doesn't delete |main_job| and
  // |alternative_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS alpn job must be deleted.");

  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/false);

  // |main_job| should be cleared.
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/false,
                  "Alternate job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       AllJobsCreatedDnsJobSucceedAltJobSucceedMainJobSucceed) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  PrepareForSecondQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "alt.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);
  // |dns_alpn_h3_job| must be created when a different origin alt service
  // was registered.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true,
                  "All types of jobs are created");

  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(1, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE, 1);

  // The success of |dns_alpn_h3_job| doesn't delete |main_job| and
  // |alternative_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true, "Jobs must not be deleted.");

  // Make |alternative_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);

  // The success of |alternative_job| doesn't delete |main_job| and
  // |dns_alpn_h3_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Alternate job must be deleted.");

  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/false);

  // |main_job| should be cleared.
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Main job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsJobFailOnDefaultNetworkDnsJobFailMainJobSucceed) {
  PrepareForMainJob();
  PrepareForFirstQuicJobFailure();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  request_ = CreateJobControllerAndStart(request_info);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  JobControllerPeer::SetDnsAlpnH3JobFailedOnDefaultNetwork(job_controller_);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Jobs must not be deleted.");

  base::RunLoop().RunUntilIdle();
  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| fail.
  quic_data_->Resume();
  base::RunLoop().RunUntilIdle();
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false, "DNS alpn job be deleted.");

  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  // Net.AlternateProtocolUsage records
  // ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON, when only main job exists.
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON,
      1);

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS alpn job must be deleted.");

  request_.reset();
  EXPECT_TRUE(IsAlternativeServiceBroken(request_info.url));
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  histogram_tester.ExpectUniqueSample("Net.AlternateServiceForDnsAlpnH3Failed",
                                      -ERR_QUIC_PROTOCOL_ERROR, 1);

  // Verify the brokenness is not cleared when the default network changes.
  session_->http_server_properties()->OnDefaultNetworkChanged();
  EXPECT_TRUE(IsAlternativeServiceBroken(request_info.url));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsJobFailOnDefaultNetworkMainJobSucceedDnsJobSucceed) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  base::HistogramTester histogram_tester;
  request_ = CreateJobControllerAndStart(request_info);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  JobControllerPeer::SetDnsAlpnH3JobFailedOnDefaultNetwork(job_controller_);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Jobs must not be deleted.");
  base::RunLoop().RunUntilIdle();
  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_MAIN_JOB_WON_RACE,
      1);

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "DNS alpn job must not be deleted.");

  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);

  request_.reset();
  histogram_tester.ExpectTotalCount("Net.AlternateServiceForDnsAlpnH3Failed",
                                    0);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  EXPECT_TRUE(IsAlternativeServiceBroken(request_info.url));

  // Verify the brokenness is cleared when the default network changes.
  session_->http_server_properties()->OnDefaultNetworkChanged();
  EXPECT_FALSE(IsAlternativeServiceBroken(request_info.url));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsJobSucceedMainJobCanceled) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  request_ = CreateJobControllerAndStart(request_info);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE, 1);

  // Main job is canceled.
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Main job must be deleted");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsJobFailOnDefaultNetworkDnsJobSucceedMainJobSucceed) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  request_ = CreateJobControllerAndStart(request_info);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  JobControllerPeer::SetDnsAlpnH3JobFailedOnDefaultNetwork(job_controller_);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Jobs must not be deleted.");

  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE, 1);

  // Main job is not canceled, because |dns_alpn_h3_job| has failed on the
  // default network.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job must not be deleted.");

  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/false);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest, PreconnectDnsAlpnH3) {
  SetPreconnect();
  PrepareForFirstQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  CreateJobController(request_info);
  job_controller_->Preconnect(/*num_streams=*/5);
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT_DNS_ALPN_H3,
            job_controller_->main_job()->job_type());

  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       PreconnectAltSvcAvailableActiveSessionAvailable) {
  SetPreconnect();
  PrepareForFirstQuicJob();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  RegisterMockHttpsRecord();
  Initialize(request_info);

  // Register Alt-Svc info.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // Create an active session of require_dns_https_alpn = true.
  std::unique_ptr<QuicHttpStream> stream =
      ConnectQuicHttpStream(/*alt_destination=*/false,
                            /*require_dns_https_alpn=*/true);

  CreateJobController(request_info);
  // Preconnect must succeed using the existing session.
  job_controller_->Preconnect(/*num_streams=*/1);
  ASSERT_TRUE(job_controller_->main_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT_DNS_ALPN_H3,
            job_controller_->main_job()->job_type());
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest, PreconnectNoDnsAlpnH3) {
  EnableOndemandHostResolver();
  PrepareForMainJob();
  SetPreconnect();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  Initialize(HttpRequestInfo());
  CreateJobController(request_info);
  job_controller_->Preconnect(/*num_streams=*/1);
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT_DNS_ALPN_H3,
            job_controller_->main_job()->job_type());

  // Resolve the host resolve request from |dns_alpn_h3_job|.
  session_deps_.host_resolver->ResolveAllPending();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(HttpStreamFactory::PRECONNECT,
            job_controller_->main_job()->job_type());

  base::RunLoop().RunUntilIdle();

  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/false);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Test that, when an Alt-Svc-based preconnect fails with
// `ERR_DNS_NO_MATCHING_SUPPORTED_ALPN`, the job controller handles it
// correctly. This is a regression test for https://crbug.com/1420202.
//
// In a general HTTPS-RR implementation, this may happen simply because there
// was no A/AAAA route. However, we do not implement HTTPS-RR in full yet (see
// https://crbug.com/1417033), so instead this is only possible in a corner case
// with ECH.
TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       PreconnectAlternateNoDnsAlpn) {
  const char kAlternateHost[] = "alt.example.com";

  EnableOndemandHostResolver();
  PrepareForMainJob();
  SetPreconnect();

  // Register a mock HTTPS record where the HTTPS-RR route is only good for h2,
  // which is incompatible with Alt-Svc. The A/AAAA route would be compatible,
  // but the server supports ECH, so we enable SVCB-reliant mode and reject it.
  // As a result, the alternate job will fail.
  HostResolverEndpointResult endpoint_result1;
  endpoint_result1.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoint_result1.metadata.ech_config_list = {1, 2, 3, 4};
  endpoint_result1.metadata.supported_protocol_alpns = {"h2"};
  HostResolverEndpointResult endpoint_result2;
  endpoint_result2.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  session_deps_.host_resolver->rules()->AddRule(
      kAlternateHost,
      MockHostResolverBase::RuleResolver::RuleResult(
          {endpoint_result1, endpoint_result2}, {kAlternateHost}));

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();
  Initialize(request_info);
  CreateJobController(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, kAlternateHost, 443);
  SetAlternativeService(request_info, alternative_service);

  job_controller_->Preconnect(/*num_streams=*/1);
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT,
            job_controller_->main_job()->job_type());

  // Resolve the DNS request.
  session_deps_.host_resolver->ResolveAllPending();
  base::RunLoop().RunUntilIdle();

  // The jobs should have failed. We currently do not try the non-Alt-Svc route
  // in preconnects if Alt-Svc failed.
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsResolutionTimeOverridesFromAlpnH3Job) {
  const base::TimeDelta kDnsDelay = base::Milliseconds(10);
  EnableOndemandHostResolver();
  PrepareForMainJob();
  session_deps_.host_resolver->rules()->AddRule(
      "www.example.org", IPAddress::IPv4Localhost().ToString());
  Initialize(HttpRequestInfo());
  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  // Simulate the delay of DNS resolution.
  FastForwardBy(kDnsDelay);

  // Resolve the host resolve request from `dns_alpn_h3_job`.
  session_deps_.host_resolver->ResolveAllPending();

  // `main_job` must be resumed.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  // DnsResolutionTimeOverrides must be set.
  EXPECT_EQ(kDnsDelay, request_->dns_resolution_end_time_override() -
                           request_->dns_resolution_start_time_override());

  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsResolutionTimeOverridesFromAlternativeJob) {
  const base::TimeDelta kDnsDelay = base::Milliseconds(10);
  EnableOndemandHostResolver();
  PrepareForMainJob();
  PrepareForFirstQuicJobFailure();
  session_deps_.host_resolver->rules()->AddRule(
      "www.example.org", IPAddress::IPv4Localhost().ToString());
  Initialize(HttpRequestInfo());

  // Register the same destination alternative service.
  HttpRequestInfo request_info = CreateTestHttpRequestInfo();
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "www.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/false,
                  "Main job and alternative job are created.");

  // Simulate the delay of DNS resolution.
  FastForwardBy(kDnsDelay);

  // Resolve the host resolve request from `alternative_job`.
  session_deps_.host_resolver->ResolveAllPending();

  // `main_job` must be resumed.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  // DnsResolutionTimeOverrides must be set by the `alternative_job`.
  EXPECT_EQ(kDnsDelay, request_->dns_resolution_end_time_override() -
                           request_->dns_resolution_start_time_override());

  // Make |dns_alpn_h3_job| fail.
  quic_data_->Resume();

  MakeMainJobSucceed(/*expect_stream_ready=*/true);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       DnsResolutionTimeOverridesNotFromDifferentAlternativeJob) {
  const base::TimeDelta kDnsDelay1 = base::Milliseconds(10);
  const base::TimeDelta kDnsDelay2 = base::Milliseconds(20);

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  EnableOndemandHostResolver();
  PrepareForMainJob();
  PrepareForFirstQuicJobFailure();

  session_deps_.host_resolver->rules()->AddRule(
      "www.example.org", IPAddress::IPv4Localhost().ToString());
  session_deps_.host_resolver->rules()->AddRule(
      "alt.example.org", IPAddress::IPv4Localhost().ToString());

  Initialize(HttpRequestInfo());

  // Register a different destination alternative service.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "alt.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true,
                  "All types of jobs are created.");

  // `main_job` is blocked until host resolves.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  EXPECT_EQ(2u, session_deps_.host_resolver->last_id());
  EXPECT_EQ("alt.example.org", session_deps_.host_resolver->request_host(1));
  EXPECT_EQ("www.example.org", session_deps_.host_resolver->request_host(2));

  // Simulate the delay of DNS resolution.
  FastForwardBy(kDnsDelay1);

  // Resolves the DNS request for "alt.example.org".
  session_deps_.host_resolver->ResolveNow(1);

  // `main_job` must be resumed.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  // DnsResolutionTimeOverrides must not be set for the different destination's
  // alternative job's DNS resolution time.
  EXPECT_TRUE(request_->dns_resolution_end_time_override().is_null());
  EXPECT_TRUE(request_->dns_resolution_start_time_override().is_null());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true,
                  "All types of jobs must alive.");

  // Make `alternative_job` fail.
  quic_data_->Resume();
  base::RunLoop().RunUntilIdle();
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Alternative job be deleted.");

  // Simulate the delay of DNS resolution.
  FastForwardBy(kDnsDelay2);

  // Resolves the DNS request for "www.example.org".
  session_deps_.host_resolver->ResolveAllPending();
  base::RunLoop().RunUntilIdle();

  // DnsResolutionTimeOverrides must be set.
  EXPECT_EQ(kDnsDelay1 + kDnsDelay2,
            request_->dns_resolution_end_time_override() -
                request_->dns_resolution_start_time_override());

  EXPECT_FALSE(job_controller_->main_job()->is_waiting());
  // `dns_alpn_h3_job` must not fail when there is a valid supported alpn.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "Only main job must be alive");

  MakeMainJobSucceed(/*expect_stream_ready=*/true);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Tests specific to the HappyEyeballsV3 feature.
// TODO(crbug.com/346835898): Find ways to run more tests with the
// HappyEyeballsV3 feature enabled.
class HttpStreamFactoryJobControllerPoolTest
    : public HttpStreamFactoryJobControllerTestBase {
 public:
  HttpStreamFactoryJobControllerPoolTest()
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/false,
            /*happy_eyeballs_v3_enabled=*/true) {}

  ~HttpStreamFactoryJobControllerPoolTest() override = default;

 protected:
  HttpStreamPool* pool() { return session_->http_stream_pool(); }

  FakeServiceEndpointResolver* resolver() {
    return static_cast<FakeServiceEndpointResolver*>(
        session_deps_.alternate_host_resolver.get());
  }
};

TEST_F(HttpStreamFactoryJobControllerPoolTest, Preconnect) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("127.0.0.1").endpoint())
      .set_start_result(OK);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SetPreconnect();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");
  Initialize(request_info);

  job_controller_->Preconnect(/*num_streams=*/1);
  // No jobs should be created.
  ASSERT_FALSE(job_controller_->main_job());
  ASSERT_FALSE(job_controller_->alternative_job());

  RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  ASSERT_EQ(pool()->TotalIdleStreamCount(), 1u);
}

TEST_F(HttpStreamFactoryJobControllerPoolTest, PreconnectSync) {
  SetPreconnect();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");
  Initialize(request_info);

  // Add an idle stream to the pool.
  const HttpStreamKey stream_key(
      url::SchemeHostPort("http", "www.example.com", 80), PRIVACY_MODE_DISABLED,
      SocketTag(), NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  HttpStreamPool::Group& group = pool()->GetOrCreateGroupForTesting(stream_key);
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());

  // Preconnect should complete immediately as we already have an idle stream.
  job_controller_->Preconnect(/*num_streams=*/1);
  // No jobs should be created.
  ASSERT_FALSE(job_controller_->main_job());
  ASSERT_FALSE(job_controller_->alternative_job());
  ASSERT_EQ(pool()->TotalIdleStreamCount(), 1u);

  // Need RunUntilIdle() because the completion notification is delayed.
  RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

}  // namespace net::test
```