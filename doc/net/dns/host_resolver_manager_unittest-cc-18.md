Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `host_resolver_manager_unittest.cc` file. They are also interested in the relationship with JavaScript, logical deductions (with input/output examples), common usage errors, and how a user operation might lead to this code being executed. Finally, as this is part 19 of 21, they want a summary of the file's overall purpose.

Here's a plan to address each of these points:

1. **Functionality:**  Analyze each test case within the provided snippet and describe its purpose. These tests generally focus on specific aspects of the `HostResolverManager`'s DNS resolution functionality.

2. **JavaScript Relationship:** Determine if any of the tested features directly relate to how DNS resolution is used by JavaScript within a browser environment. This will likely involve looking for concepts like DNS prefetching or DoH (DNS-over-HTTPS), which can be configured or observed by web pages.

3. **Logical Deduction (Input/Output):** For some tests, it's possible to infer the expected behavior based on the setup. For example, a test setting up specific DNS records and then making a resolution request should have predictable IP address results. I will provide examples where applicable.

4. **User/Programming Errors:** Identify scenarios within the tests that might reflect common mistakes in network configuration or when interacting with the DNS resolver. This could involve incorrect DNS settings, failing to handle resolution errors, or misunderstanding caching behavior.

5. **User Operation to Reach Here:** Describe the sequence of user actions within a browser that could trigger DNS resolution and thus potentially involve this part of the codebase. This includes things like typing a URL, clicking a link, or a web page making network requests.

6. **File's Overall Functionality (Part 19 of 21):**  Synthesize the purpose of the tests seen in this snippet and relate it to the broader goals of the `host_resolver_manager_unittest.cc` file, which is to comprehensively test the DNS resolution capabilities of the `HostResolverManager`.

**Constraint Checklist:**

* 列举一下它的功能: Yes
* 与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第19部分，共21部分，请归纳一下它的功能: Yes

**Mental Sandbox:**

I'll iterate through the tests:

* **`UnsolicitedHttp`:** Tests handling of unsolicited HTTP service records. Not directly JS related.
* **`UnsolicitedHttps`:** Tests handling of unsolicited HTTPS service records. Could relate to how browsers prioritize HTTPS.
* **`DohProbeRequest` series:** Tests DoH probing functionality, which is relevant to browser security and performance, and indirectly to JS via network requests.
* **`NewlyRegisteredContext` series:** Tests how `ResolveContext` interacts with DNS configuration, relevant to how different browser profiles or contexts handle DNS.
* **`AvoidMulticastIgnoredWithDnsTask`:** Tests a specific resolution parameter. Not directly JS related.
* **`ResultsAreSorted` series:** Tests IP address sorting logic. Important for browser connection establishment and performance, potentially impacting JS loading.
* **`EmptyResultsNotSorted` series:** Tests behavior with no DNS results. JS would see a network error.
* **`ResultsSortedAsUnreachable` series:** Tests how sorting failures are handled. JS would see a network error.
* **`SortFailure` and `PartialSortFailure`:** Tests error handling when IP address sorting fails. JS would see network errors.

I'll focus on the tests related to DoH and IP address sorting when considering JavaScript interaction. For logical deductions, I'll use the tests that set up specific DNS responses. For usage errors, I'll think about common DNS misconfigurations. For user operations, standard web browsing activities will be relevant.

The final summary will emphasize the comprehensive nature of these unit tests in verifying the DNS resolution logic.
这个文件 `net/dns/host_resolver_manager_unittest.cc` 是 Chromium 网络栈中用于测试 `HostResolverManager` 组件的单元测试文件。`HostResolverManager` 负责管理主机名解析的整个过程，包括从缓存中查找、进行 DNS 查询以及处理查询结果。

这个代码片段主要集中在以下几个方面的功能测试：

**1. 处理非请求的 DNS 记录 (Unsolicited Records):**

* **功能:** 测试 `HostResolverManager` 如何处理 DNS 服务器返回的非当前请求的额外记录，例如 `HTTPS` 服务记录。
* **`TEST_F(HostResolverManagerDnsTest, UnsolicitedHttps)`:**  模拟接收到一个包含 `A` 记录和额外的 `HTTPS` 服务记录的 DNS 响应。验证 `HostResolverManager` 是否正确解析了 `A` 记录，并处理了 `HTTPS` 记录，但默认情况下不会将这些额外的非请求记录包含在最终的解析结果中。
* **与 JavaScript 的关系:** 浏览器可能会使用 `HTTPS` 记录来优化 HTTPS 连接的建立，例如提前知道服务的端口和应用层协议。虽然 JavaScript 代码本身不直接操作 DNS 记录，但这些优化会影响到 JavaScript 发起的网络请求的性能。
* **假设输入与输出:**
    * **假设输入:** 对 `unsolicited.test:108` 发起解析请求，Mock DNS 服务器返回 `unsolicited.test` 的 `A` 记录 (1.2.3.4) 和一个 `HTTPS` 记录。
    * **预期输出:**  解析成功，返回 `1.2.3.4` 的 IP 地址，EndpointResults 中包含根据 `HTTPS` 记录生成的信息 (优先级 1，service name 为 ".")，但实验性结果为空，因为这些是非请求的记录。

**2. DNS-over-HTTPS (DoH) 探测请求:**

* **功能:** 测试 `HostResolverManager` 发起 DoH 探测请求以检测 DoH 服务器是否可用的功能。
* **`TEST_F(HostResolverManagerDnsTest, DohProbeRequest)`:**  测试创建和启动一个 DoH 探测请求，并验证在探测运行时 `mock_dns_client_` 的 `doh_probes_running()` 状态。
* **`TEST_F(HostResolverManagerDnsTest, DohProbeRequest_BeforeConfig)`:** 测试在 DNS 配置加载前发起 DoH 探测请求的行为。
* **`TEST_F(HostResolverManagerDnsTest, DohProbeRequest_InvalidateConfig)`:** 测试在 DoH 探测运行过程中 DNS 配置失效的情况。
* **`TEST_F(HostResolverManagerDnsTest, DohProbeRequest_RestartOnConnectionChange)`:** 测试在网络连接改变时，DoH 探测是否会重启。
* **`TEST_F(HostResolverManagerDnsTest, MultipleDohProbeRequests)`:** 测试同时发起多个 DoH 探测请求的情况。
* **与 JavaScript 的关系:** DoH 的启用与否直接影响浏览器如何进行 DNS 查询。如果启用了 DoH，浏览器会将 DNS 查询通过 HTTPS 发送到配置的 DoH 服务器，而不是传统的 UDP/53 端口。这可以提高 DNS 查询的隐私性和安全性。JavaScript 代码无需关心底层的 DNS 查询方式，但 DoH 的启用会影响到所有网络请求的安全性。
* **假设输入与输出:**
    * **假设输入:**  调用 `resolver_->CreateDohProbeRequest(resolve_context_.get())`。
    * **预期输出:**  `Start()` 方法返回 `ERR_IO_PENDING`，并且 `mock_dns_client_->factory()->doh_probes_running()` 返回 `true`，表明探测正在运行。

**3. `ResolveContext` 的注册和使用:**

* **功能:** 测试 `HostResolverManager` 与 `ResolveContext` 之间的交互。`ResolveContext` 可以为不同的网络会话提供独立的 DNS 配置和缓存。
* **`TEST_F(HostResolverManagerDnsTest, NewlyRegisteredContext_ConfigBeforeRegistration)`:** 测试在 DNS 配置加载后注册 `ResolveContext` 的情况，验证新的 `ResolveContext` 是否能立即使用当前的 DNS 配置。
* **`TEST_F(HostResolverManagerDnsTest, NewlyRegisteredContext_NoConfigAtRegistration)`:** 测试在 DNS 配置加载前注册 `ResolveContext` 的情况，验证当 DNS 配置加载后，`ResolveContext` 能否正确获取配置。
* **与 JavaScript 的关系:**  `ResolveContext` 可以对应于浏览器中的不同 Context，例如普通标签页和隐身模式标签页。不同的 Context 可以有不同的 DNS 设置。JavaScript 发起的请求会关联到当前的 Context，并使用其对应的 DNS 配置。
* **假设输入与输出:**
    * **假设输入 (针对 `NewlyRegisteredContext_ConfigBeforeRegistration`):**  先加载 DNS 配置，然后创建一个 `ResolveContext` 并使用 `resolver_->RegisterResolveContext()` 注册。之后，使用这个 `ResolveContext` 发起 DNS 解析请求。
    * **预期输出:**  使用新注册的 `ResolveContext` 发起的解析请求能够成功，表明它已经关联了之前的 DNS 配置。

**4. `avoid_multicast_resolution` 参数:**

* **功能:** 测试 `HostResolver::ResolveHostParameters::avoid_multicast_resolution` 参数在 `DnsTask` 中的行为。
* **`TEST_F(HostResolverManagerDnsTest, AvoidMulticastIgnoredWithDnsTask)`:**  验证当使用 `DnsTask` 进行 DNS 查询时，设置 `avoid_multicast_resolution` 参数会被忽略。
* **与 JavaScript 的关系:**  这个参数通常用于控制底层 DNS 查询的行为，JavaScript 代码通常不会直接设置这个参数。
* **假设输入与输出:**
    * **假设输入:**  创建一个带有 `parameters.avoid_multicast_resolution = true` 的解析请求。
    * **预期输出:**  解析请求仍然成功，表明这个参数在 `DnsTask` 中没有生效。

**5. DNS 解析结果的排序:**

* **功能:** 测试 `HostResolverManager` 对 DNS 解析返回的 IP 地址进行排序的功能，以优化连接性能。
* **`TEST_F(HostResolverManagerDnsTest, ResultsAreSorted)`:**  测试在启用 HostResolverCache 的情况下，对 IPv6 和 IPv4 地址分别进行排序。
* **`TEST_F(HostResolverManagerDnsTest, ResultsAreSortedWithHostCache)`:** 测试在使用 HostCache 时，对所有地址进行一次排序。
* **`TEST_F(HostResolverManagerDnsTest, Ipv4OnlyResultsAreSorted)`:** 测试仅有 IPv4 地址时的排序。
* **`TEST_F(HostResolverManagerDnsTest, Ipv4OnlyResultsNotSortedWithHostCache)`:** 测试在使用 HostCache 时，仅有 IPv4 地址时不进行排序。
* **`TEST_F(HostResolverManagerDnsTest, EmptyResultsNotSorted)`:** 测试当 DNS 返回空结果时不进行排序。
* **`TEST_F(HostResolverManagerDnsTest, EmptyResultsNotSortedWithHostCache)`:** 测试在使用 HostCache 时，当 DNS 返回空结果时不进行排序。
* **`TEST_F(HostResolverManagerDnsTest, ResultsSortedAsUnreachable)`:** 测试地址排序器移除所有结果的情况。
* **`TEST_F(HostResolverManagerDnsTest, ResultsSortedAsUnreachableWithHostCache)`:** 测试在使用 HostCache 时，地址排序器移除所有结果的情况。
* **`TEST_F(HostResolverManagerDnsTest, SortFailure)`:** 测试当地址排序失败时的处理逻辑。
* **`TEST_F(HostResolverManagerDnsTest, PartialSortFailure)`:** 测试当部分地址排序失败时的处理逻辑。
* **`TEST_F(HostResolverManagerDnsTest, SortFailureWithHostCache)`:** 测试在使用 HostCache 时，地址排序失败的处理逻辑。
* **与 JavaScript 的关系:**  IP 地址的排序直接影响浏览器尝试连接服务器的顺序。优化的排序可以减少连接延迟，提升页面加载速度，从而提升 JavaScript 应用的性能。JavaScript 代码感知不到具体的排序过程，但会受益于排序带来的性能提升。
* **假设输入与输出:**
    * **假设输入 (针对 `ResultsAreSorted`):**  对 `host.test` 发起解析请求，Mock DNS 服务器返回 IPv6 地址 `::1` 和 `2001:4860:4860::8888` 以及 IPv4 地址 `127.0.0.1`。同时设置一个 Mock 的地址排序器，将 IPv6 地址反序。
    * **预期输出:**  解析成功，返回的 EndpointResults 中，IPv6 地址按照排序器的结果 (`2001:4860:4860::8888`, `::1`) 排在前面，然后是 IPv4 地址 (`127.0.0.1`)。

**用户或编程常见的使用错误:**

* **DNS 配置错误:** 用户可能配置了错误的 DNS 服务器地址，导致 DNS 查询失败。例如，手动配置了一个无法访问或返回错误信息的 DNS 服务器。这会导致浏览器无法解析主机名，从而 JavaScript 发起的网络请求也会失败。错误信息可能类似于 `ERR_NAME_NOT_RESOLVED`。
* **网络连接问题:** 用户的网络连接中断或者不稳定，也会导致 DNS 查询失败。
* **DoH 配置错误:** 如果用户尝试启用 DoH，但配置了错误的 DoH 服务器地址或遇到了网络问题，可能会导致 DoH 探测失败，浏览器可能会回退到传统的 DNS 查询方式，或者完全无法解析主机名。
* **Hosts 文件配置错误:** 用户修改了操作系统中的 `hosts` 文件，将某些域名指向了错误的 IP 地址，这会影响到 DNS 解析的结果。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器需要解析 URL 中的主机名。**
3. **`HostResolverManager` 收到解析主机名的请求。**
4. **`HostResolverManager` 首先检查本地缓存（HostCache）。**
5. **如果缓存未命中，`HostResolverManager` 根据当前的 DNS 配置选择合适的解析方式（例如，使用系统的 DNS 解析器或 DoH）。**
6. **如果使用了 DNS 查询，`HostResolverManager` 会创建 `DnsTask` 来执行 DNS 查询。**
7. **如果启用了 DoH，并且需要进行探测，就会涉及到 `DohProbeRequest` 的相关代码。**
8. **当收到 DNS 响应后，`HostResolverManager` 会处理响应，包括解析记录，处理额外的记录（如 `HTTPS`），并进行 IP 地址排序。**
9. **如果配置了自定义的地址排序器，则会调用相应的排序逻辑。**
10. **如果排序失败，则会进入相应的错误处理流程。**
11. **最终，解析结果（IP 地址或错误信息）会被返回给请求者。**

在调试网络问题时，可以通过以下方式来观察是否涉及到了这部分代码：

* **使用 Chrome 的 `chrome://net-internals/#dns` 可以查看 DNS 解析的状态和日志。**
* **在 `chrome://net-internals/#events` 中可以查看更底层的网络事件，包括 DNS 查询的详细信息。**
* **在开发者工具的 "Network" 标签页中，可以查看请求的状态，如果 DNS 解析失败，会显示相应的错误信息。**
* **使用网络抓包工具（如 Wireshark）可以捕获 DNS 查询报文，查看实际的请求和响应内容。**

**作为第 19 部分，共 21 部分，这个代码片段的功能归纳:**

这个代码片段主要集中测试 `HostResolverManager` 在进行 DNS 解析过程中的一些高级特性和边缘情况的处理，包括：

* **对非请求的 DNS 记录的处理，特别是 `HTTPS` 服务记录。**
* **DNS-over-HTTPS (DoH) 探测机制的正确性和稳定性。**
* **`ResolveContext` 与 DNS 配置的交互，确保不同网络会话的 DNS 设置隔离。**
* **特定 DNS 解析参数的行为（如 `avoid_multicast_resolution`）。**
* **对 DNS 解析结果进行排序的逻辑，以及排序失败时的处理。**

总体来说，这部分测试旨在确保 `HostResolverManager` 在各种复杂和特殊的情况下，仍然能够正确、高效地进行 DNS 解析，并提供必要的安全和性能优化。它是对 `HostResolverManager` 组件功能更深入、更细致的验证。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第19部分，共21部分，请归纳一下它的功能
```

### 源代码
```cpp
llopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait until 1s before expected timeout.
  FastForwardBy(base::Minutes(20) - base::Seconds(1));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  FastForwardBy(base::Seconds(2));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No experimental results if transaction did not complete.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, UnsolicitedHttps) {
  const char kName[] = "unsolicited.test";

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestAddressRecord(kName, IPAddress(1, 2, 3, 4))};
  std::vector<DnsResourceRecord> additional = {BuildTestHttpsServiceRecord(
      kName, /*priority=*/1, /*service_name=*/".", /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeA, true /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeA, records,
                         {} /* authority */, additional)),
                     false /* delay */);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kName, 108), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // Unsolicited records not included in results.
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, DohProbeRequest) {
  ChangeDnsConfig(CreateValidDnsConfig());

  EXPECT_FALSE(mock_dns_client_->factory()->doh_probes_running());

  std::unique_ptr<HostResolver::ProbeRequest> request =
      resolver_->CreateDohProbeRequest(resolve_context_.get());
  EXPECT_THAT(request->Start(), IsError(ERR_IO_PENDING));

  EXPECT_TRUE(mock_dns_client_->factory()->doh_probes_running());

  request.reset();

  EXPECT_FALSE(mock_dns_client_->factory()->doh_probes_running());
}

TEST_F(HostResolverManagerDnsTest, DohProbeRequest_BeforeConfig) {
  InvalidateDnsConfig();

  std::unique_ptr<HostResolver::ProbeRequest> request =
      resolver_->CreateDohProbeRequest(resolve_context_.get());
  EXPECT_THAT(request->Start(), IsError(ERR_IO_PENDING));
  EXPECT_FALSE(mock_dns_client_->factory()->doh_probes_running());

  ChangeDnsConfig(CreateValidDnsConfig());
  EXPECT_TRUE(mock_dns_client_->factory()->doh_probes_running());
}

TEST_F(HostResolverManagerDnsTest, DohProbeRequest_InvalidateConfig) {
  ChangeDnsConfig(CreateValidDnsConfig());

  std::unique_ptr<HostResolver::ProbeRequest> request =
      resolver_->CreateDohProbeRequest(resolve_context_.get());
  EXPECT_THAT(request->Start(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(mock_dns_client_->factory()->doh_probes_running());

  InvalidateDnsConfig();

  EXPECT_FALSE(mock_dns_client_->factory()->doh_probes_running());
}

TEST_F(HostResolverManagerDnsTest, DohProbeRequest_RestartOnConnectionChange) {
  DestroyResolver();
  test::ScopedMockNetworkChangeNotifier notifier;
  CreateSerialResolver();
  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_NONE);
  ChangeDnsConfig(CreateValidDnsConfig());

  std::unique_ptr<HostResolver::ProbeRequest> request =
      resolver_->CreateDohProbeRequest(resolve_context_.get());
  EXPECT_THAT(request->Start(), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(mock_dns_client_->factory()->doh_probes_running());
  mock_dns_client_->factory()->CompleteDohProbeRuners();
  ASSERT_FALSE(mock_dns_client_->factory()->doh_probes_running());

  notifier.mock_network_change_notifier()->SetConnectionTypeAndNotifyObservers(
      NetworkChangeNotifier::CONNECTION_NONE);

  EXPECT_TRUE(mock_dns_client_->factory()->doh_probes_running());
}

TEST_F(HostResolverManagerDnsTest, MultipleDohProbeRequests) {
  ChangeDnsConfig(CreateValidDnsConfig());

  EXPECT_FALSE(mock_dns_client_->factory()->doh_probes_running());

  std::unique_ptr<HostResolver::ProbeRequest> request1 =
      resolver_->CreateDohProbeRequest(resolve_context_.get());
  EXPECT_THAT(request1->Start(), IsError(ERR_IO_PENDING));
  std::unique_ptr<HostResolver::ProbeRequest> request2 =
      resolver_->CreateDohProbeRequest(resolve_context_.get());
  EXPECT_THAT(request2->Start(), IsError(ERR_IO_PENDING));

  EXPECT_TRUE(mock_dns_client_->factory()->doh_probes_running());

  request1.reset();
  EXPECT_TRUE(mock_dns_client_->factory()->doh_probes_running());

  request2.reset();
  EXPECT_FALSE(mock_dns_client_->factory()->doh_probes_running());
}

// Test that a newly-registered ResolveContext is immediately usable with a DNS
// configuration loaded before the context registration.
TEST_F(HostResolverManagerDnsTest,
       NewlyRegisteredContext_ConfigBeforeRegistration) {
  ResolveContext context(nullptr /* url_request_context */,
                         true /* enable_caching */);
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ASSERT_TRUE(mock_dns_client_->GetCurrentSession());

  resolver_->RegisterResolveContext(&context);
  EXPECT_EQ(context.current_session_for_testing(),
            mock_dns_client_->GetCurrentSession());

  // Test a SECURE-mode DoH request with SetForceDohServerAvailable(false).
  // Should only succeed if a DoH server is marked available in the
  // ResolveContext. MockDnsClient skips most other interaction with
  // ResolveContext.
  mock_dns_client_->SetForceDohServerAvailable(false);
  context.RecordServerSuccess(0u /* server_index */, true /* is_doh_server */,
                              mock_dns_client_->GetCurrentSession());
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, &context));
  EXPECT_THAT(response.result_error(), IsOk());

  resolver_->DeregisterResolveContext(&context);
}

// Test interaction with a ResolveContext registered before a DNS config is
// ready.
TEST_F(HostResolverManagerDnsTest,
       NewlyRegisteredContext_NoConfigAtRegistration) {
  ResolveContext context(nullptr /* url_request_context */,
                         true /* enable_caching */);
  set_allow_fallback_to_systemtask(false);
  InvalidateDnsConfig();
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ASSERT_FALSE(mock_dns_client_->GetCurrentSession());

  // Register context before loading a DNS config.
  resolver_->RegisterResolveContext(&context);
  EXPECT_FALSE(context.current_session_for_testing());

  // Load DNS config and expect the session to be loaded into the ResolveContext
  ChangeDnsConfig(CreateValidDnsConfig());
  ASSERT_TRUE(mock_dns_client_->GetCurrentSession());
  EXPECT_EQ(context.current_session_for_testing(),
            mock_dns_client_->GetCurrentSession());

  // Test a SECURE-mode DoH request with SetForceDohServerAvailable(false).
  // Should only succeed if a DoH server is marked available in the
  // ResolveContext. MockDnsClient skips most other interaction with
  // ResolveContext.
  mock_dns_client_->SetForceDohServerAvailable(false);
  context.RecordServerSuccess(0u /* server_index */, true /* is_doh_server */,
                              mock_dns_client_->GetCurrentSession());
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, &context));
  EXPECT_THAT(response.result_error(), IsOk());

  resolver_->DeregisterResolveContext(&context);
}

// `HostResolver::ResolveHostParameters::avoid_multicast_resolution` not
// currently supported to do anything except with the system resolver. So with
// DnsTask, expect it to be ignored.
TEST_F(HostResolverManagerDnsTest, AvoidMulticastIgnoredWithDnsTask) {
  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters parameters;
  parameters.avoid_multicast_resolution = true;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
}

class MockAddressSorter : public AddressSorter {
 public:
  MOCK_METHOD(void,
              Sort,
              (const std::vector<IPEndPoint>& endpoints, CallbackType callback),
              (const, override));

  void ExpectCall(const std::vector<IPEndPoint>& expected,
                  std::vector<IPEndPoint> sorted) {
    EXPECT_CALL(*this, Sort(expected, _))
        .WillOnce([sorted](const std::vector<IPEndPoint>& endpoints,
                           AddressSorter::CallbackType callback) {
          std::move(callback).Run(true, std::move(sorted));
        });
  }

  void ExpectCallAndFailSort(const std::vector<IPEndPoint>& expected) {
    EXPECT_CALL(*this, Sort(expected, _))
        .WillOnce([](const std::vector<IPEndPoint>& endpoints,
                     AddressSorter::CallbackType callback) {
          std::move(callback).Run(false, {});
        });
  }
};

TEST_F(HostResolverManagerDnsTest, ResultsAreSorted) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  // Expect sorter to be separately called with A and AAAA results. For the
  // AAAA, sort to reversed order.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCall(
      {CreateExpected("::1", 0), CreateExpected("2001:4860:4860::8888", 0)},
      {CreateExpected("2001:4860:4860::8888", 0), CreateExpected("::1", 0)});
  sorter->ExpectCall({CreateExpected("127.0.0.1", 0)},
                     {CreateExpected("127.0.0.1", 0)});

  DnsResponse a_response =
      BuildTestDnsAddressResponse("host.test", IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv6Localhost()),
       BuildTestAddressRecord(
           "host.test",
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());

  // Expect results in the order given by the sorter (with AAAA results before A
  // results).
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(
          testing::ElementsAre(ExpectEndpointResult(testing::ElementsAre(
              CreateExpected("2001:4860:4860::8888", 80),
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

TEST_F(HostResolverManagerDnsTest, ResultsAreSortedWithHostCache) {
  base::test::ScopedFeatureList feature_list;
  DisableHostResolverCache(feature_list);

  // When using HostCache, expect sorter to be called once for all address
  // results together (AAAA before A).
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCall(
      {CreateExpected("::1", 0), CreateExpected("2001:4860:4860::8888", 0),
       CreateExpected("127.0.0.1", 0)},
      {CreateExpected("2001:4860:4860::8888", 0),
       CreateExpected("127.0.0.1", 0), CreateExpected("::1", 0)});

  DnsResponse a_response =
      BuildTestDnsAddressResponse("host.test", IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv6Localhost()),
       BuildTestAddressRecord(
           "host.test",
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());

  // Expect results in the order given by the sorter.
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(
          testing::ElementsAre(ExpectEndpointResult(testing::ElementsAre(
              CreateExpected("2001:4860:4860::8888", 80),
              CreateExpected("127.0.0.1", 80), CreateExpected("::1", 80))))));
}

TEST_F(HostResolverManagerDnsTest, Ipv4OnlyResultsAreSorted) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  // Sort to reversed order.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCall(
      {CreateExpected("127.0.0.1", 0), CreateExpected("127.0.0.2", 0)},
      {CreateExpected("127.0.0.2", 0), CreateExpected("127.0.0.1", 0)});

  DnsResponse a_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv4Localhost()),
       BuildTestAddressRecord("host.test",
                              IPAddress::FromIPLiteral("127.0.0.2").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());

  // Expect results in the order given by the sorter.
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.2", 80),
                                       CreateExpected("127.0.0.1", 80))))));
}

TEST_F(HostResolverManagerDnsTest, Ipv4OnlyResultsNotSortedWithHostCache) {
  base::test::ScopedFeatureList feature_list;
  DisableHostResolverCache(feature_list);

  // When using HostCache, expect no sort calls for IPv4-only results.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();

  DnsResponse a_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv4Localhost()),
       BuildTestAddressRecord("host.test",
                              IPAddress::FromIPLiteral("127.0.0.2").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());

  // Expect results in original unsorted order.
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80),
                                       CreateExpected("127.0.0.2", 80))))));
}

TEST_F(HostResolverManagerDnsTest, EmptyResultsNotSorted) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  // Expect no calls to sorter for empty results.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();

  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kEmpty,
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverManagerDnsTest, EmptyResultsNotSortedWithHostCache) {
  base::test::ScopedFeatureList feature_list;
  DisableHostResolverCache(feature_list);

  // Expect no calls to sorter for empty results.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();

  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kEmpty,
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

// Test for when AddressSorter removes all results.
TEST_F(HostResolverManagerDnsTest, ResultsSortedAsUnreachable) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  // Set up sorter to return result with no addresses.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCall(
      {CreateExpected("::1", 0), CreateExpected("2001:4860:4860::8888", 0)},
      {});
  sorter->ExpectCall({CreateExpected("127.0.0.1", 0)}, {});

  DnsResponse a_response =
      BuildTestDnsAddressResponse("host.test", IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv6Localhost()),
       BuildTestAddressRecord(
           "host.test",
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  ASSERT_FALSE(!!GetCacheHit(HostCache::Key(
      "host.test", DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, NetworkAnonymizationKey())));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  // Expect error is cached (because pre-sort results had a TTL).
  EXPECT_TRUE(!!GetCacheHit(HostCache::Key(
      "host.test", DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, NetworkAnonymizationKey())));
}

// Test for when AddressSorter removes all results.
TEST_F(HostResolverManagerDnsTest, ResultsSortedAsUnreachableWithHostCache) {
  base::test::ScopedFeatureList feature_list;
  DisableHostResolverCache(feature_list);

  // Set up sorter to return result with no addresses.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCall(
      {CreateExpected("::1", 0), CreateExpected("2001:4860:4860::8888", 0),
       CreateExpected("127.0.0.1", 0)},
      {});

  DnsResponse a_response =
      BuildTestDnsAddressResponse("host.test", IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv6Localhost()),
       BuildTestAddressRecord(
           "host.test",
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  ASSERT_FALSE(!!GetCacheHit(HostCache::Key(
      "host.test", DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, NetworkAnonymizationKey())));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  // Expect error is cached (because pre-sort results had a TTL).
  EXPECT_TRUE(!!GetCacheHit(HostCache::Key(
      "host.test", DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, NetworkAnonymizationKey())));
}

TEST_F(HostResolverManagerDnsTest, SortFailure) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";
  constexpr base::TimeDelta kMinTtl = base::Minutes(10);

  // Fail the AAAA sort. Don't expect resolver to even attempt to sort A.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCallAndFailSort(
      {CreateExpected("::1", 0), CreateExpected("2001:4860:4860::8888", 0)});

  DnsResponse a_response = BuildTestDnsAddressResponse(
      std::string(kHost), IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      std::string(kHost), dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord(std::string(kHost), IPAddress::IPv6Localhost(),
                              kMinTtl),
       BuildTestAddressRecord(
           std::string(kHost),
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value(),
           base::Minutes(15))});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeA,
             std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_SORT_ERROR));

  // Expect error is cached with same TTL as results that failed to sort.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::A, HostResolverSource::DNS,
      /*secure=*/false));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalErrorResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kUnknown,
                  Optional(base::TimeTicks::Now() + kMinTtl),
                  Optional(base::Time::Now() + kMinTtl), ERR_DNS_SORT_ERROR)));
}

// Test for if a transaction sort fails after another transaction has already
// succeeded.
TEST_F(HostResolverManagerDnsTest, PartialSortFailure) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";
  constexpr base::TimeDelta kMinTtl = base::Minutes(3);

  // Successfully sort A. Fail to sort AAAA.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCall({IPEndPoint(IPAddress::IPv4Localhost(), 0)},
                     {IPEndPoint(IPAddress::IPv4Localhost(), 0)});
  sorter->ExpectCallAndFailSort({IPEndPoint(IPAddress::IPv6Localhost(), 0),
                                 CreateExpected("2001:4860:4860::8888", 0)});

  DnsResponse a_response = BuildTestDnsAddressResponse(
      std::string(kHost), IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      std::string(kHost), dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord(std::string(kHost), IPAddress::IPv6Localhost(),
                              kMinTtl),
       BuildTestAddressRecord(
           std::string(kHost),
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value(),
           base::Minutes(7))});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeA,
             std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect the successful A result to be cached immediately on receipt.
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::A,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::A,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv4Localhost(), 0)))));
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA));

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_SORT_ERROR));

  // Expect error is cached with same TTL as results that failed to sort.
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::A,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::A,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv4Localhost(), 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalErrorResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kUnknown,
                  Optional(base::TimeTicks::Now() + kMinTtl),
                  Optional(base::Time::Now() + kMinTtl), ERR_DNS_SORT_ERROR)));
}

TEST_F(HostResolverManagerDnsTest, SortFailureWithHostCache) {
  base::test::ScopedFeatureList feature_list;
  DisableHostResolverCache(feature_list);

  // Fail the sort.
  auto sorter = std::make_unique<testing::StrictMock<MockAddressSorter>>();
  sorter->ExpectCallAndFailSort({CreateExpected("::1", 0),
                                 CreateExpected("2001:4860:4860::8888", 0),
                                 CreateExpected("127.0.0.1", 0)});

  DnsResponse a_response =
      BuildTestDnsAddressResponse("host.test", IPAddress::IPv4Localhost());
  DnsResponse aaaa_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("host.test", IPAddress::IPv6Localhost()),
       BuildTestAddressRecord(
           "host.test",
           IPAddress::FromIPLiteral("2001:4860:4860::8888").value())});
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(std::move(sorter));
  set_allow_fallback_to_systemtask(false);

  ASSERT_FALSE(!!GetCacheHit(HostCache::Key(
      "host.test", DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, NetworkAnonymizationKey())));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPai
```