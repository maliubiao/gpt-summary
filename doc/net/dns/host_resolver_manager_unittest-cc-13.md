Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of a unit test for Chromium's network stack, specifically the `HostResolverManager`. The user also has several specific requests: identify connections to Javascript, explain logical inferences with input/output examples, highlight common usage errors, trace user steps to reach this code, and summarize the overall function given that this is part 14 of 21.

**Plan:**

1. **High-level overview:** Determine the main purpose of the code. It appears to be testing the DNS resolution functionality of `HostResolverManager`, specifically handling `PTR` and `SRV` DNS record types.
2. **Detailed analysis of each test case:**
    - Explain what each test aims to verify.
    - Identify any assumptions or setup steps.
    - Note the expected outcome (success or specific error).
3. **Javascript relevance:**  Consider how DNS resolution interacts with web browsing and how Javascript might be involved.
4. **Logical inferences:** Analyze the conditional logic and how test inputs lead to specific outputs (assertions).
5. **Common usage errors:** Think about how developers might misuse the `HostResolver` API or encounter issues related to DNS configuration.
6. **User journey:**  Imagine the sequence of actions a user might take in a web browser that would trigger DNS resolution.
7. **Summarize the functionality of this section:**  Focus on the specific aspects of DNS resolution being tested in this part (PTR and SRV records, error handling).
```cpp
s_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          "host", dns_protocol::kTypeSRV,
          {BuildTestAddressRecord("host", IPAddress(1, 2, 3, 4))})),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  // Responses for the wrong type should be ignored.
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       SrvInsecureQueryDisallowedWhenAdditionalTypesDisallowed) {
  const std::string kName = "srv.test";

  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kOff;
  resolver_->SetDnsConfigOverrides(overrides);
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/true,
      /*additional_dns_types_enabled=*/false);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kName, 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  // No non-local work is done, so ERR_DNS_CACHE_MISS is the result.
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// Same as SrvQuery except we specify DNS HostResolverSource instead of relying
// on automatic determination. Expect same results since DNS should be what we
// automatically determine, but some slightly different logic paths are
// involved.
TEST_F(HostResolverManagerDnsTest, SrvDnsQuery) {
  const TestServiceRecord kRecord1 = {2, 3, 1223, "foo.com"};
  const TestServiceRecord kRecord2 = {5, 10, 80, "bar.com"};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeSRV, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsServiceResponse(
                         "host", {kRecord1, kRecord2})),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect ordered by priority, and random within a priority.
  ASSERT_THAT(
      response.request()->GetHostnameResults(),
      testing::Pointee(testing::UnorderedElementsAre(
          HostPortPair("foo.com", 1223), HostPortPair("bar.com", 80))));
}
```

## 功能列举

这个代码文件 `net/dns/host_resolver_manager_unittest.cc` 的主要功能是：

* **对 `HostResolverManager` 的 DNS 查询功能进行单元测试。**  它专注于测试 `HostResolverManager` 如何处理特定的 DNS 查询类型，特别是 `PTR` (Pointer Record) 和 `SRV` (Service Record) 查询。
* **模拟 DNS 客户端行为。** 使用 `MockDnsClientRuleList` 来预设 DNS 查询的响应，以便在测试中控制 DNS 服务器的返回结果，无需实际的网络请求。
* **验证不同场景下的 DNS 查询结果。**  测试了成功解析、解析失败（例如，域名不存在、超时、格式错误）、以及接收到错误类型响应等多种情况。
* **测试安全 DNS 相关的配置。**  验证在禁用额外的 DNS 类型时，是否正确阻止了不安全的 `PTR` 和 `SRV` 查询。
* **验证指定 DNS 源的查询。**  测试了通过明确设置 `HostResolverSource::DNS` 来发起查询的情况。
* **验证缓存行为 (在 `LogWithSource()` 测试中)。**  虽然不是本段代码的主要焦点，但其中一个测试用例涉及了从缓存中获取过期数据的情况。

## 与 Javascript 的关系

虽然这段 C++ 代码本身不直接包含 Javascript 代码，但它测试的网络栈功能与 Javascript 的行为密切相关。

**举例说明：**

* **`PTR` 查询和反向 DNS 查找：** 当 Javascript 代码尝试获取与特定 IP 地址关联的主机名时（例如，通过某些网络诊断 API 或服务器端 Javascript 代码），浏览器可能会执行反向 DNS 查找，这会触发 `PTR` 查询。
    ```javascript
    // 假设在 Node.js 环境中
    const dns = require('dns');
    dns.reverse('8.8.8.8', (err, hostnames) => {
      if (err) {
        console.error(err);
      } else {
        console.log(hostnames); // 可能输出 ['dns.google']
      }
    });
    ```
    这段 Javascript 代码最终会触发底层网络栈的 `PTR` 查询。本文件中的 `PtrQueryHandlesReverseIpLookup` 测试就是验证这种场景。

* **`SRV` 查询和服务发现：**  在某些使用特定协议的应用中（例如，某些即时通讯或分布式系统），Javascript 代码可能需要查找特定服务的可用实例。这通常通过 `SRV` 记录来实现。
    ```javascript
    // 假设有一个自定义的协议 "myproto"
    // Javascript 代码可能需要查找名为 "_myservice._tcp.example.com" 的 SRV 记录
    // (具体的 API 和库取决于实现)
    ```
    当 Javascript 代码执行类似的操作时，浏览器或 Node.js 环境会发起 `SRV` 查询。本文件中的 `SrvQuery` 测试就是验证 `SRV` 查询的解析和结果排序。

**总结：**  Javascript 代码通过浏览器或 Node.js 的网络 API 间接地使用了底层的 DNS 解析功能。这个 C++ 单元测试确保了这些底层功能在各种情况下的正确性，从而保证了 Javascript 网络操作的可靠性。

## 逻辑推理和假设输入/输出

以下是一些测试用例的逻辑推理和假设输入/输出示例：

**示例 1：`PtrQuery` 测试**

* **假设输入：**
    * 查询的主机名：`host`
    * 查询类型：`PTR`
    * 预设的 DNS 规则：当查询 `host` 的 `PTR` 记录时，返回 `foo.com` 和 `bar.com`。
* **逻辑推理：**  `HostResolverManager` 应该向模拟的 DNS 客户端发送 `PTR` 查询，并接收到预设的响应。
* **预期输出：**
    * `response.result_error()` 为 `IsOk()` (表示查询成功)。
    * `response.request()->GetHostnameResults()` 包含 `HostPortPair("foo.com", 108)` 和 `HostPortPair("bar.com", 108)`，顺序不确定。

**示例 2：`PtrQueryRejectsIpLiteral` 测试**

* **假设输入：**
    * 查询的主机名：`8.8.8.8` (一个 IP 地址)
    * 查询类型：`PTR`
    * 预设的 DNS 规则：存在针对 `8.8.8.8` 的 `PTR` 记录的规则，但由于 IP 地址被拒绝，此规则不应生效。
* **逻辑推理：** `HostResolverManager` 应该拒绝直接对 IP 地址进行 `PTR` 查询。
* **预期输出：**
    * `response.result_error()` 为 `IsError(ERR_NAME_NOT_RESOLVED)` (表示名称无法解析)。
    * 其他结果列表（地址、端点、文本、主机名）为空。

**示例 3：`SrvQuery` 测试**

* **假设输入：**
    * 查询的主机名：`host`
    * 查询类型：`SRV`
    * 预设的 DNS 规则：当查询 `host` 的 `SRV` 记录时，返回具有不同优先级和权重的服务记录（例如，端口、目标主机等）。
* **逻辑推理：** `HostResolverManager` 应该根据 `SRV` 记录的优先级和权重对结果进行排序。
* **预期输出：**
    * `response.result_error()` 为 `IsOk()`。
    * `response.request()->GetHostnameResults()` 包含根据优先级排序的主机名和端口，同一优先级的记录顺序不确定。

## 用户或编程常见的使用错误

* **错误地对 IP 地址执行 `PTR` 查询。**  用户或开发者可能会尝试使用 `PTR` 查询来查找 IP 地址对应的主机名，但 `PTR` 查询的正确用法是反向查找，即针对特定的反向 DNS 域名（例如，`8.8.8.8.in-addr.arpa`）。直接查询 IP 地址通常不会得到预期的结果，甚至会被拒绝（如 `PtrQueryRejectsIpLiteral` 测试所示）。

* **期望 `SRV` 查询返回 IP 地址。** `SRV` 记录指向的是主机名和端口，而不是直接的 IP 地址。用户可能会错误地期望 `SRV` 查询直接返回可连接的 IP 地址，但需要进一步解析 `SRV` 记录中返回的主机名。

* **忽略 `SRV` 记录的优先级和权重。**  `SRV` 记录的结果应该根据优先级（数值越小优先级越高）排序，并在同一优先级内根据权重随机选择。开发者在处理 `SRV` 查询结果时，需要理解并正确利用这些信息来实现负载均衡或故障转移。

* **在不允许的情况下发起不安全的非 A/AAAA 查询。**  如果系统配置为只允许安全的 DNS 查询或禁用了额外的 DNS 类型，尝试发起不安全的 `PTR` 或 `SRV` 查询将会失败（如 `PtrInsecureQueryDisallowedWhenAdditionalTypesDisallowed` 和 `SrvInsecureQueryDisallowedWhenAdditionalTypesDisallowed` 测试所示）。用户或开发者需要注意 DNS 配置和安全策略。

## 用户操作如何一步步到达这里 (调试线索)

1. **用户在浏览器地址栏输入一个主机名并尝试访问。** 例如，`www.example.com`。
2. **浏览器需要解析该主机名的 IP 地址。**  `HostResolverManager` 负责执行此操作。
3. **如果需要进行 `PTR` 查询 (例如，用于显示网站证书信息或进行某些网络诊断)：**
    * 浏览器或某些扩展程序可能需要查找与服务器 IP 地址关联的主机名。
    * 这将触发 `HostResolverManager` 发起 `PTR` 查询。
    * 可以通过浏览器的开发者工具的网络面板观察 DNS 查询类型。
4. **如果应用程序需要查找特定服务的实例 (使用 `SRV` 记录)：**
    * 某些应用或协议可能会依赖 `SRV` 记录来进行服务发现。
    * 例如，一个即时通讯应用可能需要查找可用的服务器。
    * 应用程序会调用相应的网络 API，最终导致 `HostResolverManager` 发起 `SRV` 查询。
5. **在测试或开发环境中：**
    * 开发者可能会使用特定的工具或代码来模拟 DNS 查询，以测试网络应用的特定功能。
    * 他们可能会使用 `HostResolver` API 来手动发起 `PTR` 或 `SRV` 查询。

**调试线索：**

* **网络面板：**  在 Chrome 的开发者工具的网络面板中，可以查看浏览器发起的 DNS 查询类型和结果。
* **`chrome://net-internals/#dns`：**  此页面提供了更详细的 DNS 解析信息，包括查询历史和缓存状态。
* **日志记录：**  Chromium 的网络栈具有详细的日志记录功能。通过启用网络日志，可以跟踪 DNS 查询的整个过程。
* **代码断点：**  在 `net/dns/host_resolver_manager.cc` 和相关的 DNS 代码中设置断点，可以逐步查看 DNS 查询的执行流程。

## 功能归纳 (第 14 部分)

这部分代码主要测试了 `HostResolverManager` 处理 **非地址类型的 DNS 查询** 的能力，具体而言是 **`PTR` (反向地址查询)** 和 **`SRV` (服务定位查询)**。

其核心功能包括：

* **验证 `PTR` 查询：**
    * 成功解析 `PTR` 记录并返回关联的主机名。
    * 拒绝直接对 IP 地址执行 `PTR` 查询。
    * 正确处理反向 IP 查找（查询 `.in-addr.arpa` 域名）。
    * 处理各种 DNS 错误情况（域名不存在、失败、超时、空响应、格式错误、名称不匹配、错误类型响应）。
    * 测试在禁用额外 DNS 类型时，是否阻止了不安全的 `PTR` 查询。
* **验证 `SRV` 查询：**
    * 成功解析 `SRV` 记录并返回按优先级和权重排序的主机名和端口。
    * 拒绝直接对 IP 地址执行 `SRV` 查询。
    * 正确处理权重为 0 的 `SRV` 记录。
    * 处理各种 DNS 错误情况（域名不存在、失败、超时、空响应、格式错误、名称不匹配、错误类型响应）。
    * 测试在禁用额外 DNS 类型时，是否阻止了不安全的 `SRV` 查询。
* **验证指定 DNS 源的查询。**  对于 `PTR` 和 `SRV` 查询，测试了明确指定使用 DNS 作为解析源的情况。

总而言之，这部分单元测试着重于确保 `HostResolverManager` 能够正确且健壮地处理 `PTR` 和 `SRV` 类型的 DNS 查询，覆盖了各种成功和失败的场景，并考虑了安全 DNS 的配置。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共21部分，请归纳一下它的功能

"""
LogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsOk());
  EXPECT_TRUE(cached_response.request()->GetStaleInfo());
  ASSERT_THAT(cached_response.request()->GetTextResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  "foo1", "foo2", "foo3", "bar1", "bar2")));
  results = cached_response.request()->GetTextResults();
  EXPECT_NE(results->end(), base::ranges::search(*results, foo_records));
  EXPECT_NE(results->end(), base::ranges::search(*results, bar_records));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery) {
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypePTR, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsPointerResponse(
                         "host", {"foo.com", "bar.com"})),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Order between separate records is undefined.
  EXPECT_THAT(response.request()->GetHostnameResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  HostPortPair("foo.com", 108), HostPortPair("bar.com", 108))));
}

TEST_F(HostResolverManagerDnsTest, PtrQueryRejectsIpLiteral) {
  MockDnsClientRuleList rules;

  // Entry that would resolve if DNS is mistakenly queried to ensure that does
  // not happen.
  rules.emplace_back("8.8.8.8", dns_protocol::kTypePTR, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsPointerResponse(
                         "8.8.8.8", {"foo.com", "bar.com"})),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("8.8.8.8", 108), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQueryHandlesReverseIpLookup) {
  const char kHostname[] = "8.8.8.8.in-addr.arpa";

  MockDnsClientRuleList rules;
  rules.emplace_back(kHostname, dns_protocol::kTypePTR, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsPointerResponse(
                         kHostname, {"dns.google.test", "foo.test"})),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHostname, 108), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Order between separate records is undefined.
  EXPECT_THAT(response.request()->GetHostnameResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  HostPortPair("dns.google.test", 108),
                  HostPortPair("foo.test", 108))));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_NonexistentDomain) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypePTR, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kNoDomain),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_Failure) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypePTR, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_Timeout) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypePTR, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kTimeout),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_TIMED_OUT));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_Empty) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypePTR, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_Malformed) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypePTR, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_MismatchedName) {
  std::vector<std::string> ptr_records = {{"foo.com"}};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypePTR, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsPointerResponse(
                         "host", std::move(ptr_records), "not.host")),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, PtrQuery_WrongType) {
  // Respond to a TXT query with an A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypePTR, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          "host", dns_protocol::kTypePTR,
          {BuildTestAddressRecord("host", IPAddress(1, 2, 3, 4))})),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  // Responses for the wrong type should be ignored.
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       PtrInsecureQueryDisallowedWhenAdditionalTypesDisallowed) {
  const std::string kName = "ptr.test";

  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kOff;
  resolver_->SetDnsConfigOverrides(overrides);
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/true,
      /*additional_dns_types_enabled=*/false);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kName, 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  // No non-local work is done, so ERR_DNS_CACHE_MISS is the result.
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// Same as PtrQuery except we specify DNS HostResolverSource instead of relying
// on automatic determination.  Expect same results since DNS should be what we
// automatically determine, but some slightly different logic paths are
// involved.
TEST_F(HostResolverManagerDnsTest, PtrDnsQuery) {
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypePTR, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsPointerResponse(
                         "host", {"foo.com", "bar.com"})),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  parameters.dns_query_type = DnsQueryType::PTR;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Order between separate records is undefined.
  EXPECT_THAT(response.request()->GetHostnameResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  HostPortPair("foo.com", 108), HostPortPair("bar.com", 108))));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery) {
  const TestServiceRecord kRecord1 = {2, 3, 1223, "foo.com"};
  const TestServiceRecord kRecord2 = {5, 10, 80, "bar.com"};
  const TestServiceRecord kRecord3 = {5, 1, 5, "google.com"};
  const TestServiceRecord kRecord4 = {2, 100, 12345, "chromium.org"};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeSRV, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsServiceResponse(
                         "host", {kRecord1, kRecord2, kRecord3, kRecord4})),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect ordered by priority, and random within a priority.
  const std::vector<HostPortPair>* results =
      response.request()->GetHostnameResults();
  ASSERT_THAT(
      results,
      testing::Pointee(testing::UnorderedElementsAre(
          HostPortPair("foo.com", 1223), HostPortPair("bar.com", 80),
          HostPortPair("google.com", 5), HostPortPair("chromium.org", 12345))));
  auto priority2 =
      std::vector<HostPortPair>(results->begin(), results->begin() + 2);
  EXPECT_THAT(priority2, testing::UnorderedElementsAre(
                             HostPortPair("foo.com", 1223),
                             HostPortPair("chromium.org", 12345)));
  auto priority5 =
      std::vector<HostPortPair>(results->begin() + 2, results->end());
  EXPECT_THAT(priority5,
              testing::UnorderedElementsAre(HostPortPair("bar.com", 80),
                                            HostPortPair("google.com", 5)));
}

TEST_F(HostResolverManagerDnsTest, SrvQueryRejectsIpLiteral) {
  MockDnsClientRuleList rules;

  // Entry that would resolve if DNS is mistakenly queried to ensure that does
  // not happen.
  rules.emplace_back("8.8.8.8", dns_protocol::kTypeSRV, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsServiceResponse(
                         "8.8.8.8", {{/*priority=*/4, /*weight=*/0, /*port=*/90,
                                      /*target=*/"google.test"}})),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("8.8.8.8", 108), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// 0-weight services are allowed. Ensure that we can handle such records,
// especially the case where all entries have weight 0.
TEST_F(HostResolverManagerDnsTest, SrvQuery_ZeroWeight) {
  const TestServiceRecord kRecord1 = {5, 0, 80, "bar.com"};
  const TestServiceRecord kRecord2 = {5, 0, 5, "google.com"};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeSRV, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsServiceResponse(
                         "host", {kRecord1, kRecord2})),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect ordered by priority, and random within a priority.
  EXPECT_THAT(response.request()->GetHostnameResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  HostPortPair("bar.com", 80), HostPortPair("google.com", 5))));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_NonexistentDomain) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kNoDomain),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_Failure) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_Timeout) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kTimeout),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_TIMED_OUT));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_Empty) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_Malformed) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_MismatchedName) {
  std::vector<TestServiceRecord> srv_records = {{1, 2, 3, "foo.com"}};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeSRV, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsServiceResponse(
                         "host", std::move(srv_records), "not.host")),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, SrvQuery_WrongType) {
  // Respond to a SRV query with an A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dn
"""


```