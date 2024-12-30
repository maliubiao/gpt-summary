Response:
The user wants to understand the functionality of the `host_resolver_manager_unittest.cc` file in Chromium's network stack, specifically focusing on the provided code snippet. They also want to know:

1. **Functionality:** What does this code do?
2. **JavaScript Relation:**  Is there any connection to JavaScript? If so, examples.
3. **Logic and I/O:**  If there's logical deduction, what are example inputs and outputs?
4. **Common Errors:** What are common user or programming errors related to this?
5. **User Journey:** How does a user's action lead to this code being executed?
6. **Part Summary:**  Summarize the functionality of this specific part (part 11 of 21).

Let's break down the provided code snippet:

* **It's C++ test code:** The `TEST_F` macros indicate this is a testing framework (likely Google Test).
* **Focus on DNS resolution:** The test names (e.g., `ManuallyDisableDnsClient`, `DnsCallsWithDisabledDnsClient`, `NotFoundTtl`) and the presence of `mock_dns_client_` suggest these tests are verifying the behavior of the `HostResolverManager` specifically related to DNS resolution.
* **Simulating DNS responses:**  The code uses `proc_->AddRuleForAllFamilies` and `mock_dns_client_->CompleteDelayedTransactions()` to simulate different DNS server behaviors and responses.
* **Verifying outcomes:** The `EXPECT_THAT` macros are used to assert that the results of the DNS resolution attempts match the expected outcomes (e.g., successful resolution with specific IP addresses, specific error codes).
* **Testing different scenarios:** The tests cover scenarios like disabling the DNS client, making DNS calls with the client disabled, handling "not found" responses, and dealing with cached errors.
* **Testing IPv6 handling:**  Some tests specifically check IPv6 resolution behavior (`NoCheckIpv6OnWifi`).
* **Testing canonical names (CNAMEs):**  Several tests focus on how the resolver handles canonical names in DNS responses.

Now, let's address each of the user's questions based on this analysis:

1. **Functionality:** This specific part of the test file focuses on verifying the correct behavior of the `HostResolverManager` when interacting with the DNS client and system resolver. It checks how the resolver handles various DNS configurations, including enabling/disabling the DNS client, dealing with different DNS response types (successful resolutions, "not found" errors, timeouts), and how it interacts with the DNS cache. It also examines IPv6 resolution behavior under different network conditions and the handling of canonical names (CNAME records).

2. **JavaScript Relation:**  While this C++ code doesn't directly execute JavaScript, the functionality it tests is crucial for how web browsers handle network requests initiated by JavaScript. For example:
    * When JavaScript uses `fetch()` or `XMLHttpRequest` to access a website, the browser's network stack (including the `HostResolverManager`) performs DNS resolution to find the IP address of the server.
    * The tests for disabled DNS client or missing DNS configuration directly relate to scenarios where JavaScript network requests might fail or fall back to system DNS resolution.
    * The caching behavior tested here impacts how quickly subsequent JavaScript network requests to the same domain will resolve.
    * **Example:** A JavaScript `fetch('https://example.com')` call will trigger DNS resolution. If the `HostResolverManager` has a cached result for `example.com`, the resolution might happen quickly. If the DNS client is disabled (as tested in some of these cases), this `fetch` call might fail or use the system resolver.

3. **Logic and I/O:**  The tests demonstrate logical deductions based on simulated inputs.
    * **Hypothetical Input:**  A DNS request for `slow_ok1` is made while the DNS client is enabled and configured to respond with "192.168.0.1" (simulated by `proc_->AddRuleForAllFamilies`). Then, the DNS client is disabled.
    * **Expected Output:**  The ongoing DNS resolution for `slow_ok1` should be aborted and fall back to the system resolver, which is also configured to resolve `slow_ok1` to "192.168.0.1". The `EXPECT_THAT` assertions verify this.
    * **Another Hypothetical Input:** A DNS request for `host` is made with `HostResolverSource::DNS` while the DNS client is disabled.
    * **Expected Output:** The resolution should fail with `ERR_DNS_CACHE_MISS` because explicitly requesting DNS resolution with a disabled DNS client is not allowed.

4. **Common Errors:**  This code helps prevent common user or programming errors:
    * **Incorrect DNS configuration:** The tests for disabled DNS clients and missing DNS configurations highlight potential issues if a user's system is not properly configured for DNS resolution.
    * **Relying on DNS when it's unavailable:**  Developers might assume DNS resolution always works. These tests ensure the browser handles cases where it doesn't.
    * **Caching issues:**  The tests for cached errors and TTLs are crucial for ensuring the DNS cache behaves correctly, preventing stale or incorrect IP addresses from being used. A common error would be a website not reflecting DNS changes quickly due to aggressive caching.
    * **Forcing DNS when it will fail:**  A programmer might explicitly request `HostResolverSource::DNS` without checking if a DNS client is available, leading to errors.

5. **User Journey:** Here's how a user action can lead to this code (during development/testing):
    1. **Developer modifies DNS-related code:** A Chromium developer makes changes to the `HostResolverManager` or related DNS components.
    2. **Run unit tests:** As part of their development process, the developer runs the unit tests in `host_resolver_manager_unittest.cc`.
    3. **Test execution:** When the tests are executed, the specific test cases in the provided snippet are run.
    4. **Simulated network conditions:** These tests simulate various network conditions (e.g., different DNS server responses, network type changes) using mock objects and test utilities.
    5. **Verification:** The `EXPECT_THAT` assertions verify that the `HostResolverManager` behaves as expected under these simulated conditions.

    **More concretely, a user action indirectly leads to the *need* for this code:**

    * **User types a URL in the address bar:** When a user types a domain name, the browser needs to resolve it to an IP address.
    * **Browser initiates DNS resolution:** The `HostResolverManager` is responsible for this.
    * **Different configurations are possible:** The user might be on a network with a custom DNS server, using secure DNS, or have a temporary network issue.
    * **This test code ensures robustness:**  The tests in this file verify that the DNS resolution process handles these different scenarios correctly, ensuring the user can eventually load the webpage.

6. **Part Summary:** This section of `host_resolver_manager_unittest.cc` specifically focuses on testing the `HostResolverManager`'s behavior related to DNS client interactions, including:

    * **Enabling and disabling the DNS client:** Verifying the impact of manually enabling/disabling the client on ongoing and new DNS resolutions.
    * **Forcing DNS resolution:** Testing scenarios where DNS resolution is explicitly requested and how the resolver behaves when the DNS client is unavailable.
    * **Handling "not found" responses (NODATA and NXDOMAIN):** Checking how these negative responses are cached and their TTLs.
    * **Caching of errors:**  Ensuring that DNS errors are cached correctly and how fallback mechanisms affect error caching.
    * **Secure DNS modes:**  Testing error caching behavior in automatic and secure DNS modes.
    * **Interaction between A and AAAA queries:** Verifying that the failure of one doesn't negatively impact the other.
    * **Handling canonical names (CNAMEs):**  Testing the retrieval and correctness of canonical names in DNS responses, including cases with and without associated address records, and scenarios where the system resolver is used due to CNAME requests.

这是 `net/dns/host_resolver_manager_unittest.cc` 文件的一部分，主要功能是 **测试 `HostResolverManager` 组件在处理 DNS 查询时的各种场景，特别是与 DNS 客户端相关的行为**。

具体来说，这部分代码涵盖了以下功能测试：

1. **手动禁用 DNS 客户端并处理进行中的请求:**
   - 测试当有正在进行的 DNS 查询时，手动禁用 DNS 客户端会发生什么。
   - 验证这些请求是否会回退到使用系统解析器 (`HostResolverSystemTask`) 完成。
   - **功能归纳:** 验证禁用 DNS 客户端时的请求处理机制。

2. **禁用 DNS 客户端时的 DNS 调用:**
   - 测试当 DNS 客户端被禁用时，显式请求使用 DNS 进行解析 (`HostResolverSource::DNS`) 会导致错误。
   - 分别测试了在 `HostResolverManager` 构建后禁用和构建时就禁用的情况。
   - **功能归纳:** 验证显式 DNS 请求在 DNS 客户端禁用时的错误处理。

3. **没有 DNS 配置时的 DNS 调用:**
   - 测试当没有有效的 DNS 配置时，显式请求使用 DNS 进行解析会发生什么。
   - **功能归纳:** 验证没有 DNS 配置时的显式 DNS 请求的错误处理。

4. **在 Wi-Fi 下不检查 IPv6 可达性:**
   - 测试在 Wi-Fi 网络下禁用 IPv6 可达性检查时的解析行为。
   - 验证在这种情况下，即使 IPv6 地址存在，也会优先使用 IPv4 地址，并且只有在显式请求 IPv6 地址时才会解析 IPv6。
   - 同时测试了网络类型改变后，在非 Wi-Fi 网络下 IPv6 解析恢复正常。
   - **功能归纳:** 验证在特定网络条件下（Wi-Fi）禁用 IPv6 检查的解析逻辑。

5. **未找到记录的 TTL (Time To Live):**
   - 测试当 DNS 查询返回 `NODATA` (存在域名但没有请求类型的记录) 或 `NXDOMAIN` (域名不存在) 时，这些错误结果在 DNS 缓存中的 TTL 设置。
   - 验证缓存中存储了错误信息，并且设置了合理的 TTL，防止频繁重复查询。
   - **功能归纳:** 验证 DNS 否定结果的缓存和 TTL 设置。

6. **未找到记录的 TTL 与 HostCache:**
   - 在禁用 `HostResolverCache` 特性的情况下，测试 `NODATA` 和 `NXDOMAIN` 结果在 `HostCache` 中的 TTL 设置。
   - **功能归纳:**  验证在禁用 `HostResolverCache` 时 DNS 否定结果在 `HostCache` 的缓存和 TTL 设置。

7. **缓存错误:**
   - 测试在启用和禁用回退到系统解析器的情况下，DNS 错误结果的缓存行为。
   - 验证在允许回退时，错误不会立即缓存，而在禁用回退后，错误会被缓存。
   - **功能归纳:** 验证 DNS 错误结果的缓存机制以及回退设置的影响。

8. **缓存错误 - 自动模式:**
   - 在安全 DNS 模式设置为自动时，测试 DNS 错误结果在安全和非安全缓存中的缓存行为。
   - **功能归纳:** 验证安全 DNS 自动模式下 DNS 错误在不同缓存中的存储。

9. **缓存错误 - 安全模式:**
   - 在安全 DNS 模式设置为安全时，测试 DNS 错误结果在安全和非安全缓存中的缓存行为。
   - **功能归纳:** 验证安全 DNS 安全模式下 DNS 错误在不同缓存中的存储。

10. **不同查询类型之间不共享 TTL:**
    - 测试当 A 记录查询成功而 AAAA 记录查询失败时，失败的结果不会被缓存。
    - **功能归纳:** 验证不同 DNS 查询类型之间的缓存隔离。

11. **规范名称 (Canonical Name):**
    - 测试当 DNS 响应包含 CNAME 记录时，`HostResolverManager` 能否正确获取规范名称。
    - **功能归纳:** 验证 CNAME 记录的处理和规范名称的获取。

12. **规范名称 - 偏好 IPv6:**
    - 测试当 IPv6 的 CNAME 响应比 IPv4 的慢时，`HostResolverManager` 是否会等待 IPv6 结果。
    - **功能归纳:** 验证 CNAME 解析时的优先级处理。

13. **规范名称 - 仅 IPv4:**
    - 测试在只请求 IPv4 地址时，`HostResolverManager` 能否正确处理 CNAME 记录。
    - **功能归纳:** 验证在特定地址族请求下 CNAME 记录的处理。

14. **没有结果的规范名称:**
    - 测试当 DNS 响应包含 CNAME 记录但没有地址记录时，`HostResolverManager` 的处理行为，应被视为正常的 `NODATA` 响应。
    - **功能归纳:** 验证只有 CNAME 记录但没有地址记录的 DNS 响应处理。

15. **只有一个地址族的规范名称有结果:**
    - 测试当一个地址族的 DNS 响应包含 CNAME 记录但没有地址记录，而另一个地址族有地址记录时，`HostResolverManager` 的处理行为。 验证不会因为一个地址族没有结果而影响另一个地址族的处理。
    - **功能归纳:** 验证不同地址族 CNAME 记录处理的隔离性。

16. **规范名称强制使用 Proc (系统解析器):**
    - 测试在没有指定解析源的情况下，如果请求包含规范名称，即使通常会使用 DNS 客户端，也会强制使用系统解析器。
    - **功能归纳:** 验证请求规范名称时默认使用系统解析器的行为。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不涉及 JavaScript，但 `HostResolverManager` 是 Chromium 网络栈的核心组件，它负责将域名解析为 IP 地址。这个过程对于 JavaScript 发起的网络请求至关重要。

* **`fetch()` 和 `XMLHttpRequest`:** 当 JavaScript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起网络请求时，浏览器会调用 `HostResolverManager` 来解析目标主机的 IP 地址。
* **DNS 缓存:**  `HostResolverManager` 的缓存机制会影响 JavaScript 网络请求的性能。如果 DNS 记录已缓存，则请求可以更快地建立连接。测试中关于缓存错误和 TTL 的部分就直接影响了这一行为。
* **DNS 客户端设置:** 测试中关于禁用 DNS 客户端的情况，会影响 JavaScript 网络请求的解析方式。如果 DNS 客户端被禁用，浏览器可能会回退到使用操作系统的 DNS 解析设置。
* **规范名称:** 当 JavaScript 请求的域名存在 CNAME 记录时，`HostResolverManager` 的处理会影响最终连接的服务器。

**JavaScript 举例:**

```javascript
// 当执行以下 JavaScript 代码时，浏览器会使用 HostResolverManager 来解析 "example.com" 的 IP 地址
fetch('https://example.com');

// 如果 DNS 客户端被禁用（如测试用例所示），这个 fetch 请求可能会受到影响，
// 例如，解析过程可能会回退到系统解析器，或者在显式要求 DNS 解析时可能失败。

// 如果 "example.com" 有 CNAME 记录，HostResolverManager 的处理会确保
// 最终连接到 CNAME 指向的真实服务器。
```

**逻辑推理的假设输入与输出:**

以 **手动禁用 DNS 客户端并处理进行中的请求** 这个测试为例：

* **假设输入:**
    1. 启动 `HostResolverManager`，启用 DNS 客户端。
    2. 创建多个 DNS 查询请求，其中一些是“慢速”的，模拟正在进行中的查询。
    3. 手动禁用 DNS 客户端。
* **预期输出:**
    1. 正在进行的 DNS 查询应该被取消或回退到使用系统解析器。
    2. 最终这些请求会成功完成，但使用的是系统解析器的结果。

以 **禁用 DNS 客户端时的 DNS 调用** 这个测试为例：

* **假设输入:**
    1. 启动 `HostResolverManager`，禁用 DNS 客户端。
    2. 创建一个显式指定使用 DNS (`HostResolverSource::DNS`) 的查询请求。
* **预期输出:**
    1. 该查询请求会立即失败，并返回 `ERR_DNS_CACHE_MISS` 错误。

**涉及用户或编程常见的使用错误:**

1. **用户错误:**
   - **错误的 DNS 配置:** 用户手动配置了错误的 DNS 服务器地址，导致 `HostResolverManager` 无法正常解析域名。测试中关于没有 DNS 配置的情况就模拟了这种场景。
   - **网络问题导致 DNS 不可用:** 用户的网络连接存在问题，导致无法连接到 DNS 服务器。

2. **编程错误:**
   - **强制使用 DNS 但未检查 DNS 客户端状态:**  开发者在代码中显式指定使用 DNS 解析，但没有考虑到 DNS 客户端可能被禁用或配置不正确的情况，导致程序出现意外错误。测试中 `DnsCallsWithDisabledDnsClient` 就模拟了这种情况。
   - **过度依赖 DNS 缓存:** 开发者假设 DNS 缓存总是最新的，没有处理 DNS 记录更新延迟的情况。测试中关于缓存错误和 TTL 的部分与此相关。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设用户无法访问某个网站 `example.com`，作为 Chromium 开发者进行调试：

1. **用户尝试访问网站:** 用户在浏览器地址栏输入 `example.com` 并回车。
2. **浏览器发起导航:** 浏览器开始加载网页的过程。
3. **DNS 解析请求:** 浏览器需要知道 `example.com` 的 IP 地址，因此会调用 `HostResolverManager` 发起 DNS 解析请求。
4. **`HostResolverManager` 处理请求:**
   - 如果 DNS 客户端已启用且配置正确，`HostResolverManager` 可能会使用内置的 DNS 客户端进行解析。
   - 如果 DNS 客户端被禁用，`HostResolverManager` 可能会回退到使用系统解析器。
   - 如果 DNS 记录已缓存，`HostResolverManager` 可能会直接从缓存返回结果。
5. **测试代码的作用:** 在开发和测试阶段，开发者会运行 `host_resolver_manager_unittest.cc` 中的测试用例，模拟各种 DNS 场景（例如，禁用 DNS 客户端、模拟 DNS 服务器返回错误等），以确保 `HostResolverManager` 在各种情况下都能正确处理 DNS 解析请求，并返回预期的结果或错误信息。
6. **调试:** 如果用户无法访问 `example.com`，开发者可能会检查 `HostResolverManager` 的日志，查看 DNS 解析过程是否出错。相关的测试代码可以帮助开发者理解 `HostResolverManager` 在特定情况下的行为，从而定位问题。例如，如果测试表明禁用 DNS 客户端会导致某些请求失败，那么开发者可能会检查用户的 DNS 客户端配置。

**第 11 部分功能归纳:**

这部分测试用例主要关注 `HostResolverManager` 在处理 DNS 查询时与 **DNS 客户端的启用/禁用状态、DNS 配置的有效性以及 DNS 响应中的各种情况（包括错误、未找到记录和规范名称）** 相关的行为。它旨在验证 `HostResolverManager` 在这些场景下的正确性和健壮性，确保能够按照预期进行 DNS 解析或处理解析失败的情况。同时，也覆盖了在特定网络条件（Wi-Fi）下禁用 IPv6 检查的逻辑，以及 DNS 缓存机制在存储错误信息和设置 TTL 方面的行为。最后，测试了如何处理 DNS 响应中的规范名称（CNAME 记录）。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共21部分，请归纳一下它的功能

"""
ECT_THAT(response0.result_error(), IsOk());
    EXPECT_THAT(response0.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected("192.168.0.2", 80)));
    EXPECT_THAT(response0.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected("192.168.0.2", 80))))));
    EXPECT_THAT(response1.result_error(), IsOk());
    EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected("192.168.0.3", 80)));
    EXPECT_THAT(response1.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected("192.168.0.3", 80))))));
    EXPECT_THAT(response2.result_error(), IsOk());
    EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected("192.168.0.4", 80)));
    EXPECT_THAT(response2.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected("192.168.0.4", 80))))));

    mock_dns_client_->CompleteDelayedTransactions();
    EXPECT_THAT(response_dns.result_error(), IsOk());

    EXPECT_THAT(response_system.result_error(), IsOk());
    EXPECT_THAT(response_system.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected("192.168.0.5", 80)));
    EXPECT_THAT(response_system.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected("192.168.0.5", 80))))));

    EXPECT_THAT(response_secure.result_error(), IsOk());
  }
}

// Tests a call to SetDnsClient while there are active DnsTasks.
TEST_F(HostResolverManagerDnsTest,
       ManuallyDisableDnsClientWithPendingRequests) {
  // At most 3 jobs active at once.  This number is important, since we want to
  // make sure that aborting the first HostResolverManager::Job does not trigger
  // another DnsTransaction on the second Job when it releases its second
  // prioritized dispatcher slot.
  CreateResolverWithLimitsAndParams(3u, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */);

  ChangeDnsConfig(CreateValidDnsConfig());

  proc_->AddRuleForAllFamilies("slow_ok1", "192.168.0.1");
  proc_->AddRuleForAllFamilies("slow_ok2", "192.168.0.2");
  proc_->AddRuleForAllFamilies("ok", "192.168.0.3");

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  // First active job gets two slots.
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("slow_ok1", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  EXPECT_FALSE(responses[0]->complete());
  // Next job gets one slot, and waits on another.
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("slow_ok2", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  EXPECT_FALSE(responses[1]->complete());
  // Next one is queued.
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  EXPECT_FALSE(responses[2]->complete());

  EXPECT_EQ(3u, num_running_dispatcher_jobs());

  // Clear DnsClient.  The two in-progress jobs should fall back to a
  // HostResolverSystemTask, and the next one should be started with a
  // HostResolverSystemTask.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);

  // All three in-progress requests should now be running a
  // HostResolverSystemTask.
  EXPECT_EQ(3u, num_running_dispatcher_jobs());
  proc_->SignalMultiple(3u);

  for (auto& response : responses) {
    EXPECT_THAT(response->result_error(), IsOk());
  }
  EXPECT_THAT(responses[0]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.0.1", 80)));
  EXPECT_THAT(responses[0]->request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.0.1", 80))))));
  EXPECT_THAT(responses[1]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.0.2", 80)));
  EXPECT_THAT(responses[1]->request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.0.2", 80))))));
  EXPECT_THAT(responses[2]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.0.3", 80)));
  EXPECT_THAT(responses[2]->request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.0.3", 80))))));
}

// When explicitly requesting source=DNS, no fallback allowed, so doing so with
// DnsClient disabled should result in an error.
TEST_F(HostResolverManagerDnsTest, DnsCallsWithDisabledDnsClient) {
  ChangeDnsConfig(CreateValidDnsConfig());
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);

  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      params, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
}

TEST_F(HostResolverManagerDnsTest,
       DnsCallsWithDisabledDnsClient_DisabledAtConstruction) {
  HostResolver::ManagerOptions options = DefaultOptions();
  options.insecure_dns_client_enabled = false;
  CreateResolverWithOptionsAndParams(std::move(options), DefaultParams(proc_),
                                     true /* ipv6_reachable */);
  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      params, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
}

// Same as DnsClient disabled, requests with source=DNS and no usable DnsConfig
// should result in an error.
TEST_F(HostResolverManagerDnsTest, DnsCallsWithNoDnsConfig) {
  InvalidateDnsConfig();

  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      params, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
}

TEST_F(HostResolverManagerDnsTest, NoCheckIpv6OnWifi) {
  // CreateSerialResolver will destroy the current resolver_ which will attempt
  // to remove itself from the NetworkChangeNotifier. If this happens after a
  // new NetworkChangeNotifier is active, then it will not remove itself from
  // the old NetworkChangeNotifier which is a potential use-after-free.
  DestroyResolver();
  test::ScopedMockNetworkChangeNotifier notifier;
  // Serial resolver to guarantee order of resolutions.
  CreateSerialResolver(false /* check_ipv6_on_wifi */);

  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_WIFI);
  // Needed so IPv6 availability check isn't skipped.
  ChangeDnsConfig(CreateValidDnsConfig());

  proc_->AddRule("h1", ADDRESS_FAMILY_UNSPECIFIED, "::3");
  proc_->AddRule("h1", ADDRESS_FAMILY_IPV4, "1.0.0.1");
  proc_->AddRule("h1", ADDRESS_FAMILY_IPV4, "1.0.0.1",
                 HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6);
  proc_->AddRule("h1", ADDRESS_FAMILY_IPV6, "::2");

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("h1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::A;
  ResolveHostResponseHelper v4_response(resolver_->CreateRequest(
      HostPortPair("h1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  parameters.dns_query_type = DnsQueryType::AAAA;
  ResolveHostResponseHelper v6_response(resolver_->CreateRequest(
      HostPortPair("h1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));

  proc_->SignalMultiple(3u);

  // Should revert to only IPV4 request.
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("1.0.0.1", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("1.0.0.1", 80))))));

  EXPECT_THAT(v4_response.result_error(), IsOk());
  EXPECT_THAT(v4_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("1.0.0.1", 80)));
  EXPECT_THAT(v4_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("1.0.0.1", 80))))));
  EXPECT_THAT(v6_response.result_error(), IsOk());
  EXPECT_THAT(v6_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::2", 80)));
  EXPECT_THAT(v6_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::2", 80))))));

  // Now repeat the test on non-wifi to check that IPv6 is used as normal
  // after the network changes.
  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_4G);
  base::RunLoop().RunUntilIdle();  // Wait for NetworkChangeNotifier.

  ResolveHostResponseHelper no_wifi_response(resolver_->CreateRequest(
      HostPortPair("h1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  parameters.dns_query_type = DnsQueryType::A;
  ResolveHostResponseHelper no_wifi_v4_response(resolver_->CreateRequest(
      HostPortPair("h1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  parameters.dns_query_type = DnsQueryType::AAAA;
  ResolveHostResponseHelper no_wifi_v6_response(resolver_->CreateRequest(
      HostPortPair("h1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));

  proc_->SignalMultiple(3u);

  // IPV6 should be available.
  EXPECT_THAT(no_wifi_response.result_error(), IsOk());
  EXPECT_THAT(no_wifi_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::3", 80)));
  EXPECT_THAT(no_wifi_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::3", 80))))));

  EXPECT_THAT(no_wifi_v4_response.result_error(), IsOk());
  EXPECT_THAT(no_wifi_v4_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("1.0.0.1", 80)));
  EXPECT_THAT(no_wifi_v4_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("1.0.0.1", 80))))));
  EXPECT_THAT(no_wifi_v6_response.result_error(), IsOk());
  EXPECT_THAT(no_wifi_v6_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::2", 80)));
  EXPECT_THAT(no_wifi_v6_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::2", 80))))));
}

TEST_F(HostResolverManagerDnsTest, NotFoundTtl) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  CreateResolver();
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  // NODATA
  ResolveHostResponseHelper no_data_response(resolver_->CreateRequest(
      HostPortPair("empty", 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_data_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(no_data_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(no_data_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "empty", kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalErrorResult(
          "empty", DnsQueryType::A, HostResolverInternalResult::Source::kDns,
          Optional(base::TimeTicks::Now() + base::Days(1)),
          Optional(base::Time::Now() + base::Days(1)), ERR_NAME_NOT_RESOLVED)));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "empty", kNetworkAnonymizationKey, DnsQueryType::AAAA,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalErrorResult(
          "empty", DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(base::TimeTicks::Now() + base::Days(1)),
          Optional(base::Time::Now() + base::Days(1)), ERR_NAME_NOT_RESOLVED)));

  // NXDOMAIN
  ResolveHostResponseHelper no_domain_response(resolver_->CreateRequest(
      HostPortPair("nodomain", 80), kNetworkAnonymizationKey,
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_domain_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(no_domain_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(no_domain_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "nodomain", kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalErrorResult(
          "nodomain", DnsQueryType::A, HostResolverInternalResult::Source::kDns,
          Optional(base::TimeTicks::Now() + base::Days(1)),
          Optional(base::Time::Now() + base::Days(1)), ERR_NAME_NOT_RESOLVED)));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "nodomain", kNetworkAnonymizationKey, DnsQueryType::AAAA,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalErrorResult(
          "nodomain", DnsQueryType::AAAA,
          HostResolverInternalResult::Source::kDns,
          Optional(base::TimeTicks::Now() + base::Days(1)),
          Optional(base::Time::Now() + base::Days(1)), ERR_NAME_NOT_RESOLVED)));
}

TEST_F(HostResolverManagerDnsTest, NotFoundTtlWithHostCache) {
  base::test::ScopedFeatureList feature_list;
  DisableHostResolverCache(feature_list);

  CreateResolver();
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  // NODATA
  ResolveHostResponseHelper no_data_response(resolver_->CreateRequest(
      HostPortPair("empty", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_data_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(no_data_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(no_data_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  HostCache::Key key("empty", DnsQueryType::UNSPECIFIED, 0,
                     HostResolverSource::ANY, NetworkAnonymizationKey());
  HostCache::EntryStaleness staleness;
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      resolve_context_->host_cache()->Lookup(key, base::TimeTicks::Now(),
                                             false /* ignore_secure */);
  EXPECT_TRUE(!!cache_result);
  EXPECT_TRUE(cache_result->second.has_ttl());
  EXPECT_THAT(cache_result->second.ttl(), base::Seconds(86400));

  // NXDOMAIN
  ResolveHostResponseHelper no_domain_response(resolver_->CreateRequest(
      HostPortPair("nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_domain_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(no_domain_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(no_domain_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  HostCache::Key nxkey("nodomain", DnsQueryType::UNSPECIFIED, 0,
                       HostResolverSource::ANY, NetworkAnonymizationKey());
  cache_result = resolve_context_->host_cache()->Lookup(
      nxkey, base::TimeTicks::Now(), false /* ignore_secure */);
  EXPECT_TRUE(!!cache_result);
  EXPECT_TRUE(cache_result->second.has_ttl());
  EXPECT_THAT(cache_result->second.ttl(), base::Seconds(86400));
}

TEST_F(HostResolverManagerDnsTest, CachedError) {
  proc_->AddRuleForAllFamilies(std::string(),
                               "0.0.0.1");  // Default to failures.
  proc_->SignalMultiple(1u);

  CreateResolver();
  set_allow_fallback_to_systemtask(true);
  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters cache_only_parameters;
  cache_only_parameters.source = HostResolverSource::LOCAL_ONLY;

  // Expect cache initially empty.
  ResolveHostResponseHelper cache_miss_response0(resolver_->CreateRequest(
      HostPortPair("nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), cache_only_parameters, resolve_context_.get()));
  EXPECT_THAT(cache_miss_response0.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_FALSE(cache_miss_response0.request()->GetStaleInfo());

  // The cache should not be populate with an error because fallback to
  // HostResolverSystemTask was available.
  ResolveHostResponseHelper no_domain_response_with_fallback(
      resolver_->CreateRequest(HostPortPair("nodomain", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_domain_response_with_fallback.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));

  // Expect cache still empty.
  ResolveHostResponseHelper cache_miss_response1(resolver_->CreateRequest(
      HostPortPair("nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), cache_only_parameters, resolve_context_.get()));
  EXPECT_THAT(cache_miss_response1.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_FALSE(cache_miss_response1.request()->GetStaleInfo());

  // Disable fallback to systemtask
  set_allow_fallback_to_systemtask(false);

  // Populate cache with an error.
  ResolveHostResponseHelper no_domain_response(resolver_->CreateRequest(
      HostPortPair("nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_domain_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));

  // Expect the error result can be resolved from the cache.
  ResolveHostResponseHelper cache_hit_response(resolver_->CreateRequest(
      HostPortPair("nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), cache_only_parameters, resolve_context_.get()));
  EXPECT_THAT(cache_hit_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_FALSE(cache_hit_response.request()->GetStaleInfo().value().is_stale());
}

TEST_F(HostResolverManagerDnsTest, CachedError_AutomaticMode) {
  CreateResolver();
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  // Switch to automatic mode.
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  HostCache::Key insecure_key =
      HostCache::Key("automatic_nodomain", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  HostCache::Key secure_key =
      HostCache::Key("automatic_nodomain", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  secure_key.secure = true;

  // Expect cache initially empty.
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;
  cache_result = GetCacheHit(secure_key);
  EXPECT_FALSE(!!cache_result);
  cache_result = GetCacheHit(insecure_key);
  EXPECT_FALSE(!!cache_result);

  // Populate both secure and insecure caches with an error.
  ResolveHostResponseHelper no_domain_response(resolver_->CreateRequest(
      HostPortPair("automatic_nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_domain_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));

  // Expect both secure and insecure caches to have the error result.
  cache_result = GetCacheHit(secure_key);
  EXPECT_TRUE(!!cache_result);
  cache_result = GetCacheHit(insecure_key);
  EXPECT_TRUE(!!cache_result);
}

TEST_F(HostResolverManagerDnsTest, CachedError_SecureMode) {
  CreateResolver();
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  // Switch to secure mode.
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  HostCache::Key insecure_key =
      HostCache::Key("automatic_nodomain", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  HostCache::Key secure_key =
      HostCache::Key("automatic_nodomain", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  secure_key.secure = true;

  // Expect cache initially empty.
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;
  cache_result = GetCacheHit(secure_key);
  EXPECT_FALSE(!!cache_result);
  cache_result = GetCacheHit(insecure_key);
  EXPECT_FALSE(!!cache_result);

  // Populate secure cache with an error.
  ResolveHostResponseHelper no_domain_response(resolver_->CreateRequest(
      HostPortPair("automatic_nodomain", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(no_domain_response.result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));

  // Expect only the secure cache to have the error result.
  cache_result = GetCacheHit(secure_key);
  EXPECT_TRUE(!!cache_result);
  cache_result = GetCacheHit(insecure_key);
  EXPECT_FALSE(!!cache_result);
}

// Test that if one of A and AAAA completes successfully and the other fails,
// the failure is not cached.
TEST_F(HostResolverManagerDnsTest, TtlNotSharedBetweenQtypes) {
  CreateResolver();
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_4timeout", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt /* optional_parameters */,
      resolve_context_.get()));

  // Ensure success completes before the timeout result.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_TIMED_OUT));

  // Expect failure not cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest, CanonicalName) {
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "alias", dns_protocol::kTypeA, IPAddress::IPv4Localhost(),
             "canonical", false /* delay */);
  AddDnsRule(&rules, "alias", dns_protocol::kTypeAAAA,
             IPAddress::IPv6Localhost(), "canonical", false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("alias", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      params, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsOk());

  EXPECT_THAT(
      response.request()->GetDnsAliasResults(),
      testing::Pointee(testing::UnorderedElementsAre("canonical", "alias")));
}

TEST_F(HostResolverManagerDnsTest, CanonicalName_PreferV6) {
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "alias", dns_protocol::kTypeA, IPAddress::IPv4Localhost(),
             "wrong", false /* delay */);
  AddDnsRule(&rules, "alias", dns_protocol::kTypeAAAA,
             IPAddress::IPv6Localhost(), "correct", true /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("alias", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      params, resolve_context_.get()));
  ASSERT_FALSE(response.complete());
  base::RunLoop().RunUntilIdle();
  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsOk());

  // GetDnsAliasResults() includes all aliases from all families.
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(
                  testing::UnorderedElementsAre("correct", "alias", "wrong")));
}

TEST_F(HostResolverManagerDnsTest, CanonicalName_V4Only) {
  MockDnsClientRuleList rules;
  AddDnsRule(&rules, "alias", dns_protocol::kTypeA, IPAddress::IPv4Localhost(),
             "correct", false /* delay */);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  HostResolver::ResolveHostParameters params;
  params.dns_query_type = DnsQueryType::A;
  params.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("alias", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      params, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(
      response.request()->GetDnsAliasResults(),
      testing::Pointee(testing::UnorderedElementsAre("correct", "alias")));
}

// Test that responses containing CNAME records but no address results are fine
// and treated as normal NODATA responses.
TEST_F(HostResolverManagerDnsTest, CanonicalNameWithoutResults) {
  MockDnsClientRuleList rules;

  DnsResponse a_response =
      BuildTestDnsResponse("a.test", dns_protocol::kTypeA,
                           {BuildTestCnameRecord("c.test", "d.test"),
                            BuildTestCnameRecord("b.test", "c.test"),
                            BuildTestCnameRecord("a.test", "b.test")});
  AddDnsRule(&rules, "a.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);

  DnsResponse aaaa_response =
      BuildTestDnsResponse("a.test", dns_protocol::kTypeAAAA,
                           {BuildTestCnameRecord("c.test", "d.test"),
                            BuildTestCnameRecord("b.test", "c.test"),
                            BuildTestCnameRecord("a.test", "b.test")});
  AddDnsRule(&rules, "a.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("a.test", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      /*optional_parameters=*/std::nullopt, resolve_context_.get()));

  ASSERT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_FALSE(response.request()->GetDnsAliasResults());

  // Underlying error should be the typical no-results error
  // (ERR_NAME_NOT_RESOLVED), not anything more exotic like
  // ERR_DNS_MALFORMED_RESPONSE.
  EXPECT_EQ(response.request()->GetResolveErrorInfo().error,
            ERR_NAME_NOT_RESOLVED);
}

// Test that if the response for one address family contains CNAME records but
// no address results, it doesn't interfere with the other address family
// receiving address results (as would happen if such a response were
// incorrectly treated as a malformed response error).
TEST_F(HostResolverManagerDnsTest, CanonicalNameWithResultsForOnlyOneFamily) {
  MockDnsClientRuleList rules;

  DnsResponse a_response =
      BuildTestDnsResponse("a.test", dns_protocol::kTypeA,
                           {BuildTestCnameRecord("c.test", "d.test"),
                            BuildTestCnameRecord("b.test", "c.test"),
                            BuildTestCnameRecord("a.test", "b.test")});
  AddDnsRule(&rules, "a.test", dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);

  DnsResponse aaaa_response = BuildTestDnsResponse(
      "a.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("d.test", IPAddress::IPv6Localhost()),
       BuildTestCnameRecord("c.test", "d.test"),
       BuildTestCnameRecord("b.test", "c.test"),
       BuildTestCnameRecord("a.test", "b.test")});
  AddDnsRule(&rules, "a.test", dns_protocol::kTypeAAAA,
             std::move(aaaa_response), /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("a.test", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      /*optional_parameters=*/std::nullopt, resolve_context_.get()));

  ASSERT_THAT(response.result_error(), IsOk());

  ASSERT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
          testing::ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 80))))));
}

// Test that without specifying source, a request that would otherwise be
// handled by DNS is sent to the system resolver if cannonname is requested.
TEST_F(HostResolverManagerDnsTest, CanonicalNameForcesProc) {
  // Disable fallback to ensure system resolver is used directly, not via
  // fallback.
  set_allow_fallback_to_systemtask(false);

  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102",
                               HOST_RESOLVER_CANONNAME, "canonical");
  proc_->SignalMultiple(1u);

  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters params;
  params.include_canonical_name = true;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), params, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsOk());

  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing
"""


```