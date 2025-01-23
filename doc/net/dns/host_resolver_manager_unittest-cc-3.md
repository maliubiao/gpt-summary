Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `net/dns/host_resolver_manager_unittest.cc`. I need to analyze the code and identify the different test cases and what aspects of the `HostResolverManager` they are testing.

Here's a breakdown of the tests I can identify:

1. **`LocalOnly_NoLocalData`**: Tests resolving a hostname with `HostResolverSource::LOCAL_ONLY` when no local data is available.
2. **`LocalOnly_FromHosts`**: Tests resolving a hostname with `HostResolverSource::LOCAL_ONLY` when the hostname is defined in the system's hosts file.
3. **`LocalOnly_FromIpAsync` and `LocalOnly_FromIpSync`**: Tests resolving an IP address with `HostResolverSource::LOCAL_ONLY` both asynchronously and synchronously.
4. **`LocalOnly_InvalidName`**: Tests resolving an invalid hostname with `HostResolverSource::LOCAL_ONLY`.
5. **`LocalOnly_InvalidLocalhost`**: Tests resolving an invalid localhost-like hostname with `HostResolverSource::LOCAL_ONLY`.
6. **`StaleAllowed`**: Tests using the `STALE_ALLOWED` cache policy for a hostname resolved from local data.
7. **`StaleAllowed_NonLocal`**: Tests using the `STALE_ALLOWED` cache policy for a hostname resolved non-locally.
8. **`StaleAllowed_FromIpAsync` and `StaleAllowed_FromIpSync`**: Tests using the `STALE_ALLOWED` cache policy for resolving an IP address both asynchronously and synchronously.
9. **`MultipleAttempts`**: Tests the retry mechanism for DNS resolution when the underlying resolver is slow.
10. **`DefaultMaxRetryAttempts`**: Tests that the default maximum number of retry attempts is correctly applied.
11. **`NameCollisionIcann`**: Tests how the resolver handles hostnames that resolve to the ICANN name collision detection address (127.0.53.53).
12. **`StartIPv6ReachabilityCheck`**: Tests the mechanism for checking IPv6 reachability.
13. **`IncludeCanonicalName`**: Tests resolving a hostname and including its canonical name, verifying cache behavior.
14. **`FixupCanonicalName`**: Tests that the canonical name is fixed up (lowercase) if received in uppercase.
15. **`IncludeCanonicalNameButNotReceived`**: Tests the behavior when `include_canonical_name` is set, but no canonical name is provided by the underlying resolver.
16. **`IncludeCanonicalNameSkipsUrlCanonicalization`**: Tests that canonical name is returned verbatim, without URL canonicalization.
17. **`LoopbackOnly`**: Tests resolving a hostname marked as loopback-only with the `loopback_only` flag.
18. **`IsSpeculative`**: Tests resolving a hostname with the `is_speculative` flag, which should not populate the cache immediately.
19. **`AvoidMulticastResolutionParameter`**: Tests resolving a hostname marked to avoid multicast resolution with the `avoid_multicast_resolution` flag.

Based on this analysis, I can now formulate the summary.
这个代码片段是 `net/dns/host_resolver_manager_unittest.cc` 文件的**第 4 部分**，它主要包含了一系列针对 `HostResolverManager` 中与 **本地解析 (Local Only)** 和 **允许使用陈旧缓存 (Stale Allowed)** 相关的测试用例。 此外，它还包含了一些关于 **重试机制 (Multiple Attempts)**、**默认最大重试次数 (Default Max Retry Attempts)**、**处理 ICANN 域名冲突地址 (Name Collision Icann)**、**启动 IPv6 可达性检查 (StartIPv6ReachabilityCheck)** 以及与 **规范名称 (Canonical Name)** 相关的测试。

**具体功能归纳如下：**

* **本地解析 (Local Only) 功能测试:**
    * 验证当没有本地数据时，`LOCAL_ONLY` 源的解析请求会失败。
    * 验证当主机名在 hosts 文件中时，使用 `LOCAL_ONLY` 源可以成功解析。
    * 验证从 IP 地址进行本地解析（同步和异步）。
    * 验证使用 `LOCAL_ONLY` 源解析无效主机名会失败。
    * 验证使用 `LOCAL_ONLY` 源解析无效的 localhost 形式的主机名会失败。

* **允许使用陈旧缓存 (Stale Allowed) 功能测试:**
    * 验证当缓存过期时，使用 `STALE_ALLOWED` 可以从本地缓存中获取陈旧结果。
    * 验证对于非本地解析，`STALE_ALLOWED` 参数不会影响正常的解析流程，并且没有陈旧信息。
    * 验证从 IP 地址进行陈旧缓存的解析（同步和异步）。

* **重试机制 (Multiple Attempts) 测试:**
    * 模拟 DNS 解析过程耗时过长的情况，测试 `HostResolverManager` 的重试机制是否正常工作。

* **默认最大重试次数 (Default Max Retry Attempts) 测试:**
    * 验证当设置使用默认重试次数时，实际使用的重试次数是否符合预期（通常是 4 次）。

* **处理 ICANN 域名冲突地址 (Name Collision Icann) 测试:**
    * 验证当主机名解析到 127.0.53.53 这个 ICANN 保留地址时，`HostResolverManager` 会返回 `ERR_ICANN_NAME_COLLISION` 错误。
    * 验证直接解析 IP 地址 127.0.53.53 是允许的。

* **启动 IPv6 可达性检查 (StartIPv6ReachabilityCheck) 测试:**
    * 测试启动 IPv6 可达性检查的机制，并验证连续调用会返回相同的结果。

* **规范名称 (Canonical Name) 相关测试:**
    * 验证当 `ResolveHostParameters::include_canonical_name` 设置为 true 时，可以获取到主机的规范名称，并验证缓存行为。
    * 验证如果系统解析器返回的规范名称是大写字母，`HostResolverManager` 会将其转换为小写。
    * 验证当设置了 `include_canonical_name` 但系统解析器没有返回规范名称时的情况。
    * 验证当设置了 `include_canonical_name` 时，返回的规范名称不会进行 URL hostname 的规范化处理。

**与 JavaScript 的功能关系：**

这段 C++ 代码主要测试的是 Chromium 网络栈底层的 DNS 解析功能，与 JavaScript 没有直接的功能对应关系。 然而，JavaScript 中通过浏览器提供的 API（例如 `fetch` 或 `XMLHttpRequest`）发起网络请求时，最终会调用到 Chromium 的网络栈进行 DNS 解析。

**举例说明：**

假设你在 JavaScript 中使用 `fetch` 发起一个请求：

```javascript
fetch('http://just.testing:80')
  .then(response => console.log(response))
  .catch(error => console.error(error));
```

当浏览器执行这段代码时，Chromium 网络栈会尝试解析 `just.testing` 的 IP 地址。  这段 C++ 代码中的某些测试用例，例如 `StaleAllowed` 或 `IncludeCanonicalName`， 间接地影响着 JavaScript 中网络请求的行为：

* **`StaleAllowed`:** 如果 `just.testing` 的 DNS 记录在缓存中已过期，但由于启用了 "允许使用陈旧缓存" 的策略，JavaScript 中的 `fetch` 请求可能会使用缓存中的旧 IP 地址，直到后台完成新的 DNS 解析。
* **`IncludeCanonicalName`:**  虽然 JavaScript 的 `fetch` API 本身不会直接暴露规范名称，但浏览器内部可能会利用规范名称进行一些优化，例如 HTTP/2 的连接重用等。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `LocalOnly_FromIpAsync` 测试):**

* `is_async = true` (表示进行异步测试)
* 调用 `resolver_->CreateRequest` 解析 IP 地址 "1.2.3.4"。
* 假设初始状态下 IPv6 可达性检查正在进行中或尚未完成。

**输出:**

* 第一次 `CreateRequest` 调用会同步完成，返回 `ERR_NAME_NOT_RESOLVED`，因为 `LOCAL_ONLY` 模式下无法直接解析 IP，并且异步的 IPv6 可达性检查尚未完成。
* `GetAddressResults` 和 `GetEndpointResults` 为空。
* 执行 `base::RunLoop().RunUntilIdle()` 等待异步操作完成。
* 第二次 `CreateRequest` 调用会同步完成，返回 `OK`，因为 IPv6 可达性检查已完成。
* `GetAddressResults` 包含 "1.2.3.4:56" 的地址信息。
* `GetEndpointResults` 包含 "1.2.3.4:56" 的 EndpointResult 信息。

**用户或编程常见的使用错误举例说明：**

* **错误使用 `HostResolverSource::LOCAL_ONLY`:** 用户可能会错误地认为 `LOCAL_ONLY` 可以用于解析任何主机名，但实际上它仅限于解析本地 hosts 文件中配置的主机名或 IP 地址。如果尝试使用 `LOCAL_ONLY` 解析一个不在本地配置中的域名，将会导致 `ERR_NAME_NOT_RESOLVED` 错误。
    * **用户操作步骤：** 在 Chrome 浏览器中，用户直接访问一个未在本地 hosts 文件中配置的域名，并且此时系统配置为仅使用本地 DNS 解析。
    * **调试线索：**  开发者在调试网络请求时，可能会看到 `net::ERR_NAME_NOT_RESOLVED` 错误，并且检查 NetLog 后发现请求使用了 `HostResolverSource::LOCAL_ONLY`，但该域名并未在本地配置。

* **错误理解 `STALE_ALLOWED` 的作用:**  用户可能会认为设置 `STALE_ALLOWED` 后，即使 DNS 记录过期很久，也总是会返回缓存结果。但实际上，`STALE_ALLOWED` 只是允许在缓存过期后，在后台进行新解析的同时，先返回旧的缓存结果，以提升用户体验。如果缓存中根本没有记录，或者陈旧记录已经过期太久，仍然会进行正常的 DNS 解析。
    * **用户操作步骤：** 用户首次访问一个网站，然后断开网络并等待一段时间，再次访问该网站。如果缓存中没有该网站的记录或记录已过期很久，即使之前访问过并认为应该可以使用陈旧缓存，仍然会遇到网络错误。
    * **调试线索：** 开发者在调试缓存策略时，可能会观察到尽管设置了 `STALE_ALLOWED`，但某些请求仍然会触发新的 DNS 查询，这可能是因为缓存中没有可用的陈旧记录。

**作为调试线索，用户操作如何一步步到达这里 (以 `LocalOnly_FromHosts` 为例):**

1. **用户修改本地 Hosts 文件:** 用户手动编辑操作系统上的 hosts 文件，将某个域名（例如 `just.testing`）映射到一个 IP 地址（例如 `192.168.1.42`）。
2. **用户在浏览器中输入该域名:** 用户在 Chrome 浏览器的地址栏中输入 `http://just.testing` 并回车。
3. **浏览器发起网络请求:** Chrome 浏览器开始处理该 URL，并需要解析 `just.testing` 的 IP 地址。
4. **HostResolverManager 收到解析请求:**  `HostResolverManager` 接收到解析 `just.testing` 的请求。
5. **根据配置，可能尝试本地解析:**  如果浏览器的 DNS 解析配置允许或优先使用本地 hosts 文件，或者代码中明确指定了 `HostResolverSource::LOCAL_ONLY`，则会尝试从本地 hosts 文件中查找。
6. **`LocalOnly_FromHosts` 测试覆盖此路径:**  `LocalOnly_FromHosts` 测试用例模拟了这种情况，它预先在 `proc_` 中添加了针对 `just.testing` 的 hosts 文件规则，然后发起一个 `LOCAL_ONLY` 的解析请求，验证是否能正确解析到配置的 IP 地址。

总而言之，这段代码主要测试了 `HostResolverManager` 在处理本地解析、陈旧缓存以及一些边缘情况（如重试、ICANN 域名冲突、规范名称等）时的正确性和健壮性，为 Chromium 网络栈的稳定运行提供了保障。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共21部分，请归纳一下它的功能
```

### 源代码
```cpp
ointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(stale_request.request()->GetStaleInfo());
}

void HostResolverManagerTest::LocalOnlyFromIpTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  HostResolver::ResolveHostParameters source_none_parameters;
  source_none_parameters.source = HostResolverSource::LOCAL_ONLY;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("1.2.3.4", 56), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));

  // If IPv6 reachability is asynchronous, the first request will return
  // NAME_NOT_RESOLVED. Do a second request to confirm that it returns OK once
  // reachability check completes.
  if (is_async) {
    // Expected to resolve synchronously.
    EXPECT_TRUE(response.complete());
    EXPECT_EQ(response.result_error(), ERR_NAME_NOT_RESOLVED);
    EXPECT_THAT(response.request()->GetAddressResults(),
                AnyOf(nullptr, Pointee(IsEmpty())));
    EXPECT_THAT(response.request()->GetEndpointResults(),
                AnyOf(nullptr, Pointee(IsEmpty())));
    EXPECT_FALSE(response.request()->GetStaleInfo());
    base::RunLoop().RunUntilIdle();

    ResolveHostResponseHelper response2(resolver_->CreateRequest(
        HostPortPair("1.2.3.4", 56), NetworkAnonymizationKey(),
        NetLogWithSource(), source_none_parameters, resolve_context_.get()));
    EXPECT_TRUE(response2.complete());
    EXPECT_THAT(response2.result_error(), IsOk());
    EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected("1.2.3.4", 56)));
    EXPECT_THAT(response2.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected("1.2.3.4", 56))))));
    EXPECT_FALSE(response2.request()->GetStaleInfo());
  } else {
    // Expected to resolve synchronously.
    EXPECT_TRUE(response.complete());
    EXPECT_THAT(response.result_error(), IsOk());
    EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
                testing::ElementsAre(CreateExpected("1.2.3.4", 56)));
    EXPECT_THAT(response.request()->GetEndpointResults(),
                testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                    testing::ElementsAre(CreateExpected("1.2.3.4", 56))))));
    EXPECT_FALSE(response.request()->GetStaleInfo());
  }
}

TEST_F(HostResolverManagerTest, LocalOnly_FromIpAsync) {
  LocalOnlyFromIpTest(true);
}

TEST_F(HostResolverManagerTest, LocalOnly_FromIpSync) {
  LocalOnlyFromIpTest(false);
}

TEST_F(HostResolverManagerTest, LocalOnly_InvalidName) {
  proc_->AddRuleForAllFamilies("foo,bar.com", "192.168.1.42");

  HostResolver::ResolveHostParameters source_none_parameters;
  source_none_parameters.source = HostResolverSource::LOCAL_ONLY;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("foo,bar.com", 57), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));

  // Expected to fail synchronously.
  EXPECT_TRUE(response.complete());
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}

TEST_F(HostResolverManagerTest, LocalOnly_InvalidLocalhost) {
  HostResolver::ResolveHostParameters source_none_parameters;
  source_none_parameters.source = HostResolverSource::LOCAL_ONLY;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("foo,bar.localhost", 58), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));

  // Expected to fail synchronously.
  EXPECT_TRUE(response.complete());
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}

TEST_F(HostResolverManagerTest, StaleAllowed) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);  // Need only one.

  HostResolver::ResolveHostParameters stale_allowed_parameters;
  stale_allowed_parameters.source = HostResolverSource::LOCAL_ONLY;
  stale_allowed_parameters.cache_usage =
      HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;

  // First query expected to complete synchronously as a cache miss.
  ResolveHostResponseHelper cache_miss_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), stale_allowed_parameters, resolve_context_.get()));
  EXPECT_TRUE(cache_miss_request.complete());
  EXPECT_THAT(cache_miss_request.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(cache_miss_request.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cache_miss_request.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(cache_miss_request.request()->GetStaleInfo());

  // Normal query to populate cache
  ResolveHostResponseHelper normal_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(normal_request.result_error(), IsOk());
  EXPECT_FALSE(normal_request.request()->GetStaleInfo());

  MakeCacheStale();

  // Second NONE query expected to get a stale cache hit.
  ResolveHostResponseHelper stale_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 84), NetworkAnonymizationKey(),
      NetLogWithSource(), stale_allowed_parameters, resolve_context_.get()));
  EXPECT_TRUE(stale_request.complete());
  EXPECT_THAT(stale_request.result_error(), IsOk());
  EXPECT_THAT(stale_request.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 84)));
  EXPECT_THAT(
      stale_request.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 84))))));
  EXPECT_TRUE(stale_request.request()->GetStaleInfo().value().is_stale());
}

TEST_F(HostResolverManagerTest, StaleAllowed_NonLocal) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.2.42");
  proc_->SignalMultiple(1u);  // Need only one.

  HostResolver::ResolveHostParameters stale_allowed_parameters;
  stale_allowed_parameters.cache_usage =
      HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;

  // Normal non-local resolves should still work normally with the STALE_ALLOWED
  // parameter, and there should be no stale info.
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 85), NetworkAnonymizationKey(),
      NetLogWithSource(), stale_allowed_parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.2.42", 85)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.2.42", 85))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}

void HostResolverManagerTest::StaleAllowedFromIpTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  HostResolver::ResolveHostParameters stale_allowed_parameters;
  stale_allowed_parameters.cache_usage =
      HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("1.2.3.4", 57), NetworkAnonymizationKey(),
      NetLogWithSource(), stale_allowed_parameters, resolve_context_.get()));

  if (!is_async) {
    // Expected to resolve synchronously without stale info.
    EXPECT_TRUE(response.complete());
  }
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("1.2.3.4", 57)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("1.2.3.4", 57))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}

TEST_F(HostResolverManagerTest, StaleAllowed_FromIpAsync) {
  StaleAllowedFromIpTest(true);
}

TEST_F(HostResolverManagerTest, StaleAllowed_FromIpSync) {
  StaleAllowedFromIpTest(false);
}

// TODO(mgersh): add a test case for errors with positive TTL after
// https://crbug.com/115051 is fixed.

// Test the retry attempts simulating host resolver proc that takes too long.
TEST_F(HostResolverManagerTest, MultipleAttempts) {
  // Total number of attempts would be 3 and we want the 3rd attempt to resolve
  // the host. First and second attempt will be forced to wait until they get
  // word that a resolution has completed. The 3rd resolution attempt will try
  // to get done ASAP, and won't wait.
  int kAttemptNumberToResolve = 3;
  int kTotalAttempts = 3;

  // Add a little bit of extra fudge to the delay to allow reasonable
  // flexibility for time > vs >= etc.  We don't need to fail the test if we
  // retry at t=6001 instead of t=6000.
  base::TimeDelta kSleepFudgeFactor = base::Milliseconds(1);

  auto resolver_proc = base::MakeRefCounted<LookupAttemptHostResolverProc>(
      nullptr, kAttemptNumberToResolve, kTotalAttempts);

  HostResolverSystemTask::Params params = DefaultParams(resolver_proc);
  base::TimeDelta unresponsive_delay = params.unresponsive_delay;
  int retry_factor = params.retry_factor;

  CreateResolverWithLimitsAndParams(kMaxJobs, params, true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */);

  // Override the current thread task runner, so we can simulate the passage of
  // time and avoid any actual sleeps.
  auto test_task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  base::SingleThreadTaskRunner::CurrentHandleOverrideForTesting
      task_runner_current_default_handle_override(test_task_runner);

  // Resolve "host1".
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host1", 70), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_FALSE(response.complete());

  resolver_proc->WaitForNAttemptsToBeBlocked(1);
  EXPECT_FALSE(response.complete());

  test_task_runner->FastForwardBy(unresponsive_delay + kSleepFudgeFactor);
  resolver_proc->WaitForNAttemptsToBeBlocked(2);
  EXPECT_FALSE(response.complete());

  test_task_runner->FastForwardBy(unresponsive_delay * retry_factor +
                                  kSleepFudgeFactor);

  resolver_proc->WaitForAllAttemptsToFinish();
  test_task_runner->RunUntilIdle();

  // Resolve returns -4 to indicate that 3rd attempt has resolved the host.
  // Since we're using a TestMockTimeTaskRunner, the RunLoop stuff in
  // result_error() will fail if it actually has to wait, but unless there's an
  // error, the result should be immediately ready by this point.
  EXPECT_EQ(-4, response.result_error());

  // We should be done with retries, but make sure none erroneously happen.
  test_task_runner->FastForwardUntilNoTasksRemain();

  EXPECT_EQ(resolver_proc->GetTotalAttemptsResolved(), kTotalAttempts);
}

// Regression test for https://crbug.com/976948.
//
// Tests that when the maximum number of retries is set to
// |HostResolver::ManagerOptions::kDefaultRetryAttempts| the
// number of retries used is 4 rather than something higher.
TEST_F(HostResolverManagerTest, DefaultMaxRetryAttempts) {
  auto test_task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  base::SingleThreadTaskRunner::CurrentHandleOverrideForTesting
      task_runner_current_default_handle_override(test_task_runner);

  // Instantiate a ResolverProc that will block all incoming requests.
  auto resolver_proc = base::MakeRefCounted<LookupAttemptHostResolverProc>(
      nullptr, std::numeric_limits<size_t>::max(),
      std::numeric_limits<size_t>::max());

  // This corresponds to kDefaultMaxRetryAttempts in
  // HostResolverSystemTask::Params::HostResolverSystemTask::Params(). The
  // correspondence is verified below, since that symbol is not exported.
  const size_t expected_max_retries = 4;

  // Use the special value |ManagerOptions::kDefaultRetryAttempts|, which is
  // expected to translate into |expected_num_retries|.
  ASSERT_NE(HostResolverSystemTask::Params::kDefaultRetryAttempts,
            expected_max_retries);
  HostResolverSystemTask::Params params(
      resolver_proc, HostResolverSystemTask::Params::kDefaultRetryAttempts);
  ASSERT_EQ(params.max_retry_attempts, expected_max_retries);

  CreateResolverWithLimitsAndParams(kMaxJobs, params,
                                    false /* ipv6_reachable */,
                                    false /* check_ipv6_on_wifi */);
  // Resolve "host1". The resolver proc will hang all requests so this
  // resolution should remain stalled until calling SetResolvedAttemptNumber().
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host1", 70), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_FALSE(response.complete());

  // Simulate running the main thread (network task runner) for a long
  // time. Because none of the attempts posted to worker pool can complete, this
  // should cause all of the retry attempts to get posted, according to the
  // exponential backoff schedule.
  test_task_runner->FastForwardBy(base::Minutes(20));

  // Unblock the resolver proc, then wait for all the worker pool and main
  // thread tasks to complete. Note that the call to SetResolvedAttemptNumber(1)
  // will cause all the blocked resolver procs tasks fail with -2.
  resolver_proc->SetResolvedAttemptNumber(1);
  const int kExpectedError = -2;
  base::ThreadPoolInstance::Get()->FlushForTesting();
  test_task_runner->RunUntilIdle();

  ASSERT_TRUE(response.complete());
  EXPECT_EQ(kExpectedError, response.result_error());

  // Ensure that the original attempt was executed on the worker pool, as well
  // as the maximum number of allowed retries, and no more.
  EXPECT_EQ(static_cast<int>(expected_max_retries + 1),
            resolver_proc->GetTotalAttemptsResolved());
}

// If a host resolves to a list that includes 127.0.53.53, this is treated as
// an error. 127.0.53.53 is a localhost address, however it has been given a
// special significance by ICANN to help surface name collision resulting from
// the new gTLDs.
TEST_F(HostResolverManagerTest, NameCollisionIcann) {
  proc_->AddRuleForAllFamilies("single", "127.0.53.53");
  proc_->AddRuleForAllFamilies("multiple", "127.0.0.1,127.0.53.53");
  proc_->AddRuleForAllFamilies("ipv6", "::127.0.53.53");
  proc_->AddRuleForAllFamilies("not_reserved1", "53.53.0.127");
  proc_->AddRuleForAllFamilies("not_reserved2", "127.0.53.54");
  proc_->AddRuleForAllFamilies("not_reserved3", "10.0.53.53");
  proc_->SignalMultiple(6u);

  ResolveHostResponseHelper single_response(resolver_->CreateRequest(
      HostPortPair("single", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(single_response.result_error(),
              IsError(ERR_ICANN_NAME_COLLISION));
  EXPECT_THAT(single_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(single_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // ERR_ICANN_NAME_COLLISION is cached like any other error, using a fixed TTL
  // for failed entries from proc-based resolver. That said, the fixed TTL is 0,
  // so it should never be cached.
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(HostCache::Key(
          "single", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
          HostResolverSource::ANY, NetworkAnonymizationKey()));
  EXPECT_FALSE(cache_result);

  ResolveHostResponseHelper multiple_response(resolver_->CreateRequest(
      HostPortPair("multiple", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(multiple_response.result_error(),
              IsError(ERR_ICANN_NAME_COLLISION));

  // Resolving an IP literal of 127.0.53.53 however is allowed.
  ResolveHostResponseHelper literal_response(resolver_->CreateRequest(
      HostPortPair("127.0.53.53", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(literal_response.result_error(), IsOk());

  // Moreover the address should not be recognized when embedded in an IPv6
  // address.
  ResolveHostResponseHelper ipv6_response(resolver_->CreateRequest(
      HostPortPair("127.0.53.53", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(ipv6_response.result_error(), IsOk());

  // Try some other IPs which are similar, but NOT an exact match on
  // 127.0.53.53.
  ResolveHostResponseHelper similar_response1(resolver_->CreateRequest(
      HostPortPair("not_reserved1", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(similar_response1.result_error(), IsOk());

  ResolveHostResponseHelper similar_response2(resolver_->CreateRequest(
      HostPortPair("not_reserved2", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(similar_response2.result_error(), IsOk());

  ResolveHostResponseHelper similar_response3(resolver_->CreateRequest(
      HostPortPair("not_reserved3", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(similar_response3.result_error(), IsOk());
}

TEST_F(HostResolverManagerTest, StartIPv6ReachabilityCheck) {
  // The real HostResolverManager is needed since TestHostResolverManager will
  // bypass the IPv6 reachability tests.
  DestroyResolver();
  resolver_ = std::make_unique<HostResolverManager>(
      DefaultOptions(), nullptr /* system_dns_config_notifier */,
      nullptr /* net_log */);
  // Verify that two consecutive calls return the same value.
  RecordingNetLogObserver net_log_observer;
  NetLogWithSource net_log =
      NetLogWithSource::Make(net::NetLog::Get(), NetLogSourceType::NONE);
  MockClientSocketFactory socket_factory;
  SequencedSocketData sync_connect(MockConnect(SYNCHRONOUS, OK),
                                   base::span<net::MockRead>(),
                                   base::span<net::MockWrite>());
  SequencedSocketData async_connect(MockConnect(ASYNC, OK),
                                    base::span<net::MockRead>(),
                                    base::span<net::MockWrite>());
  socket_factory.AddSocketDataProvider(&sync_connect);
  socket_factory.AddSocketDataProvider(&async_connect);

  int attempt1 = StartIPv6ReachabilityCheck(net_log, &socket_factory,
                                            base::DoNothingAs<void(int)>());
  EXPECT_EQ(attempt1, OK);
  int result1 = GetLastIpv6ProbeResult();

  int attempt2 = StartIPv6ReachabilityCheck(net_log, &socket_factory,
                                            base::DoNothingAs<void(int)>());
  EXPECT_EQ(attempt2, OK);
  int result2 = GetLastIpv6ProbeResult();
  EXPECT_EQ(result1, result2);

  // Verify that async socket connections also return the same value.
  resolver_->ResetIPv6ProbeTimeForTesting();
  TestCompletionCallback callback;
  int attempt3 =
      StartIPv6ReachabilityCheck(net_log, &socket_factory, callback.callback());
  EXPECT_EQ(attempt3, ERR_IO_PENDING);
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  int result3 = GetLastIpv6ProbeResult();
  EXPECT_EQ(result1, result3);

  // Filter reachability check events and verify that there are three of them.
  auto probe_event_list = net_log_observer.GetEntriesWithType(
      NetLogEventType::HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK);
  ASSERT_EQ(3U, probe_event_list.size());
  // Verify that the first and third requests were not cached and the second one
  // was.
  EXPECT_FALSE(GetBooleanValueFromParams(probe_event_list[0], "cached"));
  EXPECT_TRUE(GetBooleanValueFromParams(probe_event_list[1], "cached"));
  EXPECT_FALSE(GetBooleanValueFromParams(probe_event_list[0], "cached"));
}

TEST_F(HostResolverManagerTest, IncludeCanonicalName) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42",
                               HOST_RESOLVER_CANONNAME, "canon.name");
  proc_->SignalMultiple(2u);

  HostResolver::ResolveHostParameters parameters;
  parameters.include_canonical_name = true;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response_no_flag(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::UnorderedElementsAre("canon.name")));

  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "just.testing", NetworkAnonymizationKey(), DnsQueryType::A,
          HostResolverSource::SYSTEM, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          "just.testing", DnsQueryType::A,
          HostResolverInternalResult::Source::kUnknown, _, _, "canon.name")));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "just.testing", NetworkAnonymizationKey(), DnsQueryType::AAAA,
          HostResolverSource::SYSTEM, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          "just.testing", DnsQueryType::AAAA,
          HostResolverInternalResult::Source::kUnknown, _, _, "canon.name")));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "canon.name", NetworkAnonymizationKey(), DnsQueryType::A,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  "canon.name", DnsQueryType::A,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ElementsAre(CreateExpected("192.168.1.42", 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "canon.name", NetworkAnonymizationKey(), DnsQueryType::AAAA,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalErrorResult(
                  "canon.name", DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ERR_NAME_NOT_RESOLVED)));

  EXPECT_THAT(response_no_flag.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverManagerTest, FixupCanonicalName) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42", /*flags=*/0,
                               "CANON.name");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::UnorderedElementsAre("canon.name")));
}

TEST_F(HostResolverManagerTest, IncludeCanonicalNameButNotReceived) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42",
                               HOST_RESOLVER_CANONNAME);
  proc_->SignalMultiple(2u);

  HostResolver::ResolveHostParameters parameters;
  parameters.include_canonical_name = true;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response_no_flag(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));

  EXPECT_THAT(response_no_flag.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

// If `ResolveHostParameters::include_canonical_name` is set, canonical name
// should be returned exactly as received from the system resolver, without any
// attempt to do URL hostname canonicalization on it.
TEST_F(HostResolverManagerTest, IncludeCanonicalNameSkipsUrlCanonicalization) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42",
                               HOST_RESOLVER_CANONNAME, "CANON.name");
  proc_->SignalMultiple(2u);

  HostResolver::ResolveHostParameters parameters;
  parameters.include_canonical_name = true;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response_no_flag(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::UnorderedElementsAre("CANON.name")));

  EXPECT_THAT(response_no_flag.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverManagerTest, LoopbackOnly) {
  proc_->AddRuleForAllFamilies("otherlocal", "127.0.0.1",
                               HOST_RESOLVER_LOOPBACK_ONLY);
  proc_->SignalMultiple(2u);

  HostResolver::ResolveHostParameters parameters;
  parameters.loopback_only = true;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("otherlocal", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response_no_flag(resolver_->CreateRequest(
      HostPortPair("otherlocal", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));

  EXPECT_THAT(response_no_flag.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverManagerTest, IsSpeculative) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);

  HostResolver::ResolveHostParameters parameters;
  parameters.is_speculative = true;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  ASSERT_EQ(1u, proc_->GetCaptureList().size());
  EXPECT_EQ("just.testing", proc_->GetCaptureList()[0].hostname);

  // Reresolve without the |is_speculative| flag should immediately return from
  // cache.
  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(
      response2.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));

  EXPECT_EQ("just.testing", proc_->GetCaptureList()[0].hostname);
  EXPECT_EQ(1u, proc_->GetCaptureList().size());  // No increase.
}

TEST_F(HostResolverManagerTest, AvoidMulticastResolutionParameter) {
  proc_->AddRuleForAllFamilies("avoid.multicast.test", "123.123.123.123",
                               HOST_RESOLVER_AVOID_MULTICAST);
  proc_->SignalMultiple(2u);

  HostResolver::ResolveHostParameters parameters;
  parameters.avoid_multicast_resolution = true;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("avoid.multicast.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response_no_flag(resolver_->CreateRequest(
      HostPortPair("avoid.multicast.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("123.123.123.123", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("123.123.123.123", 80))))));

  EXPECT_THAT(response_no_flag.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

#if BUILDFLAG(ENABLE_MDNS)
const uint8_t kMdnsResponseA[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // "myhello.local."
    0x07, 'm', 'y', 'h', 'e', 'l', 'l', 'o', 0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,

    0x00, 0x01,              // TYPE is A.
    0x00, 0x01,              // CLASS is IN.
```