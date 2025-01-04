Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for Chromium's network stack, specifically focusing on the `HostResolverManager`.

Here's a breakdown of how to arrive at the summary:

1. **Identify the core component being tested:** The `TEST_F(HostResolverManagerTest, ...)` lines clearly indicate that the tests are for the `HostResolverManager`.

2. **Analyze individual test cases:** Go through each `TEST_F` block and understand what aspect of the `HostResolverManager` it's verifying. Look for keywords like "Localhost", "ResolveIPLiteral", "EmptyList", "FailedAsynchronousLookup", "AbortedAsynchronousLookup", "NumericIPv4Address", "NumericIPv6Address", "DeDupeRequests", "CancelMultipleRequests", "CancelWithinCallback", "DeleteWithinCallback", "StartWithinCallback", "BypassCache", etc.

3. **Group related test cases:** Notice patterns and group tests based on the feature they are exercising. For instance, several tests deal with IPv4/IPv6 resolution, others with request cancellation, and some with callbacks.

4. **Synthesize the functionality being tested:** Based on the grouped test cases, deduce the underlying functionality of the `HostResolverManager`. For example, the "Localhost" tests indicate it handles local hostname resolution. The "FailedAsynchronousLookup" tests indicate it deals with error handling.

5. **Look for JavaScript relevance:**  Consider if any tested feature directly relates to how JavaScript in a browser interacts with network requests. Hostname resolution is a fundamental part of making web requests, which are initiated by JavaScript.

6. **Identify logical reasoning and provide examples:**  When a test involves setting up specific conditions (like adding rules to `proc_`) and then asserting the output, that's logical reasoning. Provide the input setup and the expected outcome.

7. **Identify common user/programming errors:** Look for tests that handle invalid input or scenarios that could arise from incorrect usage. Examples include providing empty hostnames or very long hostnames.

8. **Infer user actions leading to these scenarios:** Think about how a user's interaction with a browser could trigger the tested code paths. For instance, typing a URL in the address bar involves hostname resolution.

9. **Consider the "Part 2 of 21" context:** Recognize that this is just a piece of a larger file and the tests likely cover a subset of the `HostResolverManager`'s complete functionality.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:**  Just list each test case's name as a function.
* **Refinement:**  Group related tests to provide a higher-level understanding of the functionality.
* **Initial thought:** Focus solely on the C++ implementation.
* **Refinement:** Consider the broader context of a web browser and how JavaScript interacts with networking components.
* **Initial thought:**  Simply state "handles errors."
* **Refinement:** Provide specific examples of errors tested (e.g., `ERR_NAME_NOT_RESOLVED`).

By following this thought process, we can construct the detailed summary provided in the initial prompt's good answer. The key is to move from specific test cases to a broader understanding of the component's responsibilities.
这是`net/dns/host_resolver_manager_unittest.cc` 文件的一部分，主要集中在测试 `HostResolverManager` 的以下功能：

**核心功能点归纳 (基于提供的代码片段):**

* **本地主机名解析 (Localhost Resolution):**  测试了同步和异步两种模式下，`HostResolverManager` 如何解析 "localhost" 这个特殊的主机名，并返回 IPv4 和 IPv6 地址 (`127.0.0.1` 和 `::1`)。

* **IP 字面量解析 (IP Literal Resolution):**  验证了当输入是 IP 地址字面量时，`HostResolverManager` 如何直接返回该 IP 地址，而不会尝试通过 DNS 解析。即使配置了规则去映射该 IP，IP 字面量解析依然具有最高优先级。

* **解析失败处理 (Failed Resolution):**  测试了当 DNS 解析返回空结果或错误时，`HostResolverManager` 如何处理，并返回 `ERR_NAME_NOT_RESOLVED` 错误。  同时验证了这种失败不会被缓存 (针对系统解析器的失败)。

* **异步解析取消 (Aborted Asynchronous Lookup):**  模拟了在异步 DNS 解析过程中，`HostResolverManager` 被销毁的情况，验证了是否会产生野指针等问题。

* **数字 IP 地址解析 (Numeric IP Address Resolution):**  测试了 `HostResolverManager` 如何解析 IPv4 和 IPv6 的数字地址，包括带端口号的情况，以及 URL 中包含数字 IP 地址的情况。

* **IPv6 可达性检测集成 (IPv6 Reachability Check):**  测试了 `HostResolverManager` 在进行 IPv6 解析时，如何处理 IPv6 的可达性检测，并确保在高并发请求的情况下不会出现数据竞争。

* **无效主机名处理 (Invalid Hostname Handling):**  测试了 `HostResolverManager` 如何处理空字符串、全是点号的字符串以及超长的主机名，并返回 `ERR_NAME_NOT_RESOLVED` 错误。

* **请求去重 (Request De-duplication):**  验证了当有多个相同的域名解析请求时，`HostResolverManager` 是否能够合并这些请求，避免重复的 DNS 查询。

* **请求取消 (Request Cancellation):**  测试了如何取消正在进行的 DNS 解析请求，并验证了取消操作的正确性。

* **取消请求释放资源 (Canceled Requests Release Job Slots):**  验证了取消的请求能够释放占用的资源，使得后续的请求能够正常执行。

* **回调函数中的操作 (Operations Within Callbacks):** 测试了在 DNS 解析完成的回调函数中执行其他操作，例如取消其他请求、销毁 `HostResolverManager` 实例、或者发起新的 DNS 解析请求，并验证了这些操作的安全性。

* **绕过缓存 (Bypass Cache):**  测试了通过设置 `HostResolver::ResolveHostParameters` 可以绕过缓存进行 DNS 查询的功能。

**与 JavaScript 功能的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但 `HostResolverManager` 是 Chromium 网络栈的核心组件，它负责将域名解析为 IP 地址。  这个过程对于 JavaScript 发起的网络请求至关重要。

**举例说明:**

当 JavaScript 代码执行 `fetch('https://www.example.com')` 时，浏览器需要知道 `www.example.com` 的 IP 地址才能建立连接。

1. **用户操作 (JavaScript 发起请求):**  JavaScript 代码调用 `fetch` 或 `XMLHttpRequest` 等 API 发起一个网络请求，目标是 `https://www.example.com`。
2. **浏览器网络栈介入:** 浏览器会将这个请求传递给网络栈。
3. **主机名解析:**  网络栈中的 `HostResolverManager` 会接收到需要解析的主机名 `www.example.com`。
4. **到达 `host_resolver_manager_unittest.cc` 中的逻辑:** 如果此时没有缓存或者需要绕过缓存，`HostResolverManager` 会根据配置和当前网络状态，发起一个 DNS 查询。 上述代码片段中的测试就是验证 `HostResolverManager` 在这个过程中各种情况下的行为，例如：
    * **本地主机名:** 如果请求的是 `localhost`，会执行 `LocalhostIPV4IPV6LookupTest` 中测试的逻辑。
    * **IP 字面量:** 如果请求的是 `https://192.168.1.100`，会执行 `ResolveIPLiteralWithHostResolverSystemOnly` 中测试的逻辑。
    * **解析失败:** 如果 `www.example.com` 不存在，会触发 `FailedAsynchronousLookup` 中测试的错误处理逻辑。
    * **请求取消:**  用户在页面加载过程中点击了停止按钮，可能会导致 JavaScript 发起的请求被取消，这会触发 `CancelMultipleRequests` 或 `CancelWithinCallback` 中测试的逻辑。

**逻辑推理 (假设输入与输出):**

* **假设输入:** `HostPortPair("just.testing", 80)`，并且 `proc_->AddRuleForAllFamilies("just.testing", "192.0.2.1");`
* **预期输出:**  `response.result_error()` 为 `net::OK`，`response.request()->GetAddressResults()->endpoints()` 包含一个 `Endpoint`，其地址为 `192.0.2.1`，端口为 `80`。

* **假设输入:** `HostPortPair("", 80)`
* **预期输出:** `response.result_error()` 为 `net::ERR_NAME_NOT_RESOLVED`。

**用户或编程常见的使用错误:**

* **输入空字符串作为主机名:** 用户或程序员可能错误地传递了一个空字符串作为主机名，例如 `fetch('')`。 `EmptyHost` 测试验证了 `HostResolverManager` 能正确处理这种情况并返回错误。
* **输入过长的主机名:** 程序员可能会因为某种原因生成一个非常长的主机名，例如超过 4096 个字符。 `LongHost` 测试验证了 `HostResolverManager` 能正确处理这种情况。
* **在高并发场景下不当的请求管理:**  程序员可能没有考虑到高并发场景下的资源限制，导致大量的 DNS 解析请求被积压。`DeDupeRequests` 和关于请求取消的测试都与优化请求管理有关。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这是最常见的触发 DNS 解析的场景。
2. **JavaScript 代码发起网络请求:** 网页中的 JavaScript 代码使用 `fetch`、`XMLHttpRequest` 等 API 发起对某个域名的请求。
3. **浏览器尝试建立连接:** 浏览器需要知道目标服务器的 IP 地址才能建立 TCP 连接。
4. **`HostResolverManager` 介入:**  浏览器会调用 `HostResolverManager` 的接口来解析主机名。
5. **单元测试模拟各种情况:**  `host_resolver_manager_unittest.cc` 中的测试会模拟各种用户操作和网络状态，例如：
    * **`LocalhostIPV4IPV6LookupAsync`:** 模拟访问 `http://localhost`。
    * **`ResolveIPLiteralWithHostResolverSystemOnly`:** 模拟访问 `http://178.78.32.1`。
    * **`FailedAsynchronousLookup`:** 模拟访问一个不存在的域名。
    * **`AbortedAsynchronousLookup`:**  模拟在页面加载过程中用户取消了请求。

**总结 (针对第 2 部分):**

这部分代码主要测试了 `HostResolverManager` 在处理基本的域名解析场景时的核心功能，包括本地主机名解析、IP 字面量解析、错误处理、异步请求取消、数字 IP 地址解析以及与 IPv6 可达性检测的集成。同时也覆盖了一些边界情况，例如无效的主机名输入。 这些测试确保了 `HostResolverManager` 能够正确、安全地执行域名解析任务，为浏览器中的网络请求提供基础支持。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共21部分，请归纳一下它的功能

"""
      CreateExpected("::1", 80)));
  EXPECT_THAT(
      v4_unsp_response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

TEST_F(HostResolverManagerTest, LocalhostIPV4IPV6LookupAsync) {
  LocalhostIPV4IPV6LookupTest(true);
}

TEST_F(HostResolverManagerTest, LocalhostIPV4IPV6LookupSync) {
  LocalhostIPV4IPV6LookupTest(false);
}

TEST_F(HostResolverManagerTest, ResolveIPLiteralWithHostResolverSystemOnly) {
  const char kIpLiteral[] = "178.78.32.1";
  // Add a mapping to tell if the resolver proc was called (if it was called,
  // then the result will be the remapped value. Otherwise it will be the IP
  // literal).
  proc_->AddRuleForAllFamilies(kIpLiteral, "183.45.32.1");

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::SYSTEM;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kIpLiteral, 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));

  // IP literal resolution is expected to take precedence over source, so the
  // result is expected to be the input IP, not the result IP from the proc rule
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected(kIpLiteral, 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected(kIpLiteral, 80))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());
}

TEST_F(HostResolverManagerTest, EmptyListMeansNameNotResolved) {
  proc_->AddRuleForAllFamilies("just.testing", "");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(response.request()->GetStaleInfo());

  EXPECT_EQ("just.testing", proc_->GetCaptureList()[0].hostname);
}

TEST_F(HostResolverManagerTest, FailedAsynchronousLookup) {
  proc_->AddRuleForAllFamilies(std::string(),
                               "0.0.0.1");  // Default to failures.
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.top_level_result_error(),
              IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(response.request()->GetStaleInfo());

  EXPECT_EQ("just.testing", proc_->GetCaptureList()[0].hostname);

  // Also test that the error is not cached.
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                                 0 /* host_resolver_flags */,
                                 HostResolverSource::ANY,
                                 NetworkAnonymizationKey()));
  EXPECT_FALSE(cache_result);

  // Expect system resolve failures never cached.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      "just.testing", NetworkAnonymizationKey()));
}

TEST_F(HostResolverManagerTest, AbortedAsynchronousLookup) {
  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response0.complete());
  ASSERT_TRUE(proc_->WaitFor(1u));

  // Resolver is destroyed while job is running on WorkerPool.
  DestroyResolver();

  proc_->SignalAll();

  // To ensure there was no spurious callback, complete with a new resolver.
  CreateResolver();
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  proc_->SignalMultiple(2u);

  EXPECT_THAT(response1.result_error(), IsOk());

  // This request was canceled.
  EXPECT_FALSE(response0.complete());
}

TEST_F(HostResolverManagerTest, NumericIPv4Address) {
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("127.1.2.3", 5555), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.1.2.3", 5555)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::UnorderedElementsAre(CreateExpected("127.1.2.3", 5555))))));
}

TEST_F(HostResolverManagerTest, NumericIPv4AddressWithScheme) {
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, "127.1.2.3", 5555),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.1.2.3", 5555)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::UnorderedElementsAre(CreateExpected("127.1.2.3", 5555))))));
}

void HostResolverManagerTest::NumericIPv6AddressTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  // Resolve a plain IPv6 address.  Don't worry about [brackets], because
  // the caller should have removed them.
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("2001:db8::1", 5555), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("2001:db8::1", 5555)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  ExpectEndpointResult(testing::UnorderedElementsAre(
                      CreateExpected("2001:db8::1", 5555))))));
}

TEST_F(HostResolverManagerTest, NumericIPv6AddressAsync) {
  NumericIPv6AddressTest(true);
}

TEST_F(HostResolverManagerTest, NumericIPv6AddressSync) {
  NumericIPv6AddressTest(false);
}

void HostResolverManagerTest::NumericIPv6AddressWithSchemeTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kFtpScheme, "[2001:db8::1]", 5555),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("2001:db8::1", 5555)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  ExpectEndpointResult(testing::UnorderedElementsAre(
                      CreateExpected("2001:db8::1", 5555))))));
}

TEST_F(HostResolverManagerTest, NumericIPv6AddressWithSchemeAsync) {
  NumericIPv6AddressWithSchemeTest(true);
}

TEST_F(HostResolverManagerTest, NumericIPv6AddressWithSchemeSync) {
  NumericIPv6AddressWithSchemeTest(false);
}

// Regression test for https://crbug.com/1432508.
//
// Tests that if a new request is made while the loop within
// FinishIPv6ReachabilityCheck is still running, and the new request needs to
// wait on a new IPv6 probe to complete, the new request does not try to modify
// the same vector that FinishIPv6ReachabilityCheck is iterating over.
TEST_F(HostResolverManagerTest, AddRequestDuringFinishIPv6ReachabilityCheck) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, true);

  // Reset `last_ipv6_probe_time_` if `reset_ipv6_probe_time` true so a new
  // request kicks off a new reachability probe.
  auto custom_callback_template = base::BindLambdaForTesting(
      [&](bool reset_ipv6_probe_time, const HostPortPair& next_host,
          std::unique_ptr<ResolveHostResponseHelper>* next_response,
          CompletionOnceCallback completion_callback, int error) {
        if (reset_ipv6_probe_time) {
          resolver_->ResetIPv6ProbeTimeForTesting();
        }
        *next_response = std::make_unique<ResolveHostResponseHelper>(
            resolver_->CreateRequest(next_host, NetworkAnonymizationKey(),
                                     NetLogWithSource(), std::nullopt,
                                     resolve_context_.get()));
        std::move(completion_callback).Run(error);
      });

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> next_responses(3);

  ResolveHostResponseHelper response0(
      resolver_->CreateRequest(HostPortPair("2001:db8::1", 5555),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      base::BindOnce(custom_callback_template, true, HostPortPair("zzz", 80),
                     &next_responses[0]));

  // New requests made by response1 and response2 will wait for a new
  // reachability probe to complete.
  ResolveHostResponseHelper response1(
      resolver_->CreateRequest(HostPortPair("2001:db8::1", 5555),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      base::BindOnce(custom_callback_template, false, HostPortPair("aaa", 80),
                     &next_responses[1]));

  ResolveHostResponseHelper response2(
      resolver_->CreateRequest(HostPortPair("2001:db8::1", 5555),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      base::BindOnce(custom_callback_template, false, HostPortPair("eee", 80),
                     &next_responses[2]));

  // Unblock all calls to proc.
  proc_->SignalMultiple(6u);

  // All requests should return OK.
  EXPECT_THAT(response0.result_error(), IsOk());
  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(next_responses[0]->result_error(), IsOk());
  EXPECT_THAT(next_responses[1]->result_error(), IsOk());
  EXPECT_THAT(next_responses[2]->result_error(), IsOk());
}

TEST_F(HostResolverManagerTest, EmptyHost) {
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(std::string(), 5555), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerTest, EmptyDotsHost) {
  for (int i = 0; i < 16; ++i) {
    ResolveHostResponseHelper response(resolver_->CreateRequest(
        HostPortPair(std::string(i, '.'), 5555), NetworkAnonymizationKey(),
        NetLogWithSource(), std::nullopt, resolve_context_.get()));

    EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
    EXPECT_THAT(response.request()->GetAddressResults(),
                AnyOf(nullptr, Pointee(IsEmpty())));
    EXPECT_THAT(response.request()->GetEndpointResults(),
                AnyOf(nullptr, Pointee(IsEmpty())));
  }
}

TEST_F(HostResolverManagerTest, LongHost) {
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(std::string(4097, 'a'), 5555), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerTest, DeDupeRequests) {
  // Start 5 requests, duplicating hosts "a" and "b". Since the resolver_proc is
  // blocked, these should all pile up until we signal it.
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  for (auto& response : responses) {
    ASSERT_FALSE(response->complete());
  }

  proc_->SignalMultiple(2u);  // One for "a:80", one for "b:80".

  for (auto& response : responses) {
    EXPECT_THAT(response->result_error(), IsOk());
  }
}

TEST_F(HostResolverManagerTest, CancelMultipleRequests) {
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  for (auto& response : responses) {
    ASSERT_FALSE(response->complete());
  }

  // Cancel everything except request for requests[3] ("a", 80).
  responses[0]->CancelRequest();
  responses[1]->CancelRequest();
  responses[2]->CancelRequest();
  responses[4]->CancelRequest();

  proc_->SignalMultiple(2u);  // One for "a", one for "b".

  EXPECT_THAT(responses[3]->result_error(), IsOk());

  EXPECT_FALSE(responses[0]->complete());
  EXPECT_FALSE(responses[1]->complete());
  EXPECT_FALSE(responses[2]->complete());
  EXPECT_FALSE(responses[4]->complete());
}

TEST_F(HostResolverManagerTest, CanceledRequestsReleaseJobSlots) {
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;

  // Fill up the dispatcher and queue.
  for (unsigned i = 0; i < kMaxJobs + 1; ++i) {
    std::string hostname = "a_";
    hostname[1] = 'a' + i;

    responses.emplace_back(
        std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
            HostPortPair(hostname, 80), NetworkAnonymizationKey(),
            NetLogWithSource(), std::nullopt, resolve_context_.get())));
    ASSERT_FALSE(responses.back()->complete());

    responses.emplace_back(
        std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
            HostPortPair(hostname, 80), NetworkAnonymizationKey(),
            NetLogWithSource(), std::nullopt, resolve_context_.get())));
    ASSERT_FALSE(responses.back()->complete());
  }

  ASSERT_TRUE(proc_->WaitFor(kMaxJobs));

  // Cancel all but last two.
  for (unsigned i = 0; i < responses.size() - 2; ++i) {
    responses[i]->CancelRequest();
  }

  ASSERT_TRUE(proc_->WaitFor(kMaxJobs + 1));

  proc_->SignalAll();

  size_t num_requests = responses.size();
  EXPECT_THAT(responses[num_requests - 1]->result_error(), IsOk());
  EXPECT_THAT(responses[num_requests - 2]->result_error(), IsOk());
  for (unsigned i = 0; i < num_requests - 2; ++i) {
    EXPECT_FALSE(responses[i]->complete());
  }
}

TEST_F(HostResolverManagerTest, CancelWithinCallback) {
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  auto custom_callback = base::BindLambdaForTesting(
      [&](CompletionOnceCallback completion_callback, int error) {
        for (auto& response : responses) {
          // Cancelling request is required to complete first, so that it can
          // attempt to cancel the others.  This test assumes all jobs are
          // completed in order.
          DCHECK(!response->complete());

          response->CancelRequest();
        }
        std::move(completion_callback).Run(error);
      });

  ResolveHostResponseHelper cancelling_response(
      resolver_->CreateRequest(HostPortPair("a", 80), NetworkAnonymizationKey(),
                               NetLogWithSource(), std::nullopt,
                               resolve_context_.get()),
      std::move(custom_callback));

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  proc_->SignalMultiple(2u);  // One for "a". One for "finalrequest".

  EXPECT_THAT(cancelling_response.result_error(), IsOk());

  ResolveHostResponseHelper final_response(resolver_->CreateRequest(
      HostPortPair("finalrequest", 70), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(final_response.result_error(), IsOk());

  for (auto& response : responses) {
    EXPECT_FALSE(response->complete());
  }
}

TEST_F(HostResolverManagerTest, DeleteWithinCallback) {
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  auto custom_callback = base::BindLambdaForTesting(
      [&](CompletionOnceCallback completion_callback, int error) {
        for (auto& response : responses) {
          // Deleting request is required to be first, so the other requests
          // will still be running to be deleted. This test assumes that the
          // Jobs will be Aborted in order and the requests in order within the
          // jobs.
          DCHECK(!response->complete());
        }

        DestroyResolver();
        std::move(completion_callback).Run(error);
      });

  ResolveHostResponseHelper deleting_response(
      resolver_->CreateRequest(HostPortPair("a", 80), NetworkAnonymizationKey(),
                               NetLogWithSource(), std::nullopt,
                               resolve_context_.get()),
      std::move(custom_callback));

  // Start additional requests to be cancelled as part of the first's deletion.
  // Assumes all requests for a job are handled in order so that the deleting
  // request will run first and cancel the rest.
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  proc_->SignalMultiple(3u);

  EXPECT_THAT(deleting_response.result_error(), IsOk());

  base::RunLoop().RunUntilIdle();
  for (auto& response : responses) {
    EXPECT_FALSE(response->complete());
  }
}

TEST_F(HostResolverManagerTest, DeleteWithinAbortedCallback) {
  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  ResolveHostResponseHelper::Callback custom_callback =
      base::BindLambdaForTesting(
          [&](CompletionOnceCallback completion_callback, int error) {
            for (auto& response : responses) {
              // Deleting request is required to be first, so the other requests
              // will still be running to be deleted. This test assumes that the
              // Jobs will be Aborted in order and the requests in order within
              // the jobs.
              DCHECK(!response->complete());
            }
            DestroyResolver();
            std::move(completion_callback).Run(error);
          });

  ResolveHostResponseHelper deleting_response(
      resolver_->CreateRequest(HostPortPair("a", 80), NetworkAnonymizationKey(),
                               NetLogWithSource(), std::nullopt,
                               resolve_context_.get()),
      std::move(custom_callback));

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 82), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("b", 82), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  // Wait for all calls to queue up, trigger abort via IP address change, then
  // signal all the queued requests to let them all try to finish.
  EXPECT_TRUE(proc_->WaitFor(2u));
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  proc_->SignalAll();

  EXPECT_THAT(deleting_response.result_error(), IsError(ERR_NETWORK_CHANGED));
  base::RunLoop().RunUntilIdle();
  for (auto& response : responses) {
    EXPECT_FALSE(response->complete());
  }
}

TEST_F(HostResolverManagerTest, StartWithinCallback) {
  std::unique_ptr<ResolveHostResponseHelper> new_response;
  auto custom_callback = base::BindLambdaForTesting(
      [&](CompletionOnceCallback completion_callback, int error) {
        new_response = std::make_unique<ResolveHostResponseHelper>(
            resolver_->CreateRequest(
                HostPortPair("new", 70), NetworkAnonymizationKey(),
                NetLogWithSource(), std::nullopt, resolve_context_.get()));
        std::move(completion_callback).Run(error);
      });

  ResolveHostResponseHelper starting_response(
      resolver_->CreateRequest(HostPortPair("a", 80), NetworkAnonymizationKey(),
                               NetLogWithSource(), std::nullopt,
                               resolve_context_.get()),
      std::move(custom_callback));

  proc_->SignalMultiple(2u);  // One for "a". One for "new".

  EXPECT_THAT(starting_response.result_error(), IsOk());
  EXPECT_THAT(new_response->result_error(), IsOk());
}

TEST_F(HostResolverManagerTest, StartWithinEvictionCallback) {
  CreateSerialResolver();
  resolver_->SetMaxQueuedJobsForTesting(2);

  std::unique_ptr<ResolveHostResponseHelper> new_response;
  auto custom_callback = base::BindLambdaForTesting(
      [&](CompletionOnceCallback completion_callback, int error) {
        new_response = std::make_unique<ResolveHostResponseHelper>(
            resolver_->CreateRequest(
                HostPortPair("new", 70), NetworkAnonymizationKey(),
                NetLogWithSource(), std::nullopt, resolve_context_.get()));
        std::move(completion_callback).Run(error);
      });

  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("initial", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper evictee1_response(
      resolver_->CreateRequest(HostPortPair("evictee1", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      std::move(custom_callback));
  ResolveHostResponseHelper evictee2_response(resolver_->CreateRequest(
      HostPortPair("evictee2", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  // Now one running request ("initial") and two queued requests ("evictee1" and
  // "evictee2"). Any further requests will cause evictions.
  ResolveHostResponseHelper evictor_response(resolver_->CreateRequest(
      HostPortPair("evictor", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(evictee1_response.result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));

  // "new" should evict "evictee2"
  EXPECT_THAT(evictee2_response.result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));

  proc_->SignalMultiple(3u);

  EXPECT_THAT(initial_response.result_error(), IsOk());
  EXPECT_THAT(evictor_response.result_error(), IsOk());
  EXPECT_THAT(new_response->result_error(), IsOk());
}

// Test where we start a new request within an eviction callback that itself
// evicts the first evictor.
TEST_F(HostResolverManagerTest, StartWithinEvictionCallback_DoubleEviction) {
  CreateSerialResolver();
  resolver_->SetMaxQueuedJobsForTesting(1);

  std::unique_ptr<ResolveHostResponseHelper> new_response;
  auto custom_callback = base::BindLambdaForTesting(
      [&](CompletionOnceCallback completion_callback, int error) {
        new_response = std::make_unique<ResolveHostResponseHelper>(
            resolver_->CreateRequest(
                HostPortPair("new", 70), NetworkAnonymizationKey(),
                NetLogWithSource(), std::nullopt, resolve_context_.get()));
        std::move(completion_callback).Run(error);
      });

  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("initial", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper evictee_response(
      resolver_->CreateRequest(HostPortPair("evictee", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      std::move(custom_callback));

  // Now one running request ("initial") and one queued requests ("evictee").
  // Any further requests will cause evictions.
  ResolveHostResponseHelper evictor_response(resolver_->CreateRequest(
      HostPortPair("evictor", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(evictee_response.result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));

  // "new" should evict "evictor"
  EXPECT_THAT(evictor_response.result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));

  proc_->SignalMultiple(2u);

  EXPECT_THAT(initial_response.result_error(), IsOk());
  EXPECT_THAT(new_response->result_error(), IsOk());
}

TEST_F(HostResolverManagerTest, StartWithinEvictionCallback_SameRequest) {
  CreateSerialResolver();
  resolver_->SetMaxQueuedJobsForTesting(2);

  std::unique_ptr<ResolveHostResponseHelper> new_response;
  auto custom_callback = base::BindLambdaForTesting(
      [&](CompletionOnceCallback completion_callback, int error) {
        new_response = std::make_unique<ResolveHostResponseHelper>(
            resolver_->CreateRequest(
                HostPortPair("evictor", 80), NetworkAnonymizationKey(),
                NetLogWithSource(), std::nullopt, resolve_context_.get()));
        std::move(completion_callback).Run(error);
      });

  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("initial", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper evictee_response(
      resolver_->CreateRequest(HostPortPair("evictee", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      std::move(custom_callback));
  ResolveHostResponseHelper additional_response(resolver_->CreateRequest(
      HostPortPair("additional", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  // Now one running request ("initial") and two queued requests ("evictee" and
  // "additional"). Any further requests will cause evictions.
  ResolveHostResponseHelper evictor_response(resolver_->CreateRequest(
      HostPortPair("evictor", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(evictee_response.result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));

  // Second "evictor" should be joined with the first and not evict "additional"

  // Only 3 proc requests because both "evictor" requests are combined.
  proc_->SignalMultiple(3u);

  EXPECT_THAT(initial_response.result_error(), IsOk());
  EXPECT_THAT(additional_response.result_error(), IsOk());
  EXPECT_THAT(evictor_response.result_error(), IsOk());
  EXPECT_THAT(new_response->result_error(), IsOk());
}

TEST_F(HostResolverManagerTest, BypassCache) {
  proc_->SignalMultiple(2u);

  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(initial_response.result_error(), IsOk());
  EXPECT_EQ(1u, proc_->GetCaptureList().size());

  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsOk());
  // Expect no increase to calls to |proc_| because result was cached.
  EXPECT_EQ(1u, proc_->GetCaptureList().size());

  HostResolver::ResolveHostParameters parameters;
  parameters.cache_usage =
      HostResolver::ResolveHostParameters::CacheUsage::DISALLOWED;
  ResolveHostResponseHelper cache_bypassed_response(resolver_->CreateRequest(
      HostPortPair("a", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(cache_bypassed_response.result_error(), IsOk());
  // Expect c
"""


```