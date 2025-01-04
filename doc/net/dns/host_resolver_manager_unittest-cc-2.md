Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. The code is a unit test file for the `HostResolverManager`. I need to analyze the test cases and explain what aspects of the `HostResolverManager` they are testing.

Here's a breakdown of the tasks:

1. **Identify the core functionality being tested:** Look for patterns in the test case names and the assertions being made.
2. **Explain the functionality:**  Describe what each test case aims to verify about the `HostResolverManager`.
3. **Relate to JavaScript (if applicable):**  Consider if any of the tested functionalities have direct or indirect counterparts in web browser behavior triggered by JavaScript (e.g., DNS resolution initiated by `fetch` or `XMLHttpRequest`).
4. **Provide logical inference examples:** For tests involving specific inputs and outputs, create simplified examples to illustrate the behavior.
5. **Highlight common usage errors:**  Think about how a developer might misuse the `HostResolverManager` based on the test scenarios.
6. **Explain user interaction:** Describe the sequence of user actions that could lead to the tested code being executed in the browser.
7. **Summarize the overall functionality:** Condense the findings into a concise description of the code's purpose.

Let's analyze each test case in the provided snippet:

- `FlushCacheOnIPAddressChangeTest`: Tests that the DNS cache is flushed when the IP address of the network interface changes.
- `AbortOnIPAddressChangedTest`: Tests that pending DNS resolution requests are aborted with `ERR_NETWORK_CHANGED` when the IP address changes.
- `ObeyPoolConstraintsAfterIPAddressChange`: Tests that the `HostResolverManager` continues to respect the maximum number of concurrent resolution jobs after an IP address change.
- `AbortOnlyExistingRequestsOnIPAddressChangeTest`: Tests that only the DNS requests active during an IP address change are aborted, and new requests initiated in their callbacks are not.
- `HigherPriorityRequestsStartedFirst`: Tests that DNS requests are processed based on their priority when the number of concurrent jobs is limited.
- `ChangePriorityTest`: Tests the functionality of dynamically changing the priority of a pending DNS resolution request.
- `CancelPendingRequest`: Tests the ability to cancel a DNS resolution request that hasn't started yet.
- `QueueOverflow`: Tests the behavior of the `HostResolverManager` when the queue of pending requests exceeds the maximum limit, leading to older requests being aborted.
- `QueueOverflow_SelfEvict`: Tests a scenario where setting the maximum queue size to 0 immediately evicts newly added requests.
- `AddressFamilyWithRawIPs`: Tests how the `HostResolverManager` handles DNS query types when resolving raw IP addresses.
- `LocalOnly_FromCache`: Tests that `HostResolverSource::LOCAL_ONLY` resolves from the cache and misses if the entry is not present.
- `LocalOnly_StaleEntry`: Tests that `HostResolverSource::LOCAL_ONLY` misses even if a stale entry exists in the cache.

Now, I can proceed with generating the detailed explanation.
这是`net/dns/host_resolver_manager_unittest.cc`文件的第3部分，主要测试了`HostResolverManager`在网络状态变化（主要是IP地址变化）时的行为，以及请求的优先级、取消和队列管理。以下是该部分代码功能的详细解释：

**功能归纳:**

这部分代码主要测试了 `HostResolverManager` 如何处理以下场景：

* **IP 地址变化时的缓存刷新和请求中止:**  验证当设备 IP 地址发生变化时，DNS 缓存会被正确刷新，并且正在进行的 DNS 解析请求会被中止。
* **IP 地址变化后遵守连接池约束:** 确保在 IP 地址变化后，`HostResolverManager` 仍然遵循配置的并发请求限制。
* **仅中止现有请求:** 确认当 IP 地址变化时，只有当时正在进行的 DNS 请求会被中止，而在中止请求的回调中发起的新的 DNS 请求不会被中止。
* **根据优先级处理请求:**  测试在限制并发请求数量的情况下，`HostResolverManager` 是否按照请求的优先级顺序处理 DNS 解析请求。
* **动态修改请求优先级:** 验证可以动态地修改尚未开始的 DNS 解析请求的优先级，并影响其执行顺序。
* **取消待处理请求:**  测试取消尚未开始执行的 DNS 解析请求的功能。
* **请求队列溢出:**  验证当待处理的 DNS 请求数量超过设定的最大值时，`HostResolverManager` 如何处理（通常是丢弃优先级较低的请求）。
* **自驱逐队列溢出:** 测试将最大队列大小设置为 0 时，新加入的请求会被立即拒绝的情况。
* **处理原始 IP 地址和地址族:** 确认当请求解析的是原始 IP 地址时，`HostResolverManager` 如何处理指定的 DNS 查询类型（例如，仅查询 A 记录或 AAAA 记录）。
* **本地缓存查询 (LOCAL_ONLY):** 测试 `HostResolverSource::LOCAL_ONLY` 选项，该选项仅从本地缓存查询 DNS 记录。

**与 JavaScript 功能的关系:**

虽然这段 C++ 代码本身不直接涉及 JavaScript，但它所测试的功能与 Web 浏览器中 JavaScript 发起的网络请求息息相关。当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，浏览器需要将主机名解析为 IP 地址。`HostResolverManager` 就负责处理这个解析过程。

* **IP 地址变化:** 当用户连接到新的 Wi-Fi 网络或移动网络切换时，设备的 IP 地址可能会发生变化。这会导致浏览器中的 DNS 缓存被刷新，重新解析域名，这与 `FlushCacheOnIPAddressChangeTest` 和 `AbortOnIPAddressChangedTest` 测试的场景相关。
* **请求优先级:** 虽然 JavaScript 的 `fetch` API 没有直接暴露设置 DNS 请求优先级的接口，但浏览器内部可能会根据请求的类型或其他因素赋予不同的优先级。`HigherPriorityRequestsStartedFirst` 和 `ChangePriorityTest` 模拟了这种内部优先级管理。
* **取消请求:**  `fetch` API 提供了 `AbortController` 接口，可以用来取消正在进行的网络请求。在底层，`HostResolverManager` 可能会收到取消 DNS 解析请求的通知，这与 `CancelPendingRequest` 测试的场景相关。
* **缓存:** 浏览器会缓存 DNS 解析结果以提高性能。`LocalOnly_FromCache` 测试了仅从缓存获取 DNS 记录的场景，这与浏览器避免进行网络 DNS 查询的行为一致。

**逻辑推理（假设输入与输出）:**

**示例 1: `FlushCacheOnIPAddressChangeTest`**

* **假设输入:**
    1. `HostResolverManager` 启动并缓存了 "host1:70" 的解析结果。
    2. 系统 IP 地址发生变化。
    3. 发起对 "host1:80" 的解析请求。
* **预期输出:**
    1. 第二次对 "host1" 的解析不会命中缓存，需要进行实际的 DNS 查询。
    2. `proc_->GetCaptureList().size()` 会增加，表明进行了新的 DNS 查询。

**示例 2: `AbortOnIPAddressChangedTest`**

* **假设输入:**
    1. 发起对 "host1:70" 的异步 DNS 解析请求，但请求尚未完成（被 `proc_->WaitFor(1u)` 阻塞）。
    2. 系统 IP 地址发生变化。
* **预期输出:**
    1. 之前未完成的请求会以 `ERR_NETWORK_CHANGED` 错误中止。
    2. 请求的结果为空。

**示例 3: `HigherPriorityRequestsStartedFirst`**

* **假设输入:**
    1. 创建了一个串行 `HostResolverManager` (一次只能处理一个请求)。
    2. 按顺序发起多个 DNS 解析请求，其中 "req4" 和 "req5" 的优先级最高。
* **预期输出:**
    1. 请求会按照优先级顺序开始执行（"req0" 先开始因为没有其他正在运行的请求，然后是 "req4", "req5", "req1", "req2", "req3", "req6"）。
    2. `proc_->GetCaptureList()` 会记录请求的执行顺序。

**用户或编程常见的使用错误:**

* **不理解 IP 地址变化的影响:** 开发者可能会假设 DNS 解析结果是永久有效的，而忽略了 IP 地址变化会导致缓存失效，需要重新解析。这可能导致在网络环境变化后，应用程序仍然使用过时的 IP 地址，导致连接失败。
* **过度依赖缓存:**  开发者可能会过度依赖 DNS 缓存来提高性能，而没有考虑到缓存过期或 IP 地址变化的情况，导致应用程序在某些情况下无法连接到服务器。
* **没有处理 `ERR_NETWORK_CHANGED` 错误:** 当 IP 地址变化时，正在进行的 DNS 解析请求会被中止并返回 `ERR_NETWORK_CHANGED` 错误。如果应用程序没有正确处理这个错误，可能会导致崩溃或功能异常。
* **错误地设置请求优先级:**  如果开发者错误地设置了 DNS 解析请求的优先级，可能会导致重要的请求被延迟处理，影响应用程序的性能和用户体验。
* **在高并发场景下没有限制请求数量:** 如果应用程序在高并发场景下发起大量的 DNS 解析请求，可能会超出 `HostResolverManager` 的处理能力，导致队列溢出和请求被丢弃。

**用户操作如何一步步到达这里（调试线索）:**

1. **用户在浏览器地址栏输入一个网址 (例如 `www.example.com`) 或点击一个链接。**
2. **浏览器解析 URL，提取主机名 (`www.example.com`)。**
3. **浏览器检查本地 DNS 缓存，看是否已经解析过该主机名。**
4. **如果缓存未命中或缓存已过期，浏览器会调用 `HostResolverManager` 来解析主机名。**
5. **`HostResolverManager` 创建一个 DNS 解析请求。**
6. **如果此时用户正在连接到新的网络，或者设备的 IP 地址发生了变化（例如，从 Wi-Fi 切换到移动网络），`NetworkChangeNotifier` 会发出通知。**
7. **`HostResolverManager` 接收到 IP 地址变化的通知。**
8. **根据 `FlushCacheOnIPAddressChangeTest` 和 `AbortOnIPAddressChangedTest` 中测试的逻辑，`HostResolverManager` 会刷新 DNS 缓存，并中止正在进行的 DNS 解析请求。**
9. **如果用户同时发起了多个网络请求，`HostResolverManager` 会根据请求的优先级和并发限制来调度这些请求，如 `HigherPriorityRequestsStartedFirst` 和 `QueueOverflow` 测试所示。**
10. **如果用户在请求完成之前导航到其他页面或关闭选项卡，浏览器可能会取消正在进行的 DNS 解析请求，这与 `CancelPendingRequest` 测试的场景相关。**

**总结这部分代码的功能:**

总而言之，这部分测试代码主要关注 `HostResolverManager` 在动态网络环境下的健壮性和正确性。它验证了当网络状态发生变化（尤其是 IP 地址变化）时，`HostResolverManager` 能够正确地管理 DNS 缓存和请求，并且能够根据请求的优先级和系统资源限制来有效地处理 DNS 解析任务。这些测试确保了 Chromium 网络栈在各种网络条件下都能稳定可靠地工作，为用户提供流畅的网络浏览体验。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共21部分，请归纳一下它的功能

"""
all to |proc_| because cache was bypassed.
  EXPECT_EQ(2u, proc_->GetCaptureList().size());
}

void HostResolverManagerTest::FlushCacheOnIPAddressChangeTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  proc_->SignalMultiple(2u);  // One before the flush, one after.

  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("host1", 70), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(initial_response.result_error(), IsOk());
  EXPECT_EQ(1u, proc_->GetCaptureList().size());

  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("host1", 75), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsOk());
  EXPECT_EQ(1u, proc_->GetCaptureList().size());  // No expected increase.

  // Flush cache by triggering an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.

  // Resolve "host1" again -- this time it won't be served from cache, so it
  // will complete asynchronously.
  ResolveHostResponseHelper flushed_response(resolver_->CreateRequest(
      HostPortPair("host1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(flushed_response.result_error(), IsOk());
  EXPECT_EQ(2u, proc_->GetCaptureList().size());  // Expected increase.
}

// Test that IP address changes flush the cache but initial DNS config reads
// do not.
TEST_F(HostResolverManagerTest, FlushCacheOnIPAddressChangeAsync) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);
  FlushCacheOnIPAddressChangeTest(true);
}
TEST_F(HostResolverManagerTest, FlushCacheOnIPAddressChangeSync) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);
  FlushCacheOnIPAddressChangeTest(false);
}

void HostResolverManagerTest::AbortOnIPAddressChangedTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host1", 70), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));

  ASSERT_FALSE(response.complete());
  if (is_async) {
    base::RunLoop().RunUntilIdle();
  }
  ASSERT_TRUE(proc_->WaitFor(1u));

  // Triggering an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.
  proc_->SignalAll();

  EXPECT_THAT(response.result_error(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_EQ(0u, resolve_context_->host_cache()->size());
}

// Test that IP address changes send ERR_NETWORK_CHANGED to pending requests.
TEST_F(HostResolverManagerTest, AbortOnIPAddressChangedAsync) {
  AbortOnIPAddressChangedTest(true);
}
TEST_F(HostResolverManagerTest, AbortOnIPAddressChangedSync) {
  AbortOnIPAddressChangedTest(false);
}

// Obey pool constraints after IP address has changed.
TEST_F(HostResolverManagerTest, ObeyPoolConstraintsAfterIPAddressChange) {
  // Runs at most one job at a time.
  CreateSerialResolver();

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
          HostPortPair("c", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));

  for (auto& response : responses) {
    ASSERT_FALSE(response->complete());
  }
  ASSERT_TRUE(proc_->WaitFor(1u));

  // Triggering an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.
  proc_->SignalMultiple(3u);  // Let the false-start go so that we can catch it.

  // Requests should complete one at a time, with the first failing.
  EXPECT_THAT(responses[0]->result_error(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_EQ(1u, num_running_dispatcher_jobs());
  EXPECT_FALSE(responses[1]->complete());
  EXPECT_FALSE(responses[2]->complete());

  EXPECT_THAT(responses[1]->result_error(), IsOk());
  EXPECT_EQ(1u, num_running_dispatcher_jobs());
  EXPECT_FALSE(responses[2]->complete());

  EXPECT_THAT(responses[2]->result_error(), IsOk());
}

void HostResolverManagerTest::AbortOnlyExistingRequestsOnIPAddressChangeTest(
    bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  auto custom_callback_template = base::BindLambdaForTesting(
      [&](const HostPortPair& next_host,
          std::unique_ptr<ResolveHostResponseHelper>* next_response,
          CompletionOnceCallback completion_callback, int error) {
        *next_response = std::make_unique<ResolveHostResponseHelper>(
            resolver_->CreateRequest(next_host, NetworkAnonymizationKey(),
                                     NetLogWithSource(), std::nullopt,
                                     resolve_context_.get()));
        std::move(completion_callback).Run(error);
      });

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> next_responses(3);

  ResolveHostResponseHelper response0(
      resolver_->CreateRequest(HostPortPair("bbb", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      base::BindOnce(custom_callback_template, HostPortPair("zzz", 80),
                     &next_responses[0]));

  ResolveHostResponseHelper response1(
      resolver_->CreateRequest(HostPortPair("eee", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      base::BindOnce(custom_callback_template, HostPortPair("aaa", 80),
                     &next_responses[1]));

  ResolveHostResponseHelper response2(
      resolver_->CreateRequest(HostPortPair("ccc", 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()),
      base::BindOnce(custom_callback_template, HostPortPair("eee", 80),
                     &next_responses[2]));

  if (is_async) {
    base::RunLoop().RunUntilIdle();
  }
  // Wait until all are blocked;
  ASSERT_TRUE(proc_->WaitFor(3u));

  // Trigger an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  // This should abort all running jobs.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(response0.result_error(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_THAT(response1.result_error(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_THAT(response2.result_error(), IsError(ERR_NETWORK_CHANGED));

  EXPECT_FALSE(next_responses[0]->complete());
  EXPECT_FALSE(next_responses[1]->complete());
  EXPECT_FALSE(next_responses[2]->complete());

  // Unblock all calls to proc.
  proc_->SignalMultiple(6u);

  // Run until the re-started requests finish.
  EXPECT_THAT(next_responses[0]->result_error(), IsOk());
  EXPECT_THAT(next_responses[1]->result_error(), IsOk());
  EXPECT_THAT(next_responses[2]->result_error(), IsOk());

  // Verify that results of aborted Jobs were not cached.
  EXPECT_EQ(6u, proc_->GetCaptureList().size());
  EXPECT_EQ(3u, resolve_context_->host_cache()->size());
}
// Tests that a new Request made from the callback of a previously aborted one
// will not be aborted.
TEST_F(HostResolverManagerTest,
       AbortOnlyExistingRequestsOnIPAddressChangeAsync) {
  AbortOnlyExistingRequestsOnIPAddressChangeTest(true);
}
TEST_F(HostResolverManagerTest,
       AbortOnlyExistingRequestsOnIPAddressChangeSync) {
  AbortOnlyExistingRequestsOnIPAddressChangeTest(false);
}

// Tests that when the maximum threads is set to 1, requests are dequeued
// in order of priority.
TEST_F(HostResolverManagerTest, HigherPriorityRequestsStartedFirst) {
  CreateSerialResolver();

  HostResolver::ResolveHostParameters low_priority;
  low_priority.initial_priority = LOW;
  HostResolver::ResolveHostParameters medium_priority;
  medium_priority.initial_priority = MEDIUM;
  HostResolver::ResolveHostParameters highest_priority;
  highest_priority.initial_priority = HIGHEST;

  // Note that at this point the MockHostResolverProc is blocked, so any
  // requests we make will not complete.

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req0", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req1", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req2", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req3", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req4", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), highest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req5", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req6", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req5", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), highest_priority, resolve_context_.get())));

  for (const auto& response : responses) {
    ASSERT_FALSE(response->complete());
  }

  // Unblock the resolver thread so the requests can run.
  proc_->SignalMultiple(responses.size());  // More than needed.

  // Wait for all the requests to complete successfully.
  for (auto& response : responses) {
    EXPECT_THAT(response->result_error(), IsOk());
  }

  // Since we have restricted to a single concurrent thread in the jobpool,
  // the requests should complete in order of priority (with the exception
  // of the first request, which gets started right away, since there is
  // nothing outstanding).
  MockHostResolverProc::CaptureList capture_list = proc_->GetCaptureList();
  ASSERT_EQ(7u, capture_list.size());

  EXPECT_EQ("req0", capture_list[0].hostname);
  EXPECT_EQ("req4", capture_list[1].hostname);
  EXPECT_EQ("req5", capture_list[2].hostname);
  EXPECT_EQ("req1", capture_list[3].hostname);
  EXPECT_EQ("req2", capture_list[4].hostname);
  EXPECT_EQ("req3", capture_list[5].hostname);
  EXPECT_EQ("req6", capture_list[6].hostname);
}

void HostResolverManagerTest::ChangePriorityTest(bool is_async) {
  CreateSerialResolver(true /* check_ipv6_on_wifi */, true /* ipv6_reachable */,
                       is_async);

  HostResolver::ResolveHostParameters lowest_priority;
  lowest_priority.initial_priority = LOWEST;
  HostResolver::ResolveHostParameters low_priority;
  low_priority.initial_priority = LOW;
  HostResolver::ResolveHostParameters medium_priority;
  medium_priority.initial_priority = MEDIUM;

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req0", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req1", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req2", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), lowest_priority, resolve_context_.get())));

  // req0 starts immediately; without ChangePriority, req1 and then req2 should
  // run.
  for (const auto& response : responses) {
    ASSERT_FALSE(response->complete());
  }

  // Changing req2 to HIGHEST should make it run before req1.
  // (It can't run before req0, since req0 started immediately.)
  responses[2]->request()->ChangeRequestPriority(HIGHEST);

  // Let all 3 requests finish.
  proc_->SignalMultiple(3u);

  for (auto& response : responses) {
    EXPECT_THAT(response->result_error(), IsOk());
  }

  MockHostResolverProc::CaptureList capture_list = proc_->GetCaptureList();
  ASSERT_EQ(3u, capture_list.size());

  EXPECT_EQ("req0", capture_list[0].hostname);
  EXPECT_EQ("req2", capture_list[1].hostname);
  EXPECT_EQ("req1", capture_list[2].hostname);
}

// Test that changing a job's priority affects the dequeueing order.
TEST_F(HostResolverManagerTest, ChangePriorityAsync) {
  ChangePriorityTest(true);
}

TEST_F(HostResolverManagerTest, ChangePrioritySync) {
  ChangePriorityTest(false);
}

// Try cancelling a job which has not started yet.
TEST_F(HostResolverManagerTest, CancelPendingRequest) {
  CreateSerialResolver();

  HostResolver::ResolveHostParameters lowest_priority;
  lowest_priority.initial_priority = LOWEST;
  HostResolver::ResolveHostParameters low_priority;
  low_priority.initial_priority = LOW;
  HostResolver::ResolveHostParameters medium_priority;
  medium_priority.initial_priority = MEDIUM;
  HostResolver::ResolveHostParameters highest_priority;
  highest_priority.initial_priority = HIGHEST;

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req0", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), lowest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req1", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), highest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req2", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req3", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req4", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), highest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req5", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), lowest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req6", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));

  // Cancel some requests
  responses[1]->CancelRequest();
  responses[4]->CancelRequest();
  responses[5]->CancelRequest();

  // Unblock the resolver thread so the requests can run.
  proc_->SignalMultiple(responses.size());  // More than needed.

  // Let everything try to finish.
  base::RunLoop().RunUntilIdle();

  // Wait for all the requests to complete succesfully.
  EXPECT_THAT(responses[0]->result_error(), IsOk());
  EXPECT_THAT(responses[2]->result_error(), IsOk());
  EXPECT_THAT(responses[3]->result_error(), IsOk());
  EXPECT_THAT(responses[6]->result_error(), IsOk());

  // Cancelled requests shouldn't complete.
  EXPECT_FALSE(responses[1]->complete());
  EXPECT_FALSE(responses[4]->complete());
  EXPECT_FALSE(responses[5]->complete());

  // Verify that they called out to the resolver proc (which runs on the
  // resolver thread) in the expected order.
  MockHostResolverProc::CaptureList capture_list = proc_->GetCaptureList();
  ASSERT_EQ(4u, capture_list.size());

  EXPECT_EQ("req0", capture_list[0].hostname);
  EXPECT_EQ("req2", capture_list[1].hostname);
  EXPECT_EQ("req6", capture_list[2].hostname);
  EXPECT_EQ("req3", capture_list[3].hostname);
}

// Test that when too many requests are enqueued, old ones start to be aborted.
TEST_F(HostResolverManagerTest, QueueOverflow) {
  CreateSerialResolver();

  // Allow only 3 queued jobs.
  const size_t kMaxPendingJobs = 3u;
  resolver_->SetMaxQueuedJobsForTesting(kMaxPendingJobs);

  HostResolver::ResolveHostParameters lowest_priority;
  lowest_priority.initial_priority = LOWEST;
  HostResolver::ResolveHostParameters low_priority;
  low_priority.initial_priority = LOW;
  HostResolver::ResolveHostParameters medium_priority;
  medium_priority.initial_priority = MEDIUM;
  HostResolver::ResolveHostParameters highest_priority;
  highest_priority.initial_priority = HIGHEST;

  // Note that at this point the MockHostResolverProc is blocked, so any
  // requests we make will not complete.

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req0", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), lowest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req1", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), highest_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req2", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req3", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));

  // At this point, there are 3 enqueued jobs (and one "running" job).
  // Insertion of subsequent requests will cause evictions.

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req4", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), low_priority, resolve_context_.get())));
  EXPECT_THAT(responses[4]->result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));  // Evicts self.
  EXPECT_THAT(responses[4]->request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(responses[4]->request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req5", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  EXPECT_THAT(responses[2]->result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));
  EXPECT_THAT(responses[2]->request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(responses[2]->request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req6", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), highest_priority, resolve_context_.get())));
  EXPECT_THAT(responses[3]->result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));
  EXPECT_THAT(responses[3]->request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(responses[3]->request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("req7", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), medium_priority, resolve_context_.get())));
  EXPECT_THAT(responses[5]->result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));
  EXPECT_THAT(responses[5]->request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(responses[5]->request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Unblock the resolver thread so the requests can run.
  proc_->SignalMultiple(4u);

  // The rest should succeed.
  EXPECT_THAT(responses[0]->result_error(), IsOk());
  EXPECT_TRUE(responses[0]->request()->GetAddressResults());
  EXPECT_TRUE(responses[0]->request()->GetEndpointResults());
  EXPECT_THAT(responses[1]->result_error(), IsOk());
  EXPECT_TRUE(responses[1]->request()->GetAddressResults());
  EXPECT_TRUE(responses[1]->request()->GetEndpointResults());
  EXPECT_THAT(responses[6]->result_error(), IsOk());
  EXPECT_TRUE(responses[6]->request()->GetAddressResults());
  EXPECT_TRUE(responses[6]->request()->GetEndpointResults());
  EXPECT_THAT(responses[7]->result_error(), IsOk());
  EXPECT_TRUE(responses[7]->request()->GetAddressResults());
  EXPECT_TRUE(responses[7]->request()->GetEndpointResults());

  // Verify that they called out the the resolver proc (which runs on the
  // resolver thread) in the expected order.
  MockHostResolverProc::CaptureList capture_list = proc_->GetCaptureList();
  ASSERT_EQ(4u, capture_list.size());

  EXPECT_EQ("req0", capture_list[0].hostname);
  EXPECT_EQ("req1", capture_list[1].hostname);
  EXPECT_EQ("req6", capture_list[2].hostname);
  EXPECT_EQ("req7", capture_list[3].hostname);

  // Verify that the evicted (incomplete) requests were not cached.
  EXPECT_EQ(4u, resolve_context_->host_cache()->size());

  for (size_t i = 0; i < responses.size(); ++i) {
    EXPECT_TRUE(responses[i]->complete()) << i;
  }
}

// Tests that jobs can self-evict by setting the max queue to 0.
TEST_F(HostResolverManagerTest, QueueOverflow_SelfEvict) {
  CreateSerialResolver();
  resolver_->SetMaxQueuedJobsForTesting(0);

  // Note that at this point the MockHostResolverProc is blocked, so any
  // requests we make will not complete.

  ResolveHostResponseHelper run_response(resolver_->CreateRequest(
      HostPortPair("run", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));

  ResolveHostResponseHelper evict_response(resolver_->CreateRequest(
      HostPortPair("req1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(evict_response.result_error(),
              IsError(ERR_HOST_RESOLVER_QUEUE_TOO_LARGE));
  EXPECT_THAT(evict_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(evict_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  proc_->SignalMultiple(1u);

  EXPECT_THAT(run_response.result_error(), IsOk());
  EXPECT_TRUE(run_response.request()->GetAddressResults());
  EXPECT_TRUE(run_response.request()->GetEndpointResults());
}

// Make sure that the dns query type parameter is respected when raw IPs are
// passed in.
TEST_F(HostResolverManagerTest, AddressFamilyWithRawIPs) {
  HostResolver::ResolveHostParameters v4_parameters;
  v4_parameters.dns_query_type = DnsQueryType::A;

  HostResolver::ResolveHostParameters v6_parameters;
  v6_parameters.dns_query_type = DnsQueryType::AAAA;

  ResolveHostResponseHelper v4_v4_request(resolver_->CreateRequest(
      HostPortPair("127.0.0.1", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), v4_parameters, resolve_context_.get()));
  EXPECT_THAT(v4_v4_request.result_error(), IsOk());
  EXPECT_THAT(v4_v4_request.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(
      v4_v4_request.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));

  ResolveHostResponseHelper v4_v6_request(resolver_->CreateRequest(
      HostPortPair("127.0.0.1", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), v6_parameters, resolve_context_.get()));
  EXPECT_THAT(v4_v6_request.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  ResolveHostResponseHelper v4_unsp_request(resolver_->CreateRequest(
      HostPortPair("127.0.0.1", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(v4_unsp_request.result_error(), IsOk());
  EXPECT_THAT(v4_unsp_request.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(
      v4_unsp_request.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));

  ResolveHostResponseHelper v6_v4_request(resolver_->CreateRequest(
      HostPortPair("::1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      v4_parameters, resolve_context_.get()));
  EXPECT_THAT(v6_v4_request.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  ResolveHostResponseHelper v6_v6_request(resolver_->CreateRequest(
      HostPortPair("::1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      v6_parameters, resolve_context_.get()));
  EXPECT_THAT(v6_v6_request.result_error(), IsOk());
  EXPECT_THAT(v6_v6_request.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::1", 80)));
  EXPECT_THAT(
      v6_v6_request.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("::1", 80))))));

  ResolveHostResponseHelper v6_unsp_request(resolver_->CreateRequest(
      HostPortPair("::1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(v6_unsp_request.result_error(), IsOk());
  EXPECT_THAT(v6_unsp_request.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::1", 80)));
  EXPECT_THAT(
      v6_unsp_request.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("::1", 80))))));
}

TEST_F(HostResolverManagerTest, LocalOnly_FromCache) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);  // Need only one.

  HostResolver::ResolveHostParameters source_none_parameters;
  source_none_parameters.source = HostResolverSource::LOCAL_ONLY;

  // First NONE query expected to complete synchronously with a cache miss.
  ResolveHostResponseHelper cache_miss_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));
  EXPECT_TRUE(cache_miss_request.complete());
  EXPECT_THAT(cache_miss_request.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(cache_miss_request.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cache_miss_request.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(cache_miss_request.request()->GetStaleInfo());

  // Normal query to populate the cache.
  ResolveHostResponseHelper normal_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(normal_request.result_error(), IsOk());
  EXPECT_FALSE(normal_request.request()->GetStaleInfo());

  // Second NONE query expected to complete synchronously with cache hit.
  ResolveHostResponseHelper cache_hit_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));
  EXPECT_TRUE(cache_hit_request.complete());
  EXPECT_THAT(cache_hit_request.result_error(), IsOk());
  EXPECT_THAT(cache_hit_request.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(
      cache_hit_request.request()->GetEndpointResults(),
      testing::Pointee(testing::UnorderedElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_FALSE(cache_hit_request.request()->GetStaleInfo().value().is_stale());
}

TEST_F(HostResolverManagerTest, LocalOnly_StaleEntry) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);  // Need only one.

  HostResolver::ResolveHostParameters source_none_parameters;
  source_none_parameters.source = HostResolverSource::LOCAL_ONLY;

  // First NONE query expected to complete synchronously with a cache miss.
  ResolveHostResponseHelper cache_miss_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));
  EXPECT_TRUE(cache_miss_request.complete());
  EXPECT_THAT(cache_miss_request.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(cache_miss_request.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cache_miss_request.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_FALSE(cache_miss_request.request()->GetStaleInfo());

  // Normal query to populate the cache.
  ResolveHostResponseHelper normal_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(normal_request.result_error(), IsOk());
  EXPECT_FALSE(normal_request.request()->GetStaleInfo());

  MakeCacheStale();

  // Second NONE query still expected to complete synchronously with cache miss.
  ResolveHostResponseHelper stale_request(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), source_none_parameters, resolve_context_.get()));
  EXPECT_TRUE(stale_request.complete());
  EXPECT_THAT(stale_request.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(stale_request.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(stale_request.request()->GetEndp
"""


```