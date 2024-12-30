Response:
The user wants a summary of the functionality of the provided C++ code, which is part of Chromium's networking stack and resides in the `net/dns/mock_host_resolver.cc` file.

I need to:
1. **Summarize the functionality** of the `MockHostResolverBase` and related classes.
2. **Identify any connections to JavaScript functionality** and provide examples.
3. **Explain logical deductions** with hypothetical inputs and outputs.
4. **Point out common user/programming errors** with examples.
5. **Describe user actions leading to this code** for debugging.

This is the *second part* of the request, so I should focus on the code provided in this snippet. The prompt indicates there is a first part. I should integrate the understanding from the first part (though it's not directly provided here) into the overall summary if possible.

Based on the code, the main functionalities seem to be:

- **Mocking DNS resolution:**  Simulating DNS resolution outcomes based on predefined rules.
- **MDNS Listener Management:**  Handling listeners for Multicast DNS (MDNS) events.
- **Caching:** Implementing a basic DNS cache for testing purposes.
- **Rule-based resolution:** Allowing the definition of rules to control resolution behavior (success, failure, timeouts, IP literal mapping, etc.).
- **Hanging Resolver:** A resolver that never completes requests, useful for testing timeouts and cancellations.
- **Scoped Default Resolver:**  A utility to temporarily replace the default host resolver.

I'll address each of these in the summary, keeping in mind the specific instructions about JavaScript interaction, logical deductions, common errors, and debugging context.
这是 `net/dns/mock_host_resolver.cc` 文件的第二部分，主要延续了第一部分关于模拟主机解析器的功能，并引入了更多用于测试和模拟网络行为的组件。以下是这部分代码功能的归纳总结：

**主要功能归纳:**

1. **MDNS 监听器触发:** `MockHostResolverBase` 提供了触发 MDNS (Multicast DNS) 监听器的功能。
   - `TriggerMdnsListeners`:  可以模拟触发不同类型的 MDNS 响应，包括 IP 地址结果、文本结果、主机名结果以及未处理的结果。
   - 这些函数允许测试依赖于 MDNS 服务的组件，例如在本地网络中发现设备或服务。

2. **请求管理:** `MockHostResolverBase` 内部维护着一个请求映射 (`state_->mutable_requests()`)，用于跟踪正在处理的异步 DNS 解析请求。
   - `request(size_t id)`:  根据请求 ID 获取请求对象，用于访问请求的状态和参数。

3. **异步解析:**  `MockHostResolverBase` 支持异步的 DNS 解析操作。
   - 当 `synchronous_mode_` 为 false 时，`Resolve` 方法会将请求存储起来，并通过 `PostTask` 异步执行 `ResolveNow`。
   - `ondemand_mode_` 控制是否立即触发异步解析。

4. **IP 字面量或缓存解析:** `ResolveFromIPLiteralOrCache` 函数尝试从 IP 字面量或缓存中解析主机名。
   - 如果主机名是 IP 字面量，则直接返回。
   - 如果启用了缓存 (`cache_.get()`)，则尝试从缓存中查找结果。
   - 支持允许使用过期缓存项 (`STALE_ALLOWED`) 的查找。
   - 实现了缓存失效计数 (`cache_invalidation_nums_`) 的逻辑，用于模拟缓存项的临时失效。

5. **同步解析:** `DoSynchronousResolution` 函数执行同步的 DNS 解析。
   - 它使用 `rule_resolver_` (通常是 `RuleBasedHostResolver::RuleResolver`) 根据预定义的规则解析主机名。
   - 根据规则的结果设置请求的 endpoint 结果或错误。
   - 如果启用了缓存，则将解析结果添加到缓存中。

6. **MDNS 监听器管理:** `AddListener` 和 `RemoveCancelledListener` 方法用于管理 MDNS 监听器集合 (`listeners_`)。

7. **`MockHostResolverFactory`:**  一个用于创建 `MockHostResolverBase` 实例的工厂类。
   - 允许配置是否启用缓存以及缓存失效的次数。

8. **`RuleBasedHostResolverProc`:** 一个基于规则的 `HostResolverProc` 的实现，用于更精细地控制 DNS 解析的行为。
   - 允许添加多种类型的规则，例如将特定主机名映射到 IP 地址、模拟解析失败、模拟超时、添加延迟等。
   - `AddRule`, `AddRuleForAddressFamily`, `AddRuleWithFlags`, `AddIPLiteralRule` 等方法用于添加不同类型的解析规则。
   - `Resolve` 方法会遍历规则，匹配主机名和 flags，并根据匹配的规则返回结果或调用下一个 `HostResolverProc`。

9. **`HangingHostResolver`:** 一个特殊的 `HostResolver` 实现，其解析请求永远不会完成，用于测试超时和取消逻辑。
   - `CreateRequest` 方法创建一个永不完成的请求。
   - 跟踪请求的取消次数。

10. **`ScopedDefaultHostResolverProc`:** 一个用于在特定作用域内替换默认 `HostResolverProc` 的工具类，方便进行单元测试。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它在 Chromium 的网络栈中扮演着关键角色，而网络栈是浏览器与外部世界通信的基础。JavaScript 代码通过浏览器提供的 Web API (如 `fetch`, `XMLHttpRequest`) 发起网络请求，这些请求最终会依赖底层的 DNS 解析。

**举例说明：**

假设一个网页的 JavaScript 代码尝试加载一个图片：

```javascript
fetch('http://example.test/image.png').then(response => {
  // 处理响应
});
```

如果配置了 `MockHostResolverBase`，可以模拟 `example.test` 的 DNS 解析结果。例如，可以使用 `RuleBasedHostResolverProc` 添加一个规则，将 `example.test` 映射到特定的 IP 地址或使其解析失败。

**逻辑推理与假设输入输出：**

**假设输入：**

- `MockHostResolverBase` 处于异步模式 (`synchronous_mode_ = false`)。
- 添加一个规则，将 `test.example.com` 映射到 `127.0.0.1`。
- JavaScript 发起对 `http://test.example.com/` 的请求。

**输出：**

1. `MockHostResolverBase::Resolve` 被调用，请求参数包含主机名 `test.example.com`。
2. 由于是异步模式，请求会被添加到 `state_->mutable_requests()`。
3. 如果 `ondemand_mode_` 为 false，一个任务会被 post 到消息循环，最终调用 `MockHostResolverBase::ResolveNow`。
4. `MockHostResolverBase::ResolveNow` 会调用 `rule_resolver_.Resolve`，根据规则匹配到 `test.example.com` 并返回 `127.0.0.1`。
5. 请求的状态会被更新为成功，endpoint 结果包含 `127.0.0.1`。
6. 请求的回调函数会被调用，JavaScript 代码能够处理来自 `127.0.0.1` 的响应。

**用户或编程常见的使用错误：**

1. **规则配置错误：**
   - **错误示例：** 添加了一个规则 `AddRule("example.com", "")`，希望阻止对 `example.com` 的解析。这实际上会匹配到 `example.com` 并尝试解析空字符串，导致意外行为。
   - **正确做法：** 使用 `AddSimulatedFailure("example.com")` 来模拟解析失败。

2. **异步模式下的同步假设：**
   - **错误示例：** 在异步模式下调用 `Resolve` 后，立即假设请求已完成并尝试访问结果。
   - **正确做法：** 依赖请求的回调函数来获取解析结果。

3. **缓存配置不当：**
   - **错误示例：**  在测试环境中未禁用缓存，导致之前的测试结果影响当前的测试。
   - **正确做法：**  根据测试需求启用或禁用缓存，或者使用 `cache_invalidation_num_` 来模拟缓存失效。

4. **MDNS 监听器管理错误：**
   - **错误示例：** 创建了 MDNS 监听器但没有正确地添加到 `MockHostResolverBase` 中，导致无法接收到模拟的 MDNS 事件。
   - **正确做法：** 使用 `AddListener` 将监听器添加到 `MockHostResolverBase`。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入一个网址 (例如 `http://example.test/`) 并按下回车。**
2. **浏览器进程中的网络线程开始处理该请求。**
3. **网络线程需要解析主机名 `example.test`。**
4. **如果系统配置使用 `MockHostResolverBase` (通常在测试环境中)，则会调用 `MockHostResolverBase::Resolve` 或其相关的函数。**
5. **如果在 `RuleBasedHostResolverProc` 中配置了匹配 `example.test` 的规则，则会按照规则进行处理（例如返回特定的 IP 地址、模拟失败等）。**
6. **如果涉及到 MDNS，并且有相应的监听器，则 `TriggerMdnsListeners` 函数会被调用来模拟 MDNS 响应。**

在调试过程中，可以设置断点在 `MockHostResolverBase::Resolve`、`RuleBasedHostResolverProc::Resolve` 或相关的 MDNS 触发函数中，来观察 DNS 解析的流程和规则的匹配情况。还可以检查 `state_->mutable_requests()` 来查看当前的异步请求状态。

总而言之，这部分代码提供了强大的模拟 DNS 解析功能，用于在 Chromium 的测试环境中模拟各种网络场景，包括成功的解析、失败、超时、缓存行为以及 MDNS 交互。它允许开发者在不依赖真实 DNS 服务器的情况下，测试网络栈的各个组件和依赖 DNS 解析的上层逻辑。

Prompt: 
```
这是目录为net/dns/mock_host_resolver.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ess_result);
  }
}

void MockHostResolverBase::TriggerMdnsListeners(
    const HostPortPair& host,
    DnsQueryType query_type,
    MdnsListenerUpdateType update_type,
    const std::vector<std::string>& text_result) {
  for (MdnsListenerImpl* listener : listeners_) {
    if (listener->host() == host && listener->query_type() == query_type)
      listener->TriggerTextResult(update_type, text_result);
  }
}

void MockHostResolverBase::TriggerMdnsListeners(
    const HostPortPair& host,
    DnsQueryType query_type,
    MdnsListenerUpdateType update_type,
    const HostPortPair& host_result) {
  for (MdnsListenerImpl* listener : listeners_) {
    if (listener->host() == host && listener->query_type() == query_type)
      listener->TriggerHostnameResult(update_type, host_result);
  }
}

void MockHostResolverBase::TriggerMdnsListeners(
    const HostPortPair& host,
    DnsQueryType query_type,
    MdnsListenerUpdateType update_type) {
  for (MdnsListenerImpl* listener : listeners_) {
    if (listener->host() == host && listener->query_type() == query_type)
      listener->TriggerUnhandledResult(update_type);
  }
}

MockHostResolverBase::RequestBase* MockHostResolverBase::request(size_t id) {
  RequestMap::iterator request = state_->mutable_requests().find(id);
  CHECK(request != state_->mutable_requests().end());
  CHECK_EQ(request->second->id(), id);
  return (*request).second;
}

// start id from 1 to distinguish from NULL RequestHandle
MockHostResolverBase::MockHostResolverBase(bool use_caching,
                                           int cache_invalidation_num,
                                           RuleResolver rule_resolver)
    : rule_resolver_(std::move(rule_resolver)),
      initial_cache_invalidation_num_(cache_invalidation_num),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      state_(base::MakeRefCounted<State>()) {
  if (use_caching)
    cache_ = std::make_unique<HostCache>(kMaxCacheEntries);
  else
    DCHECK_GE(0, cache_invalidation_num);
}

int MockHostResolverBase::Resolve(RequestBase* request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  last_request_priority_ = request->parameters().initial_priority;
  last_request_network_anonymization_key_ =
      request->network_anonymization_key();
  last_secure_dns_policy_ = request->parameters().secure_dns_policy;
  state_->IncrementNumResolve();
  std::vector<HostResolverEndpointResult> endpoints;
  std::set<std::string> aliases;
  std::optional<HostCache::EntryStaleness> stale_info;
  // TODO(crbug.com/40203587): Allow caching `ConnectionEndpoint` results.
  int rv = ResolveFromIPLiteralOrCache(
      request->request_endpoint(), request->network_anonymization_key(),
      request->parameters().dns_query_type, request->host_resolver_flags(),
      request->parameters().source, request->parameters().cache_usage,
      &endpoints, &aliases, &stale_info);

  if (rv == OK && !request->parameters().is_speculative) {
    request->SetEndpointResults(std::move(endpoints), std::move(aliases),
                                std::move(stale_info));
  } else {
    request->SetError(rv);
  }

  if (rv != ERR_DNS_CACHE_MISS ||
      request->parameters().source == HostResolverSource::LOCAL_ONLY) {
    return SquashErrorCode(rv);
  }

  // Just like the real resolver, refuse to do anything with invalid
  // hostnames.
  if (!dns_names_util::IsValidDnsName(
          request->request_endpoint().GetHostnameWithoutBrackets())) {
    request->SetError(ERR_NAME_NOT_RESOLVED);
    return ERR_NAME_NOT_RESOLVED;
  }

  if (synchronous_mode_)
    return DoSynchronousResolution(*request);

  // Store the request for asynchronous resolution
  size_t id = next_request_id_++;
  request->set_id(id);
  state_->mutable_requests()[id] = request;

  if (!ondemand_mode_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&MockHostResolverBase::ResolveNow,
                                  weak_ptr_factory_.GetWeakPtr(), id));
  }

  return ERR_IO_PENDING;
}

int MockHostResolverBase::ResolveFromIPLiteralOrCache(
    const Host& endpoint,
    const NetworkAnonymizationKey& network_anonymization_key,
    DnsQueryType dns_query_type,
    HostResolverFlags flags,
    HostResolverSource source,
    HostResolver::ResolveHostParameters::CacheUsage cache_usage,
    std::vector<HostResolverEndpointResult>* out_endpoints,
    std::set<std::string>* out_aliases,
    std::optional<HostCache::EntryStaleness>* out_stale_info) {
  DCHECK(out_endpoints);
  DCHECK(out_aliases);
  DCHECK(out_stale_info);
  out_endpoints->clear();
  out_aliases->clear();
  *out_stale_info = std::nullopt;

  IPAddress ip_address;
  if (ip_address.AssignFromIPLiteral(endpoint.GetHostnameWithoutBrackets())) {
    const DnsQueryType desired_address_query =
        AddressFamilyToDnsQueryType(GetAddressFamily(ip_address));
    DCHECK_NE(desired_address_query, DnsQueryType::UNSPECIFIED);

    // This matches the behavior HostResolverImpl.
    if (dns_query_type != DnsQueryType::UNSPECIFIED &&
        dns_query_type != desired_address_query) {
      return ERR_NAME_NOT_RESOLVED;
    }

    *out_endpoints = std::vector<HostResolverEndpointResult>(1);
    (*out_endpoints)[0].ip_endpoints.emplace_back(ip_address,
                                                  endpoint.GetPort());
    if (flags & HOST_RESOLVER_CANONNAME)
      *out_aliases = {ip_address.ToString()};
    return OK;
  }

  std::vector<IPEndPoint> localhost_endpoints;
  // Immediately resolve any "localhost" or recognized similar names.
  if (IsAddressType(dns_query_type) &&
      ResolveLocalHostname(endpoint.GetHostnameWithoutBrackets(),
                           &localhost_endpoints)) {
    *out_endpoints = std::vector<HostResolverEndpointResult>(1);
    (*out_endpoints)[0].ip_endpoints = localhost_endpoints;
    return OK;
  }
  int rv = ERR_DNS_CACHE_MISS;
  bool cache_allowed =
      cache_usage == HostResolver::ResolveHostParameters::CacheUsage::ALLOWED ||
      cache_usage ==
          HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;
  if (cache_.get() && cache_allowed) {
    // Local-only requests search the cache for non-local-only results.
    HostResolverSource effective_source =
        source == HostResolverSource::LOCAL_ONLY ? HostResolverSource::ANY
                                                 : source;
    HostCache::Key key(GetCacheHost(endpoint), dns_query_type, flags,
                       effective_source, network_anonymization_key);
    const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;
    HostCache::EntryStaleness stale_info = HostCache::kNotStale;
    if (cache_usage ==
        HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED) {
      cache_result = cache_->LookupStale(key, tick_clock_->NowTicks(),
                                         &stale_info, true /* ignore_secure */);
    } else {
      cache_result = cache_->Lookup(key, tick_clock_->NowTicks(),
                                    true /* ignore_secure */);
    }
    if (cache_result) {
      rv = cache_result->second.error();
      if (rv == OK) {
        *out_endpoints = cache_result->second.GetEndpoints();

        *out_aliases = cache_result->second.aliases();
        *out_stale_info = std::move(stale_info);
      }

      auto cache_invalidation_iterator = cache_invalidation_nums_.find(key);
      if (cache_invalidation_iterator != cache_invalidation_nums_.end()) {
        DCHECK_LE(1, cache_invalidation_iterator->second);
        cache_invalidation_iterator->second--;
        if (cache_invalidation_iterator->second == 0) {
          HostCache::Entry new_entry(cache_result->second);
          cache_->Set(key, new_entry, tick_clock_->NowTicks(),
                      base::TimeDelta());
          cache_invalidation_nums_.erase(cache_invalidation_iterator);
        }
      }
    }
  }
  return rv;
}

int MockHostResolverBase::DoSynchronousResolution(RequestBase& request) {
  state_->IncrementNumNonLocalResolves();

  const RuleResolver::RuleResultOrError& result = rule_resolver_.Resolve(
      request.request_endpoint(), {request.parameters().dns_query_type},
      request.parameters().source);

  int error = ERR_UNEXPECTED;
  std::optional<HostCache::Entry> cache_entry;
  if (absl::holds_alternative<RuleResolver::RuleResult>(result)) {
    const auto& rule_result = absl::get<RuleResolver::RuleResult>(result);
    const auto& endpoint_results = rule_result.endpoints;
    const auto& aliases = rule_result.aliases;
    request.SetEndpointResults(endpoint_results, aliases,
                               /*staleness=*/std::nullopt);
    // TODO(crbug.com/40203587): Change `error` on empty results?
    error = OK;
    if (cache_.get()) {
      cache_entry = CreateCacheEntry(request.request_endpoint().GetHostname(),
                                     endpoint_results, aliases);
    }
  } else {
    DCHECK(absl::holds_alternative<RuleResolver::ErrorResult>(result));
    error = absl::get<RuleResolver::ErrorResult>(result);
    request.SetError(error);
    if (cache_.get()) {
      cache_entry.emplace(error, HostCache::Entry::SOURCE_UNKNOWN);
    }
  }
  if (cache_.get() && cache_entry.has_value()) {
    HostCache::Key key(
        GetCacheHost(request.request_endpoint()),
        request.parameters().dns_query_type, request.host_resolver_flags(),
        request.parameters().source, request.network_anonymization_key());
    // Storing a failure with TTL 0 so that it overwrites previous value.
    base::TimeDelta ttl;
    if (error == OK) {
      ttl = base::Seconds(kCacheEntryTTLSeconds);
      if (initial_cache_invalidation_num_ > 0)
        cache_invalidation_nums_[key] = initial_cache_invalidation_num_;
    }
    cache_->Set(key, cache_entry.value(), tick_clock_->NowTicks(), ttl);
  }

  return SquashErrorCode(error);
}

void MockHostResolverBase::AddListener(MdnsListenerImpl* listener) {
  listeners_.insert(listener);
}

void MockHostResolverBase::RemoveCancelledListener(MdnsListenerImpl* listener) {
  listeners_.erase(listener);
}

MockHostResolverFactory::MockHostResolverFactory(
    MockHostResolverBase::RuleResolver rules,
    bool use_caching,
    int cache_invalidation_num)
    : rules_(std::move(rules)),
      use_caching_(use_caching),
      cache_invalidation_num_(cache_invalidation_num) {}

MockHostResolverFactory::~MockHostResolverFactory() = default;

std::unique_ptr<HostResolver> MockHostResolverFactory::CreateResolver(
    HostResolverManager* manager,
    std::string_view host_mapping_rules,
    bool enable_caching) {
  DCHECK(host_mapping_rules.empty());

  // Explicit new to access private constructor.
  auto resolver = base::WrapUnique(new MockHostResolverBase(
      enable_caching && use_caching_, cache_invalidation_num_, rules_));
  return resolver;
}

std::unique_ptr<HostResolver> MockHostResolverFactory::CreateStandaloneResolver(
    NetLog* net_log,
    const HostResolver::ManagerOptions& options,
    std::string_view host_mapping_rules,
    bool enable_caching) {
  return CreateResolver(nullptr, host_mapping_rules, enable_caching);
}

//-----------------------------------------------------------------------------

RuleBasedHostResolverProc::Rule::Rule(ResolverType resolver_type,
                                      std::string_view host_pattern,
                                      AddressFamily address_family,
                                      HostResolverFlags host_resolver_flags,
                                      std::string_view replacement,
                                      std::vector<std::string> dns_aliases,
                                      int latency_ms)
    : resolver_type(resolver_type),
      host_pattern(host_pattern),
      address_family(address_family),
      host_resolver_flags(host_resolver_flags),
      replacement(replacement),
      dns_aliases(std::move(dns_aliases)),
      latency_ms(latency_ms) {
  DCHECK(this->dns_aliases != std::vector<std::string>({""}));
}

RuleBasedHostResolverProc::Rule::Rule(const Rule& other) = default;

RuleBasedHostResolverProc::Rule::~Rule() = default;

RuleBasedHostResolverProc::RuleBasedHostResolverProc(
    scoped_refptr<HostResolverProc> previous,
    bool allow_fallback)
    : HostResolverProc(std::move(previous), allow_fallback) {}

void RuleBasedHostResolverProc::AddRule(std::string_view host_pattern,
                                        std::string_view replacement) {
  AddRuleForAddressFamily(host_pattern, ADDRESS_FAMILY_UNSPECIFIED,
                          replacement);
}

void RuleBasedHostResolverProc::AddRuleForAddressFamily(
    std::string_view host_pattern,
    AddressFamily address_family,
    std::string_view replacement) {
  DCHECK(!replacement.empty());
  HostResolverFlags flags = HOST_RESOLVER_LOOPBACK_ONLY;
  Rule rule(Rule::kResolverTypeSystem, host_pattern, address_family, flags,
            replacement, {} /* dns_aliases */, 0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AddRuleWithFlags(
    std::string_view host_pattern,
    std::string_view replacement,
    HostResolverFlags flags,
    std::vector<std::string> dns_aliases) {
  DCHECK(!replacement.empty());
  Rule rule(Rule::kResolverTypeSystem, host_pattern, ADDRESS_FAMILY_UNSPECIFIED,
            flags, replacement, std::move(dns_aliases), 0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AddIPLiteralRule(
    std::string_view host_pattern,
    std::string_view ip_literal,
    std::string_view canonical_name) {
  // Literals are always resolved to themselves by HostResolverImpl,
  // consequently we do not support remapping them.
  IPAddress ip_address;
  DCHECK(!ip_address.AssignFromIPLiteral(host_pattern));
  HostResolverFlags flags = HOST_RESOLVER_LOOPBACK_ONLY;
  std::vector<std::string> aliases;
  if (!canonical_name.empty()) {
    flags |= HOST_RESOLVER_CANONNAME;
    aliases.emplace_back(canonical_name);
  }

  Rule rule(Rule::kResolverTypeIPLiteral, host_pattern,
            ADDRESS_FAMILY_UNSPECIFIED, flags, ip_literal, std::move(aliases),
            0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AddIPLiteralRuleWithDnsAliases(
    std::string_view host_pattern,
    std::string_view ip_literal,
    std::vector<std::string> dns_aliases) {
  // Literals are always resolved to themselves by HostResolverImpl,
  // consequently we do not support remapping them.
  IPAddress ip_address;
  DCHECK(!ip_address.AssignFromIPLiteral(host_pattern));
  HostResolverFlags flags = HOST_RESOLVER_LOOPBACK_ONLY;
  if (!dns_aliases.empty())
    flags |= HOST_RESOLVER_CANONNAME;

  Rule rule(Rule::kResolverTypeIPLiteral, host_pattern,
            ADDRESS_FAMILY_UNSPECIFIED, flags, ip_literal,
            std::move(dns_aliases), 0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AddRuleWithLatency(
    std::string_view host_pattern,
    std::string_view replacement,
    int latency_ms) {
  DCHECK(!replacement.empty());
  HostResolverFlags flags = HOST_RESOLVER_LOOPBACK_ONLY;
  Rule rule(Rule::kResolverTypeSystem, host_pattern, ADDRESS_FAMILY_UNSPECIFIED,
            flags, replacement, /*dns_aliases=*/{}, latency_ms);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AllowDirectLookup(
    std::string_view host_pattern) {
  HostResolverFlags flags = HOST_RESOLVER_LOOPBACK_ONLY;
  Rule rule(Rule::kResolverTypeSystem, host_pattern, ADDRESS_FAMILY_UNSPECIFIED,
            flags, std::string(), /*dns_aliases=*/{}, 0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AddSimulatedFailure(
    std::string_view host_pattern,
    HostResolverFlags flags) {
  Rule rule(Rule::kResolverTypeFail, host_pattern, ADDRESS_FAMILY_UNSPECIFIED,
            flags, std::string(), /*dns_aliases=*/{}, 0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::AddSimulatedTimeoutFailure(
    std::string_view host_pattern,
    HostResolverFlags flags) {
  Rule rule(Rule::kResolverTypeFailTimeout, host_pattern,
            ADDRESS_FAMILY_UNSPECIFIED, flags, std::string(),
            /*dns_aliases=*/{}, 0);
  AddRuleInternal(rule);
}

void RuleBasedHostResolverProc::ClearRules() {
  CHECK(modifications_allowed_);
  base::AutoLock lock(rule_lock_);
  rules_.clear();
}

void RuleBasedHostResolverProc::DisableModifications() {
  modifications_allowed_ = false;
}

RuleBasedHostResolverProc::RuleList RuleBasedHostResolverProc::GetRules() {
  RuleList rv;
  {
    base::AutoLock lock(rule_lock_);
    rv = rules_;
  }
  return rv;
}

size_t RuleBasedHostResolverProc::NumResolvesForHostPattern(
    std::string_view host_pattern) {
  base::AutoLock lock(rule_lock_);
  return num_resolves_per_host_pattern_[host_pattern];
}

int RuleBasedHostResolverProc::Resolve(const std::string& host,
                                       AddressFamily address_family,
                                       HostResolverFlags host_resolver_flags,
                                       AddressList* addrlist,
                                       int* os_error) {
  base::AutoLock lock(rule_lock_);
  RuleList::iterator r;
  for (r = rules_.begin(); r != rules_.end(); ++r) {
    bool matches_address_family =
        r->address_family == ADDRESS_FAMILY_UNSPECIFIED ||
        r->address_family == address_family;
    // Ignore HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6, since it should
    // have no impact on whether a rule matches.
    HostResolverFlags flags =
        host_resolver_flags & ~HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6;
    // Flags match if all of the bitflags in host_resolver_flags are enabled
    // in the rule's host_resolver_flags. However, the rule may have additional
    // flags specified, in which case the flags should still be considered a
    // match.
    bool matches_flags = (r->host_resolver_flags & flags) == flags;
    if (matches_flags && matches_address_family &&
        base::MatchPattern(host, r->host_pattern)) {
      num_resolves_per_host_pattern_[r->host_pattern]++;

      if (r->latency_ms != 0) {
        base::PlatformThread::Sleep(base::Milliseconds(r->latency_ms));
      }

      // Remap to a new host.
      const std::string& effective_host =
          r->replacement.empty() ? host : r->replacement;

      // Apply the resolving function to the remapped hostname.
      switch (r->resolver_type) {
        case Rule::kResolverTypeFail:
          return ERR_NAME_NOT_RESOLVED;
        case Rule::kResolverTypeFailTimeout:
          return ERR_DNS_TIMED_OUT;
        case Rule::kResolverTypeSystem:
          EnsureSystemHostResolverCallReady();
          return SystemHostResolverCall(effective_host, address_family,
                                        host_resolver_flags, addrlist,
                                        os_error);
        case Rule::kResolverTypeIPLiteral: {
          AddressList raw_addr_list;
          std::vector<std::string> aliases;
          aliases = (!r->dns_aliases.empty())
                        ? r->dns_aliases
                        : std::vector<std::string>({host});
          std::vector<net::IPEndPoint> ip_endpoints;
          int result = ParseAddressList(effective_host, &ip_endpoints);
          // Filter out addresses with the wrong family.
          *addrlist = AddressList();
          for (const auto& address : ip_endpoints) {
            if (address_family == ADDRESS_FAMILY_UNSPECIFIED ||
                address_family == address.GetFamily()) {
              addrlist->push_back(address);
            }
          }
          addrlist->SetDnsAliases(aliases);

          if (result == OK && addrlist->empty())
            return ERR_NAME_NOT_RESOLVED;
          return result;
        }
        default:
          NOTREACHED();
      }
    }
  }

  return ResolveUsingPrevious(host, address_family, host_resolver_flags,
                              addrlist, os_error);
}

RuleBasedHostResolverProc::~RuleBasedHostResolverProc() = default;

void RuleBasedHostResolverProc::AddRuleInternal(const Rule& rule) {
  Rule fixed_rule = rule;
  // SystemResolverProc expects valid DNS addresses.
  // So for kResolverTypeSystem rules:
  // * CHECK that replacement is empty (empty domain names mean use a direct
  //   lookup) or a valid DNS name (which includes IP addresses).
  // * If the replacement is an IP address, switch to an IP literal rule.
  if (fixed_rule.resolver_type == Rule::kResolverTypeSystem) {
    CHECK(fixed_rule.replacement.empty() ||
          dns_names_util::IsValidDnsName(fixed_rule.replacement));

    IPAddress ip_address;
    bool valid_address = ip_address.AssignFromIPLiteral(fixed_rule.replacement);
    if (valid_address) {
      fixed_rule.resolver_type = Rule::kResolverTypeIPLiteral;
    }
  }

  CHECK(modifications_allowed_);
  base::AutoLock lock(rule_lock_);
  rules_.push_back(fixed_rule);
}

scoped_refptr<RuleBasedHostResolverProc> CreateCatchAllHostResolverProc() {
  auto catchall =
      base::MakeRefCounted<RuleBasedHostResolverProc>(/*previous=*/nullptr,
                                                      /*allow_fallback=*/false);
  // Note that IPv6 lookups fail.
  catchall->AddIPLiteralRule("*", "127.0.0.1", "localhost");

  // Next add a rules-based layer that the test controls.
  return base::MakeRefCounted<RuleBasedHostResolverProc>(
      std::move(catchall), /*allow_fallback=*/false);
}

//-----------------------------------------------------------------------------

// Implementation of ResolveHostRequest that tracks cancellations when the
// request is destroyed after being started.
class HangingHostResolver::RequestImpl
    : public HostResolver::ResolveHostRequest,
      public HostResolver::ProbeRequest {
 public:
  explicit RequestImpl(base::WeakPtr<HangingHostResolver> resolver)
      : resolver_(resolver) {}

  RequestImpl(const RequestImpl&) = delete;
  RequestImpl& operator=(const RequestImpl&) = delete;

  ~RequestImpl() override {
    if (is_running_ && resolver_)
      resolver_->state_->IncrementNumCancellations();
  }

  int Start(CompletionOnceCallback callback) override { return Start(); }

  int Start() override {
    DCHECK(resolver_);
    is_running_ = true;
    return ERR_IO_PENDING;
  }

  const AddressList* GetAddressResults() const override {
    base::ImmediateCrash();
  }

  const std::vector<HostResolverEndpointResult>* GetEndpointResults()
      const override {
    base::ImmediateCrash();
  }

  const std::vector<std::string>* GetTextResults() const override {
    base::ImmediateCrash();
  }

  const std::vector<HostPortPair>* GetHostnameResults() const override {
    base::ImmediateCrash();
  }

  const std::set<std::string>* GetDnsAliasResults() const override {
    base::ImmediateCrash();
  }

  net::ResolveErrorInfo GetResolveErrorInfo() const override {
    base::ImmediateCrash();
  }

  const std::optional<HostCache::EntryStaleness>& GetStaleInfo()
      const override {
    base::ImmediateCrash();
  }

  void ChangeRequestPriority(RequestPriority priority) override {}

 private:
  // Use a WeakPtr as the resolver may be destroyed while there are still
  // outstanding request objects.
  base::WeakPtr<HangingHostResolver> resolver_;
  bool is_running_ = false;
};

HangingHostResolver::State::State() = default;
HangingHostResolver::State::~State() = default;

HangingHostResolver::HangingHostResolver()
    : state_(base::MakeRefCounted<State>()) {}

HangingHostResolver::~HangingHostResolver() = default;

void HangingHostResolver::OnShutdown() {
  shutting_down_ = true;
}

std::unique_ptr<HostResolver::ResolveHostRequest>
HangingHostResolver::CreateRequest(
    url::SchemeHostPort host,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    std::optional<ResolveHostParameters> optional_parameters) {
  // TODO(crbug.com/40181080): Propagate scheme and make affect behavior.
  return CreateRequest(HostPortPair::FromSchemeHostPort(host),
                       network_anonymization_key, net_log, optional_parameters);
}

std::unique_ptr<HostResolver::ResolveHostRequest>
HangingHostResolver::CreateRequest(
    const HostPortPair& host,
    const NetworkAnonymizationKey& network_anonymization_key,
    const NetLogWithSource& source_net_log,
    const std::optional<ResolveHostParameters>& optional_parameters) {
  last_host_ = host;
  last_network_anonymization_key_ = network_anonymization_key;

  if (shutting_down_)
    return CreateFailingRequest(ERR_CONTEXT_SHUT_DOWN);

  if (optional_parameters &&
      optional_parameters.value().source == HostResolverSource::LOCAL_ONLY) {
    return CreateFailingRequest(ERR_DNS_CACHE_MISS);
  }

  return std::make_unique<RequestImpl>(weak_ptr_factory_.GetWeakPtr());
}

std::unique_ptr<HostResolver::ServiceEndpointRequest>
HangingHostResolver::CreateServiceEndpointRequest(
    Host host,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    ResolveHostParameters parameters) {
  NOTIMPLEMENTED();
  return nullptr;
}

std::unique_ptr<HostResolver::ProbeRequest>
HangingHostResolver::CreateDohProbeRequest() {
  if (shutting_down_)
    return CreateFailingProbeRequest(ERR_CONTEXT_SHUT_DOWN);

  return std::make_unique<RequestImpl>(weak_ptr_factory_.GetWeakPtr());
}

void HangingHostResolver::SetRequestContext(
    URLRequestContext* url_request_context) {}

//-----------------------------------------------------------------------------

ScopedDefaultHostResolverProc::ScopedDefaultHostResolverProc() = default;

ScopedDefaultHostResolverProc::ScopedDefaultHostResolverProc(
    HostResolverProc* proc) {
  Init(proc);
}

ScopedDefaultHostResolverProc::~ScopedDefaultHostResolverProc() {
  HostResolverProc* old_proc =
      HostResolverProc::SetDefault(previous_proc_.get());
  // The lifetimes of multiple instances must be nested.
  CHECK_EQ(old_proc, current_proc_.get());
}

void ScopedDefaultHostResolverProc::Init(HostResolverProc* proc) {
  current_proc_ = proc;
  previous_proc_ = HostResolverProc::SetDefault(current_proc_.get());
  current_proc_->SetLastProc(previous_proc_);
}

}  // namespace net

"""


```