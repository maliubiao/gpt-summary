Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/dns/host_resolver_manager.cc`. I need to identify the main tasks performed by this code and explain them concisely. I should also look for connections to Javascript functionality, illustrate logical flow with examples, point out common usage errors, and describe how a user action might lead to this code being executed.

Here's a plan:
1. **Identify core functionalities:** Analyze the methods and data structures to understand the primary responsibilities of the `HostResolverManager`.
2. **Relate to Javascript (if applicable):**  Consider if any operations directly impact or are triggered by Javascript code in the browser.
3. **Illustrate logical flow:**  Pick a key function and demonstrate its behavior with hypothetical inputs and outputs.
4. **Highlight potential errors:**  Think about common mistakes developers or the system might make when interacting with this component.
5. **Trace user actions:**  Describe a sequence of user interactions that would eventually involve this code.
6. **Summarize the functionality:** Provide a concise overview of the code's purpose.
这是 `net/dns/host_resolver_manager.cc` 文件代码的第二部分，主要负责主机名解析的管理和调度，以及与缓存、配置和不同解析策略的交互。以下是其功能的归纳：

**核心功能归纳：**

1. **管理和调度 DNS 解析任务 (Jobs):**
   -  维护一个 `jobs_` 映射，存储当前正在进行的 DNS 解析任务。
   -  根据解析请求的关键信息 (`JobKey`)，创建或复用现有的解析任务 (Job)。
   -  `CreateAndStartJob` 和 `CreateAndStartJobForServiceEndpointRequest` 函数用于创建并启动新的解析任务，如果已经存在相同的任务，则将新的请求添加到现有任务中。
   -  `AddJobWithoutRequest` 是一个内部函数，用于创建不带初始请求的解析任务。
   -  `RemoveJob` 用于移除已完成或取消的解析任务。
   -  使用 `PrioritizedDispatcher` (`dispatcher_`) 来管理和调度这些解析任务的执行优先级。

2. **从缓存中获取解析结果:**
   -  `MaybeServeFromCache` 函数检查主机缓存 (`HostCache`) 中是否存在有效的解析结果。
   -  支持允许使用过期缓存 (`STALE_ALLOWED`) 的策略。
   -  记录缓存命中事件 (`HOST_RESOLVER_MANAGER_CACHE_HIT`)。

3. **从本地配置 (如 hosts 文件) 中获取解析结果:**
   -  `MaybeReadFromConfig` 函数尝试从系统配置 (通过 `dns_client_`) 中读取预设的 IP 地址。

4. **处理 IP 地址字面量的解析:**
   -  `ResolveAsIP` 函数直接将 IP 地址字符串解析为 `HostCache::Entry`。

5. **处理本地主机名解析:**
   -  `ServeLocalhost` 函数处理诸如 "localhost" 等本地主机名的解析。

6. **从 hosts 文件中获取解析结果:**
   -  `ServeFromHosts` 函数查找系统 hosts 文件 (`dns_client_->GetHosts()`) 中是否存在与主机名匹配的 IP 地址。
   -  处理 IPv4 和 IPv6 的查找，并考虑 "happy eyeballs" 策略的因素。

7. **管理安全 DNS (Secure DNS) 解析任务:**
   -  `StartBootstrapFollowup` 函数用于在初始解析后，如果配置了安全 DNS 策略，启动安全 DNS 的后续解析任务。
   -  `GetEffectiveSecureDnsMode` 函数根据配置获取当前有效的安全 DNS 模式。
   -  `PushDnsTasks` 函数根据安全 DNS 模式决定是否以及如何添加安全 DNS 解析任务到任务队列中。

8. **创建解析任务序列:**
   -  `CreateTaskSequence` 函数根据解析请求的参数 (如缓存使用策略、安全 DNS 策略、解析源等) 生成解析任务的执行顺序 (`TaskType` 队列)。
   -  这个函数决定了首先尝试从缓存获取结果，然后查询 hosts 文件，最后进行 DNS 查询 (普通 DNS 或安全 DNS)，以及是否使用系统解析器等步骤。

9. **IPv6 可达性检查:**
   -  `StartIPv6ReachabilityCheck` 函数发起对 IPv6 网络可达性的检查。
   -  使用 UDP socket 向特定的 IPv6 地址 (`kIPv6ProbeAddress`) 发送探测包。
   -  缓存检查结果以避免频繁探测。
   -  `FinishIPv6ReachabilityCheck` 处理探测结果并更新状态。
   -  `StartGloballyReachableCheck` 和 `FinishGloballyReachableCheck` 是用于执行实际探测的底层函数。

10. **处理网络状态变化:**
    -  `OnIPAddressChanged`：当 IP 地址发生变化时，清理缓存，并重启 loopback 地址探测。
    -  `OnConnectionTypeChanged`：当网络连接类型发生变化时，更新连接类型，并可能清理缓存。
    -  `OnSystemDnsConfigChanged`：当系统 DNS 配置发生变化时，更新内部 DNS 客户端 (`dns_client_`) 的配置，并清理缓存。
    -  `UpdateJobsForChangedConfig`：当 DNS 配置改变时，可能需要中止正在进行的解析任务。

11. **回退到系统解析器:**
    -  `OnFallbackResolve`：当普通 DNS 解析失败时，根据配置决定是否回退到系统解析器。
    -  `AbortInsecureDnsTasks`：中止当前正在进行的非安全 DNS 解析任务。

12. **管理 MDNS (Multicast DNS) 客户端:**
    -  `GetOrCreateMdnsClient`：创建或获取 MDNS 客户端实例，用于处理本地网络内的设备发现。

13. **缓存结果:**
    -  `CacheResult` 函数将解析结果存入主机缓存。

14. **中止解析任务:**
    -  `AbortJobsWithoutTargetNetwork`: 中止没有目标网络的解析任务。

**与 Javascript 的关系：**

虽然这段 C++ 代码本身不直接包含 Javascript 代码，但它为浏览器中 Javascript 发起的网络请求提供底层 DNS 解析服务。

**举例说明：**

当 Javascript 代码尝试访问一个域名，例如 `www.example.com` 时：

1. **Javascript 发起请求:**  例如，使用 `fetch('https://www.example.com')`。
2. **浏览器网络栈介入:**  浏览器会创建一个网络请求。
3. **主机名解析启动:**  网络栈需要将 `www.example.com` 解析为 IP 地址。
4. **到达 `HostResolverManager`:**  `HostResolverManager` 会接收到解析 `www.example.com` 的请求。
5. **任务创建和调度:**  `CreateAndStartJob` 会被调用，创建一个 `JobKey`，包含主机名、查询类型等信息。
6. **缓存检查:**  `MaybeServeFromCache` 会被调用，检查缓存中是否存在 `www.example.com` 的解析结果。
7. **配置读取:**  如果缓存未命中，`MaybeReadFromConfig` 可能会被调用，尝试从本地配置读取。
8. **hosts 文件查找:**  如果配置中没有，`ServeFromHosts` 会被调用，查找 hosts 文件。
9. **DNS 查询:**  如果以上都失败，`CreateTaskSequence` 会生成 DNS 查询任务，并交给 `PrioritizedDispatcher` 调度执行。这可能涉及到 `PushDnsTasks` 来决定是否使用安全 DNS。
10. **结果返回:**  解析完成后，IP 地址会被返回给网络栈，最终建立与 `www.example.com` 服务器的连接。

**逻辑推理的假设输入与输出：**

**假设输入：**
- 请求解析主机名: `example.test`
- 查询类型: `DnsQueryType::A` (IPv4 地址)
- 缓存中没有 `example.test` 的记录。
- 系统 hosts 文件中 `example.test` 对应的 IP 地址是 `192.0.2.1`.

**输出：**
- `ServeFromHosts` 函数会返回一个 `HostCache::Entry`，包含以下信息：
    - `error()`: `OK`
    - `addresses()`: 包含一个 `IPEndPoint`，其 IP 地址为 `192.0.2.1`，端口为 0。
    - `aliases()`: 空。
    - `source()`: `HostCache::Entry::SOURCE_HOSTS`。

**用户或编程常见的使用错误：**

1. **未正确配置 DNS 服务器:**  如果用户的操作系统或网络配置中 DNS 服务器设置不正确，`HostResolverManager` 最终的 DNS 查询可能会失败，导致网页无法加载。
2. **缓存策略配置不当:**  如果缓存策略配置过于激进，可能会导致解析结果长期不更新，影响用户体验。反之，如果禁用缓存，则会增加 DNS 查询的频率，可能降低性能。
3. **安全 DNS 配置错误:**  如果用户启用了安全 DNS，但配置的 DoH 服务器不可用或配置错误，可能导致解析失败。
4. **hosts 文件配置错误:**  用户或恶意软件可能修改 hosts 文件，将域名指向错误的 IP 地址，导致访问异常。
5. **编程时错误地使用 HostResolver API:**  开发者可能在代码中错误地设置解析参数，例如指定了错误的查询类型或缓存策略，导致解析行为不符合预期。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入 URL 并回车:**  例如 `https://www.example.com`。
2. **浏览器解析 URL:**  提取出主机名 `www.example.com`。
3. **浏览器发起网络请求:**  需要解析主机名。
4. **`HostResolver` (高级接口) 被调用:**  浏览器网络栈会使用 `HostResolver` 的 API 发起主机名解析请求。
5. **`HostResolverManager::Resolve` (或其他类似方法) 被调用:**  `HostResolver` 将请求传递给 `HostResolverManager` 进行处理。
6. **`CreateAndStartJob` 或类似方法被调用:**  `HostResolverManager` 开始创建和调度解析任务，如代码所示的流程。
7. **代码执行到 `MaybeServeFromCache`，`MaybeReadFromConfig`，`ServeFromHosts` 等函数:**  根据配置和缓存状态，逐步尝试不同的解析方式。
8. **如果需要进行 DNS 查询，则会涉及到 `PushDnsTasks` 和实际的 DNS 查询操作。**

通过在 `net/dns/host_resolver_manager.cc` 中设置断点，并模拟用户访问网页的操作，可以观察代码的执行流程，定位问题所在。

总而言之，这段代码是 Chromium 网络栈中负责核心 DNS 解析管理的关键部分，它协调各种解析策略，利用缓存和配置信息，并处理安全 DNS 等复杂场景，最终为浏览器提供可靠的主机名到 IP 地址的映射服务。

### 提示词
```
这是目录为net/dns/host_resolver_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ved.value()); });
        return resolved.value();
      }
    } else {
      NOTREACHED();
    }
  }

  return HostCache::Entry(ERR_DNS_CACHE_MISS, HostCache::Entry::SOURCE_UNKNOWN);
}

void HostResolverManager::CreateAndStartJob(JobKey key,
                                            std::deque<TaskType> tasks,
                                            RequestImpl* request) {
  DCHECK(!tasks.empty());

  auto jobit = jobs_.find(key);
  Job* job;
  if (jobit == jobs_.end()) {
    job = AddJobWithoutRequest(key, request->parameters().cache_usage,
                               request->host_cache(), std::move(tasks),
                               request->priority(), request->source_net_log());
    job->AddRequest(request);
    job->RunNextTask();
  } else {
    job = jobit->second.get();
    job->AddRequest(request);
  }
}

HostResolverManager::Job* HostResolverManager::AddJobWithoutRequest(
    JobKey key,
    ResolveHostParameters::CacheUsage cache_usage,
    HostCache* host_cache,
    std::deque<TaskType> tasks,
    RequestPriority priority,
    const NetLogWithSource& source_net_log) {
  auto new_job =
      std::make_unique<Job>(weak_ptr_factory_.GetWeakPtr(), key, cache_usage,
                            host_cache, std::move(tasks), priority,
                            source_net_log, tick_clock_, https_svcb_options_);
  auto insert_result = jobs_.emplace(std::move(key), std::move(new_job));
  auto& iterator = insert_result.first;
  bool is_new = insert_result.second;
  DCHECK(is_new);
  auto& job = iterator->second;
  job->OnAddedToJobMap(iterator);
  return job.get();
}

void HostResolverManager::CreateAndStartJobForServiceEndpointRequest(
    JobKey key,
    std::deque<TaskType> tasks,
    ServiceEndpointRequestImpl* request) {
  CHECK(!tasks.empty());

  auto jobit = jobs_.find(key);
  if (jobit == jobs_.end()) {
    Job* job = AddJobWithoutRequest(key, request->parameters().cache_usage,
                                    request->host_cache(), std::move(tasks),
                                    request->priority(), request->net_log());
    job->AddServiceEndpointRequest(request);
    job->RunNextTask();
  } else {
    jobit->second->AddServiceEndpointRequest(request);
  }
}

HostCache::Entry HostResolverManager::ResolveAsIP(DnsQueryTypeSet query_types,
                                                  bool resolve_canonname,
                                                  const IPAddress& ip_address) {
  DCHECK(ip_address.IsValid());
  DCHECK(!query_types.Has(DnsQueryType::UNSPECIFIED));

  // IP literals cannot resolve unless the query type is an address query that
  // allows addresses with the same address family as the literal. E.g., don't
  // return IPv6 addresses for IPv4 queries or anything for a non-address query.
  AddressFamily family = GetAddressFamily(ip_address);
  if (!query_types.Has(AddressFamilyToDnsQueryType(family))) {
    return HostCache::Entry(ERR_NAME_NOT_RESOLVED,
                            HostCache::Entry::SOURCE_UNKNOWN);
  }

  std::set<std::string> aliases;
  if (resolve_canonname) {
    aliases = {ip_address.ToString()};
  }
  return HostCache::Entry(OK, {IPEndPoint(ip_address, 0)}, std::move(aliases),
                          HostCache::Entry::SOURCE_UNKNOWN);
}

std::optional<HostCache::Entry> HostResolverManager::MaybeServeFromCache(
    HostCache* cache,
    const HostCache::Key& key,
    ResolveHostParameters::CacheUsage cache_usage,
    bool ignore_secure,
    const NetLogWithSource& source_net_log,
    std::optional<HostCache::EntryStaleness>* out_stale_info) {
  DCHECK(out_stale_info);
  *out_stale_info = std::nullopt;

  if (!cache)
    return std::nullopt;

  if (cache_usage == ResolveHostParameters::CacheUsage::DISALLOWED)
    return std::nullopt;

  // Local-only requests search the cache for non-local-only results.
  HostCache::Key effective_key = key;
  if (effective_key.host_resolver_source == HostResolverSource::LOCAL_ONLY)
    effective_key.host_resolver_source = HostResolverSource::ANY;

  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;
  HostCache::EntryStaleness staleness;
  if (cache_usage == ResolveHostParameters::CacheUsage::STALE_ALLOWED) {
    cache_result = cache->LookupStale(effective_key, tick_clock_->NowTicks(),
                                      &staleness, ignore_secure);
  } else {
    DCHECK(cache_usage == ResolveHostParameters::CacheUsage::ALLOWED);
    cache_result =
        cache->Lookup(effective_key, tick_clock_->NowTicks(), ignore_secure);
    staleness = HostCache::kNotStale;
  }
  if (cache_result) {
    *out_stale_info = std::move(staleness);
    source_net_log.AddEvent(
        NetLogEventType::HOST_RESOLVER_MANAGER_CACHE_HIT,
        [&] { return NetLogResults(cache_result->second); });
    return cache_result->second;
  }
  return std::nullopt;
}

std::optional<HostCache::Entry> HostResolverManager::MaybeReadFromConfig(
    const JobKey& key) {
  DCHECK(HasAddressType(key.query_types));
  if (!key.host.HasScheme()) {
    return std::nullopt;
  }
  std::optional<std::vector<IPEndPoint>> preset_addrs =
      dns_client_->GetPresetAddrs(key.host.AsSchemeHostPort());
  if (!preset_addrs)
    return std::nullopt;

  std::vector<IPEndPoint> filtered_addresses =
      FilterAddresses(std::move(*preset_addrs), key.query_types);
  if (filtered_addresses.empty())
    return std::nullopt;

  return HostCache::Entry(OK, std::move(filtered_addresses), /*aliases=*/{},
                          HostCache::Entry::SOURCE_CONFIG);
}

void HostResolverManager::StartBootstrapFollowup(
    JobKey key,
    HostCache* host_cache,
    const NetLogWithSource& source_net_log) {
  DCHECK_EQ(SecureDnsMode::kOff, key.secure_dns_mode);
  DCHECK(host_cache);

  key.secure_dns_mode = SecureDnsMode::kSecure;
  if (jobs_.count(key) != 0)
    return;

  Job* job = AddJobWithoutRequest(
      key, ResolveHostParameters::CacheUsage::ALLOWED, host_cache,
      {TaskType::SECURE_DNS}, RequestPriority::LOW, source_net_log);
  job->RunNextTask();
}

std::optional<HostCache::Entry> HostResolverManager::ServeFromHosts(
    std::string_view hostname,
    DnsQueryTypeSet query_types,
    bool default_family_due_to_no_ipv6,
    const std::deque<TaskType>& tasks) {
  DCHECK(!query_types.Has(DnsQueryType::UNSPECIFIED));
  // Don't attempt a HOSTS lookup if there is no DnsConfig or the HOSTS lookup
  // is going to be done next as part of a system lookup.
  if (!dns_client_ || !HasAddressType(query_types) ||
      (!tasks.empty() && tasks.front() == TaskType::SYSTEM))
    return std::nullopt;
  const DnsHosts* hosts = dns_client_->GetHosts();

  if (!hosts || hosts->empty())
    return std::nullopt;

  // HOSTS lookups are case-insensitive.
  std::string effective_hostname = base::ToLowerASCII(hostname);

  // If |address_family| is ADDRESS_FAMILY_UNSPECIFIED other implementations
  // (glibc and c-ares) return the first matching line. We have more
  // flexibility, but lose implicit ordering.
  // We prefer IPv6 because "happy eyeballs" will fall back to IPv4 if
  // necessary.
  std::vector<IPEndPoint> addresses;
  if (query_types.Has(DnsQueryType::AAAA)) {
    auto it = hosts->find(DnsHostsKey(effective_hostname, ADDRESS_FAMILY_IPV6));
    if (it != hosts->end()) {
      addresses.emplace_back(it->second, 0);
    }
  }

  if (query_types.Has(DnsQueryType::A)) {
    auto it = hosts->find(DnsHostsKey(effective_hostname, ADDRESS_FAMILY_IPV4));
    if (it != hosts->end()) {
      addresses.emplace_back(it->second, 0);
    }
  }

  // If got only loopback addresses and the family was restricted, resolve
  // again, without restrictions. See SystemHostResolverCall for rationale.
  if (default_family_due_to_no_ipv6 &&
      base::ranges::all_of(addresses, &IPAddress::IsIPv4,
                           &IPEndPoint::address) &&
      base::ranges::all_of(addresses, &IPAddress::IsLoopback,
                           &IPEndPoint::address)) {
    query_types.Put(DnsQueryType::AAAA);
    return ServeFromHosts(hostname, query_types, false, tasks);
  }

  if (addresses.empty())
    return std::nullopt;

  return HostCache::Entry(OK, std::move(addresses),
                          /*aliases=*/{}, HostCache::Entry::SOURCE_HOSTS);
}

std::optional<HostCache::Entry> HostResolverManager::ServeLocalhost(
    std::string_view hostname,
    DnsQueryTypeSet query_types,
    bool default_family_due_to_no_ipv6) {
  DCHECK(!query_types.Has(DnsQueryType::UNSPECIFIED));

  std::vector<IPEndPoint> resolved_addresses;
  if (!HasAddressType(query_types) ||
      !ResolveLocalHostname(hostname, &resolved_addresses)) {
    return std::nullopt;
  }

  if (default_family_due_to_no_ipv6 && query_types.Has(DnsQueryType::A) &&
      !query_types.Has(DnsQueryType::AAAA)) {
    // The caller disabled the AAAA query due to lack of detected IPv6 support.
    // (See SystemHostResolverCall for rationale).
    query_types.Put(DnsQueryType::AAAA);
  }
  std::vector<IPEndPoint> filtered_addresses =
      FilterAddresses(std::move(resolved_addresses), query_types);
  return HostCache::Entry(OK, std::move(filtered_addresses), /*aliases=*/{},
                          HostCache::Entry::SOURCE_UNKNOWN);
}

void HostResolverManager::CacheResult(HostCache* cache,
                                      const HostCache::Key& key,
                                      const HostCache::Entry& entry,
                                      base::TimeDelta ttl) {
  // Don't cache an error unless it has a positive TTL.
  if (cache && (entry.error() == OK || ttl.is_positive()))
    cache->Set(key, entry, tick_clock_->NowTicks(), ttl);
}

std::unique_ptr<HostResolverManager::Job> HostResolverManager::RemoveJob(
    JobMap::iterator job_it) {
  CHECK(job_it != jobs_.end(), base::NotFatalUntil::M130);
  DCHECK(job_it->second);
  DCHECK_EQ(1u, jobs_.count(job_it->first));

  std::unique_ptr<Job> job;
  job_it->second.swap(job);
  jobs_.erase(job_it);
  job->OnRemovedFromJobMap();

  return job;
}

SecureDnsMode HostResolverManager::GetEffectiveSecureDnsMode(
    SecureDnsPolicy secure_dns_policy) {
  // Use switch() instead of if() to ensure that all policies are handled.
  switch (secure_dns_policy) {
    case SecureDnsPolicy::kDisable:
    case SecureDnsPolicy::kBootstrap:
      return SecureDnsMode::kOff;
    case SecureDnsPolicy::kAllow:
      break;
  }

  const DnsConfig* config =
      dns_client_ ? dns_client_->GetEffectiveConfig() : nullptr;

  SecureDnsMode secure_dns_mode = SecureDnsMode::kOff;
  if (config) {
    secure_dns_mode = config->secure_dns_mode;
  }
  return secure_dns_mode;
}

bool HostResolverManager::ShouldForceSystemResolverDueToTestOverride() const {
  // If tests have provided a catch-all DNS block and then disabled it, check
  // that we are not at risk of sending queries beyond the local network.
  if (HostResolverProc::GetDefault() && system_resolver_disabled_for_testing_) {
    DCHECK(dns_client_);
    DCHECK(dns_client_->GetEffectiveConfig());
    DCHECK(base::ranges::none_of(dns_client_->GetEffectiveConfig()->nameservers,
                                 &IPAddress::IsPubliclyRoutable,
                                 &IPEndPoint::address))
        << "Test could query a publicly-routable address.";
  }
  return !host_resolver_system_params_.resolver_proc &&
         HostResolverProc::GetDefault() &&
         !system_resolver_disabled_for_testing_;
}

void HostResolverManager::PushDnsTasks(bool system_task_allowed,
                                       SecureDnsMode secure_dns_mode,
                                       bool insecure_tasks_allowed,
                                       bool allow_cache,
                                       bool prioritize_local_lookups,
                                       ResolveContext* resolve_context,
                                       std::deque<TaskType>* out_tasks) {
  DCHECK(dns_client_);
  DCHECK(dns_client_->GetEffectiveConfig());

  // If a catch-all DNS block has been set for unit tests, we shouldn't send
  // DnsTasks. It is still necessary to call this method, however, so that the
  // correct cache tasks for the secure dns mode are added.
  const bool dns_tasks_allowed = !ShouldForceSystemResolverDueToTestOverride();
  // Upgrade the insecure DnsTask depending on the secure dns mode.
  switch (secure_dns_mode) {
    case SecureDnsMode::kSecure:
      DCHECK(!allow_cache ||
             out_tasks->front() == TaskType::SECURE_CACHE_LOOKUP);
      // Policy misconfiguration can put us in secure DNS mode without any DoH
      // servers to query. See https://crbug.com/1326526.
      if (dns_tasks_allowed && dns_client_->CanUseSecureDnsTransactions())
        out_tasks->push_back(TaskType::SECURE_DNS);
      break;
    case SecureDnsMode::kAutomatic:
      DCHECK(!allow_cache || out_tasks->front() == TaskType::CACHE_LOOKUP);
      if (dns_client_->FallbackFromSecureTransactionPreferred(
              resolve_context)) {
        // Don't run a secure DnsTask if there are no available DoH servers.
        if (dns_tasks_allowed && insecure_tasks_allowed)
          out_tasks->push_back(TaskType::DNS);
      } else if (prioritize_local_lookups) {
        // If local lookups are prioritized, the cache should be checked for
        // both secure and insecure results prior to running a secure DnsTask.
        // The task sequence should already contain the appropriate cache task.
        if (dns_tasks_allowed) {
          out_tasks->push_back(TaskType::SECURE_DNS);
          if (insecure_tasks_allowed)
            out_tasks->push_back(TaskType::DNS);
        }
      } else {
        if (allow_cache) {
          // Remove the initial cache lookup task so that the secure and
          // insecure lookups can be separated.
          out_tasks->pop_front();
          out_tasks->push_back(TaskType::SECURE_CACHE_LOOKUP);
        }
        if (dns_tasks_allowed)
          out_tasks->push_back(TaskType::SECURE_DNS);
        if (allow_cache)
          out_tasks->push_back(TaskType::INSECURE_CACHE_LOOKUP);
        if (dns_tasks_allowed && insecure_tasks_allowed)
          out_tasks->push_back(TaskType::DNS);
      }
      break;
    case SecureDnsMode::kOff:
      DCHECK(!allow_cache || IsLocalTask(out_tasks->front()));
      if (dns_tasks_allowed && insecure_tasks_allowed)
        out_tasks->push_back(TaskType::DNS);
      break;
    default:
      NOTREACHED();
  }

  constexpr TaskType kWantTasks[] = {TaskType::DNS, TaskType::SECURE_DNS};
  const bool no_dns_or_secure_tasks =
      base::ranges::find_first_of(*out_tasks, kWantTasks) == out_tasks->end();
  // The system resolver can be used as a fallback for a non-existent or
  // failing DnsTask if allowed by the request parameters.
  if (system_task_allowed &&
      (no_dns_or_secure_tasks || allow_fallback_to_systemtask_))
    out_tasks->push_back(TaskType::SYSTEM);
}

void HostResolverManager::CreateTaskSequence(
    const JobKey& job_key,
    ResolveHostParameters::CacheUsage cache_usage,
    SecureDnsPolicy secure_dns_policy,
    std::deque<TaskType>* out_tasks) {
  DCHECK(out_tasks->empty());

  // A cache lookup should generally be performed first. For jobs involving a
  // DnsTask, this task may be replaced.
  bool allow_cache =
      cache_usage != ResolveHostParameters::CacheUsage::DISALLOWED;
  if (secure_dns_policy == SecureDnsPolicy::kBootstrap) {
    DCHECK_EQ(SecureDnsMode::kOff, job_key.secure_dns_mode);
    if (allow_cache)
      out_tasks->push_front(TaskType::INSECURE_CACHE_LOOKUP);
    out_tasks->push_front(TaskType::CONFIG_PRESET);
    if (allow_cache)
      out_tasks->push_front(TaskType::SECURE_CACHE_LOOKUP);
  } else if (allow_cache) {
    if (job_key.secure_dns_mode == SecureDnsMode::kSecure) {
      out_tasks->push_front(TaskType::SECURE_CACHE_LOOKUP);
    } else {
      out_tasks->push_front(TaskType::CACHE_LOOKUP);
    }
  }
  out_tasks->push_back(TaskType::HOSTS);

  // Determine what type of task a future Job should start.
  bool prioritize_local_lookups =
      cache_usage ==
      HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;

  const bool has_address_type = HasAddressType(job_key.query_types);

  switch (job_key.source) {
    case HostResolverSource::ANY:
      // Records DnsClient capability metrics, only when `source` is ANY. This
      // is to avoid the metrics being skewed by mechanical requests of other
      // source types.
      RecordDnsClientCapabilityMetrics(dns_client_.get());
      // Force address queries with canonname to use HostResolverSystemTask to
      // counter poor CNAME support in DnsTask. See https://crbug.com/872665
      //
      // Otherwise, default to DnsTask (with allowed fallback to
      // HostResolverSystemTask for address queries). But if hostname appears to
      // be an MDNS name (ends in *.local), go with HostResolverSystemTask for
      // address queries and MdnsTask for non- address queries.
      if ((job_key.flags & HOST_RESOLVER_CANONNAME) && has_address_type) {
        out_tasks->push_back(TaskType::SYSTEM);
      } else if (!ResemblesMulticastDNSName(job_key.host.GetHostname())) {
        bool system_task_allowed =
            has_address_type &&
            job_key.secure_dns_mode != SecureDnsMode::kSecure;
        if (dns_client_ && dns_client_->GetEffectiveConfig()) {
          bool insecure_allowed =
              dns_client_->CanUseInsecureDnsTransactions() &&
              !dns_client_->FallbackFromInsecureTransactionPreferred() &&
              (has_address_type ||
               dns_client_->CanQueryAdditionalTypesViaInsecureDns());
          PushDnsTasks(system_task_allowed, job_key.secure_dns_mode,
                       insecure_allowed, allow_cache, prioritize_local_lookups,
                       &*job_key.resolve_context, out_tasks);
        } else if (system_task_allowed) {
          out_tasks->push_back(TaskType::SYSTEM);
        }
      } else if (has_address_type) {
        // For *.local address queries, try the system resolver even if the
        // secure dns mode is SECURE. Public recursive resolvers aren't expected
        // to handle these queries.
        out_tasks->push_back(TaskType::SYSTEM);
      } else {
        out_tasks->push_back(TaskType::MDNS);
      }
      break;
    case HostResolverSource::SYSTEM:
      out_tasks->push_back(TaskType::SYSTEM);
      break;
    case HostResolverSource::DNS:
      if (dns_client_ && dns_client_->GetEffectiveConfig()) {
        bool insecure_allowed =
            dns_client_->CanUseInsecureDnsTransactions() &&
            (has_address_type ||
             dns_client_->CanQueryAdditionalTypesViaInsecureDns());
        PushDnsTasks(false /* system_task_allowed */, job_key.secure_dns_mode,
                     insecure_allowed, allow_cache, prioritize_local_lookups,
                     &*job_key.resolve_context, out_tasks);
      }
      break;
    case HostResolverSource::MULTICAST_DNS:
      out_tasks->push_back(TaskType::MDNS);
      break;
    case HostResolverSource::LOCAL_ONLY:
      // If no external source allowed, a job should not be created or started
      break;
  }

  // `HOST_RESOLVER_CANONNAME` is only supported through system resolution.
  if (job_key.flags & HOST_RESOLVER_CANONNAME) {
    DCHECK(base::ranges::find(*out_tasks, TaskType::DNS) == out_tasks->end());
    DCHECK(base::ranges::find(*out_tasks, TaskType::MDNS) == out_tasks->end());
  }
}

namespace {

bool RequestWillUseWiFi(handles::NetworkHandle network) {
  NetworkChangeNotifier::ConnectionType connection_type;
  if (network == handles::kInvalidNetworkHandle)
    connection_type = NetworkChangeNotifier::GetConnectionType();
  else
    connection_type = NetworkChangeNotifier::GetNetworkConnectionType(network);

  return connection_type == NetworkChangeNotifier::CONNECTION_WIFI;
}

}  // namespace

void HostResolverManager::FinishIPv6ReachabilityCheck(
    CompletionOnceCallback callback,
    int rv) {
  SetLastIPv6ProbeResult((rv == OK) ? true : false);
  std::move(callback).Run(OK);
  if (!ipv6_request_callbacks_.empty()) {
    std::vector<CompletionOnceCallback> tmp_request_callbacks;
    ipv6_request_callbacks_.swap(tmp_request_callbacks);
    for (auto& request_callback : tmp_request_callbacks) {
      std::move(request_callback).Run(OK);
    }
  }
}

int HostResolverManager::StartIPv6ReachabilityCheck(
    const NetLogWithSource& net_log,
    ClientSocketFactory* client_socket_factory,
    CompletionOnceCallback callback) {
  // Don't bother checking if the request will use WiFi and IPv6 is assumed to
  // not work on WiFi.
  if (!check_ipv6_on_wifi_ && RequestWillUseWiFi(target_network_)) {
    probing_ipv6_ = false;
    last_ipv6_probe_result_ = false;
    last_ipv6_probe_time_ = base::TimeTicks();
    return OK;
  }

  if (probing_ipv6_) {
    ipv6_request_callbacks_.push_back(std::move(callback));
    return ERR_IO_PENDING;
  }
  // Cache the result for kIPv6ProbePeriodMs (measured from after
  // StartGloballyReachableCheck() completes).
  int rv = OK;
  bool cached = true;
  if (last_ipv6_probe_time_.is_null() ||
      (tick_clock_->NowTicks() - last_ipv6_probe_time_).InMilliseconds() >
          kIPv6ProbePeriodMs) {
    probing_ipv6_ = true;
    rv = StartGloballyReachableCheck(
        IPAddress(kIPv6ProbeAddress), net_log, client_socket_factory,
        base::BindOnce(&HostResolverManager::FinishIPv6ReachabilityCheck,
                       weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
    if (rv != ERR_IO_PENDING) {
      SetLastIPv6ProbeResult((rv == OK) ? true : false);
      rv = OK;
    }
    cached = false;
  }
  net_log.AddEvent(
      NetLogEventType::HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK, [&] {
        return NetLogIPv6AvailableParams(last_ipv6_probe_result_, cached);
      });
  return rv;
}

void HostResolverManager::SetLastIPv6ProbeResult(bool last_ipv6_probe_result) {
  probing_ipv6_ = false;
  last_ipv6_probe_result_ = last_ipv6_probe_result;
  last_ipv6_probe_time_ = tick_clock_->NowTicks();
}

int HostResolverManager::StartGloballyReachableCheck(
    const IPAddress& dest,
    const NetLogWithSource& net_log,
    ClientSocketFactory* client_socket_factory,
    CompletionOnceCallback callback) {
  std::unique_ptr<DatagramClientSocket> probing_socket =
      client_socket_factory->CreateDatagramClientSocket(
          DatagramSocket::DEFAULT_BIND, net_log.net_log(), net_log.source());
  DatagramClientSocket* probing_socket_ptr = probing_socket.get();
  auto refcounted_socket = base::MakeRefCounted<
      base::RefCountedData<std::unique_ptr<DatagramClientSocket>>>(
      std::move(probing_socket));
  int rv = probing_socket_ptr->ConnectAsync(
      IPEndPoint(dest, GetPortForGloballyReachableCheck()),
      base::BindOnce(&HostResolverManager::RunFinishGloballyReachableCheck,
                     weak_ptr_factory_.GetWeakPtr(), refcounted_socket,
                     std::move(callback)));
  if (rv != ERR_IO_PENDING) {
    rv = FinishGloballyReachableCheck(probing_socket_ptr, rv) ? OK : ERR_FAILED;
  }
  return rv;
}

bool HostResolverManager::FinishGloballyReachableCheck(
    DatagramClientSocket* socket,
    int rv) {
  if (rv != OK) {
    return false;
  }
  IPEndPoint endpoint;
  rv = socket->GetLocalAddress(&endpoint);

  if (rv != OK) {
    return false;
  }
  const IPAddress& address = endpoint.address();

  if (address.IsLinkLocal()) {
    return false;
  }

  if (address.IsIPv6()) {
    const uint8_t kTeredoPrefix[] = {0x20, 0x01, 0, 0};
    if (IPAddressStartsWith(address, kTeredoPrefix)) {
      return false;
    }
  }

  return true;
}

void HostResolverManager::RunFinishGloballyReachableCheck(
    scoped_refptr<base::RefCountedData<std::unique_ptr<DatagramClientSocket>>>
        socket,
    CompletionOnceCallback callback,
    int rv) {
  bool is_reachable = FinishGloballyReachableCheck(socket->data.get(), rv);
  std::move(callback).Run(is_reachable ? OK : ERR_FAILED);
}

void HostResolverManager::RunLoopbackProbeJob() {
  RunHaveOnlyLoopbackAddressesJob(
      base::BindOnce(&HostResolverManager::SetHaveOnlyLoopbackAddresses,
                     weak_ptr_factory_.GetWeakPtr()));
}

void HostResolverManager::RemoveAllJobs(const ResolveContext* context) {
  for (auto it = jobs_.begin(); it != jobs_.end();) {
    const JobKey& key = it->first;
    if (&*key.resolve_context == context) {
      RemoveJob(it++);
    } else {
      ++it;
    }
  }
}

void HostResolverManager::AbortJobsWithoutTargetNetwork(bool in_progress_only) {
  // In Abort, a Request callback could spawn new Jobs with matching keys, so
  // first collect and remove all running jobs from `jobs_`.
  std::vector<std::unique_ptr<Job>> jobs_to_abort;
  for (auto it = jobs_.begin(); it != jobs_.end();) {
    Job* job = it->second.get();
    if (!job->HasTargetNetwork() && (!in_progress_only || job->is_running())) {
      jobs_to_abort.push_back(RemoveJob(it++));
    } else {
      ++it;
    }
  }

  // Pause the dispatcher so it won't start any new dispatcher jobs while
  // aborting the old ones.  This is needed so that it won't start the second
  // DnsTransaction for a job in `jobs_to_abort` if the DnsConfig just became
  // invalid.
  PrioritizedDispatcher::Limits limits = dispatcher_->GetLimits();
  dispatcher_->SetLimits(
      PrioritizedDispatcher::Limits(limits.reserved_slots.size(), 0));

  // Life check to bail once `this` is deleted.
  base::WeakPtr<HostResolverManager> self = weak_ptr_factory_.GetWeakPtr();

  // Then Abort them.
  for (size_t i = 0; self.get() && i < jobs_to_abort.size(); ++i) {
    jobs_to_abort[i]->Abort();
  }

  if (self)
    dispatcher_->SetLimits(limits);
}

void HostResolverManager::AbortInsecureDnsTasks(int error, bool fallback_only) {
  // Aborting jobs potentially modifies |jobs_| and may even delete some jobs.
  // Create safe closures of all current jobs.
  std::vector<base::OnceClosure> job_abort_closures;
  for (auto& job : jobs_) {
    job_abort_closures.push_back(
        job.second->GetAbortInsecureDnsTaskClosure(error, fallback_only));
  }

  // Pause the dispatcher so it won't start any new dispatcher jobs while
  // aborting the old ones.  This is needed so that it won't start the second
  // DnsTransaction for a job if the DnsConfig just changed.
  PrioritizedDispatcher::Limits limits = dispatcher_->GetLimits();
  dispatcher_->SetLimits(
      PrioritizedDispatcher::Limits(limits.reserved_slots.size(), 0));

  for (base::OnceClosure& closure : job_abort_closures)
    std::move(closure).Run();

  dispatcher_->SetLimits(limits);
}

// TODO(crbug.com/40641277): Consider removing this and its usage.
void HostResolverManager::TryServingAllJobsFromHosts() {
  if (!dns_client_ || !dns_client_->GetEffectiveConfig())
    return;

  // TODO(szym): Do not do this if nsswitch.conf instructs not to.
  // http://crbug.com/117655

  // Life check to bail once |this| is deleted.
  base::WeakPtr<HostResolverManager> self = weak_ptr_factory_.GetWeakPtr();

  for (auto it = jobs_.begin(); self.get() && it != jobs_.end();) {
    Job* job = it->second.get();
    ++it;
    // This could remove |job| from |jobs_|, but iterator will remain valid.
    job->ServeFromHosts();
  }
}

void HostResolverManager::OnIPAddressChanged() {
  DCHECK(!IsBoundToNetwork());
  last_ipv6_probe_time_ = base::TimeTicks();
  // Abandon all ProbeJobs.
  probe_weak_ptr_factory_.InvalidateWeakPtrs();
  InvalidateCaches();
#if (BUILDFLAG(IS_POSIX) && !BUILDFLAG(IS_APPLE) && !BUILDFLAG(IS_ANDROID)) || \
    BUILDFLAG(IS_FUCHSIA)
  RunLoopbackProbeJob();
#endif
  AbortJobsWithoutTargetNetwork(true /* in_progress_only */);
  // `this` may be deleted inside AbortJobsWithoutTargetNetwork().
}

void HostResolverManager::OnConnectionTypeChanged(
    NetworkChangeNotifier::ConnectionType type) {
  DCHECK(!IsBoundToNetwork());
  UpdateConnectionType(type);
}

void HostResolverManager::OnSystemDnsConfigChanged(
    std::optional<DnsConfig> config) {
  DCHECK(!IsBoundToNetwork());
  // If tests have provided a catch-all DNS block and then disabled it, check
  // that we are not at risk of sending queries beyond the local network.
  if (HostResolverProc::GetDefault() && system_resolver_disabled_for_testing_ &&
      config.has_value()) {
    DCHECK(base::ranges::none_of(config->nameservers,
                                 &IPAddress::IsPubliclyRoutable,
                                 &IPEndPoint::address))
        << "Test could query a publicly-routable address.";
  }

  bool changed = false;
  bool transactions_allowed_before = false;
  if (dns_client_) {
    transactions_allowed_before = dns_client_->CanUseSecureDnsTransactions() ||
                                  dns_client_->CanUseInsecureDnsTransactions();
    changed = dns_client_->SetSystemConfig(std::move(config));
  }

  // Always invalidate cache, even if no change is seen.
  InvalidateCaches();

  if (changed) {
    // Need to update jobs iff transactions were previously allowed because
    // in-progress jobs may be running using a now-invalid configuration.
    if (transactions_allowed_before)
      UpdateJobsForChangedConfig();
  }
}

void HostResolverManager::UpdateJobsForChangedConfig() {
  // Life check to bail once `this` is deleted.
  base::WeakPtr<HostResolverManager> self = weak_ptr_factory_.GetWeakPtr();

  // Existing jobs that were set up using the nameservers and secure dns mode
  // from the original config need to be aborted (does not apply to jobs
  // targeting a specific network).
  AbortJobsWithoutTargetNetwork(false /* in_progress_only */);

  // `this` may be deleted inside AbortJobsWithoutTargetNetwork().
  if (self.get())
    TryServingAllJobsFromHosts();
}

void HostResolverManager::OnFallbackResolve(int dns_task_error) {
  DCHECK(dns_client_);
  DCHECK_NE(OK, dns_task_error);

  // Nothing to do if DnsTask is already not preferred.
  if (dns_client_->FallbackFromInsecureTransactionPreferred())
    return;

  dns_client_->IncrementInsecureFallbackFailures();

  // If DnsClient became not preferred, fallback all fallback-allowed insecure
  // DnsTasks to HostResolverSystemTasks.
  if (dns_client_->FallbackFromInsecureTransactionPreferred())
    AbortInsecureDnsTasks(ERR_FAILED, true /* fallback_only */);
}

int HostResolverManager::GetOrCreateMdnsClient(MDnsClient** out_client) {
#if BUILDFLAG(ENABLE_MDNS)
  if (!mdns_client_) {
    if (!mdns_socket_factory_)
      mdns_socket_factory_ = std::make_unique<MDnsSocketFactoryImpl>(net_log_);
    mdns_client_ = MDnsClient::CreateDefault();
  }

  int rv = OK;
  if (!mdns_client_->IsListening())
    rv = mdns_client_->StartListening(mdns_socket_factory_.get());

  DCHECK_NE(ERR_IO_PENDING, rv);
  DCHECK(rv != OK || mdns_client_->IsListening());
  if (rv == OK)
    *out_client = mdns_client_.get();
  return rv;
#else
  // Should not request MDNS resoltuion unless MDNS is enabled.
  NOTREACHED();
#endif
}

void HostResolverManager::InvalidateCaches(bool network_change) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!invalidation_in_progress_);

#if DCHECK_IS_ON()
  base::WeakPtr<HostResolverManager> self_ptr = weak_ptr_factory_.GetWeakPtr();
  size_t num_jobs = jobs_.size();
#endif

  invalidation_in_progress_ = true;
  for (auto& context : registered_contexts_) {
    context.InvalidateCachesAndPerSessionData(
        dns_client_ ? dns_client_->GetCurrentSession() : nullptr,
        network_change);
  }
  invalidation_in_progress_ = false;

#if DCHECK_IS_ON()
  // Sanity checks that invalidation does not have reentrancy issues.
  DCHECK(self_ptr);
  DCHECK_EQ(num_jobs, jobs_.size());
#endif
}

void HostResolverManager::UpdateConnectionType(
    NetworkChangeNotifier::ConnectionType type) {
  host_resolver_system_params_.unresponsive_delay =
      GetTimeDeltaForConnectionTypeFromFieldTrialOrDefault(
          "DnsUnresponsiveDelayMsByConnectionType",
          HostResolverSystemTask::Params::kDnsDefaultUnresponsiveDelay, type);

  // Note that NetworkChangeNotifier always sends a CONNECTION_NONE notification
  // before non-NONE notifications. This check therefore just ensures each
  // connection change notification is handled once and has nothing to do with
  // whether the change is to offline or online.
  if (type == NetworkChangeNotifier::CONNECTION_NONE && dns_client_) {
    dns_client_->ReplaceCurrentSession();
    InvalidateCaches(true /* network_change */);
  }
}

std::unique_ptr<DnsProbeRunner> HostResolverManager::CreateDohProbeRunner(
    ResolveContext* resolve_context) {
  DCHECK(resolve_context);
  DCHECK(registered_contexts_.HasObserver(resolve_context));
  if (!dns_client_ || !dns_client_->CanUseSecureDnsTransactions()) {
    return nullptr;
  }

  return dns_client_->GetTransactio
```