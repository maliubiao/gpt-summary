Response:
The user wants a summary of the functionalities of the provided C++ code snippet from Chromium's network stack. They also want to know:
1. **Relationship with JavaScript:** Does this code interact with JavaScript in any way?
2. **Logic and Examples:** Can we provide examples of the logic with hypothetical inputs and outputs?
3. **Common Errors:** What are some common user or programming errors related to this code?
4. **User Journey:** How does a user action lead to this code being executed (debugging context)?
5. **Overall Functionality (Summary of Part 2):**  A concise summary of the code provided in this part.

Let's break down the code to understand its purpose. It seems to be focused on managing and persisting HTTP server properties, specifically:

* **Alternative Services (Alt-Svc):**  Storing and retrieving information about alternative ways to connect to a server (e.g., using a different protocol or port).
* **Server Network Stats:**  Keeping track of network performance metrics for servers.
* **QUIC Server Information:** Managing information related to QUIC connections.
* **Broken Alternative Services:**  Tracking alternative services that are known to be broken.
* **Canonical Host Mapping:**  Handling the concept of canonical hostnames for certain domains.
* **Persistence:**  Loading and saving these properties to disk (using `properties_manager_`).
* **Initialization:** Handling the loading of persisted data.

Now, let's address each of the user's requests:

1. **JavaScript Relationship:**  While this C++ code directly doesn't *execute* JavaScript, it manages data that *influences* how network requests are made. JavaScript in a web page can trigger network requests. The browser uses this stored information to optimize those requests (e.g., by trying an Alt-Svc).

2. **Logic and Examples:** We can create scenarios for different functions, like `SetAlternativeService`.

3. **Common Errors:**  We can consider scenarios where the stored properties might be outdated or incorrect.

4. **User Journey:**  We need to think about user actions that trigger network requests and how the browser uses this stored information.

5. **Overall Functionality (Part 2):**  This part seems to focus heavily on setting and clearing server properties, as well as handling the loading and merging of persisted data.

Plan:
* Summarize the overall functionality of the file based on both parts.
* Explain the relationship with JavaScript and provide an example.
* Create hypothetical input/output examples for key functions like `SetAlternativeService`.
* Identify common user/programming errors.
* Describe a typical user journey.
* Summarize the specific functionalities in Part 2.这是`net/http/http_server_properties.cc`文件第二部分的分析，延续了第一部分对HTTP服务器属性的管理功能。 总体来说，这部分代码主要负责**设置、清除和获取服务器的各种属性信息，以及处理从持久化存储加载数据和合并数据的逻辑。**

以下是更详细的功能分解：

**主要功能:**

* **设置和清除服务器属性:**
    * `SetAlternativeService()`:  设置指定Origin的备用服务信息 (Alternative Services)。如果新的备用服务信息与现有信息不同，会触发写入持久化存储的操作。
    * `ClearAlternativeService()`: 清除指定Origin的备用服务信息。
    * `SetServerNetworkStatsInternal()`: 设置指定服务器的网络统计信息。
    * `ClearServerNetworkStatsInternal()`: 清除指定服务器的网络统计信息。
* **获取服务器属性:**
    * `GetServerNetworkStatsInternal()`: 获取指定服务器的网络统计信息。
    * `GetIteratorWithAlternativeServiceInfo()`: 获取包含指定Origin备用服务信息的迭代器，同时考虑了 canonical host 的情况。
    * `GetCanonicalAltSvcHost()`: 获取指定服务器的 canonical Alt-Svc 主机。
    * `GetCanonicalServerInfoHost()`: 获取指定 QUIC 服务器信息的 canonical 主机。
    * `GetCanonicalSuffix()`:  判断一个主机名是否以已知的 canonical 后缀结尾。
* **处理 canonical host:**
    * 当为某个Origin设置备用服务时，如果该Origin属于一个已知的 canonical 域（例如google.com对应.google.），则会记录其 canonical 的备用服务信息。
    * 提供了 `RemoveAltSvcCanonicalHost()` 用于移除 canonical Alt-Svc 主机信息。
    * `UpdateCanonicalServerInfoMap()` 用于更新 canonical QUIC 服务器信息映射。
* **加载和合并持久化数据:**
    * `OnPrefsLoaded()`: 当从持久化存储加载服务器属性数据后被调用，负责将加载的数据合并到内存中的数据结构中。
    * `OnServerInfoLoaded()`: 处理加载的服务器信息（例如支持SPDY、备用服务等）。
    * `OnLastLocalAddressWhenQuicWorkedLoaded()`: 处理加载的上次QUIC可用的本地地址。
    * `OnQuicServerInfoMapLoaded()`: 处理加载的 QUIC 服务器信息。
    * `OnBrokenAndRecentlyBrokenAlternativeServicesLoaded()`: 处理加载的已损坏和最近损坏的备用服务列表。
* **持久化数据:**
    * `MaybeQueueWriteProperties()`: 尝试将服务器属性数据写入持久化存储，使用了定时器来避免频繁写入。
    * `FlushWritePropertiesForTesting()`:  用于测试，立即将服务器属性写入持久化存储。
    * `WriteProperties()`: 实际执行将服务器属性写入持久化存储的操作。

**与 Javascript 的关系:**

虽然这段 C++ 代码本身不直接执行 Javascript，但它管理的数据 **直接影响着浏览器在执行 Javascript 发起的网络请求时的行为。**

**举例说明:**

假设一个网页中的 Javascript 代码尝试访问 `https://www.example.com`。

1. **Javascript 发起请求:**  `fetch('https://www.example.com/data.json')`
2. **浏览器查找备用服务:**  在发起实际的网络连接前，浏览器会查询 `HttpServerProperties`，特别是 `GetIteratorWithAlternativeServiceInfo()`，来查看是否存储了 `https://www.example.com` 的备用服务。
3. **使用备用服务 (假设存在):**  如果 `HttpServerProperties` 中存储了 `www.example.com:443` 的一个备用服务是 `h2://alt.example.com:443`，浏览器可能会尝试先连接到 `alt.example.com:443` (如果该备用服务没有被标记为损坏)。
4. **优化连接:**  使用备用服务可以减少 DNS 查询和 TCP 握手等开销，从而提高页面加载速度。

**逻辑推理与示例 (以 `SetAlternativeService` 为例):**

**假设输入:**

* `origin`:  `https://www.example.com:443`
* `network_anonymization_key`:  (一个 NetworkAnonymizationKey 对象，例如为空)
* `alternative_service_info_vector`: 一个包含以下 `AlternativeServiceInfo` 的 vector:
    * `h2://alt.example.com:443`, expiration: 明天的时间戳, advertised_versions: [ "h3-29", "h3-Q050" ]

**现有状态 (假设 `server_info_map_` 中已存在 `https://www.example.com:443` 的条目，但备用服务信息为空):**

**输出:**

* `server_info_map_` 中 `https://www.example.com:443` 对应的条目的 `alternative_services` 将被设置为输入的 `alternative_service_info_vector`。
* 由于是新的备用服务信息，`MaybeQueueWriteProperties()` 会被调用，最终将信息写入持久化存储。

**假设输入 (与现有信息部分相同，但 expiration 时间不同):**

* `origin`:  `https://www.example.com:443`
* `network_anonymization_key`:  (一个 NetworkAnonymizationKey 对象，例如为空)
* `alternative_service_info_vector`: 一个包含以下 `AlternativeServiceInfo` 的 vector:
    * `h2://alt.example.com:443`, expiration: **后天**的时间戳, advertised_versions: [ "h3-29", "h3-Q050" ]

**现有状态 (假设 `server_info_map_` 中已存在 `https://www.example.com:443` 的条目，且 `alternative_services` 包含 `h2://alt.example.com:443`，但 expiration 是明天):**

**输出:**

* `server_info_map_` 中 `https://www.example.com:443` 对应的条目的 `alternative_services` 的 expiration 时间将被更新为后天的时间戳。
* 由于 expiration 时间相差超过两倍或小于一半，`MaybeQueueWriteProperties()` 会被调用。

**用户或编程常见的使用错误:**

* **手动修改持久化存储:** 用户或恶意程序直接修改浏览器存储的 HTTP 服务器属性数据可能会导致程序行为异常，例如连接到错误的服务器或无法建立连接。
* **不正确的 canonical 后缀配置:** 如果 canonical 后缀配置不正确，可能会导致备用服务信息关联到错误的 canonical 主机，影响备用服务的查找和使用。
* **高频率地设置备用服务信息:** 频繁更新备用服务信息可能导致频繁的磁盘写入操作，影响性能。`MaybeQueueWriteProperties()` 使用定时器来缓解这个问题。
* **在不适当的时机清除备用服务信息:** 例如，在网络状况不稳定时清除所有备用服务信息可能会导致浏览器在一段时间内无法利用备用服务优化连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接，发起一个 HTTP 或 HTTPS 请求。**
2. **浏览器解析 URL，获取 Origin。**
3. **在建立连接之前，网络栈会查询 `HttpServerProperties` 以获取该 Origin 的备用服务信息。**  相关的函数可能是 `GetIteratorWithAlternativeServiceInfo()`。
4. **如果服务器在 HTTP 响应头中返回了 `Alt-Svc` 头部，**浏览器会解析该头部，并调用 `SetAlternativeService()` 将新的备用服务信息存储到 `HttpServerProperties` 中。
5. **如果连接过程中出现网络错误，导致某个备用服务连接失败，** `HttpServerProperties` 中的相关函数可能会被调用来标记该备用服务为已损坏。
6. **浏览器启动时，会从持久化存储加载 HTTP 服务器属性信息，** 触发 `OnPrefsLoaded()` 及其相关的加载函数。

**第 2 部分功能归纳:**

这部分代码主要负责 **HTTP 服务器属性的设置、清除、获取以及加载和合并来自持久化存储的数据。** 它详细实现了如何管理服务器的备用服务信息、网络统计信息以及与 QUIC 相关的属性，并处理了 canonical host 的逻辑。  其核心目标是维护一个关于服务器连接特性的本地缓存，以便浏览器能够更智能、更高效地建立网络连接。

Prompt: 
```
这是目录为net/http/http_server_properties.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
etwork_anonymization_key);
    // Don't bother moving to front when erasing information.
    auto it = server_info_map_.Peek(
        CreateServerInfoKey(origin, network_anonymization_key));

    if (it == server_info_map_.end() ||
        !it->second.alternative_services.has_value()) {
      return;
    }

    it->second.alternative_services.reset();
    server_info_map_.EraseIfEmpty(it);
    MaybeQueueWriteProperties();
    return;
  }

  auto it = server_info_map_.GetOrPut(
      CreateServerInfoKey(origin, network_anonymization_key));
  bool need_update_pref = true;
  if (it->second.alternative_services.has_value()) {
    DCHECK(!it->second.empty());
    if (it->second.alternative_services->size() ==
        alternative_service_info_vector.size()) {
      const base::Time now = clock_->Now();
      need_update_pref = false;
      auto new_it = alternative_service_info_vector.begin();
      for (const auto& old : *it->second.alternative_services) {
        // Persist to disk immediately if new entry has different scheme, host,
        // or port.
        if (old.alternative_service() != new_it->alternative_service()) {
          need_update_pref = true;
          break;
        }
        // Also persist to disk if new expiration it more that twice as far or
        // less than half as far in the future.
        base::Time old_time = old.expiration();
        base::Time new_time = new_it->expiration();
        if (new_time - now > 2 * (old_time - now) ||
            2 * (new_time - now) < (old_time - now)) {
          need_update_pref = true;
          break;
        }
        // Also persist to disk if new entry has a different list of advertised
        // versions.
        if (old.advertised_versions() != new_it->advertised_versions()) {
          need_update_pref = true;
          break;
        }
        ++new_it;
      }
    }
  }

  const bool previously_no_alternative_services =
      (GetIteratorWithAlternativeServiceInfo(
           origin, network_anonymization_key) == server_info_map_.end());

  it->second.alternative_services = alternative_service_info_vector;

  if (previously_no_alternative_services &&
      !GetAlternativeServiceInfos(origin, network_anonymization_key).empty()) {
    // TODO(rch): Consider the case where multiple requests are started
    // before the first completes. In this case, only one of the jobs
    // would reach this code, whereas all of them should should have.
    HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_MAPPING_MISSING,
                                    IsGoogleHost(origin.host()));
  }

  // If this host ends with a canonical suffix, then set it as the
  // canonical host.
  const char* kCanonicalScheme = "https";
  if (origin.scheme() == kCanonicalScheme) {
    const std::string* canonical_suffix = GetCanonicalSuffix(origin.host());
    if (canonical_suffix != nullptr) {
      url::SchemeHostPort canonical_server(kCanonicalScheme, *canonical_suffix,
                                           origin.port());
      canonical_alt_svc_map_[CreateServerInfoKey(
          canonical_server, network_anonymization_key)] = origin;
    }
  }

  if (need_update_pref)
    MaybeQueueWriteProperties();
}

void HttpServerProperties::SetServerNetworkStatsInternal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key,
    ServerNetworkStats stats) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);

  auto server_info = server_info_map_.GetOrPut(
      CreateServerInfoKey(std::move(server), network_anonymization_key));
  bool changed = !server_info->second.server_network_stats.has_value() ||
                 server_info->second.server_network_stats.value() != stats;

  if (changed) {
    server_info->second.server_network_stats = stats;
    MaybeQueueWriteProperties();
  }
}

void HttpServerProperties::ClearServerNetworkStatsInternal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  auto server_info = server_info_map_.Peek(
      CreateServerInfoKey(std::move(server), network_anonymization_key));
  // If stats are empty, nothing to do.
  if (server_info == server_info_map_.end() ||
      !server_info->second.server_network_stats.has_value()) {
    return;
  }

  // Otherwise, clear and delete if needed. No need to bring to front of MRU
  // cache when clearing data.
  server_info->second.server_network_stats.reset();
  if (server_info->second.empty())
    server_info_map_.EraseIfEmpty(server_info);
  MaybeQueueWriteProperties();
}

const ServerNetworkStats* HttpServerProperties::GetServerNetworkStatsInternal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);

  auto server_info = server_info_map_.Get(
      CreateServerInfoKey(std::move(server), network_anonymization_key));
  if (server_info == server_info_map_.end() ||
      !server_info->second.server_network_stats.has_value()) {
    return nullptr;
  }
  return &server_info->second.server_network_stats.value();
}

HttpServerProperties::QuicServerInfoMapKey
HttpServerProperties::CreateQuicServerInfoKey(
    const quic::QuicServerId& server_id,
    PrivacyMode privacy_mode,
    const NetworkAnonymizationKey& network_anonymization_key) const {
  return QuicServerInfoMapKey(server_id, privacy_mode,
                              network_anonymization_key,
                              use_network_anonymization_key_);
}

HttpServerProperties::ServerInfoMapKey
HttpServerProperties::CreateServerInfoKey(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) const {
  return ServerInfoMapKey(server, network_anonymization_key,
                          use_network_anonymization_key_);
}

HttpServerProperties::ServerInfoMap::const_iterator
HttpServerProperties::GetIteratorWithAlternativeServiceInfo(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  ServerInfoMap::const_iterator it = server_info_map_.Get(
      CreateServerInfoKey(server, network_anonymization_key));
  if (it != server_info_map_.end() && it->second.alternative_services)
    return it;

  auto canonical = GetCanonicalAltSvcHost(server, network_anonymization_key);
  if (canonical == canonical_alt_svc_map_.end()) {
    return server_info_map_.end();
  }

  const url::SchemeHostPort canonical_server = canonical->second;
  it = server_info_map_.Get(
      CreateServerInfoKey(canonical_server, network_anonymization_key));
  if (it == server_info_map_.end() || !it->second.alternative_services)
    return server_info_map_.end();

  for (const AlternativeServiceInfo& alternative_service_info :
       it->second.alternative_services.value()) {
    AlternativeService alternative_service(
        alternative_service_info.alternative_service());
    if (alternative_service.host.empty()) {
      alternative_service.host = canonical_server.host();
    }
    if (!IsAlternativeServiceBroken(alternative_service,
                                    network_anonymization_key)) {
      return it;
    }
  }

  RemoveAltSvcCanonicalHost(canonical_server, network_anonymization_key);
  return server_info_map_.end();
}

HttpServerProperties::CanonicalMap::const_iterator
HttpServerProperties::GetCanonicalAltSvcHost(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) const {
  const char* kCanonicalScheme = "https";
  if (server.scheme() != kCanonicalScheme)
    return canonical_alt_svc_map_.end();

  const std::string* canonical_suffix = GetCanonicalSuffix(server.host());
  if (canonical_suffix == nullptr)
    return canonical_alt_svc_map_.end();

  url::SchemeHostPort canonical_server(kCanonicalScheme, *canonical_suffix,
                                       server.port());
  return canonical_alt_svc_map_.find(
      CreateServerInfoKey(canonical_server, network_anonymization_key));
}

HttpServerProperties::QuicCanonicalMap::const_iterator
HttpServerProperties::GetCanonicalServerInfoHost(
    const QuicServerInfoMapKey& key) const {
  const std::string* canonical_suffix =
      GetCanonicalSuffix(key.server_id.host());
  if (canonical_suffix == nullptr)
    return canonical_server_info_map_.end();

  quic::QuicServerId canonical_server_id(*canonical_suffix,
                                         key.server_id.port());
  return canonical_server_info_map_.find(CreateQuicServerInfoKey(
      canonical_server_id, key.privacy_mode, key.network_anonymization_key));
}

void HttpServerProperties::RemoveAltSvcCanonicalHost(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  auto canonical = GetCanonicalAltSvcHost(server, network_anonymization_key);
  if (canonical == canonical_alt_svc_map_.end())
    return;

  canonical_alt_svc_map_.erase(canonical->first);
}

void HttpServerProperties::UpdateCanonicalServerInfoMap(
    const QuicServerInfoMapKey& key) {
  const std::string* suffix = GetCanonicalSuffix(key.server_id.host());
  if (!suffix)
    return;
  quic::QuicServerId canonical_server(*suffix, key.server_id.port());

  canonical_server_info_map_[CreateQuicServerInfoKey(
      canonical_server, key.privacy_mode, key.network_anonymization_key)] =
      key.server_id;
}

const std::string* HttpServerProperties::GetCanonicalSuffix(
    const std::string& host) const {
  // If this host ends with a canonical suffix, then return the canonical
  // suffix.
  for (const std::string& canonical_suffix : canonical_suffixes_) {
    if (base::EndsWith(host, canonical_suffix,
                       base::CompareCase::INSENSITIVE_ASCII)) {
      return &canonical_suffix;
    }
  }
  return nullptr;
}

void HttpServerProperties::OnPrefsLoaded(
    std::unique_ptr<ServerInfoMap> server_info_map,
    const IPAddress& last_local_address_when_quic_worked,
    std::unique_ptr<QuicServerInfoMap> quic_server_info_map,
    std::unique_ptr<BrokenAlternativeServiceList>
        broken_alternative_service_list,
    std::unique_ptr<RecentlyBrokenAlternativeServices>
        recently_broken_alternative_services) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  DCHECK(!is_initialized_);

  // Either all of these are nullptr, or none of them are (except the broken alt
  // service fields).
  if (server_info_map) {
    OnServerInfoLoaded(std::move(server_info_map));
    OnLastLocalAddressWhenQuicWorkedLoaded(last_local_address_when_quic_worked);
    OnQuicServerInfoMapLoaded(std::move(quic_server_info_map));
    if (recently_broken_alternative_services) {
      DCHECK(broken_alternative_service_list);
      OnBrokenAndRecentlyBrokenAlternativeServicesLoaded(
          std::move(broken_alternative_service_list),
          std::move(recently_broken_alternative_services));
    }
  }

  is_initialized_ = true;

  if (queue_write_on_load_) {
    // Leaving this as true doesn't actually have any effect, but seems best to
    // be safe.
    queue_write_on_load_ = false;
    MaybeQueueWriteProperties();
  }
}

void HttpServerProperties::OnServerInfoLoaded(
    std::unique_ptr<ServerInfoMap> server_info_map) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Perform a simple sanity check on loaded data, when DCHECKs are enabled.
#if DCHECK_IS_ON()
  if (!use_network_anonymization_key_) {
    for (auto server_info = server_info_map->begin();
         server_info != server_info_map->end(); ++server_info) {
      DCHECK(server_info->first.network_anonymization_key.IsEmpty());
    }
  }
#endif  // DCHECK_IS_ON()

  // Swap in the entries from persisted data. This allows the MRU cache to be
  // sorted based on the order of the entries in the newer in-memory cache.
  server_info_map_.Swap(*server_info_map);

  // Add the entries from the memory cache.
  for (auto& [key, server_info] : base::Reversed(*server_info_map)) {
    // If there's no corresponding old entry, add the new entry directly.
    auto old_entry = server_info_map_.Get(key);
    if (old_entry == server_info_map_.end()) {
      server_info_map_.Put(key, std::move(server_info));
      continue;
    }

    // Otherwise, merge the old and new entries. Prefer values from older
    // entries.
    if (!old_entry->second.supports_spdy.has_value())
      old_entry->second.supports_spdy = server_info.supports_spdy;
    if (!old_entry->second.alternative_services.has_value())
      old_entry->second.alternative_services = server_info.alternative_services;
    if (!old_entry->second.server_network_stats.has_value())
      old_entry->second.server_network_stats = server_info.server_network_stats;

    // |requires_http11| isn't saved to prefs, so the loaded entry should not
    // have it set. Unconditionally copy it from the new entry.
    DCHECK(!old_entry->second.requires_http11.has_value());
    old_entry->second.requires_http11 = server_info.requires_http11;
  }

  // Attempt to find canonical servers. Canonical suffix only apply to HTTPS.
  const uint16_t kCanonicalPort = 443;
  const char* kCanonicalScheme = "https";
  for (const auto& it : server_info_map_) {
    if (!it.second.alternative_services ||
        it.first.server.scheme() != kCanonicalScheme) {
      continue;
    }
    const std::string* canonical_suffix =
        GetCanonicalSuffix(it.first.server.host());
    if (!canonical_suffix)
      continue;
    ServerInfoMapKey key = CreateServerInfoKey(
        url::SchemeHostPort(kCanonicalScheme, *canonical_suffix,
                            kCanonicalPort),
        it.first.network_anonymization_key);
    // If we already have a valid canonical server, we're done.
    if (base::Contains(canonical_alt_svc_map_, key)) {
      auto key_it = server_info_map_.Peek(key);
      if (key_it != server_info_map_.end() &&
          key_it->second.alternative_services.has_value()) {
        continue;
      }
    }
    canonical_alt_svc_map_[key] = it.first.server;
  }
}

void HttpServerProperties::OnLastLocalAddressWhenQuicWorkedLoaded(
    const IPAddress& last_local_address_when_quic_worked) {
  last_local_address_when_quic_worked_ = last_local_address_when_quic_worked;
}

void HttpServerProperties::OnQuicServerInfoMapLoaded(
    std::unique_ptr<QuicServerInfoMap> quic_server_info_map) {
  DCHECK_EQ(quic_server_info_map->max_size(), quic_server_info_map_.max_size());

  // Add the entries from persisted data.
  quic_server_info_map_.Swap(*quic_server_info_map);

  // Add the entries from the memory cache.
  for (const auto& [key, server_info] : base::Reversed(*quic_server_info_map)) {
    if (quic_server_info_map_.Get(key) == quic_server_info_map_.end()) {
      quic_server_info_map_.Put(key, server_info);
    }
  }

  // Repopulate |canonical_server_info_map_| to stay in sync with
  // |quic_server_info_map_|.
  canonical_server_info_map_.clear();
  for (const auto& [key, server_info] : base::Reversed(quic_server_info_map_)) {
    UpdateCanonicalServerInfoMap(key);
  }
}

void HttpServerProperties::OnBrokenAndRecentlyBrokenAlternativeServicesLoaded(
    std::unique_ptr<BrokenAlternativeServiceList>
        broken_alternative_service_list,
    std::unique_ptr<RecentlyBrokenAlternativeServices>
        recently_broken_alternative_services) {
  broken_alternative_services_.SetBrokenAndRecentlyBrokenAlternativeServices(
      std::move(broken_alternative_service_list),
      std::move(recently_broken_alternative_services));
}

void HttpServerProperties::MaybeQueueWriteProperties() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (prefs_update_timer_.IsRunning() || !properties_manager_)
    return;

  if (!is_initialized_) {
    queue_write_on_load_ = true;
    return;
  }

  prefs_update_timer_.Start(
      FROM_HERE, kUpdatePrefsDelay,
      base::BindOnce(&HttpServerProperties::WriteProperties,
                     base::Unretained(this), base::OnceClosure()));
}

void HttpServerProperties::FlushWritePropertiesForTesting(
    base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!properties_manager_) {
    return;
  }

  // initialising the |properties_manager_| is not a concern here. So skip
  // it and set |is_initalized_| to true.
  is_initialized_ = true;
  // Stop the timer if it's running, since this will write to the properties
  // file immediately.
  prefs_update_timer_.Stop();
  WriteProperties(std::move(callback));
}

void HttpServerProperties::WriteProperties(base::OnceClosure callback) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(properties_manager_);

  // |this| shouldn't be waiting to load properties cached to disk when this
  // method is invoked, since this method will overwrite any cached properties.
  DCHECK(is_initialized_);

  // There shouldn't be a queued update when this is run, since this method
  // removes the need for any update to be queued.
  DCHECK(!prefs_update_timer_.IsRunning());

  properties_manager_->WriteToPrefs(
      server_info_map_,
      base::BindRepeating(&HttpServerProperties::GetCanonicalSuffix,
                          base::Unretained(this)),
      last_local_address_when_quic_worked_, quic_server_info_map_,
      broken_alternative_services_.broken_alternative_service_list(),
      broken_alternative_services_.recently_broken_alternative_services(),
      std::move(callback));
}

}  // namespace net

"""


```