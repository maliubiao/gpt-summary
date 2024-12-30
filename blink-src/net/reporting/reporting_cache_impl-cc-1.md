Response:
The user wants me to analyze a C++ source code file related to Chromium's network stack, specifically `net/reporting/reporting_cache_impl.cc`. They are asking for a summary of its functionality, its relation to JavaScript, examples of logical reasoning with inputs and outputs, common user/programming errors, debugging tips related to user actions, and a final concise summary.

This is part 2 of a 3-part request, so the final summary should focus on the functionality presented in *this* code snippet.

Here's a breakdown of how to approach this:

1. **Functionality Identification:**  Read through the provided code snippets and identify the main functions and their purpose. Focus on the data structures and operations being performed.

2. **JavaScript Relationship:**  Consider how this C++ code might interact with JavaScript. Think about features like the Reporting API exposed to web pages.

3. **Logical Reasoning:**  For some of the functions, think about simple scenarios and what the input and output would be. This will demonstrate understanding of the logic.

4. **Common Errors:**  Based on the code, identify potential pitfalls for users or programmers interacting with this system (even indirectly).

5. **User Actions and Debugging:** Think about user interactions in a browser that might lead to this code being executed. Consider developer tools or error scenarios.

6. **Part 2 Summary:**  Synthesize the findings from the previous steps to create a concise summary of the functionalities present in this specific code block. Since this is part 2, avoid repeating information from part 1. Focus on the functions present in this block.

**Detailed Plan & Self-Correction:**

* **Functionality:** The provided code focuses on:
    * **Testing/Internal Utility Functions:** `GetEndpointForTesting`, `GetEnterpriseEndpointsForTesting`, `EndpointGroupExistsForTesting`, `ClientExistsForTesting`, `GetEndpointGroupCountForTesting`, `GetClientCountForTesting`, `GetReportingSourceCountForTesting`, `SetV1EndpointForTesting`, `SetEnterpriseEndpointForTesting`, `SetEndpointForTesting`. These are likely used for unit or integration testing the reporting cache.
    * **Retrieval Functions:** `GetIsolationInfoForEndpoint`, `GetEndpointsInGroup`, `GetEndpointCountInGroup`.
    * **Internal Data Management:** `FindReportToEvict`, `ConsistencyCheckClients`, `ConsistencyCheckClient`, `ConsistencyCheckEndpointGroup`, `ConsistencyCheckEndpoint`, `FindClientIt`, `FindEndpointGroupIt`, `FindEndpointIt`, `AddOrUpdateClient`, `AddOrUpdateEndpointGroup`, `AddOrUpdateEndpoint`, `RemoveEndpointsInGroupOtherThan`, `RemoveEndpointGroupsForClientOtherThan`, `MarkEndpointGroupAndClientUsed`, `RemoveEndpointInternal`, `RemoveEndpointGroupInternal`, `RemoveClientInternal`, `EnforcePerClientAndGlobalEndpointLimits`, `EvictEndpointsFromClient`, `EvictEndpointFromGroup`, `RemoveExpiredOrStaleGroups`, `AddEndpointItToIndex`, `RemoveEndpointItFromIndex`. These functions handle adding, updating, removing, and validating data within the reporting cache.
    * **Client and Endpoint Group Classes:** Definition of `Client`.

* **JavaScript Relationship:** The testing functions are unlikely to be directly related to JavaScript. However, the functions that manage endpoints and endpoint groups are indirectly related, as they store and retrieve information based on reporting directives potentially set via JavaScript (e.g., the `Report-To` header). The `GetIsolationInfoForEndpoint` function is relevant to how credentials might be attached to reports, which could be triggered by JavaScript.

* **Logical Reasoning:** For `GetEndpointForTesting`, input would be a `ReportingEndpointGroupKey` and a `GURL`. The output would be the matching `ReportingEndpoint` or an empty one. For `EndpointGroupExistsForTesting`, input would be a `ReportingEndpointGroupKey`, `OriginSubdomains`, and `base::Time`. The output would be `true` or `false`.

* **Common Errors:** Incorrectly setting up test data using the `Set...ForTesting` methods could lead to unexpected test outcomes. Logic errors in the data management functions could lead to inconsistencies in the cache.

* **User Actions/Debugging:**  A user visiting a website that sets reporting endpoints (via HTTP headers or the Reporting API) would indirectly cause this code to be executed. Debugging could involve inspecting the contents of the cache using the testing functions or observing network requests related to reporting.

* **Part 2 Summary:**  This section of the code primarily deals with the internal mechanisms for managing reporting endpoints and endpoint groups. It includes functions for testing the cache's state, retrieving specific endpoints or information about them, and performing consistency checks. It also defines the `Client` data structure, which is central to organizing the cache.

**Final Check:** Ensure all parts of the prompt are addressed. The 'Part 2' constraint is important for the final summary.
好的，让我们继续分析 `net/reporting/reporting_cache_impl.cc` 的第二部分代码。

**功能列举 (第二部分):**

这部分代码主要集中在 `ReportingCacheImpl` 类的以下功能：

1. **测试辅助功能：**
    *   提供多种 `Get...ForTesting` 方法，用于在测试中检查缓存的内部状态，例如获取特定的 endpoint、企业 endpoint、检查 endpoint group 或 client 是否存在，以及获取 endpoint group 和 client 的数量。
    *   提供 `Set...ForTesting` 方法，用于在测试中直接设置缓存中的 endpoint 和 endpoint group 数据，包括 V1 和企业 endpoint。

2. **Endpoint 和 Endpoint Group 的管理和查找：**
    *   `GetIsolationInfoForEndpoint`:  根据给定的 `ReportingEndpoint` 获取其关联的 `IsolationInfo`，这关系到报告上传时的隔离和凭据处理。
    *   `GetEndpointsInGroup`: 获取指定 endpoint group 中的所有 endpoint。
    *   `GetEndpointCountInGroup`: 获取指定 endpoint group 中 endpoint 的数量。
    *   内部辅助查找函数： `FindClientIt` (多个重载), `FindEndpointGroupIt`, `FindEndpointIt`，用于在缓存的内部数据结构中查找特定的 client、endpoint group 或 endpoint。

3. **缓存数据一致性检查：**
    *   `ConsistencyCheckClients`, `ConsistencyCheckClient`, `ConsistencyCheckEndpointGroup`, `ConsistencyCheckEndpoint`:  一系列用于在 `DCHECK` 模式下验证缓存内部数据结构一致性的函数，帮助开发者在开发阶段发现潜在的逻辑错误。

4. **内部数据操作：**
    *   `AddOrUpdateClient`, `AddOrUpdateEndpointGroup`, `AddOrUpdateEndpoint`:  用于添加或更新缓存中的 client、endpoint group 和 endpoint 信息。
    *   `RemoveEndpointsInGroupOtherThan`:  移除指定 endpoint group 中除指定 URL 之外的所有 endpoint。
    *   `RemoveEndpointGroupsForClientOtherThan`:  移除指定 client 中除指定名称之外的所有 endpoint group。
    *   `MarkEndpointGroupAndClientUsed`:  更新 endpoint group 和 client 的最后使用时间。
    *   `RemoveEndpointInternal`, `RemoveEndpointGroupInternal`, `RemoveClientInternal`:  内部函数，用于从缓存中移除 endpoint、endpoint group 和 client。
    *   `EnforcePerClientAndGlobalEndpointLimits`:  强制执行每个 client 和全局的 endpoint 数量限制，超出限制的 endpoint 将会被移除。
    *   `EvictEndpointsFromClient`, `EvictEndpointFromGroup`:  根据策略从 client 或 endpoint group 中移除 endpoint。
    *   `RemoveExpiredOrStaleGroups`:  移除过期或过时的 endpoint group。
    *   `AddEndpointItToIndex`, `RemoveEndpointItFromIndex`:  维护 `endpoint_its_by_url_` 索引，用于根据 URL 快速查找 endpoint。

5. **数据结构定义：**
    *   定义了 `Client` 结构体，用于存储与特定 Origin 相关的 endpoint group 和 endpoint 信息。

**与 JavaScript 的关系：**

这部分代码与 JavaScript 的关系主要是间接的，体现在：

*   **Reporting API 的后端实现：**  当 JavaScript 代码使用 Reporting API (例如，通过 `navigator.sendBeacon` 或 Fetch API 的 `report-to` 选项发送报告) 或浏览器遇到需要报告的错误（例如，CSP 违规）时，这些报告最终会被存储到 `ReportingCacheImpl` 中。这部分代码负责管理这些报告的目标 endpoint 信息。
*   **配置信息的存储：**  通过 HTTP 响应头（例如 `Report-To`）设置的 reporting endpoint 配置信息会被解析并存储到这个缓存中。JavaScript 发起的网络请求可能会触发这些响应头的接收和解析，最终影响这里的缓存内容。

**举例说明：**

假设一个网页的 JavaScript 代码尝试发送一个网络错误报告：

```javascript
navigator.sendBeacon("/report_receiver", JSON.stringify({
  "type": "network-error",
  "url": "https://example.com/api/data",
  "message": "Failed to fetch data"
}));
```

1. **假设输入：** 在 `ReportingCacheImpl` 中已经存在一个针对 `example.com` 的 reporting endpoint 配置，其 `group_key` 匹配发送报告的 Origin 和 network isolation key，并且该 endpoint 的 URL 指向一个报告接收服务器。
2. **逻辑推理：** 当需要发送报告时，网络栈会查找与报告来源 Origin 关联的 reporting endpoint。这部分代码中的 `GetEndpointForReporting` (在第一部分) 或类似的查找逻辑会被调用，以确定报告应该发送到哪个 endpoint。`GetIsolationInfoForEndpoint` 会被调用以获取与该 endpoint 关联的隔离信息，用于后续的凭据处理。
3. **输出：** `GetEndpointForReporting` 或类似的函数会返回匹配的 `ReportingEndpoint` 对象，包含了报告需要发送到的 URL。`GetIsolationInfoForEndpoint` 会返回相应的 `IsolationInfo`。

**用户或编程常见的使用错误：**

虽然用户不会直接操作 `ReportingCacheImpl`，但编程错误可能导致缓存状态异常：

1. **测试代码错误地设置缓存状态：**  在使用 `Set...ForTesting` 方法时，如果传入错误的参数（例如，错误的 Origin、URL 或过期时间），可能会导致测试结果不可靠，或者掩盖了实际的 bug。例如，设置了一个永远不会过期的 endpoint，可能会影响到缓存的清理逻辑测试。
2. **在多线程环境下不正确地访问或修改缓存：** 虽然 Chromium 网络栈有其线程模型，但如果开发者在测试或调试过程中尝试从非预期线程访问或修改缓存，可能会导致数据竞争和崩溃。这可以通过 `DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);` 来部分避免，但这依赖于正确设置和使用序列检查器。
3. **忘记清理测试数据：** 在单元测试后没有清理通过 `Set...ForTesting` 方法设置的测试数据，可能会影响到后续测试的执行。

**用户操作如何到达这里（调试线索）：**

1. **用户访问一个网站：**  当用户在浏览器中打开一个新的网页或访问一个现有的网页时，浏览器会发起各种网络请求。
2. **网站设置 Reporting API 配置：**  服务器可以通过 HTTP 响应头（如 `Report-To`）来指示浏览器收集特定类型的报告并将它们发送到指定的 endpoint。或者，网站的 JavaScript 代码可以使用 Reporting API 来配置报告行为。
3. **浏览器解析和存储配置：**  当浏览器接收到包含 Reporting API 配置的 HTTP 响应头时，网络栈的解析代码会将这些配置信息提取出来。
4. **`ReportingCacheImpl` 更新缓存：**  解析后的配置信息会被传递给 `ReportingCacheImpl`，相关的方法（例如 `AddOrUpdateEndpointGroup`, `AddOrUpdateEndpoint`) 会被调用，将这些配置信息存储到缓存中。
5. **发生需要报告的事件：**  当网页上发生需要报告的事件（例如，网络错误、CSP 违规、废弃的 API 使用）时，浏览器会尝试生成相应的报告。
6. **查找合适的 Endpoint：**  在发送报告之前，网络栈会查询 `ReportingCacheImpl` 以找到与报告来源 Origin 匹配的 reporting endpoint。这会调用类似 `GetEndpointForReporting` 的方法。
7. **发送报告：**  如果找到了合适的 endpoint，浏览器会将报告发送到该 endpoint。

在调试过程中，开发者可以使用 Chrome 的开发者工具（Network 面板）来查看与 Reporting API 相关的请求和响应头，以了解网站设置了哪些 reporting endpoint。还可以使用 `chrome://net-internals/#reporting` 页面来查看当前浏览器缓存的 reporting endpoint 和报告信息。

**功能归纳 (第二部分):**

这部分 `ReportingCacheImpl` 的代码主要负责**内部管理 reporting endpoint 和 endpoint group 的信息**。它提供了用于**测试目的的访问和修改缓存状态的接口**，实现了**查找、添加、更新和删除缓存中 endpoint 和 endpoint group 的核心逻辑**，并包含了**用于确保缓存数据一致性的检查机制**。此外，它还定义了用于组织缓存数据的 `Client` 结构体，并实现了**根据策略限制缓存大小和清理过期/过时数据的机制**。这部分功能是 Reporting API 在浏览器内部正常运作的关键组成部分。

Prompt: 
```
这是目录为net/reporting/reporting_cache_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ableToken& reporting_source,
    const std::string& endpoint_name) const {
  DCHECK(!reporting_source.is_empty());
  const auto it = document_endpoints_.find(reporting_source);
  if (it != document_endpoints_.end()) {
    for (const ReportingEndpoint& endpoint : it->second) {
      if (endpoint_name == endpoint.group_key.group_name)
        return endpoint;
    }
  }
  return ReportingEndpoint();
}

ReportingEndpoint ReportingCacheImpl::GetEndpointForTesting(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) const {
  ConsistencyCheckClients();
  for (const auto& group_key_and_endpoint : endpoints_) {
    const ReportingEndpoint& endpoint = group_key_and_endpoint.second;
    if (endpoint.group_key == group_key && endpoint.info.url == url)
      return endpoint;
  }
  return ReportingEndpoint();
}

std::vector<ReportingEndpoint>
ReportingCacheImpl::GetEnterpriseEndpointsForTesting() const {
  return enterprise_endpoints_;
}

bool ReportingCacheImpl::EndpointGroupExistsForTesting(
    const ReportingEndpointGroupKey& group_key,
    OriginSubdomains include_subdomains,
    base::Time expires) const {
  ConsistencyCheckClients();
  for (const auto& key_and_group : endpoint_groups_) {
    const CachedReportingEndpointGroup& endpoint_group = key_and_group.second;
    if (endpoint_group.group_key == group_key &&
        endpoint_group.include_subdomains == include_subdomains) {
      if (expires != base::Time())
        return endpoint_group.expires == expires;
      return true;
    }
  }
  return false;
}

bool ReportingCacheImpl::ClientExistsForTesting(
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::Origin& origin) const {
  ConsistencyCheckClients();
  for (const auto& domain_and_client : clients_) {
    const Client& client = domain_and_client.second;
    DCHECK_EQ(client.origin.host(), domain_and_client.first);
    if (client.network_anonymization_key == network_anonymization_key &&
        client.origin == origin) {
      return true;
    }
  }
  return false;
}

size_t ReportingCacheImpl::GetEndpointGroupCountForTesting() const {
  return endpoint_groups_.size();
}

size_t ReportingCacheImpl::GetClientCountForTesting() const {
  return clients_.size();
}

size_t ReportingCacheImpl::GetReportingSourceCountForTesting() const {
  return document_endpoints_.size();
}

void ReportingCacheImpl::SetV1EndpointForTesting(
    const ReportingEndpointGroupKey& group_key,
    const base::UnguessableToken& reporting_source,
    const IsolationInfo& isolation_info,
    const GURL& url) {
  DCHECK(!reporting_source.is_empty());
  DCHECK(group_key.IsDocumentEndpoint());
  DCHECK_EQ(reporting_source, group_key.reporting_source.value());
  DCHECK(group_key.network_anonymization_key ==
         isolation_info.network_anonymization_key());

  ReportingEndpoint::EndpointInfo info;
  info.url = url;
  ReportingEndpoint new_endpoint(group_key, info);
  if (document_endpoints_.count(reporting_source) > 0) {
    // The endpoints list is const, so remove and replace with an updated list.
    std::vector<ReportingEndpoint> endpoints =
        document_endpoints_.at(reporting_source);
    endpoints.push_back(std::move(new_endpoint));
    document_endpoints_.erase(reporting_source);
    document_endpoints_.insert({reporting_source, std::move(endpoints)});
  } else {
    document_endpoints_.insert({reporting_source, {std::move(new_endpoint)}});
  }
  // If this is the first time we've used this reporting_source, then add the
  // isolation info. Otherwise, ensure that it is the same as what was used
  // previously.
  if (isolation_info_.count(reporting_source) == 0) {
    isolation_info_.insert({reporting_source, isolation_info});
  } else {
    DCHECK(isolation_info_.at(reporting_source)
               .IsEqualForTesting(isolation_info));  // IN-TEST
  }
  // Document endpoints should have an origin.
  DCHECK(group_key.origin.has_value());
  context_->NotifyEndpointsUpdatedForOrigin(
      FilterEndpointsByOrigin(document_endpoints_, group_key.origin.value()));
}

void ReportingCacheImpl::SetEnterpriseEndpointForTesting(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  DCHECK(group_key.IsEnterpriseEndpoint());

  ReportingEndpoint::EndpointInfo info;
  info.url = url;
  ReportingEndpoint new_endpoint(group_key, info);
  enterprise_endpoints_.push_back(std::move(new_endpoint));
}

void ReportingCacheImpl::SetEndpointForTesting(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url,
    OriginSubdomains include_subdomains,
    base::Time expires,
    int priority,
    int weight) {
  ClientMap::iterator client_it = FindClientIt(group_key);
  // If the client doesn't yet exist, add it.
  if (client_it == clients_.end()) {
    // V0 endpoints should have an origin.
    DCHECK(group_key.origin.has_value());
    Client new_client(group_key.network_anonymization_key,
                      group_key.origin.value());
    const std::string& domain = group_key.origin.value().host();
    client_it = clients_.emplace(domain, std::move(new_client));
  }

  base::Time now = clock().Now();

  EndpointGroupMap::iterator group_it = FindEndpointGroupIt(group_key);
  // If the endpoint group doesn't yet exist, add it.
  if (group_it == endpoint_groups_.end()) {
    CachedReportingEndpointGroup new_group(group_key, include_subdomains,
                                           expires, now);
    group_it = endpoint_groups_.emplace(group_key, std::move(new_group)).first;
    client_it->second.endpoint_group_names.insert(group_key.group_name);
  } else {
    // Otherwise, update the existing entry
    group_it->second.include_subdomains = include_subdomains;
    group_it->second.expires = expires;
    group_it->second.last_used = now;
  }

  MarkEndpointGroupAndClientUsed(client_it, group_it, now);

  EndpointMap::iterator endpoint_it = FindEndpointIt(group_key, url);
  // If the endpoint doesn't yet exist, add it.
  if (endpoint_it == endpoints_.end()) {
    ReportingEndpoint::EndpointInfo info;
    info.url = url;
    info.priority = priority;
    info.weight = weight;
    ReportingEndpoint new_endpoint(group_key, info);
    endpoint_it = endpoints_.emplace(group_key, std::move(new_endpoint));
    AddEndpointItToIndex(endpoint_it);
    ++client_it->second.endpoint_count;
  } else {
    // Otherwise, update the existing entry
    endpoint_it->second.info.priority = priority;
    endpoint_it->second.info.weight = weight;
  }

  EnforcePerClientAndGlobalEndpointLimits(client_it);
  ConsistencyCheckClients();
  context_->NotifyCachedClientsUpdated();
}

IsolationInfo ReportingCacheImpl::GetIsolationInfoForEndpoint(
    const ReportingEndpoint& endpoint) const {
  // Enterprise endpoints do not use a NetworkAnonymizationKey or an
  // IsolationInfo, but they need a non-empty IsolationInfo for reports to be
  // uploaded. Enterprise endpoints are profile-bound and
  // not document-bound like web developer endpoints.
  if (endpoint.group_key.target_type == ReportingTargetType::kEnterprise) {
    return IsolationInfo::CreateTransient();
  }
  // V0 endpoint groups do not support credentials.
  if (!endpoint.group_key.reporting_source.has_value()) {
    // TODO(crbug.com/344943210): Remove this and have a better way to get a
    // correct IsolationInfo here.
    return IsolationInfo::DoNotUseCreatePartialFromNak(
        endpoint.group_key.network_anonymization_key);
  }
  const auto it =
      isolation_info_.find(endpoint.group_key.reporting_source.value());
  CHECK(it != isolation_info_.end(), base::NotFatalUntil::M130);
  return it->second;
}

ReportingCacheImpl::Client::Client(
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::Origin& origin)
    : network_anonymization_key(network_anonymization_key), origin(origin) {}

ReportingCacheImpl::Client::Client(const Client& other) = default;

ReportingCacheImpl::Client::Client(Client&& other) = default;

ReportingCacheImpl::Client& ReportingCacheImpl::Client::operator=(
    const Client& other) = default;

ReportingCacheImpl::Client& ReportingCacheImpl::Client::operator=(
    Client&& other) = default;

ReportingCacheImpl::Client::~Client() = default;

ReportingCacheImpl::ReportSet::const_iterator
ReportingCacheImpl::FindReportToEvict() const {
  ReportSet::const_iterator to_evict = reports_.end();

  for (auto it = reports_.begin(); it != reports_.end(); ++it) {
    // Don't evict pending or doomed reports.
    if (it->get()->IsUploadPending())
      continue;
    if (to_evict == reports_.end() ||
        it->get()->queued < to_evict->get()->queued) {
      to_evict = it;
    }
  }

  return to_evict;
}

void ReportingCacheImpl::ConsistencyCheckClients() const {
  // TODO(crbug.com/40054414): Remove this CHECK once the investigation is done.
  CHECK_LE(endpoint_groups_.size(), context_->policy().max_endpoint_count);
#if DCHECK_IS_ON()
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  size_t total_endpoint_count = 0;
  size_t total_endpoint_group_count = 0;
  std::set<std::pair<NetworkAnonymizationKey, url::Origin>>
      nik_origin_pairs_in_cache;

  for (const auto& domain_and_client : clients_) {
    const std::string& domain = domain_and_client.first;
    const Client& client = domain_and_client.second;
    total_endpoint_count += client.endpoint_count;
    total_endpoint_group_count += ConsistencyCheckClient(domain, client);

    auto inserted = nik_origin_pairs_in_cache.emplace(
        client.network_anonymization_key, client.origin);
    // We have not seen a duplicate client with the same NAK and origin.
    DCHECK(inserted.second);
  }

  // Global endpoint cap is respected.
  DCHECK_LE(GetEndpointCount(), context_->policy().max_endpoint_count);
  // The number of endpoint groups must not exceed the number of endpoints.
  DCHECK_LE(endpoint_groups_.size(), GetEndpointCount());

  // All the endpoints and endpoint groups are accounted for.
  DCHECK_EQ(total_endpoint_count, endpoints_.size());
  DCHECK_EQ(total_endpoint_group_count, endpoint_groups_.size());

  // All the endpoints are indexed properly.
  DCHECK_EQ(total_endpoint_count, endpoint_its_by_url_.size());
  for (const auto& url_and_endpoint_it : endpoint_its_by_url_) {
    DCHECK_EQ(url_and_endpoint_it.first,
              url_and_endpoint_it.second->second.info.url);
  }
}

size_t ReportingCacheImpl::ConsistencyCheckClient(const std::string& domain,
                                                  const Client& client) const {
  // Each client is keyed by its domain name.
  DCHECK_EQ(domain, client.origin.host());
  // Client is not empty (has at least one group)
  DCHECK(!client.endpoint_group_names.empty());

  size_t endpoint_count_in_client = 0;
  size_t endpoint_group_count_in_client = 0;

  for (const std::string& group_name : client.endpoint_group_names) {
    size_t groups_with_name = 0;
    for (const auto& key_and_group : endpoint_groups_) {
      const ReportingEndpointGroupKey& key = key_and_group.first;
      // There should not be any V1 document endpoints; this is a V0 endpoint
      // group.
      DCHECK(!key_and_group.first.IsDocumentEndpoint());
      if (key.origin == client.origin &&
          key.network_anonymization_key == client.network_anonymization_key &&
          key.group_name == group_name) {
        ++endpoint_group_count_in_client;
        ++groups_with_name;
        endpoint_count_in_client +=
            ConsistencyCheckEndpointGroup(key, key_and_group.second);
      }
    }
    DCHECK_EQ(1u, groups_with_name);
  }
  // Client has the correct endpoint count.
  DCHECK_EQ(client.endpoint_count, endpoint_count_in_client);
  // Per-client endpoint cap is respected.
  DCHECK_LE(client.endpoint_count, context_->policy().max_endpoints_per_origin);

  // Note: Not checking last_used time here because base::Time is not
  // guaranteed to be monotonically non-decreasing.

  return endpoint_group_count_in_client;
}

size_t ReportingCacheImpl::ConsistencyCheckEndpointGroup(
    const ReportingEndpointGroupKey& key,
    const CachedReportingEndpointGroup& group) const {
  size_t endpoint_count_in_group = 0;

  // Each group is keyed by its origin and name.
  DCHECK(key == group.group_key);

  // Group is not empty (has at least one endpoint)
  DCHECK_LE(0u, GetEndpointCountInGroup(group.group_key));

  // Note: Not checking expiry here because expired groups are allowed to
  // linger in the cache until they are garbage collected.

  std::set<GURL> endpoint_urls_in_group;

  const auto group_range = endpoints_.equal_range(key);
  for (auto it = group_range.first; it != group_range.second; ++it) {
    const ReportingEndpoint& endpoint = it->second;

    ConsistencyCheckEndpoint(key, endpoint, it);

    auto inserted = endpoint_urls_in_group.insert(endpoint.info.url);
    // We have not seen a duplicate endpoint with the same URL in this
    // group.
    DCHECK(inserted.second);

    ++endpoint_count_in_group;
  }

  return endpoint_count_in_group;
}

void ReportingCacheImpl::ConsistencyCheckEndpoint(
    const ReportingEndpointGroupKey& key,
    const ReportingEndpoint& endpoint,
    EndpointMap::const_iterator endpoint_it) const {
  // Origin and group name match.
  DCHECK(key == endpoint.group_key);

  // Priority and weight are nonnegative integers.
  DCHECK_LE(0, endpoint.info.priority);
  DCHECK_LE(0, endpoint.info.weight);

  // The endpoint is in the |endpoint_its_by_url_| index.
  DCHECK(base::Contains(endpoint_its_by_url_, endpoint.info.url));
  auto url_range = endpoint_its_by_url_.equal_range(endpoint.info.url);
  std::vector<EndpointMap::iterator> endpoint_its_for_url;
  for (auto index_it = url_range.first; index_it != url_range.second;
       ++index_it) {
    endpoint_its_for_url.push_back(index_it->second);
  }
  DCHECK(base::Contains(endpoint_its_for_url, endpoint_it));
#endif  // DCHECK_IS_ON()
}

ReportingCacheImpl::ClientMap::iterator ReportingCacheImpl::FindClientIt(
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::Origin& origin) {
  // TODO(chlily): Limit the number of clients per domain to prevent an attacker
  // from installing many Reporting policies for different port numbers on the
  // same host.
  const auto domain_range = clients_.equal_range(origin.host());
  for (auto it = domain_range.first; it != domain_range.second; ++it) {
    if (it->second.network_anonymization_key == network_anonymization_key &&
        it->second.origin == origin) {
      return it;
    }
  }
  return clients_.end();
}

ReportingCacheImpl::ClientMap::iterator ReportingCacheImpl::FindClientIt(
    const ReportingEndpointGroupKey& group_key) {
  // V0 endpoints should have an origin.
  DCHECK(group_key.origin.has_value());
  return FindClientIt(group_key.network_anonymization_key,
                      group_key.origin.value());
}

ReportingCacheImpl::EndpointGroupMap::iterator
ReportingCacheImpl::FindEndpointGroupIt(
    const ReportingEndpointGroupKey& group_key) {
  return endpoint_groups_.find(group_key);
}

ReportingCacheImpl::EndpointMap::iterator ReportingCacheImpl::FindEndpointIt(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  const auto group_range = endpoints_.equal_range(group_key);
  for (auto it = group_range.first; it != group_range.second; ++it) {
    if (it->second.info.url == url)
      return it;
  }
  return endpoints_.end();
}

ReportingCacheImpl::ClientMap::iterator ReportingCacheImpl::AddOrUpdateClient(
    Client new_client) {
  ClientMap::iterator client_it =
      FindClientIt(new_client.network_anonymization_key, new_client.origin);

  // Add a new client for this NAK and origin.
  if (client_it == clients_.end()) {
    std::string domain = new_client.origin.host();
    client_it = clients_.emplace(std::move(domain), std::move(new_client));
  } else {
    // If an entry already existed, just update it.
    Client& old_client = client_it->second;
    old_client.endpoint_count = new_client.endpoint_count;
    old_client.endpoint_group_names =
        std::move(new_client.endpoint_group_names);
    old_client.last_used = new_client.last_used;
  }

  // Note: ConsistencyCheckClients() may fail here because we may be over the
  // global/per-origin endpoint limits.
  return client_it;
}

void ReportingCacheImpl::AddOrUpdateEndpointGroup(
    CachedReportingEndpointGroup new_group) {
  EndpointGroupMap::iterator group_it =
      FindEndpointGroupIt(new_group.group_key);

  // Add a new endpoint group for this origin and group name.
  if (group_it == endpoint_groups_.end()) {
    if (context_->IsClientDataPersisted())
      store()->AddReportingEndpointGroup(new_group);

    endpoint_groups_.emplace(new_group.group_key, std::move(new_group));
    return;
  }

  // If an entry already existed, just update it.
  CachedReportingEndpointGroup& old_group = group_it->second;
  old_group.include_subdomains = new_group.include_subdomains;
  old_group.expires = new_group.expires;
  old_group.last_used = new_group.last_used;

  if (context_->IsClientDataPersisted())
    store()->UpdateReportingEndpointGroupDetails(new_group);

  // Note: ConsistencyCheckClients() may fail here because we have not yet
  // added/updated the Client yet.
}

void ReportingCacheImpl::AddOrUpdateEndpoint(ReportingEndpoint new_endpoint) {
  EndpointMap::iterator endpoint_it =
      FindEndpointIt(new_endpoint.group_key, new_endpoint.info.url);

  // Add a new endpoint for this origin, group, and url.
  if (endpoint_it == endpoints_.end()) {
    if (context_->IsClientDataPersisted())
      store()->AddReportingEndpoint(new_endpoint);

    endpoint_it =
        endpoints_.emplace(new_endpoint.group_key, std::move(new_endpoint));
    AddEndpointItToIndex(endpoint_it);

    // If the client already exists, update its endpoint count.
    ClientMap::iterator client_it = FindClientIt(endpoint_it->second.group_key);
    if (client_it != clients_.end())
      ++client_it->second.endpoint_count;
    return;
  }

  // If an entry already existed, just update it.
  ReportingEndpoint& old_endpoint = endpoint_it->second;
  old_endpoint.info.priority = new_endpoint.info.priority;
  old_endpoint.info.weight = new_endpoint.info.weight;
  // |old_endpoint.stats| stays the same.

  if (context_->IsClientDataPersisted())
    store()->UpdateReportingEndpointDetails(new_endpoint);

  // Note: ConsistencyCheckClients() may fail here because we have not yet
  // added/updated the Client yet.
}

void ReportingCacheImpl::RemoveEndpointsInGroupOtherThan(
    const ReportingEndpointGroupKey& group_key,
    const std::set<GURL>& endpoints_to_keep_urls) {
  EndpointGroupMap::iterator group_it = FindEndpointGroupIt(group_key);
  if (group_it == endpoint_groups_.end())
    return;
  ClientMap::iterator client_it = FindClientIt(group_key);
  // Normally a group would not exist without a client for that origin, but
  // this can actually happen during header parsing if a header for an origin
  // without a pre-existing configuration erroneously contains multiple groups
  // with the same name. In that case, we assume here that they meant to set all
  // of those same-name groups as one group, so we don't remove anything.
  if (client_it == clients_.end())
    return;

  const auto group_range = endpoints_.equal_range(group_key);
  for (auto it = group_range.first; it != group_range.second;) {
    if (base::Contains(endpoints_to_keep_urls, it->second.info.url)) {
      ++it;
      continue;
    }

    // This may invalidate |group_it| (and also possibly |client_it|), but only
    // if we are processing the last remaining endpoint in the group.
    std::optional<EndpointMap::iterator> next_it =
        RemoveEndpointInternal(client_it, group_it, it);
    if (!next_it.has_value())
      return;
    it = next_it.value();
  }
}

void ReportingCacheImpl::RemoveEndpointGroupsForClientOtherThan(
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::Origin& origin,
    const std::set<std::string>& groups_to_keep_names) {
  ClientMap::iterator client_it =
      FindClientIt(network_anonymization_key, origin);
  if (client_it == clients_.end())
    return;

  std::set<std::string>& old_group_names =
      client_it->second.endpoint_group_names;
  std::vector<std::string> groups_to_remove_names =
      base::STLSetDifference<std::vector<std::string>>(old_group_names,
                                                       groups_to_keep_names);

  for (const std::string& group_name : groups_to_remove_names) {
    // The target_type is set to kDeveloper because this function is used for
    // V0 reporting, which only includes web developer entities.
    EndpointGroupMap::iterator group_it = FindEndpointGroupIt(
        ReportingEndpointGroupKey(network_anonymization_key, origin, group_name,
                                  ReportingTargetType::kDeveloper));
    RemoveEndpointGroupInternal(client_it, group_it);
  }
}

std::vector<ReportingEndpoint> ReportingCacheImpl::GetEndpointsInGroup(
    const ReportingEndpointGroupKey& group_key) const {
  const auto group_range = endpoints_.equal_range(group_key);
  std::vector<ReportingEndpoint> endpoints_out;
  for (auto it = group_range.first; it != group_range.second; ++it) {
    endpoints_out.push_back(it->second);
  }
  return endpoints_out;
}

size_t ReportingCacheImpl::GetEndpointCountInGroup(
    const ReportingEndpointGroupKey& group_key) const {
  return endpoints_.count(group_key);
}

void ReportingCacheImpl::MarkEndpointGroupAndClientUsed(
    ClientMap::iterator client_it,
    EndpointGroupMap::iterator group_it,
    base::Time now) {
  group_it->second.last_used = now;
  client_it->second.last_used = now;
  if (context_->IsClientDataPersisted())
    store()->UpdateReportingEndpointGroupAccessTime(group_it->second);
}

std::optional<ReportingCacheImpl::EndpointMap::iterator>
ReportingCacheImpl::RemoveEndpointInternal(ClientMap::iterator client_it,
                                           EndpointGroupMap::iterator group_it,
                                           EndpointMap::iterator endpoint_it) {
  CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);
  CHECK(group_it != endpoint_groups_.end(), base::NotFatalUntil::M130);
  CHECK(endpoint_it != endpoints_.end(), base::NotFatalUntil::M130);

  const ReportingEndpointGroupKey& group_key = endpoint_it->first;
  // If this is the only endpoint in the group, then removing it will cause the
  // group to become empty, so just remove the whole group. The client may also
  // be removed if it becomes empty.
  if (endpoints_.count(group_key) == 1) {
    RemoveEndpointGroupInternal(client_it, group_it);
    return std::nullopt;
  }
  // Otherwise, there are other endpoints in the group, so there is no chance
  // of needing to remove the group/client. Just remove this endpoint and
  // update the client's endpoint count.
  DCHECK_GT(client_it->second.endpoint_count, 1u);
  RemoveEndpointItFromIndex(endpoint_it);
  --client_it->second.endpoint_count;
  if (context_->IsClientDataPersisted())
    store()->DeleteReportingEndpoint(endpoint_it->second);
  return endpoints_.erase(endpoint_it);
}

std::optional<ReportingCacheImpl::EndpointGroupMap::iterator>
ReportingCacheImpl::RemoveEndpointGroupInternal(
    ClientMap::iterator client_it,
    EndpointGroupMap::iterator group_it,
    size_t* num_endpoints_removed) {
  CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);
  CHECK(group_it != endpoint_groups_.end(), base::NotFatalUntil::M130);
  const ReportingEndpointGroupKey& group_key = group_it->first;

  // Remove the endpoints for this group.
  const auto group_range = endpoints_.equal_range(group_key);
  size_t endpoints_removed =
      std::distance(group_range.first, group_range.second);
  DCHECK_GT(endpoints_removed, 0u);
  if (num_endpoints_removed)
    *num_endpoints_removed += endpoints_removed;
  for (auto it = group_range.first; it != group_range.second; ++it) {
    if (context_->IsClientDataPersisted())
      store()->DeleteReportingEndpoint(it->second);

    RemoveEndpointItFromIndex(it);
  }
  endpoints_.erase(group_range.first, group_range.second);

  // Update the client's endpoint count.
  Client& client = client_it->second;
  client.endpoint_count -= endpoints_removed;

  // Remove endpoint group from client.
  size_t erased_from_client =
      client.endpoint_group_names.erase(group_key.group_name);
  DCHECK_EQ(1u, erased_from_client);

  if (context_->IsClientDataPersisted())
    store()->DeleteReportingEndpointGroup(group_it->second);

  EndpointGroupMap::iterator rv = endpoint_groups_.erase(group_it);

  // Delete client if empty.
  if (client.endpoint_count == 0) {
    DCHECK(client.endpoint_group_names.empty());
    clients_.erase(client_it);
    return std::nullopt;
  }
  return rv;
}

ReportingCacheImpl::ClientMap::iterator
ReportingCacheImpl::RemoveClientInternal(ClientMap::iterator client_it) {
  CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);
  const Client& client = client_it->second;

  // Erase all groups in this client, and all endpoints in those groups.
  for (const std::string& group_name : client.endpoint_group_names) {
    // The target_type is set to kDeveloper because this function is used for
    // V0 reporting, which only includes web developer entities.
    ReportingEndpointGroupKey group_key(client.network_anonymization_key,
                                        client.origin, group_name,
                                        ReportingTargetType::kDeveloper);
    EndpointGroupMap::iterator group_it = FindEndpointGroupIt(group_key);
    if (context_->IsClientDataPersisted())
      store()->DeleteReportingEndpointGroup(group_it->second);
    endpoint_groups_.erase(group_it);

    const auto group_range = endpoints_.equal_range(group_key);
    for (auto it = group_range.first; it != group_range.second; ++it) {
      if (context_->IsClientDataPersisted())
        store()->DeleteReportingEndpoint(it->second);

      RemoveEndpointItFromIndex(it);
    }
    endpoints_.erase(group_range.first, group_range.second);
  }

  return clients_.erase(client_it);
}

void ReportingCacheImpl::EnforcePerClientAndGlobalEndpointLimits(
    ClientMap::iterator client_it) {
  CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);
  size_t client_endpoint_count = client_it->second.endpoint_count;
  // TODO(chlily): This is actually a limit on the endpoints for a given client
  // (for a NAK, origin pair). Rename this.
  size_t max_endpoints_per_origin = context_->policy().max_endpoints_per_origin;
  if (client_endpoint_count > max_endpoints_per_origin) {
    EvictEndpointsFromClient(client_it,
                             client_endpoint_count - max_endpoints_per_origin);
  }

  size_t max_endpoint_count = context_->policy().max_endpoint_count;
  while (GetEndpointCount() > max_endpoint_count) {
    // Find the stalest client (arbitrarily pick the first one if there are
    // multiple).
    ClientMap::iterator to_evict = clients_.end();
    for (auto it = clients_.begin(); it != clients_.end(); ++it) {
      const Client& client = it->second;
      if (to_evict == clients_.end() ||
          client.last_used < to_evict->second.last_used) {
        to_evict = it;
      }
    }

    CHECK(to_evict != clients_.end(), base::NotFatalUntil::M130);

    // Evict endpoints from the chosen client.
    size_t num_to_evict = GetEndpointCount() - max_endpoint_count;
    EvictEndpointsFromClient(
        to_evict, std::min(to_evict->second.endpoint_count, num_to_evict));
  }
}

void ReportingCacheImpl::EvictEndpointsFromClient(ClientMap::iterator client_it,
                                                  size_t endpoints_to_evict) {
  DCHECK_GT(endpoints_to_evict, 0u);
  CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);
  const Client& client = client_it->second;
  // Cache this value as |client| may be deleted.
  size_t client_endpoint_count = client.endpoint_count;
  const NetworkAnonymizationKey& network_anonymization_key =
      client.network_anonymization_key;
  const url::Origin& origin = client.origin;

  DCHECK_GE(client_endpoint_count, endpoints_to_evict);
  if (endpoints_to_evict == client_endpoint_count) {
    RemoveClientInternal(client_it);
    return;
  }

  size_t endpoints_removed = 0;
  bool client_deleted =
      RemoveExpiredOrStaleGroups(client_it, &endpoints_removed);
  // If we deleted the whole client, there is nothing left to do.
  if (client_deleted) {
    DCHECK_EQ(endpoints_removed, client_endpoint_count);
    return;
  }

  DCHECK(!client.endpoint_group_names.empty());

  while (endpoints_removed < endpoints_to_evict) {
    DCHECK_GT(client_it->second.endpoint_count, 0u);
    // Find the stalest group with the most endpoints.
    EndpointGroupMap::iterator stalest_group_it = endpoint_groups_.end();
    size_t stalest_group_endpoint_count = 0;
    for (const std::string& group_name : client.endpoint_group_names) {
      // The target_type is set to kDeveloper because enterprise endpoints
      // follow a different path.
      ReportingEndpointGroupKey group_key(network_anonymization_key, origin,
                                          group_name,
                                          ReportingTargetType::kDeveloper);
      EndpointGroupMap::iterator group_it = FindEndpointGroupIt(group_key);
      size_t group_endpoint_count = GetEndpointCountInGroup(group_key);

      const CachedReportingEndpointGroup& group = group_it->second;
      if (stalest_group_it == endpoint_groups_.end() ||
          group.last_used < stalest_group_it->second.last_used ||
          (group.last_used == stalest_group_it->second.last_used &&
           group_endpoint_count > stalest_group_endpoint_count)) {
        stalest_group_it = group_it;
        stalest_group_endpoint_count = group_endpoint_count;
      }
    }
    CHECK(stalest_group_it != endpoint_groups_.end(),
          base::NotFatalUntil::M130);

    // Evict the least important (lowest priority, lowest weight) endpoint.
    EvictEndpointFromGroup(client_it, stalest_group_it);
    ++endpoints_removed;
  }
}

void ReportingCacheImpl::EvictEndpointFromGroup(
    ClientMap::iterator client_it,
    EndpointGroupMap::iterator group_it) {
  const ReportingEndpointGroupKey& group_key = group_it->first;
  const auto group_range = endpoints_.equal_range(group_key);
  EndpointMap::iterator endpoint_to_evict_it = endpoints_.end();
  for (auto it = group_range.first; it != group_range.second; ++it) {
    const ReportingEndpoint& endpoint = it->second;
    if (endpoint_to_evict_it == endpoints_.end() ||
        // Lower priority = higher numerical value of |priority|.
        endpoint.info.priority > endpoint_to_evict_it->second.info.priority ||
        (endpoint.info.priority == endpoint_to_evict_it->second.info.priority &&
         endpoint.info.weight < endpoint_to_evict_it->second.info.weight)) {
      endpoint_to_evict_it = it;
    }
  }
  CHECK(endpoint_to_evict_it != endpoints_.end(), base::NotFatalUntil::M130);

  RemoveEndpointInternal(client_it, group_it, endpoint_to_evict_it);
}

bool ReportingCacheImpl::RemoveExpiredOrStaleGroups(
    ClientMap::iterator client_it,
    size_t* num_endpoints_removed) {
  base::Time now = clock().Now();
  // Make a copy of this because |client_it| may be invalidated.
  std::set<std::string> groups_in_client_names(
      client_it->second.endpoint_group_names);

  for (const std::string& group_name : groups_in_client_names) {
    // The target_type is set to kDeveloper because enterprise endpoints
    // follow a different path.
    EndpointGroupMap::iterator group_it = FindEndpointGroupIt(
        ReportingEndpointGroupKey(client_it->second.network_anonymization_key,
                                  client_it->second.origin, group_name,
                                  ReportingTargetType::kDeveloper));
    CHECK(group_it != endpoint_groups_.end(), base::NotFatalUntil::M130);
    const CachedReportingEndpointGroup& group = group_it->second;
    if (group.expires < now ||
        now - group.last_used > context_->policy().max_group_staleness) {
      // May delete the client, invalidating |client_it|, but only if we are
      // processing the last remaining group.
      if (!RemoveEndpointGroupInternal(client_it, group_it,
                                       num_endpoints_removed)
               .has_value()) {
        return true;
      }
    }
  }

  return false;
}

void ReportingCacheImpl::AddEndpointItToIndex(
    EndpointMap::iterator endpoint_it) {
  const GURL& url = endpoint_it->second.info.url;
  endpoint_its_by_url_.emplace(url, endpoint_it);
}

void ReportingCacheImpl::RemoveEndpointItFromIndex(
    EndpointMap::iterator 
"""


```