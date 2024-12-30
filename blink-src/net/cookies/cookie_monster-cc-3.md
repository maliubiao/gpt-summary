Response:
The user wants a summary of the functionality of the `CookieMonster` class in Chromium's network stack, based on the provided C++ source code. I need to identify the key responsibilities and behaviors of this class. The request also specifically asks about its relationship with JavaScript, examples of logical reasoning with inputs and outputs, common user/programming errors, steps to reach this code during debugging, and finally, a concise overall summary.

Here's a breakdown of the identified functionalities and how to address each point in the prompt:

1. **Core Functionality:**  The code deals with managing HTTP cookies. This includes:
    *   Storing and retrieving cookies.
    *   Matching cookies to URLs.
    *   Handling different cookie attributes (like domain, path, secure, SameSite).
    *   Persisting cookies to disk (via `CookieStore`).
    *   Managing partitioned cookies.
    *   Recording statistics about cookie usage.
    *   Interacting with `FirstPartySets`.

2. **Relationship with JavaScript:**  Cookies are accessible to JavaScript through the `document.cookie` API. The `CookieMonster` is the underlying mechanism that manages these cookies. I can illustrate this with an example of JavaScript setting a cookie and how `CookieMonster` would be involved.

3. **Logical Reasoning (Hypothetical Input/Output):** I can choose a simple function, like `GetKey()`, and provide a sample input (a domain) and the expected output (the effective domain used as a key).

4. **User/Programming Errors:**  Common mistakes involve incorrect cookie attributes, especially domain and path, which can prevent cookies from being set or sent correctly. I can provide examples of such errors.

5. **Debugging Steps:**  A user action like visiting a website or a JavaScript making a fetch request can lead to cookie operations handled by `CookieMonster`. I can outline these steps.

6. **Overall Summary:** Condense the main functionalities into a few bullet points or a short paragraph.

**Constraint Checklist & Confidence Score:**

*   List functionalities: Yes
*   Relation to JavaScript with example: Yes
*   Logical reasoning with input/output: Yes
*   User/programming errors with example: Yes
*   Steps to reach the code: Yes
*   Overall summary: Yes
*   Part 4 of 4: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I've mentally traced the code and identified the key methods and data structures. The `GetKey()` function's logic for determining the effective domain is clear. The interaction with `CookieStore` for persistence is evident. The statistical recording mechanisms are also apparent. The handling of partitioned cookies adds another layer of complexity.

I can construct a JavaScript example that uses `document.cookie` and explain how the browser would internally invoke `CookieMonster` methods to handle it.

For logical reasoning, `GetKey("example.com")` would likely output `"example.com"`. `GetKey("sub.example.co.uk")` might output `"example.co.uk"` depending on the Public Suffix List.

For user errors, setting a cookie with `domain=sub.example.com` from `example.com` will likely fail due to security restrictions.

Debugging would involve observing network requests in developer tools, looking at cookie headers, and potentially stepping through the `CookieMonster` code if one has the Chromium source.

Strategizing complete. I will now generate the response based on these identified points.

```cpp
net/cookies/cookie_monster.cc
```

这是 Chromium 网络栈中 `CookieMonster` 类的源代码文件的一部分。根据提供的代码片段，以下是该类的功能归纳：

**功能归纳：**

`CookieMonster` 的主要职责是管理 HTTP Cookie。这部分代码主要涉及以下功能：

1. **Cookie 键值生成 (`GetKey`)**:
    *   根据给定的域名（`domain`），计算出一个用于内部存储和查找 Cookie 的键值。
    *   它使用 `registry_controlled_domains::GetDomainAndRegistry` 来获取域名的有效注册域（也称为 eTLD+1），并将结果转换为适合作为主机名的格式。
    *   **逻辑推理：**
        *   **假设输入：** `"www.example.com"`
        *   **输出：** `"example.com"`
        *   **假设输入：** `"sub.example.co.uk"`
        *   **输出：** `"example.co.uk"`
        *   **假设输入：** `"127.0.0.1"`
        *   **输出：** `"127.0.0.1"` （因为 IP 地址没有注册域）
        *   **假设输入：** `"my-extension-id"` (一个扩展的 ID)
        *   **输出：** `"my-extension-id"` (因为扩展 ID 不是域名)
    *   **特殊处理：**  代码中注释提到，这个键值算法显式地忽略了协议（scheme）。这是为了简化从持久化存储加载 Cookie 的过程，因为在加载时可能无法获取协议信息。这也意味着文件 Cookie 和扩展 Cookie 会以特定的方式存储。

2. **检查 URL 的 Cookie-able 协议 (`HasCookieableScheme`)**:
    *   判断给定的 URL (`GURL`) 的协议是否允许设置和发送 Cookie。
    *   它维护一个允许的协议列表 `cookieable_schemes_`，并检查 URL 的协议是否在其中。
    *   如果协议不在允许列表中，则会记录一个警告日志。

3. **获取 Cookie 的访问语义 (`GetAccessSemanticsForCookie`)**:
    *   允许设置一个 `cookie_access_delegate_`，用于根据具体的 Cookie 信息判断其访问语义。
    *   如果未设置代理，则返回 `CookieAccessSemantics::UNKNOWN`。

4. **记录周期性统计信息 (`RecordPeriodicStats`, `DoRecordPeriodicStats`, `RecordPeriodicFirstPartySetsStats`)**:
    *   定期收集关于 Cookie 使用情况的统计信息，用于 UMA (User Metrics Analysis)。
    *   它会记录 Cookie 的数量、大小、每个键的 Cookie 数量和大小、SameSite=None 的 Cookie 数量等。
    *   它还收集有关 Partitioned Cookies 的统计信息。
    *   它与 `FirstPartySets` 集成，收集与第一方集合相关的 Cookie 统计信息。
    *   **假设输入：** `RecordPeriodicStats` 函数接收当前时间作为输入。
    *   **输出：** 如果距离上次记录统计信息的时间超过了 `kRecordStatisticsIntervalSeconds`，则会记录各种 Cookie 指标到 UMA。

5. **执行 Cookie 回调 (`DoCookieCallback`, `DoCookieCallbackForURL`, `DoCookieCallbackForHostOrDomain`)**:
    *   管理与 Cookie 相关的异步操作的回调。
    *   它确保在执行回调之前，Cookie 存储已初始化并且必要的 Cookie 数据已加载。
    *   如果尚未加载所有 Cookie，它会将回调添加到队列中，并在加载完成后执行。
    *   它区分全局任务和特定于域的任务，并分别处理。

6. **判断 Cookie 是否发送到设置它的相同端口 (`IsCookieSentToSamePortThatSetIt`)**:
    *   检查目标 URL 的端口是否与设置 Cookie 的源端口相同。
    *   考虑了默认端口的情况，例如 HTTP 的 80 端口和 HTTPS 的 443 端口。
    *   **逻辑推理：**
        *   **假设输入：** `destination` 为 `https://example.com:443`, `source_port` 为 `443`, `source_scheme` 为 `CookieSourceScheme::kSecure`
        *   **输出：** `CookieSentToSamePort::kYes`
        *   **假设输入：** `destination` 为 `http://example.com`, `source_port` 为 `80`, `source_scheme` 为 `CookieSourceScheme::kHttp`
        *   **输出：** `CookieSentToSamePort::kYes` (即使 URL 中没有显式端口，也会使用默认端口)
        *   **假设输入：** `destination` 为 `https://example.com:8080`, `source_port` 为 `443`, `source_scheme` 为 `CookieSourceScheme::kSecure`
        *   **输出：** `CookieSentToSamePort::kNo`
        *   **假设输入：** `destination` 为 `https://example.com`, `source_port` 为 `80`, `source_scheme` 为 `CookieSourceScheme::kHttp`
        *   **输出：** `CookieSentToSamePort::kNoButDefault` (端口不同，但都是各自协议的默认端口)

7. **判断站点在其他分区中是否有 Cookie (`SiteHasCookieInOtherPartition`)**:
    *   检查给定的站点 (`SchemefulSite`) 是否在与提供的 `partition_key` 不同的其他分区中存在 Cookie。
    *   如果 `partition_key` 为空，则意味着分区 Cookie 功能未启用。

**与 JavaScript 的关系：**

`CookieMonster` 是浏览器处理 JavaScript 中 `document.cookie` API 的底层机制。当 JavaScript 代码尝试读取或设置 Cookie 时，浏览器会调用 `CookieMonster` 的相应方法。

**举例说明：**

1. **JavaScript 设置 Cookie:**
    ```javascript
    document.cookie = "mycookie=myvalue; domain=example.com; path=/";
    ```
    当这段 JavaScript 代码执行时，浏览器会调用 `CookieMonster` 的方法来解析这个字符串，创建一个 `CanonicalCookie` 对象，并将其存储在内部的 Cookie 存储中。`GetKey("example.com")` 方法会被用来确定存储这个 Cookie 的键。

2. **JavaScript 读取 Cookie:**
    ```javascript
    let cookies = document.cookie;
    ```
    当 JavaScript 尝试读取 Cookie 时，浏览器会调用 `CookieMonster` 的方法来查找与当前页面域名匹配的 Cookie，并将它们格式化成一个字符串返回给 JavaScript。

**用户或编程常见的使用错误：**

1. **域名设置错误：** 用户在设置 Cookie 时，可能会将 `domain` 属性设置为当前域名之外的域名，导致 Cookie 无法被正确设置或发送。
    *   **示例：** 在 `www.example.com` 页面上设置 `document.cookie = "test=value; domain=not-example.com";` 这个 Cookie 很可能不会被设置，或者会被浏览器阻止。

2. **路径设置错误：**  `path` 属性定义了 Cookie 的有效路径。如果设置的路径不正确，Cookie 可能不会被发送到预期的页面。
    *   **示例：** 在 `/foo/bar.html` 页面上设置 `document.cookie = "test=value; path=/baz";`，这个 Cookie 不会被发送到 `/foo/bar.html`，因为它只对 `/baz` 路径下的页面有效。

3. **Secure 属性使用错误：**  如果一个 Cookie 设置了 `Secure` 属性，但页面是通过 HTTP 加载的，那么这个 Cookie 可能不会被设置或发送。

4. **SameSite 属性理解错误：** 对 `SameSite` 属性的理解不正确可能导致 Cookie 在跨站请求中无法发送，从而影响网站的功能。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户访问网页：** 用户在浏览器中输入 URL 或点击链接访问一个网站，例如 `https://www.example.com`。
2. **服务器设置 Cookie：**  服务器在 HTTP 响应头中包含 `Set-Cookie` 指令，例如：
    ```
    Set-Cookie: mycookie=myvalue; Domain=example.com; Path=/; Secure; HttpOnly
    ```
3. **浏览器接收响应：** 浏览器接收到包含 `Set-Cookie` 头的响应。
4. **调用 CookieMonster：**  网络栈的 HTTP 处理模块会解析 `Set-Cookie` 头，并创建一个 `CanonicalCookie` 对象。然后，它会调用 `CookieMonster` 的方法（例如，`SetCookie`，虽然这段代码中未直接展示，但它是 `CookieMonster` 的核心功能）来存储这个 Cookie。`GetKey("example.com")` 会被调用来确定存储的键。
5. **用户后续请求：** 当用户访问同一域名下的其他页面或资源时，浏览器会查找与该域名匹配的 Cookie。
6. **CookieMonster 查询：**  网络栈在发送 HTTP 请求前，会调用 `CookieMonster` 的方法（例如，`GetCookiesForUrl`）来获取与当前请求 URL 匹配的 Cookie。
7. **发送 Cookie：**  找到的 Cookie 会被添加到 HTTP 请求头中的 `Cookie` 字段发送到服务器。

**在调试过程中，你可能会在以下场景下接触到这段代码：**

*   **查看网络请求的 Cookie 信息：** 使用浏览器的开发者工具（Network 选项卡），你可以查看请求头和响应头中的 Cookie 信息。如果发现 Cookie 没有被正确设置或发送，你可能会需要深入研究 `CookieMonster` 的逻辑。
*   **检查浏览器的 Cookie 存储：** 一些浏览器允许你查看和管理存储的 Cookie。如果 Cookie 的行为不符合预期，你可能需要了解 `CookieMonster` 如何管理这些 Cookie。
*   **分析 Cookie 相关的安全问题：**  理解 `CookieMonster` 如何处理 `Secure` 和 `SameSite` 属性对于调试与 Cookie 相关的安全漏洞至关重要。
*   **研究 Partitioned Cookies 的行为：** 如果涉及到 Partitioned Cookies，你需要理解 `CookieMonster` 如何存储和检索这些 Cookie。

总而言之，这段代码展示了 `CookieMonster` 类中一些关键的辅助功能，用于管理 Cookie 的存储、检索、匹配和统计，并确保 Cookie 的安全性和合规性。它在浏览器的 Cookie 处理流程中扮演着核心角色。

Prompt: 
```
这是目录为net/cookies/cookie_monster.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
and in FindCookiesForRegistryControlledHost() are the only
// two places where we need to conditionalize based on key type.
//
// Note that this key algorithm explicitly ignores the scheme.  This is
// because when we're entering cookies into the map from the backing store,
// we in general won't have the scheme at that point.
// In practical terms, this means that file cookies will be stored
// in the map either by an empty string or by UNC name (and will be
// limited by kMaxCookiesPerHost), and extension cookies will be stored
// based on the single extension id, as the extension id won't have the
// form of a DNS host and hence GetKey() will return it unchanged.
//
// Arguably the right thing to do here is to make the key
// algorithm dependent on the scheme, and make sure that the scheme is
// available everywhere the key must be obtained (specfically at backing
// store load time).  This would require either changing the backing store
// database schema to include the scheme (far more trouble than it's worth), or
// separating out file cookies into their own CookieMonster instance and
// thus restricting each scheme to a single cookie monster (which might
// be worth it, but is still too much trouble to solve what is currently a
// non-problem).
//
// static
std::string CookieMonster::GetKey(std::string_view domain) {
  std::string effective_domain(
      registry_controlled_domains::GetDomainAndRegistry(
          domain, registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES));
  if (effective_domain.empty())
    effective_domain = std::string(domain);

  return cookie_util::CookieDomainAsHost(effective_domain);
}

bool CookieMonster::HasCookieableScheme(const GURL& url) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Make sure the request is on a cookie-able url scheme.
  bool is_cookieable = base::ranges::any_of(
      cookieable_schemes_, [&url](const std::string& cookieable_scheme) {
        return url.SchemeIs(cookieable_scheme.c_str());
      });

  if (!is_cookieable) {
    // The scheme didn't match any in our allowed list.
    DVLOG(net::cookie_util::kVlogPerCookieMonster)
        << "WARNING: Unsupported cookie scheme: " << url.scheme();
  }
  return is_cookieable;
}

CookieAccessSemantics CookieMonster::GetAccessSemanticsForCookie(
    const CanonicalCookie& cookie) const {
  if (cookie_access_delegate())
    return cookie_access_delegate()->GetAccessSemantics(cookie);
  return CookieAccessSemantics::UNKNOWN;
}

// Test to see if stats should be recorded, and record them if so.
// The goal here is to get sampling for the average browser-hour of
// activity.  We won't take samples when the web isn't being surfed,
// and when the web is being surfed, we'll take samples about every
// kRecordStatisticsIntervalSeconds.
// last_statistic_record_time_ is initialized to Now() rather than null
// in the constructor so that we won't take statistics right after
// startup, to avoid bias from browsers that are started but not used.
void CookieMonster::RecordPeriodicStats(const base::Time& current_time) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  const base::TimeDelta kRecordStatisticsIntervalTime(
      base::Seconds(kRecordStatisticsIntervalSeconds));

  // If we've taken statistics recently, return.
  if (current_time - last_statistic_record_time_ <=
      kRecordStatisticsIntervalTime) {
    return;
  }

  if (DoRecordPeriodicStats())
    last_statistic_record_time_ = current_time;
}

bool CookieMonster::DoRecordPeriodicStats() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeToRecordPeriodicStats");

  // These values are all bogus if we have only partially loaded the cookies.
  if (started_fetching_all_cookies_ && !finished_fetching_all_cookies_)
    return false;

  base::UmaHistogramCounts100000("Cookie.Count2", cookies_.size());

  if (cookie_access_delegate()) {
    std::vector<SchemefulSite> sites;
    for (const auto& entry : cookies_) {
      sites.emplace_back(
          GURL(base::StrCat({url::kHttpsScheme, "://", entry.first})));
    }
    for (const auto& [partition_key, cookie_map] : partitioned_cookies_) {
      for (const auto& [domain, unused_cookie] : *cookie_map) {
        sites.emplace_back(
            GURL(base::StrCat({url::kHttpsScheme, "://", domain})));
      }
    }
    std::optional<base::flat_map<SchemefulSite, FirstPartySetEntry>>
        maybe_sets = cookie_access_delegate()->FindFirstPartySetEntries(
            sites,
            base::BindOnce(&CookieMonster::RecordPeriodicFirstPartySetsStats,
                           weak_ptr_factory_.GetWeakPtr()));
    if (maybe_sets.has_value())
      RecordPeriodicFirstPartySetsStats(maybe_sets.value());
  }

  // Can be up to kMaxCookies.
  UMA_HISTOGRAM_COUNTS_10000("Cookie.NumKeys", num_keys_);

  std::map<std::string, size_t> n_same_site_none_cookies;
  size_t n_bytes = 0;
  std::map<std::string, size_t> n_bytes_per_key;

  for (const auto& [host_key, host_cookie] : cookies_) {
    size_t cookie_n_bytes = NameValueSizeBytes(*host_cookie);
    n_bytes += cookie_n_bytes;
    n_bytes_per_key[host_key] += cookie_n_bytes;

    if (!host_cookie || !host_cookie->IsEffectivelySameSiteNone())
      continue;
    n_same_site_none_cookies[host_key]++;
  }

  size_t max_n_cookies = 0;
  for (const auto& entry : n_same_site_none_cookies) {
    max_n_cookies = std::max(max_n_cookies, entry.second);
  }
  size_t max_n_bytes = 0;
  for (const auto& entry : n_bytes_per_key) {
    max_n_bytes = std::max(max_n_bytes, entry.second);
  }

  // Can be up to 180 cookies, the max per-domain.
  base::UmaHistogramCounts1000("Cookie.MaxSameSiteNoneCookiesPerKey",
                               max_n_cookies);
  base::UmaHistogramCounts100000("Cookie.CookieJarSize", n_bytes >> 10);
  base::UmaHistogramCounts100000(
      "Cookie.AvgCookieJarSizePerKey2",
      n_bytes / std::max(num_keys_, static_cast<size_t>(1)));
  base::UmaHistogramCounts100000("Cookie.MaxCookieJarSizePerKey",
                                 max_n_bytes >> 10);

  // Collect stats for partitioned cookies.
  base::UmaHistogramCounts1000("Cookie.PartitionCount",
                               partitioned_cookies_.size());
  base::UmaHistogramCounts100000("Cookie.PartitionedCookieCount",
                                 num_partitioned_cookies_);
  base::UmaHistogramCounts100000("Cookie.PartitionedCookieCount.Nonced",
                                 num_nonced_partitioned_cookies_);
  base::UmaHistogramCounts100000(
      "Cookie.PartitionedCookieCount.Unnonced",
      num_partitioned_cookies_ - num_nonced_partitioned_cookies_);
  base::UmaHistogramCounts100000("Cookie.PartitionedCookieJarSizeKibibytes",
                                 num_partitioned_cookies_bytes_ >> 10);
  base::UmaHistogramCounts100000(
      "Cookie.PartitionedCookieJarSizeKibibytes.Nonced",
      num_nonced_partitioned_cookie_bytes_ >> 10);
  base::UmaHistogramCounts100000(
      "Cookie.PartitionedCookieJarSizeKibibytes.Unnonced",
      (num_partitioned_cookies_bytes_ - num_nonced_partitioned_cookie_bytes_) >>
          10);

  for (const auto& it : bytes_per_cookie_partition_) {
    base::UmaHistogramCounts100000("Cookie.CookiePartitionSizeKibibytes",
                                   it.second >> 10);
  }

  return true;
}

void CookieMonster::RecordPeriodicFirstPartySetsStats(
    base::flat_map<SchemefulSite, FirstPartySetEntry> sets) const {
  base::flat_map<SchemefulSite, std::set<SchemefulSite>> grouped_by_owner;
  for (const auto& [site, entry] : sets) {
    grouped_by_owner[entry.primary()].insert(site);
  }
  for (const auto& set : grouped_by_owner) {
    int sample = std::accumulate(
        set.second.begin(), set.second.end(), 0,
        [this](int acc, const net::SchemefulSite& site) -> int {
          DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
          if (!site.has_registrable_domain_or_host())
            return acc;
          return acc + cookies_.count(GetKey(site.GetURL().host()));
        });
    base::UmaHistogramCustomCounts("Cookie.PerFirstPartySetCount", sample, 0,
                                   4000, 50);
  }
}

void CookieMonster::DoCookieCallback(base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  MarkCookieStoreAsInitialized();
  FetchAllCookiesIfNecessary();
  seen_global_task_ = true;

  if (!finished_fetching_all_cookies_ && store_.get()) {
    if (tasks_pending_.empty()) {
      time_start_block_load_all_ = base::TimeTicks::Now();
    }
    tasks_pending_.push_back(std::move(callback));
    return;
  }

  std::move(callback).Run();
}

void CookieMonster::DoCookieCallbackForURL(base::OnceClosure callback,
                                           const GURL& url) {
  DoCookieCallbackForHostOrDomain(std::move(callback), url.host_piece());
}

void CookieMonster::DoCookieCallbackForHostOrDomain(
    base::OnceClosure callback,
    std::string_view host_or_domain) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  MarkCookieStoreAsInitialized();
  FetchAllCookiesIfNecessary();

  // If cookies for the requested domain key (eTLD+1) have been loaded from DB
  // then run the task, otherwise load from DB.
  if (!finished_fetching_all_cookies_ && store_.get()) {
    // If a global task has been previously seen, queue the task as a global
    // task. Note that the CookieMonster may be in the middle of executing
    // the global queue, |tasks_pending_| may be empty, which is why another
    // bool is needed.
    if (seen_global_task_) {
      tasks_pending_.push_back(std::move(callback));
      return;
    }

    // Checks if the domain key has been loaded.
    std::string key = GetKey(host_or_domain);
    if (keys_loaded_.find(key) == keys_loaded_.end()) {
      auto it = tasks_pending_for_key_.find(key);
      if (it == tasks_pending_for_key_.end()) {
        store_->LoadCookiesForKey(
            key, base::BindOnce(&CookieMonster::OnKeyLoaded,
                                weak_ptr_factory_.GetWeakPtr(), key));
        it = tasks_pending_for_key_
                 .emplace(key, base::circular_deque<base::OnceClosure>())
                 .first;
      }
      it->second.push_back(std::move(callback));
      return;
    }
  }

  std::move(callback).Run();
}

CookieMonster::CookieSentToSamePort
CookieMonster::IsCookieSentToSamePortThatSetIt(
    const GURL& destination,
    int source_port,
    CookieSourceScheme source_scheme) {
  if (source_port == url::PORT_UNSPECIFIED)
    return CookieSentToSamePort::kSourcePortUnspecified;

  if (source_port == url::PORT_INVALID)
    return CookieSentToSamePort::kInvalid;

  int destination_port = destination.EffectiveIntPort();
  if (source_port == destination_port)
    return CookieSentToSamePort::kYes;

  const std::string& destination_scheme = destination.scheme();
  bool destination_port_is_default =
      url::DefaultPortForScheme(destination_scheme) == destination_port;

  // Since the source port has to be specified if we got to this point, that
  // means this is a newer cookie that therefore has its scheme set as well.
  DCHECK(source_scheme != CookieSourceScheme::kUnset);
  std::string source_scheme_string =
      source_scheme == CookieSourceScheme::kSecure
          ? url::kHttpsScheme
          : url::kHttpScheme;  // wss/ws have the same default port values as
                               // https/http, so it's ok that we use these.

  bool source_port_is_default =
      url::DefaultPortForScheme(source_scheme_string) == source_port;

  if (destination_port_is_default && source_port_is_default)
    return CookieSentToSamePort::kNoButDefault;

  return CookieSentToSamePort::kNo;
}

std::optional<bool> CookieMonster::SiteHasCookieInOtherPartition(
    const net::SchemefulSite& site,
    const std::optional<CookiePartitionKey>& partition_key) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // If the partition key is null, it implies the partitioned cookies feature is
  // not enabled.
  if (!partition_key)
    return std::nullopt;

  std::string domain = site.GetURL().host();
  if (store_ && !finished_fetching_all_cookies_ &&
      !keys_loaded_.count(domain)) {
    return std::nullopt;
  }

  for (const auto& it : partitioned_cookies_) {
    if (it.first == partition_key || CookiePartitionKey::HasNonce(it.first))
      continue;
    if (it.second->find(domain) != it.second->end()) {
      return true;
    }
  }
  return false;
}

}  // namespace net

"""


```