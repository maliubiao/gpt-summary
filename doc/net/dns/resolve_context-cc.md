Response:
Let's break down the thought process for analyzing the `resolve_context.cc` file.

**1. Understanding the Goal:**

The initial request asks for the functionalities of `resolve_context.cc`, its relationship to JavaScript, examples with assumptions, common user errors, and debugging clues. This requires a multi-faceted analysis.

**2. Initial Scan and High-Level Purpose:**

The first step is to quickly scan the file. I look for keywords and structure to get a general idea of its purpose. I notice:

* **Includes:** `net/dns/...`, `net/base/...`, `base/metrics/...`, `base/time/...`. This immediately suggests this file is related to network DNS resolution and involves tracking metrics and time.
* **Namespace:** `net`. Confirms it's part of Chromium's network stack.
* **Class Name:** `ResolveContext`. This is the central element, suggesting it manages the context of DNS resolution.
* **Member Variables:** `host_cache_`, `host_resolver_cache_`, `doh_server_stats_`, `classic_server_stats_`, `current_session_`, etc. These point to caching mechanisms and tracking of server performance (especially DoH and classic).
* **Methods:** `GetDohIterator`, `GetClassicDnsIterator`, `RecordServerFailure`, `RecordServerSuccess`, `RecordRtt`, `NextFallbackPeriod`, `TransactionTimeout`, etc. These indicate actions related to initiating and managing DNS resolution attempts and recording their outcomes.

Based on this initial scan, I form a preliminary hypothesis:  `resolve_context.cc` is responsible for managing the state and strategy of DNS resolution, including handling DoH and classic DNS, caching, tracking server performance, and making decisions about retries and timeouts.

**3. Detailed Analysis - Functionality Breakdown:**

Now, I go through the code more systematically, function by function, and group related functionalities.

* **Server Management (DoH & Classic):** The presence of `doh_server_stats_` and `classic_server_stats_`, along with methods like `GetDohIterator`, `GetClassicDnsIterator`, `RecordServerFailure`, `RecordServerSuccess`, `GetDohServerAvailability`, clearly indicates the file manages and tracks the state of both DoH and classic DNS servers.
* **Fallback and Timeout Logic:**  Methods like `NextClassicFallbackPeriod`, `NextDohFallbackPeriod`, `ClassicTransactionTimeout`, `SecureTransactionTimeout`, and the constants `kMinFallbackPeriod`, `kDefaultMaxFallbackPeriod` point to the core logic for determining when to retry DNS queries and what the overall timeout for a transaction should be. The use of histograms (`rtt_histogram`) suggests adaptive behavior based on observed server response times.
* **Caching:**  `host_cache_` and `host_resolver_cache_` indicate the file manages DNS result caching at different levels.
* **Metrics and Observability:** The inclusion of `<base/metrics/...>` and the various `Record...` methods (e.g., `RecordRttForUma`) strongly suggest this file plays a role in collecting and reporting metrics about DNS resolution performance. The `DohStatusObserver` interface highlights the ability to notify other parts of the system about changes in DoH server availability.
* **Session Management:**  The `DnsSession` class and the `current_session_` member, along with methods like `InvalidateCachesAndPerSessionData`, indicate that the `ResolveContext` is tied to a specific DNS session and needs to manage its state when sessions change.
* **DoH Auto-upgrade:** The `StartDohAutoupgradeSuccessTimer` and `EmitDohAutoupgradeSuccessMetrics` methods specifically address the logic and metrics related to the automatic enabling of DoH.

**4. Relationship with JavaScript:**

This requires understanding how Chromium's network stack interacts with the browser's JavaScript environment.

* **Indirect Relationship:**  I know that JavaScript in web pages initiates network requests (e.g., via `fetch` or `XMLHttpRequest`). These requests eventually trigger DNS resolution. `resolve_context.cc` is part of that process.
* **No Direct API:** I recognize that JavaScript doesn't directly call functions within `resolve_context.cc`. The interaction is through higher-level network APIs.
* **Impact on Performance:** I reason that the decisions made in `resolve_context.cc` (e.g., fallback periods, timeouts, DoH availability) *indirectly* impact the performance experienced by JavaScript code making network requests. Slower DNS resolution means longer load times for web pages.

**5. Logic Reasoning and Examples:**

This involves creating hypothetical scenarios to illustrate how the fallback logic and server selection might work. I need to make reasonable assumptions about initial states and then trace the execution flow conceptually.

* **Focus on Key Decisions:**  I concentrate on illustrating the `NextFallbackPeriod` logic and how failures are recorded and influence future attempts.
* **Simplified Scenarios:** I keep the examples relatively simple to make them understandable.

**6. User/Programming Errors:**

This requires thinking about common mistakes developers or users might make that would lead to issues where the behavior of `resolve_context.cc` becomes relevant.

* **Misconfigured DNS Settings:**  This is a classic user error.
* **Network Connectivity Issues:** Intermittent network problems can trigger the fallback logic.
* **Incorrect DoH Configuration:**  Typographical errors in DoH server URLs or misconfigured templates are common issues.

**7. Debugging Clues and User Actions:**

This links the internal workings of `resolve_context.cc` to observable user actions and debugging techniques.

* **User Actions:** I connect user actions like navigating to a website to the underlying DNS resolution process.
* **Debugging Tools:**  I think about the tools developers use to inspect network activity (DevTools) and how they can provide insights into DNS resolution. I also consider internal logging mechanisms within Chromium.

**8. Structuring the Answer:**

Finally, I organize the information logically, using headings and bullet points to make it easy to read and understand. I ensure that each part of the original request is addressed.

**Self-Correction/Refinement during the Process:**

* **Initial Over-Simplification:** I might initially think of the file as *only* handling fallback. However, going through the code reveals the broader scope, including caching, metrics, and DoH management.
* **JavaScript Connection Nuances:** I need to be careful to explain the *indirect* nature of the JavaScript relationship. It's not a direct API call, but the file's actions have consequences for the JavaScript environment.
* **Clarity of Examples:** I review my examples to ensure they are clear and accurately illustrate the intended points.

By following this structured thought process, I can thoroughly analyze the `resolve_context.cc` file and provide a comprehensive and informative answer.
这是 `net/dns/resolve_context.cc` 文件的功能列表，以及它与 JavaScript 的关系、逻辑推理示例、常见错误和调试线索：

**`net/dns/resolve_context.cc` 的功能:**

这个文件定义了 `ResolveContext` 类，它在 Chromium 网络栈中扮演着核心角色，负责管理 DNS 解析的上下文信息和策略。其主要功能包括：

1. **管理 DNS 服务器状态:**
   - 维护经典 DNS 服务器和 DoH (DNS over HTTPS) 服务器的状态信息，例如最近的成功/失败时间、连续失败次数等。
   - 跟踪每个服务器的 RTT (往返时间) 历史，并使用直方图来估计。
   - 决定 DoH 服务器是否可用，并通知观察者。

2. **DNS 解析策略控制:**
   - 决定何时回退到下一个 DNS 服务器 (经典或 DoH)。
   - 计算经典 DNS 和 DoH 查询的下次回退时间间隔，支持指数退避。
   - 计算 DNS 事务的超时时间。
   - 支持 DNS 服务器轮询 (仅限经典 DNS)。

3. **DNS 缓存管理:**
   - 管理 `HostCache` 和 `HostResolverCache` 实例，用于缓存 DNS 查询结果，减少网络请求。
   - 提供使缓存失效的方法。

4. **DoH 相关功能:**
   - 管理 DoH 服务器的统计信息，包括成功和失败记录。
   - 确定可用的 DoH 服务器数量。
   - 触发非系统 DNS 更改通知，当 DoH 服务器的可用性发生变化时。
   - 记录 DoH 自动升级成功的指标。

5. **指标收集和上报:**
   - 使用 UMA (User Metrics Analysis) 记录 DNS 解析相关的各种指标，例如成功/失败时间、错误代码等。
   - 区分安全 (DoH) 和不安全 (经典 DNS) 的查询，并针对不同的查询类型记录指标。
   - 针对配置了额外日志记录的 DoH 提供商记录更详细的指标。

6. **会话管理:**
   - 与 `DnsSession` 类关联，管理特定 DNS 会话的上下文信息。
   - 在 DNS 会话更改时，清理和重新初始化相关数据。

7. **网络隔离支持:**
   - 考虑网络隔离信息 (`IsolationInfo`)，虽然在这个文件中没有直接的 DNS 查询发起，但其上下文会影响到后续的 DNS 解析行为。

**与 JavaScript 的关系:**

`resolve_context.cc` 与 JavaScript 没有直接的 API 调用关系。但是，它的功能直接影响到 JavaScript 发起的网络请求的性能和行为。

**举例说明:**

当 JavaScript 代码通过 `fetch()` 或 `XMLHttpRequest()` 发起一个网络请求时，浏览器需要解析目标域名对应的 IP 地址。这个解析过程会用到 `resolve_context.cc` 管理的 DNS 解析策略和服务器信息。

* **场景:** 一个网站启用了 DoH，并且用户的浏览器也配置了 DoH。
* **用户操作:** 用户在浏览器地址栏输入网址 `https://example.com` 并回车。
* **`resolve_context.cc` 的作用:**
    - `ResolveContext` 会根据配置和服务器状态，尝试使用配置的 DoH 服务器来解析 `example.com` 的 IP 地址。
    - 如果 DoH 服务器响应缓慢或失败，`ResolveContext` 会根据其回退策略，在一定时间后尝试下一个 DoH 服务器或回退到经典的 DNS 服务器。
    - `ResolveContext` 会记录 DoH 服务器的 RTT 和成功/失败信息，用于后续的策略调整。
    - 如果解析成功，IP 地址会被缓存，下次访问相同的域名会更快。

**逻辑推理与假设输入输出:**

**假设输入:**

* **DNS 配置 (`DnsConfig`):**
    - 经典 DNS 服务器列表: `[192.168.1.1, 8.8.8.8]`
    - DoH 服务器列表: `[https://doh.example.com/dns-query, https://cloudflare-dns.com/dns-query]`
    - 安全 DNS 模式: `SecureDnsMode::kAutomatic`
    - 回退时间间隔: `100ms`
* **服务器状态:**
    - `doh.example.com` 最近失败过一次。
    - `cloudflare-dns.com` 最近成功过。
* **当前时间:** `T0`

**逻辑推理:**

当需要解析一个域名时，`ResolveContext` 会首先尝试使用 DoH 服务器，因为安全 DNS 模式是 `kAutomatic` 并且有可用的 DoH 服务器。由于 `cloudflare-dns.com` 最近成功过，可能会优先尝试它。

**假设输出 (部分):**

* `GetDohIterator` 会返回一个迭代器，优先指向 `cloudflare-dns.com`。
* 如果 `cloudflare-dns.com` 在一定时间内没有响应，`NextDohFallbackPeriod` 会根据 `cloudflare-dns.com` 的 RTT 历史和失败次数计算出下次回退的时间间隔。
* 如果回退发生，并且配置中还有其他 DoH 服务器，则会尝试下一个 DoH 服务器 (`doh.example.com`)。 由于 `doh.example.com` 最近失败过，回退时间间隔可能会更短。
* 如果所有 DoH 服务器都尝试失败，并且安全 DNS 模式允许回退到经典 DNS，则会尝试经典 DNS 服务器。

**用户或编程常见的使用错误:**

1. **错误的 DoH 服务器配置:** 用户或程序可能配置了无效的 DoH 服务器 URL，导致 DNS 解析失败。例如，URL 拼写错误或者服务器不可用。这会导致 `ResolveContext` 记录 DoH 服务器的失败，并可能最终回退到经典的 DNS。

   * **例子:** 用户在浏览器设置中手动配置了一个错误的 DoH 服务器 URL，例如 `htps://doh.example.com/dns-query` (缺少一个 `t`)。

2. **网络连接问题:** 用户的网络连接不稳定，导致无法连接到 DNS 服务器 (无论是经典的还是 DoH)。这会导致 DNS 解析超时或失败，`ResolveContext` 会记录这些失败，并影响后续的回退策略。

   * **例子:** 用户在使用移动网络时，信号不稳定，导致间歇性的 DNS 解析失败。

3. **DNS 缓存问题:** 虽然 `ResolveContext` 管理缓存，但如果缓存策略配置不当或者缓存出现错误，可能会导致解析到过期的 IP 地址。

   * **例子:** 管理员配置了一个非常长的 DNS TTL (Time To Live)，但服务器的 IP 地址发生了变化。用户可能会因为缓存而持续连接到旧的 IP 地址。

**用户操作到达此处的步骤 (调试线索):**

以下是一个用户操作导致代码执行到 `net/dns/resolve_context.cc` 的可能步骤：

1. **用户在浏览器地址栏输入网址并按下回车，或者点击一个链接。**
2. **浏览器需要解析该网址对应的域名。**
3. **浏览器会检查本地 DNS 缓存，如果找到则直接使用缓存的 IP 地址。**
4. **如果本地缓存没有找到，浏览器会调用操作系统的 DNS 解析接口。**
5. **操作系统会将 DNS 查询请求发送到配置的 DNS 服务器。**
6. **在 Chromium 内部，网络栈 (包括 `net/dns` 组件) 会处理 DNS 解析过程。**
7. **`URLRequestContext` 会持有 `ResolveContext` 的实例。**
8. **当需要解析主机名时，会调用 `ResolveContext` 的方法，例如 `GetDohIterator` 或 `GetClassicDnsIterator` 来获取要使用的 DNS 服务器迭代器。**
9. **尝试使用迭代器提供的 DNS 服务器进行解析。**
10. **如果解析过程中发生错误 (例如超时、服务器错误)，`ResolveContext` 的 `RecordServerFailure` 方法会被调用，记录服务器的失败信息。**
11. **如果解析成功，`RecordServerSuccess` 方法会被调用。**
12. **`RecordRtt` 方法会被调用来记录服务器的往返时间。**
13. **`NextFallbackPeriod` 等方法会被调用来决定下一次尝试的时间。**

**作为调试线索:**

* **网络请求失败或延迟:** 如果用户遇到网页加载缓慢或无法加载的问题，可能与 DNS 解析有关。
* **浏览器 NetLog (chrome://net-export/):**  NetLog 提供了详细的网络事件记录，可以查看 DNS 解析的详细过程，包括使用了哪些 DNS 服务器、解析是否成功、耗时多久等。
* **Chrome 开发者工具 (F12):** 在 "Network" 标签页中，可以查看资源加载的时间线，DNS 解析的时间会影响 "Stalled" 或 "DNS Lookup" 阶段的时间。
* **检查浏览器的 DNS 设置 (chrome://settings/security):** 用户可能配置了特定的 DoH 服务器或禁用了安全 DNS，这些设置会影响 `ResolveContext` 的行为。
* **操作系统 DNS 设置:**  操作系统配置的 DNS 服务器也会影响到 Chromium 的默认行为。
* **实验性功能 (chrome://flags):** 某些实验性功能可能会影响 DNS 解析的行为，例如并行 DNS 查询。

总而言之，`net/dns/resolve_context.cc` 是 Chromium 网络栈中负责管理 DNS 解析策略、服务器状态和缓存的关键组件，它的行为直接影响到用户访问网站的性能和安全性。 理解其功能有助于诊断和解决与 DNS 解析相关的网络问题。

### 提示词
```
这是目录为net/dns/resolve_context.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/resolve_context.h"

#include <cstdlib>
#include <limits>
#include <utility>

#include "base/check_op.h"
#include "base/containers/contains.h"
#include "base/metrics/bucket_ranges.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sample_vector.h"
#include "base/no_destructor.h"
#include "base/numerics/safe_conversions.h"
#include "base/observer_list.h"
#include "base/ranges/algorithm.h"
#include "base/strings/stringprintf.h"
#include "base/time/clock.h"
#include "base/time/tick_clock.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/network_change_notifier.h"
#include "net/dns/dns_server_iterator.h"
#include "net/dns/dns_session.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_cache.h"
#include "net/dns/public/dns_over_https_config.h"
#include "net/dns/public/doh_provider_entry.h"
#include "net/dns/public/secure_dns_mode.h"
#include "net/url_request/url_request_context.h"

namespace net {

namespace {

// Min fallback period between queries, in case we are talking to a local DNS
// proxy.
const base::TimeDelta kMinFallbackPeriod = base::Milliseconds(10);

// Default maximum fallback period between queries, even with exponential
// backoff. (Can be overridden by field trial.)
const base::TimeDelta kDefaultMaxFallbackPeriod = base::Seconds(5);

// Maximum RTT that will fit in the RTT histograms.
const base::TimeDelta kRttMax = base::Seconds(30);
// Number of buckets in the histogram of observed RTTs.
const size_t kRttBucketCount = 350;
// Target percentile in the RTT histogram used for fallback period.
const int kRttPercentile = 99;
// Number of samples to seed the histogram with.
const base::HistogramBase::Count kNumSeeds = 2;

DohProviderEntry::List FindDohProvidersMatchingServerConfig(
    DnsOverHttpsServerConfig server_config) {
  DohProviderEntry::List matching_entries;
  for (const DohProviderEntry* entry : DohProviderEntry::GetList()) {
    if (entry->doh_server_config == server_config)
      matching_entries.push_back(entry);
  }

  return matching_entries;
}

DohProviderEntry::List FindDohProvidersAssociatedWithAddress(
    IPAddress server_address) {
  DohProviderEntry::List matching_entries;
  for (const DohProviderEntry* entry : DohProviderEntry::GetList()) {
    if (entry->ip_addresses.count(server_address) > 0)
      matching_entries.push_back(entry);
  }

  return matching_entries;
}

base::TimeDelta GetDefaultFallbackPeriod(const DnsConfig& config) {
  NetworkChangeNotifier::ConnectionType type =
      NetworkChangeNotifier::GetConnectionType();
  return GetTimeDeltaForConnectionTypeFromFieldTrialOrDefault(
      "AsyncDnsInitialTimeoutMsByConnectionType", config.fallback_period, type);
}

base::TimeDelta GetMaxFallbackPeriod() {
  NetworkChangeNotifier::ConnectionType type =
      NetworkChangeNotifier::GetConnectionType();
  return GetTimeDeltaForConnectionTypeFromFieldTrialOrDefault(
      "AsyncDnsMaxTimeoutMsByConnectionType", kDefaultMaxFallbackPeriod, type);
}

class RttBuckets : public base::BucketRanges {
 public:
  RttBuckets() : base::BucketRanges(kRttBucketCount + 1) {
    base::Histogram::InitializeBucketRanges(
        1,
        base::checked_cast<base::HistogramBase::Sample>(
            kRttMax.InMilliseconds()),
        this);
  }
};

static RttBuckets* GetRttBuckets() {
  static base::NoDestructor<RttBuckets> buckets;
  return buckets.get();
}

static std::unique_ptr<base::SampleVector> GetRttHistogram(
    base::TimeDelta rtt_estimate) {
  std::unique_ptr<base::SampleVector> histogram =
      std::make_unique<base::SampleVector>(GetRttBuckets());
  // Seed histogram with 2 samples at |rtt_estimate|.
  histogram->Accumulate(base::checked_cast<base::HistogramBase::Sample>(
                            rtt_estimate.InMilliseconds()),
                        kNumSeeds);
  return histogram;
}

#if defined(ENABLE_BUILT_IN_DNS)
constexpr size_t kDefaultCacheSize = 1000;
#else
constexpr size_t kDefaultCacheSize = 100;
#endif

std::unique_ptr<HostCache> CreateHostCache(bool enable_caching) {
  if (enable_caching) {
    return std::make_unique<HostCache>(kDefaultCacheSize);
  } else {
    return nullptr;
  }
}

std::unique_ptr<HostResolverCache> CreateHostResolverCache(
    bool enable_caching,
    const base::Clock& clock,
    const base::TickClock& tick_clock) {
  if (enable_caching) {
    return std::make_unique<HostResolverCache>(kDefaultCacheSize, clock,
                                               tick_clock);
  } else {
    return nullptr;
  }
}

}  // namespace

ResolveContext::ServerStats::ServerStats(
    std::unique_ptr<base::SampleVector> buckets)
    : rtt_histogram(std::move(buckets)) {}

ResolveContext::ServerStats::ServerStats(ServerStats&&) = default;

ResolveContext::ServerStats::~ServerStats() = default;

ResolveContext::ResolveContext(URLRequestContext* url_request_context,
                               bool enable_caching,
                               const base::Clock& clock,
                               const base::TickClock& tick_clock)
    : url_request_context_(url_request_context),
      host_cache_(CreateHostCache(enable_caching)),
      host_resolver_cache_(
          CreateHostResolverCache(enable_caching, clock, tick_clock)),
      isolation_info_(IsolationInfo::CreateTransient()) {
  max_fallback_period_ = GetMaxFallbackPeriod();
}

ResolveContext::~ResolveContext() = default;

std::unique_ptr<DnsServerIterator> ResolveContext::GetDohIterator(
    const DnsConfig& config,
    const SecureDnsMode& mode,
    const DnsSession* session) {
  // Make the iterator even if the session differs. The first call to the member
  // functions will catch the out of date session.

  return std::make_unique<DohDnsServerIterator>(
      doh_server_stats_.size(), FirstServerIndex(true, session),
      config.doh_attempts, config.attempts, mode, this, session);
}

std::unique_ptr<DnsServerIterator> ResolveContext::GetClassicDnsIterator(
    const DnsConfig& config,
    const DnsSession* session) {
  // Make the iterator even if the session differs. The first call to the member
  // functions will catch the out of date session.

  return std::make_unique<ClassicDnsServerIterator>(
      config.nameservers.size(), FirstServerIndex(false, session),
      config.attempts, config.attempts, this, session);
}

bool ResolveContext::GetDohServerAvailability(size_t doh_server_index,
                                              const DnsSession* session) const {
  if (!IsCurrentSession(session))
    return false;

  CHECK_LT(doh_server_index, doh_server_stats_.size());
  return ServerStatsToDohAvailability(doh_server_stats_[doh_server_index]);
}

size_t ResolveContext::NumAvailableDohServers(const DnsSession* session) const {
  if (!IsCurrentSession(session))
    return 0;

  return base::ranges::count_if(doh_server_stats_,
                                &ServerStatsToDohAvailability);
}

void ResolveContext::RecordServerFailure(size_t server_index,
                                         bool is_doh_server,
                                         int rv,
                                         const DnsSession* session) {
  DCHECK(rv != OK && rv != ERR_NAME_NOT_RESOLVED && rv != ERR_IO_PENDING);

  if (!IsCurrentSession(session))
    return;

  // "FailureError" metric is only recorded for secure queries.
  if (is_doh_server) {
    std::string query_type =
        GetQueryTypeForUma(server_index, true /* is_doh_server */, session);
    DCHECK_NE(query_type, "Insecure");
    std::string provider_id =
        GetDohProviderIdForUma(server_index, true /* is_doh_server */, session);

    base::UmaHistogramSparse(
        base::JoinString(
            {"Net.DNS.DnsTransaction", query_type, provider_id, "FailureError"},
            "."),
        std::abs(rv));
  }

  size_t num_available_doh_servers_before = NumAvailableDohServers(session);

  ServerStats* stats = GetServerStats(server_index, is_doh_server);
  ++(stats->last_failure_count);
  stats->last_failure = base::TimeTicks::Now();
  stats->has_failed_previously = true;

  size_t num_available_doh_servers_now = NumAvailableDohServers(session);
  if (num_available_doh_servers_now < num_available_doh_servers_before) {
    NotifyDohStatusObserversOfUnavailable(false /* network_change */);

    // TODO(crbug.com/40106440): Consider figuring out some way to only for the
    // first context enabling DoH or the last context disabling DoH.
    if (num_available_doh_servers_now == 0)
      NetworkChangeNotifier::TriggerNonSystemDnsChange();
  }
}

void ResolveContext::RecordServerSuccess(size_t server_index,
                                         bool is_doh_server,
                                         const DnsSession* session) {
  if (!IsCurrentSession(session))
    return;

  bool doh_available_before = NumAvailableDohServers(session) > 0;

  ServerStats* stats = GetServerStats(server_index, is_doh_server);
  stats->last_failure_count = 0;
  stats->current_connection_success = true;
  stats->last_failure = base::TimeTicks();
  stats->last_success = base::TimeTicks::Now();

  // TODO(crbug.com/40106440): Consider figuring out some way to only for the
  // first context enabling DoH or the last context disabling DoH.
  bool doh_available_now = NumAvailableDohServers(session) > 0;
  if (doh_available_before != doh_available_now)
    NetworkChangeNotifier::TriggerNonSystemDnsChange();
}

void ResolveContext::RecordRtt(size_t server_index,
                               bool is_doh_server,
                               base::TimeDelta rtt,
                               int rv,
                               const DnsSession* session) {
  if (!IsCurrentSession(session))
    return;

  ServerStats* stats = GetServerStats(server_index, is_doh_server);

  base::TimeDelta base_fallback_period =
      NextFallbackPeriodHelper(stats, 0 /* num_backoffs */);
  RecordRttForUma(server_index, is_doh_server, rtt, rv, base_fallback_period,
                  session);

  // RTT values shouldn't be less than 0, but it shouldn't cause a crash if
  // they are anyway, so clip to 0. See https://crbug.com/753568.
  if (rtt.is_negative())
    rtt = base::TimeDelta();

  // Histogram-based method.
  stats->rtt_histogram->Accumulate(
      base::saturated_cast<base::HistogramBase::Sample>(rtt.InMilliseconds()),
      1);
}

base::TimeDelta ResolveContext::NextClassicFallbackPeriod(
    size_t classic_server_index,
    int attempt,
    const DnsSession* session) {
  if (!IsCurrentSession(session))
    return std::min(GetDefaultFallbackPeriod(session->config()),
                    max_fallback_period_);

  return NextFallbackPeriodHelper(
      GetServerStats(classic_server_index, false /* is _doh_server */),
      attempt / current_session_->config().nameservers.size());
}

base::TimeDelta ResolveContext::NextDohFallbackPeriod(
    size_t doh_server_index,
    const DnsSession* session) {
  if (!IsCurrentSession(session))
    return std::min(GetDefaultFallbackPeriod(session->config()),
                    max_fallback_period_);

  return NextFallbackPeriodHelper(
      GetServerStats(doh_server_index, true /* is _doh_server */),
      0 /* num_backoffs */);
}

base::TimeDelta ResolveContext::ClassicTransactionTimeout(
    const DnsSession* session) {
  if (!IsCurrentSession(session))
    return features::kDnsMinTransactionTimeout.Get();

  // Should not need to call if there are no classic servers configured.
  DCHECK(!classic_server_stats_.empty());

  return TransactionTimeoutHelper(classic_server_stats_.cbegin(),
                                  classic_server_stats_.cend());
}

base::TimeDelta ResolveContext::SecureTransactionTimeout(
    SecureDnsMode secure_dns_mode,
    const DnsSession* session) {
  // Currently only implemented for Secure mode as other modes are assumed to
  // always use aggressive timeouts. If that ever changes, need to implement
  // only accounting for available DoH servers when not Secure mode.
  DCHECK_EQ(secure_dns_mode, SecureDnsMode::kSecure);

  if (!IsCurrentSession(session))
    return features::kDnsMinTransactionTimeout.Get();

  // Should not need to call if there are no DoH servers configured.
  DCHECK(!doh_server_stats_.empty());

  return TransactionTimeoutHelper(doh_server_stats_.cbegin(),
                                  doh_server_stats_.cend());
}

void ResolveContext::RegisterDohStatusObserver(DohStatusObserver* observer) {
  DCHECK(observer);
  doh_status_observers_.AddObserver(observer);
}

void ResolveContext::UnregisterDohStatusObserver(
    const DohStatusObserver* observer) {
  DCHECK(observer);
  doh_status_observers_.RemoveObserver(observer);
}

void ResolveContext::InvalidateCachesAndPerSessionData(
    const DnsSession* new_session,
    bool network_change) {
  // Network-bound ResolveContexts should never receive a cache invalidation due
  // to a network change.
  DCHECK(GetTargetNetwork() == handles::kInvalidNetworkHandle ||
         !network_change);
  if (host_cache_) {
    host_cache_->Invalidate();
  }
  if (host_resolver_cache_) {
    host_resolver_cache_->MakeAllResultsStale();
  }

  // DNS config is constant for any given session, so if the current session is
  // unchanged, any per-session data is safe to keep, even if it's dependent on
  // a specific config.
  if (new_session && new_session == current_session_.get())
    return;

  current_session_.reset();
  doh_autoupgrade_success_metric_timer_.Stop();
  classic_server_stats_.clear();
  doh_server_stats_.clear();
  initial_fallback_period_ = base::TimeDelta();
  max_fallback_period_ = GetMaxFallbackPeriod();

  if (!new_session) {
    NotifyDohStatusObserversOfSessionChanged();
    return;
  }

  current_session_ = new_session->GetWeakPtr();

  initial_fallback_period_ =
      GetDefaultFallbackPeriod(current_session_->config());

  for (size_t i = 0; i < new_session->config().nameservers.size(); ++i) {
    classic_server_stats_.emplace_back(
        GetRttHistogram(initial_fallback_period_));
  }
  for (size_t i = 0; i < new_session->config().doh_config.servers().size();
       ++i) {
    doh_server_stats_.emplace_back(GetRttHistogram(initial_fallback_period_));
  }

  CHECK_EQ(new_session->config().nameservers.size(),
           classic_server_stats_.size());
  CHECK_EQ(new_session->config().doh_config.servers().size(),
           doh_server_stats_.size());

  NotifyDohStatusObserversOfSessionChanged();

  if (!doh_server_stats_.empty())
    NotifyDohStatusObserversOfUnavailable(network_change);
}

void ResolveContext::StartDohAutoupgradeSuccessTimer(
    const DnsSession* session) {
  if (!IsCurrentSession(session)) {
    return;
  }
  if (doh_autoupgrade_success_metric_timer_.IsRunning()) {
    return;
  }
  // We won't pass `session` to `EmitDohAutoupgradeSuccessMetrics()` but will
  // instead reset the timer in `InvalidateCachesAndPerSessionData()` so that
  // the former never gets called after the session changes.
  doh_autoupgrade_success_metric_timer_.Start(
      FROM_HERE, ResolveContext::kDohAutoupgradeSuccessMetricTimeout,
      base::BindOnce(&ResolveContext::EmitDohAutoupgradeSuccessMetrics,
                     base::Unretained(this)));
}

handles::NetworkHandle ResolveContext::GetTargetNetwork() const {
  if (!url_request_context())
    return handles::kInvalidNetworkHandle;

  return url_request_context()->bound_network();
}

size_t ResolveContext::FirstServerIndex(bool doh_server,
                                        const DnsSession* session) {
  if (!IsCurrentSession(session))
    return 0u;

  // DoH first server doesn't rotate, so always return 0u.
  if (doh_server)
    return 0u;

  size_t index = classic_server_index_;
  if (current_session_->config().rotate) {
    classic_server_index_ = (classic_server_index_ + 1) %
                            current_session_->config().nameservers.size();
  }
  return index;
}

bool ResolveContext::IsCurrentSession(const DnsSession* session) const {
  CHECK(session);
  if (session == current_session_.get()) {
    CHECK_EQ(current_session_->config().nameservers.size(),
             classic_server_stats_.size());
    CHECK_EQ(current_session_->config().doh_config.servers().size(),
             doh_server_stats_.size());
    return true;
  }

  return false;
}

ResolveContext::ServerStats* ResolveContext::GetServerStats(
    size_t server_index,
    bool is_doh_server) {
  if (!is_doh_server) {
    CHECK_LT(server_index, classic_server_stats_.size());
    return &classic_server_stats_[server_index];
  } else {
    CHECK_LT(server_index, doh_server_stats_.size());
    return &doh_server_stats_[server_index];
  }
}

base::TimeDelta ResolveContext::NextFallbackPeriodHelper(
    const ServerStats* server_stats,
    int num_backoffs) {
  // Respect initial fallback period (from config or field trial) if it exceeds
  // max.
  if (initial_fallback_period_ > max_fallback_period_)
    return initial_fallback_period_;

  static_assert(std::numeric_limits<base::HistogramBase::Count>::is_signed,
                "histogram base count assumed to be signed");

  // Use fixed percentile of observed samples.
  const base::SampleVector& samples = *server_stats->rtt_histogram;

  base::HistogramBase::Count total = samples.TotalCount();
  base::HistogramBase::Count remaining_count = kRttPercentile * total / 100;
  size_t index = 0;
  while (remaining_count > 0 && index < GetRttBuckets()->size()) {
    remaining_count -= samples.GetCountAtIndex(index);
    ++index;
  }

  base::TimeDelta fallback_period =
      base::Milliseconds(GetRttBuckets()->range(index));

  fallback_period = std::max(fallback_period, kMinFallbackPeriod);

  return std::min(fallback_period * (1 << num_backoffs), max_fallback_period_);
}

template <typename Iterator>
base::TimeDelta ResolveContext::TransactionTimeoutHelper(
    Iterator server_stats_begin,
    Iterator server_stats_end) {
  DCHECK_GE(features::kDnsMinTransactionTimeout.Get(), base::TimeDelta());
  DCHECK_GE(features::kDnsTransactionTimeoutMultiplier.Get(), 0.0);

  // Expect at least one configured server.
  DCHECK(server_stats_begin != server_stats_end);

  base::TimeDelta shortest_fallback_period = base::TimeDelta::Max();
  for (Iterator server_stats = server_stats_begin;
       server_stats != server_stats_end; ++server_stats) {
    shortest_fallback_period = std::min(
        shortest_fallback_period,
        NextFallbackPeriodHelper(&*server_stats, 0 /* num_backoffs */));
  }

  DCHECK_GE(shortest_fallback_period, base::TimeDelta());
  base::TimeDelta ratio_based_timeout =
      shortest_fallback_period *
      features::kDnsTransactionTimeoutMultiplier.Get();

  return std::max(features::kDnsMinTransactionTimeout.Get(),
                  ratio_based_timeout);
}

void ResolveContext::RecordRttForUma(size_t server_index,
                                     bool is_doh_server,
                                     base::TimeDelta rtt,
                                     int rv,
                                     base::TimeDelta base_fallback_period,
                                     const DnsSession* session) {
  DCHECK(IsCurrentSession(session));

  std::string query_type =
      GetQueryTypeForUma(server_index, is_doh_server, session);
  std::string provider_id =
      GetDohProviderIdForUma(server_index, is_doh_server, session);

  // Skip metrics for SecureNotValidated queries unless the provider is tagged
  // for extra logging.
  if (query_type == "SecureNotValidated" &&
      !GetProviderUseExtraLogging(server_index, is_doh_server, session)) {
    return;
  }

  if (rv == OK || rv == ERR_NAME_NOT_RESOLVED) {
    base::UmaHistogramMediumTimes(
        base::JoinString(
            {"Net.DNS.DnsTransaction", query_type, provider_id, "SuccessTime"},
            "."),
        rtt);
  } else {
    base::UmaHistogramMediumTimes(
        base::JoinString(
            {"Net.DNS.DnsTransaction", query_type, provider_id, "FailureTime"},
            "."),
        rtt);
  }
}

std::string ResolveContext::GetQueryTypeForUma(size_t server_index,
                                               bool is_doh_server,
                                               const DnsSession* session) {
  DCHECK(IsCurrentSession(session));

  if (!is_doh_server)
    return "Insecure";

  // Secure queries are validated if the DoH server state is available.
  if (GetDohServerAvailability(server_index, session))
    return "SecureValidated";

  return "SecureNotValidated";
}

std::string ResolveContext::GetDohProviderIdForUma(size_t server_index,
                                                   bool is_doh_server,
                                                   const DnsSession* session) {
  DCHECK(IsCurrentSession(session));

  if (is_doh_server) {
    return GetDohProviderIdForHistogramFromServerConfig(
        session->config().doh_config.servers()[server_index]);
  }

  return GetDohProviderIdForHistogramFromNameserver(
      session->config().nameservers[server_index]);
}

bool ResolveContext::GetProviderUseExtraLogging(size_t server_index,
                                                bool is_doh_server,
                                                const DnsSession* session) {
  DCHECK(IsCurrentSession(session));

  DohProviderEntry::List matching_entries;
  if (is_doh_server) {
    const DnsOverHttpsServerConfig& server_config =
        session->config().doh_config.servers()[server_index];
    matching_entries = FindDohProvidersMatchingServerConfig(server_config);
  } else {
    IPAddress server_address =
        session->config().nameservers[server_index].address();
    matching_entries = FindDohProvidersAssociatedWithAddress(server_address);
  }

  // Use extra logging if any matching provider entries have
  // `LoggingLevel::kExtra` set.
  return base::Contains(matching_entries,
                        DohProviderEntry::LoggingLevel::kExtra,
                        &DohProviderEntry::logging_level);
}

void ResolveContext::NotifyDohStatusObserversOfSessionChanged() {
  for (auto& observer : doh_status_observers_)
    observer.OnSessionChanged();
}

void ResolveContext::NotifyDohStatusObserversOfUnavailable(
    bool network_change) {
  for (auto& observer : doh_status_observers_)
    observer.OnDohServerUnavailable(network_change);
}

void ResolveContext::EmitDohAutoupgradeSuccessMetrics() {
  // This method should not be called if `current_session_` is not populated.
  CHECK(current_session_);

  // If DoH auto-upgrade is not enabled, then don't emit histograms.
  if (current_session_->config().secure_dns_mode != SecureDnsMode::kAutomatic) {
    return;
  }

  DohServerAutoupgradeStatus status;
  for (size_t i = 0; i < doh_server_stats_.size(); i++) {
    auto& entry = doh_server_stats_[i];

    if (ServerStatsToDohAvailability(entry)) {
      if (!entry.has_failed_previously) {
        // Auto-upgrade successful and no prior failures.
        status = DohServerAutoupgradeStatus::kSuccessWithNoPriorFailures;
      } else {
        // Auto-upgrade successful but some prior failures.
        status = DohServerAutoupgradeStatus::kSuccessWithSomePriorFailures;
      }
    } else {
      if (entry.last_success.is_null()) {
        if (entry.last_failure.is_null()) {
          // Skip entries that we've never attempted to use.
          continue;
        }

        // Auto-upgrade failed and DoH requests have never worked. It's possible
        // that an invalid DoH resolver config was provided by the user via
        // enterprise policy (in which case this state will always be associated
        // with the 'Other' provider_id), but it's also possible that there's an
        // issue with the user's network configuration or the provider's
        // infrastructure.
        status = DohServerAutoupgradeStatus::kFailureWithNoPriorSuccesses;
      } else {
        // Auto-upgrade is failing currently but has worked in the past.
        status = DohServerAutoupgradeStatus::kFailureWithSomePriorSuccesses;
      }
    }

    std::string provider_id = GetDohProviderIdForUma(i, /*is_doh_server=*/true,
                                                     current_session_.get());

    base::UmaHistogramEnumeration(
        base::JoinString(
            {"Net.DNS.ResolveContext.DohAutoupgrade", provider_id, "Status"},
            "."),
        status);
  }
}

// static
bool ResolveContext::ServerStatsToDohAvailability(
    const ResolveContext::ServerStats& stats) {
  return stats.last_failure_count < kAutomaticModeFailureLimit &&
         stats.current_connection_success;
}

}  // namespace net
```