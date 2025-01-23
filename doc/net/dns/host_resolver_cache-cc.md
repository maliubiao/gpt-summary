Response:
Let's break down the thought process for analyzing the `host_resolver_cache.cc` file.

1. **Understand the Core Purpose:** The file name itself, `host_resolver_cache.cc`, strongly suggests its primary function: caching host resolution results. This immediately tells us it's about storing and retrieving DNS lookups to improve performance.

2. **Identify Key Data Structures:**  Scan the code for important data structures. We see:
    * `HostResolverCache::Key`:  This likely represents the key used to store cache entries. It contains the domain name and `NetworkAnonymizationKey`.
    * `HostResolverCache::Entry`: This seems to be the value stored in the cache, holding the `HostResolverInternalResult`, source, security flag, and staleness generation.
    * `EntryMap`: This is likely the underlying data structure used for the cache itself. The `equal_range` calls in `LookupInternal` suggest it's a `std::multimap` (or similar), allowing multiple entries for the same key with different attributes.
    * `HostResolverInternalResult`:  This represents the actual resolved information (IP addresses, etc.). While its definition isn't in *this* file, we understand its role.
    * `NetworkAnonymizationKey`:  Related to privacy, this distinguishes cache entries based on the network context.

3. **Analyze Key Methods:** Go through the public methods of `HostResolverCache` and understand their roles:
    * `Lookup`: Retrieves a non-stale DNS result from the cache. It prioritizes secure results.
    * `LookupStale`: Retrieves the *best* available result, even if stale, providing information about its staleness.
    * `Set`: Adds a new DNS result to the cache.
    * `MakeAllResultsStale`: Invalidates all cached entries by incrementing the staleness generation.
    * `Serialize`/`RestoreFromValue`: Handles saving and loading the cache state (important for persistence).
    * `SerializeForLogging`: Creates a version of the cache data suitable for logging.
    * `EvictEntries`: Manages the cache size by removing entries.

4. **Examine Internal Logic (`LookupInternal`, `Set`, `EvictEntries`):**  These methods contain the core caching logic. Pay attention to:
    * How keys are compared (`KeyRef`).
    * How staleness is determined (using `IsStale` and `staleness_generation`).
    * How `LookupInternal` filters results based on query type, source, and security.
    * The eviction strategy (prioritizing stale entries and then least secure/soonest expiring).

5. **Consider Relationships to Other Components:** Think about how this cache interacts with the broader network stack. It's used by the host resolver to avoid redundant DNS lookups. The `NetworkAnonymizationKey` indicates a connection to privacy features.

6. **Address Specific Questions (Implicitly and Explicitly):** As you analyze the code, keep the prompt's questions in mind:
    * **Functionality:**  This emerges from understanding the purpose and methods.
    * **Relationship to JavaScript:** Think about how DNS resolution impacts web browsing. JavaScript uses APIs (like `fetch`) that rely on the browser resolving hostnames. Caching here directly affects the performance of those APIs.
    * **Logical Reasoning (Input/Output):** Consider what happens in specific scenarios (e.g., a successful cache hit, a cache miss, a stale entry). Imagine inputs to the `Lookup` or `Set` methods and the resulting state of the cache.
    * **User/Programming Errors:** Think about common mistakes like incorrect cache sizing, assumptions about cache consistency, or not understanding staleness.
    * **User Actions Leading Here (Debugging):** Trace a typical web request and how DNS resolution and caching fit into the process.

7. **Structure the Answer:** Organize the findings logically. Start with a high-level summary of the file's purpose, then detail the functionalities, JavaScript relationship, logical reasoning, errors, and debugging hints.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe this just stores IP addresses."  **Correction:** Realize it stores more than just IPs; it stores the entire `HostResolverInternalResult`, including query type, expiration, etc.
* **Initial thought:** "The cache is probably just a `std::map`." **Correction:** The `equal_range` usage suggests a `std::multimap` is more likely to handle multiple entries for the same host with different attributes (e.g., secure vs. insecure).
* **While analyzing staleness:**  Ensure a clear understanding of how `staleness_generation` and entry expiration times interact.
* **When thinking about JavaScript:**  Focus on the *impact* on JavaScript rather than direct code interaction (since this is C++).

By following these steps, iteratively understanding the code and addressing the prompt's questions, you can arrive at a comprehensive and accurate analysis of the `host_resolver_cache.cc` file.
This C++ source code file, `host_resolver_cache.cc`, located within the `net/dns` directory of the Chromium project, implements a **cache for DNS resolution results**. Its primary function is to store the outcomes of previous DNS lookups to avoid redundant queries, thereby improving the performance and efficiency of network requests.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Storing DNS Resolution Results:** The cache stores `HostResolverInternalResult` objects, which encapsulate the results of DNS queries (e.g., IP addresses, TTL). These results are associated with a specific domain name, network anonymization key, query type (e.g., A, AAAA), resolver source, and security status.

2. **Lookup of Cached Results:**  The cache provides methods (`Lookup`, `LookupStale`) to retrieve previously stored DNS results based on the lookup criteria (domain name, network anonymization key, query type, source, security).

3. **Staleness Management:** The cache implements a mechanism to track the staleness of entries. Entries become stale either due to their TTL expiring or through a "staleness generation" mechanism, allowing for proactive invalidation of cached results.

4. **Cache Invalidation:** The `MakeAllResultsStale` method allows for the immediate invalidation of all entries in the cache by incrementing a global staleness generation counter.

5. **Cache Eviction:**  To manage memory usage, the cache implements an eviction policy. When the cache reaches its maximum size, it removes entries, prioritizing stale entries and then the least secure, soonest-to-expire entries.

6. **Serialization and Deserialization:** The cache supports serialization (`Serialize`, `SerializeForLogging`) to persist its state (e.g., to disk) and deserialization (`RestoreFromValue`) to restore its state from a serialized representation. This is useful for persisting DNS cache across browser sessions.

**Relationship with JavaScript Functionality:**

While the `host_resolver_cache.cc` file is written in C++, it directly impacts the performance of JavaScript code running in a web browser. Here's how:

* **Faster Page Loads:** When a website's resources (images, scripts, etc.) are requested, the browser needs to resolve the domain names to IP addresses. The DNS cache avoids making network requests for previously resolved domains, leading to significantly faster page load times. JavaScript code initiating network requests (e.g., using `fetch` or `XMLHttpRequest`) benefits directly from this caching.

* **Reduced Latency for APIs:**  JavaScript code often interacts with backend services via APIs. These API calls involve resolving the API endpoint's domain name. The DNS cache minimizes the latency associated with these resolutions.

**Example:**

Imagine a JavaScript application making a `fetch` request to `https://api.example.com/data`.

1. **Without Cache:** The browser would perform a DNS lookup for `api.example.com` every time this request is made if the result is not cached.

2. **With Cache:**
   * The first time the request is made, `host_resolver_cache.cc` (through the Host Resolver) performs the DNS lookup and stores the result.
   * Subsequent requests from JavaScript to `api.example.com` will first check the cache. If a valid, non-stale entry exists, the cached IP address is used directly, skipping the network DNS lookup.

**Logical Reasoning (Hypothetical Input & Output):**

**Scenario:** The cache has a `max_entries_` of 10.

**Hypothetical Input (JavaScript initiates a network request):**

1. JavaScript makes a `fetch` request to `http://www.example.com`. Assume no entry for `www.example.com` exists in the cache.
2. The Host Resolver performs a DNS lookup and gets the IP address `192.0.2.1` with a TTL of 60 seconds.
3. `host_resolver_cache.cc` receives this result with `secure = false` and `source = SYSTEM`. It stores this in the cache.

**Hypothetical Output (Cache State):**

The cache now contains one entry:

```
Key: { domain_name: "www.example.com", network_anonymization_key: [default], query_type: A, source: SYSTEM, secure: false }
Value: { result: { ip_address: "192.0.2.1", ttl: 60s, ... }, source: SYSTEM, secure: false, staleness_generation: current_generation }
```

**Hypothetical Input (Subsequent request):**

1. 30 seconds later, JavaScript makes another `fetch` request to `http://www.example.com`.

**Hypothetical Output:**

* The `Lookup` method in `host_resolver_cache.cc` is called with the relevant key.
* It finds the entry for `www.example.com`.
* The entry is not stale (TTL has not expired).
* The cached `HostResolverInternalResult` is returned, and the browser uses the IP address `192.0.2.1` directly. No new DNS lookup is performed.

**Hypothetical Input (Cache Full):**

1. The cache is full (contains 10 entries). JavaScript makes a request for a new domain that's not cached.

**Hypothetical Output:**

* The `Set` method is called to add the new DNS result.
* `EvictEntries` is called because the cache is full.
* `EvictEntries` identifies a stale entry (or, if none are stale, the least secure, soonest-to-expire entry) and removes it to make space for the new entry.

**User or Programming Common Usage Errors:**

1. **Incorrect Cache Size Configuration:**  Setting an inappropriately small `max_entries_` value can lead to frequent cache misses, negating the benefits of caching. Conversely, a very large cache might consume excessive memory.

2. **Assuming Real-time Updates:** Developers might mistakenly assume the DNS cache always reflects the latest DNS records. DNS records have Time-To-Live (TTL) values, and cached entries are only valid for that duration. Changes to DNS records might not be immediately reflected in the cache.

3. **Ignoring Network Anonymization Key:**  For privacy reasons, DNS resolution can be tied to a `NetworkAnonymizationKey`. Incorrectly handling or ignoring this key could lead to unexpected cache behavior or privacy issues.

4. **Forcing Cache Invalidation Too Aggressively:** While `MakeAllResultsStale` is useful in certain scenarios, overusing it can defeat the purpose of the cache, leading to increased DNS traffic and latency.

**Example of User Operation Reaching This Code (Debugging Clues):**

Let's trace a user action that could lead to interaction with `host_resolver_cache.cc`:

1. **User types a URL into the browser address bar and presses Enter:**
   * The browser needs to resolve the hostname in the URL (e.g., `www.google.com`).
   * The browser's networking stack initiates a DNS lookup process.
   * **The `Lookup` method in `host_resolver_cache.cc` is the first place the system checks.** It searches for a cached entry for `www.google.com` with the relevant parameters (network anonymization key, query type, etc.).
   * **If a valid entry is found (cache hit):** The cached IP address is returned, and the browser proceeds to establish a connection to that IP.
   * **If no valid entry is found (cache miss):**
     * The browser proceeds with a real DNS lookup over the network.
     * Once the DNS lookup completes, the result (IP address, TTL, etc.) is passed to the `Set` method in `host_resolver_cache.cc`.
     * The `Set` method adds the new entry to the cache.

2. **User clicks a link on a webpage:**
   * Similar to typing a URL, the browser needs to resolve the hostname of the linked resource.
   * The `Lookup` method in `host_resolver_cache.cc` is consulted first.

3. **JavaScript code on a webpage makes a `fetch` or `XMLHttpRequest` call:**
   * The browser needs to resolve the hostname of the API endpoint or resource being fetched.
   * Again, the `Lookup` method in `host_resolver_cache.cc` is the initial point of contact to check for cached DNS results.

**Debugging Clues:**

If you are debugging network issues and suspect the DNS cache is involved, you might look for:

* **Unexpectedly old IP addresses being used:** This could indicate a stale entry in the cache.
* **Performance improvements after a restart or cache clear:** This suggests the cache was previously hindering performance due to stale entries.
* **Inconsistent behavior across different network contexts (related to Network Anonymization Key):** This could point to issues with how the cache is keyed and accessed based on the anonymization key.
* **High DNS lookup times in network tracing tools when the cache should have a valid entry:** This could indicate a problem with the cache lookup logic or entry staleness.

By understanding the functionalities of `host_resolver_cache.cc` and its interaction with the browser's network stack, developers can better diagnose and resolve network-related issues and optimize the performance of web applications.

### 提示词
```
这是目录为net/dns/host_resolver_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_cache.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/clock.h"
#include "base/time/time.h"
#include "net/base/network_anonymization_key.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_source.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_canon.h"
#include "url/url_canon_stdstring.h"

namespace net {

namespace {

constexpr std::string_view kNakKey = "network_anonymization_key";
constexpr std::string_view kSourceKey = "source";
constexpr std::string_view kSecureKey = "secure";
constexpr std::string_view kResultKey = "result";
constexpr std::string_view kStalenessGenerationKey = "staleness_generation";
constexpr std::string_view kMaxEntriesKey = "max_entries";
constexpr std::string_view kEntriesKey = "entries";

}  // namespace

HostResolverCache::Key::~Key() = default;

HostResolverCache::StaleLookupResult::StaleLookupResult(
    const HostResolverInternalResult& result,
    std::optional<base::TimeDelta> expired_by,
    bool stale_by_generation)
    : result(result),
      expired_by(expired_by),
      stale_by_generation(stale_by_generation) {}

HostResolverCache::HostResolverCache(size_t max_results,
                                     const base::Clock& clock,
                                     const base::TickClock& tick_clock)
    : max_entries_(max_results), clock_(clock), tick_clock_(tick_clock) {
  DCHECK_GT(max_entries_, 0u);
}

HostResolverCache::~HostResolverCache() = default;

HostResolverCache::HostResolverCache(HostResolverCache&&) = default;

HostResolverCache& HostResolverCache::operator=(HostResolverCache&&) = default;

const HostResolverInternalResult* HostResolverCache::Lookup(
    std::string_view domain_name,
    const NetworkAnonymizationKey& network_anonymization_key,
    DnsQueryType query_type,
    HostResolverSource source,
    std::optional<bool> secure) const {
  std::vector<EntryMap::const_iterator> candidates = LookupInternal(
      domain_name, network_anonymization_key, query_type, source, secure);

  // Get the most secure, last-matching (which is first in the vector returned
  // by LookupInternal()) non-expired result.
  base::TimeTicks now_ticks = tick_clock_->NowTicks();
  base::Time now = clock_->Now();
  HostResolverInternalResult* most_secure_result = nullptr;
  for (const EntryMap::const_iterator& candidate : candidates) {
    DCHECK(candidate->second.result->timed_expiration().has_value());

    if (candidate->second.IsStale(now, now_ticks, staleness_generation_)) {
      continue;
    }

    // If the candidate is secure, or all results are insecure, no need to check
    // any more.
    if (candidate->second.secure || !secure.value_or(true)) {
      return candidate->second.result.get();
    } else if (most_secure_result == nullptr) {
      most_secure_result = candidate->second.result.get();
    }
  }

  return most_secure_result;
}

std::optional<HostResolverCache::StaleLookupResult>
HostResolverCache::LookupStale(
    std::string_view domain_name,
    const NetworkAnonymizationKey& network_anonymization_key,
    DnsQueryType query_type,
    HostResolverSource source,
    std::optional<bool> secure) const {
  std::vector<EntryMap::const_iterator> candidates = LookupInternal(
      domain_name, network_anonymization_key, query_type, source, secure);

  // Get the least expired, most secure result.
  base::TimeTicks now_ticks = tick_clock_->NowTicks();
  base::Time now = clock_->Now();
  const Entry* best_match = nullptr;
  base::TimeDelta best_match_time_until_expiration;
  for (const EntryMap::const_iterator& candidate : candidates) {
    DCHECK(candidate->second.result->timed_expiration().has_value());

    base::TimeDelta candidate_time_until_expiration =
        candidate->second.TimeUntilExpiration(now, now_ticks);

    if (!candidate->second.IsStale(now, now_ticks, staleness_generation_) &&
        (candidate->second.secure || !secure.value_or(true))) {
      // If a non-stale candidate is secure, or all results are insecure, no
      // need to check any more.
      best_match = &candidate->second;
      best_match_time_until_expiration = candidate_time_until_expiration;
      break;
    } else if (best_match == nullptr ||
               (!candidate->second.IsStale(now, now_ticks,
                                           staleness_generation_) &&
                best_match->IsStale(now, now_ticks, staleness_generation_)) ||
               candidate->second.staleness_generation >
                   best_match->staleness_generation ||
               (candidate->second.staleness_generation ==
                    best_match->staleness_generation &&
                candidate_time_until_expiration >
                    best_match_time_until_expiration) ||
               (candidate->second.staleness_generation ==
                    best_match->staleness_generation &&
                candidate_time_until_expiration ==
                    best_match_time_until_expiration &&
                candidate->second.secure && !best_match->secure)) {
      best_match = &candidate->second;
      best_match_time_until_expiration = candidate_time_until_expiration;
    }
  }

  if (best_match == nullptr) {
    return std::nullopt;
  } else {
    std::optional<base::TimeDelta> expired_by;
    if (best_match_time_until_expiration.is_negative()) {
      expired_by = best_match_time_until_expiration.magnitude();
    }
    return StaleLookupResult(
        *best_match->result, expired_by,
        best_match->staleness_generation != staleness_generation_);
  }
}

void HostResolverCache::Set(
    std::unique_ptr<HostResolverInternalResult> result,
    const NetworkAnonymizationKey& network_anonymization_key,
    HostResolverSource source,
    bool secure) {
  Set(std::move(result), network_anonymization_key, source, secure,
      /*replace_existing=*/true, staleness_generation_);
}

void HostResolverCache::MakeAllResultsStale() {
  ++staleness_generation_;
}

base::Value HostResolverCache::Serialize() const {
  // Do not serialize any entries without a persistable anonymization key
  // because it is required to store and restore entries with the correct
  // annonymization key. A non-persistable anonymization key is typically used
  // for short-lived contexts, and associated entries are not expected to be
  // useful after persistence to disk anyway.
  return SerializeEntries(/*serialize_staleness_generation=*/false,
                          /*require_persistable_anonymization_key=*/true);
}

bool HostResolverCache::RestoreFromValue(const base::Value& value) {
  const base::Value::List* list = value.GetIfList();
  if (!list) {
    return false;
  }

  for (const base::Value& list_value : *list) {
    // Simply stop on reaching max size rather than attempting to figure out if
    // any current entries should be evicted over the deserialized entries.
    if (entries_.size() == max_entries_) {
      return true;
    }

    const base::Value::Dict* dict = list_value.GetIfDict();
    if (!dict) {
      return false;
    }

    const base::Value* anonymization_key_value = dict->Find(kNakKey);
    NetworkAnonymizationKey anonymization_key;
    if (!anonymization_key_value ||
        !NetworkAnonymizationKey::FromValue(*anonymization_key_value,
                                            &anonymization_key)) {
      return false;
    }

    const base::Value* source_value = dict->Find(kSourceKey);
    std::optional<HostResolverSource> source =
        source_value == nullptr ? std::nullopt
                                : HostResolverSourceFromValue(*source_value);
    if (!source.has_value()) {
      return false;
    }

    std::optional<bool> secure = dict->FindBool(kSecureKey);
    if (!secure.has_value()) {
      return false;
    }

    const base::Value* result_value = dict->Find(kResultKey);
    std::unique_ptr<HostResolverInternalResult> result =
        result_value == nullptr
            ? nullptr
            : HostResolverInternalResult::FromValue(*result_value);
    if (!result || !result->timed_expiration().has_value()) {
      return false;
    }

    // `staleness_generation_ - 1` to make entry stale-by-generation.
    Set(std::move(result), anonymization_key, source.value(), secure.value(),
        /*replace_existing=*/false, staleness_generation_ - 1);
  }

  CHECK_LE(entries_.size(), max_entries_);
  return true;
}

base::Value HostResolverCache::SerializeForLogging() const {
  base::Value::Dict dict;

  dict.Set(kMaxEntriesKey, base::checked_cast<int>(max_entries_));
  dict.Set(kStalenessGenerationKey, staleness_generation_);

  // Include entries with non-persistable anonymization keys, so the log can
  // contain all entries. Restoring from this serialization is not supported.
  dict.Set(kEntriesKey,
           SerializeEntries(/*serialize_staleness_generation=*/true,
                            /*require_persistable_anonymization_key=*/false));

  return base::Value(std::move(dict));
}

HostResolverCache::Entry::Entry(
    std::unique_ptr<HostResolverInternalResult> result,
    HostResolverSource source,
    bool secure,
    int staleness_generation)
    : result(std::move(result)),
      source(source),
      secure(secure),
      staleness_generation(staleness_generation) {}

HostResolverCache::Entry::~Entry() = default;

HostResolverCache::Entry::Entry(Entry&&) = default;

HostResolverCache::Entry& HostResolverCache::Entry::operator=(Entry&&) =
    default;

bool HostResolverCache::Entry::IsStale(base::Time now,
                                       base::TimeTicks now_ticks,
                                       int current_staleness_generation) const {
  return staleness_generation != current_staleness_generation ||
         TimeUntilExpiration(now, now_ticks).is_negative();
}

base::TimeDelta HostResolverCache::Entry::TimeUntilExpiration(
    base::Time now,
    base::TimeTicks now_ticks) const {
  if (result->expiration().has_value()) {
    return result->expiration().value() - now_ticks;
  } else {
    DCHECK(result->timed_expiration().has_value());
    return result->timed_expiration().value() - now;
  }
}

std::vector<HostResolverCache::EntryMap::const_iterator>
HostResolverCache::LookupInternal(
    std::string_view domain_name,
    const NetworkAnonymizationKey& network_anonymization_key,
    DnsQueryType query_type,
    HostResolverSource source,
    std::optional<bool> secure) const {
  auto matches = std::vector<EntryMap::const_iterator>();

  if (entries_.empty()) {
    return matches;
  }

  std::string canonicalized;
  url::StdStringCanonOutput output(&canonicalized);
  url::CanonHostInfo host_info;

  url::CanonicalizeHostVerbose(domain_name.data(),
                               url::Component(0, domain_name.size()), &output,
                               &host_info);

  // For performance, when canonicalization can't canonicalize, minimize string
  // copies and just reuse the input std::string_view. This optimization
  // prevents easily reusing a MaybeCanoncalize util with similar code.
  std::string_view lookup_name = domain_name;
  if (host_info.family == url::CanonHostInfo::Family::NEUTRAL) {
    output.Complete();
    lookup_name = canonicalized;
  }

  auto range = entries_.equal_range(
      KeyRef{lookup_name, raw_ref(network_anonymization_key)});
  if (range.first == entries_.cend() || range.second == entries_.cbegin() ||
      range.first == range.second) {
    return matches;
  }

  // Iterate in reverse order to return most-recently-added entry first.
  auto it = --range.second;
  while (true) {
    if ((query_type == DnsQueryType::UNSPECIFIED ||
         it->second.result->query_type() == DnsQueryType::UNSPECIFIED ||
         query_type == it->second.result->query_type()) &&
        (source == HostResolverSource::ANY || source == it->second.source) &&
        (!secure.has_value() || secure.value() == it->second.secure)) {
      matches.push_back(it);
    }

    if (it == range.first) {
      break;
    }
    --it;
  }

  return matches;
}

void HostResolverCache::Set(
    std::unique_ptr<HostResolverInternalResult> result,
    const NetworkAnonymizationKey& network_anonymization_key,
    HostResolverSource source,
    bool secure,
    bool replace_existing,
    int staleness_generation) {
  DCHECK(result);
  // Result must have at least a timed expiration to be a cacheable result.
  DCHECK(result->timed_expiration().has_value());

  std::vector<EntryMap::const_iterator> matches =
      LookupInternal(result->domain_name(), network_anonymization_key,
                     result->query_type(), source, secure);

  if (!matches.empty() && !replace_existing) {
    // Matches already present that are not to be replaced.
    return;
  }

  for (const EntryMap::const_iterator& match : matches) {
    entries_.erase(match);
  }

  std::string domain_name = result->domain_name();
  entries_.emplace(
      Key(std::move(domain_name), network_anonymization_key),
      Entry(std::move(result), source, secure, staleness_generation));

  if (entries_.size() > max_entries_) {
    EvictEntries();
  }
}

// Remove all stale entries, or if none stale, the soonest-to-expire,
// least-secure entry.
void HostResolverCache::EvictEntries() {
  base::TimeTicks now_ticks = tick_clock_->NowTicks();
  base::Time now = clock_->Now();

  bool stale_found = false;
  base::TimeDelta soonest_time_till_expriation = base::TimeDelta::Max();
  std::optional<EntryMap::const_iterator> best_for_removal;

  auto it = entries_.cbegin();
  while (it != entries_.cend()) {
    if (it->second.IsStale(now, now_ticks, staleness_generation_)) {
      stale_found = true;
      it = entries_.erase(it);
    } else {
      base::TimeDelta time_till_expiration =
          it->second.TimeUntilExpiration(now, now_ticks);

      if (!best_for_removal.has_value() ||
          time_till_expiration < soonest_time_till_expriation ||
          (time_till_expiration == soonest_time_till_expriation &&
           best_for_removal.value()->second.secure && !it->second.secure)) {
        soonest_time_till_expriation = time_till_expiration;
        best_for_removal = it;
      }

      ++it;
    }
  }

  if (!stale_found) {
    CHECK(best_for_removal.has_value());
    entries_.erase(best_for_removal.value());
  }

  CHECK_LE(entries_.size(), max_entries_);
}

base::Value HostResolverCache::SerializeEntries(
    bool serialize_staleness_generation,
    bool require_persistable_anonymization_key) const {
  base::Value::List list;

  for (const auto& [key, entry] : entries_) {
    base::Value::Dict dict;

    if (serialize_staleness_generation) {
      dict.Set(kStalenessGenerationKey, entry.staleness_generation);
    }

    base::Value anonymization_key_value;
    if (!key.network_anonymization_key.ToValue(&anonymization_key_value)) {
      if (require_persistable_anonymization_key) {
        continue;
      } else {
        // If the caller doesn't care about anonymization keys that can be
        // serialized and restored, construct a serialization just for the sake
        // of logging information.
        anonymization_key_value =
            base::Value("Non-persistable network anonymization key: " +
                        key.network_anonymization_key.ToDebugString());
      }
    }

    dict.Set(kNakKey, std::move(anonymization_key_value));
    dict.Set(kSourceKey, ToValue(entry.source));
    dict.Set(kSecureKey, entry.secure);
    dict.Set(kResultKey, entry.result->ToValue());

    list.Append(std::move(dict));
  }

  return base::Value(std::move(list));
}

}  // namespace net
```