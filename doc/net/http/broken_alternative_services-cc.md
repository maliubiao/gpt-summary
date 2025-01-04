Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `broken_alternative_services.cc` within the Chromium network stack. The request also asks for connections to JavaScript, examples of logical reasoning, common usage errors, and debugging hints.

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick scan of the code looking for prominent keywords and structures. This immediately reveals:

* **`Copyright 2017 The Chromium Authors`:**  Indicates this is a well-established part of Chromium.
* **`#include` statements:**  Shows dependencies on other Chromium components like `base/containers/adapters.h`, `base/functional/bind.h`, `base/memory/singleton.h`, `base/time/tick_clock.h`, `base/time/time.h`, and crucially, `net/http/http_server_properties.h`. This last one hints at the purpose: managing server properties related to HTTP.
* **Class names:** `BrokenAlternativeService`, `BrokenAlternativeServices`. The plural suggests a collection or manager of the singular.
* **Member variables:** In `BrokenAlternativeServices`, we see `delegate_`, `clock_`, `recently_broken_alternative_services_`, `broken_alternative_service_list_`, `broken_alternative_service_map_`, `broken_alternative_services_on_default_network_`, `expiration_timer_`, `initial_delay_`, `exponential_backoff_on_initial_delay_`. These provide clues about the internal state.
* **Method names:**  `MarkBroken`, `IsBroken`, `Confirm`, `Clear`, `OnDefaultNetworkChanged`, `SetBrokenAndRecentlyBrokenAlternativeServices`, `ExpireBrokenAlternateProtocolMappings`. These are action verbs that describe the class's behavior.
* **Constants:** `kDefaultBrokenAlternativeProtocolDelay`, `kBrokenDelayMaxShift`, `kMinBrokenAlternativeProtocolDelay`, `kMaxBrokenAlternativeProtocolDelay`. These define important time-related parameters.
* **`namespace net`:**  Confirms this belongs to the networking part of Chromium.
* **Comments:**  Helpful comments like "Default broken alternative services..." and descriptions of methods provide context.

**3. Deciphering the Core Functionality:**

Based on the keywords and structure, the core functionality seems to be:

* **Tracking broken "alternative services":** This refers to alternative ways to connect to a server (e.g., HTTP/2 instead of HTTP/1.1, or a different port).
* **Remembering failures:** The code keeps track of which alternative services have failed.
* **Implementing backoff:**  When an alternative service fails, it's not retried immediately. There's a delay that increases with repeated failures.
* **Handling network changes:**  The system can react to changes in the network.
* **Persistence (implied):**  The `SetBrokenAndRecentlyBrokenAlternativeServices` method suggests the ability to load and save the state of broken services. This is further strengthened by the dependency on `http_server_properties.h`, which is often used for persistent storage of HTTP-related information.

**4. Connecting to JavaScript (or Lack Thereof):**

The code itself is C++. There's no direct JavaScript interaction within *this file*. However, the *purpose* of this code is to inform networking decisions. JavaScript in a web page might trigger network requests. Therefore, the connection is *indirect*. JavaScript doesn't call this code directly, but its actions can *cause* this code to be used.

**5. Logical Reasoning and Examples:**

The `ComputeBrokenAlternativeServiceExpirationDelay` function is a prime example for logical reasoning. We can trace the logic with different inputs:

* **Hypothesis:**  Repeated failures lead to longer delays.
* **Input:** `broken_count = 0`, `initial_delay = 10s` -> `Output`: `10s`
* **Input:** `broken_count = 1`, `initial_delay = 10s`, `exponential_backoff_on_initial_delay = true` -> `Output`: `20s`
* **Input:** `broken_count = 1`, `initial_delay = 10s`, `exponential_backoff_on_initial_delay = false` -> `Output`: `300s` (default)
* **Input:** `broken_count = 19`, `initial_delay = 10s`, `exponential_backoff_on_initial_delay = true` -> `Output`: `kMaxBrokenAlternativeProtocolDelay` (due to the limit).

**6. Common Usage Errors:**

The code has built-in checks (like the `DCHECK` statements) and clear expectations. Common errors would likely occur in code *using* this class:

* **Forgetting to substitute the origin host:** The comments mention that an empty host means the origin host. If a caller forgets to fill this in, it could lead to unexpected behavior.
* **Incorrectly managing the `Delegate`:** The `BrokenAlternativeServices` class uses a delegate. If the delegate isn't implemented correctly, or if the caller doesn't set it up, things won't work.
* **Misunderstanding the timing:** The backoff mechanism and the network change handling are crucial. Incorrect assumptions about when a broken service will be retried could lead to problems.

**7. Debugging Hints and User Actions:**

To reach this code during debugging, a user would likely be experiencing issues with network connections:

* **User Action:** A user visits a website.
* **Browser Behavior:** The browser attempts to use an alternative service (e.g., HTTP/2).
* **Failure:** The attempt to connect via the alternative service fails.
* **`MarkBroken` is called:** This code is invoked to record the failure.
* **Subsequent Attempts:** If the browser tries to use the same alternative service again too soon, `IsBroken` will return `true`, and the browser will avoid it.
* **Debugging Scenario:**  A developer investigating why a website isn't using HTTP/2 might look at the list of broken alternative services.

**8. Structuring the Answer:**

Finally, the information needs to be structured clearly, using headings and bullet points to address each part of the request: functionality, JavaScript relationship, logical reasoning, usage errors, and debugging. This involves summarizing the insights gained from the code analysis.
The file `net/http/broken_alternative_services.cc` in the Chromium network stack is responsible for **tracking and managing alternative services that have been determined to be broken or unreliable for specific origins or network configurations.**  This helps the browser avoid repeatedly trying to use these broken alternative connections, improving performance and user experience.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Tracking Broken Alternative Services:** It maintains a list of `BrokenAlternativeService` objects. Each `BrokenAlternativeService` identifies a specific alternative service (protocol, host, port) associated with a network anonymization key (NAK).
* **Recording Failures:** When an attempt to connect using an alternative service fails, this component can mark that specific alternative service as "broken" for a certain period.
* **Exponential Backoff:**  The duration for which an alternative service is marked as broken increases exponentially with repeated failures. This prevents the browser from constantly retrying a failing connection.
* **Expiration Mechanism:**  It uses a timer to automatically remove broken alternative services from the list after their broken period expires.
* **Network Change Awareness:** It can track broken alternative services specifically for the "default network." When the default network changes, these broken entries can be cleared, as the brokenness might be specific to the previous network.
* **Recent Failure Tracking:** It keeps a history of recently broken alternative services to avoid immediately retrying them, even if their full broken period hasn't expired.
* **Persistence (Indirectly):** While this file doesn't handle persistence directly, it interacts with `net/http/http_server_properties.h`. The `HttpServerProperties` component is responsible for storing and retrieving this broken alternative service information across browser sessions.
* **Configuration:** It allows setting parameters like the initial delay before marking an alternative service as broken and whether to use exponential backoff from the initial delay.

**Relationship with JavaScript:**

This C++ code doesn't directly interact with JavaScript code running in web pages. However, it plays a crucial role in how network requests initiated by JavaScript are handled:

* **Indirect Influence:** When a JavaScript application (e.g., using `fetch()` or `XMLHttpRequest`) makes a network request, the Chromium network stack (including this component) decides how to fulfill that request.
* **Avoiding Broken Connections:** If this component has marked a particular alternative service for the target origin as broken, the network stack will avoid using that alternative service for subsequent requests from that origin, even if JavaScript initiates them. This leads to faster successful connections by skipping potentially failing ones.
* **No Direct API:**  JavaScript doesn't have a direct API to query or manipulate the state of broken alternative services.

**Example of Indirect Relationship:**

1. **JavaScript makes a fetch request:**  `fetch('https://example.com')`
2. **Browser tries HTTP/2:** The browser might initially try to connect to `example.com` using HTTP/2 (an alternative service).
3. **HTTP/2 connection fails:** If the HTTP/2 connection fails for some reason.
4. **`MarkBroken` is called:** The `BrokenAlternativeServices` component is informed and marks HTTP/2 for `example.com` as broken.
5. **Subsequent JavaScript fetch request:** If the JavaScript code makes another `fetch('https://example.com')` request soon after.
6. **Broken service check:** The network stack consults `BrokenAlternativeServices`.
7. **HTTP/1.1 is used:** Because HTTP/2 is marked as broken, the browser might directly try connecting using HTTP/1.1, avoiding the delay of attempting a broken connection.

**Logical Reasoning with Assumptions and Outputs:**

Let's consider the `ComputeBrokenAlternativeServiceExpirationDelay` function:

**Assumptions:**

* `exponential_backoff_on_initial_delay` is `true`.
* `kDefaultBrokenAlternativeProtocolDelay` is 300 seconds.
* `kMinBrokenAlternativeProtocolDelay` is 1 second.
* `kMaxBrokenAlternativeProtocolDelay` is 2 days.

**Inputs and Outputs:**

* **Input:** `broken_count = 0`, `initial_delay = 60s`
   * **Output:** `60s` (First failure, uses the provided initial delay).
* **Input:** `broken_count = 1`, `initial_delay = 60s`
   * **Output:** `120s` (Second failure, initial delay * 2^1).
* **Input:** `broken_count = 3`, `initial_delay = 60s`
   * **Output:** `480s` (Fourth failure, initial delay * 2^3).
* **Input:** `broken_count = 10`, `initial_delay = 60s`
   * **Output:** `61440s` (Eleventh failure, initial delay * 2^10).
* **Input:** `broken_count = 19`, `initial_delay = 60s`
   * **Output:** `kMaxBrokenAlternativeProtocolDelay` (Reaches the maximum delay limit).
* **Input:** `broken_count = 0`, `initial_delay = 0.5s`
   * **Output:** `1s` (Initial delay is clamped to the minimum).
* **Input:** `broken_count = 0`, `initial_delay = 600s`
   * **Output:** `300s` (Initial delay is clamped to the default maximum).

**If `exponential_backoff_on_initial_delay` is `false`:**

* **Input:** `broken_count = 1`, `initial_delay = 60s`
   * **Output:** `300s` (Second failure, uses the default delay * 2^(1-1)).
* **Input:** `broken_count = 2`, `initial_delay = 60s`
   * **Output:** `600s` (Third failure, uses the default delay * 2^(2-1)).

**User and Programming Common Usage Errors:**

1. **Incorrectly configuring `HttpServerProperties`:** If the component responsible for storing and retrieving broken alternative service information (`HttpServerProperties`) is not configured correctly, the browser might not remember broken services across sessions. This isn't an error within this specific file but affects its overall functionality.

2. **Assuming immediate retry after failure:** A common misunderstanding is that if an alternative service fails once, it will be retried immediately. This component's exponential backoff mechanism prevents this. Developers or users might misinterpret temporary network issues as permanent problems if they don't account for this backoff.

3. **Manually trying to force alternative services:** Users or developers might try to force the browser to use a specific alternative service (e.g., through browser flags or extensions) without understanding that it might be marked as broken. This can lead to connection failures and performance issues.

4. **Clearing browser data:** Clearing browser history or specific types of browsing data might inadvertently clear the stored broken alternative service information. This could lead to the browser re-attempting connections to previously broken services.

**User Operations Leading to This Code (Debugging Clues):**

To reach this code during debugging, a developer would likely be investigating scenarios related to:

1. **Alternative Service Failures:**
   * **User Action:** Visiting a website that advertises alternative services (e.g., HTTP/2, QUIC).
   * **Browser Behavior:** The browser attempts to connect using one of these alternative services.
   * **Failure Scenario:** The connection attempt fails due to network issues, server misconfiguration, or protocol incompatibility.
   * **Code Invocation:** The code in `broken_alternative_services.cc` is called to record the failure and mark the service as broken.

2. **Repeated Connection Issues:**
   * **User Action:**  Repeatedly trying to access a website that has a problematic alternative service.
   * **Browser Behavior:** The browser initially tries the alternative service, it fails, and this component increases the backoff time. Subsequent attempts might bypass the broken service or be delayed.
   * **Debugging Point:** Investigating why connections to a specific website are slow or failing intermittently.

3. **Network Changes:**
   * **User Action:** Switching between Wi-Fi networks or a wired connection.
   * **Code Invocation:** The `OnDefaultNetworkChanged()` method is called, potentially clearing broken alternative service entries that were specific to the previous network.
   * **Debugging Point:** Understanding why alternative services start working again after a network change.

4. **Investigating HTTP/2 or QUIC Issues:**
   * **Developer Focus:**  Trying to diagnose why a website isn't using HTTP/2 or QUIC as expected.
   * **Debugging Steps:** Examining the list of broken alternative services to see if these protocols have been marked as broken for the target origin.

**Steps to Reach This Code (as a Debugging Path):**

1. **Start with a network request failure:** Observe a failed attempt to connect to a website or a slow connection.
2. **Identify potential alternative service involvement:** If the website supports HTTP/2 or QUIC, these are likely candidates.
3. **Look for error messages or logs related to alternative services:** Chromium's NetLog (accessible via `chrome://net-export/`) can provide detailed information about network events, including alternative service attempts and failures.
4. **Set breakpoints in `broken_alternative_services.cc`:** Place breakpoints in methods like `MarkBroken`, `IsBroken`, `ExpireBrokenAlternateProtocolMappings`, or `OnDefaultNetworkChanged` to track the flow of execution when a network request involving alternative services is made.
5. **Analyze the state of broken alternative services:** Inspect the `broken_alternative_service_list_` and `broken_alternative_service_map_` to see which alternative services are currently marked as broken and their expiration times.
6. **Trace back the cause of the `MarkBroken` call:** Determine what event triggered the marking of a specific alternative service as broken (e.g., a connection error, a timeout).

By following these steps, a developer can pinpoint the role of `broken_alternative_services.cc` in preventing the browser from repeatedly attempting to use failing alternative connections, ultimately leading to a better user experience.

Prompt: 
```
这是目录为net/http/broken_alternative_services.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/broken_alternative_services.h"

#include "base/containers/adapters.h"
#include "base/functional/bind.h"
#include "base/memory/singleton.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "net/http/http_server_properties.h"

namespace net {

namespace {

// Default broken alternative services, which is used when
// exponential_backoff_on_initial_delay is false.
constexpr base::TimeDelta kDefaultBrokenAlternativeProtocolDelay =
    base::Seconds(300);
// Subsequent failures result in exponential (base 2) backoff.
// Given the shortest broken delay is 1s, limit binary shift to limit delay to
// approximately 2 days.
const int kBrokenDelayMaxShift = 18;
// Lower and upper limits of broken alternative service delay.
constexpr base::TimeDelta kMinBrokenAlternativeProtocolDelay = base::Seconds(1);
constexpr base::TimeDelta kMaxBrokenAlternativeProtocolDelay = base::Days(2);

base::TimeDelta ComputeBrokenAlternativeServiceExpirationDelay(
    int broken_count,
    base::TimeDelta initial_delay,
    bool exponential_backoff_on_initial_delay) {
  DCHECK_GE(broken_count, 0);
  // Make sure initial delay is within [1s, 300s].
  if (initial_delay < kMinBrokenAlternativeProtocolDelay) {
    initial_delay = kMinBrokenAlternativeProtocolDelay;
  }
  if (initial_delay > kDefaultBrokenAlternativeProtocolDelay) {
    initial_delay = kDefaultBrokenAlternativeProtocolDelay;
  }
  if (broken_count == 0) {
    return initial_delay;
  }
  // Limit broken_count to avoid overflow.
  if (broken_count > kBrokenDelayMaxShift) {
    broken_count = kBrokenDelayMaxShift;
  }
  base::TimeDelta delay;
  if (exponential_backoff_on_initial_delay) {
    delay = initial_delay * (1 << broken_count);
  } else {
    delay = kDefaultBrokenAlternativeProtocolDelay * (1 << (broken_count - 1));
  }
  return std::min(delay, kMaxBrokenAlternativeProtocolDelay);
}

}  // namespace

BrokenAlternativeService::BrokenAlternativeService(
    const AlternativeService& alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key,
    bool use_network_anonymization_key)
    : alternative_service(alternative_service),
      network_anonymization_key(use_network_anonymization_key
                                    ? network_anonymization_key
                                    : NetworkAnonymizationKey()) {}

BrokenAlternativeService::~BrokenAlternativeService() = default;

bool BrokenAlternativeService::operator<(
    const BrokenAlternativeService& other) const {
  return std::tie(alternative_service, network_anonymization_key) <
         std::tie(other.alternative_service, other.network_anonymization_key);
}

BrokenAlternativeServices::BrokenAlternativeServices(
    int max_recently_broken_alternative_service_entries,
    Delegate* delegate,
    const base::TickClock* clock)
    : delegate_(delegate),
      clock_(clock),
      recently_broken_alternative_services_(
          max_recently_broken_alternative_service_entries),
      initial_delay_(kDefaultBrokenAlternativeProtocolDelay) {
  DCHECK(delegate_);
  DCHECK(clock_);
}

BrokenAlternativeServices::~BrokenAlternativeServices() = default;

void BrokenAlternativeServices::Clear() {
  expiration_timer_.Stop();
  broken_alternative_service_list_.clear();
  broken_alternative_service_map_.clear();
  recently_broken_alternative_services_.Clear();
}

void BrokenAlternativeServices::MarkBrokenUntilDefaultNetworkChanges(
    const BrokenAlternativeService& broken_alternative_service) {
  DCHECK(!broken_alternative_service.alternative_service.host.empty());
  DCHECK_NE(kProtoUnknown,
            broken_alternative_service.alternative_service.protocol);

  // The brokenness will expire on the default network change or based on
  // timer.
  broken_alternative_services_on_default_network_.insert(
      broken_alternative_service);
  MarkBrokenImpl(broken_alternative_service);
}

void BrokenAlternativeServices::MarkBroken(
    const BrokenAlternativeService& broken_alternative_service) {
  // The brokenness expires based only on the timer, not on the default network
  // change.
  broken_alternative_services_on_default_network_.erase(
      broken_alternative_service);
  MarkBrokenImpl(broken_alternative_service);
}

void BrokenAlternativeServices::MarkBrokenImpl(
    const BrokenAlternativeService& broken_alternative_service) {
  // Empty host means use host of origin, callers are supposed to substitute.
  DCHECK(!broken_alternative_service.alternative_service.host.empty());
  DCHECK_NE(kProtoUnknown,
            broken_alternative_service.alternative_service.protocol);

  auto it =
      recently_broken_alternative_services_.Get(broken_alternative_service);
  int broken_count = 0;
  if (it == recently_broken_alternative_services_.end()) {
    recently_broken_alternative_services_.Put(broken_alternative_service, 1);
  } else {
    broken_count = it->second++;
  }
  base::TimeTicks expiration =
      clock_->NowTicks() +
      ComputeBrokenAlternativeServiceExpirationDelay(
          broken_count, initial_delay_, exponential_backoff_on_initial_delay_);
  // Return if alternative service is already in expiration queue.
  BrokenAlternativeServiceList::iterator list_it;
  if (!AddToBrokenListAndMap(broken_alternative_service, expiration,
                             &list_it)) {
    return;
  }

  // If this is now the first entry in the list (i.e.
  // |broken_alternative_service| is the next alt svc to expire), schedule
  // an expiration task for it.
  if (list_it == broken_alternative_service_list_.begin()) {
    ScheduleBrokenAlternateProtocolMappingsExpiration();
  }
}

void BrokenAlternativeServices::MarkRecentlyBroken(
    const BrokenAlternativeService& broken_alternative_service) {
  DCHECK_NE(kProtoUnknown,
            broken_alternative_service.alternative_service.protocol);
  if (recently_broken_alternative_services_.Get(broken_alternative_service) ==
      recently_broken_alternative_services_.end()) {
    recently_broken_alternative_services_.Put(broken_alternative_service, 1);
  }
}

bool BrokenAlternativeServices::IsBroken(
    const BrokenAlternativeService& broken_alternative_service) const {
  // Empty host means use host of origin, callers are supposed to substitute.
  DCHECK(!broken_alternative_service.alternative_service.host.empty());
  return broken_alternative_service_map_.find(broken_alternative_service) !=
         broken_alternative_service_map_.end();
}

bool BrokenAlternativeServices::IsBroken(
    const BrokenAlternativeService& broken_alternative_service,
    base::TimeTicks* brokenness_expiration) const {
  DCHECK(brokenness_expiration != nullptr);
  // Empty host means use host of origin, callers are supposed to substitute.
  DCHECK(!broken_alternative_service.alternative_service.host.empty());
  auto map_it =
      broken_alternative_service_map_.find(broken_alternative_service);
  if (map_it == broken_alternative_service_map_.end()) {
    return false;
  }
  auto list_it = map_it->second;
  *brokenness_expiration = list_it->second;
  return true;
}

bool BrokenAlternativeServices::WasRecentlyBroken(
    const BrokenAlternativeService& broken_alternative_service) {
  DCHECK(!broken_alternative_service.alternative_service.host.empty());
  return recently_broken_alternative_services_.Get(
             broken_alternative_service) !=
             recently_broken_alternative_services_.end() ||
         broken_alternative_service_map_.find(broken_alternative_service) !=
             broken_alternative_service_map_.end();
}

void BrokenAlternativeServices::Confirm(
    const BrokenAlternativeService& broken_alternative_service) {
  DCHECK_NE(kProtoUnknown,
            broken_alternative_service.alternative_service.protocol);

  // Remove |broken_alternative_service| from
  // |broken_alternative_service_list_|, |broken_alternative_service_map_| and
  // |broken_alternative_services_on_default_network_|.
  auto map_it =
      broken_alternative_service_map_.find(broken_alternative_service);
  if (map_it != broken_alternative_service_map_.end()) {
    broken_alternative_service_list_.erase(map_it->second);
    broken_alternative_service_map_.erase(map_it);
  }

  auto it =
      recently_broken_alternative_services_.Get(broken_alternative_service);
  if (it != recently_broken_alternative_services_.end()) {
    recently_broken_alternative_services_.Erase(it);
  }

  broken_alternative_services_on_default_network_.erase(
      broken_alternative_service);
}

bool BrokenAlternativeServices::OnDefaultNetworkChanged() {
  bool changed = !broken_alternative_services_on_default_network_.empty();
  while (!broken_alternative_services_on_default_network_.empty()) {
    Confirm(*broken_alternative_services_on_default_network_.begin());
  }
  return changed;
}

void BrokenAlternativeServices::SetBrokenAndRecentlyBrokenAlternativeServices(
    std::unique_ptr<BrokenAlternativeServiceList>
        broken_alternative_service_list,
    std::unique_ptr<RecentlyBrokenAlternativeServices>
        recently_broken_alternative_services) {
  DCHECK(broken_alternative_service_list);
  DCHECK(recently_broken_alternative_services);

  base::TimeTicks next_expiration =
      broken_alternative_service_list_.empty()
          ? base::TimeTicks::Max()
          : broken_alternative_service_list_.front().second;

  // Add |recently_broken_alternative_services| to
  // |recently_broken_alternative_services_|.
  // If an alt-svc already exists, overwrite its broken-count to the one in
  // |recently_broken_alternative_services|.

  recently_broken_alternative_services_.Swap(
      *recently_broken_alternative_services);
  // Add back all existing recently broken alt svcs to cache so they're at
  // front of recency list (LRUCache::Get() does this automatically).
  for (const auto& [service, broken_count] :
       base::Reversed(*recently_broken_alternative_services)) {
    if (recently_broken_alternative_services_.Get(service) ==
        recently_broken_alternative_services_.end()) {
      recently_broken_alternative_services_.Put(service, broken_count);
    }
  }

  // Append |broken_alternative_service_list| to
  // |broken_alternative_service_list_|
  size_t num_broken_alt_svcs_added = broken_alternative_service_list->size();
  broken_alternative_service_list_.splice(
      broken_alternative_service_list_.begin(),
      *broken_alternative_service_list);
  // For each newly-appended alt svc in |broken_alternative_service_list_|,
  // add an entry to |broken_alternative_service_map_| that points to its
  // list iterator. Also, add an entry for that alt svc in
  // |recently_broken_alternative_services_| if one doesn't exist.
  auto list_it = broken_alternative_service_list_.begin();
  for (size_t i = 0; i < num_broken_alt_svcs_added; ++i) {
    const BrokenAlternativeService& broken_alternative_service = list_it->first;
    auto map_it =
        broken_alternative_service_map_.find(broken_alternative_service);
    if (map_it != broken_alternative_service_map_.end()) {
      // Implies this entry already exists somewhere else in
      // |broken_alternative_service_list_|. Remove the existing entry from
      // |broken_alternative_service_list_|, and update the
      // |broken_alternative_service_map_| entry to point to this list entry
      // instead.
      auto list_existing_entry_it = map_it->second;
      broken_alternative_service_list_.erase(list_existing_entry_it);
      map_it->second = list_it;
    } else {
      broken_alternative_service_map_.emplace(broken_alternative_service,
                                              list_it);
    }

    if (recently_broken_alternative_services_.Peek(
            broken_alternative_service) ==
        recently_broken_alternative_services_.end()) {
      recently_broken_alternative_services_.Put(broken_alternative_service, 1);
    }

    ++list_it;
  }

  // Sort |broken_alternative_service_list_| by expiration time. This operation
  // does not invalidate list iterators, so |broken_alternative_service_map_|
  // does not need to be updated.
  broken_alternative_service_list_.sort(
      [](const std::pair<BrokenAlternativeService, base::TimeTicks>& lhs,
         const std::pair<BrokenAlternativeService, base::TimeTicks>& rhs)
          -> bool { return lhs.second < rhs.second; });

  base::TimeTicks new_next_expiration =
      broken_alternative_service_list_.empty()
          ? base::TimeTicks::Max()
          : broken_alternative_service_list_.front().second;

  if (new_next_expiration != next_expiration)
    ScheduleBrokenAlternateProtocolMappingsExpiration();
}

void BrokenAlternativeServices::SetDelayParams(
    std::optional<base::TimeDelta> initial_delay,
    std::optional<bool> exponential_backoff_on_initial_delay) {
  if (initial_delay.has_value()) {
    initial_delay_ = initial_delay.value();
  }
  if (exponential_backoff_on_initial_delay.has_value()) {
    exponential_backoff_on_initial_delay_ =
        exponential_backoff_on_initial_delay.value();
  }
}

const BrokenAlternativeServiceList&
BrokenAlternativeServices::broken_alternative_service_list() const {
  return broken_alternative_service_list_;
}

const RecentlyBrokenAlternativeServices&
BrokenAlternativeServices::recently_broken_alternative_services() const {
  return recently_broken_alternative_services_;
}

bool BrokenAlternativeServices::AddToBrokenListAndMap(
    const BrokenAlternativeService& broken_alternative_service,
    base::TimeTicks expiration,
    BrokenAlternativeServiceList::iterator* it) {
  DCHECK(it);

  auto map_it =
      broken_alternative_service_map_.find(broken_alternative_service);
  if (map_it != broken_alternative_service_map_.end())
    return false;

  // Iterate from end of |broken_alternative_service_list_| to find where to
  // insert it to keep the list sorted by expiration time.
  auto list_it = broken_alternative_service_list_.end();
  while (list_it != broken_alternative_service_list_.begin()) {
    --list_it;
    if (list_it->second <= expiration) {
      ++list_it;
      break;
    }
  }

  // Insert |broken_alternative_service| into the list and the map.
  list_it = broken_alternative_service_list_.insert(
      list_it, std::pair(broken_alternative_service, expiration));
  broken_alternative_service_map_.emplace(broken_alternative_service, list_it);

  *it = list_it;
  return true;
}

void BrokenAlternativeServices::ExpireBrokenAlternateProtocolMappings() {
  base::TimeTicks now = clock_->NowTicks();

  while (!broken_alternative_service_list_.empty()) {
    auto it = broken_alternative_service_list_.begin();
    if (now < it->second) {
      break;
    }

    delegate_->OnExpireBrokenAlternativeService(
        it->first.alternative_service, it->first.network_anonymization_key);

    broken_alternative_service_map_.erase(it->first);
    broken_alternative_service_list_.erase(it);
  }

  if (!broken_alternative_service_list_.empty())
    ScheduleBrokenAlternateProtocolMappingsExpiration();
}

void BrokenAlternativeServices ::
    ScheduleBrokenAlternateProtocolMappingsExpiration() {
  DCHECK(!broken_alternative_service_list_.empty());
  base::TimeTicks now = clock_->NowTicks();
  base::TimeTicks next_expiration =
      broken_alternative_service_list_.front().second;
  base::TimeDelta delay =
      next_expiration > now ? next_expiration - now : base::TimeDelta();
  expiration_timer_.Stop();
  expiration_timer_.Start(
      FROM_HERE, delay,
      base::BindOnce(
          &BrokenAlternativeServices ::ExpireBrokenAlternateProtocolMappings,
          weak_ptr_factory_.GetWeakPtr()));
}

}  // namespace net

"""

```