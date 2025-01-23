Response:
Let's break down the thought process for analyzing this `ResourceLoadScheduler.cc` file.

1. **Understand the Goal:** The core task is to describe the functionality of the `ResourceLoadScheduler`, its relationship to web technologies (JavaScript, HTML, CSS), provide examples, and highlight potential errors.

2. **Initial Read-Through (Skimming):**  Quickly read the code to get a general idea of the components involved. Keywords like "throttle," "priority," "pending," "running," "limit," and "client" stand out. The `#include` statements also give hints about dependencies (e.g., network, console, scheduler).

3. **Identify the Core Purpose:** The name "ResourceLoadScheduler" strongly suggests its primary function: managing the loading of resources (like images, scripts, stylesheets). The code confirms this by dealing with requests, priorities, and limits.

4. **Deconstruct by Functionality (Mental or Actual Sections):** Start dissecting the code into logical blocks based on the methods and data structures:

    * **Configuration and Initialization:**  Look for the constructor and any methods that set up initial parameters or limits. The use of `FieldTrialParams` suggests dynamic configuration. The various limits (tight, normal, medium) are key.
    * **Request Handling:** Focus on `Request()`. How are new resource load requests registered?  What information is stored?  The concept of `ThrottleOption` and `ResourceLoadPriority` is crucial.
    * **Scheduling Logic (The Heart):**  Examine `MaybeRun()` and `GetNextPendingRequest()`. How does the scheduler decide which pending request to execute next? The different throttling policies and limits come into play here. The interaction with `frame_scheduler_lifecycle_state_` is important.
    * **Execution:** `Run()` seems to be the point where a request is actually initiated.
    * **Resource Release:**  `Release()` handles the completion or cancellation of requests.
    * **Priority Management:** `SetPriority()` allows changing the priority of a pending request.
    * **Throttling:**  Identify methods related to throttling (`LoosenThrottlingPolicy()`, checks based on `frame_scheduler_lifecycle_state_`).
    * **Metrics and Debugging:**  Note the use of histograms and console messages.
    * **Shutdown:**  The `Shutdown()` method is important for cleanup.

5. **Connect to Web Technologies (The "Why It Matters"):**  Now, relate the scheduler's functions to how web pages work:

    * **HTML:**  When the browser parses HTML, it discovers resources (images, scripts, stylesheets) referenced by tags like `<script>`, `<img>`, `<link>`. The scheduler manages loading these.
    * **CSS:**  CSS files are resources that need to be fetched. The scheduler handles their loading, potentially prioritizing them.
    * **JavaScript:** JavaScript can trigger resource fetching dynamically using `fetch()` or `XMLHttpRequest`. The scheduler manages these requests as well. JavaScript performance is directly impacted by efficient resource loading.

6. **Illustrate with Examples (Concrete Scenarios):** Create simple scenarios to demonstrate the scheduler's behavior:

    * **Throttling:** A background tab downloading images slowly.
    * **Priority:**  A critical script being loaded before a non-essential image.
    * **Limits:**  The effect of exceeding the concurrent download limit.
    * **User Errors:**  How developers might unintentionally cause issues.

7. **Logical Reasoning and Assumptions:**  Where the code makes decisions, think about the inputs and outputs:

    * **Input:** A set of pending requests with different priorities and throttle options. The current throttling policy and state of the frame.
    * **Output:** The selection of the next request to run.
    * **Assumptions:** The scheduler assumes clients correctly implement the `ResourceLoadSchedulerClient` interface. It also assumes the underlying network stack is functioning.

8. **Identify Potential Errors:** Consider common mistakes developers might make or situations where the scheduler's behavior might be unexpected:

    * **Too many high-priority requests:**  Could starve lower-priority resources.
    * **Unexpected throttling:**  Not understanding when background throttling kicks in.
    * **Inefficient resource loading patterns:**  Loading many resources simultaneously without considering priority.

9. **Structure the Output:** Organize the findings in a clear and logical manner:

    * **Summary of Functionality:** Start with a high-level overview.
    * **Relationship to Web Technologies:**  Explain the connections with HTML, CSS, and JavaScript with examples.
    * **Logical Reasoning:** Provide input/output examples.
    * **User/Programming Errors:**  List common pitfalls.

10. **Refine and Elaborate:**  Review the generated output. Are the explanations clear? Are the examples relevant?  Add more detail or clarification where needed. For example, explain *why* throttling exists (to save resources).

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just manages network requests."  **Correction:** It manages resource loading, which includes network requests, but also considers priority, throttling, and lifecycle.
* **Initial example:** "JavaScript makes a fetch request." **Refinement:** Provide a *specific* example of how JavaScript interacts with the scheduler's concepts (e.g., high-priority fetches).
* **Realization:**  The `frame_scheduler_lifecycle_state_` is a *critical* input to the scheduling logic. Emphasize its role.
* **Consider edge cases:** What happens when a request is canceled?  How does the scheduler handle that?  (This leads to discussing the `Release()` method).

By following these steps, you can systematically analyze the code and produce a comprehensive and informative description of its functionality and its significance in the context of web development.
好的，我们来分析一下 `blink/renderer/platform/loader/fetch/resource_load_scheduler.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概览**

`ResourceLoadScheduler` 的主要功能是**管理和调度网页资源的加载请求**。它负责决定何时以及以何种优先级执行资源加载请求，以优化页面加载性能并避免资源竞争。

更具体地说，它的功能包括：

1. **接收资源加载请求:**  当 Blink 渲染引擎需要加载一个资源（例如图片、脚本、样式表等）时，会通过 `ResourceLoadScheduler` 提交请求。
2. **管理请求队列:** 它维护着待处理的资源加载请求队列，并根据优先级和节流策略进行排序。
3. **实施节流策略 (Throttling):**  为了避免资源加载过多导致性能问题（特别是在后台标签页或资源受限的情况下），`ResourceLoadScheduler` 会实施节流策略，延迟或限制某些请求的执行。
4. **优先级管理:**  它允许为资源加载请求设置优先级（例如，高、中、低），并优先处理高优先级的请求。
5. **并发控制:**  它控制同时进行的资源加载请求的数量，以避免资源竞争和网络拥塞。
6. **生命周期管理:**  它与 Frame 或 Worker 的生命周期状态相关联，根据 Frame 的状态（例如，前台、后台、隐藏）调整调度策略。
7. **性能监控和报告:**  它收集资源加载相关的性能指标，例如请求排队时间，并用于生成性能报告。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`ResourceLoadScheduler` 直接影响着网页中 JavaScript、HTML 和 CSS 资源的加载，从而影响页面的渲染和交互。

* **HTML:**
    * **请求发起:** 当浏览器解析 HTML 文档时，会遇到诸如 `<img>`、`<script>`、`<link>` 等标签，这些标签会触发对图片、JavaScript 文件和 CSS 文件的资源加载请求。这些请求会交给 `ResourceLoadScheduler` 进行管理。
    * **优先级影响:**  HTML 中通过 `<link rel="preload">` 或 `<link rel="prefetch">` 等标签可以暗示资源的优先级。`ResourceLoadScheduler` 会考虑这些提示来调整加载顺序。
    * **示例:**  如果 HTML 中一个关键的 CSS 文件没有被优先加载，会导致页面出现“无样式内容闪烁 (FOUC)”。`ResourceLoadScheduler` 的优先级管理可以帮助避免这种情况。

* **CSS:**
    * **请求发起:**  `<link>` 标签引入的外部 CSS 文件以及 `<style>` 标签内的 CSS 都会触发资源加载请求。
    * **渲染阻塞:**  浏览器通常会阻塞页面的渲染，直到关键的 CSS 文件加载完成。`ResourceLoadScheduler` 的调度效率直接影响 CSS 的加载速度，从而影响首次内容绘制 (FCP) 和最大内容绘制 (LCP) 等关键性能指标。
    * **示例:** 如果一个包含页面核心样式的 CSS 文件由于节流策略而被延迟加载，用户可能会看到一个没有样式的页面，直到 CSS 加载完成。

* **JavaScript:**
    * **请求发起:** `<script>` 标签引入的外部 JavaScript 文件以及内联的 JavaScript 代码（特别是通过动态 `import()` 加载的模块）会产生资源加载请求。
    * **执行顺序:**  `<script>` 标签的 `async` 和 `defer` 属性会影响 JavaScript 文件的加载和执行顺序。`ResourceLoadScheduler` 负责这些文件的加载，但执行顺序主要由 HTML 解析器和 JavaScript 引擎控制。
    * **动态加载:**  JavaScript 可以使用 `fetch()` API 或 `XMLHttpRequest` 对象动态地加载资源。这些请求也会被 `ResourceLoadScheduler` 管理。
    * **示例:**  一个大型的 JavaScript 文件如果加载缓慢，可能会导致页面交互延迟。`ResourceLoadScheduler` 的节流策略在后台标签页可能会延迟这种文件的加载。如果一个关键的交互所需的 JavaScript 文件优先级较低，可能会导致用户操作响应缓慢。

**逻辑推理与假设输入输出**

假设我们有以下情况：

* **假设输入:**
    * 当前 Frame 是后台标签页，应用了节流策略 (`policy_ = ThrottlingPolicy::kTight`)。
    * `tight_outstanding_limit_` 设置为 2，表示后台标签页同时只能进行 2 个非高优先级的资源加载。
    * 队列中有 5 个待加载的资源请求：
        * 请求 A：图片，优先级 `kMedium` (中)
        * 请求 B：JavaScript 文件，优先级 `kLow` (低)
        * 请求 C：图片，优先级 `kMedium` (中)
        * 请求 D：高优先级 JavaScript 文件，优先级 `kHigh` (高)
        * 请求 E：CSS 文件，优先级 `kLow` (低)

* **逻辑推理:**
    1. `MaybeRun()` 方法被调用，尝试调度新的资源加载。
    2. 由于是后台标签页且应用了 `kTight` 策略，`GetOutstandingLimit()` 会返回较低的并发限制。对于非高优先级请求，限制为 `tight_outstanding_limit_`，即 2。对于高优先级，可能是 `normal_outstanding_limit_` (假设大于 2)。
    3. `GetNextPendingRequest()` 会选择待处理的请求。由于高优先级请求 D 可以不受 `tight_outstanding_limit_` 的严格限制（假设 `normal_outstanding_limit_` 允许），它可能会被优先选择。
    4. 接下来，由于并发限制为 2，`MaybeRun()` 可能会选择请求 A 和请求 C，因为它们是中等优先级，且在限制范围内。请求 B 和 E 会被延迟，直到有正在进行的请求完成。

* **假设输出:**
    * 高优先级请求 D **立即**被调度执行。
    * 中等优先级请求 A 和 C **随后**被调度执行。
    * 低优先级请求 B 和 E **被延迟**，不会立即执行。

**涉及的用户或编程常见的使用错误**

1. **发送过多的高优先级请求:**
   * **错误:** 开发者可能会误将所有资源都标记为高优先级，期望它们能更快加载。
   * **后果:** 这会削弱优先级机制的作用，导致真正的关键资源与其他“伪高优先级”资源竞争，反而可能降低整体加载效率。
   * **示例:**  将所有图片都设置为高优先级加载，可能会阻塞关键的 JavaScript 或 CSS 文件的加载。

2. **不理解节流策略的影响:**
   * **错误:** 开发者可能没有意识到后台标签页或资源受限环境下的节流策略，并期望资源加载速度与前台标签页相同。
   * **后果:**  在后台标签页，资源加载可能会被显著延迟，导致用户切换回标签页时内容仍然未加载完成。
   * **示例:**  一个在页面不可见时进行大量数据请求的 JavaScript 应用，在后台标签页可能会因为节流策略而运行缓慢甚至超时。

3. **不合理地使用 `async` 和 `defer` 属性:**
   * **错误:**  不恰当的使用 `<script async>` 或 `<script defer>` 可能会导致 JavaScript 执行顺序混乱，依赖关系出错。虽然 `ResourceLoadScheduler` 管理加载，但执行顺序仍然重要。
   * **后果:**  页面可能会出现 JavaScript 错误或功能异常。
   * **示例:**  一个依赖于先加载的库的脚本使用了 `async` 属性，可能在库加载完成前就开始执行，导致找不到依赖的错误。

4. **动态加载大量低优先级资源而不考虑限制:**
   * **错误:**  使用 JavaScript 动态加载大量的非关键资源（例如延迟加载的图片），而没有考虑浏览器的并发连接限制或 `ResourceLoadScheduler` 的节流策略。
   * **后果:**  可能会导致网络拥塞，影响其他重要资源的加载，甚至降低用户体验。
   * **示例:**  一个无限滚动的页面一次性请求加载大量的图片，即使优先级较低，也可能占用大量的网络连接，影响后续交互所需资源的加载。

5. **错误地配置或理解 `preload` 和 `prefetch`:**
   * **错误:**  错误地使用 `<link rel="preload">` 或 `<link rel="prefetch">`，例如预加载了永远不会使用的资源或优先级错误的资源。
   * **后果:**  会浪费网络带宽，甚至可能影响关键资源的加载。`ResourceLoadScheduler` 会按照指示进行预加载或预取，但如果指示错误，反而会适得其反。
   * **示例:**  预加载了用户当前页面不需要的大型图片，占用了带宽，可能导致后续用户点击链接加载新页面时速度变慢。

总而言之，`ResourceLoadScheduler` 是 Blink 引擎中一个至关重要的组件，它通过智能地管理资源加载请求，帮助提升网页性能和用户体验。理解它的工作原理和相关配置，可以帮助开发者避免常见的性能问题，并更好地优化网页的加载过程。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_load_scheduler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/resource_load_scheduler.h"

#include <algorithm>
#include <memory>
#include <string>

#include "base/containers/contains.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/default_clock.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/fetch/loading_behavior_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/scheduler/public/aggregated_metric_reporter.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_status.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

constexpr char kRendererSideResourceScheduler[] =
    "RendererSideResourceScheduler";

// Used in the tight mode (see the header file for details).
constexpr size_t kTightLimitForRendererSideResourceScheduler = 2u;
// Used in the normal mode (see the header file for details).
constexpr size_t kLimitForRendererSideResourceScheduler = 1024u;

constexpr char kTightLimitForRendererSideResourceSchedulerName[] =
    "tight_limit";
constexpr char kLimitForRendererSideResourceSchedulerName[] = "limit";

// Represents a resource load circumstance, e.g. from main frame vs sub-frames,
// or on throttled state vs on not-throttled state.
// Used to report histograms. Do not reorder or insert new items.
enum class ReportCircumstance {
  kMainframeThrottled,
  kMainframeNotThrottled,
  kSubframeThrottled,
  kSubframeNotThrottled,
  // Append new items here.
  kNumOfCircumstances,
};

uint32_t GetFieldTrialUint32Param(const char* trial_name,
                                  const char* parameter_name,
                                  uint32_t default_param) {
  base::FieldTrialParams trial_params;
  bool result = base::GetFieldTrialParams(trial_name, &trial_params);
  if (!result) {
    return default_param;
  }

  const auto& found = trial_params.find(parameter_name);
  if (found == trial_params.end()) {
    return default_param;
  }

  uint32_t param;
  if (!base::StringToUint(found->second, &param)) {
    return default_param;
  }

  return param;
}

}  // namespace

constexpr ResourceLoadScheduler::ClientId
    ResourceLoadScheduler::kInvalidClientId;

ResourceLoadScheduler::ResourceLoadScheduler(
    ThrottlingPolicy initial_throttling_policy,
    ThrottleOptionOverride throttle_option_override,
    const DetachableResourceFetcherProperties& resource_fetcher_properties,
    FrameOrWorkerScheduler* frame_or_worker_scheduler,
    DetachableConsoleLogger& console_logger,
    LoadingBehaviorObserver* loading_behavior_observer)
    : resource_fetcher_properties_(resource_fetcher_properties),
      policy_(initial_throttling_policy),
      outstanding_limit_for_throttled_frame_scheduler_(
          resource_fetcher_properties_->GetOutstandingThrottledLimit()),
      console_logger_(console_logger),
      clock_(base::DefaultClock::GetInstance()),
      throttle_option_override_(throttle_option_override),
      loading_behavior_observer_(loading_behavior_observer) {
  if (!frame_or_worker_scheduler) {
    return;
  }

  normal_outstanding_limit_ =
      GetFieldTrialUint32Param(kRendererSideResourceScheduler,
                               kLimitForRendererSideResourceSchedulerName,
                               kLimitForRendererSideResourceScheduler);
  tight_outstanding_limit_ =
      GetFieldTrialUint32Param(kRendererSideResourceScheduler,
                               kTightLimitForRendererSideResourceSchedulerName,
                               kTightLimitForRendererSideResourceScheduler);

  if (base::FeatureList::IsEnabled(features::kBoostImagePriority)) {
    tight_medium_limit_ = features::kBoostImagePriorityTightMediumLimit.Get();
  }

  scheduler_observer_handle_ = frame_or_worker_scheduler->AddLifecycleObserver(
      FrameScheduler::ObserverType::kLoader,
      WTF::BindRepeating(&ResourceLoadScheduler::OnLifecycleStateChanged,
                         WrapWeakPersistent(this)));
}

ResourceLoadScheduler::~ResourceLoadScheduler() = default;

void ResourceLoadScheduler::Trace(Visitor* visitor) const {
  visitor->Trace(pending_request_map_);
  visitor->Trace(resource_fetcher_properties_);
  visitor->Trace(console_logger_);
  visitor->Trace(loading_behavior_observer_);
}

void ResourceLoadScheduler::LoosenThrottlingPolicy() {
  switch (policy_) {
    case ThrottlingPolicy::kTight:
      break;
    case ThrottlingPolicy::kNormal:
      return;
  }
  policy_ = ThrottlingPolicy::kNormal;
  MaybeRun();
}

void ResourceLoadScheduler::Shutdown() {
  // Do nothing if the feature is not enabled, or Shutdown() was already called.
  if (is_shutdown_) {
    return;
  }
  is_shutdown_ = true;

  scheduler_observer_handle_.reset();
}

void ResourceLoadScheduler::Request(ResourceLoadSchedulerClient* client,
                                    ThrottleOption option,
                                    ResourceLoadPriority priority,
                                    int intra_priority,
                                    ResourceLoadScheduler::ClientId* id) {
  *id = GenerateClientId();
  if (is_shutdown_) {
    return;
  }

  if (option == ThrottleOption::kStoppable &&
      throttle_option_override_ ==
          ThrottleOptionOverride::kStoppableAsThrottleable) {
    option = ThrottleOption::kThrottleable;
  }

  // Check if the request can be throttled.
  ClientIdWithPriority request_info(*id, priority, intra_priority);
  if (!IsClientDelayable(option)) {
    Run(*id, client, /*throttleable=*/false, priority);
    return;
  }

  DCHECK(ThrottleOption::kStoppable == option ||
         ThrottleOption::kThrottleable == option);
  if (pending_requests_[option].empty()) {
    pending_queue_update_times_[option] = clock_->Now();
  }
  pending_requests_[option].insert(request_info);
  pending_request_map_.insert(
      *id, MakeGarbageCollected<ClientInfo>(client, option, priority,
                                            intra_priority));

  // Remember the ClientId since MaybeRun() below may destruct the caller
  // instance and |id| may be inaccessible after the call.
  MaybeRun();
}

void ResourceLoadScheduler::SetPriority(ClientId client_id,
                                        ResourceLoadPriority priority,
                                        int intra_priority) {
  auto client_it = pending_request_map_.find(client_id);
  if (client_it == pending_request_map_.end()) {
    return;
  }

  auto& throttle_option_queue = pending_requests_[client_it->value->option];

  auto it = throttle_option_queue.find(ClientIdWithPriority(
      client_id, client_it->value->priority, client_it->value->intra_priority));

  CHECK(it != throttle_option_queue.end(), base::NotFatalUntil::M130);
  throttle_option_queue.erase(it);

  client_it->value->priority = priority;
  client_it->value->intra_priority = intra_priority;

  throttle_option_queue.emplace(client_id, priority, intra_priority);
  MaybeRun();
}

bool ResourceLoadScheduler::Release(
    ResourceLoadScheduler::ClientId id,
    ResourceLoadScheduler::ReleaseOption option,
    const ResourceLoadScheduler::TrafficReportHints& hints) {
  // Check kInvalidClientId that can not be passed to the HashSet.
  if (id == kInvalidClientId) {
    return false;
  }

  auto running_request = running_requests_.find(id);
  if (running_request != running_requests_.end()) {
    running_requests_.erase(id);
    running_throttleable_requests_.erase(id);
    running_medium_requests_.erase(id);

    if (option == ReleaseOption::kReleaseAndSchedule) {
      MaybeRun();
    }
    return true;
  }

  // The client may not appear in the |pending_request_map_|. For example,
  // non-delayable requests are immediately granted and skip being placed into
  // this map.
  auto pending_request = pending_request_map_.find(id);
  if (pending_request != pending_request_map_.end()) {
    pending_request_map_.erase(pending_request);
    // Intentionally does not remove it from |pending_requests_|.

    // Didn't release any running requests, but the outstanding limit might be
    // changed to allow another request.
    if (option == ReleaseOption::kReleaseAndSchedule) {
      MaybeRun();
    }
    return true;
  }
  return false;
}

void ResourceLoadScheduler::SetOutstandingLimitForTesting(
    size_t tight_limit,
    size_t normal_limit,
    size_t tight_medium_limit) {
  tight_outstanding_limit_ = tight_limit;
  normal_outstanding_limit_ = normal_limit;
  tight_medium_limit_ = tight_medium_limit;
  MaybeRun();
}

bool ResourceLoadScheduler::IsClientDelayable(ThrottleOption option) const {
  switch (frame_scheduler_lifecycle_state_) {
    case scheduler::SchedulingLifecycleState::kNotThrottled:
    case scheduler::SchedulingLifecycleState::kHidden:
    case scheduler::SchedulingLifecycleState::kThrottled:
      return option == ThrottleOption::kThrottleable;
    case scheduler::SchedulingLifecycleState::kStopped:
      return option != ThrottleOption::kCanNotBeStoppedOrThrottled;
  }
}

void ResourceLoadScheduler::OnLifecycleStateChanged(
    scheduler::SchedulingLifecycleState state) {
  if (frame_scheduler_lifecycle_state_ == state) {
    return;
  }

  frame_scheduler_lifecycle_state_ = state;

  if (state == scheduler::SchedulingLifecycleState::kNotThrottled) {
    ShowConsoleMessageIfNeeded();
  }

  MaybeRun();
}

ResourceLoadScheduler::ClientId ResourceLoadScheduler::GenerateClientId() {
  ClientId id = ++current_id_;
  CHECK_NE(0u, id);
  return id;
}

bool ResourceLoadScheduler::IsPendingRequestEffectivelyEmpty(
    ThrottleOption option) {
  for (const auto& client : pending_requests_[option]) {
    // The request in |pending_request_| is erased when it is scheduled. So if
    // the request is canceled, or Release() is called before firing its Run(),
    // the entry for the request remains in |pending_request_| until it is
    // popped in GetNextPendingRequest().
    if (base::Contains(pending_request_map_, client.client_id)) {
      return false;
    }
  }
  // There is no entry, or no existing entries are alive in
  // |pending_request_map_|.
  return true;
}

bool ResourceLoadScheduler::GetNextPendingRequest(ClientId* id) {
  auto& stoppable_queue = pending_requests_[ThrottleOption::kStoppable];
  auto& throttleable_queue = pending_requests_[ThrottleOption::kThrottleable];

  // Check if stoppable or throttleable requests are allowed to be run.
  auto stoppable_it = stoppable_queue.begin();
  bool has_runnable_stoppable_request =
      stoppable_it != stoppable_queue.end() &&
      (!IsClientDelayable(ThrottleOption::kStoppable) ||
       IsRunningThrottleableRequestsLessThanOutStandingLimit(
           GetOutstandingLimit(stoppable_it->priority),
           stoppable_it->priority));

  auto throttleable_it = throttleable_queue.begin();
  bool has_runnable_throttleable_request =
      throttleable_it != throttleable_queue.end() &&
      (!IsClientDelayable(ThrottleOption::kThrottleable) ||
       IsRunningThrottleableRequestsLessThanOutStandingLimit(
           GetOutstandingLimit(throttleable_it->priority),
           throttleable_it->priority));

  if (!has_runnable_throttleable_request && !has_runnable_stoppable_request) {
    return false;
  }

  // If both requests are allowed to be run, run the high priority requests
  // first.
  ClientIdWithPriority::Compare compare;
  bool use_stoppable = has_runnable_stoppable_request &&
                       (!has_runnable_throttleable_request ||
                        compare(*stoppable_it, *throttleable_it));

  // Remove the iterator from the correct set of |pending_requests_|, and update
  // corresponding |pending_queue_update_times_|.
  if (use_stoppable) {
    *id = stoppable_it->client_id;
    stoppable_queue.erase(stoppable_it);
    pending_queue_update_times_[ThrottleOption::kStoppable] = clock_->Now();
    return true;
  }

  *id = throttleable_it->client_id;
  throttleable_queue.erase(throttleable_it);
  pending_queue_update_times_[ThrottleOption::kThrottleable] = clock_->Now();
  return true;
}

void ResourceLoadScheduler::MaybeRun() {
  // Requests for keep-alive loaders could be remained in the pending queue,
  // but ignore them once Shutdown() is called.
  if (is_shutdown_) {
    return;
  }

  ClientId id = kInvalidClientId;
  while (GetNextPendingRequest(&id)) {
    auto found = pending_request_map_.find(id);
    if (found == pending_request_map_.end()) {
      continue;  // Already released.
    }

    ResourceLoadSchedulerClient* client = found->value->client;
    ThrottleOption option = found->value->option;
    ResourceLoadPriority priority = found->value->priority;
    pending_request_map_.erase(found);
    Run(id, client, option == ThrottleOption::kThrottleable, priority);
  }
}

void ResourceLoadScheduler::Run(ResourceLoadScheduler::ClientId id,
                                ResourceLoadSchedulerClient* client,
                                bool throttleable,
                                ResourceLoadPriority priority) {
  running_requests_.insert(id);
  if (throttleable) {
    running_throttleable_requests_.insert(id);
  }
  if (priority == ResourceLoadPriority::kMedium) {
    running_medium_requests_.insert(id);
  }
  client->Run();
}

size_t ResourceLoadScheduler::GetOutstandingLimit(
    ResourceLoadPriority priority) const {
  size_t limit = kOutstandingUnlimited;

  switch (frame_scheduler_lifecycle_state_) {
    case scheduler::SchedulingLifecycleState::kHidden:
    case scheduler::SchedulingLifecycleState::kThrottled:
      limit = std::min(limit, outstanding_limit_for_throttled_frame_scheduler_);
      break;
    case scheduler::SchedulingLifecycleState::kNotThrottled:
      break;
    case scheduler::SchedulingLifecycleState::kStopped:
      limit = 0;
      break;
  }

  switch (policy_) {
    case ThrottlingPolicy::kTight:
      limit = std::min(limit, priority < ResourceLoadPriority::kHigh
                                  ? tight_outstanding_limit_
                                  : normal_outstanding_limit_);
      break;
    case ThrottlingPolicy::kNormal:
      limit = std::min(limit, normal_outstanding_limit_);
      break;
  }
  return limit;
}

void ResourceLoadScheduler::ShowConsoleMessageIfNeeded() {
  if (is_console_info_shown_ || pending_request_map_.empty()) {
    return;
  }

  const base::Time limit = clock_->Now() - base::Seconds(60);
  if ((pending_queue_update_times_[ThrottleOption::kThrottleable] >= limit ||
       IsPendingRequestEffectivelyEmpty(ThrottleOption::kThrottleable)) &&
      (pending_queue_update_times_[ThrottleOption::kStoppable] >= limit ||
       IsPendingRequestEffectivelyEmpty(ThrottleOption::kStoppable))) {
    // At least, one of the top requests in pending queues was handled in the
    // last 1 minutes, or there is no pending requests in the inactive queue.
    return;
  }
  console_logger_->AddConsoleMessage(
      mojom::ConsoleMessageSource::kOther, mojom::ConsoleMessageLevel::kInfo,
      "Some resource load requests were throttled while the tab was in "
      "background, and no request was sent from the queue in the last 1 "
      "minute. This means previously requested in-flight requests haven't "
      "received any response from servers. See "
      "https://www.chromestatus.com/feature/5527160148197376 for more details");
  is_console_info_shown_ = true;
}

bool ResourceLoadScheduler::
    IsRunningThrottleableRequestsLessThanOutStandingLimit(
        size_t out_standing_limit,
        ResourceLoadPriority priority) {
  // Allow for a minimum number of medium-priority requests to be in-flight
  // independent of the overall number of pending requests.
  if (priority == ResourceLoadPriority::kMedium &&
      running_medium_requests_.size() < tight_medium_limit_) {
    return true;
  }
  return running_throttleable_requests_.size() < out_standing_limit;
}

void ResourceLoadScheduler::SetClockForTesting(const base::Clock* clock) {
  clock_ = clock;
}

}  // namespace blink
```