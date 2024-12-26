Response: Let's break down the thought process for analyzing the `page_scheduler_impl.cc` file.

1. **Understand the Goal:** The request asks for the file's functionalities, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and potential user/programming errors.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for keywords and class names that suggest core functions. I see:
    * `PageSchedulerImpl` (the main class)
    * `FrameSchedulerImpl` (interaction with frame scheduling)
    * `MainThreadSchedulerImpl`, `AgentGroupSchedulerImpl` (interaction with other schedulers)
    * `WakeUpBudgetPool`, `CPUTimeBudgetPool` (throttling mechanisms)
    * `SetPageVisible`, `SetPageFrozen`, `AudioStateChanged` (lifecycle management)
    * `IsLoading`, `IsBackgrounded` (state checks)
    * `UpdatePolicy` (central to applying scheduling rules)
    * Constants like `kDefaultBackgroundBudgetAsCPUFraction`, `kThrottlingDelayAfterBackgrounding` (parameters for behavior)
    * Mentions of features like `kStopInBackground` (feature flags)

3. **Identify Core Functionalities (Grouping):**  Based on the keywords and a slightly deeper read, I can start grouping related functionalities:

    * **Page Lifecycle Management:**  How the scheduler handles different states of a web page (visible, hidden, frozen, in the back/forward cache). This includes functions like `SetPageVisible`, `SetPageFrozen`, `SetPageBackForwardCached`.

    * **Scheduling and Throttling:**  How the scheduler controls the execution of tasks on the main thread. This is clearly related to `WakeUpBudgetPool`, `CPUTimeBudgetPool`, and functions like `DoThrottleCPUTime`, `DoIntensivelyThrottleWakeUps`.

    * **Frame Management:** How the scheduler interacts with individual frames within a page. This involves `RegisterFrameSchedulerImpl`, `CreateFrameScheduler`, and functions that propagate page-level state to frames.

    * **Audio Handling:**  How the scheduler reacts to audio playback on the page (`AudioStateChanged`, `OnAudioSilent`).

    * **Policy Updates:** The mechanism for applying scheduling rules based on the current state (`UpdatePolicy`, `UpdatePolicyOnVisibilityChange`).

    * **Integration with other components:**  Interaction with `MainThreadSchedulerImpl`, `AgentGroupSchedulerImpl`, and the delegate (`PageScheduler::Delegate`).

    * **Tracing:** The use of `perfetto::TracedValue` suggests integration with the Chromium tracing system.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now, consider how these functionalities impact web technologies:

    * **JavaScript:** Throttling directly affects JavaScript execution. Background throttling limits how often timers fire, and intensive throttling can significantly delay script execution. The file manages when JavaScript gets to run.
    * **HTML:** The visibility state managed here is crucial for features like the Page Lifecycle API, which lets JavaScript know when a page is hidden or frozen. The back/forward cache functionality is also tied to how HTML pages are navigated.
    * **CSS:** While less direct, the scheduler indirectly affects CSS animations and transitions, as their smoothness depends on the frame rate, which the scheduler influences. Changes in visibility can also trigger CSS media queries (though this file doesn't directly handle that).

5. **Logical Reasoning (Input/Output Examples):** Think about specific scenarios and the scheduler's likely behavior.

    * **Background Throttling:**  If a page is moved to the background (input), the scheduler will start reducing the CPU time and wake-up budget allocated to it (output), leading to less frequent timer firing.
    * **Audio Playback:** If audio starts playing (input), the scheduler will prevent the page from being frozen immediately when backgrounded (output). If audio stops (input), a timer is set, and after a delay, the page *might* become eligible for freezing (output).

6. **User/Programming Errors:**  Consider how developers might misuse the related APIs or encounter unexpected behavior due to the scheduler's actions.

    * **JavaScript Timers in Background:** Developers might set timers expecting them to fire at precise intervals, but background throttling can delay these significantly.
    * **Unexpected Freezing:** Developers might not be aware of the conditions under which a page can be frozen (e.g., backgrounded without audio) and find their application's state unexpectedly paused.
    * **Performance Issues:**  Excessive use of timers or animations, especially in the background, can lead to a page being aggressively throttled, impacting perceived performance.

7. **Structure the Answer:** Organize the findings into clear sections as requested:
    * **Functionalities:**  List the core responsibilities.
    * **Relationship to Web Technologies:** Explain the connections with examples.
    * **Logical Reasoning:** Provide concrete input/output scenarios.
    * **User/Programming Errors:** Give illustrative examples.

8. **Refine and Elaborate:**  Review the generated answer for clarity, accuracy, and completeness. Add more detail to the examples and explanations where needed. For instance, be more specific about *how* throttling affects JavaScript timers (e.g., increased delay).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about scheduling tasks."
* **Correction:** "No, it's specifically about *page-level* scheduling and how different page states influence it."
* **Initial thought:** "The connection to CSS is direct."
* **Correction:** "It's more indirect, influencing the smoothness of animations rather than directly manipulating CSS."
* **Initial thought:**  Focus only on simple scenarios.
* **Refinement:** Consider more nuanced situations like the "recently audible" state and how it affects freezing.

By following these steps, the goal is to provide a comprehensive and well-structured answer that addresses all aspects of the request. The process involves understanding the code's purpose, connecting it to broader web development concepts, and thinking critically about its behavior and potential pitfalls.
这个文件 `page_scheduler_impl.cc` 是 Chromium Blink 渲染引擎中负责 **页面级别调度** 的核心组件。它的主要功能是管理和控制页面内所有帧的调度行为，以优化性能、降低资源消耗，并提供更好的用户体验。

以下是 `PageSchedulerImpl` 的主要功能，并结合 JavaScript, HTML, CSS 的关系进行举例说明：

**核心功能:**

1. **页面生命周期管理:**
   - **设置页面可见性 (`SetPageVisible`):**  当页面从隐藏变为可见或反之时，调整调度策略。
     - **JavaScript 关系:** 当页面变为不可见时，浏览器可能会限制 JavaScript 定时器（如 `setTimeout`, `setInterval`）的执行频率，以节省资源。`PageSchedulerImpl` 参与决定这种限制的强度。
     - **HTML/CSS 关系:** 页面可见性变化可能触发 CSS 媒体查询（如 `prefers-reduced-motion`），`PageSchedulerImpl` 确保这些变化能及时反映。
   - **设置页面冻结 (`SetPageFrozen`):**  在页面被移入后台或满足特定条件时，可以冻结页面，暂停其大部分活动以节省内存和 CPU。
     - **JavaScript 关系:** 冻结会暂停 JavaScript 的执行，包括任何正在运行的脚本和定时器。
     - **HTML/CSS 关系:** 冻结意味着页面不会重新渲染，CSS 动画和过渡效果也会停止。
   - **设置页面进入/离开 Back/Forward Cache (`SetPageBackForwardCached`):**  当页面进入或离开浏览器的后退/前进缓存时，调整调度策略。进入缓存的页面会受到更严格的限制。
     - **JavaScript 关系:** 进入缓存的页面，其 JavaScript 执行会受到严格限制，以防止意外行为。`PageSchedulerImpl` 会延迟跟踪发送到缓存页面的 IPC 消息。
   - **管理音频状态 (`AudioStateChanged`):**  监听页面是否正在播放音频，这会影响后台节流策略。正在播放音频的后台页面通常不会被立即冻结。
     - **JavaScript 关系:** JavaScript 可以通过 Web Audio API 或 HTML5 `<audio>` 标签控制音频播放，`PageSchedulerImpl` 监听这些变化。
     - **HTML 关系:**  HTML5 的 `<audio>` 标签的状态会影响 `PageSchedulerImpl` 的决策。

2. **帧调度管理:**
   - **注册和管理帧调度器 (`RegisterFrameSchedulerImpl`, `CreateFrameScheduler`, `Unregister`):**  为页面内的每个帧（包括主帧和 iframe）创建并管理 `FrameSchedulerImpl` 实例，负责帧级别的调度。
     - **HTML 关系:** 每个 HTML `<iframe>` 元素都会对应一个 `FrameSchedulerImpl` 实例，由 `PageSchedulerImpl` 管理。
   - **更新帧的调度策略 (`UpdatePolicy`):**  根据页面的整体状态（可见性、音频播放、是否冻结等）更新各个帧的调度策略。

3. **资源节流 (Throttling):**
   - **CPU 时间节流 (`DoThrottleCPUTime`):**  在页面进入后台后，逐渐限制分配给页面的 CPU 时间，降低资源消耗。
     - **JavaScript 关系:**  CPU 时间节流会直接影响 JavaScript 的执行速度。后台页面的 JavaScript 执行频率会被降低。
   - **唤醒节流 (`DoIntensivelyThrottleWakeUps`):**  限制后台页面唤醒的频率，进一步降低资源消耗。
     - **JavaScript 关系:**  后台页面中的 JavaScript 定时器可能不会按照预期的时间间隔触发，因为唤醒被节流。
   - **管理 Wake-Up Budget Pool:**  维护用于控制任务唤醒的预算池，根据页面状态和帧的来源（同源/跨域）分配不同的预算。
     - **JavaScript 关系:** JavaScript 代码触发的任务（例如定时器回调，事件处理）需要通过预算池才能被唤醒执行。

4. **性能优化:**
   - **延迟后台标签冻结 (`kThrottlingDelayAfterBackgrounding`, `kDefaultDelayForBackgroundTabFreezing`):**  在页面进入后台后，并不是立即冻结，而是有一个延迟，给页面一些时间来完成必要的清理工作。
   - **抑制高强度节流 (`kTimeToInhibitIntensiveThrottlingOnTitleOrFaviconUpdate`):**  当页面标题或图标更新时，会短暂抑制对同源帧的高强度节流，以确保用户能注意到这些变化。
     - **HTML 关系:** `<title>` 标签和 `<link rel="icon">` 的更新会触发此机制。

5. **与其他组件交互:**
   - 与 `MainThreadSchedulerImpl` 交互，控制主线程的任务调度。
   - 与 `AgentGroupSchedulerImpl` 交互，管理属于同一个 Agent Group 的页面调度器。
   - 通过 `PageScheduler::Delegate` 与上层组件通信，例如通知页面冻结状态的变化。

**逻辑推理示例:**

假设输入：

1. 用户将一个包含多个 JavaScript 定时器的网页切换到后台。
2. 该网页没有正在播放音频。

输出（`PageSchedulerImpl` 的行为）：

1. `SetPageVisible(false)` 被调用。
2. 在延迟一段时间后 (`kThrottlingDelayAfterBackgrounding`)，`DoThrottleCPUTime` 被调用，开始降低分配给该页面的 CPU 时间。
3. 进一步延迟后，`DoIntensivelyThrottleWakeUps` 被调用，开始限制该页面任务的唤醒频率。
4. 如果后台时间超过 `kDefaultDelayForBackgroundTabFreezing`，且页面没有音频播放，则 `SetPageFrozen(true)` 可能会被调用，完全暂停页面的活动。
5. 在整个过程中，`PageSchedulerImpl` 会更新各个 `FrameSchedulerImpl` 的策略，使其帧也受到相应的限制。

**用户或编程常见的使用错误举例:**

1. **JavaScript 开发者假设后台定时器会精确执行:** 开发者可能编写依赖于精确时间间隔的 JavaScript 代码，例如动画或数据同步，而没有考虑到后台节流的影响。这会导致在页面进入后台后，这些功能出现异常或延迟。
   - **错误示例:**  使用 `setInterval` 每秒更新一次 UI 元素，但在后台时，更新频率可能会显著降低。
2. **开发者不了解页面生命周期 API:** 开发者可能没有使用 Page Lifecycle API 提供的事件（如 `visibilitychange`, `freeze`, `resume`) 来感知页面的状态变化，并做出相应的处理。
   - **错误示例:**  在页面隐藏时没有保存应用状态，导致页面被冻结后状态丢失。
3. **过度依赖后台活动:**  应用可能在后台执行大量的计算或网络请求，而没有考虑到浏览器对后台活动的限制。这可能会导致性能问题，并可能被浏览器强制停止。
   - **错误示例:**  在后台页面持续轮询服务器更新数据。

**总结:**

`PageSchedulerImpl` 是 Blink 渲染引擎中一个至关重要的组件，它负责在页面级别协调和优化资源的使用，确保用户体验的流畅和高效。它与 JavaScript, HTML, CSS 的功能息息相关，通过管理页面的生命周期和资源分配，直接影响着这些 Web 技术在不同页面状态下的行为。理解 `PageSchedulerImpl` 的功能对于编写高性能、资源友好的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/page_scheduler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/page_scheduler_impl.h"

#include <memory>
#include <optional>

#include "base/check_op.h"
#include "base/containers/contains.h"
#include "base/debug/stack_trace.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/memory/post_delayed_memory_reduction_task.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/cpu_time_budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/task_queue_throttler.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/wake_up_budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/page_visibility_state.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/policy_updater.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/use_case.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/perfetto/include/perfetto/tracing/traced_value.h"

namespace blink {
namespace scheduler {

namespace {

using blink::FrameScheduler;

constexpr double kDefaultBackgroundBudgetAsCPUFraction = .01;
constexpr double kDefaultMaxBackgroundBudgetLevelInSeconds = 3;
constexpr double kDefaultInitialBackgroundBudgetInSeconds = 1;
constexpr double kDefaultMaxBackgroundThrottlingDelayInSeconds = 0;

// Delay for fully throttling the page after backgrounding.
constexpr base::TimeDelta kThrottlingDelayAfterBackgrounding =
    base::Seconds(10);

// The amount of time to wait before suspending shared timers, and loading
// etc. after the renderer has been backgrounded. This is used only if
// background suspension is enabled.
constexpr base::TimeDelta kDefaultDelayForBackgroundTabFreezing =
    base::Minutes(5);

// Duration of a throttled wake up.
constexpr base::TimeDelta kThrottledWakeUpDuration = base::Milliseconds(3);

// The duration for which intensive throttling should be inhibited for
// same-origin frames when the page title or favicon is updated.
constexpr base::TimeDelta
    kTimeToInhibitIntensiveThrottlingOnTitleOrFaviconUpdate = base::Seconds(3);

constexpr base::TimeDelta kDefaultDelayForTrackingIPCsPostedToCachedFrames =
    base::Seconds(15);

// Values coming from the field trial config are interpreted as follows:
//   -1 is "not set". Scheduler should use a reasonable default.
//   0 corresponds to std::nullopt.
//   Other values are left without changes.

struct BackgroundThrottlingSettings {
  double budget_recovery_rate;
  std::optional<base::TimeDelta> max_budget_level;
  std::optional<base::TimeDelta> max_throttling_delay;
  std::optional<base::TimeDelta> initial_budget;
};

double GetDoubleParameterFromMap(const base::FieldTrialParams& settings,
                                 const std::string& setting_name,
                                 double default_value) {
  const auto& find_it = settings.find(setting_name);
  if (find_it == settings.end())
    return default_value;
  double parsed_value;
  if (!base::StringToDouble(find_it->second, &parsed_value))
    return default_value;
  if (parsed_value == -1)
    return default_value;
  return parsed_value;
}

std::optional<base::TimeDelta> DoubleToOptionalTime(double value) {
  if (value == 0)
    return std::nullopt;
  return base::Seconds(value);
}

BackgroundThrottlingSettings GetBackgroundThrottlingSettings() {
  base::FieldTrialParams background_throttling_settings;
  base::GetFieldTrialParams("ExpensiveBackgroundTimerThrottling",
                            &background_throttling_settings);

  BackgroundThrottlingSettings settings;

  settings.budget_recovery_rate =
      GetDoubleParameterFromMap(background_throttling_settings, "cpu_budget",
                                kDefaultBackgroundBudgetAsCPUFraction);

  settings.max_budget_level = DoubleToOptionalTime(
      GetDoubleParameterFromMap(background_throttling_settings, "max_budget",
                                kDefaultMaxBackgroundBudgetLevelInSeconds));

  settings.max_throttling_delay = DoubleToOptionalTime(
      GetDoubleParameterFromMap(background_throttling_settings, "max_delay",
                                kDefaultMaxBackgroundThrottlingDelayInSeconds));

  settings.initial_budget = DoubleToOptionalTime(GetDoubleParameterFromMap(
      background_throttling_settings, "initial_budget",
      kDefaultInitialBackgroundBudgetInSeconds));

  return settings;
}

base::TimeDelta GetDelayForBackgroundTabFreezing() {
  static const base::FeatureParam<int> kDelayForBackgroundTabFreezingMillis{
      &features::kStopInBackground, "DelayForBackgroundTabFreezingMills",
      static_cast<int>(kDefaultDelayForBackgroundTabFreezing.InMilliseconds())};
  return base::Milliseconds(kDelayForBackgroundTabFreezingMillis.Get());
}

base::TimeDelta GetTimeToDelayIPCTrackingWhileStoredInBackForwardCache() {
  if (base::FeatureList::IsEnabled(
          features::kLogUnexpectedIPCPostedToBackForwardCachedDocuments)) {
    static const base::FeatureParam<int>
        kDelayForLoggingUnexpectedIPCPostedToBckForwardCacheMillis{
            &features::kLogUnexpectedIPCPostedToBackForwardCachedDocuments,
            "delay_before_tracking_ms",
            static_cast<int>(kDefaultDelayForTrackingIPCsPostedToCachedFrames
                                 .InMilliseconds())};
    return base::Milliseconds(
        kDelayForLoggingUnexpectedIPCPostedToBckForwardCacheMillis.Get());
  }
  return kDefaultDelayForTrackingIPCsPostedToCachedFrames;
}

}  // namespace

constexpr base::TimeDelta PageSchedulerImpl::kDefaultThrottledWakeUpInterval;
constexpr base::TimeDelta PageSchedulerImpl::kIntensiveThrottledWakeUpInterval;

PageSchedulerImpl::PageSchedulerImpl(
    PageScheduler::Delegate* delegate,
    AgentGroupSchedulerImpl& agent_group_scheduler)
    : main_thread_scheduler_(static_cast<MainThreadSchedulerImpl*>(
          &agent_group_scheduler.GetMainThreadScheduler())),
      agent_group_scheduler_(agent_group_scheduler),
      page_visibility_(kDefaultPageVisibility),
      page_visibility_changed_time_(main_thread_scheduler_->NowTicks()),
      audio_state_(AudioState::kSilent),
      audio_state_changed_time_(page_visibility_changed_time_),
      is_frozen_(false),
      opted_out_from_aggressive_throttling_(false),
      nested_runloop_(false),
      is_main_frame_local_(false),
      is_cpu_time_throttled_(false),
      are_wake_ups_intensively_throttled_(false),
      had_recent_title_or_favicon_update_(false),
      delegate_(delegate),
      delay_for_background_tab_freezing_(GetDelayForBackgroundTabFreezing()),
      unimportant_timers_throttled_wake_up_interval_(base::Milliseconds(
          features::kUnimportantFrameTimersThrottledWakeUpIntervalMills
              .Get())) {
  do_throttle_cpu_time_callback_.Reset(base::BindRepeating(
      &PageSchedulerImpl::DoThrottleCPUTime, base::Unretained(this)));
  do_intensively_throttle_wake_ups_callback_.Reset(
      base::BindRepeating(&PageSchedulerImpl::DoIntensivelyThrottleWakeUps,
                          base::Unretained(this)));
  reset_had_recent_title_or_favicon_update_.Reset(base::BindRepeating(
      &PageSchedulerImpl::ResetHadRecentTitleOrFaviconUpdate,
      base::Unretained(this)));
  on_audio_silent_closure_.Reset(base::BindRepeating(
      &PageSchedulerImpl::OnAudioSilent, base::Unretained(this)));
}

PageSchedulerImpl::~PageSchedulerImpl() {
  // TODO(alexclarke): Find out why we can't rely on the web view outliving the
  // frame.
  {
    PolicyUpdater policy_updater;
    for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
      frame_scheduler->OnPageSchedulerDeletion(policy_updater);
    }
    agent_group_scheduler_->RemovePageScheduler(this);
  }

  main_thread_scheduler_->RemovePageScheduler(this);
}

// static
// kRecentAudioDelay is defined in the header for use in unit tests and requires
// storage for linking to succeed with some compiler toolchains.
constexpr base::TimeDelta PageSchedulerImpl::kRecentAudioDelay;

void PageSchedulerImpl::SetPageVisible(bool page_visible) {
  PolicyUpdater policy_updater;
  PageVisibilityState page_visibility = page_visible
                                            ? PageVisibilityState::kVisible
                                            : PageVisibilityState::kHidden;

  if (page_visibility_ == page_visibility)
    return;
  page_visibility_ = page_visibility;
  page_visibility_changed_time_ = main_thread_scheduler_->NowTicks();

  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    frame_scheduler->OnPageVisibilityChange(page_visibility_, policy_updater);
  }

  UpdatePolicyOnVisibilityChange(policy_updater);
  policy_updater.UpdatePagePolicy(this);
}

void PageSchedulerImpl::SetPageFrozen(bool frozen) {
  // Only transitions from HIDDEN to FROZEN are allowed for pages (see
  // https://github.com/WICG/page-lifecycle).
  // This is the page freezing path we expose via WebView, which is how
  // embedders freeze pages. Visibility is also controlled by the embedder,
  // through [WebView|WebViewFrameWidget]::SetVisibilityState(). The following
  // happens if the embedder attempts to freeze a page that it set to visible.
  // We check for this illegal state transition later on this code path in page
  // scheduler and frame scheduler when computing the new lifecycle state, but
  // it is desirable to reject the page freeze to prevent the scheduler from
  // being put in a bad state. See https://crbug.com/873214 for context of how
  // this can happen on the browser side.
  if (frozen && IsPageVisible()) {
    DCHECK(false);
    return;
  }
  PolicyUpdater policy_updater;
  SetPageFrozenImpl(frozen, policy_updater);
}

void PageSchedulerImpl::SetPageFrozenImpl(
    bool frozen,
    PolicyUpdater& policy_updater,
    base::MemoryReductionTaskContext called_from) {
  // Only pages owned by web views can be frozen.
  DCHECK(!frozen || IsOrdinary());

  update_frozen_state_timer_.Stop();
  if (is_frozen_ == frozen)
    return;
  is_frozen_ = frozen;
  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    frame_scheduler->SetPageFrozenForTracing(frozen);
    frame_scheduler->SetShouldReportPostedTasksWhenDisabled(frozen);
  }
  policy_updater.UpdatePagePolicy(this);
  if (frozen) {
    main_thread_scheduler_->OnPageFrozen(called_from);
    if (audio_state_ == AudioState::kRecentlyAudible) {
      // A recently audible page is being frozen before the audio silent timer
      // fired, which can happen if freezing from outside the scheduler (e.g.
      // bfcache). Transition to silent now since since freezing isn't dependent
      // on the timeout.
      on_audio_silent_closure_.Cancel();
      OnAudioSilent();
    }
  } else {
    // Since the page is no longer frozen, detach the handler that watches for
    // IPCs posted to frozen pages (or cancel setting up the handler).
    set_ipc_posted_handler_task_.Cancel();
    has_ipc_detection_enabled_ = false;
    main_thread_scheduler_->UpdateIpcTracking();
    for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
      frame_scheduler->DetachOnIPCTaskPostedWhileInBackForwardCacheHandler();
    }

    main_thread_scheduler_->OnPageResumed();
  }

  if (delegate_)
    delegate_->OnSetPageFrozen(frozen);
}

void PageSchedulerImpl::SetPageBackForwardCached(
    bool is_in_back_forward_cache) {
  is_stored_in_back_forward_cache_ = is_in_back_forward_cache;

  if (!is_stored_in_back_forward_cache_) {
    TRACE_EVENT_INSTANT("navigation",
                        "PageSchedulerImpl::SetPageBackForwardCached_Restore");
    stored_in_back_forward_cache_timestamp_ = base::TimeTicks();
  } else {
    TRACE_EVENT_INSTANT("navigation",
                        "PageSchedulerImpl::SetPageBackForwardCached_Store");
    stored_in_back_forward_cache_timestamp_ =
        main_thread_scheduler_->NowTicks();

    // Incorporate a delay of 15 seconds to allow for caching operations to
    // complete before tasks are logged.
    set_ipc_posted_handler_task_ = PostDelayedCancellableTask(
        *main_thread_scheduler_->ControlTaskRunner(), FROM_HERE,
        base::BindRepeating(&PageSchedulerImpl::SetUpIPCTaskDetection,
                            GetWeakPtr()),
        GetTimeToDelayIPCTrackingWhileStoredInBackForwardCache());
  }
}

void PageSchedulerImpl::SetUpIPCTaskDetection() {
  DCHECK(is_stored_in_back_forward_cache_);
  has_ipc_detection_enabled_ = true;
  main_thread_scheduler_->UpdateIpcTracking();
  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    frame_scheduler->SetOnIPCTaskPostedWhileInBackForwardCacheHandler();
  }
}

bool PageSchedulerImpl::IsMainFrameLocal() const {
  return is_main_frame_local_;
}

bool PageSchedulerImpl::IsLoading() const {
  if (base::FeatureList::IsEnabled(
          features::kLoadingPhaseBufferTimeAfterFirstMeaningfulPaint)) {
    return IsMainFrameLoading();
  }
  return IsWaitingForMainFrameContentfulPaint();
}

bool PageSchedulerImpl::IsOrdinary() const {
  if (!delegate_)
    return true;
  return delegate_->IsOrdinary();
}

void PageSchedulerImpl::SetIsMainFrameLocal(bool is_local) {
  is_main_frame_local_ = is_local;
}

void PageSchedulerImpl::RegisterFrameSchedulerImpl(
    FrameSchedulerImpl* frame_scheduler) {
  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());

  MaybeInitializeWakeUpBudgetPools(&lazy_now);
  MaybeInitializeBackgroundCPUTimeBudgetPool(&lazy_now);

  frame_schedulers_.insert(frame_scheduler);
  frame_scheduler->UpdatePolicy();
}

std::unique_ptr<blink::FrameScheduler> PageSchedulerImpl::CreateFrameScheduler(
    FrameScheduler::Delegate* delegate,
    bool is_in_embedded_frame_tree,
    FrameScheduler::FrameType frame_type) {
  auto frame_scheduler = std::make_unique<FrameSchedulerImpl>(
      this, delegate, is_in_embedded_frame_tree, frame_type);
  RegisterFrameSchedulerImpl(frame_scheduler.get());
  return frame_scheduler;
}

void PageSchedulerImpl::Unregister(FrameSchedulerImpl* frame_scheduler) {
  DCHECK(base::Contains(frame_schedulers_, frame_scheduler));
  frame_schedulers_.erase(frame_scheduler);
}

void PageSchedulerImpl::AudioStateChanged(bool is_audio_playing) {
  if (is_audio_playing) {
    PolicyUpdater policy_updater;
    on_audio_silent_closure_.Cancel();
    audio_state_ = AudioState::kAudible;
    audio_state_changed_time_ = main_thread_scheduler_->NowTicks();
    UpdateFrozenState(policy_updater);
    main_thread_scheduler_->OnAudioStateChanged();
    policy_updater.UpdatePagePolicy(this);
  } else {
    if (audio_state_ != AudioState::kAudible)
      return;
    on_audio_silent_closure_.Cancel();
    audio_state_ = AudioState::kRecentlyAudible;
    audio_state_changed_time_ = main_thread_scheduler_->NowTicks();

    if (IsFrozen()) {
      // The page was frozen from outside the scheduler before receiving the the
      // audio state change notification. Transition to silent and bypass the
      // recently audible mechanism since the page is already frozen.
      OnAudioSilent();
    } else {
      main_thread_scheduler_->ControlTaskRunner()->PostDelayedTask(
          FROM_HERE, on_audio_silent_closure_.GetCallback(), kRecentAudioDelay);
      // No need to call UpdatePagePolicy or
      // MainThreadScheduler::OnAudioStateChanged here, as for outside world
      // kAudible and kRecentlyAudible are the same thing.
    }
  }
}

void PageSchedulerImpl::OnAudioSilent() {
  DCHECK_EQ(audio_state_, AudioState::kRecentlyAudible);
  audio_state_ = AudioState::kSilent;
  audio_state_changed_time_ = main_thread_scheduler_->NowTicks();
  main_thread_scheduler_->OnAudioStateChanged();
  PolicyUpdater policy_updater;
  UpdateFrozenState(policy_updater);
  policy_updater.UpdatePagePolicy(this);
}

bool PageSchedulerImpl::IsExemptFromBudgetBasedThrottling() const {
  return opted_out_from_aggressive_throttling_;
}

bool PageSchedulerImpl::OptedOutFromAggressiveThrottlingForTest() const {
  return OptedOutFromAggressiveThrottling();
}

bool PageSchedulerImpl::OptedOutFromAggressiveThrottling() const {
  return opted_out_from_aggressive_throttling_;
}

bool PageSchedulerImpl::RequestBeginMainFrameNotExpected(bool new_state) {
  if (!delegate_)
    return false;
  return delegate_->RequestBeginMainFrameNotExpected(new_state);
}

scoped_refptr<WidgetScheduler> PageSchedulerImpl::CreateWidgetScheduler() {
  return main_thread_scheduler_->CreateWidgetScheduler();
}

bool PageSchedulerImpl::IsAudioPlaying() const {
  return audio_state_ == AudioState::kAudible ||
         audio_state_ == AudioState::kRecentlyAudible;
}

bool PageSchedulerImpl::IsPageVisible() const {
  return page_visibility_ == PageVisibilityState::kVisible;
}

bool PageSchedulerImpl::IsFrozen() const {
  return is_frozen_;
}

bool PageSchedulerImpl::IsCPUTimeThrottled() const {
  return is_cpu_time_throttled_;
}

void PageSchedulerImpl::OnThrottlingStatusUpdated() {
  bool opted_out_from_aggressive_throttling = false;
  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    opted_out_from_aggressive_throttling |=
        frame_scheduler->opted_out_from_aggressive_throttling();
  }

  if (opted_out_from_aggressive_throttling_ !=
      opted_out_from_aggressive_throttling) {
    opted_out_from_aggressive_throttling_ =
        opted_out_from_aggressive_throttling;
    base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());
    UpdateCPUTimeBudgetPool(&lazy_now);
    UpdateWakeUpBudgetPools(&lazy_now);
  }
}

void PageSchedulerImpl::OnVirtualTimeEnabled() {
  PolicyUpdater policy_updater;
  UpdatePolicyOnVisibilityChange(policy_updater);
}

void PageSchedulerImpl::OnTraceLogEnabled() {
  tracing_controller_.OnTraceLogEnabled();
  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    frame_scheduler->OnTraceLogEnabled();
  }
}

bool PageSchedulerImpl::IsWaitingForMainFrameContentfulPaint() const {
  return base::ranges::any_of(
      frame_schedulers_, [](const FrameSchedulerImpl* fs) {
        return fs->IsWaitingForContentfulPaint() &&
               !fs->IsInEmbeddedFrameTree() &&
               fs->GetFrameType() == FrameScheduler::FrameType::kMainFrame;
      });
}

bool PageSchedulerImpl::IsWaitingForMainFrameMeaningfulPaint() const {
  return base::ranges::any_of(
      frame_schedulers_, [](const FrameSchedulerImpl* fs) {
        return fs->IsWaitingForMeaningfulPaint() &&
               !fs->IsInEmbeddedFrameTree() &&
               fs->GetFrameType() == FrameScheduler::FrameType::kMainFrame;
      });
}

bool PageSchedulerImpl::IsMainFrameLoading() const {
  return base::ranges::any_of(
      frame_schedulers_, [](const FrameSchedulerImpl* fs) {
        return fs->IsLoading() && !fs->IsInEmbeddedFrameTree() &&
               fs->GetFrameType() == FrameScheduler::FrameType::kMainFrame;
      });
}

void PageSchedulerImpl::WriteIntoTrace(perfetto::TracedValue context,
                                       base::TimeTicks now) const {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("page_visible", page_visibility_ == PageVisibilityState::kVisible);
  dict.Add("is_audio_playing", IsAudioPlaying());
  dict.Add("is_frozen", is_frozen_);
  dict.Add("is_page_freezable", IsBackgrounded());

  if (cpu_time_budget_pool_) {
    dict.Add("cpu_time_budget_pool", [&](perfetto::TracedValue context) {
      cpu_time_budget_pool_->WriteIntoTrace(std::move(context), now);
    });
  }
  if (unimportant_wake_up_budget_pool_) {
    dict.Add("unimportant_wake_up_budget_pool",
             [&](perfetto::TracedValue context) {
               unimportant_wake_up_budget_pool_->WriteIntoTrace(
                   std::move(context), now);
             });
  }
  if (hidden_wake_up_budget_pool_) {
    dict.Add("hidden_wake_up_budget_pool", [&](perfetto::TracedValue context) {
      hidden_wake_up_budget_pool_->WriteIntoTrace(std::move(context), now);
    });
  }
  if (same_origin_intensive_wake_up_budget_pool_) {
    dict.Add("same_origin_intensive_wake_up_budget_pool",
             [&](perfetto::TracedValue context) {
               same_origin_intensive_wake_up_budget_pool_->WriteIntoTrace(
                   std::move(context), now);
             });
  }
  if (cross_origin_intensive_wake_up_budget_pool_) {
    dict.Add("cross_origin_intensive_wake_up_budget_pool",
             [&](perfetto::TracedValue context) {
               cross_origin_intensive_wake_up_budget_pool_->WriteIntoTrace(
                   std::move(context), now);
             });
  }

  dict.Add("frame_schedulers", frame_schedulers_);
}

void PageSchedulerImpl::AddQueueToWakeUpBudgetPool(
    MainThreadTaskQueue* task_queue,
    WakeUpBudgetPool* wake_up_budget_pool,
    base::LazyNow* lazy_now) {
  DCHECK(!task_queue->GetWakeUpBudgetPool());
  if (!wake_up_budget_pool) {
    return;
  }
  task_queue->AddToBudgetPool(lazy_now->Now(), wake_up_budget_pool);
  task_queue->SetWakeUpBudgetPool(wake_up_budget_pool);
}

void PageSchedulerImpl::RemoveQueueFromWakeUpBudgetPool(
    MainThreadTaskQueue* task_queue,
    base::LazyNow* lazy_now) {
  if (!task_queue->GetWakeUpBudgetPool())
    return;
  task_queue->RemoveFromBudgetPool(lazy_now->Now(),
                                   task_queue->GetWakeUpBudgetPool());
  task_queue->SetWakeUpBudgetPool(nullptr);
}

WakeUpBudgetPool* PageSchedulerImpl::GetWakeUpBudgetPool(
    MainThreadTaskQueue* task_queue,
    FrameOriginType frame_origin_type,
    ThrottlingType throttling_type) {
  switch (throttling_type) {
    case ThrottlingType::kNone: {
      return nullptr;
    }
    case ThrottlingType::kForegroundUnimportant: {
      return unimportant_wake_up_budget_pool_.get();
    }
    case ThrottlingType::kBackground: {
      return hidden_wake_up_budget_pool_.get();
    }
    case ThrottlingType::kBackgroundIntensive: {
      if (task_queue->CanBeIntensivelyThrottled()) {
        if (frame_origin_type == FrameOriginType::kCrossOriginToMainFrame) {
          return cross_origin_intensive_wake_up_budget_pool_.get();
        } else {
          return same_origin_intensive_wake_up_budget_pool_.get();
        }
      } else {
        return hidden_wake_up_budget_pool_.get();
      }
    }
  }
}

CPUTimeBudgetPool* PageSchedulerImpl::background_cpu_time_budget_pool() {
  return cpu_time_budget_pool_.get();
}

void PageSchedulerImpl::MaybeInitializeBackgroundCPUTimeBudgetPool(
    base::LazyNow* lazy_now) {
  if (cpu_time_budget_pool_)
    return;

  cpu_time_budget_pool_ = std::make_unique<CPUTimeBudgetPool>(
      "background", &tracing_controller_, lazy_now->Now());

  BackgroundThrottlingSettings settings = GetBackgroundThrottlingSettings();

  cpu_time_budget_pool_->SetMaxBudgetLevel(lazy_now->Now(),
                                           settings.max_budget_level);
  cpu_time_budget_pool_->SetMaxThrottlingDelay(lazy_now->Now(),
                                               settings.max_throttling_delay);

  cpu_time_budget_pool_->SetTimeBudgetRecoveryRate(
      lazy_now->Now(), settings.budget_recovery_rate);

  if (settings.initial_budget) {
    cpu_time_budget_pool_->GrantAdditionalBudget(
        lazy_now->Now(), settings.initial_budget.value());
  }

  UpdateCPUTimeBudgetPool(lazy_now);
}

void PageSchedulerImpl::MaybeInitializeWakeUpBudgetPools(
    base::LazyNow* lazy_now) {
  if (HasWakeUpBudgetPools())
    return;

  unimportant_wake_up_budget_pool_ = std::make_unique<WakeUpBudgetPool>(
      "Page - Foreground Wake Up Throttling - Visible Unimportant & "
      "Cross-Origin to Main Frame");
  hidden_wake_up_budget_pool_ = std::make_unique<WakeUpBudgetPool>(
      "Page - Hidden Wake Up Throttling - Hidden & Cross-Origin to Main "
      "Frame, Or Background Page");
  same_origin_intensive_wake_up_budget_pool_ =
      std::make_unique<WakeUpBudgetPool>(
          "Page - Intensive Wake Up Throttling - Same-Origin as Main Frame");
  cross_origin_intensive_wake_up_budget_pool_ =
      std::make_unique<WakeUpBudgetPool>(
          "Page - Intensive Wake Up Throttling - Cross-Origin to Main Frame");

  // The Wake Up Duration and Unaligned Wake Ups Allowance are constant and set
  // here. The Wake Up Interval is set in UpdateWakeUpBudgetPools(), based on
  // current state.
  for (WakeUpBudgetPool* pool : AllWakeUpBudgetPools())
    pool->SetWakeUpDuration(kThrottledWakeUpDuration);

  same_origin_intensive_wake_up_budget_pool_
      ->AllowLowerAlignmentIfNoRecentWakeUp(kDefaultThrottledWakeUpInterval);

  UpdateWakeUpBudgetPools(lazy_now);
}

void PageSchedulerImpl::UpdatePolicyOnVisibilityChange(
    PolicyUpdater& policy_updater) {
  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());

  if (IsPageVisible()) {
    is_cpu_time_throttled_ = false;
    do_throttle_cpu_time_callback_.Cancel();
    UpdateCPUTimeBudgetPool(&lazy_now);

    are_wake_ups_intensively_throttled_ = false;
    do_intensively_throttle_wake_ups_callback_.Cancel();
  } else {
    if (cpu_time_budget_pool_) {
      main_thread_scheduler_->ControlTaskRunner()->PostDelayedTask(
          FROM_HERE, do_throttle_cpu_time_callback_.GetCallback(),
          kThrottlingDelayAfterBackgrounding);
    }
    main_thread_scheduler_->ControlTaskRunner()->PostDelayedTask(
        FROM_HERE, do_intensively_throttle_wake_ups_callback_.GetCallback(),
        GetIntensiveWakeUpThrottlingGracePeriod(IsLoading()));
  }

  UpdateFrozenState(policy_updater);
  policy_updater.UpdatePagePolicy(this);
}

void PageSchedulerImpl::DoThrottleCPUTime() {
  do_throttle_cpu_time_callback_.Cancel();
  is_cpu_time_throttled_ = true;

  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());
  UpdateCPUTimeBudgetPool(&lazy_now);
  UpdatePolicy();
}

void PageSchedulerImpl::DoIntensivelyThrottleWakeUps() {
  do_intensively_throttle_wake_ups_callback_.Cancel();
  are_wake_ups_intensively_throttled_ = true;

  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());
  UpdateWakeUpBudgetPools(&lazy_now);
  UpdatePolicy();
}

void PageSchedulerImpl::UpdateCPUTimeBudgetPool(base::LazyNow* lazy_now) {
  if (!cpu_time_budget_pool_)
    return;

  if (is_cpu_time_throttled_ && !opted_out_from_aggressive_throttling_) {
    cpu_time_budget_pool_->EnableThrottling(lazy_now);
  } else {
    cpu_time_budget_pool_->DisableThrottling(lazy_now);
  }
}

void PageSchedulerImpl::OnTitleOrFaviconUpdated() {
  if (!HasWakeUpBudgetPools())
    return;
  if (are_wake_ups_intensively_throttled_ &&
      !opted_out_from_aggressive_throttling_) {
    // When the title of favicon is updated, intensive throttling is inhibited
    // for same-origin frames. This enables alternating effects meant to grab
    // the user's attention. Cross-origin frames are not affected, since they
    // shouldn't be able to observe that the page title or favicon was updated.
    had_recent_title_or_favicon_update_ = true;
    base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());
    UpdateWakeUpBudgetPools(&lazy_now);
    // Re-enable intensive throttling from a delayed task.
    reset_had_recent_title_or_favicon_update_.Cancel();
    main_thread_scheduler_->ControlTaskRunner()->PostDelayedTask(
        FROM_HERE, reset_had_recent_title_or_favicon_update_.GetCallback(),
        kTimeToInhibitIntensiveThrottlingOnTitleOrFaviconUpdate);
  }
}

void PageSchedulerImpl::ResetHadRecentTitleOrFaviconUpdate() {
  had_recent_title_or_favicon_update_ = false;

  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());
  UpdateWakeUpBudgetPools(&lazy_now);

  UpdatePolicy();
}

base::TimeDelta PageSchedulerImpl::GetIntensiveWakeUpThrottlingInterval(
    bool is_same_origin) const {
  // Title and favicon changes only affect the same_origin wake up budget pool.
  if (is_same_origin && had_recent_title_or_favicon_update_)
    return kDefaultThrottledWakeUpInterval;

  if (are_wake_ups_intensively_throttled_ &&
      !opted_out_from_aggressive_throttling_)
    return kIntensiveThrottledWakeUpInterval;
  else
    return kDefaultThrottledWakeUpInterval;
}

void PageSchedulerImpl::UpdateWakeUpBudgetPools(base::LazyNow* lazy_now) {
  if (!same_origin_intensive_wake_up_budget_pool_)
    return;

  unimportant_wake_up_budget_pool_->SetWakeUpInterval(
      lazy_now->Now(), unimportant_timers_throttled_wake_up_interval_);
  hidden_wake_up_budget_pool_->SetWakeUpInterval(
      lazy_now->Now(), kDefaultThrottledWakeUpInterval);
  same_origin_intensive_wake_up_budget_pool_->SetWakeUpInterval(
      lazy_now->Now(), GetIntensiveWakeUpThrottlingInterval(true));
  cross_origin_intensive_wake_up_budget_pool_->SetWakeUpInterval(
      lazy_now->Now(), GetIntensiveWakeUpThrottlingInterval(false));
}

void PageSchedulerImpl::UpdatePolicy() {
  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    frame_scheduler->UpdatePolicy();
  }

  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());
  UpdateWakeUpBudgetPools(&lazy_now);
}

size_t PageSchedulerImpl::FrameCount() const {
  return frame_schedulers_.size();
}

MainThreadSchedulerImpl* PageSchedulerImpl::GetMainThreadScheduler() const {
  return main_thread_scheduler_;
}

AgentGroupSchedulerImpl& PageSchedulerImpl::GetAgentGroupScheduler() {
  return *agent_group_scheduler_;
}

VirtualTimeController* PageSchedulerImpl::GetVirtualTimeController() {
  return main_thread_scheduler_;
}

bool PageSchedulerImpl::IsBackgrounded() const {
  // When virtual time is enabled, a freezing request would have its timeout
  // expire immediately when a page is backgrounded, which is undesirable in
  // headless mode. To prevent that, a page is never considerer backgrounded
  // when virtual time is enabled.
  return !IsPageVisible() && !IsAudioPlaying() &&
         !main_thread_scheduler_->IsVirtualTimeEnabled();
}

FrameSchedulerImpl* PageSchedulerImpl::SelectFrameForUkmAttribution() {
  for (FrameSchedulerImpl* frame_scheduler : frame_schedulers_) {
    if (frame_scheduler->GetUkmRecorder())
      return frame_scheduler;
  }
  return nullptr;
}

bool PageSchedulerImpl::HasWakeUpBudgetPools() const {
  // All WakeUpBudgetPools should be initialized together.
  DCHECK_EQ(!!unimportant_wake_up_budget_pool_, !!hidden_wake_up_budget_pool_);
  DCHECK_EQ(!!unimportant_wake_up_budget_pool_,
            !!same_origin_intensive_wake_up_budget_pool_);
  DCHECK_EQ(!!unimportant_wake_up_budget_pool_,
            !!cross_origin_intensive_wake_up_budget_pool_);

  return !!unimportant_wake_up_budget_pool_;
}

void PageSchedulerImpl::UpdateFrozenState(
    PolicyUpdater& policy_updater,
    base::MemoryReductionTaskContext called_from) {
  // Only ordinary pages can be frozen.
  if (!IsOrdinary()) {
    CHECK(!IsFrozen());
    return;
  }

  base::TimeTicks now = main_thread_scheduler_->NowTicks();

  // `freeze_time` indicates when the page should be frozen. If Max(), the page
  // is unfrozen immediately. Else if <= now, the page is frozen immediately.
  // Else, a task is scheduled to freeze the page later.
  base::TimeTicks freeze_time = base::TimeTicks::Max();

  if (IsBackgrounded()) {
    if (IsFrozen()) {
      // Special case: A page can remain frozen even if less than
      // `delay_for_backround_tab_freezing_` has elapsed since it was
      // backgrounded. This can happen when the page is frozen via
      // SetPageFrozen().
      freeze_time = now;
    } else if (base::FeatureList::IsEnabled(
                   blink::features::kStopInBackground)) {
      if (called_from == base::MemoryReductionTaskContext::kProactive) {
        // Special case: Freeze now if the timer has been fast-forwarded to
        // proactively reduce memory.
        freeze_time = now;
      } else {
        freeze_time =
            std::max(page_visibility_changed_time_, audio_state_changed_time_) +
            delay_for_background_tab_freezing_;
      }
    }
  }

  if (freeze_time > now) {
    SetPageFrozenImpl(/* frozen=*/false, policy_updater, called_from);
    if (!freeze_time.is_max()) {
      update_frozen_state_timer_.SetTaskRunner(
          main_thread_scheduler_->ControlTaskRunner());
      update_frozen_state_timer_.Start(
          FROM_HERE, freeze_time - now,
          base::BindOnce(
              [](PageSchedulerImpl* page_scheduler,
                 base::MemoryReductionTaskContext called_from) {
                PolicyUpdater policy_updater;
                page_scheduler->UpdateFrozenState(policy_updater, called_from);
              },
              base::Unretained(this)));
    }
  } else {
    SetPageFrozenImpl(/* frozen=*/true, policy_updater, called_from);
  }
}

void PageSchedulerImpl::UpdateFrozenState(PolicyUpdater& policy_updater) {
  PageSchedulerImpl::UpdateFrozenState(
      policy_updater, base::MemoryReductionTaskContext::kDelayExpired);
}

std::array<WakeUpBudgetPool*, PageSchedulerImpl::kNumWakeUpBudgetPools>
PageSchedulerImpl::AllWakeUpBudgetPools() {
  return {unimportant_wake_up_budget_pool_.get(),
          hidden_wake_up_budget_pool_.get(),
          same_origin_intensive_wake_up_budget_pool_.get(),
          cross_origin_intensive_wake_up_budget_pool_.get()};
}

}  // namespace scheduler
}  // namespace blink

"""

```