Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This is the second part of a two-part file. The goal is to summarize the features implemented in this section, explain their relevance to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with inputs and outputs, illustrate common usage errors, detail the user actions leading to this code execution during debugging, and finally, summarize the overall functionality of this part.

**Plan:**

1. **Identify Key Functionalities:** Read through the code and pinpoint the main functions and their purposes. Focus on methods related to interval management, active state determination, event handling, and synchronization with other animation elements.
2. **Relate to Web Technologies:**  Connect the identified functionalities to concepts in JavaScript (animation events, DOM manipulation), HTML (SVG animation elements), and CSS (animation timing and behavior). Provide concrete examples.
3. **Logical Reasoning (Hypothetical Input/Output):**  Select a few key functions and simulate their behavior with specific inputs to demonstrate the expected output.
4. **Common Usage Errors:** Think about how a web developer might misuse or misunderstand the concepts implemented in this code. Focus on errors related to animation timing, synchronization, and event handling.
5. **User Interaction and Debugging:** Describe the sequence of user actions that would trigger the execution of the code during debugging. Consider scenarios involving inspecting SVG animations and their timing.
6. **Summarize Functionality:** Concisely describe the overall purpose and responsibilities of the code snippet.

**Detailed Breakdown of Code Functionality:**

*   **`ServiceTimeContainerUpdate()`:** Handles time updates, checks active state, and reschedules for the next interval.
*   **`IntervalStateChanged()`:** Forces re-evaluation of the current interval.
*   **`DiscardOrRevalidateCurrentInterval()`:**  Manages the validity of the current animation interval based on presentation time.
*   **`HandleIntervalRestart()`:** Determines if an animation should restart based on its `restart` attribute.
*   **`LastIntervalEndTime()`:**  Calculates the end time of the last active interval.
*   **`UpdateInterval()`:** Resolves and updates the current animation interval.
*   **`AddedToTimeContainer()`:**  Called when the animation is added to the time container, initializes the animation and dispatches begin events.
*   **`RemovedFromTimeContainer()`:** Called when the animation is removed from the time container, handles end events.
*   **`GetActiveInterval()`:** Returns the currently active animation interval.
*   **`CalculateProgressState()`:** Calculates the current progress (fraction and repeat count) of the animation.
*   **`NextProgressTime()`:** Determines the next time the animation progress will change.
*   **`DetermineActiveState()`:** Determines if the animation is currently active based on the interval and elapsed time.
*   **`IsContributing()`:**  Determines if the animation is currently affecting the animated property.
*   **`UpdateActiveState()`:**  Updates the active state of the animation and determines which events to dispatch.
*   **`ComputeSeekEvents()`:** Determines the events to dispatch when the animation timeline is seeked.
*   **`DispatchEvents()`:**  Enqueues animation events (begin, end, repeat) for dispatching.
*   **`AddedEventListener()`:** Handles the addition of event listeners, specifically for the "repeatn" event.
*   **`UpdateProgressState()`:** Updates the cached progress state.
*   **`NotifyDependentsOnNewInterval()` and `NotifyDependentsOnRepeat()`:** Convenience methods to notify dependent animations about changes.
*   **`NotifyDependents()`:**  Notifies other animations that are synchronized with this animation.
*   **`CreateInstanceTimesFromSyncBase()`:**  Creates instance times for this animation based on notifications from its sync base.
*   **`AddSyncBaseDependent()` and `RemoveSyncBaseDependent()`:** Manage the list of animations that depend on this animation's timing.
*   **`BeginByLinkActivation()`:** Starts the animation due to a link activation.
*   **`StartedActiveInterval()` and `EndedActiveInterval()`:**  Update the animation's state when an active interval starts or ends.
*   **`HasValidTarget()`:** Checks if the animation has a valid target element.
*   **`WillChangeAnimationTarget()` and `DidChangeAnimationTarget()`:** Handle changes in the animation's target element.
*   **`Trace()`:**  Used for debugging and memory management.

**Synthesize the Information:** Now, construct the response based on the gathered information, adhering to the user's request for examples and explanations.
这是 blink 渲染引擎中 `blink/renderer/core/svg/animation/svg_smil_element.cc` 文件的第二部分，主要负责处理 SVG SMIL 动画元素的生命周期管理、时间控制、状态更新以及事件分发等核心逻辑。它与 JavaScript、HTML 和 CSS 功能紧密相关，因为 SMIL 动画是通过 HTML 的 SVG 元素定义，并通过 JavaScript API 进行交互，其动画效果最终体现在 CSS 样式的变化上。

**功能归纳:**

这一部分代码主要负责以下功能：

1. **处理时间容器的更新:**  `ServiceTimeContainerUpdate` 函数负责响应时间容器的更新，根据当前时间和之前的状态，判断动画是否需要进入或退出激活状态，并计算下一个需要更新的时间点。
2. **管理动画间隔:** 包含了一系列函数用于管理动画的有效时间段（interval），例如 `IntervalStateChanged` 用于标记间隔需要重新计算，`DiscardOrRevalidateCurrentInterval` 用于废弃或重新验证当前间隔，`HandleIntervalRestart` 处理动画的重启行为，`LastIntervalEndTime` 计算上一个间隔的结束时间，以及 `UpdateInterval` 负责解析和更新动画的当前间隔。
3. **处理动画的激活状态:** `AddedToTimeContainer` 和 `RemovedFromTimeContainer` 分别在动画元素添加到和从时间容器移除时被调用，用于初始化和清理动画状态，并触发相应的事件。 `GetActiveInterval` 返回当前激活的动画间隔， `DetermineActiveState` 根据当前时间和间隔判断动画是否处于激活状态。
4. **计算动画进度:** `CalculateProgressState` 计算动画在当前时间的进度（0 到 1 的浮点数以及重复次数），`NextProgressTime` 预测动画下一次进度变化的时间点。
5. **判断动画是否生效:** `IsContributing` 判断动画在给定的时间点是否对目标属性产生影响。
6. **更新激活状态并分发事件:** `UpdateActiveState` 负责更新动画的激活状态，并根据状态变化决定需要分发的事件（`beginEvent`，`endEvent`，`repeatEvent`）。 `ComputeSeekEvents`  在动画时间被seek时计算需要触发的事件。 `DispatchEvents` 实际执行事件的分发操作。
7. **处理同步动画:**  `NotifyDependentsOnNewInterval` 和 `NotifyDependentsOnRepeat` 用于通知依赖于当前动画的其他动画元素，`NotifyDependents` 执行通知操作，`CreateInstanceTimesFromSyncBase` 响应来自同步基准的通知并创建实例时间， `AddSyncBaseDependent` 和 `RemoveSyncBaseDependent` 管理依赖当前动画的元素。
8. **处理链接激活:** `BeginByLinkActivation`  处理通过链接激活触发动画的情况。
9. **维护动画目标:** `HasValidTarget` 检查动画目标元素是否有效， `WillChangeAnimationTarget` 和 `DidChangeAnimationTarget`  在动画目标元素改变时进行相应的处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:**  SMIL 动画元素（如 `<animate>`, `<set>`, `<animateMotion>` 等）在 HTML 的 SVG 文档中定义。这个文件中的代码正是负责处理这些元素的行为和时间控制。
    *   **例子:**  一个 `<animate>` 元素定义了某个 SVG 图形的属性在一段时间内的变化。`SVGSMILElement` 的代码会解析这个元素的属性，例如 `begin`, `dur`, `repeatCount` 等，来确定动画的起始时间、持续时间和重复次数。
*   **JavaScript:** JavaScript 可以通过 DOM API 与 SMIL 动画元素进行交互，例如添加事件监听器来响应动画的开始、结束或重复事件，或者通过脚本控制动画的播放状态。
    *   **例子:**  JavaScript 可以使用 `element.addEventListener('beginEvent', function(){ ... })` 来监听动画的开始事件。`DispatchEvents` 函数会将这些事件加入到事件队列中，最终由浏览器执行 JavaScript 回调函数。
*   **CSS:**  虽然 SMIL 动画不是通过 CSS 直接控制，但动画的效果最终会体现在 SVG 元素的 CSS 属性变化上。浏览器会根据 SMIL 动画的计算结果，更新元素的渲染样式。
    *   **例子:**  一个 `<animate>` 元素改变了矩形的 `x` 属性。`CalculateProgressState` 和相关的函数会计算出在特定时间点 `x` 属性的值，然后浏览器会更新该矩形的 CSS `x` 属性，从而实现动画效果。

**逻辑推理 (假设输入与输出):**

假设有一个 `<animate>` 元素，定义如下：

```html
<animate attributeName="opacity" from="0" to="1" begin="click" dur="1s" fill="freeze"/>
```

*   **假设输入:** 用户点击了该动画元素所在的 SVG 图形。当前时间容器的时间为 T0。
*   **逻辑推理过程:**
    1. 用户点击触发了一个事件。
    2. `BeginByLinkActivation` 函数被调用，将当前时间 T0 添加到 `begin_times_` 列表中，并标记来源为 `SMILTimeOrigin::kLinkActivation`。
    3. `UpdateInterval` 函数被调用，根据新的 `begin` 时间重新计算动画的 `interval_`。
    4. 如果时间容器正在运行，`AddedToTimeContainer` 会被调用（如果元素之前未被调度）。
    5. `DetermineActiveState` 函数会判断在 T0 时刻，动画由于 `begin="click"` 事件的发生而进入激活状态。
    6. `UpdateActiveState` 函数检测到动画状态从非激活变为激活，会将 `kDispatchBeginEvent` 标记添加到 `events_to_dispatch`。
    7. `DispatchEvents` 函数会被调用，将 `beginEvent` 加入到事件队列中。
*   **预期输出:**  会触发一个 `beginEvent`，如果 JavaScript 代码监听了这个事件，相应的回调函数会被执行。动画的 `opacity` 属性开始从 0 变化到 1。

**用户或编程常见的使用错误:**

1. **错误地设置 `begin` 属性:**  如果 `begin` 属性设置的值无法被解析或者永远不会发生，动画可能永远不会开始。
    *   **例子:**  `<animate begin="nonExistentEvent" ...>`  这里如果不存在 `nonExistentEvent` 事件，动画将不会启动。
2. **`dur` 和 `end` 属性冲突:**  同时设置 `dur` 和 `end` 属性可能会导致意外的动画行为，因为浏览器需要根据规范来决定哪个属性优先。
    *   **例子:**  `<animate dur="5s" end="3s" ...>`  动画会在 3 秒结束，即使 `dur` 设置为 5 秒。
3. **忘记设置 `fill` 属性:**  如果不设置 `fill="freeze"`，动画结束后可能会恢复到初始状态，而不是停留在结束时的状态。
    *   **例子:**  一个淡入动画，如果没有 `fill="freeze"`，动画结束后会立即消失。
4. **依赖于事件触发的动画但事件没有正确绑定:**  如果动画的 `begin` 属性依赖于某个事件，但该事件监听器没有正确添加到目标元素上，动画将不会启动。
    *   **例子:**  `<animate begin="myButton.click" ...>`，如果不存在 ID 为 `myButton` 的元素或者该元素没有 click 事件监听器，动画可能不会按预期启动。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个包含 SVG 动画的网页。**
2. **浏览器开始解析 HTML，构建 DOM 树。** 当解析到 `<animate>` 等 SMIL 动画元素时，会创建 `SVGSMILElement` 的对象。
3. **布局过程确定了 SVG 元素的位置和大小。**
4. **如果动画的 `begin` 属性设置为页面加载完成时开始，或者依赖于某些初始条件，时间容器会开始调度这些动画。** `AddedToTimeContainer` 会被调用。
5. **如果动画的 `begin` 属性依赖于用户交互（例如 `click` 事件），用户执行相应的操作。**
6. **浏览器捕获到用户交互事件，并根据事件目标找到相关的 SMIL 动画元素。**
7. **如果事件与动画的 `begin` 条件匹配，例如 `BeginByLinkActivation` 被调用。**
8. **在动画的生命周期中，时间容器会定期调用 `ServiceTimeContainerUpdate` 来更新动画的状态。**
9. **在调试过程中，开发者可能会使用浏览器的开发者工具，例如 "Elements" 面板查看 SVG 元素，或者使用 "Performance" 面板分析动画的性能。** 断点可能被设置在 `SVGSMILElement` 的方法中，以便观察动画状态的变化和事件的触发。
10. **当动画状态发生变化时，例如进入激活状态或结束时，`UpdateActiveState` 和 `DispatchEvents` 等函数会被调用，开发者可以在这些地方设置断点来跟踪事件的触发和状态的更新。**

**总结 (本部分功能):**

总而言之，`SVGSMILElement.cc` 的这一部分代码是 Chromium Blink 引擎中处理 SVG SMIL 动画的核心组件，负责管理动画的时间轴、状态变化、事件分发以及与其他动画元素的同步。它确保了 SVG 动画能够按照规范正确地播放和响应用户交互，是连接 HTML 定义的动画、JavaScript 控制和最终 CSS 渲染的关键桥梁。

### 提示词
```
这是目录为blink/renderer/core/svg/animation/svg_smil_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
resentation_time =
      current_presentation_time - SMILTime::Epsilon();
  if (was_active) {
    const SMILInterval& active_interval =
        GetActiveInterval(previous_presentation_time);
    active_state_ =
        DetermineActiveState(active_interval, previous_presentation_time);
    if (GetActiveState() != kActive)
      EndedActiveInterval();
  }
  if (time_container_) {
    SMILTime next_interval_time;
    // If we switched interval and the previous interval did not end yet, we
    // need to consider it when computing the next interval time.
    if (previous_interval_.IsResolved() &&
        previous_interval_.EndsAfter(previous_presentation_time)) {
      next_interval_time = previous_interval_.end;
    } else {
      next_interval_time =
          ComputeNextIntervalTime(previous_presentation_time, kIncludeRepeats);
    }
    time_container_->Reschedule(this, next_interval_time);
  }
}

void SVGSMILElement::IntervalStateChanged() {
  if (!isConnected() || !time_container_) {
    return;
  }
  // Make the time container re-evaluate the interval.
  time_container_->Reschedule(this, SMILTime::Earliest());
  interval_needs_revalidation_ = true;
}

void SVGSMILElement::DiscardOrRevalidateCurrentInterval(
    SMILTime presentation_time) {
  if (!interval_.IsResolved())
    return;
  // If the current interval has not yet started, discard it and re-resolve.
  if (interval_.BeginsAfter(presentation_time)) {
    interval_ = SMILInterval::Unresolved();
    return;
  }

  // If we have a current interval but it has not yet ended, re-resolve the
  // end time.
  if (interval_.EndsAfter(presentation_time)) {
    SMILTime new_end = ResolveActiveEnd(interval_.begin);
    if (new_end.IsUnresolved()) {
      // No active duration, discard the current interval.
      interval_ = SMILInterval::Unresolved();
      // If we discarded the first interval, revert to waiting for the first
      // interval.
      if (!previous_interval_.IsResolved())
        is_waiting_for_first_interval_ = true;
      return;
    }
    if (new_end != interval_.end)
      SetNewIntervalEnd(new_end);
  }
}

bool SVGSMILElement::HandleIntervalRestart(SMILTime presentation_time) {
  Restart restart = GetRestart();
  if (!is_waiting_for_first_interval_ && restart == kRestartNever)
    return false;
  if (!interval_.IsResolved() || interval_.EndsBefore(presentation_time))
    return true;
  if (restart == kRestartAlways) {
    SMILTime next_begin = begin_times_.NextAfter(interval_.begin);
    if (interval_.EndsAfter(next_begin)) {
      SetNewIntervalEnd(next_begin);
      return interval_.EndsBefore(presentation_time);
    }
  }
  return false;
}

SMILTime SVGSMILElement::LastIntervalEndTime() const {
  // If we're still waiting for the first interval we lack a time reference.
  if (!is_waiting_for_first_interval_) {
    // If we have a current interval (which likely just ended or restarted) use
    // the end of that.
    if (interval_.IsResolved())
      return interval_.end;
    // If we don't have a current interval (maybe because it got discarded for
    // not having started yet) but we have a previous interval, then use the
    // end of that.
    if (previous_interval_.IsResolved())
      return previous_interval_.end;
  }
  // We have to start from the beginning.
  return SMILTime::Earliest();
}

void SVGSMILElement::UpdateInterval(SMILTime presentation_time) {
  if (instance_lists_have_changed_ || interval_needs_revalidation_) {
    instance_lists_have_changed_ = false;
    interval_needs_revalidation_ = false;
    DiscardOrRevalidateCurrentInterval(presentation_time);
  }
  if (!HandleIntervalRestart(presentation_time))
    return;
  SMILTime begin_after = LastIntervalEndTime();
  SMILInterval next_interval = ResolveInterval(begin_after, presentation_time);
  // It's the same interval that we resolved before. Do nothing.
  if (next_interval == interval_)
    return;
  interval_has_changed_ = true;
  if (interval_.IsResolved())
    previous_interval_ = interval_;
  // If there are no more intervals to resolve, we have to wait for an event to
  // occur in order to get a new instance time.
  if (!next_interval.IsResolved()) {
    interval_ = next_interval;
    return;
  }
  SetNewInterval(next_interval);
}

void SVGSMILElement::AddedToTimeContainer() {
  DCHECK(time_container_);
  SMILTime current_presentation_time =
      time_container_->LatestUpdatePresentationTime();
  UpdateInterval(current_presentation_time);
  // Check active state and reschedule using the time just before the current
  // presentation time. This means that the next animation update will take
  // care of updating the active state and send events as needed.
  SMILTime previous_presentation_time =
      current_presentation_time - SMILTime::Epsilon();
  active_state_ = DetermineActiveState(interval_, previous_presentation_time);
  time_container_->Reschedule(
      this,
      ComputeNextIntervalTime(previous_presentation_time, kIncludeRepeats));

  // If there's an active interval, then revalidate the animation value.
  if (GetActiveState() != kInactive) {
    StartedActiveInterval();
    // Dispatch a 'beginEvent' if the timeline has started and the interval is
    // active.
    if (GetActiveState() == kActive && time_container_->IsStarted()) {
      DispatchEvents(kDispatchBeginEvent);
    }
  }
}

void SVGSMILElement::RemovedFromTimeContainer() {
  DCHECK(time_container_);
  // If the element is active reset to a clear state.
  if (GetActiveState() != kInactive) {
    EndedActiveInterval();
    // Dispatch a 'endEvent' if the timeline has started and the interval is
    // (was) active.
    if (GetActiveState() == kActive && time_container_->IsStarted()) {
      DispatchEvents(kDispatchEndEvent);
    }
  }
}

const SMILInterval& SVGSMILElement::GetActiveInterval(SMILTime elapsed) const {
  // If there's no current interval, return the previous interval.
  if (!interval_.IsResolved())
    return previous_interval_;
  // If there's a previous interval and the current interval hasn't begun yet,
  // return the previous interval.
  if (previous_interval_.IsResolved() && interval_.BeginsAfter(elapsed))
    return previous_interval_;
  return interval_;
}

SVGSMILElement::ProgressState SVGSMILElement::CalculateProgressState(
    SMILTime presentation_time) const {
  const SMILTime simple_duration = SimpleDuration();
  if (simple_duration.IsIndefinite())
    return {0.0f, 0};
  if (!simple_duration)
    return {1.0f, 0};
  DCHECK(simple_duration.IsFinite());
  const SMILInterval& active_interval = GetActiveInterval(presentation_time);
  DCHECK(active_interval.IsResolved());
  const SMILTime active_time = presentation_time - active_interval.begin;
  const SMILTime repeating_duration = RepeatingDuration();
  int64_t repeat;
  SMILTime simple_time;
  if (presentation_time >= active_interval.end ||
      active_time > repeating_duration) {
    // Use the interval to compute the interval position if we've passed the
    // interval end, otherwise use the "repeating duration". This prevents a
    // stale interval (with for instance an 'indefinite' end) from yielding an
    // invalid interval position.
    SMILTime last_active_duration =
        presentation_time >= active_interval.end
            ? active_interval.end - active_interval.begin
            : repeating_duration;
    if (!last_active_duration.IsFinite())
      return {0.0f, 0};
    // If the repeat duration is a multiple of the simple duration, we should
    // use a progress value of 1.0, otherwise we should return a value that is
    // within the interval (< 1.0), so subtract the smallest representable time
    // delta in that case.
    repeat = last_active_duration.IntDiv(simple_duration);
    simple_time = last_active_duration % simple_duration;
    if (simple_time) {
      simple_time = simple_time - SMILTime::Epsilon();
    } else {
      simple_time = simple_duration;
      --repeat;
    }
  } else {
    repeat = active_time.IntDiv(simple_duration);
    simple_time = active_time % simple_duration;
  }
  return {ClampTo<float>(simple_time.InternalValueAsDouble() /
                         simple_duration.InternalValueAsDouble()),
          ClampTo<unsigned>(repeat)};
}

SMILTime SVGSMILElement::NextProgressTime(SMILTime presentation_time) const {
  if (GetActiveState() == kActive) {
    // If duration is indefinite the value does not actually change over time.
    // Same is true for <set>.
    SMILTime simple_duration = SimpleDuration();
    if (simple_duration.IsIndefinite() || IsA<SVGSetElement>(*this)) {
      SMILTime repeating_duration_end = interval_.begin + RepeatingDuration();
      // We are supposed to do freeze semantics when repeating ends, even if the
      // element is still active.
      // Take care that we get a timer callback at that point.
      if (presentation_time < repeating_duration_end &&
          interval_.EndsAfter(repeating_duration_end) &&
          repeating_duration_end.IsFinite())
        return repeating_duration_end;
      return interval_.end;
    }
    return presentation_time;
  }
  return interval_.begin >= presentation_time ? interval_.begin
                                              : SMILTime::Unresolved();
}

SVGSMILElement::ActiveState SVGSMILElement::DetermineActiveState(
    const SMILInterval& interval,
    SMILTime elapsed) const {
  if (interval.Contains(elapsed))
    return kActive;
  if (is_waiting_for_first_interval_)
    return kInactive;
  return Fill() == kFillFreeze ? kFrozen : kInactive;
}

bool SVGSMILElement::IsContributing(SMILTime elapsed) const {
  // Animation does not contribute during the active time if it is past its
  // repeating duration and has fill=remove.
  return (GetActiveState() == kActive &&
          (Fill() == kFillFreeze ||
           elapsed <= interval_.begin + RepeatingDuration())) ||
         GetActiveState() == kFrozen;
}

SVGSMILElement::EventDispatchMask SVGSMILElement::UpdateActiveState(
    SMILTime presentation_time,
    bool skip_repeat) {
  const bool was_active = GetActiveState() == kActive;
  active_state_ = DetermineActiveState(interval_, presentation_time);
  const bool is_active = GetActiveState() == kActive;
  const bool interval_restart =
      interval_has_changed_ && previous_interval_.end == interval_.begin;
  interval_has_changed_ = false;

  unsigned events_to_dispatch = kDispatchNoEvent;
  if ((was_active && !is_active) || interval_restart) {
    events_to_dispatch |= kDispatchEndEvent;
    EndedActiveInterval();
  }

  if (IsContributing(presentation_time)) {
    if ((!was_active && is_active) || interval_restart) {
      events_to_dispatch |= kDispatchBeginEvent;
      StartedActiveInterval();
    }

    if (!skip_repeat) {
      // TODO(fs): This is a bit fragile. Convert to be time-based (rather than
      // based on |last_progress_|) and thus (at least more) idempotent.
      ProgressState progress_state = CalculateProgressState(presentation_time);
      if (progress_state.repeat &&
          progress_state.repeat != last_progress_.repeat) {
        NotifyDependentsOnRepeat(progress_state.repeat, presentation_time);
        events_to_dispatch |= kDispatchRepeatEvent;
      }
      last_progress_ = progress_state;
    }
  }
  return static_cast<EventDispatchMask>(events_to_dispatch);
}

SVGSMILElement::EventDispatchMask SVGSMILElement::ComputeSeekEvents(
    const SMILInterval& starting_interval) const {
  // Is the element active at the seeked-to time?
  if (GetActiveState() != SVGSMILElement::kActive) {
    // Was the element active at the previous time?
    if (!starting_interval.IsResolved())
      return kDispatchNoEvent;
    // Dispatch an 'endEvent' for ending |starting_interval|.
    return kDispatchEndEvent;
  }
  // Was the element active at the previous time?
  if (starting_interval.IsResolved()) {
    // The same interval?
    if (interval_ == starting_interval)
      return kDispatchNoEvent;
    // Dispatch an 'endEvent' for ending |starting_interval| and a 'beginEvent'
    // for beginning the current interval.
    unsigned to_dispatch = kDispatchBeginEvent | kDispatchEndEvent;
    return static_cast<EventDispatchMask>(to_dispatch);
  }
  // Was not active at the previous time. Dispatch a 'beginEvent' for beginning
  // the current interval.
  return kDispatchBeginEvent;
}

void SVGSMILElement::DispatchEvents(EventDispatchMask events_to_dispatch) {
  // The ordering is based on the usual order in which these events should be
  // dispatched (and should match the order the flags are set in
  // UpdateActiveState().
  if (events_to_dispatch & kDispatchEndEvent) {
    EnqueueEvent(*Event::Create(event_type_names::kEndEvent),
                 TaskType::kDOMManipulation);
  }
  if (events_to_dispatch & kDispatchBeginEvent) {
    EnqueueEvent(*Event::Create(event_type_names::kBeginEvent),
                 TaskType::kDOMManipulation);
  }
  if (events_to_dispatch & kDispatchRepeatEvent) {
    EnqueueEvent(*Event::Create(event_type_names::kRepeatEvent),
                 TaskType::kDOMManipulation);
    EnqueueEvent(*Event::Create(AtomicString("repeatn")),
                 TaskType::kDOMManipulation);
  }
}

void SVGSMILElement::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  SVGElement::AddedEventListener(event_type, registered_listener);
  if (event_type == "repeatn") {
    UseCounter::Count(GetDocument(),
                      WebFeature::kSMILElementHasRepeatNEventListener);
  }
}

void SVGSMILElement::UpdateProgressState(SMILTime presentation_time) {
  last_progress_ = CalculateProgressState(presentation_time);
}

struct SVGSMILElement::NotifyDependentsInfo {
  explicit NotifyDependentsInfo(const SMILInterval& interval)
      : origin(SMILTimeOrigin::kSyncBase),
        repeat_nr(0),
        begin(interval.begin),
        end(interval.end) {}
  NotifyDependentsInfo(unsigned repeat_nr, SMILTime repeat_time)
      : origin(SMILTimeOrigin::kRepeat),
        repeat_nr(repeat_nr),
        begin(repeat_time),
        end(SMILTime::Unresolved()) {}

  SMILTimeOrigin origin;
  unsigned repeat_nr;
  SMILTime begin;  // repeat time if origin == kRepeat
  SMILTime end;
};

void SVGSMILElement::NotifyDependentsOnNewInterval(
    const SMILInterval& interval) {
  DCHECK(interval.IsResolved());
  NotifyDependents(NotifyDependentsInfo(interval));
}

void SVGSMILElement::NotifyDependentsOnRepeat(unsigned repeat_nr,
                                              SMILTime repeat_time) {
  DCHECK(repeat_nr);
  DCHECK(repeat_time.IsFinite());
  NotifyDependents(NotifyDependentsInfo(repeat_nr, repeat_time));
}

void SVGSMILElement::NotifyDependents(const NotifyDependentsInfo& info) {
  // Avoid infinite recursion which may be caused by:
  // |NotifyDependents| -> |CreateInstanceTimesFromSyncBase| ->
  // |AddInstanceTime| -> |InstanceListChanged| -> |NotifyDependents|
  if (is_notifying_dependents_)
    return;
  base::AutoReset<bool> reentrancy_guard(&is_notifying_dependents_, true);
  for (SVGSMILElement* element : sync_base_dependents_)
    element->CreateInstanceTimesFromSyncBase(this, info);
}

void SVGSMILElement::CreateInstanceTimesFromSyncBase(
    SVGSMILElement* timed_element,
    const NotifyDependentsInfo& info) {
  // FIXME: To be really correct, this should handle updating exising interval
  // by changing the associated times instead of creating new ones.
  for (Condition* condition : conditions_) {
    if (!condition->IsSyncBaseFor(timed_element))
      continue;
    // TODO(edvardt): This is a lot of string compares, which is slow, it
    // might be a good idea to change it for an enum and maybe make Condition
    // into a union?
    DCHECK(condition->GetName() == "begin" || condition->GetName() == "end" ||
           condition->GetName() == "repeat");

    // No nested time containers in SVG, no need for crazy time space
    // conversions. Phew!
    SMILTime time = SMILTime::Unresolved();
    if (info.origin == SMILTimeOrigin::kSyncBase) {
      if (condition->GetName() == "begin") {
        time = info.begin + condition->Offset();
      } else if (condition->GetName() == "end") {
        time = info.end + condition->Offset();
      }
    } else {
      DCHECK_EQ(info.origin, SMILTimeOrigin::kRepeat);
      if (info.repeat_nr != condition->Repeat())
        continue;
      time = info.begin + condition->Offset();
    }
    if (!time.IsFinite())
      continue;
    AddInstanceTime(condition->GetBeginOrEnd(), time, info.origin);
  }

  // No instance times were added.
  if (!instance_lists_have_changed_)
    return;

  // We're currently sending notifications for, and thus updating, this element
  // so let that update handle the new instance times.
  if (is_notifying_dependents_)
    return;

  InstanceListChanged();
}

void SVGSMILElement::AddSyncBaseDependent(SVGSMILElement& animation) {
  sync_base_dependents_.insert(&animation);
  if (!interval_.IsResolved())
    return;
  animation.CreateInstanceTimesFromSyncBase(this,
                                            NotifyDependentsInfo(interval_));
}

void SVGSMILElement::RemoveSyncBaseDependent(SVGSMILElement& animation) {
  sync_base_dependents_.erase(&animation);
}

void SVGSMILElement::BeginByLinkActivation() {
  AddInstanceTimeAndUpdate(kBegin, Elapsed(), SMILTimeOrigin::kLinkActivation);
}

void SVGSMILElement::StartedActiveInterval() {
  is_waiting_for_first_interval_ = false;
}

void SVGSMILElement::EndedActiveInterval() {
  begin_times_.RemoveWithOrigin(SMILTimeOrigin::kScript);
  end_times_.RemoveWithOrigin(SMILTimeOrigin::kScript);
}

bool SVGSMILElement::HasValidTarget() const {
  return targetElement() && targetElement()->InActiveDocument();
}

void SVGSMILElement::WillChangeAnimationTarget() {
  if (!is_scheduled_)
    return;
  DCHECK(time_container_);
  DCHECK(target_element_);
  time_container_->Unschedule(this);
  RemovedFromTimeContainer();
  is_scheduled_ = false;
}

void SVGSMILElement::DidChangeAnimationTarget() {
  DCHECK(!is_scheduled_);
  if (!time_container_ || !HasValidTarget())
    return;
  time_container_->Schedule(this);
  AddedToTimeContainer();
  is_scheduled_ = true;
}

void SVGSMILElement::Trace(Visitor* visitor) const {
  visitor->Trace(target_element_);
  visitor->Trace(target_id_observer_);
  visitor->Trace(time_container_);
  visitor->Trace(conditions_);
  visitor->Trace(sync_base_dependents_);
  SVGElement::Trace(visitor);
  SVGTests::Trace(visitor);
}

}  // namespace blink
```