Response:
My thinking process to answer the request about `animation.cc` goes through these stages:

1. **Understanding the Core Request:** The user wants to understand the *functionality* of the `animation.cc` file in the Chromium Blink engine, specifically within the context of web animations (JavaScript, HTML, CSS). They also want examples, logical reasoning, common errors, and a summary. Crucially, this is part 3 of a 5-part series, so the answer should focus on the functionality evident in the provided code snippet.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the provided code, looking for prominent keywords and method names. This helps me get a high-level idea of what the code does. I see things like:

    * `play`, `pause`, `reverse`, `finish` - These clearly relate to controlling animation playback.
    * `startTime`, `holdTime`, `currentTime`, `playbackRate` - These are fundamental properties of an animation.
    * `pendingPlay`, `pendingPause`, `pendingPlaybackRate` -  These suggest handling asynchronous or delayed actions.
    * `readyPromise`, `finishedPromise` -  These indicate the use of Promises for managing asynchronous animation lifecycle events.
    * `UpdateFinishedState`, `CommitFinishNotification` - Focus on determining and signaling when an animation is done.
    * `CompositorPending` - Hints at interaction with the compositor thread for potentially hardware-accelerated animations.
    * `ExceptionState` -  Error handling.

3. **Grouping Functionality:** Based on the keywords and method names, I start grouping related pieces of code into functional areas. For example:

    * **Playback Control:** `play`, `pause`, `reverse`, `finish`. These manipulate the animation's state and time.
    * **Time Management:**  Setting and getting `startTime`, `holdTime`, `currentTime`. Calculating and updating these values.
    * **State Management:**  Tracking the animation's current state (playing, paused, finished, idle, pending). Using flags like `pending_play_`, `pending_pause_`, `finished_`.
    * **Asynchronous Operations:**  Using Promises (`readyPromise`, `finishedPromise`) and microtasks to handle events like "ready" and "finished".
    * **Playback Rate Control:** `updatePlaybackRate`, `setPlaybackRate`, `ApplyPendingPlaybackRate`.
    * **Compositor Integration:**  Functions and flags related to `CompositorPending`, checking if an animation can run on the compositor, and starting/canceling animations on the compositor.
    * **Error Handling:**  Using `ExceptionState` to throw errors for invalid operations.

4. **Connecting to Web Standards:**  I recognize the method names and concepts align with the Web Animations API. I explicitly mention this and provide links to the relevant W3C specifications where possible (though the prompt only provides a code snippet, in a real scenario, I'd research the specific spec sections mentioned in the comments). This helps contextualize the code within the broader web development ecosystem.

5. **Generating Examples:** For each functional area, I think about how it relates to JavaScript, HTML, and CSS. This involves imagining the corresponding JavaScript code that would call these C++ methods and the CSS properties that the animations would affect.

    * **JavaScript:** Using methods like `animation.play()`, `animation.pause()`, setting `animation.playbackRate`, and using the `finished` and `ready` promises.
    * **HTML:**  The animations are applied to HTML elements.
    * **CSS:** The `animation-*` properties in CSS trigger the creation of these `Animation` objects in the underlying engine. Keyframe rules define the animation's behavior.

6. **Logical Reasoning (Hypothetical Inputs and Outputs):**  For critical functions, I construct simple scenarios with inputs and expected outputs. This demonstrates how the code might behave under specific conditions. For example, calling `play()` on a paused animation should transition it to the playing state.

7. **Identifying User Errors:** I consider common mistakes developers might make when using web animations and link them back to the C++ code's behavior. For instance, trying to reverse an animation without an active timeline will throw an error, which is reflected in the `reverse()` function. Setting an invalid playback rate is another example.

8. **Summarizing the Functionality (Part 3 Focus):**  Given that this is part 3, I specifically focus on the features highlighted in the provided code. This means emphasizing the playback control, time management, state management, asynchronous operations (Promises), and the initial stages of compositor interaction. I avoid going into detail about aspects not covered in the snippet.

9. **Structuring the Answer:** I organize the information logically using headings and bullet points to make it easy to read and understand. I start with a general overview, then delve into specific functionalities, providing examples and explanations.

10. **Refinement and Review:**  I review my answer to ensure accuracy, clarity, and completeness, relative to the provided code snippet and the user's request. I double-check for any inconsistencies or areas where more explanation might be needed. I make sure the language is accessible to someone familiar with web development concepts.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative answer that addresses all aspects of the user's request. The focus on relating the C++ code to the visible web technologies (JavaScript, HTML, CSS) is crucial for making the explanation relevant to web developers.
这是对 `blink/renderer/core/animation/animation.cc` 文件功能的归纳总结，基于提供的第三部分代码片段。

**核心功能归纳 (基于第三部分代码):**

这部分代码主要负责实现 `Animation` 对象的生命周期管理和状态控制，特别是与动画的播放、暂停、反向、完成以及与 Compositor 的交互相关的逻辑。  它处理了 Web Animations API 中关于动画控制的关键方法。

**具体功能点:**

* **播放控制 (Play):**  实现了 `play()` 方法的内部逻辑 (`PlayInternal`)，用于启动或恢复动画播放。
    *  处理 `auto-rewind` 标志，决定是否在播放时重置动画的起始时间。
    *  管理动画的 `hold_time_` 和 `start_time_`，根据不同的条件进行设置或清除。
    *  处理待处理的播放和暂停任务，以及相关的 Promise。
    *  在动画准备就绪时调度任务。
    *  更新动画的完成状态。
* **反向播放 (Reverse):** 实现了 `reverse()` 方法，用于反向播放动画。
    *  检查动画是否关联了有效的 Timeline。
    *  计算并设置待处理的播放速率为当前有效播放速率的负值。
    *  调用 `PlayInternal` 方法启动反向播放。
* **完成动画 (Finish):** 实现了 `finish()` 方法，用于立即将动画设置为完成状态。
    *  检查播放速率是否为 0 以及目标效果的结束时间是否为无限。
    *  计算并设置动画的内部当前时间到开始或结束。
    *  如果动画处于待处理的暂停或播放状态，则解析相关的 Promise。
    *  更新动画的完成状态。
* **更新完成状态 (UpdateFinishedState):**  负责计算和更新动画的完成状态。
    *  考虑动画是否处于 seek 状态 (`UpdateType::kDiscontinuous`)。
    *  根据当前时间和播放速率，更新 `hold_time_`。
    *  计算动画的播放状态，如果动画完成，则安排完成通知。
* **异步完成通知 (ScheduleAsyncFinish, AsyncFinishMicrotask, CommitFinishNotification):**  处理动画完成时的异步通知机制，包括解析 `finished` Promise 和触发 `finish` 事件。
    *  使用微任务队列来异步处理完成通知。
    *  确保在解析 `finished` Promise 之前，待处理的播放或暂停任务已完成。
* **更新播放速率 (updatePlaybackRate):**  实现了 `updatePlaybackRate()` 方法，用于改变动画的播放速率。
    *  处理待处理的播放和暂停任务。
    *  根据动画的当前状态 (idle, paused, finished, running) 执行不同的逻辑来更新播放速率。
    *  在 `finished` 状态下，会重新计算动画的 `start_time_`。
    *  在 `running` 状态下，会调用 `PlayInternal`。
* **获取 Promise (finished, ready):**  提供了 `finished()` 和 `ready()` 方法来获取与动画完成和就绪状态相关的 Promise。
* **与 Compositor 的交互:**  包含一些与 Compositor 相关的逻辑，用于判断动画是否可以在 Compositor 上运行，以及启动或取消 Compositor 上的动画。
    *  `CheckCanStartAnimationOnCompositor`: 检查动画是否满足在 Compositor 上运行的条件。
    *  `StartAnimationOnCompositor`: 将动画启动到 Compositor 上。
    *  `SetCompositorPending`:  标记动画需要与 Compositor 进行同步更新或执行操作。
    *  `CancelAnimationOnCompositor`: 取消 Compositor 上的动画。
    *  `ComputeCompositorTimeOffset`: 计算 Compositor 需要的时间偏移量。
    *  `MarkPendingIfCompositorPropertyAnimationChanges`:  检查 Compositor 属性动画是否发生变化。
* **其他辅助功能:**
    *  `SetOutdated`, `ClearOutdated`:  管理动画的过期状态，用于触发重绘或重新计算。
    *  `ForceServiceOnNextFrame`: 强制在下一帧服务动画。
    *  `ApplyPendingPlaybackRate`:  应用待处理的播放速率。
    *  `EffectivePlaybackRate`: 获取当前的有效播放速率（包括待处理的）。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件是 Web Animations API 的底层实现，它直接响应 JavaScript 中对 `Animation` 对象的操作，并最终影响浏览器渲染 HTML 和 CSS 的效果。

**举例说明:**

* **JavaScript `animation.play()`:**  当 JavaScript 调用 `animation.play()` 时，会最终调用到 `animation.cc` 中的 `PlayInternal` 方法，该方法会更新动画的状态，使其开始播放。
    * **假设输入:**  一个 `Animation` 对象处于暂停状态，JavaScript 调用了 `animation.play()`。
    * **输出:**  `Animation` 对象的内部状态会更新为播放中，相关的 Promise 会被管理，并可能触发 Compositor 上的动画启动。

* **JavaScript `animation.reverse()`:**  JavaScript 调用 `animation.reverse()` 会触发 `animation.cc` 中的 `reverse()` 方法，该方法会改变动画的播放速率，并重新启动播放，实现反向播放的效果。
    * **假设输入:** 一个播放速率为正的 `Animation` 对象，JavaScript 调用了 `animation.reverse()`。
    * **输出:** `Animation` 对象的待处理播放速率会变为负值，并调用 `PlayInternal` 重新启动动画。

* **CSS `animation-*` 属性:**  CSS 动画属性 (例如 `animation-name`, `animation-duration`) 会在渲染引擎中创建对应的 `Animation` 对象。这个文件中的代码会管理这些动画对象的生命周期和状态。

* **JavaScript `animation.finished` Promise:**  当 JavaScript 使用 `animation.finished` 获取 Promise 时，`animation.cc` 中的 `finished()` 方法会返回一个 Promise 对象。当动画完成时，`CommitFinishNotification` 会解析这个 Promise，通知 JavaScript 动画已完成。
    * **假设输入:**  一个正在播放且即将完成的 `Animation` 对象，JavaScript 中有 `animation.finished.then(...)` 的代码。
    * **输出:**  当动画到达终点时，`finished` Promise 会被解析，触发 `.then(...)` 中的回调函数。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个 `Animation` 对象，当前时间为 T，播放速率为 1，持续时间为 D。JavaScript 调用 `animation.finish()`。
* **输出:**  `Animation` 对象的内部当前时间会被设置为 D，完成状态会被标记为 true，相关的 `finished` Promise 会被解析，并且会触发 `finish` 事件。

**用户或编程常见的使用错误:**

* **在没有激活的 Timeline 的情况下调用 `reverse()`:**  这会导致抛出一个 "InvalidStateError" DOMException，如 `reverse()` 方法的开头检查所示。
    * **例子:**  JavaScript 代码尝试在一个尚未添加到文档或其关联的 Timeline 处于非激活状态的动画上调用 `reverse()`。

* **在播放速率为 0 的情况下调用 `finish()`:**  这也会抛出一个 "InvalidStateError" DOMException，在 `finish()` 方法中进行了检查。
    * **例子:**  JavaScript 代码先将动画的 `playbackRate` 设置为 0，然后尝试调用 `finish()`。

* **尝试完成一个无限持续时间的动画 (正向播放):**  这也会抛出一个 "InvalidStateError" DOMException。
    * **例子:**  CSS 定义了一个 `animation-duration: infinite` 的动画，然后 JavaScript 尝试调用 `finish()`。

**总结 (基于第三部分):**

`animation.cc` 文件的这部分主要负责实现 Web Animations API 中 `Animation` 对象的关键控制方法，包括播放、暂停、反向、完成以及播放速率的更新。它管理着动画的状态、时间和与 Promise 相关的异步操作。 此外，它还处理了与 Compositor 相关的交互，以便将动画卸载到 GPU 上进行硬件加速渲染。  这部分代码是连接 JavaScript 动画操作和底层渲染机制的关键桥梁。

### 提示词
```
这是目录为blink/renderer/core/animation/animation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
imeline is true,
  //          * Set animation’s start time to seek time.
  //          * Let animation’s hold time be unresolved.
  //          * Apply any pending playback rate on animation.
  //      * Otherwise,
  //          * Set animation’s hold time to seek time.
  //
  // TODO(kevers): Replace seek time with hold time, and remove this block
  // entirely from the spec. We should not use a seek time with a scroll-driven
  // animation.

  // TODO(Kevers): Add steps the the spec for setting flags for scroll-driven
  // animations.

  // Note: An explicit call to play a scroll-driven animation resets any
  // stickiness in the start time of the animation, re-enabling auto-alignment
  // of the start time to the beginning or end of the animation range depending
  // on the playback rate. A flag is set to indicate that a new start time is
  // required. A play pending animation will be locked in that state until a new
  // start time is set in OnValidateSnapshot even if the animation already has a
  // start time.
  if (has_finite_timeline && auto_rewind == AutoRewind::kEnabled) {
    auto_align_start_time_ = true;
    hold_time_ = CurrentTimeInternal();
  }

  // 9. If animation’s hold time is resolved, let its start time be unresolved.

  // Note: The combination of a start time and a hold time is only permitted
  // when in the finished state. If the hold time is set, we clear the start
  // time. The finished state will be re-evaluated on the next update.
  if (hold_time_) {
    start_time_ = std::nullopt;
  }

  // 10. If animation has a pending play task or a pending pause task,
  if (pending_play_ || pending_pause_) {
    pending_play_ = false;
    pending_pause_ = false;
    has_pending_ready_promise = true;
  }

  // 11. If the following four conditions are all satisfied:
  //       * animation’s hold time is unresolved, and
  //       * seek time is unresolved, and
  //       * aborted pause is false, and
  //       * animation does not have a pending playback rate,
  //     abort this procedure.
  //
  // TODO(kevers): add an extra condition to prevent aborting if playing a
  // scroll-driven animation, which defers calculation of the start time.
  //
  // Note: If the animation is already running and there will be no change to
  // the start time or playback rate, then we can abort early as there is no
  // need for a ready promise. The remaining steps are for setting up and
  // resolving the ready promise.
  if (!hold_time_ && !seek_time && !has_finite_timeline && !aborted_pause &&
      !pending_playback_rate_) {
    return;
  }

  // 12. If has pending ready promise is false, let animation’s current ready
  //     promise be a new promise in the relevant Realm of animation.
  if (ready_promise_ && !has_pending_ready_promise) {
    ready_promise_->Reset();
  }

  // 13. Schedule a task to run as soon as animation is ready.
  pending_play_ = true;

  // Blink specific implementation details.
  finished_ = false;
  committed_finish_notification_ = false;
  SetOutdated();
  SetCompositorPending(CompositorPendingReason::kPendingUpdate);

  // Update an animation’s finished state. As the finished state may be
  // transient, we defer resolving the finished promise until the next
  // microtask checkpoint. Even if seeking, the update type is "continuous"
  // to avoid altering the hold time if set.
  UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);

  // Notify change to pending play or finished state.
  NotifyProbe();
}

// https://www.w3.org/TR/web-animations-1/#reversing-an-animation-section
void Animation::reverse(ExceptionState& exception_state) {
  // 1. If there is no timeline associated with animation, or the associated
  //    timeline is inactive throw an "InvalidStateError" DOMException and abort
  //    these steps.
  if (!timeline_ || !timeline_->IsActive()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot reverse an animation with no active timeline");
    return;
  }

  // 2. Let original pending playback rate be animation’s pending playback rate.
  // 3. Let animation’s pending playback rate be the additive inverse of its
  //    effective playback rate (i.e. -effective playback rate).
  std::optional<double> original_pending_playback_rate = pending_playback_rate_;
  pending_playback_rate_ = -EffectivePlaybackRate();

  // Resolve precision issue at zero.
  if (pending_playback_rate_.value() == -0)
    pending_playback_rate_ = 0;

  // 4. Run the steps to play an animation for animation with the auto-rewind
  //    flag set to true.
  //    If the steps to play an animation throw an exception, set animation’s
  //    pending playback rate to original pending playback rate and propagate
  //    the exception.
  PlayInternal(AutoRewind::kEnabled, exception_state);
  if (exception_state.HadException())
    pending_playback_rate_ = original_pending_playback_rate;
}

// ----------------------------------------------
// Finish methods.
// ----------------------------------------------

// https://www.w3.org/TR/web-animations-1/#finishing-an-animation-section
void Animation::finish(ExceptionState& exception_state) {
  if (!EffectivePlaybackRate()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot finish Animation with a playbackRate of 0.");
    return;
  }
  if (EffectivePlaybackRate() > 0 && EffectEnd().is_inf()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot finish Animation with an infinite target effect end.");
    return;
  }

  auto_align_start_time_ = false;

  ApplyPendingPlaybackRate();

  AnimationTimeDelta new_current_time =
      playback_rate_ < 0 ? AnimationTimeDelta() : EffectEnd();
  SetCurrentTimeInternal(new_current_time);

  if (!start_time_ && timeline_ && timeline_->IsActive())
    start_time_ = CalculateStartTime(new_current_time);

  if (pending_pause_ && start_time_) {
    hold_time_ = std::nullopt;
    pending_pause_ = false;
    if (ready_promise_)
      ResolvePromiseMaybeAsync(ready_promise_.Get());
  }
  if (pending_play_ && start_time_) {
    pending_play_ = false;
    if (ready_promise_)
      ResolvePromiseMaybeAsync(ready_promise_.Get());
  }

  SetOutdated();
  UpdateFinishedState(UpdateType::kDiscontinuous, NotificationType::kSync);

  // Notify of change to finished state.
  NotifyProbe();
}

void Animation::UpdateFinishedState(UpdateType update_type,
                                    NotificationType notification_type) {
  // TODO(kevers): Add a new step to the spec.
  // Clear finished state and abort the procedure if play-pending and waiting
  // for a new start time.
  if (timeline_ && timeline_->IsScrollTimeline() && pending_play_ &&
      auto_align_start_time_) {
    finished_ = false;
    pending_finish_notification_ = false;
    committed_finish_notification_ = false;
    return;
  }

  bool did_seek = update_type == UpdateType::kDiscontinuous;
  // 1. Calculate the unconstrained current time. The dependency on did_seek is
  // required to accommodate timelines that may change direction. Without this
  // distinction, a once-finished animation would remain finished even when its
  // timeline progresses in the opposite direction.
  std::optional<AnimationTimeDelta> unconstrained_current_time =
      did_seek ? CurrentTimeInternal() : CalculateCurrentTime();

  // 2. Conditionally update the hold time.
  if (unconstrained_current_time && start_time_ && !pending_play_ &&
      !pending_pause_) {
    // Can seek outside the bounds of the active effect. Set the hold time to
    // the unconstrained value of the current time in the event that this update
    // is the result of explicitly setting the current time and the new time
    // is out of bounds. An update due to a time tick should not snap the hold
    // value back to the boundary if previously set outside the normal effect
    // boundary. The value of previous current time is used to retain this
    // value.
    double playback_rate = EffectivePlaybackRate();
    std::optional<AnimationTimeDelta> hold_time;

    if (playback_rate > 0 &&
        GreaterThanOrEqualWithinTimeTolerance(
            unconstrained_current_time.value(), EffectEnd())) {
      if (did_seek) {
        hold_time = unconstrained_current_time;
      } else {
        if (previous_current_time_ > EffectEnd()) {
          hold_time = previous_current_time_;
        } else {
          hold_time = EffectEnd();
        }
      }
      hold_time_ = hold_time;
    } else if (playback_rate < 0 &&
               unconstrained_current_time.value() <= AnimationTimeDelta()) {
      if (did_seek) {
        hold_time = unconstrained_current_time;
      } else {
        if (previous_current_time_ <= AnimationTimeDelta()) {
          hold_time = previous_current_time_;
        } else {
          hold_time = AnimationTimeDelta();
        }
      }

      // Hack for resolving precision issue at zero.
      if (hold_time.has_value() &&
          TimingCalculations::IsWithinAnimationTimeEpsilon(
              hold_time.value().InSecondsF(), -0)) {
        hold_time = AnimationTimeDelta();
      }

      hold_time_ = hold_time;
    } else if (playback_rate != 0) {
      // Update start time and reset hold time.
      if (did_seek && hold_time_)
        start_time_ = CalculateStartTime(hold_time_.value());
      hold_time_ = std::nullopt;
    }
  }

  // 3. Set the previous current time.
  previous_current_time_ = CurrentTimeInternal();

  // 4. Set the current finished state.
  V8AnimationPlayState::Enum play_state = CalculateAnimationPlayState();
  if (play_state == V8AnimationPlayState::Enum::kFinished) {
    if (!committed_finish_notification_) {
      // 5. Setup finished notification.
      if (notification_type == NotificationType::kSync)
        CommitFinishNotification();
      else
        ScheduleAsyncFinish();
    }
  } else {
    // Previously finished animation may restart so they should be added to
    // pending animations to make sure that a compositor animation is re-created
    // during future PreCommit.
    if (finished_) {
      SetCompositorPending(CompositorPendingReason::kPendingUpdate);
    }
    // 6. If not finished but the current finished promise is already resolved,
    //    create a new promise.
    finished_ = pending_finish_notification_ = committed_finish_notification_ =
        false;
    if (finished_promise_ &&
        finished_promise_->GetState() == AnimationPromise::kResolved) {
      finished_promise_->Reset();
    }
  }
}

void Animation::ScheduleAsyncFinish() {
  auto* execution_context = GetExecutionContext();
  if (!execution_context)
    return;
  // Run a task to handle the finished promise and event as a microtask. With
  // the exception of an explicit call to Animation::finish, it is important to
  // apply these updates asynchronously as it is possible to enter the finished
  // state temporarily.
  pending_finish_notification_ = true;
  if (!has_queued_microtask_) {
    execution_context->GetAgent()->event_loop()->EnqueueMicrotask(WTF::BindOnce(
        &Animation::AsyncFinishMicrotask, WrapWeakPersistent(this)));
    has_queued_microtask_ = true;
  }
}

void Animation::AsyncFinishMicrotask() {
  // Resolve the finished promise and queue the finished event only if the
  // animation is still in a pending finished state. It is possible that the
  // transition was only temporary.
  if (pending_finish_notification_) {
    // A pending play or pause must resolve before the finish promise.
    if (PendingInternal() && timeline_)
      NotifyReady(timeline_->CurrentTime().value_or(AnimationTimeDelta()));
    CommitFinishNotification();
  }

  // This is a once callback and needs to be re-armed.
  has_queued_microtask_ = false;
}

// Refer to 'finished notification steps' in
// https://www.w3.org/TR/web-animations-1/#updating-the-finished-state
void Animation::CommitFinishNotification() {
  if (committed_finish_notification_)
    return;

  pending_finish_notification_ = false;

  // 1. If animation’s play state is not equal to finished, abort these steps.
  if (CalculateAnimationPlayState() != V8AnimationPlayState::Enum::kFinished) {
    return;
  }

  // 2. Resolve animation’s current finished promise object with animation.
  if (finished_promise_ &&
      finished_promise_->GetState() == AnimationPromise::kPending) {
    ResolvePromiseMaybeAsync(finished_promise_.Get());
  }

  // 3. Create an AnimationPlaybackEvent, finishEvent.
  QueueFinishedEvent();

  committed_finish_notification_ = true;
}

// https://www.w3.org/TR/web-animations-1/#setting-the-playback-rate-of-an-animation
void Animation::updatePlaybackRate(double playback_rate,
                                   ExceptionState& exception_state) {
  // 1. Let previous play state be animation’s play state.
  // 2. Let animation’s pending playback rate be new playback rate.
  V8AnimationPlayState::Enum play_state = CalculateAnimationPlayState();
  pending_playback_rate_ = playback_rate;

  // 3. Perform the steps corresponding to the first matching condition from
  //    below:
  //
  // 3a If animation has a pending play task or a pending pause task,
  //    Abort these steps.
  if (PendingInternal())
    return;

  switch (play_state) {
    // 3b If previous play state is idle or paused,
    //    Apply any pending playback rate on animation.
    case V8AnimationPlayState::Enum::kIdle:
    case V8AnimationPlayState::Enum::kPaused:
      ApplyPendingPlaybackRate();
      break;

    // 3c If previous play state is finished,
    //    3c.1 Let the unconstrained current time be the result of calculating
    //         the current time of animation substituting an unresolved time
    //          value for the hold time.
    //    3c.2 Let animation’s start time be the result of evaluating the
    //         following expression:
    //    timeline time - (unconstrained current time / pending playback rate)
    // Where timeline time is the current time value of the timeline associated
    // with animation.
    //    3c.3 If pending playback rate is zero, let animation’s start time be
    //         timeline time.
    //    3c.4 Apply any pending playback rate on animation.
    //    3c.5 Run the procedure to update an animation’s finished state for
    //         animation with the did seek flag set to false, and the
    //         synchronously notify flag set to false.
    case V8AnimationPlayState::Enum::kFinished: {
      std::optional<AnimationTimeDelta> unconstrained_current_time =
          CalculateCurrentTime();
      std::optional<AnimationTimeDelta> timeline_time =
          timeline_ ? timeline_->CurrentTime() : std::nullopt;
      if (playback_rate) {
        if (timeline_time) {
          start_time_ = (timeline_time && unconstrained_current_time)
                            ? std::make_optional<AnimationTimeDelta>(
                                  (timeline_time.value() -
                                   unconstrained_current_time.value()) /
                                  playback_rate)
                            : std::nullopt;
        }
      } else {
        start_time_ = timeline_time;
      }
      ApplyPendingPlaybackRate();
      UpdateFinishedState(UpdateType::kContinuous, NotificationType::kAsync);
      SetCompositorPending(CompositorPendingReason::kPendingUpdate);
      SetOutdated();
      NotifyProbe();
      break;
    }

    // 3d Otherwise,
    // Run the procedure to play an animation for animation with the
    // auto-rewind flag set to false.
    case V8AnimationPlayState::Enum::kRunning:
      PlayInternal(AutoRewind::kDisabled, exception_state);
      break;

    case V8AnimationPlayState::Enum::kPending:
      NOTREACHED();
  }
}

ScriptPromise<Animation> Animation::finished(ScriptState* script_state) {
  if (!finished_promise_) {
    finished_promise_ = MakeGarbageCollected<AnimationPromise>(
        ExecutionContext::From(script_state));
    // Do not report unhandled rejections of the finished promise.
    finished_promise_->MarkAsHandled();

    // Defer resolving the finished promise if the finish notification task is
    // pending. The finished state could change before the next microtask
    // checkpoint.
    if (CalculateAnimationPlayState() ==
            V8AnimationPlayState::Enum::kFinished &&
        !pending_finish_notification_) {
      finished_promise_->Resolve(this);
    }
  }
  return finished_promise_->Promise(script_state->World());
}

ScriptPromise<Animation> Animation::ready(ScriptState* script_state) {
  // Check for a pending state change prior to checking the ready promise, since
  // the pending check may force a style flush, which in turn could trigger a
  // reset of the ready promise when resolving a change to the
  // animationPlayState style.
  bool is_pending = pending();
  if (!ready_promise_) {
    ready_promise_ = MakeGarbageCollected<AnimationPromise>(
        ExecutionContext::From(script_state));
    // Do not report unhandled rejections of the ready promise.
    ready_promise_->MarkAsHandled();
    if (!is_pending)
      ready_promise_->Resolve(this);
  }
  return ready_promise_->Promise(script_state->World());
}

const AtomicString& Animation::InterfaceName() const {
  return event_target_names::kAnimation;
}

ExecutionContext* Animation::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

bool Animation::HasPendingActivity() const {
  bool has_pending_promise =
      finished_promise_ &&
      finished_promise_->GetState() == AnimationPromise::kPending;

  return pending_finished_event_ || pending_cancelled_event_ ||
         pending_remove_event_ || has_pending_promise ||
         (!finished_ && HasEventListeners(event_type_names::kFinish));
}

void Animation::ContextDestroyed() {
  finished_ = true;
  pending_finished_event_ = nullptr;
  pending_cancelled_event_ = nullptr;
  pending_remove_event_ = nullptr;
}

DispatchEventResult Animation::DispatchEventInternal(Event& event) {
  if (pending_finished_event_ == &event)
    pending_finished_event_ = nullptr;
  if (pending_cancelled_event_ == &event)
    pending_cancelled_event_ = nullptr;
  if (pending_remove_event_ == &event)
    pending_remove_event_ = nullptr;
  return EventTarget::DispatchEventInternal(event);
}

double Animation::playbackRate() const {
  return playback_rate_;
}

double Animation::EffectivePlaybackRate() const {
  return pending_playback_rate_.value_or(playback_rate_);
}

void Animation::ApplyPendingPlaybackRate() {
  if (pending_playback_rate_) {
    playback_rate_ = pending_playback_rate_.value();
    pending_playback_rate_ = std::nullopt;
    InvalidateNormalizedTiming();
  }
}

void Animation::setPlaybackRate(double playback_rate,
                                ExceptionState& exception_state) {
  std::optional<AnimationTimeDelta> start_time_before = start_time_;

  // 1. Clear any pending playback rate on animation.
  // 2. Let previous time be the value of the current time of animation before
  //    changing the playback rate.
  // 3. Set the playback rate to new playback rate.
  // 4. If the timeline is monotonically increasing and the previous time is
  //    resolved, set the current time of animation to previous time.
  // 5. If the timeline is not monotonically increasing, the start time is
  //    resolved and either:
  //      * the previous playback rate < 0 and the new playback rate >= 0, or
  //      * the previous playback rate >= 0 and the new playback rate < 0,
  //    Set animation's start time to the result of evaluating:
  //        associated effect end - start time
  bool preserve_current_time =
      timeline_ && timeline_->IsMonotonicallyIncreasing();
  bool reversal = (EffectivePlaybackRate() < 0) != (playback_rate < 0);
  pending_playback_rate_ = std::nullopt;
  V8CSSNumberish* previous_current_time = currentTime();
  playback_rate_ = playback_rate;
  if (previous_current_time && preserve_current_time) {
    setCurrentTime(previous_current_time, exception_state);
  }

  if (timeline_ && !timeline_->IsMonotonicallyIncreasing() && reversal &&
      start_time_) {
    if (auto_align_start_time_) {
      UpdateAutoAlignedStartTime();
    } else {
      start_time_ = EffectEnd() - start_time_.value();
    }
  }

  // Adds a UseCounter to check if setting playbackRate causes a compensatory
  // seek forcing a change in start_time_
  // We use an epsilon (1 microsecond) to handle precision issue.
  double epsilon = 1e-6;
  if (preserve_current_time && start_time_before && start_time_ &&
      fabs(start_time_.value().InMillisecondsF() -
           start_time_before.value().InMillisecondsF()) > epsilon &&
      CalculateAnimationPlayState() != V8AnimationPlayState::Enum::kFinished) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kAnimationSetPlaybackRateCompensatorySeek);
  }
  InvalidateNormalizedTiming();
  SetCompositorPending(CompositorPendingReason::kPendingUpdate);
  SetOutdated();
  NotifyProbe();
}

void Animation::ClearOutdated() {
  if (!outdated_)
    return;
  outdated_ = false;
  if (timeline_)
    timeline_->ClearOutdatedAnimation(this);
}

void Animation::SetOutdated() {
  if (outdated_)
    return;
  outdated_ = true;
  if (timeline_)
    timeline_->SetOutdatedAnimation(this);
}

void Animation::ForceServiceOnNextFrame() {
  if (timeline_)
    timeline_->ScheduleServiceOnNextFrame();
}

CompositorAnimations::FailureReasons
Animation::CheckCanStartAnimationOnCompositor(
    const PaintArtifactCompositor* paint_artifact_compositor,
    PropertyHandleSet* unsupported_properties) const {
  CompositorAnimations::FailureReasons reasons =
      CheckCanStartAnimationOnCompositorInternal();

  if (auto* keyframe_effect = DynamicTo<KeyframeEffect>(content_.Get())) {
    reasons |= keyframe_effect->CheckCanStartAnimationOnCompositor(
        paint_artifact_compositor, playback_rate_, unsupported_properties);
  }
  return reasons;
}

CompositorAnimations::FailureReasons
Animation::CheckCanStartAnimationOnCompositorInternal() const {
  CompositorAnimations::FailureReasons reasons =
      CompositorAnimations::kNoFailure;

  if (is_composited_animation_disabled_for_testing_)
    reasons |= CompositorAnimations::kAcceleratedAnimationsDisabled;

  if (EffectSuppressed())
    reasons |= CompositorAnimations::kEffectSuppressedByDevtools;

  // An Animation with zero playback rate will produce no visual output, so
  // there is no reason to composite it.
  if (TimingCalculations::IsWithinAnimationTimeEpsilon(
          0, EffectivePlaybackRate())) {
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;
  }

  // Animation times with large magnitudes cannot be accurately reflected by
  // TimeTicks. These animations will stall, be finished next frame, or
  // stuck in the before phase. In any case, there will be no visible changes
  // after the initial frame.
  std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
  if (current_time.has_value() &&
      !SupportedTimeValue(current_time.value().InMillisecondsF()))
    reasons |= CompositorAnimations::kEffectHasUnsupportedTimingParameters;

  if (!CurrentTimeInternal())
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;

  // Cannot composite an infinite duration animation with a negative playback
  // rate. TODO(crbug.com/1029167): Fix calculation of compositor timing to
  // enable compositing provided the iteration duration is finite. Having an
  // infinite number of iterations in the animation should not impede the
  // ability to composite the animation.
  if (EffectEnd().is_inf() && EffectivePlaybackRate() < 0)
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;

  // An Animation without a timeline effectively isn't playing, so there is no
  // reason to composite it. Additionally, mutating the timeline playback rate
  // is a debug feature available via devtools; we don't support this on the
  // compositor currently and there is no reason to do so.
  if (!timeline_ || (timeline_->IsDocumentTimeline() &&
                     To<DocumentTimeline>(*timeline_).PlaybackRate() != 1))
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;

  // If the scroll source is not composited, or we have not enabled scroll
  // driven animations on the compositor, fall back to main thread.
  // TODO(crbug.com/476553): Once all ScrollNodes including uncomposited ones
  // are in the compositor, the animation should be composited.
  if (timeline_ && timeline_->IsScrollSnapshotTimeline() &&
      !CompositorAnimations::CanStartScrollTimelineOnCompositor(
          To<ScrollSnapshotTimeline>(*timeline_).ResolvedSource())) {
    reasons |= CompositorAnimations::kTimelineSourceHasInvalidCompositingState;
  }

  // An Animation without an effect cannot produce a visual, so there is no
  // reason to composite it.
  if (!IsA<KeyframeEffect>(content_.Get()))
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;

  // An Animation that is not playing will not produce a visual, so there is no
  // reason to composite it.
  if (!Playing())
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;

  return reasons;
}

base::TimeDelta Animation::ComputeCompositorTimeOffset() const {
  if (start_time_ && !PendingInternal())
    return base::TimeDelta();

  double playback_rate = EffectivePlaybackRate();
  if (!playback_rate)
    return base::TimeDelta::Max();

  // Don't set a compositor time offset for progress-based timelines. When we
  // tick the animation, we pass "absolute" times to cc::KeyframeEffect::Pause.
  if (timeline_ && timeline_->IsProgressBased()) {
    return base::TimeDelta();
  }

  bool reversed = playback_rate < 0;

  std::optional<AnimationTimeDelta> current_time = CurrentTimeInternal();
  if (!current_time)
    return base::TimeDelta();

  double time_offset_s =
      reversed ? EffectEnd().InSecondsF() - current_time.value().InSecondsF()
               : current_time.value().InSecondsF();
  return base::Seconds(time_offset_s / fabs(playback_rate));
}

void Animation::MarkPendingIfCompositorPropertyAnimationChanges(
    const PaintArtifactCompositor* paint_artifact_compositor) {
  // |compositor_property_animations_have_no_effect_| will already be calculated
  // in |Animation::PreCommit| if the animation is pending.
  if (compositor_pending_)
    return;

  bool had_no_effect = compositor_property_animations_have_no_effect_;
  compositor_property_animations_have_no_effect_ = false;

  auto* keyframe_effect = DynamicTo<KeyframeEffect>(content_.Get());
  if (!keyframe_effect || !keyframe_effect->IsCurrent()) {
    // If the animation is not running, we can skip checking for having no
    // effect. We can also skip the call to |SetCompositorPending| to avoid
    // marking finished animations as pending.
    return;
  }

  Element* target = keyframe_effect->EffectTarget();
  if (target && keyframe_effect->Model() && keyframe_effect->IsCurrent()) {
    compositor_property_animations_have_no_effect_ =
        CompositorAnimations::CompositorPropertyAnimationsHaveNoEffect(
            *target, *keyframe_effect->Model(), paint_artifact_compositor);
  }
  if (compositor_property_animations_have_no_effect_ != had_no_effect)
    SetCompositorPending(CompositorPendingReason::kPendingEffectChange);
}

void Animation::StartAnimationOnCompositor(
    const PaintArtifactCompositor* paint_artifact_compositor) {
  DCHECK_EQ(
      CheckCanStartAnimationOnCompositor(paint_artifact_compositor, nullptr),
      CompositorAnimations::kNoFailure);

  // If PlaybackRate is 0, then we will run into divide by 0 issues.
  DCHECK(!TimingCalculations::IsWithinAnimationTimeEpsilon(
      0, EffectivePlaybackRate()));

  bool reversed = EffectivePlaybackRate() < 0;

  std::optional<AnimationTimeDelta> start_time;
  base::TimeDelta time_offset = base::TimeDelta();

  // Start the animation on the compositor with either a start time or time
  // offset. The start time is used for synchronous updates where the
  // compositor start time must be in precise alignment with the specified time
  // (e.g. after calling setStartTime). Scroll-driven animations always use this
  // mode even if it causes a discontinuity in the current time calculation.

  // Asynchronous updates such as updating the playback rate preserve current
  // time for a time-based animation even if the start time is set.
  // Asynchronous updates have an associated pending play or pending pause
  // task associated with them.
  if (start_time_ &&
      (timeline()->IsScrollSnapshotTimeline() || !PendingInternal())) {
    start_time = timeline_->ZeroTime() + start_time_.value();
    if (reversed) {
      start_time =
          start_time.value() - (EffectEnd() / fabs(EffectivePlaybackRate()));
    }
  } else {
    // Update preserves current time, which may not align with the value
    // computed from start time.
    time_offset = ComputeCompositorTimeOffset();
  }

  DCHECK_NE(compositor_group_, 0);
  DCHECK(To<KeyframeEffect>(content_.Get()));
  std::optional<double> start_time_s;
  if (start_time) {
    start_time_s = start_time.value().InSecondsF();
  }

  const Timing::NormalizedTiming& timing = effect()->NormalizedTiming();
  bool boundary_aligned = EffectivePlaybackRate() >= 0
                              ? timing.is_end_boundary_aligned
                              : timing.is_start_boundary_aligned;

  To<KeyframeEffect>(content_.Get())
      ->StartAnimationOnCompositor(
          compositor_group_, start_time_s, time_offset, EffectivePlaybackRate(),
          /*compositor_animation=*/nullptr,
          timeline()->IsMonotonicallyIncreasing(), boundary_aligned);
}

// TODO(crbug.com/960944): Rename to SetPendingCommit. This method handles both
// composited and non-composited animations. The use of 'compositor' in the name
// is confusing.
void Animation::SetCompositorPending(CompositorPendingReason reason) {
  // Determine if we need to reset the cached state for a property that is
  // composited via a native paint worklet. If reset, it forces Paint to
  // re-evaluate whether to paint with a native paint worklet.
  UpdateCompositedPaintStatus();

  if (RuntimeEnabledFeatures::
          CompositedAnimationsCancelledAsynchronouslyEnabled()) {
    if (compositor_state_ &&
        (reason == CompositorPendingReason::kPendingCancel ||
         reason == CompositorPendingReason::kPendingRestart)) {
      compositor_state_->pending_action = CompositorAction::kCancel;
    }
  } else {
    if (reason == CompositorPendingReason::kPendingCancel) {
      CancelAnimationOnCompositor();
      return;
    }
    if (reason == CompositorPendingReason::kPendingRestart) {
      CancelAnimationOnCompositor();
    }
    if (!HasActiveAnimationsOnCompositor()) {
      DestroyCompositorAnimation();
      compositor_state_.reset();
    }
  }

  if (compositor_state_) {
    if (reason == CompositorPendingReason::kPendingEffectChange) {
      compositor_state_->effect_changed = true;
    }
  } else {
    if (reason == CompositorPendingReason::kPendingCancel) {
      return;
    }
  }

  if (compositor_pending_) {
    return;
  }

  if (is_paused_for_testing_) {
    // Since the pause for testing API does not add the animation to the
    // list of pending animations, we must deal with any cancellations
    // immediately.
    // TODO(kevers): Fully deprecated the pause for testing API.
    if (CompositorPendingCancel()) {
      CancelAnimationOnCompositor();
    }
    return;
  }

  // In general, we need to update the compositor-side if anything has changed
  // on the blink version of the animation. There is also an edge case; if
  // neither the compositor nor blink side have a start time we still have to
  // sync them. This can happen if the blink side animation was started, the
  // compositor side hadn't started on its side yet, and then the blink side
  // start time was cleared (e.g. by setting current time).
  if (PendingInternal() || !compositor_state_ ||
      compositor_state_->effect_changed ||
      compositor_state_->pending_action == CompositorAction::kCancel ||
      compositor_state_->playback_rate != EffectivePlaybackRate() ||
      compositor_state_->start_time.has_value() != start_time_.has_value() ||
      (compositor_state_->start_time && start_time_ &&
       !TimingCalculations::IsWithinAnimationTimeEpsilon(
           compositor_state_->start_time.value(),
           start_time_.value().InSecondsF())) ||
      !compositor_state_->start_time || !start_time_) {
    compositor_pending_ = true;
    document_->GetPendingAnimations().Add(t
```