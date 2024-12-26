Response:
Let's break down the thought process for analyzing the `main_thread_event_queue.cc` file.

1. **Understand the Core Purpose from the Filename and Initial Comments:** The filename `main_thread_event_queue.cc` immediately suggests this file is about managing a queue of events specifically for the main thread. The copyright and license information are standard Chromium boilerplate and don't give functional insights.

2. **Identify Key Data Structures and Classes:**  Scanning the code reveals important classes:
    * `MainThreadEventQueue`: The central class, likely responsible for the queue itself.
    * `MainThreadEventQueueTask`: An abstract base class, indicating different types of tasks can be queued.
    * `QueuedClosure`:  A concrete `MainThreadEventQueueTask` for executing closures.
    * `QueuedWebInputEvent`:  A concrete `MainThreadEventQueueTask` specifically for web input events.
    * `WebCoalescedInputEvent`:  A Chromium type for representing and potentially merging input events.
    *  Internal data structures within `MainThreadEventQueue` like `events_` (the queue itself, a `MainThreadEventQueueTaskList`) and locks (`shared_state_lock_`).

3. **Analyze the Functionality of Each Key Class/Data Structure:**

    * **`MainThreadEventQueue`:**  Focus on its public methods and key member variables.
        * **`HandleEvent()`:**  The primary entry point for adding input events to the queue. Notice the logic around blocking/non-blocking events, touch events, and wheel events.
        * **`QueueClosure()`:** For queuing arbitrary functions to run on the main thread.
        * **`DispatchEvents()` and `DispatchRafAlignedInput()`:**  The mechanisms for processing the queue. The distinction between regular dispatch and RAF-aligned dispatch is crucial.
        * **`SetNeedsMainFrame()`:**  Indicates a need for a browser frame, often related to rendering.
        * **Various `SetNeeds...` methods:**  Configuration related to latency and debugger behavior.
        * **`UnblockQueuedBlockingTouchMovesIfNeeded()`:** Specific logic for handling touch events that were initially blocked but can be unblocked.
        * **Internal members like `events_`, locks, timers (`raf_fallback_timer_`), and the `widget_scheduler_`.** These provide hints about the internal workings.

    * **`MainThreadEventQueueTask`:**  Its virtual `Dispatch()` method is key. The `FilterNewEvent()` suggests a mechanism for potentially modifying the queue based on new events. The `IsWebInputEvent()` helps categorize tasks.

    * **`QueuedClosure`:**  A simple wrapper around a `base::OnceClosure`.

    * **`QueuedWebInputEvent`:**  More complex.
        * It holds a `WebCoalescedInputEvent`.
        * The `FilterNewEvent()` implementation details the coalescing logic for input events. Pay close attention to how different event types are handled.
        * The `Dispatch()` method shows how the event is passed to the client for handling.
        * `HandledEvent()` interacts with the `widget_scheduler_` and manages callbacks.
        * The `originally_cancelable_` flag is important for understanding how event cancellation is managed.

4. **Identify Interactions with Javascript, HTML, and CSS:**  This requires understanding how these technologies interact with the browser's rendering engine.

    * **Input Events:**  Javascript event listeners are triggered by input events (mouse clicks, keyboard presses, touch events). The queue is the central point for delivering these events to the Javascript layer.
    * **Rendering (RAF):** The "RAF-aligned" dispatch suggests a connection to `requestAnimationFrame`. This means certain input events can be synchronized with the browser's rendering loop for smoother animations and interactions.
    * **Event Handling and Blocking:** The concepts of blocking and non-blocking events directly relate to how Javascript event handlers can potentially prevent default browser actions. Passive event listeners are also mentioned.
    * **Touch Events and Scrolling:** The special handling of touch events, particularly `touchmove`, and the logic around unblocking them, connects to the user experience of scrolling and potential jank.

5. **Look for Logic and Assumptions:**

    * **Coalescing:** The `FilterNewEvent()` method in `QueuedWebInputEvent` is the core of the coalescing logic. The assumptions are that similar input events can be merged to reduce processing overhead.
    * **RAF Alignment:** The assumption is that synchronizing certain input events with the rendering loop can improve performance and smoothness.
    * **Blocking vs. Non-Blocking:** The code assumes that the compositor has determined whether event listeners are passive or can prevent default actions.
    * **Error Handling (Implicit):** While there isn't explicit error handling in the typical sense, the callbacks provide a mechanism for reporting whether an event was consumed or not.

6. **Identify Potential User/Programming Errors:**

    * **Blocking Event Handlers:**  The code implicitly handles the case where Javascript event handlers block the main thread. This can lead to jank.
    * **Passive Listeners:**  The code handles passive listeners correctly, but developers might misunderstand how they interact with event cancellation.
    * **Incorrectly Assuming Event Order:**  While the queue generally maintains order, coalescing can slightly alter the timing or number of events delivered.
    * **Misunderstanding RAF Alignment:** Developers might not be aware that certain input events are being delayed until the next rendering frame.

7. **Structure the Output:** Organize the findings into the requested categories: functionality, relationships to web technologies, logic/assumptions, and potential errors. Provide concrete examples for each point.

8. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Make sure the examples are relevant and easy to understand. Check for any technical terms that need further explanation.

This systematic approach, starting with the high-level purpose and progressively diving into the details of the code, helps in understanding the functionality and implications of a complex piece of software like the `main_thread_event_queue.cc` file.
好的，让我们来分析一下 `blink/renderer/platform/widget/input/main_thread_event_queue.cc` 这个文件。

**功能概述:**

`MainThreadEventQueue` 的主要功能是**管理和调度在 Blink 渲染引擎主线程上处理的输入事件**。它充当一个缓冲区，接收来自其他线程（如合成器线程）的输入事件，并将它们按照一定的规则和时机发送到主线程进行处理。

更具体地说，它的功能包括：

1. **接收输入事件:**  接收各种类型的 `WebInputEvent`，例如鼠标事件、触摸事件、键盘事件、手势事件等。
2. **事件排队:** 将接收到的事件存储在一个队列中 (`shared_state_.events_`)。
3. **事件合并 (Coalescing):**  对于某些类型的事件（例如 `mousemove`, `touchmove`），它可以将多个连续的同类型事件合并成一个，以减少主线程的负担并提高效率。合并的逻辑在 `QueuedWebInputEvent::FilterNewEvent` 中实现。
4. **事件调度:**  根据事件的类型、属性（例如是否需要与渲染帧同步 - "RAF aligned"）以及一些策略（例如低延迟要求）来决定何时将事件发送到主线程进行处理。
5. **与渲染帧同步 (RAF Alignment):**  对于某些类型的输入事件（例如 `mousemove`, `mousewheel`, `touchmove`），它可以选择将其与下一次渲染帧（requestAnimationFrame）同步处理，以避免在动画过程中出现卡顿。
6. **处理阻塞和非阻塞事件:**  区分需要立即处理的阻塞事件和可以稍后处理的非阻塞事件，并采取不同的处理方式。
7. **处理触摸事件的特殊逻辑:**  包含一些针对触摸事件的特殊处理，例如在滚动开始时取消后续触摸移动事件的默认行为，以及在某些情况下强制将触摸事件变为非阻塞。
8. **处理 `PointerRawUpdate` 事件:**  当存在 `pointerrawupdate` 事件处理器时，会生成并排队 `PointerRawUpdate` 事件。
9. **与 `WidgetScheduler` 交互:**  与 `WidgetScheduler` 组件协作，通知它输入事件的排队和处理情况，以便进行更精细的调度。
10. **提供回调机制:**  为处理后的事件提供回调函数，以便通知事件的消费情况。
11. **处理由于 Fling 而导致的非阻塞事件:**  当由于惯性滑动 (Fling) 而导致事件变为非阻塞时，会进行相应的处理。
12. **在 Debugger 下处理非缓冲输入:**  支持在调试器激活时立即处理某些输入事件。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

`MainThreadEventQueue` 是连接用户交互（通过硬件输入设备）和网页内容（JavaScript, HTML, CSS）的关键桥梁。

1. **JavaScript 事件处理:**
   - **功能关系:**  当用户在网页上进行操作（例如点击按钮、移动鼠标、触摸屏幕），浏览器会生成相应的输入事件。`MainThreadEventQueue` 负责将这些事件传递给主线程，最终由 JavaScript 的事件监听器处理。
   - **举例说明:**
     - 用户点击一个按钮：会生成 `mousedown` 和 `mouseup` 事件，这些事件会被 `MainThreadEventQueue` 排队并发送到主线程，触发按钮上注册的 `click` 事件监听器。
     - 用户在滑动页面：会生成大量的 `touchmove` 事件，`MainThreadEventQueue` 可能会合并这些事件，并根据是否与渲染帧同步的策略进行调度，最终 JavaScript 可以通过 `touchmove` 事件监听器获取滑动的信息。

2. **HTML 默认行为:**
   - **功能关系:**  某些输入事件具有浏览器默认的行为，例如点击链接会跳转页面，拖动文本会进行选择。`MainThreadEventQueue` 在将事件传递给 JavaScript 之前，会考虑这些默认行为。JavaScript 可以通过调用 `preventDefault()` 方法来阻止这些默认行为。
   - **举例说明:**
     - 用户在文本框中输入文字：会生成 `keydown`, `keypress`, `keyup` 等事件，`MainThreadEventQueue` 将这些事件发送到主线程，如果 JavaScript 没有阻止默认行为，浏览器会将输入的文字显示在文本框中（HTML 的默认行为）。
     - 用户滚动页面：会生成 `wheel` 或 `touchmove` 事件，`MainThreadEventQueue` 会处理这些事件，触发页面的滚动（浏览器的默认行为）。

3. **CSS 样式和动画:**
   - **功能关系:**  输入事件可以触发 CSS 状态的变化或动画效果。`MainThreadEventQueue` 确保这些事件能够及时地传递到主线程，以便浏览器更新渲染状态。
   - **举例说明:**
     - 鼠标悬停在一个元素上：会生成 `mouseover` 和 `mousemove` 事件，`MainThreadEventQueue` 将这些事件传递到主线程，如果 CSS 中定义了 `:hover` 伪类，浏览器会根据 CSS 规则改变元素的样式。
     - 用户触发一个需要动画的交互：例如点击一个按钮，按钮会有一个动画效果。`MainThreadEventQueue` 确保点击事件能够触发 JavaScript 代码，从而启动 CSS 动画或通过 JavaScript 操作 CSS 样式。

**逻辑推理和假设输入与输出:**

假设有以下输入：

- **输入:** 一个 `mousemove` 事件，鼠标坐标为 (100, 100)，时间戳为 T1。
- **假设:**  没有 JavaScript 事件监听器阻止默认行为，并且允许 RAF 对齐的输入。

**逻辑推理:**

1. `MainThreadEventQueue::HandleEvent` 被调用，接收到 `mousemove` 事件。
2. 由于是 `mousemove` 事件，且 `allow_raf_aligned_input_` 为真，并且没有低延迟需求，该事件被认为是 "RAF aligned"。
3. 事件被封装成 `QueuedWebInputEvent` 并添加到队列 `shared_state_.events_` 中。
4. `PossiblyScheduleMainFrame()` 被调用，由于队列中有 RAF 对齐的事件，并且尚未发送主帧请求，因此会请求一个主帧。
5. 在下一次浏览器渲染帧到来时，`DispatchRafAlignedInput` 被调用。
6. `mousemove` 事件从队列中取出。
7. `HandleEventResampling` 可能会对事件进行处理（例如，输入预测）。
8. 事件通过 `task->Dispatch(this)` 发送到主线程。
9. 主线程调用 `MainThreadEventQueue::HandleEventOnMainThread`。
10. `client_->HandleInputEvent` 被调用，将事件传递给 Blink 的其他组件进行处理。
11. 浏览器根据鼠标位置更新光标，并可能触发 CSS `:hover` 效果。

**输出:**

- 鼠标光标的位置更新到 (100, 100)。
- 如果存在 CSS `:hover` 规则，鼠标下的元素样式可能会改变。
- 如果有 JavaScript 监听了 `mousemove` 事件，相应的回调函数会被执行。

**用户或编程常见的使用错误及举例说明:**

1. **在高性能动画中使用阻塞的事件监听器:**
   - **错误:**  开发者在 `mousemove` 或 `touchmove` 事件监听器中执行耗时的同步操作，导致主线程阻塞，从而使动画卡顿。
   - **举例:**  在一个游戏中，开发者在 `mousemove` 事件监听器中计算复杂的物理模拟，导致鼠标移动时画面不流畅。
   - **`MainThreadEventQueue` 的影响:**  即使 `MainThreadEventQueue` 进行了事件合并和 RAF 对齐，主线程的阻塞仍然会影响渲染性能。

2. **过度依赖 `preventDefault()` 阻止默认滚动行为:**
   - **错误:**  开发者在 `touchmove` 事件监听器中调用 `preventDefault()` 来实现自定义的滚动效果，但可能没有正确处理所有情况，导致滚动不流畅或者某些平台的默认滚动行为被意外阻止。
   - **例:**  开发者尝试用 JavaScript 完全控制页面的滚动，但在某些快速滑动的情况下，可能会出现卡顿或者惯性滚动效果不佳。
   - **`MainThreadEventQueue` 的影响:**  `MainThreadEventQueue` 会区分可以取消和不可以取消的触摸事件，如果过度使用 `preventDefault()`，可能会干扰浏览器的优化。

3. **不理解 RAF 对齐的输入事件:**
   - **错误:**  开发者期望 `mousemove` 事件能够立即触发某些逻辑，但由于事件被 RAF 对齐，可能会有一定的延迟，导致交互不符合预期。
   - **例:**  开发者想要实现一个实时的鼠标拖拽效果，但由于 `mousemove` 事件的延迟，拖拽效果不够精确。
   - **`MainThreadEventQueue` 的影响:**  开发者需要理解哪些类型的事件会被 RAF 对齐，并在需要立即响应的场景中采取其他策略，例如使用非 RAF 对齐的事件或者调整代码逻辑。

4. **忘记处理非阻塞事件的回调:**
   - **错误:**  对于非阻塞的事件，开发者可能忘记为其设置回调函数，导致事件处理结果无法被正确获取。
   - **例:**  一个触摸事件被标记为非阻塞，开发者没有设置相应的回调来得知该事件是否被消费。
   - **`MainThreadEventQueue` 的影响:**  `MainThreadEventQueue` 依赖回调机制来通知事件的处理状态，如果回调缺失，可能会导致逻辑错误。

5. **在错误的时机修改事件的 `dispatch_type`:**
   - **错误:**  开发者可能错误地尝试在 JavaScript 中修改事件的 `dispatch_type` 属性，这通常是不允许的或者会产生不可预测的结果。
   - **`MainThreadEventQueue` 的影响:**  `MainThreadEventQueue` 内部会根据事件的 `dispatch_type` 进行不同的处理，如果该属性被错误修改，可能会导致事件处理流程出错。

总而言之，`MainThreadEventQueue.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责高效、有序地将用户的输入传递到主线程进行处理，并与 JavaScript, HTML, CSS 的功能紧密相关。理解它的工作原理对于编写高性能和响应迅速的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/main_thread_event_queue.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/main_thread_event_queue.h"

#include <utility>

#include "base/containers/circular_deque.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "cc/base/features.h"
#include "cc/metrics/event_metrics.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_gesture_event.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

constexpr base::TimeDelta kMaxRafDelay = base::Milliseconds(5 * 1000);

class QueuedClosure : public MainThreadEventQueueTask {
 public:
  QueuedClosure(base::OnceClosure closure) : closure_(std::move(closure)) {}

  ~QueuedClosure() override {}

  FilterResult FilterNewEvent(MainThreadEventQueueTask* other_task) override {
    return other_task->IsWebInputEvent() ? FilterResult::KeepIterating
                                         : FilterResult::StopIterating;
  }

  bool IsWebInputEvent() const override { return false; }

  void Dispatch(MainThreadEventQueue*) override { std::move(closure_).Run(); }

 private:
  base::OnceClosure closure_;
};

// Time interval at which touchmove events during scroll will be skipped
// during rAF signal.
constexpr base::TimeDelta kAsyncTouchMoveInterval = base::Milliseconds(200);

bool IsGestureScroll(WebInputEvent::Type type) {
  switch (type) {
    case WebGestureEvent::Type::kGestureScrollBegin:
    case WebGestureEvent::Type::kGestureScrollUpdate:
    case WebGestureEvent::Type::kGestureScrollEnd:
      return true;
    default:
      return false;
  }
}

}  // namespace

class QueuedWebInputEvent : public MainThreadEventQueueTask {
 public:
  QueuedWebInputEvent(std::unique_ptr<WebCoalescedInputEvent> event,
                      bool originally_cancelable,
                      HandledEventCallback callback,
                      bool known_by_scheduler,
                      const WebInputEventAttribution& attribution,
                      std::unique_ptr<cc::EventMetrics> metrics)
      : event_(std::move(event)),
        originally_cancelable_(originally_cancelable),
        callback_(std::move(callback)),
        known_by_scheduler_count_(known_by_scheduler ? 1 : 0),
        attribution_(attribution),
        metrics_(std::move(metrics)) {}

  ~QueuedWebInputEvent() override {}

  static std::unique_ptr<QueuedWebInputEvent> CreateForRawEvent(
      std::unique_ptr<WebCoalescedInputEvent> raw_event,
      const WebInputEventAttribution& attribution,
      const cc::EventMetrics* original_metrics) {
    DCHECK_EQ(raw_event->Event().GetType(),
              WebInputEvent::Type::kPointerRawUpdate);
    std::unique_ptr<cc::EventMetrics> metrics =
        cc::EventMetrics::CreateFromExisting(
            raw_event->Event().GetTypeAsUiEventType(),
            cc::EventMetrics::DispatchStage::kRendererCompositorFinished,
            original_metrics);
    return std::make_unique<QueuedWebInputEvent>(
        std::move(raw_event), false, HandledEventCallback(), false, attribution,
        std::move(metrics));
  }

  bool AreCoalescablePointerRawUpdateEvents(
      const QueuedWebInputEvent& other_event) {
    // There is no pointermove at this point in the queue.
    DCHECK(event_->Event().GetType() != WebInputEvent::Type::kPointerMove &&
           other_event.event_->Event().GetType() !=
               WebInputEvent::Type::kPointerMove);
    // Events with modifiers differing by kRelativeMotionEvent should not be
    // coalesced. In case of a pointer lock, kRelativeMotionEvent is sent
    // when the cursor is recentered. Events post the recentered event have
    // a big delta compared to the previous events and hence should not be
    // coalesced.
    return event_->Event().GetType() ==
               WebInputEvent::Type::kPointerRawUpdate &&
           other_event.event_->Event().GetType() ==
               WebInputEvent::Type::kPointerRawUpdate &&
           ((event_->Event().GetModifiers() &
             blink::WebInputEvent::Modifiers::kRelativeMotionEvent) ==
            (other_event.event_->Event().GetModifiers() &
             blink::WebInputEvent::Modifiers::kRelativeMotionEvent));
  }

  FilterResult FilterNewEvent(MainThreadEventQueueTask* other_task) override {
    if (!other_task->IsWebInputEvent())
      return FilterResult::StopIterating;

    QueuedWebInputEvent* other_event =
        static_cast<QueuedWebInputEvent*>(other_task);
    if (other_event->event_->Event().GetType() ==
        WebInputEvent::Type::kTouchScrollStarted) {
      return HandleTouchScrollStartQueued();
    }

    if (!event_->Event().IsSameEventClass(other_event->event_->Event()))
      return FilterResult::KeepIterating;

    if (!event_->CanCoalesceWith(*other_event->event_)) {
      // Two pointerevents may not be able to coalesce but we should continue
      // looking further down the queue if both of them were rawupdate or move
      // events and only their pointer_type, id, or event_type was different.
      if (AreCoalescablePointerRawUpdateEvents(*other_event))
        return FilterResult::KeepIterating;
      return FilterResult::StopIterating;
    }

    // If the other event was blocking store its callback to call later, but we
    // also save the trace_id to ensure the flow events correct show the
    // critical path.
    if (other_event->callback_) {
      blocking_coalesced_callbacks_.emplace_back(
          std::move(other_event->callback_),
          other_event->event_->latency_info().trace_id());
    }

    known_by_scheduler_count_ += other_event->known_by_scheduler_count_;
    event_->CoalesceWith(*other_event->event_);
    auto* metrics = metrics_ ? metrics_->AsScrollUpdate() : nullptr;
    auto* other_metrics = other_event->metrics_
                              ? other_event->metrics_->AsScrollUpdate()
                              : nullptr;
    if (metrics && other_metrics)
      metrics->CoalesceWith(*other_metrics);

    // The newest event (|other_item|) always wins when updating fields.
    originally_cancelable_ = other_event->originally_cancelable_;

    return FilterResult::CoalescedEvent;
  }

  bool IsWebInputEvent() const override { return true; }

  void Dispatch(MainThreadEventQueue* queue) override {
    if (originally_cancelable_ &&
        event_->Event().GetType() == WebInputEvent::Type::kTouchMove) {
      auto* touch_event = static_cast<WebTouchEvent*>(event_->EventPointer());
      if (queue->GetMainThreadOnly().should_unblock_touch_moves) {
        // Though we have unblocked queued touch events when we set
        // should_unblock_touch_moves_ to true, there is still chance of newly
        // queued blocking touch events.
        touch_event->dispatch_type =
            WebInputEvent::DispatchType::kEventNonBlocking;
      }
      // If the touch move has been unblocked (above or in
      // HandleTouchScrollStartQueued()), run callbacks before dispatching.
      if (touch_event->dispatch_type ==
          WebInputEvent::DispatchType::kEventNonBlocking) {
        RunCallbacks(mojom::blink::InputEventResultState::kNotConsumed,
                     event_->latency_info(), nullptr, std::nullopt);
      }
    }

    HandledEventCallback callback =
        base::BindOnce(&QueuedWebInputEvent::HandledEvent,
                       base::Unretained(this), base::RetainedRef(queue));
    if (!queue->HandleEventOnMainThread(
            *event_, attribution(), std::move(metrics_), std::move(callback))) {
      // The |callback| won't be run, so our stored |callback_| should run
      // indicating error.
      HandledEvent(queue, mojom::blink::InputEventResultState::kNotConsumed,
                   event_->latency_info(), nullptr, std::nullopt);
    }
  }

  void HandledEvent(MainThreadEventQueue* queue,
                    mojom::blink::InputEventResultState ack_result,
                    const ui::LatencyInfo& latency_info,
                    mojom::blink::DidOverscrollParamsPtr overscroll,
                    std::optional<cc::TouchAction> touch_action) {
    RunCallbacks(ack_result, latency_info, std::move(overscroll), touch_action);

    // TODO(dtapuska): Change the scheduler API to take into account number of
    // events processed.
    for (size_t i = 0; i < known_by_scheduler_count_; ++i) {
      queue->widget_scheduler_->DidHandleInputEventOnMainThread(
          event_->Event(),
          ack_result == mojom::blink::InputEventResultState::kConsumed
              ? WebInputEventResult::kHandledApplication
              : WebInputEventResult::kNotHandled,
          queue->client_ ? queue->client_->RequestedMainFramePending() : false);
    }

    queue->UnblockQueuedBlockingTouchMovesIfNeeded(event_->Event(), ack_result);
  }

  struct CallbackInfo {
    HandledEventCallback callback;
    ui::LatencyInfo latency_info;
  };
  void TakeCallbacksInto(Vector<CallbackInfo>& callbacks) {
    if (callback_) {
      callbacks.emplace_back(std::move(callback_), event_->latency_info());
    }
    if (!blocking_coalesced_callbacks_.empty()) {
      ui::LatencyInfo coalesced_latency_info = event_->latency_info();
      coalesced_latency_info.set_coalesced();
      for (auto& callback : blocking_coalesced_callbacks_) {
        coalesced_latency_info.set_trace_id(callback.second);
        callbacks.emplace_back(std::move(callback.first),
                               coalesced_latency_info);
      }
      blocking_coalesced_callbacks_.clear();
    }
  }

  bool originally_cancelable() const { return originally_cancelable_; }

  const WebInputEventAttribution& attribution() const { return attribution_; }

  const WebInputEvent& Event() const { return event_->Event(); }

  WebCoalescedInputEvent* mutable_coalesced_event() { return event_.get(); }

  void SetQueuedTimeStamp(base::TimeTicks queued_time) {
    event_->EventPointer()->SetQueuedTimeStamp(queued_time);
  }

 private:
  void RunCallbacks(mojom::blink::InputEventResultState ack_result,
                    const ui::LatencyInfo& latency_info,
                    mojom::blink::DidOverscrollParamsPtr overscroll,
                    const std::optional<cc::TouchAction>& touch_action) {
    // callback_ is null if we have already run it, in cases
    // 1. the event had been a blocking touchmove before it was unblocked;
    // 2. the event is an non-blocking event, and its callback was called when
    //    the event was queued, then a blocking event was coalesced into the
    //    the event.
    if (callback_) {
      std::move(callback_).Run(ack_result, latency_info, std::move(overscroll),
                               touch_action);
    }

    if (!blocking_coalesced_callbacks_.empty()) {
      ui::LatencyInfo coalesced_latency_info = latency_info;
      coalesced_latency_info.set_coalesced();
      for (auto& callback : blocking_coalesced_callbacks_) {
        coalesced_latency_info.set_trace_id(callback.second);
        std::move(callback.first)
            .Run(ack_result, coalesced_latency_info, nullptr, std::nullopt);
      }
      blocking_coalesced_callbacks_.clear();
    }
  }

  FilterResult HandleTouchScrollStartQueued() {
    // A TouchScrollStart will queued after this touch move which will make all
    // previous touch moves that are queued uncancelable.
    switch (event_->Event().GetType()) {
      case WebInputEvent::Type::kTouchMove: {
        WebTouchEvent* touch_event =
            static_cast<WebTouchEvent*>(event_->EventPointer());
        if (touch_event->dispatch_type ==
            WebInputEvent::DispatchType::kBlocking) {
          touch_event->dispatch_type =
              WebInputEvent::DispatchType::kEventNonBlocking;
        }
        return FilterResult::KeepIterating;
      }
      case WebInputEvent::Type::kTouchStart:
      case WebInputEvent::Type::kTouchEnd:
        return FilterResult::StopIterating;
      default:
        return FilterResult::KeepIterating;
    }
  }

  std::unique_ptr<WebCoalescedInputEvent> event_;

  // Contains the pending callbacks to be called, along with their associated
  // trace_ids.
  base::circular_deque<std::pair<HandledEventCallback, int64_t>>
      blocking_coalesced_callbacks_;
  // Contains the number of non-blocking events coalesced.

  // Whether the received event was originally cancelable or not. The compositor
  // input handler can change the event based on presence of event handlers so
  // this is the state at which the renderer received the event from the
  // browser.
  bool originally_cancelable_;

  HandledEventCallback callback_;

  size_t known_by_scheduler_count_;

  const WebInputEventAttribution attribution_;

  std::unique_ptr<cc::EventMetrics> metrics_;
};

MainThreadEventQueue::MainThreadEventQueue(
    MainThreadEventQueueClient* client,
    const scoped_refptr<base::SingleThreadTaskRunner>& compositor_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<scheduler::WidgetScheduler> widget_scheduler,
    bool allow_raf_aligned_input)
    : client_(client),
      allow_raf_aligned_input_(allow_raf_aligned_input),
      main_task_runner_(std::move(main_task_runner)),
      widget_scheduler_(std::move(widget_scheduler)) {
  DCHECK(widget_scheduler_);
  raf_fallback_timer_ = std::make_unique<base::OneShotTimer>();
  raf_fallback_timer_->SetTaskRunner(main_task_runner_);

  event_predictor_ = std::make_unique<InputEventPrediction>(
      base::FeatureList::IsEnabled(blink::features::kResamplingInputEvents));

#if DCHECK_IS_ON()
  compositor_task_runner_ = compositor_task_runner;
#endif
}

MainThreadEventQueue::~MainThreadEventQueue() {}

bool MainThreadEventQueue::Allowed(const WebInputEvent& event,
                                   bool force_allow) {
  if (force_allow) {
    return true;
  }

  WebInputEvent::Type event_type = event.GetType();
  if (!IsGestureScroll(event_type)) {
    return true;
  }

  const WebGestureEvent& gesture_event =
      static_cast<const WebGestureEvent&>(event);
  if (event_type == WebInputEvent::Type::kGestureScrollBegin &&
      gesture_event.data.scroll_begin.cursor_control) {
    cursor_control_in_progress_ = true;
  }

  // The Android swipe-to-move-cursor feature still sends gesture scroll events
  // to the main thread.
  bool allowed = cursor_control_in_progress_;

  if (event_type == WebInputEvent::Type::kGestureScrollEnd &&
      cursor_control_in_progress_) {
    cursor_control_in_progress_ = false;
  }

  return allowed;
}

void MainThreadEventQueue::HandleEvent(
    std::unique_ptr<WebCoalescedInputEvent> event,
    DispatchType original_dispatch_type,
    mojom::blink::InputEventResultState ack_result,
    const WebInputEventAttribution& attribution,
    std::unique_ptr<cc::EventMetrics> metrics,
    HandledEventCallback callback,
    bool allow_main_gesture_scroll) {
  TRACE_EVENT2("input", "MainThreadEventQueue::HandleEvent", "dispatch_type",
               original_dispatch_type, "event_type", event->Event().GetType());
  DCHECK(original_dispatch_type == DispatchType::kBlocking ||
         original_dispatch_type == DispatchType::kNonBlocking);
  DCHECK(ack_result == mojom::blink::InputEventResultState::kSetNonBlocking ||
         ack_result ==
             mojom::blink::InputEventResultState::kSetNonBlockingDueToFling ||
         ack_result == mojom::blink::InputEventResultState::kNotConsumed);
  DCHECK(Allowed(event->Event(), allow_main_gesture_scroll));

  bool is_blocking =
      original_dispatch_type == DispatchType::kBlocking &&
      ack_result != mojom::blink::InputEventResultState::kSetNonBlocking;
  bool is_wheel = event->Event().GetType() == WebInputEvent::Type::kMouseWheel;
  bool is_touch = WebInputEvent::IsTouchEventType(event->Event().GetType());
  bool originally_cancelable = false;

  if (is_touch) {
    WebTouchEvent* touch_event =
        static_cast<WebTouchEvent*>(event->EventPointer());

    originally_cancelable =
        touch_event->dispatch_type == WebInputEvent::DispatchType::kBlocking;

    if (!is_blocking) {
      // Adjust the `dispatch_type` on the event since the compositor
      // determined all event listeners are passive.
      touch_event->dispatch_type =
          WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    }

    bool& last_touch_start_forced_nonblocking_due_to_fling =
        GetCompositorThreadOnly()
            .last_touch_start_forced_nonblocking_due_to_fling;
    if (touch_event->GetType() == WebInputEvent::Type::kTouchStart) {
      last_touch_start_forced_nonblocking_due_to_fling = false;
    }
    if (touch_event->touch_start_or_first_touch_move &&
        touch_event->dispatch_type == WebInputEvent::DispatchType::kBlocking) {
      // If the touch start is forced to be passive due to fling, its following
      // touch move should also be passive.
      if (ack_result ==
              mojom::blink::InputEventResultState::kSetNonBlockingDueToFling ||
          last_touch_start_forced_nonblocking_due_to_fling) {
        touch_event->dispatch_type =
            WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
        is_blocking = false;
        last_touch_start_forced_nonblocking_due_to_fling = true;
      }
    }

    // If the event is non-cancelable ACK it right away.
    if (is_blocking &&
        touch_event->dispatch_type != WebInputEvent::DispatchType::kBlocking) {
      is_blocking = false;
    }
  }

  if (is_wheel) {
    WebMouseWheelEvent* wheel_event =
        static_cast<WebMouseWheelEvent*>(event->EventPointer());
    originally_cancelable =
        wheel_event->dispatch_type == WebInputEvent::DispatchType::kBlocking;
    if (!is_blocking) {
      // Adjust the |dispatchType| on the event since the compositor
      // determined all event listeners are passive.
      wheel_event->dispatch_type =
          WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    }
  }

  HandledEventCallback event_callback;
  if (is_blocking) {
    TRACE_EVENT_INSTANT0("input", "Blocking", TRACE_EVENT_SCOPE_THREAD);
    event_callback = std::move(callback);
  }

  if (has_pointerrawupdate_handlers_) {
    if (event->Event().GetType() == WebInputEvent::Type::kMouseMove) {
      auto raw_event = std::make_unique<WebCoalescedInputEvent>(
          std::make_unique<WebPointerEvent>(
              WebInputEvent::Type::kPointerRawUpdate,
              static_cast<const WebMouseEvent&>(event->Event())),
          event->latency_info());
      QueueEvent(QueuedWebInputEvent::CreateForRawEvent(
          std::move(raw_event), attribution, metrics.get()));
    } else if (event->Event().GetType() == WebInputEvent::Type::kTouchMove) {
      const WebTouchEvent& touch_event =
          static_cast<const WebTouchEvent&>(event->Event());
      for (unsigned i = 0; i < touch_event.touches_length; ++i) {
        const WebTouchPoint& touch_point = touch_event.touches[i];
        if (touch_point.state == WebTouchPoint::State::kStateMoved) {
          auto raw_event = std::make_unique<WebCoalescedInputEvent>(
              std::make_unique<WebPointerEvent>(touch_event, touch_point),
              event->latency_info());
          raw_event->EventPointer()->SetType(
              WebInputEvent::Type::kPointerRawUpdate);
          QueueEvent(QueuedWebInputEvent::CreateForRawEvent(
              std::move(raw_event), attribution, metrics.get()));
        }
      }
    }
  }

  ui::LatencyInfo cloned_latency_info;

  // Clone the latency info if we are calling the callback.
  if (callback)
    cloned_latency_info = event->latency_info();

  auto queued_event = std::make_unique<QueuedWebInputEvent>(
      std::move(event), originally_cancelable, std::move(event_callback),
      IsForwardedAndSchedulerKnown(ack_result), attribution,
      std::move(metrics));

  QueueEvent(std::move(queued_event));

  if (callback) {
    std::move(callback).Run(ack_result, cloned_latency_info, nullptr,
                            std::nullopt);
  }
}

void MainThreadEventQueue::QueueClosure(base::OnceClosure closure) {
  bool needs_post_task = false;
  std::unique_ptr<QueuedClosure> item(new QueuedClosure(std::move(closure)));
  {
    base::AutoLock lock(shared_state_lock_);
    shared_state_.events_.Enqueue(std::move(item));
    needs_post_task = !shared_state_.sent_post_task_;
    shared_state_.sent_post_task_ = true;
  }

  if (needs_post_task)
    PostTaskToMainThread();
}

void MainThreadEventQueue::PossiblyScheduleMainFrame() {
  bool needs_main_frame = false;
  {
    base::AutoLock lock(shared_state_lock_);
    if (!shared_state_.sent_main_frame_request_ &&
        !shared_state_.events_.empty() &&
        IsRafAlignedEvent(shared_state_.events_.front())) {
      needs_main_frame = true;
      shared_state_.sent_main_frame_request_ = true;
    }
  }
  if (needs_main_frame)
    SetNeedsMainFrame();
}

void MainThreadEventQueue::DispatchEvents() {
  size_t events_to_process;
  size_t queue_size;

  // Record the queue size so that we only process
  // that maximum number of events.
  {
    base::AutoLock lock(shared_state_lock_);
    shared_state_.sent_post_task_ = false;
    events_to_process = shared_state_.events_.size();

    // Don't process rAF aligned events at tail of queue.
    while (events_to_process > 0 &&
           !ShouldFlushQueue(shared_state_.events_.at(events_to_process - 1))) {
      --events_to_process;
    }
  }

  while (events_to_process--) {
    std::unique_ptr<MainThreadEventQueueTask> task;
    {
      base::AutoLock lock(shared_state_lock_);
      if (shared_state_.events_.empty())
        return;
      task = shared_state_.events_.Pop();
    }

    HandleEventResampling(task, base::TimeTicks::Now());
    // Dispatching the event is outside of critical section.
    task->Dispatch(this);
  }

  // Dispatch all raw move events as well regardless of where they are in the
  // queue
  {
    base::AutoLock lock(shared_state_lock_);
    queue_size = shared_state_.events_.size();
  }

  for (size_t current_task_index = 0; current_task_index < queue_size;
       ++current_task_index) {
    std::unique_ptr<MainThreadEventQueueTask> task;
    {
      base::AutoLock lock(shared_state_lock_);
      while (current_task_index < queue_size &&
             current_task_index < shared_state_.events_.size()) {
        if (!IsRafAlignedEvent(shared_state_.events_.at(current_task_index)))
          break;
        current_task_index++;
      }
      if (current_task_index >= queue_size ||
          current_task_index >= shared_state_.events_.size())
        break;
      if (IsRawUpdateEvent(shared_state_.events_.at(current_task_index))) {
        task = shared_state_.events_.remove(current_task_index);
        --queue_size;
        --current_task_index;
      } else if (!IsRafAlignedEvent(
                     shared_state_.events_.at(current_task_index))) {
        // Do not pass a non-rAF-aligned event to avoid delivering raw move
        // events and down/up events out of order to js.
        break;
      }
    }

    // Dispatching the event is outside of critical section.
    if (task)
      task->Dispatch(this);
  }

  PossiblyScheduleMainFrame();

  if (client_)
    client_->InputEventsDispatched(/*raf_aligned=*/false);
}

static bool IsAsyncTouchMove(
    const std::unique_ptr<MainThreadEventQueueTask>& queued_item) {
  if (!queued_item->IsWebInputEvent())
    return false;
  const QueuedWebInputEvent* event =
      static_cast<const QueuedWebInputEvent*>(queued_item.get());
  if (event->Event().GetType() != WebInputEvent::Type::kTouchMove)
    return false;
  const WebTouchEvent& touch_event =
      static_cast<const WebTouchEvent&>(event->Event());
  return touch_event.moved_beyond_slop_region &&
         !event->originally_cancelable();
}

void MainThreadEventQueue::RafFallbackTimerFired() {
  // This fallback fires when the browser doesn't produce main frames for a
  // variety of reasons. (eg. Tab gets hidden). We definitely don't want input
  // to stay forever in the queue.
  DispatchRafAlignedInput(base::TimeTicks::Now());
}

void MainThreadEventQueue::ClearRafFallbackTimerForTesting() {
  raf_fallback_timer_.reset();
}

bool MainThreadEventQueue::IsEmptyForTesting() {
  base::AutoLock lock(shared_state_lock_);
  return shared_state_.events_.empty();
}

void MainThreadEventQueue::DispatchRafAlignedInput(base::TimeTicks frame_time) {
  if (raf_fallback_timer_)
    raf_fallback_timer_->Stop();
  size_t queue_size_at_start;

  // Record the queue size so that we only process
  // that maximum number of events.
  {
    base::AutoLock lock(shared_state_lock_);
    shared_state_.sent_main_frame_request_ = false;
    queue_size_at_start = shared_state_.events_.size();
  }

  while (queue_size_at_start--) {
    std::unique_ptr<MainThreadEventQueueTask> task;
    {
      base::AutoLock lock(shared_state_lock_);

      if (shared_state_.events_.empty())
        return;

      if (IsRafAlignedEvent(shared_state_.events_.front())) {
        // Throttle touchmoves that are async.
        if (IsAsyncTouchMove(shared_state_.events_.front())) {
          if (shared_state_.events_.size() == 1 &&
              frame_time < shared_state_.last_async_touch_move_timestamp_ +
                               kAsyncTouchMoveInterval) {
            break;
          }
          shared_state_.last_async_touch_move_timestamp_ = frame_time;
        }
      }
      task = shared_state_.events_.Pop();
    }
    HandleEventResampling(task, frame_time);
    // Dispatching the event is outside of critical section.
    task->Dispatch(this);
  }

  PossiblyScheduleMainFrame();

  if (client_)
    client_->InputEventsDispatched(/*raf_aligned=*/true);
}

void MainThreadEventQueue::PostTaskToMainThread() {
  main_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&MainThreadEventQueue::DispatchEvents, this));
}

void MainThreadEventQueue::QueueEvent(
    std::unique_ptr<MainThreadEventQueueTask> event) {
  bool is_raf_aligned = IsRafAlignedEvent(event);
  bool needs_main_frame = false;
  bool needs_post_task = false;

  // Record the input event's type prior to enqueueing so that the scheduler
  // can be notified of its dispatch (if the event is not coalesced).
  bool is_input_event = event->IsWebInputEvent();
  WebInputEvent::Type input_event_type = WebInputEvent::Type::kUndefined;
  WebInputEventAttribution attribution;
  if (is_input_event) {
    auto* queued_input_event = static_cast<QueuedWebInputEvent*>(event.get());
    input_event_type = queued_input_event->Event().GetType();
    attribution = queued_input_event->attribution();
    queued_input_event->SetQueuedTimeStamp(base::TimeTicks::Now());
  }

  {
    base::AutoLock lock(shared_state_lock_);

    if (shared_state_.events_.Enqueue(std::move(event)) ==
        MainThreadEventQueueTaskList::EnqueueResult::kEnqueued) {
      if (!is_raf_aligned) {
        needs_post_task = !shared_state_.sent_post_task_;
        shared_state_.sent_post_task_ = true;
      } else {
        needs_main_frame = !shared_state_.sent_main_frame_request_;
        shared_state_.sent_main_frame_request_ = true;
      }

      // Notify the scheduler that we'll enqueue a task to the main thread.
      if (is_input_event) {
        widget_scheduler_->WillPostInputEventToMainThread(input_event_type,
                                                          attribution);
      }
    }
  }

  if (needs_post_task)
    PostTaskToMainThread();
  if (needs_main_frame)
    SetNeedsMainFrame();
}

bool MainThreadEventQueue::IsRawUpdateEvent(
    const std::unique_ptr<MainThreadEventQueueTask>& item) const {
  return item->IsWebInputEvent() &&
         static_cast<const QueuedWebInputEvent*>(item.get())
                 ->Event()
                 .GetType() == WebInputEvent::Type::kPointerRawUpdate;
}

bool MainThreadEventQueue::ShouldFlushQueue(
    const std::unique_ptr<MainThreadEventQueueTask>& item) const {
  if (IsRawUpdateEvent(item))
    return false;
  return !IsRafAlignedEvent(item);
}

bool MainThreadEventQueue::IsRafAlignedEvent(
    const std::unique_ptr<MainThreadEventQueueTask>& item) const {
  if (!item->IsWebInputEvent())
    return false;
  const QueuedWebInputEvent* event =
      static_cast<const QueuedWebInputEvent*>(item.get());
  switch (event->Event().GetType()) {
    case WebInputEvent::Type::kMouseMove:
    case WebInputEvent::Type::kMouseWheel:
    case WebInputEvent::Type::kTouchMove:
      return allow_raf_aligned_input_ && !needs_low_latency_ &&
             !needs_low_latency_until_pointer_up_ &&
             !needs_unbuffered_input_for_debugger_;
    default:
      return false;
  }
}

void MainThreadEventQueue::HandleEventResampling(
    const std::unique_ptr<MainThreadEventQueueTask>& item,
    base::TimeTicks frame_time) {
  if (item->IsWebInputEvent() && allow_raf_aligned_input_ && event_predictor_) {
    QueuedWebInputEvent* event = static_cast<QueuedWebInputEvent*>(item.get());
    event_predictor_->HandleEvents(*event->mutable_coalesced_event(),
                                   frame_time);
  }
}

bool MainThreadEventQueue::HandleEventOnMainThread(
    const WebCoalescedInputEvent& event,
    const WebInputEventAttribution& attribution,
    std::unique_ptr<cc::EventMetrics> metrics,
    HandledEventCallback handled_callback) {
  // Notify the scheduler that the main thread is about to execute handlers.
  widget_scheduler_->WillHandleInputEventOnMainThread(event.Event().GetType(),
                                                      attribution);

  bool handled = false;
  if (client_) {
    handled = client_->HandleInputEvent(event, std::move(metrics),
                                        std::move(handled_callback));
  }

  if (needs_low_latency_until_pointer_up_) {
    // Reset the needs low latency until pointer up mode if necessary.
    switch (event.Event().GetType()) {
      case WebInputEvent::Type::kMouseUp:
      case WebInputEvent::Type::kTouchCancel:
      case WebInputEvent::Type::kTouchEnd:
      case WebInputEvent::Type::kPointerCancel:
      case WebInputEvent::Type::kPointerUp:
        needs_low_latency_until_pointer_up_ = false;
        break;
      default:
        break;
    }
  }
  return handled;
}

void MainThreadEventQueue::SetNeedsMainFrame() {
  if (main_task_runner_->BelongsToCurrentThread()) {
    if (raf_fallback_timer_) {
      raf_fallback_timer_->Start(
          FROM_HERE, kMaxRafDelay,
          base::BindOnce(&MainThreadEventQueue::RafFallbackTimerFired, this));
    }
    if (client_)
      client_->SetNeedsMainFrame();
    return;
  }

  main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&MainThreadEventQueue::SetNeedsMainFrame, this));
}

void MainThreadEventQueue::ClearClient() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  client_ = nullptr;
  raf_fallback_timer_.reset();
}

void MainThreadEventQueue::SetNeedsLowLatency(bool low_latency) {
  needs_low_latency_ = low_latency;
}

void MainThreadEventQueue::SetNeedsUnbufferedInputForDebugger(bool unbuffered) {
  needs_unbuffered_input_for_debugger_ = unbuffered;
}

void MainThreadEventQueue::SetHasPointerRawUpdateEventHandlers(
    bool has_handlers) {
  has_pointerrawupdate_handlers_ = has_handlers;
}

void MainThreadEventQueue::RequestUnbufferedInputEvents() {
  needs_low_latency_until_pointer_up_ = true;
}

void MainThreadEventQueue::UnblockQueuedBlockingTouchMovesIfNeeded(
    const WebInputEvent& dispatched_event,
    mojom::blink::InputEventResultState ack_result) {
  if (!WebInputEvent::IsTouchEventType(dispatched_event.GetType())) {
    return;
  }

  {
    bool& should_unblock_touch_moves =
        GetMainThreadOnly().should_unblock_touch_moves;
    bool& blocking_touch_start_not_consumed =
        GetMainThreadOnly().blocking_touch_start_not_consumed;
    auto& touch_event = static_cast<const WebTouchEvent&>(dispatched_event);
    if (touch_event.touch_start_or_first_touch_move) {
      bool is_not_consumed_blocking =
          touch_event.dispatch_type == WebInputEvent::DispatchType::kBlocking &&
          ack_result == mojom::blink::InputEventResultState::kNotConsumed;
      if (touch_event.GetType() == WebInputEvent::Type::kTouchStart) {
        blocking_touch_start_not_consumed = is_not_consumed_blocking;
        should_unblock_touch_moves = false;
      } else {
        // `event` is the first touch move.
        CHECK_EQ(touch_event.GetType(), WebInputEvent::Type::kTouchMove);
        should_unblock_touch_moves =
            blocking_touch_start_not_consumed && is_not_consumed_blocking;
      }
    }
    if (!should_unblock_touch_moves) {
      return;
    }
  }

  // Neither the touchstart nor the first touchmove was consumed. The browser
  // process will make the remaining of the touch sequence non-blocking, but
  // we need to unblock the already queued blocking touchmove events and run
  // the callbacks (collected in a vector to avoid locking during callbacks).
  Vector<QueuedWebInputEvent::CallbackInfo> callbacks;
  {
    base::AutoLock lock(shared_state_lock_);
    for (size_t i = 0; i < shared_state_.events_.size(); ++i) {
      MainThreadEventQueueTask* task = shared_state_.events_.at(i).get();
      if (!task->IsWebInputEvent()) {
        continue;
      }
      auto* queued_event = static_cast<QueuedWebInputEvent*>(task);
      WebInputEvent* event =
          queued_event->mutable_coalesced_event()->EventPointer();
      if (event->GetType() == WebInputEvent::Type::kTouchStart ||
          event->GetType() == WebInputEvent::Type::kTouchEnd) {
        break;
      }
      if (event->GetType() != WebInputEvent::Type::kTouchMove) {
        continue;
      }

      auto* touch_event = static_cast<WebTouchEvent*>(event);
      if (!touch_event->touch_start_or_first_touch_move &&
          touch_event->dispatch_type ==
              WebInputEvent::DispatchType::kBlocking) {
        touch_event->dispatch_type =
            WebInputEvent::DispatchType::kEventNonBlocking;
        queued_event->TakeCallbacksInto(callbacks);
      }
    }
  }
  for (auto& callback_info : callbacks) {
    std::move(callback_info.callback)
        .Run(mojom::blink::InputEventResultState::kNotConsumed,
             callback_info.latency_info, nullptr, std::nullopt);
  }
}

MainThreadEventQueue::MainThreadOnly&
MainThreadEventQueue::GetMainThreadOnly() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return main_thread_only_;
}

MainThreadEventQueue::CompositorThreadOnly&
MainThreadEventQueue::GetCompositorThreadOnly() {
#if DCHECK_IS_ON()
  DCHECK(compositor_task_runner_->BelongsToCurrentThread());
#endif
  return compositor_thread_only_;
}

}  // namespace blink

"""

```