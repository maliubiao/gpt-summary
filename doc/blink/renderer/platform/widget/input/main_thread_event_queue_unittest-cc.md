Response:
The user wants a summary of the functionality of the C++ code provided. I need to identify the main purpose of the code and how it relates to web technologies (JavaScript, HTML, CSS) if applicable. I also need to look for examples of logical reasoning within the code (identifying input and output scenarios), and common usage errors (though this might be more applicable to the classes being tested).

**Breakdown of the Request:**

1. **List Functionality:**  Identify the core purpose of the `main_thread_event_queue_unittest.cc` file.
2. **Relationship to Web Tech:** Explain any connection to JavaScript, HTML, or CSS.
3. **Logical Reasoning:** Provide examples of input and expected output.
4. **Common Usage Errors:**  Highlight potential mistakes developers could make.
5. **Overall Functionality (Part 1):** Summarize the functions covered in this first part of the file.

**Analysis of the Code:**

* The file is a unit test (`_unittest.cc`) for a class named `MainThreadEventQueue`.
* The tests use the Google Test framework (`testing/gtest/include/gtest/gtest.h`).
* The code simulates various input events (touch, mouse wheel, mouse) and checks how `MainThreadEventQueue` handles them.
* Concepts like "blocking" and "non-blocking" events, requestAnimationFrame (RAF) alignment, and low-latency mode are central to the tests.
* The tests verify the correct queuing, coalescing, and dispatching of events.
* There are helper classes (`HandledTask`, `HandledEvent`, `HandledClosure`, `ReceivedCallback`, `HandledEventCallbackTracker`) to track the processing of events and callbacks.
* Mocking (`MockWidgetScheduler`) is used to simulate interactions with other components.

**Connecting to Web Technologies:**

* Input events (mouse clicks, touch gestures, scrolling) are fundamental to user interaction in web pages built with HTML, CSS, and JavaScript.
* JavaScript event listeners respond to these events.
* The timing and order of event processing can impact the responsiveness of web applications.
* RAF is a browser mechanism to synchronize animations and other visual updates with the browser's repaint cycle, which is relevant to the "RAF alignment" testing.

**Logical Reasoning Examples:**

* **Input:** Queue a non-blocking mouse wheel event, then another. **Output:** The events should be coalesced into a single event.
* **Input:** Queue a blocking touch event. **Output:** The event should be dispatched and handled before subsequent events if no RAF is triggered. If a RAF is triggered, the event will be dispatched in the RAF callback.

**Common Usage Errors (Inferred from Tests):**

* Incorrectly assuming the order of execution for blocking vs. non-blocking events without considering RAF.
* Misunderstanding the conditions under which events are coalesced.
* Not accounting for the effects of low-latency mode or events marked as "non-blocking due to fling."

**Drafting the Response (Mental Simulation):**

I'll structure the response by addressing each point in the request. For the functionality, I'll focus on the core purpose of testing the `MainThreadEventQueue`. For web tech connections, I'll use concrete examples. For logical reasoning, I'll pick representative test cases and describe their expected behavior. For common errors, I'll think about the implications of the tested behaviors. Finally, I'll provide a concise summary of the tested features in this first part. I will need to be mindful of the "part 1" constraint and focus on what's covered in the provided code snippet.
这是 `blink/renderer/platform/widget/input/main_thread_event_queue_unittest.cc` 文件的第一部分，其主要功能是 **对 `MainThreadEventQueue` 类进行单元测试**。`MainThreadEventQueue`  负责管理和调度主线程上的输入事件。

具体来说，这部分代码测试了以下 `MainThreadEventQueue` 的功能：

1. **事件的排队和调度:**
   - 测试了如何将不同类型的输入事件（例如触摸事件 `WebTouchEvent`，鼠标滚轮事件 `WebMouseWheelEvent`，鼠标事件 `WebMouseEvent`）添加到队列中。
   - 测试了事件在主线程上被调度的时机，包括是否与 requestAnimationFrame (RAF) 对齐。
   - 测试了在没有 RAF 的情况下事件的即时处理。

2. **非阻塞事件的处理:**
   - 测试了标记为非阻塞的事件是如何被处理的，例如 `kSetNonBlocking` 状态。
   - 验证了非阻塞事件可以被合并（coalesce）成一个事件进行处理。

3. **阻塞事件的处理:**
   - 测试了阻塞事件的处理流程，以及它们如何影响后续事件的调度。

4. **requestAnimationFrame (RAF) 对齐:**
   - 测试了事件是否能够与 RAF 信号对齐，从而在浏览器的下一次渲染帧之前处理。
   - 验证了 RAF 如何影响非阻塞和阻塞事件的调度。

5. **低延迟模式:**
   - 测试了低延迟模式下事件的处理方式，通常会导致事件更早被处理，不等待 RAF。

6. **在 Fling 期间的事件处理:**
   - 测试了在页面惯性滑动（fling）期间触摸事件的处理，例如 `kSetNonBlockingDueToFling` 状态。

7. **事件时间戳记录:**
   - 验证了事件被添加到队列时的时间戳是否被正确记录。

8. **闭包（Closure）的排队和执行:**
   - 测试了如何将闭包（函数回调）添加到事件队列中并在主线程上执行。
   - 测试了闭包与事件混合排队的情况。

9. **TouchMove 事件的处理逻辑:**
   - 测试了 `TouchMove` 事件在特定条件下的调度和处理，例如从阻塞变为非阻塞的情况。
   - 验证了在 `TouchStart` 或首次 `TouchMove` 没有被消费时，后续的 `TouchMove` 事件可能变为非阻塞。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`MainThreadEventQueue` 负责处理浏览器接收到的用户输入事件，这些事件是与用户在 HTML 页面上的交互直接相关的。JavaScript 代码可以通过事件监听器来捕获和处理这些事件，从而实现页面的动态行为。CSS 可能会受到 JavaScript 事件处理的影响，例如通过 JavaScript 修改 CSS 样式来响应用户输入。

* **JavaScript:** 当用户点击一个 HTML 元素时，浏览器会生成一个鼠标点击事件。`MainThreadEventQueue` 负责接收和调度这个事件。JavaScript 中注册的 `click` 事件监听器会在该事件被调度到主线程后被触发执行。

   ```javascript
   document.getElementById('myButton').addEventListener('click', function() {
     console.log('Button clicked!'); // 这段 JavaScript 代码会被执行
   });
   ```

* **HTML:** HTML 定义了用户可以交互的元素，例如按钮、链接、输入框等。用户的操作会触发各种输入事件，这些事件会进入 `MainThreadEventQueue`。

   ```html
   <button id="myButton">Click Me</button>
   ```

* **CSS:**  CSS 可以通过伪类（例如 `:hover`, `:active`）响应某些输入事件，但这通常发生在合成器线程或更早的阶段。`MainThreadEventQueue` 主要处理发送到主线程的事件，这些事件通常会触发 JavaScript 代码的执行，而 JavaScript 代码可能会修改元素的 CSS 样式。

   ```css
   #myButton:hover {
     background-color: lightblue; // 鼠标悬停时的样式变化
   }
   ```

**逻辑推理的假设输入与输出:**

**假设输入 1:**  连续快速地触发两个非阻塞的鼠标滚轮事件。

**预期输出 1:**  `MainThreadEventQueue` 会将这两个滚轮事件合并成一个事件进行处理，以提高效率。处理回调会指示这两个事件被合并处理。

**假设输入 2:**  触发一个阻塞的触摸开始事件 (`TouchStart`)，然后触发一系列阻塞的触摸移动事件 (`TouchMove`)。

**预期输出 2:**  如果触摸开始事件没有被 JavaScript 消费，后续的触摸移动事件可能会被 `MainThreadEventQueue` 标记为非阻塞，以便更流畅地处理触摸移动。

**涉及用户或编程常见的使用错误 (基于测试内容推断):**

1. **错误地假设非阻塞事件会立即执行所有监听器:** 开发者可能会认为标记为非阻塞的事件会立即同步地执行所有 JavaScript 监听器。但实际上，非阻塞事件可能会在 RAF 期间处理，并且不会阻止其他事件的处理。

   **示例:** 开发者在非阻塞的 `touchmove` 事件监听器中执行了耗时的同步操作，期望能立即完成，但由于事件是非阻塞的，可能会导致页面掉帧或性能问题。

2. **没有考虑到 RAF 对事件处理的影响:** 开发者可能会忽略 RAF 对事件调度的影响，尤其是在处理动画或需要同步更新 UI 的场景中。

   **示例:** 开发者希望在某个事件发生后立即更新 UI，但如果没有正确利用 RAF，更新可能会延迟到下一个渲染帧，导致视觉上的不连贯。

3. **对阻塞和非阻塞事件的理解不足:** 开发者可能不清楚哪些操作会导致事件被标记为阻塞或非阻塞，从而在需要高性能的交互场景下使用了阻塞事件，导致卡顿。

   **示例:**  在一个需要快速响应的拖拽操作中，如果触摸移动事件被意外地标记为阻塞，可能会导致拖拽操作不流畅。

**功能归纳 (第 1 部分):**

这部分 `main_thread_event_queue_unittest.cc` 文件的主要功能是 **全面测试 `MainThreadEventQueue` 类的核心事件管理和调度逻辑**，包括不同类型事件的排队、阻塞和非阻塞处理、与 RAF 的交互、低延迟模式以及在特定场景下（如 fling 期间）的事件处理行为。它通过模拟各种输入场景和断言输出来验证 `MainThreadEventQueue` 是否按照预期工作，确保浏览器能够正确且高效地处理用户输入。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/main_thread_event_queue_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/widget/input/main_thread_event_queue.h"

#include <stddef.h>

#include <new>
#include <tuple>
#include <utility>

#include "base/auto_reset.h"
#include "base/containers/adapters.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ref.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/string_util.h"
#include "base/test/test_simple_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/metrics/event_metrics.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/synthetic_web_input_event_builders.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/platform/scheduler/test/web_mock_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_widget_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

// Simulate a 16ms frame signal.
const base::TimeDelta kFrameInterval = base::Milliseconds(16);

bool Equal(const WebTouchEvent& lhs, const WebTouchEvent& rhs) {
  auto tie = [](const WebTouchEvent& e) {
    return std::make_tuple(
        e.touches_length, e.dispatch_type, e.moved_beyond_slop_region,
        e.hovering, e.touch_start_or_first_touch_move, e.unique_touch_event_id,
        e.GetType(), e.TimeStamp(), e.FrameScale(), e.FrameTranslate(),
        e.GetModifiers());
  };
  if (tie(lhs) != tie(rhs))
    return false;

  for (unsigned i = 0; i < lhs.touches_length; ++i) {
    auto touch_tie = [](const blink::WebTouchPoint& e) {
      return std::make_tuple(e.state, e.radius_x, e.radius_y, e.rotation_angle,
                             e.id, e.tilt_x, e.tilt_y, e.tangential_pressure,
                             e.twist, e.button, e.pointer_type, e.movement_x,
                             e.movement_y, e.is_raw_movement_event,
                             e.PositionInWidget(), e.PositionInScreen());
    };

    if (touch_tie(lhs.touches[i]) != touch_tie(rhs.touches[i]) ||
        (!std::isnan(lhs.touches[i].force) &&
         !std::isnan(rhs.touches[i].force) &&
         lhs.touches[i].force != rhs.touches[i].force))
      return false;
  }

  return true;
}

bool Equal(const WebMouseWheelEvent& lhs, const WebMouseWheelEvent& rhs) {
  auto tie = [](const WebMouseWheelEvent& e) {
    return std::make_tuple(
        e.delta_x, e.delta_y, e.wheel_ticks_x, e.wheel_ticks_y,
        e.acceleration_ratio_x, e.acceleration_ratio_y, e.phase,
        e.momentum_phase, e.rails_mode, e.dispatch_type, e.event_action,
        e.has_synthetic_phase, e.delta_units, e.click_count, e.menu_source_type,
        e.id, e.button, e.movement_x, e.movement_y, e.is_raw_movement_event,
        e.GetType(), e.TimeStamp(), e.FrameScale(), e.FrameTranslate(),
        e.GetModifiers(), e.PositionInWidget(), e.PositionInScreen());
  };
  return tie(lhs) == tie(rhs);
}

}  // namespace

class HandledTask {
 public:
  virtual ~HandledTask() = default;

  virtual blink::WebCoalescedInputEvent* taskAsEvent() = 0;
  virtual unsigned taskAsClosure() const = 0;
  virtual void Print(std::ostream* os) const = 0;

  friend void PrintTo(const HandledTask& task, std::ostream* os) {
    task.Print(os);
  }
};

class HandledEvent : public HandledTask {
 public:
  explicit HandledEvent(const blink::WebCoalescedInputEvent& event)
      : event_(event) {}
  ~HandledEvent() override = default;

  blink::WebCoalescedInputEvent* taskAsEvent() override { return &event_; }
  unsigned taskAsClosure() const override { NOTREACHED(); }

  void Print(std::ostream* os) const override {
    *os << "event_type: " << event_.Event().GetType();
    if (WebInputEvent::IsTouchEventType(event_.Event().GetType())) {
      auto& touch_event = static_cast<const WebTouchEvent&>(event_.Event());
      *os << " touch_id: " << touch_event.unique_touch_event_id
          << " dispatch_type: " << touch_event.dispatch_type;
    }
  }

 private:
  blink::WebCoalescedInputEvent event_;
};

class HandledClosure : public HandledTask {
 public:
  explicit HandledClosure(unsigned closure_id) : closure_id_(closure_id) {}
  ~HandledClosure() override = default;

  blink::WebCoalescedInputEvent* taskAsEvent() override { NOTREACHED(); }
  unsigned taskAsClosure() const override { return closure_id_; }
  void Print(std::ostream* os) const override { NOTREACHED(); }

 private:
  unsigned closure_id_;
};

enum class CallbackReceivedState {
  kPending,
  kCalledWhileHandlingEvent,
  kCalledAfterHandleEvent,
};

void PrintTo(CallbackReceivedState state, std::ostream* os) {
  const char* kCallbackReceivedStateToString[] = {
      "Pending", "CalledWhileHandlingEvent", "CalledAfterHandleEvent"};
  *os << kCallbackReceivedStateToString[static_cast<int>(state)];
}

class ReceivedCallback {
 public:
  ReceivedCallback()
      : ReceivedCallback(CallbackReceivedState::kPending, false, kNotFound) {}

  ReceivedCallback(CallbackReceivedState state,
                   bool coalesced_latency,
                   wtf_size_t after_handled_tasks = kNotFound)
      : state_(state),
        coalesced_latency_(coalesced_latency),
        after_handled_tasks_(after_handled_tasks) {}
  bool operator==(const ReceivedCallback& other) const {
    return state_ == other.state_ &&
           coalesced_latency_ == other.coalesced_latency_ &&
           after_handled_tasks_ == other.after_handled_tasks_;
  }
  friend void PrintTo(const ReceivedCallback& callback, std::ostream* os) {
    PrintTo(callback.state_, os);
    if (callback.coalesced_latency_) {
      *os << " coalesced";
    }
    *os << " after_handled_tasks=" << callback.after_handled_tasks_;
  }

 private:
  CallbackReceivedState state_;
  bool coalesced_latency_;
  // The number of handled tasks when the callback is run, for tests to check
  // the order of event handling and callbacks.
  wtf_size_t after_handled_tasks_;
};

class HandledEventCallbackTracker {
 public:
  explicit HandledEventCallbackTracker(
      const Vector<std::unique_ptr<HandledTask>>& handled_tasks)
      : handling_event_(false), handled_tasks_(handled_tasks) {
    weak_this_ = weak_ptr_factory_.GetWeakPtr();
  }

  HandledEventCallback GetCallback() {
    callbacks_received_.push_back(ReceivedCallback());
    HandledEventCallback callback =
        base::BindOnce(&HandledEventCallbackTracker::DidHandleEvent, weak_this_,
                       callbacks_received_.size() - 1);
    return callback;
  }

  void DidHandleEvent(wtf_size_t index,
                      blink::mojom::InputEventResultState ack_result,
                      const ui::LatencyInfo& latency,
                      mojom::blink::DidOverscrollParamsPtr params,
                      std::optional<cc::TouchAction> touch_action) {
    callbacks_received_[index] = ReceivedCallback(
        handling_event_ ? CallbackReceivedState::kCalledWhileHandlingEvent
                        : CallbackReceivedState::kCalledAfterHandleEvent,
        latency.coalesced(), handled_tasks_->size());
  }

  const Vector<ReceivedCallback>& GetReceivedCallbacks() const {
    return callbacks_received_;
  }

  bool handling_event_;

 private:
  Vector<ReceivedCallback> callbacks_received_;
  const raw_ref<const Vector<std::unique_ptr<HandledTask>>> handled_tasks_;
  base::WeakPtr<HandledEventCallbackTracker> weak_this_;
  base::WeakPtrFactory<HandledEventCallbackTracker> weak_ptr_factory_{this};
};

MATCHER_P3(IsHandledTouchEvent, event_type, touch_id, dispatch_type, "") {
  CHECK(WebInputEvent::IsTouchEventType(event_type));
  auto& event = static_cast<const WebTouchEvent&>(arg->taskAsEvent()->Event());
  return event.GetType() == event_type &&
         event.unique_touch_event_id == touch_id &&
         event.dispatch_type == dispatch_type;
}

class MockWidgetScheduler : public scheduler::FakeWidgetScheduler {
 public:
  MockWidgetScheduler() = default;

  MOCK_METHOD3(DidHandleInputEventOnMainThread,
               void(const WebInputEvent&, WebInputEventResult, bool));
};

class MainThreadEventQueueTest : public testing::Test,
                                 public MainThreadEventQueueClient {
 public:
  MainThreadEventQueueTest()
      : main_task_runner_(new base::TestSimpleTaskRunner()) {
    widget_scheduler_ = base::MakeRefCounted<MockWidgetScheduler>();
    handler_callback_ =
        std::make_unique<HandledEventCallbackTracker>(handled_tasks_);
  }

  void SetUp() override {
    queue_ = base::MakeRefCounted<MainThreadEventQueue>(
        this, main_task_runner_, main_task_runner_, widget_scheduler_, true);
    queue_->ClearRafFallbackTimerForTesting();
  }

  void HandleEvent(const WebInputEvent& event,
                   blink::mojom::InputEventResultState ack_result) {
    base::AutoReset<bool> in_handle_event(&handler_callback_->handling_event_,
                                          true);
    queue_->HandleEvent(std::make_unique<blink::WebCoalescedInputEvent>(
                            event.Clone(), ui::LatencyInfo()),
                        MainThreadEventQueue::DispatchType::kBlocking,
                        ack_result, blink::WebInputEventAttribution(), nullptr,
                        handler_callback_->GetCallback());
  }

  void RunClosure(unsigned closure_id) {
    auto closure = std::make_unique<HandledClosure>(closure_id);
    handled_tasks_.push_back(std::move(closure));
  }

  void QueueClosure() {
    unsigned closure_id = ++closure_count_;
    queue_->QueueClosure(base::BindOnce(&MainThreadEventQueueTest::RunClosure,
                                        base::Unretained(this), closure_id));
  }

  MainThreadEventQueueTaskList& event_queue() {
    return queue_->shared_state_.events_;
  }

  bool needs_low_latency_until_pointer_up() {
    return queue_->needs_low_latency_until_pointer_up_;
  }

  bool last_touch_start_forced_nonblocking_due_to_fling() {
    return queue_->compositor_thread_only_
        .last_touch_start_forced_nonblocking_due_to_fling;
  }

  void RunPendingTasksWithSimulatedRaf() {
    while (needs_main_frame_ || main_task_runner_->HasPendingTask()) {
      main_task_runner_->RunUntilIdle();
      needs_main_frame_ = false;
      frame_time_ += kFrameInterval;
      queue_->DispatchRafAlignedInput(frame_time_);
    }
  }

  void RunSimulatedRafOnce() {
    if (needs_main_frame_) {
      needs_main_frame_ = false;
      frame_time_ += kFrameInterval;
      queue_->DispatchRafAlignedInput(frame_time_);
    }
  }

  void RunPendingTasksWithoutRaf() { main_task_runner_->RunUntilIdle(); }

  // MainThreadEventQueueClient overrides.
  bool HandleInputEvent(const blink::WebCoalescedInputEvent& event,
                        std::unique_ptr<cc::EventMetrics> metrics,
                        HandledEventCallback callback) override {
    if (will_handle_input_event_callback_) {
      will_handle_input_event_callback_.Run(event);
    }

    if (!handle_input_event_)
      return false;
    auto handled_event = std::make_unique<HandledEvent>(event);
    handled_tasks_.push_back(std::move(handled_event));
    std::move(callback).Run(main_thread_ack_state_, event.latency_info(),
                            nullptr, std::nullopt);
    return true;
  }
  void InputEventsDispatched(bool raf_aligned) override {
    if (raf_aligned)
      raf_aligned_events_dispatched_ = true;
    else
      non_raf_aligned_events_dispatched_ = true;
  }
  void SetNeedsMainFrame() override { needs_main_frame_ = true; }
  bool RequestedMainFramePending() override { return needs_main_frame_; }

  Vector<ReceivedCallback> GetAndResetCallbackResults() {
    std::unique_ptr<HandledEventCallbackTracker> callback =
        std::make_unique<HandledEventCallbackTracker>(handled_tasks_);
    handler_callback_.swap(callback);
    return callback->GetReceivedCallbacks();
  }

  void set_handle_input_event(bool handle) { handle_input_event_ = handle; }

  void set_main_thread_ack_state(blink::mojom::InputEventResultState state) {
    main_thread_ack_state_ = state;
  }

 protected:
  scoped_refptr<base::TestSimpleTaskRunner> main_task_runner_;
  scoped_refptr<MockWidgetScheduler> widget_scheduler_;
  scoped_refptr<MainThreadEventQueue> queue_;
  Vector<std::unique_ptr<HandledTask>> handled_tasks_;
  std::unique_ptr<HandledEventCallbackTracker> handler_callback_;

  bool needs_main_frame_ = false;
  bool handle_input_event_ = true;
  bool raf_aligned_events_dispatched_ = false;
  bool non_raf_aligned_events_dispatched_ = false;
  base::TimeTicks frame_time_;
  blink::mojom::InputEventResultState main_thread_ack_state_ =
      blink::mojom::InputEventResultState::kNotConsumed;
  unsigned closure_count_ = 0;

  // This allows a test to simulate concurrent action in the compositor thread
  // when the main thread is dispatching events in the queue.
  base::RepeatingCallback<void(const blink::WebCoalescedInputEvent&)>
      will_handle_input_event_callback_;
};

TEST_F(MainThreadEventQueueTest, ClientDoesntHandleInputEvent) {
  // Prevent MainThreadEventQueueClient::HandleInputEvent() from handling the
  // event, and have it return false. Then the MainThreadEventQueue should
  // call the handled callback.
  set_handle_input_event(false);

  // The blocking event used in this test is reported to the scheduler.
  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(1);

  // Inject and try to dispatch an input event. This event is not considered
  // "non-blocking" which means the reply callback gets stored with the queued
  // event, and will be run when we work through the queue.
  SyntheticWebTouchEvent event;
  event.PressPoint(10, 10);
  event.MovePoint(0, 20, 20);
  WebMouseWheelEvent event2 = SyntheticWebMouseWheelEventBuilder::Build(
      10, 10, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel);
  HandleEvent(event2, blink::mojom::InputEventResultState::kNotConsumed);
  RunPendingTasksWithSimulatedRaf();

  Vector<ReceivedCallback> received = GetAndResetCallbackResults();
  // We didn't handle the event in the client method.
  EXPECT_EQ(handled_tasks_.size(), 0u);
  // There's 1 reply callback for our 1 event.
  EXPECT_EQ(received.size(), 1u);
  // The event was queued and disaptched, then the callback was run when
  // the client failed to handle it. If this fails, the callback was run
  // by HandleEvent() without dispatching it (kCalledWhileHandlingEvent)
  // or was not called at all (kPending).
  EXPECT_THAT(received,
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 0)));
}

TEST_F(MainThreadEventQueueTest, NonBlockingWheel) {
  WebMouseWheelEvent kEvents[4] = {
      SyntheticWebMouseWheelEventBuilder::Build(
          10, 10, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel),
      SyntheticWebMouseWheelEventBuilder::Build(
          20, 20, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel),
      SyntheticWebMouseWheelEventBuilder::Build(
          30, 30, 0, 53, 1, ui::ScrollGranularity::kScrollByPixel),
      SyntheticWebMouseWheelEventBuilder::Build(
          30, 30, 0, 53, 1, ui::ScrollGranularity::kScrollByPixel),
  };

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(0);

  for (WebMouseWheelEvent& event : kEvents)
    HandleEvent(event, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(2u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(2u, handled_tasks_.size());
  for (const auto& task : handled_tasks_) {
    EXPECT_EQ(2u, task->taskAsEvent()->CoalescedEventSize());
  }

  {
    EXPECT_EQ(kEvents[0].GetType(),
              handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
    const WebMouseWheelEvent* last_wheel_event =
        static_cast<const WebMouseWheelEvent*>(
            handled_tasks_.at(0)->taskAsEvent()->EventPointer());
    EXPECT_EQ(WebInputEvent::DispatchType::kListenersNonBlockingPassive,
              last_wheel_event->dispatch_type);
    WebMouseWheelEvent coalesced_event = kEvents[0];
    coalesced_event.Coalesce(kEvents[1]);
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *last_wheel_event));
  }

  {
    WebMouseWheelEvent coalesced_event = kEvents[0];
    const auto& coalesced_events =
        handled_tasks_[0]->taskAsEvent()->GetCoalescedEventsPointers();
    const WebMouseWheelEvent* coalesced_wheel_event0 =
        static_cast<const WebMouseWheelEvent*>(coalesced_events[0].get());
    EXPECT_TRUE(Equal(coalesced_event, *coalesced_wheel_event0));

    coalesced_event = kEvents[1];
    const WebMouseWheelEvent* coalesced_wheel_event1 =
        static_cast<const WebMouseWheelEvent*>(coalesced_events[1].get());
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *coalesced_wheel_event1));
  }

  {
    const WebMouseWheelEvent* last_wheel_event =
        static_cast<const WebMouseWheelEvent*>(
            handled_tasks_.at(1)->taskAsEvent()->EventPointer());
    WebMouseWheelEvent coalesced_event = kEvents[2];
    coalesced_event.Coalesce(kEvents[3]);
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *last_wheel_event));
  }

  {
    WebMouseWheelEvent coalesced_event = kEvents[2];
    const auto& coalesced_events =
        handled_tasks_[1]->taskAsEvent()->GetCoalescedEventsPointers();
    const WebMouseWheelEvent* coalesced_wheel_event0 =
        static_cast<const WebMouseWheelEvent*>(coalesced_events[0].get());
    EXPECT_TRUE(Equal(coalesced_event, *coalesced_wheel_event0));

    coalesced_event = kEvents[3];
    const WebMouseWheelEvent* coalesced_wheel_event1 =
        static_cast<const WebMouseWheelEvent*>(coalesced_events[1].get());
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *coalesced_wheel_event1));
  }
}

TEST_F(MainThreadEventQueueTest, NonBlockingTouch) {
  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(0);

  SyntheticWebTouchEvent kEvents[4];
  kEvents[0].PressPoint(10, 10);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].SetModifiers(1);
  kEvents[1].MovePoint(0, 20, 20);
  kEvents[2].PressPoint(10, 10);
  kEvents[2].MovePoint(0, 30, 30);
  kEvents[3].PressPoint(10, 10);
  kEvents[3].MovePoint(0, 35, 35);

  for (SyntheticWebTouchEvent& event : kEvents)
    HandleEvent(event, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(3u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(3u, handled_tasks_.size());

  EXPECT_EQ(kEvents[0].GetType(),
            handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
  const WebTouchEvent* last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(0)->taskAsEvent()->EventPointer());
  SyntheticWebTouchEvent non_blocking_touch = kEvents[0];
  non_blocking_touch.dispatch_type =
      WebInputEvent::DispatchType::kListenersNonBlockingPassive;
  EXPECT_TRUE(Equal(non_blocking_touch, *last_touch_event));

  {
    EXPECT_EQ(1u, handled_tasks_[0]->taskAsEvent()->CoalescedEventSize());
    const WebTouchEvent* coalesced_touch_event =
        static_cast<const WebTouchEvent*>(handled_tasks_[0]
                                              ->taskAsEvent()
                                              ->GetCoalescedEventsPointers()[0]
                                              .get());
    EXPECT_TRUE(Equal(kEvents[0], *coalesced_touch_event));
  }

  EXPECT_EQ(kEvents[1].GetType(),
            handled_tasks_.at(1)->taskAsEvent()->Event().GetType());
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(1)->taskAsEvent()->EventPointer());
  non_blocking_touch = kEvents[1];
  non_blocking_touch.dispatch_type =
      WebInputEvent::DispatchType::kListenersNonBlockingPassive;
  EXPECT_TRUE(Equal(non_blocking_touch, *last_touch_event));

  {
    EXPECT_EQ(1u, handled_tasks_[1]->taskAsEvent()->CoalescedEventSize());
    const WebTouchEvent* coalesced_touch_event =
        static_cast<const WebTouchEvent*>(handled_tasks_[1]
                                              ->taskAsEvent()
                                              ->GetCoalescedEventsPointers()[0]
                                              .get());
    EXPECT_TRUE(Equal(kEvents[1], *coalesced_touch_event));
  }

  {
    EXPECT_EQ(kEvents[2].GetType(),
              handled_tasks_.at(2)->taskAsEvent()->Event().GetType());
    last_touch_event = static_cast<const WebTouchEvent*>(
        handled_tasks_.at(2)->taskAsEvent()->EventPointer());
    WebTouchEvent coalesced_event = kEvents[2];
    coalesced_event.Coalesce(kEvents[3]);
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *last_touch_event));
  }

  {
    EXPECT_EQ(2u, handled_tasks_[2]->taskAsEvent()->CoalescedEventSize());
    WebTouchEvent coalesced_event = kEvents[2];
    const auto& coalesced_events =
        handled_tasks_[2]->taskAsEvent()->GetCoalescedEventsPointers();
    const WebTouchEvent* coalesced_touch_event0 =
        static_cast<const WebTouchEvent*>(coalesced_events[0].get());
    EXPECT_TRUE(Equal(coalesced_event, *coalesced_touch_event0));

    coalesced_event = kEvents[3];
    const WebTouchEvent* coalesced_touch_event1 =
        static_cast<const WebTouchEvent*>(coalesced_events[1].get());
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *coalesced_touch_event1));
  }
}

TEST_F(MainThreadEventQueueTest, BlockingTouch) {
  SyntheticWebTouchEvent kEvents[4];
  kEvents[0].PressPoint(10, 10);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 20, 20);
  kEvents[2].PressPoint(10, 10);
  kEvents[2].MovePoint(0, 30, 30);
  kEvents[3].PressPoint(10, 10);
  kEvents[3].MovePoint(0, 35, 35);

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(3);
  {
    // Ensure that coalescing takes place.
    HandleEvent(kEvents[0],
                blink::mojom::InputEventResultState::kSetNonBlocking);
    HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
    HandleEvent(kEvents[2], blink::mojom::InputEventResultState::kNotConsumed);
    HandleEvent(kEvents[3], blink::mojom::InputEventResultState::kNotConsumed);

    EXPECT_EQ(2u, event_queue().size());
    EXPECT_TRUE(main_task_runner_->HasPendingTask());
    RunPendingTasksWithSimulatedRaf();

    EXPECT_THAT(
        GetAndResetCallbackResults(),
        testing::ElementsAre(
            ReceivedCallback(CallbackReceivedState::kCalledWhileHandlingEvent,
                             false, 0),
            ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                             false, 2),
            ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                             true, 2),
            ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                             true, 2)));
    EXPECT_EQ(0u, event_queue().size());

    const WebTouchEvent* last_touch_event = static_cast<const WebTouchEvent*>(
        handled_tasks_.at(1)->taskAsEvent()->EventPointer());
    EXPECT_EQ(kEvents[1].unique_touch_event_id,
              last_touch_event->unique_touch_event_id);
  }

  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kEvents[2], blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kEvents[3], blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(1u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 2)));
}

TEST_F(MainThreadEventQueueTest, InterleavedEvents) {
  WebMouseWheelEvent kWheelEvents[2] = {
      SyntheticWebMouseWheelEventBuilder::Build(
          10, 10, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel),
      SyntheticWebMouseWheelEventBuilder::Build(
          20, 20, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel),
  };
  SyntheticWebTouchEvent kTouchEvents[2];
  kTouchEvents[0].PressPoint(10, 10);
  kTouchEvents[0].MovePoint(0, 20, 20);
  kTouchEvents[1].PressPoint(10, 10);
  kTouchEvents[1].MovePoint(0, 30, 30);

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(0);

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  HandleEvent(kWheelEvents[0],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kTouchEvents[0],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kWheelEvents[1],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kTouchEvents[1],
              blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(2u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(2u, handled_tasks_.size());
  {
    EXPECT_EQ(kWheelEvents[0].GetType(),
              handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
    const WebMouseWheelEvent* last_wheel_event =
        static_cast<const WebMouseWheelEvent*>(
            handled_tasks_.at(0)->taskAsEvent()->EventPointer());
    EXPECT_EQ(WebInputEvent::DispatchType::kListenersNonBlockingPassive,
              last_wheel_event->dispatch_type);
    WebMouseWheelEvent coalesced_event = kWheelEvents[0];
    coalesced_event.Coalesce(kWheelEvents[1]);
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *last_wheel_event));
  }
  {
    EXPECT_EQ(kTouchEvents[0].GetType(),
              handled_tasks_.at(1)->taskAsEvent()->Event().GetType());
    const WebTouchEvent* last_touch_event = static_cast<const WebTouchEvent*>(
        handled_tasks_.at(1)->taskAsEvent()->EventPointer());
    WebTouchEvent coalesced_event = kTouchEvents[0];
    coalesced_event.Coalesce(kTouchEvents[1]);
    coalesced_event.dispatch_type =
        WebInputEvent::DispatchType::kListenersNonBlockingPassive;
    EXPECT_TRUE(Equal(coalesced_event, *last_touch_event));
  }
}

TEST_F(MainThreadEventQueueTest, RafAlignedMouseInput) {
  WebMouseEvent mouseDown = SyntheticWebMouseEventBuilder::Build(
      WebInputEvent::Type::kMouseDown, 10, 10, 0);

  WebMouseEvent mouseMove = SyntheticWebMouseEventBuilder::Build(
      WebInputEvent::Type::kMouseMove, 10, 10, 0);

  WebMouseEvent mouseUp = SyntheticWebMouseEventBuilder::Build(
      WebInputEvent::Type::kMouseUp, 10, 10, 0);

  WebMouseWheelEvent wheelEvents[3] = {
      SyntheticWebMouseWheelEventBuilder::Build(
          10, 10, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel),
      SyntheticWebMouseWheelEventBuilder::Build(
          20, 20, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel),
      SyntheticWebMouseWheelEventBuilder::Build(
          20, 20, 0, 53, 1, ui::ScrollGranularity::kScrollByPixel),
  };

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(0);

  // Simulate enqueing a discrete event, followed by continuous events and
  // then a discrete event. The last discrete event should flush the
  // continuous events so the aren't aligned to rAF and are processed
  // immediately.
  HandleEvent(mouseDown, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(mouseMove, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(wheelEvents[0],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(wheelEvents[1],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(mouseUp, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(4u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_EQ(0u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));

  // Simulate the rAF running before the PostTask occurs. The rAF
  // will consume everything.
  HandleEvent(mouseDown, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(wheelEvents[0],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(needs_main_frame_);
  RunSimulatedRafOnce();
  EXPECT_FALSE(needs_main_frame_);
  EXPECT_EQ(0u, event_queue().size());
  main_task_runner_->RunUntilIdle();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 4)));

  // Simulate event consumption but no rAF signal. The mouse wheel events
  // should still be in the queue.
  handled_tasks_.clear();
  HandleEvent(mouseDown, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(wheelEvents[0],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(mouseUp, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(wheelEvents[2],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(wheelEvents[0],
              blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(5u, event_queue().size());
  EXPECT_TRUE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_TRUE(needs_main_frame_);
  EXPECT_EQ(2u, event_queue().size());
  RunSimulatedRafOnce();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  EXPECT_EQ(wheelEvents[2].GetModifiers(),
            handled_tasks_.at(3)->taskAsEvent()->Event().GetModifiers());
  EXPECT_EQ(wheelEvents[0].GetModifiers(),
            handled_tasks_.at(4)->taskAsEvent()->Event().GetModifiers());
}

TEST_F(MainThreadEventQueueTest, RafAlignedTouchInput) {
  SyntheticWebTouchEvent kEvents[3];
  kEvents[0].PressPoint(10, 10);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 50, 50);
  kEvents[2].PressPoint(10, 10);
  kEvents[2].ReleasePoint(0);

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(3);

  // Simulate enqueing a discrete event, followed by continuous events and
  // then a discrete event. The last discrete event should flush the
  // continuous events so the aren't aligned to rAF and are processed
  // immediately.
  for (SyntheticWebTouchEvent& event : kEvents)
    HandleEvent(event, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(3u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_EQ(0u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));

  // Simulate the rAF running before the PostTask occurs. The rAF
  // will consume everything.
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(needs_main_frame_);
  RunSimulatedRafOnce();
  EXPECT_FALSE(needs_main_frame_);
  EXPECT_EQ(0u, event_queue().size());
  main_task_runner_->RunUntilIdle();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 3)));

  // Simulate event consumption but no rAF signal. The touch events
  // should still be in the queue.
  handled_tasks_.clear();
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_TRUE(needs_main_frame_);
  EXPECT_EQ(1u, event_queue().size());
  RunSimulatedRafOnce();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));

  // Simulate the touch move being discrete
  kEvents[0].touch_start_or_first_touch_move = true;
  kEvents[1].touch_start_or_first_touch_move = true;

  for (SyntheticWebTouchEvent& event : kEvents)
    HandleEvent(event, blink::mojom::InputEventResultState::kNotConsumed);

  EXPECT_EQ(3u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_THAT(
      GetAndResetCallbackResults(),
      testing::ElementsAre(
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 3),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 4),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 5)));
}

TEST_F(MainThreadEventQueueTest, RafAlignedTouchInputCoalescedMoves) {
  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[0].MovePoint(0, 50, 50);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 20, 20);
  kEvents[0].dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(4);

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  {
    // Send a non-blocking input event and then blocking  event.
    // The events should coalesce together.
    HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
    EXPECT_EQ(1u, event_queue().size());
    EXPECT_FALSE(main_task_runner_->HasPendingTask());
    EXPECT_TRUE(needs_main_frame_);
    HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
    EXPECT_EQ(1u, event_queue().size());
    EXPECT_FALSE(main_task_runner_->HasPendingTask());
    EXPECT_TRUE(needs_main_frame_);
    RunPendingTasksWithSimulatedRaf();
    EXPECT_EQ(0u, event_queue().size());
    EXPECT_THAT(
        GetAndResetCallbackResults(),
        testing::ElementsAre(
            ReceivedCallback(CallbackReceivedState::kCalledWhileHandlingEvent,
                             false, 0),
            ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                             true, 1)));
  }

  // Send a non-cancelable ack required event, and then a non-ack
  // required event they should be coalesced together.
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 1)));

  // Send a non-ack required event, and then a non-cancelable ack
  // required event they should be coalesced together.
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kSetNonBlocking);
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 2)));
}

TEST_F(MainThreadEventQueueTest, RafAlignedTouchInputThrottlingMoves) {
  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(3);

  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[0].MovePoint(0, 50, 50);
  kEvents[0].dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 20, 20);
  kEvents[1].dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  // Send a non-cancelable touch move and then send it another one. The
  // second one shouldn't go out with the next rAF call and should be throttled.
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);

  // Event should still be in queue after handling a single rAF call.
  RunSimulatedRafOnce();
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);

  // And should eventually flush.
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 1)));
  EXPECT_EQ(0u, event_queue().size());
}

TEST_F(MainThreadEventQueueTest, LowLatency) {
  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 50, 50);

  queue_->SetNeedsLowLatency(true);
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(0);

  for (SyntheticWebTouchEvent& event : kEvents)
    HandleEvent(event, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());

  WebMouseEvent mouse_move = SyntheticWebMouseEventBuilder::Build(
      WebInputEvent::Type::kMouseMove, 10, 10, 0);
  WebMouseWheelEvent mouse_wheel = SyntheticWebMouseWheelEventBuilder::Build(
      10, 10, 0, 53, 0, ui::ScrollGranularity::kScrollByPixel);

  HandleEvent(mouse_move, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(mouse_wheel,
              blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 2)));
  EXPECT_EQ(0u, event_queue().size());

  // Now turn off low latency mode.
  queue_->SetNeedsLowLatency(false);
  for (SyntheticWebTouchEvent& event : kEvents)
    HandleEvent(event, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 4)));
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());

  HandleEvent(mouse_move, blink::mojom::InputEventResultState::kSetNonBlocking);
  HandleEvent(mouse_wheel,
              blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(2u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_TRUE(needs_main_frame_);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 6)));
  EXPECT_EQ(0u, event_queue().size());
}

TEST_F(MainThreadEventQueueTest, BlockingTouchesDuringFling) {
  SyntheticWebTouchEvent kEvents;
  kEvents.PressPoint(10, 10);
  kEvents.touch_start_or_first_touch_move = true;

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(4);

  EXPECT_FALSE(last_touch_start_forced_nonblocking_due_to_fling());
  HandleEvent(kEvents,
              blink::mojom::InputEventResultState::kSetNonBlockingDueToFling);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 0)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(1u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
  EXPECT_TRUE(last_touch_start_forced_nonblocking_due_to_fling());
  const WebTouchEvent* last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(0)->taskAsEvent()->EventPointer());
  kEvents.dispatch_type =
      WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));

  kEvents.MovePoint(0, 30, 30);
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  HandleEvent(kEvents,
              blink::mojom::InputEventResultState::kSetNonBlockingDueToFling);
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledWhileHandlingEvent, false, 1)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(2u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(1)->taskAsEvent()->Event().GetType());
  EXPECT_TRUE(last_touch_start_forced_nonblocking_due_to_fling());
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(1)->taskAsEvent()->EventPointer());
  kEvents.dispatch_type =
      WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));

  kEvents.MovePoint(0, 50, 50);
  kEvents.touch_start_or_first_touch_move = false;
  HandleEvent(kEvents,
              blink::mojom::InputEventResultState::kSetNonBlockingDueToFling);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 3)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(3u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(2)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(kEvents.dispatch_type, WebInputEvent::DispatchType::kBlocking);
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(2)->taskAsEvent()->EventPointer());
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));

  kEvents.ReleasePoint(0);
  HandleEvent(kEvents,
              blink::mojom::InputEventResultState::kSetNonBlockingDueToFling);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 4)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(4u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(3)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(kEvents.dispatch_type, WebInputEvent::DispatchType::kBlocking);
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(3)->taskAsEvent()->EventPointer());
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));
}

TEST_F(MainThreadEventQueueTest, BlockingTouchesOutsideFling) {
  SyntheticWebTouchEvent kEvents;
  kEvents.PressPoint(10, 10);
  kEvents.touch_start_or_first_touch_move = true;

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(4);

  HandleEvent(kEvents, blink::mojom::InputEventResultState::kNotConsumed);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 1)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(1u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(kEvents.dispatch_type, WebInputEvent::DispatchType::kBlocking);
  EXPECT_FALSE(last_touch_start_forced_nonblocking_due_to_fling());
  const WebTouchEvent* last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(0)->taskAsEvent()->EventPointer());
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));

  HandleEvent(kEvents, blink::mojom::InputEventResultState::kNotConsumed);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 2)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(2u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(1)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(kEvents.dispatch_type, WebInputEvent::DispatchType::kBlocking);
  EXPECT_FALSE(last_touch_start_forced_nonblocking_due_to_fling());
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(1)->taskAsEvent()->EventPointer());
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));

  HandleEvent(kEvents, blink::mojom::InputEventResultState::kNotConsumed);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 3)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(3u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(2)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(kEvents.dispatch_type, WebInputEvent::DispatchType::kBlocking);
  EXPECT_FALSE(last_touch_start_forced_nonblocking_due_to_fling());
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(2)->taskAsEvent()->EventPointer());
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));

  kEvents.MovePoint(0, 30, 30);
  HandleEvent(kEvents, blink::mojom::InputEventResultState::kNotConsumed);
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(GetAndResetCallbackResults(),
              testing::Each(ReceivedCallback(
                  CallbackReceivedState::kCalledAfterHandleEvent, false, 4)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(4u, handled_tasks_.size());
  EXPECT_EQ(kEvents.GetType(),
            handled_tasks_.at(3)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(kEvents.dispatch_type, WebInputEvent::DispatchType::kBlocking);
  EXPECT_FALSE(last_touch_start_forced_nonblocking_due_to_fling());
  last_touch_event = static_cast<const WebTouchEvent*>(
      handled_tasks_.at(3)->taskAsEvent()->EventPointer());
  EXPECT_TRUE(Equal(kEvents, *last_touch_event));
}

TEST_F(MainThreadEventQueueTest, QueueingEventTimestampRecorded) {
  WebMouseEvent kEvent = SyntheticWebMouseEventBuilder::Build(
      blink::WebInputEvent::Type::kMouseDown);
  // Set event timestamp to be in the past to simulate actual event
  // so that creation of event and queueing does not happen in the same tick.
  kEvent.SetTimeStamp(base::TimeTicks::Now() - base::Microseconds(10));

  HandleEvent(kEvent, blink::mojom::InputEventResultState::kSetNonBlocking);

  EXPECT_EQ(1u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  RunPendingTasksWithoutRaf();
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_EQ(1u, handled_tasks_.size());

  EXPECT_EQ(kEvent.GetType(),
            handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
  const WebMouseEvent* kHandledEvent = static_cast<const WebMouseEvent*>(
      handled_tasks_.at(0)->taskAsEvent()->EventPointer());
  EXPECT_LT(kHandledEvent->TimeStamp(), kHandledEvent->QueuedTimeStamp());
}

TEST_F(MainThreadEventQueueTest, QueuingTwoClosures) {
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  QueueClosure();
  QueueClosure();
  EXPECT_EQ(2u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_EQ(1u, handled_tasks_.at(0)->taskAsClosure());
  EXPECT_EQ(2u, handled_tasks_.at(1)->taskAsClosure());
}

TEST_F(MainThreadEventQueueTest, QueuingClosureWithRafEvent) {
  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 20, 20);

  // Simulate queueuing closure, event, closure, raf aligned event.
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  QueueClosure();
  EXPECT_EQ(1u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(2);

  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  QueueClosure();
  EXPECT_EQ(3u, event_queue().size());
  EXPECT_TRUE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(4u, event_queue().size());

  EXPECT_TRUE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();

  // The queue should still have the rAF event.
  EXPECT_TRUE(needs_main_frame_);
  EXPECT_EQ(1u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();

  EXPECT_EQ(0u, event_queue().size());
  EXPECT_THAT(
      GetAndResetCallbackResults(),
      testing::ElementsAre(
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 2),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 4)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);

  EXPECT_EQ(1u, handled_tasks_.at(0)->taskAsClosure());
  EXPECT_EQ(kEvents[0].GetType(),
            handled_tasks_.at(1)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(2u, handled_tasks_.at(2)->taskAsClosure());
  EXPECT_EQ(kEvents[1].GetType(),
            handled_tasks_.at(3)->taskAsEvent()->Event().GetType());
}

TEST_F(MainThreadEventQueueTest, QueuingClosuresBetweenEvents) {
  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].ReleasePoint(0);

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(2);

  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  QueueClosure();
  QueueClosure();
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(4u, event_queue().size());
  EXPECT_FALSE(needs_main_frame_);
  main_task_runner_->RunUntilIdle();
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_THAT(
      GetAndResetCallbackResults(),
      testing::ElementsAre(
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 1),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 4)));
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);

  EXPECT_EQ(kEvents[0].GetType(),
            handled_tasks_.at(0)->taskAsEvent()->Event().GetType());
  EXPECT_EQ(1u, handled_tasks_.at(1)->taskAsClosure());
  EXPECT_EQ(2u, handled_tasks_.at(2)->taskAsClosure());
  EXPECT_EQ(kEvents[1].GetType(),
            handled_tasks_.at(3)->taskAsEvent()->Event().GetType());
}

TEST_F(MainThreadEventQueueTest, BlockingTouchMoveBecomesNonBlocking) {
  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[0].MovePoint(0, 20, 20);
  kEvents[1].SetModifiers(1);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].MovePoint(0, 20, 30);
  kEvents[1].dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;
  WebTouchEvent scroll_start(WebInputEvent::Type::kTouchScrollStarted,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(3);
  EXPECT_EQ(WebInputEvent::DispatchType::kBlocking, kEvents[0].dispatch_type);
  EXPECT_EQ(WebInputEvent::DispatchType::kEventNonBlocking,
            kEvents[1].dispatch_type);
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
  HandleEvent(scroll_start, blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(3u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(
      GetAndResetCallbackResults(),
      testing::ElementsAre(
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 0),
          ReceivedCallback(CallbackReceivedState::kCalledWhileHandlingEvent,
                           false, 0),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 3)));
  EXPECT_THAT(
      handled_tasks_,
      ::testing::ElementsAre(
          IsHandledTouchEvent(WebInputEvent::Type::kTouchMove,
                              kEvents[0].unique_touch_event_id,
                              WebInputEvent::DispatchType::kEventNonBlocking),
          IsHandledTouchEvent(WebInputEvent::Type::kTouchMove,
                              kEvents[1].unique_touch_event_id,
                              WebInputEvent::DispatchType::kEventNonBlocking),
          IsHandledTouchEvent(WebInputEvent::Type::kTouchScrollStarted,
                              scroll_start.unique_touch_event_id,
                              WebInputEvent::DispatchType::kBlocking)));
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
}

TEST_F(MainThreadEventQueueTest, BlockingTouchMoveWithTouchEnd) {
  SyntheticWebTouchEvent kEvents[2];
  kEvents[0].PressPoint(10, 10);
  kEvents[0].MovePoint(0, 20, 20);
  kEvents[1].PressPoint(10, 10);
  kEvents[1].ReleasePoint(0);
  WebTouchEvent scroll_start(WebInputEvent::Type::kTouchScrollStarted,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());

  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(3);
  EXPECT_EQ(WebInputEvent::DispatchType::kBlocking, kEvents[0].dispatch_type);
  EXPECT_EQ(WebInputEvent::DispatchType::kBlocking, kEvents[1].dispatch_type);
  HandleEvent(kEvents[0], blink::mojom::InputEventResultState::kNotConsumed);
  HandleEvent(kEvents[1], blink::mojom::InputEventResultState::kNotConsumed);
  HandleEvent(scroll_start, blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(3u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_THAT(
      GetAndResetCallbackResults(),
      testing::ElementsAre(
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 1),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 2),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 3)));
  EXPECT_THAT(handled_tasks_,
              ::testing::ElementsAre(
                  IsHandledTouchEvent(WebInputEvent::Type::kTouchMove,
                                      kEvents[0].unique_touch_event_id,
                                      WebInputEvent::DispatchType::kBlocking),
                  IsHandledTouchEvent(WebInputEvent::Type::kTouchEnd,
                                      kEvents[1].unique_touch_event_id,
                                      WebInputEvent::DispatchType::kBlocking),
                  IsHandledTouchEvent(WebInputEvent::Type::kTouchScrollStarted,
                                      scroll_start.unique_touch_event_id,
                                      WebInputEvent::DispatchType::kBlocking)));
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
}

TEST_F(MainThreadEventQueueTest,
       UnblockTouchMoveAfterTouchStartAndFirstTouchMoveNotConsumed) {
  SyntheticWebTouchEvent touch_start;
  touch_start.PressPoint(10, 10);
  touch_start.touch_start_or_first_touch_move = true;
  ASSERT_EQ(WebInputEvent::Type::kTouchStart, touch_start.GetType());
  ASSERT_EQ(WebInputEvent::DispatchType::kBlocking, touch_start.dispatch_type);

  SyntheticWebTouchEvent touch_moves[5];
  for (auto& touch_move : touch_moves) {
    touch_move.MovePoint(0, 20, 30);
    ASSERT_EQ(WebInputEvent::Type::kTouchMove, touch_move.GetType());
    ASSERT_EQ(WebInputEvent::DispatchType::kBlocking, touch_move.dispatch_type);
  }
  touch_moves[0].touch_start_or_first_touch_move = true;

  struct WillHandleInputEventCallback {
    STACK_ALLOCATED();

   public:
    void Run(const WebCoalescedInputEvent& event) {
      test.set_main_thread_ack_state(
          blink::mojom::InputEventResultState::kNotConsumed);
      if (event.Event().GetType() == WebInputEvent::Type::kTouchStart &&
          consume_touch_start) {
        test.set_main_thread_ack_state(
            blink::mojom::InputEventResultState::kConsumed);
      }
      auto touch_id = static_cast<const WebTouchEvent&>(event.Event())
                          .unique_touch_event_id;
      if (touch_id == touch_moves[0].unique_touch_event_id) {
        if (consume_first_touch_move) {
          test.set_main_thread_ack_state(
              blink::mojom::InputEventResultState::kConsumed);
        }
        // Simulates two new blocking touchmove events enqueued while the
        // first touchmove is being dispatched.
        test.HandleEvent(touch_moves[1],
                         blink::mojom::InputEventResultState::kNotConsumed);
        test.HandleEvent(touch_moves[2],
                         blink::mojom::InputEventResultState::kNotConsumed);
      } else if (touch_id == touch_moves[1].unique_touch_event_id) {
        // Simulates two new blocking touchmove events enqueued while the
        // second touchmove is being dispatched.
        test.HandleEvent(touch_moves[3],
                         blink::mojom::InputEventResultState::kNotConsumed);
        test.HandleEvent(touch_moves[4],
                         blink::mojom::InputEventResultState::kNotConsumed);
      }
    }

    MainThreadEventQueueTest& test;
    const SyntheticWebTouchEvent* touch_moves;
    bool consume_touch_start = false;
    bool consume_first_touch_move = false;
  };
  WillHandleInputEventCallback will_handle_input_event_callback{*this,
                                                                touch_moves};

  will_handle_input_event_callback_ =
      base::BindRepeating(&WillHandleInputEventCallback::Run,
                          base::Unretained(&will_handle_input_event_callback));

  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_CALL(*widget_scheduler_, DidHandleInputEventOnMainThread(
                                      testing::_, testing::_, testing::_))
      .Times(6);
  HandleEvent(touch_start, blink::mojom::InputEventResultState::kNotConsumed);
  HandleEvent(touch_moves[0],
              blink::mojom::InputEventResultState::kNotConsumed);
  EXPECT_EQ(2u, event_queue().size());
  RunPendingTasksWithSimulatedRaf();
  EXPECT_EQ(0u, event_queue().size());
  EXPECT_FALSE(main_task_runner_->HasPendingTask());
  EXPECT_FALSE(needs_main_frame_);
  EXPECT_THAT(
      GetAndResetCallbackResults(),
      testing::ElementsAre(
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 1),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 2),
          // These callbacks were run just after handling the first touchmove.
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent,
                           false, 2),
          ReceivedCallback(CallbackReceivedState::kCalledAfterHandleEvent, true,
    
"""


```