Response:
My thought process to analyze the provided C++ code snippet and fulfill the user's request goes like this:

1. **Understand the Goal:** The user wants a functional description of the C++ source file `input_handler_proxy_unittest.cc`, along with connections to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common user/programming errors. This is the first of three parts, so focus on the core functionality.

2. **Identify the Core Class Under Test:** The filename `input_handler_proxy_unittest.cc` strongly suggests the primary class being tested is `InputHandlerProxy`. The `#include` directives confirm this.

3. **Determine the Purpose of Unit Tests:** Unit tests are designed to verify the behavior of individual units of code in isolation. In this case, the unit is `InputHandlerProxy`. Therefore, the main function of this file is to test the different functionalities and edge cases of the `InputHandlerProxy` class.

4. **Analyze Key Dependencies and Interactions:**  Examine the `#include` directives to understand what other classes and systems `InputHandlerProxy` interacts with. I see:
    * **Input Events:** `WebInputEvent`, `WebKeyboardEvent`, `WebMouseEvent`, `WebMouseWheelEvent`, `WebPointerEvent`, `WebTouchEvent`, `WebGestureEvent`. This indicates `InputHandlerProxy` handles various input types.
    * **Compositor:** `cc::InputHandler`, `cc::CompositorDelegateForInput`, `cc::ScrollTree`, `cc::LayerTreeHostImpl`. This signifies interaction with the Chromium compositor for rendering and scrolling.
    * **Client Interface:** `InputHandlerProxyClient`. This implies a clear separation of concerns, where `InputHandlerProxy` uses a client interface for specific actions.
    * **Asynchronous Operations:** `base::functional::bind`, `base::test::TaskEnvironment`. This points towards handling events and operations asynchronously.
    * **Testing Framework:** `testing::gmock`, `testing::gtest`. This confirms it's a unit test file using Google Test and Google Mock.

5. **Infer Key Functionalities Based on Dependencies and Test Structure:** Based on the included headers and the general structure of unit tests (setting up expectations and verifying outcomes), I can infer the following functionalities being tested:
    * **Input Event Handling:**  Processing different types of input events (mouse, touch, wheel, gestures).
    * **Compositor Integration:** Interacting with the compositor for scrolling, pinch-zooming, and potentially other compositing-related tasks.
    * **Event Routing:** Deciding how to handle different input events (e.g., passing them to the main thread or handling them on the compositor thread).
    * **Touch Action Handling:** Managing allowed touch actions based on event listeners.
    * **Scroll Handling:**  Initiating, updating, and ending scrolls, including different scroll types (normal, by page, flinging, snapping).
    * **Pinch Zoom Handling:** Beginning, updating, and ending pinch zoom gestures.
    * **Event Queuing:**  Potentially using a queue to manage input events.
    * **Synchronization:**  Potentially dealing with synchronization between the main thread and the compositor thread.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how the tested functionalities relate to the user experience of a web page:
    * **JavaScript:** Event listeners in JavaScript (`addEventListener`) directly correspond to the event handling logic being tested. Passive and blocking listeners are explicitly mentioned in the code.
    * **HTML:** Scrolling, pinch zooming, and touch interactions are fundamental to how users interact with HTML content. The `InputHandlerProxy` plays a role in enabling these interactions.
    * **CSS:**  CSS properties like `touch-action` influence how touch events are handled. The testing of `cc::TouchAction` directly relates to this. Fixed background attachments (mentioned in a comment) are also a CSS concept that can impact scrolling behavior.

7. **Provide Examples of Logical Reasoning (Assumptions and Outputs):** Create simple scenarios to illustrate how `InputHandlerProxy` might behave:
    * **Mouse Wheel Scroll:** Input: Mouse wheel event. Possible outputs: Scroll on the compositor thread, send scroll events to the main thread.
    * **Touch Scroll:** Input: Touch events. Possible outputs: Initiate scrolling, update scroll position, handle touch-action.
    * **Pinch Zoom:** Input: Pinch gesture events. Possible outputs: Start pinch zoom, update zoom level.

8. **Illustrate Common User/Programming Errors:** Think about common mistakes developers or the system might make when dealing with input events:
    * **Incorrect Event Handling:** Forgetting to handle certain event types.
    * **Synchronization Issues:** Problems when the main thread and compositor thread disagree about the state.
    * **Touch Action Conflicts:**  Misconfiguring `touch-action` CSS property.
    * **Event Listener Errors:** Incorrectly implementing passive/blocking listeners.

9. **Summarize the Core Functionality for Part 1:**  Based on the analysis, condense the key functions of the file into a concise summary for the first part of the response. Emphasize the testing aspect and the core responsibilities of `InputHandlerProxy`.

10. **Structure the Response:** Organize the information logically, using headings and bullet points for clarity. Address each part of the user's request (functionality, web technology relation, logical reasoning, common errors).

By following these steps, I can effectively analyze the C++ code and generate a comprehensive response that addresses the user's request, even without executing the code. The focus is on understanding the purpose, interactions, and implications of the code based on its structure and dependencies.
这是chromium blink引擎源代码文件`input_handler_proxy_unittest.cc`的第一部分，其主要功能是**测试 `InputHandlerProxy` 类的各种功能和行为**。

`InputHandlerProxy` 在Blink渲染引擎中扮演着重要的角色，它位于渲染进程的主线程，负责接收来自浏览器的输入事件，并将这些事件路由到合适的处理者，通常是 compositor 线程上的 `InputHandler`。  这个单元测试文件通过模拟各种输入事件和场景，来验证 `InputHandlerProxy` 是否按照预期的方式工作。

以下是根据代码推断出的主要功能点，以及它们与javascript, html, css 功能的关系，逻辑推理和常见错误：

**主要功能归纳:**

1. **输入事件的接收和处理:** 测试 `InputHandlerProxy` 是否能正确接收各种类型的输入事件，例如鼠标事件 (MouseDown, MouseUp, MouseMove, MouseWheel)、触摸事件 (TouchStart, TouchMove, TouchEnd, TouchCancel)、键盘事件 (KeyPress, KeyDown, KeyUp) 和手势事件 (GestureScrollBegin, GestureScrollUpdate, GestureScrollEnd, GesturePinchBegin, GesturePinchUpdate, GesturePinchEnd)。
2. **事件路由到 compositor 线程:** 测试 `InputHandlerProxy` 是否能将接收到的输入事件适当地转发到 compositor 线程的 `InputHandler` 进行处理。
3. **compositor 线程滚动的协调:** 测试 `InputHandlerProxy` 如何协调 compositor 线程上的滚动操作，例如处理 `GestureScrollBegin`, `GestureScrollUpdate`, `GestureScrollEnd` 事件。
4. **主线程滚动的触发:** 测试在某些情况下，输入事件需要在主线程处理时，`InputHandlerProxy` 如何生成相应的事件并发送到主线程。 例如，当事件目标有监听器时。
5. **触摸动作 (Touch Action) 的处理:** 测试 `InputHandlerProxy` 如何根据事件目标上的 `touch-action` CSS 属性，决定是否允许 compositor 线程处理触摸事件。
6. **鼠标滚轮事件的处理:** 测试 `InputHandlerProxy` 如何根据事件目标上的事件监听器（例如 `wheel` 事件监听器）来处理鼠标滚轮事件。 包括被动监听器 (passive listener) 和阻止监听器 (blocking listener) 的情况。
7. **手势缩放 (Pinch Zoom) 的处理:** 测试 `InputHandlerProxy` 如何处理 `GesturePinchBegin`, `GesturePinchUpdate`, `GesturePinchEnd` 事件。
8. **事件的丢弃 (Dropping):** 测试在某些情况下，例如当事件无法被处理或不应该被处理时，`InputHandlerProxy` 是否会正确地丢弃这些事件。
9. **同步输入处理器的支持:** 测试 `InputHandlerProxy` 如何与同步输入处理器 (`SynchronousInputHandler`) 协同工作，这在某些嵌入式或特定的渲染场景中会使用到。
10. **性能指标的记录:**  虽然这部分代码没有直接展示，但通常这类测试还会涉及到验证性能指标的记录是否正确。

**与 javascript, html, css 的功能关系及举例:**

*   **JavaScript:**
    *   **事件监听器:**  代码中模拟了检查事件监听器是否存在 (`HasBlockingWheelEventHandlerAt`, `EventListenerTypeForTouchStartOrMoveAt`)，这直接关系到 JavaScript 中使用 `addEventListener` 注册的事件监听器。 例如，如果一个 HTML 元素通过 JavaScript 注册了一个 `wheel` 事件的阻止监听器，那么当鼠标滚轮在该元素上滚动时，`InputHandlerProxy` 会检测到这个监听器，并可能阻止 compositor 线程处理滚动，而将事件发送到主线程的 JavaScript 处理。
    *   **`preventDefault()` 的效果:**  虽然代码中没有直接模拟 `preventDefault()` 的调用，但阻止监听器的存在意味着 JavaScript 代码有可能调用 `preventDefault()` 来阻止默认行为，这会影响 `InputHandlerProxy` 的行为。
*   **HTML:**
    *   **可滚动元素:** `InputHandlerProxy` 需要判断事件发生的目标是否是可滚动元素，以及是否应该由 compositor 线程处理滚动。 HTML 结构决定了哪些元素是可滚动的。
    *   **事件目标:** 输入事件的目标 HTML 元素会影响事件的处理方式。 例如，点击一个链接 (<a> 标签) 和点击一个普通 <div> 元素，`InputHandlerProxy` 的行为可能会不同。
*   **CSS:**
    *   **`touch-action` 属性:** 代码中使用了 `cc::TouchAction` 来表示触摸动作，这直接对应于 CSS 的 `touch-action` 属性。例如，如果一个元素设置了 `touch-action: none;`，那么 `InputHandlerProxy` 可能会阻止对该元素进行默认的触摸滚动或缩放操作。
    *   **`overflow` 属性:** CSS 的 `overflow` 属性决定了元素是否可滚动。 `InputHandlerProxy` 在处理滚动事件时，需要考虑元素的 `overflow` 属性。

**逻辑推理及假设输入与输出:**

*   **假设输入:** 一个 `WebMouseWheelEvent`，其坐标位于一个设置了 `wheel` 事件阻止监听器的 HTML 元素之上。
*   **逻辑推理:** `InputHandlerProxy` 会调用 `HasBlockingWheelEventHandlerAt` 并返回 `true`，表示存在阻止监听器。
*   **预期输出:** `InputHandlerProxy` 不会将该滚轮事件交给 compositor 线程处理，而是会将其发送到主线程进行 JavaScript 处理。

*   **假设输入:** 一个 `WebTouchEvent` (TouchStart) 事件，触摸的目标元素 CSS 样式设置了 `touch-action: pan-y;`。
*   **逻辑推理:** `InputHandlerProxy` 会根据 `touch-action` 属性的值，确定允许的触摸操作是垂直方向的平移。
*   **预期输出:** `InputHandlerProxy` 会将允许的触摸动作 (`cc::TouchAction::kPanUp | cc::TouchAction::kPanDown`) 告知 compositor 线程，以便 compositor 线程可以根据这个限制来处理后续的触摸移动事件。

**涉及用户或编程常见的使用错误:**

*   **JavaScript 中错误地使用 `passive` 监听器:**  开发者可能错误地认为 `passive: true` 的监听器可以调用 `preventDefault()` 来阻止滚动，但实际上 `passive` 监听器内部调用 `preventDefault()` 会被忽略，并可能导致性能警告。  `InputHandlerProxy` 的测试需要确保在这种情况下，行为是符合预期的。
*   **CSS 中 `touch-action` 属性的误用:** 开发者可能不理解 `touch-action` 属性的作用，错误地设置了该属性，导致页面无法滚动或缩放。  `InputHandlerProxy` 的测试需要覆盖各种 `touch-action` 的取值，确保其行为正确。
*   **在 JavaScript 中同时注册 `passive` 和非 `passive` 的监听器:**  在某些情况下，可能会在同一个元素上同时注册相同事件类型的 `passive` 和非 `passive` 监听器，这可能会导致行为不确定。 `InputHandlerProxy` 的测试需要考虑这种情况。
*   **Compositor 线程和主线程事件处理的同步问题:**  如果开发者对事件的处理逻辑有误解，可能会导致 compositor 线程和主线程在处理同一个事件时出现冲突或不同步的情况。 `InputHandlerProxy` 的测试需要确保事件在合适的线程被处理。

**总结 (针对第1部分):**

`input_handler_proxy_unittest.cc` 的第1部分主要关注 `InputHandlerProxy` **接收和初步处理各种输入事件的能力**，以及它**如何根据事件的类型、目标和相关的属性 (例如 CSS 的 `touch-action` 和 JavaScript 的事件监听器) 来决定如何路由这些事件**。 它涵盖了鼠标滚轮事件、基本的触摸事件处理、以及手势事件的初步处理逻辑。  重点在于验证 `InputHandlerProxy` 的核心功能，为后续更复杂的测试场景打下基础。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/input_handler_proxy_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/input_handler_proxy.h"

#include <memory>

#include "base/containers/circular_deque.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/lazy_instance.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/task_environment.h"
#include "base/test/trace_event_analyzer.h"
#include "base/types/optional_ref.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/input/browser_controls_offset_tags_info.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/test/fake_impl_task_runner_provider.h"
#include "cc/test/fake_layer_tree_host_impl.h"
#include "cc/test/test_task_graph_runner.h"
#include "cc/trees/latency_info_swap_promise_monitor.h"
#include "cc/trees/layer_tree_settings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/renderer/platform/widget/input/compositor_thread_event_queue.h"
#include "third_party/blink/renderer/platform/widget/input/event_with_callback.h"
#include "third_party/blink/renderer/platform/widget/input/input_handler_proxy.h"
#include "third_party/blink/renderer/platform/widget/input/input_handler_proxy_client.h"
#include "third_party/blink/renderer/platform/widget/input/scroll_predictor.h"
#include "ui/events/types/scroll_input_type.h"
#include "ui/gfx/geometry/size_f.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "ui/latency/latency_info.h"

using cc::InputHandler;
using cc::ScrollBeginThreadState;
using cc::TouchAction;
using testing::_;
using testing::AllOf;
using testing::DoAll;
using testing::Eq;
using testing::Field;
using testing::Mock;
using testing::NiceMock;
using testing::Property;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace blink {
namespace test {

namespace {

MATCHER_P(WheelEventsMatch, expected, "") {
  return WheelEventsMatch(arg, expected);
}

std::unique_ptr<WebInputEvent> CreateGestureScrollPinch(
    WebInputEvent::Type type,
    WebGestureDevice source_device,
    base::TimeTicks event_time,
    float delta_y_or_scale = 0,
    int x = 0,
    int y = 0) {
  auto gesture = std::make_unique<WebGestureEvent>(
      type, WebInputEvent::kNoModifiers, event_time, source_device);
  if (type == WebInputEvent::Type::kGestureScrollUpdate) {
    gesture->data.scroll_update.delta_y = delta_y_or_scale;
  } else if (type == WebInputEvent::Type::kGesturePinchUpdate) {
    gesture->data.pinch_update.scale = delta_y_or_scale;
    gesture->SetPositionInWidget(gfx::PointF(x, y));
  }
  return gesture;
}

class FakeCompositorDelegateForInput : public cc::CompositorDelegateForInput {
 public:
  FakeCompositorDelegateForInput()
      : host_impl_(&task_runner_provider_, &task_graph_runner_) {}
  void BindToInputHandler(
      std::unique_ptr<cc::InputDelegateForCompositor> delegate) override {}
  cc::ScrollTree& GetScrollTree() const override { return scroll_tree_; }
  bool HasAnimatedScrollbars() const override { return false; }
  void SetNeedsCommit() override {}
  void SetNeedsFullViewportRedraw() override {}
  void SetDeferBeginMainFrame(bool defer_begin_main_frame) const override {}
  void DidUpdateScrollAnimationCurve() override {}
  void AccumulateScrollDeltaForTracing(const gfx::Vector2dF& delta) override {}
  void DidStartPinchZoom() override {}
  void DidUpdatePinchZoom() override {}
  void DidEndPinchZoom() override {}
  void DidStartScroll() override {}
  void DidEndScroll() override {}
  void DidMouseLeave() override {}
  bool IsInHighLatencyMode() const override { return false; }
  void WillScrollContent(cc::ElementId element_id) override {}
  void DidScrollContent(cc::ElementId element_id, bool animated) override {}
  float DeviceScaleFactor() const override { return 0; }
  float PageScaleFactor() const override { return 0; }
  gfx::Size VisualDeviceViewportSize() const override { return gfx::Size(); }
  const cc::LayerTreeSettings& GetSettings() const override {
    return settings_;
  }
  cc::LayerTreeHostImpl& GetImplDeprecated() override { return host_impl_; }
  const cc::LayerTreeHostImpl& GetImplDeprecated() const override {
    return host_impl_;
  }
  void UpdateBrowserControlsState(
      cc::BrowserControlsState constraints,
      cc::BrowserControlsState current,
      bool animate,
      base::optional_ref<const cc::BrowserControlsOffsetTagsInfo>
          offset_tags_info) override {}
  bool HasScrollLinkedAnimation(cc::ElementId for_scroller) const override {
    return false;
  }

 private:
  mutable cc::ScrollTree scroll_tree_;
  cc::LayerTreeSettings settings_;
  cc::FakeImplTaskRunnerProvider task_runner_provider_;
  cc::TestTaskGraphRunner task_graph_runner_;
  cc::FakeLayerTreeHostImpl host_impl_;
};

base::LazyInstance<FakeCompositorDelegateForInput>::Leaky
    g_fake_compositor_delegate = LAZY_INSTANCE_INITIALIZER;

class MockInputHandler : public cc::InputHandler {
 public:
  MockInputHandler() : cc::InputHandler(g_fake_compositor_delegate.Get()) {}
  MockInputHandler(const MockInputHandler&) = delete;
  MockInputHandler& operator=(const MockInputHandler&) = delete;

  ~MockInputHandler() override = default;

  base::WeakPtr<InputHandler> AsWeakPtr() override {
    return weak_ptr_factory_.GetWeakPtr();
  }

  MOCK_METHOD2(PinchGestureBegin,
               void(const gfx::Point& anchor, ui::ScrollInputType type));
  MOCK_METHOD2(PinchGestureUpdate,
               void(float magnify_delta, const gfx::Point& anchor));
  MOCK_METHOD1(PinchGestureEnd, void(const gfx::Point& anchor));

  MOCK_METHOD0(SetNeedsAnimateInput, void());

  MOCK_METHOD2(ScrollBegin,
               ScrollStatus(cc::ScrollState*, ui::ScrollInputType type));
  MOCK_METHOD2(RootScrollBegin,
               ScrollStatus(cc::ScrollState*, ui::ScrollInputType type));
  MOCK_METHOD2(ScrollUpdate,
               cc::InputHandlerScrollResult(cc::ScrollState, base::TimeDelta));
  MOCK_METHOD1(ScrollEnd, void(bool));
  MOCK_METHOD2(RecordScrollBegin,
               void(ui::ScrollInputType type,
                    cc::ScrollBeginThreadState state));
  MOCK_METHOD1(RecordScrollEnd, void(ui::ScrollInputType type));
  MOCK_METHOD1(HitTest,
               cc::PointerResultType(const gfx::PointF& mouse_position));
  MOCK_METHOD2(MouseDown,
               cc::InputHandlerPointerResult(const gfx::PointF& mouse_position,
                                             const bool shift_modifier));
  MOCK_METHOD1(
      MouseUp,
      cc::InputHandlerPointerResult(const gfx::PointF& mouse_position));
  MOCK_METHOD1(SetIsHandlingTouchSequence, void(bool));
  void NotifyInputEvent() override {}

  std::unique_ptr<cc::LatencyInfoSwapPromiseMonitor>
  CreateLatencyInfoSwapPromiseMonitor(ui::LatencyInfo* latency) override {
    return nullptr;
  }

  std::unique_ptr<cc::EventsMetricsManager::ScopedMonitor>
  GetScopedEventMetricsMonitor(
      cc::EventsMetricsManager::ScopedMonitor::DoneCallback) override {
    return nullptr;
  }

  cc::ScrollElasticityHelper* CreateScrollElasticityHelper() override {
    return nullptr;
  }
  void DestroyScrollElasticityHelper() override {}

  bool GetScrollOffsetForLayer(cc::ElementId element_id,
                               gfx::PointF* offset) override {
    return false;
  }
  bool ScrollLayerTo(cc::ElementId element_id,
                     const gfx::PointF& offset) override {
    return false;
  }

  void BindToClient(cc::InputHandlerClient* client) override {}

  void MouseLeave() override {}

  MOCK_METHOD1(FindFrameElementIdAtPoint, cc::ElementId(const gfx::PointF&));

  cc::InputHandlerPointerResult MouseMoveAt(
      const gfx::Point& mouse_position) override {
    return cc::InputHandlerPointerResult();
  }

  MOCK_CONST_METHOD1(
      GetEventListenerProperties,
      cc::EventListenerProperties(cc::EventListenerClass event_class));
  MOCK_METHOD2(EventListenerTypeForTouchStartOrMoveAt,
               cc::InputHandler::TouchStartOrMoveEventListenerType(
                   const gfx::Point& point,
                   cc::TouchAction* touch_action));
  MOCK_CONST_METHOD1(HasBlockingWheelEventHandlerAt, bool(const gfx::Point&));

  MOCK_METHOD0(RequestUpdateForSynchronousInputHandler, void());
  MOCK_METHOD1(SetSynchronousInputHandlerRootScrollOffset,
               void(const gfx::PointF& root_offset));

  bool IsCurrentlyScrollingViewport() const override {
    return is_scrolling_root_;
  }
  void set_is_scrolling_root(bool is) { is_scrolling_root_ = is; }

  MOCK_METHOD4(GetSnapFlingInfoAndSetAnimatingSnapTarget,
               bool(const gfx::Vector2dF& current_delta,
                    const gfx::Vector2dF& natural_displacement,
                    gfx::PointF* initial_offset,
                    gfx::PointF* target_offset));
  MOCK_METHOD1(ScrollEndForSnapFling, void(bool));

  bool ScrollbarScrollIsActive() override { return false; }

  void SetDeferBeginMainFrame(bool defer_begin_main_frame) const override {}

  MOCK_METHOD4(UpdateBrowserControlsState,
               void(cc::BrowserControlsState constraints,
                    cc::BrowserControlsState current,
                    bool animate,
                    base::optional_ref<const cc::BrowserControlsOffsetTagsInfo>
                        offset_tags_info));

 private:
  bool is_scrolling_root_ = true;

  base::WeakPtrFactory<MockInputHandler> weak_ptr_factory_{this};
};

class MockSynchronousInputHandler : public SynchronousInputHandler {
 public:
  MOCK_METHOD6(UpdateRootLayerState,
               void(const gfx::PointF& total_scroll_offset,
                    const gfx::PointF& max_scroll_offset,
                    const gfx::SizeF& scrollable_size,
                    float page_scale_factor,
                    float min_page_scale_factor,
                    float max_page_scale_factor));
};

class MockInputHandlerProxyClient : public InputHandlerProxyClient {
 public:
  MockInputHandlerProxyClient() {}
  MockInputHandlerProxyClient(const MockInputHandlerProxyClient&) = delete;
  MockInputHandlerProxyClient& operator=(const MockInputHandlerProxyClient&) =
      delete;

  ~MockInputHandlerProxyClient() override {}

  void WillShutdown() override {}

  MOCK_METHOD3(GenerateScrollBeginAndSendToMainThread,
               void(const WebGestureEvent& update_event,
                    const WebInputEventAttribution&,
                    const cc::EventMetrics*));

  MOCK_METHOD5(DidOverscroll,
               void(const gfx::Vector2dF& accumulated_overscroll,
                    const gfx::Vector2dF& latest_overscroll_delta,
                    const gfx::Vector2dF& current_fling_velocity,
                    const gfx::PointF& causal_event_viewport_point,
                    const cc::OverscrollBehavior& overscroll_behavior));
  void DidStartScrollingViewport() override {}
  MOCK_METHOD1(SetAllowedTouchAction, void(cc::TouchAction touch_action));
  bool AllowsScrollResampling() override { return true; }
};

WebTouchPoint CreateWebTouchPoint(WebTouchPoint::State state,
                                  float x,
                                  float y) {
  WebTouchPoint point;
  point.state = state;
  point.SetPositionInScreen(x, y);
  point.SetPositionInWidget(x, y);
  return point;
}

const cc::InputHandler::ScrollStatus kImplThreadScrollState{
    cc::InputHandler::ScrollThread::kScrollOnImplThread};

const cc::InputHandler::ScrollStatus kRequiresMainThreadHitTestState{
    cc::InputHandler::ScrollThread::kScrollOnImplThread,
    /*main_thread_hit_test_reasons*/
    cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion};

constexpr auto kSampleMainThreadScrollingReason =
    cc::MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects;

const cc::InputHandler::ScrollStatus kScrollIgnoredScrollState{
    cc::InputHandler::ScrollThread::kScrollIgnored};

}  // namespace

class TestInputHandlerProxy : public InputHandlerProxy {
 public:
  TestInputHandlerProxy(cc::InputHandler& input_handler,
                        InputHandlerProxyClient* client)
      : InputHandlerProxy(input_handler, client) {}
  void RecordScrollBeginForTest(WebGestureDevice device, uint32_t reasons) {
    RecordScrollBegin(device,
                      reasons & cc::MainThreadScrollingReason::kHitTestReasons,
                      reasons & cc::MainThreadScrollingReason::kRepaintReasons);
  }

  MOCK_METHOD0(SetNeedsAnimateInput, void());

  EventDisposition HitTestTouchEventForTest(
      const WebTouchEvent& touch_event,
      bool* is_touching_scrolling_layer,
      cc::TouchAction* allowed_touch_action) {
    return HitTestTouchEvent(touch_event, is_touching_scrolling_layer,
                             allowed_touch_action);
  }

  EventDisposition HandleMouseWheelForTest(
      const WebMouseWheelEvent& wheel_event) {
    return HandleMouseWheel(wheel_event);
  }

  // This is needed because the tests can't directly call
  // DispatchQueuedInputEvents since it is private.
  void DispatchQueuedInputEventsHelper() { DispatchQueuedInputEvents(true); }
};

// Whether or not the input handler says that the viewport is scrolling the
// root scroller or a child.
enum class ScrollerType { kRoot, kChild };

// Whether or not to setup a synchronous input handler. This simulates the mode
// that WebView runs in.
enum class HandlerType { kNormal, kSynchronous };

class InputHandlerProxyTest : public testing::Test,
                              public testing::WithParamInterface<
                                  std::tuple<ScrollerType, HandlerType>> {
  ScrollerType GetScrollerType() { return std::get<0>(GetParam()); }
  HandlerType GetHandlerType() { return std::get<1>(GetParam()); }

 public:
  InputHandlerProxyTest() {
    input_handler_ = std::make_unique<TestInputHandlerProxy>(
        mock_input_handler_, &mock_client_);
    scroll_result_did_scroll_.did_scroll = true;
    scroll_result_did_not_scroll_.did_scroll = false;

    if (GetHandlerType() == HandlerType::kSynchronous) {
      EXPECT_CALL(mock_input_handler_,
                  RequestUpdateForSynchronousInputHandler())
          .Times(1);
      input_handler_->SetSynchronousInputHandler(
          &mock_synchronous_input_handler_);
    }

    mock_input_handler_.set_is_scrolling_root(
        GetHandlerType() == HandlerType::kSynchronous &&
        GetScrollerType() == ScrollerType::kRoot);

    // Set a default device so tests don't always have to set this.
    gesture_.SetSourceDevice(WebGestureDevice::kTouchpad);

    input_handler_->set_event_attribution_enabled(false);
  }

  virtual ~InputHandlerProxyTest() = default;

// This is defined as a macro so the line numbers can be traced back to the
// correct spot when it fails.
#define EXPECT_SET_NEEDS_ANIMATE_INPUT(times)                              \
  do {                                                                     \
    EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(times); \
  } while (false)

// This is defined as a macro because when an expectation is not satisfied the
// only output you get out of gmock is the line number that set the expectation.
#define VERIFY_AND_RESET_MOCKS()                                     \
  do {                                                               \
    testing::Mock::VerifyAndClearExpectations(&mock_input_handler_); \
    testing::Mock::VerifyAndClearExpectations(                       \
        &mock_synchronous_input_handler_);                           \
    testing::Mock::VerifyAndClearExpectations(&mock_client_);        \
  } while (false)

  void Animate(base::TimeTicks time) { input_handler_->Animate(time); }

  void SetSmoothScrollEnabled(bool value) {}

  base::HistogramTester& histogram_tester() { return histogram_tester_; }

 protected:
  void GestureScrollStarted();
  void GestureScrollIgnored();
  void FlingAndSnap();

  base::test::SingleThreadTaskEnvironment task_environment_;
  testing::StrictMock<MockInputHandler> mock_input_handler_;
  testing::StrictMock<MockSynchronousInputHandler>
      mock_synchronous_input_handler_;
  std::unique_ptr<TestInputHandlerProxy> input_handler_;
  testing::StrictMock<MockInputHandlerProxyClient> mock_client_;
  WebGestureEvent gesture_;
  InputHandlerProxy::EventDisposition expected_disposition_ =
      InputHandlerProxy::DID_HANDLE;
  base::HistogramTester histogram_tester_;
  cc::InputHandlerScrollResult scroll_result_did_scroll_;
  cc::InputHandlerScrollResult scroll_result_did_not_scroll_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

// The helper basically returns the EventDisposition that is returned by
// RouteToTypeSpecificHandler. This is done by passing in a callback when
// calling HandleInputEventWithLatencyInfo. By design, DispatchSingleInputEvent
// will then call this callback with the disposition returned by
// RouteToTypeSpecificHandler and that is what gets returned by this helper.
InputHandlerProxy::EventDisposition HandleInputEventWithLatencyInfo(
    TestInputHandlerProxy* input_handler,
    const WebInputEvent& event) {
  std::unique_ptr<WebCoalescedInputEvent> scoped_input_event =
      std::make_unique<WebCoalescedInputEvent>(event.Clone(),
                                               ui::LatencyInfo());
  InputHandlerProxy::EventDisposition event_disposition =
      InputHandlerProxy::DID_NOT_HANDLE;
  input_handler->HandleInputEventWithLatencyInfo(
      std::move(scoped_input_event), nullptr,
      base::BindLambdaForTesting(
          [&event_disposition](
              InputHandlerProxy::EventDisposition disposition,
              std::unique_ptr<blink::WebCoalescedInputEvent> event,
              std::unique_ptr<InputHandlerProxy::DidOverscrollParams> callback,
              const WebInputEventAttribution& attribution,
              std::unique_ptr<cc::EventMetrics> metrics) {
            event_disposition = disposition;
          }));
  return event_disposition;
}

// This helper forces the CompositorThreadEventQueue to be flushed.
InputHandlerProxy::EventDisposition HandleInputEventAndFlushEventQueue(
    testing::StrictMock<MockInputHandler>& mock_input_handler,
    TestInputHandlerProxy* input_handler,
    const WebInputEvent& event) {
  EXPECT_CALL(mock_input_handler, SetNeedsAnimateInput())
      .Times(testing::AnyNumber());

  std::unique_ptr<WebCoalescedInputEvent> scoped_input_event =
      std::make_unique<WebCoalescedInputEvent>(event.Clone(),
                                               ui::LatencyInfo());
  InputHandlerProxy::EventDisposition event_disposition =
      InputHandlerProxy::DID_NOT_HANDLE;
  input_handler->HandleInputEventWithLatencyInfo(
      std::move(scoped_input_event), nullptr,
      base::BindLambdaForTesting(
          [&event_disposition](
              InputHandlerProxy::EventDisposition disposition,
              std::unique_ptr<blink::WebCoalescedInputEvent> event,
              std::unique_ptr<InputHandlerProxy::DidOverscrollParams> callback,
              const WebInputEventAttribution& attribution,
              std::unique_ptr<cc::EventMetrics> metrics) {
            event_disposition = disposition;
          }));

  input_handler->DispatchQueuedInputEventsHelper();
  return event_disposition;
}

class InputHandlerProxyEventQueueTest : public testing::Test {
 public:
  InputHandlerProxyEventQueueTest()
      : input_handler_proxy_(mock_input_handler_, &mock_client_) {
    SetScrollPredictionEnabled(true);
  }

  ~InputHandlerProxyEventQueueTest() override = default;

  void HandleGestureEvent(WebInputEvent::Type type,
                          float delta_y_or_scale = 0,
                          int x = 0,
                          int y = 0) {
    HandleGestureEventWithSourceDevice(type, WebGestureDevice::kTouchscreen,
                                       delta_y_or_scale, x, y);
  }

  void HandleGestureEventWithSourceDevice(WebInputEvent::Type type,
                                          WebGestureDevice source_device,
                                          float delta_y_or_scale = 0,
                                          int x = 0,
                                          int y = 0) {
    InjectInputEvent(CreateGestureScrollPinch(
        type, source_device, input_handler_proxy_.tick_clock_->NowTicks(),
        delta_y_or_scale, x, y));
  }

  void InjectInputEvent(std::unique_ptr<WebInputEvent> event) {
    input_handler_proxy_.HandleInputEventWithLatencyInfo(
        std::make_unique<WebCoalescedInputEvent>(std::move(event),
                                                 ui::LatencyInfo()),
        nullptr,
        base::BindOnce(
            &InputHandlerProxyEventQueueTest::DidHandleInputEventAndOverscroll,
            weak_ptr_factory_.GetWeakPtr()));
  }

  void HandleMouseEvent(WebInputEvent::Type type, int x = 0, int y = 0) {
    WebMouseEvent mouse_event(type, WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());

    mouse_event.SetPositionInWidget(gfx::PointF(x, y));
    mouse_event.button = WebMouseEvent::Button::kLeft;
    HandleInputEventWithLatencyInfo(&input_handler_proxy_, mouse_event);
  }

  void DidHandleInputEventAndOverscroll(
      InputHandlerProxy::EventDisposition event_disposition,
      std::unique_ptr<WebCoalescedInputEvent> input_event,
      std::unique_ptr<InputHandlerProxy::DidOverscrollParams> overscroll_params,
      const WebInputEventAttribution& attribution,
      std::unique_ptr<cc::EventMetrics> metrics) {
    event_disposition_recorder_.push_back(event_disposition);
    latency_info_recorder_.push_back(input_event->latency_info());
  }

  base::circular_deque<std::unique_ptr<EventWithCallback>>& event_queue() {
    return input_handler_proxy_.compositor_event_queue_->queue_;
  }

  void SetInputHandlerProxyTickClockForTesting(
      const base::TickClock* tick_clock) {
    input_handler_proxy_.SetTickClockForTesting(tick_clock);
  }

  void DeliverInputForBeginFrame(
      base::TimeTicks frame_time = base::TimeTicks(),
      viz::BeginFrameArgs::BeginFrameArgsType begin_frame_args_type =
          viz::BeginFrameArgs::NORMAL) {
    constexpr base::TimeDelta interval = base::Milliseconds(16);
    if (frame_time.is_null()) {
      frame_time = WebInputEvent::GetStaticTimeStampForTests() +
                   (next_begin_frame_number_ -
                    viz::BeginFrameArgs::kStartingFrameNumber) *
                       interval;
    }
    input_handler_proxy_.DeliverInputForBeginFrame(viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, frame_time,
        frame_time + interval, interval, begin_frame_args_type));
  }

  void DeliverInputForHighLatencyMode() {
    input_handler_proxy_.DeliverInputForHighLatencyMode();
  }

  void SetScrollPredictionEnabled(bool enabled) {
    input_handler_proxy_.scroll_predictor_ =
        enabled ? std::make_unique<ScrollPredictor>() : nullptr;
  }

  std::unique_ptr<ui::InputPredictor::InputData>
  GestureScrollEventPredictionAvailable() {
    return input_handler_proxy_.scroll_predictor_->predictor_
        ->GeneratePrediction(WebInputEvent::GetStaticTimeStampForTests());
  }

  base::TimeTicks NowTimestampForEvents() {
    return input_handler_proxy_.tick_clock_->NowTicks();
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;
  testing::StrictMock<MockInputHandler> mock_input_handler_;
  testing::StrictMock<MockInputHandlerProxyClient> mock_client_;
  TestInputHandlerProxy input_handler_proxy_;
  std::vector<InputHandlerProxy::EventDisposition> event_disposition_recorder_;
  std::vector<ui::LatencyInfo> latency_info_recorder_;

  uint64_t next_begin_frame_number_ = viz::BeginFrameArgs::kStartingFrameNumber;

  base::WeakPtrFactory<InputHandlerProxyEventQueueTest> weak_ptr_factory_{this};
};

// Tests that changing source devices mid gesture scroll is handled gracefully.
// For example, when a touch scroll is in progress and the user initiates a
// scrollbar scroll before the touch scroll has had a chance to dispatch a GSE.
TEST_P(InputHandlerProxyTest, NestedGestureBasedScrollsDifferentSourceDevice) {
  // Touchpad initiates a scroll.
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(ui::ScrollInputType::kWheel,
                        cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  gesture_.SetSourceDevice(WebGestureDevice::kTouchpad);
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));
  EXPECT_TRUE(input_handler_->gesture_scroll_on_impl_thread_for_testing());

  VERIFY_AND_RESET_MOCKS();

  // Before ScrollEnd for touchpad is fired, user starts a thumb drag. This is
  // expected to immediately end the touchpad scroll.
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(ui::ScrollInputType::kWheel))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(ui::ScrollInputType::kScrollbar,
                        cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.SetPositionInWidget(gfx::PointF(0, 20));
  mouse_event.button = WebMouseEvent::Button::kLeft;

  cc::InputHandlerPointerResult pointer_down_result;
  pointer_down_result.type = cc::PointerResultType::kScrollbarScroll;
  pointer_down_result.scroll_delta = gfx::Vector2dF(0, 1);
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(pointer_down_result.type));
  EXPECT_CALL(mock_input_handler_, MouseDown(_, _))
      .WillOnce(testing::Return(pointer_down_result));

  EXPECT_EQ(InputHandlerProxy::DID_NOT_HANDLE,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), mouse_event));

  VERIFY_AND_RESET_MOCKS();

  // Touchpad GSE comes in while a scrollbar drag is in progress. This is
  // expected to be dropped because a scrollbar scroll is currently active.
  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  gesture_.SetSourceDevice(WebGestureDevice::kTouchpad);
  gesture_.data.scroll_update.delta_y = 0;
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(ui::ScrollInputType::kWheel))
      .Times(1);
  EXPECT_EQ(InputHandlerProxy::DROP_EVENT,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));
  VERIFY_AND_RESET_MOCKS();

  // The GSE from the scrollbar needs to be handled.
  EXPECT_CALL(mock_input_handler_,
              RecordScrollEnd(ui::ScrollInputType::kScrollbar))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(1);
  cc::InputHandlerPointerResult pointer_up_result;
  pointer_up_result.type = cc::PointerResultType::kScrollbarScroll;
  EXPECT_CALL(mock_input_handler_, MouseUp(_))
      .WillOnce(testing::Return(pointer_up_result));
  mouse_event.SetType(WebInputEvent::Type::kMouseUp);
  EXPECT_EQ(InputHandlerProxy::DID_NOT_HANDLE,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), mouse_event));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MouseWheelNoListener) {
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  EXPECT_CALL(mock_input_handler_, HasBlockingWheelEventHandlerAt(_))
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(mock_input_handler_,
              GetEventListenerProperties(cc::EventListenerClass::kMouseWheel))
      .WillOnce(testing::Return(cc::EventListenerProperties::kNone));

  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kControlKey,
                           WebInputEvent::GetStaticTimeStampForTests());
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), wheel));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MouseWheelPassiveListener) {
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  EXPECT_CALL(mock_input_handler_, HasBlockingWheelEventHandlerAt(_))
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(mock_input_handler_,
              GetEventListenerProperties(cc::EventListenerClass::kMouseWheel))
      .WillOnce(testing::Return(cc::EventListenerProperties::kPassive));

  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kControlKey,
                           WebInputEvent::GetStaticTimeStampForTests());
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), wheel));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MouseWheelBlockingListener) {
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE;
  EXPECT_CALL(mock_input_handler_, HasBlockingWheelEventHandlerAt(_))
      .WillRepeatedly(testing::Return(true));

  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kControlKey,
                           WebInputEvent::GetStaticTimeStampForTests());
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), wheel));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MouseWheelBlockingAndPassiveListener) {
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE;
  EXPECT_CALL(mock_input_handler_, HasBlockingWheelEventHandlerAt(_))
      .WillRepeatedly(testing::Return(true));
  // We will not call GetEventListenerProperties because we early out when we
  // hit blocking region.
  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kControlKey,
                           WebInputEvent::GetStaticTimeStampForTests());
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), wheel));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MouseWheelEventOutsideBlockingListener) {
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  EXPECT_CALL(mock_input_handler_,
              HasBlockingWheelEventHandlerAt(
                  testing::Property(&gfx::Point::y, testing::Gt(10))))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(mock_input_handler_,
              HasBlockingWheelEventHandlerAt(
                  testing::Property(&gfx::Point::y, testing::Le(10))))
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(mock_input_handler_,
              GetEventListenerProperties(cc::EventListenerClass::kMouseWheel))
      .WillRepeatedly(testing::Return(cc::EventListenerProperties::kBlocking));

  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kControlKey,
                           WebInputEvent::GetStaticTimeStampForTests());
  wheel.SetPositionInScreen(0, 5);
  wheel.SetPositionInWidget(0, 5);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), wheel));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest,
       MouseWheelEventOutsideBlockingListenerWithPassiveListener) {
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  EXPECT_CALL(mock_input_handler_,
              HasBlockingWheelEventHandlerAt(
                  testing::Property(&gfx::Point::y, testing::Gt(10))))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(mock_input_handler_,
              HasBlockingWheelEventHandlerAt(
                  testing::Property(&gfx::Point::y, testing::Le(10))))
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(mock_input_handler_,
              GetEventListenerProperties(cc::EventListenerClass::kMouseWheel))
      .WillRepeatedly(
          testing::Return(cc::EventListenerProperties::kBlockingAndPassive));

  WebMouseWheelEvent wheel(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kControlKey,
                           WebInputEvent::GetStaticTimeStampForTests());
  wheel.SetPositionInScreen(0, 5);
  wheel.SetPositionInWidget(0, 5);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), wheel));
  VERIFY_AND_RESET_MOCKS();
}

// Tests that changing source devices when an animated scroll is in progress
// ends the current scroll offset animation and ensures that a new one gets
// created.
TEST_P(InputHandlerProxyTest, ScrollbarScrollEndOnDeviceChange) {
  // A scrollbar scroll begins.
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(ui::ScrollInputType::kScrollbar,
                        cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);
  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.SetPositionInWidget(gfx::PointF(0, 20));
  mouse_event.button = WebMouseEvent::Button::kLeft;
  cc::InputHandlerPointerResult pointer_down_result;
  pointer_down_result.type = cc::PointerResultType::kScrollbarScroll;
  pointer_down_result.scroll_delta = gfx::Vector2dF(0, 1);
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(pointer_down_result.type));
  EXPECT_CALL(mock_input_handler_, MouseDown(_, _))
      .WillOnce(testing::Return(pointer_down_result));
  EXPECT_EQ(InputHandlerProxy::DID_NOT_HANDLE,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), mouse_event));

  EXPECT_EQ(input_handler_->currently_active_gesture_device(),
            WebGestureDevice::kScrollbar);
  VERIFY_AND_RESET_MOCKS();

  // A mousewheel tick takes place before the scrollbar scroll ends.
  EXPECT_CALL(mock_input_handler_,
              RecordScrollEnd(ui::ScrollInputType::kScrollbar))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(ui::ScrollInputType::kWheel,
                        cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  gesture_.SetSourceDevice(WebGestureDevice::kTouchpad);
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));
  EXPECT_TRUE(input_handler_->gesture_scroll_on_impl_thread_for_testing());
  EXPECT_EQ(input_handler_->currently_active_gesture_device(),
            WebGestureDevice::kTouchpad);

  VERIFY_AND_RESET_MOCKS();

  // Mousewheel GSE is then fired and the mousewheel scroll ends.
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(ui::ScrollInputType::kWheel))
      .Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  gesture_.SetSourceDevice(WebGestureDevice::kTouchpad);
  EXPECT_EQ(InputHandlerProxy::DID_HANDLE,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  // Mouse up gets ignored as the scrollbar scroll already ended before the
  // mousewheel tick took place.
  EXPECT_CALL(mock_input_handler_,
              RecordScrollEnd(ui::ScrollInputType::kScrollbar))
      .Times(1);
  mouse_event.SetType(WebInputEvent::Type::kMouseUp);
  cc::InputHandlerPointerResult pointer_up_result;
  pointer_up_result.type = cc::PointerResultType::kScrollbarScroll;
  EXPECT_CALL(mock_input_handler_, MouseUp(_))
      .WillOnce(testing::Return(pointer_up_result));
  EXPECT_EQ(InputHandlerProxy::DID_NOT_HANDLE,
            HandleInputEventAndFlushEventQueue(
                mock_input_handler_, input_handler_.get(), mouse_event));
  VERIFY_AND_RESET_MOCKS();
}

void InputHandlerProxyTest::GestureScrollStarted() {
  // We shouldn't send any events to the widget for this gesture.
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  // The event should not be marked as handled if scrolling is not possible.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGestureScrollUpdate);
  gesture_.data.scroll_update.delta_y =
      -40;  // -Y means scroll down - i.e. in the +Y direction.
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_not_scroll_));
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  // Mark the event as handled if scroll happens.
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGestureScrollUpdate);
  gesture_.data.scroll_update.delta_y =
      -40;  // -Y means scroll down - i.e. in the +Y direction.
  EXPECT_CALL(
      mock_input_handler_,
      ScrollUpdate(testing::Property(&cc::ScrollState::delta_y, testing::Gt(0)),
                   _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  gesture_.data.scroll_update.delta_y = 0;
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();
}
TEST_P(InputHandlerProxyTest, GestureScrollStarted) {
  GestureScrollStarted();
}

TEST_P(InputHandlerProxyTest, GestureScrollIgnored) {
  // We shouldn't handle the GestureScrollBegin.
  // Instead, we should get a DROP_EVENT result, indicating
  // that we could determine that there's nothing that could scroll or otherwise
  // react to this gesture sequence and thus we should drop the whole gesture
  // sequence on the floor, except for the ScrollEnd.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kScrollIgnoredScrollState));
  EXPECT_CALL(mock_input_handler_, RecordScrollBegin(_, _)).Times(0);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  // GSB is dropped and not sent to the main thread, GSE shouldn't get sent to
  // the main thread, either.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(0);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, GestureScrollByPage) {
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  gesture_.data.scroll_begin.delta_hint_units =
      ui::ScrollGranularity::kScrollByPage;
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
      .WillOnce(testing::Return(scroll_result_did_scroll_));

  gesture_.SetType(WebInputEvent::Type::kGestureScrollUpdate);
  gesture_.data.scroll_update.delta_y = 1;
  gesture_.data.scroll_update.delta_units =
      ui::ScrollGranularity::kScrollByPage;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(1);
  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  gesture_.data.scroll_update.delta_y = 0;
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, GestureScrollBeginThatTargetViewport) {
  // We shouldn't send any events to the widget for this gesture.
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, RootScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  gesture_.data.scroll_begin.target_viewport = true;
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();
}

void InputHandlerProxyTest::FlingAndSnap() {
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  // The event should be dropped if InputHandler decides to snap.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGestureScrollUpdate);
  gesture_.data.scroll_update.delta_y =
      -40;  // -Y means scroll down - i.e. in the +Y direction.
  gesture_.data.scroll_update.inertial_phase =
      WebGestureEvent::InertialPhaseState::kMomentum;
  EXPECT_CALL(mock_input_handler_,
              GetSnapFlingInfoAndSetAnimatingSnapTarget(_, _, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<2>(gfx::PointF(0, 0)),
                      testing::SetArgPointee<3>(gfx::PointF(0, 100)),
                      testing::Return(true)));
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);
  EXPECT_SET_NEEDS_ANIMATE_INPUT(1);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, SnapFlingIgnoresFollowingGSUAndGSE) {
  FlingAndSnap();
  // The next GestureScrollUpdate should also be ignored, and will not ask for
  // snap position.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;

  EXPECT_CALL(mock_input_handler_,
              GetSnapFlingInfoAndSetAnimatingSnapTarget(_, _, _, _))
      .Times(0);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(0);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));
  VERIFY_AND_RESET_MOCKS();

  // The GestureScrollEnd should also be ignored.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  gesture_.data.scroll_end.inertial_phase =
      WebGestureEvent::InertialPhaseState::kMomentum;
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(0);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(_)).Times(0);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, GesturePinch) {
  // We shouldn't send any events to the widget for this gesture.
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGesturePinchBegin);
  EXPECT_CALL(mock_input_handler_, PinchGestureBegin(_, _));
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGesturePinchUpdate);
  gesture_.data.pinch_update.scale = 1.5;
  gesture_.SetPositionInWidget(gfx::PointF(7, 13));
  EXPECT_CALL(mock_input_handler_, PinchGestureUpdate(1.5, gfx::Point(7, 13)));
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGesturePinchUpdate);
  gesture_.data.pinch_update.scale = 0.5;
  gesture_.SetPositionInWidget(gfx::PointF(9, 6));
  EXPECT_CALL(mock_input_handler_, PinchGestureUpdate(.5, gfx::Point(9, 6)));
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();

  gesture_.SetType(WebInputEvent::Type::kGesturePinchEnd);
  EXPECT_CALL(mock_input_handler_, PinchGestureEnd(gfx::Point(9, 6)));
  EXPECT_EQ(expected_disposition_,
            HandleInputEventAndFlushEventQueue(mock_input_handler_,
                                               input_handler_.get(), gesture_));

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest,
       GestureScrollOnImplThreadFlagClearedAfterScrollEnd) {
  // We shouldn't send any events to the widget for this gesture.
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  // After sending a GestureScrollBegin, the member variable
  // |gesture_scroll_on_impl_thread_| should be true.
  EXPECT_TRUE(input_handler_->gesture_scroll_on_impl_thread_for_testing());

  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollEnd(true));
  gesture_.SetType(WebInputEvent::Type::kGestureScrollEnd);
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  // |gesture_scroll_on_impl_thread_| should be false once a GestureScrollEnd
  // gets handled.
  EXPECT_FALSE(input_handler_->gesture_scroll_on_impl_thread_for_testing());

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest,
       BeginScrollWhenGestureScrollOnImplThreadFlagIsSet) {
  // We shouldn't send any events to the widget for this gesture.
  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(testing::Return(kImplThreadScrollState));
  EXPECT_CALL(
      mock_input_handler_,
      RecordScrollBegin(_, cc::ScrollBeginThreadState::kScrollingOnCompositor))
      .Times(1);

  gesture_.SetType(WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), gesture_));

  // After sending a GestureScrollBegin, the member variable
  // |gesture_scroll_on_impl_thread_| should be true.
  EXPECT_TRUE(input_handler_->gesture_scroll_on_impl_thread_for_testing());

  expected_disposition_ = InputHandlerProxy::DID_HANDLE;
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, HitTestTouchEventNonNullTouchAction) {
  // One of the touch points is on a touch-region. So the event should be sent
  // to the main thread.
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Eq(0)), _))
      .WillOnce(testing::Invoke([](const gfx::Point&,
                                   cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kMax;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Gt(0)), _))
      .WillOnce(
          testing::Invoke([](const gfx::Point&, cc::TouchAction* touch_action) {
            *touch_action = cc::TouchAction::kPanUp;
            return cc::InputHandler::TouchStartOrMoveEventListenerType::
                kHandlerOnScrollingLayer;
          }));
  // Since the second touch point hits a touch-region, there should be no
  // hit-testing for the third touch point.

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.touches_length = 3;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  touch.touches[1] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  touch.touches[2] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, -10, 10);

  bool is_touching_scrolling_layer;
  cc::TouchAction allowed_touch_action = cc::TouchAction::kAuto;
  EXPECT_EQ(expected_disposition_,
            input_handler_->HitTestTouchEventForTest(
                touch, &is_touching_scrolling_layer, &allowed_touch_action));
  EXPECT_TRUE(is_touching_scrolling_layer);
  EXPECT_EQ(allowed_touch_action, cc::TouchAction::kPanUp);
  VERIFY_AND_RESET_MOCKS();
}

// Tests that multiple mousedown(s) on scrollbar are handled gracefully and
// don't fail any DCHECK(s).
TEST_F(InputHandlerProxyEventQueueTest,
       NestedGestureBasedScrollsSameSourceDevice) {
  // Start with mousedown. Expect CompositorThreadEventQueue to contain [GSB,
  // GSU].
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput());
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(3)
      .WillRepeatedly(testing::Return(cc::ElementId()));

  cc::InputHandlerPointerResult pointer_down_result;
  pointer_down_result.type = cc::PointerResultType::kScrollbarScroll;
  pointer_down_result.scroll_delta = gfx::Vector2dF(0, 1);
  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(pointer_down_result.type));
  EXPECT_CALL(mock_input_handler_, MouseDown(_, _))
      .WillOnce(testing::Return(pointer_down_result));

  HandleMouseEvent(WebInputEvent::Type::kMouseDown);
  EXPECT_EQ(2ul, event_queue().size());
  EXPECT_EQ(event_queue()[0]->event().GetType(),
            WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(event_queue()[1]->event().GetType(),
            WebInputEvent::Type::kGestureScrollUpdate);

  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(Return(kImplThreadScrollState));
  EXPECT_CALL(mock_input_handler_, RecordScrollBegin(_, _)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);

  DeliverInputForBeginFrame();
  Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // A mouseup adds a GSE to the CompositorThreadEventQueue.
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput());
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId()));
  cc::InputHandlerPointerResult pointer_up_result;
  pointer_up_result.type = cc::PointerResultType::kScrollbarScroll;
  EXPECT_CALL(mock_input_handler_, MouseUp(_))
      .WillOnce(testing::Return(pointer_up_result));
  HandleMouseEvent(WebInputEvent::Type::kMouseUp);
  Mock::VerifyAndClearExpectations(&mock_input_handler_);

  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(1)
      .WillOnce(testing::Return(cc::ElementId()));
  EXPECT_EQ(1ul, event_queue().size());
  EXPECT_EQ(event_queue()[0]->event().GetType(),
            WebInputEvent::Type::kGestureScrollEnd);

  // Called when a mousedown is being handled as it tries to end the ongoing
  // scroll.
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(1);

  EXPECT_CALL(mock_input_handler_, HitTest(_))
      .WillOnce(testing::Return(pointer_down_result.type));
  EXPECT_CALL(mock_input_handler_, MouseDown(_, _))
      .WillOnce(testing::Return(pointer_down_result));
  // A mousedown occurs on the scrollbar *before* the GSE is dispatched.
  HandleMouseEvent(WebInputEvent::Type::kMouseDown);
  Mock::VerifyAndClearExpectations(&mock_input_handler_);

  EXPECT_EQ(3ul, event_queue().size());
  EXPECT_EQ(event_queue()[1]->event().GetType(),
            WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(event_queue()[2]->event().GetType(),
            WebInputEvent::Type::kGestureScrollUpdate);

  // Called when the GSE is being handled. (Note that ScrollEnd isn't called
  // when the GSE is being handled as the GSE gets dropped in
  // HandleGestureScrollEnd because handling_gesture_on_impl_thread_ is false)
  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
      .WillOnce(Return(kImplThreadScrollState));
  EXPECT_CALL(mock_input_handler_, RecordScrollBegin(_, _)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(3)
      .WillRepeatedly(testing::Return(cc::ElementId()));

  DeliverInputForBeginFrame();
  Mock::VerifyAndClearExpectations(&mock_input_handler_);

  // Finally, a mouseup ends the scroll.
  EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput());
  EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
      .Times(2)
      .WillRepeatedly(testing::Return(cc::ElementId()));
  EXPECT_CALL(mock_input_handler_, MouseUp(_))
      .WillOnce(testing::Return(pointer_up_result));
  HandleMouseEvent(WebInputEvent::Type::kMouseUp);

  EXPECT_CALL(mock_input_handler_, RecordScrollEnd(_)).Times(1);
  EXPECT_CALL(mock_input_handler_, ScrollEnd(true)).Times(1);

  DeliverInputForBeginFrame();
  Mock::VerifyAndClearExpectations(&mock_input_handler_);
}

// Tests that the allowed touch action is correctly set when a touch is made
// non-blocking due to an ongoing fling. https://crbug.com/1048098.
TEST_F(InputHandlerProxyEventQueueTest, AckTouchActionNonBlockingForFling) {
  // Simulate starting a compositor scroll and then flinging. This is setup for
  // the real checks below.
  {
    float delta = 10;

    // ScrollBegin
    {
      EXPECT_CALL(mock_input_handler_, ScrollBegin(_, _))
          .WillOnce(Return(kImplThreadScrollState));
      EXPECT_CALL(
          mock_input_handler_,
          RecordScrollBegin(_, ScrollBeginThreadState::kScrollingOnCompositor))
          .Times(1);
      EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
          .Times(1)
          .WillOnce(testing::Return(cc::ElementId()));

      HandleGestureEvent(WebInputEvent::Type::kGestureScrollBegin, delta);
      Mock::VerifyAndClearExpectations(&mock_input_handler_);
    }

    // ScrollUpdate
    {
      EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
      EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
          .Times(1)
          .WillOnce(testing::Return(cc::ElementId()));
      EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _)).Times(1);

      HandleGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, delta);
      DeliverInputForBeginFrame();
      Mock::VerifyAndClearExpectations(&mock_input_handler_);
    }

    // Start a fling - ScrollUpdate with momentum
    {
      cc::InputHandlerScrollResult scroll_result_did_scroll;
      scroll_result_did_scroll.did_scroll = true;
      EXPECT_CALL(mock_input_handler_, ScrollUpdate(_, _))
          .WillOnce(Return(scroll_result_did_scroll));
      EXPECT_CALL(mock_input_handler_, SetNeedsAnimateInput()).Times(1);
      EXPECT_CALL(mock_input_handler_, FindFrameElementIdAtPoint(_))
          .Times(2)
          .WillRepeatedly(testing::Return(cc::ElementId()));
      EXPECT_CALL(mock_input_handler_,
                  GetSnapFlingInfoAndSetAnimatingSnapTarget(_, _, _, _))
          .WillOnce(Return(false));

      auto gsu_fling = CreateGestureScrollPinch(
          WebInputEvent::Type::kGestureScrollUpdate,
          WebGestureDevice::kTouchscreen, NowTimestampForEvents(), delta,
          /*x=*/0, /*y=*/0);
      static_cast<WebGestureEvent*>(gsu_fling.get())
          ->data.scroll_update.inertial_phase =
          WebGestureEvent::InertialPhaseState::kMomentum;
      InjectInputEvent(std::move(gsu_fling));
      DeliverInputForBeginFrame();
    }
  }

  // We're now in an active gesture fling. Simulate the user touching down on
  // the screen. If this touch hits a blocking region (e.g. touch-action or a
  // non-passive touchstart listener), we won't actually treat it as blocking;
  // because of the ongoing fling it will be treated as non blocking. However,
  // we also have to ensure that the allowed_touch_action reported is also kAuto
  // so that the browser knows that it shouldn't wait for an ACK with an allowed
  // touch-action before dispatching more scrolls.
  {
    // Simulate hitting a blocking region on the scrolling layer, as if there
    // was a non-passive touchstart handler.
    EXPECT_CALL(mock_input_handler_,
                EventListenerTypeForTouchStartOrMoveAt(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(TouchAction::kNone),
                        Return(InputHandler::TouchStartOrMoveEventListenerType::
                                   kHandlerOnScrollingLayer)));

    std::unique_ptr<WebTouchEvent> touch_start =
        std::make_unique<WebTouchEvent>(
            WebInputEvent::Type::kTouchStart, WebInputEvent::kNoModifiers,
            WebInputEvent::GetStaticTimeStampForTests());
    touch_start->touches_length = 1;
    touch_start->touch_start_or_first_touch_move = true;
    touch_start->touches[0] =
        CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);

    // This is the call this test is checking: we expect that the client will
    // report the touch as non-blocking and also that the allowed touch action
    // matches the non blocking expectation (i.e. all touches are allowed).
    EXPECT_CALL(mock_client_, SetAllowedTouchAction(TouchAction::kAuto))
        .WillOnce(Return());
    EXPECT_CALL(mock_input_handler_, SetIsHandlingTouchSequence(true));

    InjectInputEvent(std::move(touch_start));
  }
}

TEST_P(InputHandlerProxyTest, HitTestTouchEventNullTouchAction) {
  // One of the touch points is on a touch-region. So the event should be sent
  // to the main thread.
  expected_disposition_ = InputHandlerProxy::DID_NOT_HANDLE;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Eq(0)), _))
      .WillOnce(testing::Return(
          cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler));

  EXPECT_CALL(mock_input_handler_,
              EventListenerTypeForTouchStartOrMoveAt(
                  testing::Property(&gfx::Point::x, testing::Gt(0)), _))
      .WillOnce(
          testing::Return(cc::InputHandler::TouchStartOrMoveEventListenerType::
                              kHandlerOnScrollingLayer));
  // Since the second touch point hits a touch-region, there should be no
  // hit-testing for the third touch point.

  WebTouchEvent touch(WebInputEvent::Type::kTouchMove,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.touches_length = 3;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 0, 0);
  touch.touches[1] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  touch.touches[2] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, -10, 10);

  bool is_touching_scrolling_layer;
  cc::TouchAction* allowed_touch_action = nullptr;
  EXPECT_EQ(expected_disposition_,
            input_handler_->HitTestTouchEventForTest(
                touch, &is_touching_scrolling_layer, allowed_touch_action));
  EXPECT_TRUE(is_touching_scrolling_layer);
  EXPECT_TRUE(!allowed_touch_action);
  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHandlerProxyTest, MultiTouchPointHitTestNegative) {
  // None of the three touch points fall in the touch region. So the event
  // should be dropped.
  expected_disposition_ = InputHandlerProxy::DROP_EVENT;
  VERIFY_AND_RESET_MOCKS();

  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchStartOrMove))
      .WillOnce(testing::Return(cc::EventListenerProperties::kNone));
  EXPECT_CALL(
      mock_input_handler_,
      GetEventListenerProperties(cc::EventListenerClass::kTouchEndOrCancel))
      .WillOnce(testing::Return(cc::EventListenerProperties::kNone));
  EXPECT_CALL(mock_input_handler_, EventListenerTypeForTouchStartOrMoveAt(_, _))
      .Times(2)
      .WillRepeatedly(testing::Invoke([](const gfx::Point&,
                                         cc::TouchAction* touch_action) {
        *touch_action = cc::TouchAction::kPanUp;
        return cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler;
      }));
  EXPECT_CALL(mock_client_, SetAllowedTouchAction(cc::TouchAction::kPanUp))
      .WillOnce(testing::Return());

  WebTouchEvent touch(WebInputEvent::Type::kTouchStart,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  touch.unique_touch_event_id = 1;
  touch.touches_length = 3;
  touch.touch_start_or_first_touch_move = true;
  touch.touches[0] =
      CreateWebTouchPoint(WebTouchPoint::State::kStateStationary, 0, 0);
  touch.touches[1] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, 10, 10);
  touch.touches[2] =
      CreateWebTouchPoint(WebTouchPoint::State::kStatePressed, -10, 10);
  EXPECT_EQ(expected_disposition_,
            HandleInputEventWithLatencyInfo(input_handler_.get(), touch));

  VERIFY_AND_RESET_MOCKS();
}

TEST_P(InputHan
```