Response:
My thinking process for summarizing the `InputHandlerProxy` code goes like this:

1. **Understand the Context:** The file path `blink/renderer/platform/widget/input/input_handler_proxy.cc` immediately tells me this is part of the Blink rendering engine, specifically dealing with input handling in the widget layer. The "proxy" suffix suggests it mediates communication between different parts of the input system.

2. **Identify Key Includes:**  The `#include` directives reveal a lot about the class's responsibilities. I scan them for important keywords:
    * `third_party/blink/renderer/platform/widget/input/input_handler_proxy.h`:  Indicates the header file, likely defining the `InputHandlerProxy` class itself.
    * `cc/`:  Points to the Chromium Compositor, meaning this class interacts with the compositor for tasks like scrolling and animation.
    * `third_party/blink/public/common/input/`: Shows it deals with various input event types (mouse, touch, gesture).
    * `third_party/blink/renderer/platform/widget/input/`:  Highlights other related input components within Blink, like `CompositorThreadEventQueue`, `CursorControlHandler`, `ElasticOverscrollController`, etc.
    * `base/`:  Indicates use of general Chromium base utilities like `bind`, `callback`, `location`, `metrics`, `time`, tracing (`TRACE_EVENT`).
    * `ui/events/`:  Related to UI event types.
    * `ui/latency/`:  Handles latency tracking for input events.

3. **Initial Function Scan (High-Level):** I quickly skim through the public methods of the `InputHandlerProxy` class. I'm looking for verbs that suggest the class's core functions:
    * `HandleInputEventWithLatencyInfo`: The primary entry point for input events. The "LatencyInfo" part is significant.
    * `ContinueScrollBeginAfterMainThreadHitTest`:  Handles the continuation of a scroll after a main thread check.
    * `DispatchSingleInputEvent`, `DispatchQueuedInputEvents`:  Methods for sending input events.
    * `InjectScrollbarGestureScroll`:  Specifically for injecting scrollbar interactions.
    * `HandleMouseWheel`, `HandleGestureScrollBegin`, `HandleGestureScrollUpdate`, `HandleGestureScrollEnd`, `HandleTouchStart`, `HandleTouchMove`, `HandleTouchEnd`:  Individual handlers for different input event types.
    * `Animate`:  Deals with animations, likely related to scrolling or overscroll.
    * `SetPrefersReducedMotion`:  Handles user preferences.
    * `UpdateRootLayerStateForSynchronousInputHandler`:  For synchronous input scenarios.
    * `DeliverInputForBeginFrame`:  Crucial for coordinating input with the frame rendering pipeline.

4. **Identify Core Responsibilities:** Based on the includes and the function names, I start to formulate the core responsibilities of `InputHandlerProxy`:
    * **Receiving and Routing Input Events:** It acts as a central point for receiving various types of input events.
    * **Interaction with the Compositor:** It communicates with the compositor to handle scrolling, pinch-zoom, and other visual updates.
    * **Main Thread Communication:** It manages situations where input handling needs information from the main thread (e.g., hit testing).
    * **Input Event Queuing and Dispatching:** It has a queue for managing input events, especially during ongoing gestures.
    * **Latency Tracking:**  It integrates with Chromium's latency tracking mechanisms to measure input responsiveness.
    * **Feature Integration:** It incorporates other input-related features like elastic overscroll, snap flinging, and cursor control.
    * **Scroll Prediction:** It uses a `ScrollPredictor` to potentially improve scrolling smoothness.

5. **Group Related Functionality:** I group the identified functions into logical categories:
    * **Input Event Handling:** The various `Handle...` methods.
    * **Compositor Interaction:** Methods that directly call the `cc::InputHandler`.
    * **Queuing and Dispatching:** `DispatchSingleInputEvent`, `DispatchQueuedInputEvents`.
    * **Specialized Input:** `InjectScrollbarGestureScroll`.
    * **Animation and Synchronization:** `Animate`, `DeliverInputForBeginFrame`, `UpdateRootLayerStateForSynchronousInputHandler`.
    * **Feature-Specific Handling:** Methods related to elastic overscroll, snap flinging, etc.

6. **Refine the Summary:** I synthesize the grouped information into a concise summary, highlighting the key responsibilities and interactions. I try to use clear and descriptive language.

7. **Address Specific Instructions (Where Applicable in Part 1):**
    * **Function Listing:** I mentally list the core functionalities as identified above.
    * **Relationship to JavaScript/HTML/CSS:**  At this stage (Part 1), the direct connections are implicit. The code handles events triggered by user interaction with web content (rendered HTML/CSS) and may influence JavaScript event handlers. Specific examples will likely be in Part 2, where we see the actual logic inside the handlers.
    * **Logical Reasoning (Hypothetical Input/Output):**  For Part 1, the logical reasoning is general: Input events come in, are processed and potentially queued, and then dispatched to the compositor. More specific input/output examples would require deeper analysis of individual handlers.
    * **User/Programming Errors:**  Again, for Part 1, the errors are more conceptual. For example, if the compositor isn't responding, input might get backed up. More concrete examples might emerge from examining specific error handling or assumptions within the code.

8. **Structure the Output:** I organize the summary into clear sections (Core Functionality, Key Aspects, Relationships, etc.) to make it easy to understand.

By following this process, I can systematically analyze the provided code snippet and generate a comprehensive and informative summary of its functionality, even without diving into the detailed implementation of every method. The focus in Part 1 is on the overall purpose and structure.

```
这是目录为blink/renderer/platform/widget/input/input_handler_proxy.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

**InputHandlerProxy.cc (第 1 部分) 的功能归纳:**

`InputHandlerProxy` 是 Chromium Blink 渲染引擎中处理输入事件的核心组件之一。它充当了渲染进程中接收到的各种输入事件（例如鼠标、触摸、手势等）的代理，并负责将这些事件路由到合适的处理程序，最终影响页面的渲染和 JavaScript 代码的执行。

**核心功能:**

1. **输入事件接收与分发:**
   - 接收来自浏览器进程的各种原始输入事件 (`WebCoalescedInputEvent`)，并附加延迟信息 (`LatencyInfo`).
   - 根据事件类型（鼠标、触摸、手势等）和当前状态，将事件分发到相应的内部处理函数（例如 `HandleMouseWheel`, `HandleGestureScrollBegin` 等）。
   - 维护一个事件队列 (`compositor_event_queue_`)，用于在特定情况下（例如正在进行的手势操作）暂存事件。

2. **与 Compositor 的交互:**
   - 作为 `cc::InputHandler` 的客户端，将处理后的输入事件传递给 Compositor 线程进行合成和渲染。
   - 监听 Compositor 的回调，例如 `DeliverInputForBeginFrame`，以同步输入事件的处理与渲染帧的生成。
   - 处理与 Compositor 相关的状态，例如判断滚动是否发生在 Compositor 线程。

3. **手势处理:**
   - 负责处理各种手势事件，如滚动 (`GestureScrollBegin`, `GestureScrollUpdate`, `GestureScrollEnd`) 和缩放 (`GesturePinchBegin`, `GesturePinchUpdate`, `GesturePinchEnd`)。
   - 管理手势操作的状态，例如 `handling_gesture_on_impl_thread_` 标识是否在 Compositor 线程上处理手势。
   - 处理惯性滚动 (inertial scrolling)。
   - 集成了 `SnapFlingController` 用于处理滚动吸附和甩动。

4. **触摸事件处理:**
   - 处理触摸事件 (`TouchStart`, `TouchMove`, `TouchEnd`, `TouchCancel`)，并进行命中测试 (`HitTestTouchEvent`)，判断触摸点是否在可滚动的图层上或是否有事件监听器。
   - 决定触摸事件是否应该被发送到主线程处理。
   - 管理触摸序列的状态。

5. **鼠标事件处理:**
   - 处理鼠标滚轮事件 (`MouseWheel`)，判断是否有阻塞的事件监听器。
   - 处理鼠标按下 (`MouseDown`)、抬起 (`MouseUp`) 和移动 (`MouseMove`) 事件，用于检测滚动条交互。

6. **延迟信息追踪:**
   - 利用 `LatencyInfo` 追踪输入事件从发生到渲染的延迟。

7. **弹性拉伸效果 (Elastic Overscroll):**
   - 集成 `ElasticOverscrollController` 来实现页面边缘的弹性拉伸效果。

8. **滚动预测 (Scroll Prediction):**
   - 可选地使用 `ScrollPredictor` 来预测后续的滚动事件，以提高滚动平滑度 (需要 feature flag 启用)。

9. **滚动条交互:**
   - 支持模拟滚动条手势滚动 (`InjectScrollbarGestureScroll`)。

10. **同步输入处理:**
    - 支持与同步输入处理器的交互 (`synchronous_input_handler_`)，用于某些需要同步更新的场景。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    - 当用户在页面上滚动时，`InputHandlerProxy` 处理 `GestureScrollUpdate` 事件。如果 JavaScript 代码注册了 `scroll` 事件监听器，`InputHandlerProxy` 会决定是否将事件传递给主线程，从而触发 JavaScript 代码的执行。
    - 当用户触摸屏幕时，`InputHandlerProxy` 处理 `TouchStart` 事件，并根据命中测试的结果，决定是否将事件传递给绑定在 HTML 元素上的 JavaScript 触摸事件监听器 (`touchstart`, `touchmove`, `touchend`).
    - **假设输入与输出:** 假设用户在触摸屏上滑动手指 (`TouchMove` 事件)。`InputHandlerProxy` 可能会先将事件发送给 Compositor 进行滚动，同时如果该位置有 JavaScript 监听器，也会通知主线程执行相应的 JavaScript 代码。

* **HTML:**
    - HTML 结构定义了页面的可滚动区域和元素。`InputHandlerProxy` 的命中测试会检查触摸或鼠标事件发生的位置是否在这些可滚动元素上。
    - **假设输入与输出:** 假设 HTML 中有一个 `<div>` 元素设置了 `overflow: auto;` 属性，使其可以滚动。当用户在该 `<div>` 元素内进行滚动操作时，`InputHandlerProxy` 会识别出这是对可滚动区域的操作。

* **CSS:**
    - CSS 的 `touch-action` 属性可以影响 `InputHandlerProxy` 对触摸事件的处理。例如，`touch-action: none;` 可以阻止元素的默认触摸行为，例如滚动。
    - **假设输入与输出:** 假设一个 HTML 元素设置了 `touch-action: pan-y;`。当用户在该元素上进行垂直滑动时，`InputHandlerProxy` 会允许垂直滚动，但会阻止水平滑动。

**逻辑推理的假设输入与输出 (更具体的例子在 Part 2 可能更多):**

* **假设输入:** 用户使用鼠标滚轮向下滚动。
* **输出:** `InputHandlerProxy` 接收到 `MouseWheel` 事件。如果页面没有阻塞的滚轮事件监听器，`InputHandlerProxy` 会将滚轮增量信息传递给 Compositor，Compositor 更新页面的滚动位置并重新绘制。

* **假设输入:** 用户在触摸屏上进行双指捏合手势。
* **输出:** `InputHandlerProxy` 接收到 `GesturePinchBegin` 和后续的 `GesturePinchUpdate` 事件。它会将缩放比例信息传递给 Compositor，Compositor 执行页面的缩放操作。

**用户或编程常见的使用错误举例:**

* **JavaScript 中使用 `preventDefault()` 阻止默认滚动行为:**  如果 JavaScript 代码在滚轮或触摸事件监听器中调用了 `preventDefault()`，`InputHandlerProxy` 会收到通知，并可能阻止 Compositor 进行优化后的滚动，导致滚动性能下降。

* **不恰当的 `touch-action` CSS 属性使用:**  错误地设置 `touch-action: none;` 可能会意外地阻止用户的滚动交互。

**总结 (针对第 1 部分):**

`InputHandlerProxy` 的主要职责是作为渲染引擎中输入事件的入口点和调度中心。它负责接收、分类和初步处理各种输入事件，并与 Compositor 紧密协作来驱动页面的渲染更新。它还需要考虑 JavaScript 事件监听器的存在，并协调输入事件在渲染线程和主线程之间的传递。第 1 部分的代码主要关注事件的接收、初步处理、与 Compositor 的交互以及手势和触摸事件的基础处理逻辑。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/input_handler_proxy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/input_handler_proxy.h"

#include <stddef.h>

#include <algorithm>

#include "base/check_op.h"
#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/profiler/sample_metadata.h"
#include "base/task/common/task_annotator.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "base/tracing/protos/chrome_track_event.pbzero.h"
#include "base/types/optional_ref.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/input/browser_controls_offset_tags_info.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/metrics/event_metrics.h"
#include "cc/trees/latency_info_swap_promise_monitor.h"
#include "services/tracing/public/cpp/perfetto/macros.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/renderer/platform/widget/input/compositor_thread_event_queue.h"
#include "third_party/blink/renderer/platform/widget/input/cursor_control_handler.h"
#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller.h"
#include "third_party/blink/renderer/platform/widget/input/event_with_callback.h"
#include "third_party/blink/renderer/platform/widget/input/input_handler_proxy_client.h"
#include "third_party/blink/renderer/platform/widget/input/input_metrics.h"
#include "third_party/blink/renderer/platform/widget/input/scroll_predictor.h"
#include "ui/events/types/scroll_input_type.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/latency/latency_info.h"

using ScrollThread = cc::InputHandler::ScrollThread;

namespace blink {
namespace {

using ::perfetto::protos::pbzero::ChromeLatencyInfo2;
using ::perfetto::protos::pbzero::TrackEvent;

cc::ScrollStateData CreateScrollStateDataForGesture(
    const WebGestureEvent& event) {
  cc::ScrollStateData scroll_state_data;
  if (event.SourceDevice() == WebGestureDevice::kScrollbar) {
    scroll_state_data.is_scrollbar_interaction = true;
  }
  switch (event.GetType()) {
    case WebInputEvent::Type::kGestureScrollBegin:
      scroll_state_data.position_x = event.PositionInWidget().x();
      scroll_state_data.position_y = event.PositionInWidget().y();
      scroll_state_data.delta_x_hint = -event.data.scroll_begin.delta_x_hint;
      scroll_state_data.delta_y_hint = -event.data.scroll_begin.delta_y_hint;
      scroll_state_data.is_beginning = true;
      // On Mac, a GestureScrollBegin in the inertial phase indicates a fling
      // start.
      scroll_state_data.is_in_inertial_phase =
          (event.data.scroll_begin.inertial_phase ==
           WebGestureEvent::InertialPhaseState::kMomentum);
      scroll_state_data.delta_granularity =
          event.data.scroll_begin.delta_hint_units;

      if (cc::ElementId::IsValidInternalValue(
              event.data.scroll_begin.scrollable_area_element_id)) {
        cc::ElementId target_scroller(
            event.data.scroll_begin.scrollable_area_element_id);
        scroll_state_data.set_current_native_scrolling_element(target_scroller);

        scroll_state_data.main_thread_hit_tested_reasons =
            event.data.scroll_begin.main_thread_hit_tested_reasons;
      } else {
        // If a main thread hit test didn't yield a target we should have
        // discarded this event before this point.
        DCHECK(!event.data.scroll_begin.main_thread_hit_tested_reasons);
      }

      break;
    case WebInputEvent::Type::kGestureScrollUpdate:
      scroll_state_data.delta_x = -event.data.scroll_update.delta_x;
      scroll_state_data.delta_y = -event.data.scroll_update.delta_y;
      scroll_state_data.is_in_inertial_phase =
          event.data.scroll_update.inertial_phase ==
          WebGestureEvent::InertialPhaseState::kMomentum;
      scroll_state_data.delta_granularity =
          event.data.scroll_update.delta_units;
      break;
    case WebInputEvent::Type::kGestureScrollEnd:
      scroll_state_data.is_ending = true;
      break;
    default:
      NOTREACHED();
  }
  scroll_state_data.is_direct_manipulation =
      event.SourceDevice() == WebGestureDevice::kTouchscreen;
  return scroll_state_data;
}

cc::ScrollState CreateScrollStateForInertialUpdate(
    const gfx::Vector2dF& delta) {
  cc::ScrollStateData scroll_state_data;
  scroll_state_data.delta_x = delta.x();
  scroll_state_data.delta_y = delta.y();
  scroll_state_data.is_in_inertial_phase = true;
  return cc::ScrollState(scroll_state_data);
}

ui::ScrollInputType GestureScrollInputType(WebGestureDevice device) {
  switch (device) {
    case WebGestureDevice::kTouchpad:
      return ui::ScrollInputType::kWheel;
    case WebGestureDevice::kTouchscreen:
      return ui::ScrollInputType::kTouchscreen;
    case WebGestureDevice::kSyntheticAutoscroll:
      return ui::ScrollInputType::kAutoscroll;
    case WebGestureDevice::kScrollbar:
      return ui::ScrollInputType::kScrollbar;
    case WebGestureDevice::kUninitialized:
      NOTREACHED();
  }
}

cc::SnapFlingController::GestureScrollType GestureScrollEventType(
    WebInputEvent::Type web_event_type) {
  switch (web_event_type) {
    case WebInputEvent::Type::kGestureScrollBegin:
      return cc::SnapFlingController::GestureScrollType::kBegin;
    case WebInputEvent::Type::kGestureScrollUpdate:
      return cc::SnapFlingController::GestureScrollType::kUpdate;
    case WebInputEvent::Type::kGestureScrollEnd:
      return cc::SnapFlingController::GestureScrollType::kEnd;
    default:
      NOTREACHED();
  }
}

cc::SnapFlingController::GestureScrollUpdateInfo GetGestureScrollUpdateInfo(
    const WebGestureEvent& event) {
  cc::SnapFlingController::GestureScrollUpdateInfo info;
  info.delta = gfx::Vector2dF(-event.data.scroll_update.delta_x,
                              -event.data.scroll_update.delta_y);
  info.is_in_inertial_phase = event.data.scroll_update.inertial_phase ==
                              WebGestureEvent::InertialPhaseState::kMomentum;
  info.event_time = event.TimeStamp();
  return info;
}

cc::ScrollBeginThreadState RecordScrollingThread(
    bool scrolling_on_compositor_thread,
    bool blocked_on_main_at_begin,
    WebGestureDevice device) {
  const char* kWheelHistogramName = "Renderer4.ScrollingThread.Wheel";
  const char* kTouchHistogramName = "Renderer4.ScrollingThread.Touch";

  auto status = cc::ScrollBeginThreadState::kScrollingOnMain;
  if (scrolling_on_compositor_thread) {
    status =
        blocked_on_main_at_begin
            ? cc::ScrollBeginThreadState::kScrollingOnCompositorBlockedOnMain
            : cc::ScrollBeginThreadState::kScrollingOnCompositor;
  }

  if (device == WebGestureDevice::kTouchscreen) {
    UMA_HISTOGRAM_ENUMERATION(kTouchHistogramName, status);
  } else if (device == WebGestureDevice::kTouchpad) {
    UMA_HISTOGRAM_ENUMERATION(kWheelHistogramName, status);
  } else if (device == WebGestureDevice::kScrollbar) {
    // TODO(crbug.com/1101502): Add support for
    // Renderer4.ScrollingThread.Scrollbar
  } else {
    NOTREACHED();
  }
  return status;
}

bool IsGestureScrollOrPinch(WebInputEvent::Type type) {
  switch (type) {
    case WebGestureEvent::Type::kGestureScrollBegin:
    case WebGestureEvent::Type::kGestureScrollUpdate:
    case WebGestureEvent::Type::kGestureScrollEnd:
    case WebGestureEvent::Type::kGesturePinchBegin:
    case WebGestureEvent::Type::kGesturePinchUpdate:
    case WebGestureEvent::Type::kGesturePinchEnd:
      return true;
    default:
      return false;
  }
}

bool ImmediatelyDispatchFirstScrollEventBeforeDeadline(
    cc::InputHandlerClient::ScrollEventDispatchMode mode) {
  return mode == cc::InputHandlerClient::ScrollEventDispatchMode::
                     kDispatchScrollEventsImmediately ||
         mode == cc::InputHandlerClient::ScrollEventDispatchMode::
                     kUseScrollPredictorForDeadline ||
         mode == cc::InputHandlerClient::ScrollEventDispatchMode::
                     kDispatchScrollEventsUntilDeadline;
}

// Determines if we have exceeded our internal deadline for dispatching input,
// when compared to `args`. Returns true when we are in the mode that supports
// this, and the deadline has been exceeded. With the exception of `args` being
// more than one VSync in the past. Otherwise returns false.
bool ShouldNotDispatchLateInputEvent(
    cc::InputHandlerClient::ScrollEventDispatchMode mode,
    double scroll_deadline_ratio,
    const viz::BeginFrameArgs& args,
    const base::TickClock* tick_clock) {
  // This will cause us to dispatch immediately. This is okay, as it is the
  // existing default behaviour. Input will still be processed and displayed.
  // There is just potentially increased latency for the remainder of the
  // scroll.
  if (mode != cc::InputHandlerClient::ScrollEventDispatchMode::
                  kDispatchScrollEventsUntilDeadline) {
    return false;
  }
  auto frame_time_delta = tick_clock->NowTicks() - args.frame_time;
  // If the `frame_time` is more than one VSync in the past, everything is
  // backed up. We should not throttle input delivery.
  if (frame_time_delta > args.interval) {
    return false;
  }
  auto deadline_delta = args.interval * scroll_deadline_ratio;
  // If `frame_time_delta` is beyond the `deadline_delta` then we should not
  // dispatch input. A late submission can lead to back pressure, causing future
  // frames to be skipped.
  //
  // This can occur when:
  //   1) Frame production was not properly stopped. Which would lead to us
  //      submitting an input that was intended for the next VSync
  //   2) We began subscribing to `OnBeginFrame`, however we receive an initial
  //      `BeginFrameArgs::MISSED` that is too far in the past.
  return frame_time_delta > deadline_delta;
}

}  // namespace

InputHandlerProxy::InputHandlerProxy(cc::InputHandler& input_handler,
                                     InputHandlerProxyClient* client)
    : client_(client),
      input_handler_(&input_handler),
      synchronous_input_handler_(nullptr),
      handling_gesture_on_impl_thread_(false),
      scroll_sequence_ignored_(false),
      current_overscroll_params_(nullptr),
      has_seen_first_gesture_scroll_update_after_begin_(false),
      last_injected_gesture_was_begin_(false),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      snap_fling_controller_(std::make_unique<cc::SnapFlingController>(this)),
      cursor_control_handler_(std::make_unique<CursorControlHandler>()) {
  DCHECK(client);
  input_handler_->BindToClient(this);

  UpdateElasticOverscroll();
  compositor_event_queue_ = std::make_unique<CompositorThreadEventQueue>();
  scroll_predictor_ =
      (base::FeatureList::IsEnabled(blink::features::kResamplingScrollEvents) &&
       client->AllowsScrollResampling())
          ? std::make_unique<ScrollPredictor>()
          : nullptr;

  if (base::FeatureList::IsEnabled(blink::features::kSkipTouchEventFilter) &&
      GetFieldTrialParamValueByFeature(
          blink::features::kSkipTouchEventFilter,
          blink::features::kSkipTouchEventFilterFilteringProcessParamName) ==
          blink::features::
              kSkipTouchEventFilterFilteringProcessParamValueBrowserAndRenderer) {
    // Skipping filtering for touch events on renderer process is enabled.
    // Always skip filtering discrete events.
    skip_touch_filter_discrete_ = true;
    if (GetFieldTrialParamValueByFeature(
            blink::features::kSkipTouchEventFilter,
            blink::features::kSkipTouchEventFilterTypeParamName) ==
        blink::features::kSkipTouchEventFilterTypeParamValueAll) {
      // The experiment config also specifies to skip touchmove events.
      skip_touch_filter_all_ = true;
    }
  }
}

InputHandlerProxy::~InputHandlerProxy() {}

void InputHandlerProxy::WillShutdown() {
  elastic_overscroll_controller_.reset();
  input_handler_ = nullptr;
  client_->WillShutdown();
}

void InputHandlerProxy::HandleInputEventWithLatencyInfo(
    std::unique_ptr<blink::WebCoalescedInputEvent> event,
    std::unique_ptr<cc::EventMetrics> metrics,
    EventDispositionCallback callback) {
  int64_t trace_id = event->latency_info().trace_id();
  TRACE_EVENT("input,benchmark,latencyInfo", "LatencyInfo.Flow",
              [&](perfetto::EventContext ctx) {
                base::TaskAnnotator::EmitTaskTimingDetails(ctx);
                ui::LatencyInfo::FillTraceEvent(
                    ctx, trace_id,
                    ChromeLatencyInfo2::Step::STEP_HANDLE_INPUT_EVENT_IMPL);
              });

  DCHECK(input_handler_);
  input_handler_->NotifyInputEvent();

  // Prevent the events to be counted into INP metrics if there is an active
  // scroll.
  if (handling_gesture_on_impl_thread_) {
    event->EventPointer()->SetPreventCountingAsInteractionTrue();
  }

  auto event_with_callback = std::make_unique<EventWithCallback>(
      std::move(event), std::move(callback), std::move(metrics));

  enum {
    NO_SCROLL_PINCH = 0,
    ONGOING_SCROLL_PINCH = 1,
    SCROLL_PINCH = 2,
  };
  // Note: Other input can race ahead of gesture input as they don't have to go
  // through the queue, but we believe it's OK to do so.
  //
  // TODO(b/329346768): this allows Fling events to be dispatched immediately
  // rather than during the start of the VSync. Confirm if this is another
  // source of input events missing submitted frames.
  if (!IsGestureScrollOrPinch(event_with_callback->event().GetType())) {
    base::ScopedSampleMetadata metadata("Input.GestureScrollOrPinch",
                                        NO_SCROLL_PINCH,
                                        base::SampleMetadataScope::kProcess);
    DispatchSingleInputEvent(std::move(event_with_callback));
    return;
  } else if (event_with_callback->event().IsGestureScroll() &&
             event_with_callback->metrics()) {
    event_with_callback->metrics()->AsScroll()->set_begin_frame_args(
        current_begin_frame_args_);
  }

  base::ScopedSampleMetadata metadata(
      "Input.GestureScrollOrPinch",
      currently_active_gesture_device_.has_value() ? ONGOING_SCROLL_PINCH
                                                   : SCROLL_PINCH,
      base::SampleMetadataScope::kProcess);
  const auto& gesture_event =
      static_cast<const WebGestureEvent&>(event_with_callback->event());
  const bool is_first_gesture_scroll_update =
      !has_seen_first_gesture_scroll_update_after_begin_ &&
      gesture_event.GetType() == WebGestureEvent::Type::kGestureScrollUpdate;

  if (gesture_event.GetType() == WebGestureEvent::Type::kGestureScrollBegin) {
    has_seen_first_gesture_scroll_update_after_begin_ = false;
  } else if (gesture_event.GetType() ==
             WebGestureEvent::Type::kGestureScrollUpdate) {
    has_seen_first_gesture_scroll_update_after_begin_ = true;
  }

  if (currently_active_gesture_device_.has_value()) {
    // While scrolling, if there were no enqueued events during
    // DeliverInputForBeginFrame we want to dispatch the first event
    // immediately. We will return to `enqueue_scroll_events_` once frame
    // production has begun.
    if (gesture_event.IsScrollEvent() &&
        ImmediatelyDispatchFirstScrollEventBeforeDeadline(
            scroll_event_dispatch_mode_) &&
        !enqueue_scroll_events_) {
      // TODO(jonross): this will update to a prediction that is -5ms before
      // `current_begin_frame_args_.frame_time`. We should consider not
      // dispatching if `event_with_callback` is too old, and if we expect a
      // newer input event to still arrive in time.
      enqueue_scroll_events_ = true;
      if (scroll_predictor_) {
        std::unique_ptr<EventWithCallback> event_to_dispatch =
            scroll_predictor_->ResampleScrollEvents(
                std::move(event_with_callback),
                current_begin_frame_args_.frame_time,
                current_begin_frame_args_.interval);
        compositor_event_queue_->Queue(std::move(event_to_dispatch));
      } else {
        compositor_event_queue_->Queue(std::move(event_with_callback));
      }
      if (ShouldNotDispatchLateInputEvent(
              scroll_event_dispatch_mode_, scroll_deadline_ratio_,
              current_begin_frame_args_, tick_clock_)) {
        input_handler_->SetNeedsAnimateInput();
        return;
      }
      // To reach here we should of had no events in the queue. We also should
      // have only enqueued one event.
      DCHECK_EQ(compositor_event_queue_->size(), 1u);
      DispatchQueuedInputEvents(false /* frame_aligned */);
      return;
    }

    // TODO(bokan): This was added in https://crrev.com/c/557463 before async
    // wheel events. It's not clear to me why flushing on a scroll end would
    // help or why this is specific to wheel events but I suspect it's no
    // longer needed now that wheel scrolling uses non-blocking events.
    bool is_scroll_end_from_wheel =
        gesture_event.SourceDevice() == WebGestureDevice::kTouchpad &&
        gesture_event.GetType() == WebGestureEvent::Type::kGestureScrollEnd;

    // Wheel events have the same issue as the blocking touch issue above.
    // However, all wheel events are initially sent blocking and become non-
    // blocking on the first unconsumed event. We can therefore simply look for
    // the first scroll update in a wheel gesture.
    bool is_first_wheel_scroll_update =
        gesture_event.SourceDevice() == WebGestureDevice::kTouchpad &&
        is_first_gesture_scroll_update;

    bool queue_was_empty = compositor_event_queue_->empty();
    compositor_event_queue_->Queue(std::move(event_with_callback));

    // |synchronous_input_handler_| is WebView only. WebView has different
    // mechanisms and we want to forward all events immediately. While we
    // normally end up here when `enqueue_scroll_events_` is true, these edge
    // cases will cause input to be forwarded immediately, rather than enqueued.
    if (is_scroll_end_from_wheel || is_first_wheel_scroll_update ||
        synchronous_input_handler_) {
      DispatchQueuedInputEvents(false /* frame_aligned */);
    }
    if (queue_was_empty && !compositor_event_queue_->empty()) {
      input_handler_->SetNeedsAnimateInput();
    }
    return;
  }

  // We have to dispatch the event to know whether the gesture sequence will be
  // handled by the compositor or not.
  DispatchSingleInputEvent(std::move(event_with_callback));
}

void InputHandlerProxy::ContinueScrollBeginAfterMainThreadHitTest(
    std::unique_ptr<blink::WebCoalescedInputEvent> event,
    std::unique_ptr<cc::EventMetrics> metrics,
    EventDispositionCallback callback,
    cc::ElementId hit_test_result) {
  DCHECK_EQ(event->Event().GetType(),
            WebGestureEvent::Type::kGestureScrollBegin);
  DCHECK(scroll_begin_main_thread_hit_test_reasons_);
  DCHECK(currently_active_gesture_device_);
  DCHECK(input_handler_);

  uint32_t main_thread_hit_test_reasons =
      scroll_begin_main_thread_hit_test_reasons_;
  scroll_begin_main_thread_hit_test_reasons_ =
      cc::MainThreadScrollingReason::kNotScrollingOnMain;

  // HandleGestureScrollBegin has logic to end an existing scroll when an
  // unexpected scroll begin arrives. We currently think we're in a scroll
  // because of the first ScrollBegin so clear this so we don't spurriously
  // call ScrollEnd. It will be set again in HandleGestureScrollBegin.
  currently_active_gesture_device_ = std::nullopt;
  current_active_gesture_scroll_modifiers_ = std::nullopt;

  auto* gesture_event =
      static_cast<blink::WebGestureEvent*>(event->EventPointer());
  if (hit_test_result) {
    gesture_event->data.scroll_begin.scrollable_area_element_id =
        hit_test_result.GetInternalValue();
    gesture_event->data.scroll_begin.main_thread_hit_tested_reasons =
        main_thread_hit_test_reasons;

    if (metrics) {
      // The event is going to be re-processed on the compositor thread; so,
      // reset timstamps of following dispatch stages.
      metrics->ResetToDispatchStage(
          cc::EventMetrics::DispatchStage::kArrivedInRendererCompositor);
    }
    auto event_with_callback = std::make_unique<EventWithCallback>(
        std::move(event), std::move(callback), std::move(metrics));

    DispatchSingleInputEvent(std::move(event_with_callback));
  } else {
    // If the main thread failed to return a scroller for whatever reason,
    // consider the ScrollBegin to be dropped.
    scroll_sequence_ignored_ = true;
    WebInputEventAttribution attribution =
        PerformEventAttribution(event->Event());
    std::move(callback).Run(DROP_EVENT, std::move(event),
                            /*overscroll_params=*/nullptr, attribution,
                            std::move(metrics));
  }

  // We do not call `SetNeedsAnimateInput` here, as it is set when this event
  // was enqueued.
  if (ShouldNotDispatchLateInputEvent(scroll_event_dispatch_mode_,
                                      scroll_deadline_ratio_,
                                      current_begin_frame_args_, tick_clock_)) {
    return;
  }

  // We blocked the compositor gesture event queue while the hit test was
  // pending so scroll updates may be waiting in the queue. Now that we've
  // finished the hit test and performed the scroll begin, flush the queue.
  DispatchQueuedInputEvents(false /* frame_aligned */);
}

void InputHandlerProxy::DispatchSingleInputEvent(
    std::unique_ptr<EventWithCallback> event_with_callback) {
  ui::LatencyInfo monitored_latency_info = event_with_callback->latency_info();
  std::unique_ptr<cc::LatencyInfoSwapPromiseMonitor>
      latency_info_swap_promise_monitor =
          input_handler_->CreateLatencyInfoSwapPromiseMonitor(
              &monitored_latency_info);

  current_overscroll_params_.reset();

  WebInputEventAttribution attribution =
      PerformEventAttribution(event_with_callback->event());
  InputHandlerProxy::EventDisposition disposition =
      RouteToTypeSpecificHandler(event_with_callback.get(), attribution);

  const WebInputEvent& event = event_with_callback->event();
  const WebGestureEvent::Type type = event.GetType();
  switch (type) {
    case WebGestureEvent::Type::kGestureScrollBegin:
    case WebGestureEvent::Type::kGesturePinchBegin:
      if (disposition == DID_HANDLE ||
          disposition == REQUIRES_MAIN_THREAD_HIT_TEST ||
          (disposition == DROP_EVENT && handling_gesture_on_impl_thread_)) {
        // REQUIRES_MAIN_THREAD_HIT_TEST means the scroll will be handled by
        // the compositor but needs to block until a hit test is performed by
        // Blink. We need to set this to indicate we're in a scroll so that
        // gestures are queued rather than dispatched immediately.
        // TODO(bokan): It's a bit of an open question if we need to also set
        // |handling_gesture_on_impl_thread_|. Ideally these two bits would be
        // merged. The queueing behavior is currently just determined by having
        // an active gesture device.
        //
        // DROP_EVENT and handling_gesture_on_impl_thread_ means that the
        // gesture was handled but the scroll was not consumed.
        currently_active_gesture_device_ =
            static_cast<const WebGestureEvent&>(event).SourceDevice();
        current_active_gesture_scroll_modifiers_ = event.GetModifiers();
      }
      break;

    case WebGestureEvent::Type::kGestureScrollEnd:
    case WebGestureEvent::Type::kGesturePinchEnd:
      if (!handling_gesture_on_impl_thread_) {
        currently_active_gesture_device_ = std::nullopt;
        current_active_gesture_scroll_modifiers_ = std::nullopt;
      }
      break;
    case WebInputEvent::Type::kTouchStart:
      if (static_cast<const WebTouchEvent&>(event).IsTouchSequenceStart()) {
        input_handler_->SetIsHandlingTouchSequence(true);
      }
      break;
    case WebInputEvent::Type::kTouchCancel:
    case WebInputEvent::Type::kTouchEnd:
      if (static_cast<const WebTouchEvent&>(event).IsTouchSequenceEnd()) {
        input_handler_->SetIsHandlingTouchSequence(false);
      }
      break;
    default:
      break;
  }

  // Will run callback for every original events.
  event_with_callback->RunCallbacks(disposition, monitored_latency_info,
                                    std::move(current_overscroll_params_),
                                    attribution);
}

bool InputHandlerProxy::HasQueuedEventsReadyForDispatch(
    bool frame_aligned) const {
  // Block flushing the compositor gesture event queue while there's an async
  // scroll begin hit test outstanding. We'll flush the queue when the hit test
  // responds.
  if (scroll_begin_main_thread_hit_test_reasons_) {
    return false;
  }

  if (compositor_event_queue_->empty()) {
    return false;
  }

  // Defer scroll updates if they need to be frame-aligned.
  if (compositor_event_queue_->PeekType() ==
          WebGestureEvent::Type::kGestureScrollUpdate &&
      input_handler_->CurrentScrollNeedsFrameAlignment() && !frame_aligned) {
    return false;
  }
  return true;
}

void InputHandlerProxy::DispatchQueuedInputEvents(bool frame_aligned) {
  while (HasQueuedEventsReadyForDispatch(frame_aligned)) {
    DispatchSingleInputEvent(compositor_event_queue_->Pop());
  }
}

void InputHandlerProxy::GenerateAndDispatchSytheticScrollPrediction(
    const viz::BeginFrameArgs& args) {
  // It is possible that a user can move their finger very slowly, or hold it in
  // place. When this occurs we can stop receiving input events, or they can be
  // so far apart that we cannot reliably create predictions. When that occurs
  // we do not create any synthetic events.
  if (!currently_active_gesture_device_.has_value() || !scroll_predictor_ ||
      !scroll_predictor_->HasPrediction() ||
      scroll_begin_main_thread_hit_test_reasons_) {
    return;
  }
  std::unique_ptr<EventWithCallback> event_with_callback =
      scroll_predictor_->GenerateSyntheticScrollUpdate(
          args.frame_time, args.interval,
          currently_active_gesture_device_.value(),
          current_active_gesture_scroll_modifiers_.value_or(0));

  int64_t trace_id = event_with_callback->latency_info().trace_id();
  TRACE_EVENT("input,benchmark,latencyInfo", "LatencyInfo.Flow",
              [&](perfetto::EventContext ctx) {
                base::TaskAnnotator::EmitTaskTimingDetails(ctx);
                ui::LatencyInfo::FillTraceEvent(
                    ctx, trace_id,
                    ChromeLatencyInfo2::Step::STEP_HANDLE_INPUT_EVENT_IMPL);
              });

  DispatchSingleInputEvent(std::move(event_with_callback));
}

void InputHandlerProxy::UpdateElasticOverscroll() {
  bool can_use_elastic_overscroll = true;
#if BUILDFLAG(IS_ANDROID)
  // On android, elastic overscroll introduces quite a bit of motion which can
  // effect those sensitive to it. Disable when prefers_reduced_motion_ is
  // disabled.
  can_use_elastic_overscroll = !prefers_reduced_motion_;
#endif
  if (!can_use_elastic_overscroll && elastic_overscroll_controller_) {
    elastic_overscroll_controller_.reset();
    input_handler_->DestroyScrollElasticityHelper();
  } else if (can_use_elastic_overscroll && !elastic_overscroll_controller_) {
    cc::ScrollElasticityHelper* scroll_elasticity_helper =
        input_handler_->CreateScrollElasticityHelper();
    if (scroll_elasticity_helper) {
      elastic_overscroll_controller_ =
          ElasticOverscrollController::Create(scroll_elasticity_helper);
    }
  }
}

void InputHandlerProxy::InjectScrollbarGestureScroll(
    const WebInputEvent::Type type,
    const gfx::PointF& position_in_widget,
    const cc::InputHandlerPointerResult& pointer_result,
    const ui::LatencyInfo& latency_info,
    const base::TimeTicks original_timestamp,
    const cc::EventMetrics* original_metrics) {
  gfx::Vector2dF scroll_delta = pointer_result.scroll_delta;

  std::unique_ptr<WebGestureEvent> synthetic_gesture_event =
      WebGestureEvent::GenerateInjectedScrollbarGestureScroll(
          type, original_timestamp, position_in_widget, scroll_delta,
          pointer_result.scroll_units);

  if (type == WebInputEvent::Type::kGestureScrollBegin) {
    // Gesture events for scrollbars are considered synthetic because they're
    // created in response to mouse events. Additionally, synthetic GSB(s) are
    // ignored by the blink::ElasticOverscrollController.
    synthetic_gesture_event->data.scroll_begin.synthetic = true;

    // This will avoid hit testing and directly scroll the scroller with the
    // provided element_id.
    synthetic_gesture_event->data.scroll_begin.scrollable_area_element_id =
        pointer_result.target_scroller.GetInternalValue();
  }

  // Send in a LatencyInfo with SCROLLBAR type so that the end to end latency
  // is calculated specifically for scrollbars.
  ui::LatencyInfo scrollbar_latency_info(latency_info);

  // This latency_info should not have already been scheduled for rendering -
  // i.e. it should be the original latency_info that was associated with the
  // input event that caused this scroll injection. If it has already been
  // scheduled it won't get queued to be shipped off with the CompositorFrame
  // when the gesture is handled.
  DCHECK(!scrollbar_latency_info.FindLatency(
      ui::INPUT_EVENT_LATENCY_RENDERING_SCHEDULED_IMPL_COMPONENT, nullptr));

  std::unique_ptr<cc::EventMetrics> metrics;
  if (type == WebInputEvent::Type::kGestureScrollUpdate) {
    // For injected GSUs, add a scroll update component to the latency info
    // so that it is properly classified as a scroll. If the last injected
    // gesture was a GSB, then this GSU is the first scroll update - mark
    // the LatencyInfo as such.
    scrollbar_latency_info.AddLatencyNumberWithTimestamp(
        last_injected_gesture_was_begin_
            ? ui::INPUT_EVENT_LATENCY_FIRST_SCROLL_UPDATE_ORIGINAL_COMPONENT
            : ui::INPUT_EVENT_LATENCY_SCROLL_UPDATE_ORIGINAL_COMPONENT,
        original_timestamp);
    metrics = cc::ScrollUpdateEventMetrics::CreateFromExisting(
        synthetic_gesture_event->GetTypeAsUiEventType(),
        synthetic_gesture_event->GetScrollInputType(),
        /*is_inertial=*/false,
        last_injected_gesture_was_begin_
            ? cc::ScrollUpdateEventMetrics::ScrollUpdateType::kStarted
            : cc::ScrollUpdateEventMetrics::ScrollUpdateType::kContinued,
        synthetic_gesture_event->data.scroll_update.delta_y,
        cc::EventMetrics::DispatchStage::kArrivedInRendererCompositor,
        original_metrics);
  } else {
    metrics = cc::ScrollEventMetrics::CreateFromExisting(
        synthetic_gesture_event->GetTypeAsUiEventType(),
        synthetic_gesture_event->GetScrollInputType(),
        /*is_inertial=*/false,
        cc::EventMetrics::DispatchStage::kArrivedInRendererCompositor,
        original_metrics);
  }

  last_injected_gesture_was_begin_ =
      type == WebInputEvent::Type::kGestureScrollBegin;

  auto gesture_event_with_callback_update = std::make_unique<EventWithCallback>(
      std::make_unique<WebCoalescedInputEvent>(
          std::move(synthetic_gesture_event), scrollbar_latency_info),
      base::DoNothing(), std::move(metrics));

  bool needs_animate_input = compositor_event_queue_->empty();
  compositor_event_queue_->Queue(std::move(gesture_event_with_callback_update));

  if (needs_animate_input)
    input_handler_->SetNeedsAnimateInput();
}

bool HasScrollbarJumpKeyModifier(const WebInputEvent& event) {
#if BUILDFLAG(IS_MAC)
  // Mac uses the "Option" key (which is mapped to the enum "kAltKey").
  return event.GetModifiers() & WebInputEvent::kAltKey;
#else
  return event.GetModifiers() & WebInputEvent::kShiftKey;
#endif
}

InputHandlerProxy::EventDisposition
InputHandlerProxy::RouteToTypeSpecificHandler(
    EventWithCallback* event_with_callback,
    const WebInputEventAttribution& original_attribution) {
  DCHECK(input_handler_);

  cc::EventsMetricsManager::ScopedMonitor::DoneCallback done_callback;
  if (event_with_callback->metrics()) {
    event_with_callback->WillStartProcessingForMetrics();
    done_callback = base::BindOnce(
        [](EventWithCallback* event, bool handled) {
          event->DidCompleteProcessingForMetrics();
          std::unique_ptr<cc::EventMetrics> result =
              handled ? event->TakeMetrics() : nullptr;
          return result;
        },
        event_with_callback);
  }
  auto scoped_event_monitor =
      input_handler_->GetScopedEventMetricsMonitor(std::move(done_callback));

  const WebInputEvent& event = event_with_callback->event();
  if (event.IsGestureScroll() &&
      (snap_fling_controller_->FilterEventForSnap(
          GestureScrollEventType(event.GetType())))) {
    return DROP_EVENT;
  }

  if (std::optional<InputHandlerProxy::EventDisposition> handled =
          cursor_control_handler_->ObserveInputEvent(event)) {
    return *handled;
  }

  switch (event.GetType()) {
    case WebInputEvent::Type::kMouseWheel:
      return HandleMouseWheel(static_cast<const WebMouseWheelEvent&>(event));

    case WebInputEvent::Type::kGestureScrollBegin:
      return HandleGestureScrollBegin(
          static_cast<const WebGestureEvent&>(event));

    case WebInputEvent::Type::kGestureScrollUpdate:
      return HandleGestureScrollUpdate(
          static_cast<const WebGestureEvent&>(event), original_attribution,
          event_with_callback->metrics(),
          event_with_callback->latency_info().trace_id());

    case WebInputEvent::Type::kGestureScrollEnd:
      return HandleGestureScrollEnd(static_cast<const WebGestureEvent&>(event));

    case WebInputEvent::Type::kGesturePinchBegin: {
      DCHECK(!gesture_pinch_in_progress_);
      const WebGestureEvent& gesture_event =
          static_cast<const WebGestureEvent&>(event);
      input_handler_->PinchGestureBegin(
          gfx::ToFlooredPoint(gesture_event.PositionInWidget()),
          GestureScrollInputType(gesture_event.SourceDevice()));
      gesture_pinch_in_progress_ = true;
      return DID_HANDLE;
    }

    case WebInputEvent::Type::kGesturePinchEnd: {
      DCHECK(gesture_pinch_in_progress_);
      gesture_pinch_in_progress_ = false;
      const WebGestureEvent& gesture_event =
          static_cast<const WebGestureEvent&>(event);
      input_handler_->PinchGestureEnd(
          gfx::ToFlooredPoint(gesture_event.PositionInWidget()));
      return DID_HANDLE;
    }

    case WebInputEvent::Type::kGesturePinchUpdate: {
      DCHECK(gesture_pinch_in_progress_);
      const WebGestureEvent& gesture_event =
          static_cast<const WebGestureEvent&>(event);
      input_handler_->PinchGestureUpdate(
          gesture_event.data.pinch_update.scale,
          gfx::ToFlooredPoint(gesture_event.PositionInWidget()));
      return DID_HANDLE;
    }

    case WebInputEvent::Type::kTouchStart:
      return HandleTouchStart(event_with_callback);

    case WebInputEvent::Type::kTouchMove:
      return HandleTouchMove(event_with_callback);

    case WebInputEvent::Type::kTouchEnd:
      return HandleTouchEnd(event_with_callback);

    case WebInputEvent::Type::kMouseDown: {
      // Only for check scrollbar captured
      const WebMouseEvent& mouse_event =
          static_cast<const WebMouseEvent&>(event);

      if (mouse_event.button == WebMouseEvent::Button::kLeft) {
        CHECK(input_handler_);
        // TODO(arakeri): Pass in the modifier instead of a bool once the
        // refactor (crbug.com/1022097) is done. For details, see
        // crbug.com/1016955.
        HandlePointerDown(event_with_callback, mouse_event.PositionInWidget());
      }

      return DID_NOT_HANDLE;
    }
    case WebInputEvent::Type::kMouseUp: {
      // Only for release scrollbar captured
      const WebMouseEvent& mouse_event =
          static_cast<const WebMouseEvent&>(event);
      CHECK(input_handler_);
      if (mouse_event.button == WebMouseEvent::Button::kLeft)
        HandlePointerUp(event_with_callback, mouse_event.PositionInWidget());
      return DID_NOT_HANDLE;
    }
    case WebInputEvent::Type::kMouseMove: {
      const WebMouseEvent& mouse_event =
          static_cast<const WebMouseEvent&>(event);
      // TODO(davemoore): This should never happen, but bug #326635 showed some
      // surprising crashes.
      CHECK(input_handler_);
      // This should stay in sync with EventHandler::HandleMouseMoveOrLeaveEvent
      // for main-thread scrollbar interactions.
      bool should_cancel_scrollbar_drag =
          (mouse_event.button == WebPointerProperties::Button::kNoButton &&
           !(mouse_event.GetModifiers() &
             WebInputEvent::Modifiers::kRelativeMotionEvent));
      HandlePointerMove(event_with_callback, mouse_event.PositionInWidget(),
                        should_cancel_scrollbar_drag);
      return DID_NOT_HANDLE;
    }
    case WebInputEvent::Type::kMouseLeave: {
      CHECK(input_handler_);
      input_handler_->MouseLeave();
      return DID_NOT_HANDLE;
    }
    // Fling gestures are handled only in the browser process and not sent to
    // the renderer.
    case WebInputEvent::Type::kGestureFlingStart:
    case WebInputEvent::Type::kGestureFlingCancel:
      NOTREACHED();

    default:
      break;
  }

  return DID_NOT_HANDLE;
}

WebInputEventAttribution InputHandlerProxy::PerformEventAttribution(
    const WebInputEvent& event) {
  if (!event_attribution_enabled_) {
    return WebInputEventAttribution(WebInputEventAttribution::kUnknown);
  }

  if (WebInputEvent::IsKeyboardEventType(event.GetType())) {
    // Keyboard events should be dispatched to the focused frame.
    return WebInputEventAttribution(WebInputEventAttribution::kFocusedFrame);
  } else if (WebInputEvent::IsMouseEventType(event.GetType()) ||
             event.GetType() == WebInputEvent::Type::kMouseWheel) {
    // Mouse events are dispatched based on their location in the DOM tree.
    // Perform frame attribution via cc.
    // TODO(acomminos): handle pointer locks, or provide a hint to the renderer
    //                  to check pointer lock state
    gfx::PointF point =
        static_cast<const WebMouseEvent&>(event).PositionInWidget();
    return WebInputEventAttribution(
        WebInputEventAttribution::kTargetedFrame,
        input_handler_->FindFrameElementIdAtPoint(point));
  } else if (WebInputEvent::IsGestureEventType(event.GetType())) {
    gfx::PointF point =
        static_cast<const WebGestureEvent&>(event).PositionInWidget();
    return WebInputEventAttribution(
        WebInputEventAttribution::kTargetedFrame,
        input_handler_->FindFrameElementIdAtPoint(point));
  } else if (WebInputEvent::IsTouchEventType(event.GetType())) {
    const auto& touch_event = static_cast<const WebTouchEvent&>(event);
    if (touch_event.touches_length == 0) {
      return WebInputEventAttribution(WebInputEventAttribution::kTargetedFrame,
                                      cc::ElementId());
    }

    // Use the first touch location to perform frame attribution, similar to
    // how the renderer host performs touch event dispatch.
    // https://cs.chromium.org/chromium/src/content/browser/renderer_host/render_widget_host_input_event_router.cc?l=808&rcl=10fe9d0a725d4ed7b69266a5936c525f0a5b26d3
    gfx::PointF point = touch_event.touches[0].PositionInWidget();
    const cc::ElementId targeted_element =
        input_handler_->FindFrameElementIdAtPoint(point);

    return WebInputEventAttribution(WebInputEventAttribution::kTargetedFrame,
                                    targeted_element);
  } else {
    return WebInputEventAttribution(WebInputEventAttribution::kUnknown);
  }
}

void InputHandlerProxy::RecordScrollBegin(
    WebGestureDevice device,
    uint32_t main_thread_hit_tested_reasons,
    uint32_t main_thread_repaint_reasons) {
  DCHECK(cc::MainThreadScrollingReason::AreHitTestReasons(
      main_thread_hit_tested_reasons));
  DCHECK(cc::MainThreadScrollingReason::AreRepaintReasons(
      main_thread_repaint_reasons));
  if (device != WebGestureDevice::kTouchpad &&
      device != WebGestureDevice::kScrollbar &&
      device != WebGestureDevice::kTouchscreen) {
    return;
  }

  // This records whether a scroll is handled on the main or compositor
  // threads. Note: scrolls handled on the compositor but blocked on main due
  // to event handlers are still considered compositor scrolls.
  const bool is_compositor_scroll =
      main_thread_repaint_reasons ==
          cc::MainThreadScrollingReason::kNotScrollingOnMain;

  std::optional<EventDisposition> disposition =
      (device == WebGestureDevice::kTouchpad ? mouse_wheel_result_
                                             : touch_result_);

  // Scrolling can be handled on the compositor thread but it might be blocked
  // on the main thread waiting for non-passive event handlers to process the
  // wheel/touch events (i.e. were they preventDefaulted?).
  bool blocked_on_main_thread_handler =
      disposition.has_value() && disposition == DID_NOT_HANDLE;

  bool blocked_on_main_at_begin =
      blocked_on_main_thread_handler || main_thread_hit_tested_reasons;

  auto scroll_start_state = RecordScrollingThread(
      is_compositor_scroll, blocked_on_main_at_begin, device);
  input_handler_->RecordScrollBegin(GestureScrollInputType(device),
                                    scroll_start_state);

  // We never scroll "on main" from the perspective of cc::InputHandler, but we
  // still want to log reasons if the user will not see new pixels until the
  // next BeginMainFrame. These reasons are passed as
  // main_thread_repaint_reasons.
  uint32_t reportable_reasons =
      main_thread_hit_tested_reasons | main_thread_repaint_reasons;
  if (blocked_on_main_thread_handler) {
    // We should also collect main thread scrolling reasons if a scroll event
    // scrolls on impl thread but is blocked by main thread event handlers.
    reportable_reasons |=
        (device == WebGestureDevice::kTouchpad
             ? cc::MainThreadScrollingReason::kWheelEventHandlerRegion
             : cc::MainThreadScrollingReason::kTouchEventHandlerRegion);
  }

  RecordScrollReasonsMetric(device, reportable_reasons);
}

InputHandlerProxy::EventDisposition InputHandlerProxy::HandleMouseWheel(
    const WebMouseWheelEvent& wheel_event) {
  InputHandlerProxy::EventDisposition result = DROP_EVENT;

  if (wheel_event.dispatch_type ==
      WebInputEvent::DispatchType::kEventNonBlocking) {
    // The first wheel event in the sequence should be cancellable.
    DCHECK(wheel_event.phase != WebMouseWheelEvent::kPhaseBegan);
    // Noncancellable wheel events should have phase info.
    DCHECK(wheel_event.phase != WebMouseWheelEvent::kPhaseNone ||
           wheel_event.momentum_phase != WebMouseWheelEvent::kPhaseNone);

    // TODO(bokan): This should never happen but after changing
    // mouse_event_result_ to a std::optional, crashes indicate that it does
    // so |if| maintains prior behavior. https://crbug.com/1069760.
    if (mouse_wheel_result_.has_value()) {
      result = mouse_wheel_result_.value();
      if (wheel_event.phase == WebMouseWheelEvent::kPhaseEnded ||
          wheel_event.phase == WebMouseWheelEvent::kPhaseCancelled ||
          wheel_event.momentum_phase == WebMouseWheelEvent::kPhaseEnded ||
          wheel_event.momentum_phase == WebMouseWheelEvent::kPhaseCancelled) {
        mouse_wheel_result_.reset();
      } else {
        return result;
      }
    }
  }

  gfx::PointF position_in_widget = wheel_event.PositionInWidget();
  if (input_handler_->HasBlockingWheelEventHandlerAt(
          gfx::Point(position_in_widget.x(), position_in_widget.y()))) {
    result = DID_NOT_HANDLE;
  } else {
    cc::EventListenerProperties properties =
        input_handler_->GetEventListenerProperties(
            cc::EventListenerClass::kMouseWheel);
    switch (properties) {
      case cc::EventListenerProperties::kBlockingAndPassive:
      case cc::EventListenerProperties::kPassive:
        result = DID_NOT_HANDLE_NON_BLOCKING;
        break;
      case cc::EventListenerProperties::kNone:
        result = DROP_EVENT;
        break;
      default:
        // If properties is kBlocking, and the event falls outside wheel event
        // handler region, we should handle it the same as kNone.
        result = DROP_EVENT;
    }
  }

  mouse_wheel_result_ = result;
  return result;
}

InputHandlerProxy::EventDisposition InputHandlerProxy::HandleGestureScrollBegin(
    const WebGestureEvent& gesture_event) {
  TRACE_EVENT0("input", "InputHandlerProxy::HandleGestureScrollBegin");

  if (scroll_predictor_)
    scroll_predictor_->ResetOnGestureScrollBegin(gesture_event);

  // When a GSB is being handled, end any pre-existing gesture scrolls that are
  // in progress.
  if (currently_active_gesture_device_.has_value() &&
      handling_gesture_on_impl_thread_) {
    // TODO(arakeri): Once crbug.com/1074209 is fixed, delete calls to
    // RecordScrollEnd.
    input_handler_->RecordScrollEnd(
        GestureScrollInputType(*currently_active_gesture_device_));
    InputHandlerScrollEnd();
  }

  cc::ScrollState scroll_state(CreateScrollStateDataForGesture(gesture_event));
  cc::InputHandler::ScrollStatus scroll_status;
  if (gesture_event.data.scroll_begin.target_viewport) {
    scroll_status = input_handler_->RootScrollBegin(
        &scroll_state, GestureScrollInputType(gesture_event.SourceDevice()));
  } else {
    scroll_status = input_handler_->ScrollBegin(
        &scroll_state, GestureScrollInputType(gesture_event.SourceDevice()));
  }
  DCHECK(cc::MainThreadScrollingReason::AreHitTestReasons(
      scroll_status.main_thread_hit_test_reasons));
  DCHECK(cc::MainThreadScrollingReason::AreRepaintReasons(
      scroll_status.main_thread_repaint_reasons));

  // If we need a hit test from the main thread, we'll reinject this scroll
  // begin event once the hit test is complete so avoid everything below for
  // now, it'll be run on the second iteration.
  if (scroll_status.main_thread_hit_test_reasons) {
    scroll_begin_main_thread_hit_test_reasons_ =
        scroll_status.main_thread_hit_test_reasons;
    return REQUIRES_MAIN_THREAD_HIT_TEST;
  }

  if (scroll_status.thread != ScrollThread::kScrollIgnored) {
    RecordScrollBegin(gesture_event.SourceDevice(),
                      scroll_state.main_thread_hit_tested_reasons(),
                      scroll_status.main_thread_repaint_reasons);
  }

  InputHandlerProxy::EventDisposition result = DID_NOT_HANDLE;
  scroll_sequence_ignored_ = false;
  in_inertial_scrolling_ = false;
  switch (scroll_status.thread) {
    case ScrollThread::kScrollOnImplThread:
      TRACE_EVENT_INSTANT0("input", "Handle On Impl", TRACE_EVENT_SCOPE_THREAD);
      handling_gesture_on_impl_thread_ = true;
      if (input_handler_->IsCurrentlyScrollingViewport())
        client_->DidStartScrollingViewport();
      // if the viewport cannot scroll, the scroll cannot be consumed so we
      // drop the event
      if (scroll_status.viewport_cannot_scroll)
        result = DROP_EVENT;
      else
        result = DID_HANDLE;
      break;
    case ScrollThread::kScrollIgnored:
      TRACE_EVENT_INSTANT0("input", "Ignore Scroll", TRACE_EVENT_SCOPE_THREAD);
      scroll_sequence_ignored_ = true;
      result = DROP_EVENT;
      break;
    default:
      NOTREACHED();
  }

  // TODO(bokan): Should we really be calling this in cases like DROP_EVENT and
  // DID_NOT_HANDLE_NON_BLOCKING_DUE_TO_FLING? I think probably not.
  if (elastic_overscroll_controller_ && result != DID_NOT_HANDLE) {
    HandleScrollElasticityOverscroll(gesture_event,
                                     cc::InputHandlerScrollResult());
  }

  return result;
}

InputHandlerProxy::EventDisposition
InputHandlerProxy::HandleGestureScrollUpdate(
    const WebGestureEvent& gesture_event,
    const WebInputEventAttribution& original_attribution,
    cc::EventMetrics* metrics,
    int64_t trace_id) {
  TRACE_EVENT("input", "InputHandlerProxy::HandleGestureScrollUpdate",
              "trace_id", trace_id, "dx",
              -gesture_event.data.scroll_update.delta_x, "dy",
              -gesture_event.data.scroll_update.delta_y);
  const float provided_delta_x = gesture_event.data.scroll_update.delta_x;
  const float provided_delta_y = gesture_event.data.scroll_update.delta_y;

  if (scroll_sequence_ignored_) {
    TRACE_EVENT_INSTANT0("input", "Scroll Sequence Ignored",
                         TRACE_EVENT_SCOPE_THREAD);
    return DROP_EVENT;
  }

  if (!handling_gesture_on_impl_thread_ && !gesture_pinch_in_progress_) {
    return DROP_EVENT;
  }

  const auto scroll_state_data = CreateScrollStateDataForGesture(gesture_event);
  in_inertial_scrolling_ = scroll_state_data.is_in_inertial_phase;

  TRACE_EVENT_INSTANT1(
      "input", "DeltaUnits", TRACE_EVENT_SCOPE_THREAD, "unit",
      static_cast<int>(gesture_event.data.scroll_update.delta_units));

  if (snap_fling_controller_->HandleGestureScrollUpdate(
          GetGestureScrollUpdateInfo(gesture_event))) {
    handling_gesture_on_impl_thread_ = false;
    return DROP_EVENT;
  }

  base::TimeTicks event_time = gesture_event.TimeStamp();
  base::TimeDelta delay = base::TimeTicks::Now() - event_time;

  cc::InputHandlerScrollResult scroll_result =
      input_handler_->ScrollUpdate(cc::ScrollState(scroll_state_data), delay);

  TRACE_EVENT(
      "input,input.scrolling",
      "InputHandlerProxy::HandleGestureScrollUpdate_Result",
      [trace_id, provided_delta_x, provided_delta_y,
       visual_offset_x = scroll_result.current_visual_offset.x(),
       visual_offset_y = scroll_result.current_visual_offset.y()](
          perfetto::EventContext& ctx) {
        auto* event = ctx.event<perfetto::protos::pbzero::ChromeTrackEvent>();
        auto* scroll_data = event->set_scroll_deltas();
        scroll_data->set_trace_id(trace_id);
        scroll_data->set_provided_to_compositor_delta_x(provided_delta_x);
        scroll_data->set_provided_to_compositor_delta_y(provided_delta_y);
        scroll_data->set_visual_offset_x(visual_offset_x);
        scroll_data->set_visual_offset_y(visual_offset_y);
      });

  HandleOverscroll(gesture_event.PositionInWidget(), scroll_result);

  if (elastic_overscroll_controller_)
    HandleScrollElasticityOverscroll(gesture_event, scroll_result);

  if (metrics && scroll_result.needs_main_thread_repaint)
    metrics->set_requires_main_thread_update();

  return scroll_result.did_scroll ? DID_HANDLE : DROP_EVENT;
}

// TODO(arakeri): Ensure that redudant GSE(s) in the CompositorThreadEventQueue
// are handled gracefully. (i.e currently, when an ongoing scroll needs to end,
// we call RecordScrollEnd and InputHandlerScrollEnd synchronously. Ideally, we
// should end the scroll when the GSB is being handled).
InputHandlerProxy::EventDisposition InputHandlerProxy::HandleGestureScrollEnd(
    const WebGestureEvent& gesture_event) {
  TRACE_EVENT0("input", "InputHandlerProxy::HandleGestureScrollEnd");

  if (scroll_sequence_ignored_) {
    DCHECK(!currently_active_gesture_device_.has_value());
    return DROP_EVENT;
  }

  input_handler_->RecordScrollEnd(
      GestureScrollInputType(gesture_event.SourceDevice()));

  if (!handling_gesture_on_impl_thread_) {
    DCHECK(!currently_active_gesture_device_.has_value());
    return DROP_EVENT;
  }

  if (!currently_active_gesture_device_.has_value() ||
      (currently_active_gesture_device_.value() !=
       gesture_event.SourceDevice()))
    return DROP_EVENT;

  InputHandlerScrollEnd();
  if (elastic_overscroll_controller_) {
    HandleScrollElasticityOverscroll(gesture_event,
                                     cc::InputHandlerScrollResult());
  }

  return DID_HANDLE;
}

void InputHandlerProxy::InputHandlerScrollEnd() {
  input_handler_->ScrollEnd(/*should_snap=*/true);
  handling_gesture_on_impl_thread_ = false;

  DCHECK(!gesture_pinch_in_progress_);
  currently_active_gesture_device_ = std::nullopt;
  current_active_gesture_scroll_modifiers_ = std::nullopt;
}

InputHandlerProxy::EventDisposition InputHandlerProxy::HitTestTouchEvent(
    const WebTouchEvent& touch_event,
    bool* is_touching_scrolling_layer,
    cc::TouchAction* allowed_touch_action) {
  TRACE_EVENT1("input", "InputHandlerProxy::HitTestTouchEvent",
               "Needs allowed TouchAction",
               static_cast<bool>(allowed_touch_action));
  *is_touching_scrolling_layer = false;
  EventDisposition result = DROP_EVENT;
  for (size_t i = 0; i < touch_event.touches_length; ++i) {
    if (touch_event.touch_start_or_first_touch_move)
      DCHECK(allowed_touch_action);
    else
      DCHECK(!allowed_touch_action);

    if (touch_event.GetType() == WebInputEvent::Type::kTouchStart &&
        touch_event.touches[i].state != WebTouchPoint::State::kStatePressed) {
      continue;
    }

    cc::TouchAction touch_action = cc::TouchAction::kAuto;
    cc::InputHandler::TouchStartOrMoveEventListenerType event_listener_type =
        input_handler_->EventListenerTypeForTouchStartOrMoveAt(
            gfx::Point(touch_event.touches[i].PositionInWidget().x(),
                       touch_event.touches[i].PositionInWidget().y()),
            &touch_action);
    if (allowed_touch_action && touch_action != cc::TouchAction::kAuto) {
      TRACE_EVENT_INSTANT1("input", "Adding TouchAction",
                           TRACE_EVENT_SCOPE_THREAD, "TouchAction",
                           cc::TouchActionToString(touch_action));
      *allowed_touch_action &= touch_action;
    }

    if (event_listener_type !=
        cc::InputHandler::TouchStartOrMoveEventListenerType::kNoHandler) {
      TRACE_EVENT_INSTANT1("input", "HaveHandler", TRACE_EVENT_SCOPE_THREAD,
                           "Type", event_listener_type);

      *is_touching_scrolling_layer =
          event_listener_type ==
          cc::InputHandler::TouchStartOrMoveEventListenerType::
              kHandlerOnScrollingLayer;

      // A non-passive touch start / move will always set the allowed touch
      // action to TouchAction::kNone, and in that case we do not ack the event
      // from the compositor.
      if (allowed_touch_action &&
          *allowed_touch_action != cc::TouchAction::kNone) {
        TRACE_EVENT_INSTANT0("input", "NonBlocking due to allowed touchaction",
                             TRACE_EVENT_SCOPE_THREAD);
        result = DID_NOT_HANDLE_NON_BLOCKING;
      } else {
        TRACE_EVENT_INSTANT0("input", "DidNotHandle due to no touchaction",
                             TRACE_EVENT_SCOPE_THREAD);
        result = DID_NOT_HANDLE;
      }
      break;
    }
  }

  // If |result| is DROP_EVENT it wasn't processed above.
  if (result == DROP_EVENT) {
    auto event_listener_class = input_handler_->GetEventListenerProperties(
        cc::EventListenerClass::kTouchStartOrMove);
    TRACE_EVENT_INSTANT1("input", "DropEvent", TRACE_EVENT_SCOPE_THREAD,
                         "listener", event_listener_class);
    switch (event_listener_class) {
      case cc::EventListenerProperties::kPassive:
        result = DID_NOT_HANDLE_NON_BLOCKING;
        break;
      case cc::EventListenerProperties::kBlocking:
        // The touch area rects above already have checked whether it hits
        // a blocking region. Since it does not the event can be dropped.
        result = DROP_EVENT;
        break;
      case cc::EventListenerProperties::kBlockingAndPassive:
        // There is at least one passive listener that needs to possibly
        // be notified so it can't be dropped.
        result = DID_NOT_HANDLE_NON_BLOCKING;
        break;
      case cc::EventListenerProperties::kNone:
        result = DROP_EVENT;
        break;
      default:
        NOTREACHED();
    }
  }

  // Depending on which arm of the SkipTouchEventFilter experiment we're on, we
  // may need to simulate a passive listener instead of dropping touch events.
  if (result == DROP_EVENT &&
      (skip_touch_filter_all_ ||
       (skip_touch_filter_discrete_ &&
        touch_event.GetType() == WebInputEvent::Type::kTouchStart))) {
    TRACE_EVENT_INSTANT0("input", "Non blocking due to skip filter",
                         TRACE_EVENT_SCOPE_THREAD);
    result = DID_NOT_HANDLE_NON_BLOCKING;
  }

  // Merge |touch_result_| and |result| so the result has the highest
  // priority value according to the sequence; (DROP_EVENT,
  // DID_NOT_HANDLE_NON_BLOCKING, DID_NOT_HANDLE).
  if (!touch_result_.has_value() || touch_result_ == DROP_EVENT ||
      result == DID_NOT_HANDLE) {
    TRACE_EVENT_INSTANT2(
        "input", "Update touch_result_", TRACE_EVENT_SCOPE_THREAD, "old",
        (touch_result_ ? touch_result_.value() : -1), "new", result);
    touch_result_ = result;
  }

  return result;
}

InputHandlerProxy::EventDisposition InputHandlerProxy::HandleTouchStart(
    EventWithCallback* event_with_callback) {
  TRACE_EVENT0("input", "InputHandlerProxy::HandleTouchStart");
  const auto& touch_event =
      static_cast<const WebTouchEvent&>(event_with_callback->event());

  bool is_touching_scrolling_layer;
  cc::TouchAction allowed_touch_action = cc::TouchAction::kAuto;
  EventDisposition result = HitTestTouchEvent(
      touch_event, &is_touching_scrolling_layer, &allowed_touch_action);
  TRACE_EVENT_INSTANT1("input", "HitTest", TRACE_EVENT_SCOPE_THREAD,
                       "disposition", result);

  if (allowed_touch_action != cc::TouchAction::kNone &&
      touch_event.touches_length == 1) {
    DCHECK(touch_event.touches[0].state == WebTouchPoint::State::kStatePressed);
    cc::InputHandlerPointerResult pointer_result = HandlePointerDown(
        event_with_callback, touch_event.touches[0].PositionInWidget());
    if (pointer_result.type == cc::PointerResultType::kScrollbarScroll) {
      client_->SetAllowedTouchAction(allowed_touch_action);
      return DID_HANDLE;
    }
  }

  // main_thread_touch_sequence_start_disposition_ will indicate that touchmoves
  // in the sequence should be sent to the main thread if the touchstart event
  // was blocking. We may change |result| from DROP_EVENT if there is a touchend
  // listener so we need to update main_thread_touch_sequence_start_disposition_
  // here (before the check for a touchend listener) so that we send touchmoves
  // only IF we send the (blocking) touchstart.
  if (!(result == DID_HANDLE || result == DROP_EVENT))
    main_thread_touch_sequence_start_disposition_ = result;

  // If |result| is still DROP_EVENT look at the touch end handler as we may
  // not want to discard the entire touch sequence. Note this code is
  // explicitly after the assignment of the |touch_result_| in
  // HitTestTouchEvent so the touch moves are not sent to the main thread
  // un-necessarily.
  if (result == DROP_EVENT && input_handler_->GetEventListenerProperties(
                                  cc::EventListenerClass::kTouchEndOrCancel) !=
                                  cc::EventListenerProperties::kNone) {
    TRACE_EVENT_INSTANT0("input", "NonBlocking due to TouchEnd handler",
                         TRACE_EVENT_SCOPE_THREAD);
    result = DID_NOT_HANDLE_NON_BLOCKING;
  }

  bool is_in_inertial_scrolling_on_impl =
      in_inertial_scrolling_ && handling_gesture_on_impl_thread_;
  if (is_in_inertial_scrolling_on_impl && is_touching_scrolling_layer) {
    // If the touchstart occurs during a fling, it will be ACK'd immediately
    // and it and its following touch moves will be dispatched as non-blocking.
    // Due to tap suppression on the browser side, this will reset the
    // browser-side touch action (see comment in
    // TouchActionFilter::FilterGestureEvent for GestureScrollBegin). Ensure we
    // send back an allowed_touch_action that matches this non-blocking behavior
    // rather than treating it as if it'll block.
    TRACE_EVENT_INSTANT0("input", "NonBlocking due to fling",
                         TRACE_EVENT_SCOPE_THREAD);
    allowed_touch_action = cc::TouchAction::kAuto;
    result = DID_NOT_HANDLE_NON_BLOCKING_DUE_TO_FLING;
  }

  TRACE_EVENT_INSTANT2(
      "input", "Allowed TouchAction", TRACE_EVENT_SCOPE_THREAD, "TouchAction",
      cc::TouchActionToString(allowed_touch_action), "disposition", result);
  client_->SetAllowedTouchAction(allowed_touch_action);

  return result;
}

InputHandlerProxy::EventDisposition InputHandlerProxy::HandleTouchMove(
    EventWithCallback* event_with_callback) {
  const auto& touch_event =
      static_cast<const WebTouchEvent&>(event_with_callback->event());
  TRACE_EVENT2("input", "InputHandlerProxy::HandleTouchMove", "touch_result",
               touch_result_.has_value() ? touch_result_.value() : -1,
               "is_start_or_first",
               touch_event.touch_start_or_first_touch_move);
  if (touch_event.touches_length == 1) {
    cc::InputHandlerPointerResult pointer_result = HandlePointerMove(
        event_with_callback, touch_event.touches[0].PositionInWidget(),
        false /* should_cancel_scrollbar_drag */);
    if (pointer_result.type == cc::PointerResultType::kScrollbarScroll) {
      return DID_HANDLE;
    }
  }
  // Hit test if this is the first touch move or we don't have any results
  // from a previous hit test.
  if (!touch_result_.has_value() ||
      touch_event.touch_start_or_first_touch_move) {
    bool is_touching_scrolling_layer;
    cc::TouchAction allowed_touch_action = cc::TouchAction::kAuto;
    EventDisposition result;
    bool is_main_thread_touch_sequence_with_blocking_start =
        main_thread_touch_sequence_start_disposition_.has_value() &&
        main_thread_touch_sequence_start_disposition_.value() == DID_NOT_HANDLE;
    // If the touchmove occurs in a touch sequence that's being forwarded to
    // the main thread, we can avoid the hit test since we want to also forward
    // touchmoves in the sequence to the main thread.
    if (is_main_thread_touch_sequence_with_blocking_start) {
      touch_result_ = main_thread_touch_sequence_start_disposition_.value();
      result = touch_result_.value();
    } else {
      result = HitTestTouchEvent(touch_event, &is_touching_scrolling_layer,
                                 &allowed_touch_action);
    }
    TRACE_EVENT_INSTANT2(
        "input", "Allowed TouchAction", TRACE_EVENT_SCOPE_THREAD, "TouchAction",
        cc::TouchActionToString(allowed_touch_action), "disposition", result);
    client_->SetAllowedTouchAction(allowed_touch_action);
    return result;
  }
  return touch_result_.value();
}

InputHandlerProxy::EventDisposition InputHandlerProxy::HandleTouchEnd(
    EventWithCallback* event_with_callback) {
  const auto& touch_event =
      static_cast<const WebTouchEvent&>(event_with_callback->event());
  TRACE_EVENT1("input", "InputHandlerProxy::HandleTouchEnd", "num_touches",
               touch_event.touches_length);
  if (touch_event.touches_length == 1) {
    cc::InputHandlerPointerResult pointer_result = HandlePointerUp(
        event_with_callback, touch_event.touches[0].PositionInWidget());
    if (pointer_result.type == cc::PointerResultType::kScrollbarScroll) {
      return DID_HANDLE;
    }
  }

  if (touch_event.touches_length == 1)
    touch_result_.reset();

  if (main_thread_touch_sequence_start_disposition_.has_value())
    main_thread_touch_sequence_start_disposition_.reset();

  return DID_NOT_HANDLE;
}

void InputHandlerProxy::Animate(base::TimeTicks time) {
  if (elastic_overscroll_controller_)
    elastic_overscroll_controller_->Animate(time);

  snap_fling_controller_->Animate(time);

  // These animations can change the root scroll offset, so inform the
  // synchronous input handler.
  if (synchronous_input_handler_)
    input_handler_->RequestUpdateForSynchronousInputHandler();
}

void InputHandlerProxy::ReconcileElasticOverscrollAndRootScroll() {
  if (elastic_overscroll_controller_)
    elastic_overscroll_controller_->ReconcileStretchAndScroll();
  // This is called as a result of the starting of draw. We should return to
  // queueing events.
  enqueue_scroll_events_ = true;
}

void InputHandlerProxy::SetPrefersReducedMotion(bool prefers_reduced_motion) {
  if (prefers_reduced_motion_ == prefers_reduced_motion)
    return;
  prefers_reduced_motion_ = prefers_reduced_motion;

  UpdateElasticOverscroll();
}

void InputHandlerProxy::UpdateRootLayerStateForSynchronousInputHandler(
    const gfx::PointF& total_scroll_offset,
    const gfx::PointF& max_scroll_offset,
    const gfx::SizeF& scrollable_size,
    float page_scale_factor,
    float min_page_scale_factor,
    float max_page_scale_factor) {
  if (synchronous_input_handler_) {
    synchronous_input_handler_->UpdateRootLayerState(
        total_scroll_offset, max_scroll_offset, scrollable_size,
        page_scale_factor, min_page_scale_factor, max_page_scale_factor);
  }
}

void InputHandlerProxy::DeliverInputForBeginFrame(
    const viz::BeginFrameArgs& args) {
  current_begin_frame_args_ = args;
  enqueue_scroll_e
```