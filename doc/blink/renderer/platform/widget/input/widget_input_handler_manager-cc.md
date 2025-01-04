Response:
Let's break down the thought process for analyzing this C++ source code and generating the detailed explanation.

**1. Initial Understanding & High-Level Goal:**

The primary goal is to understand the purpose of `widget_input_handler_manager.cc` in the Chromium Blink rendering engine and explain its functionality, relationships with web technologies (JavaScript, HTML, CSS), logic, and potential usage errors.

**2. Core Functionality Identification (Keyword Scan & Initial Interpretation):**

The filename itself, "widget_input_handler_manager," suggests this component manages input handling for widgets. Scanning the `#include` directives reveals key related concepts:

*   Input events (`WebCoalescedInputEvent`, `WebKeyboardEvent`, `WebGestureEvent`)
*   Widget interaction (`WidgetBase`, `FrameWidget`)
*   Compositor integration (`cc::LayerTreeHost`, `cc::InputHandler`)
*   Threading and scheduling (`CompositorThreadScheduler`, `WidgetScheduler`, `MainThreadEventQueue`)
*   Mojo communication (`mojom::blink::WidgetInputHandler`, `mojom::blink::FrameWidgetInputHandler`)
*   Performance metrics and tracing (`base::metrics::histogram_macros`, `TRACE_EVENT`)

From this initial scan, it's clear the class is central to how input events are received, processed, and dispatched within the rendering pipeline, involving both the main thread and the compositor thread.

**3. Deeper Dive into Key Methods and Members:**

Now, a more systematic examination of the class's members and methods is needed. I'll focus on the public interface and important private methods:

*   **Constructor/`Create()`:** How is the object instantiated? What dependencies are involved (widget, input handler, schedulers)?
*   **`HandleInputEvent()` and related dispatch methods:** This is crucial for understanding the core input processing logic. How are events routed? Are they sent to the compositor or handled directly? What role does the `InputHandlerProxy` play?
*   **`DidHandleInputEventSentToCompositor()` and `DidHandleInputEventSentToMain()`:** These are callbacks indicating the result of input processing on different threads. They are important for understanding the multi-threaded flow.
*   **`DispatchEvent()`:**  This method appears to be the entry point for receiving input events.
*   **`WaitForInputProcessed()`:** This suggests a mechanism for synchronizing input processing, likely for JavaScript interactions.
*   **Methods related to paint timing (`DidFirstVisuallyNonEmptyPaint`, `RecordEventMetricsForPaintTiming`)**:  This points to performance tracking related to input responsiveness during page load.
*   **Methods for handling scrolling (`FindScrollTargetOnMainThread`, `DidStartScrollingViewport`)**:  This indicates specific handling for scroll-related input.
*   **Methods for managing input suppression (`InitializeInputEventSuppressionStates`, `OnDeferMainFrameUpdatesChanged`, `OnDeferCommitsChanged`)**:  This highlights mechanisms to control input processing based on the rendering state.
*   **Threading-related members (`main_thread_task_runner_`, `compositor_thread_default_task_runner_`, `InputThreadTaskRunner()`)**:  Essential for understanding the threading model.

**4. Relationship to JavaScript, HTML, and CSS:**

At this stage, I start connecting the observed functionality to web technologies:

*   **JavaScript:**  Input events are ultimately what trigger JavaScript event handlers (e.g., `onclick`, `onmousemove`). The `WaitForInputProcessed()` method strongly suggests a mechanism for ensuring JavaScript observes the effects of input. The concept of "blocking" vs. "non-blocking" input relates to whether the browser waits for JavaScript to respond.
*   **HTML:** The structure of the HTML document and the positioning of elements are crucial for hit-testing (determining which element received the input). The `FindScrollTargetOnMainThread()` method is directly related to this.
*   **CSS:** CSS properties, especially those related to scrolling (`overflow`, `scroll-behavior`) and touch interaction (`touch-action`), influence how input events are handled. The `SetAllowedTouchAction()` and `ProcessTouchAction()` methods are relevant here.

**5. Logical Reasoning and Hypothetical Input/Output:**

Now, I consider specific scenarios:

*   **Click on a button with a JavaScript handler:**
    *   **Input:** Mouse click event.
    *   **Processing:** Event is dispatched, potentially sent to the compositor first, then to the main thread. `WaitForInputProcessed()` might be called to ensure the JavaScript handler runs and the visual changes are reflected.
    *   **Output:** JavaScript handler executes, potentially modifying the DOM and triggering a repaint.
*   **Scrolling a div with `overflow: auto`:**
    *   **Input:** Mouse wheel or touch scroll gesture.
    *   **Processing:**  `FindScrollTargetOnMainThread()` might be used to determine the scrollable element. The event is dispatched, potentially handled by the compositor for smooth scrolling.
    *   **Output:** The content of the div scrolls.
*   **Touch event on an element with `touch-action: none`:**
    *   **Input:** Touch event.
    *   **Processing:** `SetAllowedTouchAction()` and `ProcessTouchAction()` might be involved to prevent default touch behavior (like scrolling).
    *   **Output:** No scrolling occurs due to the `touch-action` CSS property.

**6. Identifying Common Usage Errors:**

Thinking about the interactions between different parts of the system leads to potential error scenarios:

*   **Incorrect threading assumptions:**  Accessing members that should only be accessed on a specific thread. The code uses `DCHECK` to catch some of these.
*   **Missing initialization:**  Not properly initializing the `WidgetInputHandlerManager`, leading to null pointers or unexpected behavior.
*   **Deadlocks:** Although not immediately apparent in this code, incorrect synchronization between the main and compositor threads *could* lead to deadlocks in more complex scenarios involving input handling.
*   **Forgetting to handle asynchronous operations:** Input processing often involves asynchronous communication between threads. Failing to handle callbacks correctly can lead to lost events or incorrect state updates.

**7. Structuring the Explanation:**

Finally, I organize the gathered information into a clear and comprehensive explanation, covering the requested aspects: functionality, relationships with web technologies, logical reasoning (input/output), and common errors. Using headings, bullet points, and code snippets makes the explanation easier to understand. I also prioritize the most important aspects of the class's functionality.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:** Maybe this class *only* deals with compositor thread input.
*   **Correction:**  The code clearly shows interaction with the main thread (`main_thread_task_runner_`, `DispatchDirectlyToWidget`). It manages input for widgets regardless of whether they are composited.
*   **Initial thought:**  The input suppression is only about performance.
*   **Correction:** While performance is a factor, input suppression is also about preventing interaction with elements that haven't been painted or committed, ensuring a better user experience.

By following this structured approach of scanning, analyzing, connecting, reasoning, and organizing, I can generate a thorough and accurate explanation of the given source code.
这个文件是 Chromium Blink 引擎中 `WidgetInputHandlerManager` 类的实现，其核心功能是**管理和协调 widget 的输入事件处理流程**。它充当了连接渲染进程主线程和合成器线程的桥梁，确保输入事件能够被正确地路由和处理。

以下是 `WidgetInputHandlerManager` 的主要功能分解：

**1. 输入事件接收与分发：**

*   **接收浏览器进程发送来的输入事件:**  它接收来自浏览器进程的各种输入事件，例如鼠标事件、键盘事件、触摸事件和手势事件。
*   **决定事件的处理线程:** 根据 widget 的合成状态（是否使用合成器）和事件类型，决定事件应该先在合成器线程处理还是直接在主线程处理。
*   **将事件分发到相应的处理程序:**
    *   **合成器线程 (Compositor Thread):** 如果 widget 使用合成器，并且事件适合在合成器线程处理（例如，滚动、惯性滑动），则将事件发送到 `InputHandlerProxy`，后者与合成器线程上的 `cc::InputHandler` 通信。
    *   **主线程 (Main Thread):** 如果 widget 没有使用合成器，或者事件需要主线程参与处理（例如，点击事件、文本输入），则将事件发送到主线程上的 `WidgetBaseInputHandler`。
*   **处理事件的 ack (acknowledgement):** 接收来自合成器线程或主线程的事件处理结果，并将 ack 返回给浏览器进程。

**2. 合成器线程集成：**

*   **创建和管理 `InputHandlerProxy`:**  如果 widget 使用合成器，则创建并管理一个 `InputHandlerProxy` 对象，作为与合成器线程上的 `cc::InputHandler` 通信的代理。
*   **处理合成器线程的事件处理结果:**  接收 `InputHandlerProxy` 返回的事件处理结果（例如，事件被消费、未被消费、需要主线程 hit-test 等），并采取相应的行动。
*   **管理触摸动作 (Touch Action):**  处理和设置允许的触摸动作（例如，`pan-x`, `pan-y`, `none`），这影响了浏览器如何处理触摸滚动和缩放手势。
*   **处理弹性过度滚动 (Elastic Overscroll):**  如果启用了弹性过度滚动，则会观察手势事件并将其传递给 `ElasticOverscrollController`。

**3. 主线程集成：**

*   **管理主线程事件队列 (`MainThreadEventQueue`):**  对于需要在主线程处理的事件，将其放入主线程事件队列中，确保事件按照正确的顺序处理。
*   **处理主线程的事件处理结果:**  接收主线程 `WidgetBaseInputHandler` 的事件处理结果。
*   **处理需要主线程 hit-test 的滚动事件:**  对于合成器线程无法直接确定滚动目标的滚动开始事件，会将其发送到主线程进行 hit-test，找到可滚动的元素。
*   **管理输入处理完成回调 (`WaitForInputProcessed`):**  提供机制等待输入事件的完整处理流程完成，这通常用于确保 JavaScript 能够观察到输入事件带来的影响。

**4. 性能优化和指标收集：**

*   **抑制早期输入事件:**  在页面首次绘制完成前，可以抑制某些输入事件，避免用户与不可见的元素交互。
*   **记录输入事件处理延迟和指标:**  使用 UMA (User Metrics Analysis) 记录各种输入事件处理相关的指标，例如事件处理延迟、被抑制的事件数量等，用于性能分析和优化。
*   **延迟首帧绘制的输入事件处理:**  在某些情况下，会延迟处理输入事件直到首帧绘制完成，以避免不必要的渲染。

**5. 其他功能：**

*   **处理同步合成器 (Synchronous Compositor) (Android WebView):**  在 Android WebView 中，支持同步合成模式，该类负责与同步合成器进行交互。
*   **处理浏览器控件状态更新:**  接收并传递浏览器控件（例如，地址栏）的状态更新，以便合成器线程能够进行相应的调整。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`WidgetInputHandlerManager` 扮演着连接用户输入与网页内容的关键角色，它处理的输入事件最终会影响 JavaScript 的执行、HTML 元素的交互以及 CSS 样式的呈现。

*   **JavaScript:**
    *   **功能关系:** 当用户点击一个按钮时，`WidgetInputHandlerManager` 接收到鼠标点击事件，最终该事件会被传递给 JavaScript 事件监听器 (例如 `onclick`)。
    *   **举例说明:**
        ```javascript
        // HTML
        <button id="myButton">Click Me</button>

        // JavaScript
        document.getElementById('myButton').onclick = function() {
          console.log('Button clicked!');
          // 修改 DOM 或执行其他操作
          document.getElementById('myButton').textContent = 'Clicked!';
        };
        ```
        当用户点击按钮时，`WidgetInputHandlerManager` 负责将点击事件传递给 JavaScript 的 `onclick` 处理函数，从而执行 `console.log` 和修改按钮文本的操作。`WaitForInputProcessed` 方法可以确保在 JavaScript 执行完成后，浏览器才会继续渲染，避免用户看到不一致的状态。
    *   **假设输入与输出:**
        *   **假设输入:** 用户点击了 ID 为 "myButton" 的按钮。
        *   **输出:** JavaScript 的 `onclick` 函数被调用，控制台输出 "Button clicked!"，按钮的文本变为 "Clicked!"。

*   **HTML:**
    *   **功能关系:**  `WidgetInputHandlerManager` 在处理滚动事件时，可能需要进行 hit-test 来确定哪个 HTML 元素是滚动目标。`GetScrollableContainerIdAt` 方法用于获取指定坐标下的可滚动容器 ID。
    *   **举例说明:**
        ```html
        <div style="overflow: auto; height: 100px;">
          <p>This is some scrollable content.</p>
          <p>More content...</p>
        </div>
        ```
        当用户尝试滚动这个 div 时，`WidgetInputHandlerManager` 需要确定这个 div 是滚动目标，才能正确处理滚动事件。
    *   **假设输入与输出:**
        *   **假设输入:** 用户使用鼠标滚轮在上述 div 上滚动。
        *   **输出:**  div 内的内容向上或向下滚动。

*   **CSS:**
    *   **功能关系:** CSS 的 `touch-action` 属性会影响 `WidgetInputHandlerManager` 如何处理触摸事件。例如，`touch-action: none` 会阻止元素的默认触摸滚动和缩放行为。
    *   **举例说明:**
        ```css
        #noScroll {
          touch-action: none;
        }
        ```
        ```html
        <div id="noScroll">
          Try to scroll or zoom here.
        </div>
        ```
        当用户尝试在 ID 为 "noScroll" 的 div 上进行触摸滚动或缩放时，由于 `touch-action: none` 的设置，`WidgetInputHandlerManager` 会阻止这些默认行为。
    *   **假设输入与输出:**
        *   **假设输入:** 用户尝试在 ID 为 "noScroll" 的 div 上进行捏合缩放。
        *   **输出:**  div 不会发生缩放。

**逻辑推理的假设输入与输出:**

*   **场景：** 页面正在加载，尚未完成首次绘制，用户快速移动鼠标。
    *   **假设输入:**  多个 `WebMouseEvent::Type::kMouseMove` 事件连续到达。
    *   **逻辑推理:** 由于 `suppressing_input_events_state_` 包含 `SuppressingInputEventsBits::kHasNotPainted`，这些鼠标移动事件（除了可能是保持指针位置更新的少量事件外）可能会被抑制，不会立即传递给渲染管线。`StartFirstPaintMaxDelayTimer` 可能会被启动，用于监控首帧绘制的延迟。
    *   **输出:** 大部分鼠标移动事件被丢弃或延迟处理，直到页面完成首次绘制。性能指标可能会记录被抑制的事件数量。

*   **场景：** 用户在可滚动的 div 上开始触摸滑动。
    *   **假设输入:**  一个 `WebGestureEvent::Type::kGestureScrollBegin` 事件。
    *   **逻辑推理:**  如果合成器线程无法直接确定滚动目标（例如，存在 iframe 或复杂的布局），`WidgetInputHandlerManager` 会发送请求到主线程进行 hit-test (`FindScrollTargetOnMainThread`)。合成器线程会等待主线程返回 hit-test 结果后，再继续处理后续的滚动事件。
    *   **输出:** 主线程执行 hit-test，找到可滚动的元素 ID，并将结果返回给合成器线程。合成器线程基于此信息开始处理后续的 `kGestureScrollUpdate` 和 `kGestureScrollEnd` 事件，实现平滑滚动。

**用户或编程常见的使用错误举例说明:**

*   **错误地在非主线程访问 `WidgetBase` 或其客户端：** `WidgetBase` 及其客户端对象通常只能在主线程安全访问。如果在合成器线程或其他线程中直接访问这些对象，可能导致数据竞争和崩溃。
    *   **举例:** 在 `DidHandleInputEventSentToCompositor` 中，直接调用 `widget_->client()->FrameWidget()` 而不进行线程检查或跨线程通信。

*   **忘记处理异步回调：**  输入事件的处理流程可能涉及跨线程通信，需要正确处理来自不同线程的回调。如果忘记处理回调，可能导致事件处理流程中断或资源泄漏。
    *   **举例:** 在 `FindScrollTargetOnMainThread` 中发送 hit-test 请求后，没有正确实现 `FindScrollTargetReply` 来处理主线程返回的结果。

*   **不正确的线程模型理解：** 对 Blink 的多线程模型理解不足，可能导致在错误的线程执行某些操作，例如在合成器线程中尝试修改 DOM (DOM 修改必须在主线程进行)。
    *   **举例:**  尝试在 `InputHandlerProxy` 的方法中直接调用修改 DOM 的 Blink API。

*   **过度依赖同步操作：**  在输入事件处理流程中过度使用同步操作可能会阻塞线程，导致性能问题或 UI 卡顿。应该尽可能使用异步操作和回调。
    *   **举例:**  在处理触摸事件时，同步等待 JavaScript 执行完成再返回 ack。

*   **不正确的事件处理顺序假设：**  假设事件总是按照特定的顺序到达和处理，而忽略了可能存在的并发和延迟。
    *   **举例:**  在处理手势事件时，假设 `kGestureScrollUpdate` 事件一定会在 `kGestureScrollBegin` 之后立即到达，而没有处理事件丢失或延迟的情况。

总而言之，`WidgetInputHandlerManager` 是 Blink 引擎中一个复杂而关键的组件，它协调了输入事件在不同线程之间的流动和处理，确保用户与网页的交互能够被正确地响应和反馈。理解其功能和与 web 技术的关系对于深入了解 Chromium 的渲染机制至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/widget_input_handler_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_manager.h"

#include <utility>

#include "base/check_op.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/tracing/protos/chrome_track_event.pbzero.h"
#include "base/types/optional_ref.h"
#include "base/types/pass_key.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/input/browser_controls_offset_tags_info.h"
#include "cc/metrics/event_metrics.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/paint_holding_reason.h"
#include "components/viz/common/features.h"
#include "services/tracing/public/cpp/perfetto/flow_event_utils.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/scheduler/public/agent_group_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/compositor_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/widget_scheduler.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller.h"
#include "third_party/blink/renderer/platform/widget/input/main_thread_event_queue.h"
#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_impl.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/widget/widget_base_client.h"
#include "ui/latency/latency_info.h"

#if BUILDFLAG(IS_ANDROID)
#include "third_party/blink/renderer/platform/widget/compositing/android_webview/synchronous_compositor_registry.h"
#include "third_party/blink/renderer/platform/widget/input/synchronous_compositor_proxy.h"
#endif

namespace blink {

using ::perfetto::protos::pbzero::ChromeLatencyInfo2;
using ::perfetto::protos::pbzero::TrackEvent;

namespace {
// We will count dropped pointerdown by posting a task in the main thread.
// To avoid blocking the main thread, we need a timer to send the data
// intermittently. The time delay of the timer is 10X of the threshold of
// long tasks which block the main thread 50 ms or longer.
const base::TimeDelta kEventCountsTimerDelay = base::Milliseconds(500);

// The 99th percentile of the delay between navigation start and first paint is
// around 10sec on most platforms.  We are setting the max acceptable limit to
// 1.5x to avoid false positives on slow devices.
const base::TimeDelta kFirstPaintMaxAcceptableDelay = base::Seconds(15);

mojom::blink::DidOverscrollParamsPtr ToDidOverscrollParams(
    const InputHandlerProxy::DidOverscrollParams* overscroll_params) {
  if (!overscroll_params)
    return nullptr;
  return mojom::blink::DidOverscrollParams::New(
      overscroll_params->accumulated_overscroll,
      overscroll_params->latest_overscroll_delta,
      overscroll_params->current_fling_velocity,
      overscroll_params->causal_event_viewport_point,
      overscroll_params->overscroll_behavior);
}

void CallCallback(
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback,
    mojom::blink::InputEventResultState result_state,
    const ui::LatencyInfo& latency_info,
    mojom::blink::DidOverscrollParamsPtr overscroll_params,
    std::optional<cc::TouchAction> touch_action) {
  int64_t trace_id = latency_info.trace_id();
  TRACE_EVENT("input,benchmark,latencyInfo", "LatencyInfo.Flow",
              [&](perfetto::EventContext ctx) {
                base::TaskAnnotator::EmitTaskTimingDetails(ctx);
                ui::LatencyInfo::FillTraceEvent(
                    ctx, trace_id,
                    ChromeLatencyInfo2::Step::STEP_HANDLED_INPUT_EVENT_IMPL);
              });

  std::move(callback).Run(
      mojom::blink::InputEventResultSource::kMainThread, latency_info,
      result_state, std::move(overscroll_params),
      touch_action
          ? mojom::blink::TouchActionOptional::New(touch_action.value())
          : nullptr);
}

mojom::blink::InputEventResultState InputEventDispositionToAck(
    InputHandlerProxy::EventDisposition disposition) {
  switch (disposition) {
    case InputHandlerProxy::DID_HANDLE:
      return mojom::blink::InputEventResultState::kConsumed;
    case InputHandlerProxy::DID_NOT_HANDLE:
      return mojom::blink::InputEventResultState::kNotConsumed;
    case InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING_DUE_TO_FLING:
      return mojom::blink::InputEventResultState::kSetNonBlockingDueToFling;
    case InputHandlerProxy::DROP_EVENT:
      return mojom::blink::InputEventResultState::kNoConsumerExists;
    case InputHandlerProxy::DID_NOT_HANDLE_NON_BLOCKING:
      return mojom::blink::InputEventResultState::kSetNonBlocking;
    case InputHandlerProxy::REQUIRES_MAIN_THREAD_HIT_TEST:
    default:
      NOTREACHED();
  }
}

}  // namespace

#if BUILDFLAG(IS_ANDROID)
class SynchronousCompositorProxyRegistry
    : public SynchronousCompositorRegistry {
 public:
  explicit SynchronousCompositorProxyRegistry(
      scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
      base::PlatformThreadId io_thread_id,
      base::PlatformThreadId main_thread_id)
      : compositor_thread_default_task_runner_(
            std::move(compositor_task_runner)),
        io_thread_id_(io_thread_id),
        main_thread_id_(main_thread_id) {}

  ~SynchronousCompositorProxyRegistry() override {
    // Ensure the proxy has already been release on the compositor thread
    // before destroying this object.
    DCHECK(!proxy_);
  }

  void CreateProxy(InputHandlerProxy* handler) {
    DCHECK(compositor_thread_default_task_runner_->BelongsToCurrentThread());
    proxy_ = std::make_unique<SynchronousCompositorProxy>(handler);

    proxy_->Init();

    if (base::FeatureList::IsEnabled(::features::kWebViewEnableADPF)) {
      Vector<viz::Thread> renderer_threads;
      renderer_threads.push_back(viz::Thread{base::PlatformThread::CurrentId(),
                                             viz::Thread::Type::kCompositor});
      if (io_thread_id_ != base::kInvalidThreadId) {
        renderer_threads.push_back(
            viz::Thread{io_thread_id_, viz::Thread::Type::kIO});
      }
      if (main_thread_id_ != base::kInvalidThreadId &&
          base::FeatureList::IsEnabled(
              ::features::kWebViewEnableADPFRendererMain)) {
        renderer_threads.push_back(
            viz::Thread{main_thread_id_, viz::Thread::Type::kMain});
      }
      proxy_->SetThreads(renderer_threads);
    }

    if (sink_)
      proxy_->SetLayerTreeFrameSink(sink_);
  }

  SynchronousCompositorProxy* proxy() { return proxy_.get(); }

  void RegisterLayerTreeFrameSink(
      SynchronousLayerTreeFrameSink* layer_tree_frame_sink) override {
    DCHECK(compositor_thread_default_task_runner_->BelongsToCurrentThread());
    DCHECK_EQ(nullptr, sink_);
    sink_ = layer_tree_frame_sink;
    if (proxy_)
      proxy_->SetLayerTreeFrameSink(layer_tree_frame_sink);
  }

  void UnregisterLayerTreeFrameSink(
      SynchronousLayerTreeFrameSink* layer_tree_frame_sink) override {
    DCHECK(compositor_thread_default_task_runner_->BelongsToCurrentThread());
    DCHECK_EQ(layer_tree_frame_sink, sink_);
    sink_ = nullptr;
  }

  void DestroyProxy() {
    DCHECK(compositor_thread_default_task_runner_->BelongsToCurrentThread());
    proxy_.reset();
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner>
      compositor_thread_default_task_runner_;
  std::unique_ptr<SynchronousCompositorProxy> proxy_;
  raw_ptr<SynchronousLayerTreeFrameSink> sink_ = nullptr;
  base::PlatformThreadId io_thread_id_;
  base::PlatformThreadId main_thread_id_;
};

#endif

scoped_refptr<WidgetInputHandlerManager> WidgetInputHandlerManager::Create(
    base::WeakPtr<WidgetBase> widget,
    base::WeakPtr<mojom::blink::FrameWidgetInputHandler>
        frame_widget_input_handler,
    bool never_composited,
    CompositorThreadScheduler* compositor_thread_scheduler,
    scoped_refptr<scheduler::WidgetScheduler> widget_scheduler,
    bool uses_input_handler,
    bool allow_scroll_resampling,
    base::PlatformThreadId io_thread_id,
    base::PlatformThreadId main_thread_id) {
  DCHECK(widget_scheduler);
  auto manager = base::MakeRefCounted<WidgetInputHandlerManager>(
      base::PassKey<WidgetInputHandlerManager>(), std::move(widget),
      std::move(frame_widget_input_handler), never_composited,
      compositor_thread_scheduler, std::move(widget_scheduler),
      allow_scroll_resampling, io_thread_id, main_thread_id);

  manager->InitializeInputEventSuppressionStates();
  if (uses_input_handler)
    manager->InitInputHandler();

  // A compositor thread implies we're using an input handler.
  DCHECK(!manager->compositor_thread_default_task_runner_ ||
         uses_input_handler);
  // Conversely, if we don't use an input handler we must not have a compositor
  // thread.
  DCHECK(uses_input_handler ||
         !manager->compositor_thread_default_task_runner_);

  return manager;
}

WidgetInputHandlerManager::WidgetInputHandlerManager(
    base::PassKey<WidgetInputHandlerManager>,
    base::WeakPtr<WidgetBase> widget,
    base::WeakPtr<mojom::blink::FrameWidgetInputHandler>
        frame_widget_input_handler,
    bool never_composited,
    CompositorThreadScheduler* compositor_thread_scheduler,
    scoped_refptr<scheduler::WidgetScheduler> widget_scheduler,
    bool allow_scroll_resampling,
    base::PlatformThreadId io_thread_id,
    base::PlatformThreadId main_thread_id)
    : widget_(std::move(widget)),
      frame_widget_input_handler_(std::move(frame_widget_input_handler)),
      widget_scheduler_(std::move(widget_scheduler)),
      widget_is_embedded_(widget_ && widget_->is_embedded()),
      main_thread_task_runner_(widget_scheduler_->InputTaskRunner()),
      compositor_thread_default_task_runner_(
          compositor_thread_scheduler
              ? compositor_thread_scheduler->DefaultTaskRunner()
              : nullptr),
      compositor_thread_input_blocking_task_runner_(
          compositor_thread_scheduler
              ? compositor_thread_scheduler->InputTaskRunner()
              : nullptr),
      input_event_queue_(base::MakeRefCounted<MainThreadEventQueue>(
          this,
          InputThreadTaskRunner(),
          widget_scheduler_->InputTaskRunner(),
          widget_scheduler_,
          /*allow_raf_aligned_input=*/!never_composited)),
      allow_scroll_resampling_(allow_scroll_resampling) {
#if BUILDFLAG(IS_ANDROID)
  if (compositor_thread_default_task_runner_) {
    synchronous_compositor_registry_ =
        std::make_unique<SynchronousCompositorProxyRegistry>(
            compositor_thread_default_task_runner_, io_thread_id,
            main_thread_id);
  }
#endif
}

void WidgetInputHandlerManager::DidFirstVisuallyNonEmptyPaint(
    const base::TimeTicks& first_paint_time) {
  suppressing_input_events_state_ &=
      ~static_cast<uint16_t>(SuppressingInputEventsBits::kHasNotPainted);

  RecordEventMetricsForPaintTiming(first_paint_time);
}

void WidgetInputHandlerManager::InitInputHandler() {
  bool sync_compositing = false;
#if BUILDFLAG(IS_ANDROID)
  sync_compositing =
      Platform::Current()->IsSynchronousCompositingEnabledForAndroidWebView();
#endif
  uses_input_handler_ = true;
  base::OnceClosure init_closure = base::BindOnce(
      &WidgetInputHandlerManager::InitOnInputHandlingThread,
      weak_ptr_factory_.GetWeakPtr(),
      widget_->LayerTreeHost()->GetDelegateForInput(), sync_compositing);
  InputThreadTaskRunner()->PostTask(FROM_HERE, std::move(init_closure));
}

WidgetInputHandlerManager::~WidgetInputHandlerManager() = default;

void WidgetInputHandlerManager::AddInterface(
    mojo::PendingReceiver<mojom::blink::WidgetInputHandler> receiver,
    mojo::PendingRemote<mojom::blink::WidgetInputHandlerHost> host) {
  if (compositor_thread_default_task_runner_) {
    host_ = mojo::SharedRemote<mojom::blink::WidgetInputHandlerHost>(
        std::move(host), compositor_thread_default_task_runner_);
    // Mojo channel bound on compositor thread.
    compositor_thread_default_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&WidgetInputHandlerManager::BindChannel, this,
                                  std::move(receiver)));
  } else {
    host_ = mojo::SharedRemote<mojom::blink::WidgetInputHandlerHost>(
        std::move(host));
    // Mojo channel bound on main thread.
    BindChannel(std::move(receiver));
  }
}

bool WidgetInputHandlerManager::HandleInputEvent(
    const WebCoalescedInputEvent& event,
    std::unique_ptr<cc::EventMetrics> metrics,
    HandledEventCallback handled_callback) {
  WidgetBaseInputHandler::HandledEventCallback blink_callback = base::BindOnce(
      [](HandledEventCallback callback,
         blink::mojom::InputEventResultState ack_state,
         const ui::LatencyInfo& latency_info,
         std::unique_ptr<InputHandlerProxy::DidOverscrollParams>
             overscroll_params,
         std::optional<cc::TouchAction> touch_action) {
        if (!callback)
          return;
        std::move(callback).Run(ack_state, latency_info,
                                ToDidOverscrollParams(overscroll_params.get()),
                                touch_action);
      },
      std::move(handled_callback));
  widget_->input_handler().HandleInputEvent(event, std::move(metrics),
                                            std::move(blink_callback));

  if (!widget_) {
    // The `HandleInputEvent()` call above might result in deletion of
    // `widget_`.
    return true;
  }
  // TODO(szager): Should this be limited to discrete input events by
  // conditioning on (!scheduler::PendingUserInput::IsContinuousEventType())?
  widget_->LayerTreeHost()->proxy()->SetInputResponsePending();

  return true;
}

void WidgetInputHandlerManager::InputEventsDispatched(bool raf_aligned) {
  DCHECK(main_thread_task_runner_->BelongsToCurrentThread());

  // Immediately after dispatching rAF-aligned events, a frame is still in
  // progress. There is no need to check and break swap promises here, because
  // when the frame is finished, they will be broken if there is no update (see
  // `LayerTreeHostImpl::BeginMainFrameAborted`). Also, unlike non-rAF-aligned
  // events, checking `RequestedMainFramePending()` would not work here, because
  // it is reset before dispatching rAF-aligned events.
  if (raf_aligned)
    return;

  // If no main frame request is pending after dispatching non-rAF-aligned
  // events, there will be no updated frame to submit to Viz; so, break
  // outstanding swap promises here due to no update.
  if (widget_ && !widget_->LayerTreeHost()->RequestedMainFramePending()) {
    widget_->LayerTreeHost()->GetSwapPromiseManager()->BreakSwapPromises(
        cc::SwapPromise::DidNotSwapReason::COMMIT_NO_UPDATE);
  }
}

void WidgetInputHandlerManager::SetNeedsMainFrame() {
  widget_->RequestAnimationAfterDelay(base::TimeDelta());
}

bool WidgetInputHandlerManager::RequestedMainFramePending() {
  return widget_->LayerTreeHost()->RequestedMainFramePending();
}

void WidgetInputHandlerManager::WillShutdown() {
#if BUILDFLAG(IS_ANDROID)
  if (synchronous_compositor_registry_)
    synchronous_compositor_registry_->DestroyProxy();
#endif
  input_handler_proxy_.reset();
  dropped_event_counts_timer_.reset();
}

void WidgetInputHandlerManager::FindScrollTargetOnMainThread(
    const gfx::PointF& point,
    ElementAtPointCallback callback) {
  TRACE_EVENT2("input",
               "WidgetInputHandlerManager::FindScrollTargetOnMainThread",
               "point.x", point.x(), "point.y", point.y());
  DCHECK(main_thread_task_runner_->BelongsToCurrentThread());

  cc::ElementId element_id;
  if (widget_) {
    element_id =
        widget_->client()->FrameWidget()->GetScrollableContainerIdAt(point);
  }

  InputThreadTaskRunner(TaskRunnerType::kInputBlocking)
      ->PostTask(FROM_HERE, base::BindOnce(std::move(callback), element_id));
}

void WidgetInputHandlerManager::DidStartScrollingViewport() {
  mojom::blink::WidgetInputHandlerHost* host = GetWidgetInputHandlerHost();
  if (!host)
    return;
  host->DidStartScrollingViewport();
}

void WidgetInputHandlerManager::SetAllowedTouchAction(
    cc::TouchAction touch_action) {
  compositor_allowed_touch_action_ = touch_action;
}

void WidgetInputHandlerManager::ProcessTouchAction(
    cc::TouchAction touch_action) {
  if (mojom::blink::WidgetInputHandlerHost* host = GetWidgetInputHandlerHost())
    host->SetTouchActionFromMain(touch_action);
}

mojom::blink::WidgetInputHandlerHost*
WidgetInputHandlerManager::GetWidgetInputHandlerHost() {
  if (host_)
    return host_.get();
  return nullptr;
}

#if BUILDFLAG(IS_ANDROID)
void WidgetInputHandlerManager::AttachSynchronousCompositor(
    mojo::PendingRemote<mojom::blink::SynchronousCompositorControlHost>
        control_host,
    mojo::PendingAssociatedRemote<mojom::blink::SynchronousCompositorHost> host,
    mojo::PendingAssociatedReceiver<mojom::blink::SynchronousCompositor>
        compositor_request) {
  DCHECK(synchronous_compositor_registry_);
  if (synchronous_compositor_registry_->proxy()) {
    synchronous_compositor_registry_->proxy()->BindChannel(
        std::move(control_host), std::move(host),
        std::move(compositor_request));
  }
}
#endif

void WidgetInputHandlerManager::ObserveGestureEventOnMainThread(
    const WebGestureEvent& gesture_event,
    const cc::InputHandlerScrollResult& scroll_result) {
  base::OnceClosure observe_gesture_event_closure = base::BindOnce(
      &WidgetInputHandlerManager::ObserveGestureEventOnInputHandlingThread,
      this, gesture_event, scroll_result);
  InputThreadTaskRunner()->PostTask(FROM_HERE,
                                    std::move(observe_gesture_event_closure));
}

void WidgetInputHandlerManager::LogInputTimingUMA() {
  bool should_emit_uma;
  {
    base::AutoLock lock(uma_data_lock_);
    should_emit_uma = !uma_data_.have_emitted_uma;
    uma_data_.have_emitted_uma = true;
  }

  if (!should_emit_uma)
    return;

  InitialInputTiming lifecycle_state = InitialInputTiming::kBeforeLifecycle;
  if (!(suppressing_input_events_state_ &
        (unsigned)SuppressingInputEventsBits::kDeferMainFrameUpdates)) {
    if (suppressing_input_events_state_ &
        (unsigned)SuppressingInputEventsBits::kDeferCommits) {
      lifecycle_state = InitialInputTiming::kBeforeCommit;
    } else if (suppressing_input_events_state_ &
               (unsigned)SuppressingInputEventsBits::kHasNotPainted) {
      lifecycle_state = InitialInputTiming::kBeforeFirstPaint;
    } else {
      lifecycle_state = InitialInputTiming::kAfterFirstPaint;
    }
  }

  UMA_HISTOGRAM_ENUMERATION("PaintHolding.InputTiming4", lifecycle_state);
}

void WidgetInputHandlerManager::RecordEventMetricsForPaintTiming(
    std::optional<base::TimeTicks> first_paint_time) {
  CHECK(main_thread_task_runner_->BelongsToCurrentThread());

  if (recorded_event_metric_for_paint_timing_) {
    return;
  }
  recorded_event_metric_for_paint_timing_ = true;

  if (first_paint_max_delay_timer_ &&
      first_paint_max_delay_timer_->IsRunning()) {
    first_paint_max_delay_timer_->Stop();
  }

  bool first_paint_max_delay_reached = !first_paint_time.has_value();

  // Initialize to 0 timestamp and log 0 if there was no suppressed event or
  // the most recent suppressed event was before the first_paint_time
  auto diff = base::TimeDelta();
  int suppressed_interactions_count = 0;
  int suppressed_events_count = 0;
  {
    base::AutoLock lock(uma_data_lock_);
    if (first_paint_max_delay_reached) {
      diff = kFirstPaintMaxAcceptableDelay;
    } else if (uma_data_.most_recent_suppressed_event_time >
               first_paint_time.value()) {
      diff = uma_data_.most_recent_suppressed_event_time -
             first_paint_time.value();
    }

    suppressed_interactions_count = uma_data_.suppressed_interactions_count;
    suppressed_events_count = uma_data_.suppressed_events_count;
  }

  UMA_HISTOGRAM_TIMES("PageLoad.Internal.SuppressedEventsTimingBeforePaint3",
                      diff);
  UMA_HISTOGRAM_COUNTS(
      "PageLoad.Internal.SuppressedInteractionsCountBeforePaint3",
      suppressed_interactions_count);
  UMA_HISTOGRAM_COUNTS("PageLoad.Internal.SuppressedEventsCountBeforePaint3",
                       suppressed_events_count);
  UMA_HISTOGRAM_BOOLEAN(
      "PageLoad.Internal.SuppressedEventsBeforeMissingFirstPaint",
      first_paint_max_delay_reached);
}

void WidgetInputHandlerManager::StartFirstPaintMaxDelayTimer() {
  if (first_paint_max_delay_timer_ || recorded_event_metric_for_paint_timing_) {
    return;
  }
  first_paint_max_delay_timer_ = std::make_unique<base::OneShotTimer>();
  first_paint_max_delay_timer_->Start(
      FROM_HERE, kFirstPaintMaxAcceptableDelay,
      base::BindOnce(
          &WidgetInputHandlerManager::RecordEventMetricsForPaintTiming, this,
          std::nullopt));
}

void WidgetInputHandlerManager::DispatchScrollGestureToCompositor(
    std::unique_ptr<WebGestureEvent> event) {
  std::unique_ptr<WebCoalescedInputEvent> web_scoped_gesture_event =
      std::make_unique<WebCoalescedInputEvent>(std::move(event),
                                               ui::LatencyInfo());
  // input thread task runner is |main_thread_task_runner_| only in tests
  InputThreadTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&WidgetInputHandlerManager::
                         HandleInputEventWithLatencyOnInputHandlingThread,
                     this, std::move(web_scoped_gesture_event)));
}

void WidgetInputHandlerManager::
    HandleInputEventWithLatencyOnInputHandlingThread(
        std::unique_ptr<WebCoalescedInputEvent> event) {
  DCHECK(input_handler_proxy_);
  input_handler_proxy_->HandleInputEventWithLatencyInfo(
      std::move(event), nullptr, base::DoNothing());
}

void WidgetInputHandlerManager::DispatchEventOnInputThreadForTesting(
    std::unique_ptr<blink::WebCoalescedInputEvent> event,
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback) {
  InputThreadTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&WidgetInputHandlerManager::DispatchEvent, this,
                                std::move(event), std::move(callback)));
}

void WidgetInputHandlerManager::DispatchEvent(
    std::unique_ptr<WebCoalescedInputEvent> event,
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback) {
  WebInputEvent::Type event_type = event->Event().GetType();
  bool event_is_mouse_or_pointer_move =
      event_type == WebInputEvent::Type::kMouseMove ||
      event_type == WebInputEvent::Type::kPointerMove;
  if (!event_is_mouse_or_pointer_move &&
      event_type != WebInputEvent::Type::kTouchMove) {
    LogInputTimingUMA();

    // We only count it if the only reason we are suppressing is because we
    // haven't painted yet.
    if (suppressing_input_events_state_ ==
        static_cast<uint16_t>(SuppressingInputEventsBits::kHasNotPainted)) {
      base::AutoLock lock(uma_data_lock_);
      uma_data_.most_recent_suppressed_event_time = base::TimeTicks::Now();
      uma_data_.suppressed_events_count += 1;

      // Each of the events in the condition below represents a single
      // interaction by the user even though some of these events can fire
      // multiple JS events.  For example, further downstream from here Blink
      // `EventHandler` fires a JS "pointerdown" event (and under certain
      // conditions even a "mousedown" event) for single a kTouchStart event
      // here.
      if (event_type == WebInputEvent::Type::kMouseDown ||
          event_type == WebInputEvent::Type::kRawKeyDown ||
          event_type == WebInputEvent::Type::kKeyDown ||
          event_type == WebInputEvent::Type::kTouchStart ||
          event_type == WebInputEvent::Type::kPointerDown) {
        uma_data_.suppressed_interactions_count += 1;
      }
    }
  }

  if (!widget_is_embedded_ &&
      (suppressing_input_events_state_ &
       static_cast<uint16_t>(SuppressingInputEventsBits::kHasNotPainted))) {
    main_thread_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&WidgetInputHandlerManager::StartFirstPaintMaxDelayTimer,
                       this));
  }

  // Drop input if we are deferring a rendering pipeline phase, unless it's a
  // move event, or we are waiting for first visually non empty paint.
  // We don't want users interacting with stuff they can't see, so we drop it.
  // We allow moves because we need to keep the current pointer location up
  // to date. Tests and other code can allow pre-commit input through the
  // "allow-pre-commit-input" command line flag.
  // TODO(schenney): Also allow scrolls? This would make some tests not flaky,
  // it seems, because they sometimes crash on seeing a scroll update/end
  // without a begin. Scrolling, pinch-zoom etc. don't seem dangerous.

  uint16_t suppress_input = suppressing_input_events_state_;

  bool ignore_first_paint = !base::FeatureList::IsEnabled(
      blink::features::kDropInputEventsBeforeFirstPaint);
  // TODO(https://crbug.com/1490296): Investigate the possibility of a stale
  // subframe after navigation.
  if (widget_is_embedded_) {
    ignore_first_paint = true;
  }
  if (ignore_first_paint) {
    suppress_input &=
        ~static_cast<uint16_t>(SuppressingInputEventsBits::kHasNotPainted);
  }

  if (suppress_input && !allow_pre_commit_input_ &&
      !event_is_mouse_or_pointer_move) {
    if (callback) {
      std::move(callback).Run(
          mojom::blink::InputEventResultSource::kMainThread, ui::LatencyInfo(),
          mojom::blink::InputEventResultState::kNotConsumed, nullptr, nullptr);
    }
    return;
  }

  // If TimeTicks is not consistent across processes we cannot use the event's
  // platform timestamp in this process. Instead use the time that the event is
  // received as the event's timestamp.
  if (!base::TimeTicks::IsConsistentAcrossProcesses()) {
    event->EventPointer()->SetTimeStamp(base::TimeTicks::Now());
  }

  // TODO(b/224960731): Fix tests and add
  // `DCHECK(!arrived_in_browser_main_timestamp.is_null())`.
  //  We expect that `arrived_in_browser_main_timestamp` is always
  //  found, but there are a lot of tests where this component is not set.
  //  Currently EventMetrics knows how to handle null timestamp, so we
  //  don't process it here.
  const base::TimeTicks arrived_in_browser_main_timestamp =
      event->Event()
          .GetEventLatencyMetadata()
          .arrived_in_browser_main_timestamp;
  std::unique_ptr<cc::EventMetrics> metrics;
  if (event->Event().IsGestureScroll()) {
    const auto& gesture_event =
        static_cast<const WebGestureEvent&>(event->Event());
    const bool is_inertial = gesture_event.InertialPhase() ==
                             WebGestureEvent::InertialPhaseState::kMomentum;
    //'scrolls_blocking_touch_dispatched_to_renderer' can be null. It is set
    // by the Browser only if the corresponding TouchMove was blocking.
    base::TimeTicks blocking_touch_dispatched_to_renderer_timestamp =
        event->Event()
            .GetEventLatencyMetadata()
            .scrolls_blocking_touch_dispatched_to_renderer;

    if (gesture_event.GetType() == WebInputEvent::Type::kGestureScrollUpdate) {
      metrics = cc::ScrollUpdateEventMetrics::Create(
          gesture_event.GetTypeAsUiEventType(),
          gesture_event.GetScrollInputType(), is_inertial,
          has_seen_first_gesture_scroll_update_after_begin_
              ? cc::ScrollUpdateEventMetrics::ScrollUpdateType::kContinued
              : cc::ScrollUpdateEventMetrics::ScrollUpdateType::kStarted,
          gesture_event.data.scroll_update.delta_y, event->Event().TimeStamp(),
          arrived_in_browser_main_timestamp,
          blocking_touch_dispatched_to_renderer_timestamp,
          base::IdType64<class ui::LatencyInfo>(
              event->latency_info().trace_id()));
      has_seen_first_gesture_scroll_update_after_begin_ = true;
    } else {
      metrics = cc::ScrollEventMetrics::Create(
          gesture_event.GetTypeAsUiEventType(),
          gesture_event.GetScrollInputType(), is_inertial,
          event->Event().TimeStamp(), arrived_in_browser_main_timestamp,
          blocking_touch_dispatched_to_renderer_timestamp,
          base::IdType64<class ui::LatencyInfo>(
              event->latency_info().trace_id()));
      has_seen_first_gesture_scroll_update_after_begin_ = false;
    }
  } else if (WebInputEvent::IsPinchGestureEventType(event_type)) {
    const auto& gesture_event =
        static_cast<const WebGestureEvent&>(event->Event());
    metrics = cc::PinchEventMetrics::Create(
        gesture_event.GetTypeAsUiEventType(),
        gesture_event.GetScrollInputType(), event->Event().TimeStamp(),
        base::IdType64<class ui::LatencyInfo>(
            event->latency_info().trace_id()));
  } else {
    metrics = cc::EventMetrics::Create(event->Event().GetTypeAsUiEventType(),
                                       event->Event().TimeStamp(),
                                       arrived_in_browser_main_timestamp,
                                       base::IdType64<class ui::LatencyInfo>(
                                           event->latency_info().trace_id()));
  }

  if (uses_input_handler_) {
    // If the input_handler_proxy has disappeared ensure we just ack event.
    if (!input_handler_proxy_) {
      if (callback) {
        std::move(callback).Run(
            mojom::blink::InputEventResultSource::kMainThread,
            ui::LatencyInfo(),
            mojom::blink::InputEventResultState::kNotConsumed, nullptr,
            nullptr);
      }
      return;
    }

    // The InputHandlerProxy will be the first to try handling the event on the
    // compositor thread. It will respond to this class by calling
    // DidHandleInputEventSentToCompositor with the result of its attempt. Based
    // on the resulting disposition, DidHandleInputEventSentToCompositor will
    // either ACK the event as handled to the browser or forward it to the main
    // thread.
    input_handler_proxy_->HandleInputEventWithLatencyInfo(
        std::move(event), std::move(metrics),
        base::BindOnce(
            &WidgetInputHandlerManager::DidHandleInputEventSentToCompositor,
            this, std::move(callback)));
  } else {
    DCHECK(!input_handler_proxy_);
    DispatchDirectlyToWidget(std::move(event), std::move(metrics),
                             std::move(callback));
  }
}

void WidgetInputHandlerManager::InvokeInputProcessedCallback() {
  DCHECK(main_thread_task_runner_->BelongsToCurrentThread());

  // We can call this method even if we didn't request a callback (e.g. when
  // the renderer becomes hidden).
  if (!input_processed_callback_)
    return;

  // The handler's method needs to respond to the mojo message so it needs to
  // run on the input handling thread.  Even if we're already on the correct
  // thread, we PostTask for symmetry.
  InputThreadTaskRunner()->PostTask(FROM_HERE,
                                    std::move(input_processed_callback_));
}

static void WaitForInputProcessedFromMain(base::WeakPtr<WidgetBase> widget) {
  // If the widget is destroyed while we're posting to the main thread, the
  // Mojo message will be acked in WidgetInputHandlerImpl's destructor.
  if (!widget)
    return;

  WidgetInputHandlerManager* manager = widget->widget_input_handler_manager();

  // TODO(bokan): Temporary to unblock synthetic gesture events running under
  // VR. https://crbug.com/940063
  bool ack_immediately = widget->client()->ShouldAckSyntheticInputImmediately();

  // If the WidgetBase is hidden, we won't produce compositor frames for it
  // so just ACK the input to prevent blocking the browser indefinitely.
  if (widget->is_hidden() || ack_immediately) {
    manager->InvokeInputProcessedCallback();
    return;
  }

  auto redraw_complete_callback =
      base::BindOnce(&WidgetInputHandlerManager::InvokeInputProcessedCallback,
                     manager->AsWeakPtr());

  // Since wheel-events can kick off animations, we can not consider
  // all observable effects of an input gesture to be processed
  // when the CompositorFrame caused by that input has been produced, send, and
  // displayed. Therefore, explicitly request the presentation *after* any
  // ongoing scroll-animation ends. After the scroll-animation ends (if any),
  // the call will force a commit and redraw and callback when the
  // CompositorFrame has been displayed in the display service. Some examples of
  // non-trivial effects that require waiting that long: committing
  // MainThreadScrollHitTestRegion to the compositor, sending touch-action rects
  // to the browser, and sending updated surface information to the display
  // compositor for up-to-date OOPIF hit-testing.

  widget->RequestPresentationAfterScrollAnimationEnd(
      std::move(redraw_complete_callback));
}

void WidgetInputHandlerManager::WaitForInputProcessed(
    base::OnceClosure callback) {
  // Note, this will be called from the mojo-bound thread which could be either
  // main or compositor.
  DCHECK(!input_processed_callback_);
  input_processed_callback_ = std::move(callback);

  // We mustn't touch widget_ from the impl thread so post all the setup to the
  // main thread. Make sure the callback runs after all the queued events are
  // dispatched.
  base::OnceClosure closure =
      base::BindOnce(&MainThreadEventQueue::QueueClosure, input_event_queue_,
                     base::BindOnce(&WaitForInputProcessedFromMain, widget_));

  // If there are frame-aligned input events waiting to be dispatched, wait for
  // that to happen before posting to the main thread input queue.
  if (input_handler_proxy_) {
    input_handler_proxy_->RequestCallbackAfterEventQueueFlushed(
        std::move(closure));
  } else {
    std::move(closure).Run();
  }
}

void WidgetInputHandlerManager::InitializeInputEventSuppressionStates() {
  suppressing_input_events_state_ =
      static_cast<uint16_t>(SuppressingInputEventsBits::kHasNotPainted);

  first_paint_max_delay_timer_.reset();
  recorded_event_metric_for_paint_timing_ = false;

  base::AutoLock lock(uma_data_lock_);
  uma_data_.have_emitted_uma = false;
  uma_data_.most_recent_suppressed_event_time = base::TimeTicks();
  uma_data_.suppressed_interactions_count = 0;
  uma_data_.suppressed_events_count = 0;
}

void WidgetInputHandlerManager::OnDeferMainFrameUpdatesChanged(bool status) {
  if (status) {
    suppressing_input_events_state_ |= static_cast<uint16_t>(
        SuppressingInputEventsBits::kDeferMainFrameUpdates);
  } else {
    suppressing_input_events_state_ &= ~static_cast<uint16_t>(
        SuppressingInputEventsBits::kDeferMainFrameUpdates);
  }
}

void WidgetInputHandlerManager::OnDeferCommitsChanged(
    bool status,
    cc::PaintHoldingReason reason) {
  if (status && reason == cc::PaintHoldingReason::kFirstContentfulPaint) {
    suppressing_input_events_state_ |=
        static_cast<uint16_t>(SuppressingInputEventsBits::kDeferCommits);
  } else {
    suppressing_input_events_state_ &=
        ~static_cast<uint16_t>(SuppressingInputEventsBits::kDeferCommits);
  }
}

void WidgetInputHandlerManager::InitOnInputHandlingThread(
    const base::WeakPtr<cc::CompositorDelegateForInput>& compositor_delegate,
    bool sync_compositing) {
  DCHECK(InputThreadTaskRunner()->BelongsToCurrentThread());
  DCHECK(uses_input_handler_);

  // It is possible that the input_handler has already been destroyed before
  // this Init() call was invoked. If so, early out.
  if (!compositor_delegate)
    return;

  // The input handler is created and ownership is passed to the compositor
  // delegate; hence we only receive a WeakPtr back.
  base::WeakPtr<cc::InputHandler> input_handler =
      cc::InputHandler::Create(*compositor_delegate);
  DCHECK(input_handler);

  input_handler_proxy_ =
      std::make_unique<InputHandlerProxy>(*input_handler.get(), this);

#if BUILDFLAG(IS_ANDROID)
  if (sync_compositing) {
    DCHECK(synchronous_compositor_registry_);
    synchronous_compositor_registry_->CreateProxy(input_handler_proxy_.get());
  }
#endif
}

void WidgetInputHandlerManager::BindChannel(
    mojo::PendingReceiver<mojom::blink::WidgetInputHandler> receiver) {
  if (!receiver.is_valid())
    return;
  // Passing null for |input_event_queue_| tells the handler that we don't have
  // a compositor thread. (Single threaded-mode shouldn't use the queue, or else
  // events might get out of order - see crrev.com/519829).
  WidgetInputHandlerImpl* handler = new WidgetInputHandlerImpl(
      this,
      compositor_thread_default_task_runner_ ? input_event_queue_ : nullptr,
      widget_, frame_widget_input_handler_);
  handler->SetReceiver(std::move(receiver));
}

void WidgetInputHandlerManager::DispatchDirectlyToWidget(
    std::unique_ptr<WebCoalescedInputEvent> event,
    std::unique_ptr<cc::EventMetrics> metrics,
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback) {
  // This path should only be taken by non-frame WidgetBase that don't use a
  // compositor (e.g. popups, plugins). Events bounds for a frame WidgetBase
  // must be passed through the InputHandlerProxy first.
  DCHECK(!uses_input_handler_);

  // Input messages must not be processed if the WidgetBase was destroyed or
  // was just recreated for a provisional frame.
  if (!widget_ || widget_->IsForProvisionalFrame()) {
    if (callback) {
      std::move(callback).Run(mojom::blink::InputEventResultSource::kMainThread,
                              event->latency_info(),
                              mojom::blink::InputEventResultState::kNotConsumed,
                              nullptr, nullptr);
    }
    return;
  }

  auto send_callback = base::BindOnce(
      &WidgetInputHandlerManager::DidHandleInputEventSentToMainFromWidgetBase,
      this, std::move(callback));

  widget_->input_handler().HandleInputEvent(*event, std::move(metrics),
                                            std::move(send_callback));
  InputEventsDispatched(/*raf_aligned=*/false);
}

void WidgetInputHandlerManager::FindScrollTargetReply(
    std::unique_ptr<WebCoalescedInputEvent> event,
    std::unique_ptr<cc::EventMetrics> metrics,
    mojom::blink::WidgetInputHandler::DispatchEventCallback browser_callback,
    cc::ElementId hit_test_result) {
  TRACE_EVENT1("input", "WidgetInputHandlerManager::FindScrollTargetReply",
               "hit_test_result", hit_test_result.ToString());
  DCHECK(InputThreadTaskRunner()->BelongsToCurrentThread());

  // If the input_handler was destroyed in the mean time just ACK the event as
  // unconsumed to the browser and drop further handling.
  if (!input_handler_proxy_) {
    std::move(browser_callback)
        .Run(mojom::blink::InputEventResultSource::kMainThread,
             ui::LatencyInfo(),
             mojom::blink::InputEventResultState::kNotConsumed, nullptr,
             nullptr);
    return;
  }

  input_handler_proxy_->ContinueScrollBeginAfterMainThreadHitTest(
      std::move(event), std::move(metrics),
      base::BindOnce(
          &WidgetInputHandlerManager::DidHandleInputEventSentToCompositor, this,
          std::move(browser_callback)),
      hit_test_result);

  // Let the main frames flow.
  input_handler_proxy_->SetDeferBeginMainFrame(false);
}

void WidgetInputHandlerManager::SendDroppedPointerDownCounts() {
  main_thread_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&WidgetBase::CountDroppedPointerDownForEventTiming,
                     widget_, dropped_pointer_down_));
  dropped_pointer_down_ = 0;
}

void WidgetInputHandlerManager::DidHandleInputEventSentToCompositor(
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback,
    InputHandlerProxy::EventDisposition event_disposition,
    std::unique_ptr<WebCoalescedInputEvent> event,
    std::unique_ptr<InputHandlerProxy::DidOverscrollParams> overscroll_params,
    const WebInputEventAttribution& attribution,
    std::unique_ptr<cc::EventMetrics> metrics) {
  TRACE_EVENT1("input",
               "WidgetInputHandlerManager::DidHandleInputEventSentToCompositor",
               "Disposition", event_disposition);

  int64_t trace_id = event->latency_info().trace_id();
  TRACE_EVENT(
      "input,benchmark,latencyInfo", "LatencyInfo.Flow",
      [&](perfetto::EventContext ctx) {
        base::TaskAnnotator::EmitTaskTimingDetails(ctx);
        ui::LatencyInfo::FillTraceEvent(
            ctx, trace_id,
            ChromeLatencyInfo2::Step::STEP_DID_HANDLE_INPUT_AND_OVERSCROLL);
      });

  DCHECK(InputThreadTaskRunner()->BelongsToCurrentThread());

  if (event_disposition == InputHandlerProxy::DROP_EVENT &&
      event->Event().GetType() == blink::WebInputEvent::Type::kTouchStart) {
    const WebTouchEvent touch_event =
        static_cast<const WebTouchEvent&>(event->Event());
    for (unsigned i = 0; i < touch_event.touches_length; ++i) {
      const WebTouchPoint& touch_point = touch_event.touches[i];
      if (touch_point.state == WebTouchPoint::State::kStatePressed) {
        dropped_pointer_down_++;
      }
    }
    if (dropped_pointer_down_ > 0) {
      if (!dropped_event_counts_timer_) {
        dropped_event_counts_timer_ = std::make_unique<base::OneShotTimer>();
      }

      if (!dropped_event_counts_timer_->IsRunning()) {
        dropped_event_counts_timer_->Start(
            FROM_HERE, kEventCountsTimerDelay,
            base::BindOnce(
                &WidgetInputHandlerManager::SendDroppedPointerDownCounts,
                this));
      }
    }
  }

  if (event_disposition == InputHandlerProxy::REQUIRES_MAIN_THREAD_HIT_TEST) {
    TRACE_EVENT_INSTANT0("input", "PostingHitTestToMainThread",
                         TRACE_EVENT_SCOPE_THREAD);
    DCHECK_EQ(event->Event().GetType(),
              WebInputEvent::Type::kGestureScrollBegin);
    DCHECK(input_handler_proxy_);

    gfx::PointF event_position =
        static_cast<const WebGestureEvent&>(event->Event()).PositionInWidget();

    ElementAtPointCallback result_callback = base::BindOnce(
        &WidgetInputHandlerManager::FindScrollTargetReply, this,
        std::move(event), std::move(metrics), std::move(callback));

    main_thread_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&WidgetInputHandlerManager::FindScrollTargetOnMainThread,
                       this, event_position, std::move(result_callback)));

    // The hit test is on the critical path of the scroll. Don't post any
    // BeginMainFrame tasks until we've returned from the hit test and handled
    // the rest of the input in the compositor event queue.
    //
    // NOTE: setting this in FindScrollTargetOnMainThread would be too late; we
    // might have already posted a BeginMainFrame by then. Even though the
    // scheduler prioritizes the hit test, that main frame won't see the updated
    // scroll offset because the task is bound to CompositorCommitData from the
    // time it was posted. We'd then have to wait for a SECOND BeginMainFrame to
    // actually repaint the scroller at the right offset.
    input_handler_proxy_->SetDeferBeginMainFrame(true);
    return;
  }

  std::optional<cc::TouchAction> touch_action =
      compositor_allowed_touch_action_;
  compositor_allowed_touch_action_.reset();

  mojom::blink::InputEventResultState ack_state =
      InputEventDispositionToAck(event_disposition);
  if (ack_state == mojom::blink::InputEventResultState::kConsumed) {
    widget_scheduler_->DidHandleInputEventOnCompositorThread(
        event->Event(), scheduler::WidgetScheduler::InputEventState::
                            EVENT_CONSUMED_BY_COMPOSITOR);
  } else if (MainThreadEventQueue::IsForwardedAndSchedulerKnown(ack_state)) {
    widget_scheduler_->DidHandleInputEventOnCompositorThread(
        event->Event(), scheduler::WidgetScheduler::InputEventState::
                            EVENT_FORWARDED_TO_MAIN_THREAD);
  }

  if (ack_state == mojom::blink::InputEventResultState::kSetNonBlocking ||
      ack_state ==
          mojom::blink::InputEventResultState::kSetNonBlockingDueToFling ||
      ack_state == mojom::blink::InputEventResultState::kNotConsumed) {
    DCHECK(!overscroll_params);
    DCHECK(!event->latency_info().coalesced());
    MainThreadEventQueue::DispatchType dispatch_type =
        callback.is_null() ? MainThreadEventQueue::DispatchType::kNonBlocking
                           : MainThreadEventQueue::DispatchType::kBlocking;
    HandledEventCallback handled_event = base::BindOnce(
        &WidgetInputHandlerManager::DidHandleInputEventSentToMain, this,
        std::move(callback), touch_action);
    input_event_queue_->HandleEvent(std::move(event), dispatch_type, ack_state,
                                    attribution, std::move(metrics),
                                    std::move(handled_event));
    return;
  }

  if (callback) {
    std::move(callback).Run(
        mojom::blink::InputEventResultSource::kCompositorThread,
        event->latency_info(), ack_state,
        ToDidOverscrollParams(overscroll_params.get()),
        touch_action
            ? mojom::blink::TouchActionOptional::New(touch_action.value())
            : nullptr);
  }
}

void WidgetInputHandlerManager::DidHandleInputEventSentToMainFromWidgetBase(
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback,
    mojom::blink::InputEventResultState ack_state,
    const ui::LatencyInfo& latency_info,
    std::unique_ptr<blink::InputHandlerProxy::DidOverscrollParams>
        overscroll_params,
    std::optional<cc::TouchAction> touch_action) {
  DidHandleInputEventSentToMain(
      std::move(callback), std::nullopt, ack_state, latency_info,
      ToDidOverscrollParams(overscroll_params.get()), touch_action);
}

void WidgetInputHandlerManager::DidHandleInputEventSentToMain(
    mojom::blink::WidgetInputHandler::DispatchEventCallback callback,
    std::optional<cc::TouchAction> touch_action_from_compositor,
    mojom::blink::InputEventResultState ack_state,
    const ui::LatencyInfo& latency_info,
    mojom::blink::DidOverscrollParamsPtr overscroll_params,
    std::optional<cc::TouchAction> touch_action_from_main) {
  if (!callback)
    return;

  TRACE_EVENT1("input",
               "WidgetInputHandlerManager::DidHandleInputEventSentToMain",
               "ack_state", ack_state);

  int64_t trace_id = latency_info.trace_id();
  TRACE_EVENT(
      "input,benchmark,latencyInfo", "LatencyInfo.Flow",
      [&](perfetto::EventContext ctx) {
        base::TaskAnnotator::EmitTaskTimingDetails(ctx);
        ui::LatencyInfo::FillTraceEvent(
            ctx, trace_id,
            ChromeLatencyInfo2::Step::STEP_HANDLED_INPUT_EVENT_MAIN_OR_IMPL);
      });

  std::optional<cc::TouchAction> touch_action_for_ack = touch_action_from_main;
  if (!touch_action_for_ack.has_value()) {
    TRACE_EVENT_INSTANT0("input", "Using allowed_touch_action",
                         TRACE_EVENT_SCOPE_THREAD);
    touch_action_for_ack = touch_action_from_compositor;
  }

  // This method is called from either the main thread or the compositor thread.
  bool is_compositor_thread =
      compositor_thread_default_task_runner_ &&
      compositor_thread_default_task_runner_->BelongsToCurrentThread();

  // If there is a compositor task runner and the current thread isn't the
  // compositor thread proxy it over to the compositor thread.
  if (compositor_thread_default_task_runner_ && !is_compositor_thread) {
    TRACE_EVENT_INSTANT0("input", "PostingToCompositor",
                         TRACE_EVENT_SCOPE_THREAD);
    compositor_thread_default_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(CallCallback, std::move(callback), ack_state,
                                  latency_info, std::move(overscroll_params),
                                  touch_action_for_ack));
  } else {
    // Otherwise call the callback immediately.
    std::move(callback).Run(
        is_compositor_thread
            ? mojom::blink::InputEventResultSource::kCompositorThread
            : mojom::blink::InputEventResultSource::kMainThread,
        latency_info, ack_state, std::move(overscroll_params),
        touch_action_for_ack ? mojom::blink::TouchActionOptional::New(
                                   touch_action_for_ack.value())
                             : nullptr);
  }
}

void WidgetInputHandlerManager::ObserveGestureEventOnInputHandlingThread(
    const WebGestureEvent& gesture_event,
    const cc::InputHandlerScrollResult& scroll_result) {
  if (!input_handler_proxy_)
    return;
  // The elastic overscroll controller on android can be dynamically created or
  // removed by changing prefers-reduced-motion. When removed, we do not need to
  // observe the event.
  if (!input_handler_proxy_->elastic_overscroll_controller())
    return;
  input_handler_proxy_->elastic_overscroll_controller()
      ->ObserveGestureEventAndResult(gesture_event, scroll_result);
}

const scoped_refptr<base::SingleThreadTaskRunner>&
WidgetInputHandlerManager::InputThreadTaskRunner(TaskRunnerType type) const {
  if (compositor_thread_input_blocking_task_runner_ &&
      type == TaskRunnerType::kInputBlocking) {
    return compositor_thread_input_blocking_task_runner_;
  } else if (compositor_thread_default_task_runner_) {
    return compositor_thread_default_task_runner_;
  }
  return main_thread_task_runner_;
}

#if BUILDFLAG(IS_ANDROID)
SynchronousCompositorRegistry*
WidgetInputHandlerManager::GetSynchronousCompositorRegistry() {
  DCHECK(synchronous_compositor_registry_);
  return synchronous_compositor_registry_.get();
}
#endif

void WidgetInputHandlerManager::ClearClient() {
  first_paint_max_delay_timer_.reset();
  recorded_event_metric_for_paint_timing_ = false;
  input_event_queue_->ClearClient();
}

void WidgetInputHandlerManager::UpdateBrowserControlsState(
    cc::BrowserControlsState constraints,
    cc::BrowserControlsState current,
    bool animate,
    base::optional_ref<const cc::BrowserControlsOffsetTagsInfo>
        offset_tags_info) {
  if (!input_handler_proxy_) {
    return;
  }

  DCHECK(InputThreadTaskRunner()->BelongsToCurrentThread());
  input_handler_proxy_->UpdateBrowserControlsState(constraints, current,
                                                   animate, offset_tags_info);
}

void WidgetInputHandlerManager::FlushCompositorQueueForTesting() {
  CHECK(InputThreadTaskRunner()->BelongsToCurrentThread());
  if (!input_handler_proxy_) {
    return;
  }
  input_handler_proxy_->FlushQueuedEventsForTesting();
}

void WidgetInputHandlerManager::FlushMainThreadQueueForTesting(
    base::OnceClosure done) {
  CHECK(main_thread_task_runner_->BelongsToCurrentThread());
  input_event_queue()->DispatchRafAlignedInput(base::TimeTicks::Now());
  CHECK(input_event_queue()->IsEmptyForTesting());
  std::move(done).Run();
}

void WidgetInputHandlerManager::FlushEventQueuesForTesting(
    base::OnceClosure done_callback) {
  CHECK(main_thread_task_runner_->BelongsToCurrentThread());

  auto flush_compositor_queue = base::BindOnce(
      &WidgetInputHandlerManager::FlushCompositorQueueForTesting, this);

  auto flush_main_queue =
      base::BindOnce(&WidgetInputHandlerManager::FlushMainThreadQueueForTesting,
                     this, std::move(done_callback));

  // Flush the compositor queue first since dispatching compositor events may
  // bounce them back into the main thread event queue.
  InputThreadTaskRunner()->PostTaskAndReply(FROM_HERE,
                                            std::move(flush_compositor_queue),
                                            std::move(flush_main_queue));
}

}  // namespace blink

"""

```