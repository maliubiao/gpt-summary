Response:
The user wants to understand the functionality of the provided C++ source code file `widget_input_handler_manager.cc`. I need to analyze the code and explain its purpose, especially its interactions with JavaScript, HTML, and CSS. I also need to identify potential logical inferences, provide examples with hypothetical inputs and outputs, and point out common user/programming errors related to this component. Finally, I need to summarize the overall function of the code.

Here's a breakdown of how to approach this:

1. **High-level Functionality:** Read through the method names and comments to grasp the core responsibilities of `WidgetInputHandlerManager`. It seems to be managing input events and their processing across different threads (main thread and compositor thread).

2. **Interaction with JS, HTML, CSS:** Look for methods or actions that directly or indirectly influence or are influenced by these web technologies. For instance:
    * **Scrolling:** Input events often trigger scrolling, which can affect the visual layout (CSS) and potentially trigger JavaScript events.
    * **Hit Testing:** Determining which element is the target of an event is crucial for event handling and can involve the DOM structure (HTML) and element positioning (CSS).
    * **Touch Actions:** These influence the browser's default handling of touch events, potentially interacting with CSS touch-action properties.
    * **Requesting Presentation:** This ties into when changes caused by input become visible, which is related to rendering the HTML and CSS.

3. **Logical Inferences (Assumptions & Outputs):**  Analyze methods where decisions are made based on certain conditions. Consider:
    * **Input Suppression:** What conditions lead to input events being suppressed? What is the outcome?
    * **Thread Handling:** How are events passed between the main and compositor threads? What are the assumptions about thread safety?
    * **Event Acknowledgement:** How are input events acknowledged (consumed or not consumed)? What determines this?

4. **User/Programming Errors:** Think about common mistakes developers might make when dealing with input handling, especially in a multithreaded context:
    * **Incorrect Threading:** Accessing UI elements from the wrong thread.
    * **Missing Event Listeners:** Assuming an event will be handled without proper setup.
    * **Conflicting Input Handlers:** Multiple handlers potentially interfering with each other.
    * **Performance Issues:** Blocking the main thread with long-running input handlers.

5. **Code Structure and Key Components:**  Identify the main parts of the class, like the input event queue, the interaction with the `InputHandlerProxy`, and the communication with the `WidgetBase`.

6. **Summarization:** Condense the key findings into a concise summary of the class's purpose.

**Mental Sandbox/Pre-computation:**

* **Event Flow:** Visualize the journey of an input event from the browser to the renderer, and how this class manages that flow, especially the handoff between threads.
* **Compositor vs. Main Thread:**  Keep in mind the responsibilities of each thread and how this class ensures proper synchronization. The compositor handles scrolling and animations smoothly, while the main thread executes JavaScript and handles DOM updates.
* **Key Methods:**  Focus on methods like `HandleInputEvent`, `WaitForInputProcessed`, `DidHandleInputEventSentToCompositor`, and `DidHandleInputEventSentToMain`.

By following these steps, I can provide a comprehensive explanation of the `WidgetInputHandlerManager`'s functionality and its role within the Blink rendering engine.
好的，这是对`blink/renderer/platform/widget/input/widget_input_handler_manager.cc`文件功能的归纳总结：

**功能归纳：**

`WidgetInputHandlerManager` 的核心职责是**管理和协调 Web 页面中输入事件的处理流程**，尤其是在 Blink 渲染引擎的**主线程和合成器线程之间**。它确保输入事件能够被正确地分发、处理，并最终影响页面的渲染和行为。

以下是其主要功能点的总结：

1. **输入事件接收与分发:**
   - 接收来自浏览器进程的输入事件（例如鼠标点击、触摸、键盘输入等）。
   - 决定是将事件直接分发到 `WidgetBase` (对于非主框架的 Widget，例如弹出窗口)，还是通过 `InputHandlerProxy` 发送到合成器线程进行处理。

2. **合成器线程交互:**
   - 如果使用了合成器（通常是主框架），则通过 `InputHandlerProxy` 将输入事件发送到合成器线程。
   - 处理来自合成器线程的关于输入事件处理结果的反馈，例如事件是否被消费、是否需要主线程进行命中测试等。
   - 管理合成器线程中的输入事件队列，确保事件按顺序处理。

3. **主线程交互:**
   - 将需要主线程处理的输入事件添加到主线程的事件队列中 (`MainThreadEventQueue`)。
   - 处理来自主线程的关于输入事件处理结果的反馈。
   - 协调主线程和合成器线程之间的同步，例如在滚动动画结束后请求 Presentation，确保所有相关的副作用都已生效。

4. **输入事件抑制与延迟:**
   - 管理输入事件的抑制状态，例如在首次绘制前、主帧更新被延迟时、提交被延迟时等情况下，可以抑制输入事件的处理，以优化性能。
   - 使用计时器来管理首次绘制的最大延迟，并在超时后记录相关指标。

5. **命中测试 (Hit Testing):**
   - 协调在主线程上执行命中测试，以确定特定坐标下的目标元素，尤其是在合成器线程无法直接确定滚动目标时。

6. **事件确认 (Acknowledgement):**
   - 将输入事件的处理结果（是否被消费、是否需要滚动等）告知浏览器进程。

7. **滚动处理:**
   - 与合成器线程协作处理滚动事件，包括处理惯性滚动和弹性溢出滚动。

8. **浏览器控件状态更新:**
   - 将浏览器控件（例如顶部工具栏）的状态变化传递给合成器线程，以便进行相应的渲染更新。

9. **性能监控与指标收集:**
   - 记录与输入事件处理相关的性能指标，例如输入事件的延迟、被抑制的次数等。

10. **线程管理:**
    - 维护指向主线程和合成器线程的任务运行器的指针，以便在不同线程之间传递任务。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * 当一个鼠标点击事件发生时，`WidgetInputHandlerManager` 负责将其传递到主线程，最终触发 JavaScript 中注册的 `click` 事件监听器。
    * **假设输入：** 用户点击了一个绑定了 JavaScript `onclick` 事件处理函数的按钮。
    * **输出：** `WidgetInputHandlerManager` 将点击事件传递到主线程，JavaScript 引擎执行相应的事件处理函数。
* **HTML:**
    * `WidgetInputHandlerManager` 在处理滚动事件时，会涉及到 HTML 结构，因为它需要确定哪些元素是可滚动的。
    * **假设输入：** 用户在可滚动的 `<div>` 元素上进行拖动操作。
    * **输出：** `WidgetInputHandlerManager` 将滚动事件发送到合成器线程，合成器线程根据 HTML 结构和 CSS 样式来更新滚动位置。
* **CSS:**
    * CSS 的 `touch-action` 属性会影响 `WidgetInputHandlerManager` 对触摸事件的处理。例如，如果一个元素设置了 `touch-action: none;`，则 `WidgetInputHandlerManager` 可能会阻止浏览器默认的触摸行为（如滚动）。
    * **假设输入：** 用户尝试在设置了 `touch-action: pan-y;` 的元素上进行水平滑动。
    * **输出：** `WidgetInputHandlerManager` 会根据 CSS 属性的指示，允许垂直滚动，但阻止水平滚动。

**逻辑推理的假设输入与输出：**

* **假设输入：** 在页面首次加载完成前，用户快速连续点击屏幕。
* **逻辑推理：** `WidgetInputHandlerManager` 会检查 `suppressing_input_events_state_`，如果发现尚未完成首次绘制 (`kHasNotPainted` 位被设置)，则会将后续的点击事件暂时抑制，以避免在页面未完全准备好时进行不必要的处理。
* **输出：** 被抑制的点击事件会被缓存，直到首次绘制完成后再进行处理。

**涉及用户或者编程常见的使用错误举例说明：**

* **错误：** 在 JavaScript 中阻止了默认的滚动行为（例如使用 `event.preventDefault()`），但没有考虑到合成器线程的滚动处理。
* **后果：** 用户可能会看到页面滚动不流畅或者出现卡顿，因为合成器线程可能仍然在尝试执行滚动动画，而主线程的 JavaScript 代码阻止了默认行为，导致状态不一致。
* **错误：** 错误地假设所有输入事件都会立即在主线程上处理。
* **后果：**  开发者可能会编写依赖于输入事件立即生效的代码，但由于合成器线程的介入或者输入事件的抑制，这些代码可能不会按预期执行，导致逻辑错误。

总而言之，`WidgetInputHandlerManager` 是 Blink 渲染引擎中处理用户输入的核心组件，它负责在多线程环境下协调各种输入事件的处理，确保用户交互能够正确地反映在页面上，并尽可能地优化性能。 它深刻地影响着 JavaScript 事件的触发、HTML 元素的行为以及 CSS 样式的应用。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/widget_input_handler_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ll observable effects of an input gesture to be processed
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
```