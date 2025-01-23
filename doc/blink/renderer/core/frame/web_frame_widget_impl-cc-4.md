Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `web_frame_widget_impl.cc`.
The summary should include:
- General functionalities of the code.
- Relationships with Javascript, HTML, and CSS, with examples.
- Logical reasoning with assumed input and output.
- Common user or programming errors with examples.
- This is part 5 of 7, so the summary should reflect the functionalities present in this specific part.

**Plan:**
1. Read through the code and identify the core functionalities of each method.
2. Analyze how these functionalities relate to rendering, input handling, and interaction with the web page.
3. Identify connections to Javascript, HTML, and CSS concepts.
4. Formulate logical reasoning scenarios with hypothetical inputs and expected outputs.
5. Consider common mistakes related to the functionalities.
6. Summarize the functionalities covered in this specific section of the code.
这是 `blink/renderer/core/frame/web_frame_widget_impl.cc` 源代码文件的第五部分，主要负责以下功能：

**核心功能归纳：**

* **管理和同步渲染层的状态:**  这部分代码继续处理与渲染层相关的操作，例如设置根渲染层 (root layer)、管理动画工作单元 (AnimationWorklet) 和绘制工作单元 (PaintWorklet) 的调度器。
* **处理交换链 (Swap Chain) 的时间信息:** 实现了 `ReportTimeSwapPromise` 类，用于在交换发生时通知 Blink，并处理 presentation time 和 swap time 的回调，以便进行性能监控和同步。
* **处理输入法 (IME) 相关的功能:**  包含设置输入法组合 (composition) 、提交文本 (commit text)、完成组合 (finish composing text)、获取选区边界 (selection bounds)、以及与虚拟键盘相关的操作。
* **处理键盘事件的命令:** 允许添加和执行与特定键盘事件关联的编辑命令。
* **处理焦点和工具提示:**  管理焦点状态的设置和获取，以及更新工具提示的显示。
* **处理滚动事件:**  允许注入合成的滚动条手势滚动事件。
* **提供 hit testing 功能:**  提供 `CoreHitTestResultAt` 方法，用于在特定点进行命中测试。

**与 JavaScript, HTML, CSS 的关系及举例：**

* **JavaScript:**
    * **动画和渲染:** `EnsureCompositorMutatorDispatcher` 和 `EnsureCompositorPaintDispatcher` 与 JavaScript 的 Animation Worklet 和 Paint Worklet API 相关。JavaScript 代码可以通过这些 API 定义自定义的动画和绘制逻辑，而这段 C++ 代码负责在渲染进程中管理这些逻辑的执行。
        * **假设输入:** JavaScript 代码使用 `registerAnimator()` 注册了一个自定义动画器。
        * **输出:** `EnsureCompositorMutatorDispatcher` 会确保在渲染线程上创建并设置相应的动画调度器，以便在渲染时执行 JavaScript 定义的动画逻辑。
    * **输入法事件:**  当用户在网页中输入文本时，JavaScript 可以通过监听 `compositionstart`, `compositionupdate`, `compositionend`, 和 `textInput` 等事件来响应输入法操作。 这段 C++ 代码中的 `SetComposition`, `CommitText`, `FinishComposingText` 等方法，正是 Blink 引擎接收到底层操作系统输入法事件后，传递给渲染引擎进行处理的关键步骤。
        * **假设输入:** 用户使用中文输入法输入 "你好"。
        * **输出:**  Blink 会先调用 `SetComposition` 多次，传递拼音字母的组合，并在输入完成后调用 `CommitText` 提交最终的 "你好" 文本。 JavaScript 监听器可以接收到相应的 composition 和 textInput 事件。
* **HTML:**
    * **焦点和输入元素:**  `TextInputInfo`, `GetEditContextBoundsInWindow`, `ComputeWebTextInputNextPreviousFlags` 等方法与 HTML 中的 `<input>`、`<textarea>` 等表单元素的交互密切相关。当这些元素获得焦点时，这段 C++ 代码负责获取和管理它们的输入状态和上下文信息。
        * **假设输入:** 用户点击了一个 `<input type="text">` 元素。
        * **输出:** `SetFocus(true)` 会被调用，并且 `TextInputInfo` 可以返回该输入元素的当前值、光标位置等信息。
    * **选区 (Selection):** `GetSelectionBoundsInWindow` 方法用于获取当前页面选区的边界。HTML 内容被选中时，这个方法可以提供选区的屏幕坐标，这对于实现复制粘贴等功能至关重要。
        * **假设输入:** 用户在网页上选中了一段文字。
        * **输出:** `GetSelectionBoundsInWindow` 将返回包含选区起始和结束位置的矩形信息。
* **CSS:**
    * **工具提示样式:** 虽然这段代码本身不直接操作 CSS 样式，但 `UpdateTooltipUnderCursor` 和 `UpdateTooltipFromKeyboard` 方法负责更新工具提示的文本内容和位置。工具提示的最终样式是由 CSS 决定的。
        * **假设输入:** 鼠标悬停在一个设置了 `title` 属性的 HTML 元素上。
        * **输出:** `UpdateTooltipUnderCursor` 会被调用，传递 `title` 属性的值，浏览器会根据预设的或自定义的 CSS 样式显示工具提示。
    * **渲染层和合成:** `SetRootLayer` 方法设置根渲染层，这与 CSS 的 `transform`, `opacity`, `filter` 等属性可能触发的合成 (compositing) 有关。如果一个元素被提升为自己的合成层，这段代码会负责管理这个层的生命周期。

**逻辑推理及假设输入与输出：**

* **场景：处理交换链时间回调**
    * **假设输入:**  渲染器完成了一帧的渲染，并准备进行屏幕刷新 (swap)。`ReportTimeSwapPromise` 被创建并添加到交换链中。
    * **逻辑:**  `WillSwap` 被调用，记录帧 token。在实际交换发生后，`DidSwap` 被调用，并发布一个任务到主线程，执行 `RunCallbackAfterSwap`。`RunCallbackAfterSwap`  会进一步调用 `widget_base_->AddPresentationCallback` 来注册 presentation time 的回调，并立即执行 swap time 的回调。
    * **输出:**  主线程会收到 swap time 的时间戳。当 GPU 驱动程序通知 presentation time 时，之前注册的回调函数会被执行，提供更精确的帧显示时间。

* **场景：处理键盘事件的编辑命令**
    * **假设输入:**  用户按下了一个绑定了自定义编辑命令的快捷键，例如 "Ctrl+B" 绑定了 "bold"。
    * **逻辑:**  `AddEditCommandForNextKeyEvent` 被调用，将 "bold" 命令添加到 `edit_commands_` 队列中。当键盘事件被处理时，`HandleCurrentKeyboardEvent` 会遍历 `edit_commands_` 并调用 `frame->ExecuteCommand` 执行相应的编辑操作。
    * **输出:**  如果当前焦点在一个可编辑的文本区域，文本会被加粗。

**用户或编程常见的使用错误举例：**

* **忘记调用 `SetRootLayer`:** 如果没有正确设置根渲染层，页面内容将无法显示，或者合成效果可能无法正常工作。
    * **错误场景:**  在创建 `WebFrameWidgetImpl` 后，没有调用 `SetRootLayer` 将渲染层的根节点连接起来。
    * **结果:** 页面显示空白。
* **在错误的线程访问 Compositor Mutator/Paint Dispatcher:**  `mutator_dispatcher_` 和 `paint_dispatcher_` 应该只在合成器线程上访问。如果在主线程或其他线程上直接访问，可能导致崩溃或未定义的行为。
    * **错误场景:**  在主线程中尝试直接调用 `mutator_dispatcher_->Mutate()`。
    * **结果:**  可能触发断言失败或导致程序崩溃。
* **不正确地处理 IME 事件:**  如果开发者没有正确处理 `compositionstart`, `compositionupdate`, `compositionend` 等事件，可能会导致输入法输入异常，例如输入内容丢失或格式错误。
    * **错误场景:**  JavaScript 代码错误地阻止了 `compositionend` 事件的默认行为。
    * **结果:**  用户完成输入后，文本没有正确提交到页面。
* **在非聚焦状态下尝试获取选区信息:**  如果当前窗口或 frame 没有焦点，调用 `GetSelectionBoundsInWindow` 可能会返回不准确的信息或导致错误。
    * **错误场景:**  在后台运行的 frame 中尝试获取选区信息。
    * **结果:**  返回的选区边界可能为空或无效。

**总结 (第5部分的功能):**

这部分 `WebFrameWidgetImpl` 的代码主要集中在**渲染层管理、交换链时间同步以及输入法和键盘事件的处理**上。它负责将底层的渲染机制与上层的输入事件和 JavaScript API 连接起来，确保页面的正确显示和用户交互的流畅进行。 具体来说，它处理了如何设置和更新渲染层，如何精确地测量渲染性能，以及如何响应用户的文本输入和键盘操作。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
layer) {
  if (!View()->does_composite()) {
    DCHECK(ForMainFrame());
    DCHECK(!layer);
    return;
  }

  // Set up some initial state before we are setting the layer.
  if (ForSubframe() && layer) {
    // Child local roots will always have a transparent background color.
    widget_base_->LayerTreeHost()->set_background_color(SkColors::kTransparent);
    // Pass the limits even though this is for subframes, as the limits will
    // be needed in setting the raster scale.
    SetPageScaleStateAndLimits(1.f, false /* is_pinch_gesture_active */,
                               View()->MinimumPageScaleFactor(),
                               View()->MaximumPageScaleFactor());
  }

  bool root_layer_exists = !!layer;
  if (widget_base_->WillBeDestroyed()) {
    CHECK(!layer);
  } else {
    widget_base_->LayerTreeHost()->SetRootLayer(std::move(layer));
  }

  // Notify the WebView that we did set a layer.
  if (ForMainFrame()) {
    View()->DidChangeRootLayer(root_layer_exists);
  }
}

base::WeakPtr<AnimationWorkletMutatorDispatcherImpl>
WebFrameWidgetImpl::EnsureCompositorMutatorDispatcher(
    scoped_refptr<base::SingleThreadTaskRunner> mutator_task_runner) {
  if (!mutator_task_runner_) {
    mutator_task_runner_ = std::move(mutator_task_runner);
    widget_base_->LayerTreeHost()->SetLayerTreeMutator(
        AnimationWorkletMutatorDispatcherImpl::CreateCompositorThreadClient(
            mutator_dispatcher_, mutator_task_runner_));
  }

  DCHECK(mutator_task_runner_);
  return mutator_dispatcher_;
}

HitTestResult WebFrameWidgetImpl::CoreHitTestResultAt(
    const gfx::PointF& point_in_viewport) {
  LocalFrameView* view = LocalRootImpl()->GetFrameView();
  gfx::PointF point_in_root_frame(view->ViewportToFrame(point_in_viewport));
  return HitTestResultForRootFramePos(point_in_root_frame);
}

cc::AnimationHost* WebFrameWidgetImpl::AnimationHost() const {
  return widget_base_->AnimationHost();
}

cc::AnimationTimeline* WebFrameWidgetImpl::ScrollAnimationTimeline() const {
  return widget_base_->ScrollAnimationTimeline();
}

base::WeakPtr<PaintWorkletPaintDispatcher>
WebFrameWidgetImpl::EnsureCompositorPaintDispatcher(
    scoped_refptr<base::SingleThreadTaskRunner>* paint_task_runner) {
  // We check paint_task_runner_ not paint_dispatcher_ because the dispatcher is
  // a base::WeakPtr that should only be used on the compositor thread.
  if (!paint_task_runner_) {
    widget_base_->LayerTreeHost()->SetPaintWorkletLayerPainter(
        PaintWorkletPaintDispatcher::CreateCompositorThreadPainter(
            &paint_dispatcher_));
    paint_task_runner_ = Thread::CompositorThread()->GetTaskRunner();
  }
  DCHECK(paint_task_runner_);
  *paint_task_runner = paint_task_runner_;
  return paint_dispatcher_;
}

void WebFrameWidgetImpl::SetDelegatedInkMetadata(
    std::unique_ptr<gfx::DelegatedInkMetadata> metadata) {
  widget_base_->LayerTreeHost()->SetDelegatedInkMetadata(std::move(metadata));
}

// Enables measuring and reporting both presentation times and swap times in
// swap promises.
class ReportTimeSwapPromise : public cc::SwapPromise {
 public:
  ReportTimeSwapPromise(WebFrameWidgetImpl::PromiseCallbacks callbacks,
                        scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                        WebFrameWidgetImpl* widget)
      : promise_callbacks_(std::move(callbacks)),
        task_runner_(std::move(task_runner)),
        widget_(MakeCrossThreadWeakHandle(widget)) {}

  ReportTimeSwapPromise(const ReportTimeSwapPromise&) = delete;
  ReportTimeSwapPromise& operator=(const ReportTimeSwapPromise&) = delete;

  ~ReportTimeSwapPromise() override = default;

  void DidActivate() override {}

  void WillSwap(viz::CompositorFrameMetadata* metadata) override {
    DCHECK_GT(metadata->frame_token, 0u);
    // The interval between the current swap and its presentation time is
    // reported in UMA (see corresponding code in DidSwap() below).
    frame_token_ = metadata->frame_token;
  }

  void DidSwap() override {
    DCHECK_GT(frame_token_, 0u);
    PostCrossThreadTask(
        *task_runner_, FROM_HERE,
        CrossThreadBindOnce(&RunCallbackAfterSwap,
                            MakeUnwrappingCrossThreadWeakHandle(widget_),
                            base::TimeTicks::Now(),
                            std::move(promise_callbacks_), frame_token_));
  }

  DidNotSwapAction DidNotSwap(DidNotSwapReason reason,
                              base::TimeTicks timestamp) override {
    if (reason != DidNotSwapReason::SWAP_FAILS &&
        reason != DidNotSwapReason::COMMIT_NO_UPDATE) {
      return DidNotSwapAction::KEEP_ACTIVE;
    }

    DidNotSwapAction action = DidNotSwapAction::BREAK_PROMISE;
    WebFrameWidgetImpl::PromiseCallbacks promise_callbacks_on_failure = {
        .swap_time_callback = std::move(promise_callbacks_.swap_time_callback),
        .presentation_time_callback =
            std::move(promise_callbacks_.presentation_time_callback)};

#if BUILDFLAG(IS_APPLE)
    if (reason == DidNotSwapReason::COMMIT_FAILS &&
        promise_callbacks_.core_animation_error_code_callback) {
      action = DidNotSwapAction::KEEP_ACTIVE;
    } else {
      promise_callbacks_on_failure.core_animation_error_code_callback =
          std::move(promise_callbacks_.core_animation_error_code_callback);
    }
#endif

    if (!promise_callbacks_on_failure.IsEmpty()) {
      ReportSwapAndPresentationFailureOnTaskRunner(
          task_runner_, std::move(promise_callbacks_on_failure), timestamp);
    }
    return action;
  }

  int64_t GetTraceId() const override { return 0; }

 private:
  static void RunCallbackAfterSwap(
      WebFrameWidgetImpl* widget,
      base::TimeTicks swap_time,
      WebFrameWidgetImpl::PromiseCallbacks callbacks,
      int frame_token) {
    // If the widget was collected or the widget wasn't collected yet, but
    // it was closed don't schedule a presentation callback.
    if (widget && widget->widget_base_) {
      widget->widget_base_->AddPresentationCallback(
          frame_token,
          WTF::BindOnce(&RunCallbackAfterPresentation,
                        std::move(callbacks.presentation_time_callback),
                        swap_time));
      ReportTime(std::move(callbacks.swap_time_callback), swap_time);

#if BUILDFLAG(IS_APPLE)
      if (callbacks.core_animation_error_code_callback) {
        widget->widget_base_->AddCoreAnimationErrorCodeCallback(
            frame_token,
            std::move(callbacks.core_animation_error_code_callback));
      }
#endif
    } else {
      ReportTime(std::move(callbacks.swap_time_callback), swap_time);
      ReportPresentationTime(std::move(callbacks.presentation_time_callback),
                             swap_time);
#if BUILDFLAG(IS_APPLE)
      ReportErrorCode(std::move(callbacks.core_animation_error_code_callback),
                      gfx::kCALayerUnknownNoWidget);
#endif
    }
  }

  static void RunCallbackAfterPresentation(
      base::OnceCallback<void(const viz::FrameTimingDetails&)>
          presentation_callback,
      base::TimeTicks swap_time,
      const viz::FrameTimingDetails& frame_timing_details) {
    DCHECK(!swap_time.is_null());

    base::TimeTicks presentation_time =
        frame_timing_details.presentation_feedback.timestamp;
    bool presentation_time_is_valid =
        !presentation_time.is_null() && (presentation_time > swap_time);
    if (presentation_time_is_valid) {
      ReportPresentationTime(std::move(presentation_callback),
                             frame_timing_details);
    } else {
      viz::FrameTimingDetails frame_timing_details_with_swap_time =
          frame_timing_details;
      frame_timing_details_with_swap_time.presentation_feedback.timestamp =
          swap_time;
      ReportPresentationTime(std::move(presentation_callback),
                             frame_timing_details_with_swap_time);
    }
  }

  static void ReportTime(base::OnceCallback<void(base::TimeTicks)> callback,
                         base::TimeTicks time) {
    if (callback)
      std::move(callback).Run(time);
  }

  static void ReportPresentationTime(
      base::OnceCallback<void(const viz::FrameTimingDetails&)> callback,
      base::TimeTicks time) {
    viz::FrameTimingDetails frame_timing_details;
    frame_timing_details.presentation_feedback.timestamp = time;
    ReportPresentationTime(std::move(callback), frame_timing_details);
  }

  static void ReportPresentationTime(
      base::OnceCallback<void(const viz::FrameTimingDetails&)> callback,
      const viz::FrameTimingDetails& frame_timing_details) {
    if (callback) {
      std::move(callback).Run(frame_timing_details);
    }
  }

#if BUILDFLAG(IS_APPLE)
  static void ReportErrorCode(
      base::OnceCallback<void(gfx::CALayerResult)> callback,
      gfx::CALayerResult error_code) {
    if (callback)
      std::move(callback).Run(error_code);
  }
#endif

  static void ReportSwapAndPresentationFailureOnTaskRunner(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      WebFrameWidgetImpl::PromiseCallbacks callbacks,
      base::TimeTicks failure_time) {
    if (!task_runner->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *task_runner, FROM_HERE,
          CrossThreadBindOnce(&ReportSwapAndPresentationFailureOnTaskRunner,
                              task_runner, std::move(callbacks), failure_time));
      return;
    }

    ReportTime(std::move(callbacks.swap_time_callback), failure_time);
    ReportPresentationTime(std::move(callbacks.presentation_time_callback),
                           failure_time);
#if BUILDFLAG(IS_APPLE)
    ReportErrorCode(std::move(callbacks.core_animation_error_code_callback),
                    gfx::kCALayerUnknownDidNotSwap);
#endif
  }

  WebFrameWidgetImpl::PromiseCallbacks promise_callbacks_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  CrossThreadWeakHandle<WebFrameWidgetImpl> widget_;
  uint32_t frame_token_ = 0;
};

void WebFrameWidgetImpl::NotifySwapAndPresentationTimeForTesting(
    PromiseCallbacks callbacks) {
  NotifySwapAndPresentationTime(std::move(callbacks));
}

void WebFrameWidgetImpl::NotifyPresentationTimeInBlink(
    base::OnceCallback<void(const viz::FrameTimingDetails&)>
        presentation_callback) {
  NotifySwapAndPresentationTime(
      {.presentation_time_callback = std::move(presentation_callback)});
}

void WebFrameWidgetImpl::NotifyPresentationTime(
    base::OnceCallback<void(const viz::FrameTimingDetails&)>
        presentation_callback) {
  NotifySwapAndPresentationTime(
      {.presentation_time_callback = std::move(presentation_callback)});
}

#if BUILDFLAG(IS_APPLE)
void WebFrameWidgetImpl::NotifyCoreAnimationErrorCode(
    base::OnceCallback<void(gfx::CALayerResult)>
        core_animation_error_code_callback) {
  NotifySwapAndPresentationTime(
      {.core_animation_error_code_callback =
           std::move(core_animation_error_code_callback)});
}
#endif

void WebFrameWidgetImpl::NotifySwapAndPresentationTime(
    PromiseCallbacks callbacks) {
  if (!View()->does_composite())
    return;

  widget_base_->LayerTreeHost()->QueueSwapPromise(
      std::make_unique<ReportTimeSwapPromise>(std::move(callbacks),
                                              widget_base_->LayerTreeHost()
                                                  ->GetTaskRunnerProvider()
                                                  ->MainThreadTaskRunner(),
                                              this));
}

void WebFrameWidgetImpl::WaitForDebuggerWhenShown() {
  local_root_->WaitForDebuggerWhenShown();
}

void WebFrameWidgetImpl::SetTextZoomFactor(float text_zoom_factor) {
  local_root_->GetFrame()->SetTextZoomFactor(text_zoom_factor);
}

float WebFrameWidgetImpl::TextZoomFactor() {
  return local_root_->GetFrame()->TextZoomFactor();
}

void WebFrameWidgetImpl::SetMainFrameOverlayColor(SkColor color) {
  DCHECK(!local_root_->Parent());
  local_root_->GetFrame()->SetMainFrameColorOverlay(color);
}

void WebFrameWidgetImpl::AddEditCommandForNextKeyEvent(const WebString& name,
                                                       const WebString& value) {
  edit_commands_.push_back(mojom::blink::EditCommand::New(name, value));
}

bool WebFrameWidgetImpl::HandleCurrentKeyboardEvent() {
  if (edit_commands_.empty()) {
    return false;
  }
  WebLocalFrame* frame = FocusedWebLocalFrameInWidget();
  if (!frame)
    frame = local_root_;
  bool did_execute_command = false;
  // Executing an edit command can run JS and we can end up reassigning
  // `edit_commands_` so move it to a stack variable before iterating on it.
  Vector<mojom::blink::EditCommandPtr> edit_commands =
      std::move(edit_commands_);
  for (const auto& command : edit_commands) {
    // In gtk and cocoa, it's possible to bind multiple edit commands to one
    // key (but it's the exception). Once one edit command is not executed, it
    // seems safest to not execute the rest.
    if (!frame->ExecuteCommand(command->name, command->value))
      break;
    did_execute_command = true;
  }

  return did_execute_command;
}

void WebFrameWidgetImpl::ClearEditCommands() {
  edit_commands_ = Vector<mojom::blink::EditCommandPtr>();
}

WebTextInputInfo WebFrameWidgetImpl::TextInputInfo() {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return WebTextInputInfo();
  return controller->TextInputInfo();
}

ui::mojom::blink::VirtualKeyboardVisibilityRequest
WebFrameWidgetImpl::GetLastVirtualKeyboardVisibilityRequest() {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return ui::mojom::blink::VirtualKeyboardVisibilityRequest::NONE;
  return controller->GetLastVirtualKeyboardVisibilityRequest();
}

bool WebFrameWidgetImpl::ShouldSuppressKeyboardForFocusedElement() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return false;
  return focused_frame->ShouldSuppressKeyboardForFocusedElement();
}

void WebFrameWidgetImpl::GetEditContextBoundsInWindow(
    std::optional<gfx::Rect>* edit_context_control_bounds,
    std::optional<gfx::Rect>* edit_context_selection_bounds) {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return;
  gfx::Rect control_bounds;
  gfx::Rect selection_bounds;
  controller->GetLayoutBounds(&control_bounds, &selection_bounds);
  *edit_context_control_bounds =
      widget_base_->BlinkSpaceToEnclosedDIPs(control_bounds);
  if (controller->IsEditContextActive()) {
    *edit_context_selection_bounds =
        widget_base_->BlinkSpaceToEnclosedDIPs(selection_bounds);
  }
}

int32_t WebFrameWidgetImpl::ComputeWebTextInputNextPreviousFlags() {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return 0;
  return controller->ComputeWebTextInputNextPreviousFlags();
}

void WebFrameWidgetImpl::ResetVirtualKeyboardVisibilityRequest() {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return;
  controller->SetVirtualKeyboardVisibilityRequest(
      ui::mojom::blink::VirtualKeyboardVisibilityRequest::NONE);
  ;
}

bool WebFrameWidgetImpl::GetSelectionBoundsInWindow(
    gfx::Rect* focus,
    gfx::Rect* anchor,
    gfx::Rect* bounding_box,
    base::i18n::TextDirection* focus_dir,
    base::i18n::TextDirection* anchor_dir,
    bool* is_anchor_first) {
  if (ShouldDispatchImeEventsToPlugin()) {
    // TODO(kinaba) http://crbug.com/101101
    // Current Pepper IME API does not handle selection bounds. So we simply
    // use the caret position as an empty range for now. It will be updated
    // after Pepper API equips features related to surrounding text retrieval.
    gfx::Rect pepper_caret_in_dips = widget_base_->BlinkSpaceToEnclosedDIPs(
        GetFocusedPluginContainer()->GetPluginCaretBounds());
    if (pepper_caret_in_dips == *focus && pepper_caret_in_dips == *anchor)
      return false;
    *focus = pepper_caret_in_dips;
    *anchor = *focus;
    return true;
  }
  gfx::Rect focus_root_frame;
  gfx::Rect anchor_root_frame;
  gfx::Rect bounding_box_root_frame;
  CalculateSelectionBounds(focus_root_frame, anchor_root_frame,
                           &bounding_box_root_frame);
  gfx::Rect focus_rect_in_dips =
      widget_base_->BlinkSpaceToEnclosedDIPs(gfx::Rect(focus_root_frame));
  gfx::Rect anchor_rect_in_dips =
      widget_base_->BlinkSpaceToEnclosedDIPs(gfx::Rect(anchor_root_frame));
  gfx::Rect bounding_box_in_dips = widget_base_->BlinkSpaceToEnclosedDIPs(
      gfx::Rect(bounding_box_root_frame));

  // if the bounds are the same return false.
  if (focus_rect_in_dips == *focus && anchor_rect_in_dips == *anchor)
    return false;
  *focus = focus_rect_in_dips;
  *anchor = anchor_rect_in_dips;
  *bounding_box = bounding_box_in_dips;

  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return true;
  focused_frame->SelectionTextDirection(*focus_dir, *anchor_dir);
  *is_anchor_first = focused_frame->IsSelectionAnchorFirst();
  return true;
}

void WebFrameWidgetImpl::ClearTextInputState() {
  widget_base_->ClearTextInputState();
}

bool WebFrameWidgetImpl::IsPasting() {
  return widget_base_->is_pasting();
}

bool WebFrameWidgetImpl::HandlingSelectRange() {
  return widget_base_->handling_select_range();
}

void WebFrameWidgetImpl::SetFocus(bool focus) {
  widget_base_->SetFocus(
      focus ? mojom::blink::FocusState::kFocused
            : View()->IsActive()
                  ? mojom::blink::FocusState::kNotFocusedAndActive
                  : mojom::blink::FocusState::kNotFocusedAndNotActive);
}

bool WebFrameWidgetImpl::HasFocus() {
  return widget_base_->has_focus();
}

void WebFrameWidgetImpl::UpdateTooltipUnderCursor(const String& tooltip_text,
                                                  TextDirection dir) {
  widget_base_->UpdateTooltipUnderCursor(tooltip_text, dir);
}

void WebFrameWidgetImpl::UpdateTooltipFromKeyboard(const String& tooltip_text,
                                                   TextDirection dir,
                                                   const gfx::Rect& bounds) {
  widget_base_->UpdateTooltipFromKeyboard(tooltip_text, dir, bounds);
}

void WebFrameWidgetImpl::ClearKeyboardTriggeredTooltip() {
  widget_base_->ClearKeyboardTriggeredTooltip();
}

void WebFrameWidgetImpl::InjectScrollbarGestureScroll(
    const gfx::Vector2dF& delta,
    ui::ScrollGranularity granularity,
    cc::ElementId scrollable_area_element_id,
    blink::WebInputEvent::Type injected_type) {
  // create a GestureScroll Event and post it to the compositor thread
  // TODO(crbug.com/1126098) use original input event's timestamp.
  // TODO(crbug.com/1082590) ensure continuity in scroll metrics collection
  base::TimeTicks now = base::TimeTicks::Now();
  std::unique_ptr<WebGestureEvent> gesture_event =
      WebGestureEvent::GenerateInjectedScrollbarGestureScroll(
          injected_type, now, gfx::PointF(0, 0), delta, granularity);
  if (injected_type == WebInputEvent::Type::kGestureScrollBegin) {
    gesture_event->data.scroll_begin.scrollable_area_element_id =
        scrollable_area_element_id.GetInternalValue();
    gesture_event->data.scroll_begin.main_thread_hit_tested_reasons =
        cc::MainThreadScrollingReason::kScrollbarScrolling;
  }

  // Notifies TestWebFrameWidget of the injected event. Does nothing outside
  // of unit tests. This would happen in WidgetBase::QueueSyntheticEvent if
  // scroll unification were not enabled.
  WillQueueSyntheticEvent(
      WebCoalescedInputEvent(*gesture_event, ui::LatencyInfo()));

  widget_base_->widget_input_handler_manager()
      ->DispatchScrollGestureToCompositor(std::move(gesture_event));
}

void WebFrameWidgetImpl::DidChangeCursor(const ui::Cursor& cursor) {
  widget_base_->SetCursor(cursor);
}

bool WebFrameWidgetImpl::SetComposition(
    const String& text,
    const Vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int selection_start,
    int selection_end) {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return false;

  return controller->SetComposition(
      text, ime_text_spans,
      replacement_range.IsValid()
          ? WebRange(base::checked_cast<int>(replacement_range.start()),
                     base::checked_cast<int>(replacement_range.length()))
          : WebRange(),
      selection_start, selection_end);
}

void WebFrameWidgetImpl::CommitText(
    const String& text,
    const Vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int relative_cursor_pos) {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return;
  controller->CommitText(
      text, ime_text_spans,
      replacement_range.IsValid()
          ? WebRange(base::checked_cast<int>(replacement_range.start()),
                     base::checked_cast<int>(replacement_range.length()))
          : WebRange(),
      relative_cursor_pos);
}

void WebFrameWidgetImpl::FinishComposingText(bool keep_selection) {
  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return;
  controller->FinishComposingText(
      keep_selection ? WebInputMethodController::kKeepSelection
                     : WebInputMethodController::kDoNotKeepSelection);
}

bool WebFrameWidgetImpl::IsProvisional() {
  return LocalRoot()->IsProvisional();
}

cc::ElementId WebFrameWidgetImpl::GetScrollableContainerIdAt(
    const gfx::PointF& point) {
  gfx::PointF hit_test_point = point;
  LocalFrameView* view = LocalRootImpl()->GetFrameView();
  hit_test_point.Scale(1 / view->InputEventsScaleFactor());
  return HitTestResultForRootFramePos(hit_test_point).GetScrollableContainer();
}

bool WebFrameWidgetImpl::ShouldHandleImeEvents() {
  if (ForMainFrame()) {
    return HasFocus();
  } else {
    // TODO(ekaramad): main frame widget returns true only if it has focus.
    // We track page focus in all WebViews on the page but the WebFrameWidgets
    // corresponding to child local roots do not get the update. For now, this
    // method returns true when the WebFrameWidget is for a child local frame,
    // i.e., IME events will be processed regardless of page focus. We should
    // revisit this after page focus for OOPIFs has been fully resolved
    // (https://crbug.com/689777).
    return LocalRootImpl();
  }
}

void WebFrameWidgetImpl::SetEditCommandsForNextKeyEvent(
    Vector<mojom::blink::EditCommandPtr> edit_commands) {
  edit_commands_ = std::move(edit_commands);
}

void WebFrameWidgetImpl::FocusChangeComplete() {
  blink::WebLocalFrame* focused = LocalRoot()->View()->FocusedFrame();

  if (focused && focused->AutofillClient())
    focused->AutofillClient()->DidCompleteFocusChangeInFrame();
}

void WebFrameWidgetImpl::ShowVirtualKeyboardOnElementFocus() {
  widget_base_->ShowVirtualKeyboardOnElementFocus();
}

void WebFrameWidgetImpl::ProcessTouchAction(WebTouchAction touch_action) {
  widget_base_->ProcessTouchAction(touch_action);
}

void WebFrameWidgetImpl::SetPanAction(mojom::blink::PanAction pan_action) {
  if (!widget_base_->widget_input_handler_manager())
    return;
  mojom::blink::WidgetInputHandlerHost* host =
      widget_base_->widget_input_handler_manager()->GetWidgetInputHandlerHost();
  if (!host)
    return;
  host->SetPanAction(pan_action);
}

void WebFrameWidgetImpl::DidHandleGestureEvent(const WebGestureEvent& event) {
#if BUILDFLAG(IS_ANDROID) || defined(USE_AURA) || BUILDFLAG(IS_IOS)
  if (event.GetType() == WebInputEvent::Type::kGestureTap) {
    widget_base_->ShowVirtualKeyboard();
  } else if (event.GetType() == WebInputEvent::Type::kGestureLongPress) {
    WebInputMethodController* controller = GetActiveWebInputMethodController();
    if (!controller || controller->TextInputInfo().value.IsEmpty())
      widget_base_->UpdateTextInputState();
    else
      widget_base_->ShowVirtualKeyboard();
  }
#endif
}

void WebFrameWidgetImpl::SetHasPointerRawUpdateEventHandlers(
    bool has_handlers) {
  widget_base_->widget_input_handler_manager()
      ->input_event_queue()
      ->SetHasPointerRawUpdateEventHandlers(has_handlers);
}

void WebFrameWidgetImpl::SetNeedsLowLatencyInput(bool needs_low_latency) {
  widget_base_->widget_input_handler_manager()
      ->input_event_queue()
      ->SetNeedsLowLatency(needs_low_latency);
}

void WebFrameWidgetImpl::RequestUnbufferedInputEvents() {
  widget_base_->widget_input_handler_manager()
      ->input_event_queue()
      ->RequestUnbufferedInputEvents();
}

void WebFrameWidgetImpl::SetNeedsUnbufferedInputForDebugger(bool unbuffered) {
  widget_base_->widget_input_handler_manager()
      ->input_event_queue()
      ->SetNeedsUnbufferedInputForDebugger(unbuffered);
}

void WebFrameWidgetImpl::DidNavigate() {
  // The input handler wants to know about navigation so that it can
  // suppress input until the newly navigated page has a committed frame.
  // It also resets the state for UMA reporting of input arrival with respect
  // to document lifecycle.
  if (!widget_base_->widget_input_handler_manager())
    return;
  widget_base_->widget_input_handler_manager()
      ->InitializeInputEventSuppressionStates();
}

void WebFrameWidgetImpl::FlushInputForTesting(base::OnceClosure done_callback) {
  widget_base_->widget_input_handler_manager()->FlushEventQueuesForTesting(
      std::move(done_callback));
}

void WebFrameWidgetImpl::SetMouseCapture(bool capture) {
  if (mojom::blink::WidgetInputHandlerHost* host =
          widget_base_->widget_input_handler_manager()
              ->GetWidgetInputHandlerHost()) {
    host->SetMouseCapture(capture);
  }
}

void WebFrameWidgetImpl::NotifyAutoscrollForSelectionInMainFrame(
    bool autoscroll_selection) {
  if (mojom::blink::WidgetInputHandlerHost* host =
          widget_base_->widget_input_handler_manager()
              ->GetWidgetInputHandlerHost()) {
    host->SetAutoscrollSelectionActiveInMainFrame(autoscroll_selection);
  }

  if (!autoscroll_selection) {
    LocalFrame* local_root_frame = LocalRootImpl()->GetFrame();
    CHECK(local_root_frame);
    if (LocalDOMWindow* current_window = local_root_frame->DomWindow()) {
      WindowPerformance* window_performance =
          DOMWindowPerformance::performance(*current_window);
      window_performance->ResetAutoscroll();
    }
  }
}

gfx::Range WebFrameWidgetImpl::CompositionRange() {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame || ShouldDispatchImeEventsToPlugin())
    return gfx::Range::InvalidRange();

  blink::WebInputMethodController* controller =
      focused_frame->GetInputMethodController();
  WebRange web_range = controller->CompositionRange();
  if (web_range.IsNull())
    return gfx::Range::InvalidRange();
  return gfx::Range(web_range.StartOffset(), web_range.EndOffset());
}

void WebFrameWidgetImpl::GetCompositionCharacterBoundsInWindow(
    Vector<gfx::Rect>* bounds_in_dips) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame || ShouldDispatchImeEventsToPlugin())
    return;
  blink::WebInputMethodController* controller =
      focused_frame->GetInputMethodController();
  blink::WebVector<gfx::Rect> bounds_from_blink;
  if (!controller->GetCompositionCharacterBounds(bounds_from_blink))
    return;

  for (auto& rect : bounds_from_blink) {
    bounds_in_dips->push_back(widget_base_->BlinkSpaceToEnclosedDIPs(rect));
  }
}

namespace {

void GetLineBounds(Vector<gfx::QuadF>& line_quads,
                   TextControlInnerEditorElement* inner_editor) {
  for (const Node& node : NodeTraversal::DescendantsOf(*inner_editor)) {
    if (!node.GetLayoutObject() || !node.GetLayoutObject()->IsText()) {
      continue;
    }
    node.GetLayoutObject()->AbsoluteQuads(line_quads,
                                          kApplyRemoteMainFrameTransform);
  }
}

}  // namespace

Vector<gfx::Rect> WebFrameWidgetImpl::CalculateVisibleLineBoundsOnScreen() {
  Vector<gfx::Rect> bounds_in_dips;
  Element* focused_element = FocusedElement();
  if (!focused_element) {
    return bounds_in_dips;
  }
  TextControlElement* text_control = ToTextControlOrNull(focused_element);
  if (!text_control || text_control->IsDisabledOrReadOnly() ||
      text_control->Value().empty() || !text_control->GetLayoutObject()) {
    return bounds_in_dips;
  }

  Vector<gfx::QuadF> bounds_from_blink;
  GetLineBounds(bounds_from_blink, text_control->InnerEditorElement());

  gfx::Rect screen = LocalRootImpl()->GetFrameView()->FrameToScreen(
      GetPage()->GetVisualViewport().VisibleContentRect());
  for (auto& quad : bounds_from_blink) {
    gfx::Rect bounding_box =
        focused_element->GetLayoutObject()->GetFrameView()->FrameToScreen(
            gfx::ToRoundedRect(quad.BoundingBox()));
    bounding_box.Intersect(screen);
    if (bounding_box.IsEmpty()) {
      continue;
    }
    bounds_in_dips.push_back(bounding_box);
  }
  return bounds_in_dips;
}

Vector<gfx::Rect>& WebFrameWidgetImpl::GetVisibleLineBoundsOnScreen() {
  return input_visible_line_bounds_;
}

void WebFrameWidgetImpl::UpdateLineBounds() {
  Vector<gfx::Rect> line_bounds = CalculateVisibleLineBoundsOnScreen();
  if (line_bounds == input_visible_line_bounds_) {
    return;
  }
  input_visible_line_bounds_.swap(line_bounds);
  if (RuntimeEnabledFeatures::CursorAnchorInfoMojoPipeEnabled()) {
    UpdateCursorAnchorInfo();
    return;
  }
  if (mojom::blink::WidgetInputHandlerHost* host =
          widget_base_->widget_input_handler_manager()
              ->GetWidgetInputHandlerHost()) {
    host->ImeCompositionRangeChanged(gfx::Range::InvalidRange(), std::nullopt,
                                     input_visible_line_bounds_);
  }
}

void WebFrameWidgetImpl::UpdateCursorAnchorInfo() {
#if BUILDFLAG(IS_ANDROID)
  Element* focused_element = FocusedElement();
  if (!focused_element) {
    return;
  }
  TextControlElement* text_control = ToTextControlOrNull(focused_element);
  if (!text_control || text_control->IsDisabledOrReadOnly() ||
      !text_control->GetLayoutObject()) {
    return;
  }

  Vector<gfx::Rect> character_bounds;
  GetCompositionCharacterBoundsInWindow(&character_bounds);

  gfx::RectF editor_bounds =
      gfx::RectF(LocalRootImpl()->GetFrameView()->FrameToScreen(
          focused_element->VisibleBoundsInLocalRoot()));
  float device_scale_factor = widget_base_->GetScreenInfo().device_scale_factor;
  gfx::RectF handwriting_bounds(editor_bounds);
  // See kStylusWritableAdjustmentSizeDip in
  // third_party/blink/renderer/core/input/pointer_event_manager.cc
  handwriting_bounds.Outset(30 / device_scale_factor);
  mojom::blink::EditorBoundsInfoPtr editor_bounds_info =
      mojom::blink::EditorBoundsInfo::New(editor_bounds, handwriting_bounds);

  mojom::blink::TextAppearanceInfoPtr text_appearance_info =
      mojom::blink::TextAppearanceInfo::New(
          text_control->GetLayoutObject()
              ->StyleRef()
              .VisitedDependentColor(GetCSSPropertyColor())
              .Rgb());

  mojom::blink::InputCursorAnchorInfoPtr cursor_anchor_info =
      mojom::blink::InputCursorAnchorInfo::New(
          character_bounds, std::move(editor_bounds_info),
          std::move(text_appearance_info), input_visible_line_bounds_);
  // Since the IME pushes this endpoint to the renderer, it may not be bound
  // yet.
  if (ime_render_widget_host_) {
    ime_render_widget_host_->UpdateCursorAnchorInfo(
        std::move(cursor_anchor_info));
  }
#endif  // BUILDFLAG(IS_ANDROID)
}

void WebFrameWidgetImpl::AddImeTextSpansToExistingText(
    uint32_t start,
    uint32_t end,
    const Vector<ui::ImeTextSpan>& ime_text_spans) {
  WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return;
  focused_frame->AddImeTextSpansToExistingText(ime_text_spans, start, end);
}

Vector<ui::mojom::blink::ImeTextSpanInfoPtr>
WebFrameWidgetImpl::GetImeTextSpansInfo(
    const WebVector<ui::ImeTextSpan>& ime_text_spans) {
  auto* focused_frame = FocusedWebLocalFrameInWidget();
  if (!focused_frame)
    return Vector<ui::mojom::blink::ImeTextSpanInfoPtr>();

  Vector<ui::mojom::blink::ImeTextSpanInfoPtr> ime_text_spans_info;

  for (const auto& ime_text_span : ime_text_spans) {
    gfx::Rect rect;
    auto length = base::checked_cast<wtf_size_t>(ime_text_span.end_offset -
                                                 ime_text_span.start_offset);
    focused_frame->FirstRectForCharacterRange(
        base::checked_cast<wtf_size_t>(ime_text_span.start_offset), length,
        rect);

    ime_text_spans_info.push_back(ui::mojo
```