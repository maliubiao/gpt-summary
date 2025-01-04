Response:
My goal is to summarize the functionality of the provided C++ code snippet from the Chromium Blink engine and identify its relationships with web technologies like JavaScript, HTML, and CSS. I also need to address potential user or programming errors and provide examples for each.

Here's a breakdown of the thinking process to achieve this:

1. **Understand the Context:** The code is part of `WebFrameWidgetImpl.cc`, located in the `blink/renderer/core/frame` directory. This suggests it deals with the rendering and management of web frames within the Blink engine. The "Impl" suffix often indicates an implementation class for a public interface (likely `WebFrameWidget`). The fact that this is "part 4 of 7" implies a larger file segmented for readability or organization.

2. **Identify Key Responsibilities by Analyzing Function Names:** I'll go through each function in the snippet and infer its purpose based on its name. Keywords like `ScrollIntoView`, `ResetMeaningfulLayoutState`, `InitializeCompositing`, `Resize`, `BeginMainFrame`, `HandleInputEvent`, `SetCursor`, `UpdateTextInputState`, `ApplyViewportChanges`, etc., provide strong clues.

3. **Group Related Functions:**  I'll group functions with similar functionalities together. For example, functions related to compositing (`InitializeCompositing`, `SetCompositorVisible`, `WarmUpCompositor`), input handling (`HandleInputEvent`, `WillHandleMouseEvent`, `WillHandleGestureEvent`), lifecycle management (`BeginMainFrame`, `BeginCommitCompositorFrame`, `EndCommitCompositorFrame`), and viewport/size management (`Resize`, `ApplyViewportChanges`, `SetScreenRects`).

4. **Establish Relationships with Web Technologies:**
    * **JavaScript:** Look for functions that trigger or respond to JavaScript events or actions. Input event handling is a prime example, as JavaScript event listeners react to these. Also, consider how the rendering process interacts with JavaScript's manipulation of the DOM and CSSOM. Animation and layout are areas where JavaScript and the rendering engine closely interact.
    * **HTML:**  Consider how the code handles the structure and elements of an HTML document. Functions dealing with scrolling, focus, and input directly relate to HTML elements. The `edit_context` mentioned in `ScrollIntoViewForFocusedEditableElement` strongly suggests interaction with editable HTML elements.
    * **CSS:** Look for functions that handle styling and layout. Viewport changes, resizing, and compositing are influenced by CSS. The mention of `touch-action` relates to CSS properties. The `display_mode_`, `window_show_state_`, and `resizable_` properties and their impact on media queries are direct connections to CSS media features.

5. **Identify Logic and Assumptions:**  For functions with conditional logic (like the `if` statements in `ScrollIntoViewForFocusedEditableElement`), try to understand the conditions and their implications. What are the assumptions being made about the input data (e.g., the presence of an `edit_context` or a `LayoutObject`)?  What are the expected outcomes under different scenarios?  This leads to creating "hypothetical input and output" examples.

6. **Pinpoint Potential Errors:**  Think about scenarios where things could go wrong. Common issues include null pointers, incorrect function arguments, unexpected state, and race conditions. Look for `DCHECK` statements, which indicate internal assertions, and consider what conditions would violate these assertions. The comment about `View()->MainFrameImpl()` being potentially null highlights a specific bug-hunting scenario and a potential error. The handling of provisional frames in `HandleInputEvent` also suggests a scenario where incorrect state could lead to issues.

7. **Synthesize the Summary:** Combine the identified functionalities and relationships into a concise summary. Focus on the major responsibilities of the code within the context of web frame management and rendering.

8. **Review and Refine:** Read through the analysis and the summary to ensure clarity, accuracy, and completeness. Are there any redundancies?  Is the language precise?  Are the examples helpful and easy to understand?  For example, I initially focused heavily on individual function descriptions but realized a higher-level functional grouping would be more effective for the summary.

**(Self-Correction Example during the process):**  Initially, I might have missed the connection between `SetDisplayMode`, `SetWindowShowState`, and `SetResizable` with CSS. Upon closer inspection, the code explicitly mentions `MediaQueryAffectingValueChangedForLocalSubtree`, which directly links these methods to CSS media queries and responsive design. This requires going back and adding this connection to the "Relationships with Web Technologies" section. Similarly, the `TouchAction` calculation in `ScrollIntoViewForFocusedEditableElement` is a direct link to CSS touch interaction properties.
这是 `blink/renderer/core/frame/web_frame_widget_impl.cc` 文件的第 4 部分，它主要负责实现 `WebFrameWidgetImpl` 类的一些核心功能。从这段代码来看，它涵盖了以下几个关键方面：

**核心功能归纳：**

1. **处理滚动和焦点相关的操作：** 包括将元素滚动到可见区域，特别是处理可编辑元素的焦点情况。
2. **管理渲染流程的初始状态：**  重置主框架的一些关键布局状态，以便在渲染流程的早期阶段正确触发事件。
3. **初始化和管理合成 (Compositing)：**  负责初始化渲染合成，包括从之前的 Widget 继承合成状态。区分合成和非合成的渲染方式。
4. **管理 Widget 的尺寸和生命周期：**  包括调整 Widget 的大小，处理提交请求等。
5. **驱动主帧的渲染和动画：**  处理主帧的开始渲染、提交合成器帧等核心渲染流程。
6. **处理视口 (Viewport) 变化：**  响应并应用视口的变化。
7. **记录用户交互类型：**  统计不同类型的用户交互方式（如鼠标滚轮、触摸等）。
8. **处理输入事件：**  接收并分发各种输入事件，包括鼠标事件和手势事件。
9. **管理文本输入状态：**  更新和获取文本输入状态，控制虚拟键盘的显示。
10. **处理鼠标锁定：**  响应鼠标锁定的请求。
11. **应用视觉属性：**  接收并应用视觉相关的属性。
12. **管理屏幕和表面信息：**  更新和获取屏幕信息、表面 ID 等渲染相关信息。
13. **管理窗口和视口矩形：**  设置和获取 Widget 和窗口的矩形信息。
14. **处理子框架的固有尺寸信息：**  接收并传递子框架的尺寸信息。
15. **处理自动滚动：**  启动、停止和执行自动滚动操作。
16. **处理有意义的布局事件：**  在关键布局阶段触发回调，例如首次可视非空布局。
17. **请求动画帧：**  在延迟后请求动画帧。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **JavaScript:**
   * **滚动到可见区域:**  JavaScript 可以调用 `element.scrollIntoView()` 方法，`ScrollIntoViewForFocusedEditableElement` 方法的功能与此类似，确保元素在用户操作（例如聚焦输入框）后可见。
     * **假设输入:** 用户点击了一个文本输入框，该输入框位于当前视口之外。
     * **输出:** `ScrollIntoViewForFocusedEditableElement` 计算出需要滚动的距离和位置，最终将输入框滚动到视口内。
   * **输入事件处理:** `HandleInputEvent` 接收的事件最终会触发 JavaScript 事件监听器。例如，鼠标点击事件会触发 `onclick` 事件，键盘事件会触发 `onkeypress` 等。
     * **假设输入:** 用户在页面上点击了一个按钮。
     * **输出:** `HandleInputEvent` 接收到 `kMouseDown` 和 `kMouseUp` 事件，Blink 内部处理后，会触发该按钮上绑定的 JavaScript `onclick` 事件。
   * **动画帧请求:** `RequestAnimationAfterDelay` 类似于 JavaScript 的 `setTimeout` 或 `requestAnimationFrame`，用于安排在未来执行动画或更新。

2. **HTML:**
   * **焦点处理:** `ScrollIntoViewForFocusedEditableElement` 专门处理具有焦点的可编辑元素（例如 `<input>`, `<textarea>`）。
   * **触摸动作 (touch-action):** 代码中使用了 `touch_action_util::ComputeEffectiveTouchAction(*element)`，这与 CSS 的 `touch-action` 属性有关。`touch-action` 控制元素如何响应触摸输入，例如是否允许双指缩放。
     * **举例:** 如果一个包含文本框的 `div` 元素设置了 `touch-action: none;`，则 `params->for_focused_editable->can_zoom` 将为 false，即使文本框本身允许缩放，也会因为父容器的限制而阻止缩放。
   * **输入类型 (TextInputType):** `GetTextInputType` 方法会根据当前焦点元素的类型（例如 `text`, `password`, `email`）返回不同的 `WebTextInputType`，这对应于 HTML 输入元素的 `type` 属性。

3. **CSS:**
   * **视口 (Viewport) 管理:** `ApplyViewportChanges` 方法处理视口的变化，这与 HTML 的 `<meta name="viewport">` 标签和 CSS 的 `@viewport` 规则有关。
   * **媒体查询 (Media Queries):** `SetDisplayMode`, `SetWindowShowState`, `SetResizable` 等方法会影响媒体查询的评估。例如，当窗口被最大化时，`SetWindowShowState` 会被调用，这可能会改变匹配的 CSS 媒体查询，从而改变页面的样式。
   * **光标 (Cursor):** `SetCursor` 方法用于设置鼠标光标的样式，对应于 CSS 的 `cursor` 属性。
   * **缩放 (Zoom):**  `ScrollIntoViewForFocusedEditableElement` 中会考虑是否允许缩放，这与 CSS 的 `zoom` 属性或浏览器的缩放功能有关。

**逻辑推理及假设输入与输出：**

* **`ScrollIntoViewForFocusedEditableElement` 函数的逻辑：**
    * **假设输入:** 一个 HTML 页面中有一个被用户聚焦的 `<textarea>` 元素，该元素部分或完全不在当前视口内。
    * **逻辑推理:**
        1. 获取该 `<textarea>` 元素的布局信息（位置和大小）。
        2. 获取当前光标的位置信息。
        3. 计算需要滚动的偏移量，以便将光标所在的位置滚动到可见区域。
        4. 考虑父元素的 `touch-action` 属性，判断是否允许用户进行缩放操作。
        5. 调用 `scroll_into_view_util::ScrollRectToVisible` 执行滚动操作。
    * **输出:** 页面滚动，使得 `<textarea>` 元素（特别是光标位置）出现在用户的视口内。

**用户或编程常见的使用错误举例说明：**

1. **在非主线程调用合成相关的初始化方法:** 代码中有 `DCHECK(!non_composited_client_); // Assure only one initialize is called.`，这意味着 `InitializeCompositingInternal` 或 `InitializeNonCompositing` 只能被调用一次。如果在错误的线程或多次调用，会导致程序崩溃。
   * **错误示例:**  在异步回调中尝试再次初始化 Compositing。

2. **在 Widget 销毁后尝试访问其成员:**  代码中多处使用了 `LocalRootImpl()`，如果 Widget 已经被销毁，访问 `local_root_` 可能会导致空指针解引用。
   * **错误示例:** 在一个定时器回调中，访问一个可能已经销毁的 `WebFrameWidgetImpl` 的 `LocalRootImpl()`。

3. **不匹配的 `BeginMainFrame` 和 `EndMainFrame` 逻辑:** 虽然这段代码没有直接展示 `EndMainFrame`，但作为渲染流程的一部分，必须保证 `BeginMainFrame` 和相应的 `EndMainFrame` 调用匹配，否则可能导致渲染状态不一致。

4. **错误地假设输入事件总是被处理:**  `HandleInputEvent` 方法返回 `WebInputEventResult`，表示事件是否被处理。调用者不应该假设所有事件都会被内部处理，需要根据返回值进行后续操作。

**这段代码的功能总结:**

总而言之，`WebFrameWidgetImpl.cc` 的第 4 部分主要负责 **管理 Web 框架 (Frame) 的渲染、布局、用户交互以及与浏览器 Compositor 的通信**。它处理了诸如滚动、焦点、视口变化、输入事件和合成等关键功能，是 Blink 引擎中连接渲染引擎和浏览器进程的重要组成部分。它通过处理各种事件和状态变化，确保网页能够正确地呈现并响应用户的操作。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
havior::kInstant);
  params->for_focused_editable = mojom::blink::FocusedEditableParams::New();

  // When deciding whether to zoom in on a focused text box, we should
  // decide not to zoom in if the user won't be able to zoom out. e.g if the
  // textbox is within a touch-action: none container the user can't zoom
  // back out.
  TouchAction action = touch_action_util::ComputeEffectiveTouchAction(*element);
  params->for_focused_editable->can_zoom =
      static_cast<int>(action) & static_cast<int>(TouchAction::kPinchZoom);

  PhysicalRect absolute_element_bounds;
  PhysicalRect absolute_caret_bounds;

  if (edit_context) {
    gfx::Rect control_bounds_in_physical_pixels;
    gfx::Rect selection_bounds_in_physical_pixels;
    edit_context->GetLayoutBounds(&control_bounds_in_physical_pixels,
                                  &selection_bounds_in_physical_pixels);

    absolute_element_bounds = PhysicalRect(control_bounds_in_physical_pixels);
    absolute_caret_bounds = PhysicalRect(selection_bounds_in_physical_pixels);
  } else {
    absolute_element_bounds =
        PhysicalRect(element->GetLayoutObject()->AbsoluteBoundingBoxRect());
    absolute_caret_bounds = PhysicalRect(
        element->GetDocument().GetFrame()->Selection().ComputeRectToScroll(
            kRevealExtent));
  }

  gfx::Vector2dF editable_offset_from_caret(absolute_element_bounds.offset -
                                            absolute_caret_bounds.offset);
  gfx::SizeF editable_size(absolute_element_bounds.size);

  if (editable_size.IsEmpty()) {
    return false;
  }

  params->for_focused_editable->relative_location = editable_offset_from_caret;
  params->for_focused_editable->size = editable_size;

  scroll_into_view_util::ScrollRectToVisible(
      *element->GetLayoutObject(), absolute_caret_bounds, std::move(params));

  return true;
}

void WebFrameWidgetImpl::ResetMeaningfulLayoutStateForMainFrame() {
  MainFrameData& data = main_data();
  data.should_dispatch_first_visually_non_empty_layout = true;
  data.should_dispatch_first_layout_after_finished_parsing = true;
  data.should_dispatch_first_layout_after_finished_loading = true;
  data.last_background_color.reset();
}

void WebFrameWidgetImpl::InitializeCompositing(
    const display::ScreenInfos& screen_infos,
    const cc::LayerTreeSettings* settings) {
  InitializeCompositingInternal(screen_infos, settings, nullptr);
}

void WebFrameWidgetImpl::InitializeCompositingFromPreviousWidget(
    const display::ScreenInfos& screen_infos,
    const cc::LayerTreeSettings* settings,
    WebFrameWidget& previous_widget) {
  InitializeCompositingInternal(screen_infos, settings, &previous_widget);
}

void WebFrameWidgetImpl::InitializeCompositingInternal(
    const display::ScreenInfos& screen_infos,
    const cc::LayerTreeSettings* settings,
    WebFrameWidget* previous_widget) {
  DCHECK(View()->does_composite());
  DCHECK(!non_composited_client_);  // Assure only one initialize is called.
  widget_base_->InitializeCompositing(
      *GetPage()->GetPageScheduler(), screen_infos, settings,
      input_handler_weak_ptr_factory_.GetWeakPtr(),
      previous_widget ? static_cast<WebFrameWidgetImpl*>(previous_widget)
                            ->widget_base_.get()
                      : nullptr);

  probe::DidInitializeFrameWidget(local_root_->GetFrame());
  local_root_->GetFrame()->NotifyFrameWidgetCreated();

  // TODO(bokan): This seems wrong. Page may host multiple FrameWidgets so this
  // will call DidInitializeCompositing once per FrameWidget. It probably makes
  // sense to move LinkHighlight from Page to WidgetBase so initialization is
  // per-widget. See also: https://crbug.com/1344531.
  GetPage()->DidInitializeCompositing(*AnimationHost());
}

void WebFrameWidgetImpl::InitializeNonCompositing(
    WebNonCompositedWidgetClient* client) {
  DCHECK(!non_composited_client_);
  DCHECK(client);
  DCHECK(!View()->does_composite());
  widget_base_->InitializeNonCompositing();
  non_composited_client_ = client;
}

void WebFrameWidgetImpl::SetCompositorVisible(bool visible) {
  widget_base_->SetCompositorVisible(visible);
}

void WebFrameWidgetImpl::WarmUpCompositor() {
  // TODO(crbug.com/41496019): See if `widget_base_` is unexpectedly null in
  // this code path.
  CHECK(widget_base_);
  widget_base_->WarmUpCompositor();
}

gfx::Size WebFrameWidgetImpl::Size() {
  return size_.value_or(gfx::Size());
}

void WebFrameWidgetImpl::Resize(const gfx::Size& new_size) {
  if (size_ && *size_ == new_size)
    return;

  if (ForMainFrame()) {
    size_ = new_size;
    View()->Resize(new_size);
    return;
  }

  if (child_data().did_suspend_parsing) {
    child_data().did_suspend_parsing = false;
    LocalRootImpl()->GetFrame()->Loader().GetDocumentLoader()->ResumeParser();
  }

  LocalFrameView* view = LocalRootImpl()->GetFrameView();
  DCHECK(view);

  size_ = new_size;

  view->SetLayoutSize(*size_);
  view->Resize(*size_);
}

void WebFrameWidgetImpl::OnCommitRequested() {
  // This can be called during shutdown, in which case local_root_ will be
  // nullptr.
  if (!LocalRootImpl() || !LocalRootImpl()->GetFrame()) {
    return;
  }
  if (auto* view = LocalRootImpl()->GetFrame()->View())
    view->OnCommitRequested();
}

void WebFrameWidgetImpl::BeginMainFrame(base::TimeTicks last_frame_time) {
  TRACE_EVENT1("blink", "WebFrameWidgetImpl::BeginMainFrame", "frameTime",
               last_frame_time);
  DCHECK(!last_frame_time.is_null());
  CHECK(LocalRootImpl());

  if (animation_frame_timing_monitor_) {
    animation_frame_timing_monitor_->BeginMainFrame(
        *LocalRootImpl()->GetFrame()->DomWindow());
  }

  // Dirty bit on MouseEventManager is not cleared in OOPIFs after scroll
  // or layout changes. Ensure the hover state is recomputed if necessary.
  LocalRootImpl()
      ->GetFrame()
      ->GetEventHandler()
      .RecomputeMouseHoverStateIfNeeded();

  std::optional<LocalFrameUkmAggregator::ScopedUkmHierarchicalTimer> ukm_timer;
  if (WidgetBase::ShouldRecordBeginMainFrameMetrics()) {
    ukm_timer.emplace(
        LocalRootImpl()->GetFrame()->View()->GetUkmAggregator()->GetScopedTimer(
            LocalFrameUkmAggregator::kAnimate));
  }

  GetPage()->Animate(last_frame_time);
  // Animate can cause the local frame to detach.
  if (!LocalRootImpl())
    return;

  GetPage()->GetValidationMessageClient().LayoutOverlay();
}

void WebFrameWidgetImpl::BeginCommitCompositorFrame() {
  if (commit_compositor_frame_start_time_.has_value()) {
    next_commit_compositor_frame_start_time_.emplace(base::TimeTicks::Now());
  } else {
    commit_compositor_frame_start_time_.emplace(base::TimeTicks::Now());
  }
  GetPage()->GetChromeClient().WillCommitCompositorFrame();
  probe::LayerTreePainted(LocalRootImpl()->GetFrame());
  if (ForTopMostMainFrame()) {
    Document* doc = local_root_->GetFrame()->GetDocument();
    bool tap_delay_enabled = doc->GetSettings()->GetViewportMetaEnabled() &&
                             !LayerTreeHost()->IsMobileOptimized();
    if (tap_delay_enabled) {
      UseCounter::Count(doc, WebFeature::kTapDelayEnabled);
    }
    TRACE_EVENT_INSTANT2(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "BeginCommitCompositorFrame", TRACE_EVENT_SCOPE_THREAD,
                         "frame",
                         local_root_->GetFrame()->GetFrameIdForTracing(),
                         "is_mobile_optimized", !tap_delay_enabled);
  }
  if (ForMainFrame()) {
    View()->DidCommitCompositorFrameForLocalMainFrame();
    View()->UpdatePreferredSize();
    if (!View()->MainFrameImpl()) {
      // Trying to track down why the view's idea of the main frame varies
      // from LocalRootImpl's.
      // TODO(https://crbug.com/1139104): Remove this.
      std::string reason = View()->GetNullFrameReasonForBug1139104();
      DCHECK(false) << reason;
      SCOPED_CRASH_KEY_STRING32("Crbug1139104", "NullFrameReason", reason);
      base::debug::DumpWithoutCrashing();
    }
  }
}

void WebFrameWidgetImpl::EndCommitCompositorFrame(
    base::TimeTicks commit_start_time,
    base::TimeTicks commit_finish_time) {
  DCHECK(commit_compositor_frame_start_time_.has_value());
  LocalRootImpl()
      ->GetFrame()
      ->View()
      ->GetUkmAggregator()
      ->RecordImplCompositorSample(commit_compositor_frame_start_time_.value(),
                                   commit_start_time, commit_finish_time);
  WindowPerformance* performance = DOMWindowPerformance::performance(
      *LocalRootImpl()->GetFrame()->DomWindow());
  performance->SetCommitFinishTimeStampForPendingEvents(commit_finish_time);

  commit_compositor_frame_start_time_ =
      next_commit_compositor_frame_start_time_;
  next_commit_compositor_frame_start_time_.reset();
}

void WebFrameWidgetImpl::ApplyViewportChanges(
    const ApplyViewportChangesArgs& args) {
  // Viewport changes only change the outermost main frame.
  if (!LocalRootImpl()->GetFrame()->IsOutermostMainFrame())
    return;

  WebViewImpl* web_view = View();
  // TODO(https://crbug.com/1160652): Figure out if View is null.
  CHECK(widget_base_);
  CHECK(web_view);
  web_view->ApplyViewportChanges(args);
}

void WebFrameWidgetImpl::RecordManipulationTypeCounts(
    cc::ManipulationInfo info) {
  // Manipulation counts are only recorded for the main frame.
  if (!ForMainFrame())
    return;

  if ((info & cc::kManipulationInfoWheel) == cc::kManipulationInfoWheel) {
    UseCounter::Count(LocalRootImpl()->GetDocument(),
                      WebFeature::kScrollByWheel);
  }
  if ((info & cc::kManipulationInfoTouch) == cc::kManipulationInfoTouch) {
    UseCounter::Count(LocalRootImpl()->GetDocument(),
                      WebFeature::kScrollByTouch);
  }
  if ((info & cc::kManipulationInfoPinchZoom) ==
      cc::kManipulationInfoPinchZoom) {
    UseCounter::Count(LocalRootImpl()->GetDocument(), WebFeature::kPinchZoom);
  }
  if ((info & cc::kManipulationInfoPrecisionTouchPad) ==
      cc::kManipulationInfoPrecisionTouchPad) {
    UseCounter::Count(LocalRootImpl()->GetDocument(),
                      WebFeature::kScrollByPrecisionTouchPad);
  }
}

void WebFrameWidgetImpl::RecordDispatchRafAlignedInputTime(
    base::TimeTicks raf_aligned_input_start_time) {
  if (LocalRootImpl()) {
    LocalRootImpl()->GetFrame()->View()->GetUkmAggregator()->RecordTimerSample(
        LocalFrameUkmAggregator::kHandleInputEvents,
        raf_aligned_input_start_time, base::TimeTicks::Now());
  }
}

void WebFrameWidgetImpl::SetSuppressFrameRequestsWorkaroundFor704763Only(
    bool suppress_frame_requests) {
  GetPage()->Animator().SetSuppressFrameRequestsWorkaroundFor704763Only(
      suppress_frame_requests);
}

void WebFrameWidgetImpl::CountDroppedPointerDownForEventTiming(unsigned count) {
  if (!local_root_ || !(local_root_->GetFrame()) ||
      !(local_root_->GetFrame()->DomWindow())) {
    return;
  }
  WindowPerformance* performance = DOMWindowPerformance::performance(
      *(local_root_->GetFrame()->DomWindow()));

  performance->eventCounts()->AddMultipleEvents(event_type_names::kPointerdown,
                                                count);
  // We only count dropped touchstart that can trigger pointerdown.
  performance->eventCounts()->AddMultipleEvents(event_type_names::kTouchstart,
                                                count);
  // TouchEnd will not be dropped. But in touch event model only touch starts
  // can set the target and after that the touch event always goes to that
  // target. So if a touchstart has been dropped, the following touchend will
  // not be dispatched. Meanwhile, the pointerup can be captured in the
  // pointer_event_manager.
  performance->eventCounts()->AddMultipleEvents(event_type_names::kTouchend,
                                                count);
}

std::unique_ptr<cc::BeginMainFrameMetrics>
WebFrameWidgetImpl::GetBeginMainFrameMetrics() {
  if (!LocalRootImpl())
    return nullptr;

  return LocalRootImpl()
      ->GetFrame()
      ->View()
      ->GetUkmAggregator()
      ->GetBeginMainFrameMetrics();
}


void WebFrameWidgetImpl::BeginUpdateLayers() {
  if (LocalRootImpl())
    update_layers_start_time_.emplace(base::TimeTicks::Now());
}

void WebFrameWidgetImpl::EndUpdateLayers() {
  if (LocalRootImpl()) {
    DCHECK(update_layers_start_time_);
    LocalRootImpl()->GetFrame()->View()->GetUkmAggregator()->RecordTimerSample(
        LocalFrameUkmAggregator::kUpdateLayers,
        update_layers_start_time_.value(), base::TimeTicks::Now());
    probe::LayerTreeDidChange(LocalRootImpl()->GetFrame());
  }
  update_layers_start_time_.reset();
}

void WebFrameWidgetImpl::RecordStartOfFrameMetrics() {
  if (!LocalRootImpl())
    return;

  LocalRootImpl()->GetFrame()->View()->GetUkmAggregator()->BeginMainFrame();
}

void WebFrameWidgetImpl::RecordEndOfFrameMetrics(
    base::TimeTicks frame_begin_time,
    cc::ActiveFrameSequenceTrackers trackers) {
  if (!LocalRootImpl())
    return;
  Document* document = LocalRootImpl()->GetFrame()->GetDocument();
  DCHECK(document);
  LocalRootImpl()
      ->GetFrame()
      ->View()
      ->GetUkmAggregator()
      ->RecordEndOfFrameMetrics(frame_begin_time, base::TimeTicks::Now(),
                                trackers, document->UkmSourceID(),
                                document->UkmRecorder());
}

void WebFrameWidgetImpl::WillHandleGestureEvent(const WebGestureEvent& event,
                                                bool* suppress) {
  possible_drag_event_info_.source = ui::mojom::blink::DragEventSource::kTouch;
  possible_drag_event_info_.location =
      gfx::ToFlooredPoint(event.PositionInScreen());

  bool handle_as_cursor_control = false;
  switch (event.GetType()) {
    case WebInputEvent::Type::kGestureScrollBegin: {
      if (event.data.scroll_begin.cursor_control) {
        swipe_to_move_cursor_activated_ = true;
        handle_as_cursor_control = true;
      }
      break;
    }
    case WebInputEvent::Type::kGestureScrollUpdate: {
      if (swipe_to_move_cursor_activated_)
        handle_as_cursor_control = true;
      break;
    }
    case WebInputEvent::Type::kGestureScrollEnd: {
      if (swipe_to_move_cursor_activated_) {
        swipe_to_move_cursor_activated_ = false;
        handle_as_cursor_control = true;
      }
      break;
    }
    default:
      break;
  }
  // TODO(crbug.com/1140106): Place cursor for scroll begin other than just move
  // cursor.
  if (handle_as_cursor_control) {
    WebLocalFrame* focused_frame = FocusedWebLocalFrameInWidget();
    if (focused_frame) {
      gfx::Point base(event.PositionInWidget().x(),
                      event.PositionInWidget().y());
      focused_frame->MoveCaretSelection(base);
    }
    *suppress = true;
  }
}

void WebFrameWidgetImpl::WillHandleMouseEvent(const WebMouseEvent& event) {
  possible_drag_event_info_.source = ui::mojom::blink::DragEventSource::kMouse;
  possible_drag_event_info_.location =
      gfx::Point(event.PositionInScreen().x(), event.PositionInScreen().y());
}

void WebFrameWidgetImpl::ObserveGestureEventAndResult(
    const WebGestureEvent& gesture_event,
    const gfx::Vector2dF& unused_delta,
    const cc::OverscrollBehavior& overscroll_behavior,
    bool event_processed) {
  if (!widget_base_->LayerTreeHost()->GetSettings().enable_elastic_overscroll)
    return;

  cc::InputHandlerScrollResult scroll_result;
  scroll_result.did_scroll = event_processed;
  scroll_result.did_overscroll_root = !unused_delta.IsZero();
  scroll_result.unused_scroll_delta = unused_delta;
  scroll_result.overscroll_behavior = overscroll_behavior;

  widget_base_->widget_input_handler_manager()->ObserveGestureEventOnMainThread(
      gesture_event, scroll_result);
}

void WebFrameWidgetImpl::DidHandleKeyEvent() {
  ClearEditCommands();
}

WebTextInputType WebFrameWidgetImpl::GetTextInputType() {
  if (ShouldDispatchImeEventsToPlugin()) {
    return GetFocusedPluginContainer()->GetPluginTextInputType();
  }

  WebInputMethodController* controller = GetActiveWebInputMethodController();
  if (!controller)
    return WebTextInputType::kWebTextInputTypeNone;
  return controller->TextInputType();
}

void WebFrameWidgetImpl::SetCursorVisibilityState(bool is_visible) {
  GetPage()->SetIsCursorVisible(is_visible);
}

void WebFrameWidgetImpl::ApplyViewportChangesForTesting(
    const ApplyViewportChangesArgs& args) {
  widget_base_->ApplyViewportChanges(args);
}

void WebFrameWidgetImpl::SetDisplayMode(mojom::blink::DisplayMode mode) {
  if (mode != display_mode_) {
    display_mode_ = mode;
    LocalFrame* frame = LocalRootImpl()->GetFrame();
    frame->MediaQueryAffectingValueChangedForLocalSubtree(
        MediaValueChange::kOther);
  }
}

void WebFrameWidgetImpl::SetWindowShowState(
    ui::mojom::blink::WindowShowState state) {
  if (state == window_show_state_) {
    return;
  }

  window_show_state_ = state;
  LocalFrame* frame = LocalRootImpl()->GetFrame();
  frame->MediaQueryAffectingValueChangedForLocalSubtree(
      MediaValueChange::kOther);
}

void WebFrameWidgetImpl::SetResizable(bool resizable) {
  if (resizable_ == resizable) {
    return;
  }

  resizable_ = resizable;
  LocalFrame* frame = LocalRootImpl()->GetFrame();
  frame->MediaQueryAffectingValueChangedForLocalSubtree(
      MediaValueChange::kOther);
}

void WebFrameWidgetImpl::OverrideDevicePostureForEmulation(
    mojom::blink::DevicePostureType device_posture_param) {
  LocalFrame* frame = LocalRootImpl()->GetFrame();
  frame->OverrideDevicePostureForEmulation(device_posture_param);
}

void WebFrameWidgetImpl::DisableDevicePostureOverrideForEmulation() {
  LocalFrame* frame = LocalRootImpl()->GetFrame();
  frame->DisableDevicePostureOverrideForEmulation();
}

void WebFrameWidgetImpl::SetViewportSegments(
    const std::vector<gfx::Rect>& viewport_segments_param) {
  WebVector<gfx::Rect> viewport_segments(viewport_segments_param);
  if (!viewport_segments_.Equals(viewport_segments)) {
    viewport_segments_ = viewport_segments;
    LocalFrame* frame = LocalRootImpl()->GetFrame();
    frame->ViewportSegmentsChanged(viewport_segments_);

    ForEachRemoteFrameControlledByWidget(
        [&viewport_segments =
             viewport_segments_param](RemoteFrame* remote_frame) {
          remote_frame->DidChangeRootViewportSegments(viewport_segments);
        });
  }
}

void WebFrameWidgetImpl::SetCursor(const ui::Cursor& cursor) {
  widget_base_->SetCursor(cursor);
}

bool WebFrameWidgetImpl::HandlingInputEvent() {
  return widget_base_->input_handler().handling_input_event();
}

void WebFrameWidgetImpl::SetHandlingInputEvent(bool handling) {
  widget_base_->input_handler().set_handling_input_event(handling);
}

void WebFrameWidgetImpl::ProcessInputEventSynchronouslyForTesting(
    const WebCoalescedInputEvent& event,
    WidgetBaseInputHandler::HandledEventCallback callback) {
  widget_base_->input_handler().HandleInputEvent(event, nullptr,
                                                 std::move(callback));
}

void WebFrameWidgetImpl::ProcessInputEventSynchronouslyForTesting(
    const WebCoalescedInputEvent& event) {
  ProcessInputEventSynchronouslyForTesting(event, base::DoNothing());
}

WebInputEventResult WebFrameWidgetImpl::DispatchBufferedTouchEvents() {
  CHECK(LocalRootImpl());

  if (WebDevToolsAgentImpl* devtools =
          LocalRootImpl()->DevToolsAgentImpl(/*create_if_necessary=*/false)) {
    devtools->DispatchBufferedTouchEvents();
  }

  return LocalRootImpl()
      ->GetFrame()
      ->GetEventHandler()
      .DispatchBufferedTouchEvents();
}

WebInputEventResult WebFrameWidgetImpl::HandleInputEvent(
    const WebCoalescedInputEvent& coalesced_event) {
  const WebInputEvent& input_event = coalesced_event.Event();
  TRACE_EVENT1("input,rail", "WebFrameWidgetImpl::HandleInputEvent", "type",
               WebInputEvent::GetName(input_event.GetType()));
  DCHECK(!WebInputEvent::IsTouchEventType(input_event.GetType()));
  CHECK(LocalRootImpl());

  // Clients shouldn't be dispatching events to a provisional frame but this
  // can happen. Ensure that event handling can assume we're in a committed
  // frame.
  if (IsProvisional())
    return WebInputEventResult::kHandledSuppressed;

  // If a drag-and-drop operation is in progress, ignore input events except
  // PointerCancel and GestureLongPress.
  if (doing_drag_and_drop_ &&
      input_event.GetType() != WebInputEvent::Type::kPointerCancel &&
      input_event.GetType() != WebInputEvent::Type::kGestureLongPress) {
    return WebInputEventResult::kHandledSuppressed;
  }

  // Don't handle events once we've started shutting down or when the page is in
  // bfcache.
  if (!GetPage() ||
      GetPage()->GetPageLifecycleState()->is_in_back_forward_cache) {
    return WebInputEventResult::kNotHandled;
  }

  if (WebDevToolsAgentImpl* devtools =
          LocalRootImpl()->DevToolsAgentImpl(/*create_if_necessary=*/false)) {
    auto result = devtools->HandleInputEvent(input_event);
    if (result != WebInputEventResult::kNotHandled)
      return result;
  }

  // If we are a mouse down potentially activate the paused debugger window.
  if (input_event.GetType() == WebInputEvent::Type::kMouseDown) {
    WebDevToolsAgentImpl::ActivatePausedDebuggerWindow(LocalRootImpl());
  }

  // Report the event to be NOT processed by WebKit, so that the browser can
  // handle it appropriately.
  if (ShouldIgnoreInputEvents()) {
    return WebInputEventResult::kNotHandled;
  }

  base::AutoReset<const WebInputEvent*> current_event_change(
      &CurrentInputEvent::current_input_event_, &input_event);
  UIEventWithKeyState::ClearNewTabModifierSetFromIsolatedWorld();

  if (GetPage()->GetPointerLockController().IsPointerLocked() &&
      WebInputEvent::IsMouseEventType(input_event.GetType())) {
    PointerLockMouseEvent(coalesced_event);
    return WebInputEventResult::kHandledSystem;
  }

  /// These metrics are only captured for the main frame.
  if (ForMainFrame()) {
    Document& main_frame_document = *LocalRootImpl()->GetFrame()->GetDocument();

    if (input_event.GetType() != WebInputEvent::Type::kMouseMove) {
      FirstMeaningfulPaintDetector::From(main_frame_document)
          .NotifyInputEvent();
    }

    if (input_event.GetType() != WebInputEvent::Type::kMouseMove &&
        input_event.GetType() != WebInputEvent::Type::kMouseEnter &&
        input_event.GetType() != WebInputEvent::Type::kMouseLeave) {
      InteractiveDetector* interactive_detector(
          InteractiveDetector::From(main_frame_document));
      if (interactive_detector) {
        interactive_detector->OnInvalidatingInputEvent(input_event.TimeStamp());
      }
    }
  }

  NotifyInputObservers(coalesced_event);

  // Notify the focus frame of the input. Note that the other frames are not
  // notified as input is only handled by the focused frame.
  Frame* frame = FocusedCoreFrame();
  if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
    if (auto* content_capture_manager =
            local_frame->LocalFrameRoot().GetOrResetContentCaptureManager()) {
      content_capture_manager->NotifyInputEvent(input_event.GetType(),
                                                *local_frame);
    }

    if (animation_frame_timing_monitor_) {
      animation_frame_timing_monitor_->WillHandleInput(local_frame);
    }
  }

  // Skip the pointerrawupdate for mouse capture case.
  if (mouse_capture_element_ &&
      input_event.GetType() == WebInputEvent::Type::kPointerRawUpdate)
    return WebInputEventResult::kHandledSystem;

  if (mouse_capture_element_ &&
      WebInputEvent::IsMouseEventType(input_event.GetType()))
    return HandleCapturedMouseEvent(coalesced_event);

  // FIXME: This should take in the intended frame, not the local frame
  // root.
  return WidgetEventHandler::HandleInputEvent(coalesced_event,
                                              LocalRootImpl()->GetFrame());
}

WebInputEventResult WebFrameWidgetImpl::HandleCapturedMouseEvent(
    const WebCoalescedInputEvent& coalesced_event) {
  const WebInputEvent& input_event = coalesced_event.Event();
  TRACE_EVENT1("input", "captured mouse event", "type", input_event.GetType());
  // Save |mouse_capture_element_| since |MouseCaptureLost()| will clear it.
  HTMLPlugInElement* element = mouse_capture_element_;

  // Not all platforms call mouseCaptureLost() directly.
  if (input_event.GetType() == WebInputEvent::Type::kMouseUp) {
    SetMouseCapture(false);
    MouseCaptureLost();
  }

  AtomicString event_type;
  switch (input_event.GetType()) {
    case WebInputEvent::Type::kMouseEnter:
      event_type = event_type_names::kMouseover;
      break;
    case WebInputEvent::Type::kMouseMove:
      event_type = event_type_names::kMousemove;
      break;
    case WebInputEvent::Type::kPointerRawUpdate:
      // There will be no mouse event for rawupdate events.
      event_type = event_type_names::kPointerrawupdate;
      break;
    case WebInputEvent::Type::kMouseLeave:
      event_type = event_type_names::kMouseout;
      break;
    case WebInputEvent::Type::kMouseDown:
      event_type = event_type_names::kMousedown;
      LocalFrame::NotifyUserActivation(
          element->GetDocument().GetFrame(),
          mojom::blink::UserActivationNotificationType::kInteraction);
      break;
    case WebInputEvent::Type::kMouseUp:
      event_type = event_type_names::kMouseup;
      break;
    default:
      NOTREACHED();
  }

  WebMouseEvent transformed_event =
      TransformWebMouseEvent(LocalRootImpl()->GetFrameView(),
                             static_cast<const WebMouseEvent&>(input_event));
  if (LocalFrame* frame = element->GetDocument().GetFrame()) {
    frame->GetEventHandler().HandleTargetedMouseEvent(
        element, transformed_event, event_type,
        TransformWebMouseEventVector(
            LocalRootImpl()->GetFrameView(),
            coalesced_event.GetCoalescedEventsPointers()),
        TransformWebMouseEventVector(
            LocalRootImpl()->GetFrameView(),
            coalesced_event.GetPredictedEventsPointers()));
  }
  return WebInputEventResult::kHandledSystem;
}

void WebFrameWidgetImpl::UpdateTextInputState() {
  widget_base_->UpdateTextInputState();
}

void WebFrameWidgetImpl::UpdateSelectionBounds() {
  widget_base_->UpdateSelectionBounds();
}

void WebFrameWidgetImpl::ShowVirtualKeyboard() {
  widget_base_->ShowVirtualKeyboard();
}

void WebFrameWidgetImpl::FlushInputProcessedCallback() {
  widget_base_->FlushInputProcessedCallback();
}

void WebFrameWidgetImpl::CancelCompositionForPepper() {
  widget_base_->CancelCompositionForPepper();
}

void WebFrameWidgetImpl::RequestMouseLock(
    bool has_transient_user_activation,
    bool request_unadjusted_movement,
    mojom::blink::WidgetInputHandlerHost::RequestMouseLockCallback callback) {
  mojom::blink::WidgetInputHandlerHost* host =
      widget_base_->widget_input_handler_manager()->GetWidgetInputHandlerHost();

  // If we don't have a host just leave the callback uncalled. This simulates
  // the browser indefinitely postponing the mouse request which is valid.
  // Note that |callback| is not a mojo bound callback (until it is passed
  // into the mojo interface) and can be destructed without invoking the
  // callback. It does share the same signature as the mojo definition
  // for simplicity.
  if (host) {
    host->RequestMouseLock(has_transient_user_activation,
                           request_unadjusted_movement, std::move(callback));
  }
}

void WebFrameWidgetImpl::MouseCaptureLost() {
  TRACE_EVENT_NESTABLE_ASYNC_END0("input", "capturing mouse",
                                  TRACE_ID_LOCAL(this));
  mouse_capture_element_ = nullptr;
}

void WebFrameWidgetImpl::ApplyVisualProperties(
    const VisualProperties& visual_properties) {
  widget_base_->UpdateVisualProperties(visual_properties);
}

bool WebFrameWidgetImpl::IsFullscreenGranted() {
  return is_fullscreen_granted_;
}

bool WebFrameWidgetImpl::PinchGestureActiveInMainFrame() {
  return is_pinch_gesture_active_in_mainframe_;
}

float WebFrameWidgetImpl::PageScaleInMainFrame() {
  return page_scale_factor_in_mainframe_;
}

void WebFrameWidgetImpl::UpdateSurfaceAndScreenInfo(
    const viz::LocalSurfaceId& new_local_surface_id,
    const gfx::Rect& compositor_viewport_pixel_rect,
    const display::ScreenInfos& new_screen_infos) {
  widget_base_->UpdateSurfaceAndScreenInfo(
      new_local_surface_id, compositor_viewport_pixel_rect, new_screen_infos);
}

void WebFrameWidgetImpl::UpdateScreenInfo(
    const display::ScreenInfos& new_screen_infos) {
  widget_base_->UpdateScreenInfo(new_screen_infos);
}

void WebFrameWidgetImpl::UpdateSurfaceAndCompositorRect(
    const viz::LocalSurfaceId& new_local_surface_id,
    const gfx::Rect& compositor_viewport_pixel_rect) {
  widget_base_->UpdateSurfaceAndCompositorRect(new_local_surface_id,
                                               compositor_viewport_pixel_rect);
}

void WebFrameWidgetImpl::UpdateCompositorViewportRect(
    const gfx::Rect& compositor_viewport_pixel_rect) {
  widget_base_->UpdateCompositorViewportRect(compositor_viewport_pixel_rect);
}

const display::ScreenInfo& WebFrameWidgetImpl::GetScreenInfo() {
  return widget_base_->GetScreenInfo();
}

const display::ScreenInfos& WebFrameWidgetImpl::GetScreenInfos() {
  return widget_base_->screen_infos();
}

const display::ScreenInfo& WebFrameWidgetImpl::GetOriginalScreenInfo() {
  if (device_emulator_)
    return device_emulator_->GetOriginalScreenInfo();
  return widget_base_->GetScreenInfo();
}

const display::ScreenInfos& WebFrameWidgetImpl::GetOriginalScreenInfos() {
  if (device_emulator_)
    return device_emulator_->original_screen_infos();
  return widget_base_->screen_infos();
}

gfx::Rect WebFrameWidgetImpl::WindowRect() {
  return widget_base_->WindowRect();
}

double WebFrameWidgetImpl::GetCSSZoomFactor() const {
  return css_zoom_factor_;
}

gfx::Rect WebFrameWidgetImpl::ViewRect() {
  return widget_base_->ViewRect();
}

void WebFrameWidgetImpl::SetScreenRects(const gfx::Rect& widget_screen_rect,
                                        const gfx::Rect& window_screen_rect) {
  widget_base_->SetScreenRects(widget_screen_rect, window_screen_rect);
}

gfx::Size WebFrameWidgetImpl::VisibleViewportSizeInDIPs() {
  return widget_base_->VisibleViewportSizeInDIPs();
}

void WebFrameWidgetImpl::SetPendingWindowRect(
    const gfx::Rect& window_screen_rect) {
  widget_base_->SetPendingWindowRect(window_screen_rect);
}

void WebFrameWidgetImpl::AckPendingWindowRect() {
  widget_base_->AckPendingWindowRect();
}

bool WebFrameWidgetImpl::IsHidden() const {
  return widget_base_->is_hidden();
}

WebString WebFrameWidgetImpl::GetLastToolTipTextForTesting() const {
  return GetPage()->GetChromeClient().GetLastToolTipTextForTesting();
}

float WebFrameWidgetImpl::GetEmulatorScale() {
  if (device_emulator_)
    return device_emulator_->scale();
  return 1.0f;
}

void WebFrameWidgetImpl::IntrinsicSizingInfoChanged(
    mojom::blink::IntrinsicSizingInfoPtr sizing_info) {
  DCHECK(ForSubframe());
  GetAssociatedFrameWidgetHost()->IntrinsicSizingInfoChanged(
      std::move(sizing_info));
}

void WebFrameWidgetImpl::AutoscrollStart(const gfx::PointF& position) {
  GetAssociatedFrameWidgetHost()->AutoscrollStart(std::move(position));
}

void WebFrameWidgetImpl::AutoscrollFling(const gfx::Vector2dF& velocity) {
  GetAssociatedFrameWidgetHost()->AutoscrollFling(std::move(velocity));
}

void WebFrameWidgetImpl::AutoscrollEnd() {
  GetAssociatedFrameWidgetHost()->AutoscrollEnd();
}

void WebFrameWidgetImpl::DidMeaningfulLayout(WebMeaningfulLayout layout_type) {
  if (layout_type == blink::WebMeaningfulLayout::kVisuallyNonEmpty) {
    NotifyPresentationTime(WTF::BindOnce(
        &WebFrameWidgetImpl::PresentationCallbackForMeaningfulLayout,
        WrapWeakPersistent(this)));
  }

  ForEachLocalFrameControlledByWidget(
      local_root_->GetFrame(), [layout_type](WebLocalFrameImpl* local_frame) {
        local_frame->Client()->DidMeaningfulLayout(layout_type);
      });
}

void WebFrameWidgetImpl::PresentationCallbackForMeaningfulLayout(
    const viz::FrameTimingDetails& first_paint_details) {
  // |local_root_| may be null if the widget has shut down between when this
  // callback was requested and when it was resolved by the compositor.
  if (local_root_)
    local_root_->ViewImpl()->DidFirstVisuallyNonEmptyPaint();

  base::TimeTicks first_paint_time =
      first_paint_details.presentation_feedback.timestamp;
  if (widget_base_)
    widget_base_->DidFirstVisuallyNonEmptyPaint(first_paint_time);
}

void WebFrameWidgetImpl::RequestAnimationAfterDelay(
    const base::TimeDelta& delay) {
  widget_base_->RequestAnimationAfterDelay(delay);
}

void WebFrameWidgetImpl::SetRootLayer(scoped_refptr<cc::Layer>
"""


```