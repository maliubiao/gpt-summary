Response:
The user wants a summary of the functionalities implemented in the provided C++ code snippet from `local_frame.cc`. I need to identify the core features and their relation to web technologies like Javascript, HTML, and CSS. The user also wants examples of logical reasoning, common user errors, and specifically asked for a summary as this is part 3 of 6.

Here's a breakdown of the code's functionality:

1. **Paint Invalidation and Capture:**  The code manages invalidating parts of the frame for repainting, specifically related to capturing the frame's content.
2. **Scroll Offset Management:** It handles saving and restoring scroll positions, useful for maintaining user experience across navigations or state changes.
3. **Zoom Factor Control:**  The code allows setting and managing layout and text zoom levels. This impacts how content is rendered.
4. **Media Query Updates:** It deals with triggering updates to media queries when relevant factors change, affecting responsive design.
5. **Viewport Segments:** This section seems to handle scenarios where the viewport is divided into segments, likely for dual-screen or foldable devices, and how CSS environment variables are updated accordingly.
6. **Device Posture Emulation:**  The code provides mechanisms for emulating different device postures (e.g., folded, unfolded) for testing purposes.
7. **Pixel Ratio:**  It calculates and returns the device pixel ratio, important for rendering sharp images on high-DPI screens.
8. **Text Selection:** The code retrieves and handles selected text within the frame.
9. **Point to Position Mapping:** It allows finding the DOM position corresponding to a given point in the frame.
10. **Document at Point:** It identifies the document at a specific point within the frame hierarchy.
11. **Spelling Marker Removal:** The code provides a function to remove spelling markers.
12. **Layer Tree Inspection:** It offers a way to get a text representation of the composited layer tree, useful for debugging rendering issues.
13. **Rendering Throttling:** The code checks if rendering should be throttled, likely for performance optimization when the frame is not visible.
14. **Frame Navigation Control:**  The code includes logic for determining if a frame is allowed to navigate to a certain URL, taking into account factors like security origins, sandboxing, and user gestures.
15. **Content Capture Management:** It manages the `ContentCaptureManager`, potentially for features like accessibility or content indexing.
16. **Frame Visibility:**  It handles notifications when the frame becomes hidden.

Now let's organize this into the requested categories.
这是`blink/renderer/core/frame/local_frame.cc`文件的一部分，主要负责以下功能：

**1. 处理渲染失效和捕获 (Paint Invalidation and Capture):**

*   **功能:**  `SetInvalidationForCapture(bool capturing)` 函数根据是否正在进行捕获操作，来设置当前 `LocalFrame` 及其子 `LocalFrame` 的 `is_invalidating_for_capture_` 标志。
*   **与 JavaScript/HTML/CSS 的关系:**  当网页进行截屏或者录屏等捕获操作时，浏览器需要知道哪些部分需要被重新绘制。这个函数就是参与这个过程，确保捕获的内容是最新的。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  `capturing = true`
    *   **输出:**  当前 `LocalFrame` 和所有子 `LocalFrame` 的 `is_invalidating_for_capture_` 标志被设置为 `true`。
    *   **假设输入:**  `capturing = false`
    *   **输出:**  当前 `LocalFrame` 和所有子 `LocalFrame` 的 `is_invalidating_for_capture_` 标志被设置为 `false`。
*   **功能:**  触发布局视图的属性更新 (`layout_view->SetNeedsPaintPropertyUpdate()`)，以确保非裁剪行为应用于框架级别的滚动条。
*   **与 JavaScript/HTML/CSS 的关系:**  CSS 属性会影响元素的渲染和布局，这个更新确保了与滚动相关的 CSS 属性（比如是否显示滚动条）能够正确应用。
*   **功能:**  如果当前页面不使用覆盖滚动条 (`!GetPage()->GetScrollbarTheme().UsesOverlayScrollbars()`)，并且正在进入或退出预览模式，则强制进行重新布局 (`layout_view->SetNeedsLayout(layout_invalidation_reason::kPaintPreview)`)。
*   **与 JavaScript/HTML/CSS 的关系:**  滚动条的显示与否会影响页面的布局，尤其是在一些旧的浏览器或者特定配置下。这个逻辑确保在捕获预览场景下布局的正确性。

**2. 保存和恢复滚动偏移 (Save and Restore Scroll Offsets):**

*   **功能:**  `EnsureSaveScrollOffset(Node& node)` 函数用于保存指定节点 (`node`) 的滚动偏移量。它会创建一个 `saved_scroll_offsets_` 容器来存储这些偏移量。只会保存每个可滚动区域的第一个滚动偏移量。
*   **与 JavaScript/HTML/CSS 的关系:**  当网页进行一些操作（例如后退、前进）时，有时需要恢复用户之前的滚动位置，这个函数就用于保存这些信息。节点通常是 HTML 元素。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  一个可滚动的 `div` 元素作为 `node` 传入，且当前滚动位置为 (100, 200)。
    *   **输出:**  `saved_scroll_offsets_` 容器中会存储该 `div` 元素和其滚动偏移量 (100, 200) 的对应关系。
*   **功能:**  `RestoreScrollOffsets()` 函数用于恢复之前保存的滚动偏移量。它会遍历 `saved_scroll_offsets_` 容器，并无条件地设置每个可滚动区域的滚动位置。
*   **与 JavaScript/HTML/CSS 的关系:**  在需要恢复滚动位置时调用此函数。
*   **用户或编程常见的使用错误:**  如果在节点被销毁后尝试恢复其滚动偏移，可能会导致空指针访问或者其他错误。

**3. 设置布局和文本缩放因子 (Set Layout and Text Zoom Factors):**

*   **功能:**  `SetLayoutZoomFactor(float factor)` 和 `SetTextZoomFactor(float factor)` 分别用于设置页面的布局缩放因子和文本缩放因子。`SetLayoutAndTextZoomFactors(float layout_zoom_factor, float text_zoom_factor)` 是一个统一设置的函数。
*   **与 JavaScript/HTML/CSS 的关系:**  这些函数对应浏览器提供的缩放功能，用户可以通过浏览器界面或者 JavaScript API 来调整页面的缩放比例，从而改变网页元素的显示大小。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  `SetLayoutZoomFactor(1.5f)`
    *   **输出:**  页面的布局会放大到原来的 1.5 倍，包括图片、文本等所有元素。
    *   **假设输入:**  `SetTextZoomFactor(2.0f)`
    *   **输出:**  页面中的文本会放大到原来的 2.0 倍，而其他非文本元素大小不变。
*   **功能:**  对于独立的 SVG 文档，会检查其 `zoomAndPan` 属性，如果设置为 "disabled"，则不会进行缩放。
*   **与 JavaScript/HTML/CSS 的关系:**  SVG 元素的 `zoomAndPan` 属性可以控制是否允许用户进行缩放操作。
*   **功能:**  如果浏览器启用了标准化浏览器缩放 (`GetDocument()->StandardizedBrowserZoomEnabled()`)，则缩放因子会通过样式解析传播。否则，需要手动将缩放因子传递给子框架。
*   **与 JavaScript/HTML/CSS 的关系:**  浏览器的缩放功能最终会影响 CSS 样式的计算和应用。
*   **功能:**  布局缩放因子改变时，会触发窗口控件覆盖层的更新 (`MaybeUpdateWindowControlsOverlayWithNewZoomLevel()`)（非 Android 平台），并通知文档视口大小已调整 (`document->LayoutViewportWasResized()`)，并触发媒体查询的重新评估 (`document->MediaQueryAffectingValueChanged(MediaValueChange::kOther)`)。
*   **与 JavaScript/HTML/CSS 的关系:**  视口大小的改变会影响响应式设计的布局。媒体查询会根据视口大小的变化来应用不同的 CSS 样式。
*   **功能:**  最后，会标记所有元素需要重新计算样式 (`document->GetStyleEngine().MarkAllElementsForStyleRecalc(...)`)，并触发视图重新布局 (`View()->SetNeedsLayout()`)。

**总结 (基于第 3 部分):**

这部分代码主要关注 `LocalFrame` 的渲染控制和用户交互行为的管理。具体来说，它涵盖了：

*   **控制渲染失效和捕获行为，确保捕获操作能获取到最新的渲染结果。**
*   **提供保存和恢复页面滚动位置的能力，提升用户体验。**
*   **管理页面的布局和文本缩放级别，允许用户调整页面显示效果。**

这些功能都直接或间接地与网页的呈现方式和用户的交互体验相关，并与 HTML 结构、CSS 样式以及可能的 JavaScript 脚本操作相互作用。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
    child_local_frame->SetInvalidationForCapture(capturing);
    }
  }

  auto* layout_view = View()->GetLayoutView();
  if (!layout_view) {
    return;
  }

  // Trigger a paint property update to ensure the unclipped behavior is
  // applied to the frame level scroller.
  layout_view->SetNeedsPaintPropertyUpdate();

  if (!GetPage()->GetScrollbarTheme().UsesOverlayScrollbars()) {
    // During CapturePaintPreview, the LayoutView thinks it should not have
    // scrollbars. So if scrollbars affect layout, we should force relayout
    // when entering and exiting paint preview.
    layout_view->SetNeedsLayout(layout_invalidation_reason::kPaintPreview);
  }
}

void LocalFrame::EnsureSaveScrollOffset(Node& node) {
  const auto* scrollable_area = PaintLayerScrollableArea::FromNode(node);
  if (!scrollable_area)
    return;
  if (!saved_scroll_offsets_)
    saved_scroll_offsets_ = MakeGarbageCollected<SavedScrollOffsets>();
  // Retain the first scroll offset saved for each scrollable area.
  if (!saved_scroll_offsets_->Contains(&node))
    saved_scroll_offsets_->Set(&node, scrollable_area->GetScrollOffset());
}

void LocalFrame::RestoreScrollOffsets() {
  if (!saved_scroll_offsets_)
    return;

  // Restore scroll offsets unconditionally (i.e. without clamping) in case
  // layout or view sizes haven't been updated yet.
  for (auto& entry : *saved_scroll_offsets_) {
    auto* scrollable_area = PaintLayerScrollableArea::FromNode(*entry.key);
    if (!scrollable_area)
      continue;
    scrollable_area->SetScrollOffsetUnconditionally(
        entry.value, mojom::blink::ScrollType::kProgrammatic);
  }
  saved_scroll_offsets_ = nullptr;
}

void LocalFrame::SetLayoutZoomFactor(float factor) {
  SetLayoutAndTextZoomFactors(factor, text_zoom_factor_);
}

void LocalFrame::SetTextZoomFactor(float factor) {
  SetLayoutAndTextZoomFactors(layout_zoom_factor_, factor);
}

void LocalFrame::SetLayoutAndTextZoomFactors(float layout_zoom_factor,
                                             float text_zoom_factor) {
  if (layout_zoom_factor_ == layout_zoom_factor &&
      text_zoom_factor_ == text_zoom_factor) {
    return;
  }

  Page* page = GetPage();
  if (!page)
    return;

  Document* document = GetDocument();
  if (!document)
    return;

  // Respect SVGs zoomAndPan="disabled" property in standalone SVG documents.
  // FIXME: How to handle compound documents + zoomAndPan="disabled"? Needs SVG
  // WG clarification.
  if (document->IsSVGDocument()) {
    if (!document->AccessSVGExtensions().ZoomAndPanEnabled())
      return;
  }

  bool layout_zoom_changed = (layout_zoom_factor != layout_zoom_factor_);

  layout_zoom_factor_ = layout_zoom_factor;
  text_zoom_factor_ = text_zoom_factor;

  if (!GetDocument()->StandardizedBrowserZoomEnabled()) {
    // Zoom factor will not be propagated via style resolution, it must be
    // propagated here.
    for (Frame* child = Tree().FirstChild(); child;
         child = child->Tree().NextSibling()) {
      if (auto* child_local_frame = DynamicTo<LocalFrame>(child)) {
        child_local_frame->SetLayoutAndTextZoomFactors(layout_zoom_factor_,
                                                       text_zoom_factor_);
      } else {
        DynamicTo<RemoteFrame>(child)->ZoomFactorChanged(layout_zoom_factor);
      }
    }
  }

  if (layout_zoom_changed) {
#if !BUILDFLAG(IS_ANDROID)
    MaybeUpdateWindowControlsOverlayWithNewZoomLevel();
#endif
    document->LayoutViewportWasResized();
    document->MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  }
  document->GetStyleEngine().MarkViewportStyleDirty();
  document->GetStyleEngine().MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(style_change_reason::kZoom));
  if (View())
    View()->SetNeedsLayout();
}

void LocalFrame::MediaQueryAffectingValueChangedForLocalSubtree(
    MediaValueChange value) {
  GetDocument()->MediaQueryAffectingValueChanged(value);
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (auto* child_local_frame = DynamicTo<LocalFrame>(child))
      child_local_frame->MediaQueryAffectingValueChangedForLocalSubtree(value);
  }
}

void LocalFrame::ViewportSegmentsChanged(
    const WebVector<gfx::Rect>& viewport_segments) {
  if (!RuntimeEnabledFeatures::ViewportSegmentsEnabled(
          GetDocument()->GetExecutionContext())) {
    return;
  }

  DCHECK(IsLocalRoot());

  // A change in the viewport segments requires re-evaluation of media queries
  // for the local frame subtree (the segments affect the
  // "horizontal-viewport-segments" and "vertical-viewport-segments" features).
  MediaQueryAffectingValueChangedForLocalSubtree(MediaValueChange::kOther);

  // Fullscreen element has its own document and uses the viewport media queries,
  // so we need to make sure the media queries are re-evaluated.
  if (Element* fullscreen = Fullscreen::FullscreenElementFrom(*GetDocument())) {
    GetDocument()->GetStyleEngine().MarkAllElementsForStyleRecalc(
        StyleChangeReasonForTracing::Create(style_change_reason::kFullscreen));
    CSSDefaultStyleSheets::Instance()
        .RebuildFullscreenRuleSetIfMediaQueriesChanged(*fullscreen);
  }

  // Also need to update the environment variables related to viewport segments.
  UpdateViewportSegmentCSSEnvironmentVariables(viewport_segments);
}

void LocalFrame::UpdateViewportSegmentCSSEnvironmentVariables(
    const WebVector<gfx::Rect>& viewport_segments) {
  DCHECK(RuntimeEnabledFeatures::ViewportSegmentsEnabled(
      GetDocument()->GetExecutionContext()));

  // Update the variable values on the root instance so that documents that
  // are created after the values change automatically have the right values.
  UpdateViewportSegmentCSSEnvironmentVariables(
      StyleEnvironmentVariables::GetRootInstance(), viewport_segments);

  if (Element* fullscreen = Fullscreen::FullscreenElementFrom(*GetDocument())) {
    // Fullscreen has its own document so we need to update its variables as
    // well.
    UpdateViewportSegmentCSSEnvironmentVariables(
        fullscreen->GetDocument().GetStyleEngine().EnsureEnvironmentVariables(),
        viewport_segments);
  }
}

void LocalFrame::UpdateViewportSegmentCSSEnvironmentVariables(
    StyleEnvironmentVariables& vars,
    const WebVector<gfx::Rect>& viewport_segments) {
  // Unset all variables, since they will be set as a whole by the code below.
  // Since the number and configurations of the segments can change, and
  // removing variables clears all values that have previously been set,
  // we will recalculate all the values on each change.
  const UADefinedTwoDimensionalVariable vars_to_remove[] = {
      UADefinedTwoDimensionalVariable::kViewportSegmentTop,
      UADefinedTwoDimensionalVariable::kViewportSegmentRight,
      UADefinedTwoDimensionalVariable::kViewportSegmentBottom,
      UADefinedTwoDimensionalVariable::kViewportSegmentLeft,
      UADefinedTwoDimensionalVariable::kViewportSegmentWidth,
      UADefinedTwoDimensionalVariable::kViewportSegmentHeight,
  };

  ExecutionContext* context = GetDocument()->GetExecutionContext();
  for (auto var : vars_to_remove) {
    vars.RemoveVariable(var, context);
  }

  // Per [css-env-1], only set the segment variables if there is more than one.
  if (viewport_segments.size() >= 2) {
    // Iterate the segments in row-major order, setting the segment variables
    // based on x and y index.
    int current_y_position = viewport_segments[0].y();
    unsigned x_index = 0;
    unsigned y_index = 0;
    SetViewportSegmentVariablesForRect(vars, viewport_segments[0], x_index,
                                       y_index, context);
    for (size_t i = 1; i < viewport_segments.size(); i++) {
      if (viewport_segments[i].y() == current_y_position) {
        x_index++;
        SetViewportSegmentVariablesForRect(vars, viewport_segments[i], x_index,
                                           y_index, context);
      } else {
        // If there is a different y value, this is the next row so increase
        // y index and start again from 0 for x.
        y_index++;
        x_index = 0;
        current_y_position = viewport_segments[i].y();
        SetViewportSegmentVariablesForRect(vars, viewport_segments[i], x_index,
                                           y_index, context);
      }
    }
  }
}

void LocalFrame::OverrideDevicePostureForEmulation(
    mojom::blink::DevicePostureType device_posture_param) {
  mojo_handler_->OverrideDevicePostureForEmulation(device_posture_param);
}

void LocalFrame::DisableDevicePostureOverrideForEmulation() {
  mojo_handler_->DisableDevicePostureOverrideForEmulation();
}

mojom::blink::DevicePostureType LocalFrame::GetDevicePosture() {
  return mojo_handler_->GetDevicePosture();
}

double LocalFrame::DevicePixelRatio() const {
  if (!page_)
    return 0;

  double ratio = page_->InspectorDeviceScaleFactorOverride();
  ratio *= LayoutZoomFactor();
  return ratio;
}

String LocalFrame::SelectedText() const {
  return Selection().SelectedText();
}

String LocalFrame::SelectedText(const TextIteratorBehavior& behavior) const {
  return Selection().SelectedText(behavior);
}

String LocalFrame::SelectedTextForClipboard() const {
  if (!GetDocument())
    return g_empty_string;
  DCHECK(!GetDocument()->NeedsLayoutTreeUpdate());
  return Selection().SelectedTextForClipboard();
}

void LocalFrame::TextSelectionChanged(const WTF::String& selection_text,
                                      uint32_t offset,
                                      const gfx::Range& range) const {
  GetLocalFrameHostRemote().TextSelectionChanged(selection_text, offset, range);
}

PositionWithAffinity LocalFrame::PositionForPoint(
    const PhysicalOffset& frame_point) {
  HitTestLocation location(frame_point);
  HitTestResult result = GetEventHandler().HitTestResultAtLocation(location);
  return result.GetPositionForInnerNodeOrImageMapImage();
}

Document* LocalFrame::DocumentAtPoint(
    const PhysicalOffset& point_in_root_frame) {
  if (!View())
    return nullptr;

  HitTestLocation location(View()->ConvertFromRootFrame(point_in_root_frame));

  if (!ContentLayoutObject())
    return nullptr;
  HitTestResult result = GetEventHandler().HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
  return result.InnerNode() ? &result.InnerNode()->GetDocument() : nullptr;
}

void LocalFrame::RemoveSpellingMarkersUnderWords(const Vector<String>& words) {
  GetSpellChecker().RemoveSpellingMarkersUnderWords(words);
}

String LocalFrame::GetLayerTreeAsTextForTesting(unsigned flags) const {
  if (!ContentLayoutObject())
    return String();

  std::unique_ptr<JSONObject> layers;
  if (!(flags & kOutputAsLayerTree)) {
    layers = View()->CompositedLayersAsJSON(static_cast<LayerTreeFlags>(flags));
  }
  return layers ? layers->ToPrettyJSONString() : String();
}

bool LocalFrame::ShouldThrottleRendering() const {
  return View() && View()->ShouldThrottleRendering();
}

LocalFrame::LocalFrame(
    LocalFrameClient* client,
    Page& page,
    FrameOwner* owner,
    Frame* parent,
    Frame* previous_sibling,
    FrameInsertType insert_type,
    const LocalFrameToken& frame_token,
    WindowAgentFactory* inheriting_agent_factory,
    InterfaceRegistry* interface_registry,
    mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker> interface_broker,
    const base::TickClock* clock)
    : Frame(client,
            page,
            owner,
            parent,
            previous_sibling,
            insert_type,
            frame_token,
            client->GetDevToolsFrameToken(),
            MakeGarbageCollected<LocalWindowProxyManager>(
                page.GetAgentGroupScheduler().Isolate(),
                *this),
            inheriting_agent_factory),
      frame_scheduler_(page.GetPageScheduler()->CreateFrameScheduler(
          this,
          IsInFencedFrameTree(),
          IsMainFrame() ? FrameScheduler::FrameType::kMainFrame
                        : FrameScheduler::FrameType::kSubframe)),
      loader_(this),
      editor_(MakeGarbageCollected<Editor>(*this)),
      selection_(MakeGarbageCollected<FrameSelection>(*this)),
      event_handler_(MakeGarbageCollected<EventHandler>(*this)),
      console_(MakeGarbageCollected<FrameConsole>(*this)),
      navigation_disable_count_(0),
      in_view_source_mode_(false),
      frozen_(false),
      paused_(false),
      hidden_(false),
      layout_zoom_factor_(ParentLayoutZoomFactor(this)),
      text_zoom_factor_(ParentTextZoomFactor(this)),
      inspector_task_runner_(InspectorTaskRunner::Create(
          GetTaskRunner(TaskType::kInternalInspector))),
      interface_registry_(interface_registry
                              ? interface_registry
                              : InterfaceRegistry::GetEmptyInterfaceRegistry()),
      v8_local_compile_hints_producer_(
          MakeGarbageCollected<v8_compile_hints::V8LocalCompileHintsProducer>(
              this)),
      // TODO(https://crbug.com/352165586): Give non-null context to the proxy.
      browser_interface_broker_proxy_(nullptr /* No LocalDOMWindow yet... */) {
  auto frame_tracking_result =
      GetLocalFramesMap().insert(FrameToken::Hasher()(GetFrameToken()), this);
  CHECK(frame_tracking_result.stored_value) << "Inserting a duplicate item.";
  v8::Isolate* isolate = page.GetAgentGroupScheduler().Isolate();

  if (interface_broker.is_valid()) {  // This may be invalid in unit tests.
    browser_interface_broker_proxy_.Bind(
        std::move(interface_broker),
        page.GetAgentGroupScheduler().DefaultTaskRunner());
  }

  // There is generally one probe sink per local frame tree, so for root frames
  // we create a new child sink and for child frames we propagate one from root.
  // However, if local frame swap is performed, we don't want both frames to be
  // active at once, so a dummy probe sink is created for provisional frame and
  // swapped for that of the frame being swapped on in `SwapIn()`. Since we can
  // only know whether the frame is provisional upon `Initialize()` call which
  // does a lot of things that may potentially lead to instrumentation calls,
  // we set provisional probe sink unconditionally here, then possibly replace
  // it with that of the local root after `Initialize()`.
  probe_sink_ = MakeGarbageCollected<CoreProbeSink>();
  if (IsLocalRoot()) {
    performance_monitor_ =
        MakeGarbageCollected<PerformanceMonitor>(this, isolate);

    inspector_issue_reporter_ = MakeGarbageCollected<InspectorIssueReporter>(
        &page.GetInspectorIssueStorage());
    probe_sink_->AddInspectorIssueReporter(inspector_issue_reporter_);
    inspector_trace_events_ = MakeGarbageCollected<InspectorTraceEvents>();
    probe_sink_->AddInspectorTraceEvents(inspector_trace_events_);
    if (RuntimeEnabledFeatures::AdTaggingEnabled()) {
      ad_tracker_ = MakeGarbageCollected<AdTracker>(this);
    }
    if (blink::LcppScriptObserverEnabled()) {
      script_observer_ = MakeGarbageCollected<LCPScriptObserver>(this);
    }
  } else {
    // Inertness only needs to be updated if this frame might inherit the
    // inert state from a higher-level frame. If this is an OOPIF local root,
    // it will be updated later.
    UpdateInertIfPossible();
    UpdateInheritedEffectiveTouchActionIfPossible();
    ad_tracker_ = LocalFrameRoot().ad_tracker_;
    performance_monitor_ = LocalFrameRoot().performance_monitor_;
    script_observer_ = LocalFrameRoot().script_observer_;
  }
  idleness_detector_ = MakeGarbageCollected<IdlenessDetector>(this, clock);
  attribution_src_loader_ = MakeGarbageCollected<AttributionSrcLoader>(this);
  inspector_task_runner_->InitIsolate(isolate);

  if (IsOutermostMainFrame()) {
    intersection_state_.occlusion_state =
        mojom::blink::FrameOcclusionState::kGuaranteedNotOccluded;
  }

  DCHECK(ad_tracker_ ? RuntimeEnabledFeatures::AdTaggingEnabled()
                     : !RuntimeEnabledFeatures::AdTaggingEnabled());

  // See SubresourceFilterAgent::Initialize for why we don't set this here for
  // fenced frames.
  is_frame_created_by_ad_script_ =
      !IsMainFrame() && ad_tracker_ &&
      ad_tracker_->IsAdScriptInStack(
          AdTracker::StackType::kBottomAndTop,
          /*out_ad_script=*/&ad_script_from_frame_creation_stack_);

  Initialize();
  // Now that we know whether the frame is provisional, inherit the probe
  // sink from parent if appropriate. See comment above for more details.
  if (!IsLocalRoot() && !IsProvisional()) {
    probe_sink_ = LocalFrameRoot().probe_sink_;
    probe::FrameAttachedToParent(this, ad_script_from_frame_creation_stack_);
  }
}

FrameScheduler* LocalFrame::GetFrameScheduler() {
  return frame_scheduler_.get();
}

EventHandlerRegistry& LocalFrame::GetEventHandlerRegistry() const {
  return event_handler_->GetEventHandlerRegistry();
}

scoped_refptr<base::SingleThreadTaskRunner> LocalFrame::GetTaskRunner(
    TaskType type) {
  DCHECK(IsMainThread());
  return frame_scheduler_->GetTaskRunner(type);
}

void LocalFrame::ScheduleVisualUpdateUnlessThrottled() {
  if (ShouldThrottleRendering())
    return;
  GetPage()->Animator().ScheduleVisualUpdate(this);
}

static bool CanAccessAncestor(const SecurityOrigin& active_security_origin,
                              const Frame* target_frame) {
  // targetFrame can be 0 when we're trying to navigate a top-level frame
  // that has a 0 opener.
  if (!target_frame)
    return false;

  const bool is_local_active_origin = active_security_origin.IsLocal();
  for (const Frame* ancestor_frame = target_frame; ancestor_frame;
       ancestor_frame = ancestor_frame->Tree().Parent()) {
    const SecurityOrigin* ancestor_security_origin =
        ancestor_frame->GetSecurityContext()->GetSecurityOrigin();
    if (active_security_origin.CanAccess(ancestor_security_origin))
      return true;

    // Allow file URL descendant navigation even when
    // allowFileAccessFromFileURLs is false.
    // FIXME: It's a bit strange to special-case local origins here. Should we
    // be doing something more general instead?
    if (is_local_active_origin && ancestor_security_origin->IsLocal())
      return true;
  }

  return false;
}

bool LocalFrame::CanNavigate(const Frame& target_frame,
                             const KURL& destination_url) {
  // https://html.spec.whatwg.org/multipage/browsers.html#allowed-to-navigate
  // If source is target, then return true.
  if (&target_frame == this)
    return true;

  // Navigating window.opener cross origin, without user activation. See
  // https://crbug.com/813643.
  if (Opener() == target_frame && !HasTransientUserActivation(this) &&
      !target_frame.GetSecurityContext()->GetSecurityOrigin()->CanAccess(
          SecurityOrigin::Create(destination_url).get())) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kOpenerNavigationWithoutGesture);
  }

  // Frames from different browsing context groups in the same CoopRelatedGroup
  // should not be able navigate one another.
  if (IsNavigationBlockedByCoopRestrictProperties(*this, target_frame)) {
    return false;
  }

  if (destination_url.ProtocolIsJavaScript() &&
      (!GetSecurityContext()->GetSecurityOrigin()->CanAccess(
          target_frame.GetSecurityContext()->GetSecurityOrigin()))) {
    PrintNavigationErrorMessage(
        target_frame,
        "The frame attempting navigation must be same-origin with the target "
        "if navigating to a javascript: url");
    return false;
  }

  if (GetSecurityContext()->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kNavigation)) {
    // 'allow-top-navigation' and 'allow-top-navigation-by-user-activation'
    // allow the outermost frame navigations. They don't allow root fenced frame
    // navigations from the descendant frames.
    const bool target_is_outermost_frame =
        target_frame.IsMainFrame() &&
        !target_frame.GetPage()->IsMainFrameFencedFrameRoot();

    if (!target_frame.Tree().IsDescendantOf(this) &&
        !target_is_outermost_frame) {
      PrintNavigationErrorMessage(
          target_frame,
          IsInFencedFrameTree()
              ? "The frame attempting navigation is in a fenced frame tree, "
                "and is therefore disallowed from navigating its ancestors."
              : "The frame attempting navigation is sandboxed, and is "
                "therefore "
                "disallowed from navigating its ancestors.");
      return false;
    }

    // Sandboxed frames can also navigate popups, if the
    // 'allow-sandbox-escape-via-popup' flag is specified, or if
    // 'allow-popups' flag is specified and the popup's opener is the frame.
    if (target_is_outermost_frame && target_frame != Tree().Top() &&
        GetSecurityContext()->IsSandboxed(
            network::mojom::blink::WebSandboxFlags::
                kPropagatesToAuxiliaryBrowsingContexts) &&
        (GetSecurityContext()->IsSandboxed(
             network::mojom::blink::WebSandboxFlags::kPopups) ||
         target_frame.Opener() != this)) {
      PrintNavigationErrorMessage(
          target_frame,
          "The frame attempting navigation is sandboxed and is trying "
          "to navigate a popup, but is not the popup's opener and is not "
          "set to propagate sandboxing to popups.");
      return false;
    }

    // Top navigation is forbidden in sandboxed frames unless opted-in, and only
    // then if the ancestor chain allowed to navigate the top frame.
    // Note: We don't check root fenced frames for kTop* flags since the kTop*
    // flags imply the actual top-level page.
    if ((target_frame == Tree().Top()) &&
        !target_frame.GetPage()->IsMainFrameFencedFrameRoot()) {
      if (GetSecurityContext()->IsSandboxed(
              network::mojom::blink::WebSandboxFlags::kTopNavigation) &&
          GetSecurityContext()->IsSandboxed(
              network::mojom::blink::WebSandboxFlags::
                  kTopNavigationByUserActivation)) {
        PrintNavigationErrorMessage(
            target_frame,
            "The frame attempting navigation of the top-level window is "
            "sandboxed, but the flag of 'allow-top-navigation' or "
            "'allow-top-navigation-by-user-activation' is not set.");
        return false;
      }

      // With only 'allow-top-navigation-by-user-activation' (but not
      // 'allow-top-navigation'), top navigation requires a user gesture.
      if (GetSecurityContext()->IsSandboxed(
              network::mojom::blink::WebSandboxFlags::kTopNavigation) &&
          !GetSecurityContext()->IsSandboxed(
              network::mojom::blink::WebSandboxFlags::
                  kTopNavigationByUserActivation)) {
        // If there is no user activation, fail.
        if (!HasTransientUserActivation(this)) {
          GetLocalFrameHostRemote().DidBlockNavigation(
              destination_url, mojom::blink::NavigationBlockedReason::
                                   kRedirectWithNoUserGestureSandbox);
          PrintNavigationErrorMessage(
              target_frame,
              "The frame attempting navigation of the top-level window is "
              "sandboxed with the 'allow-top-navigation-by-user-activation' "
              "flag, but has no user activation (aka gesture). See "
              "https://www.chromestatus.com/feature/5629582019395584.");
          return false;
        }
      }

      // With only 'allow-top-navigation':
      // This is a "last line of defense" to prevent a cross-origin document
      // from escalating its own top-navigation privileges. See
      // `PolicyContainerPolicies::can_navigate_top_without_user_gesture`
      // for the cases where this would be allowed or disallowed.
      // See (crbug.com/1145553) and (crbug.com/1251790).
      if (!DomWindow()
               ->GetExecutionContext()
               ->GetPolicyContainer()
               ->GetPolicies()
               .can_navigate_top_without_user_gesture &&
          !HasStickyUserActivation()) {
        String message =
            "The frame attempting to navigate the top-level window is "
            "cross-origin and either it or one of its ancestors is not "
            "allowed to navigate the top frame.\n";
        PrintNavigationErrorMessage(target_frame, message);
        return false;
      }
      return true;
    }
  }

  DCHECK(GetSecurityContext()->GetSecurityOrigin());
  const SecurityOrigin& origin = *GetSecurityContext()->GetSecurityOrigin();

  // This is the normal case. A document can navigate its decendant frames,
  // or, more generally, a document can navigate a frame if the document is
  // in the same origin as any of that frame's ancestors (in the frame
  // hierarchy).
  //
  // See http://www.adambarth.com/papers/2008/barth-jackson-mitchell.pdf for
  // historical information about this security check.
  if (CanAccessAncestor(origin, &target_frame))
    return true;

  // Top-level frames are easier to navigate than other frames because they
  // display their URLs in the address bar (in most browsers). However, there
  // are still some restrictions on navigation to avoid nuisance attacks.
  // Specifically, a document can navigate a top-level frame if that frame
  // opened the document or if the document is the same-origin with any of
  // the top-level frame's opener's ancestors (in the frame hierarchy).
  //
  // In both of these cases, the document performing the navigation is in
  // some way related to the frame being navigate (e.g., by the "opener"
  // and/or "parent" relation). Requiring some sort of relation prevents a
  // document from navigating arbitrary, unrelated top-level frames.
  if (!target_frame.Tree().Parent()) {
    if (target_frame == Opener())
      return true;
    if (CanAccessAncestor(origin, target_frame.Opener()))
      return true;
  }

  if (target_frame == Tree().Top()) {
    // A frame navigating its top may blocked if the document initiating
    // the navigation has never received a user gesture and the navigation
    // isn't same-origin with the target.
    if (HasStickyUserActivation() ||
        target_frame.GetSecurityContext()->GetSecurityOrigin()->CanAccess(
            SecurityOrigin::Create(destination_url).get())) {
      return true;
    }

    String target_domain = network_utils::GetDomainAndRegistry(
        target_frame.GetSecurityContext()->GetSecurityOrigin()->Domain(),
        network_utils::kIncludePrivateRegistries);
    String destination_domain = network_utils::GetDomainAndRegistry(
        destination_url.Host(), network_utils::kIncludePrivateRegistries);
    if (!target_domain.empty() && !destination_domain.empty() &&
        target_domain == destination_domain &&
        (target_frame.GetSecurityContext()->GetSecurityOrigin()->Protocol() ==
             destination_url.Protocol())) {
      return true;
    }

    if (loader_.GetDocumentLoader()->GetContentSettings()->allow_popup) {
      return true;
    }
    PrintNavigationErrorMessage(
        target_frame,
        "The frame attempting navigation is targeting its top-level window, "
        "but is neither same-origin with its target nor has it received a "
        "user gesture. See "
        "https://www.chromestatus.com/feature/5851021045661696.");
    GetLocalFrameHostRemote().DidBlockNavigation(
        destination_url,
        mojom::blink::NavigationBlockedReason::kRedirectWithNoUserGesture);

  } else {
    PrintNavigationErrorMessage(
        target_frame,
        "The frame attempting navigation is neither same-origin with the "
        "target, nor is it the target's parent or opener.");
  }
  return false;
}

void LocalFrame::MaybeStartOutermostMainFrameNavigation(
    const Vector<KURL>& urls) const {
  TRACE_EVENT0("navigation",
               "LocalFrame::MaybeStartOutermostMainFrameNavigation");
  mojo_handler_->NonAssociatedLocalFrameHostRemote()
      .MaybeStartOutermostMainFrameNavigation(urls);
}

ContentCaptureManager* LocalFrame::GetOrResetContentCaptureManager() {
  DCHECK(Client());
  if (!IsLocalRoot())
    return nullptr;

  // WebContentCaptureClient is set on each navigation and it could become null
  // because the url is in disallowed list, so ContentCaptureManager
  // is created or released as needed to save the resources.
  // It is a little bit odd that ContentCaptureManager is created or released on
  // demand, and that this is something that could be improved with an explicit
  // signal for creating / destroying content capture managers.
  if (Client()->GetWebContentCaptureClient()) {
    if (!content_capture_manager_) {
      content_capture_manager_ =
          MakeGarbageCollected<ContentCaptureManager>(*this);
    }
  } else if (content_capture_manager_) {
    content_capture_manager_->Shutdown();
    content_capture_manager_ = nullptr;
  }
  return content_capture_manager_.Get();
}

BrowserInterfaceBrokerProxy& LocalFrame::GetBrowserInterfaceBroker() {
  if (!browser_interface_broker_proxy_.is_bound()) {
    // This branch is taken in unit tests.
    return GetEmptyBrowserInterfaceBroker();
  }
  return browser_interface_broker_proxy_;
}

AssociatedInterfaceProvider*
LocalFrame::GetRemoteNavigationAssociatedInterfaces() {
  DCHECK(Client());
  return Client()->GetRemoteNavigationAssociatedInterfaces();
}

LocalFrameClient* LocalFrame::Client() const {
  return static_cast<LocalFrameClient*>(Frame::Client());
}

FrameWidget* LocalFrame::GetWidgetForLocalRoot() {
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(this);
  if (!web_frame)
    return nullptr;
  // This WebFrameWidgetImpl upcasts to a FrameWidget which is the interface
  // exposed to Blink core.
  return web_frame->LocalRootFrameWidget();
}

WebContentSettingsClient* LocalFrame::GetContentSettingsClient() {
  return Client() ? Client()->GetContentSettingsClient() : nullptr;
}

PluginData* LocalFrame::GetPluginData() const {
  if (!Loader().AllowPlugins())
    return nullptr;
  return GetPage()->GetPluginData();
}

void LocalFrame::SetAdTrackerForTesting(AdTracker* ad_tracker) {
  if (ad_tracker_)
    ad_tracker_->Shutdown();
  ad_tracker_ = ad_tracker;
}

DEFINE_WEAK_IDENTIFIER_MAP(LocalFrame)

FrameNavigationDisabler::FrameNavigationDisabler(LocalFrame& frame)
    : frame_(&frame) {
  frame_->DisableNavigation();
}

FrameNavigationDisabler::~FrameNavigationDisabler() {
  frame_->EnableNavigation();
}

LocalFrame::LazyLoadImageSetting LocalFrame::GetLazyLoadImageSetting() const {
  DCHECK(GetSettings());
  if (!GetSettings()->GetLazyLoadEnabled()) {
    return LocalFrame::LazyLoadImageSetting::kDisabled;
  }

  // Disable explicit and automatic lazyload for backgrounded pages including
  // NoStatePrefetch and Prerender.
  if (!GetDocument()->IsPageVisible()) {
    return LocalFrame::LazyLoadImageSetting::kDisabled;
  }

  return LocalFrame::LazyLoadImageSetting::kEnabledExplicit;
}

scoped_refptr<network::SharedURLLoaderFactory>
LocalFrame::GetURLLoaderFactory() {
  return Client()->GetURLLoaderFactory();
}

std::unique_ptr<URLLoader> LocalFrame::CreateURLLoaderForTesting() {
  return Client()->CreateURLLoaderForTesting();
}

scoped_refptr<WebBackgroundResourceFetchAssets>
LocalFrame::MaybeGetBackgroundResourceFetchAssets() {
  return Client()->MaybeGetBackgroundResourceFetchAssets();
}

WebPluginContainerImpl* LocalFrame::GetWebPluginContainer(Node* node) const {
  if (auto* plugin_document = DynamicTo<PluginDocument>(GetDocument())) {
    return plugin_document->GetPluginView();
  }
  if (!node) {
    DCHECK(GetDocument());
    node = GetDocument()->FocusedElement();
  }

  if (node) {
    return node->GetWebPluginContainer();
  }
  return nullptr;
}

void LocalFrame::WasHidden() {
  if (hidden_)
    return;
  hidden_ = true;

  if (auto* content_capture_manager = GetOrResetContentCaptureManager()) {
    content_capture_manager->OnFrameWasHidden();
  }

  // An iframe may get a "was hidden" notification before it has been attached
  // to the frame tree; in that case, skip further processing.
  if (!Owner() || IsProvisional())
    return;

  // Mark intersections as dirty, so that child frames will reevaluate their
  // render throttling status on the next lifecycle update.
  LocalFrameView* frame_view = View();
  if (frame_view)
    frame_view->SetIntersectionObservationState(LocalFrameView::kDesired);

  // If we are tracking occlusion for this frame, and it was not previously
  // known to be occluded, then we need to force "not visible" notifications to
  // be sent, since it's unknown whether this frame will run lifecycle updates.

  // Frame was already occluded, nothing more to do.
  if (intersection_state_.occlusion_state ==
      mo
"""


```