Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `local_frame_view.cc`. This is part 5 of 6, implying the previous parts have established other functionalities of this class. I need to identify the core responsibilities demonstrated in this specific section of the code.

Looking at the code, the primary focus is on:

1. **Coordinate Transformations:**  Functions like `DocumentToFrame`, `FrameToDocument`, `ConvertToContainingEmbeddedContentView`, `ConvertFromContainingEmbeddedContentView`, `ConvertToRootFrame`, `ConvertFromRootFrame`, `ViewportToFrame`, `FrameToViewport`, and `FrameToScreen` deal with converting points and rectangles between different coordinate systems (document, frame, embedded content, root frame, viewport, screen).

2. **Scroll Handling:**  Functions like `ServiceScrollAnimations`, `AddScrollAnchoringScrollableArea`, `RemoveScrollAnchoringScrollableArea`, `AddAnimatingScrollableArea`, `RemoveAnimatingScrollableArea`, `AddScrollableArea`, `RemoveScrollableArea`, `AddUserScrollableArea`, `RemoveUserScrollableArea`, `ScrollRectToVisibleInRemoteParent`, `DidChangeScrollOffset`, and `ScrollableAreaWithElementId` manage and interact with scrollable areas within the frame.

3. **Visibility Management:** Functions like `AttachToLayout`, `DetachFromLayout`, `ParentVisibleChanged`, `SelfVisibleChanged`, `Show`, and `Hide` control the visibility of the frame and its impact on child frames.

4. **Painting and Compositing:** Functions like `SetTracksRasterInvalidations`, `Paint`, `PaintFrame`, `PrintPage`, `PaintOutsideOfLifecycle`, `PaintForTest`, `GetPaintRecord`, and `GetPaintArtifact` are involved in the painting and compositing processes, including handling paint previews.

5. **Event Scheduling:**  The `ScheduleAnimation` function is used to schedule animations.

6. **Plugin Management:**  Functions `AddPlugin` and `RemovePlugin` manage browser plugins associated with the frame.

7. **Coordinate System Utility:** Functions like `ViewportWidth`, `ViewportHeight`, and `GetScrollableArea` provide information about the frame's dimensions and scrollable areas.

8. **Intersection Observation:** The `UpdateViewportIntersectionsForSubtree` function handles the logic for intersection observers.

I need to summarize these functionalities concisely, provide examples relating to JavaScript, HTML, and CSS, illustrate logical reasoning with input/output examples, point out potential usage errors, and finally, provide a concluding summary for this specific part of the code.
这是 `blink/renderer/core/frame/local_frame_view.cc` 源代码文件的第 5 部分，主要功能集中在**坐标空间转换、滚动管理、视图的可见性控制、绘制以及与父框架和根框架的交互**。

以下是具体的功能列举和说明：

**1. 坐标空间转换：**

该部分代码定义了多个方法用于在不同的坐标空间之间进行转换，这对于正确渲染和处理用户交互至关重要。

*   **DocumentToFrame:** 将文档坐标系中的点或矩形转换为当前框架坐标系。
    *   **假设输入：**  鼠标在文档中的位置 (100, 200)。
    *   **输出：**  如果当前框架没有滚动，则在框架坐标系中也是 (100, 200)。如果框架水平滚动了 50px，垂直滚动了 100px，则输出为 (50, 100)。
    *   **与 JavaScript 关系：** 当 JavaScript 获取 `event.clientX` 和 `event.clientY` (文档坐标) 后，如果需要相对于特定 iframe 的位置，就需要进行这种转换。
    *   **与 HTML 关系：**  确定元素在 iframe 内部的绝对位置。
    *   **与 CSS 关系：**  计算固定定位元素在 iframe 中的位置。
*   **FrameToDocument:** 将当前框架坐标系中的点或矩形转换为文档坐标系。
    *   **假设输入：**  鼠标在 iframe 内部的位置 (30, 50)。 iframe 在文档中水平偏移 70px，垂直偏移 120px，iframe 自身没有滚动。
    *   **输出：**  在文档坐标系中为 (100, 170)。
    *   **与 JavaScript 关系：**  当需要将 iframe 内部的坐标转换为相对于整个文档的坐标时使用。
*   **ConvertToContainingEmbeddedContentView:** 将当前框架的局部坐标转换为其父框架嵌入内容视图的坐标。这涉及到考虑父框架的边框、内边距等。
    *   **假设输入：**  iframe 内部的一个矩形 {x: 10, y: 10, width: 50, height: 50}。父框架的 iframe 元素有 5px 的边框。
    *   **输出：**  在父框架的嵌入内容视图中，该矩形可能变为 {x: 15, y: 15, width: 50, height: 50}。
    *   **与 HTML 关系：**  处理嵌套 iframe 的定位。
    *   **与 CSS 关系：**  与 iframe 的边框和内边距相关。
*   **ConvertFromContainingEmbeddedContentView:** 将父框架嵌入内容视图的坐标转换回当前框架的局部坐标。
    *   **假设输入：**  父框架传递下来的一个矩形坐标。
    *   **输出：**  该矩形在当前 iframe 内部的相对位置。
*   **ConvertToRootFrame:** 将当前框架的局部坐标转换为根框架（通常是主文档）的坐标。会递归地向上遍历父框架进行转换。
    *   **与 JavaScript 关系：**  确定元素相对于主文档的位置，例如用于跨 iframe 通信时的坐标传递。
*   **ConvertFromRootFrame:** 将根框架的坐标转换回当前框架的局部坐标。
*   **ViewportToFrame:** 将视口坐标转换为当前框架坐标。
    *   **与 JavaScript 关系：**  处理基于视口坐标的事件，并将其转换为当前 iframe 内部的坐标。
*   **FrameToViewport:** 将当前框架坐标转换为视口坐标。
*   **FrameToScreen:** 将当前框架坐标转换为屏幕坐标。
    *   **与 JavaScript 关系：**  某些需要屏幕绝对位置的操作，例如弹出窗口的定位。

**2. 滚动管理：**

*   **ServiceScrollAnimations:**  处理当前框架及其子框架中正在进行的滚动动画。
    *   **与 JavaScript 关系：**  响应 `window.scrollTo()`, `element.scrollTo()` 或 CSS scroll-behavior 触发的动画。
    *   **假设：**  页面上有一个元素正在使用 CSS `scroll-behavior: smooth;` 进行滚动。
    *   **输出：**  该函数会在每一帧更新滚动位置，产生平滑的滚动效果。
*   **AddScrollAnchoringScrollableArea / RemoveScrollAnchoringScrollableArea:**  管理参与滚动锚定的可滚动区域。滚动锚定是一种防止页面布局在滚动时发生意外跳跃的技术。
*   **AddAnimatingScrollableArea / RemoveAnimatingScrollableArea:** 管理正在进行动画的可滚动区域。
*   **AddScrollableArea / RemoveScrollableArea / AddUserScrollableArea / RemoveUserScrollableArea:**  管理框架中可滚动区域的集合。
*   **ScrollRectToVisibleInRemoteParent:** 当需要将一个矩形滚动到在远程父框架中可见时调用。
    *   **假设输入：**  当前 iframe 中的某个矩形区域需要滚动到在父 iframe 中可见。
    *   **输出：**  向父框架发送消息，指示其滚动相应的区域。
*   **DidChangeScrollOffset:**  当框架的滚动偏移发生变化时通知客户端。
    *   **与 JavaScript 关系：**  触发 `scroll` 事件。
*   **ScrollableAreaWithElementId:**  根据元素的 ID 查找可滚动区域。

**3. 视图的可见性控制：**

*   **AttachToLayout / DetachFromLayout:**  当框架被添加到布局树或从布局树移除时调用，会更新可见性状态。
*   **ParentVisibleChanged / SelfVisibleChanged:**  当父框架或当前框架的可见性发生变化时调用，并通知子框架。
*   **Show / Hide:**  显式地显示或隐藏当前框架。
    *   **与 CSS 关系：**  类似于设置 `display: block` 或 `display: none`，但由 Blink 内部管理。

**4. 绘制和 Compositing：**

*   **SetTracksRasterInvalidations:**  控制是否跟踪栅格化失效，用于性能分析和调试。
*   **Paint / PaintFrame:**  执行框架的绘制操作。`Paint` 方法会检查裁剪矩形，并调用 `PaintFrame` 进行实际绘制。
    *   **与 CSS 关系：**  CSS 样式决定了元素的绘制方式和外观。
*   **PrintPage:**  在打印页面时执行绘制。
*   **PaintOutsideOfLifecycle:**  在生命周期之外执行绘制，通常用于特定的场景，如打印或生成预览。
*   **PaintForTest:**  用于测试目的的绘制。
*   **GetPaintRecord / GetPaintArtifact:**  获取绘制记录和绘制产物，用于调试和分析。
*   **CapturePaintPreview:**  用于捕获嵌入式内容的绘制预览，用于优化加载和渲染性能。

**5. 与父框架和根框架的交互：**

*   上述的坐标转换方法和服务于这种交互。
*   **PropagateFrameRects:**  将框架的矩形信息传递给子框架和插件。
    *   **与 HTML 关系：**  确保嵌套的 iframe 正确布局和渲染。
*   **ScrollRectToVisibleInRemoteParent:** 上文已述。
*   **ConvertToRootFrame / ConvertFromRootFrame:**  实现与根框架的坐标转换。

**6. 其他功能：**

*   **ScheduleAnimation:**  安排动画的执行。
    *   **与 JavaScript 关系：**  与 `requestAnimationFrame` 类似，但由 Blink 内部管理。
*   **OnCommitRequested:** 当提交请求时被调用。
*   **AddPlugin / RemovePlugin:**  管理附加到此框架视图的浏览器插件。
*   **AddScrollbar / RemoveScrollbar:** 管理框架的滚动条。
*   **VisualViewportSuppliesScrollbars:**  判断视觉视口是否提供滚动条。
*   **ExistingAXObjectCache:**  获取可访问性对象缓存。
*   **SetCursor:**  设置鼠标光标。
    *   **与 CSS 关系：**  响应 CSS 的 `cursor` 属性。
*   **ZoomFactorChanged:**  当缩放因子改变时被调用。
*   **SetLayoutSizeInternal:**  设置布局大小。
    *   **与 CSS 关系：**  与 CSS 中设置的宽度和高度相关。
*   **ViewportWidth / ViewportHeight:**  获取视口的宽度和高度。
*   **GetScrollableArea / LayoutViewport / GetRootFrameViewport:**  获取不同类型的可滚动区域对象。
*   **CollectDraggableRegions:**  收集可拖拽区域。
*   **UpdateViewportIntersectionsForSubtree:**  更新子树的视口交叉信息，用于 Intersection Observer API。

**逻辑推理的例子：**

假设一个 iframe 内部有一个按钮，JavaScript 需要获取该按钮在主文档中的绝对位置。

*   **输入：**  按钮在 iframe 内部的坐标 (button_x, button_y)。iframe 在文档中的偏移量 (iframe_offset_x, iframe_offset_y)。
*   **处理步骤：**
    1. 使用 `FrameToDocument` 将按钮在 iframe 内部的坐标转换为文档坐标： `document_x = button_x + iframe_scroll_x; document_y = button_y + iframe_scroll_y;` (假设 iframe 没有父框架)。
    2. 如果 iframe 嵌套在其他 iframe 中，则需要递归地向上进行 `ConvertToContainingEmbeddedContentView` 或 `ConvertToRootFrame` 转换。
*   **输出：**  按钮在主文档中的绝对坐标。

**用户或编程常见的使用错误举例：**

*   **坐标转换方向错误：**  错误地使用了 `DocumentToFrame` 而不是 `FrameToDocument`，或者在嵌套 iframe 中没有正确处理多层转换，导致获取的坐标不准确。
*   **忘记考虑滚动偏移：**  在进行坐标转换时，没有考虑框架自身的滚动偏移，导致计算结果错误。
*   **在不合适的时机调用绘制方法：**  例如，在生命周期早期或晚期调用 `PaintOutsideOfLifecycle` 可能会导致状态不一致或崩溃。

**本部分功能归纳：**

这部分 `LocalFrameView` 的代码主要负责管理和维护框架的**视觉和交互属性**，包括在不同坐标系之间进行精确的转换，处理框架内的滚动行为，控制框架的可见性，以及执行绘制操作。它还处理了与父框架和根框架的交互，确保了嵌套框架环境下的正确渲染和事件处理。 这些功能是 Web 浏览器正确渲染页面内容、响应用户交互以及实现复杂页面布局的基础。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
 const gfx::Point& point_in_document) const {
  return gfx::ToFlooredPoint(DocumentToFrame(gfx::PointF(point_in_document)));
}

gfx::PointF LocalFrameView::DocumentToFrame(
    const gfx::PointF& point_in_document) const {
  ScrollableArea* layout_viewport = LayoutViewport();
  if (!layout_viewport)
    return point_in_document;

  return point_in_document - layout_viewport->GetScrollOffset();
}

PhysicalOffset LocalFrameView::DocumentToFrame(
    const PhysicalOffset& offset_in_document) const {
  ScrollableArea* layout_viewport = LayoutViewport();
  if (!layout_viewport)
    return offset_in_document;

  return offset_in_document -
         PhysicalOffset::FromVector2dFRound(layout_viewport->GetScrollOffset());
}

PhysicalRect LocalFrameView::DocumentToFrame(
    const PhysicalRect& rect_in_document) const {
  return PhysicalRect(DocumentToFrame(rect_in_document.offset),
                      rect_in_document.size);
}

gfx::Point LocalFrameView::FrameToDocument(
    const gfx::Point& point_in_frame) const {
  return ToFlooredPoint(FrameToDocument(PhysicalOffset(point_in_frame)));
}

PhysicalOffset LocalFrameView::FrameToDocument(
    const PhysicalOffset& offset_in_frame) const {
  ScrollableArea* layout_viewport = LayoutViewport();
  if (!layout_viewport)
    return offset_in_frame;

  return offset_in_frame +
         PhysicalOffset::FromVector2dFRound(layout_viewport->GetScrollOffset());
}

gfx::Rect LocalFrameView::FrameToDocument(
    const gfx::Rect& rect_in_frame) const {
  return gfx::Rect(FrameToDocument(rect_in_frame.origin()),
                   rect_in_frame.size());
}

PhysicalRect LocalFrameView::FrameToDocument(
    const PhysicalRect& rect_in_frame) const {
  return PhysicalRect(FrameToDocument(rect_in_frame.offset),
                      rect_in_frame.size);
}

gfx::Rect LocalFrameView::ConvertToContainingEmbeddedContentView(
    const gfx::Rect& local_rect) const {
  if (ParentFrameView()) {
    auto* layout_object = GetLayoutEmbeddedContent();
    if (!layout_object)
      return local_rect;

    // Add borders and padding etc.
    gfx::Rect rect = layout_object->BorderBoxFromEmbeddedContent(local_rect);
    return ToPixelSnappedRect(
        layout_object->LocalToAbsoluteRect(PhysicalRect(rect)));
  }

  return local_rect;
}

gfx::Rect LocalFrameView::ConvertFromContainingEmbeddedContentView(
    const gfx::Rect& parent_rect) const {
  if (ParentFrameView()) {
    gfx::Rect local_rect = parent_rect;
    local_rect.Offset(-Location().OffsetFromOrigin());
    return local_rect;
  }
  return parent_rect;
}

PhysicalOffset LocalFrameView::ConvertToContainingEmbeddedContentView(
    const PhysicalOffset& local_offset) const {
  if (ParentFrameView()) {
    auto* layout_object = GetLayoutEmbeddedContent();
    if (!layout_object)
      return local_offset;

    PhysicalOffset point(local_offset);
    // Add borders and padding etc.
    point = layout_object->BorderBoxFromEmbeddedContent(point);
    return layout_object->LocalToAbsolutePoint(point);
  }

  return local_offset;
}

gfx::PointF LocalFrameView::ConvertToContainingEmbeddedContentView(
    const gfx::PointF& local_point) const {
  if (ParentFrameView()) {
    auto* layout_object = GetLayoutEmbeddedContent();
    if (!layout_object)
      return local_point;

    PhysicalOffset point = PhysicalOffset::FromPointFRound(local_point);
    // Add borders and padding etc.
    point = layout_object->BorderBoxFromEmbeddedContent(point);
    return static_cast<gfx::PointF>(layout_object->LocalToAbsolutePoint(point));
  }

  return local_point;
}

PhysicalOffset LocalFrameView::ConvertFromContainingEmbeddedContentView(
    const PhysicalOffset& parent_offset) const {
  return PhysicalOffset::FromPointFRound(
      ConvertFromContainingEmbeddedContentView(gfx::PointF(parent_offset)));
}

gfx::PointF LocalFrameView::ConvertFromContainingEmbeddedContentView(
    const gfx::PointF& parent_point) const {
  if (ParentFrameView()) {
    // Get our layoutObject in the parent view
    auto* layout_object = GetLayoutEmbeddedContent();
    if (!layout_object)
      return parent_point;

    gfx::PointF point = layout_object->AbsoluteToLocalPoint(parent_point);
    // Subtract borders and padding etc.
    point = layout_object->EmbeddedContentFromBorderBox(point);
    return point;
  }

  return parent_point;
}

void LocalFrameView::SetTracksRasterInvalidations(
    bool track_raster_invalidations) {
  if (!GetFrame().IsLocalRoot()) {
    GetFrame().LocalFrameRoot().View()->SetTracksRasterInvalidations(
        track_raster_invalidations);
    return;
  }
  if (track_raster_invalidations == is_tracking_raster_invalidations_)
    return;

  // Ensure the document is up-to-date before tracking invalidations.
  UpdateAllLifecyclePhasesForTest();

  is_tracking_raster_invalidations_ = track_raster_invalidations;
  if (paint_artifact_compositor_) {
    paint_artifact_compositor_->SetTracksRasterInvalidations(
        track_raster_invalidations);
  }

  TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("blink.invalidation"),
                       "LocalFrameView::setTracksPaintInvalidations",
                       TRACE_EVENT_SCOPE_GLOBAL, "enabled",
                       track_raster_invalidations);
}

void LocalFrameView::ServiceScrollAnimations(base::TimeTicks start_time) {
  bool can_throttle = CanThrottleRendering();
  // Disallow throttling in case any script needs to do a synchronous
  // lifecycle update in other frames which are throttled.
  DisallowThrottlingScope disallow_throttling(*this);
  Document* document = GetFrame().GetDocument();
  DCHECK(document);
  if (!can_throttle) {
    if (ScrollableArea* scrollable_area = GetScrollableArea()) {
      scrollable_area->ServiceScrollAnimations(
          start_time.since_origin().InSecondsF());
    }
    if (const ScrollableAreaSet* animating_scrollable_areas =
            AnimatingScrollableAreas()) {
      // Iterate over a copy, since ScrollableAreas may deregister
      // themselves during the iteration.
      HeapVector<Member<PaintLayerScrollableArea>>
          animating_scrollable_areas_copy(*animating_scrollable_areas);
      for (PaintLayerScrollableArea* scrollable_area :
           animating_scrollable_areas_copy) {
        scrollable_area->ServiceScrollAnimations(
            start_time.since_origin().InSecondsF());
      }
    }
    // After scroll updates, snapshot scroll state once at top of animation
    // frame.
    GetFrame().UpdateScrollSnapshots();

    if (SVGDocumentExtensions::ServiceSmilOnAnimationFrame(*document))
      GetPage()->Animator().SetHasSmilAnimation();
    SVGDocumentExtensions::ServiceWebAnimationsOnAnimationFrame(*document);
    document->GetDocumentAnimations().UpdateAnimationTimingForAnimationFrame();
  }
}

void LocalFrameView::ScheduleAnimation(base::TimeDelta delay,
                                       base::Location location) {
  TRACE_EVENT("cc", "LocalFrameView::ScheduleAnimation", "frame", GetFrame(),
              "delay", delay, "location", location);
  if (auto* client = GetChromeClient())
    client->ScheduleAnimation(this, delay);
}

void LocalFrameView::OnCommitRequested() {
  DCHECK(frame_->IsLocalRoot());
  if (frame_->GetDocument() &&
      !frame_->GetDocument()->IsInitialEmptyDocument() && GetUkmAggregator()) {
    GetUkmAggregator()->OnCommitRequested();
  }
}

void LocalFrameView::AddScrollAnchoringScrollableArea(
    PaintLayerScrollableArea* scrollable_area) {
  DCHECK(scrollable_area);
  if (!scroll_anchoring_scrollable_areas_) {
    scroll_anchoring_scrollable_areas_ =
        MakeGarbageCollected<ScrollableAreaSet>();
  }
  scroll_anchoring_scrollable_areas_->insert(scrollable_area);
}

void LocalFrameView::RemoveScrollAnchoringScrollableArea(
    PaintLayerScrollableArea* scrollable_area) {
  if (scroll_anchoring_scrollable_areas_)
    scroll_anchoring_scrollable_areas_->erase(scrollable_area);
}

void LocalFrameView::AddAnimatingScrollableArea(
    PaintLayerScrollableArea* scrollable_area) {
  DCHECK(scrollable_area);
  if (!animating_scrollable_areas_)
    animating_scrollable_areas_ = MakeGarbageCollected<ScrollableAreaSet>();
  animating_scrollable_areas_->insert(scrollable_area);
}

void LocalFrameView::RemoveAnimatingScrollableArea(
    PaintLayerScrollableArea* scrollable_area) {
  if (!animating_scrollable_areas_)
    return;
  animating_scrollable_areas_->erase(scrollable_area);
}

void LocalFrameView::AddScrollableArea(
    PaintLayerScrollableArea& scrollable_area) {
  CHECK(RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled());
  scrollable_areas_.insert(scrollable_area.GetScrollElementId(),
                           scrollable_area);
}

void LocalFrameView::RemoveScrollableArea(
    PaintLayerScrollableArea& scrollable_area) {
  scrollable_areas_.erase(scrollable_area.GetScrollElementId());
  RemoveScrollAnchoringScrollableArea(&scrollable_area);
  RemoveAnimatingScrollableArea(&scrollable_area);
  RemovePendingSnapUpdate(&scrollable_area);
}

void LocalFrameView::AddUserScrollableArea(
    PaintLayerScrollableArea& scrollable_area) {
  CHECK(!RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled());
  scrollable_areas_.insert(scrollable_area.GetScrollElementId(),
                           &scrollable_area);
}

void LocalFrameView::RemoveUserScrollableArea(
    PaintLayerScrollableArea& scrollable_area) {
  CHECK(!RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled());
  scrollable_areas_.erase(scrollable_area.GetScrollElementId());
}

void LocalFrameView::AttachToLayout() {
  CHECK(!IsAttached());
  if (frame_->GetDocument())
    CHECK_NE(Lifecycle().GetState(), DocumentLifecycle::kStopping);
  SetAttached(true);
  LocalFrameView* parent_view = ParentFrameView();
  CHECK(parent_view);
  if (parent_view->IsVisible())
    SetParentVisible(true);
  UpdateRenderThrottlingStatus(IsHiddenForThrottling(),
                               parent_view->CanThrottleRendering(),
                               IsDisplayLocked());

  // This is to handle a special case: a display:none iframe may have a fully
  // populated layout tree if it contains an <embed>. In that case, we must
  // ensure that the embed's compositing layer is properly reattached.
  // crbug.com/749737 for context.
  if (auto* layout_view = GetLayoutView())
    layout_view->Layer()->SetNeedsCompositingInputsUpdate();

  // We may have updated paint properties in detached frame subtree for
  // printing (see UpdateLifecyclePhasesForPrinting()). The paint properties
  // may change after the frame is attached.
  if (auto* layout_view = GetLayoutView()) {
    layout_view->AddSubtreePaintPropertyUpdateReason(
        SubtreePaintPropertyUpdateReason::kPrinting);
  }
}

void LocalFrameView::DetachFromLayout() {
  CHECK(IsAttached());
  SetParentVisible(false);
  SetAttached(false);

  // We may need update paint properties in detached frame subtree for printing.
  // See UpdateLifecyclePhasesForPrinting().
  if (auto* layout_view = GetLayoutView()) {
    layout_view->AddSubtreePaintPropertyUpdateReason(
        SubtreePaintPropertyUpdateReason::kPrinting);
  }
}

void LocalFrameView::AddPlugin(WebPluginContainerImpl* plugin) {
  DCHECK(!plugins_.Contains(plugin));
  plugins_.insert(plugin);
}

void LocalFrameView::RemovePlugin(WebPluginContainerImpl* plugin) {
  DCHECK(plugins_.Contains(plugin));
  plugins_.erase(plugin);
}

void LocalFrameView::RemoveScrollbar(Scrollbar* scrollbar) {
  DCHECK(scrollbars_.Contains(scrollbar));
  scrollbars_.erase(scrollbar);
}

void LocalFrameView::AddScrollbar(Scrollbar* scrollbar) {
  DCHECK(!scrollbars_.Contains(scrollbar));
  scrollbars_.insert(scrollbar);
}

bool LocalFrameView::VisualViewportSuppliesScrollbars() {
  // On desktop, we always use the layout viewport's scrollbars.
  if (!frame_->GetSettings() || !frame_->GetSettings()->GetViewportEnabled() ||
      !frame_->GetDocument() || !frame_->GetPage())
    return false;

  if (!LayoutViewport())
    return false;

  const TopDocumentRootScrollerController& controller =
      frame_->GetPage()->GlobalRootScrollerController();
  return controller.RootScrollerArea() == LayoutViewport();
}

AXObjectCache* LocalFrameView::ExistingAXObjectCache() const {
  if (GetFrame().GetDocument())
    return GetFrame().GetDocument()->ExistingAXObjectCache();
  return nullptr;
}

void LocalFrameView::SetCursor(const ui::Cursor& cursor) {
  Page* page = GetFrame().GetPage();
  if (!page || frame_->GetEventHandler().IsMousePositionUnknown())
    return;
  LogCursorSizeCounter(&GetFrame(), cursor);
  page->GetChromeClient().SetCursor(cursor, frame_);
}

void LocalFrameView::PropagateFrameRects() {
  TRACE_EVENT0("blink", "LocalFrameView::PropagateFrameRects");
  if (LayoutSizeFixedToFrameSize())
    SetLayoutSizeInternal(Size());

  ForAllChildViewsAndPlugins([](EmbeddedContentView& view) {
    auto* local_frame_view = DynamicTo<LocalFrameView>(view);
    if (!local_frame_view || !local_frame_view->ShouldThrottleRendering()) {
      view.PropagateFrameRects();
    }
  });

  // To limit the number of Mojo communications, only notify the browser when
  // the rect's size changes, not when the position changes. The size needs to
  // be replicated if the iframe goes out-of-process.
  gfx::Size frame_size = FrameRect().size();
  if (!frame_size_ || *frame_size_ != frame_size) {
    frame_size_ = frame_size;
    GetFrame().GetLocalFrameHostRemote().FrameSizeChanged(frame_size);
  }
}

void LocalFrameView::ZoomFactorChanged(float zoom_factor) {
  GetFrame().SetLayoutZoomFactor(zoom_factor);
}

void LocalFrameView::SetLayoutSizeInternal(const gfx::Size& size) {
  if (layout_size_ == size)
    return;
  layout_size_ = size;
  SetNeedsLayout();
  Document* document = GetFrame().GetDocument();
  if (!document || !document->IsActive())
    return;
  document->LayoutViewportWasResized();
  if (frame_->IsMainFrame())
    TextAutosizer::UpdatePageInfoInAllFrames(frame_);
}

void LocalFrameView::DidChangeScrollOffset() {
  GetFrame().Client()->DidChangeScrollOffset();
  if (GetFrame().IsOutermostMainFrame()) {
    GetFrame()
        .GetPage()
        ->GetChromeClient()
        .OutermostMainFrameScrollOffsetChanged();
  }
}

ScrollableArea* LocalFrameView::ScrollableAreaWithElementId(
    const CompositorElementId& id) {
  if (!RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled()) {
    // Check for the layout viewport, which may not be in scrollable_areas_
    // if it is styled overflow: hidden.  (Other overflow: hidden elements won't
    // have composited scrolling layers per crbug.com/784053, so we don't have
    // to worry about them.)
    ScrollableArea* viewport = LayoutViewport();
    if (id == viewport->GetScrollElementId()) {
      return viewport;
    }
  }

  auto it = scrollable_areas_.find(id);
  if (it != scrollable_areas_.end()) {
    return it->value;
  }
  return nullptr;
}

void LocalFrameView::ScrollRectToVisibleInRemoteParent(
    const PhysicalRect& rect_to_scroll,
    mojom::blink::ScrollIntoViewParamsPtr params) {
  DCHECK(GetFrame().IsLocalRoot());
  DCHECK(!GetFrame().IsOutermostMainFrame());

  // If the scroll doesn't cross origin boundaries then it must already have
  // been blocked for a scroll crossing an embedded frame tree boundary.
  DCHECK(params->cross_origin_boundaries ||
         (!GetFrame().IsMainFrame() || GetFrame().IsOutermostMainFrame()));

  DCHECK(params->cross_origin_boundaries ||
         GetFrame()
             .Tree()
             .Parent()
             ->GetSecurityContext()
             ->GetSecurityOrigin()
             ->CanAccess(GetFrame().GetSecurityContext()->GetSecurityOrigin()));
  PhysicalRect new_rect = ConvertToRootFrame(rect_to_scroll);
  GetFrame().GetLocalFrameHostRemote().ScrollRectToVisibleInParentFrame(
      gfx::RectF(new_rect), std::move(params));
}

void LocalFrameView::NotifyFrameRectsChangedIfNeeded() {
  if (root_layer_did_scroll_) {
    root_layer_did_scroll_ = false;
    PropagateFrameRects();
  }
}

PhysicalOffset LocalFrameView::ViewportToFrame(
    const PhysicalOffset& point_in_viewport) const {
  PhysicalOffset point_in_root_frame = PhysicalOffset::FromPointFRound(
      frame_->GetPage()->GetVisualViewport().ViewportToRootFrame(
          gfx::PointF(point_in_viewport)));
  return ConvertFromRootFrame(point_in_root_frame);
}

gfx::PointF LocalFrameView::ViewportToFrame(
    const gfx::PointF& point_in_viewport) const {
  gfx::PointF point_in_root_frame(
      frame_->GetPage()->GetVisualViewport().ViewportToRootFrame(
          point_in_viewport));
  return ConvertFromRootFrame(point_in_root_frame);
}

gfx::Rect LocalFrameView::ViewportToFrame(
    const gfx::Rect& rect_in_viewport) const {
  gfx::Rect rect_in_root_frame =
      frame_->GetPage()->GetVisualViewport().ViewportToRootFrame(
          rect_in_viewport);
  return ConvertFromRootFrame(rect_in_root_frame);
}

gfx::Point LocalFrameView::ViewportToFrame(
    const gfx::Point& point_in_viewport) const {
  return ToRoundedPoint(ViewportToFrame(PhysicalOffset(point_in_viewport)));
}

gfx::Rect LocalFrameView::FrameToViewport(
    const gfx::Rect& rect_in_frame) const {
  gfx::Rect rect_in_root_frame = ConvertToRootFrame(rect_in_frame);
  return frame_->GetPage()->GetVisualViewport().RootFrameToViewport(
      rect_in_root_frame);
}

gfx::Point LocalFrameView::FrameToViewport(
    const gfx::Point& point_in_frame) const {
  gfx::Point point_in_root_frame = ConvertToRootFrame(point_in_frame);
  return frame_->GetPage()->GetVisualViewport().RootFrameToViewport(
      point_in_root_frame);
}

gfx::PointF LocalFrameView::FrameToViewport(
    const gfx::PointF& point_in_frame) const {
  gfx::PointF point_in_root_frame = ConvertToRootFrame(point_in_frame);
  return frame_->GetPage()->GetVisualViewport().RootFrameToViewport(
      point_in_root_frame);
}

gfx::Rect LocalFrameView::FrameToScreen(const gfx::Rect& rect) const {
  if (auto* client = GetChromeClient())
    return client->LocalRootToScreenDIPs(ConvertToRootFrame(rect), this);
  return gfx::Rect();
}

gfx::Point LocalFrameView::SoonToBeRemovedUnscaledViewportToContents(
    const gfx::Point& point_in_viewport) const {
  gfx::Point point_in_root_frame = gfx::ToFlooredPoint(
      frame_->GetPage()->GetVisualViewport().ViewportCSSPixelsToRootFrame(
          gfx::PointF(point_in_viewport)));
  return ConvertFromRootFrame(point_in_root_frame);
}

LocalFrameView::AllowThrottlingScope::AllowThrottlingScope(
    const LocalFrameView& frame_view)
    : value_(&frame_view.GetFrame().LocalFrameRoot().View()->allow_throttling_,
             true) {}

LocalFrameView::DisallowThrottlingScope::DisallowThrottlingScope(
    const LocalFrameView& frame_view)
    : value_(&frame_view.GetFrame().LocalFrameRoot().View()->allow_throttling_,
             false) {}

LocalFrameView::ForceThrottlingScope::ForceThrottlingScope(
    const LocalFrameView& frame_view)
    : allow_scope_(frame_view),
      value_(&frame_view.GetFrame().LocalFrameRoot().View()->force_throttling_,
             true) {}

PaintControllerPersistentData&
LocalFrameView::EnsurePaintControllerPersistentData() {
  if (!paint_controller_persistent_data_) {
    paint_controller_persistent_data_ =
        MakeGarbageCollected<PaintControllerPersistentData>();
  }
  return *paint_controller_persistent_data_;
}

bool LocalFrameView::CapturePaintPreview(
    GraphicsContext& context,
    const gfx::Vector2d& paint_offset) const {
  std::optional<base::UnguessableToken> maybe_embedding_token =
      GetFrame().GetEmbeddingToken();

  // Avoid crashing if a local frame doesn't have an embedding token.
  // e.g. it was unloaded or hasn't finished loading (crbug/1103157).
  if (!maybe_embedding_token.has_value())
    return false;

  // Ensure a recording canvas is properly created.
  DrawingRecorder recorder(context, *GetFrame().OwnerLayoutObject(),
                           DisplayItem::kDocumentBackground);
  context.Save();
  context.Translate(paint_offset.x(), paint_offset.y());
  DCHECK(context.Canvas());

  auto* tracker = context.Canvas()->GetPaintPreviewTracker();
  DCHECK(tracker);  // |tracker| must exist or there is a bug upstream.

  // Create a placeholder ID that maps to an embedding token.
  context.Canvas()->recordCustomData(tracker->CreateContentForRemoteFrame(
      FrameRect(), maybe_embedding_token.value()));
  context.Restore();

  // Send a request to the browser to trigger a capture of the frame.
  GetFrame().GetLocalFrameHostRemote().CapturePaintPreviewOfSubframe(
      FrameRect(), tracker->Guid());
  return true;
}

void LocalFrameView::Paint(GraphicsContext& context,
                           PaintFlags paint_flags,
                           const CullRect& cull_rect,
                           const gfx::Vector2d& paint_offset) const {
  const auto* owner_layout_object = GetFrame().OwnerLayoutObject();
  std::optional<Document::PaintPreviewScope> paint_preview;
  if (owner_layout_object &&
      owner_layout_object->GetDocument().GetPaintPreviewState() !=
          Document::kNotPaintingPreview) {
    paint_preview.emplace(
        *GetFrame().GetDocument(),
        owner_layout_object->GetDocument().GetPaintPreviewState());
    // When capturing a Paint Preview we want to capture scrollable embedded
    // content separately. Paint should stop here and ask the browser to
    // coordinate painting such frames as a separate task.
    if (LayoutViewport()->ScrollsOverflow()) {
      // If capture fails we should fallback to capturing inline if possible.
      if (CapturePaintPreview(context, paint_offset))
        return;
    }
  }

  if (!cull_rect.Rect().Intersects(FrameRect()))
    return;

  // |paint_offset| is not used because paint properties of the contents will
  // ensure the correct location.
  PaintFrame(context, paint_flags);
}

void LocalFrameView::PaintFrame(GraphicsContext& context,
                                PaintFlags paint_flags) const {
  FramePainter(*this).Paint(context, paint_flags);
}

void LocalFrameView::PrintPage(GraphicsContext& context,
                               wtf_size_t page_index,
                               const CullRect& cull_rect) {
  DCHECK(GetFrame().GetDocument()->Printing());
  if (pagination_state_) {
    pagination_state_->SetCurrentPageIndex(page_index);
  }
  const PaintFlags flags =
      PaintFlag::kOmitCompositingInfo | PaintFlag::kAddUrlMetadata;
  PaintOutsideOfLifecycle(context, flags, cull_rect);
}

static bool PaintOutsideOfLifecycleIsAllowed(GraphicsContext& context,
                                             const LocalFrameView& frame_view) {
  // A paint outside of lifecycle should not conflict about paint controller
  // caching with the default painting executed during lifecycle update,
  // otherwise the caller should either use a transient paint controller or
  // explicitly skip cache.
  if (context.GetPaintController().IsSkippingCache())
    return true;
  return false;
}

void LocalFrameView::PaintOutsideOfLifecycle(GraphicsContext& context,
                                             const PaintFlags paint_flags,
                                             const CullRect& cull_rect) {
  DCHECK(PaintOutsideOfLifecycleIsAllowed(context, *this));

  UpdateAllLifecyclePhasesExceptPaint(DocumentUpdateReason::kPrinting);

  SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(), LocalFrameUkmAggregator::kPaint);

  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.Lifecycle().AdvanceTo(DocumentLifecycle::kInPaint);
  });

  {
    if (pagination_state_) {
      pagination_state_->UpdateContentAreaPropertiesForCurrentPage(
          *GetLayoutView());
    }

    bool disable_expansion = paint_flags & PaintFlag::kOmitCompositingInfo;
    OverriddenCullRectScope force_cull_rect(*GetLayoutView()->Layer(),
                                            cull_rect, disable_expansion);
    context.GetPaintController().SetRecordDebugInfo(PaintDebugInfoEnabled());
    PaintFrame(context, paint_flags);
  }

  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.Lifecycle().AdvanceTo(DocumentLifecycle::kPaintClean);
  });
}

void LocalFrameView::PaintOutsideOfLifecycleWithThrottlingAllowed(
    GraphicsContext& context,
    const PaintFlags paint_flags,
    const CullRect& cull_rect) {
  AllowThrottlingScope allow_throttling(*this);
  PaintOutsideOfLifecycle(context, paint_flags, cull_rect);
}

void LocalFrameView::PaintForTest(const CullRect& cull_rect) {
  AllowThrottlingScope allow_throttling(*this);
  Lifecycle().AdvanceTo(DocumentLifecycle::kInPaint);
  CullRectUpdater(*GetLayoutView()->Layer()).UpdateForTesting(cull_rect);
  if (GetLayoutView()->Layer()->SelfOrDescendantNeedsRepaint()) {
    PaintController paint_controller(PaintDebugInfoEnabled(),
                                     &EnsurePaintControllerPersistentData());
    GraphicsContext graphics_context(paint_controller);
    PaintFrame(graphics_context);
    paint_controller.CommitNewDisplayItems();
  }
  Lifecycle().AdvanceTo(DocumentLifecycle::kPaintClean);
  CullRectUpdater(*GetLayoutView()->Layer())
      .UpdateForTesting(CullRect::Infinite());
}

PaintRecord LocalFrameView::GetPaintRecord(const gfx::Rect* cull_rect) const {
  DCHECK_EQ(DocumentLifecycle::kPaintClean, Lifecycle().GetState());
  DCHECK(frame_->IsLocalRoot());
  DCHECK(paint_controller_persistent_data_);
  return paint_controller_persistent_data_->GetPaintArtifact().GetPaintRecord(
      PropertyTreeState::Root(), cull_rect);
}

const PaintArtifact& LocalFrameView::GetPaintArtifact() const {
  CHECK_EQ(DocumentLifecycle::kPaintClean, Lifecycle().GetState());
  return GetFrame()
      .LocalFrameRoot()
      .View()
      ->EnsurePaintControllerPersistentData()
      .GetPaintArtifact();
}

gfx::Rect LocalFrameView::ConvertToRootFrame(
    const gfx::Rect& local_rect) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    gfx::Rect parent_rect = ConvertToContainingEmbeddedContentView(local_rect);
    return parent->ConvertToRootFrame(parent_rect);
  }
  return local_rect;
}

gfx::Point LocalFrameView::ConvertToRootFrame(
    const gfx::Point& local_point) const {
  return ToRoundedPoint(ConvertToRootFrame(PhysicalOffset(local_point)));
}

PhysicalOffset LocalFrameView::ConvertToRootFrame(
    const PhysicalOffset& local_offset) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    PhysicalOffset parent_offset =
        ConvertToContainingEmbeddedContentView(local_offset);
    return parent->ConvertToRootFrame(parent_offset);
  }
  return local_offset;
}

gfx::PointF LocalFrameView::ConvertToRootFrame(
    const gfx::PointF& local_point) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    gfx::PointF parent_point =
        ConvertToContainingEmbeddedContentView(local_point);
    return parent->ConvertToRootFrame(parent_point);
  }
  return local_point;
}

PhysicalRect LocalFrameView::ConvertToRootFrame(
    const PhysicalRect& local_rect) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    PhysicalOffset parent_offset =
        ConvertToContainingEmbeddedContentView(local_rect.offset);
    PhysicalRect parent_rect(parent_offset, local_rect.size);
    return parent->ConvertToRootFrame(parent_rect);
  }
  return local_rect;
}

gfx::Rect LocalFrameView::ConvertFromRootFrame(
    const gfx::Rect& rect_in_root_frame) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    gfx::Rect parent_rect = parent->ConvertFromRootFrame(rect_in_root_frame);
    return ConvertFromContainingEmbeddedContentView(parent_rect);
  }
  return rect_in_root_frame;
}

gfx::Point LocalFrameView::ConvertFromRootFrame(
    const gfx::Point& point_in_root_frame) const {
  return ToRoundedPoint(
      ConvertFromRootFrame(PhysicalOffset(point_in_root_frame)));
}

PhysicalOffset LocalFrameView::ConvertFromRootFrame(
    const PhysicalOffset& offset_in_root_frame) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    PhysicalOffset parent_point =
        parent->ConvertFromRootFrame(offset_in_root_frame);
    return ConvertFromContainingEmbeddedContentView(parent_point);
  }
  return offset_in_root_frame;
}

gfx::PointF LocalFrameView::ConvertFromRootFrame(
    const gfx::PointF& point_in_root_frame) const {
  if (LocalFrameView* parent = ParentFrameView()) {
    gfx::PointF parent_point =
        parent->ConvertFromRootFrame(point_in_root_frame);
    return ConvertFromContainingEmbeddedContentView(parent_point);
  }
  return point_in_root_frame;
}

void LocalFrameView::ParentVisibleChanged() {
  if (!IsSelfVisible())
    return;

  bool visible = IsParentVisible();
  ForAllChildViewsAndPlugins(
      [visible](EmbeddedContentView& embedded_content_view) {
        embedded_content_view.SetParentVisible(visible);
      });
}

void LocalFrameView::SelfVisibleChanged() {
  // FrameView visibility affects PLC::CanBeComposited, which in turn affects
  // compositing inputs.
  if (LayoutView* view = GetLayoutView())
    view->Layer()->SetNeedsCompositingInputsUpdate();
}

void LocalFrameView::Show() {
  if (!IsSelfVisible()) {
    SetSelfVisible(true);
    if (IsParentVisible()) {
      ForAllChildViewsAndPlugins(
          [](EmbeddedContentView& embedded_content_view) {
            embedded_content_view.SetParentVisible(true);
          });
    }
  }
}

void LocalFrameView::Hide() {
  if (IsSelfVisible()) {
    if (IsParentVisible()) {
      ForAllChildViewsAndPlugins(
          [](EmbeddedContentView& embedded_content_view) {
            embedded_content_view.SetParentVisible(false);
          });
    }
    SetSelfVisible(false);
  }
}

int LocalFrameView::ViewportWidth() const {
  int viewport_width = GetLayoutSize().width();
  return AdjustForAbsoluteZoom::AdjustInt(viewport_width, GetLayoutView());
}

int LocalFrameView::ViewportHeight() const {
  int viewport_height = GetLayoutSize().height();
  return AdjustForAbsoluteZoom::AdjustInt(viewport_height, GetLayoutView());
}

ScrollableArea* LocalFrameView::GetScrollableArea() {
  if (viewport_scrollable_area_)
    return viewport_scrollable_area_.Get();

  return LayoutViewport();
}

PaintLayerScrollableArea* LocalFrameView::LayoutViewport() const {
  auto* layout_view = GetLayoutView();
  return layout_view ? layout_view->GetScrollableArea() : nullptr;
}

RootFrameViewport* LocalFrameView::GetRootFrameViewport() {
  return viewport_scrollable_area_.Get();
}

void LocalFrameView::CollectDraggableRegions(
    LayoutObject& layout_object,
    Vector<DraggableRegionValue>& regions) const {
  // LayoutTexts don't have their own style, they just use their parent's style,
  // so we don't want to include them.
  if (layout_object.IsText())
    return;

  layout_object.AddDraggableRegions(regions);
  for (LayoutObject* curr = layout_object.SlowFirstChild(); curr;
       curr = curr->NextSibling())
    CollectDraggableRegions(*curr, regions);
}

bool LocalFrameView::UpdateViewportIntersectionsForSubtree(
    unsigned parent_flags,
    ComputeIntersectionsContext& context) {
  // This will be recomputed, but default to the previous computed value if
  // there's an early return.
  bool needs_occlusion_tracking = false;
  IntersectionObserverController* controller =
      GetFrame().GetDocument()->GetIntersectionObserverController();
  if (controller) {
    needs_occlusion_tracking = controller->NeedsOcclusionTracking();
  }

  // TODO(dcheng): Since LocalFrameView tree updates are deferred, FrameViews
  // might still be in the LocalFrameView hierarchy even though the associated
  // Document is already detached. Investigate if this check and a similar check
  // in lifecycle updates are still needed when there are no more deferred
  // LocalFrameView updates: https://crbug.com/561683
  if (!GetFrame().GetDocument()->IsActive()) {
    return needs_occlusion_tracking;
  }

  unsigned flags = GetIntersectionObservationFlags(parent_flags);
  if (!NeedsLayout() || IsDisplayLocked()) {
    // Notify javascript IntersectionObservers
    if (controller) {
      needs_occlusion_tracking = controller->ComputeIntersections(
          flags, *this,
          accumulated_scroll_delta_since_last_intersection_update_, context);
      accumulated_scroll_delta_since_last_intersection_update_ =
          gfx::Vector2dF();
    }
    intersection_observation_state_ = kNotNeeded;
  }

  {
    SCOPED_UMA_AND_UKM_TIMER(
        GetUkmAggregator(),
        LocalFrameUkmAggregator::kUpdateViewportIntersection);
    UpdateViewportIntersection(flags, needs_occlusion_tracking);
  }

  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    needs_occlusion_tracking |=
        child->View()->UpdateViewportIntersectionsForSubtree(flags,
"""


```