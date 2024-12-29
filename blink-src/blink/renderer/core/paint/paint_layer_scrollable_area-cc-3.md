Response:
My thinking process to arrive at the summary of the `PaintLayerScrollableArea` functionality went through these stages:

1. **Understanding the Goal:** The prompt asks for a summary of the functionalities of the provided code snippet from `paint_layer_scrollable_area.cc`. It's part of a larger series, implying the need for a concise overview of what this *specific* section does.

2. **Initial Scan and Keyword Spotting:**  I quickly scanned the code for recurring terms and patterns. Keywords like `scrolls_overflow_`, `Scrollbar`, `PaintInvalidation`, `CompositedScrolling`, `ScrollSnap`, and methods like `SetNeedsPaintPropertyUpdate` stood out. These immediately hinted at the core functionalities.

3. **Logical Grouping of Functionality:** I started mentally grouping related code blocks. For instance, the code related to `scrolls_overflow_` and the subsequent invalidation of scrollbars clearly belonged together as handling changes in scrollability. The methods within the `ScrollbarManager` were obviously related to scrollbar creation and destruction.

4. **Identifying Key Variables and their Impact:**  I noticed the central role of `scrolls_overflow_`. Its change triggered various actions, like updating paint properties, invalidating backgrounds, and managing the `UserScrollableArea` list. This highlighted its importance in the overall functionality.

5. **Tracing Data Flow and Dependencies:** I followed the execution flow for certain key actions. For example, the change in `scrolls_overflow_` leading to potential `ScrollTranslation` updates and the subsequent invalidation of `ScrollDisplayItem` showed a clear dependency chain.

6. **Recognizing the "Why":** For each group of functionalities, I tried to understand *why* it was there. The scrollbar management was clearly for creating and destroying scrollbars. The invalidation logic was for ensuring the visual representation was up-to-date after changes. The `ImplicitRootScrollerEnabled` block was related to optimizing the root scroller.

7. **Considering External Interactions (Based on Naming and Context):** Even without the full file, the method names and variable types suggested interactions with other parts of the Blink engine. For instance, `GetScrollingCoordinator` likely interacts with a separate system for managing scrolling. `SetNeedsPaintPropertyUpdate` clearly interacts with the paint property tree building process.

8. **Filtering for the "Essence":** Given that this is part 4 of 5, I focused on the core actions within this specific chunk. I avoided getting bogged down in the low-level details of every function call and instead focused on the high-level purpose of each block of code.

9. **Formulating a Concise Summary:**  Based on the identified groupings and their purposes, I started constructing a summary. I aimed for clarity and conciseness, using action verbs to describe the functionalities.

10. **Refining and Ordering:** I reviewed the summary to ensure it flowed logically and covered the key aspects. I organized it into points that highlighted the different categories of functionality. I also tried to connect the functionalities to the larger rendering process where possible.

11. **Addressing the "Part 4 of 5" Aspect:** Finally, I explicitly acknowledged that this is a part of a larger system and therefore the summary reflects the functionalities within *this specific segment* of the code.

By following these steps, I could dissect the code snippet and extract the core functionalities, leading to the comprehensive yet concise summary provided. The iterative process of scanning, grouping, understanding dependencies, and refining the summary was crucial to capturing the essence of the code.
这是 `blink/renderer/core/paint/paint_layer_scrollable_area.cc` 文件代码的第四部分，主要功能集中在 **处理滚动溢出状态的变化、管理滚动条的生命周期和绘制、以及与合成线程的交互**。

以下是更详细的功能归纳：

**核心功能:**

1. **滚动溢出状态管理 (`UpdateScrollsOverflow`)**:
   - **功能:**  检测并更新当前 `PaintLayerScrollableArea` 是否真正发生了内容溢出并需要滚动 (`scrolls_overflow_`)。
   - **触发条件:**  当可能影响滚动条显示或行为的因素发生变化时被调用，例如内容大小变化、可见性变化等。
   - **逻辑推理:**
     - **假设输入:**  `has_overflow` (布尔值，表示是否有内容溢出), `is_visible` (布尔值，表示是否可见)。
     - **输出:**  更新 `scrolls_overflow_` 的状态。
   - **与 Javascript/HTML/CSS 的关系:**
     - **CSS:**  CSS 的 `overflow` 属性决定了 `has_overflow` 的值。例如，`overflow: auto;` 或 `overflow: scroll;` 可能导致 `has_overflow` 为真。
     - **HTML:**  HTML 结构中的内容超过容器尺寸时，结合 CSS 的 `overflow` 设置，会触发滚动溢出。
   - **用户操作如何到达这里:** 用户在页面上操作，例如添加大量内容到一个固定大小的 `div` 元素中，使得内容超出容器，CSS 的 `overflow` 属性被设置为允许滚动，从而触发引擎重新计算布局和绘制，最终调用到 `UpdateScrollsOverflow`。

2. **滚动条的创建和销毁 (`ScrollbarManager::SetHasHorizontalScrollbar`, `ScrollbarManager::SetHasVerticalScrollbar`, `ScrollbarManager::CreateScrollbar`, `ScrollbarManager::DestroyScrollbar`, `ScrollbarManager::DestroyDetachedScrollbars`, `ScrollbarManager::Dispose`)**:
   - **功能:**  根据 `scrolls_overflow_` 的状态动态地创建、附加、分离和销毁水平和垂直滚动条。
   - **逻辑推理:**
     - **假设输入:**  `has_scrollbar` (布尔值，表示是否需要显示滚动条)。
     - **输出:**  创建或销毁相应的 `Scrollbar` 对象。
   - **与 Javascript/HTML/CSS 的关系:**
     - **CSS:**  CSS 的 `overflow` 属性，以及 `-webkit-scrollbar-*` 等样式可以影响滚动条的显示和样式。
   - **用户操作如何到达这里:**  当 `UpdateScrollsOverflow` 判断需要显示或隐藏滚动条时，会调用这些方法来管理滚动条的生命周期。例如，用户调整浏览器窗口大小，导致内容不再溢出，滚动条会被销毁。

3. **滚动条的绘制和刷新 (`SetNeedsPaintInvalidation`, `InvalidatePaintOfScrollbarIfNeeded`, `InvalidatePaintOfScrollControlsIfNeeded`)**:
   - **功能:**  当滚动条的状态或位置发生变化时，标记滚动条需要重绘，并进行实际的绘制失效操作。
   - **逻辑推理:**  通过比较滚动条的旧视觉矩形和新视觉矩形，判断是否需要重绘。
   - **与 Javascript/HTML/CSS 的关系:**
     - **CSS:**  滚动条的样式变化（例如通过 CSS 伪类 `:hover` 修改背景颜色）会触发重绘。
   - **用户操作如何到达这里:** 用户拖动滚动条、点击滚动条上的按钮、或者鼠标悬停在滚动条上触发样式变化，都会导致滚动条需要重绘。

4. **与合成线程的交互 (`ShouldScrollOnMainThread`, `PrefersNonCompositedScrolling`, `UsesCompositedScrolling`, `GetCompositorAnimationHost`, `GetCompositorAnimationTimeline`, `DropCompositorScrollDeltaNextCommit`)**:
   - **功能:**  决定滚动是否在主线程处理，获取合成线程相关的动画主机和时间线，以及通知合成线程丢弃下一次提交的滚动增量。
   - **逻辑推理:**  根据特性开关、节点类型和 Paint Properties 来判断是否使用合成滚动。
   - **与 Javascript/HTML/CSS 的关系:**
     - **CSS:**  CSS 的 `will-change: transform` 或 `will-change: scroll-position` 可能会影响是否使用合成滚动。
   - **用户操作如何到达这里:**  用户进行滚动操作时，引擎需要判断如何处理滚动事件，涉及到是否在合成线程执行。

5. **滚动捕捉 (Scroll Snap) 相关功能 (`UpdateSnappedTargetsAndEnqueueScrollSnapChange`, `SetScrollsnapchangingTargetIds`, `UpdateScrollSnapChangingTargetsAndEnqueueScrollSnapChanging`, `EnqueueScrollSnapChangeEvent`, `EnqueueScrollSnapChangingEvent`, `GetSnapTargetAlongAxis`, `GetSnapEventTargetAlongAxis`, `GetSnappedQueryTargetAlongAxis`, `SetScrollsnapchangeTargetIds`, `EnsureSnappedQueryScrollSnapshot`, `GetSnappedQueryScrollSnapshot`, `CreateAndSetSnappedQueryScrollSnapshotIfNeeded`, `SetSnappedQueryTargetIds`)**:
   - **功能:**  处理 CSS 滚动捕捉功能，跟踪捕捉目标的变化，并触发相应的事件。
   - **逻辑推理:**  比较当前的捕捉目标和之前的捕捉目标，判断是否发生了捕捉位置的改变。
   - **与 Javascript/HTML/CSS 的关系:**
     - **CSS:**  `scroll-snap-type`, `scroll-snap-align` 等 CSS 属性定义了滚动捕捉的行为。
     - **Javascript:**  通过监听 `scroll` 事件，可以获取滚动捕捉的相关信息。新的 CSS Scroll Snap API 提供了 `scrollend` 事件。
   - **用户操作如何到达这里:** 用户进行滚动操作，当滚动停止在某个捕捉点时，或者在捕捉点之间滚动时，会触发这些与滚动捕捉相关的逻辑。

6. **冻结滚动条 (`FreezeScrollbarsScope`, `FreezeScrollbarsRootScope`)**:
   - **功能:**  提供一种机制来临时冻结滚动条的创建和销毁，用于优化某些场景下的性能。
   - **用户操作如何到达这里:**  这通常是引擎内部的优化机制，用户操作不会直接触发。

7. **延迟滚动偏移量钳制 (`DelayScrollOffsetClampScope`)**:
   - **功能:**  提供一种机制来延迟滚动偏移量的调整，避免在某些场景下过度调整。
   - **用户操作如何到达这里:**  这通常是引擎内部的优化机制，用户操作不会直接触发。

8. **辅助功能 (Accessibility) (`AXObjectCache::MarkElementDirty`)**:
   - **功能:**  当滚动溢出状态发生变化时，通知辅助功能树进行更新。
   - **与 Javascript/HTML/CSS 的关系:**  无直接关系，但辅助功能最终会将信息呈现给用户或辅助工具。
   - **用户操作如何到达这里:**  任何导致滚动溢出状态变化的用户操作都可能触发辅助功能树的更新。

9. **性能监控 (`probe::UpdateScrollableFlag`)**:
   - **功能:**  更新与滚动相关的性能监控标志。
   - **用户操作如何到达这里:**  任何影响滚动状态的用户操作都可能触发性能监控标志的更新。

**与 Javascript, HTML, CSS 的功能关系举例:**

* **CSS `overflow: auto;`**:  当一个 `div` 元素的 CSS 样式设置为 `overflow: auto;` 并且其内容超出其大小时，`UpdateScrollsOverflow` 会检测到溢出，并将 `scrolls_overflow_` 设置为 true，然后 `ScrollbarManager` 会创建相应的滚动条。
* **HTML `<textarea>` 元素**:  当用户在一个 `<textarea>` 元素中输入大量文本，超过其可见区域时，会自动出现滚动条。这个过程涉及到 `UpdateScrollsOverflow` 和 `ScrollbarManager` 的工作。
* **Javascript 动态修改内容高度**:  如果 Javascript 代码动态地增加一个 `div` 元素的内容高度，使得原本没有滚动条的元素现在需要显示滚动条，`UpdateScrollsOverflow` 会被调用，并更新滚动条的显示状态。

**用户或编程常见的使用错误举例:**

* **错误地假设滚动条总是存在:** 开发者可能编写 Javascript 代码，直接操作滚动条的 DOM 元素，而没有考虑到滚动条可能因为内容不足而隐藏的情况。这可能导致 Javascript 错误。
* **CSS 样式冲突导致滚动条显示异常:**  不合理的 CSS 样式设置，例如错误的 `z-index` 或 `position` 属性，可能导致滚动条被遮挡或显示位置错误。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户加载包含可滚动元素的网页。**
2. **用户向该元素添加内容，或调整浏览器窗口大小，导致元素内容溢出。**
3. **浏览器引擎计算布局，发现需要显示滚动条。**
4. **`UpdateScrollsOverflow` 函数被调用，检测到滚动溢出。**
5. **如果 `scrolls_overflow_` 的状态发生变化，会触发一系列操作：**
   - **`ScrollbarManager` 创建或销毁滚动条。**
   - **`SetNeedsPaintPropertyUpdate` 标记需要更新绘制属性。**
   - **`SetBackgroundNeedsFullPaintInvalidation` 标记需要重新绘制背景。**
   - **根据 `UnifiedScrollableAreasEnabled` 特性，将该区域添加到或移除出用户可滚动区域列表。**
   - **通知辅助功能树更新。**
6. **当用户进行滚动操作时：**
   - **`ShouldScrollOnMainThread` 判断是否在主线程处理滚动。**
   - **如果使用合成滚动，则与合成线程进行交互。**
   - **滚动条的状态和位置发生变化，触发 `SetNeedsPaintInvalidation`，最终调用到 `InvalidatePaintOfScrollbarIfNeeded` 进行重绘。**

**本部分功能归纳:**

这部分代码主要负责 **动态管理和绘制页面的滚动区域，特别是滚动条的生命周期和视觉更新**。它根据内容的溢出状态来决定是否需要显示滚动条，并在需要时创建和管理滚动条对象。同时，它也处理与合成线程的交互，以实现更流畅的滚动体验。此外，还包含了处理 CSS 滚动捕捉以及一些内部优化机制的代码。 简单来说，**这部分代码是 Blink 引擎中负责让用户“看到”和“使用”滚动条的关键组成部分。**

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
AlwaysOff)
      has_overflow = false;
  }

  scrolls_overflow_ = has_overflow && is_visible;
  if (did_scroll_overflow == ScrollsOverflow())
    return;

  // Change of scrolls_overflow may affect whether we create ScrollTranslation
  // which is referenced from ScrollDisplayItem. Invalidate scrollbars (but not
  // their parts) to repaint the display item.
  if (auto* scrollbar = HorizontalScrollbar())
    scrollbar->SetNeedsPaintInvalidation(kNoPart);
  if (auto* scrollbar = VerticalScrollbar())
    scrollbar->SetNeedsPaintInvalidation(kNoPart);

  if (RuntimeEnabledFeatures::ImplicitRootScrollerEnabled() &&
      scrolls_overflow_) {
    if (IsA<LayoutView>(GetLayoutBox())) {
      if (Element* owner = GetLayoutBox()->GetDocument().LocalOwner()) {
        owner->GetDocument().GetRootScrollerController().ConsiderForImplicit(
            *owner);
      }
    } else {
      // In some cases, the LayoutBox may not be associated with a Node (e.g.
      // <input> and <fieldset> can generate anonymous LayoutBoxes for their
      // scrollers). We don't care about those cases for root scroller so
      // simply avoid these. https://crbug.com/1125621.
      if (GetLayoutBox()->GetNode()) {
        GetLayoutBox()
            ->GetDocument()
            .GetRootScrollerController()
            .ConsiderForImplicit(*GetLayoutBox()->GetNode());
      }
    }
  }

  // The scroll and scroll offset properties depend on |scrollsOverflow| (see:
  // PaintPropertyTreeBuilder::updateScrollAndScrollTranslation).
  GetLayoutBox()->SetNeedsPaintPropertyUpdate();

  // Scroll hit test data depend on whether the box scrolls overflow.
  // They are painted in the background phase
  // (see: BoxPainter::PaintBoxDecorationBackground).
  GetLayoutBox()->SetBackgroundNeedsFullPaintInvalidation();

  if (!RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled()) {
    if (scrolls_overflow_) {
      DCHECK(CanHaveOverflowScrollbars(*GetLayoutBox()));
      frame_view->AddUserScrollableArea(*this);
    } else {
      frame_view->RemoveUserScrollableArea(*this);
    }
  }
  probe::UpdateScrollableFlag(GetLayoutBox()->GetNode(), std::nullopt);

  layer_->DidUpdateScrollsOverflow();

  if (AXObjectCache* cache =
          GetLayoutBox()->GetDocument().ExistingAXObjectCache()) {
    cache->MarkElementDirty(GetLayoutBox()->GetNode());
  }
}

ScrollingCoordinator* PaintLayerScrollableArea::GetScrollingCoordinator()
    const {
  LocalFrame* frame = GetLayoutBox()->GetFrame();
  if (!frame)
    return nullptr;

  Page* page = frame->GetPage();
  if (!page)
    return nullptr;

  return page->GetScrollingCoordinator();
}

bool PaintLayerScrollableArea::ShouldScrollOnMainThread() const {
  DCHECK_GE(GetDocument()->Lifecycle().GetState(),
            DocumentLifecycle::kPaintClean);
  if (HasBeenDisposed()) {
    return true;
  }

  if (!GetLayoutBox()->GetFrame()->Client()->GetWebFrame()) {
    // If there's no WebFrame, then there's no WebFrameWidget, and we can't do
    // threaded scrolling. This currently only happens in a WebPagePopup.
    return true;
  }

  if (const auto* paint_artifact_compositor =
          GetLayoutBox()->GetFrameView()->GetPaintArtifactCompositor()) {
    if (const auto* properties =
            GetLayoutBox()->FirstFragment().PaintProperties()) {
      if (const auto* scroll = properties->Scroll()) {
        return paint_artifact_compositor->GetMainThreadRepaintReasons(
                   *scroll) !=
               cc::MainThreadScrollingReason::kNotScrollingOnMain;
      }
    }
  }
  return true;
}

bool PaintLayerScrollableArea::PrefersNonCompositedScrolling() const {
  if (RuntimeEnabledFeatures::PreferNonCompositedScrollingEnabled()) {
    return true;
  }
  if (Node* node = GetLayoutBox()->GetNode()) {
    if (IsA<HTMLSelectElement>(node)) {
      return true;
    }
    if (TextControlElement* text_control = EnclosingTextControl(node)) {
      if (IsA<HTMLInputElement>(text_control)) {
        return true;
      }
    }
  }
  return false;
}

bool PaintLayerScrollableArea::UsesCompositedScrolling() const {
  const auto* properties = GetLayoutBox()->FirstFragment().PaintProperties();
  if (!properties || !properties->Scroll()) {
    return false;
  }
  const auto* paint_artifact_compositor =
      GetLayoutBox()->GetFrameView()->GetPaintArtifactCompositor();
  return paint_artifact_compositor &&
         paint_artifact_compositor->UsesCompositedScrolling(
             *properties->Scroll());
}

bool PaintLayerScrollableArea::VisualViewportSuppliesScrollbars() const {
  LocalFrame* frame = GetLayoutBox()->GetFrame();
  if (!frame || !frame->GetSettings())
    return false;

  // On desktop, we always use the layout viewport's scrollbars.
  if (!frame->GetSettings()->GetViewportEnabled())
    return false;

  const TopDocumentRootScrollerController& controller =
      GetLayoutBox()->GetDocument().GetPage()->GlobalRootScrollerController();
  return controller.RootScrollerArea() == this;
}

bool PaintLayerScrollableArea::ScheduleAnimation() {
  if (ChromeClient* client =
          GetLayoutBox()->GetFrameView()->GetChromeClient()) {
    client->ScheduleAnimation(GetLayoutBox()->GetFrameView());
    return true;
  }
  return false;
}

cc::AnimationHost* PaintLayerScrollableArea::GetCompositorAnimationHost()
    const {
  return layer_->GetLayoutObject().GetFrameView()->GetCompositorAnimationHost();
}

cc::AnimationTimeline*
PaintLayerScrollableArea::GetCompositorAnimationTimeline() const {
  return layer_->GetLayoutObject().GetFrameView()->GetScrollAnimationTimeline();
}

bool PaintLayerScrollableArea::HasTickmarks() const {
  if (RareData() && !RareData()->tickmarks_override_.empty())
    return true;
  return layer_->IsRootLayer() &&
         To<LayoutView>(GetLayoutBox())->HasTickmarks();
}

Vector<gfx::Rect> PaintLayerScrollableArea::GetTickmarks() const {
  if (RareData() && !RareData()->tickmarks_override_.empty())
    return RareData()->tickmarks_override_;
  if (layer_->IsRootLayer())
    return To<LayoutView>(GetLayoutBox())->GetTickmarks();
  return Vector<gfx::Rect>();
}

void PaintLayerScrollableArea::ScrollbarManager::SetHasHorizontalScrollbar(
    bool has_scrollbar) {
  if (has_scrollbar) {
    if (!h_bar_) {
      h_bar_ = CreateScrollbar(kHorizontalScrollbar);
      h_bar_is_attached_ = 1;
      if (!h_bar_->IsCustomScrollbar())
        ScrollableArea()->DidAddScrollbar(*h_bar_, kHorizontalScrollbar);
    } else {
      h_bar_is_attached_ = 1;
    }
  } else {
    h_bar_is_attached_ = 0;
    if (!DelayScrollOffsetClampScope::ClampingIsDelayed())
      DestroyScrollbar(kHorizontalScrollbar);
  }
}

void PaintLayerScrollableArea::ScrollbarManager::SetHasVerticalScrollbar(
    bool has_scrollbar) {
  if (has_scrollbar) {
    if (!v_bar_) {
      v_bar_ = CreateScrollbar(kVerticalScrollbar);
      v_bar_is_attached_ = 1;
      if (!v_bar_->IsCustomScrollbar())
        ScrollableArea()->DidAddScrollbar(*v_bar_, kVerticalScrollbar);
    } else {
      v_bar_is_attached_ = 1;
    }
  } else {
    v_bar_is_attached_ = 0;
    if (!DelayScrollOffsetClampScope::ClampingIsDelayed())
      DestroyScrollbar(kVerticalScrollbar);
  }
}

Scrollbar* PaintLayerScrollableArea::ScrollbarManager::CreateScrollbar(
    ScrollbarOrientation orientation) {
  DCHECK(orientation == kHorizontalScrollbar ? !h_bar_is_attached_
                                             : !v_bar_is_attached_);
  Scrollbar* scrollbar = nullptr;
  Element* element = nullptr;
  const LayoutObject& style_source =
      ScrollbarStyleSource(*ScrollableArea()->GetLayoutBox());
  if (style_source.GetNode() && style_source.GetNode()->IsElementNode()) {
    element = To<Element>(style_source.GetNode());
  }
  if (style_source.StyleRef().HasCustomScrollbarStyle(element)) {
    DCHECK(element);
    scrollbar = MakeGarbageCollected<CustomScrollbar>(
        ScrollableArea(), orientation, &style_source);
  } else {
    scrollbar = MakeGarbageCollected<Scrollbar>(ScrollableArea(), orientation,
                                                &style_source);
  }
  ScrollableArea()->GetLayoutBox()->GetDocument().View()->AddScrollbar(
      scrollbar);
  return scrollbar;
}

void PaintLayerScrollableArea::ScrollbarManager::DestroyScrollbar(
    ScrollbarOrientation orientation) {
  Member<Scrollbar>& scrollbar =
      orientation == kHorizontalScrollbar ? h_bar_ : v_bar_;
  DCHECK(orientation == kHorizontalScrollbar ? !h_bar_is_attached_
                                             : !v_bar_is_attached_);
  if (!scrollbar)
    return;

  ScrollableArea()->SetScrollbarNeedsPaintInvalidation(orientation);

  if (!scrollbar->IsCustomScrollbar())
    ScrollableArea()->WillRemoveScrollbar(*scrollbar, orientation);

  ScrollableArea()->GetLayoutBox()->GetDocument().View()->RemoveScrollbar(
      scrollbar);
  scrollbar->DisconnectFromScrollableArea();
  ScrollableArea()
      ->GetLayoutBox()
      ->GetFrame()
      ->GetEventHandler()
      .OnScrollbarDestroyed(*scrollbar);
  scrollbar = nullptr;
}

void PaintLayerScrollableArea::ScrollbarManager::DestroyDetachedScrollbars() {
  DCHECK(!h_bar_is_attached_ || h_bar_);
  DCHECK(!v_bar_is_attached_ || v_bar_);
  if (h_bar_ && !h_bar_is_attached_)
    DestroyScrollbar(kHorizontalScrollbar);
  if (v_bar_ && !v_bar_is_attached_)
    DestroyScrollbar(kVerticalScrollbar);
}

void PaintLayerScrollableArea::ScrollbarManager::Dispose() {
  h_bar_is_attached_ = v_bar_is_attached_ = 0;
  DestroyScrollbar(kHorizontalScrollbar);
  DestroyScrollbar(kVerticalScrollbar);
}

void PaintLayerScrollableArea::ScrollbarManager::Trace(
    blink::Visitor* visitor) const {
  visitor->Trace(scrollable_area_);
  visitor->Trace(h_bar_);
  visitor->Trace(v_bar_);
}

int PaintLayerScrollableArea::FreezeScrollbarsScope::count_ = 0;

PaintLayerScrollableArea::FreezeScrollbarsRootScope::FreezeScrollbarsRootScope(
    const LayoutBox& box,
    bool freeze_horizontal,
    bool freeze_vertical)
    : scrollable_area_(box.GetScrollableArea()) {
  if (scrollable_area_ && !FreezeScrollbarsScope::ScrollbarsAreFrozen() &&
      (freeze_horizontal || freeze_vertical)) {
    scrollable_area_->EstablishScrollbarRoot(freeze_horizontal,
                                             freeze_vertical);
    freezer_.emplace();
  }
}

PaintLayerScrollableArea::FreezeScrollbarsRootScope::
    ~FreezeScrollbarsRootScope() {
  if (scrollable_area_)
    scrollable_area_->ClearScrollbarRoot();
}

int PaintLayerScrollableArea::DelayScrollOffsetClampScope::count_ = 0;

PaintLayerScrollableArea::DelayScrollOffsetClampScope::
    DelayScrollOffsetClampScope() {
  DCHECK(count_ > 0 || NeedsClampList().empty());
  count_++;
}

PaintLayerScrollableArea::DelayScrollOffsetClampScope::
    ~DelayScrollOffsetClampScope() {
  if (--count_ == 0)
    DelayScrollOffsetClampScope::ClampScrollableAreas();
}

void PaintLayerScrollableArea::DelayScrollOffsetClampScope::SetNeedsClamp(
    PaintLayerScrollableArea* scrollable_area) {
  if (!scrollable_area->NeedsScrollOffsetClamp()) {
    scrollable_area->SetNeedsScrollOffsetClamp(true);
    NeedsClampList().push_back(scrollable_area);
  }
}

void PaintLayerScrollableArea::DelayScrollOffsetClampScope::
    ClampScrollableAreas() {
  for (auto& scrollable_area : NeedsClampList())
    scrollable_area->ClampScrollOffsetAfterOverflowChange();
  NeedsClampList().clear();
}

HeapVector<Member<PaintLayerScrollableArea>>&
PaintLayerScrollableArea::DelayScrollOffsetClampScope::NeedsClampList() {
  DEFINE_STATIC_LOCAL(
      Persistent<HeapVector<Member<PaintLayerScrollableArea>>>,
      needs_clamp_list,
      (MakeGarbageCollected<HeapVector<Member<PaintLayerScrollableArea>>>()));
  return *needs_clamp_list;
}

ScrollbarTheme& PaintLayerScrollableArea::GetPageScrollbarTheme() const {
  // If PaintLayer is destructed before PaintLayerScrollable area, we can not
  // get the page scrollbar theme setting.
  DCHECK(!HasBeenDisposed());

  Page* page = GetLayoutBox()->GetFrame()->GetPage();
  DCHECK(page);

  return page->GetScrollbarTheme();
}

void PaintLayerScrollableArea::DidAddScrollbar(
    Scrollbar& scrollbar,
    ScrollbarOrientation orientation) {
  if (HasOverlayOverflowControls() ||
      layer_->NeedsReorderOverlayOverflowControls()) {
    // Z-order of existing or new recordered overflow controls is updated along
    // with the z-order lists.
    layer_->DirtyStackingContextZOrderLists();
  }
  ScrollableArea::DidAddScrollbar(scrollbar, orientation);
}

void PaintLayerScrollableArea::WillRemoveScrollbar(
    Scrollbar& scrollbar,
    ScrollbarOrientation orientation) {
  if (layer_->NeedsReorderOverlayOverflowControls()) {
    // Z-order of recordered overflow controls is updated along with the z-order
    // lists.
    layer_->DirtyStackingContextZOrderLists();
  }

  if (!scrollbar.IsCustomScrollbar()) {
    ObjectPaintInvalidator(*GetLayoutBox())
        .SlowSetPaintingLayerNeedsRepaintAndInvalidateDisplayItemClient(
            scrollbar, PaintInvalidationReason::kScrollControl);
  }

  ScrollableArea::WillRemoveScrollbar(scrollbar, orientation);
}

// Returns true if the scroll control is invalidated.
static bool ScrollControlNeedsPaintInvalidation(
    const gfx::Rect& new_visual_rect,
    const gfx::Rect& previous_visual_rect,
    bool needs_paint_invalidation) {
  if (new_visual_rect != previous_visual_rect)
    return true;
  if (previous_visual_rect.IsEmpty()) {
    DCHECK(new_visual_rect.IsEmpty());
    // Do not issue an empty invalidation.
    return false;
  }

  return needs_paint_invalidation;
}

bool PaintLayerScrollableArea::MayCompositeScrollbar(
    const Scrollbar& scrollbar) const {
  // Don't composite non-scrollable scrollbars.
  // TODO(crbug.com/1020913): !ScrollsOverflow() should imply
  // !scrollbar.Maximum(), but currently that isn't always true due to
  // different or incorrect rounding methods for scroll geometries.
  if (!ScrollsOverflow() || !scrollbar.Maximum()) {
    return false;
  }
  if (scrollbar.IsCustomScrollbar()) {
    return false;
  }
  // Compositing of scrollbar is decided in PaintArtifactCompositor. We assume
  // compositing here so that paint invalidation will be skipped here. We'll
  // invalidate raster if needed after paint, without paint invalidation.
  return true;
}

void PaintLayerScrollableArea::EstablishScrollbarRoot(bool freeze_horizontal,
                                                      bool freeze_vertical) {
  DCHECK(!FreezeScrollbarsScope::ScrollbarsAreFrozen());
  is_scrollbar_freeze_root_ = true;
  is_horizontal_scrollbar_frozen_ = freeze_horizontal;
  is_vertical_scrollbar_frozen_ = freeze_vertical;
}

void PaintLayerScrollableArea::ClearScrollbarRoot() {
  is_scrollbar_freeze_root_ = false;
  is_horizontal_scrollbar_frozen_ = false;
  is_vertical_scrollbar_frozen_ = false;
}

void PaintLayerScrollableArea::InvalidatePaintOfScrollbarIfNeeded(
    const PaintInvalidatorContext& context,
    bool needs_paint_invalidation,
    Scrollbar* scrollbar,
    bool& previously_was_overlay,
    bool& previously_might_be_composited,
    gfx::Rect& visual_rect) {
  bool is_overlay = scrollbar && scrollbar->IsOverlayScrollbar();

  gfx::Rect new_visual_rect;
  if (scrollbar) {
    new_visual_rect = scrollbar->FrameRect();
    // TODO(crbug.com/1020913): We should not round paint_offset but should
    // consider subpixel accumulation when painting scrollbars.
    new_visual_rect.Offset(
        ToRoundedVector2d(context.fragment_data->PaintOffset()));
  }

  // Invalidate the box's display item client if the box's padding box size is
  // affected by change of the non-overlay scrollbar width. We detect change of
  // visual rect size instead of change of scrollbar width, which may have some
  // false-positives (e.g. the scrollbar changed length but not width) but won't
  // invalidate more than expected because in the false-positive case the box
  // must have changed size and have been invalidated.
  gfx::Size new_scrollbar_used_space_in_box;
  if (!is_overlay)
    new_scrollbar_used_space_in_box = new_visual_rect.size();
  gfx::Size previous_scrollbar_used_space_in_box;
  if (!previously_was_overlay)
    previous_scrollbar_used_space_in_box = visual_rect.size();

  // The IsEmpty() check avoids invalidaiton in cases when the visual rect
  // changes from (0,0 0x0) to (0,0 0x100).
  if (!(new_scrollbar_used_space_in_box.IsEmpty() &&
        previous_scrollbar_used_space_in_box.IsEmpty()) &&
      new_scrollbar_used_space_in_box != previous_scrollbar_used_space_in_box) {
    context.painting_layer->SetNeedsRepaint();
    const auto& box = *GetLayoutBox();
    ObjectPaintInvalidator(box).InvalidateDisplayItemClient(
        box, PaintInvalidationReason::kLayout);
  }

  previously_was_overlay = is_overlay;

  if (scrollbar) {
    bool may_be_composited = MayCompositeScrollbar(*scrollbar);
    if (may_be_composited != previously_might_be_composited) {
      needs_paint_invalidation = true;
      previously_might_be_composited = may_be_composited;
    } else if (may_be_composited &&
               (RuntimeEnabledFeatures::RasterInducingScrollEnabled() ||
                UsesCompositedScrolling())) {
      // Don't invalidate composited scrollbar if the change is only inside of
      // the scrollbar. ScrollbarDisplayItem will handle such change.
      // TODO(crbug.com/1505560): Avoid paint invalidation for non-composited
      // scrollbars for changes inside of the scrollbar.
      needs_paint_invalidation = false;
    }
  }

  if (scrollbar &&
      ScrollControlNeedsPaintInvalidation(new_visual_rect, visual_rect,
                                          needs_paint_invalidation)) {
    context.painting_layer->SetNeedsRepaint();
    scrollbar->Invalidate(PaintInvalidationReason::kScrollControl);
    if (auto* custom_scrollbar = DynamicTo<CustomScrollbar>(scrollbar))
      custom_scrollbar->InvalidateDisplayItemClientsOfScrollbarParts();
  }

  visual_rect = new_visual_rect;
}

void PaintLayerScrollableArea::InvalidatePaintOfScrollControlsIfNeeded(
    const PaintInvalidatorContext& context) {
  if (context.subtree_flags & PaintInvalidatorContext::kSubtreeFullInvalidation)
    SetScrollControlsNeedFullPaintInvalidation();

  InvalidatePaintOfScrollbarIfNeeded(
      context, HorizontalScrollbarNeedsPaintInvalidation(),
      HorizontalScrollbar(), horizontal_scrollbar_previously_was_overlay_,
      horizontal_scrollbar_previously_might_be_composited_,
      horizontal_scrollbar_visual_rect_);
  InvalidatePaintOfScrollbarIfNeeded(
      context, VerticalScrollbarNeedsPaintInvalidation(), VerticalScrollbar(),
      vertical_scrollbar_previously_was_overlay_,
      vertical_scrollbar_previously_might_be_composited_,
      vertical_scrollbar_visual_rect_);

  gfx::Rect new_scroll_corner_and_resizer_visual_rect =
      ScrollCornerAndResizerRect();
  // TODO(crbug.com/1020913): We should not round paint_offset but should
  // consider subpixel accumulation when painting scrollbars.
  new_scroll_corner_and_resizer_visual_rect.Offset(
      ToRoundedVector2d(context.fragment_data->PaintOffset()));
  if (ScrollControlNeedsPaintInvalidation(
          new_scroll_corner_and_resizer_visual_rect,
          scroll_corner_and_resizer_visual_rect_,
          ScrollCornerNeedsPaintInvalidation())) {
    scroll_corner_and_resizer_visual_rect_ =
        new_scroll_corner_and_resizer_visual_rect;
    if (LayoutCustomScrollbarPart* scroll_corner = ScrollCorner()) {
      DCHECK(!scroll_corner->PaintingLayer());
      ObjectPaintInvalidator(*scroll_corner)
          .InvalidateDisplayItemClient(*scroll_corner,
                                       PaintInvalidationReason::kScrollControl);
    }
    if (LayoutCustomScrollbarPart* resizer = Resizer()) {
      DCHECK(!resizer->PaintingLayer());
      ObjectPaintInvalidator(*resizer).InvalidateDisplayItemClient(
          *resizer, PaintInvalidationReason::kScrollControl);
    }

    context.painting_layer->SetNeedsRepaint();
    ObjectPaintInvalidator(*GetLayoutBox())
        .InvalidateDisplayItemClient(GetScrollCornerDisplayItemClient(),
                                     PaintInvalidationReason::kLayout);
  }

  ClearNeedsPaintInvalidationForScrollControls();
}

void PaintLayerScrollableArea::ScrollControlWasSetNeedsPaintInvalidation() {
  SetShouldCheckForPaintInvalidation();
}

void PaintLayerScrollableArea::DidScrollWithScrollbar(
    ScrollbarPart part,
    ScrollbarOrientation orientation,
    WebInputEvent::Type type) {
  WebFeature scrollbar_use_uma;
  switch (part) {
    case kBackButtonEndPart:
    case kForwardButtonStartPart:
      UseCounter::Count(
          GetLayoutBox()->GetDocument(),
          WebFeature::kScrollbarUseScrollbarButtonReversedDirection);
      [[fallthrough]];
    case kBackButtonStartPart:
    case kForwardButtonEndPart:
      scrollbar_use_uma =
          (orientation == kVerticalScrollbar
               ? WebFeature::kScrollbarUseVerticalScrollbarButton
               : WebFeature::kScrollbarUseHorizontalScrollbarButton);
      break;
    case kThumbPart:
      if (orientation == kVerticalScrollbar) {
        scrollbar_use_uma =
            (WebInputEvent::IsMouseEventType(type)
                 ? WebFeature::kVerticalScrollbarThumbScrollingWithMouse
                 : WebFeature::kVerticalScrollbarThumbScrollingWithTouch);
      } else {
        scrollbar_use_uma =
            (WebInputEvent::IsMouseEventType(type)
                 ? WebFeature::kHorizontalScrollbarThumbScrollingWithMouse
                 : WebFeature::kHorizontalScrollbarThumbScrollingWithTouch);
      }
      break;
    case kBackTrackPart:
    case kForwardTrackPart:
      scrollbar_use_uma =
          (orientation == kVerticalScrollbar
               ? WebFeature::kScrollbarUseVerticalScrollbarTrack
               : WebFeature::kScrollbarUseHorizontalScrollbarTrack);
      break;
    default:
      return;
  }

  Document& document = GetLayoutBox()->GetDocument();

  UseCounter::Count(document, scrollbar_use_uma);
}

CompositorElementId PaintLayerScrollableArea::GetScrollElementId() const {
  return CompositorElementIdFromUniqueObjectId(
      GetLayoutBox()->UniqueId(), CompositorElementIdNamespace::kScroll);
}

gfx::Size PaintLayerScrollableArea::PixelSnappedBorderBoxSize() const {
  // TODO(crbug.com/1020913): We use this method during
  // PositionOverflowControls() even before the paint offset is updated.
  // This can be fixed only after we support subpixels in overflow control
  // geometry. For now we ensure correct pixel snapping of overflow controls by
  // calling PositionOverflowControls() again when paint offset is updated.
  // TODO(crbug.com/962299): Only correct if the paint offset is correct.
  return PhysicalRect(GetLayoutBox()->FirstFragment().PaintOffset(),
                      GetLayoutBox()->Size())
      .PixelSnappedSize();
}

void PaintLayerScrollableArea::DropCompositorScrollDeltaNextCommit() {
  auto* frame_view = GetLayoutBox()->GetFrameView();
  CHECK(frame_view);
  if (auto* paint_artifact_compositor =
          frame_view->GetPaintArtifactCompositor()) {
    paint_artifact_compositor->DropCompositorScrollDeltaNextCommit(
        GetScrollElementId());
  }
}

gfx::Rect PaintLayerScrollableArea::ScrollingBackgroundVisualRect(
    const PhysicalOffset& paint_offset) const {
  const auto* box = GetLayoutBox();
  auto clip_rect = box->OverflowClipRect(paint_offset);
  auto overflow_clip_rect = ToPixelSnappedRect(clip_rect);
  auto scroll_size = PixelSnappedContentsSize(clip_rect.offset);
  // Ensure scrolling contents are at least as large as the scroll clip
  scroll_size.SetToMax(overflow_clip_rect.size());
  gfx::Rect result(overflow_clip_rect.origin(), scroll_size);

  // The HTML element of a document is special, in that it can have a transform,
  // but the bounds of the painted area of the element still extends beyond
  // its actual size to encompass the entire viewport canvas. This is
  // accomplished in ViewPainter by starting with a rect in viewport canvas
  // space that is equal to the size of the viewport canvas, then mapping it
  // into the local border box space of the HTML element, and painting a rect
  // equal to the bounding box of the result. We need to add in that mapped rect
  // in such cases.
  const Document& document = box->GetDocument();
  if (IsA<LayoutView>(box) &&
      (document.IsXMLDocument() || document.IsHTMLDocument())) {
    if (const auto* document_element = document.documentElement()) {
      if (const auto* document_element_object =
              document_element->GetLayoutObject()) {
        const auto& document_element_state =
            document_element_object->FirstFragment().LocalBorderBoxProperties();
        const auto& view_contents_state =
            box->FirstFragment().ContentsProperties();
        gfx::Rect result_in_view = result;
        GeometryMapper::SourceToDestinationRect(
            view_contents_state.Transform(), document_element_state.Transform(),
            result_in_view);
        result.Union(result_in_view);
      }
    }
  }

  return result;
}

String
PaintLayerScrollableArea::ScrollingBackgroundDisplayItemClient::DebugName()
    const {
  return "Scrolling background of " +
         scrollable_area_->GetLayoutBox()->DebugName();
}

DOMNodeId
PaintLayerScrollableArea::ScrollingBackgroundDisplayItemClient::OwnerNodeId()
    const {
  return static_cast<const DisplayItemClient*>(scrollable_area_->GetLayoutBox())
      ->OwnerNodeId();
}

String PaintLayerScrollableArea::ScrollCornerDisplayItemClient::DebugName()
    const {
  return "Scroll corner of " + scrollable_area_->GetLayoutBox()->DebugName();
}

DOMNodeId PaintLayerScrollableArea::ScrollCornerDisplayItemClient::OwnerNodeId()
    const {
  return static_cast<const DisplayItemClient*>(scrollable_area_->GetLayoutBox())
      ->OwnerNodeId();
}

void PaintLayerScrollableArea::
    UpdateSnappedTargetsAndEnqueueScrollSnapChange() {
  if (!RuntimeEnabledFeatures::CSSScrollSnapChangeEventEnabled() &&
      !RuntimeEnabledFeatures::CSSSnapContainerQueriesEnabled()) {
    return;
  }
  const cc::SnapContainerData* container_data = GetSnapContainerData();
  if (!container_data) {
    return;
  }

  cc::TargetSnapAreaElementIds new_target_ids =
      container_data->GetTargetSnapAreaElementIds();

  CreateAndSetSnappedQueryScrollSnapshotIfNeeded(new_target_ids);

  auto& rare_data = EnsureRareData();
  bool scrollsnapchange =
      (rare_data.scrollsnapchange_target_ids_
           ? (new_target_ids.x != rare_data.scrollsnapchange_target_ids_->x ||
              new_target_ids.y != rare_data.scrollsnapchange_target_ids_->y)
           : true);
  if (scrollsnapchange) {
    rare_data.scrollsnapchange_target_ids_ = new_target_ids;
    rare_data.snapped_query_target_ids_ = new_target_ids;
    EnqueueScrollSnapChangeEvent();
  }
}

void PaintLayerScrollableArea::SetScrollsnapchangingTargetIds(
    std::optional<cc::TargetSnapAreaElementIds> ids) {
  EnsureRareData().scrollsnapchanging_target_ids_ = ids;
}

void PaintLayerScrollableArea::
    UpdateScrollSnapChangingTargetsAndEnqueueScrollSnapChanging(
        const cc::TargetSnapAreaElementIds& new_target_ids) {
  if (!RuntimeEnabledFeatures::CSSScrollSnapChangingEventEnabled()) {
    return;
  }
  const cc::SnapContainerData* container_data = GetSnapContainerData();
  if (!container_data) {
    return;
  }

  CreateAndSetSnappedQueryScrollSnapshotIfNeeded(new_target_ids);

  auto& rare_data = EnsureRareData();
  bool scrollsnapchanging =
      (rare_data.scrollsnapchanging_target_ids_
           ? (new_target_ids.x != rare_data.scrollsnapchanging_target_ids_->x ||
              new_target_ids.y != rare_data.scrollsnapchanging_target_ids_->y)
           : true);
  if (scrollsnapchanging) {
    rare_data.scrollsnapchanging_target_ids_ = new_target_ids;
    rare_data.snapped_query_target_ids_ = new_target_ids;
    EnqueueScrollSnapChangingEvent();
  }
}

void PaintLayerScrollableArea::
    EnqueueScrollSnapChangingEventFromImplIfNeeded() {
  const cc::SnapContainerData* container_data = GetSnapContainerData();
  if (!container_data) {
    return;
  }
  const cc::SnapSelectionStrategy* strategy = GetImplSnapStrategy();
  if (!strategy) {
    return;
  }
  cc::SnapPositionData snap = container_data->FindSnapPosition(*strategy);
  UpdateScrollSnapChangingTargetsAndEnqueueScrollSnapChanging(
      snap.target_element_ids);
}

Node* PaintLayerScrollableArea::GetSnapTargetAlongAxis(
    cc::TargetSnapAreaElementIds ids,
    cc::SnapAxis axis) const {
  using cc::SnapAxis::kBlock;
  using cc::SnapAxis::kInline;
  using cc::SnapAxis::kX;
  using cc::SnapAxis::kY;
  if (!GetLayoutBox() || !GetLayoutBox()->Style()) {
    return nullptr;
  }
  bool horiz = GetLayoutBox()->Style()->GetWritingDirection().IsHorizontal();
  if (ids.y && (axis == kY || (axis == kBlock && horiz) ||
                (axis == kInline && !horiz))) {
    return DOMNodeIds::NodeForId(DOMNodeIdFromCompositorElementId(ids.y));
  }
  if (ids.x && (axis == kX || (axis == kInline && horiz) ||
                (axis == kBlock && !horiz))) {
    return DOMNodeIds::NodeForId(DOMNodeIdFromCompositorElementId(ids.x));
  }
  return nullptr;
}

Node* PaintLayerScrollableArea::GetSnapEventTargetAlongAxis(
    const AtomicString& event_type,
    cc::SnapAxis axis) const {
  std::optional<cc::TargetSnapAreaElementIds> ids;
  if (event_type == event_type_names::kScrollsnapchange) {
    ids = RareData()->scrollsnapchange_target_ids_;
  } else {
    ids = RareData()->scrollsnapchanging_target_ids_;
  }
  if (!ids) {
    return nullptr;
  }
  Node* node = GetSnapTargetAlongAxis(ids.value(), axis);
  if (node && node->IsPseudoElement()) {
    node = node->parentElement();
  }
  return node;
}

Element* PaintLayerScrollableArea::GetSnappedQueryTargetAlongAxis(
    cc::SnapAxis axis) const {
  if (RareData()) {
    std::optional<cc::TargetSnapAreaElementIds> ids =
        RareData()->snapped_query_target_ids_;
    if (ids) {
      return DynamicTo<Element>(GetSnapTargetAlongAxis(ids.value(), axis));
    }
  }
  return nullptr;
}

void PaintLayerScrollableArea::SetScrollsnapchangeTargetIds(
    std::optional<cc::TargetSnapAreaElementIds> ids) {
  EnsureRareData().scrollsnapchange_target_ids_ = ids;
}

SnappedQueryScrollSnapshot&
PaintLayerScrollableArea::EnsureSnappedQueryScrollSnapshot() {
  PaintLayerScrollableAreaRareData& rare_data = EnsureRareData();
  if (rare_data.snapped_query_snapshot_ == nullptr) {
    rare_data.snapped_query_snapshot_ =
        MakeGarbageCollected<SnappedQueryScrollSnapshot>(*this);
  }
  return *rare_data.snapped_query_snapshot_;
}

SnappedQueryScrollSnapshot*
PaintLayerScrollableArea::GetSnappedQueryScrollSnapshot() {
  return RareData() ? RareData()->snapped_query_snapshot_ : nullptr;
}

void PaintLayerScrollableArea::CreateAndSetSnappedQueryScrollSnapshotIfNeeded(
    cc::TargetSnapAreaElementIds ids) {
  if (!RuntimeEnabledFeatures::CSSSnapContainerQueriesEnabled()) {
    return;
  }
  Element* target_x = nullptr;
  if (ids.x) {
    target_x = DynamicTo<Element>(
        DOMNodeIds::NodeForId(DOMNodeIdFromCompositorElementId(ids.x)));
  }
  Element* target_y = nullptr;
  if (ids.y) {
    target_y = DynamicTo<Element>(
        DOMNodeIds::NodeForId(DOMNodeIdFromCompositorElementId(ids.y)));
  }
  for (Element* target : {target_x, target_y}) {
    if (!target) {
      continue;
    }
    if (ContainerQueryEvaluator* evaluator =
            target->GetContainerQueryEvaluator()) {
      if (evaluator->DependsOnSnapped()) {
        EnsureSnappedQueryScrollSnapshot();
      }
    }
  }
}

void PaintLayerScrollableArea::SetSnappedQueryTargetIds(
    std::optional<cc::TargetSnapAreaElementIds> ids) {
  EnsureRareData().snapped_query_target_ids_ = ids;
}

ScrollOffset PaintLayerScrollableArea::GetScrollOffsetForScrollMarkerUpdate() {
  ScrollOffset offset_for_scroll_marker_update = GetScrollOffset();
  if (GetScrollAnimator().HasRunningAnimation()) {
    offset_for_scroll_marker_update = GetScrollAnimator().DesiredTargetOffset();
  } else if (GetProgrammaticScrollAnimator().HasRunningAnimation()) {
    offset_for_scroll_marker_update =
        GetProgrammaticScrollAnimator().TargetOffset();
  }
  return offset_for_scroll_marker_update;
}

void PaintLayerScrollableArea::UpdateScrollMarkers() {
  if (Element* element = DynamicTo<Element>(GetLayoutBox()->GetNode())) {
    ScrollOffset scroll_offset = GetScrollOffsetForScrollMarkerUpdate();
    if (PseudoElement* before =
            element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
      auto* group_before = DynamicTo<ScrollMarkerGroupPseudoElement>(before);
      group_before->UpdateSelectedScrollMarker(scroll_offset);
    } else if (PseudoElement* a
"""


```