Response:
My thinking process for analyzing the provided code snippet went something like this:

1. **Identify the Core Purpose:** The first step is to understand the high-level function of the code. Looking at the class name `Document` and the file path `blink/renderer/core/dom/document.cc`, it's clear this code is part of the Blink rendering engine and deals with the `Document` object in the DOM.

2. **Scan for Key Functionality Areas:**  I scanned the code for recurring themes and keywords. Immediately, I noticed:
    * `Clone`:  Functions like `CloneDocumentWithoutChildren` and `CloneDataFromDocument` suggest object duplication.
    * `ResizeObserver`:  The presence of `EnsureResizeObserver`, `ObserveForIntrinsicSize`, and related functions points to handling element resizing and notifications.
    * `Focus`:  Functions like `SetHoverElement`, `SetActiveElement`, `SetFocusedElement`, and `ClearFocusedElement` clearly deal with focus management.
    * `MediaQuery`:  `EvaluateMediaQueryListIfNeeded` and `LayoutViewportWasResized` indicate handling media queries and viewport changes.
    * `DraggableRegions`:  `DraggableRegions` and `SetDraggableRegions` suggest support for draggable elements/regions.
    * `Node Lists/Iterators`: Functions like `RegisterNodeList`, `AttachNodeIterator`, and the associated unregister/detach functions indicate management of live collections of nodes.
    * `Mutation Observation`:  The presence of `synchronous_mutation_observer_set_` and methods like `NodeChildrenWillBeRemoved`, `NotifyAttributeChanged`, etc., clearly link to the DOM Mutation Observer API.
    * `Events`:  The `Enqueue...Event` functions (like `EnqueueResizeEvent`, `EnqueueScrollEventForNode`) and the handling of focus/blur events point to event management.
    * `CSS Styling`: Mentions of `GetStyleResolver`, `GetStyleEngine`, and `PseudoStateChanged` suggest interactions with the CSS styling system.

3. **Analyze Individual Functions and Blocks:** After identifying the broad areas, I looked at individual functions and code blocks more closely. For each function, I asked:
    * What does this function do? (Its primary action)
    * What are its inputs and outputs (explicit and implicit)?
    * What other parts of the code or the browser might it interact with?

4. **Connect Functionality to Web Standards:**  I considered how the observed functionality relates to web standards like HTML, CSS, and JavaScript APIs. For example:
    * `Clone` relates to the `cloneNode()` JavaScript method.
    * `ResizeObserver` is a direct implementation of the W3C Resize Observer API.
    * Focus management ties into the `focus()`, `blur()`, `focusin`, `focusout` events, and the `:focus` CSS pseudo-class.
    * Media queries are a fundamental part of CSS.
    * Mutation Observers are a JavaScript API for tracking DOM changes.
    * Event queuing is how the browser schedules and dispatches events.

5. **Identify Relationships and Dependencies:** I looked for dependencies between different parts of the code. For example, focus management interacts with event dispatching and styling. Resize observation interacts with layout.

6. **Consider User/Developer Implications:** I thought about how developers and users might interact with these features and what common mistakes they might make. For instance, incorrect use of `cloneNode()`, failing to handle resize events properly, or misunderstanding the nuances of focus and blur events.

7. **Infer Debugging Scenarios:** Based on the functionality, I imagined scenarios where a developer might need to step into this code during debugging. This often involves user interactions that trigger DOM changes, focus shifts, or resizing events.

8. **Address the Specific Prompts:**  I specifically addressed each point in the prompt:
    * **Functionality Listing:**  Summarizing the key areas identified in step 2.
    * **Relationship to JavaScript, HTML, CSS:** Providing concrete examples of how the code interacts with these technologies (step 4).
    * **Logical Reasoning (Hypothetical Input/Output):** Constructing simple scenarios to illustrate the behavior of specific functions.
    * **User/Programming Errors:**  Brainstorming common mistakes related to the discussed features (step 6).
    * **User Operations and Debugging:**  Describing user actions that would lead into this code and what a developer might observe during debugging (step 7).
    * **Summarization (Part 7 of 11):**  Focusing on the specific functionality within this particular code snippet, acknowledging that it's part of a larger whole. I looked for the common threads tying the functions together in this section. The presence of cloning, resize observation, focus management, and some DOM manipulation within this chunk were key indicators.

9. **Refine and Organize:** Finally, I organized my thoughts and wrote the response in a clear and structured manner, using headings and bullet points to improve readability. I tried to use precise terminology related to web development and browser internals. I made sure to explicitly state assumptions and point out areas where further investigation might be needed if more context were available.
这是 `blink/renderer/core/dom/document.cc` 文件第七部分的代码，主要集中在以下几个核心功能：

**1. Document 的克隆 (Cloning):**

* **`CloneDocumentWithoutChildren()`:** 创建一个不包含子节点的当前文档的副本。它会复制文档的基本信息，例如执行上下文、Agent、URL 和回退的基础 URL。对于 XML 文档，它会区分 XHTML 和普通 XML。
* **`CloneDataFromDocument()`:** 将另一个文档的特定数据（例如兼容性模式、编码数据和 MIME 类型）复制到当前文档。
* **`Clone(DocumentCloneData& data)`:** 这是主要的克隆函数。它调用 `CloneDocumentWithoutChildren()` 创建基本副本，然后复制数据，并根据 `CloneOption` 决定是否克隆 DOM 部件和子节点。
    * **`CloneOption::kPreserveDOMParts`:**  如果设置，则会克隆文档的 DOM 部件（PartRoot）。
    * **`CloneOption::kIncludeDescendants`:** 如果设置，则会递归克隆子节点。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  `document.cloneNode()` JavaScript 方法最终会调用到 Blink 引擎的克隆逻辑。这段代码是实现 `cloneNode()` 的核心部分。
    * **假设输入:** JavaScript 调用 `document.cloneNode(true)`。
    * **输出:**  Blink 引擎会执行 `Clone(data)`，其中 `data` 包含 `CloneOption::kIncludeDescendants`。最终会返回一个包含所有子节点的完整文档副本。

* **HTML:**  克隆操作直接影响 HTML 结构的复制。`CloneDocumentWithoutChildren()` 复制了文档的基本 HTML 结构（例如 `<html>` 标签），而带子节点的克隆则复制了整个 HTML 树。

* **CSS:**  克隆操作也可能影响 CSS 的应用。虽然这段代码本身不直接处理 CSS 样式，但在克隆节点后，浏览器需要重新计算克隆节点的样式。

**2. 监听和处理元素大小变化 (Resize Observation):**

* **`EnsureResizeObserver()`:**  确保文档拥有一个 `ResizeObserver` 实例，用于监听元素的尺寸变化。
* **`ObserveForIntrinsicSize(Element* element)`:**  开始监听指定元素的固有尺寸变化。
* **`UnobserveForIntrinsicSize(Element* element)`:** 停止监听指定元素的固有尺寸变化。
* **`LazyLoadedAutoSizedImgResizeObserverDelegate`:** 一个 `ResizeObserver::Delegate` 的实现，专门用于处理懒加载的自动调整大小的 `<img>` 元素的尺寸变化。
* **`GetLazyLoadedAutoSizedImgObserver()`:**  获取用于懒加载图片的 `ResizeObserver` 实例。
* **`ObserveForLazyLoadedAutoSizedImg(HTMLImageElement* img)`:**  开始监听懒加载图片的尺寸变化。
* **`UnobserveForLazyLoadedAutoSizedImg(HTMLImageElement* img)`:** 停止监听懒加载图片的尺寸变化。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  这段代码实现了 W3C 的 Resize Observer API，允许 JavaScript 代码监听元素的尺寸变化。
    * **假设输入:** JavaScript 代码创建了一个 `ResizeObserver` 并调用 `observe(element)`。
    * **输出:** Blink 引擎会调用 `ObserveForIntrinsicSize(element)` 或 `ObserveForLazyLoadedAutoSizedImg(element)`，开始监听元素的尺寸变化，并在尺寸变化时通知 JavaScript 回调函数。

* **HTML:**  监听的目标是 HTML 元素 (`Element`, `HTMLImageElement`)。懒加载的图片通常使用 `<img>` 标签，其尺寸变化会触发相应的回调。

* **CSS:** 元素的尺寸变化通常由 CSS 属性（例如 `width`, `height`, `box-sizing`) 控制。`ResizeObserver` 能够感知这些 CSS 变化导致的元素尺寸改变。

**用户或编程常见的使用错误:**

* **忘记取消监听:**  如果 JavaScript 代码使用 `ResizeObserver` 监听了元素，但在不再需要时忘记调用 `unobserve()`，可能会导致内存泄漏和不必要的性能开销。
* **在回调中进行复杂的 DOM 操作:**  在 `ResizeObserver` 的回调函数中进行大量的 DOM 操作可能会导致布局抖动和性能问题。最佳实践是在回调中收集信息，然后在下一个渲染帧中进行 DOM 更新。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户操作触发尺寸变化:** 用户调整浏览器窗口大小，或者网页中的某些交互导致元素尺寸发生改变（例如，通过 JavaScript 动态修改元素的 CSS 属性）。
2. **Blink 布局引擎检测到尺寸变化:** Blink 的布局引擎会检测到这些尺寸变化。
3. **ResizeObserver 通知:** 如果有 `ResizeObserver` 监听了这些元素，布局引擎会通知 `ResizeObserver`。
4. **Document 的 ResizeObserver 处理:** `Document::EnsureResizeObserver()` 获取或创建 `ResizeObserver` 实例，并调用其 `observe()` 方法来注册监听。
5. **回调触发:** 当被监听的元素尺寸改变时，`ResizeObserver` 会调用其关联的 `Delegate` 的 `OnResize()` 方法。 例如，对于懒加载图片，会调用 `LazyLoadedAutoSizedImgResizeObserverDelegate::OnResize()`。
6. **JavaScript 回调:**  `ResizeObserver` 的 `OnResize()` 方法最终会触发 JavaScript 中注册的回调函数。

**调试线索:** 如果在调试与元素尺寸变化相关的问题时，你可以设置断点在以下位置来追踪代码执行流程：

* `Document::EnsureResizeObserver()`:  查看是否创建了 `ResizeObserver` 实例。
* `Document::ObserveForIntrinsicSize()` 或 `Document::ObserveForLazyLoadedAutoSizedImg()`:  确认哪些元素被监听了尺寸变化。
* `LazyLoadedAutoSizedImgResizeObserverDelegate::OnResize()`:  查看懒加载图片的尺寸变化是如何处理的。
* JavaScript 中 `ResizeObserver` 的回调函数:  查看 JavaScript 代码如何响应尺寸变化。

**3. 处理媒体查询 (Media Queries):**

* **`EvaluateMediaQueryListIfNeeded()`:**  如果需要，评估媒体查询列表。
* **`EvaluateMediaQueryList()`:**  评估媒体查询列表，并通知监听器（例如，更新样式）。
* **`LayoutViewportWasResized()`:** 当布局视口大小改变时被调用。它会通知媒体查询匹配器和触发 `resize` 事件。
* **`MarkViewportUnitsDirty()`:** 标记视口单位（例如 `vw`, `vh`) 为脏，以便重新计算。
* **`DynamicViewportUnitsChanged()`:** 当动态视口单位的值改变时被调用。
* **`MediaQueryAffectingValueChanged(MediaValueChange)`:**  通知媒体查询相关的某个值发生了变化。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  可以通过 JavaScript 访问和操作媒体查询（例如，使用 `window.matchMedia()`）。`LayoutViewportWasResized()` 的最终结果可能会影响 JavaScript 代码的执行。
* **HTML:**  `<link>` 标签的 `media` 属性允许根据媒体查询加载不同的 CSS 文件。
* **CSS:**  媒体查询是 CSS 的核心特性，允许根据不同的设备或视口特征应用不同的样式。这段代码负责评估这些 CSS 媒体查询。

**假设输入与输出:**

* **假设输入:** 用户调整浏览器窗口大小，导致媒体查询从不匹配变为匹配。
* **输出:** `LayoutViewportWasResized()` 被调用，接着 `MediaQueryAffectingValueChanged()` 和 `media_query_matcher_->ViewportChanged()` 被调用。浏览器会重新评估 CSS 样式，并应用与新媒体查询匹配的样式规则。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户调整浏览器窗口大小:** 这是触发媒体查询重新评估的最常见方式。
2. **操作系统通知浏览器窗口大小改变:** 操作系统会通知浏览器窗口大小发生了变化。
3. **Blink 接收到窗口大小改变的通知:** Blink 引擎接收到这个通知。
4. **`Document::LayoutViewportWasResized()` 被调用:**  文档对象会收到视口大小改变的通知。
5. **媒体查询评估:** `EvaluateMediaQueryListIfNeeded()` 或 `EvaluateMediaQueryList()` 被调用，Blink 会重新计算当前文档的媒体查询是否匹配。
6. **样式更新:** 如果媒体查询的状态发生变化，会触发样式的重新计算和渲染。

**调试线索:** 在调试媒体查询相关问题时，可以断点在以下位置：

* `Document::LayoutViewportWasResized()`:  确认视口大小改变的事件是否被正确捕获。
* `Document::EvaluateMediaQueryList()`:  查看媒体查询的评估过程。
* `MediaQueryMatcher::ViewportChanged()`:  查看媒体查询匹配器如何处理视口变化。
* 浏览器的开发者工具：使用 Network 面板查看 CSS 文件是否因为媒体查询的变化而被重新加载；使用 Elements 面板查看应用于元素的 CSS 规则是否因为媒体查询的变化而发生改变。

**总结 (针对第七部分):**

这部分 `document.cc` 代码主要负责了文档的克隆机制和对元素尺寸变化以及媒体查询的处理。它提供了核心的功能，使得浏览器能够复制文档结构，响应元素的尺寸变化，并根据不同的视口特征应用不同的 CSS 样式。这些功能是构建动态和响应式网页的基础。

### 提示词
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
ntext_)
    return nullptr;
  Document* clone = CloneDocumentWithoutChildren();
  clone->CloneDataFromDocument(*this);
  DocumentPartRoot* part_root = nullptr;
  DCHECK(!data.Has(CloneOption::kPreserveDOMPartsMinimalAPI) || !HasNodePart());
  if (data.Has(CloneOption::kPreserveDOMParts)) {
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
    DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
    part_root = &clone->getPartRoot();
    data.PushPartRoot(*part_root);
    PartRoot::CloneParts(*this, *clone, data);
  }
  if (data.Has(CloneOption::kIncludeDescendants)) {
    clone->CloneChildNodesFrom(*this, data);
  }
  DCHECK(!part_root || &data.CurrentPartRoot() == part_root);
  return clone;
}

ResizeObserver& Document::EnsureResizeObserver() {
  if (!intrinsic_size_observer_) {
    intrinsic_size_observer_ = ResizeObserver::Create(
        domWindow(),
        MakeGarbageCollected<IntrinsicSizeResizeObserverDelegate>());
  }
  return *intrinsic_size_observer_;
}

void Document::ObserveForIntrinsicSize(Element* element) {
  // Defaults to content-box, which is what we want.
  EnsureResizeObserver().observe(element);
}

void Document::UnobserveForIntrinsicSize(Element* element) {
  if (intrinsic_size_observer_)
    intrinsic_size_observer_->unobserve(element);
}

class LazyLoadedAutoSizedImgResizeObserverDelegate final
    : public ResizeObserver::Delegate {
  void OnResize(const HeapVector<Member<ResizeObserverEntry>>& entries) final {
    for (const auto& entry : entries) {
      DCHECK(entry->contentRect());
      if (auto* img = DynamicTo<HTMLImageElement>(entry->target())) {
        img->OnResize();
      }
    }
  }

  ResizeObserver::DeliveryTime Delivery() const final {
    return ResizeObserver::DeliveryTime::kBeforeOthers;
  }
};

ResizeObserver& Document::GetLazyLoadedAutoSizedImgObserver() {
  if (!lazy_loaded_auto_sized_img_observer_) {
    lazy_loaded_auto_sized_img_observer_ = ResizeObserver::Create(
        domWindow(),
        MakeGarbageCollected<LazyLoadedAutoSizedImgResizeObserverDelegate>());
  }

  return *lazy_loaded_auto_sized_img_observer_;
}

void Document::ObserveForLazyLoadedAutoSizedImg(HTMLImageElement* img) {
  GetLazyLoadedAutoSizedImgObserver().observe(img);
}

void Document::UnobserveForLazyLoadedAutoSizedImg(HTMLImageElement* img) {
  if (lazy_loaded_auto_sized_img_observer_) {
    lazy_loaded_auto_sized_img_observer_->unobserve(img);
  }
}

Document* Document::CloneDocumentWithoutChildren() const {
  DocumentInit init =
      DocumentInit::Create()
          .WithExecutionContext(execution_context_.Get())
          .WithAgent(GetAgent())
          .WithURL(Url())
          .WithFallbackBaseURL(Url().IsAboutBlankURL() ? fallback_base_url_
                                                       : KURL());
  if (IsA<XMLDocument>(this)) {
    if (IsXHTMLDocument())
      return XMLDocument::CreateXHTML(init);
    return MakeGarbageCollected<XMLDocument>(init);
  }
  return MakeGarbageCollected<Document>(init);
}

void Document::CloneDataFromDocument(const Document& other) {
  SetCompatibilityMode(other.GetCompatibilityMode());
  SetEncodingData(other.encoding_data_);
  SetMimeType(other.contentType());
}

void Document::EvaluateMediaQueryListIfNeeded() {
  if (!evaluate_media_queries_on_style_recalc_)
    return;
  EvaluateMediaQueryList();
  evaluate_media_queries_on_style_recalc_ = false;
}

void Document::EvaluateMediaQueryList() {
  if (media_query_matcher_)
    media_query_matcher_->MediaFeaturesChanged();
}

void Document::LayoutViewportWasResized() {
  if (!IsActive()) {
    return;
  }
  MediaQueryAffectingValueChanged(MediaValueChange::kSize);
  if (media_query_matcher_)
    media_query_matcher_->ViewportChanged();

  // We need to be careful not to trigger a resize event when setting the
  // initial layout size. It might seem like the correct check should be
  // (load_event_progress_ >= kLoadEventInProgress), but that doesn't actually
  // work because the initial value of load_event_progress_ is
  // kLoadEventCompleted. DidFirstLayout() is a reliable indicator that the load
  // event *actually* completed; but we also need to fire a resize event if the
  // window size changes during load event dispatch.
  // Note that in the case of the initial empty document, the load may hav
  // completed before performing the first layout.
  if ((View() && View()->DidFirstLayout()) ||
      load_event_progress_ == kLoadEventInProgress || IsLoadCompleted()) {
    EnqueueResizeEvent();
    EnqueueVisualViewportResizeEvent();
    if (GetFrame()->IsMainFrame() && !Printing())
      probe::DidResizeMainFrame(GetFrame());
  }

  MarkViewportUnitsDirty();
}

void Document::MarkViewportUnitsDirty() {
  if (!HasViewportUnits())
    return;
  GetStyleResolver().SetResizedForViewportUnits();
  GetStyleEngine().MarkViewportUnitDirty(ViewportUnitFlag::kStatic);
  GetStyleEngine().MarkViewportUnitDirty(ViewportUnitFlag::kDynamic);
}

void Document::DynamicViewportUnitsChanged() {
  MediaQueryAffectingValueChanged(MediaValueChange::kDynamicViewport);
  if (media_query_matcher_)
    media_query_matcher_->DynamicViewportChanged();
  if (!HasDynamicViewportUnits())
    return;
  GetStyleResolver().SetResizedForViewportUnits();
  GetStyleEngine().MarkViewportUnitDirty(ViewportUnitFlag::kDynamic);
}

void EmitDidChangeHoverElement(Document& document, Element* new_hover_element) {
  LocalFrame* local_frame = document.GetFrame();
  if (!local_frame) {
    return;
  }

  WebLinkPreviewTriggerer* triggerer =
      local_frame->GetOrCreateLinkPreviewTriggerer();
  if (!triggerer) {
    return;
  }

  WebElement web_element = WebElement(DynamicTo<Element>(new_hover_element));
  triggerer->DidChangeHoverElement(web_element);
}

void Document::SetHoverElement(Element* new_hover_element) {
  HTMLElement::HoveredElementChanged(hover_element_, new_hover_element);
  EmitDidChangeHoverElement(*this, new_hover_element);

  hover_element_ = new_hover_element;
}

void Document::SetActiveElement(Element* new_active_element) {
  if (!new_active_element) {
    active_element_.Clear();
    return;
  }

  active_element_ = new_active_element;
}

void Document::RemoveFocusedElementOfSubtree(Node& node,
                                             bool among_children_only) {
  if (!node.isConnected() || !focused_element_ ||
      !node.IsShadowIncludingInclusiveAncestorOf(*focused_element_)) {
    return;
  }
  const auto& focused_element = *node.GetTreeScope().AdjustedFocusedElement();
  if (focused_element.IsDescendantOf(&node) ||
      (!among_children_only && node == focused_element)) {
    bool omit_blur_events =
        RuntimeEnabledFeatures::OmitBlurEventOnElementRemovalEnabled();
    ClearFocusedElement(omit_blur_events);
  }
}

static Element* SkipDisplayNoneAncestors(Element* element) {
  for (; element; element = FlatTreeTraversal::ParentElement(*element)) {
    if (element->GetLayoutObject() || element->HasDisplayContentsStyle())
      return element;
  }
  return nullptr;
}

static Element* SkipDisplayNoneAncestorsOrReturnNullIfFlatTreeIsDirty(
    Element& element) {
  if (element.GetDocument().IsSlotAssignmentDirty()) {
    // We shouldn't use FlatTreeTraversal during detach if slot assignment is
    // dirty because it might trigger assignment recalc. The hover and active
    // elements are then set to null. The hover element is updated on the next
    // lifecycle update instead.
    //
    // TODO(crbug.com/939769): The active element is not updated on the next
    // lifecycle update, and is generally not correctly updated on re-slotting.
    return nullptr;
  }
  return SkipDisplayNoneAncestors(&element);
}

void Document::HoveredElementDetached(Element& element) {
  if (!hover_element_)
    return;
  if (element != hover_element_)
    return;
  hover_element_ =
      SkipDisplayNoneAncestorsOrReturnNullIfFlatTreeIsDirty(element);

  // If the mouse cursor is not visible, do not clear existing
  // hover effects on the ancestors of |element| and do not invoke
  // new hover effects on any other element.
  if (!GetPage()->IsCursorVisible())
    return;

  if (GetFrame())
    GetFrame()->GetEventHandler().ScheduleHoverStateUpdate();
}

void Document::ActiveChainNodeDetached(Element& element) {
  if (active_element_ && element == active_element_) {
    active_element_ =
        SkipDisplayNoneAncestorsOrReturnNullIfFlatTreeIsDirty(element);
  }
}

const Vector<DraggableRegionValue>& Document::DraggableRegions() const {
  return draggable_regions_;
}

void Document::SetDraggableRegions(
    const Vector<DraggableRegionValue>& regions) {
  draggable_regions_ = regions;
  SetDraggableRegionsDirty(false);
}

void Document::SetLastFocusType(mojom::blink::FocusType last_focus_type) {
  last_focus_type_ = last_focus_type;
}

bool Document::SetFocusedElement(Element* new_focused_element,
                                 const FocusParams& params) {
  DCHECK(!lifecycle_.InDetach());

  clear_focused_element_timer_.Stop();

  // Make sure new_focused_element is actually in this document.
  if (new_focused_element) {
    if (new_focused_element->GetDocument() != this)
      return true;

    if (NodeChildRemovalTracker::IsBeingRemoved(*new_focused_element))
      return true;
  }

  if (focused_element_ == new_focused_element)
    return true;

  bool focus_change_blocked = false;
  Element* old_focused_element = focused_element_;
  focused_element_ = nullptr;

  Element* ancestor =
      (old_focused_element && old_focused_element->isConnected() &&
       new_focused_element)
          ? DynamicTo<Element>(FlatTreeTraversal::CommonAncestor(
                *old_focused_element, *new_focused_element))
          : nullptr;

  // Remove focus from the existing focus node (if any)
  if (old_focused_element) {
    old_focused_element->SetFocused(false, params.type);
    old_focused_element->SetHasFocusWithinUpToAncestor(false, ancestor, true);

    DisplayLockUtilities::ElementLostFocus(old_focused_element);

    // Dispatch the blur event and let the node do any other blur related
    // activities (important for text fields)
    // If page lost focus, blur event will have already been dispatched
    if (!params.omit_blur_events && GetPage() &&
        (GetPage()->GetFocusController().IsFocused())) {
      old_focused_element->DispatchBlurEvent(new_focused_element, params.type,
                                             params.source_capabilities);
      if (focused_element_) {
        // handler shifted focus
        focus_change_blocked = true;
        new_focused_element = nullptr;
      }

      // 'focusout' is a DOM level 3 name for the bubbling blur event.
      old_focused_element->DispatchFocusOutEvent(event_type_names::kFocusout,
                                                 new_focused_element,
                                                 params.source_capabilities);
      // 'DOMFocusOut' is a DOM level 2 name for compatibility.
      // FIXME: We should remove firing DOMFocusOutEvent event when we are sure
      // no content depends on it, probably when <rdar://problem/8503958> is
      // resolved.
      old_focused_element->DispatchFocusOutEvent(event_type_names::kDOMFocusOut,
                                                 new_focused_element,
                                                 params.source_capabilities);

      if (focused_element_) {
        // handler shifted focus
        focus_change_blocked = true;
        new_focused_element = nullptr;
      }
    }
  }

  // Blur/focusout handlers could have moved the new element out of this
  // document. See crbug.com/1204223.
  if (new_focused_element && new_focused_element->GetDocument() != this)
    return true;

  if (new_focused_element) {
    UpdateStyleAndLayoutTreeForElement(new_focused_element,
                                       DocumentUpdateReason::kFocus);
  }

  if (new_focused_element && new_focused_element->IsFocusable()) {
    if (IsRootEditableElement(*new_focused_element) &&
        !AcceptsEditingFocus(*new_focused_element)) {
      // delegate blocks focus change
      UpdateStyleAndLayoutTree();
      if (LocalFrame* frame = GetFrame())
        frame->Selection().DidChangeFocus();
      return false;
    }
    // Set focus on the new node
    focused_element_ = new_focused_element;
    SetSequentialFocusNavigationStartingPoint(focused_element_.Get());

    // Keep track of last focus from user interaction, ignoring focus from code
    // and other non-user internal interventions.
    if (params.type != mojom::blink::FocusType::kNone &&
        params.type != mojom::blink::FocusType::kScript)
      SetLastFocusType(params.type);

    for (auto& observer : focused_element_change_observers_)
      observer->DidChangeFocus();

    focused_element_->SetFocused(true, params.type);
    // Setting focus can cause the element to become detached (e.g. if an
    // ancestor element's onblur removes it), so return early here if that's
    // happened.
    if (focused_element_ == nullptr) {
      return false;
    }
    focused_element_->SetHasFocusWithinUpToAncestor(true, ancestor, true);
    DisplayLockUtilities::ElementGainedFocus(focused_element_.Get());

    // Element::setFocused for frames can dispatch events.
    if (focused_element_ != new_focused_element) {
      UpdateStyleAndLayoutTree();
      if (LocalFrame* frame = GetFrame())
        frame->Selection().DidChangeFocus();
      return false;
    }
    SetShouldUpdateSelectionAfterLayout(false);
    EnsurePaintLocationDataValidForNode(focused_element_,
                                        DocumentUpdateReason::kFocus);
    focused_element_->UpdateSelectionOnFocus(params.selection_behavior,
                                             params.options);

    // Dispatch the focus event and let the node do any other focus related
    // activities (important for text fields)
    // If page lost focus, event will be dispatched on page focus, don't
    // duplicate
    if (GetPage() && (GetPage()->GetFocusController().IsFocused())) {
      focused_element_->DispatchFocusEvent(old_focused_element, params.type,
                                           params.source_capabilities);

      if (focused_element_ != new_focused_element) {
        // handler shifted focus
        UpdateStyleAndLayoutTree();
        if (LocalFrame* frame = GetFrame())
          frame->Selection().DidChangeFocus();
        return false;
      }
      // DOM level 3 bubbling focus event.
      focused_element_->DispatchFocusInEvent(event_type_names::kFocusin,
                                             old_focused_element, params.type,
                                             params.source_capabilities);

      if (focused_element_ != new_focused_element) {
        // handler shifted focus
        UpdateStyleAndLayoutTree();
        if (LocalFrame* frame = GetFrame())
          frame->Selection().DidChangeFocus();
        return false;
      }

      // For DOM level 2 compatibility.
      // FIXME: We should remove firing DOMFocusInEvent event when we are sure
      // no content depends on it, probably when <rdar://problem/8503958> is m.
      focused_element_->DispatchFocusInEvent(event_type_names::kDOMFocusIn,
                                             old_focused_element, params.type,
                                             params.source_capabilities);

      if (focused_element_ != new_focused_element) {
        // handler shifted focus
        UpdateStyleAndLayoutTree();
        if (LocalFrame* frame = GetFrame())
          frame->Selection().DidChangeFocus();
        return false;
      }
    }
  }

  if (!focus_change_blocked) {
    NotifyFocusedElementChanged(old_focused_element, focused_element_.Get(),
                                params.type);
  }

  UpdateStyleAndLayoutTree();
  if (LocalFrame* frame = GetFrame())
    frame->Selection().DidChangeFocus();

  // EditContext's activation is synced with the associated element being
  // focused or not. If an element loses focus, its associated EditContext
  // is deactivated. If getting focus, the EditContext is activated.
  if (old_focused_element) {
    if (auto* old_edit_context = old_focused_element->editContext()) {
      old_edit_context->Blur();
    }
  }
  if (new_focused_element) {
    if (auto* edit_context = new_focused_element->editContext()) {
      edit_context->Focus();
    }
  }

  return !focus_change_blocked;
}

void Document::ClearFocusedElement(bool omit_blur_events) {
  FocusParams params(SelectionBehaviorOnFocus::kNone,
                     mojom::blink::FocusType::kNone, nullptr);
  params.omit_blur_events = omit_blur_events;
  SetFocusedElement(nullptr, params);
}

void Document::SendFocusNotification(Element* new_focused_element,
                                     mojom::blink::FocusType focus_type) {
  if (!GetPage())
    return;

  bool is_editable = false;
  bool is_richly_editable = false;
  gfx::Rect element_bounds_in_dips;
  if (new_focused_element) {
    auto* text_control = ToTextControlOrNull(new_focused_element);
    is_editable =
        IsEditable(*new_focused_element) ||
        (text_control && !text_control->IsDisabledOrReadOnly()) ||
        EqualIgnoringASCIICase(
            new_focused_element->FastGetAttribute(html_names::kRoleAttr),
            "textbox");
    is_richly_editable = IsRichlyEditable(*new_focused_element);
    gfx::Rect bounds_in_viewport;

    if (new_focused_element->IsSVGElement()) {
      // Convert to window coordinate system (this will be in DIPs).
      bounds_in_viewport = new_focused_element->BoundsInWidget();
    } else {
      Vector<gfx::Rect> outline_rects =
          new_focused_element->OutlineRectsInWidget(
              DocumentUpdateReason::kFocus);
      for (auto& outline_rect : outline_rects)
        bounds_in_viewport.Union(outline_rect);
    }

    if (GetFrame()->GetWidgetForLocalRoot()) {
      element_bounds_in_dips =
          GetFrame()->GetWidgetForLocalRoot()->BlinkSpaceToEnclosedDIPs(
              bounds_in_viewport);
    } else {
      element_bounds_in_dips = bounds_in_viewport;
    }
  }

  GetFrame()->GetLocalFrameHostRemote().FocusedElementChanged(
      is_editable, is_richly_editable, element_bounds_in_dips, focus_type);
}

void Document::NotifyFocusedElementChanged(Element* old_focused_element,
                                           Element* new_focused_element,
                                           mojom::blink::FocusType focus_type) {
  // |old_focused_element| may not belong to this document by invoking
  // adoptNode in event handlers during moving the focus to the new element.
  DCHECK(!new_focused_element || new_focused_element->GetDocument() == this);

  if (AXObjectCache* cache = ExistingAXObjectCache()) {
    cache->HandleFocusedUIElementChanged(old_focused_element,
                                         new_focused_element);
  }

  if (GetPage()) {
    GetPage()->GetValidationMessageClient().DidChangeFocusTo(
        new_focused_element);

    SendFocusNotification(new_focused_element, focus_type);

    Document* old_document =
        old_focused_element ? &old_focused_element->GetDocument() : nullptr;
    if (old_document && old_document != this && old_document->GetFrame())
      old_document->GetFrame()->Client()->FocusedElementChanged(nullptr);

    // Ensures that further text input state can be sent even when previously
    // focused input and the newly focused input share the exact same state.
    if (GetFrame()->GetWidgetForLocalRoot())
      GetFrame()->GetWidgetForLocalRoot()->ClearTextInputState();
    GetFrame()->Client()->FocusedElementChanged(new_focused_element);

    GetPage()->GetChromeClient().SetKeyboardFocusURL(new_focused_element);
  }

  blink::NotifyPriorityScrollAnchorStatusChanged(old_focused_element,
                                                 new_focused_element);
}

void Document::SetSequentialFocusNavigationStartingPoint(Node* node) {
  if (!dom_window_)
    return;
  if (!node || node->GetDocument() != this) {
    sequential_focus_navigation_starting_point_ = nullptr;
    return;
  }
  if (!sequential_focus_navigation_starting_point_)
    sequential_focus_navigation_starting_point_ = Range::Create(*this);
  sequential_focus_navigation_starting_point_->selectNodeContents(
      node, ASSERT_NO_EXCEPTION);
}

Element* Document::SequentialFocusNavigationStartingPoint(
    mojom::blink::FocusType type) const {
  if (focused_element_)
    return focused_element_.Get();
  if (!sequential_focus_navigation_starting_point_)
    return nullptr;
  DCHECK(sequential_focus_navigation_starting_point_->IsConnected());
  if (!sequential_focus_navigation_starting_point_->collapsed()) {
    Node* node = sequential_focus_navigation_starting_point_->startContainer();
    DCHECK_EQ(node,
              sequential_focus_navigation_starting_point_->endContainer());
    if (auto* element = DynamicTo<Element>(node))
      return element;
    if (Element* neighbor_element = type == mojom::blink::FocusType::kForward
                                        ? ElementTraversal::Previous(*node)
                                        : ElementTraversal::Next(*node))
      return neighbor_element;
    return node->ParentOrShadowHostElement();
  }

  // Range::selectNodeContents didn't select contents because the element had
  // no children.
  auto* element = DynamicTo<Element>(
      sequential_focus_navigation_starting_point_->startContainer());
  if (element && !element->hasChildren() &&
      sequential_focus_navigation_starting_point_->startOffset() == 0)
    return element;

  // A node selected by Range::selectNodeContents was removed from the
  // document tree.
  if (Node* next_node =
          sequential_focus_navigation_starting_point_->FirstNode()) {
    if (next_node->IsShadowRoot())
      return next_node->OwnerShadowHost();
    // TODO(tkent): Using FlatTreeTraversal is inconsistent with
    // FocusController. Ideally we should find backward/forward focusable
    // elements before the starting point is disconnected. crbug.com/606582
    if (type == mojom::blink::FocusType::kForward) {
      Node* previous = FlatTreeTraversal::Previous(*next_node);
      for (; previous; previous = FlatTreeTraversal::Previous(*previous)) {
        if (auto* previous_element = DynamicTo<Element>(previous))
          return previous_element;
      }
    }
    for (Node* next = next_node; next; next = FlatTreeTraversal::Next(*next)) {
      if (auto* next_element = DynamicTo<Element>(next))
        return next_element;
    }
  }
  return nullptr;
}

void Document::SetSelectorFragmentAnchorCSSTarget(Element* new_target) {
  SetCSSTarget(new_target);
  if (css_target_) {
    css_target_is_selector_fragment_ = true;
    css_target_->PseudoStateChanged(CSSSelector::kPseudoSelectorFragmentAnchor);
  }
}

void Document::SetCSSTarget(Element* new_target) {
  if (css_target_) {
    css_target_->PseudoStateChanged(CSSSelector::kPseudoTarget);
    if (css_target_is_selector_fragment_) {
      css_target_->PseudoStateChanged(
          CSSSelector::kPseudoSelectorFragmentAnchor);
    }
    css_target_->ClearTargetedSnapAreaIdsForSnapContainers();
  }
  css_target_ = new_target;
  css_target_is_selector_fragment_ = false;
  if (css_target_) {
    css_target_->PseudoStateChanged(CSSSelector::kPseudoTarget);
    css_target_->SetTargetedSnapAreaIdsForSnapContainers();
  }
}

void Document::RegisterNodeList(const LiveNodeListBase* list) {
  node_lists_.Add(list, list->InvalidationType());
  if (list->IsRootedAtTreeScope())
    lists_invalidated_at_document_.insert(list);
}

void Document::UnregisterNodeList(const LiveNodeListBase* list) {
  node_lists_.Remove(list, list->InvalidationType());
  if (list->IsRootedAtTreeScope()) {
    DCHECK(lists_invalidated_at_document_.Contains(list));
    lists_invalidated_at_document_.erase(list);
  }
}

void Document::RegisterNodeListWithIdNameCache(const LiveNodeListBase* list) {
  node_lists_.Add(list, kInvalidateOnIdNameAttrChange);
}

void Document::UnregisterNodeListWithIdNameCache(const LiveNodeListBase* list) {
  node_lists_.Remove(list, kInvalidateOnIdNameAttrChange);
}

void Document::AttachNodeIterator(NodeIterator* ni) {
  node_iterators_.insert(ni);
}

void Document::DetachNodeIterator(NodeIterator* ni) {
  // The node iterator can be detached without having been attached if its root
  // node didn't have a document when the iterator was created, but has it now.
  node_iterators_.erase(ni);
}

void Document::MoveNodeIteratorsToNewDocument(Node& node,
                                              Document& new_document) {
  HeapHashSet<WeakMember<NodeIterator>> node_iterators_list = node_iterators_;
  for (NodeIterator* ni : node_iterators_list) {
    if (ni->root() == node) {
      DetachNodeIterator(ni);
      new_document.AttachNodeIterator(ni);
    }
  }
}

void Document::DidMoveTreeToNewDocument(const Node& root) {
  DCHECK_NE(root.GetDocument(), this);
  if (!ranges_.empty()) {
    AttachedRangeSet ranges = ranges_;
    for (Range* range : ranges)
      range->UpdateOwnerDocumentIfNeeded();
  }
  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->DidMoveTreeToNewDocument(root);
      });
}

void Document::NodeChildrenWillBeRemoved(ContainerNode& container) {
  EventDispatchForbiddenScope assert_no_event_dispatch;
  for (Range* range : ranges_) {
    range->NodeChildrenWillBeRemoved(container);
    if (range == sequential_focus_navigation_starting_point_)
      range->FixupRemovedChildrenAcrossShadowBoundary(container);
  }

  for (NodeIterator* ni : node_iterators_) {
    for (Node& n : NodeTraversal::ChildrenOf(container))
      ni->NodeWillBeRemoved(n);
  }

  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->NodeChildrenWillBeRemoved(container);
      });

  if (MayContainShadowRoots()) {
    for (Node& n : NodeTraversal::ChildrenOf(container))
      n.CheckSlotChangeBeforeRemoved();
  }
}

void Document::NodeWillBeRemoved(Node& n) {
  for (NodeIterator* ni : node_iterators_)
    ni->NodeWillBeRemoved(n);

  // We want to run the normal Range reset code when we're not in the middle of
  // `moveBefore()`, or when we *are* but when range preservation is disabled
  // (it is by default).
  if (!StatePreservingAtomicMoveInProgress() ||
      !RuntimeEnabledFeatures::AtomicMoveRangePreservationEnabled()) {
    for (Range* range : ranges_) {
      range->NodeWillBeRemoved(n);
      if (range == sequential_focus_navigation_starting_point_) {
        range->FixupRemovedNodeAcrossShadowBoundary(n);
      }
    }
  }

  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->NodeWillBeRemoved(n);
      });

  if (MayContainShadowRoots())
    n.CheckSlotChangeBeforeRemoved();

  if (n.InActiveDocument())
    GetStyleEngine().NodeWillBeRemoved(n);
}

void Document::NotifyUpdateCharacterData(CharacterData* character_data,
                                         const TextDiffRange& diff) {
  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->DidUpdateCharacterData(character_data, diff.offset,
                                         diff.old_size, diff.new_size);
      });
}

void Document::NotifyChangeChildren(
    const ContainerNode& container,
    const ContainerNode::ChildrenChange& change) {
  if (LocalFrameView* frame_view = View()) {
    if (FragmentAnchor* anchor = frame_view->GetFragmentAnchor()) {
      anchor->NewContentMayBeAvailable();
    }
  }

  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->DidChangeChildren(container, change);
      });
}

void Document::NotifyAttributeChanged(const Element& element,
                                      const QualifiedName& name,
                                      const AtomicString& old_value,
                                      const AtomicString& new_value) {
  // There are other attributes (not to mention style changes) that could
  // potentially make more content available to the fragment anchor but
  // this is a best effort heuristic, based on commonly seen patterns in the
  // wild, so isn't meant to be comprehensive.
  if (name == html_names::kHiddenAttr) {
    if (LocalFrameView* frame_view = View()) {
      if (FragmentAnchor* anchor = frame_view->GetFragmentAnchor()) {
        anchor->NewContentMayBeAvailable();
      }
    }
  }

  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->AttributeChanged(element, name, old_value, new_value);
      });
}

void Document::DidInsertText(const CharacterData& text,
                             unsigned offset,
                             unsigned length) {
  for (Range* range : ranges_)
    range->DidInsertText(text, offset, length);
}

void Document::DidRemoveText(const CharacterData& text,
                             unsigned offset,
                             unsigned length) {
  for (Range* range : ranges_)
    range->DidRemoveText(text, offset, length);
}

void Document::DidMergeTextNodes(const Text& merged_node,
                                 const Text& node_to_be_removed,
                                 unsigned old_length) {
  NodeWithIndex node_to_be_removed_with_index(
      const_cast<Text&>(node_to_be_removed));
  if (!ranges_.empty()) {
    for (Range* range : ranges_)
      range->DidMergeTextNodes(node_to_be_removed_with_index, old_length);
  }

  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->DidMergeTextNodes(merged_node, node_to_be_removed_with_index,
                                    old_length);
      });

  // FIXME: This should update markers for spelling and grammar checking.
}

void Document::DidSplitTextNode(const Text& old_node) {
  for (Range* range : ranges_)
    range->DidSplitTextNode(old_node);

  synchronous_mutation_observer_set_.ForEachObserver(
      [&](SynchronousMutationObserver* observer) {
        observer->DidSplitTextNode(old_node);
      });

  // FIXME: This should update markers for spelling and grammar checking.
}

void Document::SetWindowAttributeEventListener(const AtomicString& event_type,
                                               EventListener* listener) {
  LocalDOMWindow* dom_window = domWindow();
  if (!dom_window)
    return;
  dom_window->SetAttributeEventListener(event_type, listener);
}

EventListener* Document::GetWindowAttributeEventListener(
    const AtomicString& event_type) {
  LocalDOMWindow* dom_window = domWindow();
  if (!dom_window)
    return nullptr;
  return dom_window->GetAttributeEventListener(event_type);
}

void Document::EnqueueDisplayLockActivationTask(base::OnceClosure task) {
  scripted_animation_controller_->EnqueueTask(std::move(task));
}

void Document::EnqueueAnimationFrameTask(base::OnceClosure task) {
  scripted_animation_controller_->EnqueueTask(std::move(task));
}

void Document::EnqueueAnimationFrameEvent(Event* event) {
  scripted_animation_controller_->EnqueueEvent(event);
}

void Document::EnqueueUniqueAnimationFrameEvent(Event* event) {
  scripted_animation_controller_->EnqueuePerFrameEvent(event);
}

void Document::EnqueueScrollEventForNode(Node* target) {
  // Per the W3C CSSOM View Module only scroll events fired at the document
  // should bubble.
  overscroll_accumulated_delta_x_ = overscroll_accumulated_delta_y_ = 0;
  Event* scroll_event = target->IsDocumentNode()
                            ? Event::CreateBubble(event_type_names::kScroll)
                            : Event::Create(event_type_names::kScroll);
  scroll_event->SetTarget(target);
  scripted_animation_controller_->EnqueuePerFrameEvent(scroll_event);
}

void Document::EnqueueScrollEndEventForNode(Node* target) {
  // Mimic bubbling behavior of scroll event for consistency.
  overscroll_accumulated_delta_x_ = overscroll_accumulated_delta_y_ = 0;
  Event* scroll_end_event =
      target->IsDocumentNode()
          ? Event::CreateBubble(event_type_names::kScrollend)
          : Event::Create(event_type_names::kScrollend);
  scroll_end_event->SetTarget(target);
  scripted_animation_controller_->EnqueuePerFrameEvent(scroll_end_event);
}

void Document::EnqueueOverscrollEventForNode(Node* target,
                                             double delta_x,
                                             double delta_y) {
  // Mimic bubbling behavior of scroll event for consistency.
  overscroll_accumulated_
```