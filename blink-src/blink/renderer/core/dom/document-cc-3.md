Response:
My thought process for analyzing the `document.cc` code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the `document.cc` file in the Chromium Blink engine, focusing on its relationship with JavaScript, HTML, and CSS, and providing examples, debugging insights, and a high-level overview.

2. **Initial Scan and Keyword Recognition:**  I quickly scanned the code, looking for recurring keywords and patterns. "Style," "Layout," "Update," "Invalidate," "Tree," "DOM," "JavaScript," "HTML," and "CSS" jumped out. This immediately told me the file is heavily involved in the rendering pipeline.

3. **Identify Key Functions:**  I started identifying the main functions and their purpose. Functions like `UpdateStyle`, `UpdateLayoutTree`, `UpdateStyleAndLayout`, `NeedsLayoutTreeUpdateForNode`, `InvalidateStyleAndLayoutForFontUpdates` are clearly central to the file's functionality.

4. **Infer Function Relationships:** I noticed how these functions call each other. `UpdateStyleAndLayout` seems to be a high-level orchestrator, calling `UpdateStyle` and implicitly triggering layout updates. `NeedsLayoutTreeUpdateForNode` is a decision point before triggering updates. This suggested a hierarchical process.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**  Based on the function names and keywords, I started connecting them to web technologies:
    * **CSS:** Functions like `UpdateStyle`, `InvalidateStyleAndLayoutForFontUpdates`, and mentions of `StyleEngine` and `StyleResolver` directly relate to CSS processing.
    * **HTML:** The file interacts with the DOM (Document Object Model), which is a representation of HTML. The presence of functions dealing with node connections, shadow DOM (`UpdateUseShadowTreesIfNeeded`), and the overall document lifecycle points to HTML interaction.
    * **JavaScript:** While the `document.cc` file is C++, it interacts with JavaScript. The comments about "running script," the inclusion of timers (`clear_focused_element_timer_`), and the handling of events (`RemovedEventListener`) indicate this interaction. The `FontFaceSetDocument::DidLayout(*this)` call suggests communication related to font loading events in JavaScript.

6. **Look for Logic and Decision Points:**  I paid attention to `if` statements and boolean flags. The `NeedsLayoutTreeUpdateForThisDocument()` check is a crucial optimization, preventing unnecessary recalculations. The logic around display locking (`DisplayLockUtilities`) adds complexity and indicates a performance optimization.

7. **Identify Potential Errors and Debugging Information:**  The `DCHECK` and `CHECK` macros are strong indicators of internal assertions and potential error points. The tracing statements (`TRACE_EVENT`) provide debugging information. The comments about "re-entering style recalc" being a fatal error highlight common pitfalls. The section on `ApplyScrollRestorationLogic` provides a clear example of how user actions (scrolling, navigation) can lead to code execution in this file.

8. **Focus on Specific Examples:**  For each web technology, I tried to come up with concrete examples based on the code:
    * **JavaScript:** Modifying CSS properties via JavaScript will trigger style recalculation, leading to calls in this file.
    * **HTML:** Adding or removing elements, or changing their attributes, can trigger layout updates. The example with `<object>` elements illustrates a specific scenario.
    * **CSS:** Changing CSS rules, especially those affecting layout (like `display`, `position`, `width`), will definitely involve this file.

9. **Infer User Actions:** I thought about how user interactions could trigger the code in `document.cc`. Loading a page, scrolling, clicking, and even focusing elements are all potential triggers. The `ApplyScrollRestorationLogic` section was particularly helpful here.

10. **Consider Assumptions and Outputs:**  While the code doesn't have explicit "inputs" in the traditional sense of a function, I considered the *state* of the document and the DOM as the implicit input. The "output" is the updated visual representation of the page and the internal state of the rendering engine.

11. **Structure the Response:** I organized the information into logical categories based on the request: functionality, relationships with web technologies, examples, assumptions, common errors, debugging, and a summary.

12. **Refine and Elaborate:**  I reviewed my initial thoughts and tried to provide more detail and context where necessary. For instance, I elaborated on the role of the `StyleEngine` and `LayoutView`.

13. **Address the "Part X of Y" Instruction:**  Finally, I ensured I addressed the specific instruction to summarize the functionality as part of a larger sequence. This involved emphasizing the central role of `document.cc` in the style and layout pipeline.

By following these steps, I could systematically analyze the code snippet and generate a comprehensive and informative response that addressed all aspects of the request. The process involves a combination of code reading, domain knowledge about web technologies and browser rendering, and logical reasoning.
这是提供的 `blink/renderer/core/dom/document.cc` 文件的第四部分，根据其内容，可以归纳出以下功能：

**核心功能：样式和布局更新管理**

这部分代码主要负责管理文档的样式（CSS）和布局（Layout Tree）的更新过程，确保浏览器能够正确地呈现网页。其核心目标是：

* **决定是否需要更新样式和布局:** 通过检查文档和节点的状态，判断是否需要进行样式重算和布局树更新，避免不必要的计算，提高性能。
* **触发和执行样式重算:**  调用 `StyleEngine` 的方法来更新元素的样式，处理各种样式相关的逻辑，例如媒体查询、CSS 计数器、视口单位等。
* **触发和执行布局树更新:** 在样式更新完成后，通知布局系统进行布局计算，将样式信息转化为实际的页面排布。
* **处理与更新相关的优化和特殊情况:**  例如，处理 Shadow DOM 的更新 (`UpdateUseShadowTreesIfNeeded`)，处理 SVG 资源的失效 (`InvalidatePendingSVGResources`)，以及处理字体更新导致的样式和布局失效。
* **管理文档的生命周期状态:**  通过 `lifecycle_` 对象跟踪文档所处的阶段（例如 `kInStyleRecalc`, `kStyleClean`, `kLayoutClean`），确保操作在正确的时机进行。

**与 JavaScript, HTML, CSS 的关系及举例：**

* **CSS:**  `document.cc` 负责将 CSS 规则应用到 HTML 元素上。
    * **例子:** 当 JavaScript 修改了元素的 `style` 属性（例如 `element.style.color = 'red'`)，或者添加/修改了 `<style>` 标签或外部 CSS 文件时，会触发样式失效，最终导致 `UpdateStyle` 等函数被调用。
    * **假设输入:** JavaScript 代码 `document.getElementById('myDiv').style.display = 'none';`
    * **输出:** `UpdateStyle` 函数会被调用，重新计算 `#myDiv` 及其子元素的样式，布局树也会更新以反映 `display: none` 的效果。

* **HTML:**  `document.cc` 基于 HTML 结构构建和更新布局树。
    * **例子:** 当 JavaScript 通过 DOM API (例如 `document.createElement`, `appendChild`) 添加或删除 HTML 元素时，会触发布局失效，需要更新布局树。
    * **假设输入:** JavaScript 代码 `document.body.appendChild(document.createElement('p'));`
    * **输出:**  `NeedsLayoutTreeUpdateForThisDocument` 返回 `true`，`UpdateStyleAndLayout` 会被调用，将新的 `<p>` 元素添加到布局树中。

* **JavaScript:**  `document.cc` 的某些操作可能由 JavaScript 触发，反过来，样式和布局的更新也会影响 JavaScript 的执行环境。
    * **例子:** JavaScript 可以监听 `resize` 事件，当浏览器窗口大小改变时，会触发样式重算和布局更新，因为视口大小变化影响了 CSS 的视口单位。
    * **假设输入:** 用户调整浏览器窗口大小。
    * **输出:** `EvaluateMediaQueryListIfNeeded` 会被调用，重新评估媒体查询，如果媒体查询结果发生变化，会触发样式和布局的更新。

**逻辑推理的假设输入与输出：**

* **假设输入:**  一个 HTML 页面加载完成，但 CSS 文件尚未完全解析。
* **输出:**  `NeedsLayoutTreeUpdateForThisDocument` 最初可能返回 `false`，因为样式信息不完整。当 CSS 文件解析完成后，会触发样式失效，导致后续的样式和布局更新。

* **假设输入:**  一个元素的 `visibility` 属性通过 CSS 从 `visible` 变为 `hidden`。
* **输出:**  `NeedsLayoutTreeUpdateForNode` 会针对该元素返回 `true`，因为 `visibility` 属性影响布局（元素占据空间但不可见）。

**用户或编程常见的使用错误及举例：**

* **频繁地、小幅度地修改样式:**  如果 JavaScript 代码在一个循环中频繁修改元素的样式（例如，每次循环只改变 1px 的位置），会导致浏览器进行大量的样式重算和布局更新，影响性能，造成卡顿。
    * **例子:**
    ```javascript
    const element = document.getElementById('animate');
    for (let i = 0; i < 100; i++) {
      element.style.left = i + 'px'; // 错误：每次循环都触发样式和布局
    }
    ```
    **调试线索：** 开发者工具的 Performance 面板会显示大量的 "Recalculate Style" 和 "Layout" 事件。

* **在布局或绘制过程中修改 DOM 或样式:**  在某些情况下，例如在处理 `scroll` 事件时尝试修改 DOM 或样式，可能会导致强制同步布局（Forced Synchronous Layout），阻塞渲染流水线，影响性能。
    * **例子:**
    ```javascript
    window.addEventListener('scroll', () => {
      document.getElementById('indicator').textContent = window.scrollY; // 可能触发强制同步布局
    });
    ```
    **调试线索：**  开发者工具的 Performance 面板会警告 "Avoid forced synchronous layout"。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户加载网页:** 浏览器开始解析 HTML、CSS 和 JavaScript。
2. **CSSOM 构建:**  浏览器解析 CSS，构建 CSS 对象模型 (CSSOM)。
3. **渲染树构建:** 浏览器将 DOM 和 CSSOM 结合，构建渲染树 (Render Tree)。
4. **布局:** 浏览器根据渲染树计算每个元素在页面中的确切位置和大小。 这部分逻辑很大程度上由 `document.cc` 中的函数管理。
5. **绘制:** 浏览器将布局计算的结果绘制到屏幕上。

**更具体的调试线索：**

* **JavaScript 修改样式:** 用户与页面交互，例如点击按钮，触发 JavaScript 代码修改元素的 `style` 属性。这会导致样式失效，`Document::UpdateStyleAndLayoutTreeForElement` 等函数会被调用。
* **HTML 结构变化:** 用户操作触发 JavaScript 代码动态添加或删除 DOM 元素。这会导致布局失效，`Document::UpdateStyleAndLayout` 会被调用。
* **窗口大小调整:** 用户调整浏览器窗口大小，触发 `resize` 事件，导致 `Document::UpdateStyleAndLayout` 被调用，以重新计算布局和处理媒体查询。
* **字体加载完成:** 当网页使用的自定义字体加载完成后，`Document::InvalidateStyleAndLayoutForFontUpdates` 会被调用，以确保使用新字体进行渲染。
* **Shadow DOM 的操作:**  当 JavaScript 操作 Shadow DOM 中的元素时，`Document::UpdateUseShadowTreesIfNeeded` 会被调用来更新 Shadow DOM 的渲染。

**总结 (针对第四部分):**

这部分 `document.cc` 代码专注于**文档样式和布局的更新管理**。它负责决定何时、如何以及为什么需要重新计算样式和更新布局树，是 Blink 渲染引擎中至关重要的组成部分，直接关系到网页的正确呈现和性能表现。它与 JavaScript、HTML 和 CSS 紧密相连，响应用户操作、脚本操作和浏览器事件，确保网页内容能够以最新的样式和布局展示给用户。

Prompt: 
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共11部分，请归纳一下它的功能

"""

    }
    // If we insert <object> elements into display:none subtrees, we might not
    // need a layout tree update, but need to make sure they are not blocking
    // the load event.
    UnblockLoadEventAfterLayoutTreeUpdate();
  };

  bool needs_slot_assignment = IsSlotAssignmentDirty();
  bool needs_layout_tree_update = false;

  if (!needs_slot_assignment) {
    needs_layout_tree_update = NeedsLayoutTreeUpdateForThisDocument();
    if (!needs_layout_tree_update) {
      // Early out for no-op calls before the UMA/UKM measurement is set up to
      // avoid a large number of close-to-zero samples.
      advance_to_style_clean();
      return;
    }
  }

  SCOPED_UMA_AND_UKM_TIMER(View()->GetUkmAggregator(),
                           LocalFrameUkmAggregator::kStyle);
  FontPerformance::StyleScope font_performance_scope;
  ENTER_EMBEDDER_STATE(GetAgent().isolate(), GetFrame(), BlinkState::STYLE);

  if (needs_slot_assignment) {
    // RecalcSlotAssignments should be done before checking
    // NeedsLayoutTreeUpdateForThisDocument().
    GetSlotAssignmentEngine().RecalcSlotAssignments();
    DCHECK(!needs_layout_tree_update) << "Should be postponed above";
    needs_layout_tree_update = NeedsLayoutTreeUpdateForThisDocument();
  }

  if (!needs_layout_tree_update) {
    advance_to_style_clean();
    return;
  }

  // We can call FlatTreeTraversal::AssertFlatTreeNodeDataUpdated just after
  // calling RecalcSlotAssignments(), however, it would be better to call it at
  // least after InStyleRecalc() check below in order to avoid superfluous
  // check, which would be the cause of web tests timeout when dcheck is on.

  SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(*this);

  if (InStyleRecalc()) {
    NOTREACHED() << "We should not re-enter style recalc for the same document";
  }

#if DCHECK_IS_ON()
  int assigned_nodes_in_slot_count = 0;
  int nodes_which_have_assigned_slot_count = 0;
  FlatTreeTraversal::AssertFlatTreeNodeDataUpdated(
      *this, assigned_nodes_in_slot_count,
      nodes_which_have_assigned_slot_count);
  DCHECK_EQ(assigned_nodes_in_slot_count, nodes_which_have_assigned_slot_count);
#endif

  // Entering here from inside layout, paint etc. would be catastrophic since
  // recalcStyle can tear down the layout tree or (unfortunately) run
  // script. Kill the whole layoutObject if someone managed to get into here in
  // states not allowing tree mutations.
  CHECK(Lifecycle().StateAllowsTreeMutations());

  // No SVG resources should be scheduled for invalidation outside of
  // style-recalc and layout tree detach (Node::DetachLayoutTree).
  DCHECK(svg_resources_needing_invalidation_.empty());

  TRACE_EVENT_BEGIN1("blink,devtools.timeline", "UpdateLayoutTree", "beginData",
                     [&](perfetto::TracedValue context) {
                       inspector_recalculate_styles_event::Data(
                           std::move(context), GetFrame());
                     });

  StyleEngine& style_engine = GetStyleEngine();
  unsigned start_element_count = style_engine.StyleForElementCount();

  probe::RecalculateStyle recalculate_style_scope(this);

  document_animations_->UpdateAnimationTimingIfNeeded();
  EvaluateMediaQueryListIfNeeded();
  UpdateUseShadowTreesIfNeeded();

  style_engine.UpdateActiveStyle();
  style_engine.UpdateCounterStyles();
  style_engine.InvalidatePositionTryStyles();
  style_engine.InvalidateViewportUnitStylesIfNeeded();
  style_engine.InvalidateEnvDependentStylesIfNeeded();
  InvalidateStyleAndLayoutForFontUpdates();
  UpdateStyleInvalidationIfNeeded();
  UpdateStyle();
  GetStyleResolver().ClearResizedForViewportUnits();
  InvalidatePendingSVGResources();

  rendering_had_begun_for_last_style_update_ = RenderingHasBegun();

  GetLayoutView()->ClearHitTestCache();

  DCHECK(!document_animations_->NeedsAnimationTimingUpdate());

  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_element_count;

  // Make sure that document.fonts.ready fires, if appropriate.
  FontFaceSetDocument::DidLayout(*this);

  UnblockLoadEventAfterLayoutTreeUpdate();

  if (auto* document_rules = DocumentSpeculationRules::FromIfExists(*this)) {
    document_rules->DocumentStyleUpdated();
  }

  TRACE_EVENT_END1("blink,devtools.timeline", "UpdateLayoutTree",
                   "elementCount", element_count);

  ElementRuleCollector::DumpAndClearRulesPerfMap();

#if DCHECK_IS_ON()
  AssertLayoutTreeUpdated(*this, true /* allow_dirty_container_subtrees */);
#endif
}

void Document::InvalidateStyleAndLayoutForFontUpdates() {
  DCHECK(IsActive());
  DCHECK(IsMainThread());
  GetStyleEngine().InvalidateStyleAndLayoutForFontUpdates();
}

void Document::UpdateStyle() {
  DCHECK(!View()->ShouldThrottleRendering());
  TRACE_EVENT_BEGIN0("blink,blink_style", "Document::updateStyle");
  RUNTIME_CALL_TIMER_SCOPE(GetAgent().isolate(),
                           RuntimeCallStats::CounterId::kUpdateStyle);

  StyleEngine& style_engine = GetStyleEngine();
  unsigned initial_element_count = style_engine.StyleForElementCount();

  lifecycle_.AdvanceTo(DocumentLifecycle::kInStyleRecalc);

  // SetNeedsStyleRecalc should only happen on Element and Text nodes.
  DCHECK(!NeedsStyleRecalc());

  bool should_record_stats;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("blink,blink_style", &should_record_stats);

  style_engine.SetStatsEnabled(should_record_stats);
  style_engine.UpdateStyleAndLayoutTree();

  LayoutView* layout_view = GetLayoutView();
  layout_view->UpdateCountersAfterStyleChange();
  layout_view->RecalcScrollableOverflow();

#if DCHECK_IS_ON()
  AssertNodeClean(*this);
#endif
  DCHECK(InStyleRecalc());
  lifecycle_.AdvanceTo(DocumentLifecycle::kStyleClean);
  if (should_record_stats) {
    TRACE_EVENT_END2(
        "blink,blink_style", "Document::updateStyle", "resolverAccessCount",
        style_engine.StyleForElementCount() - initial_element_count, "counters",
        GetStyleEngine().Stats()->ToTracedValue());
  } else {
    TRACE_EVENT_END1(
        "blink,blink_style", "Document::updateStyle", "resolverAccessCount",
        style_engine.StyleForElementCount() - initial_element_count);
  }
}

bool Document::NeedsLayoutTreeUpdateForNode(const Node& node) const {
  // TODO(rakina): Switch some callers that may need to call
  // NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked instead of this.
  if (DisplayLockUtilities::LockedAncestorPreventingStyle(node)) {
    // |node| is in a locked-subtree, so we don't need to update it.
    return false;
  }
  return NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(node);
}

bool Document::NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(
    const Node& node) const {
  if (!node.isConnected())
    return false;
  if (node.IsShadowRoot())
    return false;
  const StyleAndLayoutTreeUpdate update = CalculateStyleAndLayoutTreeUpdate();
  if (update == StyleAndLayoutTreeUpdate::kFull)
    return true;
  bool analyze = update == StyleAndLayoutTreeUpdate::kAnalyzed;

  // If DisplayLockUtilities::IsUnlockedQuickCheck returns 'false', then
  // we may or may not be unlocked: we have to traverse the ancestor chain
  // to know for sure.
  if (!analyze)
    analyze = !DisplayLockUtilities::IsUnlockedQuickCheck(node);

  StyleEngine& style_engine = GetStyleEngine();
  bool maybe_affected_by_layout = false;
  if (const auto* element = DynamicTo<Element>(node)) {
    maybe_affected_by_layout =
        style_engine.StyleMaybeAffectedByLayout(*element);
  }
  // Even if we don't need layout *now*, any dirty style may invalidate layout.
  bool maybe_needs_layout =
      (update != StyleAndLayoutTreeUpdate::kNone) || View()->NeedsLayout();
  bool needs_update_inside_interleaving_root =
      maybe_affected_by_layout && maybe_needs_layout;

  if (!analyze)
    analyze = needs_update_inside_interleaving_root;

  if (!analyze) {
    DCHECK_EQ(StyleAndLayoutTreeUpdate::kNone, update);
    return false;
  }

  switch (style_engine.AnalyzeAncestors(node)) {
    case StyleEngine::AncestorAnalysis::kNone:
      return false;
    case StyleEngine::AncestorAnalysis::kInterleavingRoot:
      return needs_update_inside_interleaving_root;
    case StyleEngine::AncestorAnalysis::kStyleRoot:
      return true;
  }
}

void Document::UpdateStyleAndLayoutTreeForElement(const Element* element,
                                                  DocumentUpdateReason) {
  DCHECK(element);
  if (!element->InActiveDocument()) {
    // If |node| is not in the active document, we can't update its style or
    // layout tree.
    DCHECK_EQ(element->ownerDocument(), this);
    return;
  }
  DCHECK(!InStyleRecalc())
      << "UpdateStyleAndLayoutTreeForElement called from within style recalc";
  if (!NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(*element)) {
    return;
  }

  DisplayLockUtilities::ScopedForcedUpdate scoped_update_forced(
      element, DisplayLockContext::ForcedPhase::kStyleAndLayoutTree);
  ElementLayoutUpgrade upgrade(*element);
  UpdateStyleAndLayoutTree(upgrade);
}

void Document::UpdateStyleAndLayoutTreeForSubtree(const Element* element,
                                                  DocumentUpdateReason) {
  DCHECK(element);
  if (!element->InActiveDocument()) {
    DCHECK_EQ(element->ownerDocument(), this);
    return;
  }
  DCHECK(!InStyleRecalc())
      << "UpdateStyleAndLayoutTreeForSubtree called from within style recalc";

  if (NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(*element) ||
      element->ChildNeedsStyleRecalc() ||
      element->ChildNeedsStyleInvalidation()) {
    DisplayLockUtilities::ScopedForcedUpdate scoped_update_forced(
        element, DisplayLockContext::ForcedPhase::kStyleAndLayoutTree);
    UpdateStyleAndLayoutTree();
  }
}

void Document::UpdateStyleAndLayoutForRange(const Range* range,
                                            DocumentUpdateReason reason) {
  DisplayLockUtilities::ScopedForcedUpdate scoped_update_forced(
      range, DisplayLockContext::ForcedPhase::kLayout);
  UpdateStyleAndLayout(reason);
}

void Document::UpdateStyleAndLayoutForNode(const Node* node,
                                           DocumentUpdateReason reason) {
  DCHECK(node);
  if (!node->InActiveDocument())
    return;

  DisplayLockUtilities::ScopedForcedUpdate scoped_update_forced(
      node, DisplayLockContext::ForcedPhase::kLayout);

  // For all nodes we must have up-to-date style and have performed layout to do
  // any location-based calculation.
  UpdateStyleAndLayout(reason);
}

DocumentPartRoot& Document::getPartRoot() {
  return EnsureDocumentPartRoot();
}

DocumentPartRoot& Document::EnsureDocumentPartRoot() {
  CHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  if (!document_part_root_) {
    document_part_root_ = MakeGarbageCollected<DocumentPartRoot>(*this);
  }
  return *document_part_root_;
}

void Document::ApplyScrollRestorationLogic() {
  DCHECK(View());
  // This function is not re-entrant. However, the places that invoke this are
  // re-entrant. Specifically, UpdateStyleAndLayout() calls this, which in turn
  // can do a find-in-page for the scroll-to-text feature, which can cause
  // UpdateStyleAndLayout to happen with content-visibility, which gets back
  // here and recurses indefinitely. As a result, we ensure to early out from
  // this function if are currently in process of restoring scroll.
  if (applying_scroll_restoration_logic_)
    return;
  base::AutoReset<bool> applying_scroll_restoration_logic_scope(
      &applying_scroll_restoration_logic_, true);

  if (AnnotationAgentContainerImpl* container =
          AnnotationAgentContainerImpl::FromIfExists(*this)) {
    // Check for cleanliness since that'll also account for parsing state.
    if (container->IsLifecycleCleanForAttachment()) {
      container->PerformInitialAttachments();
    }
  }

  // If we're restoring a scroll position from history, that takes precedence
  // over scrolling to the anchor in the URL.
  View()->InvokeFragmentAnchor();
  LocalFrame* frame = GetFrame();
  auto& frame_loader = frame->Loader();
  auto* document_loader = frame_loader.GetDocumentLoader();
  if (!document_loader)
    return;
  if (frame->IsLoading() &&
      !FrameLoader::NeedsHistoryItemRestore(document_loader->LoadType())) {
    return;
  }

  HistoryItem* history_item = document_loader->GetHistoryItem();

  if (!history_item || !history_item->GetViewState())
    return;

  if (!View()->GetScrollableArea()->HasPendingHistoryRestoreScrollOffset())
    return;

  bool should_restore_scroll = history_item->ScrollRestorationType() !=
                               mojom::blink::ScrollRestorationType::kManual;
  auto& scroll_offset = history_item->GetViewState()->scroll_offset_;

  // This tries to balance:
  // 1. restoring as soon as possible.
  // 2. not overriding user scroll (TODO(majidvp): also respect user scale).
  // 3. detecting clamping to avoid repeatedly popping the scroll position
  // down
  //    as the page height increases.
  // 4. ignoring clamp detection if scroll state is not being restored, if
  // load
  //    is complete, or if the navigation is same-document (as the new page
  //    may be smaller than the previous page).
  bool can_restore_without_clamping =
      View()->LayoutViewport()->ClampScrollOffset(scroll_offset) ==
      scroll_offset;

  bool can_restore_without_annoying_user =
      !document_loader->GetInitialScrollState().was_scrolled_by_user &&
      (can_restore_without_clamping || !GetFrame()->IsLoading() ||
       !should_restore_scroll);
  if (!can_restore_without_annoying_user)
    return;

  // Apply scroll restoration to the LayoutView's scroller. Note that we do
  // *not* apply it to the RootFrameViewport's LayoutViewport, because that
  // may be for child frame's implicit root scroller, which is not the right
  // one to apply to because scroll restoration does not affect implicit root
  // scrollers.
  auto* layout_scroller = View()->LayoutViewport();
  layout_scroller->ApplyPendingHistoryRestoreScrollOffset();

  // Also apply restoration to the visual viewport of the root frame, if needed.
  auto* root_frame_scroller = View()->GetScrollableArea();
  if (root_frame_scroller != layout_scroller)
    root_frame_scroller->ApplyPendingHistoryRestoreScrollOffset();

  document_loader->GetInitialScrollState().did_restore_from_history = true;
}

void Document::MarkHasFindInPageRequest() {
  // Only record the event once in a document.
  if (had_find_in_page_request_)
    return;

  auto* recorder = UkmRecorder();
  DCHECK(recorder);
  DCHECK(UkmSourceID() != ukm::kInvalidSourceId);
  ukm::builders::Blink_FindInPage(UkmSourceID())
      .SetDidSearch(true)
      .Record(recorder);
  had_find_in_page_request_ = true;
}

void Document::MarkHasFindInPageContentVisibilityActiveMatch() {
  // Only record the event once in a document.
  if (had_find_in_page_render_subtree_active_match_)
    return;

  auto* recorder = UkmRecorder();
  DCHECK(recorder);
  DCHECK(UkmSourceID() != ukm::kInvalidSourceId);
  // TODO(vmpstr): Rename UKM values if possible.
  ukm::builders::Blink_FindInPage(UkmSourceID())
      .SetDidHaveRenderSubtreeMatch(true)
      .Record(recorder);
  had_find_in_page_render_subtree_active_match_ = true;
}

void Document::MarkHasFindInPageBeforematchExpandedHiddenMatchable() {
  // Only record the event once in a document.
  if (had_find_in_page_beforematch_expanded_hidden_matchable_)
    return;

  auto* recorder = UkmRecorder();
  DCHECK(recorder);
  DCHECK(UkmSourceID() != ukm::kInvalidSourceId);
  ukm::builders::Blink_FindInPage(UkmSourceID())
      .SetBeforematchExpandedHiddenMatchable(true)
      .Record(recorder);
  had_find_in_page_beforematch_expanded_hidden_matchable_ = true;
}

void Document::UpdateStyleAndLayout(DocumentUpdateReason reason) {
  DCHECK(IsMainThread());
  // TODO(paint-dev): LifecyclePostponed() and
  // LocalFrameView::IsUpdatingLifecycle() overlap in functionality, but with
  // slight differences. We should combine them.
  if (Lifecycle().LifecyclePostponed()) {
    return;
  }
  TRACE_EVENT("blink", "Document::UpdateStyleAndLayout");
  LocalFrameView* frame_view = View();

  if (reason != DocumentUpdateReason::kBeginMainFrame && frame_view)
    frame_view->WillStartForcedLayout(reason);

  HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
  ScriptForbiddenScope forbid_script;

  DCHECK(!frame_view || !frame_view->IsInPerformLayout())
      << "View layout should not be re-entrant";

  if (HTMLFrameOwnerElement* owner = LocalOwner()) {
    owner->GetDocument().UpdateStyleAndLayout(reason);
  }

  if (!IsActive()) {
    if (reason != DocumentUpdateReason::kBeginMainFrame && frame_view)
      frame_view->DidFinishForcedLayout();
    return;
  }

  if (frame_view)
    frame_view->UpdateStyleAndLayout();

  if (Lifecycle().GetState() < DocumentLifecycle::kLayoutClean)
    Lifecycle().AdvanceTo(DocumentLifecycle::kLayoutClean);

  if (frame_view)
    ApplyScrollRestorationLogic();

  if (LocalFrameView* frame_view_anchored = View())
    frame_view_anchored->PerformScrollAnchoringAdjustments();

  if (frame_view) {
    frame_view->ExecutePendingSnapUpdates();
  }

  if (reason != DocumentUpdateReason::kBeginMainFrame && frame_view)
    frame_view->DidFinishForcedLayout();

  if (should_update_selection_after_layout_)
    UpdateSelectionAfterLayout();
}

void Document::LayoutUpdated() {
  DCHECK(GetFrame());
  DCHECK(View());

  // Plugins can run script inside layout which can detach the page.
  // TODO(dcheng): Does it make sense to do any of this work if detached?
  if (auto* frame = GetFrame()) {
    if (frame->IsMainFrame()) {
      frame->GetPage()->GetChromeClient().MainFrameLayoutUpdated();
    }
  }

  Markers().InvalidateRectsForAllTextMatchMarkers();
}

void Document::AttachCompositorTimeline(cc::AnimationTimeline* timeline) const {
  if (!Platform::Current()->IsThreadedAnimationEnabled() ||
      !GetSettings()->GetAcceleratedCompositingEnabled())
    return;

  if (cc::AnimationHost* host =
          GetPage()->GetChromeClient().GetCompositorAnimationHost(
              *GetFrame())) {
    if (timeline->animation_host()) {
      DCHECK_EQ(timeline->animation_host(), host);
      return;
    }
    host->AddAnimationTimeline(timeline);
  }
}

void Document::ClearFocusedElementIfNeeded() {
  if (clear_focused_element_timer_.IsActive() || !focused_element_ ||
      focused_element_->IsFocusable(
          Element::UpdateBehavior::kNoneForFocusManagement)) {
    return;
  }
  clear_focused_element_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void Document::ClearFocusedElementTimerFired(TimerBase*) {
  UpdateStyleAndLayoutTree();

  if (focused_element_ && !focused_element_->IsFocusable())
    focused_element_->blur();
}

void Document::EnsurePaintLocationDataValidForNode(
    const Node* node,
    DocumentUpdateReason reason) {
  UpdateStyleAndLayoutForNode(node, reason);
}

WebPrintPageDescription Document::GetPageDescription(uint32_t page_index) {
  View()->UpdateLifecycleToLayoutClean(DocumentUpdateReason::kUnknown);
  return GetPageDescriptionFromLayout(*this, page_index);
}

void Document::SetIsXrOverlay(bool val, Element* overlay_element) {
  if (!documentElement())
    return;

  if (val == is_xr_overlay_)
    return;

  is_xr_overlay_ = val;

  // On navigation, the layout view may be invalid, skip style changes.
  if (!GetLayoutView())
    return;

  if (overlay_element) {
    // Now that the custom style sheet is loaded, update the pseudostyle for
    // the overlay element.
    overlay_element->PseudoStateChanged(CSSSelector::kPseudoXrOverlay);
  }

  // The DOM overlay may change the effective root element. Need to update
  // compositing inputs to avoid a mismatch in CompositingRequirementsUpdater.
  GetLayoutView()->Layer()->SetNeedsCompositingInputsUpdate();
}

void Document::ScheduleUseShadowTreeUpdate(SVGUseElement& element) {
  use_elements_needing_update_.insert(&element);
  ScheduleLayoutTreeUpdateIfNeeded();
}

void Document::UnscheduleUseShadowTreeUpdate(SVGUseElement& element) {
  use_elements_needing_update_.erase(&element);
}

void Document::UpdateUseShadowTreesIfNeeded() {
  ScriptForbiddenScope forbid_script;

  // Breadth-first search since nested use elements add to the queue.
  while (!use_elements_needing_update_.empty()) {
    HeapHashSet<Member<SVGUseElement>> elements;
    use_elements_needing_update_.swap(elements);
    for (SVGUseElement* element : elements)
      element->BuildPendingResource();
  }
}

void Document::ScheduleSVGResourceInvalidation(LocalSVGResource& resource) {
  DCHECK(InStyleRecalc() || GetStyleEngine().InDetachLayoutTree());
  svg_resources_needing_invalidation_.insert(&resource);
}

void Document::InvalidatePendingSVGResources() {
  HeapHashSet<Member<LocalSVGResource>> pending_resources;
  svg_resources_needing_invalidation_.swap(pending_resources);
  for (LocalSVGResource* resource : pending_resources) {
    resource->NotifyContentChanged();
  }
  DCHECK(svg_resources_needing_invalidation_.empty());
}

StyleResolver& Document::GetStyleResolver() const {
  return style_engine_->GetStyleResolver();
}

void Document::Initialize() {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::Initialize", TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK_EQ(lifecycle_.GetState(), DocumentLifecycle::kInactive);
  DCHECK(!ax_object_cache_ || this != &AXObjectCacheOwner());

  UpdateForcedColors();
  const ComputedStyle* style = GetStyleResolver().StyleForViewport();
  layout_view_ = MakeGarbageCollected<LayoutView>(this);
  SetLayoutObject(layout_view_);

  layout_view_->SetStyle(style);

  AttachContext context;
  AttachLayoutTree(context);

  // The TextAutosizer can't update layout view info while the Document is
  // detached, so update now in case anything changed.
  if (TextAutosizer* autosizer = GetTextAutosizer())
    autosizer->UpdatePageInfo();

  GetFrame()->DidAttachDocument();
  lifecycle_.AdvanceTo(DocumentLifecycle::kStyleClean);

  if (View())
    View()->DidAttachDocument();
}

void Document::Shutdown() {
  TRACE_EVENT_WITH_FLOW0("blink", "Document::shutdown", TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN);
  CHECK((!GetFrame() || GetFrame()->Tree().ChildCount() == 0) &&
        ConnectedSubframeCount() == 0);
  if (!IsActive())
    return;

  // An active Document must have an associated window.
  CHECK(dom_window_);

  // Frame navigation can cause a new Document to be attached. Don't allow that,
  // since that will cause a situation where LocalFrame still has a Document
  // attached after this finishes!  Normally, it shouldn't actually be possible
  // to trigger navigation here.  However, plugins (see below) can cause lots of
  // crazy things to happen, since plugin detach involves nested run loops.
  FrameNavigationDisabler navigation_disabler(*GetFrame());
  // Defer plugin dispose to avoid plugins trying to run script inside
  // ScriptForbiddenScope, which will crash the renderer after
  // https://crrev.com/200984
  // TODO(dcheng): This is a temporary workaround, Document::Shutdown() should
  // not be running script at all.
  HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
  // Don't allow script to run in the middle of DetachLayoutTree() because a
  // detaching Document is not in a consistent state.
  ScriptForbiddenScope forbid_script;

  lifecycle_.AdvanceTo(DocumentLifecycle::kStopping);

  // Do not add code before this without a documented reason. A postcondition of
  // Shutdown() is that |dom_window_| must not have an attached Document.
  // Allowing script execution when the Document is shutting down can make it
  // easy to accidentally violate this condition, and the ordering of the
  // scopers above is subtle due to legacy interactions with plugins.

  if (num_canvases_ > 0)
    UMA_HISTOGRAM_COUNTS_100("Blink.Canvas.NumCanvasesPerPage", num_canvases_);

  if (font_matching_metrics_) {
    font_matching_metrics_->PublishAllMetrics();
  }

  GetViewportData().Shutdown();

  View()->Dispose();
  DCHECK(!View()->IsAttached());

  // If the EmbeddedContentView of the document's frame owner doesn't match
  // view() then LocalFrameView::Dispose() didn't clear the owner's
  // EmbeddedContentView. If we don't clear it here, it may be clobbered later
  // in LocalFrame::CreateView(). See also https://crbug.com/673170 and the
  // comment in LocalFrameView::Dispose().
  HTMLFrameOwnerElement* owner_element = GetFrame()->DeprecatedLocalOwner();

  // In the case of a provisional frame, skip clearing the EmbeddedContentView.
  // A provisional frame is not fully attached to the DOM yet and clearing the
  // EmbeddedContentView here could clear a not-yet-swapped-out frame
  // (https://crbug.com/807772).
  if (owner_element && !GetFrame()->IsProvisional())
    owner_element->SetEmbeddedContentView(nullptr);

  markers_->PrepareForDestruction();

  if (TextFragmentHandler* handler = GetFrame()->GetTextFragmentHandler())
    handler->DidDetachDocumentOrFrame();

  GetPage()->DocumentDetached(this);

  probe::DocumentDetached(this);

  if (AnchorElementMetricsSender* sender =
          AnchorElementMetricsSender::GetForFrame(GetFrame())) {
    sender->DocumentDetached(*this);
  }

  if (SvgExtensions())
    AccessSVGExtensions().PauseAnimations();

  CancelPendingJavaScriptUrls();
  http_refresh_scheduler_->Cancel();

  GetDocumentAnimations().DetachCompositorTimelines();

  if (GetFrame()->IsLocalRoot())
    GetPage()->GetChromeClient().AttachRootLayer(nullptr, GetFrame());

  MutationObserver::CleanSlotChangeList(*this);

  hover_element_ = nullptr;
  active_element_ = nullptr;
  autofocus_candidates_.clear();

  if (focused_element_.Get()) {
    Element* old_focused_element = focused_element_;
    focused_element_ = nullptr;
    NotifyFocusedElementChanged(old_focused_element, nullptr,
                                mojom::blink::FocusType::kNone);
  }
  sequential_focus_navigation_starting_point_ = nullptr;
  focused_element_change_observers_.clear();

  if (this == &AXObjectCacheOwner()) {
    ax_contexts_.clear();
    ClearAXObjectCache();
  } else {
    DCHECK(!ax_object_cache_ || ExistingAXObjectCache())
        << "Had AXObjectCache for parent, but not for popup document.";
    if (AXObjectCache* cache = ExistingAXObjectCache()) {
      // This is a popup document. Clear all accessibility state related to it
      // by removing the AXObject for its root. The AXObjectCache is
      // retrieved from the main document, but it maintains both documents.
      cache->RemovePopup(this);
    }
  }

  DetachLayoutTree();
  layout_view_ = nullptr;
  DCHECK(!View()->IsAttached());

  GetStyleEngine().DidDetach();

  GetFrame()->DocumentDetached();
  GetFrame()->GetEventHandlerRegistry().DocumentDetached(*this);

  // Signal destruction to mutation observers.
  synchronous_mutation_observer_set_.ForEachObserver(
      [](SynchronousMutationObserver* observer) {
        observer->ContextDestroyed();
        observer->ObserverSetWillBeCleared();
      });
  synchronous_mutation_observer_set_.Clear();

  cookie_jar_ = nullptr;  // Not accessible after navigated away.
  fetcher_->ClearContext();

  if (media_query_matcher_)
    media_query_matcher_->DocumentDetached();

  lifecycle_.AdvanceTo(DocumentLifecycle::kStopped);
  DCHECK(!View()->IsAttached());

  // Don't create a |ukm_recorder_| and |ukm_source_id_| unless necessary.
  if (IdentifiabilityStudySettings::Get()->IsActive()) {
    IdentifiabilitySampleCollector::Get()->FlushSource(UkmRecorder(),
                                                       UkmSourceID());
  }

  mime_handler_view_before_unload_event_listener_ = nullptr;

  resource_coordinator_.reset();

  // Because the document view transition supplement can get destroyed before
  // the execution context notification, we should clean up the transition
  // object here.
  if (auto* transition = ViewTransitionUtils::GetTransition(*this)) {
    transition->SkipTransition();
  }

  // This is required, as our LocalFrame might delete itself as soon as it
  // detaches us. However, this violates Node::detachLayoutTree() semantics, as
  // it's never possible to re-attach. Eventually Document::detachLayoutTree()
  // should be renamed, or this setting of the frame to 0 could be made
  // explicit in each of the callers of Document::detachLayoutTree().
  dom_window_ = nullptr;
  execution_context_ = nullptr;
}

void Document::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  ContainerNode::RemovedEventListener(event_type, registered_listener);

  // We need to track the existence of the visibilitychange event listeners to
  // enable/disable sudden terminations.
  if (event_type == event_type_names::kVisibilitychange) {
    if (auto* frame = GetFrame())
      frame->RemovedSuddenTerminationDisablerListener(*this, event_type);
  }
}

void Document::RemoveAllEventListeners() {
  int previous_visibility_change_handlers_count =
      NumberOfEventListeners(event_type_names::kVisibilitychange);

  ContainerNode::RemoveAllEventListeners();

  if (LocalDOMWindow* dom_window = domWindow())
    dom_window->RemoveAllEventListeners();

  // Update sudden termination disabler state if we previously have listeners
  // for visibilitychange.
  if (previous_visibility_change_handlers_count) {
    if (auto* frame = GetFrame()) {
      frame->RemovedSuddenTerminationDisablerListener(
          *this, event_type_names::kVisibilitychange);
    }
  }
}

Document& Document::AXObjectCacheOwner() const {
  // Every document has its own axObjectCache if accessibility is enabled,
  // except for page popups, which share the axObjectCache of their owner.
  Document* doc = const_cast<Document*>(this);
  auto* frame = doc->GetFrame();
  if (frame && frame->HasPagePopupOwner()) {
    DCHECK(!doc->ax_object_cache_);
    return frame->PagePopupOwner()->GetDocument().AXObjectCacheOwner();
  }
  return *doc;
}

static ui::AXMode ComputeAXModeFromAXContexts(Vector<AXContext*> ax_contexts) {
  ui::AXMode ax_mode = 0;
  for (AXContext* context : ax_contexts)
    ax_mode |= context->GetAXMode();

  if (!ax_contexts.empty()) {
    DCHECK(!ax_mode.is_mode_off())
        << "The computed AX mode was empty but there were > 0 AXContext "
           "objects. A caller should have called RemoveAXContext().";
  }

  return ax_mode;
}

namespace {

// Simple count of AXObjectCache objects that are reachable from Documents. The
// count assumes that multiple Documents in a single process can have such
// caches and that the caches will only ever be created from the main rendering
// thread.
size_t g_ax_object_cache_count = 0;

}  // namespace

void Document::AddAXContext(AXContext* context) {
  DCHECK(IsMainThread());
  // The only case when |&cache_owner| is not |this| is when this is a
  // popup. We want popups to share the AXObjectCache of their parent
  // document. However, there's no valid reason to explicitly create an
  // AXContext for a popup document, so check to make sure we're not
  // trying to do that here.
  DCHECK_EQ(&AXObjectCacheOwner(), this);

  // If the document has already been detached, do not make a new AXObjectCache.
  if (!GetLayoutView())
    return;

  ax_contexts_.push_back(context);
  if (ax_contexts_.size() != 1) {
    DCHECK(ax_object_cache_);
    ax_object_cache_->SetAXMode(ComputeAXModeFromAXContexts(ax_contexts_));
    return;
  }

  if (!ax_object_cache_) {
    ax_object_cache_ =
        AXObjectCache::Create(*this, ComputeAXModeFromAXContexts(ax_contexts_));
    // Invalidate style on the entire document, because accessibility
    // needs to compute style on all elements, even those in
    // content-visibility:auto subtrees.
    if (documentElement()) {
      documentElement()->SetNeedsStyleRecalc(
          kSubtreeStyleChange, StyleChangeReasonForTracing::Create(
                                   style_change_reason::kAccessibility));
    }
    g_ax_object_cache_count++;
  }
}

void Document::AXContextModeChanged() {
  DCHECK_GT(ax_contexts_.size(), 0u);
  DCHECK(ax_object_cache_);
  ax_object_cache_->SetAXMode(ComputeAXModeFromAXContexts(ax_contexts_));
}

void Document::RemoveAXContext(AXContext* context) {
  auto iter = base::ranges::find(ax_contexts_, context);
  if (iter != ax_contexts_.end())
    ax_contexts_.erase(iter);
  if (ax_contexts_.size() == 0) {
    ClearAXObjectCache();
  } else {
    DCHECK(ax_object_cache_);
    ax_object_cache_->SetAXMode(ComputeAXModeFromAXContexts(ax_contexts_));
  }
}

void Document::ClearAXObjectCache() {
  DCHECK(IsMainThread());
  DCHECK_EQ(&A
"""


```