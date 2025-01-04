Response:
The user wants to understand the functionality of the `element.cc` file in the Chromium Blink engine. Specifically, they're interested in:

1. **Core Functionality:** What does this file do?
2. **Relationships to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Reasoning:**  If there's logical flow, what are the inputs and outputs?
4. **Common Errors:** What mistakes do developers or users often make related to this?
5. **User Actions and Debugging:** How does a user's interaction eventually lead to this code being executed, useful for debugging?
6. **Summary:** A concise overview of the file's purpose based on the provided code snippet.

The snippet primarily deals with:

* **Detaching and Reattaching Layout Tree:** Functions like `DetachLayoutTree` and `ReattachLayoutTreeChildren`.
* **Style Recalculation:** Functions like `StyleForLayoutObject`, `OriginalStyleForLayoutObject`, `RecalcStyle`, and `RecalcOwnStyle`.
* **Handling Container Queries:** Logic involving `ContainerQueryData` and skipping style recalculation.
* **Pseudo-elements:** Interactions with pseudo-elements like `::before`, `::after`, `::first-letter`, etc.
* **Display Locking:** The `DisplayLockContext`.
* **Animations:**  Checks for `ElementAnimations`.
* **Accessibility:**  Notification to the accessibility tree (`NotifyAXOfAttachedSubtree`).

Based on these observations, I can structure the answer by addressing each of the user's points, using the code snippet as the primary source of information.
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共13部分，请归纳一下它的功能
```

基于提供的代码片段，该文件 `element.cc` 的主要功能集中在以下几个方面，都与渲染引擎处理元素及其样式息息相关：

**核心功能:**

1. **布局树的脱离与重新连接 (Detach and Reattach Layout Tree):**
   - `DetachLayoutTree()`:  负责将元素从渲染布局树中移除。这包括处理子元素、伪元素、动画、滚动位置等。它会根据情况选择性地脱离子元素的布局树。
   - `ReattachLayoutTreeChildren()`:  负责将元素的子元素重新连接到布局树。这发生在元素本身已经连接到布局树之后。它会考虑阴影根、伪元素，并维护正确的兄弟节点关系。

2. **样式计算 (Style Calculation):**
   - `StyleForLayoutObject()`:  为元素获取用于布局的计算样式。这个过程会考虑动画、自定义样式回调、`@starting-style` 规则以及 `content-visibility` 属性。
   - `OriginalStyleForLayoutObject()`:  调用样式解析器来计算元素的原始样式。
   - `RecalcStyle()`:  触发元素的样式重计算。这是一个核心函数，会根据样式变化类型和上下文，递归地更新元素自身及其子元素的样式。它会处理容器查询、伪元素、阴影根等复杂情况。
   - `RecalcOwnStyle()`:  计算元素自身的样式，并确定样式变化对子元素的影响程度。它可以利用父元素的样式进行优化（例如，只传播独立的继承属性）。
   - `PropagateInheritedProperties()`:  优化后的样式计算，只传播独立的继承属性，避免完全重新计算。

3. **容器查询 (Container Queries):**
   - `SkipStyleRecalcForContainer()`:  判断是否可以跳过容器元素子树的样式重计算，以优化性能。这涉及到检查子元素是否需要重排、是否是表单控件、是否在顶层等条件。
   -  代码中多次涉及到 `ContainerQueryData`，用于存储和管理容器查询相关的信息。

4. **伪元素处理 (Pseudo-element Handling):**
   - `DetachPrecedingPseudoElements()`, `DetachSucceedingPseudoElements()`, `AttachPrecedingPseudoElements()`, `AttachSucceedingPseudoElements()`:  处理 `::before` 和 `::after` 等伪元素的脱离和连接。
   - `UpdateBackdropPseudoElement()`, `UpdatePseudoElement()` 等函数负责更新各种伪元素的样式。

5. **显示锁 (Display Lock):**
   - 代码中出现 `DisplayLockContext`，用于管理 `content-visibility` 属性，它可以在某些情况下阻止子元素的样式更新。

6. **动画 (Animations):**
   - 代码中检查 `ElementAnimations`，并在样式计算过程中处理动画相关的更新。

7. **无障碍 (Accessibility):**
   - `NotifyAXOfAttachedSubtree()`:  通知无障碍功能树，元素子树已连接。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  `element.cc` 负责处理 HTML 元素在渲染过程中的行为。例如，当 JavaScript 操作 DOM 添加或删除 HTML 元素时，会触发布局树的脱离和重新连接。
    * **例子:** JavaScript 代码 `document.getElementById('container').innerHTML = '<p>New content</p>';`  会导致 `'container'` 元素的部分子树被脱离，然后新的 `<p>` 元素及其内容被创建并连接到布局树。`element.cc` 中的 `DetachLayoutTree` 和相关的连接函数会被调用。

* **CSS:**  `element.cc` 的核心功能是处理 CSS 样式。当 CSS 规则发生变化（例如，通过 JavaScript 修改 `element.style` 或外部 CSS 文件更新）时，会触发样式重计算。
    * **例子:**
        * CSS 规则修改:  用户修改 CSS 文件，或者 JavaScript 代码 `element.style.color = 'red';`  会导致 `RecalcStyle` 被调用，重新计算元素的 `color` 属性，并可能影响其子元素。
        * 容器查询: CSS 中定义了容器查询规则，`element.cc` 中的相关逻辑会判断当前元素是否是容器，并根据容器的尺寸或其他状态来决定是否跳过子元素的样式重计算。

* **JavaScript:** JavaScript 可以通过 DOM API 触发与 `element.cc` 相关的操作。
    * **例子:**
        * `element.remove()`:  JavaScript 调用 `remove()` 方法会触发 `DetachLayoutTree`，将元素从布局树中移除。
        * `element.classList.add('active')`:  修改元素的 class 列表可能会导致 CSS 规则匹配发生变化，从而触发 `RecalcStyle`。
        * `getComputedStyle(element)`: 虽然这个 API 主要在 JavaScript 中使用，但其背后依赖于 `element.cc` 中计算好的样式信息。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一个 `div` 元素，其 CSS `display` 属性从 `block` 修改为 `none`。
* **输出:**
    * `RecalcStyle` 会被调用，检测到 `display` 属性的变化。
    * `DetachLayoutTree` 会被调用，将该 `div` 元素及其所有子元素从布局树中移除。
    * 如果该 `div` 元素有动画，相关的动画也会被停止或取消。
    * 如果该 `div` 元素有伪元素，它们的布局树也会被脱离。

* **假设输入:**  一个包含多个子元素的父元素，其 CSS `color` 属性被修改。
* **输出:**
    * `RecalcStyle` 会被调用。
    * `RecalcOwnStyle` 会计算父元素的新的 `color` 样式。
    * 由于 `color` 是继承属性，`RecalcStyle` 会递归地调用子元素的样式重计算。
    * 如果启用了独立继承属性优化，并且只是 `color` 属性发生变化，可能会调用 `PropagateInheritedProperties` 来更高效地更新子元素的样式。

**用户或编程常见的使用错误：**

1. **频繁操作 DOM 导致过度重排 (Layout Thrashing):**  JavaScript 代码中连续多次修改 DOM 结构或样式，例如在一个循环中添加大量元素或修改元素的几何属性，会导致浏览器频繁地进行布局计算，严重影响性能。`element.cc` 中的脱离和连接布局树的函数会被反复调用。
    * **例子:**
    ```javascript
    const container = document.getElementById('container');
    for (let i = 0; i < 1000; i++) {
      const newElement = document.createElement('div');
      newElement.textContent = `Item ${i}`;
      container.appendChild(newElement); // 每次 appendChild 都可能触发布局
    }
    ```

2. **强制同步布局 (Forced Synchronous Layout):**  在 JavaScript 中，先读取一个元素的布局信息（例如 `offsetWidth`, `offsetHeight`），然后立即修改会影响布局的样式，会导致浏览器被迫同步执行布局计算。
    * **例子:**
    ```javascript
    const element = document.getElementById('myElement');
    console.log(element.offsetWidth); // 读取布局信息
    element.style.width = '200px';      // 修改样式，触发布局
    ```

3. **不必要的样式重写:**  在 CSS 或 JavaScript 中，重复设置相同的样式值，或者设置了会被其他规则覆盖的样式，虽然功能上没有问题，但会增加样式计算的开销。

**用户操作到达这里的步骤 (调试线索):**

1. **用户交互触发 DOM 变化:** 用户点击按钮、输入文本、滚动页面等操作可能通过 JavaScript 代码修改 DOM 结构或属性。
2. **JavaScript 代码执行:** 相关的 JavaScript 代码 (例如事件监听器中的代码) 调用 DOM API (如 `appendChild`, `removeChild`, `setAttribute`, 修改 `style` 属性等)。
3. **Blink 接收 DOM 操作:** Blink 引擎接收到这些 DOM 操作的通知。
4. **触发样式失效 (Style Invalidation):**  DOM 的变化可能导致元素的样式需要重新计算。例如，添加或删除元素会影响父元素的子元素数量，修改元素的 class 会影响 CSS 规则的匹配。
5. **触发布局失效 (Layout Invalidation):** 样式的变化，尤其是影响元素几何属性的样式变化，会导致布局失效，需要重新计算元素的位置和大小。
6. **进入样式计算阶段:** Blink 的样式计算模块开始工作，`element.cc` 中的 `RecalcStyle` 等函数会被调用，根据失效的范围和类型进行样式重计算。
7. **进入布局阶段:** 如果布局也失效，Blink 的布局模块会根据计算好的样式，构建或更新渲染布局树，`element.cc` 中的 `DetachLayoutTree` 和 `ReattachLayoutTreeChildren` 等函数会被调用来管理布局树的结构。

**归纳功能 (基于提供的代码片段 - 第 5 部分):**

**这部分代码主要负责元素的布局树的脱离和重新连接，以及元素自身及其子元素的样式重计算。它处理了包括伪元素、容器查询、动画、显示锁等复杂的场景，确保渲染引擎能够正确地根据 HTML 结构和 CSS 样式构建和更新渲染树。** 核心关注点在于维护渲染树的正确性和高效性，并响应 DOM 变化和样式变化。

Prompt: 
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共13部分，请归纳一下它的功能

"""
mations->RestartAnimationOnCompositor();
    }

    data->RemoveAnchorPositionScrollData();
  }

  DetachPrecedingPseudoElements(performing_reattach);

  auto* context = GetDisplayLockContext();

  // TODO(futhark): We need to traverse into IsUserActionElement() subtrees,
  // even if they are already display:none because we do not clear the
  // hovered/active bits as part of style recalc, but wait until the next time
  // we do a hit test. That means we could be doing a forced layout tree update
  // making a hovered subtree display:none and immediately remove the subtree
  // leaving stale hovered/active state on ancestors. See relevant issues:
  // https://crbug.com/967548
  // https://crbug.com/939769
  if (ChildNeedsReattachLayoutTree() || GetComputedStyle() ||
      (!performing_reattach && IsUserActionElement())) {
    if (ShadowRoot* shadow_root = GetShadowRoot()) {
      shadow_root->DetachLayoutTree(performing_reattach);
      Node::DetachLayoutTree(performing_reattach);
    } else {
      ContainerNode::DetachLayoutTree(performing_reattach);
    }
  } else {
    Node::DetachLayoutTree(performing_reattach);
  }

  DetachSucceedingPseudoElements(performing_reattach);

  if (!performing_reattach) {
    UpdateCallbackSelectors(GetComputedStyle(), nullptr);
    NotifyIfMatchedDocumentRulesSelectorsChanged(GetComputedStyle(), nullptr);
    SetComputedStyle(nullptr);
  }

  if (!performing_reattach && IsUserActionElement()) {
    if (IsHovered()) {
      GetDocument().HoveredElementDetached(*this);
    }
    if (InActiveChain()) {
      GetDocument().ActiveChainNodeDetached(*this);
    }
    GetDocument().UserActionElements().DidDetach(*this);
  }

  if (context) {
    context->DetachLayoutTree();
  }
}

void Element::ReattachLayoutTreeChildren(base::PassKey<StyleEngine>) {
  DCHECK(NeedsReattachLayoutTree());
  DCHECK(ChildNeedsReattachLayoutTree());
  DCHECK(GetLayoutObject());

  constexpr bool performing_reattach = true;

  DetachPrecedingPseudoElements(performing_reattach);

  ShadowRoot* shadow_root = GetShadowRoot();

  if (shadow_root) {
    shadow_root->DetachLayoutTree(performing_reattach);
  } else {
    // Can not use ContainerNode::DetachLayoutTree() because that would also
    // call Node::DetachLayoutTree for this element.
    for (Node* child = firstChild(); child; child = child->nextSibling()) {
      child->DetachLayoutTree(performing_reattach);
    }
  }

  DetachSucceedingPseudoElements(performing_reattach);

  LayoutObject* layout_object = GetLayoutObject();
  AttachContext context;
  context.parent = layout_object;
  context.performing_reattach = performing_reattach;
  context.use_previous_in_flow = true;
  context.next_sibling_valid = true;

  if (!IsPseudoElement()) {
    DCHECK(layout_object);
    context.counters_context.EnterObject(*layout_object);
  }

  AttachPrecedingPseudoElements(context);

  if (shadow_root) {
    shadow_root->AttachLayoutTree(context);
  } else {
    // Can not use ContainerNode::DetachLayoutTree() because that would also
    // call Node::AttachLayoutTree for this element.
    for (Node* child = firstChild(); child; child = child->nextSibling()) {
      child->AttachLayoutTree(context);
    }
  }

  AttachSucceedingPseudoElements(context);

  if (!IsPseudoElement()) {
    DCHECK(layout_object);
    context.counters_context.LeaveObject(*layout_object);
  }

  ClearChildNeedsReattachLayoutTree();
  ClearNeedsReattachLayoutTree();
}

const ComputedStyle* Element::StyleForLayoutObject(
    const StyleRecalcContext& style_recalc_context) {
  DCHECK(GetDocument().InStyleRecalc());

  StyleRecalcContext new_style_recalc_context(style_recalc_context);

  if (ElementAnimations* element_animations = GetElementAnimations()) {
    // For multiple style recalc passes for the same element in the same
    // lifecycle, which can happen for container queries, we may end up having
    // pending updates from the previous pass. In that case the update from the
    // previous pass should be dropped as it will be re-added if necessary. It
    // may be that an update detected in the previous pass would no longer be
    // necessary if the animated property flipped back to the old style with no
    // change as the result.
    DCHECK(GetDocument().GetStyleEngine().InContainerQueryStyleRecalc() ||
           GetDocument().GetStyleEngine().InPositionTryStyleRecalc() ||
           PostStyleUpdateScope::InPendingPseudoUpdate() ||
           element_animations->CssAnimations().PendingUpdate().IsEmpty());
    element_animations->CssAnimations().ClearPendingUpdate();
  }

  new_style_recalc_context.old_style = PostStyleUpdateScope::GetOldStyle(*this);
  const ComputedStyle* style =
      HasCustomStyleCallbacks()
          ? CustomStyleForLayoutObject(new_style_recalc_context)
          : OriginalStyleForLayoutObject(new_style_recalc_context);
  if (!style) {
    DCHECK(IsPseudoElement());
    return nullptr;
  }
  if (style->IsStartingStyle()) {
    // @starting-style styles matched. We need to compute the style a second
    // time to compute the actual style and trigger transitions starting from
    // style with @starting-style applied.
    new_style_recalc_context.old_style =
        style->Display() == EDisplay::kNone ? nullptr : style;
    style = HasCustomStyleCallbacks()
                ? CustomStyleForLayoutObject(new_style_recalc_context)
                : OriginalStyleForLayoutObject(new_style_recalc_context);
  }

  DisplayLockContext* context = GetDisplayLockContext();
  // The common case for most elements is that we don't have a context and have
  // the default (visible) content-visibility value.
  if (context || !style->IsContentVisibilityVisible()) [[unlikely]] {
    if (!context) {
      context = &EnsureDisplayLockContext();
    }
    context->SetRequestedState(style->ContentVisibility());
    style = context->AdjustElementStyle(style);
  }

  if (style->DependsOnSizeContainerQueries() ||
      style->GetPositionTryFallbacks() || style->HasAnchorFunctions()) {
    GetDocument().GetStyleEngine().SetStyleAffectedByLayout();
  }

  return style;
}

void Element::AdjustStyle(base::PassKey<StyleAdjuster>,
                          ComputedStyleBuilder& builder) {
  AdjustStyle(builder);
}

const ComputedStyle* Element::OriginalStyleForLayoutObject(
    const StyleRecalcContext& style_recalc_context) {
  return GetDocument().GetStyleResolver().ResolveStyle(this,
                                                       style_recalc_context);
}

void Element::RecalcStyleForTraversalRootAncestor() {
  if (!ChildNeedsReattachLayoutTree()) {
    UpdateFirstLetterPseudoElement(StyleUpdatePhase::kRecalc);
  }
  if (HasCustomStyleCallbacks()) {
    DidRecalcStyle({});
  }
}

bool Element::SkipStyleRecalcForContainer(
    const ComputedStyle& style,
    const StyleRecalcChange& child_change,
    const StyleRecalcContext& style_recalc_context) {
  if (!GetDocument().GetStyleEngine().SkipStyleRecalcAllowed()) {
    return false;
  }

  if (!child_change.TraversePseudoElements(*this)) {
    // If none of the children or pseudo elements need to be traversed for style
    // recalc, there is no point in marking the subtree as skipped.
    DCHECK(!child_change.TraverseChildren(*this));
    return false;
  }

  if (!child_change.ReattachLayoutTree()) {
    LayoutObject* layout_object = GetLayoutObject();
    if (!layout_object ||
        !WillUpdateSizeContainerDuringLayout(*layout_object)) {
      return false;
    }
  }

  // Don't skip style recalc for form controls. The reason for skipping is a
  // baseline inconsistency issue laying out an input element with a placeholder
  // when interleaving layout and style recalc. This bigger cannon is to avoid
  // potential issues with other peculiarities inside form controls.
  if (IsFormControlElement()) {
    return false;
  }

  // If we are moving the ::backdrop element to the top layer while laying out
  // its originating element, it means we will add a layout-dirty box as a
  // preceding sibling of the originating element's box which means we will not
  // reach the box for ::backdrop during layout. Don't skip style recalc for
  // children of containers in the top layer for this reason.
  if (style.IsRenderedInTopLayer(*this)) {
    return false;
  }

  // We are both a size container and trying to compute interleaved styles
  // from out-of-flow layout. Our children should be the first opportunity to
  // skip recalc.
  //
  // Note that anchor_evaluator will be non-null only for the root element
  // of the interleaved style recalc.
  if (style_recalc_context.anchor_evaluator) {
    return false;
  }

  // ::scroll-marker-group boxes are created outside their originating element's
  // box and cannot be skipped if the originating element is a size container
  // because the pseudo element and its box need to be created before layout.
  if (style.HasPseudoElementStyle(kPseudoIdScrollMarkerGroup)) {
    return false;
  }

  // Store the child_change so that we can continue interleaved style layout
  // from where we left off.
  EnsureElementRareData().EnsureContainerQueryData().SkipStyleRecalc(
      child_change.ForceMarkReattachLayoutTree());

  GetDocument().GetStyleEngine().IncrementSkippedContainerRecalc();

  if (HasCustomStyleCallbacks()) {
    DidRecalcStyle(child_change);
  }

  // This needs to be cleared to satisty the DCHECKed invariants in
  // Element::RebuildLayoutTree(). ChildNeedsStyleRecalc() is flipped back on
  // before resuming the style recalc when the container is laid out. The stored
  // child_change contains the correct flags to resume recalc of child nodes.
  ClearChildNeedsStyleRecalc();
  return true;
}

void Element::MarkNonSlottedHostChildrenForStyleRecalc() {
  // Mark non-slotted children of shadow hosts for style recalc for forced
  // subtree recalcs when they have ensured computed style outside the flat
  // tree. Elements outside the flat tree are not recomputed during the style
  // recalc step, but we need to make sure the ensured styles are dirtied so
  // that we know to clear out old styles from
  // StyleEngine::ClearEnsuredDescendantStyles() the next time we call
  // getComputedStyle() on any of the descendant elements.
  for (Node* child = firstChild(); child; child = child->nextSibling()) {
    if (child->NeedsStyleRecalc()) {
      continue;
    }
    if (auto* element = DynamicTo<Element>(child)) {
      if (auto* style = element->GetComputedStyle()) {
        if (style->IsEnsuredOutsideFlatTree()) {
          child->SetStyleChangeForNonSlotted();
        }
      }
    }
  }
}

const ComputedStyle* Element::ParentComputedStyle() const {
  Element* parent = LayoutTreeBuilderTraversal::ParentElement(*this);
  if (parent && parent->ChildrenCanHaveStyle()) {
    const ComputedStyle* parent_style = parent->GetComputedStyle();
    if (parent_style && !parent_style->IsEnsuredInDisplayNone()) {
      return parent_style;
    }
  }
  return nullptr;
}

// Recalculate the style for this element, and if that element notes
// that children must also be recalculated, call ourself recursively
// on any children (via RecalcDescendantStyles()), and/or update
// pseudo-elements.
void Element::RecalcStyle(const StyleRecalcChange change,
                          const StyleRecalcContext& style_recalc_context) {
  DCHECK(InActiveDocument());
  DCHECK(GetDocument().InStyleRecalc());
  DCHECK(!GetDocument().Lifecycle().InDetach());
  DCHECK(!GetForceReattachLayoutTree() || GetComputedStyle())
      << "No need to force a layout tree reattach if we had no computed style";
  DCHECK(LayoutTreeBuilderTraversal::ParentElement(*this) ||
         this == GetDocument().documentElement())
      << "No recalc for Elements outside flat tree";

  DisplayLockStyleScope display_lock_style_scope(this);
  if (HasCustomStyleCallbacks()) {
    WillRecalcStyle(change);
  }

  StyleScopeFrame style_scope_frame(
      *this, /* parent */ style_recalc_context.style_scope_frame);
  StyleRecalcContext local_style_recalc_context = style_recalc_context;
  local_style_recalc_context.style_scope_frame = &style_scope_frame;

  StyleRecalcChange child_change = change.ForChildren(*this);
  if (change.ShouldRecalcStyleFor(*this)) {
    child_change = RecalcOwnStyle(change, local_style_recalc_context);
    if (GetStyleChangeType() == kSubtreeStyleChange) {
      child_change =
          child_change.EnsureAtLeast(StyleRecalcChange::kRecalcDescendants);
    }
    ClearNeedsStyleRecalc();
  } else if (GetForceReattachLayoutTree() ||
             (change.MarkReattachLayoutTree() && GetComputedStyle())) {
    SetNeedsReattachLayoutTree();
    child_change = child_change.ForceReattachLayoutTree();
    ClearNeedsStyleRecalc();
  }

  // We may need to update the internal CSSContainerValues of the
  // ContainerQueryEvaluator if e.g. the value of the 'rem' unit or container-
  // relative units changed. It are not guaranteed to reach RecalcOwnStyle for
  // the container, so this update happens here instead.
  if (ContainerQueryEvaluator* evaluator = GetContainerQueryEvaluator()) {
    evaluator->UpdateContainerValuesFromUnitChanges(child_change);
  }

  // We're done with self style, notify the display lock.
  child_change = display_lock_style_scope.DidUpdateSelfStyle(child_change);
  if (!display_lock_style_scope.ShouldUpdateChildStyle()) {
    display_lock_style_scope.NotifyChildStyleRecalcWasBlocked(child_change);
    if (HasCustomStyleCallbacks()) {
      DidRecalcStyle(child_change);
    }
    return;
  }

  StyleRecalcContext child_recalc_context = local_style_recalc_context;
  // If we're in StyleEngine::UpdateStyleForOutOfFlow, then anchor_evaluator
  // may be non-nullptr to allow evaluation of anchor() and anchor-size()
  // queries, and the try sets may be non-nullptr if we're attempting
  // some position option [1]. These are only supposed to apply to the
  // interleaving root itself (i.e. the out-of-flow element being laid out),
  // and not to descendants.
  //
  // [1] https://drafts.csswg.org/css-anchor-position-1/#fallback
  child_recalc_context.anchor_evaluator = nullptr;
  child_recalc_context.try_set = nullptr;
  child_recalc_context.try_tactics_set = nullptr;

  if (ContainerQueryData* cq_data = GetContainerQueryData()) {
    // If we skipped the subtree during style recalc, retrieve the
    // StyleRecalcChange which was the current change for the skipped subtree
    // and combine it with the current child_change.
    if (cq_data->SkippedStyleRecalc()) {
      GetDocument().GetStyleEngine().DecrementSkippedContainerRecalc();
      child_change = cq_data->ClearAndReturnRecalcChangeForChildren().Combine(
          child_change);
    }
  }

  if (const ComputedStyle* style = GetComputedStyle()) {
    if (style->CanMatchSizeContainerQueries(*this)) {
      // IsSuppressed() means we are at the root of a container subtree called
      // from UpdateStyleAndLayoutTreeForContainer(). If so, we can not skip
      // recalc again. Otherwise, we may skip recalc of the subtree if we can
      // guarantee that we will be able to resume during layout later.
      if (!change.IsSuppressed()) {
        if (SkipStyleRecalcForContainer(*style, child_change,
                                        style_recalc_context)) {
          return;
        }
      }
    }
    if (style->IsContainerForSizeContainerQueries()) {
      child_recalc_context.container = this;
    }
  }

  if (LayoutObject* layout_object = GetLayoutObject()) {
    // If a layout subtree was synchronously detached on DOM or flat tree
    // changes, we need to revisit the element during layout tree rebuild for
    // two reasons:
    //
    // 1. SubtreeDidChange() needs to be called on list-item layout objects
    //    ancestors for markers (see SubtreeDidChange() implementation on list
    //    item layout objects).
    // 2. Whitespace siblings of removed subtrees may change to have their
    //    layout object added or removed as the need for rendering the
    //    whitespace may have changed.
    bool mark_ancestors = layout_object->WasNotifiedOfSubtreeChange();
    if (layout_object->WhitespaceChildrenMayChange()) {
      if (LayoutTreeBuilderTraversal::FirstChild(*this)) {
        mark_ancestors = true;
      } else {
        layout_object->SetWhitespaceChildrenMayChange(false);
      }
    }
    if (mark_ancestors) {
      MarkAncestorsWithChildNeedsReattachLayoutTree();
    }
  }

  if (child_change.TraversePseudoElements(*this)) {
    UpdateBackdropPseudoElement(child_change, child_recalc_context);
    UpdatePseudoElement(kPseudoIdScrollPrevButton, child_change,
                        child_recalc_context);
    UpdateScrollMarkerGroupPseudoElement(kPseudoIdScrollMarkerGroupBefore,
                                         child_change, child_recalc_context);
    UpdatePseudoElement(kPseudoIdMarker, child_change, child_recalc_context);
    UpdatePseudoElement(kPseudoIdScrollMarker, child_change,
                        child_recalc_context);
    UpdateColumnPseudoElements(child_change, child_recalc_context);

    if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
      if (DynamicTo<HTMLOptionElement>(this)) {
        UpdatePseudoElement(kPseudoIdCheck, child_change, child_recalc_context);
      }
    }

    UpdatePseudoElement(kPseudoIdBefore, child_change, child_recalc_context);
  }

  if (child_change.TraverseChildren(*this)) {
    SelectorFilterParentScope filter_scope(*this);
    if (ShadowRoot* root = GetShadowRoot()) {
      root->RecalcDescendantStyles(child_change, child_recalc_context);
      if (child_change.RecalcDescendants()) {
        MarkNonSlottedHostChildrenForStyleRecalc();
      }
    } else if (auto* slot = ToHTMLSlotElementIfSupportsAssignmentOrNull(this)) {
      slot->RecalcStyleForSlotChildren(
          child_change, child_recalc_context.ForSlotChildren(*slot));
    } else {
      RecalcDescendantStyles(child_change, child_recalc_context);
    }
  }

  if (child_change.TraversePseudoElements(*this)) {
    UpdatePseudoElement(kPseudoIdAfter, child_change, child_recalc_context);

    if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
      if (IsA<HTMLSelectElement>(this)) {
        UpdatePseudoElement(kPseudoIdSelectArrow, child_change,
                            child_recalc_context);
      }
    }

    UpdateScrollMarkerGroupPseudoElement(kPseudoIdScrollMarkerGroupAfter,
                                         child_change, child_recalc_context);
    UpdatePseudoElement(kPseudoIdScrollNextButton, child_change,
                        child_recalc_context);

    // If we are re-attaching us or any of our descendants, we need to attach
    // the descendants before we know if this element generates a ::first-letter
    // and which element the ::first-letter inherits style from.
    //
    // If style recalc was suppressed for this element, it means it's a size
    // query container, and child_change.ReattachLayoutTree() comes from the
    // skipped style recalc. In that case we haven't updated the style, and we
    // will not update the ::first-letter style in the originating element's
    // AttachLayoutTree().
    if (child_change.ReattachLayoutTree() && !change.IsSuppressed()) {
      // Make sure we reach this element during reattachment. There are cases
      // where we compute and store the styles for a subtree but stop attaching
      // layout objects at an element that does not allow child boxes. Marking
      // dirty for re-attachment means we AttachLayoutTree() will still traverse
      // down to all elements with a ComputedStyle which clears the
      // NeedsStyleRecalc() flag.
      if (PseudoElement* first_letter =
              GetPseudoElement(kPseudoIdFirstLetter)) {
        first_letter->SetNeedsReattachLayoutTree();
      }
    } else if (!ChildNeedsReattachLayoutTree()) {
      UpdateFirstLetterPseudoElement(StyleUpdatePhase::kRecalc,
                                     child_recalc_context);
    }
  }

  ClearChildNeedsStyleRecalc();
  // We've updated all the children that needs an update (might be 0).
  display_lock_style_scope.DidUpdateChildStyle();

  if (HasCustomStyleCallbacks()) {
    DidRecalcStyle(child_change);
  }
}

const ComputedStyle* Element::PropagateInheritedProperties() {
  if (IsPseudoElement()) {
    return nullptr;
  }
  if (NeedsStyleRecalc()) {
    return nullptr;
  }
  if (HasAnimations()) {
    return nullptr;
  }
  if (HasCustomStyleCallbacks()) {
    return nullptr;
  }
  const ComputedStyle* parent_style = ParentComputedStyle();
  DCHECK(parent_style);
  const ComputedStyle* style = GetComputedStyle();
  if (!style || style->Animations() || style->Transitions() ||
      style->HasVariableReference() || style->HasVariableDeclaration()) {
    return nullptr;
  }
  if (style->InsideLink() != EInsideLink::kNotInsideLink) {
    // We cannot do the inherited propagation optimization within links,
    // since -internal-visited-color is handled in CascadeExpansion
    // (which we do not run in that path), and we also have no tracking
    // of whether the property was inherited or not.
    return nullptr;
  }
  if (style->HasAppliedTextDecorations()) {
    // If we have text decorations, they can depend on currentColor,
    // and are normally updated by the StyleAdjuster. We can, however,
    // reach this path when color is modified, leading to the decoration
    // being the wrong color (see crbug.com/1330953). We could rerun
    // the right part of the StyleAdjuster here, but it's simpler just to
    // disable the optimization in such cases (especially as we have already
    // disabled it for links, which are the main causes of text decorations),
    // so we do that.
    return nullptr;
  }
  ComputedStyleBuilder builder(*style);
  builder.PropagateIndependentInheritedProperties(*parent_style);
  INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                independent_inherited_styles_propagated, 1);
  return builder.TakeStyle();
}

static bool NeedsContainerQueryEvaluator(
    const ContainerQueryEvaluator& evaluator,
    const ComputedStyle& new_style) {
  return evaluator.DependsOnStyle() ||
         new_style.IsContainerForSizeContainerQueries() ||
         new_style.IsContainerForScrollStateContainerQueries();
}

static const StyleRecalcChange ApplyComputedStyleDiff(
    const StyleRecalcChange change,
    ComputedStyle::Difference diff) {
  if (change.RecalcDescendants() ||
      diff < ComputedStyle::Difference::kPseudoElementStyle) {
    return change;
  }
  if (diff == ComputedStyle::Difference::kDescendantAffecting) {
    return change.EnsureAtLeast(StyleRecalcChange::kRecalcDescendants);
  }
  if (diff == ComputedStyle::Difference::kInherited) {
    return change.EnsureAtLeast(StyleRecalcChange::kRecalcChildren);
  }
  if (diff == ComputedStyle::Difference::kIndependentInherited) {
    return change.EnsureAtLeast(StyleRecalcChange::kIndependentInherit);
  }
  DCHECK(diff == ComputedStyle::Difference::kPseudoElementStyle);
  return change.EnsureAtLeast(StyleRecalcChange::kUpdatePseudoElements);
}

static bool LayoutViewCanHaveChildren(Element& element) {
  if (LayoutObject* view = element.GetDocument().GetLayoutView()) {
    return view->CanHaveChildren();
  }
  return false;
}

void Element::NotifyAXOfAttachedSubtree() {
  if (auto* ax_cache = GetDocument().ExistingAXObjectCache()) {
    ax_cache->SubtreeIsAttached(this);
  }
}

// This function performs two important tasks:
//
//  1. It computes the correct style for the element itself.
//  2. It figures out to what degree we need to propagate changes
//     to child elements (and returns that).
//
// #1 can happen in one out of two ways. The normal way is that ask the
// style resolver to compute the style from scratch (modulo some caching).
// The other one is an optimization for “independent inherited properties”;
// if this recalc is because the parent has changed only properties marked
// as “independent” (i.e., they do not affect other properties; “visibility”
// is an example of such a property), we can reuse our existing style and just
// re-propagate those properties.
//
// #2 happens by diffing the old and new styles. In the extreme example,
// if the two are identical, we don't need to invalidate child elements
// at all. But if they are different, they will usually be different to
// differing degrees; e.g. as noted above, if only independent properties
// changed, we can inform children of that for less work down the tree.
// Our own diff gets combined with the input StyleRecalcChange to produce a
// child recalc policy that's roughly the strictest of the two.
StyleRecalcChange Element::RecalcOwnStyle(
    const StyleRecalcChange change,
    const StyleRecalcContext& style_recalc_context) {
  DCHECK(GetDocument().InStyleRecalc());

  StyleRecalcContext new_style_recalc_context = style_recalc_context;
  if (change.RecalcChildren() || change.RecalcContainerQueryDependent(*this)) {
    if (NeedsStyleRecalc()) {
      if (ElementRareDataVector* data = GetElementRareData()) {
        // This element needs recalc because its parent changed inherited
        // properties or there was some style change in the ancestry which
        // needed a full subtree recalc. In that case we cannot use the
        // BaseComputedStyle optimization.
        if (ElementAnimations* element_animations =
                data->GetElementAnimations()) {
          element_animations->SetAnimationStyleChange(false);
        }
        // We can not apply the style incrementally if we're propagating
        // inherited changes from the parent, as incremental styling would not
        // include those changes. (Incremental styling is disabled by default.)
      }
    }
  } else {
    // We are not propagating inherited changes from the parent,
    // and (if other circumstances allow it;
    // see CanApplyInlineStyleIncrementally()), incremental style
    // may be used.
    new_style_recalc_context.can_use_incremental_style = true;
  }

  const ComputedStyle* new_style = nullptr;
  const ComputedStyle* old_style = GetComputedStyle();

  StyleRecalcChange child_change = change.ForChildren(*this);

  const ComputedStyle* parent_style = ParentComputedStyle();
  if (parent_style && old_style && change.IndependentInherit(*old_style)) {
    // When propagating inherited changes, we don't need to do a full style
    // recalc if the only changed properties are independent. In this case, we
    // can simply clone the old ComputedStyle and set these directly.
    new_style = PropagateInheritedProperties();
    if (new_style) {
      // If the child style is copied from the old one, we'll never
      // reach StyleBuilder::ApplyProperty(), hence we'll
      // never set the flag on the parent. this is completely analogous
      // to the code in StyleResolver::ApplyMatchedCache().
      if (new_style->HasExplicitInheritance()) {
        parent_style->SetChildHasExplicitInheritance();
      }
    }
  }
  if (!new_style && (parent_style || (GetDocument().documentElement() == this &&
                                      LayoutViewCanHaveChildren(*this)))) {
    // This is the normal flow through the function; calculates
    // the element's style more or less from scratch (typically
    // ending up calling StyleResolver::ResolveStyle()).
    new_style = StyleForLayoutObject(new_style_recalc_context);
  }
  bool base_is_display_none =
      !new_style ||
      new_style->GetBaseComputedStyleOrThis()->Display() == EDisplay::kNone;

  if (new_style) {
    if (!ShouldStoreComputedStyle(*new_style)) {
      new_style = nullptr;
      NotifyAXOfAttachedSubtree();
    } else {
      if (!old_style && !new_style->IsContentVisibilityVisible()) {
        NotifyAXOfAttachedSubtree();
      }
      if (new_style->IsContainerForSizeContainerQueries()) {
        new_style_recalc_context.container = this;
      }
      new_style = RecalcHighlightStyles(new_style_recalc_context, old_style,
                                        *new_style, parent_style);
    }
  }

  ComputedStyle::Difference diff =
      ComputedStyle::ComputeDifference(old_style, new_style);

  if (old_style && old_style->IsEnsuredInDisplayNone()) {
    // Make sure we traverse children for clearing ensured computed styles
    // further down the tree.
    child_change =
        child_change.EnsureAtLeast(StyleRecalcChange::kRecalcChildren);
    // If the existing style was ensured in a display:none subtree, set it to
    // null to make sure we don't mark for re-attachment if the new style is
    // null.
    old_style = nullptr;
  }

  if (!new_style) {
    if (ElementRareDataVector* data = GetElementRareData()) {
      if (ElementAnimations* element_animations =
              data->GetElementAnimations()) {
        // The animation should only be canceled when the base style is
        // display:none. If new_style is otherwise set to display:none, then it
        // means an animation set display:none, and an animation shouldn't
        // cancel itself in this case.
        if (base_is_display_none) {
          element_animations->CssAnimations().Cancel();
        }
      }
      data->SetContainerQueryEvaluator(nullptr);
      data->ClearPseudoElements();
    }
  }
  SetComputedStyle(new_style);

  if ((!old_style && new_style && new_style->GetCounterDirectives()) ||
      (old_style && new_style &&
       !old_style->CounterDirectivesEqual(*new_style)) ||
      (old_style && old_style->GetCounterDirectives() && !new_style)) {
    GetDocument().GetStyleEngine().MarkCountersDirty();
  }

  if ((!new_style && old_style && old_style->ContainsStyle()) ||
      (old_style && new_style &&
       old_style->ContainsStyle() != new_style->ContainsStyle())) {
    GetDocument().GetStyleEngine().MarkCountersDirty();
  }

  // Update style containment tree if the style containment of the element
  // has changed.
  // Don't update if the style containment tree has not been initialized.
  if (GetDocument().GetStyleEngine().GetStyleContainmentScopeTree() &&
      ((!new_style && old_style && old_style->ContainsStyle()) ||
       (old_style && new_style &&
        old_style->ContainsStyle() != new_style->ContainsStyle()))) {
    StyleContainmentScopeTree& tree =
        GetDocument().GetStyleEngine().EnsureStyleContainmentScopeTree();
    if (old_style && old_style->ContainsStyle()) {
      tree.DestroyScopeForElement(*this);
    }
    if (new_style && new_style->ContainsStyle()) {
      tree.CreateScopeForElement(*this);
    }
  }

  ProcessContainIntrinsicSizeChanges();

  if (!child_change.ReattachLayoutTree() &&
      (GetForceReattachLayoutTree() || NeedsReattachLayoutTree() ||
       ComputedStyle::NeedsReattachLayoutTree(*this, old_style, new_style))) {
    child_change = child_change.ForceReattachLayoutTree();
  }

  if (diff == ComputedStyle::Difference::kEqual) {
    INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                  styles_unchanged, 1);
    if (!new_style) {
      DCHECK(!old_style);
      return {};
    }
  } else {
    INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                  styles_changed, 1);
    probe::DidUpdateComputedStyle(this, old_style, new_style);
    if (this == GetDocument().documentElement()) {
      if (GetDocument().GetStyleEngine().UpdateRootFontRelativeUnits(
              old_style, new_style)) {
        // Trigger a full document recalc on root font units changes. We could
        // keep track of which elements depend on root font units like we do for
        // viewport styles, but we assume root font size changes are rare and
        // just recalculate everything.
        child_change =
            child_change.EnsureAtLeast(StyleRecalcChange::kRecalcDescendants);
      }
    }
    child_change = ApplyComputedStyleDiff(child_change, diff);
    UpdateCallbackSelectors(old_style, new_style);
    NotifyIfMatchedDocumentRulesSelectorsChanged(old_style, new_style);
  }

  if (auto* context = GetDisplayLockContext()) {
    // Combine the change from the display lock context. If the context is
    // locked and is preventing child update, we'll store this style recalc
    // change again from Element::RecalcStyle.
    child_change =
        child_change.Combine(context->TakeBlockedStyleRecalcChange());
  }

  if (new_style) {
    if (old_style && !child_change.RecalcChildren() &&
        old_style->HasChildDependentFlags()) {
      new_style->CopyChildDependentFlagsFrom(*old_style);
    }
    if (ContainerQueryEvaluator* evaluator = GetContainerQueryEvaluator()) {
      if (!NeedsContainerQueryEvaluator(*evaluator, *new_style)) {
        Ensure
"""


```