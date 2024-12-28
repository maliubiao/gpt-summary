Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/element.cc`. I need to analyze the code, identify its purpose, and explain its relationship to web technologies (JavaScript, HTML, CSS).

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:**  The code primarily deals with updating and managing the styling and layout of an `Element` within the Blink rendering engine. Key functions like `UpdateStyle`, `ProcessContainIntrinsicSizeChanges`, `RebuildLayoutTree`, and `PseudoStateChanged` strongly suggest this.

2. **Analyze Key Functions:**
    * **`UpdateStyle`:** This function is central to applying style changes to an element and its descendants. It handles container queries, style diffing, and updates the `LayoutObject`. It also deals with special cases like `<br>`/`<wbr>` in combined text and HTML root element styling.
    * **`ProcessContainIntrinsicSizeChanges`:** This relates to the `contain-intrinsic-size` CSS property, controlling how an element's size is determined when its content is not rendered.
    * **`RebuildLayoutTree`:** This function manages the rebuilding of the layout tree for the element and its children, considering things like whitespace, pseudo-elements, and shadow DOM.
    * **`PseudoStateChanged`:** This function handles the consequences of an element's pseudo-state changing (e.g., `:hover`, `:focus`), triggering style recalculations.
    * **Directionality functions (`ParentDirectionality`, `RecomputeDirectionFromParent`, `UpdateDirectionalityAndDescendant`, `ResolveAutoDirectionality`):** These functions handle the complexities of text direction (LTR/RTL) based on parent elements and the `dir` attribute.
    * **Shadow DOM related functions (`CreateAndAttachShadowRoot`, `GetShadowRoot`):** These functions are responsible for creating and managing shadow DOM for encapsulation.
    * **Edit Context functions (`editContext`, `setEditContext`):** These functions are related to the experimental EditContext API for richer text editing.

3. **Connect to Web Technologies:**
    * **CSS:** The most prominent connection. The code directly manipulates `ComputedStyle`, applies style changes based on CSS properties (e.g., `contain-intrinsic-size`, `display`, `position`), and handles pseudo-classes.
    * **HTML:** The code deals with specific HTML elements (e.g., `HTMLHtmlElement`, `HTMLAnchorElementBase`, `HTMLSlotElement`), attributes (e.g., `dir`), and the structure of the DOM.
    * **JavaScript:** While not directly manipulating JavaScript, the code is the *result* of JavaScript interactions that might change styles or the DOM structure. For example, setting `element.style.display = 'none'` or using methods like `attachShadow()` will eventually lead to this C++ code being executed.

4. **Identify Logic and Assumptions:**
    * **Style Diffing:** The code assumes that comparing `ComputedStyle` objects can determine if visual invalidation is needed.
    * **Layout Tree Rebuilding:** It's assumed that specific conditions (like `NeedsReattachLayoutTree`) trigger a complete rebuild, while others allow for more targeted updates.
    * **Directionality Inheritance:** The logic for directionality relies on the DOM tree and the cascading nature of the `dir` attribute.

5. **Consider User/Programming Errors:**
    * **Incorrect `dir` Attribute:** Setting an invalid value for the `dir` attribute might lead to unexpected directionality.
    * **Modifying Styles in a Loop:**  Repeatedly changing styles in JavaScript can trigger multiple style recalculations, potentially impacting performance.
    * **Conflicting Styles:**  CSS specificity rules and the order of style application can lead to unexpected styling outcomes.

6. **Trace User Actions:**  Think about user interactions that would trigger style or layout changes:
    * **Page Load:** Initial rendering of the HTML and CSS.
    * **JavaScript DOM Manipulation:** Adding/removing elements, changing attributes, modifying styles.
    * **CSS Interactions:** Hovering over an element, focusing on an input field, state changes triggered by CSS selectors (e.g., `:checked`).
    * **Resize Events:** Changing the browser window size can trigger layout recalculations.

7. **Focus on the Provided Snippet:** The code snippet focuses on the `UpdateStyle` function. It details how style changes are applied, considering container queries, and how the `LayoutObject` is updated. The critical part is the conditional logic based on the style difference (`diff`).

8. **Synthesize the Summary:** Combine the above points into a concise description of the code's functionality. Emphasize the core purpose, connections to web technologies, and potential issues. Specifically address the provided `UpdateStyle` function's role.

**(Self-Correction/Refinement):** Initially, I might focus too broadly on all the functions. However, since the user provided a specific snippet, I need to make sure the explanation emphasizes that part while still providing context about the overall file's purpose. Also, I need to ensure the examples are concrete and illustrative. For the "user operations" section, it's important to show a progression that leads to the `UpdateStyle` function being called.
文件 `blink/renderer/core/dom/element.cc` 是 Chromium Blink 引擎中 `Element` 类的实现文件，它是 DOM 树中节点的基础类之一，代表 HTML 或 XML 文档中的一个元素。

**主要功能归纳：**

该文件的主要功能是处理与元素的样式更新、布局以及一些高级特性相关的逻辑。具体来说，它负责：

1. **样式更新 (`UpdateStyle` 函数):**
   - 接收新的计算样式 (`new_style`) 并将其应用到元素。
   - 与旧的计算样式 (`old_style`) 进行比较，以确定需要进行的布局更新或重绘的范围。
   - 处理容器查询相关的逻辑，例如在样式改变时更新容器查询的评估器。
   - 针对特定元素类型（例如文本节点在组合文本中）或伪元素进行样式调整。
   - 考虑 `position-try-fallbacks` 属性的变化。
   - 处理 HTML 根元素的特殊样式应用逻辑。
   - 避免在即将删除的 `LayoutObject` 上进行不必要的样式更新。
   - 考虑 `anchor()` 函数对布局的影响。

2. **内联尺寸 (`ProcessContainIntrinsicSizeChanges` 函数):**
   - 处理 `contain-intrinsic-size` CSS 属性，该属性允许元素在内容尚未加载或渲染时指定其固有大小。
   - 跟踪和更新元素的最后记忆的块状和内联尺寸。
   - 根据样式和上下文决定是否需要观察元素的固有尺寸变化。

3. **布局树重建 (`RebuildLayoutTree` 函数及其相关函数):**
   - 决定是否需要重新连接元素的布局树或重建其子元素的布局树。
   - 处理 `display: contents` 元素的特殊情况。
   - 管理伪元素的布局树重建 (例如 `::before`, `::after`, `::first-letter` 等)。
   - 处理 Shadow DOM 的布局树重建。
   - 在布局树重建前后执行必要的清理工作，例如清除 `NeedsReattachLayoutTree` 标志。

4. **方向性处理 (`ParentDirectionality`, `RecomputeDirectionFromParent`, `UpdateDirectionalityAndDescendant`, `ResolveAutoDirectionality` 等函数):**
   - 处理元素的文本方向性 (`ltr` 或 `rtl`)，包括从父元素继承、`dir` 属性的影响以及 `dir="auto"` 的解析。
   - 管理 `SelfOrAncestorHasDirAutoAttribute` 状态。
   - 涉及对包含文本的自动方向性判断。

5. **Shadow DOM (`CreateAndAttachShadowRoot`, `GetShadowRoot` 函数):**
   - 创建并附加 Shadow DOM 到元素上，实现样式和结构的封装。

6. **编辑上下文 (`editContext`, `setEditContext` 函数):**
   -  处理实验性的 `EditContext` API，允许自定义文本编辑行为。

7. **伪状态改变 (`PseudoStateChanged` 函数):**
   - 当元素的伪状态（例如 `:hover`, `:focus`）改变时触发样式重新计算。
   - 考虑伪状态改变对子元素、兄弟元素和祖先元素的影响，特别是与 `:has()` 伪类选择器相关的逻辑。

8. **回调选择器和文档规则选择器 (`UpdateCallbackSelectors`, `NotifyIfMatchedDocumentRulesSelectorsChanged` 函数):**
   - 管理与 CSS 回调选择器和文档规则选择器的匹配状态变化相关的通知。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** `Element` 类是 DOM 树的基础，直接对应 HTML 中的各种标签。
    * **举例:** 当浏览器解析 HTML 代码 `<div id="myDiv">Hello</div>` 时，会在 Blink 引擎中创建一个 `Element` 类的实例来表示这个 `<div>` 元素。
* **CSS:**  该文件处理样式计算和应用的核心逻辑。CSS 规则决定了元素的 `ComputedStyle`，而 `UpdateStyle` 函数负责将这些样式应用到元素并更新其布局。
    * **举例:**  如果 CSS 规则是 `#myDiv { color: red; }`，当这个规则匹配到 ID 为 `myDiv` 的元素时，`UpdateStyle` 函数会被调用，将 `color` 属性设置为红色。
    * **举例 (容器查询):**  CSS 中定义了 `@container style(--size > 100px) { ... }` 这样的容器查询规则，当 `#myDiv` 元素的父容器的 `--size` 自定义属性大于 100px 时，`UpdateStyle` 函数中与容器查询相关的代码会执行，可能会为 `#myDiv` 应用不同的样式。
* **JavaScript:** JavaScript 可以动态地修改元素的样式、属性和 DOM 结构，这些操作最终会触发 `element.cc` 中的代码执行。
    * **举例:**  JavaScript 代码 `document.getElementById('myDiv').style.backgroundColor = 'blue';` 会导致 `myDiv` 元素的 `ComputedStyle` 发生变化，进而调用 `UpdateStyle` 函数来更新元素的渲染。
    * **举例 (Shadow DOM):** JavaScript 代码 `element.attachShadow({mode: 'open'});` 会调用 `CreateAndAttachShadowRoot` 函数来创建和附加 Shadow DOM。
    * **举例 (方向性):** JavaScript 代码 `element.setAttribute('dir', 'rtl');` 会导致元素的方向性改变，可能会触发 `UpdateDirectionalityAndDescendant` 等函数的调用。

**逻辑推理的假设输入与输出：**

**假设输入:**
1. 一个 `<div>` 元素，其 `id` 为 "testDiv"。
2. 初始 CSS 样式为 `#testDiv { width: 100px; }`。
3. JavaScript 代码执行 `document.getElementById('testDiv').style.width = '200px';`。

**输出:**
1. `UpdateStyle` 函数会被调用，`old_style`  的宽度信息为 100px，`new_style` 的宽度信息为 200px。
2. 由于宽度发生了变化，`diff` 不会是 `ComputedStyle::Difference::kEqual`。
3. `LayoutObject` 的尺寸会更新，并且可能触发后续的布局过程。
4. 如果该元素是某个容器查询的包含元素，相关的容器查询评估器可能会被更新。

**用户或编程常见的使用错误举例说明：**

* **用户错误 (CSS):**  编写了相互冲突的 CSS 规则，导致样式应用结果不符合预期。例如，同时设置了 `width: 100px;` 和 `width: 200px !important;`。浏览器会按照 CSS 的优先级规则应用样式，但用户可能对此感到困惑。
* **编程错误 (JavaScript):**  在循环中频繁修改元素的样式，例如：
   ```javascript
   for (let i = 0; i < 1000; i++) {
     document.getElementById('myElement').style.left = i + 'px';
   }
   ```
   这种操作会导致 `UpdateStyle` 函数被大量调用，可能导致性能问题。应该尽量批量更新样式或使用动画 API。
* **编程错误 (Shadow DOM):**  不理解 Shadow DOM 的封装性，试图从主文档的 CSS 或 JavaScript 中直接访问或修改 Shadow DOM 内部的元素样式，这可能会导致预期之外的结果，因为 Shadow DOM 具有自己的样式作用域。
* **编程错误 (方向性):**  错误地设置或假设了元素的方向性，导致文本显示错乱。例如，在包含阿拉伯语文本的元素上忘记设置 `dir="rtl"`。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中打开一个包含 HTML、CSS 和 JavaScript 的网页。**
2. **浏览器开始解析 HTML 文档，构建 DOM 树。**  每遇到一个 HTML 元素，就会创建对应的 `Element` 对象。
3. **浏览器解析 CSS 样式表，构建 CSSOM 树。**
4. **浏览器将 DOM 树和 CSSOM 树结合，计算每个元素的最终样式 (`ComputedStyle`)。**  这个过程中会调用 `UpdateStyle` 函数来应用初始样式。
5. **用户与页面进行交互，例如鼠标悬停在一个元素上。**  这会触发 `:hover` 伪类状态的改变。
6. **Blink 引擎检测到伪状态的改变，调用 `PseudoStateChanged` 函数。**
7. **`PseudoStateChanged` 函数会标记需要重新计算样式的元素。**
8. **在下一次样式计算阶段，`UpdateStyle` 函数会被调用，传入新的 `ComputedStyle` (包含 `:hover` 样式)。**
9. **如果 JavaScript 代码被执行，例如点击一个按钮，JavaScript 代码可能会修改元素的样式或属性。**
10. **这些 JavaScript 修改会导致 `Element` 对象的状态发生变化，进而触发 `UpdateStyle` 函数的调用。**

**调试线索:** 如果在调试过程中发现元素的样式没有按照预期更新，可以考虑以下步骤：

* **检查 CSS 规则的优先级和是否被覆盖。**
* **使用浏览器的开发者工具查看元素的 `ComputedStyle`，确认最终应用的样式。**
* **在 JavaScript 代码中设置断点，查看样式修改的代码是否正确执行。**
* **检查是否存在由于 Shadow DOM 的封装性导致样式无法应用的情况。**
* **如果涉及到容器查询，检查容器元素的尺寸或相关属性是否满足查询条件。**
* **如果涉及到方向性问题，检查元素的 `dir` 属性以及父元素的 `dir` 属性。**
* **使用 Blink 的 tracing 工具 (例如 `chrome://tracing`) 追踪样式计算和布局的过程，查看 `UpdateStyle` 函数的调用栈和参数。**

总而言之，`blink/renderer/core/dom/element.cc` 中的代码是 Blink 引擎中处理元素样式和布局更新的核心部分，它连接了 HTML 结构、CSS 样式和 JavaScript 动态修改，确保网页能够按照预期的方式渲染和交互。

Prompt: 
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共13部分，请归纳一下它的功能

"""
ElementRareData()
            .EnsureContainerQueryData()
            .SetContainerQueryEvaluator(nullptr);
      } else if (old_style) {
        child_change = evaluator->ApplyScrollStateAndStyleChanges(
            child_change, *old_style, *new_style,
            diff != ComputedStyle::Difference::kEqual);
      }
    }
  }

  if (child_change.ReattachLayoutTree()) {
    if (new_style || old_style) {
      SetNeedsReattachLayoutTree();
    }
    return child_change;
  }

  DCHECK(!NeedsReattachLayoutTree())
      << "If we need to reattach the layout tree we should have returned "
         "above. Updating and diffing the style of a LayoutObject which is "
         "about to be deleted is a waste.";

  if (LayoutObject* layout_object = GetLayoutObject()) {
    DCHECK(new_style);
    if (layout_object->IsText() &&
        IsA<LayoutTextCombine>(layout_object->Parent())) [[unlikely]] {
      // Adjust style for <br> and <wbr> in combined text.
      // See http://crbug.com/1228058
      ComputedStyleBuilder adjust_builder(*new_style);
      StyleAdjuster::AdjustStyleForCombinedText(adjust_builder);
      new_style = adjust_builder.TakeStyle();
    }
    // kEqual means that the computed style didn't change, but there are
    // additional flags in ComputedStyle which may have changed. For instance,
    // the AffectedBy* flags. We don't need to go through the visual
    // invalidation diffing in that case, but we replace the old ComputedStyle
    // object with the new one to ensure the mentioned flags are up to date.
    LayoutObject::ApplyStyleChanges apply_changes =
        diff == ComputedStyle::Difference::kEqual
            ? LayoutObject::ApplyStyleChanges::kNo
            : LayoutObject::ApplyStyleChanges::kYes;

    if (diff != ComputedStyle::Difference::kEqual && GetOutOfFlowData() &&
        (!new_style->HasOutOfFlowPosition() ||
         !base::ValuesEquivalent(old_style->GetPositionTryFallbacks().Get(),
                                 new_style->GetPositionTryFallbacks().Get()))) {
      // position-try-fallbacks or positioning changed, which both invalidate
      // last successful try option.
      GetDocument()
          .GetStyleEngine()
          .MarkLastSuccessfulPositionFallbackDirtyForElement(*this);
    }

    const ComputedStyle* layout_style = new_style;
    if (auto* pseudo_element = DynamicTo<PseudoElement>(this)) {
      if (const ComputedStyle* adjusted_style =
              pseudo_element->AdjustedLayoutStyle(
                  *layout_style, layout_object->Parent()->StyleRef())) {
        layout_style = adjusted_style;
      }
    } else if (auto* html_element = DynamicTo<HTMLHtmlElement>(this)) {
      if (this == GetDocument().documentElement()) {
        layout_style = html_element->LayoutStyleForElement(layout_style);
        // Always apply changes for html root, even if the ComputedStyle may be
        // the same, propagation changes picked up from body style, or
        // previously propagated styles from a removed body element, may still
        // change the LayoutObject's style.
        apply_changes = LayoutObject::ApplyStyleChanges::kYes;
      }
    }
    if (style_recalc_context.is_interleaved_oof) {
      // If we're in interleaved style recalc from out-of-flow,
      // we're already in the middle of laying out the objects
      // we would mark for layout.
      apply_changes = LayoutObject::ApplyStyleChanges::kNo;
    } else if (new_style->HasAnchorFunctionsWithoutEvaluator()) {
      // For regular (non-interleaved) recalcs that depend on anchor*()
      // functions, we need to invalidate layout even without a diff,
      // see ComputedStyle::HasAnchorFunctionsWithoutEvaluator.
      apply_changes = LayoutObject::ApplyStyleChanges::kYes;
    }
    layout_object->SetStyle(layout_style, apply_changes);
  }
  return child_change;
}

void Element::ProcessContainIntrinsicSizeChanges() {
  // It is important that we early out, since ShouldUpdateLastRemembered*Size
  // functions only return meaningful results if we have computed style. If we
  // don't have style, we also avoid clearing the last remembered sizes.
  if (!GetComputedStyle()) {
    GetDocument().UnobserveForIntrinsicSize(this);
    return;
  }

  DisplayLockContext* context = GetDisplayLockContext();
  // The only case where we _don't_ record new sizes is if we're skipping
  // contents.
  bool allowed_to_record_new_intrinsic_sizes = !context || !context->IsLocked();

  // We should only record new sizes if we will update either the block or
  // inline direction. IOW, if we have contain-intrinsic-size: auto on at least
  // one of the directions.
  bool should_record_new_intrinsic_sizes = false;
  if (ShouldUpdateLastRememberedBlockSize()) {
    should_record_new_intrinsic_sizes = true;
  } else {
    SetLastRememberedBlockSize(std::nullopt);
  }

  if (ShouldUpdateLastRememberedInlineSize()) {
    should_record_new_intrinsic_sizes = true;
  } else {
    SetLastRememberedInlineSize(std::nullopt);
  }

  if (allowed_to_record_new_intrinsic_sizes &&
      should_record_new_intrinsic_sizes) {
    GetDocument().ObserveForIntrinsicSize(this);
  } else {
    GetDocument().UnobserveForIntrinsicSize(this);
  }
}

void Element::RebuildLayoutTree(WhitespaceAttacher& whitespace_attacher) {
  DCHECK(InActiveDocument());
  DCHECK(parentNode());

  if (NeedsReattachLayoutTree()) {
    AttachContext reattach_context;
    if (IsDocumentElement()) {
      reattach_context.counters_context.SetAttachmentRootIsDocumentElement();
    }
    reattach_context.parent =
        LayoutTreeBuilderTraversal::ParentLayoutObject(*this);
    ReattachLayoutTree(reattach_context);
    if (IsDocumentElement()) {
      GetDocument().GetStyleEngine().MarkCountersClean();
    }
    whitespace_attacher.DidReattachElement(this,
                                           reattach_context.previous_in_flow);
  } else if (NeedsRebuildChildLayoutTrees(whitespace_attacher) &&
             !ChildStyleRecalcBlockedByDisplayLock() &&
             !SkippedContainerStyleRecalc()) {
    // TODO(crbug.com/972752): Make the condition above a DCHECK instead when
    // style recalc and dirty bit propagation uses flat-tree traversal.
    // We create a local WhitespaceAttacher when rebuilding children of an
    // element with a LayoutObject since whitespace nodes do not rely on layout
    // objects further up the tree. Also, if this Element's layout object is an
    // out-of-flow box, in-flow children should not affect whitespace siblings
    // of the out-of-flow box. However, if this element is a display:contents
    // element. Continue using the passed in attacher as display:contents
    // children may affect whitespace nodes further up the tree as they may be
    // layout tree siblings.
    WhitespaceAttacher local_attacher;
    WhitespaceAttacher* child_attacher;
    RebuildPseudoElementLayoutTree(kPseudoIdScrollMarkerGroupAfter,
                                   local_attacher);
    LayoutObject* layout_object = GetLayoutObject();
    if (layout_object || !HasDisplayContentsStyle()) {
      whitespace_attacher.DidVisitElement(this);
      if (layout_object && layout_object->WhitespaceChildrenMayChange()) {
        layout_object->SetWhitespaceChildrenMayChange(false);
        local_attacher.SetReattachAllWhitespaceNodes();
      }
      child_attacher = &local_attacher;
    } else {
      child_attacher = &whitespace_attacher;
    }
    RebuildPseudoElementLayoutTree(kPseudoIdScrollNextButton, *child_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdAfter, *child_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdSelectArrow, *child_attacher);
    if (GetShadowRoot()) {
      RebuildShadowRootLayoutTree(*child_attacher);
    } else {
      RebuildChildrenLayoutTrees(*child_attacher);
    }
    RebuildPseudoElementLayoutTree(kPseudoIdCheck, *child_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdBefore, *child_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdMarker, *child_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdScrollMarkerGroupBefore,
                                   local_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdScrollPrevButton, *child_attacher);
    RebuildPseudoElementLayoutTree(kPseudoIdBackdrop, *child_attacher);
    RebuildFirstLetterLayoutTree();
    ClearChildNeedsReattachLayoutTree();
  }
  DCHECK(!NeedsStyleRecalc());
  DCHECK(!ChildNeedsStyleRecalc() || ChildStyleRecalcBlockedByDisplayLock());
  DCHECK(!NeedsReattachLayoutTree());
  DCHECK(!ChildNeedsReattachLayoutTree() ||
         ChildStyleRecalcBlockedByDisplayLock());
  HandleSubtreeModifications();
}

void Element::RebuildShadowRootLayoutTree(
    WhitespaceAttacher& whitespace_attacher) {
  DCHECK(IsShadowHost(this));
  ShadowRoot* root = GetShadowRoot();
  root->RebuildLayoutTree(whitespace_attacher);
}

void Element::RebuildPseudoElementLayoutTree(
    PseudoId pseudo_id,
    WhitespaceAttacher& whitespace_attacher) {
  if (PseudoElement* element = GetPseudoElement(pseudo_id)) {
    RebuildLayoutTreeForChild(element, whitespace_attacher);
  }
}

void Element::RebuildFirstLetterLayoutTree() {
  // Need to create a ::first-letter element here for the following case:
  //
  // <style>#outer::first-letter {...}</style>
  // <div id=outer><div id=inner style="display:none">Text</div></div>
  // <script> outer.offsetTop; inner.style.display = "block" </script>
  //
  // The creation of FirstLetterPseudoElement relies on the layout tree of the
  // block contents. In this case, the ::first-letter element is not created
  // initially since the #inner div is not displayed. On RecalcStyle it's not
  // created since the layout tree is still not built, and AttachLayoutTree
  // for #inner will not update the ::first-letter of outer. However, we end
  // up here for #outer after AttachLayoutTree is called on #inner at which
  // point the layout sub-tree is available for deciding on creating the
  // ::first-letter.
  StyleEngine::AllowMarkForReattachFromRebuildLayoutTreeScope scope(
      GetDocument().GetStyleEngine());

  UpdateFirstLetterPseudoElement(StyleUpdatePhase::kRebuildLayoutTree);
  if (PseudoElement* element = GetPseudoElement(kPseudoIdFirstLetter)) {
    WhitespaceAttacher whitespace_attacher;
    if (element->NeedsRebuildLayoutTree(whitespace_attacher)) {
      element->RebuildLayoutTree(whitespace_attacher);
    }
  }
}

void Element::HandleSubtreeModifications() {
  if (auto* layout_object = GetLayoutObject()) {
    layout_object->HandleSubtreeModifications();
  }
}

void Element::UpdateCallbackSelectors(const ComputedStyle* old_style,
                                      const ComputedStyle* new_style) {
  Vector<String> empty_vector;
  const Vector<String>& old_callback_selectors =
      old_style ? old_style->CallbackSelectors() : empty_vector;
  const Vector<String>& new_callback_selectors =
      new_style ? new_style->CallbackSelectors() : empty_vector;
  if (old_callback_selectors.empty() && new_callback_selectors.empty()) {
    return;
  }
  if (old_callback_selectors != new_callback_selectors) {
    CSSSelectorWatch::From(GetDocument())
        .UpdateSelectorMatches(old_callback_selectors, new_callback_selectors);
  }
}

void Element::NotifyIfMatchedDocumentRulesSelectorsChanged(
    const ComputedStyle* old_style,
    const ComputedStyle* new_style) {
  if (!IsLink() ||
      !(HasTagName(html_names::kATag) || HasTagName(html_names::kAreaTag))) {
    return;
  }

  HTMLAnchorElementBase* link = To<HTMLAnchorElementBase>(this);
  auto* document_rules = DocumentSpeculationRules::FromIfExists(GetDocument());
  if (!document_rules) {
    return;
  }

  if (ComputedStyle::IsNullOrEnsured(old_style) !=
      ComputedStyle::IsNullOrEnsured(new_style)) {
    document_rules->LinkGainedOrLostComputedStyle(link);
    return;
  }

  auto get_selectors_from_computed_style = [](const ComputedStyle* style) {
    HeapHashSet<WeakMember<StyleRule>> empty_set;
    if (!style || !style->DocumentRulesSelectors()) {
      return empty_set;
    }
    return *style->DocumentRulesSelectors();
  };

  const HeapHashSet<WeakMember<StyleRule>>& old_document_rules_selectors =
      get_selectors_from_computed_style(old_style);
  const HeapHashSet<WeakMember<StyleRule>>& new_document_rules_selectors =
      get_selectors_from_computed_style(new_style);
  if (old_document_rules_selectors.empty() &&
      new_document_rules_selectors.empty()) {
    return;
  }
  if (old_document_rules_selectors != new_document_rules_selectors) {
    document_rules->LinkMatchedSelectorsUpdated(link);
  }
}

TextDirection Element::ParentDirectionality() const {
  Node* parent = parentNode();
  if (Element* parent_element = DynamicTo<Element>(parent)) {
    return parent_element->CachedDirectionality();
  }

  if (ShadowRoot* shadow_root = DynamicTo<ShadowRoot>(parent)) {
    return shadow_root->host().CachedDirectionality();
  }

  return TextDirection::kLtr;
}

void Element::RecomputeDirectionFromParent() {
  // This function recomputes the inherited direction if an element inherits
  // direction from a parent or shadow host.
  //
  // It should match the computation done in
  // Element::UpdateDirectionalityAndDescendant that applies an inherited
  // direction change to the descendants that need updating.
  if (GetDocument().HasDirAttribute() &&
      HTMLElement::ElementInheritsDirectionality(this)) {
    SetCachedDirectionality(ParentDirectionality());
  }
}

void Element::UpdateDirectionalityAndDescendant(TextDirection direction) {
  // This code applies a direction change to an element and to any elements
  // that inherit from it.  It should match the code in
  // Element::RecomputeDirectionFromParent that determines whether a single
  // element should inherit direction and recomputes it if it does.
  Element* element = this;
  do {
    if (element != this &&
        (!HTMLElement::ElementInheritsDirectionality(element) ||
         element->CachedDirectionality() == direction)) {
      element = ElementTraversal::NextSkippingChildren(*element, this);
      continue;
    }

    element->SetCachedDirectionality(direction);
    element->PseudoStateChanged(CSSSelector::kPseudoDir);

    if (ShadowRoot* shadow_root = element->GetShadowRoot()) {
      for (Node& child : ElementTraversal::ChildrenOf(*shadow_root)) {
        if (Element* child_element = DynamicTo<Element>(child)) {
          if (HTMLElement::ElementInheritsDirectionality(child_element) &&
              child_element->CachedDirectionality() != direction) {
            child_element->UpdateDirectionalityAndDescendant(direction);
          }
        }
      }

      // The directionality of a shadow host also affects the effect of
      // its slots on the auto directionality of an ancestor.
      if (shadow_root->HasSlotAssignment()) {
        for (HTMLSlotElement* slot : shadow_root->GetSlotAssignment().Slots()) {
          Element* slot_parent = slot->parentElement();
          if (slot_parent && slot_parent->SelfOrAncestorHasDirAutoAttribute() &&
              slot_parent->CachedDirectionality() != direction) {
            slot_parent->UpdateAncestorWithDirAuto(
                UpdateAncestorTraversal::IncludeSelf);
          }
        }
      }
    }
    element = ElementTraversal::Next(*element, this);
  } while (element);
}

// Because the self-or-ancestor has dir=auto state could come from either a
// node tree ancestor, a slot, or an input, we have a method to
// recalculate it (just for this element) based on all three sources.
bool Element::RecalcSelfOrAncestorHasDirAuto() {
  if (IsHTMLElement()) {
    AtomicString dir_attribute_value = FastGetAttribute(html_names::kDirAttr);
    if (HTMLElement::IsValidDirAttribute(dir_attribute_value)) {
      return EqualIgnoringASCIICase(dir_attribute_value, "auto");
    }
  }
  Node* parent = parentNode();
  if (parent && parent->SelfOrAncestorHasDirAutoAttribute()) {
    return true;
  }
  if (HTMLSlotElement* slot = AssignedSlot()) {
    if (slot->HasDirectionAuto()) {
      return true;
    }
  }
  if (ShadowRoot* shadow_root = DynamicTo<ShadowRoot>(parent)) {
    if (TextControlElement* text_element =
            HTMLElement::ElementIfAutoDirectionalityFormAssociatedOrNull(
                &shadow_root->host())) {
      if (text_element->HasDirectionAuto()) {
        return true;
      }
    }
  }
  return false;
}

void Element::UpdateDescendantHasDirAutoAttribute(bool has_dir_auto) {
  if (ToHTMLSlotElementIfSupportsAssignmentOrNull(this) ||
      HTMLElement::ElementIfAutoDirectionalityFormAssociatedOrNull(this)) {
    for (Node& node : FlatTreeTraversal::ChildrenOf(*this)) {
      if (Element* element = DynamicTo<Element>(node)) {
        if (!element->IsHTMLElement() ||
            !HTMLElement::IsValidDirAttribute(
                element->FastGetAttribute(html_names::kDirAttr))) {
          if (!has_dir_auto) {
            if (!element->SelfOrAncestorHasDirAutoAttribute() ||
                element->RecalcSelfOrAncestorHasDirAuto()) {
              continue;
            }
            element->ClearSelfOrAncestorHasDirAutoAttribute();
          } else {
            if (element->SelfOrAncestorHasDirAutoAttribute()) {
              continue;
            }
            element->SetSelfOrAncestorHasDirAutoAttribute();
          }
          element->UpdateDescendantHasDirAutoAttribute(has_dir_auto);
        }
      }
    }
  } else {
    Element* element = ElementTraversal::FirstChild(*this);
    while (element) {
      if (element->IsHTMLElement()) {
        AtomicString dir_attribute_value =
            element->FastGetAttribute(html_names::kDirAttr);
        if (HTMLElement::IsValidDirAttribute(dir_attribute_value)) {
          element = ElementTraversal::NextSkippingChildren(*element, this);
          continue;
        }
      }

      if (!has_dir_auto) {
        if (!element->SelfOrAncestorHasDirAutoAttribute() ||
            element->RecalcSelfOrAncestorHasDirAuto()) {
          element = ElementTraversal::NextSkippingChildren(*element, this);
          continue;
        }
        element->ClearSelfOrAncestorHasDirAutoAttribute();
      } else {
        if (element->SelfOrAncestorHasDirAutoAttribute()) {
          element = ElementTraversal::NextSkippingChildren(*element, this);
          continue;
        }
        element->SetSelfOrAncestorHasDirAutoAttribute();
      }
      element = ElementTraversal::Next(*element, this);
    }
  }
}

std::optional<TextDirection> Element::ResolveAutoDirectionality() const {
  if (const TextControlElement* text_element =
          HTMLElement::ElementIfAutoDirectionalityFormAssociatedOrNull(this)) {
    return BidiParagraph::BaseDirectionForStringOrLtr(text_element->Value());
  }

  auto include_in_traversal = [](Element* element) -> bool {
    // Skip bdi, script, style and textarea.
    if (element->HasTagName(html_names::kBdiTag) ||
        element->HasTagName(html_names::kScriptTag) ||
        element->HasTagName(html_names::kStyleTag) ||
        element->HasTagName(html_names::kTextareaTag) ||
        element->ShadowPseudoId() ==
            shadow_element_names::kPseudoInputPlaceholder) {
      return false;
    }

    // Skip elements with valid dir attribute
    if (element->IsHTMLElement()) {
      AtomicString dir_attribute_value =
          element->FastGetAttribute(html_names::kDirAttr);
      if (HTMLElement::IsValidDirAttribute(dir_attribute_value)) {
        return false;
      }
    }
    return true;
  };

  // https://html.spec.whatwg.org/multipage/dom.html#contained-text-auto-directionality
  auto contained_text_auto_directionality =
      [&include_in_traversal](
          const Element* subtree_root) -> std::optional<TextDirection> {
    Node* node = NodeTraversal::FirstChild(*subtree_root);
    while (node) {
      if (auto* element = DynamicTo<Element>(node)) {
        if (!include_in_traversal(element)) {
          node = NodeTraversal::NextSkippingChildren(*node, subtree_root);
          continue;
        }
      }

      if (auto* slot = ToHTMLSlotElementIfSupportsAssignmentOrNull(node)) {
        if (ShadowRoot* root = slot->ContainingShadowRoot()) {
          return root->host().CachedDirectionality();
        }
      }

      if (node->IsTextNode()) {
        if (const std::optional<TextDirection> text_direction =
                BidiParagraph::BaseDirectionForString(
                    node->textContent(true))) {
          return *text_direction;
        }
      }

      node = NodeTraversal::Next(*node, subtree_root);
    }
    return std::nullopt;
  };

  // Note that the one caller of this method is overridden by HTMLSlotElement
  // in order to defer doing this until it is safe to do so.
  if (const HTMLSlotElement* slot_this =
          ToHTMLSlotElementIfSupportsAssignmentOrNull(this)) {
    auto& assigned_nodes = slot_this->AssignedNodes();
    // Use the assigned nodes if there are any.  Otherwise, the <slot>
    // represents its content and we should fall back to the regular codepath.
    if (!assigned_nodes.empty()) {
      for (Node* slotted_node : assigned_nodes) {
        if (slotted_node->IsTextNode()) {
          if (const std::optional<TextDirection> text_direction =
                  BidiParagraph::BaseDirectionForString(
                      slotted_node->textContent(true))) {
            return *text_direction;
          }
        } else if (Element* slotted_element =
                       DynamicTo<Element>(slotted_node)) {
          if (include_in_traversal(slotted_element) ||
              !RuntimeEnabledFeatures::DirAutoFixSlotExclusionsEnabled()) {
            std::optional<TextDirection> slotted_child_result =
                contained_text_auto_directionality(slotted_element);
            if (slotted_child_result) {
              return slotted_child_result;
            }
          }
        }
      }
      return std::nullopt;
    }
  }

  return contained_text_auto_directionality(this);
}

void Element::AdjustDirectionalityIfNeededAfterChildrenChanged(
    const ChildrenChange& change) {
  if (!SelfOrAncestorHasDirAutoAttribute()) {
    return;
  }

  if (change.type == ChildrenChangeType::kTextChanged) {
    CHECK(change.old_text);
    std::optional<TextDirection> old_text_direction =
        BidiParagraph::BaseDirectionForString(*change.old_text);
    auto* character_data = DynamicTo<CharacterData>(change.sibling_changed);
    DCHECK(character_data);
    std::optional<TextDirection> new_text_direction =
        BidiParagraph::BaseDirectionForString(character_data->data());
    if (old_text_direction == new_text_direction) {
      return;
    }
  } else if (change.IsChildInsertion()) {
    if (!ShouldAdjustDirectionalityForInsert(change)) {
      return;
    }
  }

  UpdateDescendantHasDirAutoAttribute(true /* has_dir_auto */);
  this->UpdateAncestorWithDirAuto(UpdateAncestorTraversal::IncludeSelf);
}

bool Element::ShouldAdjustDirectionalityForInsert(
    const ChildrenChange& change) const {
  if (change.type ==
      ChildrenChangeType::kFinishedBuildingDocumentFragmentTree) {
    for (Node& child : NodeTraversal::ChildrenOf(*this)) {
      if (!DoesChildTextNodesDirectionMatchThis(child)) {
        return true;
      }
    }
    return false;
  }
  return !DoesChildTextNodesDirectionMatchThis(*change.sibling_changed);
}

bool Element::DoesChildTextNodesDirectionMatchThis(const Node& node) const {
  if (node.IsTextNode()) {
    const std::optional<TextDirection> new_text_direction =
        BidiParagraph::BaseDirectionForString(node.textContent(true));
    if (!new_text_direction || *new_text_direction == CachedDirectionality()) {
      return true;
    }
  }
  return false;
}

void Element::UpdateAncestorWithDirAuto(UpdateAncestorTraversal traversal) {
  bool skip = traversal == UpdateAncestorTraversal::ExcludeSelf;

  for (Element* element_to_adjust = this; element_to_adjust;
       element_to_adjust = element_to_adjust->parentElement()) {
    if (!skip) {
      if (HTMLElement::ElementAffectsDirectionality(element_to_adjust)) {
        HTMLElement* html_element_to_adjust =
            To<HTMLElement>(element_to_adjust);
        if (html_element_to_adjust->HasDirectionAuto() &&
            html_element_to_adjust->CalculateAndAdjustAutoDirectionality()) {
          SetNeedsStyleRecalc(kLocalStyleChange,
                              StyleChangeReasonForTracing::Create(
                                  style_change_reason::kPseudoClass));
          element_to_adjust->PseudoStateChanged(CSSSelector::kPseudoDir);
        }
        return;
      }
      if (!element_to_adjust->SelfOrAncestorHasDirAutoAttribute()) {
        return;
      }
    }
    skip = false;
    // Directionality mostly operates on the node tree rather than the
    // flat tree.  However, a <slot>'s dir=auto is affected by its
    // assigned nodes.
    if (HTMLSlotElement* slot = element_to_adjust->AssignedSlot()) {
      if (slot->HasDirectionAuto() &&
          slot->CalculateAndAdjustAutoDirectionality()) {
        SetNeedsStyleRecalc(kLocalStyleChange,
                            StyleChangeReasonForTracing::Create(
                                style_change_reason::kPseudoClass));
        slot->PseudoStateChanged(CSSSelector::kPseudoDir);
      }
    }
    // And the values of many text form controls influence dir=auto on
    // the control.
    if (ShadowRoot* shadow_root =
            DynamicTo<ShadowRoot>(element_to_adjust->parentNode())) {
      if (TextControlElement* text_control =
              HTMLElement::ElementIfAutoDirectionalityFormAssociatedOrNull(
                  &shadow_root->host())) {
        if (text_control->HasDirectionAuto() &&
            text_control->CalculateAndAdjustAutoDirectionality()) {
          SetNeedsStyleRecalc(kLocalStyleChange,
                              StyleChangeReasonForTracing::Create(
                                  style_change_reason::kPseudoClass));
          text_control->PseudoStateChanged(CSSSelector::kPseudoDir);
        }
      }
    }
  }
}

ShadowRoot& Element::CreateAndAttachShadowRoot(ShadowRootMode type,
                                               SlotAssignmentMode mode) {
#if DCHECK_IS_ON()
  NestingLevelIncrementer slot_assignment_recalc_forbidden_scope(
      GetDocument().SlotAssignmentRecalcForbiddenRecursionDepth());
#endif
  HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
  EventDispatchForbiddenScope assert_no_event_dispatch;
  ScriptForbiddenScope forbid_script;

  DCHECK(!GetShadowRoot());

  auto* shadow_root =
      MakeGarbageCollected<ShadowRoot>(GetDocument(), type, mode);

  if (InActiveDocument()) {
    // We need to call child.RemovedFromFlatTree() before setting a shadow
    // root to the element because detach must use the original flat tree
    // structure before attachShadow happens. We cannot use
    // ParentSlotChanged() because we don't know at this point whether a
    // slot will be added and the child assigned to a slot on the next slot
    // assignment update.
    for (Node& child : NodeTraversal::ChildrenOf(*this)) {
      child.RemovedFromFlatTree();
    }
  }
  EnsureElementRareData().SetShadowRoot(*shadow_root);
  shadow_root->SetParentOrShadowHostNode(this);
  shadow_root->SetParentTreeScope(GetTreeScope());
  shadow_root->InsertedInto(*this);

  probe::DidPushShadowRoot(this, shadow_root);

  return *shadow_root;
}

ShadowRoot* Element::GetShadowRoot() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetShadowRoot();
  }
  return nullptr;
}

EditContext* Element::editContext() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetEditContext();
  }
  return nullptr;
}

void Element::setEditContext(EditContext* edit_context,
                             ExceptionState& exception_state) {
  CHECK(DynamicTo<HTMLElement>(this));

  // https://w3c.github.io/edit-context/#extensions-to-the-htmlelement-interface
  // 1. If this's local name is neither a valid shadow host name nor "canvas",
  // then throw a "NotSupportedError" DOMException.
  const AtomicString& local_name = localName();
  if (!(IsCustomElement() && CustomElement::IsValidName(local_name)) &&
      !IsValidShadowHostName(local_name) &&
      local_name != html_names::kCanvasTag) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "This element does not support EditContext");
    return;
  }

  if (edit_context && edit_context->attachedElements().size() > 0 &&
      edit_context->attachedElements()[0] != this) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "An EditContext can be only be associated with a single element");
    return;
  }

  // If an element is in focus when being attached to a new EditContext,
  // its old EditContext, if it has any, will get blurred,
  // and the new EditContext will automatically get focused.
  if (auto* old_edit_context = editContext()) {
    if (IsFocusedElementInDocument()) {
      old_edit_context->Blur();
    }

    old_edit_context->DetachElement(DynamicTo<HTMLElement>(this));
  }

  if (edit_context) {
    edit_context->AttachElement(DynamicTo<HTMLElement>(this));

    if (IsFocusedElementInDocument()) {
      edit_context->Focus();
    }
  }

  EnsureElementRareData().SetEditContext(edit_context);

  // EditContext affects the -webkit-user-modify CSS property of the element
  // (which is what Chromium uses internally to determine editability) so
  // we need to recalc styles. This is an inherited property, so we invalidate
  // the subtree rather than just the node itself.
  SetNeedsStyleRecalc(
      StyleChangeType::kSubtreeStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kEditContext));
}

struct Element::AffectedByPseudoStateChange {
  bool children_or_siblings{true};
  bool ancestors_or_siblings{true};

  AffectedByPseudoStateChange(CSSSelector::PseudoType pseudo_type,
                              Element& element) {
    switch (pseudo_type) {
      case CSSSelector::kPseudoFocus:
        children_or_siblings = element.ChildrenOrSiblingsAffectedByFocus();
        ancestors_or_siblings =
            element.AncestorsOrSiblingsAffectedByFocusInHas();
        break;
      case CSSSelector::kPseudoFocusVisible:
        children_or_siblings =
            element.ChildrenOrSiblingsAffectedByFocusVisible();
        ancestors_or_siblings =
            element.AncestorsOrSiblingsAffectedByFocusVisibleInHas();
        break;
      case CSSSelector::kPseudoFocusWithin:
        children_or_siblings =
            element.ChildrenOrSiblingsAffectedByFocusWithin();
        ancestors_or_siblings =
            element.AncestorsOrSiblingsAffectedByFocusInHas();
        break;
      case CSSSelector::kPseudoHover:
        children_or_siblings = element.ChildrenOrSiblingsAffectedByHover();
        ancestors_or_siblings =
            element.AncestorsOrSiblingsAffectedByHoverInHas();
        break;
      case CSSSelector::kPseudoActive:
        children_or_siblings = element.ChildrenOrSiblingsAffectedByActive();
        ancestors_or_siblings =
            element.AncestorsOrSiblingsAffectedByActiveInHas();
        break;
      default:
        // Activate :has() invalidation for all allowed pseudo classes.
        //
        // IsPseudoClassValidWithinHasArgument() in css_selector_parser.cc
        // maintains the disallowed pseudo classes inside :has().
        // If a :has() argument contains any of the disallowed pseudo,
        // CSSSelectorParser will drop the argument. If the argument is
        // dropped, RuleFeatureSet will not maintain the pseudo type for
        // :has() invalidation. So, StyleEngine will not do :has()
        // invalidation for the disallowed pseudo type changes even if
        // the Element::PseudoStateChanged() was called with the disallowed
        // pseudo type.
        break;
    }
  }

  AffectedByPseudoStateChange() : ancestors_or_siblings(true) {}  // For testing
};

void Element::PseudoStateChanged(CSSSelector::PseudoType pseudo) {
  PseudoStateChanged(pseudo, AffectedByPseudoStateChange(pseudo, *this));
}

void Element::PseudoStateChangedForTesting(CSSSelector::PseudoType pseudo) {
  PseudoStateChanged(pseudo, AffectedByPseudoStateChange());
}

void Element::PseudoStateChanged(
    CSSSelector::PseudoType pseudo,
    AffectedByPseudoStateChange&& affected_by_pseudo) {
  // We can't schedule invaliation sets from inside style recalc otherwise
  // we'd never process them.
  // TODO(esprehn): Make this an ASSERT and fix places that call into this
  // like HTMLSelectElement.
  Document& document = GetDocumen
"""


```