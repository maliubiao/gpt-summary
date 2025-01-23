Response:
My thinking process to analyze the provided code snippet and generate the explanation went through these stages:

1. **Decomposition of the Request:** I first broke down the request into its key components:
    * Analyze the functionality of `blink/renderer/core/css/style_engine.cc`.
    * Explain its relationship with JavaScript, HTML, and CSS.
    * Provide examples of these relationships.
    * Offer hypothetical input/output scenarios for logical reasoning.
    * Detail common user/programming errors related to this code.
    * Explain how a user action could lead to this code execution.
    * Summarize the functionality of *this specific snippet* (part 5 of 6).

2. **Initial Code Scan and Keyword Identification:** I scanned the provided code snippet for key terms and patterns:
    * `containerChanged`: This immediately suggested a focus on CSS container queries.
    * `ContainerQueryData`, `ContainerQueryEvaluator`: Reinforces the container query theme.
    * `RecalcStyleForContainer`, `ReattachContainerSubtree`, `RebuildLayoutTree`: Indicate style recalculation and layout tree manipulation.
    * `::first-line`: Points to interaction with CSS pseudo-elements.
    * `NeedsReattachLayoutTree`, `NeedsLayoutTreeRebuild`: Flags indicating the necessity of layout updates.
    * `GetStyleContainmentScopeTree`, `UpdateQuotes`: Hints at features related to CSS containment.
    * `GetDocument().documentElement()`: Indicates operations at the document level.
    * `GetStyleResolver().PropagateStyleToViewport()`: Suggests propagating styles to the viewport.
    * `UpdateStyleForOutOfFlow`: Focuses on handling absolutely positioned elements or similar.
    * `StyleRecalcContext`:  A central structure for managing style recalculation.
    * `RecalcStyle`, `RecalcPositionTryStyleForPseudoElement`: Core functions for style calculation.
    * `ScriptForbiddenScope`, `SkipStyleRecalcScope`: Indicate optimization strategies and restrictions.
    * `RecalcTransitionPseudoStyle`: Handles animations and transitions.
    * `ClearEnsuredDescendantStyles`: Relates to performance and invalidation.
    * `RebuildLayoutTreeForTraversalRootAncestors`: Deals with updating the layout tree of parent elements.

3. **Focusing on the Snippet's Core Functionality:**  Given the "part 5 of 6" context, I recognized this section likely deals with specific aspects of the `StyleEngine`. The prevalence of `containerChanged` and related logic strongly indicated this part focuses on **handling changes related to CSS container queries**. The presence of `UpdateStyleForOutOfFlow` also suggested the section covers how the style engine deals with elements that don't follow the normal document flow.

4. **Inferring Relationships with JavaScript, HTML, and CSS:** Based on the identified keywords and functionality, I deduced the connections:
    * **CSS:** The core functionality revolves around interpreting and applying CSS rules, especially container queries, pseudo-elements (`::first-line`), and potentially CSS containment.
    * **HTML:** The code interacts with HTML elements (`Element`, `HTMLBodyElement`, `HTMLHtmlElement`), manipulates the document tree, and considers shadow DOM (`IsShadowHost`).
    * **JavaScript:** While not directly evident in *this* snippet, I know the `StyleEngine` is triggered by DOM manipulations and CSS changes often initiated by JavaScript. I included this indirect relationship in my explanation.

5. **Constructing Examples:**  For each relationship (JavaScript, HTML, CSS), I created concrete examples illustrating how the `StyleEngine` would be involved. For instance, showing how changing a container's size via JavaScript triggers `containerChanged`, or how different HTML structures (with and without shadow DOM) impact container query evaluation.

6. **Developing Hypothetical Input/Output:** For the `containerChanged` function, I created a simple scenario: changing the width of a container element. I described the expected input (element and its new size) and the likely output (triggering style recalculation and potentially layout changes).

7. **Identifying Common Errors:** I thought about common mistakes developers might make when working with container queries and related features: incorrect syntax, assuming immediate updates, and not understanding shadow DOM boundaries.

8. **Tracing User Actions:** I outlined the steps a user might take that would eventually lead to the execution of the `containerChanged` function. This involves interacting with the webpage in a way that triggers a change in a container element's dimensions.

9. **Summarizing the Snippet:** Based on my analysis, I summarized the core functions of this specific part of `style_engine.cc`: handling container query changes, dealing with `::first-line` pseudo-elements in containers, managing out-of-flow elements, and providing utility functions for style recalculation.

10. **Review and Refinement:** Finally, I reviewed my explanation to ensure clarity, accuracy, and completeness, addressing all aspects of the original request. I made sure the examples were easy to understand and the overall explanation flowed logically. I particularly emphasized the container query handling as the dominant theme of the provided snippet.
好的，让我们分析一下 `blink/renderer/core/css/style_engine.cc` 文件的这段代码片段的功能。

**这段代码片段的功能归纳：**

这段代码主要负责处理 **CSS 容器查询（Container Queries）** 相关的样式更新和布局调整，以及处理 **脱离文档流（Out-of-flow）元素** 的样式计算。它还包含一些辅助性的样式重计算和布局重建的逻辑。

**更细致的功能拆解：**

1. **`containerChanged` 函数:**
   - **核心功能:**  当一个元素的容器的尺寸或包含轴发生变化时被调用，以触发必要的样式重计算和布局更新。这是容器查询功能的核心入口点。
   - **容器查询变化类型处理:**  根据 `query_change` 的不同值（`kNone`, `kNearestContainer`, `kDescendantContainers`）采取不同的处理策略：
     - `kNone`:  如果容器查询结果没有变化，但之前跳过了样式重计算，则返回。
     - `kNearestContainer`:  如果最近的容器发生变化，则强制重算容器的尺寸。对于非 Shadow Host 容器或启用了 Flat Tree Container 的情况，直接标记为需要重算尺寸。对于 Shadow Host 容器，会“fallthrough”到 `kDescendantContainers` 的逻辑。
     - `kDescendantContainers`:  强制重算所有子代容器的尺寸。
   - **处理 `::first-line` 伪元素:**  当容器查询发生变化时，需要特别处理依赖于尺寸容器查询的 `::first-line` 伪元素。由于样式计算和布局的顺序问题，以及缓存机制，直接的样式差异可能无法检测到 `::first-line` 的变化。因此，如果存在这样的 `::first-line` 规则，则强制标记容器需要重新依附布局树。
   - **样式清理和重计算:** 清除容器的缓存伪元素样式，并调用 `RecalcStyleForContainer` 进行样式重计算。
   - **布局更新:**  根据容器的状态（是否需要重新依附布局树）和全局的布局状态，决定是否调用 `ReattachContainerSubtree` 或 `RebuildLayoutTree` 来更新布局。
   - **引号更新:** 如果存在样式包含范围树，则更新引号。
   - **根元素特殊处理:** 如果容器是根元素（`<html>`），则可能需要将 body 元素的样式传播到视口。
   - **计数器更新和 SVG 资源失效:**  更新文档的布局视图的计数器，并使待处理的 SVG 资源失效。

2. **`UpdateStyleForOutOfFlow` 函数:**
   - **核心功能:**  处理脱离文档流的元素（例如，`position: absolute` 或 `position: fixed` 的元素）的样式更新。
   - **尝试样式集和策略列表:** 接收可选的 `try_set` 和 `tactic_list` 参数，用于尝试不同的样式值，这可能与 CSS Houdini 的属性或布局 API 相关。
   - **上下文设置:**  创建一个 `StyleRecalcContext`，包含祖先信息、是否为交错的脱离文档流元素、锚点评估器以及尝试的样式集。
   - **强制子元素重算:**  标记需要重算子元素的样式。
   - **伪元素和普通元素处理:**  根据元素类型调用 `RecalcPositionTryStyleForPseudoElement` 或 `RecalcStyle` 进行样式重计算。

3. **`GetPositionTryRule` 函数:**
   - **核心功能:**  根据作用域 CSS 名称获取位置尝试规则（Position Try Rule）。这可能与 CSS 锚定定位（CSS Anchor Positioning）特性有关。

4. **`RecalcStyle` 函数:**
   - **核心功能:**  执行样式重计算的核心逻辑。
   - **禁止脚本和跳过重计算作用域:**  使用 `ScriptForbiddenScope` 和 `SkipStyleRecalcScope` 来确保样式重计算过程中的安全性并优化性能。
   - **选择器过滤:**  使用 `SelectorFilterRootScope` 来优化选择器匹配。
   - **递归样式重计算:**  调用元素的 `RecalcStyle` 方法进行递归的样式计算。
   - **祖先元素处理:**  遍历需要样式重算的元素的祖先，调用 `RecalcStyleForTraversalRootAncestor` 并清除 `ChildNeedsStyleRecalc` 标记。
   - **HTML 根元素处理:**  如果重算的是 `<body>` 元素或其父元素为空，则将书写模式和方向传播到 `<html>` 根元素。

5. **`RecalcPositionTryStyleForPseudoElement` 函数:**
   - **核心功能:**  专门用于重计算伪元素的位置尝试样式。

6. **`RecalcTransitionPseudoStyle` 函数:**
   - **核心功能:**  重计算过渡相关的伪元素样式，可能用于实现视图过渡效果。

7. **`RecalcStyle()` 函数 (无参数):**
   - **核心功能:**  触发完整的样式重计算，包括普通元素和过渡相关的伪元素。

8. **`ClearEnsuredDescendantStyles` 函数:**
   - **核心功能:**  清除指定根元素下所有后代元素的已确保的样式（`EnsuredStyle`）。这可能用于优化性能，清理不再需要的样式信息。

9. **`RebuildLayoutTreeForTraversalRootAncestors` 函数:**
   - **核心功能:**  为遍历根的祖先元素重建布局树。这通常在容器查询相关的布局更新中使用。

10. **`RebuildLayoutTree` 函数:**
    - **核心功能:**  重建布局树的核心入口。
    - **防止递归:** 使用 `in_layout_tree_rebuild_` 标记防止无限递归。
    - **选择器过滤:** 应用选择器过滤。
    - **调用元素方法:** 调用元素的 `RebuildLayoutTree` 方法执行实际的布局树重建。
    - **处理祖先:** 调用 `RebuildLayoutTreeForTraversalRootAncestors` 处理祖先元素的布局。
    - **过渡伪元素:** 如果不是因容器查询触发，则重建过渡伪元素的布局树。
    - **传播书写模式:** 如果根元素是 `<html>` 或 `<body>`，则传播书写模式和方向。

11. **`ReattachContainerSubtree` 函数:**
    - **核心功能:**  重新依附容器的子树到布局树。这通常在容器查询导致布局变化时使用，比完全重建布局树更高效。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  这段代码的核心职责是处理 CSS 样式。
    * **容器查询:** `containerChanged` 函数直接响应 CSS 容器尺寸或包含轴的变化。例如，当 CSS 中定义了 `@container` 规则，并且容器的尺寸发生变化时，浏览器会调用这个函数来更新受影响元素的样式。
    * **伪元素:** 代码中明确处理了 `::first-line` 伪元素在容器查询变化时的特殊情况。例如，如果一个容器设置了依赖容器尺寸的 `::first-line` 样式，当容器宽度变化时，这段代码会确保 `::first-line` 的样式得到正确更新。
    * **脱离文档流元素:** `UpdateStyleForOutOfFlow` 处理 `position: absolute` 或 `position: fixed` 元素的样式计算，这些元素的布局不影响正常的文档流。
    * **CSS 属性和值:** 代码间接处理了各种 CSS 属性和值，例如尺寸相关的属性（`width`, `height`），以及与布局相关的属性。

* **HTML:**  这段代码操作 HTML 元素及其树结构。
    * **元素类型:** 代码中使用了 `Element`, `HTMLBodyElement`, `HTMLHtmlElement`, `PseudoElement` 等类型，表明它与 HTML 元素及其特性紧密相关。
    * **DOM 树遍历:** 代码中使用了 `FlatTreeTraversal` 等方法来遍历 DOM 树，查找父元素、子元素等。
    * **Shadow DOM:** 代码考虑了 Shadow Host 的情况，表明它需要处理包含 Shadow DOM 的复杂 HTML 结构。

* **JavaScript:**  虽然这段代码是 C++ 实现的，但它与 JavaScript 的交互非常频繁。
    * **JavaScript 触发样式变化:** JavaScript 可以通过修改元素的样式属性或类名来触发样式变化，进而间接触发 `containerChanged` 或 `UpdateStyleForOutOfFlow` 等函数。例如，一个 JavaScript 脚本修改了一个容器元素的 `width` 属性，就会导致 `containerChanged` 被调用。
    * **JavaScript 与布局交互:** JavaScript 可以读取元素的布局信息（例如，使用 `getBoundingClientRect()`），而这些信息的准确性依赖于 `StyleEngine` 正确地计算和应用样式。
    * **CSSOM:** JavaScript 可以操作 CSSOM（CSS Object Model），修改样式规则，这些修改最终会由 `StyleEngine` 来处理和应用。

**逻辑推理的假设输入与输出示例 (`containerChanged` 函数):**

**假设输入：**

* `container`:  一个 `<div>` 元素，其 CSS 中定义了 `@container` 规则。
* `physical_size`:  一个表示容器新尺寸的 `LayoutSize` 对象，例如 `{ width: 500px, height: 300px }`。
* `physical_axes`: 一个表示尺寸变化的轴的枚举值，例如 `kHorizontal`.
* `query_change`: `ContainerQueryEvaluator::Change::kNearestContainer`，表示最近的容器发生了变化。

**预期输出：**

1. `cq_data->SkippedStyleRecalc()` 返回 `false` (假设没有跳过重计算)。
2. 进入 `case ContainerQueryEvaluator::Change::kNearestContainer:` 分支。
3. `change` 被修改为 `change.ForceRecalcSizeContainer()`，标记需要重算容器尺寸。
4. 清除容器的缓存伪元素样式 (`style.ClearCachedPseudoElementStyles()`).
5. 调用 `RecalcStyleForContainer(container, change)`，触发容器的样式重计算。
6. 根据容器和全局布局状态，可能调用 `ReattachContainerSubtree` 或 `RebuildLayoutTree` 来更新布局。

**用户或编程常见的使用错误举例说明：**

* **错误地假设容器查询立即生效：**  开发者可能会在 JavaScript 中修改容器尺寸后，立即读取依赖容器查询的元素的样式，但此时样式可能尚未更新。正确的做法是等待渲染更新，或者使用 `requestAnimationFrame`。
* **在 Shadow DOM 边界上理解容器查询的范围：**  开发者可能没有意识到容器查询的范围受到 Shadow DOM 的影响。最近的容器是在包含 Shadow DOM 的祖先链上查找的，而不是在扁平树上。这可能导致意外的样式应用或不应用。
* **忘记处理 `::first-line` 伪元素的特殊性：**  如果 `::first-line` 的样式依赖于容器查询，开发者可能会遇到样式更新不及时的问题，因为标准的样式差异检测可能无法捕捉到变化。了解需要强制重新依附布局树是重要的。
* **过度使用容器查询导致性能问题：**  如果页面上有大量的容器和复杂的容器查询规则，频繁的容器尺寸变化可能会导致大量的样式重计算和布局更新，影响页面性能。开发者需要谨慎设计容器查询规则。

**用户操作如何一步步到达这里 (以 `containerChanged` 为例)：**

1. **用户加载包含容器查询的网页:**  用户在浏览器中打开一个网页，该网页的 CSS 中定义了使用 `@container` 的规则。
2. **用户与页面交互导致容器尺寸变化:** 用户执行某些操作，例如：
   * **调整浏览器窗口大小:** 这会影响视口大小，进而可能影响容器的尺寸。
   * **拖动页面上的元素:**  拖动操作可能改变某些容器的尺寸。
   * **执行 JavaScript 脚本:**  网页上的 JavaScript 代码可能会修改容器元素的 `width`、`height` 等样式属性，或者修改影响容器尺寸的其他元素的样式。
3. **布局引擎检测到容器尺寸变化:** Chromium 的布局引擎（LayoutNG 或 Blink 的旧布局引擎）会检测到容器元素的尺寸发生了变化。
4. **触发 `StyleEngine::containerChanged`:**  布局引擎会通知 `StyleEngine`，并调用 `containerChanged` 函数，将发生变化的容器元素、新的尺寸和变化的轴等信息传递给它。
5. **`containerChanged` 执行后续的样式重计算和布局更新。**

**作为调试线索：**

当开发者遇到与容器查询相关的样式问题时，理解 `containerChanged` 函数的执行流程可以作为重要的调试线索：

* **断点调试:** 可以在 `containerChanged` 函数内部设置断点，查看容器元素、新的尺寸、查询变化类型等信息，以确认容器尺寸变化是否被正确检测到。
* **日志输出:**  可以添加日志输出语句，记录 `containerChanged` 的调用时机和参数，帮助理解容器查询的触发条件。
* **Performance 面板:** 使用 Chrome DevTools 的 Performance 面板，可以分析样式重计算和布局更新的耗时，了解容器查询是否导致了性能瓶颈。
* **理解 Shadow DOM 的边界:**  在涉及 Shadow DOM 的场景中，需要仔细检查容器查询的范围是否符合预期，避免跨越 Shadow DOM 边界的错误假设。

希望以上分析能够帮助你理解这段 `blink/renderer/core/css/style_engine.cc` 代码片段的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
tainerChanged(
          physical_size, physical_axes);

  ContainerQueryData* cq_data = container.GetContainerQueryData();
  CHECK(cq_data);

  switch (query_change) {
    case ContainerQueryEvaluator::Change::kNone:
      if (!cq_data->SkippedStyleRecalc()) {
        return;
      }
      break;
    case ContainerQueryEvaluator::Change::kNearestContainer:
      if (RuntimeEnabledFeatures::CSSFlatTreeContainerEnabled() ||
          !IsShadowHost(container)) {
        change = change.ForceRecalcSizeContainer();
        break;
      }
      // Since the nearest container is found in shadow-including ancestors and
      // not in flat tree ancestors, and style recalc traversal happens in flat
      // tree order, we need to invalidate inside flat tree descendant
      // containers if such containers are inside shadow trees.
      //
      // See also StyleRecalcChange::FlagsForChildren where we turn
      // kRecalcContainer into kRecalcDescendantContainers when traversing past
      // a shadow host.
      [[fallthrough]];
    case ContainerQueryEvaluator::Change::kDescendantContainers:
      change = change.ForceRecalcDescendantSizeContainers();
      break;
  }

  if (query_change != ContainerQueryEvaluator::Change::kNone) {
    style.ClearCachedPseudoElementStyles();
    // When the container query changes, the ::first-line matching the container
    // itself is not detected as changed. Firstly, because the style for the
    // container is computed before the layout causing the ::first-line styles
    // to change. Also, we mark the ComputedStyle with HasPseudoElementStyle()
    // for kPseudoIdFirstLine, even when the container query for the
    // ::first-line rules doesn't match, which means a diff for that flag would
    // not detect a change. Instead, if a container has ::first-line rules which
    // depends on size container queries, fall back to re-attaching its box tree
    // when any of the size queries change the evaluation result.
    if (style.HasPseudoElementStyle(kPseudoIdFirstLine) &&
        style.FirstLineDependsOnSizeContainerQueries()) {
      change = change.ForceMarkReattachLayoutTree().ForceReattachLayoutTree();
    }
  }

  NthIndexCache nth_index_cache(GetDocument());

  UpdateViewportSize();
  RecalcStyleForContainer(container, change);

  if (container.NeedsReattachLayoutTree()) {
    ReattachContainerSubtree(container);
  } else if (NeedsLayoutTreeRebuild()) {
    if (layout_tree_rebuild_root_.GetRootNode()->IsDocumentNode()) {
      // Avoid traversing from outside the container root. We know none of the
      // elements outside the subtree should be marked dirty in this pass, but
      // we may have fallen back to the document root.
      layout_tree_rebuild_root_.Clear();
      layout_tree_rebuild_root_.Update(nullptr, &container);
    } else {
      DCHECK(FlatTreeTraversal::ContainsIncludingPseudoElement(
          container, *layout_tree_rebuild_root_.GetRootNode()));
    }
    RebuildLayoutTree(&container);
  }

  // Update quotes only if there are any scopes marked dirty.
  if (StyleContainmentScopeTree* tree = GetStyleContainmentScopeTree()) {
    tree->UpdateQuotes();
  }
  if (container == GetDocument().documentElement()) {
    // If the container is the root element, there may be body styles which have
    // changed as a result of the new container query evaluation, and if
    // properties propagated from body changed, we need to update the viewport
    // styles.
    GetStyleResolver().PropagateStyleToViewport();
  }
  GetDocument().GetLayoutView()->UpdateCountersAfterStyleChange(
      container.GetLayoutObject());
  GetDocument().InvalidatePendingSVGResources();
}

void StyleEngine::UpdateStyleForOutOfFlow(Element& element,
                                          const CSSPropertyValueSet* try_set,
                                          const TryTacticList& tactic_list,
                                          AnchorEvaluator* anchor_evaluator) {
  const CSSPropertyValueSet* try_tactics_set =
      try_value_flips_.FlipSet(tactic_list);

  base::AutoReset<bool> pt_recalc(&in_position_try_style_recalc_, true);

  UpdateViewportSize();

  StyleRecalcContext style_recalc_context =
      StyleRecalcContext::FromAncestors(element);
  style_recalc_context.is_interleaved_oof = true;
  style_recalc_context.anchor_evaluator = anchor_evaluator;
  style_recalc_context.try_set = try_set;
  style_recalc_context.try_tactics_set = try_tactics_set;

  StyleRecalcChange change = StyleRecalcChange().ForceRecalcChildren();

  if (auto* pseudo_element = DynamicTo<PseudoElement>(element)) {
    RecalcPositionTryStyleForPseudoElement(*pseudo_element, change,
                                           style_recalc_context);
  } else {
    element.SetChildNeedsStyleRecalc();
    style_recalc_root_.Update(nullptr, &element);
    RecalcStyle(change, style_recalc_context);
  }
}

StyleRulePositionTry* StyleEngine::GetPositionTryRule(
    const ScopedCSSName& scoped_name) {
  const TreeScope* tree_scope = scoped_name.GetTreeScope();
  if (!tree_scope) {
    tree_scope = &GetDocument();
  }
  return GetStyleResolver().ResolvePositionTryRule(tree_scope,
                                                   scoped_name.GetName());
}

void StyleEngine::RecalcStyle(StyleRecalcChange change,
                              const StyleRecalcContext& style_recalc_context) {
  DCHECK(GetDocument().documentElement());
  ScriptForbiddenScope forbid_script;
  SkipStyleRecalcScope skip_scope(*this);
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &GetDocument(), /*within_selector_checking=*/false);
  Element& root_element = style_recalc_root_.RootElement();
  Element* parent = FlatTreeTraversal::ParentElement(root_element);

  SelectorFilterRootScope filter_scope(parent);
  root_element.RecalcStyle(change, style_recalc_context);

  for (ContainerNode* ancestor = root_element.GetStyleRecalcParent(); ancestor;
       ancestor = ancestor->GetStyleRecalcParent()) {
    if (auto* ancestor_element = DynamicTo<Element>(ancestor)) {
      ancestor_element->RecalcStyleForTraversalRootAncestor();
    }
    ancestor->ClearChildNeedsStyleRecalc();
  }
  style_recalc_root_.Clear();
  if (!parent || IsA<HTMLBodyElement>(root_element)) {
    PropagateWritingModeAndDirectionToHTMLRoot();
  }
}

void StyleEngine::RecalcPositionTryStyleForPseudoElement(
    PseudoElement& pseudo_element,
    const StyleRecalcChange style_recalc_change,
    const StyleRecalcContext& style_recalc_context) {
  ScriptForbiddenScope forbid_script;
  SkipStyleRecalcScope skip_scope(*this);
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &GetDocument(), /*within-selector_checking=*/false);
  SelectorFilterRootScope filter_scope(FlatTreeTraversal::ParentElement(
      *pseudo_element.UltimateOriginatingElement()));
  pseudo_element.RecalcStyle(style_recalc_change, style_recalc_context);
}

void StyleEngine::RecalcTransitionPseudoStyle() {
  // TODO(khushalsagar) : This forces a style recalc and layout tree rebuild
  // for the pseudo element tree each time we do a style recalc phase. See if
  // we can optimize this to only when the pseudo element tree is dirtied.
  SelectorFilterRootScope filter_scope(nullptr);
  document_->documentElement()->RecalcTransitionPseudoTreeStyle(
      view_transition_names_);
}

void StyleEngine::RecalcStyle() {
  RecalcStyle(
      {}, StyleRecalcContext::FromAncestors(style_recalc_root_.RootElement()));
  RecalcTransitionPseudoStyle();
}

void StyleEngine::ClearEnsuredDescendantStyles(Element& root) {
  Node* current = &root;
  while (current) {
    if (auto* element = DynamicTo<Element>(current)) {
      if (const auto* style = element->GetComputedStyle()) {
        DCHECK(style->IsEnsuredOutsideFlatTree());
        element->SetComputedStyle(nullptr);
        element->ClearNeedsStyleRecalc();
        element->ClearChildNeedsStyleRecalc();
        current = FlatTreeTraversal::Next(*current, &root);
        continue;
      }
    }
    current = FlatTreeTraversal::NextSkippingChildren(*current, &root);
  }
}

void StyleEngine::RebuildLayoutTreeForTraversalRootAncestors(
    Element* parent,
    Element* container_parent) {
  bool is_container_ancestor = false;

  for (auto* ancestor = parent; ancestor;
       ancestor = ancestor->GetReattachParent()) {
    if (ancestor == container_parent) {
      is_container_ancestor = true;
    }
    if (is_container_ancestor) {
      ancestor->RebuildLayoutTreeForSizeContainerAncestor();
    } else {
      ancestor->RebuildLayoutTreeForTraversalRootAncestor();
    }
    ancestor->ClearChildNeedsStyleRecalc();
    ancestor->ClearChildNeedsReattachLayoutTree();
  }
}

void StyleEngine::RebuildLayoutTree(Element* size_container) {
  bool propagate_to_root = false;
  {
    DCHECK(GetDocument().documentElement());
    DCHECK(!InRebuildLayoutTree());
    base::AutoReset<bool> rebuild_scope(&in_layout_tree_rebuild_, true);

    // We need a root scope here in case we recalc style for ::first-letter
    // elements as part of UpdateFirstLetterPseudoElement.
    SelectorFilterRootScope filter_scope(nullptr);

    Element& root_element = layout_tree_rebuild_root_.RootElement();
    {
      WhitespaceAttacher whitespace_attacher;
      root_element.RebuildLayoutTree(whitespace_attacher);
    }

    Element* container_parent =
        size_container ? size_container->GetReattachParent() : nullptr;
    RebuildLayoutTreeForTraversalRootAncestors(root_element.GetReattachParent(),
                                               container_parent);
    if (size_container == nullptr) {
      document_->documentElement()->RebuildTransitionPseudoLayoutTree(
          view_transition_names_);
    }
    layout_tree_rebuild_root_.Clear();
    propagate_to_root = IsA<HTMLHtmlElement>(root_element) ||
                        IsA<HTMLBodyElement>(root_element);
  }
  if (propagate_to_root) {
    PropagateWritingModeAndDirectionToHTMLRoot();
    if (NeedsLayoutTreeRebuild()) {
      RebuildLayoutTree(size_container);
    }
  }
}

void StyleEngine::ReattachContainerSubtree(Element& container) {
  // Generally, the container itself should not be marked for re-attachment. In
  // the case where we have a fieldset as a container, the fieldset itself is
  // marked for re-attachment in HTMLFieldSetElement::DidRecalcStyle to make
  // sure the rendered legend is appropriately placed in the layout tree. We
  // cannot re-attach the fieldset itself in this case since we are in the
  // process of laying it out. Instead we re-attach all children, which should
  // be sufficient.

  DCHECK(container.NeedsReattachLayoutTree());
  DCHECK(CountersChanged() || DynamicTo<HTMLFieldSetElement>(container));

  base::AutoReset<bool> rebuild_scope(&in_layout_tree_rebuild_, true);
  container.ReattachLayoutTreeChildren(base::PassKey<StyleEngine>());
  RebuildLayoutTreeForTraversalRootAncestors(&container,
                                             container.GetReattachParent());
  layout_tree_rebuild_root_.Clear();
}

void StyleEngine::UpdateStyleAndLayoutTree() {
  // All of layout tree dirtiness and rebuilding needs to happen on a stable
  // flat tree. We have an invariant that all of that happens in this method
  // as a result of style recalc and the following layout tree rebuild.
  //
  // NeedsReattachLayoutTree() marks dirty up the flat tree ancestors. Re-
  // slotting on a dirty tree could break ancestor chains and fail to update the
  // tree properly.
  DCHECK(!NeedsLayoutTreeRebuild());

  UpdateViewportStyle();

  if (GetDocument().documentElement()) {
    UpdateViewportSize();
    NthIndexCache nth_index_cache(GetDocument());
    if (NeedsStyleRecalc()) {
      TRACE_EVENT0("blink,blink_style", "Document::recalcStyle");
      SCOPED_BLINK_UMA_HISTOGRAM_TIMER_HIGHRES("Style.RecalcTime");
      Element* viewport_defining = GetDocument().ViewportDefiningElement();
      RecalcStyle();
      if (viewport_defining != GetDocument().ViewportDefiningElement()) {
        ViewportDefiningElementDidChange();
      }
    }
    if (NeedsLayoutTreeRebuild()) {
      TRACE_EVENT0("blink,blink_style", "Document::rebuildLayoutTree");
      SCOPED_BLINK_UMA_HISTOGRAM_TIMER_HIGHRES("Style.RebuildLayoutTreeTime");
      RebuildLayoutTree();
    }
    // Update quotes only if there are any scopes marked dirty.
    if (StyleContainmentScopeTree* tree = GetStyleContainmentScopeTree()) {
      tree->UpdateQuotes();
    }
    UpdateCounters();
  } else {
    style_recalc_root_.Clear();
  }
  UpdateColorSchemeBackground();
  GetStyleResolver().PropagateStyleToViewport();
}

void StyleEngine::ViewportDefiningElementDidChange() {
  // Guarded by if-test in UpdateStyleAndLayoutTree().
  DCHECK(GetDocument().documentElement());

  // No need to update a layout object which will be destroyed.
  if (GetDocument().documentElement()->NeedsReattachLayoutTree()) {
    return;
  }
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  if (!body || body->NeedsReattachLayoutTree()) {
    return;
  }

  LayoutObject* layout_object = body->GetLayoutObject();
  if (layout_object && layout_object->IsLayoutBlock()) {
    // When the overflow style for documentElement changes to or from visible,
    // it changes whether the body element's box should have scrollable overflow
    // on its own box or propagated to the viewport. If the body style did not
    // need a recalc, this will not be updated as its done as part of setting
    // ComputedStyle on the LayoutObject. Force a SetStyle for body when the
    // ViewportDefiningElement changes in order to trigger an update of
    // IsScrollContainer() and the PaintLayer in StyleDidChange().
    //
    // This update is also necessary if the first body element changes because
    // another body element is inserted or removed.
    layout_object->SetStyle(
        ComputedStyleBuilder(*layout_object->Style()).TakeStyle());
  }
}

void StyleEngine::FirstBodyElementChanged(HTMLBodyElement* body) {
  // If a body element changed status as being the first body element or not,
  // it might have changed its needs for scrollbars even if the style didn't
  // change. Marking it for recalc here will make sure a new ComputedStyle is
  // set on the layout object for the next style recalc, and the scrollbars will
  // be updated in LayoutObject::SetStyle(). SetStyle cannot be called here
  // directly because SetStyle() relies on style information to be up-to-date,
  // otherwise scrollbar style update might crash.
  //
  // If the body parameter is null, it means the last body is removed. Removing
  // an element does not cause a style recalc on its own, which means we need
  // to force an update of the documentElement to remove used writing-mode and
  // direction which was previously propagated from the removed body element.
  Element* dirty_element = body ? body : GetDocument().documentElement();
  DCHECK(dirty_element);
  if (body) {
    LayoutObject* layout_object = body->GetLayoutObject();
    if (!layout_object || !layout_object->IsLayoutBlock()) {
      return;
    }
  }
  dirty_element->SetNeedsStyleRecalc(
      kLocalStyleChange, StyleChangeReasonForTracing::Create(
                             style_change_reason::kViewportDefiningElement));
}

void StyleEngine::UpdateStyleInvalidationRoot(ContainerNode* ancestor,
                                              Node* dirty_node) {
  if (GetDocument().IsActive()) {
    if (InDOMRemoval()) {
      ancestor = nullptr;
      dirty_node = document_;
    }
    style_invalidation_root_.Update(ancestor, dirty_node);
  }
}

void StyleEngine::UpdateStyleRecalcRoot(ContainerNode* ancestor,
                                        Node* dirty_node) {
  if (!GetDocument().IsActive()) {
    return;
  }
  // We have at least one instance where we mark style dirty from style recalc
  // (from LayoutTextControl::StyleDidChange()). That means we are in the
  // process of traversing down the tree from the recalc root. Any updates to
  // the style recalc root will be cleared after the style recalc traversal
  // finishes and updating it may just trigger sanity DCHECKs in
  // StyleTraversalRoot. Just return here instead.
  if (GetDocument().InStyleRecalc()) {
    DCHECK(allow_mark_style_dirty_from_recalc_);
    return;
  }
  DCHECK(!InRebuildLayoutTree());
  if (InDOMRemoval()) {
    ancestor = nullptr;
    dirty_node = document_;
  }
#if DCHECK_IS_ON()
  DCHECK(!dirty_node || DisplayLockUtilities::AssertStyleAllowed(*dirty_node));
#endif
  style_recalc_root_.Update(ancestor, dirty_node);
}

void StyleEngine::UpdateLayoutTreeRebuildRoot(ContainerNode* ancestor,
                                              Node* dirty_node) {
  DCHECK(!InDOMRemoval());
  if (!GetDocument().IsActive()) {
    return;
  }
  if (InRebuildLayoutTree()) {
    DCHECK(allow_mark_for_reattach_from_rebuild_layout_tree_);
    return;
  }
#if DCHECK_IS_ON()
  DCHECK(GetDocument().InStyleRecalc());
  DCHECK(dirty_node);
  DCHECK(DisplayLockUtilities::AssertStyleAllowed(*dirty_node));
#endif
  layout_tree_rebuild_root_.Update(ancestor, dirty_node);
}

namespace {

Node* AnalysisParent(const Node& node) {
  return IsA<ShadowRoot>(node) ? node.ParentOrShadowHostElement()
                               : LayoutTreeBuilderTraversal::Parent(node);
}

bool IsRootOrSibling(const Node* root, const Node& node) {
  if (!root) {
    return false;
  }
  if (root == &node) {
    return true;
  }
  if (Node* root_parent = AnalysisParent(*root)) {
    return root_parent == AnalysisParent(node);
  }
  return false;
}

}  // namespace

StyleEngine::AncestorAnalysis StyleEngine::AnalyzeInclusiveAncestor(
    const Node& node) {
  if (IsRootOrSibling(style_recalc_root_.GetRootNode(), node)) {
    return AncestorAnalysis::kStyleRoot;
  }
  if (IsRootOrSibling(style_invalidation_root_.GetRootNode(), node)) {
    return AncestorAnalysis::kStyleRoot;
  }
  if (auto* element = DynamicTo<Element>(node)) {
    if (ComputedStyle::IsInterleavingRoot(element->GetComputedStyle())) {
      return AncestorAnalysis::kInterleavingRoot;
    }
  }
  return AncestorAnalysis::kNone;
}

StyleEngine::AncestorAnalysis StyleEngine::AnalyzeExclusiveAncestor(
    const Node& node) {
  if (DisplayLockUtilities::IsPotentialStyleRecalcRoot(node)) {
    return AncestorAnalysis::kStyleRoot;
  }
  return AnalyzeInclusiveAncestor(node);
}

StyleEngine::AncestorAnalysis StyleEngine::AnalyzeAncestors(const Node& node) {
  AncestorAnalysis analysis = AnalyzeInclusiveAncestor(node);

  for (const Node* ancestor = LayoutTreeBuilderTraversal::Parent(node);
       ancestor; ancestor = LayoutTreeBuilderTraversal::Parent(*ancestor)) {
    // Already at maximum severity, no need to proceed.
    if (analysis == AncestorAnalysis::kStyleRoot) {
      return analysis;
    }

    // LayoutTreeBuilderTraversal::Parent skips ShadowRoots, so we check it
    // explicitly here.
    if (ShadowRoot* root = ancestor->GetShadowRoot()) {
      analysis = std::max(analysis, AnalyzeExclusiveAncestor(*root));
    }

    analysis = std::max(analysis, AnalyzeExclusiveAncestor(*ancestor));
  }

  return analysis;
}

bool StyleEngine::MarkReattachAllowed() const {
  return !InRebuildLayoutTree() ||
         allow_mark_for_reattach_from_rebuild_layout_tree_;
}

bool StyleEngine::MarkStyleDirtyAllowed() const {
  if (GetDocument().InStyleRecalc() || InContainerQueryStyleRecalc()) {
    return allow_mark_style_dirty_from_recalc_;
  }
  return !InRebuildLayoutTree();
}

bool StyleEngine::SupportsDarkColorScheme() {
  return (page_color_schemes_ &
          static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark)) &&
         (!(page_color_schemes_ &
            static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight)) ||
          preferred_color_scheme_ == mojom::blink::PreferredColorScheme::kDark);
}

void StyleEngine::UpdateColorScheme() {
  const Settings* settings = GetDocument().GetSettings();
  if (!settings) {
    return;
  }

  ForcedColors old_forced_colors = forced_colors_;
  forced_colors_ = settings->GetInForcedColors() ? ForcedColors::kActive
                                                 : ForcedColors::kNone;

  mojom::blink::PreferredColorScheme old_preferred_color_scheme =
      preferred_color_scheme_;
  if (GetDocument().IsInMainFrame()) {
    preferred_color_scheme_ = settings->GetPreferredColorScheme();
  } else {
    preferred_color_scheme_ = owner_preferred_color_scheme_;
  }
  bool old_force_dark_mode_enabled = force_dark_mode_enabled_;
  force_dark_mode_enabled_ = settings->GetForceDarkModeEnabled();
  bool media_feature_override_color_scheme = false;

  // TODO(1479201): Should DevTools emulation use the WebPreferences API
  // overrides?
  if (const MediaFeatureOverrides* overrides =
          GetDocument().GetPage()->GetMediaFeatureOverrides()) {
    if (std::optional<ForcedColors> forced_color_override =
            overrides->GetForcedColors()) {
      forced_colors_ = forced_color_override.value();
    }
    if (std::optional<mojom::blink::PreferredColorScheme>
            preferred_color_scheme_override =
                overrides->GetPreferredColorScheme()) {
      preferred_color_scheme_ = preferred_color_scheme_override.value();
      media_feature_override_color_scheme = true;
    }
  }

  const PreferenceOverrides* preference_overrides =
      GetDocument().GetPage()->GetPreferenceOverrides();
  if (preference_overrides && !media_feature_override_color_scheme) {
    std::optional<mojom::blink::PreferredColorScheme>
        preferred_color_scheme_override =
            preference_overrides->GetPreferredColorScheme();
    if (preferred_color_scheme_override.has_value()) {
      preferred_color_scheme_ = preferred_color_scheme_override.value();
    }
  }

  if (GetDocument().Printing()) {
    preferred_color_scheme_ = mojom::blink::PreferredColorScheme::kLight;
    force_dark_mode_enabled_ = false;
  }

  if (forced_colors_ != old_forced_colors ||
      preferred_color_scheme_ != old_preferred_color_scheme ||
      force_dark_mode_enabled_ != old_force_dark_mode_enabled) {
    PlatformColorsChanged();
  }

  UpdateColorSchemeMetrics();
}

void StyleEngine::UpdateColorSchemeMetrics() {
  const Settings* settings = GetDocument().GetSettings();
  if (settings->GetForceDarkModeEnabled()) {
    UseCounter::Count(GetDocument(), WebFeature::kForcedDarkMode);
  }

  // True if the preferred color scheme will match dark.
  if (preferred_color_scheme_ == mojom::blink::PreferredColorScheme::kDark) {
    UseCounter::Count(GetDocument(), WebFeature::kPreferredColorSchemeDark);
  }

  // This is equal to kPreferredColorSchemeDark in most cases, but can differ
  // with forced dark mode. With the system in dark mode and forced dark mode
  // enabled, the preferred color scheme can be light while the setting is dark.
  if (settings->GetPreferredColorScheme() ==
      mojom::blink::PreferredColorScheme::kDark) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kPreferredColorSchemeDarkSetting);
  }

  // Record kColorSchemeDarkSupportedOnRoot if the meta color-scheme contains
  // dark (though dark may not be used). This metric is also recorded in
  // longhands_custom.cc (see: ColorScheme::ApplyValue) if the root style
  // color-scheme contains dark.
  if (page_color_schemes_ &
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark)) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kColorSchemeDarkSupportedOnRoot);
  }
}

void StyleEngine::ColorSchemeChanged() {
  UpdateColorScheme();
}

void StyleEngine::SetPageColorSchemes(const CSSValue* color_scheme) {
  if (!GetDocument().IsActive()) {
    return;
  }

  if (auto* value_list = DynamicTo<CSSValueList>(color_scheme)) {
    page_color_schemes_ = StyleBuilderConverter::ExtractColorSchemes(
        GetDocument(), *value_list, nullptr /* color_schemes */);
  } else {
    page_color_schemes_ =
        static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal);
  }
  DCHECK(GetDocument().documentElement());
  // kSubtreeStyleChange is necessary since the page color schemes may affect
  // used values of any element in the document with a specified color-scheme of
  // 'normal'. A more targeted invalidation would need to traverse the whole
  // document tree for specified values.
  GetDocument().documentElement()->SetNeedsStyleRecalc(
      kSubtreeStyleChange, StyleChangeReasonForTracing::Create(
                               style_change_reason::kPlatformColorChange));
  UpdateColorScheme();
  UpdateColorSchemeBackground();
}

void StyleEngine::UpdateColorSchemeBackground(bool color_scheme_changed) {
  LocalFrameView* view = GetDocument().View();
  if (!view) {
    return;
  }

  LocalFrameView::UseColorAdjustBackground use_color_adjust_background =
      LocalFrameView::UseColorAdjustBackground::kNo;

  if (forced_colors_ != ForcedColors::kNone) {
    if (GetDocument().IsInMainFrame()) {
      use_color_adjust_background =
          LocalFrameView::UseColorAdjustBackground::kIfBaseNotTransparent;
    }
  } else {
    // Find out if we should use a canvas color that is different from the
    // view's base background color in order to match the root element color-
    // scheme. See spec:
    // https://drafts.csswg.org/css-color-adjust/#color-scheme-effect
    mojom::blink::ColorScheme root_color_scheme =
        mojom::blink::ColorScheme::kLight;
    if (auto* root_element = GetDocument().documentElement()) {
      if (const ComputedStyle* style = root_element->GetComputedStyle()) {
        root_color_scheme = style->UsedColorScheme();
      } else if (SupportsDarkColorScheme()) {
        root_color_scheme = mojom::blink::ColorScheme::kDark;
      }
    }
    color_scheme_background_ =
        root_color_scheme == mojom::blink::ColorScheme::kLight
            ? Color::kWhite
            : Color(0x12, 0x12, 0x12);
    if (GetDocument().IsInMainFrame()) {
      if (root_color_scheme == mojom::blink::ColorScheme::kDark) {
        use_color_adjust_background =
            LocalFrameView::UseColorAdjustBackground::kIfBaseNotTransparent;
      }
    } else if (root_color_scheme != owner_color_scheme_ &&
               // https://html.spec.whatwg.org/C#is-initial-about:blank
               !view->GetFrame().Loader().IsOnInitialEmptyDocument()) {
      // Iframes should paint a solid background if the embedding iframe has a
      // used color-scheme different from the used color-scheme of the embedded
      // root element. Normally, iframes as transparent by default.
      use_color_adjust_background =
          LocalFrameView::UseColorAdjustBackground::kYes;
    }
  }

  view->SetUseColorAdjustBackground(use_color_adjust_background,
                                    color_scheme_changed);
}

void StyleEngine::SetOwnerColorScheme(
    mojom::blink::ColorScheme color_scheme,
    mojom::blink::PreferredColorScheme preferred_color_scheme) {
  DCHECK(!GetDocument().IsInMainFrame());
  if (owner_preferred_color_scheme_ != preferred_color_scheme) {
    owner_preferred_color_scheme_ = preferred_color_scheme;
    GetDocument().ColorSchemeChanged();
  }
  if (owner_color_scheme_ != color_scheme) {
    owner_color_scheme_ = color_scheme;
    UpdateColorSchemeBackground(true);
  }
}

mojom::blink::PreferredColorScheme StyleEngine::ResolveColorSchemeForEmbedding(
    const ComputedStyle* embedder_style) const {
  // ...if 'color-scheme' is 'normal' and there's no 'color-scheme' meta tag,
  // the propagated scheme is the preferred color-scheme of the embedder
  // document.
  if (!embedder_style || embedder_style->ColorSchemeFlagsIsNormal()) {
    return GetPreferredColorScheme();
  }
  return embedder_style && embedder_style->UsedColorScheme() ==
                               mojom::blink::ColorScheme::kDark
             ? mojom::blink::PreferredColorScheme::kDark
             : mojom::blink::PreferredColorScheme::kLight;
}

void StyleEngine::UpdateForcedBackgroundColor() {
  CHECK(GetDocument().GetPage());
  mojom::blink::ColorScheme color_scheme = mojom::blink::ColorScheme::kLight;
  forced_background_color_ = LayoutTheme::GetTheme().SystemColor(
      CSSValueID::kCanvas, color_scheme,
      GetDocument().GetPage()->GetColorProviderForPainting(
          color_scheme, forced_colors_ != ForcedColors::kNone),
      GetDocument().IsInWebAppScope());
}

Color StyleEngine::ColorAdjustBackgroundColor() const {
  if (forced_colors_ != ForcedColors::kNone) {
    return ForcedBackgroundColor();
  }
  return color_scheme_background_;
}

void StyleEngine::MarkAllElementsForStyleRecalc(
    const StyleChangeReasonForTracing& reason) {
  if (Element* root = GetDocument().documentElement()) {
    root->SetNeedsStyleRecalc(kSubtreeStyleChange, reason);
  }
}

void StyleEngine::UpdateViewportStyle() {
  if (!viewport_style_dirty_) {
    return;
  }

  viewport_style_dirty_ = false;

  if (!resolver_) {
    return;
  }

  const ComputedStyle* viewport_style = resolver_->StyleForViewport();
  if (ComputedStyle::ComputeDifference(
          viewport_style, GetDocument().GetLayoutView()->Style()) !=
      ComputedStyle::Difference::kEqual) {
    GetDocument().GetLayoutView()->SetStyle(viewport_style);
  }
}

bool StyleEngine::NeedsFullStyleUpdate() const {
  return NeedsActiveStyleUpdate() || IsViewportStyleDirty() ||
         viewport_unit_dirty_flags_ || is_env_dirty_;
}

void StyleEngine::PropagateWritingModeAndDirectionToHTMLRoot() {
  if (HTMLHtmlElement* root_element =
          DynamicTo<HTMLHtmlElement>(GetDocument().documentElement())) {
    root_element->PropagateWritingModeAndDirectionFromBody();
  }
}

CounterStyleMap& StyleEngine::EnsureUserCounterStyleMap() {
  if (!user_counter_style_map_) {
    user_counter_style_map_ =
        CounterStyleMap::CreateUserCounterStyleMap(GetDocument());
  }
  return *user_counter_style_map_;
}

const CounterStyle& StyleEngine::FindCounterStyleAcrossScopes(
    const AtomicString& name,
    const TreeScope* scope) const {
  CounterStyleMap* target_map = nullptr;
  while (scope) {
    if (CounterStyleMap* map =
            CounterStyleMap::GetAuthorCounterStyleMap(*scope)) {
      target_map = map;
      break;
    }
    scope = scope->ParentTreeScope();
  }
  if (!target_map && user_counter_style_map_) {
    target_map = user_counter_style_map_;
  }
  if (!target_map) {
    target_map = CounterStyleMap::GetUACounterStyleMap();
  }
  if (CounterStyle* result = target_map->FindCounterStyleAcrossScopes(name)) {
    return *result;
  }
  return CounterStyle::GetDecimal();
}

void StyleEngine::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(injected_user_style_sheets_);
  visitor->Trace(injected_author_style_sheets_);
  visitor->Trace(active_user_style_sheets_);
  visitor->Trace(keyframes_rule_map_);
  visitor->Trace(font_palette_values_rule_map_);
  visitor->Trace(user_counter_style_map_);
  visitor->Trace(user_cascade_layer_map_);
  visitor->Trace(environment_variables_);
  visitor->Trace(initial_data_);
  visitor->Trace(inspector_style_sheet_);
  visitor->Trace(document_style_sheet_collection_);
  visitor->Trace(style_sheet_collection_map_);
  visitor->Trace(dirty_tree_scopes_);
  visitor->Trace(active_tree_scopes_);
  visitor->Trace(resolver_);
  visitor->Trace(vision_deficiency_filter_);
  visitor->Trace(viewport_resolver_);
  visitor->Trace(media_query_evaluator_);
  visitor->Trace(global_rule_set_);
  visitor->Trace(pending_invalidations_);
  visitor->Trace(style_invalidation_root_);
  visitor->Trace(style_recalc_root_);
  visitor->Trace(layout_tree_rebuild_root_);
  visitor->Trace(font_selector_);
  visitor->Trace(text_to_sheet_cache_);
  visitor->Trace(tracker_);
  visitor->Trace(text_tracks_);
  visitor->Trace(vtt_originating_element_);
  visitor->Trace(parent_for_detached_subtree_);
  visitor->Trace(view_transition_rule_);
  visitor->Trace(style_image_cache_);
  visitor->Trace(fill_or_clip_path_uri_value_cache_);
  visitor->Trace(style_containment_scope_tree_);
  visitor->Trace(try_value_flips_);
  visitor->Trace(last_successful_option_dirty_set_);
  FontSelectorClient::Trace(visitor);
}

namespace {

inline bool MayHaveFlatTreeChildren(const Element& element) {
  return element.firstChild() || IsShadowHost(element) ||
         element.IsActiveSlot();
}

}  // namespace

void StyleEngine::MarkForLayoutTreeChangesAfterDetach() {
  if (!parent_for_detached_subtree_) {
    return;
  }
  auto* layout_object = parent_for_detached_subtree_.Get();
  if (auto* layout_object_element =
          DynamicTo<Element>(layout_object->GetNode())) {
    DCHECK_EQ(layout_object, layout_object_element->GetLayoutObject());

    // Mark the parent of a detached subtree for doing a whitespace or list item
    // update.
```