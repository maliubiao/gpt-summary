Response:
Let's break down the thought process to analyze the provided C++ code and generate the detailed explanation.

**1. Initial Understanding & Goal Identification:**

The first step is to recognize the code is part of the Chromium Blink rendering engine and resides in the `container_query_evaluator.cc` file. The immediate goal is to understand its purpose and how it fits within the broader context of CSS Container Queries.

**2. Core Functionality Identification:**

The name `ContainerQueryEvaluator` strongly suggests its primary function: evaluating CSS Container Queries. This involves determining whether a given container element satisfies the conditions specified in a container query.

**3. Key Data Structures and Concepts:**

Scanning the code reveals several important types and concepts:

*   `ContainerQuery`: Represents a CSS `@container` rule.
*   `ContainerSelector`:  The selector part of a container query (e.g., `container-type: inline-size`).
*   `ComputedStyle`: The final computed style for an element, containing properties like `container-type` and `container-name`.
*   `MediaQueryEvaluator`: A class likely responsible for evaluating media queries (and container queries, which are similar).
*   `CSSContainerValues`:  A class holding the relevant values of a container for query evaluation (width, height, scroll state, etc.).
*   `MatchResult`: Tracks dependencies and whether a rule matches.
*   `ContainerSelectorCache`:  Optimization to avoid repeatedly finding the same container.

**4. Function-by-Function Analysis (High-Level):**

Go through the public methods and some key private ones to understand their roles:

*   **Constructor:** Initializes the evaluator, potentially capturing initial scroll state.
*   `FindContainer()`:  The core logic for finding the nearest ancestor container that matches the selector.
*   `EvalAndAdd()`: Evaluates a container query and adds its result to a cache.
*   `Eval()`:  Evaluates a single container query against the current container's values.
*   `SizeContainerChanged()`, `StickyContainerChanged()`, etc.: Methods triggered when container properties change, leading to re-evaluation.
*   `ApplyScrollState()`:  Updates the container's scroll state based on a snapshot.
*   `StyleContainerChanged()`: Handles style changes that might affect container queries.
*   `UpdateContainerValues()`:  Updates the `CSSContainerValues` object.
*   `ClearResults()`:  Invalidates cached query results when the container changes.

**5. Relationship to Web Technologies (HTML, CSS, JavaScript):**

Consider how this C++ code interacts with the front-end technologies:

*   **CSS:**  It directly implements the logic for evaluating CSS Container Queries defined in stylesheets.
*   **HTML:**  It operates on the DOM tree (`Element` objects) to find containers and evaluate queries.
*   **JavaScript:** While this code is C++, JavaScript interacts with the rendering engine. Changes in JavaScript (like modifying styles or scrolling) can trigger the C++ code to re-evaluate container queries and update the visual rendering.

**6. Logic and Reasoning (Input/Output Examples):**

Think about specific scenarios and how the code would behave:

*   **Input:** A container element with `container-type: inline-size`, and a CSS rule `@container (min-width: 300px) { ... }`.
*   **Output:** The `Eval()` method would return `true` if the container's inline size is 300px or more, `false` otherwise.

*   **Input:** Scrolling a container with a `@container (scroll-y: snap-mandatory) { ... }` rule.
*   **Output:** `ApplyScrollState()` and `SnapContainerChanged()` would be involved in updating the state and triggering re-evaluation.

**7. Common User/Programming Errors:**

Consider how developers might misuse container queries:

*   **Forgetting `container-type`:** A common mistake is defining `@container` rules without setting `container-type` on an ancestor, leading to queries not working.
*   **Incorrect selector:**  Using complex selectors that don't match any ancestor container.
*   **Performance issues:** Overusing container queries, especially with complex logic, could impact rendering performance.

**8. Debugging Workflow (Path to the Code):**

Think about the steps a developer or browser might take to reach this code:

1. **Load HTML:** The browser loads an HTML page.
2. **Parse CSS:** The browser parses the CSS, identifying `@container` rules and `container-type` declarations.
3. **Layout:** The browser performs layout, establishing the container hierarchy.
4. **Style Calculation:** When styles need to be recalculated (due to changes in size, style, or scroll), the `ContainerQueryEvaluator` is invoked to determine if any container query conditions are met.
5. **Rendering:** Based on the evaluation results, different styles are applied, and the page is rendered.

**9. Refinement and Organization:**

Structure the explanation logically, using headings and bullet points to improve readability. Provide clear examples and explanations for each aspect.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:**  Maybe focus too much on individual functions in isolation.
*   **Correction:** Realize the importance of showing the *flow* and *interaction* between different parts of the code and its connection to the overall rendering process.
*   **Initial thought:**  Assume the reader has deep knowledge of Blink internals.
*   **Correction:** Provide simpler explanations and analogies where possible to make the concepts more accessible. Explain acronyms or internal terms (like `TreeScope`).
*   **Initial thought:** Not enough concrete examples.
*   **Correction:** Add input/output scenarios and examples of user errors to make the explanation more practical.

By following these steps and continually refining the understanding, a comprehensive and accurate explanation of the `container_query_evaluator.cc` file can be generated.
好的，我们来详细分析一下 `blink/renderer/core/css/container_query_evaluator.cc` 文件的功能。

**文件功能总览:**

`container_query_evaluator.cc` 文件实现了 CSS Container Queries 的评估逻辑。它的核心任务是判断一个元素是否满足其祖先容器上定义的 `@container` 规则的条件。简单来说，它决定了一个元素是否应该应用某个容器查询块中的样式。

**核心功能点:**

1. **查找容器 (Finding Containers):**
    *   `FindContainer()` 函数负责向上遍历 DOM 树，查找满足指定 `ContainerSelector` 的祖先元素。
    *   它会检查祖先元素的 `ComputedStyle`，判断其 `container-type` 和 `container-name` 是否与 `@container` 规则的 `container-selector` 匹配。
    *   使用了 `ContainerSelectorCache` 来缓存已经找到的容器，提高查找效率。

2. **评估容器查询 (Evaluating Container Queries):**
    *   `Eval()` 函数接收一个 `ContainerQuery` 对象，并根据当前容器的状态（尺寸、滚动状态、样式等）评估该查询的条件是否成立。
    *   它内部使用 `MediaQueryEvaluator` 来进行实际的媒体查询评估，因为容器查询在语法和评估方式上与媒体查询有很多相似之处。
    *   评估结果会缓存起来，避免重复计算。

3. **管理容器状态变化 (Managing Container State Changes):**
    *   提供了一系列函数来处理容器状态的变化，例如：
        *   `SizeContainerChanged()`: 当容器的尺寸发生变化时调用。
        *   `StickyContainerChanged()`: 当容器的 sticky 状态发生变化时调用。
        *   `SnapContainerChanged()`: 当容器的 scroll snap 状态发生变化时调用。
        *   `OverflowContainerChanged()`: 当容器的 overflow 状态发生变化时调用。
        *   `StyleContainerChanged()`: 当容器的样式发生变化时调用。
    *   这些函数会更新内部的容器状态，并触发相关的容器查询重新评估。

4. **确定样式重计算范围 (Determining Style Recalculation Scope):**
    *   `EvalAndAdd()` 函数不仅评估查询，还负责确定样式重计算的范围。
    *   它会根据容器查询的类型（尺寸、样式、滚动状态）以及容器的变化情况，设置 `MatchResult` 中的标志，指示哪些元素的样式需要重新计算。

5. **处理单位变化 (Handling Unit Changes):**
    *   `UpdateContainerValuesFromUnitChanges()` 函数处理像 `rem` 或容器相对单位等值变化的情况，这些变化可能影响容器查询的评估结果。

6. **与滚动相关的处理 (Scroll-related Handling):**
    *   `ApplyScrollState()` 和 `SetPendingSnappedStateFromScrollSnapshot()` 函数处理与滚动相关的容器查询，例如 `@container (scroll-x: ...)` 或 `@container (scroll-y: snap-mandatory) ...`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **CSS:** `container_query_evaluator.cc` 直接实现了 CSS Container Queries 的核心逻辑。它解析 CSS 样式规则中的 `@container` 查询，并根据容器的状态来决定是否应用这些样式。
    *   **例子:**  假设有以下 CSS：
        ```css
        .container {
          container-type: inline-size;
        }

        .item {
          width: 100px;
        }

        @container (min-width: 300px) {
          .item {
            width: 200px;
          }
        }
        ```
        当 `.container` 的内联尺寸达到 300px 时，`container_query_evaluator.cc` 会评估 `@container (min-width: 300px)` 为真，从而使 `.item` 的宽度变为 200px。

*   **HTML:** `container_query_evaluator.cc` 操作的是 HTML 元素构成的 DOM 树。它需要找到作为容器的祖先元素，并根据这些容器的状态来影响子元素的样式。
    *   **例子:**  考虑以下 HTML 结构：
        ```html
        <div class="container">
          <div class="item"></div>
        </div>
        ```
        `container_query_evaluator.cc` 会从 `.item` 元素开始，向上查找拥有 `container-type` 属性的 `.container` 元素，并评估针对该容器定义的查询。

*   **JavaScript:**  JavaScript 可以通过修改元素的样式或属性，间接地触发 `container_query_evaluator.cc` 的工作。例如，通过 JavaScript 改变容器的宽度，会导致 `SizeContainerChanged()` 被调用，并可能导致容器查询的重新评估。
    *   **例子:**  以下 JavaScript 代码可能会触发容器查询的重新评估：
        ```javascript
        const container = document.querySelector('.container');
        container.style.width = '350px'; // 容器宽度改变
        ```
        如果存在针对 `.container` 宽度定义的容器查询，`container_query_evaluator.cc` 会重新评估这些查询，并可能更新子元素的样式。

**逻辑推理的假设输入与输出:**

假设有以下 HTML 和 CSS：

```html
<div class="container" style="container-type: inline-size; width: 200px;">
  <div class="item" style="width: 50px;"></div>
</div>
```

```css
@container (min-width: 250px) {
  .item {
    width: 100px;
  }
}
```

**假设输入:**  当前正在评估 `.item` 元素的样式。

**逻辑推理过程:**

1. `container_query_evaluator.cc` 会从 `.item` 向上查找容器。
2. 找到 `.container` 元素，其 `container-type` 为 `inline-size`。
3. 评估 `@container (min-width: 250px)`。
4. 获取 `.container` 的内联尺寸 (假设等同于 `width`)，当前为 200px。
5. 比较 200px 与 250px，结果为 false。

**输出:**  `Eval()` 函数对于该容器查询返回 `false`。因此，`.item` 元素的宽度将保持其初始样式中的 50px，而不是容器查询中定义的 100px。

**用户或编程常见的使用错误举例说明:**

1. **忘记设置 `container-type`:**  这是最常见的错误。如果在祖先元素上没有设置 `container-type` 属性，那么 `@container` 规则将不会生效。
    ```css
    /* 错误示例：缺少 container-type */
    .container {
      /* container-type: inline-size;  <-- 忘记添加 */
    }

    @container (min-width: 300px) {
      .item {
        width: 200px;
      }
    }
    ```
    在这种情况下，即使 `.container` 的宽度超过 300px，`.item` 的宽度也不会改变。

2. **容器查询选择器不匹配:** `@container` 规则中的选择器无法正确匹配到期望的容器元素。
    ```css
    /* 错误示例：选择器错误 */
    .my-special-container {
      container-type: inline-size;
    }

    @container .other-container (min-width: 300px) { /* 选择器错误 */
      .item {
        width: 200px;
      }
    }
    ```
    如果 `.item` 的父元素是 `.my-special-container` 而不是 `.other-container`，则容器查询不会生效。

3. **循环依赖:**  容器的尺寸或样式依赖于自身容器查询的结果，这可能导致无限循环或未定义的行为。虽然浏览器会尝试避免这种情况，但编写 CSS 时应注意避免此类依赖。

4. **过度使用复杂的容器查询:**  过多的或过于复杂的容器查询可能会影响渲染性能。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户加载包含容器查询的网页:** 用户在浏览器中打开一个包含使用了 CSS Container Queries 的网页。
2. **浏览器解析 HTML 和 CSS:** 浏览器开始解析 HTML 结构和 CSS 样式表，包括 `@container` 规则和 `container-type` 声明。
3. **布局计算 (Layout):** 浏览器进行布局计算，确定元素的尺寸和位置，这涉及到识别容器元素。
4. **样式计算 (Style Calculation):**
    *   当需要计算或重新计算某个元素的样式时（例如，首次渲染或容器尺寸变化），渲染引擎会查找该元素的所有匹配的 CSS 规则，包括容器查询块中的规则。
    *   对于容器查询块中的规则，`container_query_evaluator.cc` 中的代码会被调用。
    *   **查找容器:**  `FindContainer()` 会被调用，从当前元素向上遍历 DOM 树，查找声明了 `container-type` 并且 `container-name` (如果指定) 匹配的祖先元素。
    *   **评估查询:**  一旦找到容器，`Eval()` 函数会被调用，传入相应的 `ContainerQuery` 对象。
    *   `Eval()` 内部会获取容器的当前状态（例如，尺寸），并与查询条件进行比较。
    *   `MediaQueryEvaluator` 会执行实际的条件判断。
5. **应用样式:**  根据容器查询的评估结果，相应的样式会被应用到元素上。
6. **用户交互导致容器状态变化:**
    *   用户调整浏览器窗口大小：可能触发容器尺寸变化，导致 `SizeContainerChanged()` 被调用，并重新评估相关的容器查询。
    *   用户滚动容器：可能触发 `StickyContainerChanged()` 或 `SnapContainerChanged()`，并重新评估相关的滚动状态容器查询。
    *   JavaScript 修改容器样式或属性：可能触发 `StyleContainerChanged()` 或 `SizeContainerChanged()`，并重新评估相关的容器查询。

**调试线索:**

*   如果在调试工具的 "Elements" 面板中，某个元素的样式来自 `@container` 规则，但看起来并没有生效，可以检查以下几点：
    *   **是否存在祖先容器:** 确认该元素是否存在设置了 `container-type` 的祖先元素。
    *   **容器查询条件:**  检查 `@container` 规则中的条件（例如 `min-width`, `max-height`, `scroll-x` 等）是否满足当前容器的状态。
    *   **容器名称匹配:** 如果使用了 `container-name`，确认容器的 `container-name` 属性与 `@container` 规则中的名称是否匹配。
    *   **浏览器兼容性:** 确认使用的浏览器版本支持 CSS Container Queries。
    *   **"Computed" 面板:**  在浏览器的 "Elements" 面板的 "Computed" 标签中，可以查看元素最终应用的样式，以及哪些 `@container` 查询匹配成功。
    *   **Performance 面板:**  如果怀疑容器查询影响性能，可以使用浏览器的 "Performance" 面板来分析渲染过程。

总而言之，`container_query_evaluator.cc` 是 Blink 引擎中实现 CSS Container Queries 这一强大特性的关键组成部分，负责评估查询条件，管理容器状态，并最终决定是否应用相应的样式规则。 理解其工作原理对于调试和优化使用了容器查询的网页至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/container_query_evaluator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/container_query_evaluator.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/css/container_query.h"
#include "third_party/blink/renderer/core/css/css_container_values.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/resolver/match_result.h"
#include "third_party/blink/renderer/core/css/scroll_state_query_snapshot.h"
#include "third_party/blink/renderer/core/css/snapped_query_scroll_snapshot.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_recalc_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

// Produce PhysicalAxes corresponding to the computed container-type.
// Note that this may be different from the *actually* contained axes
// provided to ContainerChanged, since there are multiple sources of
// applied containment (e.g. the 'contain' property itself).
PhysicalAxes ContainerTypeAxes(const ComputedStyle& style) {
  LogicalAxes axes = kLogicalAxesNone;
  if (style.ContainerType() & kContainerTypeInlineSize) {
    axes |= kLogicalAxesInline;
  }
  if (style.ContainerType() & kContainerTypeBlockSize) {
    axes |= kLogicalAxesBlock;
  }
  return ToPhysicalAxes(axes, style.GetWritingMode());
}

bool NameMatches(const ComputedStyle& style,
                 const ContainerSelector& container_selector,
                 const TreeScope* selector_tree_scope) {
  const AtomicString& name = container_selector.Name();
  if (name.IsNull()) {
    return true;
  }
  if (const ScopedCSSNameList* container_name = style.ContainerName()) {
    const HeapVector<Member<const ScopedCSSName>>& names =
        container_name->GetNames();
    for (auto scoped_name : names) {
      if (scoped_name->GetName() == name) {
        const TreeScope* name_tree_scope = scoped_name->GetTreeScope();
        if (!name_tree_scope || !selector_tree_scope) {
          // Either the container-name or @container have a UA or User origin.
          // In that case always match the name regardless of the other one's
          // origin.
          return true;
        }
        // Match a tree-scoped container name if the container-name
        // declaration's tree scope is an inclusive ancestor of the @container
        // rule's tree scope.
        for (const TreeScope* match_scope = selector_tree_scope; match_scope;
             match_scope = match_scope->ParentTreeScope()) {
          if (match_scope == name_tree_scope) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

bool TypeMatches(const ComputedStyle& style,
                 const ContainerSelector& container_selector) {
  DCHECK(!container_selector.HasUnknownFeature());
  unsigned type = container_selector.Type(style.GetWritingMode());
  return !type || ((style.ContainerType() & type) == type);
}

bool Matches(const ComputedStyle& style,
             const ContainerSelector& container_selector,
             const TreeScope* selector_tree_scope) {
  return TypeMatches(style, container_selector) &&
         NameMatches(style, container_selector, selector_tree_scope);
}

Element* CachedContainer(Element* starting_element,
                         const ContainerSelector& container_selector,
                         const TreeScope* selector_tree_scope,
                         ContainerSelectorCache& container_selector_cache) {
  auto it =
      container_selector_cache.Find<ScopedContainerSelectorHashTranslator>(
          ScopedContainerSelector(container_selector, selector_tree_scope));
  if (it != container_selector_cache.end()) {
    return it->value.Get();
  }
  Element* container = ContainerQueryEvaluator::FindContainer(
      starting_element, container_selector, selector_tree_scope);
  container_selector_cache.insert(MakeGarbageCollected<ScopedContainerSelector>(
                                      container_selector, selector_tree_scope),
                                  container);
  return container;
}

PaintLayerScrollableArea* FindScrollContainerScrollableArea(
    const Element& container) {
  if (const LayoutObject* layout_object = container.GetLayoutObject()) {
    if (const LayoutBox* snap_container =
            layout_object->ContainingScrollContainer()) {
      return snap_container->GetScrollableArea();
    }
  }
  return nullptr;
}

}  // namespace

ContainerQueryEvaluator::ContainerQueryEvaluator(Element& container) {
  if (PaintLayerScrollableArea* scrollable_area =
          FindScrollContainerScrollableArea(container)) {
    if (SnappedQueryScrollSnapshot* snapshot =
            scrollable_area->GetSnappedQueryScrollSnapshot()) {
      ContainerSnappedFlags snapped =
          static_cast<ContainerSnappedFlags>(ContainerSnapped::kNone);
      if (snapshot->GetSnappedTargetX() == container) {
        snapped |= static_cast<ContainerSnappedFlags>(ContainerSnapped::kX);
      }
      if (snapshot->GetSnappedTargetY() == container) {
        snapped |= static_cast<ContainerSnappedFlags>(ContainerSnapped::kY);
      }
      snapped_ = pending_snapped_ = snapped;
    }
  }
  auto* query_values = MakeGarbageCollected<CSSContainerValues>(
      container.GetDocument(), container, std::nullopt, std::nullopt,
      ContainerStuckPhysical::kNo, ContainerStuckPhysical::kNo, snapped_,
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kNone),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kNone));
  media_query_evaluator_ =
      MakeGarbageCollected<MediaQueryEvaluator>(query_values);
}

// static
Element* ContainerQueryEvaluator::ParentContainerCandidateElement(
    Element& element) {
  if (RuntimeEnabledFeatures::CSSFlatTreeContainerEnabled()) {
    return FlatTreeTraversal::ParentElement(element);
  }
  return element.ParentOrShadowHostElement();
}

// static
Element* ContainerQueryEvaluator::FindContainer(
    Element* starting_element,
    const ContainerSelector& container_selector,
    const TreeScope* selector_tree_scope) {
  // TODO(crbug.com/1213888): Cache results.
  for (Element* element = starting_element; element;
       element = ParentContainerCandidateElement(*element)) {
    if (const ComputedStyle* style = element->GetComputedStyle()) {
      if (style->StyleType() == kPseudoIdNone) {
        if (Matches(*style, container_selector, selector_tree_scope)) {
          return element;
        }
      }
    }
  }

  return nullptr;
}

bool ContainerQueryEvaluator::EvalAndAdd(
    Element* style_container_candidate,
    const StyleRecalcContext& context,
    const ContainerQuery& query,
    ContainerSelectorCache& container_selector_cache,
    MatchResult& match_result) {
  const ContainerSelector& selector = query.Selector();
  if (selector.HasUnknownFeature()) {
    return false;
  }
  bool selects_size = selector.SelectsSizeContainers();
  bool selects_style = selector.SelectsStyleContainers();
  bool selects_scroll_state = selector.SelectsScrollStateContainers();
  if (!selects_size && !selects_style && !selects_scroll_state) {
    return false;
  }

  if (selects_size) {
    match_result.SetDependsOnSizeContainerQueries();
  }
  if (selects_style) {
    match_result.SetDependsOnStyleContainerQueries();
  }
  if (selects_scroll_state) {
    match_result.SetDependsOnScrollStateContainerQueries();
  }

  Element* starting_element =
      selects_size ? context.container : style_container_candidate;
  if (Element* container = CachedContainer(starting_element, query.Selector(),
                                           match_result.CurrentTreeScope(),
                                           container_selector_cache)) {
    Change change = starting_element == container
                        ? Change::kNearestContainer
                        : Change::kDescendantContainers;
    return container->EnsureContainerQueryEvaluator().EvalAndAdd(query, change,
                                                                 match_result);
  }
  return false;
}

std::optional<double> ContainerQueryEvaluator::Width() const {
  CHECK(media_query_evaluator_);
  return media_query_evaluator_->GetMediaValues().Width();
}

std::optional<double> ContainerQueryEvaluator::Height() const {
  CHECK(media_query_evaluator_);
  return media_query_evaluator_->GetMediaValues().Height();
}

ContainerQueryEvaluator::Result ContainerQueryEvaluator::Eval(
    const ContainerQuery& container_query) const {
  CHECK(media_query_evaluator_);

  if (container_query.Selector().HasUnknownFeature()) {
    Element* container = ContainerElement();
    CHECK(container);
    container->GetDocument().CountUse(WebFeature::kContainerQueryEvalUnknown);
  }

  MediaQueryResultFlags result_flags;
  bool value =
      (media_query_evaluator_->Eval(*container_query.query_, &result_flags) ==
       KleeneValue::kTrue);

  Result result;
  result.value = value;
  result.unit_flags = result_flags.unit_flags;
  return result;
}

bool ContainerQueryEvaluator::EvalAndAdd(const ContainerQuery& query,
                                         Change change,
                                         MatchResult& match_result) {
  HeapHashMap<Member<const ContainerQuery>, Result>::AddResult entry =
      results_.insert(&query, Result());

  Result& result = entry.stored_value->value;

  // We can only use the cached values when evaluating queries whose results
  // would have been cleared by [Size,Style]ContainerChanged. The following
  // represents dependencies on external circumstance that can change without
  // ContainerQueryEvaluator being notified.
  bool use_cached =
      (result.unit_flags & (MediaQueryExpValue::UnitFlags::kRootFontRelative |
                            MediaQueryExpValue::UnitFlags::kDynamicViewport |
                            MediaQueryExpValue::UnitFlags::kStaticViewport |
                            MediaQueryExpValue::UnitFlags::kContainer)) == 0;
  bool has_cached = !entry.is_new_entry;

  if (has_cached && use_cached) {
    // Verify that the cached result is equal to the value we would get
    // had we Eval'ed in full.
#if EXPENSIVE_DCHECKS_ARE_ON()
    Result actual = Eval(query);

    // This ignores `change`, because it's not actually part of Eval's result.
    DCHECK_EQ(result.value, actual.value);
    DCHECK_EQ(result.unit_flags, actual.unit_flags);
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
  } else {
    result = Eval(query);
  }

  // Store the most severe `Change` seen.
  result.change = std::max(result.change, change);

  if (result.unit_flags & MediaQueryExpValue::UnitFlags::kDynamicViewport) {
    match_result.SetDependsOnDynamicViewportUnits();
  }
  // Note that container-relative units *may* fall back to the small viewport,
  // hence we also set the DependsOnStaticViewportUnits flag when in that case.
  if (result.unit_flags & (MediaQueryExpValue::UnitFlags::kStaticViewport |
                           MediaQueryExpValue::UnitFlags::kContainer)) {
    match_result.SetDependsOnStaticViewportUnits();
  }
  if (result.unit_flags & MediaQueryExpValue::UnitFlags::kRootFontRelative) {
    match_result.SetDependsOnRootFontContainerQueries();
  }
  if (!depends_on_size_) {
    depends_on_size_ = query.Selector().SelectsSizeContainers();
  }
  if (!depends_on_style_) {
    depends_on_style_ = query.Selector().SelectsStyleContainers();
  }
  if (!depends_on_stuck_) {
    depends_on_stuck_ = query.Selector().SelectsStickyContainers();
    if (depends_on_stuck_ && !scroll_state_snapshot_) {
      CHECK(media_query_evaluator_);
      Element* container_element = ContainerElement();
      CHECK(container_element);
      scroll_state_snapshot_ =
          MakeGarbageCollected<ScrollStateQuerySnapshot>(*container_element);
    }
  }
  if (!depends_on_snapped_) {
    depends_on_snapped_ = query.Selector().SelectsSnapContainers();
    if (depends_on_snapped_) {
      if (PaintLayerScrollableArea* scrollable_area =
              FindScrollContainerScrollableArea(*ContainerElement())) {
        scrollable_area->EnsureSnappedQueryScrollSnapshot();
      }
    }
  }
  if (!depends_on_overflowing_) {
    depends_on_overflowing_ = query.Selector().SelectsOverflowContainers();
    if (depends_on_overflowing_ && !scroll_state_snapshot_) {
      CHECK(media_query_evaluator_);
      Element* container_element = ContainerElement();
      CHECK(container_element);
      scroll_state_snapshot_ =
          MakeGarbageCollected<ScrollStateQuerySnapshot>(*container_element);
    }
  }
  unit_flags_ |= result.unit_flags;

  return result.value;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::SizeContainerChanged(
    PhysicalSize size,
    PhysicalAxes contained_axes) {
  if (size_ == size && contained_axes_ == contained_axes) {
    return Change::kNone;
  }

  UpdateContainerSize(size, contained_axes);

  Change change = ComputeSizeChange();
  if (change != Change::kNone) {
    ClearResults(change, kSizeContainer);
  }

  return referenced_by_unit_ ? Change::kDescendantContainers : change;
}

void ContainerQueryEvaluator::SetPendingSnappedStateFromScrollSnapshot(
    const SnappedQueryScrollSnapshot& snapshot) {
  Element* container = ContainerElement();
  pending_snapped_ =
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kNone);
  if (snapshot.GetSnappedTargetX() == container) {
    pending_snapped_ |=
        static_cast<ContainerSnappedFlags>(ContainerSnapped::kX);
  }
  if (snapshot.GetSnappedTargetY() == container) {
    pending_snapped_ |=
        static_cast<ContainerSnappedFlags>(ContainerSnapped::kY);
  }

  if (pending_snapped_ != snapped_) {
    // TODO(crbug.com/40279568): The kLocalStyleChange is not necessary for the
    // container itself, but it is a way to reach reach ApplyScrollState() in
    // Element::RecalcOwnStyle() for the next lifecycle update.
    container->SetNeedsStyleRecalc(kLocalStyleChange,
                                   StyleChangeReasonForTracing::Create(
                                       style_change_reason::kScrollTimeline));
  }
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::ApplyScrollState() {
  Change change = Change::kNone;
  if (scroll_state_snapshot_) {
    change = StickyContainerChanged(scroll_state_snapshot_->StuckHorizontal(),
                                    scroll_state_snapshot_->StuckVertical());
    Change overflow_change = OverflowContainerChanged(
        scroll_state_snapshot_->OverflowingHorizontal(),
        scroll_state_snapshot_->OverflowingVertical());
    change = std::max(change, overflow_change);
  }
  Change snap_change = SnapContainerChanged(pending_snapped_);
  change = std::max(change, snap_change);
  return change;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::StickyContainerChanged(
    ContainerStuckPhysical stuck_horizontal,
    ContainerStuckPhysical stuck_vertical) {
  if (stuck_horizontal_ == stuck_horizontal &&
      stuck_vertical_ == stuck_vertical) {
    return Change::kNone;
  }

  UpdateContainerStuck(stuck_horizontal, stuck_vertical);
  Change change = ComputeStickyChange();
  if (change != Change::kNone) {
    ClearResults(change, kStickyContainer);
  }

  return change;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::SnapContainerChanged(
    ContainerSnappedFlags snapped) {
  if (snapped_ == snapped) {
    return Change::kNone;
  }

  UpdateContainerSnapped(snapped);
  Change change = ComputeSnapChange();
  if (change != Change::kNone) {
    ClearResults(change, kSnapContainer);
  }

  return change;
}

ContainerQueryEvaluator::Change
ContainerQueryEvaluator::OverflowContainerChanged(
    ContainerOverflowingFlags overflowing_horizontal,
    ContainerOverflowingFlags overflowing_vertical) {
  if (overflowing_horizontal_ == overflowing_horizontal &&
      overflowing_vertical_ == overflowing_vertical) {
    return Change::kNone;
  }

  UpdateContainerOverflowing(overflowing_horizontal, overflowing_vertical);
  Change change = ComputeOverflowChange();
  if (change != Change::kNone) {
    ClearResults(change, kOverflowContainer);
  }

  return change;
}

ContainerQueryEvaluator::Change
ContainerQueryEvaluator::StyleContainerChanged() {
  if (!depends_on_style_) {
    return Change::kNone;
  }

  Change change = ComputeStyleChange();

  if (change != Change::kNone) {
    ClearResults(change, kStyleContainer);
  }

  return change;
}

ContainerQueryEvaluator::Change
ContainerQueryEvaluator::StyleAffectingSizeChanged() {
  Change change = ComputeSizeChange();
  if (change != Change::kNone) {
    ClearResults(change, kSizeContainer);
  }
  return change;
}

ContainerQueryEvaluator::Change
ContainerQueryEvaluator::StyleAffectingScrollStateChanged() {
  Change snap_change = ComputeSnapChange();
  if (snap_change != Change::kNone) {
    ClearResults(snap_change, kSnapContainer);
  }
  Change sticky_change = ComputeStickyChange();
  if (sticky_change != Change::kNone) {
    ClearResults(sticky_change, kStickyContainer);
  }
  Change overflow_change = ComputeOverflowChange();
  if (overflow_change != Change::kNone) {
    ClearResults(overflow_change, kOverflowContainer);
  }
  return std::max(std::max(snap_change, sticky_change), overflow_change);
}

void ContainerQueryEvaluator::UpdateContainerValues() {
  const MediaValues& existing_values = media_query_evaluator_->GetMediaValues();
  Element* container = existing_values.ContainerElement();
  auto* query_values = MakeGarbageCollected<CSSContainerValues>(
      container->GetDocument(), *container, existing_values.Width(),
      existing_values.Height(), existing_values.StuckHorizontal(),
      existing_values.StuckVertical(), existing_values.SnappedFlags(),
      existing_values.OverflowingHorizontal(),
      existing_values.OverflowingVertical());
  media_query_evaluator_ =
      MakeGarbageCollected<MediaQueryEvaluator>(query_values);
}

void ContainerQueryEvaluator::Trace(Visitor* visitor) const {
  visitor->Trace(media_query_evaluator_);
  visitor->Trace(results_);
  visitor->Trace(scroll_state_snapshot_);
}

void ContainerQueryEvaluator::UpdateContainerSize(PhysicalSize size,
                                                  PhysicalAxes contained_axes) {
  size_ = size;
  contained_axes_ = contained_axes;

  std::optional<double> width;
  std::optional<double> height;

  const MediaValues& existing_values = media_query_evaluator_->GetMediaValues();
  Element* container = existing_values.ContainerElement();

  // An axis is "supported" only when it appears in the computed value of
  // 'container-type', and when containment is actually applied for that axis.
  //
  // See IsEligibleForSizeContainment (and similar).
  PhysicalAxes supported_axes =
      ContainerTypeAxes(container->ComputedStyleRef()) & contained_axes;

  if ((supported_axes & PhysicalAxes(kPhysicalAxesHorizontal)) !=
      PhysicalAxes(kPhysicalAxesNone)) {
    width = size.width.ToDouble();
  }

  if ((supported_axes & PhysicalAxes(kPhysicalAxesVertical)) !=
      PhysicalAxes(kPhysicalAxesNone)) {
    height = size.height.ToDouble();
  }

  auto* query_values = MakeGarbageCollected<CSSContainerValues>(
      container->GetDocument(), *container, width, height,
      existing_values.StuckHorizontal(), existing_values.StuckVertical(),
      existing_values.SnappedFlags(), existing_values.OverflowingHorizontal(),
      existing_values.OverflowingVertical());
  media_query_evaluator_ =
      MakeGarbageCollected<MediaQueryEvaluator>(query_values);
}

void ContainerQueryEvaluator::UpdateContainerStuck(
    ContainerStuckPhysical stuck_horizontal,
    ContainerStuckPhysical stuck_vertical) {
  stuck_horizontal_ = stuck_horizontal;
  stuck_vertical_ = stuck_vertical;

  const MediaValues& existing_values = media_query_evaluator_->GetMediaValues();
  Element* container = existing_values.ContainerElement();

  auto* query_values = MakeGarbageCollected<CSSContainerValues>(
      container->GetDocument(), *container, existing_values.Width(),
      existing_values.Height(), stuck_horizontal, stuck_vertical,
      existing_values.SnappedFlags(), existing_values.OverflowingHorizontal(),
      existing_values.OverflowingVertical());
  media_query_evaluator_ =
      MakeGarbageCollected<MediaQueryEvaluator>(query_values);
}

void ContainerQueryEvaluator::UpdateContainerSnapped(
    ContainerSnappedFlags snapped) {
  snapped_ = snapped;

  const MediaValues& existing_values = media_query_evaluator_->GetMediaValues();
  Element* container = existing_values.ContainerElement();

  auto* query_values = MakeGarbageCollected<CSSContainerValues>(
      container->GetDocument(), *container, existing_values.Width(),
      existing_values.Height(), existing_values.StuckHorizontal(),
      existing_values.StuckVertical(), snapped,
      existing_values.OverflowingHorizontal(),
      existing_values.OverflowingVertical());
  media_query_evaluator_ =
      MakeGarbageCollected<MediaQueryEvaluator>(query_values);
}

void ContainerQueryEvaluator::UpdateContainerOverflowing(
    ContainerOverflowingFlags overflowing_horizontal,
    ContainerOverflowingFlags overflowing_vertical) {
  overflowing_horizontal_ = overflowing_horizontal;
  overflowing_vertical_ = overflowing_horizontal;

  const MediaValues& existing_values = media_query_evaluator_->GetMediaValues();
  Element* container = existing_values.ContainerElement();

  auto* query_values = MakeGarbageCollected<CSSContainerValues>(
      container->GetDocument(), *container, existing_values.Width(),
      existing_values.Height(), existing_values.StuckHorizontal(),
      existing_values.StuckVertical(), existing_values.Snapped(),
      overflowing_horizontal, overflowing_vertical);
  media_query_evaluator_ =
      MakeGarbageCollected<MediaQueryEvaluator>(query_values);
}

void ContainerQueryEvaluator::ClearResults(Change change,
                                           ContainerType container_type) {
  if (change == Change::kNone) {
    return;
  }
  if (change == Change::kDescendantContainers) {
    if (container_type == kSizeContainer) {
      referenced_by_unit_ = false;
    } else {
      depends_on_style_ = false;
    }
  }
  unit_flags_ = 0;

  HeapHashMap<Member<const ContainerQuery>, Result> new_results;
  for (const auto& pair : results_) {
    if (pair.value.change <= change &&
        ((container_type == kSizeContainer &&
          pair.key->Selector().SelectsSizeContainers()) ||
         (container_type == kStickyContainer &&
          pair.key->Selector().SelectsStickyContainers()) ||
         (container_type == kSnapContainer &&
          pair.key->Selector().SelectsSnapContainers()) ||
         (container_type == kOverflowContainer &&
          pair.key->Selector().SelectsOverflowContainers()) ||
         (container_type == kStyleContainer &&
          pair.key->Selector().SelectsStyleContainers()))) {
      continue;
    }
    new_results.Set(pair.key, pair.value);
    unit_flags_ |= pair.value.unit_flags;
  }

  std::swap(new_results, results_);
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::ComputeSizeChange()
    const {
  Change change = Change::kNone;

  for (const auto& result : results_) {
    const ContainerQuery& query = *result.key;
    if (!query.Selector().SelectsSizeContainers()) {
      continue;
    }
    if (Eval(query).value != result.value.value) {
      change = std::max(result.value.change, change);
    }
  }

  return change;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::ComputeStyleChange()
    const {
  Change change = Change::kNone;

  for (const auto& result : results_) {
    const ContainerQuery& query = *result.key;
    if (!query.Selector().SelectsStyleContainers()) {
      continue;
    }
    if (Eval(query).value == result.value.value) {
      continue;
    }
    change = std::max(result.value.change, change);
  }

  return change;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::ComputeStickyChange()
    const {
  Change change = Change::kNone;

  for (const auto& result : results_) {
    const ContainerQuery& query = *result.key;
    if (!query.Selector().SelectsStickyContainers()) {
      continue;
    }
    if (Eval(query).value == result.value.value) {
      continue;
    }
    change = std::max(result.value.change, change);
  }

  return change;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::ComputeSnapChange()
    const {
  Change change = Change::kNone;

  for (const auto& result : results_) {
    const ContainerQuery& query = *result.key;
    if (!query.Selector().SelectsSnapContainers()) {
      continue;
    }
    if (Eval(query).value == result.value.value) {
      continue;
    }
    change = std::max(result.value.change, change);
  }

  return change;
}

ContainerQueryEvaluator::Change ContainerQueryEvaluator::ComputeOverflowChange()
    const {
  Change change = Change::kNone;

  for (const auto& result : results_) {
    const ContainerQuery& query = *result.key;
    if (!query.Selector().SelectsOverflowContainers()) {
      continue;
    }
    if (Eval(query).value == result.value.value) {
      continue;
    }
    change = std::max(result.value.change, change);
  }

  return change;
}

void ContainerQueryEvaluator::UpdateContainerValuesFromUnitChanges(
    StyleRecalcChange change) {
  CHECK(media_query_evaluator_);
  unsigned changed_flags = 0;
  if (change.RemUnitsMaybeChanged()) {
    changed_flags |= MediaQueryExpValue::kRootFontRelative;
  }
  if (change.ContainerRelativeUnitsMaybeChanged()) {
    changed_flags |= MediaQueryExpValue::kContainer;
  }
  if (!(unit_flags_ & changed_flags)) {
    return;
  }
  // We recreate both the MediaQueryEvaluator and the CSSContainerValues objects
  // here only to update the font-size etc from the current container style in
  // CSSContainerValues.
  UpdateContainerValues();
}

StyleRecalcChange ContainerQueryEvaluator::ApplyScrollStateAndStyleChanges(
    const StyleRecalcChange& child_change,
    const ComputedStyle& old_style,
    const ComputedStyle& new_style,
    bool style_changed) {
  StyleRecalcChange recalc_change = child_change;
  if (RuntimeEnabledFeatures::CSSStickyContainerQueriesEnabled() ||
      RuntimeEnabledFeatures::CSSSnapContainerQueriesEnabled() ||
      RuntimeEnabledFeatures::CSSOverflowContainerQueriesEnabled()) {
    switch (ApplyScrollState()) {
      case ContainerQueryEvaluator::Change::kNone:
        break;
      case ContainerQueryEvaluator::Change::kNearestContainer:
        recalc_change = recalc_change.ForceRecalcScrollStateContainer();
        break;
      case ContainerQueryEvaluator::Change::kDescendantContainers:
        recalc_change =
            recalc_change.ForceRecalcDescendantScrollStateContainers();
        break;
    }
  }

  if (!style_changed) {
    return recalc_change;
  }

  // If size container queries are expressed in font-relative units, the query
  // evaluation may change even if the size of the container in pixels did not
  // change. If the old and new style use different font properties, and there
  // are existing queries that depend on font relative units, we need to update
  // the container values and invalidate style for any changed queries.
  bool invalidate_for_font =
      (unit_flags_ & MediaQueryExpValue::kFontRelative) &&
      old_style.GetFont() != new_style.GetFont();

  // Writing direction changes may affect how logical queries match for size and
  // scroll-state() queries even when the physical size or scroll-state do not
  // change.
  bool invalidate_for_writing_direction =
      MayDependOnWritingDirection() &&
      old_style.GetWritingDirection() != new_style.GetWritingDirection();

  if (invalidate_for_writing_direction || invalidate_for_font) {
    // Writing direction and font sizing are cached on CSSContainerValues. Need
    // to recreate the values based on the current ComputedStyle.
    UpdateContainerValues();
  }

  if (invalidate_for_writing_direction || invalidate_for_font) {
    switch (StyleAffectingSizeChanged()) {
      case ContainerQueryEvaluator::Change::kNone:
        break;
      case ContainerQueryEvaluator::Change::kNearestContainer:
        recalc_change = recalc_change.ForceRecalcSizeContainer();
        break;
      case ContainerQueryEvaluator::Change::kDescendantContainers:
        recalc_change = recalc_change.ForceRecalcDescendantSizeContainers();
        break;
    }
  }
  if (invalidate_for_writing_direction) {
    if (RuntimeEnabledFeatures::CSSStickyContainerQueriesEnabled() ||
        RuntimeEnabledFeatures::CSSSnapContainerQueriesEnabled() ||
        RuntimeEnabledFeatures::CSSOverflowContainerQueriesEnabled()) {
      switch (StyleAffectingScrollStateChanged()) {
        case ContainerQueryEvaluator::Change::kNone:
          break;
        case ContainerQueryEvaluator::Change::kNearestContainer:
          recalc_change = recalc_change.ForceRecalcScrollStateContainer();
          break;
        case ContainerQueryEvaluator::Change::kDescendantContainers:
          recalc_change =
              recalc_change.ForceRecalcDescendantScrollStateContainers();
          break;
      }
    }
  }
  if (!base::ValuesEquivalent(old_style.InheritedVariables(),
                              new_style.InheritedVariables()) ||
      !base::ValuesEquivalent(old_style.NonInheritedVariables(),
                              new_style.NonInheritedVariables())) {
    switch (StyleContainerChanged()) {
      case ContainerQueryEvaluator::Change::kNone:
        break;
      case ContainerQueryEvaluator::Change::kNearestContainer:
        recalc_change = recalc_change.ForceRecalcStyleContainerChildren();
        break;
      case ContainerQueryEvaluator::Change::kDescendantContainers:
        recalc_change = recalc_change.ForceRecalcStyleContainerDescendants();
        break;
    }
  }
  return recalc_change;
}

Element* ContainerQueryEvaluator::ContainerElement() const {
  CHECK(media_query_evaluator_);
  return media_query_evaluator_->GetMediaValues().ContainerElement();
}

}  // namespace blink

"""

```