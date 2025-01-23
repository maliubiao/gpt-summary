Response:
Let's break down the thought process for analyzing the given C++ code. The goal is to understand its purpose, its relationship to web technologies, and potential usage scenarios and errors.

**1. Initial Code Scan and Keyword Spotting:**

* Immediately, the file name `check_pseudo_has_cache_scope.cc` and the namespace `blink` hint at a Chromium rendering engine component related to CSS pseudo-classes, specifically `:has()`.
* Keywords like `cache`, `result`, `filter`, `selector`, `element`, `document`, `traversal`, `argument`, `bloom filter` jump out. These are strong indicators of caching mechanisms for optimizing CSS selector matching, especially for the potentially expensive `:has()` pseudo-class.
* The `#include` directives confirm dependencies on CSS selector components (`css_selector.h`, `selector_checker.h`), DOM elements (`document.h`, `element_traversal.h`), and utility classes (`string_builder.h`).

**2. Understanding the Core Class: `CheckPseudoHasCacheScope`**

* **Constructor and Destructor:** The constructor takes a `Document*` and a `bool within_selector_checking`. The constructor and destructor manage a flag on the `Document` (`document_->GetCheckPseudoHasCacheScope()`) and call `EnterPseudoHasChecking()` and `LeavePseudoHasChecking()`. This suggests a lifecycle management role related to the `:has()` check within a document. The `within_selector_checking_` flag indicates whether this scope is being created during the core selector matching process.
* **`GetResultMap`:** This static method retrieves a cache (`ElementCheckPseudoHasResultMap`) associated with a specific CSS selector on a given document. The comment about "cache hit ratio" and "same cache key" reinforces the caching purpose. The use of `SelectorTextExpandingPseudoParent()` suggests the cache key is derived from the textual representation of the selector.
* **`GetFastRejectFilterMap`:** This static method retrieves another cache (`ElementCheckPseudoHasFastRejectFilterMap`), this time based on the `CheckPseudoHasArgumentTraversalType`. The name "fast reject filter" implies this cache is used for quickly ruling out elements that cannot possibly match the `:has()` condition.

**3. Analyzing the `Context` Inner Class:**

* **Constructor:**  The `Context` constructor takes a `Document*` and a `CheckPseudoHasArgumentContext&`. The `argument_context` seems to define the scope of the `:has()` check (e.g., subtree, siblings). The `switch` statement based on `TraversalScope()` determines if caching is allowed for the given scope. If allowed, it retrieves the relevant caches using the static methods of `CheckPseudoHasCacheScope`.
* **`SetMatchedAndGetOldResult`, `SetChecked`, `SetResultAndGetOld`:** These methods manipulate the `result_map_`, storing whether an element has been checked and if it matched the `:has()` condition. The `DCHECK` statements ensure internal consistency.
* **`SetTraversedElementAsChecked`, `SetAllTraversedElementsAsChecked`:** These methods update the cache to mark elements as checked during the traversal of the DOM to evaluate the `:has()` condition. The logic in `SetAllTraversedElementsAsChecked` is particularly interesting, showing different strategies for marking elements based on the traversal scope.
* **`GetResult`:** Retrieves the cached result for a given element.
* **`HasSiblingsWithAllDescendantsOrNextSiblingsChecked`, `HasAncestorsWithAllDescendantsOrNextSiblingsChecked`:** These methods check the cache to see if ancestor or sibling elements have already been fully checked, allowing for potential early exits in the `:has()` evaluation.
* **`AlreadyChecked`:** Combines the previous methods to determine if an element has already been considered within the current `:has()` evaluation context.
* **`EnsureFastRejectFilter`:** This is where the "bloom filter" comes in. It retrieves or creates a `CheckPseudoHasFastRejectFilter` associated with an element. The logic attempts to reuse existing filters from ancestor or sibling elements if their traversal scope is a superset, optimizing memory usage.
* **`GetBloomFilterAllocationCountForTesting`:**  A testing utility to count allocated bloom filters.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **CSS:** The core connection is to the `:has()` pseudo-class. This allows selecting elements based on whether they have descendants matching another selector. The code is directly involved in optimizing how `:has()` is evaluated. Example: `div:has(> p.highlight)` selects `div` elements that have a direct child paragraph with the class "highlight".
* **HTML:** The DOM structure represented by `Element` and `Document` is the target of the `:has()` evaluation. The code traverses the DOM tree to check the conditions specified in the `:has()` argument.
* **JavaScript:** While this C++ code doesn't directly interact with JavaScript, JavaScript can trigger style recalculations that involve this code. For instance, adding or removing elements, changing class names, or force-refreshing styles can lead to the execution of this code during CSS selector matching.

**5. Logical Reasoning and Examples:**

* **Assumption:**  The `:has()` pseudo-class can be computationally expensive, especially on large DOM trees.
* **Caching Strategy:** The code employs two main caching strategies:
    * **`ElementCheckPseudoHasResultMap`:** Caches the result (matched, not matched, checked) of evaluating the `:has()` condition for specific elements and selectors.
    * **`ElementCheckPseudoHasFastRejectFilterMap`:** Uses Bloom filters to quickly determine if an element *cannot* match the `:has()` condition, avoiding more expensive checks.
* **Input/Output (Conceptual):**
    * **Input:** A DOM `Element`, a CSS selector containing `:has()`, and the current state of the document's style.
    * **Output:**  Whether the `Element` matches the selector, potentially retrieved from the cache or determined through traversal. The caches are updated as a side effect.

**6. Common User/Programming Errors:**

* **Overly Complex `:has()` Selectors:**  Nesting `:has()` or using very broad selectors within `:has()` can still lead to performance issues even with caching. Example: `body :has(div :has(span))` will trigger extensive DOM traversal.
* **Dynamic DOM Manipulation:** Frequent and large-scale DOM changes can invalidate the cache, leading to more cache misses and reduced performance benefits.
* **Incorrect Understanding of `:has()` Scope:**  Developers might misunderstand the traversal scope of `:has()`, leading to unexpected matching behavior. The different `TraversalScope` options in the code reflect this complexity.

**7. Debugging Clues and User Operations:**

* **Performance Profiling:**  Developers might notice slow style recalculations or layout times when using `:has()`. Profiling tools in Chromium DevTools could point to CSS selector matching as a bottleneck.
* **Inspecting Style Rules:** Examining the computed styles of an element in DevTools might reveal that a `:has()` rule is being applied (or not applied) as expected.
* **DOM Mutation Observation:**  Tracking DOM changes with JavaScript's `MutationObserver` can help understand when and how often the `:has()` evaluation might be triggered.
* **Step-by-Step Debugging (Advanced):** A Chromium developer could set breakpoints in `check_pseudo_has_cache_scope.cc` (or related files like `selector_checker.cc`) to trace the execution flow during style calculation, especially when a `:has()` selector is involved. The `EnterPseudoHasChecking` and `LeavePseudoHasChecking` calls, as well as the cache lookups, would be key points of interest.

By following this thought process, combining code analysis with knowledge of web technologies and potential use cases, we arrive at a comprehensive understanding of the provided C++ code.
这个文件 `blink/renderer/core/css/check_pseudo_has_cache_scope.cc` 的主要功能是**为 CSS `:has()` 伪类选择器的匹配过程提供缓存机制，以提高性能。**

更具体地说，它管理着用于存储和检索 `:has()` 伪类匹配结果的缓存。这个缓存可以避免在每次需要检查 `:has()` 条件时都重新遍历 DOM 树，从而显著优化性能。

以下是该文件的关键功能点：

* **创建和管理缓存作用域:**  `CheckPseudoHasCacheScope` 类负责创建一个与特定 `Document` 关联的缓存作用域。这个作用域在 `:has()` 伪类选择器检查开始时创建，并在检查结束后销毁。
* **存储匹配结果:**  通过 `GetResultMap` 方法获取的 `ElementCheckPseudoHasResultMap` 用于存储元素是否匹配特定 `:has()` 选择器的结果。这避免了重复的 DOM 遍历。
* **存储快速拒绝过滤器:** 通过 `GetFastRejectFilterMap` 方法获取的 `ElementCheckPseudoHasFastRejectFilterMap` 用于存储快速拒绝过滤器。这些过滤器（通常是 Bloom 过滤器）可以快速判断某个元素是否 *不可能* 匹配 `:has()` 选择器，从而避免更昂贵的检查。
* **提供上下文信息:** `Context` 内部类提供了在 `:has()` 检查过程中使用的上下文信息，包括允许缓存、结果缓存的引用以及快速拒绝过滤器缓存的引用。
* **记录检查状态:** `Context` 类中的方法（例如 `SetMatchedAndGetOldResult`, `SetChecked`, `SetTraversedElementAsChecked`）用于更新缓存中元素的检查和匹配状态。
* **查询缓存结果:** `Context` 类中的 `GetResult` 方法用于从缓存中检索元素的匹配结果。
* **优化遍历:**  `Context` 类中的方法（例如 `AlreadyChecked`, `HasSiblingsWithAllDescendantsOrNextSiblingsChecked`, `HasAncestorsWithAllDescendantsOrNextSiblingsChecked`)  利用缓存的信息来优化 DOM 遍历，避免重复检查已经确定结果的元素或分支。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接服务于 **CSS** 的功能，特别是 `:has()` 伪类选择器。它通过优化 `:has()` 的匹配过程，间接地提高了使用这些选择器的网页的性能。

* **CSS:**
    * **功能关系:** 该文件是 Blink 渲染引擎实现和优化 CSS `:has()` 伪类选择器的一部分。`:has()` 允许我们选择包含匹配特定选择器的后代元素的元素。
    * **举例说明:** 考虑以下 CSS 规则：
      ```css
      div:has(> p.highlight) {
        background-color: yellow;
      }
      ```
      这个规则会选择所有直接包含带有 `highlight` 类名的 `<p>` 元素的 `<div>` 元素，并将它们的背景色设置为黄色。`check_pseudo_has_cache_scope.cc` 的代码会在评估这个规则时被调用，用于缓存 `:has(> p.highlight)` 的匹配结果，以便在后续的样式计算中快速重用，特别是当 DOM 结构没有发生变化时。

* **HTML:**
    * **功能关系:**  CSS 选择器作用于 HTML 构成的 DOM 树。 `:has()` 伪类的匹配需要在 DOM 树中进行查找。
    * **举例说明:**  对于以下 HTML 结构：
      ```html
      <div>
        <p>普通段落</p>
        <p class="highlight">高亮段落</p>
      </div>
      <div>
        <p>另一个普通段落</p>
      </div>
      ```
      当浏览器应用上述 CSS 规则时，`check_pseudo_has_cache_scope.cc` 的代码会遍历 DOM 树，检查每个 `<div>` 元素是否直接包含 `<p class="highlight">`。缓存会记录哪些 `<div>` 匹配了 `:has()` 条件，以便下次重新计算样式时可以更快地确定结果。

* **JavaScript:**
    * **功能关系:** JavaScript 可以动态修改 DOM 结构和元素属性，这可能会导致 CSS 样式的重新计算，从而触发 `:has()` 伪类的重新评估。
    * **举例说明:**  假设有 JavaScript 代码动态地给一个 `<p>` 元素添加了 `highlight` 类：
      ```javascript
      const p = document.querySelector('div:nth-child(2) > p');
      p.classList.add('highlight');
      ```
      在这个操作之后，浏览器的渲染引擎需要重新计算样式。`check_pseudo_has_cache_scope.cc` 中的缓存机制可以帮助加速这个过程。如果没有缓存，引擎可能需要重新遍历整个 DOM 树来检查 `:has()` 条件。有了缓存，引擎可以先检查缓存中是否有相关的结果，如果有，则直接使用，避免重复的 DOM 遍历。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **文档对象 (Document):**  一个包含了 HTML 内容的 `Document` 对象。
2. **CSS 选择器 (CSSSelector):** 一个包含 `:has()` 伪类的 CSS 选择器，例如 `div:has(> .my-class)`.
3. **目标元素 (Element):**  DOM 树中的一个 `Element` 对象，需要判断它是否匹配该 CSS 选择器。

**逻辑推理过程 (简化):**

1. `CheckPseudoHasCacheScope` 对象被创建，与 `Document` 关联。
2. `SelectorChecker` 使用 `:has()` 选择器的参数创建一个 `CheckPseudoHasArgumentContext`。
3. 创建一个 `CheckPseudoHasCacheScope::Context` 对象，该对象会尝试从缓存中获取之前对该元素和选择器的匹配结果。
4. 如果缓存中存在结果，则直接返回缓存的结果 (匹配或不匹配)。
5. 如果缓存中没有结果，则需要进行 DOM 遍历来评估 `:has()` 条件。
6. 在遍历过程中，`Context` 对象会使用 `GetFastRejectFilterMap` 获取快速拒绝过滤器，尝试快速排除不匹配的元素。
7. 对于需要检查的元素，`Context` 对象会调用 `SetMatchedAndGetOldResult` 或 `SetChecked` 等方法来更新缓存，记录该元素的检查状态和匹配结果。
8. 如果 `:has()` 条件匹配，则在缓存中标记该元素为匹配。
9. 如果 `:has()` 条件不匹配，则在缓存中标记该元素为已检查但不匹配。
10. 遍历完成后，最初的目标元素的匹配结果被确定。

**输出:**

*   **匹配结果 (bool):**  目标元素是否匹配输入的 CSS 选择器。
*   **缓存更新:**  `ElementCheckPseudoHasResultMap` 和 `ElementCheckPseudoHasFastRejectFilterMap` 可能会被更新，存储了本次检查的结果，以便后续使用。

**用户或编程常见的使用错误:**

1. **过度复杂的 `:has()` 选择器:**  编写过于复杂的 `:has()` 选择器，例如嵌套多层 `:has()` 或在 `:has()` 中使用性能较差的选择器，仍然可能导致性能问题，即使有缓存机制。例如： `body :has(div :has(span.important))`。虽然缓存可以减少重复计算，但首次计算的成本可能仍然很高。
2. **频繁的 DOM 结构变动:**  当页面的 DOM 结构频繁变动时，缓存可能会失效，导致缓存命中率降低，无法充分发挥缓存的优势。例如，在一个富交互应用中，如果频繁地添加、删除或移动元素，与这些元素相关的 `:has()` 缓存可能需要频繁更新或失效。
3. **错误理解 `:has()` 的作用域:**  开发者可能不清楚 `:has()` 检查的范围，导致预期之外的匹配结果。例如，误以为 `:has()` 只检查直接子元素，而实际上它会检查所有后代元素（除非使用了组合符如 `>`）。

**用户操作如何一步步到达这里作为调试线索:**

作为一个最终用户，你不太可能直接触发 `check_pseudo_has_cache_scope.cc` 的代码。这个文件是浏览器引擎内部的实现。但是，以下用户操作会导致浏览器执行 CSS 样式计算，从而可能涉及到这个文件：

1. **加载网页:** 当你打开一个包含使用 `:has()` 伪类的 CSS 规则的网页时，浏览器会解析 CSS 并尝试匹配元素，这时会用到缓存机制。
2. **与网页交互:**  用户与网页的交互（例如，鼠标悬停、点击、滚动、输入等）可能会触发 JavaScript 代码执行，这些代码可能会修改 DOM 结构或元素属性。
3. **动态修改样式:**  JavaScript 代码可以直接修改元素的样式或添加/删除 CSS 类，这会导致浏览器重新计算样式。
4. **浏览器窗口大小调整或滚动:**  这些操作也可能触发样式的重新计算，特别是当 CSS 中使用了视口单位（如 `vw`, `vh`）或者有依赖于滚动位置的样式时。

**作为调试线索:**

如果你是 Chromium 的开发者，想要调试与 `:has()` 相关的性能问题或错误，可以按照以下步骤：

1. **识别使用 `:has()` 的 CSS 规则:**  在开发者工具中，检查元素的“Computed”或“Styles”面板，找到应用到该元素的包含 `:has()` 伪类的 CSS 规则。
2. **使用性能分析工具:**  使用 Chrome DevTools 的 Performance 面板录制网页加载或交互过程，分析“Rendering”或“Recalculate Style”部分，查看是否有大量的样式计算耗时与 `:has()` 相关。
3. **设置断点:**  在 `check_pseudo_has_cache_scope.cc` 文件中的关键方法（例如 `GetResult`, `SetMatchedAndGetOldResult`）设置断点，然后重新加载或操作网页，观察代码的执行流程和缓存的使用情况。
4. **查看日志输出:**  Blink 引擎可能会有相关的调试日志输出，可以配置编译选项来启用更详细的日志，以了解 `:has()` 匹配和缓存的详细过程。
5. **分析缓存命中率:**  虽然代码中没有直接暴露缓存命中率的接口，但可以通过在关键路径上添加计数器来统计缓存的命中和未命中次数，从而评估缓存的效果。

总而言之，`check_pseudo_has_cache_scope.cc` 是 Chromium Blink 引擎中一个关键的性能优化组件，专门用于提高 CSS `:has()` 伪类选择器的匹配效率，通过缓存机制避免重复的 DOM 遍历。理解其功能有助于开发者编写更高效的 CSS 代码，并有助于 Chromium 开发者调试与 `:has()` 相关的性能问题。

### 提示词
```
这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"

#include "third_party/blink/renderer/core/css/check_pseudo_has_argument_context.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/selector_checker.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

CheckPseudoHasCacheScope::CheckPseudoHasCacheScope(
    Document* document,
    bool within_selector_checking)
    : document_(document), within_selector_checking_(within_selector_checking) {
  DCHECK(document_);

  if (within_selector_checking) {
    document_->EnterPseudoHasChecking();
  }

  if (document_->GetCheckPseudoHasCacheScope()) {
    return;
  }

  document_->SetCheckPseudoHasCacheScope(this);
}

CheckPseudoHasCacheScope::~CheckPseudoHasCacheScope() {
  if (within_selector_checking_) {
    document_->LeavePseudoHasChecking();
  }
  if (document_->GetCheckPseudoHasCacheScope() != this) {
    return;
  }

  document_->SetCheckPseudoHasCacheScope(nullptr);
}

// static
ElementCheckPseudoHasResultMap& CheckPseudoHasCacheScope::GetResultMap(
    const Document* document,
    const CSSSelector* selector) {
  // To increase the cache hit ratio, we need to have a same cache key
  // for multiple selector instances those are actually has a same selector.
  // TODO(blee@igalia.com) Find a way to get hash key without serialization.
  String selector_text = selector->SelectorTextExpandingPseudoParent();

  DCHECK(document);
  DCHECK(document->GetCheckPseudoHasCacheScope());

  auto entry = document->GetCheckPseudoHasCacheScope()->GetResultCache().insert(
      selector_text, nullptr);
  if (entry.is_new_entry) {
    entry.stored_value->value =
        MakeGarbageCollected<ElementCheckPseudoHasResultMap>();
  }
  DCHECK(entry.stored_value->value);
  return *entry.stored_value->value;
}

// static
ElementCheckPseudoHasFastRejectFilterMap&
CheckPseudoHasCacheScope::GetFastRejectFilterMap(
    const Document* document,
    CheckPseudoHasArgumentTraversalType traversal_type) {
  DCHECK(document);
  DCHECK(document->GetCheckPseudoHasCacheScope());

  auto entry = document->GetCheckPseudoHasCacheScope()
                   ->GetFastRejectFilterCache()
                   .insert(traversal_type, nullptr);
  if (entry.is_new_entry) {
    entry.stored_value->value =
        MakeGarbageCollected<ElementCheckPseudoHasFastRejectFilterMap>();
  }
  DCHECK(entry.stored_value->value);
  return *entry.stored_value->value;
}

CheckPseudoHasCacheScope::Context::Context(
    const Document* document,
    const CheckPseudoHasArgumentContext& argument_context)
    : argument_context_(argument_context) {
  switch (argument_context_.TraversalScope()) {
    case CheckPseudoHasArgumentTraversalScope::kSubtree:
    case CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree:
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees:
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblings:
      cache_allowed_ = true;
      result_map_ = &CheckPseudoHasCacheScope::GetResultMap(
          document, argument_context.HasArgument());
      fast_reject_filter_map_ =
          &CheckPseudoHasCacheScope::GetFastRejectFilterMap(
              document, argument_context.TraversalType());
      break;
    default:
      cache_allowed_ = false;
      break;
  }
}

CheckPseudoHasResult
CheckPseudoHasCacheScope::Context::SetMatchedAndGetOldResult(Element* element) {
  return SetResultAndGetOld(
      element, kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched);
}

void CheckPseudoHasCacheScope::Context::SetChecked(Element* element) {
  SetResultAndGetOld(element, kCheckPseudoHasResultChecked);
}

CheckPseudoHasResult CheckPseudoHasCacheScope::Context::SetResultAndGetOld(
    Element* element,
    CheckPseudoHasResult result) {
  DCHECK(cache_allowed_);
  DCHECK(result_map_);
  CheckPseudoHasResult old_result = kCheckPseudoHasResultNotCached;
  auto cache_result = result_map_->insert(element, result);
  if (!cache_result.is_new_entry) {
    old_result = cache_result.stored_value->value;
    cache_result.stored_value->value |= result;
  }

  // kCheckPseudoHasResultMatched must set with kCheckPseudoHasResultChecked
  DCHECK_NE(cache_result.stored_value->value &
                (kCheckPseudoHasResultMatched | kCheckPseudoHasResultChecked),
            kCheckPseudoHasResultMatched);

  // kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked must set with
  // kCheckPseudoHasResultChecked
  DCHECK_NE(cache_result.stored_value->value &
                (kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked |
                 kCheckPseudoHasResultChecked),
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked);

  return old_result;
}

void CheckPseudoHasCacheScope::Context::SetTraversedElementAsChecked(
    Element* traversed_element,
    Element* parent) {
  DCHECK(traversed_element);
  DCHECK(parent);
  DCHECK_EQ(traversed_element->parentElement(), parent);
  SetResultAndGetOld(
      traversed_element,
      kCheckPseudoHasResultChecked |
          kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked);
  SetResultAndGetOld(parent, kCheckPseudoHasResultSomeChildrenChecked);
}

void CheckPseudoHasCacheScope::Context::SetAllTraversedElementsAsChecked(
    Element* last_traversed_element,
    int last_traversed_depth) {
  DCHECK(last_traversed_element);
  switch (argument_context_.TraversalScope()) {
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees:
      if (last_traversed_depth == 1 &&
          !ElementTraversal::PreviousSibling(*last_traversed_element)) {
        // The :has() argument checking traversal stopped at the first child of
        // a depth 0 element. It means that, all the descendants of the depth 0
        // element were checked. In this case, we can set the depth 0 element as
        // '[NotMatched|Matched]AndAllDescendantsOrNextSiblingsChecked' instead
        // of setting it as '[NotCached|Matched]AndSomeChildrenChecked'.
        // We can skip the following :has() checking operation of the depth 0
        // element with the cached checking result ('NotMatched' or 'Matched').
        Element* parent = last_traversed_element->parentElement();
        SetTraversedElementAsChecked(parent, parent->parentElement());
        break;
      }
      [[fallthrough]];
    case CheckPseudoHasArgumentTraversalScope::kSubtree:
    case CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree: {
      // Mark the traversed elements in the subtree or next sibling subtree
      // of the :has() anchor element as checked.
      Element* element = last_traversed_element;
      Element* parent = element->parentElement();
      int depth = last_traversed_depth;
      for (; depth > 0; --depth) {
        if (element) {
          SetTraversedElementAsChecked(element, parent);
        }
        element = ElementTraversal::NextSibling(*parent);
        parent = parent->parentElement();
      }

      // If the argument checking traverses all the next siblings' subtrees,
      // it guarantees that we can get all the possibly matched next siblings.
      // By marking all the traversed next siblings as checked, we can skip
      // to check :has() on the already-checked next siblings.
      if (argument_context_.TraversalScope() ==
              CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees &&
          element) {
        SetTraversedElementAsChecked(element, parent);
      }
    } break;
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblings:
      DCHECK_EQ(last_traversed_depth, 0);
      // Mark the last traversed element and all its next siblings as checked.
      SetTraversedElementAsChecked(last_traversed_element,
                                   last_traversed_element->parentElement());
      break;
    default:
      break;
  }
}

CheckPseudoHasResult CheckPseudoHasCacheScope::Context::GetResult(
    Element* element) const {
  DCHECK(cache_allowed_);
  DCHECK(result_map_);
  auto iterator = result_map_->find(element);
  return iterator == result_map_->end() ? kCheckPseudoHasResultNotCached
                                        : iterator->value;
}

bool CheckPseudoHasCacheScope::Context::
    HasSiblingsWithAllDescendantsOrNextSiblingsChecked(Element* element) const {
  for (Element* sibling = ElementTraversal::PreviousSibling(*element); sibling;
       sibling = ElementTraversal::PreviousSibling(*sibling)) {
    CheckPseudoHasResult sibling_result = GetResult(sibling);
    if (sibling_result == kCheckPseudoHasResultNotCached) {
      continue;
    }
    if (sibling_result &
        kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked) {
      return true;
    }
  }
  return false;
}

bool CheckPseudoHasCacheScope::Context::
    HasAncestorsWithAllDescendantsOrNextSiblingsChecked(
        Element* element) const {
  for (Element* parent = element->parentElement(); parent;
       element = parent, parent = element->parentElement()) {
    CheckPseudoHasResult parent_result = GetResult(parent);
    if (parent_result == kCheckPseudoHasResultNotCached) {
      continue;
    }
    if (parent_result &
        kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked) {
      return true;
    }
    if (parent_result & kCheckPseudoHasResultSomeChildrenChecked) {
      if (HasSiblingsWithAllDescendantsOrNextSiblingsChecked(element)) {
        return true;
      }
    }
  }
  return false;
}

bool CheckPseudoHasCacheScope::Context::AlreadyChecked(Element* element) const {
  switch (argument_context_.TraversalScope()) {
    case CheckPseudoHasArgumentTraversalScope::kSubtree:
    case CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree:
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees:
      return HasAncestorsWithAllDescendantsOrNextSiblingsChecked(element);
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblings:
      if (Element* parent = element->parentElement()) {
        if (!(GetResult(parent) & kCheckPseudoHasResultSomeChildrenChecked)) {
          return false;
        }
        return HasSiblingsWithAllDescendantsOrNextSiblingsChecked(element);
      }
      break;
    default:
      break;
  }
  return false;
}

CheckPseudoHasFastRejectFilter&
CheckPseudoHasCacheScope::Context::EnsureFastRejectFilter(Element* element,
                                                          bool& is_new_entry) {
  DCHECK(element);
  DCHECK(cache_allowed_);
  DCHECK(fast_reject_filter_map_);

  is_new_entry = false;

  // In order to minimize memory consumption, if the traversal scope of an
  // other element is a superset of the traversal scope of the target element,
  // use the less accurate fast reject filter of the other element.
  switch (argument_context_.TraversalScope()) {
    case CheckPseudoHasArgumentTraversalScope::kSubtree:
      for (Element* parent = element->parentElement(); parent;
           parent = parent->parentElement()) {
        auto iterator = fast_reject_filter_map_->find(parent);
        if (iterator == fast_reject_filter_map_->end()) {
          continue;
        }
        if (!iterator->value->BloomFilterAllocated()) {
          continue;
        }
        return *iterator->value.get();
      }
      break;
    case CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree:
      for (Element* parent = element->parentElement(); parent;
           parent = parent->parentElement()) {
        Element* sibling = ElementTraversal::PreviousSibling(*parent);
        for (int i = argument_context_.AdjacentDistanceLimit() - 1;
             sibling && i >= 0;
             sibling = ElementTraversal::PreviousSibling(*sibling), --i) {
        }
        if (!sibling) {
          continue;
        }
        auto iterator = fast_reject_filter_map_->find(sibling);
        if (iterator == fast_reject_filter_map_->end()) {
          continue;
        }
        if (!iterator->value->BloomFilterAllocated()) {
          continue;
        }
        return *iterator->value.get();
      }
      break;
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees:
      for (Element* parent = element->parentElement(); parent;
           parent = parent->parentElement()) {
        for (Element* sibling = ElementTraversal::PreviousSibling(*parent);
             sibling; sibling = ElementTraversal::PreviousSibling(*sibling)) {
          auto iterator = fast_reject_filter_map_->find(sibling);
          if (iterator == fast_reject_filter_map_->end()) {
            continue;
          }
          if (!iterator->value->BloomFilterAllocated()) {
            continue;
          }
          return *iterator->value.get();
        }
      }
      break;
    case CheckPseudoHasArgumentTraversalScope::kAllNextSiblings:
      for (Element* sibling = ElementTraversal::PreviousSibling(*element);
           sibling; sibling = ElementTraversal::PreviousSibling(*sibling)) {
        auto iterator = fast_reject_filter_map_->find(sibling);
        if (iterator == fast_reject_filter_map_->end()) {
          continue;
        }
        if (!iterator->value->BloomFilterAllocated()) {
          continue;
        }
        return *iterator->value.get();
      }
      break;
    default:
      NOTREACHED();
  }

  auto entry = fast_reject_filter_map_->insert(element, nullptr);
  if (entry.is_new_entry) {
    entry.stored_value->value =
        std::make_unique<CheckPseudoHasFastRejectFilter>();
    is_new_entry = true;
  }
  DCHECK(entry.stored_value->value);
  return *entry.stored_value->value.get();
}

size_t
CheckPseudoHasCacheScope::Context::GetBloomFilterAllocationCountForTesting()
    const {
  if (!cache_allowed_) {
    return 0;
  }
  size_t bloom_filter_allocation_count = 0;
  for (const auto& iterator : *fast_reject_filter_map_) {
    if (iterator.value->BloomFilterAllocated()) {
      bloom_filter_allocation_count++;
    }
  }
  return bloom_filter_allocation_count;
}

}  // namespace blink
```