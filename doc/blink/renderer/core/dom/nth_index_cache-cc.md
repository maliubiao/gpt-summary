Response:
My thought process to analyze the `nth_index_cache.cc` file goes through several stages:

1. **Understanding the Core Purpose:** I first read the file headers and the main class definition (`NthIndexCache`). The comments clearly state its purpose: to cache the indices of elements based on `:nth-child` and `:nth-of-type` CSS selectors. This immediately tells me it's an optimization technique.

2. **Identifying Key Data Structures:**  I look for the main data structures used. The `NthIndexCache` itself has a `cache_` member, which is a `HeapHashMap`. The keys of this map are of type `Key`, and the values are of type `NthIndexData`. I then examine these key and value classes. `Key` stores the parent node and the CSS selector filter (or tag name for `nth-of-type`). `NthIndexData` stores a mapping of elements to their cached indices (`element_index_map_`) and the total count of relevant elements.

3. **Analyzing Key Methods:** I then go through the important methods of `NthIndexCache`:
    * **Constructors/Destructor:** How is the cache created and destroyed? It's tied to the `Document` lifecycle.
    * **`NthChildIndex`, `NthLastChildIndex`, `NthOfTypeIndex`, `NthLastOfTypeIndex`:** These are the core functions for retrieving the indices. I note the logic: they first check the cache, and if the data is not present, they calculate it and potentially cache it.
    * **`UncachedNthChildIndex`, `UncachedNthLastChildIndex`, `UncachedNthOfTypeIndex`:** These are the non-cached versions of the index calculation, providing the baseline logic.
    * **`MatchesFilter`:**  This function checks if an element matches a given CSS selector, crucial for `:nth-child` with selectors.
    * **`CacheNthIndexDataForParent`, `CacheNthOfTypeIndexDataForParent`:** These methods populate the cache. I observe the `kCachedSiblingCountLimit` which triggers caching for performance.
    * **`EnsureCache`:** Ensures the cache map is initialized.

4. **Connecting to Web Technologies:** Based on the method names and the use of CSS selectors, it's clear this code directly relates to CSS pseudo-classes like `:nth-child`, `:nth-last-child`, `:nth-of-type`, and `:nth-last-of-type`. The interaction with `CSSSelectorList` and `SelectorChecker` confirms this. The mention of `Element` and `Document` links it to the HTML DOM structure. JavaScript interacts with the DOM, so any changes to the DOM structure or CSS that trigger these pseudo-classes will involve this code.

5. **Inferring Logic and Assumptions:**
    * **Caching Strategy:** The code caches index data per parent node and filter/tag name. This makes sense as `:nth-child` and `:nth-of-type` are relative to siblings.
    * **Performance Optimization:** The `kCachedSiblingCountLimit` and the "spread" value in `NthIndexData`'s constructor suggest optimizations to balance memory usage and lookup speed. Caching is only done when there are enough siblings to make it worthwhile. The spread reduces memory by not caching every element's index.
    * **Invalidation:** The code doesn't explicitly show cache invalidation. I infer that changes to the DOM tree (adding/removing/reordering elements) would likely lead to the cache being discarded or rebuilt, possibly triggered by the `dom_tree_version_` check in debug mode.

6. **Considering User/Developer Errors:**  Since this is internal Blink code, direct user errors are less likely. However, developers writing complex CSS selectors with many `:nth-child` or `:nth-of-type` selectors on large lists could inadvertently trigger performance issues if the caching wasn't in place or efficient.

7. **Tracing User Actions (Debugging Clues):**  I think about how a user action leads to this code being executed. A user interacts with a webpage, causing changes in the DOM or triggering CSS style calculations. Specifically, if the CSS includes `:nth-child` or `:nth-of-type` selectors, and the browser needs to determine which elements match those selectors, it will need to calculate the index of those elements, potentially using the `NthIndexCache`. Developer tools' "Elements" panel, especially when inspecting elements with these pseudo-classes applied, could trigger this code.

8. **Structuring the Answer:** I organize my findings into the requested categories: functionality, relationship to web technologies, logic/assumptions, potential errors, and debugging clues. I use clear examples to illustrate the connections to JavaScript, HTML, and CSS.

By following these steps, I can systematically analyze the code and extract the relevant information to answer the prompt comprehensively. The key is to understand the *what*, *why*, and *how* of the code within the context of a web browser engine.
好的，我们来详细分析一下 `blink/renderer/core/dom/nth_index_cache.cc` 这个文件。

**功能概要**

`NthIndexCache` 的主要功能是**缓存 DOM 元素在兄弟节点中的索引位置**，以便在处理 CSS 伪类选择器 `:nth-child`, `:nth-last-child`, `:nth-of-type`, 和 `:nth-last-of-type` 时提高性能。

具体来说，它做了以下事情：

1. **存储和管理缓存:**  它使用一个哈希映射 (`HeapHashMap`) 来存储已计算的索引信息。缓存的键（`Key`）由父元素和用于过滤的 CSS 选择器列表（或者标签名，对于 `nth-of-type`）组成。缓存的值（`NthIndexData`）包含了实际的索引数据。
2. **计算元素的索引:**  当需要获取一个元素的 `nth-child` 或 `nth-of-type` 索引时，它首先尝试从缓存中查找。如果缓存命中，则直接返回缓存的值。如果缓存未命中，则会进行实际的 DOM 遍历来计算索引。
3. **缓存计算结果:**  为了避免重复计算，在首次计算出索引后，`NthIndexCache` 会将结果存储到缓存中，以便下次访问相同父元素和选择器的子元素时可以直接使用。
4. **优化缓存策略:**  为了平衡性能和内存使用，缓存并不是针对所有情况都启用。它会根据兄弟节点的数量 (`kCachedSiblingCountLimit`) 来决定是否进行缓存。只有当兄弟节点数量超过一定阈值时，才会触发缓存。另外，`NthIndexData` 内部也会采用一定的策略 (`kSpread`) 来决定缓存哪些元素的索引，以减少内存占用。
5. **处理带过滤器的 `nth-child`:**  `NthIndexCache` 可以处理带有选择器过滤器的 `:nth-child(an+b of <selector-list>)` 这种形式，它会根据提供的选择器列表来确定哪些兄弟节点应该被计入索引。
6. **与 `Document` 关联:**  每个 `Document` 对象都会有一个关联的 `NthIndexCache` 实例，用于管理该文档中的索引缓存。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`NthIndexCache` 的核心作用是为 CSS 选择器提供性能优化，这些选择器又常被 JavaScript 用于查询和操作 DOM。

* **CSS:**
    * **`:nth-child(n)`:**  当 CSS 规则中使用 `:nth-child(n)` 时，浏览器需要确定元素在其父元素的所有子元素中的位置。`NthIndexCache` 可以缓存这些信息，加速样式计算。
        * **例子:**
          ```html
          <ul>
            <li>Item 1</li>
            <li>Item 2</li>
            <li>Item 3</li>
          </ul>
          ```
          ```css
          li:nth-child(2) { color: blue; }
          ```
          当浏览器渲染这个页面时，`NthIndexCache` 可能会被用来快速确定第二个 `<li>` 元素。

    * **`:nth-last-child(n)`:**  类似于 `:nth-child`，但是从后向前计数。
        * **例子:**
          ```css
          li:nth-last-child(1) { font-weight: bold; }
          ```
          `NthIndexCache` 可以加速找到最后一个 `<li>` 元素。

    * **`:nth-of-type(n)`:**  选择父元素下特定类型的第 n 个子元素。
        * **例子:**
          ```html
          <div>
            <p>Paragraph 1</p>
            <span>Span 1</span>
            <p>Paragraph 2</p>
          </div>
          ```
          ```css
          p:nth-of-type(2) { text-decoration: underline; }
          ```
          `NthIndexCache` 可以帮助快速找到第二个 `<p>` 元素。

    * **`:nth-last-of-type(n)`:**  类似于 `:nth-of-type`，但是从后向前计数。
        * **例子:**
          ```css
          p:nth-last-of-type(1) { font-style: italic; }
          ```
          `NthIndexCache` 可以加速找到最后一个 `<p>` 元素。

    * **`:nth-child(an+b of <selector-list>)` 和 `:nth-last-child(an+b of <selector-list>)`:**  允许基于选择器列表进行过滤的 `nth-child`。
        * **例子:**
          ```html
          <ul>
            <li class="highlight">Item 1</li>
            <li>Item 2</li>
            <li class="highlight">Item 3</li>
            <li>Item 4</li>
          </ul>
          ```
          ```css
          li:nth-child(odd of .highlight) { background-color: yellow; }
          ```
          `NthIndexCache` 会根据 `.highlight` 选择器过滤兄弟节点，然后计算奇数位置的元素。

* **JavaScript:**
    * **`querySelector()` 和 `querySelectorAll()`:**  当 JavaScript 使用这些方法，并且选择器中包含 `:nth-child` 或 `:nth-of-type` 等伪类时，Blink 引擎会使用 `NthIndexCache` 来提高查询效率。
        * **例子:**
          ```javascript
          const secondListItem = document.querySelector('ul > li:nth-child(2)');
          ```
          在这个例子中，`NthIndexCache` 可以帮助快速定位到第二个 `<li>` 元素。

* **HTML:**
    * HTML 结构是 `NthIndexCache` 工作的对象。元素的父子关系和兄弟关系决定了索引的计算。

**逻辑推理（假设输入与输出）**

假设我们有以下 HTML 结构：

```html
<div id="parent">
  <p class="item">Item 1</p>
  <p class="item">Item 2</p>
  <span>Span 1</span>
  <p class="item">Item 3</p>
</div>
```

并且有以下 CSS 规则：

```css
#parent p.item:nth-child(odd) { color: red; }
#parent p:nth-of-type(even) { font-weight: bold; }
```

**假设输入:**

1. **对于 `#parent p.item:nth-child(odd)`:**
    *   `element`: 第一个 `<p class="item">` 元素 (Item 1)
    *   `filter`: `.item` 选择器 (隐含在 `:nth-child(odd)`)
    *   `parent`: `#parent` 元素

2. **对于 `#parent p:nth-of-type(even)`:**
    *   `element`: 第二个 `<p class="item">` 元素 (Item 2)
    *   `tagName`: `p`
    *   `parent`: `#parent` 元素

**逻辑推理过程 (简化):**

1. **`:nth-child(odd)`:**
    *   `NthIndexCache` 查找是否缓存了 `parent=#parent`, `filter=.item` 的信息。
    *   如果未缓存，则遍历 `#parent` 的子节点，只计算带有 `.item` class 的元素的位置。
    *   对于 "Item 1"，它是 `#parent` 下第一个 `.item` 元素，索引为 1 (奇数)。
    *   对于 "Item 3"，它是 `#parent` 下第三个 `.item` 元素，索引为 3 (奇数)。
    *   缓存 `#parent` 和 `.item` 相关的索引信息。

2. **`:nth-of-type(even)`:**
    *   `NthIndexCache` 查找是否缓存了 `parent=#parent`, `tagName=p` 的信息。
    *   如果未缓存，则遍历 `#parent` 的子节点，只计算 `<p>` 元素的位置。
    *   对于 "Item 2"，它是 `#parent` 下第二个 `<p>` 元素，索引为 2 (偶数)。
    *   缓存 `#parent` 和 `p` 相关的索引信息。

**假设输出:**

1. **对于 `#parent p.item:nth-child(odd)`:**  Item 1 和 Item 3 的文字颜色会变成红色。
2. **对于 `#parent p:nth-of-type(even)`:** Item 2 的文字会加粗。

**用户或编程常见的使用错误**

虽然 `NthIndexCache` 是 Blink 引擎内部的实现，用户或开发者通常不会直接与之交互，但一些 CSS 或 JavaScript 的使用方式可能会影响其性能或导致意外结果，间接与 `NthIndexCache` 的工作相关：

1. **在大型动态列表中使用复杂的 `:nth-child` 或 `:nth-of-type` 选择器:**  如果在一个包含大量元素的动态列表中频繁使用计算成本较高的 `:nth-child` 或带有复杂选择器的 `:nth-child`，即使有缓存，频繁的 DOM 结构变化也可能导致缓存失效，引发性能问题。

2. **误解 `:nth-child` 和 `:nth-of-type` 的区别:**  开发者可能会混淆这两个选择器，导致样式没有按预期应用。`NthIndexCache` 虽然能加速计算，但无法纠正选择器本身的逻辑错误。

    *   **错误示例:** 假设开发者想选择所有偶数段落，可能会错误地使用 `p:nth-child(even)`。如果段落之间有其他类型的元素，这会导致选择不正确。正确的做法是使用 `p:nth-of-type(even)`。

3. **过度依赖客户端计算:**  在处理大量数据时，过度依赖客户端的 CSS 选择器进行过滤和样式设置可能会导致性能瓶颈。虽然 `NthIndexCache` 提供了优化，但在某些场景下，服务端渲染或虚拟 DOM 等技术可能更适合处理大规模数据。

**用户操作是如何一步步的到达这里，作为调试线索**

作为调试线索，了解用户操作如何触发 `NthIndexCache` 的执行路径很有帮助：

1. **用户加载网页:**  当用户在浏览器中打开一个网页时，HTML 代码被解析成 DOM 树。
2. **CSS 解析和样式计算:**  浏览器解析 CSS 样式表，并开始为 DOM 树中的元素计算最终样式。
3. **遇到 `:nth-child` 或 `:nth-of-type` 选择器:**  当样式计算过程遇到包含这些伪类选择器的 CSS 规则时，就需要确定哪些元素符合这些选择器的条件。
4. **调用 `NthIndexCache`:**  Blink 引擎会调用 `NthIndexCache` 的相关方法（如 `NthChildIndex`, `NthOfTypeIndex` 等）来获取元素的索引信息。
5. **缓存查找或计算:**  `NthIndexCache` 尝试从缓存中查找索引。如果找不到，则会遍历 DOM 树计算索引，并将结果缓存起来。
6. **应用样式:**  根据计算出的索引，浏览器决定是否将相应的 CSS 样式应用到元素上。
7. **JavaScript DOM 操作:**  用户与网页交互，例如点击按钮、滚动页面等，可能会触发 JavaScript 代码修改 DOM 结构或样式。如果 JavaScript 代码涉及到添加、删除或移动元素，并且相关的 CSS 规则使用了 `nth-child` 等选择器，那么 `NthIndexCache` 可能会被再次调用来更新样式。
8. **开发者工具检查:**  开发者在使用浏览器开发者工具的 "Elements" 面板检查元素时，特别是查看 "Computed" 样式时，浏览器也可能需要重新计算元素的索引，从而触发 `NthIndexCache` 的执行。

**调试线索示例:**

假设开发者发现一个使用了 `:nth-child` 的样式没有按预期工作：

1. 开发者会打开浏览器的开发者工具，检查 "Elements" 面板。
2. 选中目标元素，查看 "Computed" 样式，确认该样式规则是否被应用。
3. 如果样式没有应用，开发者可能会检查选择器是否正确。
4. 如果选择器看起来正确，开发者可以查看元素的父元素和兄弟元素，手动计算元素的 `nth-child` 值，看是否与预期一致。
5. 如果怀疑是缓存问题，虽然不能直接操作 `NthIndexCache`，但可以尝试刷新页面（硬刷新可能会清除一些缓存）。
6. 如果问题仍然存在，开发者可能需要更深入地理解 `:nth-child` 的工作原理，例如它会考虑所有类型的子元素，而 `:nth-of-type` 只考虑特定类型的子元素。

总而言之，`blink/renderer/core/dom/nth_index_cache.cc` 文件实现了一个重要的性能优化机制，用于加速 CSS 中 `:nth-child` 和 `:nth-of-type` 等伪类选择器的处理，它在浏览器渲染网页和执行 JavaScript DOM 操作的过程中发挥着关键作用。理解它的功能有助于开发者更好地理解浏览器的工作原理，并编写更高效的网页代码。

### 提示词
```
这是目录为blink/renderer/core/dom/nth_index_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/nth_index_cache.h"

#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"

namespace blink {

NthIndexCache::NthIndexCache(Document& document)
    : document_(&document)
#if DCHECK_IS_ON()
      ,
      dom_tree_version_(document.DomTreeVersion())
#endif
{
  document.SetNthIndexCache(this);
}

NthIndexCache::~NthIndexCache() {
#if DCHECK_IS_ON()
  DCHECK_EQ(dom_tree_version_, document_->DomTreeVersion());
#endif
  document_->SetNthIndexCache(nullptr);
}

void NthIndexCache::Key::Trace(Visitor* visitor) const {
  visitor->Trace(parent);
  visitor->Trace(filter);
}

unsigned NthIndexCache::Key::GetHash() const {
  unsigned hash = WTF::GetHash(parent);
  if (filter != nullptr) {
    WTF::AddIntToHash(hash, WTF::GetHash(filter));
  }
  if (!child_tag_name.empty()) {
    WTF::AddIntToHash(hash, WTF::GetHash(child_tag_name));
  }
  return hash;
}

namespace {

// Generating the cached nth-index counts when the number of children
// exceeds this count. This number is picked based on testing
// querySelectorAll for :nth-child(3n+2) and :nth-of-type(3n+2) on an
// increasing number of children.

const unsigned kCachedSiblingCountLimit = 32;

unsigned UncachedNthOfTypeIndex(Element& element, unsigned& sibling_count) {
  int index = 1;
  const QualifiedName& tag = element.TagQName();
  for (const Element* sibling = ElementTraversal::PreviousSibling(element);
       sibling; sibling = ElementTraversal::PreviousSibling(*sibling)) {
    if (sibling->TagQName().Matches(tag)) {
      ++index;
    }
    ++sibling_count;
  }
  return index;
}

unsigned UncachedNthLastOfTypeIndex(Element& element, unsigned& sibling_count) {
  int index = 1;
  const QualifiedName& tag = element.TagQName();
  for (const Element* sibling = ElementTraversal::NextSibling(element); sibling;
       sibling = ElementTraversal::NextSibling(*sibling)) {
    if (sibling->TagQName().Matches(tag)) {
      ++index;
    }
    ++sibling_count;
  }
  return index;
}

}  // namespace

bool NthIndexCache::MatchesFilter(
    Element* element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) {
  if (filter == nullptr) {
    // With no selector list, consider all elements.
    return true;
  }

  SelectorChecker::SelectorCheckingContext sub_context(*context);
  sub_context.element = element;
  sub_context.is_sub_selector = true;
  sub_context.in_nested_complex_selector = true;
  sub_context.pseudo_id = kPseudoIdNone;
  for (sub_context.selector = filter->First(); sub_context.selector;
       sub_context.selector = CSSSelectorList::Next(*sub_context.selector)) {
    // NOTE: We don't want to propagate match_result up to the parent;
    // the correct flags were already set when the caller tested that
    // the element matched the selector list itself.
    SelectorChecker::MatchResult dummy_match_result;
    if (selector_checker->MatchSelector(sub_context, dummy_match_result) ==
        SelectorChecker::kSelectorMatches) {
      return true;
    }
  }
  return false;
}

unsigned NthIndexCache::UncachedNthChildIndex(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context,
    unsigned& sibling_count) {
  int index = 1;
  for (Element* sibling = ElementTraversal::PreviousSibling(element); sibling;
       sibling = ElementTraversal::PreviousSibling(*sibling)) {
    if (MatchesFilter(sibling, filter, selector_checker, context)) {
      ++index;
    }
    ++sibling_count;
  }

  return index;
}

unsigned NthIndexCache::UncachedNthLastChildIndex(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context,
    unsigned& sibling_count) {
  int index = 1;
  for (Element* sibling = ElementTraversal::NextSibling(element); sibling;
       sibling = ElementTraversal::NextSibling(*sibling)) {
    if (MatchesFilter(sibling, filter, selector_checker, context)) {
      index++;
    }
    ++sibling_count;
  }
  return index;
}

unsigned NthIndexCache::NthChildIndex(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) {
  if (element.IsPseudoElement() || !element.parentNode()) {
    return 1;
  }
  NthIndexCache* nth_index_cache = element.GetDocument().GetNthIndexCache();
  if (nth_index_cache && nth_index_cache->cache_) {
    auto it = nth_index_cache->cache_->Find<KeyHashTranslator>(
        Key(element.parentNode(), filter));
    if (it != nth_index_cache->cache_->end()) {
      unsigned result =
          it->value->NthIndex(element, filter, selector_checker, context);
      [[maybe_unused]] unsigned sibling_count = 0;
      DCHECK_EQ(result, UncachedNthChildIndex(element, filter, selector_checker,
                                              context, sibling_count));
      return result;
    }
  }
  unsigned sibling_count = 0;
  unsigned index = UncachedNthChildIndex(element, filter, selector_checker,
                                         context, sibling_count);
  if (nth_index_cache && sibling_count > kCachedSiblingCountLimit) {
    nth_index_cache->CacheNthIndexDataForParent(element, filter,
                                                selector_checker, context);
  }
  return index;
}

unsigned NthIndexCache::NthLastChildIndex(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) {
  if (element.IsPseudoElement() && !element.parentNode()) {
    return 1;
  }
  NthIndexCache* nth_index_cache = element.GetDocument().GetNthIndexCache();
  if (nth_index_cache && nth_index_cache->cache_) {
    auto it = nth_index_cache->cache_->Find<KeyHashTranslator>(
        Key(element.parentNode(), filter));
    if (it != nth_index_cache->cache_->end()) {
      unsigned result =
          it->value->NthLastIndex(element, filter, selector_checker, context);
      [[maybe_unused]] unsigned sibling_count = 0;
      DCHECK_EQ(result,
                UncachedNthLastChildIndex(element, filter, selector_checker,
                                          context, sibling_count));
      return result;
    }
  }
  unsigned sibling_count = 0;
  unsigned index = UncachedNthLastChildIndex(element, filter, selector_checker,
                                             context, sibling_count);
  if (nth_index_cache && sibling_count > kCachedSiblingCountLimit) {
    nth_index_cache->CacheNthIndexDataForParent(element, filter,
                                                selector_checker, context);
  }
  return index;
}

unsigned NthIndexCache::NthOfTypeIndex(Element& element) {
  if (element.IsPseudoElement() || !element.parentNode()) {
    return 1;
  }
  NthIndexCache* nth_index_cache = element.GetDocument().GetNthIndexCache();
  if (nth_index_cache && nth_index_cache->cache_) {
    auto it = nth_index_cache->cache_->Find<KeyHashTranslator>(
        Key(element.parentNode(), element.tagName()));
    if (it != nth_index_cache->cache_->end()) {
      return it->value->NthOfTypeIndex(element);
    }
  }
  unsigned sibling_count = 0;
  unsigned index = UncachedNthOfTypeIndex(element, sibling_count);
  if (nth_index_cache && sibling_count > kCachedSiblingCountLimit) {
    nth_index_cache->CacheNthOfTypeIndexDataForParent(element);
  }
  return index;
}

unsigned NthIndexCache::NthLastOfTypeIndex(Element& element) {
  if (element.IsPseudoElement() || !element.parentNode()) {
    return 1;
  }
  NthIndexCache* nth_index_cache = element.GetDocument().GetNthIndexCache();
  if (nth_index_cache && nth_index_cache->cache_) {
    auto it = nth_index_cache->cache_->Find<KeyHashTranslator>(
        Key(element.parentNode(), element.tagName()));
    if (it != nth_index_cache->cache_->end()) {
      return it->value->NthLastOfTypeIndex(element);
    }
  }
  unsigned sibling_count = 0;
  unsigned index = UncachedNthLastOfTypeIndex(element, sibling_count);
  if (nth_index_cache && sibling_count > kCachedSiblingCountLimit) {
    nth_index_cache->CacheNthOfTypeIndexDataForParent(element);
  }
  return index;
}

void NthIndexCache::EnsureCache() {
  if (!cache_) {
    cache_ = MakeGarbageCollected<
        HeapHashMap<Member<Key>, Member<NthIndexData>, KeyHashTraits>>();
  }
}

void NthIndexCache::CacheNthIndexDataForParent(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) {
  DCHECK(element.parentNode());
  EnsureCache();
  auto add_result = cache_->insert(
      MakeGarbageCollected<Key>(element.parentNode(), filter),
      MakeGarbageCollected<NthIndexData>(*element.parentNode(), filter,
                                         selector_checker, context));
  DCHECK(add_result.is_new_entry);
}

void NthIndexCache::CacheNthOfTypeIndexDataForParent(Element& element) {
  DCHECK(element.parentNode());
  EnsureCache();
  auto add_result = cache_->insert(
      MakeGarbageCollected<Key>(element.parentNode(), element.tagName()),
      MakeGarbageCollected<NthIndexData>(*element.parentNode(),
                                         element.TagQName()));
  DCHECK(add_result.is_new_entry);
}

unsigned NthIndexData::NthIndex(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) const {
  DCHECK(!element.IsPseudoElement());
  auto matches = [&](Element& element) {
    return NthIndexCache::MatchesFilter(&element, filter, selector_checker,
                                        context);
  };

  unsigned index = 0;
  for (Element* sibling = &element; sibling;
       sibling = ElementTraversal::PreviousSibling(*sibling)) {
    if (!matches(*sibling)) {
      continue;
    }
    auto it = element_index_map_.find(sibling);
    if (it != element_index_map_.end()) {
      return it->value + index;
    }
    ++index;
  }
  return index;
}

unsigned NthIndexData::NthOfTypeIndex(Element& element) const {
  DCHECK(!element.IsPseudoElement());

  unsigned index = 0;
  for (Element* sibling = &element; sibling;
       sibling = ElementTraversal::PreviousSibling(
           *sibling, HasTagName(element.TagQName())),
                index++) {
    auto it = element_index_map_.find(sibling);
    if (it != element_index_map_.end()) {
      return it->value + index;
    }
  }
  return index;
}

unsigned NthIndexData::NthLastIndex(
    Element& element,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) const {
  return count_ - NthIndex(element, filter, selector_checker, context) + 1;
}

unsigned NthIndexData::NthLastOfTypeIndex(Element& element) const {
  return count_ - NthOfTypeIndex(element) + 1;
}

NthIndexData::NthIndexData(
    ContainerNode& parent,
    const CSSSelectorList* filter,
    const SelectorChecker* selector_checker,
    const SelectorChecker::SelectorCheckingContext* context) {
  auto matches = [&](Element& element) {
    return NthIndexCache::MatchesFilter(&element, filter, selector_checker,
                                        context);
  };

  // The frequency at which we cache the nth-index for a set of siblings.  A
  // spread value of 3 means every third Element will have its nth-index cached.
  // Using a spread value > 1 is done to save memory. Looking up the nth-index
  // will still be done in constant time in terms of sibling count, at most
  // 'spread' elements will be traversed.
  const unsigned kSpread = 3;
  unsigned count = 0;
  for (Element* sibling = ElementTraversal::FirstChild(parent, matches);
       sibling; sibling = ElementTraversal::NextSibling(*sibling, matches)) {
    if (!(++count % kSpread)) {
      element_index_map_.insert(sibling, count);
    }
  }
  DCHECK(count);
  count_ = count;
}

NthIndexData::NthIndexData(ContainerNode& parent, const QualifiedName& type) {
  // The frequency at which we cache the nth-index of type for a set of
  // siblings.  A spread value of 3 means every third Element of its type will
  // have its nth-index cached.  Using a spread value > 1 is done to save
  // memory. Looking up the nth-index of its type will still be done in less
  // time, as most number of elements traversed will be equal to find 'spread'
  // elements in the sibling set.
  const unsigned kSpread = 3;
  unsigned count = 0;
  for (Element* sibling =
           ElementTraversal::FirstChild(parent, HasTagName(type));
       sibling;
       sibling = ElementTraversal::NextSibling(*sibling, HasTagName(type))) {
    if (!(++count % kSpread)) {
      element_index_map_.insert(sibling, count);
    }
  }
  DCHECK(count);
  count_ = count;
}

void NthIndexData::Trace(Visitor* visitor) const {
  visitor->Trace(element_index_map_);
}

}  // namespace blink
```