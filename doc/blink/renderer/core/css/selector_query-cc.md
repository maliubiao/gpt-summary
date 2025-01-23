Response:
Let's break down the thought process for analyzing the `selector_query.cc` file.

1. **Understand the Core Purpose:** The file name itself, `selector_query.cc`, strongly suggests it's about querying elements based on CSS selectors. The initial copyright notices reinforce this, mentioning CSS selector handling. Reading the includes further confirms this, showing dependencies on CSS parsing (`css_parser.h`, `css_selector_parser.h`), DOM manipulation (`document.h`, `element_traversal.h`, `node.h`), and CSS rule resolution (`element_resolve_context.h`, `selector_checker.h`).

2. **Identify Key Data Structures:** The code defines a `SelectorQuery` class. This is likely the central entity for performing selector queries. It holds a `CSSSelectorList` (`selectors_`) and potentially some optimization flags (like `use_slow_scan_`, `selector_id_`). The `SelectorQueryCache` also stands out, indicating a mechanism to optimize repeated queries.

3. **Analyze Public Methods of `SelectorQuery`:** These are the primary ways to interact with the class.

    * `Matches(Element&)`:  This suggests checking if a *single* element matches the query.
    * `Closest(Element&)`:  This hints at finding the nearest ancestor of an element that matches the query (like `Element.closest()` in JavaScript).
    * `QueryAll(ContainerNode&)`:  This strongly indicates retrieving *all* matching elements within a given root. It likely corresponds to `querySelectorAll()`.
    * `QueryFirst(ContainerNode&)`: This suggests retrieving only the *first* matching element within a given root, likely corresponding to `querySelector()`.
    * `Adopt(CSSSelectorList*)`: This looks like a factory method for creating `SelectorQuery` instances.

4. **Examine Template Functions:**  The presence of template functions like `Execute`, `CollectElementsByClassName`, `CollectElementsByTagName`, and `CollectElementsByAttributeExact` suggests different strategies for optimizing queries based on the selector type. This is a common pattern in performance-sensitive code.

5. **Trace the Execution Flow (Conceptual):**  Consider how the public methods might use the private/template functions. For instance, `QueryAll` probably calls one of the `Execute` templates, which in turn might call the `Collect...` functions for simple selectors or fall back to a more general matching mechanism.

6. **Look for Optimizations:** The use of `NthIndexCache`, `SelectorChecker`, and the separate `ExecuteWithId` function points to performance optimizations. The `SelectorQueryCache` is a major optimization for repeated queries.

7. **Relate to Web Technologies:**  Connect the found functionalities to their counterparts in JavaScript, HTML, and CSS:

    * `QueryAll` and `QueryFirst` directly correspond to `querySelectorAll()` and `querySelector()`.
    * `Matches` is similar to the functionality used internally when CSS rules are applied.
    * `Closest` maps directly to the `closest()` method.
    * The different `Collect...` functions are optimized ways to find elements based on class names, tag names, and attributes, core CSS selector concepts.

8. **Infer Logic and Assumptions:**

    * **Fast Paths:** The code has different execution paths based on selector complexity. Simple selectors (like `#id`, `.class`, `tag`) have optimized paths.
    * **ID Optimization:**  The `ExecuteWithId` function demonstrates a specific optimization for ID-based selectors.
    * **Case Sensitivity:** The code explicitly handles case sensitivity/insensitivity in attribute matching, which is important for HTML and XML.
    * **Document Order:** The comment in `FindTraverseRootsAndExecute` mentions returning matches in document order, a requirement for `querySelectorAll`.

9. **Consider Potential Issues and Debugging:** Think about common mistakes developers make when using selectors and how those might lead to issues within this code:

    * **Syntax Errors:** Invalid selectors will be caught by the parsing logic.
    * **Performance:** Inefficient selectors can lead to slow query performance. The code includes stats and different execution paths to address this.
    * **Case Sensitivity:**  Understanding the nuances of case sensitivity in different contexts is crucial.
    * **Shadow DOM:**  While not explicitly detailed in the provided snippet, the presence of `shadow_root.h` in the includes hints at potential Shadow DOM considerations.

10. **Simulate User Actions:**  Imagine how a user interacting with a web page might trigger these code paths:

    * Typing in a search bar that uses JavaScript to filter elements.
    * Clicking a button that uses JavaScript to find related elements.
    * The browser's rendering engine applying styles based on CSS rules.

11. **Structure the Explanation:** Organize the findings into logical sections: Functionality, Relationships, Logic/Assumptions, Usage Errors, and Debugging Clues. Use clear and concise language. Provide concrete examples to illustrate the points.

**(Self-Correction during the Process):**  Initially, I might have focused too much on the individual functions without understanding the overarching flow. Realizing the importance of the `Execute` templates and how they branch based on selector type is a crucial step. Also, recognizing the performance considerations behind the different execution paths and the caching mechanism is key to a complete understanding. I would also double-check the relationships with JavaScript APIs to ensure accuracy.
这个文件 `blink/renderer/core/css/selector_query.cc` 是 Chromium Blink 渲染引擎中的一个核心组件，主要负责高效地执行 CSS 选择器查询。它的功能是将 CSS 选择器应用于 DOM 树，以查找匹配的元素。

以下是它的主要功能及其与 JavaScript, HTML, CSS 的关系，以及一些示例、逻辑推理、常见错误和调试线索：

**主要功能:**

1. **解析和编译 CSS 选择器:** 接收 CSS 选择器字符串，并将其解析成内部表示（`CSSSelectorList`）。这个过程可能涉及到语法分析、错误检查和优化。
2. **高效的元素查询:**  提供多种查询策略，根据选择器的类型和复杂度选择最有效的方式在 DOM 树中查找匹配的元素。这包括：
    * **基于 ID 的快速查找:** 对于 `#id` 选择器，利用 DOM 树的 ID 索引进行快速定位。
    * **基于类名的快速查找:** 对于 `.class` 选择器，利用元素的类名列表进行快速过滤。
    * **基于标签名的快速查找:** 对于 `tag` 选择器，遍历指定标签名的元素。
    * **基于属性的快速查找:** 对于 `[attribute="value"]` 这样的属性选择器，进行优化查找。
    * **通用的深度优先遍历:**  对于更复杂的选择器，例如包含组合器（` `, `>`, `+`, `~`）或伪类/伪元素的，进行 DOM 树的深度优先遍历并逐个检查元素是否匹配。
3. **支持 `querySelector` 和 `querySelectorAll` 等 API:**  为 JavaScript 提供的 `document.querySelector()`, `document.querySelectorAll()`, `element.querySelector()`, `element.querySelectorAll()` 等方法提供底层实现。
4. **支持 `matches()` 方法:**  实现 `Element.matches()` 方法，用于检查单个元素是否匹配给定的 CSS 选择器。
5. **支持 `closest()` 方法:** 实现 `Element.closest()` 方法，用于查找匹配给定 CSS 选择器的最近祖先元素（包括元素自身）。
6. **查询结果缓存:**  通过 `SelectorQueryCache` 缓存已解析的 CSS 选择器，避免重复解析，提高性能。
7. **统计查询信息:** 在调试模式下或特定编译配置下，可以收集查询的统计信息，例如不同查询类型的执行次数，用于性能分析和优化。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS (层叠样式表):**
    * **输入:** `selector_query.cc` 的核心功能是处理 CSS 选择器。例如，CSS 样式规则中的选择器（如 `div.container p`, `#header`, `.item:hover`）会被解析并用于查找需要应用样式的元素。
    * **逻辑推理（假设输入与输出）:**
        * **假设输入 CSS:** `p.highlight`
        * **假设 HTML:** `<p>普通段落</p> <p class="highlight">高亮段落</p>`
        * **预期输出 (匹配元素):**  `<p class="highlight">高亮段落</p>`
* **HTML (超文本标记语言):**
    * **操作目标:** `selector_query.cc` 在 HTML 构成的 DOM 树上进行操作，查找特定的 HTML 元素。
    * **用户操作导致到达这里:** 用户在浏览器中加载 HTML 页面，浏览器解析 HTML 构建 DOM 树。CSS 样式规则需要应用到 DOM 元素时，或者 JavaScript 代码调用选择器 API 时，会触发这里的代码。
* **JavaScript:**
    * **API 接口:** JavaScript 通过 `querySelector`, `querySelectorAll`, `matches`, `closest` 等 DOM API 调用 `selector_query.cc` 的功能。
    * **举例说明:**
        * **`querySelector`:**  JavaScript 代码 `document.querySelector('.active')` 会调用 `selector_query.cc` 中的相应函数，查找文档中第一个 class 为 `active` 的元素。
        * **`querySelectorAll`:** JavaScript 代码 `element.querySelectorAll('li')` 会调用 `selector_query.cc` 中的相应函数，查找 `element` 内部所有 `li` 元素。
        * **`matches`:** JavaScript 代码 `if (targetElement.matches('.highlight')) { ... }` 会调用 `selector_query.cc` 的 `Matches` 方法来判断 `targetElement` 是否匹配 `.highlight` 选择器。
        * **`closest`:** JavaScript 代码 `element.closest('form')` 会调用 `selector_query.cc` 的 `Closest` 方法来查找最近的父级 `form` 元素。

**逻辑推理（假设输入与输出）:**

* **假设输入 (JavaScript 代码):** `document.querySelectorAll('div > p.text')`
* **假设 HTML:**
  ```html
  <div>
    <p>普通段落</p>
    <p class="text">文本段落</p>
  </div>
  <section>
    <p class="text">另一个文本段落</p>
  </section>
  ```
* **预期输出 (匹配元素):** `<p class="text">文本段落</p>` (只会匹配 `div` 的直接子元素且 class 为 `text` 的 `p` 元素)

**用户或编程常见的使用错误及示例说明:**

1. **选择器语法错误:**
   * **错误示例 (JavaScript):** `document.querySelector('#my id')`  // ID 选择器中包含空格，语法错误。
   * **后果:**  `SelectorQueryCache::Add` 函数中的 `CSSParser::ParseSelector` 会解析失败，抛出 `DOMExceptionCode::kSyntaxError` 异常。

2. **性能问题：使用过于复杂的选择器:**
   * **错误示例 (CSS/JavaScript):**  `body > div article .content p span.emphasis` // 过于深且复杂的选择器，会导致查询效率降低。
   * **后果:**  `selector_query.cc` 会回退到更通用的深度优先遍历算法，可能导致页面渲染或脚本执行变慢。

3. **对大小写敏感性的误解:**
   * **错误示例 (HTML):** `<div id="MyElement"></div>`
   * **错误示例 (JavaScript):** `document.querySelector('#myelement')` // 在标准模式下，ID 选择器是大小写敏感的。
   * **后果:**  `ExecuteWithId` 函数可能无法找到对应的元素，导致查询返回 `null`。

4. **在不合适的上下文中使用选择器:**
   * **错误示例 (JavaScript):** 在 Shadow DOM 边界之外使用选择器尝试选取 Shadow DOM 内部的元素，如果 Shadow DOM 没有明确对外暴露。
   * **后果:**  查询可能返回 `null` 或不符合预期的结果，因为选择器默认不会穿透 Shadow DOM 边界。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并加载网页。**
2. **浏览器开始解析 HTML 代码，构建 DOM 树。**
3. **浏览器解析 CSS 样式表，遇到 CSS 规则时，例如 `div.container { ... }`。**
4. **渲染引擎需要找到匹配 `div.container` 的元素，这时会调用 `selector_query.cc` 中的函数来执行选择器查询。**
5. **用户与网页交互，例如点击按钮，触发 JavaScript 事件监听器。**
6. **JavaScript 代码中调用了 `document.querySelector('.active')` 或类似的选择器 API。**
7. **浏览器将该选择器字符串传递给 `selector_query.cc` 的 `QueryFirst` 或 `QueryAll` 等方法。**
8. **`selector_query.cc` 解析选择器，并根据选择器的类型选择合适的查询策略在 DOM 树中查找匹配的元素。**
9. **返回匹配的元素给 JavaScript 代码，JavaScript 代码执行后续操作。**

**调试线索:**

* **断点:** 在 `selector_query.cc` 中设置断点，例如在 `Execute`, `ExecuteWithId`, `CollectElementsByClassName` 等关键函数入口处，可以观察选择器的解析过程和查询路径。
* **日志输出:**  在代码中添加日志输出，打印选择器字符串、匹配的元素等信息，帮助理解查询过程。
* **Chrome DevTools:**  使用 Chrome 开发者工具的 "Elements" 面板可以查看元素的 CSS 规则和匹配情况。 "Performance" 面板可以分析选择器查询的性能。 "Console" 面板可以执行 JavaScript 代码并查看选择器查询的结果。
* **`// #define RELEASE_QUERY_STATS`:**  取消注释此行可以在 Release 版本中启用查询统计，有助于分析不同选择器类型的性能表现。
* **检查 `SelectorQueryCache`:** 查看缓存中是否存在对应的选择器，以及缓存是否命中，有助于理解性能瓶颈。

总而言之，`blink/renderer/core/css/selector_query.cc` 是 Blink 引擎中负责高效执行 CSS 选择器查询的关键组件，它连接了 CSS 样式规则、HTML DOM 结构和 JavaScript DOM 操作，是现代 Web 开发中不可或缺的一部分。

### 提示词
```
这是目录为blink/renderer/core/css/selector_query.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011, 2013 Apple Inc. All rights reserved.
 * Copyright (C) 2014 Samsung Electronics. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/selector_query.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/resolver/element_resolve_context.h"
#include "third_party/blink/renderer/core/css/selector_checker.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/nth_index_cache.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

// Uncomment to run the SelectorQueryTests for stats in a release build.
// #define RELEASE_QUERY_STATS

namespace blink {

#if DCHECK_IS_ON() || defined(RELEASE_QUERY_STATS)
static SelectorQuery::QueryStats& CurrentQueryStats() {
  DEFINE_STATIC_LOCAL(SelectorQuery::QueryStats, stats, ());
  return stats;
}

SelectorQuery::QueryStats SelectorQuery::LastQueryStats() {
  return CurrentQueryStats();
}

#define QUERY_STATS_INCREMENT(name) \
  (void)(CurrentQueryStats().total_count++, CurrentQueryStats().name++);
#define QUERY_STATS_RESET() (void)(CurrentQueryStats() = {});

#else

#define QUERY_STATS_INCREMENT(name)
#define QUERY_STATS_RESET()

#endif

struct SingleElementSelectorQueryTrait {
  typedef Element* OutputType;
  static const bool kShouldOnlyMatchFirstElement = true;
  ALWAYS_INLINE static bool IsEmpty(const OutputType& output) {
    return !output;
  }
  ALWAYS_INLINE static void AppendElement(OutputType& output,
                                          Element& element) {
    DCHECK(!output);
    output = &element;
  }
};

struct AllElementsSelectorQueryTrait {
  typedef HeapVector<Member<Element>> OutputType;
  static const bool kShouldOnlyMatchFirstElement = false;
  ALWAYS_INLINE static bool IsEmpty(const OutputType& output) {
    return output.empty();
  }
  ALWAYS_INLINE static void AppendElement(OutputType& output,
                                          Element& element) {
    output.push_back(&element);
  }
};

inline bool SelectorMatches(const CSSSelector& selector,
                            Element& element,
                            const ContainerNode& root_node,
                            const SelectorChecker& checker) {
  SelectorChecker::SelectorCheckingContext context(&element);
  context.selector = &selector;
  context.scope = &root_node;
  return checker.Match(context);
}

bool SelectorQuery::Matches(Element& target_element) const {
  QUERY_STATS_RESET();
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &target_element.GetDocument(), /*within_selector_checking=*/false);
  return SelectorListMatches(target_element, target_element);
}

Element* SelectorQuery::Closest(Element& target_element) const {
  QUERY_STATS_RESET();
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &target_element.GetDocument(), /*within_selector_checking=*/false);
  if (selectors_.empty()) {
    return nullptr;
  }

  for (Element* current_element = &target_element; current_element;
       current_element = current_element->parentElement()) {
    if (SelectorListMatches(target_element, *current_element)) {
      return current_element;
    }
  }
  return nullptr;
}

StaticElementList* SelectorQuery::QueryAll(ContainerNode& root_node) const {
  QUERY_STATS_RESET();
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &root_node.GetDocument(), /*within_selector_checking=*/false);
  NthIndexCache nth_index_cache(root_node.GetDocument());
  HeapVector<Member<Element>> result;
  Execute<AllElementsSelectorQueryTrait>(root_node, result);
  return StaticElementList::Adopt(result);
}

Element* SelectorQuery::QueryFirst(ContainerNode& root_node) const {
  QUERY_STATS_RESET();
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &root_node.GetDocument(), /*within_selector_checking=*/false);
  NthIndexCache nth_index_cache(root_node.GetDocument());
  Element* matched_element = nullptr;
  Execute<SingleElementSelectorQueryTrait>(root_node, matched_element);
  return matched_element;
}

template <typename SelectorQueryTrait>
static void CollectElementsByClassName(
    ContainerNode& root_node,
    const AtomicString& class_name,
    const CSSSelector* selector,
    typename SelectorQueryTrait::OutputType& output) {
  SelectorChecker checker(SelectorChecker::kQueryingRules);
  for (Element& element : ElementTraversal::DescendantsOf(root_node)) {
    QUERY_STATS_INCREMENT(fast_class);
    if (!element.HasClassName(class_name)) {
      continue;
    }
    if (selector && !SelectorMatches(*selector, element, root_node, checker)) {
      continue;
    }
    SelectorQueryTrait::AppendElement(output, element);
    if (SelectorQueryTrait::kShouldOnlyMatchFirstElement) {
      return;
    }
  }
}

inline bool MatchesTagName(const QualifiedName& tag_name,
                           const Element& element) {
  if (tag_name == AnyQName()) {
    return true;
  }
  if (element.HasLocalName(tag_name.LocalName())) {
    return true;
  }
  // Non-html elements in html documents are normalized to their camel-cased
  // version during parsing if applicable. Yet, type selectors are lower-cased
  // for selectors in html documents. Compare the upper case converted names
  // instead to allow matching SVG elements like foreignObject.
  if (!element.IsHTMLElement() && IsA<HTMLDocument>(element.GetDocument())) {
    return element.TagQName().LocalNameUpper() == tag_name.LocalNameUpper();
  }
  return false;
}

template <typename SelectorQueryTrait>
static void CollectElementsByTagName(
    ContainerNode& root_node,
    const QualifiedName& tag_name,
    typename SelectorQueryTrait::OutputType& output) {
  DCHECK_EQ(tag_name.NamespaceURI(), g_star_atom);
  for (Element& element : ElementTraversal::DescendantsOf(root_node)) {
    QUERY_STATS_INCREMENT(fast_tag_name);
    if (MatchesTagName(tag_name, element)) {
      SelectorQueryTrait::AppendElement(output, element);
      if (SelectorQueryTrait::kShouldOnlyMatchFirstElement) {
        return;
      }
    }
  }
}

// TODO(sesse): Reduce the duplication against SelectorChecker.
static bool AttributeValueMatchesExact(const Attribute& attribute_item,
                                       const AtomicString& selector_value,
                                       bool case_insensitive) {
  const AtomicString& value = attribute_item.Value();
  if (value.IsNull()) {
    return false;
  }
  return selector_value == value ||
         (case_insensitive && EqualIgnoringASCIICase(selector_value, value));
}

// SynchronizeAttribute() is rather expensive to call. We can determine ahead of
// time if it's needed. The exact set needed for svg is rather large, so this
// errors on the side of caution.
static bool NeedsSynchronizeAttribute(const QualifiedName& qname,
                                      bool is_html_doc) {
  // Assume any known name needs synchronization.
  if (qname.IsDefinedName()) {
    return true;
  }
  const QualifiedName local_qname(qname.LocalName());
  if (local_qname.IsDefinedName()) {
    return true;
  }
  // HTML elements in an html doc use the lower case name.
  if (!is_html_doc || qname.LocalName().IsLowerASCII()) {
    return false;
  }
  const QualifiedName lower_local_qname(qname.LocalName().LowerASCII());
  return lower_local_qname.IsDefinedName();
}

template <typename SelectorQueryTrait>
static void CollectElementsByAttributeExact(
    ContainerNode& root_node,
    const CSSSelector& selector,
    typename SelectorQueryTrait::OutputType& output) {
  const QualifiedName& selector_attr = selector.Attribute();
  const AtomicString& selector_value = selector.Value();
  const bool is_html_doc = IsA<HTMLDocument>(root_node.GetDocument());
  // Legacy dictates that values of some attributes should be compared in
  // a case-insensitive manner regardless of whether the case insensitive
  // flag is set or not (but an explicit case sensitive flag will override
  // that, by causing LegacyCaseInsensitiveMatch() never to be set).
  const bool case_insensitive =
      selector.AttributeMatch() ==
          CSSSelector::AttributeMatchType::kCaseInsensitive ||
      (selector.LegacyCaseInsensitiveMatch() && is_html_doc);
  const bool needs_synchronize_attribute =
      NeedsSynchronizeAttribute(selector_attr, is_html_doc);

  for (Element& element : ElementTraversal::DescendantsOf(root_node)) {
    QUERY_STATS_INCREMENT(fast_scan);
    if (needs_synchronize_attribute) {
      // Synchronize the attribute in case it is lazy-computed.
      // Currently all lazy properties have a null namespace, so only pass
      // localName().
      element.SynchronizeAttribute(selector_attr.LocalName());
    }
    AttributeCollection attributes = element.AttributesWithoutUpdate();
    for (const auto& attribute_item : attributes) {
      if (!attribute_item.Matches(selector_attr)) {
        if (element.IsHTMLElement() || !is_html_doc) {
          continue;
        }
        // Non-html attributes in html documents are normalized to their camel-
        // cased version during parsing if applicable. Yet, attribute selectors
        // are lower-cased for selectors in html documents. Compare the selector
        // and the attribute local name insensitively to e.g. allow matching SVG
        // attributes like viewBox.
        //
        // NOTE: If changing this behavior, be sure to also update the bucketing
        // in ElementRuleCollector::CollectMatchingRules() accordingly.
        if (!attribute_item.MatchesCaseInsensitive(selector_attr)) {
          continue;
        }
      }

      if (AttributeValueMatchesExact(attribute_item, selector_value,
                                     case_insensitive)) {
        SelectorQueryTrait::AppendElement(output, element);
        if (SelectorQueryTrait::kShouldOnlyMatchFirstElement) {
          return;
        }
        break;
      }

      if (selector_attr.NamespaceURI() != g_star_atom) {
        break;
      }
    }
  }
}

inline bool AncestorHasClassName(ContainerNode& root_node,
                                 const AtomicString& class_name) {
  auto* root_node_element = DynamicTo<Element>(root_node);
  if (!root_node_element) {
    return false;
  }

  for (auto* element = root_node_element; element;
       element = element->parentElement()) {
    if (element->HasClassName(class_name)) {
      return true;
    }
  }
  return false;
}

template <typename SelectorQueryTrait>
void SelectorQuery::FindTraverseRootsAndExecute(
    ContainerNode& root_node,
    typename SelectorQueryTrait::OutputType& output) const {
  // We need to return the matches in document order. To use id lookup while
  // there is possiblity of multiple matches we would need to sort the
  // results. For now, just traverse the document in that case.
  DCHECK_EQ(selectors_.size(), 1u);

  bool is_rightmost_selector = true;
  bool is_affected_by_sibling_combinator = false;

  for (const CSSSelector* selector = selectors_[0]; selector;
       selector = selector->NextSimpleSelector()) {
    if (!is_affected_by_sibling_combinator &&
        selector->Match() == CSSSelector::kClass) {
      if (is_rightmost_selector) {
        CollectElementsByClassName<SelectorQueryTrait>(
            root_node, selector->Value(), selectors_[0], output);
        return;
      }
      // Since there exists some ancestor element which has the class name, we
      // need to see all children of rootNode.
      if (AncestorHasClassName(root_node, selector->Value())) {
        break;
      }

      const AtomicString& class_name = selector->Value();
      Element* element = ElementTraversal::FirstWithin(root_node);
      while (element) {
        QUERY_STATS_INCREMENT(fast_class);
        if (element->HasClassName(class_name)) {
          ExecuteForTraverseRoot<SelectorQueryTrait>(*element, root_node,
                                                     output);
          if (SelectorQueryTrait::kShouldOnlyMatchFirstElement &&
              !SelectorQueryTrait::IsEmpty(output)) {
            return;
          }
          element =
              ElementTraversal::NextSkippingChildren(*element, &root_node);
        } else {
          element = ElementTraversal::Next(*element, &root_node);
        }
      }
      return;
    }

    if (selector->Relation() == CSSSelector::kSubSelector) {
      continue;
    }
    is_rightmost_selector = false;
    is_affected_by_sibling_combinator =
        selector->Relation() == CSSSelector::kDirectAdjacent ||
        selector->Relation() == CSSSelector::kIndirectAdjacent;
  }

  ExecuteForTraverseRoot<SelectorQueryTrait>(root_node, root_node, output);
}

template <typename SelectorQueryTrait>
void SelectorQuery::ExecuteForTraverseRoot(
    ContainerNode& traverse_root,
    ContainerNode& root_node,
    typename SelectorQueryTrait::OutputType& output) const {
  DCHECK_EQ(selectors_.size(), 1u);

  const CSSSelector& selector = *selectors_[0];
  SelectorChecker checker(SelectorChecker::kQueryingRules);

  for (Element& element : ElementTraversal::DescendantsOf(traverse_root)) {
    QUERY_STATS_INCREMENT(fast_scan);
    if (SelectorMatches(selector, element, root_node, checker)) {
      SelectorQueryTrait::AppendElement(output, element);
      if (SelectorQueryTrait::kShouldOnlyMatchFirstElement) {
        return;
      }
    }
  }
}

bool SelectorQuery::SelectorListMatches(ContainerNode& root_node,
                                        Element& element) const {
  SelectorChecker checker(SelectorChecker::kQueryingRules);
  for (auto* const selector : selectors_) {
    if (SelectorMatches(*selector, element, root_node, checker)) {
      return true;
    }
  }
  return false;
}

template <typename SelectorQueryTrait>
void SelectorQuery::ExecuteSlow(
    ContainerNode& root_node,
    typename SelectorQueryTrait::OutputType& output) const {
  for (Element& element : ElementTraversal::DescendantsOf(root_node)) {
    QUERY_STATS_INCREMENT(slow_scan);
    if (!SelectorListMatches(root_node, element)) {
      continue;
    }
    SelectorQueryTrait::AppendElement(output, element);
    if (SelectorQueryTrait::kShouldOnlyMatchFirstElement) {
      return;
    }
  }
}

template <typename SelectorQueryTrait>
void SelectorQuery::ExecuteWithId(
    ContainerNode& root_node,
    typename SelectorQueryTrait::OutputType& output) const {
  DCHECK_EQ(selectors_.size(), 1u);
  DCHECK(!root_node.GetDocument().InQuirksMode());

  const CSSSelector& first_selector = *selectors_[0];
  DCHECK(root_node.IsInTreeScope());
  const TreeScope& scope = root_node.GetTreeScope();
  SelectorChecker checker(SelectorChecker::kQueryingRules);

  if (scope.ContainsMultipleElementsWithId(selector_id_)) {
    // We don't currently handle cases where there's multiple elements with the
    // id and it's not in the rightmost selector.
    if (!selector_id_is_rightmost_) {
      FindTraverseRootsAndExecute<SelectorQueryTrait>(root_node, output);
      return;
    }
    const auto& elements = scope.GetAllElementsById(selector_id_);
    for (const auto& element : elements) {
      if (!element->IsDescendantOf(&root_node)) {
        continue;
      }
      QUERY_STATS_INCREMENT(fast_id);
      if (SelectorMatches(first_selector, *element, root_node, checker)) {
        SelectorQueryTrait::AppendElement(output, *element);
        if (SelectorQueryTrait::kShouldOnlyMatchFirstElement) {
          return;
        }
      }
    }
    return;
  }

  Element* element = scope.getElementById(selector_id_);
  if (!element) {
    return;
  }
  if (selector_id_is_rightmost_) {
    if (!element->IsDescendantOf(&root_node)) {
      return;
    }
    QUERY_STATS_INCREMENT(fast_id);
    if (SelectorMatches(first_selector, *element, root_node, checker)) {
      SelectorQueryTrait::AppendElement(output, *element);
    }
    return;
  }
  ContainerNode* start = &root_node;
  if (element->IsDescendantOf(&root_node)) {
    start = element;
    if (selector_id_affected_by_sibling_combinator_) {
      start = start->parentNode();
    }
  }
  if (!start) {
    return;
  }
  QUERY_STATS_INCREMENT(fast_id);
  ExecuteForTraverseRoot<SelectorQueryTrait>(*start, root_node, output);
}

template <typename SelectorQueryTrait>
void SelectorQuery::Execute(
    ContainerNode& root_node,
    typename SelectorQueryTrait::OutputType& output) const {
  if (selectors_.empty()) {
    return;
  }

  if (use_slow_scan_) {
    ExecuteSlow<SelectorQueryTrait>(root_node, output);
    return;
  }

  DCHECK_EQ(selectors_.size(), 1u);

  // In quirks mode getElementById("a") is case sensitive and should only
  // match elements with lowercase id "a", but querySelector is case-insensitive
  // so querySelector("#a") == querySelector("#A"), which means we can only use
  // the id fast path when we're in a standards mode document.
  if (selector_id_ && root_node.IsInTreeScope() &&
      !root_node.GetDocument().InQuirksMode()) {
    ExecuteWithId<SelectorQueryTrait>(root_node, output);
    return;
  }

  const CSSSelector& first_selector = *selectors_[0];
  if (!first_selector.NextSimpleSelector()) {
    // Fast path for querySelector*('.foo'), and querySelector*('div').
    switch (first_selector.Match()) {
      case CSSSelector::kClass:
        CollectElementsByClassName<SelectorQueryTrait>(
            root_node, first_selector.Value(), nullptr, output);
        return;
      case CSSSelector::kTag:
        if (first_selector.TagQName().NamespaceURI() == g_star_atom) {
          CollectElementsByTagName<SelectorQueryTrait>(
              root_node, first_selector.TagQName(), output);
          return;
        }
        // querySelector*() doesn't allow namespace prefix resolution and
        // throws before we get here, but we still may have selectors for
        // elements without a namespace.
        DCHECK_EQ(first_selector.TagQName().NamespaceURI(), g_null_atom);
        break;
      case CSSSelector::kAttributeExact:
        if (RuntimeEnabledFeatures::FastPathSingleSelectorExactMatchEnabled()) {
          CollectElementsByAttributeExact<SelectorQueryTrait>(
              root_node, first_selector, output);
          return;
        }
        break;
      default:
        break;  // If we need another fast path, add here.
    }
  }

  FindTraverseRootsAndExecute<SelectorQueryTrait>(root_node, output);
}

std::unique_ptr<SelectorQuery> SelectorQuery::Adopt(
    CSSSelectorList* selector_list) {
  return base::WrapUnique(new SelectorQuery(selector_list));
}

SelectorQuery::SelectorQuery(CSSSelectorList* selector_list)
    : selector_list_(selector_list),
      selector_id_is_rightmost_(true),
      selector_id_affected_by_sibling_combinator_(false),
      use_slow_scan_(true) {
  selectors_.ReserveInitialCapacity(selector_list_->ComputeLength());
  for (const CSSSelector* selector = selector_list_->First(); selector;
       selector = CSSSelectorList::Next(*selector)) {
    if (selector->MatchesPseudoElement()) {
      continue;
    }
    selectors_.UncheckedAppend(selector);
  }

  if (selectors_.size() == 1) {
    use_slow_scan_ = false;
    for (const CSSSelector* current = selectors_[0]; current;
         current = current->NextSimpleSelector()) {
      if (current->Match() == CSSSelector::kId) {
        selector_id_ = current->Value();
        break;
      }
      // We only use the fast path when in standards mode where #id selectors
      // are case sensitive, so we need the same behavior for [id=value].
      if (current->Match() == CSSSelector::kAttributeExact &&
          current->Attribute() == html_names::kIdAttr &&
          current->AttributeMatch() ==
              CSSSelector::AttributeMatchType::kCaseSensitive) {
        selector_id_ = current->Value();
        break;
      }
      if (current->Relation() == CSSSelector::kSubSelector) {
        continue;
      }
      selector_id_is_rightmost_ = false;
      selector_id_affected_by_sibling_combinator_ =
          current->Relation() == CSSSelector::kDirectAdjacent ||
          current->Relation() == CSSSelector::kIndirectAdjacent;
    }
  }
}

SelectorQuery* SelectorQueryCache::Add(const AtomicString& selectors,
                                       const Document& document,
                                       ExceptionState& exception_state) {
  if (selectors.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "The provided selector is empty.");
    return nullptr;
  }

  HashMap<AtomicString, std::unique_ptr<SelectorQuery>>::iterator it =
      entries_.find(selectors);
  if (it != entries_.end()) {
    return it->value.get();
  }

  HeapVector<CSSSelector> arena;
  base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
      MakeGarbageCollected<CSSParserContext>(
          document, document.BaseURL(), true /* origin_clean */, Referrer()),
      CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false, nullptr, selectors, arena);

  if (selector_vector.empty()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "'" + selectors + "' is not a valid selector.");
    return nullptr;
  }

  CSSSelectorList* selector_list =
      CSSSelectorList::AdoptSelectorVector(selector_vector);

  const unsigned kMaximumSelectorQueryCacheSize = 256;
  if (entries_.size() == kMaximumSelectorQueryCacheSize) {
    entries_.erase(entries_.begin());
  }

  return entries_.insert(selectors, SelectorQuery::Adopt(selector_list))
      .stored_value->value.get();
}

void SelectorQueryCache::Invalidate() {
  entries_.clear();
}

}  // namespace blink
```