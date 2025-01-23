Response:
The user wants to understand the functionality of the provided C++ code file. I need to analyze the code and explain:
1. **Core Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Examples:**  Provide hypothetical inputs and outputs to illustrate its behavior.
4. **Common Errors:**  Explain potential mistakes users or programmers might make related to this code.
5. **Debugging Context:** Describe how a user might end up interacting with this code during debugging.
6. **Summary:** Briefly summarize the file's purpose.

Based on the file name `check_pseudo_has_cache_scope_context_test.cc` and the included headers, it seems this file is part of the Blink rendering engine and specifically focuses on testing the caching mechanism for the `:has()` CSS pseudo-class.

Here's a breakdown of the code:
- **Includes:** Standard C++ libraries, Google Test, and Blink-specific headers related to CSS parsing, selectors, DOM, and testing.
- **Namespace:** `blink` indicates it's part of the Blink engine.
- **Test Fixture:** `CheckPseudoHasCacheScopeContextTest` inherits from `PageTestBase`, suggesting it's a unit test for a specific functionality.
- **Helper Functions:**
    - `GetResult`, `ElementCached`, `ElementChecked`:  These functions likely interact with the cache to check the status of an element's `:has()` evaluation.
    - `GetQueryRoot`: Helps in selecting the root node for queries, potentially within shadow DOM.
    - `TestResultToString`: Converts the cache result enum to a human-readable string.
- **Template Functions:**
    - `CheckCacheResults`: This is the core testing function. It parses a CSS selector, finds the `:has()` part, and then checks the state of the cache for various elements based on the provided expectations.
    - `TestMatches`: Tests the `matches()` method of an element with a given selector and validates the cache state.
    - `TestQuerySelectorAll`: Tests the `querySelectorAll()` method and validates the cache state.
- **Test Cases:**  The `TEST_F` macros define individual test cases, each with a descriptive name like `Case1StartsWithDescendantCombinator`. These test cases set up an HTML structure and then call the helper functions to verify the caching behavior of `:has()` under different scenarios.

**Hypotheses for Input and Output:**

- **Input (for `CheckCacheResults`):**
    - `document`: A DOM tree (HTML structure).
    - `query_name`: A string identifier for the test.
    - `selector_text`: A CSS selector string containing `:has()`.
    - `expected_result_cache_count`: The expected number of entries in the result cache.
    - `expected_result_cache_entries`: An array of structs defining the expected cache state for specific elements.
    - `expected_fast_reject_filter_cache_count`: Expected count for fast reject filter cache.
    - `expected_bloom_filter_allocation_count`: Expected count for bloom filter allocation.
    - `match_in_shadow_tree`: A boolean indicating whether to consider shadow DOM.
- **Output (assertions within the test):** The test will assert that the actual cache state matches the expected state for various elements and cache counts.

**Relationship to Web Technologies:**

- **CSS:** The code directly deals with CSS selectors, particularly the `:has()` pseudo-class. It tests how the engine caches the results of evaluating selectors with `:has()`.
- **HTML:** The test cases create HTML documents and elements to simulate real-world scenarios where CSS selectors are applied. The caching mechanism being tested is directly related to how the browser efficiently matches CSS rules to HTML elements.
- **JavaScript:** While this specific file is C++, the caching mechanisms it tests are crucial for the performance of JavaScript code that interacts with the DOM and CSS, such as using `querySelector`, `querySelectorAll`, or checking if an element matches a selector using `matches()`.

**Common User/Programming Errors:**

- **Incorrect CSS Syntax in `:has()`:**  Users might write invalid selectors within the `:has()` pseudo-class, leading to parsing errors or unexpected matching behavior. The caching might behave unexpectedly if the underlying selector is flawed.
- **Over-reliance on Caching:** Developers might assume the caching is always perfect and not account for scenarios where the cache might need invalidation (e.g., dynamic DOM changes). This can lead to stale results if not handled correctly.
- **Understanding Cache Invalidation:**  A common mistake is not understanding when and how the cache is invalidated. Modifying the DOM or CSS rules can affect the cache, and developers need to be aware of these implications.

**Debugging Scenario:**

A web developer might encounter issues where a CSS rule with `:has()` doesn't seem to be applying correctly or is causing performance problems. To investigate, a Chromium engineer might:

1. **Inspect the DOM and Styles:** Use the browser's developer tools to examine the applied styles and the DOM structure.
2. **Profile Performance:** Use performance profiling tools to identify potential bottlenecks related to CSS selector matching.
3. **Examine the Rendering Engine Code:** If the issue seems to be within the browser's rendering engine, they might delve into the Blink source code, potentially landing in files like this one to understand how the `:has()` pseudo-class and its caching are implemented.
4. **Run Unit Tests:**  Engineers might run specific unit tests like those in this file to verify the correctness of the caching logic under different conditions. They might even add new test cases to reproduce and fix the bug.
5. **Step Through the Code:** Using a debugger, they can step through the C++ code in files like `check_pseudo_has_cache_scope_context_test.cc` and the related implementation files to see exactly how the caching mechanism behaves with the problematic HTML and CSS.

**Summary of Functionality (Part 1):**

This C++ source code file (`check_pseudo_has_cache_scope_context_test.cc`) contains unit tests for the caching mechanism used by the Blink rendering engine when evaluating CSS selectors that include the `:has()` pseudo-class. The tests verify that the cache correctly stores and retrieves results of `:has()` evaluations for different elements and selector combinations, ensuring efficiency and correctness in CSS matching. It sets up various HTML structures and CSS selectors and then asserts the expected state of the cache after performing selector matching operations.

这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc的chromium blink引擎源代码文件，它是一个 **单元测试文件**，专门用于测试 `CheckPseudoHasCacheScope::Context` 类的功能。

**它的主要功能是验证在 CSS 规则中使用 `:has()` 伪类时，Blink 渲染引擎的缓存机制是否正常工作。**  具体来说，它会测试：

1. **结果缓存 (Result Cache):**  `:has()` 伪类的匹配结果是否被正确地缓存，以便在后续的匹配过程中能够复用，提高性能。
2. **快速拒绝过滤器缓存 (Fast Reject Filter Cache):** 是否使用了快速拒绝过滤器来避免对某些元素进行昂贵的 `:has()` 匹配计算。
3. **布隆过滤器分配 (Bloom Filter Allocation):**  是否按需分配布隆过滤器来优化 `:has()` 的匹配性能。

**与 JavaScript, HTML, CSS 的功能关系：**

* **CSS:**  该文件直接测试与 CSS 相关的特性，特别是 `:has()` 伪类的缓存机制。 `:has()` 允许你根据元素是否包含符合特定选择器的后代元素来选择元素。例如，`div:has(p)` 会选择所有包含 `<p>` 元素的 `<div>` 元素。该测试文件验证了当浏览器处理包含 `:has()` 的 CSS 规则时，是否有效地利用缓存来加速匹配过程。
* **HTML:** 测试用例中会创建 HTML 文档和元素，用于模拟浏览器在渲染网页时遇到的各种 DOM 结构。例如，测试用例会创建嵌套的 `<div>` 元素，并赋予不同的 ID 和类名，以便在 CSS 选择器中引用。
* **JavaScript:** 虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能直接影响到 JavaScript 代码与 DOM 交互的性能。当 JavaScript 代码使用 `querySelector` 或 `querySelectorAll` 等方法，并且这些选择器中包含 `:has()` 时，该测试所验证的缓存机制就起到了优化作用。

**逻辑推理与假设输入输出：**

假设有以下 HTML 片段：

```html
<div id="parent">
  <p class="target">This is a paragraph.</p>
</div>
<div id="another"></div>
```

和一个 CSS 选择器： `div:has(.target)`

该测试文件可能会有如下类似的测试用例：

**假设输入:**

* **CSS 选择器:** `div:has(.target)`
* **待检查元素:** `document.getElementById("parent")`
* **期望缓存结果:** `kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched` (表示该元素已检查且匹配)

**逻辑推理:**  由于 `parent` div 包含一个 class 为 `target` 的 `<p>` 元素，因此该 `:has()` 选择器应该匹配 `parent` div。缓存机制应该记录下这个匹配结果。

**假设输出:**  测试会断言 `CheckPseudoHasCacheScope::Context` 返回的结果与期望缓存结果一致。

**用户或编程常见的使用错误举例说明：**

* **错误地假设 `:has()` 的性能开销:**  开发者可能会在性能敏感的代码中过度使用 `:has()`，而没有意识到它可能带来的性能影响。虽然 Blink 实现了缓存机制来优化 `:has()`，但在某些复杂的场景下，它仍然可能比其他选择器更慢。
* **不理解缓存的失效机制:**  开发者可能会错误地认为 `:has()` 的结果会被永久缓存，而忽略了 DOM 结构变化会导致缓存失效。例如，如果通过 JavaScript 动态地向一个元素添加或删除匹配 `:has()` 内部选择器的子元素，那么之前缓存的结果可能不再有效。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户报告网页性能问题：** 用户可能遇到网页加载缓慢或者交互卡顿的情况。
2. **开发者进行性能分析：** 开发者使用 Chrome DevTools 等工具进行性能分析，发现 CSS 选择器匹配是性能瓶颈之一。
3. **关注 `:has()` 伪类：** 开发者注意到 CSS 规则中使用了 `:has()` 伪类，怀疑它可能导致了性能问题。
4. **Blink 开发者介入：** 如果问题很可能出在浏览器渲染引擎层面，Blink 开发者可能会介入调查。
5. **检查 `:has()` 的实现和缓存：** Blink 开发者会查看 `:has()` 的具体实现代码以及相关的缓存机制，例如 `CheckPseudoHasCacheScope::Context`。
6. **运行单元测试：** 为了验证缓存机制的正确性或者排查潜在的 bug，Blink 开发者会运行 `check_pseudo_has_cache_scope_context_test.cc` 中的单元测试。如果测试失败，则说明缓存机制存在问题。
7. **代码调试：**  如果单元测试失败，开发者可能会使用调试器来跟踪代码执行流程，查看缓存的存储和检索过程，以找出 bug 的根源。

**归纳一下它的功能 (第 1 部分):**

总而言之，`check_pseudo_has_cache_scope_context_test.cc` 文件的主要功能是 **作为 Blink 渲染引擎中 `:has()` 伪类缓存机制的单元测试**。它通过创建各种 HTML 结构和 CSS 选择器，并断言缓存的状态和结果是否符合预期，来确保该缓存机制的正确性和性能。这部分代码定义了测试框架和一些辅助方法，用于设置测试环境和验证缓存结果。

### 提示词
```
这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <memory>
#include <utility>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_argument_context.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class CheckPseudoHasCacheScopeContextTest : public PageTestBase {
 protected:
  enum ExpectedCheckPseudoHasResult {
    kSameAsCached,
    kNotYetChecked,
    kAlreadyNotMatched,
  };

  struct ExpectedResultCacheEntry {
    const char* element_query;
    CheckPseudoHasResult cached_result;
    ExpectedCheckPseudoHasResult expected_result;
    const char* shadow_host_id = nullptr;
  };

  static CheckPseudoHasResult GetResult(
      CheckPseudoHasCacheScope::Context& cache_scope_context,
      Element* element) {
    return cache_scope_context.CacheAllowed()
               ? cache_scope_context.GetResult(element)
               : kCheckPseudoHasResultNotCached;
  }

  static bool ElementCached(
      CheckPseudoHasCacheScope::Context& cache_scope_context,
      Element* element) {
    return GetResult(cache_scope_context, element) !=
           kCheckPseudoHasResultNotCached;
  }

  static bool ElementChecked(
      CheckPseudoHasCacheScope::Context& cache_scope_context,
      Element* element) {
    return GetResult(cache_scope_context, element) &
           kCheckPseudoHasResultChecked;
  }

  static ContainerNode* GetQueryRoot(Document* document,
                                     const char* shadow_host_id) {
    if (shadow_host_id) {
      return document->getElementById(AtomicString(shadow_host_id))
          ->GetShadowRoot();
    }
    return document;
  }

  static String TestResultToString(CheckPseudoHasResult test_result) {
    return String::Format(
        "0b%c%c%c%c",
        (test_result & kCheckPseudoHasResultSomeChildrenChecked ? '1' : '0'),
        (test_result & kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked
             ? '1'
             : '0'),
        (test_result & kCheckPseudoHasResultMatched ? '1' : '0'),
        (test_result & kCheckPseudoHasResultChecked ? '1' : '0'));
  }

  template <unsigned length>
  void CheckCacheResults(
      Document* document,
      String query_name,
      const char* selector_text,
      unsigned expected_result_cache_count,
      const ExpectedResultCacheEntry (&expected_result_cache_entries)[length],
      unsigned expected_fast_reject_filter_cache_count,
      unsigned expected_bloom_filter_allocation_count,
      bool match_in_shadow_tree) const {
    HeapVector<CSSSelector> arena;
    base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
        MakeGarbageCollected<CSSParserContext>(
            *document, NullURL(), true /* origin_clean */, Referrer()),
        CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false, nullptr,
        selector_text, arena);
    CSSSelectorList* selector_list =
        CSSSelectorList::AdoptSelectorVector(selector_vector);
    const CSSSelector* selector = nullptr;
    for (selector = selector_list->First();
         selector && selector->GetPseudoType() != CSSSelector::kPseudoHas;
         selector = selector->NextSimpleSelector()) {
    }
    if (!selector) {
      ADD_FAILURE() << "Failed : " << query_name << " (Cannot find :has() in "
                    << selector_text << ")";
      return;
    }
    const CSSSelector* argument_selector = selector->SelectorList()->First();

    CheckPseudoHasArgumentContext argument_context(argument_selector,
                                                   match_in_shadow_tree);
    CheckPseudoHasCacheScope::Context cache_scope_context(document,
                                                          argument_context);

    EXPECT_EQ(expected_result_cache_count,
              cache_scope_context.GetResultCacheCountForTesting())
        << "Failed : " << query_name;

    for (ExpectedResultCacheEntry expected_result_cache_entry :
         expected_result_cache_entries) {
      String test_name =
          String::Format("[%s] cache result of %s", query_name.Utf8().c_str(),
                         expected_result_cache_entry.element_query);
      Element* element =
          GetQueryRoot(document, expected_result_cache_entry.shadow_host_id)
              ->QuerySelector(
                  AtomicString(expected_result_cache_entry.element_query));
      DCHECK(element) << "Failed to get `"
                      << expected_result_cache_entry.element_query << "'";

      EXPECT_EQ(expected_result_cache_entry.cached_result,
                GetResult(cache_scope_context, element))
          << "Failed : " << test_name << " : { expected: "
          << TestResultToString(expected_result_cache_entry.cached_result)
          << ", actual: "
          << TestResultToString(GetResult(cache_scope_context, element))
          << " }";

      switch (expected_result_cache_entry.expected_result) {
        case kSameAsCached:
          EXPECT_TRUE(ElementCached(cache_scope_context, element))
              << "Failed : " << test_name;
          break;
        case kNotYetChecked:
        case kAlreadyNotMatched:
          EXPECT_FALSE(ElementChecked(cache_scope_context, element))
              << "Failed : " << test_name;
          EXPECT_EQ(
              expected_result_cache_entry.expected_result == kAlreadyNotMatched,
              cache_scope_context.AlreadyChecked(element))
              << "Failed : " << test_name;
          break;
      }
    }

    EXPECT_EQ(expected_fast_reject_filter_cache_count,
              cache_scope_context.GetFastRejectFilterCacheCountForTesting())
        << "Failed : " << query_name;

    EXPECT_EQ(expected_bloom_filter_allocation_count,
              cache_scope_context.GetBloomFilterAllocationCountForTesting())
        << "Failed : " << query_name;
  }

  template <unsigned cache_size>
  void TestMatches(Document* document,
                   const char* query_scope_element_id,
                   const char* selector_text,
                   bool expected_match_result,
                   unsigned expected_result_cache_count,
                   const ExpectedResultCacheEntry (
                       &expected_result_cache_entries)[cache_size],
                   unsigned expected_fast_reject_filter_cache_count,
                   unsigned expected_bloom_filter_allocation_count,
                   const char* shadow_host_id = nullptr) const {
    Element* query_scope_element =
        GetQueryRoot(document, shadow_host_id)
            ->getElementById(AtomicString(query_scope_element_id));
    ASSERT_TRUE(query_scope_element);

    CheckPseudoHasCacheScope cache_scope(document,
                                         /*within_selector_checking=*/false);

    String query_name = String::Format("#%s.matches('%s')",
                                       query_scope_element_id, selector_text);

    EXPECT_EQ(expected_match_result,
              query_scope_element->matches(AtomicString(selector_text)))
        << "Failed : " << query_name;

    CheckCacheResults(
        document, query_name, selector_text, expected_result_cache_count,
        expected_result_cache_entries, expected_fast_reject_filter_cache_count,
        expected_bloom_filter_allocation_count, !!shadow_host_id);
  }

  template <unsigned query_result_size, unsigned cache_size>
  void TestQuerySelectorAll(Document* document,
                            const char* query_scope_element_id,
                            const char* selector_text,
                            const String (&expected_results)[query_result_size],
                            unsigned expected_result_cache_count,
                            const ExpectedResultCacheEntry (
                                &expected_result_cache_entries)[cache_size],
                            unsigned expected_fast_reject_filter_cache_count,
                            unsigned expected_bloom_filter_allocation_count,
                            const char* shadow_host_id = nullptr) const {
    ContainerNode* query_scope_node = GetQueryRoot(document, shadow_host_id);
    if (query_scope_element_id) {
      query_scope_node = query_scope_node->getElementById(
          AtomicString(query_scope_element_id));
    }
    ASSERT_TRUE(query_scope_node);

    CheckPseudoHasCacheScope cache_scope(document,
                                         /*within_selector_checking=*/false);

    String query_name = String::Format("#%s.querySelectorAll('%s')",
                                       query_scope_element_id, selector_text);

    StaticElementList* result =
        query_scope_node->QuerySelectorAll(AtomicString(selector_text));

    EXPECT_EQ(query_result_size, result->length()) << "Failed : " << query_name;
    unsigned size_max = query_result_size > result->length() ? query_result_size
                                                             : result->length();
    for (unsigned i = 0; i < size_max; ++i) {
      EXPECT_EQ((i < query_result_size ? expected_results[i] : "<null>"),
                (i < result->length() ? result->item(i)->GetIdAttribute()
                                      : AtomicString()))
          << "Failed :" << query_name << " result at index " << i;
    }

    CheckCacheResults(
        document, query_name, selector_text, expected_result_cache_count,
        expected_result_cache_entries, expected_fast_reject_filter_cache_count,
        expected_bloom_filter_allocation_count, !!shadow_host_id);
  }
};

TEST_F(CheckPseudoHasCacheScopeContextTest,
       Case1StartsWithDescendantCombinator) {
  // CheckPseudoHasArgumentTraversalScope::kSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
      </div>
      <div id=div2>
        <div id=div21>
          <div id=div211></div>
        </div>
        <div id=div22>
          <div id=div221></div>
          <div id=div222 class=a>
            <div id=div2221></div>
          </div>
          <div id=div223>
            <div id=div2231></div>
            <div id=div2232>
              <div id=div22321></div>
              <div id=div22322 class=b>
                <div id=div223221></div>
              </div>
              <div id=div22323></div>
            </div>
          </div>
        </div>
        <div id=div23>
          <div id=div231></div>
        </div>
        <div id=div24>
          <div id=div241></div>
        </div>
      </div>
      <div id=div3>
        <div id=div31></div>
      </div>
      <div id=div4>
        <div id=div41></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div2", ":has(.a)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 7,
      {{"main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div2", ":has(.b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 9,
      {{"main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div223", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2232",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div22321", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22322",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div223221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div2", ":has(.c)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 2,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div21",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div222", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, Case1StartsWithChildCombinator) {
  // CheckPseudoHasArgumentTraversalScope::kSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
      </div>
      <div id=div2>
        <div id=div21>
          <div id=div211></div>
        </div>
        <div id=div22>
          <div id=div221>
            <div id=div2211></div>
          </div>
          <div id=div222 class=a>
            <div id=div2221>
              <div id=div22211></div>
              <div id=div22212 class=b>
                <div id=div222121></div>
              </div>
              <div id=div22213></div>
            </div>
          </div>
          <div id=div223>
            <div id=div2231></div>
          </div>
          <div id=div224>
            <div id=div2241></div>
            <div id=div2242 class=a>
              <div id=div22421></div>
              <div id=div22422>
                <div id=div224221></div>
                <div id=div224222 class=b>
                  <div id=div2242221></div>
                </div>
                <div id=div224223></div>
              </div>
              <div id=div22423>
                <div id=div224231></div>
              </div>
              <div id=div22424></div>
            </div>
            <div id=div2243>
              <div id=div22431></div>
            </div>
            <div id=div2244></div>
          </div>
          <div id=div225>
            <div id=div2251></div>
          </div>
          <div id=div226></div>
        </div>
        <div id=div23>
          <div id=div231></div>
        </div>
        <div id=div24></div>
      </div>
      <div id=div3>
        <div id=div31></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div22", ":has(> .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 5,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2221", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div22211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22212",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div222121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22213", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2242", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22421", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22422", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224222", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2242221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22423", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22424", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2243", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22431", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2244", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div225", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2251", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div226", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div24", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div2", ":has(> .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 4,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div21",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div222", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22212", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div222121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22213", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2242", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22421", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22422", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224222", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2242221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22423", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22424", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2243", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22431", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2244", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div225", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2251", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div226", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div2", ":has(> .a .c)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 2,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div21",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div222", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22211", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22212", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div222121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22213", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2242", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22421", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22422", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224222", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2242221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224223", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22423", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div224231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22424", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2243", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22431", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2244", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div225", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2251", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div226", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, Case2StartsWithIndirectAdjacent) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblings

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
      </div>
      <div id=div2>
        <div id=div21>
          <div id=div211></div>
          <div id=div212 class=a></div>
        </div>
        <div id=div22>
          <div id=div221></div>
          <div id=div222 class=a></div>
        </div>
        <div id=div23>
          <div id=div231></div>
          <div id=div232 class=a></div>
        </div>
        <div id=div24 class=a>
          <div id=div241></div>
          <div id=div242 class=a></div>
        </div>
        <div id=div25>
          <div id=div251></div>
          <div id=div252 class=a></div>
        </div>
      </div>
      <div id=div3 class=a>
        <div id=div31></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div22", ":has(~ .a)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 5,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked},
       {"#div21", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div212", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div232", kCheckPseudoHasResultNotCached, kNo
```