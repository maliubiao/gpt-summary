Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine. This is part 4 of a 5-part analysis. I need to summarize the functionality of this specific part of the file.

Based on the code, this file seems to contain unit tests for the `:has()` CSS pseudo-class, specifically focusing on how the caching mechanism works within different scope contexts. The tests evaluate the number of cache hits and misses for various selectors using `:has()`.

Here's a breakdown of what each test case seems to be doing:

*   **Test Structure**: Each `TEST_F` block sets up an HTML document and then runs `TestMatches` or `TestQuerySelectorAll` to evaluate CSS selector matching.
*   **`TestMatches`**: Checks if a specific element matches a given CSS selector. It also verifies the expected state of the cache for different nodes.
*   **`TestQuerySelectorAll`**:  Queries the document for all elements matching a given CSS selector and verifies the expected set of matching elements, along with the cache states.
*   **Cache State Verification**:  The tests verify the expected number of result cache hits (`expected_result_cache_count`), fast reject filter cache hits (`expected_fast_reject_filter_cache_count`), and bloom filter allocations (`expected_bloom_filter_allocation_count`). They also explicitly check the cache state of individual elements using enums like `kCheckPseudoHasResultNotCached`, `kCheckPseudoHasResultChecked`, `kSameAsCached`, etc.
*   **Different Scenarios**: The test names suggest different scenarios being tested, such as "NonSubjectHas", "StartsWithDirectAdjacentCombinator", and different `CheckPseudoHasArgumentTraversalScope` values, indicating variations in how the `:has()` pseudo-class searches for matching elements.

**Functionality Summary for this Part:** This section of the test file focuses on validating the caching behavior of the `:has()` pseudo-class when used with different types of combinators (like `+` and `~`) and different scopes of searching within the `:has()` argument. It checks that the caching mechanism correctly identifies opportunities to reuse previous results, optimizing selector matching.
这是 `blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc` 文件的第 4 部分，主要功能是 **继续测试 CSS `:has()` 伪类的缓存机制在不同作用域上下文中的行为**。

**具体功能归纳：**

这部分代码延续了之前部分对 `:has()` 伪类缓存的测试，更加细致地覆盖了以下几种场景：

1. **非主体 `:has()` 的查询 (NonSubjectHas)**：测试 `:has()` 伪类内部的选择器匹配目标不是直接选中的元素本身的情况。它验证了在这种情况下缓存是如何工作的，特别是针对 `+` (相邻兄弟选择器) 和 `~` (后续兄弟选择器) 组合符。
2. **以相邻兄弟组合符开头的查询 (StartsWithDirectAdjacentCombinator)**：测试 `:has()` 伪类内部的选择器以 `+` 或 `~` 开头的情况。这会影响 `:has()` 伪类内部的查找范围和缓存行为。
3. **不同 `CheckPseudoHasArgumentTraversalScope` 的查询 (QuerySelectorAllCase5, QuerySelectorAllCase6, QuerySelectorAllCase7)**：继续测试针对不同类型的内部元素查找范围 (`CheckPseudoHasArgumentTraversalScope`) 的缓存行为，包括：
    *   `kOneNextSibling` (下一个兄弟元素)
    *   `kFixedDepthDescendants` (固定深度的后代元素，即子元素)
    *   `kOneNextSiblingFixedDepthDescendants` (下一个兄弟元素的子元素)

**与 JavaScript, HTML, CSS 的关系：**

*   **CSS**: 该测试文件直接测试 CSS 的 `:has()` 伪类的功能和性能优化（缓存）。`:has()` 允许你选择包含符合特定条件的后代元素的父元素。例如，`div:has(.active)` 会选择包含 class 为 `active` 的元素的 `div` 元素。
*   **HTML**: 测试用例中使用了 HTML 结构来模拟不同的 DOM 树，用于测试在不同 HTML 结构下 `:has()` 伪类的匹配和缓存行为。例如，`<div id=div1> <div id=div11 class=a></div> </div>` 创建了一个父 `div` 和一个带有 class `a` 的子 `div`。
*   **JavaScript**: 虽然这个文件本身是 C++ 代码，用于测试 Blink 引擎的功能，但在实际的 Web 开发中，JavaScript 可以使用 `querySelectorAll` 或 `matches` 等方法结合包含 `:has()` 的 CSS 选择器来查询和操作 DOM 元素。

**逻辑推理 (假设输入与输出):**

以下以 `QuerySelectorAllCase3NonSubjectHas` 中的一个 `TestMatches` 为例：

**假设输入：**

*   **HTML 结构：**
    ```html
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11 class=c></div>
      </div>
      <div id=div2 class=a>
        <div id=div21>
          <div id=div211 class=c></div>
        </div>
        <div id=div22 class=a>
          <div id=div221 class=b></div>
        </div>
        <div id=div23>
          <div id=div231 class=b></div>
        </div>
      </div>
    </main>
    ```
*   **待匹配元素：**  `#div11`
*   **CSS 选择器：** `:has(+ .a .b) .c`

**逻辑推理：**

1. 选择器 `:has(+ .a .b)` 的意思是查找紧跟在当前元素后面的兄弟元素，该兄弟元素包含后代元素 `.b`。
2. 对于 `#div11`，它的下一个兄弟元素是 `#div2`，`#div2` 包含 `#div221` (class 为 `b`) 和 `#div231` (class 为 `b`)，所以 `#div11` 满足 `:has(+ .a .b)` 的条件。
3. 最终选择器 `:has(+ .a .b) .c` 意味着选择所有自身 class 为 `c`，并且其前一个兄弟元素包含后代元素 `.b` 的元素。
4. 因为 `#div1` 的下一个兄弟 `#div2` 包含 `.b`，所以 `#div1` 满足 `:has(+ .a .b)` 的条件。
5. 因此，选择器最终会匹配到 `#div11` (自身 class 为 `c`)。

**预期输出：**

*   `expected_match_result`: `true` (表示 `#div11` 匹配该选择器)
*   `expected_result_cache_count`: `3` (表示结果缓存命中了 3 次)
*   `expected_fast_reject_filter_cache_count`: `1` (表示快速拒绝过滤器缓存命中了 1 次)
*   `expected_bloom_filter_allocation_count`: `0` (表示没有分配布隆过滤器)
*   各个节点的缓存状态，例如：`{"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked}` 表示 `#div11` 的 `:has()` 结果未缓存，且尚未检查。

**用户或编程常见的使用错误：**

*   **过度使用 `:has()` 导致性能问题:** `:has()` 是一个强大的选择器，但如果内部的选择器过于复杂或匹配范围过大，可能会导致性能问题。开发者应该谨慎使用，避免不必要的复杂性。
*   **对 `:has()` 的缓存机制理解不足:**  开发者可能不清楚浏览器是如何缓存 `:has()` 的结果的，导致在某些情况下期望缓存生效，但实际并没有。理解这些测试用例可以帮助开发者更好地理解缓存机制。
*   **在 JavaScript 中使用包含复杂 `:has()` 的选择器进行频繁查询:** 如果在 JavaScript 中频繁使用像 `:has(+ .a ~ .b .c)` 这样复杂的选择器，可能会影响页面性能。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个包含复杂 CSS 选择器的网页。**  例如，网页的 CSS 中使用了 `:has()` 伪类，并且可能嵌套了其他的选择器，如相邻兄弟选择器或后代选择器。
2. **浏览器引擎 (Blink) 在渲染网页时，需要解析和应用这些 CSS 规则。** 当遇到包含 `:has()` 的选择器时，Blink 会尝试匹配 DOM 元素。
3. **为了优化性能，Blink 实现了 `:has()` 的缓存机制。**  当再次遇到相同的 `:has()` 选择器和上下文时，Blink 会尝试从缓存中获取结果，而不是重新进行匹配计算。
4. **如果用户操作导致 DOM 结构发生变化，或者 CSS 规则被修改，Blink 可能会更新或失效相关的缓存。**
5. **在开发或调试过程中，开发者可能会遇到 `:has()` 选择器匹配不正确或性能不佳的情况。**  为了排查问题，开发者可能会：
    *   **检查 CSS 规则是否正确。**
    *   **查看浏览器的开发者工具，例如“元素”面板，查看元素的样式计算结果。**
    *   **使用性能分析工具，查看 CSS 选择器匹配的耗时。**
    *   **如果怀疑是 `:has()` 的缓存机制有问题，Blink 的开发者可能会查看类似于 `check_pseudo_has_cache_scope_context_test.cc` 这样的测试文件，了解 `:has()` 缓存的预期行为和实现细节。**  这些测试用例可以作为调试的参考，帮助理解在特定场景下缓存是否应该生效以及是如何生效的。

**总结第 4 部分的功能：**

第 4 部分的测试用例专注于验证 CSS `:has()` 伪类在更复杂的场景下的缓存行为，特别是当 `:has()` 内部的选择器涉及到非主体匹配、相邻兄弟选择器、以及不同的元素查找范围时。这些测试旨在确保 `:has()` 的缓存机制在各种情况下都能正确且有效地工作，从而提升页面渲染的性能。

Prompt: 
```
这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
SiblingsChecked,
        kSameAsCached},
       {"#div2",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 3,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(~ .a) .b", {"div1111", "div1211"},
      /* expected_result_cache_count */ 10,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div111", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div12",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div1211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div122",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div13",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 4,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase3NonSubjectHas) {
  // CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11 class=c></div>
      </div>
      <div id=div2 class=a>
        <div id=div21>
          <div id=div211 class=c></div>
        </div>
        <div id=div22 class=a>
          <div id=div221 class=b></div>
        </div>
        <div id=div23>
          <div id=div231 class=b></div>
        </div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div11", ":has(+ .a .b) .c",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div231",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div211", ":has(+ .a .b) .c",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div221",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(+ .a .b) .c", {"div11", "div211"},
      /* expected_result_cache_count */ 6,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div221",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div23", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div231",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 2,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase4NonSubjectHas) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11 class=c></div>
      </div>
      <div id=div2 class=a>
        <div id=div21>
          <div id=div211>
            <div id=div2111 class=c></div>
          </div>
          <div id=div212 class=a>
            <div id=div2121 class=b></div>
          </div>
        </div>
        <div id=div22>
          <div id=div221 class=b></div>
        </div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div11", ":has(~ .a .b) .c",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div212", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2121", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div221",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div2111", ":has(~ .a .b) .c",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div212",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(~ .a .b) .c", {"div11", "div2111"},
      /* expected_result_cache_count */ 6,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div212",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div22", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div221",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 2,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase4StartsWithDirectAdjacentCombinator) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
        <div id=div12 class=a></div>
        <div id=div13 class=b>
          <div id=div131></div>
          <div id=div132 class=c></div>
        </div>
        <div id=div14>
          <div id=div141></div>
        </div>
        <div id=div15></div>
      </div>
      <div id=div2>
        <div id=div21></div>
      </div>
      <div id=div3>
        <div id=div31></div>
      </div>
      <div id=div4>
        <div id=div41></div>
      </div>
      <div id=div5 class=a>
        <div id=div51></div>
      </div>
      <div id=div6 class=b>
        <div id=div61 class=c></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div1", ":has(+ .a ~ .b .c)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 4,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div131", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div132", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div14", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div141", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div15", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div21", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div31", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div4", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div41", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div5", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div51", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div6", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div61", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div11", ":has(+ .a ~ .b .c)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 5,
      {{"#div1", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div131", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div132",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div141", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div15", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div12", ":has(+ .a ~ .b .c)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 4,
      {{"#div1", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div12", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div13",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div131", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div132", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div14", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div141", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div15", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(+ .a ~ .b .c)", {"div11", "div4"},
      /* expected_result_cache_count */ 9,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div12", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div13",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div131", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div132",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div141", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div15", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div21", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div31", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div4", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div41", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div5", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div51", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div6", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div61", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 3,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(+ .a ~ .b .c), :has(+ .d ~ .e .f)",
      {"div11", "div4"}, /* expected_result_cache_count */ 9,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div12", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div13",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div131", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div132",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div141", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div15", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div21", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div31", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div4", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div41", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div5", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div51", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div6", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div61", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 3,
      /* expected_bloom_filter_allocation_count */ 2);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, QuerySelectorAllCase5) {
  // CheckPseudoHasArgumentTraversalScope::kOneNextSibling

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
        <div id=div12></div>
        <div id=div13></div>
      </div>
      <div id=div2>
        <div id=div21></div>
        <div id=div22 class=a></div>
        <div id=div23></div>
      </div>
      <div id=div3 class=a>
        <div id=div31></div>
        <div id=div32></div>
        <div id=div33></div>
      </div>
    </main>
  )HTML");

  TestMatches(document, "div2", ":has(+ .a)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div21", ":has(+ .a)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(+ .a)", {"div2", "div21"},
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, QuerySelectorAllCase6) {
  // CheckPseudoHasArgumentTraversalScope::kFixedDepthDescendants

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11 class=a>
          <div id=div111></div>
          <div id=div112>
            <div id=div1121></div>
            <div id=div1122 class=a></div>
            <div id=div1123></div>
          </div>
          <div id=div113></div>
        </div>
        <div id=div12>
          <div id=div121></div>
          <div id=div122 class=a></div>
          <div id=div123></div>
        </div>
      </div>
    </main>
  )HTML");

  TestMatches(document, "div1", ":has(> .a)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div111", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div112", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1121", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1122", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1123", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div113", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div122", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div123", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div112", ":has(> .a)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div111", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div112", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1121", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1122", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1123", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div113", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div122", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div123", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div12", ":has(> .a)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div111", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div112", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1121", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1122", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1123", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div113", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div122", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div123", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(> .a)", {"div1", "div112", "div12"},
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div112", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1121", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1122", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1123", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div113", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div122", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div123", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, QuerySelectorAllCase7) {
  // CheckPseudoHasArgumentTraversalScope::kOneNextSiblingFixedDepthDescendants

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
        <div id=div12></div>
        <div id=div13></div>
      </div>
      <div id=div2 class=a>
        <div id=div21></div>
        <div id=div22 class=b></div>
        <div id=div23 class=a>
          <div id=div231></div>
          <div id=div232 class=b></div>
          <div id=div233></div>
        </div>
      </div>
    </main>
  )HTML");

  TestMatches(document, "div1", ":has(+ .a > .b)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div233", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div22", ":has(+ .a > .b)",
              /* expected_match_result */ true,
              /* expected_result_cache_count */ 0,
              {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div233", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(+ .a > .b)", {"div1", "div22"},
      /* expected_result_cache_count */ 0,
      {{"#ma
"""


```