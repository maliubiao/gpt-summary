Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a larger test file.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the file:** The filename `check_pseudo_has_cache_scope_context_test.cc` suggests this file contains tests related to caching the results of the `:has()` CSS pseudo-class, specifically focusing on how the scope of the `:has()` selector influences caching.

2. **Examine the test structure:** The code uses the `TEST_F` macro, indicating it's using Google Test. Each `TEST_F` block represents a specific test case. The names of these test cases (`Case1`, `Case2StartsWithDirectAdjacent`, `Case3`, `Case4`) likely correspond to different scenarios or edge cases being tested.

3. **Analyze the core function:**  The `TestMatches` function is central to each test case. It takes a document, a selector string (with `:has()`), an expected match result, an expected cache hit count, and a set of expected cache states for specific elements. This strongly indicates the primary goal is to verify the caching behavior of `:has()`.

4. **Understand the HTML structure:** Each test case sets up an HTML document using `document->write(R"HTML(...)HTML")`. The HTML structure within each case varies, likely designed to test different DOM tree configurations and how they interact with the `:has()` selector and its caching mechanisms.

5. **Focus on the `:has()` selector:**  The core of the tests revolves around selectors like `:has(.a .b)`, `:has(~ .b)`, `:has(+ .a ~ .b)`. These are `:has()` pseudo-classes with various complex selectors inside them. The tests aim to verify that the caching mechanism correctly handles different types of selectors within `:has()`, including descendant selectors, sibling selectors, and combinations thereof.

6. **Interpret the expected results:** The `expected_result_cache_count` and the array of element-specific cache states provide crucial information. They indicate what the expected caching behavior is for each test case. The different `kCheckPseudoHasResult*` and `k*Checked` constants denote different caching states (not cached, cached, already matched/not matched, etc.).

7. **Infer the purpose of the tests:** Based on the above, the tests seem designed to ensure that:
    * The `:has()` pseudo-class correctly identifies elements based on the presence of other elements matching the selector within its arguments.
    * The results of `:has()` evaluations are cached effectively to avoid redundant computations.
    * The caching mechanism correctly considers the scope of the `:has()` selector (e.g., descendants, siblings).
    * Different types of selectors within `:has()` are handled correctly by the caching system.

8. **Connect to web technologies:**  The `:has()` pseudo-class is a CSS feature. The tests are written in C++ within the Blink rendering engine, which is responsible for interpreting and applying CSS to HTML. Therefore, the tests directly relate to CSS functionality and how it's implemented in the browser.

9. **Consider user impact and debugging:**  If caching of `:has()` is implemented incorrectly, it could lead to:
    * **Performance issues:**  Repeatedly evaluating complex `:has()` selectors can be computationally expensive.
    * **Incorrect styling:** If cached results are not invalidated correctly when the DOM changes, elements might not be styled as expected.

10. **Formulate the summary:** Combine the observations into a concise summary, highlighting the key aspects: testing the `:has()` pseudo-class, focusing on caching, considering different scopes and selector types, and the implications for performance and correct styling. Emphasize that this is part of a larger test suite.
这是Blink渲染引擎中`check_pseudo_has_cache_scope_context_test.cc`文件的第二部分，主要功能是**测试CSS `:has()` 伪类在不同作用域上下文下的缓存行为**。

**具体功能归纳:**

* **测试 `:has()` 的缓存机制:**  这部分代码延续了第一部分的功能，继续测试 `:has()` 伪类在特定场景下的结果缓存是否正确生效。重点在于验证当 `:has()` 内部的选择器涉及到不同的作用域时，缓存是否能够被有效利用，避免重复计算。
* **测试不同的作用域上下文:**  这部分代码通过 `TestMatches` 函数和不同的HTML结构，测试了以下几种 `:has()` 的作用域上下文：
    * **`Case1`:** 包含了 `~` (通用兄弟选择器)，测试在兄弟节点中查找元素时的缓存行为。
    * **`Case2StartsWithDirectAdjacent`:** 包含了 `+` (相邻兄弟选择器) 和 `~`，测试以相邻兄弟选择器开始的复杂兄弟选择器场景下的缓存。
    * **`Case3`:** 包含了 `+` 和后代选择器 (空格)，测试在相邻兄弟节点的子树中查找元素时的缓存。
    * **`Case4`:** 包含了 `~` 和后代选择器，测试在后续兄弟节点的子树中查找元素时的缓存。
* **验证缓存命中和未命中情况:**  `TestMatches` 函数的核心是验证在执行 `:has()` 查询后，哪些元素的 `:has()` 结果会被缓存 (`kSameAsCached`)，哪些不会被缓存 (`kNotYetChecked`)，哪些之前已经匹配过或未匹配过 (`kAlreadyNotMatched`)。
* **验证快速拒绝过滤器和布隆过滤器计数:** 代码中还检查了 `expected_fast_reject_filter_cache_count` 和 `expected_bloom_filter_allocation_count`，这涉及到 Blink 内部优化 `:has()` 性能的机制。快速拒绝过滤器用于快速判断某些情况下 `:has()` 是否不可能匹配，而布隆过滤器则用于更精细的排除。

**与 JavaScript, HTML, CSS 的关系及举例:**

这个测试文件直接关联 CSS 的 `:has()` 伪类。

* **CSS:** `:has()` 允许你选择父元素，当其内部包含匹配特定选择器的子元素时。例如，`div:has(.active)` 会选择所有包含 class 为 `active` 的子元素的 `div` 元素。
    * **本代码中的例子:**  `":has(~ .b)"`，`":has(+ .a ~ .b)"`，`":has(+ .a .b)"`，`":has(~ .a .b)"` 这些都是 `:has()` 伪类的用法，用于测试不同内部选择器下的缓存行为。
* **HTML:** 测试代码通过构建不同的 HTML 结构来模拟各种 DOM 树形结构，以便测试 `:has()` 在不同上下文中的行为。
    * **本代码中的例子:**  代码中使用了嵌套的 `div` 元素，并赋予不同的 `id` 和 `class`，例如 `<div id=div23 class=a> ... <div id=div2322 class=b> ... </div> ... </div>`。
* **JavaScript:**  虽然这个测试文件是用 C++ 写的，但 `:has()` 最终会被 JavaScript API (如 `querySelectorAll`) 调用。  如果 `:has()` 的缓存机制有问题，可能会导致 JavaScript 查询结果不一致或性能下降。

**逻辑推理 (假设输入与输出):**

以 `TestMatches(document, "div23", ":has(+ .a ~ .b)", ...)` 为例：

* **假设输入:**
    * `document`:  一个包含特定 HTML 结构的 DOM 树。
    * `"div23"`:  目标元素，即要判断是否匹配 `:has()` 选择器的元素（`#div23`）。
    * `":has(+ .a ~ .b)"`: CSS 选择器，表示选择紧跟在当前元素后面的兄弟节点，该兄弟节点拥有 class `a`，并且在该兄弟节点之后存在一个拥有 class `b` 的兄弟节点。
* **预期输出:**
    * `expected_match_result`: `true`，因为在 `#div23` 之后存在 `#div24.a`，并且 `#div26.b` 在 `#div24.a` 之后。
    * `expected_result_cache_count`: `3`，表示期望有 3 个元素的 `:has()` 结果被缓存。
    * 后面的数组详细描述了每个元素的预期缓存状态 (`kCheckPseudoHasResult*`, `k*Checked`)。

**用户或编程常见的使用错误及举例:**

* **CSS 选择器错误:**  用户可能写出错误的 `:has()` 内部选择器，导致预期外的匹配结果。例如，写成 `:has(.a > .b)` 想要匹配孙子节点，但实际上只有直接子节点才会被匹配。
* **DOM 结构理解偏差:**  用户可能对 HTML 的 DOM 树形结构理解有误，导致对 `:has()` 的匹配结果产生错误的预期。例如，认为 `:has(.a)` 会匹配所有祖先节点包含 class `a` 的元素，但实际上只会匹配直接子节点包含 class `a` 的父元素。
* **JavaScript 中使用 `:has()` 的性能问题:**  如果在一个循环或者频繁调用的函数中使用复杂的 `:has()` 选择器，可能会导致性能问题，因为浏览器需要进行大量的 DOM 查询。 理解 `:has()` 的缓存机制有助于优化这类性能问题。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页。**
2. **该网页的 CSS 样式中使用了 `:has()` 伪类。**
3. **浏览器开始渲染网页，Blink 渲染引擎负责解析 CSS 并应用样式。**
4. **当渲染引擎遇到使用了 `:has()` 的 CSS 规则时，会执行相关的匹配逻辑。**
5. **为了优化性能，渲染引擎会尝试缓存 `:has()` 的匹配结果。**
6. **如果 `:has()` 的缓存机制存在 bug，例如在特定作用域上下文下缓存失效或错误，那么可能需要调试 Blink 的源代码。**
7. **开发者可能会运行 `check_pseudo_has_cache_scope_context_test.cc` 这样的测试文件，来验证和修复 `:has()` 缓存相关的 bug。**
8. **测试失败时，开发者会分析测试用例的 HTML 结构、CSS 选择器以及预期的缓存状态，来定位问题所在。**

**总结这部分的功能:**

这部分代码专注于测试 Blink 渲染引擎中 `:has()` 伪类的缓存机制，特别是当 `:has()` 的内部选择器涉及到不同的 DOM 树作用域（如兄弟节点、后代节点）时，缓存是否能够正确地生效和被利用，从而提高 CSS 匹配的性能。 它通过多个测试用例覆盖了不同的作用域上下文和选择器组合，并验证了预期的缓存命中和未命中情况，以及相关的内部优化机制的计数。

### 提示词
```
这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
tYetChecked},
       {"#div24",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div242", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div25", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div251", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div252", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div22", ":has(~ .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div212", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div242", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div25", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div251", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div252", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, Case2StartsWithDirectAdjacent) {
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
          <div id=div213 class=b></div>
        </div>
        <div id=div22>
          <div id=div221></div>
          <div id=div222 class=a></div>
          <div id=div223 class=b></div>
        </div>
        <div id=div23>
          <div id=div231></div>
          <div id=div232 class=a></div>
          <div id=div233 class=b></div>
        </div>
        <div id=div24 class=a>
          <div id=div241></div>
          <div id=div242 class=a></div>
          <div id=div243 class=b></div>
        </div>
        <div id=div25>
          <div id=div251></div>
          <div id=div252 class=a></div>
          <div id=div253 class=b></div>
        </div>
        <div id=div26 class=b>
          <div id=div261></div>
          <div id=div262 class=a></div>
          <div id=div263 class=b></div>
        </div>
        <div id=div27>
          <div id=div271></div>
          <div id=div272 class=a></div>
          <div id=div273 class=b></div>
        </div>
      </div>
      <div id=div3 class=a>
        <div id=div31></div>
      </div>
      <div id=div4 class=b>
        <div id=div41></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div23", ":has(+ .a ~ .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div212", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div213", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div233", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div24", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div242", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div243", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div25", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div251", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div252", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div253", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div26",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div261", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div262", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div263", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div27", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div271", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div272", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div273", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div22", ":has(+ .a ~ .b)",
              /* expected_match_result */ false,
              /* expected_result_cache_count */ 3,
              {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div2", kCheckPseudoHasResultSomeChildrenChecked},
               {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div212", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div213", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div22", kCheckPseudoHasResultChecked, kSameAsCached},
               {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23",
                kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
                    kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
                kSameAsCached},
               {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div233", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div242", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div243", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div25", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div251", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div252", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div253", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div26", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div261", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div262", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div263", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div27", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div271", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div272", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div273", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 1,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div22", ":has(+ .a ~ .c)",
              /* expected_match_result */ false,
              /* expected_result_cache_count */ 3,
              {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div2", kCheckPseudoHasResultSomeChildrenChecked},
               {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div211", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div212", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div213", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div22", kCheckPseudoHasResultChecked, kSameAsCached},
               {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23",
                kCheckPseudoHasResultChecked |
                    kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
                kSameAsCached},
               {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div233", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div242", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div243", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div25", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div251", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div252", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div253", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div26", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div261", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div262", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div263", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div27", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
               {"#div271", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div272", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div273", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 1,
              /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, Case3) {
  // CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree

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
        <div id=div21></div>
        <div id=div22></div>
        <div id=div23 class=a>
          <div id=div231></div>
          <div id=div232>
            <div id=div2321></div>
            <div id=div2322 class=b>
              <div id=div23221></div>
            </div>
            <div id=div2323></div>
          </div>
          <div id=div233></div>
          <div id=div234>
            <div id=div2341></div>
            <div id=div2342></div>
            <div id=div2343 class=a>
              <div id=div23431></div>
              <div id=div23432>
                <div id=div234321></div>
                <div id=div234322 class=b>
                  <div id=div2343221></div>
                </div>
                <div id=div234323></div>
              </div>
              <div id=div23433>
                <div id=div234331></div>
              </div>
              <div id=div23434></div>
            </div>
            <div id=div2344>
              <div id=div23441></div>
            </div>
            <div id=div2345></div>
          </div>
          <div id=div235>
            <div id=div2351></div>
          </div>
          <div id=div236></div>
        </div>
        <div id=div24>
          <div id=div241></div>
        </div>
        <div id=div25></div>
      </div>
      <div id=div3></div>
      <div id=div4></div>
    </main>
  )HTML");

  TestMatches(
      document, "div22", ":has(+ .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 10,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div23", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div232", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2321", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2322", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2323", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div233", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div234", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div2341", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2342", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2343", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div23431", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23432", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div234321", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div234322",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2343221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23433",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div234331", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23434", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2344",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div23441", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2345", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div235",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div2351", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div236", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div25", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div1", ":has(+ .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 5,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div21",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div23", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div233", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2341", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2342", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2343", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23431", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23432", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2343221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23433", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234331", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23434", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2344", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23441", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2345", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div235", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2351", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div236", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div25", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div22", ":has(+ .a .c)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div23", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div231",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div233", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2341", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2342", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2343", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23431", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23432", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2343221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23433", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div234331", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23434", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2344", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23441", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2345", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div235", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2351", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div236", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div241", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div25", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, Case4) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees

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
        <div id=div21></div>
        <div id=div22></div>
        <div id=div23 class=a>
          <div id=div231></div>
          <div id=div232>
            <div id=div2321></div>
            <div id=div2322 class=b>
              <div id=div23221></div>
            </div>
            <div id=div2323></div>
          </div>
          <div id=div233></div>
        </div>
        <div id=div24>
          <div id=div241></div>
          <div id=div242>
            <div id=div2421></div>
            <div id=div2422></div>
            <div id=div2423 class=a>
              <div id=div24231></div>
              <div id=div24232>
                <div id=div242321></div>
                <div id=div242322 class=b>
                  <div id=div2423221></div>
                </div>
                <div id=div242323></div>
              </div>
              <div id=div24233>
                <div id=div242331></div>
              </div>
              <div id=div24234></div>
            </div>
            <div id=div2424>
              <div id=div24241></div>
            </div>
            <div id=div2425></div>
          </div>
          <div id=div243>
            <div id=div2431></div>
          </div>
          <div id=div244></div>
        </div>
        <div id=div25>
          <div id=div251></div>
        </div>
        <div id=div26>
          <div id=div261></div>
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
      document, "div22", ":has(~ .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 10,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div23", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div232", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div2321", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2322",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div23221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div233",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div24",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2421", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2422", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2423", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2423221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24233", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242331", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24234", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2424", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2425", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div243", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2431", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div244", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div25", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div251", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div26", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div261", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div4", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div41", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div21", ":has(~ .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 10,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div22", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div23", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div231", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div232", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div2321", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2322",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div23221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div233",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div24",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2421", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2422", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div2423", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2423221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24233", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242331", kCheckPseudoHasResultNotCac
```