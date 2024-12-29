Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. This file seems to be a test case for the `:has()` CSS pseudo-class and its caching mechanism.

Here's a breakdown of how to approach the prompt:

1. **Identify the core purpose:** The file is a test suite (`_test.cc`) for `CheckPseudoHasCacheScopeContext`. This strongly suggests it's about verifying the caching behavior of the `:has()` pseudo-class.

2. **Analyze the `TestMatches` and `TestQuerySelectorAll` functions:** These are likely helper functions within the test suite. They take a CSS selector with `:has()` and check if the matching behavior and the cache states are as expected.

3. **Examine the test cases:** Each `TEST_F` block sets up a small HTML structure and then calls `TestMatches` or `TestQuerySelectorAll` with different selectors and expected results. The expected results include the match outcome and the cache state of various elements.

4. **Relate to web technologies (JavaScript, HTML, CSS):** The `:has()` pseudo-class is a CSS feature. The test cases manipulate HTML structures and assert the behavior of CSS selectors. JavaScript might be indirectly involved as the engine that executes these selectors in a browser.

5. **Infer logical reasoning:** The tests involve specific HTML structures and CSS selectors. By analyzing the selectors and the expected match results and cache states, we can infer the logic being tested. The cache states indicate whether the engine re-evaluated the `:has()` condition for specific elements or used a cached result.

6. **Consider user errors:** Incorrectly using the `:has()` pseudo-class can lead to unexpected behavior or performance issues if caching is not working correctly.

7. **Trace user operations:**  While the code itself is not directly tied to a specific user action, the scenarios it tests relate to how a browser engine processes CSS selectors triggered by user interactions or page rendering.

8. **Focus on summarizing the functionality:**  Given this is part 3 of 5, the request is to synthesize the information into a concise summary of the file's purpose.
```cpp
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(~ .a) .b", {"div1111", "div1211"},
      /* expected_result_cache_count */ 10,
      {{"main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div12",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1211", kCheckPseudoHasResultChecked, kSameAsCached},
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

  TestQuerySelectorAll(
      document, "main", ":has(~ .a) .b, :has(+ .c) .d", {"div1111", "div1211"},
      /* expected_result_cache_count */ 10,
      {{"main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div12",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1211", kCheckPseudoHasResultChecked, kSameAsCached},
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
      /* expected_fast_reject_filter_cache_count */ 5,
      /* expected_bloom_filter_allocation_count */ 2);
}

}  // namespace blink
```

Based on the provided code snippet (part 3 of 5), here's a summary of its functionality:

**Functionality:**

This code file (`check_pseudo_has_cache_scope_context_test.cc`) contains **unit tests** for the caching mechanism specifically related to the `:has()` CSS pseudo-class within the Blink rendering engine. It focuses on verifying how the engine caches the results of `:has()` queries in different scenarios to optimize performance.

**Relationship to JavaScript, HTML, and CSS:**

* **CSS:** The core of these tests revolves around the `:has()` CSS pseudo-class. This pseudo-class allows you to select elements based on whether they have descendants matching a given selector. The tests verify that the results of these potentially expensive `:has()` evaluations are cached correctly.
    * **Example:** The selectors like `:has(.a .b)` and `:has(~ .a .b)` are directly CSS syntax being tested.

* **HTML:** The tests create small, controlled HTML document structures (using `document->write(R"HTML(...)HTML")`) to simulate different scenarios where `:has()` might be used. The structure of the HTML directly influences which elements the `:has()` selector will match and how the caching should behave.
    * **Example:** The HTML code defines elements with specific IDs (like `#div1`, `#div11`, etc.) and classes (`.a`, `.b`), which are then used in the CSS selectors within the tests.

* **JavaScript:** While this specific file is C++, it tests the underlying engine that would execute CSS selectors often triggered by JavaScript interactions or during initial page rendering. JavaScript's `querySelector` and `querySelectorAll` methods can trigger the evaluation of these CSS selectors, including those with `:has()`.

**Logical Reasoning (with assumptions and examples):**

The tests use helper functions like `TestMatches` and `TestQuerySelectorAll`. These functions likely take:

* **Input (Assumption):**
    * An HTML document.
    * A CSS selector string containing `:has()`.
    * A target element within the document (for `TestMatches`).
    * Expected match result (true/false for `TestMatches`).
    * Expected cache states for specific elements.

* **Output (Implicit):** The tests assert that:
    * The `:has()` selector correctly matches or doesn't match the target element.
    * The internal cache states of the elements involved are as expected (e.g., `kCheckPseudoHasResultChecked`, `kCheckPseudoHasResultNotCached`, `kSameAsCached`).

**Example of Logical Reasoning from the Code:**

The test case:

```cpp
  TestMatches(
      document, "div1", ":has(~ .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 7,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       // ... other elements with their expected cache states
      },
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);
```

**Assumptions:**

* The HTML document contains the structure defined earlier in that `TEST_F` block.
* The selector `:has(~ .a .b)` checks if the selected element (`div1` in this case) has a sibling that contains an element with class `a` that further contains an element with class `b`.

**Reasoning:**

1. The test asserts that `div1` does **not** match the selector (`expected_match_result` is `false`).
2. It also asserts that after this match attempt, the element `main` has a cache state of `kCheckPseudoHasResultSomeChildrenChecked` and its result is `kNotYetChecked`. This suggests that the engine started checking descendants of `main` but hasn't fully cached the result for this specific `:has()` query yet.
3. Other elements have specific expected cache states (`kSameAsCached`, `kAlreadyNotMatched`, etc.), indicating that the engine's caching mechanism is working in a specific way for those elements based on previous evaluations.

**User or Programming Common Usage Errors:**

* **Over-reliance on complex `:has()` selectors:**  While powerful, deeply nested or very broad `:has()` selectors can be computationally expensive. If the caching mechanism isn't working correctly, this could lead to performance bottlenecks. These tests ensure the caching helps mitigate this.
* **Unexpected caching behavior:** Developers might make assumptions about when and how the results of `:has()` are cached. These tests help ensure the caching behavior is predictable and consistent with expectations. For instance, they test scenarios where a result is marked `kSameAsCached`, meaning a previous evaluation was reused.

**User Operation to Reach This Code (Debugging Clue):**

While a user won't directly interact with this C++ test file, their actions can trigger the code being tested:

1. **User Browses a Website:** A user navigates to a website that uses complex CSS selectors, including `:has()`, for styling or dynamic behavior.
2. **Browser Renders the Page:** The browser's rendering engine (Blink in this case) needs to evaluate the CSS to determine which styles apply to which elements.
3. **CSS Selector Evaluation:**  When encountering a `:has()` selector, the engine initiates a search within the DOM to find matching descendants (or siblings, depending on the combinator).
4. **Caching Mechanism Engages:** The `CheckPseudoHasCacheScopeContext` logic is involved in determining if the result of this `:has()` evaluation can be retrieved from a cache or if a new evaluation is needed.
5. **Potential Performance Issues (Without Correct Caching):** If the caching isn't working correctly, the browser might repeatedly evaluate the same expensive `:has()` selectors, leading to jank or slow rendering.
6. **Developer Debugging:** If a web developer notices performance issues related to CSS selectors, they might investigate the rendering engine's behavior, potentially leading them to examine test files like this one to understand how the `:has()` caching is implemented and tested.

**Summary of Functionality (for Part 3):**

This part of the test file focuses on verifying the caching behavior of the `:has()` CSS pseudo-class when used with the **sibling combinator (`~`)** and the **descendant combinator (space)**. It checks various scenarios, including cases where the `:has()` selector matches, doesn't match, and how the cache states of different elements are updated during these evaluations. The tests ensure that the engine correctly caches and reuses the results of `:has()` queries to optimize performance, particularly when dealing with complex selectors and nested HTML structures.

Prompt: 
```
这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
hed, kAlreadyNotMatched},
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
      document, "div1", ":has(~ .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 7,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div21", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
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
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
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
       {"#div3", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div31", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div4", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div41", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div22", ":has(~ .a .c)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div23",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div231", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div232", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2321", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2322", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div23221", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2323", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div233", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div24", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div241", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div242", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2421", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2422", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
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
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase1StartsWithDescendantCombinator) {
  // CheckPseudoHasArgumentTraversalScope::kSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
        <div id=div12 class=a>
          <div id=div121 class=b>
            <div id=div1211 class=a>
              <div id=div12111 class=b></div>
            </div>
          </div>
        </div>
        <div id=div13 class=a>
          <div id=div131 class=b></div>
        </div>
        <div id=div14></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div1", ":has(.a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 7,
      {{"html", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"body", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div131",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div11", ":has(.a .b)",
              /* expected_match_result */ false,
              /* expected_result_cache_count */ 1,
              {{"#div11", kCheckPseudoHasResultChecked, kSameAsCached}},
              /* expected_fast_reject_filter_cache_count */ 1,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div12", ":has(.a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 8,
      {{"html", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"body", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1211", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div12111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div131", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div14", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  // ':has(.a .b)' does not match #div1211 but this caches possibly matched
  // elements because argument selector checking can cross over the :has()
  // anchor element.
  TestMatches(
      document, "div1211", ":has(.a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 8,
      {{"html", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"body", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1211",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div12111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div131", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div14", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  // ':has(.a .b)' does not match #div13 but this caches possibly matched
  // elements because argument selector checking can cross over the :has()
  // anchor element.
  TestMatches(
      document, "div13", ":has(.a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 6,
      {{"html", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"body", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div131",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(.a .b)", {"div1", "div12", "div121"},
      /* expected_result_cache_count */ 12,
      {{"html", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"body", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div12", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1211",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div12111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div13",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div131",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 5,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(.a .b), :has(.c .d)", {"div1", "div12", "div121"},
      /* expected_result_cache_count */ 12,
      {{"html", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"body", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#main", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultChecked, kSameAsCached},
       {"#div12", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div121", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1211",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div12111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div13",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div131",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div14",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 6,
      /* expected_bloom_filter_allocation_count */ 3);
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase1StartsWithChildCombinator) {
  // CheckPseudoHasArgumentTraversalScope::kSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11 class=a>
          <div id=div111 class=b>
            <div id=div1111 class=a>
              <div id=div11111 class=b></div>
            </div>
          </div>
        </div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div1", ":has(> .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 4,
      {{"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div111", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div11111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div11", ":has(> .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 3,
      {{"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div11111", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(> .a .b)", {"div1", "div111"},
      /* expected_result_cache_count */ 5,
      {{"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 2,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(> .a .b), :has(> .c .d)", {"div1", "div111"},
      /* expected_result_cache_count */ 5,
      {{"#div1", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 2,
      /* expected_bloom_filter_allocation_count */ 1);
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase1StartsWithChildCombinatorNonSubjectHas) {
  // CheckPseudoHasArgumentTraversalScope::kSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11>
          <div id=div111 class=a>
            <div id=div1111 class=a>
              <div id=div11111 class=b></div>
            </div>
            <div id=div1112></div>
          </div>
          <div id=div112>
            <div id=div1121></div>
          </div>
          <div id=div113 class=c>
            <div id=div1131 class=d></div>
          </div>
        </div>
        <div id=div12 class=c>
          <div id=div121 class=d></div>
        </div>
      </div>
      <div id=div2 class=c>
        <div id=div21 class=d></div>
      </div>
    </main>
  )HTML");

  TestMatches(
      document, "div112", ":has(> .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 2,
      {{"#div112",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div1121",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div111", ":has(> .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 4,
      {{"#div111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div11111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div11", ":has(> .a .b)",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 6,
      {{"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div11111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div113", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div1131", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div1", ":has(> .a .b)",
      /* expected_match_result */ false,
      /* expected_result_cache_count */ 3,
      {{"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div111", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div11111", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div1112", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div112", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div1121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div113", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div1131", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div12", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(> .a .b) ~ .c .d", {"div1131", "div121"},
      /* expected_result_cache_count */ 8,
      {{"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div111",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultSomeChildrenChecked,
        kAlreadyNotMatched},
       {"#div11111",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div1112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div1121",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div113", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div1131", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div12", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div121", kCheckPseudoHasResultNotCached, kAlreadyNotMatched},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 4,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest,
       QuerySelectorAllCase2NonSubjectHas) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblings

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11 class=a>
          <div id=div111>
            <div id=div1111 class=b></div>
          </div>
          <div id=div112 class=a></div>
        </div>
        <div id=div12>
          <div id=div121>
            <div id=div1211 class=b></div>
          </div>
          <div id=div122></div>
        </div>
        <div id=div13></div>
      </div>
      <div id=div2 class=a></div>
    </main>
  )HTML");

  TestMatches(
      document, "div1111", ":has(~ .a) .b",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 3,
      {{"main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div111", kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched,
        kSameAsCached},
       {"#div1111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div112",
        kCheckPseudoHasResultChecked |
            kCheckPseudoHasResultAllDescendantsOrNextSiblingsChecked,
        kSameAsCached},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div121", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1211", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div122", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 1,
      /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(
      document, "div1211", ":has(~ .a) .b",
      /* expected_match_result */ true,
      /* expected_result_cache_count */ 7,
      {{"main", kCheckPseudoHasResultSomeChildrenChecked, kNotYetChecked},
       {"#div1",
        kCheckPseudoHasResultChecked | kCheckPseudoHasResultMatched |
            kCheckPseudoHasResultSomeChildrenChecked,
        kSameAsCached},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1111", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div112", kCheckPseudoHasResultNotCached, kNotYetChecked},
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
            kCheckPseudoHasResultAllDescendantsOrNext
"""


```