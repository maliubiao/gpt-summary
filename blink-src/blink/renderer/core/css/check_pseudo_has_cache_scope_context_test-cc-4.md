Response:
The user is asking for a summary of the functionality of the provided C++ test file for the Chromium Blink engine. The file is located at `blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc`.

I need to:
1. **Determine the main purpose of the test file.** Based on the name, it likely tests the caching mechanism for the `:has()` CSS pseudo-class, specifically focusing on the scope context.
2. **Explain how this relates to JavaScript, HTML, and CSS.** The `:has()` pseudo-class is a CSS feature that allows selecting elements based on whether they have certain descendant elements. This interacts with the DOM structure (HTML) and can be manipulated using JavaScript.
3. **Provide examples illustrating the interaction.** I should use the provided test cases as inspiration for these examples.
4. **If there's logic involved, outline input and output.** The tests check if a selector matches and verify the caching behavior. I can show a simple HTML structure and a CSS rule using `:has()` and the expected matching result.
5. **Identify common user errors.**  Misunderstanding the scope or specificity of the `:has()` selector is a common mistake.
6. **Describe user actions leading to these tests.** Developers writing or modifying CSS and JavaScript code that uses the `:has()` pseudo-class might trigger these tests.
7. **Finally, summarize the file's function as part 5 of 5.** This should be a concise recap of its core purpose.这是 `blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc` 文件的第 5 部分，也是最后一部分。综合前 4 部分，我们可以归纳出这个文件的主要功能是：

**该文件用于测试 Blink 渲染引擎中 `:has()` CSS 伪类的缓存机制，特别是当 `:has()` 伪类的参数涉及到不同的作用域上下文时，缓存是否能够正确工作。**

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  `:has()` 是一个 CSS 伪类，允许你选择父元素，当其内部存在匹配特定选择器的子元素时。例如，`div:has(> p.highlight)` 会选择所有直接子元素包含 class 为 `highlight` 的 `<p>` 元素的 `div` 元素。
* **HTML:**  测试文件中的 `document->write(R"HTML(...)HTML");`  部分定义了用于测试的 HTML 结构。这些结构模拟了不同的 DOM 树形结构，以便测试 `:has()` 在不同场景下的行为。
* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部逻辑，但 `:has()` 伪类的最终效果会影响 JavaScript 代码的行为。例如，使用 `document.querySelectorAll()` 或 `element.matches()` 等 JavaScript API 来查询 DOM 元素时，`:has()` 伪类的匹配结果会直接影响这些 API 返回的元素集合。

**功能归纳：**

这个测试文件着重于验证 `:has()` 伪类的缓存机制在以下场景中的正确性：

* **不同的遍历作用域 (Traversal Scope):**  `:has()` 伪类的参数选择器可能需要在不同的 DOM 结构中进行遍历，例如：
    * 仅限子元素 (`>`)
    * 后续兄弟元素 (`~`)
    * 所有后代元素
    * 影子 DOM 子树
    * 固定深度的后代元素
* **缓存命中与未命中:**  测试用例会验证在不同查询条件下，缓存是否被正确使用，避免重复计算，提高性能。
* **快速拒绝过滤器 (Fast Reject Filter) 和 Bloom 过滤器:**  测试用例会检查这些优化技术是否被正确应用于 `:has()` 伪类的缓存。

**逻辑推理 (假设输入与输出):**

假设我们有以下 HTML 结构和 CSS 规则：

**HTML:**

```html
<div id="parent">
  <p class="target">目标段落</p>
</div>
<div id="another-parent"></div>
```

**CSS:**

```css
#parent:has(.target) {
  color: red;
}
```

**测试用例的逻辑可能如下：**

1. **输入：**  针对上述 HTML 结构，执行 JavaScript 代码 `document.querySelector('#parent')` 并检查其样式。
2. **预期输出：** 由于 `#parent` 元素包含 class 为 `target` 的子元素，CSS 规则应该生效，`#parent` 的文本颜色应该是红色。
3. **缓存测试：** 随后，可能执行类似的查询，例如 `document.querySelector('#another-parent:has(.target)')`。由于 `#another-parent` 没有 class 为 `target` 的子元素，且缓存机制正常工作，引擎应该能够快速判断不匹配，而不需要重新遍历整个 DOM 树。测试会验证此时缓存状态是否正确。

**用户或编程常见的使用错误举例：**

* **误解 `:has()` 的作用域:**  用户可能错误地认为 `:has()` 会在其父元素的更远祖先元素中查找匹配项，而实际上 `:has()` 的查找范围取决于其参数选择器。例如：
    ```html
    <div class="grandparent">
      <div class="parent"></div>
      <p class="target"></p>
    </div>
    ```
    CSS: `div.parent:has(.target)`  **错误预期：** 认为会选中 `div.parent`，因为 `.target` 是其祖先元素。
    **正确理解：**  此选择器只会查找 `div.parent` 的 **后代元素** 中是否存在 `.target`。由于 `.target` 是 `div.parent` 的兄弟元素，所以不会被选中。

* **性能问题:**  过度使用复杂的 `:has()` 选择器可能会导致性能问题，尤其是在大型、动态的页面上。用户可能会无意中编写出性能不佳的 CSS 规则。这个测试文件确保了 Blink 引擎对 `:has()` 的实现进行了优化，包括缓存机制，以缓解这类问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **开发者编写或修改使用了 `:has()` 伪类的 CSS 代码。**
2. **浏览器渲染引擎（Blink）在解析和应用 CSS 规则时，会遇到包含 `:has()` 的选择器。**
3. **为了确定哪些元素匹配这些规则，Blink 引擎需要执行 `:has()` 伪类的匹配逻辑。**
4. **为了提高性能，Blink 引擎尝试利用缓存来存储 `:has()` 伪类匹配的结果。**
5. **如果发现 `:has()` 伪类的行为异常，例如匹配结果不正确或性能下降，Blink 开发者可能会通过运行测试用例来调试问题。**
6. **这个 `check_pseudo_has_cache_scope_context_test.cc` 文件就是用于专门测试 `:has()` 伪类在不同作用域上下文中的缓存机制的。** 开发者会运行这个测试文件，观察测试结果，并根据失败的测试用例来定位和修复代码中的缺陷。

**总结:**

总而言之，`blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc` 文件是 Blink 引擎中一个重要的测试组件，它专注于验证 `:has()` CSS 伪类在涉及不同 DOM 结构作用域时的缓存机制的正确性和效率，确保了浏览器在处理这种复杂的 CSS 特性时能够保持高性能和准确性。

Prompt: 
```
这是目录为blink/renderer/core/css/check_pseudo_has_cache_scope_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
in", kCheckPseudoHasResultNotCached, kNotYetChecked},
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
}

TEST_F(CheckPseudoHasCacheScopeContextTest, QuerySelectorAllCase8) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblingsFixedDepthDescendants

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
        <div id=div22 class=a>
          <div id=div221 class=b></div>
          <div id=div222></div>
          <div id=div223></div>
        </div>
        <div id=div23></div>
      </div>
      <div id=div3 class=a>
        <div id=div31 class=b></div>
        <div id=div32></div>
        <div id=div33></div>
      </div>
    </main>
  )HTML");

  TestMatches(document, "div1", ":has(~ .a > .b)",
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
               {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div2", ":has(~ .a > .b)",
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
               {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestMatches(document, "div21", ":has(~ .a > .b)",
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
               {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
               {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
              /* expected_fast_reject_filter_cache_count */ 0,
              /* expected_bloom_filter_allocation_count */ 0);

  TestQuerySelectorAll(
      document, "main", ":has(~ .a > .b)", {"div1", "div2", "div21"},
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div12", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div13", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div222", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div223", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div32", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div33", kCheckPseudoHasResultNotCached, kNotYetChecked}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0);
}

TEST_F(CheckPseudoHasCacheScopeContextTest, QuerySelectorAllCase9) {
  // CheckPseudoHasArgumentTraversalScope::kShadowRootSubtree

  // TODO(blee@igalia.com) Need cache support for this case - :has() checks a
  // relationship between shadow root and its descendant. (e.g. :host:has(.a))

  Document* document = &GetDocument();
  document->body()->setHTMLUnsafe(R"HTML(
    <!DOCTYPE html>
    <main id="main">
      <div id="host">
        <template shadowrootmode="open">
          <div id="div1" class="b">
            <div id="div11"></div>
          </div>
          <div id="div2">
            <div id="div21"></div>
            <div id="div22" class="a">
              <div id="div221" class="b"></div>
            </div>
            <div id="div23"></div>
          </div>
          <div id="div3">
            <div id="div31" class="b"></div>
          </div>
        </template>
      </div>
    </main>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  TestMatches(
      document, "div1", ":host:has(.a) .b", /* expected_match_result */ true,
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");

  TestMatches(
      document, "div221", ":host:has(.a) .b", /* expected_match_result */ true,
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");

  TestMatches(
      document, "div31", ":host:has(.a) .b", /* expected_match_result */ true,
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");

  TestQuerySelectorAll(
      document, nullptr, ":host:has(.a) .b", {"div1", "div221", "div31"},
      /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");
}

TEST_F(CheckPseudoHasCacheScopeContextTest, QuerySelectorAllCase10) {
  // CheckPseudoHasArgumentTraversalScope::kShadowRootFixedDepthDescendants

  Document* document = &GetDocument();
  document->body()->setHTMLUnsafe(R"HTML(
    <!DOCTYPE html>
    <main id="main">
      <div id="host">
        <template shadowrootmode="open">
          <div id="div1" class="b">
            <div id="div11"></div>
          </div>
          <div id="div2">
            <div id="div21"></div>
            <div id="div22" class="a">
              <div id="div221" class="b"></div>
            </div>
            <div id="div23"></div>
          </div>
          <div id="div3">
            <div id="div31" class="b"></div>
          </div>
        </template>
      </div>
    </main>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  TestMatches(
      document, "div1", ":host:has(> div > .a) .b",
      /* expected_match_result */ true, /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");

  TestMatches(
      document, "div221", ":host:has(> div > .a) .b",
      /* expected_match_result */ true, /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");

  TestMatches(
      document, "div31", ":host:has(> div > .a) .b",
      /* expected_match_result */ true, /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");

  TestQuerySelectorAll(
      document, nullptr, ":host:has(> div > .a) .b",
      {"div1", "div221", "div31"}, /* expected_result_cache_count */ 0,
      {{"#main", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#host", kCheckPseudoHasResultNotCached, kNotYetChecked},
       {"#div1", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div11", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div2", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div21", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div22", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div221", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div23", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div3", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"},
       {"#div31", kCheckPseudoHasResultNotCached, kNotYetChecked, "host"}},
      /* expected_fast_reject_filter_cache_count */ 0,
      /* expected_bloom_filter_allocation_count */ 0,
      /* shadow_host_id */ "host");
}

}  // namespace blink

"""


```