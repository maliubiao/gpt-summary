Response:
My thinking process to answer the request goes through these stages:

1. **Understanding the Core Request:** The main goal is to understand the functionality of the provided C++ code snippet (`style_resolver_test.cc`) within the Chromium/Blink context. The request specifically asks about its relationship to JavaScript, HTML, and CSS, to provide examples, to illustrate logical reasoning with input/output, to identify potential user errors, to trace user operations, and to summarize its function.

2. **Initial Code Scan and Identification of Key Areas:** I first scan the code looking for patterns and keywords. I see a lot of `TEST_F`, which immediately tells me this is a unit testing file using the Google Test framework. I notice keywords related to:
    * **CSS Properties:** `color`, `font-size`, `left`, `width`, `display`, `unicode-bidi`, `font-family`, `background-color`, `contain`, `transform-origin`, `perspective-origin`.
    * **CSS Features:**  `anchor()`, cascade layers (`@layer`), container queries (`@container`), `transition`, `!important`.
    * **DOM Elements and Attributes:** `div`, `style`, `id`, `class`, `inert`, `dialog`, `template`, `shadowrootmode`, `fullscreen`.
    * **Blink/Chromium Specifics:** `GetDocument()`, `ComputedValue()`, `ComputedStyleRef()`, `UpdateAllLifecyclePhasesForTest()`, `StyleForId()`, `StyleResolverState`, `ElementRuleCollector`, `MatchAllRules()`, `CascadeLayerMap`, `GetScopedStyleResolver()`, `QuerySelector()`, `QuerySelectorAll()`, `SetInlineStyleProperty()`, `GetComputedStyle()`, `GetLayoutObject()`, `showModal()`, `close()`, `Fullscreen`, `IsUseCounted()`, `WebFeature`.
    * **Testing Concepts:** `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`.

3. **Categorizing Functionality:** Based on the keywords, I start grouping the tests into logical categories:
    * **Basic Style Resolution:** Tests checking computed values of basic CSS properties.
    * **Anchor Positioning:** Tests related to the `anchor()` CSS function.
    * **Cascade Layers:** Tests focused on the behavior of `@layer` in CSS.
    * **Container Queries:** Tests concerning `@container` and container query styling.
    * **`inert` Attribute:** Tests verifying how the `inert` attribute affects styling, especially in combination with dialogs and fullscreen.
    * **Fullscreen API:** Tests checking the interaction of the Fullscreen API with styling and the `inert` attribute.
    * **Legacy CSS Property Handling:** Tests dealing with prefixed (`-webkit-`) and standard versions of `perspective-origin` and `transform-origin`.

4. **Relating to HTML, CSS, and JavaScript:** I then explicitly consider how these tests relate to the core web technologies:
    * **HTML:** The tests manipulate the DOM structure using JavaScript-like syntax (though within the C++ testing environment). They create elements, set attributes, and manipulate innerHTML. This directly tests how style resolution works with different HTML structures.
    * **CSS:** The core of the tests is verifying how CSS rules are applied and resolved. They test various CSS features like selectors, properties, cascade layers, container queries, and the `inert` attribute.
    * **JavaScript:** While the tests themselves are in C++, they indirectly test the results of JavaScript interactions. For example, the tests around `dialog.showModal()` and `Fullscreen.requestFullscreen()` simulate JavaScript actions that trigger style recalculations. The tests verify the *outcome* of these JavaScript actions on the styling.

5. **Developing Examples and Scenarios:** For each category, I start thinking about concrete examples:
    * **Basic Styling:** Setting basic properties and verifying the computed values.
    * **Anchor Positioning:** Showing how `anchor()` can position elements relative to others.
    * **Cascade Layers:**  Illustrating how `@layer` affects the order and precedence of styles.
    * **`inert`:** Demonstrating how `inert` disables interactivity and its behavior within dialogs and fullscreen.
    * **Fullscreen:**  Showing how entering fullscreen affects the styling of different elements.

6. **Constructing Logical Reasoning with Input/Output:** For a few representative tests, I try to formulate a clear input (the HTML and CSS setup) and the expected output (the computed style or a specific behavior). This helps illustrate the test's logic.

7. **Identifying Potential User Errors:** I consider common mistakes developers might make when working with the features tested in the file. For example, misunderstanding cascade layer order, incorrect usage of the `inert` attribute, or forgetting to include necessary polyfills for older browsers.

8. **Tracing User Operations (Debugging Clues):** I think about how a developer might end up needing to debug this part of the rendering engine. This usually involves issues with styles not being applied correctly, unexpected behavior with `inert`, or problems with newer CSS features like cascade layers or container queries. The debugging process involves inspecting the DOM, computed styles, and potentially stepping through the rendering engine's code.

9. **Summarizing the Function:** Finally, I synthesize the information gathered into a concise summary of the file's purpose, emphasizing its role in testing CSS style resolution within Blink.

10. **Structuring the Answer:** I organize the information into the requested sections (功能, 与...关系, 逻辑推理, 常见错误, 用户操作, 功能归纳) to make the answer clear and easy to understand. I pay attention to using the correct terminology and providing sufficient detail without being overly verbose. I also remember that this is part 3 of a 5-part series, so I keep the summary focused on the content of this specific file.

Throughout this process, I iteratively refine my understanding and the examples based on the specific tests provided in the code snippet. I focus on extracting the *intent* of each test and generalizing it to explain the overall functionality of the `style_resolver_test.cc` file.
好的，这是对提供的第三部分代码的功能归纳：

**功能归纳 (第 3 部分):**

这部分 `style_resolver_test.cc` 文件主要关注以下几个方面的 CSS 样式解析和应用逻辑的测试：

* **CSS 锚点定位 (`anchor()`):**  测试了 `anchor()` 函数的基本功能，包括计算基于锚点元素的属性值，以及在带有 `transition` 属性时是否会存储旧的样式状态。
* **CSS 层叠层 (`@layer`):**
    * 测试了在没有显式声明层叠层的情况下，样式的层叠顺序。
    * 测试了在不同的样式表中使用 `@layer` 定义层叠层，以及它们之间的样式优先级关系。
    * 测试了在不同的 Shadow DOM 树作用域中使用 `@layer` 定义层叠层时的样式隔离和优先级。
    * 测试了在修改其他样式表后，已定义的层叠层是否能正确更新和应用样式。
    * 测试了在层叠层中使用 `!important` 声明时，样式的优先级处理。
* **`contain` 属性与 `body` 元素:** 测试了 `contain: size` 属性在 `documentElement` 上设置时，是否会影响 `body` 元素的背景色继承，避免不必要的断言失败。
* **`inert` 属性:**
    * 测试了 `inert` 属性的基本功能，包括阻止元素及其子元素的交互。
    * 测试了 `inert` 属性与 `dialog` 元素（模态框）的相互作用，包括模态框打开和关闭时 `inert` 属性的继承和状态变化。
    * 测试了嵌套 `dialog` 元素时 `inert` 属性的作用范围。
    * 测试了 `inert` 属性与全屏 API 的交互，包括进入和退出全屏时 `inert` 属性在不同元素上的状态变化。
    * 测试了 `inert` 属性与 `<dialog>` 元素的 backdrop 伪元素的关联。
    * 测试了 `dialog` 元素和全屏模式同时存在时，`inert` 属性的状态变化。
* **CSS 容器查询 (`@container`):** 测试了对于带有容器查询规则的元素，即使容器查询条件不满足，也会收集到对应的样式规则。
* **旧有 `-webkit-` 前缀属性的兼容性处理 (`perspective-origin`, `transform-origin`):** 测试了当同时存在标准属性和带有 `-webkit-` 前缀的旧有属性时，Blink 的处理逻辑，以及是否会统计对旧有属性的使用情况。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **HTML:** 代码中通过 C++ 代码模拟了 HTML 结构，例如使用 `setInnerHTML` 创建 `<div>`, `<style>`, `<dialog>` 等元素，并设置 `id`, `class`, `inert` 等属性。这直接关系到浏览器如何解析和构建 DOM 树。
    * **例子:**  `GetDocument().documentElement()->setInnerHTML(R"HTML(<div id=a class=b></div>)HTML");`  这段代码模拟了在 HTML 中创建了一个 `id` 为 "a"， `class` 为 "b" 的 `div` 元素。

* **CSS:**  测试的核心是 CSS 样式的解析和应用。代码中包含了各种 CSS 规则的定义，例如选择器、属性和值。测试验证了不同 CSS 特性（如层叠层、锚点定位、容器查询）的实现是否符合规范。
    * **例子:** `EXPECT_EQ("100px", ComputedValue("left", a->ComputedStyleRef()));` 这行代码验证了 id 为 "a" 的元素计算后的 `left` 样式属性值是否为 "100px"。

* **Javascript:** 虽然测试代码本身是 C++，但它模拟了 JavaScript 交互可能触发的样式变化。例如，`dialog->showModal()` 模拟了 JavaScript 调用打开模态框，这会导致浏览器重新计算样式。全屏 API 的测试也模拟了 JavaScript 请求进入全屏的操作。
    * **例子:** `dialog->showModal(exception_state);`  模拟了 JavaScript 调用 `dialog.showModal()` 方法，测试在这种情况下 `inert` 属性的表现。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
    ```html
    <style>
      #container { container-type: inline-size }
      @container (min-width: 100px) {
        #target { color: red; }
      }
    </style>
    <div id="container" style="width: 50px;">
      <div id="target"></div>
    </div>
    ```
* **预期输出:**  `#target` 元素的计算样式中 `color` 属性的值不会是 `red`，因为容器 `#container` 的宽度（50px）小于容器查询条件 `min-width: 100px`。测试会验证即使容器查询条件不满足，相关的样式规则仍然会被收集到。

**用户或编程常见的使用错误:**

* **层叠层优先级理解错误:** 用户可能不清楚 `@layer` 定义的层叠顺序，导致样式被意外覆盖。例如，在一个层叠层中定义的样式可能被另一个层叠层中定义的同名样式覆盖，即使后者的选择器优先级较低。
* **`inert` 属性误用:**  用户可能错误地将 `inert` 应用于不应该禁用的元素，导致用户无法与页面交互。或者，在模态框或全屏元素中使用 `inert` 时，没有充分理解其影响范围。
* **忘记处理 `-webkit-` 前缀属性:**  虽然现代浏览器逐渐淘汰 `-webkit-` 前缀，但用户可能仍然在旧代码中使用，或者需要兼容旧版本浏览器。测试确保了 Blink 仍然能正确处理这些旧有属性，并能检测到其使用情况。

**用户操作是如何一步步到达这里 (调试线索):**

1. **用户报告样式问题:** 用户在网页上发现某些元素的样式没有正确应用，例如颜色不对、布局错乱，或者某些交互元素无法点击。
2. **开发者检查 CSS:** 开发者首先会检查相关的 CSS 规则，查看选择器、属性和值是否正确。
3. **使用开发者工具调试:** 开发者使用浏览器开发者工具（如 Chrome DevTools）检查元素的计算样式 (`Computed` 标签)，查看哪些 CSS 规则生效，以及是否有样式被覆盖。
4. **怀疑是 CSS 层叠或优先级问题:** 如果发现样式被意外覆盖，开发者可能会怀疑是 CSS 层叠顺序或选择器优先级的问题。
5. **涉及到新的 CSS 特性:** 如果问题涉及到使用了新的 CSS 特性，如层叠层或容器查询，开发者可能会更加关注这些特性的实现细节。
6. **Blink 渲染引擎内部错误 (极端情况):** 在极少数情况下，如果开发者排除了所有 CSS 代码错误，并且问题只在特定浏览器出现，他们可能会怀疑是浏览器渲染引擎（如 Blink）的 bug。这时，他们可能会尝试搜索相关的 bug 报告或查看 Blink 的源代码和测试用例，例如 `style_resolver_test.cc`，来理解样式的解析和应用过程，并尝试找到潜在的 bug 所在。

**总结:**

这部分测试用例主要集中在验证 Blink 渲染引擎在处理复杂的 CSS 特性（如锚点定位、层叠层、容器查询）以及特殊属性（如 `inert`, `contain`) 时的正确性。它确保了这些特性能够按照 CSS 规范工作，并且在与 HTML 结构和 JavaScript 交互时能够产生预期的样式效果。此外，还关注了对旧有 CSS 属性的兼容性处理和使用情况统计。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ing("a"));
  auto* b = GetDocument().getElementById(AtomicString("b"));

  ASSERT_TRUE(a);
  ASSERT_TRUE(b);

  EXPECT_EQ("100px", ComputedValue("left", a->ComputedStyleRef()));
  EXPECT_EQ("150px", ComputedValue("left", b->ComputedStyleRef()));
}

TEST_F(StyleResolverTest, AnchorQueryNoOldStyle) {
  // This captures any calls to StoreOldStyleIfNeeded made during
  // StyleResolver::ResolveStyle.
  PostStyleUpdateScope post_style_update_scope(GetDocument());

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #anchored {
        position: absolute;
        left: anchor(--a left, 42px);
      }
    </style>
    <div id=anchored>A</div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetCurrentOldStylesCount());
}

TEST_F(StyleResolverTest, AnchorQueryStoreOldStyle) {
  // This captures any calls to StoreOldStyleIfNeeded made during
  // StyleResolver::ResolveStyle.
  PostStyleUpdateScope post_style_update_scope(GetDocument());

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #anchored {
        position: absolute;
        left: anchor(--a left, 42px);
        transition: left 1s;
      }
    </style>
    <div id=anchored>A</div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, GetCurrentOldStylesCount());
}

TEST_F(StyleResolverTest, AnchorQueryBaseComputedStyle) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #div {
        position: absolute;
        left: anchor(--a left, 42px);
      }
    </style>
    <div id=div>A</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  // Create a situation where the base computed style optimization
  // would normally be used.
  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kWidth,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("50px", ComputedValue("width", *StyleForId("div")));
  div->SetNeedsAnimationStyleRecalc();

  // TODO(crbug.com/41483417): Enable this optimization for styles with
  // anchor queries.
  StyleResolverState state(GetDocument(), *div);
  EXPECT_FALSE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_F(StyleResolverTest, NoCascadeLayers) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #a { color: green; }
      .b { font-size: 16px; }
    </style>
    <div id=a class=b></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  StyleResolverState state(GetDocument(),
                           *GetDocument().getElementById(AtomicString("a")));
  SelectorFilter filter;
  MatchResult match_result;
  ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                 filter, match_result,
                                 EInsideLink::kNotInsideLink);
  MatchAllRules(state, collector);
  const auto& properties = match_result.GetMatchedProperties();
  ASSERT_EQ(properties.size(), 4u);

  const uint16_t kImplicitOuterLayerOrder =
      ClampTo<uint16_t>(CascadeLayerMap::kImplicitOuterLayerOrder);

  // div { display: block; }
  EXPECT_TRUE(properties[0].properties->HasProperty(CSSPropertyID::kDisplay));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[0].data_.layer_order);
  EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kUserAgent);

  // div { unicode-bidi: isolate; }
  EXPECT_TRUE(
      properties[1].properties->HasProperty(CSSPropertyID::kUnicodeBidi));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[1].data_.layer_order);
  EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kUserAgent);

  // .b { font-size: 16px; }
  EXPECT_TRUE(properties[2].properties->HasProperty(CSSPropertyID::kFontSize));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[2].data_.layer_order);
  EXPECT_EQ(properties[2].data_.origin, CascadeOrigin::kAuthor);

  // #a { color: green; }
  EXPECT_TRUE(properties[3].properties->HasProperty(CSSPropertyID::kColor));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[3].data_.layer_order);
  EXPECT_EQ(properties[3].data_.origin, CascadeOrigin::kAuthor);
}

TEST_F(StyleResolverTest, CascadeLayersInDifferentSheets) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      @layer foo, bar;
      @layer bar {
        .b { color: green; }
      }
    </style>
    <style>
      @layer foo {
        #a { font-size: 16px; }
      }
    </style>
    <div id=a class=b style="font-family: custom"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  StyleResolverState state(GetDocument(),
                           *GetDocument().getElementById(AtomicString("a")));
  SelectorFilter filter;
  MatchResult match_result;
  ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                 filter, match_result,
                                 EInsideLink::kNotInsideLink);
  MatchAllRules(state, collector);
  const auto& properties = match_result.GetMatchedProperties();
  ASSERT_EQ(properties.size(), 5u);

  const uint16_t kImplicitOuterLayerOrder =
      ClampTo<uint16_t>(CascadeLayerMap::kImplicitOuterLayerOrder);

  // div { display: block; }
  EXPECT_TRUE(properties[0].properties->HasProperty(CSSPropertyID::kDisplay));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[0].data_.layer_order);
  EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kUserAgent);

  // div { unicode-bidi: isolate; }
  EXPECT_TRUE(
      properties[1].properties->HasProperty(CSSPropertyID::kUnicodeBidi));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[1].data_.layer_order);
  EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kUserAgent);

  // @layer foo { #a { font-size: 16px } }"
  EXPECT_TRUE(properties[2].properties->HasProperty(CSSPropertyID::kFontSize));
  EXPECT_EQ(0u, properties[2].data_.layer_order);
  EXPECT_EQ(properties[2].data_.origin, CascadeOrigin::kAuthor);

  // @layer bar { .b { color: green } }"
  EXPECT_TRUE(properties[3].properties->HasProperty(CSSPropertyID::kColor));
  EXPECT_EQ(1u, properties[3].data_.layer_order);
  EXPECT_EQ(properties[3].data_.origin, CascadeOrigin::kAuthor);

  // style="font-family: custom"
  EXPECT_TRUE(
      properties[4].properties->HasProperty(CSSPropertyID::kFontFamily));
  EXPECT_TRUE(properties[4].data_.is_inline_style);
  EXPECT_EQ(properties[4].data_.origin, CascadeOrigin::kAuthor);
  // There's no layer order for inline style; it's always above all layers.
}

TEST_F(StyleResolverTest, CascadeLayersInDifferentTreeScopes) {
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      @layer foo {
        #host { color: green; }
      }
    </style>
    <div id=host>
      <template shadowrootmode=open>
        <style>
          @layer bar {
            :host { font-size: 16px; }
          }
        </style>
      </template>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  StyleResolverState state(GetDocument(),
                           *GetDocument().getElementById(AtomicString("host")));
  SelectorFilter filter;
  MatchResult match_result;
  ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                 filter, match_result,
                                 EInsideLink::kNotInsideLink);
  MatchAllRules(state, collector);
  const auto& properties = match_result.GetMatchedProperties();
  ASSERT_EQ(properties.size(), 4u);

  const uint16_t kImplicitOuterLayerOrder =
      ClampTo<uint16_t>(CascadeLayerMap::kImplicitOuterLayerOrder);

  // div { display: block }
  EXPECT_TRUE(properties[0].properties->HasProperty(CSSPropertyID::kDisplay));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[0].data_.layer_order);
  EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kUserAgent);

  // div { unicode-bidi: isolate; }
  EXPECT_TRUE(
      properties[1].properties->HasProperty(CSSPropertyID::kUnicodeBidi));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[1].data_.layer_order);
  EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kUserAgent);

  // @layer bar { :host { font-size: 16px } }
  EXPECT_TRUE(properties[2].properties->HasProperty(CSSPropertyID::kFontSize));
  EXPECT_EQ(0u, properties[2].data_.layer_order);
  EXPECT_EQ(properties[2].data_.origin, CascadeOrigin::kAuthor);
  EXPECT_EQ(
      match_result.ScopeFromTreeOrder(properties[2].data_.tree_order),
      GetDocument().getElementById(AtomicString("host"))->GetShadowRoot());

  // @layer foo { #host { color: green } }
  EXPECT_TRUE(properties[3].properties->HasProperty(CSSPropertyID::kColor));
  EXPECT_EQ(0u, properties[3].data_.layer_order);
  EXPECT_EQ(match_result.ScopeFromTreeOrder(properties[3].data_.tree_order),
            &GetDocument());
}

// https://crbug.com/1313357
TEST_F(StyleResolverTest, CascadeLayersAfterModifyingAnotherSheet) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      @layer {
        target { color: red; }
      }
    </style>
    <style id="addrule"></style>
    <target></target>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument()
      .getElementById(AtomicString("addrule"))
      ->appendChild(
          GetDocument().createTextNode("target { font-size: 10px; }"));

  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap());

  StyleResolverState state(
      GetDocument(), *GetDocument().QuerySelector(AtomicString("target")));
  SelectorFilter filter;
  MatchResult match_result;
  ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                 filter, match_result,
                                 EInsideLink::kNotInsideLink);
  MatchAllRules(state, collector);
  const auto& properties = match_result.GetMatchedProperties();
  ASSERT_EQ(properties.size(), 2u);

  const uint16_t kImplicitOuterLayerOrder =
      ClampTo<uint16_t>(CascadeLayerMap::kImplicitOuterLayerOrder);

  // @layer { target { color: red } }"
  EXPECT_TRUE(properties[0].properties->HasProperty(CSSPropertyID::kColor));
  EXPECT_EQ(0u, properties[0].data_.layer_order);
  EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kAuthor);

  // target { font-size: 10px }
  EXPECT_TRUE(properties[1].properties->HasProperty(CSSPropertyID::kFontSize));
  EXPECT_EQ(kImplicitOuterLayerOrder, properties[1].data_.layer_order);
  EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kAuthor);
}

// https://crbug.com/1326791
TEST_F(StyleResolverTest, CascadeLayersAddLayersWithImportantDeclarations) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style id="addrule"></style>
    <target></target>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument()
      .getElementById(AtomicString("addrule"))
      ->appendChild(GetDocument().createTextNode(
          "@layer { target { font-size: 20px !important; } }"
          "@layer { target { font-size: 10px !important; } }"));

  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap());

  StyleResolverState state(
      GetDocument(), *GetDocument().QuerySelector(AtomicString("target")));
  SelectorFilter filter;
  MatchResult match_result;
  ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                 filter, match_result,
                                 EInsideLink::kNotInsideLink);
  MatchAllRules(state, collector);
  const auto& properties = match_result.GetMatchedProperties();
  ASSERT_EQ(properties.size(), 2u);

  // @layer { target { font-size: 20px !important } }
  EXPECT_TRUE(properties[0].properties->HasProperty(CSSPropertyID::kFontSize));
  EXPECT_TRUE(
      properties[0].properties->PropertyIsImportant(CSSPropertyID::kFontSize));
  EXPECT_EQ("20px", properties[0].properties->GetPropertyValue(
                        CSSPropertyID::kFontSize));
  EXPECT_EQ(0u, properties[0].data_.layer_order);
  EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kAuthor);

  // @layer { target { font-size: 10px !important } }
  EXPECT_TRUE(properties[1].properties->HasProperty(CSSPropertyID::kFontSize));
  EXPECT_TRUE(
      properties[1].properties->PropertyIsImportant(CSSPropertyID::kFontSize));
  EXPECT_EQ("10px", properties[1].properties->GetPropertyValue(
                        CSSPropertyID::kFontSize));
  EXPECT_EQ(1u, properties[1].data_.layer_order);
  EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kAuthor);
}

TEST_F(StyleResolverTest, BodyPropagationLayoutImageContain) {
  GetDocument().documentElement()->setAttribute(
      html_names::kStyleAttr,
      AtomicString("contain:size; display:inline-table; content:url(img);"));
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor,
                                               "red");

  // Should not trigger DCHECK
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(Color::kTransparent,
            GetDocument().GetLayoutView()->StyleRef().VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleResolverTest, IsInertWithAttributeAndDialog) {
  Document& document = GetDocument();
  NonThrowableExceptionState exception_state;

  document.body()->setInnerHTML(R"HTML(
    <div inert>
      div_text
      <dialog>dialog_text</dialog>
    </div>
  )HTML");
  Element* html = document.documentElement();
  Element* body = document.body();
  Element* div = document.QuerySelector(AtomicString("div"));
  Node* div_text = div->firstChild();
  auto* dialog =
      To<HTMLDialogElement>(document.QuerySelector(AtomicString("dialog")));
  Node* dialog_text = dialog->firstChild();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);
  EXPECT_EQ(dialog_text->GetLayoutObject(), nullptr);

  div->SetBooleanAttribute(html_names::kInertAttr, false);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);
  EXPECT_EQ(dialog_text->GetLayoutObject(), nullptr);

  dialog->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_FALSE(dialog->GetComputedStyle()->IsInert());
  EXPECT_FALSE(dialog_text->GetLayoutObject()->StyleRef().IsInert());

  div->SetBooleanAttribute(html_names::kInertAttr, true);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_FALSE(dialog->GetComputedStyle()->IsInert());
  EXPECT_FALSE(dialog_text->GetLayoutObject()->StyleRef().IsInert());

  dialog->close();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);
  EXPECT_EQ(dialog_text->GetLayoutObject(), nullptr);
}

TEST_F(StyleResolverTest, IsInertWithDialogs) {
  Document& document = GetDocument();
  NonThrowableExceptionState exception_state;

  document.body()->setInnerHTML(R"HTML(
    <dialog>
      dialog1_text
      <dialog>dialog2_text</dialog>
    </dialog>
    <div>
      <dialog>dialog3_text</dialog>
    </div>
  )HTML");
  StaticElementList* dialogs =
      document.QuerySelectorAll(AtomicString("dialog"));
  Element* html = document.documentElement();
  Element* body = document.body();
  auto* dialog1 = To<HTMLDialogElement>(dialogs->item(0));
  Node* dialog1_text = dialog1->firstChild();
  auto* dialog2 = To<HTMLDialogElement>(dialogs->item(1));
  Node* dialog2_text = dialog2->firstChild();
  Element* div = document.QuerySelector(AtomicString("div"));
  auto* dialog3 = To<HTMLDialogElement>(dialogs->item(2));
  Node* dialog3_text = dialog3->firstChild();
  UpdateAllLifecyclePhasesForTest();

  auto ExpectState0 = [&]() {
    EXPECT_FALSE(html->GetComputedStyle()->IsInert());
    EXPECT_FALSE(body->GetComputedStyle()->IsInert());
    EXPECT_EQ(dialog1->GetComputedStyle(), nullptr);
    EXPECT_EQ(dialog1_text->GetLayoutObject(), nullptr);
    EXPECT_EQ(dialog2->GetComputedStyle(), nullptr);
    EXPECT_EQ(dialog2_text->GetLayoutObject(), nullptr);
    EXPECT_FALSE(div->GetComputedStyle()->IsInert());
    EXPECT_EQ(dialog3->GetComputedStyle(), nullptr);
    EXPECT_EQ(dialog3_text->GetLayoutObject(), nullptr);
  };
  ExpectState0();

  dialog1->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  auto ExpectState1 = [&]() {
    EXPECT_TRUE(html->GetComputedStyle()->IsInert());
    EXPECT_TRUE(body->GetComputedStyle()->IsInert());
    EXPECT_FALSE(dialog1->GetComputedStyle()->IsInert());
    EXPECT_FALSE(dialog1_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_EQ(dialog2->GetComputedStyle(), nullptr);
    EXPECT_EQ(dialog2_text->GetLayoutObject(), nullptr);
    EXPECT_TRUE(div->GetComputedStyle()->IsInert());
    EXPECT_EQ(dialog3->GetComputedStyle(), nullptr);
    EXPECT_EQ(dialog3_text->GetLayoutObject(), nullptr);
  };
  ExpectState1();

  dialog2->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  auto ExpectState2 = [&]() {
    EXPECT_TRUE(html->GetComputedStyle()->IsInert());
    EXPECT_TRUE(body->GetComputedStyle()->IsInert());
    EXPECT_TRUE(dialog1->GetComputedStyle()->IsInert());
    EXPECT_TRUE(dialog1_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_FALSE(dialog2->GetComputedStyle()->IsInert());
    EXPECT_FALSE(dialog2_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_TRUE(div->GetComputedStyle()->IsInert());
    EXPECT_EQ(dialog3->GetComputedStyle(), nullptr);
    EXPECT_EQ(dialog3_text->GetLayoutObject(), nullptr);
  };
  ExpectState2();

  dialog3->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  auto ExpectState3 = [&]() {
    EXPECT_TRUE(html->GetComputedStyle()->IsInert());
    EXPECT_TRUE(body->GetComputedStyle()->IsInert());
    EXPECT_TRUE(dialog1->GetComputedStyle()->IsInert());
    EXPECT_TRUE(dialog1_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_TRUE(dialog2->GetComputedStyle()->IsInert());
    EXPECT_TRUE(dialog2_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_TRUE(div->GetComputedStyle()->IsInert());
    EXPECT_FALSE(dialog3->GetComputedStyle()->IsInert());
    EXPECT_FALSE(dialog3_text->GetLayoutObject()->StyleRef().IsInert());
  };
  ExpectState3();

  dialog3->close();
  UpdateAllLifecyclePhasesForTest();

  ExpectState2();

  dialog2->close();
  UpdateAllLifecyclePhasesForTest();

  ExpectState1();

  dialog1->close();
  UpdateAllLifecyclePhasesForTest();

  ExpectState0();
}

static void EnterFullscreen(Document& document, Element& element) {
  LocalFrame::NotifyUserActivation(
      document.GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(element);
  Fullscreen::DidResolveEnterFullscreenRequest(document, /*granted*/ true);
  EXPECT_EQ(Fullscreen::FullscreenElementFrom(document), element);
}

static void ExitFullscreen(Document& document) {
  Fullscreen::FullyExitFullscreen(document);
  Fullscreen::DidExitFullscreen(document);
  EXPECT_EQ(Fullscreen::FullscreenElementFrom(document), nullptr);
}

TEST_F(StyleResolverTest, IsInertWithFullscreen) {
  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <div>
      div_text
      <span>span_text</span>
    </div>
    <p>p_text</p>
  )HTML");
  Element* html = document.documentElement();
  Element* body = document.body();
  Element* div = document.QuerySelector(AtomicString("div"));
  Node* div_text = div->firstChild();
  Element* span = document.QuerySelector(AtomicString("span"));
  Node* span_text = span->firstChild();
  Element* p = document.QuerySelector(AtomicString("p"));
  Node* p_text = p->firstChild();
  UpdateAllLifecyclePhasesForTest();

  auto ExpectState0 = [&]() {
    EXPECT_FALSE(html->GetComputedStyle()->IsInert());
    EXPECT_FALSE(body->GetComputedStyle()->IsInert());
    EXPECT_FALSE(div->GetComputedStyle()->IsInert());
    EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_FALSE(span->GetComputedStyle()->IsInert());
    EXPECT_FALSE(span_text->GetLayoutObject()->StyleRef().IsInert());
    EXPECT_FALSE(p->GetComputedStyle()->IsInert());
    EXPECT_FALSE(p_text->GetLayoutObject()->StyleRef().IsInert());
  };
  ExpectState0();

  EnterFullscreen(document, *div);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_FALSE(span->GetComputedStyle()->IsInert());
  EXPECT_FALSE(span_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_TRUE(p->GetComputedStyle()->IsInert());
  EXPECT_TRUE(p_text->GetLayoutObject()->StyleRef().IsInert());

  EnterFullscreen(document, *span);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_FALSE(span->GetComputedStyle()->IsInert());
  EXPECT_FALSE(span_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_TRUE(p->GetComputedStyle()->IsInert());
  EXPECT_TRUE(p_text->GetLayoutObject()->StyleRef().IsInert());

  EnterFullscreen(document, *p);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_TRUE(span->GetComputedStyle()->IsInert());
  EXPECT_TRUE(span_text->GetLayoutObject()->StyleRef().IsInert());
  EXPECT_FALSE(p->GetComputedStyle()->IsInert());
  EXPECT_FALSE(p_text->GetLayoutObject()->StyleRef().IsInert());

  ExitFullscreen(document);
  UpdateAllLifecyclePhasesForTest();

  ExpectState0();
}

TEST_F(StyleResolverTest, IsInertWithFrameAndFullscreen) {
  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <div>div_text</div>
  )HTML");
  Element* html = document.documentElement();
  Element* body = document.body();
  Element* div = document.QuerySelector(AtomicString("div"));
  Node* div_text = div->firstChild();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());

  EnterFullscreen(document, *div);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());

  EnterFullscreen(document, *body);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());

  EnterFullscreen(document, *html);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div_text->GetLayoutObject()->StyleRef().IsInert());
  ExitFullscreen(document);
}

TEST_F(StyleResolverTest, IsInertWithBackdrop) {
  Document& document = GetDocument();
  NonThrowableExceptionState exception_state;

  document.documentElement()->setInnerHTML(R"HTML(
    <style>:root:fullscreen::backdrop { --enable: true }</style>
    <dialog></dialog>
  )HTML");
  Element* html = document.documentElement();
  Element* body = document.body();
  auto* dialog =
      To<HTMLDialogElement>(document.QuerySelector(AtomicString("dialog")));

  auto IsBackdropInert = [](Element* element) {
    PseudoElement* backdrop = element->GetPseudoElement(kPseudoIdBackdrop);
    EXPECT_NE(backdrop, nullptr) << element;
    return backdrop->GetComputedStyle()->IsInert();
  };

  EnterFullscreen(document, *body);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(html->GetPseudoElement(kPseudoIdBackdrop), nullptr);
  EXPECT_FALSE(IsBackdropInert(body));
  EXPECT_EQ(dialog->GetPseudoElement(kPseudoIdBackdrop), nullptr);

  dialog->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(html->GetPseudoElement(kPseudoIdBackdrop), nullptr);
  EXPECT_TRUE(IsBackdropInert(body));
  EXPECT_FALSE(IsBackdropInert(dialog));

  dialog->close();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(html->GetPseudoElement(kPseudoIdBackdrop), nullptr);
  EXPECT_FALSE(IsBackdropInert(body));
  EXPECT_EQ(dialog->GetPseudoElement(kPseudoIdBackdrop), nullptr);

  EnterFullscreen(document, *html);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(IsBackdropInert(html));
  EXPECT_FALSE(IsBackdropInert(body));
  EXPECT_EQ(dialog->GetPseudoElement(kPseudoIdBackdrop), nullptr);

  dialog->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(IsBackdropInert(html));
  EXPECT_TRUE(IsBackdropInert(body));
  EXPECT_FALSE(IsBackdropInert(dialog));
  ExitFullscreen(document);
}

TEST_F(StyleResolverTest, IsInertWithDialogAndFullscreen) {
  Document& document = GetDocument();
  NonThrowableExceptionState exception_state;

  document.body()->setInnerHTML(R"HTML(
    <div></div>
    <dialog></dialog>
  )HTML");
  Element* html = document.documentElement();
  Element* body = document.body();
  Element* div = document.QuerySelector(AtomicString("div"));
  auto* dialog =
      To<HTMLDialogElement>(document.QuerySelector(AtomicString("dialog")));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);

  EnterFullscreen(document, *div);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);

  dialog->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(dialog->GetComputedStyle()->IsInert());

  dialog->close();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);

  ExitFullscreen(document);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);

  dialog->showModal(exception_state);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(dialog->GetComputedStyle()->IsInert());

  EnterFullscreen(document, *div);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(dialog->GetComputedStyle()->IsInert());

  ExitFullscreen(document);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(html->GetComputedStyle()->IsInert());
  EXPECT_TRUE(body->GetComputedStyle()->IsInert());
  EXPECT_TRUE(div->GetComputedStyle()->IsInert());
  EXPECT_FALSE(dialog->GetComputedStyle()->IsInert());

  dialog->close();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(html->GetComputedStyle()->IsInert());
  EXPECT_FALSE(body->GetComputedStyle()->IsInert());
  EXPECT_FALSE(div->GetComputedStyle()->IsInert());
  EXPECT_EQ(dialog->GetComputedStyle(), nullptr);
}

TEST_F(StyleResolverTestCQ, StyleRulesForElementContainerQuery) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #container { container-type: inline-size }
      @container (min-width: 1px) {
        #target { }
      }
      @container (min-width: 99999px) {
        #target { color: red }
      }
    </style>
    <div id="container">
      <div id="target"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto& resolver = GetDocument().GetStyleResolver();

  auto* rule_list =
      resolver.StyleRulesForElement(target, StyleResolver::kAuthorCSSRules);
  ASSERT_TRUE(rule_list);
  ASSERT_EQ(rule_list->size(), 1u)
      << "The empty #target rule in the container query should be collected";
  EXPECT_TRUE(rule_list->at(0)->Properties().IsEmpty())
      << "Check that it is in fact the empty rule";
}

TEST_F(StyleResolverTest, LegacyOverlapPerspectiveOrigin_Single) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          perspective-origin: 1px 2px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyPerspectiveOrigin))
      << "Not counted when only perspective-origin is used";
}

TEST_F(StyleResolverTest, LegacyOverlapPerspectiveOrigin_Order) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          -webkit-perspective-origin-x: 1px;
          -webkit-perspective-origin-y: 2px;
          perspective-origin: 3px 4px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyPerspectiveOrigin))
      << "Not counted when perspective-origin is last";
}

TEST_F(StyleResolverTest, LegacyOverlapPerspectiveOrigin_Values) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          perspective-origin: 1px 2px;
          -webkit-perspective-origin-x: 1px;
          -webkit-perspective-origin-y: 2px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyPerspectiveOrigin))
      << "Not counted when values are the same";
}

TEST_F(StyleResolverTest, LegacyOverlapPerspectiveOrigin_Last) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          perspective-origin: 1px 2px;
          -webkit-perspective-origin-x: 3px;
          -webkit-perspective-origin-y: 4px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyPerspectiveOrigin))
      << "Counted when -webkit-perspective-* is last with different values";
}

TEST_F(StyleResolverTest, LegacyOverlapTransformOrigin_Single) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          transform-origin: 1px 2px 3px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyTransformOrigin))
      << "Not counted when only transform-origin is used";
}

TEST_F(StyleResolverTest, LegacyOverlapTransformOrigin_Order) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          -webkit-transform-origin-x: 1px;
          -webkit-transform-origin-y: 2px;
          -webkit-transform-origin-z: 3px;
          transform-origin: 4px 5px 6px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyTransformOrigin))
      << "Not counted when transform-origin is last";
}

TEST_F(StyleResolverTest, LegacyOverlapTransformOrigin_Values) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          transform-origin: 1px 2px
```