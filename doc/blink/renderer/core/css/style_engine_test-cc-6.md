Response:
My thinking process to analyze the `style_engine_test.cc` file and answer the prompt involved these steps:

1. **Understand the Core Purpose:** The filename `style_engine_test.cc` immediately signals that this file contains unit tests for the Blink rendering engine's CSS style engine. This engine is responsible for calculating the final styles applied to HTML elements based on CSS rules.

2. **Identify Key Areas of Functionality:**  I scanned the code for common patterns and keywords. The `TEST_F` macro indicates individual test cases. Recurring themes emerged:
    * **Cascade Layers:**  Multiple tests explicitly mention `@layer` and test how different layers interact, especially with user-defined styles.
    * **User Stylesheets:** Several tests inject user stylesheets (`GetStyleEngine().InjectSheet(...)`) to see how they interact with author stylesheets.
    * **Specific CSS Features:**  Tests target `@keyframes`, `@counter-style`, `@property` (custom properties), `@font-face`, and comparison functions (`min`, `max`, `clamp`).
    * **Pseudo-classes:**  Tests involving `:has()`, `:link`, and `:visited` reveal testing of complex CSS selectors and their invalidation mechanisms.
    * **Layout and Rendering:** Tests involving `OffsetWidth`, `UpdateAllLifecyclePhases`, and `Compositor().BeginFrame()` indicate tests related to how styles affect layout and rendering.
    * **Performance and Optimization:**  The "ScrollbarStyleNoExcessiveCaching" test hints at performance considerations.
    * **Error Handling and Edge Cases:**  Tests with names like "CascadeLayerActiveStyleSheetVectorNullRuleSetCrash" and "MathDepthOverflow" point to testing for potential crashes or issues with unusual inputs.

3. **Analyze Individual Test Cases (Examples):**  To illustrate the connection to JavaScript, HTML, and CSS, I mentally walked through a few test cases:
    * **`UserKeyframesOverrideWithCascadeLayers`:** This test shows how a user-defined animation (`@keyframes`) in a specific cascade layer overrides another animation. This directly relates to CSS animations and the cascade. The JavaScript aspect is the testing framework itself, and indirectly, JavaScript could trigger changes that necessitate style recalculation. The HTML is the simple `<div>` being styled.
    * **`UserCounterStyleOverrideWithCascadeLayers`:** This tests the interaction of user-defined counter styles with cascade layers. It involves CSS counters and the `content` property, which is crucial for rendering. Again, JavaScript drives the test, and HTML provides the target element.
    * **`:has()` pseudo-class tests:** These demonstrate how changes to elements *within* the scope of a `:has()` selector trigger style recalculation for the element using the `:has()`. This is a more advanced CSS selector feature. JavaScript is used to manipulate the DOM (adding/removing classes/IDs/attributes) to trigger these recalculations. HTML provides the structure.

4. **Infer Assumptions, Inputs, and Outputs:** For tests that implied logic, I considered what the test was setting up and verifying:
    * **Assumption:** The CSS parser correctly interprets the provided CSS strings.
    * **Input:** The CSS strings within the `R"CSS(...)CSS"` blocks, the HTML structure set up with `setInnerHTML`, and the injected user stylesheets.
    * **Output:** The expected values of properties like `OffsetWidth` or the background color, as asserted by `EXPECT_EQ` or similar macros.

5. **Identify Potential User/Programming Errors:**  By understanding the tests, I could infer common mistakes. For instance, the cascade layer tests highlight the importance of understanding layer order. Incorrectly ordering layers in CSS could lead to unexpected styles. The `:has()` tests imply that developers need to understand how changes in the DOM subtree can affect elements higher up in the tree due to these selectors.

6. **Trace User Operations (Debugging Clues):**  I considered how a user interaction might lead to the code being tested. A user action (like typing, clicking, or scrolling) can trigger JavaScript events, which might modify the DOM or CSS styles. The style engine then kicks in to recalculate styles. Specifically for the `:has()` tests, user actions that change the attributes or children of elements could trigger the invalidation logic being tested.

7. **Synthesize and Summarize:** Finally, I organized my observations into a clear summary covering the functionality, relationships to web technologies, logical deductions, error examples, and debugging clues. Because this was part 7 of 8, I focused on summarizing the functionality covered *in this specific part*.

**Self-Correction/Refinement:**  Initially, I might have focused too much on the specific syntax of the C++ testing framework. I then shifted to understanding the *purpose* of each test – what CSS feature or engine behavior it was verifying. I also made sure to connect the technical details back to the broader concepts of HTML, CSS, and how JavaScript interacts with them. The "debugging clues" section required thinking about the chain of events from user action to code execution.
这是目录为 `blink/renderer/core/css/style_engine_test.cc` 的 Chromium Blink 引擎源代码文件的第 7 部分，共 8 部分。根据提供的代码片段，我们可以归纳出这部分的主要功能是：**测试 Blink 渲染引擎中 CSS 样式引擎的各种特性，特别是关于级联层（Cascade Layers）和 `:has()` 伪类选择器的行为和正确性。**

以下是更详细的功能列举和说明：

**主要功能:**

1. **测试级联层 (Cascade Layers) 的优先级和覆盖规则：**  大量的测试用例专门针对 `@layer` 指令，验证在不同来源（用户样式表、作者样式表）和不同层级的样式规则如何相互覆盖和生效。这包括对以下 CSS 特性的级联层行为进行测试：
    * **`@import` 规则中的级联层。**
    * **`@keyframes` 动画关键帧的覆盖。**
    * **`@counter-style` 计数器样式的覆盖。**
    * **`@property` 自定义属性的覆盖。**
    * **`@font-face` 字体声明的覆盖。**

2. **测试用户样式表与作者样式表在级联层中的交互：** 重点测试用户定义的样式规则在级联层中是否按照预期覆盖或被作者定义的规则覆盖。

3. **测试 `:has()` 伪类选择器的行为和性能优化：**  一系列测试用例验证 `:has()` 伪类选择器在各种 DOM 结构变化下的样式更新机制，包括：
    * **类名变化。**
    * **ID 变化。**
    * **属性变化。**
    * **子元素的插入和移除。**
    * **`:has()` 中使用通配符 `*`。**
    * **`:has()` 中使用其他伪类（如 `:focus`、`:link`、`:visited`）。**
    * **测试 `:has()` 伪类选择器的选择器匹配效率和避免不必要的样式重算。**

4. **测试其他 CSS 特性：**  虽然本部分主要关注级联层和 `:has()`，但也包含一些其他 CSS 特性的测试，例如：
    * **CSS 比较函数 (`min`, `max`, `clamp`) 的 use counter 机制。**
    * **`math-depth` 属性的溢出处理。**
    * **移除了 `<body>` 元素后样式如何传递到 `<html>` 元素。**
    * **`revert` 和 `revert-layer` 关键字与 presentational hints 的交互。**
    * **渲染阻塞的样式表加载完成时，过渡效果是否应该触发。**

5. **测试样式引擎在特定场景下的健壮性，防止崩溃：**  例如，测试了在 `ActiveStyleSheetVector` 中存在空 `RuleSet` 时，级联层相关的代码是否会崩溃。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  该文件是直接测试 CSS 样式引擎的，所以与 CSS 的关系最为紧密。几乎所有的测试用例都涉及到 CSS 语法和特性。
    * **举例：** `TEST_F(StyleEngineTest, UserKeyframesOverrideWithCascadeLayers)`  测试了 CSS 的 `@keyframes` 规则和 `@layer` 指令的交互，以及用户样式表对作者样式表的覆盖。

* **HTML:** 测试用例通常会通过 `GetDocument().body()->setInnerHTML(...)` 创建 HTML 结构，并操作这些 HTML 元素来触发样式计算和更新。
    * **举例：** 在 `:has()` 相关的测试中，会动态地添加或删除 HTML 元素，然后验证使用了 `:has()` 的 CSS 规则是否正确生效。

* **JavaScript:**  虽然此文件是 C++ 代码，但它测试的样式引擎是浏览器渲染的核心部分，与 JavaScript 的交互非常频繁。JavaScript 可以动态地修改 DOM 结构和元素的样式，从而触发样式引擎的重新计算。
    * **举例：** `:has()` 伪类选择器的测试，例如 `TEST_F(StyleEngineTest, HasPseudoClassInvalidationSkipIrrelevantClassChange)`，模拟了 JavaScript 修改元素类名的场景，并验证样式引擎是否只在相关的元素上进行样式重算。

**逻辑推理 (假设输入与输出):**

* **假设输入 (对于 `UserKeyframesOverrideWithCascadeLayers`):**
    ```css
    @layer base, override;

    #target {
      animation: anim 1s paused;
    }

    @layer override {
      @keyframes anim {
        from { width: 100px; }
      }
    }

    @layer base {
      @keyframes anim {
        from { width: 50px; }
      }
    }
    ```
    以及 HTML:
    ```html
    <div id=target style='height: 100px'></div>
    ```
    并且用户样式表被注入。

* **输出:**  `target` 元素的 `OffsetWidth()` 应该等于 `100`，因为 `override` 层的 `@keyframes anim` 具有更高的优先级。

**用户或编程常见的使用错误 (举例说明):**

* **级联层优先级理解错误：** 用户可能错误地认为低层级的样式会覆盖高层级的样式，导致样式不生效。
    * **例子：** 如果用户认为 `@layer base { ... }` 中的样式会覆盖 `@layer override { ... }` 中的同名样式，则会得到与预期不符的结果。

* **对 `:has()` 伪类选择器的性能影响理解不足：** 开发者可能会过度使用 `:has()`，特别是在复杂的 DOM 结构中，导致样式计算的性能问题。
    * **例子：** 在一个包含大量子元素的父元素上使用 `.parent:has(.child .grandchild)` 可能会导致频繁且耗时的样式重算。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载一个网页。**
2. **网页包含 HTML 结构和 CSS 样式。**
3. **浏览器解析 HTML 和 CSS。**
4. **样式引擎根据 CSS 规则计算每个元素的最终样式。**  这正是 `style_engine_test.cc` 测试的核心部分。
5. **如果网页包含用户自定义样式（通过浏览器插件或开发者工具），这些样式也会被考虑在内。** 相关的测试用例会模拟这种情况。
6. **如果 CSS 中使用了级联层，样式引擎会按照层级顺序和优先级规则应用样式。**
7. **当 DOM 结构或元素样式发生变化时（例如，通过 JavaScript 操作），样式引擎需要重新计算受影响元素的样式。** `:has()` 相关的测试就模拟了这种动态变化。
8. **当用户与网页交互，触发状态变化（例如，鼠标悬停、点击、输入），或者浏览器窗口大小变化时，也可能触发样式重新计算。**

**归纳本部分的功能：**

总而言之，`blink/renderer/core/css/style_engine_test.cc` 的第 7 部分主要集中在**细致地测试 Blink 引擎的 CSS 样式引擎在处理级联层和 `:has()` 伪类选择器时的正确性和性能**，同时也涵盖了一些其他 CSS 特性的边缘情况和健壮性测试。这些测试确保了浏览器能够按照 CSS 规范正确地渲染网页，并有效地处理动态的 DOM 结构和用户交互。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
er(WebFeature::kCSSCascadeLayers);
  }

  {
    ASSERT_FALSE(IsUseCounted(WebFeature::kCSSCascadeLayers));
    GetDocument().body()->setInnerHTML(
        "<style>@import url(foo.css) layer(foo);</style>");
    EXPECT_TRUE(IsUseCounted(WebFeature::kCSSCascadeLayers));
    ClearUseCounter(WebFeature::kCSSCascadeLayers);
  }
}

TEST_F(StyleEngineTest, UserKeyframesOverrideWithCascadeLayers) {
  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(R"CSS(
    @layer base, override;

    #target {
      animation: anim 1s paused;
    }

    @layer override {
      @keyframes anim {
        from { width: 100px; }
      }
    }

    @layer base {
      @keyframes anim {
        from { width: 50px; }
      }
    }
  )CSS");
  StyleSheetKey key("user");
  GetStyleEngine().InjectSheet(key, user_sheet, WebCssOrigin::kUser);

  GetDocument().body()->setInnerHTML(
      "<div id=target style='height: 100px'></div>");

  UpdateAllLifecyclePhases();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(100, target->OffsetWidth());
}

TEST_F(StyleEngineTest, UserCounterStyleOverrideWithCascadeLayers) {
  PageTestBase::LoadAhem(*GetDocument().GetFrame());

  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(R"CSS(
    @layer base, override;

    #target {
      width: min-content;
      font: 10px/1 Ahem;
    }

    #target::before {
      content: counter(dont-care, cnt-style);
    }

    @layer override {
      @counter-style cnt-style {
        system: cyclic;
        symbols: '0000';
      }
    }

    @layer base {
      @counter-style cnt-style {
        system: cyclic;
        symbols: '000';
      }
    }
  )CSS");
  StyleSheetKey key("user");
  GetStyleEngine().InjectSheet(key, user_sheet, WebCssOrigin::kUser);

  GetDocument().body()->setInnerHTML("<div id=target></div>");

  UpdateAllLifecyclePhases();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(40, target->OffsetWidth());
}

TEST_F(StyleEngineTest, UserPropertyOverrideWithCascadeLayers) {
  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(R"CSS(
    @layer base, override;

    #target {
      width: var(--foo);
    }

    @layer override {
      @property --foo {
        syntax: '<length>';
        initial-value: 100px;
        inherits: false;
      }
    }

    @layer base {
      @property --foo {
        syntax: '<length>';
        initial-value: 50px;
        inherits: false;
      }
    }
  )CSS");
  StyleSheetKey key("user");
  GetStyleEngine().InjectSheet(key, user_sheet, WebCssOrigin::kUser);

  GetDocument().body()->setInnerHTML(
      "<div id=target style='height: 100px'></div>");

  UpdateAllLifecyclePhases();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(100, target->OffsetWidth());
}

TEST_F(StyleEngineTest, UserAndAuthorPropertyOverrideWithCascadeLayers) {
  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(R"CSS(
    @layer base, override;

    @layer override {
      @property --foo {
        syntax: '<length>';
        initial-value: 50px;
        inherits: false;
      }
    }
  )CSS");
  StyleSheetKey key("user");
  GetStyleEngine().InjectSheet(key, user_sheet, WebCssOrigin::kUser);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @property --foo {
        syntax: '<length>';
        initial-value: 100px;
        inherits: false;
      }

      #target {
        width: var(--foo);
      }
    </style>
    <div id=target style='height: 100px'></div>
  )HTML");

  UpdateAllLifecyclePhases();

  // User-defined custom properties should not override author-defined
  // properties regardless of cascade layers.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(100, target->OffsetWidth());
}

TEST_F(StyleEngineSimTest, UserFontFaceOverrideWithCascadeLayers) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest ahem_resource("https://example.com/ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <div id=target>Test</div>
  )HTML");

  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(R"CSS(
    @layer base, override;

    @layer override {
      @font-face {
        font-family: custom-font;
        src: url('ahem.woff2') format('woff2');
      }
    }

    @layer base {
      @font-face {
        font-family: custom-font;
        src: url('ahem.woff2') format('woff2');
        size-adjust: 200%; /* To distinguish with the other @font-face */
      }
    }

    #target {
      font: 20px/1 custom-font;
      width: min-content;
    }
  )CSS");
  StyleSheetKey key("user");
  GetDocument().GetStyleEngine().InjectSheet(key, user_sheet,
                                             WebCssOrigin::kUser);

  Compositor().BeginFrame();

  ahem_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(80, target->OffsetWidth());
}

TEST_F(StyleEngineSimTest, UserAndAuthorFontFaceOverrideWithCascadeLayers) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest ahem_resource("https://example.com/ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url('ahem.woff2') format('woff2');
      }

      #target {
        font: 20px/1 custom-font;
        width: min-content;
      }
    </style>
    <div id=target>Test</div>
  )HTML");

  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(R"CSS(
    @layer base, override;

    @layer override {
      @font-face {
        font-family: custom-font;
        src: url('ahem.woff2') format('woff2');
        size-adjust: 200%; /* To distinguish with the other @font-face */
      }
    }

  )CSS");
  StyleSheetKey key("user");
  GetDocument().GetStyleEngine().InjectSheet(key, user_sheet,
                                             WebCssOrigin::kUser);

  Compositor().BeginFrame();

  ahem_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));

  test::RunPendingTasks();
  Compositor().BeginFrame();

  // User-defined font faces should not override author-defined font faces
  // regardless of cascade layers.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(80, target->OffsetWidth());
}

TEST_F(StyleEngineTest, CascadeLayerActiveStyleSheetVectorNullRuleSetCrash) {
  // This creates an ActiveStyleSheetVector where the first entry has no
  // RuleSet, and the second entry has a layer rule difference.
  GetDocument().documentElement()->setInnerHTML(
      "<style media=invalid></style>"
      "<style>@layer {}</style>");

  // Should not crash
  UpdateAllLifecyclePhases();
}

TEST_F(StyleEngineTest, EmptyDetachParent) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <span id="parent"><b>A</b> <i>B</i></span>
  )HTML");
  UpdateAllLifecyclePhases();

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  parent->setInnerHTML("");

  ASSERT_TRUE(parent->GetLayoutObject());
  EXPECT_FALSE(parent->GetLayoutObject()->WhitespaceChildrenMayChange());
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
}

TEST_F(StyleEngineTest, LegacyListItemRebuildRootCrash) {
  UpdateAllLifecyclePhases();

  auto* doc_elm = GetDocument().documentElement();
  ASSERT_TRUE(doc_elm);

  doc_elm->SetInlineStyleProperty(CSSPropertyID::kDisplay, "list-item");
  doc_elm->SetInlineStyleProperty(CSSPropertyID::kColumnCount, "1");
  UpdateAllLifecyclePhases();

  doc_elm->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor, "green");
  // Should not crash
  UpdateAllLifecyclePhases();
}

// Regression test for https://crbug.com/1270190
TEST_F(StyleEngineTest, ScrollbarStyleNoExcessiveCaching) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
    .a {
      width: 50px;
      height: 50px;
      background-color: magenta;
      overflow-y: scroll;
      margin: 5px;
      float: left;
    }

    .b {
      height: 100px;
    }

    ::-webkit-scrollbar {
      width: 10px;
    }

    ::-webkit-scrollbar-thumb {
      background: green;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: red;
    }
    </style>
    <div class="a" id="container">
      <div class="b">
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  // We currently don't cache ::-webkit-scrollbar-* pseudo element styles, so
  // the cache is always empty. If we decide to cache them, we should make sure
  // that the cache size remains bounded.

  Element* container = GetDocument().getElementById(AtomicString("container"));
  EXPECT_FALSE(container->GetComputedStyle()->GetPseudoElementStyleCache());

  PaintLayerScrollableArea* area =
      container->GetLayoutBox()->GetScrollableArea();
  Scrollbar* scrollbar = area->VerticalScrollbar();
  CustomScrollbar* custom_scrollbar = To<CustomScrollbar>(scrollbar);

  scrollbar->SetHoveredPart(kThumbPart);
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(container->GetComputedStyle()->GetPseudoElementStyleCache());
  EXPECT_EQ("rgb(255, 0, 0)", custom_scrollbar->GetPart(kThumbPart)
                                  ->Style()
                                  ->BackgroundColor()
                                  .GetColor()
                                  .SerializeAsCSSColor());

  scrollbar->SetHoveredPart(kNoPart);
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(container->GetComputedStyle()->GetPseudoElementStyleCache());
  EXPECT_EQ("rgb(0, 128, 0)", custom_scrollbar->GetPart(kThumbPart)
                                  ->Style()
                                  ->BackgroundColor()
                                  .GetColor()
                                  .SerializeAsCSSColor());
}

TEST_F(StyleEngineTest, HasPseudoClassInvalidationSkipIrrelevantClassChange) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.a:has(.b) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3>
          <div id=div4></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div4"))
      ->setAttribute(html_names::kClassAttr, AtomicString("c"));
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div4"))
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(StyleEngineTest, HasPseudoClassInvalidationSkipIrrelevantIdChange) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.a:has(#b) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3>
          <div id=div4></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div4"))
      ->setAttribute(html_names::kIdAttr, AtomicString("c"));
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("c"))
      ->setAttribute(html_names::kIdAttr, AtomicString("b"));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(StyleEngineTest,
       HasPseudoClassInvalidationSkipIrrelevantAttributeChange) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.a:has([b]) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3>
          <div id=div4></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div4"))
      ->setAttribute(
          QualifiedName(g_empty_atom, AtomicString("c"), g_empty_atom),
          AtomicString("C"));
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div4"))
      ->setAttribute(
          QualifiedName(g_empty_atom, AtomicString("b"), g_empty_atom),
          AtomicString("B"));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(StyleEngineTest,
       HasPseudoClassInvalidationSkipIrrelevantInsertionRemoval) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.a:has(.b) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* div5 = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  div5->setAttribute(html_names::kIdAttr, AtomicString("div5"));
  div5->setInnerHTML(R"HTML(<div class='c'></div>)HTML");
  GetDocument().getElementById(AtomicString("div3"))->AppendChild(div5);
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  auto* div6 = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  div6->setAttribute(html_names::kIdAttr, AtomicString("div6"));
  div6->setInnerHTML(R"HTML(<div class='b'></div>)HTML");
  GetDocument().getElementById(AtomicString("div4"))->AppendChild(div6);
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(3U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div3"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div5")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div4"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div6")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(StyleEngineTest, HasPseudoClassInvalidationUniversalInArgument) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.a:has(*) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* div3 = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  div3->setAttribute(html_names::kIdAttr, AtomicString("div3"));
  GetDocument().getElementById(AtomicString("div2"))->AppendChild(div3);
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div2"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div3")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(StyleEngineTest,
       HasPseudoClassInvalidationInsertionRemovalWithPseudoInHas) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .a:has(.b:focus) { background-color: lime; }
      .c:has(.d) { background-color: green; }
    </style>
    <div id=div1>
      <div id=div2 class='a'></div>
      <div id=div3 class='c'></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* div4 = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  div4->setAttribute(html_names::kIdAttr, AtomicString("div4"));
  GetDocument().getElementById(AtomicString("div2"))->AppendChild(div4);
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  auto* div5 = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  div5->setAttribute(html_names::kIdAttr, AtomicString("div5"));
  GetDocument().getElementById(AtomicString("div3"))->AppendChild(div5);
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div2"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div4")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div3"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div5")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
}

TEST_F(StyleEngineTest, HasPseudoClassInvalidationLinkInHas) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .a:has(:link) { background-color: lime; }
    </style>
    <div id=div1 class='a'>
      <a href="unvisited"></a>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* anchor = MakeGarbageCollected<HTMLAnchorElement>(GetDocument());
  anchor->setAttribute(html_names::kIdAttr, AtomicString("anchor1"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(anchor);
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("anchor1")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(StyleEngineTest, HasPseudoClassInvalidationIgnoreVisitedPseudoInHas) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .a:has(:visited) { background-color: lime; }
    </style>
    <div id=div1 class='a'>
      <a href="unvisited"></a>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* anchor = MakeGarbageCollected<HTMLAnchorElement>(GetDocument());
  anchor->SetHref(g_empty_atom);
  anchor->setAttribute(html_names::kIdAttr, AtomicString("anchor1"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(anchor);
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("anchor1")));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
}

TEST_F(StyleEngineTest, HasPseudoClassInvalidationCheckFiltering) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
    div { color: grey }
    .a:has(.b) { color: red }
    .c:has(.d) { color: green }
    .e:has(.f) .g { color: blue }
    .e:has(.h) .i { color: navy }
    .e:has(.f.h) .j { color: lightgreen }
    </style>
    <div class='a e'>
      <div class=g></div>
      <div class=i></div>
      <div class=j></div>
      <div id=child></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  // TODO(blee@igalia.com) Should be 0U. Need additional filtering
  // - skip invalidation of non-subject :has() rules
  //    - .e:has(.f) .g
  //    - .e:has(.h) .i
  //    - .e:has(.f.h) .j
  // - skip invalidation of the irrelevant ancestor
  //    - .a:has(.b)
  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kClassAttr, AtomicString("d"));
  UpdateAllLifecyclePhases();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  EXPECT_EQ(4U, element_count);

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhases();

  // TODO(blee@igalia.com) Should be 1U. Need additional filtering
  // - skip invalidation of subject :has() rules
  //    - .a:has(.b)
  // - skip invalidation of irrelevant rules
  //    - .e:has(.h) .i
  // - skip invalidation of the mutation on irrelevant element
  //    - .e:has(.f.h) .j
  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhases();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  EXPECT_EQ(4U, element_count);
}

TEST_F(StyleEngineTest, CSSComparisonFunctionsUseCount) {
  ClearUseCounter(WebFeature::kCSSComparisonFunctions);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div { width: calc(10px + 20%); }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSComparisonFunctions));
  ClearUseCounter(WebFeature::kCSSComparisonFunctions);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div { width: calc(min(10px, 20%) + max(20px, 10%)); }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSComparisonFunctions));
  ClearUseCounter(WebFeature::kCSSComparisonFunctions);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div { width: calc(clamp(10px, 20px, 30px)); }
    </style>
    <div></div>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSComparisonFunctions));
  ClearUseCounter(WebFeature::kCSSComparisonFunctions);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div { width: calc(clamp(10px, 20%, 20px + 30%)); }
    </style>
    <div></div>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSComparisonFunctions));
  ClearUseCounter(WebFeature::kCSSComparisonFunctions);
}

TEST_F(StyleEngineTest, MathDepthOverflow) {
  css_test_helpers::RegisterProperty(
      GetDocument(), "--int16-max", "<integer>",
      String::Format("%i", std::numeric_limits<int16_t>::max()), false);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #parent1 {
        math-style: compact;
        math-depth: var(--int16-max);
      }
      #parent2 {
        math-style: compact;
        math-depth: 1;
      }
      #child1, #control1 {
        math-depth: add(1);
      }
      #child2, #control2 {
        math-depth: auto-add;
      }
      #child3 {
        math-depth: calc(var(--int16-max) + 1);
      }
    </style>
    <div id=parent1>
      <div id=child1></div>
      <div id=child2></div>
      <div id=child3></div>
    </div>
    <div id=parent2>
      <div id=control1></div>
      <div id=control2></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* control1 = GetDocument().getElementById(AtomicString("control1"));
  Element* control2 = GetDocument().getElementById(AtomicString("control2"));

  ASSERT_TRUE(control1 && control1->GetComputedStyle());
  ASSERT_TRUE(control2 && control2->GetComputedStyle());

  EXPECT_EQ(2, control1->GetComputedStyle()->MathDepth());
  EXPECT_EQ(2, control2->GetComputedStyle()->MathDepth());

  Element* child1 = GetDocument().getElementById(AtomicString("child1"));
  Element* child2 = GetDocument().getElementById(AtomicString("child2"));
  Element* child3 = GetDocument().getElementById(AtomicString("child3"));

  ASSERT_TRUE(child1 && child1->GetComputedStyle());
  ASSERT_TRUE(child2 && child2->GetComputedStyle());
  ASSERT_TRUE(child3 && child3->GetComputedStyle());

  EXPECT_EQ(std::numeric_limits<int16_t>::max(),
            child1->GetComputedStyle()->MathDepth());
  EXPECT_EQ(std::numeric_limits<int16_t>::max(),
            child2->GetComputedStyle()->MathDepth());
  EXPECT_EQ(std::numeric_limits<int16_t>::max(),
            child3->GetComputedStyle()->MathDepth());
}

TEST_F(StyleEngineTest, RemovedBodyToHTMLPropagation) {
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kWritingMode,
                                               "vertical-lr");

  UpdateAllLifecyclePhases();

  Element* root = GetDocument().documentElement();
  ASSERT_TRUE(root);
  EXPECT_TRUE(root->ComputedStyleRef().IsHorizontalWritingMode())
      << "body to html propagation does not affect computed value";
  EXPECT_FALSE(root->GetLayoutObject()->StyleRef().IsHorizontalWritingMode())
      << "body to html propagation affects used value";

  // Make sure that recalculating style for the root element does not trigger a
  // visual diff that requires layout. That is, we take the body -> root
  // propagation of writing-mode into account before setting ComputedStyle on
  // the root LayoutObject.
  GetDocument().body()->remove();

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(root->ComputedStyleRef().IsHorizontalWritingMode())
      << "body to html propagation does not affect computed value";
  EXPECT_TRUE(root->GetLayoutObject()->StyleRef().IsHorizontalWritingMode())
      << "No propagation from removed body";
}

TEST_F(StyleEngineTest, RevertWithPresentationalHints) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      img {
        width: revert;
        height: revert;
      }
    </style>
    <img id="img" width="44" height="33"></img>
  )HTML");
  UpdateAllLifecyclePhases();

  // For the purpose of the 'revert' keyword, presentational hints are
  // considered part of the author origin.
  Element* img = GetElementById("img");
  EXPECT_NE(44, img->OffsetWidth());
  EXPECT_NE(33, img->OffsetHeight());
}

TEST_F(StyleEngineTest, RevertLayerWithPresentationalHints) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      img {
        width: revert-layer;
        height: revert-layer;
      }
    </style>
    <img id="img" width="44" height="33"></img>
  )HTML");
  UpdateAllLifecyclePhases();

  // 'revert-layer' from the lowest author layer should revert to the
  // presentational hints.
  Element* img = GetElementById("img");
  EXPECT_EQ(44, img->OffsetWidth());
  EXPECT_EQ(33, img->OffsetHeight());
}

TEST_F(StyleEngineSimTest, ResizeWithBlockingSheetTransition) {
  WebView().MainFrameWidget()->Resize(gfx::Size(500, 500));

  SimRequest html_request("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_request("https://example.com/slow.css", "text/css");

  LoadURL("https://example.com/test.html");
  html_request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        #trans {
          transition-duration: 30s;
          color: red;
        }
      </style>
      <link rel="stylesheet" href="slow.css">
      <div id="trans"></div>
  )HTML");

  css_request.Start();
  WebView().MainFrameWidget()->Resize(gfx::Size(800, 800));

  css_request.Complete(R"CSS(
    #trans { color: green; }
  )CSS");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  Element* trans = GetDocument().getElementById(AtomicString("trans"));
  ASSERT_TRUE(trans);

  // Completing the linked stylesheet should not start a transition since the
  // sheet is render-blocking.
  EXPECT_EQ(
      trans->ComputedStyleRef().VisitedDependentColor(GetCSSPropertyColor()),
      Color::FromRGB(0, 128, 0));
}

TEST_F(StyleEngineSimTest, FocusWithBlockingSheetTransition) {
  WebView().MainFrameWidget()->Resize(gfx::Size(500, 500));

  SimRequest html_request("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_request("https://example.com/slow.css", "text/css");

  LoadURL("https://example.com/test.html");
  html_request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        #trans {
          transition-duration: 30s;
          color: red;
        }
      </style>
      <link rel="stylesheet" href="slow.css">
      <div id="trans"></div>
  )HTML");

  css_request.Start();

  GetDocument().GetPage()->GetFocusController().SetActive(true);
  GetDocument().GetPage()->GetFocusController().SetFocused(true);
  GetDocument().GetPage()->GetFocusController().SetFocusedFrame(
      GetDocument().GetFrame());

  css_request.Complete(R"CSS(
    #trans { color: green; }
  )CSS");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  Element* trans = GetDocument().getElementById(AtomicString("trans"));
  ASSERT_TRUE(trans);

  // Completing the linked stylesheet should not start a transition since the
  // sheet is render-blocking.
  EXPECT_EQ(
      trans->ComputedStyleRef().VisitedDependentColor(GetCSSPropertyColor()),
      Color::FromRGB(0, 128, 0));
}

TEST_F(StyleEngineSimTest,
       ShouldInvalidateSubjectPseudoHasAfterChildrenParsingFinished) {
  SimRequest main_resource("https://example.com/", "text/html");

  LoadURL("https://example.com/");

  main_resource.Write(R"HTML(
    <!DOCTYPE html>
    <style>
      .a { color: black }
      .a:not(:has(+ div)) { color: red }
    </style>
    <div id="first" class="a"> First </div>
    <div id="second" class="a"> Second
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  Element* first = GetDocument().getElementById(AtomicString("first"));
  EXPECT_TRUE(first);
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      first->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  Element* second = GetDocument().getElementById(AtomicString("second"));
  EXPECT_TRUE(second);
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      second->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  main_resource.Write(R"HTML(
    </div>
    <div id="third" class="a"> Third
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  first = GetDocument().getElementById(AtomicString("first"));
  EXPECT_TRUE(first);
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      first->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  second = GetDocument().getElementById(AtomicString("second"));
  EXPECT_TRUE(second);
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      second->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  Element* third = GetDocument().getElementById(AtomicString("third"));
  EXPECT_TRUE(third);
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      third->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  main_resource.Complete(R"HTML(
    </div>
    <div id="fourth"> Fourth </div>
  )HTML");

  first = GetDocument().getElementById(AtomicString("first"));
  EXPECT_TRUE(first);
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      first->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  second = GetDocument().getElementById(AtomicString("second"));
  EXPECT_TRUE(s
```