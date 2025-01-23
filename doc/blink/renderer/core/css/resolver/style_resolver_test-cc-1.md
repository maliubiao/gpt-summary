Response:
My thought process to answer the request about the `style_resolver_test.cc` file goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of this specific test file within the Chromium Blink engine. They are particularly interested in its relationship to web technologies (HTML, CSS, JavaScript), logical reasoning within the tests, common usage errors, and how a user's actions might lead to this code being executed. Crucially, this is the *second* part of a five-part request, so I need to summarize the functionality of *this specific snippet*.

2. **Identify the Key Components of the Code:** I scan the provided code snippet, looking for recurring patterns and keywords. I notice:
    * `TEST_F(StyleResolverTest, ...)`: This indicates individual test cases within a larger test fixture named `StyleResolverTest`.
    * Code manipulating the DOM using `GetDocument().body()->setInnerHTML(...)`: This means the tests are setting up specific HTML structures for testing.
    * `EXPECT_EQ(...)`, `EXPECT_TRUE(...)`, `EXPECT_FALSE(...)`: These are assertion macros, showing the expected outcomes of the tests.
    * References to CSS properties (e.g., `width`, `top`, `color`, `animation-name`).
    * References to pseudo-elements (e.g., `::before`, `::marker`, `::selection`).
    * References to Shadow DOM (`AttachShadowRootForTesting`, `<slot>`).
    * Mentions of Container Queries (`@container`).
    * Mentions of Anchor Positioning (`anchor()`).
    * Calls to `UpdateAllLifecyclePhasesForTest()`: This suggests the tests are interacting with Blink's rendering pipeline.
    * Calls to `GetComputedStyle()` and related methods: This signifies testing how styles are computed and applied.
    * Use of custom properties (`--a`, `--color`).

3. **Group Tests by Functionality:** I start to group the tests based on the CSS features they seem to be exercising:
    * **List Markers:** Tests related to `list-style`, `::marker`, and nested pseudo-elements.
    * **Custom Properties:** Tests involving `var()` and how inherited custom properties are handled.
    * **Rule Matching:** Tests checking which CSS rules apply to specific elements (`CssRulesForElement`).
    * **Cascaded Values:** Tests using `CascadedValuesForElement` to verify the order and source of applied styles.
    * **Shadow DOM:** Tests involving slots, fallbacks, and style inheritance within Shadow DOM.
    * **`EnsureComputedStyle`:** Tests focusing on when and how computed styles are calculated, especially for elements outside the main rendering tree.
    * **`ComputeValue`:** Tests verifying how CSS values are computed, both for standard and custom properties.
    * **Tree Scoping:** Tests related to style isolation and application within Shadow DOM trees.
    * **Inheritance from `display: contents`:** Tests checking how styles (specifically images) are inherited through elements with `display: contents`.
    * **Text Shadows in Highlights (`::selection`):** Tests specifically checking the use counting of text shadows within selection pseudo-elements.
    * **Container Queries:** Tests related to `@container` rules, including size and style container queries, and verifying the `DependsOnSizeContainerQueries` flag.
    * **Anchor Positioning:** Tests for the `anchor()` function.

4. **Infer Purpose and Functionality:** Based on the grouped tests, I can infer the overarching purpose of `style_resolver_test.cc`. It's a comprehensive suite of tests designed to ensure the correct functioning of Blink's style resolution process. This includes:
    * Correctly matching CSS rules to DOM elements.
    * Properly calculating and applying computed styles.
    * Handling different types of CSS properties (standard and custom).
    * Managing style inheritance, including complex cases like `display: contents` and Shadow DOM.
    * Implementing new CSS features like Container Queries and Anchor Positioning.
    * Ensuring performance optimizations don't introduce errors (as suggested by the comment about `HasPseudoElementStyle`).

5. **Connect to Web Technologies:** I explicitly link the tested features to HTML, CSS, and JavaScript:
    * **HTML:** The tests directly manipulate HTML structure.
    * **CSS:** The core focus is on CSS properties, selectors, pseudo-elements, and new CSS features.
    * **JavaScript:** While not directly tested *in this snippet*, the underlying style resolution mechanism is crucial for JavaScript interactions with the DOM and styling.

6. **Identify Logical Reasoning (Assumptions and Outputs):** For each test case, I consider the setup (the HTML and CSS) as the "input" or assumptions, and the `EXPECT_*` assertions as the expected "output."  I give concrete examples like "If the CSS sets `width: var(--b)` and `--b: var(--a)`, and `--a` is defined on the parent, then the computed width should be the value of `--a`."

7. **Consider User/Programming Errors:** I think about common mistakes developers might make that these tests could catch:
    * Incorrectly specifying CSS selectors.
    * Misunderstanding CSS inheritance rules.
    * Not accounting for Shadow DOM boundaries.
    * Improperly using custom properties or `var()`.
    * Incorrectly implementing new CSS features.

8. **Trace User Actions (Debugging Clues):** I outline how a user interaction might trigger the style resolution process and thus lead to this code:
    * Loading a web page.
    * Dynamic CSS changes through JavaScript.
    * User interactions that trigger state changes (hover, focus, etc.).

9. **Summarize for Part 2:**  Finally, I synthesize the information into a concise summary that captures the main function of *this specific part* of the `style_resolver_test.cc` file, keeping in mind it's part two of a larger set of tests. I emphasize the focus on testing various CSS features and their interactions.

10. **Refine and Organize:** I review my thoughts, ensuring clarity, accuracy, and proper organization into the requested categories. I use clear and concise language.
```cpp
功能归纳:

这段代码是 Chromium Blink 引擎中 `style_resolver_test.cc` 文件的第二部分，它主要包含了一系列针对 **CSS 样式解析器 (Style Resolver)** 功能的单元测试。  这些测试覆盖了样式解析器在处理各种 CSS 特性时的正确性，尤其关注以下几个方面：

* **列表标记 (List Markers) 和伪元素 (`::marker`, `::before`) 的样式解析:**  测试了浏览器默认样式 (UA style) 和开发者自定义样式对列表标记以及通过 `::before` 生成的标记伪元素的影响，验证了 `HasPseudoElementStyle` 标志的设置时机。
* **继承型自定义属性 (Inherited Custom Properties) 的变更处理:** 验证了当继承型的自定义属性发生变化时，样式解析器能否正确地重新应用包括非继承属性在内的所有样式。
* **获取元素关联的 CSS 规则 (`CssRulesForElement`):**  测试了获取与特定元素关联的不同来源 (UA, User, Author) 的 CSS 规则的功能，确保不会崩溃。
* **嵌套伪元素样式的处理:**  测试了对嵌套伪元素 (例如 `div::before::marker`) 计算样式的能力，防止出现崩溃。
* **获取元素的级联值 (`CascadedValuesForElement`):**  测试了能够正确获取元素及其伪元素的级联样式值，包括来自不同来源 (style 属性, CSS 规则) 的值，以及处理 `!important` 的情况。
* **容器查询 (Container Queries) 对级联值的影响:**  测试了在容器查询的上下文中，样式解析器是否能够正确获取元素的级联样式值。
* **`EnsureComputedStyle` 的行为，特别是针对 Shadow DOM 和非扁平树 (Non-Flat Tree) 中的元素:** 验证了在需要时 (即使元素不在扁平树中) 能够正确地计算样式，并处理了 `slot` 插槽的 fallback 内容样式继承问题。
* **`ComputeValue` 的功能，用于计算最终的 CSS 值:** 测试了 `ComputeValue` 函数在解析和计算标准 CSS 属性和自定义属性值时的正确性。
* **树作用域引用 (Tree-Scoped References) 的处理:**  测试了 Shadow DOM 中样式规则的作用域限制，确保样式只在所属的 Shadow Root 内生效，以及 `::slotted` 伪元素选择器的行为。
* **从 `display: contents` 元素继承图像资源:**  验证了当父元素设置了 `display: contents` 时，子元素能否正确继承父元素的图像相关的 CSS 属性值 (例如 `background-image`, `border-image-source`)。
* **`::selection` 伪元素中的 `text-shadow` 属性的使用计数 (Use Counting):**  测试了在 `::selection` 伪元素中使用 `text-shadow` 属性时，是否正确触发了相应的 Web Feature 使用计数器。
* **容器查询对 `ComputedStyle` 的影响 (`DependsOnSizeContainerQueries`, `DependsOnStyleContainerQueries`):**  测试了容器查询是否正确地设置了 `ComputedStyle` 对象上的相关标志，以及这些标志是否被正确地缓存和使用。
* **锚点定位 (Anchor Positioning) 的测试:**  初步涉及了锚点定位功能的测试，验证了 `anchor()` 函数的基本使用。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**  测试代码通过 `GetDocument().body()->setInnerHTML(...)` 来动态创建和修改 HTML 结构，这是所有样式解析的基础。 例如，创建一个包含多个 `<li>` 元素的 `<ul>` 列表，用于测试列表标记的样式。
* **CSS:**  测试代码的核心是验证 CSS 样式的解析和应用。例如，使用 `<style>` 标签定义各种 CSS 规则，包括选择器、属性和值，用于测试样式解析器是否能正确匹配和应用这些规则。 比如，定义 `#parent1 { --a: 10px; }` 和 `#child1 { width: var(--b); --b: var(--a); }` 来测试自定义属性的继承。
* **JavaScript:**  虽然这段代码本身是 C++ 写的测试，但它测试的功能直接影响 JavaScript 操作样式的结果。 例如，JavaScript 可以通过 `element.style.property = value` 或修改 class 来改变元素的样式，而样式解析器则负责解析这些改变并更新元素的最终样式。  测试中虽然没有直接的 JavaScript 代码，但通过设置 HTML 和 CSS，然后断言最终的计算样式，间接地验证了 JavaScript 改变样式后的效果。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对列表标记测试):**
    * HTML:  一个包含不同 `list-style-type` 和 `list-style-position` 的 `<ul>` 列表，每个 `<li>` 内包含一个 `<b>` 元素。
    * CSS:  可能包含针对 `li`, `li::marker`, `li b::before`, `li b::before::marker` 的 CSS 规则，包括 UA 样式和 Author 样式。
* **预期输出:**
    * 断言 `PseudoElement` 是否被正确创建 (例如 `EXPECT_TRUE(marker)`).
    * 断言 `ComputedStyle` 中的属性值是否符合预期 (例如 `EXPECT_EQ(marker->GetComputedStyle()->GetUnicodeBidi(), UnicodeBidi::kIsolate)`).
    * 断言 `HasPseudoElementStyle` 标志是否在合适的时机被设置。

* **假设输入 (针对继承型自定义属性测试):**
    * HTML:  两个父元素 (`#parent1`, `#parent2`)，每个包含一个子元素 (`#child1`, `#child2`)。
    * CSS:  定义了自定义属性 `--a` 在父元素上，并通过 `var(--a)` 和 `--b` 在子元素上设置 `width`。
* **预期输出:**
    * 断言子元素的 `width` 计算值是否正确地反映了父元素上定义的自定义属性值 (例如 `EXPECT_EQ("10px", ComputedValue("width", *StyleForId("child1")))`).

**涉及用户或编程常见的使用错误举例说明:**

* **CSS 选择器错误:** 用户可能写出错误的 CSS 选择器，导致样式没有应用到预期的元素上。 例如，误写成 `#parent > .child` 而实际 DOM 结构是嵌套的。 测试会验证样式解析器是否按照 CSS 规范正确匹配选择器。
* **CSS 优先级理解错误:**  用户可能不理解 CSS 优先级规则 (特异性、来源、顺序)，导致样式被意外覆盖。 例如，在内联样式中设置了某个属性，又在 CSS 文件中设置了相同的属性，但期望的是 CSS 文件中的样式生效。 测试通过设置不同的样式来源来验证优先级规则的正确性。
* **Shadow DOM 样式隔离问题:** 用户可能忘记 Shadow DOM 的样式隔离特性，期望外部样式能够直接影响 Shadow Root 内的元素，或者反之。 测试通过创建 Shadow DOM 并验证样式的应用范围来暴露这类问题。
* **自定义属性使用错误:**  用户可能错误地使用 `var()` 函数，例如引用了不存在的自定义属性，或者在定义自定义属性时出现语法错误。 测试会验证样式解析器在处理这些错误情况时的行为。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载或浏览网页:**  这是最基本的入口点。浏览器需要解析 HTML 和 CSS 来渲染页面，这涉及到样式解析器的核心功能。
2. **网页包含复杂的 CSS 规则:**  如果网页使用了大量的 CSS 规则，包括各种选择器、伪元素、自定义属性、容器查询等新特性，那么样式解析器就需要执行更复杂的逻辑。
3. **网页使用了 Shadow DOM:**  当网页使用了 Web Components 和 Shadow DOM 时，样式解析器需要处理样式作用域的隔离和 `::slotted` 等选择器，这会触发相关的测试用例。
4. **网页通过 JavaScript 动态修改样式:**  JavaScript 可以修改元素的 `style` 属性或添加/删除 class，这些操作会触发样式的重新解析和计算。 例如，通过 JavaScript 改变一个元素的 `width`，可能会触发与容器查询相关的样式重新评估。
5. **开发者在 Chromium 引擎中开发或调试样式解析器相关的功能:**  当开发者修改了样式解析器的代码时，为了确保修改的正确性，就需要运行这些单元测试。 如果某个测试失败，就意味着新代码可能引入了 bug，开发者会根据失败的测试用例来定位和修复问题。

例如，如果用户在一个使用了列表的网页上发现列表标记的样式显示不正确，开发者在调试时可能会关注与列表标记和伪元素相关的代码，并运行 `style_resolver_test.cc` 中相关的测试用例来验证样式解析器的行为是否符合预期。  或者，如果开发者正在实现容器查询的新功能，他们会编写类似的测试用例来确保容器查询的样式应用逻辑正确无误。

**本部分功能归纳:**

总的来说，`style_resolver_test.cc` 的这段代码主要集中在测试 **CSS 样式解析器在处理列表标记、继承型自定义属性、嵌套伪元素、级联值计算、Shadow DOM 样式、`ComputeValue` 函数、树作用域、`display: contents` 继承、`::selection` 伪元素以及容器查询等核心 CSS 特性时的正确性**。  它通过构建特定的 HTML 和 CSS 场景，并断言计算出的样式结果，来确保 Blink 引擎的样式解析器能够按照 CSS 规范的要求工作。 这部分测试覆盖了样式解析器在面对各种复杂的 CSS 规则和 DOM 结构时的行为，对于保证网页渲染的正确性至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ist-style: disc inside"><b></b></li>
      <li style="list-style: '- ' outside"><b></b></li>
      <li style="list-style: '- ' inside"><b></b></li>
      <li style="list-style: linear-gradient(blue, cyan) outside"><b></b></li>
      <li style="list-style: linear-gradient(blue, cyan) inside"><b></b></li>
      <li style="list-style: none outside"><b></b></li>
      <li style="list-style: none inside"><b></b></li>
    </ul>
  )HTML");
  StaticElementList* lis = GetDocument().QuerySelectorAll(AtomicString("li"));
  EXPECT_EQ(lis->length(), 10U);

  UpdateAllLifecyclePhasesForTest();
  for (unsigned i = 0; i < lis->length(); ++i) {
    Element* li = lis->item(i);
    PseudoElement* marker = li->GetPseudoElement(kPseudoIdMarker);
    PseudoElement* before =
        li->QuerySelector(AtomicString("b"))->GetPseudoElement(kPseudoIdBefore);
    PseudoElement* nested_marker = before->GetPseudoElement(kPseudoIdMarker);

    // Check that UA styles for list markers don't set HasPseudoElementStyle
    const ComputedStyle* li_style = li->GetComputedStyle();
    EXPECT_FALSE(li_style->HasPseudoElementStyle(kPseudoIdMarker));
    EXPECT_FALSE(li_style->HasAnyPseudoElementStyles());
    // Check that UA's ::before::marker rule doesn't set HasPseudoElementStyle.
    // For performance reason we do not SetHasPseudoElementStyle() for ::marker
    // pseudo element selectors from UA stylesheets for now.
    const ComputedStyle* before_style = before->GetComputedStyle();
    EXPECT_FALSE(before_style->HasPseudoElementStyle(kPseudoIdMarker));
    EXPECT_FALSE(before_style->HasAnyPseudoElementStyles());

    if (i >= 8) {
      EXPECT_FALSE(marker);
      EXPECT_FALSE(nested_marker);
      continue;
    }

    // Check that list markers have UA styles
    EXPECT_TRUE(marker);
    EXPECT_TRUE(nested_marker);
    EXPECT_EQ(marker->GetComputedStyle()->GetUnicodeBidi(),
              UnicodeBidi::kIsolate);
    EXPECT_EQ(nested_marker->GetComputedStyle()->GetUnicodeBidi(),
              UnicodeBidi::kIsolate);
  }

  GetDocument().body()->SetIdAttribute(AtomicString("marker"));
  UpdateAllLifecyclePhasesForTest();
  for (unsigned i = 0; i < lis->length(); ++i) {
    Element* li = lis->item(i);
    PseudoElement* before =
        li->QuerySelector(AtomicString("b"))->GetPseudoElement(kPseudoIdBefore);

    // Check that author styles for list markers do set HasPseudoElementStyle
    const ComputedStyle* li_style = li->GetComputedStyle();
    EXPECT_TRUE(li_style->HasPseudoElementStyle(kPseudoIdMarker));
    EXPECT_TRUE(li_style->HasAnyPseudoElementStyles());

    // But #marker ::marker styles don't match a ::before::marker
    const ComputedStyle* before_style = before->GetComputedStyle();
    EXPECT_FALSE(before_style->HasPseudoElementStyle(kPseudoIdMarker));
    EXPECT_FALSE(before_style->HasAnyPseudoElementStyles());
  }

  GetDocument().body()->SetIdAttribute(AtomicString("before-marker"));
  UpdateAllLifecyclePhasesForTest();
  Element* li = lis->item(0);
  PseudoElement* before =
      li->QuerySelector(AtomicString("b"))->GetPseudoElement(kPseudoIdBefore);
  // And #before-marker ::before::marker styles match a ::before::marker
  const ComputedStyle* before_style = before->GetComputedStyle();
  EXPECT_TRUE(before_style->HasPseudoElementStyle(kPseudoIdMarker));
  EXPECT_TRUE(before_style->HasAnyPseudoElementStyles());
}

TEST_F(StyleResolverTest, ApplyInheritedOnlyCustomPropertyChange) {
  // This test verifies that when we get a "apply inherited only"-type
  // hit in the MatchesPropertiesCache, we're able to detect that custom
  // properties changed, and that we therefore need to apply the non-inherited
  // properties as well.

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #parent1 { --a: 10px; }
      #parent2 { --a: 20px; }
      #child1, #child2 {
        --b: var(--a);
        width: var(--b);
      }
    </style>
    <div id=parent1><div id=child1></div></div>
    <div id=parent2><div id=child2></div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("10px", ComputedValue("width", *StyleForId("child1")));
  EXPECT_EQ("20px", ComputedValue("width", *StyleForId("child2")));
}

TEST_F(StyleResolverTest, CssRulesForElementIncludedRules) {
  UpdateAllLifecyclePhasesForTest();

  Element* body = GetDocument().body();
  ASSERT_TRUE(body);

  // Don't crash when only getting one type of rule.
  auto& resolver = GetDocument().GetStyleResolver();
  resolver.CssRulesForElement(body, StyleResolver::kUACSSRules);
  resolver.CssRulesForElement(body, StyleResolver::kUserCSSRules);
  resolver.CssRulesForElement(body, StyleResolver::kAuthorCSSRules);
}

TEST_F(StyleResolverTest, NestedPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div::before { content: "Hello"; display: list-item; }
      div::before::marker { color: green; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  // Don't crash when calculating style for nested pseudo elements.
}

TEST_F(StyleResolverTest, CascadedValuesForElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #div {
        top: 1em;
      }
      div {
        top: 10em;
        right: 20em;
        bottom: 30em;
        left: 40em;

        width: 50em;
        width: 51em;
        height: 60em !important;
        height: 61em;
      }
    </style>
    <div id=div style="bottom:300em;"></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto& resolver = GetDocument().GetStyleResolver();
  Element* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);

  auto map = resolver.CascadedValuesForElement(div, kPseudoIdNone);

  CSSPropertyName top(CSSPropertyID::kTop);
  CSSPropertyName right(CSSPropertyID::kRight);
  CSSPropertyName bottom(CSSPropertyID::kBottom);
  CSSPropertyName left(CSSPropertyID::kLeft);
  CSSPropertyName width(CSSPropertyID::kWidth);
  CSSPropertyName height(CSSPropertyID::kHeight);

  ASSERT_TRUE(map.at(top));
  ASSERT_TRUE(map.at(right));
  ASSERT_TRUE(map.at(bottom));
  ASSERT_TRUE(map.at(left));
  ASSERT_TRUE(map.at(width));
  ASSERT_TRUE(map.at(height));

  EXPECT_EQ("1em", map.at(top)->CssText());
  EXPECT_EQ("20em", map.at(right)->CssText());
  EXPECT_EQ("300em", map.at(bottom)->CssText());
  EXPECT_EQ("40em", map.at(left)->CssText());
  EXPECT_EQ("51em", map.at(width)->CssText());
  EXPECT_EQ("60em", map.at(height)->CssText());
}

TEST_F(StyleResolverTest, CascadedValuesForPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #div::before {
        top: 1em;
      }
      div::before {
        top: 10em;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto& resolver = GetDocument().GetStyleResolver();
  Element* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);

  auto map = resolver.CascadedValuesForElement(div, kPseudoIdBefore);

  CSSPropertyName top(CSSPropertyID::kTop);
  ASSERT_TRUE(map.at(top));
  EXPECT_EQ("1em", map.at(top)->CssText());
}

TEST_F(StyleResolverTestCQ, CascadedValuesForElementInContainer) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #container { container-type: inline-size; }
      @container (min-width: 1px) {
        #inner {
          top: 1em;
        }
      }
      div {
        top: 10em;
      }
    </style>
    <div id="container">
      <div id="inner"></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto& resolver = GetDocument().GetStyleResolver();
  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  ASSERT_TRUE(inner);

  auto map = resolver.CascadedValuesForElement(inner, kPseudoIdNone);

  CSSPropertyName top(CSSPropertyID::kTop);
  ASSERT_TRUE(map.at(top));
  EXPECT_EQ("1em", map.at(top)->CssText());
}

TEST_F(StyleResolverTestCQ, CascadedValuesForPseudoElementInContainer) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #container { container-type: inline-size; }
      @container (min-width: 1px) {
        #inner::before {
          top: 1em;
        }
      }
      div::before {
        top: 10em;
      }
    </style>
    <div id="container">
      <div id="inner"></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto& resolver = GetDocument().GetStyleResolver();
  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  ASSERT_TRUE(inner);

  auto map = resolver.CascadedValuesForElement(inner, kPseudoIdBefore);

  CSSPropertyName top(CSSPropertyID::kTop);
  ASSERT_TRUE(map.at(top));
  EXPECT_EQ("1em", map.at(top)->CssText());
}

TEST_F(StyleResolverTest, EnsureComputedStyleSlotFallback) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="host"><span></span></div>
  )HTML");

  ShadowRoot& shadow_root =
      GetDocument()
          .getElementById(AtomicString("host"))
          ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
    <style>
      slot { color: red }
    </style>
    <slot><span id="fallback"></span></slot>
  )HTML");
  Element* fallback = shadow_root.getElementById(AtomicString("fallback"));
  ASSERT_TRUE(fallback);

  UpdateAllLifecyclePhasesForTest();

  // Elements outside the flat tree does not get styles computed during the
  // lifecycle update.
  EXPECT_FALSE(fallback->GetComputedStyle());

  // We are currently allowed to query the computed style of elements outside
  // the flat tree, but slot fallback does not inherit from the slot.
  const ComputedStyle* fallback_style = fallback->EnsureComputedStyle();
  ASSERT_TRUE(fallback_style);
  EXPECT_EQ(Color::kBlack,
            fallback_style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleResolverTest, EnsureComputedStyleOutsideFlatTree) {
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <div id=host>
      <template shadowrootmode=open>
      </template>
      <div id=a>
        <div id=b>
          <div id=c>
            <div id=d>
              <div id=e>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* host = GetElementById("host");
  ASSERT_TRUE(host);
  ASSERT_TRUE(host->GetShadowRoot());

  Element* a = GetElementById("a");
  Element* b = GetElementById("b");
  Element* c = GetElementById("c");
  Element* d = GetElementById("d");
  Element* e = GetElementById("e");
  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  ASSERT_TRUE(c);
  ASSERT_TRUE(d);
  ASSERT_TRUE(e);

  EXPECT_FALSE(a->GetComputedStyle());
  EXPECT_FALSE(b->GetComputedStyle());
  EXPECT_FALSE(c->GetComputedStyle());
  EXPECT_FALSE(d->GetComputedStyle());
  EXPECT_FALSE(e->GetComputedStyle());

  c->EnsureComputedStyle();

  const ComputedStyle* a_style = a->GetComputedStyle();
  const ComputedStyle* b_style = b->GetComputedStyle();
  const ComputedStyle* c_style = c->GetComputedStyle();

  ASSERT_TRUE(a_style);
  ASSERT_TRUE(b_style);
  ASSERT_TRUE(c_style);
  EXPECT_FALSE(d->GetComputedStyle());
  EXPECT_FALSE(e->GetComputedStyle());

  // Dirty style of #a.
  a->SetInlineStyleProperty(CSSPropertyID::kZIndex, "42");

  // Note that there is no call to UpdateAllLifecyclePhasesForTest here,
  // because #a is outside the flat tree, hence that process would anyway not
  // reach #a.

  // Ensuring the style of some deep descendant must discover that some ancestor
  // is marked for recalc.
  e->EnsureComputedStyle();
  EXPECT_TRUE(a->GetComputedStyle());
  EXPECT_TRUE(b->GetComputedStyle());
  EXPECT_TRUE(c->GetComputedStyle());
  EXPECT_TRUE(d->GetComputedStyle());
  EXPECT_TRUE(e->GetComputedStyle());
  EXPECT_NE(a_style, a->GetComputedStyle());
  EXPECT_NE(b_style, b->GetComputedStyle());
  EXPECT_NE(c_style, c->GetComputedStyle());
}

TEST_F(StyleResolverTest, ComputeValueStandardProperty) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #target { --color: green }
    </style>
    <div id="target"></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  // Unable to parse a variable reference with css_test_helpers::ParseLonghand.
  CSSPropertyID property_id = CSSPropertyID::kColor;
  auto* set =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  MutableCSSPropertyValueSet::SetResult result = set->ParseAndSetProperty(
      property_id, "var(--color)", false, SecureContextMode::kInsecureContext,
      /*context_style_sheet=*/nullptr);
  ASSERT_NE(MutableCSSPropertyValueSet::kParseError, result);
  const CSSValue* parsed_value = set->GetPropertyCSSValue(property_id);
  ASSERT_TRUE(parsed_value);
  const CSSValue* computed_value = StyleResolver::ComputeValue(
      target, CSSPropertyName(property_id), *parsed_value);
  ASSERT_TRUE(computed_value);
  EXPECT_EQ("rgb(0, 128, 0)", computed_value->CssText());
}

namespace {

const CSSValue* ParseCustomProperty(Document& document,
                                    const CustomProperty& property,
                                    const String& value) {
  const auto* context = MakeGarbageCollected<CSSParserContext>(document);
  CSSParserLocalContext local_context;

  return property.Parse(value, *context, local_context);
}

}  // namespace

TEST_F(StyleResolverTest, ComputeValueCustomProperty) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #target { --color: green }
    </style>
    <div id="target"></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  AtomicString custom_property_name("--color");
  const CSSValue* parsed_value = ParseCustomProperty(
      GetDocument(), CustomProperty(custom_property_name, GetDocument()),
      "blue");
  ASSERT_TRUE(parsed_value);
  const CSSValue* computed_value = StyleResolver::ComputeValue(
      target, CSSPropertyName(custom_property_name), *parsed_value);
  ASSERT_TRUE(computed_value);
  EXPECT_EQ("blue", computed_value->CssText());
}

TEST_F(StyleResolverTest, TreeScopedReferences) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #host { animation-name: anim }
    </style>
    <div id="host">
      <span id="slotted"></span>
    </host>
  )HTML");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ShadowRoot& root = host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  root.setInnerHTML(R"HTML(
    <style>
      ::slotted(span) { animation-name: anim-slotted }
      :host { font-family: myfont }
    </style>
    <div id="inner-host">
      <slot></slot>
    </div>
  )HTML");

  Element* inner_host = root.getElementById(AtomicString("inner-host"));
  ASSERT_TRUE(inner_host);
  ShadowRoot& inner_root =
      inner_host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  inner_root.setInnerHTML(R"HTML(
    <style>
      ::slotted(span) { animation-name: anim-inner-slotted }
    </style>
    <slot></slot>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  {
    StyleResolverState state(GetDocument(), *host);
    SelectorFilter filter;
    MatchResult match_result;
    ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                   filter, match_result,
                                   EInsideLink::kNotInsideLink);
    GetDocument().GetStyleEngine().GetStyleResolver().MatchAllRules(
        state, collector, false /* include_smil_properties */);
    const auto& properties = match_result.GetMatchedProperties();
    ASSERT_EQ(properties.size(), 4u);

    // div { display: block }
    EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kUserAgent);

    // div { unicode-bidi: isolate; }
    EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kUserAgent);

    // :host { font-family: myfont }
    EXPECT_EQ(match_result.ScopeFromTreeOrder(properties[2].data_.tree_order),
              root.GetTreeScope());
    EXPECT_EQ(properties[2].data_.origin, CascadeOrigin::kAuthor);

    // #host { animation-name: anim }
    EXPECT_EQ(properties[3].data_.origin, CascadeOrigin::kAuthor);
    EXPECT_EQ(match_result.ScopeFromTreeOrder(properties[3].data_.tree_order),
              host->GetTreeScope());
  }

  {
    auto* span = GetDocument().getElementById(AtomicString("slotted"));
    StyleResolverState state(GetDocument(), *span);
    SelectorFilter filter;
    MatchResult match_result;
    ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                   filter, match_result,
                                   EInsideLink::kNotInsideLink);
    GetDocument().GetStyleEngine().GetStyleResolver().MatchAllRules(
        state, collector, false /* include_smil_properties */);
    const auto& properties = match_result.GetMatchedProperties();
    ASSERT_EQ(properties.size(), 2u);

    // ::slotted(span) { animation-name: anim-inner-slotted }
    EXPECT_EQ(properties[0].data_.origin, CascadeOrigin::kAuthor);
    EXPECT_EQ(match_result.ScopeFromTreeOrder(properties[0].data_.tree_order),
              inner_root.GetTreeScope());

    // ::slotted(span) { animation-name: anim-slotted }
    EXPECT_EQ(properties[1].data_.origin, CascadeOrigin::kAuthor);
    EXPECT_EQ(match_result.ScopeFromTreeOrder(properties[1].data_.tree_order),
              root.GetTreeScope());
  }
}

TEST_F(StyleResolverTest, InheritStyleImagesFromDisplayContents) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #parent {
        display: contents;

        background-image: url(1.png);
        border-image-source: url(2.png);
        cursor: url(3.ico), text;
        list-style-image: url(4.png);
        shape-outside: url(5.png);
        -webkit-box-reflect: below 0 url(6.png);
        -webkit-mask-box-image-source: url(7.png);
        -webkit-mask-image: url(8.png);
      }
      #child {
        background-image: inherit;
        border-image-source: inherit;
        cursor: inherit;
        list-style-image: inherit;
        shape-outside: inherit;
        -webkit-box-reflect: inherit;
        -webkit-mask-box-image-source: inherit;
        -webkit-mask-image: inherit;
      }
    </style>
    <div id="parent">
      <div id="child"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* child = GetDocument().getElementById(AtomicString("child"));
  auto* style = child->GetComputedStyle();
  ASSERT_TRUE(style);

  ASSERT_TRUE(style->BackgroundLayers().GetImage());
  EXPECT_FALSE(style->BackgroundLayers().GetImage()->IsPendingImage())
      << "background-image is fetched";

  ASSERT_TRUE(style->BorderImageSource());
  EXPECT_FALSE(style->BorderImageSource()->IsPendingImage())
      << "border-image-source is fetched";

  ASSERT_TRUE(style->Cursors());
  ASSERT_TRUE(style->Cursors()->size());
  ASSERT_TRUE(style->Cursors()->at(0).GetImage());
  EXPECT_FALSE(style->Cursors()->at(0).GetImage()->IsPendingImage())
      << "cursor is fetched";

  ASSERT_TRUE(style->ListStyleImage());
  EXPECT_FALSE(style->ListStyleImage()->IsPendingImage())
      << "list-style-image is fetched";

  ASSERT_TRUE(style->ShapeOutside());
  ASSERT_TRUE(style->ShapeOutside()->GetImage());
  EXPECT_FALSE(style->ShapeOutside()->GetImage()->IsPendingImage())
      << "shape-outside is fetched";

  ASSERT_TRUE(style->BoxReflect());
  ASSERT_TRUE(style->BoxReflect()->Mask().GetImage());
  EXPECT_FALSE(style->BoxReflect()->Mask().GetImage()->IsPendingImage())
      << "-webkit-box-reflect is fetched";

  ASSERT_TRUE(style->MaskBoxImageSource());
  EXPECT_FALSE(style->MaskBoxImageSource()->IsPendingImage())
      << "-webkit-mask-box-image-source";

  ASSERT_TRUE(style->MaskLayers().GetImage());
  EXPECT_FALSE(style->MaskLayers().GetImage()->IsPendingImage())
      << "-webkit-mask-image is fetched";
}

TEST_F(StyleResolverTest, TextShadowInHighlightPseudoNotCounted1) {
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      * {
        text-shadow: 5px 5px green;
      }
    </style>
    <div id="target">target</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  const auto* element_style = target->GetComputedStyle();
  ASSERT_TRUE(element_style);

  StyleRequest pseudo_style_request;
  pseudo_style_request.parent_override = element_style;
  pseudo_style_request.layout_parent_override = element_style;
  pseudo_style_request.originating_element_style = element_style;
  pseudo_style_request.pseudo_id = kPseudoIdSelection;
  const ComputedStyle* selection_style =
      GetDocument().GetStyleResolver().ResolveStyle(
          target, StyleRecalcContext(), pseudo_style_request);
  ASSERT_FALSE(selection_style);

  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));
}

TEST_F(StyleResolverTest, TextShadowInHighlightPseudoNotCounted2) {
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      * {
        text-shadow: 5px 5px green;
      }
      ::selection {
        color: white;
        background: blue;
      }
    </style>
    <div id="target">target</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  const auto* element_style = target->GetComputedStyle();
  ASSERT_TRUE(element_style);

  StyleRequest pseudo_style_request;
  pseudo_style_request.parent_override = element_style;
  pseudo_style_request.layout_parent_override = element_style;
  pseudo_style_request.originating_element_style = element_style;
  pseudo_style_request.pseudo_id = kPseudoIdSelection;
  const ComputedStyle* selection_style =
      GetDocument().GetStyleResolver().ResolveStyle(
          target, StyleRecalcContext(), pseudo_style_request);
  ASSERT_TRUE(selection_style);

  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));
}

TEST_F(StyleResolverTest, TextShadowInHighlightPseudotNone) {
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      * {
        text-shadow: 5px 5px green;
      }
      ::selection {
        text-shadow: none;
      }
    </style>
    <div id="target">target</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  const auto* element_style = target->GetComputedStyle();
  ASSERT_TRUE(element_style);

  StyleRequest pseudo_style_request;
  pseudo_style_request.parent_override = element_style;
  pseudo_style_request.layout_parent_override = element_style;
  pseudo_style_request.originating_element_style = element_style;
  pseudo_style_request.pseudo_id = kPseudoIdSelection;
  const ComputedStyle* selection_style =
      GetDocument().GetStyleResolver().ResolveStyle(
          target, StyleRecalcContext(), pseudo_style_request);
  ASSERT_TRUE(selection_style);

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));
}

TEST_F(StyleResolverTest, TextShadowInHighlightPseudoNotNone1) {
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      ::selection {
        text-shadow: 5px 5px green;
      }
    </style>
    <div id="target">target</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  const auto* element_style = target->GetComputedStyle();
  ASSERT_TRUE(element_style);

  StyleRequest pseudo_style_request;
  pseudo_style_request.parent_override = element_style;
  pseudo_style_request.layout_parent_override = element_style;
  pseudo_style_request.originating_element_style = element_style;
  pseudo_style_request.pseudo_id = kPseudoIdSelection;
  const ComputedStyle* selection_style =
      GetDocument().GetStyleResolver().ResolveStyle(
          target, StyleRecalcContext(), pseudo_style_request);
  ASSERT_TRUE(selection_style);

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));
}

TEST_F(StyleResolverTest, TextShadowInHighlightPseudoNotNone2) {
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      * {
        text-shadow: 5px 5px green;
      }
      ::selection {
        text-shadow: 5px 5px green;
      }
    </style>
    <div id="target">target</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  const auto* element_style = target->GetComputedStyle();
  ASSERT_TRUE(element_style);

  StyleRequest pseudo_style_request;
  pseudo_style_request.parent_override = element_style;
  pseudo_style_request.layout_parent_override = element_style;
  pseudo_style_request.originating_element_style = element_style;
  pseudo_style_request.pseudo_id = kPseudoIdSelection;
  const ComputedStyle* selection_style =
      GetDocument().GetStyleResolver().ResolveStyle(
          target, StyleRecalcContext(), pseudo_style_request);
  ASSERT_TRUE(selection_style);

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kTextShadowInHighlightPseudo));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kTextShadowNotNoneInHighlightPseudo));
}

TEST_F(StyleResolverTestCQ, DependsOnSizeContainerQueries) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #a { color: red; }
      @container (min-width: 0px) {
        #b { color: blue; }
        span { color: green; }
        #d { color: coral; }
      }
    </style>
    <div id=a></div>
    <span id=b></span>
    <span id=c></span>
    <div id=d></div>
    <div id=e></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* a = GetDocument().getElementById(AtomicString("a"));
  auto* b = GetDocument().getElementById(AtomicString("b"));
  auto* c = GetDocument().getElementById(AtomicString("c"));
  auto* d = GetDocument().getElementById(AtomicString("d"));
  auto* e = GetDocument().getElementById(AtomicString("e"));

  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  ASSERT_TRUE(c);
  ASSERT_TRUE(d);
  ASSERT_TRUE(e);

  EXPECT_FALSE(a->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_TRUE(b->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_TRUE(c->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_TRUE(d->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(e->ComputedStyleRef().DependsOnSizeContainerQueries());

  EXPECT_FALSE(a->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_FALSE(b->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_FALSE(c->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_FALSE(d->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_FALSE(e->ComputedStyleRef().DependsOnStyleContainerQueries());
}

TEST_F(StyleResolverTestCQ, DependsOnSizeContainerQueriesPseudo) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      main { container-type: size; width: 100px; }
      #a::before { content: "before"; }
      @container (min-width: 0px) {
        #a::after { content: "after"; }
      }
    </style>
    <main>
      <div id=a></div>
    </main>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* a = GetDocument().getElementById(AtomicString("a"));
  auto* before = a->GetPseudoElement(kPseudoIdBefore);
  auto* after = a->GetPseudoElement(kPseudoIdAfter);

  ASSERT_TRUE(a);
  ASSERT_TRUE(before);
  ASSERT_TRUE(after);

  EXPECT_TRUE(a->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(before->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_TRUE(after->ComputedStyleRef().DependsOnSizeContainerQueries());
}

// Verify that the ComputedStyle::DependsOnSizeContainerQuery flag does
// not end up in the MatchedPropertiesCache (MPC).
TEST_F(StyleResolverTestCQ, DependsOnSizeContainerQueriesMPC) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      @container (min-width: 9999999px) {
        #a { color: green; }
      }
    </style>
    <div id=a></div>
    <div id=b></div>
  )HTML");

  // In the above example, both <div id=a> and <div id=b> match the same
  // rules (i.e. whatever is provided by UA style). The selector inside
  // the @container rule does ultimately _not_ match <div id=a> (because the
  // container query evaluates to 'false'), however, it _does_ cause the
  // ComputedStyle::DependsOnSizeContainerQuery flag to be set on #a.
  //
  // We must ensure that we don't add the DependsOnSizeContainerQuery-flagged
  // style to the MPC, otherwise the subsequent cache hit for #b would result
  // in the flag being (incorrectly) set for that element.

  UpdateAllLifecyclePhasesForTest();

  auto* a = GetDocument().getElementById(AtomicString("a"));
  auto* b = GetDocument().getElementById(AtomicString("b"));

  ASSERT_TRUE(a);
  ASSERT_TRUE(b);

  EXPECT_TRUE(a->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(b->ComputedStyleRef().DependsOnSizeContainerQueries());
}

TEST_F(StyleResolverTestCQ, DependsOnStyleContainerQueries) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #a { color: red; }
      @container style(--foo: bar) {
        #b { color: blue; }
        span { color: green; }
        #d { color: coral; }
      }
    </style>
    <div id=a></div>
    <span id=b></span>
    <span id=c></span>
    <div id=d></div>
    <div id=e></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* a = GetDocument().getElementById(AtomicString("a"));
  auto* b = GetDocument().getElementById(AtomicString("b"));
  auto* c = GetDocument().getElementById(AtomicString("c"));
  auto* d = GetDocument().getElementById(AtomicString("d"));
  auto* e = GetDocument().getElementById(AtomicString("e"));

  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  ASSERT_TRUE(c);
  ASSERT_TRUE(d);
  ASSERT_TRUE(e);

  EXPECT_FALSE(a->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_TRUE(b->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_TRUE(c->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_TRUE(d->ComputedStyleRef().DependsOnStyleContainerQueries());
  EXPECT_FALSE(e->ComputedStyleRef().DependsOnStyleContainerQueries());

  EXPECT_FALSE(a->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(b->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(c->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(d->ComputedStyleRef().DependsOnSizeContainerQueries());
  EXPECT_FALSE(e->ComputedStyleRef().DependsOnSizeContainerQueries());
}

TEST_F(StyleResolverTest, AnchorQueriesMPC) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      .anchor {
        position: absolute;
        width: 100px;
        height: 100px;
      }
      #anchor1 { left: 100px; }
      #anchor2 { left: 150px; }
      .anchored {
        position: absolute;
        left: anchor(left);
      }
    </style>
    <div class=anchor id=anchor1>X</div>
    <div class=anchor id=anchor2>Y</div>
    <div class=anchored id=a anchor=anchor1>A</div>
    <div class=anchored id=b anchor=anchor2>B</div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  // #a and #b have identical styles, but the implicit anchor makes
  // the anchor() queries give two different answers.

  auto* a = GetDocument().getElementById(AtomicStr
```