Response:
The user wants a summary of the functionality of the `style_engine_test.cc` file in the Chromium Blink engine. I need to identify the main purpose of the file and how it relates to web technologies like JavaScript, HTML, and CSS. I also need to look for examples of logic, potential user errors, and how a user might trigger this code. Finally, I need to remember this is part 4 of an 8-part request.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The filename `style_engine_test.cc` strongly suggests this file contains tests for the style engine. The tests likely cover how the engine handles CSS parsing, application, and updates in response to changes in the DOM or other factors.

2. **Relate to JavaScript, HTML, and CSS:** The tests manipulate the DOM (HTML), modify inline styles and use CSS rules, and might implicitly involve JavaScript by triggering DOM manipulations or checking computed styles. I need to find concrete examples within the provided code.

3. **Find Examples of Logic and Reasoning:** Look for test cases that involve conditional behavior or checks based on certain inputs or states. Hypothesize inputs and expected outputs for these cases.

4. **Identify Potential User Errors:** Think about common mistakes web developers make related to styling, like invalid CSS or incorrect DOM manipulation, and see if the tests cover such scenarios.

5. **Trace User Actions (Debugging Clues):** Consider how a user's interaction with a webpage might lead to the style engine being invoked and these specific test scenarios being relevant for debugging.

6. **Summarize the Functionality:** Based on the identified functionalities, provide a concise overview of the file's purpose.

**Mental Walkthrough of the Code:**

* **`QuerySelector`:** Shows interaction with the DOM and CSS selectors. Input: HTML with a specific structure. Output: Confirmation that a rule is fast-rejected.
* **`FirstLetterRemoved`:**  Demonstrates how the style engine handles dynamic changes to `::first-letter` pseudo-elements when content is removed. Input: HTML with `::first-letter` styles. Output: Verification of style recalc flags and the presence/absence of the pseudo-element.
* **`InitialDataCreation`:** Tests the creation and invalidation of initial style data, potentially related to custom properties.
* **`CSSSelectorEmptyWhitespaceOnlyFail`:** Focuses on the `:empty` CSS selector and how whitespace affects its behavior. Input: HTML with different content within divs. Output: Tracking of a specific use counter.
* **`EnsuredComputedStyleRecalc`:** Explores how forcing computed styles in initially hidden elements affects style recalculation.
* **`EnsureCustomComputedStyle`:**  Similar to the previous one, but with a focus on elements that have a `display: none` style applied through other mechanisms.
* **`NoCrashWhenMarkingPartiallyRemovedSubtree`:** Aims to ensure stability when manipulating the DOM in specific ways that involve forms and subtree removal.
* **`ColorSchemeBaseBackgroundChange` and `ColorSchemeOverride`:** Test how the style engine reacts to changes in color scheme preferences and overrides.
* **`PseudoElementBaseComputedStyle`:** Focuses on the handling of base computed styles for pseudo-elements, especially in the context of animations.
* **`NeedsLayoutTreeRebuild`:** Verifies the flags related to needing a layout tree rebuild based on style changes.
* **`ForceReattachLayoutTreeStyleRecalcRoot` and `ForceReattachNoStyleForElement`:** Investigate how forcing a layout reattach affects the style recalculation root.
* **`RecalcPropagatedWritingMode`:**  Ensures that properties like `writing-mode` are propagated correctly during style recalculation.
* **`GetComputedStyleOutsideFlatTree` and related tests (`MoveSlottedOutsideFlatTree`, `StyleRecalcRootInShadowTree`, `StyleRecalcRootOutsideFlatTree`, `RemoveStyleRecalcRootFromFlatTree`, `SlottedWithEnsuredStyleOutsideFlatTree`, `ForceReattachRecalcRootAttachShadow`):**  These tests extensively cover how the style engine handles scenarios involving Shadow DOM and elements outside the flat tree.
* **`InitialColorChange`:** Tests how initial values for color are resolved based on the color scheme.
* **`MediaQueryAffectingValueChanged_*`:**  Focus on how changes to media queries (viewport size, media type, reduced motion) trigger style recalculations.
* **`RevertUseCount` and `RevertUseCountForCustomProperties`:** Check the tracking of the `revert` CSS keyword.
* **`NoRevertUseCountForForcedColors`:** Verifies that `revert` is not counted in forced colors mode.
* **`PrintNoDarkColorScheme`:** Tests the interaction of print media queries and color schemes.

**Overall Summary Idea:** The file tests the core functionalities of Blink's style engine, covering various aspects of CSS application, DOM manipulation, and interactions with browser features like color schemes and media queries. It ensures the engine behaves correctly and efficiently in different scenarios, including edge cases and potential developer errors.

Ready to generate the response.
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能
```

**功能列举:**

这个 `style_engine_test.cc` 文件是 Chromium Blink 引擎中用于测试 **样式引擎 (Style Engine)** 功能的单元测试文件。它的主要功能是：

1. **验证 CSS 规则的应用:** 测试各种 CSS 规则（选择器、属性、值）是否能正确地应用到 HTML 元素上。
2. **测试样式计算:** 验证样式引擎在不同情况下（例如，添加/删除元素、修改属性、媒体查询变化等）如何重新计算元素的样式。
3. **测试级联和继承:** 验证 CSS 的级联 (cascade) 和继承 (inheritance) 机制是否按预期工作。
4. **测试伪类和伪元素:** 验证诸如 `:hover`, `::before`, `::first-letter` 等伪类和伪元素的选择和样式应用。
5. **测试特定 CSS 特性:**  针对一些特定的 CSS 特性（例如，`color-scheme`, `revert` 关键字，媒体查询等）进行功能验证。
6. **测试性能优化:**  虽然不是直接测试性能，但可以通过某些测试场景来验证样式引擎的优化策略，例如快速拒绝不匹配的规则。
7. **测试 Shadow DOM 的样式处理:** 验证样式引擎在处理 Shadow DOM 边界时的行为。
8. **测试样式失效和重算机制:** 验证在 DOM 结构或样式发生变化时，样式引擎是否能正确地标记需要重算的元素。
9. **测试 ComputedStyle 的创建和管理:** 验证 ComputedStyle 对象的创建、缓存和失效机制。
10. **确保代码稳定性:** 通过各种边界情况和异常情况的测试，确保样式引擎在不同场景下的稳定性，避免崩溃。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 HTML, CSS，并且在很多测试场景中，通过 JavaScript 操作 DOM 来触发样式引擎的行为。

* **HTML:** 测试用例会创建各种 HTML 结构，作为样式应用的上下文。
    * **例子:** `<div id="test"></div>` - 创建一个简单的 div 元素作为测试目标。
* **CSS:** 测试用例会定义 CSS 规则，验证样式引擎是否正确解析和应用这些规则。
    * **例子:** `<style>.test { color: red; }</style>` - 定义一个 CSS 规则，将 class 为 "test" 的元素的颜色设置为红色。
* **JavaScript:** 测试用例会使用 Blink 提供的 API（类似于 JavaScript DOM API）来操作 HTML 结构和元素的样式，从而触发样式引擎的工作。
    * **例子:** `GetDocument().QuerySelector(AtomicString("#test"))->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor, "blue");` -  使用类似 JavaScript 的方式选择 id 为 "test" 的元素，并设置其内联背景色为蓝色。

**逻辑推理、假设输入与输出:**

* **假设输入:**  一段包含 CSS 规则和 HTML 结构的代码片段。例如：
  ```html
  <style>
    .container div { color: green; }
    #target { color: blue; }
  </style>
  <div class="container">
    <div id="target">Hello</div>
  </div>
  ```
* **逻辑推理:** 样式引擎会根据 CSS 规则的优先级和特异性来计算 `#target` 元素的最终颜色。由于 `#target` 选择器比 `.container div` 更具体，所以 `#target` 元素的颜色应该是蓝色。
* **预期输出:** 测试会断言 `#target` 元素的 computed style 的 color 属性值为蓝色。

**用户或编程常见的使用错误及举例说明:**

这个测试文件可以帮助发现和防止一些用户或开发者在使用 HTML 和 CSS 时可能犯的错误：

1. **CSS 选择器错误:** 例如，使用了不存在的 class 或 id，导致样式没有应用。测试用例会验证各种选择器的正确性。
    * **例子:** 如果 CSS 中定义了 `.nonexistent { color: red; }`，但 HTML 中没有使用这个 class，测试会确保样式不会被应用。
2. **CSS 属性值错误:** 例如，使用了无效的属性值，导致样式被忽略。
    * **例子:**  如果设置了 `style="color: bluuue;"`（拼写错误），测试会验证样式是否被正确处理（通常会被忽略或使用默认值）。
3. **CSS 优先级问题:** 开发者可能不清楚 CSS 规则的优先级，导致样式被意外覆盖。
    * **例子:** 测试用例会创建多个规则作用于同一个元素，并验证最终应用的样式是否符合优先级规则。
4. **DOM 操作导致的样式失效问题:**  在 JavaScript 中操作 DOM 后，样式可能需要重新计算。测试验证样式引擎是否能正确处理这些失效情况。
    * **例子:**  JavaScript 动态添加一个带有特定 class 的元素，测试会验证相应的 CSS 规则是否被应用。

**用户操作到达这里的步骤 (调试线索):**

作为一个最终用户，通常不会直接“到达”这个测试文件。这个文件是 Blink 引擎的内部测试代码。但是，用户在浏览器中的操作会触发样式引擎的工作，而这些测试就是在验证这些工作是否正确。以下是一些可能关联的用户操作和调试线索：

1. **加载网页:** 当用户打开一个网页时，Blink 的渲染引擎会解析 HTML 和 CSS，样式引擎会负责计算元素的样式。如果页面显示异常，开发者可能会检查样式引擎的日志或进行断点调试。
2. **与网页交互:** 用户在网页上的交互（例如，鼠标悬停、点击、滚动）可能会触发 JavaScript 代码，这些代码可能会修改 DOM 或元素的样式，导致样式引擎重新计算样式。
3. **开发者工具检查:** 开发者可以使用浏览器开发者工具的 "Elements" 面板来检查元素的 computed style。如果发现样式不符合预期，他们可能会怀疑是样式引擎的问题，并可能需要查看相关的测试用例来理解样式引擎的行为。
4. **性能问题排查:** 如果网页渲染性能有问题，例如页面卡顿，开发者可能会分析样式计算是否是瓶颈，并查看样式引擎的内部机制。

**归纳一下它的功能 (第4部分):**

总而言之，`style_engine_test.cc` 这个文件是 Blink 引擎中至关重要的组成部分，它通过大量的单元测试用例，全面地验证了样式引擎的各项核心功能。这些测试覆盖了 CSS 规则的解析和应用、样式计算、级联继承、伪类伪元素、Shadow DOM 以及各种特定 CSS 特性。它的存在确保了 Blink 引擎能够正确、高效地渲染网页样式，为用户提供一致且符合预期的浏览体验。 这些测试也帮助开发者理解样式引擎的行为，并有助于发现和预防在使用 HTML 和 CSS 时可能出现的错误。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
).QuerySelector(AtomicString("div"));
  ASSERT_TRUE(div);
  div->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // Should fast reject ".not-in-filter div::before {}" for both the div and its
  // ::before pseudo element.
  EXPECT_EQ(2u, stats->rules_fast_rejected);
}

TEST_F(StyleEngineTest, FirstLetterRemoved) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.fl::first-letter { color: pink }</style>
    <div class=fl id=d1><div><span id=f1>A</span></div></div>
    <div class=fl id=d2><div><span id=f2>BB</span></div></div>
    <div class=fl id=d3><div><span id=f3>C<!---->C</span></div></div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* d1 = GetDocument().getElementById(AtomicString("d1"));
  Element* d2 = GetDocument().getElementById(AtomicString("d2"));
  Element* d3 = GetDocument().getElementById(AtomicString("d3"));

  FirstLetterPseudoElement* fl1 =
      To<FirstLetterPseudoElement>(d1->GetPseudoElement(kPseudoIdFirstLetter));
  EXPECT_TRUE(fl1);

  GetDocument().getElementById(AtomicString("f1"))->firstChild()->remove();

  EXPECT_FALSE(d1->firstChild()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(d1->firstChild()->ChildNeedsReattachLayoutTree());
  EXPECT_FALSE(d1->firstChild()->NeedsReattachLayoutTree());
  EXPECT_TRUE(d1->ChildNeedsStyleRecalc());
  EXPECT_TRUE(fl1->NeedsStyleRecalc());

  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      To<FirstLetterPseudoElement>(d1->GetPseudoElement(kPseudoIdFirstLetter)));

  FirstLetterPseudoElement* fl2 =
      To<FirstLetterPseudoElement>(d2->GetPseudoElement(kPseudoIdFirstLetter));
  EXPECT_TRUE(fl2);

  GetDocument().getElementById(AtomicString("f2"))->firstChild()->remove();

  EXPECT_FALSE(d2->firstChild()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(d2->firstChild()->ChildNeedsReattachLayoutTree());
  EXPECT_FALSE(d2->firstChild()->NeedsReattachLayoutTree());
  EXPECT_TRUE(d2->ChildNeedsStyleRecalc());
  EXPECT_TRUE(fl2->NeedsStyleRecalc());

  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      To<FirstLetterPseudoElement>(d2->GetPseudoElement(kPseudoIdFirstLetter)));

  FirstLetterPseudoElement* fl3 =
      To<FirstLetterPseudoElement>(d3->GetPseudoElement(kPseudoIdFirstLetter));
  EXPECT_TRUE(fl3);

  Element* f3 = GetDocument().getElementById(AtomicString("f3"));
  f3->firstChild()->remove();

  EXPECT_TRUE(d3->firstChild()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(d3->firstChild()->ChildNeedsReattachLayoutTree());
  EXPECT_FALSE(d3->firstChild()->NeedsReattachLayoutTree());
  EXPECT_TRUE(d3->ChildNeedsStyleRecalc());
  EXPECT_TRUE(fl3->NeedsStyleRecalc());

  UpdateAllLifecyclePhases();
  fl3 =
      To<FirstLetterPseudoElement>(d3->GetPseudoElement(kPseudoIdFirstLetter));
  EXPECT_TRUE(fl3);
  EXPECT_EQ(f3->lastChild()->GetLayoutObject(),
            fl3->RemainingTextLayoutObject());
}

TEST_F(StyleEngineTest, InitialDataCreation) {
  UpdateAllLifecyclePhases();

  // There should be no initial data if nothing is registered.
  EXPECT_FALSE(GetStyleEngine().MaybeCreateAndGetInitialData());

  // After registering, there should be initial data.
  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "10px",
                                     false);
  auto* data1 = GetStyleEngine().MaybeCreateAndGetInitialData();
  EXPECT_TRUE(data1);

  // After a full recalc, we should have the same initial data.
  GetDocument().body()->setInnerHTML("<style>* { font-size: 1px; } </style>");
  EXPECT_TRUE(GetDocument().documentElement()->NeedsStyleRecalc());
  EXPECT_TRUE(GetDocument().documentElement()->ChildNeedsStyleRecalc());
  UpdateAllLifecyclePhases();
  auto* data2 = GetStyleEngine().MaybeCreateAndGetInitialData();
  EXPECT_TRUE(data2);
  EXPECT_EQ(data1, data2);

  // After registering a new property, initial data should be invalidated,
  // such that the new initial data is different.
  css_test_helpers::RegisterProperty(GetDocument(), "--y", "<color>", "black",
                                     false);
  EXPECT_NE(data1, GetStyleEngine().MaybeCreateAndGetInitialData());
}

TEST_F(StyleEngineTest, CSSSelectorEmptyWhitespaceOnlyFail) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>.match:empty { background-color: red }</style>
    <div></div>
    <div> <span></span></div>
    <div> <!-- -->X</div>
    <div></div>
    <div> <!-- --></div>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSSelectorEmptyWhitespaceOnlyFail));

  auto* div_elements = GetDocument().getElementsByTagName(AtomicString("div"));
  ASSERT_TRUE(div_elements);
  ASSERT_EQ(5u, div_elements->length());

  auto is_counted = [](Element* element) {
    element->setAttribute(blink::html_names::kClassAttr, AtomicString("match"));
    element->GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    return element->GetDocument().IsUseCounted(
        WebFeature::kCSSSelectorEmptyWhitespaceOnlyFail);
  };

  EXPECT_FALSE(is_counted(div_elements->item(0)));
  EXPECT_FALSE(is_counted(div_elements->item(1)));
  EXPECT_FALSE(is_counted(div_elements->item(2)));
  EXPECT_FALSE(is_counted(div_elements->item(3)));
  EXPECT_TRUE(is_counted(div_elements->item(4)));
}

TEST_F(StyleEngineTest, EnsuredComputedStyleRecalc) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div style="display:none">
      <div>
        <div id="computed">
          <span id="span"><span>XXX</span></span>
        </div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* computed = GetDocument().getElementById(AtomicString("computed"));
  Element* span_outer = GetDocument().getElementById(AtomicString("span"));
  Element* span_inner = span_outer->firstElementChild();

  // Initially all null in display:none subtree.
  EXPECT_FALSE(computed->GetComputedStyle());
  EXPECT_FALSE(span_outer->GetComputedStyle());
  EXPECT_FALSE(span_inner->GetComputedStyle());

  // Force computed style down to #computed.
  computed->EnsureComputedStyle();
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(computed->GetComputedStyle());
  EXPECT_FALSE(span_outer->GetComputedStyle());
  EXPECT_FALSE(span_inner->GetComputedStyle());

  // Setting span color should not create ComputedStyles during style recalc.
  span_outer->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");
  EXPECT_TRUE(span_outer->NeedsStyleRecalc());
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kStyleClean);

  EXPECT_FALSE(span_outer->NeedsStyleRecalc());
  EXPECT_FALSE(span_outer->GetComputedStyle());
  EXPECT_FALSE(span_inner->GetComputedStyle());
  // #computed still non-null because #span_outer is the recalc root.
  EXPECT_TRUE(computed->GetComputedStyle());

  // Triggering style recalc which propagates the color down the tree should
  // clear ComputedStyle objects in the display:none subtree.
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kColor, "pink");
  UpdateAllLifecyclePhases();

  EXPECT_FALSE(computed->GetComputedStyle());
  EXPECT_FALSE(span_outer->GetComputedStyle());
  EXPECT_FALSE(span_inner->GetComputedStyle());
}

TEST_F(StyleEngineTest, EnsureCustomComputedStyle) {
  GetDocument().body()->setInnerHTML("");
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=div>
      <progress id=progress>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  // Note: <progress> is chosen because it creates ProgressShadowElement
  // instances, which override CustomStyleForLayoutObject with
  // display:none.
  Element* div = GetDocument().getElementById(AtomicString("div"));
  Element* progress = GetDocument().getElementById(AtomicString("progress"));
  ASSERT_TRUE(div);
  ASSERT_TRUE(progress);

  // This causes ProgressShadowElements to get ComputedStyles with
  // IsEnsuredInDisplayNone==true.
  for (Node* node = progress; node;
       node = FlatTreeTraversal::Next(*node, progress)) {
    if (Element* element = DynamicTo<Element>(node)) {
      element->EnsureComputedStyle();
    }
  }

  // This triggers layout tree building.
  div->SetInlineStyleProperty(CSSPropertyID::kDisplay, "inline");
  UpdateAllLifecyclePhases();

  // We must not create LayoutObjects for Nodes with
  // IsEnsuredInDisplayNone==true
  for (Node* node = progress; node;
       node = FlatTreeTraversal::Next(*node, progress)) {
    if (auto* element = DynamicTo<Element>(node)) {
      ASSERT_TRUE(!element->GetComputedStyle() ||
                  !element->ComputedStyleRef().IsEnsuredInDisplayNone() ||
                  !element->GetLayoutObject());
    }
  }
}

// Via HTMLFormControlElement, it's possible to enter
// Node::MarkAncestorsWithChildNeedsStyleRecalc for nodes which have
// isConnected==true, but an ancestor with isConnected==false. This is because
// we mark the ancestor chain for style recalc via HTMLFormElement::
// InvalidateDefaultButtonStyle while the subtree disconnection
// is taking place.
TEST_F(StyleEngineTest, NoCrashWhenMarkingPartiallyRemovedSubtree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #foo:default {} /* Needed to enter Element::PseudoStateChanged */
    </style>
    <form id="form">
      <div id="outer">
        <button>
        <div id="inner"></div>
      </div>
    </form>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* form = GetDocument().getElementById(AtomicString("form"));
  Element* outer = GetDocument().getElementById(AtomicString("outer"));
  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  ASSERT_TRUE(form);
  ASSERT_TRUE(outer);
  ASSERT_TRUE(inner);

  // Add some more buttons, to give InvalidateDefaultButtonStyle
  // something to do when the original <button> is removed.
  inner->setInnerHTML("<button><button>");
  UpdateAllLifecyclePhases();

  form->removeChild(outer);
}

TEST_F(StyleEngineTest, ColorSchemeBaseBackgroundChange) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhases();

  EXPECT_EQ(Color::kWhite, GetDocument().View()->BaseBackgroundColor());

  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kColorScheme, "dark");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(Color(0x12, 0x12, 0x12),
            GetDocument().View()->BaseBackgroundColor());

  color_scheme_helper.SetInForcedColors(GetDocument(),
                                        /*in_forced_colors=*/true);
  UpdateAllLifecyclePhases();
  mojom::blink::ColorScheme color_scheme = mojom::blink::ColorScheme::kLight;
  Color system_background_color = LayoutTheme::GetTheme().SystemColor(
      CSSValueID::kCanvas, color_scheme,
      GetDocument().GetColorProviderForPainting(color_scheme),
      GetDocument().IsInWebAppScope());

  EXPECT_EQ(system_background_color,
            GetDocument().View()->BaseBackgroundColor());
}

TEST_F(StyleEngineTest, ColorSchemeOverride) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);

  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kColorScheme, "light dark");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(
      mojom::blink::ColorScheme::kLight,
      GetDocument().documentElement()->GetComputedStyle()->UsedColorScheme());

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(
      mojom::blink::ColorScheme::kDark,
      GetDocument().documentElement()->GetComputedStyle()->UsedColorScheme());

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  UpdateAllLifecyclePhases();

  EXPECT_EQ(
      mojom::blink::ColorScheme::kLight,
      GetDocument().documentElement()->GetComputedStyle()->UsedColorScheme());

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(
      mojom::blink::ColorScheme::kDark,
      GetDocument().documentElement()->GetComputedStyle()->UsedColorScheme());

  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();

  EXPECT_EQ(
      mojom::blink::ColorScheme::kLight,
      GetDocument().documentElement()->GetComputedStyle()->UsedColorScheme());

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "light");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(
      mojom::blink::ColorScheme::kDark,
      GetDocument().documentElement()->GetComputedStyle()->UsedColorScheme());
}

TEST_F(StyleEngineTest, PseudoElementBaseComputedStyle) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @keyframes anim {
        from { background-color: white }
        to { background-color: blue }
      }
      #anim::before {
        content:"";
        animation: anim 1s;
      }
    </style>
    <div id="anim"></div>
  )HTML");

  UpdateAllLifecyclePhases();

  auto* anim_element = GetDocument().getElementById(AtomicString("anim"));
  auto* before = anim_element->GetPseudoElement(kPseudoIdBefore);
  auto* animations = before->GetElementAnimations();

  ASSERT_TRUE(animations);

  before->SetNeedsAnimationStyleRecalc();
  UpdateAllLifecyclePhases();

  ASSERT_TRUE(before->GetComputedStyle());
  const ComputedStyle* base_computed_style =
      before->GetComputedStyle()->GetBaseComputedStyle();
  EXPECT_TRUE(base_computed_style);

  before->SetNeedsAnimationStyleRecalc();
  UpdateAllLifecyclePhases();

  ASSERT_TRUE(before->GetComputedStyle());
  EXPECT_TRUE(before->GetComputedStyle()->GetBaseComputedStyle());
#if !DCHECK_IS_ON()
  // When DCHECK is enabled, ShouldComputeBaseComputedStyle always returns true
  // and we repeatedly create new instances which means the pointers will be
  // different here.
  EXPECT_EQ(base_computed_style,
            before->GetComputedStyle()->GetBaseComputedStyle());
#endif
}

TEST_F(StyleEngineTest, NeedsLayoutTreeRebuild) {
  UpdateAllLifecyclePhases();

  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_FALSE(GetStyleEngine().NeedsLayoutTreeRebuild());

  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kDisplay, "none");

  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetDocument().GetStyleEngine().RecalcStyle();

  EXPECT_TRUE(GetStyleEngine().NeedsLayoutTreeRebuild());
}

TEST_F(StyleEngineTest, ForceReattachLayoutTreeStyleRecalcRoot) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="outer">
      <div id="inner"></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* outer = GetDocument().getElementById(AtomicString("outer"));
  Element* inner = GetDocument().getElementById(AtomicString("inner"));

  outer->SetForceReattachLayoutTree();
  inner->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");

  EXPECT_EQ(outer, GetStyleRecalcRoot());
}

TEST_F(StyleEngineTest, ForceReattachNoStyleForElement) {
  GetDocument().body()->setInnerHTML(R"HTML(<div id="reattach"></div>)HTML");

  auto* reattach = GetDocument().getElementById(AtomicString("reattach"));

  UpdateAllLifecyclePhases();

  unsigned initial_count = GetStyleEngine().StyleForElementCount();

  reattach->SetForceReattachLayoutTree();
  EXPECT_EQ(reattach, GetStyleRecalcRoot());

  UpdateAllLifecyclePhases();
  EXPECT_EQ(GetStyleEngine().StyleForElementCount(), initial_count);
}

TEST_F(StyleEngineTest, RecalcPropagatedWritingMode) {
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kWritingMode,
                                               "vertical-lr");

  UpdateAllLifecyclePhases();

  // Make sure that recalculating style for the root element does not trigger a
  // visual diff that requires layout. That is, we take the body -> root
  // propagation of writing-mode into account before setting ComputedStyle on
  // the root LayoutObject.
  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kWritingMode, "horizontal-tb");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetDocument().GetStyleEngine().RecalcStyle();

  EXPECT_FALSE(GetStyleEngine().NeedsLayoutTreeRebuild());
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());
}

TEST_F(StyleEngineTest, GetComputedStyleOutsideFlatTree) {
  GetDocument().body()->setInnerHTML(
      R"HTML(<div id="host"><div id="outer"><div id="inner"><div id="innermost"></div></div></div></div>)HTML");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* outer = GetDocument().getElementById(AtomicString("outer"));
  auto* inner = GetDocument().getElementById(AtomicString("inner"));
  auto* innermost = GetDocument().getElementById(AtomicString("innermost"));

  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhases();

  EXPECT_TRUE(host->GetComputedStyle());
  // ComputedStyle is not generated outside the flat tree.
  EXPECT_FALSE(outer->GetComputedStyle());
  EXPECT_FALSE(inner->GetComputedStyle());
  EXPECT_FALSE(innermost->GetComputedStyle());

  inner->EnsureComputedStyle();
  const ComputedStyle* outer_style = outer->GetComputedStyle();
  const ComputedStyle* inner_style = inner->GetComputedStyle();

  ASSERT_TRUE(outer_style);
  ASSERT_TRUE(inner_style);
  EXPECT_FALSE(innermost->GetComputedStyle());
  EXPECT_TRUE(outer_style->IsEnsuredOutsideFlatTree());
  EXPECT_TRUE(inner_style->IsEnsuredOutsideFlatTree());
  EXPECT_EQ(Color::kTransparent, inner_style->VisitedDependentColor(
                                     GetCSSPropertyBackgroundColor()));

  inner->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor, "green");
  UpdateAllLifecyclePhases();

  // Old ensured style is not cleared before we re-ensure it.
  EXPECT_TRUE(inner->NeedsStyleRecalc());
  EXPECT_EQ(inner_style, inner->GetComputedStyle());

  inner->EnsureComputedStyle();

  // Outer style was not dirty - we still have the same ComputedStyle object.
  EXPECT_EQ(outer_style, outer->GetComputedStyle());
  EXPECT_NE(inner_style, inner->GetComputedStyle());

  inner_style = inner->GetComputedStyle();
  EXPECT_EQ(Color(0, 128, 0), inner_style->VisitedDependentColor(
                                  GetCSSPropertyBackgroundColor()));

  // Making outer dirty will require that we clear ComputedStyles all the way up
  // ensuring the style for innermost later because of inheritance.
  outer->SetInlineStyleProperty(CSSPropertyID::kColor, "green");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(outer_style, outer->GetComputedStyle());
  EXPECT_EQ(inner_style, inner->GetComputedStyle());
  EXPECT_FALSE(innermost->GetComputedStyle());

  auto* innermost_style = innermost->EnsureComputedStyle();

  EXPECT_NE(outer_style, outer->GetComputedStyle());
  EXPECT_NE(inner_style, inner->GetComputedStyle());
  ASSERT_TRUE(innermost_style);
  EXPECT_EQ(Color(0, 128, 0),
            innermost_style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MoveSlottedOutsideFlatTree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="parent">
      <div id="host1"><span style="display:contents"></span></div>
      <div id="host2"></div>
    </div>
  )HTML");

  auto* host1 = GetDocument().getElementById(AtomicString("host1"));
  auto* host2 = GetDocument().getElementById(AtomicString("host2"));
  auto* span = host1->firstChild();

  ShadowRoot& shadow_root =
      host1->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<slot></slot>");
  host2->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  UpdateAllLifecyclePhases();

  host2->appendChild(span);
  EXPECT_FALSE(GetStyleRecalcRoot());

  span->remove();
  EXPECT_FALSE(GetStyleRecalcRoot());
}

TEST_F(StyleEngineTest, StyleRecalcRootInShadowTree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="host"></div>
  )HTML");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div><span></span></div>");
  UpdateAllLifecyclePhases();

  Element* span = To<Element>(shadow_root.firstChild()->firstChild());
  // Mark style dirty.
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");

  EXPECT_EQ(span, GetStyleRecalcRoot());
}

TEST_F(StyleEngineTest, StyleRecalcRootOutsideFlatTree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="host"><div id="ensured"><span></span></div></div>
    <div id="dirty"></div>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* dirty = GetDocument().getElementById(AtomicString("dirty"));
  auto* ensured = GetDocument().getElementById(AtomicString("ensured"));
  auto* span = To<Element>(ensured->firstChild());

  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  UpdateAllLifecyclePhases();

  dirty->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");
  EXPECT_EQ(dirty, GetStyleRecalcRoot());

  // Ensure a computed style for the span parent to try to trick us into
  // incorrectly using the span as a recalc root.
  ensured->EnsureComputedStyle();
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "pink");

  // <span> is outside the flat tree, so it should not affect the style recalc
  // root.
  EXPECT_EQ(dirty, GetStyleRecalcRoot());

  // Should not trigger any DCHECK failures.
  UpdateAllLifecyclePhases();
}

TEST_F(StyleEngineTest, RemoveStyleRecalcRootFromFlatTree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=host><span style="display:contents"></span></div>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* span = To<Element>(host->firstChild());

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div><slot></slot></div>");

  UpdateAllLifecyclePhases();

  // Make the span style dirty.
  span->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));

  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_EQ(span, GetStyleRecalcRoot());

  auto* div = shadow_root.firstChild();
  auto* slot = To<Element>(div->firstChild());

  slot->setAttribute(html_names::kNameAttr, AtomicString("x"));
  GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();

  // Make sure shadow tree div and slot have their ChildNeedsStyleRecalc()
  // cleared.
  EXPECT_FALSE(div->ChildNeedsStyleRecalc());
  EXPECT_FALSE(slot->ChildNeedsStyleRecalc());
  EXPECT_FALSE(span->NeedsStyleRecalc());
  EXPECT_FALSE(GetStyleRecalcRoot());
}

TEST_F(StyleEngineTest, SlottedWithEnsuredStyleOutsideFlatTree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="host"><span></span></div>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* span = To<Element>(host->firstChild());

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
    <div><slot name="default"></slot></div>
  )HTML");

  UpdateAllLifecyclePhases();

  // Ensure style outside the flat tree.
  const ComputedStyle* style = span->EnsureComputedStyle();
  ASSERT_TRUE(style);
  EXPECT_TRUE(style->IsEnsuredOutsideFlatTree());

  span->setAttribute(html_names::kSlotAttr, AtomicString("default"));
  GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();
  EXPECT_EQ(span, GetStyleRecalcRoot());
  EXPECT_FALSE(span->GetComputedStyle());
}

TEST_F(StyleEngineTest, ForceReattachRecalcRootAttachShadow) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="reattach"></div>
    <div id="host"><span style="display:contents"></span></div>
  )HTML");

  auto* reattach = GetDocument().getElementById(AtomicString("reattach"));
  auto* host = GetDocument().getElementById(AtomicString("host"));

  UpdateAllLifecyclePhases();

  reattach->SetForceReattachLayoutTree();
  EXPECT_FALSE(reattach->NeedsStyleRecalc());
  EXPECT_EQ(reattach, GetStyleRecalcRoot());

  // Attaching the shadow root will call FlatTreePositionChanged() on the span
  // child of the host. The style recalc root should still be #reattach.
  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  EXPECT_EQ(reattach, GetStyleRecalcRoot());
}

TEST_F(StyleEngineTest, InitialColorChange) {
  // Set color scheme to light.
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :root { color-scheme: light dark }
      #initial { color: initial }
    </style>
    <div id="initial"></div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* initial = GetDocument().getElementById(AtomicString("initial"));
  ASSERT_TRUE(initial);
  ASSERT_TRUE(GetDocument().documentElement());
  const ComputedStyle* document_element_style =
      GetDocument().documentElement()->GetComputedStyle();
  ASSERT_TRUE(document_element_style);
  EXPECT_EQ(Color::kBlack, document_element_style->VisitedDependentColor(
                               GetCSSPropertyColor()));

  const ComputedStyle* initial_style = initial->GetComputedStyle();
  ASSERT_TRUE(initial_style);
  EXPECT_EQ(Color::kBlack,
            initial_style->VisitedDependentColor(GetCSSPropertyColor()));

  // Change color scheme to dark.
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhases();

  document_element_style = GetDocument().documentElement()->GetComputedStyle();
  ASSERT_TRUE(document_element_style);
  EXPECT_EQ(Color::kWhite, document_element_style->VisitedDependentColor(
                               GetCSSPropertyColor()));

  initial_style = initial->GetComputedStyle();
  ASSERT_TRUE(initial_style);
  EXPECT_EQ(Color::kWhite,
            initial_style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_InvalidateForChangedSizeQueries) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (min-width: 1000px) {
        div { color: green }
      }
    </style>
    <style>
      @media (min-width: 1200px) {
        * { color: red }
      }
    </style>
    <style>
      @media print {
        * { color: blue }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* div = GetDocument().getElementById(AtomicString("green"));
  EXPECT_EQ(Color::kBlack, div->GetComputedStyle()->VisitedDependentColor(
                               GetCSSPropertyColor()));

  unsigned initial_count = GetStyleEngine().StyleForElementCount();

  GetDocument().View()->SetLayoutSizeFixedToFrameSize(false);
  GetDocument().View()->SetLayoutSize(gfx::Size(1100, 800));
  UpdateAllLifecyclePhases();

  // Only the single div element should have its style recomputed.
  EXPECT_EQ(1u, GetStyleEngine().StyleForElementCount() - initial_count);
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      div->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_InvalidateForChangedTypeQuery) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media speech {
        div { color: green }
      }
    </style>
    <style>
      @media (max-width: 100px) {
        * { color: red }
      }
    </style>
    <style>
      @media print {
        * { color: blue }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* div = GetDocument().getElementById(AtomicString("green"));
  EXPECT_EQ(Color::kBlack, div->GetComputedStyle()->VisitedDependentColor(
                               GetCSSPropertyColor()));

  unsigned initial_count = GetStyleEngine().StyleForElementCount();

  GetDocument().GetSettings()->SetMediaTypeOverride("speech");
  UpdateAllLifecyclePhases();

  // Only the single div element should have its style recomputed.
  EXPECT_EQ(1u, GetStyleEngine().StyleForElementCount() - initial_count);
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      div->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_InvalidateForChangedReducedMotionQuery) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (prefers-reduced-motion: reduce) {
        div { color: green }
      }
    </style>
    <style>
      @media (max-width: 100px) {
        * { color: red }
      }
    </style>
    <style>
      @media print {
        * { color: blue }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* div = GetDocument().getElementById(AtomicString("green"));
  EXPECT_EQ(Color::kBlack, div->GetComputedStyle()->VisitedDependentColor(
                               GetCSSPropertyColor()));

  unsigned initial_count = GetStyleEngine().StyleForElementCount();

  GetDocument().GetSettings()->SetPrefersReducedMotion(true);
  UpdateAllLifecyclePhases();

  // Only the single div element should have its style recomputed.
  EXPECT_EQ(1u, GetStyleEngine().StyleForElementCount() - initial_count);
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      div->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, RevertUseCount) {
  GetDocument().body()->setInnerHTML(
      "<style>div { display: unset; }</style><div></div>");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSKeywordRevert));

  GetDocument().body()->setInnerHTML(
      "<style>div { display: revert; }</style><div></div>");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSKeywordRevert));
}

TEST_F(StyleEngineTest, RevertUseCountForCustomProperties) {
  GetDocument().body()->setInnerHTML(
      "<style>div { --x: unset; }</style><div></div>");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSKeywordRevert));

  GetDocument().body()->setInnerHTML(
      "<style>div { --x: revert; }</style><div></div>");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSKeywordRevert));
}

TEST_F(StyleEngineTest, NoRevertUseCountForForcedColors) {
  ScopedForcedColorsForTest scoped_feature(true);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #elem { color: red; }
    </style>
    <div id=ref></div>
    <div id=elem></div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* ref = GetDocument().getElementById(AtomicString("ref"));
  Element* elem = GetDocument().getElementById(AtomicString("elem"));
  ASSERT_TRUE(ref);
  ASSERT_TRUE(elem);

  // This test assumes that the initial color is not 'red'. Verify that
  // assumption.
  ASSERT_NE(ComputedValue(ref, "color")->CssText(),
            ComputedValue(elem, "color")->CssText());

  EXPECT_EQ("rgb(255, 0, 0)", ComputedValue(elem, "color")->CssText());

  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetInForcedColors(GetDocument(),
                                        /*in_forced_colors=*/true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(ComputedValue(ref, "color")->CssText(),
            ComputedValue(elem, "color")->CssText());

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSKeywordRevert));
}

TEST_F(StyleEngineTest, PrintNoDarkColorScheme) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :root { color-scheme: light dark }
      @media (prefers-color-scheme: light) {
        body { color: green; }
      }
      @media (prefers-color-scheme: dark) {
        body { color: red; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  Element* body = GetDocument().body();
  Element* root = GetDocument().documentElement();

  EXPECT_EQ(Color::kWhite, root->GetComputedStyle()->VisitedDependentColor(
                               GetCSSPropertyColor()));
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            root->GetComputedStyle()->UsedColorScheme());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
```