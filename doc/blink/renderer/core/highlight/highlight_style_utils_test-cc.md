Response:
The user wants to understand the functionality of the C++ source code file `highlight_style_utils_test.cc`. I need to analyze the code and identify its purpose, focusing on how it tests the `HighlightStyleUtils` class. Specifically, I should look for:

1. **Core Functionality:** What aspects of highlight styling are being tested?
2. **Relationship to Web Technologies:** How does the tested code relate to JavaScript, HTML, and CSS? Provide concrete examples from the test cases.
3. **Logic and Assumptions:**  Identify any logical reasoning within the tests and state the assumed inputs and expected outputs.
4. **Potential User/Programming Errors:**  Look for tests that might reveal common mistakes users or developers could make when working with highlights.

**Detailed Analysis Plan:**

* **Identify Test Fixture:** The code defines `HighlightStyleUtilsTest` which inherits from `SimTest`. This suggests it's a unit test environment simulating a browser.
* **Analyze Individual Test Cases:** Go through each `TEST_F` and determine its objective.
* **Connect to Web Technologies:** For each test, identify the relevant HTML structure, CSS rules, and potentially JavaScript used to set up the test conditions. Explain how these relate to the tested functionality.
* **Infer Logic and Assumptions:**  For example, a test checking if a CSS `color` property is applied correctly to a selection implies an input HTML with that CSS and an expected output color.
* **Spot Potential Errors:** Consider scenarios where a developer might incorrectly apply CSS styles to highlights or misunderstand how inheritance works. The tests themselves often implicitly reveal these possibilities by testing specific edge cases or inheritance rules.
这个文件 `highlight_style_utils_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要功能是**测试 `HighlightStyleUtils` 类中的各种功能**，这个类主要负责处理与网页元素高亮显示相关的样式计算和应用。

以下是该文件测试功能的详细列举，以及与 JavaScript, HTML, CSS 的关系和使用错误的说明：

**核心功能测试：**

1. **测试文本选择 (::selection) 样式的应用:**
   -  `SelectedTextInputShadow`: 测试当 input 元素的 `::selection` 伪类设置了 `color` 和 `text-shadow` 属性时，这些样式是否正确应用到 input 元素内部用于显示 value 的文本节点上。
   -  `SelectedTextIsRespected`: 测试浏览器是否尊重开发者在 `::selection` 伪类中定义的 `background-color` 和 `color` 属性。它会测试不同的场景，包括显式设置颜色、前景色与默认背景色相同的情况，以及没有设置选择伪类颜色的情况。

2. **测试自定义高亮 (::highlight()) 样式的应用:**
   -  `CurrentColorReportingAll`: 测试当自定义高亮伪类 (`::highlight(highlight1)`) 和 `::selection` 伪类都设置了 `text-decoration-line: underline` 时，`HighlightPaintingStyle` 函数是否正确报告哪些属性使用了 `currentcolor`。这涉及到颜色属性的继承和默认值。
   -  `CurrentColorReportingSome`: 测试当自定义高亮伪类显式设置了 `text-decoration-line`, `text-decoration-color`, `-webkit-text-fill-color` 等属性时，`HighlightPaintingStyle` 函数是否正确报告哪些属性使用了 `currentcolor`。
   -  `CustomPropertyInheritance`: 测试自定义属性在选择高亮中的继承行为。验证定义在 `:root` 上的自定义属性能否被 `div::selection` 继承，并且在 `::selection` 内部定义的自定义属性不会影响外部。
   -  `CustomPropertyOriginatingInheritanceUniversal`:  测试自定义属性在整个文档中从定义它的元素向子元素高亮的继承行为。它模拟了在不同层级的元素上定义了同名的自定义属性，并验证高亮显示时是否使用了正确的值。
   -  `FontMetricsFromOriginatingElement`: 测试当自定义高亮伪类使用了依赖于字体大小的单位 (如 `em`) 时，计算出的长度值是否基于定义该高亮样式的元素的字体大小。
   -  `CustomHighlightsNotOverlapping`:  虽然名字上不是直接的样式测试，但它测试了自定义高亮范围的管理，确保当多个自定义高亮范围重叠时，DocumentMarkerController 能正确地创建和管理这些标记，这间接关系到样式的应用，因为不同的高亮会应用不同的样式。
   -  `ContainerMetricsFromOriginatingElement`: 测试当自定义高亮样式规则包含容器查询单位（如 `cqw`, `cqh`）时，计算出的长度值是否基于定义该高亮样式的容器元素的大小。
   -  `ContainerIsOriginatingElement`: 测试当容器查询条件直接应用在设置自定义高亮样式的元素上时，容器查询单位是否能正确计算。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件与 Web 技术栈紧密相关，因为它测试的是浏览器引擎如何处理与高亮显示相关的 CSS 样式。

* **HTML:** 测试用例中会创建 HTML 结构来模拟不同的网页场景。例如，会创建 `<input>` 元素测试输入框的选择样式，创建 `<div>` 元素测试普通的文本选择和自定义高亮。
   ```html
   <input type="text" value="Selected">
   <div id="div1">Green text selection color and background</div>
   ```
* **CSS:**  测试的核心是 CSS 样式规则的处理，特别是 `::selection` 和 `::highlight()` 伪类。测试会定义各种 CSS 规则，例如设置颜色、背景色、文本阴影、文本装饰线等，来验证 `HighlightStyleUtils` 是否能正确解析和应用这些样式。
   ```css
   input::selection {
     color: green;
     text-shadow: 2px 2px;
   }
   ::highlight(highlight1) {
     text-decoration-line: underline;
   }
   ```
* **JavaScript:**  JavaScript 通常用于动态地创建和管理高亮范围。测试用例中会使用 JavaScript 的 `Selection` API 来模拟用户选择文本，或者使用 `CSS.highlights.set()` API 来创建自定义高亮。
   ```javascript
   window.getSelection()->setBaseAndExtent(div_node, 0, div_node, 1);
   CSS.highlights.set("highlight1", new Highlight(r1));
   ```

**逻辑推理和假设输入与输出：**

以 `SelectedTextInputShadow` 测试为例：

* **假设输入 (HTML/CSS):**
  ```html
  <!doctype html>
  <style>
    input::selection {
      color: green;
      text-shadow: 2px 2px;
    }
  </style>
  <input type="text" value="Selected">
  ```
* **逻辑推理:**  当 input 元素中的文本被选中时，应该应用 `input::selection` 中定义的样式。这意味着文本的颜色应该变成绿色，并且应该有文本阴影。
* **预期输出 (C++ 断言):**
  ```c++
  EXPECT_EQ(Color(0, 128, 0), paint_style.fill_color); // 绿色 (R=0, G=128, B=0)
  EXPECT_TRUE(paint_style.shadow); // 存在阴影
  ```

**用户或编程常见的使用错误举例：**

1. **错误地假设自定义高亮样式会像普通样式一样继承:**  `CustomPropertyInheritance` 测试就展示了 `::selection` 内部定义的自定义属性不会影响外部，这可以防止开发者错误地认为在选择器伪类中定义的变量会泄漏到其他地方。

2. **忘记考虑高亮样式特异性:**  如果开发者定义了与浏览器默认高亮样式冲突的自定义高亮样式，可能会因为特异性问题导致自定义样式没有生效。虽然这个测试文件没有直接测试特异性，但它覆盖了自定义高亮的基本功能，为理解特异性打下了基础。

3. **错误地使用依赖于字体大小或容器大小的单位:** `FontMetricsFromOriginatingElement` 和 `ContainerMetricsFromOriginatingElement` 测试确保了浏览器能正确地基于定义高亮样式的元素（或其容器）来计算这些单位的值。开发者可能会错误地认为这些单位总是相对于当前元素或视口来计算。

4. **误解自定义高亮的范围管理:** `CustomHighlightsNotOverlapping` 测试揭示了当多个自定义高亮范围重叠时，浏览器会创建多个独立的 marker。开发者可能错误地认为重叠的高亮会合并或者产生其他意想不到的效果。

总而言之，`highlight_style_utils_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确地处理各种高亮显示相关的 CSS 样式，涵盖了标准的选择高亮和新的自定义高亮功能，并考虑了样式继承、自定义属性以及不同类型的长度单位等复杂情况。 这些测试有助于防止与高亮显示相关的 bug，并确保开发者能够按照预期的方式使用 CSS 来定制网页元素的高亮效果。

### 提示词
```
这是目录为blink/renderer/core/highlight/highlight_style_utils_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/dom_selection.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/text_paint_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class HighlightStyleUtilsTest : public SimTest,
                                private ScopedHighlightInheritanceForTest {
 public:
  // TODO(crbug.com/1024156) remove CachedPseudoStyles tests, but keep
  // SelectedTextInputShadow, when HighlightInheritance becomes stable
  HighlightStyleUtilsTest() : ScopedHighlightInheritanceForTest(false) {}
};

TEST_F(HighlightStyleUtilsTest, SelectedTextInputShadow) {
  // Test that we apply input ::selection style to the value text.
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      input::selection {
        color: green;
        text-shadow: 2px 2px;
      }
    </style>
    <input type="text" value="Selected">
  )HTML");

  Compositor().BeginFrame();

  auto* text_node =
      To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")))
          ->InnerEditorElement()
          ->firstChild();
  const ComputedStyle& text_style = text_node->GetLayoutObject()->StyleRef();

  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);
  TextPaintStyle paint_style;

  const ComputedStyle* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
      text_node, text_style, kPseudoIdSelection);
  paint_style = HighlightStyleUtils::HighlightPaintingStyle(
                    GetDocument(), text_style, pseudo_style, text_node,
                    kPseudoIdSelection, paint_style, paint_info,
                    SearchTextIsActiveMatch::kNo)
                    .style;

  EXPECT_EQ(Color(0, 128, 0), paint_style.fill_color);
  EXPECT_TRUE(paint_style.shadow);
}

TEST_F(HighlightStyleUtilsTest, SelectedTextIsRespected) {
  // Test that we respect the author's colors in ::selection
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  Color default_highlight_background =
      LayoutTheme::GetTheme().InactiveSelectionBackgroundColor(
          mojom::blink::ColorScheme::kLight);
  String html_content =
      R"HTML(
      <!doctype html>
      <style>
        #div1::selection {
          background-color: green;
          color: green;
        }
        #div2::selection {
          color: )HTML" +
      default_highlight_background.SerializeAsCSSColor() + R"HTML(;
        }
        #div3 {
          color: )HTML" +
      default_highlight_background.SerializeAsCSSColor() + R"HTML(;
        }
      }
      </style>
      <div id="div1">Green text selection color and background</div>
      <div id="div2">Foreground matches default background color</div>
      <div id="div3">No selection pseudo colors matching text color</div>
    )HTML";
  main_resource.Complete(html_content);

  Compositor().BeginFrame();

  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);
  TextPaintStyle paint_style;
  Color background_color;

  auto* div1_text =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#div1")))
          ->firstChild();
  const ComputedStyle& div1_style = div1_text->GetLayoutObject()->StyleRef();
  const ComputedStyle* div1_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(div1_text, div1_style,
                                                kPseudoIdSelection);
  paint_style = HighlightStyleUtils::HighlightPaintingStyle(
                    GetDocument(), div1_style, div1_pseudo_style, div1_text,
                    kPseudoIdSelection, paint_style, paint_info,
                    SearchTextIsActiveMatch::kNo)
                    .style;
  background_color = HighlightStyleUtils::HighlightBackgroundColor(
      GetDocument(), div1_style, div1_text, std::nullopt, kPseudoIdSelection,
      SearchTextIsActiveMatch::kNo);
  EXPECT_EQ(Color(0, 128, 0), paint_style.fill_color);
  EXPECT_EQ(Color(0, 128, 0), background_color);

  auto* div2_text =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#div2")))
          ->firstChild();
  const ComputedStyle& div2_style = div1_text->GetLayoutObject()->StyleRef();
  const ComputedStyle* div2_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(div2_text, div2_style,
                                                kPseudoIdSelection);
  paint_style = HighlightStyleUtils::HighlightPaintingStyle(
                    GetDocument(), div2_style, div2_pseudo_style, div2_text,
                    kPseudoIdSelection, paint_style, paint_info,
                    SearchTextIsActiveMatch::kNo)
                    .style;
  background_color = HighlightStyleUtils::HighlightBackgroundColor(
      GetDocument(), div2_style, div2_text, std::nullopt, kPseudoIdSelection,
      SearchTextIsActiveMatch::kNo);
  EXPECT_EQ(default_highlight_background, paint_style.current_color);
  // Paired defaults means this is transparent
  EXPECT_EQ(Color(0, 0, 0, 0), background_color);

  auto* div3_text =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#div3")))
          ->firstChild();
  const ComputedStyle& div3_style = div1_text->GetLayoutObject()->StyleRef();
  const ComputedStyle* div3_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(div3_text, div3_style,
                                                kPseudoIdSelection);
  paint_style = HighlightStyleUtils::HighlightPaintingStyle(
                    GetDocument(), div3_style, div3_pseudo_style, div3_text,
                    kPseudoIdSelection, paint_style, paint_info,
                    SearchTextIsActiveMatch::kNo)
                    .style;
  std::optional<Color> current_layer_color = default_highlight_background;
  background_color = HighlightStyleUtils::HighlightBackgroundColor(
      GetDocument(), div3_style, div3_text, current_layer_color,
      kPseudoIdSelection, SearchTextIsActiveMatch::kNo);
#if BUILDFLAG(IS_MAC)
  EXPECT_EQ(default_highlight_background, paint_style.current_color);
  EXPECT_EQ(Color(255, 255, 255), background_color);
#else
  Color default_highlight_foreground =
      LayoutTheme::GetTheme().InactiveSelectionForegroundColor(
          mojom::blink::ColorScheme::kLight);
  EXPECT_EQ(default_highlight_foreground, paint_style.current_color);
  EXPECT_EQ(Color(92, 92, 92), background_color);
#endif
}

TEST_F(HighlightStyleUtilsTest, CurrentColorReportingAll) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  String html_content =
      R"HTML(
      <!doctype html>
      <style>
        ::selection {
          text-decoration-line: underline;
        }
        ::highlight(highlight1) {
          text-decoration-line: underline;
        }
        div {
          text-decoration-line: underline;
        }
      </style>
      <div id="div">Some text</div>
      <script>
        let r1 = new Range();
        r1.setStart(div, 0);
        r1.setEnd(div, 1);
        CSS.highlights.set("highlight1", new Highlight(r1));
      </script>
    )HTML";
  main_resource.Complete(html_content);

  auto* div_node =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#div")));
  Window().getSelection()->setBaseAndExtent(div_node, 0, div_node, 1);

  Compositor().BeginFrame();

  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);
  TextPaintStyle paint_style;

  auto* div_text = div_node->firstChild();
  const ComputedStyle& div_style = div_text->GetLayoutObject()->StyleRef();
  const ComputedStyle* div_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(
          div_text, div_style, kPseudoIdHighlight, AtomicString("highlight1"));
  HighlightStyleUtils::HighlightTextPaintStyle highlight_paint_style =
      HighlightStyleUtils::HighlightPaintingStyle(
          GetDocument(), div_style, div_pseudo_style, div_text,
          kPseudoIdHighlight, paint_style, paint_info,
          SearchTextIsActiveMatch::kNo);

  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kCurrentColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kFillColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kStrokeColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kEmphasisColor));
#if BUILDFLAG(IS_MAC)
  // Mac does not have default selection in tests
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kSelectionDecorationColor));
#else
  EXPECT_FALSE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kSelectionDecorationColor));
#endif

#if BUILDFLAG(IS_MAC)
  // Mac does not have default selection colors in testing
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kCurrentColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kFillColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kStrokeColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kEmphasisColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kSelectionDecorationColor));
#else
  const ComputedStyle* selection_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(div_text, div_style,
                                                kPseudoIdSelection);
  HighlightStyleUtils::HighlightTextPaintStyle selection_paint_style =
      HighlightStyleUtils::HighlightPaintingStyle(
          GetDocument(), div_style, selection_pseudo_style, div_text,
          kPseudoIdSelection, paint_style, paint_info,
          SearchTextIsActiveMatch::kNo);
  // Selection uses explicit default colors.
  EXPECT_TRUE(selection_paint_style.properties_using_current_color.empty());
#endif
}

TEST_F(HighlightStyleUtilsTest, CurrentColorReportingSome) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  String html_content =
      R"HTML(
      <!doctype html>
      <style>
        ::highlight(highlight1) {
          text-decoration-line: underline;
          text-decoration-color: red;
          -webkit-text-fill-color: blue;
        }
      </style>
      <div id="div">Some text</div>
      <script>
        let r1 = new Range();
        r1.setStart(div, 0);
        r1.setEnd(div, 1);
        CSS.highlights.set("highlight1", new Highlight(r1));
      </script>
    )HTML";
  main_resource.Complete(html_content);

  Compositor().BeginFrame();

  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);
  TextPaintStyle paint_style;

  auto* div_text =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#div")))
          ->firstChild();
  const ComputedStyle& div_style = div_text->GetLayoutObject()->StyleRef();
  const ComputedStyle* div_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(
          div_text, div_style, kPseudoIdHighlight, AtomicString("highlight1"));
  HighlightStyleUtils::HighlightTextPaintStyle highlight_paint_style =
      HighlightStyleUtils::HighlightPaintingStyle(
          GetDocument(), div_style, div_pseudo_style, div_text,
          kPseudoIdHighlight, paint_style, paint_info,
          SearchTextIsActiveMatch::kNo);

  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kCurrentColor));
  EXPECT_FALSE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kFillColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kStrokeColor));
  EXPECT_TRUE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kEmphasisColor));
  EXPECT_FALSE(highlight_paint_style.properties_using_current_color.Has(
      HighlightStyleUtils::HighlightColorProperty::kSelectionDecorationColor));
}

TEST_F(HighlightStyleUtilsTest, CustomPropertyInheritance) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      :root {
        --root-color: green;
      }
      ::selection {
        /* This rule should not apply */
        --selection-color: blue;
      }
      div::selection {
        /* Use the fallback */
        color: var(--selection-color, red);
        /* Use the :root inherited via originating */
        background-color: var(--root-color, red);
      }
    </style>
    <div>Selected</div>
  )HTML");

  // Select some text.
  auto* div_node =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  Window().getSelection()->setBaseAndExtent(div_node, 0, div_node, 1);
  Compositor().BeginFrame();
  std::optional<Color> previous_layer_color;

  PaintController controller;
  GraphicsContext context(controller);
  PaintInfo paint_info(context, CullRect(), PaintPhase::kForeground,
                       /*descendant_painting_blocked=*/false);
  TextPaintStyle paint_style;
  const ComputedStyle& div_style = div_node->ComputedStyleRef();
  const ComputedStyle* div_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(div_node, div_style,
                                                kPseudoIdSelection);
  paint_style = HighlightStyleUtils::HighlightPaintingStyle(
                    GetDocument(), div_style, div_pseudo_style, div_node,
                    kPseudoIdSelection, paint_style, paint_info,
                    SearchTextIsActiveMatch::kNo)
                    .style;

  EXPECT_EQ(Color(255, 0, 0), paint_style.fill_color);

  Color background_color = HighlightStyleUtils::HighlightBackgroundColor(
      GetDocument(), div_style, div_node, previous_layer_color,
      kPseudoIdSelection, SearchTextIsActiveMatch::kNo);

  EXPECT_EQ(Color(0, 128, 0), background_color);
}

TEST_F(HighlightStyleUtilsTest,
       CustomPropertyOriginatingInheritanceUniversal) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      :root {
        --selection-color: green;
      }
      ::selection {
        background-color: var(--selection-color);
      }
      .blue {
        --selection-color: blue;
      }
    </style>
    <div>
      <p>Some <strong>green</strong> highlight</p>
      <p class="blue">Some <strong>still blue</strong> highlight</p>
    </div>
  )HTML");

  // Select some text.
  auto* div_node =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  Window().getSelection()->setBaseAndExtent(div_node, 0, div_node, 1);
  Compositor().BeginFrame();

  const ComputedStyle& div_style = div_node->ComputedStyleRef();
  std::optional<Color> previous_layer_color;
  Color div_background_color = HighlightStyleUtils::HighlightBackgroundColor(
      GetDocument(), div_style, div_node, previous_layer_color,
      kPseudoIdSelection, SearchTextIsActiveMatch::kNo);
  EXPECT_EQ(Color(0, 128, 0), div_background_color);

  auto* div_inherited_vars = div_style.InheritedVariables();

  auto* first_p_node = To<HTMLElement>(div_node->firstChild()->nextSibling());
  const ComputedStyle& first_p_style = first_p_node->ComputedStyleRef();
  Color first_p_background_color =
      HighlightStyleUtils::HighlightBackgroundColor(
          GetDocument(), first_p_style, first_p_node, previous_layer_color,
          kPseudoIdSelection, SearchTextIsActiveMatch::kNo);
  EXPECT_EQ(Color(0, 128, 0), first_p_background_color);
  auto* first_p_inherited_vars = first_p_style.InheritedVariables();
  EXPECT_EQ(div_inherited_vars, first_p_inherited_vars);

  auto* second_p_node =
      To<HTMLElement>(first_p_node->nextSibling()->nextSibling());
  const ComputedStyle& second_p_style = second_p_node->ComputedStyleRef();
  Color second_p_background_color =
      HighlightStyleUtils::HighlightBackgroundColor(
          GetDocument(), second_p_style, second_p_node, previous_layer_color,
          kPseudoIdSelection, SearchTextIsActiveMatch::kNo);
  EXPECT_EQ(Color(0, 0, 255), second_p_background_color);
  auto* second_p_inherited_vars = second_p_style.InheritedVariables();
  EXPECT_NE(second_p_inherited_vars, first_p_inherited_vars);

  auto* second_strong_node =
      To<HTMLElement>(second_p_node->firstChild()->nextSibling());
  const ComputedStyle& second_strong_style =
      second_strong_node->ComputedStyleRef();
  Color second_strong_background_color =
      HighlightStyleUtils::HighlightBackgroundColor(
          GetDocument(), second_strong_style, second_strong_node,
          previous_layer_color, kPseudoIdSelection,
          SearchTextIsActiveMatch::kNo);
  EXPECT_EQ(Color(0, 0, 255), second_strong_background_color);
  auto* second_strong_inherited_vars = second_strong_style.InheritedVariables();
  EXPECT_EQ(second_p_inherited_vars, second_strong_inherited_vars);
}

TEST_F(HighlightStyleUtilsTest, FontMetricsFromOriginatingElement) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      :root {
        font-size: 16px;
      }
      div {
        font-size: 40px;
      }
      ::highlight(highlight1) {
        text-underline-offset: 0.5em;
        text-decoration-line: underline;
        text-decoration-color: green;
        text-decoration-thickness: 0.25rem;
      }
    </style>
    <div id="h1">Font-dependent lengths</div>
    <script>
      let r1 = new Range();
      r1.setStart(h1, 0);
      r1.setEnd(h1, 1);
      CSS.highlights.set("highlight1", new Highlight(r1));
    </script>
  )HTML");

  Compositor().BeginFrame();

  auto* div_node =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  const ComputedStyle& div_style = div_node->ComputedStyleRef();
  EXPECT_EQ(div_style.SpecifiedFontSize(), 40);

  const ComputedStyle* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
      div_node, div_style, kPseudoIdHighlight, AtomicString("highlight1"));

  EXPECT_TRUE(pseudo_style->HasAppliedTextDecorations());
  const AppliedTextDecoration& text_decoration =
      pseudo_style->AppliedTextDecorations()[0];
  TextDecorationThickness thickness = text_decoration.Thickness();
  EXPECT_EQ(FloatValueForLength(thickness.Thickness(), 1), 4);
  Length offset = text_decoration.UnderlineOffset();
  EXPECT_EQ(FloatValueForLength(offset, 1), 20);
}

TEST_F(HighlightStyleUtilsTest, CustomHighlightsNotOverlapping) {
  // Not really a style utils test, but this is the only Pseudo Highlights
  // unit test suite making use of SimTest.
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      ::highlight(highlight1) {
        background-color: red;
      }
      ::highlight(highlight2) {
        background-color: green;
      }
      ::highlight(highlight3) {
        background-color: blue;
      }
    </style>
    <div id="h1">0123456789</div>
    <script>
      let text = h1.firstChild;
      let r1 = new Range();
      r1.setStart(text, 0);
      r1.setEnd(text, 5);
      let r2 = new Range();
      r2.setStart(text, 4);
      r2.setEnd(text, 10);
      CSS.highlights.set("highlight1", new Highlight(r1, r2));
      let r3 = new Range();
      r3.setStart(text, 3);
      r3.setEnd(text, 6);
      let r4 = new Range();
      r4.setStart(text, 1);
      r4.setEnd(text, 9);
      CSS.highlights.set("highlight2", new Highlight(r3, r4));
      let r5 = new Range();
      r5.setStart(text, 2);
      r5.setEnd(text, 4);
      let r6 = new Range();
      r6.setStart(text, 5);
      r6.setEnd(text, 9);
      CSS.highlights.set("highlight3", new Highlight(r5, r6));
    </script>
  )HTML");

  Compositor().BeginFrame();

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* node = div->firstChild();
  EXPECT_TRUE(node->IsTextNode());
  Text* text = To<Text>(node);

  auto& marker_controller = GetDocument().Markers();

  DocumentMarkerVector markers = marker_controller.MarkersFor(*text);
  EXPECT_EQ(4u, markers.size());

  DocumentMarker* marker = markers[0];
  EXPECT_EQ(DocumentMarker::MarkerType::kCustomHighlight, marker->GetType());
  EXPECT_EQ(AtomicString("highlight1"),
            To<CustomHighlightMarker>(marker)->GetHighlightName());
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(10u, marker->EndOffset());

  marker = markers[1];
  EXPECT_EQ(DocumentMarker::MarkerType::kCustomHighlight, marker->GetType());
  EXPECT_EQ(AtomicString("highlight2"),
            To<CustomHighlightMarker>(marker)->GetHighlightName());
  EXPECT_EQ(1u, marker->StartOffset());
  EXPECT_EQ(9u, marker->EndOffset());

  marker = markers[2];
  EXPECT_EQ(DocumentMarker::MarkerType::kCustomHighlight, marker->GetType());
  EXPECT_EQ(AtomicString("highlight3"),
            To<CustomHighlightMarker>(marker)->GetHighlightName());
  EXPECT_EQ(2u, marker->StartOffset());
  EXPECT_EQ(4u, marker->EndOffset());

  marker = markers[3];
  EXPECT_EQ(DocumentMarker::MarkerType::kCustomHighlight, marker->GetType());
  EXPECT_EQ(AtomicString("highlight3"),
            To<CustomHighlightMarker>(marker)->GetHighlightName());
  EXPECT_EQ(5u, marker->StartOffset());
  EXPECT_EQ(9u, marker->EndOffset());
}

TEST_F(HighlightStyleUtilsTest, ContainerMetricsFromOriginatingElement) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <head>
      <style>
        .wrapper {
          container: wrapper / size;
          width: 200px;
          height: 100px;
        }
        @container wrapper (width > 100px) {
          ::highlight(highlight1) {
            text-underline-offset: 2cqw;
            text-decoration-line: underline;
            text-decoration-color: green;
            text-decoration-thickness: 4cqh;
          }
        }
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div id="h1">With container size</div>
      </div>
      <script>
        let r1 = new Range();
        r1.setStart(h1, 0);
        r1.setEnd(h1, 1);
        CSS.highlights.set("highlight1", new Highlight(r1));
      </script>
    </body>
  )HTML");

  Compositor().BeginFrame();

  auto* div_node =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#h1")));
  EXPECT_TRUE(div_node);
  const ComputedStyle& div_style = div_node->ComputedStyleRef();

  const ComputedStyle* div_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(
          div_node, div_style, kPseudoIdHighlight, AtomicString("highlight1"));

  EXPECT_TRUE(div_pseudo_style->HasAppliedTextDecorations());
  const AppliedTextDecoration& text_decoration =
      div_pseudo_style->AppliedTextDecorations()[0];
  TextDecorationThickness thickness = text_decoration.Thickness();
  EXPECT_EQ(FloatValueForLength(thickness.Thickness(), 1), 4);
  Length offset = text_decoration.UnderlineOffset();
  EXPECT_EQ(FloatValueForLength(offset, 1), 4);
}

TEST_F(HighlightStyleUtilsTest, ContainerIsOriginatingElement) {
  ScopedHighlightInheritanceForTest highlight_inheritance_enabled(true);
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <head>
      <style>
        .wrapper {
          container: wrapper / size;
          width: 200px;
          height: 100px;
        }
        @container (width > 100px) {
          .wrapper::highlight(highlight1) {
            text-underline-offset: 2cqw;
            text-decoration-line: underline;
            text-decoration-color: green;
            text-decoration-thickness: 4cqh;
          }
        }
      </style>
    </head>
    <body>
      <div id="h1" class="wrapper">With container size</div>
      <script>
        let r1 = new Range();
        r1.setStart(h1, 0);
        r1.setEnd(h1, 1);
        CSS.highlights.set("highlight1", new Highlight(r1));
      </script>
    </body>
  )HTML");

  Compositor().BeginFrame();

  auto* div_node =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("#h1")));
  EXPECT_TRUE(div_node);
  const ComputedStyle& div_style = div_node->ComputedStyleRef();

  const ComputedStyle* div_pseudo_style =
      HighlightStyleUtils::HighlightPseudoStyle(
          div_node, div_style, kPseudoIdHighlight, AtomicString("highlight1"));

  EXPECT_TRUE(div_pseudo_style);
  EXPECT_TRUE(div_pseudo_style->HasAppliedTextDecorations());
  const AppliedTextDecoration& text_decoration =
      div_pseudo_style->AppliedTextDecorations()[0];
  TextDecorationThickness thickness = text_decoration.Thickness();
  EXPECT_EQ(FloatValueForLength(thickness.Thickness(), 1), 4);
  Length offset = text_decoration.UnderlineOffset();
  EXPECT_EQ(FloatValueForLength(offset, 1), 4);
}

}  // namespace blink
```