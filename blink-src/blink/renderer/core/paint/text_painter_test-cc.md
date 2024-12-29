Response:
Let's break down the thought process for analyzing this `text_painter_test.cc` file.

1. **Understanding the Core Purpose:** The file name immediately suggests it's a test file for something related to "text painter."  The `.cc` extension confirms it's C++ code. The `_test` suffix strongly indicates unit testing. Therefore, the primary function is to test the `TextPainter` class (or related functionality) in the Blink rendering engine.

2. **Identifying Key Classes:** Looking at the `#include` directives reveals the main classes involved:
    * `third_party/blink/renderer/core/paint/text_painter.h`: This is the header file for the class being tested.
    * `third_party/blink/renderer/core/paint/text_paint_style.h`:  This likely defines a structure or class related to text painting styles.
    * Other includes (`cc/paint/paint_op.h`, `testing/gtest/include/gtest/gtest.h`, etc.) are standard for graphics/testing in Chromium.

3. **Examining the Test Structure:**  The file uses the Google Test framework (`TEST_F`). This tells us:
    * There's a test fixture class: `TextPainterTest` inheriting from `RenderingTest`. This provides a controlled environment for testing, likely setting up a minimal rendering context.
    * Individual test cases are defined using `TEST_F(TextPainterTest, TestName)`.

4. **Analyzing Individual Test Cases:**  The names of the test cases are very informative:
    * `TextPaintingStyle_Simple`:  Probably tests basic text styling.
    * `TextPaintingStyle_AllProperties`: Likely tests a wider range of text styling properties.
    * `TextPaintingStyle_UsesTextAsClip`:  Suggests testing how text can be used as a clipping mask.
    * `TextPaintingStyle_ForceBackgroundToWhite_NoAdjustmentNeeded` and `TextPaintingStyle_ForceBackgroundToWhite_Darkened`:  Focus on printing scenarios and color adjustments.
    * `CachedTextBlob`:  Tests caching mechanisms related to text rendering.

5. **Connecting to Web Technologies (HTML, CSS, JavaScript):** This is where understanding how Blink works is crucial. The tests manipulate the DOM and CSS properties:
    * `GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kColor, CSSValueID::kBlue);`: This directly manipulates the `style` attribute of the `<body>` element, demonstrating interaction with CSS.
    * The test cases check the resulting `TextPaintStyle`, which determines how the text will be rendered. This links CSS properties to the internal rendering logic.
    * The setup (`SetBodyInnerHTML("Hello world");`) shows how HTML content is established for testing.
    * While JavaScript isn't directly *in* this test file, the functionality being tested is what makes JavaScript manipulation of text styles effective. JavaScript code changing `element.style.color` will eventually lead to this kind of code being executed.

6. **Inferring Functionality of `TextPainter`:** Based on the tests, we can infer that `TextPainter` (and particularly its `TextPaintingStyle` method) is responsible for:
    * Taking CSS styles (like `color`, `text-fill-color`, `text-stroke-color`, `text-shadow`, etc.) and converting them into a structure (`TextPaintStyle`) that the rendering engine can use.
    * Handling different paint phases (e.g., `kSelfBlockBackgroundOnly`, `kTextClip`).
    * Potentially optimizing rendering by caching `SkTextBlob` objects.
    * Considering printing-specific adjustments.

7. **Logic Reasoning and Input/Output:**  For each test case, we can create a hypothetical scenario:
    * **Input:**  Specific CSS properties set on an HTML element.
    * **Process:** The `TextPainter::TextPaintingStyle` method is called.
    * **Output:** The values within the resulting `TextPaintStyle` object are asserted to match the expected outcome based on the input CSS. For example, setting `color: blue` should result in `text_style.fill_color` being blue.

8. **Identifying Potential User/Programming Errors:**  The tests implicitly reveal potential errors:
    * **Incorrect CSS property names:** If a developer misspells a CSS property, the test for that property might fail, highlighting the error.
    * **Unexpected interaction of CSS properties:** The tests with multiple properties help ensure that combinations of styles are handled correctly.
    * **Assumptions about default values:**  The tests establish expected default values if a property isn't explicitly set.
    * **Forgetting to update layout:**  The `UpdateAllLifecyclePhasesForTest()` calls are crucial. Forgetting this after changing styles would lead to incorrect test results, mirroring a developer error.

9. **Debugging Workflow (How to reach this code):** Imagine a developer noticing text isn't rendering with the correct color. They might:
    1. **Inspect the element:** Use the browser's developer tools to examine the computed styles.
    2. **Trace the rendering path:** If the styles seem correct but the rendering isn't, they might need to delve deeper into the rendering engine. This would involve:
        * **Setting breakpoints:**  They might set breakpoints in `TextPainter::Paint` or related functions.
        * **Stepping through the code:** Follow the execution flow to see how the text is being painted.
        * **Looking at the `TextPaintStyle`:** Examining the values in this structure at runtime can reveal if the styles are being interpreted correctly.
        * **Consulting the tests:**  Looking at tests like these can help understand the expected behavior and might reveal edge cases or bugs in the rendering logic.

**Self-Correction/Refinement During the Process:**

* Initially, I might just focus on the individual tests. However, realizing that the overarching goal is to understand `TextPainter` would lead to grouping related tests together in the explanation.
*  I might initially overemphasize the direct link to JavaScript in the test file itself. Reflecting on the architecture clarifies that the *tests* are driven by C++, but the *functionality* being tested is what makes CSS and JavaScript style manipulation work.
* I might initially miss the significance of the `PaintPhase`. Recognizing that different painting phases might have different styling rules is important for a complete understanding.

By following this systematic approach, combining code analysis with an understanding of web technologies and the Chromium architecture, we can effectively analyze and explain the functionality of a file like `text_painter_test.cc`.
This C++ source code file, `text_painter_test.cc`, located within the `blink/renderer/core/paint` directory of the Chromium Blink engine, serves as **unit tests for the `TextPainter` class**. Its primary function is to verify the correctness of the `TextPainter`'s logic, especially how it handles text styling and rendering information.

Here's a breakdown of its functionalities and relationships:

**Core Functionality:**

* **Testing `TextPainter::TextPaintingStyle`:** The majority of the tests focus on the `TextPaintingStyle` static method of the `TextPainter` class. This method is responsible for determining the final styling information for text based on various factors like CSS properties, paint phase, and printing settings. The tests assert that the returned `TextPaintStyle` object contains the expected color, stroke, shadow, and other properties.
* **Verifying CSS Property Handling:** The tests systematically set different CSS properties related to text styling (e.g., `color`, `text-fill-color`, `text-stroke-color`, `text-shadow`, `text-emphasis-color`) and check if the `TextPaintingStyle` method correctly reflects these styles in the returned `TextPaintStyle` object.
* **Testing Different Paint Phases:** The tests demonstrate how the `TextPaintingStyle` behaves in different paint phases, specifically `kSelfBlockBackgroundOnly` and `kTextClip`. This is important because the styling might vary depending on what part of the rendering process is being performed.
* **Testing Printing Scenarios:** Some tests specifically address how text styling is handled during printing, including scenarios where background printing is disabled (`kWebkitPrintColorAdjust: economy`).
* **Testing Text Blob Caching:** The `CachedTextBlob` test verifies that the rendering engine correctly reuses cached `SkTextBlob` objects for text when only style properties like color change, but not when font size or content changes. This is an optimization to improve rendering performance.
* **Using the Google Test Framework:** The file utilizes the Google Test framework (`TEST_F`, `EXPECT_EQ`, `ASSERT_TRUE`, etc.) to structure the tests and perform assertions.

**Relationship to JavaScript, HTML, and CSS:**

This test file is **directly related to how CSS styles applied to HTML elements are interpreted and used to render text**.

* **HTML:** The tests start by setting up a basic HTML structure using `SetBodyInnerHTML("Hello world");`. The tests then operate on the `LayoutText` object representing this text node in the render tree.
* **CSS:** The core of the tests involves setting inline CSS styles using methods like `GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kColor, CSSValueID::kBlue);`. The tests then verify if these CSS properties are correctly translated into the `TextPaintStyle`. Specifically, it tests CSS properties like:
    * `color`: The basic text color.
    * `-webkit-text-fill-color`:  Specifies the fill color of the text.
    * `-webkit-text-stroke-color`: Specifies the color of the text stroke.
    * `text-emphasis-color`: Specifies the color of emphasis marks (like dots or circles) for text.
    * `-webkit-text-stroke-width`: Specifies the width of the text stroke.
    * `text-shadow`:  Adds shadow effects to the text.
    * `-webkit-print-color-adjust`: Controls how the browser adjusts colors during printing.
* **JavaScript:** While the test file itself is C++, the functionality it tests is what enables JavaScript to dynamically manipulate text styles. For example, if JavaScript code changes the color of a text element using `element.style.color = 'red'`, the underlying rendering engine, including the logic tested here, will be responsible for applying that color during the painting process.

**Examples and Logic Reasoning:**

**Example 1: Testing basic color**

* **Assumption:**  Setting the `color` CSS property to `blue` should result in the `fill_color`, `stroke_color`, and `emphasis_mark_color` in the `TextPaintStyle` being blue.
* **Input (CSS):** `body { color: blue; }`
* **Test Code:**
  ```c++
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kColor,
                                               CSSValueID::kBlue);
  // ...
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(...);
  EXPECT_EQ(Color(0, 0, 255), text_style.fill_color);
  EXPECT_EQ(Color(0, 0, 255), text_style.stroke_color);
  EXPECT_EQ(Color(0, 0, 255), text_style.emphasis_mark_color);
  ```
* **Output (Expected `TextPaintStyle`):** `fill_color = blue`, `stroke_color = blue`, `emphasis_mark_color = blue`.

**Example 2: Testing `text-shadow`**

* **Assumption:** Setting the `text-shadow` property should create a `ShadowData` object within the `TextPaintStyle` with the correct offset, blur, and color.
* **Input (CSS):** `body { text-shadow: 1px 2px 3px yellow; }`
* **Test Code:**
  ```c++
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kTextShadow,
                                               "1px 2px 3px yellow");
  // ...
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(...);
  ASSERT_NE(nullptr, text_style.shadow);
  EXPECT_EQ(1u, text_style.shadow->Shadows().size());
  EXPECT_EQ(1, text_style.shadow->Shadows()[0].X());
  EXPECT_EQ(2, text_style.shadow->Shadows()[0].Y());
  EXPECT_EQ(3, text_style.shadow->Shadows()[0].Blur());
  EXPECT_EQ(Color(255, 255, 0),
            text_style.shadow->Shadows()[0].GetColor().GetColor());
  ```
* **Output (Expected `TextPaintStyle`):** `shadow` is not null and contains a single shadow with x=1, y=2, blur=3, and color yellow.

**User or Programming Common Usage Errors:**

* **Misspelling CSS property names:** If a web developer misspells a CSS property like `colr` instead of `color`, the browser won't recognize it, and the styling won't be applied. The tests in this file ensure that Blink correctly interprets the *correctly spelled* CSS properties.
* **Incorrect CSS syntax:** Using invalid syntax for CSS values (e.g., `color: bl;` instead of `color: blue;`) will also lead to the style not being applied.
* **Assuming default values:** Developers might assume a default value for a property that is different from the actual default. The tests help ensure that the default styling behavior is consistent.
* **Forgetting to update layout after style changes (in development/debugging):** While this test file handles the lifecycle updates internally, a developer debugging rendering issues might forget to trigger a layout update after programmatically changing styles with JavaScript, leading to unexpected rendering.

**User Operation and Debugging Clues:**

A user's interaction with a web page can lead to this code being executed in various ways:

1. **Static HTML and CSS:** When a user loads a webpage with statically defined HTML and CSS, the browser parses these resources. The CSS rules are then applied to the DOM, creating a render tree. During the paint phase, the `TextPainter` and its `TextPaintingStyle` method are used to determine how the text should be drawn based on the applied CSS.

2. **Dynamic Style Changes via JavaScript:** When JavaScript code modifies the styles of HTML elements (e.g., using `element.style.color = 'red'`), this triggers a style recalculation and potentially a repaint. The `TextPainter` is then involved in rendering the text with the newly applied styles.

3. **Browser Reflows/Repaints:**  Various user interactions can trigger reflows (layout recalculations) and repaints, such as:
    * Resizing the browser window.
    * Scrolling.
    * Hovering over elements (triggering `:hover` styles).
    * Focusing on input fields.

**Debugging Clues to Reach This Code:**

If a developer is investigating issues related to text rendering (e.g., incorrect color, missing shadows, incorrect stroke):

1. **Inspect Element in DevTools:** The developer would typically start by inspecting the affected text element in the browser's developer tools. This allows them to see the computed styles applied to the element.

2. **Check Computed Styles:** The "Computed" tab in DevTools shows the final styles that the browser has applied, taking into account all relevant CSS rules. This can help identify if the CSS is being applied correctly in the first place.

3. **Search for `TextPainter` in Chromium Code:** If the computed styles look correct, but the rendering is still wrong, the developer might suspect an issue in the rendering pipeline itself. They might search the Chromium codebase for `TextPainter` to understand how text is painted.

4. **Set Breakpoints in `TextPainter::TextPaintingStyle`:**  To understand how the text style is being determined, a developer could set breakpoints in the `TextPainter::TextPaintingStyle` method (or related methods) within the Chromium source code.

5. **Step Through the Code:** By stepping through the code execution, the developer can examine the values of variables and understand the logic flow within the `TextPaintingStyle` method. They can see which CSS properties are being considered and how they are influencing the final `TextPaintStyle` object.

6. **Consult Unit Tests:** If a bug is suspected, developers might look at unit tests like `text_painter_test.cc` to understand the expected behavior for different CSS property combinations and paint phases. This can help them identify discrepancies between the expected and actual behavior.

In summary, `text_painter_test.cc` plays a crucial role in ensuring the correctness and reliability of text rendering in the Blink engine by thoroughly testing how CSS styles are translated into rendering instructions. It's a key component for maintaining the visual fidelity of web pages across different browsers.

Prompt: 
```
这是目录为blink/renderer/core/paint/text_painter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/text_painter.h"

#include <memory>

#include "cc/paint/paint_op.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/style/shadow_data.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/core/paint/text_paint_style.h"
#include "third_party/skia/include/core/SkTextBlob.h"

namespace blink {
namespace {

class TextPainterTest : public RenderingTest {
 protected:
  const LayoutText& GetLayoutText() { return *layout_text_; }

  PaintInfo CreatePaintInfoForBackground(GraphicsContext& context) {
    return PaintInfo(context, CullRect(), PaintPhase::kSelfBlockBackgroundOnly,
                     /*descendant_painting_blocked=*/false);
  }

  PaintInfo CreatePaintInfoForTextClip(GraphicsContext& context) {
    return PaintInfo(context, CullRect(), PaintPhase::kTextClip,
                     /*descendant_painting_blocked=*/false);
  }

 protected:
  void SetUp() override {
    RenderingTest::SetUp();
    SetBodyInnerHTML("Hello world");
    UpdateLayoutText();
  }
  void UpdateLayoutText() {
    layout_text_ =
        To<LayoutText>(GetDocument().body()->firstChild()->GetLayoutObject());
    ASSERT_TRUE(layout_text_);
    ASSERT_EQ("Hello world", layout_text_->TransformedText());
  }

  Persistent<LayoutText> layout_text_;
};

TEST_F(TextPainterTest, TextPaintingStyle_Simple) {
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kColor,
                                               CSSValueID::kBlue);
  UpdateAllLifecyclePhasesForTest();

  PaintController controller;
  GraphicsContext context(controller);
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(
      GetLayoutText().GetDocument(), GetLayoutText().StyleRef(),
      CreatePaintInfoForBackground(context));
  EXPECT_EQ(Color(0, 0, 255), text_style.fill_color);
  EXPECT_EQ(Color(0, 0, 255), text_style.stroke_color);
  EXPECT_EQ(Color(0, 0, 255), text_style.emphasis_mark_color);
  EXPECT_EQ(0, text_style.stroke_width);
  EXPECT_EQ(nullptr, text_style.shadow);
}

TEST_F(TextPainterTest, TextPaintingStyle_AllProperties) {
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextFillColor, CSSValueID::kRed);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextStrokeColor, CSSValueID::kLime);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kTextEmphasisColor, CSSValueID::kBlue);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextStrokeWidth, 4,
      CSSPrimitiveValue::UnitType::kPixels);
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kTextShadow,
                                               "1px 2px 3px yellow");
  UpdateAllLifecyclePhasesForTest();

  PaintController controller;
  GraphicsContext context(controller);
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(
      GetLayoutText().GetDocument(), GetLayoutText().StyleRef(),
      CreatePaintInfoForBackground(context));
  EXPECT_EQ(Color(255, 0, 0), text_style.fill_color);
  EXPECT_EQ(Color(0, 255, 0), text_style.stroke_color);
  EXPECT_EQ(Color(0, 0, 255), text_style.emphasis_mark_color);
  EXPECT_EQ(4, text_style.stroke_width);
  ASSERT_NE(nullptr, text_style.shadow);
  EXPECT_EQ(1u, text_style.shadow->Shadows().size());
  EXPECT_EQ(1, text_style.shadow->Shadows()[0].X());
  EXPECT_EQ(2, text_style.shadow->Shadows()[0].Y());
  EXPECT_EQ(3, text_style.shadow->Shadows()[0].Blur());
  EXPECT_EQ(Color(255, 255, 0),
            text_style.shadow->Shadows()[0].GetColor().GetColor());
}

TEST_F(TextPainterTest, TextPaintingStyle_UsesTextAsClip) {
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextFillColor, CSSValueID::kRed);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextStrokeColor, CSSValueID::kLime);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kTextEmphasisColor, CSSValueID::kBlue);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextStrokeWidth, 4,
      CSSPrimitiveValue::UnitType::kPixels);
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kTextShadow,
                                               "1px 2px 3px yellow");
  UpdateAllLifecyclePhasesForTest();

  PaintController controller;
  GraphicsContext context(controller);
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(
      GetLayoutText().GetDocument(), GetLayoutText().StyleRef(),
      CreatePaintInfoForTextClip(context));
  EXPECT_EQ(Color::kBlack, text_style.fill_color);
  EXPECT_EQ(Color::kBlack, text_style.stroke_color);
  EXPECT_EQ(Color::kBlack, text_style.emphasis_mark_color);
  EXPECT_EQ(4, text_style.stroke_width);
  EXPECT_EQ(nullptr, text_style.shadow);
}

TEST_F(TextPainterTest,
       TextPaintingStyle_ForceBackgroundToWhite_NoAdjustmentNeeded) {
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextFillColor, CSSValueID::kRed);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextStrokeColor, CSSValueID::kLime);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kTextEmphasisColor, CSSValueID::kBlue);
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitPrintColorAdjust, CSSValueID::kEconomy);
  GetDocument().GetSettings()->SetShouldPrintBackgrounds(false);
  gfx::SizeF page_size(500, 800);
  GetFrame().StartPrinting(WebPrintParams(page_size));
  UpdateAllLifecyclePhasesForTest();
  // In LayoutNG, printing currently forces layout tree reattachment,
  // so we need to re-get layout_text_.
  UpdateLayoutText();

  PaintController controller;
  GraphicsContext context(controller);
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(
      GetLayoutText().GetDocument(), GetLayoutText().StyleRef(),
      CreatePaintInfoForBackground(context));
  EXPECT_EQ(Color(255, 0, 0), text_style.fill_color);
  EXPECT_EQ(Color(0, 255, 0), text_style.stroke_color);
  EXPECT_EQ(Color(0, 0, 255), text_style.emphasis_mark_color);
}

TEST_F(TextPainterTest, TextPaintingStyle_ForceBackgroundToWhite_Darkened) {
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextFillColor, "rgb(255, 220, 220)");
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitTextStrokeColor, "rgb(220, 255, 220)");
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kTextEmphasisColor, "rgb(220, 220, 255)");
  GetDocument().body()->SetInlineStyleProperty(
      CSSPropertyID::kWebkitPrintColorAdjust, CSSValueID::kEconomy);
  GetDocument().GetSettings()->SetShouldPrintBackgrounds(false);
  gfx::SizeF page_size(500, 800);
  GetFrame().StartPrinting(WebPrintParams(page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();
  // In LayoutNG, printing currently forces layout tree reattachment,
  // so we need to re-get layout_text_.
  UpdateLayoutText();

  PaintController controller;
  GraphicsContext context(controller);
  TextPaintStyle text_style = TextPainter::TextPaintingStyle(
      GetLayoutText().GetDocument(), GetLayoutText().StyleRef(),
      CreatePaintInfoForBackground(context));
  EXPECT_EQ(Color(255, 220, 220).Dark(), text_style.fill_color);
  EXPECT_EQ(Color(220, 255, 220).Dark(), text_style.stroke_color);
  EXPECT_EQ(Color(220, 220, 255).Dark(), text_style.emphasis_mark_color);
}

TEST_F(TextPainterTest, CachedTextBlob) {
  auto& persistent_data =
      GetDocument().View()->GetPaintControllerPersistentDataForTesting();
  auto* item =
      DynamicTo<DrawingDisplayItem>(persistent_data.GetDisplayItemList()[1]);
  ASSERT_TRUE(item);
  auto* op = static_cast<const cc::DrawTextBlobOp*>(
      &item->GetPaintRecord().GetFirstOp());
  ASSERT_EQ(cc::PaintOpType::kDrawTextBlob, op->GetType());
  cc::PaintFlags flags = op->flags;
  sk_sp<SkTextBlob> blob = op->blob;

  // Should reuse text blob on color change.
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kColor, "red");
  UpdateAllLifecyclePhasesForTest();
  item = DynamicTo<DrawingDisplayItem>(persistent_data.GetDisplayItemList()[1]);
  ASSERT_TRUE(item);
  op = static_cast<const cc::DrawTextBlobOp*>(
      &item->GetPaintRecord().GetFirstOp());
  ASSERT_EQ(cc::PaintOpType::kDrawTextBlob, op->GetType());
  EXPECT_FALSE(flags.EqualsForTesting(op->flags));
  flags = op->flags;
  EXPECT_EQ(blob, op->blob);

  // Should not reuse text blob on font-size change.
  GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kFontSize,
                                               "30px");
  UpdateAllLifecyclePhasesForTest();
  item = DynamicTo<DrawingDisplayItem>(persistent_data.GetDisplayItemList()[1]);
  ASSERT_TRUE(item);
  op = static_cast<const cc::DrawTextBlobOp*>(
      &item->GetPaintRecord().GetFirstOp());
  ASSERT_EQ(cc::PaintOpType::kDrawTextBlob, op->GetType());
  EXPECT_TRUE(flags.EqualsForTesting(op->flags));
  EXPECT_NE(blob, op->blob);
  blob = op->blob;

  // Should not reuse text blob on text content change.
  GetDocument().body()->firstChild()->setTextContent("Hello, Hello");
  UpdateAllLifecyclePhasesForTest();
  item = DynamicTo<DrawingDisplayItem>(persistent_data.GetDisplayItemList()[1]);
  ASSERT_TRUE(item);
  op = static_cast<const cc::DrawTextBlobOp*>(
      &item->GetPaintRecord().GetFirstOp());
  ASSERT_EQ(cc::PaintOpType::kDrawTextBlob, op->GetType());
  EXPECT_TRUE(flags.EqualsForTesting(op->flags));
  EXPECT_NE(blob, op->blob);

  // In dark mode, the text should be drawn with dark mode flags.
  GetDocument().GetSettings()->SetForceDarkModeEnabled(true);
  UpdateAllLifecyclePhasesForTest();
  item = DynamicTo<DrawingDisplayItem>(persistent_data.GetDisplayItemList()[1]);
  ASSERT_TRUE(item);
  op = static_cast<const cc::DrawTextBlobOp*>(
      &item->GetPaintRecord().GetFirstOp());
  ASSERT_EQ(cc::PaintOpType::kDrawTextBlob, op->GetType());
  EXPECT_FALSE(flags.EqualsForTesting(op->flags));
}

}  // namespace
}  // namespace blink

"""

```