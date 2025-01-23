Response:
Let's break down the thought process for analyzing the `media_query_exp_test.cc` file.

1. **Identify the Core Purpose:** The file name itself, `media_query_exp_test.cc`, strongly suggests this file is a test suite for code related to media query expressions. The `.cc` extension confirms it's C++ code.

2. **Examine Includes:** The `#include` directives at the top are crucial. They tell us what other parts of the Chromium/Blink codebase this file interacts with. Key inclusions are:
    * `media_query_exp.h`:  This is likely the header file for the code being tested. It defines the classes and functions for representing media query expressions.
    * `testing/gtest/include/gtest/gtest.h`:  This indicates the use of Google Test, a popular C++ testing framework. We can expect to see `TEST()` macros.
    * `css/css_numeric_literal_value.h`, `css/css_test_helpers.h`: These point to CSS-related functionality, implying the media query expressions deal with CSS values.
    * `dom/document.h`: Suggests interaction with the Document Object Model, where CSS is applied.
    * `testing/null_execution_context.h`: This is a testing utility, likely used to create a minimal environment for testing without full browser context.
    * `platform/testing/task_environment.h`: Another testing utility, probably for managing asynchronous tasks if needed (though not heavily used in this particular test file).

3. **Analyze the Namespace:** The code is within the `blink` namespace, and a nested anonymous namespace `namespace { ... }`. This is standard C++ practice for encapsulation and avoiding naming conflicts.

4. **Inspect Helper Functions:** The anonymous namespace contains a series of helper functions like `WrapDouble`, `IdentValue`, `RatioValue`, `PxValue`, etc. These functions are designed to simplify the creation of `MediaQueryExpValue` objects with different types and units. This is a common pattern in testing to make test setup more readable and less verbose. Pay attention to the different CSS units they handle (pixels, ems, rems, viewports, etc.).

5. **Focus on `TEST()` Macros:** The core of the file is the set of `TEST()` macros. Each `TEST()` function isolates a specific aspect of `MediaQueryExp` functionality. Go through each test and understand what it's verifying:
    * `ValuesType`: Checks if different value creation helpers produce values of the expected type (identifier, numeric literal, ratio).
    * `ValueEquality`: Tests the equality and inequality operators for `MediaQueryExpValue` objects, considering different values, units, and types.
    * `ComparisonEquality`, `BoundaryEquality`, `ExpEquality`:  These follow the same pattern, testing equality for `MediaQueryExpComparison`, `MediaQueryExpBounds`, and `MediaQueryExp` objects respectively.
    * `Serialize`:  A very important test!  It verifies that media query expressions can be converted into their string representation, which is how they appear in CSS. This test covers various expression formats (boolean features, plain features, range comparisons).
    * `SerializeNode`: Tests the serialization of the *node* representation of media query expressions (which includes logical operators like `and`, `or`, `not`).
    * `CollectExpressions`: Examines how to extract individual `MediaQueryExp` objects from a potentially complex expression tree.
    * `UnitFlags`: Checks if the correct flags representing CSS units are associated with `MediaQueryExp` objects. This is important for later processing and understanding the units involved.
    * `UtilsNullptrHandling`: Tests the robustness of the code by ensuring it handles null pointers gracefully, preventing crashes.
    * `ResolutionChecks`: Specifically tests the `IsResolution()` method, confirming that values intended as resolutions are correctly identified.

6. **Connect to Core Concepts:** Now, link the observations back to the initial question about relationships with JavaScript, HTML, and CSS:
    * **CSS:** The entire file revolves around media queries, which are a fundamental part of CSS. The tests directly manipulate and serialize CSS media query syntax. The use of specific CSS units is a direct connection.
    * **HTML:** While not directly manipulated in this test file, media queries are used to apply different styles to HTML elements based on device characteristics. The `Document::CreateForTest` suggests a minimal HTML context is needed for parsing CSS values.
    * **JavaScript:** While this is a C++ test, the functionality being tested (media query parsing and evaluation) is often used in conjunction with JavaScript. For example, JavaScript can query the computed styles of elements, which are influenced by media queries. JavaScript can also programmatically check if a media query matches the current environment using `window.matchMedia()`.

7. **Infer User Actions and Debugging:** Based on the tested functionality, think about how a user might encounter issues related to media queries:
    * Incorrect media query syntax in CSS.
    * Unexpected behavior when media queries are evaluated.
    * Issues with specific CSS units in media queries.
    * Complex media query combinations leading to unexpected results.

    The test file provides debugging clues by showing how different media query components are created, compared, and serialized. If a user reports a problem with a specific media query, a developer could potentially write a new test case based on that query to reproduce and fix the issue.

8. **Consider Edge Cases and Errors:** The `UtilsNullptrHandling` test explicitly addresses a common programming error: using null pointers. Other potential errors relate to:
    * Using incorrect CSS syntax in media queries.
    * Misunderstanding the precedence of logical operators (`and`, `or`, `not`).
    * Incorrectly specifying units or values in media queries.

9. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt: functionality, relationships, logical reasoning, user errors, and debugging. Use clear language and provide concrete examples.

By following this systematic approach, we can thoroughly understand the purpose and implications of the `media_query_exp_test.cc` file within the larger context of the Chromium/Blink rendering engine.
This C++ source code file, `media_query_exp_test.cc`, is a **unit test file** within the Chromium Blink rendering engine. Its primary function is to **test the functionality of the `MediaQueryExp` class and related classes**, which are responsible for representing and manipulating **media query expressions** in CSS.

Here's a breakdown of its functions and relationships:

**1. Core Function: Testing `MediaQueryExp` Functionality**

   - **Creation and Manipulation of `MediaQueryExpValue`:** The file defines helper functions (within the anonymous namespace) to create various types of `MediaQueryExpValue` objects. These represent the values used within media query expressions, such as numbers with units (px, em, rem), identifiers (like `top`), and ratios. Examples:
     - `PxValue(10)` creates a pixel value of 10.
     - `IdentValue(CSSValueID::kTop)` creates an identifier value for `top`.
     - `RatioValue(1, 2)` creates a ratio value of 1/2.
   - **Comparison of Values, Comparisons, and Expressions:** The tests use Google Test (`TEST()` macros) to assert the equality and inequality of these objects. This ensures that the comparison logic within `MediaQueryExpValue`, `MediaQueryExpComparison`, and `MediaQueryExp` is correct.
   - **Serialization of Expressions:** The `Serialize()` tests verify that `MediaQueryExp` objects can be correctly converted into their string representation, which is the format used in CSS. This is crucial for outputting and debugging media queries.
   - **Logical Operations on Expressions:** The tests for `SerializeNode`, `CollectExpressions`, and the node creation functions (`AndNode`, `OrNode`, `NotNode`) focus on how media query expressions can be combined using logical operators (`and`, `or`, `not`) and how to manipulate these complex structures.
   - **Extraction of Expressions:** The `CollectExpressions` test verifies the ability to extract individual `MediaQueryExp` objects from a potentially nested and complex expression tree.
   - **Tracking Units:** The `UnitFlags` test ensures that the code correctly identifies the types of units used within media query expressions (e.g., font-relative, viewport-relative). This information is important for proper evaluation of media queries.
   - **Handling Null Pointers:** The `UtilsNullptrHandling` test checks for robustness by verifying that the code handles null pointers gracefully, preventing crashes.
   - **Resolution Checks:** The `ResolutionChecks` test specifically validates the `IsResolution()` method, ensuring it correctly identifies values that represent screen resolution.

**2. Relationship to JavaScript, HTML, and CSS**

   This test file directly relates to **CSS**. Media queries are a core feature of CSS, allowing styles to be applied conditionally based on characteristics of the user's device or browser.

   - **CSS Syntax:** The `Serialize()` tests directly deal with the string representation of CSS media query syntax (e.g., `width < 10px`, `color`, `(min-width: 100px) and (orientation: landscape)`).
   - **CSS Values and Units:** The helper functions create `MediaQueryExpValue` objects that represent CSS values and units (pixels, ems, rems, viewports, etc.). The tests verify how these values are compared and used in expressions.

   While this specific file doesn't directly manipulate **HTML** or interact with **JavaScript** code, the functionality it tests is essential for how CSS (and therefore the styling of HTML) works in web browsers.

   - **HTML:** Media queries in CSS are used to apply different styles to HTML elements. The correct parsing and evaluation of media query expressions (tested here) determine which styles are ultimately applied to the HTML content.
   - **JavaScript:** JavaScript can interact with media queries through the `window.matchMedia()` method. This allows JavaScript code to programmatically check if a given media query matches the current environment and to react to changes in media query state. The underlying logic for evaluating these queries is what this test file is exercising.

**3. Logical Reasoning and Examples**

   The tests often involve setting up a specific media query expression and then asserting that its properties (like equality with another expression or its serialized string representation) are as expected.

   **Assumption (Input):** We create two `MediaQueryExpValue` objects representing pixel values: one for 10px and another for 20px.

   **Test (Logical Reasoning):**  The `MediaQueryExpTest.ValueEquality` test includes assertions like:
   ```c++
   EXPECT_EQ(PxValue(10), PxValue(10)); // Equal values should be equal
   EXPECT_NE(PxValue(10), PxValue(20)); // Different values should not be equal
   EXPECT_NE(PxValue(10), EmValue(10));  // Different units should not be equal
   ```

   **Output (Expected):** These assertions will pass if the equality operators for `MediaQueryExpValue` are implemented correctly.

   **Another Example (Input):** We create a `MediaQueryExp` representing `width < 10px`.

   **Test (Logical Reasoning):** The `MediaQueryExpTest.Serialize` test includes:
   ```c++
   EXPECT_EQ("width < 10px", RightExp("width", LtCmp(PxValue(10))).Serialize());
   ```

   **Output (Expected):** The `Serialize()` method of the created `MediaQueryExp` should return the string "width < 10px".

**4. User or Programming Common Usage Errors**

   While this is a *test* file, it highlights potential areas where developers might make mistakes when working with media queries:

   - **Incorrect CSS Syntax:** If the parsing logic (tested indirectly here) is flawed, users might write valid CSS media queries that are incorrectly interpreted by the browser.
   - **Misunderstanding Media Query Logic:** Developers might incorrectly combine media query features using `and`, `or`, or `not`, leading to unexpected style application. The tests for logical operations are designed to prevent bugs in this area.
   - **Unit Mismatches:** Comparing values with incompatible units (e.g., comparing pixels to ems without proper conversion) can lead to unexpected results. The `ValueEquality` test with different units highlights this.
   - **Incorrect Range Comparisons:** Mistakes in using `<`, `<=`, `>`, `>=`, or `=` in media query ranges can lead to styles not being applied when expected. The `Serialize` tests for ranges cover these cases.

**5. User Operations Leading to This Code (Debugging Clues)**

   A user's interaction with a web page can indirectly lead to this code being executed (or needing debugging) in several ways:

   1. **Page Load and Rendering:** When a user loads a web page, the browser parses the CSS, including any media queries. The code being tested here is part of that parsing and evaluation process. If a media query behaves unexpectedly, developers might investigate this code.
   2. **Resizing the Browser Window:** Media queries often depend on viewport dimensions. When a user resizes the browser, the browser re-evaluates the media queries, potentially triggering the code being tested.
   3. **Device Orientation Changes (Mobile):** Similar to resizing, changing the orientation of a mobile device triggers media query re-evaluation.
   4. **Zooming:** Browser zoom levels can also affect the evaluation of certain media queries.
   5. **Developer Tools Inspection:** When developers inspect the "Computed" styles of an element in the browser's developer tools, they can see which media queries are currently active and influencing the styles. If a media query is unexpectedly active or inactive, it might indicate a bug in the media query evaluation logic, leading developers to investigate code like this.

   **Debugging Scenario:**

   - **User Action:** A user reports that on a mobile device in portrait mode, the website's layout is broken, but it looks fine in landscape mode.
   - **Developer's Investigation:** The developer examines the CSS and sees media queries targeting different orientations. They suspect a problem with the `orientation: portrait` media query.
   - **Debugging Clue (Relating to this file):** The developer might set breakpoints in the `MediaQueryExp` evaluation code (which this test file exercises) to see how the `orientation` media feature is being parsed and compared to the device's actual orientation. The tests in this file, particularly those involving identifiers (like `portrait` or `landscape`), would be relevant to ensuring this comparison is correct.

In summary, `media_query_exp_test.cc` is a crucial part of ensuring the correctness and reliability of CSS media query processing within the Blink rendering engine. It systematically tests various aspects of media query expression creation, comparison, serialization, and logical combination, ultimately contributing to a consistent and predictable web browsing experience.

### 提示词
```
这是目录为blink/renderer/core/css/media_query_exp_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/media_query_exp.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

const CSSNumericLiteralValue& WrapDouble(
    double value,
    CSSPrimitiveValue::UnitType unit_type =
        CSSPrimitiveValue::UnitType::kNumber) {
  return *CSSNumericLiteralValue::Create(value, unit_type);
}

MediaQueryExpValue IdentValue(CSSValueID id) {
  return MediaQueryExpValue(id);
}

MediaQueryExpValue RatioValue(unsigned numerator, unsigned denominator) {
  return MediaQueryExpValue(WrapDouble(numerator), WrapDouble(denominator));
}

MediaQueryExpValue PxValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kPixels));
}

MediaQueryExpValue EmValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kEms));
}

MediaQueryExpValue RemValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kRems));
}

MediaQueryExpValue DvhValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kDynamicViewportHeight));
}

MediaQueryExpValue SvhValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kSmallViewportHeight));
}

MediaQueryExpValue LvhValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kLargeViewportHeight));
}

MediaQueryExpValue VhValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kViewportHeight));
}

MediaQueryExpValue CqhValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kContainerHeight));
}

MediaQueryExpValue CssValue(const CSSPrimitiveValue& value) {
  return MediaQueryExpValue(value);
}

MediaQueryExpValue DppxValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kDotsPerPixel));
}

MediaQueryExpValue CalcValue(const String& syntax, const String& value) {
  ScopedNullExecutionContext execution_context;
  const auto* calc_value =
      DynamicTo<CSSPrimitiveValue>(css_test_helpers::ParseValue(
          *Document::CreateForTest(execution_context.GetExecutionContext()),
          syntax, value));
  EXPECT_NE(calc_value, nullptr);

  return CssValue(*calc_value);
}

MediaQueryExpValue NumericLiteralValue(double value,
                                       CSSPrimitiveValue::UnitType unit) {
  auto* num_lit_val = CSSNumericLiteralValue::Create(value, unit);
  EXPECT_NE(num_lit_val, nullptr);

  return CssValue(*num_lit_val);
}

MediaQueryExpValue InvalidValue() {
  return MediaQueryExpValue();
}

MediaQueryExpComparison NoCmp(MediaQueryExpValue v) {
  return MediaQueryExpComparison(v);
}

MediaQueryExpComparison LtCmp(MediaQueryExpValue v) {
  return MediaQueryExpComparison(v, MediaQueryOperator::kLt);
}

MediaQueryExpComparison LeCmp(MediaQueryExpValue v) {
  return MediaQueryExpComparison(v, MediaQueryOperator::kLe);
}

MediaQueryExpComparison GtCmp(MediaQueryExpValue v) {
  return MediaQueryExpComparison(v, MediaQueryOperator::kGt);
}

MediaQueryExpComparison GeCmp(MediaQueryExpValue v) {
  return MediaQueryExpComparison(v, MediaQueryOperator::kGe);
}

MediaQueryExpComparison EqCmp(MediaQueryExpValue v) {
  return MediaQueryExpComparison(v, MediaQueryOperator::kEq);
}

MediaQueryExp LeftExp(String feature, MediaQueryExpComparison cmp) {
  return MediaQueryExp::Create(AtomicString(feature),
                               MediaQueryExpBounds(cmp, NoCmp(InvalidValue())));
}

MediaQueryExp RightExp(String feature, MediaQueryExpComparison cmp) {
  return MediaQueryExp::Create(AtomicString(feature),
                               MediaQueryExpBounds(NoCmp(InvalidValue()), cmp));
}

MediaQueryExp PairExp(String feature,
                      MediaQueryExpComparison left,
                      MediaQueryExpComparison right) {
  return MediaQueryExp::Create(AtomicString(feature),
                               MediaQueryExpBounds(left, right));
}

const MediaQueryExpNode* FeatureNode(MediaQueryExp expr) {
  return MakeGarbageCollected<MediaQueryFeatureExpNode>(expr);
}

const MediaQueryExpNode* EnclosedFeatureNode(MediaQueryExp expr) {
  return MediaQueryExpNode::Nested(
      MakeGarbageCollected<MediaQueryFeatureExpNode>(expr));
}

const MediaQueryExpNode* NestedNode(const MediaQueryExpNode* child) {
  return MediaQueryExpNode::Nested(child);
}

const MediaQueryExpNode* FunctionNode(const MediaQueryExpNode* child,
                                      const AtomicString& name) {
  return MediaQueryExpNode::Function(child, name);
}

const MediaQueryExpNode* NotNode(const MediaQueryExpNode* operand) {
  return MediaQueryExpNode::Not(operand);
}

const MediaQueryExpNode* AndNode(const MediaQueryExpNode* left,
                                 const MediaQueryExpNode* right) {
  return MediaQueryExpNode::And(left, right);
}

const MediaQueryExpNode* OrNode(const MediaQueryExpNode* left,
                                const MediaQueryExpNode* right) {
  return MediaQueryExpNode::Or(left, right);
}

const MediaQueryExpNode* UnknownNode(String string) {
  return MakeGarbageCollected<MediaQueryUnknownExpNode>(string);
}

}  // namespace

TEST(MediaQueryExpTest, ValuesType) {
  test::TaskEnvironment task_environment;
  EXPECT_TRUE(IdentValue(CSSValueID::kTop).IsId());
  EXPECT_TRUE(PxValue(10).IsNumericLiteralValue());
  EXPECT_TRUE(RatioValue(0, 1).IsRatio());
}

TEST(MediaQueryExpTest, ValueEquality) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(PxValue(10), PxValue(10));
  EXPECT_EQ(EmValue(10), EmValue(10));
  EXPECT_EQ(IdentValue(CSSValueID::kTop), IdentValue(CSSValueID::kTop));
  EXPECT_EQ(IdentValue(CSSValueID::kTop), IdentValue(CSSValueID::kTop));
  EXPECT_EQ(RatioValue(1, 2), RatioValue(1, 2));

  // Mismatched values:
  EXPECT_NE(PxValue(10), PxValue(20));
  EXPECT_NE(EmValue(20), EmValue(10));
  EXPECT_NE(IdentValue(CSSValueID::kTop), IdentValue(CSSValueID::kLeft));
  EXPECT_NE(RatioValue(16, 9), RatioValue(4, 3));

  // Mismatched unit:
  EXPECT_NE(PxValue(10), EmValue(10));

  // Mismatched types:
  EXPECT_NE(PxValue(10), IdentValue(CSSValueID::kTop));
  EXPECT_NE(PxValue(10), RatioValue(1, 2));

  // Mismatched validity:
  EXPECT_NE(PxValue(10), InvalidValue());
  EXPECT_NE(PxValue(0), InvalidValue());
  EXPECT_NE(RatioValue(0, 1), InvalidValue());
}

TEST(MediaQueryExpTest, ComparisonEquality) {
  test::TaskEnvironment task_environment;
  auto px1 = PxValue(10.0);
  auto px2 = PxValue(20.0);

  EXPECT_EQ(LtCmp(px1), LtCmp(px1));

  EXPECT_NE(LtCmp(px1), LeCmp(px1));
  EXPECT_NE(LtCmp(px1), LtCmp(px2));
}

TEST(MediaQueryExpTest, BoundaryEquality) {
  test::TaskEnvironment task_environment;
  auto px1 = PxValue(10.0);
  auto px2 = PxValue(20.0);

  EXPECT_EQ(MediaQueryExpBounds(LtCmp(px1), LeCmp(px1)),
            MediaQueryExpBounds(LtCmp(px1), LeCmp(px1)));

  EXPECT_NE(MediaQueryExpBounds(LtCmp(px1), LeCmp(px1)),
            MediaQueryExpBounds(GtCmp(px1), LeCmp(px1)));
  EXPECT_NE(MediaQueryExpBounds(LtCmp(px1), LeCmp(px1)),
            MediaQueryExpBounds(LtCmp(px1), GeCmp(px1)));
  EXPECT_NE(MediaQueryExpBounds(LtCmp(px1), LeCmp(px2)),
            MediaQueryExpBounds(LtCmp(px1), LeCmp(px1)));
}

TEST(MediaQueryExpTest, ExpEquality) {
  test::TaskEnvironment task_environment;
  auto px1 = PxValue(10.0);
  auto px2 = PxValue(20.0);

  EXPECT_EQ(LeftExp("width", LtCmp(px1)), LeftExp("width", LtCmp(px1)));

  EXPECT_NE(LeftExp("width", LtCmp(px1)), LeftExp("height", LtCmp(px1)));
  EXPECT_NE(LeftExp("width", LtCmp(px2)), LeftExp("width", LtCmp(px1)));
  EXPECT_NE(LeftExp("width", LtCmp(px1)), RightExp("width", LtCmp(px1)));
  EXPECT_NE(LeftExp("width", LtCmp(px1)), LeftExp("width", GtCmp(px1)));
}

TEST(MediaQueryExpTest, Serialize) {
  test::TaskEnvironment task_environment;
  // Boolean feature:
  EXPECT_EQ("color", RightExp("color", NoCmp(InvalidValue())).Serialize());

  auto px = PxValue(10.0);

  // Plain feature:
  EXPECT_EQ("width: 10px", RightExp("width", NoCmp(px)).Serialize());

  // Ranges:
  EXPECT_EQ("width = 10px", RightExp("width", EqCmp(px)).Serialize());
  EXPECT_EQ("width < 10px", RightExp("width", LtCmp(px)).Serialize());
  EXPECT_EQ("width <= 10px", RightExp("width", LeCmp(px)).Serialize());
  EXPECT_EQ("width > 10px", RightExp("width", GtCmp(px)).Serialize());
  EXPECT_EQ("width >= 10px", RightExp("width", GeCmp(px)).Serialize());

  EXPECT_EQ("10px = width", LeftExp("width", EqCmp(px)).Serialize());
  EXPECT_EQ("10px < width", LeftExp("width", LtCmp(px)).Serialize());
  EXPECT_EQ("10px <= width", LeftExp("width", LeCmp(px)).Serialize());
  EXPECT_EQ("10px > width", LeftExp("width", GtCmp(px)).Serialize());
  EXPECT_EQ("10px >= width", LeftExp("width", GeCmp(px)).Serialize());

  EXPECT_EQ(
      "10px < width < 20px",
      PairExp("width", LtCmp(PxValue(10.0)), LtCmp(PxValue(20.0))).Serialize());
  EXPECT_EQ(
      "20px > width > 10px",
      PairExp("width", GtCmp(PxValue(20.0)), GtCmp(PxValue(10.0))).Serialize());
  EXPECT_EQ(
      "10px <= width <= 20px",
      PairExp("width", LeCmp(PxValue(10.0)), LeCmp(PxValue(20.0))).Serialize());
  EXPECT_EQ(
      "20px > width >= 10px",
      PairExp("width", GtCmp(PxValue(20.0)), GeCmp(PxValue(10.0))).Serialize());
}

TEST(MediaQueryExpTest, SerializeNode) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ("width < 10px",
            FeatureNode(RightExp("width", LtCmp(PxValue(10))))->Serialize());

  EXPECT_EQ(
      "(width < 10px)",
      EnclosedFeatureNode(RightExp("width", LtCmp(PxValue(10))))->Serialize());

  EXPECT_EQ(
      "(width < 10px) and (11px >= thing) and (height = 12px)",
      AndNode(
          EnclosedFeatureNode(RightExp("width", LtCmp(PxValue(10)))),
          AndNode(EnclosedFeatureNode(LeftExp("thing", GeCmp(PxValue(11)))),
                  EnclosedFeatureNode(RightExp("height", EqCmp(PxValue(12))))))
          ->Serialize());

  // Same as previous, but with 'or' instead:
  EXPECT_EQ(
      "(width < 10px) or (11px >= thing) or (height = 12px)",
      OrNode(
          EnclosedFeatureNode(RightExp("width", LtCmp(PxValue(10)))),
          OrNode(EnclosedFeatureNode(LeftExp("thing", GeCmp(PxValue(11)))),
                 EnclosedFeatureNode(RightExp("height", EqCmp(PxValue(12))))))
          ->Serialize());

  EXPECT_EQ("not (width < 10px)",
            NotNode(EnclosedFeatureNode(RightExp("width", LtCmp(PxValue(10)))))
                ->Serialize());

  EXPECT_EQ(
      "((width < 10px))",
      NestedNode(EnclosedFeatureNode(RightExp("width", LtCmp(PxValue(10)))))
          ->Serialize());
  EXPECT_EQ("(((width < 10px)))",
            NestedNode(NestedNode(EnclosedFeatureNode(
                           RightExp("width", LtCmp(PxValue(10))))))
                ->Serialize());

  EXPECT_EQ(
      "not ((11px >= thing) and (height = 12px))",
      NotNode(NestedNode(AndNode(
                  EnclosedFeatureNode(LeftExp("thing", GeCmp(PxValue(11)))),
                  EnclosedFeatureNode(RightExp("height", EqCmp(PxValue(12)))))))
          ->Serialize());

  EXPECT_EQ("special(width < 10px)",
            FunctionNode(FeatureNode(RightExp("width", LtCmp(PxValue(10)))),
                         AtomicString("special"))
                ->Serialize());
  EXPECT_EQ(
      "special((width < 10px))",
      FunctionNode(EnclosedFeatureNode(RightExp("width", LtCmp(PxValue(10)))),
                   AtomicString("special"))
          ->Serialize());
  EXPECT_EQ(
      "special((11px >= thing) and (height = 12px))",
      FunctionNode(
          AndNode(EnclosedFeatureNode(LeftExp("thing", GeCmp(PxValue(11)))),
                  EnclosedFeatureNode(RightExp("height", EqCmp(PxValue(12))))),
          AtomicString("special"))
          ->Serialize());
}

TEST(MediaQueryExpTest, CollectExpressions) {
  test::TaskEnvironment task_environment;
  MediaQueryExp width_lt10 = RightExp("width", LtCmp(PxValue(10)));
  MediaQueryExp height_lt10 = RightExp("height", LtCmp(PxValue(10)));

  // (width < 10px)
  {
    HeapVector<MediaQueryExp> expressions;
    EnclosedFeatureNode(width_lt10)->CollectExpressions(expressions);
    ASSERT_EQ(1u, expressions.size());
    EXPECT_EQ(width_lt10, expressions[0]);
  }

  // (width < 10px) and (height < 10px)
  {
    HeapVector<MediaQueryExp> expressions;
    AndNode(EnclosedFeatureNode(width_lt10), EnclosedFeatureNode(height_lt10))
        ->CollectExpressions(expressions);
    ASSERT_EQ(2u, expressions.size());
    EXPECT_EQ(width_lt10, expressions[0]);
    EXPECT_EQ(height_lt10, expressions[1]);
  }

  // (width < 10px) or (height < 10px)
  {
    HeapVector<MediaQueryExp> expressions;
    OrNode(EnclosedFeatureNode(width_lt10), EnclosedFeatureNode(height_lt10))
        ->CollectExpressions(expressions);
    ASSERT_EQ(2u, expressions.size());
    EXPECT_EQ(width_lt10, expressions[0]);
    EXPECT_EQ(height_lt10, expressions[1]);
  }

  // ((width < 10px))
  {
    HeapVector<MediaQueryExp> expressions;
    NestedNode(EnclosedFeatureNode(width_lt10))
        ->CollectExpressions(expressions);
    ASSERT_EQ(1u, expressions.size());
    EXPECT_EQ(width_lt10, expressions[0]);
  }

  // not (width < 10px)
  {
    HeapVector<MediaQueryExp> expressions;
    NotNode(EnclosedFeatureNode(width_lt10))->CollectExpressions(expressions);
    ASSERT_EQ(1u, expressions.size());
    EXPECT_EQ(width_lt10, expressions[0]);
  }

  // unknown
  {
    HeapVector<MediaQueryExp> expressions;
    UnknownNode("foo")->CollectExpressions(expressions);
    EXPECT_EQ(0u, expressions.size());
  }
}

TEST(MediaQueryExpTest, UnitFlags) {
  test::TaskEnvironment task_environment;
  // width < 10px
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kNone,
            RightExp("width", LtCmp(PxValue(10.0))).GetUnitFlags());
  // width < 10em
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kFontRelative,
            RightExp("width", LtCmp(EmValue(10.0))).GetUnitFlags());
  // width < 10rem
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kRootFontRelative,
            RightExp("width", LtCmp(RemValue(10.0))).GetUnitFlags());
  // 10px < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kNone,
            LeftExp("width", LtCmp(PxValue(10.0))).GetUnitFlags());
  // 10em <  width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kFontRelative,
            LeftExp("width", LtCmp(EmValue(10.0))).GetUnitFlags());
  // 10rem < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kRootFontRelative,
            LeftExp("width", LtCmp(RemValue(10.0))).GetUnitFlags());
  // 10dvh < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kDynamicViewport,
            LeftExp("width", LtCmp(DvhValue(10.0))).GetUnitFlags());
  // 10svh < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kStaticViewport,
            LeftExp("width", LtCmp(SvhValue(10.0))).GetUnitFlags());
  // 10lvh < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kStaticViewport,
            LeftExp("width", LtCmp(LvhValue(10.0))).GetUnitFlags());
  // 10vh < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kStaticViewport,
            LeftExp("width", LtCmp(VhValue(10.0))).GetUnitFlags());
  // 10cqh < width
  EXPECT_EQ(MediaQueryExpValue::UnitFlags::kContainer,
            LeftExp("width", LtCmp(CqhValue(10.0))).GetUnitFlags());

  // width < calc(10em + 10dvh)
  ScopedNullExecutionContext execution_context;
  const auto* calc_value =
      DynamicTo<CSSPrimitiveValue>(css_test_helpers::ParseValue(
          *Document::CreateForTest(execution_context.GetExecutionContext()),
          "<length>", "calc(10em + 10dvh)"));
  ASSERT_TRUE(calc_value);
  EXPECT_EQ(
      static_cast<unsigned>(MediaQueryExpValue::UnitFlags::kFontRelative |
                            MediaQueryExpValue::UnitFlags::kDynamicViewport),
      RightExp("width", LtCmp(CssValue(*calc_value))).GetUnitFlags());
}

TEST(MediaQueryExpTest, UtilsNullptrHandling) {
  test::TaskEnvironment task_environment;
  MediaQueryExp exp = RightExp("width", LtCmp(PxValue(10)));

  EXPECT_FALSE(MediaQueryExpNode::Nested(nullptr));
  EXPECT_FALSE(MediaQueryExpNode::Function(nullptr, AtomicString("test")));
  EXPECT_FALSE(MediaQueryExpNode::Not(nullptr));
  EXPECT_FALSE(MediaQueryExpNode::And(nullptr, FeatureNode(exp)));
  EXPECT_FALSE(MediaQueryExpNode::And(FeatureNode(exp), nullptr));
  EXPECT_FALSE(MediaQueryExpNode::And(nullptr, nullptr));
  EXPECT_FALSE(MediaQueryExpNode::Or(nullptr, FeatureNode(exp)));
  EXPECT_FALSE(MediaQueryExpNode::Or(FeatureNode(exp), nullptr));
  EXPECT_FALSE(MediaQueryExpNode::Or(nullptr, nullptr));
}

TEST(MediaQueryExpTest, ResolutionChecks) {
  test::TaskEnvironment task_environment;
  EXPECT_TRUE(DppxValue(3).IsResolution());
  EXPECT_TRUE(CalcValue("<resolution>", "calc(96dpi)").IsResolution());

  EXPECT_FALSE(InvalidValue().IsResolution());
  EXPECT_FALSE(PxValue(10).IsResolution());
  EXPECT_FALSE(RatioValue(3, 5).IsResolution());
  EXPECT_FALSE(CalcValue("<length>", "calc(13px)").IsResolution());
  EXPECT_FALSE(NumericLiteralValue(3, CSSPrimitiveValue::UnitType::kPixels)
                   .IsResolution());
}

}  // namespace blink
```