Response:
My thinking process to arrive at the summary of `computed_style_test.cc` goes like this:

1. **Understand the File Name and Location:** The file is named `computed_style_test.cc` and resides in `blink/renderer/core/style/`. This immediately tells me it's a *test* file specifically for the `ComputedStyle` class within Blink's rendering engine. The `.cc` extension confirms it's C++ code.

2. **Scan the Includes:** The included headers give clues about the file's purpose. I look for recurring themes and important classes:
    * `computed_style.h`: This is the primary class being tested.
    * `testing/gtest/include/gtest/gtest.h`: Indicates the use of the Google Test framework.
    * `css/...`: A large number of CSS-related headers (e.g., `CSSDynamicRangeLimitMixValue`, `CSSFontSelector`, `CSSGradientValue`, etc.). This suggests the tests are focused on how `ComputedStyle` interacts with and represents CSS properties and values.
    * `style_resolver.h`, `style_cascade.h`:  These indicate the testing of how styles are resolved and cascaded, which is directly related to `ComputedStyle`.
    * `dom/document.h`, `html/html_body_element.h`:  Show that the tests involve the DOM structure, as `ComputedStyle` is applied to DOM elements.
    * `layout/layout_object.h`:  Connects `ComputedStyle` to the layout process.
    * `style/...`: Other style-related headers like `clip_path_operation.h`, `shape_value.h`, `style_difference.h` point to tests for specific style features.

3. **Identify the Core Testing Class:** The code defines a test fixture class `ComputedStyleTest` inheriting from `testing::Test`. This is the structure for organizing the tests.

4. **Analyze the `SetUp` Method:** The `SetUp` method initializes a `DummyPageHolder` and retrieves the initial `ComputedStyle`. This is standard practice in Blink tests to create a minimal testing environment.

5. **Examine the `TEST_F` Macros:**  These are the individual test cases. I start reading through them, looking for patterns and what aspects of `ComputedStyle` are being tested:
    * **Equality Comparisons (`EXPECT_EQ`):** Many tests compare `ComputedStyle` objects after setting different properties. This tells me the tests are verifying the correct storage and comparison logic for various style properties.
    * **Boolean Checks (`EXPECT_TRUE`, `EXPECT_FALSE`):**  Tests for flags and states within `ComputedStyle`, such as `IsStackingContextWithoutContainment`, `HasOutline`, `HasBorder`, and animation-related flags.
    * **Specific Property Setters:** I see calls to `builder.Set...()` for various CSS properties (e.g., `SetShapeOutside`, `SetClipPath`, `SetForcesStackingContext`, `SetTransform`, `SetOpacity`, `SetBorderWidth`, `SetBorderStyle`, `SetVariableValue`). This confirms that the tests cover setting and verifying the values of different CSS properties within `ComputedStyle`.
    * **Style Difference (`StyleDifference`):** Tests involving `VisualInvalidationDiff` and checking for `TransformChanged`, `CompositingReasonsChanged`. This shows the tests are validating how changes in `ComputedStyle` are detected and classified for rendering invalidation purposes.
    * **Custom Properties:**  Tests specifically for CSS custom properties (variables), including equality checks and inheritance behavior.
    * **Animation Flags:** Dedicated tests for various animation-related flags in `ComputedStyle`.

6. **Group and Categorize the Test Functionality:** As I read the tests, I start mentally grouping them by the features they are testing:
    * Basic property setting and equality
    * Stacking context behavior
    * Shape-outside and clip-path
    * Transform and animation properties
    * Border properties
    * Cursor properties
    * Style difference calculation
    * Custom properties (variables)
    * Animation flags

7. **Formulate a High-Level Summary:** Based on the identified categories, I can now write a concise summary of the file's functionality. I focus on the *what* and *why* of the tests.

8. **Identify Relationships to Web Technologies:** I consider how the tested features relate to JavaScript, HTML, and CSS:
    * **CSS:** The most direct relationship is with CSS properties and values. The tests verify how these are represented in `ComputedStyle`.
    * **HTML:** `ComputedStyle` is applied to HTML elements. The tests implicitly involve how styles are associated with the DOM.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the properties being tested are often manipulated by JavaScript through the CSSOM (CSS Object Model).

9. **Consider Logic and Assumptions:** I look for examples of tests that involve some level of logical reasoning or implicit assumptions:
    * Stacking context tests involve understanding the rules for creating stacking contexts.
    * Tests involving `UsedTransformStyle3D` demonstrate how certain properties can influence the final computed value.

10. **Identify Potential Usage Errors:** I think about common mistakes developers might make when working with CSS or manipulating styles programmatically that these tests might be indirectly preventing:
    * Incorrectly setting or comparing style properties.
    * Not understanding the implications of properties on stacking contexts or compositing.
    * Issues with custom property inheritance.

11. **Refine and Organize the Summary:** I structure the summary logically, starting with the main purpose and then breaking it down into more specific areas. I use clear and concise language. I ensure I address all aspects of the prompt (functionality, relationships, logic, errors).

By following this systematic approach, I can effectively analyze the code and generate a comprehensive and accurate summary of its functionality. The key is to understand the context, identify the core components being tested, and then infer the purpose and implications of the individual test cases.
好的，这是对提供的 `computed_style_test.cc` 文件第一部分的分析和归纳。

**文件功能归纳:**

`computed_style_test.cc` 文件是 Chromium Blink 引擎中用于测试 `ComputedStyle` 类的单元测试文件。它的主要功能是验证 `ComputedStyle` 类的各种方法和属性是否按预期工作，确保在不同的 CSS 属性组合和状态下，`ComputedStyle` 对象能够正确地存储、比较和计算样式信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ComputedStyle` 类在 Blink 引擎中扮演着至关重要的角色，它代表了元素最终计算出的样式。因此，这个测试文件与 JavaScript, HTML, 和 CSS 都有着密切的关系：

* **CSS (核心关系):**  测试文件直接测试了各种 CSS 属性在 `ComputedStyle` 中的表示和行为。
    * **例子:** `TEST_F(ComputedStyleTest, ShapeOutsideBoxEqual)` 测试了 `shape-outside` 属性，该属性是 CSS Shapes 模块的一部分。它验证了当两个元素的 `shape-outside` 属性值相同时，它们的 `ComputedStyle` 对象是否相等。
    * **例子:**  多个测试用例涉及到 `border` 相关的属性 (`border-width`, `border-style`)，例如 `TEST_F(ComputedStyleTest, BorderWidth)` 和 `TEST_F(ComputedStyleTest, BorderStyle)`，验证了这些 CSS 属性的设置和比较逻辑。
    * **例子:**  测试用例 `TEST_F(ComputedStyleTest, CursorList)` 测试了 `cursor` 属性，它允许开发者指定鼠标指针的样式。

* **HTML:** `ComputedStyle` 对象是与 HTML 元素关联的。测试文件通过 `DummyPageHolder` 创建了一个简单的文档环境，并隐式地与 HTML 元素相关联。
    * **例子:** 虽然代码中没有直接创建 HTML 元素，但 `ComputedStyle` 的计算结果最终会应用到 HTML 元素上，影响元素的渲染。例如，测试 `forces_stacking_context` 会影响元素的层叠顺序，这直接关系到 HTML 元素的展示。

* **JavaScript:** JavaScript 可以通过 DOM API (例如 `element.style`, `window.getComputedStyle`) 来访问和操作元素的样式。`ComputedStyle` 对象是 `window.getComputedStyle` 返回的结果的核心部分。
    * **例子:**  当 JavaScript 代码使用 `window.getComputedStyle(element).getPropertyValue('opacity')` 获取元素的 `opacity` 值时，引擎内部会访问该元素的 `ComputedStyle` 对象，并返回相应的属性值。  测试文件中对 `opacity` 动画相关的测试 (`TEST_F(ComputedStyleTest, UpdatePropertySpecificDifferencesCompositingReasonsOpacity)`) 间接验证了 JavaScript 获取到的值的正确性。
    * **例子:** JavaScript 可以通过设置元素的 style 属性来改变元素的样式，这些改变最终会反映到 `ComputedStyle` 对象上。 例如，设置 `element.style.transform = 'scale(2)'` 会影响该元素的 `ComputedStyle` 中的 `transform` 属性。

**逻辑推理、假设输入与输出:**

很多测试用例都涉及逻辑推理，通过设置不同的属性值，然后断言 `ComputedStyle` 对象的状态或比较结果。

* **例子 (Stacking Context):**
    * **假设输入:** 创建一个 `ComputedStyleBuilder` 对象，并调用 `SetForcesStackingContext(true)`。
    * **逻辑推理:**  如果 `forces_stacking_context` 设置为 true，那么该元素应该创建一个新的 stacking context。
    * **输出:** `EXPECT_TRUE(style->IsStackingContextWithoutContainment());` 断言该 `ComputedStyle` 对象指示这是一个无需 containment 的 stacking context。

* **例子 (Border Width):**
    * **假设输入:** 先设置 `border-bottom-width` 为 5，但不设置 `border-bottom-style`。
    * **逻辑推理:**  如果没有设置 `border-style`，那么 `border-width` 应该被视为 0。
    * **输出:** `EXPECT_EQ(style->BorderBottomWidth(), 0);` 断言 `borderBottomWidth()` 返回 0。
    * **假设输入:** 在上面的基础上，再设置 `border-bottom-style` 为 `solid`。
    * **逻辑推理:**  现在 `border-style` 已设置，`border-width` 应该生效。
    * **输出:** `EXPECT_EQ(style->BorderBottomWidth(), 5);` 断言 `borderBottomWidth()` 返回之前设置的 5。

**用户或编程常见的使用错误举例说明:**

虽然这个文件是测试代码，但它测试的功能与开发者在使用 CSS 和 JavaScript 操作样式时容易犯的错误息息相关。

* **错误 1: 误以为只设置 `border-width` 就能显示边框。**
    * **测试体现:** `TEST_F(ComputedStyleTest, BorderWidth)` 验证了只有同时设置了 `border-style`，`border-width` 才会生效。这是开发者常见的错误，忘记设置 `border-style` 导致边框不显示。

* **错误 2: 不理解 stacking context 的创建条件。**
    * **测试体现:**  `TEST_F(ComputedStyleTest, ForcesStackingContext)` 和其他 stacking context 相关的测试验证了哪些 CSS 属性会触发 stacking context 的创建。开发者可能不清楚哪些属性会导致元素成为 stacking context，从而在布局上出现意外的层叠效果。

* **错误 3:  对动画属性的理解不准确，导致动画效果不生效或影响性能。**
    * **测试体现:** 多个以 `TEST_F(ComputedStyleTest, UpdatePropertySpecificDifferencesRespects...)` 开头的测试，以及 `TEST_F(ComputedStyleTest, AnimationFlags)`， 验证了与动画相关的标志位的正确设置。 开发者可能错误地使用了动画属性，或者不了解动画对 compositing 的影响。

* **错误 4:  在使用 CSS 自定义属性 (变量) 时，对继承规则理解不透彻。**
    * **测试体现:**  `TEST_F(ComputedStyleTest, CustomPropertiesInheritance_FastPath)` 和 `TEST_F(ComputedStyleTest, CustomPropertiesInheritance_StyleRecalc)` 测试了自定义属性的继承行为和对样式重计算的影响。开发者可能在复杂的组件结构中使用自定义属性时，遇到继承问题或性能问题。

**第一部分功能归纳:**

总而言之，`computed_style_test.cc` 的第一部分主要集中在测试 `ComputedStyle` 对象的基础属性和行为，包括：

* **基本属性的设置和比较:** 例如 `shape-outside`, `clip-path`。
* **Stacking context 的创建:** 测试了 `forces-stacking-context` 和 `contain` 属性对 stacking context 的影响。
* **Style 克隆和继承行为:** 验证了在克隆 `ComputedStyle` 对象时，某些非继承属性的处理方式。
* **伪元素样式的管理:**  测试了 `ComputedStyle` 如何存储和表示伪元素样式。
* **样式差异的计算:**  测试了 `VisualInvalidationDiff` 方法，用于判断两个 `ComputedStyle` 对象之间的差异，特别是与动画和 compositing 相关的差异。
* **边框属性的处理:**  测试了 `border-width` 和 `border-style` 的交互和 `hasOutline` 及 `hasBorder` 的判断。
* **光标属性的存储和比较。**
* **动画相关标志位的设置和测试。**
* **CSS 自定义属性 (变量) 的基本相等性比较。**

这部分测试覆盖了 `ComputedStyle` 类中一些核心且常用的功能，为后续更复杂的样式计算和渲染提供了基础保障。

### 提示词
```
这是目录为blink/renderer/core/style/computed_style_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/style/computed_style.h"

#include "base/memory/values_equivalent.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_dynamic_range_limit_mix_value.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_style_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/style_adjuster.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_cascade.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/clip_path_operation.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/shape_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/shape_value.h"
#include "third_party/blink/renderer/core/style/style_difference.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/style/style_initial_data.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/transforms/scale_transform_operation.h"
#include "ui/base/ui_base_features.h"

namespace blink {

class ComputedStyleTest : public testing::Test {
 protected:
  void SetUp() override {
    dummy_page_holder_ =
        std::make_unique<DummyPageHolder>(gfx::Size(0, 0), nullptr);
    initial_style_ = ComputedStyle::GetInitialStyleSingleton();
  }

  Document& GetDocument() { return dummy_page_holder_->GetDocument(); }

  const ComputedStyle* InitialComputedStyle() { return initial_style_; }

  ComputedStyleBuilder CreateComputedStyleBuilder() {
    return ComputedStyleBuilder(*initial_style_);
  }

  ComputedStyleBuilder CreateComputedStyleBuilderFrom(
      const ComputedStyle& style) {
    return ComputedStyleBuilder(style);
  }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
  Persistent<const ComputedStyle> initial_style_;
};

TEST_F(ComputedStyleTest, ShapeOutsideBoxEqual) {
  auto* shape1 = MakeGarbageCollected<ShapeValue>(CSSBoxType::kContent);
  auto* shape2 = MakeGarbageCollected<ShapeValue>(CSSBoxType::kContent);
  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();
  builder1.SetShapeOutside(shape1);
  builder2.SetShapeOutside(shape2);
  EXPECT_EQ(*builder1.TakeStyle(), *builder2.TakeStyle());
}

TEST_F(ComputedStyleTest, ShapeOutsideCircleEqual) {
  scoped_refptr<BasicShapeCircle> circle1 = BasicShapeCircle::Create();
  scoped_refptr<BasicShapeCircle> circle2 = BasicShapeCircle::Create();
  auto* shape1 = MakeGarbageCollected<ShapeValue>(std::move(circle1),
                                                  CSSBoxType::kContent);
  auto* shape2 = MakeGarbageCollected<ShapeValue>(std::move(circle2),
                                                  CSSBoxType::kContent);
  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();
  builder1.SetShapeOutside(shape1);
  builder2.SetShapeOutside(shape2);
  EXPECT_EQ(*builder1.TakeStyle(), *builder2.TakeStyle());
}

TEST_F(ComputedStyleTest, ClipPathEqual) {
  scoped_refptr<BasicShapeCircle> shape = BasicShapeCircle::Create();
  ShapeClipPathOperation* path1 = MakeGarbageCollected<ShapeClipPathOperation>(
      shape, GeometryBox::kBorderBox);
  ShapeClipPathOperation* path2 = MakeGarbageCollected<ShapeClipPathOperation>(
      shape, GeometryBox::kBorderBox);
  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();
  builder1.SetClipPath(path1);
  builder2.SetClipPath(path2);
  EXPECT_EQ(*builder1.TakeStyle(), *builder2.TakeStyle());
}

TEST_F(ComputedStyleTest, ForcesStackingContext) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetForcesStackingContext(true);
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_TRUE(style->IsStackingContextWithoutContainment());
}

TEST_F(ComputedStyleTest, Preserve3dForceStackingContext) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetTransformStyle3D(ETransformStyle3D::kPreserve3d);
  builder.SetOverflowX(EOverflow::kHidden);
  builder.SetOverflowY(EOverflow::kHidden);
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_EQ(ETransformStyle3D::kFlat, style->UsedTransformStyle3D());
  EXPECT_TRUE(style->IsStackingContextWithoutContainment());
}

TEST_F(ComputedStyleTest, LayoutContainmentStackingContext) {
  const ComputedStyle* style = InitialComputedStyle();
  EXPECT_FALSE(style->IsStackingContextWithoutContainment());

  ComputedStyleBuilder builder(*style);
  builder.SetContain(kContainsLayout);
  style = builder.TakeStyle();
  // Containment doesn't change IsStackingContextWithoutContainment
  EXPECT_FALSE(style->IsStackingContextWithoutContainment());
}

TEST_F(ComputedStyleTest, IsStackingContextWithoutContainmentAfterClone) {
  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  builder1.SetForcesStackingContext(true);
  const ComputedStyle* style1 = builder1.TakeStyle();
  EXPECT_TRUE(style1->IsStackingContextWithoutContainment());

  ComputedStyleBuilder builder2(*style1);
  const ComputedStyle* style2 = builder2.TakeStyle();
  EXPECT_TRUE(style2->IsStackingContextWithoutContainment());

  // Verify that the cached value for IsStackingContextWithoutContainment
  // isn't copied from `style1`.
  ComputedStyleBuilder builder3(*style1);
  builder3.SetForcesStackingContext(false);
  const ComputedStyle* style3 = builder3.TakeStyle();
  EXPECT_FALSE(style3->IsStackingContextWithoutContainment());
}

TEST_F(ComputedStyleTest, DerivedFlagCopyNonInherited) {
  {
    ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
    builder1.SetForcesStackingContext(true);
    const ComputedStyle* style1 = builder1.TakeStyle();
    EXPECT_TRUE(style1->IsStackingContextWithoutContainment());

    // Whether the style is a stacking context or not should not be copied
    // from the style we're cloning.
    ComputedStyleBuilder builder2 = CreateComputedStyleBuilderFrom(*style1);
    const ComputedStyle* style2 = builder2.TakeStyle();
    EXPECT_TRUE(style2->IsStackingContextWithoutContainment());
  }

  // The same as above, except that IsStackingContextWithoutContainment is
  // expected to be false.
  {
    ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
    const ComputedStyle* style1 = builder1.TakeStyle();
    EXPECT_FALSE(style1->IsStackingContextWithoutContainment());

    ComputedStyleBuilder builder2 = CreateComputedStyleBuilderFrom(*style1);
    const ComputedStyle* style2 = builder2.TakeStyle();
    EXPECT_FALSE(style2->IsStackingContextWithoutContainment());
  }

  // The same as the first case, except builder2 sets
  // SetForcesStackingContext(false) after cloning.
  {
    ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
    builder1.SetForcesStackingContext(true);
    const ComputedStyle* style1 = builder1.TakeStyle();
    EXPECT_TRUE(style1->IsStackingContextWithoutContainment());

    ComputedStyleBuilder builder2 = CreateComputedStyleBuilderFrom(*style1);
    builder2.SetForcesStackingContext(false);
    const ComputedStyle* style2 = builder2.TakeStyle();
    // Value copied from 'style1' must not persist.
    EXPECT_FALSE(style2->IsStackingContextWithoutContainment());
  }
}

TEST_F(ComputedStyleTest, TrackedPseudoStyle) {
  for (uint8_t pseudo_id_int = kFirstPublicPseudoId;
       pseudo_id_int <= kLastTrackedPublicPseudoId; pseudo_id_int++) {
    PseudoId pseudo_id = static_cast<PseudoId>(pseudo_id_int);
    MatchResult match_result;
    match_result.SetHasPseudoElementStyle(pseudo_id);

    ComputedStyleBuilder builder = CreateComputedStyleBuilder();
    builder.SetPseudoElementStyles(match_result.PseudoElementStyles());
    const ComputedStyle* style = builder.TakeStyle();

    EXPECT_TRUE(style->HasPseudoElementStyle(pseudo_id));
    EXPECT_TRUE(style->HasAnyPseudoElementStyles());
  }
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesRespectsTransformAnimation) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentTransformAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.TransformChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsTransform) {
  TransformOperations operations;
  // An operation is necessary since having either a non-empty transform list
  // or a transform animation will set HasTransform();
  operations.Operations().push_back(
      MakeGarbageCollected<ScaleTransformOperation>(
          1, 1, TransformOperation::kScale));

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetTransform(operations);
  const ComputedStyle* style = builder.TakeStyle();

  builder = ComputedStyleBuilder(*style);
  builder.SetHasCurrentTransformAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_FALSE(diff.TransformChanged());
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesRespectsScaleAnimation) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentScaleAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.TransformChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesRespectsRotateAnimation) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentRotateAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.TransformChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesRespectsTranslateAnimation) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentTranslateAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.TransformChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsOpacity) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentOpacityAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsFilter) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentFilterAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsBackdropFilter) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetHasCurrentBackdropFilterAnimation(true);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsBackfaceVisibility) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetBackfaceVisibility(EBackfaceVisibility::kHidden);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsWillChange) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetBackfaceVisibility(EBackfaceVisibility::kHidden);
  builder.SetWillChangeProperties({CSSPropertyID::kOpacity});
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsUsedStylePreserve3D) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetTransformStyle3D(ETransformStyle3D::kPreserve3d);
  const ComputedStyle* style = builder.TakeStyle();

  builder = ComputedStyleBuilder(*style);
  // This induces a flat used transform style.
  builder.SetOpacity(0.5);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsOverflow) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  builder.SetOverflowX(EOverflow::kHidden);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest,
       UpdatePropertySpecificDifferencesCompositingReasonsContainsPaint) {
  const ComputedStyle* style = InitialComputedStyle();
  ComputedStyleBuilder builder(*style);
  // This induces a flat used transform style.
  builder.SetContain(kContainsPaint);
  const ComputedStyle* other = builder.TakeStyle();

  StyleDifference diff = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_TRUE(diff.CompositingReasonsChanged());
}

TEST_F(ComputedStyleTest, HasOutlineWithCurrentColor) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_FALSE(style->HasOutline());
  EXPECT_FALSE(style->HasOutlineWithCurrentColor());

  builder = CreateComputedStyleBuilder();
  builder.SetOutlineColor(StyleColor::CurrentColor());
  builder.SetOutlineWidth(5);
  style = builder.TakeStyle();
  EXPECT_FALSE(style->HasOutlineWithCurrentColor());

  builder = CreateComputedStyleBuilder();
  builder.SetOutlineColor(StyleColor::CurrentColor());
  builder.SetOutlineWidth(5);
  builder.SetOutlineStyle(EBorderStyle::kSolid);
  style = builder.TakeStyle();
  EXPECT_TRUE(style->HasOutlineWithCurrentColor());
}

TEST_F(ComputedStyleTest, BorderWidth) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetBorderBottomWidth(5);
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_EQ(style->BorderBottomWidth(), 0);

  builder = ComputedStyleBuilder(*style);
  builder.SetBorderBottomStyle(EBorderStyle::kSolid);
  style = builder.TakeStyle();
  EXPECT_EQ(style->BorderBottomWidth(), 5);
}

TEST_F(ComputedStyleTest, CursorList) {
  auto* gradient = MakeGarbageCollected<cssvalue::CSSLinearGradientValue>(
      nullptr, nullptr, nullptr, nullptr, nullptr, cssvalue::kRepeating);

  auto* image_value = MakeGarbageCollected<StyleGeneratedImage>(
      *gradient, StyleGeneratedImage::ContainerSizes());
  auto* other_image_value = MakeGarbageCollected<StyleGeneratedImage>(
      *gradient, StyleGeneratedImage::ContainerSizes());

  EXPECT_TRUE(base::ValuesEquivalent(image_value, other_image_value));

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.AddCursor(image_value, false);
  const ComputedStyle* style = builder.TakeStyle();

  builder = CreateComputedStyleBuilder();
  builder.AddCursor(other_image_value, false);
  const ComputedStyle* other = builder.TakeStyle();
  EXPECT_EQ(*style, *other);
}

#define UPDATE_STYLE(style_object, setter, value)      \
  {                                                    \
    ComputedStyleBuilder style_builder(*style_object); \
    style_builder.setter(value);                       \
    style_object = style_builder.TakeStyle();          \
  }

TEST_F(ComputedStyleTest, BorderStyle) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetBorderLeftStyle(EBorderStyle::kSolid);
  builder.SetBorderTopStyle(EBorderStyle::kSolid);
  builder.SetBorderRightStyle(EBorderStyle::kSolid);
  builder.SetBorderBottomStyle(EBorderStyle::kSolid);
  const ComputedStyle* style = builder.CloneStyle();
  const ComputedStyle* other = builder.TakeStyle();
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderLeftWidth, 1);
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(other, SetBorderLeftWidth, 1);
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderTopWidth, 1);
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(other, SetBorderTopWidth, 1);
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderRightWidth, 1);
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(other, SetBorderRightWidth, 1);
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderBottomWidth, 1);
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(other, SetBorderBottomWidth, 1);
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderLeftStyle, EBorderStyle::kHidden);
  EXPECT_EQ(LayoutUnit(), style->BorderLeftWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderLeftStyle, EBorderStyle::kNone);
  EXPECT_EQ(LayoutUnit(), style->BorderLeftWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderLeftStyle, EBorderStyle::kSolid);
  EXPECT_EQ(LayoutUnit(1), style->BorderLeftWidth());
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderTopStyle, EBorderStyle::kHidden);
  EXPECT_EQ(LayoutUnit(), style->BorderTopWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderTopStyle, EBorderStyle::kNone);
  EXPECT_EQ(LayoutUnit(), style->BorderTopWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderTopStyle, EBorderStyle::kSolid);
  EXPECT_EQ(LayoutUnit(1), style->BorderTopWidth());
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderRightStyle, EBorderStyle::kHidden);
  EXPECT_EQ(LayoutUnit(), style->BorderRightWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderRightStyle, EBorderStyle::kNone);
  EXPECT_EQ(LayoutUnit(), style->BorderRightWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderRightStyle, EBorderStyle::kSolid);
  EXPECT_EQ(LayoutUnit(1), style->BorderRightWidth());
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  UPDATE_STYLE(style, SetBorderBottomStyle, EBorderStyle::kHidden);
  EXPECT_EQ(LayoutUnit(), style->BorderBottomWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderBottomStyle, EBorderStyle::kNone);
  EXPECT_EQ(LayoutUnit(), style->BorderBottomWidth());
  EXPECT_FALSE(style->BorderSizeEquals(*other));
  UPDATE_STYLE(style, SetBorderBottomStyle, EBorderStyle::kSolid);
  EXPECT_EQ(LayoutUnit(1), style->BorderBottomWidth());
  EXPECT_TRUE(style->BorderSizeEquals(*other));

  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderTopStyle, EBorderStyle::kHidden);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderRightStyle, EBorderStyle::kHidden);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderBottomStyle, EBorderStyle::kHidden);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderLeftStyle, EBorderStyle::kHidden);
  EXPECT_FALSE(style->HasBorder());

  UPDATE_STYLE(style, SetBorderTopStyle, EBorderStyle::kSolid);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderRightStyle, EBorderStyle::kSolid);
  UPDATE_STYLE(style, SetBorderBottomStyle, EBorderStyle::kSolid);
  UPDATE_STYLE(style, SetBorderLeftStyle, EBorderStyle::kSolid);
  EXPECT_TRUE(style->HasBorder());

  UPDATE_STYLE(style, SetBorderTopStyle, EBorderStyle::kNone);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderRightStyle, EBorderStyle::kNone);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderBottomStyle, EBorderStyle::kNone);
  EXPECT_TRUE(style->HasBorder());
  UPDATE_STYLE(style, SetBorderLeftStyle, EBorderStyle::kNone);
  EXPECT_FALSE(style->HasBorder());
}

#define TEST_ANIMATION_FLAG(flag, inherited)                     \
  do {                                                           \
    auto builder = CreateComputedStyleBuilder();                 \
    builder.Set##flag(true);                                     \
    const auto* style = builder.TakeStyle();                     \
    EXPECT_TRUE(style->flag());                                  \
    const auto* other = InitialComputedStyle();                  \
    EXPECT_FALSE(other->flag());                                 \
    EXPECT_EQ(ComputedStyle::Difference::inherited,              \
              ComputedStyle::ComputeDifference(style, other));   \
    auto diff = style->VisualInvalidationDiff(document, *other); \
    EXPECT_TRUE(diff.HasDifference());                           \
    EXPECT_TRUE(diff.CompositingReasonsChanged());               \
  } while (false)

#define TEST_ANIMATION_FLAG_NO_DIFF(flag)                        \
  do {                                                           \
    auto builder = CreateComputedStyleBuilder();                 \
    builder.Set##flag(true);                                     \
    const auto* style = builder.TakeStyle();                     \
    EXPECT_TRUE(style->flag());                                  \
    const auto* other = InitialComputedStyle();                  \
    EXPECT_FALSE(other->flag());                                 \
    EXPECT_EQ(ComputedStyle::Difference::kEqual,                 \
              ComputedStyle::ComputeDifference(style, other));   \
    auto diff = style->VisualInvalidationDiff(document, *other); \
    EXPECT_FALSE(diff.HasDifference());                          \
    EXPECT_FALSE(diff.CompositingReasonsChanged());              \
  } while (false)

TEST_F(ComputedStyleTest, AnimationFlags) {
  Document& document = GetDocument();
  TEST_ANIMATION_FLAG(HasCurrentTransformAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(HasCurrentScaleAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(HasCurrentRotateAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(HasCurrentTranslateAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(HasCurrentOpacityAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(HasCurrentFilterAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(HasCurrentBackdropFilterAnimation, kNonInherited);
  TEST_ANIMATION_FLAG(SubtreeWillChangeContents, kInherited);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningTransformAnimationOnCompositor);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningScaleAnimationOnCompositor);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningRotateAnimationOnCompositor);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningTranslateAnimationOnCompositor);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningOpacityAnimationOnCompositor);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningFilterAnimationOnCompositor);
  TEST_ANIMATION_FLAG_NO_DIFF(IsRunningBackdropFilterAnimationOnCompositor);
}

TEST_F(ComputedStyleTest, CustomPropertiesEqual_Values) {
  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "0px",
                                     false);

  using UnitType = CSSPrimitiveValue::UnitType;

  const auto* value1 = CSSNumericLiteralValue::Create(1.0, UnitType::kPixels);
  const auto* value2 = CSSNumericLiteralValue::Create(2.0, UnitType::kPixels);
  const auto* value3 = CSSNumericLiteralValue::Create(1.0, UnitType::kPixels);

  Vector<AtomicString> properties;
  properties.push_back("--x");

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetVariableValue(AtomicString("--x"), value1, false);
  const ComputedStyle* style1 = builder.TakeStyle();

  builder = CreateComputedStyleBuilder();
  builder.SetVariableValue(AtomicString("--x"), value1, false);
  const ComputedStyle* style2 = builder.TakeStyle();
  EXPECT_TRUE(style1->CustomPropertiesEqual(properties, *style2));

  builder = CreateComputedStyleBuilder();
  builder.SetVariableValue(AtomicString("--x"), value3, false);
  style2 = builder.TakeStyle();
  EXPECT_TRUE(style1->CustomPropertiesEqual(properties, *style2));

  builder = CreateComputedStyleBuilder();
  builder.SetVariableValue(AtomicString("--x"), value2, false);
  style2 = builder.TakeStyle();
  EXPECT_FALSE(style1->CustomPropertiesEqual(properties, *style2));
}

TEST_F(ComputedStyleTest, CustomPropertiesEqual_Data) {
  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "0px",
                                     false);

  const ComputedStyle* style1;
  const ComputedStyle* style2;

  auto* value1 = css_test_helpers::CreateVariableData("foo");
  auto* value2 = css_test_helpers::CreateVariableData("bar");
  auto* value3 = css_test_helpers::CreateVariableData("foo");

  Vector<AtomicString> properties;
  properties.push_back("--x");

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--x"), value1, false);
  style1 = builder.TakeStyle();

  builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--x"), value1, false);
  style2 = builder.TakeStyle();
  EXPECT_TRUE(style1->CustomPropertiesEqual(properties, *style2));

  builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--x"), value3, false);
  style2 = builder.TakeStyle();
  EXPECT_TRUE(style1->CustomPropertiesEqual(properties, *style2));

  builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--x"), value2, false);
  style2 = builder.TakeStyle();
  EXPECT_FALSE(style1->CustomPropertiesEqual(properties, *style2));
}

TEST_F(ComputedStyleTest, CustomPropertiesInheritance_FastPath) {
  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "0px",
                                     true);

  ComputedStyleBuilder old_builder = CreateComputedStyleBuilder();
  ComputedStyleBuilder new_builder = CreateComputedStyleBuilder();

  using UnitType = CSSPrimitiveValue::UnitType;

  const auto* value1 = CSSNumericLiteralValue::Create(1.0, UnitType::kPixels);
  const auto* value2 = CSSNumericLiteralValue::Create(2.0, UnitType::kPixels);

  const ComputedStyle* old_style = old_builder.TakeStyle();
  const ComputedStyle* new_style = new_builder.TakeStyle();
  EXPECT_FALSE(old_style->HasVariableDeclaration());
  EXPECT_FALSE(old_style->HasVariableReference());
  EXPECT_FALSE(new_style->HasVariableReference());
  EXPECT_FALSE(new_style->HasVariableDeclaration());

  // Removed variable
  old_builder = CreateComputedStyleBuilder();
  old_builder.SetVariableValue(AtomicString("--x"), value1, true);
  old_style = old_builder.TakeStyle();
  EXPECT_EQ(ComputedStyle::Difference::kIndependentInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  old_builder = CreateComputedStyleBuilder();
  new_builder = CreateComputedStyleBuilder();

  // Added a new variable
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_EQ(ComputedStyle::Difference::kIndependentInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  // Change value of variable
  old_builder = CreateComputedStyleBuilder();
  new_builder = ComputedStyleBuilder(*new_style);
  old_builder.SetVariableValue(AtomicString("--x"), value1, true);
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  new_builder.SetHasVariableReference();
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_FALSE(new_style->HasVariableDeclaration());
  EXPECT_TRUE(new_style->HasVariableReference());
  EXPECT_EQ(ComputedStyle::Difference::kIndependentInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  old_builder = CreateComputedStyleBuilder();
  new_builder = CreateComputedStyleBuilder();

  // New styles with variable declaration don't force style recalc
  old_builder.SetVariableValue(AtomicString("--x"), value1, true);
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  new_builder.SetHasVariableDeclaration();
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_TRUE(new_style->HasVariableDeclaration());
  EXPECT_FALSE(new_style->HasVariableReference());
  EXPECT_EQ(ComputedStyle::Difference::kIndependentInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  old_builder = CreateComputedStyleBuilder();
  new_builder = CreateComputedStyleBuilder();

  // New styles with variable reference don't force style recalc
  old_builder.SetVariableValue(AtomicString("--x"), value1, true);
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  new_builder.SetHasVariableDeclaration();
  new_builder.SetHasVariableReference();
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_TRUE(new_style->HasVariableDeclaration());
  EXPECT_TRUE(new_style->HasVariableReference());
  EXPECT_EQ(ComputedStyle::Difference::kIndependentInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));
}

TEST_F(ComputedStyleTest, CustomPropertiesInheritance_StyleRecalc) {
  css_test_helpers::RegisterProperty(GetDocument(), "--x", "<length>", "0px",
                                     true);

  ComputedStyleBuilder old_builder = CreateComputedStyleBuilder();
  ComputedStyleBuilder new_builder = CreateComputedStyleBuilder();

  using UnitType = CSSPrimitiveValue::UnitType;

  const auto* value1 = CSSNumericLiteralValue::Create(1.0, UnitType::kPixels);
  const auto* value2 = CSSNumericLiteralValue::Create(2.0, UnitType::kPixels);

  const ComputedStyle* old_style = old_builder.TakeStyle();
  const ComputedStyle* new_style = new_builder.TakeStyle();
  EXPECT_FALSE(old_style->HasVariableDeclaration());
  EXPECT_FALSE(old_style->HasVariableReference());
  EXPECT_FALSE(new_style->HasVariableReference());
  EXPECT_FALSE(new_style->HasVariableDeclaration());
```