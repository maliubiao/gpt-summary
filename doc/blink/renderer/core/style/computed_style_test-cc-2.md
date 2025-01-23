Response:
The user wants a summary of the functionality of the `computed_style_test.cc` file in the Chromium Blink engine. I need to go through the provided code snippets and identify the main areas of testing.

The file seems to be focused on testing the `ComputedStyle` class, its builder, and related functionalities. The tests cover a wide range of CSS properties and how they are computed and compared.

Here's a breakdown of the functionalities based on the tests:

1. **Containment (`contain` property):** Tests how the `contain` property interacts with the `display` property on HTML and body elements. It checks if containment is correctly applied based on these properties.
2. **Debugging Differences (`DebugDiffFields`):**  Tests the functionality for identifying differences between two `ComputedStyle` objects, particularly for debugging purposes. It covers basic property differences and differences in derived/lazy-evaluated properties.
3. **Logical Scroll Padding (`LogicalScrollPaddingUtils`):** Tests the mapping of logical scroll padding properties (inline-start, inline-end, block-start, block-end) to physical properties (left, right, top, bottom) based on text direction and writing mode.
4. **ComputedStyle Builder (`BasicBuilder`, `MoveBuilder`, `MoveAssignBuilder`):** Tests the `ComputedStyleBuilder` class, ensuring it can correctly modify properties of a `ComputedStyle` object and that move semantics work correctly.
5. **Timeline Properties (`ScrollTimelineNameNoDiff`, `ScrollTimelineAxisNoDiff`, `ViewTimelineNameNoDiff`, `ViewTimelineAxisNoDiff`, `ViewTimelineInsetNoDiff`):** Tests the comparison of timeline-related properties like scroll timeline name, axis, view timeline name, axis, and inset, ensuring that styles with the same timeline configurations are considered equal.
6. **Container Queries (`ContainerNameNoDiff`):** Tests the comparison of container query properties (name and type), ensuring that styles with the same container query configurations are considered equal.
7. **CSS Property Value Retrieval (`BackgroundRepeat`, `MaskRepeat`, `MaskMode`, `DynamicRangeLimitMixStandardToConstrainedHigh`, `DynamicRangeLimitMixStandardToHigh`, `DynamicRangeLimitMixConstrainedHighToHigh`, `DynamicRangeLimitMixAllThree`):** Tests the retrieval of computed CSS property values using `CSSValueFromComputedStyleInternal` for various properties like `background-repeat`, `mask-repeat`, `mask-mode`, and `dynamic-range-limit`. It also checks the correct conversion of values and their textual representation.
8. **Quirks and Use Counters (`UseCountInsideListMarkerPositionQuirk`):** Tests the enabling of a specific quirk (`WebFeature::kInsideListMarkerPositionQuirk`) based on the presence of certain HTML structures.
9. **Zoom Inheritance (`ZoomInheritance`):** Tests the inheritance behavior of the `zoom` property.
10. **Color Scheme (`ColorSchemeFlagsIsNormal`, `ColorSchemeFlagsIsNormal_WithMeta`):** Tests the `ColorSchemeFlagsIsNormal` method, checking if the color scheme is set to "normal" based on the `color-scheme` CSS property and meta tags.

Based on this analysis, I can now summarize the functionalities of the file.
这是`blink/renderer/core/style/computed_style_test.cc`文件的第 3 部分，它主要包含针对 `ComputedStyle` 类及其相关功能的单元测试。结合前两部分，我们可以归纳一下它的功能：

**文件总体功能归纳:**

`computed_style_test.cc` 文件是 Chromium Blink 引擎中用于测试 `ComputedStyle` 类的单元测试集合。`ComputedStyle` 类存储了元素最终计算出的样式信息，这些信息是在考虑了 CSS 规则、继承、层叠等因素后确定的。该测试文件旨在验证 `ComputedStyle` 类的各种功能是否正确实现，包括：

* **属性值的计算和存储:**  测试各种 CSS 属性（例如 `display`, `width`, `contain`, `scroll-padding`, `background-repeat`, `mask-repeat`, `mask-mode`, `dynamic-range-limit`, `color-scheme` 等）的计算结果是否正确存储在 `ComputedStyle` 对象中。
* **样式的比较和差异检测:**  测试比较两个 `ComputedStyle` 对象是否相等，并能准确地找出两个样式对象之间的差异，用于调试。
* **与 CSS 相关的逻辑:** 测试一些与特定 CSS 特性相关的逻辑，例如 `contain` 属性与 `display` 属性的交互，以及逻辑属性（如 `scroll-padding-inline-start`）到物理属性的映射。
* **Builder 模式的使用:** 测试 `ComputedStyleBuilder` 类的功能，该类用于方便地创建和修改 `ComputedStyle` 对象。
* **Timeline 和 Container 查询功能:** 测试与 CSS Scroll Timeline 和 Container Queries 相关的属性的比较。
* **初始值的处理:**  测试获取元素初始计算样式的功能。
* **Quirks 模式下的行为:** 检查特定情况下是否触发了浏览器的 quirks 模式。
* **继承行为:** 测试某些 CSS 属性的继承行为。
* **内部方法的正确性:** 测试一些用于获取和处理计算样式值的内部方法。

**第 3 部分具体功能归纳:**

这部分的代码延续了对 `ComputedStyle` 类的测试，主要关注以下方面：

1. **Contain 属性测试 (延续):**
   - 继续测试 `contain` 属性的不同取值 (`none`, `layout`, `paint`, `size`, `style`) 与各种 `display` 属性值组合时，在 `<html>` 和 `<body>` 元素上的行为。
   - **逻辑推理:**
     - **假设输入:** 分别设置 `html` 和 `body` 元素的 `contain` 属性为不同的值 (`none`, `layout`, `paint`, `size`, `style`)，并遍历设置它们的 `display` 属性为各种可能的取值 (例如 `inline`, `block`, `list-item` 等)。
     - **预期输出:** 验证 `html` 和 `body` 元素的布局对象是否应该应用 containment，以及它们的计算样式是否符合预期。特别是当 `body` 没有布局对象时，其计算出的 `display` 应该为 `contents`，并且只有当 `contain` 为 `style` 时才应该应用 containment。

2. **调试差异功能测试 (`DebugDiffFields`, `DerivedDebugDiff`, `DerivedDebugDiffLazy`):**
   - 测试 `ComputedStyle` 类的 `DebugDiffFields` 方法，该方法用于比较两个 `ComputedStyle` 对象并返回差异字段的列表。
   - **举例说明:**
     - 创建两个 `ComputedStyle` 对象，并设置它们的 `width` 属性为不同的值。
     - 调用 `DebugDiffFields` 方法比较这两个对象，预期输出应该包含 `width` 字段的差异，并显示实际值和预期值。
   - 测试派生属性的差异检测，例如 `forces_stacking_context` 和 `is_stacking_context_without_containment_`。
   - 测试延迟计算的属性在差异检测中的行为，确保即使一个属性是延迟计算的，比较时也能正确处理。

3. **逻辑 Scroll Padding 测试 (`LogicalScrollPaddingUtils`):**
   - 测试逻辑滚动内边距属性（`scroll-padding-inline-start`, `scroll-padding-inline-end`, `scroll-padding-block-start`, `scroll-padding-block-end`）在不同书写模式 (`writing-mode`) 和文本方向 (`direction`) 下如何映射到物理内边距属性（`scroll-padding-left`, `scroll-padding-right`, `scroll-padding-top`, `scroll-padding-bottom`）。
   - **举例说明:**
     - 设置元素的 `scroll-padding-left`, `scroll-padding-right`, `scroll-padding-top`, `scroll-padding-bottom` 为特定值。
     - 分别设置元素的 `direction` 为 `ltr` 和 `rtl`，`writing-mode` 为 `horizontal-tb`, `vertical-lr`, `vertical-rl`。
     - 验证通过 `ScrollPaddingInlineStart`, `ScrollPaddingInlineEnd`, `ScrollPaddingBlockStart`, `ScrollPaddingBlockEnd` 获取到的值是否与预期的物理内边距值一致。

4. **ComputedStyleBuilder 测试 (`BasicBuilder`, `MoveBuilder`, `MoveAssignBuilder`):**
   - 测试 `ComputedStyleBuilder` 类的基本用法，包括从现有的 `ComputedStyle` 对象创建 builder，并修改属性值。
   - 测试 `ComputedStyleBuilder` 的移动语义，确保通过 `std::move` 转移 builder 的所有权后，数据仍然有效。
   - **举例说明:**
     - 创建一个初始的 `ComputedStyle` 对象。
     - 使用其创建一个 `ComputedStyleBuilder` 对象。
     - 通过 builder 修改 `scroll-padding-left` 和 `scroll-padding-right` 的值。
     - 从 builder 中获取新的 `ComputedStyle` 对象，并验证修改后的属性值是否正确。

5. **Timeline 属性比较测试 (`ScrollTimelineNameNoDiff`, `ScrollTimelineAxisNoDiff`, `ViewTimelineNameNoDiff`, `ViewTimelineAxisNoDiff`, `ViewTimelineInsetNoDiff`):**
   - 测试当两个 `ComputedStyle` 对象的 Scroll Timeline 或 View Timeline 的名称、轴向或内边距相同时，`ComputeDifference` 方法是否返回 `kEqual`。

6. **Container 查询属性比较测试 (`ContainerNameNoDiff`):**
   - 测试当两个 `ComputedStyle` 对象的 Container 名称和类型相同时，`ComputeDifference` 方法是否返回 `kEqual`。

7. **获取计算样式值测试 (`BackgroundRepeat`, `MaskRepeat`, `MaskMode`, `DynamicRangeLimitMixStandardToConstrainedHigh` 等):**
   - 测试通过 `CSSValueFromComputedStyleInternal` 方法从 `ComputedStyle` 对象中获取各种 CSS 属性的计算值，并验证其文本表示是否正确。
   - **举例说明:**
     - 设置元素的 `background-repeat` 属性为 `repeat-x`。
     - 从其计算样式中获取 `background-repeat` 的值，并验证其文本表示为 "repeat-x"。
   - 测试了 `mask-repeat`, `mask-mode`, `dynamic-range-limit` 等属性的类似功能。

8. **Quirks 模式 Use Count 测试 (`UseCountInsideListMarkerPositionQuirk`):**
   - 测试在特定 HTML 结构下（例如 `<li>` 元素没有父 `<ul>` 或 `<ol>`），是否会记录 `WebFeature::kInsideListMarkerPositionQuirk` 的使用次数。
   - **假设输入:** 创建不同的 HTML 结构，有些结构会触发该 quirk，有些不会。
   - **预期输出:** 验证 `document.IsUseCounted(WebFeature::kInsideListMarkerPositionQuirk)` 的返回值是否符合预期。

9. **Zoom 继承测试 (`ZoomInheritance`):**
   - 测试 `zoom` 属性的继承行为，确保设置了 `zoom` 属性的父元素，其子元素在特定情况下不会触发断言失败 (DCHECK)。

10. **Color Scheme 测试 (`ColorSchemeFlagsIsNormal`, `ColorSchemeFlagsIsNormal_WithMeta`):**
    - 测试 `ComputedStyleRef().ColorSchemeFlagsIsNormal()` 方法，该方法用于判断元素的 `color-scheme` 属性是否为 `normal`。
    - 测试了在有 `<meta name="color-scheme">` 的情况下，该方法是否能正确判断。
    - **举例说明:**
      - 创建带有不同 `color-scheme` 属性值的 `<div>` 元素 (`normal`, `light`, `dark`)。
      - 验证 `ColorSchemeFlagsIsNormal()` 方法对不同元素的返回值是否正确。

**用户或编程常见的使用错误举例 (基于测试内容推断):**

虽然测试代码本身不直接涉及用户错误，但可以推断出一些与 `ComputedStyle` 和 CSS 相关的常见错误：

* **误解 `contain` 属性的影响:** 开发者可能不清楚 `contain` 属性的不同取值对布局、渲染等方面的影响，导致页面出现非预期的行为。例如，错误地使用了 `contain: paint` 可能导致某些元素的重绘隔离，影响性能。
* **逻辑属性使用错误:**  不熟悉逻辑属性与物理属性的映射关系，可能在不同的书写模式和文本方向下得到错误的布局。例如，在 `rtl` 模式下，将左内边距理解为 `scroll-padding-inline-start`。
* **直接修改 `ComputedStyle` 对象:** 开发者应该使用 `StyleResolver` 和 `ComputedStyleBuilder` 来修改元素的样式，而不是直接操作 `ComputedStyle` 对象，因为 `ComputedStyle` 是计算后的结果，直接修改可能会导致状态不一致。
* **对 `zoom` 属性的滥用:**  `zoom` 属性是非标准的，其继承行为可能与其他标准属性不同，过度依赖 `zoom` 可能会导致兼容性问题。
* **不理解 `color-scheme` 的工作原理:**  开发者可能不清楚 `color-scheme` 属性和 `<meta name="color-scheme">` 的作用以及它们之间的优先级，导致网站的颜色主题在不同用户偏好下显示不正确。

总而言之，`computed_style_test.cc` 的第 3 部分以及整个文件都在细致地测试 `ComputedStyle` 类的各个方面，确保 Blink 引擎能正确地计算和处理元素的样式，为网页的正确渲染奠定基础。这些测试覆盖了各种 CSS 特性和使用场景，有助于发现和修复潜在的 bug，保证了浏览器的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/core/style/computed_style_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
Inline,
                               CSSValueID::kBlock,
                               CSSValueID::kListItem,
                               CSSValueID::kInlineBlock,
                               CSSValueID::kTable,
                               CSSValueID::kInlineTable,
                               CSSValueID::kTableRowGroup,
                               CSSValueID::kTableHeaderGroup,
                               CSSValueID::kTableFooterGroup,
                               CSSValueID::kTableRow,
                               CSSValueID::kTableColumnGroup,
                               CSSValueID::kTableColumn,
                               CSSValueID::kTableCell,
                               CSSValueID::kTableCaption,
                               CSSValueID::kWebkitBox,
                               CSSValueID::kWebkitInlineBox,
                               CSSValueID::kFlex,
                               CSSValueID::kInlineFlex,
                               CSSValueID::kGrid,
                               CSSValueID::kInlineGrid,
                               CSSValueID::kContents,
                               CSSValueID::kFlowRoot,
                               CSSValueID::kNone,
                               CSSValueID::kMath};
  for (auto contain :
       {CSSValueID::kNone, CSSValueID::kLayout, CSSValueID::kPaint,
        CSSValueID::kSize, CSSValueID::kStyle}) {
    html->SetInlineStyleProperty(CSSPropertyID::kContain,
                                 GetCSSValueNameAs<String>(contain));
    body->SetInlineStyleProperty(CSSPropertyID::kContain,
                                 GetCSSValueNameAs<String>(contain));
    for (auto html_display : display_types) {
      html->SetInlineStyleProperty(CSSPropertyID::kDisplay, html_display);
      for (auto body_display : display_types) {
        body->SetInlineStyleProperty(CSSPropertyID::kDisplay, body_display);
        document.View()->UpdateAllLifecyclePhasesForTest();

        if (!html->GetLayoutObject()) {
          EXPECT_TRUE(!html->GetComputedStyle());
          continue;
        }
        EXPECT_EQ(html->GetLayoutObject()->ShouldApplyAnyContainment(),
                  html->GetLayoutObject()->StyleRef().ShouldApplyAnyContainment(
                      *html))
            << "html contain:" << GetCSSValueName(contain)
            << " display:" << GetCSSValueName(html_display);
        if (!body->GetLayoutObject()) {
          if (const auto* body_style = body->GetComputedStyle()) {
            EXPECT_EQ(body_style->Display(), EDisplay::kContents);
            EXPECT_EQ(body_style->ShouldApplyAnyContainment(*body),
                      contain == CSSValueID::kStyle);
          }
          continue;
        }
        EXPECT_EQ(body->GetLayoutObject()->ShouldApplyAnyContainment(),
                  body->GetLayoutObject()->StyleRef().ShouldApplyAnyContainment(
                      *body))
            << "body contain:" << GetCSSValueName(contain)
            << " display:" << GetCSSValueName(body_display);
      }
    }
  }
}

#if DCHECK_IS_ON()

TEST_F(ComputedStyleTest, DebugDiffFields) {
  using DebugField = ComputedStyleBase::DebugField;

  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();

  builder1.SetWidth(Length(100.0, Length::kFixed));
  builder2.SetWidth(Length(200.0, Length::kFixed));

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(0u, style1->DebugDiffFields(*style1).size());
  EXPECT_EQ(0u, style2->DebugDiffFields(*style2).size());

  EXPECT_EQ(1u, style1->DebugDiffFields(*style2).size());

  // The extra quotes are unfortunate, but comes from operator<< on String.
  EXPECT_EQ(DebugField::width_, style1->DebugDiffFields(*style2)[0].field);
  EXPECT_EQ("\"Length(Fixed, 100)\"",
            style1->DebugDiffFields(*style2)[0].actual);
  EXPECT_EQ("\"Length(Fixed, 200)\"",
            style1->DebugDiffFields(*style2)[0].correct);

  EXPECT_EQ("width_",
            ComputedStyleBase::DebugFieldToString(DebugField::width_));
}

TEST_F(ComputedStyleTest, DerivedDebugDiff) {
  using DebugField = ComputedStyleBase::DebugField;

  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();

  builder1.SetForcesStackingContext(true);

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  ASSERT_EQ(2u, style1->DebugDiffFields(*style2).size());

  EXPECT_EQ(DebugField::forces_stacking_context_,
            style1->DebugDiffFields(*style2)[0].field);
  EXPECT_EQ("1", style1->DebugDiffFields(*style2)[0].actual);
  EXPECT_EQ("0", style1->DebugDiffFields(*style2)[0].correct);

  EXPECT_EQ(DebugField::is_stacking_context_without_containment_,
            style1->DebugDiffFields(*style2)[1].field);
  EXPECT_EQ("true", style1->DebugDiffFields(*style2)[1].actual);
  EXPECT_EQ("false", style1->DebugDiffFields(*style2)[1].correct);
}

TEST_F(ComputedStyleTest, DerivedDebugDiffLazy) {
  ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();
  ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  // Trigger lazy-evaluation of the field on *one* of the styles.
  EXPECT_FALSE(style1->IsStackingContextWithoutContainment());

  // We should not detect a difference, because ComputedStyle(Base) should
  // evaluate the field automatically when needed.
  EXPECT_EQ(0u, style1->DebugDiffFields(*style2).size());
}

#endif  // #if DCHECK_IS_ON()

TEST_F(ComputedStyleTest, LogicalScrollPaddingUtils) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();

  Length left = Length::Fixed(1.0f);
  Length right = Length::Fixed(2.0f);
  Length top = Length::Fixed(3.0f);
  Length bottom = Length::Fixed(4.0f);

  builder.SetScrollPaddingLeft(left);
  builder.SetScrollPaddingRight(right);
  builder.SetScrollPaddingTop(top);
  builder.SetScrollPaddingBottom(bottom);

  // ltr

  builder.SetDirection(TextDirection::kLtr);
  builder.SetWritingMode(WritingMode::kHorizontalTb);
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_EQ(left, style->ScrollPaddingInlineStart());
  EXPECT_EQ(right, style->ScrollPaddingInlineEnd());
  EXPECT_EQ(top, style->ScrollPaddingBlockStart());
  EXPECT_EQ(bottom, style->ScrollPaddingBlockEnd());

  builder = ComputedStyleBuilder(*style);
  builder.SetDirection(TextDirection::kLtr);
  builder.SetWritingMode(WritingMode::kVerticalLr);
  style = builder.TakeStyle();
  EXPECT_EQ(top, style->ScrollPaddingInlineStart());
  EXPECT_EQ(bottom, style->ScrollPaddingInlineEnd());
  EXPECT_EQ(left, style->ScrollPaddingBlockStart());
  EXPECT_EQ(right, style->ScrollPaddingBlockEnd());

  builder = ComputedStyleBuilder(*style);
  builder.SetDirection(TextDirection::kLtr);
  builder.SetWritingMode(WritingMode::kVerticalRl);
  style = builder.TakeStyle();
  EXPECT_EQ(top, style->ScrollPaddingInlineStart());
  EXPECT_EQ(bottom, style->ScrollPaddingInlineEnd());
  EXPECT_EQ(right, style->ScrollPaddingBlockStart());
  EXPECT_EQ(left, style->ScrollPaddingBlockEnd());

  // rtl

  builder = ComputedStyleBuilder(*style);
  builder.SetDirection(TextDirection::kRtl);
  builder.SetWritingMode(WritingMode::kHorizontalTb);
  style = builder.TakeStyle();
  EXPECT_EQ(right, style->ScrollPaddingInlineStart());
  EXPECT_EQ(left, style->ScrollPaddingInlineEnd());
  EXPECT_EQ(top, style->ScrollPaddingBlockStart());
  EXPECT_EQ(bottom, style->ScrollPaddingBlockEnd());

  builder = ComputedStyleBuilder(*style);
  builder.SetDirection(TextDirection::kRtl);
  builder.SetWritingMode(WritingMode::kVerticalLr);
  style = builder.TakeStyle();
  EXPECT_EQ(bottom, style->ScrollPaddingInlineStart());
  EXPECT_EQ(top, style->ScrollPaddingInlineEnd());
  EXPECT_EQ(left, style->ScrollPaddingBlockStart());
  EXPECT_EQ(right, style->ScrollPaddingBlockEnd());

  builder = ComputedStyleBuilder(*style);
  builder.SetDirection(TextDirection::kRtl);
  builder.SetWritingMode(WritingMode::kVerticalRl);
  style = builder.TakeStyle();
  EXPECT_EQ(bottom, style->ScrollPaddingInlineStart());
  EXPECT_EQ(top, style->ScrollPaddingInlineEnd());
  EXPECT_EQ(right, style->ScrollPaddingBlockStart());
  EXPECT_EQ(left, style->ScrollPaddingBlockEnd());
}

TEST_F(ComputedStyleTest, BasicBuilder) {
  const ComputedStyle* original = InitialComputedStyle();

  Length left = Length::Fixed(1.0f);
  Length right = Length::Fixed(2.0f);

  ComputedStyleBuilder builder(*original);
  builder.SetScrollPaddingLeft(left);
  builder.SetScrollPaddingRight(right);

  const ComputedStyle* style = builder.TakeStyle();

  EXPECT_NE(left, original->ScrollPaddingLeft());
  EXPECT_NE(right, original->ScrollPaddingRight());

  EXPECT_EQ(left, style->ScrollPaddingLeft());
  EXPECT_EQ(right, style->ScrollPaddingRight());
}

TEST_F(ComputedStyleTest, MoveBuilder) {
  Length one = Length::Fixed(1.0f);

  ComputedStyleBuilder builder1(*InitialComputedStyle());
  builder1.SetScrollPaddingLeft(one);

  ComputedStyleBuilder builder2(std::move(builder1));

  const ComputedStyle* style2 = builder2.TakeStyle();
  ASSERT_TRUE(style2);
  EXPECT_EQ(one, style2->ScrollPaddingLeft());
}

TEST_F(ComputedStyleTest, MoveAssignBuilder) {
  Length one = Length::Fixed(1.0f);

  ComputedStyleBuilder builder1(*InitialComputedStyle());
  builder1.SetScrollPaddingLeft(one);

  ComputedStyleBuilder builder2(*InitialComputedStyle());
  builder2 = std::move(builder1);

  const ComputedStyle* style2 = builder2.TakeStyle();
  ASSERT_TRUE(style2);
  EXPECT_EQ(one, style2->ScrollPaddingLeft());
}

TEST_F(ComputedStyleTest, ScrollTimelineNameNoDiff) {
  ComputedStyleBuilder builder1(*InitialComputedStyle());
  ComputedStyleBuilder builder2(*InitialComputedStyle());

  builder1.SetScrollTimelineName(MakeGarbageCollected<ScopedCSSNameList>(
      HeapVector<Member<const ScopedCSSName>>(
          1u, MakeGarbageCollected<ScopedCSSName>(AtomicString("test"),
                                                  /* tree_scope */ nullptr))));
  builder2.SetScrollTimelineName(MakeGarbageCollected<ScopedCSSNameList>(
      HeapVector<Member<const ScopedCSSName>>(
          1u, MakeGarbageCollected<ScopedCSSName>(AtomicString("test"),
                                                  /* tree_scope */ nullptr))));

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(ComputedStyle::Difference::kEqual,
            ComputedStyle::ComputeDifference(style1, style2));
}

TEST_F(ComputedStyleTest, ScrollTimelineAxisNoDiff) {
  ComputedStyleBuilder builder1(*InitialComputedStyle());
  ComputedStyleBuilder builder2(*InitialComputedStyle());

  builder1.SetScrollTimelineAxis(Vector<TimelineAxis>(1u, TimelineAxis::kY));
  builder2.SetScrollTimelineAxis(Vector<TimelineAxis>(1u, TimelineAxis::kY));

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(ComputedStyle::Difference::kEqual,
            ComputedStyle::ComputeDifference(style1, style2));
}

TEST_F(ComputedStyleTest, ViewTimelineNameNoDiff) {
  ComputedStyleBuilder builder1(*InitialComputedStyle());
  ComputedStyleBuilder builder2(*InitialComputedStyle());

  builder1.SetViewTimelineName(MakeGarbageCollected<ScopedCSSNameList>(
      HeapVector<Member<const ScopedCSSName>>(
          1u, MakeGarbageCollected<ScopedCSSName>(AtomicString("test"),
                                                  /* tree_scope */ nullptr))));
  builder2.SetViewTimelineName(MakeGarbageCollected<ScopedCSSNameList>(
      HeapVector<Member<const ScopedCSSName>>(
          1u, MakeGarbageCollected<ScopedCSSName>(AtomicString("test"),
                                                  /* tree_scope */ nullptr))));

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(ComputedStyle::Difference::kEqual,
            ComputedStyle::ComputeDifference(style1, style2));
}

TEST_F(ComputedStyleTest, ViewTimelineAxisNoDiff) {
  ComputedStyleBuilder builder1(*InitialComputedStyle());
  ComputedStyleBuilder builder2(*InitialComputedStyle());

  builder1.SetViewTimelineAxis(Vector<TimelineAxis>(1u, TimelineAxis::kY));
  builder2.SetViewTimelineAxis(Vector<TimelineAxis>(1u, TimelineAxis::kY));

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(ComputedStyle::Difference::kEqual,
            ComputedStyle::ComputeDifference(style1, style2));
}

TEST_F(ComputedStyleTest, ViewTimelineInsetNoDiff) {
  ComputedStyleBuilder builder1(*InitialComputedStyle());
  ComputedStyleBuilder builder2(*InitialComputedStyle());

  builder1.SetViewTimelineInset(Vector<TimelineInset>(
      1u, TimelineInset(Length::Fixed(1.0f), Length::Fixed(1.0f))));
  builder2.SetViewTimelineInset(Vector<TimelineInset>(
      1u, TimelineInset(Length::Fixed(1.0f), Length::Fixed(1.0f))));

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(ComputedStyle::Difference::kEqual,
            ComputedStyle::ComputeDifference(style1, style2));
}

TEST_F(ComputedStyleTest, ContainerNameNoDiff) {
  ComputedStyleBuilder builder1(*InitialComputedStyle());
  ComputedStyleBuilder builder2(*InitialComputedStyle());

  builder1.SetContainerName(MakeGarbageCollected<ScopedCSSNameList>(
      HeapVector<Member<const ScopedCSSName>>(
          1u, MakeGarbageCollected<ScopedCSSName>(AtomicString("test"),
                                                  /* tree_scope */ nullptr))));
  builder1.SetContainerType(kContainerTypeSize);
  builder2.SetContainerName(MakeGarbageCollected<ScopedCSSNameList>(
      HeapVector<Member<const ScopedCSSName>>(
          1u, MakeGarbageCollected<ScopedCSSName>(AtomicString("test"),
                                                  /* tree_scope */ nullptr))));
  builder2.SetContainerType(kContainerTypeSize);

  const ComputedStyle* style1 = builder1.TakeStyle();
  const ComputedStyle* style2 = builder2.TakeStyle();

  EXPECT_EQ(ComputedStyle::Difference::kEqual,
            ComputedStyle::ComputeDifference(style1, style2));
}

TEST_F(ComputedStyleTest, BackgroundRepeat) {
  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  auto* repeat_style_value = MakeGarbageCollected<CSSRepeatStyleValue>(
      CSSIdentifierValue::Create(CSSValueID::kRepeatX));

  GetCSSPropertyBackgroundRepeat().ApplyValue(state, *repeat_style_value,
                                              CSSProperty::ValueMode::kNormal);
  const ComputedStyle* style = state.TakeStyle();
  auto* computed_value =
      GetCSSPropertyBackgroundRepeat().CSSValueFromComputedStyleInternal(
          *style, nullptr /* layout_object */, false /* allow_visited_style */,
          CSSValuePhase::kComputedValue);
  ASSERT_TRUE(computed_value);
  ASSERT_EQ("repeat-x", computed_value->CssText());
}

TEST_F(ComputedStyleTest, MaskRepeat) {
  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  auto* repeat_style_value = MakeGarbageCollected<CSSRepeatStyleValue>(
      CSSIdentifierValue::Create(CSSValueID::kRepeatY));

  GetCSSPropertyMaskRepeat().ApplyValue(state, *repeat_style_value,
                                        CSSProperty::ValueMode::kNormal);
  const ComputedStyle* style = state.TakeStyle();
  auto* computed_value =
      GetCSSPropertyMaskRepeat().CSSValueFromComputedStyleInternal(
          *style, nullptr /* layout_object */, false /* allow_visited_style */,
          CSSValuePhase::kComputedValue);
  ASSERT_TRUE(computed_value);
  ASSERT_EQ("repeat-y", computed_value->CssText());
}

TEST_F(ComputedStyleTest, MaskMode) {
  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  auto* mode_style_value = CSSIdentifierValue::Create(CSSValueID::kAlpha);

  GetCSSPropertyMaskMode().ApplyValue(state, *mode_style_value,
                                      CSSProperty::ValueMode::kNormal);
  const ComputedStyle* style = state.TakeStyle();
  auto* computed_value =
      GetCSSPropertyMaskMode().CSSValueFromComputedStyleInternal(
          *style, nullptr /* layout_object */, false /* allow_visited_style */,
          CSSValuePhase::kComputedValue);
  ASSERT_TRUE(computed_value);
  ASSERT_EQ("alpha", computed_value->CssText());
}

TEST_F(ComputedStyleTest, DynamicRangeLimitMixStandardToConstrainedHigh) {
  const DynamicRangeLimit limit(/*standard_mix=*/0.3f,
                                /*constrained_high_mix=*/0.7f);
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetDynamicRangeLimit(limit);
  auto* dynamic_range_limit_mix_value =
      GetCSSPropertyDynamicRangeLimit().CSSValueFromComputedStyleInternal(
          *builder.TakeStyle(), nullptr /* layout_object */,
          false /* allow_visited_style */, CSSValuePhase::kComputedValue);
  ASSERT_NE(dynamic_range_limit_mix_value, nullptr);

  EXPECT_EQ(dynamic_range_limit_mix_value->CssText(),
            "dynamic-range-limit-mix(standard 30%, constrained-high 70%)");

  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  GetCSSPropertyDynamicRangeLimit().ApplyValue(
      state, *dynamic_range_limit_mix_value, CSSProperty::ValueMode::kNormal);

  const DynamicRangeLimit converted_limit =
      state.TakeStyle()->GetDynamicRangeLimit();
  EXPECT_FLOAT_EQ(converted_limit.standard_mix, limit.standard_mix);
  EXPECT_FLOAT_EQ(converted_limit.constrained_high_mix,
                  limit.constrained_high_mix);
}

TEST_F(ComputedStyleTest, DynamicRangeLimitMixStandardToHigh) {
  const DynamicRangeLimit limit(/*standard_mix=*/0.4f,
                                /*constrained_high_mix=*/0.f);
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetDynamicRangeLimit(limit);
  auto* dynamic_range_limit_mix_value =
      GetCSSPropertyDynamicRangeLimit().CSSValueFromComputedStyleInternal(
          *builder.TakeStyle(), nullptr /* layout_object */,
          false /* allow_visited_style */, CSSValuePhase::kComputedValue);
  ASSERT_NE(dynamic_range_limit_mix_value, nullptr);

  EXPECT_EQ(dynamic_range_limit_mix_value->CssText(),
            "dynamic-range-limit-mix(standard 40%, high 60%)");

  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  GetCSSPropertyDynamicRangeLimit().ApplyValue(
      state, *dynamic_range_limit_mix_value, CSSProperty::ValueMode::kNormal);

  const DynamicRangeLimit converted_limit =
      state.TakeStyle()->GetDynamicRangeLimit();
  EXPECT_FLOAT_EQ(converted_limit.standard_mix, limit.standard_mix);
  EXPECT_FLOAT_EQ(converted_limit.constrained_high_mix,
                  limit.constrained_high_mix);
}

TEST_F(ComputedStyleTest, DynamicRangeLimitMixConstrainedHighToHigh) {
  const DynamicRangeLimit limit(/*standard_mix=*/0.f,
                                /*constrained_high_mix=*/0.55f);
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetDynamicRangeLimit(limit);
  auto* dynamic_range_limit_mix_value =
      GetCSSPropertyDynamicRangeLimit().CSSValueFromComputedStyleInternal(
          *builder.TakeStyle(), nullptr /* layout_object */,
          false /* allow_visited_style */, CSSValuePhase::kComputedValue);
  ASSERT_NE(dynamic_range_limit_mix_value, nullptr);

  EXPECT_EQ(dynamic_range_limit_mix_value->CssText(),
            "dynamic-range-limit-mix(constrained-high 55%, high 45%)");

  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  GetCSSPropertyDynamicRangeLimit().ApplyValue(
      state, *dynamic_range_limit_mix_value, CSSProperty::ValueMode::kNormal);

  const DynamicRangeLimit converted_limit =
      state.TakeStyle()->GetDynamicRangeLimit();
  EXPECT_FLOAT_EQ(converted_limit.standard_mix, limit.standard_mix);
  EXPECT_FLOAT_EQ(converted_limit.constrained_high_mix,
                  limit.constrained_high_mix);
}

TEST_F(ComputedStyleTest, DynamicRangeLimitMixAllThree) {
  const DynamicRangeLimit limit(/*standard_mix=*/0.2f,
                                /*constrained_high_mix=*/0.6f);
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetDynamicRangeLimit(limit);
  auto* dynamic_range_limit_mix_value =
      GetCSSPropertyDynamicRangeLimit().CSSValueFromComputedStyleInternal(
          *builder.TakeStyle(), nullptr /* layout_object */,
          false /* allow_visited_style */, CSSValuePhase::kComputedValue);
  ASSERT_NE(dynamic_range_limit_mix_value, nullptr);

  EXPECT_EQ(
      dynamic_range_limit_mix_value->CssText(),
      "dynamic-range-limit-mix(standard 20%, constrained-high 60%, high 20%)");

  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  GetCSSPropertyDynamicRangeLimit().ApplyValue(
      state, *dynamic_range_limit_mix_value, CSSProperty::ValueMode::kNormal);

  const DynamicRangeLimit converted_limit =
      state.TakeStyle()->GetDynamicRangeLimit();
  EXPECT_FLOAT_EQ(converted_limit.standard_mix, limit.standard_mix);
  EXPECT_FLOAT_EQ(converted_limit.constrained_high_mix,
                  limit.constrained_high_mix);
}

TEST_F(ComputedStyleTest, UseCountInsideListMarkerPositionQuirk) {
  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <style>.marker-content-none::marker { content: none }</style>
    <ul><li></li></ul>
    <ol><li></li></ol>
    <ul><div><li></li></ul>
    <ol><li><li></li></li></ol>
    <div style="display: list-item"></div>
    <li style="list-style-position: inside"></li>
    <li style="list-style: none"></li>
    <li class="marker-content-none"></li>
    <li style="display: flex"></li>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(
      document.IsUseCounted(WebFeature::kInsideListMarkerPositionQuirk));

  document.body()->setInnerHTML("<li></li>");
  document.View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(
      document.IsUseCounted(WebFeature::kInsideListMarkerPositionQuirk));
}

TEST_F(ComputedStyleTest, ZoomInheritance) {
  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <div id="target" style="line-height: revert; zoom: 2;">Hello, world!</div>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(true) << "Test passes if it doesn't hit a DCHECK.";
}

TEST_F(ComputedStyleTest, ColorSchemeFlagsIsNormal) {
  Document& document = GetDocument();
  ColorSchemeHelper color_scheme_helper(document);
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);

  document.body()->setInnerHTML(R"HTML(
    <div id="normal" style="color-scheme: normal"></div>
    <div id="light" style="color-scheme: light"></div>
    <div id="dark" style="color-scheme: dark"></div>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetDocument()
                  .getElementById(AtomicString("normal"))
                  ->ComputedStyleRef()
                  .ColorSchemeFlagsIsNormal());
  EXPECT_FALSE(GetDocument()
                   .getElementById(AtomicString("light"))
                   ->ComputedStyleRef()
                   .ColorSchemeFlagsIsNormal());
  EXPECT_FALSE(GetDocument()
                   .getElementById(AtomicString("dark"))
                   ->ComputedStyleRef()
                   .ColorSchemeFlagsIsNormal());
}

TEST_F(ComputedStyleTest, ColorSchemeFlagsIsNormal_WithMeta) {
  Document& document = GetDocument();
  ColorSchemeHelper color_scheme_helper(document);
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);

  document.body()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="light">
    <div id="normal" style="color-scheme: normal"></div>
    <div id="light" style="color-scheme: light"></div>
    <div id="dark" style="color-scheme: dark"></div>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetDocument()
                   .getElementById(AtomicString("normal"))
                   ->ComputedStyleRef()
                   .ColorSchemeFlagsIsNormal());
  EXPECT_FALSE(GetDocument()
                   .getElementById(AtomicString("light"))
                   ->ComputedStyleRef()
                   .ColorSchemeFlagsIsNormal());
  EXPECT_FALSE(GetDocument()
                   .getElementById(AtomicString("dark"))
                   ->ComputedStyleRef()
                   .ColorSchemeFlagsIsNormal());
}

}  // namespace blink
```