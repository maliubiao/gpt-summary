Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This code snippet is part of a larger file, `computed_style_test.cc`, which, judging by its name, is a unit test file for the `ComputedStyle` class in the Blink rendering engine.

The provided code focuses on testing various aspects of how `ComputedStyle` objects handle CSS variables, color schemes, and specific properties like `border-width`, `text-decoration`, and animations/transitions.

Here's a breakdown of the code's functionalities:

1. **CSS Variables:** It tests how changes in CSS variable declarations and references affect the need for style recalculation.
2. **Color Schemes:** It examines how the `color-scheme` property and the `light-dark()` function interact to determine the used color based on the preferred color scheme.
3. **Border Width:** It tests how `border-width`, `outline-width`, and `column-rule-width` are affected by zoom and how their values are converted to pixels. It also includes tests for "thin", "medium", and "thick" keyword values.
4. **CSS Variable Names:** It tests how a `ComputedStyle` object stores and manages the names of CSS variables declared and referenced within its style.
5. **Text Decoration:** It checks if changes to specific `text-decoration` properties trigger a recomputation of ink overflow.
6. **Animations and Transitions:** It verifies that cloned `ComputedStyle` objects have independent animation and transition data, ensuring copy-on-write behavior.
7. **Initial Values:** It confirms that applying initial values for animation names and transition properties doesn't create animation or transition data structures if they don't exist initially.
8. **SVG Style Comparison:** It tests that certain SVG related style properties are compared by value rather than by pointer.
这个代码片段主要测试了 `ComputedStyle` 类在处理 CSS 变量和颜色主题时的行为，以及特定 CSS 属性的计算和比较逻辑。以下是它的功能归纳：

**主要功能归纳:**

1. **测试 CSS 变量相关的样式重计算：**
   - 验证当样式中引入或移除 CSS 变量值时，是否会强制进行样式重计算。
   - 验证当样式中存在 CSS 变量声明或引用，并且变量的值发生变化时，是否会强制进行样式重计算。

2. **测试 `color-scheme` 属性的应用：**
   - 验证如何根据用户偏好的颜色主题 (`light` 或 `dark`) 应用 `color-scheme` 属性。

3. **测试 `light-dark()` CSS 函数的应用：**
   - 验证 `light-dark()` 函数如何根据当前的颜色主题选择不同的颜色值。
   - 针对 `color` 和 `background-image` 属性测试 `light-dark()` 函数在不同颜色主题下的表现。

4. **测试特定 CSS 属性与缩放 (`zoom`) 的交互：**
   - 测试 `stroke-width` 属性在存在 `zoom` 时的计算结果。
   - 测试 `border-top-width`, `outline-width`, 和 `column-rule-width` 等属性在存在 `zoom` 时的计算结果。

5. **测试 CSS 属性值的转换：**
   - 针对 `border-top-width`, `outline-width`, 和 `column-rule-width` 属性，测试不同像素值（包括小数）如何转换为最终的像素值。

6. **测试 `ComputedStyle` 中 CSS 变量名称的管理：**
   - 验证 `ComputedStyle` 对象如何存储和获取其中包含的 CSS 变量名称。
   - 测试初始的、继承的和非继承的 CSS 变量名称是如何被存储和访问的。
   - 测试在修改 `ComputedStyle` 的 CSS 变量数据后，变量名称的获取是否会更新。

7. **测试 `text-decoration` 属性的视觉失效差异：**
   - 验证当 `text-decoration` 属性的值相同时，视觉失效差异不需要重新计算墨迹溢出 (ink overflow)。
   - 验证当 `text-decoration` 的子属性（如 `text-decoration-style`, `text-decoration-line`, `text-decoration-thickness`, `text-underline-offset`, `text-underline-position`）的值不同时，视觉失效差异需要重新计算墨迹溢出。

8. **测试克隆的 `ComputedStyle` 对象的独立性：**
   - 验证克隆的 `ComputedStyle` 对象中关于动画 (`animations`) 和过渡 (`transitions`) 的数据与原始对象是独立的，修改克隆对象的数据不会影响原始对象。

9. **测试应用初始的动画名称和过渡属性：**
   - 验证当应用初始的 `animation-name` 和 `transition-property` 时，如果不存在动画或过渡数据，则不会创建相关的数据结构。

10. **测试 SVG 相关属性的比较：**
    - 验证某些 SVG 相关的属性（如 `stroke-opacity`, `stroke-miter-limit`, `stroke-width` 等）在进行视觉失效差异比较时，是基于其值进行比较，而不是指针。

**与 JavaScript, HTML, CSS 的关系举例说明:**

- **CSS 变量：**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
  <style>
    :root {
      --main-bg-color: lightblue;
    }
    body {
      background-color: var(--main-bg-color);
    }
  </style>
  </head>
  <body>
    <p>This paragraph has a light blue background.</p>
  </body>
  </html>
  ```
  这段 HTML 和 CSS 代码展示了 CSS 变量的使用。`computed_style_test.cc` 中的相关测试会验证当 JavaScript 修改 `--main-bg-color` 的值时，浏览器是否会正确地重新计算 `body` 的背景色。

- **Color Scheme 和 `light-dark()`：**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
  <style>
    body {
      background-color: light-dark(white, black);
      color: light-dark(black, white);
    }
    @media (prefers-color-scheme: dark) {
      body {
        /* 这里的样式会覆盖上面的 light 模式样式 */
      }
    }
  </style>
  </head>
  <body>
    <p>This text's color and background will change based on the preferred color scheme.</p>
  </body>
  </html>
  ```
  这段代码展示了如何使用 `light-dark()` 函数来根据用户的颜色偏好设置不同的背景色和文字颜色。`computed_style_test.cc` 中会测试浏览器是否正确地根据用户的设置应用了相应的颜色。

- **Border Width 和 Zoom：**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
  <style>
    div {
      border: medium solid black;
      zoom: 2;
    }
  </style>
  </head>
  <body>
    <div>This div has a medium border, which will be scaled by zoom.</div>
  </body>
  </html>
  ```
  这段代码展示了 `zoom` 属性如何影响边框的显示效果。`computed_style_test.cc` 中会测试浏览器在应用 `zoom` 后是否正确计算了边框的最终像素宽度。

- **Text Decoration：**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
  <style>
    a {
      text-decoration: underline dotted red;
    }
  </style>
  </head>
  <body>
    <a href="#">This link has a red dotted underline.</a>
  </body>
  </html>
  ```
  这段代码展示了如何使用 `text-decoration` 属性来设置链接的下划线样式。`computed_style_test.cc` 中会测试当 `text-decoration` 的子属性发生变化时，渲染引擎是否需要重新计算元素的布局和绘制。

- **Animations 和 Transitions：**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
  <style>
    div {
      width: 100px;
      transition: width 1s;
    }
    div:hover {
      width: 200px;
    }
  </style>
  </head>
  <body>
    <div>Hover over me to see a transition.</div>
  </body>
  </html>
  ```
  这段代码展示了 CSS 过渡效果。`computed_style_test.cc` 中会测试当克隆一个具有过渡效果的元素的 `ComputedStyle` 时，修改克隆对象的过渡属性不会影响原始对象。

**假设输入与输出 (逻辑推理):**

以下是一个关于 CSS 变量的测试用例的假设输入与输出：

**假设输入:**

- `old_style`：一个 `ComputedStyle` 对象，其中包含 CSS 变量 `--x` 的引用。
- `new_style`：一个 `ComputedStyle` 对象，其中 CSS 变量 `--x` 的值被改变。

**预期输出:**

- `ComputedStyle::ComputeDifference(old_style, new_style)` 应该返回 `ComputedStyle::Difference::kInherited`，表示需要进行样式重计算，因为 CSS 变量的值影响了最终的样式。

**用户或编程常见的使用错误举例说明:**

- **未考虑 CSS 变量的级联和继承：** 开发者可能会错误地认为在父元素中定义的 CSS 变量会自动应用到所有子元素，而没有考虑到 CSS 的级联规则和继承性。例如，如果子元素也定义了同名的 CSS 变量，子元素的定义会覆盖父元素的定义。`computed_style_test.cc` 中关于 CSS 变量的测试可以帮助确保引擎正确处理这些情况。

- **在 JavaScript 中修改样式后未触发重新渲染：** 开发者可能会使用 JavaScript 直接修改元素的样式，但忘记了某些样式更改可能不会立即触发重新渲染，导致页面显示不一致。例如，直接修改一个元素的 CSS 变量值可能需要手动触发某些操作才能确保样式更新。`computed_style_test.cc` 中关于样式重计算的测试可以帮助验证引擎是否在必要的时刻触发了重新渲染。

总而言之，这个代码片段是 Chromium 渲染引擎中用于测试 `ComputedStyle` 类的关键部分，它确保了浏览器能够正确地处理各种 CSS 特性，包括 CSS 变量、颜色主题以及特定属性的计算和比较，从而保证网页的正确渲染和用户体验。

### 提示词
```
这是目录为blink/renderer/core/style/computed_style_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Removed variable value
  // Old styles with variable reference force style recalc
  old_builder = CreateComputedStyleBuilder();
  old_builder.SetHasVariableReference();
  old_builder.SetVariableValue(AtomicString("--x"), value2, true);
  old_style = old_builder.TakeStyle();
  EXPECT_TRUE(old_style->HasVariableReference());
  EXPECT_EQ(ComputedStyle::Difference::kInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  old_builder = CreateComputedStyleBuilder();
  new_builder = CreateComputedStyleBuilder();

  // New variable value
  // Old styles with variable declaration force style recalc
  old_builder.SetHasVariableDeclaration();
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_TRUE(old_style->HasVariableDeclaration());
  EXPECT_EQ(ComputedStyle::Difference::kInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  old_builder = CreateComputedStyleBuilder();
  new_builder = CreateComputedStyleBuilder();

  // Change variable value
  // Old styles with variable declaration force style recalc
  old_builder.SetVariableValue(AtomicString("--x"), value1, true);
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  old_builder.SetHasVariableDeclaration();
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_TRUE(old_style->HasVariableDeclaration());
  EXPECT_EQ(ComputedStyle::Difference::kInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));

  old_builder = CreateComputedStyleBuilder();
  new_builder = CreateComputedStyleBuilder();

  // Change variable value
  // Old styles with variable reference force style recalc
  old_builder.SetVariableValue(AtomicString("--x"), value1, true);
  new_builder.SetVariableValue(AtomicString("--x"), value2, true);
  old_builder.SetHasVariableReference();
  old_style = old_builder.TakeStyle();
  new_style = new_builder.TakeStyle();
  EXPECT_TRUE(old_style->HasVariableReference());
  EXPECT_EQ(ComputedStyle::Difference::kInherited,
            ComputedStyle::ComputeDifference(old_style, new_style));
}

TEST_F(ComputedStyleTest, ApplyColorSchemeLightOnDark) {
  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  ColorSchemeHelper color_scheme_helper(document);
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  CSSPropertyRef ref("color-scheme", state.GetDocument());

  CSSValueList* dark_value = CSSValueList::CreateSpaceSeparated();
  dark_value->Append(*CSSIdentifierValue::Create(CSSValueID::kDark));

  CSSValueList* light_value = CSSValueList::CreateSpaceSeparated();
  light_value->Append(*CSSIdentifierValue::Create(CSSValueID::kLight));

  To<Longhand>(ref.GetProperty())
      .ApplyValue(state, *dark_value, CSSProperty::ValueMode::kNormal);
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            state.StyleBuilder().UsedColorScheme());

  To<Longhand>(ref.GetProperty())
      .ApplyValue(state, *light_value, CSSProperty::ValueMode::kNormal);
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            state.StyleBuilder().UsedColorScheme());
}

TEST_F(ComputedStyleTest, ApplyLightDarkColor) {
  using css_test_helpers::ParseDeclarationBlock;

  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  ColorSchemeHelper color_scheme_helper(document);
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  CSSValueList* dark_value = CSSValueList::CreateSpaceSeparated();
  dark_value->Append(*CSSIdentifierValue::Create(CSSValueID::kDark));

  CSSValueList* light_value = CSSValueList::CreateSpaceSeparated();
  light_value->Append(*CSSIdentifierValue::Create(CSSValueID::kLight));

  auto* color_declaration = ParseDeclarationBlock(
      "color:light-dark(black, white)", CSSParserMode::kUASheetMode);
  auto* dark_declaration = ParseDeclarationBlock("color-scheme:dark");
  auto* light_declaration = ParseDeclarationBlock("color-scheme:light");

  StyleCascade cascade1(state);
  cascade1.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(document);
  cascade1.MutableMatchResult().AddMatchedProperties(
      color_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade1.MutableMatchResult().AddMatchedProperties(
      dark_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade1.Apply();
  const ComputedStyle* style = state.StyleBuilder().CloneStyle();
  EXPECT_EQ(Color::kWhite, style->VisitedDependentColor(GetCSSPropertyColor()));

  StyleCascade cascade2(state);
  cascade2.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(document);
  cascade2.MutableMatchResult().AddMatchedProperties(
      color_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade2.MutableMatchResult().AddMatchedProperties(
      light_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade2.Apply();
  style = state.StyleBuilder().CloneStyle();
  EXPECT_EQ(Color::kBlack, style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(ComputedStyleTest, ApplyLightDarkBackgroundImage) {
  using css_test_helpers::ParseDeclarationBlock;

  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  ColorSchemeHelper color_scheme_helper(document);
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);

  auto* bgimage_declaration = ParseDeclarationBlock(
      "background-image:light-dark(none, url(dummy.png))", kUASheetMode);
  auto* dark_declaration = ParseDeclarationBlock("color-scheme:dark");
  auto* light_declaration = ParseDeclarationBlock("color-scheme:light");

  StyleCascade cascade1(state);
  cascade1.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(document);
  cascade1.MutableMatchResult().AddMatchedProperties(
      bgimage_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade1.MutableMatchResult().AddMatchedProperties(
      dark_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade1.Apply();
  EXPECT_TRUE(state.TakeStyle()->HasBackgroundImage());

  state.SetStyle(*initial);

  StyleCascade cascade2(state);
  cascade2.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(document);
  cascade2.MutableMatchResult().AddMatchedProperties(
      bgimage_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade2.MutableMatchResult().AddMatchedProperties(
      light_declaration, {.origin = CascadeOrigin::kAuthor});
  cascade2.Apply();
  EXPECT_FALSE(state.TakeStyle()->HasBackgroundImage());
}

TEST_F(ComputedStyleTest, StrokeWidthZoomAndCalc) {
  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);
  state.StyleBuilder().SetEffectiveZoom(1.5);

  auto* calc_value = CSSMathFunctionValue::Create(
      CSSMathExpressionNumericLiteral::Create(CSSNumericLiteralValue::Create(
          10, CSSPrimitiveValue::UnitType::kNumber)));

  GetCSSPropertyStrokeWidth().ApplyValue(state, *calc_value,
                                         CSSProperty::ValueMode::kNormal);
  const ComputedStyle* style = state.TakeStyle();
  auto* computed_value =
      GetCSSPropertyStrokeWidth().CSSValueFromComputedStyleInternal(
          *style, nullptr /* layout_object */, false /* allow_visited_style */,
          CSSValuePhase::kComputedValue);
  ASSERT_TRUE(computed_value);
  ASSERT_EQ("calc(10px)", computed_value->CssText());
}

TEST_F(ComputedStyleTest, InitialVariableNamesEmpty) {
  const ComputedStyle* style = InitialComputedStyle();
  EXPECT_TRUE(style->GetVariableNames().empty());
}

TEST_F(ComputedStyleTest, InitialVariableNames) {
  using css_test_helpers::CreateLengthRegistration;

  PropertyRegistry* registry = MakeGarbageCollected<PropertyRegistry>();
  registry->RegisterProperty(AtomicString("--x"),
                             *CreateLengthRegistration("--x", 1));
  registry->RegisterProperty(AtomicString("--y"),
                             *CreateLengthRegistration("--y", 2));

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetInitialData(
      MakeGarbageCollected<StyleInitialData>(GetDocument(), *registry));
  const ComputedStyle* style = builder.TakeStyle();

  EXPECT_EQ(2u, style->GetVariableNames().size());
  EXPECT_TRUE(style->GetVariableNames().Contains("--x"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--y"));
}

TEST_F(ComputedStyleTest, InheritedVariableNames) {
  using css_test_helpers::CreateVariableData;

  const bool inherited = true;
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--a"), CreateVariableData("foo"),
                          inherited);
  builder.SetVariableData(AtomicString("--b"), CreateVariableData("bar"),
                          inherited);
  const ComputedStyle* style = builder.TakeStyle();

  EXPECT_EQ(2u, style->GetVariableNames().size());
  EXPECT_TRUE(style->GetVariableNames().Contains("--a"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--b"));
}

TEST_F(ComputedStyleTest, NonInheritedVariableNames) {
  using css_test_helpers::CreateVariableData;

  const bool inherited = true;
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--a"), CreateVariableData("foo"),
                          !inherited);
  builder.SetVariableData(AtomicString("--b"), CreateVariableData("bar"),
                          !inherited);
  const ComputedStyle* style = builder.TakeStyle();

  EXPECT_EQ(2u, style->GetVariableNames().size());
  EXPECT_TRUE(style->GetVariableNames().Contains("--a"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--b"));
}

TEST_F(ComputedStyleTest, InheritedAndNonInheritedVariableNames) {
  using css_test_helpers::CreateVariableData;

  const bool inherited = true;
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--a"), CreateVariableData("foo"),
                          inherited);
  builder.SetVariableData(AtomicString("--b"), CreateVariableData("bar"),
                          inherited);
  builder.SetVariableData(AtomicString("--d"), CreateVariableData("foz"),
                          !inherited);
  builder.SetVariableData(AtomicString("--c"), CreateVariableData("baz"),
                          !inherited);
  const ComputedStyle* style = builder.TakeStyle();

  EXPECT_EQ(4u, style->GetVariableNames().size());
  EXPECT_TRUE(style->GetVariableNames().Contains("--a"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--b"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--c"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--d"));
}

TEST_F(ComputedStyleTest, InitialAndInheritedAndNonInheritedVariableNames) {
  using css_test_helpers::CreateLengthRegistration;
  using css_test_helpers::CreateVariableData;

  PropertyRegistry* registry = MakeGarbageCollected<PropertyRegistry>();
  registry->RegisterProperty(AtomicString("--b"),
                             *CreateLengthRegistration("--b", 1));
  registry->RegisterProperty(AtomicString("--e"),
                             *CreateLengthRegistration("--e", 2));

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetInitialData(
      MakeGarbageCollected<StyleInitialData>(GetDocument(), *registry));

  const bool inherited = true;
  builder.SetVariableData(AtomicString("--a"), CreateVariableData("foo"),
                          inherited);
  builder.SetVariableData(AtomicString("--b"), CreateVariableData("bar"),
                          inherited);
  builder.SetVariableData(AtomicString("--d"), CreateVariableData("foz"),
                          !inherited);
  builder.SetVariableData(AtomicString("--c"), CreateVariableData("baz"),
                          !inherited);
  const ComputedStyle* style = builder.TakeStyle();

  EXPECT_EQ(5u, style->GetVariableNames().size());
  EXPECT_TRUE(style->GetVariableNames().Contains("--a"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--b"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--c"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--d"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--e"));
}

TEST_F(ComputedStyleTest, GetVariableNamesCount_Invalidation) {
  const ComputedStyle* style = InitialComputedStyle();
  EXPECT_EQ(style->GetVariableNamesCount(), 0u);

  auto* data = css_test_helpers::CreateVariableData("foo");
  ComputedStyleBuilder builder(*style);
  builder.SetVariableData(AtomicString("--x"), data, false);
  style = builder.TakeStyle();
  EXPECT_EQ(style->GetVariableNamesCount(), 1u);

  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--y"), data, false);
  style = builder.TakeStyle();
  EXPECT_EQ(style->GetVariableNamesCount(), 2u);

  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--z"), data, true);
  style = builder.TakeStyle();
  EXPECT_EQ(style->GetVariableNamesCount(), 3u);
}

TEST_F(ComputedStyleTest, GetVariableNames_Invalidation) {
  const ComputedStyle* style;

  auto* data = css_test_helpers::CreateVariableData("foo");
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetVariableData(AtomicString("--x"), data, false);
  style = builder.TakeStyle();
  EXPECT_EQ(style->GetVariableNames().size(), 1u);
  EXPECT_TRUE(style->GetVariableNames().Contains("--x"));

  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--y"), data, false);
  style = builder.TakeStyle();
  EXPECT_EQ(style->GetVariableNames().size(), 2u);
  EXPECT_TRUE(style->GetVariableNames().Contains("--x"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--y"));

  builder = ComputedStyleBuilder(*style);
  builder.SetVariableData(AtomicString("--z"), data, true);
  style = builder.TakeStyle();
  EXPECT_EQ(style->GetVariableNames().size(), 3u);
  EXPECT_TRUE(style->GetVariableNames().Contains("--x"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--y"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--z"));
}

TEST_F(ComputedStyleTest, GetVariableNamesWithInitialData_Invalidation) {
  using css_test_helpers::CreateLengthRegistration;

  const ComputedStyle* style;

  {
    ComputedStyleBuilder builder = CreateComputedStyleBuilder();
    PropertyRegistry* registry = MakeGarbageCollected<PropertyRegistry>();
    registry->RegisterProperty(AtomicString("--x"),
                               *CreateLengthRegistration("--x", 1));
    builder.SetInitialData(
        MakeGarbageCollected<StyleInitialData>(GetDocument(), *registry));
    style = builder.TakeStyle();
  }
  EXPECT_EQ(style->GetVariableNames().size(), 1u);
  EXPECT_TRUE(style->GetVariableNames().Contains("--x"));

  // Not set StyleInitialData to something else.
  {
    ComputedStyleBuilder builder(*style);
    PropertyRegistry* registry = MakeGarbageCollected<PropertyRegistry>();
    registry->RegisterProperty(AtomicString("--y"),
                               *CreateLengthRegistration("--y", 2));
    registry->RegisterProperty(AtomicString("--z"),
                               *CreateLengthRegistration("--z", 3));
    builder.SetInitialData(
        MakeGarbageCollected<StyleInitialData>(GetDocument(), *registry));
    style = builder.TakeStyle();
  }
  EXPECT_EQ(style->GetVariableNames().size(), 2u);
  EXPECT_TRUE(style->GetVariableNames().Contains("--y"));
  EXPECT_TRUE(style->GetVariableNames().Contains("--z"));
}

TEST_F(ComputedStyleTest, BorderWidthZoom) {
  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <style>
      div {
        border-top-style: solid;
        column-rule-style: solid;
        outline-style: solid;
        border-top-width: var(--x);
        column-rule-width: var(--x);
        outline-width: var(--x);
        zoom: 2;
      }
      #thin { --x: thin; }
      #medium { --x: medium; }
      #thick { --x: thick; }
    </style>
    <div id="thin"></div>
    <div id="medium"></div>
    <div id="thick"></div>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();

  const struct {
    const ComputedStyle* style;
    double expected_px;
    STACK_ALLOCATED();
  } tests[] = {
      {document.getElementById(AtomicString("thin"))->GetComputedStyle(), 1.0},
      {document.getElementById(AtomicString("medium"))->GetComputedStyle(),
       3.0},
      {document.getElementById(AtomicString("thick"))->GetComputedStyle(), 5.0},
  };

  for (const auto& test : tests) {
    for (const Longhand* property :
         {static_cast<const Longhand*>(&GetCSSPropertyBorderTopWidth()),
          static_cast<const Longhand*>(&GetCSSPropertyOutlineWidth()),
          static_cast<const Longhand*>(&GetCSSPropertyColumnRuleWidth())}) {
      const Longhand& longhand = To<Longhand>(*property);
      auto* computed_value = longhand.CSSValueFromComputedStyleInternal(
          *test.style, nullptr /* layout_object */,
          false /* allow_visited_style */, CSSValuePhase::kComputedValue);
      AtomicString prop_name = longhand.GetCSSPropertyName().ToAtomicString();
      ASSERT_TRUE(computed_value) << prop_name;
      auto* numeric_value = DynamicTo<CSSNumericLiteralValue>(computed_value);
      ASSERT_TRUE(numeric_value) << prop_name;
      EXPECT_TRUE(numeric_value->IsPx()) << prop_name;
      EXPECT_EQ(test.expected_px, numeric_value->DoubleValue()) << prop_name;
    }
  }
}

TEST_F(ComputedStyleTest, BorderWidthConversion) {
  // Tests that Border, Outline and Column Rule Widths
  // are converted as expected.

  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <style>
      div {
        border-top-style: solid;
        column-rule-style: solid;
        outline-style: solid;
        border-top-width: var(--x);
        column-rule-width: var(--x);
        outline-width: var(--x);
      }
      #t1 { --x: 0px; }
      #t2 { --x: 0.1px; }
      #t3 { --x: 0.5px; }
      #t4 { --x: 0.9px; }
      #t5 { --x: 1.0px; }
      #t6 { --x: 3.0px; }
      #t7 { --x: 3.3px; }
      #t8 { --x: 3.5px; }
      #t9 { --x: 3.9px; }
      #t10 { --x: 3.999px; }
    </style>
    <div id="t1"></div>
    <div id="t2"></div>
    <div id="t3"></div>
    <div id="t4"></div>
    <div id="t5"></div>
    <div id="t6"></div>
    <div id="t7"></div>
    <div id="t8"></div>
    <div id="t9"></div>
    <div id="t10"></div>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();

  const struct {
    const ComputedStyle* style;
    double expected_px;
    STACK_ALLOCATED();
  } tests[] = {
      {document.getElementById(AtomicString("t1"))->GetComputedStyle(), 0.0},
      {document.getElementById(AtomicString("t2"))->GetComputedStyle(), 1.0},
      {document.getElementById(AtomicString("t3"))->GetComputedStyle(), 1.0},
      {document.getElementById(AtomicString("t4"))->GetComputedStyle(), 1.0},
      {document.getElementById(AtomicString("t5"))->GetComputedStyle(), 1.0},
      {document.getElementById(AtomicString("t6"))->GetComputedStyle(), 3.0},
      {document.getElementById(AtomicString("t7"))->GetComputedStyle(), 3.0},
      {document.getElementById(AtomicString("t8"))->GetComputedStyle(), 3.0},
      {document.getElementById(AtomicString("t9"))->GetComputedStyle(), 3.0},
      {document.getElementById(AtomicString("t10"))->GetComputedStyle(), 3.0},
  };

  for (const auto& test : tests) {
    for (const Longhand* longhand :
         {static_cast<const Longhand*>(&GetCSSPropertyBorderTopWidth()),
          static_cast<const Longhand*>(&GetCSSPropertyOutlineWidth()),
          static_cast<const Longhand*>(&GetCSSPropertyColumnRuleWidth())}) {
      auto* computed_value = longhand->CSSValueFromComputedStyleInternal(
          *test.style, nullptr /* layout_object */,
          false /* allow_visited_style */, CSSValuePhase::kComputedValue);
      ASSERT_NE(computed_value, nullptr);
      auto* numeric_value = DynamicTo<CSSNumericLiteralValue>(computed_value);
      ASSERT_NE(numeric_value, nullptr);
      EXPECT_TRUE(numeric_value->IsPx());
      EXPECT_DOUBLE_EQ(test.expected_px, numeric_value->DoubleValue());
    }
  }
}

TEST_F(ComputedStyleTest, BorderWidthConversionWithZoom) {
  // Tests that Border Widths
  // are converted as expected when Zoom is applied.

  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <style>
      div {
        border-top-style: solid;
        border-top-width: var(--x);
        zoom: 2;
      }
      #t1 { --x: thin; }
      #t2 { --x: medium; }
      #t3 { --x: thick; }
      #t4 { --x: 0px; }
      #t5 { --x: 0.1px; }
      #t6 { --x: 0.5px; }
      #t7 { --x: 0.9px; }
      #t8 { --x: 1.0px; }
      #t9 { --x: 1.5px; }
      #t10 { --x: 3.0px; }
      #t11 { --x: 3.3px; }
      #t12 { --x: 3.5px; }
      #t13 { --x: 3.9px; }
    </style>
    <div id="t1"></div>
    <div id="t2"></div>
    <div id="t3"></div>
    <div id="t4"></div>
    <div id="t5"></div>
    <div id="t6"></div>
    <div id="t7"></div>
    <div id="t8"></div>
    <div id="t9"></div>
    <div id="t10"></div>
    <div id="t11"></div>
    <div id="t12"></div>
    <div id="t13"></div>
  )HTML");
  document.View()->UpdateAllLifecyclePhasesForTest();

  const struct {
    const ComputedStyle* style;
    int expected_px;
    STACK_ALLOCATED();
  } tests[] = {
      {document.getElementById(AtomicString("t1"))->GetComputedStyle(), 2},
      {document.getElementById(AtomicString("t2"))->GetComputedStyle(), 6},
      {document.getElementById(AtomicString("t3"))->GetComputedStyle(), 10},
      {document.getElementById(AtomicString("t4"))->GetComputedStyle(), 0},
      {document.getElementById(AtomicString("t5"))->GetComputedStyle(), 1},
      {document.getElementById(AtomicString("t6"))->GetComputedStyle(), 1},
      {document.getElementById(AtomicString("t7"))->GetComputedStyle(), 1},
      {document.getElementById(AtomicString("t8"))->GetComputedStyle(), 2},
      {document.getElementById(AtomicString("t9"))->GetComputedStyle(), 3},
      {document.getElementById(AtomicString("t10"))->GetComputedStyle(), 6},
      {document.getElementById(AtomicString("t11"))->GetComputedStyle(), 6},
      {document.getElementById(AtomicString("t12"))->GetComputedStyle(), 7},
      {document.getElementById(AtomicString("t13"))->GetComputedStyle(), 7},
  };

  for (const auto& test : tests) {
    auto width = test.style->BorderTopWidth();
    EXPECT_EQ(test.expected_px, width);
  }
}

TEST_F(ComputedStyleTest,
       TextDecorationEqualDoesNotRequireRecomputeInkOverflow) {
  using css_test_helpers::ParseDeclarationBlock;

  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <style>
      div {
        text-decoration: underline solid green 5px;
        text-underline-offset: 2px;
        text-underline-position: under;
      }
    </style>
    <div id="style"></div>
    <div id="clone"></div>
    <div id="other" style="text-decoration-color: blue;"></div>
  )HTML",
                                ASSERT_NO_EXCEPTION);
  document.View()->UpdateAllLifecyclePhasesForTest();

  const ComputedStyle* style =
      document.getElementById(AtomicString("style"))->GetComputedStyle();
  const ComputedStyle* clone =
      document.getElementById(AtomicString("clone"))->GetComputedStyle();
  const ComputedStyle* other =
      document.getElementById(AtomicString("other"))->GetComputedStyle();

  EXPECT_EQ(TextDecorationLine::kUnderline, style->TextDecorationsInEffect());

  StyleDifference diff1 = style->VisualInvalidationDiff(GetDocument(), *clone);
  EXPECT_FALSE(diff1.NeedsRecomputeVisualOverflow());

  // Different color, should not invalidate.
  StyleDifference diff2 = style->VisualInvalidationDiff(GetDocument(), *other);
  EXPECT_FALSE(diff2.NeedsRecomputeVisualOverflow());
}

TEST_F(ComputedStyleTest, TextDecorationNotEqualRequiresRecomputeInkOverflow) {
  using css_test_helpers::ParseDeclarationBlock;

  Document& document = GetDocument();
  document.body()->setInnerHTML(R"HTML(
    <style>
      div {
        text-decoration: underline solid green 5px;
        text-underline-offset: 2px;
        text-underline-position: under;
      }
    </style>
    <div id="style"></div>
    <div id="wavy" style="text-decoration-style: wavy;"></div>
    <div id="overline" style="text-decoration-line: overline;"></div>
    <div id="thickness" style="text-decoration-thickness: 3px;"></div>
    <div id="offset" style="text-underline-offset: 4px;"></div>
    <div id="position" style="text-underline-position: left;"></div>
  )HTML",
                                ASSERT_NO_EXCEPTION);
  document.View()->UpdateAllLifecyclePhasesForTest();

  const ComputedStyle* style =
      document.getElementById(AtomicString("style"))->GetComputedStyle();
  const ComputedStyle* wavy =
      document.getElementById(AtomicString("wavy"))->GetComputedStyle();
  const ComputedStyle* overline =
      document.getElementById(AtomicString("overline"))->GetComputedStyle();
  const ComputedStyle* thickness =
      document.getElementById(AtomicString("thickness"))->GetComputedStyle();
  const ComputedStyle* offset =
      document.getElementById(AtomicString("offset"))->GetComputedStyle();
  const ComputedStyle* position =
      document.getElementById(AtomicString("position"))->GetComputedStyle();

  // Change decoration style
  StyleDifference diff_decoration_style =
      style->VisualInvalidationDiff(GetDocument(), *wavy);
  EXPECT_TRUE(diff_decoration_style.NeedsRecomputeVisualOverflow());

  // Change decoration line
  StyleDifference diff_decoration_line =
      style->VisualInvalidationDiff(GetDocument(), *overline);
  EXPECT_TRUE(diff_decoration_line.NeedsRecomputeVisualOverflow());

  // Change decoration thickness
  StyleDifference diff_decoration_thickness =
      style->VisualInvalidationDiff(GetDocument(), *thickness);
  EXPECT_TRUE(diff_decoration_thickness.NeedsRecomputeVisualOverflow());

  // Change underline offset
  StyleDifference diff_underline_offset =
      style->VisualInvalidationDiff(GetDocument(), *offset);
  EXPECT_TRUE(diff_underline_offset.NeedsRecomputeVisualOverflow());

  // Change underline position
  StyleDifference diff_underline_position =
      style->VisualInvalidationDiff(GetDocument(), *position);
  EXPECT_TRUE(diff_underline_position.NeedsRecomputeVisualOverflow());
}

// Verify that cloned ComputedStyle is independent from source, i.e.
// copy-on-write works as expected.
TEST_F(ComputedStyleTest, ClonedStyleAnimationsAreIndependent) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();

  auto& animations = builder.AccessAnimations();
  animations.DelayStartList().clear();
  animations.DelayStartList().push_back(CSSAnimationData::InitialDelayStart());
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_EQ(1u, style->Animations()->DelayStartList().size());

  builder = ComputedStyleBuilder(*style);
  auto& cloned_style_animations = builder.AccessAnimations();
  EXPECT_EQ(1u, cloned_style_animations.DelayStartList().size());
  cloned_style_animations.DelayStartList().push_back(
      CSSAnimationData::InitialDelayStart());
  const ComputedStyle* cloned_style = builder.TakeStyle();

  EXPECT_EQ(2u, cloned_style->Animations()->DelayStartList().size());
  EXPECT_EQ(1u, style->Animations()->DelayStartList().size());
}

TEST_F(ComputedStyleTest, ClonedStyleTransitionsAreIndependent) {
  ComputedStyleBuilder builder = CreateComputedStyleBuilder();

  auto& transitions = builder.AccessTransitions();
  transitions.PropertyList().clear();
  transitions.PropertyList().push_back(CSSTransitionData::InitialProperty());
  const ComputedStyle* style = builder.TakeStyle();
  EXPECT_EQ(1u, style->Transitions()->PropertyList().size());

  builder = ComputedStyleBuilder(*style);
  auto& cloned_style_transitions = builder.AccessTransitions();
  EXPECT_EQ(1u, cloned_style_transitions.PropertyList().size());
  cloned_style_transitions.PropertyList().push_back(
      CSSTransitionData::InitialProperty());
  const ComputedStyle* cloned_style = builder.TakeStyle();

  EXPECT_EQ(2u, cloned_style->Transitions()->PropertyList().size());
  EXPECT_EQ(1u, style->Transitions()->PropertyList().size());
}

TEST_F(ComputedStyleTest, ApplyInitialAnimationNameAndTransitionProperty) {
  Document& document = GetDocument();
  const ComputedStyle* initial =
      document.GetStyleResolver().InitialStyleForElement();

  StyleResolverState state(document, *document.documentElement(),
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(initial));

  state.SetStyle(*initial);
  EXPECT_FALSE(state.StyleBuilder().Animations());
  EXPECT_FALSE(state.StyleBuilder().Transitions());

  GetCSSPropertyAnimationName().ApplyInitial(state);
  GetCSSPropertyTransitionProperty().ApplyInitial(state);
  EXPECT_FALSE(state.StyleBuilder().Animations());
  EXPECT_FALSE(state.StyleBuilder().Transitions());
}

#define TEST_STYLE_VALUE_NO_DIFF(field_name)                       \
  {                                                                \
    ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();  \
    ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();  \
    builder1.Set##field_name(                                      \
        ComputedStyleInitialValues::Initial##field_name());        \
    builder2.Set##field_name(                                      \
        ComputedStyleInitialValues::Initial##field_name());        \
    const ComputedStyle* style1 = builder1.TakeStyle();            \
    const ComputedStyle* style2 = builder2.TakeStyle();            \
    auto diff = style1->VisualInvalidationDiff(document, *style2); \
    EXPECT_FALSE(diff.HasDifference());                            \
  }

// Ensures ref-counted values are compared by their values, not by pointers.
#define TEST_STYLE_REFCOUNTED_VALUE_NO_DIFF(type, field_name)              \
  {                                                                        \
    ComputedStyleBuilder builder1 = CreateComputedStyleBuilder();          \
    ComputedStyleBuilder builder2 = CreateComputedStyleBuilder();          \
    scoped_refptr<type> value1 = base::MakeRefCounted<type>();             \
    scoped_refptr<type> value2 = base::MakeRefCounted<type>(value1->data); \
    builder1.Set##field_name(value1);                                      \
    builder2.Set##field_name(value2);                                      \
    const ComputedStyle* style1 = builder1.TakeStyle();                    \
    const ComputedStyle* style2 = builder2.TakeStyle();                    \
    auto diff = style1->VisualInvalidationDiff(document, *style2);         \
    EXPECT_FALSE(diff.HasDifference());                                    \
  }

TEST_F(ComputedStyleTest, SvgStrokeStyleShouldCompareValue) {
  Document& document = GetDocument();
  TEST_STYLE_VALUE_NO_DIFF(StrokeOpacity);
  TEST_STYLE_VALUE_NO_DIFF(StrokeMiterLimit);
  TEST_STYLE_VALUE_NO_DIFF(StrokeWidth);
  TEST_STYLE_VALUE_NO_DIFF(StrokeDashOffset);
  TEST_STYLE_REFCOUNTED_VALUE_NO_DIFF(SVGDashArray, StrokeDashArray);

  TEST_STYLE_VALUE_NO_DIFF(StrokePaint);
  TEST_STYLE_VALUE_NO_DIFF(InternalVisitedStrokePaint);
}

TEST_F(ComputedStyleTest, SvgMiscStyleShouldCompareValue) {
  Document& document = GetDocument();
  TEST_STYLE_VALUE_NO_DIFF(FloodColor);
  TEST_STYLE_VALUE_NO_DIFF(FloodOpacity);
  TEST_STYLE_VALUE_NO_DIFF(LightingColor);
  TEST_STYLE_VALUE_NO_DIFF(BaselineShift);
}

TEST_F(ComputedStyleTest, ShouldApplyAnyContainment) {
  Document& document = GetDocument();

  auto* html = document.documentElement();
  auto* body = document.body();
  ASSERT_TRUE(html);
  ASSERT_TRUE(body);

  std::vector display_types = {CSSValueID::k
```