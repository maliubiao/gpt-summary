Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the CSS parser in the Chromium Blink engine.

I need to:
1. **Identify the core purpose** of the code, which is testing the parsing of various CSS features.
2. **List the specific CSS features** being tested, such as `@layer`, `@import`, `@supports`, `@font-palette-values`, `@font-feature-values`, and `@function`.
3. **Explain the relationship** of these features to HTML, CSS, and JavaScript.
4. **Provide examples** of how these features are used in each language.
5. **Infer the input and expected output** for some test cases based on the assertions in the code.
6. **Identify potential user errors** related to these CSS features.
7. **Describe how a user might trigger** these parsing tests (debugging scenario).
8. **Summarize the overall functionality** of the provided code snippet.
这是对 `blink/renderer/core/css/parser/css_parser_impl_test.cc` 文件第二部分的分析和功能归纳。

**功能归纳:**

这部分代码继续测试 CSSParserImpl 类的 CSS 解析功能，主要集中在以下 CSS 特性的解析和处理：

* **`@font-palette-values` 规则:** 测试了 `@font-palette-values` 规则的基本解析，包括解析规则名称、`font-family` 描述符、`base-palette` 和 `override-colors` 描述符。同时测试了当特性被禁用时的处理以及 `font-family` 描述符中不允许使用通用字体族的情况。
* **`@font-feature-values` 规则:** 测试了 `@font-feature-values` 规则的解析，包括解析关联的字体族、`@styleset` 和 `@swash` 块。还测试了在 Inspector 中解析时如何记录规则的偏移量。
* **`@function` 规则:**  测试了 `@function` 规则的解析，特别是提取函数体的内容。
* **解析所有 CSS 属性并处理 `!important` 标记:** 遍历所有 WebExposed 的 CSS 属性，并测试 CSSParserImpl 是否能正确解析带有 `!important` 标记的属性值。
* **`@supports blink-feature()` 规则:** 测试了 Blink 特定的 `@supports` 规则，用于检查特定实验性 CSS 特性是否被启用。区分了用户代理样式表和作者样式表中的行为，以及特性启用和禁用时的解析结果。
* **处理类似自定义属性的规则时的歧义:** 测试了当遇到看起来像自定义属性选择器（例如 `--x:hover`) 但实际上不符合标准 CSS 语法时的解析行为，区分了顶级规则和嵌套规则的情况。
* **处理无效规则错误:** 测试了当解析器遇到无效的 CSS 规则（例如带有无效选择器）时是否能正确标记错误。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这部分代码的核心是测试 CSS 解析器，因此与 CSS 的各种语法规则直接相关。例如：
    * **`@font-palette-values`:** 定义了字体调色板的值，可以在 CSS 中使用 `font-palette` 属性引用。
        ```css
        @font-palette-values --myPalette {
          font-family: MyFont;
          base-palette: 1;
          override-colors: 0 red, 1 blue;
        }

        body {
          font-family: MyFont;
          font-palette: --myPalette;
        }
        ```
    * **`@font-feature-values`:**  允许为特定的 OpenType 特性定义有意义的名称，然后在 CSS 中通过 `font-variant-settings` 属性使用。
        ```css
        @font-feature-values MyFont {
          @styleset { nice-curly-e: 1; }
        }

        body {
          font-family: MyFont;
          font-variant-settings: "ss01" 1; /* 或者使用自定义的名字 */
          font-variant-settings: "curly" 1; /* 假设 curly 映射到 ss01 */
        }
        ```
    * **`@function`:** 允许在 CSS 中定义自定义函数，用于计算属性值。
        ```css
        @function double($x) {
          @return calc($x * 2);
        }

        div {
          width: double(10px); /* 结果为 20px */
        }
        ```
    * **`@supports blink-feature()`:**  允许根据 Blink 引擎特定的特性支持情况应用不同的样式。
        ```css
        @supports blink-feature(CSSGridLayout) {
          .container {
            display: grid;
          }
        }
        ```
* **HTML:** CSS 样式最终应用于 HTML 元素，影响其渲染。例如，通过上述 CSS 代码，HTML 元素的字体、颜色、布局等外观会发生变化。
* **JavaScript:** JavaScript 可以操作 DOM 结构和元素的样式，也可以读取或修改 CSS 样式表。例如，可以使用 JavaScript 来动态地添加或修改带有 `@font-palette-values` 或 `@supports` 规则的样式表。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  CSS 字符串 `@font-palette-values --test { font-family: Arial; base-palette: 2; }`
* **预期输出:** 解析器成功创建一个 `StyleRuleFontPaletteValues` 对象，其 `GetName()` 返回 `--test`，`GetFontFamily()->CssText()` 返回 `Arial`，并且 `GetBasePalette()` 的计算值为 `2`。

* **假设输入:** CSS 字符串 `@supports blink-feature(NonExistentFeature) { div { color: blue; } }` 作为用户代理样式表进行解析。
* **预期输出:**  解析器创建一个 `StyleRuleSupports` 对象，其 `ConditionIsSupported()` 返回 `false`，但其内部的 `div { color: blue; }` 规则仍然会被解析并存储。

**用户或编程常见的使用错误:**

* **`@font-palette-values` 中 `font-family` 使用通用字体族:** 用户可能会错误地在 `@font-palette-values` 的 `font-family` 中使用 `serif`、`sans-serif` 等通用字体族，这是不允许的。
    ```css
    @font-palette-values --myPalette {
      font-family: serif; /* 错误用法 */
    }
    ```
* **`@supports blink-feature()` 在作者样式表中的误用:** 开发者可能会错误地认为在所有样式表中 `@supports blink-feature()` 都会像用户代理样式表一样工作，但实际上在作者样式表中，即使特性存在，条件也可能为 false。
* **拼写错误或语法错误的 CSS 规则:**  例如 `@font-parette-values` (拼写错误) 或者 `@font-palette-values --myPalette font-family: Arial;` (缺少花括号)。这些错误会导致解析失败。
* **在不支持的浏览器中使用新的 CSS 特性:** 用户编写了使用了 `@font-palette-values` 等新特性的 CSS，但在旧版本的浏览器中可能无法生效。

**用户操作到达此处的调试线索:**

1. **用户在 HTML 文件中引入了包含特定 CSS 特性的样式表:** 用户可能在 `<style>` 标签内或者通过 `<link>` 引入了包含 `@font-palette-values`, `@font-feature-values`, `@supports blink-feature()` 或 `@function` 等规则的 CSS 代码。
2. **浏览器加载并解析样式表:** 当浏览器渲染页面时，Blink 引擎的 CSS 解析器会负责解析这些样式表。
3. **解析器遇到相关的 CSS 规则:** 当解析器扫描到这些特定的 `@` 规则时，会调用相应的解析逻辑。
4. **测试用例覆盖了这些解析路径:**  为了确保解析器的正确性，`css_parser_impl_test.cc` 中的测试用例会模拟各种合法的和非法的 CSS 语法，覆盖这些解析路径。
5. **开发者调试解析器逻辑:** 如果解析器在处理这些规则时出现错误，Chromium 的开发者可能会运行这些测试用例来定位和修复问题。他们可能会在 `CSSParserImpl::ParseStyleSheet` 或相关的解析函数中设置断点，单步执行代码，观察解析过程中的状态变化。

总而言之，这部分测试代码专注于验证 `CSSParserImpl` 类对于一些相对较新或特定的 CSS 特性的解析能力，确保 Blink 引擎能够正确理解和处理这些 CSS 代码。 这对于保证 Web 页面的正常渲染和开发者能够使用最新的 CSS 功能至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_parser_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
RT_EQ(2u, barbaz->GetNames().size());
    ASSERT_EQ(1u, barbaz->GetNames()[0].size());
    EXPECT_EQ("bar", barbaz->GetNames()[0][0]);
    ASSERT_EQ(1u, barbaz->GetNames()[1].size());
    EXPECT_EQ("baz", barbaz->GetNames()[1][0]);
  }

  // Nested in an unnamed layer.
  {
    String rule = "@layer { @layer foo; @layer bar { } }";
    auto* parent = DynamicTo<StyleRuleLayerBlock>(ParseRule(*document, rule));
    ASSERT_TRUE(parent);
    ASSERT_EQ(1u, parent->GetName().size());
    EXPECT_EQ(g_empty_atom, parent->GetName()[0]);
    ASSERT_EQ(2u, parent->ChildRules().size());

    auto* foo =
        DynamicTo<StyleRuleLayerStatement>(parent->ChildRules()[0].Get());
    ASSERT_TRUE(foo);
    ASSERT_EQ(1u, foo->GetNames().size());
    ASSERT_EQ(1u, foo->GetNames()[0].size());
    EXPECT_EQ("foo", foo->GetNames()[0][0]);

    auto* bar = DynamicTo<StyleRuleLayerBlock>(parent->ChildRules()[1].Get());
    ASSERT_TRUE(bar);
    ASSERT_EQ(1u, bar->GetName().size());
    EXPECT_EQ("bar", bar->GetName()[0]);
  }
}

TEST(CSSParserImplTest, LayeredImportRules) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  {
    String rule = "@import url(foo.css) layer;";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->IsLayered());
    ASSERT_EQ(1u, parsed->GetLayerName().size());
    EXPECT_EQ(g_empty_atom, parsed->GetLayerName()[0]);
  }

  {
    String rule = "@import url(foo.css) layer(bar);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->IsLayered());
    ASSERT_EQ(1u, parsed->GetLayerName().size());
    EXPECT_EQ("bar", parsed->GetLayerName()[0]);
  }

  {
    String rule = "@import url(foo.css) layer(bar.baz);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->IsLayered());
    ASSERT_EQ(2u, parsed->GetLayerName().size());
    EXPECT_EQ("bar", parsed->GetLayerName()[0]);
    EXPECT_EQ("baz", parsed->GetLayerName()[1]);
  }
}

TEST(CSSParserImplTest, LayeredImportRulesInvalid) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  // Invalid layer declarations in @import rules should not make the entire rule
  // invalid. They should be parsed as <general-enclosed> and have no effect.

  {
    String rule = "@import url(foo.css) layer();";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_FALSE(parsed->IsLayered());
  }

  {
    String rule = "@import url(foo.css) layer(bar, baz);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_FALSE(parsed->IsLayered());
  }

  {
    String rule = "@import url(foo.css) layer(bar.baz.);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_FALSE(parsed->IsLayered());
  }
}

TEST(CSSParserImplTest, ImportRulesWithSupports) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  {
    String rule =
        "@import url(foo.css) layer(bar.baz) supports(display: block);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_TRUE(parsed->IsSupported());
  }

  {
    String rule = "@import url(foo.css) supports(display: block);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_TRUE(parsed->IsSupported());
  }

  {
    String rule =
        "@import url(foo.css)   supports((display: block) and (color: green));";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_TRUE(parsed->IsSupported());
  }

  {
    String rule =
        "@import url(foo.css) supports((foo: bar) and (color: green));";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_FALSE(parsed->IsSupported());
  }

  {
    String rule = "@import url(foo.css) supports());";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    EXPECT_FALSE(parsed);
  }

  {
    String rule = "@import url(foo.css) supports(color: green) (width >= 0px);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    EXPECT_TRUE(parsed->IsSupported());
    EXPECT_TRUE(parsed->MediaQueries());
    EXPECT_EQ(parsed->MediaQueries()->QueryVector().size(), 1u);
    EXPECT_EQ(parsed->MediaQueries()->MediaText(), String("(width >= 0px)"));
  }
}

TEST(CSSParserImplTest, LayeredImportRulesMultipleLayers) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  // If an @import rule has more than one layer keyword/function, only the first
  // one is parsed as layer, and the remaining ones are parsed as
  // <general-enclosed> and hence have no effect.

  {
    String rule = "@import url(foo.css) layer layer;";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->IsLayered());
    ASSERT_EQ(1u, parsed->GetLayerName().size());
    EXPECT_EQ(g_empty_atom, parsed->GetLayerName()[0]);
    EXPECT_EQ("not all", parsed->MediaQueries()->MediaText());
  }

  {
    String rule = "@import url(foo.css) layer layer(bar);";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->IsLayered());
    ASSERT_EQ(1u, parsed->GetLayerName().size());
    EXPECT_EQ(g_empty_atom, parsed->GetLayerName()[0]);
  }

  {
    String rule = "@import url(foo.css) layer(bar) layer;";
    auto* parsed = DynamicTo<StyleRuleImport>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->IsLayered());
    ASSERT_EQ(1u, parsed->GetLayerName().size());
    EXPECT_EQ("bar", parsed->GetLayerName()[0]);
    EXPECT_EQ("not all", parsed->MediaQueries()->MediaText());
  }
}

TEST(CSSParserImplTest, CorrectAtRuleOrderingWithLayers) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    @layer foo;
    @import url(bar.css) layer(bar);
    @namespace url(http://www.w3.org/1999/xhtml);
    @layer baz;
    @layer qux { }
  )CSS";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  // All rules should parse successfully.
  EXPECT_EQ(1u, sheet->PreImportLayerStatementRules().size());
  EXPECT_EQ(1u, sheet->ImportRules().size());
  EXPECT_EQ(1u, sheet->NamespaceRules().size());
  EXPECT_EQ(2u, sheet->ChildRules().size());
}

TEST(CSSParserImplTest, EmptyLayerStatementsAtWrongPositions) {
  test::TaskEnvironment task_environment;
  {
    // @layer interleaving with @import rules
    String sheet_text = R"CSS(
      @layer foo;
      @import url(bar.css) layer(bar);
      @layer baz;
      @import url(qux.css);
    )CSS";
    auto* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
    CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

    EXPECT_EQ(1u, sheet->PreImportLayerStatementRules().size());
    EXPECT_EQ(1u, sheet->ChildRules().size());

    // After parsing @layer baz, @import rules are no longer allowed, so the
    // second @import rule should be ignored.
    ASSERT_EQ(1u, sheet->ImportRules().size());
    EXPECT_TRUE(sheet->ImportRules()[0]->IsLayered());
  }

  {
    // @layer between @import and @namespace rules
    String sheet_text = R"CSS(
      @layer foo;
      @import url(bar.css) layer(bar);
      @layer baz;
      @namespace url(http://www.w3.org/1999/xhtml);
    )CSS";
    auto* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
    CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

    EXPECT_EQ(1u, sheet->PreImportLayerStatementRules().size());
    EXPECT_EQ(1u, sheet->ImportRules().size());
    EXPECT_EQ(1u, sheet->ChildRules().size());

    // After parsing @layer baz, @namespace rules are no longer allowed.
    EXPECT_EQ(0u, sheet->NamespaceRules().size());
  }
}

TEST(CSSParserImplTest, EmptyLayerStatementAfterRegularRule) {
  test::TaskEnvironment task_environment;
  // Empty @layer statements after regular rules are parsed as regular rules.

  String sheet_text = R"CSS(
    .element { color: green; }
    @layer foo, bar;
  )CSS";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  EXPECT_EQ(0u, sheet->PreImportLayerStatementRules().size());
  EXPECT_EQ(2u, sheet->ChildRules().size());
  EXPECT_TRUE(sheet->ChildRules()[0]->IsStyleRule());
  EXPECT_TRUE(sheet->ChildRules()[1]->IsLayerStatementRule());
}

TEST(CSSParserImplTest, FontPaletteValuesDisabled) {
  test::TaskEnvironment task_environment;
  // @font-palette-values rules should be ignored when the feature is disabled.

  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  EXPECT_FALSE(ParseRule(*document, "@font-palette-values foo;"));
  EXPECT_FALSE(ParseRule(*document, "@font-palette-values foo { }"));
  EXPECT_FALSE(ParseRule(*document, "@font-palette-values foo.bar { }"));
  EXPECT_FALSE(ParseRule(*document, "@font-palette-values { }"));
}

TEST(CSSParserImplTest, FontPaletteValuesBasicRuleParsing) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  String rule = R"CSS(@font-palette-values --myTestPalette {
    font-family: testFamily;
    base-palette: 0;
    override-colors: 0 red, 1 blue;
  })CSS";
  auto* parsed =
      DynamicTo<StyleRuleFontPaletteValues>(ParseRule(*document, rule));
  ASSERT_TRUE(parsed);
  ASSERT_EQ("--myTestPalette", parsed->GetName());
  ASSERT_EQ("testFamily", parsed->GetFontFamily()->CssText());
  ASSERT_EQ(
      0, DynamicTo<CSSPrimitiveValue>(parsed->GetBasePalette())
             ->ComputeInteger(CSSToLengthConversionData(/*element=*/nullptr)));
  ASSERT_TRUE(parsed->GetOverrideColors()->IsValueList());
  ASSERT_EQ(2u, DynamicTo<CSSValueList>(parsed->GetOverrideColors())->length());
}

TEST(CSSParserImplTest, FontPaletteValuesMultipleFamiliesParsing) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  String rule = R"CSS(@font-palette-values --myTestPalette {
    font-family: testFamily1, testFamily2;
    base-palette: 0;
  })CSS";
  auto* parsed =
      DynamicTo<StyleRuleFontPaletteValues>(ParseRule(*document, rule));
  ASSERT_TRUE(parsed);
  ASSERT_EQ("--myTestPalette", parsed->GetName());
  ASSERT_EQ("testFamily1, testFamily2", parsed->GetFontFamily()->CssText());
  ASSERT_EQ(
      0, DynamicTo<CSSPrimitiveValue>(parsed->GetBasePalette())
             ->ComputeInteger(CSSToLengthConversionData(/*element=*/nullptr)));
}

// Font-family descriptor inside @font-palette-values should not contain generic
// families, compare:
// https://drafts.csswg.org/css-fonts/#descdef-font-palette-values-font-family.
TEST(CSSParserImplTest, FontPaletteValuesGenericFamiliesNotParsing) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  String rule = R"CSS(@font-palette-values --myTestPalette {
    font-family: testFamily1, testFamily2, serif;
    base-palette: 0;
  })CSS";
  auto* parsed =
      DynamicTo<StyleRuleFontPaletteValues>(ParseRule(*document, rule));
  ASSERT_TRUE(parsed);
  ASSERT_EQ("--myTestPalette", parsed->GetName());
  ASSERT_FALSE(parsed->GetFontFamily());
  ASSERT_EQ(
      0, DynamicTo<CSSPrimitiveValue>(parsed->GetBasePalette())
             ->ComputeInteger(CSSToLengthConversionData(/*element=*/nullptr)));
}

TEST(CSSParserImplTest, FontFeatureValuesRuleParsing) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  String rule = R"CSS(@font-feature-values fontFam1, fontFam2 {
    @styleset { curly: 4 3 2 1; wavy: 2; cool: 3; }
    @swash { thrown: 1; }
    @styleset { yo: 1; }
  })CSS";
  auto* parsed =
      DynamicTo<StyleRuleFontFeatureValues>(ParseRule(*document, rule));
  ASSERT_TRUE(parsed);
  auto& families = parsed->GetFamilies();
  ASSERT_EQ(AtomicString("fontFam1"), families[0]);
  ASSERT_EQ(AtomicString("fontFam2"), families[1]);
  ASSERT_EQ(parsed->GetStyleset()->size(), 4u);
  ASSERT_TRUE(parsed->GetStyleset()->Contains(AtomicString("cool")));
  ASSERT_EQ(parsed->GetStyleset()->at(AtomicString("curly")).indices,
            Vector<uint32_t>({4, 3, 2, 1}));
}

TEST(CSSParserImplTest, FontFeatureValuesOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@font-feature-values myFam { @styleset { curly: 1; } }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kFontFeatureValues);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 21u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 27u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 28u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 53u);
}

TEST(CSSParserImplTest, CSSFunction) {
  test::TaskEnvironment task_environment;

  String sheet_text = R"CSS(
    @function --foo(): color {
      @return red;
    }
  )CSS";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);
  ASSERT_EQ(sheet->ChildRules().size(), 1u);

  const StyleRuleFunction* rule =
      DynamicTo<StyleRuleFunction>(sheet->ChildRules()[0].Get());
  EXPECT_TRUE(rule);

  EXPECT_EQ("red", rule->GetFunctionBody().OriginalText());
}

static String RoundTripProperty(Document& document, String property_text) {
  String rule_text = "p { " + property_text + " }";
  StyleRule* style_rule =
      To<StyleRule>(css_test_helpers::ParseRule(document, rule_text));
  if (!style_rule) {
    return "";
  }
  return style_rule->Properties().AsText();
}

TEST(CSSParserImplTest, AllPropertiesCanParseImportant) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  const ComputedStyle& initial_style =
      *ComputedStyle::GetInitialStyleSingleton();

  int broken_properties = 0;

  for (CSSPropertyID property_id : CSSPropertyIDList()) {
    const CSSProperty& property = CSSProperty::Get(property_id);
    if (!property.IsWebExposed() || property.IsSurrogate()) {
      continue;
    }

    // Get some reasonable value that we can use for testing parsing.
    const CSSValue* computed_value = property.CSSValueFromComputedStyle(
        initial_style,
        /*layout_object=*/nullptr,
        /*allow_visited_style=*/true, CSSValuePhase::kComputedValue);
    if (!computed_value) {
      continue;
    }

    // TODO(b/338535751): We have some properties that don't properly
    // round-trip even without !important, so we cannot easily
    // test them using this test. Remove this test when everything
    // is fixed.
    String property_text = property.GetPropertyNameString() + ": " +
                           computed_value->CssText() + ";";
    if (RoundTripProperty(*document, property_text) != property_text) {
      ++broken_properties;
      continue;
    }

    // Now for the actual test.
    property_text = property.GetPropertyNameString() + ": " +
                    computed_value->CssText() + " !important;";
    EXPECT_EQ(RoundTripProperty(*document, property_text), property_text);
  }

  // So that we don't introduce more, or break the entire test inadvertently.
  EXPECT_EQ(broken_properties, 18);
}

TEST(CSSParserImplTest, ParseSupportsBlinkFeature) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    @supports blink-feature(TestFeatureStable) {
      div { color: red; }
      span { color: green; }
    }
  )CSS";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kUASheetMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);
  ASSERT_EQ(sheet->ChildRules().size(), 1u);

  StyleRuleBase* rule = sheet->ChildRules()[0].Get();
  ASSERT_EQ(rule->GetType(), StyleRuleBase::RuleType::kSupports);
  StyleRuleSupports* supports_rule = DynamicTo<StyleRuleSupports>(rule);
  ASSERT_TRUE(supports_rule->ConditionIsSupported());

  HeapVector<Member<StyleRuleBase>> child_rules = supports_rule->ChildRules();
  ASSERT_EQ(child_rules.size(), 2u);
  ASSERT_EQ(String("div"),
            To<StyleRule>(child_rules[0].Get())->SelectorsText());
  ASSERT_EQ(String("span"),
            To<StyleRule>(child_rules[1].Get())->SelectorsText());
}

TEST(CSSParserImplTest, ParseSupportsBlinkFeatureAuthorStylesheet) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    @supports blink-feature(TestFeatureStable) {
      div { color: red; }
      span { color: green; }
    }
  )CSS";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);
  ASSERT_EQ(sheet->ChildRules().size(), 1u);

  StyleRuleBase* rule = sheet->ChildRules()[0].Get();
  ASSERT_EQ(rule->GetType(), StyleRuleBase::RuleType::kSupports);
  StyleRuleSupports* supports_rule = DynamicTo<StyleRuleSupports>(rule);
  EXPECT_FALSE(supports_rule->ConditionIsSupported());
}

TEST(CSSParserImplTest, ParseSupportsBlinkFeatureDisabledFeature) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    @supports blink-feature(TestFeature) {
      div { color: red; }
      span { color: green; }
    }
  )CSS";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kUASheetMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);
  ASSERT_EQ(sheet->ChildRules().size(), 1u);

  StyleRuleBase* rule = sheet->ChildRules()[0].Get();
  ASSERT_EQ(rule->GetType(), StyleRuleBase::RuleType::kSupports);
  StyleRuleSupports* supports_rule = DynamicTo<StyleRuleSupports>(rule);
  ASSERT_FALSE(supports_rule->ConditionIsSupported());

  HeapVector<Member<StyleRuleBase>> child_rules = supports_rule->ChildRules();
  ASSERT_EQ(child_rules.size(), 2u);
  ASSERT_EQ(String("div"),
            To<StyleRule>(child_rules[0].Get())->SelectorsText());
  ASSERT_EQ(String("span"),
            To<StyleRule>(child_rules[1].Get())->SelectorsText());
}

// Test that we behave correctly for rules that look like custom properties.
//
// https://drafts.csswg.org/css-syntax/#consume-qualified-rule

TEST(CSSParserImplTest, CustomPropertyAmbiguityTopLevel) {
  test::TaskEnvironment task_environment;

  String text = "--x:hover { } foo; bar";
  CSSParserTokenStream stream(text);

  bool invalid_rule_error = false;

  TestCSSParserImpl parser;
  const StyleRule* rule = parser.ConsumeStyleRule(
      stream, CSSNestingType::kNone, /* parent_rule_for_nesting */ nullptr,
      /* nested */ false, invalid_rule_error);

  // "If nested is false, consume a block from input, and return nothing."
  EXPECT_EQ(nullptr, rule);
  EXPECT_FALSE(invalid_rule_error);
  EXPECT_EQ(" foo; bar", stream.RemainingText());
}

TEST(CSSParserImplTest, CustomPropertyAmbiguityNested) {
  test::TaskEnvironment task_environment;

  String text = "--x:hover { } foo; bar";
  CSSParserTokenStream stream(text);

  bool invalid_rule_error = false;

  TestCSSParserImpl parser;
  const StyleRule* rule = parser.ConsumeStyleRule(
      stream, CSSNestingType::kNesting, /* parent_rule_for_nesting */ nullptr,
      /* nested */ true, invalid_rule_error);

  // "If nested is true, consume the remnants of a bad declaration from input,
  //  with nested set to true, and return nothing."
  EXPECT_EQ(nullptr, rule);
  EXPECT_FALSE(invalid_rule_error);
  // "Consume the remnants of a bad declaration" should consume everything
  // until the next semicolon, but we leave that to the caller.
  EXPECT_EQ("{ } foo; bar", stream.RemainingText());
}

// https://drafts.csswg.org/css-syntax/#invalid-rule-error

TEST(CSSParserImplTest, InvalidRuleError) {
  test::TaskEnvironment task_environment;

  String text = "<<::any-invalid-selector::>> { } foo; bar";
  CSSParserTokenStream stream(text);

  bool invalid_rule_error = false;

  TestCSSParserImpl parser;
  const StyleRule* rule = parser.ConsumeStyleRule(
      stream, CSSNestingType::kNone, /* parent_rule_for_nesting */ nullptr,
      /* nested */ false, invalid_rule_error);

  EXPECT_EQ(nullptr, rule);
  EXPECT_TRUE(invalid_rule_error);
  EXPECT_EQ(" foo; bar", stream.RemainingText());
}

}  // namespace blink

"""


```