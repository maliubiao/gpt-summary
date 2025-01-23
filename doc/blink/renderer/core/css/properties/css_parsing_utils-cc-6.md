Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. I need to analyze the code and identify its purpose, its relationship to web technologies like JavaScript, HTML, and CSS, and potential usage errors.

Here's a breakdown of the code's key functions and their relevance:

1. **`ConsumeCommaIncludingWhitespace`**:  This is a utility function for parsing comma-separated lists, common in CSS property values.

2. **`ConsumeGenericFamily` and `ConsumeFamilyName`**: These functions are related to parsing font family names, a core CSS feature.

3. **`ConcatenateFamilyName`**:  Handles cases where font family names consist of multiple words.

4. **`CombineToRangeList`**:  Creates a list of two values, likely used for specifying ranges (e.g., font-style: oblique 10deg 20deg;).

5. **`IsAngleWithinLimits`**:  Validates if an angle value is within a specific range.

6. **`ConsumeFontStyle`**: Parses the `font-style` CSS property, including `normal`, `italic`, and `oblique` with optional angle ranges.

7. **`ConsumeFontStretchKeywordOnly` and `ConsumeFontStretch`**:  Parses the `font-stretch` CSS property, which defines the width of the font.

8. **`ConsumeFontWeight`**: Parses the `font-weight` CSS property, including numerical weights and keywords.

9. **`ConsumeFontFeatureSettings` and `ConsumeFontFeatureTag`**: Parses the `font-feature-settings` CSS property, which allows access to advanced typographic features of fonts.

10. **`ConsumeFontVariantCSS21`**: Parses older `font-variant` values.

11. **`ConsumeFontTechIdent` and `ConsumeFontFormatIdent`**: Parses identifiers related to font technologies and formats, potentially used in `@font-face` rules.

12. **`FontFormatToId`, `IsSupportedKeywordTech`, `IsSupportedKeywordFormat`**: Functions for converting and validating font technology and format keywords.

13. **`ParseGridTemplateAreasColumnNames`**:  Parses column names within the `grid-template-areas` CSS property.

14. **`ConsumeGridBreadth`**: Parses values for grid track sizing (e.g., `auto`, lengths, percentages, fractions).

15. **`ConsumeFitContent`**: Parses the `fit-content()` CSS function used in grid layout.

16. **`IsGridBreadthFixedSized` and `IsGridTrackFixedSized`**:  Determine if grid track sizes are fixed or flexible.

17. **`ConsumeGridTrackSize`**: Parses individual grid track sizes, including `minmax()` and `fit-content()`.

18. **`ConsumeCustomIdentForGridLine`**: Parses custom identifiers for grid lines.

19. **`ConsumeGridLineNames`**: Parses bracketed lists of grid line names.

20. **`AppendLineNames`**:  Appends parsed grid line names to a list.

21. **`ConsumeGridTrackRepeatFunction`**: Parses the `repeat()` function used in grid track lists.

22. **`ConsumeGridTemplateRowsAndAreasAndColumns`**:  Parses the combined syntax for `grid-template-rows`, `grid-template-columns`, and `grid-template-areas`.

23. **`ConsumeGridLine`**: Parses values for grid placement properties like `grid-row-start`.

24. **`ConsumeGridTrackList`**: Parses lists of grid track sizes and line names.

25. **`ParseGridTemplateAreasRow`**: Parses a single row of the `grid-template-areas` property.

26. **`ConsumeGridTemplatesRowsOrColumns`**: Parses values for `grid-template-rows` or `grid-template-columns`.

27. **`ConsumeGridItemPositionShorthand`**:  This function's definition is incomplete in the snippet, but it likely parses the shorthand for grid item placement properties.

**Relationship to JavaScript, HTML, and CSS:**

- **CSS:** This file is deeply intertwined with CSS parsing. The functions are responsible for taking CSS property values (represented as tokens) and converting them into internal data structures that the browser can understand and use for rendering. The examples in the code directly correspond to CSS syntax for properties like `font-family`, `font-style`, `font-weight`, `font-feature-settings`, and the various grid layout properties.

- **HTML:** The parsed CSS styles are applied to HTML elements to determine their visual presentation. For example, the font properties parsed by these functions will dictate how text content within HTML tags is rendered. The grid layout properties will define how HTML elements are positioned within a grid container.

- **JavaScript:** JavaScript can interact with CSS in several ways:
    - **Setting Styles:** JavaScript can directly manipulate the `style` attribute of HTML elements or use the CSSOM (CSS Object Model) to set CSS properties. The parsing logic in this file is what interprets the CSS values set by JavaScript.
    - **Getting Computed Styles:** JavaScript can use methods like `getComputedStyle` to retrieve the final styles applied to an element after CSS rules are processed. The parsing done by this code is a crucial step in determining these computed styles.

**Logical Reasoning Examples (Hypothetical):**

**Assumption:** The `ConsumeInteger` function correctly parses integer tokens.

**Input:** A CSS token stream containing "100" followed by other tokens.

**Code:** `CSSPrimitiveValue* start_weight = ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kNonNegative); auto* numeric_start_weight = DynamicTo<CSSNumericLiteralValue>(start_weight); if (!start_weight || (numeric_start_weight && (numeric_start_weight->DoubleValue() < 1 || numeric_start_weight->DoubleValue() > 1000))) { return nullptr; }`

**Scenario:** This code is inside `ConsumeFontWeight`.

**Reasoning:**  If `ConsumeNumber` successfully parses "100" as a numeric value, and 100 is within the valid font-weight range (1-1000), the function will proceed. If the parsed number was outside this range (e.g., "0" or "1001"), the function would return `nullptr`, indicating an invalid font-weight value.

**User/Programming Common Usage Errors:**

1. **Incorrect Font Family Names:**
   - **User Error:** Typing a font family name incorrectly in CSS (e.g., `font-family: Ariall;`). The `ConsumeFamilyName` function would likely parse this as a single identifier.
   - **Programming Error:** When generating CSS dynamically, not handling spaces in font family names correctly, leading to names like `"Times New Roman"` instead of `"Times New Roman"`. `ConsumeFamilyName` handles quoted strings correctly.

2. **Invalid Font Weight Values:**
   - **User Error:** Using a font weight outside the valid range (1-1000) in `@font-face` rules. The `ConsumeFontWeight` function has checks for this.
   - **Programming Error:**  Setting a font weight to "0" in JavaScript, which is invalid. The parsing logic will reject this.

3. **Grid Layout Mistakes:**
   - **User Error:** Inconsistent number of columns in `grid-template-areas`. `ParseGridTemplateAreasRow` checks for this.
   - **User Error:** Overlapping or non-rectangular named grid areas. The logic within `ParseGridTemplateAreasRow` validates the shape of the areas.
   - **Programming Error:** Incorrectly generating the string for `grid-template-areas` in JavaScript, leading to syntax errors that the parsing functions would catch.

**Steps to Reach This Code (Debugging Scenario):**

1. **User edits a CSS file:** A web developer modifies a CSS file, perhaps changing the `font-family` of an element or defining a grid layout.
2. **Browser parses the CSS:** When the browser loads the HTML page or encounters updated CSS, the CSS parser (which includes code from this file) starts processing the CSS rules.
3. **Tokenization:** The CSS is first tokenized, breaking it down into meaningful units like identifiers, numbers, strings, and delimiters.
4. **Property parsing:** For each CSS property, a specific parsing function is called. For example, if the property is `font-family`, `ConsumeFamilyName` (or related functions) will be invoked. If it's a grid layout property, functions like `ConsumeGridTemplateAreasRow` or `ConsumeGridTrackList` will be used.
5. **Error handling:** If the parsing functions encounter invalid syntax (e.g., a misspelled keyword, an out-of-range value), they may return `nullptr` or other error indicators, which will be handled by the higher-level CSS parsing logic. This might lead to the browser ignoring the invalid rule or property.
6. **Rendering:** If the CSS is parsed successfully, the browser uses the parsed values to style the HTML content and render the page.

**Part 7 of 9 - Function Summary:**

This specific part of the `css_parsing_utils.cc` file focuses on parsing **font-related CSS properties** (`font-family`, `font-style`, `font-weight`, `font-stretch`, `font-feature-settings`, `font-variant`) and **various aspects of CSS Grid Layout** (`grid-template-areas`, `grid-template-rows`, `grid-template-columns`, `grid-row-start`, `grid-column-start`, grid track sizing, and line naming). It provides the building blocks for the browser to understand the structure and values of these CSS properties.

这是 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的第 7 部分（共 9 部分）。根据提供的代码片段，我们可以归纳出这部分代码的主要功能是：**解析与 CSS 字体属性和 CSS Grid 布局相关的各种语法结构和值。**

具体来说，这部分代码涵盖了以下方面的解析：

**1. 字体相关属性的解析:**

* **`ConsumeGenericFamily` 和 `ConsumeFamilyName`:** 解析通用的字体族名称和具体的字体族名称（例如，"Arial" 或 "Times New Roman"）。
* **`ConcatenateFamilyName`:**  处理由多个标识符组成的字体族名称。
* **`ConsumeFontStyle`:** 解析 `font-style` 属性的值，包括 `normal`, `italic`, `oblique` 以及 `oblique` 后面的角度值范围。
* **`ConsumeFontStretchKeywordOnly` 和 `ConsumeFontStretch`:** 解析 `font-stretch` 属性的值，包括关键字（如 `normal`, `condensed`）和百分比范围。
* **`ConsumeFontWeight`:** 解析 `font-weight` 属性的值，包括关键字（如 `normal`, `bold`）和数值范围。
* **`ConsumeFontFeatureSettings` 和 `ConsumeFontFeatureTag`:** 解析 `font-feature-settings` 属性的值，用于控制 OpenType 字体特性。
* **`ConsumeFontVariantCSS21`:** 解析 CSS 2.1 版本的 `font-variant` 属性的值。
* **`ConsumeFontTechIdent` 和 `ConsumeFontFormatIdent`:**  解析与 `@font-face` 规则中使用的字体技术和格式相关的标识符。
* **`FontFormatToId`, `IsSupportedKeywordTech`, `IsSupportedKeywordFormat`:**  辅助函数，用于将字体格式字符串转换为 ID，并检查字体技术和格式关键字是否受支持。

**2. CSS Grid 布局相关属性的解析:**

* **`ParseGridTemplateAreasColumnNames`:** 解析 `grid-template-areas` 属性中定义的区域名称。
* **`ConsumeGridBreadth`:** 解析 Grid 轨道尺寸，包括关键字 (`auto`, `min-content`, `max-content`)、长度、百分比和 `fr` 单位。
* **`ConsumeFitContent`:** 解析 `fit-content()` 函数，用于根据内容调整 Grid 轨道尺寸。
* **`IsGridBreadthFixedSized` 和 `IsGridTrackFixedSized`:**  判断 Grid 轨道的尺寸是否是固定的。
* **`ConsumeGridTrackSize`:** 解析单个 Grid 轨道的尺寸，包括 `minmax()` 函数。
* **`ConsumeCustomIdentForGridLine`:** 解析 Grid 线的自定义名称。
* **`ConsumeGridLineNames`:** 解析用方括号括起来的 Grid 线名称列表。
* **`AppendLineNames`:** 将解析到的 Grid 线名称添加到列表中。
* **`ConsumeGridTrackRepeatFunction`:** 解析 `repeat()` 函数，用于重复定义 Grid 轨道。
* **`ConsumeGridTemplateRowsAndAreasAndColumns`:** 解析 `grid-template` 缩写属性中同时包含行、列和区域定义的情况。
* **`ConsumeGridLine`:** 解析用于指定 Grid 项目位置的线名称或数字。
* **`ConsumeGridTrackList`:** 解析 Grid 轨道列表，用于 `grid-template-rows` 和 `grid-template-columns` 等属性。
* **`ParseGridTemplateAreasRow`:** 解析 `grid-template-areas` 属性中的单行定义。
* **`ConsumeGridTemplatesRowsOrColumns`:** 解析 `grid-template-rows` 或 `grid-template-columns` 属性的值。
* **`ConsumeGridItemPositionShorthand`:** (代码片段不完整) 可能是用于解析 `grid-row` 和 `grid-column` 等属性的缩写形式。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这个文件直接负责解析 CSS 语法。例如：
    * **`ConsumeFamilyName`:** 当浏览器解析 CSS 规则 `font-family: "Times New Roman", serif;` 时，此函数负责提取 `"Times New Roman"` 和 `serif` 这两个字体族名称。
    * **`ConsumeFontWeight`:**  当解析 `font-weight: bold;` 或 `font-weight: 600;` 时，此函数会将 `bold` 转换为对应的数值，或者解析数值 `600`。
    * **`ConsumeGridTemplateAreasRow`:**  对于 CSS 规则 `grid-template-areas: "header header" "nav main";`，此函数将解析 `"header header"` 和 `"nav main"` 这两行字符串，并提取出定义的 Grid 区域名称。

* **HTML:**  解析后的 CSS 样式会应用到 HTML 元素上，影响其渲染效果。例如，如果 HTML 中有 `<p style="font-family: Arial;">Text</p>`，那么 `ConsumeFamilyName` 解析出的 "Arial" 将决定文本的显示字体。Grid 布局属性的解析结果将决定 HTML 元素在 Grid 容器中的位置和大小。

* **JavaScript:** JavaScript 可以操作 CSS 样式，例如通过 `element.style.fontFamily = "Verdana"` 或修改 CSS 规则。当 JavaScript 动态修改 CSS 样式时，Blink 引擎仍然会使用这里的解析逻辑来理解新的样式值。此外，JavaScript 可以通过 CSSOM (CSS Object Model) 获取元素的计算样式，而这些计算样式是基于 CSS 解析结果得出的。

**逻辑推理举例 (假设输入与输出):**

**假设输入:** CSS 属性值为字符串 `"oblique 10deg"`

**代码:**  `ConsumeFontStyle` 函数被调用，`stream` 指向 `"oblique 10deg"`。

**逻辑推理:**

1. `ConsumeFontStyle` 首先匹配到 `kOblique` 标识符，调用 `ConsumeIdent<CSSValueID::kOblique>(stream)` 消耗掉 `"oblique"`。
2. 接着调用 `ConsumeAngle` 来解析角度值。
3. `ConsumeAngle` 会解析出 `10` 和 `deg` 单位，创建一个 `CSSPrimitiveValue` 对象表示这个角度。
4. 由于没有更多的角度值，且当前不是 `@font-face` 规则，因此会创建一个 `CSSValueList` 包含这个角度值。
5. 最后，`ConsumeFontStyle` 返回一个 `CSSFontStyleRangeValue` 对象，其中包含了 `oblique` 标识符和包含角度值的 `CSSValueList`。

**假设输出:**  一个指向 `CSSFontStyleRangeValue` 对象的指针，该对象内部包含 `CSSValueID::kOblique` 和一个包含 `10deg` 的 `CSSValueList`。

**用户或编程常见的使用错误举例:**

1. **字体名称错误:** 用户在 CSS 中输入了错误的字体名称，例如 `font-family: Ariall;`。`ConsumeFamilyName` 可能会将其解析为一个未知的标识符。
2. **`font-weight` 值超出范围:**  在 `@font-face` 规则中设置了无效的 `font-weight` 值，例如 `font-weight: 1050;`。`ConsumeFontWeight` 会检查数值范围并返回 `nullptr`。
3. **Grid 布局定义错误:**
    * `grid-template-areas` 中每行的列数不一致，`ParseGridTemplateAreasRow` 会检测到并返回 `false`。
    * `repeat()` 函数的语法错误，例如缺少逗号或指定了无效的重复次数，`ConsumeGridTrackRepeatFunction` 会返回 `false`。
4. **在不支持范围的上下文中使用范围值:** 例如，在非 `@font-face` 规则的 `font-style` 中使用 `oblique 10deg 20deg`，后续的解析可能会出错或被忽略。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编辑 CSS 文件或通过 JavaScript 修改样式:**  开发者在代码编辑器中修改了 CSS 文件，例如更改了某个元素的 `font-family` 或定义了一个新的 Grid 布局。或者，JavaScript 代码通过 DOM API 修改了元素的样式。
2. **浏览器加载并解析 HTML 和 CSS:** 当用户访问网页时，浏览器会下载 HTML、CSS 和 JavaScript 文件。
3. **CSS 引擎开始解析 CSS:**  Blink 引擎的 CSS 模块开始解析下载的 CSS 文件。
4. **词法分析 (Tokenization):**  CSS 文本被分解成一个个的 Token，例如标识符、数字、字符串、运算符等。
5. **语法分析 (Parsing):**  根据 CSS 语法规则，解析器会调用相应的函数来处理不同的 CSS 属性和值。
6. **调用 `css_parsing_utils.cc` 中的函数:**  当解析到字体相关或 Grid 布局相关的属性时，就会调用此文件中的函数，例如 `ConsumeFamilyName` 解析 `font-family`，`ConsumeGridTemplateAreasRow` 解析 `grid-template-areas` 的每一行。
7. **如果解析出错，会记录错误或忽略该规则:** 如果在解析过程中遇到语法错误或无效的值，解析器可能会记录错误信息（开发者可以在浏览器的开发者工具中看到），或者直接忽略该条 CSS 规则。
8. **构建 CSSOM 树:**  成功解析的 CSS 规则会被组织成 CSSOM (CSS Object Model) 树，用于后续的样式计算和渲染。

**调试线索:** 如果开发者发现网页的字体样式或 Grid 布局没有按照预期显示，可以检查浏览器的开发者工具中的 "Styles" 面板，查看是否有 CSS 解析错误。如果怀疑是解析器的问题，可以设置断点到 `css_parsing_utils.cc` 中相关的函数，例如在 `ConsumeFamilyName` 入口处设置断点，查看传入的 Token 流是否正确，以及解析过程是否按预期进行。通过分析调用栈，可以追踪到是哪个 CSS 属性的解析出现了问题。

总而言之，这部分代码是 Blink 引擎中负责理解和处理 CSS 字体和 Grid 布局语法的核心组成部分，它连接了 CSS 文本和浏览器内部的样式表示，使得浏览器能够正确地渲染网页。

### 提示词
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
lue = ConsumeFamilyName(stream);
    if (parsed_value) {
      list->Append(*parsed_value);
    } else {
      return nullptr;
    }
  } while (ConsumeCommaIncludingWhitespace(stream));
  return list;
}

CSSValue* ConsumeGenericFamily(CSSParserTokenStream& stream) {
  return ConsumeIdentRange(stream, CSSValueID::kSerif, CSSValueID::kMath);
}

CSSValue* ConsumeFamilyName(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() == kStringToken) {
    return CSSFontFamilyValue::Create(
        stream.ConsumeIncludingWhitespace().Value().ToAtomicString());
  }
  if (stream.Peek().GetType() != kIdentToken) {
    return nullptr;
  }
  String family_name = ConcatenateFamilyName(stream);
  if (family_name.IsNull()) {
    return nullptr;
  }
  return CSSFontFamilyValue::Create(AtomicString(family_name));
}

String ConcatenateFamilyName(CSSParserTokenStream& stream) {
  StringBuilder builder;
  bool added_space = false;
  const CSSParserToken first_token = stream.Peek();
  while (stream.Peek().GetType() == kIdentToken) {
    if (!builder.empty()) {
      builder.Append(' ');
      added_space = true;
    }
    builder.Append(stream.ConsumeIncludingWhitespace().Value());
  }
  if (!added_space && (IsCSSWideKeyword(first_token.Value()) ||
                       IsDefaultKeyword(first_token.Value()))) {
    return String();
  }
  return builder.ReleaseString();
}

CSSValueList* CombineToRangeList(const CSSPrimitiveValue* range_start,
                                 const CSSPrimitiveValue* range_end) {
  DCHECK(range_start);
  DCHECK(range_end);
  // Reversed ranges are valid, let them pass through here and swap them in
  // FontFace to keep serialisation of the value as specified.
  // https://drafts.csswg.org/css-fonts/#font-prop-desc
  CSSValueList* value_list = CSSValueList::CreateSpaceSeparated();
  value_list->Append(*range_start);
  value_list->Append(*range_end);
  return value_list;
}

bool IsAngleWithinLimits(CSSPrimitiveValue* angle) {
  constexpr float kMaxAngle = 90.0f;
  auto* numeric_angle = DynamicTo<CSSNumericLiteralValue>(angle);
  if (!numeric_angle) {
    // Can't resolve math function here without length resolver.
    return true;
  }
  return numeric_angle->DoubleValue() >= -kMaxAngle &&
         numeric_angle->DoubleValue() <= kMaxAngle;
}

CSSValue* ConsumeFontStyle(CSSParserTokenStream& stream,
                           const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal ||
      stream.Peek().Id() == CSSValueID::kItalic) {
    return ConsumeIdent(stream);
  }

  if (stream.Peek().Id() == CSSValueID::kAuto &&
      context.Mode() == kCSSFontFaceRuleMode) {
    return ConsumeIdent(stream);
  }

  if (stream.Peek().Id() != CSSValueID::kOblique) {
    return nullptr;
  }

  CSSIdentifierValue* oblique_identifier =
      ConsumeIdent<CSSValueID::kOblique>(stream);

  CSSPrimitiveValue* start_angle = ConsumeAngle(
      stream, context, std::nullopt, kMinObliqueValue, kMaxObliqueValue);
  if (!start_angle) {
    return oblique_identifier;
  }
  if (!IsAngleWithinLimits(start_angle)) {
    return nullptr;
  }

  if (context.Mode() != kCSSFontFaceRuleMode || stream.AtEnd()) {
    CSSValueList* value_list = CSSValueList::CreateSpaceSeparated();
    value_list->Append(*start_angle);
    return MakeGarbageCollected<cssvalue::CSSFontStyleRangeValue>(
        *oblique_identifier, *value_list);
  }

  CSSPrimitiveValue* end_angle = ConsumeAngle(
      stream, context, std::nullopt, kMinObliqueValue, kMaxObliqueValue);
  if (!end_angle || !IsAngleWithinLimits(end_angle)) {
    return nullptr;
  }

  CSSValueList* range_list = CombineToRangeList(start_angle, end_angle);
  if (!range_list) {
    return nullptr;
  }
  return MakeGarbageCollected<cssvalue::CSSFontStyleRangeValue>(
      *oblique_identifier, *range_list);
}

CSSIdentifierValue* ConsumeFontStretchKeywordOnly(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  const CSSParserToken& token = stream.Peek();
  if (token.Id() == CSSValueID::kNormal ||
      (token.Id() >= CSSValueID::kUltraCondensed &&
       token.Id() <= CSSValueID::kUltraExpanded)) {
    return ConsumeIdent(stream);
  }
  if (token.Id() == CSSValueID::kAuto &&
      context.Mode() == kCSSFontFaceRuleMode) {
    return ConsumeIdent(stream);
  }
  return nullptr;
}

CSSValue* ConsumeFontStretch(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  CSSIdentifierValue* parsed_keyword =
      ConsumeFontStretchKeywordOnly(stream, context);
  if (parsed_keyword) {
    return parsed_keyword;
  }

  CSSPrimitiveValue* start_percent = ConsumePercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!start_percent) {
    return nullptr;
  }

  // In a non-font-face context, more than one percentage is not allowed.
  if (context.Mode() != kCSSFontFaceRuleMode || stream.AtEnd()) {
    return start_percent;
  }

  CSSPrimitiveValue* end_percent = ConsumePercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!end_percent) {
    return nullptr;
  }

  return CombineToRangeList(start_percent, end_percent);
}

CSSValue* ConsumeFontWeight(CSSParserTokenStream& stream,
                            const CSSParserContext& context) {
  const CSSParserToken& token = stream.Peek();
  if (context.Mode() != kCSSFontFaceRuleMode) {
    if (token.Id() >= CSSValueID::kNormal &&
        token.Id() <= CSSValueID::kLighter) {
      return ConsumeIdent(stream);
    }
  } else {
    if (token.Id() == CSSValueID::kNormal || token.Id() == CSSValueID::kBold ||
        token.Id() == CSSValueID::kAuto) {
      return ConsumeIdent(stream);
    }
  }

  // Avoid consuming the first zero of font: 0/0; e.g. in the Acid3 test.  In
  // font:0/0; the first zero is the font size, the second is the line height.
  // In font: 100 0/0; we should parse the first 100 as font-weight, the 0
  // before the slash as font size. We need to peek and check the token in order
  // to avoid parsing a 0 font size as a font-weight. If we call ConsumeNumber
  // straight away without Peek, then the parsing cursor advances too far and we
  // parsed font-size as font-weight incorrectly.
  if (token.GetType() == kNumberToken &&
      (token.NumericValue() < 1 || token.NumericValue() > 1000)) {
    return nullptr;
  }

  CSSPrimitiveValue* start_weight = ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  auto* numeric_start_weight = DynamicTo<CSSNumericLiteralValue>(start_weight);
  if (!start_weight ||
      (numeric_start_weight && (numeric_start_weight->DoubleValue() < 1 ||
                                numeric_start_weight->DoubleValue() > 1000))) {
    return nullptr;
  }

  // In a non-font-face context, more than one number is not allowed. Return
  // what we have. If there is trailing garbage, the AtEnd() check in
  // CSSPropertyParser::ParseValueStart will catch that.
  if (context.Mode() != kCSSFontFaceRuleMode || stream.AtEnd()) {
    return start_weight;
  }

  CSSPrimitiveValue* end_weight = ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  auto* numeric_end_weight = DynamicTo<CSSNumericLiteralValue>(end_weight);
  if (!end_weight ||
      (numeric_end_weight && (numeric_end_weight->DoubleValue() < 1 ||
                              numeric_end_weight->DoubleValue() > 1000))) {
    return nullptr;
  }

  return CombineToRangeList(start_weight, end_weight);
}

CSSValue* ConsumeFontFeatureSettings(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return ConsumeIdent(stream);
  }
  CSSValueList* settings = CSSValueList::CreateCommaSeparated();
  do {
    CSSFontFeatureValue* font_feature_value =
        ConsumeFontFeatureTag(stream, context);
    if (!font_feature_value) {
      return nullptr;
    }
    settings->Append(*font_feature_value);
  } while (ConsumeCommaIncludingWhitespace(stream));
  return settings;
}

CSSFontFeatureValue* ConsumeFontFeatureTag(CSSParserTokenStream& stream,
                                           const CSSParserContext& context) {
  // Feature tag name consists of 4-letter characters.
  const unsigned kTagNameLength = 4;

  const CSSParserToken& token = stream.Peek();
  // Feature tag name comes first
  if (token.GetType() != kStringToken) {
    return nullptr;
  }
  if (token.Value().length() != kTagNameLength) {
    return nullptr;
  }
  AtomicString tag = token.Value().ToAtomicString();
  stream.ConsumeIncludingWhitespace();
  for (unsigned i = 0; i < kTagNameLength; ++i) {
    // Limits the stream of characters to 0x20-0x7E, following the tag name
    // rules defined in the OpenType specification.
    UChar character = tag[i];
    if (character < 0x20 || character > 0x7E) {
      return nullptr;
    }
  }

  int tag_value = 1;
  // Feature tag values could follow: <integer> | on | off
  if (CSSPrimitiveValue* value = ConsumeInteger(stream, context, 0)) {
    tag_value = ClampTo<int>(value->GetDoubleValue());
  } else if (stream.Peek().Id() == CSSValueID::kOn ||
             stream.Peek().Id() == CSSValueID::kOff) {
    tag_value = stream.ConsumeIncludingWhitespace().Id() == CSSValueID::kOn;
  }
  return MakeGarbageCollected<CSSFontFeatureValue>(tag, tag_value);
}

CSSIdentifierValue* ConsumeFontVariantCSS21(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kNormal, CSSValueID::kSmallCaps>(stream);
}

CSSIdentifierValue* ConsumeFontTechIdent(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kFeaturesOpentype, CSSValueID::kFeaturesAat,
                      CSSValueID::kFeaturesGraphite, CSSValueID::kColorCOLRv0,
                      CSSValueID::kColorCOLRv1, CSSValueID::kColorSVG,
                      CSSValueID::kColorSbix, CSSValueID::kColorCBDT,
                      CSSValueID::kVariations, CSSValueID::kPalettes,
                      CSSValueID::kIncremental>(stream);
}

CSSIdentifierValue* ConsumeFontFormatIdent(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kCollection, CSSValueID::kEmbeddedOpentype,
                      CSSValueID::kOpentype, CSSValueID::kTruetype,
                      CSSValueID::kSVG, CSSValueID::kWoff, CSSValueID::kWoff2>(
      stream);
}

CSSValueID FontFormatToId(String font_format) {
  CSSValueID converted_id = CssValueKeywordID(font_format);
  if (converted_id == CSSValueID::kCollection ||
      converted_id == CSSValueID::kEmbeddedOpentype ||
      converted_id == CSSValueID::kOpentype ||
      converted_id == CSSValueID::kTruetype ||
      converted_id == CSSValueID::kSVG || converted_id == CSSValueID::kWoff ||
      converted_id == CSSValueID::kWoff2) {
    return converted_id;
  }
  return CSSValueID::kInvalid;
}

bool IsSupportedKeywordTech(CSSValueID keyword) {
  switch (keyword) {
    case CSSValueID::kFeaturesOpentype:
    case CSSValueID::kFeaturesAat:
    case CSSValueID::kColorCOLRv0:
    case CSSValueID::kColorCOLRv1:
    case CSSValueID::kColorSbix:
    case CSSValueID::kColorCBDT:
    case CSSValueID::kVariations:
    case CSSValueID::kPalettes:
      return true;
    case CSSValueID::kFeaturesGraphite:
    case CSSValueID::kColorSVG:
    case CSSValueID::kIncremental:
      return false;
    default:
      return false;
  }
  NOTREACHED();
}

bool IsSupportedKeywordFormat(CSSValueID keyword) {
  switch (keyword) {
    case CSSValueID::kCollection:
    case CSSValueID::kOpentype:
    case CSSValueID::kTruetype:
    case CSSValueID::kWoff:
    case CSSValueID::kWoff2:
      return true;
    case CSSValueID::kEmbeddedOpentype:
    case CSSValueID::kSVG:
      return false;
    default:
      return false;
  }
}

Vector<String> ParseGridTemplateAreasColumnNames(const String& grid_row_names) {
  DCHECK(!grid_row_names.empty());

  // Using StringImpl to avoid checks and indirection in every call to
  // String::operator[].
  StringImpl& text = *grid_row_names.Impl();
  StringBuilder area_name;
  Vector<String> column_names;
  for (unsigned i = 0; i < text.length(); ++i) {
    if (IsCSSSpace(text[i])) {
      if (!area_name.empty()) {
        column_names.push_back(area_name.ReleaseString());
      }
      continue;
    }
    if (text[i] == '.') {
      if (area_name == ".") {
        continue;
      }
      if (!area_name.empty()) {
        column_names.push_back(area_name.ReleaseString());
      }
    } else {
      if (!IsNameCodePoint(text[i])) {
        return Vector<String>();
      }
      if (area_name == ".") {
        column_names.push_back(area_name.ReleaseString());
      }
    }
    area_name.Append(text[i]);
  }

  if (!area_name.empty()) {
    column_names.push_back(area_name.ReleaseString());
  }

  return column_names;
}

CSSValue* ConsumeGridBreadth(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  const CSSParserToken& token = stream.Peek();
  if (IdentMatches<CSSValueID::kAuto, CSSValueID::kMinContent,
                   CSSValueID::kMaxContent>(token.Id())) {
    return ConsumeIdent(stream);
  }
  if (token.GetType() == kDimensionToken &&
      token.GetUnitType() == CSSPrimitiveValue::UnitType::kFlex) {
    if (token.NumericValue() < 0) {
      return nullptr;
    }
    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(),
        CSSPrimitiveValue::UnitType::kFlex);
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative,
                                UnitlessQuirk::kForbid);
}

CSSValue* ConsumeFitContent(CSSParserTokenStream& stream,
                            const CSSParserContext& context) {
  CSSFunctionValue* result;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    CSSPrimitiveValue* length = ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
        UnitlessQuirk::kAllow);
    if (!length || !stream.AtEnd()) {
      return nullptr;
    }
    guard.Release();
    result = MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kFitContent);
    result->Append(*length);
  }
  stream.ConsumeWhitespace();
  return result;
}

bool IsGridBreadthFixedSized(const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CSSValueID value_id = identifier_value->GetValueID();
    return value_id != CSSValueID::kAuto &&
           value_id != CSSValueID::kMinContent &&
           value_id != CSSValueID::kMaxContent;
  }

  if (auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    return !primitive_value->IsFlex();
  }

  NOTREACHED();
}

bool IsGridTrackFixedSized(const CSSValue& value) {
  if (value.IsPrimitiveValue() || value.IsIdentifierValue()) {
    return IsGridBreadthFixedSized(value);
  }

  auto& function = To<CSSFunctionValue>(value);
  if (function.FunctionType() == CSSValueID::kFitContent) {
    return false;
  }

  const CSSValue& min_value = function.Item(0);
  const CSSValue& max_value = function.Item(1);
  return IsGridBreadthFixedSized(min_value) ||
         IsGridBreadthFixedSized(max_value);
}

CSSValue* ConsumeGridTrackSize(CSSParserTokenStream& stream,
                               const CSSParserContext& context) {
  const auto& token_id = stream.Peek().FunctionId();

  if (token_id == CSSValueID::kMinmax) {
    CSSFunctionValue* result;
    DCHECK_EQ(stream.Peek().GetType(), kFunctionToken);
    {
      CSSParserTokenStream::RestoringBlockGuard guard(stream);
      stream.ConsumeWhitespace();
      CSSValue* min_track_breadth = ConsumeGridBreadth(stream, context);
      auto* min_track_breadth_primitive_value =
          DynamicTo<CSSPrimitiveValue>(min_track_breadth);
      if (!min_track_breadth ||
          (min_track_breadth_primitive_value &&
           min_track_breadth_primitive_value->IsFlex()) ||
          !ConsumeCommaIncludingWhitespace(stream)) {
        return nullptr;
      }
      CSSValue* max_track_breadth = ConsumeGridBreadth(stream, context);
      if (!max_track_breadth || !stream.AtEnd()) {
        return nullptr;
      }
      guard.Release();
      result = MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kMinmax);
      result->Append(*min_track_breadth);
      result->Append(*max_track_breadth);
    }
    stream.ConsumeWhitespace();
    return result;
  }

  return (token_id == CSSValueID::kFitContent)
             ? ConsumeFitContent(stream, context)
             : ConsumeGridBreadth(stream, context);
}

CSSCustomIdentValue* ConsumeCustomIdentForGridLine(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAuto ||
      stream.Peek().Id() == CSSValueID::kSpan) {
    return nullptr;
  }
  return ConsumeCustomIdent(stream, context);
}

// Appends to the passed in CSSBracketedValueList if any, otherwise creates a
// new one. Returns nullptr if an empty list is consumed.
CSSBracketedValueList* ConsumeGridLineNames(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    bool is_subgrid_track_list,
    CSSBracketedValueList* line_names = nullptr) {
  if (stream.Peek().GetType() != kLeftBracketToken) {
    return nullptr;
  }
  {
    CSSParserTokenStream::RestoringBlockGuard savepoint(stream);
    stream.ConsumeWhitespace();

    if (!line_names) {
      line_names = MakeGarbageCollected<CSSBracketedValueList>();
    }

    while (CSSCustomIdentValue* line_name =
               ConsumeCustomIdentForGridLine(stream, context)) {
      line_names->Append(*line_name);
    }

    if (!savepoint.Release()) {
      return nullptr;
    }
  }
  stream.ConsumeWhitespace();

  if (!is_subgrid_track_list && line_names->length() == 0U) {
    return nullptr;
  }

  return line_names;
}

bool AppendLineNames(CSSParserTokenStream& stream,
                     const CSSParserContext& context,
                     bool is_subgrid_track_list,
                     CSSValueList* values) {
  if (CSSBracketedValueList* line_names =
          ConsumeGridLineNames(stream, context, is_subgrid_track_list)) {
    values->Append(*line_names);
    return true;
  }
  return false;
}

bool ConsumeGridTrackRepeatFunction(CSSParserTokenStream& stream,
                                    const CSSParserContext& context,
                                    bool is_subgrid_track_list,
                                    CSSValueList& list,
                                    bool& is_auto_repeat,
                                    bool& all_tracks_are_fixed_sized) {
  DCHECK_EQ(stream.Peek().GetType(), kFunctionToken);
  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();

  // <name-repeat> syntax for subgrids only supports `auto-fill`.
  if (is_subgrid_track_list &&
      IdentMatches<CSSValueID::kAutoFit>(stream.Peek().Id())) {
    return false;
  }

  is_auto_repeat = IdentMatches<CSSValueID::kAutoFill, CSSValueID::kAutoFit>(
      stream.Peek().Id());
  CSSValueList* repeated_values;
  // The number of repetitions for <auto-repeat> is not important at parsing
  // level because it will be computed later, let's set it to 1.
  wtf_size_t repetitions = 1;

  if (is_auto_repeat) {
    repeated_values = MakeGarbageCollected<cssvalue::CSSGridAutoRepeatValue>(
        stream.ConsumeIncludingWhitespace().Id());
  } else {
    // TODO(rob.buis): a consumeIntegerRaw would be more efficient here.
    CSSPrimitiveValue* repetition = ConsumePositiveInteger(stream, context);
    if (!repetition) {
      return false;
    }
    repetitions =
        ClampTo<wtf_size_t>(repetition->GetDoubleValue(), 0, kGridMaxTracks);
    repeated_values = CSSValueList::CreateSpaceSeparated();
  }

  if (!ConsumeCommaIncludingWhitespace(stream)) {
    return false;
  }

  wtf_size_t number_of_line_name_sets =
      AppendLineNames(stream, context, is_subgrid_track_list, repeated_values);
  wtf_size_t number_of_tracks = 0;
  while (!stream.AtEnd()) {
    if (is_subgrid_track_list) {
      if (!number_of_line_name_sets ||
          !AppendLineNames(stream, context, is_subgrid_track_list,
                           repeated_values)) {
        return false;
      }
      ++number_of_line_name_sets;
    } else {
      CSSValue* track_size = ConsumeGridTrackSize(stream, context);
      if (!track_size) {
        return false;
      }
      if (all_tracks_are_fixed_sized) {
        all_tracks_are_fixed_sized = IsGridTrackFixedSized(*track_size);
      }
      repeated_values->Append(*track_size);
      ++number_of_tracks;
      AppendLineNames(stream, context, is_subgrid_track_list, repeated_values);
    }
  }

  // We should have found at least one <track-size> or else it is not a valid
  // <track-list>. If it's a subgrid <line-name-list>, then we should have found
  // at least one named grid line.
  if ((is_subgrid_track_list && !number_of_line_name_sets) ||
      (!is_subgrid_track_list && !number_of_tracks)) {
    return false;
  }

  if (is_auto_repeat) {
    list.Append(*repeated_values);
  } else {
    // We clamp the repetitions to a multiple of the repeat() track list's size,
    // while staying below the max grid size.
    repetitions =
        std::min(repetitions, kGridMaxTracks / (is_subgrid_track_list
                                                    ? number_of_line_name_sets
                                                    : number_of_tracks));
    auto* integer_repeated_values =
        MakeGarbageCollected<cssvalue::CSSGridIntegerRepeatValue>(repetitions);
    for (wtf_size_t i = 0; i < repeated_values->length(); ++i) {
      integer_repeated_values->Append(repeated_values->Item(i));
    }
    list.Append(*integer_repeated_values);
  }

  return true;
}

bool ConsumeGridTemplateRowsAndAreasAndColumns(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSValue*& template_rows,
    const CSSValue*& template_columns,
    const CSSValue*& template_areas) {
  DCHECK(!template_rows);
  DCHECK(!template_columns);
  DCHECK(!template_areas);

  NamedGridAreaMap grid_area_map;
  wtf_size_t row_count = 0;
  wtf_size_t column_count = 0;
  CSSValueList* template_rows_value_list = CSSValueList::CreateSpaceSeparated();

  // Persists between loop iterations so we can use the same value for
  // consecutive <line-names> values
  CSSBracketedValueList* line_names = nullptr;

  // See comment in Grid::ParseShorthand() about the use of AtEnd.

  do {
    // Handle leading <custom-ident>*.
    bool has_previous_line_names = line_names;
    line_names = ConsumeGridLineNames(
        stream, context, /* is_subgrid_track_list */ false, line_names);
    if (line_names && !has_previous_line_names) {
      template_rows_value_list->Append(*line_names);
    }

    // Handle a template-area's row.
    if (stream.Peek().GetType() != kStringToken ||
        !ParseGridTemplateAreasRow(
            stream.ConsumeIncludingWhitespace().Value().ToString(),
            grid_area_map, row_count, column_count)) {
      return false;
    }
    ++row_count;

    // Handle template-rows's track-size.
    CSSValue* value = ConsumeGridTrackSize(stream, context);
    if (!value) {
      value = CSSIdentifierValue::Create(CSSValueID::kAuto);
    }
    template_rows_value_list->Append(*value);

    // This will handle the trailing/leading <custom-ident>* in the grammar.
    line_names = ConsumeGridLineNames(stream, context,
                                      /* is_subgrid_track_list */ false);
    if (line_names) {
      template_rows_value_list->Append(*line_names);
    }
  } while (!stream.AtEnd() && !(stream.Peek().GetType() == kDelimiterToken &&
                                (stream.Peek().Delimiter() == '/' ||
                                 stream.Peek().Delimiter() == '!')));

  if (!stream.AtEnd() && stream.Peek().Delimiter() != '!') {
    if (!ConsumeSlashIncludingWhitespace(stream)) {
      return false;
    }
    template_columns = ConsumeGridTrackList(
        stream, context, TrackListType::kGridTemplateNoRepeat);
    if (!template_columns ||
        !(stream.AtEnd() || stream.Peek().Delimiter() == '!')) {
      return false;
    }
  } else {
    template_columns = CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  template_rows = template_rows_value_list;
  template_areas = MakeGarbageCollected<cssvalue::CSSGridTemplateAreasValue>(
      grid_area_map, row_count, column_count);
  return true;
}

CSSValue* ConsumeGridLine(CSSParserTokenStream& stream,
                          const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return ConsumeIdent(stream);
  }

  CSSIdentifierValue* span_value = nullptr;
  CSSCustomIdentValue* grid_line_name = nullptr;
  CSSPrimitiveValue* numeric_value = ConsumeInteger(stream, context);
  if (numeric_value) {
    grid_line_name = ConsumeCustomIdentForGridLine(stream, context);
    span_value = ConsumeIdent<CSSValueID::kSpan>(stream);
  } else {
    span_value = ConsumeIdent<CSSValueID::kSpan>(stream);
    if (span_value) {
      numeric_value = ConsumeInteger(stream, context);
      grid_line_name = ConsumeCustomIdentForGridLine(stream, context);
      if (!numeric_value) {
        numeric_value = ConsumeInteger(stream, context);
      }
    } else {
      grid_line_name = ConsumeCustomIdentForGridLine(stream, context);
      if (grid_line_name) {
        numeric_value = ConsumeInteger(stream, context);
        span_value = ConsumeIdent<CSSValueID::kSpan>(stream);
        if (!span_value && !numeric_value) {
          return grid_line_name;
        }
      } else {
        return nullptr;
      }
    }
  }

  if (span_value && !numeric_value && !grid_line_name) {
    return nullptr;  // "span" keyword alone is invalid.
  }
  if (span_value && numeric_value && numeric_value->GetIntValue() < 0) {
    return nullptr;  // Negative numbers are not allowed for span.
  }
  if (numeric_value && numeric_value->GetIntValue() == 0) {
    return nullptr;  // An <integer> value of zero makes the declaration
                     // invalid.
  }

  if (numeric_value) {
    numeric_value = CSSNumericLiteralValue::Create(
        ClampTo(numeric_value->GetIntValue(), -kGridMaxTracks, kGridMaxTracks),
        CSSPrimitiveValue::UnitType::kInteger);
  }

  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  if (span_value) {
    values->Append(*span_value);
  }
  // If span is present, omit `1` if there's a trailing identifier.
  if (numeric_value &&
      (!span_value || !grid_line_name || numeric_value->GetIntValue() != 1)) {
    values->Append(*numeric_value);
  }
  if (grid_line_name) {
    values->Append(*grid_line_name);
  }
  DCHECK(values->length());
  return values;
}

CSSValue* ConsumeGridTrackList(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               TrackListType track_list_type) {
  bool allow_grid_line_names = track_list_type != TrackListType::kGridAuto;
  if (!allow_grid_line_names && stream.Peek().GetType() == kLeftBracketToken) {
    return nullptr;
  }

  bool is_subgrid_track_list =
      track_list_type == TrackListType::kGridTemplateSubgrid;

  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  if (is_subgrid_track_list) {
    if (IdentMatches<CSSValueID::kSubgrid>(stream.Peek().Id())) {
      values->Append(*ConsumeIdent(stream));
    } else {
      return nullptr;
    }
  }

  AppendLineNames(stream, context, is_subgrid_track_list, values);

  bool allow_repeat =
      is_subgrid_track_list || track_list_type == TrackListType::kGridTemplate;
  bool seen_auto_repeat = false;
  bool all_tracks_are_fixed_sized = true;
  auto IsRangeAtEnd = [](CSSParserTokenStream& stream) -> bool {
    return stream.AtEnd() || stream.Peek().GetType() == kDelimiterToken;
  };

  do {
    bool is_auto_repeat;
    if (stream.Peek().FunctionId() == CSSValueID::kRepeat) {
      if (!allow_repeat) {
        return nullptr;
      }
      if (!ConsumeGridTrackRepeatFunction(
              stream, context, is_subgrid_track_list, *values, is_auto_repeat,
              all_tracks_are_fixed_sized)) {
        return nullptr;
      }
      stream.ConsumeWhitespace();
      if (is_auto_repeat && seen_auto_repeat) {
        return nullptr;
      }

      seen_auto_repeat = seen_auto_repeat || is_auto_repeat;
    } else if (CSSValue* value = ConsumeGridTrackSize(stream, context)) {
      // If we find a <track-size> in a subgrid track list, then it isn't a
      // valid <line-name-list>.
      if (is_subgrid_track_list) {
        return nullptr;
      }
      if (all_tracks_are_fixed_sized) {
        all_tracks_are_fixed_sized = IsGridTrackFixedSized(*value);
      }

      values->Append(*value);
    } else if (!is_subgrid_track_list) {
      return nullptr;
    }

    if (seen_auto_repeat && !all_tracks_are_fixed_sized) {
      return nullptr;
    }
    if (!allow_grid_line_names &&
        stream.Peek().GetType() == kLeftBracketToken) {
      return nullptr;
    }

    bool did_append_line_names =
        AppendLineNames(stream, context, is_subgrid_track_list, values);
    if (is_subgrid_track_list && !did_append_line_names &&
        stream.Peek().FunctionId() != CSSValueID::kRepeat) {
      return IsRangeAtEnd(stream) ? values : nullptr;
    }
  } while (!IsRangeAtEnd(stream));

  return values;
}

bool ParseGridTemplateAreasRow(const String& grid_row_names,
                               NamedGridAreaMap& grid_area_map,
                               const wtf_size_t row_count,
                               wtf_size_t& column_count) {
  if (grid_row_names.ContainsOnlyWhitespaceOrEmpty()) {
    return false;
  }

  Vector<String> column_names =
      ParseGridTemplateAreasColumnNames(grid_row_names);
  if (row_count == 0) {
    column_count = column_names.size();
    if (column_count == 0) {
      return false;
    }
  } else if (column_count != column_names.size()) {
    // The declaration is invalid if all the rows don't have the number of
    // columns.
    return false;
  }

  for (wtf_size_t current_column = 0; current_column < column_count;
       ++current_column) {
    const String& grid_area_name = column_names[current_column];

    // Unamed areas are always valid (we consider them to be 1x1).
    if (grid_area_name == ".") {
      continue;
    }

    wtf_size_t look_ahead_column = current_column + 1;
    while (look_ahead_column < column_count &&
           column_names[look_ahead_column] == grid_area_name) {
      look_ahead_column++;
    }

    NamedGridAreaMap::iterator grid_area_it =
        grid_area_map.find(grid_area_name);
    if (grid_area_it == grid_area_map.end()) {
      grid_area_map.insert(grid_area_name,
                           GridArea(GridSpan::TranslatedDefiniteGridSpan(
                                        row_count, row_count + 1),
                                    GridSpan::TranslatedDefiniteGridSpan(
                                        current_column, look_ahead_column)));
    } else {
      GridArea& grid_area = grid_area_it->value;

      // The following checks test that the grid area is a single filled-in
      // rectangle.
      // 1. The new row is adjacent to the previously parsed row.
      if (row_count != grid_area.rows.EndLine()) {
        return false;
      }

      // 2. The new area starts at the same position as the previously parsed
      // area.
      if (current_column != grid_area.columns.StartLine()) {
        return false;
      }

      // 3. The new area ends at the same position as the previously parsed
      // area.
      if (look_ahead_column != grid_area.columns.EndLine()) {
        return false;
      }

      grid_area.rows = GridSpan::TranslatedDefiniteGridSpan(
          grid_area.rows.StartLine(), grid_area.rows.EndLine() + 1);
    }
    current_column = look_ahead_column - 1;
  }

  return true;
}

CSSValue* ConsumeGridTemplatesRowsOrColumns(CSSParserTokenStream& stream,
                                            const CSSParserContext& context) {
  switch (stream.Peek().Id()) {
    case CSSValueID::kNone:
      return ConsumeIdent(stream);
    case CSSValueID::kSubgrid:
      return ConsumeGridTrackList(stream, context,
                                  TrackListType::kGridTemplateSubgrid);
    default:
      return ConsumeGridTrackList(stream, context,
                                  TrackListType::kGridTemplate);
  }
}

bool ConsumeGridItemPositionShorthand(bool important,
                                      CSSParserTokenStream& stream,
                                      const CSSParserContext& context,
```