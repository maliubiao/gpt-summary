Response:
The user wants a summary of the functionality of the provided C++ code snippet from `css_parser_fast_paths.cc`. This code seems to be part of a fast path for parsing CSS color values.

Here's a breakdown of the code's functions:

1. **Parsing RGB/RGBA colors:** The code checks if a string might represent an `rgb()` or `rgba()` color. If so, it extracts the red, green, blue, and optionally alpha components. It handles different separators (commas and slashes for alpha) and validates the syntax.

2. **Parsing HSL/HSLA colors:**  Similarly, it checks for `hsl()` or `hsla()` color functions. It parses the hue (handling different angle units), saturation, lightness, and optional alpha. It also normalizes the hue value to be within the 0-360 degree range.

3. **`ParseColor` function:** This function attempts to parse a color from a string. It first checks for color keywords. If not a keyword, it calls `FastParseColorInternal` (the code snippet provided) to handle hex, rgb/rgba, and hsl/hsla color formats.

4. **`CSSParserFastPaths::ParseColor` function:** This is a wrapper around the internal `ParseColor` function. It handles 8-bit strings only, likely for performance reasons in the "fast path".

5. **`IsValidKeywordPropertyAndValue` function:** This function checks if a given CSS property and value (represented by CSSValueID) combination is valid. It contains a large switch statement covering various CSS properties and the allowed keyword values for each.

Let's address the specific requirements of the prompt:

- **Functionality:**  The primary function is to efficiently parse common CSS color formats and validate CSS property-value pairs for keyword values.
- **Relationship to JavaScript, HTML, CSS:**  This code directly implements CSS parsing. It's used by the browser's rendering engine to interpret CSS styles applied to HTML elements. JavaScript can interact with these styles, and this parsing logic is crucial for those interactions to function correctly.
- **Logic Inference (Assumptions & Outputs):** We can infer the expected behavior of the parsing functions based on the code.
- **User/Programming Errors:** We can identify potential errors related to incorrect CSS syntax.
- **User Operation Leading to This Code:** We can trace how a browser might invoke this parsing logic.
- **Summary of Functionality (for Part 2):** We need to summarize the functionality of the code snippet provided in Part 2.
这是 `blink/renderer/core/css/parser/css_parser_fast_paths.cc` 文件的第二部分，主要关注于快速解析 CSS 颜色值和验证某些 CSS 属性的关键字值。

**功能归纳：**

这部分代码的核心功能是提供了用于快速解析 CSS 颜色值的优化路径，并且包含了用于快速验证特定 CSS 属性是否使用了合法的关键字值的逻辑。

**更具体的功能点：**

1. **快速解析 RGB 和 RGBA 颜色值:**
   - 代码检查输入的字符串是否符合 `rgb()` 或 `rgba()` 的语法结构。
   - 它会提取红色、绿色、蓝色分量的值，以及可选的 alpha 透明度值。
   - 它支持逗号 (`,`) 和斜杠 (`/`) 作为分隔符，并能处理无空格或空格分隔的情况。
   - **假设输入:**  字符串 `"rgb(255, 0, 0)"` 或 `"rgba(100, 100, 100, 0.5)"` 或 `"rgb(10%, 20%, 30%)"`。
   - **预期输出:**  成功解析颜色值并将其存储在 `color` 变量中。如果语法不正确，则返回 `false`。

2. **快速解析 HSL 和 HSLA 颜色值:**
   - 代码检查输入的字符串是否符合 `hsl()` 或 `hsla()` 的语法结构。
   - 它会提取色相 (hue)、饱和度 (saturation)、亮度 (lightness) 的值，以及可选的 alpha 透明度值。
   - 色相值可以以 `deg` (度), `rad` (弧度), `grad` (百分度), `turn` (圈数) 为单位，无单位时默认为度。
   - 饱和度和亮度值必须是百分比。
   - 它同样支持逗号 (`,`) 和斜杠 (`/`) 作为分隔符。
   - **假设输入:**  字符串 `"hsl(120, 100%, 50%)"` 或 `"hsla(240deg, 80%, 60%, 0.8)"` 或 `"hsl(0.5turn, 70%, 40%)"`。
   - **预期输出:**  成功解析颜色值并将其存储在 `color` 变量中。如果语法不正确，则返回 `false`。

3. **`ParseColor` 函数:**
   - 此函数接收 CSS 属性 ID、字符串形式的颜色值以及解析模式作为输入。
   - 它首先尝试将字符串识别为 CSS 颜色关键字（例如 "red", "blue"）。
   - 如果不是关键字，它会调用 `FastParseColorInternal` 函数（本代码片段所在函数）来尝试快速解析颜色值（hex, rgb/rgba, hsl/hsla）。
   - **与 CSS 的关系:**  直接处理 CSS 颜色值的解析。
   - **与 HTML 的关系:** 当 HTML 元素的 `style` 属性或 `<style>` 标签中的 CSS 规则包含颜色值时，这个函数会被调用。
   - **与 JavaScript 的关系:** 当 JavaScript 通过 DOM API (例如 `element.style.color = 'red'`) 设置颜色值时，或者当 JavaScript 获取元素的样式信息时，底层的 CSS 解析过程会涉及到这个函数。

4. **`CSSParserFastPaths::ParseColor` 函数:**
   - 这是一个外部接口，用于调用内部的 `ParseColor` 函数。
   - 它限制了输入字符串必须是 8-bit 的，这是一种性能优化手段。

5. **`IsValidKeywordPropertyAndValue` 函数:**
   - 此函数用于快速检查给定的 CSS 属性和值（以 `CSSValueID` 枚举表示）是否是合法的关键字组合。
   - 它包含一个大型的 `switch` 语句，针对不同的 CSS 属性列出了其允许的关键字值。
   - **与 CSS 的关系:**  用于验证 CSS 属性值是否合法。
   - **与 HTML 的关系:** 当浏览器解析 HTML 中元素的 `style` 属性或 `<style>` 标签中的 CSS 规则时，会使用这个函数来验证关键字值。
   - **与 JavaScript 的关系:**  当 JavaScript 通过 DOM API 设置 CSS 属性的关键字值时，或者在开发工具中检查样式时，可能会涉及到这类验证。
   - **假设输入:** `CSSPropertyID::kTextAlign` 和 `CSSValueID::kCenter`。
   - **预期输出:**  `true`，因为 `center` 是 `text-align` 属性的合法关键字值。
   - **假设输入:** `CSSPropertyID::kBorderWidth` 和 `CSSValueID::kSolid`。
   - **预期输出:** `false`，因为 `solid` 不是 `border-width` 属性的合法关键字值。

**用户或编程常见的使用错误举例:**

1. **颜色值语法错误:**
   - 用户在 CSS 或 JavaScript 中输入了错误的颜色值格式，例如 `"rgb(255,00)"` (缺少一个分量)， `"hsl(120 100% 50%)"` (缺少逗号分隔符)。
   - **用户操作:** 在 CSS 文件中编写 `color: rgb(255,00);` 或者在 JavaScript 中执行 `element.style.color = 'hsl(120 100% 50%)';`。
   - **调试线索:**  解析器会尝试调用 `FastParseColorInternal`，但由于语法错误会返回 `false`。开发者可能会在控制台中看到样式解析错误或元素样式未生效。

2. **使用了属性不允许的关键字值:**
   - 用户尝试将一个不属于该属性的关键字值赋给 CSS 属性。
   - **用户操作:** 在 CSS 文件中编写 `border-width: solid;` 或在 JavaScript 中执行 `element.style.borderWidth = 'solid';`。
   - **调试线索:** `IsValidKeywordPropertyAndValue` 函数会返回 `false`，指示该关键字值不合法。浏览器可能会忽略该样式声明。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 代码，构建 DOM 树。**
3. **浏览器遇到 `<style>` 标签或外部 CSS 文件链接。**
4. **CSS 解析器开始解析 CSS 规则。**
5. **当解析到包含颜色值的属性 (如 `color`, `background-color`) 或需要验证关键字值的属性时，`CSSParserFastPaths::ParseColor` 或 `IsValidKeywordPropertyAndValue` 函数会被调用。**
6. **对于颜色值，如果字符串看起来像是 `rgb()`, `rgba()`, `hsl()`, 或 `hsla()`，则会尝试调用 `FastParseColorInternal` 进行快速解析。**
7. **如果颜色值解析失败或关键字值验证失败，浏览器可能会记录错误信息或忽略该样式声明。**

**总结 (针对第2部分):**

这段代码专注于提供高效的 CSS 颜色值解析和特定 CSS 属性关键字值验证。它通过直接操作字符和使用快速路径来优化解析性能，是浏览器渲染引擎中处理 CSS 样式的重要组成部分。它与 CSS, HTML 和 JavaScript 都有着密切的关系，保证了网页样式的正确解析和应用。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_fast_paths.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
the same syntax.
  if (MightBeRGBOrRGBA(characters, length)) {
    int length_to_add = (characters[3] == 'a') ? 5 : 4;
    const LChar* current = characters + length_to_add;
    const LChar* end = characters + length;
    int red;
    int green;
    int blue;
    int alpha;
    bool should_have_alpha = false;

    TerminatorStatus terminator_status = kCouldWhitespaceTerminate;
    CSSPrimitiveValue::UnitType expect = CSSPrimitiveValue::UnitType::kUnknown;
    if (!ParseColorNumberOrPercentage(current, end, ',', terminator_status,
                                      expect, red)) {
      return false;
    }
    if (!ParseColorNumberOrPercentage(current, end, ',', terminator_status,
                                      expect, green)) {
      return false;
    }

    TerminatorStatus no_whitespace_check = kMustCharacterTerminate;
    if (!ParseColorNumberOrPercentage(current, end, ',', no_whitespace_check,
                                      expect, blue)) {
      // Might have slash as separator.
      if (ParseColorNumberOrPercentage(current, end, '/', no_whitespace_check,
                                       expect, blue)) {
        if (terminator_status != kMustWhitespaceTerminate) {
          return false;
        }
        should_have_alpha = true;
      }
      // Might not have alpha.
      else if (!ParseColorNumberOrPercentage(
                   current, end, ')', no_whitespace_check, expect, blue)) {
        return false;
      }
    } else {
      if (terminator_status != kMustCharacterTerminate) {
        return false;
      }
      should_have_alpha = true;
    }

    if (should_have_alpha) {
      if (!ParseAlphaValue(current, end, ')', alpha)) {
        return false;
      }
      color = Color::FromRGBA(red, green, blue, alpha);
    } else {
      if (current != end) {
        return false;
      }
      color = Color::FromRGB(red, green, blue);
    }
    return true;
  }

  // hsl() and hsla() also have the same syntax:
  // https://www.w3.org/TR/css-color-4/#the-hsl-notation
  // Also for legacy reasons, an hsla() function also exists, with an identical
  // grammar and behavior to hsl().

  if (MightBeHSLOrHSLA(characters, length)) {
    int length_to_add = (characters[3] == 'a') ? 5 : 4;
    const LChar* current = characters + length_to_add;
    const LChar* end = characters + length;
    bool should_have_alpha = false;

    // Skip any whitespace before the hue.
    while (current != end && IsHTMLSpace(*current)) {
      current++;
    }

    CSSPrimitiveValue::UnitType hue_unit = CSSPrimitiveValue::UnitType::kNumber;
    double hue;
    unsigned hue_length = ParseSimpleAngle(
        current, static_cast<unsigned>(end - current), hue_unit, hue);
    if (hue_length == 0) {
      return false;
    }

    switch (hue_unit) {
      case CSSPrimitiveValue::UnitType::kNumber:
      case CSSPrimitiveValue::UnitType::kDegrees:
        // Unitless numbers are to be treated as degrees.
        break;
      case CSSPrimitiveValue::UnitType::kRadians:
        hue = Rad2deg(hue);
        break;
      case CSSPrimitiveValue::UnitType::kGradians:
        hue = Grad2deg(hue);
        break;
      case CSSPrimitiveValue::UnitType::kTurns:
        hue *= 360.0;
        break;
      default:
        NOTREACHED();
    }

    // Deal with wraparound so that we end up in [0, 360],
    // roughly analogous to the code in ParseHSLParameters().
    // Taking these branches should be rare.
    if (hue < 0.0) {
      hue = fmod(hue, 360.0) + 360.0;
    } else if (hue > 360.0) {
      hue = fmod(hue, 360.0);
    }

    current += hue_length;

    TerminatorStatus terminator_status = kCouldWhitespaceTerminate;
    if (!SkipToTerminator(current, end, ',', terminator_status)) {
      return false;
    }

    // Saturation and lightness must always be percentages.
    double saturation;
    if (!ParsePercentage(current, end, ',', terminator_status, saturation)) {
      return false;
    }

    TerminatorStatus no_whitespace_check = kMustCharacterTerminate;

    double lightness;
    if (!ParsePercentage(current, end, ',', no_whitespace_check, lightness)) {
      // Might have slash as separator.
      if (ParsePercentage(current, end, '/', no_whitespace_check, lightness)) {
        if (terminator_status != kMustWhitespaceTerminate) {
          return false;
        }
        should_have_alpha = true;
      }
      // Might not have alpha.
      else if (!ParsePercentage(current, end, ')', no_whitespace_check,
                                lightness)) {
        return false;
      }
    } else {
      if (terminator_status != kMustCharacterTerminate) {
        return false;
      }
      should_have_alpha = true;
    }

    if (should_have_alpha) {
      int alpha;
      if (!ParseAlphaValue(current, end, ')', alpha)) {
        return false;
      }
      if (current != end) {
        return false;
      }
      color =
          Color::FromHSLA(hue, saturation, lightness, alpha * (1.0f / 255.0f));
    } else {
      if (current != end) {
        return false;
      }
      color = Color::FromHSLA(hue, saturation, lightness, 1.0f);
    }
    return true;
  }

  return false;
}

// If the string identifies a color keyword, `out_color_keyword` is set and
// `kKeyword` is returned. If the string identifies a color, then `out_color`
// is set and `kColor` is returned.
static ParseColorResult ParseColor(CSSPropertyID property_id,
                                   StringView string,
                                   CSSParserMode parser_mode,
                                   Color& out_color,
                                   CSSValueID& out_color_keyword) {
  DCHECK(!string.empty());
  DCHECK(IsColorPropertyID(property_id));
  CSSValueID value_id = CssValueKeywordID(string);
  if ((value_id == CSSValueID::kAccentcolor ||
       value_id == CSSValueID::kAccentcolortext) &&
      !RuntimeEnabledFeatures::CSSAccentColorKeywordEnabled()) {
    return ParseColorResult::kFailure;
  }
  if (StyleColor::IsColorKeyword(value_id)) {
    if (!IsValueAllowedInMode(value_id, parser_mode)) {
      return ParseColorResult::kFailure;
    }
    out_color_keyword = value_id;
    return ParseColorResult::kKeyword;
  }

  bool quirks_mode = IsQuirksModeBehavior(parser_mode) &&
                     ColorPropertyAllowsQuirkyColor(property_id);

  // Fast path for hex colors and rgb()/rgba()/hsl()/hsla() colors.
  // Note that ParseColor may be called from external contexts,
  // i.e., when parsing style sheets, so we need the Unicode path here.
  const bool parsed = FastParseColorInternal(out_color, string.Characters8(),
                                             string.length(), quirks_mode);
  return parsed ? ParseColorResult::kColor : ParseColorResult::kFailure;
}

ParseColorResult CSSParserFastPaths::ParseColor(const String& string,
                                                CSSParserMode parser_mode,
                                                Color& color) {
  if (!string.Is8Bit()) {
    // See comment on MaybeParseValue().
    return ParseColorResult::kFailure;
  }
  CSSValueID color_id;
  return blink::ParseColor(CSSPropertyID::kColor, string, parser_mode, color,
                           color_id);
}

bool CSSParserFastPaths::IsValidKeywordPropertyAndValue(
    CSSPropertyID property_id,
    CSSValueID value_id,
    CSSParserMode parser_mode) {
  if (!IsValidCSSValueID(value_id) ||
      !IsValueAllowedInMode(value_id, parser_mode)) {
    return false;
  }

  // For range checks, enum ordering is defined by CSSValueKeywords.in.
  switch (property_id) {
    case CSSPropertyID::kAlignmentBaseline:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kAlphabetic ||
             value_id == CSSValueID::kBaseline ||
             value_id == CSSValueID::kMiddle ||
             value_id == CSSValueID::kHanging ||
             (value_id >= CSSValueID::kBeforeEdge &&
              value_id <= CSSValueID::kMathematical);
    case CSSPropertyID::kAll:
      return false;  // Only accepts css-wide keywords
    case CSSPropertyID::kBaselineSource:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kFirst ||
             value_id == CSSValueID::kLast;
    case CSSPropertyID::kBorderCollapse:
      return value_id == CSSValueID::kCollapse ||
             value_id == CSSValueID::kSeparate;
    case CSSPropertyID::kBorderTopStyle:
    case CSSPropertyID::kBorderRightStyle:
    case CSSPropertyID::kBorderBottomStyle:
    case CSSPropertyID::kBorderLeftStyle:
    case CSSPropertyID::kBorderBlockEndStyle:
    case CSSPropertyID::kBorderBlockStartStyle:
    case CSSPropertyID::kBorderInlineEndStyle:
    case CSSPropertyID::kBorderInlineStartStyle:
    case CSSPropertyID::kColumnRuleStyle:
      return value_id >= CSSValueID::kNone && value_id <= CSSValueID::kDouble;
    case CSSPropertyID::kBoxSizing:
      return value_id == CSSValueID::kBorderBox ||
             value_id == CSSValueID::kContentBox;
    case CSSPropertyID::kBufferedRendering:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kDynamic ||
             value_id == CSSValueID::kStatic;
    case CSSPropertyID::kCaptionSide:
      return value_id == CSSValueID::kTop || value_id == CSSValueID::kBottom;
    case CSSPropertyID::kCaretAnimation:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kManual;
    case CSSPropertyID::kClear:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kLeft ||
             value_id == CSSValueID::kRight || value_id == CSSValueID::kBoth ||
             value_id == CSSValueID::kInlineStart ||
             value_id == CSSValueID::kInlineEnd;
    case CSSPropertyID::kClipRule:
    case CSSPropertyID::kFillRule:
      return value_id == CSSValueID::kNonzero ||
             value_id == CSSValueID::kEvenodd;
    case CSSPropertyID::kColorInterpolation:
    case CSSPropertyID::kColorInterpolationFilters:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kSRGB ||
             value_id == CSSValueID::kLinearrgb;
    case CSSPropertyID::kColorRendering:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kOptimizespeed ||
             value_id == CSSValueID::kOptimizequality;
    case CSSPropertyID::kDirection:
      return value_id == CSSValueID::kLtr || value_id == CSSValueID::kRtl;
    case CSSPropertyID::kDominantBaseline:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kAlphabetic ||
             value_id == CSSValueID::kMiddle ||
             value_id == CSSValueID::kHanging ||
             (value_id >= CSSValueID::kUseScript &&
              value_id <= CSSValueID::kResetSize) ||
             (value_id >= CSSValueID::kCentral &&
              value_id <= CSSValueID::kMathematical);
    case CSSPropertyID::kEmptyCells:
      return value_id == CSSValueID::kShow || value_id == CSSValueID::kHide;
    case CSSPropertyID::kFloat:
      return value_id == CSSValueID::kLeft || value_id == CSSValueID::kRight ||
             value_id == CSSValueID::kInlineStart ||
             value_id == CSSValueID::kInlineEnd ||
             value_id == CSSValueID::kNone;
    case CSSPropertyID::kForcedColorAdjust:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kAuto ||
             (value_id == CSSValueID::kPreserveParentColor &&
              (RuntimeEnabledFeatures::
                   ForcedColorsPreserveParentColorEnabled() ||
               parser_mode == kUASheetMode));
    case CSSPropertyID::kImageRendering:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kWebkitOptimizeContrast ||
             value_id == CSSValueID::kPixelated;
    case CSSPropertyID::kInterpolateSize:
      return value_id == CSSValueID::kNumericOnly ||
             value_id == CSSValueID::kAllowKeywords;
    case CSSPropertyID::kIsolation:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kIsolate;
    case CSSPropertyID::kListStylePosition:
      return value_id == CSSValueID::kInside ||
             value_id == CSSValueID::kOutside;
    case CSSPropertyID::kMaskType:
      return value_id == CSSValueID::kLuminance ||
             value_id == CSSValueID::kAlpha;
    case CSSPropertyID::kMathShift:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kCompact;
    case CSSPropertyID::kMathStyle:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kCompact;
    case CSSPropertyID::kObjectFit:
      return value_id == CSSValueID::kFill ||
             value_id == CSSValueID::kContain ||
             value_id == CSSValueID::kCover || value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kScaleDown;
    case CSSPropertyID::kOutlineStyle:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone ||
             (value_id >= CSSValueID::kInset &&
              value_id <= CSSValueID::kDouble);
    case CSSPropertyID::kOverflowAnchor:
      return value_id == CSSValueID::kVisible ||
             value_id == CSSValueID::kNone || value_id == CSSValueID::kAuto;
    case CSSPropertyID::kOverflowWrap:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kBreakWord ||
             value_id == CSSValueID::kAnywhere;
    case CSSPropertyID::kInternalOverflowBlock:
    case CSSPropertyID::kInternalOverflowInline:
    case CSSPropertyID::kOverflowBlock:
    case CSSPropertyID::kOverflowInline:
    case CSSPropertyID::kOverflowX:
    case CSSPropertyID::kOverflowY:
      return value_id == CSSValueID::kVisible ||
             value_id == CSSValueID::kHidden ||
             value_id == CSSValueID::kScroll || value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kOverlay || value_id == CSSValueID::kClip;
    case CSSPropertyID::kBreakAfter:
    case CSSPropertyID::kBreakBefore:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kAvoid ||
             value_id == CSSValueID::kAvoidPage ||
             value_id == CSSValueID::kPage || value_id == CSSValueID::kLeft ||
             value_id == CSSValueID::kRight || value_id == CSSValueID::kRecto ||
             value_id == CSSValueID::kVerso ||
             value_id == CSSValueID::kAvoidColumn ||
             value_id == CSSValueID::kColumn;
    case CSSPropertyID::kBreakInside:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kAvoid ||
             value_id == CSSValueID::kAvoidPage ||
             value_id == CSSValueID::kAvoidColumn;
    case CSSPropertyID::kPageOrientation:
      return value_id == CSSValueID::kUpright ||
             value_id == CSSValueID::kRotateLeft ||
             value_id == CSSValueID::kRotateRight;
    case CSSPropertyID::kPointerEvents:
      return value_id == CSSValueID::kVisible ||
             value_id == CSSValueID::kNone || value_id == CSSValueID::kAll ||
             value_id == CSSValueID::kAuto ||
             (value_id >= CSSValueID::kVisiblepainted &&
              value_id <= CSSValueID::kBoundingBox);
    case CSSPropertyID::kPosition:
      return value_id == CSSValueID::kStatic ||
             value_id == CSSValueID::kRelative ||
             value_id == CSSValueID::kAbsolute ||
             value_id == CSSValueID::kFixed || value_id == CSSValueID::kSticky;
    case CSSPropertyID::kPositionTryOrder:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kMostWidth ||
             value_id == CSSValueID::kMostHeight ||
             value_id == CSSValueID::kMostBlockSize ||
             value_id == CSSValueID::kMostInlineSize;
    case CSSPropertyID::kReadingFlow:
      DCHECK(RuntimeEnabledFeatures::CSSReadingFlowEnabled());
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kFlexVisual ||
             value_id == CSSValueID::kFlexFlow ||
             value_id == CSSValueID::kGridRows ||
             value_id == CSSValueID::kGridColumns ||
             value_id == CSSValueID::kGridOrder;
    case CSSPropertyID::kResize:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kBoth ||
             value_id == CSSValueID::kHorizontal ||
             value_id == CSSValueID::kVertical ||
             value_id == CSSValueID::kBlock ||
             value_id == CSSValueID::kInline ||
             value_id == CSSValueID::kInternalTextareaAuto ||
             (RuntimeEnabledFeatures::CSSResizeAutoEnabled() &&
              value_id == CSSValueID::kAuto);
    case CSSPropertyID::kScrollMarkerGroup:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kAfter ||
             value_id == CSSValueID::kBefore;
    case CSSPropertyID::kScrollBehavior:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kSmooth;
    case CSSPropertyID::kScrollStartTarget:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone;
    case CSSPropertyID::kShapeRendering:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kOptimizespeed ||
             value_id == CSSValueID::kCrispedges ||
             value_id == CSSValueID::kGeometricprecision;
    case CSSPropertyID::kSpeak:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kSpellOut ||
             value_id == CSSValueID::kDigits ||
             value_id == CSSValueID::kLiteralPunctuation ||
             value_id == CSSValueID::kNoPunctuation;
    case CSSPropertyID::kStrokeLinejoin:
      return value_id == CSSValueID::kMiter || value_id == CSSValueID::kRound ||
             value_id == CSSValueID::kBevel;
    case CSSPropertyID::kStrokeLinecap:
      return value_id == CSSValueID::kButt || value_id == CSSValueID::kRound ||
             value_id == CSSValueID::kSquare;
    case CSSPropertyID::kTableLayout:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kFixed;
    case CSSPropertyID::kTextAlign:
      return (value_id >= CSSValueID::kWebkitAuto &&
              value_id <= CSSValueID::kInternalCenter) ||
             value_id == CSSValueID::kStart || value_id == CSSValueID::kEnd;
    case CSSPropertyID::kTextAlignLast:
      return (value_id >= CSSValueID::kLeft &&
              value_id <= CSSValueID::kJustify) ||
             value_id == CSSValueID::kStart || value_id == CSSValueID::kEnd ||
             value_id == CSSValueID::kAuto;
    case CSSPropertyID::kTextAnchor:
      return value_id == CSSValueID::kStart ||
             value_id == CSSValueID::kMiddle || value_id == CSSValueID::kEnd;
    case CSSPropertyID::kTextCombineUpright:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kAll;
    case CSSPropertyID::kTextDecorationStyle:
      return value_id == CSSValueID::kSolid ||
             value_id == CSSValueID::kDouble ||
             value_id == CSSValueID::kDotted ||
             value_id == CSSValueID::kDashed || value_id == CSSValueID::kWavy;
    case CSSPropertyID::kTextDecorationSkipInk:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone;
    case CSSPropertyID::kTextOrientation:
      return value_id == CSSValueID::kMixed ||
             value_id == CSSValueID::kUpright ||
             value_id == CSSValueID::kSideways ||
             value_id == CSSValueID::kSidewaysRight;
    case CSSPropertyID::kWebkitTextOrientation:
      return value_id == CSSValueID::kSideways ||
             value_id == CSSValueID::kSidewaysRight ||
             value_id == CSSValueID::kVerticalRight ||
             value_id == CSSValueID::kUpright;
    case CSSPropertyID::kTextOverflow:
      return value_id == CSSValueID::kClip || value_id == CSSValueID::kEllipsis;
    case CSSPropertyID::kOverlay:
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kAuto;
    case CSSPropertyID::kTextRendering:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kOptimizespeed ||
             value_id == CSSValueID::kOptimizelegibility ||
             value_id == CSSValueID::kGeometricprecision;
    case CSSPropertyID::kTextTransform:
      return (value_id >= CSSValueID::kCapitalize &&
              value_id <= CSSValueID::kMathAuto) ||
             value_id == CSSValueID::kNone;
    case CSSPropertyID::kUnicodeBidi:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kEmbed ||
             value_id == CSSValueID::kBidiOverride ||
             value_id == CSSValueID::kWebkitIsolate ||
             value_id == CSSValueID::kWebkitIsolateOverride ||
             value_id == CSSValueID::kWebkitPlaintext ||
             value_id == CSSValueID::kIsolate ||
             value_id == CSSValueID::kIsolateOverride ||
             value_id == CSSValueID::kPlaintext;
    case CSSPropertyID::kVectorEffect:
      return value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kNonScalingStroke;
    case CSSPropertyID::kVisibility:
      return value_id == CSSValueID::kVisible ||
             value_id == CSSValueID::kHidden ||
             value_id == CSSValueID::kCollapse;
    case CSSPropertyID::kAppRegion:
      return (value_id >= CSSValueID::kDrag &&
              value_id <= CSSValueID::kNoDrag) ||
             value_id == CSSValueID::kNone;
    case CSSPropertyID::kAppearance:
      return (value_id == CSSValueID::kCheckbox ||
              value_id == CSSValueID::kRadio ||
              value_id == CSSValueID::kButton ||
              value_id == CSSValueID::kListbox ||
              value_id == CSSValueID::kInternalMediaControl ||
              value_id == CSSValueID::kMenulist ||
              value_id == CSSValueID::kMenulistButton ||
              value_id == CSSValueID::kMeter ||
              value_id == CSSValueID::kProgressBar ||
              value_id == CSSValueID::kSearchfield ||
              value_id == CSSValueID::kTextfield ||
              value_id == CSSValueID::kTextarea) ||
             (RuntimeEnabledFeatures::CustomizableSelectEnabled() &&
              value_id == CSSValueID::kBaseSelect) ||
             (RuntimeEnabledFeatures::
                  NonStandardAppearanceValueSliderVerticalEnabled() &&
              value_id == CSSValueID::kSliderVertical) ||
             value_id == CSSValueID::kNone || value_id == CSSValueID::kAuto;
    case CSSPropertyID::kBackfaceVisibility:
      return value_id == CSSValueID::kVisible ||
             value_id == CSSValueID::kHidden;
    case CSSPropertyID::kMixBlendMode:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kMultiply ||
             value_id == CSSValueID::kScreen ||
             value_id == CSSValueID::kOverlay ||
             value_id == CSSValueID::kDarken ||
             value_id == CSSValueID::kLighten ||
             value_id == CSSValueID::kColorDodge ||
             value_id == CSSValueID::kColorBurn ||
             value_id == CSSValueID::kHardLight ||
             value_id == CSSValueID::kSoftLight ||
             value_id == CSSValueID::kDifference ||
             value_id == CSSValueID::kExclusion ||
             value_id == CSSValueID::kHue ||
             value_id == CSSValueID::kSaturation ||
             value_id == CSSValueID::kColor ||
             value_id == CSSValueID::kLuminosity ||
             value_id == CSSValueID::kPlusLighter;
    case CSSPropertyID::kWebkitBoxAlign:
      return value_id == CSSValueID::kStretch ||
             value_id == CSSValueID::kStart || value_id == CSSValueID::kEnd ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kBaseline;
    case CSSPropertyID::kBoxDecorationBreak:
      if (!RuntimeEnabledFeatures::BoxDecorationBreakEnabled()) {
        return false;
      }
      [[fallthrough]];
    case CSSPropertyID::kWebkitBoxDecorationBreak:
      return value_id == CSSValueID::kClone || value_id == CSSValueID::kSlice;
    case CSSPropertyID::kWebkitBoxDirection:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kReverse;
    case CSSPropertyID::kWebkitBoxOrient:
      return value_id == CSSValueID::kHorizontal ||
             value_id == CSSValueID::kVertical ||
             value_id == CSSValueID::kInlineAxis ||
             value_id == CSSValueID::kBlockAxis;
    case CSSPropertyID::kWebkitBoxPack:
      return value_id == CSSValueID::kStart || value_id == CSSValueID::kEnd ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kJustify;
    case CSSPropertyID::kColumnFill:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kBalance;
    case CSSPropertyID::kAlignContent:
      // FIXME: Per CSS alignment, this property should accept an optional
      // <overflow-position>. We should share this parsing code with
      // 'justify-self'.
      return value_id == CSSValueID::kFlexStart ||
             value_id == CSSValueID::kFlexEnd ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kSpaceBetween ||
             value_id == CSSValueID::kSpaceAround ||
             value_id == CSSValueID::kStretch;
    case CSSPropertyID::kAlignItems:
      // FIXME: Per CSS alignment, this property should accept the same
      // arguments as 'justify-self' so we should share its parsing code.
      return value_id == CSSValueID::kFlexStart ||
             value_id == CSSValueID::kFlexEnd ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kBaseline ||
             value_id == CSSValueID::kStretch;
    case CSSPropertyID::kAlignSelf:
      // FIXME: Per CSS alignment, this property should accept the same
      // arguments as 'justify-self' so we should share its parsing code.
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kFlexStart ||
             value_id == CSSValueID::kFlexEnd ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kBaseline ||
             value_id == CSSValueID::kStretch;
    case CSSPropertyID::kFlexDirection:
      return value_id == CSSValueID::kRow ||
             value_id == CSSValueID::kRowReverse ||
             value_id == CSSValueID::kColumn ||
             value_id == CSSValueID::kColumnReverse;
    case CSSPropertyID::kFlexWrap:
      return value_id == CSSValueID::kNowrap || value_id == CSSValueID::kWrap ||
             value_id == CSSValueID::kWrapReverse;
    case CSSPropertyID::kFieldSizing:
      return value_id == CSSValueID::kFixed || value_id == CSSValueID::kContent;
    case CSSPropertyID::kHyphens:
#if BUILDFLAG(USE_MINIKIN_HYPHENATION) || BUILDFLAG(IS_APPLE)
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kManual;
#else
      return value_id == CSSValueID::kNone || value_id == CSSValueID::kManual;
#endif
    case CSSPropertyID::kJustifyContent:
      // FIXME: Per CSS alignment, this property should accept an optional
      // <overflow-position>. We should share this parsing code with
      // 'justify-self'.
      return value_id == CSSValueID::kFlexStart ||
             value_id == CSSValueID::kFlexEnd ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kSpaceBetween ||
             value_id == CSSValueID::kSpaceAround;
    case CSSPropertyID::kFontKerning:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kNone;
    case CSSPropertyID::kFontOpticalSizing:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone;
    case CSSPropertyID::kFontSynthesisWeight:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone;
    case CSSPropertyID::kFontSynthesisStyle:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone;
    case CSSPropertyID::kFontSynthesisSmallCaps:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone;
    case CSSPropertyID::kWebkitFontSmoothing:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kAntialiased ||
             value_id == CSSValueID::kSubpixelAntialiased;
    case CSSPropertyID::kFontVariantPosition:
      return value_id == CSSValueID::kNormal || value_id == CSSValueID::kSub ||
             value_id == CSSValueID::kSuper;
    case CSSPropertyID::kFontVariantEmoji:
      DCHECK(RuntimeEnabledFeatures::FontVariantEmojiEnabled());
      return value_id == CSSValueID::kNormal || value_id == CSSValueID::kText ||
             value_id == CSSValueID::kEmoji || value_id == CSSValueID::kUnicode;
    case CSSPropertyID::kLineBreak:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kLoose ||
             value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kStrict ||
             value_id == CSSValueID::kAnywhere;
    case CSSPropertyID::kWebkitLineBreak:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kLoose ||
             value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kStrict ||
             value_id == CSSValueID::kAfterWhiteSpace;
    case CSSPropertyID::kWebkitPrintColorAdjust:
      return value_id == CSSValueID::kExact || value_id == CSSValueID::kEconomy;
    case CSSPropertyID::kWebkitRtlOrdering:
      return value_id == CSSValueID::kLogical ||
             value_id == CSSValueID::kVisual;
    case CSSPropertyID::kRubyAlign:
      return value_id == CSSValueID::kSpaceAround ||
             value_id == CSSValueID::kStart ||
             value_id == CSSValueID::kCenter ||
             value_id == CSSValueID::kSpaceBetween;
    case CSSPropertyID::kWebkitRubyPosition:
      return value_id == CSSValueID::kBefore || value_id == CSSValueID::kAfter;
    case CSSPropertyID::kRubyPosition:
      return value_id == CSSValueID::kOver || value_id == CSSValueID::kUnder;
    case CSSPropertyID::kTextAutospace:
      DCHECK(RuntimeEnabledFeatures::CSSTextAutoSpaceEnabled());
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kNoAutospace;
    case CSSPropertyID::kTextSpacingTrim:
      return value_id == CSSValueID::kNormal ||
             value_id == CSSValueID::kTrimStart ||
             value_id == CSSValueID::kSpaceAll ||
             value_id == CSSValueID::kSpaceFirst;
    case CSSPropertyID::kWebkitTextCombine:
      return value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kHorizontal;
    case CSSPropertyID::kWebkitTextSecurity:
      return value_id == CSSValueID::kDisc || value_id == CSSValueID::kCircle ||
             value_id == CSSValueID::kSquare || value_id == CSSValueID::kNone;
    case CSSPropertyID::kTextWrapMode:
      return value_id == CSSValueID::kWrap || value_id == CSSValueID::kNowrap;
    case CSSPropertyID::kTextWrapStyle:
      return value_id == CSSValueID::kAuto ||
             value_id == CSSValueID::kBalance ||
             value_id == CSSValueID::kPretty || value_id == CSSValueID::kStable;
    case CSSPropertyID::kTransformBox:
      return value_id == CSSValueID::kContentBox ||
             value_id == CSSValueID::kBorderBox ||
             value_id == CSSValueID::kStrokeBox ||
             value_id == CSSValueID::kFillBox ||
             value_id == CSSValueID::kViewBox;
    case CSSPropertyID::kTransformStyle:
      return value_id == CSSValueID::kFlat ||
             value_id == CSSValueID::kPreserve3d;
    case CSSPropertyID::kWebkitUserDrag:
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kElement;
    case CSSPropertyID::kWebkitUserModify:
      return value_id == CSSValueID::kReadOnly ||
             value_id == CSSValueID::kReadWrite ||
             value_id == CSSValueID::kReadWritePlaintextOnly;
    case CSSPropertyID::kUserSelect:
      if (!RuntimeEnabledFeatures::CSSUserSelectContainEnabled()) {
        return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone ||
               value_id == CSSValueID::kText || value_id == CSSValueID::kAll;
      }
      return value_id == CSSValueID::kAuto || value_id == CSSValueID::kNone ||
             value_id == CSSValueID::kText || value_id == CSSValueID::kAll ||
             value_id == CSSValueID::kContain;
    case CSSPropertyID::kWebkitWritingMode:
      return value_id >= CSSValueID::kHorizontalTb &&
             value_id <= CSSValueID::kVerticalLr;
    case CSSPropertyID::kWritingMode:
      if (RuntimeEnabledFeatures::SidewaysWritingModesEnabled()) {
        if (value_id == CSSValueID::kSidewaysRl ||
            value_id =
```