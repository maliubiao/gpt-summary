Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file for parsing CSS in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename `css_parsing_utils.cc` and the function names within the snippet strongly suggest that this code provides utility functions for parsing CSS values. This involves reading tokens from a `CSSParserTokenStream` and converting them into specific CSS value types (like integers, lengths, colors, etc.).

2. **Analyze Key Function Categories:**  Group the functions based on the type of CSS value they handle:
    * **Basic Types:** Integers, numbers, percentages.
    * **Dimensions:** Lengths, angles, times, resolutions.
    * **Textual Values:** Identifiers, custom identifiers, strings, URLs.
    * **Compound Values:** Ratios, gradients (implicitly by checking `IsImage`), color spaces.
    * **Utility/Helper Functions:**  `Complete4Sides`, `ConsumeCommaIncludingWhitespace`, `ConsumeSlashIncludingWhitespace`, `ConsumeAnyValue`, `MathFunctionParser`.

3. **Examine Individual Functions:**  For each function, determine its specific role:
    * **`IsImage()`/`IsImageSet()`:** Checks if a given `CSSValueID` represents an image-related function.
    * **`Complete4Sides()`:**  Handles shorthand properties by filling in missing values (e.g., `margin: 10px` becomes `margin: 10px 10px 10px 10px`).
    * **`ConsumeCommaIncludingWhitespace()`/`ConsumeSlashIncludingWhitespace()`:**  Consume specific delimiters.
    * **`ConsumeAnyValue()`/`ConsumeAnyComponentValue()`:**  Consume any valid CSS component value, useful for generic parsing.
    * **`MathFunctionParser`:** A crucial class for handling `calc()` and other math functions, allowing for lookahead and rewinding if the parse fails. It handles different categories of math functions (length, number, angle, etc.).
    * **`ConsumeInteger*()`/`ConsumeNumber*()`/`ConsumePercent()`:** Functions for parsing numeric values with optional units or percentage signs. Note the variations for different ranges and handling of `calc()`.
    * **`ConsumeLength()`:**  Parses length values with different units, handling unitless zero in specific contexts (SVG, quirks mode).
    * **`ConsumeAngle()`/`ConsumeTime()`/`ConsumeResolution()`:**  Parse specific dimension types.
    * **`ConsumeRatio()`:** Parses `<ratio>` values.
    * **`ConsumeIdent*()`/`ConsumeCustomIdent*()`/`ConsumeString*()`:**  Parse identifier and string values.
    * **`ConsumeUrl*()`:** Parses URL values, with considerations for security (data URLs only) and attribute tainting.
    * **`ConsumeColorInterpolationSpace()`:** Parses color space and hue interpolation options within color functions.

4. **Identify Relationships with Web Technologies:**
    * **JavaScript:** While the C++ code doesn't directly execute JavaScript, its parsing results are used by the rendering engine, which is heavily influenced by JavaScript manipulations of the DOM and CSSOM. Example: JavaScript setting `element.style.width = 'calc(100% - 50px)'` relies on this code to parse the `calc()` function.
    * **HTML:** The CSS parsed by this code styles HTML elements. The structure of the HTML influences which CSS rules apply. Example:  `<div style="width: 100px;">` – the `width` style is parsed here.
    * **CSS:** This code *is* about CSS parsing. It takes CSS syntax as input and produces internal representations of CSS values. Example: Parsing `color: red;` would involve identifying the `color` property and the `red` keyword.

5. **Illustrate with Examples:** Provide simple CSS snippets and explain how the relevant functions would process them. This makes the explanation more concrete.

6. **Infer Logic and Provide Hypothetical Input/Output:** For functions with clear logic (like `Complete4Sides`), demonstrate how they transform input. For more complex parsing functions, the "output" is the successful creation of a CSS value object or a failure (returning `nullptr`).

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers make when writing CSS that could involve these parsing functions:
    * Incorrect units (`width: 100;` in strict mode).
    * Invalid `calc()` expressions (`calc(100% + )`).
    * Incorrect syntax in color functions.
    * Issues with URLs (especially when restrictions are in place).

8. **Explain the Debugging Context:**  Describe how a developer might end up looking at this code during debugging, tracing the flow from user actions to the parsing process.

9. **Structure and Summarize:** Organize the information logically with clear headings and bullet points. The final summary should concisely capture the main purpose of the code.

10. **Address the "Part 2 of 9" aspect:**  Acknowledge that this is part of a larger system and that this section specifically deals with parsing utilities.

**(Self-Correction/Refinement during the process):**

* Initially, I might have just listed the functions without grouping them. Realizing the importance of categorization improves clarity.
* I might have focused too much on the low-level details of token streams. Shifting the focus to the *purpose* of each function (parsing specific CSS value types) is more helpful.
* The connection to JavaScript and HTML might not be immediately obvious. Explicitly stating how the parsed CSS is used in the browser's rendering pipeline is crucial.
* The debugging scenario adds practical context and helps understand *why* this code exists.

By following these steps, we can generate a comprehensive and informative explanation of the provided code snippet.
这是对 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件第二部分的分析。 从代码来看，这部分主要专注于**消费和解析各种类型的 CSS 值**，并提供了一些辅助函数来简化解析过程。

以下是这部分代码功能的归纳：

**核心功能：解析和消费 CSS 值**

* **图像相关:**
    * `IsImage(const CSSValueID id)`: 判断给定的 `CSSValueID` 是否代表一个 CSS 图像函数 (例如 `url`, `image`, `linear-gradient` 等)。
    * `IsImageSet(const CSSValueID id)`: 判断给定的 `CSSValueID` 是否代表 `image-set` 函数。

* **通用辅助函数:**
    * `Complete4Sides(std::array<CSSValue*, 4>& side)`: 用于处理 CSS 简写属性，例如 `margin: 10px` 会被展开成 `margin: 10px 10px 10px 10px`。如果 `side` 数组中缺少值，则会根据已有的值进行填充。
    * `ConsumeCommaIncludingWhitespace(CSSParserTokenStream& stream)`: 尝试消费一个逗号，包括其前后的空白字符。成功则返回 `true`。
    * `ConsumeSlashIncludingWhitespace(CSSParserTokenStream& stream)`: 尝试消费一个斜杠，包括其前后的空白字符。成功则返回 `true`。
    * `ConsumeAnyComponentValue(CSSParserTokenStream& stream)`: 尝试消费任何合法的 CSS 组件值 (例如标识符，数字，字符串，块等)。
    * `ConsumeAnyValue(CSSParserTokenStream& stream)`: 消费流中所有剩余的组件值。

* **数学函数解析器 (`MathFunctionParser`):**
    * 这是一个辅助类，用于解析可能存在的 CSS 数学函数 (例如 `calc()`, `min()`, `max()`).
    * 它的主要作用是允许 "回溯"。如果尝试解析的不是一个有效的数学函数，它会将解析器状态恢复到开始解析之前。
    * 提供了 `ConsumeValue()` 和 `ConsumeNumberRaw()` 等方法来获取解析后的数学函数值。

* **具体数值类型解析:**
    * `ConsumeIntegerInternal()`, `ConsumeInteger()`: 解析整数值，可以指定最小值，并支持解析 `calc()` 表达式。`ConsumeIntegerOrNumberCalc()` 特别处理了 `calc()` 表达式返回非整数的情况，使其在期望整数时也有效。
    * `ConsumePositiveInteger()`: 解析正整数。
    * `ConsumeNumberRaw()`: 解析原始数字值 (不带单位)，可以支持 `calc()`。
    * `ConsumeNumber()`: 解析数字值，可以指定数值范围，并支持解析返回数字的 `calc()` 表达式。

* **长度和百分比解析:**
    * `ShouldAcceptUnitlessLength()`:  判断在特定情况下是否接受无单位的长度值 (例如，0 值，SVG 属性，Quirks 模式)。
    * `ConsumeLength()`: 解析长度值，支持各种长度单位 (px, em, rem, vw, vh 等)，并根据上下文 (例如 SVG 属性) 处理无单位值。也支持解析返回长度的 `calc()` 表达式。
    * `ConsumePercent()`: 解析百分比值，并支持解析返回百分比的 `calc()` 表达式。
    * `ConsumeNumberOrPercent()`: 尝试解析数字或百分比，并将百分比转换为 0 到 1 之间的数字。
    * `ConsumeAlphaValue()`: 用于解析 alpha 通道值，本质上是解析一个数字或百分比。
    * `CanConsumeCalcValue()`: 判断 `calc()` 表达式的返回类型是否在当前上下文中有效。
    * `ConsumeLengthOrPercent()`: 尝试解析长度或百分比，并支持解析返回长度或百分比的 `calc()` 表达式，并可以根据 `allow_calc_size` 参数控制是否允许 `auto` 和 `content` 等关键字在 `calc()` 中使用。
    * `ConsumeSVGGeometryPropertyLength()`:  专门用于解析 SVG 几何属性的长度或百分比，在 SVG 属性模式下，无单位的值会被认为是用户单位。
    * `ConsumeGradientLengthOrPercent()`: 用于解析渐变相关的长度或百分比。

* **角度解析:**
    * `ConsumeNumericLiteralAngle()`: 解析字面量角度值 (例如 `45deg`, `1rad`)。
    * `ConsumeMathFunctionAngle()` (两个重载): 解析返回角度的 `calc()` 表达式，可以限定角度范围。
    * `ConsumeAngle()` (两个重载):  尝试解析角度值，可以是字面量或者 `calc()` 表达式。

* **时间解析:**
    * `ConsumeTime()`: 解析时间值 (例如 `100ms`, `2s`)，并支持解析返回时间的 `calc()` 表达式。

* **分辨率解析:**
    * `ConsumeResolution()`: 解析分辨率值 (例如 `72dpi`, `96dppx`)，并支持解析返回分辨率的 `calc()` 表达式。

* **比例值解析:**
    * `ConsumeRatio()`: 解析比例值 (例如 `16/9`, `2`).

* **标识符解析:**
    * `ConsumeIdent()`: 尝试消费一个标识符 (例如 `auto`, `red`).
    * `ConsumeIdentRange()`: 尝试消费一个指定范围内的标识符。
    * `ConsumeCustomIdent()`: 尝试消费一个自定义标识符 (不能是 CSS 预定义的关键字)。
    * `ConsumeDashedIdent()`: 尝试消费一个以双短划线开头的自定义标识符。
    * `ConsumeScopedKeywordValue()`: 尝试消费一个作用域关键字值。

* **字符串解析:**
    * `ConsumeString()`: 尝试消费一个字符串字面量 (用引号括起来)。
    * `ConsumeStringAsString()`: 尝试消费一个字符串字面量并返回其 `String` 表示。

* **URL 解析:**
    * `CollectUrlData()`: 收集 URL 相关的信息，例如完整 URL，referrer 等。
    * `ConsumeUrlAsToken()`: 尝试消费一个 URL，将其作为 token 返回。会考虑 `data:` URL 限制和属性污染。
    * `ConsumeUrl()`: 尝试消费一个 URL 并创建一个 `CSSURIValue` 对象。

* **颜色插值空间解析:**
    * `ConsumeColorInterpolationSpace()`:  解析颜色插值空间和色调插值方法 (例如 `in lch longer`).

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:** 这个文件直接参与 CSS 的解析过程。它读取 CSS 语法并将其转换为 Blink 引擎可以理解的内部表示。例如，当解析 `width: 100px;` 时，`ConsumeLength()` 函数会被用来解析 `100px`。
* **HTML:** HTML 元素通过 `style` 属性或外部 CSS 文件应用样式。这个文件解析的 CSS 值最终会影响 HTML 元素的渲染。例如，HTML 中的 `<div style="width: calc(50% - 10px);">` 会触发 `ConsumeLengthOrPercent()` 和 `MathFunctionParser` 来解析 `calc()` 表达式。
* **JavaScript:** JavaScript 可以通过 DOM API (例如 `element.style.width = '200px'`) 修改元素的样式。当 JavaScript 设置 CSS 属性时，Blink 引擎仍然需要解析这些值，这个文件中的函数可能会被调用。例如，当 JavaScript 设置 `element.style.transform = 'rotate(45deg)'` 时，`ConsumeAngle()` 会被用来解析 `45deg`。

**逻辑推理的假设输入与输出：**

* **假设输入 (CSS):** `margin: 10px;`
* **调用函数:** `Complete4Sides` (可能在处理 `margin` 简写属性时调用)
* **输出 (C++ 数据结构):**  `side[0] = CSSNumericLiteralValue(10, CSSPrimitiveValue::UnitType::kPixels)`, `side[1] = CSSNumericLiteralValue(10, CSSPrimitiveValue::UnitType::kPixels)`, `side[2] = CSSNumericLiteralValue(10, CSSPrimitiveValue::UnitType::kPixels)`, `side[3] = CSSNumericLiteralValue(10, CSSPrimitiveValue::UnitType::kPixels)`

* **假设输入 (CSS):** `width: calc(100% - 50px);`
* **调用函数:** `ConsumeLengthOrPercent`, `MathFunctionParser`
* **输出 (C++ 对象):** 一个 `CSSCalcValue` 对象，内部表示为 100% 减去 50px。

**用户或编程常见的使用错误举例：**

* **错误的单位:** 用户在 CSS 中写了 `width: 100;` (缺少单位)。`ConsumeLength()` 在严格模式下会返回 `nullptr`，因为缺少了合法的长度单位。
* **`calc()` 表达式错误:** 用户写了 `width: calc(100% + );` (缺少操作数)。`MathFunctionParser` 在解析时会失败，导致 `ConsumeLengthOrPercent()` 返回 `nullptr`。
* **URL 拼写错误或访问限制:**  用户在 CSS 中使用了错误的 URL 或者该 URL 由于安全策略 (例如只允许 `data:` URL) 而无法加载。`ConsumeUrl()` 可能会返回一个空的 URL 或 `nullptr`。
* **颜色函数参数错误:** 用户在 CSS 中使用了错误的颜色函数参数，例如 `rgb(255, , 0)`。相关的颜色解析函数会失败。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 和 CSS 被下载并由 Blink 引擎解析。**
3. **当解析 CSS 样式规则时，例如 `style` 属性或 CSS 文件中的规则，Blink 的 CSS 解析器会调用 `css_parsing_utils.cc` 中的函数。**
4. **例如，如果解析器遇到 `width: 100px;`，它会调用 `ConsumeLength()` 函数。**
5. **如果开发者工具被打开，并且设置了断点或者使用了单步调试，他们可以跟踪代码执行到 `css_parsing_utils.cc` 中的特定函数，例如 `ConsumeLength()` 或 `MathFunctionParser`。**
6. **他们可以观察 `CSSParserTokenStream` 中的 token 流，以及这些函数如何消费和转换 token。**
7. **如果样式没有按预期工作，开发者可能会检查这些解析函数是否正确地解释了 CSS 值，例如，检查 `calc()` 表达式是否被正确解析。**

总而言之，这部分 `css_parsing_utils.cc` 文件的核心职责是提供一组用于安全可靠地解析各种 CSS 值的工具函数，它是 Blink 引擎理解和应用 CSS 样式的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
kWebkitGradient:
    case CSSValueID::kWebkitCrossFade:
    case CSSValueID::kPaint:
    case CSSValueID::kCrossFade:
      return true;

    default:
      return false;
  }
}

bool IsImageSet(const CSSValueID id) {
  return id == CSSValueID::kWebkitImageSet || id == CSSValueID::kImageSet;
}

}  // namespace

void Complete4Sides(std::array<CSSValue*, 4>& side) {
  if (side[3]) {
    return;
  }
  if (!side[2]) {
    if (!side[1]) {
      side[1] = side[0];
    }
    side[2] = side[0];
  }
  side[3] = side[1];
}

bool ConsumeCommaIncludingWhitespace(CSSParserTokenStream& stream) {
  CSSParserToken value = stream.Peek();
  if (value.GetType() != kCommaToken) {
    return false;
  }
  stream.ConsumeIncludingWhitespace();
  return true;
}

bool ConsumeSlashIncludingWhitespace(CSSParserTokenStream& stream) {
  CSSParserToken value = stream.Peek();
  if (value.GetType() != kDelimiterToken || value.Delimiter() != '/') {
    return false;
  }
  stream.ConsumeIncludingWhitespace();
  return true;
}

namespace {

bool ConsumeAnyComponentValue(CSSParserTokenStream& stream) {
  if (stream.Peek().GetBlockType() == CSSParserToken::kBlockStart) {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    ConsumeAnyValue(stream);
    if (guard.Release()) {
      return true;
    }
  } else if (IsTokenAllowedForAnyValue(stream.Peek())) {
    stream.Consume();
    return true;
  }
  return false;
}

}  // namespace

void ConsumeAnyValue(CSSParserTokenStream& stream) {
  while (!stream.AtEnd()) {
    if (!ConsumeAnyComponentValue(stream)) {
      return;
    }
  }
}

// MathFunctionParser is a helper for parsing something that _might_ be a
// function. In particular, it helps rewinding the parser to the point where it
// started if what was to be parsed was not a function (or an invalid function).
// This rewinding happens in the destructor, unless Consume*() was called _and_
// returned success. In effect, this gives us a multi-token peek for functions.
//
// TODO(rwlbuis): consider pulling in the parsing logic from
// css_math_expression_node.cc.
class MathFunctionParser {
  STACK_ALLOCATED();

 public:
  using Flag = CSSMathExpressionNode::Flag;
  using Flags = CSSMathExpressionNode::Flags;

  MathFunctionParser(
      CSSParserTokenStream& stream,
      const CSSParserContext& context,
      CSSPrimitiveValue::ValueRange value_range,
      const Flags parsing_flags = Flags({Flag::AllowPercent}),
      CSSAnchorQueryTypes allowed_anchor_queries = kCSSAnchorQueryTypesNone,
      const CSSColorChannelMap& color_channel_map = {})
      : stream_(&stream), savepoint_(stream.Save()) {
    const CSSParserToken token = stream.Peek();
    if (token.GetType() == kFunctionToken) {
      {
        CSSParserTokenStream::BlockGuard guard(*stream_);
        stream_->ConsumeWhitespace();
        calc_value_ = CSSMathFunctionValue::Create(
            CSSMathExpressionNode::ParseMathFunction(
                token.FunctionId(), *stream_, context, parsing_flags,
                allowed_anchor_queries),
            value_range);
      }
      stream_->ConsumeWhitespace();
    }
  }

  ~MathFunctionParser() {
    if (!has_consumed_) {
      // Rewind the parser.
      stream_->Restore(savepoint_);
    }
  }

  const CSSMathFunctionValue* Value() const { return calc_value_; }
  CSSMathFunctionValue* ConsumeValue() {
    if (!calc_value_) {
      return nullptr;
    }
    DCHECK(!has_consumed_);  // Cannot consume twice.
    has_consumed_ = true;
    CSSMathFunctionValue* result = calc_value_;
    calc_value_ = nullptr;
    return result;
  }

  bool ConsumeNumberRaw(double& result) {
    if (!calc_value_ || calc_value_->Category() != kCalcNumber) {
      return false;
    }
    DCHECK(!has_consumed_);  // Cannot consume twice.
    has_consumed_ = true;
    result = calc_value_->GetDoubleValue();
    return true;
  }

 private:
  bool has_consumed_ = false;
  CSSParserTokenStream* stream_;
  // For rewinding.
  CSSParserTokenStream::State savepoint_;
  CSSMathFunctionValue* calc_value_ = nullptr;
};

CSSPrimitiveValue* ConsumeIntegerInternal(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          double minimum_value,
                                          const bool is_percentage_allowed) {
  const CSSParserToken token = stream.Peek();
  if (token.GetType() == kNumberToken) {
    if (token.GetNumericValueType() == kNumberValueType ||
        token.NumericValue() < minimum_value) {
      return nullptr;
    }
    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(),
        CSSPrimitiveValue::UnitType::kInteger);
  }

  DCHECK(minimum_value == -std::numeric_limits<double>::max() ||
         minimum_value == 0 || minimum_value == 1);

  CSSPrimitiveValue::ValueRange value_range =
      CSSPrimitiveValue::ValueRange::kInteger;
  if (minimum_value == 0) {
    value_range = CSSPrimitiveValue::ValueRange::kNonNegativeInteger;
  } else if (minimum_value == 1) {
    value_range = CSSPrimitiveValue::ValueRange::kPositiveInteger;
  }

  using enum CSSMathExpressionNode::Flag;
  using Flags = CSSMathExpressionNode::Flags;

  Flags parsing_flags;
  if (is_percentage_allowed) {
    parsing_flags.Put(AllowPercent);
  }

  MathFunctionParser math_parser(stream, context, value_range, parsing_flags);
  if (const CSSMathFunctionValue* math_value = math_parser.Value()) {
    if (math_value->Category() != kCalcNumber) {
      return nullptr;
    }
    return math_parser.ConsumeValue();
  }
  return nullptr;
}

CSSPrimitiveValue* ConsumeInteger(CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  double minimum_value,
                                  const bool is_percentage_allowed) {
  return ConsumeIntegerInternal(stream, context, minimum_value,
                                is_percentage_allowed);
}

// This implements the behavior defined in [1], where calc() expressions
// are valid when <integer> is expected, even if the calc()-expression does
// not result in an integral value.
//
// TODO(andruud): Eventually this behavior should just be part of
// ConsumeInteger, and this function can be removed. For now, having a separate
// function with this behavior allows us to implement [1] gradually.
//
// [1] https://drafts.csswg.org/css-values-4/#calc-type-checking
CSSPrimitiveValue* ConsumeIntegerOrNumberCalc(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSPrimitiveValue::ValueRange value_range) {
  double minimum_value = -std::numeric_limits<double>::max();
  switch (value_range) {
    case CSSPrimitiveValue::ValueRange::kAll:
      NOTREACHED() << "unexpected value range for integer parsing";
    case CSSPrimitiveValue::ValueRange::kInteger:
      minimum_value = -std::numeric_limits<double>::max();
      break;
    case CSSPrimitiveValue::ValueRange::kNonNegative:
      NOTREACHED() << "unexpected value range for integer parsing";
    case CSSPrimitiveValue::ValueRange::kNonNegativeInteger:
      minimum_value = 0.0;
      break;
    case CSSPrimitiveValue::ValueRange::kPositiveInteger:
      minimum_value = 1.0;
      break;
  }
  if (CSSPrimitiveValue* value =
          ConsumeInteger(stream, context, minimum_value)) {
    return value;
  }

  MathFunctionParser math_parser(stream, context, value_range);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (calculation->Category() != kCalcNumber) {
      return nullptr;
    }
    return math_parser.ConsumeValue();
  }
  return nullptr;
}

CSSPrimitiveValue* ConsumePositiveInteger(CSSParserTokenStream& stream,
                                          const CSSParserContext& context) {
  return ConsumeInteger(stream, context, 1);
}

bool ConsumeNumberRaw(CSSParserTokenStream& stream,
                      const CSSParserContext& context,
                      double& result) {
  if (stream.Peek().GetType() == kNumberToken) {
    result = stream.ConsumeIncludingWhitespace().NumericValue();
    return true;
  }
  MathFunctionParser math_parser(stream, context,
                                 CSSPrimitiveValue::ValueRange::kAll);
  return math_parser.ConsumeNumberRaw(result);
}

CSSPrimitiveValue* ConsumeNumber(CSSParserTokenStream& stream,
                                 const CSSParserContext& context,
                                 CSSPrimitiveValue::ValueRange value_range) {
  const CSSParserToken token = stream.Peek();
  if (token.GetType() == kNumberToken) {
    if (value_range == CSSPrimitiveValue::ValueRange::kNonNegative &&
        token.NumericValue() < 0) {
      return nullptr;
    }
    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(),
        token.GetUnitType());
  }
  MathFunctionParser math_parser(stream, context, value_range);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (calculation->Category() != kCalcNumber) {
      return nullptr;
    }
    return math_parser.ConsumeValue();
  }
  return nullptr;
}

inline bool ShouldAcceptUnitlessLength(double value,
                                       CSSParserMode css_parser_mode,
                                       UnitlessQuirk unitless) {
  return value == 0 || css_parser_mode == kSVGAttributeMode ||
         (css_parser_mode == kHTMLQuirksMode &&
          unitless == UnitlessQuirk::kAllow);
}

CSSPrimitiveValue* ConsumeLength(CSSParserTokenStream& stream,
                                 const CSSParserContext& context,
                                 CSSPrimitiveValue::ValueRange value_range,
                                 UnitlessQuirk unitless) {
  const CSSParserToken token = stream.Peek();
  if (token.GetType() == kDimensionToken) {
    switch (token.GetUnitType()) {
      case CSSPrimitiveValue::UnitType::kQuirkyEms:
        if (context.Mode() != kUASheetMode) {
          return nullptr;
        }
        [[fallthrough]];
      case CSSPrimitiveValue::UnitType::kEms:
      case CSSPrimitiveValue::UnitType::kRems:
      case CSSPrimitiveValue::UnitType::kChs:
      case CSSPrimitiveValue::UnitType::kExs:
      case CSSPrimitiveValue::UnitType::kPixels:
      case CSSPrimitiveValue::UnitType::kCentimeters:
      case CSSPrimitiveValue::UnitType::kMillimeters:
      case CSSPrimitiveValue::UnitType::kQuarterMillimeters:
      case CSSPrimitiveValue::UnitType::kInches:
      case CSSPrimitiveValue::UnitType::kPoints:
      case CSSPrimitiveValue::UnitType::kPicas:
      case CSSPrimitiveValue::UnitType::kUserUnits:
      case CSSPrimitiveValue::UnitType::kViewportWidth:
      case CSSPrimitiveValue::UnitType::kViewportHeight:
      case CSSPrimitiveValue::UnitType::kViewportMin:
      case CSSPrimitiveValue::UnitType::kViewportMax:
      case CSSPrimitiveValue::UnitType::kIcs:
      case CSSPrimitiveValue::UnitType::kLhs:
      case CSSPrimitiveValue::UnitType::kRexs:
      case CSSPrimitiveValue::UnitType::kRchs:
      case CSSPrimitiveValue::UnitType::kRics:
      case CSSPrimitiveValue::UnitType::kRlhs:
      case CSSPrimitiveValue::UnitType::kCaps:
      case CSSPrimitiveValue::UnitType::kRcaps:
      case CSSPrimitiveValue::UnitType::kViewportInlineSize:
      case CSSPrimitiveValue::UnitType::kViewportBlockSize:
      case CSSPrimitiveValue::UnitType::kSmallViewportWidth:
      case CSSPrimitiveValue::UnitType::kSmallViewportHeight:
      case CSSPrimitiveValue::UnitType::kSmallViewportInlineSize:
      case CSSPrimitiveValue::UnitType::kSmallViewportBlockSize:
      case CSSPrimitiveValue::UnitType::kSmallViewportMin:
      case CSSPrimitiveValue::UnitType::kSmallViewportMax:
      case CSSPrimitiveValue::UnitType::kLargeViewportWidth:
      case CSSPrimitiveValue::UnitType::kLargeViewportHeight:
      case CSSPrimitiveValue::UnitType::kLargeViewportInlineSize:
      case CSSPrimitiveValue::UnitType::kLargeViewportBlockSize:
      case CSSPrimitiveValue::UnitType::kLargeViewportMin:
      case CSSPrimitiveValue::UnitType::kLargeViewportMax:
      case CSSPrimitiveValue::UnitType::kDynamicViewportWidth:
      case CSSPrimitiveValue::UnitType::kDynamicViewportHeight:
      case CSSPrimitiveValue::UnitType::kDynamicViewportInlineSize:
      case CSSPrimitiveValue::UnitType::kDynamicViewportBlockSize:
      case CSSPrimitiveValue::UnitType::kDynamicViewportMin:
      case CSSPrimitiveValue::UnitType::kDynamicViewportMax:
      case CSSPrimitiveValue::UnitType::kContainerWidth:
      case CSSPrimitiveValue::UnitType::kContainerHeight:
      case CSSPrimitiveValue::UnitType::kContainerInlineSize:
      case CSSPrimitiveValue::UnitType::kContainerBlockSize:
      case CSSPrimitiveValue::UnitType::kContainerMin:
      case CSSPrimitiveValue::UnitType::kContainerMax:
        break;
      default:
        return nullptr;
    }
    if (value_range == CSSPrimitiveValue::ValueRange::kNonNegative &&
        token.NumericValue() < 0) {
      return nullptr;
    }
    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(),
        token.GetUnitType());
  }
  if (token.GetType() == kNumberToken) {
    if (!ShouldAcceptUnitlessLength(token.NumericValue(), context.Mode(),
                                    unitless) ||
        (value_range == CSSPrimitiveValue::ValueRange::kNonNegative &&
         token.NumericValue() < 0)) {
      return nullptr;
    }
    CSSPrimitiveValue::UnitType unit_type =
        CSSPrimitiveValue::UnitType::kPixels;
    if (context.Mode() == kSVGAttributeMode) {
      unit_type = CSSPrimitiveValue::UnitType::kUserUnits;
    }
    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(), unit_type);
  }
  if (context.Mode() == kSVGAttributeMode) {
    return nullptr;
  }
  MathFunctionParser math_parser(stream, context, value_range);
  if (math_parser.Value() && math_parser.Value()->Category() == kCalcLength) {
    return math_parser.ConsumeValue();
  }
  return nullptr;
}

CSSPrimitiveValue* ConsumePercent(CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  CSSPrimitiveValue::ValueRange value_range) {
  const CSSParserToken token = stream.Peek();
  if (token.GetType() == kPercentageToken) {
    if (value_range == CSSPrimitiveValue::ValueRange::kNonNegative &&
        token.NumericValue() < 0) {
      return nullptr;
    }
    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(),
        CSSPrimitiveValue::UnitType::kPercentage);
  }
  MathFunctionParser math_parser(stream, context, value_range);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (calculation->Category() == kCalcPercent) {
      return math_parser.ConsumeValue();
    }
  }
  return nullptr;
}

CSSPrimitiveValue* ConsumeNumberOrPercent(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSPrimitiveValue::ValueRange value_stream) {
  if (CSSPrimitiveValue* value = ConsumeNumber(stream, context, value_stream)) {
    return value;
  }
  if (CSSPrimitiveValue* value =
          ConsumePercent(stream, context, value_stream)) {
    return CSSNumericLiteralValue::Create(value->GetDoubleValue() / 100.0,
                                          CSSPrimitiveValue::UnitType::kNumber);
  }
  return nullptr;
}

CSSPrimitiveValue* ConsumeAlphaValue(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  return ConsumeNumberOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kAll);
}

bool CanConsumeCalcValue(CalculationResultCategory category,
                         CSSParserMode css_parser_mode) {
  return category == kCalcLength || category == kCalcPercent ||
         category == kCalcLengthFunction || category == kCalcIntrinsicSize ||
         (css_parser_mode == kSVGAttributeMode && category == kCalcNumber);
}

CSSPrimitiveValue* ConsumeLengthOrPercent(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSPrimitiveValue::ValueRange value_range,
    UnitlessQuirk unitless,
    CSSAnchorQueryTypes allowed_anchor_queries,
    AllowCalcSize allow_calc_size) {
  using enum CSSMathExpressionNode::Flag;
  using Flags = CSSMathExpressionNode::Flags;

  const CSSParserToken& token = stream.Peek();
  if (token.GetType() == kDimensionToken || token.GetType() == kNumberToken) {
    return ConsumeLength(stream, context, value_range, unitless);
  }
  if (token.GetType() == kPercentageToken) {
    return ConsumePercent(stream, context, value_range);
  }
  Flags parsing_flags({AllowPercent});
  switch (allow_calc_size) {
    case AllowCalcSize::kAllowWithAutoAndContent:
      parsing_flags.Put(AllowContentInCalcSize);
      [[fallthrough]];
    case AllowCalcSize::kAllowWithAuto:
      parsing_flags.Put(AllowAutoInCalcSize);
      [[fallthrough]];
    case AllowCalcSize::kAllowWithoutAuto:
      parsing_flags.Put(AllowCalcSize);
      [[fallthrough]];
    case AllowCalcSize::kForbid:
      break;
  }
  MathFunctionParser math_parser(stream, context, value_range, parsing_flags,
                                 allowed_anchor_queries);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (CanConsumeCalcValue(calculation->Category(), context.Mode())) {
      return math_parser.ConsumeValue();
    }
  }
  return nullptr;
}

namespace {

bool IsNonZeroUserUnitsValue(const CSSPrimitiveValue* value) {
  if (!value) {
    return false;
  }
  if (const auto* numeric_literal = DynamicTo<CSSNumericLiteralValue>(value)) {
    return numeric_literal->GetType() ==
               CSSPrimitiveValue::UnitType::kUserUnits &&
           value->GetDoubleValue() != 0;
  }
  const auto& math_value = To<CSSMathFunctionValue>(*value);
  return math_value.Category() == kCalcNumber && math_value.DoubleValue() != 0;
}

}  // namespace

CSSPrimitiveValue* ConsumeSVGGeometryPropertyLength(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSPrimitiveValue::ValueRange value_range) {
  CSSParserContext::ParserModeOverridingScope scope(context, kSVGAttributeMode);
  CSSPrimitiveValue* value = ConsumeLengthOrPercent(
      stream, context, value_range, UnitlessQuirk::kForbid);
  if (IsNonZeroUserUnitsValue(value)) {
    context.Count(WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue);
  }
  return value;
}

CSSPrimitiveValue* ConsumeGradientLengthOrPercent(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSPrimitiveValue::ValueRange value_range,
    UnitlessQuirk unitless) {
  return ConsumeLengthOrPercent(stream, context, value_range, unitless);
}

static CSSPrimitiveValue* ConsumeNumericLiteralAngle(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    std::optional<WebFeature> unitless_zero_feature) {
  const CSSParserToken token = stream.Peek();
  if (token.GetType() == kDimensionToken) {
    switch (token.GetUnitType()) {
      case CSSPrimitiveValue::UnitType::kDegrees:
      case CSSPrimitiveValue::UnitType::kRadians:
      case CSSPrimitiveValue::UnitType::kGradians:
      case CSSPrimitiveValue::UnitType::kTurns:
        return CSSNumericLiteralValue::Create(
            stream.ConsumeIncludingWhitespace().NumericValue(),
            token.GetUnitType());
      default:
        return nullptr;
    }
  }
  if (token.GetType() == kNumberToken && token.NumericValue() == 0 &&
      unitless_zero_feature) {
    stream.ConsumeIncludingWhitespace();
    context.Count(*unitless_zero_feature);
    return CSSNumericLiteralValue::Create(
        0, CSSPrimitiveValue::UnitType::kDegrees);
  }
  return nullptr;
}

template <class T>
  requires std::is_same_v<T, CSSParserTokenStream>
static CSSPrimitiveValue* ConsumeMathFunctionAngle(
    T& stream,
    const CSSParserContext& context,
    double minimum_value,
    double maximum_value) {
  MathFunctionParser math_parser(stream, context,
                                 CSSPrimitiveValue::ValueRange::kAll);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (calculation->Category() != kCalcAngle) {
      return nullptr;
    }
  }
  if (CSSMathFunctionValue* result = math_parser.ConsumeValue()) {
    auto* numeric_result =
        DynamicTo<CSSMathExpressionNumericLiteral>(result->ExpressionNode());
    if (numeric_result && numeric_result->DoubleValue() < minimum_value) {
      return CSSNumericLiteralValue::Create(
          minimum_value, CSSPrimitiveValue::UnitType::kDegrees);
    }
    if (numeric_result && numeric_result->DoubleValue() > maximum_value) {
      return CSSNumericLiteralValue::Create(
          maximum_value, CSSPrimitiveValue::UnitType::kDegrees);
    }
    return result;
  }
  return nullptr;
}

static CSSPrimitiveValue* ConsumeMathFunctionAngle(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  MathFunctionParser math_parser(stream, context,
                                 CSSPrimitiveValue::ValueRange::kAll);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (calculation->Category() != kCalcAngle) {
      return nullptr;
    }
  }
  return math_parser.ConsumeValue();
}

CSSPrimitiveValue* ConsumeAngle(CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                std::optional<WebFeature> unitless_zero_feature,
                                double minimum_value,
                                double maximum_value) {
  if (auto* result =
          ConsumeNumericLiteralAngle(stream, context, unitless_zero_feature)) {
    return result;
  }

  return ConsumeMathFunctionAngle(stream, context, minimum_value,
                                  maximum_value);
}

CSSPrimitiveValue* ConsumeAngle(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    std::optional<WebFeature> unitless_zero_feature) {
  if (auto* result =
          ConsumeNumericLiteralAngle(stream, context, unitless_zero_feature)) {
    return result;
  }

  return ConsumeMathFunctionAngle(stream, context);
}

CSSPrimitiveValue* ConsumeTime(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               CSSPrimitiveValue::ValueRange value_range) {
  const CSSParserToken token = stream.Peek();
  if (token.GetType() == kDimensionToken) {
    if (value_range == CSSPrimitiveValue::ValueRange::kNonNegative &&
        token.NumericValue() < 0) {
      return nullptr;
    }
    CSSPrimitiveValue::UnitType unit = token.GetUnitType();
    if (unit == CSSPrimitiveValue::UnitType::kMilliseconds ||
        unit == CSSPrimitiveValue::UnitType::kSeconds) {
      return CSSNumericLiteralValue::Create(
          stream.ConsumeIncludingWhitespace().NumericValue(),
          token.GetUnitType());
    }
    return nullptr;
  }
  MathFunctionParser math_parser(stream, context, value_range);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    if (calculation->Category() == kCalcTime) {
      return math_parser.ConsumeValue();
    }
  }
  return nullptr;
}

CSSPrimitiveValue* ConsumeResolution(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  if (const CSSParserToken& token = stream.Peek();
      token.GetType() == kDimensionToken) {
    CSSPrimitiveValue::UnitType unit = token.GetUnitType();
    if (!CSSPrimitiveValue::IsResolution(unit) || token.NumericValue() < 0.0) {
      // "The allowed range of <resolution> values always excludes negative
      // values"
      // https://www.w3.org/TR/css-values-4/#resolution-value

      return nullptr;
    }

    return CSSNumericLiteralValue::Create(
        stream.ConsumeIncludingWhitespace().NumericValue(), unit);
  }

  MathFunctionParser math_parser(stream, context,
                                 CSSPrimitiveValue::ValueRange::kNonNegative);
  const CSSMathFunctionValue* math_value = math_parser.Value();
  if (math_value && math_value->IsResolution()) {
    return math_parser.ConsumeValue();
  }

  return nullptr;
}

// https://drafts.csswg.org/css-values-4/#ratio-value
//
// <ratio> = <number [0,+inf]> [ / <number [0,+inf]> ]?
CSSValue* ConsumeRatio(CSSParserTokenStream& stream,
                       const CSSParserContext& context) {
  CSSParserSavePoint savepoint(stream);

  CSSPrimitiveValue* first = ConsumeNumber(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!first) {
    return nullptr;
  }

  CSSPrimitiveValue* second = nullptr;

  if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
    second = ConsumeNumber(stream, context,
                           CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!second) {
      return nullptr;
    }
  } else {
    second = CSSNumericLiteralValue::Create(
        1, CSSPrimitiveValue::UnitType::kInteger);
  }

  savepoint.Release();
  return MakeGarbageCollected<cssvalue::CSSRatioValue>(*first, *second);
}

CSSIdentifierValue* ConsumeIdent(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kIdentToken) {
    return nullptr;
  }
  return CSSIdentifierValue::Create(stream.ConsumeIncludingWhitespace().Id());
}

CSSIdentifierValue* ConsumeIdentRange(CSSParserTokenStream& stream,
                                      CSSValueID lower,
                                      CSSValueID upper) {
  if (stream.Peek().Id() < lower || stream.Peek().Id() > upper) {
    return nullptr;
  }
  return ConsumeIdent(stream);
}

CSSCustomIdentValue* ConsumeCustomIdent(CSSParserTokenStream& stream,
                                        const CSSParserContext& context) {
  if (stream.Peek().GetType() != kIdentToken ||
      IsCSSWideKeyword(stream.Peek().Id()) ||
      stream.Peek().Id() == CSSValueID::kDefault) {
    return nullptr;
  }
  return MakeGarbageCollected<CSSCustomIdentValue>(
      stream.ConsumeIncludingWhitespace().Value().ToAtomicString());
}

CSSCustomIdentValue* ConsumeDashedIdent(CSSParserTokenStream& stream,
                                        const CSSParserContext& context) {
  if (stream.Peek().GetType() != kIdentToken) {
    return nullptr;
  }
  if (!stream.Peek().Value().ToString().StartsWith(kTwoDashes)) {
    return nullptr;
  }

  return ConsumeCustomIdent(stream, context);
}

cssvalue::CSSScopedKeywordValue* ConsumeScopedKeywordValue(
    CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kIdentToken) {
    return nullptr;
  }
  return MakeGarbageCollected<cssvalue::CSSScopedKeywordValue>(
      stream.ConsumeIncludingWhitespace().Id());
}

CSSStringValue* ConsumeString(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kStringToken) {
    return nullptr;
  }
  return MakeGarbageCollected<CSSStringValue>(
      stream.ConsumeIncludingWhitespace().Value().ToString());
}

String ConsumeStringAsString(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != CSSParserTokenType::kStringToken) {
    return String();
  }

  return stream.ConsumeIncludingWhitespace().Value().ToString();
}

namespace {

// Invalidate the URL if only data URLs are allowed and the protocol is not
// data.
//
// NOTE: The StringView must be instantiated with an empty string; otherwise the
// URL will incorrectly be identified as null. The resource should behave as
// if it failed to load.
bool IsFetchRestricted(StringView url, const CSSParserContext& context) {
  return !url.IsNull() &&
         context.ResourceFetchRestriction() ==
             ResourceFetchRestriction::kOnlyDataUrls &&
         !ProtocolIs(url.ToString(), "data");
}

CSSUrlData CollectUrlData(const StringView& url,
                          const CSSParserContext& context) {
  AtomicString url_string = url.ToAtomicString();
  return CSSUrlData(
      url_string, context.CompleteNonEmptyURL(url_string),
      context.GetReferrer(),
      context.IsOriginClean() ? OriginClean::kTrue : OriginClean::kFalse,
      context.IsAdRelated());
}

}  // namespace

// Returns a token whose token.Value() will contain the URL,
// or the empty string if there are fetch restrictions,
// or an EOF token if we failed to parse.
//
// NOTE: We are careful not to return a reference, since the token
// will be overwritten once we move to the next one.
CSSParserToken ConsumeUrlAsToken(CSSParserTokenStream& stream,
                                 const CSSParserContext& context) {
  wtf_size_t value_start_offset = stream.LookAheadOffset();
  stream.EnsureLookAhead();

  CSSParserToken token = stream.Peek();
  if (token.GetType() == kUrlToken) {
    stream.ConsumeIncludingWhitespace();
  } else if (token.FunctionId() == CSSValueID::kUrl) {
    {
      CSSParserTokenStream::RestoringBlockGuard guard(stream);
      stream.ConsumeWhitespace();
      // If the block doesn't start with a quote, then the tokenizer
      // would return a kUrlToken or kBadUrlToken instead of a
      // kFunctionToken. Note also that this Peek() placates the
      // DCHECK that we Peek() before Consume().
      DCHECK(stream.Peek().GetType() == kStringToken ||
             stream.Peek().GetType() == kBadStringToken)
          << "Got unexpected token " << stream.Peek();
      token = stream.ConsumeIncludingWhitespace();
      if (token.GetType() == kBadStringToken || !stream.AtEnd()) {
        return CSSParserToken(kEOFToken);
      }
      guard.Release();
    }
    DCHECK_EQ(token.GetType(), kStringToken);
    stream.ConsumeWhitespace();
  } else {
    return CSSParserToken(kEOFToken);
  }
  wtf_size_t value_end_offset = stream.LookAheadOffset();
  if (IsAttrTainted(stream, value_start_offset, value_end_offset)) {
    return CSSParserToken(kEOFToken);
  }
  return IsFetchRestricted(token.Value(), context)
             ? CSSParserToken(kUrlToken, StringView(""))
             : token;
}

cssvalue::CSSURIValue* ConsumeUrl(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  CSSParserToken url = ConsumeUrlAsToken(stream, context);
  if (url.GetType() == kEOFToken) {
    return nullptr;
  }
  return MakeGarbageCollected<cssvalue::CSSURIValue>(
      CollectUrlData(url.Value(), context));
}

static bool ConsumeColorInterpolationSpace(
    CSSParserTokenStream& stream,
    Color::ColorSpace& color_space,
    Color::HueInterpolationMethod& hue_interpolation) {
  if (!ConsumeIdent<CSSValueID::kIn>(stream)) {
    return false;
  }

  std::optional<Color::ColorSpace> read_color_space;
  if (ConsumeIdent<CSSValueID::kXyz>(stream)) {
    read_color_space = Color::ColorSpace::kXYZD65;
  } else if (ConsumeIdent<CSSValueID::kXyzD50>(stream)) {
    read_color_space = Color::ColorSpace::kXYZD50;
  } else if (ConsumeIdent<CSSValueID::kXyzD65>(stream)) {
    read_color_space = Color::ColorSpace::kXYZD65;
  } else if (ConsumeIdent<CSSValueID::kSRGBLinear>(stream)) {
    read_color_space = Color::ColorSpace::kSRGBLinear;
  } else if (ConsumeIdent<CSSValueID::kDisplayP3>(stream)) {
    read_color_space = Color::ColorSpace::kDisplayP3;
  } else if (ConsumeIdent<CSSValueID::kA98Rgb>(stream)) {
    read_color_space = Color::ColorSpace::kA98RGB;
  } else if (ConsumeIdent<CSSValueID::kProphotoRgb>(stream)) {
    read_color_space = Color::ColorSpace::kProPhotoRGB;
  } else if (ConsumeIdent<CSSValueID::kRec2020>(stream)) {
    read_color_space = Color::ColorSpace::kRec2020;
  } else if (ConsumeIdent<CSSValueID::kLab>(stream)) {
    read_color_space = Color::ColorSpace::kLab;
  } else if (ConsumeIdent<CSSValueID::kOklab>(stream)) {
    read_color_space = Color::ColorSpace::kOklab;
  } else if (ConsumeIdent<CSSValueID::kLch>(stream)) {
    read_color_space = Color::ColorSpace::kLch;
  } else if (ConsumeIdent<CSSValueID::kOklch>(stream)) {
    read_color_space = Color::ColorSpace::kOklch;
  } else if (ConsumeIdent<CSSValueID::kSRGB>(stream)) {
    read_color_space = Color::ColorSpace::kSRGB;
  } else if (ConsumeIdent<CSSValueID::kHsl>(stream)) {
    read_color_space = Color::ColorSpace::kHSL;
  } else if (ConsumeIdent<CSSValueID::kHwb>(stream)) {
    read_color_space = Color::ColorSpace::kHWB;
  }

  if (read_color_space) {
    color_space = read_color_space.value();
    std::optional<Color::HueInterpolationMethod> read_hue;
    if (color_space == Color::ColorSpace::kHSL ||
        color_space == Color::ColorSpace::kHWB ||
        color_space == Color::ColorSpace::kLch ||
        color_space == Color::ColorSpace::kOklch) {
      if (ConsumeIdent<CSSValueID::kShorter>(stream)) {
        read_hue = Color::HueInterpolationMethod::kShorter;
      } else if (ConsumeIdent<CSSValueID::kLonger>
```