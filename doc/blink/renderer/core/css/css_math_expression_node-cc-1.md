Response:
The user wants to understand the functionality of the `css_math_expression_node.cc` file in the Chromium Blink rendering engine. Specifically, they are asking for a summary of the functionality covered in the provided code snippet, which is the second part of a six-part file.

To address this, I need to:

1. **Identify the key classes and their methods within the snippet.**  The main focus appears to be on `CSSMathExpressionNumericLiteral`, `CSSMathExpressionIdentifierLiteral`, `CSSMathExpressionKeywordLiteral`, and `CSSMathExpressionOperation`.
2. **Summarize the purpose of each class and its prominent methods.**
3. **Explain the relationships to JavaScript, HTML, and CSS.** This will involve understanding how these classes contribute to the evaluation and representation of CSS `calc()` expressions.
4. **Provide examples of logical reasoning with input and output.** This likely involves demonstrating how these classes handle specific mathematical operations and value conversions.
5. **Illustrate common user or programming errors.**  This could involve incorrect syntax in `calc()` expressions or misunderstandings of unit conversions.
6. **Describe the user actions leading to this code.** This will involve the user writing CSS that includes `calc()` expressions.
7. **Focus specifically on the functionality within *this* code snippet (part 2).**  Avoid making assumptions about the functionality in the other parts.
这是 blink/renderer/core/css/css_math_expression_node.cc 文件的第 2 部分，主要集中在以下几个方面：

**核心功能归纳:**

1. **`CSSMathExpressionNumericLiteral` 类**:
   - **表示 CSS 数值字面量：**  这个类用来表示 `calc()` 表达式中的数字值，包括数字、长度、百分比、角度、时间、频率和分辨率等单位。
   - **单位处理和转换：** 提供了方法用于将数值转换为规范单位 (`CreateCanonicalUnitValue`), 将百分比转换为数字 (`ConvertLiteralsFromPercentageToNumber`), 以及计算在不同单位下的值 (例如 `ComputeLengthPx`, `ComputeDegrees`, `ComputeSeconds`)。
   - **值解析和比较：**  可以判断数值是否解析为特定值 (`ResolvesTo`), 是否为负数 (`IsNegative`)。
   - **转换为其他表示形式：** 能够将数值字面量转换为 `CalculationExpressionNode` 体系下的节点 (`ToCalculationExpression`)，这可能是用于更底层的计算或序列化。
   - **支持 `PixelsAndPercent` 结构：**  提供将数值转换为 `PixelsAndPercent` 结构的能力，用于处理长度和百分比的组合。

2. **`CSSMathExpressionIdentifierLiteral` 类**:
   - **表示 CSS 标识符：**  用于表示 `calc()` 表达式中使用的标识符 (identifiers)，例如变量名。
   - **转换为 `CalculationExpressionNode`：** 能够将其表示的标识符转换为 `CalculationExpressionIdentifierNode`。

3. **`CSSMathExpressionKeywordLiteral` 类**:
   - **表示 CSS 关键字：** 用于表示 `calc()` 表达式中使用的关键字，例如 `min-content`, `max-content`, `width`, `height` 等。
   - **区分上下文：**  通过 `Context` 枚举来区分关键字的使用场景，例如 `kMediaProgress` (与媒体进度相关), `kCalcSize` (与尺寸计算相关), `kColorChannel` (与颜色通道相关)。
   - **转换为 `CalculationExpressionNode`：** 根据不同的上下文，将其转换为不同的 `CalculationExpressionNode` 子类，例如 `CalculationExpressionSizingKeywordNode` (尺寸关键字), `CalculationExpressionColorChannelKeywordNode` (颜色通道关键字)。
   - **计算值：**  在 `kMediaProgress` 上下文中，能够计算 `width` 和 `height` 关键字对应的视口宽度和高度。

4. **`CSSMathExpressionOperation` 类**:
   - **表示 CSS 数学运算：**  用于表示 `calc()` 表达式中的各种数学运算，例如加减乘除、`min()`, `max()`, `clamp()`, 三角函数、指数函数、取整函数等。
   - **运算符处理：**  通过 `CSSMathOperator` 枚举来表示不同的运算符。
   - **类型推断：** 提供了 `DetermineCategory` 等静态方法来推断运算结果的类型。
   - **创建运算节点：**  提供了多种静态方法 (`CreateArithmeticOperation`, `CreateCalcSizeOperation`, `CreateComparisonFunction`, `CreateTrigonometricFunctionSimplified` 等) 来创建不同类型的运算节点。
   - **算术运算简化：**  提供了 `CreateArithmeticOperationSimplified` 用于创建已简化的算术运算节点，前提是操作数都是数值字面量。
   - **三角函数和指数函数支持：** 实现了对 `sin()`, `cos()`, `tan()`, `asin()`, `acos()`, `atan()`, `atan2()`, `pow()`, `sqrt()`, `hypot()`, `log()`, `exp()` 等函数的支持，并尝试在可能的情况下进行简化。
   - **`round()` 函数支持：** 实现了对 `round()`, `ceil()`, `floor()`, `trunc()` 等取整函数的支持。
   - **`abs()` 和 `sign()` 函数支持：** 实现了对绝对值和符号函数的支持。
   - **百分比到数字的转换：**  提供了将操作数中的百分比转换为数字的功能 (`ConvertLiteralsFromPercentageToNumber`).

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这个文件直接服务于 CSS 的 `calc()` 函数。`calc()` 允许在 CSS 属性值中使用数学表达式。
    * **例子：**  CSS 代码 `width: calc(100% - 20px);` 会被解析，其中 `100%` 和 `20px` 会被表示为 `CSSMathExpressionNumericLiteral`，`-` 运算会被表示为 `CSSMathExpressionOperation`。
    * **例子：**  CSS 代码 `width: calc(min-content + 10px);` 中的 `min-content` 关键字会被表示为 `CSSMathExpressionKeywordLiteral`。
    * **例子：**  CSS 代码 `width: calc(var(--my-variable) * 2);` 中的 `--my-variable` 可能会被表示为 `CSSMathExpressionIdentifierLiteral` (取决于具体的实现和变量解析阶段)。

* **HTML:** HTML 结构会影响某些 `calc()` 表达式的计算，特别是与尺寸相关的计算。例如，一个元素的宽度依赖于其父元素的宽度时，HTML 的结构就起到了作用。

* **JavaScript:** JavaScript 可以通过 DOM API 获取和修改元素的样式，包括包含 `calc()` 函数的属性值。浏览器在处理这些样式时会用到这里的代码。此外，CSSOM (CSS Object Model) 允许 JavaScript 操作 CSS 规则和值，可能涉及到对 `calc()` 表达式的访问和修改。

**逻辑推理的假设输入与输出举例:**

* **假设输入 (CSS):** `width: calc(50px + 2rem);`
* **逻辑推理 (Simplified):**
    1. `50px` 被创建为 `CSSMathExpressionNumericLiteral` (kCalcLength)。
    2. `2rem` 被创建为 `CSSMathExpressionNumericLiteral` (kCalcLength)。
    3. `+` 运算被创建为 `CSSMathExpressionOperation`，使用 `kAdd` 运算符。
    4. `DetermineCategory` 方法会判断结果类型为 `kCalcLength`。
* **假设输出 (Internal Representation):** 一个 `CSSMathExpressionOperation` 对象，包含两个 `CSSMathExpressionNumericLiteral` 子节点。

* **假设输入 (CSS):** `font-size: calc(16px * 1.5);`
* **逻辑推理 (Simplified):**
    1. `16px` 被创建为 `CSSMathExpressionNumericLiteral` (kCalcLength)。
    2. `1.5` 被创建为 `CSSMathExpressionNumericLiteral` (kCalcNumber)。
    3. `*` 运算被创建为 `CSSMathExpressionOperation`，使用 `kMultiply` 运算符。
    4. `DetermineCategory` 方法会判断结果类型为 `kCalcLength`。
* **假设输出 (Internal Representation):** 一个 `CSSMathExpressionOperation` 对象，包含两个 `CSSMathExpressionNumericLiteral` 子节点。

**用户或编程常见的使用错误举例:**

* **单位不兼容的加减运算:**  例如 `calc(10px + 5%)`，在没有上下文信息的情况下是无效的。这个文件中的代码会尝试确定运算结果的类型，如果类型不兼容，可能会返回 `nullptr` 或导致后续处理出错。
* **除数为零:** 例如 `calc(100px / 0)` 会导致错误。
* **`min()` 或 `max()` 函数的参数类型不一致导致无法比较:** 例如 `calc(min(10px, 5%))`，如果没有上下文，px 和 % 无法直接比较大小。
* **在不支持 `calc()` 的 CSS 属性中使用:** 某些旧版本的浏览器或特定的 CSS 属性可能不支持 `calc()`。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户编写 HTML 文件，并在 `<style>` 标签或外部 CSS 文件中使用了包含 `calc()` 函数的 CSS 规则。**
   * 例如：`<div style="width: calc(100% / 3 - 20px);"></div>`

2. **浏览器解析 HTML 和 CSS。**  当解析器遇到包含 `calc()` 的属性值时，会识别这是一个数学表达式。

3. **Blink 渲染引擎的 CSS 解析器会创建表示该表达式的语法树。**  在这个过程中，会创建 `CSSMathExpressionNode` 及其子类的对象，例如 `CSSMathExpressionNumericLiteral` 表示数值，`CSSMathExpressionOperation` 表示运算。

4. **当需要计算该属性的最终值时（例如在布局阶段），会遍历这个语法树，并调用 `CSSMathExpressionNode` 及其子类的方法进行计算。**  例如，`ComputeLengthPx` 方法会被调用来计算长度值。

5. **调试时，可以在 Blink 的渲染流水线中设置断点，查看这些 `CSSMathExpressionNode` 对象的创建和计算过程。**  例如，可以在 `CSSMathExpressionOperation::Compute` 或 `CSSMathExpressionNumericLiteral::ComputeLengthPx` 等方法中设置断点。

**总结来说，这个代码片段定义了用于表示和处理 CSS `calc()` 表达式中数值、标识符、关键字以及各种数学运算的类，并提供了进行单位转换、类型推断和表达式简化的功能。 它是 Blink 引擎解析和计算 CSS `calc()` 函数的核心组成部分。**

### 提示词
```
这是目录为blink/renderer/core/css/css_math_expression_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
>GetType()),
                            false /* has_comparisons*/,
                            false /* has_anchor_functions*/,
                            false /* needs_tree_scope_population*/),
      value_(value) {
  if (!value_->IsNumber() && CanEagerlySimplify(this)) {
    // "If root is a dimension that is not expressed in its canonical unit, and
    // there is enough information available to convert it to the canonical
    // unit, do so, and return the value."
    // https://w3c.github.io/csswg-drafts/css-values/#calc-simplification
    //
    // However, Numbers should not be eagerly simplified here since that would
    // result in converting Integers to Doubles (kNumber, canonical unit for
    // Numbers).

    value_ = value_->CreateCanonicalUnitValue();
  }
}

const CSSMathExpressionNode*
CSSMathExpressionNumericLiteral::ConvertLiteralsFromPercentageToNumber() const {
  if (category_ != kCalcPercent) {
    return this;
  }
  return CSSMathExpressionNumericLiteral::Create(
      value_->DoubleValue() / 100, CSSPrimitiveValue::UnitType::kNumber);
}

CSSPrimitiveValue::BoolStatus CSSMathExpressionNumericLiteral::ResolvesTo(
    double value) const {
  std::optional<double> maybe_value = ComputeValueInCanonicalUnit();
  if (!maybe_value.has_value()) {
    return CSSPrimitiveValue::BoolStatus::kUnresolvable;
  }
  return maybe_value.value() == value ? CSSPrimitiveValue::BoolStatus::kTrue
                                      : CSSPrimitiveValue::BoolStatus::kFalse;
}

CSSPrimitiveValue::BoolStatus CSSMathExpressionNumericLiteral::IsNegative()
    const {
  std::optional<double> maybe_value = ComputeValueInCanonicalUnit();
  if (!maybe_value.has_value()) {
    return CSSPrimitiveValue::BoolStatus::kUnresolvable;
  }
  return maybe_value.value() < 0.0 ? CSSPrimitiveValue::BoolStatus::kTrue
                                   : CSSPrimitiveValue::BoolStatus::kFalse;
}

String CSSMathExpressionNumericLiteral::CustomCSSText() const {
  return value_->CssText();
}

std::optional<PixelsAndPercent>
CSSMathExpressionNumericLiteral::ToPixelsAndPercent(
    const CSSLengthResolver& length_resolver) const {
  switch (category_) {
    case kCalcLength:
      return PixelsAndPercent(value_->ComputeLengthPx(length_resolver), 0.0f,
                              /*has_explicit_pixels=*/true,
                              /*has_explicit_percent=*/false);
    case kCalcPercent:
      DCHECK(value_->IsPercentage());
      return PixelsAndPercent(0.0f, value_->GetDoubleValueWithoutClamping(),
                              /*has_explicit_pixels=*/false,
                              /*has_explicit_percent=*/true);
    case kCalcNumber:
      // TODO(alancutter): Stop treating numbers like pixels unconditionally
      // in calcs to be able to accomodate border-image-width
      // https://drafts.csswg.org/css-backgrounds-3/#the-border-image-width
      return PixelsAndPercent(value_->GetFloatValue() * length_resolver.Zoom(),
                              0.0f, /*has_explicit_pixels=*/true,
                              /*has_explicit_percent=*/false);
    case kCalcAngle:
      // Treat angles as pixels to support calc() expressions on hue angles in
      // relative color syntax. This allows converting such expressions to
      // CalculationValues.
      return PixelsAndPercent(value_->GetFloatValue(), 0.0f,
                              /*has_explicit_pixels=*/true,
                              /*has_explicit_percent=*/false);
    default:
      NOTREACHED();
  }
}

scoped_refptr<const CalculationExpressionNode>
CSSMathExpressionNumericLiteral::ToCalculationExpression(
    const CSSLengthResolver& length_resolver) const {
  if (Category() == kCalcNumber) {
    return base::MakeRefCounted<CalculationExpressionNumberNode>(
        value_->DoubleValue());
  }
  return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
      *ToPixelsAndPercent(length_resolver));
}

double CSSMathExpressionNumericLiteral::DoubleValue() const {
  if (HasDoubleValue(ResolvedUnitType())) {
    return value_->GetDoubleValueWithoutClamping();
  }
  DUMP_WILL_BE_NOTREACHED();
  return 0;
}

std::optional<double>
CSSMathExpressionNumericLiteral::ComputeValueInCanonicalUnit() const {
  switch (category_) {
    case kCalcNumber:
    case kCalcPercent:
      return value_->DoubleValue();
    case kCalcLength:
      if (CSSPrimitiveValue::IsRelativeUnit(value_->GetType())) {
        return std::nullopt;
      }
      [[fallthrough]];
    case kCalcAngle:
    case kCalcTime:
    case kCalcFrequency:
    case kCalcResolution:
      return value_->DoubleValue() *
             CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(
                 value_->GetType());
    default:
      return std::nullopt;
  }
}

std::optional<double>
CSSMathExpressionNumericLiteral::ComputeValueInCanonicalUnit(
    const CSSLengthResolver& length_resolver) const {
  return value_->ComputeInCanonicalUnit(length_resolver);
}

double CSSMathExpressionNumericLiteral::ComputeDouble(
    const CSSLengthResolver& length_resolver) const {
  switch (category_) {
    case kCalcLength:
      return value_->ComputeLengthPx(length_resolver);
    case kCalcPercent:
    case kCalcNumber:
      return value_->DoubleValue();
    case kCalcAngle:
      return value_->ComputeDegrees();
    case kCalcTime:
      return value_->ComputeSeconds();
    case kCalcResolution:
      return value_->ComputeDotsPerPixel();
    case kCalcFrequency:
      return value_->ComputeInCanonicalUnit();
    case kCalcLengthFunction:
    case kCalcIntrinsicSize:
    case kCalcOther:
    case kCalcIdent:
      NOTREACHED();
  }
  NOTREACHED();
}

double CSSMathExpressionNumericLiteral::ComputeLengthPx(
    const CSSLengthResolver& length_resolver) const {
  switch (category_) {
    case kCalcLength:
      return value_->ComputeLengthPx(length_resolver);
    case kCalcNumber:
    case kCalcPercent:
    case kCalcAngle:
    case kCalcFrequency:
    case kCalcLengthFunction:
    case kCalcIntrinsicSize:
    case kCalcTime:
    case kCalcResolution:
    case kCalcOther:
    case kCalcIdent:
      NOTREACHED();
  }
  NOTREACHED();
}

bool CSSMathExpressionNumericLiteral::AccumulateLengthArray(
    CSSLengthArray& length_array,
    double multiplier) const {
  DCHECK_NE(Category(), kCalcNumber);
  return value_->AccumulateLengthArray(length_array, multiplier);
}

void CSSMathExpressionNumericLiteral::AccumulateLengthUnitTypes(
    CSSPrimitiveValue::LengthTypeFlags& types) const {
  value_->AccumulateLengthUnitTypes(types);
}

bool CSSMathExpressionNumericLiteral::operator==(
    const CSSMathExpressionNode& other) const {
  if (!other.IsNumericLiteral()) {
    return false;
  }

  return base::ValuesEquivalent(
      value_, To<CSSMathExpressionNumericLiteral>(other).value_);
}

CSSPrimitiveValue::UnitType CSSMathExpressionNumericLiteral::ResolvedUnitType()
    const {
  return value_->GetType();
}

bool CSSMathExpressionNumericLiteral::IsComputationallyIndependent() const {
  return value_->IsComputationallyIndependent();
}

void CSSMathExpressionNumericLiteral::Trace(Visitor* visitor) const {
  visitor->Trace(value_);
  CSSMathExpressionNode::Trace(visitor);
}

#if DCHECK_IS_ON()
bool CSSMathExpressionNumericLiteral::InvolvesPercentageComparisons() const {
  return false;
}
#endif

// ------ End of CSSMathExpressionNumericLiteral member functions

static constexpr std::array<std::array<CalculationResultCategory, kCalcOther>,
                            kCalcOther>
    kAddSubtractResult = {
        /* CalcNumber */
        {{kCalcNumber, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther},
         /* CalcLength */
         {kCalcOther, kCalcLength, kCalcLengthFunction, kCalcLengthFunction,
          kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther},
         /* CalcPercent */
         {kCalcOther, kCalcLengthFunction, kCalcPercent, kCalcLengthFunction,
          kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther},
         /* CalcLengthFunction */
         {kCalcOther, kCalcLengthFunction, kCalcLengthFunction,
          kCalcLengthFunction, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcOther},
         /* CalcIntrinsicSize */
         {kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther},
         /* CalcAngle */
         {kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcAngle, kCalcOther, kCalcOther, kCalcOther, kCalcOther},
         /* CalcTime */
         {kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcTime, kCalcOther, kCalcOther, kCalcOther},
         /* CalcFrequency */
         {kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcOther, kCalcFrequency, kCalcOther, kCalcOther},
         /* CalcResolution */
         {kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcOther, kCalcOther, kCalcResolution, kCalcOther},
         /* CalcIdent */
         {kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther,
          kCalcOther, kCalcOther, kCalcOther, kCalcOther, kCalcOther}}};

static CalculationResultCategory DetermineCategory(
    const CSSMathExpressionNode& left_side,
    const CSSMathExpressionNode& right_side,
    CSSMathOperator op) {
  CalculationResultCategory left_category = left_side.Category();
  CalculationResultCategory right_category = right_side.Category();

  if (left_category == kCalcOther || right_category == kCalcOther) {
    return kCalcOther;
  }

  if (left_category == kCalcIntrinsicSize ||
      right_category == kCalcIntrinsicSize) {
    return kCalcOther;
  }

  switch (op) {
    case CSSMathOperator::kAdd:
    case CSSMathOperator::kSubtract:
      return kAddSubtractResult[left_category][right_category];
    case CSSMathOperator::kMultiply:
      if (left_category != kCalcNumber && right_category != kCalcNumber) {
        return kCalcOther;
      }
      return left_category == kCalcNumber ? right_category : left_category;
    case CSSMathOperator::kDivide:
      if (right_category != kCalcNumber) {
        return kCalcOther;
      }
      return left_category;
    default:
      break;
  }

  NOTREACHED();
}

static CalculationResultCategory DetermineComparisonCategory(
    const CSSMathExpressionOperation::Operands& operands) {
  DCHECK(!operands.empty());

  bool is_first = true;
  CalculationResultCategory category = kCalcOther;
  for (const CSSMathExpressionNode* operand : operands) {
    if (is_first) {
      category = operand->Category();
    } else {
      category = kAddSubtractResult[category][operand->Category()];
    }

    is_first = false;
    if (category == kCalcOther) {
      break;
    }
  }

  return category;
}

static CalculationResultCategory DetermineCalcSizeCategory(
    const CSSMathExpressionNode& left_side,
    const CSSMathExpressionNode& right_side,
    CSSMathOperator op) {
  CalculationResultCategory basis_category = left_side.Category();
  CalculationResultCategory calculation_category = right_side.Category();

  if ((basis_category == kCalcLength || basis_category == kCalcPercent ||
       basis_category == kCalcLengthFunction ||
       basis_category == kCalcIntrinsicSize) &&
      (calculation_category == kCalcLength ||
       calculation_category == kCalcPercent ||
       calculation_category == kCalcLengthFunction)) {
    return kCalcIntrinsicSize;
  }
  return kCalcOther;
}

// ------ Start of CSSMathExpressionIdentifierLiteral member functions -

CSSMathExpressionIdentifierLiteral::CSSMathExpressionIdentifierLiteral(
    AtomicString identifier)
    : CSSMathExpressionNode(UnitCategory(CSSPrimitiveValue::UnitType::kIdent),
                            false /* has_comparisons*/,
                            false /* has_anchor_unctions*/,
                            false /* needs_tree_scope_population*/),
      identifier_(std::move(identifier)) {}

scoped_refptr<const CalculationExpressionNode>
CSSMathExpressionIdentifierLiteral::ToCalculationExpression(
    const CSSLengthResolver&) const {
  return base::MakeRefCounted<CalculationExpressionIdentifierNode>(identifier_);
}

// ------ End of CSSMathExpressionIdentifierLiteral member functions ----

// ------ Start of CSSMathExpressionKeywordLiteral member functions -

namespace {

CalculationExpressionSizingKeywordNode::Keyword CSSValueIDToSizingKeyword(
    CSSValueID keyword) {
  // The keywords supported here should be the ones supported in
  // css_parsing_utils::ValidWidthOrHeightKeyword plus 'any', 'auto' and 'size'.

  // This should also match SizingKeywordToCSSValueID below.
  switch (keyword) {
#define KEYWORD_CASE(kw) \
  case CSSValueID::kw:   \
    return CalculationExpressionSizingKeywordNode::Keyword::kw;

    KEYWORD_CASE(kAny)
    KEYWORD_CASE(kSize)
    KEYWORD_CASE(kAuto)
    KEYWORD_CASE(kContent)
    KEYWORD_CASE(kMinContent)
    KEYWORD_CASE(kWebkitMinContent)
    KEYWORD_CASE(kMaxContent)
    KEYWORD_CASE(kWebkitMaxContent)
    KEYWORD_CASE(kFitContent)
    KEYWORD_CASE(kWebkitFitContent)
    KEYWORD_CASE(kStretch)
    KEYWORD_CASE(kWebkitFillAvailable)

#undef KEYWORD_CASE

    default:
      break;
  }

  NOTREACHED();
}

CSSValueID SizingKeywordToCSSValueID(
    CalculationExpressionSizingKeywordNode::Keyword keyword) {
  // This should match CSSValueIDToSizingKeyword above.
  switch (keyword) {
#define KEYWORD_CASE(kw)                                    \
  case CalculationExpressionSizingKeywordNode::Keyword::kw: \
    return CSSValueID::kw;

    KEYWORD_CASE(kAny)
    KEYWORD_CASE(kSize)
    KEYWORD_CASE(kAuto)
    KEYWORD_CASE(kContent)
    KEYWORD_CASE(kMinContent)
    KEYWORD_CASE(kWebkitMinContent)
    KEYWORD_CASE(kMaxContent)
    KEYWORD_CASE(kWebkitMaxContent)
    KEYWORD_CASE(kFitContent)
    KEYWORD_CASE(kWebkitFitContent)
    KEYWORD_CASE(kStretch)
    KEYWORD_CASE(kWebkitFillAvailable)

#undef KEYWORD_CASE
  }

  NOTREACHED();
}

CalculationResultCategory DetermineKeywordCategory(
    CSSValueID keyword,
    CSSMathExpressionKeywordLiteral::Context context) {
  switch (context) {
    case CSSMathExpressionKeywordLiteral::Context::kMediaProgress:
      return kCalcLength;
    case CSSMathExpressionKeywordLiteral::Context::kCalcSize:
      return kCalcLengthFunction;
    case CSSMathExpressionKeywordLiteral::Context::kColorChannel:
      return kCalcNumber;
  };
}

}  // namespace

CSSMathExpressionKeywordLiteral::CSSMathExpressionKeywordLiteral(
    CSSValueID keyword,
    Context context)
    : CSSMathExpressionNode(DetermineKeywordCategory(keyword, context),
                            false /* has_comparisons*/,
                            false /* has_anchor_unctions*/,
                            false /* needs_tree_scope_population*/),
      keyword_(keyword),
      context_(context) {}

scoped_refptr<const CalculationExpressionNode>
CSSMathExpressionKeywordLiteral::ToCalculationExpression(
    const CSSLengthResolver& length_resolver) const {
  switch (context_) {
    case CSSMathExpressionKeywordLiteral::Context::kMediaProgress: {
      switch (keyword_) {
        case CSSValueID::kWidth:
          return base::MakeRefCounted<
              CalculationExpressionPixelsAndPercentNode>(
              PixelsAndPercent(length_resolver.ViewportWidth()));
        case CSSValueID::kHeight:
          return base::MakeRefCounted<
              CalculationExpressionPixelsAndPercentNode>(
              PixelsAndPercent(length_resolver.ViewportHeight()));
        default:
          NOTREACHED();
      }
    }
    case CSSMathExpressionKeywordLiteral::Context::kCalcSize:
      return base::MakeRefCounted<CalculationExpressionSizingKeywordNode>(
          CSSValueIDToSizingKeyword(keyword_));
    case CSSMathExpressionKeywordLiteral::Context::kColorChannel:
      return base::MakeRefCounted<CalculationExpressionColorChannelKeywordNode>(
          CSSValueIDToColorChannelKeyword(keyword_));
  };
}

double CSSMathExpressionKeywordLiteral::ComputeDouble(
    const CSSLengthResolver& length_resolver) const {
  switch (context_) {
    case CSSMathExpressionKeywordLiteral::Context::kMediaProgress: {
      switch (keyword_) {
        case CSSValueID::kWidth:
          return length_resolver.ViewportWidth();
        case CSSValueID::kHeight:
          return length_resolver.ViewportHeight();
        default:
          NOTREACHED();
      }
    }
    case CSSMathExpressionKeywordLiteral::Context::kCalcSize:
    case CSSMathExpressionKeywordLiteral::Context::kColorChannel:
      NOTREACHED();
  };
}

std::optional<PixelsAndPercent>
CSSMathExpressionKeywordLiteral::ToPixelsAndPercent(
    const CSSLengthResolver& length_resolver) const {
  switch (context_) {
    case CSSMathExpressionKeywordLiteral::Context::kMediaProgress:
      switch (keyword_) {
        case CSSValueID::kWidth:
          return PixelsAndPercent(length_resolver.ViewportWidth());
        case CSSValueID::kHeight:
          return PixelsAndPercent(length_resolver.ViewportHeight());
        default:
          NOTREACHED();
      }
    case CSSMathExpressionKeywordLiteral::Context::kCalcSize:
    case CSSMathExpressionKeywordLiteral::Context::kColorChannel:
      return std::nullopt;
  }
}

// ------ End of CSSMathExpressionKeywordLiteral member functions ----

// ------ Start of CSSMathExpressionOperation member functions ------

bool CSSMathExpressionOperation::AllOperandsAreNumeric() const {
  return std::all_of(
      operands_.begin(), operands_.end(),
      [](const CSSMathExpressionNode* op) { return op->IsNumericLiteral(); });
}

// static
CSSMathExpressionNode* CSSMathExpressionOperation::CreateArithmeticOperation(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side,
    CSSMathOperator op) {
  DCHECK_NE(left_side->Category(), kCalcOther);
  DCHECK_NE(right_side->Category(), kCalcOther);

  CalculationResultCategory new_category =
      DetermineCategory(*left_side, *right_side, op);
  if (new_category == kCalcOther) {
    return nullptr;
  }

  return MakeGarbageCollected<CSSMathExpressionOperation>(left_side, right_side,
                                                          op, new_category);
}

// static
CSSMathExpressionNode* CSSMathExpressionOperation::CreateCalcSizeOperation(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side) {
  DCHECK_NE(left_side->Category(), kCalcOther);
  DCHECK_NE(right_side->Category(), kCalcOther);

  const CSSMathOperator op = CSSMathOperator::kCalcSize;
  CalculationResultCategory new_category =
      DetermineCalcSizeCategory(*left_side, *right_side, op);
  if (new_category == kCalcOther) {
    return nullptr;
  }

  return MakeGarbageCollected<CSSMathExpressionOperation>(left_side, right_side,
                                                          op, new_category);
}

// static
CSSMathExpressionNode* CSSMathExpressionOperation::CreateComparisonFunction(
    Operands&& operands,
    CSSMathOperator op) {
  DCHECK(op == CSSMathOperator::kMin || op == CSSMathOperator::kMax ||
         op == CSSMathOperator::kClamp);

  CalculationResultCategory category = DetermineComparisonCategory(operands);
  if (category == kCalcOther) {
    return nullptr;
  }

  return MakeGarbageCollected<CSSMathExpressionOperation>(
      category, std::move(operands), op);
}

// static
CSSMathExpressionNode*
CSSMathExpressionOperation::CreateComparisonFunctionSimplified(
    Operands&& operands,
    CSSMathOperator op) {
  DCHECK(op == CSSMathOperator::kMin || op == CSSMathOperator::kMax ||
         op == CSSMathOperator::kClamp);

  CalculationResultCategory category = DetermineComparisonCategory(operands);
  if (category == kCalcOther) {
    return nullptr;
  }

  if (CanEagerlySimplify(operands)) {
    Vector<double> canonical_values;
    canonical_values.reserve(operands.size());
    for (const CSSMathExpressionNode* operand : operands) {
      std::optional<double> canonical_value =
          operand->ComputeValueInCanonicalUnit();

      DCHECK(canonical_value.has_value());

      canonical_values.push_back(canonical_value.value());
    }

    CSSPrimitiveValue::UnitType canonical_unit =
        CSSPrimitiveValue::CanonicalUnit(operands.front()->ResolvedUnitType());

    return CSSMathExpressionNumericLiteral::Create(
        EvaluateOperator(canonical_values, op), canonical_unit);
  }

  if (operands.size() == 1) {
    return operands.front()->Copy();
  }

  return MakeGarbageCollected<CSSMathExpressionOperation>(
      category, std::move(operands), op);
}

// Helper function for parsing number value
static double ValueAsNumber(const CSSMathExpressionNode* node, bool& error) {
  if (node->Category() == kCalcNumber) {
    return node->DoubleValue();
  }
  error = true;
  return 0;
}

static bool SupportedCategoryForAtan2(
    const CalculationResultCategory category) {
  switch (category) {
    case kCalcNumber:
    case kCalcLength:
    case kCalcPercent:
    case kCalcTime:
    case kCalcFrequency:
    case kCalcAngle:
      return true;
    default:
      return false;
  }
}

static bool IsRelativeLength(CSSPrimitiveValue::UnitType type) {
  return CSSPrimitiveValue::IsRelativeUnit(type) &&
         CSSPrimitiveValue::IsLength(type);
}

static double ResolveAtan2(const CSSMathExpressionNode* y_node,
                           const CSSMathExpressionNode* x_node,
                           bool& error) {
  const CalculationResultCategory category = y_node->Category();
  if (category != x_node->Category() || !SupportedCategoryForAtan2(category)) {
    error = true;
    return 0;
  }
  CSSPrimitiveValue::UnitType y_type = y_node->ResolvedUnitType();
  CSSPrimitiveValue::UnitType x_type = x_node->ResolvedUnitType();

  // TODO(crbug.com/1392594): We ignore parameters in complex relative units
  // (e.g., 1rem + 1px) until they can be supported.
  if (y_type == CSSPrimitiveValue::UnitType::kUnknown ||
      x_type == CSSPrimitiveValue::UnitType::kUnknown) {
    error = true;
    return 0;
  }

  if (IsRelativeLength(y_type) || IsRelativeLength(x_type)) {
    // TODO(crbug.com/1392594): Relative length units are currently hard
    // to resolve. We ignore the units for now, so that
    // we can at least support the case where both operands have the same unit.
    double y = y_node->DoubleValue();
    double x = x_node->DoubleValue();
    return std::atan2(y, x);
  }
  auto y = y_node->ComputeValueInCanonicalUnit();
  auto x = x_node->ComputeValueInCanonicalUnit();
  return std::atan2(y.value(), x.value());
}

// Helper function for parsing trigonometric functions' parameter
static double ValueAsDegrees(const CSSMathExpressionNode* node, bool& error) {
  if (node->Category() == kCalcAngle) {
    return node->ComputeValueInCanonicalUnit().value();
  }
  return Rad2deg(ValueAsNumber(node, error));
}

static bool CanonicalizeRoundArguments(
    CSSMathExpressionOperation::Operands& nodes) {
  if (nodes.size() == 2) {
    return true;
  }
  // If the type of A matches <number>, then B may be omitted, and defaults to
  // 1; omitting B is otherwise invalid.
  // (https://drafts.csswg.org/css-values-4/#round-func)
  if (nodes.size() == 1 &&
      nodes[0]->Category() == CalculationResultCategory::kCalcNumber) {
    // Add B=1 to get the function on canonical form.
    nodes.push_back(CSSMathExpressionNumericLiteral::Create(
        1, CSSPrimitiveValue::UnitType::kNumber));
    return true;
  }
  return false;
}

static bool ShouldSerializeRoundingStep(
    const CSSMathExpressionOperation::Operands& operands) {
  // Omit the step (B) operand to round(...) if the type of A is <number> and
  // the step is the literal 1.
  if (operands[0]->Category() != CalculationResultCategory::kCalcNumber) {
    return true;
  }
  auto* literal = DynamicTo<CSSMathExpressionNumericLiteral>(*operands[1]);
  if (!literal) {
    return true;
  }
  const CSSNumericLiteralValue& literal_value = literal->GetValue();
  if (!literal_value.IsNumber() || literal_value.DoubleValue() != 1) {
    return true;
  }
  return false;
}

CSSMathExpressionNode*
CSSMathExpressionOperation::CreateTrigonometricFunctionSimplified(
    Operands&& operands,
    CSSValueID function_id) {
  double value;
  auto unit_type = CSSPrimitiveValue::UnitType::kUnknown;
  bool error = false;
  switch (function_id) {
    case CSSValueID::kSin: {
      DCHECK_EQ(operands.size(), 1u);
      unit_type = CSSPrimitiveValue::UnitType::kNumber;
      value = gfx::SinCosDegrees(ValueAsDegrees(operands[0], error)).sin;
      break;
    }
    case CSSValueID::kCos: {
      DCHECK_EQ(operands.size(), 1u);
      unit_type = CSSPrimitiveValue::UnitType::kNumber;
      value = gfx::SinCosDegrees(ValueAsDegrees(operands[0], error)).cos;
      break;
    }
    case CSSValueID::kTan: {
      DCHECK_EQ(operands.size(), 1u);
      unit_type = CSSPrimitiveValue::UnitType::kNumber;
      value = TanDegrees(ValueAsDegrees(operands[0], error));
      break;
    }
    case CSSValueID::kAsin: {
      DCHECK_EQ(operands.size(), 1u);
      unit_type = CSSPrimitiveValue::UnitType::kDegrees;
      value = Rad2deg(std::asin(ValueAsNumber(operands[0], error)));
      DCHECK(value >= -90 && value <= 90 || std::isnan(value));
      break;
    }
    case CSSValueID::kAcos: {
      DCHECK_EQ(operands.size(), 1u);
      unit_type = CSSPrimitiveValue::UnitType::kDegrees;
      value = Rad2deg(std::acos(ValueAsNumber(operands[0], error)));
      DCHECK(value >= 0 && value <= 180 || std::isnan(value));
      break;
    }
    case CSSValueID::kAtan: {
      DCHECK_EQ(operands.size(), 1u);
      unit_type = CSSPrimitiveValue::UnitType::kDegrees;
      value = Rad2deg(std::atan(ValueAsNumber(operands[0], error)));
      DCHECK(value >= -90 && value <= 90 || std::isnan(value));
      break;
    }
    case CSSValueID::kAtan2: {
      DCHECK_EQ(operands.size(), 2u);
      unit_type = CSSPrimitiveValue::UnitType::kDegrees;
      value = Rad2deg(ResolveAtan2(operands[0], operands[1], error));
      DCHECK(value >= -180 && value <= 180 || std::isnan(value));
      break;
    }
    default:
      return nullptr;
  }

  if (error) {
    return nullptr;
  }

  DCHECK_NE(unit_type, CSSPrimitiveValue::UnitType::kUnknown);
  return CSSMathExpressionNumericLiteral::Create(value, unit_type);
}

CSSMathExpressionNode* CSSMathExpressionOperation::CreateSteppedValueFunction(
    Operands&& operands,
    CSSMathOperator op) {
  if (!RuntimeEnabledFeatures::CSSSteppedValueFunctionsEnabled()) {
    return nullptr;
  }
  DCHECK_EQ(operands.size(), 2u);
  if (operands[0]->Category() == kCalcOther ||
      operands[1]->Category() == kCalcOther) {
    return nullptr;
  }
  CalculationResultCategory category =
      kAddSubtractResult[operands[0]->Category()][operands[1]->Category()];
  if (category == kCalcOther) {
    return nullptr;
  }
  if (CanEagerlySimplify(operands)) {
    std::optional<double> a = operands[0]->ComputeValueInCanonicalUnit();
    std::optional<double> b = operands[1]->ComputeValueInCanonicalUnit();
    DCHECK(a.has_value());
    DCHECK(b.has_value());
    double value = EvaluateSteppedValueFunction(op, a.value(), b.value());
    return CSSMathExpressionNumericLiteral::Create(
        value,
        CSSPrimitiveValue::CanonicalUnit(operands.front()->ResolvedUnitType()));
  }
  return MakeGarbageCollected<CSSMathExpressionOperation>(
      category, std::move(operands), op);
}

// static
CSSMathExpressionNode* CSSMathExpressionOperation::CreateExponentialFunction(
    Operands&& operands,
    CSSValueID function_id) {
  if (!RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled()) {
    return nullptr;
  }

  double value = 0;
  bool error = false;
  auto unit_type = CSSPrimitiveValue::UnitType::kNumber;
  switch (function_id) {
    case CSSValueID::kPow: {
      DCHECK_EQ(operands.size(), 2u);
      double a = ValueAsNumber(operands[0], error);
      double b = ValueAsNumber(operands[1], error);
      value = std::pow(a, b);
      break;
    }
    case CSSValueID::kSqrt: {
      DCHECK_EQ(operands.size(), 1u);
      double a = ValueAsNumber(operands[0], error);
      value = std::sqrt(a);
      break;
    }
    case CSSValueID::kHypot: {
      DCHECK_GE(operands.size(), 1u);
      CalculationResultCategory category =
          DetermineComparisonCategory(operands);
      if (category == kCalcOther) {
        return nullptr;
      }
      if (CanEagerlySimplify(operands)) {
        for (const CSSMathExpressionNode* operand : operands) {
          std::optional<double> a = operand->ComputeValueInCanonicalUnit();
          DCHECK(a.has_value());
          value = std::hypot(value, a.value());
        }
        unit_type = CSSPrimitiveValue::CanonicalUnit(
            operands.front()->ResolvedUnitType());
      } else {
        return MakeGarbageCollected<CSSMathExpressionOperation>(
            category, std::move(operands), CSSMathOperator::kHypot);
      }
      break;
    }
    case CSSValueID::kLog: {
      DCHECK_GE(operands.size(), 1u);
      DCHECK_LE(operands.size(), 2u);
      double a = ValueAsNumber(operands[0], error);
      if (operands.size() == 2) {
        double b = ValueAsNumber(operands[1], error);
        value = std::log2(a) / std::log2(b);
      } else {
        value = std::log(a);
      }
      break;
    }
    case CSSValueID::kExp: {
      DCHECK_EQ(operands.size(), 1u);
      double a = ValueAsNumber(operands[0], error);
      value = std::exp(a);
      break;
    }
    default:
      return nullptr;
  }
  if (error) {
    return nullptr;
  }

  DCHECK_NE(unit_type, CSSPrimitiveValue::UnitType::kUnknown);
  return CSSMathExpressionNumericLiteral::Create(value, unit_type);
}

CSSMathExpressionNode* CSSMathExpressionOperation::CreateSignRelatedFunction(
    Operands&& operands,
    CSSValueID function_id) {
  if (!RuntimeEnabledFeatures::CSSSignRelatedFunctionsEnabled()) {
    return nullptr;
  }

  const CSSMathExpressionNode* operand = operands.front();

  if (operand->Category() == kCalcIntrinsicSize) {
    return nullptr;
  }

  switch (function_id) {
    case CSSValueID::kAbs: {
      if (CanEagerlySimplify(operand)) {
        const std::optional<double> opt =
            operand->ComputeValueInCanonicalUnit();
        DCHECK(opt.has_value());
        return CSSMathExpressionNumericLiteral::Create(
            std::abs(opt.value()), operand->ResolvedUnitType());
      }
      return MakeGarbageCollected<CSSMathExpressionOperation>(
          operand->Category(), std::move(operands), CSSMathOperator::kAbs);
    }
    case CSSValueID::kSign: {
      if (CanEagerlySimplify(operand)) {
        const std::optional<double> opt =
            operand->ComputeValueInCanonicalUnit();
        DCHECK(opt.has_value());
        const double value = opt.value();
        const double signum =
            (value == 0 || std::isnan(value)) ? value : ((value > 0) ? 1 : -1);
        return CSSMathExpressionNumericLiteral::Create(
            signum, CSSPrimitiveValue::UnitType::kNumber);
      }
      return MakeGarbageCollected<CSSMathExpressionOperation>(
          kCalcNumber, std::move(operands), CSSMathOperator::kSign);
    }
    default:
      NOTREACHED();
  }
}

const CSSMathExpressionNode*
CSSMathExpressionOperation::ConvertLiteralsFromPercentageToNumber() const {
  Operands ops;
  ops.reserve(operands_.size());
  for (const CSSMathExpressionNode* op : operands_) {
    ops.push_back(op->ConvertLiteralsFromPercentageToNumber());
  }
  CalculationResultCategory category =
      category_ == kCalcPercent ? kCalcNumber : category_;
  return MakeGarbageCollected<CSSMathExpressionOperation>(
      category, std::move(ops), operator_);
}

namespace {

inline const CSSMathExpressionOperation* DynamicToCalcSize(
    const CSSMathExpressionNode* node) {
  const CSSMathExpressionOperation* operation =
      DynamicTo<CSSMathExpressionOperation>(node);
  if (!operation || !operation->IsCalcSize()) {
    return nullptr;
  }
  return operation;
}

inline bool CanArithmeticOperationBeSimplified(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side) {
  return left_side->IsNumericLiteral() && right_side->IsNumericLiteral();
}

}  // namespace

// static
CSSMathExpressionNode*
CSSMathExpressionOperation::CreateArithmeticOperationSimplified(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side,
    CSSMathOperator op) {
  DCHECK(op == CSSMathOperator::kAdd || op == CSSMathOperator::kSubtract ||
         op == CSSMathOperator::kMultiply || op == CSSMathOperator::kDivide);
```