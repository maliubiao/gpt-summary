Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They also want to understand its relationship to web technologies (HTML, CSS, Javascript), common errors, debugging tips, and specifically, the function of *this* particular part of the code within the larger file.

To address this, I will:

1. **Identify the core purpose:** The code primarily deals with representing and manipulating CSS math expressions within the Blink rendering engine. It focuses on how these expressions are stored, represented as text, compared, and resolved to specific units.
2. **Relate to web technologies:**
    - **CSS:** This is the most direct relationship. The code parses and evaluates CSS `calc()`, `min()`, `max()`, `clamp()`, and other math functions. It handles different units and performs calculations. The new anchor positioning functions (`anchor()`, `anchor-size()`) are also handled.
    - **HTML:** While not directly involved in HTML parsing, the *results* of these CSS math expressions (like computed lengths) directly affect the layout and rendering of HTML elements.
    - **Javascript:** Javascript can manipulate CSS properties, including those using math functions. The `CSSOM` (CSS Object Model) provides an interface for Javascript to interact with CSS, and this code contributes to how those interactions are handled internally.
3. **Analyze specific functionalities within the snippet:**
    - **`CustomCSSText()` methods:** Focus on how different math operations and functions are serialized back into CSS string representation. Pay attention to parenthesis usage for correct operator precedence.
    - **`operator==()`:** Explain how the equality of two math expression nodes is determined, which involves comparing the operator and operands.
    - **`ResolvedUnitType()`:**  Describe how the resulting unit type of a math expression is determined based on the operators and the units of the operands.
    - **`EvaluateOperator()`:** Summarize the logic for actually performing the math operations.
    - **`CSSMathExpressionAnchorQuery` related code:** Explain the handling of the new anchor positioning functions and how they are evaluated and represented.
4. **Infer logical flow and error scenarios:**
    - **Input:**  Consider what kind of CSS input would lead to the execution of this code.
    - **Output:** What is the result of the code's execution?
    - **Errors:** Think about common mistakes a web developer might make when using CSS math functions (e.g., incompatible units, division by zero). Although the C++ code itself won't have the *user* make errors directly, it's designed to handle and potentially flag such invalid CSS.
5. **Debugging clues:** Suggest how a developer might end up looking at this specific part of the Blink code. This usually involves inspecting how computed styles are being calculated or investigating issues with specific CSS math functions.
6. **Focus on the provided snippet:** Given that this is part 4 of 6, I should focus on the specific functionality within this chunk of code, which seems heavily related to the serialization of math expressions back to CSS strings and the handling of the `CSSMathExpressionOperation` and `CSSMathExpressionAnchorQuery` classes.
这是 Chromium Blink 引擎源代码文件 `blink/renderer/core/css/css_math_expression_node.cc` 的第 4 部分，主要功能是 **将 CSS 数学表达式节点转换为 CSS 文本表示，并处理 `CSSMathExpressionOperation` 和 `CSSMathExpressionAnchorQuery` 这两种特定类型的节点。**

**功能归纳:**

* **`CSSMathExpressionOperation::CustomCSSText()`:**  负责将 `CSSMathExpressionOperation` 节点（代表一个数学运算，如加、减、乘、除、min、max 等）转换回其对应的 CSS 文本表示形式。这包括：
    * 处理不同运算符的输出格式，例如 `+`, `-`, `*`, `/`, `min()`, `max()` 等。
    * 根据运算符优先级和结合性，决定是否需要添加括号以确保运算顺序正确。例如，在乘法或除法运算中，如果其中一个操作数是未简化的加法或减法表达式，则需要添加括号。
    * 特殊处理 `round()` 函数，包括对舍入策略和步长的序列化。
    * 特殊处理 `progress()`, `media-progress()`, `container-progress()` 等进度相关函数。
* **`CSSMathExpressionOperation::operator==()`:**  用于比较两个 `CSSMathExpressionOperation` 节点是否相等。它会比较运算符类型和所有操作数是否都相等。
* **`CSSMathExpressionOperation::ResolvedUnitType()`:**  确定 `CSSMathExpressionOperation` 节点解析后的单位类型。这取决于运算符和操作数的单位类型。例如：
    * 两个相同单位的长度相加，结果仍然是该单位的长度。
    * 一个长度乘以一个数字，结果是该单位的长度。
    * `min()` 或 `max()` 函数的结果单位类型与其所有参数的共同单位类型相同。
* **`CSSMathExpressionOperation::EvaluateOperator()`:**  静态方法，用于实际执行数学运算。它接收一个包含操作数的 double 向量和一个运算符枚举，并返回运算结果。该方法考虑了 NaN 值的处理，并对不同的运算符实现了相应的计算逻辑。
* **`CSSMathExpressionContainerFeature`:**  处理容器查询相关的特性，例如获取容器的宽度或高度。
* **`CSSMathExpressionAnchorQuery`:**  处理 CSS 锚点定位相关的新增函数 `anchor()` 和 `anchor-size()`。
    * **`CSSMathExpressionAnchorQuery::CustomCSSText()`:**  将 `anchor()` 或 `anchor-size()` 函数转换回其 CSS 文本表示。
    * **`CSSMathExpressionAnchorQuery::operator==()`:**  比较两个 `CSSMathExpressionAnchorQuery` 节点是否相等。
    * **`CSSMathExpressionAnchorQuery::ToCalculationExpression()`:** 将锚点查询转换为 `CalculationExpressionNode`，用于后续的计算。
    * **`CSSMathExpressionAnchorQuery::EvaluateQuery()`:**  实际执行锚点查询的评估逻辑。
    * **`CSSMathExpressionAnchorQuery::ToQuery()`:**  将 `CSSMathExpressionAnchorQuery` 转换为 `AnchorQuery` 对象，方便评估。
    * **`CSSMathExpressionAnchorQuery::TransformAnchors()`:**  在布局过程中，根据书写模式和变换策略调整锚点的位置。
    * **`CSSMathExpressionAnchorQuery::HasInvalidAnchorFunctions()`:**  检查锚点函数是否有效。如果锚点找不到目标并且没有提供回退值，则该函数是无效的。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这是最直接的关系。
    * **例子:** 当 CSS 中使用 `width: calc(100% - 20px);` 时，Blink 引擎会解析这个表达式并创建 `CSSMathExpressionOperation` 节点来表示减法运算，其操作数分别是 `100%` 和 `20px`。 `CustomCSSText()` 可以将这个内部表示转换回 CSS 字符串 `"calc(100% - 20px)"`。
    * **例子:** 使用 `min(10px, 20px)` 时，会创建 `CSSMathExpressionOperation` 节点，`EvaluateOperator()` 方法会计算出结果为 `10px`。
    * **例子:** 使用新的锚点定位 `anchor(--my-anchor top, 10px)` 时，会创建 `CSSMathExpressionAnchorQuery` 节点。`CustomCSSText()` 会将其序列化为 `"anchor(--my-anchor top, 10px)"`。

* **HTML:**  CSS 样式应用于 HTML 元素。
    * **例子:**  如果一个 `<div>` 元素的 CSS 样式中使用了 `width: calc(50vw + 100px);`，那么 Blink 引擎会计算这个表达式，最终确定 `<div>` 的宽度，并将其渲染到 HTML 页面上。

* **Javascript:** Javascript 可以通过 CSSOM (CSS Object Model) 操作 CSS 样式。
    * **例子:** Javascript 可以获取一个元素的计算样式 `getComputedStyle(element).width`，如果这个宽度是通过 `calc()` 计算出来的，那么 Blink 引擎内部会用到这里讨论的代码来表示和计算这个值。
    * **例子:** Javascript 可以设置元素的样式 `element.style.width = 'calc(100% / 3)';`，Blink 引擎会解析这个新的 CSS 值，并创建相应的数学表达式节点。

**逻辑推理、假设输入与输出:**

**假设输入 (CSS):** `width: min(10px + 5px, 30px - 2px);`

**内部处理:**

1. **解析器:** CSS 解析器会识别出 `min()` 函数，并递归解析其参数。
2. **创建节点:**  会创建两个 `CSSMathExpressionOperation` 节点，分别代表 `10px + 5px` 和 `30px - 2px`，以及一个 `CSSMathExpressionOperation` 节点代表 `min()` 运算。
3. **`CustomCSSText()` (可能调用):** 如果需要将这个内部表示转换回 CSS 字符串，最终会生成 `"min(calc(10px + 5px), calc(30px - 2px))"` 或简化后的 `"min(15px, 28px)"`。
4. **`EvaluateOperator()`:** 当需要计算这个宽度时，会先计算两个加减法表达式的结果 (15px 和 28px)，然后调用 `EvaluateOperator()` 处理 `min` 运算，输入操作数为 `[15, 28]`，运算符为 `kMin`，输出结果为 `15` (单位为像素)。
5. **`ResolvedUnitType()`:**  `min()` 运算的 `ResolvedUnitType()` 会确定最终结果的单位类型为 `px`，因为其参数都是 `px` 单位的长度。

**用户或编程常见的使用错误及举例说明:**

* **单位不兼容:** 在 `calc()` 中进行单位不兼容的运算。
    * **例子 (CSS):** `width: calc(100px + 50%);`  浏览器会尝试解析，但由于 `px` 和 `%` 是不同类型的单位，无法直接相加，可能会导致解析错误或使用默认值。`ResolvedUnitType()` 可能会返回 `kUnknown`。
* **除零错误:** 在 `calc()` 中进行除零运算。
    * **例子 (CSS):** `width: calc(100px / 0);`  `EvaluateOperator()` 在执行除法运算时会遇到除零错误，通常会返回 `NaN`。
* **`min()` 或 `max()` 函数参数类型不一致:**
    * **例子 (CSS):** `width: min(10px, 2em);`  虽然是长度单位，但单位类型不同，可能导致解析错误或计算结果不符合预期。`ResolvedUnitType()` 可能会返回 `kUnknown`。
* **错误的锚点函数使用:**
    * **例子 (CSS):** `left: anchor(top);`  缺少必要的锚点元素信息，会导致 `EvaluateQuery()` 无法找到锚点，如果未提供回退值，则 `HasInvalidAnchorFunctions()` 会返回 true。

**用户操作如何一步步到达这里 (调试线索):**

1. **开发者编写包含 CSS 数学函数的样式:** 用户在 CSS 文件或 `<style>` 标签中使用了 `calc()`, `min()`, `max()`, `anchor()` 等函数。
2. **浏览器解析 HTML 和 CSS:** 浏览器开始解析 HTML 文档和关联的 CSS 文件。
3. **CSSOM 构建:**  Blink 引擎的 CSS 解析器会将 CSS 规则转换为内部的 CSSOM 结构，其中数学表达式会被创建为 `CSSMathExpressionNode` 的子类对象。
4. **样式计算:**  当浏览器需要计算元素的最终样式时，会遍历 CSSOM 树，并计算各种样式属性的值。对于包含数学函数的属性，会调用 `CSSMathExpressionNode` 及其子类的相关方法进行计算，例如 `EvaluateOperator()`。
5. **布局和渲染:**  计算出的样式值（例如元素的宽度、高度、位置）会被用于布局和渲染阶段，将元素绘制到屏幕上。

**调试线索:**

* **在开发者工具中检查元素的计算样式:**  查看元素的 "Computed" 选项卡，可以观察到经过计算后的属性值。如果涉及到 `calc()` 等函数，可以看到其最终的计算结果。
* **使用 "Sources" 面板设置断点:**  可以在 `blink/renderer/core/css/css_math_expression_node.cc` 文件的相关方法（例如 `EvaluateOperator()`, `CustomCSSText()`）中设置断点，观察代码的执行流程和变量的值，从而理解数学表达式的计算过程。
* **查看控制台错误信息:**  如果 CSS 数学表达式存在语法错误或计算错误，浏览器可能会在控制台中输出相关的警告或错误信息。
* **检查布局问题:** 如果页面布局出现异常，例如元素尺寸不正确，可以怀疑是相关的 CSS 数学表达式计算错误，并着重调试相关的代码。

总而言之，这部分代码的核心职责是将 CSS 数学表达式在 Blink 引擎内部的表示形式与外部的 CSS 文本形式之间进行转换，并负责执行实际的数学计算，同时处理新的锚点定位功能。它是 CSS 引擎的重要组成部分，确保浏览器能够正确理解和应用包含数学表达式的 CSS 样式。

Prompt: 
```
这是目录为blink/renderer/core/css/css_math_expression_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
rands[0]->CustomCSSText());
      if (left_side_needs_parentheses) {
        result.Append(')');
      }

      result.Append(' ');
      result.Append(ToString(op));
      result.Append(' ');

      // After all the simplifications we only need parentheses here for the
      // cases like: lhs [* or /] (rhs as unsimplified sum/sub)
      const bool right_side_needs_parentheses =
          IsMultiplyOrDivide() && operands.back()->IsOperation() &&
          To<CSSMathExpressionOperation>(operands.back().Get())
              ->IsAddOrSubtract();
      if (right_side_needs_parentheses) {
        result.Append('(');
      }
      result.Append(operands[1]->CustomCSSText());
      if (right_side_needs_parentheses) {
        result.Append(')');
      }

      return result.ReleaseString();
    }
    case CSSMathOperator::kMin:
    case CSSMathOperator::kMax:
    case CSSMathOperator::kClamp:
    case CSSMathOperator::kMod:
    case CSSMathOperator::kRem:
    case CSSMathOperator::kHypot:
    case CSSMathOperator::kAbs:
    case CSSMathOperator::kSign:
    case CSSMathOperator::kCalcSize: {
      StringBuilder result;
      result.Append(ToString(operator_));
      result.Append('(');
      result.Append(operands_.front()->CustomCSSText());
      for (const CSSMathExpressionNode* operand : SecondToLastOperands()) {
        result.Append(", ");
        result.Append(operand->CustomCSSText());
      }
      result.Append(')');

      return result.ReleaseString();
    }
    case CSSMathOperator::kRoundNearest:
    case CSSMathOperator::kRoundUp:
    case CSSMathOperator::kRoundDown:
    case CSSMathOperator::kRoundToZero: {
      StringBuilder result;
      result.Append(ToString(operator_));
      result.Append('(');
      if (operator_ != CSSMathOperator::kRoundNearest) {
        result.Append(ToRoundingStrategyString(operator_));
        result.Append(", ");
      }
      result.Append(operands_[0]->CustomCSSText());
      if (ShouldSerializeRoundingStep(operands_)) {
        result.Append(", ");
        result.Append(operands_[1]->CustomCSSText());
      }
      result.Append(')');

      return result.ReleaseString();
    }
    case CSSMathOperator::kProgress:
    case CSSMathOperator::kMediaProgress:
    case CSSMathOperator::kContainerProgress: {
      CHECK_EQ(operands_.size(), 3u);
      StringBuilder result;
      result.Append(ToString(operator_));
      result.Append('(');
      result.Append(operands_.front()->CustomCSSText());
      result.Append(" from ");
      result.Append(operands_[1]->CustomCSSText());
      result.Append(" to ");
      result.Append(operands_.back()->CustomCSSText());
      result.Append(')');

      return result.ReleaseString();
    }
    case CSSMathOperator::kInvalid:
      NOTREACHED();
  }
}

bool CSSMathExpressionOperation::operator==(
    const CSSMathExpressionNode& exp) const {
  if (!exp.IsOperation()) {
    return false;
  }

  const CSSMathExpressionOperation& other = To<CSSMathExpressionOperation>(exp);
  if (operator_ != other.operator_) {
    return false;
  }
  if (operands_.size() != other.operands_.size()) {
    return false;
  }
  for (wtf_size_t i = 0; i < operands_.size(); ++i) {
    if (!base::ValuesEquivalent(operands_[i], other.operands_[i])) {
      return false;
    }
  }
  return true;
}

CSSPrimitiveValue::UnitType CSSMathExpressionOperation::ResolvedUnitType()
    const {
  switch (category_) {
    case kCalcNumber:
      return CSSPrimitiveValue::UnitType::kNumber;
    case kCalcAngle:
    case kCalcTime:
    case kCalcFrequency:
    case kCalcLength:
    case kCalcPercent:
    case kCalcResolution:
      switch (operator_) {
        case CSSMathOperator::kMultiply:
        case CSSMathOperator::kDivide: {
          DCHECK_EQ(operands_.size(), 2u);
          if (operands_[0]->Category() == kCalcNumber) {
            return operands_[1]->ResolvedUnitType();
          }
          if (operands_[1]->Category() == kCalcNumber) {
            return operands_[0]->ResolvedUnitType();
          }
          NOTREACHED();
        }
        case CSSMathOperator::kAdd:
        case CSSMathOperator::kSubtract:
        case CSSMathOperator::kMin:
        case CSSMathOperator::kMax:
        case CSSMathOperator::kClamp:
        case CSSMathOperator::kRoundNearest:
        case CSSMathOperator::kRoundUp:
        case CSSMathOperator::kRoundDown:
        case CSSMathOperator::kRoundToZero:
        case CSSMathOperator::kMod:
        case CSSMathOperator::kRem:
        case CSSMathOperator::kHypot:
        case CSSMathOperator::kAbs: {
          CSSPrimitiveValue::UnitType first_type =
              operands_.front()->ResolvedUnitType();
          if (first_type == CSSPrimitiveValue::UnitType::kUnknown) {
            return CSSPrimitiveValue::UnitType::kUnknown;
          }
          for (const CSSMathExpressionNode* operand : SecondToLastOperands()) {
            CSSPrimitiveValue::UnitType next = operand->ResolvedUnitType();
            if (next == CSSPrimitiveValue::UnitType::kUnknown ||
                next != first_type) {
              return CSSPrimitiveValue::UnitType::kUnknown;
            }
          }
          return first_type;
        }
        case CSSMathOperator::kSign:
        case CSSMathOperator::kProgress:
        case CSSMathOperator::kMediaProgress:
        case CSSMathOperator::kContainerProgress:
          return CSSPrimitiveValue::UnitType::kNumber;
        case CSSMathOperator::kCalcSize: {
          DCHECK_EQ(operands_.size(), 2u);
          CSSPrimitiveValue::UnitType calculation_type =
              operands_[1]->ResolvedUnitType();
          if (calculation_type != CSSPrimitiveValue::UnitType::kIdent) {
            // The basis is not involved.
            return calculation_type;
          }
          // TODO(https://crbug.com/313072): We could in theory resolve the
          // 'size' keyword to produce a correct answer in more cases.
          return CSSPrimitiveValue::UnitType::kUnknown;
        }
        case CSSMathOperator::kInvalid:
          NOTREACHED();
      }
    case kCalcLengthFunction:
    case kCalcIntrinsicSize:
    case kCalcOther:
      return CSSPrimitiveValue::UnitType::kUnknown;
    case kCalcIdent:
      return CSSPrimitiveValue::UnitType::kIdent;
  }

  NOTREACHED();
}

void CSSMathExpressionOperation::Trace(Visitor* visitor) const {
  visitor->Trace(operands_);
  CSSMathExpressionNode::Trace(visitor);
}

// static
const CSSMathExpressionNode* CSSMathExpressionOperation::GetNumericLiteralSide(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side) {
  if (left_side->Category() == kCalcNumber && left_side->IsNumericLiteral()) {
    return left_side;
  }
  if (right_side->Category() == kCalcNumber && right_side->IsNumericLiteral()) {
    return right_side;
  }
  return nullptr;
}

// static
double CSSMathExpressionOperation::EvaluateOperator(
    const Vector<double>& operands,
    CSSMathOperator op) {
  // Design doc for infinity and NaN: https://bit.ly/349gXjq

  // Any operation with at least one NaN argument produces NaN
  // https://drafts.csswg.org/css-values/#calc-type-checking
  for (double operand : operands) {
    if (std::isnan(operand)) {
      return operand;
    }
  }

  switch (op) {
    case CSSMathOperator::kAdd:
      DCHECK_EQ(operands.size(), 2u);
      return operands[0] + operands[1];
    case CSSMathOperator::kSubtract:
      DCHECK_EQ(operands.size(), 2u);
      return operands[0] - operands[1];
    case CSSMathOperator::kMultiply:
      DCHECK_EQ(operands.size(), 2u);
      return operands[0] * operands[1];
    case CSSMathOperator::kDivide:
      DCHECK(operands.size() == 1u || operands.size() == 2u);
      return operands[0] / operands[1];
    case CSSMathOperator::kMin: {
      if (operands.empty()) {
        return std::numeric_limits<double>::quiet_NaN();
      }
      double minimum = operands[0];
      for (double operand : operands) {
        // std::min(0.0, -0.0) returns 0.0, manually check for such situation
        // and set result to -0.0.
        if (minimum == 0 && operand == 0 &&
            std::signbit(minimum) != std::signbit(operand)) {
          minimum = -0.0;
          continue;
        }
        minimum = std::min(minimum, operand);
      }
      return minimum;
    }
    case CSSMathOperator::kMax: {
      if (operands.empty()) {
        return std::numeric_limits<double>::quiet_NaN();
      }
      double maximum = operands[0];
      for (double operand : operands) {
        // std::max(-0.0, 0.0) returns -0.0, manually check for such situation
        // and set result to 0.0.
        if (maximum == 0 && operand == 0 &&
            std::signbit(maximum) != std::signbit(operand)) {
          maximum = 0.0;
          continue;
        }
        maximum = std::max(maximum, operand);
      }
      return maximum;
    }
    case CSSMathOperator::kClamp: {
      DCHECK_EQ(operands.size(), 3u);
      double min = operands[0];
      double val = operands[1];
      double max = operands[2];
      // clamp(MIN, VAL, MAX) is identical to max(MIN, min(VAL, MAX))
      // according to the spec,
      // https://drafts.csswg.org/css-values-4/#funcdef-clamp.
      double minimum = std::min(val, max);
      // std::min(0.0, -0.0) returns 0.0, so manually check for this situation
      // to set result to -0.0.
      if (val == 0 && max == 0 && !std::signbit(val) && std::signbit(max)) {
        minimum = -0.0;
      }
      double maximum = std::max(min, minimum);
      // std::max(-0.0, 0.0) returns -0.0, so manually check for this situation
      // to set result to 0.0.
      if (min == 0 && minimum == 0 && std::signbit(min) &&
          !std::signbit(minimum)) {
        maximum = 0.0;
      }
      return maximum;
    }
    case CSSMathOperator::kRoundNearest:
    case CSSMathOperator::kRoundUp:
    case CSSMathOperator::kRoundDown:
    case CSSMathOperator::kRoundToZero:
    case CSSMathOperator::kMod:
    case CSSMathOperator::kRem: {
      DCHECK_EQ(operands.size(), 2u);
      return EvaluateSteppedValueFunction(op, operands[0], operands[1]);
    }
    case CSSMathOperator::kHypot: {
      DCHECK_GE(operands.size(), 1u);
      double value = 0;
      for (double operand : operands) {
        value = std::hypot(value, operand);
      }
      return value;
    }
    case CSSMathOperator::kAbs: {
      DCHECK_EQ(operands.size(), 1u);
      return std::abs(operands.front());
    }
    case CSSMathOperator::kSign: {
      DCHECK_EQ(operands.size(), 1u);
      const double value = operands.front();
      const double signum =
          (value == 0 || std::isnan(value)) ? value : ((value > 0) ? 1 : -1);
      return signum;
    }
    case CSSMathOperator::kProgress:
    case CSSMathOperator::kMediaProgress:
    case CSSMathOperator::kContainerProgress: {
      CHECK_EQ(operands.size(), 3u);
      return (operands[0] - operands[1]) / (operands[2] - operands[1]);
    }
    case CSSMathOperator::kCalcSize: {
      CHECK_EQ(operands.size(), 2u);
      // TODO(https://crbug.com/313072): In theory we could also
      // evaluate (a) cases where the basis (operand 0) is not a double,
      // and (b) cases where the basis (operand 0) is a double and the
      // calculation (operand 1) requires 'size' keyword substitutions.
      // But for now just handle the simplest case.
      return operands[1];
    }

    case CSSMathOperator::kInvalid:
      NOTREACHED();
  }
}

const CSSMathExpressionNode& CSSMathExpressionOperation::PopulateWithTreeScope(
    const TreeScope* tree_scope) const {
  Operands populated_operands;
  for (const CSSMathExpressionNode* op : operands_) {
    populated_operands.push_back(&op->EnsureScopedValue(tree_scope));
  }
  return *MakeGarbageCollected<CSSMathExpressionOperation>(
      Category(), std::move(populated_operands), operator_);
}

const CSSMathExpressionNode* CSSMathExpressionOperation::TransformAnchors(
    LogicalAxis logical_axis,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) const {
  Operands transformed_operands;
  for (const CSSMathExpressionNode* op : operands_) {
    transformed_operands.push_back(
        op->TransformAnchors(logical_axis, transform, writing_direction));
  }
  if (transformed_operands != operands_) {
    return MakeGarbageCollected<CSSMathExpressionOperation>(
        Category(), std::move(transformed_operands), operator_);
  }
  return this;
}

bool CSSMathExpressionOperation::HasInvalidAnchorFunctions(
    const CSSLengthResolver& length_resolver) const {
  for (const CSSMathExpressionNode* op : operands_) {
    if (op->HasInvalidAnchorFunctions(length_resolver)) {
      return true;
    }
  }
  return false;
}

#if DCHECK_IS_ON()
bool CSSMathExpressionOperation::InvolvesPercentageComparisons() const {
  if (IsMinOrMax() && Category() == kCalcPercent && operands_.size() > 1u) {
    return true;
  }
  for (const CSSMathExpressionNode* operand : operands_) {
    if (operand->InvolvesPercentageComparisons()) {
      return true;
    }
  }
  return false;
}
#endif

// ------ End of CSSMathExpressionOperation member functions ------

// ------ Start of CSSMathExpressionContainerProgress member functions ----

namespace {

double EvaluateContainerSize(const CSSIdentifierValue* size_feature,
                             const CSSCustomIdentValue* container_name,
                             const CSSLengthResolver& length_resolver) {
  if (container_name) {
    ScopedCSSName* name = MakeGarbageCollected<ScopedCSSName>(
        container_name->Value(), container_name->GetTreeScope());
    switch (size_feature->GetValueID()) {
      case CSSValueID::kWidth:
        return length_resolver.ContainerWidth(*name);
      case CSSValueID::kHeight:
        return length_resolver.ContainerHeight(*name);
      default:
        NOTREACHED();
    }
  } else {
    switch (size_feature->GetValueID()) {
      case CSSValueID::kWidth:
        return length_resolver.ContainerWidth();
      case CSSValueID::kHeight:
        return length_resolver.ContainerHeight();
      default:
        NOTREACHED();
    }
  }
}

}  // namespace

CSSMathExpressionContainerFeature::CSSMathExpressionContainerFeature(
    const CSSIdentifierValue* size_feature,
    const CSSCustomIdentValue* container_name)
    : CSSMathExpressionNode(
          CalculationResultCategory::kCalcLength,
          /*has_comparisons =*/false,
          /*has_anchor_functions =*/false,
          /*needs_tree_scope_population =*/
          (container_name && !container_name->IsScopedValue())),
      size_feature_(size_feature),
      container_name_(container_name) {
  CHECK(size_feature);
}

String CSSMathExpressionContainerFeature::CustomCSSText() const {
  StringBuilder builder;
  builder.Append(size_feature_->CustomCSSText());
  if (container_name_ && !container_name_->Value().empty()) {
    builder.Append(" of ");
    builder.Append(container_name_->CustomCSSText());
  }
  return builder.ToString();
}

scoped_refptr<const CalculationExpressionNode>
CSSMathExpressionContainerFeature::ToCalculationExpression(
    const CSSLengthResolver& length_resolver) const {
  double progress =
      EvaluateContainerSize(size_feature_, container_name_, length_resolver);
  return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
      PixelsAndPercent(progress));
}

std::optional<PixelsAndPercent>
CSSMathExpressionContainerFeature::ToPixelsAndPercent(
    const CSSLengthResolver& length_resolver) const {
  return PixelsAndPercent(ComputeDouble(length_resolver));
}

double CSSMathExpressionContainerFeature::ComputeDouble(
    const CSSLengthResolver& length_resolver) const {
  return EvaluateContainerSize(size_feature_, container_name_, length_resolver);
}

// ------ End of CSSMathExpressionContainerProgress member functions ------

// ------ Start of CSSMathExpressionAnchorQuery member functions ------

namespace {

CalculationResultCategory AnchorQueryCategory(
    const CSSPrimitiveValue* fallback) {
  // Note that the main (non-fallback) result of an anchor query is always
  // a kCalcLength, so the only thing that can make our overall result anything
  // else is the fallback.
  if (!fallback || fallback->IsLength()) {
    return kCalcLength;
  }
  // This can happen for e.g. anchor(--a top, 10%). In this case, we can't
  // tell if we're going to return a <length> or a <percentage> without actually
  // evaluating the query.
  //
  // TODO(crbug.com/326088870): Evaluate anchor queries when understanding
  // the CalculationResultCategory for an expression.
  return kCalcLengthFunction;
}

}  // namespace

CSSMathExpressionAnchorQuery::CSSMathExpressionAnchorQuery(
    CSSAnchorQueryType type,
    const CSSValue* anchor_specifier,
    const CSSValue* value,
    const CSSPrimitiveValue* fallback)
    : CSSMathExpressionNode(
          AnchorQueryCategory(fallback),
          false /* has_comparisons */,
          true /* has_anchor_functions */,
          (anchor_specifier && !anchor_specifier->IsScopedValue()) ||
              (fallback && !fallback->IsScopedValue())),
      type_(type),
      anchor_specifier_(anchor_specifier),
      value_(value),
      fallback_(fallback) {}

double CSSMathExpressionAnchorQuery::DoubleValue() const {
  NOTREACHED();
}

double CSSMathExpressionAnchorQuery::ComputeLengthPx(
    const CSSLengthResolver& length_resolver) const {
  return ComputeDouble(length_resolver);
}

double CSSMathExpressionAnchorQuery::ComputeDouble(
    const CSSLengthResolver& length_resolver) const {
  CHECK_EQ(kCalcLength, Category());
  // Note: The category may also be kCalcLengthFunction (see
  // AnchorQueryCategory), in which case we'll reach ToCalculationExpression
  // instead.

  AnchorQuery query = ToQuery(length_resolver);

  if (std::optional<LayoutUnit> px = EvaluateQuery(query, length_resolver)) {
    return px.value();
  }

  // We should have checked HasInvalidAnchorFunctions() before entering here.
  CHECK(fallback_);
  return fallback_->ComputeLength<double>(length_resolver);
}

String CSSMathExpressionAnchorQuery::CustomCSSText() const {
  StringBuilder result;
  result.Append(IsAnchor() ? "anchor(" : "anchor-size(");
  if (anchor_specifier_) {
    result.Append(anchor_specifier_->CssText());
    if (value_) {
      result.Append(" ");
    }
  }
  if (value_) {
    result.Append(value_->CssText());
  }
  if (fallback_) {
    if (anchor_specifier_ || value_) {
      result.Append(", ");
    }
    result.Append(fallback_->CustomCSSText());
  }
  result.Append(")");
  return result.ToString();
}

bool CSSMathExpressionAnchorQuery::operator==(
    const CSSMathExpressionNode& other) const {
  const auto* other_anchor = DynamicTo<CSSMathExpressionAnchorQuery>(other);
  if (!other_anchor) {
    return false;
  }
  return type_ == other_anchor->type_ &&
         base::ValuesEquivalent(anchor_specifier_,
                                other_anchor->anchor_specifier_) &&
         base::ValuesEquivalent(value_, other_anchor->value_) &&
         base::ValuesEquivalent(fallback_, other_anchor->fallback_);
}

namespace {

CSSAnchorValue CSSValueIDToAnchorValueEnum(CSSValueID value) {
  switch (value) {
    case CSSValueID::kInside:
      return CSSAnchorValue::kInside;
    case CSSValueID::kOutside:
      return CSSAnchorValue::kOutside;
    case CSSValueID::kTop:
      return CSSAnchorValue::kTop;
    case CSSValueID::kLeft:
      return CSSAnchorValue::kLeft;
    case CSSValueID::kRight:
      return CSSAnchorValue::kRight;
    case CSSValueID::kBottom:
      return CSSAnchorValue::kBottom;
    case CSSValueID::kStart:
      return CSSAnchorValue::kStart;
    case CSSValueID::kEnd:
      return CSSAnchorValue::kEnd;
    case CSSValueID::kSelfStart:
      return CSSAnchorValue::kSelfStart;
    case CSSValueID::kSelfEnd:
      return CSSAnchorValue::kSelfEnd;
    case CSSValueID::kCenter:
      return CSSAnchorValue::kCenter;
    default:
      NOTREACHED();
  }
}

CSSAnchorSizeValue CSSValueIDToAnchorSizeValueEnum(CSSValueID value) {
  switch (value) {
    case CSSValueID::kWidth:
      return CSSAnchorSizeValue::kWidth;
    case CSSValueID::kHeight:
      return CSSAnchorSizeValue::kHeight;
    case CSSValueID::kBlock:
      return CSSAnchorSizeValue::kBlock;
    case CSSValueID::kInline:
      return CSSAnchorSizeValue::kInline;
    case CSSValueID::kSelfBlock:
      return CSSAnchorSizeValue::kSelfBlock;
    case CSSValueID::kSelfInline:
      return CSSAnchorSizeValue::kSelfInline;
    default:
      NOTREACHED();
  }
}

}  // namespace

scoped_refptr<const CalculationExpressionNode>
CSSMathExpressionAnchorQuery::ToCalculationExpression(
    const CSSLengthResolver& length_resolver) const {
  AnchorQuery query = ToQuery(length_resolver);

  Length result;

  if (std::optional<LayoutUnit> px = EvaluateQuery(query, length_resolver)) {
    result = Length::Fixed(px.value());
  } else {
    // We should have checked HasInvalidAnchorFunctions() before entering here.
    CHECK(fallback_);
    result = fallback_->ConvertToLength(length_resolver);
  }

  return result.AsCalculationValue()->GetOrCreateExpression();
}

std::optional<LayoutUnit> CSSMathExpressionAnchorQuery::EvaluateQuery(
    const AnchorQuery& query,
    const CSSLengthResolver& length_resolver) const {
  length_resolver.ReferenceAnchor();
  if (AnchorEvaluator* anchor_evaluator =
          length_resolver.GetAnchorEvaluator()) {
    return anchor_evaluator->Evaluate(query,
                                      length_resolver.GetPositionAnchor(),
                                      length_resolver.GetPositionAreaOffsets());
  }
  return std::nullopt;
}

AnchorQuery CSSMathExpressionAnchorQuery::ToQuery(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(IsScopedValue());
  AnchorSpecifierValue* anchor_specifier = AnchorSpecifierValue::Default();
  if (const auto* custom_ident =
          DynamicTo<CSSCustomIdentValue>(anchor_specifier_.Get())) {
    length_resolver.ReferenceTreeScope();
    anchor_specifier = MakeGarbageCollected<AnchorSpecifierValue>(
        *MakeGarbageCollected<ScopedCSSName>(custom_ident->Value(),
                                             custom_ident->GetTreeScope()));
  }
  if (type_ == CSSAnchorQueryType::kAnchor) {
    if (const CSSPrimitiveValue* percentage =
            DynamicTo<CSSPrimitiveValue>(*value_)) {
      DCHECK(percentage->IsPercentage());
      return AnchorQuery(type_, anchor_specifier, percentage->GetFloatValue(),
                         CSSAnchorValue::kPercentage);
    }
    const CSSIdentifierValue& side = To<CSSIdentifierValue>(*value_);
    return AnchorQuery(type_, anchor_specifier, /* percentage */ 0,
                       CSSValueIDToAnchorValueEnum(side.GetValueID()));
  }

  DCHECK_EQ(type_, CSSAnchorQueryType::kAnchorSize);
  CSSAnchorSizeValue size = CSSAnchorSizeValue::kImplicit;
  if (value_) {
    size = CSSValueIDToAnchorSizeValueEnum(
        To<CSSIdentifierValue>(*value_).GetValueID());
  }
  return AnchorQuery(type_, anchor_specifier, /* percentage */ 0, size);
}

const CSSMathExpressionNode&
CSSMathExpressionAnchorQuery::PopulateWithTreeScope(
    const TreeScope* tree_scope) const {
  return *MakeGarbageCollected<CSSMathExpressionAnchorQuery>(
      type_,
      anchor_specifier_ ? &anchor_specifier_->EnsureScopedValue(tree_scope)
                        : nullptr,
      value_,
      fallback_
          ? To<CSSPrimitiveValue>(&fallback_->EnsureScopedValue(tree_scope))
          : nullptr);
}

namespace {

bool FlipLogical(LogicalAxis logical_axis,
                 const TryTacticTransform& transform) {
  return (logical_axis == LogicalAxis::kInline) ? transform.FlippedInline()
                                                : transform.FlippedBlock();
}

CSSValueID TransformAnchorCSSValueID(
    CSSValueID from,
    LogicalAxis logical_axis,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  // The value transformation happens on logical insets, so we need to first
  // translate physical to logical, then carry out the transform, and then
  // convert *back* to physical.
  PhysicalToLogical logical_insets(writing_direction, CSSValueID::kTop,
                                   CSSValueID::kRight, CSSValueID::kBottom,
                                   CSSValueID::kLeft);

  LogicalToPhysical<CSSValueID> insets = transform.Transform(
      TryTacticTransform::LogicalSides<CSSValueID>{
          .inline_start = logical_insets.InlineStart(),
          .inline_end = logical_insets.InlineEnd(),
          .block_start = logical_insets.BlockStart(),
          .block_end = logical_insets.BlockEnd()},
      writing_direction);

  bool flip_logical = FlipLogical(logical_axis, transform);

  switch (from) {
    // anchor()
    case CSSValueID::kTop:
      return insets.Top();
    case CSSValueID::kLeft:
      return insets.Left();
    case CSSValueID::kRight:
      return insets.Right();
    case CSSValueID::kBottom:
      return insets.Bottom();
    case CSSValueID::kStart:
      return flip_logical ? CSSValueID::kEnd : from;
    case CSSValueID::kEnd:
      return flip_logical ? CSSValueID::kStart : from;
    case CSSValueID::kSelfStart:
      return flip_logical ? CSSValueID::kSelfEnd : from;
    case CSSValueID::kSelfEnd:
      return flip_logical ? CSSValueID::kSelfStart : from;
    case CSSValueID::kCenter:
      return from;
    // anchor-size()
    case CSSValueID::kWidth:
      return transform.FlippedStart() ? CSSValueID::kHeight : from;
    case CSSValueID::kHeight:
      return transform.FlippedStart() ? CSSValueID::kWidth : from;
    case CSSValueID::kBlock:
      return transform.FlippedStart() ? CSSValueID::kInline : from;
    case CSSValueID::kInline:
      return transform.FlippedStart() ? CSSValueID::kBlock : from;
    case CSSValueID::kSelfBlock:
      return transform.FlippedStart() ? CSSValueID::kSelfInline : from;
    case CSSValueID::kSelfInline:
      return transform.FlippedStart() ? CSSValueID::kSelfBlock : from;
    default:
      NOTREACHED();
  }
}

float TransformAnchorPercentage(float from,
                                LogicalAxis logical_axis,
                                const TryTacticTransform& transform) {
  return FlipLogical(logical_axis, transform) ? (100.0f - from) : from;
}

}  // namespace

const CSSMathExpressionNode* CSSMathExpressionAnchorQuery::TransformAnchors(
    LogicalAxis logical_axis,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) const {
  const CSSValue* transformed_value = value_;
  if (const auto* side = DynamicTo<CSSIdentifierValue>(value_.Get())) {
    CSSValueID from = side->GetValueID();
    CSSValueID to = TransformAnchorCSSValueID(from, logical_axis, transform,
                                              writing_direction);
    if (from != to) {
      transformed_value = CSSIdentifierValue::Create(to);
    }
  } else if (const auto* percentage =
                 DynamicTo<CSSPrimitiveValue>(value_.Get())) {
    DCHECK(percentage->IsPercentage());
    float from = percentage->GetFloatValue();
    float to = TransformAnchorPercentage(from, logical_axis, transform);
    if (from != to) {
      transformed_value = CSSNumericLiteralValue::Create(
          to, CSSPrimitiveValue::UnitType::kPercentage);
    }
  }

  // The fallback can contain anchors.
  const CSSPrimitiveValue* transformed_fallback = fallback_.Get();
  if (const auto* math_function =
          DynamicTo<CSSMathFunctionValue>(fallback_.Get())) {
    transformed_fallback = math_function->TransformAnchors(
        logical_axis, transform, writing_direction);
  }

  if (transformed_value != value_ || transformed_fallback != fallback_) {
    // Either the value or the fallback was transformed.
    return MakeGarbageCollected<CSSMathExpressionAnchorQuery>(
        type_, anchor_specifier_, transformed_value, transformed_fallback);
  }

  // No transformation.
  return this;
}

bool CSSMathExpressionAnchorQuery::HasInvalidAnchorFunctions(
    const CSSLengthResolver& length_resolver) const {
  AnchorQuery query = ToQuery(length_resolver);
  std::optional<LayoutUnit> px = EvaluateQuery(query, length_resolver);

  if (px.has_value()) {
    return false;
  }

  // We need to take the fallback. However, if there is no fallback,
  // then we are invalid at computed-value time [1].
  // [1] // https://drafts.csswg.org/css-anchor-position-1/#anchor-valid

  if (fallback_) {
    if (auto* math_fallback =
            DynamicTo<CSSMathFunctionValue>(fallback_.Get())) {
      // The fallback itself may also contain invalid anchor*() functions.
      return math_fallback->HasInvalidAnchorFunctions(length_resolver);
    }
    return false;
  }

  return true;
}

void CSSMathExpressionAnchorQuery::Trace(Visitor* visitor) const {
  visitor->Trace(anchor_specifier_);
  visitor->Trace(value_);
  visitor->Trace(fallback_);
  CSSMathExpressionNode::Trace(visitor);
}

// ------ End of CSSMathExpressionAnchorQuery member functions ------

class CSSMathExpressionNodeParser {
  STACK_ALLOCATED();

 public:
  using Flag = CSSMathExpressionNode::Flag;
  using Flags = CSSMathExpressionNode::Flags;

  // A struct containing parser state that varies within the expression tree.
  struct State {
    STACK_ALLOCATED();

   public:
    uint8_t depth;
    bool allow_size_keyword;

    static_assert(uint8_t(kMaxExpressionDepth + 1) == kMaxExpressionDepth + 1);

    State() : depth(0), allow_size_keyword(false) {}
    State(const State&) = default;
    State& operator=(const State&) = default;
  };

  CSSMathExpressionNodeParser(const CSSParserContext& context,
                              const Flags parsing_flags,
                              CSSAnchorQueryTypes allowed_anchor_queries,
                              const CSSColorChannelMap& color_channel_map)
      : context_(context),
        allowed_anchor_queries_(allowed_anchor_queries),
        parsing_flags_(parsing_flags),
        color_channel_map_(color_channel_map) {}

  bool IsSupportedMathFunction(CSSValueID function_id) {
    switch (function_id) {
      case CSSValueID::kMin:
      case CSSValueID::kMax:
      case CSSValueID::kClamp:
      case CSSValueID::kCalc:
      case CSSValueID::kWebkitCalc:
      case CSSValueID::kSin:
      case CSSValueID::kCos:
      case CSSValueID::kTan:
      case CSSValueID::kAsin:
      case CSSValueID::kAcos:
      case CSSValueID::kAtan:
      case CSSValueID::kAtan2:
      case CSSValueID::kAnchor:
      case CSSValueID::kAnchorSize:
        return true;
      case CSSValueID::kPow:
      case CSSValueID::kSqrt:
      case CSSValueID::kHypot:
      case CSSValueID::kLog:
      case CSSValueID::kExp:
        return RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled();
      case CSSValueID::kRound:
      case CSSValueID::kMod:
      case CSSValueID::kRem:
        return RuntimeEnabledFeatures::CSSSteppedValueFunctionsEnabled();
      case CSSValueID::kAbs:
      case CSSValueID::kSign:
        return RuntimeEnabledFeatures::CSSSignRelatedFunctionsEnabled();
      case CSSValueID::kProgress:
      case CSSValueID::kMediaProgress:
      case CSSValueID::kContainerProgress:
        return RuntimeEnabledFeatures::CSSProgressNotationEnabled();
      case CSSValueID::kCalcSize:
        return RuntimeEnabledFeatures::CSSCalcSizeFunctionEnabled();
      case CSSValueID::kSiblingCount:
      case CSSValueID::kSiblingIndex:
        return RuntimeEnabledFeatures::CSSSiblingFunctionsEnabled();
      // TODO(crbug.com/1284199): Support other math functions.
      default:
        return false;
    }
  }

  CSSMathExpressionNode* ParseAnchorQuery(CSSValueID function_id,
                                          CSSParserTokenStream& stream) {
    CSSAnchorQueryType anchor_query_type;
    switch (function_id) {
      case CSSValueID::kAnchor:
        anchor_query_type = CSSAnchorQueryType::kAnchor;
        break;
      case CSSValueID::kAnchorSize:
        anchor_query_type = CSSAnchorQueryType::kAnchorSize;
        break;
      default:
        return nullptr;
    }

    if (!(static_cast<CSSAnchorQueryTypes>(anchor_query_type) &
          allowed_anchor_queries_)) {
      return nullptr;
    }

    // |anchor_specifier| may be omitted to represent the default anchor.
    const CSSValue* anchor_specifier =
        css_parsing_utils::ConsumeDashedIdent(stream, context_);

    stream.ConsumeWhitespace();
    const CSSValue* value = nullptr;
    switch (anchor_query_type) {
      case CSSAnchorQueryType::kAnchor:
        value = css_parsing_utils::ConsumeIdent<
            CSSValueID::kInside, CSSValueID::kOutside, CSSValueID::kTop,
            CSSValueID::kLeft, CSSValueID::kRight, CSSValueID::kBottom,

"""


```