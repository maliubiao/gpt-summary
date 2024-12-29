Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. The code is part of `css_math_expression_node.cc` and seems to deal with simplifying and manipulating CSS math expressions.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The code primarily focuses on the `CreateArithmeticOperationSimplified` function and the `SubstituteForSizeKeyword`, `SubstituteForPercentages`, and `MakeBasisCanonical` helper functions, along with the `CreateArithmeticOperationAndSimplifyCalcSize` function. These functions are all involved in simplifying and canonicalizing CSS math expressions, especially those involving `calc-size()`.

2. **Analyze `CreateArithmeticOperationSimplified`:** This function takes two `CSSMathExpressionNode` pointers and an operator as input. It appears to attempt various simplifications based on the types of the operands and the operator. Key simplifications include:
    * Distributing arithmetic operations.
    * Handling cases where simplification isn't possible.
    * Simplifying operations with numeric literals.
    * Simplifying addition and subtraction of the same unit types.
    * Simplifying multiplication and division by a number.

3. **Analyze helper functions:**
    * `SubstituteForSizeKeyword`:  This function seems to replace instances of the keyword "size" within a math expression with a provided substitution node. It's likely related to how `calc-size()` expressions are processed.
    * `SubstituteForPercentages`:  This function seems to transform percentages within a math expression in the context of `calc-size()`. It likely converts a percentage like `P%` into `size * (P/100)`.
    * `BasisIsCanonical`: This function checks if the "basis" of a `calc-size()` expression is in a canonical form (either a sizing keyword, 'any', or '100%').
    * `MakeBasisCanonical`: This function ensures the basis of a `calc-size()` expression is in its canonical form by performing substitutions and transformations.

4. **Analyze `CreateArithmeticOperationAndSimplifyCalcSize`:** This function appears to specifically handle the creation and simplification of arithmetic operations involving `calc-size()`. It seems to be designed to "merge" `calc-size()` expressions and ensure they remain at the top level of the expression. It also calls `MakeBasisCanonical` to handle non-canonical bases.

5. **Relate to CSS, HTML, and JavaScript:**
    * **CSS:** The entire code snippet directly manipulates CSS math expressions. The functions deal with units, percentages, and the `calc()` and `calc-size()` functions, which are core CSS features.
    * **HTML:**  CSS styles, including those using `calc()` or `calc-size()`, are applied to HTML elements. The code plays a role in how those styles are interpreted.
    * **JavaScript:** JavaScript can interact with CSS through the CSSOM (CSS Object Model). Properties calculated using `calc()` or `calc-size()` can be accessed and potentially modified via JavaScript.

6. **Identify potential user/programming errors:** Incorrectly nested `calc()` or `calc-size()` expressions, mixing incompatible units without proper conversion, and exceeding the limits of expression complexity could lead to errors handled by this code.

7. **Outline user interaction leading to this code:** A user specifying a CSS property value using `calc()` or `calc-size()` in a stylesheet or inline style would trigger the parsing and processing that eventually leads to this code.

8. **Infer input and output for logical reasoning:** For functions like `CreateArithmeticOperationSimplified`, the input would be two `CSSMathExpressionNode` pointers and an operator. The output would be a simplified `CSSMathExpressionNode`. For `SubstituteForPercentages`, the input is a `CSSMathExpressionNode` potentially containing percentages, and the output is a transformed node.

9. **Structure the summary:** Organize the information logically, starting with the overall purpose, then detailing the functionality of each key function, and finally addressing the connections to CSS, HTML, JavaScript, potential errors, user interaction, and input/output.

10. **Refine and elaborate:** Add details and examples where necessary to make the explanation clearer and more comprehensive. For example, explaining what "canonical basis" means for `calc-size()`.

By following these steps, we can generate a detailed and informative summary of the provided code snippet.
Based on the provided code snippet from `blink/renderer/core/css/css_math_expression_node.cc`, here's a breakdown of its functionality:

**Core Functionality: Simplifying CSS Arithmetic Operations**

This code snippet primarily focuses on the `CreateArithmeticOperationSimplified` function and related helper functions. Its main goal is to **create and simplify CSS arithmetic operations** within `calc()` expressions. It takes two `CSSMathExpressionNode` objects (representing the left and right sides of the operation) and a `CSSMathOperator` as input, and attempts to return a simplified `CSSMathExpressionNode`.

Here's a breakdown of the key steps involved in the simplification process:

1. **Distribution Check:** It first tries to distribute the arithmetic operation using `MaybeDistributeArithmeticOperation`. This is not shown in the snippet but is called.
2. **Simplification Check:** It checks if the arithmetic operation can be simplified using `CanArithmeticOperationBeSimplified`. If not, it creates a basic `CSSMathExpressionOperation`.
3. **Category Checks:** It gets the calculation result categories of the left and right sides. It asserts that neither side has a `kCalcOther` category (meaning their types are known and can be operated on).
4. **Numeric Literal Simplification:** If both sides are numeric literals (like `10px` or `2`), it directly evaluates the operation using `EvaluateOperator` and creates a new `CSSMathExpressionNumericLiteral` with the result.
5. **Addition and Subtraction Simplification (Same Types):**  For addition and subtraction, if both sides have the same unit category (e.g., both are lengths, both are angles), it attempts further simplification:
    * **Same Unit Type:** If the exact unit types are the same (e.g., `px + px`), it evaluates the operation on their double values and creates a new `CSSMathExpressionNumericLiteral` with the same unit type.
    * **Convertible Unit Types:** If the unit types belong to the same category but are different (e.g., `px + cm`), it converts both values to a canonical unit within that category, performs the operation, and creates a new `CSSMathExpressionNumericLiteral` with the canonical unit.
6. **Multiplication and Division Simplification (by a Number):** For multiplication and division, if one side is a numeric literal, it identifies that numeric literal and the other side. It then evaluates the operation on the double value of the other side and the number, creating a new `CSSMathExpressionNumericLiteral` with the unit type of the non-numeric side.
7. **Default Operation Creation:** If none of the above simplifications apply, it creates a new `CSSMathExpressionOperation` representing the unsimplified operation.

**Relationship to JavaScript, HTML, and CSS:**

* **CSS:** This code is directly related to **CSS's `calc()` function**. The `calc()` function allows authors to perform calculations within CSS property values. This code handles the simplification and evaluation of the arithmetic operations defined within those `calc()` expressions.
    * **Example:**  A CSS rule like `width: calc(100% - 20px);` would involve this code to subtract `20px` from `100%`. The code would determine the types, potentially convert units, and ultimately calculate the final width.
* **HTML:** The results of these CSS calculations directly affect the **rendering of HTML elements**. The computed styles, including those derived from `calc()`, determine the layout and appearance of the webpage.
    * **Example:** If the above `width: calc(100% - 20px);` is applied to a `<div>`, this code helps determine the actual pixel width of that `<div>` on the screen.
* **JavaScript:** While this code is C++ within the browser engine, JavaScript can interact with CSS and trigger the execution of this code in several ways:
    * **Setting Styles:** JavaScript can set the `style` property of an HTML element with a `calc()` value. This would eventually lead to this code being executed.
        * **Example:** `document.getElementById('myDiv').style.width = 'calc(50vw + 10px)';`
    * **Getting Computed Styles:** JavaScript can use `getComputedStyle()` to retrieve the final computed value of a CSS property, even if it was defined using `calc()`. The browser engine would have used this code to resolve the `calc()` expression before the JavaScript can retrieve the value.
        * **Example:** `window.getComputedStyle(document.getElementById('myDiv')).getPropertyValue('width');`

**Logical Reasoning: Assumptions, Inputs, and Outputs**

Let's consider the `CreateArithmeticOperationSimplified` function with some hypothetical inputs:

**Assumption:** The input `CSSMathExpressionNode` objects represent valid CSS values.

**Input 1:**
* `left_side`: A `CSSMathExpressionNumericLiteral` representing `10px`.
* `right_side`: A `CSSMathExpressionNumericLiteral` representing `5px`.
* `op`: `CSSMathOperator::kAdd`

**Output 1:**
* A `CSSMathExpressionNumericLiteral` representing `15px`. The code would identify that both are length values with the same unit, perform the addition, and create a new literal.

**Input 2:**
* `left_side`: A `CSSMathExpressionNumericLiteral` representing `100%`.
* `right_side`: A `CSSMathExpressionNumericLiteral` representing `20px`.
* `op`: `CSSMathOperator::kSubtract`

**Output 2:**
* A `CSSMathExpressionOperation` representing `100% - 20px`. The code recognizes that percentage and pixel units cannot be directly subtracted without further context (like the size of the containing element). Therefore, it creates an operation node representing the unevaluated expression.

**Input 3:**
* `left_side`: A `CSSMathExpressionNumericLiteral` representing `2`.
* `right_side`: A `CSSMathExpressionNumericLiteral` representing `5em`.
* `op`: `CSSMathOperator::kMultiply`

**Output 3:**
* A `CSSMathExpressionNumericLiteral` representing `10em`. The code identifies one side as a number and the other as a length, performs the multiplication, and retains the unit of the length value.

**Common User or Programming Errors:**

* **Mixing Incompatible Units:** Trying to add or subtract values with incompatible units without a clear conversion path will often result in the creation of an unevaluated `CSSMathExpressionOperation`.
    * **Example (CSS):** `margin-left: calc(10px + 5deg);` (Trying to add a length and an angle). The simplification logic wouldn't know how to handle this directly.
* **Incorrectly Nested `calc()` Expressions (less common now):** While modern CSS handles nested `calc()` well, older systems or very complex nestings could potentially lead to issues that this code might encounter during parsing or simplification.
* **Division by Zero:**  While not explicitly shown in this snippet, if a `calc()` expression involves division by zero, the evaluation logic (likely in `EvaluateOperator`) would need to handle this error.
    * **Example (CSS):** `width: calc(100px / 0);`

**User Operations Leading to This Code (Debugging Clues):**

1. **User writes CSS code:** A web developer writes CSS code in a stylesheet or inline styles that includes the `calc()` function.
   ```css
   .my-element {
       width: calc(50% + 30px);
       font-size: calc(16px * 1.2);
   }
   ```
2. **Browser parses the CSS:** When the browser loads the HTML and encounters the CSS, the CSS parser will identify the `calc()` expressions.
3. **CSSOM is built:** The browser creates a CSS Object Model (CSSOM) representation of the stylesheets. The `calc()` expressions are likely represented by objects corresponding to `CSSMathExpressionNode` or related classes.
4. **Layout and Rendering:** When the browser needs to lay out and render the webpage, it needs to determine the concrete values of CSS properties. For properties with `calc()`, the browser will invoke the code in `css_math_expression_node.cc` (including the snippet you provided) to simplify and evaluate these expressions.
5. **Debugging Scenario:** If a developer is inspecting the computed styles of `.my-element` in the browser's developer tools, and the `width` or `font-size` shows the result of the calculation, it indicates that this code has been executed. If there's an issue with the calculated value, a developer might set breakpoints or use logging within this C++ code to understand how the simplification is happening and where a potential error might lie.

**Part 3 of 6 Summary of Functionality:**

This specific part of the `css_math_expression_node.cc` file is responsible for the **core logic of simplifying CSS arithmetic operations within `calc()` expressions**. It handles various scenarios, including operations between numbers, length units, percentages, and combinations thereof. The code attempts to perform immediate evaluation when possible (e.g., adding pixels to pixels) and creates operation nodes for expressions that require further context or cannot be immediately simplified (e.g., subtracting pixels from percentages). This simplification process is crucial for the browser to ultimately determine the concrete values of CSS properties for rendering HTML elements.

Prompt: 
```
这是目录为blink/renderer/core/css/css_math_expression_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
  if (CSSMathExpressionNode* result =
          MaybeDistributeArithmeticOperation(left_side, right_side, op)) {
    return result;
  }

  if (!CanArithmeticOperationBeSimplified(left_side, right_side)) {
    return CreateArithmeticOperation(left_side, right_side, op);
  }

  CalculationResultCategory left_category = left_side->Category();
  CalculationResultCategory right_category = right_side->Category();
  DCHECK_NE(left_category, kCalcOther);
  DCHECK_NE(right_category, kCalcOther);

  // Simplify numbers.
  if (left_category == kCalcNumber && left_side->IsNumericLiteral() &&
      right_category == kCalcNumber && right_side->IsNumericLiteral()) {
    return CSSMathExpressionNumericLiteral::Create(
        EvaluateOperator({left_side->DoubleValue(), right_side->DoubleValue()},
                         op),
        CSSPrimitiveValue::UnitType::kNumber);
  }

  // Simplify addition and subtraction between same types.
  if (op == CSSMathOperator::kAdd || op == CSSMathOperator::kSubtract) {
    if (left_category == right_side->Category()) {
      CSSPrimitiveValue::UnitType left_type = left_side->ResolvedUnitType();
      if (HasDoubleValue(left_type)) {
        CSSPrimitiveValue::UnitType right_type = right_side->ResolvedUnitType();
        if (left_type == right_type) {
          return CSSMathExpressionNumericLiteral::Create(
              EvaluateOperator(
                  {left_side->DoubleValue(), right_side->DoubleValue()}, op),
              left_type);
        }
        CSSPrimitiveValue::UnitCategory left_unit_category =
            CSSPrimitiveValue::UnitTypeToUnitCategory(left_type);
        if (left_unit_category != CSSPrimitiveValue::kUOther &&
            left_unit_category ==
                CSSPrimitiveValue::UnitTypeToUnitCategory(right_type)) {
          CSSPrimitiveValue::UnitType canonical_type =
              CSSPrimitiveValue::CanonicalUnitTypeForCategory(
                  left_unit_category);
          if (canonical_type != CSSPrimitiveValue::UnitType::kUnknown) {
            double left_value =
                left_side->DoubleValue() *
                CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(
                    left_type);
            double right_value =
                right_side->DoubleValue() *
                CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(
                    right_type);
            return CSSMathExpressionNumericLiteral::Create(
                EvaluateOperator({left_value, right_value}, op),
                canonical_type);
          }
        }
      }
    }
  } else {
    // Simplify multiplying or dividing by a number for simplifiable types.
    DCHECK(op == CSSMathOperator::kMultiply || op == CSSMathOperator::kDivide);
    const CSSMathExpressionNode* number_side =
        GetNumericLiteralSide(left_side, right_side);
    if (!number_side) {
      return CreateArithmeticOperation(left_side, right_side, op);
    }
    const CSSMathExpressionNode* other_side =
        left_side == number_side ? right_side : left_side;

    double number = number_side->DoubleValue();

    CSSPrimitiveValue::UnitType other_type = other_side->ResolvedUnitType();
    if (HasDoubleValue(other_type)) {
      return CSSMathExpressionNumericLiteral::Create(
          EvaluateOperator({other_side->DoubleValue(), number}, op),
          other_type);
    }
  }

  return CreateArithmeticOperation(left_side, right_side, op);
}

namespace {

std::tuple<const CSSMathExpressionNode*, wtf_size_t> SubstituteForSizeKeyword(
    const CSSMathExpressionNode* source,
    const CSSMathExpressionNode* size_substitution,
    wtf_size_t count_in_substitution) {
  CHECK_GT(count_in_substitution, 0u);
  if (const auto* operation = DynamicTo<CSSMathExpressionOperation>(source)) {
    using Operands = CSSMathExpressionOperation::Operands;
    const Operands& source_operands = operation->GetOperands();
    Operands dest_operands;
    dest_operands.reserve(source_operands.size());
    wtf_size_t total_substitution_count = 0;
    for (const CSSMathExpressionNode* source_op : source_operands) {
      const CSSMathExpressionNode* dest_op;
      wtf_size_t substitution_count;
      std::tie(dest_op, substitution_count) = SubstituteForSizeKeyword(
          source_op, size_substitution, count_in_substitution);
      CHECK_EQ(dest_op == source_op, substitution_count == 0);
      total_substitution_count += substitution_count;
      if (!dest_op || total_substitution_count > (1u << 16)) {
        // hit the size limit
        return std::make_tuple(nullptr, total_substitution_count);
      }
      dest_operands.push_back(dest_op);
    }

    if (total_substitution_count == 0) {
      // return the original rather than making a new one
      return std::make_tuple(source, 0);
    }

    return std::make_tuple(MakeGarbageCollected<CSSMathExpressionOperation>(
                               operation->Category(), std::move(dest_operands),
                               operation->OperatorType()),
                           total_substitution_count);
  }

  auto* literal = DynamicTo<CSSMathExpressionKeywordLiteral>(source);
  if (literal &&
      literal->GetContext() ==
          CSSMathExpressionKeywordLiteral::Context::kCalcSize &&
      literal->GetValue() == CSSValueID::kSize) {
    return std::make_tuple(size_substitution, count_in_substitution);
  }
  return std::make_tuple(source, 0);
}

// https://drafts.csswg.org/css-values-5/#de-percentify-a-calc-size-calculation
const CSSMathExpressionNode* SubstituteForPercentages(
    const CSSMathExpressionNode* source) {
  if (const auto* operation = DynamicTo<CSSMathExpressionOperation>(source)) {
    using Operands = CSSMathExpressionOperation::Operands;
    const Operands& source_operands = operation->GetOperands();
    Operands dest_operands;
    dest_operands.reserve(source_operands.size());
    for (const CSSMathExpressionNode* source_op : source_operands) {
      const CSSMathExpressionNode* dest_op =
          SubstituteForPercentages(source_op);
      dest_operands.push_back(dest_op);
    }

    return MakeGarbageCollected<CSSMathExpressionOperation>(
        operation->Category(), std::move(dest_operands),
        operation->OperatorType());
  }

  if (const auto* numeric_literal =
          DynamicTo<CSSMathExpressionNumericLiteral>(source)) {
    const CSSNumericLiteralValue& value = numeric_literal->GetValue();
    if (value.IsPercentage()) {
      return CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionKeywordLiteral::Create(
              CSSValueID::kSize,
              CSSMathExpressionKeywordLiteral::Context::kCalcSize),
          CSSMathExpressionNumericLiteral::Create(
              value.DoubleValue() / 100.0,
              CSSPrimitiveValue::UnitType::kNumber),
          CSSMathOperator::kMultiply);
    }
  }
  return source;
}

bool BasisIsCanonical(const CSSMathExpressionNode* basis) {
  // A basis is canonical if it is a sizing keyword, 'any', or '100%'.
  if (const auto* numeric_literal =
          DynamicTo<CSSMathExpressionNumericLiteral>(basis)) {
    const CSSNumericLiteralValue& value = numeric_literal->GetValue();
    return value.IsPercentage() &&
           value.IsHundred() == CSSMathFunctionValue::BoolStatus::kTrue;
  }

  if (const auto* keyword_literal =
          DynamicTo<CSSMathExpressionKeywordLiteral>(basis)) {
    return keyword_literal->GetContext() ==
           CSSMathExpressionKeywordLiteral::Context::kCalcSize;
  }

  return false;
}

// Do substitution in order to produce a calc-size() whose basis is not
// another calc-size() and is not in non-canonical form.
const CSSMathExpressionOperation* MakeBasisCanonical(
    const CSSMathExpressionOperation* calc_size_input) {
  DCHECK(calc_size_input->IsCalcSize());
  HeapVector<Member<const CSSMathExpressionNode>, 4> calculation_stack;
  const CSSMathExpressionNode* final_basis = nullptr;
  const CSSMathExpressionNode* current_result = nullptr;

  wtf_size_t substitution_count = 1;
  const CSSMathExpressionOperation* current_calc_size = calc_size_input;
  while (true) {
    // If the basis is a calc-size(), push the calculation on the stack, and
    // enter this loop again with its basis.
    const CSSMathExpressionNode* basis = current_calc_size->GetOperands()[0];
    const CSSMathExpressionNode* calculation =
        current_calc_size->GetOperands()[1];
    if (const CSSMathExpressionOperation* basis_calc_size =
            DynamicToCalcSize(basis)) {
      calculation_stack.push_back(calculation);
      current_calc_size = basis_calc_size;
      continue;
    }

    // If the basis is canonical, use it.
    if (BasisIsCanonical(basis)) {
      if (calculation_stack.empty()) {
        // No substitution is needed; return the original.
        return calc_size_input;
      }

      current_result = calculation;
      final_basis = basis;
      break;
    }

    // Otherwise, we have a <calc-sum>, and our canonical basis should be
    // '100%' if we have a percentage and 'any' if we don't.  The percentage
    // case also requires that we substitute (size * (P/100)) for P% in the
    // basis.
    if (basis->HasPercentage()) {
      basis = SubstituteForPercentages(basis);
      final_basis = CSSMathExpressionNumericLiteral::Create(
          100.0, CSSPrimitiveValue::UnitType::kPercentage);
    } else {
      final_basis = CSSMathExpressionKeywordLiteral::Create(
          CSSValueID::kAny,
          CSSMathExpressionKeywordLiteral::Context::kCalcSize);
    }
    CHECK_EQ(substitution_count, 1u);
    std::tie(current_result, substitution_count) =
        SubstituteForSizeKeyword(calculation, basis, 1u);
    break;
  }

  while (!calculation_stack.empty()) {
    std::tie(current_result, substitution_count) =
        SubstituteForSizeKeyword(calculation_stack.back(), current_result,
                                 std::max(substitution_count, 1u));
    if (!current_result) {
      // too much expansion
      return nullptr;
    }
    calculation_stack.pop_back();
  }

  return To<CSSMathExpressionOperation>(
      CSSMathExpressionOperation::CreateCalcSizeOperation(final_basis,
                                                          current_result));
}

}  // namespace

// static
CSSMathExpressionNode*
CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side,
    CSSMathOperator op) {
  DCHECK(op == CSSMathOperator::kAdd || op == CSSMathOperator::kSubtract ||
         op == CSSMathOperator::kMultiply || op == CSSMathOperator::kDivide);

  // Merge calc-size() expressions to keep calc-size() always at the top level.
  const CSSMathExpressionOperation* left_calc_size =
      DynamicToCalcSize(left_side);
  const CSSMathExpressionOperation* right_calc_size =
      DynamicToCalcSize(right_side);
  if (left_calc_size) {
    if (right_calc_size) {
      if (op != CSSMathOperator::kAdd && op != CSSMathOperator::kSubtract) {
        return nullptr;
      }
      // In theory we could check for basis equality or for one basis being
      // 'any' before we canonicalize to make some cases faster (and then
      // check again after).  However, the spec doesn't have this
      // optimization, and it is observable.

      // If either value has a non-canonical basis, substitute to produce a
      // canonical basis and try again recursively (with only one level of
      // recursion possible).
      //
      // We need to interpolate between the values *following* substitution of
      // the basis in the calculation, because if we interpolate the two
      // separately we are likely to get nonlinear interpolation behavior
      // (since we would be interpolating two different things linearly and
      // then multiplying them together).
      if (!BasisIsCanonical(left_calc_size->GetOperands()[0])) {
        left_calc_size = MakeBasisCanonical(left_calc_size);
        if (!left_calc_size) {
          return nullptr;  // hit the expansion limit
        }
      }
      if (!BasisIsCanonical(right_calc_size->GetOperands()[0])) {
        right_calc_size = MakeBasisCanonical(right_calc_size);
        if (!right_calc_size) {
          return nullptr;  // hit the expansion limit
        }
      }

      const CSSMathExpressionNode* left_basis =
          left_calc_size->GetOperands()[0];
      const CSSMathExpressionNode* right_basis =
          right_calc_size->GetOperands()[0];

      CHECK(BasisIsCanonical(left_basis));
      CHECK(BasisIsCanonical(right_basis));

      const CSSMathExpressionNode* final_basis = nullptr;
      // If the bases are equal, or one of them is the
      // any keyword, then we can interpolate only the calculations.
      auto is_any_keyword = [](const CSSMathExpressionNode* node) -> bool {
        const auto* literal = DynamicTo<CSSMathExpressionKeywordLiteral>(node);
        return literal && literal->GetValue() == CSSValueID::kAny &&
               literal->GetContext() ==
                   CSSMathExpressionKeywordLiteral::Context::kCalcSize;
      };

      if (*left_basis == *right_basis) {
        final_basis = left_basis;
      } else if (is_any_keyword(left_basis)) {
        final_basis = right_basis;
      } else if (is_any_keyword(right_basis)) {
        final_basis = left_basis;
      }
      if (!final_basis) {
        return nullptr;
      }
      const CSSMathExpressionNode* left_calculation =
          left_calc_size->GetOperands()[1];
      const CSSMathExpressionNode* right_calculation =
          right_calc_size->GetOperands()[1];
      return CreateCalcSizeOperation(
          final_basis, CreateArithmeticOperationSimplified(
                           left_calculation, right_calculation, op));
    } else {
      const CSSMathExpressionNode* left_basis =
          left_calc_size->GetOperands()[0];
      const CSSMathExpressionNode* left_calculation =
          left_calc_size->GetOperands()[1];
      return CreateCalcSizeOperation(
          left_basis, CreateArithmeticOperationSimplified(left_calculation,
                                                          right_side, op));
    }
  } else if (right_calc_size) {
    const CSSMathExpressionNode* right_basis =
        right_calc_size->GetOperands()[0];
    const CSSMathExpressionNode* right_calculation =
        right_calc_size->GetOperands()[1];
    return CreateCalcSizeOperation(
        right_basis,
        CreateArithmeticOperationSimplified(left_side, right_calculation, op));
  }

  return CreateArithmeticOperationSimplified(left_side, right_side, op);
}

CSSMathExpressionOperation::CSSMathExpressionOperation(
    const CSSMathExpressionNode* left_side,
    const CSSMathExpressionNode* right_side,
    CSSMathOperator op,
    CalculationResultCategory category)
    : CSSMathExpressionNode(
          category,
          left_side->HasComparisons() || right_side->HasComparisons(),
          left_side->HasAnchorFunctions() || right_side->HasAnchorFunctions(),
          !left_side->IsScopedValue() || !right_side->IsScopedValue()),
      operands_({left_side, right_side}),
      operator_(op) {}

bool CSSMathExpressionOperation::HasPercentage() const {
  if (Category() == kCalcPercent) {
    return true;
  }
  if (Category() != kCalcLengthFunction && Category() != kCalcIntrinsicSize) {
    return false;
  }
  switch (operator_) {
    case CSSMathOperator::kProgress:
      return false;
    case CSSMathOperator::kCalcSize:
      DCHECK_EQ(operands_.size(), 2u);
      return operands_[0]->HasPercentage();
    default:
      break;
  }
  for (const CSSMathExpressionNode* operand : operands_) {
    if (operand->HasPercentage()) {
      return true;
    }
  }
  return false;
}

bool CSSMathExpressionOperation::InvolvesLayout() const {
  if (Category() == kCalcPercent || Category() == kCalcLengthFunction) {
    return true;
  }
  for (const CSSMathExpressionNode* operand : operands_) {
    if (operand->InvolvesLayout()) {
      return true;
    }
  }
  return false;
}

static bool AnyOperandHasComparisons(
    CSSMathExpressionOperation::Operands& operands) {
  for (const CSSMathExpressionNode* operand : operands) {
    if (operand->HasComparisons()) {
      return true;
    }
  }
  return false;
}

static bool AnyOperandHasAnchorFunctions(
    CSSMathExpressionOperation::Operands& operands) {
  for (const CSSMathExpressionNode* operand : operands) {
    if (operand->HasAnchorFunctions()) {
      return true;
    }
  }
  return false;
}

static bool AnyOperandNeedsTreeScopePopulation(
    CSSMathExpressionOperation::Operands& operands) {
  for (const CSSMathExpressionNode* operand : operands) {
    if (!operand->IsScopedValue()) {
      return true;
    }
  }
  return false;
}

CSSMathExpressionOperation::CSSMathExpressionOperation(
    CalculationResultCategory category,
    Operands&& operands,
    CSSMathOperator op)
    : CSSMathExpressionNode(
          category,
          IsComparison(op) || AnyOperandHasComparisons(operands),
          AnyOperandHasAnchorFunctions(operands),
          AnyOperandNeedsTreeScopePopulation(operands)),
      operands_(std::move(operands)),
      operator_(op) {}

CSSMathExpressionOperation::CSSMathExpressionOperation(
    CalculationResultCategory category,
    CSSMathOperator op)
    : CSSMathExpressionNode(category,
                            IsComparison(op),
                            false /*has_anchor_functions*/,
                            false),
      operator_(op) {}

CSSPrimitiveValue::BoolStatus CSSMathExpressionOperation::ResolvesTo(
    double value) const {
  std::optional<double> maybe_value = ComputeValueInCanonicalUnit();
  if (!maybe_value.has_value()) {
    return CSSPrimitiveValue::BoolStatus::kUnresolvable;
  }
  return maybe_value.value() == value ? CSSPrimitiveValue::BoolStatus::kTrue
                                      : CSSPrimitiveValue::BoolStatus::kFalse;
}

CSSPrimitiveValue::BoolStatus CSSMathExpressionOperation::IsNegative() const {
  std::optional<double> maybe_value = ComputeValueInCanonicalUnit();
  if (!maybe_value.has_value()) {
    return CSSPrimitiveValue::BoolStatus::kUnresolvable;
  }
  return maybe_value.value() < 0.0 ? CSSPrimitiveValue::BoolStatus::kTrue
                                   : CSSPrimitiveValue::BoolStatus::kFalse;
}

std::optional<PixelsAndPercent> CSSMathExpressionOperation::ToPixelsAndPercent(
    const CSSLengthResolver& length_resolver) const {
  std::optional<PixelsAndPercent> result;
  switch (operator_) {
    case CSSMathOperator::kAdd:
    case CSSMathOperator::kSubtract: {
      DCHECK_EQ(operands_.size(), 2u);
      result = operands_[0]->ToPixelsAndPercent(length_resolver);
      if (!result) {
        return std::nullopt;
      }

      std::optional<PixelsAndPercent> other_side =
          operands_[1]->ToPixelsAndPercent(length_resolver);
      if (!other_side) {
        return std::nullopt;
      }
      if (operator_ == CSSMathOperator::kAdd) {
        result.value() += other_side.value();
      } else {
        result.value() -= other_side.value();
      }
      break;
    }
    case CSSMathOperator::kMultiply:
    case CSSMathOperator::kDivide: {
      DCHECK_EQ(operands_.size(), 2u);
      const CSSMathExpressionNode* number_side =
          GetNumericLiteralSide(operands_[0], operands_[1]);
      if (!number_side) {
        return std::nullopt;
      }
      const CSSMathExpressionNode* other_side =
          operands_[0] == number_side ? operands_[1] : operands_[0];
      result = other_side->ToPixelsAndPercent(length_resolver);
      if (!result) {
        return std::nullopt;
      }
      float number = number_side->DoubleValue();
      if (operator_ == CSSMathOperator::kDivide) {
        number = 1.0 / number;
      }
      result.value() *= number;
      break;
    }
    case CSSMathOperator::kCalcSize:
      // While it looks like we might be able to handle some calc-size() cases
      // here, we don't want to do because it would be difficult to avoid a
      // has_explicit_percent state inside the calculation propagating to the
      // result (which should not happen; only the has_explicit_percent state
      // from the basis should do so).
      return std::nullopt;
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
    case CSSMathOperator::kAbs:
    case CSSMathOperator::kSign:
    case CSSMathOperator::kProgress:
    case CSSMathOperator::kMediaProgress:
    case CSSMathOperator::kContainerProgress:
      return std::nullopt;
    case CSSMathOperator::kInvalid:
      NOTREACHED();
  }
  return result;
}

scoped_refptr<const CalculationExpressionNode>
CSSMathExpressionOperation::ToCalculationExpression(
    const CSSLengthResolver& length_resolver) const {
  switch (operator_) {
    case CSSMathOperator::kAdd:
      DCHECK_EQ(operands_.size(), 2u);
      return CalculationExpressionOperationNode::CreateSimplified(
          CalculationExpressionOperationNode::Children(
              {operands_[0]->ToCalculationExpression(length_resolver),
               operands_[1]->ToCalculationExpression(length_resolver)}),
          CalculationOperator::kAdd);
    case CSSMathOperator::kSubtract:
      DCHECK_EQ(operands_.size(), 2u);
      return CalculationExpressionOperationNode::CreateSimplified(
          CalculationExpressionOperationNode::Children(
              {operands_[0]->ToCalculationExpression(length_resolver),
               operands_[1]->ToCalculationExpression(length_resolver)}),
          CalculationOperator::kSubtract);
    case CSSMathOperator::kMultiply:
      DCHECK_EQ(operands_.size(), 2u);
      return CalculationExpressionOperationNode::CreateSimplified(
          {operands_.front()->ToCalculationExpression(length_resolver),
           operands_.back()->ToCalculationExpression(length_resolver)},
          CalculationOperator::kMultiply);
    case CSSMathOperator::kDivide:
      DCHECK_EQ(operands_.size(), 2u);
      return CalculationExpressionOperationNode::CreateSimplified(
          {operands_[0]->ToCalculationExpression(length_resolver),
           CalculationExpressionOperationNode::CreateSimplified(
               {operands_[1]->ToCalculationExpression(length_resolver)},
               CalculationOperator::kInvert)},
          CalculationOperator::kMultiply);
    case CSSMathOperator::kMin:
    case CSSMathOperator::kMax: {
      Vector<scoped_refptr<const CalculationExpressionNode>> operands;
      operands.reserve(operands_.size());
      for (const CSSMathExpressionNode* operand : operands_) {
        operands.push_back(operand->ToCalculationExpression(length_resolver));
      }
      auto expression_operator = operator_ == CSSMathOperator::kMin
                                     ? CalculationOperator::kMin
                                     : CalculationOperator::kMax;
      return CalculationExpressionOperationNode::CreateSimplified(
          std::move(operands), expression_operator);
    }
    case CSSMathOperator::kClamp: {
      Vector<scoped_refptr<const CalculationExpressionNode>> operands;
      operands.reserve(operands_.size());
      for (const CSSMathExpressionNode* operand : operands_) {
        operands.push_back(operand->ToCalculationExpression(length_resolver));
      }
      return CalculationExpressionOperationNode::CreateSimplified(
          std::move(operands), CalculationOperator::kClamp);
    }
    case CSSMathOperator::kRoundNearest:
    case CSSMathOperator::kRoundUp:
    case CSSMathOperator::kRoundDown:
    case CSSMathOperator::kRoundToZero:
    case CSSMathOperator::kMod:
    case CSSMathOperator::kRem:
    case CSSMathOperator::kHypot:
    case CSSMathOperator::kAbs:
    case CSSMathOperator::kSign:
    case CSSMathOperator::kProgress:
    case CSSMathOperator::kMediaProgress:
    case CSSMathOperator::kContainerProgress:
    case CSSMathOperator::kCalcSize: {
      Vector<scoped_refptr<const CalculationExpressionNode>> operands;
      operands.reserve(operands_.size());
      for (const CSSMathExpressionNode* operand : operands_) {
        operands.push_back(operand->ToCalculationExpression(length_resolver));
      }
      CalculationOperator op;
      if (operator_ == CSSMathOperator::kRoundNearest) {
        op = CalculationOperator::kRoundNearest;
      } else if (operator_ == CSSMathOperator::kRoundUp) {
        op = CalculationOperator::kRoundUp;
      } else if (operator_ == CSSMathOperator::kRoundDown) {
        op = CalculationOperator::kRoundDown;
      } else if (operator_ == CSSMathOperator::kRoundToZero) {
        op = CalculationOperator::kRoundToZero;
      } else if (operator_ == CSSMathOperator::kMod) {
        op = CalculationOperator::kMod;
      } else if (operator_ == CSSMathOperator::kRem) {
        op = CalculationOperator::kRem;
      } else if (operator_ == CSSMathOperator::kHypot) {
        op = CalculationOperator::kHypot;
      } else if (operator_ == CSSMathOperator::kAbs) {
        op = CalculationOperator::kAbs;
      } else if (operator_ == CSSMathOperator::kSign) {
        op = CalculationOperator::kSign;
      } else if (operator_ == CSSMathOperator::kProgress) {
        op = CalculationOperator::kProgress;
      } else if (operator_ == CSSMathOperator::kMediaProgress) {
        op = CalculationOperator::kMediaProgress;
      } else if (operator_ == CSSMathOperator::kContainerProgress) {
        op = CalculationOperator::kContainerProgress;
      } else {
        CHECK(operator_ == CSSMathOperator::kCalcSize);
        op = CalculationOperator::kCalcSize;
      }
      return CalculationExpressionOperationNode::CreateSimplified(
          std::move(operands), op);
    }
    case CSSMathOperator::kInvalid:
      NOTREACHED();
  }
}

double CSSMathExpressionOperation::DoubleValue() const {
  DCHECK(HasDoubleValue(ResolvedUnitType())) << CustomCSSText();
  Vector<double> double_values;
  double_values.reserve(operands_.size());
  for (const CSSMathExpressionNode* operand : operands_) {
    double_values.push_back(operand->DoubleValue());
  }
  return Evaluate(double_values);
}

static bool HasCanonicalUnit(CalculationResultCategory category) {
  return category == kCalcNumber || category == kCalcLength ||
         category == kCalcPercent || category == kCalcAngle ||
         category == kCalcTime || category == kCalcFrequency ||
         category == kCalcResolution;
}

std::optional<double> CSSMathExpressionOperation::ComputeValueInCanonicalUnit()
    const {
  if (!HasCanonicalUnit(category_)) {
    return std::nullopt;
  }

  Vector<double> double_values;
  double_values.reserve(operands_.size());
  for (const CSSMathExpressionNode* operand : operands_) {
    std::optional<double> maybe_value = operand->ComputeValueInCanonicalUnit();
    if (!maybe_value) {
      return std::nullopt;
    }
    double_values.push_back(*maybe_value);
  }
  return Evaluate(double_values);
}

std::optional<double> CSSMathExpressionOperation::ComputeValueInCanonicalUnit(
    const CSSLengthResolver& length_resolver) const {
  if (!HasCanonicalUnit(category_)) {
    return std::nullopt;
  }

  Vector<double> double_values;
  double_values.reserve(operands_.size());
  for (const CSSMathExpressionNode* operand : operands_) {
    std::optional<double> maybe_value =
        operand->ComputeValueInCanonicalUnit(length_resolver);
    if (!maybe_value.has_value()) {
      return std::nullopt;
    }
    double_values.push_back(maybe_value.value());
  }
  return Evaluate(double_values);
}

double CSSMathExpressionOperation::ComputeDouble(
    const CSSLengthResolver& length_resolver) const {
  Vector<double> double_values;
  double_values.reserve(operands_.size());
  for (const CSSMathExpressionNode* operand : operands_) {
    double_values.push_back(
        CSSMathExpressionNode::ComputeDouble(operand, length_resolver));
  }
  return Evaluate(double_values);
}

double CSSMathExpressionOperation::ComputeLengthPx(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(!HasPercentage());
  DCHECK_EQ(Category(), kCalcLength);
  return ComputeDouble(length_resolver);
}

bool CSSMathExpressionOperation::AccumulateLengthArray(
    CSSLengthArray& length_array,
    double multiplier) const {
  switch (operator_) {
    case CSSMathOperator::kAdd:
      DCHECK_EQ(operands_.size(), 2u);
      if (!operands_[0]->AccumulateLengthArray(length_array, multiplier)) {
        return false;
      }
      if (!operands_[1]->AccumulateLengthArray(length_array, multiplier)) {
        return false;
      }
      return true;
    case CSSMathOperator::kSubtract:
      DCHECK_EQ(operands_.size(), 2u);
      if (!operands_[0]->AccumulateLengthArray(length_array, multiplier)) {
        return false;
      }
      if (!operands_[1]->AccumulateLengthArray(length_array, -multiplier)) {
        return false;
      }
      return true;
    case CSSMathOperator::kMultiply:
      DCHECK_EQ(operands_.size(), 2u);
      DCHECK_NE((operands_[0]->Category() == kCalcNumber),
                (operands_[1]->Category() == kCalcNumber));
      if (operands_[0]->Category() == kCalcNumber) {
        return operands_[1]->AccumulateLengthArray(
            length_array, multiplier * operands_[0]->DoubleValue());
      } else {
        return operands_[0]->AccumulateLengthArray(
            length_array, multiplier * operands_[1]->DoubleValue());
      }
    case CSSMathOperator::kDivide:
      DCHECK_EQ(operands_.size(), 2u);
      DCHECK_EQ(operands_[1]->Category(), kCalcNumber);
      return operands_[0]->AccumulateLengthArray(
          length_array, multiplier / operands_[1]->DoubleValue());
    case CSSMathOperator::kMin:
    case CSSMathOperator::kMax:
    case CSSMathOperator::kClamp:
      // When comparison functions are involved, we can't resolve the expression
      // into a length array.
    case CSSMathOperator::kRoundNearest:
    case CSSMathOperator::kRoundUp:
    case CSSMathOperator::kRoundDown:
    case CSSMathOperator::kRoundToZero:
    case CSSMathOperator::kMod:
    case CSSMathOperator::kRem:
    case CSSMathOperator::kHypot:
    case CSSMathOperator::kAbs:
    case CSSMathOperator::kSign:
      // When stepped value functions are involved, we can't resolve the
      // expression into a length array.
    case CSSMathOperator::kProgress:
    case CSSMathOperator::kCalcSize:
    case CSSMathOperator::kMediaProgress:
    case CSSMathOperator::kContainerProgress:
      return false;
    case CSSMathOperator::kInvalid:
      NOTREACHED();
  }
}

void CSSMathExpressionOperation::AccumulateLengthUnitTypes(
    CSSPrimitiveValue::LengthTypeFlags& types) const {
  for (const CSSMathExpressionNode* operand : operands_) {
    operand->AccumulateLengthUnitTypes(types);
  }
}

bool CSSMathExpressionOperation::IsComputationallyIndependent() const {
  for (const CSSMathExpressionNode* operand : operands_) {
    if (!operand->IsComputationallyIndependent()) {
      return false;
    }
  }
  return true;
}

String CSSMathExpressionOperation::CustomCSSText() const {
  switch (operator_) {
    case CSSMathOperator::kAdd:
    case CSSMathOperator::kSubtract:
    case CSSMathOperator::kMultiply:
    case CSSMathOperator::kDivide: {
      DCHECK_EQ(operands_.size(), 2u);

      // As per
      // https://drafts.csswg.org/css-values-4/#sort-a-calculations-children
      // we should sort the dimensions of the sum node.
      const CSSMathExpressionOperation* operation = this;
      if (IsAddOrSubtract()) {
        const CSSMathExpressionNode* node = MaybeSortSumNode(this);
        // Note: we can hit here, since CSS Typed OM doesn't currently follow
        // the same simplifications as CSS Values spec.
        // https://github.com/w3c/csswg-drafts/issues/9451
        if (!node->IsOperation()) {
          return node->CustomCSSText();
        }
        operation = To<CSSMathExpressionOperation>(node);
      }
      CSSMathOperator op = operation->OperatorType();
      const Operands& operands = operation->GetOperands();

      StringBuilder result;

      // After all the simplifications we only need parentheses here for the
      // cases like: (lhs as unsimplified sum/sub) [* or /] rhs
      const bool left_side_needs_parentheses =
          IsMultiplyOrDivide() && operands.front()->IsOperation() &&
          To<CSSMathExpressionOperation>(operands.front().Get())
              ->IsAddOrSubtract();
      if (left_side_needs_parentheses) {
        result.Append('(');
      }
      result.Append(ope
"""


```