Response:
Let's break down the thought process for analyzing this code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for the functionality of the `calculation_expression_node.cc` file in the Chromium Blink rendering engine. Specifically, it wants to know its relationship to web technologies (JavaScript, HTML, CSS), see examples of logic, and identify common usage errors.

2. **Initial Skim and Keyword Recognition:**  Read through the code quickly, looking for key terms and patterns. Immediately, terms like "CalculationExpression," "NumberNode," "SizingKeywordNode," "PixelsAndPercentNode," "OperationNode," and operators like "Add," "Subtract," "Multiply," "Min," "Max," etc., stand out. The namespace `blink` confirms it's part of the rendering engine. The `#include` directives tell us about dependencies (like `Length`).

3. **Identify Core Concepts:**  The class names strongly suggest that this code is about representing and evaluating mathematical expressions, specifically those involving calculations of lengths, sizes, and potentially other numeric values in the context of web page rendering. The "Node" suffix indicates a tree-like structure for representing these expressions.

4. **Analyze Each Class/Structure:**  Go through each class defined in the file and understand its purpose:

    * **`CalculationExpressionNumberNode`:**  Represents a simple numeric value. The `Evaluate` method directly returns the stored value. The `Zoom` method suggests scaling.
    * **`CalculationExpressionSizingKeywordNode`:**  Handles keywords like `auto`, `content`, `min-content`, `max-content`, `fit-content`, `stretch`. These are crucial for CSS layout. The `Evaluate` method shows how these keywords are translated into numeric values based on the `EvaluationInput`.
    * **`CalculationExpressionColorChannelKeywordNode`:**  Represents keywords related to color channels (not explicitly used in the provided example but present). The `Evaluate` method shows it retrieves values from the `EvaluationInput`.
    * **`CalculationExpressionPixelsAndPercentNode`:** Represents a value that can be a combination of pixels and percentages. The `Evaluate` method calculates the final value based on a `max_value` (likely the context size). The `Zoom` method shows scaling of pixel values.
    * **`CalculationExpressionOperationNode`:**  Represents mathematical operations (add, subtract, multiply, min, max, etc.) on other `CalculationExpressionNode` objects. The `CreateSimplified` static method hints at optimization by simplifying expressions. The `Evaluate` method recursively evaluates the operands and applies the operation. The `Zoom` method handles scaling differently based on the operation.

5. **Connect to Web Technologies:**  Based on the identified concepts, start connecting them to HTML, CSS, and JavaScript:

    * **CSS:** The keywords in `CalculationExpressionSizingKeywordNode` directly correspond to CSS sizing keywords. The combination of pixels and percentages in `CalculationExpressionPixelsAndPercentNode` is a fundamental concept in CSS lengths. The operations in `CalculationExpressionOperationNode` are used to implement CSS `calc()` and related functions like `min()`, `max()`, `clamp()`, etc.
    * **HTML:**  While not directly manipulating HTML structure, the calculations performed by this code determine the layout and size of HTML elements.
    * **JavaScript:** JavaScript can interact with CSS properties, including those using `calc()` and related functions. The results of these calculations influence how JavaScript interacts with the DOM and performs animations or other dynamic behavior.

6. **Identify Logic and Examples:**  Focus on the `Evaluate` methods and the `CreateSimplified` method:

    * **`Evaluate`:**  For each node type, trace how the evaluation works. Pay attention to how `max_value` is used (especially for percentages) and how `EvaluationInput` provides context.
    * **`CreateSimplified`:** This is where the core logic for optimization resides. Go through each `case` in the `switch` statement and understand how it tries to simplify expressions involving `PixelsAndPercentNode` and `NumberNode`. Formulate "Assume input..." and "Output..." examples to illustrate these simplifications.

7. **Consider Common Usage Errors:** Think about how developers might misuse CSS `calc()` and related functions:

    * **Type Mismatches:**  Trying to add incompatible units (though this code aims to handle pixels and percentages specifically).
    * **Division by Zero:** Though not explicitly checked for in all cases, it's a potential error.
    * **Incorrect Nesting:**  While the code handles nesting, overly complex or nonsensical nesting could lead to unexpected results.
    * **Forgetting Context (for percentages):**  Percentages are relative to something. Forgetting or miscalculating that context is a common error.

8. **Structure the Explanation:** Organize the findings logically:

    * Start with a high-level summary of the file's purpose.
    * Detail the functionality of each class.
    * Explain the relationship to JavaScript, HTML, and CSS with concrete examples.
    * Provide specific examples of logic and their inputs/outputs.
    * List common usage errors with examples.

9. **Refine and Review:**  Read through the generated explanation. Ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Make sure the examples are easy to understand. Ensure the explanation directly addresses all parts of the original request. For instance, explicitly mention the file's role in implementing CSS `calc()` and related functions.

Self-Correction Example during the process:  Initially, I might focus too much on the individual node types. Then, I'd realize that the key is how these nodes work together to represent and evaluate expressions. I would then shift the focus to the `Evaluate` methods and the `CreateSimplified` method, as these demonstrate the dynamic nature of the calculations. I might also initially miss the connection to specific CSS functions like `min()`, `max()`, and `clamp()` and would need to go back and explicitly make those links. Similarly, I might initially overlook the nuances of how `max_value` and `EvaluationInput` provide context, and would need to refine the explanation to cover those aspects.
这个文件 `calculation_expression_node.cc` 是 Chromium Blink 渲染引擎中负责处理 CSS `calc()` 函数以及其他类似数学表达式的核心组件。它定义了用于表示和计算这些表达式的节点结构。

**主要功能:**

1. **表示计算表达式:**
   - 定义了不同类型的节点，用于表示计算表达式的不同部分，例如数字、关键字、带单位的值（像素和百分比）以及操作符。
   - 这些节点形成一个树状结构，反映了计算表达式的语法结构。

2. **计算表达式求值:**
   - 提供了 `Evaluate` 方法，用于根据给定的上下文（例如，最大可用空间）计算表达式的最终值。
   - 不同的节点类型有不同的 `Evaluate` 实现，以处理各自的求值逻辑。

3. **表达式简化:**
   - 包含 `CreateSimplified` 方法，用于在可能的情况下对计算表达式进行静态简化，例如，将多个像素值相加，或者在编译时执行某些乘法运算。这可以提高运行时性能。

4. **支持各种 CSS 数学函数:**
   - 实现了对 CSS `calc()`, `min()`, `max()`, `clamp()`, `round()`, `mod()`, `rem()`, `hypot()`, `abs()`, `sign()`, 以及一些实验性的进度相关函数 (如 `progress`, `media-progress`, `container-progress`) 的支持。
   - 每个函数都对应着 `CalculationExpressionOperationNode` 中的一个 `CalculationOperator` 枚举值。

5. **处理不同类型的单位:**
   - 主要处理像素 (`px`) 和百分比 (`%`) 单位的组合，并能根据上下文中的最大值正确地计算百分比。
   - 也支持像 `auto`, `content`, `min-content`, `max-content`, `fit-content`, `stretch` 这样的尺寸关键字。

6. **支持缩放 (Zoom):**
   - 提供了 `Zoom` 方法，用于在页面缩放时调整表达式的值，主要针对像素值进行缩放。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

- **CSS:** 这个文件是实现 CSS `calc()` 和相关数学函数的关键部分。
    - **举例:**  当你写 CSS `width: calc(100% - 20px);` 时，解析器会将这个表达式转换为由 `CalculationExpressionOperationNode` (减法) 和 `CalculationExpressionPixelsAndPercentNode` (100%) 以及 `CalculationExpressionNumberNode` (20px) 组成的树。`Evaluate` 方法会在布局过程中被调用，根据父元素的宽度计算出元素的最终宽度。
    - **尺寸关键字:** 当你使用 `width: min-content;` 时，`CalculationExpressionSizingKeywordNode` 会被创建，并且它的 `Evaluate` 方法会调用合适的内部机制来确定元素的最小内容宽度。
    - **数学函数:**  `height: max(100px, 50%);`  会被解析成一个 `CalculationExpressionOperationNode` (max 操作)，其子节点是表示 `100px` 和 `50%` 的节点。`Evaluate` 方法会比较这两个值并返回较大的那个。

- **HTML:**  虽然这个文件不直接操作 HTML 结构，但它计算出的样式值会直接影响 HTML 元素的布局和渲染。
    - **举例:**  `calc()` 计算出的 `width` 值最终会应用到 HTML 元素上，决定其在页面上的宽度。

- **JavaScript:**  JavaScript 可以通过 `getComputedStyle` 获取使用了 `calc()` 的元素的最终计算值。虽然 JavaScript 不会直接操作这些节点，但它能感知到 `calc()` 的效果。此外，在某些复杂的动画或交互中，JavaScript 可能会间接地触发重新计算样式，从而调用到这个文件中的代码。
    - **举例:**  一个 JavaScript 动画可能会改变一个元素的父元素的宽度，这会导致使用了百分比的 `calc()` 表达式重新求值。

**逻辑推理和假设输入与输出:**

- **假设输入 (CSS):** `width: calc(50px + 25px);`
  - **内部表示:** 创建一个 `CalculationExpressionOperationNode` (加法)，其子节点是两个 `CalculationExpressionNumberNode` 分别表示 50 和 25。
  - **`Evaluate` 调用:**  `Evaluate` 方法被调用，`max_value` 参数在这里不重要，因为都是像素值。
  - **输出:** `Evaluate` 方法返回 `75` (float)。

- **假设输入 (CSS):** `width: calc(50% - 10px);`，假设父元素宽度为 `200px`。
  - **内部表示:** 创建一个 `CalculationExpressionOperationNode` (减法)，其子节点是 `CalculationExpressionPixelsAndPercentNode` (50%) 和 `CalculationExpressionNumberNode` (10)。
  - **`Evaluate` 调用:** `Evaluate` 方法被调用，`max_value` 参数为 `200`。
  - **输出:** `Evaluate` 方法首先计算 `50%` 为 `0.5 * 200 = 100`，然后减去 `10`，最终返回 `90` (float)。

- **假设输入 (CSS):** `width: min(100px, 80px);`
  - **内部表示:** 创建一个 `CalculationExpressionOperationNode` (min 操作)，其子节点是两个 `CalculationExpressionNumberNode` 分别表示 100 和 80。
  - **`Evaluate` 调用:** `Evaluate` 方法被调用。
  - **输出:** `Evaluate` 方法比较 100 和 80，返回 `80` (float)。

**用户或编程常见的使用错误:**

1. **类型不匹配的运算:**  虽然 `calc()` 允许不同单位的混合运算，但某些组合是没有意义的，或者会导致意外的结果。
   - **举例:**  `calc(100px * 50%)` 在 CSS Values and Units Module Level 4 中是无效的，除非其中一个操作数是无单位的数字。旧的规范可能允许，但行为可能不明确。

2. **除数为零:**  在 `calc()` 中进行除法运算时，如果除数最终计算结果为零，会导致问题。
   - **举例:** `width: calc(100px / 0);` 这会导致解析错误或未定义的行为。

3. **过度复杂的嵌套:**  虽然 `calc()` 允许嵌套，但过度复杂的嵌套可能会降低性能或使代码难以理解。

4. **忘记百分比的上下文:** 百分比值是相对于某个参考值的，如果在没有明确上下文的情况下使用百分比，可能会得到意想不到的结果。
   - **举例:**  在元素的 `width` 中使用百分比通常是相对于父元素的宽度，但在其他属性中可能有不同的含义。

5. **与不支持的单位或函数混合使用:**  `calc()` 内部的运算应该使用支持的单位和函数。使用不支持的单位或函数会导致解析错误。

总而言之，`calculation_expression_node.cc` 是 Blink 渲染引擎中一个至关重要的文件，它负责解析、表示和计算 CSS 数学表达式，直接影响着网页的布局和渲染效果。理解其功能有助于开发者更好地理解 CSS `calc()` 以及相关函数的内部工作原理。

Prompt: 
```
这是目录为blink/renderer/platform/geometry/calculation_expression_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/geometry/calculation_expression_node.h"

#include <cfloat>
#include <numeric>

#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/geometry/math_functions.h"

namespace blink {

// ------ CalculationExpressionNumberNode ------

float CalculationExpressionNumberNode::Evaluate(float max_value,
                                                const EvaluationInput&) const {
  return value_;
}

bool CalculationExpressionNumberNode::Equals(
    const CalculationExpressionNode& other) const {
  auto* other_number = DynamicTo<CalculationExpressionNumberNode>(other);
  if (!other_number) {
    return false;
  }
  return value_ == other_number->Value();
}

scoped_refptr<const CalculationExpressionNode>
CalculationExpressionNumberNode::Zoom(double) const {
  return base::MakeRefCounted<CalculationExpressionNumberNode>(value_);
}

#if DCHECK_IS_ON()
CalculationExpressionNode::ResultType
CalculationExpressionNumberNode::ResolvedResultType() const {
  return result_type_;
}
#endif

// ------ CalculationExpressionSizingKeywordNode ------

CalculationExpressionSizingKeywordNode::CalculationExpressionSizingKeywordNode(
    Keyword keyword)
    : keyword_(keyword) {
  if (keyword != Keyword::kSize && keyword != Keyword::kAny) {
    if (keyword == Keyword::kAuto) {
      has_auto_ = true;
    } else if (keyword == Keyword::kWebkitFillAvailable ||
               keyword == Keyword::kStretch) {
      has_stretch_ = true;
    } else {
      has_content_or_intrinsic_ = true;
    }
  }
#if DCHECK_IS_ON()
  result_type_ = ResultType::kPixelsAndPercent;
#endif
}

float CalculationExpressionSizingKeywordNode::Evaluate(
    float max_value,
    const EvaluationInput& input) const {
  Length::Type intrinsic_type = Length::kFixed;
  switch (keyword_) {
    case Keyword::kSize:
      CHECK(input.size_keyword_basis);
      return *input.size_keyword_basis;
    case Keyword::kAny:
      return 0.0f;
    case Keyword::kAuto:
      intrinsic_type = Length::Type::kAuto;
      break;
    case Keyword::kContent:
      intrinsic_type =
          input.calc_size_keyword_behavior == CalcSizeKeywordBehavior::kAsAuto
              ? Length::Type::kAuto
              : Length::Type::kContent;
      break;
    case Keyword::kMinContent:
    case Keyword::kWebkitMinContent:
      CHECK_EQ(input.calc_size_keyword_behavior,
               CalcSizeKeywordBehavior::kAsSpecified);
      intrinsic_type = Length::Type::kMinContent;
      break;
    case Keyword::kMaxContent:
    case Keyword::kWebkitMaxContent:
      CHECK_EQ(input.calc_size_keyword_behavior,
               CalcSizeKeywordBehavior::kAsSpecified);
      intrinsic_type = Length::Type::kMaxContent;
      break;
    case Keyword::kFitContent:
    case Keyword::kWebkitFitContent:
      intrinsic_type =
          input.calc_size_keyword_behavior == CalcSizeKeywordBehavior::kAsAuto
              ? Length::Type::kAuto
              : Length::Type::kFitContent;
      break;
    case Keyword::kStretch:
    case Keyword::kWebkitFillAvailable:
      intrinsic_type =
          input.calc_size_keyword_behavior == CalcSizeKeywordBehavior::kAsAuto
              ? Length::Type::kAuto
              : Length::Type::kStretch;
      break;
  }

  if (!input.intrinsic_evaluator) {
    // TODO(https://crbug.com/313072): I'd like to be able to CHECK() this
    // instead.  However, we hit this code in three cases:
    //  * the code in ContentMinimumInlineSize, which passes max_value of 0
    //  * the (questionable) code in EvaluateValueIfNaNorInfinity(), which
    //    passes max_value of 1 or -1
    //  * the DCHECK()s in
    //    CSSLengthInterpolationType::ApplyStandardPropertyValue pass a max
    //    value of 100
    // So we have to return something.  Return 0 for now, though this may
    // not be ideal.
    CHECK(max_value == 1.0f || max_value == -1.0f || max_value == 0.0f ||
          max_value == 100.0f);
    return 0.0f;
  }
  CHECK(input.intrinsic_evaluator);
  return (*input.intrinsic_evaluator)(Length(intrinsic_type));
}

// ------ CalculationExpressionColorChannelKeywordNode ------

CalculationExpressionColorChannelKeywordNode::
    CalculationExpressionColorChannelKeywordNode(ColorChannelKeyword channel)
    : channel_(channel) {}

float CalculationExpressionColorChannelKeywordNode::Evaluate(
    float max_value,
    const EvaluationInput& evaluation_input) const {
  // If the calling code hasn't set up the input environment, then always
  // return zero.
  if (evaluation_input.color_channel_keyword_values.empty()) {
    return 0;
  }
  return evaluation_input.color_channel_keyword_values.at(channel_);
}

// ------ CalculationExpressionPixelsAndPercentNode ------

float CalculationExpressionPixelsAndPercentNode::Evaluate(
    float max_value,
    const EvaluationInput&) const {
  return value_.pixels + value_.percent / 100 * max_value;
}

bool CalculationExpressionPixelsAndPercentNode::Equals(
    const CalculationExpressionNode& other) const {
  auto* other_pixels_and_percent =
      DynamicTo<CalculationExpressionPixelsAndPercentNode>(other);
  if (!other_pixels_and_percent) {
    return false;
  }
  return value_.pixels == other_pixels_and_percent->value_.pixels &&
         value_.percent == other_pixels_and_percent->value_.percent;
}

scoped_refptr<const CalculationExpressionNode>
CalculationExpressionPixelsAndPercentNode::Zoom(double factor) const {
  PixelsAndPercent result(value_.pixels * factor, value_.percent,
                          value_.has_explicit_pixels,
                          value_.has_explicit_percent);
  return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
      result);
}

#if DCHECK_IS_ON()
CalculationExpressionNode::ResultType
CalculationExpressionPixelsAndPercentNode::ResolvedResultType() const {
  return result_type_;
}
#endif

// ------ CalculationExpressionOperationNode ------

// static
scoped_refptr<const CalculationExpressionNode>
CalculationExpressionOperationNode::CreateSimplified(Children&& children,
                                                    CalculationOperator op) {
  switch (op) {
    case CalculationOperator::kAdd:
    case CalculationOperator::kSubtract: {
      DCHECK_EQ(children.size(), 2u);
      if (!children[0]->IsPixelsAndPercent() ||
          !children[1]->IsPixelsAndPercent()) {
        return base::MakeRefCounted<CalculationExpressionOperationNode>(
            Children({std::move(children[0]), std::move(children[1])}), op);
      }
      const auto& left_pixels_and_percent =
          To<CalculationExpressionPixelsAndPercentNode>(*children[0]);
      PixelsAndPercent right_pixels_and_percent =
          To<CalculationExpressionPixelsAndPercentNode>(*children[1])
              .GetPixelsAndPercent();
      PixelsAndPercent value = left_pixels_and_percent.GetPixelsAndPercent();
      if (op == CalculationOperator::kAdd) {
        value += right_pixels_and_percent;
      } else {
        value -= right_pixels_and_percent;
      }
      return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
          value);
    }
    case CalculationOperator::kMultiply: {
      DCHECK_EQ(children.size(), 2u);
      if (children.front()->IsOperation() || children.back()->IsOperation()) {
        return base::MakeRefCounted<CalculationExpressionOperationNode>(
            Children({std::move(children[0]), std::move(children[1])}), op);
      }
      auto& maybe_pixels_and_percent_node =
          children[0]->IsNumber() ? children[1] : children[0];
      if (!maybe_pixels_and_percent_node->IsPixelsAndPercent()) {
        return base::MakeRefCounted<CalculationExpressionOperationNode>(
            Children({std::move(children[0]), std::move(children[1])}), op);
      }
      auto& number_node = children[0]->IsNumber() ? children[0] : children[1];
      const auto& number = To<CalculationExpressionNumberNode>(*number_node);
      PixelsAndPercent pixels_and_percent =
          To<CalculationExpressionPixelsAndPercentNode>(
              *maybe_pixels_and_percent_node)
              .GetPixelsAndPercent();
      pixels_and_percent *= number.Value();
      return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
          pixels_and_percent);
    }
    case CalculationOperator::kInvert: {
      DCHECK_EQ(children.size(), 1u);
      auto* number = DynamicTo<CalculationExpressionNumberNode>(*children[0]);
      if (number) {
        return base::MakeRefCounted<CalculationExpressionNumberNode>(
            1.0 / number->Value());
      }
      return base::MakeRefCounted<CalculationExpressionOperationNode>(
          Children({std::move(children[0])}), op);
    }
    case CalculationOperator::kMin:
    case CalculationOperator::kMax: {
      DCHECK(children.size());
      float simplified_px;
      bool can_simplify = true;
      for (wtf_size_t i = 0; i < children.size(); ++i) {
        const auto* pixels_and_percent =
            DynamicTo<CalculationExpressionPixelsAndPercentNode>(*children[i]);
        if (!pixels_and_percent || pixels_and_percent->Percent()) {
          can_simplify = false;
          break;
        }
        if (!i) {
          simplified_px = pixels_and_percent->Pixels();
        } else {
          if (op == CalculationOperator::kMin) {
            simplified_px =
                std::min(simplified_px, pixels_and_percent->Pixels());
          } else {
            simplified_px =
                std::max(simplified_px, pixels_and_percent->Pixels());
          }
        }
      }
      if (can_simplify) {
        return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
            PixelsAndPercent(simplified_px));
      }
      return base::MakeRefCounted<CalculationExpressionOperationNode>(
          std::move(children), op);
    }
    case CalculationOperator::kClamp: {
      DCHECK_EQ(children.size(), 3u);
      Vector<float> operand_pixels;
      operand_pixels.reserve(children.size());
      bool can_simplify = true;
      for (auto& child : children) {
        const auto* pixels_and_percent =
            DynamicTo<CalculationExpressionPixelsAndPercentNode>(*child);
        if (!pixels_and_percent || pixels_and_percent->Percent()) {
          can_simplify = false;
          break;
        }
        operand_pixels.push_back(pixels_and_percent->Pixels());
      }
      if (can_simplify) {
        float min_px = operand_pixels[0];
        float val_px = operand_pixels[1];
        float max_px = operand_pixels[2];
        // clamp(MIN, VAL, MAX) is identical to max(MIN, min(VAL, MAX))
        // according to the spec,
        // https://drafts.csswg.org/css-values-4/#funcdef-clamp.
        float clamped_px = std::max(min_px, std::min(val_px, max_px));
        return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
            PixelsAndPercent(clamped_px));
      }
      return base::MakeRefCounted<CalculationExpressionOperationNode>(
          std::move(children), op);
    }
    case CalculationOperator::kRoundNearest:
    case CalculationOperator::kRoundUp:
    case CalculationOperator::kRoundDown:
    case CalculationOperator::kRoundToZero:
    case CalculationOperator::kMod:
    case CalculationOperator::kRem: {
      DCHECK_EQ(children.size(), 2u);
      const auto* a =
          DynamicTo<CalculationExpressionPixelsAndPercentNode>(*children[0]);
      const auto* b =
          DynamicTo<CalculationExpressionPixelsAndPercentNode>(*children[1]);
      bool can_simplify = a && !a->Percent() && b && !b->Percent();
      if (can_simplify) {
        float value =
            EvaluateSteppedValueFunction(op, a->Pixels(), b->Pixels());
        return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
            PixelsAndPercent(value));
      } else {
        return base::MakeRefCounted<CalculationExpressionOperationNode>(
            std::move(children), op);
      }
    }
    case CalculationOperator::kHypot: {
      DCHECK_GE(children.size(), 1u);
      Vector<float> operand_pixels;
      operand_pixels.reserve(children.size());
      bool can_simplify = true;
      for (auto& child : children) {
        const auto* pixels_and_percent =
            DynamicTo<CalculationExpressionPixelsAndPercentNode>(*child);
        if (!pixels_and_percent || pixels_and_percent->Percent()) {
          can_simplify = false;
          break;
        }
        operand_pixels.push_back(pixels_and_percent->Pixels());
      }
      if (can_simplify) {
        float value = 0;
        for (float operand : operand_pixels) {
          value = std::hypot(value, operand);
        }
        return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
            PixelsAndPercent(value));
      }
      return base::MakeRefCounted<CalculationExpressionOperationNode>(
          std::move(children), op);
    }
    case CalculationOperator::kAbs:
    case CalculationOperator::kSign: {
      DCHECK_EQ(children.size(), 1u);
      const auto* pixels_and_percent =
          DynamicTo<CalculationExpressionPixelsAndPercentNode>(
              *children.front());
      if (!pixels_and_percent || pixels_and_percent->Percent()) {
        return base::MakeRefCounted<CalculationExpressionOperationNode>(
            std::move(children), op);
      } else {
        float value = pixels_and_percent->Pixels();
        if (op == CalculationOperator::kAbs) {
          return base::MakeRefCounted<
              CalculationExpressionPixelsAndPercentNode>(
              PixelsAndPercent(std::abs(value)));
        } else {
          if (value == 0 || std::isnan(value)) {
            return base::MakeRefCounted<CalculationExpressionNumberNode>(value);
          }
          return base::MakeRefCounted<CalculationExpressionNumberNode>(
              value > 0 ? 1 : -1);
        }
      }
    }
    case CalculationOperator::kProgress:
    case CalculationOperator::kMediaProgress:
    case CalculationOperator::kContainerProgress: {
      DCHECK_EQ(children.size(), 3u);
      Vector<float, 3> operand_pixels;
      bool can_simplify = true;
      for (scoped_refptr<const CalculationExpressionNode>& child : children) {
        const auto* pixels_and_percent =
            DynamicTo<CalculationExpressionPixelsAndPercentNode>(*child);
        if (!pixels_and_percent || pixels_and_percent->Percent()) {
          can_simplify = false;
          break;
        }
        operand_pixels.push_back(pixels_and_percent->Pixels());
      }
      if (can_simplify) {
        float progress_px = operand_pixels[0];
        float from_px = operand_pixels[1];
        float to_px = operand_pixels[2];
        float progress = (progress_px - from_px) / (to_px - from_px);
        return base::MakeRefCounted<CalculationExpressionPixelsAndPercentNode>(
            PixelsAndPercent(progress));
      }
      return base::MakeRefCounted<CalculationExpressionOperationNode>(
          std::move(children), op);
    }
    case CalculationOperator::kCalcSize: {
      DCHECK_EQ(children.size(), 2u);
      // TODO(https://crbug.com/313072): It may be worth implementing
      // simplification for calc-size(), but it's not likely to be possible to
      // simplify calc-size() in any of its real use cases.
      return base::MakeRefCounted<CalculationExpressionOperationNode>(
          std::move(children), op);
    }
    case CalculationOperator::kInvalid:
      NOTREACHED();
  }
}

CalculationExpressionOperationNode::CalculationExpressionOperationNode(
    Children&& children,
    CalculationOperator op)
    : children_(std::move(children)), operator_(op) {
#if DCHECK_IS_ON()
  result_type_ = ResolvedResultType();
  DCHECK_NE(result_type_, ResultType::kInvalid);
#endif
  if (op == CalculationOperator::kCalcSize) {
    // "A calc-size() is treated, in all respects, as if it were its
    // calc-size basis."  This is particularly relevant for ignoring the
    // presence of percentages in the calculation.
    CHECK_EQ(children_.size(), 2u);
    const auto& basis = children_[0];
    has_content_or_intrinsic_ = basis->HasContentOrIntrinsicSize();
    has_auto_ = basis->HasAuto();
    has_percent_ = basis->HasPercent();
    has_stretch_ = basis->HasStretch();
#if DCHECK_IS_ON()
    {
      const auto& calculation = children_[1];
      DCHECK(!calculation->HasAuto());
      DCHECK(!calculation->HasContentOrIntrinsicSize());
      DCHECK(!calculation->HasStretch());
    }
#endif
  } else {
    for (const auto& child : children_) {
      DCHECK(!child->HasAuto());
      DCHECK(!child->HasContentOrIntrinsicSize());
      DCHECK(!child->HasStretch());
      if (child->HasPercent()) {
        has_percent_ = true;
      }
    }
  }
}

float CalculationExpressionOperationNode::Evaluate(
    float max_value,
    const EvaluationInput& input) const {
  switch (operator_) {
    case CalculationOperator::kAdd: {
      DCHECK_EQ(children_.size(), 2u);
      float left = children_[0]->Evaluate(max_value, input);
      float right = children_[1]->Evaluate(max_value, input);
      return left + right;
    }
    case CalculationOperator::kSubtract: {
      DCHECK_EQ(children_.size(), 2u);
      float left = children_[0]->Evaluate(max_value, input);
      float right = children_[1]->Evaluate(max_value, input);
      return left - right;
    }
    case CalculationOperator::kMultiply: {
      DCHECK_EQ(children_.size(), 2u);
      float left = children_[0]->Evaluate(max_value, input);
      float right = children_[1]->Evaluate(max_value, input);
      return left * right;
    }
    case CalculationOperator::kInvert: {
      DCHECK_EQ(children_.size(), 1u);
      float denominator = children_[0]->Evaluate(max_value, input);
      return 1.0 / denominator;
    }
    case CalculationOperator::kMin: {
      DCHECK(!children_.empty());
      float minimum = children_[0]->Evaluate(max_value, input);
      for (auto& child : children_) {
        minimum = std::min(minimum, child->Evaluate(max_value, input));
      }
      return minimum;
    }
    case CalculationOperator::kMax: {
      DCHECK(!children_.empty());
      float maximum = children_[0]->Evaluate(max_value, input);
      for (auto& child : children_) {
        maximum = std::max(maximum, child->Evaluate(max_value, input));
      }
      return maximum;
    }
    case CalculationOperator::kClamp: {
      DCHECK(!children_.empty());
      float min = children_[0]->Evaluate(max_value, input);
      float val = children_[1]->Evaluate(max_value, input);
      float max = children_[2]->Evaluate(max_value, input);
      // clamp(MIN, VAL, MAX) is identical to max(MIN, min(VAL, MAX))
      return std::max(min, std::min(val, max));
    }
    case CalculationOperator::kRoundNearest:
    case CalculationOperator::kRoundUp:
    case CalculationOperator::kRoundDown:
    case CalculationOperator::kRoundToZero:
    case CalculationOperator::kMod:
    case CalculationOperator::kRem: {
      DCHECK_EQ(children_.size(), 2u);
      float a = children_[0]->Evaluate(max_value, input);
      float b = children_[1]->Evaluate(max_value, input);
      return EvaluateSteppedValueFunction(operator_, a, b);
    }
    case CalculationOperator::kHypot: {
      DCHECK_GE(children_.size(), 1u);
      float value = 0;
      for (scoped_refptr<const CalculationExpressionNode> operand : children_) {
        float a = operand->Evaluate(max_value, input);
        value = std::hypot(value, a);
      }
      return value;
    }
    case CalculationOperator::kAbs:
    case CalculationOperator::kSign: {
      DCHECK_EQ(children_.size(), 1u);
      const float value = children_.front()->Evaluate(max_value, input);
      if (operator_ == CalculationOperator::kAbs) {
        return std::abs(value);
      } else {
        if (value == 0 || std::isnan(value)) {
          return value;
        }
        return value > 0 ? 1 : -1;
      }
    }
    case CalculationOperator::kCalcSize: {
      DCHECK_EQ(children_.size(), 2u);
      EvaluationInput calculation_input(input);
      calculation_input.size_keyword_basis =
          children_[0]->Evaluate(max_value, input);
      if (max_value == kIndefiniteSize.ToFloat()) {
        // "When evaluating the calc-size calculation, if percentages are not
        // definite in the given context, the resolve to 0px. Otherwise, they
        // resolve as normal."
        //   -- https://drafts.csswg.org/css-values-5/#resolving-calc-size
        max_value = 0.0f;
      }
      return children_[1]->Evaluate(max_value, calculation_input);
    }
    case CalculationOperator::kProgress:
    case CalculationOperator::kMediaProgress:
    case CalculationOperator::kContainerProgress: {
      DCHECK(!children_.empty());
      float progress = children_[0]->Evaluate(max_value, input);
      float from = children_[1]->Evaluate(max_value, input);
      float to = children_[2]->Evaluate(max_value, input);
      return (progress - from) / (to - from);
    }
    case CalculationOperator::kInvalid:
      break;
      // TODO(crbug.com/1284199): Support other math functions.
  }
  NOTREACHED();
}

bool CalculationExpressionOperationNode::Equals(
    const CalculationExpressionNode& other) const {
  auto* other_operation = DynamicTo<CalculationExpressionOperationNode>(other);
  if (!other_operation) {
    return false;
  }
  if (operator_ != other_operation->GetOperator()) {
    return false;
  }
  using ValueType = Children::value_type;
  return base::ranges::equal(
      children_, other_operation->GetChildren(),
      [](const ValueType& a, const ValueType& b) { return *a == *b; });
}

scoped_refptr<const CalculationExpressionNode>
CalculationExpressionOperationNode::Zoom(double factor) const {
  switch (operator_) {
    case CalculationOperator::kAdd:
    case CalculationOperator::kSubtract:
      DCHECK_EQ(children_.size(), 2u);
      return CreateSimplified(
          Children({children_[0]->Zoom(factor), children_[1]->Zoom(factor)}),
          operator_);
    case CalculationOperator::kMultiply: {
      DCHECK_EQ(children_.size(), 2u);
      auto& number = children_[0]->IsNumber() ? children_[0] : children_[1];
      auto& pixels_and_percent =
          children_[0]->IsNumber() ? children_[1] : children_[0];
      return CreateSimplified(
          Children({pixels_and_percent->Zoom(factor), number}), operator_);
    }
    case CalculationOperator::kInvert: {
      DCHECK_EQ(children_.size(), 1u);
      return CreateSimplified(Children({children_[0]->Zoom(factor)}),
                              operator_);
    }
    case CalculationOperator::kCalcSize: {
      DCHECK_EQ(children_.size(), 2u);
      return CreateSimplified(
          Children({children_[0], children_[1]->Zoom(factor)}), operator_);
    }
    case CalculationOperator::kMin:
    case CalculationOperator::kMax:
    case CalculationOperator::kClamp:
    case CalculationOperator::kRoundNearest:
    case CalculationOperator::kRoundUp:
    case CalculationOperator::kRoundDown:
    case CalculationOperator::kRoundToZero:
    case CalculationOperator::kMod:
    case CalculationOperator::kRem:
    case CalculationOperator::kHypot:
    case CalculationOperator::kAbs:
    case CalculationOperator::kSign:
    case CalculationOperator::kProgress:
    case CalculationOperator::kMediaProgress:
    case CalculationOperator::kContainerProgress: {
      DCHECK(children_.size());
      Vector<scoped_refptr<const CalculationExpressionNode>> cloned_operands;
      cloned_operands.reserve(children_.size());
      for (const auto& child : children_)
        cloned_operands.push_back(child->Zoom(factor));
      return CreateSimplified(std::move(cloned_operands), operator_);
    }
    case CalculationOperator::kInvalid:
      NOTREACHED();
  }
}

bool CalculationExpressionOperationNode::HasMinContent() const {
  if (operator_ != CalculationOperator::kCalcSize) {
    return false;
  }
  CHECK_EQ(children_.size(), 2u);
  const auto& basis = children_[0];
  return basis->HasMinContent();
}

bool CalculationExpressionOperationNode::HasMaxContent() const {
  if (operator_ != CalculationOperator::kCalcSize) {
    return false;
  }
  CHECK_EQ(children_.size(), 2u);
  const auto& basis = children_[0];
  return basis->HasMaxContent();
}

bool CalculationExpressionOperationNode::HasFitContent() const {
  if (operator_ != CalculationOperator::kCalcSize) {
    return false;
  }
  CHECK_EQ(children_.size(), 2u);
  const auto& basis = children_[0];
  return basis->HasFitContent();
}

#if DCHECK_IS_ON()
CalculationExpressionNode::ResultType
CalculationExpressionOperationNode::ResolvedResultType() const {
  switch (operator_) {
    case CalculationOperator::kAdd:
    case CalculationOperator::kSubtract: {
      DCHECK_EQ(children_.size(), 2u);
      auto left_type = children_[0]->ResolvedResultType();
      auto right_type = children_[1]->ResolvedResultType();
      if (left_type == ResultType::kInvalid ||
          right_type == ResultType::kInvalid || left_type != right_type)
        return ResultType::kInvalid;

      return left_type;
    }
    case CalculationOperator::kMultiply: {
      DCHECK_EQ(children_.size(), 2u);
      auto left_type = children_[0]->ResolvedResultType();
      auto right_type = children_[1]->ResolvedResultType();
      if (left_type == ResultType::kInvalid ||
          right_type == ResultType::kInvalid ||
          (left_type == ResultType::kPixelsAndPercent &&
           right_type == ResultType::kPixelsAndPercent))
        return ResultType::kInvalid;

      if ((left_type == ResultType::kPixelsAndPercent &&
           right_type == ResultType::kNumber) ||
          (left_type == ResultType::kNumber &&
           right_type == ResultType::kPixelsAndPercent))
        return ResultType::kPixelsAndPercent;

      return ResultType::kNumber;
    }
    case CalculationOperator::kInvert: {
      DCHECK_EQ(children_.size(), 1u);
      auto denominator_type = children_[0]->ResolvedResultType();
      if (denominator_type == ResultType::kNumber) {
        return ResultType::kNumber;
      }
      return ResultType::kInvalid;
    }
    case CalculationOperator::kCalcSize: {
      DCHECK_EQ(children_.size(), 2u);
      auto basis_type = children_[0]->ResolvedResultType();
      auto calculation_type = children_[1]->ResolvedResultType();
      if (basis_type != ResultType::kPixelsAndPercent ||
          calculation_type != ResultType::kPixelsAndPercent) {
        return ResultType::kInvalid;
      }
      return ResultType::kPixelsAndPercent;
    }
    case CalculationOperator::kMin:
    case CalculationOperator::kMax:
    case CalculationOperator::kClamp:
    case CalculationOperator::kRoundNearest:
    case CalculationOperator::kRoundUp:
    case CalculationOperator::kRoundDown:
    case CalculationOperator::kRoundToZero:
    case CalculationOperator::kMod:
    case CalculationOperator::kRem:
    case CalculationOperator::kHypot:
    case CalculationOperator::kAbs: {
      DCHECK(children_.size());
      auto first_child_type = children_.front()->ResolvedResultType();
      for (const auto& child : children_) {
        if (first_child_type != child->ResolvedResultType())
          return ResultType::kInvalid;
      }

      return first_child_type;
    }
    case CalculationOperator::kSign:
    case CalculationOperator::kContainerProgress:
    case CalculationOperator::kProgress:
    case CalculationOperator::kMediaProgress:
      return ResultType::kNumber;
    case CalculationOperator::kInvalid:
      NOTREACHED();
  }
}
#endif

}  // namespace blink

"""

```