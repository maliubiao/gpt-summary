Response:
The user wants to understand the functionality of the provided C++ code snippet from `ml_graph_builder.cc`. This file seems to be part of the WebNN API implementation in the Chromium browser, responsible for building computational graphs for machine learning operations.

To address the user's request, I need to:

1. **Summarize the overall purpose of the code.**  It appears to define methods within the `MLGraphBuilder` class to construct various machine learning operations (like addition, subtraction, convolution, etc.) within a computation graph.

2. **Identify connections to web technologies (JavaScript, HTML, CSS).**  Since this is part of the WebNN API, it directly relates to JavaScript. I need to explain how JavaScript uses these C++ functions.

3. **Provide examples of logical reasoning with input/output.**  The code often involves validation and output descriptor inference. I can pick a simple function and illustrate this.

4. **Illustrate common usage errors.**  The validation steps suggest potential errors. I should point out scenarios where the API might be misused.

5. **Describe the user interaction flow leading to this code.**  This involves the JavaScript API calls that eventually trigger these C++ methods.

6. **Provide a concise summary of the code's functionality.**

**Plan:**

*   Start by summarizing the role of `MLGraphBuilder` in the WebNN API.
*   Explain how JavaScript interacts with this C++ code through the WebNN API.
*   Choose the `cumulativeSum` function to demonstrate input validation, output inference, and graph construction.
*   Use `cumulativeSum` to illustrate potential user errors, such as providing an invalid axis.
*   Outline the steps in JavaScript that would lead to the `cumulativeSum` function being called.
*   Finally, condense the functionality of the provided code section.
这是 `blink/renderer/modules/ml/webnn/ml_graph_builder.cc` 文件的第三部分，该文件是 Chromium Blink 引擎中用于构建 WebNN (Web Neural Network API) 计算图的核心组件。

**它的主要功能是：**

1. **提供构建 WebNN 计算图中各种操作的方法。** 这部分代码定义了 `MLGraphBuilder` 类中用于创建特定机器学习操作（如累积和、元素级二元运算、元素级一元运算、类型转换、反量化、归约操作、激活函数、形状变换、收集操作、通用矩阵乘法、循环神经网络单元等）的成员函数。每个函数对应一个特定的 WebNN 操作。

2. **封装了底层的 WebNN 操作创建和连接过程。** 这些方法接收 JavaScript 传递的参数（例如输入张量、操作选项），进行参数校验，推断输出张量的描述符，创建相应的 WebNN 操作对象，并将其连接到计算图中。

3. **执行输入参数的校验。** 在创建操作之前，代码会调用 `ValidateGraphBuilderState()` 和 `ValidateInput()`/`ValidateInputs()` 等函数来确保 `MLGraphBuilder` 的状态是有效的，并且输入操作数的类型、形状等属性符合要求。如果校验失败，会抛出 JavaScript 异常。

4. **推断输出张量的描述符。**  对于许多操作，代码会调用 `webnn::Validate...AndInferOutput()` 这样的辅助函数来根据输入操作数的属性和操作的参数，自动推断出输出张量的形状和数据类型。

5. **创建并连接操作符和操作数。**  使用 `MakeGarbageCollected` 创建表示 WebNN 操作的 C++ 对象（例如 `MLCumulativeSumOperator`，`MLOperator` 等），并创建表示输出张量的 `MLOperand` 对象。然后，使用 `Connect()` 方法将输入操作数和输出操作数连接到该操作符。

**与 JavaScript, HTML, CSS 的功能关系：**

该文件是 WebNN API 的底层实现，它不直接与 HTML 或 CSS 交互。它的主要接口是通过 JavaScript 暴露给 Web 开发者的。

*   **JavaScript:** Web 开发者使用 JavaScript 中的 `navigator.ml.createGraphBuilder()` 方法来获取 `MLGraphBuilder` 实例。然后，他们调用 `MLGraphBuilder` 实例上的各种方法（例如 `add()`, `mul()`, `matmul()`, `relu()`, `conv2d()` 等）来构建计算图。这些 JavaScript 方法的调用最终会触发 `ml_graph_builder.cc` 中定义的 C++ 方法的执行。

    **举例说明：**

    ```javascript
    // JavaScript 代码
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [1, 10] });
    const weight = builder.constant({ type: 'float32', dimensions: [10, 5] }, new Float32Array(50));
    const output = builder.matmul(input, weight); // 调用 C++ 的 MLGraphBuilder::matmul 方法
    ```

*   **HTML:**  HTML 可以包含 `<script>` 标签来执行 JavaScript 代码，从而间接地使用 WebNN API 和 `ml_graph_builder.cc` 中的功能。

*   **CSS:** CSS 与 WebNN API 没有直接关系。

**逻辑推理的假设输入与输出：**

以 `cumulativeSum` 函数为例：

**假设输入：**

*   `input`: 一个形状为 `[2, 3, 4]` 的 `float32` 类型的 `MLOperand`。
*   `axis`:  `1` (表示沿着第二个维度进行累加)。
*   `options`:  一个空的 `MLCumulativeSumOptions` 对象。

**逻辑推理过程：**

1. `ValidateGraphBuilderState()` 检查 `MLGraphBuilder` 的状态是否有效。
2. `ValidateInput(input)` 检查输入 `MLOperand` 是否有效。
3. `webnn::ValidateCumulativeSumAndInferOutput()` 被调用，它会：
    *   检查 `axis` 的值是否在有效范围内 (0 到 2)。
    *   推断输出张量的形状和数据类型。由于是累积和，输出张量的形状与输入相同，数据类型也相同。因此，输出描述符的形状为 `[2, 3, 4]`，类型为 `float32`。
4. 创建一个 `MLCumulativeSumOperator` 对象，并设置 `axis` 和 `options`。
5. 创建一个输出 `MLOperand` 对象，并将其描述符设置为推断出的值。
6. 使用 `Connect()` 方法将输入 `MLOperand` 和输出 `MLOperand` 连接到 `MLCumulativeSumOperator`。

**预期输出：**

返回一个新的 `MLOperand` 对象，它代表了沿着第二个维度对输入张量进行累积求和的结果。该 `MLOperand` 的描述符将是 `{ type: 'float32', dimensions: [2, 3, 4] }`。

**用户或编程常见的使用错误：**

1. **无效的 `axis` 值：**  例如，对于一个三维张量，如果用户将 `axis` 设置为 3，`webnn::ValidateCumulativeSumAndInferOutput()` 会检测到错误并抛出异常。

    **举例说明：**

    ```javascript
    // JavaScript 代码
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [2, 3, 4] });
    const output = builder.cumulativeSum(input, 3); // 错误：axis 超出范围
    ```

2. **输入操作数类型不支持：**  某些操作可能只支持特定类型的输入。例如，`elu` 操作通常只支持浮点类型。如果用户尝试使用整型张量作为输入，`BuildUnaryOperator` 函数会进行类型检查并抛出异常。

    **举例说明：**

    ```javascript
    // JavaScript 代码
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'int32', dimensions: [2, 3] });
    const output = builder.elu(input); // 错误：elu 不支持 int32 输入
    ```

3. **输入形状不兼容：**  对于二元运算（如 `add`），输入的两个操作数的形状需要兼容（可以广播）。如果形状不兼容且无法广播，`ValidateInputs` 或底层的形状推断函数会检测到错误。

    **举例说明：**

    ```javascript
    // JavaScript 代码
    const builder = await navigator.ml.createGraphBuilder();
    const inputA = builder.input('inputA', { type: 'float32', dimensions: [2, 3] });
    const inputB = builder.input('inputB', { type: 'float32', dimensions: [3, 2] });
    const output = builder.add(inputA, inputB); // 错误：形状不兼容，无法直接相加
    ```

4. **`alpha` 值无效（针对 `elu`）：** `elu` 操作要求 `alpha` 值大于 0。如果用户提供一个非正的 `alpha` 值，代码会抛出 `TypeError`。

    **举例说明：**

    ```javascript
    // JavaScript 代码
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [2, 3] });
    const output = builder.elu(input, { alpha: 0 }); // 错误：alpha 值必须大于 0
    ```

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 JavaScript 代码，使用 WebNN API。** 例如，他们可能使用 `navigator.ml.createModel()` 加载一个模型定义，或者使用 `navigator.ml.createGraphBuilder()` 手动构建一个计算图。

2. **在构建计算图的过程中，用户调用 `MLGraphBuilder` 实例上的方法来添加操作。** 例如，调用 `builder.cumulativeSum(input, 1)`。

3. **JavaScript 引擎接收到该方法调用，并将其路由到 Blink 渲染引擎中的相应 C++ 代码。** 这通常涉及到 JavaScript 与 C++ 之间的绑定机制（例如，V8 的 bindings）。

4. **`ml_graph_builder.cc` 中的 `MLGraphBuilder::cumulativeSum` 方法被调用。**

5. **该方法执行参数校验、输出推断、创建操作符对象、创建输出操作数对象，并将它们连接起来。**

6. **最终，该方法返回一个 `MLOperand` 对象，该对象代表了计算图中的一个中间或最终结果。**

**调试线索：**

当开发者在使用 WebNN API 时遇到问题，他们可以：

*   **检查 JavaScript 控制台中的错误信息。** WebNN API 的实现会抛出 JavaScript 异常来指示错误。
*   **使用浏览器的开发者工具进行断点调试。** 可以在 JavaScript 代码中设置断点，查看 `MLGraphBuilder` 方法的调用过程和参数值。
*   **如果需要深入了解底层实现，可以查看 Chromium 的源代码，包括 `ml_graph_builder.cc` 文件。**  错误信息中的堆栈跟踪可能指向这个文件中的特定行号。
*   **检查 WebNN 规范，确认 API 的使用方式是否正确。**

**功能归纳 (针对提供的代码片段):**

这段代码主要负责实现 `MLGraphBuilder` 类中用于创建和连接各种**逐元素 (element-wise)** 和 **归约 (reduce)** 类型的机器学习操作的方法。它包含了：

*   **`cumulativeSum`**: 创建累积和操作。
*   **`BUILD_ELEMENTWISE_BINARY_OP` 宏定义的二元运算**:  例如 `add`, `sub`, `mul`, `div`, `min`, `max` 等。
*   **`BUILD_ELEMENTWISE_UNARY_OP` 宏定义的一元运算**: 例如 `abs`, `ceil`, `cos`, `exp`, `floor`, `log`, `neg`, `sin` 等。
*   **`logicalNot`**: 创建逻辑非运算。
*   **`cast`**: 创建类型转换操作。
*   **`dequantizeLinear`**: 创建反量化操作。
*   **`BUILD_REDUCE_OP` 宏定义的归约运算**: 例如 `reduceL1`, `reduceL2`, `reduceSum`, `reduceMean` 等。
*   以及其他一些特定的操作，如 `elu`, `expand`, `gather`, `gemm`, 循环神经网络相关的操作 (`gru`, `lstm` 等), `hardSigmoid`, `hardSwish`, `instanceNormalization`, `layerNormalization`, `leakyRelu`, `linear`, `matmul`, `pad` 等。

总而言之，这部分代码是 WebNN 计算图构建的核心，它将用户在 JavaScript 中定义的高级机器学习操作转化为底层可以执行的计算图结构。

Prompt: 
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
 ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateCumulativeSumAndInferOutput(ml_context_->GetProperties(),
                                                 input->Descriptor(), axis,
                                                 options->label().Utf8()));

  // Create cumulativeSum operator and its output operand. Connect the
  // cumulativeSum operator to its input and output operands.
  auto* cumulativeSum =
      MakeGarbageCollected<MLCumulativeSumOperator>(this, axis, options);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), cumulativeSum);
  cumulativeSum->Connect({input}, {output});

  return output;
}

// Macro to define the function for an elementwise binary op. `op_camel` is the
// name of the op in camel case. `op_snake` is the name of the op in snake case.
// `op_kind` is the corresponding `ElementWiseBinary::Kind` enum. We need to
// separately specify the camel case and the snake case name because the
// function name is in camel case, while the corresponding `DataTypeLimits`
// field is in snake case.
#define BUILD_ELEMENTWISE_BINARY_OP(op_camel, op_snake, op_kind)              \
  MLOperand* MLGraphBuilder::op_camel(MLOperand* a, MLOperand* b,             \
                                      const MLOperatorOptions* options,       \
                                      ExceptionState& exception_state) {      \
    THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);          \
    THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs({a, b}), nullptr);          \
    return BuildElementWiseBinary(                                            \
        this, blink_mojom::ElementWiseBinary::Kind::op_kind,                  \
        ml_context_->GetProperties().data_type_limits.op_snake##_input, a, b, \
        options, exception_state);                                            \
  }

BUILD_ELEMENTWISE_BINARY_OP(add, add, kAdd)
BUILD_ELEMENTWISE_BINARY_OP(sub, sub, kSub)
BUILD_ELEMENTWISE_BINARY_OP(mul, mul, kMul)
BUILD_ELEMENTWISE_BINARY_OP(div, div, kDiv)
BUILD_ELEMENTWISE_BINARY_OP(min, min, kMin)
BUILD_ELEMENTWISE_BINARY_OP(max, max, kMax)
BUILD_ELEMENTWISE_BINARY_OP(pow, pow, kPow)
BUILD_ELEMENTWISE_BINARY_OP(equal, equal, kEqual)
BUILD_ELEMENTWISE_BINARY_OP(greater, greater, kGreater)
BUILD_ELEMENTWISE_BINARY_OP(lesser, lesser, kLesser)
BUILD_ELEMENTWISE_BINARY_OP(greaterOrEqual, greater_or_equal, kGreaterOrEqual)
BUILD_ELEMENTWISE_BINARY_OP(lesserOrEqual, lesser_or_equal, kLesserOrEqual)
BUILD_ELEMENTWISE_BINARY_OP(logicalAnd, logical_and, kLogicalAnd)
BUILD_ELEMENTWISE_BINARY_OP(logicalOr, logical_or, kLogicalOr)
BUILD_ELEMENTWISE_BINARY_OP(logicalXor, logical_xor, kLogicalXor)

#define BUILD_ELEMENTWISE_UNARY_OP(op, op_kind)                              \
  MLOperand* MLGraphBuilder::op(MLOperand* input,                            \
                                const MLOperatorOptions* options,            \
                                ExceptionState& exception_state) {           \
    THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);         \
    THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);           \
    return BuildElementWiseUnaryOperator(                                    \
        this, exception_state, blink_mojom::ElementWiseUnary::Kind::op_kind, \
        ml_context_->GetProperties().data_type_limits.op##_input, input,     \
        options);                                                            \
  }

BUILD_ELEMENTWISE_UNARY_OP(abs, kAbs)
BUILD_ELEMENTWISE_UNARY_OP(ceil, kCeil)
BUILD_ELEMENTWISE_UNARY_OP(cos, kCos)
BUILD_ELEMENTWISE_UNARY_OP(exp, kExp)
BUILD_ELEMENTWISE_UNARY_OP(floor, kFloor)
BUILD_ELEMENTWISE_UNARY_OP(log, kLog)
BUILD_ELEMENTWISE_UNARY_OP(neg, kNeg)
BUILD_ELEMENTWISE_UNARY_OP(sign, kSign)
BUILD_ELEMENTWISE_UNARY_OP(sin, kSin)
BUILD_ELEMENTWISE_UNARY_OP(tan, kTan)
BUILD_ELEMENTWISE_UNARY_OP(erf, kErf)
BUILD_ELEMENTWISE_UNARY_OP(identity, kIdentity)
BUILD_ELEMENTWISE_UNARY_OP(reciprocal, kReciprocal)
BUILD_ELEMENTWISE_UNARY_OP(sqrt, kSqrt)

MLOperand* MLGraphBuilder::logicalNot(MLOperand* input,
                                      const MLOperatorOptions* options,
                                      ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);
  return BuildElementWiseUnaryOperator(
      this, exception_state, blink_mojom::ElementWiseUnary::Kind::kLogicalNot,
      ml_context_->GetProperties().data_type_limits.logical_not_input, input,
      options);
}

MLOperand* MLGraphBuilder::cast(MLOperand* input,
                                const V8MLOperandDataType output_data_type,
                                const MLOperatorOptions* options,
                                ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();

  if (!ml_context_->GetProperties().data_type_limits.cast_input.Has(
          input->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        String(NotSupportedInputArgumentTypeError(
            input->DataType(),
            ml_context_->GetProperties().data_type_limits.cast_input)));
    return nullptr;
  }

  const webnn::OperandDataType cast_data_type =
      FromBlinkDataType(output_data_type.AsEnum());

  if (!ml_context_->GetProperties().data_type_limits.cast_input.Has(
          cast_data_type)) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        String(NotSupportedOpOutputTypeError(
            cast_data_type,
            ml_context_->GetProperties().data_type_limits.cast_input)));
    return nullptr;
  }

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::OperandDescriptor::Create(cast_data_type, input->Shape()));

  auto* cast = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kElementWiseUnary, options,
      /*sub_kind=*/blink_mojom::ElementWiseUnary::Kind::kCast);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), cast);

  cast->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::dequantizeLinear(MLOperand* input,
                                            MLOperand* scale,
                                            MLOperand* zeroPoint,
                                            const MLOperatorOptions* options,
                                            ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  HeapVector<Member<MLOperand>> inputs = {input, scale, zeroPoint};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateDequantizeLinearAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          scale->Descriptor(), zeroPoint->Descriptor(),
          options->label().Utf8()));

  auto* dequantize_linear = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kDequantizeLinear, options);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), dequantize_linear);
  dequantize_linear->Connect(std::move(inputs), {output});
  return output;
}

#define BUILD_REDUCE_OP(op, op_kind)                                 \
  MLOperand* MLGraphBuilder::op(MLOperand* input,                    \
                                const MLReduceOptions* options,      \
                                ExceptionState& exception_state) {   \
    THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr); \
    THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);   \
    return BuildReduce(this, blink_mojom::Reduce::Kind::op_kind,     \
                       ml_context_->GetProperties(), input, options, \
                       exception_state);                             \
  }

BUILD_REDUCE_OP(reduceL1, kL1)
BUILD_REDUCE_OP(reduceL2, kL2)
BUILD_REDUCE_OP(reduceLogSum, kLogSum)
BUILD_REDUCE_OP(reduceLogSumExp, kLogSumExp)
BUILD_REDUCE_OP(reduceMax, kMax)
BUILD_REDUCE_OP(reduceMean, kMean)
BUILD_REDUCE_OP(reduceMin, kMin)
BUILD_REDUCE_OP(reduceProduct, kProduct)
BUILD_REDUCE_OP(reduceSum, kSum)
BUILD_REDUCE_OP(reduceSumSquare, kSumSquare)

MLOperand* MLGraphBuilder::elu(MLOperand* input,
                               const MLEluOptions* options,
                               ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);
  const std::string label = options->label().Utf8();
  // The current spec doesn't restrict the value of alpha. An issue has been
  // filed to track it: https://github.com/webmachinelearning/webnn/issues/383
  if (options->alpha() <= 0.0f) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The value of alpha must be greater than 0.");
    return nullptr;
  }

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-elu, the output tensor of
  // elu has the same data type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kElu,
      ml_context_->GetProperties().data_type_limits.elu_input, input, options);
}

MLOperand* MLGraphBuilder::expand(MLOperand* input,
                                  const Vector<uint32_t>& new_shape,
                                  const MLOperatorOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();

  const webnn::SupportedDataTypes& data_type_constraint =
      ml_context_->GetProperties().data_type_limits.expand_input;
  if (!data_type_constraint.Has(input->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(options->label().Utf8())) +
        String(NotSupportedInputArgumentTypeError(input->DataType(),
                                                  data_type_constraint)));
    return nullptr;
  }

  auto output_shape = webnn::BroadcastShapes(input->Shape(), new_shape,
                                             /*bidirectional=*/false);
  if (!output_shape) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The input shape is not broadcastable to the new shape.");
    return nullptr;
  }
  CHECK(base::ranges::equal(*output_shape, new_shape));

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::OperandDescriptor::Create(input->DataType(), *output_shape));

  auto* expand = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kExpand, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), expand);

  expand->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::gather(MLOperand* input,
                                  MLOperand* indices,
                                  const MLGatherOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, indices};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateGatherAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          indices->Descriptor(), options->axis(), options->label().Utf8()));

  auto* gather = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kGather, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), gather);

  gather->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::gatherElements(MLOperand* input,
                                          MLOperand* indices,
                                          const MLGatherOptions* options,
                                          ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, indices};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateGatherElementsAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          indices->Descriptor(), options->axis(), options->label().Utf8()));

  auto* gather_elements = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kGatherElements, options);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), gather_elements);

  gather_elements->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::gatherND(MLOperand* input,
                                    MLOperand* indices,
                                    const MLOperatorOptions* options,
                                    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, indices};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateGatherNDAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          indices->Descriptor(), options->label().Utf8()));

  auto* gather_nd = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kGatherNd, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), gather_nd);

  gather_nd->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::gelu(MLOperand* input,
                                const MLOperatorOptions* options,
                                ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-gelu, the output tensor of
  // gelu has the same data type and dimensions as its input. And the input data
  // type must be one of the floating point types.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kGelu,
      ml_context_->GetProperties().data_type_limits.gelu_input, input, options);
}

MLOperand* MLGraphBuilder::gemm(MLOperand* a,
                                MLOperand* b,
                                const MLGemmOptions* options,
                                ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {a, b};
  if (options->hasC()) {
    inputs.push_back(options->c());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateGemmAndInferOutput(ml_context_->GetProperties(),
                                        a->Descriptor(), b->Descriptor(),
                                        ConvertToGemmAttributes(options)));

  auto* gemm = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kGemm, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), gemm);

  gemm->Connect(std::move(inputs), {output});
  return output;
}

HeapVector<Member<const MLOperand>> MLGraphBuilder::gru(
    MLOperand* input,
    MLOperand* weight,
    MLOperand* recurrent_weight,
    const uint32_t steps,
    const uint32_t hidden_size,
    MLGruOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(),
                            HeapVector<Member<const MLOperand>>());

  HeapVector<Member<MLOperand>> inputs = {input, weight, recurrent_weight};
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  if (options->hasRecurrentBias()) {
    inputs.push_back(options->recurrentBias());
  }
  if (options->hasInitialHiddenState()) {
    inputs.push_back(options->initialHiddenState());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs),
                                 HeapVector<Member<const MLOperand>>());

  auto validated_outputs = webnn::ValidateGruAndInferOutput(
      ml_context_->GetProperties(), input->Descriptor(), weight->Descriptor(),
      recurrent_weight->Descriptor(), steps, hidden_size,
      ConvertToGruAttributes(this, options));
  if (!validated_outputs.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(validated_outputs.error()));
    return {};
  }
  auto* gru =
      MakeGarbageCollected<MLGruOperator>(this, steps, hidden_size, options);

  HeapVector<Member<const MLOperand>> outputs;
  for (const auto& validated_output : validated_outputs.value()) {
    outputs.push_back(MLOperand::CreateOutput(this, validated_output, gru));
  }

  gru->Connect(std::move(inputs), outputs);
  return outputs;
}

MLOperand* MLGraphBuilder::gruCell(MLOperand* input,
                                   MLOperand* weight,
                                   MLOperand* recurrent_weight,
                                   MLOperand* hidden_state,
                                   const uint32_t hidden_size,
                                   MLGruCellOptions* options,
                                   ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, weight, recurrent_weight,
                                          hidden_state};
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  if (options->hasRecurrentBias()) {
    inputs.push_back(options->recurrentBias());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  auto validated_output = webnn::ValidateGruCellAndInferOutput(
      ml_context_->GetProperties(), input->Descriptor(), weight->Descriptor(),
      recurrent_weight->Descriptor(), hidden_state->Descriptor(), hidden_size,
      ConvertToGruCellAttributes(this, options));
  if (!validated_output.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(validated_output.error()));
    return {};
  }
  auto* gru_cell =
      MakeGarbageCollected<MLGruCellOperator>(this, hidden_size, options);

  MLOperand* output =
      MLOperand::CreateOutput(this, *std::move(validated_output), gru_cell);

  gru_cell->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::hardSigmoid(MLOperand* input,
                                       const MLHardSigmoidOptions* options,
                                       ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-hardsigmoid, the output
  // tensor of softplus has the same type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kHardSigmoid,
      ml_context_->GetProperties().data_type_limits.hard_sigmoid_input, input,
      options);
}

MLOperand* MLGraphBuilder::hardSwish(MLOperand* input,
                                     const MLOperatorOptions* options,
                                     ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-hard-swish, the output
  // tensor of hard-swish has the same data type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kHardSwish,
      ml_context_->GetProperties().data_type_limits.hard_swish_input, input,
      options);
}

MLOperand* MLGraphBuilder::instanceNormalization(
    MLOperand* input,
    const MLInstanceNormalizationOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input};
  // Adding the optional operands into inputs ensures the graph traversal
  // algorithm GetOperatorsInTopologicalOrder() works. For backends, the
  // optional operands should be retrieved from the options instead of inputs.
  if (options->hasScale()) {
    inputs.push_back(options->scale());
  }
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateInstanceNormalizationAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          ConvertToInstanceNormalizationAttributes(options)));

  auto* instance_normalization = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kInstanceNormalization, options);

  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), instance_normalization);

  instance_normalization->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::layerNormalization(
    MLOperand* input,
    const MLLayerNormalizationOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input};
  // Adding the optional operands into inputs ensures the graph traversal
  // algorithm GetOperatorsInTopologicalOrder() works. For backends, the
  // optional operands should be retrieved from the options instead of inputs.
  if (options->hasScale()) {
    inputs.push_back(options->scale());
  }
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  // TODO(crbug.com/1273291): Figure out whether the `axes` should be required,
  // tracked by issue: https://github.com/webmachinelearning/webnn/issues/487
  const Vector<uint32_t> axes =
      options->getAxesOr(CreateLayerNormalizationDefaultAxes(input->Rank()));

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateLayerNormalizationAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(), axes,
          ConvertToLayerNormalizationAttributes(options)));

  auto* layer_normalization = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kLayerNormalization, options);

  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), layer_normalization);

  layer_normalization->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::leakyRelu(MLOperand* input,
                                     const MLLeakyReluOptions* options,
                                     ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-leakyrelu, the output
  // tensor of leaky relu has the same type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kLeakyRelu,
      ml_context_->GetProperties().data_type_limits.leaky_relu_input, input,
      options);
}

MLOperand* MLGraphBuilder::linear(MLOperand* input,
                                  const MLLinearOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // The current spec doesn't specify the operand data type constraints of
  // linear. An issue has been filed to track it:
  // https://github.com/webmachinelearning/webnn/issues/283.
  //
  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-linear, the output tensor
  // of linear has the same type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kLinear,
      ml_context_->GetProperties().data_type_limits.linear_input, input,
      options);
}

HeapVector<Member<const MLOperand>> MLGraphBuilder::lstm(
    MLOperand* input,
    MLOperand* weight,
    MLOperand* recurrent_weight,
    const uint32_t steps,
    const uint32_t hidden_size,
    MLLstmOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(),
                            HeapVector<Member<const MLOperand>>());

  HeapVector<Member<MLOperand>> inputs = {input, weight, recurrent_weight};
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  if (options->hasRecurrentBias()) {
    inputs.push_back(options->recurrentBias());
  }
  if (options->hasPeepholeWeight()) {
    inputs.push_back(options->peepholeWeight());
  }
  if (options->hasInitialHiddenState()) {
    inputs.push_back(options->initialHiddenState());
  }
  if (options->hasInitialCellState()) {
    inputs.push_back(options->initialCellState());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs),
                                 HeapVector<Member<const MLOperand>>());

  if (!options->hasActivations()) {
    // Create a default activation sequence as defined in the spec.
    options->setActivations(
        {V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kSigmoid),
         V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kTanh),
         V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kTanh)});
  }

  auto validated_outputs = webnn::ValidateLstmAndInferOutput(
      ml_context_->GetProperties(), input->Descriptor(), weight->Descriptor(),
      recurrent_weight->Descriptor(), steps, hidden_size,
      ConvertToLstmAttributes(options));
  if (!validated_outputs.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(validated_outputs.error()));
    return {};
  }

  auto* lstm =
      MakeGarbageCollected<MLLstmOperator>(this, steps, hidden_size, options);

  HeapVector<Member<const MLOperand>> outputs;
  for (const auto& validated_output : validated_outputs.value()) {
    outputs.push_back(MLOperand::CreateOutput(this, validated_output, lstm));
  }

  lstm->Connect(std::move(inputs), outputs);
  return outputs;
}

HeapVector<Member<const MLOperand>> MLGraphBuilder::lstmCell(
    MLOperand* input,
    MLOperand* weight,
    MLOperand* recurrent_weight,
    MLOperand* hidden_state,
    MLOperand* cell_state,
    const uint32_t hidden_size,
    MLLstmCellOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(),
                            HeapVector<Member<const MLOperand>>());

  HeapVector<Member<MLOperand>> inputs = {input, weight, recurrent_weight,
                                          hidden_state, cell_state};
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  if (options->hasRecurrentBias()) {
    inputs.push_back(options->recurrentBias());
  }
  if (options->hasPeepholeWeight()) {
    inputs.push_back(options->peepholeWeight());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs),
                                 HeapVector<Member<const MLOperand>>());

  if (!options->hasActivations()) {
    // Create a default activation sequence as defined in the spec.
    options->setActivations(
        {V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kSigmoid),
         V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kTanh),
         V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kTanh)});
  }

  auto validated_outputs = webnn::ValidateLstmCellAndInferOutput(
      ml_context_->GetProperties(), input->Descriptor(), weight->Descriptor(),
      recurrent_weight->Descriptor(), hidden_state->Descriptor(),
      cell_state->Descriptor(), hidden_size,
      ConvertToLstmCellAttributes(options));
  if (!validated_outputs.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(validated_outputs.error()));
    return {};
  }

  auto* lstm_cell =
      MakeGarbageCollected<MLLstmCellOperator>(this, hidden_size, options);

  HeapVector<Member<const MLOperand>> outputs;
  CHECK_EQ(validated_outputs->size(), 2u);
  outputs.reserve(2);
  for (const auto& validated_output : validated_outputs.value()) {
    outputs.push_back(
        MLOperand::CreateOutput(this, validated_output, lstm_cell));
  }

  lstm_cell->Connect(std::move(inputs), outputs);
  return outputs;
}

MLOperand* MLGraphBuilder::matmul(MLOperand* a,
                                  MLOperand* b,
                                  const MLOperatorOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {a, b};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateMatmulAndInferOutput(ml_context_->GetProperties(),
                                          a->Descriptor(), b->Descriptor(),
                                          options->label().Utf8()));

  // Create matmul operator and its output operand. Connect the matmul operator
  // to its input and output operands.
  auto* matmul = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kMatmul, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), matmul);

  matmul->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::pad(ScriptState* script_state,
                               MLOperand* input,
                               const Vector<uint32_t>& beginning_padding,
                               const Vector<uint32_t>& ending_padding,
                               const MLPadOptions* options,
                               ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();
  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidatePadAndInferOutput(ml_context_->GetProperties(),
                                       input->Descriptor(), beginning_padding,
                                       ending_padding, label));

  if (options->mode().AsEnum() != V8MLPaddingMode::Enum::kConstant &&
      fabs(options->value() - 0.0f) > std::numeric_limits<float>::epsilon()) {
    LogConsoleWarning(
        script_state,
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
            String::Format(
                "The pad value is ignored unless the options.mode is set to "
                "constant."));
  }

  auto* pad = MakeGarbageCollected<MLPadOperator>(this, beginning_padding,
                                                  ending_padding, options);
  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-pad, the output
  // tensor of pad has the same data type as its input.
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), pad);
"""


```