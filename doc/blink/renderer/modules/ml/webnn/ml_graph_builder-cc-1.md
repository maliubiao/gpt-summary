Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ml_graph_builder.cc`. This is part 2 of a 4-part request.

The code defines several functions responsible for:

1. **Converting WebNN API options objects to internal WebNN attribute structures:** `ConvertTo*Attributes` functions.
2. **Validating input options:** `ValidateClampOptions`.
3. **Building WebNN graph operations:** `BuildArgMinMax`, `BuildElementWiseBinary`, `BuildUnaryOperator`, `BuildElementWiseUnaryOperator`, `BuildReduce`, `BuildPool2d`. These functions take input operands and options, validate them, infer output shapes, create operator objects, and connect operands to operators.
4. **Determining graph constraints:** `DetermineGraphConstraintsFromOutputs`. This function analyzes the output operands to identify the required input operands and their descriptors.
5. **Building the WebNN graph information:** `BuildWebNNGraphInfo`. This function converts the internal representation of the graph into a `blink_mojom::GraphInfoPtr` which is used for communication with the underlying WebNN implementation.
这是 `blink/renderer/modules/ml/webnn/ml_graph_builder.cc` 文件的第二部分，主要包含以下功能：

**1. 将 WebNN API 的选项对象转换为内部使用的属性结构体:**

*   **`ConvertToConv2dAttributes(const blink::MLConv2dOptions* options)`:** 将 `MLConv2dOptions` 转换为 `webnn::Conv2dAttributes`。它提取诸如 padding、strides、dilations、groups、autoPad 和 layout 等属性。
*   **`ConvertToConvTranspose2dAttributes(const blink::MLConvTranspose2dOptions* options)`:** 将 `MLConvTranspose2dOptions` 转换为 `webnn::ConvTranspose2dAttributes`。 提取 padding、strides、dilations、groups、autoPad、layout 和 outputPadding、outputSizes 等属性。
*   **`ConvertToPool2dAttributes(const blink::MLPool2dOptions* options)`:** 将 `MLPool2dOptions` 转换为 `std::optional<webnn::Pool2dAttributes>`。 提取 windowDimensions、padding、strides、dilations 和 autoPad 等属性。如果 stride 或 dilation 大小与维度不匹配，则返回错误信息。
*   **`ConvertToGemmAttributes(const blink::MLGEMMOptions* options)`:** 将 `MLGEMMOptions` 转换为 `webnn::GemmAttributes`。 提取 alpha、beta、transposeA 和 transposeB 等属性。
*   **`ConvertToReduceOptions(const blink::MLReduceOptions* options)`:** 将 `MLReduceOptions` 转换为 `webnn::ReduceOptions`。 提取 keepDimensions 属性。
*   **`ConvertToReshapeOptions(const blink::MLReshapeOptions* options)`:** 将 `MLReshapeOptions` 转换为 `webnn::ReshapeOptions`。
*   **`ConvertToSqueezeOptions(const blink::MLSqueezeOptions* options)`:** 将 `MLSqueezeOptions` 转换为 `webnn::SqueezeOptions`。
*   **`ConvertToSplitOptions(const blink::MLSplitOptions* options)`:** 将 `MLSplitOptions` 转换为 `webnn::SplitAttributes`。
*   **`ConvertToTransposeOptions(const blink::MLTransposeOptions* options)`:** 将 `MLTransposeOptions` 转换为 `webnn::TransposeAttributes`。
*   **`ConvertToUnaryOptions(const blink::MLUnaryOptions* options)`:** 将 `MLUnaryOptions` 转换为 `webnn::UnaryAttributes`。
*   **`ConvertToBatchNormalizationAttributes(const blink::MLBatchNormalizationOptions* options)`:** 将 `MLBatchNormalizationOptions` 转换为 `webnn::BatchNormalizationAttributes`。 提取 epsilon 和 momentum 等属性。
*   **`ConvertToGruAttributes(const blink::MLGRUOptions* options)`:** 将 `MLGRUOptions` 转换为 `webnn::GruAttributes`。 提取 resetAfter、returnSequence 和 direction 等属性。
*   **`ConvertToGruCellAttributes(const blink::MLGRUCellOptions* options)`:** 将 `MLGRUCellOptions` 转换为 `webnn::GruCellAttributes`。 提取 resetAfter 属性。
*   **`ConvertToReluOptions(const blink::MLReLUNodeOptions* options)`:** 将 `MLReLUNodeOptions` 转换为 `webnn::ReluAttributes`。
*   **`ConvertToLeakyReluOptions(const blink::MLLeakyReLUNodeOptions* options)`:** 将 `MLLeakyReLUNodeOptions` 转换为 `webnn::LeakyReluAttributes`。 提取 alpha 属性。
*   **`ConvertToPReluOptions(const blink::MLPReLUNodeOptions* options)`:** 将 `MLPReLUNodeOptions` 转换为 `webnn::PReluAttributes`。
*   **`ConvertToSigmoidOptions(const blink::MLSigmoidNodeOptions* options)`:** 将 `MLSigmoidNodeOptions` 转换为 `webnn::SigmoidAttributes`。
*   **`ConvertToTanhOptions(const blink::MLTanhNodeOptions* options)`:** 将 `MLTanhNodeOptions` 转换为 `webnn::TanhAttributes`。
*   **`ConvertToSoftplusOptions(const blink::MLSoftplusNodeOptions* options)`:** 将 `MLSoftplusNodeOptions` 转换为 `webnn::SoftplusAttributes`。
*   **`ConvertToSoftsignOptions(const blink::MLSoftsignNodeOptions* options)`:** 将 `MLSoftsignNodeOptions` 转换为 `webnn::SoftsignAttributes`。
*   **`ConvertToThresholdReluOptions(const blink::MLThresholdReLUNodeOptions* options)`:** 将 `MLThresholdReLUNodeOptions` 转换为 `webnn::ThresholdReluAttributes`。 提取 threshold 属性。
*   **`ConvertToLSTMCommonAttributes(const blink::MLLSTMCommonOptions* options)`:** 将 `MLLSTMCommonOptions` 转换为 `webnn::LSTMCommonAttributes`。 提取 bias 和 label 属性。
*   **`ConvertToLstmAttributes(const blink::MLLstmOptions* options)`:** 将 `MLLstmOptions` 转换为 `webnn::LstmAttributes`。 提取 bias、recurrent_bias、peephole_weight、initial_hidden_state、initial_cell_state、activation_count、return_sequence、direction 和 label 等属性。
*   **`ConvertToLstmCellAttributes(const blink::MLLstmCellOptions* options)`:** 将 `MLLstmCellOptions` 转换为 `webnn::LstmCellAttributes`。 提取 bias、recurrent_bias、peephole_weight、activation_count 和 label 等属性。

**2. 验证 `MLClampOptions`：**

*   **`ValidateClampOptions(const MLClampOptions* options, ExceptionState& exception_state)`:** 检查 `min` 值是否小于或等于 `max` 值。如果不是，则抛出 `TypeError` 异常。

**3. 构建 WebNN 图中的操作 (Operators):**

*   **`MLOperand* BuildArgMinMax(MLGraphBuilder* builder, blink_mojom::ArgMinMax::Kind sub_kind, MLOperand* input, const uint32_t axis, const MLArgMinMaxOptions* options, ExceptionState& exception_state)`:** 构建 `argmin` 或 `argmax` 操作。它验证输入，推断输出描述符，创建 `MLArgMinMaxOperator`，并连接输入和输出。
*   **`MLOperand* BuildElementWiseBinary(MLGraphBuilder* builder, blink_mojom::ElementWiseBinary::Kind kind, const webnn::SupportedDataTypes& data_type_constraint, MLOperand* a, MLOperand* b, const MLOperatorOptions* options, ExceptionState& exception_state)`:** 构建元素级二元操作 (例如 add, sub, mul, div)。它检查输入数据类型是否受支持，是否匹配，以及形状是否可广播。根据操作类型确定输出数据类型，创建 `MLOperator`，并连接输入和输出。
*   **`MLOperand* BuildUnaryOperator(MLGraphBuilder* builder, ExceptionState& exception_state, blink_mojom::Operation::Tag kind, const webnn::SupportedDataTypes& data_type_constraint, MLOperand* input, const MLOperatorOptions* options)`:** 构建一元操作 (输出类型与输入类型相同)。它检查输入数据类型是否受支持，创建 `MLOperator`，并连接输入和输出。
*   **`MLOperand* BuildElementWiseUnaryOperator(MLGraphBuilder* builder, ExceptionState& exception_state, blink_mojom::ElementWiseUnary::Kind kind, const webnn::SupportedDataTypes& data_type_constraint, MLOperand* input, const MLOperatorOptions* options)`:** 构建元素级一元操作。它检查输入数据类型是否受支持，创建 `MLOperator`，并连接输入和输出。
*   **`MLOperand* BuildReduce(MLGraphBuilder* builder, blink_mojom::Reduce::Kind kind, const webnn::ContextProperties& context_properties, MLOperand* input, const MLReduceOptions* options, ExceptionState& exception_state)`:** 构建 reduce 操作 (例如 sum, max, min)。它验证输入，推断输出描述符，创建 `MLOperator`，并连接输入和输出。
*   **`MLOperand* BuildPool2d(MLGraphBuilder* builder, blink_mojom::Pool2d::Kind kind, const webnn::ContextProperties& context_properties, MLOperand* input, const MLPool2dOptions* options, ExceptionState& exception_state)`:** 构建 2D 池化操作 (例如 max pooling, average pooling)。它将选项转换为属性，验证输入，推断输出描述符，创建 `MLOperator`，并连接输入和输出。

**4. 确定图的约束:**

*   **`base::expected<std::pair<MLGraph::NamedOperandDescriptors, MLGraph::NamedOperandDescriptors>, String> DetermineGraphConstraintsFromOutputs(const MLNamedOperands& named_outputs)`:**  通过从输出遍历到输入来确定计算图的输入和输出资源需求。它使用广度优先搜索来遍历操作符，并记录输入和输出操作数的描述符。如果图无效（例如，输出不是输出操作数，或者输入名称重复），则返回错误。

**5. 构建 WebNN 图信息:**

*   **`base::expected<blink_mojom::GraphInfoPtr, String> BuildWebNNGraphInfo(const MLNamedOperands& named_outputs, const webnn::ContextProperties& context_properties)`:** 将内部图表示转换为 `blink_mojom::GraphInfoPtr`，用于与底层的 WebNN 实现进行通信。它将操作数和操作符转换为 Mojo 结构体，并优化掉冗余的常量 reshape 操作。

**与 JavaScript, HTML, CSS 的关系:**

这些 C++ 代码是 Chromium Blink 引擎的一部分，为 WebNN API 提供底层实现。WebNN API 是一个 JavaScript API，允许在浏览器中执行机器学习模型。

*   **JavaScript:**  Web 开发者使用 JavaScript 的 WebNN API 来构建和执行机器学习图。例如，使用 `navigator.ml.createGraphBuilder()` 创建 `MLGraphBuilder` 实例，然后调用其方法（如 `input()`, `constant()`, `conv2d()`, `add()`, `softmax()`, `build()`）来定义图的结构和操作。这些 JavaScript 调用最终会调用到这里列出的 C++ 代码。
*   **HTML:** HTML 可以包含引用执行机器学习模型的 JavaScript 代码的 `<script>` 标签。用户与 HTML 页面的交互可能会触发 JavaScript 代码，从而间接地使用到这里的 C++ 代码。
*   **CSS:** CSS 主要负责页面的样式和布局，与这里的机器学习代码没有直接的功能关系。但是，机器学习模型的结果可能会影响页面的显示，例如，图像识别模型可以用于根据图像内容动态调整 CSS 样式。

**举例说明:**

**假设输入与输出 (以 `BuildElementWiseBinary` 为例):**

*   **假设输入:**
    *   `kind`: `blink_mojom::ElementWiseBinary::Kind::kAdd` (加法操作)
    *   `a`: 一个形状为 `[2, 3]`，数据类型为 `float32` 的 `MLOperand`
    *   `b`: 一个形状为 `[2, 3]`，数据类型为 `float32` 的 `MLOperand`
    *   `options`: 一个空的 `MLOperatorOptions`
*   **逻辑推理:** 代码会检查 `a` 和 `b` 的数据类型是否受支持且匹配，形状是否可以广播（这里形状相同，可以广播）。然后创建一个加法操作符，输出形状与输入相同，数据类型也为 `float32`。
*   **输出:**  一个新的 `MLOperand`，代表加法操作的结果，形状为 `[2, 3]`，数据类型为 `float32`。

**用户或编程常见的使用错误:**

*   **`ValidateClampOptions`:**  用户可能错误地设置了 `minValue` 大于 `maxValue`。例如：
    ```javascript
    builder.clamp(inputTensor, { minValue: 10, maxValue: 5 }); // 错误！
    ```
    C++ 代码会捕获这个错误并抛出一个 `TypeError`。
*   **`BuildElementWiseBinary`:**  用户可能提供了数据类型不匹配的输入：
    ```javascript
    const inputA = builder.input('inputA', { type: 'float32', dimensions: [2, 3] });
    const inputB = builder.input('inputB', { type: 'int32', dimensions: [2, 3] });
    builder.add(inputA, inputB); // 错误！
    ```
    C++ 代码会检查到数据类型不匹配并抛出 `TypeError`。
*   **`BuildPool2d`:** 用户提供的 strides 或 dilations 的大小与输入维度不匹配。例如，对于一个 4D 输入，提供了 2 个元素的 strides 数组。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户编写 JavaScript 代码:** 开发者编写使用 WebNN API 的 JavaScript 代码来定义和执行机器学习模型。例如，创建一个 `MLGraphBuilder`，添加输入、常量和各种操作。
2. **JavaScript 调用 WebNN API:** 当 JavaScript 代码调用 `MLGraphBuilder` 的方法 (例如 `conv2d`, `add`) 时，浏览器引擎会接收这些调用。
3. **Blink 渲染引擎处理 API 调用:** Blink 渲染引擎的 JavaScript 绑定会将这些 JavaScript 调用转换为对 C++ 代码的调用。例如，调用 `MLGraphBuilder::conv2d` 方法。
4. **`ml_graph_builder.cc` 中的代码执行:**  `MLGraphBuilder::conv2d` 方法会调用到这里列出的 `ConvertToConv2dAttributes` 和 `BuildPool2d` 等函数，来处理选项、验证输入、创建内部操作符表示等。
5. **最终构建图:** 当 JavaScript 代码调用 `MLGraphBuilder.build()` 时，会调用 `BuildWebNNGraphInfo` 函数，将内部图表示转换为 `blink_mojom::GraphInfoPtr`，并发送给底层的 WebNN 实现 (可能在 GPU 进程或其他进程中) 进行执行。

**本部分功能归纳:**

这部分代码主要负责将 WebNN JavaScript API 中用于定义模型构建的各种选项对象转换为引擎内部使用的属性结构体，并根据这些选项和输入操作数构建 WebNN 图中的各种基本操作 (operators)，例如卷积、池化、元素级运算等。同时，它还负责一些基本的输入验证和图的约束确定，为后续的图编译和执行做准备。

Prompt: 
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  attributes.label = options->label().Utf8();
  return attributes;
}

webnn::LstmAttributes ConvertToLstmAttributes(
    const blink::MLLstmOptions* options) {
  CHECK(options);
  webnn::LstmAttributes attributes;

  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  if (options->hasRecurrentBias()) {
    attributes.recurrent_bias = options->recurrentBias()->Descriptor();
  }
  if (options->hasPeepholeWeight()) {
    attributes.peephole_weight = options->peepholeWeight()->Descriptor();
  }
  if (options->hasInitialHiddenState()) {
    attributes.initial_hidden_state =
        options->initialHiddenState()->Descriptor();
  }
  if (options->hasInitialCellState()) {
    attributes.initial_cell_state = options->initialCellState()->Descriptor();
  }
  attributes.activation_count = options->activations().size();
  attributes.return_sequence = options->returnSequence();
  attributes.direction =
      BlinkRecurrentNetworkDirectionToComponent(options->direction().AsEnum());
  attributes.label = options->label().Utf8();
  return attributes;
}

webnn::LstmCellAttributes ConvertToLstmCellAttributes(
    const blink::MLLstmCellOptions* options) {
  CHECK(options);
  webnn::LstmCellAttributes attributes;

  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  if (options->hasRecurrentBias()) {
    attributes.recurrent_bias = options->recurrentBias()->Descriptor();
  }
  if (options->hasPeepholeWeight()) {
    attributes.peephole_weight = options->peepholeWeight()->Descriptor();
  }
  attributes.activation_count = options->activations().size();
  attributes.label = options->label().Utf8();
  return attributes;
}

bool ValidateClampOptions(const MLClampOptions* options,
                          ExceptionState& exception_state) {
  // The generated code of MLClampOptions uses blink::ToRestrictedFloat to
  // convert the min/max value to a single precision float. It will throw on
  // non-finite values.
  const std::string label = options->label().Utf8();
  if (options->hasMinValue() && options->hasMaxValue()) {
    if (options->minValue() > options->maxValue()) {
      exception_state.ThrowTypeError(
          String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
          String::Format("The min value (%f) should be less than or equal to "
                         "the max value (%f).",
                         options->minValue(), options->maxValue()));
      return false;
    }
  }
  return true;
}

MLOperand* BuildArgMinMax(MLGraphBuilder* builder,
                          blink_mojom::ArgMinMax::Kind sub_kind,
                          MLOperand* input,
                          const uint32_t axis,
                          const MLArgMinMaxOptions* options,
                          ExceptionState& exception_state) {
  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateArgMinMaxAndInferOutput(
          builder->GetContext()->GetProperties(), input->Descriptor(),
          options->label().Utf8(), axis,
          FromBlinkDataType(options->outputDataType().AsEnum()),
          options->keepDimensions()));

  auto* arg_min_max = MakeGarbageCollected<MLArgMinMaxOperator>(
      builder, sub_kind, axis, options);
  MLOperand* output = MLOperand::CreateOutput(
      builder, std::move(output_descriptor), arg_min_max);
  arg_min_max->Connect({input}, {output});

  return output;
}

MLOperand* BuildElementWiseBinary(
    MLGraphBuilder* builder,
    blink_mojom::ElementWiseBinary::Kind kind,
    const webnn::SupportedDataTypes& data_type_constraint,
    MLOperand* a,
    MLOperand* b,
    const MLOperatorOptions* options,
    ExceptionState& exception_state) {
  const std::string label = options->label().Utf8();
  if (!data_type_constraint.Has(a->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        String(NotSupportedArgumentTypeError("a", a->DataType(),
                                             data_type_constraint)));
    return nullptr;
  }
  if (!data_type_constraint.Has(b->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        String(NotSupportedArgumentTypeError("b", b->DataType(),
                                             data_type_constraint)));
    return nullptr;
  }

  if (a->DataType() != b->DataType()) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The input operand data types don't match.");
    return nullptr;
  }
  auto output_shape = webnn::BroadcastShapes(a->Shape(), b->Shape());
  if (!output_shape) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The input shapes are not broadcastable.");
    return nullptr;
  }

  // Logical operator outputs are bools, otherwise output operators are the same
  // type as input operators.
  webnn::OperandDataType data_type = IsLogicalBinaryOperator(kind)
                                         ? webnn::OperandDataType::kUint8
                                         : a->DataType();

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::OperandDescriptor::Create(data_type, *output_shape));

  auto* binary = MakeGarbageCollected<MLOperator>(
      builder, /*kind=*/blink_mojom::Operation::Tag::kElementWiseBinary,
      options, /*sub_kind=*/kind);
  MLOperand* output =
      MLOperand::CreateOutput(builder, std::move(output_descriptor), binary);

  binary->Connect({a, b}, {output});
  return output;
}

MLOperand* BuildUnaryOperator(
    MLGraphBuilder* builder,
    ExceptionState& exception_state,
    blink_mojom::Operation::Tag kind,
    const webnn::SupportedDataTypes& data_type_constraint,
    MLOperand* input,
    const MLOperatorOptions* options) {
  // The output tensor of unary operator has the same data type and dimensions
  // as its input tensor.
  if (!data_type_constraint.Has(input->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(options->label().Utf8())) +
        String(NotSupportedInputArgumentTypeError(input->DataType(),
                                                  data_type_constraint)));
    return nullptr;
  }

  auto* unary = MakeGarbageCollected<MLOperator>(builder, kind, options);

  MLOperand* output =
      MLOperand::CreateOutput(builder, input->Descriptor(), unary);
  unary->Connect({input}, {output});
  return output;
}

MLOperand* BuildElementWiseUnaryOperator(
    MLGraphBuilder* builder,
    ExceptionState& exception_state,
    blink_mojom::ElementWiseUnary::Kind kind,
    const webnn::SupportedDataTypes& data_type_constraint,
    MLOperand* input,
    const MLOperatorOptions* options) {
  const std::string label = options->label().Utf8();
  if (!data_type_constraint.Has(input->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(options->label().Utf8())) +
        String(NotSupportedInputArgumentTypeError(input->DataType(),
                                                  data_type_constraint)));
    return nullptr;
  }

  auto* unary = MakeGarbageCollected<MLOperator>(
      builder, /*kind=*/blink_mojom::Operation::Tag::kElementWiseUnary, options,
      /*sub_kind=*/kind);
  MLOperand* output =
      MLOperand::CreateOutput(builder, input->Descriptor(), unary);
  unary->Connect({input}, {output});
  return output;
}

MLOperand* BuildReduce(MLGraphBuilder* builder,
                       blink_mojom::Reduce::Kind kind,
                       const webnn::ContextProperties& context_properties,
                       MLOperand* input,
                       const MLReduceOptions* options,
                       ExceptionState& exception_state) {
  const auto axes = options->getAxesOr(CreateAllAxes(input->Rank()));
  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateReduceAndInferOutput(
          context_properties, MojoReduceKindToComponent(kind),
          input->Descriptor(), options->label().Utf8(), axes,
          options->keepDimensions()));

  auto* reduce = MakeGarbageCollected<MLOperator>(
      builder, /*kind=*/blink_mojom::Operation::Tag::kReduce, options,
      /*sub_kind=*/kind);
  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-reduce, the output
  // tensor of reduce has the same data type as its input.
  MLOperand* output =
      MLOperand::CreateOutput(builder, std::move(output_descriptor), reduce);
  reduce->Connect({input}, {output});
  return output;
}

MLOperand* BuildPool2d(MLGraphBuilder* builder,
                       blink_mojom::Pool2d::Kind kind,
                       const webnn::ContextProperties& context_properties,
                       MLOperand* input,
                       const MLPool2dOptions* options,
                       ExceptionState& exception_state) {
  auto pool2d_attributes = ConvertToPool2dAttributes(options);
  if (!pool2d_attributes.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(pool2d_attributes.error()));
    return nullptr;
  }

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidatePool2dAndInferOutput(
          context_properties, input->Descriptor(),
          std::move(pool2d_attributes.value()), FromMojoPool2dKind(kind)));

  // Create pool2d operator and its output operand. Connect the pool2d operator
  // to its input and output operands.
  auto* pool2d = MakeGarbageCollected<MLOperator>(
      builder, /*kind=*/blink_mojom::Operation::Tag::kPool2d, options,
      /*sub_kind=*/kind);
  MLOperand* output =
      MLOperand::CreateOutput(builder, std::move(output_descriptor), pool2d);
  pool2d->Connect({input}, {output});
  return output;
}

// Determines the input and output resources required for this computational
// graph by traversing the graph from `named_outputs` to its inputs.
// This may fail if the graph is not valid.
base::expected<std::pair<MLGraph::NamedOperandDescriptors,
                         MLGraph::NamedOperandDescriptors>,
               String>
DetermineGraphConstraintsFromOutputs(const MLNamedOperands& named_outputs) {
  // The outputs should not be empty.
  if (named_outputs.empty()) {
    return base::unexpected("At least one output needs to be provided.");
  }

  // The queue and visited set of operators that help implement the
  // breadth-first graph traversal:
  // https://en.wikipedia.org/wiki/Breadth-first_search
  HeapDeque<Member<const MLOperator>> operators_queue;
  HeapHashSet<Member<const MLOperator>> visited_operators;

  MLGraph::NamedOperandDescriptors input_constraints;
  MLGraph::NamedOperandDescriptors output_constraints;

  // Validate the named outputs, setup corresponding output resource info and
  // initialize the queue and visited set with their dependent operators.
  for (const auto& output : named_outputs) {
    const auto& name = output.first;
    const auto& operand = output.second;
    // Validate whether it is an output operand.
    if (operand->Kind() != blink_mojom::Operand::Kind::kOutput) {
      return base::unexpected(String::Format(
          "The operand with name \"%s\" is not an output operand.",
          name.Utf8().c_str()));
    }
    // Setup resource info for this output operand.
    output_constraints.insert(name, operand->Descriptor());
    // Mark its dependent operator is visited.
    visited_operators.insert(operand->Operator());
    // Enqueue its dependent operator.
    operators_queue.push_back(operand->Operator());
  }

  // An input MLOperand may be used by more than one MLOperators. This set
  // ensures an input MLOperand won't be validated multiple times.
  HeapHashSet<Member<const MLOperand>> visited_input_operands;
  while (operators_queue.size() > 0) {
    // If the queue is not empty, dequeue an operator from the queue.
    const auto current_operator = operators_queue.TakeFirst();
    // Enumerate the current operator's input operands.
    for (const auto& operand : current_operator->Inputs()) {
      switch (operand->Kind()) {
        case blink_mojom::Operand::Kind::kOutput:
          DCHECK(operand->Operator());
          // If the operand is an output operand and its dependent operator is
          // not visited, mark the dependent operator is visited and enqueue
          // it.
          if (!visited_operators.Contains(operand->Operator())) {
            visited_operators.insert(operand->Operator());
            operators_queue.push_back(operand->Operator());
          }
          break;
        case blink_mojom::Operand::Kind::kInput:
          // If the operand has been validated, it doesn't need to be verified
          // multiple times.
          if (visited_input_operands.Contains(operand)) {
            continue;
          }
          visited_input_operands.insert(operand);
          // If the operand is an input operand, validate whether its name is
          // unique.
          if (input_constraints.Contains(operand->Name())) {
            return base::unexpected(
                String::Format("The input name \"%s\" is duplicated.",
                               operand->Name().Utf8().c_str()));
          }
          // Setup resource info for this input operand.
          input_constraints.insert(operand->Name(), operand->Descriptor());
          break;
        case blink_mojom::Operand::Kind::kConstant:
          // If the operand has been validated, it doesn't need to be verified
          // multiple times.
          if (visited_input_operands.Contains(operand)) {
            continue;
          }
          visited_input_operands.insert(operand);
          break;
      }
    }
  }
  return std::make_pair(std::move(input_constraints),
                        std::move(output_constraints));
}

base::expected<blink_mojom::GraphInfoPtr, String> BuildWebNNGraphInfo(
    const MLNamedOperands& named_outputs,
    const webnn::ContextProperties& context_properties) {
  // The `GraphInfo` represents an entire information of WebNN graph.
  auto graph_info = blink_mojom::GraphInfo::New();

  HeapHashMap<Member<const MLOperand>, uint64_t> operand_to_id_map;
  for (const auto& [name, operand] : named_outputs) {
    // Create `mojo::Operand` for output operands of graph with the name.
    auto output_operand =
        mojo::ConvertTo<blink_mojom::OperandPtr>(operand.Get());
    output_operand->name = name;
    uint64_t operand_id = NextOperandId(*graph_info);
    graph_info->id_to_operand_map.insert(operand_id, std::move(output_operand));
    graph_info->output_operands.push_back(operand_id);
    operand_to_id_map.insert(operand, operand_id);
  }

  HeapVector<Member<const MLOperator>>* topologically_sorted_operators =
      GetOperatorsInTopologicalOrder(named_outputs);

  // Optimize away redundant constant reshapes by removing the reshape operator
  // and change constant operand's descriptor to the reshape output operand's
  // descriptor.
  // The algorithm walks down all constants and its dependent operators to
  // identify redundant reshapes, skips serialization for reshape operator and
  // points the reshape output operand in `operand_to_id_map` to constant's id.
  HeapHashSet<Member<const MLOperand>> constant_operands;
  for (const auto& current_operator : *topologically_sorted_operators) {
    for (const auto& operand : current_operator->Inputs()) {
      if (operand->Kind() == blink_mojom::Operand::Kind::kConstant) {
        constant_operands.insert(operand);
      }
    }
  }
  // Hash map of redundant reshape output operand from constant that can be
  // removed from the graph.
  HeapHashMap<Member<const MLOperand>, Member<const MLOperand>>
      reshaped_to_constant_mapping;
  HeapHashMap<Member<const MLOperand>, Member<const MLOperand>>
      constant_to_reshaped_mapping;

  for (const auto& constant_operand : constant_operands) {
    Member<const MLOperand> next_operand = constant_operand;
    // For each constant operand, keep walking down the dependencies until no
    // reshape is found.
    while (true) {
      auto dependent_operators = next_operand->DependentOperators();
      // If reshape is the only dependent of the constant, then this reshape
      // operation can be removed from the graph.
      if (dependent_operators.size() != 1) {
        break;
      }
      auto dependent_operator = *dependent_operators.begin();
      if (dependent_operator->Kind() != blink_mojom::Operation::Tag::kReshape) {
        break;
      }
      Member<const MLOperand> reshape_output = dependent_operator->Outputs()[0];
      reshaped_to_constant_mapping.Set(reshape_output, constant_operand);
      constant_to_reshaped_mapping.Set(constant_operand, reshape_output);
      next_operand = reshape_output;
    }
  }
  // Visit the operators in topological order. For each operator,
  // 1, Create `mojo::Operand` for its input and output operands if needed.
  // 2, Create `mojo::Operator` with the id of input and output operands.
  //
  // Skips the redundant constant reshapes.
  for (const auto& current_operator : *topologically_sorted_operators) {
    for (const auto& operand : current_operator->Inputs()) {
      if (operand_to_id_map.Contains(operand.Get())) {
        // The `mojo::Operand` is already converted with the MLOperand, skip it.
        continue;
      }
      switch (operand->Kind()) {
        case blink_mojom::Operand::Kind::kInput: {
          // Create `mojo::Operand` for the input MLOperand.
          uint64_t operand_id = NextOperandId(*graph_info);
          graph_info->id_to_operand_map.insert(
              operand_id,
              mojo::ConvertTo<blink_mojom::OperandPtr>(operand.Get()));
          //  Build the array of input operands for this graph with the id.
          graph_info->input_operands.push_back(operand_id);
          operand_to_id_map.insert(operand, operand_id);
          break;
        }
        case blink_mojom::Operand::Kind::kConstant: {
          // Convert `mojo::Operand` for constant operand.
          uint64_t operand_id = NextOperandId(*graph_info);
          auto mojo_operand =
              mojo::ConvertTo<blink_mojom::OperandPtr>(operand.Get());
          // Set constant's descriptor to the redundant reshape's output's
          // descriptor.
          if (constant_to_reshaped_mapping.Contains(operand)) {
            mojo_operand->descriptor =
                mojo::ConvertTo<blink_mojom::OperandPtr>(
                    constant_to_reshaped_mapping.at(operand))
                    ->descriptor;
          }
          graph_info->id_to_operand_map.insert(operand_id,
                                               std::move(mojo_operand));
          // Build the map of constant operands for this graph with the id.
          graph_info->constant_id_to_buffer_map.insert(
              operand_id, operand->AsConstantOperand()->Bytes());
          operand_to_id_map.insert(operand, operand_id);
          break;
        }
        case blink_mojom::Operand::Kind::kOutput:
          // Because the operators are visited in topological order, if this
          // operand is an intermediate operand, it should already be defined as
          // an output operand of the dependent operator.
          NOTREACHED();
      }
    }
    bool is_redundant_reshape = false;
    for (const auto& operand : current_operator->Outputs()) {
      if (operand_to_id_map.Contains(operand.Get())) {
        // The `mojo::Operand` is already converted with the MLOperand, skip it.
        continue;
      }

      if (reshaped_to_constant_mapping.Contains(operand)) {
        is_redundant_reshape = true;
        // Point redundant reshape's output operand to its corresponding
        // constant operand.
        operand_to_id_map.insert(
            operand,
            operand_to_id_map.at(reshaped_to_constant_mapping.at(operand)));
        continue;
      }
      // Because the graph's output operands are already converted before, this
      // operand should be an intermediate operand that connects with two
      // operators. Create `mojo::Operand` for this operand.
      uint64_t operand_id = NextOperandId(*graph_info);
      graph_info->id_to_operand_map.insert(
          operand_id, mojo::ConvertTo<blink_mojom::OperandPtr>(operand.Get()));
      operand_to_id_map.insert(operand, operand_id);
    }
    if (is_redundant_reshape) {
      continue;
    }
    // Create `mojo::Operation` with the id of the input and output operands.
    std::optional<String> error =
        SerializeMojoOperation(operand_to_id_map, context_properties,
                               current_operator.Get(), graph_info.get());
    if (error.has_value()) {
      // Return here if the operator is not implemented.
      return base::unexpected(*error);
    }
  }

  return graph_info;
}

}  // namespace

// static
MLGraphBuilder* MLGraphBuilder::Create(ScriptState* script_state,
                                       MLContext* context,
                                       ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return nullptr;
  }

  return context->CreateWebNNGraphBuilder(script_state, exception_state);
}

MLGraphBuilder::MLGraphBuilder(
    ExecutionContext* execution_context,
    MLContext* context,
    mojo::PendingAssociatedRemote<blink_mojom::WebNNGraphBuilder>
        pending_remote)
    : ml_context_(context), remote_(execution_context) {
  CHECK(base::FeatureList::IsEnabled(
      webnn::mojom::features::kWebMachineLearningNeuralNetwork));

  remote_.Bind(std::move(pending_remote),
               execution_context->GetTaskRunner(TaskType::kMachineLearning));
  remote_.set_disconnect_handler(WTF::BindOnce(
      &MLGraphBuilder::OnConnectionError, WrapWeakPersistent(this)));
}

MLGraphBuilder::~MLGraphBuilder() = default;

void MLGraphBuilder::Trace(Visitor* visitor) const {
  visitor->Trace(ml_context_);
  visitor->Trace(remote_);
  visitor->Trace(constant_operands_);
  visitor->Trace(pending_resolver_);
  ScriptWrappable::Trace(visitor);
}

MLContext* MLGraphBuilder::GetContext() const {
  return ml_context_.Get();
}

MLOperand* MLGraphBuilder::input(ScriptState* script_state,
                                 String name,
                                 const MLOperandDescriptor* desc,
                                 ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  auto input_operand = MLOperand::ValidateAndCreateInput(
      this, desc->dataType().AsEnum(), desc->shape(), std::move(name));
  if (!input_operand.has_value()) {
    exception_state.ThrowTypeError(input_operand.error());
    return nullptr;
  }

  if (!ml_context_->GetProperties().data_type_limits.input.Has(
          input_operand.value()->DataType())) {
    exception_state.ThrowTypeError(String(webnn::NotSupportedInputTypeError(
        input_operand.value()->Name().Utf8(), input_operand.value()->DataType(),
        ml_context_->GetProperties().data_type_limits.input)));
    return nullptr;
  }

  return input_operand.value();
}

MLOperand* MLGraphBuilder::constant(ScriptState* script_state,
                                    const MLOperandDescriptor* desc,
                                    NotShared<DOMArrayBufferView> buffer_view,
                                    ExceptionState& exception_state) {
  CHECK(buffer_view);

  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor descriptor,
      webnn::OperandDescriptor::Create(
          FromBlinkDataType(desc->dataType().AsEnum()), desc->shape()));

  if (GetArrayBufferViewType(descriptor.data_type()) !=
      buffer_view->GetType()) {
    exception_state.ThrowTypeError(
        "The buffer view type doesn't match the operand data type.");
    return nullptr;
  }

  if (descriptor.PackedByteLength() != buffer_view->byteLength()) {
    exception_state.ThrowTypeError(String::Format(
        "The buffer view byte length (%zu) doesn't match the "
        "expected byte length (%zu).",
        buffer_view->byteLength(), descriptor.PackedByteLength()));
    return nullptr;
  }

  if (!ml_context_->GetProperties().data_type_limits.constant.Has(
          descriptor.data_type())) {
    exception_state.ThrowTypeError(String(webnn::NotSupportedConstantTypeError(
        descriptor.data_type(),
        ml_context_->GetProperties().data_type_limits.constant)));
    return nullptr;
  }

  auto* constant_operand = MakeGarbageCollected<MLConstantOperand>(this, std::move(descriptor),
                                                 buffer_view->ByteSpan());
  constant_operands_.push_back(constant_operand);
  return constant_operand;
}

MLOperand* MLGraphBuilder::argMin(MLOperand* input,
                                  const uint32_t axis,
                                  const MLArgMinMaxOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);
  return BuildArgMinMax(this, blink_mojom::ArgMinMax::Kind::kMin, input, axis,
                        options, exception_state);
}

MLOperand* MLGraphBuilder::argMax(MLOperand* input,
                                  const uint32_t axis,
                                  const MLArgMinMaxOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);
  return BuildArgMinMax(this, blink_mojom::ArgMinMax::Kind::kMax, input, axis,
                        options, exception_state);
}

MLOperand* MLGraphBuilder::batchNormalization(
    MLOperand* input,
    MLOperand* mean,
    MLOperand* variance,
    const MLBatchNormalizationOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, mean, variance};
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
      webnn::ValidateBatchNormalizationAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(), mean->Descriptor(),
          variance->Descriptor(),
          ConvertToBatchNormalizationAttributes(options)));

  // Create batchNormalization operator and its output operand. Connect the
  // batchNormalization operator to its input and output operands.
  auto* batch_normalization = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kBatchNormalization, options);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), batch_normalization);
  batch_normalization->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::concat(const HeapVector<Member<MLOperand>>& inputs,
                                  const uint32_t axis,
                                  const MLOperatorOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  std::vector<webnn::OperandDescriptor> input_component_operands;
  input_component_operands.reserve(inputs.size());
  base::ranges::transform(
      inputs, std::back_inserter(input_component_operands),
      [](const auto& input) { return input->Descriptor(); });

  const std::string label = options->label().Utf8();
  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateConcatAndInferOutput(
          ml_context_->GetProperties(), input_component_operands, axis, label));

  auto* concat = MakeGarbageCollected<MLConcatOperator>(this, axis, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), concat);

  concat->Connect(inputs, {output});
  return output;
}

MLOperand* MLGraphBuilder::clamp(MLOperand* input,
                                 const MLClampOptions* options,
                                 ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  if (!ValidateClampOptions(options, exception_state)) {
    return nullptr;
  }

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-clamp, the output tensor of
  // clamp has the same data type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kClamp,
      ml_context_->GetProperties().data_type_limits.clamp_input, input,
      options);
}

MLOperand* MLGraphBuilder::conv2d(MLOperand* input,
                                  MLOperand* filter,
                                  const MLConv2dOptions* options,
                                  ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, filter};
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  auto conv2d_attributes = ConvertToConv2dAttributes(options);
  if (!conv2d_attributes.has_value()) {
    exception_state.ThrowTypeError(conv2d_attributes.error());
    return nullptr;
  }

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateConv2dAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          filter->Descriptor(), std::move(conv2d_attributes.value())));

  // Create conv2d operator and its output operand. Connect the conv2d operator
  // to its input and output operands.
  auto* conv2d = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kConv2d, options,
      /*sub_type=*/blink_mojom::Conv2d::Kind::kDirect);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), conv2d);
  conv2d->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::convTranspose2d(
    MLOperand* input,
    MLOperand* filter,
    const MLConvTranspose2dOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, filter};
  if (options->hasBias()) {
    inputs.push_back(options->bias());
  }
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  auto convTranspose2d_attributes = ConvertToConvTranspose2dAttributes(options);
  if (!convTranspose2d_attributes.has_value()) {
    exception_state.ThrowTypeError(convTranspose2d_attributes.error());
    return nullptr;
  }

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateConvTranspose2dAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          filter->Descriptor(), std::move(convTranspose2d_attributes.value())));

  // Create convTranspose2d operator and its output operand. Connect the
  // convTranspose2d operator to its input and output operands.
  auto* convTranspose2d = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kConv2d, options,
      /*sub_type=*/blink_mojom::Conv2d::Kind::kTransposed);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), convTranspose2d);
  convTranspose2d->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::cumulativeSum(MLOperand* input,
                                         const uint32_t axis,
                                         const MLCumulativeSumOptions* options,
                                        
"""


```