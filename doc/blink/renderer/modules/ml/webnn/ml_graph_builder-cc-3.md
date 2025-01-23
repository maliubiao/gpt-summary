Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. The code defines the `MLGraphBuilder` class, which is part of the Web Neural Network (WebNN) API implementation. I need to identify the core purpose of this class and how its methods contribute to that purpose. I also need to consider the relationships with JavaScript, HTML, and CSS, provide examples of logical inference, highlight potential user errors, and trace user actions leading to this code.

Here's a breakdown of the steps:

1. **Identify the Core Functionality:** The primary role of `MLGraphBuilder` is to provide an interface for constructing WebNN graphs. These graphs represent machine learning models.

2. **Analyze Individual Methods:**  Go through each method and determine its specific function in building the graph. Most methods correspond to specific neural network operations (e.g., `add`, `conv2d`, `relu`).

3. **Relate to Web Technologies:** Explain how this C++ code interacts with JavaScript (the primary interface for WebNN), HTML (where JavaScript code is embedded), and CSS (less directly related but can influence application behavior).

4. **Provide Logical Inference Examples:** For some methods, illustrate the input and output based on the operation they perform.

5. **Identify Common User Errors:**  Think about how developers using the WebNN API might misuse these functions.

6. **Trace User Actions:** Describe a typical scenario where a web developer would use the WebNN API, leading to the execution of this C++ code.

7. **Synthesize a Summary:** Combine the individual method analyses into a concise summary of the `MLGraphBuilder`'s overall function.
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

基于提供的代码片段，`MLGraphBuilder::build` 和 `MLGraphBuilder::DidCreateWebNNGraph` 以及后续错误处理和验证函数，可以归纳出以下功能：

**MLGraphBuilder 的核心功能（结合所有部分）：**

`MLGraphBuilder` 类是 Chromium Blink 引擎中用于构建 Web Neural Network (WebNN) 图的核心组件。 它提供了一系列方法，允许 JavaScript 代码通过 WebNN API 来定义和构建机器学习模型的计算图。  这个类的主要功能可以归纳为：

1. **定义计算图节点（Operations）：**  提供了一系列方法（如 `add`, `conv2d`, `relu`, `matmul` 等）来表示神经网络中的各种操作或层。每个方法接收输入操作数（`MLOperand`）和可选的参数（`MLOperatorOptions` 等），并返回一个新的输出操作数。
2. **管理计算图中的数据（Operands）：**  负责创建和管理计算图中的张量数据（`MLOperand`），这些数据在操作之间流动。
3. **验证计算图的结构和参数：**  在构建过程中进行各种验证，例如检查输入操作数的类型、维度是否匹配，以及参数是否合法。如果验证失败，会抛出 JavaScript 异常。
4. **将计算图转换为底层表示：**  将用户通过 JavaScript 定义的计算图转换为浏览器底层可以执行的表示形式（通过 `blink_mojom::Operation::Tag` 枚举表示操作类型）。
5. **与 GPU 或其他加速器进行交互：**  通过 `ml_context_` 与底层的 WebNN 实现（可能使用 GPU 或其他硬件加速器）进行通信，将构建好的图传递给它们。
6. **处理异步构建过程：**  `build` 方法是异步的，它返回一个 Promise，当计算图成功构建后 resolve，或在构建失败时 reject。
7. **处理构建过程中的错误：**  捕获并处理构建过程中可能出现的错误，并将错误信息传递给 JavaScript。
8. **资源管理：**  管理计算图中常量数据的生命周期，并在构建完成后释放这些资源。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** `MLGraphBuilder` 是 WebNN API 的 C++ 实现部分，JavaScript 代码通过 WebNN API 与其直接交互。开发者在 JavaScript 中调用 `navigator.ml.createGraphBuilder()` 获取 `MLGraphBuilder` 实例，然后调用其上的各种方法（如 `add()`, `conv2d()`) 来构建模型。
    ```javascript
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [1, 28, 28, 1] });
    const conv2dOutput = builder.conv2d(input, weights, { padding: 'same', strides: [1, 1] });
    const output = builder.output(conv2dOutput);
    const graph = await builder.build({ output });
    ```
* **HTML:** HTML 文件中通常包含 `<script>` 标签，用于嵌入或引用包含 WebNN API 使用代码的 JavaScript 文件。当浏览器解析到这些 JavaScript 代码并执行时，就会调用到 `MLGraphBuilder` 的相关功能。
* **CSS:** CSS 对 `MLGraphBuilder` 的功能没有直接关系。CSS 主要负责页面的样式和布局，而 `MLGraphBuilder` 负责构建机器学习模型。然而，机器学习模型的输出结果可能会影响页面的展示，从而间接地与 CSS 产生联系。例如，一个图像识别模型识别出图像中的物体，然后 JavaScript 可以根据识别结果动态修改 HTML 元素和它们的 CSS 样式。

**逻辑推理的例子：**

考虑 `averagePool2d` 方法：

* **假设输入：**
    * `input`: 一个 `MLOperand`，表示一个形状为 `[1, 10, 10, 3]` 的浮点型特征图。
    * `options`: 一个 `MLPool2dOptions` 对象，设置 `windowDimensions` 为 `[2, 2]`，`strides` 为 `[2, 2]`，`padding` 为 `'same'`。
* **逻辑推理：**  `averagePool2d` 操作会对输入特征图应用 2x2 的平均池化窗口，步长为 2x2。`padding: 'same'` 表示输出特征图的尺寸与输入特征图的尺寸除以步长后的尺寸相同。
* **预期输出：**  `averagePool2d` 方法将返回一个新的 `MLOperand`，表示池化后的特征图。根据上述输入和选项，输出特征图的形状可能是 `[1, 5, 5, 3]`。

**用户或编程常见的使用错误：**

* **数据类型不匹配：**  例如，`averagePool2d` 方法的代码片段中检查了输入数据类型必须是浮点型。如果用户传递了一个整型 `MLOperand`，将会抛出 `TypeError`。
    ```javascript
    // 错误示例：输入数据类型为 int32
    const input = builder.input('input', { type: 'int32', dimensions: [1, 10, 10, 3] });
    builder.averagePool2d(input, {}); // 这里会抛出 TypeError
    ```
* **操作数来自不同的构建器：**  一个 `MLOperand` 只能属于一个 `MLGraphBuilder` 实例。如果尝试将一个构建器创建的 `MLOperand` 作为另一个构建器的操作输入，将会导致错误。
    ```javascript
    const builder1 = await navigator.ml.createGraphBuilder();
    const input1 = builder1.input('input', { type: 'float32', dimensions: [1, 10] });
    const builder2 = await navigator.ml.createGraphBuilder();
    builder2.relu(input1); // 这里会因为 input1 来自 builder1 而报错
    ```
* **构建后尝试添加操作：**  一旦调用了 `build()` 方法，`MLGraphBuilder` 的状态变为已构建，不能再添加新的操作。
    ```javascript
    const builder = await navigator.ml.createGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [1, 10] });
    const reluOutput = builder.relu(input);
    await builder.build({ output: reluOutput });
    builder.add(reluOutput, anotherInput); // 在 build() 之后添加操作会报错
    ```
* **输出名称重复：** 在 `build()` 方法中，如果 `named_outputs` 中存在重复的输出名称，可能会导致错误。

**用户操作到达这里的步骤（调试线索）：**

1. **用户编写包含 WebNN API 的 JavaScript 代码：**  开发者在 JavaScript 代码中使用 `navigator.ml.createGraphBuilder()` 获取 `MLGraphBuilder` 实例。
2. **定义计算图：**  开发者调用 `MLGraphBuilder` 上的各种方法（如 `conv2d()`, `relu()`, `add()` 等）来描述神经网络的结构和操作。这些调用会创建对应的 `MLOperator` 和 `MLOperand` 对象。
3. **指定输出：**  开发者通过 `builder.output()` 方法标记计算图的输出节点，并给它们命名。
4. **调用 `build()` 方法：**  当计算图定义完成后，开发者调用 `builder.build(namedOutputs)` 方法，传入一个包含输出名称和对应 `MLOperand` 的对象。
5. **进入 C++ 代码：**  `build()` 方法的调用会触发 Blink 引擎中对应的 C++ 代码执行，即 `blink::MLGraphBuilder::build()`。
6. **图的验证和转换：**  在 `build()` 方法内部，会进行一系列的验证，并将用户定义的计算图转换为底层的 `WebNNGraphInfo` 结构。
7. **创建底层图：**  `remote_->CreateGraph()` 调用会将构建好的图信息传递给底层的 WebNN 实现（可能运行在 GPU 进程中）。
8. **接收创建结果：**  底层图创建完成后，会调用 `MLGraphBuilder::DidCreateWebNNGraph` 方法，该方法处理创建结果（成功或失败）。

**第4部分的功能归纳：**

提供的代码片段是 `MLGraphBuilder` 类的实现的一部分，重点在于：

* **构建过程的最终阶段：**  `build()` 方法是构建计算图的最后一步，它会触发对已定义图的验证、转换和底层创建。
* **异步处理：**  `build()` 方法使用 Promise 来处理异步的图构建过程。
* **底层图的创建和结果处理：**  `DidCreateWebNNGraph()` 方法接收底层图创建的结果，并将结果传递给 JavaScript 的 Promise。
* **错误处理：**  包含了对构建过程中可能出现的错误的捕获和处理机制，并将错误信息返回给 JavaScript。
* **资源管理：** `ReleaseConstantData()` 用于释放不再需要的常量数据。
* **状态管理和验证：** `ValidateGraphBuilderState()` 用于检查构建器的状态是否有效。

总而言之，这部分代码负责将用户在 JavaScript 中定义的 WebNN 计算图“物化”成浏览器底层可以执行的结构，并处理构建过程中的异步性和潜在的错误。

### 提示词
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
pad->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::averagePool2d(MLOperand* input,
                                         const MLPool2dOptions* options,
                                         ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();
  if (!(input->DataType() == webnn::OperandDataType::kFloat32 ||
        input->DataType() == webnn::OperandDataType::kFloat16)) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The input data type must be a floating point type.");
    return nullptr;
  }

  return BuildPool2d(this, blink_mojom::Pool2d::Kind::kAveragePool2d,
                     ml_context_->GetProperties(), input, options,
                     exception_state);
}

MLOperand* MLGraphBuilder::l2Pool2d(MLOperand* input,
                                    const MLPool2dOptions* options,
                                    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();
  if (!(input->DataType() == webnn::OperandDataType::kFloat32 ||
        input->DataType() == webnn::OperandDataType::kFloat16)) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The input data type must be a floating point type.");
    return nullptr;
  }

  return BuildPool2d(this, blink_mojom::Pool2d::Kind::kL2Pool2d,
                     ml_context_->GetProperties(), input, options,
                     exception_state);
}

MLOperand* MLGraphBuilder::maxPool2d(MLOperand* input,
                                     const MLPool2dOptions* options,
                                     ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  return BuildPool2d(this, blink_mojom::Pool2d::Kind::kMaxPool2d,
                     ml_context_->GetProperties(), input, options,
                     exception_state);
}

MLOperand* MLGraphBuilder::prelu(MLOperand* input,
                                 MLOperand* slope,
                                 const MLOperatorOptions* options,
                                 ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, slope};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidatePreluAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          slope->Descriptor(), options->label().Utf8()));

  auto* prelu = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kPrelu, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), prelu);

  prelu->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::quantizeLinear(MLOperand* input,
                                          MLOperand* scale,
                                          MLOperand* zeroPoint,
                                          const MLOperatorOptions* options,
                                          ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  HeapVector<Member<MLOperand>> inputs = {input, scale, zeroPoint};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateQuantizeLinearAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          scale->Descriptor(), zeroPoint->Descriptor(),
          options->label().Utf8()));

  auto* quantize_linear = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kQuantizeLinear, options);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), quantize_linear);
  quantize_linear->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::relu(MLOperand* input,
                                const MLOperatorOptions* options,
                                ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-relu, the output tensor of
  // relu has the same data type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kRelu,
      ml_context_->GetProperties().data_type_limits.relu_input, input, options);
}

MLOperand* MLGraphBuilder::reshape(MLOperand* input,
                                   const Vector<uint32_t>& new_shape,
                                   const MLOperatorOptions* options,
                                   ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();

  if (!ml_context_->GetProperties().data_type_limits.reshape_input.Has(
          input->DataType())) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        String(NotSupportedInputArgumentTypeError(
            input->DataType(),
            ml_context_->GetProperties().data_type_limits.reshape_input)));
    return nullptr;
  }

  // Setting the initial number of elements to 1 would cover the 0-D scalar with
  // empty dimensions.
  base::CheckedNumeric<size_t> checked_newshape_number_of_elements = 1;
  Vector<uint32_t> output_shape(new_shape.size());
  for (wtf_size_t i = 0; i < new_shape.size(); ++i) {
    auto dim = new_shape[i];
    if (dim == 0) {
      exception_state.ThrowTypeError(
          String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
          "The value of new shape should not be 0.");
      return nullptr;
    }
    checked_newshape_number_of_elements *= dim;
    output_shape[i] = dim;
  }
  size_t newshape_number_of_elements;
  if (!checked_newshape_number_of_elements.AssignIfValid(
          &newshape_number_of_elements)) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The number of elements implied by new shape is too large.");
    return nullptr;
  }
  DCHECK_NE(newshape_number_of_elements, size_t(0));
  // The number of elements implied by new shape must be the same as the
  // number of elements in the input tensor.
  if (input->NumberOfElements() != newshape_number_of_elements) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        String::Format(
            "The number of elements (%zu) implied by new shape doesn't match "
            "the number of elements (%zu) in the input tensor.",
            newshape_number_of_elements, input->NumberOfElements()));
    return nullptr;
  }

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::OperandDescriptor::Create(input->DataType(), output_shape));

  auto* reshape = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kReshape, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), reshape);

  reshape->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::resample2d(ScriptState* script_state,
                                      MLOperand* input,
                                      const MLResample2dOptions* options,
                                      ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  const std::string label = options->label().Utf8();
  absl::variant<base::span<const float>, base::span<const uint32_t>>
      scales_or_sizes;
  Vector<float> default_scales = {1.0, 1.0};
  if (options->hasSizes()) {
    if (options->hasScales()) {
      LogConsoleWarning(script_state,
                        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
                            "When sizes and scales are both "
                            "specified, scales argument is "
                            "ignored.");
    }
    scales_or_sizes = options->sizes();
  } else {
    scales_or_sizes = options->hasScales() ? options->scales() : default_scales;
  }

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateResample2dAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(), scales_or_sizes,
          options->getAxesOr({2, 3}), label));

  // Create resample2d operator and its output operand. Connect the resample2d
  // operator to its input and output operands.
  auto* resample2d = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kResample2d, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), resample2d);

  resample2d->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::reverse(MLOperand* input,
                                   const MLReverseOptions* options,
                                   ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  Vector<uint32_t> axes = options->getAxesOr(CreateAllAxes(input->Rank()));
  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateReverseAndInferOutput(ml_context_->GetProperties(),
                                           input->Descriptor(), axes,
                                           options->label().Utf8()));

  auto* reverse =
      MakeGarbageCollected<MLReverseOperator>(this, std::move(axes), options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), reverse);

  reverse->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::scatterElements(MLOperand* input,
                                           MLOperand* indices,
                                           MLOperand* updates,
                                           const MLScatterOptions* options,
                                           ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, indices, updates};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateScatterElementsAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          indices->Descriptor(), updates->Descriptor(), options->axis(),
          options->label().Utf8()));

  auto* scatter_elements = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kScatterElements, options);
  MLOperand* output = MLOperand::CreateOutput(
      this, std::move(output_descriptor), scatter_elements);

  scatter_elements->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::scatterND(MLOperand* input,
                                     MLOperand* indices,
                                     MLOperand* updates,
                                     const MLOperatorOptions* options,
                                     ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {input, indices, updates};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateScatterNDAndInferOutput(
          ml_context_->GetProperties(), input->Descriptor(),
          indices->Descriptor(), updates->Descriptor(),
          options->label().Utf8()));

  auto* scatter_nd = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kScatterNd, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), scatter_nd);

  scatter_nd->Connect(std::move(inputs), {output});
  return output;
}

MLOperand* MLGraphBuilder::sigmoid(MLOperand* input,
                                   const MLOperatorOptions* options,
                                   ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://webmachinelearning.github.io/webnn/#api-mlgraphbuilder-sigmoid, the
  // output tensor of sigmoid has the same data type and dimensions as its
  // input. And the input data type must be one of the floating point types.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kSigmoid,
      ml_context_->GetProperties().data_type_limits.sigmoid_input, input,
      options);
}

MLOperand* MLGraphBuilder::slice(MLOperand* input,
                                 const Vector<uint32_t>& starts,
                                 const Vector<uint32_t>& sizes,
                                 const MLSliceOptions* options,
                                 ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  webnn::SliceAttributes attributes;
  attributes.sizes.assign(sizes.begin(), sizes.end());
  attributes.starts.assign(starts.begin(), starts.end());
  Vector<uint32_t> strides =
      options->getStridesOr(CreateSliceDefaultStrides(input->Rank()));
  attributes.strides.assign(strides.begin(), strides.end());
  attributes.label = options->label().Utf8();

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateSliceAndInferOutput(ml_context_->GetProperties(),
                                         input->Descriptor(), attributes));

  auto* slice = MakeGarbageCollected<MLSliceOperator>(this, starts, sizes,
                                                      strides, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), slice);

  slice->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::softmax(MLOperand* input,
                                   uint32_t axis,
                                   const MLOperatorOptions* options,
                                   ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateSoftmaxAndInferOutput(ml_context_->GetProperties(),
                                           input->Descriptor(), axis,
                                           options->label().Utf8()));

  auto* softmax = MakeGarbageCollected<MLSoftmaxOperator>(this, axis, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), softmax);

  softmax->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::softmax(MLOperand* input,
                                   const MLOperatorOptions* options,
                                   ExceptionState& exception_state) {
  // This is to emulate the deprecated 2-D softmax until all Chrome channels
  // support the latest version.
  if (input->Rank() != 2) {
    exception_state.ThrowTypeError(
        String::FromUTF8(webnn::GetErrorLabelPrefix(options->label().Utf8())) +
        "The input must be a 2-D tensor.");
    return nullptr;
  }
  return softmax(input, /*axis=*/1, options, exception_state);
}

MLOperand* MLGraphBuilder::softplus(MLOperand* input,
                                    const MLOperatorOptions* options,
                                    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-softplus, the output
  // tensor of softplus has the same type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kSoftplus,
      ml_context_->GetProperties().data_type_limits.softplus_input, input,
      options);
}

MLOperand* MLGraphBuilder::softsign(MLOperand* input,
                                    const MLOperatorOptions* options,
                                    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-softsign, the output tensor
  // of softsign has the same data type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kSoftsign,
      ml_context_->GetProperties().data_type_limits.softsign_input, input,
      options);
}

HeapVector<Member<const MLOperand>> MLGraphBuilder::split(
    MLOperand* input,
    const uint32_t splits,
    const MLSplitOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(),
                            HeapVector<Member<const MLOperand>>());
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input),
                                 HeapVector<Member<const MLOperand>>());

  auto validated_outputs = webnn::ValidateSplitAndInferOutput(
      ml_context_->GetProperties(), input->Descriptor(),
      {.splits = splits,
       .axis = options->axis(),
       .label = options->label().Utf8()});
  if (!validated_outputs.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(validated_outputs.error()));
    return {};
  }

  auto* split = MakeGarbageCollected<MLSplitOperator>(this, splits, options);
  HeapVector<Member<const MLOperand>> outputs;
  for (const auto& validated_output : validated_outputs.value()) {
    outputs.push_back(MLOperand::CreateOutput(this, validated_output, split));
  }
  split->Connect({input}, outputs);
  return outputs;
}

HeapVector<Member<const MLOperand>> MLGraphBuilder::split(
    MLOperand* input,
    const Vector<uint32_t>& splits,
    const MLSplitOptions* options,
    ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(),
                            HeapVector<Member<const MLOperand>>());
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input),
                                 HeapVector<Member<const MLOperand>>());

  auto validated_outputs = webnn::ValidateSplitAndInferOutput(
      ml_context_->GetProperties(), input->Descriptor(),
      {.splits = splits,
       .axis = options->axis(),
       .label = options->label().Utf8()});
  if (!validated_outputs.has_value()) {
    exception_state.ThrowTypeError(String::FromUTF8(validated_outputs.error()));
    return {};
  }

  auto* split = MakeGarbageCollected<MLSplitOperator>(this, splits, options);
  HeapVector<Member<const MLOperand>> outputs;
  for (const auto& validated_output : validated_outputs.value()) {
    outputs.push_back(MLOperand::CreateOutput(this, validated_output, split));
  }
  split->Connect({input}, outputs);
  return outputs;
}

MLOperand* MLGraphBuilder::tanh(MLOperand* input,
                                const MLOperatorOptions* options,
                                ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // The input data type must be one of the floating point types.
  // The current spec doesn't specify the operand data type constraints of tanh,
  // an issue has been filed to track it-
  // https://github.com/webmachinelearning/webnn/issues/283.
  //
  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-tanh, the output tensor of
  // tanh has the same data type and dimensions as its input.
  return BuildUnaryOperator(
      this, exception_state, blink_mojom::Operation::Tag::kTanh,
      ml_context_->GetProperties().data_type_limits.tanh_input, input, options);
}

MLOperand* MLGraphBuilder::tile(MLOperand* input,
                                const Vector<uint32_t>& repetitions,
                                const MLOperatorOptions* options,
                                ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateTileAndInferOutput(ml_context_->GetProperties(),
                                        input->Descriptor(), repetitions,
                                        options->label().Utf8()));

  auto* tile = MakeGarbageCollected<MLTileOperator>(this, repetitions, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), tile);

  tile->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::transpose(MLOperand* input,
                                     const MLTransposeOptions* options,
                                     ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  // According to WebNN spec:
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-transpose,
  // When permutation is not specified, it’s set to [N-1, ..., 0], where N is
  // the rank of the input tensor.
  const Vector<uint32_t> permutation =
      options->getPermutationOr(CreateDefaultPermutation(input->Rank()));
  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateTransposeAndInferOutput(ml_context_->GetProperties(),
                                             input->Descriptor(), permutation,
                                             options->label().Utf8()));

  auto* transpose = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kTranspose, options);
  // According to WebNN spec
  // https://www.w3.org/TR/webnn/#api-mlgraphbuilder-transpose, the output
  // tensor of transpose has the same data type as its input.
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), transpose);

  transpose->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::triangular(MLOperand* input,
                                      const MLTriangularOptions* options,
                                      ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInput(input), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateTriangularAndInferOutput(ml_context_->GetProperties(),
                                              input->Descriptor(),
                                              options->label().Utf8()));

  auto* triangular = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kTriangular, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), triangular);

  triangular->Connect({input}, {output});
  return output;
}

MLOperand* MLGraphBuilder::where(MLOperand* condition,
                                 MLOperand* true_value,
                                 MLOperand* false_value,
                                 const MLOperatorOptions* options,
                                 ExceptionState& exception_state) {
  THROW_AND_RETURN_IF_ERROR(ValidateGraphBuilderState(), nullptr);

  HeapVector<Member<MLOperand>> inputs = {condition, true_value, false_value};
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(inputs), nullptr);

  ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(
      webnn::OperandDescriptor output_descriptor,
      webnn::ValidateWhereAndInferOutput(
          ml_context_->GetProperties(), condition->Descriptor(),
          true_value->Descriptor(), false_value->Descriptor(),
          options->label().Utf8()));

  auto* where = MakeGarbageCollected<MLOperator>(
      this, blink_mojom::Operation::Tag::kWhere, options);
  MLOperand* output =
      MLOperand::CreateOutput(this, std::move(output_descriptor), where);
  where->Connect(std::move(inputs), {output});
  return output;
}

ScriptPromise<MLGraph> MLGraphBuilder::build(
    ScriptState* script_state,
    const MLNamedOperands& named_outputs,
    ExceptionState& exception_state) {
  base::expected<void, String> validation_result = ValidateGraphBuilderState();
  if (!validation_result.has_value()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      std::move(validation_result.error()));
    return EmptyPromise();
  }

  HeapVector<Member<MLOperand>> outputs(named_outputs.size());
  base::ranges::transform(
      named_outputs, outputs.begin(),
      [](const auto& named_output) { return named_output.second; });
  THROW_AND_RETURN_TYPE_IF_ERROR(ValidateInputs(outputs),
                                 ScriptPromise<MLGraph>());

  for (const auto& named_output : named_outputs) {
    if (!ml_context_->GetProperties().data_type_limits.output().Has(
            named_output.second->DataType())) {
      exception_state.ThrowTypeError(String(webnn::NotSupportedOutputTypeError(
          named_output.first.Utf8(), named_output.second->DataType(),
          ml_context_->GetProperties().data_type_limits.output())));
      return EmptyPromise();
    }
  }

  ScopedMLTrace scoped_trace("MLGraphBuilder::build");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return EmptyPromise();
  }

  auto graph_constraints = DetermineGraphConstraintsFromOutputs(named_outputs);
  if (!graph_constraints.has_value()) {
    exception_state.ThrowTypeError(graph_constraints.error());
    return EmptyPromise();
  }

  auto graph_info =
      BuildWebNNGraphInfo(named_outputs, ml_context_->GetProperties());
  if (!graph_info.has_value()) {
    // TODO(crbug.com/345271830): Move the platform-specific checks into the
    // respective synchronous operator builder methods, such that
    // `BuildWebNNGraphInfo` always succeeds.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Failed to build graph: " + graph_info.error());
    return EmptyPromise();
  }

  // Set `has_built_` after all inputs have been validated.
  has_built_ = true;

  RecordOperatorsUsed(**graph_info);

  // Release constant data held by the renderer now that it has been copied to
  // the remote graph.
  ReleaseConstantData();

  pending_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<MLGraph>>(
      script_state, exception_state.GetContext());

  remote_->CreateGraph(
      *std::move(graph_info),
      WTF::BindOnce(&MLGraphBuilder::DidCreateWebNNGraph, WrapPersistent(this),
                    WrapPersistent(pending_resolver_.Get()),
                    *std::move(graph_constraints)));
  return pending_resolver_->Promise();
}

void MLGraphBuilder::DidCreateWebNNGraph(
    ScriptPromiseResolver<blink::MLGraph>* resolver,
    std::pair<MLGraph::NamedOperandDescriptors,
              MLGraph::NamedOperandDescriptors> input_and_output_constraints,
    blink_mojom::CreateGraphResultPtr result) {
  CHECK(has_built_);

  pending_resolver_.Clear();

  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }

  if (result->is_error()) {
    const auto& create_graph_error = result->get_error();
    resolver->RejectWithDOMException(
        WebNNErrorCodeToDOMExceptionCode(create_graph_error->code),
        create_graph_error->message);
    return;
  }

  auto* graph = MakeGarbageCollected<MLGraph>(
      resolver->GetExecutionContext(), ml_context_,
      std::move(result->get_graph_remote()),
      std::move(input_and_output_constraints.first),
      std::move(input_and_output_constraints.second),
      base::PassKey<MLGraphBuilder>());
  ml_context_->OnGraphCreated(graph);

  resolver->Resolve(graph);
}

void MLGraphBuilder::OnConnectionError() {
  remote_.reset();

  ReleaseConstantData();

  if (pending_resolver_) {
    pending_resolver_->RejectWithDOMException(
        DOMExceptionCode::kInvalidStateError, "Context is lost.");
    pending_resolver_.Clear();
  }
}

base::expected<void, String> MLGraphBuilder::ValidateGraphBuilderState() const {
  if (has_built_) {
    return base::unexpected(kGraphAlreadyBuiltError);
  }
  if (!remote_.is_bound()) {
    return base::unexpected("Context is lost.");
  }
  return base::ok();
}

// As specified in https://www.w3.org/TR/webnn/#mlgraphbuilder-validate-operand.
base::expected<void, String> MLGraphBuilder::ValidateInput(
    const MLOperand* input) {
  CHECK(input);
  if (input->Builder() != this) {
    return base::unexpected("Invalid input: Created from another builder.");
  }
  return base::ok();
}

base::expected<void, String> MLGraphBuilder::ValidateInputs(
    const HeapVector<Member<MLOperand>>& inputs) {
  for (const MLOperand* input_to_validate : inputs) {
    RETURN_IF_ERROR(ValidateInput(input_to_validate));
  }
  return base::ok();
}

void MLGraphBuilder::ReleaseConstantData() {
  base::ranges::for_each(constant_operands_, [](auto& constant_operand) {
    constant_operand->ReleaseBytes();
  });
  constant_operands_.clear();
}

}  // namespace blink
```