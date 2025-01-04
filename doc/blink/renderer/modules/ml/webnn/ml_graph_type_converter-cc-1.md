Response:
The user is asking for the functionalities of the provided C++ code snippet from a Chromium file. The code seems to be responsible for converting WebNN (Web Neural Network API) operators into a format suitable for the underlying implementation (likely Mojo IPC messages).

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The function names (e.g., `CreateDequantizeLinearOperation`, `CreateElementWiseBinaryOperator`) clearly suggest the creation of specific operation types. The parameters often include `MLOperator` and `OperandToIdMap`, hinting at a mapping process from a higher-level representation to a lower-level one. The return type `OperationPtr` which appears to be a smart pointer to a `blink_mojom::Operation` further reinforces this idea of converting to Mojo structures.

2. **Recognize the Pattern:**  Notice the consistent structure in each function:
    * Create a new Mojo object (e.g., `blink_mojom::DequantizeLinear::New()`).
    * Extract input and output operand IDs using helper functions like `GetOperatorInputId` and `GetOperatorOutputId`.
    * Populate the Mojo object's fields with data from the `MLOperator` (e.g., kind, axes, labels, and potentially options).
    * Move the Mojo object into an `OperationPtr` and return it.

3. **Infer Functionality based on Names:** The function names are highly descriptive. One can deduce the purpose of each function based on the name of the WebNN operator it handles: `DequantizeLinear`, `ElementWiseBinary`, `Gather`, `Gemm`, `Gru`, `Lstm`, `Matmul`, `Pad`, `Pool2d`, `Prelu`, `QuantizeLinear`, `Reduce`, `Resample2d`, `Relu`, `Reshape`, `Reverse`, `ScatterElements`, `ScatterND`, `Sigmoid`.

4. **Consider Relationships to Web Technologies:** Since this is part of the Chromium engine and deals with WebNN, it's directly related to JavaScript. WebNN is a JavaScript API. The conversion happening here is what allows the browser to take WebNN instructions from JavaScript and execute them. There's no direct connection to HTML or CSS, which are primarily about structure and presentation.

5. **Reason about Logic and Data Flow:** The code takes an `MLOperator` (likely representing a node in a WebNN graph) and converts it into a Mojo representation. The `OperandToIdMap` is crucial for managing the connections between operands (data) in the graph. The input and output IDs are used to link operations together.

6. **Identify Potential Usage Errors:**  The code uses `CHECK()` macros, which indicate potential runtime errors if certain conditions are not met. For instance, casting `MLOperator` to more specific types like `MLGatherOptions*` and then accessing members suggests that passing the wrong type of `MLOperator` to a particular conversion function would be an error. Also, not providing necessary options (when `hasX()` check fails) or providing incorrect data types could lead to issues.

7. **Trace User Interaction (Debugging Clues):**  A user would interact with this code indirectly through JavaScript. They would use the WebNN API in their JavaScript code. The browser's JavaScript engine would then translate these calls into internal representations that eventually lead to this C++ code. Debugging would involve inspecting the WebNN graph, the operands, and tracing the execution flow from the JavaScript API calls down to these conversion functions.

8. **Focus on the Provided Snippet (Part 2):** The prompt specifically asks for the functionality of *this* part of the file. This section handles the conversion of a specific set of WebNN operators. It doesn't cover the entire file's purpose (which might include the overall graph conversion process).

9. **Synthesize the Summary:** Based on the observations, the core function of this part of the code is to convert individual WebNN operator objects into their corresponding Mojo IPC message representations. This enables communication with other browser processes or potentially hardware acceleration layers to execute the neural network operations defined via the WebNN API in JavaScript.

By following these steps, we can arrive at the detailed and accurate description of the code's functionality, its relation to web technologies, potential errors, and debugging approaches.
这是 `blink/renderer/modules/ml/webnn/ml_graph_type_converter.cc` 文件的第二部分，主要功能是**将 WebNN API 中定义的各种机器学习操作 (MLOperator) 转换为 blink 中用于进程间通信 (IPC) 的 Mojo 接口表示形式 (blink_mojom::Operation)**。

以下是更详细的功能归纳：

**核心功能:**

* **将 MLOperator 转换为 Mojo Operation:**  这段代码包含一系列 `Create...Operation` 函数，每个函数负责将一个特定的 `MLOperator` 子类（例如 `MLConv2dOperator`, `MLAddOperator` 等）转换为对应的 `blink_mojom::Operation` 联合体中的一个特定变体。
* **提取和映射操作数 ID:**  使用 `GetOperatorInputId` 和 `GetOperatorOutputId` 函数从 `MLOperator` 中提取输入和输出操作数的 ID，并使用 `OperandToIdMap` 将这些 WebNN 内部的 ID 映射到 Mojo 中使用的 ID。
* **处理操作的各种选项:**  对于每个操作，代码会检查其对应的选项对象（例如 `MLConv2dOptions`, `MLAddOptions`），并将这些选项的值映射到 Mojo 消息的相应字段中。
* **处理特定操作的复杂逻辑:** 某些操作（例如 `Pool2d`, `Resample2d`, `Gru`, `Lstm`）可能需要更复杂的处理，例如处理不同的布局、计算默认值、插入必要的转置操作等。
* **支持不同的数据类型和参数:** 代码能够处理各种类型的输入数据和参数，并将其正确地转换为 Mojo 消息中的对应类型。
* **添加操作标签:**  代码会将 `MLOperator` 的标签信息传递到 Mojo `Operation` 中，这有助于调试和跟踪。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  WebNN API 是一个 JavaScript API，开发者可以使用它来构建和执行机器学习模型。这段 C++ 代码是 WebNN API 在 Blink 渲染引擎中的底层实现的一部分。当 JavaScript 代码调用 WebNN API 创建一个操作时，最终会调用到这里相应的 `Create...Operation` 函数来创建 Mojo 表示。
    * **举例:**  假设 JavaScript 代码中使用了 `navigator.ml.createModel().add(...)` 添加了一个加法操作。Blink 引擎会创建一个 `MLAddOperator` 对象，然后调用 `CreateElementWiseBinaryOperator` 函数将其转换为 `blink_mojom::Operation::NewElementWiseBinary(...)`。
* **HTML/CSS:**  这段代码本身与 HTML 和 CSS 没有直接关系。HTML 用于定义网页的结构，CSS 用于定义网页的样式。然而，WebNN API 可以在 JavaScript 中使用，而 JavaScript 代码通常嵌入在 HTML 文件中，或者由 HTML 文件加载。因此，最终用户通过与网页的交互（可能触发 JavaScript 代码执行 WebNN 模型）可以间接地触发这段 C++ 代码的执行。

**逻辑推理和假设输入输出:**

以下是一些函数的逻辑推理和假设输入输出示例：

* **`CreateDequantizeLinearOperation`:**
    * **假设输入:** 一个指向 `MLDequantizeLinearOperator` 的指针 `dequantize_linear`，以及一个 `OperandToIdMap` 对象。
    * **逻辑推理:** 函数会从 `dequantize_linear` 中获取输入、缩放因子和零点的操作数 ID，以及操作的标签。然后创建一个 `blink_mojom::DequantizeLinear` 对象，并将这些信息填充进去。
    * **假设输出:** 一个指向 `blink_mojom::Operation` 的智能指针，其内部包含一个 `blink_mojom::DequantizeLinear` 对象，该对象正确地描述了反量化线性操作。

* **`CreateElementWiseBinaryOperator`:**
    * **假设输入:** 一个 `OperandToIdMap` 对象，一个指向 `MLOperator` 的指针 `binary` (实际类型可能是 `MLAddOperator`, `MLMulOperator` 等)，以及一个 `blink_mojom::ElementWiseBinary::Kind` 枚举值（例如 `kAdd`, `kMul`）。
    * **逻辑推理:** 函数会从 `binary` 中获取左右操作数的 ID 和输出操作数的 ID，以及操作的标签。然后创建一个 `blink_mojom::ElementWiseBinary` 对象，并将操作类型、操作数 ID 和标签填充进去。
    * **假设输出:** 一个指向 `blink_mojom::Operation` 的智能指针，其内部包含一个 `blink_mojom::ElementWiseBinary` 对象，该对象正确地描述了元素级二元操作。

**用户或编程常见的使用错误:**

* **传递错误类型的 MLOperator:** 如果将一个 `MLConv2dOperator` 传递给 `CreateElementWiseBinaryOperator` 函数，`GetOperatorInputId` 和 `GetOperatorOutputId` 可能会返回错误的 ID，或者代码会因为类型转换失败而崩溃。
* **操作数 ID 不存在于 OperandToIdMap 中:**  如果在创建操作时，某个输入或输出操作数的 ID 没有被正确添加到 `OperandToIdMap` 中，`GetOperatorInputId` 或 `GetOperatorOutputId` 可能会抛出异常或返回无效的 ID。
* **选项对象为空:** 对于某些需要选项的操作，如果 `MLOperator` 的选项对象为空（例如 `binary->Options()` 返回 nullptr），代码中的 `CHECK(options)` 会触发断言失败。
* **选项值不合法:** 尽管代码中没有显式的错误处理，但如果选项值超出预期范围（例如卷积的步幅为负数），可能会导致后续的计算错误或崩溃。

**用户操作如何到达这里 (调试线索):**

1. **用户在网页中编写 JavaScript 代码，使用 WebNN API 创建模型并添加操作。** 例如：
   ```javascript
   navigator.ml.createModelBuilder()
       .input('input', { type: 'float32', dimensions: [1, 28, 28, 1] })
       .conv2d('input', ...) // 添加一个卷积操作
       .output('output')
       .build()
       .then(model => ...);
   ```
2. **当 JavaScript 代码执行到 `conv2d` 或其他添加操作的 API 调用时，Blink 渲染引擎中的 WebNN 相关模块会接收到这些请求。**
3. **WebNN 模块会创建相应的 `MLOperator` 对象（例如 `MLConv2dOperator`）来表示这些操作。**
4. **在构建 WebNN 图的过程中，`ml_graph_type_converter.cc` 文件中的相关函数会被调用，将这些 `MLOperator` 对象转换为 Mojo 消息。**  例如，对于 `conv2d` 操作，`CreateConv2dOperation` 函数会被调用。
5. **转换后的 Mojo 消息会被发送到实现了 WebNN 执行的 GPU 进程或其他进程。**

**作为调试线索，如果开发者发现 WebNN 模型执行出现问题，可以：**

* **检查 JavaScript 代码中 WebNN API 的使用是否正确，包括操作的参数和输入输出的连接。**
* **在 Blink 渲染引擎的 WebNN 模块中设置断点，查看 `MLOperator` 对象的创建和属性。**
* **在 `ml_graph_type_converter.cc` 中设置断点，查看 `MLOperator` 对象是如何被转换为 Mojo 消息的，检查转换过程中数据是否正确。**
* **检查发送到 GPU 进程或其他进程的 Mojo 消息的内容，确认转换后的操作表示是否符合预期。**

**归纳一下它的功能 (针对提供的代码片段):**

这段代码片段的核心功能是 **将一部分 WebNN API 中定义的机器学习操作符 (`MLOperator`) 转换为用于进程间通信的 Mojo 消息 (`blink_mojom::Operation`)**。它涵盖了反量化线性、元素级二元和一元运算、各种 Gather 操作、Gelu、Gemm、Gru、GruCell、HardSwish、各种归一化操作、Lstm、LstmCell、Matmul、Pad、Pool2d、Prelu、量化线性、Reduce、Resample2d、Relu、Reshape、Reverse 和各种 Scatter 操作的转换逻辑。 这使得 Blink 渲染引擎可以将高层的 WebNN 操作描述传递给下层实现进行执行。

Prompt: 
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_type_converter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
nputId(dequantize_linear, operand_to_id_map, 2);
  dequantize_linear_mojo->output_operand_id =
      GetOperatorOutputId(dequantize_linear, operand_to_id_map);
  dequantize_linear_mojo->label = dequantize_linear->Options()->label();
  return blink_mojom::Operation::NewDequantizeLinear(
      std::move(dequantize_linear_mojo));
}

OperationPtr CreateElementWiseBinaryOperator(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* binary,
    const blink_mojom::ElementWiseBinary::Kind& kind) {
  const uint64_t lhs_operand_id =
      GetOperatorInputId(binary, operand_to_id_map, 0);
  const uint64_t rhs_operand_id =
      GetOperatorInputId(binary, operand_to_id_map, 1);
  const uint64_t output_operand_id =
      GetOperatorOutputId(binary, operand_to_id_map);

  auto operator_mojo = ElementWiseBinary::New();
  operator_mojo->kind = kind;
  operator_mojo->lhs_operand_id = lhs_operand_id;
  operator_mojo->rhs_operand_id = rhs_operand_id;
  operator_mojo->output_operand_id = output_operand_id;
  operator_mojo->label = binary->Options()->label();
  return webnn::mojom::blink::Operation::NewElementWiseBinary(
      std::move(operator_mojo));
}

OperationPtr CreateElementWiseUnaryOperator(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* unary,
    const blink_mojom::ElementWiseUnary::Kind& kind) {
  auto operator_mojo = ElementWiseUnary::New();
  operator_mojo->input_operand_id =
      GetOperatorInputId(unary, operand_to_id_map);
  operator_mojo->output_operand_id =
      GetOperatorOutputId(unary, operand_to_id_map);
  operator_mojo->kind = kind;
  operator_mojo->label = unary->Options()->label();
  return webnn::mojom::blink::Operation::NewElementWiseUnary(
      std::move(operator_mojo));
}

OperationPtr CreateGatherOperation(const OperandToIdMap& operand_to_id_map,
                                   const MLOperator* gather) {
  auto gather_mojo = webnn::mojom::blink::Gather::New();
  gather_mojo->input_operand_id =
      GetOperatorInputId(gather, operand_to_id_map, 0);
  gather_mojo->indices_operand_id =
      GetOperatorInputId(gather, operand_to_id_map, 1);
  gather_mojo->output_operand_id =
      GetOperatorOutputId(gather, operand_to_id_map);

  const auto* options = static_cast<const MLGatherOptions*>(gather->Options());
  CHECK(options);
  gather_mojo->axis = options->axis();
  gather_mojo->label = options->label();
  return webnn::mojom::blink::Operation::NewGather(std::move(gather_mojo));
}

OperationPtr CreateGatherElementsOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* gather_elements) {
  auto gather_elements_mojo = webnn::mojom::blink::GatherElements::New();
  gather_elements_mojo->input_operand_id =
      GetOperatorInputId(gather_elements, operand_to_id_map, 0);
  gather_elements_mojo->indices_operand_id =
      GetOperatorInputId(gather_elements, operand_to_id_map, 1);
  gather_elements_mojo->output_operand_id =
      GetOperatorOutputId(gather_elements, operand_to_id_map);

  const auto* options =
      static_cast<const MLGatherOptions*>(gather_elements->Options());
  CHECK(options);
  gather_elements_mojo->axis = options->axis();
  gather_elements_mojo->label = options->label();
  return webnn::mojom::blink::Operation::NewGatherElements(
      std::move(gather_elements_mojo));
}

OperationPtr CreateGatherNDOperation(const OperandToIdMap& operand_to_id_map,
                                     const MLOperator* gather_nd) {
  auto gather_nd_mojo = webnn::mojom::blink::GatherND::New();
  gather_nd_mojo->input_operand_id =
      GetOperatorInputId(gather_nd, operand_to_id_map, 0);
  gather_nd_mojo->indices_operand_id =
      GetOperatorInputId(gather_nd, operand_to_id_map, 1);
  gather_nd_mojo->output_operand_id =
      GetOperatorOutputId(gather_nd, operand_to_id_map);
  gather_nd_mojo->label = gather_nd->Options()->label();

  return webnn::mojom::blink::Operation::NewGatherNd(std::move(gather_nd_mojo));
}

OperationPtr CreateGeluOperation(const OperandToIdMap& operand_to_id_map,
                                 const MLOperator* gelu) {
  auto gelu_mojo = blink_mojom::Gelu::New(
      GetOperatorInputId(gelu, operand_to_id_map),
      GetOperatorOutputId(gelu, operand_to_id_map), gelu->Options()->label());
  return blink_mojom::Operation::NewGelu(std::move(gelu_mojo));
}

OperationPtr CreateGemmOperation(const OperandToIdMap& operand_to_id_map,
                                 const MLOperator* gemm) {
  auto gemm_mojo = webnn::mojom::blink::Gemm::New();
  gemm_mojo->a_operand_id = GetOperatorInputId(gemm, operand_to_id_map, 0);
  gemm_mojo->b_operand_id = GetOperatorInputId(gemm, operand_to_id_map, 1);
  gemm_mojo->output_operand_id = GetOperatorOutputId(gemm, operand_to_id_map);

  const auto* options = static_cast<const MLGemmOptions*>(gemm->Options());
  CHECK(options);
  if (options->hasC()) {
    gemm_mojo->c_operand_id = operand_to_id_map.at(options->c());
  }
  gemm_mojo->alpha = options->alpha();
  gemm_mojo->beta = options->beta();
  gemm_mojo->a_transpose = options->aTranspose();
  gemm_mojo->b_transpose = options->bTranspose();
  gemm_mojo->label = options->label();

  return webnn::mojom::blink::Operation::NewGemm(std::move(gemm_mojo));
}

OperationPtr CreateGruOperation(const OperandToIdMap& operand_to_id_map,
                                const MLOperator* gru) {
  auto gru_mojo = blink_mojom::Gru::New();
  gru_mojo->input_operand_id = GetOperatorInputId(gru, operand_to_id_map, 0);
  gru_mojo->weight_operand_id = GetOperatorInputId(gru, operand_to_id_map, 1);
  gru_mojo->recurrent_weight_operand_id =
      GetOperatorInputId(gru, operand_to_id_map, 2);

  const auto* gru_operator = static_cast<const MLGruOperator*>(gru);
  gru_mojo->hidden_size = gru_operator->hidden_size();
  gru_mojo->steps = gru_operator->steps();

  const auto* options = static_cast<const MLGruOptions*>(gru->Options());
  CHECK(options);

  if (options->hasBias()) {
    gru_mojo->bias_operand_id = operand_to_id_map.at(options->bias());
  }
  if (options->hasRecurrentBias()) {
    gru_mojo->recurrent_bias_operand_id =
        operand_to_id_map.at(options->recurrentBias());
  }
  if (options->hasInitialHiddenState()) {
    gru_mojo->initial_hidden_state_operand_id =
        operand_to_id_map.at(options->initialHiddenState());
  }
  gru_mojo->reset_after = options->resetAfter();
  gru_mojo->return_sequence = options->returnSequence();
  gru_mojo->direction =
      mojo::BlinkRecurrentNetworkDirectionToMojo(options->direction().AsEnum());
  gru_mojo->layout =
      mojo::BlinkGruWeightLayoutToMojo(options->layout().AsEnum());

  const auto& activations = options->activations();
  CHECK_EQ(activations.size(), 2u);
  gru_mojo->activations.reserve(activations.size());
  for (const auto& activation : activations) {
    gru_mojo->activations.push_back(
        mojo::BlinkRecurrentNetworkActivationToMojo(activation));
  }

  const wtf_size_t output_count = gru->Outputs().size();
  gru_mojo->output_operand_ids.reserve(output_count);
  for (wtf_size_t i = 0; i < output_count; ++i) {
    gru_mojo->output_operand_ids.push_back(
        GetOperatorOutputId(gru, operand_to_id_map, i));
  }

  gru_mojo->label = options->label();
  return blink_mojom::Operation::NewGru(std::move(gru_mojo));
}

base::expected<OperationPtr, String> CreateGruCellOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* gru_cell) {
  uint64_t input_operand_id =
      GetOperatorInputId(gru_cell, operand_to_id_map, 0);
  uint64_t weight_operand_id =
      GetOperatorInputId(gru_cell, operand_to_id_map, 1);
  uint64_t recurrent_weight_operand_id =
      GetOperatorInputId(gru_cell, operand_to_id_map, 2);
  uint64_t hidden_state_operand_id =
      GetOperatorInputId(gru_cell, operand_to_id_map, 3);

  const auto* gru_cell_operator =
      static_cast<const MLGruCellOperator*>(gru_cell);
  uint32_t hidden_size = gru_cell_operator->hidden_size();

  const auto* options =
      static_cast<const MLGruCellOptions*>(gru_cell->Options());
  CHECK(options);

  std::optional<uint64_t> bias_operand_id;
  if (options->hasBias()) {
    bias_operand_id = operand_to_id_map.at(options->bias());
  }
  std::optional<uint64_t> recurrent_bias_operand_id;
  if (options->hasRecurrentBias()) {
    recurrent_bias_operand_id = operand_to_id_map.at(options->recurrentBias());
  }

  const Vector<V8MLRecurrentNetworkActivation>& ml_activations =
      options->activations();
  CHECK_EQ(ml_activations.size(), 2u);
  Vector<webnn::mojom::blink::RecurrentNetworkActivation> activations;
  activations.reserve(ml_activations.size());
  for (const auto& activation : ml_activations) {
    activations.push_back(
        mojo::BlinkRecurrentNetworkActivationToMojo(activation));
  }

  uint64_t output_operand_id = GetOperatorOutputId(gru_cell, operand_to_id_map);

  auto gru_cell_mojo = blink_mojom::GruCell::New(
      input_operand_id, weight_operand_id, recurrent_weight_operand_id,
      hidden_state_operand_id, hidden_size, output_operand_id, bias_operand_id,
      recurrent_bias_operand_id, options->resetAfter(),
      mojo::BlinkGruWeightLayoutToMojo(options->layout().AsEnum()),
      std::move(activations), options->label());

  return blink_mojom::Operation::NewGruCell(std::move(gru_cell_mojo));
}

OperationPtr CreateHardSwishOperation(const OperandToIdMap& operand_to_id_map,
                                      const MLOperator* hard_swish) {
  auto hard_swish_mojo = blink_mojom::HardSwish::New();
  hard_swish_mojo->input_operand_id =
      GetOperatorInputId(hard_swish, operand_to_id_map);
  hard_swish_mojo->output_operand_id =
      GetOperatorOutputId(hard_swish, operand_to_id_map);
  hard_swish_mojo->label = hard_swish->Options()->label();
  return blink_mojom::Operation::NewHardSwish(std::move(hard_swish_mojo));
}

OperationPtr CreateLayerNormalizationOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* layer_normalization) {
  auto layer_normalization_mojo =
      webnn::mojom::blink::LayerNormalization::New();
  layer_normalization_mojo->input_operand_id =
      GetOperatorInputId(layer_normalization, operand_to_id_map);
  layer_normalization_mojo->output_operand_id =
      GetOperatorOutputId(layer_normalization, operand_to_id_map);

  const auto* options = static_cast<const MLLayerNormalizationOptions*>(
      layer_normalization->Options());
  CHECK(options);

  if (options->hasScale()) {
    layer_normalization_mojo->scale_operand_id =
        operand_to_id_map.at(options->scale());
  }
  if (options->hasBias()) {
    layer_normalization_mojo->bias_operand_id =
        operand_to_id_map.at(options->bias());
  }

  layer_normalization_mojo->axes =
      options->getAxesOr(CreateLayerNormalizationDefaultAxes(
          layer_normalization->Inputs()[0]->Rank()));

  layer_normalization_mojo->epsilon = options->epsilon();
  layer_normalization_mojo->label = options->label();
  return webnn::mojom::blink::Operation::NewLayerNormalization(
      std::move(layer_normalization_mojo));
}

OperationPtr CreateInstanceNormalizationOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* instance_normalization) {
  auto instance_normalization_mojo =
      webnn::mojom::blink::InstanceNormalization::New();
  instance_normalization_mojo->input_operand_id =
      GetOperatorInputId(instance_normalization, operand_to_id_map, 0);
  instance_normalization_mojo->output_operand_id =
      GetOperatorOutputId(instance_normalization, operand_to_id_map);

  const auto* options = static_cast<const MLInstanceNormalizationOptions*>(
      instance_normalization->Options());
  CHECK(options);
  if (options->hasScale()) {
    instance_normalization_mojo->scale_operand_id =
        operand_to_id_map.at(options->scale());
  }
  if (options->hasBias()) {
    instance_normalization_mojo->bias_operand_id =
        operand_to_id_map.at(options->bias());
  }
  instance_normalization_mojo->layout =
      BlinkInputOperandLayoutToMojo(options->layout().AsEnum());
  instance_normalization_mojo->epsilon = options->epsilon();
  instance_normalization_mojo->label = options->label();

  return webnn::mojom::blink::Operation::NewInstanceNormalization(
      std::move(instance_normalization_mojo));
}

OperationPtr CreateLstmOperation(const OperandToIdMap& operand_to_id_map,
                                 const MLOperator* lstm) {
  auto lstm_mojo = blink_mojom::Lstm::New();
  lstm_mojo->input_operand_id = GetOperatorInputId(lstm, operand_to_id_map, 0);
  lstm_mojo->weight_operand_id = GetOperatorInputId(lstm, operand_to_id_map, 1);
  lstm_mojo->recurrent_weight_operand_id =
      GetOperatorInputId(lstm, operand_to_id_map, 2);

  const auto* lstm_operator = static_cast<const MLLstmOperator*>(lstm);
  lstm_mojo->hidden_size = lstm_operator->hidden_size();
  lstm_mojo->steps = lstm_operator->steps();

  const auto* options = static_cast<const MLLstmOptions*>(lstm->Options());
  CHECK(options);

  if (options->hasBias()) {
    lstm_mojo->bias_operand_id = operand_to_id_map.at(options->bias());
  }
  if (options->hasRecurrentBias()) {
    lstm_mojo->recurrent_bias_operand_id =
        operand_to_id_map.at(options->recurrentBias());
  }
  if (options->hasPeepholeWeight()) {
    lstm_mojo->peephole_weight_operand_id =
        operand_to_id_map.at(options->peepholeWeight());
  }
  if (options->hasInitialHiddenState()) {
    lstm_mojo->initial_hidden_state_operand_id =
        operand_to_id_map.at(options->initialHiddenState());
  }
  if (options->hasInitialCellState()) {
    lstm_mojo->initial_cell_state_operand_id =
        operand_to_id_map.at(options->initialCellState());
  }
  lstm_mojo->return_sequence = options->returnSequence();
  lstm_mojo->direction =
      mojo::BlinkRecurrentNetworkDirectionToMojo(options->direction().AsEnum());
  lstm_mojo->layout =
      mojo::BlinkLstmWeightLayoutToMojo(options->layout().AsEnum());

  const auto& activations = options->activations();
  lstm_mojo->activations.reserve(activations.size());
  for (const auto& activation : activations) {
    lstm_mojo->activations.push_back(
        mojo::BlinkRecurrentNetworkActivationToMojo(activation));
  }

  const wtf_size_t output_count = lstm->Outputs().size();
  lstm_mojo->output_operand_ids.reserve(output_count);
  for (wtf_size_t i = 0; i < output_count; ++i) {
    lstm_mojo->output_operand_ids.push_back(
        GetOperatorOutputId(lstm, operand_to_id_map, i));
  }
  lstm_mojo->label = options->label();
  return blink_mojom::Operation::NewLstm(std::move(lstm_mojo));
}

base::expected<OperationPtr, String> CreateLstmCellOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* lstm_cell) {
  uint64_t input_operand_id =
      GetOperatorInputId(lstm_cell, operand_to_id_map, 0);
  uint64_t weight_operand_id =
      GetOperatorInputId(lstm_cell, operand_to_id_map, 1);
  uint64_t recurrent_weight_operand_id =
      GetOperatorInputId(lstm_cell, operand_to_id_map, 2);
  uint64_t hidden_state_operand_id =
      GetOperatorInputId(lstm_cell, operand_to_id_map, 3);
  uint64_t cell_state_operand_id =
      GetOperatorInputId(lstm_cell, operand_to_id_map, 4);

  const auto* options =
      static_cast<const MLLstmCellOptions*>(lstm_cell->Options());
  CHECK(options);

  std::optional<uint64_t> bias_operand_id;
  if (options->hasBias()) {
    bias_operand_id = operand_to_id_map.at(options->bias());
  }
  std::optional<uint64_t> recurrent_bias_operand_id;
  if (options->hasRecurrentBias()) {
    recurrent_bias_operand_id = operand_to_id_map.at(options->recurrentBias());
  }
  std::optional<uint64_t> peephole_weight_operand_id;
  if (options->hasPeepholeWeight()) {
    peephole_weight_operand_id =
        operand_to_id_map.at(options->peepholeWeight());
  }

  const Vector<V8MLRecurrentNetworkActivation>& ml_activations =
      options->activations();
  CHECK_EQ(ml_activations.size(), 3u);
  Vector<webnn::mojom::blink::RecurrentNetworkActivation> activations;
  activations.reserve(ml_activations.size());
  for (const auto& activation : ml_activations) {
    activations.push_back(
        mojo::BlinkRecurrentNetworkActivationToMojo(activation));
  }

  Vector<uint64_t> output_operand_ids;
  CHECK_EQ(lstm_cell->Outputs().size(), 2u);
  output_operand_ids.reserve(lstm_cell->Outputs().size());
  output_operand_ids.push_back(
      GetOperatorOutputId(lstm_cell, operand_to_id_map, 0));
  output_operand_ids.push_back(
      GetOperatorOutputId(lstm_cell, operand_to_id_map, 1));

  const auto* lstm_cell_operator =
      static_cast<const MLLstmCellOperator*>(lstm_cell);

  auto lstm_cell_mojo = blink_mojom::LstmCell::New(
      input_operand_id, weight_operand_id, recurrent_weight_operand_id,
      hidden_state_operand_id, cell_state_operand_id,
      std::move(output_operand_ids), lstm_cell_operator->hidden_size(),
      bias_operand_id, recurrent_bias_operand_id, peephole_weight_operand_id,
      mojo::BlinkLstmWeightLayoutToMojo(options->layout().AsEnum()),
      std::move(activations), options->label());

  return blink_mojom::Operation::NewLstmCell(std::move(lstm_cell_mojo));
}

OperationPtr CreateMatmulOperation(const OperandToIdMap& operand_to_id_map,
                                   const MLOperator* matmul) {
  auto matmul_mojo = blink_mojom::Matmul::New();
  matmul_mojo->a_operand_id = GetOperatorInputId(matmul, operand_to_id_map, 0);
  matmul_mojo->b_operand_id = GetOperatorInputId(matmul, operand_to_id_map, 1);
  matmul_mojo->output_operand_id =
      GetOperatorOutputId(matmul, operand_to_id_map);
  matmul_mojo->label = matmul->Options()->label();
  return blink_mojom::Operation::NewMatmul(std::move(matmul_mojo));
}

OperationPtr CreatePadOperation(const OperandToIdMap& operand_to_id_map,
                                const MLOperator* op) {
  const auto* pad = static_cast<const blink::MLPadOperator*>(op);
  CHECK(pad);
  auto pad_mojo = blink_mojom::Pad::New();
  pad_mojo->input_operand_id = GetOperatorInputId(pad, operand_to_id_map);
  pad_mojo->output_operand_id = GetOperatorOutputId(pad, operand_to_id_map);
  pad_mojo->beginning_padding = pad->BeginningPadding();
  pad_mojo->ending_padding = pad->EndingPadding();

  const auto* options = static_cast<const blink::MLPadOptions*>(pad->Options());
  CHECK(options);
  switch (options->mode().AsEnum()) {
    case blink::V8MLPaddingMode::Enum::kConstant: {
      auto constant_padding = blink_mojom::ConstantPadding::New();
      constant_padding->value = options->value();
      pad_mojo->mode =
          blink_mojom::PaddingMode::NewConstant(std::move(constant_padding));
      break;
    }
    case blink::V8MLPaddingMode::Enum::kEdge:
      pad_mojo->mode =
          blink_mojom::PaddingMode::NewEdge(blink_mojom::EdgePadding::New());
      break;
    case blink::V8MLPaddingMode::Enum::kReflection:
      pad_mojo->mode = blink_mojom::PaddingMode::NewReflection(
          blink_mojom::ReflectionPadding::New());
      break;
    case blink::V8MLPaddingMode::Enum::kSymmetric:
      pad_mojo->mode = blink_mojom::PaddingMode::NewSymmetric(
          blink_mojom::SymmetricPadding::New());
      break;
  }
  pad_mojo->label = options->label();

  return blink_mojom::Operation::NewPad(std::move(pad_mojo));
}

void SerializePool2dOperation(
    const OperandToIdMap& operand_to_id_map,
    const webnn::ContextProperties& context_properties,
    const MLOperator* pool2d,
    const blink_mojom::Pool2d::Kind& kind,
    blink_mojom::GraphInfo* graph_info) {
  auto pool2d_mojo = blink_mojom::Pool2d::New();
  pool2d_mojo->kind = kind;
  const MLOperand* input_operand = pool2d->Inputs()[0];
  const MLOperand* output_operand = pool2d->Outputs()[0];
  uint64_t output_operand_id = operand_to_id_map.at(output_operand);
  const auto* options =
      static_cast<const blink::MLPool2dOptions*>(pool2d->Options());
  CHECK(options);
  const std::optional<base::span<const uint32_t>> input_permutation =
      GetInputOperandPermutation(options->layout().AsEnum(),
                                 context_properties);
  if (input_permutation.has_value()) {
    pool2d_mojo->input_operand_id =
        InsertInputTranspose(operand_to_id_map, input_operand,
                             *input_permutation, graph_info, options->label());

    output_operand_id = InsertTemporaryOperand(
        operand_to_id_map,
        *webnn::OperandDescriptor::Create(
            output_operand->DataType(),
            PermuteShape(output_operand->Shape(), *input_permutation)),
        graph_info);
  } else {
    pool2d_mojo->input_operand_id = operand_to_id_map.at(input_operand);
  }
  pool2d_mojo->output_operand_id = output_operand_id;

  // If strides is not present, the values are assumed to be [1,1].
  auto strides = options->getStridesOr({1, 1});
  CHECK_EQ(strides.size(), 2u);
  pool2d_mojo->strides = Size2d::New(strides[0], strides[1]);

  // If dilations is not present, the values are assumed to be [1, 1].
  auto dilations = options->getDilationsOr({1, 1});
  CHECK_EQ(dilations.size(), 2u);
  pool2d_mojo->dilations = Size2d::New(dilations[0], dilations[1]);

  // Get height and width of input for calculating padding.
  auto input_size = mojo::GetInputOperandSize2d(pool2d->Inputs()[0].Get(),
                                                options->layout().AsEnum());
  // The dimensions of the sliding window are the height and width of input
  // operand if they are not supplied by user.
  uint32_t window_height = input_size.height;
  uint32_t window_width = input_size.width;
  if (options->hasWindowDimensions()) {
    auto& window_dimensions = options->windowDimensions();
    CHECK_EQ(window_dimensions.size(), 2u);
    window_height = window_dimensions[0];
    window_width = window_dimensions[1];
  }
  pool2d_mojo->window_dimensions = Size2d::New(window_height, window_width);

  // Set the padding from WebNN explicit padding that is in
  // [beginning_height, ending_height, beginning_width, ending_width],
  // default to 0.
  auto ml_padding = options->getPaddingOr({0, 0, 0, 0});
  CHECK_EQ(ml_padding.size(), 4u);
  pool2d_mojo->padding = blink_mojom::Padding2d::New(
      /*beginning padding*/ Size2d::New(ml_padding[0], ml_padding[2]),
      /*ending padding*/ Size2d::New(ml_padding[1], ml_padding[3]));
  pool2d_mojo->label = options->label();

  graph_info->operations.push_back(
      blink_mojom::Operation::NewPool2d(std::move(pool2d_mojo)));

  const std::optional<base::span<const uint32_t>> output_permutation =
      GetOutputOperandPermutation(options->layout().AsEnum(),
                                  context_properties);
  if (output_permutation) {
    auto output_transpose = blink_mojom::Transpose::New();
    output_transpose->input_operand_id = output_operand_id;
    output_transpose->output_operand_id = operand_to_id_map.at(output_operand);
    output_transpose->permutation = Vector<uint32_t>(*output_permutation);
    output_transpose->label = options->label();

    graph_info->operations.push_back(
        blink_mojom::Operation::NewTranspose(std::move(output_transpose)));
  }
}

OperationPtr CreatePreluOperation(const OperandToIdMap& operand_to_id_map,
                                  const MLOperator* prelu) {
  auto prelu_mojo = blink_mojom::Prelu::New();
  prelu_mojo->input_operand_id =
      GetOperatorInputId(prelu, operand_to_id_map, 0);
  prelu_mojo->slope_operand_id =
      GetOperatorInputId(prelu, operand_to_id_map, 1);
  prelu_mojo->output_operand_id = GetOperatorOutputId(prelu, operand_to_id_map);
  prelu_mojo->label = prelu->Options()->label();
  return blink_mojom::Operation::NewPrelu(std::move(prelu_mojo));
}

OperationPtr CreateQuantizeLinearOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* quantize_linear) {
  auto quantize_linear_mojo = blink_mojom::QuantizeLinear::New();
  quantize_linear_mojo->input_operand_id =
      GetOperatorInputId(quantize_linear, operand_to_id_map, 0);
  quantize_linear_mojo->scale_operand_id =
      GetOperatorInputId(quantize_linear, operand_to_id_map, 1);
  quantize_linear_mojo->zero_point_operand_id =
      GetOperatorInputId(quantize_linear, operand_to_id_map, 2);
  quantize_linear_mojo->output_operand_id =
      GetOperatorOutputId(quantize_linear, operand_to_id_map);
  quantize_linear_mojo->label = quantize_linear->Options()->label();
  return blink_mojom::Operation::NewQuantizeLinear(
      std::move(quantize_linear_mojo));
}

OperationPtr CreateReduceOperator(const OperandToIdMap& operand_to_id_map,
                                  const MLOperator* reduce,
                                  const blink_mojom::Reduce::Kind kind) {
  auto reduce_mojo = blink_mojom::Reduce::New();
  reduce_mojo->kind = kind;
  reduce_mojo->input_operand_id = GetOperatorInputId(reduce, operand_to_id_map);
  reduce_mojo->output_operand_id =
      GetOperatorOutputId(reduce, operand_to_id_map);

  const auto* options =
      static_cast<const blink::MLReduceOptions*>(reduce->Options());
  CHECK(options);
  const wtf_size_t input_rank = reduce->Inputs()[0]->Rank();
  const auto axes = options->getAxesOr(CreateAllAxes(input_rank));
  CHECK_LE(axes.size(), input_rank);
  reduce_mojo->axes = axes;
  reduce_mojo->keep_dimensions = options->keepDimensions();
  reduce_mojo->label = options->label();

  return blink_mojom::Operation::NewReduce(std::move(reduce_mojo));
}

void SerializeResample2dOperation(
    const OperandToIdMap& operand_to_id_map,
    const webnn::ContextProperties& context_properties,
    const MLOperator* resample2d,
    blink_mojom::GraphInfo* graph_info) {
  auto resample2d_mojo = blink_mojom::Resample2d::New();

  const auto* options =
      static_cast<const blink::MLResample2dOptions*>(resample2d->Options());
  CHECK(options);
  switch (options->mode().AsEnum()) {
    case blink::V8MLInterpolationMode::Enum::kNearestNeighbor:
      resample2d_mojo->mode =
          blink_mojom::Resample2d::InterpolationMode::kNearestNeighbor;
      break;
    case blink::V8MLInterpolationMode::Enum::kLinear:
      resample2d_mojo->mode =
          blink_mojom::Resample2d::InterpolationMode::kLinear;
      break;
  }

  // If axes are not present, the values are assumed to be channels first [2,
  // 3].
  auto axes = options->getAxesOr(
      {kResample2dChannelFirstAxes[0], kResample2dChannelFirstAxes[1]});
  CHECK_EQ(axes.size(), 2u);

  // When the target sizes are specified, the scales argument is ignored.
  if (!options->hasSizes()) {
    // If scales are not present, the values are assumed to be [1.0, 1.0].
    auto scales = options->getScalesOr({1.0, 1.0});
    CHECK_EQ(scales.size(), 2u);
    // If axes are not sorted, and backends are expecting sorted axes, sort the
    // corresponding scales too.
    if (context_properties.resample_2d_axes != webnn::Resample2DAxes::kAny &&
        axes[0] > axes[1]) {
      std::swap(scales[0], scales[1]);
    }
    resample2d_mojo->scales = scales;
  }


  const MLOperand* input_operand = resample2d->Inputs()[0];
  const MLOperand* output_operand = resample2d->Outputs()[0];
  uint64_t input_operand_id = operand_to_id_map.at(input_operand);
  uint64_t output_operand_id = operand_to_id_map.at(output_operand);

  base::ranges::sort(axes);
  const std::optional<std::vector<uint32_t>> input_permutation =
      GetResample2DPermutation(axes, context_properties);
  if (input_permutation.has_value()) {
    switch (context_properties.resample_2d_axes) {
      case webnn::Resample2DAxes::kChannelsFirst:
        axes = {kResample2dChannelFirstAxes[0], kResample2dChannelFirstAxes[1]};
        break;
      case webnn::Resample2DAxes::kChannelsLast:
        axes = {kResample2dChannelLastAxes[0], kResample2dChannelLastAxes[1]};
        break;
      case webnn::Resample2DAxes::kAny:
        NOTREACHED();
    }

    input_operand_id =
        InsertInputTranspose(operand_to_id_map, input_operand,
                             *input_permutation, graph_info, options->label());

    output_operand_id = InsertTemporaryOperand(
        operand_to_id_map,
        *webnn::OperandDescriptor::Create(
            output_operand->DataType(),
            PermuteShape(output_operand->Shape(), *input_permutation)),
        graph_info);
  }

  resample2d_mojo->input_operand_id = input_operand_id;
  resample2d_mojo->output_operand_id = output_operand_id;

  resample2d_mojo->axes = {axes[0], axes[1]};
  resample2d_mojo->label = options->label();

  graph_info->operations.push_back(
      blink_mojom::Operation::NewResample2d(std::move(resample2d_mojo)));

  if (input_permutation) {
    const std::optional<std::vector<uint32_t>> output_permutation =
        GetInversePermutation(*input_permutation);
    if (output_permutation) {
      auto output_transpose = blink_mojom::Transpose::New();
      output_transpose->input_operand_id = output_operand_id;
      output_transpose->output_operand_id =
          operand_to_id_map.at(output_operand);
      output_transpose->permutation = Vector<uint32_t>(*output_permutation);
      output_transpose->label = options->label();

      graph_info->operations.push_back(
          blink_mojom::Operation::NewTranspose(std::move(output_transpose)));
    }
  }
}

OperationPtr CreateReluOperation(const OperandToIdMap& operand_to_id_map,
                                 const MLOperator* relu) {
  auto relu_mojo = blink_mojom::Relu::New();
  relu_mojo->input_operand_id = GetOperatorInputId(relu, operand_to_id_map);
  relu_mojo->output_operand_id = GetOperatorOutputId(relu, operand_to_id_map);
  relu_mojo->label = relu->Options()->label();
  return blink_mojom::Operation::NewRelu(std::move(relu_mojo));
}

OperationPtr CreateReshapeOperation(const OperandToIdMap& operand_to_id_map,
                                    const MLOperator* reshape) {
  auto reshape_mojo = blink_mojom::Reshape::New();
  reshape_mojo->input_operand_id =
      GetOperatorInputId(reshape, operand_to_id_map);
  reshape_mojo->output_operand_id =
      GetOperatorOutputId(reshape, operand_to_id_map);
  reshape_mojo->label = reshape->Options()->label();
  return blink_mojom::Operation::NewReshape(std::move(reshape_mojo));
}

OperationPtr CreateReverseOperation(const OperandToIdMap& operand_to_id_map,
                                    const MLOperator* reverse) {
  auto reverse_mojo = blink_mojom::Reverse::New(
      GetOperatorInputId(reverse, operand_to_id_map),
      GetOperatorOutputId(reverse, operand_to_id_map),
      static_cast<const MLReverseOperator*>(reverse)->Axes(),
      reverse->Options()->label());
  return blink_mojom::Operation::NewReverse(std::move(reverse_mojo));
}

OperationPtr CreateScatterElementsOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* scatter_elements) {
  auto scatter_elements_mojo = webnn::mojom::blink::ScatterElements::New();
  scatter_elements_mojo->input_operand_id =
      GetOperatorInputId(scatter_elements, operand_to_id_map, 0);
  scatter_elements_mojo->indices_operand_id =
      GetOperatorInputId(scatter_elements, operand_to_id_map, 1);
  scatter_elements_mojo->updates_operand_id =
      GetOperatorInputId(scatter_elements, operand_to_id_map, 2);
  scatter_elements_mojo->output_operand_id =
      GetOperatorOutputId(scatter_elements, operand_to_id_map);

  const auto* options =
      static_cast<const MLScatterOptions*>(scatter_elements->Options());
  scatter_elements_mojo->axis = options->axis();
  scatter_elements_mojo->label = options->label();
  return webnn::mojom::blink::Operation::NewScatterElements(
      std::move(scatter_elements_mojo));
}

OperationPtr CreateScatterNDOperation(const OperandToIdMap& operand_to_id_map,
                                      const MLOperator* scatter_nd) {
  auto scatter_nd_mojo = webnn::mojom::blink::ScatterND::New();
  scatter_nd_mojo->input_operand_id =
      GetOperatorInputId(scatter_nd, operand_to_id_map, 0);
  scatter_nd_mojo->indices_operand_id =
      GetOperatorInputId(scatter_nd, operand_to_id_map, 1);
  scatter_nd_mojo->updates_operand_id =
      GetOperatorInputId(scatter_nd, operand_to_id_map, 2);
  scatter_nd_mojo->output_operand_id =
      GetOperatorOutputId(scatter_nd, operand_to_id_map);
  scatter_nd_mojo->label = scatter_nd->Options()->label();
  return webnn::mojom::blink::Operation::NewScatterNd(
      std::move(scatter_nd_mojo));
}

OperationPtr CreateSigmoidOperation(const OperandToIdMap& operand_to_id_map,
                                    const MLOperator* sigmoid) {
  auto sigmoid_mojo = blink_mojom::Sigmoid::New();
  sigmoid_mojo->input_operand_id =
      GetOperatorInputId(sigmoid, operand_to_id_map);
  sigmoid_mojo->output_operand_id =
      GetOperatorOutputId(sigmoid, operand_to_id_map);
  sigmoid_mojo->label = sigmoid->Options()->label();
  return blink_mojom::Operation::New
"""


```