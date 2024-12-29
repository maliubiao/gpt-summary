Response:
The user wants a summary of the functionality of the `ml_graph_type_converter.cc` file in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename strongly suggests this file is responsible for converting types related to ML graphs. Specifically, it's likely converting from the Blink representation (used in JavaScript APIs) to the Mojo representation (used for inter-process communication within Chromium).

2. **Scan the includes:**  The included headers provide significant clues:
    * `<v8_ml_*>` headers indicate interaction with JavaScript WebNN API types.
    * `services/webnn/public/cpp/*` and `services/webnn/public/mojom/*` headers point to the Mojo representation of WebNN concepts.
    * `ml_graph_utils.h`, `ml_operand.h`, `ml_operator.h` are internal Blink WebNN classes.

3. **Examine the namespaces:** The code uses `blink`, `mojo`, and `blink_mojom`. This confirms the conversion between Blink and Mojo representations.

4. **Analyze the functions:**
    * Functions like `ToOperandDataType`, `BlinkRecurrentNetworkActivationToMojo`, `BlinkLstmWeightLayoutToMojo`, `BlinkGruWeightLayoutToMojo` are clearly responsible for converting specific enum types from Blink to Mojo.
    * The `TypeConverter<blink_mojom::OperandPtr, blink::MLOperand*>::Convert` function stands out as a more general conversion for `MLOperand`.
    * Functions starting with `Create...Operation` (like `CreateClamp`, `CreateElu`, `CreateHardSigmoid`, etc.) suggest the creation of Mojo representations for different WebNN operations.
    * Functions like `GetInputOperandSize2d`, `GetInputOperandPermutation`, `GetOutputOperandPermutation`, `GetConv2DFilterPermutation`, `GetConvTranspose2DFilterPermutation`, `GetResample2DPermutation` indicate logic related to data layout and potentially handling differences in layout expectations between Blink and the underlying WebNN service.
    * The `SerializeConv2dOperation` function suggests a more involved conversion process for the Conv2D operation, likely including handling of data layout transformations.

5. **Infer the main function:** Based on the above, the primary responsibility is converting a Blink-internal representation of a WebNN graph into a Mojo representation suitable for sending to a separate service process. This involves converting individual operands, operators, and their associated options.

6. **Consider the relationship with JavaScript, HTML, CSS:**
    * The inclusion of `<v8_ml_*>` headers makes the connection to JavaScript clear. The file facilitates the use of the WebNN API in JavaScript by bridging the gap to the internal implementation.
    * HTML and CSS are less directly involved. However, the WebNN API is exposed to JavaScript, which runs in the context of web pages defined by HTML and styled by CSS. Therefore, a website using WebNN through JavaScript would indirectly rely on this conversion process.

7. **Think about logical inference:** The permutation logic (e.g., `GetInputOperandPermutation`, `InsertInputTranspose`) is a form of logical inference. Given an input layout and the target layout of the WebNN service, the code determines the necessary transformation (permutation of dimensions) to align the data.

8. **Consider potential user/programming errors:** Incorrectly specifying data types, shapes, or operator options in the JavaScript WebNN API would likely be caught during this conversion process, as the code needs to map these JavaScript values to the corresponding Mojo types. Mismatched layouts could also lead to errors or unexpected behavior if not handled correctly by the conversion logic.

9. **Imagine the user's journey:** A user interacts with the WebNN API in JavaScript. This triggers the creation of Blink's internal representation of the ML graph. This `ml_graph_type_converter.cc` file is invoked to transform this internal representation into the Mojo format for communication with the WebNN service.

10. **Focus on summarizing for Part 1:**  The request specifically asks for a summary of the *functionality* in this first part of the file. Therefore, the summary should emphasize the core conversion role and highlight the specific types of conversions performed. It should mention the connection to JavaScript and the handling of data layouts.

By following these steps, we can arrive at a comprehensive and accurate summary of the `ml_graph_type_converter.cc` file's functionality, as demonstrated in the initial good answer.
这是 `blink/renderer/modules/ml/webnn/ml_graph_type_converter.cc` 文件的第一部分，其主要功能是**将 Blink 引擎中 WebNN (Web Neural Network API) 的数据结构和类型转换为对应的 Mojo (Message Passing Objects) 消息类型**，以便与 Chromium 浏览器进程中的 WebNN 服务进行通信。

以下是对其功能的详细归纳：

**核心功能：Blink WebNN 类型到 Mojo 类型的转换**

* **数据类型转换:**  `ToOperandDataType` 函数负责将 Blink 中定义的 `V8MLOperandDataType` 枚举类型转换为 Mojo 中定义的 `webnn::OperandDataType` 枚举类型。这包括 `float32`, `float16`, `int32`, `uint32`, `int64`, `uint64`, `int8`, `uint8`, `int4`, `uint4` 等数据类型的转换。
* **枚举类型转换:** 多个函数负责将 Blink 中定义的 WebNN 相关枚举类型转换为 Mojo 中对应的枚举类型，例如：
    * `BlinkRecurrentNetworkActivationToMojo`: 转换循环神经网络的激活函数类型 (`relu`, `sigmoid`, `tanh`)。
    * `BlinkRecurrentNetworkDirectionToMojo`: 转换循环神经网络的方向 (`forward`, `backward`, `both`)。
    * `BlinkLstmWeightLayoutToMojo`: 转换 LSTM 权重的布局 (`iofg`, `ifgo`)。
    * `BlinkGruWeightLayoutToMojo`: 转换 GRU 权重的布局 (`zrn`, `rzn`)。
* **Operand 转换:** `TypeConverter<blink_mojom::OperandPtr, blink::MLOperand*>::Convert` 函数负责将 Blink 中的 `MLOperand` 对象转换为 Mojo 中的 `blink_mojom::OperandPtr`。这包括设置操作数的描述符 (`descriptor`)、类型 (`kind`: input, constant, output) 和名称 (`name`)。
* **输入操作数尺寸获取:** `GetInputOperandSize2d` 函数根据输入的 `MLOperand` 和布局类型 (`kNchw` 或 `kNhwc`)，获取输入操作数的二维尺寸 (高度和宽度)。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接与 **JavaScript** 的 WebNN API 功能相关。

* **JavaScript API 的桥梁:** 当 JavaScript 代码调用 WebNN API 创建和执行机器学习模型时，Blink 引擎会解析这些调用并创建内部的 `MLOperand` 和 `MLOperator` 对象。`ml_graph_type_converter.cc` 文件充当了将这些 JavaScript 概念表示的内部对象转换为可以跨进程传递的 Mojo 消息的桥梁。
* **示例:**
    * 假设 JavaScript 代码使用 `navigator.ml.createModel()` 创建了一个模型，并在其中定义了一个输入张量，数据类型为 `float32`。当 Blink 需要将这个输入张量的信息发送给浏览器进程中的 WebNN 服务时，`ToOperandDataType(blink::V8MLOperandDataType::Enum::kFloat32)` 会被调用，将其转换为 Mojo 中的 `webnn::OperandDataType::kFloat32`。
    * 又如，如果 JavaScript 代码中定义了一个 LSTM 层，并指定了权重布局为 `ifgo`，那么 `BlinkLstmWeightLayoutToMojo(blink::V8MLLstmWeightLayout::Enum::kIfgo)` 会被调用，将其转换为 Mojo 中的 `blink_mojom::LstmWeightLayout::kIfgo`。

**逻辑推理 (初步展现，后续部分可能更详细):**

* **假设输入:** 一个 Blink 内部的 `MLOperand` 对象，表示一个浮点数类型的输入张量，形状为 `[1, 3, 224, 224]` (NCHW 布局)。
* **输出:** 一个 `blink_mojom::OperandPtr` 对象，其 `descriptor` 成员的 `dataType` 为 `webnn::OperandDataType::kFloat32`，`dimensions` 为 `[1, 3, 224, 224]`，`kind` 为 `kInput` (假设是输入操作数)。

**用户或编程常见的使用错误 (在这个部分尚未直接体现，后续部分可能会涉及):**

在这个文件的第一部分，主要关注的是类型转换，因此直接的用户或编程错误较少体现。不过，可以推测后续部分可能会处理以下错误：

* **数据类型不匹配:** 用户在 JavaScript 中提供的操作数数据类型与模型定义的不符。
* **形状不匹配:** 用户提供的输入张量形状与模型期望的形状不一致。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页中编写 JavaScript 代码，使用 WebNN API 定义和创建机器学习模型。** 例如，使用 `navigator.ml.createModel()` 创建模型，使用 `model.addOperand()` 添加操作数，使用 `model.addOperation()` 添加运算。
2. **JavaScript 代码调用 `model.compute()` 或类似方法来执行模型。**
3. **Blink 引擎接收到执行模型的请求。**
4. **Blink 内部的 WebNN 实现开始构建计算图的表示。** 这涉及到创建 `MLOperand` 和 `MLOperator` 对象。
5. **当需要将这个计算图的信息发送到浏览器进程的 WebNN 服务时，`ml_graph_type_converter.cc` 中的代码会被调用。**
6. **对于每个 `MLOperand` 和相关的配置选项，会调用相应的转换函数 (例如 `ToOperandDataType`, `BlinkRecurrentNetworkActivationToMojo`, `TypeConverter::Convert`)。**
7. **转换后的 Mojo 消息会被发送到浏览器进程，由 WebNN 服务进行实际的计算。**

**功能归纳 (针对第 1 部分):**

这个文件的第一部分主要负责 **将 Blink 引擎中对 WebNN 操作数和相关属性的内部表示 (例如数据类型、枚举值) 转换为可以跨进程通信的 Mojo 消息格式**。它定义了各种转换函数，用于处理不同类型的 WebNN 数据和配置。这为后续将完整的 WebNN 图结构转换为 Mojo 消息奠定了基础。 这部分重点在于基础数据类型和枚举类型的转换，以及 `MLOperand` 的初步转换。

Prompt: 
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_type_converter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_type_converter.h"

#include <array>
#include <optional>

#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/types/expected_macros.h"
#include "services/webnn/public/cpp/context_properties.h"
#include "services/webnn/public/cpp/graph_validation_utils.h"
#include "services/webnn/public/cpp/operand_descriptor.h"
#include "services/webnn/public/mojom/webnn_graph.mojom-blink-forward.h"
#include "services/webnn/public/mojom/webnn_graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_arg_min_max_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_batch_normalization_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_clamp_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_conv_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_conv_transpose_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_cumulative_sum_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_elu_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gather_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gemm_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_cell_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gru_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_hard_sigmoid_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_input_operand_layout.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_instance_normalization_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_layer_normalization_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_leaky_relu_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_linear_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_cell_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operator_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_pad_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_pool_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_recurrent_network_activation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_reduce_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_resample_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_scatter_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_slice_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_split_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_transpose_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_triangular_options.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_utils.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_operand.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_operator.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink_mojom = webnn::mojom::blink;

namespace mojo {

webnn::OperandDataType ToOperandDataType(
    blink::V8MLOperandDataType::Enum data_type) {
  switch (data_type) {
    case blink::V8MLOperandDataType::Enum::kFloat32:
      return webnn::OperandDataType::kFloat32;
    case blink::V8MLOperandDataType::Enum::kFloat16:
      return webnn::OperandDataType::kFloat16;
    case blink::V8MLOperandDataType::Enum::kInt32:
      return webnn::OperandDataType::kInt32;
    case blink::V8MLOperandDataType::Enum::kUint32:
      return webnn::OperandDataType::kUint32;
    case blink::V8MLOperandDataType::Enum::kInt64:
      return webnn::OperandDataType::kInt64;
    case blink::V8MLOperandDataType::Enum::kUint64:
      return webnn::OperandDataType::kUint64;
    case blink::V8MLOperandDataType::Enum::kInt8:
      return webnn::OperandDataType::kInt8;
    case blink::V8MLOperandDataType::Enum::kUint8:
      return webnn::OperandDataType::kUint8;
    case blink::V8MLOperandDataType::Enum::kInt4:
      return webnn::OperandDataType::kInt4;
    case blink::V8MLOperandDataType::Enum::kUint4:
      return webnn::OperandDataType::kUint4;
  }
}

webnn::mojom::blink::RecurrentNetworkActivation
BlinkRecurrentNetworkActivationToMojo(
    blink::V8MLRecurrentNetworkActivation activation) {
  // This assertion protects against the IDL enum changing without updating the
  // corresponding mojom interface, or vice versa. The offset of 1 accounts for
  // the zero-indexing of the mojom enum values.
  static_assert(
      blink::V8MLRecurrentNetworkActivation::kEnumSize ==
          static_cast<size_t>(
              webnn::mojom::blink::RecurrentNetworkActivation::kMaxValue) +
              1,
      "the number of values in the RecurrentNetworkActivation mojom enum must "
      "match the number of values in the MLRecurrentNetworkActivation blink "
      "enum");

  switch (activation.AsEnum()) {
    case blink::V8MLRecurrentNetworkActivation::Enum::kRelu:
      return webnn::mojom::blink::RecurrentNetworkActivation::kRelu;
    case blink::V8MLRecurrentNetworkActivation::Enum::kSigmoid:
      return webnn::mojom::blink::RecurrentNetworkActivation::kSigmoid;
    case blink::V8MLRecurrentNetworkActivation::Enum::kTanh:
      return webnn::mojom::blink::RecurrentNetworkActivation::kTanh;
  }
}

blink_mojom::RecurrentNetworkDirection BlinkRecurrentNetworkDirectionToMojo(
    blink::V8MLRecurrentNetworkDirection::Enum direction) {
  switch (direction) {
    case blink::V8MLRecurrentNetworkDirection::Enum::kForward:
      return blink_mojom::RecurrentNetworkDirection::kForward;
    case blink::V8MLRecurrentNetworkDirection::Enum::kBackward:
      return blink_mojom::RecurrentNetworkDirection::kBackward;
    case blink::V8MLRecurrentNetworkDirection::Enum::kBoth:
      return blink_mojom::RecurrentNetworkDirection::kBoth;
  }
}

blink_mojom::LstmWeightLayout BlinkLstmWeightLayoutToMojo(
    blink::V8MLLstmWeightLayout::Enum layout) {
  switch (layout) {
    case blink::V8MLLstmWeightLayout::Enum::kIofg:
      return blink_mojom::LstmWeightLayout::kIofg;
    case blink::V8MLLstmWeightLayout::Enum::kIfgo:
      return blink_mojom::LstmWeightLayout::kIfgo;
  }
}

blink_mojom::GruWeightLayout BlinkGruWeightLayoutToMojo(
    blink::V8MLGruWeightLayout::Enum layout) {
  switch (layout) {
    case blink::V8MLGruWeightLayout::Enum::kZrn:
      return blink_mojom::GruWeightLayout::kZrn;
    case blink::V8MLGruWeightLayout::Enum::kRzn:
      return blink_mojom::GruWeightLayout::kRzn;
  }
}

// Converters from IDL to Mojo.
blink_mojom::OperandPtr
TypeConverter<blink_mojom::OperandPtr, blink::MLOperand*>::Convert(
    const blink::MLOperand* ml_operand) {
  if (!ml_operand) {
    return nullptr;
  }

  auto mojo_operand = blink_mojom::Operand::New();
  mojo_operand->descriptor = ml_operand->Descriptor();

  switch (ml_operand->Kind()) {
    case webnn::mojom::blink::Operand::Kind::kInput:
      mojo_operand->kind = blink_mojom::Operand::Kind::kInput;
      mojo_operand->name = ml_operand->Name();
      break;
    case webnn::mojom::blink::Operand::Kind::kConstant:
      mojo_operand->kind = blink_mojom::Operand::Kind::kConstant;
      break;
    case webnn::mojom::blink::Operand::Kind::kOutput:
      mojo_operand->kind = blink_mojom::Operand::Kind::kOutput;
      break;
  }
  return mojo_operand;
}

// Get height and width of input operand.
webnn::Size2d<uint32_t> GetInputOperandSize2d(
    const blink::MLOperand* input,
    blink::V8MLInputOperandLayout::Enum type) {
  CHECK(input);
  const auto input_shape = input->Shape();
  CHECK_EQ(input_shape.size(), 4u);
  uint32_t input_height, input_width;
  switch (type) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      // "nchw": [batches, channels, height, width]
      input_height = input_shape[2];
      input_width = input_shape[3];
      break;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      // "nhwc": [batches, height, width, channels]
      input_height = input_shape[1];
      input_width = input_shape[2];
      break;
  }
  return {.height = input_height, .width = input_width};
}

}  // namespace mojo

namespace blink {

namespace {

using blink_mojom::ElementWiseBinary;
using blink_mojom::ElementWiseUnary;
using blink_mojom::Operation;
using blink_mojom::OperationPtr;
using blink_mojom::Size2d;

// Maps MLOperand to its id which is used to identify the `mojo::Operand` across
// processes.
using OperandToIdMap = HeapHashMap<Member<const MLOperand>, uint64_t>;

uint64_t GetOperatorInputId(const MLOperator* op,
                            const OperandToIdMap& operand_to_id_map,
                            wtf_size_t index = 0) {
  CHECK_NE(op, nullptr);
  CHECK_LE(index, op->Inputs().size());
  const auto* input = op->Inputs()[index].Get();
  return operand_to_id_map.at(input);
}

uint64_t GetOperatorOutputId(const MLOperator* op,
                             const OperandToIdMap& operand_to_id_map,
                             wtf_size_t index = 0) {
  CHECK_NE(op, nullptr);
  CHECK_LE(index, op->Outputs().size());
  const auto* output = op->Outputs()[index].Get();
  return operand_to_id_map.at(output);
}

uint64_t InsertTemporaryOperand(const OperandToIdMap& operand_to_id_map,
                                webnn::OperandDescriptor descriptor,
                                blink_mojom::GraphInfo* graph_info) {
  uint64_t operand_id = NextOperandId(*graph_info);

  auto mojo_operand = blink_mojom::Operand::New();
  mojo_operand->kind = blink_mojom::Operand::Kind::kOutput;
  mojo_operand->descriptor = std::move(descriptor);

  graph_info->id_to_operand_map.insert(operand_id, std::move(mojo_operand));
  return operand_id;
}

Vector<uint32_t> PermuteShape(base::span<const uint32_t> shape,
                              base::span<const uint32_t> permutation) {
  wtf_size_t shape_size = base::checked_cast<wtf_size_t>(shape.size());
  Vector<uint32_t> permuted_array(shape_size);

  CHECK_EQ(shape_size, permutation.size());
  for (wtf_size_t i = 0; i < shape_size; ++i) {
    permuted_array[i] = shape[permutation[i]];
  }

  return permuted_array;
}

// Insert a transpose operation after the given operand. Returns the ID of the
// operand holding the transposed result.
uint64_t InsertInputTranspose(const OperandToIdMap& operand_to_id_map,
                              const MLOperand* operand,
                              base::span<const uint32_t> permutation,
                              blink_mojom::GraphInfo* graph_info,
                              const String& label) {
  uint64_t operand_id = InsertTemporaryOperand(
      operand_to_id_map,
      *webnn::OperandDescriptor::Create(
          operand->DataType(), PermuteShape(operand->Shape(), permutation)),
      graph_info);

  auto transpose = blink_mojom::Transpose::New();
  transpose->input_operand_id = operand_to_id_map.at(operand);
  transpose->output_operand_id = operand_id;
  transpose->permutation = Vector<uint32_t>(permutation);
  transpose->label = label;
  graph_info->operations.push_back(
      blink_mojom::Operation::NewTranspose(std::move(transpose)));

  return operand_id;
}

blink_mojom::ClampPtr CreateClamp(const OperandToIdMap& operand_to_id_map,
                                  const MLOperator* clamp) {
  const auto* options = static_cast<const MLClampOptions*>(clamp->Options());
  CHECK(options);

  auto clamp_mojo = blink_mojom::Clamp::New(
      GetOperatorInputId(clamp, operand_to_id_map),
      GetOperatorOutputId(clamp, operand_to_id_map),
      options->getMinValueOr(-std::numeric_limits<float>::infinity()),
      options->getMaxValueOr(+std::numeric_limits<float>::infinity()),
      options->label());
  return clamp_mojo;
}

blink_mojom::EluPtr CreateElu(const OperandToIdMap& operand_to_id_map,
                              const MLOperator* elu) {
  const auto* options = static_cast<const MLEluOptions*>(elu->Options());
  CHECK(options);
  return blink_mojom::Elu::New(GetOperatorInputId(elu, operand_to_id_map),
                               GetOperatorOutputId(elu, operand_to_id_map),
                               options->alpha(), options->label());
}

blink_mojom::HardSigmoidPtr CreateHardSigmoid(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* hard_sigmoid) {
  const auto* options =
      static_cast<const MLHardSigmoidOptions*>(hard_sigmoid->Options());
  CHECK(options);
  return blink_mojom::HardSigmoid::New(
      GetOperatorInputId(hard_sigmoid, operand_to_id_map),
      GetOperatorOutputId(hard_sigmoid, operand_to_id_map), options->alpha(),
      options->beta(), options->label());
}

OperationPtr CreateExpandOperation(const OperandToIdMap& operand_to_id_map,
                                   const MLOperator* expand) {
  auto expand_mojo = blink_mojom::Expand::New();
  expand_mojo->input_operand_id = GetOperatorInputId(expand, operand_to_id_map);
  expand_mojo->output_operand_id =
      GetOperatorOutputId(expand, operand_to_id_map);
  expand_mojo->label = expand->Options()->label();
  return blink_mojom::Operation::NewExpand(std::move(expand_mojo));
}

blink_mojom::LeakyReluPtr CreateLeakyRelu(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* leaky_relu) {
  const auto* options =
      static_cast<const MLLeakyReluOptions*>(leaky_relu->Options());
  CHECK(options);
  return blink_mojom::LeakyRelu::New(
      GetOperatorInputId(leaky_relu, operand_to_id_map),
      GetOperatorOutputId(leaky_relu, operand_to_id_map), options->alpha(),
      options->label());
}

blink_mojom::LinearPtr CreateLinear(const OperandToIdMap& operand_to_id_map,
                                    const MLOperator* linear) {
  const auto* options = static_cast<const MLLinearOptions*>(linear->Options());
  CHECK(options);
  return blink_mojom::Linear::New(
      GetOperatorInputId(linear, operand_to_id_map),
      GetOperatorOutputId(linear, operand_to_id_map), options->alpha(),
      options->beta(), options->label());
}

OperationPtr CreateSoftmaxOperation(const OperandToIdMap& operand_to_id_map,
                                    const MLOperator* softmax) {
  const auto* softmax_operator = static_cast<const MLSoftmaxOperator*>(softmax);
  auto softmax_mojo = blink_mojom::Softmax::New(
      GetOperatorInputId(softmax, operand_to_id_map),
      GetOperatorOutputId(softmax, operand_to_id_map), softmax_operator->Axis(),
      softmax->Options()->label());
  return blink_mojom::Operation::NewSoftmax(std::move(softmax_mojo));
}

OperationPtr CreateSoftplus(const OperandToIdMap& operand_to_id_map,
                            const MLOperator* softplus) {
  auto softplus_mojo = blink_mojom::Softplus::New(
      GetOperatorInputId(softplus, operand_to_id_map),
      GetOperatorOutputId(softplus, operand_to_id_map),
      softplus->Options()->label());
  return blink_mojom::Operation::NewSoftplus(std::move(softplus_mojo));
}

webnn::mojom::InputOperandLayout BlinkInputOperandLayoutToMojo(
    blink::V8MLInputOperandLayout::Enum type) {
  switch (type) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      return webnn::mojom::InputOperandLayout::kChannelsFirst;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      return webnn::mojom::InputOperandLayout::kChannelsLast;
  }
}

webnn::InputOperandLayout BlinkInputOperandLayoutToNative(
    blink::V8MLInputOperandLayout::Enum type) {
  switch (type) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      return webnn::InputOperandLayout::kNchw;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      return webnn::InputOperandLayout::kNhwc;
  }
}

constexpr std::array<uint32_t, 4> kNchwToNhwcPermutation = {0u, 2u, 3u, 1u};
constexpr std::array<uint32_t, 4> kNhwcToNchwPermutation = {0u, 3u, 1u, 2u};

std::optional<base::span<const uint32_t>> GetInputOperandPermutation(
    blink::V8MLInputOperandLayout::Enum input_layout,
    const webnn::ContextProperties& context_properties) {
  if (BlinkInputOperandLayoutToNative(input_layout) ==
      context_properties.input_operand_layout) {
    return std::nullopt;
  }

  switch (input_layout) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      CHECK_EQ(context_properties.input_operand_layout,
               webnn::InputOperandLayout::kNhwc);
      return kNchwToNhwcPermutation;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      CHECK_EQ(context_properties.input_operand_layout,
               webnn::InputOperandLayout::kNchw);
      return kNhwcToNchwPermutation;
  }
}

std::optional<base::span<const uint32_t>> GetOutputOperandPermutation(
    blink::V8MLInputOperandLayout::Enum input_layout,
    const webnn::ContextProperties& context_properties) {
  if (BlinkInputOperandLayoutToNative(input_layout) ==
      context_properties.input_operand_layout) {
    return std::nullopt;
  }

  // The output layout is the same as the input layout and so the output
  // needs to have the inverse of the permutation returned by
  // `GetInputOperandPermutation()` applied.
  switch (input_layout) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      CHECK_EQ(context_properties.input_operand_layout,
               webnn::InputOperandLayout::kNhwc);
      return kNhwcToNchwPermutation;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      CHECK_EQ(context_properties.input_operand_layout,
               webnn::InputOperandLayout::kNchw);
      return kNchwToNhwcPermutation;
  }
}

std::optional<std::array<uint32_t, 4>> GetConv2DFilterPermutation(
    webnn::InputOperandLayout input_layout,
    bool depthwise,
    blink::V8MLConv2dFilterOperandLayout filter_layout) {
  switch (input_layout) {
    case webnn::InputOperandLayout::kNchw:
      // Mojo expects the OIHW layout.
      switch (filter_layout.AsEnum()) {
        case blink::V8MLConv2dFilterOperandLayout::Enum::kOihw:
          return std::nullopt;
        case blink::V8MLConv2dFilterOperandLayout::Enum::kHwio:
          return std::to_array<uint32_t>({3u, 2u, 0u, 1u});
        case blink::V8MLConv2dFilterOperandLayout::Enum::kOhwi:
          return std::to_array<uint32_t>({0u, 3u, 1u, 2u});
        case blink::V8MLConv2dFilterOperandLayout::Enum::kIhwo:
          return std::to_array<uint32_t>({3u, 0u, 1u, 2u});
      }
      break;
    case webnn::InputOperandLayout::kNhwc:
      if (depthwise) {
        // Mojo expects the IHWO layout.
        switch (filter_layout.AsEnum()) {
          case blink::V8MLConv2dFilterOperandLayout::Enum::kOihw:
            return std::to_array<uint32_t>({1u, 2u, 3u, 0u});
          case blink::V8MLConv2dFilterOperandLayout::Enum::kHwio:
            return std::to_array<uint32_t>({2u, 0u, 1u, 3u});
          case blink::V8MLConv2dFilterOperandLayout::Enum::kOhwi:
            return std::to_array<uint32_t>({3u, 1u, 2u, 0u});
          case blink::V8MLConv2dFilterOperandLayout::Enum::kIhwo:
            return std::nullopt;
        }
      } else {
        switch (filter_layout.AsEnum()) {
          // Mojo expects the OHWI layout.
          case blink::V8MLConv2dFilterOperandLayout::Enum::kOihw:
            return std::to_array<uint32_t>({0u, 2u, 3u, 1u});
          case blink::V8MLConv2dFilterOperandLayout::Enum::kHwio:
            return std::to_array<uint32_t>({3u, 0u, 1u, 2u});
          case blink::V8MLConv2dFilterOperandLayout::Enum::kOhwi:
            return std::nullopt;
          case blink::V8MLConv2dFilterOperandLayout::Enum::kIhwo:
            return std::to_array<uint32_t>({3u, 1u, 2u, 0u});
        }
      }
      break;
  }
}

std::optional<std::array<uint32_t, 4>> GetConvTranspose2DFilterPermutation(
    webnn::InputOperandLayout input_layout,
    blink::V8MLConvTranspose2dFilterOperandLayout filter_layout) {
  switch (input_layout) {
    case webnn::InputOperandLayout::kNchw:
      // Mojo expects IOHW layout.
      switch (filter_layout.AsEnum()) {
        case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kIohw:
          return std::nullopt;
        case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kHwoi:
          return std::to_array<uint32_t>({3, 2, 0, 1});
        case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kOhwi:
          return std::to_array<uint32_t>({3u, 0u, 1u, 2u});
      }
      break;
    case webnn::InputOperandLayout::kNhwc:
      // Mojo expects OHWI layout.
      switch (filter_layout.AsEnum()) {
        case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kIohw:
          return std::to_array<uint32_t>({1u, 2u, 3u, 0u});
        case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kHwoi:
          return std::to_array<uint32_t>({2u, 0u, 1u, 3u});
        case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kOhwi:
          return std::nullopt;
      }
      break;
  }
}

constexpr std::array<uint32_t, 2> kResample2dChannelFirstAxes{2u, 3u};
constexpr std::array<uint32_t, 2> kResample2dChannelLastAxes{1u, 2u};
std::optional<std::vector<uint32_t>> GetResample2DPermutation(
    const Vector<uint32_t>& from_axes,
    const webnn::ContextProperties& context_properties) {
  if (context_properties.resample_2d_axes == webnn::Resample2DAxes::kAny) {
    return std::nullopt;
  }

  base::span<const uint32_t> to_axes =
      context_properties.resample_2d_axes ==
              webnn::Resample2DAxes::kChannelsFirst
          ? kResample2dChannelFirstAxes
          : kResample2dChannelLastAxes;

  CHECK_EQ(from_axes.size(), 2u);
  CHECK(base::ranges::is_sorted(from_axes));
  if (from_axes == to_axes) {
    return std::nullopt;
  }

  std::vector<uint32_t> permutation{0u, 1u, 2u, 3u};

  // Move each axis from from_axes to to_axes.
  for (size_t i = 0; i < from_axes.size(); ++i) {
    uint32_t from_axis = from_axes[static_cast<wtf_size_t>(i)];
    uint32_t to_axis = to_axes[i];
    // Find the current index of the from_axis as it could have been moved from
    // previous iteration.
    auto it = base::ranges::find(permutation, from_axis);
    CHECK(it != permutation.end());
    size_t from_axis_index = std::distance(permutation.begin(), it);
    std::swap(permutation[to_axis], permutation[from_axis_index]);
  }
  return permutation;
}

std::vector<uint32_t> GetInversePermutation(
    base::span<const uint32_t> permutation) {
  std::vector<uint32_t> inverse_perm(permutation.size());
  for (size_t i = 0; i < permutation.size(); ++i) {
    CHECK(permutation[i] < inverse_perm.size());
    inverse_perm[permutation[i]] = base::checked_cast<uint32_t>(i);
  }
  return inverse_perm;
}

OperationPtr CreateArgMinMaxOperation(const OperandToIdMap& operand_to_id_map,
                                      const MLOperator* op,
                                      blink_mojom::ArgMinMax::Kind kind) {
  const auto* arg_min_max = static_cast<const MLArgMinMaxOperator*>(op);
  auto input_operand_id = GetOperatorInputId(arg_min_max, operand_to_id_map);
  auto output_operand_id = GetOperatorOutputId(arg_min_max, operand_to_id_map);
  const auto* options =
      static_cast<const blink::MLArgMinMaxOptions*>(arg_min_max->Options());
  CHECK(options);
  auto arg_min_max_mojo = blink_mojom::ArgMinMax::New(
      kind, input_operand_id, output_operand_id, arg_min_max->Axis(),
      options->keepDimensions(), options->label());
  return blink_mojom::Operation::NewArgMinMax(std::move(arg_min_max_mojo));
}

OperationPtr CreateBatchNormalizationOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* batch_normalization) {
  auto batch_normalization_mojo =
      webnn::mojom::blink::BatchNormalization::New();
  batch_normalization_mojo->input_operand_id =
      GetOperatorInputId(batch_normalization, operand_to_id_map, 0);
  batch_normalization_mojo->mean_operand_id =
      GetOperatorInputId(batch_normalization, operand_to_id_map, 1);
  batch_normalization_mojo->variance_operand_id =
      GetOperatorInputId(batch_normalization, operand_to_id_map, 2);
  batch_normalization_mojo->output_operand_id =
      GetOperatorOutputId(batch_normalization, operand_to_id_map);

  const auto* options = static_cast<const MLBatchNormalizationOptions*>(
      batch_normalization->Options());
  CHECK(options);
  if (options->hasScale()) {
    batch_normalization_mojo->scale_operand_id =
        operand_to_id_map.at(options->scale());
  }
  if (options->hasBias()) {
    batch_normalization_mojo->bias_operand_id =
        operand_to_id_map.at(options->bias());
  }
  batch_normalization_mojo->axis = options->axis();
  batch_normalization_mojo->epsilon = options->epsilon();
  batch_normalization_mojo->label = options->label();
  return webnn::mojom::blink::Operation::NewBatchNormalization(
      std::move(batch_normalization_mojo));
}

OperationPtr CreateConcatOperation(const OperandToIdMap& operand_to_id_map,
                                   const MLOperator* concat) {
  const auto& inputs = concat->Inputs();

  Vector<uint64_t> input_operand_ids;
  input_operand_ids.reserve(inputs.size());
  base::ranges::transform(inputs, std::back_inserter(input_operand_ids),
                          [operand_to_id_map](const auto& input) {
                            return operand_to_id_map.at(input);
                          });

  auto concat_mojo = blink_mojom::Concat::New();
  concat_mojo->input_operand_ids = std::move(input_operand_ids);
  concat_mojo->output_operand_id =
      GetOperatorOutputId(concat, operand_to_id_map);
  const auto* concat_operator = static_cast<const MLConcatOperator*>(concat);
  concat_mojo->axis = concat_operator->Axis();
  concat_mojo->label = concat->Options()->label();
  return blink_mojom::Operation::NewConcat(std::move(concat_mojo));
}

bool IsDepthwiseConv2d(const MLOperator* conv2d) {
  const auto* options = static_cast<const MLConv2dOptions*>(conv2d->Options());
  CHECK(options);

  const MLOperand* input = conv2d->Inputs()[0];
  CHECK(input);
  const std::vector<uint32_t>& input_shape = input->Shape();
  CHECK_EQ(input_shape.size(), 4u);
  const MLOperand* output = conv2d->Outputs()[0].Get();
  CHECK(output);
  const std::vector<uint32_t>& output_shape = output->Shape();
  CHECK_EQ(output_shape.size(), 4u);

  uint32_t input_channels, output_channels;
  switch (options->inputLayout().AsEnum()) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      input_channels = input_shape[1];
      output_channels = output_shape[1];
      break;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      input_channels = input_shape[3];
      output_channels = output_shape[3];
      break;
  }

  const uint32_t groups = base::checked_cast<uint32_t>(options->groups());
  return webnn::IsDepthwiseConv2d(input_channels, output_channels, groups);
}

template <typename MLConv2dOptionsType>
std::optional<String> SerializeConv2dOperation(
    const OperandToIdMap& operand_to_id_map,
    const webnn::ContextProperties& context_properties,
    const MLOperator* conv2d,
    blink_mojom::GraphInfo* graph_info) {
  auto conv2d_mojo = blink_mojom::Conv2d::New();

  const auto* options =
      static_cast<const MLConv2dOptionsType*>(conv2d->Options());
  CHECK(options);

  // If strides is not present, the values are assumed to be [1,1].
  auto strides = options->getStridesOr({1, 1});
  CHECK_EQ(strides.size(), 2u);
  conv2d_mojo->strides = Size2d::New(strides[0], strides[1]);

  // If dilations is not present, the values are assumed to be [1, 1].
  auto dilations = options->getDilationsOr({1, 1});
  CHECK_EQ(dilations.size(), 2u);
  conv2d_mojo->dilations = Size2d::New(dilations[0], dilations[1]);
  conv2d_mojo->groups = options->groups();
  if (options->hasBias()) {
    conv2d_mojo->bias_operand_id = operand_to_id_map.at(options->bias());
  }

  const MLOperand* input_operand = conv2d->Inputs()[0];
  const MLOperand* output_operand = conv2d->Outputs()[0];
  uint64_t output_operand_id = operand_to_id_map.at(output_operand);

  const std::optional<base::span<const uint32_t>> input_permutation =
      GetInputOperandPermutation(options->inputLayout().AsEnum(),
                                 context_properties);
  if (input_permutation.has_value()) {
    conv2d_mojo->input_operand_id =
        InsertInputTranspose(operand_to_id_map, input_operand,
                             *input_permutation, graph_info, options->label());

    output_operand_id = InsertTemporaryOperand(
        operand_to_id_map,
        *webnn::OperandDescriptor::Create(
            output_operand->DataType(),
            PermuteShape(output_operand->Shape(), *input_permutation)),
        graph_info);
  } else {
    conv2d_mojo->input_operand_id = operand_to_id_map.at(input_operand);
  }
  conv2d_mojo->output_operand_id = output_operand_id;

  const MLOperand* filter_operand = conv2d->Inputs()[1];
  std::optional<std::array<uint32_t, 4>> filter_permutation;

  if constexpr (std::is_same<MLConv2dOptionsType, MLConv2dOptions>::value) {
    conv2d_mojo->kind = blink_mojom::Conv2d::Kind::kDirect;

    bool depthwise = IsDepthwiseConv2d(conv2d);
    filter_permutation =
        GetConv2DFilterPermutation(context_properties.input_operand_layout,
                                   depthwise, options->filterLayout());
  } else if constexpr (std::is_same<MLConv2dOptionsType,
                                    MLConvTranspose2dOptions>::value) {
    conv2d_mojo->kind = blink_mojom::Conv2d::Kind::kTransposed;

    filter_permutation = GetConvTranspose2DFilterPermutation(
        context_properties.input_operand_layout, options->filterLayout());
  } else {
    NOTREACHED();
  }

  if (filter_permutation) {
    conv2d_mojo->filter_operand_id =
        InsertInputTranspose(operand_to_id_map, filter_operand,
                             *filter_permutation, graph_info, options->label());
  } else {
    conv2d_mojo->filter_operand_id = operand_to_id_map.at(filter_operand);
  }

  // Set the padding from WebNN explicit padding that is in
  // [beginning_height, ending_height, beginning_width, ending_width],
  // default to 0.
  auto ml_padding = options->getPaddingOr({0, 0, 0, 0});
  CHECK_EQ(ml_padding.size(), 4u);
  conv2d_mojo->padding = blink_mojom::Padding2d::New(
      /*beginning padding*/ Size2d::New(ml_padding[0], ml_padding[2]),
      /*ending padding*/ Size2d::New(ml_padding[1], ml_padding[3]));

  conv2d_mojo->label = options->label();

  graph_info->operations.push_back(
      blink_mojom::Operation::NewConv2d(std::move(conv2d_mojo)));

  const std::optional<base::span<const uint32_t>> output_permutation =
      GetOutputOperandPermutation(options->inputLayout().AsEnum(),
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

  return std::nullopt;
}

OperationPtr CreateCumulativeSumOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* cumulative_sum) {
  const auto* cumulative_sum_operator =
      static_cast<const MLCumulativeSumOperator*>(cumulative_sum);
  const auto* options =
      static_cast<const MLCumulativeSumOptions*>(cumulative_sum->Options());

  auto cumulative_sum_mojo = blink_mojom::CumulativeSum::New(
      GetOperatorInputId(cumulative_sum, operand_to_id_map),
      GetOperatorOutputId(cumulative_sum, operand_to_id_map),
      cumulative_sum_operator->Axis(), options->exclusive(),
      options->reversed(), options->label());

  return blink_mojom::Operation::NewCumulativeSum(
      std::move(cumulative_sum_mojo));
}

OperationPtr CreateDequantizeLinearOperation(
    const OperandToIdMap& operand_to_id_map,
    const MLOperator* dequantize_linear) {
  auto dequantize_linear_mojo = blink_mojom::DequantizeLinear::New();
  dequantize_linear_mojo->input_operand_id =
      GetOperatorInputId(dequantize_linear, operand_to_id_map, 0);
  dequantize_linear_mojo->scale_operand_id =
      GetOperatorInputId(dequantize_linear, operand_to_id_map, 1);
  dequantize_linear_mojo->zero_point_operand_id =
      GetOperatorI
"""


```