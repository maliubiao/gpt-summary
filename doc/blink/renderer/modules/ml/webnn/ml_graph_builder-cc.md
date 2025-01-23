Response:
The user is asking for a summary of the functionality of the `ml_graph_builder.cc` file in the Chromium Blink engine. They also want to know:
- Its relationship to JavaScript, HTML, and CSS.
- Examples of logical reasoning within the code (with input and output).
- Common user or programming errors.
- How a user's action can lead to this code being executed (debugging clues).

Based on the provided code snippet, which includes various headers and function definitions, the core responsibility of `ml_graph_builder.cc` is to construct a WebNN (Web Neural Network API) graph. This involves:

1. **Receiving operator and operand definitions.** These definitions likely come from JavaScript code using the WebNN API.
2. **Converting JavaScript API objects and options into internal representations.**  This is evident in the numerous `ConvertTo...Attributes` functions that transform `blink::ML...Options` into `webnn::...Attributes`.
3. **Interacting with the WebNN service.** The `#include "services/webnn/public/mojom/..."` headers suggest that this file communicates with a separate process or component responsible for the actual execution of the neural network.
4. **Tracking operator usage for metrics.** The `MLGraphOperatorUma` enum and `RecordOperatorsUsed` function indicate that the file collects data on which WebNN operators are being used.
5. **Handling potential errors and throwing JavaScript exceptions.** The `THROW_AND_RETURN...` macros are used to propagate errors back to the JavaScript layer.

Therefore, the primary function is **building a computational graph for neural network execution based on user-provided definitions via the WebNN API in JavaScript.**
## 功能归纳：blink/renderer/modules/ml/webnn/ml_graph_builder.cc (第1部分)

这个文件的主要功能是 **构建 WebNN (Web Neural Network API) 的计算图 (Graph)**。它负责接收用户通过 JavaScript WebNN API 提供的神经网络层和操作的描述，并将这些描述转换成底层的 WebNN 服务可以理解的形式。

**具体来说，这个文件的第 1 部分主要负责以下方面：**

1. **头文件包含和命名空间定义:** 引入了必要的 Chromium 基础库、Blink 渲染引擎库、以及 WebNN 相关的接口定义。
2. **枚举定义 (`MLGraphOperatorUma`):** 定义了一个枚举类型 `MLGraphOperatorUma`，用于记录用户在构建 WebNN 图时使用的各种操作（如 `kAdd`, `kConv2d`, `kRelu` 等）。这用于收集性能指标和用户使用习惯。
3. **辅助函数 (`GetUmaValueForOperation`, `RecordOperatorsUsed`):**
    - `GetUmaValueForOperation`:  根据 `blink_mojom::Operation` 的类型，返回对应的 `MLGraphOperatorUma` 枚举值。
    - `RecordOperatorsUsed`: 接收构建好的图的信息 `blink_mojom::GraphInfo`，并记录其中使用的各种 WebNN 操作到 UMA (User Metrics Analysis) 系统。
4. **错误处理宏定义 (`THROW_AND_RETURN_TYPE_IF_ERROR`, `THROW_AND_RETURN_IF_ERROR`, `ASSIGN_OR_THROW_AND_RETURN_IF_ERROR`):** 定义了一些宏，用于简化错误处理流程，当底层操作发生错误时，会抛出相应的 JavaScript 异常并返回。
5. **常量定义 (`kGraphAlreadyBuiltError`):** 定义了一个常量字符串，用于表示图已经被构建过的错误。
6. **类型转换函数 (例如 `BlinkInputOperandLayoutToComponent`, `BlinkConv2dFilterLayoutToComponent` 等):**  定义了一系列函数，用于将 JavaScript WebNN API 中定义的枚举类型（例如 `MLInputOperandLayout`, `MLConv2dFilterOperandLayout`）转换为底层 WebNN 服务使用的枚举类型。
7. **属性转换函数 (例如 `ConvertToBatchNormalizationAttributes`, `ConvertToConv2dAttributes`, `ConvertToPool2dAttributes` 等):**  定义了一系列函数，用于将 JavaScript WebNN API 中提供的操作选项对象（例如 `MLBatchNormalizationOptions`, `MLConv2dOptions`）转换为底层 WebNN 服务需要的属性结构体。这些函数会处理各种选项参数，例如 `padding`, `strides`, `dilations`, `groups` 等。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接与 **JavaScript** 的功能相关，因为它负责处理 JavaScript WebNN API 的调用，并将用户在 JavaScript 中定义的神经网络结构转换为底层实现。

**举例说明:**

假设 JavaScript 代码中创建了一个卷积层，并指定了填充 (padding) 和步幅 (strides) 参数：

```javascript
const builder = new MLGraphBuilder();
const input = builder.input('input', { type: 'float32', dimensions: [1, 28, 28, 3] });
const filter = builder.constant({ type: 'float32', dimensions: [32, 3, 3, 3] }, new Float32Array(32 * 3 * 3 * 3));
const conv2dOptions = { padding: [1, 1, 1, 1], strides: [2, 2] };
const output = builder.conv2d(input, filter, conv2dOptions);
```

当调用 `builder.conv2d(input, filter, conv2dOptions)` 时，Blink 引擎会调用 `ml_graph_builder.cc` 中的相应代码。`ConvertToConv2dAttributes` 函数会被调用，它会接收 JavaScript 传递的 `conv2dOptions` 对象，并将其中的 `padding` 和 `strides` 数组转换成 `webnn::Conv2dAttributes` 结构体中对应的 `padding` 和 `strides` 字段。

**HTML 和 CSS** 本身不直接与这个文件交互。但是，WebNN API 是通过 JavaScript 暴露给 Web 开发者的，而 JavaScript 代码通常嵌入在 HTML 文件中，并可能与 CSS 产生视觉效果上的关联（例如，通过 WebNN 处理图像数据并用于 Canvas 渲染）。

**逻辑推理 (假设输入与输出):**

例如，在 `ConvertToConv2dAttributes` 函数中，对于 `padding` 参数的处理：

**假设输入 (JavaScript 的 `conv2dOptions`):**

```javascript
const conv2dOptions = { padding: [1, 2, 3, 4] };
```

**逻辑推理:** 函数会检查 `padding` 数组的长度是否为 4。如果不是，则会抛出错误。如果是，则会将数组中的值分别赋给 `webnn::Conv2dAttributes` 的 `padding` 字段：

```c++
  attributes.padding = webnn::Padding2d{
      .beginning =
          webnn::Size2d<uint32_t>{.height = padding[0], .width = padding[2]},
      .ending =
          webnn::Size2d<uint32_t>{.height = padding[1], .width = padding[3]}};
```

**假设输出 (`webnn::Conv2dAttributes` 的 `padding` 字段):**

```
padding: {
  beginning: { height: 1, width: 3 },
  ending: { height: 2, width: 4 }
}
```

**用户或编程常见的使用错误:**

1. **`padding`, `strides`, `dilations` 等数组的长度不正确:** 用户可能错误地提供了长度不是 2 或 4 的数组，例如 `padding: [1, 2]`。`ConvertToConv2dAttributes` 等函数会检查这些数组的长度并抛出错误。
2. **在图构建完成后尝试添加新的操作:** `kGraphAlreadyBuiltError` 常量提示了这种错误，用户在调用 `MLGraphBuilder.build()` 之后，不应该再调用任何添加操作的方法 (例如 `conv2d`, `add` 等)。
3. **提供了不支持的选项参数或枚举值:** 例如，提供了一个不存在的 `MLInputOperandLayout` 枚举值。类型转换函数会处理这些错误并抛出异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 JavaScript 中编写使用 WebNN API 的代码:**  例如，创建 `MLGraphBuilder` 对象，定义输入张量，添加各种神经网络层 (如卷积层、激活函数等)，并设置相应的选项参数。
2. **JavaScript 代码调用 `MLGraphBuilder` 的方法:** 当 JavaScript 调用如 `builder.conv2d(input, filter, conv2dOptions)` 这样的方法时，Blink 引擎会捕获这个调用。
3. **Blink 引擎将 JavaScript 对象和参数传递给对应的 C++ 代码:**  Blink 的 V8 绑定机制会将 JavaScript 的 `conv2dOptions` 对象转换为 C++ 可以理解的数据结构，并传递给 `ml_graph_builder.cc` 中 `MLGraphBuilder::Conv2d` 方法。
4. **`MLGraphBuilder::Conv2d` 方法调用内部的属性转换函数:** 例如，`ConvertToConv2dAttributes` 会被调用来处理选项参数。
5. **属性转换函数将 JavaScript 的选项转换为底层的 WebNN 服务需要的格式:**  这个过程中会进行各种检查和转换。
6. **`ml_graph_builder.cc` 与 WebNN 服务进行通信:**  最终，`ml_graph_builder.cc` 会使用 Mojo 接口将构建好的图的信息发送给底层的 WebNN 服务。

**总结第 1 部分的功能:**

第 1 部分主要负责 **处理 WebNN 图构建过程中的基础数据转换和校验**。它定义了用于记录操作使用情况的枚举，提供了将 JavaScript WebNN API 类型转换为底层服务类型的方法，以及将 JavaScript 操作选项转换为底层属性结构体的函数。这部分代码是连接 JavaScript WebNN API 和底层 WebNN 服务的关键桥梁，负责确保用户提供的参数正确有效，并将其转换为服务可以理解的形式。

### 提示词
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_builder.h"

#include <algorithm>

#include "base/containers/enum_set.h"
#include "base/containers/span.h"
#include "base/metrics/histogram_macros.h"
#include "base/notimplemented.h"
#include "base/numerics/checked_math.h"
#include "base/ranges/algorithm.h"
#include "base/types/expected.h"
#include "base/types/expected_macros.h"
#include "base/types/pass_key.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "services/webnn/public/cpp/operand_descriptor.h"
#include "services/webnn/public/cpp/webnn_errors.h"
#include "services/webnn/public/mojom/features.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_context_provider.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_graph.mojom-blink.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
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
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_instance_normalization_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_layer_normalization_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_leaky_relu_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_linear_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_cell_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_lstm_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operand_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operator_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_pad_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_pool_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_recurrent_network_activation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_reduce_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_resample_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_reverse_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_scatter_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_slice_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_split_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_transpose_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_triangular_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/ml/ml_context.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_constant_operand.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_error.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_type_converter.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_utils.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_operand.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_operator.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace blink_mojom = webnn::mojom::blink;

namespace {

// These values are persisted to logs. Entries should not be renumbered or
// removed and numeric values should never be reused.
// Please keep in sync with MLGraphOperatorUma in
// //tools/metrics/histograms/metadata/webnn/enums.xml.
enum class MLGraphOperatorUma {
  kGraphBuilt = 0,
  kAbs = 1,
  kAdd = 2,
  kArgMax = 3,
  kArgMin = 4,
  kAveragePool2d = 5,
  kBatchNormalization = 6,
  kCast = 7,
  kCeil = 8,
  kClamp = 9,
  kConcat = 10,
  kConv2d = 11,
  kConvTranspose2d = 12,
  kCos = 13,
  kCumulativeSum = 14,
  kDequantizeLinear = 15,
  kDiv = 16,
  kElu = 17,
  kEqual = 18,
  kErf = 19,
  kExp = 20,
  kExpand = 21,
  kFloor = 22,
  kGather = 23,
  kGatherElements = 24,
  kGatherNd = 25,
  kGelu = 26,
  kGemm = 27,
  kGreater = 28,
  kGreaterOrEqual = 29,
  kGru = 30,
  kGruCell = 31,
  kHardSigmoid = 32,
  kHardSwish = 33,
  kIdentity = 34,
  kInstanceNormalization = 35,
  kL2Pool2d = 36,
  kLayerNormalization = 37,
  kLeakyRelu = 38,
  kLesser = 39,
  kLesserOrEqual = 40,
  kLinear = 41,
  kLog = 42,
  kLogicalAnd = 43,
  kLogicalNot = 44,
  kLogicalOr = 45,
  kLogicalXor = 46,
  kLstm = 47,
  kLstmCell = 48,
  kMatmul = 49,
  kMax = 50,
  kMaxPool2d = 51,
  kMin = 52,
  kMul = 53,
  kNeg = 54,
  kPad = 55,
  kPow = 56,
  kPrelu = 57,
  kQuantizeLinear = 58,
  kReciprocal = 59,
  kReduceL1 = 60,
  kReduceL2 = 61,
  kReduceLogSum = 62,
  kReduceLogSumExp = 63,
  kReduceMax = 64,
  kReduceMean = 65,
  kReduceMin = 66,
  kReduceProduct = 67,
  kReduceSum = 68,
  kReduceSumSquare = 69,
  kRelu = 70,
  kResample2d = 71,
  kReshape = 72,
  kScatterElements = 73,
  kScatterNd = 74,
  kSigmoid = 75,
  kSign = 76,
  kSin = 77,
  kSlice = 78,
  kSoftmax = 79,
  kSoftplus = 80,
  kSoftsign = 81,
  kSplit = 82,
  kSqrt = 83,
  kSub = 84,
  kTan = 85,
  kTanh = 86,
  kTile = 87,
  kTranspose = 88,
  kTriangular = 89,
  kWhere = 90,
  kReverse = 91,
  kMinValue = kGraphBuilt,
  kMaxValue = kReverse,
};

using MLGraphOperatorUmaSet = base::EnumSet<MLGraphOperatorUma,
                                            MLGraphOperatorUma::kMinValue,
                                            MLGraphOperatorUma::kMaxValue>;

MLGraphOperatorUma GetUmaValueForOperation(
    const blink_mojom::Operation& operation) {
  switch (operation.which()) {
    case blink_mojom::Operation::Tag::kArgMinMax: {
      switch (operation.get_arg_min_max()->kind) {
        case blink_mojom::ArgMinMax::Kind::kMax:
          return MLGraphOperatorUma::kArgMax;
        case blink_mojom::ArgMinMax::Kind::kMin:
          return MLGraphOperatorUma::kArgMin;
      }
      break;
    }
    case blink_mojom::Operation::Tag::kBatchNormalization:
      return MLGraphOperatorUma::kBatchNormalization;
    case blink_mojom::Operation::Tag::kClamp:
      return MLGraphOperatorUma::kClamp;
    case blink_mojom::Operation::Tag::kConv2d:
      return MLGraphOperatorUma::kConv2d;
    case blink_mojom::Operation::Tag::kConcat:
      return MLGraphOperatorUma::kConcat;
    case blink_mojom::Operation::Tag::kCumulativeSum:
      return MLGraphOperatorUma::kCumulativeSum;
    case blink_mojom::Operation::Tag::kDequantizeLinear:
      return MLGraphOperatorUma::kDequantizeLinear;
    case blink_mojom::Operation::Tag::kElementWiseBinary: {
      switch (operation.get_element_wise_binary()->kind) {
        case blink_mojom::ElementWiseBinary::Kind::kAdd:
          return MLGraphOperatorUma::kAdd;
        case blink_mojom::ElementWiseBinary::Kind::kSub:
          return MLGraphOperatorUma::kSub;
        case blink_mojom::ElementWiseBinary::Kind::kMul:
          return MLGraphOperatorUma::kMul;
        case blink_mojom::ElementWiseBinary::Kind::kDiv:
          return MLGraphOperatorUma::kDiv;
        case blink_mojom::ElementWiseBinary::Kind::kMax:
          return MLGraphOperatorUma::kMax;
        case blink_mojom::ElementWiseBinary::Kind::kMin:
          return MLGraphOperatorUma::kMin;
        case blink_mojom::ElementWiseBinary::Kind::kPow:
          return MLGraphOperatorUma::kPow;
        case blink_mojom::ElementWiseBinary::Kind::kEqual:
          return MLGraphOperatorUma::kEqual;
        case blink_mojom::ElementWiseBinary::Kind::kGreater:
          return MLGraphOperatorUma::kGreater;
        case blink_mojom::ElementWiseBinary::Kind::kGreaterOrEqual:
          return MLGraphOperatorUma::kGreaterOrEqual;
        case blink_mojom::ElementWiseBinary::Kind::kLesser:
          return MLGraphOperatorUma::kLesser;
        case blink_mojom::ElementWiseBinary::Kind::kLesserOrEqual:
          return MLGraphOperatorUma::kLesserOrEqual;
        case blink_mojom::ElementWiseBinary::Kind::kLogicalAnd:
          return MLGraphOperatorUma::kLogicalAnd;
        case blink_mojom::ElementWiseBinary::Kind::kLogicalOr:
          return MLGraphOperatorUma::kLogicalOr;
        case blink_mojom::ElementWiseBinary::Kind::kLogicalXor:
          return MLGraphOperatorUma::kLogicalXor;
      }
      break;
    }
    case blink_mojom::Operation::Tag::kElementWiseUnary: {
      switch (operation.get_element_wise_unary()->kind) {
        case blink_mojom::ElementWiseUnary::Kind::kAbs:
          return MLGraphOperatorUma::kAbs;
        case blink_mojom::ElementWiseUnary::Kind::kCast:
          return MLGraphOperatorUma::kCast;
        case blink_mojom::ElementWiseUnary::Kind::kCeil:
          return MLGraphOperatorUma::kCeil;
        case blink_mojom::ElementWiseUnary::Kind::kCos:
          return MLGraphOperatorUma::kCos;
        case blink_mojom::ElementWiseUnary::Kind::kExp:
          return MLGraphOperatorUma::kExp;
        case blink_mojom::ElementWiseUnary::Kind::kFloor:
          return MLGraphOperatorUma::kFloor;
        case blink_mojom::ElementWiseUnary::Kind::kIdentity:
          return MLGraphOperatorUma::kIdentity;
        case blink_mojom::ElementWiseUnary::Kind::kLog:
          return MLGraphOperatorUma::kLog;
        case blink_mojom::ElementWiseUnary::Kind::kLogicalNot:
          return MLGraphOperatorUma::kLogicalNot;
        case blink_mojom::ElementWiseUnary::Kind::kNeg:
          return MLGraphOperatorUma::kNeg;
        case blink_mojom::ElementWiseUnary::Kind::kReciprocal:
          return MLGraphOperatorUma::kReciprocal;
        case blink_mojom::ElementWiseUnary::Kind::kSign:
          return MLGraphOperatorUma::kSign;
        case blink_mojom::ElementWiseUnary::Kind::kSin:
          return MLGraphOperatorUma::kSin;
        case blink_mojom::ElementWiseUnary::Kind::kSqrt:
          return MLGraphOperatorUma::kSqrt;
        case blink_mojom::ElementWiseUnary::Kind::kTan:
          return MLGraphOperatorUma::kTan;
        case blink_mojom::ElementWiseUnary::Kind::kErf:
          return MLGraphOperatorUma::kErf;
      }
      break;
    }
    case blink_mojom::Operation::Tag::kElu:
      return MLGraphOperatorUma::kElu;
    case blink_mojom::Operation::Tag::kExpand:
      return MLGraphOperatorUma::kExpand;
    case blink_mojom::Operation::Tag::kGather:
      return MLGraphOperatorUma::kGather;
    case blink_mojom::Operation::Tag::kGatherElements:
      return MLGraphOperatorUma::kGatherElements;
    case blink_mojom::Operation::Tag::kGatherNd:
      return MLGraphOperatorUma::kGatherNd;
    case blink_mojom::Operation::Tag::kGelu:
      return MLGraphOperatorUma::kGelu;
    case blink_mojom::Operation::Tag::kGemm:
      return MLGraphOperatorUma::kGemm;
    case blink_mojom::Operation::Tag::kGru:
      return MLGraphOperatorUma::kGru;
    case blink_mojom::Operation::Tag::kGruCell:
      return MLGraphOperatorUma::kGruCell;
    case blink_mojom::Operation::Tag::kHardSigmoid:
      return MLGraphOperatorUma::kHardSigmoid;
    case blink_mojom::Operation::Tag::kHardSwish:
      return MLGraphOperatorUma::kHardSwish;
    case blink_mojom::Operation::Tag::kInstanceNormalization:
      return MLGraphOperatorUma::kInstanceNormalization;
    case blink_mojom::Operation::Tag::kLayerNormalization:
      return MLGraphOperatorUma::kLayerNormalization;
    case blink_mojom::Operation::Tag::kLeakyRelu:
      return MLGraphOperatorUma::kLeakyRelu;
    case blink_mojom::Operation::Tag::kLinear:
      return MLGraphOperatorUma::kLinear;
    case blink_mojom::Operation::Tag::kLstmCell:
      return MLGraphOperatorUma::kLstmCell;
    case blink_mojom::Operation::Tag::kLstm:
      return MLGraphOperatorUma::kLstm;
    case blink_mojom::Operation::Tag::kMatmul:
      return MLGraphOperatorUma::kMatmul;
    case blink_mojom::Operation::Tag::kPad:
      return MLGraphOperatorUma::kPad;
    case blink_mojom::Operation::Tag::kPool2d: {
      switch (operation.get_pool2d()->kind) {
        case blink_mojom::Pool2d::Kind::kAveragePool2d:
          return MLGraphOperatorUma::kAveragePool2d;
        case blink_mojom::Pool2d::Kind::kMaxPool2d:
          return MLGraphOperatorUma::kMaxPool2d;
        case blink_mojom::Pool2d::Kind::kL2Pool2d:
          return MLGraphOperatorUma::kL2Pool2d;
      }
      break;
    }
    case blink_mojom::Operation::Tag::kPrelu:
      return MLGraphOperatorUma::kPrelu;
    case blink_mojom::Operation::Tag::kQuantizeLinear:
      return MLGraphOperatorUma::kQuantizeLinear;
    case blink_mojom::Operation::Tag::kReduce: {
      switch (operation.get_reduce()->kind) {
        case blink_mojom::Reduce::Kind::kL1:
          return MLGraphOperatorUma::kReduceL1;
        case blink_mojom::Reduce::Kind::kL2:
          return MLGraphOperatorUma::kReduceL2;
        case blink_mojom::Reduce::Kind::kLogSum:
          return MLGraphOperatorUma::kReduceLogSum;
        case blink_mojom::Reduce::Kind::kLogSumExp:
          return MLGraphOperatorUma::kReduceLogSumExp;
        case blink_mojom::Reduce::Kind::kMax:
          return MLGraphOperatorUma::kReduceMax;
        case blink_mojom::Reduce::Kind::kMean:
          return MLGraphOperatorUma::kReduceMean;
        case blink_mojom::Reduce::Kind::kMin:
          return MLGraphOperatorUma::kReduceMin;
        case blink_mojom::Reduce::Kind::kProduct:
          return MLGraphOperatorUma::kReduceProduct;
        case blink_mojom::Reduce::Kind::kSum:
          return MLGraphOperatorUma::kReduceSum;
        case blink_mojom::Reduce::Kind::kSumSquare:
          return MLGraphOperatorUma::kReduceSumSquare;
      }
      break;
    }
    case blink_mojom::Operation::Tag::kRelu:
      return MLGraphOperatorUma::kRelu;
    case blink_mojom::Operation::Tag::kResample2d:
      return MLGraphOperatorUma::kResample2d;
    case blink_mojom::Operation::Tag::kReshape:
      return MLGraphOperatorUma::kReshape;
    case blink_mojom::Operation::Tag::kReverse:
      return MLGraphOperatorUma::kReverse;
    case blink_mojom::Operation::Tag::kScatterElements:
      return MLGraphOperatorUma::kScatterElements;
    case blink_mojom::Operation::Tag::kScatterNd:
      return MLGraphOperatorUma::kScatterNd;
    case blink_mojom::Operation::Tag::kSigmoid:
      return MLGraphOperatorUma::kSigmoid;
    case blink_mojom::Operation::Tag::kSlice:
      return MLGraphOperatorUma::kSlice;
    case blink_mojom::Operation::Tag::kSoftmax:
      return MLGraphOperatorUma::kSoftmax;
    case blink_mojom::Operation::Tag::kSoftplus:
      return MLGraphOperatorUma::kSoftplus;
    case blink_mojom::Operation::Tag::kSoftsign:
      return MLGraphOperatorUma::kSoftsign;
    case blink_mojom::Operation::Tag::kSplit:
      return MLGraphOperatorUma::kSplit;
    case blink_mojom::Operation::Tag::kTanh:
      return MLGraphOperatorUma::kTanh;
    case blink_mojom::Operation::Tag::kTile:
      return MLGraphOperatorUma::kTile;
    case blink_mojom::Operation::Tag::kTranspose:
      return MLGraphOperatorUma::kTranspose;
    case blink_mojom::Operation::Tag::kTriangular:
      return MLGraphOperatorUma::kTriangular;
    case blink_mojom::Operation::Tag::kWhere:
      return MLGraphOperatorUma::kWhere;
  }
}

void RecordOperatorsUsed(const blink_mojom::GraphInfo& graph_info) {
  static const std::string_view kOperatorHistogram = "WebNN.Operator";

  // Record once per graph that it has been built. This will give us a count
  // for the total number of built graphs, which will be used to
  // calculate what percentage of graphs use a given operator.
  UMA_HISTOGRAM_ENUMERATION(kOperatorHistogram,
                            MLGraphOperatorUma::kGraphBuilt);

  MLGraphOperatorUmaSet operators_used;
  for (const auto& operation : graph_info.operations) {
    MLGraphOperatorUma uma_value = GetUmaValueForOperation(*operation);
    // For a given operator, record that it has been used only once.
    if (!operators_used.Has(uma_value)) {
      UMA_HISTOGRAM_ENUMERATION(kOperatorHistogram, uma_value);
      operators_used.Put(uma_value);
    }
  }
}

#define THROW_AND_RETURN_TYPE_IF_ERROR(func, return_value) \
  RETURN_IF_ERROR(func, [&exception_state](String error) { \
    exception_state.ThrowTypeError(error);                 \
    return return_value;                                   \
  });

#define THROW_AND_RETURN_IF_ERROR(func, return_value)                       \
  RETURN_IF_ERROR(func, [&exception_state](String error) {                  \
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, \
                                      error);                               \
    return return_value;                                                    \
  });

#define ASSIGN_OR_THROW_AND_RETURN_IF_ERROR(lhs, rexpr)                \
  ASSIGN_OR_RETURN(lhs, rexpr, [&exception_state](std::string error) { \
    exception_state.ThrowTypeError(String::FromUTF8(error));           \
    return nullptr;                                                    \
  });

constexpr char kGraphAlreadyBuiltError[] =
    "This MLGraphBuilder has already built a graph.";

webnn::InputOperandLayout BlinkInputOperandLayoutToComponent(
    blink::V8MLInputOperandLayout::Enum type) {
  switch (type) {
    case blink::V8MLInputOperandLayout::Enum::kNchw:
      return webnn::InputOperandLayout::kNchw;
    case blink::V8MLInputOperandLayout::Enum::kNhwc:
      return webnn::InputOperandLayout::kNhwc;
  }
}

webnn::Conv2dFilterOperandLayout BlinkConv2dFilterLayoutToComponent(
    blink::V8MLConv2dFilterOperandLayout::Enum type) {
  switch (type) {
    case blink::V8MLConv2dFilterOperandLayout::Enum::kOihw:
      return webnn::Conv2dFilterOperandLayout::kOihw;
    case blink::V8MLConv2dFilterOperandLayout::Enum::kHwio:
      return webnn::Conv2dFilterOperandLayout::kHwio;
    case blink::V8MLConv2dFilterOperandLayout::Enum::kOhwi:
      return webnn::Conv2dFilterOperandLayout::kOhwi;
    case blink::V8MLConv2dFilterOperandLayout::Enum::kIhwo:
      return webnn::Conv2dFilterOperandLayout::kIhwo;
  }
}

webnn::ConvTranspose2dFilterOperandLayout
BlinkConvTranspose2dFilterLayoutToComponent(
    blink::V8MLConvTranspose2dFilterOperandLayout::Enum type) {
  switch (type) {
    case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kIohw:
      return webnn::ConvTranspose2dFilterOperandLayout::kIohw;
    case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kHwoi:
      return webnn::ConvTranspose2dFilterOperandLayout::kHwoi;
    case blink::V8MLConvTranspose2dFilterOperandLayout::Enum::kOhwi:
      return webnn::ConvTranspose2dFilterOperandLayout::kOhwi;
  }
}

webnn::RoundingType BlinkRoundingTypeToComponent(
    blink::V8MLRoundingType::Enum type) {
  switch (type) {
    case blink::V8MLRoundingType::Enum::kFloor:
      return webnn::RoundingType::kFloor;
    case blink::V8MLRoundingType::Enum::kCeil:
      return webnn::RoundingType::kCeil;
  }
}

webnn::Pool2dKind FromMojoPool2dKind(blink_mojom::Pool2d::Kind kind) {
  switch (kind) {
    case blink_mojom::Pool2d::Kind::kAveragePool2d:
      return webnn::Pool2dKind::kAverage;
    case blink_mojom::Pool2d::Kind::kL2Pool2d:
      return webnn::Pool2dKind::kL2;
    case blink_mojom::Pool2d::Kind::kMaxPool2d:
      return webnn::Pool2dKind::kMax;
  }
}

webnn::ReduceKind MojoReduceKindToComponent(blink_mojom::Reduce::Kind kind) {
  switch (kind) {
    case blink_mojom::Reduce::Kind::kL1:
      return webnn::ReduceKind::kL1;
    case blink_mojom::Reduce::Kind::kL2:
      return webnn::ReduceKind::kL2;
    case blink_mojom::Reduce::Kind::kLogSum:
      return webnn::ReduceKind::kLogSum;
    case blink_mojom::Reduce::Kind::kLogSumExp:
      return webnn::ReduceKind::kLogSumExp;
    case blink_mojom::Reduce::Kind::kMax:
      return webnn::ReduceKind::kMax;
    case blink_mojom::Reduce::Kind::kMean:
      return webnn::ReduceKind::kMean;
    case blink_mojom::Reduce::Kind::kMin:
      return webnn::ReduceKind::kMin;
    case blink_mojom::Reduce::Kind::kProduct:
      return webnn::ReduceKind::kProduct;
    case blink_mojom::Reduce::Kind::kSum:
      return webnn::ReduceKind::kSum;
    case blink_mojom::Reduce::Kind::kSumSquare:
      return webnn::ReduceKind::kSumSquare;
  }
}

webnn::RecurrentNetworkDirection BlinkRecurrentNetworkDirectionToComponent(
    blink::V8MLRecurrentNetworkDirection::Enum direction) {
  switch (direction) {
    case blink::V8MLRecurrentNetworkDirection::Enum::kForward:
      return webnn::RecurrentNetworkDirection::kForward;
    case blink::V8MLRecurrentNetworkDirection::Enum::kBackward:
      return webnn::RecurrentNetworkDirection::kBackward;
    case blink::V8MLRecurrentNetworkDirection::Enum::kBoth:
      return webnn::RecurrentNetworkDirection::kBoth;
  }
}

webnn::BatchNormalizationAttributes ConvertToBatchNormalizationAttributes(
    const blink::MLBatchNormalizationOptions* options) {
  CHECK(options);
  webnn::BatchNormalizationAttributes attributes;
  if (options->hasScale()) {
    attributes.scale = options->scale()->Descriptor();
  }
  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  attributes.label = options->label().Utf8();
  attributes.axis = options->axis();
  return attributes;
}

template <typename MLConv2dOptionsType, typename Conv2dAttributesType>
base::expected<Conv2dAttributesType, String> ConvertToConv2dAttributesBase(
    const MLConv2dOptionsType* options) {
  Conv2dAttributesType attributes;
  CHECK(options);
  const std::string label = options->label().Utf8();
  // If padding is not present, the values are assumed to be [0,0,0,0].
  auto padding = options->getPaddingOr({0, 0, 0, 0});
  if (padding.size() != 4) {
    return base::unexpected(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The length of padding should be 4.");
  }
  // The order of padding array is [beginning_height, ending_height,
  // beginning_width, ending_width].
  attributes.padding = webnn::Padding2d{
      .beginning =
          webnn::Size2d<uint32_t>{.height = padding[0], .width = padding[2]},
      .ending =
          webnn::Size2d<uint32_t>{.height = padding[1], .width = padding[3]}};

  // If strides is not present, the values are assumed to be [1,1].
  auto strides = options->getStridesOr({1, 1});
  if (strides.size() != 2) {
    return base::unexpected(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The length of strides should be 2.");
  }
  attributes.strides =
      webnn::Size2d<uint32_t>{.height = strides[0], .width = strides[1]};

  // If dilations is not present, the values are assumed to be [1,1].
  auto dilations = options->getDilationsOr({1, 1});
  if (dilations.size() != 2) {
    return base::unexpected(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        +"The length of dilations should be 2.");
  }
  attributes.dilations =
      webnn::Size2d<uint32_t>{.height = dilations[0], .width = dilations[1]};
  attributes.groups = options->groups();
  attributes.input_layout =
      BlinkInputOperandLayoutToComponent(options->inputLayout().AsEnum());
  if (options->hasBias()) {
    attributes.bias_operand = options->bias()->Descriptor();
  }
  attributes.label = label;

  return std::move(attributes);
}

base::expected<webnn::Conv2dAttributes, String> ConvertToConv2dAttributes(
    const blink::MLConv2dOptions* options) {
  auto attributes =
      ConvertToConv2dAttributesBase<blink::MLConv2dOptions,
                                    webnn::Conv2dAttributes>(options);
  if (!attributes.has_value()) {
    return base::unexpected(attributes.error());
  }
  attributes.value().filter_layout =
      BlinkConv2dFilterLayoutToComponent(options->filterLayout().AsEnum());

  return attributes;
}

base::expected<webnn::ConvTranspose2dAttributes, String>
ConvertToConvTranspose2dAttributes(
    const blink::MLConvTranspose2dOptions* options) {
  auto attributes =
      ConvertToConv2dAttributesBase<blink::MLConvTranspose2dOptions,
                                    webnn::ConvTranspose2dAttributes>(options);
  if (!attributes.has_value()) {
    return base::unexpected(attributes.error());
  }

  const std::string& label = attributes.value().label;
  // If output padding is not present, the values are assumed to be [0,0].
  const auto output_padding = options->getOutputPaddingOr({0, 0});
  if (output_padding.size() != 2) {
    return base::unexpected(
        String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
        "The length of output padding should be 2.");
  }
  attributes.value().output_padding = webnn::Size2d<uint32_t>{
      .height = output_padding[0], .width = output_padding[1]};

  if (options->hasOutputSizes()) {
    auto output_sizes = options->getOutputSizesOr({});
    if (output_sizes.size() != 2) {
      return base::unexpected(
          String::FromUTF8(webnn::GetErrorLabelPrefix(label)) +
          "The length of output sizes should be 2.");
    }
    attributes.value().output_sizes = webnn::Size2d<uint32_t>{
        .height = output_sizes[0], .width = output_sizes[1]};
  }

  attributes.value().filter_layout =
      BlinkConvTranspose2dFilterLayoutToComponent(
          options->filterLayout().AsEnum());

  return attributes;
}

base::expected<webnn::Pool2dAttributes, std::string> ConvertToPool2dAttributes(
    const blink::MLPool2dOptions* options) {
  CHECK(options);
  const std::string label = options->label().Utf8();
  webnn::Pool2dAttributes attributes;
  if (options->hasWindowDimensions()) {
    auto& window_dimensions = options->windowDimensions();
    if (window_dimensions.size() != 2) {
      return base::unexpected(webnn::GetErrorLabelPrefix(label) +
                              "The length of window dimensions should be 2.");
    }
    attributes.window_dimensions = webnn::Size2d<uint32_t>{
        .height = window_dimensions[0], .width = window_dimensions[1]};
  }

  // If padding is not present, the values are assumed to be [0,0,0,0].
  auto padding = options->getPaddingOr({0, 0, 0, 0});
  if (padding.size() != 4) {
    return base::unexpected(webnn::GetErrorLabelPrefix(label) +
                            "The length of padding should be 4.");
  }
  attributes.padding = webnn::Padding2d{
      .beginning =
          webnn::Size2d<uint32_t>{.height = padding[0], .width = padding[2]},
      .ending =
          webnn::Size2d<uint32_t>{.height = padding[1], .width = padding[3]}};

  // If strides is not present, the values are assumed to be [1,1].
  auto strides = options->getStridesOr({1, 1});
  if (strides.size() != 2) {
    return base::unexpected(webnn::GetErrorLabelPrefix(label) +
                            "The length of strides should be 2.");
  }
  attributes.strides =
      webnn::Size2d<uint32_t>{.height = strides[0], .width = strides[1]};

  // If dilations is not present, the values are assumed to be [1,1].
  auto dilations = options->getDilationsOr({1, 1});
  if (dilations.size() != 2) {
    return base::unexpected(webnn::GetErrorLabelPrefix(label) +
                            "The length of dilations should be 2.");
  }
  attributes.dilations =
      webnn::Size2d<uint32_t>{.height = dilations[0], .width = dilations[1]};
  attributes.layout =
      BlinkInputOperandLayoutToComponent(options->layout().AsEnum());
  attributes.rounding_type =
      BlinkRoundingTypeToComponent(options->roundingType().AsEnum());
  if (options->hasOutputSizes()) {
    // TODO(ningxin.hu@intel.com): report a DevTools warning message if rounding
    // type is provided but ignored.
    auto& output_size = options->outputSizes();
    if (output_size.size() != 2) {
      return base::unexpected(webnn::GetErrorLabelPrefix(label) +
                              "The length of output sizes should be 2.");
    }
    attributes.output_sizes = webnn::Size2d<uint32_t>{.height = output_size[0],
                                                      .width = output_size[1]};
  }
  attributes.label = label;
  return attributes;
}

webnn::GemmAttributes ConvertToGemmAttributes(
    const blink::MLGemmOptions* options) {
  CHECK(options);
  webnn::GemmAttributes attributes;
  if (options->hasC()) {
    attributes.c_operand = options->c()->Descriptor();
  }
  attributes.alpha = options->alpha();
  attributes.beta = options->beta();
  attributes.a_transpose = options->aTranspose();
  attributes.b_transpose = options->bTranspose();
  attributes.label = options->label().Utf8();
  return attributes;
}

webnn::GruAttributes ConvertToGruAttributes(MLGraphBuilder* builder,
                                            blink::MLGruOptions* options) {
  CHECK(options);
  webnn::GruAttributes attributes;

  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  if (options->hasRecurrentBias()) {
    attributes.recurrent_bias = options->recurrentBias()->Descriptor();
  }
  if (options->hasInitialHiddenState()) {
    attributes.initial_hidden_state =
        options->initialHiddenState()->Descriptor();
  }
  attributes.return_sequence = options->returnSequence();
  attributes.direction =
      BlinkRecurrentNetworkDirectionToComponent(options->direction().AsEnum());
  if (!options->hasActivations()) {
    // Create a default activation sequence as defined in the spec.
    options->setActivations(
        {V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kSigmoid),
         V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kTanh)});
  }
  attributes.activation_count = options->activations().size();
  attributes.label = options->label().Utf8();
  return attributes;
}

webnn::GruCellAttributes ConvertToGruCellAttributes(
    MLGraphBuilder* builder,
    blink::MLGruCellOptions* options) {
  CHECK(options);
  webnn::GruCellAttributes attributes;

  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  if (options->hasRecurrentBias()) {
    attributes.recurrent_bias = options->recurrentBias()->Descriptor();
  }
  if (!options->hasActivations()) {
    // Create a default activation sequence as defined in the spec.
    options->setActivations(
        {V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kSigmoid),
         V8MLRecurrentNetworkActivation(
             V8MLRecurrentNetworkActivation::Enum::kTanh)});
  }
  attributes.activation_count = options->activations().size();
  attributes.label = options->label().Utf8();
  return attributes;
}

webnn::InstanceNormalizationAttributes ConvertToInstanceNormalizationAttributes(
    const blink::MLInstanceNormalizationOptions* options) {
  CHECK(options);
  webnn::InstanceNormalizationAttributes attributes;
  if (options->hasScale()) {
    attributes.scale = options->scale()->Descriptor();
  }
  if (options->hasBias()) {
    attributes.bias = options->bias()->Descriptor();
  }
  attributes.layout =
      BlinkInputOperandLayoutToComponent(options->layout().AsEnum());
  attributes.label = options->label().Utf8();
  return attributes;
}

webnn::LayerNormalizationAttributes ConvertToLayerNormalizationAttributes(
    const blink::MLLayerNormalizationOptions* options) {
  CHECK(options);
  webnn::LayerNormalizationAttributes attributes;
  if (options->hasScale()) {
    attributes.scale = options->scale()->Descriptor();
  }
```