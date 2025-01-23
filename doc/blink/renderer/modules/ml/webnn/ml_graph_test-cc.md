Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a test file for the WebNN API in the Chromium Blink engine.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Core Purpose:** The file name `ml_graph_test.cc` and the `#include "third_party/blink/renderer/modules/ml/webnn/ml_graph.h"` strongly suggest this file contains unit tests for the `MLGraph` class within the WebNN (Web Neural Network) API.

2. **Analyze Includes:** Examine the included headers to understand the dependencies and related functionalities. Key includes include:
    * `ml_graph.h`: The header for the class being tested.
    * `gtest/gtest.h`:  Indicates this is a Google Test based unit test file.
    * `mojo/...`:  Indicates the usage of Mojo for inter-process communication, which is crucial for WebNN's implementation in Chromium.
    * `services/webnn/public/mojom/...`:  Signifies interaction with the WebNN service via Mojo interfaces.
    * `third_party/blink/renderer/bindings/core/v8/...` and `third_party/blink/renderer/bindings/modules/v8/...`:  Show interaction with JavaScript (V8 engine) and the WebNN JavaScript API.
    * `third_party/blink/renderer/modules/ml/...`:  Indicates the context within the broader Machine Learning module.

3. **Look for Key Test Structures:** Identify the main test fixture. The `class MLGraphTest : public testing::Test` declaration confirms this is a standard Google Test setup.

4. **Examine Helper Structures and Functions:** The code defines several helper structs and classes like `BuildResult`, `ComputeResult`, `OperandInfo`, `FakeWebNNGraph`, `FakeWebNNTensor`, `FakeWebNNGraphBuilder`, `FakeWebNNContext`, and `FakeWebNNContextProvider`. These suggest the test file uses mocking or faking to simulate the behavior of the actual WebNN service and related components. This is common in unit testing to isolate the code under test.

5. **Analyze the `BuildGraph` Function:** This function is critical. It demonstrates how a WebNN graph is built within the test environment. It takes an `MLGraphBuilder` and named operands as input and attempts to build the graph. The use of `ScriptPromise` indicates asynchronous operations, aligning with the nature of WebNN's API. The error handling logic within `BuildResult` is also important.

6. **Identify Test-Specific Infrastructure:**  The `ScopedWebNNServiceBinder` class suggests a mechanism for setting up and tearing down the mock WebNN service environment during tests.

7. **Connect to Web Standards (JavaScript, HTML, CSS):**  The includes related to V8 bindings directly link this code to JavaScript. The WebNN API is designed to be used from JavaScript within web pages. While this specific *test* file doesn't directly manipulate HTML or CSS, the tested *functionality* (WebNN) is accessed through JavaScript in a web browser context.

8. **Infer Functionality from Test Helpers:** The helper functions like `CreateContext`, `BuildConstant`, `BuildConv2d`, `BuildGemm`, and `BuildElementWiseBinary` reveal that the tests cover the creation and building of various WebNN graph components and operators.

9. **Consider User Errors:** The `BuildResult` structure and the error handling within the `BuildGraph` function indicate that the tests are designed to catch errors during graph construction, which are potential user errors in how they define their WebNN models.

10. **Trace User Operations (Debugging Clues):** The setup with mock services suggests that debugging a real WebNN implementation might involve looking at the communication between the renderer process (where this code runs) and the WebNN service process. The test structure simulates the steps a web page would take to create a context, build a graph, and potentially execute it (though the execution part isn't fully shown in this snippet).

11. **Focus on the "Part 1" Request:** The request explicitly asks for a summary of the *current* code snippet's functionality. Avoid going too deep into the details that might be covered in subsequent parts of the file.

By following these steps, we can arrive at the summarized functionality provided in the initial good answer. The key is to understand the context (unit testing for WebNN), the main components involved (MLGraph, MLGraphBuilder, Mojo), and how the test infrastructure simulates the real WebNN environment.
好的，根据您提供的代码片段，`blink/renderer/modules/ml/webnn/ml_graph_test.cc` 文件的第 1 部分主要包含以下功能：

**核心功能：**

* **提供 WebNN `MLGraph` 类的单元测试基础结构:**  这是个测试文件，用于验证 `MLGraph` 类的功能是否正常。它使用了 Google Test 框架 (`testing/gmock/include/gmock/gmock.h` 和 `testing/gtest/include/gtest/gtest.h`)。
* **模拟 WebNN 服务交互:**  为了在测试环境中独立测试 `MLGraph` 的行为，该文件创建了一系列模拟（fake）的 WebNN 服务组件，例如 `FakeWebNNGraph`, `FakeWebNNTensor`, `FakeWebNNGraphBuilder`, `FakeWebNNContext`, 和 `FakeWebNNContextProvider`。这些模拟组件替代了实际的 WebNN 服务实现，允许测试在没有完整服务环境的情况下运行。
* **提供构建和执行 WebNN 图的辅助函数:**  例如 `BuildGraph` 函数，它用于简化在测试中创建和构建 `MLGraph` 的过程。还有用于创建各种 WebNN 操作 (例如 `BuildConv2d`, `BuildGemm`, `BuildElementWiseBinary`) 和常量的辅助函数。
* **处理异步操作:**  使用了 `ScriptPromise` 和 `ScriptPromiseTester` 来处理 WebNN API 中常见的异步操作，例如图的构建。
* **处理错误情况:**  `BuildResult` 结构体用于存储图构建的结果，包括可能的错误信息（名称和消息）。
* **支持不同的数据类型和操作选项:**  代码中包含了对各种 `MLOperandDataType` 和操作选项类的引用和使用，表明测试覆盖了 WebNN API 的多种特性。
* **管理 Mojo 接口:**  代码中大量使用了 Mojo 相关的类，例如 `mojo::PendingAssociatedReceiver`, `mojo::MakeSelfOwnedAssociatedReceiver` 等，表明该测试文件需要处理与 WebNN 服务的进程间通信。

**与 JavaScript, HTML, CSS 的关系 (通过 WebNN API):**

虽然这个 C++ 文件本身不直接涉及 HTML 或 CSS，但它测试的 `MLGraph` 类是 WebNN API 的一部分，而 WebNN API 是一个 **JavaScript API**，允许网页开发者在浏览器中利用硬件加速进行机器学习推断。

* **JavaScript:**  该测试文件通过模拟 WebNN 服务的方式，间接地测试了 JavaScript 如何与 WebNN API 进行交互。 例如，`BuildGraph` 函数模拟了 JavaScript 调用 `MLGraphBuilder.build()` 方法的过程。测试中使用的各种 `V8ML...` 类型的类 (例如 `V8MLOperandDataType`, `V8MLConv2dOptions`) 是 WebNN JavaScript API 中对应类型的 C++ 表示。
    * **举例:** 当 JavaScript 代码调用 `navigator.ml.createContext()` 创建一个 MLContext 时，Blink 引擎会通过 Mojo 与 WebNN 服务进行通信。该测试文件中的 `FakeWebNNContextProvider` 和 `FakeWebNNContext` 就模拟了 WebNN 服务接收和处理这个 JavaScript 请求的过程。
    * **举例:**  JavaScript 使用 `MLGraphBuilder` 来定义计算图，例如添加卷积层 (`builder.conv2d()`)。测试文件中的 `BuildConv2d` 函数就模拟了这种 JavaScript API 调用，并验证了内部 C++ 逻辑的正确性。

* **HTML:**  HTML 文件可以通过 `<script>` 标签引入 JavaScript 代码，从而使用 WebNN API。测试文件间接验证了当 HTML 中嵌入的 JavaScript 代码使用 WebNN 功能时，底层的 C++ 实现是否按预期工作。

* **CSS:**  CSS 本身与 WebNN API 没有直接的功能关系。

**逻辑推理的假设输入与输出 (以 `BuildConv2d` 为例):**

* **假设输入:**
    * `input`: 一个 `MLOperand` 对象，表示卷积运算的输入张量，例如形状为 `{1, 3, 32, 32}` (batch, channels, height, width)，数据类型为 `float32`。
    * `filter`: 一个 `MLOperand` 对象，表示卷积核，例如形状为 `{6, 3, 5, 5}` (output channels, input channels, kernel height, kernel width)，数据类型为 `float32`。
    * `options`: 一个 `MLConv2dOptions` 对象，包含卷积的步幅、填充等参数，例如 `{ strides: [1, 1], padding: [2, 2, 2, 2] }`。

* **预期输出:**
    * 一个新的 `MLOperand` 对象，表示卷积运算的输出张量。其形状将根据输入、滤波器和选项进行计算，例如 `{1, 6, 32, 32}`，数据类型与输入相同 (`float32`)。
    * 内部会创建一个 `webnn::mojom::blink::Operation::Tag::kConv2d` 类型的操作对象。

**用户或编程常见的使用错误举例:**

* **数据类型不匹配:** 用户在 JavaScript 中尝试构建一个图，其中某个操作的输入操作数的数据类型不兼容。例如，尝试将一个 `uint8` 类型的张量和一个 `float32` 类型的张量相加，而 WebNN 服务不支持这种操作。该测试文件可能会包含测试用例来验证这种情况是否会抛出正确的错误。
* **张量形状不兼容:** 用户提供的输入张量形状与操作的要求不符。例如，一个矩阵乘法操作的两个输入矩阵的维度不满足乘法规则。
* **操作选项参数错误:** 用户为某个操作提供了无效的选项参数。例如，卷积的步幅设置为负数。
* **尝试在未构建的图上进行计算:** 用户在 JavaScript 中尝试在一个尚未调用 `build()` 方法构建完成的 `MLGraphBuilder` 上进行操作。

**用户操作到达这里的调试线索:**

1. **网页开发者使用 WebNN API:** 开发者编写 JavaScript 代码，使用 `navigator.ml` API 来创建 `MLContext` 和 `MLGraphBuilder` 对象。
2. **构建计算图:** 开发者使用 `MLGraphBuilder` 的方法（例如 `conv2d`, `add`, `matmul` 等）来定义神经网络的计算图。
3. **调用 `build()` 方法:** 开发者在 `MLGraphBuilder` 对象上调用 `build()` 方法来创建 `MLGraph` 对象。
4. **Blink 引擎内部处理:**  当 JavaScript 调用 `build()` 时，Blink 引擎会将图的定义转换为内部表示，并通过 Mojo 接口与 WebNN 服务进行通信，请求构建实际的计算图。
5. **WebNN 服务处理:** WebNN 服务接收到构建请求后，会进行图的优化和编译。
6. **测试覆盖的范围:** `ml_graph_test.cc` 文件中的测试用例模拟了从步骤 2 到步骤 5 的过程，验证了 Blink 引擎在处理 `build()` 调用以及与 WebNN 服务交互时的正确性。如果开发者在使用 WebNN API 时遇到问题，例如图构建失败，那么开发者或者 Chromium 的工程师可能会需要查看这个测试文件以及相关的 WebNN 服务代码，以找出问题的根源。

**归纳一下它的功能 (第 1 部分):**

`blink/renderer/modules/ml/webnn/ml_graph_test.cc` 的第 1 部分主要功能是 **构建一个用于测试 WebNN `MLGraph` 类的基础测试环境和工具集**。这包括：

* **设置测试框架:** 使用 Google Test。
* **模拟 WebNN 服务:**  创建假的 WebNN 服务组件以隔离测试。
* **提供便捷的图构建工具:**  定义辅助函数来简化测试中创建和操作 WebNN 图的过程。
* **处理异步操作和错误:**  支持 Promise 和错误处理机制。
* **支持多种数据类型和操作:**  覆盖 WebNN API 的多种特性。
* **处理与 WebNN 服务的 Mojo 通信:**  模拟与服务端的交互。

总而言之，这部分代码是为后续更具体的 `MLGraph` 功能测试奠定基础，并确保在没有实际 WebNN 服务的情况下也能进行单元测试。

### 提示词
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/webnn/ml_graph.h"

#include <array>
#include <numeric>
#include <optional>
#include <utility>

#include "base/containers/span.h"
#include "base/memory/raw_ref.h"
#include "base/notreached.h"
#include "base/test/scoped_feature_list.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/self_owned_associated_receiver.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/bindings/unique_associated_receiver_set.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "services/webnn/public/cpp/context_properties.h"
#include "services/webnn/public/cpp/operand_descriptor.h"
#include "services/webnn/public/mojom/features.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_context_provider.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_graph.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_graph_builder.mojom-blink.h"
#include "services/webnn/public/mojom/webnn_tensor.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_clamp_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_context_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_conv_2d_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_elu_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_gemm_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_hard_sigmoid_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_leaky_relu_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_linear_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operand_data_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_operator_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_recurrent_network_activation.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_tensor_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_triangular_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/ml/ml.h"
#include "third_party/blink/renderer/modules/ml/ml_context.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_builder.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_builder_test_utils.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_type_converter.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_utils.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_operand.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_tensor.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace blink_mojom = webnn::mojom::blink;

class FakeWebNNTensor;

namespace {

// BuildResult is returned by Build() method. If the graph building is
// successful, `graph` points to the MLGraph and `error_name` and
// `error_message` are null. Otherwise, `graph` is a nullptr and
// `error_name` and `error_message` are populated from the JS error or
// DOMException.
struct BuildResult {
  Persistent<MLGraph> graph;
  String error_name;
  String error_message;
};

// Helper struct to create faked mojom result of inference.
struct ComputeResult {
  WTF::HashMap<WTF::String, WTF::Vector<uint8_t>> output;
};

template <typename T>
struct OperandInfo {
  V8MLOperandDataType::Enum data_type;
  Vector<uint32_t> dimensions;
  Vector<T> values;
};

webnn::OperandDescriptor ToDescriptor(webnn::OperandDataType data_type,
                                      base::span<const uint32_t> shape) {
  return *webnn::OperandDescriptor::Create(data_type, shape);
}

template <typename T>
T* V8ToObject(V8TestingScope* scope, ScriptValue value) {
  return NativeValueTraits<T>::NativeValue(scope->GetIsolate(), value.V8Value(),
                                           scope->GetExceptionState());
}

String ExceptionCodeToString(ExceptionCode exception_code) {
  switch (static_cast<ESErrorType>(exception_code)) {
    case ESErrorType::kTypeError:
      return "TypeError";
    default:
      NOTREACHED();
  }
}

std::pair<String, String> GetErrorNameAndMessage(V8TestingScope* scope,
                                                 ScriptValue value) {
  v8::Local<v8::Object> object;
  if (!value.V8Value()
           ->ToObject(scope->GetScriptState()->GetContext())
           .ToLocal(&object)) {
    return {"undefined", "undefined"};
  }
  const auto& Get = [&scope, object](const String& key) -> String {
    v8::Local<v8::Value> prop_value;
    if (!object
             ->Get(scope->GetScriptState()->GetContext(),
                   V8AtomicString(scope->GetScriptState()->GetIsolate(), key))
             .ToLocal(&prop_value)) {
      return "undefined";
    }
    return ToCoreStringWithUndefinedOrNullCheck(
        scope->GetScriptState()->GetIsolate(), prop_value);
  };
  return {Get("name"), Get("message")};
}

// Helper function to set the data of an ArrayBufferView from a vector.
template <typename T>
void SetArrayBufferViewValues(NotShared<DOMArrayBufferView> array_buffer_view,
                              const Vector<T>& values) {
  DCHECK_EQ(array_buffer_view->byteLength(), values.size() * sizeof(T));
  memcpy(array_buffer_view->BaseAddress(), values.data(),
         values.size() * sizeof(T));
}

// Helper function to create an ArrayBufferView given an operand.
NotShared<DOMArrayBufferView> CreateArrayBufferViewForOperand(
    const MLOperand* operand) {
  return CreateDOMArrayBufferView(operand->NumberOfElements(),
                                  operand->dataType().AsEnum());
}

// Overrode helper function to create an ArrayBufferView given an operand and
// set its data from a vector.
template <typename T>
NotShared<DOMArrayBufferView> CreateArrayBufferViewForOperand(
    const MLOperand* operand,
    const Vector<T>& values) {
  auto array_buffer_view = CreateArrayBufferViewForOperand(operand);
  SetArrayBufferViewValues(array_buffer_view, values);
  return array_buffer_view;
}

// Helper function to get the data of an ArrayBufferView into a vector.
template <typename T>
Vector<T> GetArrayBufferViewValues(
    NotShared<DOMArrayBufferView> array_buffer_view) {
  Vector<T> values(base::checked_cast<wtf_size_t>(
      array_buffer_view->byteLength() / array_buffer_view->TypeSize()));
  memcpy(values.data(), array_buffer_view->BaseAddress(),
         array_buffer_view->byteLength());
  return values;
}

MLContext* CreateContext(V8TestingScope& scope, MLContextOptions* options) {
  auto* ml = MakeGarbageCollected<ML>(scope.GetExecutionContext());
  ScriptPromiseTester tester(scope.GetScriptState(),
                             ml->createContext(scope.GetScriptState(), options,
                                               scope.GetExceptionState()));
  tester.WaitUntilSettled();
  CHECK(tester.IsFulfilled());

  return NativeValueTraits<MLContext>::NativeValue(
      scope.GetIsolate(), tester.Value().V8Value(), scope.GetExceptionState());
}

template <typename T>
MLOperand* BuildConstant(ScriptState* script_state,
                         MLGraphBuilder* builder,
                         const Vector<uint32_t>& dimensions,
                         V8MLOperandDataType::Enum data_type,
                         const Vector<T>& values,
                         ExceptionState& exception_state) {
  size_t buffer_size = std::accumulate(dimensions.begin(), dimensions.end(),
                                       size_t(1), std::multiplies<uint32_t>());
  auto buffer = CreateDOMArrayBufferView(buffer_size, data_type);
  DCHECK_EQ(buffer->byteLength(), values.size() * sizeof(T));
  memcpy(buffer->BaseAddress(), values.data(), buffer->byteLength());
  return BuildConstant(script_state, builder, dimensions, data_type,
                       exception_state, buffer);
}

MLOperand* BuildConv2d(
    V8TestingScope& scope,
    MLGraphBuilder* builder,
    MLOperand* input,
    MLOperand* filter,
    const MLConv2dOptions* options = MLConv2dOptions::Create()) {
  auto* output =
      builder->conv2d(input, filter, options, scope.GetExceptionState());
  EXPECT_THAT(output, testing::NotNull());
  EXPECT_EQ(output->Kind(), webnn::mojom::blink::Operand::Kind::kOutput);
  EXPECT_EQ(output->DataType(), input->DataType());
  auto* conv2d = output->Operator();
  EXPECT_THAT(conv2d, testing::NotNull());
  EXPECT_EQ(conv2d->Kind(), webnn::mojom::blink::Operation::Tag::kConv2d);
  EXPECT_THAT(conv2d->Options(), testing::NotNull());
  return output;
}

MLOperand* BuildGemm(V8TestingScope& scope,
                     MLGraphBuilder* builder,
                     MLOperand* a,
                     MLOperand* b,
                     const MLGemmOptions* options = MLGemmOptions::Create()) {
  auto* output = builder->gemm(a, b, options, scope.GetExceptionState());
  EXPECT_THAT(output, testing::NotNull());
  EXPECT_EQ(output->Kind(), webnn::mojom::blink::Operand::Kind::kOutput);
  EXPECT_EQ(output->DataType(), a->DataType());
  auto* gemm = output->Operator();
  EXPECT_THAT(gemm, testing::NotNull());
  EXPECT_EQ(gemm->Kind(), webnn::mojom::blink::Operation::Tag::kGemm);
  EXPECT_THAT(gemm->Options(), testing::NotNull());
  return output;
}

MLOperand* BuildElementWiseBinaryOperator(
    MLGraphBuilder* builder,
    V8TestingScope& scope,
    MLOperand* a,
    MLOperand* b,
    webnn::mojom::blink::ElementWiseBinary::Kind kind,
    const MLOperatorOptions* options) {
  switch (kind) {
    case webnn::mojom::blink::ElementWiseBinary::Kind::kAdd:
      return builder->add(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kSub:
      return builder->sub(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kMul:
      return builder->mul(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kDiv:
      return builder->div(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kMin:
      return builder->min(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kMax:
      return builder->max(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kPow:
      return builder->pow(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kEqual:
      return builder->equal(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kGreater:
      return builder->greater(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kGreaterOrEqual:
      return builder->greaterOrEqual(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kLesser:
      return builder->lesser(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kLesserOrEqual:
      return builder->lesserOrEqual(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kLogicalAnd:
      return builder->logicalAnd(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kLogicalOr:
      return builder->logicalOr(a, b, options, scope.GetExceptionState());
    case webnn::mojom::blink::ElementWiseBinary::Kind::kLogicalXor:
      return builder->logicalXor(a, b, options, scope.GetExceptionState());
  }
}

MLOperand* BuildElementWiseBinary(
    V8TestingScope& scope,
    MLGraphBuilder* builder,
    webnn::mojom::blink::ElementWiseBinary::Kind kind,
    MLOperand* a,
    MLOperand* b,
    const MLOperatorOptions* options = MLOperatorOptions::Create()) {
  MLOperand* output =
      BuildElementWiseBinaryOperator(builder, scope, a, b, kind, options);
  EXPECT_THAT(output, testing::NotNull());
  EXPECT_EQ(output->Kind(), webnn::mojom::blink::Operand::Kind::kOutput);

  if (IsLogicalBinaryOperator(kind)) {
    EXPECT_EQ(output->dataType().AsEnum(), V8MLOperandDataType::Enum::kUint8);
  } else {
    EXPECT_EQ(output->DataType(), a->DataType());
  }

  auto* op = output->Operator();
  EXPECT_THAT(op, testing::NotNull());
  EXPECT_EQ(op->Kind(),
            webnn::mojom::blink::Operation::Tag::kElementWiseBinary);
  EXPECT_EQ(op->SubKind<webnn::mojom::blink::ElementWiseBinary::Kind>(), kind);
  return output;
}

}  // namespace

class MLGraphTest : public testing::Test {
 public:
  MLGraphTest()
      : scoped_feature_list_(webnn::mojom::features::kWebMachineLearningNeuralNetwork) {}

  void SetGraphInfo(blink_mojom::GraphInfoPtr graph_info) {
    graph_info_ = std::move(graph_info);
  }

  blink_mojom::GraphInfoPtr GetGraphInfo() { return std::move(graph_info_); }

  void SetComputeResult(const ComputeResult& compute_result) {
    compute_result_ = std::move(compute_result);
  }

  const ComputeResult& GetComputeResult() const { return compute_result_; }

  void SetInputArrayBuffers(HashMap<String, mojo_base::BigBuffer> buffers) {
    input_array_buffers_ = std::move(buffers);
  }

  const HashMap<String, mojo_base::BigBuffer>& GetInputArrayBuffers() const {
    return input_array_buffers_;
  }

  BuildResult BuildGraph(V8TestingScope& scope,
                         MLGraphBuilder* builder,
                         const MLNamedOperands& named_operands) {
    ScriptPromise<MLGraph> build_promise = builder->build(
        scope.GetScriptState(), named_operands, scope.GetExceptionState());
    // An empty promise will be returned if `build()` synchronously rejects.
    if (build_promise.IsEmpty()) {
      return BuildResult{
          .error_name = ExceptionCodeToString(scope.GetExceptionState().Code()),
          .error_message = scope.GetExceptionState().Message()};
    }

    ScriptPromiseTester tester(scope.GetScriptState(), build_promise);
    tester.WaitUntilSettled();
    if (tester.IsFulfilled()) {
      return BuildResult{.graph = V8ToObject<MLGraph>(&scope, tester.Value())};
    } else {
      auto [name, message] = GetErrorNameAndMessage(&scope, tester.Value());
      return BuildResult{.error_name = name, .error_message = message};
    }
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
  test::TaskEnvironment task_environment_;

  blink_mojom::GraphInfoPtr graph_info_;
  HashMap<String, mojo_base::BigBuffer> input_array_buffers_;
  ComputeResult compute_result_;
};

class WebNNContextHelper {
 public:
  WebNNContextHelper() = default;
  ~WebNNContextHelper() = default;

  void ConnectWebNNTensorImpl(const blink::WebNNTensorToken& handle,
                              std::unique_ptr<FakeWebNNTensor> tensor) {
    const auto it = tensor_impls_.find(handle);
    ASSERT_TRUE(it == tensor_impls_.end());
    tensor_impls_.try_emplace(handle, std::move(tensor));
  }

  void DisconnectAndDestroyWebNNTensorImpl(
      const blink::WebNNTensorToken& handle) {
    tensor_impls_.erase(handle);
  }

 private:
  std::map<blink::WebNNTensorToken, std::unique_ptr<FakeWebNNTensor>>
      tensor_impls_;

  mojo::UniqueAssociatedReceiverSet<blink_mojom::WebNNGraphBuilder> builders_;
};

class FakeWebNNGraph : public blink_mojom::WebNNGraph {
 public:
  explicit FakeWebNNGraph(MLGraphTest& helper) : helper_(helper) {}
  FakeWebNNGraph(const FakeWebNNGraph&) = delete;
  FakeWebNNGraph(FakeWebNNGraph&&) = delete;
  ~FakeWebNNGraph() override = default;

 private:
  // Just return for testing the validation of inputs and outputs.
  void Dispatch(
      const HashMap<WTF::String, blink::WebNNTensorToken>& named_inputs,
      const HashMap<WTF::String, blink::WebNNTensorToken>& named_outputs)
      override {}

  // TODO(crbug.com/354741414): Fix this dangling pointer.
  const raw_ref<MLGraphTest, DanglingUntriaged> helper_;
};

class FakeWebNNTensor : public blink_mojom::WebNNTensor {
 public:
  FakeWebNNTensor(
      WebNNContextHelper& helper,
      mojo::PendingAssociatedReceiver<blink_mojom::WebNNTensor> receiver,
      const blink::WebNNTensorToken& tensor_handle,
      blink_mojom::TensorInfoPtr tensor_info)
      : helper_(helper),
        receiver_(this, std::move(receiver)),
        handle_(tensor_handle) {
    buffer_ = mojo_base::BigBuffer(tensor_info->descriptor.PackedByteLength());
    receiver_.set_disconnect_handler(WTF::BindOnce(
        &FakeWebNNTensor::OnConnectionError, WTF::Unretained(this)));
  }

  ~FakeWebNNTensor() override = default;

  FakeWebNNTensor(const FakeWebNNTensor&) = delete;
  FakeWebNNTensor(FakeWebNNTensor&&) = delete;

  const blink::WebNNTensorToken& handle() const { return handle_; }

 private:
  void ReadTensor(ReadTensorCallback callback) override {
    mojo_base::BigBuffer dst_buffer(buffer_.byte_span());

    std::move(callback).Run(
        blink_mojom::ReadTensorResult::NewBuffer(std::move(dst_buffer)));
  }

  void WriteTensor(mojo_base::BigBuffer src_buffer) override {
    ASSERT_LE(src_buffer.size(), buffer_.size());
    base::span(buffer_).copy_prefix_from(src_buffer);
  }

  void OnConnectionError() {
    helper_->DisconnectAndDestroyWebNNTensorImpl(handle());
  }

  // TODO(crbug.com/354741414): Fix this dangling pointer.
  const raw_ref<WebNNContextHelper, DanglingUntriaged> helper_;

  mojo::AssociatedReceiver<blink_mojom::WebNNTensor> receiver_;

  const blink::WebNNTensorToken handle_;

  mojo_base::BigBuffer buffer_;
};

class FakeWebNNGraphBuilder : public blink_mojom::WebNNGraphBuilder {
 public:
  explicit FakeWebNNGraphBuilder(MLGraphTest& helper) : helper_(helper) {}
  FakeWebNNGraphBuilder(const FakeWebNNGraphBuilder&) = delete;
  FakeWebNNGraphBuilder(FakeWebNNGraphBuilder&&) = delete;
  ~FakeWebNNGraphBuilder() override = default;

 private:
  // webnn::mojom::blink::WebNNGraphBuilder:
  void CreateGraph(blink_mojom::GraphInfoPtr graph_info,
                   CreateGraphCallback callback) override {
    helper_->SetGraphInfo(std::move(graph_info));

    mojo::PendingAssociatedRemote<blink_mojom::WebNNGraph> blink_remote;
    // The receiver bind to FakeWebNNGraph.
    mojo::MakeSelfOwnedAssociatedReceiver<blink_mojom::WebNNGraph>(
        std::make_unique<FakeWebNNGraph>(*helper_),
        blink_remote.InitWithNewEndpointAndPassReceiver());

    std::move(callback).Run(blink_mojom::CreateGraphResult::NewGraphRemote(
        std::move(blink_remote)));
  }

  // TODO(crbug.com/354741414): Fix this dangling pointer.
  const raw_ref<MLGraphTest, DanglingUntriaged> helper_;
};

class FakeWebNNContext : public blink_mojom::WebNNContext {
 public:
  explicit FakeWebNNContext(MLGraphTest& helper) : helper_(helper) {}
  FakeWebNNContext(const FakeWebNNContext&) = delete;
  FakeWebNNContext(FakeWebNNContext&&) = delete;
  ~FakeWebNNContext() override = default;

 private:
  // Override methods from webnn::mojom::WebNNContext.
  void CreateGraphBuilder(
      mojo::PendingAssociatedReceiver<blink_mojom::WebNNGraphBuilder> receiver)
      override {
    mojo::MakeSelfOwnedAssociatedReceiver<blink_mojom::WebNNGraphBuilder>(
        std::make_unique<FakeWebNNGraphBuilder>(*helper_), std::move(receiver));
  }

  void CreateTensor(blink_mojom::TensorInfoPtr tensor_info,
                    CreateTensorCallback callback) override {
    mojo::PendingAssociatedRemote<blink_mojom::WebNNTensor> blink_remote;
    auto blink_receiver = blink_remote.InitWithNewEndpointAndPassReceiver();
    blink::WebNNTensorToken tensor_handle;
    context_helper_.ConnectWebNNTensorImpl(
        tensor_handle, std::make_unique<FakeWebNNTensor>(
                           context_helper_, std::move(blink_receiver),
                           tensor_handle, std::move(tensor_info)));

    auto success = blink_mojom::CreateTensorSuccess::New(
        std::move(blink_remote), std::move(tensor_handle));
    std::move(callback).Run(
        blink_mojom::CreateTensorResult::NewSuccess(std::move(success)));
  }

  // TODO(crbug.com/354741414): Fix this dangling pointer.
  const raw_ref<MLGraphTest, DanglingUntriaged> helper_;

  WebNNContextHelper context_helper_;
};

class FakeWebNNContextProvider : public blink_mojom::WebNNContextProvider {
 public:
  explicit FakeWebNNContextProvider(MLGraphTest& helper)
      : helper_(helper), receiver_(this) {}
  FakeWebNNContextProvider(const FakeWebNNContextProvider&) = delete;
  FakeWebNNContextProvider(FakeWebNNContextProvider&&) = delete;
  ~FakeWebNNContextProvider() override = default;

  void BindRequest(mojo::ScopedMessagePipeHandle handle) {
    DCHECK(!receiver_.is_bound());
    receiver_.Bind(mojo::PendingReceiver<blink_mojom::WebNNContextProvider>(
        std::move(handle)));
    receiver_.set_disconnect_handler(WTF::BindOnce(
        &FakeWebNNContextProvider::OnConnectionError, WTF::Unretained(this)));
  }

  bool IsBound() const { return receiver_.is_bound(); }

  void OnConnectionError() { receiver_.reset(); }

 private:
  // Override methods from webnn::mojom::WebNNContextProvider.
  void CreateWebNNContext(blink_mojom::CreateContextOptionsPtr options,
                          CreateWebNNContextCallback callback) override {
    mojo::PendingRemote<blink_mojom::WebNNContext> blink_remote;
    // The receiver bind to FakeWebNNContext.
    mojo::MakeSelfOwnedReceiver<blink_mojom::WebNNContext>(
        std::make_unique<FakeWebNNContext>(*helper_),
        blink_remote.InitWithNewPipeAndPassReceiver());

    webnn::ContextProperties context_properties(
        webnn::InputOperandLayout::kNchw, webnn::Resample2DAxes::kAny,
        {/*input=*/webnn::SupportedDataTypes::All(),
         /*constant=*/webnn::SupportedDataTypes::All(),
         /*arg_min_max_input=*/
         webnn::SupportedDataTypes::All(),
         /*arg_min_max_output=*/
         webnn::SupportedDataTypes::All(),
         /*batch_normalization_input=*/webnn::SupportedDataTypes::All(),
         /*cast_input=*/webnn::SupportedDataTypes::All(),
         /*clamp_input=*/webnn::SupportedDataTypes::All(),
         /*concat_inputs=*/
         webnn::SupportedDataTypes::All(),
         /*conv2d_input=*/webnn::SupportedDataTypes::All(),
         /*conv_transpose2d_input=*/webnn::SupportedDataTypes::All(),
         /*cumulative_sum_input=*/webnn::SupportedDataTypes::All(),
         /*dequantize_linear_input=*/webnn::SupportedDataTypes::All(),
         /*dequantize_linear_scale=*/webnn::SupportedDataTypes::All(),
         /*add_input=*/webnn::SupportedDataTypes::All(),
         /*sub_input=*/webnn::SupportedDataTypes::All(),
         /*mul_input=*/webnn::SupportedDataTypes::All(),
         /*div_input=*/webnn::SupportedDataTypes::All(),
         /*max_input=*/webnn::SupportedDataTypes::All(),
         /*min_input=*/webnn::SupportedDataTypes::All(),
         /*pow_input=*/webnn::SupportedDataTypes::All(),
         /*equal_input=*/webnn::SupportedDataTypes::All(),
         /*greater_input=*/webnn::SupportedDataTypes::All(),
         /*greater_or_equal_input=*/webnn::SupportedDataTypes::All(),
         /*lesser_input=*/webnn::SupportedDataTypes::All(),
         /*lesser_or_equal_input=*/webnn::SupportedDataTypes::All(),
         /*logical_and_input=*/webnn::SupportedDataTypes::All(),
         /*logical_or_input=*/webnn::SupportedDataTypes::All(),
         /*logical_xor_input=*/webnn::SupportedDataTypes::All(),
         /*logical_not_input=*/webnn::SupportedDataTypes::All(),
         /*logical_output=*/webnn::SupportedDataTypes::All(),
         /*abs_input=*/webnn::SupportedDataTypes::All(),
         /*ceil_input=*/webnn::SupportedDataTypes::All(),
         /*cos_input=*/webnn::SupportedDataTypes::All(),
         /*erf_input=*/webnn::SupportedDataTypes::All(),
         /*exp_input=*/webnn::SupportedDataTypes::All(),
         /*floor_input=*/webnn::SupportedDataTypes::All(),
         /*identity_input=*/webnn::SupportedDataTypes::All(),
         /*log_input=*/webnn::SupportedDataTypes::All(),
         /*neg_input=*/webnn::SupportedDataTypes::All(),
         /*reciprocal_input=*/webnn::SupportedDataTypes::All(),
         /*sign_input=*/webnn::SupportedDataTypes::All(),
         /*sin_input=*/webnn::SupportedDataTypes::All(),
         /*sqrt_input=*/webnn::SupportedDataTypes::All(),
         /*tan_input=*/webnn::SupportedDataTypes::All(),
         /*elu_input=*/webnn::SupportedDataTypes::All(),
         /*expand_input=*/webnn::SupportedDataTypes::All(),
         /*gather_input=*/webnn::SupportedDataTypes::All(),
         /*gather_indices=*/
         webnn::SupportedDataTypes::All(),
         /*gather_elements_input=*/webnn::SupportedDataTypes::All(),
         /*gather_elements_indices=*/
         webnn::SupportedDataTypes::All(),
         /*gather_nd_input=*/webnn::SupportedDataTypes::All(),
         /*gather_nd_indices=*/
         webnn::SupportedDataTypes::All(),
         /*gelu_input=*/webnn::SupportedDataTypes::All(),
         /*gemm_input=*/webnn::SupportedDataTypes::All(),
         /*gru_input=*/webnn::SupportedDataTypes::All(),
         /*gru_cell_input=*/webnn::SupportedDataTypes::All(),
         /*hard_sigmoid_input=*/webnn::SupportedDataTypes::All(),
         /*hard_swish_input=*/webnn::SupportedDataTypes::All(),
         /*instance_normalization_input=*/webnn::SupportedDataTypes::All(),
         /*layer_normalization_input=*/webnn::SupportedDataTypes::All(),
         /*leaky_relu_input=*/webnn::SupportedDataTypes::All(),
         /*linear_input=*/webnn::SupportedDataTypes::All(),
         /*lstm_input=*/webnn::SupportedDataTypes::All(),
         /*lstm_cell_input=*/webnn::SupportedDataTypes::All(),
         /*matmul_input=*/webnn::SupportedDataTypes::All(),
         /*pad_input=*/webnn::SupportedDataTypes::All(),
         /*average_pool2d_input=*/webnn::SupportedDataTypes::All(),
         /*l2_pool2d_input=*/webnn::SupportedDataTypes::All(),
         /*max_pool2d_input=*/webnn::SupportedDataTypes::All(),
         /*prelu_input=*/webnn::SupportedDataTypes::All(),
         /*quantize_linear_input=*/webnn::SupportedDataTypes::All(),
         /*quantize_linear_zero_point=*/webnn::SupportedDataTypes::All(),
         /*reduce_l1_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_l2_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_log_sum_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_log_sum_exp_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_max_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_mean_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_min_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_product_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_sum_input=*/webnn::SupportedDataTypes::All(),
         /*reduce_sum_square_input=*/webnn::SupportedDataTypes::All(),
         /*relu_input=*/webnn::SupportedDataTypes::All(),
         /*resample2d_input=*/webnn::SupportedDataTypes::All(),
         /*reshape_input=*/webnn::SupportedDataTypes::All(),
         /*reverse_input=*/webnn::SupportedDataTypes::All(),
         /*scatter_elements_input=*/webnn::SupportedDataTypes::All(),
         /*scatter_elements_indices=*/webnn::SupportedDataTypes::All(),
         /*scatter_nd_input=*/webnn::SupportedDataTypes::All(),
         /*scatter_nd_indices=*/webnn::SupportedDataTypes::All(),
         /*sigmoid_input=*/webnn::SupportedDataTypes::All(),
         /*slice_input=*/webnn::SupportedDataTypes::All(),
         /*softmax_input=*/webnn::SupportedDataTypes::All(),
         /*softplus_input=*/webnn::SupportedDataTypes::All(),
         /*softsign_input=*/webnn::SupportedDataTypes::All(),
         /*split_input=*/webnn::SupportedDataTypes::All(),
         /*tanh_input=*/webnn::SupportedDataTypes::All(),
         /*tile_input=*/webnn::SupportedDataTypes::All(),
         /*transpose_input=*/webnn::SupportedDataTypes::All(),
         /*triangular_input=*/webnn::SupportedDataTypes::All(),
         /*where_condition=*/
         webnn::SupportedDataTypes::All(),
         /*where_value=*/
         webnn::SupportedDataTypes::All()});
    auto success = blink_mojom::CreateContextSuccess::New(
        std::move(blink_remote), std::move(context_properties),
        blink::WebNNContextToken());
    std::move(callback).Run(
        blink_mojom::CreateContextResult::NewSuccess(std::move(success)));
  }

  const raw_ref<MLGraphTest> helper_;
  mojo::Receiver<blink_mojom::WebNNContextProvider> receiver_;
};

class ScopedWebNNServiceBinder {
 public:
  explicit ScopedWebNNServiceBinder(MLGraphTest& helper,
                                    V8TestingScope& scope)
      : fake_webnn_context_provider_(
            std::make_unique<FakeWebNNContextProvider>(helper)),
        interface_broker_(
            scope.GetExecutionContext()->GetBrowserInterfaceBroker()) {
    interface_broker_->SetBinderForTesting(
        blink_mojom::WebNNContextProvider::Name_,
        WTF::BindRepeating(
            &FakeWebNNContextProvider::BindRequest,
            WTF::Unretained(fake_webnn_context_provider_.get())));
  }

  ~ScopedWebNNServiceBinder() {
    interface_broker_->SetBinderForTesting(
        blink_mojom::WebNNContextProvider::Name_, base::NullCallback());
  }

  bool IsWebNNContextBound() const {
    return fake_webnn_context_provider_->IsBound();
  }

 private:
  std::unique_ptr<FakeWebNNContextProvider> fake_webnn_context_provider_;
  const raw_ref<const BrowserInterfaceBrokerProxy> interface_broker_;
};

// Build a simple MLGraph asynchronously with only one relu operator.
ScriptPromise<MLGraph> BuildSimpleGraph(V8TestingScope& scope,
                                        MLContextOptions* context_options) {
  auto* context = CreateContext(scope, context_options);
  auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                         scope.GetExceptionState());
  if (builder == nullptr) {
    return ScriptPromise<MLGraph>::RejectWithDOMException(
        scope.GetScriptState(),
        DOMException::Create(
            "Unable to create graph builder.",
            DOMException::GetErrorName(DOMExceptionCode::kOperationError)));
  }

  auto* lhs_operand = BuildInput(scope.GetScriptState(), builder, "lhs",
                                 {3, 4, 5}, V8MLOperandDataType::Enum::kFloat32,
                                 scope.GetExceptionState());
  auto* rhs_operand = BuildInput(scope.GetScriptState(), builder, "rhs",
                                 {3, 4, 5}, V8MLOperandDataType::Enum::kFloat32,
                                 scope.GetExceptionState());
  const MLOperatorOptions* options = MLOperatorOptions::Create();
  auto* output = builder->add(lhs_operand, rhs_operand, options,
                              scope.GetExceptionState());
  EXPECT_THAT(output, testing::NotNull
```