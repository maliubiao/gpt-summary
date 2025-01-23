Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of the `ml_graph_test.cc` file in the Chromium Blink engine. I need to identify the main purpose of the code and how it contributes to the overall testing framework for WebNN (Web Neural Network API).

Here's a breakdown of the code's key parts:

1. **Helper Functions:** The code defines several utility functions for creating and manipulating `MLTensor` objects, including `CreateArrayBufferViewForOperand`, `IsBufferDataEqual`, `CreateArrayBufferViewFromBytes`, `DownloadMLTensorAndCheck`, `CreateMLTensorForOperand`, and `GetMLTensorValues`. These functions are used to set up test data, verify the results of WebNN operations, and interact with the WebNN API.

2. **`TEST_F(MLGraphTest, CreateWebNNTensorTest)`:** This test case focuses on verifying the creation of `MLTensor` objects. It checks if a tensor can be created with specific data types and shapes.

3. **`TEST_F(MLGraphTest, WriteWebNNTensorTest)`:** This test case verifies the functionality of writing data to an `MLTensor`. It checks if data written to the tensor can be successfully read back and if subsequent writes overwrite the previous data.

4. **`TEST_F(MLGraphTest, WriteWebNNTensorThenDestroyTest)`:** This test case aims to ensure that writing to a destroyed `MLTensor` does not cause a crash. It's a safety check for resource management.

5. **`TEST_F(MLGraphTest, ReadWebNNTensorThenDestroyTest)`:** Similar to the previous test, this one checks if attempting to read from a destroyed `MLTensor` is handled gracefully and doesn't lead to a crash.

6. **`TEST_F(MLGraphTest, WebNNGraphDispatchTest)`:** This test case focuses on the `dispatch` functionality of a WebNN graph. It creates a simple graph with an element-wise addition, sets input tensors, and verifies that dispatching the graph executes without errors and that the output tensor has the expected initial values (before any actual computation happens in the fake service). It also tests dispatching the same graph multiple times.

7. **`TEST_F(MLGraphTest, CreateWebNNGraphTest)`:** This test case verifies the creation of an `MLGraph` object using the `BuildSimpleGraph` helper function (defined in the preceding part of the file).

8. **`struct SoftmaxTester` and `TEST_F(MLGraphTest, SoftmaxTest)`:** This section tests the building of a WebNN graph containing a softmax operation. It verifies that the graph is built correctly and that the output operand has the expected descriptor (data type and shape).

9. **`template <typename T> struct ConstantTester` and `TEST_F(MLGraphTest, ConstantTest)`:** This section tests the creation of constant operands within a WebNN graph. It checks that the constant values and their descriptors are correctly represented in the underlying graph representation. It tests various data types for the constant.

10. **`struct CastTester` and `TEST_F(MLGraphTest, CastTester)`:** This section tests the building of a WebNN graph with a cast operation, which changes the data type of a tensor. It verifies the correct creation of the cast operation and the output operand's descriptor.
这是 `blink/renderer/modules/ml/webnn/ml_graph_test.cc` 文件的第二部分，主要功能是测试 WebNN (Web Neural Network API) 中与 **MLTensor** 对象以及 **图的执行 (dispatch)** 相关的操作。它模拟了 WebNN 的使用场景，并验证了 API 的正确性和健壮性。

**功能归纳:**

这部分代码主要测试了以下 WebNN 功能：

1. **MLTensor 的创建和属性验证:**
   - 测试了通过 `MLContext::createTensor` 方法创建 `MLTensor` 对象。
   - 验证了创建的 `MLTensor` 是否具有预期的 `dataType` 和 `shape`。

2. **MLTensor 的数据读写:**
   - 测试了通过 `MLContext::writeTensor` 方法向 `MLTensor` 写入数据。
   - 测试了通过 `MLContext::readTensor` 方法从 `MLTensor` 读取数据。
   - 使用 `IsBufferDataEqual` 和 `DownloadMLTensorAndCheck` 等辅助函数来验证读取的数据是否与预期一致。
   - 测试了重复写入不同数据到同一个 `MLTensor` 的情况。

3. **MLTensor 的生命周期管理:**
   - 测试了在 `MLTensor` 对象被销毁后，尝试写入或读取数据是否会导致崩溃。这属于健壮性测试，验证了资源管理的安全性。

4. **WebNN 图的执行 (Dispatch):**
   - 测试了通过 `MLContext::dispatch` 方法执行已构建的 `MLGraph`。
   - 创建包含简单元素级加法运算的图，并提供输入和输出 `MLTensor`。
   - 验证了 `dispatch` 方法的调用是否成功，并且没有抛出异常。
   - 使用 `GetMLTensorValues` 获取输出 `MLTensor` 的值，用于后续的数值验证 (尽管在这个测试中，由于是模拟环境，输出值默认为 0)。
   - 测试了多次 dispatch 同一个图的情况。

5. **WebNN 图的创建 (使用 `BuildSimpleGraph`):**
   - 测试了使用 `BuildSimpleGraph` (在文件的第一部分定义) 创建 `MLGraph` 对象的过程。

6. **特定算子的图构建和信息验证 (Softmax, Constant, Cast):**
   - 针对 `softmax`, `constant`, `cast` 等算子，测试了如何使用 `MLGraphBuilder` 构建包含这些算子的图。
   - 通过 `GetGraphInfo` (在文件的第一部分定义) 获取构建后的图的详细信息。
   - 验证了图中的操作类型 (例如 `is_softmax`, `is_element_wise_unary`) 以及输出操作数的描述符 (数据类型和形状) 是否符合预期。
   - 对于 `constant` 算子，还验证了常量数据是否正确地存储在图的信息中。

**与 JavaScript, HTML, CSS 的关系 (以及举例说明):**

这部分代码直接测试的是 Blink 引擎中 WebNN API 的 C++ 实现，它位于 JavaScript API 的底层。JavaScript 是用户与 WebNN 交互的主要方式。

* **JavaScript 创建和使用 Tensor:** 用户在 JavaScript 中会创建 `MLTensor` 对象，并设置其数据。`TEST_F(MLGraphTest, CreateWebNNTensorTest)` 和 `TEST_F(MLGraphTest, WriteWebNNTensorTest)` 验证了底层 C++ 实现是否正确处理了这些操作。
    ```javascript
    // JavaScript 示例
    const inputTensor = new MLMultiDimensionalArray(new Float32Array([1, 2, 3, 4]), [2, 2]);
    const outputTensor = new MLMultiDimensionalArray(new Float32Array(4), [2, 2]);
    // ... 构建图 ...
    const outputs = await context.compute(graph, { input: inputTensor }, { output: outputTensor });
    ```

* **JavaScript 执行图:** 用户在 JavaScript 中调用 `MLContext.compute()` 方法来执行构建好的 WebNN 图。`TEST_F(MLGraphTest, WebNNGraphDispatchTest)` 模拟了图的执行过程，并验证了 C++ 层的 `dispatch` 方法的正确性。

* **JavaScript 创建包含特定算子的图:** 用户在 JavaScript 中使用 `MLGraphBuilder` 的方法 (如 `add`, `softmax`, `constant`, `cast` 等) 来构建包含各种算子的图。`TEST_F(MLGraphTest, SoftmaxTest)`, `TEST_F(MLGraphTest, ConstantTest)`, 和 `TEST_F(MLGraphTest, CastTester)` 测试了 C++ 层构建这些特定算子的能力和正确性。
    ```javascript
    // JavaScript 示例
    const builder = new MLGraphBuilder();
    const input = builder.input('input', { type: 'float32', dimensions: [2, 4] });
    const output = builder.softmax(input);
    const graph = await builder.build({ output });
    ```

**逻辑推理 (假设输入与输出):**

* **`TEST_F(MLGraphTest, WriteWebNNTensorTest)` 假设输入:**
    - 创建一个 shape 为 `{2, 2}`，数据类型为 `uint8` 的 `MLTensor`。
    - 提供一个包含 `0xAA, 0xAA, 0xAA, 0xAA` 的 `DOMArrayBuffer`。
    - 然后提供一个包含 `0xAA, 0xCC, 0xBB, 0xBB` 的 `DOMArrayBuffer` 进行第二次写入。
  **预期输出:**
    - 第一次读取 `MLTensor` 的数据应为 `0xAA, 0xAA, 0xAA, 0xAA`。
    - 第二次读取 `MLTensor` 的数据应为 `0xAA, 0xCC, 0xBB, 0xBB`。

* **`TEST_F(MLGraphTest, WebNNGraphDispatchTest)` 假设输入:**
    - 构建一个包含元素级加法的图，输入操作数 "lhs" 和 "rhs" 的 shape 为 `{3, 5}`，数据类型为 `uint8`。
    - 创建两个 `MLTensor` 作为输入，初始值未明确指定 (在这个测试中，由于是模拟，实际计算不会发生)。
  **预期输出:**
    - `dispatch` 方法调用成功，没有异常。
    - 输出 `MLTensor` 的值 (通过 `GetMLTensorValues` 获取) 应该是一个长度为 15 的 `uint8` 向量，所有元素都为 0 (这是模拟环境下的默认行为)。

**用户或编程常见的使用错误 (举例说明):**

* **尝试写入已销毁的 Tensor:** 用户在 JavaScript 中可能会错误地持有一个 `MLTensor` 对象的引用，并在其被垃圾回收或显式销毁后尝试向其写入数据。`TEST_F(MLGraphTest, WriteWebNNTensorThenDestroyTest)` 验证了底层是否能安全地处理这种情况，防止崩溃。

* **尝试读取已销毁的 Tensor:** 类似地，用户可能尝试读取一个已经被销毁的 `MLTensor`。`TEST_F(MLGraphTest, ReadWebNNTensorThenDestroyTest)` 验证了这种情况的安全性。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户编写 JavaScript 代码，使用 WebNN API:** 用户开始编写使用 WebNN API 的 JavaScript 代码，例如创建 `MLContext`，`MLGraphBuilder`，添加操作，构建 `MLGraph`，创建 `MLTensor`，并调用 `context.compute()`。

2. **JavaScript 引擎调用 Blink 的 WebNN 实现:** 当 JavaScript 代码执行到 WebNN 相关的 API 调用时，JavaScript 引擎会将这些调用转发到 Blink 引擎中对应的 C++ 实现。

3. **`MLContext::createTensor` 被调用 (例如 `CreateWebNNTensorTest`):** 如果用户在 JavaScript 中创建 `MLTensor`，最终会调用到 `blink::MLContext` 的 `createTensor` 方法。`CreateWebNNTensorTest` 就模拟了这个过程，确保 `createTensor` 的 C++ 实现能正确创建 `MLTensor` 对象。

4. **`MLContext::writeTensor` 被调用 (例如 `WriteWebNNTensorTest`):** 当用户在 JavaScript 中设置 `MLTensor` 的数据时，会调用到 `blink::MLContext` 的 `writeTensor` 方法。`WriteWebNNTensorTest` 验证了数据写入的正确性。

5. **`MLContext::dispatch` 被调用 (例如 `WebNNGraphDispatchTest`):** 当用户在 JavaScript 中调用 `context.compute()` 执行图时，会调用到 `blink::MLContext` 的 `dispatch` 方法。`WebNNGraphDispatchTest` 测试了图执行的流程。

6. **`MLGraphBuilder` 构建图 (例如 `SoftmaxTest`, `ConstantTest`, `CastTester`):** 用户在 JavaScript 中使用 `MLGraphBuilder` 构建包含各种算子的图，这会触发 Blink 中 `MLGraphBuilder` 相应的方法调用，最终构建出 `MLGraph` 对象。这些测试用例验证了图构建的正确性。

**总结:**

这部分 `ml_graph_test.cc` 文件专注于测试 WebNN API 中 `MLTensor` 的生命周期管理、数据读写操作以及图的执行流程。它通过模拟 JavaScript 的使用场景，验证了底层 C++ 实现的正确性和健壮性，确保了 WebNN API 的核心功能能够正常工作。它还针对特定的算子进行了图构建和信息验证的测试。

### 提示词
```
这是目录为blink/renderer/modules/ml/webnn/ml_graph_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
());
  return builder->build(scope.GetScriptState(), {{"output", output}},
                        scope.GetExceptionState());
}

bool IsBufferDataEqual(DOMArrayBuffer* array_buffer,
                       base::span<const uint8_t> expected_data) {
  return array_buffer->ByteSpan() == expected_data;
}

MaybeShared<DOMArrayBufferView> CreateArrayBufferViewFromBytes(
    DOMArrayBuffer* array_buffer,
    base::span<const uint8_t> data) {
  array_buffer->ByteSpan().copy_prefix_from(data);
  return MaybeShared<DOMArrayBufferView>(
      blink::DOMUint8Array::Create(array_buffer, /*byte_offset=*/0,
                                   /*length=*/array_buffer->ByteLength()));
}

// Checks the contents of a MLTensor.
// Returns false if unable to download or the tensor data did not match
// expected.
bool DownloadMLTensorAndCheck(V8TestingScope& scope,
                              MLContext* context,
                              MLTensor* src_tensor,
                              base::span<const uint8_t> expected_data) {
  auto* script_state = scope.GetScriptState();
  ScriptPromiseTester tester(
      script_state,
      context->readTensor(script_state, src_tensor, scope.GetExceptionState()));
  tester.WaitUntilSettled();
  if (tester.IsRejected()) {
    return false;
  }
  EXPECT_TRUE(tester.IsFulfilled());
  auto* array_buffer = V8ToObject<DOMArrayBuffer>(&scope, tester.Value());
  return IsBufferDataEqual(array_buffer, expected_data);
}

MLTensor* CreateMLTensorForOperand(V8TestingScope& scope,
                                   MLContext* ml_context,
                                   const MLOperand* operand) {
  auto array_buffer_view = CreateArrayBufferViewForOperand(operand);
  auto* desc = MLTensorDescriptor::Create();
  desc->setDataType(operand->dataType());
  desc->setShape(operand->shape());
  desc->setReadable(true);
  desc->setWritable(true);

  ScriptPromiseTester tester(
      scope.GetScriptState(),
      ml_context->createTensor(scope.GetScriptState(), desc,
                               scope.GetExceptionState()));
  tester.WaitUntilSettled();
  CHECK(tester.IsFulfilled());

  MLTensor* ml_tensor = V8ToObject<MLTensor>(&scope, tester.Value());

  ml_context->writeTensor(
      scope.GetScriptState(), ml_tensor,
      MaybeShared<DOMArrayBufferView>(array_buffer_view.Get()),
      scope.GetExceptionState());
  return ml_tensor;
}

Vector<uint8_t> GetMLTensorValues(V8TestingScope& scope,
                                  MLContext* ml_context,
                                  MLTensor* ml_tensor) {
  ScriptPromiseTester tester(
      scope.GetScriptState(),
      ml_context->readTensor(scope.GetScriptState(), ml_tensor,
                             scope.GetExceptionState()));
  tester.WaitUntilSettled();
  if (tester.IsRejected()) {
    return {};
  }
  auto* array_buffer = V8ToObject<DOMArrayBuffer>(&scope, tester.Value());
  return GetArrayBufferViewValues<uint8_t>(
      NotShared<DOMArrayBufferView>(blink::DOMUint8Array::Create(
          array_buffer, /*byte_offset=*/0, ml_tensor->PackedByteLength())));
}

TEST_F(MLGraphTest, BuildTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  MLContext* context = CreateContext(scope, MLContextOptions::Create());
  {
    // Test throwing exception if the named outputs is empty.
    DummyExceptionStateForTesting exception_state;
    MLNamedOperands named_outputs;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, named_outputs);
    EXPECT_EQ(error_name, "TypeError");
    EXPECT_EQ(error_message, "At least one output needs to be provided.");
  }
  {
    // Test throwing exception if the named output is an input operand.
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* input =
        BuildInput(scope.GetScriptState(), builder, "input", {3, 4, 5},
                   V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"output", input}});
    EXPECT_EQ(error_name, "TypeError");
    EXPECT_EQ(error_message,
              "The operand with name \"output\" is not an output operand.");
  }
  {
    // Test throwing exception if the named output is a constant operand.
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* constant =
        BuildConstant(scope.GetScriptState(), builder, {3, 4, 5},
                      V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"output", constant}});
    EXPECT_EQ(error_name, "TypeError");
    EXPECT_EQ(error_message,
              "The operand with name \"output\" is not an output operand.");
  }
  {
    // Test throwing exception if the named outputs is a mix of input and
    // constant operands.
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* input =
        BuildInput(scope.GetScriptState(), builder, "input", {3, 4, 5},
                   V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto* constant =
        BuildConstant(scope.GetScriptState(), builder, {3, 4, 5},
                      V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"output1", input}, {"output2", constant}});
    EXPECT_EQ(error_name, "TypeError");
    EXPECT_EQ(error_message,
              "The operand with name \"output1\" is not an output operand.");
  }
  {
    // Test throwing exception if two inputs have the same name.
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* a = BuildInput(scope.GetScriptState(), builder, "a", {3, 4, 5},
                         V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto* b = BuildInput(scope.GetScriptState(), builder, "a", {3, 4, 5},
                         V8MLOperandDataType::Enum::kFloat32, exception_state);
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* c = builder->add(a, b, options, exception_state);
    ASSERT_THAT(c, testing::NotNull());

    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"c", c}});
    EXPECT_EQ(error_name, "TypeError");
    EXPECT_EQ(error_message, "The input name \"a\" is duplicated.");
  }
  {
    // Test building a graph with an elementwise add operator that uses the same
    // input for both lhs and rhs:
    //   [a]
    //   / \
    //   \ /
    //   add
    //    |
    //   [b]
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* a = BuildInput(scope.GetScriptState(), builder, "a", {3, 4, 5},
                         V8MLOperandDataType::Enum::kFloat32, exception_state);
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* output = builder->add(a, a, options, exception_state);
    ASSERT_THAT(output, testing::NotNull());
    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"b", output}});
    ASSERT_THAT(graph, testing::NotNull());
    const auto& inputs = graph->GetInputConstraints();
    EXPECT_EQ(inputs.size(), static_cast<uint32_t>(1));
    EXPECT_EQ(*inputs.at("a"), a->Descriptor());
    const auto& outputs = graph->GetOutputConstraints();
    EXPECT_EQ(outputs.size(), static_cast<uint32_t>(1));
    EXPECT_EQ(*outputs.at("b"), output->Descriptor());
  }
  {
    // Test building a graph with two operators sharing a same input:
    //      [a]
    //     /   \
    //  relu   sigmoid
    //    |      |
    //   [b]    [c]
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* a = BuildInput(scope.GetScriptState(), builder, "a", {3, 4, 5},
                         V8MLOperandDataType::Enum::kFloat32, exception_state);
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* b = builder->relu(a, options, exception_state);
    ASSERT_THAT(b, testing::NotNull());
    auto* c = builder->sigmoid(a, options, exception_state);
    ASSERT_THAT(c, testing::NotNull());
    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"b", b}, {"c", c}});
    ASSERT_THAT(graph, testing::NotNull());
    const auto& inputs = graph->GetInputConstraints();
    EXPECT_EQ(inputs.size(), static_cast<uint32_t>(1));
    EXPECT_EQ(*inputs.at("a"), a->Descriptor());
    const auto& outputs = graph->GetOutputConstraints();
    EXPECT_EQ(outputs.size(), static_cast<uint32_t>(2));
    EXPECT_EQ(*outputs.at("b"), b->Descriptor());
    EXPECT_EQ(*outputs.at("c"), c->Descriptor());
  }
  {
    // Test building a fake graph with two inputs, one gemm operation and one
    // output.
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    auto* a = BuildInput(scope.GetScriptState(), builder, "a", {3, 4},
                         V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto* b = BuildInput(scope.GetScriptState(), builder, "b", {4, 3},
                         V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto* c = BuildGemm(scope, builder, a, b);

    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"c", c}});
    ASSERT_THAT(graph, testing::NotNull());
    const auto& inputs = graph->GetInputConstraints();
    EXPECT_EQ(inputs.size(), static_cast<uint32_t>(2));
    EXPECT_EQ(*inputs.at("a"), a->Descriptor());
    EXPECT_EQ(*inputs.at("b"), b->Descriptor());
    const auto& outputs = graph->GetOutputConstraints();
    EXPECT_EQ(outputs.size(), static_cast<uint32_t>(1));
    EXPECT_EQ(*outputs.at("c"), c->Descriptor());
  }
  {
    DummyExceptionStateForTesting exception_state;
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           exception_state);
    ASSERT_THAT(builder, testing::NotNull());
    // Test building a fake graph with conv2d, add and relu operations.
    auto* input =
        BuildInput(scope.GetScriptState(), builder, "input", {1, 1, 5, 5},
                   V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto* filter =
        BuildConstant(scope.GetScriptState(), builder, {1, 1, 3, 3},
                      V8MLOperandDataType::Enum::kFloat32, exception_state);
    auto* conv2d = BuildConv2d(scope, builder, input, filter);
    auto* bias =
        BuildConstant(scope.GetScriptState(), builder, {1},
                      V8MLOperandDataType::Enum::kFloat32, exception_state);
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* add = builder->add(conv2d, bias, options, exception_state);
    ASSERT_THAT(add, testing::NotNull());
    auto* output = builder->relu(add, options, exception_state);
    ASSERT_THAT(output, testing::NotNull());

    auto [graph, error_name, error_message] =
        BuildGraph(scope, builder, {{"output", output}});
    ASSERT_THAT(graph, testing::NotNull());
    const auto& inputs = graph->GetInputConstraints();
    EXPECT_EQ(inputs.size(), static_cast<uint32_t>(1));
    EXPECT_EQ(*inputs.at("input"), input->Descriptor());
    const auto& outputs = graph->GetOutputConstraints();
    EXPECT_EQ(outputs.size(), static_cast<uint32_t>(1));
    EXPECT_EQ(*outputs.at("output"), output->Descriptor());
  }
}

TEST_F(MLGraphTest, CreateWebNNTensorTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  auto* script_state = scope.GetScriptState();

  MLContext* ml_context = CreateContext(scope, options);

  auto* desc = MLTensorDescriptor::Create();
  desc->setDataType(V8MLOperandDataType::Enum::kFloat32);
  desc->setShape({2, 2});

  ScriptPromiseTester tensor_tester(
      script_state,
      ml_context->createTensor(script_state, desc, scope.GetExceptionState()));
  tensor_tester.WaitUntilSettled();
  EXPECT_TRUE(tensor_tester.IsFulfilled());

  MLTensor* ml_tensor = V8ToObject<MLTensor>(&scope, tensor_tester.Value());
  ASSERT_THAT(ml_tensor, testing::NotNull());
  EXPECT_EQ(ml_tensor->dataType(), desc->dataType());
  EXPECT_EQ(ml_tensor->shape(), desc->shape());
}

TEST_F(MLGraphTest, WriteWebNNTensorTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  auto* script_state = scope.GetScriptState();

  MLContext* ml_context = CreateContext(scope, options);

  constexpr size_t kTensorSize = 4ull;
  const Vector<uint32_t> kTensorShape{2, 2};

  auto* desc = MLTensorDescriptor::Create();
  desc->setDataType(V8MLOperandDataType::Enum::kUint8);
  desc->setShape(kTensorShape);
  desc->setReadable(true);
  desc->setWritable(true);

  ScriptPromiseTester tensor_tester(
      script_state,
      ml_context->createTensor(script_state, desc, scope.GetExceptionState()));
  tensor_tester.WaitUntilSettled();
  EXPECT_TRUE(tensor_tester.IsFulfilled());

  MLTensor* ml_tensor = V8ToObject<MLTensor>(&scope, tensor_tester.Value());
  ASSERT_THAT(ml_tensor, testing::NotNull());

  std::array<const uint8_t, kTensorSize> input_data = {0xAA, 0xAA, 0xAA, 0xAA};
  DOMArrayBuffer* array_buffer = DOMArrayBuffer::Create(input_data);
  ASSERT_THAT(array_buffer, testing::NotNull());

  // Write data to the tensor.
  ml_context->writeTensor(
      script_state, ml_tensor,
      CreateArrayBufferViewFromBytes(array_buffer, input_data),
      scope.GetExceptionState());
  ASSERT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_TRUE(
      DownloadMLTensorAndCheck(scope, ml_context, ml_tensor, input_data));

  // Write different data to the tensor.
  std::array<const uint8_t, kTensorSize> new_data = {0xAA, 0xCC, 0xBB, 0xBB};
  ml_context->writeTensor(
      script_state, ml_tensor,
      CreateArrayBufferViewFromBytes(array_buffer, new_data),
      scope.GetExceptionState());
  ASSERT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_TRUE(DownloadMLTensorAndCheck(scope, ml_context, ml_tensor, new_data));
}

// Writing data from an array buffer to a destroyed MLTensor should not crash.
TEST_F(MLGraphTest, WriteWebNNTensorThenDestroyTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  auto* script_state = scope.GetScriptState();

  MLContext* ml_context = CreateContext(scope, options);

  auto* desc = MLTensorDescriptor::Create();
  desc->setDataType(V8MLOperandDataType::Enum::kUint8);
  desc->setShape({2, 2});
  desc->setWritable(true);

  ScriptPromiseTester tensor_tester(
      script_state,
      ml_context->createTensor(script_state, desc, scope.GetExceptionState()));
  tensor_tester.WaitUntilSettled();
  EXPECT_TRUE(tensor_tester.IsFulfilled());

  MLTensor* ml_tensor = V8ToObject<MLTensor>(&scope, tensor_tester.Value());
  ASSERT_THAT(ml_tensor, testing::NotNull());

  ml_tensor->destroy();

  ml_context->writeTensor(
      script_state, ml_tensor,
      CreateDOMArrayBufferView(ml_tensor->PackedByteLength(),
                               V8MLOperandDataType::Enum::kUint8)
          ->BufferBase(),
      scope.GetExceptionState());
}

// Reading data from an array buffer to a destroyed MLTensor should not crash.
TEST_F(MLGraphTest, ReadWebNNTensorThenDestroyTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  auto* script_state = scope.GetScriptState();

  MLContext* ml_context = CreateContext(scope, options);

  auto* desc = MLTensorDescriptor::Create();
  desc->setDataType(V8MLOperandDataType::Enum::kFloat32);
  desc->setShape({2, 2});
  desc->setReadable(true);

  ScriptPromiseTester create_tensor_tester(
      script_state,
      ml_context->createTensor(script_state, desc, scope.GetExceptionState()));
  create_tensor_tester.WaitUntilSettled();
  EXPECT_TRUE(create_tensor_tester.IsFulfilled());

  MLTensor* ml_tensor =
      V8ToObject<MLTensor>(&scope, create_tensor_tester.Value());
  ASSERT_THAT(ml_tensor, testing::NotNull());

  ml_tensor->destroy();

  ScriptPromise<DOMArrayBuffer> read_promise = ml_context->readTensor(
      script_state, ml_tensor, scope.GetExceptionState());
  EXPECT_TRUE(read_promise.IsEmpty());
}

TEST_F(MLGraphTest, WebNNGraphDispatchTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  MLContext* ml_context = CreateContext(scope, options);
  auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), ml_context,
                                         scope.GetExceptionState());
  ASSERT_THAT(builder, testing::NotNull());
  const Vector<uint32_t> dimensions = {3, 5};
  const wtf_size_t number_of_elements = 15;

  // Build the graph.
  auto* lhs_operand =
      BuildInput(scope.GetScriptState(), builder, "lhs", dimensions,
                 V8MLOperandDataType::Enum::kUint8, scope.GetExceptionState());
  auto* rhs_operand =
      BuildInput(scope.GetScriptState(), builder, "rhs", dimensions,
                 V8MLOperandDataType::Enum::kUint8, scope.GetExceptionState());
  auto* output_operand = BuildElementWiseBinary(
      scope, builder, webnn::mojom::blink::ElementWiseBinary::Kind::kAdd,
      lhs_operand, rhs_operand);
  auto [graph, error_message, build_exception] =
      BuildGraph(scope, builder, {{"output", output_operand}});
  ASSERT_THAT(graph, testing::NotNull());

  MLTensor* input_tensor =
      CreateMLTensorForOperand(scope, ml_context, lhs_operand);
  ASSERT_THAT(input_tensor, testing::NotNull());

  MLNamedTensors inputs(
      {{"lhs", input_tensor},
       {"rhs", CreateMLTensorForOperand(scope, ml_context, rhs_operand)}});
  MLNamedTensors outputs({{"output", CreateMLTensorForOperand(
                                         scope, ml_context, output_operand)}});

  {
    // Dispatch successfully.
    ml_context->dispatch(scope.GetScriptState(), graph, inputs, outputs,
                         scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().Code(),
              ToExceptionCode(DOMExceptionCode::kNoError));
    Vector<uint8_t> results =
        GetMLTensorValues(scope, ml_context, outputs[0].second);
    EXPECT_EQ(results, Vector<uint8_t>(number_of_elements, 0));

    // Dispatch again successfully.
    ml_context->dispatch(scope.GetScriptState(), graph, inputs, outputs,
                         scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().Code(),
              ToExceptionCode(DOMExceptionCode::kNoError));
    results = GetMLTensorValues(scope, ml_context, outputs[0].second);
    EXPECT_EQ(results, Vector<uint8_t>(number_of_elements, 0));
  }
}

TEST_F(MLGraphTest, CreateWebNNGraphTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* script_state = scope.GetScriptState();
  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);

  {
    ScriptPromiseTester tester(script_state, BuildSimpleGraph(scope, options));
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
    MLGraph* ml_graph = V8ToObject<MLGraph>(&scope, tester.Value());
    ASSERT_THAT(ml_graph, testing::NotNull());
    EXPECT_TRUE(scoped_setup_binder.IsWebNNContextBound());
  }
}

struct ClampOptions {
  std::optional<float> min_value;
  std::optional<float> max_value;
};

struct SoftmaxTester {
  OperandInfo<float> input;
  webnn::OperandDescriptor expected_descriptor;

  void Test(MLGraphTest& helper, V8TestingScope& scope, MLContext* context) {
    // Build the graph.
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           scope.GetExceptionState());
    ASSERT_THAT(builder, testing::NotNull());
    auto* input_operand =
        BuildInput(scope.GetScriptState(), builder, "input", input.dimensions,
                   input.data_type, scope.GetExceptionState());
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* output_operand =
        builder->softmax(input_operand, options, scope.GetExceptionState());
    auto [graph, error_name, error_message] =
        helper.BuildGraph(scope, builder, {{"output", output_operand}});
    ASSERT_THAT(graph, testing::NotNull());

    auto graph_info = helper.GetGraphInfo();
    // Verify the graph information of mojo are as expected.
    ASSERT_EQ(graph_info->operations.size(), 1u);
    auto& operation = graph_info->operations[0];
    EXPECT_TRUE(operation->is_softmax());
    EXPECT_EQ(graph_info->output_operands.size(), 1u);
    auto output_operand_id = graph_info->output_operands[0];
    auto output_operand_iter =
        graph_info->id_to_operand_map.find(output_operand_id);
    ASSERT_TRUE(output_operand_iter != graph_info->id_to_operand_map.end());
    EXPECT_EQ(output_operand_iter->value->descriptor, expected_descriptor);
  }
};

TEST_F(MLGraphTest, SoftmaxTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  MLContext* context = CreateContext(scope, options);

  {
    // Test building softmax with float32 input.
    SoftmaxTester{
        .input = {.data_type = V8MLOperandDataType::Enum::kFloat32,
                  .dimensions = {2, 4}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kFloat32,
                                            std::array<uint32_t, 2>{2, 4})}
        .Test(*this, scope, context);
  }
  {
    // Test building softmax with float16 input.
    SoftmaxTester{
        .input = {.data_type = V8MLOperandDataType::Enum::kFloat16,
                  .dimensions = {1, 5}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kFloat16,
                                            std::array<uint32_t, 2>{1, 5})}
        .Test(*this, scope, context);
  }
}

template <typename T>
struct ConstantTester {
  OperandInfo<T> constant;
  webnn::OperandDescriptor expected_descriptor;
  Vector<T> expected_constant_data;

  void Test(MLGraphTest& helper, V8TestingScope& scope, MLContext* context) {
    // Build the graph.
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           scope.GetExceptionState());
    ASSERT_THAT(builder, testing::NotNull());
    auto* constant_operand = BuildConstant(
        scope.GetScriptState(), builder, constant.dimensions,
        constant.data_type, constant.values, scope.GetExceptionState());
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* output_operand =
        builder->relu(constant_operand, options, scope.GetExceptionState());
    auto [graph, error_name, error_message] =
        helper.BuildGraph(scope, builder, {{"output", output_operand}});
    ASSERT_THAT(graph, testing::NotNull());

    auto graph_info = helper.GetGraphInfo();
    // Verify the graph information of mojo are as expected.
    EXPECT_EQ(graph_info->id_to_operand_map.size(), 2u);
    EXPECT_EQ(graph_info->constant_id_to_buffer_map.size(), 1u);
    // Verify the constant `mojo::Operand`.
    for (auto& [constant_id, constant_buffer] :
         graph_info->constant_id_to_buffer_map) {
      auto constant_operand_iter =
          graph_info->id_to_operand_map.find(constant_id);
      ASSERT_TRUE(constant_operand_iter != graph_info->id_to_operand_map.end());
      EXPECT_EQ(constant_operand_iter->value->kind,
                blink_mojom::Operand::Kind::kConstant);
      EXPECT_EQ(constant_operand_iter->value->descriptor, expected_descriptor);
      EXPECT_TRUE(constant_operand_iter->value->name.empty());
      // Verify the constant data in the mojo.
      const wtf_size_t constant_size =
          base::checked_cast<wtf_size_t>(constant_buffer.size() / sizeof(T));
      Vector<T> constant_data(constant_size);
      memcpy(constant_data.data(), constant_buffer.data(),
             constant_buffer.size());
      EXPECT_EQ(expected_constant_data, constant_data);
    }
  }
};

TEST_F(MLGraphTest, ConstantTest) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  MLContext* context = CreateContext(scope, options);

  {  // Test scalar constant operand.
    ConstantTester<float>{
        .constant = {.data_type = V8MLOperandDataType::Enum::kFloat32,
                     .dimensions = {},
                     .values = {1.0}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kFloat32,
                                            std::array<uint32_t, 0>{}),
        .expected_constant_data = {1.0}}
        .Test(*this, scope, context);
  }
  {
    // Test Constant operand for Float32 data type.
    ConstantTester<float>{
        .constant = {.data_type = V8MLOperandDataType::Enum::kFloat32,
                     .dimensions = {2, 3},
                     .values = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kFloat32,
                                            std::array<uint32_t, 2>{2, 3}),
        .expected_constant_data = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0}}
        .Test(*this, scope, context);
  }
  {
    // Test Constant operand for Float16 data type.
    ConstantTester<uint16_t>{
        .constant = {.data_type = V8MLOperandDataType::Enum::kFloat16,
                     .dimensions = {2, 3},
                     .values = {1, 2, 3, 4, 5, 6}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kFloat16,
                                            std::array<uint32_t, 2>{2, 3}),
        .expected_constant_data = {1, 2, 3, 4, 5, 6}}
        .Test(*this, scope, context);
  }
  {
    // Test Constant operand for Int32 data type.
    ConstantTester<int32_t>{
        .constant = {.data_type = V8MLOperandDataType::Enum::kInt32,
                     .dimensions = {2, 3},
                     .values = {1, 2, 3, 4, 5, 6}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kInt32,
                                            std::array<uint32_t, 2>{2, 3}),
        .expected_constant_data = {1, 2, 3, 4, 5, 6}}
        .Test(*this, scope, context);
  }
  {
    // Test Constant operand for Int8 data type.
    ConstantTester<int8_t>{
        .constant = {.data_type = V8MLOperandDataType::Enum::kInt8,
                     .dimensions = {2, 3},
                     .values = {1, 2, 3, 4, 5, 6}},
        .expected_descriptor = ToDescriptor(webnn::OperandDataType::kInt8,
                                            std::array<uint32_t, 2>{2, 3}),
        .expected_constant_data = {1, 2, 3, 4, 5, 6}}
        .Test(*this, scope, context);
  }
}

struct CastTester {
  OperandInfo<float> input;
  V8MLOperandDataType::Enum output_data_type;
  webnn::OperandDescriptor expected_descriptor;

  void Test(MLGraphTest& helper, V8TestingScope& scope, MLContext* context) {
    // Build the graph.
    auto* builder = MLGraphBuilder::Create(scope.GetScriptState(), context,
                                           scope.GetExceptionState());
    ASSERT_THAT(builder, testing::NotNull());
    auto* input_operand =
        BuildInput(scope.GetScriptState(), builder, "input", input.dimensions,
                   input.data_type, scope.GetExceptionState());
    const MLOperatorOptions* options = MLOperatorOptions::Create();
    auto* output_operand =
        builder->cast(input_operand, V8MLOperandDataType(output_data_type),
                      options, scope.GetExceptionState());
    auto [graph, error_name, error_message] =
        helper.BuildGraph(scope, builder, {{"output", output_operand}});
    ASSERT_THAT(graph, testing::NotNull());

    auto graph_info = helper.GetGraphInfo();
    // Verify the graph information of mojo are as expected.
    ASSERT_EQ(graph_info->operations.size(), 1u);
    auto& operation = graph_info->operations[0];
    EXPECT_TRUE(operation->is_element_wise_unary());
    webnn::mojom::blink::ElementWiseUnaryPtr& element_wise_unary =
        operation->get_element_wise_unary();
    EXPECT_EQ(element_wise_unary->kind,
              blink_mojom::ElementWiseUnary::Kind::kCast);
    EXPECT_EQ(graph_info->output_operands.size(), 1u);
    auto output_operand_id = graph_info->output_operands[0];
    auto output_operand_iter =
        graph_info->id_to_operand_map.find(output_operand_id);
    ASSERT_TRUE(output_operand_iter != graph_info->id_to_operand_map.end());
    EXPECT_EQ(output_operand_iter->value->descriptor, expected_descriptor);
  }
};

TEST_F(MLGraphTest, CastTester) {
  V8TestingScope scope;
  // Bind fake WebNN Context in the service for testing.
  ScopedWebNNServiceBinder scoped_setup_binder(*this, scope);

  auto* options = MLContextOptions::Create();
  // Create WebNN Context with GPU device type.
  options->setDeviceType(V8MLDeviceType::Enum::kGpu);
  MLContext* context = CreateContext(scope, options);

  const std::array<uint32_t, 2> shape{2, 2};
  const Vector<uint32_t> wtf_shape(shape);
  {
    CastTester{.input = {.data_type = V8MLOperandDataType::Enum::kFloat32,
                         .dimensions = wtf_shape},
               .output_data_type = V8MLOperandDataType::Enum::kInt32,
               .expected_descriptor =
                   ToDescriptor(webnn::OperandDataType::kInt32, shape)}
        .Test(*this, scope, context);
    CastTester{.input = {.data_type = V8MLOperandDataType::Enum::kFloat32,
                         .dimensions = wtf_shape},
               .output_data_type = V8MLOperandDataType::Enum::kFloat16,
               .expected_descriptor =
                   ToDescriptor(webnn::OperandDataType::kFloat16, shape)}
        .Test(*this, scope, context);
    CastTester{.input = {.data_type = V8MLOperandDataType::Enum::kFloat32,
                         .dimensions = wtf_shape},
               .output_data_type = V8MLOperandDataType::Enum::kUint32,
               .expected_descriptor =
                   ToDescriptor(webnn::OperandDataType::kUint32, shape)}
        .Test(*this, scope, context);
    CastTester{.input = {.data_type = V8MLOperandDataT
```