Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `MLContext` class in the Chromium Blink engine. This is the second part of the code. The request also asks to highlight connections to JavaScript, HTML, CSS, provide examples of logical reasoning with input/output, common usage errors, and debugging hints related to how a user interaction might lead to this code.

**Plan:**

1. **Summarize the code's functionality:** Focus on what the functions within this snippet do. It appears to be related to creating, reading, and writing tensors, and dispatching operations on graphs.
2. **Connect to web technologies:** Explain how these C++ functions are likely exposed to JavaScript through the Web Neural Network API.
3. **Provide examples:** Illustrate how JavaScript code interacting with the WebNN API would trigger these C++ functions.
4. **Logical reasoning:** While this part doesn't have complex logical reasoning, illustrate the flow of data when creating, reading, and writing tensors.
5. **Common errors:** Point out potential errors developers might make when using the WebNN API that would lead to these functions failing (e.g., incorrect tensor dimensions, data types).
6. **Debugging hints:** Explain how a user action in a web page could lead to this code being executed during the processing of a neural network.
7. **Since this is part 2, integrate insights from part 1.**
```cpp
void MLContext::DidCreateWebNNTensor(
    ScopedMLTrace scoped_trace,
    ScriptPromiseResolver<blink::MLTensor>* resolver,
    webnn::OperandDescriptor validated_descriptor,
    webnn::MLTensorUsage usage,
    webnn::mojom::blink::CreateTensorResultPtr result) {
  pending_resolvers_.erase(resolver);

  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }

  if (result->is_error()) {
    const auto& create_tensor_error = result->get_error();
    resolver->RejectWithDOMException(
        WebNNErrorCodeToDOMExceptionCode(create_tensor_error->code),
        create_tensor_error->message);
    return;
  }

  auto* tensor = MakeGarbageCollected<MLTensor>(
      resolver->GetExecutionContext(), this, std::move(validated_descriptor),
      usage, std::move(result->get_success()), base::PassKey<MLContext>());
  tensors_.insert(tensor);

  resolver->Resolve(tensor);
}

}  // namespace blink
```

**功能归纳:**

这段代码主要负责处理 `MLContext::createTensor` 的异步结果，即在底层的 WebNN API 完成 Tensor 创建后，将结果返回给 JavaScript。具体功能如下：

1. **处理 Tensor 创建结果:** `DidCreateWebNNTensor` 函数是 `MLContext::createTensor` 调用底层 WebNN API 创建 Tensor 后的回调函数。它接收创建操作的结果。
2. **移除 Promise Resolver:**  从 `pending_resolvers_` 集合中移除已完成的 Promise resolver。这是为了管理正在进行的异步操作。
3. **检查 ScriptState 的有效性:** 确保当前的 JavaScript 执行上下文仍然有效，避免在页面卸载等情况下发生错误。
4. **处理错误情况:** 如果底层 Tensor 创建失败（`result->is_error()` 为真），则提取错误信息（错误代码和消息），并使用 `resolver->RejectWithDOMException` 将 Promise 标记为 rejected，并将错误信息传递给 JavaScript。这会让 JavaScript 中的 `createTensor()` 返回的 Promise 进入 rejected 状态，并抛出相应的异常。
5. **创建 MLTensor 对象:** 如果底层 Tensor 创建成功，则创建一个新的 `MLTensor` 对象。这个对象封装了底层创建的 Tensor 的信息和句柄。
    - `resolver->GetExecutionContext()`: 获取 JavaScript 的执行上下文。
    - `this`: 指向当前的 `MLContext` 对象。
    - `std::move(validated_descriptor)`:  移动经过验证的 Tensor 描述符。
    - `usage`: Tensor 的使用标志（读、写、WebGPU互操作）。
    - `std::move(result->get_success())`: 移动底层创建成功的 Tensor 的信息。
    - `base::PassKey<MLContext>()`:  这是一个编译时类型安全的机制，用于限制 `MLTensor` 的构造函数只能由 `MLContext` 调用。
6. **管理 Tensor 对象:** 将新创建的 `MLTensor` 对象添加到 `tensors_` 集合中，用于跟踪当前上下文中创建的所有 Tensor。
7. **Resolve Promise:** 使用 `resolver->Resolve(tensor)` 将 Promise 标记为 resolved，并将新创建的 `MLTensor` 对象作为结果传递给 JavaScript。这会触发 JavaScript 中 `createTensor()` 返回的 Promise 的 `then()` 回调。

**与 JavaScript, HTML, CSS 的关系:**

这段代码是 Chromium 渲染引擎中 WebNN API 的一部分，直接与 JavaScript 交互。

* **JavaScript:**  JavaScript 代码通过 WebNN API 调用 `MLContext` 的 `createTensor` 方法来创建 Tensor。`DidCreateWebNNTensor` 函数负责将 C++ 层 Tensor 创建的结果通过 Promise 返回给 JavaScript。

   **举例:**
   ```javascript
   const builder = new MLGraphBuilder();
   const inputShape = [1, 28, 28, 1];
   const input = builder.input('input', { type: 'float32', dimensions: inputShape });
   // ... 其他图构建操作 ...
   const output = builder.output('output');
   const model = await builder.build();

   const context = await navigator.ml.createContext();
   const inputTensorDescriptor = { type: 'float32', dimensions: inputShape };
   const inputTensor = await context.createTensor(inputTensorDescriptor); // 调用 createTensor

   // 当底层 Tensor 创建完成后，DidCreateWebNNTensor 会被调用，
   // 并将创建的 MLTensor 对象传递给这里的 inputTensor 变量。
   ```

* **HTML:** HTML 文件中嵌入的 `<script>` 标签内的 JavaScript 代码可以调用 WebNN API，从而间接触发这段 C++ 代码的执行。

   **举例:**
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <title>WebNN Example</title>
   </head>
   <body>
       <script>
           // 上面的 JavaScript 代码
       </script>
   </body>
   </html>
   ```

* **CSS:** CSS 与这段代码没有直接关系。CSS 主要负责页面的样式和布局，而这段代码处理的是底层的机器学习操作。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `resolver`: 一个指向在 JavaScript 中创建的 Promise 的 resolver 对象的指针。
* `validated_descriptor`:  一个 `webnn::OperandDescriptor` 对象，描述了要创建的 Tensor 的属性（数据类型、形状等）。
* `usage`: 一个 `webnn::MLTensorUsage` 枚举值，指示 Tensor 的用途（例如，可读、可写）。
* `result`: 一个 `webnn::mojom::blink::CreateTensorResultPtr`，包含了底层 Tensor 创建操作的结果。

**假设输出 (成功情况):**

* `pending_resolvers_`:  之前与该 resolver 关联的条目被移除。
* 一个新的 `MLTensor` 对象被创建，并添加到 `tensors_` 集合中。
* `resolver` 对应的 JavaScript Promise 被 resolve，并将新创建的 `MLTensor` 对象作为结果传递给 JavaScript 的 `then()` 回调。

**假设输出 (失败情况):**

* `pending_resolvers_`: 之前与该 resolver 关联的条目被移除。
* `resolver` 对应的 JavaScript Promise 被 reject，并将包含错误代码和消息的 DOMException 传递给 JavaScript 的 `catch()` 回调。

**用户或编程常见的使用错误:**

1. **在无效的 ScriptState 中调用 `createTensor`:**  如果在页面卸载或其他导致 ScriptState 失效的情况下调用 `createTensor`，`script_state->ContextIsValid()` 将返回 false，导致 Promise 不会被 resolve 或 reject，可能会造成资源泄漏或程序崩溃。 这在 Part 1 中已经有所涉及。
2. **底层 Tensor 创建失败:** 底层 WebNN 实现可能因为各种原因（例如，硬件不支持、资源不足）导致 Tensor 创建失败。这段代码正确处理了这种情况，将错误信息传递回 JavaScript。开发者需要根据错误信息进行调试。
3. **忘记处理 Promise 的 rejection:** 如果 JavaScript 代码没有为 `createTensor` 返回的 Promise 添加 `catch()` 回调，那么当 Tensor 创建失败时，错误可能会被忽略，导致程序行为异常。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户访问包含 WebNN 代码的网页:** 用户在浏览器中打开一个包含使用 WebNN API 的 JavaScript 代码的网页。
2. **JavaScript 代码执行:** 网页加载后，JavaScript 代码开始执行。
3. **调用 `navigator.ml.createContext()`:**  JavaScript 代码首先获取一个 `MLContext` 对象。这可能对应着 Part 1 中的 `MLContext::create` 或相关初始化过程。
4. **调用 `context.createTensor(descriptor)`:** JavaScript 代码调用 `MLContext` 对象的 `createTensor` 方法，请求创建一个 Tensor。
5. **`MLContext::createTensor` 执行 (Part 1):**  在 Part 1 的代码中，`MLContext::createTensor` 会验证输入参数，并将创建 Tensor 的请求发送到底层的 WebNN API。同时会创建一个 Promise 和一个 resolver，并将 resolver 存储起来。
6. **底层 WebNN API 处理:** 浏览器底层的 WebNN 实现接收到创建 Tensor 的请求，并在硬件或软件上执行相应的操作。这是一个异步过程。
7. **底层 WebNN API 返回结果:**  底层 WebNN API 完成 Tensor 创建后，会将结果（成功或失败信息）返回给 Chromium 渲染引擎。
8. **`MLContext::DidCreateWebNNTensor` 被调用 (Part 2):** 当底层 WebNN API 返回结果时，`MLContext::DidCreateWebNNTensor` 作为回调函数被调用，接收创建结果。
9. **Promise 被 resolve 或 reject:** 根据底层创建结果，`DidCreateWebNNTensor` 会将 JavaScript 中 `createTensor` 返回的 Promise resolve (成功) 或 reject (失败)。
10. **JavaScript 处理 Promise 结果:** JavaScript 代码中的 `then()` 或 `catch()` 回调函数会被执行，处理 Tensor 创建的结果。

因此，用户访问包含 WebNN 代码的网页，并且该代码尝试创建一个 Tensor 时，就会一步步地触发到这里的 `MLContext::DidCreateWebNNTensor` 函数。  调试时，可以关注 JavaScript 中 `createTensor` 调用的参数和返回的 Promise 状态，以及浏览器控制台中可能的 WebNN 相关错误信息。

Prompt: 
```
这是目录为blink/renderer/modules/ml/ml_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ypesToSupportLimits(data_type_limits.matmul_input));
  matmul->setB(
      SupportedDataTypesToSupportLimits(data_type_limits.matmul_input));
  matmul->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.matmul_input));
  op_support_limits->setMatmul(matmul);

  MLSingleInputSupportLimits* pad = MLSingleInputSupportLimits::Create();
  pad->setInput(SupportedDataTypesToSupportLimits(data_type_limits.pad_input));
  pad->setOutput(SupportedDataTypesToSupportLimits(data_type_limits.pad_input));
  op_support_limits->setPad(pad);

  // Pool2d.
  MLSingleInputSupportLimits* average_pool2d =
      MLSingleInputSupportLimits::Create();
  average_pool2d->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.average_pool2d_input));
  average_pool2d->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.average_pool2d_input));
  op_support_limits->setAveragePool2d(average_pool2d);

  MLSingleInputSupportLimits* l2_pool2d = MLSingleInputSupportLimits::Create();
  l2_pool2d->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.l2_pool2d_input));
  l2_pool2d->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.l2_pool2d_input));
  op_support_limits->setL2Pool2d(l2_pool2d);

  MLSingleInputSupportLimits* max_pool2d = MLSingleInputSupportLimits::Create();
  max_pool2d->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.max_pool2d_input));
  max_pool2d->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.max_pool2d_input));
  op_support_limits->setMaxPool2d(max_pool2d);

  MLPreluSupportLimits* prelu = MLPreluSupportLimits::Create();
  prelu->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.prelu_input));
  prelu->setSlope(
      SupportedDataTypesToSupportLimits(data_type_limits.prelu_input));
  prelu->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.prelu_input));
  op_support_limits->setPrelu(prelu);

  MLQuantizeDequantizeLinearSupportLimits* quantize_linear =
      MLQuantizeDequantizeLinearSupportLimits::Create();
  quantize_linear->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.quantize_linear_input));
  quantize_linear->setScale(SupportedDataTypesToSupportLimits(
      data_type_limits.quantize_linear_input));
  quantize_linear->setZeroPoint(SupportedDataTypesToSupportLimits(
      data_type_limits.quantize_linear_zero_point));
  quantize_linear->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.quantize_linear_zero_point));
  op_support_limits->setQuantizeLinear(quantize_linear);

  // Reduction ops.
  MLSingleInputSupportLimits* reduce_l1 = MLSingleInputSupportLimits::Create();
  reduce_l1->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_l1_input));
  reduce_l1->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_l1_input));
  op_support_limits->setReduceL1(reduce_l1);
  MLSingleInputSupportLimits* reduce_l2 = MLSingleInputSupportLimits::Create();
  reduce_l2->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_l2_input));
  reduce_l2->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_l2_input));
  op_support_limits->setReduceL2(reduce_l2);
  MLSingleInputSupportLimits* reduce_log_sum =
      MLSingleInputSupportLimits::Create();
  reduce_log_sum->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_log_sum_input));
  reduce_log_sum->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_log_sum_input));
  op_support_limits->setReduceLogSum(reduce_log_sum);
  MLSingleInputSupportLimits* reduce_log_sum_exp =
      MLSingleInputSupportLimits::Create();
  reduce_log_sum_exp->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.reduce_log_sum_exp_input));
  reduce_log_sum_exp->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.reduce_log_sum_exp_input));
  op_support_limits->setReduceLogSumExp(reduce_log_sum_exp);
  MLSingleInputSupportLimits* reduce_max = MLSingleInputSupportLimits::Create();
  reduce_max->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_max_input));
  reduce_max->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_max_input));
  op_support_limits->setReduceMax(reduce_max);
  MLSingleInputSupportLimits* reduce_mean =
      MLSingleInputSupportLimits::Create();
  reduce_mean->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_mean_input));
  reduce_mean->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_mean_input));
  op_support_limits->setReduceMean(reduce_mean);
  MLSingleInputSupportLimits* reduce_min = MLSingleInputSupportLimits::Create();
  reduce_min->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_min_input));
  reduce_min->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_min_input));
  op_support_limits->setReduceMin(reduce_min);
  MLSingleInputSupportLimits* reduce_product =
      MLSingleInputSupportLimits::Create();
  reduce_product->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_product_input));
  reduce_product->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_product_input));
  op_support_limits->setReduceProduct(reduce_product);
  MLSingleInputSupportLimits* reduce_sum = MLSingleInputSupportLimits::Create();
  reduce_sum->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_sum_input));
  reduce_sum->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reduce_sum_input));
  op_support_limits->setReduceSum(reduce_sum);
  MLSingleInputSupportLimits* reduce_sum_square =
      MLSingleInputSupportLimits::Create();
  reduce_sum_square->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.reduce_sum_square_input));
  reduce_sum_square->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.reduce_sum_square_input));
  op_support_limits->setReduceSumSquare(reduce_sum_square);

  MLSingleInputSupportLimits* relu = MLSingleInputSupportLimits::Create();
  relu->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.relu_input));
  relu->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.relu_input));
  op_support_limits->setRelu(relu);

  MLSingleInputSupportLimits* resample2d = MLSingleInputSupportLimits::Create();
  resample2d->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.resample2d_input));
  resample2d->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.resample2d_input));
  op_support_limits->setResample2d(resample2d);

  MLSingleInputSupportLimits* reshape = MLSingleInputSupportLimits::Create();
  reshape->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reshape_input));
  reshape->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reshape_input));
  op_support_limits->setReshape(reshape);

  MLSingleInputSupportLimits* reverse = MLSingleInputSupportLimits::Create();
  reverse->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.reverse_input));
  reverse->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.reverse_input));
  op_support_limits->setReverse(reverse);

  MLScatterSupportLimits* scatter_elements = MLScatterSupportLimits::Create();
  scatter_elements->setInput(SupportedDataTypesToSupportLimits(
      data_type_limits.scatter_elements_input));
  scatter_elements->setIndices(SupportedDataTypesToSupportLimits(
      data_type_limits.scatter_elements_indices));
  scatter_elements->setUpdates(SupportedDataTypesToSupportLimits(
      data_type_limits.scatter_elements_input));
  scatter_elements->setOutput(SupportedDataTypesToSupportLimits(
      data_type_limits.scatter_elements_input));
  op_support_limits->setScatterElements(scatter_elements);

  MLScatterSupportLimits* scatter_nd = MLScatterSupportLimits::Create();
  scatter_nd->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.scatter_nd_input));
  scatter_nd->setIndices(
      SupportedDataTypesToSupportLimits(data_type_limits.scatter_nd_indices));
  scatter_nd->setUpdates(
      SupportedDataTypesToSupportLimits(data_type_limits.scatter_nd_input));
  scatter_nd->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.scatter_nd_input));
  op_support_limits->setScatterND(scatter_nd);

  MLSingleInputSupportLimits* sigmoid = MLSingleInputSupportLimits::Create();
  sigmoid->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.sigmoid_input));
  sigmoid->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.sigmoid_input));
  op_support_limits->setSigmoid(sigmoid);

  MLSingleInputSupportLimits* slice = MLSingleInputSupportLimits::Create();
  slice->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.slice_input));
  slice->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.slice_input));
  op_support_limits->setSlice(slice);

  MLSingleInputSupportLimits* softmax = MLSingleInputSupportLimits::Create();
  softmax->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.softmax_input));
  softmax->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.softmax_input));
  op_support_limits->setSoftmax(softmax);

  MLSingleInputSupportLimits* softplus = MLSingleInputSupportLimits::Create();
  softplus->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.softplus_input));
  softplus->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.softplus_input));
  op_support_limits->setSoftplus(softplus);

  MLSingleInputSupportLimits* softsign = MLSingleInputSupportLimits::Create();
  softsign->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.softsign_input));
  softsign->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.softsign_input));
  op_support_limits->setSoftsign(softsign);

  MLSingleInputSupportLimits* split = MLSingleInputSupportLimits::Create();
  split->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.split_input));
  split->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.split_input));
  op_support_limits->setSplit(split);

  MLSingleInputSupportLimits* tanh = MLSingleInputSupportLimits::Create();
  tanh->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.tanh_input));
  tanh->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.tanh_input));
  op_support_limits->setTanh(tanh);

  MLSingleInputSupportLimits* tile = MLSingleInputSupportLimits::Create();
  tile->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.tile_input));
  tile->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.tile_input));
  op_support_limits->setTile(tile);

  MLSingleInputSupportLimits* transpose = MLSingleInputSupportLimits::Create();
  transpose->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.transpose_input));
  transpose->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.transpose_input));
  op_support_limits->setTranspose(transpose);

  MLSingleInputSupportLimits* triangular = MLSingleInputSupportLimits::Create();
  triangular->setInput(
      SupportedDataTypesToSupportLimits(data_type_limits.triangular_input));
  triangular->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.triangular_input));
  op_support_limits->setTriangular(triangular);

  MLWhereSupportLimits* where = MLWhereSupportLimits::Create();
  where->setCondition(
      SupportedDataTypesToSupportLimits(data_type_limits.where_condition));
  where->setTrueValue(
      SupportedDataTypesToSupportLimits(data_type_limits.where_value));
  where->setFalseValue(
      SupportedDataTypesToSupportLimits(data_type_limits.where_value));
  where->setOutput(
      SupportedDataTypesToSupportLimits(data_type_limits.where_value));
  op_support_limits->setWhere(where);

  return op_support_limits;
}

void MLContext::OnGraphCreated(MLGraph* graph) {
  graphs_.insert(graph);
}

ScriptPromise<MLTensor> MLContext::createTensor(
    ScriptState* script_state,
    const MLTensorDescriptor* descriptor,
    ExceptionState& exception_state) {
  ScopedMLTrace scoped_trace("MLContext::createTensor");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return EmptyPromise();
  }

  if (!base::FeatureList::IsEnabled(
          webnn::mojom::features::kWebMachineLearningNeuralNetwork)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Not implemented");
    return EmptyPromise();
  }

  if (!context_remote_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Context is lost.");
    return EmptyPromise();
  }

  ASSIGN_OR_RETURN(webnn::OperandDescriptor validated_descriptor,
                   webnn::OperandDescriptor::Create(
                       FromBlinkDataType(descriptor->dataType().AsEnum()),
                       descriptor->shape()),
                   [&exception_state](std::string error) {
                     exception_state.ThrowTypeError(String(error));
                     return ScriptPromise<MLTensor>();
                   });

  RETURN_IF_ERROR(webnn::ValidateTensor(properties_, validated_descriptor),
                  [&exception_state](std::string error) {
                    exception_state.ThrowTypeError(String(error));
                    return ScriptPromise<MLTensor>();
                  });

  // Map the IDL tensor usage flags to the `MLTensorUsage` enumset.
  //
  // This assertion protects against the usage flags changing without updating
  // this mapping.
  static_assert(base::to_underlying(webnn::MLTensorUsageFlags::kMaxValue) == 2);
  webnn::MLTensorUsage usage;
  if (descriptor->importableToWebGPU()) {
    usage.Put(webnn::MLTensorUsageFlags::kWebGpuInterop);
  }
  if (descriptor->readable()) {
    usage.Put(webnn::MLTensorUsageFlags::kRead);
  }
  if (descriptor->writable()) {
    usage.Put(webnn::MLTensorUsageFlags::kWrite);
  }

  auto tensor_info =
      webnn::mojom::blink::TensorInfo::New(validated_descriptor, usage);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<MLTensor>>(
      script_state, exception_state.GetContext());
  pending_resolvers_.insert(resolver);

  // Use `WebNNContext` to create `WebNNTensor` message pipe.
  context_remote_->CreateTensor(
      std::move(tensor_info),
      WTF::BindOnce(&MLContext::DidCreateWebNNTensor, WrapPersistent(this),
                    std::move(scoped_trace), WrapPersistent(resolver),
                    std::move(validated_descriptor), usage));

  return resolver->Promise();
}

void MLContext::writeTensor(
    ScriptState* script_state,
    MLTensor* dst_tensor,
    const MaybeShared<DOMArrayBufferView>& src_data_view,
    ExceptionState& exception_state) {
  WriteWebNNTensor(script_state, dst_tensor,
                   src_data_view->ByteSpanMaybeShared(), exception_state);
}

void MLContext::writeTensor(ScriptState* script_state,
                            MLTensor* dst_tensor,
                            const DOMArrayBufferBase* src_data_base,
                            ExceptionState& exception_state) {
  WriteWebNNTensor(script_state, dst_tensor,
                   src_data_base->IsDetached()
                       ? base::span<const uint8_t>()
                       : src_data_base->ByteSpanMaybeShared(),
                   exception_state);
}

ScriptPromise<DOMArrayBuffer> MLContext::readTensor(
    ScriptState* script_state,
    MLTensor* src_tensor,
    ExceptionState& exception_state) {
  ScopedMLTrace scoped_trace("MLContext::readTensor");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return EmptyPromise();
  }

  if (src_tensor->context() != this) {
    exception_state.ThrowTypeError(
        "The source tensor wasn't created with this context.");
    return EmptyPromise();
  }

  if (!src_tensor->Usage().Has(webnn::MLTensorUsageFlags::kRead)) {
    exception_state.ThrowTypeError(
        "The source tensor doesn't have read access.");
    return EmptyPromise();
  }

  return src_tensor->ReadTensorImpl(std::move(scoped_trace), script_state,
                                    exception_state);
}

ScriptPromise<IDLUndefined> MLContext::readTensor(
    ScriptState* script_state,
    MLTensor* src_tensor,
    DOMArrayBufferBase* dst_data,
    ExceptionState& exception_state) {
  ScopedMLTrace scoped_trace("MLContext::readTensor");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return EmptyPromise();
  }

  if (src_tensor->context() != this) {
    exception_state.ThrowTypeError(
        "The source tensor wasn't created with this context.");
    return EmptyPromise();
  }

  return src_tensor->ReadTensorImpl(std::move(scoped_trace), script_state,
                                    dst_data, exception_state);
}

ScriptPromise<IDLUndefined> MLContext::readTensor(
    ScriptState* script_state,
    MLTensor* src_tensor,
    MaybeShared<DOMArrayBufferView> dst_data,
    ExceptionState& exception_state) {
  ScopedMLTrace scoped_trace("MLContext::readTensor");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return EmptyPromise();
  }

  if (src_tensor->context() != this) {
    exception_state.ThrowTypeError(
        "The source tensor wasn't created with this context.");
    return EmptyPromise();
  }

  return src_tensor->ReadTensorImpl(std::move(scoped_trace), script_state,
                                    dst_data.Get(), exception_state);
}

void MLContext::WriteWebNNTensor(ScriptState* script_state,
                                 MLTensor* dst_tensor,
                                 base::span<const uint8_t> src_data,
                                 ExceptionState& exception_state) {
  ScopedMLTrace scoped_trace("MLContext::writeTensor");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return;
  }

  if (dst_tensor->context() != this) {
    exception_state.ThrowTypeError(
        "The destination tensor wasn't created with this context.");
    return;
  }

  if (!dst_tensor->Usage().Has(webnn::MLTensorUsageFlags::kWrite)) {
    exception_state.ThrowTypeError(
        "The destination tensor doesn't have write access.");
    return;
  }

  if (src_data.size() != dst_tensor->PackedByteLength()) {
    exception_state.ThrowTypeError(
        "The sizes of the source buffer and destination tensor do not match.");
    return;
  }

  dst_tensor->WriteTensorImpl(src_data, exception_state);
}

void MLContext::dispatch(ScriptState* script_state,
                         MLGraph* graph,
                         const MLNamedTensors& inputs,
                         const MLNamedTensors& outputs,
                         ExceptionState& exception_state) {
  ScopedMLTrace scoped_trace("MLContext::dispatch");
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid script state");
    return;
  }

  if (graph->Context() != this) {
    exception_state.ThrowTypeError(
        "The graph isn't built within this context.");
    return;
  }

  return graph->Dispatch(std::move(scoped_trace), inputs, outputs,
                         exception_state);
}

void MLContext::DidCreateWebNNTensor(
    ScopedMLTrace scoped_trace,
    ScriptPromiseResolver<blink::MLTensor>* resolver,
    webnn::OperandDescriptor validated_descriptor,
    webnn::MLTensorUsage usage,
    webnn::mojom::blink::CreateTensorResultPtr result) {
  pending_resolvers_.erase(resolver);

  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }

  if (result->is_error()) {
    const auto& create_tensor_error = result->get_error();
    resolver->RejectWithDOMException(
        WebNNErrorCodeToDOMExceptionCode(create_tensor_error->code),
        create_tensor_error->message);
    return;
  }

  auto* tensor = MakeGarbageCollected<MLTensor>(
      resolver->GetExecutionContext(), this, std::move(validated_descriptor),
      usage, std::move(result->get_success()), base::PassKey<MLContext>());
  tensors_.insert(tensor);

  resolver->Resolve(tensor);
}

}  // namespace blink

"""


```