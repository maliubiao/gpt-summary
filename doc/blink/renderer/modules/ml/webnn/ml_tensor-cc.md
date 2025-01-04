Response:
Let's break down the thought process for analyzing this `ml_tensor.cc` file.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to imports, class names, function names, and comments. This gives a general idea of the file's purpose.

* **Imports:**  `third_party/blink/renderer/modules/ml/webnn/...`, `services/webnn/public/...`,  `third_party/blink/renderer/bindings/modules/v8/...`. These strongly suggest this code is part of the Web Neural Network (WebNN) implementation in the Blink rendering engine. The `ml_tensor` name is a big clue about its function.
* **Class Name:** `MLTensor`. This confirms the file is about the `MLTensor` class.
* **Function Names:**  `ReadTensorImpl`, `WriteTensorImpl`, `destroy`, `dataType`, `shape`, `importableToWebGPU`, `readable`, `writable`, `OnDidReadTensor`, `OnDidReadTensorByob`, `OnConnectionError`. These functions clearly relate to managing the lifecycle and data access of a tensor.
* **Comments:**  The copyright notice and the comment in `destroy()` are helpful for context.

**2. Identify Key Responsibilities:**

Based on the initial skim, the core responsibilities of `MLTensor` seem to be:

* **Representing a WebNN tensor:**  Holding data about the tensor (shape, data type, usage).
* **Interfacing with the WebNN service:** Communicating with a lower-level service to perform operations on the tensor (reading, writing).
* **Managing asynchronous operations:** Handling the asynchronous nature of reading tensor data, likely using Promises.
* **Error handling:**  Dealing with potential errors during tensor operations (e.g., tensor destroyed, invalid state).
* **Resource management:**  Releasing resources when the tensor is no longer needed.

**3. Analyze Key Functions in Detail:**

Now, dive deeper into the important functions:

* **Constructor (`MLTensor::MLTensor`):**  Focus on how the tensor is created. It receives a `webnn::OperandDescriptor`, `webnn::MLTensorUsage`, and a `webnn::mojom::blink::CreateTensorSuccessPtr`. This confirms it's created through an interaction with the WebNN service. The binding of `remote_tensor_` is crucial for the communication.
* **`ReadTensorImpl` (overloads):** These methods are the primary way to read tensor data. Notice the use of `ScriptPromise` indicating asynchronous behavior. The overloads handle reading into a new `DOMArrayBuffer` or an existing `DOMArrayBufferBase`/`DOMArrayBufferView`.
* **`WriteTensorImpl`:**  This is for writing data into the tensor. It directly calls the remote interface.
* **`OnDidReadTensor`, `OnDidReadTensorByob`, `OnDidReadTensorByobView`:** These are callback functions for the asynchronous read operations. They handle the results from the WebNN service, resolving or rejecting the Promises.
* **`destroy` and `OnConnectionError`:** These are crucial for cleanup and error handling when the connection to the WebNN service is lost. The handling of `pending_resolvers_` and `pending_byob_resolvers_` is important to avoid unhandled Promises.
* **Getter methods (`dataType`, `shape`, `importableToWebGPU`, etc.):** These provide access to the tensor's properties.

**4. Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**

Think about how this C++ code connects to the web developer's world:

* **JavaScript:** The `MLTensor` class is likely exposed to JavaScript through the WebNN API. The `ScriptPromise` usage directly connects to JavaScript Promises. The data transfer involves `DOMArrayBuffer` and `DOMArrayBufferView`, which are JavaScript types.
* **HTML:** While not directly related to rendering or layout, WebNN (and thus `MLTensor`) is used within web pages. An HTML page would contain JavaScript that uses the WebNN API.
* **CSS:**  No direct relationship. WebNN is about computation, not styling.

**5. Consider Logic and Input/Output:**

Focus on the core logic of reading and writing:

* **`ReadTensorImpl`:**
    * **Input (Conceptual):**  A request from JavaScript to read the tensor.
    * **Output (Asynchronous):** A `Promise` that resolves with the tensor data (as a `DOMArrayBuffer`) or rejects with an error.
* **`WriteTensorImpl`:**
    * **Input:**  Data (as `base::span<const uint8_t>`) to write into the tensor.
    * **Output:** (Implicit) The tensor's data in the WebNN service is updated.

**6. Think About User/Programming Errors:**

Consider common mistakes developers might make:

* **Reading a destroyed tensor:**  Calling `readTensor` after `destroy()` has been called.
* **Providing an undersized buffer for `ReadTensor` with BYOB:** Not allocating enough space in the destination buffer.
* **Detached buffers:** Trying to read into a detached `ArrayBuffer`.
* **Incorrect data types:** Although not directly handled in *this* file, the overall WebNN API would involve checking data type compatibility.

**7. Construct a Debugging Scenario:**

Imagine a developer encountering an error. How did they get there?

* **Start with a basic use case:**  A web page using the WebNN API to perform some ML inference.
* **Introduce a potential problem:**  The inference fails, or the data read back is incorrect.
* **Trace back through the code:**  The developer might set breakpoints in `ReadTensorImpl` or the `OnDidReadTensor` callbacks to see what's happening with the data and the Promise. They might check if the tensor is still bound.

**8. Organize and Refine:**

Finally, structure the findings clearly, using headings and bullet points as in the example answer. Ensure the explanations are concise and easy to understand for someone familiar with web development concepts. Review and refine the wording for clarity and accuracy.

This systematic approach helps to thoroughly analyze the code and understand its purpose, interactions, and potential issues.
好的，我们来分析一下 `blink/renderer/modules/ml/webnn/ml_tensor.cc` 这个文件。

**文件功能概要:**

`ml_tensor.cc` 文件定义了 Blink 渲染引擎中用于表示 WebNN (Web Neural Network API) 张量 (`MLTensor`) 的 C++ 类。这个类负责：

1. **封装 WebNN 张量数据和元信息:**  它存储了张量的形状 (shape)、数据类型 (data type)、以及用途 (usage) 等信息。
2. **与 WebNN 服务通信:** 它通过 `remote_tensor_` 成员与底层的 WebNN 服务进行通信，执行诸如读取和写入张量数据的操作。
3. **管理张量的生命周期:**  它提供了 `destroy()` 方法来释放与张量相关的资源。
4. **实现异步读取操作:**  它提供了 `ReadTensorImpl()` 方法来异步地从 WebNN 服务读取张量数据，并使用 Promise 来处理异步结果。
5. **处理读取结果回调:**  它定义了 `OnDidReadTensor` 和 `OnDidReadTensorByob` 等回调函数来处理从 WebNN 服务读取数据后的结果，包括成功和失败的情况。
6. **实现同步写入操作:** 它提供了 `WriteTensorImpl()` 方法来同步地将数据写入到 WebNN 服务中的张量。
7. **处理连接错误:**  它定义了 `OnConnectionError()` 方法来处理与 WebNN 服务的连接断开的情况。
8. **与 JavaScript 层交互:**  它通过 Blink 的绑定机制与 JavaScript 层进行交互，使得 JavaScript 代码可以创建和操作 `MLTensor` 对象。
9. **记录性能指标:** 它使用 `base::UmaHistogramMediumTimes` 记录读取张量数据所花费的时间。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    * **直接关联:** `MLTensor` 类是 WebNN API 的一部分，在 JavaScript 中可以直接创建和使用 `MLTensor` 对象。例如，JavaScript 代码可以调用 `MLContext.createTensor()` 方法来创建一个 `MLTensor` 实例。
    * **数据交互:** `MLTensor` 的 `read()` 方法返回一个 Promise，该 Promise 解析为包含张量数据的 `ArrayBuffer`。JavaScript 可以使用这个 `ArrayBuffer` 来访问张量的数据。`WriteTensorImpl` 接收 `base::span<const uint8_t>`，这意味着 JavaScript 传递的 `ArrayBuffer` 或 `TypedArray` 的底层数据会被传递到 C++ 层进行写入。
    * **事件处理:**  当与 WebNN 服务的连接断开时，`OnConnectionError()` 会被调用，这可能会导致之前挂起的 Promise 被拒绝，从而在 JavaScript 中触发相应的错误处理逻辑。

    **举例说明 (JavaScript):**

    ```javascript
    const builder = new MLGraphBuilder();
    const inputShape = [1, 28, 28, 1];
    const inputTensor = builder.input('input', { type: 'float32', dimensions: inputShape });

    // ... 构建模型 ...

    const outputTensor = // ... 模型输出张量 ...

    const outputBuffer = await context.compute(graph, { input: inputTensor }).outputs.get(outputTensor);
    console.log('输出张量数据:', outputBuffer);

    // 读取一个已存在的张量
    const existingTensor = // ... 获取已存在的 MLTensor 对象 ...
    const tensorData = await existingTensor.read();
    console.log('读取到的张量数据:', tensorData);

    // 写入数据到张量 (假设 tensor 是一个可写的 MLTensor)
    const writeBuffer = new Float32Array([1, 2, 3, 4]).buffer;
    tensor.write(writeBuffer);
    ```

* **HTML:**
    * **间接关联:** HTML 文件中嵌入的 `<script>` 标签内的 JavaScript 代码可以使用 WebNN API，从而间接地与 `MLTensor` 类产生关联。用户在浏览器中加载和运行包含 WebNN 代码的 HTML 页面时，会触发 `MLTensor` 类的创建和操作。

* **CSS:**
    * **无直接关联:** CSS 主要负责页面的样式和布局，与 `MLTensor` 的功能没有直接关系。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用了 `MLTensor` 对象的 `read()` 方法：

* **假设输入:**
    * JavaScript 调用 `mlTensor.read()`。
    * `mlTensor` 是一个 `MLTensor` 类的实例，并且其 `remote_tensor_` 成员已绑定到 WebNN 服务。
* **内部处理:**
    * `ReadTensorImpl()` 方法被调用。
    * 创建一个 `ScriptPromiseResolver` 来处理异步结果。
    * 调用 `remote_tensor_->ReadTensor()`，向 WebNN 服务发送读取张量数据的请求。
    * 绑定 `OnDidReadTensor` 或 `OnDidReadTensorByob` 作为读取完成后的回调函数。
* **假设输出 (成功):**
    * WebNN 服务成功读取到张量数据。
    * `OnDidReadTensor` 或 `OnDidReadTensorByob` 回调函数被调用，接收到包含张量数据的 `webnn::mojom::blink::ReadTensorResultPtr`。
    * 回调函数将数据封装成 `DOMArrayBuffer` 或直接写入到提供的 `ArrayBuffer` 中。
    * `ScriptPromiseResolver` 的 `resolve()` 方法被调用，将 `DOMArrayBuffer` 返回给 JavaScript。
* **假设输出 (失败):**
    * WebNN 服务读取张量数据失败 (例如，权限错误，张量已被销毁)。
    * `OnDidReadTensor` 或 `OnDidReadTensorByob` 回调函数被调用，接收到包含错误信息的 `webnn::mojom::blink::ReadTensorResultPtr`。
    * 回调函数调用 `ScriptPromiseResolver` 的 `rejectWithDOMException()` 方法，将错误信息传递给 JavaScript 的 Promise。

**用户或编程常见的使用错误:**

1. **在张量被销毁后尝试读取或写入:**
   * **错误场景:** JavaScript 代码调用了 `tensor.destroy()` 后，仍然尝试调用 `tensor.read()` 或 `tensor.write()`。
   * **结果:**  `remote_tensor_.is_bound()` 检查会失败，抛出 `InvalidStateError` 异常。
   * **假设输入:** `MLTensor` 对象已通过 `destroy()` 方法释放了与 WebNN 服务的连接。
   * **输出:**  `ReadTensorImpl` 或 `WriteTensorImpl` 会抛出异常，Promise 会被拒绝。

2. **为 BYOB (Bring Your Own Buffer) 读取提供过小的缓冲区:**
   * **错误场景:** JavaScript 代码调用 `tensor.read(buffer)`，但提供的 `buffer` 的大小小于张量的实际大小。
   * **结果:** `ReadTensorImpl` 方法中的 `dst_data->ByteLength() < PackedByteLength()` 检查会失败，抛出 `TypeError` 异常。
   * **假设输入:** `dst_data->ByteLength()` 的值小于 `PackedByteLength()` 的返回值。
   * **输出:** `ReadTensorImpl` 会抛出 `TypeError` 异常，Promise 会被拒绝。

3. **在读取操作进行中销毁张量:**
   * **错误场景:** JavaScript 代码调用 `tensor.read()` 发起读取操作后，但在 Promise resolve 之前，调用了 `tensor.destroy()`。
   * **结果:**  `OnConnectionError()` 会被调用，它会遍历 `pending_resolvers_` 和 `pending_byob_resolvers_`，并拒绝所有挂起的 Promise，提示 "Tensor has been destroyed or context is lost."。
   * **假设输入:**  `pending_resolvers_` 或 `pending_byob_resolvers_` 中存在未完成的 Promise resolver。
   * **输出:**  对应的 Promise 会被拒绝，JavaScript 代码会捕获到 `InvalidStateError` 异常。

4. **尝试读取不可读的张量或写入不可写的张量:**
   * **错误场景:** 创建张量时指定的 `usage` 不包含 `read` 或 `write` 标志，但尝试调用 `read()` 或 `write()` 方法。
   * **结果:** 虽然这个文件本身没有直接处理这种错误（错误可能在 WebNN 服务或更上层处理），但这是一个潜在的使用错误，会导致操作失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问包含 WebNN 功能的网页:** 用户在浏览器中打开一个使用了 WebNN API 的网页。
2. **JavaScript 代码执行 WebNN 相关操作:** 网页中的 JavaScript 代码调用了 WebNN API，例如 `navigator.ml.requestAdapter()` 获取适配器，然后创建设备、上下文和图。
3. **创建 MLTensor 对象:** JavaScript 代码调用 `MLContext.createTensor()` 方法，这会在 Blink 渲染进程中创建 `MLTensor` 的 C++ 对象。
4. **调用 `read()` 方法 (触发异步读取):** JavaScript 代码调用 `mlTensor.read()` 方法来读取张量的数据。
   * 这会触发 `MLTensor::ReadTensorImpl()` 方法的执行。
   * `ReadTensorImpl()` 会与底层的 WebNN 服务进行通信，请求读取数据。
5. **WebNN 服务处理读取请求:** 底层的 WebNN 服务接收到请求，执行实际的张量数据读取操作。
6. **WebNN 服务返回读取结果:** WebNN 服务将读取结果（成功或失败，以及数据）返回给 Blink 渲染进程。
7. **调用 `OnDidReadTensor` 或 `OnDidReadTensorByob` (处理异步结果):**
   * 当 WebNN 服务返回结果时，与 `ReadTensorImpl()` 中绑定的回调函数 `MLTensor::OnDidReadTensor()` 或 `MLTensor::OnDidReadTensorByob()` 会被调用。
   * 这些回调函数会处理返回的结果，例如将数据封装成 `DOMArrayBuffer` 并 resolve Promise，或者在发生错误时 reject Promise。
8. **JavaScript Promise 状态更新:** JavaScript 中 `read()` 方法返回的 Promise 会根据回调函数的结果变成 resolved 或 rejected 状态，触发相应的 `.then()` 或 `.catch()` 处理。

**调试线索:**

当开发者遇到与 `MLTensor` 相关的错误时，可以按照以下步骤进行调试：

1. **在 JavaScript 代码中设置断点:** 在调用 `read()` 或 `write()` 方法的地方设置断点，查看 `MLTensor` 对象的状态和参数。
2. **在 `ml_tensor.cc` 中设置断点:** 在 `ReadTensorImpl()`, `WriteTensorImpl()`, `OnDidReadTensor()`, `OnDidReadTensorByob()`, `OnConnectionError()` 等关键方法中设置断点，跟踪 C++ 代码的执行流程。
3. **检查 `remote_tensor_.is_bound()` 的状态:** 确保在进行读取或写入操作之前，`remote_tensor_` 成员是绑定的，这意味着与 WebNN 服务的连接是正常的。
4. **查看传递给 `ReadTensorImpl` 的参数:** 尤其是在使用 BYOB 的情况下，检查提供的缓冲区的大小是否足够。
5. **检查 WebNN 服务的返回结果:** 通过日志或调试工具查看 WebNN 服务返回的 `ReadTensorResultPtr` 中的错误信息。
6. **关注 Promise 的状态变化:** 使用浏览器的开发者工具查看 Promise 的状态是 resolved 还是 rejected，以及 rejected 时的错误信息。
7. **检查张量的生命周期:** 确认是否在张量被销毁后仍然尝试对其进行操作。

总而言之，`ml_tensor.cc` 文件是 WebNN API 在 Blink 渲染引擎中的核心实现之一，负责管理张量的生命周期、数据交互以及与底层服务的通信，是连接 JavaScript 和底层机器学习服务的桥梁。理解其功能和交互方式对于调试 WebNN 相关的应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/ml/webnn/ml_tensor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ml/webnn/ml_tensor.h"

#include "base/metrics/histogram_functions.h"
#include "base/types/expected.h"
#include "base/types/expected_macros.h"
#include "services/webnn/public/cpp/ml_tensor_usage.h"
#include "services/webnn/public/cpp/operand_descriptor.h"
#include "services/webnn/public/mojom/webnn_tensor.mojom-blink.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ml_tensor_descriptor.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/ml/ml_context.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_error.h"
#include "third_party/blink/renderer/modules/ml/webnn/ml_graph_utils.h"

namespace blink {

namespace {

void RecordReadTensorTime(base::ElapsedTimer read_tensor_timer) {
  base::UmaHistogramMediumTimes("WebNN.MLTensor.TimingMs.Read",
                                read_tensor_timer.Elapsed());
}

}  // namespace

MLTensor::MLTensor(
    ExecutionContext* execution_context,
    MLContext* context,
    webnn::OperandDescriptor descriptor,
    webnn::MLTensorUsage usage,
    webnn::mojom::blink::CreateTensorSuccessPtr create_tensor_success,
    base::PassKey<MLContext> /*pass_key*/)
    : ml_context_(context),
      descriptor_(std::move(descriptor)),
      usage_(usage),
      webnn_handle_(std::move(create_tensor_success->tensor_handle)),
      remote_tensor_(execution_context) {
  remote_tensor_.Bind(
      std::move(create_tensor_success->tensor_remote),
      execution_context->GetTaskRunner(TaskType::kMachineLearning));
  remote_tensor_.set_disconnect_handler(
      WTF::BindOnce(&MLTensor::OnConnectionError, WrapWeakPersistent(this)));
}

MLTensor::~MLTensor() = default;

void MLTensor::Trace(Visitor* visitor) const {
  visitor->Trace(ml_context_);
  visitor->Trace(remote_tensor_);
  visitor->Trace(pending_resolvers_);
  visitor->Trace(pending_byob_resolvers_);
  ScriptWrappable::Trace(visitor);
}

V8MLOperandDataType MLTensor::dataType() const {
  return ToBlinkDataType(descriptor_.data_type());
}

Vector<uint32_t> MLTensor::shape() const {
  return Vector<uint32_t>(descriptor_.shape());
}

bool MLTensor::importableToWebGPU() const {
  return usage_.Has(webnn::MLTensorUsageFlags::kWebGpuInterop);
}

bool MLTensor::readable() const {
  return usage_.Has(webnn::MLTensorUsageFlags::kRead);
}

bool MLTensor::writable() const {
  return usage_.Has(webnn::MLTensorUsageFlags::kWrite);
}

void MLTensor::destroy() {
  // Calling OnConnectionError() will disconnect and destroy the tensor in
  // the service. The remote tensor must remain unbound after calling
  // OnConnectionError() because it is valid to call destroy() multiple times.
  OnConnectionError();
}

const webnn::OperandDescriptor& MLTensor::Descriptor() const {
  return descriptor_;
}

webnn::OperandDataType MLTensor::DataType() const {
  return descriptor_.data_type();
}

const std::vector<uint32_t>& MLTensor::Shape() const {
  return descriptor_.shape();
}

const webnn::MLTensorUsage& MLTensor::Usage() const {
  return usage_;
}

uint64_t MLTensor::PackedByteLength() const {
  return descriptor_.PackedByteLength();
}

ScriptPromise<DOMArrayBuffer> MLTensor::ReadTensorImpl(
    ScopedMLTrace scoped_trace,
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // Remote context gets automatically unbound when the execution context
  // destructs.
  if (!remote_tensor_.is_bound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Tensor has been destroyed or context is lost.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<DOMArrayBuffer>>(
      script_state, exception_state.GetContext());
  pending_resolvers_.insert(resolver);

  base::ElapsedTimer read_tensor_timer;
  remote_tensor_->ReadTensor(WTF::BindOnce(
      &MLTensor::OnDidReadTensor, WrapPersistent(this), std::move(scoped_trace),
      WrapPersistent(resolver), std::move(read_tensor_timer)));

  return resolver->Promise();
}

ScriptPromise<IDLUndefined> MLTensor::ReadTensorImpl(
    ScopedMLTrace scoped_trace,
    ScriptState* script_state,
    DOMArrayBufferBase* dst_data,
    ExceptionState& exception_state) {
  // Remote context gets automatically unbound when the execution context
  // destructs.
  if (!remote_tensor_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid tensor state");
    return EmptyPromise();
  }

  if (dst_data->ByteLength() < PackedByteLength()) {
    exception_state.ThrowTypeError("The destination tensor is too small.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  pending_byob_resolvers_.insert(resolver);

  base::ElapsedTimer read_tensor_timer;
  remote_tensor_->ReadTensor(
      WTF::BindOnce(&MLTensor::OnDidReadTensorByob, WrapPersistent(this),
                    std::move(scoped_trace), WrapPersistent(resolver),
                    WrapPersistent(dst_data), std::move(read_tensor_timer)));
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> MLTensor::ReadTensorImpl(
    ScopedMLTrace scoped_trace,
    ScriptState* script_state,
    DOMArrayBufferView* dst_data,
    ExceptionState& exception_state) {
  // Remote context gets automatically unbound when the execution context
  // destructs.
  if (!remote_tensor_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid tensor state");
    return EmptyPromise();
  }

  if (dst_data->byteLength() < PackedByteLength()) {
    exception_state.ThrowTypeError("The destination tensor is too small.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  pending_byob_resolvers_.insert(resolver);

  base::ElapsedTimer read_tensor_timer;
  remote_tensor_->ReadTensor(
      WTF::BindOnce(&MLTensor::OnDidReadTensorByobView, WrapPersistent(this),
                    std::move(scoped_trace), WrapPersistent(resolver),
                    WrapPersistent(dst_data), std::move(read_tensor_timer)));
  return resolver->Promise();
}

void MLTensor::OnDidReadTensor(
    ScopedMLTrace scoped_trace,
    ScriptPromiseResolver<DOMArrayBuffer>* resolver,
    base::ElapsedTimer read_tensor_timer,
    webnn::mojom::blink::ReadTensorResultPtr result) {
  pending_resolvers_.erase(resolver);

  if (result->is_error()) {
    const webnn::mojom::blink::Error& read_tensor_error = *result->get_error();
    resolver->RejectWithDOMException(
        WebNNErrorCodeToDOMExceptionCode(read_tensor_error.code),
        read_tensor_error.message);
    return;
  }
  resolver->Resolve(DOMArrayBuffer::Create(result->get_buffer()));

  RecordReadTensorTime(std::move(read_tensor_timer));
}

void MLTensor::OnDidReadTensorByob(
    ScopedMLTrace scoped_trace,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    DOMArrayBufferBase* dst_data,
    base::ElapsedTimer read_tensor_timer,
    webnn::mojom::blink::ReadTensorResultPtr result) {
  pending_byob_resolvers_.erase(resolver);

  if (result->is_error()) {
    const webnn::mojom::blink::Error& read_tensor_error = *result->get_error();
    resolver->RejectWithDOMException(
        WebNNErrorCodeToDOMExceptionCode(read_tensor_error.code),
        read_tensor_error.message);
    return;
  }

  if (dst_data->IsDetached()) {
    resolver->RejectWithTypeError("Buffer was detached.");
    return;
  }

  // It is safe to write into `dst_data` even though it was not transferred
  // because this method is called in a task which runs on same thread where
  // script executes, so script can't observe a partially written state (unless
  // `dst_data` is a SharedArrayBuffer).
  dst_data->ByteSpanMaybeShared().copy_prefix_from(result->get_buffer());
  resolver->Resolve();

  RecordReadTensorTime(std::move(read_tensor_timer));
}

void MLTensor::OnDidReadTensorByobView(
    ScopedMLTrace scoped_trace,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    DOMArrayBufferView* dst_data,
    base::ElapsedTimer read_tensor_timer,
    webnn::mojom::blink::ReadTensorResultPtr result) {
  pending_byob_resolvers_.erase(resolver);

  if (result->is_error()) {
    const webnn::mojom::blink::Error& read_tensor_error = *result->get_error();
    resolver->RejectWithDOMException(
        WebNNErrorCodeToDOMExceptionCode(read_tensor_error.code),
        read_tensor_error.message);
    return;
  }

  if (dst_data->IsDetached()) {
    resolver->RejectWithTypeError("Buffer was detached.");
    return;
  }

  // It is safe to write into `dst_data` even though it was not transferred
  // because this method is called in a task which runs on same thread where
  // script executes, so script can't observe a partially written state (unless
  // `dst_data` is a SharedArrayBuffer).
  dst_data->ByteSpanMaybeShared().copy_prefix_from(result->get_buffer());
  resolver->Resolve();

  RecordReadTensorTime(std::move(read_tensor_timer));
}

void MLTensor::WriteTensorImpl(base::span<const uint8_t> src_data,
                               ExceptionState& exception_state) {
  // Remote context gets automatically unbound when the execution context
  // destructs.
  if (!remote_tensor_.is_bound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Tensor has been destroyed or context is lost.");
    return;
  }

  // Return early since empty written data can be ignored with no observable
  // effect.
  if (src_data.size() == 0) {
    return;
  }

  // Copy src data.
  remote_tensor_->WriteTensor(src_data);
}

void MLTensor::OnConnectionError() {
  remote_tensor_.reset();

  for (const auto& resolver : pending_resolvers_) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Tensor has been destroyed or context is lost.");
  }
  pending_resolvers_.clear();

  for (const auto& resolver : pending_byob_resolvers_) {
    resolver->RejectWithDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Tensor has been destroyed or context is lost.");
  }
  pending_byob_resolvers_.clear();
}

}  // namespace blink

"""

```