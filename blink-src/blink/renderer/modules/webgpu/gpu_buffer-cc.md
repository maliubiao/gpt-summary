Response:
Let's break down the thought process to analyze the provided C++ code for `gpu_buffer.cc`.

**1. Understanding the Goal:**

The core request is to understand the functionality of this specific Chromium Blink engine file, especially in relation to JavaScript, HTML, and CSS, and to identify potential user errors and debugging paths.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for keywords and recognizable patterns. This helps in forming initial hypotheses:

* **`#include` statements:** These tell me about dependencies. I see things like `webgpu_interface.h`, `v8_gpu_buffer_descriptor.h`, `dom_exception.h`, `dom_array_buffer.h`, `gpu.h`, `gpu_device.h`, `gpu_queue.h`. This strongly suggests the file is about implementing WebGPU buffer objects within the Blink rendering engine, interacting with the underlying GPU through Dawn (indicated by `dawn_conversions.h`). The presence of `v8` includes suggests interaction with JavaScript.
* **Class Definition `GPUBuffer`:** This is the central entity. The methods within this class will define its functionality.
* **Methods like `Create`, `mapAsync`, `getMappedRange`, `unmap`, `destroy`:** These directly map to WebGPU API calls related to buffer management.
* **`ScriptPromise`:**  Indicates asynchronous operations, likely related to JavaScript promises.
* **`DOMArrayBuffer`:** Points to a way of accessing raw binary data, suggesting interaction with JavaScript typed arrays.
* **Error handling (`ExceptionState`, `DOMExceptionCode`):**  Shows how the code handles invalid operations and reports errors to JavaScript.
* **`mappedAtCreation`:** A key flag for buffer creation.
* **`MapMode` (read/write):**  Relates to how the buffer is mapped for access.

**3. Deduction of Core Functionality:**

Based on the keywords, I can deduce the main purpose of the `GPUBuffer` class:

* **Represents a WebGPU Buffer:**  It's a C++ representation of the JavaScript `GPUBuffer` object.
* **Manages the Underlying GPU Buffer:** It holds a `wgpu::Buffer` (from Dawn) and interacts with the GPU.
* **Handles Mapping and Unmapping:**  Provides mechanisms to access the buffer's content from JavaScript using `mapAsync` and `getMappedRange`.
* **Manages Lifetime:**  Includes methods for creation and destruction (`Create`, `destroy`).
* **Deals with Asynchronous Operations:** `mapAsync` returns a `ScriptPromise`, indicating asynchronous mapping.

**4. Connecting to JavaScript, HTML, and CSS:**

Now, let's link this back to the web development stack:

* **JavaScript:**
    * The presence of `ScriptPromise` and `DOMArrayBuffer` directly links to JavaScript's asynchronous operations and typed arrays. The methods like `mapAsync` and `getMappedRange` are the underlying implementation for the JavaScript WebGPU API.
    * The code handles errors (`ExceptionState`) which will be reflected as JavaScript exceptions.
* **HTML:**
    * While `gpu_buffer.cc` doesn't directly manipulate the HTML DOM, it's part of the rendering pipeline. JavaScript code (within `<script>` tags or linked `.js` files) running in an HTML page will use the WebGPU API, ultimately invoking this C++ code.
* **CSS:**
    *  Similarly, CSS doesn't directly interact with `gpu_buffer.cc`. However, CSS can trigger visual updates that might be powered by WebGPU rendering. For instance, a complex animation or shader effect implemented using WebGPU would involve buffer manipulation handled by this code.

**5. Logical Reasoning and Examples (Hypothetical Input/Output):**

I need to demonstrate how the code works with specific examples. Let's consider `mapAsync`:

* **Hypothetical Input (JavaScript):**
  ```javascript
  const buffer = device.createBuffer({
    size: 1024,
    usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST
  });
  buffer.mapAsync(GPUMapMode.READ).then(() => {
    const arrayBuffer = buffer.getMappedRange();
    // ... access the data ...
    buffer.unmap();
  });
  ```
* **Corresponding Actions in `gpu_buffer.cc`:** The `mapAsync` call in JavaScript would eventually call the `GPUBuffer::MapAsyncImpl` method in C++. This would interact with the underlying Dawn API to initiate the mapping. The promise would resolve when the mapping is complete. `getMappedRange` would then call `GPUBuffer::GetMappedRangeImpl` to return a `DOMArrayBuffer`.

**6. Identifying User and Programming Errors:**

By examining the code, especially the error handling, I can infer common errors:

* **Incorrect `usage` flags:** Creating a buffer without `MAP_READ` or `MAP_WRITE` and then trying to map it.
* **Mapping errors:** Trying to map an already mapped buffer, or mapping with invalid offsets or sizes.
* **Out-of-bounds access:**  Accessing data in the `DOMArrayBuffer` beyond the allocated size.
* **Forgetting to `unmap()`:**  This can lead to resource leaks or unexpected behavior.
* **Destroying a mapped buffer:** This is invalid and the code prevents it.

**7. Debugging Scenario:**

To construct a debugging scenario, I need to think about how a developer might reach this code:

1. **User Action:** A user interacts with a web page that uses WebGPU (e.g., clicks a button that triggers a WebGPU animation).
2. **JavaScript Execution:** The JavaScript code for the animation calls `device.createBuffer()` to create a buffer. This calls `GPUBuffer::Create`.
3. **Mapping the Buffer:** The JavaScript code calls `buffer.mapAsync()`. This calls `GPUBuffer::MapAsyncImpl`.
4. **Error Occurs (Hypothetical):**  Suppose the `MapAsync` call fails on the GPU side (e.g., out of memory). The `OnMapAsyncCallback` would be invoked with an error status.
5. **Rejection of Promise:** The `OnMapAsyncCallback` would reject the JavaScript promise with a `DOMException`.
6. **Developer Debugging:** The developer sees an error in the browser's developer console related to the `mapAsync` promise rejection. They might then set breakpoints in the JavaScript code and potentially within `gpu_buffer.cc` (if they have access to the Chromium source) to understand why the mapping failed.

**8. Refinement and Organization:**

Finally, I'd organize the information logically, using clear headings and examples, as presented in the initial good answer. This involves:

* **Summarizing the core functionality.**
* **Explaining the relationship to web technologies.**
* **Providing concrete examples.**
* **Listing potential errors.**
* **Outlining a debugging scenario.**

This detailed thought process allows for a comprehensive understanding of the code and its role within the larger web development ecosystem. It combines code analysis, knowledge of WebGPU and browser architecture, and a bit of logical deduction to arrive at a useful explanation.
这个文件 `blink/renderer/modules/webgpu/gpu_buffer.cc` 是 Chromium Blink 引擎中关于 WebGPU `GPUBuffer` 接口的实现。它负责管理 GPU 上的内存缓冲区，这些缓冲区可以用来存储各种数据，供 GPU 进行计算或渲染。

以下是它的主要功能：

**1. `GPUBuffer` 对象的创建和管理:**

* **创建:**  `GPUBuffer::Create` 方法负责创建 `GPUBuffer` 对象。它接收一个 `GPUDevice` 对象和一个 `GPUBufferDescriptor` 对象作为参数。`GPUBufferDescriptor` 定义了缓冲区的大小、用途（usage）以及是否在创建时就进行映射（mappedAtCreation）。
* **持有底层 GPU 资源:** `GPUBuffer` 对象内部持有 `wgpu::Buffer` 对象，这是 Dawn 库（WebGPU 的底层实现）中的缓冲区对象，代表了实际的 GPU 内存。
* **大小和用途记录:**  记录了缓冲区的创建大小和用途，可以通过 `size()` 和 `usage()` 方法获取。
* **生命周期管理:**  通过垃圾回收机制进行管理，并在析构函数中释放底层 `wgpu::Buffer` 资源。

**2. 缓冲区映射和取消映射:**

* **`mapAsync()`:**  允许将 GPU 缓冲区的一部分或全部映射到 CPU 可访问的内存空间。这是一个异步操作，返回一个 `ScriptPromise`，在映射完成后 resolve。可以指定映射的模式（读或写）、偏移量和大小。
    * **假设输入:** JavaScript 调用 `buffer.mapAsync(GPUMapMode.READ, 0, 1024)`，尝试将 `buffer` 从偏移量 0 开始的 1024 字节映射为可读。
    * **逻辑推理:**  `MapAsyncImpl` 会被调用，它会调用底层 Dawn 的 `MapAsync` 函数，并注册一个回调函数 `OnMapAsyncCallback`。当 GPU 完成映射后，回调函数会被执行，并且 promise 会 resolve。
    * **假设输出:** 如果映射成功，promise 将 resolve。如果映射失败（例如，缓冲区已经被映射或者参数无效），promise 将 reject，并携带相应的错误信息。
* **`getMappedRange()`:**  在缓冲区已经被成功映射后调用，返回一个 `DOMArrayBuffer` 对象，该对象允许 JavaScript 代码直接访问缓冲区的内容。可以指定访问的偏移量和大小。
    * **假设输入:** 在 `mapAsync` 成功 resolve 后，JavaScript 调用 `buffer.getMappedRange(0, 512)`，获取映射区域从偏移量 0 开始的 512 字节。
    * **逻辑推理:** `GetMappedRangeImpl` 会被调用，它会调用底层 Dawn 的 `GetConstMappedRange` 获取映射区域的指针，并创建一个 `GPUMappedDOMArrayBuffer` 对象。
    * **假设输出:** 返回一个 `DOMArrayBuffer` 对象，其内容指向 GPU 缓冲区中已映射的内存区域。
* **`unmap()`:**  取消缓冲区的映射，使 CPU 无法再访问其内容。在调用 `unmap()` 后，之前通过 `getMappedRange()` 获取的 `DOMArrayBuffer` 将变为 detached，无法再使用。
* **`mapState()`:**  返回当前缓冲区的映射状态，例如 `unmapped`，`pending`，`mapped`。

**3. 缓冲区销毁:**

* **`destroy()`:**  显式地销毁 `GPUBuffer` 对象。销毁后，该缓冲区将无法再被映射或使用。

**4. 与 JavaScript, HTML, CSS 的关系:**

`GPUBuffer` 是 WebGPU API 的一部分，主要通过 JavaScript 进行交互。

* **JavaScript:**
    * JavaScript 代码使用 `device.createBuffer()` 方法创建 `GPUBuffer` 对象。
    * 使用 `buffer.mapAsync()` 和 `buffer.getMappedRange()` 将缓冲区映射到 CPU 可访问的内存，并获取 `DOMArrayBuffer` 进行数据读写。
    * 使用 `buffer.unmap()` 取消映射。
    * 使用 `buffer.destroy()` 销毁缓冲区。
    * **举例:** 一个 JavaScript WebGPU 应用可能创建一个用于存储顶点数据的 `GPUBuffer`，使用 `mapAsync` 将数据上传到缓冲区，然后在渲染循环中使用该缓冲区进行绘制。
* **HTML:**
    * HTML 文件通过 `<script>` 标签引入 JavaScript 代码，这些代码可以调用 WebGPU API，包括创建和操作 `GPUBuffer`。
    * **举例:** 一个 HTML 页面包含一个 `<canvas>` 元素，JavaScript 代码获取该 canvas 的 WebGPU 上下文，并创建 `GPUBuffer` 来渲染图形。
* **CSS:**
    * CSS 本身不直接操作 `GPUBuffer`。但是，CSS 样式可能会触发浏览器的渲染过程，而 WebGPU 可以作为渲染的后端，使用 `GPUBuffer` 来存储渲染所需的数据。
    * **举例:** 一个使用 CSS `transform` 属性进行复杂动画的元素，其渲染过程可能由 WebGPU 完成，并使用 `GPUBuffer` 来存储顶点或纹理数据。

**5. 逻辑推理的假设输入与输出:**

* **假设输入:** JavaScript 调用 `buffer.getMappedRange(100)`，尝试获取已映射缓冲区从偏移量 100 字节到末尾的映射区域。
* **逻辑推理:** `GetMappedRangeImpl` 会计算出需要的映射大小（`size_ - 100`），然后尝试获取指向该区域的指针并创建 `DOMArrayBuffer`。
* **假设输出:** 如果缓冲区已成功映射且偏移量有效，将返回一个 `DOMArrayBuffer`，其 `byteLength` 属性为 `buffer.size() - 100`。如果缓冲区未映射或偏移量超出范围，则会抛出异常并返回 `nullptr`。

**6. 用户或编程常见的使用错误:**

* **在缓冲区未映射时调用 `getMappedRange()`:**  这是不允许的，会导致 `OperationError` 异常。
    * **举例:**
    ```javascript
    const buffer = device.createBuffer({ size: 1024, usage: GPUBufferUsage.MAP_READ });
    const mappedRange = buffer.getMappedRange(); // 错误：缓冲区尚未映射
    ```
* **映射已经被映射的缓冲区:**  尝试在缓冲区已经通过 `mapAsync()` 映射后再次调用 `mapAsync()` 或 `getMappedRange()`，会导致 `OperationError` 异常。
* **在 `mapAsync()` 的回调函数完成之前调用 `getMappedRange()`:**  由于 `mapAsync()` 是异步的，必须等待 promise resolve 后才能安全地调用 `getMappedRange()`。
* **忘记调用 `unmap()`:**  持续映射缓冲区会占用资源，可能导致性能问题或内存泄漏。
* **在缓冲区映射后尝试销毁它:**  会导致错误，必须先 `unmap()` 才能 `destroy()`。
* **在 `getMappedRange()` 返回的 `DOMArrayBuffer` detached 后继续使用它:**  `unmap()` 会导致 `DOMArrayBuffer` detached，此时访问其内容会抛出异常。
* **`mapAsync()` 指定的偏移量或大小超出缓冲区范围:**  会导致 `RangeError` 异常。

**7. 用户操作到达此处的调试线索:**

要调试 `GPUBuffer` 相关的问题，可以按照以下步骤追踪用户操作：

1. **用户在网页上执行某些操作:** 例如，点击按钮、滚动页面、进行交互等。
2. **JavaScript 代码响应用户操作:**  用户的操作会触发 JavaScript 事件监听器中的代码。
3. **JavaScript 代码调用 WebGPU API:**  例如，调用 `device.createBuffer()` 创建缓冲区，或者调用 `buffer.mapAsync()` 映射缓冲区。
4. **Blink 引擎处理 WebGPU API 调用:**  JavaScript 的 WebGPU API 调用会被传递到 Blink 引擎的 WebGPU 模块。
5. **`GPUBuffer::Create` 或 `GPUBuffer::MapAsyncImpl` 等方法被调用:**  根据 JavaScript 的调用，会执行 `gpu_buffer.cc` 中的相应方法。
6. **底层 Dawn 库交互:**  `GPUBuffer` 的实现会调用 Dawn 库的接口来与 GPU 驱动进行交互。
7. **GPU 操作:**  GPU 执行缓冲区创建或映射等操作。
8. **回调函数执行:**  对于异步操作（如 `mapAsync()`），当 GPU 完成操作后，会调用预先注册的回调函数。
9. **Promise 的 resolve 或 reject:**  回调函数会根据 GPU 操作的结果 resolve 或 reject 相应的 JavaScript Promise。
10. **JavaScript 代码处理 Promise 的结果:**  JavaScript 代码根据 Promise 的状态执行后续操作。

**调试线索:**

* **浏览器开发者工具的 Console 面板:**  查看是否有 JavaScript 错误或警告信息，特别是与 WebGPU 相关的错误。
* **浏览器开发者工具的 Sources 面板:**  在 JavaScript 代码中设置断点，追踪 WebGPU API 的调用过程。
* **Chrome 的 `chrome://gpu` 页面:**  查看 GPU 的状态信息、WebGPU 的支持情况以及是否有相关的错误报告。
* **Blink 渲染器的日志输出:**  在 Chromium 的开发版本中，可以启用详细的渲染器日志，以查看 WebGPU 相关的操作和错误信息。
* **WebGPU API 的错误处理:**  确保 JavaScript 代码正确处理了 WebGPU API 调用返回的 Promise 的 rejection，并输出了有用的错误信息。

总而言之，`gpu_buffer.cc` 是 WebGPU 中至关重要的一个文件，它负责管理 GPU 上的内存资源，并提供 JavaScript 接口来访问和操作这些资源，从而实现高性能的图形渲染和并行计算。理解其功能和潜在的错误场景对于开发 WebGPU 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webgpu/gpu_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/gpu_buffer.h"

#include <cinttypes>
#include <utility>

#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "gpu/command_buffer/client/webgpu_interface.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_buffer_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_buffer_map_state.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_queue.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_callback.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// A size that if used to create a dawn_wire buffer, will guarantee we'll OOM
// immediately. It is an implementation detail of dawn_wire but that's tested
// on CQ in Dawn. Note that we set kGuaranteedBufferOOMSize to
// (wgpu::kWholeMapSize - 1) to ensure we never pass wgpu::kWholeMapSize from
// blink to wire_client.
constexpr uint64_t kGuaranteedBufferOOMSize = wgpu::kWholeMapSize - 1u;

wgpu::BufferDescriptor AsDawnType(const GPUBufferDescriptor* webgpu_desc,
                                  std::string* label) {
  DCHECK(webgpu_desc);
  DCHECK(label);

  wgpu::BufferDescriptor dawn_desc = {
      .usage = AsDawnFlags<wgpu::BufferUsage>(webgpu_desc->usage()),
      .size = webgpu_desc->size(),
      .mappedAtCreation = webgpu_desc->mappedAtCreation(),
  };
  *label = webgpu_desc->label().Utf8();
  if (!label->empty()) {
    dawn_desc.label = label->c_str();
  }

  return dawn_desc;
}

}  // namespace

// GPUMappedDOMArrayBuffer is returned from mappings created from
// GPUBuffer which point to shared memory. This memory is owned by
// the underlying wgpu::Buffer used to implement GPUBuffer.
// GPUMappedDOMArrayBuffer exists because mapped DOMArrayBuffers need
// to keep their owning GPUBuffer alive, or the shared memory may be
// freed while it is in use. It derives from DOMArrayBuffer and holds
// a Member<GPUBuffer> to its owner. Alternative ideas might be to keep
// the wgpu::Buffer alive using a custom deleter of v8::BackingStore or
// ArrayBufferContents. However, since these are non-GC objects, it
// becomes complex to handle destruction when the last reference to
// the wgpu::Buffer may be held either by a GC object, or a non-GC object.
class GPUMappedDOMArrayBuffer : public DOMArrayBuffer {
  static constexpr char kWebGPUBufferMappingDetachKey[] = "WebGPUBufferMapping";

 public:
  static GPUMappedDOMArrayBuffer* Create(v8::Isolate* isolate,
                                         GPUBuffer* owner,
                                         ArrayBufferContents contents) {
    auto* mapped_array_buffer = MakeGarbageCollected<GPUMappedDOMArrayBuffer>(
        owner, std::move(contents));
    mapped_array_buffer->SetDetachKey(isolate, kWebGPUBufferMappingDetachKey);
    return mapped_array_buffer;
  }

  GPUMappedDOMArrayBuffer(GPUBuffer* owner, ArrayBufferContents contents)
      : DOMArrayBuffer(std::move(contents)), owner_(owner) {}
  ~GPUMappedDOMArrayBuffer() override = default;

  void DetachContents(v8::Isolate* isolate) {
    if (IsDetached()) {
      return;
    }
    NonThrowableExceptionState exception_state;
    // Detach the array buffer by transferring the contents out and dropping
    // them.
    ArrayBufferContents contents;
    bool result = DOMArrayBuffer::Transfer(
        isolate, V8AtomicString(isolate, kWebGPUBufferMappingDetachKey),
        contents, exception_state);
    // TODO(crbug.com/1326210): Temporary CHECK to prevent aliased array
    // buffers.
    CHECK(result && IsDetached());
  }

  // Due to an unusual non-owning backing these array buffers can't be shared
  // for internal use.
  bool ShareNonSharedForInternalUse(ArrayBufferContents& result) override {
    result.Detach();
    return false;
  }

  void Trace(Visitor* visitor) const override {
    DOMArrayBuffer::Trace(visitor);
    visitor->Trace(owner_);
  }

 private:
  Member<GPUBuffer> owner_;
};

// static
GPUBuffer* GPUBuffer::Create(GPUDevice* device,
                             const GPUBufferDescriptor* webgpu_desc,
                             ExceptionState& exception_state) {
  DCHECK(device);

  std::string label;
  wgpu::BufferDescriptor dawn_desc = AsDawnType(webgpu_desc, &label);

  // Save the requested size of the buffer, for reflection and defaults.
  uint64_t buffer_size = dawn_desc.size;
  // If the buffer is mappable, make sure the size stays in a size_t but still
  // guarantees that we have an OOM.
  bool is_mappable = dawn_desc.usage & (wgpu::BufferUsage::MapRead |
                                        wgpu::BufferUsage::MapWrite) ||
                     dawn_desc.mappedAtCreation;
  if (is_mappable) {
    dawn_desc.size = std::min(dawn_desc.size, kGuaranteedBufferOOMSize);
  }

  wgpu::Buffer wgpuBuffer = device->GetHandle().CreateBuffer(&dawn_desc);
  // dawn_wire::client will return nullptr when mappedAtCreation == true and
  // dawn_wire::client fails to allocate memory for initializing an active
  // buffer mapping, which is required by latest WebGPU SPEC.
  if (wgpuBuffer == nullptr) {
    DCHECK(dawn_desc.mappedAtCreation);
    exception_state.ThrowRangeError(
        WTF::String::Format("createBuffer failed, size (%" PRIu64
                            ") is too large for "
                            "the implementation when "
                            "mappedAtCreation == true",
                            buffer_size));
    return nullptr;
  }

  GPUBuffer* buffer = MakeGarbageCollected<GPUBuffer>(
      device, buffer_size, std::move(wgpuBuffer), webgpu_desc->label());

  if (is_mappable) {
    GPU* gpu = device->adapter()->gpu();
    gpu->TrackMappableBuffer(buffer);
    device->TrackMappableBuffer(buffer);
    buffer->mappable_buffer_handles_ = gpu->mappable_buffer_handles();
  }

  return buffer;
}

GPUBuffer::GPUBuffer(GPUDevice* device,
                     uint64_t size,
                     wgpu::Buffer buffer,
                     const String& label)
    : DawnObject<wgpu::Buffer>(device, std::move(buffer), label), size_(size) {}

GPUBuffer::~GPUBuffer() {
  if (mappable_buffer_handles_) {
    mappable_buffer_handles_->erase(GetHandle());
  }
}

void GPUBuffer::Trace(Visitor* visitor) const {
  visitor->Trace(mapped_array_buffers_);
  DawnObject<wgpu::Buffer>::Trace(visitor);
}

ScriptPromise<IDLUndefined> GPUBuffer::mapAsync(
    ScriptState* script_state,
    uint32_t mode,
    uint64_t offset,
    ExceptionState& exception_state) {
  return MapAsyncImpl(script_state, mode, offset, std::nullopt,
                      exception_state);
}

ScriptPromise<IDLUndefined> GPUBuffer::mapAsync(
    ScriptState* script_state,
    uint32_t mode,
    uint64_t offset,
    uint64_t size,
    ExceptionState& exception_state) {
  return MapAsyncImpl(script_state, mode, offset, size, exception_state);
}

DOMArrayBuffer* GPUBuffer::getMappedRange(ScriptState* script_state,
                                          uint64_t offset,
                                          ExceptionState& exception_state) {
  return GetMappedRangeImpl(script_state, offset, std::nullopt,
                            exception_state);
}

DOMArrayBuffer* GPUBuffer::getMappedRange(ScriptState* script_state,
                                          uint64_t offset,
                                          uint64_t size,
                                          ExceptionState& exception_state) {
  return GetMappedRangeImpl(script_state, offset, size, exception_state);
}

void GPUBuffer::unmap(v8::Isolate* isolate) {
  ResetMappingState(isolate);
  GetHandle().Unmap();
}

void GPUBuffer::destroy(v8::Isolate* isolate) {
  ResetMappingState(isolate);
  GetHandle().Destroy();
  // Destroyed, so it can never be mapped again. Stop tracking.
  device_->adapter()->gpu()->UntrackMappableBuffer(this);
  device_->UntrackMappableBuffer(this);
  // Drop the reference to the mapped buffer handles. No longer
  // need to remove the wgpu::Buffer from this set in ~GPUBuffer.
  mappable_buffer_handles_ = nullptr;
}

uint64_t GPUBuffer::size() const {
  return size_;
}

uint32_t GPUBuffer::usage() const {
  return static_cast<uint32_t>(GetHandle().GetUsage());
}

V8GPUBufferMapState GPUBuffer::mapState() const {
  return FromDawnEnum(GetHandle().GetMapState());
}

ScriptPromise<IDLUndefined> GPUBuffer::MapAsyncImpl(
    ScriptState* script_state,
    uint32_t mode,
    uint64_t offset,
    std::optional<uint64_t> size,
    ExceptionState& exception_state) {
  // Compute the defaulted size which is "until the end of the buffer" or 0 if
  // offset is past the end of the buffer.
  uint64_t size_defaulted = 0;
  if (size) {
    size_defaulted = *size;
  } else if (offset <= size_) {
    size_defaulted = size_ - offset;
  }

  // We need to convert from uint64_t to size_t. Either of these two variables
  // are bigger or equal to the guaranteed OOM size then mapAsync should be an
  // error so. That OOM size fits in a size_t so we can clamp size and offset
  // with it.
  size_t map_offset =
      static_cast<size_t>(std::min(offset, kGuaranteedBufferOOMSize));
  size_t map_size =
      static_cast<size_t>(std::min(size_defaulted, kGuaranteedBufferOOMSize));

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  // And send the command, leaving remaining validation to Dawn.
  auto* callback = MakeWGPUOnceCallback(resolver->WrapCallbackInScriptScope(
      WTF::BindOnce(&GPUBuffer::OnMapAsyncCallback, WrapPersistent(this))));

  GetHandle().MapAsync(static_cast<wgpu::MapMode>(mode), map_offset, map_size,
                       wgpu::CallbackMode::AllowSpontaneous,
                       callback->UnboundCallback(), callback->AsUserdata());

  // WebGPU guarantees that promises are resolved in finite time so we
  // need to ensure commands are flushed.
  EnsureFlush(ToEventLoop(script_state));
  return promise;
}

DOMArrayBuffer* GPUBuffer::GetMappedRangeImpl(ScriptState* script_state,
                                              uint64_t offset,
                                              std::optional<uint64_t> size,
                                              ExceptionState& exception_state) {
  // Compute the defaulted size which is "until the end of the buffer" or 0 if
  // offset is past the end of the buffer.
  uint64_t size_defaulted = 0;
  if (size) {
    size_defaulted = *size;
  } else if (offset <= size_) {
    size_defaulted = size_ - offset;
  }

  // We need to convert from uint64_t to size_t. Either of these two variables
  // are bigger or equal to the guaranteed OOM size then getMappedRange should
  // be an error so. That OOM size fits in a size_t so we can clamp size and
  // offset with it.
  size_t range_offset =
      static_cast<size_t>(std::min(offset, kGuaranteedBufferOOMSize));
  size_t range_size =
      static_cast<size_t>(std::min(size_defaulted, kGuaranteedBufferOOMSize));

  if (range_size > std::numeric_limits<size_t>::max() - range_offset) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        WTF::String::Format(
            "getMappedRange failed, offset(%zu) + size(%zu) overflows size_t",
            range_offset, range_size));
    return nullptr;
  }
  size_t range_end = range_offset + range_size;

  // Check if an overlapping range has already been returned.
  // TODO: keep mapped_ranges_ sorted (e.g. std::map), and do a binary search
  // (e.g. map.upper_bound()) to make this O(lg(n)) instead of linear.
  // (Note: std::map is not allowed in Blink.)
  for (const auto& overlap_candidate : mapped_ranges_) {
    size_t candidate_start = overlap_candidate.first;
    size_t candidate_end = overlap_candidate.second;
    if (range_end > candidate_start && range_offset < candidate_end) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kOperationError,
          WTF::String::Format("getMappedRange [%zu, %zu) overlaps with "
                              "previously returned range [%zu, %zu).",
                              range_offset, range_end, candidate_start,
                              candidate_end));
      return nullptr;
    }
  }

  // And send the command, leaving remaining validation to Dawn.
  const void* map_data_const =
      GetHandle().GetConstMappedRange(range_offset, range_size);

  if (!map_data_const) {
    // Ensure that GPU process error messages are bubbled back to the renderer process.
    EnsureFlush(ToEventLoop(script_state));
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "getMappedRange failed");
    return nullptr;
  }

  // The maximum size that can be mapped in JS so that we can ensure we don't
  // create mappable buffers bigger than it. According to ECMAScript SPEC, a
  // RangeError exception will be thrown if it is impossible to allocate an
  // array buffer.
  // This could eventually be upgrade to the max ArrayBuffer size instead of the
  // max TypedArray size. See crbug.com/951196
  // Note that we put this check after the checks in Dawn because the latest
  // WebGPU SPEC requires the checks on the buffer state (mapped or not) should
  // be done before the creation of ArrayBuffer.
  if (range_size > v8::TypedArray::kMaxByteLength) {
    exception_state.ThrowRangeError(
        WTF::String::Format("getMappedRange failed, size (%zu) is too large "
                            "for the implementation. max size = %zu",
                            range_size, v8::TypedArray::kMaxByteLength));
    return nullptr;
  }

  // It is safe to const_cast the |data| pointer because it is a shadow
  // copy that Dawn wire makes and does not point to the mapped GPU
  // data. Dawn wire's copy of the data is not used outside of tests.
  uint8_t* map_data =
      const_cast<uint8_t*>(static_cast<const uint8_t*>(map_data_const));

  mapped_ranges_.push_back(std::make_pair(range_offset, range_end));
  return CreateArrayBufferForMappedData(script_state->GetIsolate(), map_data,
                                        range_size);
}

void GPUBuffer::OnMapAsyncCallback(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    wgpu::MapAsyncStatus status,
    wgpu::StringView message) {
  switch (status) {
    case wgpu::MapAsyncStatus::Success:
      resolver->Resolve();
      break;
    case wgpu::MapAsyncStatus::InstanceDropped:
      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError,
                                       String::FromUTF8(message));
      break;
    case wgpu::MapAsyncStatus::Error:
      resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                       String::FromUTF8(message));
      break;
    case wgpu::MapAsyncStatus::Aborted:
      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError,
                                       String::FromUTF8(message));
      break;
    case wgpu::MapAsyncStatus::Unknown:
      resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                       String::FromUTF8(message));
      break;
  }
}

DOMArrayBuffer* GPUBuffer::CreateArrayBufferForMappedData(v8::Isolate* isolate,
                                                          void* data,
                                                          size_t data_length) {
  DCHECK(data);
  DCHECK_LE(static_cast<uint64_t>(data_length), v8::TypedArray::kMaxByteLength);

  ArrayBufferContents contents(v8::ArrayBuffer::NewBackingStore(
      data, data_length, v8::BackingStore::EmptyDeleter, nullptr));
  GPUMappedDOMArrayBuffer* array_buffer =
      GPUMappedDOMArrayBuffer::Create(isolate, this, contents);
  mapped_array_buffers_.push_back(array_buffer);
  return array_buffer;
}

void GPUBuffer::ResetMappingState(v8::Isolate* isolate) {
  mapped_ranges_.clear();
  DetachMappedArrayBuffers(isolate);
}

void GPUBuffer::DetachMappedArrayBuffers(v8::Isolate* isolate) {
  for (Member<GPUMappedDOMArrayBuffer>& mapped_array_buffer :
       mapped_array_buffers_) {
    GPUMappedDOMArrayBuffer* array_buffer = mapped_array_buffer.Release();
    array_buffer->DetachContents(isolate);
  }
  mapped_array_buffers_.clear();
}

}  // namespace blink

"""

```