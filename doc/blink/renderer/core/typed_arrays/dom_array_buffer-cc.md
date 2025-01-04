Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request is to understand the functionality of `dom_array_buffer.cc` in the Chromium Blink engine, specifically its relation to JavaScript, HTML, CSS, potential errors, and to provide examples.

2. **Initial Scan for Key Information:**  I'll start by quickly skimming the code for keywords and recognizable patterns:
    * `#include`: Lists dependencies, indicating what this file interacts with. `DOMArrayBuffer.h`, `v8_binding.h`, `SharedBuffer.h` are important clues.
    * `namespace blink`: Confirms this is Blink-specific code.
    * `class DOMArrayBuffer`:  The core class this file defines.
    * `wrapper_type_info_`:  Indicates this class interacts with the JavaScript binding system.
    * Methods like `Create`, `IsDetachable`, `Transfer`, `Slice`, `Wrap`, `IsDetached`, `SetDetachKey`: These are the core functionalities.
    * Mentions of `v8::Isolate`, `v8::ArrayBuffer`, `ScriptState`: Strong evidence of JavaScript interaction.

3. **Focus on Core Functionality (the "What"):**  Now, let's go through the methods and try to summarize their purpose:
    * **`DOMArrayBuffer` (constructor/creation methods):**  Handles creating instances of `DOMArrayBuffer` from various sources (size, existing data, `SharedBuffer`). The `CreateOrNull` variants suggest error handling.
    * **`IsDetachable`:**  Checks if the underlying JavaScript `ArrayBuffer` can be detached (a memory optimization technique).
    * **`SetDetachKey`:** Allows setting a key for detaching the buffer, suggesting a security or synchronization mechanism.
    * **`Transfer`:** Moves the underlying data to a new `ArrayBuffer`, potentially detaching the original. The existence of `detach_key` parameter in one overload reinforces the detachment aspect.
    * **`ShareNonSharedForInternalUse`:**  Likely related to internal data sharing within Blink.
    * **`TransferDetachable`:** The core logic for detaching and transferring. It involves iterating over all JavaScript wrappers of this `DOMArrayBuffer`.
    * **`Wrap`:**  Crucial for the JavaScript integration. It creates the corresponding JavaScript `ArrayBuffer` object and links it to the C++ object.
    * **`IsDetached`:** Checks if the `ArrayBuffer` has been detached. The logic involving multiple worlds is interesting and suggests this class needs to handle `ArrayBuffers` across different JavaScript contexts.
    * **`Slice`:** Creates a new `DOMArrayBuffer` representing a portion of the original.

4. **Identify Relationships with JavaScript, HTML, and CSS (the "How"):**
    * **JavaScript:** The presence of `v8::ArrayBuffer`, `ScriptState`, `Wrap`, and the mention of "worlds" strongly indicates direct interaction with JavaScript. `DOMArrayBuffer` is a representation of JavaScript's `ArrayBuffer` in the C++ layer of Blink.
    * **HTML:**  `ArrayBuffer` is used in JavaScript, which is a core part of web pages. Specifically, `ArrayBuffer` is used for handling binary data, often fetched through mechanisms like `XMLHttpRequest` or `fetch`, which are triggered by JavaScript within an HTML context. File uploads are another potential area.
    * **CSS:**  Less direct. While CSS itself doesn't directly manipulate `ArrayBuffers`, if JavaScript uses `ArrayBuffers` to process image data or other resources that are then rendered based on CSS rules, there's an indirect relationship. This is more of a consequence than a direct dependency.

5. **Deduce Logic and Provide Examples (the "Why"):**  Now, based on the functionality, we can infer the reasoning behind certain operations and create example scenarios:
    * **Detaching:** This is an optimization. If a large `ArrayBuffer` is no longer needed in one context, detaching it frees up memory. The `detach_key` adds a layer of control.
    * **Transferring:** Useful for transferring ownership of data between different parts of the JavaScript code or between workers. This avoids unnecessary copying.
    * **Slicing:**  Allows working with portions of a large buffer without creating a full copy.

6. **Identify Potential Errors (the "Pitfalls"):** Look for situations where things could go wrong based on the code's behavior:
    * **Incorrect `detach_key`:**  The `TransferDetachable` logic explicitly checks for this.
    * **Detaching an already detached buffer:**  This could lead to errors or unexpected behavior.
    * **Using a detached buffer:**  Accessing the data of a detached buffer will result in an error.
    * **Memory allocation failure:**  The `CreateOrNull` methods suggest this is a possibility.

7. **Structure the Answer:**  Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logic and Examples, Common Errors. Use bullet points and code snippets to make it easy to understand.

8. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check if the examples are helpful and if the explanations are easy to follow. For instance, initially, I might just say "handles memory," but refining it to "managing raw binary data in memory" is more precise. Similarly, explaining *why* detaching is useful (memory optimization) adds more value.

By following this structured approach, analyzing the code becomes more systematic, allowing for a comprehensive understanding of its purpose and interactions.
好的，让我们来分析一下 `blink/renderer/core/typed_arrays/dom_array_buffer.cc` 这个文件。

**功能概览:**

`DOMArrayBuffer.cc` 文件定义了 Blink 渲染引擎中 `DOMArrayBuffer` 类的实现。`DOMArrayBuffer` 是 JavaScript 中 `ArrayBuffer` 对象的在 C++ 层的表示。它的主要功能是：

1. **管理和操作二进制数据缓冲区:**  `DOMArrayBuffer` 封装了实际的二进制数据存储，提供了创建、访问、修改这块内存区域的方法。
2. **作为 JavaScript `ArrayBuffer` 的底层实现:**  当 JavaScript 代码创建一个 `ArrayBuffer` 对象时，Blink 引擎会在 C++ 层创建一个对应的 `DOMArrayBuffer` 实例来管理实际的内存。
3. **支持 `ArrayBuffer` 的各种操作:**  实现了 JavaScript `ArrayBuffer` 对象暴露的方法，例如 `slice()` (对应 `DOMArrayBuffer::Slice`)，以及用于数据传输和内存管理的方法，例如 `transfer()` 和 `detach()`.
4. **处理跨 JavaScript Context 的 `ArrayBuffer`:**  代码中涉及了 "worlds" 的概念，表示它能够处理在不同 JavaScript 执行上下文（例如主线程和 Worker 线程）中创建的 `ArrayBuffer`。
5. **内存管理和优化:**  实现了 `ArrayBuffer` 的 detach 功能，允许在不再需要时释放底层的内存，或者将内存的所有权转移到另一个 `ArrayBuffer`。
6. **与 V8 JavaScript 引擎的绑定:**  通过 Blink 的绑定机制，将 C++ 的 `DOMArrayBuffer` 对象与 JavaScript 的 `ArrayBuffer` 对象关联起来，使得 JavaScript 代码可以操作底层的二进制数据。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **与 JavaScript 的关系最为直接和紧密:**
    * **创建 `ArrayBuffer`:** 当 JavaScript 代码执行 `new ArrayBuffer(length)` 时，Blink 引擎会调用 `DOMArrayBuffer::CreateOrNull` 或类似的方法创建一个 `DOMArrayBuffer` 实例，并分配指定大小的内存。
    ```javascript
    // JavaScript 代码
    const buffer = new ArrayBuffer(1024); // 创建一个 1KB 的 ArrayBuffer
    ```
    在 Blink 内部，这会触发 `DOMArrayBuffer::CreateOrNull(1024, 1)`。
    * **访问和修改数据:**  JavaScript 通过 `TypedArray` (例如 `Uint8Array`, `Float32Array`) 或 `DataView` 来访问和修改 `ArrayBuffer` 中的数据。这些操作最终会调用 `DOMArrayBuffer` 提供的底层内存访问机制。
    ```javascript
    // JavaScript 代码
    const uint8Array = new Uint8Array(buffer);
    uint8Array[0] = 255; // 修改 ArrayBuffer 的第一个字节
    ```
    这会在 `DOMArrayBuffer` 管理的内存中修改对应的字节。
    * **`slice()` 方法:**  JavaScript 的 `ArrayBuffer.prototype.slice()` 方法对应于 `DOMArrayBuffer::Slice()`。
    ```javascript
    // JavaScript 代码
    const slice = buffer.slice(10, 20); // 创建一个 buffer 的切片
    ```
    这会调用 `DOMArrayBuffer::Slice(10, 20)` 创建一个新的 `DOMArrayBuffer` 对象，共享原始 `DOMArrayBuffer` 的一部分数据。
    * **`transfer()` 和 `detach()`:**  JavaScript 的可转移对象 (Transferable objects) 机制允许将 `ArrayBuffer` 的所有权转移到不同的执行上下文（例如 Web Worker）。这背后涉及到 `DOMArrayBuffer::Transfer()` 和底层的 detach 机制。
    ```javascript
    // JavaScript 代码 (在主线程中)
    const worker = new Worker('worker.js');
    worker.postMessage(buffer, [buffer]); // 将 buffer 的所有权转移给 worker
    ```
    这会触发 `DOMArrayBuffer::Transfer()`，并可能涉及到 `DOMArrayBuffer::Detach()`。

* **与 HTML 的关系:**
    * **通过 `XMLHttpRequest` 或 `fetch` 获取二进制数据:**  当从服务器请求二进制数据时，例如图片、音频或视频，可以使用 `XMLHttpRequest` 的 `responseType = 'arraybuffer'` 或 `fetch` API 来获取 `ArrayBuffer`。
    ```javascript
    // JavaScript 代码
    const xhr = new XMLHttpRequest();
    xhr.open('GET', 'image.png');
    xhr.responseType = 'arraybuffer';
    xhr.onload = function() {
      const arrayBuffer = xhr.response; // 获取到的 ArrayBuffer
      // ... 处理 arrayBuffer
    };
    xhr.send();
    ```
    当 `responseType` 为 `'arraybuffer'` 时，浏览器会将接收到的二进制数据存储在 `DOMArrayBuffer` 中。
    * **`FileReader` API 读取本地文件:**  `FileReader` API 可以将本地文件读取为 `ArrayBuffer`。
    ```javascript
    // JavaScript 代码
    const fileInput = document.getElementById('fileInput');
    fileInput.addEventListener('change', function(e) {
      const file = fileInput.files[0];
      const reader = new FileReader();
      reader.onload = function(event) {
        const arrayBuffer = event.target.result; // 获取到的 ArrayBuffer
        // ... 处理 arrayBuffer
      };
      reader.readAsArrayBuffer(file);
    });
    ```
    `FileReader.readAsArrayBuffer()` 会创建一个 `DOMArrayBuffer` 来存储文件内容。

* **与 CSS 的关系:**  CSS 本身不直接操作 `ArrayBuffer`。但 `ArrayBuffer` 存储的二进制数据可以被 JavaScript 处理后用于 CSS 的渲染。例如：
    * **WebGL:** WebGL 使用 `TypedArray`（基于 `ArrayBuffer`）将顶点数据、纹理数据等传递给 GPU 进行渲染。CSS 的样式可能会影响 WebGL 渲染的最终效果，但 CSS 不直接操作 `ArrayBuffer`。
    * **Canvas API:** 可以使用 `ImageData` 对象来操作 Canvas 的像素数据，而 `ImageData.data` 属性就是一个 `Uint8ClampedArray`，它是 `ArrayBuffer` 的视图。
    ```javascript
    // JavaScript 代码
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data; // Uint8ClampedArray，基于 ArrayBuffer
    // 修改 data 中的像素数据
    for (let i = 0; i < data.length; i += 4) {
      data[i] = 255;   // Red
      data[i+1] = 0;   // Green
      data[i+2] = 0;   // Blue
      data[i+3] = 255; // Alpha
    }
    ctx.putImageData(imageData, 0, 0);
    ```
    虽然 CSS 不直接操作 `ArrayBuffer`，但 JavaScript 可以使用 `ArrayBuffer` 中的数据来动态生成或修改 Canvas 的内容，而 Canvas 的显示最终受到 CSS 样式的控制。

**逻辑推理与假设输入输出:**

**假设输入:** JavaScript 代码尝试创建一个 1024 字节的 `ArrayBuffer`。
```javascript
const buffer = new ArrayBuffer(1024);
```

**逻辑推理:**

1. Blink 的 JavaScript 引擎接收到创建 `ArrayBuffer` 的请求。
2. Blink 内部会调用 `DOMArrayBuffer::CreateOrNull(1024, 1)` (或者类似的创建方法)。
3. `DOMArrayBuffer::CreateOrNull` 尝试分配 1024 字节的内存。
4. 如果内存分配成功，则创建一个新的 `DOMArrayBuffer` 对象，并将其与新分配的内存关联。
5. Blink 的绑定机制会将这个 `DOMArrayBuffer` 对象包装成一个 JavaScript 的 `ArrayBuffer` 对象返回给 JavaScript 代码。

**输出:**  JavaScript 代码中的 `buffer` 变量将引用一个新创建的 `ArrayBuffer` 对象，该对象在 C++ 层由一个 `DOMArrayBuffer` 实例管理，并分配了 1024 字节的内存。

**假设输入:** JavaScript 代码对一个 `ArrayBuffer` 执行 `slice()` 操作。
```javascript
const originalBuffer = new ArrayBuffer(20);
const sliceBuffer = originalBuffer.slice(5, 15);
```

**逻辑推理:**

1. JavaScript 引擎调用与 `ArrayBuffer.prototype.slice()` 对应的 Blink 内部方法。
2. 这个内部方法会调用 `DOMArrayBuffer::Slice(5, 15)`，其中 `this` 指向 `originalBuffer` 对应的 `DOMArrayBuffer` 实例。
3. `DOMArrayBuffer::Slice` 会计算切片的起始和结束位置，并创建一个新的 `DOMArrayBuffer` 对象。
4. 新的 `DOMArrayBuffer` 对象会引用 `originalBuffer` 对应内存区域的子集 (从偏移量 5 开始，长度为 10 字节)。**注意：通常 `slice` 操作不会复制数据，而是创建一个新的视图或引用。**
5. Blink 的绑定机制会将新的 `DOMArrayBuffer` 对象包装成 JavaScript 的 `ArrayBuffer` 对象返回给 JavaScript 代码。

**输出:**  JavaScript 代码中的 `sliceBuffer` 变量将引用一个新的 `ArrayBuffer` 对象，该对象在 C++ 层由一个新的 `DOMArrayBuffer` 实例管理，但它指向 `originalBuffer` 底层内存的一部分。

**涉及用户或编程常见的使用错误:**

1. **尝试操作已分离 (detached) 的 `ArrayBuffer`:**
   * **场景:**  一个 `ArrayBuffer` 被转移到 Web Worker 后，主线程的代码仍然尝试访问或修改它。
   * **错误:**  会抛出 `TypeError` 异常，提示 `ArrayBuffer` 已被分离。
   ```javascript
   // 主线程
   const buffer = new ArrayBuffer(10);
   const worker = new Worker('worker.js');
   worker.postMessage(buffer, [buffer]);
   // ... 稍后 ...
   const view = new Uint8Array(buffer); // 尝试访问已转移的 buffer
   console.log(view[0]); // 可能会抛出 TypeError
   ```
2. **创建过大的 `ArrayBuffer` 导致内存分配失败:**
   * **场景:**  尝试创建一个非常大的 `ArrayBuffer`，超过了可用内存的限制。
   * **错误:**  可能会导致程序崩溃或者抛出异常（取决于具体的实现和环境）。`DOMArrayBuffer::CreateOrNull` 这类方法会返回 `nullptr`。
   ```javascript
   // JavaScript 代码
   try {
     const hugeBuffer = new ArrayBuffer(Number.MAX_SAFE_INTEGER); // 尝试创建非常大的 buffer
   } catch (e) {
     console.error("创建 ArrayBuffer 失败:", e);
   }
   ```
3. **在不适当的时候设置 Detach Key:**
    * **场景:**  多次设置 detach key，或者在已经分离的 `ArrayBuffer` 上设置 detach key。
    * **错误:**  代码中的 `DCHECK(detach_key_.IsEmpty())` 表明，多次设置 detach key 被认为是程序错误，可能会触发断言失败。
    ```c++
    void DOMArrayBuffer::SetDetachKey(v8::Isolate* isolate,
                                     const StringView& detach_key) {
      // It's easy to support setting a detach key multiple times, but it's very
      // likely to be a program error to set a detach key multiple times.
      DCHECK(detach_key_.IsEmpty());
      // ...
    }
    ```
4. **在使用 Transfer 进行数据转移时，误用原始的 `ArrayBuffer`:**
    * **场景:**  将 `ArrayBuffer` 通过 `postMessage` 转移到 Worker 后，主线程仍然假设拥有该 `ArrayBuffer` 的所有权并尝试操作它。
    * **错误:**  会导致数据竞争或访问到已分离的内存。
5. **对 `slice` 操作的误解:**
    * **场景:**  认为 `slice()` 操作会创建数据的深拷贝，并修改切片后的 `ArrayBuffer` 不会影响原始的 `ArrayBuffer`。
    * **错误:**  `slice()` 通常创建的是浅拷贝或视图，修改切片后的 `ArrayBuffer` 可能会影响原始的 `ArrayBuffer` 的数据（如果它们共享底层的内存）。

希望这个详细的分析能够帮助你理解 `DOMArrayBuffer.cc` 的功能和它在 Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/core/typed_arrays/dom_array_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"

#include <algorithm>

#include "base/containers/buffer_iterator.h"
#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

// Construction of WrapperTypeInfo may require non-trivial initialization due
// to cross-component address resolution in order to load the pointer to the
// parent interface's WrapperTypeInfo.  We ignore this issue because the issue
// happens only on component builds and the official release builds
// (statically-linked builds) are never affected by this issue.
#if defined(COMPONENT_BUILD) && defined(WIN32) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wglobal-constructors"
#endif

const WrapperTypeInfo DOMArrayBuffer::wrapper_type_info_body_{
    gin::kEmbedderBlink,
    nullptr,
    nullptr,
    "ArrayBuffer",
    nullptr,
    kDOMWrappersTag,
    kDOMWrappersTag,
    WrapperTypeInfo::kWrapperTypeObjectPrototype,
    WrapperTypeInfo::kObjectClassId,
    WrapperTypeInfo::kNotInheritFromActiveScriptWrappable,
    WrapperTypeInfo::kIdlBufferSourceType,
};

const WrapperTypeInfo& DOMArrayBuffer::wrapper_type_info_ =
    DOMArrayBuffer::wrapper_type_info_body_;

#if defined(COMPONENT_BUILD) && defined(WIN32) && defined(__clang__)
#pragma clang diagnostic pop
#endif

namespace {

template <typename Function>
void ForArrayBuffersInAllWorlds(v8::Isolate* isolate,
                                const DOMArrayBuffer* object,
                                Function f) {
  if (!object->has_non_main_world_wrappers() && IsMainThread()) {
    const DOMWrapperWorld& world = DOMWrapperWorld::MainWorld(isolate);
    v8::Local<v8::Object> wrapper;
    if (world.DomDataStore()
            .Get</*entered_context=*/false>(isolate, object)
            .ToLocal(&wrapper)) {
      f(v8::Local<v8::ArrayBuffer>::Cast(wrapper));
    }
    return;
  }

  HeapVector<Member<DOMWrapperWorld>> worlds;
  DOMWrapperWorld::AllWorldsInIsolate(isolate, worlds);
  for (const auto& world : worlds) {
    v8::Local<v8::Object> wrapper;
    if (world->DomDataStore()
            .Get</*entered_context=*/false>(isolate, object)
            .ToLocal(&wrapper)) {
      f(v8::Local<v8::ArrayBuffer>::Cast(wrapper));
    }
  }
}

}  // namespace

bool DOMArrayBuffer::IsDetachable(v8::Isolate* isolate) {
  v8::HandleScope handle_scope(isolate);
  v8::LocalVector<v8::ArrayBuffer> buffer_handles(isolate);
  bool is_detachable = true;
  ForArrayBuffersInAllWorlds(
      isolate, this,
      [&is_detachable](v8::Local<v8::ArrayBuffer> buffer_handle) {
        is_detachable &= buffer_handle->IsDetachable();
      });
  return is_detachable;
}

void DOMArrayBuffer::SetDetachKey(v8::Isolate* isolate,
                                  const StringView& detach_key) {
  // It's easy to support setting a detach key multiple times, but it's very
  // likely to be a program error to set a detach key multiple times.
  DCHECK(detach_key_.IsEmpty());

  v8::HandleScope handle_scope(isolate);
  v8::LocalVector<v8::ArrayBuffer> buffer_handles(isolate);

  v8::Local<v8::String> v8_detach_key = V8AtomicString(isolate, detach_key);
  detach_key_.Reset(isolate, v8_detach_key);

  ForArrayBuffersInAllWorlds(
      isolate, this,
      [&v8_detach_key](v8::Local<v8::ArrayBuffer> buffer_handle) {
        buffer_handle->SetDetachKey(v8_detach_key);
      });
}

bool DOMArrayBuffer::Transfer(v8::Isolate* isolate,
                              ArrayBufferContents& result,
                              ExceptionState& exception_state) {
  return Transfer(isolate, v8::Local<v8::Value>(), result, exception_state);
}

bool DOMArrayBuffer::Transfer(v8::Isolate* isolate,
                              v8::Local<v8::Value> detach_key,
                              ArrayBufferContents& result,
                              ExceptionState& exception_state) {
  DOMArrayBuffer* to_transfer = this;
  if (!IsDetachable(isolate)) {
    to_transfer = DOMArrayBuffer::Create(Content()->ByteSpan());
  }

  TryRethrowScope rethrow_scope(isolate, exception_state);
  bool detach_result = false;
  if (!to_transfer->TransferDetachable(isolate, detach_key, result)
           .To(&detach_result)) {
    return false;
  }
  if (!detach_result) {
    exception_state.ThrowTypeError("Could not transfer ArrayBuffer.");
    return false;
  }
  return true;
}

bool DOMArrayBuffer::ShareNonSharedForInternalUse(ArrayBufferContents& result) {
  if (!Content()->BackingStore()) {
    result.Detach();
    return false;
  }
  Content()->ShareNonSharedForInternalUse(result);
  return true;
}

v8::Maybe<bool> DOMArrayBuffer::TransferDetachable(
    v8::Isolate* isolate,
    v8::Local<v8::Value> detach_key,
    ArrayBufferContents& result) {
  DCHECK(IsDetachable(isolate));

  if (IsDetached()) {
    result.Detach();
    return v8::Just(false);
  }

  if (!Content()->Data()) {
    // We transfer an empty ArrayBuffer, we can just allocate an empty content.
    result = ArrayBufferContents(Content()->BackingStore());
  } else {
    Content()->Transfer(result);
  }

  v8::HandleScope handle_scope(isolate);
  v8::LocalVector<v8::ArrayBuffer> buffer_handles(isolate);

  bool first = true;
  bool failed = false;
  ForArrayBuffersInAllWorlds(
      isolate, this,
      [&first, &failed, &detach_key](v8::Local<v8::ArrayBuffer> buffer_handle) {
        // Loop to detach all buffer handles. This may throw an exception
        // if the |detach_key| is incorrect. It should either fail for all
        // handles or succeed for all handles. It should never be the case that
        // the handles have different detach keys. CHECK to catch when this
        // invariant is broken.
        if (!failed) {
          bool detach_result = false;
          if (!buffer_handle->Detach(detach_key).To(&detach_result)) {
            CHECK(first);
            failed = true;
          } else {
            // On success, Detach must always return true.
            DCHECK(detach_result);
          }
          first = false;
        }
      });

  if (failed) {
    // Propagate an exception to the caller.
    return v8::Nothing<bool>();
  }

  Detach();
  return v8::Just(true);
}

DOMArrayBuffer* DOMArrayBuffer::Create(
    scoped_refptr<SharedBuffer> shared_buffer) {
  ArrayBufferContents contents(
      shared_buffer->size(), 1, ArrayBufferContents::kNotShared,
      ArrayBufferContents::kDontInitialize,
      ArrayBufferContents::AllocationFailureBehavior::kCrash);
  CHECK(contents.IsValid());

  base::BufferIterator iterator(contents.ByteSpan());
  for (const auto& span : *shared_buffer) {
    iterator.MutableSpan<char>(span.size()).copy_from(span);
  }

  return Create(std::move(contents));
}

DOMArrayBuffer* DOMArrayBuffer::Create(
    const Vector<base::span<const char>>& data) {
  size_t size = 0;
  for (const auto& span : data) {
    size += span.size();
  }
  ArrayBufferContents contents(
      size, 1, ArrayBufferContents::kNotShared,
      ArrayBufferContents::kDontInitialize,
      ArrayBufferContents::AllocationFailureBehavior::kCrash);
  CHECK(contents.IsValid());

  base::BufferIterator iterator(contents.ByteSpan());
  for (const auto& span : data) {
    iterator.MutableSpan<char>(span.size()).copy_from(span);
  }

  return Create(std::move(contents));
}

DOMArrayBuffer* DOMArrayBuffer::CreateOrNull(size_t num_elements,
                                             size_t element_byte_size) {
  ArrayBufferContents contents(num_elements, element_byte_size,
                               ArrayBufferContents::kNotShared,
                               ArrayBufferContents::kZeroInitialize);
  if (!contents.Data()) {
    return nullptr;
  }
  return Create(std::move(contents));
}

DOMArrayBuffer* DOMArrayBuffer::CreateOrNull(base::span<const uint8_t> source) {
  DOMArrayBuffer* buffer = CreateUninitializedOrNull(source.size(), 1);
  if (!buffer) {
    return nullptr;
  }

  buffer->ByteSpan().copy_from(source);
  return buffer;
}

DOMArrayBuffer* DOMArrayBuffer::CreateUninitializedOrNull(
    size_t num_elements,
    size_t element_byte_size) {
  ArrayBufferContents contents(num_elements, element_byte_size,
                               ArrayBufferContents::kNotShared,
                               ArrayBufferContents::kDontInitialize);
  if (!contents.Data()) {
    return nullptr;
  }
  return Create(std::move(contents));
}

v8::Local<v8::Value> DOMArrayBuffer::Wrap(ScriptState* script_state) {
  DCHECK(!DOMDataStore::ContainsWrapper(script_state->GetIsolate(), this));

  const WrapperTypeInfo* wrapper_type_info = GetWrapperTypeInfo();

  v8::Local<v8::ArrayBuffer> wrapper;
  {
    v8::Context::Scope context_scope(script_state->GetContext());
    std::shared_ptr<v8::BackingStore> backing_store = Content()->BackingStore();
    wrapper = backing_store
                  ? v8::ArrayBuffer::New(script_state->GetIsolate(),
                                         std::move(backing_store))
                  : v8::ArrayBuffer::New(script_state->GetIsolate(), 0);

    if (!detach_key_.IsEmpty()) {
      wrapper->SetDetachKey(detach_key_.Get(script_state->GetIsolate()));
    }
  }

  return AssociateWithWrapper(script_state->GetIsolate(), wrapper_type_info,
                              wrapper);
}

bool DOMArrayBuffer::IsDetached() const {
  if (contents_.BackingStore() == nullptr) {
    return is_detached_;
  }
  if (is_detached_) {
    return true;
  }

  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope handle_scope(isolate);

  // There may be several v8::ArrayBuffers corresponding to the DOMArrayBuffer,
  // but at most one of them may be non-detached.
  int nondetached_count = 0;
  int detached_count = 0;

  ForArrayBuffersInAllWorlds(isolate, this,
                             [&detached_count, &nondetached_count](
                                 v8::Local<v8::ArrayBuffer> buffer_handle) {
                               if (buffer_handle->WasDetached()) {
                                 ++detached_count;
                               } else {
                                 ++nondetached_count;
                               }
                             });

  // This CHECK fires even though it should not. TODO(330759272): Investigate
  // under which conditions we end up with multiple non-detached JSABs for the
  // same DOMAB and potentially restore this check.

  // CHECK_LE(nondetached_count, 1);

  return nondetached_count == 0 && detached_count > 0;
}

v8::Local<v8::Object> DOMArrayBuffer::AssociateWithWrapper(
    v8::Isolate* isolate,
    const WrapperTypeInfo* wrapper_type_info,
    v8::Local<v8::Object> wrapper) {
  if (!DOMWrapperWorld::Current(isolate).IsMainWorld()) {
    has_non_main_world_wrappers_ = true;
  }
  return ScriptWrappable::AssociateWithWrapper(isolate, wrapper_type_info,
                                               wrapper);
}

DOMArrayBuffer* DOMArrayBuffer::Slice(size_t begin, size_t end) const {
  begin = std::min(begin, ByteLength());
  end = std::min(end, ByteLength());
  size_t size = begin <= end ? end - begin : 0;
  return Create(ByteSpan().subspan(begin, size));
}

void DOMArrayBuffer::Trace(Visitor* visitor) const {
  visitor->Trace(detach_key_);
  DOMArrayBufferBase::Trace(visitor);
}

}  // namespace blink

"""

```