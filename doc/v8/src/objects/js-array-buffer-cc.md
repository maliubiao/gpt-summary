Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of a V8 source file (`v8/src/objects/js-array-buffer.cc`). It also has specific instructions regarding file type (.tq), JavaScript relation, code logic, and common programming errors.

**2. Core Functionality Identification (High-Level):**

The file name itself, `js-array-buffer.cc`, strongly suggests that this code is responsible for the internal representation and manipulation of JavaScript `ArrayBuffer` objects within the V8 engine. We can expect to see code related to:

* **Creation and Initialization:** How `ArrayBuffer` instances are created.
* **Memory Management:**  How the underlying memory buffer is allocated, managed, and potentially detached.
* **Shared Buffers:** Handling of `SharedArrayBuffer`.
* **Resizing Buffers:** Handling of resizable `ArrayBuffer` (likely a newer feature).
* **Typed Arrays:**  The relationship between `ArrayBuffer` and `TypedArray`.
* **Interaction with V8 Internals:**  Calls to other V8 components like the heap, garbage collector, and protectors.

**3. Code Structure Scan and Keyword Spotting:**

A quick scan of the code reveals key classes and functions:

* `JSArrayBuffer`:  The central class for `ArrayBuffer` representation.
* `BackingStore`:  Represents the underlying memory buffer.
* `ArrayBufferExtension`:  Seems to handle extra data associated with the buffer (potentially for GC or other internal tracking).
* `Detach`:  Functions related to detaching the underlying buffer.
* `Attach`: Functions related to attaching a backing store.
* `Setup`: Initialization of a `JSArrayBuffer`.
* `CanonicalNumericIndexString`:  A helper function for validating array indices.
* `JSTypedArray`:  Functions showing the connection to `TypedArray`.
* `DefineOwnProperty`:  Implementation of property definition for `TypedArray`.

**4. Detailed Function Analysis (Iterative Process):**

Now, let's go through the functions one by one, trying to understand their purpose.

* **`CanonicalNumericIndexString`:**  The name is self-explanatory. It checks if a given string can be interpreted as a valid array index. The code handles cases like positive integers and the special case of "-0".

* **`JSArrayBuffer::Setup`:** This is clearly the constructor or initializer. It sets up various internal flags (shared, resizable, detachable), initializes the backing store (potentially empty), and sets up embedder fields (for external integration).

* **`JSArrayBuffer::Attach`:** This function connects a `BackingStore` to a `JSArrayBuffer`. It performs checks for shared/resizable status and updates internal fields like `backing_store`, `byte_length`, and `max_byte_length`. The interaction with `ArrayBufferExtension` is also important for memory management.

* **`JSArrayBuffer::Detach` and `DetachInternal`:** These functions handle the process of detaching the underlying memory. The `Detach` function includes a key-based mechanism for preventing unauthorized detachment. `DetachInternal` handles the actual memory release and invalidation of protectors.

* **`JSArrayBuffer::GsabByteLength`:**  This specifically deals with getting the length of a `SharedArrayBuffer` (GSAB). The `std::memory_order_seq_cst` indicates atomic access, crucial for shared memory.

* **`JSArrayBuffer::GetResizableBackingStorePageConfiguration`:**  This function calculates page sizes and the number of pages needed for resizable array buffers, suggesting memory management at a page level.

* **`JSArrayBuffer::EnsureExtension` and `RemoveExtension`:** These manage the `ArrayBufferExtension`, which appears to hold the `BackingStore` and potentially other metadata. This pattern suggests a separation of concerns and might be related to garbage collection.

* **`JSArrayBuffer::MarkExtension` and `YoungMarkExtension`:** These are clearly related to the garbage collection process. Marking is a standard GC technique.

* **`JSTypedArray::GetBuffer`:** This function seems to optimize the representation of `TypedArray`. If a `TypedArray` is initially on the heap, this function can move its data to an `ArrayBuffer`'s backing store, potentially improving performance and memory management.

* **`JSTypedArray::DefineOwnProperty`:** This implements the `defineProperty` behavior for `TypedArray` elements. It performs checks for valid indices, configurability, enumerability, writability, and handles setting values.

* **`JSTypedArray::type`, `element_size`, `LengthTrackingGsabBackedTypedArrayLength`, `GetVariableLengthOrOutOfBounds`:** These are helper functions for `TypedArray` to determine its type, element size, and length (especially for variable-length shared buffers).

**5. Identifying Relationships and Patterns:**

As we analyze the functions, we start seeing connections:

* **`JSArrayBuffer` and `BackingStore`:**  A clear ownership relationship.
* **`JSArrayBuffer` and `ArrayBufferExtension`:**  A mechanism for attaching extra data and managing the `BackingStore`.
* **`JSArrayBuffer` and `JSTypedArray`:**  `TypedArray` instances are views on `ArrayBuffer` data.
* **Detachment and Protectors:**  A mechanism to invalidate optimizations when a buffer is detached.
* **Shared Buffers and Atomic Operations:**  The use of `std::memory_order_seq_cst`.
* **Resizable Buffers and Page Management:**  The `GetResizableBackingStorePageConfiguration` function.

**6. Connecting to JavaScript Concepts:**

Now, we try to relate the C++ code back to JavaScript:

* `new ArrayBuffer(size)` maps to `JSArrayBuffer::Setup` and `BackingStore::Allocate`.
* `new SharedArrayBuffer(size)` maps to similar functions but with the `SharedFlag::kShared` flag.
* `buffer.byteLength` maps to accessing the `byte_length` field of `JSArrayBuffer`.
* `buffer.slice()` might involve creating new `JSArrayBuffer` or `JSTypedArray` instances.
* Detaching an `ArrayBuffer` maps to `JSArrayBuffer::Detach`.
* `TypedArray` constructors (e.g., `new Uint8Array(buffer)`) map to the creation of `JSTypedArray` instances that reference a `JSArrayBuffer`.
* Setting elements of a `TypedArray` maps to logic within `JSTypedArray::DefineOwnProperty` or similar low-level access functions.

**7. Considering Edge Cases and Errors:**

We think about potential errors:

* **Invalid `ArrayBuffer` size:**  Handled by checks in `Setup` and `GetResizableBackingStorePageConfiguration`.
* **Detaching a non-detachable buffer:** Handled by the `is_detachable()` check.
* **Mismatched detach key:** Handled in `JSArrayBuffer::Detach`.
* **Out-of-bounds access in `TypedArray`:** Handled in `JSTypedArray::DefineOwnProperty` and other accessors.
* **Modifying non-configurable/non-writable properties:**  Handled in `JSTypedArray::DefineOwnProperty`.

**8. Structuring the Output:**

Finally, we organize our findings into the requested categories:

* **Functionality:** A clear list of what the code does.
* **Torque:** Check the file extension.
* **JavaScript Examples:**  Concrete JavaScript code illustrating the C++ functionality.
* **Code Logic Reasoning:**  Hypothetical inputs and outputs for specific functions (like `CanonicalNumericIndexString`).
* **Common Programming Errors:**  Examples of JavaScript errors that these C++ functions are designed to prevent or handle.

This iterative process of code scanning, function analysis, relationship identification, JavaScript mapping, and error consideration allows for a comprehensive understanding of the C++ code's role within the V8 engine. The key is to start with the big picture and gradually drill down into the details, constantly connecting the C++ implementation back to the user-facing JavaScript features.
好的，让我们来分析一下 `v8/src/objects/js-array-buffer.cc` 这个 V8 源代码文件的功能。

**文件功能概述:**

`v8/src/objects/js-array-buffer.cc` 文件主要负责定义和实现 JavaScript 中 `ArrayBuffer` 和相关的 `SharedArrayBuffer` 对象的内部表示和操作。它包含了创建、管理、操作以及与底层内存交互的关键逻辑。

**功能详细列举:**

1. **`JSArrayBuffer` 对象的创建和初始化:**
   - `JSArrayBuffer::Setup`:  负责 `JSArrayBuffer` 对象的初始化，包括设置标志位（如是否共享、是否可调整大小、是否可分离）、初始化扩展信息、设置内嵌字段以及最重要的设置底层存储 (`backing_store`)。
   - 它可以处理创建普通 `ArrayBuffer` 和 `SharedArrayBuffer` 的情况。

2. **底层存储 (`BackingStore`) 的管理:**
   - `JSArrayBuffer::Attach`: 将一个 `BackingStore` 对象关联到 `JSArrayBuffer`，这是 `ArrayBuffer` 真正拥有内存的地方。它会更新 `JSArrayBuffer` 的字节长度和最大字节长度等属性。
   - `JSArrayBuffer::Detach` 和 `JSArrayBuffer::DetachInternal`:  负责分离 `JSArrayBuffer` 的底层存储。对于 `SharedArrayBuffer` 和 WebAssembly 内存，分离操作会有一些限制。`Detach` 方法还引入了 `detach_key` 的概念，用于安全地分离。
   - `JSArrayBuffer::EnsureExtension` 和 `JSArrayBuffer::RemoveExtension`:  用于管理与 `ArrayBuffer` 关联的扩展信息 (`ArrayBufferExtension`)，其中包含了 `BackingStore`。这与垃圾回收和内存管理有关。

3. **共享 `ArrayBuffer` (`SharedArrayBuffer`) 的支持:**
   - 代码中多处地方都考虑了 `SharedFlag::kShared`，用于区分普通 `ArrayBuffer` 和 `SharedArrayBuffer`。
   - `JSArrayBuffer::GsabByteLength`:  专门用于获取 `SharedArrayBuffer` 的当前字节长度，由于是共享内存，需要使用原子操作 (`std::memory_order_seq_cst`)。

4. **可调整大小的 `ArrayBuffer` (`Resizable ArrayBuffer`) 的支持:**
   - 代码中使用了 `ResizableFlag::kResizable` 来标记可调整大小的 `ArrayBuffer`。
   - `JSArrayBuffer::GetResizableBackingStorePageConfiguration`:  用于计算可调整大小的 `ArrayBuffer` 所需的页大小和初始/最大页数。

5. **与 `TypedArray` 的关联:**
   - `JSTypedArray::GetBuffer`:  允许从一个 `JSTypedArray` 中获取其底层的 `JSArrayBuffer`。如果 `TypedArray` 的数据当前在堆上，此方法会将其移动到 `ArrayBuffer` 的 `BackingStore` 中。
   - `JSTypedArray::DefineOwnProperty`:  实现了 `TypedArray` 对象上属性的定义行为，其中会检查索引的有效性以及是否已分离。

6. **辅助函数:**
   - `CanonicalNumericIndexString`:  判断一个字符串是否可以转换为有效的数组索引。这在处理 `TypedArray` 的属性访问时非常重要。

7. **垃圾回收支持:**
   - `JSArrayBuffer::MarkExtension` 和 `JSArrayBuffer::YoungMarkExtension`:  用于在垃圾回收过程中标记与 `ArrayBuffer` 相关的扩展信息，确保 `BackingStore` 不会被意外回收。

**如果 `v8/src/objects/js-array-buffer.cc` 以 `.tq` 结尾：**

如果该文件以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。Torque 是 V8 使用的一种类型化的中间语言，用于生成高效的 C++ 代码。在这种情况下，该文件将包含用 Torque 编写的 `JSArrayBuffer` 相关逻辑，Torque 编译器会将其转换为实际的 C++ 代码。

**与 JavaScript 功能的关系及示例:**

`v8/src/objects/js-array-buffer.cc` 的功能直接对应于 JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 的使用。

**JavaScript 示例：**

```javascript
// 创建一个 16 字节的 ArrayBuffer
const buffer = new ArrayBuffer(16);
console.log(buffer.byteLength); // 输出 16

// 创建一个指向 ArrayBuffer 的 Uint8Array 视图
const view = new Uint8Array(buffer);
view[0] = 42;

// 创建一个 SharedArrayBuffer
const sharedBuffer = new SharedArrayBuffer(1024);
console.log(sharedBuffer.byteLength); // 输出 1024

// 分离 ArrayBuffer (需要 detach_key)
// let detachKey = {};
// buffer.detach(detachKey); // 假设 detach 方法存在，实际上 detach 是一个函数名，需要配合 setDetachKey 使用

// 创建一个可调整大小的 ArrayBuffer（较新的特性）
// const resizableBuffer = new ArrayBuffer(10, { maxByteLength: 100 });
// console.log(resizableBuffer.byteLength);
// resizableBuffer.resize(50);
// console.log(resizableBuffer.byteLength);
```

在这个例子中：

- `new ArrayBuffer(16)` 的创建过程涉及到 `JSArrayBuffer::Setup` 和 `BackingStore` 的分配。
- `new Uint8Array(buffer)` 创建了一个 `TypedArray`，它内部会关联到 `JSArrayBuffer` 对象。
- `new SharedArrayBuffer(1024)` 的创建涉及到 `JSArrayBuffer::Setup` 中 `SharedFlag::kShared` 的设置。
- `buffer.detach()`  （概念上）对应于 `JSArrayBuffer::Detach` 的调用。
- 可调整大小的 `ArrayBuffer` 的创建和调整大小涉及到 `JSArrayBuffer::Setup` 中 `ResizableFlag::kResizable` 的设置以及相关的调整大小逻辑。

**代码逻辑推理及假设输入输出:**

**示例：`CanonicalNumericIndexString` 函数**

**假设输入：**

- `isolate`: 一个 V8 Isolate 实例。
- `lookup_key`: 一个 `PropertyKey` 对象，其 `name()` 方法返回一个 Handle 指向字符串 `"123"`。
- `is_minus_zero`: 一个指向 `bool` 变量的指针。

**代码逻辑推理：**

1. `lookup_key.is_element()` 为 false（假设键不是直接的元素索引）。
2. `IsString(*lookup_key.name())` 为 true，因为键是字符串 `"123"`。
3. `String::ToNumber(isolate, key)` 将字符串 `"123"` 转换为数字 123。
4. `IsMinusZero(*result)` 为 false，因为 123 不是 -0。
5. `Object::ToString(isolate, result)` 将数字 123 转换回字符串 `"123"`。
6. `Object::SameValue(*str, *key)` 比较 `"123"` 和 `"123"`，结果为 true。

**预期输出：**

- 函数返回 `true`。
- `is_minus_zero` 指向的变量的值为 `false`。

**示例：`JSArrayBuffer::Detach` 函数**

**假设输入：**

- `buffer`: 一个指向可分离的 `JSArrayBuffer` 实例的 `DirectHandle`。
- `force_for_wasm_memory`: `false`。
- `maybe_key`: `Handle<Object>::null()`，并且 `buffer` 的 `detach_key` 是 `undefined`。

**代码逻辑推理：**

1. `detach_key` 是 `undefined`。
2. `key_mismatch` 为 `false`，因为 `maybe_key` 是 null 且 `detach_key` 是 undefined。
3. `buffer->was_detached()` 为 `false`（假设缓冲区尚未分离）。
4. `buffer->is_detachable()` 为 `true`（因为假设缓冲区是可分离的）。
5. 调用 `buffer->DetachInternal(false, isolate)`。
6. `DetachInternal` 会执行分离操作，设置 `was_detached` 为 `true` 等。

**预期输出：**

- 函数返回 `Just(true)`。
- `buffer` 对象的内部状态已更新，表示已分离。

**涉及用户常见的编程错误：**

1. **尝试在已分离的 `ArrayBuffer` 上进行操作：**
   ```javascript
   const buffer = new ArrayBuffer(8);
   const view = new Uint8Array(buffer);
   // 假设某种方式 buffer 被分离了
   // buffer.detach(); // 实际上需要 detachKey
   try {
       view[0] = 10; // 错误：尝试访问已分离的 ArrayBuffer
   } catch (e) {
       console.error(e); // 输出 TypeError
   }
   ```
   V8 会在 C++ 代码中检查 `was_detached()` 标志，并抛出 `TypeError`。

2. **在 `SharedArrayBuffer` 上使用不安全的原子操作：**
   虽然 `JSArrayBuffer.cc` 负责 `SharedArrayBuffer` 的底层，但用户错误通常发生在 JavaScript 中对 `SharedArrayBuffer` 的操作上，例如没有正确使用 `Atomics` 对象进行同步。这不会直接在 `JSArrayBuffer.cc` 中体现，但该文件为 `SharedArrayBuffer` 的正确操作提供了基础。

3. **尝试分离不可分离的 `ArrayBuffer` (通常是 WebAssembly 的 Memory)：**
   ```javascript
   const wasmMemory = new WebAssembly.Memory({ initial: 1 });
   // wasmMemory.buffer.detach(); // 通常会抛出 TypeError，因为 WebAssembly.Memory 的 buffer 不可分离
   ```
   `JSArrayBuffer::Detach` 中会检查 `is_detachable()` 标志，对于不可分离的缓冲区，会直接返回。

4. **使用错误的 `detachKey` 分离 `ArrayBuffer`：**
   ```javascript
   const buffer = new ArrayBuffer(8);
   // buffer.setDetachKey({}); // 假设有这个方法
   // try {
   //     buffer.detach({ key: 'wrong' });
   // } catch (e) {
   //     console.error(e); // 输出 TypeError: ArrayBuffer detach key doesn't match
   // }
   ```
   `JSArrayBuffer::Detach` 中的键匹配逻辑会防止使用错误的密钥进行分离。

理解 `v8/src/objects/js-array-buffer.cc` 的功能对于深入了解 JavaScript 中 `ArrayBuffer` 的底层实现至关重要，也有助于理解 V8 如何进行内存管理和优化。

### 提示词
```
这是目录为v8/src/objects/js-array-buffer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-array-buffer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-array-buffer.h"

#include "src/execution/protectors-inl.h"
#include "src/logging/counters.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/property-descriptor.h"

namespace v8 {
namespace internal {

namespace {

// ES#sec-canonicalnumericindexstring
// Returns true if the lookup_key represents a valid index string.
bool CanonicalNumericIndexString(Isolate* isolate,
                                 const PropertyKey& lookup_key,
                                 bool* is_minus_zero) {
  // 1. Assert: Type(argument) is String.
  DCHECK(lookup_key.is_element() || IsString(*lookup_key.name()));
  *is_minus_zero = false;
  if (lookup_key.is_element()) return true;

  Handle<String> key = Cast<String>(lookup_key.name());

  // 3. Let n be ! ToNumber(argument).
  Handle<Object> result = String::ToNumber(isolate, key);
  if (IsMinusZero(*result)) {
    // 2. If argument is "-0", return -0𝔽.
    // We are not performing SaveValue check for -0 because it'll be rejected
    // anyway.
    *is_minus_zero = true;
  } else {
    // 4. If SameValue(! ToString(n), argument) is false, return undefined.
    DirectHandle<String> str =
        Object::ToString(isolate, result).ToHandleChecked();
    // Avoid treating strings like "2E1" and "20" as the same key.
    if (!Object::SameValue(*str, *key)) return false;
  }
  return true;
}
}  // anonymous namespace

void JSArrayBuffer::Setup(SharedFlag shared, ResizableFlag resizable,
                          std::shared_ptr<BackingStore> backing_store,
                          Isolate* isolate) {
  clear_padding();
  set_detach_key(ReadOnlyRoots(isolate).undefined_value());
  set_bit_field(0);
  set_is_shared(shared == SharedFlag::kShared);
  set_is_resizable_by_js(resizable == ResizableFlag::kResizable);
  set_is_detachable(shared != SharedFlag::kShared);
  init_extension();
  SetupLazilyInitializedCppHeapPointerField(
      JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
  for (int i = 0; i < v8::ArrayBuffer::kEmbedderFieldCount; i++) {
    SetEmbedderField(i, Smi::zero());
  }
  if (!backing_store) {
    set_backing_store(isolate, EmptyBackingStoreBuffer());
    set_byte_length(0);
    set_max_byte_length(0);
  } else {
    Attach(std::move(backing_store));
  }
  if (shared == SharedFlag::kShared) {
    isolate->CountUsage(
        v8::Isolate::UseCounterFeature::kSharedArrayBufferConstructed);
  }
}

void JSArrayBuffer::Attach(std::shared_ptr<BackingStore> backing_store) {
  DCHECK_NOT_NULL(backing_store);
  DCHECK_EQ(is_shared(), backing_store->is_shared());
  DCHECK_EQ(is_resizable_by_js(), backing_store->is_resizable_by_js());
  DCHECK_IMPLIES(
      !backing_store->is_wasm_memory() && !backing_store->is_resizable_by_js(),
      backing_store->byte_length() == backing_store->max_byte_length());
  DCHECK(!was_detached());
  Isolate* isolate = GetIsolate();

  void* backing_store_buffer = backing_store->buffer_start();
  // Wasm memory always needs a backing store; this is guaranteed by reserving
  // at least one page for the BackingStore (so {IsEmpty()} is always false).
  CHECK_IMPLIES(backing_store->is_wasm_memory(), !backing_store->IsEmpty());
  // Non-empty backing stores must start at a non-null pointer.
  DCHECK_IMPLIES(backing_store_buffer == nullptr, backing_store->IsEmpty());
  // Empty backing stores can be backed by a null pointer or an externally
  // provided pointer: Either is acceptable. If pointers are sandboxed then
  // null pointers must be replaced by a special null entry.
  if (V8_ENABLE_SANDBOX_BOOL && !backing_store_buffer) {
    backing_store_buffer = EmptyBackingStoreBuffer();
  }
  set_backing_store(isolate, backing_store_buffer);

  // GSABs need to read their byte_length from the BackingStore. Maintain the
  // invariant that their byte_length field is always 0.
  auto byte_len =
      (is_shared() && is_resizable_by_js()) ? 0 : backing_store->byte_length();
  CHECK_LE(backing_store->byte_length(), kMaxByteLength);
  set_byte_length(byte_len);
  // For Wasm memories, it is possible for the backing store maximum to be
  // different from the JSArrayBuffer maximum. The maximum pages allowed on a
  // Wasm memory are tracked on the Wasm memory object, and not the
  // JSArrayBuffer associated with it.
  auto max_byte_len = is_resizable_by_js() ? backing_store->max_byte_length()
                                           : backing_store->byte_length();
  set_max_byte_length(max_byte_len);
  if (backing_store->is_wasm_memory()) set_is_detachable(false);
  ArrayBufferExtension* extension = EnsureExtension();
  size_t bytes = backing_store->PerIsolateAccountingLength();
  extension->set_accounting_state(bytes, ArrayBufferExtension::Age::kYoung);
  extension->set_backing_store(std::move(backing_store));
  isolate->heap()->AppendArrayBufferExtension(*this, extension);
}

Maybe<bool> JSArrayBuffer::Detach(DirectHandle<JSArrayBuffer> buffer,
                                  bool force_for_wasm_memory,
                                  Handle<Object> maybe_key) {
  Isolate* const isolate = buffer->GetIsolate();

  DirectHandle<Object> detach_key(buffer->detach_key(), isolate);

  bool key_mismatch = false;

  if (!IsUndefined(*detach_key, isolate)) {
    key_mismatch =
        maybe_key.is_null() || !Object::StrictEquals(*maybe_key, *detach_key);
  } else {
    // Detach key is undefined; allow not passing maybe_key but disallow passing
    // something else than undefined.
    key_mismatch =
        !maybe_key.is_null() && !Object::StrictEquals(*maybe_key, *detach_key);
  }
  if (key_mismatch) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewTypeError(MessageTemplate::kArrayBufferDetachKeyDoesntMatch),
        Nothing<bool>());
  }

  if (buffer->was_detached()) return Just(true);

  if (force_for_wasm_memory) {
    // Skip the is_detachable() check.
  } else if (!buffer->is_detachable()) {
    // Not detachable, do nothing.
    return Just(true);
  }

  buffer->DetachInternal(force_for_wasm_memory, isolate);
  return Just(true);
}

void JSArrayBuffer::DetachInternal(bool force_for_wasm_memory,
                                   Isolate* isolate) {
  ArrayBufferExtension* extension = this->extension();

  if (extension) {
    DisallowGarbageCollection disallow_gc;
    isolate->heap()->DetachArrayBufferExtension(extension);
    std::shared_ptr<BackingStore> backing_store = RemoveExtension();
    CHECK_IMPLIES(force_for_wasm_memory, backing_store->is_wasm_memory());
  }

  if (Protectors::IsArrayBufferDetachingIntact(isolate)) {
    Protectors::InvalidateArrayBufferDetaching(isolate);
  }

  DCHECK(!is_shared());
  set_backing_store(isolate, EmptyBackingStoreBuffer());
  set_byte_length(0);
  set_was_detached(true);
}

size_t JSArrayBuffer::GsabByteLength(Isolate* isolate,
                                     Address raw_array_buffer) {
  // TODO(v8:11111): Cache the last seen length in JSArrayBuffer and use it
  // in bounds checks to minimize the need for calling this function.
  DisallowGarbageCollection no_gc;
  DisallowJavascriptExecution no_js(isolate);
  Tagged<JSArrayBuffer> buffer =
      Cast<JSArrayBuffer>(Tagged<Object>(raw_array_buffer));
  CHECK(buffer->is_resizable_by_js());
  CHECK(buffer->is_shared());
  return buffer->GetBackingStore()->byte_length(std::memory_order_seq_cst);
}

// static
Maybe<bool> JSArrayBuffer::GetResizableBackingStorePageConfiguration(
    Isolate* isolate, size_t byte_length, size_t max_byte_length,
    ShouldThrow should_throw, size_t* page_size, size_t* initial_pages,
    size_t* max_pages) {
  DCHECK_NOT_NULL(page_size);
  DCHECK_NOT_NULL(initial_pages);
  DCHECK_NOT_NULL(max_pages);

  *page_size = AllocatePageSize();

  if (!RoundUpToPageSize(byte_length, *page_size, JSArrayBuffer::kMaxByteLength,
                         initial_pages)) {
    if (should_throw == kDontThrow) return Nothing<bool>();
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferLength),
        Nothing<bool>());
  }

  if (!RoundUpToPageSize(max_byte_length, *page_size,
                         JSArrayBuffer::kMaxByteLength, max_pages)) {
    if (should_throw == kDontThrow) return Nothing<bool>();
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferMaxLength),
        Nothing<bool>());
  }

  return Just(true);
}

ArrayBufferExtension* JSArrayBuffer::EnsureExtension() {
  ArrayBufferExtension* extension = this->extension();
  if (extension != nullptr) return extension;

  extension = new ArrayBufferExtension(std::shared_ptr<BackingStore>());
  set_extension(extension);
  return extension;
}

std::shared_ptr<BackingStore> JSArrayBuffer::RemoveExtension() {
  ArrayBufferExtension* extension = this->extension();
  DCHECK_NOT_NULL(extension);
  auto result = extension->RemoveBackingStore();
  // Remove pointer to extension such that the next GC will free it
  // automatically.
  set_extension(nullptr);
  return result;
}

void JSArrayBuffer::MarkExtension() {
  ArrayBufferExtension* extension = this->extension();
  if (extension) {
    extension->Mark();
  }
}

void JSArrayBuffer::YoungMarkExtension() {
  ArrayBufferExtension* extension = this->extension();
  if (extension) {
    DCHECK_EQ(ArrayBufferExtension::Age::kYoung, extension->age());
    extension->YoungMark();
  }
}

void JSArrayBuffer::YoungMarkExtensionPromoted() {
  ArrayBufferExtension* extension = this->extension();
  if (extension) {
    extension->YoungMarkPromoted();
  }
}

Handle<JSArrayBuffer> JSTypedArray::GetBuffer() {
  Isolate* isolate = GetIsolate();
  DirectHandle<JSTypedArray> self(*this, isolate);
  DCHECK(IsTypedArrayOrRabGsabTypedArrayElementsKind(self->GetElementsKind()));
  Handle<JSArrayBuffer> array_buffer(Cast<JSArrayBuffer>(self->buffer()),
                                     isolate);
  if (!is_on_heap()) {
    // Already is off heap, so return the existing buffer.
    return array_buffer;
  }
  DCHECK(!array_buffer->is_resizable_by_js());

  // The existing array buffer should be empty.
  DCHECK(array_buffer->IsEmpty());

  // Allocate a new backing store and attach it to the existing array buffer.
  size_t byte_length = self->byte_length();
  auto backing_store =
      BackingStore::Allocate(isolate, byte_length, SharedFlag::kNotShared,
                             InitializedFlag::kUninitialized);

  if (!backing_store) {
    isolate->heap()->FatalProcessOutOfMemory("JSTypedArray::GetBuffer");
  }

  // Copy the elements into the backing store of the array buffer.
  if (byte_length > 0) {
    memcpy(backing_store->buffer_start(), self->DataPtr(), byte_length);
  }

  // Attach the backing store to the array buffer.
  array_buffer->Setup(SharedFlag::kNotShared, ResizableFlag::kNotResizable,
                      std::move(backing_store), isolate);

  // Clear the elements of the typed array.
  self->set_elements(ReadOnlyRoots(isolate).empty_byte_array());
  self->SetOffHeapDataPtr(isolate, array_buffer->backing_store(), 0);
  DCHECK(!self->is_on_heap());

  return array_buffer;
}

// ES#sec-integer-indexed-exotic-objects-defineownproperty-p-desc
// static
Maybe<bool> JSTypedArray::DefineOwnProperty(Isolate* isolate,
                                            Handle<JSTypedArray> o,
                                            Handle<Object> key,
                                            PropertyDescriptor* desc,
                                            Maybe<ShouldThrow> should_throw) {
  DCHECK(IsName(*key) || IsNumber(*key));
  // 1. If Type(P) is String, then
  PropertyKey lookup_key(isolate, key);
  if (lookup_key.is_element() || IsSmi(*key) || IsString(*key)) {
    // 1a. Let numericIndex be ! CanonicalNumericIndexString(P)
    // 1b. If numericIndex is not undefined, then
    bool is_minus_zero = false;
    if (IsSmi(*key) ||  // Smi keys are definitely canonical
        CanonicalNumericIndexString(isolate, lookup_key, &is_minus_zero)) {
      // 1b i. If IsValidIntegerIndex(O, numericIndex) is false, return false.

      // IsValidIntegerIndex:
      size_t index = lookup_key.index();
      bool out_of_bounds = false;
      size_t length = o->GetLengthOrOutOfBounds(out_of_bounds);
      if (o->WasDetached() || out_of_bounds || index >= length) {
        RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                       NewTypeError(MessageTemplate::kInvalidTypedArrayIndex));
      }
      if (!lookup_key.is_element() || is_minus_zero) {
        RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                       NewTypeError(MessageTemplate::kInvalidTypedArrayIndex));
      }

      // 1b ii. If Desc has a [[Configurable]] field and if
      //     Desc.[[Configurable]] is false, return false.
      // 1b iii. If Desc has an [[Enumerable]] field and if Desc.[[Enumerable]]
      //     is false, return false.
      // 1b iv. If IsAccessorDescriptor(Desc) is true, return false.
      // 1b v. If Desc has a [[Writable]] field and if Desc.[[Writable]] is
      //     false, return false.

      if (PropertyDescriptor::IsAccessorDescriptor(desc)) {
        RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                       NewTypeError(MessageTemplate::kRedefineDisallowed, key));
      }

      if ((desc->has_configurable() && !desc->configurable()) ||
          (desc->has_enumerable() && !desc->enumerable()) ||
          (desc->has_writable() && !desc->writable())) {
        RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                       NewTypeError(MessageTemplate::kRedefineDisallowed, key));
      }

      // 1b vi. If Desc has a [[Value]] field, perform
      // ? IntegerIndexedElementSet(O, numericIndex, Desc.[[Value]]).
      if (desc->has_value()) {
        if (!desc->has_configurable()) desc->set_configurable(true);
        if (!desc->has_enumerable()) desc->set_enumerable(true);
        if (!desc->has_writable()) desc->set_writable(true);
        Handle<Object> value = desc->value();
        LookupIterator it(isolate, o, index, LookupIterator::OWN);
        RETURN_ON_EXCEPTION_VALUE(
            isolate,
            DefineOwnPropertyIgnoreAttributes(&it, value, desc->ToAttributes()),
            Nothing<bool>());
      }
      // 1b vii. Return true.
      return Just(true);
    }
  }
  // 4. Return ! OrdinaryDefineOwnProperty(O, P, Desc).
  return OrdinaryDefineOwnProperty(isolate, o, lookup_key, desc, should_throw);
}

ExternalArrayType JSTypedArray::type() {
  switch (map()->elements_kind()) {
#define ELEMENTS_KIND_TO_ARRAY_TYPE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                                      \
    return kExternal##Type##Array;

    TYPED_ARRAYS(ELEMENTS_KIND_TO_ARRAY_TYPE)
    RAB_GSAB_TYPED_ARRAYS_WITH_TYPED_ARRAY_TYPE(ELEMENTS_KIND_TO_ARRAY_TYPE)
#undef ELEMENTS_KIND_TO_ARRAY_TYPE

    default:
      UNREACHABLE();
  }
}

size_t JSTypedArray::element_size() const {
  switch (map()->elements_kind()) {
#define ELEMENTS_KIND_TO_ELEMENT_SIZE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                                        \
    return sizeof(ctype);

    TYPED_ARRAYS(ELEMENTS_KIND_TO_ELEMENT_SIZE)
    RAB_GSAB_TYPED_ARRAYS(ELEMENTS_KIND_TO_ELEMENT_SIZE)
#undef ELEMENTS_KIND_TO_ELEMENT_SIZE

    default:
      UNREACHABLE();
  }
}

size_t JSTypedArray::LengthTrackingGsabBackedTypedArrayLength(
    Isolate* isolate, Address raw_array) {
  // TODO(v8:11111): Cache the last seen length in JSArrayBuffer and use it
  // in bounds checks to minimize the need for calling this function.
  DisallowGarbageCollection no_gc;
  DisallowJavascriptExecution no_js(isolate);
  Tagged<JSTypedArray> array = Cast<JSTypedArray>(Tagged<Object>(raw_array));
  CHECK(array->is_length_tracking());
  Tagged<JSArrayBuffer> buffer = array->buffer();
  CHECK(buffer->is_resizable_by_js());
  CHECK(buffer->is_shared());
  size_t backing_byte_length =
      buffer->GetBackingStore()->byte_length(std::memory_order_seq_cst);
  CHECK_GE(backing_byte_length, array->byte_offset());
  auto element_byte_size = ElementsKindToByteSize(array->GetElementsKind());
  return (backing_byte_length - array->byte_offset()) / element_byte_size;
}

size_t JSTypedArray::GetVariableLengthOrOutOfBounds(bool& out_of_bounds) const {
  DCHECK(!WasDetached());
  if (is_length_tracking()) {
    if (is_backed_by_rab()) {
      if (byte_offset() > buffer()->byte_length()) {
        out_of_bounds = true;
        return 0;
      }
      return (buffer()->byte_length() - byte_offset()) / element_size();
    }
    if (byte_offset() >
        buffer()->GetBackingStore()->byte_length(std::memory_order_seq_cst)) {
      out_of_bounds = true;
      return 0;
    }
    return (buffer()->GetBackingStore()->byte_length(
                std::memory_order_seq_cst) -
            byte_offset()) /
           element_size();
  }
  DCHECK(is_backed_by_rab());
  size_t array_length = LengthUnchecked();
  // The sum can't overflow, since we have managed to allocate the
  // JSTypedArray.
  if (byte_offset() + array_length * element_size() > buffer()->byte_length()) {
    out_of_bounds = true;
    return 0;
  }
  return array_length;
}

}  // namespace internal
}  // namespace v8
```