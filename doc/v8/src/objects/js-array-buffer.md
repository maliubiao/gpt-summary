Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for the functionality of the C++ file `js-array-buffer.cc` within the V8 JavaScript engine, and how it relates to JavaScript features, illustrated with JavaScript examples.

2. **Initial Skim and Keyword Spotting:** Quickly read through the code, looking for familiar terms and patterns. Keywords like "ArrayBuffer", "SharedArrayBuffer", "TypedArray", "detach", "length", "byte", "resizable", "wasm", and function names like `Setup`, `Attach`, `Detach`, `DefineOwnProperty`, `GetBuffer` jump out. These immediately suggest the file deals with the underlying implementation of JavaScript's `ArrayBuffer` and related objects.

3. **Identify the Core Class:** The filename and the frequent use of `JSArrayBuffer` clearly indicate this class is central. The methods within this class are the key to understanding its functionality.

4. **Analyze Key Functions and Their Roles:** Go through the major functions in `JSArrayBuffer` and `JSTypedArray` and try to understand their purpose:

    * **`JSArrayBuffer::Setup`**:  This likely handles the initial setup of an `ArrayBuffer` object. The parameters `shared`, `resizable`, and `backing_store` are strong indicators of the different types of array buffers.
    * **`JSArrayBuffer::Attach`**: Deals with connecting a `BackingStore` (the actual memory) to the `JSArrayBuffer` object.
    * **`JSArrayBuffer::Detach` and `DetachInternal`**:  Handles the process of detaching the underlying memory from the `ArrayBuffer`. The mention of "detach key" is interesting and warrants further investigation.
    * **`JSArrayBuffer::GsabByteLength`**: The "Gsab" likely stands for "Growable Shared Array Buffer," and this function seems to retrieve its current length.
    * **`JSArrayBuffer::GetResizableBackingStorePageConfiguration`**: This seems related to how memory is allocated and managed for resizable array buffers.
    * **`JSArrayBuffer::EnsureExtension` and `RemoveExtension`**:  These functions deal with an "extension," suggesting some kind of auxiliary data or functionality associated with the `ArrayBuffer`.
    * **`JSTypedArray::GetBuffer`**: This function appears to handle the creation of an `ArrayBuffer` from a `TypedArray`. This is a less common operation but important for understanding the relationship between the two.
    * **`JSTypedArray::DefineOwnProperty`**: This is a standard JavaScript object operation, but its specialization for `TypedArray` indicates how property definitions (especially indexed properties) are handled.
    * **`JSTypedArray::LengthTrackingGsabBackedTypedArrayLength` and `GetVariableLengthOrOutOfBounds`**:  These seem focused on how the length of `TypedArray` objects backed by resizable shared buffers is tracked.

5. **Connect C++ Concepts to JavaScript Concepts:**  Now, link the identified C++ functionality to corresponding JavaScript features:

    * `JSArrayBuffer` directly maps to JavaScript's `ArrayBuffer` and `SharedArrayBuffer`.
    * The `shared` and `resizable` parameters in `Setup` map to the concepts of shared and resizable array buffers.
    * `Detach` directly corresponds to the `detach()` method in JavaScript.
    * `JSTypedArray` corresponds to the various `Int8Array`, `Uint32Array`, etc. in JavaScript.
    * The `DefineOwnProperty` function relates to how you can set and modify elements of `TypedArray` objects.

6. **Focus on the "Why":**  Don't just list the functions. Explain *why* these functions exist and what problems they solve within the JavaScript environment. For example, explaining the need for `Detach` to manage memory and prevent dangling pointers.

7. **Construct the Summary:** Synthesize the findings into a concise summary, highlighting the main responsibilities of the file and the key classes involved. Emphasize the connection to JavaScript.

8. **Develop JavaScript Examples:** For each major piece of functionality, create simple, illustrative JavaScript code snippets. These examples should directly demonstrate the C++ code's effect at the JavaScript level. Think about common use cases for `ArrayBuffer`, `SharedArrayBuffer`, and `TypedArray`. Specifically:

    * Show the creation of `ArrayBuffer` and `SharedArrayBuffer`.
    * Demonstrate detaching an `ArrayBuffer`.
    * Illustrate the interaction between `TypedArray` and `ArrayBuffer`.
    * Show setting and getting values in a `TypedArray`.
    * Briefly touch upon resizable array buffers (even though they are more advanced).

9. **Refine and Organize:** Review the summary and examples for clarity and accuracy. Organize the information logically. Ensure the JavaScript examples are easy to understand and directly relate to the C++ functionality. Add explanations to the JavaScript examples to clarify what they demonstrate.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file is just about creating ArrayBuffers."
* **Correction:** "No, it also handles SharedArrayBuffers, resizable buffers, and the connection to TypedArrays. The detach functionality is also significant."
* **Initial thought:** "Just list the C++ functions."
* **Correction:** "The request asks for the *functionality* and its relation to *JavaScript*. I need to explain the purpose of these functions in the context of JavaScript."
* **Initial thought:** "A complex JavaScript example is better."
* **Correction:** "Keep the JavaScript examples simple and focused on demonstrating one key concept at a time."
* **Realization:**  The `CanonicalNumericIndexString` function is about how JavaScript interprets string keys for array-like access, a subtle but important detail. Include this in the explanation.

By following this structured approach, combining code analysis with an understanding of JavaScript concepts, the comprehensive summary and illustrative examples can be effectively generated.
这个C++源代码文件 `v8/src/objects/js-array-buffer.cc` 实现了 **JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 对象的核心功能**。它负责管理这些对象在 V8 引擎内部的表示、内存分配、以及与这些缓冲区相关的操作。

更具体地说，这个文件包含以下主要功能：

**1. `JSArrayBuffer` 类的实现:**

* **创建和初始化:**  `JSArrayBuffer::Setup` 方法负责初始化 `ArrayBuffer` 对象，包括设置其是否为共享 (`SharedFlag`)、是否可调整大小 (`ResizableFlag`)、以及关联的 `BackingStore` (实际存储数据的内存)。
* **内存管理:**
    * `Attach`:  将一个 `BackingStore` 关联到 `JSArrayBuffer` 对象。`BackingStore` 封装了实际的内存分配和管理。
    * `Detach`:  分离 `ArrayBuffer` 与其 `BackingStore`，释放对底层内存的引用。这用于实现 `ArrayBuffer.prototype.detach()` 方法。
    *  与 `ArrayBufferExtension` 相关的操作 (`EnsureExtension`, `RemoveExtension`, `MarkExtension`, `YoungMarkExtension`, `YoungMarkExtensionPromoted`):  `ArrayBufferExtension` 似乎是用于存储与 `ArrayBuffer` 相关的额外信息，比如会计信息和 `BackingStore` 的智能指针。
* **获取长度:** `JSArrayBuffer::GsabByteLength` 用于获取 `SharedArrayBuffer` 的当前字节长度。
* **可调整大小的 `ArrayBuffer` 支持:**  `JSArrayBuffer::GetResizableBackingStorePageConfiguration`  用于计算可调整大小的 `ArrayBuffer` 的初始和最大页数。

**2. 与 `TypedArray` 的交互:**

* **`JSTypedArray::GetBuffer()`:**  允许从一个 `TypedArray` 对象获取其底层的 `ArrayBuffer`。如果 `TypedArray` 最初是在堆上的（例如，直接创建的），则此方法会创建一个新的 `ArrayBuffer` 并将数据复制过去。
* **`JSTypedArray::DefineOwnProperty()`:**  覆盖了 `TypedArray` 的 `defineProperty` 行为，特别处理了对索引属性的定义，并与 `JSArrayBuffer` 的长度和状态相关联。
* **`JSTypedArray::LengthTrackingGsabBackedTypedArrayLength()` 和 `JSTypedArray::GetVariableLengthOrOutOfBounds()`:**  用于获取由可调整大小的共享 `ArrayBuffer` 支持的 `TypedArray` 的长度，并处理越界访问。

**3. 辅助函数:**

* **`CanonicalNumericIndexString`:**  判断一个字符串是否可以被转换为有效的数组索引。这在处理 `TypedArray` 的属性访问时非常重要。

**与 JavaScript 功能的关系和示例:**

这个文件直接实现了 JavaScript 中的 `ArrayBuffer` 和 `SharedArrayBuffer` 对象，以及它们与 `TypedArray` 的交互。

**1. `ArrayBuffer` 的创建和基本操作:**

```javascript
// 创建一个 16 字节的 ArrayBuffer
const buffer = new ArrayBuffer(16);
console.log(buffer.byteLength); // 输出: 16

// 创建一个指向 ArrayBuffer 的 Uint8Array 视图
const view = new Uint8Array(buffer);
view[0] = 42;
console.log(view[0]); // 输出: 42
```

`JSArrayBuffer::Setup` 在 JavaScript 中 `new ArrayBuffer(16)` 时被调用，负责分配 16 字节的内存。`Uint8Array` 的创建和访问则涉及到 `JSTypedArray` 的相关逻辑。

**2. `SharedArrayBuffer` 的创建和使用:**

```javascript
// 创建一个共享的 1024 字节的 SharedArrayBuffer
const sharedBuffer = new SharedArrayBuffer(1024);
console.log(sharedBuffer.byteLength); // 输出: 1024

// 在多个 Worker 之间共享 sharedBuffer
const worker = new Worker('worker.js');
worker.postMessage(sharedBuffer);
```

`JSArrayBuffer::Setup` 也会在 `new SharedArrayBuffer(1024)` 时被调用，但会设置相应的标志表明这是一个共享缓冲区。

**3. `ArrayBuffer.prototype.detach()`:**

```javascript
const buffer = new ArrayBuffer(10);
console.log(buffer.byteLength); // 输出: 10

buffer.detach();
console.log(buffer.byteLength); // 输出: 0

try {
  const view = new Uint8Array(buffer); // 抛出错误
} catch (e) {
  console.error(e); // 输出: TypeError: Cannot perform %TypedArray%.prototype.byteLength on a detached ArrayBuffer
}
```

`JSArrayBuffer::Detach` 方法实现了 `detach()` 的核心逻辑，释放底层内存，并使相关的 `TypedArray` 视图失效。

**4. `TypedArray` 从 `ArrayBuffer` 获取数据:**

```javascript
const buffer = new ArrayBuffer(8);
const view1 = new Int32Array(buffer);
const view2 = new Uint16Array(buffer);

view1[0] = 100;
console.log(view2[0]); // 输出取决于字节序，例如可能是 100 或其他值
```

`JSTypedArray::GetBuffer()` 在幕后被使用，尽管在这个例子中并没有显式调用。当创建一个 `TypedArray` 时，它会关联到一个 `ArrayBuffer`，并使用 `JSArrayBuffer` 中管理的内存。

**5. 可调整大小的 `ArrayBuffer` (Resizable ArrayBuffer):**

```javascript
const buffer = new ArrayBuffer(10, { maxByteLength: 100 });
console.log(buffer.resizable); // 输出: true

// 目前 JavaScript 中还没有标准的 API 来调整 Resizable ArrayBuffer 的大小，
// 但 V8 内部会使用相关的 C++ 代码来支持这种功能。
```

`JSArrayBuffer::Setup` 会根据传入的 `maxByteLength` 参数来设置 `ArrayBuffer` 是否可调整大小。`JSArrayBuffer::GetResizableBackingStorePageConfiguration` 会在内存分配时被使用。

**总结:**

`v8/src/objects/js-array-buffer.cc` 文件是 V8 引擎中关于 `ArrayBuffer` 和 `SharedArrayBuffer` 的基础设施，它负责对象的创建、内存管理、以及与 `TypedArray` 的协同工作。 它背后的 C++ 代码使得 JavaScript 能够高效地处理二进制数据。理解这个文件有助于深入了解 JavaScript 中内存管理和底层数据结构的工作方式。

### 提示词
```
这是目录为v8/src/objects/js-array-buffer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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