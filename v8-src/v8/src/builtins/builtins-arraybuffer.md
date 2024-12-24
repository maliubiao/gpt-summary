Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the `builtins-arraybuffer.cc` file and illustrate its connection to JavaScript's `ArrayBuffer` and `SharedArrayBuffer` features.

2. **Initial Scan for Keywords:**  Immediately look for recognizable keywords related to `ArrayBuffer` and `SharedArrayBuffer`. The file name itself is a strong indicator. Scanning the code quickly reveals the presence of `ArrayBufferConstructor`, `ArrayBufferPrototypeSlice`, `SharedArrayBufferPrototypeSlice`, `ArrayBufferPrototypeResize`, `SharedArrayBufferPrototypeGrow`, and `ArrayBufferPrototypeTransfer`. These are strong clues about the file's purpose.

3. **Identify Core Functionality Areas:** Based on the keywords, the code seems to handle:
    * **Construction:** Creating new `ArrayBuffer` and `SharedArrayBuffer` instances.
    * **Slicing:** Creating a new buffer containing a portion of an existing one.
    * **Resizing (for `ArrayBuffer`):**  Changing the size of an existing `ArrayBuffer`.
    * **Growing (for `SharedArrayBuffer`):** Increasing the size of an existing `SharedArrayBuffer`.
    * **Transferring:** Creating a new `ArrayBuffer` and moving the data from an existing one.

4. **Examine Key Functions and Macros:**
    * **`BUILTIN(...)` macros:**  These indicate functions that are exposed as built-in JavaScript methods. Pay close attention to the names within the macro, as they directly correspond to JavaScript APIs.
    * **`CHECK_SHARED`, `CHECK_RESIZABLE` macros:** These are important for understanding constraints on `ArrayBuffer` and `SharedArrayBuffer` operations (whether they are shared, resizable, etc.). They throw `TypeError` exceptions if the conditions aren't met. This directly relates to JavaScript's runtime error handling.
    * **`ConstructBuffer` function:**  This function appears to be the central logic for creating both `ArrayBuffer` and `SharedArrayBuffer` instances, handling length and maximum length parameters.
    * **`SliceHelper` function:** This function implements the core logic for the `slice` method, handling start and end indices and the creation of the new buffer.
    * **`ResizeHelper` function:** This handles the resizing logic for `ArrayBuffer` and the growing logic for `SharedArrayBuffer`.
    * **`ArrayBufferTransfer` function:**  This function deals with the data transfer mechanism between `ArrayBuffer` instances.

5. **Connect C++ Code to JavaScript Concepts:** For each identified functionality area, think about the corresponding JavaScript API.
    * **Construction:**  `new ArrayBuffer(length)` and `new SharedArrayBuffer(length)`. The code also reveals handling of `maxByteLength` for resizable buffers.
    * **Slicing:** `arrayBuffer.slice(start, end)` and `sharedArrayBuffer.slice(start, end)`.
    * **Resizing:** `arrayBuffer.resize(newLength)`.
    * **Growing:** `sharedArrayBuffer.grow(newLength)`.
    * **Transferring:** `arrayBuffer.transfer(newLength)` and `arrayBuffer.transferToFixedLength(newLength)`.

6. **Illustrate with JavaScript Examples:**  Create concise JavaScript code snippets demonstrating the use of the corresponding APIs. Focus on showing the basic functionality and how it relates to the C++ implementation. For example, the `CHECK_SHARED` macro is directly related to the `TypeError` you get when trying to slice a non-shared buffer with the `SharedArrayBuffer.prototype.slice` method.

7. **Summarize the Functionality:**  Write a clear and concise summary of the file's purpose. Highlight the core functionalities and the distinction between `ArrayBuffer` and `SharedArrayBuffer`. Mention the connection to JavaScript.

8. **Review and Refine:** Read through the summary and examples to ensure accuracy and clarity. Check for any inconsistencies or areas that could be explained better. For instance, explicitly mentioning the `TypeError` exceptions thrown by the checks improves understanding.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the file also handles data views (like `Uint8Array`).
* **Correction:**  A closer look at the function names and the included headers suggests the focus is specifically on the `ArrayBuffer` and `SharedArrayBuffer` *themselves*, not the views. Data views would likely be in a separate file.
* **Initial thought:** The examples could be more complex.
* **Correction:**  Simple, focused examples are better for illustrating the core functionality. Complex scenarios can be overwhelming and obscure the connection to the C++ code.
* **Refinement:** Explicitly mention the role of the `SpeciesConstructor` in the `slice` method, as it's a key concept in JavaScript for controlling the type of the returned object.

By following these steps, combining code analysis with knowledge of JavaScript APIs, one can effectively summarize the functionality of a C++ file like `builtins-arraybuffer.cc` and demonstrate its relevance to JavaScript.
这个C++源代码文件 `builtins-arraybuffer.cc` 主要负责实现 **JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 相关的内建函数 (built-in functions)**。它定义了这些对象构造函数和原型方法在 V8 引擎中的具体行为。

**核心功能归纳:**

1. **构造函数 (`ArrayBufferConstructor`, `ArrayBufferConstructor_DoNotInitialize`):**
   - 实现了 `ArrayBuffer` 和 `SharedArrayBuffer` 的构造过程。
   - 处理了构造时传入的 `length` 参数，用于指定缓冲区的字节大小。
   - 允许创建可调整大小的 `ArrayBuffer` (resizable array buffers) 和可增长的 `SharedArrayBuffer` (growable shared array buffers)，需要处理 `maxByteLength` 参数。
   -  `ArrayBufferConstructor_DoNotInitialize` 是一种特殊构造方式，用于创建未初始化的 `ArrayBuffer`，需要调用者确保后续初始化。

2. **原型方法 (`ArrayBufferPrototypeSlice`, `SharedArrayBufferPrototypeSlice`):**
   - 实现了 `ArrayBuffer.prototype.slice()` 和 `SharedArrayBuffer.prototype.slice()` 方法。
   - 用于创建现有缓冲区的浅拷贝，可以指定起始和结束位置。
   - 涉及到类型检查、边界检查以及新缓冲区的创建和数据拷贝。
   - 考虑了 `SpeciesConstructor`，允许子类自定义 slice 操作返回的对象类型。

3. **原型方法 (`ArrayBufferPrototypeResize`):**
   - 实现了 `ArrayBuffer.prototype.resize()` 方法 (仅针对可调整大小的 `ArrayBuffer`)。
   - 允许改变 `ArrayBuffer` 的字节长度，但不能超过其 `maxByteLength`。
   - 涉及到内存的重新分配和可能的拷贝。

4. **原型方法 (`SharedArrayBufferPrototypeGrow`):**
   - 实现了 `SharedArrayBuffer.prototype.grow()` 方法 (仅针对可增长的 `SharedArrayBuffer`)。
   - 允许增加 `SharedArrayBuffer` 的字节长度，但不能超过其初始设置的 `maxByteLength`。

5. **原型方法 (`ArrayBufferPrototypeTransfer`, `ArrayBufferPrototypeTransferToFixedLength`):**
   - 实现了 `ArrayBuffer.prototype.transfer()` 和 `ArrayBuffer.prototype.transferToFixedLength()` 方法。
   - 用于创建一个新的 `ArrayBuffer`，并将原 `ArrayBuffer` 的内容移动（或拷贝）到新缓冲区，并将原缓冲区分离 (detached)。
   - `transferToFixedLength` 总是创建一个不可调整大小的新缓冲区。

6. **Getter 方法 (`SharedArrayBufferPrototypeGetByteLength`):**
   - 实现了 `get SharedArrayBuffer.prototype.byteLength` 访问器。
   - 用于获取 `SharedArrayBuffer` 当前的字节长度。

7. **内部辅助函数 (`ConstructBuffer`, `SliceHelper`, `ResizeHelper`, `ArrayBufferTransfer`):**
   - 提供了一些通用的逻辑，被不同的内建函数调用，以避免代码重复。
   - 例如 `ConstructBuffer` 负责实际的缓冲区内存分配和初始化。
   - `SliceHelper` 包含了 `slice` 方法的核心逻辑。

8. **类型检查和错误处理:**
   - 使用宏 (`CHECK_SHARED`, `CHECK_RESIZABLE`) 来确保方法调用的接收者类型正确 (是 `ArrayBuffer` 还是 `SharedArrayBuffer`，是否可调整大小)。
   - 当参数无效或操作不被允许时，会抛出相应的 JavaScript 错误 (例如 `TypeError`, `RangeError`)。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接实现了 JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 的核心功能。你在 JavaScript 中使用的相关 API 的行为，都由这里的 C++ 代码来定义和执行。

**JavaScript 示例:**

```javascript
// 创建 ArrayBuffer
const buffer = new ArrayBuffer(16); // 创建一个 16 字节的 ArrayBuffer
console.log(buffer.byteLength); // 输出 16

// 创建 SharedArrayBuffer
const sharedBuffer = new SharedArrayBuffer(32); // 创建一个 32 字节的 SharedArrayBuffer
console.log(sharedBuffer.byteLength); // 输出 32

// slice 方法
const slice1 = buffer.slice(4, 8); // 创建 buffer 的一个从索引 4 到 7 的切片
console.log(slice1.byteLength); // 输出 4

const sharedSlice = sharedBuffer.slice(10); // 创建 sharedBuffer 从索引 10 到末尾的切片
console.log(sharedSlice.byteLength); // 输出 22

// 可调整大小的 ArrayBuffer (需要启用实验性特性)
// const resizableBuffer = new ArrayBuffer(8, { maxByteLength: 16 });
// resizableBuffer.resize(12);
// console.log(resizableBuffer.byteLength); // 输出 12

// 可增长的 SharedArrayBuffer (需要启用实验性特性)
// const growableSharedBuffer = new SharedArrayBuffer(8, { maxByteLength: 32 });
// growableSharedBuffer.grow(24);
// console.log(growableSharedBuffer.byteLength); // 输出 24

// transfer 方法
const originalBuffer = new ArrayBuffer(10);
const view = new Uint8Array(originalBuffer);
view.fill(1);

const transferredBuffer = originalBuffer.transfer(5);
console.log(transferredBuffer.byteLength); // 输出 5
// console.log(originalBuffer.byteLength); // 访问已分离的 buffer 会报错

const transferredToFixed = originalBuffer.transferToFixedLength(7);
console.log(transferredToFixed.byteLength); // 输出 7

// 获取 SharedArrayBuffer 的 byteLength
console.log(sharedBuffer.byteLength); // 输出 32
```

**总结:**

`builtins-arraybuffer.cc` 是 V8 引擎中至关重要的一个文件，它实现了 JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 对象的底层行为。它处理了对象的创建、内存管理、数据拷贝以及各种原型方法的实现，确保了 JavaScript 中这些核心数据结构的正确性和性能。理解这个文件的功能有助于深入理解 JavaScript 内存模型和并发编程的基础。

Prompt: 
```
这是目录为v8/src/builtins/builtins-arraybuffer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/execution/protectors-inl.h"
#include "src/execution/protectors.h"
#include "src/handles/maybe-handles-inl.h"
#include "src/heap/heap-inl.h"  // For ToBoolean. TODO(jkummerow): Drop.
#include "src/logging/counters.h"
#include "src/numbers/conversions.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

#define CHECK_SHARED(expected, name, method)                                \
  if (name->is_shared() != expected) {                                      \
    THROW_NEW_ERROR_RETURN_FAILURE(                                         \
        isolate,                                                            \
        NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,          \
                     isolate->factory()->NewStringFromAsciiChecked(method), \
                     name));                                                \
  }

#define CHECK_RESIZABLE(expected, name, method)                             \
  if (name->is_resizable_by_js() != expected) {                             \
    THROW_NEW_ERROR_RETURN_FAILURE(                                         \
        isolate,                                                            \
        NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,          \
                     isolate->factory()->NewStringFromAsciiChecked(method), \
                     name));                                                \
  }

// -----------------------------------------------------------------------------
// ES#sec-arraybuffer-objects

namespace {

Tagged<Object> ConstructBuffer(Isolate* isolate, Handle<JSFunction> target,
                               Handle<JSReceiver> new_target,
                               DirectHandle<Object> length,
                               Handle<Object> max_length,
                               InitializedFlag initialized) {
  SharedFlag shared = *target != target->native_context()->array_buffer_fun()
                          ? SharedFlag::kShared
                          : SharedFlag::kNotShared;
  ResizableFlag resizable = max_length.is_null() ? ResizableFlag::kNotResizable
                                                 : ResizableFlag::kResizable;
  Handle<JSObject> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      JSObject::New(target, new_target, Handle<AllocationSite>::null(),
                    NewJSObjectType::kAPIWrapper));
  auto array_buffer = Cast<JSArrayBuffer>(result);
  // Ensure that all fields are initialized because BackingStore::Allocate is
  // allowed to GC. Note that we cannot move the allocation of the ArrayBuffer
  // after BackingStore::Allocate because of the spec.
  array_buffer->Setup(shared, resizable, nullptr, isolate);

  size_t byte_length;
  size_t max_byte_length = 0;
  if (!TryNumberToSize(*length, &byte_length) ||
      byte_length > JSArrayBuffer::kMaxByteLength) {
    // ToNumber failed.
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferLength));
  }

  std::unique_ptr<BackingStore> backing_store;
  if (resizable == ResizableFlag::kNotResizable) {
    backing_store =
        BackingStore::Allocate(isolate, byte_length, shared, initialized);
    max_byte_length = byte_length;
  } else {
    static_assert(JSArrayBuffer::kMaxByteLength ==
                  JSTypedArray::kMaxByteLength);
    if (!TryNumberToSize(*max_length, &max_byte_length) ||
        max_byte_length > JSArrayBuffer::kMaxByteLength) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidArrayBufferMaxLength));
    }
    if (byte_length > max_byte_length) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidArrayBufferMaxLength));
    }

    size_t page_size, initial_pages, max_pages;
    MAYBE_RETURN(JSArrayBuffer::GetResizableBackingStorePageConfiguration(
                     isolate, byte_length, max_byte_length, kThrowOnError,
                     &page_size, &initial_pages, &max_pages),
                 ReadOnlyRoots(isolate).exception());

    backing_store = BackingStore::TryAllocateAndPartiallyCommitMemory(
        isolate, byte_length, max_byte_length, page_size, initial_pages,
        max_pages, WasmMemoryFlag::kNotWasm, shared);
  }
  if (!backing_store) {
    // Allocation of backing store failed.
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kArrayBufferAllocationFailed));
  }

  array_buffer->Attach(std::move(backing_store));
  array_buffer->set_max_byte_length(max_byte_length);
  return *array_buffer;
}

}  // namespace

// ES #sec-arraybuffer-constructor
BUILTIN(ArrayBufferConstructor) {
  HandleScope scope(isolate);
  Handle<JSFunction> target = args.target();
  DCHECK(*target == target->native_context()->array_buffer_fun() ||
         *target == target->native_context()->shared_array_buffer_fun());
  if (IsUndefined(*args.new_target(), isolate)) {  // [[Call]]
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              handle(target->shared()->Name(), isolate)));
  }
  // [[Construct]]
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());
  Handle<Object> length = args.atOrUndefined(isolate, 1);

  Handle<Object> number_length;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, number_length,
                                     Object::ToInteger(isolate, length));
  if (Object::NumberValue(*number_length) < 0.0) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferLength));
  }

  Handle<Object> number_max_length;
  Handle<Object> max_length;
  Handle<Object> options = args.atOrUndefined(isolate, 2);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, max_length,
      JSObject::ReadFromOptionsBag(
          options, isolate->factory()->max_byte_length_string(), isolate));

  if (!IsUndefined(*max_length, isolate)) {
    if (*target == target->native_context()->array_buffer_fun()) {
      isolate->CountUsage(
          v8::Isolate::UseCounterFeature::kResizableArrayBuffer);
    } else {
      isolate->CountUsage(
          v8::Isolate::UseCounterFeature::kGrowableSharedArrayBuffer);
    }
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, number_max_length,
                                       Object::ToInteger(isolate, max_length));
  }
  return ConstructBuffer(isolate, target, new_target, number_length,
                         number_max_length, InitializedFlag::kZeroInitialized);
}

// This is a helper to construct an ArrayBuffer with uinitialized memory.
// This means the caller must ensure the buffer is totally initialized in
// all cases, or we will expose uinitialized memory to user code.
BUILTIN(ArrayBufferConstructor_DoNotInitialize) {
  HandleScope scope(isolate);
  Handle<JSFunction> target(isolate->native_context()->array_buffer_fun(),
                            isolate);
  DirectHandle<Object> length = args.atOrUndefined(isolate, 1);
  return ConstructBuffer(isolate, target, target, length, Handle<Object>(),
                         InitializedFlag::kUninitialized);
}

static Tagged<Object> SliceHelper(BuiltinArguments args, Isolate* isolate,
                                  const char* kMethodName, bool is_shared) {
  HandleScope scope(isolate);
  Handle<Object> start = args.at(1);
  Handle<Object> end = args.atOrUndefined(isolate, 2);

  // * If Type(O) is not Object, throw a TypeError exception.
  // * If O does not have an [[ArrayBufferData]] internal slot, throw a
  //   TypeError exception.
  CHECK_RECEIVER(JSArrayBuffer, array_buffer, kMethodName);
  // * [AB] If IsSharedArrayBuffer(O) is true, throw a TypeError exception.
  // * [SAB] If IsSharedArrayBuffer(O) is false, throw a TypeError exception.
  CHECK_SHARED(is_shared, array_buffer, kMethodName);

  // * [AB] If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  if (!is_shared && array_buffer->was_detached()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  kMethodName)));
  }

  // * [AB] Let len be O.[[ArrayBufferByteLength]].
  // * [SAB] Let len be O.[[ArrayBufferByteLength]].
  double const len = array_buffer->GetByteLength();

  // * Let relativeStart be ? ToInteger(start).
  Handle<Object> relative_start;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, relative_start,
                                     Object::ToInteger(isolate, start));

  // * If relativeStart < 0, let first be max((len + relativeStart), 0); else
  //   let first be min(relativeStart, len).
  double const first =
      (Object::NumberValue(*relative_start) < 0)
          ? std::max(len + Object::NumberValue(*relative_start), 0.0)
          : std::min(Object::NumberValue(*relative_start), len);

  // * If end is undefined, let relativeEnd be len; else let relativeEnd be ?
  //   ToInteger(end).
  double relative_end;
  if (IsUndefined(*end, isolate)) {
    relative_end = len;
  } else {
    Handle<Object> relative_end_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, relative_end_obj,
                                       Object::ToInteger(isolate, end));
    relative_end = Object::NumberValue(*relative_end_obj);
  }

  // * If relativeEnd < 0, let final be max((len + relativeEnd), 0); else let
  //   final be min(relativeEnd, len).
  double const final_ = (relative_end < 0) ? std::max(len + relative_end, 0.0)
                                           : std::min(relative_end, len);

  // * Let newLen be max(final-first, 0).
  double const new_len = std::max(final_ - first, 0.0);
  Handle<Object> new_len_obj = isolate->factory()->NewNumber(new_len);

  // * [AB] Let ctor be ? SpeciesConstructor(O, %ArrayBuffer%).
  // * [SAB] Let ctor be ? SpeciesConstructor(O, %SharedArrayBuffer%).
  Handle<JSFunction> constructor_fun = is_shared
                                           ? isolate->shared_array_buffer_fun()
                                           : isolate->array_buffer_fun();
  Handle<Object> ctor;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, ctor,
      Object::SpeciesConstructor(isolate, Cast<JSReceiver>(args.receiver()),
                                 constructor_fun));

  // * Let new be ? Construct(ctor, newLen).
  Handle<JSReceiver> new_;
  {
    constexpr int argc = 1;
    std::array<Handle<Object>, argc> argv = {new_len_obj};

    Handle<Object> new_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, new_obj, Execution::New(isolate, ctor, argc, argv.data()));

    new_ = Cast<JSReceiver>(new_obj);
  }

  // * If new does not have an [[ArrayBufferData]] internal slot, throw a
  //   TypeError exception.
  if (!IsJSArrayBuffer(*new_)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                     isolate->factory()->NewStringFromAsciiChecked(kMethodName),
                     new_));
  }

  // * [AB] If IsSharedArrayBuffer(new) is true, throw a TypeError exception.
  // * [SAB] If IsSharedArrayBuffer(new) is false, throw a TypeError exception.
  Handle<JSArrayBuffer> new_array_buffer = Cast<JSArrayBuffer>(new_);
  CHECK_SHARED(is_shared, new_array_buffer, kMethodName);

  // The created ArrayBuffer might or might not be resizable, since the species
  // constructor might return a non-resizable or a resizable buffer.

  // * [AB] If IsDetachedBuffer(new) is true, throw a TypeError exception.
  if (!is_shared && new_array_buffer->was_detached()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  kMethodName)));
  }

  // * [AB] If SameValue(new, O) is true, throw a TypeError exception.
  if (!is_shared && Object::SameValue(*new_, *args.receiver())) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kArrayBufferSpeciesThis));
  }

  // * [SAB] If new.[[ArrayBufferData]] and O.[[ArrayBufferData]] are the same
  //         Shared Data Block values, throw a TypeError exception.
  if (is_shared &&
      new_array_buffer->backing_store() == array_buffer->backing_store()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kSharedArrayBufferSpeciesThis));
  }

  // * If new.[[ArrayBufferByteLength]] < newLen, throw a TypeError exception.
  size_t new_array_buffer_byte_length = new_array_buffer->GetByteLength();
  if (new_array_buffer_byte_length < new_len) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(is_shared ? MessageTemplate::kSharedArrayBufferTooShort
                               : MessageTemplate::kArrayBufferTooShort));
  }

  // * [AB] NOTE: Side-effects of the above steps may have detached O.
  // * [AB] If IsDetachedBuffer(O) is true, throw a TypeError exception.
  if (!is_shared && array_buffer->was_detached()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  kMethodName)));
  }

  // * Let fromBuf be O.[[ArrayBufferData]].
  // * Let toBuf be new.[[ArrayBufferData]].
  // * Perform CopyDataBlockBytes(toBuf, 0, fromBuf, first, newLen).
  size_t first_size = first;
  size_t new_len_size = new_len;
  DCHECK(new_array_buffer_byte_length >= new_len_size);

  if (new_len_size != 0) {
    size_t from_byte_length = array_buffer->GetByteLength();
    if (V8_UNLIKELY(!is_shared && array_buffer->is_resizable_by_js())) {
      // The above steps might have resized the underlying buffer. In that case,
      // only copy the still-accessible portion of the underlying data.
      if (first_size > from_byte_length) {
        return *new_;  // Nothing to copy.
      }
      if (new_len_size > from_byte_length - first_size) {
        new_len_size = from_byte_length - first_size;
      }
    }
    DCHECK(first_size <= from_byte_length);
    DCHECK(from_byte_length - first_size >= new_len_size);
    uint8_t* from_data =
        reinterpret_cast<uint8_t*>(array_buffer->backing_store()) + first_size;
    uint8_t* to_data =
        reinterpret_cast<uint8_t*>(new_array_buffer->backing_store());
    if (is_shared) {
      base::Relaxed_Memcpy(reinterpret_cast<base::Atomic8*>(to_data),
                           reinterpret_cast<base::Atomic8*>(from_data),
                           new_len_size);
    } else {
      CopyBytes(to_data, from_data, new_len_size);
    }
  }

  return *new_;
}

// ES #sec-sharedarraybuffer.prototype.slice
BUILTIN(SharedArrayBufferPrototypeSlice) {
  const char* const kMethodName = "SharedArrayBuffer.prototype.slice";
  return SliceHelper(args, isolate, kMethodName, true);
}

// ES #sec-arraybuffer.prototype.slice
// ArrayBuffer.prototype.slice ( start, end )
BUILTIN(ArrayBufferPrototypeSlice) {
  const char* const kMethodName = "ArrayBuffer.prototype.slice";
  return SliceHelper(args, isolate, kMethodName, false);
}

static Tagged<Object> ResizeHelper(BuiltinArguments args, Isolate* isolate,
                                   const char* kMethodName, bool is_shared) {
  HandleScope scope(isolate);

  // 1 Let O be the this value.
  // 2. Perform ? RequireInternalSlot(O, [[ArrayBufferMaxByteLength]]).
  CHECK_RECEIVER(JSArrayBuffer, array_buffer, kMethodName);
  CHECK_RESIZABLE(true, array_buffer, kMethodName);

  // [RAB] 3. If IsSharedArrayBuffer(O) is true, throw a *TypeError* exception
  // [GSAB] 3. If IsSharedArrayBuffer(O) is false, throw a *TypeError* exception
  CHECK_SHARED(is_shared, array_buffer, kMethodName);

  // Let newByteLength to ? ToIntegerOrInfinity(newLength).
  Handle<Object> new_length = args.at(1);
  Handle<Object> number_new_byte_length;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, number_new_byte_length,
                                     Object::ToInteger(isolate, new_length));

  // [RAB] If IsDetachedBuffer(O) is true, throw a TypeError exception.
  if (!is_shared && array_buffer->was_detached()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  kMethodName)));
  }

  // [RAB] If newByteLength < 0 or newByteLength >
  // O.[[ArrayBufferMaxByteLength]], throw a RangeError exception.

  // [GSAB] If newByteLength < currentByteLength or newByteLength >
  // O.[[ArrayBufferMaxByteLength]], throw a RangeError exception.
  size_t new_byte_length;
  if (!TryNumberToSize(*number_new_byte_length, &new_byte_length)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferResizeLength,
                               isolate->factory()->NewStringFromAsciiChecked(
                                   kMethodName)));
  }

  if (is_shared && new_byte_length < array_buffer->byte_length()) {
    // GrowableSharedArrayBuffer is only allowed to grow.
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferResizeLength,
                               isolate->factory()->NewStringFromAsciiChecked(
                                   kMethodName)));
  }

  if (new_byte_length > array_buffer->max_byte_length()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferResizeLength,
                               isolate->factory()->NewStringFromAsciiChecked(
                                   kMethodName)));
  }

  // [RAB] Let hostHandled be ? HostResizeArrayBuffer(O, newByteLength).
  // [GSAB] Let hostHandled be ? HostGrowArrayBuffer(O, newByteLength).
  // If hostHandled is handled, return undefined.

  // TODO(v8:11111, v8:12746): Wasm integration.

  if (!is_shared) {
    // [RAB] Let oldBlock be O.[[ArrayBufferData]].
    // [RAB] Let newBlock be ? CreateByteDataBlock(newByteLength).
    // [RAB] Let copyLength be min(newByteLength, O.[[ArrayBufferByteLength]]).
    // [RAB] Perform CopyDataBlockBytes(newBlock, 0, oldBlock, 0, copyLength).
    // [RAB] NOTE: Neither creation of the new Data Block nor copying from the
    // old Data Block are observable. Implementations reserve the right to
    // implement this method as in-place growth or shrinkage.
    if (array_buffer->GetBackingStore()->ResizeInPlace(isolate,
                                                       new_byte_length) !=
        BackingStore::ResizeOrGrowResult::kSuccess) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewRangeError(MessageTemplate::kOutOfMemory,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     kMethodName)));
    }

    // TypedsArrays in optimized code may go out of bounds. Trigger deopts
    // through the ArrayBufferDetaching protector.
    if (new_byte_length < array_buffer->byte_length()) {
      if (Protectors::IsArrayBufferDetachingIntact(isolate)) {
        Protectors::InvalidateArrayBufferDetaching(isolate);
      }
    }

    isolate->heap()->ResizeArrayBufferExtension(
        array_buffer->extension(),
        static_cast<int64_t>(new_byte_length) - array_buffer->byte_length());

    // [RAB] Set O.[[ArrayBufferByteLength]] to newLength.
    array_buffer->set_byte_length(new_byte_length);
  } else {
    // [GSAB] (Detailed description of the algorithm omitted.)
    auto result =
        array_buffer->GetBackingStore()->GrowInPlace(isolate, new_byte_length);
    if (result == BackingStore::ResizeOrGrowResult::kFailure) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewRangeError(MessageTemplate::kOutOfMemory,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     kMethodName)));
    }
    if (result == BackingStore::ResizeOrGrowResult::kRace) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate,
          NewRangeError(
              MessageTemplate::kInvalidArrayBufferResizeLength,
              isolate->factory()->NewStringFromAsciiChecked(kMethodName)));
    }
    // Invariant: byte_length for a GSAB is 0 (it needs to be read from the
    // BackingStore).
    CHECK_EQ(0, array_buffer->byte_length());
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

// ES #sec-get-sharedarraybuffer.prototype.bytelength
// get SharedArrayBuffer.prototype.byteLength
BUILTIN(SharedArrayBufferPrototypeGetByteLength) {
  const char* const kMethodName = "get SharedArrayBuffer.prototype.byteLength";
  HandleScope scope(isolate);
  // 1. Let O be the this value.
  // 2. Perform ? RequireInternalSlot(O, [[ArrayBufferData]]).
  CHECK_RECEIVER(JSArrayBuffer, array_buffer, kMethodName);
  // 3. If IsSharedArrayBuffer(O) is false, throw a TypeError exception.
  CHECK_SHARED(true, array_buffer, kMethodName);

  DCHECK_IMPLIES(!array_buffer->GetBackingStore()->is_wasm_memory(),
                 array_buffer->max_byte_length() ==
                     array_buffer->GetBackingStore()->max_byte_length());

  // 4. Let length be ArrayBufferByteLength(O, SeqCst).
  size_t byte_length = array_buffer->GetByteLength();
  // 5. Return F(length).
  return *isolate->factory()->NewNumberFromSize(byte_length);
}

// ES #sec-arraybuffer.prototype.resize
// ArrayBuffer.prototype.resize(new_size)
BUILTIN(ArrayBufferPrototypeResize) {
  const char* const kMethodName = "ArrayBuffer.prototype.resize";
  constexpr bool kIsShared = false;
  return ResizeHelper(args, isolate, kMethodName, kIsShared);
}

namespace {

enum PreserveResizability { kToFixedLength, kPreserveResizability };

Tagged<Object> ArrayBufferTransfer(Isolate* isolate,
                                   Handle<JSArrayBuffer> array_buffer,
                                   Handle<Object> new_length,
                                   PreserveResizability preserve_resizability,
                                   const char* method_name) {
  // 2. If IsSharedArrayBuffer(arrayBuffer) is true, throw a TypeError
  // exception.
  CHECK_SHARED(false, array_buffer, method_name);

  size_t new_byte_length;
  if (IsUndefined(*new_length, isolate)) {
    // 3. If newLength is undefined, then
    //   a. Let newByteLength be arrayBuffer.[[ArrayBufferByteLength]].
    new_byte_length = array_buffer->GetByteLength();
  } else {
    // 4. Else,
    //   a. Let newByteLength be ? ToIndex(newLength).
    Handle<Object> number_new_byte_length;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, number_new_byte_length,
                                       Object::ToInteger(isolate, new_length));
    if (Object::NumberValue(*number_new_byte_length) < 0.0) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferLength));
    }
    if (!TryNumberToSize(*number_new_byte_length, &new_byte_length) ||
        new_byte_length > JSArrayBuffer::kMaxByteLength) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate,
          NewRangeError(
              MessageTemplate::kInvalidArrayBufferResizeLength,
              isolate->factory()->NewStringFromAsciiChecked(method_name)));
    }
  }

  // 5. If IsDetachedBuffer(arrayBuffer) is true, throw a TypeError exception.
  if (array_buffer->was_detached()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kDetachedOperation,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }

  ResizableFlag resizable;
  size_t new_max_byte_length;
  if (preserve_resizability == kPreserveResizability &&
      array_buffer->is_resizable_by_js()) {
    // 6. If preserveResizability is preserve-resizability and
    //    IsResizableArrayBuffer(arrayBuffer) is true, then
    //   a. Let newMaxByteLength be arrayBuffer.[[ArrayBufferMaxByteLength]].
    new_max_byte_length = array_buffer->max_byte_length();
    resizable = ResizableFlag::kResizable;
  } else {
    // 7. Else,
    //   a. Let newMaxByteLength be empty.
    new_max_byte_length = new_byte_length;
    resizable = ResizableFlag::kNotResizable;
  }

  // 8. If arrayBuffer.[[ArrayBufferDetachKey]] is not undefined, throw a
  //     TypeError exception.

  if (!array_buffer->is_detachable()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kDataCloneErrorNonDetachableArrayBuffer));
  }

  // After this point the steps are not observable and are performed out of
  // spec order.

  // Case 1: We don't need a BackingStore.
  if (new_byte_length == 0) {
    // 15. Perform ! DetachArrayBuffer(arrayBuffer).
    JSArrayBuffer::Detach(array_buffer).Check();

    // 9. Let newBuffer be ? AllocateArrayBuffer(%ArrayBuffer%, newByteLength,
    //    newMaxByteLength).
    //
    // Nothing to do for steps 10-14.
    //
    // 16. Return newBuffer.
    return *isolate->factory()
                ->NewJSArrayBufferAndBackingStore(
                    0, new_max_byte_length, InitializedFlag::kUninitialized,
                    resizable)
                .ToHandleChecked();
  }

  // Case 2: We can reuse the same BackingStore.
  auto from_backing_store = array_buffer->GetBackingStore();
  if (from_backing_store && !from_backing_store->is_resizable_by_js() &&
      resizable == ResizableFlag::kNotResizable &&
      new_byte_length == array_buffer->GetByteLength()) {
    // TODO(syg): Consider realloc when the default ArrayBuffer allocator's
    // Reallocate does better than copy.
    //
    // See https://crbug.com/330575496#comment27

    // 15. Perform ! DetachArrayBuffer(arrayBuffer).
    JSArrayBuffer::Detach(array_buffer).Check();

    // 9. Let newBuffer be ? AllocateArrayBuffer(%ArrayBuffer%, newByteLength,
    //    newMaxByteLength).
    // 16. Return newBuffer.
    return *isolate->factory()->NewJSArrayBuffer(std::move(from_backing_store));
  }

  // Case 3: We can't reuse the same BackingStore. Copy the buffer.

  if (new_byte_length > new_max_byte_length) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayBufferLength));
  }

  // 9. Let newBuffer be ? AllocateArrayBuffer(%ArrayBuffer%, newByteLength,
  //    newMaxByteLength).
  Handle<JSArrayBuffer> new_buffer;
  MaybeHandle<JSArrayBuffer> result =
      isolate->factory()->NewJSArrayBufferAndBackingStore(
          new_byte_length, new_max_byte_length, InitializedFlag::kUninitialized,
          resizable);
  if (!result.ToHandle(&new_buffer)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kArrayBufferAllocationFailed));
  }

  // 10. Let copyLength be min(newByteLength,
  //    arrayBuffer.[[ArrayBufferByteLength]]).
  //
  // (Size comparison is done manually below instead of using min.)

  // 11. Let fromBlock be arrayBuffer.[[ArrayBufferData]].
  uint8_t* from_data =
      reinterpret_cast<uint8_t*>(array_buffer->backing_store());

  // 12. Let toBlock be newBuffer.[[ArrayBufferData]].
  uint8_t* to_data = reinterpret_cast<uint8_t*>(new_buffer->backing_store());

  // 13. Perform CopyDataBlockBytes(toBlock, 0, fromBlock, 0, copyLength).
  // 14. NOTE: Neither creation of the new Data Block nor copying from the old
  //     Data Block are observable. Implementations reserve the right to
  //     implement this method as a zero-copy move or a realloc.
  size_t from_byte_length = array_buffer->GetByteLength();
  if (new_byte_length <= from_byte_length) {
    CopyBytes(to_data, from_data, new_byte_length);
  } else {
    CopyBytes(to_data, from_data, from_byte_length);
    memset(to_data + from_byte_length, 0, new_byte_length - from_byte_length);
  }

  // 15. Perform ! DetachArrayBuffer(arrayBuffer).
  JSArrayBuffer::Detach(array_buffer).Check();

  // 16. Return newBuffer.
  return *new_buffer;
}

}  // namespace

// ES #sec-arraybuffer.prototype.transfer
// ArrayBuffer.prototype.transfer([new_length])
BUILTIN(ArrayBufferPrototypeTransfer) {
  const char kMethodName[] = "ArrayBuffer.prototype.transfer";
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::kArrayBufferTransfer);

  // 1. Perform ? RequireInternalSlot(arrayBuffer, [[ArrayBufferData]]).
  CHECK_RECEIVER(JSArrayBuffer, array_buffer, kMethodName);
  Handle<Object> new_length = args.atOrUndefined(isolate, 1);
  return ArrayBufferTransfer(isolate, array_buffer, new_length,
                             kPreserveResizability, kMethodName);
}

// ES #sec-arraybuffer.prototype.transferToFixedLength
// ArrayBuffer.prototype.transferToFixedLength([new_length])
BUILTIN(ArrayBufferPrototypeTransferToFixedLength) {
  const char kMethodName[] = "ArrayBuffer.prototype.transferToFixedLength";
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::kArrayBufferTransfer);

  // 1. Perform ? RequireInternalSlot(arrayBuffer, [[ArrayBufferData]]).
  CHECK_RECEIVER(JSArrayBuffer, array_buffer, kMethodName);
  Handle<Object> new_length = args.atOrUndefined(isolate, 1);
  return ArrayBufferTransfer(isolate, array_buffer, new_length, kToFixedLength,
                             kMethodName);
}

// ES #sec-sharedarraybuffer.prototype.grow
// SharedArrayBuffer.prototype.grow(new_size)
BUILTIN(SharedArrayBufferPrototypeGrow) {
  const char* const kMethodName = "SharedArrayBuffer.prototype.grow";
  constexpr bool kIsShared = true;
  return ResizeHelper(args, isolate, kMethodName, kIsShared);
}

}  // namespace internal
}  // namespace v8

"""

```