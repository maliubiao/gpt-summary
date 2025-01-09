Response:
Let's break down the thought process to analyze the provided C++ code for `v8/src/builtins/builtins-arraybuffer.cc`.

1. **Understand the Goal:** The primary objective is to understand the functionality of this specific C++ file within the V8 JavaScript engine. The prompt also gives hints about Torque and JavaScript relationships, which should be explored.

2. **Initial Code Scan (Keywords and Structure):**  Start by quickly scanning the code for recognizable keywords and structural elements:
    * `#include`: Indicates dependencies on other V8 components. Notice files like `builtins-utils-inl.h`, `builtins.h`, `objects/js-array-buffer-inl.h`, etc. These suggest the file deals with built-in JavaScript functionality related to ArrayBuffers.
    * `namespace v8 { namespace internal {`:  Clearly places the code within V8's internal implementation.
    * `#define`:  Macro definitions like `CHECK_SHARED` and `CHECK_RESIZABLE` hint at common checks performed within the functions. These likely enforce type constraints on the `this` value.
    * `BUILTIN(...)`: This is a crucial marker. It signifies functions that are exposed as built-in JavaScript methods. The names like `ArrayBufferConstructor`, `ArrayBufferPrototypeSlice`, etc., strongly suggest the file implements the core ArrayBuffer functionality.
    * Function names like `ConstructBuffer`, `SliceHelper`, `ResizeHelper`, `ArrayBufferTransfer`: These indicate specific operations related to ArrayBuffers.

3. **Identify Core Functionality Areas:** Based on the `BUILTIN` functions, group the functionality into logical areas:
    * **Construction:** `ArrayBufferConstructor`, `ArrayBufferConstructor_DoNotInitialize`. These are responsible for creating new ArrayBuffer instances.
    * **Slicing:** `ArrayBufferPrototypeSlice`, `SharedArrayBufferPrototypeSlice`. These implement the `slice()` method for both regular and shared ArrayBuffers.
    * **Resizing (Grow/Shrink):** `ArrayBufferPrototypeResize`, `SharedArrayBufferPrototypeGrow`. These handle the resizing of ArrayBuffers.
    * **Getting Byte Length:** `SharedArrayBufferPrototypeGetByteLength`. This implements the getter for the `byteLength` property.
    * **Transferring:** `ArrayBufferPrototypeTransfer`, `ArrayBufferPrototypeTransferToFixedLength`. These implement methods for transferring the underlying buffer of an ArrayBuffer.

4. **Analyze Key Functions in Detail:**  Focus on the most important `BUILTIN` functions and their helper functions:
    * **`ConstructBuffer`:** This function is called by the constructors. Notice the handling of `SharedFlag` and `ResizableFlag`, suggesting it deals with both regular and resizable ArrayBuffers. The allocation of `BackingStore` is a critical step. The logic for resizable buffers with `max_length` is also important.
    * **`SliceHelper`:** This function implements the core logic for `slice()`. Pay attention to the checks for detached buffers, shared status, and the creation of the new ArrayBuffer using the species constructor. The `CopyDataBlockBytes` operation is the core of the slicing process.
    * **`ResizeHelper`:** This handles both `resize()` and `grow()`. The code distinguishes between regular and shared ArrayBuffers and their resizing constraints. The interaction with `BackingStore::ResizeInPlace` and `BackingStore::GrowInPlace` is key. The invalidation of the `ArrayBufferDetaching` protector is a subtle detail related to optimization.
    * **`ArrayBufferTransfer`:** This function deals with transferring the backing store. The code handles cases where the size remains the same, is zero, or needs copying. The detachment of the original buffer is a crucial part of the transfer process.

5. **Connect to JavaScript:**  For each functional area, think about the corresponding JavaScript API and how the C++ code implements it. Provide simple JavaScript examples to illustrate the usage.

6. **Consider Potential Errors:** Examine the code for error handling (e.g., `THROW_NEW_ERROR_RETURN_FAILURE`). Think about the conditions that would trigger these errors and translate them into common programming mistakes in JavaScript. Detached buffers, invalid lengths, and type mismatches are likely candidates.

7. **Address Torque (if applicable):** The prompt mentions `.tq` files. Since the provided file is `.cc`, it's *not* a Torque file. Explicitly state this and explain what Torque is in the context of V8.

8. **Code Logic Inference (Hypothetical Input/Output):** For functions like `SliceHelper` and `ResizeHelper`, create simple scenarios with example inputs and expected outputs to illustrate the function's behavior. This helps in understanding the code's logic more concretely.

9. **Review and Refine:**  Go through the analysis, ensuring clarity, accuracy, and completeness. Check for any missing aspects or areas that need further explanation. Ensure the JavaScript examples are correct and relevant.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file handles all TypedArrays. **Correction:** Closer inspection of the `BUILTIN` names and includes reveals the focus is specifically on `ArrayBuffer` and `SharedArrayBuffer`.
* **Initial thought:**  The `#define` macros are just for brevity. **Correction:** Realize they are enforcing crucial type and state checks, essential for the security and correctness of ArrayBuffer operations.
* **Initial thought:**  Just list the `BUILTIN` functions. **Correction:** Grouping them by functionality provides a more organized and understandable analysis.
* **Missed detail:** Initially overlooked the `ArrayBufferDetaching` protector invalidation in `ResizeHelper`. **Correction:** Added this detail as it's an important aspect of how V8 handles optimizations and potential side effects.

By following this structured approach, combining code analysis with knowledge of JavaScript APIs and potential error scenarios, we can effectively understand the functionality of a complex V8 C++ file like `builtins-arraybuffer.cc`.
This C++ file, `v8/src/builtins/builtins-arraybuffer.cc`, contains the implementation of built-in functions for the `ArrayBuffer` and `SharedArrayBuffer` JavaScript objects in the V8 JavaScript engine.

Here's a breakdown of its functionality:

**Core Functionality:**

* **`ArrayBuffer` and `SharedArrayBuffer` Construction:**
    * Implements the `ArrayBuffer()` and `SharedArrayBuffer()` constructors, allowing the creation of new buffer objects in JavaScript. This includes handling the `length` argument to specify the size of the buffer in bytes, and the optional `maxByteLength` for resizable ArrayBuffers.
    * The `ConstructBuffer` helper function encapsulates the common logic for creating both types of buffers, handling initialization (zeroed or uninitialized memory), and checking for valid lengths.
    * `ArrayBufferConstructor_DoNotInitialize` provides a way to create `ArrayBuffer` instances with uninitialized memory, which is a more advanced feature used internally and requires careful handling to avoid exposing uninitialized data to JavaScript.

* **`ArrayBuffer.prototype.slice()` and `SharedArrayBuffer.prototype.slice()`:**
    * Implements the `slice()` method, which creates a new `ArrayBuffer` or `SharedArrayBuffer` containing a copy of a portion of the original buffer.
    * The `SliceHelper` function handles the shared logic, including argument parsing (start and end indices), bounds checking, and the actual copying of bytes. It also respects the "species constructor" pattern, allowing subclasses to control the type of the returned buffer.

* **`ArrayBuffer.prototype.resize()`:**
    * Implements the `resize()` method for resizable `ArrayBuffer` instances, allowing the byte length of the buffer to be changed after creation. This involves reallocating the underlying memory. It also handles potential deoptimization of optimized code that might be affected by the resizing.

* **`SharedArrayBuffer.prototype.grow()`:**
    * Implements the `grow()` method for `SharedArrayBuffer` instances, allowing the byte length to be increased. Growing a `SharedArrayBuffer` requires careful synchronization to avoid race conditions.

* **`SharedArrayBuffer.prototype.byteLength` (getter):**
    * Implements the getter for the `byteLength` property of `SharedArrayBuffer` instances, returning the current size of the buffer.

* **`ArrayBuffer.prototype.transfer()` and `ArrayBuffer.prototype.transferToFixedLength()`:**
    * Implement methods for transferring the underlying memory of an `ArrayBuffer` to a new `ArrayBuffer`. This is a zero-copy operation when possible, potentially avoiding the overhead of copying large amounts of data.
    * `transfer()` can create a new resizable buffer if the original was resizable.
    * `transferToFixedLength()` always creates a new non-resizable buffer.

**Relationship to JavaScript:**

This C++ code directly implements the functionality of the `ArrayBuffer` and `SharedArrayBuffer` objects that JavaScript developers interact with.

**JavaScript Examples:**

```javascript
// ArrayBuffer construction
const buffer = new ArrayBuffer(16); // Creates a 16-byte ArrayBuffer
const sharedBuffer = new SharedArrayBuffer(32); // Creates a 32-byte SharedArrayBuffer

// ArrayBuffer slice
const slice = buffer.slice(4, 8); // Creates a new 4-byte ArrayBuffer from bytes 4-7 of 'buffer'

// Resizable ArrayBuffer construction and resize
const resizableBuffer = new ArrayBuffer(8, { maxByteLength: 64 });
resizableBuffer.resize(16); // Resizes the buffer to 16 bytes

// SharedArrayBuffer grow
sharedBuffer.grow(64); // Increases the size of the shared buffer to 64 bytes

// Getting SharedArrayBuffer byteLength
console.log(sharedBuffer.byteLength); // Output: the current byte length of sharedBuffer

// ArrayBuffer transfer
const buffer1 = new ArrayBuffer(10);
const buffer2 = buffer1.transfer(20); // buffer1 is detached, buffer2 is a new 20-byte buffer with the content of the original buffer1 (up to 10 bytes)
const buffer3 = buffer1.transferToFixedLength(5); // buffer1 is detached, buffer3 is a new 5-byte non-resizable buffer.
```

**If `v8/src/builtins/builtins-arraybuffer.cc` ended with `.tq`:**

It would be a **V8 Torque source code file**. Torque is a domain-specific language developed by the V8 team for writing built-in functions. Torque code is statically typed and compiled into C++ code. It offers benefits like improved type safety and potentially better performance for certain built-in operations.

**Code Logic Inference (Hypothetical Input and Output for `ArrayBuffer.prototype.slice()`):**

**Assumption:**  We are focusing on the `ArrayBufferPrototypeSlice` function.

**Hypothetical Input:**

* `this` (receiver): An `ArrayBuffer` instance with a byte length of 10, containing the bytes `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]`.
* `start` argument: The number `2`.
* `end` argument: The number `7`.

**Code Logic:**

1. `SliceHelper` is called.
2. Input arguments are parsed: `start` is 2, `end` is 7.
3. Bounds are checked and adjusted: `first` becomes 2, `final` becomes 7.
4. `new_len` is calculated as `max(7 - 2, 0)`, which is 5.
5. A new `ArrayBuffer` (or a subclass as specified by the species constructor) with a length of 5 is created.
6. Bytes from the original buffer starting at index 2 (value 2) up to (but not including) index 7 (value 6) are copied to the new buffer.

**Hypothetical Output:**

A new `ArrayBuffer` instance with a byte length of 5, containing the bytes `[2, 3, 4, 5, 6]`.

**User Common Programming Errors:**

* **Incorrect `length` argument in constructors:**
    ```javascript
    // Error: Invalid array buffer length
    const buffer = new ArrayBuffer(-1);
    const buffer2 = new ArrayBuffer(Number.MAX_SAFE_INTEGER + 1);
    ```
* **Accessing detached buffers:**
    ```javascript
    const buffer1 = new ArrayBuffer(10);
    const buffer2 = buffer1.transfer(); // buffer1 is now detached
    // Error: Cannot perform operations on a detached ArrayBuffer
    const view = new Uint8Array(buffer1);
    ```
* **Out-of-bounds access with `slice()`:** While `slice()` handles bounds gracefully by clamping the start and end values, understanding the behavior is important.
    ```javascript
    const buffer = new ArrayBuffer(5);
    const slice = buffer.slice(10, 15); // Creates an empty buffer as start is out of bounds
    const slice2 = buffer.slice(2, 1); // Creates an empty buffer as end is before start
    ```
* **Using `resize()` on a non-resizable `ArrayBuffer`:**
    ```javascript
    const buffer = new ArrayBuffer(10);
    // Error: TypeError: Cannot perform 'resize' on non-resizable ArrayBuffer
    buffer.resize(20);

    const sharedBuffer = new SharedArrayBuffer(10);
    // Error: TypeError: Cannot perform 'resize' on SharedArrayBuffer
    sharedBuffer.resize(20);
    ```
* **Trying to shrink a `SharedArrayBuffer` with `grow()`:**
    ```javascript
    const sharedBuffer = new SharedArrayBuffer(20);
    // Error: RangeError: Invalid ArrayBuffer resize length
    sharedBuffer.grow(10);
    ```
* **Confusing `transfer()` and copying:**  `transfer()` detaches the original buffer, which can lead to unexpected errors if the original buffer is still being referenced.
* **Not understanding the implications of shared memory with `SharedArrayBuffer`:**  Modifying a `SharedArrayBuffer` from one context affects all other contexts sharing that buffer. This requires careful synchronization to prevent race conditions and data corruption.

This detailed explanation covers the functionality of the provided C++ code, its relationship to JavaScript, and common programming errors related to `ArrayBuffer` and `SharedArrayBuffer`.

Prompt: 
```
这是目录为v8/src/builtins/builtins-arraybuffer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-arraybuffer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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