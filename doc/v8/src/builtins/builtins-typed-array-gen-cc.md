Response:
Let's break down the thought process for analyzing the provided V8 source code.

1. **Identify the File and Its Location:** The first step is to note the file path: `v8/src/builtins/builtins-typed-array-gen.cc`. This immediately tells us it's related to TypedArray built-in functions within the V8 engine. The `.cc` extension indicates it's C++ code.

2. **Check for Torque Clues:** The prompt explicitly asks about `.tq` files, suggesting Torque. Scanning the code, we see `#include "src/codegen/define-code-stub-assembler-macros.inc"` and the use of `TF_BUILTIN`. `TF_BUILTIN` is a strong indicator that this code uses the CodeStubAssembler (CSA), which is the C++ backend for Torque. While this file itself isn't a `.tq` file, it *generates* code or functionality that interacts with the Torque-generated builtins (or is a C++ implementation for functionality that might have corresponding Torque parts).

3. **Understand the Purpose (Based on Filename and Includes):** The filename "builtins-typed-array-gen.cc" strongly suggests it's responsible for generating or implementing the core functionality of TypedArray objects in JavaScript. The included headers reinforce this:
    * `builtins-constructor-gen.h`: Likely related to the constructors of TypedArrays (e.g., `new Uint8Array(...)`).
    * `builtins-utils-gen.h`: Utility functions used within the builtins.
    * `builtins.h`:  Base definitions for built-in functions.
    * `growable-fixed-array-gen.h`:  Potentially used for internal data structures.
    * `execution/protectors.h`:  Mechanisms for optimizing and guarding against certain operations.
    * `handles/handles-inl.h`: V8's handle system for managing objects on the heap.
    * `heap/factory-inl.h`:  Creating objects on the V8 heap.
    * `objects/elements-kind.h`: Defines the different kinds of elements that can be stored in arrays (including TypedArrays).
    * `objects/js-array-buffer-inl.h`:  Represents the underlying buffer for TypedArrays.

4. **Analyze Key Functions and Their Actions:**  Go through the code and identify the main functions and what they do. Look for keywords like "Allocate," "Store," "Load," "CallBuiltin," "ThrowTypeError," etc. Here's a breakdown of some important functions:

    * `SetupTypedArrayEmbedderFields`:  Deals with setting up internal slots used by embedders (environments hosting V8).
    * `AllocateEmptyOnHeapBuffer`: Creates the underlying `ArrayBuffer` for TypedArrays. It sets up the buffer's properties, byte length, and backing store.
    * `TypedArrayBaseConstructor`:  Throws an error because `TypedArray` itself is abstract and cannot be directly constructed.
    * `TypedArrayConstructor`: Handles the main construction logic for specific TypedArray types (like `Uint8Array`). It calls `CreateTypedArray` (likely a Torque builtin).
    * `TypedArrayPrototypeByteLength`, `TypedArrayPrototypeByteOffset`, `TypedArrayPrototypeLength`: Implement the getter properties for byte length, byte offset, and length of a TypedArray. They involve checks for detached buffers.
    * `IsUint8ElementsKind`, `IsBigInt64ElementsKind`: Helper functions to check the element type.
    * `GetTypedArrayElementSize`, `GetTypedArrayElementsInfo`:  Retrieve information about the element size and kind.
    * `GetDefaultConstructor`:  Gets the constructor function for a given TypedArray type.
    * `ValidateTypedArray`, `ValidateTypedArrayAndGetLength`: Perform checks to ensure the object is a valid, non-detached TypedArray.
    * `CallCMemmove`, `CallCRelaxedMemmove`, `CallCMemcpy`, `CallCRelaxedMemcpy`, `CallCMemset`: These functions call the C standard library functions for memory manipulation. The "relaxed" variants likely have different memory ordering guarantees.
    * `CallCCopyFastNumberJSArrayElementsToTypedArray`, `CallCCopyTypedArrayElementsToTypedArray`, `CallCCopyTypedArrayElementsSlice`:  These call C++ functions to efficiently copy data between arrays.
    * `DispatchTypedArrayByElementsKind`: A crucial function that uses a switch statement (or similar logic) to handle different TypedArray types based on their element kind. This is fundamental to how V8 optimizes operations on different TypedArray types.
    * `SetJSTypedArrayOnHeapDataPtr`, `SetJSTypedArrayOffHeapDataPtr`: Set up the internal pointers to the underlying data buffer. They handle both on-heap and off-heap (external) buffers.
    * `StoreJSTypedArrayElementFromNumeric`, `StoreJSTypedArrayElementFromPreparedValue`, `StoreJSTypedArrayElementFromTagged`: Functions responsible for writing values into the TypedArray, handling type conversions and detached buffer checks.
    * `TypedArrayPrototypeToStringTag`:  Implements the `@@toStringTag` symbol, which determines the string representation of a TypedArray (e.g., "[object Uint8Array]").

5. **Relate to JavaScript Functionality:** Think about how these C++ functions map to JavaScript code. The constructors, the getter properties (`byteLength`, `byteOffset`, `length`), and operations that modify TypedArrays (setting elements) are the most obvious connections.

6. **Consider Error Scenarios:** Identify places where errors might occur. The code explicitly throws `TypeError` in several situations, such as:
    * Trying to construct the abstract `TypedArray`.
    * Calling a TypedArray constructor without `new`.
    * Accessing properties of a detached TypedArray.
    * Providing invalid arguments.

7. **Infer Code Logic and Examples:** Based on the function names and operations, create hypothetical scenarios to illustrate the code's behavior. For example, the `AllocateEmptyOnHeapBuffer` function suggests the creation of a zero-length buffer, and the constructor functions imply the process of creating and initializing TypedArray objects.

8. **Address the `.tq` Question:**  Reiterate that while this specific file is `.cc`, the presence of `TF_BUILTIN` and the overall architecture indicate a close relationship with Torque.

9. **Structure the Answer:** Organize the findings logically, starting with the main function, then delving into specific aspects like JavaScript examples, error handling, and code logic. Use clear headings and bullet points to make the information easy to digest.

Self-Correction/Refinement during the thought process:

* **Initial thought:** "This file implements *all* TypedArray functionality."  **Correction:**  It implements *core* functionality and likely *generates* code or interfaces with Torque for other parts.
* **Initial thought:** Focus solely on individual functions in isolation. **Correction:** Consider how the functions interact and the overall flow of operations, especially within the constructors and property accessors.
* **Overlook edge cases:**  Initially might miss the detached buffer checks. **Correction:** Pay close attention to `IsDetachedBuffer` and the error-throwing logic.
* **Not connecting C++ to JS:**  Describe the C++ functions but forget to illustrate their impact in JavaScript. **Correction:** Add concrete JavaScript examples to bridge the gap.

By following these steps and constantly refining the understanding of the code, we arrive at a comprehensive analysis like the example provided in the prompt.
`v8/src/builtins/builtins-typed-array-gen.cc` 是一个 V8 源代码文件，它实现了 **ECMAScript TypedArray 相关的内置函数**。 由于它以 `.cc` 结尾，所以这是一个 **V8 C++ 源代码文件**，而不是 Torque (`.tq`) 文件。

**主要功能列举:**

这个文件包含了一系列用于实现 TypedArray 功能的 C++ 内置函数。 这些功能涵盖了 TypedArray 对象的创建、属性访问、以及一些基本操作。 更具体地说，它实现了以下功能：

* **TypedArray 构造函数 (`TypedArrayConstructor`)**:  处理 `new Uint8Array(...)`, `new Int16Array(...)` 等构造函数的调用。 它负责根据传入的参数（长度、ArrayBuffer、偏移量等）创建并初始化新的 TypedArray 对象。
* **获取 TypedArray 的属性**:
    * `TypedArrayPrototypeByteLength`: 实现 `TypedArray.prototype.byteLength` getter，返回 TypedArray 占用的字节数。
    * `TypedArrayPrototypeByteOffset`: 实现 `TypedArray.prototype.byteOffset` getter，返回 TypedArray 在其底层 ArrayBuffer 中的起始偏移量（以字节为单位）。
    * `TypedArrayPrototypeLength`: 实现 `TypedArray.prototype.length` getter，返回 TypedArray 中元素的个数。
* **内部辅助函数**:
    * `SetupTypedArrayEmbedderFields`:  初始化 TypedArray 对象中用于嵌入器数据的字段。
    * `AllocateEmptyOnHeapBuffer`:  分配一个新的空的 ArrayBuffer。
    * `IsUint8ElementsKind`, `IsBigInt64ElementsKind`:  检查 TypedArray 的元素类型。
    * `GetTypedArrayElementSize`:  获取 TypedArray 元素的大小（以字节为单位）。
    * `GetTypedArrayElementsInfo`:  获取 TypedArray 的元素信息，包括大小和类型。
    * `GetDefaultConstructor`: 获取特定元素类型的 TypedArray 的默认构造函数。
    * `ValidateTypedArray`:  验证给定的对象是否是一个合法的 TypedArray 实例。
    * `ValidateTypedArrayAndGetLength`: 验证 TypedArray 并获取其长度。
* **内存操作辅助函数**:
    * `CallCMemmove`, `CallCRelaxedMemmove`, `CallCMemcpy`, `CallCRelaxedMemcpy`, `CallCMemset`:  调用 C 标准库的内存操作函数，用于高效地操作 ArrayBuffer 的内存。 "Relaxed" 版本可能用于处理并发场景。
* **数据拷贝辅助函数**:
    * `CallCCopyFastNumberJSArrayElementsToTypedArray`:  将普通 JavaScript 数组的数字元素快速拷贝到 TypedArray。
    * `CallCCopyTypedArrayElementsToTypedArray`:  将一个 TypedArray 的元素拷贝到另一个 TypedArray。
    * `CallCCopyTypedArrayElementsSlice`:  拷贝 TypedArray 的一部分元素到另一个 TypedArray。
* **类型分发函数**:
    * `DispatchTypedArrayByElementsKind`:  根据 TypedArray 的元素类型执行不同的代码分支，这是 V8 中优化 TypedArray 操作的关键技术。
* **设置数据指针函数**:
    * `SetJSTypedArrayOnHeapDataPtr`:  设置 TypedArray 对象指向其底层 ArrayBuffer 数据的指针 (当 ArrayBuffer 在堆上时)。
    * `SetJSTypedArrayOffHeapDataPtr`: 设置 TypedArray 对象指向其底层 ArrayBuffer 数据的指针 (当 ArrayBuffer 是外部的，不在 V8 堆上时)。
* **元素存储函数**:
    * `StoreJSTypedArrayElementFromNumeric`:  将一个数字值存储到 TypedArray 的指定索引位置。
    * `StoreJSTypedArrayElementFromPreparedValue`:  存储一个已经准备好的值到 TypedArray。
    * `StoreJSTypedArrayElementFromTagged`:  将一个 JavaScript 值存储到 TypedArray 的指定索引位置，会进行类型转换。
* **`@@toStringTag` 实现**:
    * `TypedArrayPrototypeToStringTag`:  实现 `TypedArray.prototype[Symbol.toStringTag]`，用于指定 `Object.prototype.toString.call(new Uint8Array())` 返回的字符串标签 (例如 "Uint8Array")。

**与 JavaScript 功能的关系及举例:**

这个文件中的 C++ 代码直接实现了 JavaScript 中 TypedArray 相关的 API。  以下是一些 JavaScript 例子以及它们背后可能由 `builtins-typed-array-gen.cc` 中的哪些函数支持：

```javascript
// 创建一个 Uint8Array
const uint8Array = new Uint8Array(10); // 可能调用 TypedArrayConstructor

// 获取 byteLength
console.log(uint8Array.byteLength); // 可能调用 TypedArrayPrototypeByteLength

// 获取 byteOffset
console.log(uint8Array.byteOffset); // 可能调用 TypedArrayPrototypeByteOffset

// 获取 length
console.log(uint8Array.length);   // 可能调用 TypedArrayPrototypeLength

// 设置元素
uint8Array[0] = 255;             // 可能调用 StoreJSTypedArrayElementFromTagged

// 从普通数组创建 TypedArray
const normalArray = [1, 2, 3];
const typedArrayFromNormal = new Uint8Array(normalArray); // 可能调用 TypedArrayConstructor 和 CallCCopyFastNumberJSArrayElementsToTypedArray

// 从另一个 TypedArray 创建 TypedArray
const anotherTypedArray = new Uint8Array(typedArrayFromNormal.buffer, 1, 2); // 可能调用 TypedArrayConstructor 和相关 buffer 处理逻辑

// 获取 TypedArray 的字符串标签
console.log(Object.prototype.toString.call(uint8Array)); // 可能调用 TypedArrayPrototypeToStringTag
```

**代码逻辑推理及假设输入与输出:**

以 `TypedArrayPrototypeByteLength` 为例：

**假设输入:**

* `receiver`: 一个 JSTypedArray 实例，例如一个 `Uint16Array`，其底层 ArrayBuffer 包含 20 个字节。

**代码逻辑推理:**

1. `ThrowIfNotInstanceType`: 检查 `receiver` 是否是 `JS_TYPED_ARRAY_TYPE` 的实例。
2. `LoadJSArrayBufferViewBuffer`: 加载 `receiver` 的底层 `JSArrayBuffer`。
3. `IsDetachedBuffer`: 检查底层 `JSArrayBuffer` 是否已被分离。
4. 如果未分离，`LoadJSArrayBufferViewByteLength` 加载 TypedArray 存储的字节长度。
5. `ChangeUintPtrToTagged`: 将字节长度转换为 V8 标记指针类型以便返回给 JavaScript。

**假设输出:**

* 如果输入的 `receiver` 是一个未分离的 `Uint16Array` 且底层 buffer 为 20 字节，则返回表示数字 20 的 V8 标记指针。
* 如果输入的 `receiver` 不是 TypedArray，则会抛出一个 `TypeError`。
* 如果输入的 `receiver` 的 buffer 已分离，则返回表示数字 0 的 V8 标记指针。

**用户常见的编程错误举例:**

1. **在 TypedArray 的 buffer 分离后尝试访问其属性或元素:**

   ```javascript
   const buffer = new ArrayBuffer(10);
   const uint8Array = new Uint8Array(buffer);
   buffer.detach(); // 分离 buffer
   console.log(uint8Array.byteLength); // 错误：可能抛出 TypeError 或返回不正确的值 (通常为 0)
   uint8Array[0] = 10;              // 错误：抛出 TypeError
   ```
   `builtins-typed-array-gen.cc` 中的 `ThrowIfArrayBufferViewBufferIsDetached` 等函数会检查这种情况并抛出错误。

2. **在构造 TypedArray 时提供无效的参数:**

   ```javascript
   // 错误的长度
   const invalidLengthArray = new Uint8Array(-1); // 错误：通常会抛出 RangeError

   // 错误的偏移量或长度导致越界
   const buffer = new ArrayBuffer(10);
   const uint8Array = new Uint8Array(buffer, 5, 10); // 错误：偏移量 + 长度 超出 buffer 大小，抛出 RangeError
   ```
   `TypedArrayConstructor` 中的逻辑会验证这些参数。

3. **尝试直接构造抽象的 `TypedArray` 对象:**

   ```javascript
   const abstractArray = new TypedArray(10); // 错误：抛出 TypeError
   ```
   `TypedArrayBaseConstructor` 会显式地抛出此错误。

4. **混淆 `length` (元素数量) 和 `byteLength` (字节数):**

   ```javascript
   const int32Array = new Int32Array(5); // 5 个 4 字节的整数
   console.log(int32Array.length);    // 输出 5
   console.log(int32Array.byteLength); // 输出 20 (5 * 4)

   // 错误地认为可以通过 length 设置字节数
   int32Array.length = 10; // 这不会改变 byteLength 或底层 buffer 的大小
   ```
   这个文件中的 `TypedArrayPrototypeLength` 和 `TypedArrayPrototypeByteLength` 实现了这两个不同的属性。

总而言之，`v8/src/builtins/builtins-typed-array-gen.cc` 是 V8 引擎中实现 JavaScript TypedArray 功能的关键组成部分，它包含了处理 TypedArray 对象创建、属性访问和基本操作的底层 C++ 代码。

### 提示词
```
这是目录为v8/src/builtins/builtins-typed-array-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-typed-array-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-typed-array-gen.h"

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/builtins/growable-fixed-array-gen.h"
#include "src/execution/protectors.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/js-array-buffer-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// -----------------------------------------------------------------------------
// ES6 section 22.2 TypedArray Objects

// Sets the embedder fields to 0 for a TypedArray which is under construction.
void TypedArrayBuiltinsAssembler::SetupTypedArrayEmbedderFields(
    TNode<JSTypedArray> holder) {
  InitializeJSAPIObjectWithEmbedderSlotsCppHeapWrapperPtr(holder);
  for (int offset = JSTypedArray::kHeaderSize;
       offset < JSTypedArray::kSizeWithEmbedderFields; offset += kTaggedSize) {
    // TODO(v8:10391, saelo): Handle external pointers in EmbedderDataSlot
    StoreObjectField(holder, offset, SmiConstant(0));
  }
}

// Allocate a new ArrayBuffer and initialize it with empty properties and
// elements.
// TODO(bmeurer,v8:4153): Rename this and maybe fix up the implementation a bit.
TNode<JSArrayBuffer> TypedArrayBuiltinsAssembler::AllocateEmptyOnHeapBuffer(
    TNode<Context> context) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map =
      CAST(LoadContextElement(native_context, Context::ARRAY_BUFFER_MAP_INDEX));
  TNode<FixedArray> empty_fixed_array = EmptyFixedArrayConstant();

  TNode<JSArrayBuffer> buffer = UncheckedCast<JSArrayBuffer>(
      Allocate(JSArrayBuffer::kSizeWithEmbedderFields));
  StoreMapNoWriteBarrier(buffer, map);
  StoreObjectFieldNoWriteBarrier(buffer, JSArray::kPropertiesOrHashOffset,
                                 empty_fixed_array);
  StoreObjectFieldNoWriteBarrier(buffer, JSArray::kElementsOffset,
                                 empty_fixed_array);
  // Setup the ArrayBuffer.
  //  - Set BitField to 0.
  //  - Set IsExternal and IsDetachable bits of BitFieldSlot.
  //  - Set the byte_length field to zero.
  //  - Set backing_store to null/Tagged<Smi>(0).
  //  - Set extension to null.
  //  - Set all embedder fields to Tagged<Smi>(0).
  if (FIELD_SIZE(JSArrayBuffer::kOptionalPaddingOffset) != 0) {
    DCHECK_EQ(4, FIELD_SIZE(JSArrayBuffer::kOptionalPaddingOffset));
    StoreObjectFieldNoWriteBarrier(
        buffer, JSArrayBuffer::kOptionalPaddingOffset, Int32Constant(0));
  }
  int32_t bitfield_value = (1 << JSArrayBuffer::IsExternalBit::kShift) |
                           (1 << JSArrayBuffer::IsDetachableBit::kShift);
  StoreObjectFieldNoWriteBarrier(buffer, JSArrayBuffer::kBitFieldOffset,
                                 Int32Constant(bitfield_value));

  StoreObjectFieldNoWriteBarrier(buffer, JSArrayBuffer::kDetachKeyOffset,
                                 UndefinedConstant());
  StoreBoundedSizeToObject(buffer, JSArrayBuffer::kRawByteLengthOffset,
                           UintPtrConstant(0));
  StoreBoundedSizeToObject(buffer, JSArrayBuffer::kRawMaxByteLengthOffset,
                           UintPtrConstant(0));
  StoreSandboxedPointerToObject(buffer, JSArrayBuffer::kBackingStoreOffset,
                                EmptyBackingStoreBufferConstant());
#ifdef V8_COMPRESS_POINTERS
  // When pointer compression is enabled, the extension slot contains a
  // (lazily-initialized) external pointer handle.
  StoreObjectFieldNoWriteBarrier(buffer, JSArrayBuffer::kExtensionOffset,
                                 ExternalPointerHandleNullConstant());
#else
  StoreObjectFieldNoWriteBarrier(buffer, JSArrayBuffer::kExtensionOffset,
                                 IntPtrConstant(0));
#endif
  InitializeJSAPIObjectWithEmbedderSlotsCppHeapWrapperPtr(buffer);
  for (int offset = JSArrayBuffer::kHeaderSize;
       offset < JSArrayBuffer::kSizeWithEmbedderFields; offset += kTaggedSize) {
    // TODO(v8:10391, saelo): Handle external pointers in EmbedderDataSlot
    StoreObjectFieldNoWriteBarrier(buffer, offset, SmiConstant(0));
  }
  return buffer;
}

TF_BUILTIN(TypedArrayBaseConstructor, TypedArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  ThrowTypeError(context, MessageTemplate::kConstructAbstractClass,
                 "TypedArray");
}

// ES #sec-typedarray-constructors
TF_BUILTIN(TypedArrayConstructor, TypedArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto target = Parameter<JSFunction>(Descriptor::kJSTarget);
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);
  TNode<Object> arg1 = args.GetOptionalArgumentValue(0);
  TNode<Object> arg2 = args.GetOptionalArgumentValue(1);
  TNode<Object> arg3 = args.GetOptionalArgumentValue(2);

  // If NewTarget is undefined, throw a TypeError exception.
  // All the TypedArray constructors have this as the first step:
  // https://tc39.github.io/ecma262/#sec-typedarray-constructors
  Label throwtypeerror(this, Label::kDeferred);
  GotoIf(IsUndefined(new_target), &throwtypeerror);

  TNode<Object> result = CallBuiltin(Builtin::kCreateTypedArray, context,
                                     target, new_target, arg1, arg2, arg3);
  args.PopAndReturn(result);

  BIND(&throwtypeerror);
  {
    TNode<String> name =
        CAST(CallRuntime(Runtime::kGetFunctionName, context, target));
    ThrowTypeError(context, MessageTemplate::kConstructorNotFunction, name);
  }
}

// ES6 #sec-get-%typedarray%.prototype.bytelength
TF_BUILTIN(TypedArrayPrototypeByteLength, TypedArrayBuiltinsAssembler) {
  const char* const kMethodName = "get TypedArray.prototype.byteLength";
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);

  // Check if the {receiver} is actually a JSTypedArray.
  ThrowIfNotInstanceType(context, receiver, JS_TYPED_ARRAY_TYPE, kMethodName);

  TNode<JSTypedArray> receiver_array = CAST(receiver);
  TNode<JSArrayBuffer> receiver_buffer =
      LoadJSArrayBufferViewBuffer(receiver_array);

  Label variable_length(this), normal(this);
  Branch(IsVariableLengthJSArrayBufferView(receiver_array), &variable_length,
         &normal);
  BIND(&variable_length);
  {
    Return(ChangeUintPtrToTagged(LoadVariableLengthJSTypedArrayByteLength(
        context, receiver_array, receiver_buffer)));
  }

  BIND(&normal);
  {
    // Default to zero if the {receiver}s buffer was detached.
    TNode<UintPtrT> byte_length = Select<UintPtrT>(
        IsDetachedBuffer(receiver_buffer),
        [=, this] { return UintPtrConstant(0); },
        [=, this] { return LoadJSArrayBufferViewByteLength(receiver_array); });
    Return(ChangeUintPtrToTagged(byte_length));
  }
}

// ES6 #sec-get-%typedarray%.prototype.byteoffset
TF_BUILTIN(TypedArrayPrototypeByteOffset, TypedArrayBuiltinsAssembler) {
  const char* const kMethodName = "get TypedArray.prototype.byteOffset";
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);

  // Check if the {receiver} is actually a JSTypedArray.
  ThrowIfNotInstanceType(context, receiver, JS_TYPED_ARRAY_TYPE, kMethodName);

  // Default to zero if the {receiver}s buffer was detached / out of bounds.
  Label detached_or_oob(this), not_detached_nor_oob(this);
  IsJSArrayBufferViewDetachedOrOutOfBounds(CAST(receiver), &detached_or_oob,
                                           &not_detached_nor_oob);
  BIND(&detached_or_oob);
  Return(ChangeUintPtrToTagged(UintPtrConstant(0)));

  BIND(&not_detached_nor_oob);
  Return(
      ChangeUintPtrToTagged(LoadJSArrayBufferViewByteOffset(CAST(receiver))));
}

// ES6 #sec-get-%typedarray%.prototype.length
TF_BUILTIN(TypedArrayPrototypeLength, TypedArrayBuiltinsAssembler) {
  const char* const kMethodName = "get TypedArray.prototype.length";
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);

  // Check if the {receiver} is actually a JSTypedArray.
  ThrowIfNotInstanceType(context, receiver, JS_TYPED_ARRAY_TYPE, kMethodName);

  TNode<JSTypedArray> receiver_array = CAST(receiver);
  TVARIABLE(UintPtrT, length);
  Label detached(this), end(this);
  length = LoadJSTypedArrayLengthAndCheckDetached(receiver_array, &detached);
  Return(ChangeUintPtrToTagged(length.value()));
  BIND(&detached);
  Return(ChangeUintPtrToTagged(UintPtrConstant(0)));
}

TNode<BoolT> TypedArrayBuiltinsAssembler::IsUint8ElementsKind(
    TNode<Int32T> kind) {
  return Word32Or(
      Word32Or(Word32Equal(kind, Int32Constant(UINT8_ELEMENTS)),
               Word32Equal(kind, Int32Constant(UINT8_CLAMPED_ELEMENTS))),
      Word32Or(
          Word32Equal(kind, Int32Constant(RAB_GSAB_UINT8_ELEMENTS)),
          Word32Equal(kind, Int32Constant(RAB_GSAB_UINT8_CLAMPED_ELEMENTS))));
}

TNode<BoolT> TypedArrayBuiltinsAssembler::IsBigInt64ElementsKind(
    TNode<Int32T> kind) {
  static_assert(BIGUINT64_ELEMENTS + 1 == BIGINT64_ELEMENTS);
  return Word32Or(
      IsElementsKindInRange(kind, BIGUINT64_ELEMENTS, BIGINT64_ELEMENTS),
      IsElementsKindInRange(kind, RAB_GSAB_BIGUINT64_ELEMENTS,
                            RAB_GSAB_BIGINT64_ELEMENTS));
}

TNode<IntPtrT> TypedArrayBuiltinsAssembler::GetTypedArrayElementSize(
    TNode<Int32T> elements_kind) {
  TVARIABLE(IntPtrT, element_size);

  DispatchTypedArrayByElementsKind(
      elements_kind,
      [&](ElementsKind el_kind, int size, int typed_array_fun_index) {
        element_size = IntPtrConstant(size);
      });

  return element_size.value();
}

TorqueStructTypedArrayElementsInfo
TypedArrayBuiltinsAssembler::GetTypedArrayElementsInfo(
    TNode<JSTypedArray> typed_array) {
  return GetTypedArrayElementsInfo(LoadMap(typed_array));
}

TorqueStructTypedArrayElementsInfo
TypedArrayBuiltinsAssembler::GetTypedArrayElementsInfo(TNode<Map> map) {
  TNode<Int32T> elements_kind = LoadMapElementsKind(map);
  TVARIABLE(UintPtrT, var_size_log2);
  TVARIABLE(Map, var_map);
  ReadOnlyRoots roots(isolate());

  DispatchTypedArrayByElementsKind(
      elements_kind,
      [&](ElementsKind kind, int size, int typed_array_fun_index) {
        DCHECK_GT(size, 0);
        var_size_log2 = UintPtrConstant(ElementsKindToShiftSize(kind));
      });

  return TorqueStructTypedArrayElementsInfo{var_size_log2.value(),
                                            elements_kind};
}

TNode<JSFunction> TypedArrayBuiltinsAssembler::GetDefaultConstructor(
    TNode<Context> context, TNode<JSTypedArray> exemplar) {
  TVARIABLE(IntPtrT, context_slot);
  TNode<Int32T> elements_kind = LoadElementsKind(exemplar);

  DispatchTypedArrayByElementsKind(
      elements_kind,
      [&](ElementsKind el_kind, int size, int typed_array_function_index) {
        context_slot = IntPtrConstant(typed_array_function_index);
      });

  return CAST(
      LoadContextElement(LoadNativeContext(context), context_slot.value()));
}

TNode<JSTypedArray> TypedArrayBuiltinsAssembler::ValidateTypedArray(
    TNode<Context> context, TNode<Object> obj, const char* method_name) {
  // If it is not a typed array, throw
  ThrowIfNotInstanceType(context, obj, JS_TYPED_ARRAY_TYPE, method_name);

  // If the typed array's buffer is detached, throw
  ThrowIfArrayBufferViewBufferIsDetached(context, CAST(obj), method_name);

  // TODO(v8:11111): Throw if the RAB / GSAB is OOB.
  return CAST(obj);
}

TNode<UintPtrT> TypedArrayBuiltinsAssembler::ValidateTypedArrayAndGetLength(
    TNode<Context> context, TNode<Object> obj, const char* method_name) {
  // If it is not a typed array, throw
  ThrowIfNotInstanceType(context, obj, JS_TYPED_ARRAY_TYPE, method_name);

  Label detached_or_oob(this), not_detached_nor_oob(this);
  TNode<UintPtrT> length =
      LoadJSTypedArrayLengthAndCheckDetached(CAST(obj), &detached_or_oob);
  Goto(&not_detached_nor_oob);

  BIND(&detached_or_oob);
  ThrowTypeError(context, MessageTemplate::kDetachedOperation, method_name);

  BIND(&not_detached_nor_oob);
  return length;
}

void TypedArrayBuiltinsAssembler::CallCMemmove(TNode<RawPtrT> dest_ptr,
                                               TNode<RawPtrT> src_ptr,
                                               TNode<UintPtrT> byte_length) {
  TNode<ExternalReference> memmove =
      ExternalConstant(ExternalReference::libc_memmove_function());
  CallCFunction(memmove, MachineType::AnyTagged(),
                std::make_pair(MachineType::Pointer(), dest_ptr),
                std::make_pair(MachineType::Pointer(), src_ptr),
                std::make_pair(MachineType::UintPtr(), byte_length));
}

void TypedArrayBuiltinsAssembler::CallCRelaxedMemmove(
    TNode<RawPtrT> dest_ptr, TNode<RawPtrT> src_ptr,
    TNode<UintPtrT> byte_length) {
  TNode<ExternalReference> memmove =
      ExternalConstant(ExternalReference::relaxed_memmove_function());
  CallCFunction(memmove, MachineType::AnyTagged(),
                std::make_pair(MachineType::Pointer(), dest_ptr),
                std::make_pair(MachineType::Pointer(), src_ptr),
                std::make_pair(MachineType::UintPtr(), byte_length));
}

void TypedArrayBuiltinsAssembler::CallCMemcpy(TNode<RawPtrT> dest_ptr,
                                              TNode<RawPtrT> src_ptr,
                                              TNode<UintPtrT> byte_length) {
  TNode<ExternalReference> memcpy =
      ExternalConstant(ExternalReference::libc_memcpy_function());
  CallCFunction(memcpy, MachineType::AnyTagged(),
                std::make_pair(MachineType::Pointer(), dest_ptr),
                std::make_pair(MachineType::Pointer(), src_ptr),
                std::make_pair(MachineType::UintPtr(), byte_length));
}

void TypedArrayBuiltinsAssembler::CallCRelaxedMemcpy(
    TNode<RawPtrT> dest_ptr, TNode<RawPtrT> src_ptr,
    TNode<UintPtrT> byte_length) {
  TNode<ExternalReference> relaxed_memcpy =
      ExternalConstant(ExternalReference::relaxed_memcpy_function());
  CallCFunction(relaxed_memcpy, MachineType::AnyTagged(),
                std::make_pair(MachineType::Pointer(), dest_ptr),
                std::make_pair(MachineType::Pointer(), src_ptr),
                std::make_pair(MachineType::UintPtr(), byte_length));
}

void TypedArrayBuiltinsAssembler::CallCMemset(TNode<RawPtrT> dest_ptr,
                                              TNode<IntPtrT> value,
                                              TNode<UintPtrT> length) {
  TNode<ExternalReference> memset =
      ExternalConstant(ExternalReference::libc_memset_function());
  CallCFunction(memset, MachineType::AnyTagged(),
                std::make_pair(MachineType::Pointer(), dest_ptr),
                std::make_pair(MachineType::IntPtr(), value),
                std::make_pair(MachineType::UintPtr(), length));
}

void TypedArrayBuiltinsAssembler::
    CallCCopyFastNumberJSArrayElementsToTypedArray(
        TNode<Context> context, TNode<JSArray> source, TNode<JSTypedArray> dest,
        TNode<UintPtrT> source_length, TNode<UintPtrT> offset) {
  CSA_DCHECK(this,
             Word32BinaryNot(IsBigInt64ElementsKind(LoadElementsKind(dest))));
  TNode<ExternalReference> f = ExternalConstant(
      ExternalReference::copy_fast_number_jsarray_elements_to_typed_array());
  CallCFunction(f, MachineType::AnyTagged(),
                std::make_pair(MachineType::AnyTagged(), context),
                std::make_pair(MachineType::AnyTagged(), source),
                std::make_pair(MachineType::AnyTagged(), dest),
                std::make_pair(MachineType::UintPtr(), source_length),
                std::make_pair(MachineType::UintPtr(), offset));
}

void TypedArrayBuiltinsAssembler::CallCCopyTypedArrayElementsToTypedArray(
    TNode<JSTypedArray> source, TNode<JSTypedArray> dest,
    TNode<UintPtrT> source_length, TNode<UintPtrT> offset) {
  TNode<ExternalReference> f = ExternalConstant(
      ExternalReference::copy_typed_array_elements_to_typed_array());
  CallCFunction(f, MachineType::AnyTagged(),
                std::make_pair(MachineType::AnyTagged(), source),
                std::make_pair(MachineType::AnyTagged(), dest),
                std::make_pair(MachineType::UintPtr(), source_length),
                std::make_pair(MachineType::UintPtr(), offset));
}

void TypedArrayBuiltinsAssembler::CallCCopyTypedArrayElementsSlice(
    TNode<JSTypedArray> source, TNode<JSTypedArray> dest, TNode<UintPtrT> start,
    TNode<UintPtrT> end) {
  TNode<ExternalReference> f =
      ExternalConstant(ExternalReference::copy_typed_array_elements_slice());
  CallCFunction(f, MachineType::AnyTagged(),
                std::make_pair(MachineType::AnyTagged(), source),
                std::make_pair(MachineType::AnyTagged(), dest),
                std::make_pair(MachineType::UintPtr(), start),
                std::make_pair(MachineType::UintPtr(), end));
}

void TypedArrayBuiltinsAssembler::DispatchTypedArrayByElementsKind(
    TNode<Word32T> elements_kind, const TypedArraySwitchCase& case_function) {
  Label next(this), if_unknown_type(this, Label::kDeferred);

  int32_t elements_kinds[] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) TYPE##_ELEMENTS,
      TYPED_ARRAYS(TYPED_ARRAY_CASE) RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) Label if_##type##array(this);
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
  RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  Label* elements_kind_labels[] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) &if_##type##array,
      TYPED_ARRAYS(TYPED_ARRAY_CASE) RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };
  static_assert(arraysize(elements_kinds) == arraysize(elements_kind_labels));

  Switch(elements_kind, &if_unknown_type, elements_kinds, elements_kind_labels,
         arraysize(elements_kinds));

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)   \
  BIND(&if_##type##array);                          \
  {                                                 \
    case_function(TYPE##_ELEMENTS, sizeof(ctype),   \
                  Context::TYPE##_ARRAY_FUN_INDEX); \
    Goto(&next);                                    \
  }
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype, NON_RAB_GSAB_TYPE) \
  BIND(&if_##type##array);                                           \
  {                                                                  \
    case_function(TYPE##_ELEMENTS, sizeof(ctype),                    \
                  Context::NON_RAB_GSAB_TYPE##_ARRAY_FUN_INDEX);     \
    Goto(&next);                                                     \
  }
  RAB_GSAB_TYPED_ARRAYS_WITH_NON_RAB_GSAB_ELEMENTS_KIND(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  BIND(&if_unknown_type);
  Unreachable();

  BIND(&next);
}

void TypedArrayBuiltinsAssembler::SetJSTypedArrayOnHeapDataPtr(
    TNode<JSTypedArray> holder, TNode<ByteArray> base, TNode<UintPtrT> offset) {
  offset = UintPtrAdd(
      UintPtrConstant(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag),
      offset);
  if (COMPRESS_POINTERS_BOOL) {
    TNode<IntPtrT> full_base = Signed(BitcastTaggedToWord(base));
    TNode<Int32T> compressed_base = TruncateIntPtrToInt32(full_base);
    // TODO(v8:9706): Add a way to directly use kRootRegister value.
    TNode<IntPtrT> ptr_compr_cage_base =
        IntPtrSub(full_base, Signed(ChangeUint32ToWord(compressed_base)));
    // Add JSTypedArray::ExternalPointerCompensationForOnHeapArray() to offset.
    // See JSTypedArray::AddExternalPointerCompensationForDeserialization().
    DCHECK_EQ(
        isolate()->cage_base(),
        JSTypedArray::ExternalPointerCompensationForOnHeapArray(isolate()));
    offset = Unsigned(IntPtrAdd(offset, ptr_compr_cage_base));
  }

  StoreJSTypedArrayBasePointer(holder, base);
  StoreJSTypedArrayExternalPointerPtr(holder, ReinterpretCast<RawPtrT>(offset));
}

void TypedArrayBuiltinsAssembler::SetJSTypedArrayOffHeapDataPtr(
    TNode<JSTypedArray> holder, TNode<RawPtrT> base, TNode<UintPtrT> offset) {
  StoreObjectFieldNoWriteBarrier(holder, JSTypedArray::kBasePointerOffset,
                                 SmiConstant(0));

  base = RawPtrAdd(base, Signed(offset));
  StoreJSTypedArrayExternalPointerPtr(holder, base);
}

void TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromNumeric(
    TNode<Context> context, TNode<JSTypedArray> typed_array,
    TNode<UintPtrT> index, TNode<Numeric> value, ElementsKind elements_kind) {
  TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(typed_array);
  switch (elements_kind) {
    case UINT8_ELEMENTS:
    case UINT8_CLAMPED_ELEMENTS:
    case INT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
      StoreElement(data_ptr, elements_kind, index, SmiToInt32(CAST(value)));
      break;
    case UINT32_ELEMENTS:
    case INT32_ELEMENTS:
      StoreElement(data_ptr, elements_kind, index,
                   TruncateTaggedToWord32(context, value));
      break;
    case FLOAT16_ELEMENTS:
      StoreElement(data_ptr, elements_kind, index,
                   TruncateFloat64ToFloat16(LoadHeapNumberValue(CAST(value))));
      break;
    case FLOAT32_ELEMENTS:
      StoreElement(data_ptr, elements_kind, index,
                   TruncateFloat64ToFloat32(LoadHeapNumberValue(CAST(value))));
      break;
    case FLOAT64_ELEMENTS:
      StoreElement(data_ptr, elements_kind, index,
                   LoadHeapNumberValue(CAST(value)));
      break;
    case BIGUINT64_ELEMENTS:
    case BIGINT64_ELEMENTS:
      StoreElement(data_ptr, elements_kind, index,
                   UncheckedCast<BigInt>(value));
      break;
    default:
      UNREACHABLE();
  }
}

template <typename TValue>
void TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromPreparedValue(
    TNode<Context> context, TNode<JSTypedArray> typed_array,
    TNode<UintPtrT> index, TNode<TValue> prepared_value,
    ElementsKind elements_kind, Label* if_detached_or_out_of_bounds) {
  static_assert(std::is_same<TValue, Word32T>::value ||
                    std::is_same<TValue, Float16RawBitsT>::value ||
                    std::is_same<TValue, Float32T>::value ||
                    std::is_same<TValue, Float64T>::value ||
                    std::is_same<TValue, BigInt>::value,
                "Only Word32T, Float16T, Float32T, Float64T or BigInt values "
                "are allowed");
  // ToNumber/ToBigInt (or other functions called by the upper level) may
  // execute JavaScript code, which could detach the TypedArray's buffer or make
  // the TypedArray out of bounds.
  TNode<UintPtrT> length = LoadJSTypedArrayLengthAndCheckDetached(
      typed_array, if_detached_or_out_of_bounds);
  GotoIf(UintPtrGreaterThanOrEqual(index, length),
         if_detached_or_out_of_bounds);

  TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(typed_array);
  StoreElement(data_ptr, elements_kind, index, prepared_value);
}

void TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromTagged(
    TNode<Context> context, TNode<JSTypedArray> typed_array,
    TNode<UintPtrT> index, TNode<Object> value, ElementsKind elements_kind,
    Label* if_detached_or_out_of_bounds) {
  switch (elements_kind) {
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case UINT32_ELEMENTS:
    case INT32_ELEMENTS:
    case UINT8_CLAMPED_ELEMENTS: {
      auto prepared_value = PrepareValueForWriteToTypedArray<Word32T>(
          value, elements_kind, context);
      StoreJSTypedArrayElementFromPreparedValue(context, typed_array, index,
                                                prepared_value, elements_kind,
                                                if_detached_or_out_of_bounds);
      break;
    }
    case FLOAT16_ELEMENTS: {
      auto prepared_value = PrepareValueForWriteToTypedArray<Float16RawBitsT>(
          value, elements_kind, context);
      StoreJSTypedArrayElementFromPreparedValue(context, typed_array, index,
                                                prepared_value, elements_kind,
                                                if_detached_or_out_of_bounds);
      break;
    }
    case FLOAT32_ELEMENTS: {
      auto prepared_value = PrepareValueForWriteToTypedArray<Float32T>(
          value, elements_kind, context);
      StoreJSTypedArrayElementFromPreparedValue(context, typed_array, index,
                                                prepared_value, elements_kind,
                                                if_detached_or_out_of_bounds);
      break;
    }
    case FLOAT64_ELEMENTS: {
      auto prepared_value = PrepareValueForWriteToTypedArray<Float64T>(
          value, elements_kind, context);
      StoreJSTypedArrayElementFromPreparedValue(context, typed_array, index,
                                                prepared_value, elements_kind,
                                                if_detached_or_out_of_bounds);
      break;
    }
    case BIGINT64_ELEMENTS:
    case BIGUINT64_ELEMENTS: {
      auto prepared_value = PrepareValueForWriteToTypedArray<BigInt>(
          value, elements_kind, context);
      StoreJSTypedArrayElementFromPreparedValue(context, typed_array, index,
                                                prepared_value, elements_kind,
                                                if_detached_or_out_of_bounds);
      break;
    }
    default:
      UNREACHABLE();
  }
}

// ES #sec-get-%typedarray%.prototype-@@tostringtag
TF_BUILTIN(TypedArrayPrototypeToStringTag, TypedArrayBuiltinsAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Label if_receiverisheapobject(this), return_undefined(this);
  Branch(TaggedIsSmi(receiver), &return_undefined, &if_receiverisheapobject);

  // Dispatch on the elements kind, offset by
  // FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND.
  static_assert(LAST_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1 ==
                FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
  size_t const kTypedElementsKindCount =
      LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND -
      FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1;
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  Label return_##type##array(this);               \
  BIND(&return_##type##array);                    \
  Return(StringConstant(#Type "Array"));
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  // clang-format off
  Label* elements_kind_labels[kTypedElementsKindCount] = {
  // The TYPED_ARRAYS macro is invoked twice because while the RAB/GSAB-backed
  // TAs have distinct ElementsKinds internally, they have the same "class"
  // name for toString output.
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) &return_##type##array,
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };

  int32_t elements_kinds[kTypedElementsKindCount] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  TYPE##_ELEMENTS - FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  // The use of FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND below is not a typo! This
  // computes an index into elements_kind_labels, and all TypedArray
  // ElementsKind values are contiguous.
#define RAB_GSAB_TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  TYPE##_ELEMENTS - FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
  RAB_GSAB_TYPED_ARRAYS(RAB_GSAB_TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
#undef RAB_GSAB_TYPED_ARRAY_CASE
  };
  // clang-format on

  // We offset the dispatch by FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND, so that
  // this can be turned into a non-sparse table switch for ideal performance.
  BIND(&if_receiverisheapobject);
  TNode<HeapObject> receiver_heap_object = CAST(receiver);
  TNode<Int32T> elements_kind =
      Int32Sub(LoadElementsKind(receiver_heap_object),
               Int32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND));
  Switch(elements_kind, &return_undefined, elements_kinds, elements_kind_labels,
         kTypedElementsKindCount);

  BIND(&return_undefined);
  Return(UndefinedConstant());
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```