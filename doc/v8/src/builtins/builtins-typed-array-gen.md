Response: Let's break down the thought process for analyzing this C++ file and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and, crucially, how it relates to JavaScript, with illustrative JavaScript examples.

2. **Initial Scan for Keywords and Structure:**  Quickly read through the code, looking for recognizable terms. I see "TypedArray," "ArrayBuffer,"  "builtins," "ES6," "prototype," and various data types like `Int32T`, `UintPtrT`, `Float64T`, etc. The `#include` statements at the beginning hint at dependencies and the overall scope. The `namespace v8::internal` strongly suggests this is part of the V8 JavaScript engine.

3. **Identify Core Components:**  The file name `builtins-typed-array-gen.cc` is a huge clue. It deals with the built-in functions for Typed Arrays in JavaScript. The code within confirms this. I see functions related to:
    * Construction of Typed Arrays (`TypedArrayConstructor`, `TypedArrayBaseConstructor`).
    * Getting properties like `byteLength`, `byteOffset`, `length`.
    * Internal operations like allocation (`AllocateEmptyOnHeapBuffer`), data manipulation (`CallCMemmove`, `CallCMemcpy`, `CallCMemset`), and element access (`StoreJSTypedArrayElementFromNumeric`, `StoreJSTypedArrayElementFromTagged`).
    * Type checking (`IsUint8ElementsKind`, `IsBigInt64ElementsKind`).
    * Metadata retrieval (`GetTypedArrayElementSize`, `GetTypedArrayElementsInfo`).
    * Validation (`ValidateTypedArray`, `ValidateTypedArrayAndGetLength`).
    * The `@@toStringTag` symbol.

4. **Infer JavaScript Relevance:**  Because the file deals with "TypedArray" and their properties and methods, the connection to JavaScript's `TypedArray` objects is direct and obvious. The "ES6" references reinforce this, as Typed Arrays were introduced in ECMAScript 2015 (ES6). The built-in function names like `TypedArrayPrototypeByteLength` directly map to JavaScript prototype properties.

5. **Group Functionality:** Organize the identified components into logical categories. This makes the summary clearer. Good categories would be:
    * **Core Functionality:**  Basic operations like construction and allocation.
    * **Property Getters:**  Methods for accessing `byteLength`, `byteOffset`, `length`.
    * **Internal Helpers:** Functions used internally for data manipulation, type checking, and metadata.
    * **Validation:**  Functions that ensure the validity of TypedArray operations.
    * **`@@toStringTag`:**  A special symbol.

6. **Explain Internal Mechanisms (without being too technical for the request):** Briefly touch upon the internal implementation details where relevant to understanding the JavaScript connection. For example, mention that it deals with memory management (allocation, copying), raw pointers, and different element types. Highlight that these are *internal* operations that JavaScript developers don't directly manipulate.

7. **Craft the Summary:** Write a concise summary based on the grouped functionality. Use clear and simple language. Emphasize the connection to JavaScript.

8. **Develop JavaScript Examples:** This is the crucial part that bridges the C++ code to the JavaScript world. For each key functionality area identified in the C++ code, think about how a JavaScript developer would interact with that functionality.

    * **Construction:** Show different ways to create Typed Arrays (with length, with an existing buffer, with an array of values).
    * **Properties:** Demonstrate accessing `byteLength`, `byteOffset`, and `length`. Crucially, show how detaching the buffer affects these properties.
    * **Internal Helpers (indirectly):**  While you can't directly call `CallCMemmove` from JavaScript, the *effects* of such functions are seen when you manipulate Typed Array data (e.g., `set`, slicing). Give an example of `set`.
    * **Validation:** Show how JavaScript throws `TypeError` when you try to access properties of a detached Typed Array. This demonstrates the C++ validation functions in action.
    * **`@@toStringTag`:** Demonstrate how to access the `@@toStringTag` symbol and what values it returns for different Typed Array types.

9. **Refine and Iterate:** Review the summary and examples. Are they accurate? Are they easy to understand?  Do the examples clearly illustrate the connection between the C++ code and JavaScript?  For instance, initially, I might just say "deals with memory manipulation," but it's better to be slightly more specific and mention allocation, copying, etc. Also, ensuring the JavaScript examples are correct and runnable is important.

10. **Consider Edge Cases/Key Details:**  Think about important details revealed in the C++ code. The handling of detached buffers is a significant aspect. The different element types (`Uint8Array`, `Int32Array`, `Float64Array`, etc.) are also key. Make sure the summary and examples touch upon these.

By following these steps, systematically analyzing the C++ code, and constantly relating it back to the JavaScript perspective, I can arrive at a comprehensive and accurate summary with helpful JavaScript examples.
这个C++源代码文件 `builtins-typed-array-gen.cc` 是 V8 JavaScript 引擎中用于实现 **ECMAScript 2015 (ES6) 规范中定义的 `TypedArray` 对象** 的内置函数（builtins）的生成代码。  它使用了一种名为 CodeStubAssembler (CSA) 的 V8 内部 DSL (Domain Specific Language) 来生成高效的机器代码。

**主要功能归纳:**

1. **实现 `TypedArray` 构造函数和原型方法:**  文件包含了实现各种 `TypedArray` 构造函数（如 `Int8Array`, `Uint32Array` 等）以及 `TypedArray.prototype` 上的各种属性和方法的逻辑。 例如：
    * **构造函数 (`TypedArrayConstructor`):**  处理创建新的 `TypedArray` 实例，根据传入的参数（长度、ArrayBuffer、偏移量等）进行初始化。
    * **属性访问器 (`TypedArrayPrototypeByteLength`, `TypedArrayPrototypeByteOffset`, `TypedArrayPrototypeLength`):** 实现 `byteLength`, `byteOffset`, `length` 等属性的 getter 方法。
    * **内部工具函数:** 提供各种辅助函数来处理 `TypedArray` 的内部操作，例如：
        * **内存分配和初始化 (`AllocateEmptyOnHeapBuffer`, `SetupTypedArrayEmbedderFields`):**  负责分配 `ArrayBuffer` 和 `TypedArray` 对象的内存，并进行初始化。
        * **类型检查 (`IsUint8ElementsKind`, `IsBigInt64ElementsKind`):**  判断 `TypedArray` 的元素类型。
        * **元素大小获取 (`GetTypedArrayElementSize`):**  获取 `TypedArray` 元素的字节大小。
        * **数据指针操作 (`SetJSTypedArrayOnHeapDataPtr`, `SetJSTypedArrayOffHeapDataPtr`, `LoadJSTypedArrayDataPtr`):**  管理 `TypedArray` 内部指向实际数据的指针。
        * **内存拷贝和设置 (`CallCMemmove`, `CallCMemcpy`, `CallCMemset`):** 调用 C 库函数进行高效的内存操作。
        * **元素存储 (`StoreJSTypedArrayElementFromNumeric`, `StoreJSTypedArrayElementFromTagged`):**  将数值或 JavaScript 值存储到 `TypedArray` 的指定位置。
        * **`@@toStringTag` 符号 (`TypedArrayPrototypeToStringTag`):**  定义 `TypedArray` 实例的 `@@toStringTag` 符号，用于 `Object.prototype.toString.call()` 方法返回正确的类型字符串。
        * **校验 (`ValidateTypedArray`, `ValidateTypedArrayAndGetLength`):**  在执行操作前验证 `TypedArray` 的状态，例如是否已分离（detached）。

2. **与 JavaScript 功能的关系及示例:**

   该文件直接实现了 JavaScript 中 `TypedArray` 的核心功能。  当你在 JavaScript 中使用 `TypedArray` 对象时，V8 引擎会调用这里定义的内置函数来执行相应的操作。

   **JavaScript 示例:**

   ```javascript
   // 创建不同类型的 TypedArray
   const uint8 = new Uint8Array(10);
   const int16 = new Int16Array(5);
   const float32 = new Float32Array(new ArrayBuffer(16)); // 使用已有的 ArrayBuffer

   // 设置和获取元素
   uint8[0] = 255;
   console.log(uint8[0]); // 输出 255

   int16[0] = -1000;
   console.log(int16[0]); // 输出 -1000

   float32[0] = 3.14;
   console.log(float32[0]); // 输出 3.14

   // 访问属性
   console.log(uint8.byteLength);   // 输出 10 (10 * 1 字节)
   console.log(int16.byteLength);   // 输出 10 (5 * 2 字节)
   console.log(float32.byteLength); // 输出 16

   console.log(uint8.byteOffset);   // 输出 0
   console.log(int16.byteOffset);   // 输出 0
   console.log(float32.byteOffset); // 输出 0

   console.log(uint8.length);       // 输出 10
   console.log(int16.length);       // 输出 5
   console.log(float32.length);     // 输出 4 (16 字节 / 4 字节/float)

   // 尝试在 detached 的 ArrayBuffer 上操作会抛出 TypeError
   const buffer = new ArrayBuffer(8);
   const view = new Int32Array(buffer);
   buffer.detach();
   try {
     console.log(view.byteLength); // 尝试访问 detached 缓冲区的属性
   } catch (e) {
     console.error(e); // 输出 TypeError: Cannot perform操作 on detached ArrayBuffer
   }

   // 使用 @@toStringTag
   console.log(Object.prototype.toString.call(uint8));   // 输出 "[object Uint8Array]"
   console.log(Object.prototype.toString.call(int16));   // 输出 "[object Int16Array]"
   console.log(Object.prototype.toString.call(float32)); // 输出 "[object Float32Array]"
   ```

   在上面的 JavaScript 示例中，当我们创建 `Uint8Array`，访问其 `byteLength` 属性，或者设置元素值时，V8 引擎内部就会调用 `builtins-typed-array-gen.cc` 文件中相应的 C++ 函数来实现这些功能。  例如：

   * `new Uint8Array(10)` 会最终调用到 `TypedArrayConstructor`，并根据传入的参数分配内存并初始化 `Uint8Array` 对象。
   * 访问 `uint8.byteLength` 会调用到 `TypedArrayPrototypeByteLength` 函数。
   * 设置 `uint8[0] = 255` 会涉及到 `StoreJSTypedArrayElementFromNumeric` 或 `StoreJSTypedArrayElementFromTagged` 等函数。
   * 当 `ArrayBuffer` 被 `detach()` 后，尝试访问 `TypedArray` 的属性时抛出的 `TypeError`，就是由 `ValidateTypedArray` 等验证函数在 C++ 层实现的。
   * `Object.prototype.toString.call(uint8)` 返回 `"[object Uint8Array]"`，这个字符串 `"Uint8Array"` 是在 `TypedArrayPrototypeToStringTag` 函数中定义的。

总而言之， `builtins-typed-array-gen.cc` 是 V8 引擎中至关重要的一个文件，它直接支撑了 JavaScript 中 `TypedArray` 对象的实现，使得 JavaScript 能够高效地处理二进制数据。

### 提示词
```
这是目录为v8/src/builtins/builtins-typed-array-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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