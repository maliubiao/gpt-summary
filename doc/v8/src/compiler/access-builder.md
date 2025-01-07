Response: Let's break down the thought process to analyze the `access-builder.cc` file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and its relation to JavaScript, including a JavaScript example.

2. **Initial Scan for Keywords:**  Look for recurring terms and patterns. Immediately, `FieldAccess` and `ElementAccess` stand out. The names of the static methods like `ForJSObjectPropertiesOrHash`, `ForJSArrayLength`, etc., clearly indicate they are related to JavaScript objects.

3. **Infer the Core Functionality:** The presence of `FieldAccess` and `ElementAccess`, combined with the method names referencing JavaScript objects and their properties (like `length`, `prototype`, `context`), suggests this file is about *describing how to access data within the internal representation of JavaScript objects*. It's defining the layout and access paths.

4. **Focus on `FieldAccess` and `ElementAccess`:** Examine the structure of these types. They contain information like:
    * `kTaggedBase`:  Indicates if the base address is tagged (points to a V8 object) or untagged (raw memory address).
    * `offset`: The byte offset within the object where the data is located.
    * `MaybeHandle<Name>()`:  Potentially the name of the field (though often empty).
    * `OptionalMapRef()`: Related to the object's type information (Map).
    * `Type`: The data type of the field (e.g., `Type::Any()`, `Type::String()`, `TypeCache::Get()->kInt32`).
    * `MachineType`: The underlying machine representation of the data (e.g., `MachineType::AnyTagged()`, `MachineType::Int32()`).
    * `WriteBarrierKind`: Information about how writes to this field should be handled by the garbage collector.
    * `name`: A descriptive string.

5. **Connect to Compiler Context:** The file is located in `v8/src/compiler`. This confirms the initial inference that it's part of the V8 compiler. Compilers need to know the exact memory layout of objects to generate efficient code for accessing their properties.

6. **Identify the Purpose of `AccessBuilder`:** The class name itself is a strong clue. It "builds" or provides "access" information. The static methods act as factory functions, creating `FieldAccess` and `ElementAccess` structures for specific JavaScript object properties.

7. **Establish the Link to JavaScript:** The method names and the fields they describe directly correspond to JavaScript concepts:
    * `JSObject.properties`
    * `JSArray.length`
    * `JSFunction.prototype`
    * `JSGeneratorObject.context`
    * Array elements
    * String characters

8. **Formulate the Functional Summary:** Based on the above observations, we can summarize the file's purpose as providing a central place to define and retrieve metadata about accessing fields and elements within V8's internal representation of JavaScript objects. This metadata is crucial for the compiler to generate efficient machine code.

9. **Develop the JavaScript Examples:**  The goal is to illustrate how the internal accesses defined in the C++ code relate to observable JavaScript behavior. Focus on simple, direct mappings:
    * Accessing a property of an object (`obj.prop`). Relate this to `ForJSObjectPropertiesOrHash` or `ForJSObjectInObjectProperty`.
    * Accessing the length of an array (`arr.length`). Relate this to `ForJSArrayLength`.
    * Accessing an element of an array (`arr[0]`). Relate this to `ForFixedArrayElement`.
    * Accessing the prototype of an object (`obj.__proto__`). Relate this to `ForJSObjectPropertiesOrHash` (prototype chain lookup involves property access).
    * Accessing the context of a function. Relate this to `ForJSFunctionContext`.

10. **Explain the Connection:** Clearly articulate how the C++ code facilitates JavaScript execution: The compiler uses the information from `access-builder.cc` to understand how to read and write data when a JavaScript program accesses object properties or elements. This enables optimization and efficient code generation.

11. **Refine and Structure:** Organize the information logically. Start with the core function, then explain the details of `FieldAccess` and `ElementAccess`, provide JavaScript examples, and finally summarize the relationship. Use clear and concise language.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe it's about memory allocation. *Correction:*  While related to memory layout, the focus is on *accessing* existing memory, not allocating it.
* **Overly technical explanation:**  Avoid jargon where possible. Explain concepts like "tagged pointers" simply or avoid them if not strictly necessary for the high-level summary.
* **Insufficient JavaScript examples:** Ensure the examples are diverse enough to cover different access patterns (properties, elements, built-in properties).
* **Unclear connection:** Explicitly state how the C++ code aids JavaScript execution. Don't just list the functionalities.

By following this thought process, combining keyword analysis, structural understanding, and connecting the C++ code to observable JavaScript behavior, we arrive at a comprehensive and accurate summary.
这个C++源代码文件 `access-builder.cc` 的主要功能是**为V8 JavaScript引擎的编译器提供构建访问JavaScript对象内部属性和元素的元数据的方法。**

简单来说，它定义了一系列静态方法，这些方法返回描述如何访问特定JavaScript对象属性或元素的结构体 (`FieldAccess` 或 `ElementAccess`)。 这些结构体包含了编译器进行高效代码生成所需的关键信息，例如：

* **存储基址类型 (`kTaggedBase`, `kUntaggedBase`)**:  指示访问的起始地址是带标签的V8对象指针还是原始内存地址。
* **偏移量 (`offset`)**: 相对于基址，目标属性或元素在内存中的偏移量。
* **类型信息 (`Type`)**: 属性或元素的数据类型 (例如，数字，字符串，对象)。
* **机器类型 (`MachineType`)**: 底层机器表示的数据类型 (例如，32位整数，64位浮点数，指针)。
* **写屏障类型 (`WriteBarrierKind`)**:  垃圾回收器需要的关于如何处理对该属性或元素写入的指示。
* **名称 (`name`)**: 用于调试和文档的属性或元素的名称。

**与 JavaScript 功能的关系：**

`access-builder.cc` 文件直接关系到 V8 如何在底层实现和优化 JavaScript 代码的执行。 当 JavaScript 代码尝试访问对象的属性或数组的元素时，V8 的编译器会使用 `AccessBuilder` 提供的信息来生成高效的机器码，以便直接读取或写入内存中的相应位置。

**JavaScript 举例说明：**

假设我们有以下 JavaScript 代码：

```javascript
const obj = { x: 10, y: "hello" };
const arr = [1, 2, 3];

console.log(obj.x); // 访问对象 obj 的属性 x
console.log(arr[0]); // 访问数组 arr 的索引为 0 的元素
console.log(arr.length); // 访问数组 arr 的 length 属性
```

在 V8 的编译过程中，当遇到 `obj.x` 时，编译器可能会调用 `AccessBuilder::ForJSObjectPropertiesOrHash()` (如果 `x` 是一个常规属性) 或者 `AccessBuilder::ForJSObjectInObjectProperty()` (如果 `x` 是一个内联属性) 来获取访问 `x` 所需的 `FieldAccess` 信息。这个信息会告诉编译器：

* `x` 存储在 `obj` 对象内部的哪个偏移量。
* `x` 的数据类型可能是数字 (`MachineType::Int32()` 或 `MachineType::Float64()`)。
* 对 `x` 的写入可能需要写屏障 (`kFullWriteBarrier`)。

同样地，当遇到 `arr[0]` 时，编译器可能会调用 `AccessBuilder::ForFixedArrayElement()` 来获取访问数组元素的 `ElementAccess` 信息，其中包括元素相对于数组数据起始位置的偏移量和元素的类型。

当遇到 `arr.length` 时，编译器会调用 `AccessBuilder::ForJSArrayLength()` 来获取 `length` 属性的 `FieldAccess` 信息。

**更具体的 JavaScript 示例和对应的 `AccessBuilder` 方法：**

* **访问对象属性:**
  ```javascript
  const myObject = { name: "V8" };
  console.log(myObject.name);
  ```
  对应 `access-builder.cc` 中的方法可能包括：
    * `AccessBuilder::ForJSObjectPropertiesOrHash()` (用于访问属性存储的哈希表或属性数组)
    * `AccessBuilder::ForJSObjectInObjectProperty()` (用于访问直接存储在对象自身内存中的内联属性)

* **访问数组长度:**
  ```javascript
  const myArray = [1, 2, 3];
  console.log(myArray.length);
  ```
  对应 `access-builder.cc` 中的方法：
    * `AccessBuilder::ForJSArrayLength()`

* **访问数组元素:**
  ```javascript
  const myArray = [100, 200];
  console.log(myArray[1]);
  ```
  对应 `access-builder.cc` 中的方法：
    * `AccessBuilder::ForFixedArrayElement()` (假设是密集数组)
    * 或者根据数组的元素类型，可能是 `AccessBuilder::ForFixedDoubleArrayElement()` 等。

* **访问函数的原型:**
  ```javascript
  function MyClass() {}
  console.log(MyClass.prototype);
  ```
  对应 `access-builder.cc` 中的方法：
    * `AccessBuilder::ForJSFunctionPrototypeOrInitialMap()`

* **访问字符串的长度:**
  ```javascript
  const myString = "hello";
  console.log(myString.length);
  ```
  对应 `access-builder.cc` 中的方法：
    * `AccessBuilder::ForStringLength()`

**总结：**

`access-builder.cc` 是 V8 编译器中一个关键的组件，它通过提供结构化的元数据来指导编译器如何安全有效地访问 JavaScript 对象在内存中的表示。 它将高级的 JavaScript 属性和元素访问操作映射到低级的内存访问细节，是 V8 实现高性能 JavaScript 执行的基础之一。

Prompt: 
```
这是目录为v8/src/compiler/access-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/access-builder.h"

#include "src/compiler/type-cache.h"
#include "src/handles/handles-inl.h"
#include "src/objects/arguments.h"
#include "src/objects/contexts.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-collection.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/source-text-module.h"
#include "src/objects/tagged-field.h"

namespace v8 {
namespace internal {
namespace compiler {

// static
FieldAccess AccessBuilder::ForExternalIntPtr() {
  FieldAccess access = {kUntaggedBase,       0,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::Any(),         MachineType::IntPtr(),
                        kNoWriteBarrier,     "ExternalIntPtr"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMap(WriteBarrierKind write_barrier) {
  FieldAccess access = {kTaggedBase,           HeapObject::kMapOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::MapInHeader(),
                        write_barrier,         "Map"};
  return access;
}

// static
FieldAccess AccessBuilder::ForHeapNumberValue() {
  FieldAccess access = {kTaggedBase,
                        offsetof(HeapNumber, value_),
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kFloat64,
                        MachineType::Float64(),
                        kNoWriteBarrier,
                        "HeapNumberValue"};
  return access;
}

// static
FieldAccess AccessBuilder::ForHeapNumberOrOddballOrHoleValue() {
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    Hole::kRawNumericValueOffset);
  return ForHeapNumberValue();
}

// static
FieldAccess AccessBuilder::ForBigIntBitfield() {
  FieldAccess access = {kTaggedBase,
                        offsetof(BigInt, bitfield_),
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kInt32,
                        MachineType::Uint32(),
                        kNoWriteBarrier,
                        "BigIntBitfield"};
  return access;
}

#ifdef BIGINT_NEEDS_PADDING
// static
FieldAccess AccessBuilder::ForBigIntOptionalPadding() {
  static_assert(arraysize(BigInt::padding_) == sizeof(uint32_t));
  FieldAccess access = {
      kTaggedBase,      offsetof(BigInt, padding_), MaybeHandle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kInt32,   MachineType::Uint32(),
      kNoWriteBarrier,  "BigIntOptionalPadding"};
  return access;
}
#endif

// static
FieldAccess AccessBuilder::ForBigIntLeastSignificantDigit64() {
  DCHECK_EQ(BigInt::SizeFor(1) - BigInt::SizeFor(0), 8);
  FieldAccess access = {
      kTaggedBase,      OFFSET_OF_DATA_START(BigInt),   MaybeHandle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kBigUint64,   MachineType::Uint64(),
      kNoWriteBarrier,  "BigIntLeastSignificantDigit64"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSObjectPropertiesOrHash() {
  FieldAccess access = {kTaggedBase,         JSObject::kPropertiesOrHashOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::Any(),         MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSObjectPropertiesOrHash"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer() {
  FieldAccess access = {
      kTaggedBase,          JSObject::kPropertiesOrHashOffset,
      MaybeHandle<Name>(),  OptionalMapRef(),
      Type::Any(),          MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSObjectPropertiesOrHashKnownPointer"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSObjectElements() {
  FieldAccess access = {kTaggedBase,          JSObject::kElementsOffset,
                        MaybeHandle<Name>(),  OptionalMapRef(),
                        Type::Internal(),     MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "JSObjectElements"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSObjectInObjectProperty(
    MapRef map, int index, MachineType machine_type) {
  int const offset = map.GetInObjectPropertyOffset(index);
  FieldAccess access = {kTaggedBase,         offset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), machine_type,
                        kFullWriteBarrier,   "JSObjectInObjectProperty"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSObjectOffset(
    int offset, WriteBarrierKind write_barrier_kind) {
  FieldAccess access = {kTaggedBase,         offset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        write_barrier_kind,  "JSObjectOffset"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSCollectionTable() {
  FieldAccess access = {kTaggedBase,           JSCollection::kTableOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "JSCollectionTable"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSCollectionIteratorTable() {
  FieldAccess access = {
      kTaggedBase,           JSCollectionIterator::kTableOffset,
      MaybeHandle<Name>(),   OptionalMapRef(),
      Type::OtherInternal(), MachineType::TaggedPointer(),
      kPointerWriteBarrier,  "JSCollectionIteratorTable"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSCollectionIteratorIndex() {
  FieldAccess access = {kTaggedBase,
                        JSCollectionIterator::kIndexOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kFixedArrayLengthType,
                        MachineType::TaggedSigned(),
                        kNoWriteBarrier,
                        "JSCollectionIteratorIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSExternalObjectValue() {
  FieldAccess access = {
      kTaggedBase,
      JSExternalObject::kValueOffset,
      MaybeHandle<Name>(),
      OptionalMapRef(),
      Type::ExternalPointer(),
      MachineType::Pointer(),
      kNoWriteBarrier,
      "JSExternalObjectValue",
      ConstFieldInfo::None(),
      false,
      kExternalObjectValueTag,
  };
  return access;
}

#ifdef V8_ENABLE_SANDBOX
// static
FieldAccess AccessBuilder::ForJSExternalObjectPointerHandle() {
  FieldAccess access = {
      kTaggedBase,      JSExternalObject::kValueOffset, MaybeHandle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kUint32,      MachineType::Uint32(),
      kNoWriteBarrier,  "JSExternalObjectPointerHandle"};
  return access;
}
#endif

// static
FieldAccess AccessBuilder::ForJSFunctionPrototypeOrInitialMap() {
  FieldAccess access = {
      kTaggedBase,          JSFunction::kPrototypeOrInitialMapOffset,
      MaybeHandle<Name>(),  OptionalMapRef(),
      Type::Any(),          MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSFunctionPrototypeOrInitialMap"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSFunctionContext() {
  FieldAccess access = {kTaggedBase,          JSFunction::kContextOffset,
                        MaybeHandle<Name>(),  OptionalMapRef(),
                        Type::Internal(),     MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "JSFunctionContext"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSFunctionSharedFunctionInfo() {
  FieldAccess access = {
      kTaggedBase,           JSFunction::kSharedFunctionInfoOffset,
      Handle<Name>(),        OptionalMapRef(),
      Type::OtherInternal(), MachineType::TaggedPointer(),
      kPointerWriteBarrier,  "JSFunctionSharedFunctionInfo"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSFunctionFeedbackCell() {
  FieldAccess access = {kTaggedBase,          JSFunction::kFeedbackCellOffset,
                        Handle<Name>(),       OptionalMapRef(),
                        Type::Internal(),     MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "JSFunctionFeedbackCell"};
  return access;
}

#ifdef V8_ENABLE_LEAPTIERING
// static
FieldAccess AccessBuilder::ForJSFunctionDispatchHandleNoWriteBarrier() {
  // We currently don't require write barriers when writing dispatch handles of
  // JSFunctions because they are loaded from the function's FeedbackCell and
  // so must already be reachable. If this ever changes, we'll need to
  // implement write barrier support for dispatch handles in generated code.
  FieldAccess access = {
      kTaggedBase,      JSFunction::kDispatchHandleOffset, Handle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kInt32,          MachineType::Int32(),
      kNoWriteBarrier,  "JSFunctionDispatchHandle"};
  return access;
}
#else
#ifdef V8_ENABLE_SANDBOX
// static
FieldAccess AccessBuilder::ForJSFunctionCode() {
  FieldAccess access = {kTaggedBase,
                        JSFunction::kCodeOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        Type::OtherInternal(),
                        MachineType::IndirectPointer(),
                        kIndirectPointerWriteBarrier,
                        "JSFunctionCode"};
  access.indirect_pointer_tag = kCodeIndirectPointerTag;
  return access;
}
#else
// static
FieldAccess AccessBuilder::ForJSFunctionCode() {
  FieldAccess access = {kTaggedBase,           JSFunction::kCodeOffset,
                        Handle<Name>(),        OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "JSFunctionCode"};
  return access;
}
#endif  // V8_ENABLE_SANDBOX
#endif  // V8_ENABLE_LEAPTIERING

// static
FieldAccess AccessBuilder::ForJSBoundFunctionBoundTargetFunction() {
  FieldAccess access = {
      kTaggedBase,          JSBoundFunction::kBoundTargetFunctionOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::Callable(),     MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSBoundFunctionBoundTargetFunction"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSBoundFunctionBoundThis() {
  FieldAccess access = {kTaggedBase,         JSBoundFunction::kBoundThisOffset,
                        Handle<Name>(),      OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSBoundFunctionBoundThis"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSBoundFunctionBoundArguments() {
  FieldAccess access = {
      kTaggedBase,          JSBoundFunction::kBoundArgumentsOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::Internal(),     MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSBoundFunctionBoundArguments"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectContext() {
  FieldAccess access = {kTaggedBase,          JSGeneratorObject::kContextOffset,
                        Handle<Name>(),       OptionalMapRef(),
                        Type::Internal(),     MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "JSGeneratorObjectContext"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectFunction() {
  FieldAccess access = {kTaggedBase,
                        JSGeneratorObject::kFunctionOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        Type::CallableFunction(),
                        MachineType::TaggedPointer(),
                        kPointerWriteBarrier,
                        "JSGeneratorObjectFunction"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectReceiver() {
  FieldAccess access = {
      kTaggedBase,          JSGeneratorObject::kReceiverOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::Internal(),     MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSGeneratorObjectReceiver"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectContinuation() {
  FieldAccess access = {
      kTaggedBase,         JSGeneratorObject::kContinuationOffset,
      Handle<Name>(),      OptionalMapRef(),
      Type::SignedSmall(), MachineType::TaggedSigned(),
      kNoWriteBarrier,     "JSGeneratorObjectContinuation"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectInputOrDebugPos() {
  FieldAccess access = {
      kTaggedBase,         JSGeneratorObject::kInputOrDebugPosOffset,
      Handle<Name>(),      OptionalMapRef(),
      Type::NonInternal(), MachineType::AnyTagged(),
      kFullWriteBarrier,   "JSGeneratorObjectInputOrDebugPos"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectParametersAndRegisters() {
  FieldAccess access = {
      kTaggedBase,          JSGeneratorObject::kParametersAndRegistersOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::Internal(),     MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSGeneratorObjectParametersAndRegisters"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSGeneratorObjectResumeMode() {
  FieldAccess access = {
      kTaggedBase,         JSGeneratorObject::kResumeModeOffset,
      Handle<Name>(),      OptionalMapRef(),
      Type::SignedSmall(), MachineType::TaggedSigned(),
      kNoWriteBarrier,     "JSGeneratorObjectResumeMode"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSAsyncFunctionObjectPromise() {
  FieldAccess access = {
      kTaggedBase,          JSAsyncFunctionObject::kPromiseOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::OtherObject(),  MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSAsyncFunctionObjectPromise"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSAsyncGeneratorObjectQueue() {
  FieldAccess access = {
      kTaggedBase,         JSAsyncGeneratorObject::kQueueOffset,
      Handle<Name>(),      OptionalMapRef(),
      Type::NonInternal(), MachineType::AnyTagged(),
      kFullWriteBarrier,   "JSAsyncGeneratorObjectQueue"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSAsyncGeneratorObjectIsAwaiting() {
  FieldAccess access = {
      kTaggedBase,         JSAsyncGeneratorObject::kIsAwaitingOffset,
      Handle<Name>(),      OptionalMapRef(),
      Type::SignedSmall(), MachineType::TaggedSigned(),
      kNoWriteBarrier,     "JSAsyncGeneratorObjectIsAwaiting"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayLength(ElementsKind elements_kind) {
  TypeCache const* type_cache = TypeCache::Get();
  FieldAccess access = {kTaggedBase,
                        JSArray::kLengthOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        type_cache->kJSArrayLengthType,
                        MachineType::AnyTagged(),
                        kFullWriteBarrier,
                        "JSArrayLength"};
  if (IsDoubleElementsKind(elements_kind)) {
    access.type = type_cache->kFixedDoubleArrayLengthType;
    access.machine_type = MachineType::TaggedSigned();
    access.write_barrier_kind = kNoWriteBarrier;
  } else if (IsFastElementsKind(elements_kind)) {
    access.type = type_cache->kFixedArrayLengthType;
    access.machine_type = MachineType::TaggedSigned();
    access.write_barrier_kind = kNoWriteBarrier;
  }
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayBufferBitField() {
  FieldAccess access = {
      kTaggedBase,      JSArrayBuffer::kBitFieldOffset, MaybeHandle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kUint8,       MachineType::Uint32(),
      kNoWriteBarrier,  "JSArrayBufferBitField"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayBufferByteLength() {
  FieldAccess access = {kTaggedBase,
                        JSArrayBuffer::kRawByteLengthOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kJSArrayBufferByteLengthType,
                        MachineType::UintPtr(),
                        kNoWriteBarrier,
                        "JSArrayBufferByteLength"};
#ifdef V8_ENABLE_SANDBOX
  access.is_bounded_size_access = true;
#endif
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayBufferViewBuffer() {
  FieldAccess access = {kTaggedBase,           JSArrayBufferView::kBufferOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "JSArrayBufferViewBuffer"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayBufferViewByteLength() {
  FieldAccess access = {kTaggedBase,
                        JSArrayBufferView::kRawByteLengthOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kJSArrayBufferViewByteLengthType,
                        MachineType::UintPtr(),
                        kNoWriteBarrier,
                        "JSArrayBufferViewByteLength"};
#ifdef V8_ENABLE_SANDBOX
  access.is_bounded_size_access = true;
#endif
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayBufferViewByteOffset() {
  FieldAccess access = {kTaggedBase,
                        JSArrayBufferView::kRawByteOffsetOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kJSArrayBufferViewByteOffsetType,
                        MachineType::UintPtr(),
                        kNoWriteBarrier,
                        "JSArrayBufferViewByteOffset"};
#ifdef V8_ENABLE_SANDBOX
  access.is_bounded_size_access = true;
#endif
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayBufferViewBitField() {
  FieldAccess access = {kTaggedBase,
                        JSArrayBufferView::kBitFieldOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kUint32,
                        MachineType::Uint32(),
                        kNoWriteBarrier,
                        "JSArrayBufferViewBitField"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSTypedArrayLength() {
  FieldAccess access = {kTaggedBase,
                        JSTypedArray::kRawLengthOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kJSTypedArrayLengthType,
                        MachineType::UintPtr(),
                        kNoWriteBarrier,
                        "JSTypedArrayLength"};
#ifdef V8_ENABLE_SANDBOX
  access.is_bounded_size_access = true;
#endif
  return access;
}

// static
FieldAccess AccessBuilder::ForJSTypedArrayBasePointer() {
  FieldAccess access = {kTaggedBase,           JSTypedArray::kBasePointerOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,     "JSTypedArrayBasePointer"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSTypedArrayExternalPointer() {
  FieldAccess access = {
      kTaggedBase,
      JSTypedArray::kExternalPointerOffset,
      MaybeHandle<Name>(),
      OptionalMapRef(),
#ifdef V8_ENABLE_SANDBOX
      Type::SandboxedPointer(),
      MachineType::SandboxedPointer(),
#else
      Type::ExternalPointer(),
      MachineType::Pointer(),
#endif
      kNoWriteBarrier,
      "JSTypedArrayExternalPointer",
      ConstFieldInfo::None(),
      false,
  };
  return access;
}

// static
FieldAccess AccessBuilder::ForJSDataViewDataPointer() {
  FieldAccess access = {
      kTaggedBase,
      JSDataView::kDataPointerOffset,
      MaybeHandle<Name>(),
      OptionalMapRef(),
#ifdef V8_ENABLE_SANDBOX
      Type::SandboxedPointer(),
      MachineType::SandboxedPointer(),
#else
      Type::ExternalPointer(),
      MachineType::Pointer(),
#endif
      kNoWriteBarrier,
      "JSDataViewDataPointer",
      ConstFieldInfo::None(),
      false,
  };
  return access;
}

// static
FieldAccess AccessBuilder::ForJSDateValue() {
  FieldAccess access = {kTaggedBase,
                        JSDate::kValueOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kJSDateValueType,
                        MachineType::Float64(),
                        kNoWriteBarrier,
                        "JSDateValue"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSDateField(JSDate::FieldIndex index) {
  FieldAccess access = {
      kTaggedBase,         JSDate::kYearOffset + index * kTaggedSize,
      MaybeHandle<Name>(), OptionalMapRef(),
      Type::Number(),      MachineType::AnyTagged(),
      kFullWriteBarrier,   "JSDateField"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSIteratorResultDone() {
  FieldAccess access = {kTaggedBase,         JSIteratorResult::kDoneOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSIteratorResultDone"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSIteratorResultValue() {
  FieldAccess access = {kTaggedBase,         JSIteratorResult::kValueOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSIteratorResultValue"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSPrimitiveWrapperValue() {
  FieldAccess access = {kTaggedBase,         JSPrimitiveWrapper::kValueOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSPrimitiveWrapperValue"};
  return access;
}

#ifdef V8_ENABLE_SANDBOX
// static
FieldAccess AccessBuilder::ForJSRegExpData() {
  FieldAccess access = {kTaggedBase,
                        JSRegExp::kDataOffset,
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        Type::OtherInternal(),
                        MachineType::IndirectPointer(),
                        kIndirectPointerWriteBarrier,
                        "JSRegExpData"};
  access.indirect_pointer_tag = kRegExpDataIndirectPointerTag;
  return access;
}
#else
// static
FieldAccess AccessBuilder::ForJSRegExpData() {
  FieldAccess access = {kTaggedBase,           JSRegExp::kDataOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "JSRegExpData"};
  return access;
}
#endif  // V8_ENABLE_SANDBOX

// static
FieldAccess AccessBuilder::ForJSRegExpFlags() {
  FieldAccess access = {kTaggedBase,         JSRegExp::kFlagsOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSRegExpFlags"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSRegExpLastIndex() {
  FieldAccess access = {kTaggedBase,         JSRegExp::kLastIndexOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSRegExpLastIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSRegExpSource() {
  FieldAccess access = {kTaggedBase,         JSRegExp::kSourceOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "JSRegExpSource"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFixedArrayLength() {
  FieldAccess access = {kTaggedBase,
                        offsetof(FixedArray, length_),
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kFixedArrayLengthType,
                        MachineType::TaggedSigned(),
                        kNoWriteBarrier,
                        "FixedArrayLength"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForWeakFixedArrayLength() {
  FieldAccess access = {kTaggedBase,
                        offsetof(WeakFixedArray, length_),
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kWeakFixedArrayLengthType,
                        MachineType::TaggedSigned(),
                        kNoWriteBarrier,
                        "WeakFixedArrayLength"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForSloppyArgumentsElementsContext() {
  FieldAccess access = {
      kTaggedBase,          offsetof(SloppyArgumentsElements, context_),
      MaybeHandle<Name>(),  OptionalMapRef(),
      Type::Any(),          MachineType::TaggedPointer(),
      kPointerWriteBarrier, "SloppyArgumentsElementsContext"};
  return access;
}

// static
FieldAccess AccessBuilder::ForSloppyArgumentsElementsArguments() {
  FieldAccess access = {
      kTaggedBase,          offsetof(SloppyArgumentsElements, arguments_),
      MaybeHandle<Name>(),  OptionalMapRef(),
      Type::Any(),          MachineType::TaggedPointer(),
      kPointerWriteBarrier, "SloppyArgumentsElementsArguments"};
  return access;
}

// static
FieldAccess AccessBuilder::ForPropertyArrayLengthAndHash() {
  FieldAccess access = {
      kTaggedBase,         PropertyArray::kLengthAndHashOffset,
      MaybeHandle<Name>(), OptionalMapRef(),
      Type::SignedSmall(), MachineType::TaggedSigned(),
      kNoWriteBarrier,     "PropertyArrayLengthAndHash"};
  return access;
}

// static
FieldAccess AccessBuilder::ForDescriptorArrayEnumCache() {
  FieldAccess access = {
      kTaggedBase,           DescriptorArray::kEnumCacheOffset,
      Handle<Name>(),        OptionalMapRef(),
      Type::OtherInternal(), MachineType::TaggedPointer(),
      kPointerWriteBarrier,  "DescriptorArrayEnumCache"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMapBitField() {
  FieldAccess access = {kTaggedBase,
                        Map::kBitFieldOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kUint8,
                        MachineType::Uint8(),
                        kNoWriteBarrier,
                        "MapBitField"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMapBitField2() {
  FieldAccess access = {kTaggedBase,
                        Map::kBitField2Offset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kUint8,
                        MachineType::Uint8(),
                        kNoWriteBarrier,
                        "MapBitField2"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMapBitField3() {
  FieldAccess access = {kTaggedBase,
                        Map::kBitField3Offset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kInt32,
                        MachineType::Int32(),
                        kNoWriteBarrier,
                        "MapBitField3"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMapDescriptors() {
  FieldAccess access = {kTaggedBase,           Map::kInstanceDescriptorsOffset,
                        Handle<Name>(),        OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "MapDescriptors"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMapInstanceType() {
  FieldAccess access = {
      kTaggedBase,      Map::kInstanceTypeOffset,  Handle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kUint16, MachineType::Uint16(),
      kNoWriteBarrier,  "MapInstanceType"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForMapPrototype() {
  FieldAccess access = {kTaggedBase,          Map::kPrototypeOffset,
                        Handle<Name>(),       OptionalMapRef(),
                        Type::Any(),          MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "MapPrototype"};
  return access;
}

// static
FieldAccess AccessBuilder::ForMapNativeContext() {
  FieldAccess access = {
      kTaggedBase,          Map::kConstructorOrBackPointerOrNativeContextOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::Any(),          MachineType::TaggedPointer(),
      kPointerWriteBarrier, "MapNativeContext"};
  return access;
}

// static
FieldAccess AccessBuilder::ForModuleRegularExports() {
  FieldAccess access = {
      kTaggedBase,           SourceTextModule::kRegularExportsOffset,
      Handle<Name>(),        OptionalMapRef(),
      Type::OtherInternal(), MachineType::TaggedPointer(),
      kPointerWriteBarrier,  "ModuleRegularExports"};
  return access;
}

// static
FieldAccess AccessBuilder::ForModuleRegularImports() {
  FieldAccess access = {
      kTaggedBase,           SourceTextModule::kRegularImportsOffset,
      Handle<Name>(),        OptionalMapRef(),
      Type::OtherInternal(), MachineType::TaggedPointer(),
      kPointerWriteBarrier,  "ModuleRegularImports"};
  return access;
}

// static
FieldAccess AccessBuilder::ForNameRawHashField() {
  FieldAccess access = {kTaggedBase,        offsetof(Name, raw_hash_field_),
                        Handle<Name>(),     OptionalMapRef(),
                        Type::Unsigned32(), MachineType::Uint32(),
                        kNoWriteBarrier,    "NameRawHashField"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFreeSpaceSize() {
  FieldAccess access = {kTaggedBase,         FreeSpace::kSizeOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::SignedSmall(), MachineType::TaggedSigned(),
                        kNoWriteBarrier};
  return access;
}

// static
FieldAccess AccessBuilder::ForStringLength() {
  FieldAccess access = {kTaggedBase,
                        offsetof(String, length_),
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kStringLengthType,
                        MachineType::Uint32(),
                        kNoWriteBarrier,
                        "StringLength"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForConsStringFirst() {
  FieldAccess access = {kTaggedBase,          offsetof(ConsString, first_),
                        Handle<Name>(),       OptionalMapRef(),
                        Type::String(),       MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "ConsStringFirst"};
  // Not immutable since flattening can mutate.
  access.is_immutable = false;
  return access;
}

// static
FieldAccess AccessBuilder::ForConsStringSecond() {
  FieldAccess access = {kTaggedBase,          offsetof(ConsString, second_),
                        Handle<Name>(),       OptionalMapRef(),
                        Type::String(),       MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "ConsStringSecond"};
  // Not immutable since flattening can mutate.
  access.is_immutable = false;
  return access;
}

// static
FieldAccess AccessBuilder::ForThinStringActual() {
  FieldAccess access = {kTaggedBase,          offsetof(ThinString, actual_),
                        Handle<Name>(),       OptionalMapRef(),
                        Type::String(),       MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "ThinStringActual"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForSlicedStringOffset() {
  FieldAccess access = {kTaggedBase,         offsetof(SlicedString, offset_),
                        Handle<Name>(),      OptionalMapRef(),
                        Type::SignedSmall(), MachineType::TaggedSigned(),
                        kNoWriteBarrier,     "SlicedStringOffset"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForSlicedStringParent() {
  FieldAccess access = {kTaggedBase,          offsetof(SlicedString, parent_),
                        Handle<Name>(),       OptionalMapRef(),
                        Type::String(),       MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "SlicedStringParent"};
  access.is_immutable = true;
  return access;
}

// static
FieldAccess AccessBuilder::ForExternalStringResourceData() {
  FieldAccess access = {
      kTaggedBase,
      offsetof(ExternalString, resource_data_),
      Handle<Name>(),
      OptionalMapRef(),
      Type::ExternalPointer(),
      MachineType::Pointer(),
      kNoWriteBarrier,
      "ExternalStringResourceData",
      ConstFieldInfo::None(),
      false,
      kExternalStringResourceDataTag,
  };
  return access;
}

// static
ElementAccess AccessBuilder::ForSeqOneByteStringCharacter() {
  ElementAccess access = {kTaggedBase, OFFSET_OF_DATA_START(SeqOneByteString),
                          TypeCache::Get()->kUint8, MachineType::Uint8(),
                          kNoWriteBarrier};
  return access;
}

// static
ElementAccess AccessBuilder::ForSeqTwoByteStringCharacter() {
  ElementAccess access = {kTaggedBase, OFFSET_OF_DATA_START(SeqTwoByteString),
                          TypeCache::Get()->kUint16, MachineType::Uint16(),
                          kNoWriteBarrier};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayIteratorIteratedObject() {
  FieldAccess access = {
      kTaggedBase,          JSArrayIterator::kIteratedObjectOffset,
      Handle<Name>(),       OptionalMapRef(),
      Type::Receiver(),     MachineType::TaggedPointer(),
      kPointerWriteBarrier, "JSArrayIteratorIteratedObject"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayIteratorNextIndex() {
  // In generic case, cap to 2^53-1 (per ToLength() in spec) via
  // kPositiveSafeInteger
  FieldAccess access = {kTaggedBase,
                        JSArrayIterator::kNextIndexOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kPositiveSafeInteger,
                        MachineType::AnyTagged(),
                        kFullWriteBarrier,
                        "JSArrayIteratorNextIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSArrayIteratorKind() {
  FieldAccess access = {kTaggedBase,
                        JSArrayIterator::kKindOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kJSArrayIteratorKindType,
                        MachineType::TaggedSigned(),
                        kNoWriteBarrier,
                        "JSArrayIteratorKind"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSStringIteratorString() {
  FieldAccess access = {kTaggedBase,          JSStringIterator::kStringOffset,
                        Handle<Name>(),       OptionalMapRef(),
                        Type::String(),       MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "JSStringIteratorString"};
  return access;
}

// static
FieldAccess AccessBuilder::ForJSStringIteratorIndex() {
  FieldAccess access = {kTaggedBase,
                        JSStringIterator::kIndexOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kStringLengthType,
                        MachineType::TaggedSigned(),
                        kNoWriteBarrier,
                        "JSStringIteratorIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForArgumentsLength() {
  constexpr int offset = JSStrictArgumentsObject::kLengthOffset;
  static_assert(offset == JSSloppyArgumentsObject::kLengthOffset);
  FieldAccess access = {kTaggedBase,         offset,
                        Handle<Name>(),      OptionalMapRef(),
                        Type::NonInternal(), MachineType::AnyTagged(),
                        kFullWriteBarrier,   "ArgumentsLength"};
  return access;
}

// static
FieldAccess AccessBuilder::ForArgumentsCallee() {
  FieldAccess access = {
      kTaggedBase,         JSSloppyArgumentsObject::kCalleeOffset,
      Handle<Name>(),      OptionalMapRef(),
      Type::NonInternal(), MachineType::AnyTagged(),
      kFullWriteBarrier,   "ArgumentsCallee"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFixedArraySlot(
    size_t index, WriteBarrierKind write_barrier_kind) {
  int offset = FixedArray::OffsetOfElementAt(static_cast<int>(index));
  FieldAccess access = {kTaggedBase,        offset,
                        Handle<Name>(),     OptionalMapRef(),
                        Type::Any(),        MachineType::AnyTagged(),
                        write_barrier_kind, "FixedArraySlot"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFeedbackVectorSlot(int index) {
  int offset = FeedbackVector::OffsetOfElementAt(index);
  FieldAccess access = {kTaggedBase,       offset,
                        Handle<Name>(),    OptionalMapRef(),
                        Type::Any(),       MachineType::AnyTagged(),
                        kFullWriteBarrier, "FeedbackVectorSlot"};
  return access;
}

// static
FieldAccess AccessBuilder::ForPropertyArraySlot(int index) {
  int offset = PropertyArray::OffsetOfElementAt(index);
  FieldAccess access = {kTaggedBase,       offset,
                        Handle<Name>(),    OptionalMapRef(),
                        Type::Any(),       MachineType::AnyTagged(),
                        kFullWriteBarrier, "PropertyArraySlot"};
  return access;
}

// static
FieldAccess AccessBuilder::ForWeakFixedArraySlot(int index) {
  int offset = WeakFixedArray::OffsetOfElementAt(index);
  FieldAccess access = {kTaggedBase,       offset,
                        Handle<Name>(),    OptionalMapRef(),
                        Type::Any(),       MachineType::AnyTagged(),
                        kFullWriteBarrier, "WeakFixedArraySlot"};
  return access;
}
// static
FieldAccess AccessBuilder::ForCellValue() {
  FieldAccess access = {kTaggedBase,       Cell::kValueOffset,
                        Handle<Name>(),    OptionalMapRef(),
                        Type::Any(),       MachineType::AnyTagged(),
                        kFullWriteBarrier, "CellValue"};
  return access;
}

// static
FieldAccess AccessBuilder::ForScopeInfoFlags() {
  FieldAccess access = {kTaggedBase,         ScopeInfo::kFlagsOffset,
                        MaybeHandle<Name>(), OptionalMapRef(),
                        Type::Unsigned32(),  MachineType::Uint32(),
                        kNoWriteBarrier,     "ScopeInfoFlags"};
  return access;
}

// static
FieldAccess AccessBuilder::ForContextSlot(size_t index) {
  int offset = Context::OffsetOfElementAt(static_cast<int>(index));
  DCHECK_EQ(offset,
            Context::SlotOffset(static_cast<int>(index)) + kHeapObjectTag);
  FieldAccess access = {kTaggedBase,       offset,
                        Handle<Name>(),    OptionalMapRef(),
                        Type::Any(),       MachineType::AnyTagged(),
                        kFullWriteBarrier, "ContextSlot"};
  return access;
}

// static
FieldAccess AccessBuilder::ForContextSlotKnownPointer(size_t index) {
  int offset = Context::OffsetOfElementAt(static_cast<int>(index));
  DCHECK_EQ(offset,
            Context::SlotOffset(static_cast<int>(index)) + kHeapObjectTag);
  FieldAccess access = {kTaggedBase,          offset,
                        Handle<Name>(),       OptionalMapRef(),
                        Type::Any(),          MachineType::TaggedPointer(),
                        kPointerWriteBarrier, "ContextSlotKnownPointer"};
  return access;
}

// static
FieldAccess AccessBuilder::ForContextSlotSmi(size_t index) {
  int offset = Context::OffsetOfElementAt(static_cast<int>(index));
  DCHECK_EQ(offset,
            Context::SlotOffset(static_cast<int>(index)) + kHeapObjectTag);
  FieldAccess access = {kTaggedBase,         offset,
                        Handle<Name>(),      OptionalMapRef(),
                        Type::SignedSmall(), MachineType::TaggedSigned(),
                        kNoWriteBarrier,     "Smi"};
  return access;
}

// static
ElementAccess AccessBuilder::ForFixedArrayElement() {
  ElementAccess access = {kTaggedBase, OFFSET_OF_DATA_START(FixedArray),
                          Type::Any(), MachineType::AnyTagged(),
                          kFullWriteBarrier};
  return access;
}

// static
ElementAccess AccessBuilder::ForWeakFixedArrayElement() {
  ElementAccess const access = {
      kTaggedBase, OFFSET_OF_DATA_START(WeakFixedArray), Type::Any(),
      MachineType::AnyTagged(), kFullWriteBarrier};
  return access;
}

// static
ElementAccess AccessBuilder::ForSloppyArgumentsElementsMappedEntry() {
  ElementAccess access = {
      kTaggedBase, OFFSET_OF_DATA_START(SloppyArgumentsElements), Type::Any(),
      MachineType::AnyTagged(), kFullWriteBarrier};
  return access;
}

// statics
ElementAccess AccessBuilder::ForFixedArrayElement(ElementsKind kind) {
  ElementAccess access = {kTaggedBase, OFFSET_OF_DATA_START(FixedArray),
                          Type::Any(), MachineType::AnyTagged(),
                          kFullWriteBarrier};
  switch (kind) {
    case PACKED_SMI_ELEMENTS:
      access.type = Type::SignedSmall();
      access.machine_type = MachineType::TaggedSigned();
      access.write_barrier_kind = kNoWriteBarrier;
      break;
    case HOLEY_SMI_ELEMENTS:
      access.type = TypeCache::Get()->kHoleySmi;
      break;
    case PACKED_ELEMENTS:
      access.type = Type::NonInternal();
      break;
    case HOLEY_ELEMENTS:
      break;
    case PACKED_DOUBLE_ELEMENTS:
      access.type = Type::Number();
      access.write_barrier_kind = kNoWriteBarrier;
      access.machine_type = MachineType::Float64();
      break;
    case HOLEY_DOUBLE_ELEMENTS:
      access.type = Type::NumberOrHole();
      access.write_barrier_kind = kNoWriteBarrier;
      access.machine_type = MachineType::Float64();
      break;
    default:
      UNREACHABLE();
  }
  return access;
}

// static
ElementAccess AccessBuilder::ForFixedDoubleArrayElement() {
  ElementAccess access = {kTaggedBase, OFFSET_OF_DATA_START(FixedDoubleArray),
                          TypeCache::Get()->kFloat64, MachineType::Float64(),
                          kNoWriteBarrier};
  return access;
}

// static
FieldAccess AccessBuilder::ForEnumCacheKeys() {
  FieldAccess access = {kTaggedBase,           EnumCache::kKeysOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "EnumCacheKeys"};
  return access;
}

// static
FieldAccess AccessBuilder::ForEnumCacheIndices() {
  FieldAccess access = {kTaggedBase,           EnumCache::kIndicesOffset,
                        MaybeHandle<Name>(),   OptionalMapRef(),
                        Type::OtherInternal(), MachineType::TaggedPointer(),
                        kPointerWriteBarrier,  "EnumCacheIndices"};
  return access;
}

// static
ElementAccess AccessBuilder::ForTypedArrayElement(ExternalArrayType type,
                                                  bool is_external) {
  BaseTaggedness taggedness = is_external ? kUntaggedBase : kTaggedBase;
  int header_size = is_external ? 0 : OFFSET_OF_DATA_START(ByteArray);
  switch (type) {
    case kExternalInt8Array: {
      ElementAccess access = {taggedness, header_size, Type::Signed32(),
                              MachineType::Int8(), kNoWriteBarrier};
      return access;
    }
    case kExternalUint8Array:
    case kExternalUint8ClampedArray: {
      ElementAccess access = {taggedness, header_size, Type::Unsigned32(),
                              MachineType::Uint8(), kNoWriteBarrier};
      return access;
    }
    case kExternalInt16Array: {
      ElementAccess access = {taggedness, header_size, Type::Signed32(),
                              MachineType::Int16(), kNoWriteBarrier};
      return access;
    }
    case kExternalUint16Array: {
      ElementAccess access = {taggedness, header_size, Type::Unsigned32(),
                              MachineType::Uint16(), kNoWriteBarrier};
      return access;
    }
    case kExternalInt32Array: {
      ElementAccess access = {taggedness, header_size, Type::Signed32(),
                              MachineType::Int32(), kNoWriteBarrier};
      return access;
    }
    case kExternalUint32Array: {
      ElementAccess access = {taggedness, header_size, Type::Unsigned32(),
                              MachineType::Uint32(), kNoWriteBarrier};
      return access;
    }
    case kExternalFloat16Array: {
      // TODO(v8:14012): support machine logic
      UNIMPLEMENTED();
    }
    case kExternalFloat32Array: {
      ElementAccess access = {taggedness, header_size, Type::Number(),
                              MachineType::Float32(), kNoWriteBarrier};
      return access;
    }
    case kExternalFloat64Array: {
      ElementAccess access = {taggedness, header_size, Type::Number(),
                              MachineType::Float64(), kNoWriteBarrier};
      return access;
    }
    case kExternalBigInt64Array: {
      ElementAccess access = {taggedness, header_size, Type::SignedBigInt64(),
                              MachineType::Int64(), kNoWriteBarrier};
      return access;
    }
    case kExternalBigUint64Array: {
      ElementAccess access = {taggedness, header_size, Type::UnsignedBigInt64(),
                              MachineType::Uint64(), kNoWriteBarrier};
      return access;
    }
  }
  UNREACHABLE();
}

// static
ElementAccess AccessBuilder::ForJSForInCacheArrayElement(ForInMode mode) {
  ElementAccess access = {
      kTaggedBase, OFFSET_OF_DATA_START(FixedArray),
      (mode == ForInMode::kGeneric ? Type::String()
                                   : Type::InternalizedString()),
      MachineType::AnyTagged(), kFullWriteBarrier};
  return access;
}

// static
FieldAccess AccessBuilder::ForHashTableBaseNumberOfElements() {
  FieldAccess access = {
      kTaggedBase,
      FixedArray::OffsetOfElementAt(HashTableBase::kNumberOfElementsIndex),
      MaybeHandle<Name>(),
      OptionalMapRef(),
      Type::SignedSmall(),
      MachineType::TaggedSigned(),
      kNoWriteBarrier,
      "HashTableBaseNumberOfElements"};
  return access;
}

// static
FieldAccess AccessBuilder::ForHashTableBaseNumberOfDeletedElement() {
  FieldAccess access = {kTaggedBase,
                        FixedArray::OffsetOfElementAt(
                            HashTableBase::kNumberOfDeletedElementsIndex),
                        MaybeHandle<Name>(),
                        OptionalMapRef(),
                        Type::SignedSmall(),
                        MachineType::TaggedSigned(),
                        kNoWriteBarrier,
                        "HashTableBaseNumberOfDeletedElement"};
  return access;
}

// static
FieldAccess AccessBuilder::ForHashTableBaseCapacity() {
  FieldAccess access = {
      kTaggedBase,
      FixedArray::OffsetOfElementAt(HashTableBase::kCapacityIndex),
      MaybeHandle<Name>(),
      OptionalMapRef(),
      Type::SignedSmall(),
      MachineType::TaggedSigned(),
      kNoWriteBarrier,
      "HashTableBaseCapacity"};
  return access;
}

// static
FieldAccess AccessBuilder::ForOrderedHashMapOrSetNextTable() {
  // TODO(turbofan): This will be redundant with the HashTableBase
  // methods above once the hash table unification is done.
  static_assert(OrderedHashMap::NextTableOffset() ==
                OrderedHashSet::NextTableOffset());
  FieldAccess const access = {
      kTaggedBase,         OrderedHashMap::NextTableOffset(),
      MaybeHandle<Name>(), OptionalMapRef(),
      Type::Any(),         MachineType::AnyTagged(),
      kFullWriteBarrier,   "OrderedHashMapOrSetNextTable"};
  return access;
}

// static
FieldAccess AccessBuilder::ForOrderedHashMapOrSetNumberOfBuckets() {
  // TODO(turbofan): This will be redundant with the HashTableBase
  // methods above once the hash table unification is done.
  static_assert(OrderedHashMap::NumberOfBucketsOffset() ==
                OrderedHashSet::NumberOfBucketsOffset());
  FieldAccess const access = {kTaggedBase,
                              OrderedHashMap::NumberOfBucketsOffset(),
                              MaybeHandle<Name>(),
                              OptionalMapRef(),
                              TypeCache::Get()->kFixedArrayLengthType,
                              MachineType::TaggedSigned(),
                              kNoWriteBarrier,
                              "OrderedHashMapOrSetNumberOfBuckets"};
  return access;
}

// static
FieldAccess AccessBuilder::ForOrderedHashMapOrSetNumberOfDeletedElements() {
  // TODO(turbofan): This will be redundant with the HashTableBase
  // methods above once the hash table unification is done.
  static_assert(OrderedHashMap::NumberOfDeletedElementsOffset() ==
                OrderedHashSet::NumberOfDeletedElementsOffset());
  FieldAccess const access = {kTaggedBase,
                              OrderedHashMap::NumberOfDeletedElementsOffset(),
                              MaybeHandle<Name>(),
                              OptionalMapRef(),
                              TypeCache::Get()->kFixedArrayLengthType,
                              MachineType::TaggedSigned(),
                              kNoWriteBarrier,
                              "OrderedHashMapOrSetNumberOfDeletedElements"};
  return access;
}

// static
FieldAccess AccessBuilder::ForOrderedHashMapOrSetNumberOfElements() {
  // TODO(turbofan): This will be redundant with the HashTableBase
  // methods above once the hash table unification is done.
  static_assert(OrderedHashMap::NumberOfElementsOffset() ==
                OrderedHashSet::NumberOfElementsOffset());
  FieldAccess const access = {kTaggedBase,
                              OrderedHashMap::NumberOfElementsOffset(),
                              MaybeHandle<Name>(),
                              OptionalMapRef(),
                              TypeCache::Get()->kFixedArrayLengthType,
                              MachineType::TaggedSigned(),
                              kNoWriteBarrier,
                              "OrderedHashMapOrSetNumberOfElements"};
  return access;
}

// static
ElementAccess AccessBuilder::ForOrderedHashMapEntryValue() {
  ElementAccess const access = {kTaggedBase,
                                OrderedHashMap::HashTableStartOffset() +
                                    OrderedHashMap::kValueOffset * kTaggedSize,
                                Type::Any(), MachineType::AnyTagged(),
                                kFullWriteBarrier};
  return access;
}

// static
FieldAccess AccessBuilder::ForDictionaryNextEnumerationIndex() {
  FieldAccess access = {
      kTaggedBase,
      FixedArray::OffsetOfElementAt(NameDictionary::kNextEnumerationIndexIndex),
      MaybeHandle<Name>(),
      OptionalMapRef(),
      Type::SignedSmall(),
      MachineType::TaggedSigned(),
      kNoWriteBarrier,
      "DictionaryNextEnumerationIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForDictionaryObjectHashIndex() {
  FieldAccess access = {
      kTaggedBase,
      FixedArray::OffsetOfElementAt(NameDictionary::kObjectHashIndex),
      MaybeHandle<Name>(),
      OptionalMapRef(),
      Type::SignedSmall(),
      MachineType::TaggedSigned(),
      kNoWriteBarrier,
      "DictionaryObjectHashIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForNameDictionaryFlagsIndex() {
  FieldAccess access = {
      kTaggedBase,
      FixedArray::OffsetOfElementAt(NameDictionary::kFlagsIndex),
      MaybeHandle<Name>(),
      OptionalMapRef(),
      Type::SignedSmall(),
      MachineType::TaggedSigned(),
      kNoWriteBarrier,
      "NameDictionaryFlagsIndex"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFeedbackCellInterruptBudget() {
  FieldAccess access = {kTaggedBase,
                        FeedbackCell::kInterruptBudgetOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kInt32,
                        MachineType::Int32(),
                        kNoWriteBarrier,
                        "FeedbackCellInterruptBudget"};
  return access;
}

#ifdef V8_ENABLE_LEAPTIERING
// static
FieldAccess AccessBuilder::ForFeedbackCellDispatchHandleNoWriteBarrier() {
  // Dispatch handles in FeedbackCells are effectively const-after-init and so
  // they are marked as kNoWriteBarrier here (because the fields will not be
  // written to).
  FieldAccess access = {kTaggedBase,
                        FeedbackCell::kDispatchHandleOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kInt32,
                        MachineType::Int32(),
                        kNoWriteBarrier,
                        "FeedbackCellDispatchHandle"};
  return access;
}
#endif  // V8_ENABLE_LEAPTIERING

// static
FieldAccess AccessBuilder::ForFeedbackVectorInvocationCount() {
  FieldAccess access = {kTaggedBase,
                        FeedbackVector::kInvocationCountOffset,
                        Handle<Name>(),
                        OptionalMapRef(),
                        TypeCache::Get()->kInt32,
                        MachineType::Int32(),
                        kNoWriteBarrier,
                        "FeedbackVectorInvocationCount"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFeedbackVectorFlags() {
  FieldAccess access = {
      kTaggedBase,      FeedbackVector::kFlagsOffset, Handle<Name>(),
      OptionalMapRef(), TypeCache::Get()->kUint16,    MachineType::Uint16(),
      kNoWriteBarrier,  "FeedbackVectorFlags"};
  return access;
}

// static
FieldAccess AccessBuilder::ForFeedbackVectorClosureFeedbackCellArray() {
  FieldAccess access = {
      kTaggedBase,       FeedbackVector::kClosureFeedbackCellArrayOffset,
      Handle<Name>(),    OptionalMapRef(),
      Type::Any(),       MachineType::TaggedPointer(),
      kFullWriteBarrier, "FeedbackVectorClosureFeedbackCellArray"};
  return access;
}

#if V8_ENABLE_WEBASSEMBLY
// static
FieldAccess AccessBuilder::ForWasmArrayLength() {
  return {compiler::kTaggedBase,
          WasmArray::kLengthOffset,
          MaybeHandle<Name>(),
          compiler::OptionalMapRef(),
          compiler::Type::OtherInternal(),
          MachineType::Uint32(),
          compiler::kNoWriteBarrier,
          "WasmArrayLength"};
}

// static
FieldAccess AccessBuilder::ForWasmDispatchTableLength() {
  return {compiler::kTaggedBase,
          WasmDispatchTable::kLengthOffset,
          MaybeHandle<Name>{},
          compiler::OptionalMapRef{},
          compiler::Type::OtherInternal(),
          MachineType::Uint32(),
          compiler::kNoWriteBarrier,
          "WasmDispatchTableLength"};
}
#endif  // V8_ENABLE_WEBASSEMBLY

// static
FieldAccess AccessBuilder::ForContextSideProperty() {
  FieldAccess access = {
      kTaggedBase,         ContextSidePropertyCell::kPropertyDetailsRawOffset,
      MaybeHandle<Name>(), OptionalMapRef(),
      Type::SignedSmall(), MachineType::TaggedSigned(),
      kNoWriteBarrier,     "ContextSidePropertyDetails"};
  return access;
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```