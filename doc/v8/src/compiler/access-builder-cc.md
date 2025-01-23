Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the requested information.

**1. Understanding the Goal:**

The core request is to understand the purpose of `v8/src/compiler/access-builder.cc`. The prompt also has specific sub-questions about its relationship to Torque, JavaScript, code logic, and common errors. The fact that it's part 1 of 2 suggests there might be more to this file or related files.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for obvious patterns and keywords. Things that immediately stand out:

* **`// Copyright ... BSD-style license`**: Standard V8 copyright and licensing information, indicating this is indeed V8 source code.
* **`#include ...`**:  Includes of other V8 header files (`type-cache.h`, `handles-inl.h`, `objects/...`). This tells us that `access-builder.cc` interacts with V8's object model and type system.
* **`namespace v8 { namespace internal { namespace compiler {`**:  Confirms the location within the V8 codebase and that it's part of the compiler.
* **`// static FieldAccess AccessBuilder::For...()`**: A very common pattern. The `static` keyword means these are class methods. `FieldAccess` suggests it's building or describing how to access fields of objects. The `For...()` naming convention strongly hints at factory methods, creating `FieldAccess` objects for specific data members.
* **Numerous `FieldAccess` definitions with initializers**: This reinforces the idea that the file is about defining ways to access object fields. The initializers show various properties like `kTaggedBase`, offsets, `MachineType`, `WriteBarrierKind`, and descriptive names.
* **Object names in method names**:  Methods like `ForMap`, `ForHeapNumberValue`, `ForJSObjectPropertiesOrHash`, etc., directly correlate to V8's internal object types. This is a strong clue that the file is about accessing members of these specific V8 objects.
* **`offsetof`**: This C++ macro is used to calculate the byte offset of a member within a struct or class. This confirms that `access-builder.cc` is working with the low-level memory layout of V8 objects.
* **`MachineType`**:  Indicates the underlying machine representation of the data being accessed (e.g., `IntPtr`, `Float64`, `TaggedPointer`). This is compiler-specific information.
* **`WriteBarrierKind`**:  Related to V8's garbage collector. Different write barriers are needed for different types of pointers to maintain memory safety.
* **Descriptive strings in `FieldAccess` initializers**: Strings like "Map", "HeapNumberValue", "JSObjectPropertiesOrHash" make it clear what field is being described.

**3. Deducing the Functionality:**

Based on the keywords and patterns, the core functionality emerges: `access-builder.cc` provides a way to create descriptions (`FieldAccess` objects) of how to access specific fields within various V8 internal objects. It's essentially a catalog or factory for field access information.

**4. Addressing Specific Questions:**

* **`.tq` extension:** The code is `.cc`, so it's C++, not Torque. This is a straightforward check.
* **Relationship to JavaScript:** Since it deals with internal V8 objects (like `JSObject`, `JSArray`, `String`), which are the runtime representations of JavaScript concepts, there's a direct relationship. The compiler uses this information to generate efficient code for accessing JavaScript object properties and data.
* **JavaScript Examples:**  To illustrate the connection, simple JavaScript code that accesses properties of these objects is needed. For example, `object.property`, `array[index]`, etc. The key is to link the internal V8 object names with their JavaScript counterparts.
* **Code Logic/Inference:** The code itself is mostly declarative (defining data structures). The "logic" lies in *how* the compiler uses this information. A simple example of inference would be: if you access `object.x`, the compiler might use `AccessBuilder::ForJSObjectPropertiesOrHash()` to determine the memory location of that property. However, without knowing the *usage* of this class within the compiler, the inference is limited. A basic example with a hypothetical function is the best approach.
* **Common Programming Errors:** The most common errors are related to accessing properties that don't exist or using the wrong type of access. Examples in JavaScript would be `undefined` errors, type errors, or accessing out-of-bounds array elements. Linking these high-level errors to the low-level field access mechanisms in V8 is the goal.

**5. Structuring the Output:**

The prompt asks for a summary of functionality and then addresses specific points. A logical structure would be:

* **Overall Functionality:** Start with a concise description of what `access-builder.cc` does.
* **Torque Check:** Address the `.tq` question.
* **JavaScript Relationship:** Explain the connection and provide JavaScript examples.
* **Code Logic/Inference:** Present a simplified scenario of how the `FieldAccess` information might be used.
* **Common Errors:** Illustrate common JavaScript errors that relate to the concepts in the code.
* **Summary (Part 1):** Reiterate the main purpose of the file.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this file *implements* object access.
* **Correction:**  Closer inspection reveals it *describes* object access. The compiler will likely use this information to generate the actual access instructions.
* **Focus on `FieldAccess`**: Realize that the `FieldAccess` struct is the central data structure and everything revolves around creating and using instances of it.
* **JavaScript examples need to be simple and direct**: Avoid complex JavaScript code; focus on the basic property and array access that maps to the V8 object fields.
* **Acknowledge limitations of inference**:  Without the context of the broader compiler, detailed code logic inference is impossible. Focus on illustrating the *potential* usage.

By following these steps, the detailed and informative answer provided earlier can be generated. The process involves a combination of code reading, keyword identification, deduction, and relating the low-level C++ code to high-level JavaScript concepts.
好的，让我们来分析一下 `v8/src/compiler/access-builder.cc` 这个 V8 源代码文件的功能。

**1. 文件类型判断:**

首先，根据您的描述，`v8/src/compiler/access-builder.cc` 以 `.cc` 结尾，而不是 `.tq`。这意味着它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码文件。

**2. 功能归纳:**

浏览代码内容，我们可以观察到 `AccessBuilder` 类中定义了大量的静态方法，这些方法都返回一个 `FieldAccess` 类型的结构体。每个方法的名字都以 `For` 开头，并且通常与 V8 内部对象的成员变量有关，例如 `ForMap`, `ForHeapNumberValue`, `ForJSObjectPropertiesOrHash` 等。

`FieldAccess` 结构体包含了访问对象成员所需的各种信息，例如：

* **`base_is_tagged` (隐含在 `kTaggedBase` 等枚举值中):** 指示访问的起始地址是否是带标签的指针。
* **`offset`:** 相对于基地址的偏移量。
* **`name`:** 可选的成员变量名称。
* **`optional_map_ref`:** 可选的 Map 引用，用于类型检查。
* **`type`:** 成员变量的类型信息。
* **`machine_type`:** 成员变量在机器层的表示类型。
* **`write_barrier_kind`:**  写屏障类型，用于垃圾回收。
* **`name_for_diagnostic`:** 用于诊断的名称。

因此，`v8/src/compiler/access-builder.cc` 的主要功能是：

**提供了一组静态方法，用于创建和描述如何访问 V8 内部对象的特定成员变量。** 这些方法返回的 `FieldAccess` 对象封装了访问这些成员所需的元数据，供 V8 编译器在生成机器码时使用。

**3. 与 JavaScript 的关系及示例:**

`v8/src/compiler/access-builder.cc` 虽然是 C++ 代码，但它直接服务于 JavaScript 的执行。V8 引擎负责将 JavaScript 代码编译成机器码并执行。在编译过程中，编译器需要了解 JavaScript 对象的内部布局，以及如何访问对象的属性和元素。

`AccessBuilder` 提供的信息正是用于实现 JavaScript 对象属性访问的关键。例如：

* 当访问一个 JavaScript 对象的属性时 (例如 `object.property` 或 `object['property']`)，编译器需要知道 `property` 在对象内存中的偏移量。
* 当访问一个 JavaScript 数组的元素时 (例如 `array[i]`)，编译器需要知道数组元素的存储位置和类型。

**JavaScript 示例:**

```javascript
const obj = { x: 10, y: "hello" };
console.log(obj.x); // 访问属性 x

const arr = [1, 2, 3];
console.log(arr[1]); // 访问数组的第二个元素
```

在 V8 内部，当编译这些 JavaScript 代码时，编译器可能会使用 `AccessBuilder` 中定义的方法来获取访问 `obj.x` 和 `arr[1]` 所需的 `FieldAccess` 信息。

例如，对于 `obj.x` 的访问，编译器可能会查找与 `JSObject` 相关的属性存储方式，并使用类似 `AccessBuilder::ForJSObjectInObjectProperty` 或 `AccessBuilder::ForJSObjectPropertiesOrHash` 这样的方法来获取 `x` 属性的偏移量和其他访问信息。

**4. 代码逻辑推理及假设输入输出:**

`AccessBuilder` 本身更多的是数据描述，而不是复杂的逻辑推理。它的主要作用是提供预定义好的访问信息。

**假设输入:** 编译器需要生成访问一个 `JSArray` 对象长度的机器码。

**输出:** 编译器会调用 `AccessBuilder::ForJSArrayLength(elements_kind)` 方法，根据数组的元素类型 `elements_kind`，该方法会返回一个 `FieldAccess` 对象，其中包含了 `JSArray` 对象长度属性的偏移量 (`JSArray::kLengthOffset`)、数据类型 (`TypeCache::Get()->kJSArrayLengthType`) 和机器类型 (`MachineType::AnyTagged()` 或 `MachineType::TaggedSigned()`) 等信息。

**5. 涉及用户常见的编程错误及示例:**

`AccessBuilder` 自身不直接处理用户编程错误，但它所描述的访问机制与用户常见的编程错误息息相关。

**常见编程错误示例:**

* **访问未定义的属性:**

```javascript
const obj = { x: 10 };
console.log(obj.y); // 输出 undefined
```

在 V8 内部，当尝试访问 `obj.y` 时，如果 `obj` 的属性列表中没有 `y`，编译器根据 `AccessBuilder` 提供的信息，会知道在哪里查找属性，但最终会返回一个表示未找到的值 (通常是 `undefined`)。

* **访问数组越界:**

```javascript
const arr = [1, 2, 3];
console.log(arr[5]); // 输出 undefined
```

编译器会使用 `AccessBuilder::ForJSArrayElements` 等方法来确定数组元素的访问方式。当索引超出数组边界时，V8 会返回 `undefined` 或抛出错误 (取决于具体的访问方式和优化情况)。

* **类型错误:**

```javascript
const obj = { x: "hello" };
console.log(obj.x + 5); // 可能会产生错误，因为字符串不能直接加数字
```

虽然 `AccessBuilder` 不直接处理类型错误，但它提供的类型信息 (`FieldAccess::type` 和 `FieldAccess::machine_type`) 可以帮助编译器在早期阶段进行类型检查和优化。

**6. 功能归纳 (第 1 部分):**

总而言之，`v8/src/compiler/access-builder.cc` 的主要功能是：

**为 V8 编译器提供了一种结构化的方式来定义和获取访问 V8 内部对象成员变量所需的元数据。它就像一个蓝图库，告诉编译器如何安全有效地读取和写入不同类型对象的各种字段。**  这个文件不包含复杂的业务逻辑，而是专注于提供精确的内存布局和类型信息，使得编译器能够生成正确的机器码来操作 JavaScript 对象。

在接下来的第 2 部分，我们可能会看到更多关于如何使用 `AccessBuilder` 提供的信息，例如在编译器管道中的具体应用，以及与其他编译阶段的交互。

### 提示词
```
这是目录为v8/src/compiler/access-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/access-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                        Han
```