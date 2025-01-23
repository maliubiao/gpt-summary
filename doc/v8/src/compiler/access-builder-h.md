Response:
Let's break down the thought process for analyzing the provided C++ header file `access-builder.h`.

1. **Initial Scan and Identification of Purpose:**

   - The header comment clearly states: "This access builder provides a set of static methods constructing commonly used FieldAccess and ElementAccess descriptors."
   -  Keywords like "FieldAccess" and "ElementAccess" hint at accessing data within objects.
   - The namespace `v8::internal::compiler` suggests this is part of V8's compilation pipeline.

2. **Understanding `FieldAccess` and `ElementAccess`:**

   - The comment mentions these are "descriptors" used as parameters for "simplified load/store operators."  This implies these structures define *how* to access data (e.g., the offset, data type, and whether a write barrier is needed).

3. **Categorizing the Methods:**

   - Quickly scanning the methods, a clear pattern emerges:  Many methods are named `For[Something]`.
   -  The `[Something]` part usually corresponds to a specific V8 internal object or concept (e.g., `Map`, `JSObject`, `FixedArray`).
   - This suggests the main function is to provide convenient ways to describe access to specific fields or elements of these V8 internal objects.

4. **Identifying Key Concepts:**

   - **Heap Objects:** Many methods refer to `JSObject`, `HeapNumber`, `BigInt`, etc. This indicates a focus on accessing data within V8's heap-allocated objects.
   - **Fields:**  Methods like `ForMap`, `ForJSObjectPropertiesOrHash` clearly point to accessing *fields* of objects.
   - **Elements:** Methods like `ForFixedArrayElement`, `ForSeqOneByteStringCharacter` relate to accessing *elements* of arrays or strings.
   - **External References:** `ForExternalIntPtr` stands out, suggesting access to memory outside the V8 heap.
   - **Write Barriers:**  The `WriteBarrierKind` parameter in some methods (like `ForMap`) hints at V8's garbage collection mechanism and the need to inform the collector about object modifications.
   - **Machine Types:** The `MachineType` parameter (e.g., in `ForJSObjectInObjectProperty`) suggests that the access might need to be aware of the underlying data representation.

5. **Inferring Functionality Based on Method Names:**

   -  `ForMap()`: Accesses the map (object metadata) of a heap object.
   -  `ForJSObjectPropertiesOrHash()`: Accesses the properties or hash part of a JSObject.
   -  `ForFixedArrayLength()`: Gets the length of a fixed-size array.
   -  `ForContextSlot()`: Accesses a slot within a context (lexical environment).
   -  `ForTypedArrayElement()`: Accesses an element of a Typed Array.

6. **Connecting to JavaScript:**

   -  Think about common JavaScript operations and how they might relate to these internal accesses:
      - Accessing a property (`object.property`):  Likely involves `ForJSObjectInObjectProperty` or related methods.
      - Accessing an array element (`array[index]`): Likely uses `ForFixedArrayElement` or `ForTypedArrayElement`.
      - Getting the length of an array (`array.length`):  Uses `ForJSArrayLength`.
      - Accessing the prototype of an object: Uses `ForMapPrototype`.
      - Function calls and context:  Relates to `ForJSFunctionContext`.

7. **Considering Potential Errors:**

   -  Based on the access patterns, think about common JavaScript errors:
      - Trying to access a property that doesn't exist (might lead to checks related to `JSObject` properties).
      - Indexing an array out of bounds (could relate to `FixedArrayLength` checks).
      - Type errors (e.g., trying to access a property on a primitive value; this might involve checks against object maps).

8. **Addressing Specific Questions from the Prompt:**

   - **Functionality:**  Summarize the observations from the previous steps.
   - **`.tq` extension:**  The prompt itself provides the answer to this. If the file ended in `.tq`, it would be a Torque file.
   - **JavaScript Relationship:** Provide concrete examples linking the C++ methods to JavaScript operations.
   - **Logic Inference:** Create simple scenarios with input and output to illustrate how these accessors might be used internally.
   - **Common Errors:** Give examples of JavaScript errors that might relate to the underlying access mechanisms.

9. **Refinement and Structuring:**

   - Organize the information logically. Start with a high-level overview and then delve into specifics.
   - Use clear and concise language.
   - Provide code examples where appropriate.
   - Ensure all parts of the prompt are addressed.

**Self-Correction/Refinement Example During the Process:**

- **Initial thought:**  "Maybe `AccessBuilder` is about creating actual objects."
- **Correction:** "The comments say it constructs *descriptors*. Descriptors are used *when* accessing objects, not for creating them. The load/store operators use these descriptors."  This correction clarifies the role of `AccessBuilder`.

By following this kind of systematic analysis, combining code reading with knowledge of JavaScript and V8 internals, you can effectively understand the purpose and functionality of a complex piece of code like `access-builder.h`.
`v8/src/compiler/access-builder.h` 是 V8 引擎中 Turbofan 编译器的一部分，它提供了一组静态方法，用于构建 `FieldAccess` 和 `ElementAccess` 描述符。这些描述符被用作简化加载和存储操作符的参数，用于访问 JavaScript 对象的属性和元素。

**功能概括:**

`AccessBuilder` 类的主要功能是提供便捷的方式来描述如何访问 V8 堆中各种对象的特定字段或元素。 它封装了构建 `FieldAccess` 和 `ElementAccess` 结构体的细节，使得编译器代码更加简洁易懂。  本质上，它是一个工厂类，用于创建描述符。

**功能详细列举:**

该头文件中定义了大量的静态方法，每个方法对应一种特定的访问场景，主要可以归纳为以下几类：

1. **访问外部值:**
   - `ForExternalIntPtr()`:  用于访问通过外部引用标识的 `IntPtr` 类型的字段。

2. **访问堆对象字段:** 提供了访问各种 V8 堆对象（例如 `JSObject`, `HeapNumber`, `String`, `Array` 等）特定字段的方法。  例如：
   - `ForMap()`:  访问对象的 `map` 字段（描述对象结构和类型的元数据）。
   - `ForJSObjectPropertiesOrHash()`: 访问 `JSObject` 的 `properties` 字段（存储命名属性）或者其哈希值。
   - `ForJSArrayLength()`: 访问 `JSArray` 的 `length` 字段。
   - `ForJSFunctionContext()`: 访问 `JSFunction` 的 `context` 字段（闭包上下文）。
   - `ForStringLength()`: 访问 `String` 对象的 `length` 字段。

3. **访问堆对象元素:** 提供了访问各种 V8 堆对象元素的方法，例如数组元素、字符串字符等。例如：
   - `ForFixedArrayElement()`: 访问 `FixedArray` 的元素。
   - `ForSeqOneByteStringCharacter()`: 访问单字节字符串的字符。
   - `ForTypedArrayElement()`: 访问类型化数组的元素。

4. **访问特定类型的槽位 (Slots):**  提供访问特定数据结构中槽位的方法，例如：
   - `ForFixedArraySlot()`: 访问 `FixedArray` 的特定槽位。
   - `ForContextSlot()`: 访问 `Context` (作用域链) 的特定槽位。
   - `ForFeedbackVectorSlot()`: 访问 `FeedbackVector` 的特定槽位（用于性能优化）。

5. **访问哈希表相关字段:** 提供访问哈希表（如 `Dictionary`, `OrderedHashMap`）内部结构的字段。

**关于 .tq 扩展名:**

如果 `v8/src/compiler/access-builder.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于定义运行时内置函数和类型系统的领域特定语言。Torque 代码会被编译成 C++ 代码。  当前的 `access-builder.h` 是一个 C++ 头文件。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`AccessBuilder` 中定义的方法与 JavaScript 的许多基本操作密切相关，因为编译器需要理解并高效地执行这些操作。

**示例 1: 访问对象属性**

```javascript
const obj = { name: "Alice", age: 30 };
const name = obj.name;
```

在 V8 的编译过程中，当编译器遇到 `obj.name` 时，它可能使用 `AccessBuilder::ForJSObjectInObjectProperty()` 或类似的函数来构建一个 `FieldAccess` 描述符，指明要访问 `obj` 对象中名为 "name" 的属性。这个描述符会告诉后续的加载操作符在哪里以及如何找到这个属性的值。

**示例 2: 访问数组元素**

```javascript
const arr = [1, 2, 3];
const firstElement = arr[0];
```

当编译器处理 `arr[0]` 时，它可能使用 `AccessBuilder::ForFixedArrayElement()` 来创建一个 `ElementAccess` 描述符，说明要访问 `arr` 内部存储元素的 `FixedArray` 中的第一个元素。

**示例 3: 获取数组长度**

```javascript
const arr = [1, 2, 3, 4];
const length = arr.length;
```

编译器在处理 `arr.length` 时，会使用 `AccessBuilder::ForJSArrayLength()` 生成一个 `FieldAccess` 描述符，指向 `JSArray` 对象的 `length` 字段。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下简化场景：编译器需要生成访问一个 `JSArray` 对象长度的代码。

**假设输入:**

- 一个指向 `JSArray` 对象的指针（或者表示该对象的节点）。
- 需要访问的字段是 `length`。

**代码逻辑 (简化):**

编译器会调用 `AccessBuilder::ForJSArrayLength(elements_kind)`，其中 `elements_kind` 可能代表数组元素的类型 (例如，SMI, DOUBLE, HOLEY 等)。

**预期输出:**

- 一个 `FieldAccess` 结构体，其中包含了访问 `JSArray` 对象 `length` 字段所需的信息，例如：
    - 字段在对象中的偏移量。
    - 字段的机器类型 (例如，Smi)。
    - 写屏障类型 (用于垃圾回收)。

**用户常见的编程错误及示例:**

虽然 `access-builder.h` 是编译器内部的组件，但用户编写的 JavaScript 代码中的错误最终会导致编译器生成不正确的或者抛出异常的代码。以下是一些可能相关的用户错误：

**示例 1: 访问未定义的属性**

```javascript
const obj = { name: "Bob" };
console.log(obj.age); // 访问未定义的属性
```

当编译器尝试访问 `obj.age` 时，由于 `age` 属性不存在，V8 内部的属性查找机制会失败。虽然 `AccessBuilder` 不直接处理这种错误，但它提供的工具被用来构建访问属性的代码，而这些代码最终会处理属性不存在的情况（通常返回 `undefined`）。

**示例 2: 数组越界访问**

```javascript
const arr = [10, 20];
console.log(arr[5]); // 数组越界访问
```

当编译器处理 `arr[5]` 时，它会生成访问数组元素的代码。然而，在运行时，由于索引超出了数组的界限，V8 会抛出一个错误（如果启用了严格模式，或者数组是密集数组）。 `AccessBuilder::ForFixedArrayElement()` 用于描述元素访问，但运行时的边界检查是另一部分机制负责的。

**总结:**

`v8/src/compiler/access-builder.h` 是 V8 编译器中一个关键的工具类，它通过提供静态方法来简化 `FieldAccess` 和 `ElementAccess` 描述符的创建，使得编译器能够方便地描述如何访问 JavaScript 对象的内部数据。它与 JavaScript 的各种操作息息相关，是 V8 引擎高效执行 JavaScript 代码的基础。

### 提示词
```
这是目录为v8/src/compiler/access-builder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/access-builder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_ACCESS_BUILDER_H_
#define V8_COMPILER_ACCESS_BUILDER_H_

#include "src/base/compiler-specific.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/objects/elements-kind.h"
#include "src/objects/js-objects.h"

namespace v8 {
namespace internal {
namespace compiler {

// This access builder provides a set of static methods constructing commonly
// used FieldAccess and ElementAccess descriptors. These descriptors serve as
// parameters to simplified load/store operators.
class V8_EXPORT_PRIVATE AccessBuilder final
    : public NON_EXPORTED_BASE(AllStatic) {
 public:
  // ===========================================================================
  // Access to external values (based on external references).

  // Provides access to an IntPtr field identified by an external reference.
  static FieldAccess ForExternalIntPtr();

  // ===========================================================================
  // Access to heap object fields and elements (based on tagged pointer).

  // Provides access to HeapObject::map() field.
  static FieldAccess ForMap(WriteBarrierKind write_barrier = kMapWriteBarrier);

  // Provides access to HeapNumber::value() field.
  static FieldAccess ForHeapNumberValue();

  // Provides access to HeapNumber::value() and Oddball::to_number_raw() fields.
  // This is the same as ForHeapNumberValue, except it documents (and static
  // asserts) that both inputs are valid.
  static FieldAccess ForHeapNumberOrOddballOrHoleValue();

  // Provides access to BigInt's bit field.
  static FieldAccess ForBigIntBitfield();

#ifdef BIGINT_NEEDS_PADDING
  // Provides access to BigInt's 32 bit padding that is placed after the
  // bitfield on 64 bit architectures without pointer compression.
  static FieldAccess ForBigIntOptionalPadding();
#endif

  // Provides access to BigInt's least significant digit on 64 bit
  // architectures. Do not use this on 32 bit architectures.
  static FieldAccess ForBigIntLeastSignificantDigit64();

  // Provides access to JSObject::properties() field.
  static FieldAccess ForJSObjectPropertiesOrHash();

  // Provides access to JSObject::properties() field for known pointers.
  static FieldAccess ForJSObjectPropertiesOrHashKnownPointer();

  // Provides access to JSObject::elements() field.
  static FieldAccess ForJSObjectElements();

  // Provides access to JSObject inobject property fields.
  static FieldAccess ForJSObjectInObjectProperty(
      MapRef map, int index,
      MachineType machine_type = MachineType::AnyTagged());
  static FieldAccess ForJSObjectOffset(
      int offset, WriteBarrierKind write_barrier_kind = kFullWriteBarrier);

  // Provides access to JSCollecton::table() field.
  static FieldAccess ForJSCollectionTable();

  // Provides access to JSCollectionIterator::table() field.
  static FieldAccess ForJSCollectionIteratorTable();

  // Provides access to JSCollectionIterator::index() field.
  static FieldAccess ForJSCollectionIteratorIndex();

  // Provides access to an ExternalPointer through the JSExternalObject::value()
  // field.
  static FieldAccess ForJSExternalObjectValue();

#ifdef V8_ENABLE_SANDBOX
  // Provides access to JSExternalObject::value() field.
  static FieldAccess ForJSExternalObjectPointerHandle();
#endif

  // Provides access to JSFunction::prototype_or_initial_map() field.
  static FieldAccess ForJSFunctionPrototypeOrInitialMap();

  // Provides access to JSFunction::context() field.
  static FieldAccess ForJSFunctionContext();

  // Provides access to JSFunction::shared() field.
  static FieldAccess ForJSFunctionSharedFunctionInfo();

  // Provides access to JSFunction::feedback_cell() field.
  static FieldAccess ForJSFunctionFeedbackCell();

#ifdef V8_ENABLE_LEAPTIERING
  // Provides access to JSFunction::dispatch_handle() field.
  static FieldAccess ForJSFunctionDispatchHandleNoWriteBarrier();
#else
  // Provides access to JSFunction::code() field.
  static FieldAccess ForJSFunctionCode();
#endif  // V8_ENABLE_LEAPTIERING

  // Provides access to JSBoundFunction::bound_target_function() field.
  static FieldAccess ForJSBoundFunctionBoundTargetFunction();

  // Provides access to JSBoundFunction::bound_this() field.
  static FieldAccess ForJSBoundFunctionBoundThis();

  // Provides access to JSBoundFunction::bound_arguments() field.
  static FieldAccess ForJSBoundFunctionBoundArguments();

  // Provides access to JSGeneratorObject::context() field.
  static FieldAccess ForJSGeneratorObjectContext();

  // Provides access to JSGeneratorObject::continuation() field.
  static FieldAccess ForJSGeneratorObjectContinuation();

  // Provides access to JSGeneratorObject::input_or_debug_pos() field.
  static FieldAccess ForJSGeneratorObjectInputOrDebugPos();

  // Provides access to JSGeneratorObject::parameters_and_registers() field.
  static FieldAccess ForJSGeneratorObjectParametersAndRegisters();

  // Provides access to JSGeneratorObject::function() field.
  static FieldAccess ForJSGeneratorObjectFunction();

  // Provides access to JSGeneratorObject::receiver() field.
  static FieldAccess ForJSGeneratorObjectReceiver();

  // Provides access to JSGeneratorObject::resume_mode() field.
  static FieldAccess ForJSGeneratorObjectResumeMode();

  // Provides access to JSAsyncFunctionObject::promise() field.
  static FieldAccess ForJSAsyncFunctionObjectPromise();

  // Provides access to JSAsyncGeneratorObject::queue() field.
  static FieldAccess ForJSAsyncGeneratorObjectQueue();

  // Provides access to JSAsyncGeneratorObject::is_awaiting() field.
  static FieldAccess ForJSAsyncGeneratorObjectIsAwaiting();

  // Provides access to JSArray::length() field.
  static FieldAccess ForJSArrayLength(ElementsKind elements_kind);

  // Provides access to JSArrayBuffer::bit_field() field.
  static FieldAccess ForJSArrayBufferBitField();

  // Provides access to JSArrayBuffer::byteLength() field.
  static FieldAccess ForJSArrayBufferByteLength();

  // Provides access to JSArrayBufferView::buffer() field.
  static FieldAccess ForJSArrayBufferViewBuffer();

  // Provides access to JSArrayBufferView::byteLength() field.
  static FieldAccess ForJSArrayBufferViewByteLength();

  // Provides access to JSArrayBufferView::byteOffset() field.
  static FieldAccess ForJSArrayBufferViewByteOffset();

  // Provides access to JSArrayBufferView::bitfield() field
  static FieldAccess ForJSArrayBufferViewBitField();

  // Provides access to JSTypedArray::length() field.
  static FieldAccess ForJSTypedArrayLength();

  // Provides access to JSTypedArray::byteLength() field.
  static FieldAccess ForJSTypedArrayByteLength() {
    return ForJSArrayBufferViewByteLength();
  }

  // Provides access to JSTypedArray::base_pointer() field.
  static FieldAccess ForJSTypedArrayBasePointer();

  // Provides access to JSTypedArray::external_pointer() field.
  static FieldAccess ForJSTypedArrayExternalPointer();

  // Provides access to JSDataView::data_pointer() field.
  static FieldAccess ForJSDataViewDataPointer();

  static FieldAccess ForJSDataViewByteLength() {
    return ForJSArrayBufferViewByteLength();
  }

  // Provides access to JSDate::value() field.
  static FieldAccess ForJSDateValue();

  // Provides access to JSDate fields.
  static FieldAccess ForJSDateField(JSDate::FieldIndex index);

  // Provides access to JSIteratorResult::done() field.
  static FieldAccess ForJSIteratorResultDone();

  // Provides access to JSIteratorResult::value() field.
  static FieldAccess ForJSIteratorResultValue();

  static FieldAccess ForJSPrimitiveWrapperValue();

  // Provides access to JSRegExp::data() field.
  static FieldAccess ForJSRegExpData();

  // Provides access to JSRegExp::flags() field.
  static FieldAccess ForJSRegExpFlags();

  // Provides access to JSRegExp::last_index() field.
  static FieldAccess ForJSRegExpLastIndex();

  // Provides access to JSRegExp::source() field.
  static FieldAccess ForJSRegExpSource();

  // Provides access to FixedArray::length() field.
  static FieldAccess ForFixedArrayLength();

  // Provides access to WeakFixedArray::length() field.
  static FieldAccess ForWeakFixedArrayLength();

  // Provides access to SloppyArgumentsElements::context() field.
  static FieldAccess ForSloppyArgumentsElementsContext();

  // Provides access to SloppyArgumentsElements::arguments() field.
  static FieldAccess ForSloppyArgumentsElementsArguments();

  // Provides access to PropertyArray::length() field.
  static FieldAccess ForPropertyArrayLengthAndHash();

  // Provides access to DescriptorArray::enum_cache() field.
  static FieldAccess ForDescriptorArrayEnumCache();

  // Provides access to Map::bit_field() byte.
  static FieldAccess ForMapBitField();

  // Provides access to Map::bit_field2() byte.
  static FieldAccess ForMapBitField2();

  // Provides access to Map::bit_field3() field.
  static FieldAccess ForMapBitField3();

  // Provides access to Map::descriptors() field.
  static FieldAccess ForMapDescriptors();

  // Provides access to Map::instance_type() field.
  static FieldAccess ForMapInstanceType();

  // Provides access to Map::prototype() field.
  static FieldAccess ForMapPrototype();

  // Provides access to Map::native_context() field.
  static FieldAccess ForMapNativeContext();

  // Provides access to Module::regular_exports() field.
  static FieldAccess ForModuleRegularExports();

  // Provides access to Module::regular_imports() field.
  static FieldAccess ForModuleRegularImports();

  // Provides access to Name::raw_hash_field() field.
  static FieldAccess ForNameRawHashField();

  // Provides access to FreeSpace::size() field
  static FieldAccess ForFreeSpaceSize();

  // Provides access to String::length() field.
  static FieldAccess ForStringLength();

  // Provides access to ConsString::first() field.
  static FieldAccess ForConsStringFirst();

  // Provides access to ConsString::second() field.
  static FieldAccess ForConsStringSecond();

  // Provides access to ThinString::actual() field.
  static FieldAccess ForThinStringActual();

  // Provides access to SlicedString::offset() field.
  static FieldAccess ForSlicedStringOffset();

  // Provides access to SlicedString::parent() field.
  static FieldAccess ForSlicedStringParent();

  // Provides access to ExternalString::resource_data() field.
  static FieldAccess ForExternalStringResourceData();

  // Provides access to SeqOneByteString characters.
  static ElementAccess ForSeqOneByteStringCharacter();

  // Provides access to SeqTwoByteString characters.
  static ElementAccess ForSeqTwoByteStringCharacter();

  // Provides access to JSArrayIterator::iterated_object() field.
  static FieldAccess ForJSArrayIteratorIteratedObject();

  // Provides access to JSArrayIterator::next_index() field.
  static FieldAccess ForJSArrayIteratorNextIndex();

  // Provides access to JSArrayIterator::kind() field.
  static FieldAccess ForJSArrayIteratorKind();

  // Provides access to JSStringIterator::string() field.
  static FieldAccess ForJSStringIteratorString();

  // Provides access to JSStringIterator::index() field.
  static FieldAccess ForJSStringIteratorIndex();

  // Provides access to Cell::value() field.
  static FieldAccess ForCellValue();

  // Provides access to arguments object fields.
  static FieldAccess ForArgumentsLength();
  static FieldAccess ForArgumentsCallee();

  // Provides access to FixedArray slots.
  static FieldAccess ForFixedArraySlot(
      size_t index, WriteBarrierKind write_barrier_kind = kFullWriteBarrier);

  static FieldAccess ForFeedbackVectorSlot(int index);

  // Provides access to PropertyArray slots.
  static FieldAccess ForPropertyArraySlot(int index);

  // Provides access to ScopeInfo flags.
  static FieldAccess ForScopeInfoFlags();

  // Provides access to Context slots.
  static FieldAccess ForContextSlot(size_t index);

  // Provides access to Context slots that are known to be pointers.
  static FieldAccess ForContextSlotKnownPointer(size_t index);

  // Provides access to Context slots that are known to be Smis.
  static FieldAccess ForContextSlotSmi(size_t index);

  // Provides access to WeakFixedArray elements.
  static ElementAccess ForWeakFixedArrayElement();
  static FieldAccess ForWeakFixedArraySlot(int index);

  // Provides access to FixedArray elements.
  static ElementAccess ForFixedArrayElement();
  static ElementAccess ForFixedArrayElement(ElementsKind kind);

  // Provides access to SloppyArgumentsElements elements.
  static ElementAccess ForSloppyArgumentsElementsMappedEntry();

  // Provides access to FixedDoubleArray elements.
  static ElementAccess ForFixedDoubleArrayElement();

  // Provides access to EnumCache::keys() field.
  static FieldAccess ForEnumCacheKeys();

  // Provides access to EnumCache::indices() field.
  static FieldAccess ForEnumCacheIndices();

  // Provides access to Fixed{type}TypedArray and External{type}Array elements.
  static ElementAccess ForTypedArrayElement(ExternalArrayType type,
                                            bool is_external);

  // Provides access to the for-in cache array.
  static ElementAccess ForJSForInCacheArrayElement(ForInMode mode);

  // Provides access to HashTable fields.
  static FieldAccess ForHashTableBaseNumberOfElements();
  static FieldAccess ForHashTableBaseNumberOfDeletedElement();
  static FieldAccess ForHashTableBaseCapacity();

  // Provides access to OrderedHashMapOrSet fields.
  static FieldAccess ForOrderedHashMapOrSetNextTable();
  static FieldAccess ForOrderedHashMapOrSetNumberOfBuckets();
  static FieldAccess ForOrderedHashMapOrSetNumberOfElements();
  static FieldAccess ForOrderedHashMapOrSetNumberOfDeletedElements();

  // Provides access to OrderedHashMap elements.
  static ElementAccess ForOrderedHashMapEntryValue();

  // Provides access to Dictionary fields.
  static FieldAccess ForDictionaryNextEnumerationIndex();
  static FieldAccess ForDictionaryObjectHashIndex();

  // Provides access to NameDictionary fields.
  static FieldAccess ForNameDictionaryFlagsIndex();

  // Provides access to FeedbackCell fields.
  static FieldAccess ForFeedbackCellInterruptBudget();
#ifdef V8_ENABLE_LEAPTIERING
  static FieldAccess ForFeedbackCellDispatchHandleNoWriteBarrier();
#endif  // V8_ENABLE_LEAPTIERING

  // Provides access to a FeedbackVector fields.
  static FieldAccess ForFeedbackVectorInvocationCount();
  static FieldAccess ForFeedbackVectorFlags();
  static FieldAccess ForFeedbackVectorClosureFeedbackCellArray();

#if V8_ENABLE_WEBASSEMBLY
  static FieldAccess ForWasmArrayLength();
  static FieldAccess ForWasmDispatchTableLength();
#endif

  static FieldAccess ForContextSideProperty();

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(AccessBuilder);
};

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_ACCESS_BUILDER_H_
```