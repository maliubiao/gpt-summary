Response:
Let's break down the thought process for analyzing this C++ header file and generating the summary.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to keywords like `class`, `template`, `namespace`, `#ifndef`, `#define`, and the included header files. This provides a general idea of the file's purpose.

* **Includes:**  The included headers suggest this file deals with low-level V8 internals, specifically object representation (`src/objects/*`). `v8-internal.h` confirms this.
* **Namespaces:** The code is within `namespace v8 { namespace internal { ... }`, indicating it's part of V8's internal implementation.
* **Class Structure:**  The code defines many classes with names ending in `BodyDescriptor`. This is a strong indicator of the file's core function.
* **Templates:**  The use of `template` suggests generic programming, likely for handling different types of objects.
* **Macros:** `#ifndef`, `#define` are standard C/C++ include guards.
* **Copyright:** The initial copyright notice confirms it's a V8 project file.

**2. Identifying the Core Functionality: `BodyDescriptor` Classes:**

The repeated pattern of classes named `Something::BodyDescriptor` is the most prominent feature. This immediately suggests that the file's main job is to define how to *describe* the "body" of various V8 objects. The methods within these classes, particularly `IterateBody` and `SizeOf`, reinforce this idea.

* **`IterateBody`:** This method clearly iterates through the "body" of an object, likely visiting or processing individual fields (pointers, data, etc.). The `ObjectVisitor` argument confirms this.
* **`SizeOf`:** This method calculates the size of the object's body.

**3. Analyzing `IterateBody` Implementations:**

Next, we examine the implementations of `IterateBody` within different `BodyDescriptor` classes. This reveals *how* the iteration is done for different object types.

* **`IteratePointers`:**  A common pattern is calling `IteratePointers`, suggesting the file is concerned with managing pointers within objects, potentially for garbage collection or memory management.
* **Specific Field Offsets:**  References to constants like `kPropertiesOrHashOffset`, `kCodeOffset`, etc., indicate that the iteration is based on the specific memory layout of each object type.
* **Specialized Iteration:**  Methods like `IterateCustomWeakPointer`, `IterateCodePointer`, `IterateExternalPointer`, and `IterateProtectedPointer` show that different types of pointers are handled differently, likely due to different garbage collection requirements or security implications.
* **Conditional Logic:**  The `JSObject::BodyDescriptor` implementation with `DCHECK_LE` and the handling of embedder fields demonstrates that the iteration logic can be conditional based on object properties.

**4. Connecting to V8 Object Types:**

The names of the `BodyDescriptor` classes directly correspond to V8 object types like `JSObject`, `JSArrayBuffer`, `JSFunction`, `HeapNumber`, etc. This confirms the file's role in describing the structure of these fundamental V8 entities.

**5. Inferring the Purpose of `BodyDescriptor`s:**

Based on the analysis of `IterateBody` and `SizeOf`, it becomes clear that `BodyDescriptor`s are used for tasks that need to understand the internal layout of V8 objects, such as:

* **Garbage Collection:**  Iterating through pointers is essential for marking live objects during garbage collection. The distinction between strong and weak pointers is crucial here.
* **Object Size Calculation:**  `SizeOf` is directly used for memory allocation and tracking.
* **Debugging and Inspection:**  Knowing the structure of objects is vital for debugging and introspection tools.
* **Serialization/Deserialization:**  Potentially for saving and restoring V8 object states.

**6. Addressing the Specific Questions:**

Now, we can address the specific questions in the prompt:

* **Functionality:** The core functionality is describing the layout and size of V8 objects' bodies for operations like garbage collection and size calculation.
* **`.tq` Extension:** The filename ends with `.inl.h`, not `.tq`. Therefore, it's not a Torque source file. Torque files usually have a `.tq` extension.
* **Relationship to JavaScript:**  While this is low-level C++, it directly relates to how JavaScript objects are represented in memory within the V8 engine. The examples provided in the initial prompt demonstrate this by showing how JavaScript concepts like arrays, functions, and objects map to these internal structures.
* **Code Logic Reasoning (Hypothetical Input/Output):** The `IterateBody` functions can be thought of as taking a `Map` (describing the object's type) and a `HeapObject` as input. The "output" is the traversal of the object's fields, potentially performing actions via the `ObjectVisitor`. Specific examples can be constructed by choosing a particular object type and outlining the sequence of `Visit...` calls.
* **Common Programming Errors:**  Incorrectly assuming object layouts, especially when dealing with inheritance or embedder fields, can lead to memory corruption or crashes if developers tried to manually manipulate V8 objects outside of the V8 API.
* **Summary:** Synthesize the main points gathered from the analysis.

**7. Iterative Refinement:**

Throughout this process, there's often some back-and-forth. For example, initially, one might focus too much on the template aspect. However, realizing the common naming pattern of `BodyDescriptor` and the core methods helps to refine the understanding of the file's primary purpose. Similarly, seeing the different `Iterate...` methods clarifies the specific types of data being handled within the object bodies.
好的，让我们来分析一下 V8 源代码文件 `v8/src/objects/objects-body-descriptors-inl.h` 的功能。

**文件功能归纳:**

`v8/src/objects/objects-body-descriptors-inl.h` 文件定义了**对象体描述符 (Body Descriptors)**，用于描述 V8 堆中各种类型对象的**内存布局**和如何**遍历**这些对象的内部字段。

**具体功能点:**

1. **定义对象体的遍历方式:**  该文件为不同的 V8 对象类型（例如 `JSObject`, `JSArrayBuffer`, `JSFunction` 等）定义了 `BodyDescriptor` 类。每个 `BodyDescriptor` 类都包含一个静态方法 `IterateBody`，该方法负责遍历特定类型对象的 body 部分的指针字段。

2. **提供对象体的大小信息:**  每个 `BodyDescriptor` 类通常还包含一个静态方法 `SizeOf`，用于计算特定类型对象的实例大小。

3. **区分不同类型的指针:**  文件中定义了多种遍历指针的方法，例如 `IteratePointers` (遍历普通指针), `IterateCustomWeakPointer` (遍历自定义弱指针), `IterateCodePointer` (遍历代码指针), `IterateExternalPointer` (遍历外部指针) 等。这反映了 V8 内部对不同类型指针的管理需求，例如垃圾回收时对强弱引用的处理，以及对代码对象和外部数据的特殊处理。

4. **处理内嵌对象 (Embedder Fields):** 代码中可以看到对内嵌对象的处理逻辑 (`IterateJSObjectBodyImpl`)，这允许 V8 的嵌入者 (例如 Chromium) 在 V8 对象中存储自己的数据。

5. **支持灵活大小的对象:**  `FlexibleBodyDescriptor` 和 `FlexibleWeakBodyDescriptor` 模板类表明 V8 支持具有运行时确定大小的对象。

6. **为特定对象类型提供优化的遍历方法:**  例如 `JSObject::FastBodyDescriptor` 提供了更快速的指针遍历方式，可能用于某些特定的优化场景。

**关于文件扩展名 `.tq`:**

您提供的代码片段的文件名是 `.inl.h`，这表明它是一个内联的头文件。如果文件名以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**文件。Torque 是一种 V8 使用的领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。

**与 JavaScript 功能的关系及示例:**

`objects-body-descriptors-inl.h` 文件虽然是 C++ 代码，但它直接关系到 JavaScript 对象在 V8 引擎内部的表示方式。  理解这一点对于理解 V8 的性能特性和内存管理至关重要。

**JavaScript 示例:**

```javascript
const obj = { a: 1, b: 'hello' };
const arr = [1, 2, 3];
const fn = function() {};
const buffer = new ArrayBuffer(10);
```

当你在 JavaScript 中创建这些对象时，V8 引擎会在堆上分配内存来存储它们。`objects-body-descriptors-inl.h` 中定义的 `BodyDescriptor` 就描述了这些对象在内存中的布局：

* **`obj` (普通对象):**  `JSObject::BodyDescriptor` 定义了如何遍历 `obj` 的属性（`a` 和 `b`）。V8 会追踪这些属性的值，并可能在需要时进行垃圾回收。
* **`arr` (数组):** 数组在 V8 内部也是一种特殊的对象。其 `BodyDescriptor` 定义了如何访问数组的元素。
* **`fn` (函数):** `JSFunction::BodyDescriptor` 描述了函数对象的结构，包括其关联的代码、作用域等信息。
* **`buffer` (ArrayBuffer):** `JSArrayBuffer::BodyDescriptor` 描述了 `ArrayBuffer` 对象的结构，包括其指向实际内存的指针。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `JSObject` 实例，其 `Map` 指示它有两个指针类型的 in-object 属性，偏移量分别为 `offset1` 和 `offset2`。

**假设输入:**

* `map`: 指向 `JSObject` 的 `Map` 对象，表示该对象有两个指针类型的 in-object 属性。
* `obj`: 指向该 `JSObject` 实例的指针。
* `start_offset`:  `JSObject::kPropertiesOrHashOffset` (假设从属性开始遍历)。
* `end_offset`:  根据对象大小计算出的属性结束偏移量。
* `v`: 一个 `ObjectVisitor` 实例，用于访问对象字段。

**代码逻辑 (简化版 `IterateBody` 中的 `IteratePointers` 调用):**

```c++
template <typename ObjectVisitor>
DISABLE_CFI_PERF void BodyDescriptorBase::IteratePointers(
    Tagged<HeapObject> obj, int start_offset, int end_offset,
    ObjectVisitor* v) {
  if (start_offset == HeapObject::kMapOffset) {
    v->VisitMapPointer(obj);
    start_offset += kTaggedSize;
  }
  v->VisitPointers(obj, obj->RawField(start_offset), obj->RawField(end_offset));
}
```

**输出:**

`ObjectVisitor` `v` 会执行以下操作：

1. 如果 `start_offset` 是 `HeapObject::kMapOffset`，则调用 `v->VisitMapPointer(obj)` 来访问对象的 `Map` 指针。
2. 调用 `v->VisitPointers(obj, obj->RawField(start_offset), obj->RawField(end_offset))`。 这意味着 `ObjectVisitor` 将被通知访问从 `start_offset` 到 `end_offset` 范围内的内存位置，这些位置存储着对象的属性值（指针）。  具体来说，`v` 可能会访问 `obj->RawField(offset1)` 和 `obj->RawField(offset2)` 指向的内存位置。

**涉及用户常见的编程错误 (与 JavaScript 交互相关):**

虽然用户通常不会直接操作 V8 的内部对象，但理解这些概念有助于避免一些与性能和内存管理相关的错误：

1. **过度创建对象:** 理解对象的大小和布局有助于理解创建大量小对象可能带来的内存开销。

2. **意外的内存泄漏:**  虽然 V8 有垃圾回收机制，但理解对象之间的引用关系（例如，闭包捕获的变量）有助于避免意外地保持对不再需要的对象的引用，导致内存泄漏。

3. **性能问题:**  理解 V8 如何访问对象属性有助于理解某些操作的性能影响。例如，频繁访问深层嵌套对象的属性可能比访问简单对象的属性更耗时。

**总结一下它的功能:**

`v8/src/objects/objects-body-descriptors-inl.h` 的主要功能是定义了 V8 引擎如何描述和操作堆中各种类型对象的内部结构。它为每种对象类型提供了遍历其内部指针字段和获取其大小的方法，这对于垃圾回收、调试以及 V8 引擎的整体运行至关重要。虽然这是一个底层的 C++ 文件，但它直接影响着 JavaScript 对象在 V8 中的表示和行为。

这是第 1 部分的分析。如果您有关于第 2 部分的内容，请随时提供！

Prompt: 
```
这是目录为v8/src/objects/objects-body-descriptors-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects-body-descriptors-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_OBJECTS_BODY_DESCRIPTORS_INL_H_
#define V8_OBJECTS_OBJECTS_BODY_DESCRIPTORS_INL_H_

#include <algorithm>

#include "include/v8-internal.h"
#include "src/base/logging.h"
#include "src/codegen/reloc-info.h"
#include "src/common/globals.h"
#include "src/heap/heap-layout-inl.h"
#include "src/ic/handler-configuration.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/bigint.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/call-site-info.h"
#include "src/objects/cell.h"
#include "src/objects/data-handler.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/fixed-array.h"
#include "src/objects/foreign-inl.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/hash-table.h"
#include "src/objects/heap-number.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "src/objects/js-collection.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/literal-objects.h"
#include "src/objects/megadom-handler-inl.h"
#include "src/objects/objects-body-descriptors.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/property-descriptor-object.h"
#include "src/objects/source-text-module.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/synthetic-module.h"
#include "src/objects/tagged-field.h"
#include "src/objects/template-objects-inl.h"
#include "src/objects/torque-defined-classes-inl.h"
#include "src/objects/transitions.h"
#include "src/objects/turbofan-types-inl.h"
#include "src/objects/turboshaft-types-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

template <int start_offset>
int FlexibleBodyDescriptor<start_offset>::SizeOf(Tagged<Map> map,
                                                 Tagged<HeapObject> object) {
  return object->SizeFromMap(map);
}

template <int start_offset>
int FlexibleWeakBodyDescriptor<start_offset>::SizeOf(
    Tagged<Map> map, Tagged<HeapObject> object) {
  return object->SizeFromMap(map);
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateJSObjectBodyImpl(Tagged<Map> map,
                                                 Tagged<HeapObject> obj,
                                                 int start_offset,
                                                 int end_offset,
                                                 ObjectVisitor* v) {
#ifdef V8_COMPRESS_POINTERS
  static_assert(kEmbedderDataSlotSize == 2 * kTaggedSize);
  int header_end_offset = JSObject::GetHeaderSize(map);
  int inobject_fields_start_offset = map->GetInObjectPropertyOffset(0);
  // We are always requested to process header and embedder fields.
  DCHECK_LE(inobject_fields_start_offset, end_offset);
  // Embedder fields are located between header and inobject properties.
  if (header_end_offset < inobject_fields_start_offset) {
    // There are embedder fields.
    DCHECK_EQ(header_end_offset, JSObject::GetEmbedderFieldsStartOffset(map));
    IteratePointers(obj, start_offset, header_end_offset, v);
    for (int offset = header_end_offset; offset < inobject_fields_start_offset;
         offset += kEmbedderDataSlotSize) {
      IteratePointer(obj, offset + EmbedderDataSlot::kTaggedPayloadOffset, v);
      v->VisitExternalPointer(
          obj, obj->RawExternalPointerField(
                   offset + EmbedderDataSlot::kExternalPointerOffset,
                   kEmbedderDataSlotPayloadTag));
    }
    // Proceed processing inobject properties.
    start_offset = inobject_fields_start_offset;
  }
#else
  // We store raw aligned pointers as Smis, so it's safe to iterate the whole
  // embedder field area as tagged slots.
  static_assert(kEmbedderDataSlotSize == kTaggedSize);
#endif
  IteratePointers(obj, start_offset, end_offset, v);
}

template <typename ObjectVisitor>
// static
void BodyDescriptorBase::IterateJSObjectBodyWithoutEmbedderFieldsImpl(
    Tagged<Map> map, Tagged<HeapObject> obj, int start_offset, int end_offset,
    ObjectVisitor* v) {
  // This body iteration assumes that there's no embedder fields.
  DCHECK_IMPLIES(JSObject::MayHaveEmbedderFields(map),
                 UncheckedCast<JSObject>(obj)->GetEmbedderFieldCount() == 0);
  IteratePointers(obj, start_offset, end_offset, v);
}

// This is a BodyDescriptor helper for usage within JSAPIObjectWithEmbedderSlots
// and JSSpecialObject. The class hierarchies are separate but
// `kCppHeapWrappableOffset` is the same for both.
class JSAPIObjectWithEmbedderSlotsOrJSSpecialObjectBodyDescriptor
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateJSAPIObjectWithEmbedderSlotsHeader(
      Tagged<Map> map, Tagged<HeapObject> obj, int object_size,
      ObjectVisitor* v) {
    // Visit JSObject header.
    IteratePointers(obj, JSObject::kPropertiesOrHashOffset,
                    JSObject::kEndOfStrongFieldsOffset, v);

    // Visit JSAPIObjectWithEmbedderSlots or JSSpecialObject header.
    static_assert(JSObject::kEndOfStrongFieldsOffset ==
                  JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
    static_assert(JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset ==
                  JSSpecialObject::kCppHeapWrappableOffset);
    static_assert(JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffsetEnd +
                      1 ==
                  JSAPIObjectWithEmbedderSlots::kHeaderSize);
    v->VisitCppHeapPointer(
        obj, obj->RawCppHeapPointerField(
                 JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset));
  }

  template <typename ConcreteType, typename ObjectVisitor>
  static inline void IterateJSAPIObjectWithEmbedderSlotsTail(
      Tagged<Map> map, Tagged<HeapObject> obj, int object_size,
      ObjectVisitor* v) {
    // Visit the tail of JSObject with possible embedder fields and in-object
    // properties. Note that embedder fields are processed in the JSObject base
    // class as there's other object hierarchies that contain embedder fields as
    // well.
    IterateJSObjectBodyImpl(map, obj, ConcreteType::kHeaderSize, object_size,
                            v);
  }

  template <typename ConcreteType, typename ObjectVisitor>
  static inline void IterateJSAPIObjectWithoutEmbedderSlotsTail(
      Tagged<Map> map, Tagged<HeapObject> obj, int object_size,
      ObjectVisitor* v) {
    IterateJSObjectBodyWithoutEmbedderFieldsImpl(
        map, obj, ConcreteType::kHeaderSize, object_size, v);
  }

  static constexpr int kHeaderSize = JSSpecialObject::kHeaderSize;

  static_assert(JSAPIObjectWithEmbedderSlots::kHeaderSize ==
                JSSpecialObject::kHeaderSize);
  static_assert(Internals::kJSAPIObjectWithEmbedderSlotsHeaderSize ==
                JSSpecialObject::kHeaderSize);
};

class JSAPIObjectWithEmbedderSlots::BodyDescriptor
    : public JSAPIObjectWithEmbedderSlotsOrJSSpecialObjectBodyDescriptor {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateJSAPIObjectWithEmbedderSlotsHeader(map, obj, object_size, v);
    IterateJSAPIObjectWithEmbedderSlotsTail<
        JSAPIObjectWithEmbedderSlotsOrJSSpecialObjectBodyDescriptor>(
        map, obj, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

template <typename ObjectVisitor>
DISABLE_CFI_PERF void BodyDescriptorBase::IteratePointers(
    Tagged<HeapObject> obj, int start_offset, int end_offset,
    ObjectVisitor* v) {
  if (start_offset == HeapObject::kMapOffset) {
    v->VisitMapPointer(obj);
    start_offset += kTaggedSize;
  }
  v->VisitPointers(obj, obj->RawField(start_offset), obj->RawField(end_offset));
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IteratePointer(Tagged<HeapObject> obj, int offset,
                                        ObjectVisitor* v) {
  DCHECK_NE(offset, HeapObject::kMapOffset);
  v->VisitPointer(obj, obj->RawField(offset));
}

template <typename ObjectVisitor>
DISABLE_CFI_PERF void BodyDescriptorBase::IterateMaybeWeakPointers(
    Tagged<HeapObject> obj, int start_offset, int end_offset,
    ObjectVisitor* v) {
  v->VisitPointers(obj, obj->RawMaybeWeakField(start_offset),
                   obj->RawMaybeWeakField(end_offset));
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateMaybeWeakPointer(Tagged<HeapObject> obj,
                                                 int offset, ObjectVisitor* v) {
  DCHECK_NE(offset, HeapObject::kMapOffset);
  v->VisitPointer(obj, obj->RawMaybeWeakField(offset));
}

template <typename ObjectVisitor>
DISABLE_CFI_PERF void BodyDescriptorBase::IterateCustomWeakPointers(
    Tagged<HeapObject> obj, int start_offset, int end_offset,
    ObjectVisitor* v) {
  v->VisitCustomWeakPointers(obj, obj->RawField(start_offset),
                             obj->RawField(end_offset));
}

template <typename ObjectVisitor>
DISABLE_CFI_PERF void BodyDescriptorBase::IterateEphemeron(
    Tagged<HeapObject> obj, int index, int key_offset, int value_offset,
    ObjectVisitor* v) {
  v->VisitEphemeron(obj, index, obj->RawField(key_offset),
                    obj->RawField(value_offset));
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateCustomWeakPointer(Tagged<HeapObject> obj,
                                                  int offset,
                                                  ObjectVisitor* v) {
  v->VisitCustomWeakPointer(obj, obj->RawField(offset));
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateTrustedPointer(Tagged<HeapObject> obj,
                                               int offset, ObjectVisitor* v,
                                               IndirectPointerMode mode,
                                               IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  v->VisitIndirectPointer(obj, obj->RawIndirectPointerField(offset, tag), mode);
#else
  if (mode == IndirectPointerMode::kStrong) {
    IteratePointer(obj, offset, v);
  } else {
    IterateCustomWeakPointer(obj, offset, v);
  }
#endif
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateCodePointer(Tagged<HeapObject> obj, int offset,
                                            ObjectVisitor* v,
                                            IndirectPointerMode mode) {
  IterateTrustedPointer(obj, offset, v, mode, kCodeIndirectPointerTag);
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateSelfIndirectPointer(Tagged<HeapObject> obj,
                                                    IndirectPointerTag tag,
                                                    ObjectVisitor* v) {
#ifdef V8_ENABLE_SANDBOX
  v->VisitTrustedPointerTableEntry(
      obj, obj->RawIndirectPointerField(
               ExposedTrustedObject::kSelfIndirectPointerOffset, tag));
#endif
}

template <typename ObjectVisitor>
void BodyDescriptorBase::IterateProtectedPointer(Tagged<HeapObject> obj,
                                                 int offset, ObjectVisitor* v) {
  DCHECK(IsTrustedObject(obj));
  Tagged<TrustedObject> host = Cast<TrustedObject>(obj);
  v->VisitProtectedPointer(host, host->RawProtectedPointerField(offset));
}

#ifdef V8_ENABLE_LEAPTIERING
template <typename ObjectVisitor>
void BodyDescriptorBase::IterateJSDispatchEntry(Tagged<HeapObject> obj,
                                                int offset, ObjectVisitor* v) {
  JSDispatchHandle handle = obj->Relaxed_ReadField<JSDispatchHandle>(offset);
  v->VisitJSDispatchTableEntry(obj, handle);
}
#endif  // V8_ENABLE_LEAPTIERING

class HeapNumber::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static constexpr int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return sizeof(HeapNumber);
  }
};

// This is a descriptor for one/two pointer fillers.
class FreeSpaceFillerBodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return map->instance_size();
  }
};

class FreeSpace::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<FreeSpace>(raw_object)->Size();
  }
};

class JSObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  static const int kStartOffset = JSReceiver::kPropertiesOrHashOffset;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateJSObjectBodyImpl(map, obj, kStartOffset, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSObject::FastBodyDescriptor final : public BodyDescriptorBase {
 public:
  static const int kStartOffset = JSReceiver::kPropertiesOrHashOffset;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, kStartOffset, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSDate::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSObject::BodyDescriptor::kStartOffset,
                    JSDate::kValueOffset, v);
    IterateJSObjectBodyImpl(map, obj, JSDate::kStartOfStrongFieldsOffset,
                            object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSRegExp::BodyDescriptor final : public BodyDescriptorBase {
 public:
  static const int kStartOffset = JSReceiver::kPropertiesOrHashOffset;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, kPropertiesOrHashOffset, JSObject::kHeaderSize, v);
    IterateTrustedPointer(obj, kDataOffset, v, IndirectPointerMode::kStrong,
                          kRegExpDataIndirectPointerTag);
    IteratePointer(obj, kSourceOffset, v);
    IterateJSObjectBodyImpl(map, obj, kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class RegExpData::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // If new pointers are added to RegExpData, make sure to also add them to
    // the subclasses descriptors (AtomRegExpData and IrRegExpData).
    // We don't directly call the base class IterateBody, as in the future
    // the subclasses will have a different indirect pointer tag from the base
    // class (once inheritance hierarchies are supported for indirect pointer
    // tags).
    IterateSelfIndirectPointer(obj, kRegExpDataIndirectPointerTag, v);
    IteratePointer(obj, kSourceOffset, v);
    IteratePointer(obj, kWrapperOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return kSize;
  }
};

class AtomRegExpData::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kRegExpDataIndirectPointerTag, v);

    IteratePointer(obj, kSourceOffset, v);
    IteratePointer(obj, kWrapperOffset, v);

    IteratePointer(obj, kPatternOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return kSize;
  }
};

class IrRegExpData::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kRegExpDataIndirectPointerTag, v);

    IteratePointer(obj, kSourceOffset, v);
    IteratePointer(obj, kWrapperOffset, v);

    IterateProtectedPointer(obj, kLatin1BytecodeOffset, v);
    IterateProtectedPointer(obj, kUc16BytecodeOffset, v);
    IterateCodePointer(obj, kLatin1CodeOffset, v, IndirectPointerMode::kStrong);
    IterateCodePointer(obj, kUc16CodeOffset, v, IndirectPointerMode::kStrong);
    IteratePointer(obj, kCaptureNameMapOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return kSize;
  }
};

class RegExpDataWrapper::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateTrustedPointer(obj, kDataOffset, v, IndirectPointerMode::kStrong,
                          kRegExpDataIndirectPointerTag);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return kSize;
  }
};

class WeakCell::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, HeapObject::kHeaderSize, kTargetOffset, v);
    IterateCustomWeakPointer(obj, kTargetOffset, v);
    IterateCustomWeakPointer(obj, kUnregisterTokenOffset, v);
    IteratePointers(obj, kUnregisterTokenOffset + kTaggedSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSWeakRef::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSReceiver::kPropertiesOrHashOffset, kTargetOffset, v);
    IterateCustomWeakPointer(obj, kTargetOffset, v);
    IterateJSObjectBodyImpl(map, obj, kTargetOffset + kTaggedSize, object_size,
                            v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSFinalizationRegistry::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSObject::BodyDescriptor::kStartOffset,
                    kNextDirtyOffset, v);
    IterateCustomWeakPointer(obj, kNextDirtyOffset, v);
    IterateJSObjectBodyImpl(map, obj, kNextDirtyOffset + kTaggedSize,
                            object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class AllocationSite::BodyDescriptor final : public BodyDescriptorBase {
 public:
  static_assert(AllocationSite::kCommonPointerFieldEndOffset ==
                AllocationSite::kPretenureDataOffset);
  static_assert(AllocationSite::kPretenureDataOffset + kInt32Size ==
                AllocationSite::kPretenureCreateCountOffset);
  static_assert(AllocationSite::kPretenureCreateCountOffset + kInt32Size ==
                AllocationSite::kWeakNextOffset);

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // Iterate over all the common pointer fields
    IteratePointers(obj, AllocationSite::kStartOffset,
                    AllocationSite::kCommonPointerFieldEndOffset, v);
    // Skip PretenureDataOffset and PretenureCreateCount which are Int32 fields.
    // Visit weak_next only if it has weak_next field.
    if (object_size == AllocationSite::kSizeWithWeakNext) {
      IterateCustomWeakPointers(obj, AllocationSite::kWeakNextOffset,
                                AllocationSite::kSizeWithWeakNext, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSFunction::BodyDescriptor final : public BodyDescriptorBase {
 public:
  static const int kStartOffset = JSObject::BodyDescriptor::kStartOffset;
#ifdef V8_ENABLE_LEAPTIERING
  static const int kCodeFieldOffset = JSFunction::kDispatchHandleOffset;
#else
  static const int kCodeFieldOffset = JSFunction::kCodeOffset;
#endif

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // Iterate JSFunction header fields first.
    int header_size = JSFunction::GetHeaderSize(map->has_prototype_slot());
    DCHECK_GE(object_size, header_size);
    IteratePointers(obj, kStartOffset, kCodeFieldOffset, v);

#ifdef V8_ENABLE_LEAPTIERING
    IterateJSDispatchEntry(obj, kDispatchHandleOffset, v);
#else
    // The code field is treated as a custom weak pointer. This field
    // is visited as a weak pointer if the Code is baseline code
    // and the bytecode array corresponding to this function is old. In the rest
    // of the cases this field is treated as strong pointer.
    // See MarkingVisitorBase::VisitJSFunction.
    IterateCodePointer(obj, kCodeOffset, v, IndirectPointerMode::kCustom);
    DCHECK_GE(header_size, kCodeOffset);
#endif  // V8_ENABLE_LEAPTIERING

    // Iterate rest of the header fields
    IteratePointers(obj, kCodeFieldOffset + kTaggedSize, header_size, v);
    // Iterate rest of the fields starting after the header.
    IterateJSObjectBodyImpl(map, obj, header_size, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSArrayBuffer::BodyDescriptor final
    : public JSAPIObjectWithEmbedderSlots::BodyDescriptor {
 public:
  using Base = JSAPIObjectWithEmbedderSlots::BodyDescriptor;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // JSObject with wrapper field.
    IterateJSAPIObjectWithEmbedderSlotsHeader(map, obj, object_size, v);
    // JSArrayBuffer.
    IteratePointers(obj, JSArrayBuffer::kStartOfStrongFieldsOffset,
                    JSArrayBuffer::kEndOfStrongFieldsOffset, v);
    v->VisitExternalPointer(
        obj, obj->RawExternalPointerField(JSArrayBuffer::kExtensionOffset,
                                          kArrayBufferExtensionTag));
    // JSObject tail: possible embedder fields + in-object properties.
    if constexpr (JSArrayBuffer::kContainsEmbedderFields) {
      IterateJSAPIObjectWithEmbedderSlotsTail<JSArrayBuffer>(map, obj,
                                                             object_size, v);
    } else {
      IterateJSAPIObjectWithoutEmbedderSlotsTail<JSArrayBuffer>(map, obj,
                                                                object_size, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSArrayBufferView::BodyDescriptor
    : public JSAPIObjectWithEmbedderSlots::BodyDescriptor {
 public:
  using Base = JSAPIObjectWithEmbedderSlots::BodyDescriptor;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // JSObject with wrapper field.
    IterateJSAPIObjectWithEmbedderSlotsHeader(map, obj, object_size, v);
    // JSArrayBufferView.
    IteratePointers(obj, JSArrayBufferView::kStartOfStrongFieldsOffset,
                    JSArrayBufferView::kEndOfStrongFieldsOffset, v);
  }
};

class JSTypedArray::BodyDescriptor : public JSArrayBufferView::BodyDescriptor {
 public:
  using Base = JSArrayBufferView::BodyDescriptor;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // JSArrayBufferView (including JSObject).
    Base::IterateBody(map, obj, object_size, v);
    // JSTypedArray.
    IteratePointers(obj, JSTypedArray::kStartOfStrongFieldsOffset,
                    JSTypedArray::kEndOfStrongFieldsOffset, v);

    // JSObject tail: possible embedder fields + in-object properties.
    if constexpr (JSTypedArray::kContainsEmbedderFields) {
      IterateJSAPIObjectWithEmbedderSlotsTail<JSTypedArray>(map, obj,
                                                            object_size, v);
    } else {
      IterateJSAPIObjectWithoutEmbedderSlotsTail<JSTypedArray>(map, obj,
                                                               object_size, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSDataViewOrRabGsabDataView::BodyDescriptor final
    : public JSArrayBufferView::BodyDescriptor {
 public:
  using Base = JSArrayBufferView::BodyDescriptor;

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // JSArrayBufferView (including JSObject).
    Base::IterateBody(map, obj, object_size, v);
    // JSDataViewOrRabGsabDataView.
    IteratePointers(obj,
                    JSDataViewOrRabGsabDataView::kStartOfStrongFieldsOffset,
                    JSDataViewOrRabGsabDataView::kEndOfStrongFieldsOffset, v);
    // JSObject tail: possible embedder fields + in-object properties.
    if constexpr (JSDataViewOrRabGsabDataView::kContainsEmbedderFields) {
      IterateJSAPIObjectWithEmbedderSlotsTail<JSDataViewOrRabGsabDataView>(
          map, obj, object_size, v);
    } else {
      IterateJSAPIObjectWithoutEmbedderSlotsTail<JSDataViewOrRabGsabDataView>(
          map, obj, object_size, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSExternalObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    DCHECK_EQ(0, map->GetInObjectProperties());
    IteratePointers(obj, kPropertiesOrHashOffset, kEndOfTaggedFieldsOffset, v);
    v->VisitExternalPointer(obj, obj->RawExternalPointerField(
                                     kValueOffset, kExternalObjectValueTag));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

template <typename Derived>
class V8_EXPORT_PRIVATE SmallOrderedHashTable<Derived>::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    Tagged<Derived> table = Cast<Derived>(obj);
    int start_offset = DataTableStartOffset();
    int end_offset = table->GetBucketsStartOffset();
    IteratePointers(obj, start_offset, end_offset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    Tagged<Derived> table = Cast<Derived>(obj);
    return Derived::SizeFor(table->Capacity());
  }
};

class V8_EXPORT_PRIVATE SwissNameDictionary::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    Tagged<SwissNameDictionary> table = UncheckedCast<SwissNameDictionary>(obj);
    static_assert(MetaTablePointerOffset() + kTaggedSize ==
                  DataTableStartOffset());
    int start_offset = MetaTablePointerOffset();
    int end_offset = table->DataTableEndOffset(table->Capacity());
    IteratePointers(obj, start_offset, end_offset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    Tagged<SwissNameDictionary> table = UncheckedCast<SwissNameDictionary>(obj);
    return SwissNameDictionary::SizeFor(table->Capacity());
  }
};

class ByteArray::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return UncheckedCast<ByteArray>(obj)->AllocatedSize();
  }
};

class TrustedByteArray::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return UncheckedCast<TrustedByteArray>(obj)->AllocatedSize();
  }
};

class BytecodeArray::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kBytecodeArrayIndirectPointerTag, v);
    IteratePointer(obj, kWrapperOffset, v);
    IterateProtectedPointer(obj, kSourcePositionTableOffset, v);
    IterateProtectedPointer(obj, kHandlerTableOffset, v);
    IterateProtectedPointer(obj, kConstantPoolOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return BytecodeArray::SizeFor(
        Cast<BytecodeArray>(obj)->length(kAcquireLoad));
  }
};

class BytecodeWrapper::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateTrustedPointer(obj, kBytecodeOffset, v, IndirectPointerMode::kStrong,
                          kBytecodeArrayIndirectPointerTag);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return kSize;
  }
};

class BigInt::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return BigInt::SizeFor(UncheckedCast<BigInt>(obj)->length(kAcquireLoad));
  }
};

class FixedDoubleArray::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return UncheckedCast<FixedDoubleArray>(obj)->AllocatedSize();
  }
};

class FeedbackMetadata::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return UncheckedCast<FeedbackMetadata>(obj)->AllocatedSize();
  }
};

class PreparseData::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    Tagged<PreparseData> data = UncheckedCast<PreparseData>(obj);
    int start_offset = data->inner_start_offset();
    int end_offset = start_offset + data->children_length() * kTaggedSize;
    IteratePointers(obj, start_offset, end_offset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    Tagged<PreparseData> data = UncheckedCast<PreparseData>(obj);
    return PreparseData::SizeFor(data->data_length(), data->children_length());
  }
};

class InterpreterData::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kInterpreterDataIndirectPoin
"""


```