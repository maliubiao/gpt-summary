Response:
Let's break down the thought process for analyzing this V8 header file and generating the response.

**1. Understanding the Core Purpose:**

The file name `objects-body-descriptors-inl.h` immediately suggests that it's about *describing the bodies of objects*. The `.inl` extension signifies that it's an inline header file, likely containing implementation details meant to be included in other compilation units.

**2. Identifying the Key Structure: `BodyDescriptor`**

A quick scan of the code reveals the recurring pattern of classes named `Something::BodyDescriptor`. This strongly suggests a common pattern or interface. The base class `BodyDescriptorBase` confirms this. The presence of a static `IterateBody` function within each of these nested classes reinforces the idea that these descriptors are used to process the internal structure (the "body") of different V8 object types.

**3. Deconstructing `IterateBody`:**

The `IterateBody` function is the core of each descriptor. Its signature `template <typename ObjectVisitor> static inline void IterateBody(...)`  tells us:

* **Template:** It's generic and can work with different types of "visitors."
* **Static Inline:**  Optimized for direct inclusion and performance.
* **Void Return:**  It performs an action, likely iterating through the object's fields.
* **Arguments:**
    * `Tagged<Map> map`: The object's map, which describes its layout and type.
    * `Tagged<HeapObject> obj`: The actual object being described.
    * `int object_size`: The size of the object in memory.
    * `ObjectVisitor* v`:  The object visitor, responsible for processing each field.

The various `Iterate...` helper functions within `IterateBody` (e.g., `IteratePointer`, `IterateTrustedPointer`, `IterateProtectedPointer`, `IterateSelfIndirectPointer`)  indicate different ways of accessing and interpreting the data within the object's body. These likely correspond to different pointer types and memory management strategies within V8.

**4. Recognizing Object Types:**

The class names enclosing the `BodyDescriptor` (e.g., `JSFunction`, `BytecodeArray`, `SharedFunctionInfo`, `Map`) are names of well-known V8 internal object types. This confirms the initial hypothesis that the file is defining how to traverse and understand the layout of various V8 objects.

**5. Inferring Functionality:**

Based on the structure and the names, the primary function of this file is to provide a mechanism for iterating over the internal fields of V8 heap objects. This is crucial for:

* **Garbage Collection:** The garbage collector needs to traverse all reachable objects and their pointers.
* **Debugging and Inspection:** Tools like debuggers need to understand object layouts to display their contents.
* **Serialization/Deserialization:**  Persisting and restoring V8 heap objects requires knowing their structure.
* **Optimization and Analysis:**  Understanding object layouts is essential for optimizing memory usage and performance.

**6. Addressing Specific Instructions:**

* **`.tq` extension:**  The code itself is C++, not Torque. The instruction is a conditional statement, so the analysis needs to acknowledge this.
* **Relationship to JavaScript:** Since V8 *is* the JavaScript engine, all its internal structures are fundamentally related to JavaScript execution. The examples provided in the response link the described objects (like functions, bytecode, scopes) to their corresponding JavaScript concepts.
* **Code Logic and Examples:** The `IterateBody` functions contain the core logic. The explanation focuses on the *purpose* of iteration rather than simulating specific input/output of a visitor. The example provided for `JSFunction` demonstrates how the described fields (context, code, etc.) are used in JavaScript.
* **Common Programming Errors:**  The main point here is the potential for *memory corruption* if the iteration logic is incorrect or if assumptions about object layouts change. The example emphasizes the dangers of manual memory management that V8 handles internally.

**7. Synthesizing the Summary:**

The summary should concisely capture the key takeaways: the purpose of describing object layouts, the role of `IterateBody`, the usage by garbage collection and other internal V8 components, and the absence of Torque.

**Underlying Assumptions and Heuristics:**

* **Familiarity with V8 Internals (to some extent):**  Knowing the names of common V8 objects like `JSFunction`, `BytecodeArray`, `Map` is helpful.
* **Understanding of C++ Templates and Inline Functions:** Crucial for interpreting the `IterateBody` signature.
* **Knowledge of Garbage Collection Concepts:**  Essential for understanding why iterating through object pointers is important.
* **Pattern Recognition:** Identifying the recurring `::BodyDescriptor` pattern is key to understanding the file's structure.
* **Deductive Reasoning:**  Connecting the file name, the class names, and the function signatures to infer the overall purpose.

**Self-Correction/Refinement:**

Initially, one might focus too much on the individual `Iterate...` functions. However, realizing that these are helper functions *within* the `IterateBody` method and that `IterateBody` is the central point of each descriptor provides a more accurate understanding. Also, remembering that this is an *internal* V8 header file clarifies that it's not directly used in typical JavaScript development.
好的，这是对 `v8/src/objects/objects-body-descriptors-inl.h` 文件功能的归纳：

**功能概览**

`v8/src/objects/objects-body-descriptors-inl.h` 文件定义了 V8 堆中各种不同类型对象的“BodyDescriptor”。这些描述符的核心作用是提供一种机制，让 V8 引擎能够遍历和访问这些对象的内部字段，特别是用于垃圾回收（GC）等需要扫描堆内存的操作。

**详细功能分解**

1. **对象布局描述:**  为每一种需要特殊处理的堆对象类型（例如 `JSFunction`, `BytecodeArray`, `Map` 等）都定义了一个内部静态类 `BodyDescriptor`。这个类指定了如何遍历该类型对象的内部指针和数据。

2. **垃圾回收支持:**  最核心的功能是为垃圾回收器提供对象内部结构的元数据。通过 `IterateBody` 模板函数，垃圾回收器可以访问对象中所有需要追踪的指针（指向其他堆对象的引用）。

3. **`IterateBody` 模板函数:**  每个 `BodyDescriptor` 都包含一个静态的 `IterateBody` 函数模板。这个函数接受一个 `ObjectVisitor` 类型的参数。`ObjectVisitor` 是一个抽象类或函数对象，定义了对遍历到的指针进行操作的方法（例如标记为可达，更新指针等）。

4. **不同类型的指针迭代:** 文件中定义了多种 `Iterate...` 辅助函数，用于处理不同类型的指针：
    * `IteratePointer`: 迭代普通的堆对象指针。
    * `IterateTrustedPointer`: 迭代已知有效的堆对象指针。
    * `IterateProtectedPointer`: 迭代受保护的指针，可能需要特殊处理。
    * `IterateSelfIndirectPointer`: 迭代指向对象自身的间接指针。
    * `IterateMaybeWeakPointer`, `IterateCustomWeakPointers`: 处理弱引用。
    * `IterateCodePointer`, `VisitInstructionStreamPointer`: 处理代码对象和指令流。
    * `IterateEphemeron`: 处理弱哈希表中的键值对。
    * `IterateJSObjectBodyImpl`: 用于迭代 JS 对象的属性。

5. **`SizeOf` 函数:**  每个 `BodyDescriptor` 通常还包含一个静态的 `SizeOf` 函数，用于返回该类型对象的大小。有些情况下，对象的大小是固定的，有些情况下则需要根据 `Map` 或对象自身的信息来动态计算。

**关于 .tq 扩展名**

正如你提到的，如果 `v8/src/objects/objects-body-descriptors-inl.h` 以 `.tq` 结尾，那么它将是一个 Torque 源代码文件。Torque 是 V8 用来生成 C++ 代码的领域特定语言。然而，当前的这个文件是以 `.h` 结尾，所以它是直接编写的 C++ 代码。

**与 JavaScript 的关系**

`v8/src/objects/objects-body-descriptors-inl.h` 文件是 V8 引擎内部实现的关键部分，直接关系到 JavaScript 的执行和内存管理。它描述了 V8 如何在底层表示和处理 JavaScript 中的各种概念，例如：

* **函数 (`JSFunction`, `SharedFunctionInfo`):**  描述了函数对象的内部结构，包括指向其代码、作用域、上下文等的指针。
* **数组 (`FixedArray`, `WeakFixedArray`):**  描述了数组对象的内部结构，包括存储元素的区域。
* **对象 (`JSObject` 及各种子类):**  虽然 `JSObject` 本身的 `BodyDescriptor` 可能在其他地方定义（因为它更通用），但这个文件定义了许多特定类型 JS 对象的结构。
* **代码 (`Code`, `BytecodeArray`):**  描述了编译后的代码和字节码的内部结构。
* **作用域 (`ScopeInfo`):** 虽然没直接列出，但这里描述的其他对象（如 `SharedFunctionInfo`)  会间接地关联到作用域。

**JavaScript 示例**

```javascript
function myFunction(a, b) {
  console.log(a + b);
}

const myArray = [1, 2, 3];

const myObject = { x: 10, y: 20 };
```

在 V8 的内部，`myFunction`、`myArray` 和 `myObject` 将会以不同的堆对象表示，而 `objects-body-descriptors-inl.h` 中定义的 `BodyDescriptor` 就描述了这些对象在内存中的布局，使得 V8 能够有效地管理它们，例如：

* 当垃圾回收器运行时，它会使用这些描述符来遍历 `myFunction` 对象，找到它引用的代码对象和作用域对象。
* 当访问 `myArray[0]` 时，V8 需要知道 `FixedArray` 的内部结构才能找到存储元素的位置。
* 当访问 `myObject.x` 时，V8 需要知道 `JSObject` 的属性存储方式。

**代码逻辑推理（假设输入与输出）**

假设我们有一个 `JSFunction` 对象 `func`。 当垃圾回收器调用 `JSFunction::BodyDescriptor::IterateBody` 时，输入可能是：

* `map`: 指向 `func` 的 `Map` 对象的指针，描述了 `JSFunction` 的类型和布局。
* `obj`: 指向 `func` 自身的指针（类型为 `Tagged<HeapObject>`）。
* `object_size`: `func` 对象的大小。
* `v`:  一个具体的 `ObjectVisitor` 实现，例如垃圾回收器的标记阶段。

`IterateBody` 函数内部会根据 `JSFunction` 的布局，调用诸如 `IteratePointer(obj, kContextOffset, v)` 和 `IterateTrustedPointer(obj, kCodeOffset, v, ...)` 这样的函数。

**输出:** `ObjectVisitor` 会根据遍历到的指针执行相应的操作。例如，如果 `v` 是垃圾回收器的标记访问器，它会将 `func` 引用的上下文对象和代码对象标记为可达。

**用户常见的编程错误（间接相关）**

这个头文件是 V8 内部实现，普通 JavaScript 开发者不会直接与之交互。但是，理解其背后的概念可以帮助理解一些与内存和性能相关的常见错误：

1. **创建大量临时对象:**  过多的临时对象会导致频繁的垃圾回收，而垃圾回收器正是依赖于像 `objects-body-descriptors-inl.h` 中定义的机制来工作。
2. **内存泄漏 (在 Native 代码中):** 如果编写 V8 扩展或 Node.js 原生模块时，没有正确地管理对象的生命周期，可能会导致内存泄漏，而 V8 的垃圾回收机制旨在避免这种情况。
3. **性能问题:**  理解对象布局和垃圾回收的原理，可以帮助开发者编写更高效的 JavaScript 代码，减少不必要的对象创建和内存分配。

**总结它的功能 (第 2 部分)**

总而言之，`v8/src/objects/objects-body-descriptors-inl.h` 是 V8 引擎中一个至关重要的基础设施文件。它：

* **定义了 V8 堆中各种对象类型的内部结构描述符 (`BodyDescriptor`)。**
* **主要用于支持垃圾回收器遍历和标记堆对象中的引用。**
* **通过 `IterateBody` 模板函数和各种 `Iterate...` 辅助函数实现对不同类型指针的访问。**
* **间接地关系到 JavaScript 的执行和内存管理，因为它描述了 JavaScript 概念在 V8 底层的表示。**

这个文件是 V8 引擎实现其内存管理和垃圾回收策略的核心组成部分，对于保证 JavaScript 代码的正确执行和性能至关重要。

Prompt: 
```
这是目录为v8/src/objects/objects-body-descriptors-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects-body-descriptors-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
terTag, v);
    IterateProtectedPointer(obj, kBytecodeArrayOffset, v);
    IterateProtectedPointer(obj, kInterpreterTrampolineOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class UncompiledDataWithoutPreparseData::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kUncompiledDataIndirectPointerTag, v);
    IteratePointer(obj, kInferredNameOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class UncompiledDataWithPreparseData::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kUncompiledDataIndirectPointerTag, v);
    IteratePointer(obj, kInferredNameOffset, v);
    IteratePointer(obj, kPreparseDataOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class UncompiledDataWithoutPreparseDataWithJob::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kUncompiledDataIndirectPointerTag, v);
    IteratePointer(obj, kInferredNameOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class UncompiledDataWithPreparseDataAndJob::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kUncompiledDataIndirectPointerTag, v);
    IteratePointer(obj, kInferredNameOffset, v);
    IteratePointer(obj, kPreparseDataOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class SharedFunctionInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateTrustedPointer(obj, kTrustedFunctionDataOffset, v,
                          IndirectPointerMode::kCustom,
                          kUnknownIndirectPointerTag);
    IteratePointers(obj, kStartOfStrongFieldsOffset, kEndOfStrongFieldsOffset,
                    v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class SharedFunctionInfoWrapper::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointer(obj, kSharedInfoOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return kSize;
  }
};

class DebugInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, kStartOfStrongFieldsOffset, kEndOfStrongFieldsOffset,
                    v);
    IterateTrustedPointer(obj, kDebugBytecodeArrayOffset, v,
                          IndirectPointerMode::kStrong,
                          kBytecodeArrayIndirectPointerTag);
    IterateTrustedPointer(obj, kOriginalBytecodeArrayOffset, v,
                          IndirectPointerMode::kStrong,
                          kBytecodeArrayIndirectPointerTag);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return obj->SizeFromMap(map);
  }
};

class CallSiteInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // The field can contain either a Code or a BytecodeArray object, so we need
    // to use the kUnknownIndirectPointerTag here.
    IterateTrustedPointer(obj, kCodeObjectOffset, v,
                          IndirectPointerMode::kStrong,
                          kUnknownIndirectPointerTag);
    IteratePointers(obj, kStartOfStrongFieldsOffset, kEndOfStrongFieldsOffset,
                    v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return obj->SizeFromMap(map);
  }
};

class PrototypeInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, HeapObject::kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return obj->SizeFromMap(map);
  }
};

class JSWeakCollection::BodyDescriptorImpl final : public BodyDescriptorBase {
 public:
  static_assert(kTableOffset + kTaggedSize == kHeaderSizeOfAllWeakCollections);

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateJSObjectBodyImpl(map, obj, kPropertiesOrHashOffset, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class JSSynchronizationPrimitive::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, kPropertiesOrHashOffset, kEndOfTaggedFieldsOffset, v);
    v->VisitExternalPointer(obj,
                            obj->RawExternalPointerField(kWaiterQueueHeadOffset,
                                                         kWaiterQueueNodeTag));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

#if V8_ENABLE_WEBASSEMBLY
class WasmTypeInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    v->VisitExternalPointer(
        obj, obj->RawExternalPointerField(kNativeTypeOffset,
                                          kWasmTypeInfoNativeTypeTag));

    IterateTrustedPointer(obj, kTrustedDataOffset, v,
                          IndirectPointerMode::kStrong,
                          kWasmTrustedInstanceDataIndirectPointerTag);
    IteratePointers(obj, kSupertypesOffset, SizeOf(map, obj), v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return kSupertypesOffset +
           Cast<WasmTypeInfo>(object)->supertypes_length() * kTaggedSize;
  }
};

class WasmInstanceObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, kPropertiesOrHashOffset, JSObject::kHeaderSize, v);
    IterateTrustedPointer(obj, kTrustedDataOffset, v,
                          IndirectPointerMode::kStrong,
                          kWasmTrustedInstanceDataIndirectPointerTag);
    IteratePointer(obj, kModuleObjectOffset, v);
    IteratePointer(obj, kExportsObjectOffset, v);
    IterateJSObjectBodyImpl(map, obj, kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class WasmTrustedInstanceData::BodyDescriptor final
    : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kWasmTrustedInstanceDataIndirectPointerTag,
                               v);
    for (uint16_t offset : kTaggedFieldOffsets) {
      IteratePointer(obj, offset, v);
    }

    for (uint16_t offset : kProtectedFieldOffsets) {
      IterateProtectedPointer(obj, offset, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return kSize;
  }
};

class WasmTableObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSObject::BodyDescriptor::kStartOffset,
                    kTrustedDataOffset, v);
    IterateTrustedPointer(obj, kTrustedDataOffset, v,
                          IndirectPointerMode::kStrong,
                          kWasmTrustedInstanceDataIndirectPointerTag);
    IterateJSObjectBodyImpl(map, obj, kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class WasmTagObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSObject::BodyDescriptor::kStartOffset,
                    kTrustedDataOffset, v);
    IterateTrustedPointer(obj, kTrustedDataOffset, v,
                          IndirectPointerMode::kStrong,
                          kWasmTrustedInstanceDataIndirectPointerTag);
    IterateJSObjectBodyImpl(map, obj, kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class WasmGlobalObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSObject::BodyDescriptor::kStartOffset,
                    kTrustedDataOffset, v);
    IterateTrustedPointer(obj, kTrustedDataOffset, v,
                          IndirectPointerMode::kStrong,
                          kWasmTrustedInstanceDataIndirectPointerTag);
    IteratePointer(obj, kUntaggedBufferOffset, v);
    IteratePointer(obj, kTaggedBufferOffset, v);
    IterateJSObjectBodyImpl(map, obj, kIsMutableOffset + kTaggedSize,
                            object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};

class WasmDispatchTable::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateProtectedPointer(obj, kProtectedOffheapDataOffset, v);
    int length = Cast<WasmDispatchTable>(obj)->length(kAcquireLoad);
    for (int i = 0; i < length; ++i) {
      IterateProtectedPointer(obj, OffsetOf(i) + kImplicitArgBias, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    int capacity = Cast<WasmDispatchTable>(object)->capacity();
    return SizeFor(capacity);
  }
};

class WasmArray::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    // The type is safe to use because it's kept alive by the {map}'s
    // WasmTypeInfo.
    if (!WasmArray::GcSafeType(map)->element_type().is_reference()) return;
    IteratePointers(obj, WasmArray::kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return WasmArray::SizeFor(map, UncheckedCast<WasmArray>(object)->length());
  }
};

class WasmStruct::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    Tagged<WasmStruct> wasm_struct = UncheckedCast<WasmStruct>(obj);
    // The {type} is safe to use because it's kept alive by the {map}'s
    // WasmTypeInfo.
    wasm::StructType* type = WasmStruct::GcSafeType(map);
    for (uint32_t i = 0; i < type->field_count(); i++) {
      if (!type->field(i).is_reference()) continue;
      int offset = static_cast<int>(type->field_offset(i));
      v->VisitPointer(wasm_struct, wasm_struct->RawField(offset));
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return WasmStruct::GcSafeSize(map);
  }
};

class WasmNull::BodyDescriptor : public DataOnlyBodyDescriptor {
 public:
  static_assert(WasmNull::kStartOfStrongFieldsOffset ==
                WasmNull::kEndOfStrongFieldsOffset);

  static constexpr int kSize = WasmNull::kSize;

  static constexpr int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return kSize;
  }
};

class WasmMemoryObject::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, JSObject::BodyDescriptor::kStartOffset,
                    kEndOfStrongFieldsOffset, v);
    IterateJSObjectBodyImpl(map, obj, kHeaderSize, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return map->instance_size();
  }
};
#endif  // V8_ENABLE_WEBASSEMBLY

class ExternalString::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    Tagged<ExternalString> string = UncheckedCast<ExternalString>(obj);
    v->VisitExternalPointer(obj, ExternalPointerSlot(&string->resource_));
    if (string->is_uncached()) return;
    v->VisitExternalPointer(obj, ExternalPointerSlot(&string->resource_data_));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    InstanceType type = map->instance_type();
    const auto is_uncached =
        (type & kUncachedExternalStringMask) == kUncachedExternalStringTag;
    return is_uncached ? sizeof(UncachedExternalString)
                       : sizeof(ExternalString);
  }
};

class CoverageInfo::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    Tagged<CoverageInfo> info = Cast<CoverageInfo>(object);
    return CoverageInfo::SizeFor(info->slot_count());
  }
};

class InstructionStream::BodyDescriptor final : public BodyDescriptorBase {
 public:
  static_assert(static_cast<int>(HeapObject::kHeaderSize) ==
                static_cast<int>(kCodeOffset));
  static_assert(kCodeOffset + kTaggedSize == kRelocationInfoOffset);
  static_assert(kRelocationInfoOffset + kTaggedSize == kDataStart);

  static constexpr int kRelocModeMask =
      RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
      RelocInfo::ModeMask(RelocInfo::RELATIVE_CODE_TARGET) |
      RelocInfo::ModeMask(RelocInfo::FULL_EMBEDDED_OBJECT) |
      RelocInfo::ModeMask(RelocInfo::COMPRESSED_EMBEDDED_OBJECT) |
      RelocInfo::ModeMask(RelocInfo::EXTERNAL_REFERENCE) |
      RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
      RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED) |
      RelocInfo::ModeMask(RelocInfo::OFF_HEAP_TARGET) |
      RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL);

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 ObjectVisitor* v) {
    IterateProtectedPointer(obj, kCodeOffset, v);
    IterateProtectedPointer(obj, kRelocationInfoOffset, v);

    Tagged<InstructionStream> istream = UncheckedCast<InstructionStream>(obj);
    if (istream->IsFullyInitialized()) {
      RelocIterator it(istream, kRelocModeMask);
      v->VisitRelocInfo(istream, &it);
    }
  }

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateBody(map, obj, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return UncheckedCast<InstructionStream>(object)->Size();
  }
};

class Map::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, Map::kStartOfStrongFieldsOffset,
                    Map::kEndOfStrongFieldsOffset, v);
    IterateMaybeWeakPointer(obj, kTransitionsOrPrototypeInfoOffset, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return Map::kSize;
  }
};

class DataHandler::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    static_assert(kSmiHandlerOffset < kData1Offset,
                  "Field order must be in sync with this iteration code");
    static_assert(kData1Offset < kSizeWithData1,
                  "Field order must be in sync with this iteration code");
    IteratePointers(obj, kSmiHandlerOffset, kData1Offset, v);
    IterateMaybeWeakPointers(obj, kData1Offset, object_size, v);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return object->SizeFromMap(map);
  }
};

class NativeContext::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, NativeContext::kStartOfStrongFieldsOffset,
                    NativeContext::kEndOfStrongFieldsOffset, v);
    IterateCustomWeakPointers(obj, NativeContext::kStartOfWeakFieldsOffset,
                              NativeContext::kEndOfWeakFieldsOffset, v);
    v->VisitExternalPointer(
        obj, obj->RawExternalPointerField(kMicrotaskQueueOffset,
                                          kNativeContextMicrotaskQueueTag));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return NativeContext::kSize;
  }
};

class Code::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateSelfIndirectPointer(obj, kCodeIndirectPointerTag, v);
    IterateProtectedPointer(
        obj, Code::kDeoptimizationDataOrInterpreterDataOffset, v);
    IterateProtectedPointer(obj, Code::kPositionTableOffset, v);
    IteratePointers(obj, Code::kStartOfStrongFieldsOffset,
                    Code::kEndOfStrongFieldsWithMainCageBaseOffset, v);

    static_assert(Code::kEndOfStrongFieldsWithMainCageBaseOffset ==
                  Code::kInstructionStreamOffset);
    static_assert(Code::kInstructionStreamOffset + kTaggedSize ==
                  Code::kEndOfStrongFieldsOffset);
    v->VisitInstructionStreamPointer(
        Cast<Code>(obj),
        obj->RawInstructionStreamField(kInstructionStreamOffset));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return Code::kSize;
  }
};

class CodeWrapper::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IterateCodePointer(obj, kCodeOffset, v, IndirectPointerMode::kStrong);
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> obj) {
    return kSize;
  }
};

class EmbedderDataArray::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
#ifdef V8_COMPRESS_POINTERS
    static_assert(kEmbedderDataSlotSize == 2 * kTaggedSize);
    for (int offset = EmbedderDataArray::OffsetOfElementAt(0);
         offset < object_size; offset += kEmbedderDataSlotSize) {
      IteratePointer(obj, offset + EmbedderDataSlot::kTaggedPayloadOffset, v);
      v->VisitExternalPointer(
          obj, obj->RawExternalPointerField(
                   offset + EmbedderDataSlot::kExternalPointerOffset,
                   kEmbedderDataSlotPayloadTag));
    }

#else
    // We store raw aligned pointers as Smis, so it's safe to iterate the whole
    // array.
    static_assert(kEmbedderDataSlotSize == kTaggedSize);
    IteratePointers(obj, EmbedderDataArray::kHeaderSize, object_size, v);
#endif
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return object->SizeFromMap(map);
  }
};

class EphemeronHashTable::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    int entries_start = EphemeronHashTable::OffsetOfElementAt(
        EphemeronHashTable::kElementsStartIndex);
    IteratePointers(obj, OFFSET_OF_DATA_START(EphemeronHashTable),
                    entries_start, v);
    Tagged<EphemeronHashTable> table = UncheckedCast<EphemeronHashTable>(obj);
    for (InternalIndex i : table->IterateEntries()) {
      const int key_index = EphemeronHashTable::EntryToIndex(i);
      const int value_index = EphemeronHashTable::EntryToValueIndex(i);
      IterateEphemeron(obj, i.as_int(), OffsetOfElementAt(key_index),
                       OffsetOfElementAt(value_index), v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return object->SizeFromMap(map);
  }
};

class AccessorInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  static_assert(AccessorInfo::kEndOfStrongFieldsOffset ==
                AccessorInfo::kMaybeRedirectedGetterOffset);
  static_assert(AccessorInfo::kMaybeRedirectedGetterOffset <
                AccessorInfo::kSetterOffset);
  static_assert(AccessorInfo::kSetterOffset < AccessorInfo::kFlagsOffset);
  static_assert(AccessorInfo::kFlagsOffset < AccessorInfo::kSize);

  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, HeapObject::kHeaderSize,
                    AccessorInfo::kEndOfStrongFieldsOffset, v);
    v->VisitExternalPointer(obj, obj->RawExternalPointerField(
                                     AccessorInfo::kMaybeRedirectedGetterOffset,
                                     kAccessorInfoGetterTag));
    v->VisitExternalPointer(
        obj, obj->RawExternalPointerField(AccessorInfo::kSetterOffset,
                                          kAccessorInfoSetterTag));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return kSize;
  }
};

class FunctionTemplateInfo::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointers(obj, HeapObject::kHeaderSize,
                    FunctionTemplateInfo::kEndOfStrongFieldsOffset, v);
    v->VisitExternalPointer(
        obj, obj->RawExternalPointerField(
                 FunctionTemplateInfo::kMaybeRedirectedCallbackOffset,
                 kFunctionTemplateInfoCallbackTag));
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return kSize;
  }
};

// TODO(jgruber): Combine these into generic Suffix descriptors.
class FixedArray::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<FixedArray>(raw_object)->AllocatedSize();
  }
};

class TrustedFixedArray::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<TrustedObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<TrustedFixedArray>(raw_object)->AllocatedSize();
  }
};

class ProtectedFixedArray::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    for (int offset = OFFSET_OF_DATA_START(ProtectedFixedArray);
         offset < object_size; offset += kTaggedSize) {
      IterateProtectedPointer(obj, offset, v);
    }
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<ProtectedFixedArray>(raw_object)->AllocatedSize();
  }
};

class SloppyArgumentsElements::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<SloppyArgumentsElements>(raw_object)->AllocatedSize();
  }
};

class RegExpMatchInfo::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<RegExpMatchInfo>(raw_object)->AllocatedSize();
  }
};

class ArrayList::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<ArrayList>(raw_object)->AllocatedSize();
  }
};

class ObjectBoilerplateDescription::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<ObjectBoilerplateDescription>(raw_object)
        ->AllocatedSize();
  }
};

class FeedbackCell::BodyDescriptor final : public BodyDescriptorBase {
 public:
  template <typename ObjectVisitor>
  static inline void IterateBody(Tagged<Map> map, Tagged<HeapObject> obj,
                                 int object_size, ObjectVisitor* v) {
    IteratePointer(obj, kValueOffset, v);

#ifdef V8_ENABLE_LEAPTIERING
    IterateJSDispatchEntry(obj, kDispatchHandleOffset, v);
#endif
  }

  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> object) {
    return kAlignedSize;
  }
};

class ClosureFeedbackCellArray::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<ClosureFeedbackCellArray>(raw_object)->AllocatedSize();
  }
};

class ScriptContextTable::BodyDescriptor final
    : public SuffixRangeBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<ScriptContextTable>(raw_object)->AllocatedSize();
  }
};

class WeakFixedArray::BodyDescriptor final
    : public SuffixRangeWeakBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<WeakFixedArray>(raw_object)->AllocatedSize();
  }
};

class TrustedWeakFixedArray::BodyDescriptor final
    : public SuffixRangeWeakBodyDescriptor<HeapObject::kHeaderSize> {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<TrustedWeakFixedArray>(raw_object)->AllocatedSize();
  }
};

#include "torque-generated/objects-body-descriptors-inl.inc"

}  // namespace internal
}  // namespace v8

#endif  // V8_OBJECTS_OBJECTS_BODY_DESCRIPTORS_INL_H_

"""


```