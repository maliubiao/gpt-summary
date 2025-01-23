Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Scan and Keyword Recognition:**

First, I quickly scanned the file, looking for familiar C++ keywords and structures. Things that jumped out were:

* `#ifndef`, `#define`, `#include`:  Standard C++ header guard.
* `namespace v8`, `namespace internal`: Indicates this is part of the V8 JavaScript engine.
* `class`:  Definition of classes.
* `template <typename ConcreteVisitor>`:  Indicates template usage, meaning the class is designed to be used with different types.
* `public`, `protected`, `private`: Access modifiers for class members.
* `V8_INLINE`:  Likely a macro for inline functions, hinting at performance-critical code.
* `size_t`:  Standard type for representing object sizes.
* `Tagged<HeapObject>`, `Tagged<Map>`, etc.:  V8-specific template types likely related to memory management and object representation.
* `Visit...`:  Many functions starting with "Visit" suggest a visitor pattern implementation.
* Macros like `TYPED_VISITOR_ID_LIST`, `TYPED_VISITOR_WITH_SLACK_ID_LIST`:  These are strong indicators of code generation or repetitive structure.
* `MaybeObjectSize`: A small class for handling optional sizes.
* Comments like `// Copyright...`, `// This class is used...`: Provide high-level context.

**2. Understanding the Core Purpose - The Visitor Pattern:**

The repeated "Visit" functions and the class naming (`HeapVisitor`) strongly suggested the *Visitor design pattern*. My initial hypothesis was that this header defines a framework for traversing the V8 heap and performing operations on different types of objects.

**3. Analyzing Key Classes and Structures:**

* **`MaybeObjectSize`:**  A simple optimization to avoid the overhead of `std::optional` when representing an object's size might be present or not.

* **Macros like `TYPED_VISITOR_ID_LIST`:** I recognized these as likely generating lists of function declarations. The arguments to these macros (`V(TypeName)`) implied that the macro would expand into something like `V8_INLINE size_t VisitTypeName(...)`. This reinforces the visitor pattern idea, where there's a specific `Visit` method for each object type.

* **`HeapVisitor<ConcreteVisitor>`:** The template parameter indicates extensibility. Different concrete visitors can be created to perform different operations on the heap (e.g., garbage collection marking, object size calculation, debugging). The base class provides the generic traversal logic.

* **`ConcurrentHeapVisitor` and `NewSpaceVisitor`:** These derived classes suggest specialized visitors for different scenarios (concurrent processing, specific memory spaces).

* **`VisitWeakList`:** This function stands out as handling weak references, which are crucial for garbage collection and preventing memory leaks.

**4. Deduction of Functionality:**

Based on the above observations, I started to list the likely functionalities:

* **Heap Traversal:** The core purpose is to visit objects in the V8 heap.
* **Type-Specific Handling:** The `VisitTypeName` functions indicate that the visitor can handle different object types.
* **Customizable Actions:**  The template structure allows users to define their own actions within concrete visitor classes.
* **Optimization:** `MaybeObjectSize` and `V8_INLINE` hint at performance considerations.
* **Concurrency:** `ConcurrentHeapVisitor` indicates support for concurrent heap traversal.
* **Memory Management:**  `NewSpaceVisitor` and `VisitWeakList` suggest involvement in garbage collection and memory management.
* **Object Size Information:** The `MaybeObjectSize` parameter suggests that the visitor might deal with object sizes.

**5. Considering the ".tq" Extension and JavaScript Relevance:**

* **".tq" Extension:**  I recalled that ".tq" often signifies Torque code in V8. Torque is a domain-specific language used for implementing built-in functions.

* **JavaScript Relevance:** Since V8 *is* the JavaScript engine, nearly everything in its codebase is related to JavaScript execution in some way. The heap is where JavaScript objects reside. The visitor pattern would be used when performing operations on these objects.

**6. Developing Examples and Reasoning:**

* **JavaScript Example:**  I thought of common JavaScript operations that would involve the heap: object creation, garbage collection. This led to the examples of creating objects and relying on the garbage collector.

* **Code Logic Reasoning:** I looked for specific logic within the header. The `ShouldVisitMapPointer` and `ShouldVisitReadOnlyMapPointer` functions suggested conditional logic based on object properties. I constructed a hypothetical scenario where a visitor might skip read-only maps for optimization.

* **Common Programming Errors:** I considered errors related to manual memory management in other languages and how V8's garbage collection helps avoid them. This led to the example of forgetting to free memory.

**7. Structuring the Output:**

Finally, I organized my findings into the requested sections:

* **功能 (Functions):**  Summarizing the core purposes.
* **Torque 源代码:** Addressing the ".tq" extension.
* **与 JavaScript 的关系 (Relationship with JavaScript):**  Providing a concrete JavaScript example.
* **代码逻辑推理 (Code Logic Reasoning):**  Explaining the conditional map visitation with a hypothetical scenario.
* **用户常见的编程错误 (Common User Programming Errors):**  Relating V8's memory management to common pitfalls.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on the low-level details of the macros. I then shifted my focus to the overall design pattern (Visitor) and the high-level purpose of the header file within V8. I also made sure to connect the C++ code to concrete JavaScript concepts to fulfill that part of the prompt. I double-checked the prompt to ensure I addressed all the specific questions.
## v8/src/heap/heap-visitor.h 的功能解析

这个头文件 `v8/src/heap/heap-visitor.h` 定义了 V8 引擎中用于遍历堆内存对象的访问者（Visitor）模式的基础框架。它提供了一种结构化的方式来对堆中的各种类型的对象执行操作，而无需在遍历代码中硬编码针对每种类型的处理逻辑。

**主要功能可以概括为：**

1. **定义通用的访问者接口：**  `HeapVisitor` 类是一个模板基类，它定义了访问堆中不同类型对象的方法 (`VisitTypeName`)。这个基类提供了一些默认的行为，例如根据对象的 `Map` 来确定对象类型并调用相应的 `Visit` 方法。

2. **提供不同类型的访问者：**  通过模板机制，可以创建继承自 `HeapVisitor` 的具体访问者类，例如 `ConcurrentHeapVisitor` 和 `NewSpaceVisitor`，它们可以实现特定的遍历和操作逻辑。

3. **支持对不同类型的堆对象进行访问：** 文件中定义了大量的宏 (`TYPED_VISITOR_ID_LIST`, `TYPED_VISITOR_WITH_SLACK_ID_LIST`, `TORQUE_VISITOR_ID_LIST`, `TRUSTED_VISITOR_ID_LIST`)，这些宏展开后会生成针对各种 V8 堆对象的 `Visit` 方法，例如 `VisitAccessorInfo`, `VisitJSObject`, `VisitBytecodeArray` 等。

4. **优化访问过程：**
   - `MaybeObjectSize` 类用于作为 `HeapVisitor::Visit()` 方法的参数，它是一种比 `std::optional<size_t>` 更轻量级的替代方案，用于传递对象大小信息。
   - `ShouldVisitMapPointer` 和 `ShouldVisitReadOnlyMapPointer` 等静态 constexpr 函数允许具体的访问者控制是否需要访问对象的 `Map` 指针，或者是否需要访问只读 `Map` 指针，从而进行优化。

5. **支持并发访问：** `ConcurrentHeapVisitor` 类提供了一种允许并发遍历对象的机制，但需要注意潜在的并发安全问题。

6. **针对不同内存空间的访问：** `NewSpaceVisitor` 类是针对新生代 (New Space) 的访问者，它假定一些对象类型不会出现在新生代中，并提供了相应的断言 (`UNREACHABLE()`).

7. **处理弱引用列表：** `VisitWeakList` 函数用于遍历和清理包含弱引用的链表。

**如果 v8/src/heap/heap-visitor.h 以 .tq 结尾，那它是个 v8 torque 源代码:**

这个说法是正确的。V8 使用 Torque 作为一种领域特定语言来编写一些性能关键的代码，包括一些内置函数和类型定义。如果文件以 `.tq` 结尾，则表示它是一个 Torque 源代码文件，而不是 C++ 头文件。然而，你提供的文件内容是 C++ 头文件 (`.h`)。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`v8/src/heap/heap-visitor.h` 与 JavaScript 的功能有着直接且深远的关系。  V8 引擎负责执行 JavaScript 代码，而堆是用于存储 JavaScript 对象的核心内存区域。`HeapVisitor` 框架是 V8 管理和操作这些 JavaScript 对象的基础工具。

**JavaScript 例子:**

```javascript
let obj = { a: 1, b: "hello" };
let arr = [1, 2, 3];
function myFunction() {}
```

当你在 JavaScript 中创建对象 (`obj`), 数组 (`arr`), 函数 (`myFunction`) 时，V8 引擎会在堆上分配内存来存储这些对象。`HeapVisitor` 框架会被 V8 的各种子系统使用，例如：

* **垃圾回收 (Garbage Collection):** 垃圾回收器会使用访问者模式来遍历堆中的所有对象，标记哪些对象仍然被引用，从而回收不再使用的内存。例如，一个垃圾回收器的访问者可能会检查对象是否可达。
* **快照 (Snapshotting):**  在创建堆快照时，需要遍历堆中的所有对象，将它们的状态保存下来。
* **调试 (Debugging):** 调试器可以使用访问者来检查堆中对象的值和结构。
* **性能分析 (Profiling):** 性能分析工具可能会使用访问者来收集有关对象分配和内存使用的信息。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个具体的访问者类 `SizeCalculatorVisitor`，它继承自 `HeapVisitor`，其目的是计算堆中所有对象的总大小。

**假设输入:**

* 堆中存在以下对象：
    * 一个 `JSObject` 实例，包含两个属性，大小为 32 字节。
    * 一个 `SeqOneByteString` 实例，内容为 "test"，大小为 8 字节（假设每个字符 1 字节 + 元数据）。
    * 一个 `FixedArray` 实例，包含 3 个元素，大小为 24 字节（假设每个元素 8 字节）。

**SizeCalculatorVisitor 的实现 (简化示例):**

```c++
class SizeCalculatorVisitor : public HeapVisitor<SizeCalculatorVisitor> {
 public:
  explicit SizeCalculatorVisitor(Isolate* isolate) : HeapVisitor(isolate), total_size_(0) {}

  size_t total_size() const { return total_size_; }

 protected:
  size_t VisitJSObject(Tagged<Map> map, Tagged<JSObject> object, MaybeObjectSize maybe_object_size) {
    size_t size = maybe_object_size.AssumeSize();
    total_size_ += size;
    return size;
  }

  size_t VisitSeqOneByteString(Tagged<Map> map, Tagged<SeqOneByteString> object, MaybeObjectSize maybe_object_size) {
    size_t size = maybe_object_size.AssumeSize();
    total_size_ += size;
    return size;
  }

  size_t VisitFixedArray(Tagged<Map> map, Tagged<FixedArray> object, MaybeObjectSize maybe_object_size) {
    size_t size = maybe_object_size.AssumeSize();
    total_size_ += size;
    return size;
  }

 private:
  size_t total_size_;
};
```

**输出:**

当我们使用 `SizeCalculatorVisitor` 遍历上述假设的堆时，`total_size()` 的输出将是：

32 (JSObject) + 8 (SeqOneByteString) + 24 (FixedArray) = **64 字节**

**用户常见的编程错误 (举例说明):**

虽然用户通常不直接与 `HeapVisitor` 打交道，但理解其背后的原理可以帮助理解 V8 的行为，并避免一些与内存相关的常见错误：

1. **内存泄漏 (Memory Leaks):**  在手动管理内存的语言中，忘记释放不再使用的对象会导致内存泄漏。V8 使用垃圾回收器来自动管理内存，这在很大程度上避免了这个问题。理解 `HeapVisitor` 在垃圾回收中的作用，可以更好地理解 V8 如何识别和回收不再使用的对象。如果 JavaScript 代码持有对不再需要的对象的强引用，垃圾回收器就无法回收这些对象，导致类似内存泄漏的问题。

   **JavaScript 示例:**

   ```javascript
   let leakedMemory = [];
   setInterval(() => {
     let largeObject = new Array(1000000).fill(0); // 创建一个大对象
     leakedMemory.push(largeObject); // 将其添加到全局数组，保持强引用
   }, 100);
   ```

   在这个例子中，`largeObject` 被不断地创建并添加到 `leakedMemory` 数组中，即使这些对象不再需要使用，垃圾回收器也无法回收它们，因为 `leakedMemory` 数组持有着对它们的引用。`HeapVisitor` 在垃圾回收过程中会遍历这些对象，但只要它们可达，就不会被回收。

2. **意外的性能瓶颈:**  理解 V8 如何遍历和处理堆对象，可以帮助开发者避免创建大量小对象或者导致大量对象间接引用的复杂结构。这些情况可能会增加垃圾回收的负担，导致性能下降。虽然 `HeapVisitor` 的具体实现对用户是透明的，但其背后的逻辑影响着 V8 的性能。

总而言之，`v8/src/heap/heap-visitor.h` 定义了 V8 引擎中用于高效、结构化地访问和操作堆内存对象的关键框架，它是 V8 诸多核心功能（如垃圾回收、快照、调试等）的基础。虽然 JavaScript 开发者通常不直接使用这个头文件中的类，但理解其背后的概念有助于更好地理解 V8 的工作原理和优化 JavaScript 代码。

### 提示词
```
这是目录为v8/src/heap/heap-visitor.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap-visitor.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_HEAP_VISITOR_H_
#define V8_HEAP_HEAP_VISITOR_H_

#include "src/base/logging.h"
#include "src/objects/bytecode-array.h"
#include "src/objects/contexts.h"
#include "src/objects/fixed-array.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/map.h"
#include "src/objects/object-list-macros.h"
#include "src/objects/objects.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string.h"
#include "src/objects/visitors.h"

namespace v8 {
namespace internal {

// This class is used as argument to the HeapVisitor::Visit() method as a
// cheaper alternative to std::optional<size_t>.
class MaybeObjectSize final {
 public:
  explicit MaybeObjectSize(size_t size) : raw_size_(size) {
    DCHECK_GT(size, 0);
  }

  MaybeObjectSize() : raw_size_(0) {}

  size_t AssumeSize() const {
    DCHECK_GT(raw_size_, 0);
    return raw_size_;
  }

  bool IsNone() const { return raw_size_ == 0; }

 private:
  size_t raw_size_;
};

// Visitation in here will refer to BodyDescriptors with the regular instance
// size.
#define TYPED_VISITOR_ID_LIST(V)     \
  V(AccessorInfo)                    \
  V(AllocationSite)                  \
  V(BigInt)                          \
  V(BytecodeWrapper)                 \
  V(CallSiteInfo)                    \
  V(Cell)                            \
  V(CodeWrapper)                     \
  V(ConsString)                      \
  V(ContextSidePropertyCell)         \
  V(CoverageInfo)                    \
  V(DataHandler)                     \
  V(DebugInfo)                       \
  V(EmbedderDataArray)               \
  V(EphemeronHashTable)              \
  V(ExternalString)                  \
  V(FeedbackCell)                    \
  V(FeedbackMetadata)                \
  V(Foreign)                         \
  V(FunctionTemplateInfo)            \
  V(HeapNumber)                      \
  V(Hole)                            \
  V(Map)                             \
  V(NativeContext)                   \
  V(Oddball)                         \
  V(PreparseData)                    \
  V(PropertyArray)                   \
  V(PropertyCell)                    \
  V(PrototypeInfo)                   \
  V(RegExpBoilerplateDescription)    \
  V(RegExpDataWrapper)               \
  V(SeqOneByteString)                \
  V(SeqTwoByteString)                \
  V(SharedFunctionInfo)              \
  V(SlicedString)                    \
  V(SloppyArgumentsElements)         \
  V(SmallOrderedHashMap)             \
  V(SmallOrderedHashSet)             \
  V(SmallOrderedNameDictionary)      \
  V(SourceTextModule)                \
  V(SwissNameDictionary)             \
  V(Symbol)                          \
  V(SyntheticModule)                 \
  V(ThinString)                      \
  V(TransitionArray)                 \
  V(WeakCell)                        \
  IF_WASM(V, WasmArray)              \
  IF_WASM(V, WasmContinuationObject) \
  IF_WASM(V, WasmFuncRef)            \
  IF_WASM(V, WasmNull)               \
  IF_WASM(V, WasmResumeData)         \
  IF_WASM(V, WasmStruct)             \
  IF_WASM(V, WasmSuspenderObject)    \
  IF_WASM(V, WasmTypeInfo)           \
  SIMPLE_HEAP_OBJECT_LIST1(V)

// Visitation in here will refer to BodyDescriptors with the used size of the
// map. Slack will thus be ignored. We are not allowed to visit slack as that's
// visiting free space fillers.
#define TYPED_VISITOR_WITH_SLACK_ID_LIST(V) \
  V(JSArrayBuffer)                          \
  V(JSDataViewOrRabGsabDataView)            \
  V(JSDate)                                 \
  V(JSExternalObject)                       \
  V(JSFinalizationRegistry)                 \
  V(JSFunction)                             \
  V(JSObject)                               \
  V(JSRegExp)                               \
  V(JSSynchronizationPrimitive)             \
  V(JSTypedArray)                           \
  V(JSWeakCollection)                       \
  V(JSWeakRef)                              \
  IF_WASM(V, WasmGlobalObject)              \
  IF_WASM(V, WasmInstanceObject)            \
  IF_WASM(V, WasmMemoryObject)              \
  IF_WASM(V, WasmSuspendingObject)          \
  IF_WASM(V, WasmTableObject)               \
  IF_WASM(V, WasmTagObject)

// List of visitor ids that can only appear in read-only maps. Unfortunately,
// these are generally contained in all other lists.
//
// Adding an instance type here allows skipping vistiation of Map slots for
// visitors with `ShouldVisitReadOnlyMapPointer() == false`.
#define VISITOR_IDS_WITH_READ_ONLY_MAPS_LIST(V)           \
  /* All trusted objects have maps in read-only space. */ \
  CONCRETE_TRUSTED_OBJECT_TYPE_LIST1(V)                   \
  V(AccessorInfo)                                         \
  V(AllocationSite)                                       \
  V(BigInt)                                               \
  V(BytecodeWrapper)                                      \
  V(ByteArray)                                            \
  V(Cell)                                                 \
  V(CodeWrapper)                                          \
  V(DataHandler)                                          \
  V(DescriptorArray)                                      \
  V(EmbedderDataArray)                                    \
  V(ExternalString)                                       \
  V(FeedbackCell)                                         \
  V(FeedbackMetadata)                                     \
  V(FeedbackVector)                                       \
  V(Filler)                                               \
  V(FixedArray)                                           \
  V(FixedDoubleArray)                                     \
  V(FunctionTemplateInfo)                                 \
  V(FreeSpace)                                            \
  V(HeapNumber)                                           \
  V(PreparseData)                                         \
  V(PropertyArray)                                        \
  V(PropertyCell)                                         \
  V(PrototypeInfo)                                        \
  V(RegExpBoilerplateDescription)                         \
  V(RegExpDataWrapper)                                    \
  V(ScopeInfo)                                            \
  V(SeqOneByteString)                                     \
  V(SeqTwoByteString)                                     \
  V(SharedFunctionInfo)                                   \
  V(ShortcutCandidate)                                    \
  V(SlicedString)                                         \
  V(SloppyArgumentsElements)                              \
  V(Symbol)                                               \
  V(ThinString)                                           \
  V(TransitionArray)                                      \
  V(WeakArrayList)                                        \
  V(WeakFixedArray)

#define FORWARD_DECLARE(TypeName) class TypeName;
TYPED_VISITOR_ID_LIST(FORWARD_DECLARE)
TYPED_VISITOR_WITH_SLACK_ID_LIST(FORWARD_DECLARE)
TORQUE_VISITOR_ID_LIST(FORWARD_DECLARE)
TRUSTED_VISITOR_ID_LIST(FORWARD_DECLARE)
#undef FORWARD_DECLARE

// The base class for visitors that need to dispatch on object type. The default
// behavior of all visit functions is to iterate body of the given object using
// the BodyDescriptor of the object.
//
// The visit functions return the size of the object.
//
// This class is intended to be used in the following way:
//
//   class SomeVisitor : public HeapVisitor<SomeVisitor> {
//     ...
//   }
template <typename ConcreteVisitor>
class HeapVisitor : public ObjectVisitorWithCageBases {
 public:
  inline HeapVisitor(PtrComprCageBase cage_base,
                     PtrComprCageBase code_cage_base);
  inline explicit HeapVisitor(Isolate* isolate);
  inline explicit HeapVisitor(Heap* heap);

  V8_INLINE size_t Visit(Tagged<HeapObject> object)
    requires(!ConcreteVisitor::UsePrecomputedObjectSize());

  V8_INLINE size_t Visit(Tagged<Map> map, Tagged<HeapObject> object)
    requires(!ConcreteVisitor::UsePrecomputedObjectSize());

  V8_INLINE size_t Visit(Tagged<Map> map, Tagged<HeapObject> object,
                         int object_size)
    requires(ConcreteVisitor::UsePrecomputedObjectSize());

 protected:
  V8_INLINE size_t Visit(Tagged<Map> map, Tagged<HeapObject> object,
                         MaybeObjectSize maybe_object_size);

  // If this predicate returns false the default implementations of Visit*
  // functions bail out from visiting the map pointer.
  V8_INLINE static constexpr bool ShouldVisitMapPointer() { return true; }
  // If this predicate returns false the default implementations of Visit*
  // functions bail out from visiting known read-only maps.
  V8_INLINE static constexpr bool ShouldVisitReadOnlyMapPointer() {
    return true;
  }
  // If this predicate returns false the default implementation of
  // `VisitFiller()` and `VisitFreeSpace()` will be unreachable.
  V8_INLINE static constexpr bool CanEncounterFillerOrFreeSpace() {
    return true;
  }
  // If this predicate returns false the default implementation of
  // `VisitFiller()` and `VisitFreeSpace()` will be unreachable.
  V8_INLINE static constexpr bool ShouldUseUncheckedCast() { return false; }

  // This should really only be defined and used in ConcurrentHeapVisitor but we
  // need it here for a DCHECK in HeapVisitor::VisitWithBodyDescriptor.
  V8_INLINE static constexpr bool EnableConcurrentVisitation() { return false; }

  // Avoids size computation in visitors and uses the input argument instead.
  V8_INLINE static constexpr bool UsePrecomputedObjectSize() { return false; }

  // Only visits the Map pointer if `ShouldVisitMapPointer()` returns true.
  template <VisitorId visitor_id>
  V8_INLINE void VisitMapPointerIfNeeded(Tagged<HeapObject> host);

  // If this predicate returns true, the visitor will visit the full JSObject
  // (including slack).
  V8_INLINE static constexpr bool ShouldVisitFullJSObject() { return false; }

  ConcreteVisitor* concrete_visitor() {
    return static_cast<ConcreteVisitor*>(this);
  }

  const ConcreteVisitor* concrete_visitor() const {
    return static_cast<const ConcreteVisitor*>(this);
  }

#define VISIT(TypeName)                                                      \
  V8_INLINE size_t Visit##TypeName(Tagged<Map> map, Tagged<TypeName> object, \
                                   MaybeObjectSize maybe_object_size);
  TYPED_VISITOR_ID_LIST(VISIT)
  TYPED_VISITOR_WITH_SLACK_ID_LIST(VISIT)
  TORQUE_VISITOR_ID_LIST(VISIT)
  TRUSTED_VISITOR_ID_LIST(VISIT)
#undef VISIT
  V8_INLINE size_t VisitShortcutCandidate(Tagged<Map> map,
                                          Tagged<ConsString> object,
                                          MaybeObjectSize maybe_object_size);
  V8_INLINE size_t VisitJSObjectFast(Tagged<Map> map, Tagged<JSObject> object,
                                     MaybeObjectSize maybe_object_size);
  V8_INLINE size_t VisitJSApiObject(Tagged<Map> map, Tagged<JSObject> object,
                                    MaybeObjectSize maybe_object_size);
  V8_INLINE size_t VisitStruct(Tagged<Map> map, Tagged<HeapObject> object,
                               MaybeObjectSize maybe_object_size);
  V8_INLINE size_t VisitFiller(Tagged<Map> map, Tagged<HeapObject> object,
                               MaybeObjectSize maybe_object_size);
  V8_INLINE size_t VisitFreeSpace(Tagged<Map> map, Tagged<FreeSpace> object,
                                  MaybeObjectSize maybe_object_size);

  template <typename T, typename TBodyDescriptor = typename T::BodyDescriptor>
  V8_INLINE size_t VisitJSObjectSubclass(Tagged<Map> map, Tagged<T> object,
                                         MaybeObjectSize maybe_object_size);

  template <VisitorId visitor_id, typename T,
            typename TBodyDescriptor = typename T::BodyDescriptor>
  V8_INLINE size_t VisitWithBodyDescriptor(Tagged<Map> map, Tagged<T> object,
                                           MaybeObjectSize maybe_object_size);

  template <typename T>
  static V8_INLINE Tagged<T> Cast(Tagged<HeapObject> object);

  // Inspects the slot and filters some well-known RO objects and Smis in a fast
  // way. May still return Smis or RO objects.
  template <typename TSlot>
  std::optional<Tagged<Object>> GetObjectFilterReadOnlyAndSmiFast(
      TSlot slot) const;
};

// These strings can be sources of safe string transitions. Transitions are safe
// if they don't result in invalidated slots. It's safe to read the length field
// on such strings as that's common for all.
//
// No special visitors are generated for such strings.
// V(VisitorId, TypeName)
#define SAFE_STRING_TRANSITION_SOURCES(V) \
  V(SeqOneByteString, SeqOneByteString)   \
  V(SeqTwoByteString, SeqTwoByteString)

// These strings can be sources of unsafe string transitions.
// V(VisitorId, TypeName)
#define UNSAFE_STRING_TRANSITION_SOURCES(V) \
  V(ExternalString, ExternalString)         \
  V(ConsString, ConsString)                 \
  V(SlicedString, SlicedString)

// V(VisitorId, TypeName)
#define UNSAFE_STRING_TRANSITION_TARGETS(V) \
  UNSAFE_STRING_TRANSITION_SOURCES(V)       \
  V(ShortcutCandidate, ConsString)          \
  V(ThinString, ThinString)

// A HeapVisitor that allows for concurrently tracing through objects. Tracing
// through objects with unsafe shape changes is guarded by
// `EnableConcurrentVisitation()` which defaults to off.
template <typename ConcreteVisitor>
class ConcurrentHeapVisitor : public HeapVisitor<ConcreteVisitor> {
 public:
  V8_INLINE explicit ConcurrentHeapVisitor(Isolate* isolate);

  V8_INLINE static constexpr bool EnableConcurrentVisitation() { return false; }

 protected:
#define VISIT_AS_LOCKED_STRING(VisitorId, TypeName)                          \
  V8_INLINE size_t Visit##TypeName(Tagged<Map> map, Tagged<TypeName> object, \
                                   MaybeObjectSize maybe_object_size);

  UNSAFE_STRING_TRANSITION_SOURCES(VISIT_AS_LOCKED_STRING)
#undef VISIT_AS_LOCKED_STRING

  template <typename T>
  static V8_INLINE Tagged<T> Cast(Tagged<HeapObject> object);

 private:
  template <typename T>
  V8_INLINE size_t VisitStringLocked(Tagged<T> object);

  friend class HeapVisitor<ConcreteVisitor>;
};

template <typename ConcreteVisitor>
class NewSpaceVisitor : public ConcurrentHeapVisitor<ConcreteVisitor> {
 public:
  V8_INLINE explicit NewSpaceVisitor(Isolate* isolate);

  // Special cases: Unreachable visitors for objects that are never found in the
  // young generation.
  void VisitInstructionStreamPointer(Tagged<Code>,
                                     InstructionStreamSlot) final {
    UNREACHABLE();
  }
  void VisitCodeTarget(Tagged<InstructionStream> host, RelocInfo*) final {
    UNREACHABLE();
  }
  void VisitEmbeddedPointer(Tagged<InstructionStream> host, RelocInfo*) final {
    UNREACHABLE();
  }
  void VisitMapPointer(Tagged<HeapObject>) override { UNREACHABLE(); }

 protected:
  V8_INLINE static constexpr bool ShouldVisitMapPointer() { return false; }

  // Special cases: Unreachable visitors for objects that are never found in the
  // young generation.
  size_t VisitNativeContext(Tagged<Map>, Tagged<NativeContext>,
                            MaybeObjectSize) {
    UNREACHABLE();
  }
  size_t VisitBytecodeArray(Tagged<Map>, Tagged<BytecodeArray>,
                            MaybeObjectSize) {
    UNREACHABLE();
  }
  size_t VisitSharedFunctionInfo(Tagged<Map> map, Tagged<SharedFunctionInfo>,
                                 MaybeObjectSize) {
    UNREACHABLE();
  }
  size_t VisitWeakCell(Tagged<Map>, Tagged<WeakCell>, MaybeObjectSize) {
    UNREACHABLE();
  }

  friend class HeapVisitor<ConcreteVisitor>;
};

class WeakObjectRetainer;

// A weak list is single linked list where each element has a weak pointer to
// the next element. Given the head of the list, this function removes dead
// elements from the list and if requested records slots for next-element
// pointers. The template parameter T is a WeakListVisitor that defines how to
// access the next-element pointers.
template <class T>
Tagged<Object> VisitWeakList(Heap* heap, Tagged<Object> list,
                             WeakObjectRetainer* retainer);
}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_HEAP_VISITOR_H_
```