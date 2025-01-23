Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Assessment and High-Level Understanding:**

* **File Name and Path:** `v8/src/heap/setup-heap-internal.cc`. Keywords here are "heap" and "setup."  This immediately suggests the file is involved in initializing the heap, a crucial part of V8's memory management. The `.cc` extension confirms it's C++ source code.
* **Copyright and License:** Standard V8 header, indicating its origins and licensing.
* **Includes:**  A large number of include files from the `src` directory. This tells us the file interacts with various core V8 components: API, builtins, codegen, execution, heap (obviously!), IC, initialization, interpreter, objects, regexp, roots, and utilities. The `#if V8_ENABLE_WEBASSEMBLY` section also hints at WebAssembly integration.
* **Namespace:** `v8::internal`. This confirms it's part of V8's internal implementation, not the public API.

**2. Examining Key Structures and Functions:**

* **Anonymous Namespace:**  The code starts with `namespace { ... }`. This is a common C++ practice to limit the scope of names within the file, preventing naming conflicts.
* **`CreateSharedFunctionInfo`:**  This function creates a `SharedFunctionInfo` object, which is fundamental for representing functions in V8. The arguments suggest it's for built-in functions.
* **`IsMutableMap` (ifdef DEBUG):** This debug-only function checks if a map is mutable based on its instance type and elements kind. The logic involving `IsJSObject`, `IsAlwaysSharedSpaceJSObject`, and WASM types indicates a concern for where different kinds of objects reside in memory (read-only vs. mutable).
* **`ConstantStringInit`, `kImportantConstantStringTable`, `kNotImportantConstantStringTable`:**  These structures and constant initializers deal with initializing string constants. The separation into "important" and "not important" hints at optimization strategies during startup.
* **`StringTypeInit`, `kStringTypeTable`:** Similar to the string constants, this handles initializing different string types (e.g., SeqOneByteString, ConsString).
* **`StructInit`, `kStructTable`, `is_important_struct`:**  This pattern continues for initializing structs, with a distinction between "important" ones.
* **`SetupIsolateDelegate::SetupHeapInternal`:** This is a key function. The logic checks if the read-only heap is initialized, then creates read-only and mutable heap objects. The comment about fitting read-only space in one page suggests performance considerations.
* **`Heap::CreateReadOnlyHeapObjects`:**  This function is responsible for creating various read-only heap objects, including maps and other fundamental structures. The comments about the order of creation are important for performance and memory layout.
* **`Heap::CreateMutableHeapObjects`:**  This function handles the creation of mutable heap objects.
* **`Heap::AllocateMap` and `Heap::AllocatePartialMap`:** These functions are central to allocating map objects, which are crucial for object representation in V8. The `AllocationType` parameter indicates whether the allocation is in read-only or mutable space.
* **`Heap::FinalizePartialMap`:**  This function completes the initialization of partially created maps.
* **`Heap::Allocate`:** A general allocation function that takes a map as input.
* **The large blocks of `ALLOCATE_AND_SET_ROOT`, `ALLOCATE_PARTIAL_MAP`, and `ALLOCATE_MAP` macros:**  These sections are doing the heavy lifting of allocating and initializing the core V8 objects and maps. The consistent naming pattern (`set_...`) indicates they are setting fields within the `Heap` object.

**3. Identifying Core Functionality:**

Based on the above examination, the core functionalities emerge:

* **Initialization of Read-Only Heap:** Creating fundamental, immutable objects and maps that are essential for V8's operation.
* **Initialization of Mutable Heap:** Creating objects that will change during V8's execution.
* **Allocation Mechanisms:** Providing functions for allocating different types of heap objects and maps in both read-only and mutable spaces.
* **Setting Up Core Objects:**  Creating essential objects like `undefined`, `null`, `true`, `false`, and empty collections.
* **Initializing Maps:** Creating and configuring map objects, which define the structure and behavior of other objects.

**4. Connecting to JavaScript and Torque:**

* **JavaScript Relationship:** The file creates the foundational objects and data structures that JavaScript code will manipulate. Examples include the maps for `String`, `Number`, `Boolean`, and the representation of `undefined` and `null`.
* **Torque:** The presence of `TORQUE_DEFINED_FIXED_INSTANCE_TYPE_LIST` and `TORQUE_DEFINED_VARSIZE_INSTANCE_TYPE_LIST` strongly suggests that this file interacts with Torque, V8's internal language for defining built-in functions and object layouts. If the file ended in `.tq`, it would *be* a Torque source file. Since it's `.cc`, it's using the output of Torque (likely generated C++ code or metadata).

**5. Code Logic and Assumptions:**

The code relies on the assumption that the underlying memory allocation is successful. The order of operations is critical, especially for the read-only heap, to optimize memory layout and access. The `DCHECK` statements are assertions that help ensure the correctness of these assumptions in debug builds.

**6. Common Programming Errors (Implicit):**

While the C++ code itself is carefully written, the *purpose* of this file relates to avoiding errors in higher-level JavaScript code:

* **Incorrect Object Type Handling:** By setting up the correct maps, V8 ensures that objects are treated according to their intended types.
* **Memory Corruption:**  Proper heap initialization is crucial for preventing memory corruption issues that can arise from uninitialized or incorrectly sized objects.

**7. Synthesizing the Summary (as in the prompt):**

Bringing all these observations together leads to the summary provided in the example answer. It highlights the core purpose of setting up the heap, differentiates between read-only and mutable objects, mentions the connection to JavaScript and Torque, and implicitly touches upon the importance of this code for overall V8 stability and performance.
这是目录为 `v8/src/heap/setup-heap-internal.cc` 的一个 V8 源代码文件，其主要功能是**负责在 V8 引擎启动时初始化堆（Heap）的内部结构和核心对象**。 这是构建 V8 运行时环境的关键步骤。

以下是根据提供的代码片段进行的功能归纳：

**核心功能:**

1. **创建只读堆对象 (Read-Only Heap Objects):**
   - 初始化在只读内存空间中存放的核心对象，这些对象在 V8 运行期间是不可变的。
   - 这包括基本类型的值（如 `undefined`, `null`, `true`, `false`），以及它们的映射 (maps)。
   - 还包括各种字符串类型、符号 (Symbol) 的映射。
   - 创建用于描述对象结构的元数据，例如 `meta_map`。
   - 创建一些重要的结构体类型的映射，例如 `EnumCache` 和 `CallSiteInfo` 的映射。
   - 这些只读对象为 V8 的高效运行提供了基础，避免了重复创建和修改这些基本对象。

2. **创建可变堆对象 (Mutable Heap Objects):**
   - 初始化在可变内存空间中存放的对象，这些对象在 V8 运行期间可以被修改。
   - 创建 `JSMessageObject` 和 `JSExternalObject` 的映射。
   - 初始化 API 相关的可变对象。
   - 创建初始的可变对象，例如内部访问器信息对象。
   - 初始化一些列表，用于管理垃圾回收和对象生命周期，例如 `native_contexts_list` 和 `allocation_sites_list`。

3. **分配和初始化映射 (Maps):**
   - `AllocateMap` 函数负责分配和初始化映射对象。映射是 V8 中描述对象结构的关键，包含了对象的类型、大小、属性等信息。
   - `AllocatePartialMap` 用于分配部分初始化的映射，后续再进行完善。
   - `FinalizePartialMap` 完成部分初始化映射的最终设置。
   - 代码中大量使用了 `ALLOCATE_MAP` 和 `ALLOCATE_PARTIAL_MAP` 宏，用于简化各种对象映射的创建。

4. **处理不同类型的对象:**
   - 代码中针对不同的对象类型（例如字符串、数字、布尔值、数组、函数等）创建了相应的映射。
   - 区分了重要的常量字符串和非重要的常量字符串，可能用于优化初始化过程。

5. **与 Torque 的关联 (根据文件名推测):**
   - 尽管代码片段是 `.cc` 文件，但如果存在 `.tq` 结尾的文件，那么 Torque 用于定义 V8 的内置函数和对象布局。
   - 这个 `.cc` 文件可能使用了 Torque 生成的代码或者数据结构来初始化堆。

**如果 `v8/src/heap/setup-heap-internal.cc` 以 `.tq` 结尾:**

那么它将是 **V8 Torque 源代码**。 Torque 是一种 V8 内部使用的领域特定语言，用于更安全、更易于维护的方式定义内置函数和对象布局。 Torque 代码会被编译成 C++ 代码，然后参与 V8 的构建。

**与 JavaScript 的功能关系:**

`v8/src/heap/setup-heap-internal.cc` 中创建的对象和映射是 JavaScript 运行时环境的基础。

**例如：**

- **`undefined_value` 和 `undefined_map`:**  代表 JavaScript 中的 `undefined` 值。
  ```javascript
  console.log(undefined); // JavaScript 中的 undefined
  ```

- **`null_value` 和 `null_map`:** 代表 JavaScript 中的 `null` 值。
  ```javascript
  console.log(null); // JavaScript 中的 null
  ```

- **字符串类型的映射 (`SeqOneByteStringMap` 等):**  用于创建和管理 JavaScript 中的字符串对象。
  ```javascript
  const str = "hello"; // JavaScript 中的字符串
  ```

- **数字类型的映射 (`HeapNumberMap`):** 用于创建和管理 JavaScript 中的数字对象。
  ```javascript
  const num = 123; // JavaScript 中的数字
  ```

- **布尔类型的映射 (`BooleanMap`):** 用于创建和管理 JavaScript 中的布尔值。
  ```javascript
  const bool = true; // JavaScript 中的布尔值
  ```

**代码逻辑推理 (假设输入与输出):**

这个文件主要进行初始化操作，不涉及复杂的运行时逻辑推理。它的“输入”是 V8 引擎启动的初始状态， “输出”是初始化完成的堆，包含了各种核心对象和映射。

**假设输入:**  V8 引擎开始启动，堆内存尚未初始化。

**输出:**  堆内存被填充了各种预先创建的只读对象（如 `undefined`, `null` 及其映射）和可变对象，为后续 JavaScript 代码的执行提供了必要的环境。

**涉及用户常见的编程错误 (间接):**

这个文件本身不直接涉及用户编写的 JavaScript 代码，但它所创建的基础设施对于避免某些编程错误至关重要。例如：

- **类型错误:** 通过精确地定义对象的映射，V8 能够在运行时正确地处理不同类型的 JavaScript 值，避免将数字误当成字符串等错误。
- **内存管理错误:**  堆的正确初始化是 V8 垃圾回收机制正常工作的基石，有助于防止内存泄漏等问题。

**总结 (针对第 1 部分):**

`v8/src/heap/setup-heap-internal.cc` 的第 1 部分主要负责 V8 堆的**早期初始化**，包括创建最核心的只读和可变对象及其映射。 它的目标是建立 V8 运行时环境的基础骨架，确保最基本的 JavaScript 值和对象类型能够被正确表示和管理。 这部分的工作为后续更复杂的堆对象和功能的初始化奠定了基础。

### 提示词
```
这是目录为v8/src/heap/setup-heap-internal.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/setup-heap-internal.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-natives.h"
#include "src/api/api.h"
#include "src/builtins/accessors.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/assert-scope.h"
#include "src/execution/isolate.h"
#include "src/execution/protectors.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/new-spaces.h"
#include "src/ic/handler-configuration.h"
#include "src/init/heap-symbols.h"
#include "src/init/setup-isolate.h"
#include "src/interpreter/interpreter.h"
#include "src/objects/arguments.h"
#include "src/objects/call-site-info.h"
#include "src/objects/cell-inl.h"
#include "src/objects/contexts.h"
#include "src/objects/data-handler.h"
#include "src/objects/debug-objects.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/dictionary.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-atomics-synchronization.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-shared-array.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/lookup-cache.h"
#include "src/objects/map.h"
#include "src/objects/microtask.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/promise.h"
#include "src/objects/property-descriptor-object.h"
#include "src/objects/script.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/smi.h"
#include "src/objects/source-text-module.h"
#include "src/objects/string.h"
#include "src/objects/synthetic-module.h"
#include "src/objects/template-objects-inl.h"
#include "src/objects/templates.h"
#include "src/objects/torque-defined-classes-inl.h"
#include "src/objects/turbofan-types.h"
#include "src/objects/turboshaft-types.h"
#include "src/regexp/regexp.h"
#include "src/roots/roots.h"
#include "src/utils/allocation.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

namespace {

Handle<SharedFunctionInfo> CreateSharedFunctionInfo(
    Isolate* isolate, Builtin builtin, int len,
    FunctionKind kind = FunctionKind::kNormalFunction) {
  Handle<SharedFunctionInfo> shared =
      isolate->factory()->NewSharedFunctionInfoForBuiltin(
          isolate->factory()->empty_string(), builtin, len, kAdapt, kind);
  return shared;
}

#ifdef DEBUG
bool IsMutableMap(InstanceType instance_type, ElementsKind elements_kind) {
  bool is_js_object = InstanceTypeChecker::IsJSObject(instance_type);
  bool is_always_shared_space_js_object =
      InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(instance_type);
  bool is_wasm_object = false;
#if V8_ENABLE_WEBASSEMBLY
  is_wasm_object =
      instance_type == WASM_STRUCT_TYPE || instance_type == WASM_ARRAY_TYPE;
#endif  // V8_ENABLE_WEBASSEMBLY
  DCHECK_IMPLIES(is_js_object &&
                     !Map::CanHaveFastTransitionableElementsKind(instance_type),
                 IsDictionaryElementsKind(elements_kind) ||
                     IsTerminalElementsKind(elements_kind) ||
                     (is_always_shared_space_js_object &&
                      elements_kind == SHARED_ARRAY_ELEMENTS));
  // JSObjects have maps with a mutable prototype_validity_cell, so they cannot
  // go in RO_SPACE. Maps for managed Wasm objects have mutable subtype lists.
  return (is_js_object && !is_always_shared_space_js_object) || is_wasm_object;
}
#endif

struct ConstantStringInit {
  const char* contents;
  RootIndex index;
};

constexpr std::initializer_list<ConstantStringInit>
#define CONSTANT_STRING_ELEMENT(_, name, contents) \
  {contents, RootIndex::k##name},
    kImportantConstantStringTable{
        EXTRA_IMPORTANT_INTERNALIZED_STRING_LIST_GENERATOR(
            CONSTANT_STRING_ELEMENT, /* not used */)
            IMPORTANT_INTERNALIZED_STRING_LIST_GENERATOR(
                CONSTANT_STRING_ELEMENT, /* not used */)
#undef CONSTANT_STRING_ELEMENT
    };

constexpr std::initializer_list<ConstantStringInit>
#define CONSTANT_STRING_ELEMENT(_, name, contents) \
  {contents, RootIndex::k##name},
    kNotImportantConstantStringTable{
        NOT_IMPORTANT_INTERNALIZED_STRING_LIST_GENERATOR(
            CONSTANT_STRING_ELEMENT, /* not used */)
#undef CONSTANT_STRING_ELEMENT
    };

struct StringTypeInit {
  InstanceType type;
  int size;
  RootIndex index;
};

constexpr std::initializer_list<StringTypeInit> kStringTypeTable{
#define STRING_TYPE_ELEMENT(type, size, name, CamelName) \
  {type, size, RootIndex::k##CamelName##Map},
    STRING_TYPE_LIST(STRING_TYPE_ELEMENT)
#undef STRING_TYPE_ELEMENT
};

struct StructInit {
  InstanceType type;
  int size;
  RootIndex index;
};

constexpr bool is_important_struct(InstanceType type) {
  return type == ENUM_CACHE_TYPE || type == CALL_SITE_INFO_TYPE;
}

constexpr std::initializer_list<StructInit> kStructTable{
#define STRUCT_TABLE_ELEMENT(TYPE, Name, name) \
  {TYPE, Name::kSize, RootIndex::k##Name##Map},
    STRUCT_LIST(STRUCT_TABLE_ELEMENT)
#undef STRUCT_TABLE_ELEMENT
#define ALLOCATION_SITE_ELEMENT(_, TYPE, Name, Size, name) \
  {TYPE, Name::kSize##Size, RootIndex::k##Name##Size##Map},
        ALLOCATION_SITE_LIST(ALLOCATION_SITE_ELEMENT, /* not used */)
#undef ALLOCATION_SITE_ELEMENT
#define DATA_HANDLER_ELEMENT(_, TYPE, Name, Size, name) \
  {TYPE, Name::kSizeWithData##Size, RootIndex::k##Name##Size##Map},
            DATA_HANDLER_LIST(DATA_HANDLER_ELEMENT, /* not used */)
#undef DATA_HANDLER_ELEMENT
};

}  // namespace

bool SetupIsolateDelegate::SetupHeapInternal(Isolate* isolate) {
  auto heap = isolate->heap();
  if (!isolate->read_only_heap()->roots_init_complete()) {
    if (!heap->CreateReadOnlyHeapObjects()) return false;
    isolate->VerifyStaticRoots();
    isolate->read_only_heap()->OnCreateRootsComplete(isolate);
  }
  // We prefer to fit all of read-only space in one page.
  CHECK_EQ(heap->read_only_space()->pages().size(), 1);
  auto ro_size = heap->read_only_space()->Size();
  DCHECK_EQ(heap->old_space()->Size(), 0);
  DCHECK_IMPLIES(heap->new_space(), heap->new_space()->Size() == 0);
  auto res = heap->CreateMutableHeapObjects();
  DCHECK_EQ(heap->read_only_space()->Size(), ro_size);
  USE(ro_size);
  return res;
}

bool Heap::CreateReadOnlyHeapObjects() {
  // Create initial maps and important objects.
  if (!CreateEarlyReadOnlyMapsAndObjects()) return false;
  if (!CreateImportantReadOnlyObjects()) return false;

#if V8_STATIC_ROOTS_BOOL
  // The read only heap is sorted such that often used objects are allocated
  // early for their compressed address to fit into 12bit arm immediates.
  ReadOnlySpace* ro_space = isolate()->heap()->read_only_space();
  DCHECK_LT(V8HeapCompressionScheme::CompressAny(ro_space->top()), 0xfff);
  USE(ro_space);
#endif

  if (!CreateLateReadOnlyNonJSReceiverMaps()) return false;
  CreateReadOnlyApiObjects();
  if (!CreateReadOnlyObjects()) return false;

  // Order is important. JSReceiver maps must come after all non-JSReceiver maps
  // in RO space with a sufficiently large gap in address. Currently there are
  // no JSReceiver instances in RO space.
  //
  // See InstanceTypeChecker::kNonJsReceiverMapLimit.
  if (!CreateLateReadOnlyJSReceiverMaps()) return false;

#ifdef DEBUG
  ReadOnlyRoots roots(isolate());
  for (auto pos = RootIndex::kFirstReadOnlyRoot;
       pos <= RootIndex::kLastReadOnlyRoot; ++pos) {
    DCHECK(roots.is_initialized(pos));
  }
#endif
  return true;
}

bool Heap::CreateMutableHeapObjects() {
  ReadOnlyRoots roots(this);

#define ALLOCATE_MAP(instance_type, size, field_name)                       \
  {                                                                         \
    Tagged<Map> map;                                                        \
    if (!AllocateMap(AllocationType::kMap, (instance_type), size).To(&map)) \
      return false;                                                         \
    set_##field_name##_map(map);                                            \
  }

  {  // Map allocation
    ALLOCATE_MAP(JS_MESSAGE_OBJECT_TYPE, JSMessageObject::kHeaderSize,
                 message_object)
    ALLOCATE_MAP(JS_EXTERNAL_OBJECT_TYPE, JSExternalObject::kHeaderSize,
                 external)
    external_map()->set_is_extensible(false);
  }
#undef ALLOCATE_MAP

  // Ensure that all young generation pages are iterable. It must be after heap
  // setup, so that the maps have been created.
  if (new_space()) new_space()->MakeIterable();

  CreateMutableApiObjects();

  // Create initial objects
  CreateInitialMutableObjects();
  CreateInternalAccessorInfoObjects();
  CHECK_EQ(0u, gc_count_);

  set_native_contexts_list(roots.undefined_value());
  set_allocation_sites_list(roots.undefined_value());
  set_dirty_js_finalization_registries_list(roots.undefined_value());
  set_dirty_js_finalization_registries_list_tail(roots.undefined_value());

  return true;
}

// Allocates contextless map in read-only or map (old) space.
AllocationResult Heap::AllocateMap(AllocationType allocation_type,
                                   InstanceType instance_type,
                                   int instance_size,
                                   ElementsKind elements_kind,
                                   int inobject_properties) {
  static_assert(LAST_JS_OBJECT_TYPE == LAST_TYPE);
  Tagged<HeapObject> result;
  DCHECK_EQ(allocation_type, IsMutableMap(instance_type, elements_kind)
                                 ? AllocationType::kMap
                                 : AllocationType::kReadOnly);
  AllocationResult allocation = AllocateRaw(Map::kSize, allocation_type);
  if (!allocation.To(&result)) return allocation;

  ReadOnlyRoots roots(this);
  result->set_map_after_allocation(isolate(), roots.meta_map(),
                                   SKIP_WRITE_BARRIER);
  Tagged<Map> map = isolate()->factory()->InitializeMap(
      Cast<Map>(result), instance_type, instance_size, elements_kind,
      inobject_properties, roots);

  return AllocationResult::FromObject(map);
}

namespace {
void InitializePartialMap(Isolate* isolate, Tagged<Map> map,
                          Tagged<Map> meta_map, InstanceType instance_type,
                          int instance_size) {
  map->set_map_after_allocation(isolate, meta_map, SKIP_WRITE_BARRIER);
  map->set_instance_type(instance_type);
  map->set_instance_size(instance_size);
  map->set_visitor_id(Map::GetVisitorId(map));
  map->set_inobject_properties_start_or_constructor_function_index(0);
  DCHECK(!IsJSObjectMap(map));
  map->set_prototype_validity_cell(Map::kPrototypeChainValidSmi, kRelaxedStore);
  map->SetInObjectUnusedPropertyFields(0);
  map->set_bit_field(0);
  map->set_bit_field2(0);
  int bit_field3 =
      Map::Bits3::EnumLengthBits::encode(kInvalidEnumCacheSentinel) |
      Map::Bits3::OwnsDescriptorsBit::encode(true) |
      Map::Bits3::ConstructionCounterBits::encode(Map::kNoSlackTracking);
  map->set_bit_field3(bit_field3);
  DCHECK(!map->is_in_retained_map_list());
  map->clear_padding();
  map->set_elements_kind(TERMINAL_FAST_ELEMENTS_KIND);
}
}  // namespace

AllocationResult Heap::AllocatePartialMap(InstanceType instance_type,
                                          int instance_size) {
  Tagged<Object> result;
  AllocationResult allocation =
      AllocateRaw(Map::kSize, AllocationType::kReadOnly);
  if (!allocation.To(&result)) return allocation;
  // Cast<Map> cannot be used due to uninitialized map field.
  Tagged<Map> map = UncheckedCast<Map>(result);
  InitializePartialMap(isolate(), map,
                       UncheckedCast<Map>(isolate()->root(RootIndex::kMetaMap)),
                       instance_type, instance_size);
  return AllocationResult::FromObject(map);
}

void Heap::FinalizePartialMap(Tagged<Map> map) {
  ReadOnlyRoots roots(this);
  map->set_dependent_code(DependentCode::empty_dependent_code(roots));
  map->set_raw_transitions(Smi::zero());
  map->SetInstanceDescriptors(isolate(), roots.empty_descriptor_array(), 0,
                              SKIP_WRITE_BARRIER);
  map->init_prototype_and_constructor_or_back_pointer(roots);
}

AllocationResult Heap::Allocate(DirectHandle<Map> map,
                                AllocationType allocation_type) {
  DCHECK(map->instance_type() != MAP_TYPE);
  int size = map->instance_size();
  Tagged<HeapObject> result;
  AllocationResult allocation = AllocateRaw(size, allocation_type);
  if (!allocation.To(&result)) return allocation;
  // New space objects are allocated white.
  WriteBarrierMode write_barrier_mode =
      allocation_type == AllocationType::kYoung ? SKIP_WRITE_BARRIER
                                                : UPDATE_WRITE_BARRIER;
  result->set_map_after_allocation(isolate(), *map, write_barrier_mode);
  return AllocationResult::FromObject(result);
}

bool Heap::CreateEarlyReadOnlyMapsAndObjects() {
  // Setup maps and objects which are used often, or used in
  // CreateImportantReadOnlyObjects.
  ReadOnlyRoots roots(this);

  // First create the following, in the following order:
  //   - Undefined value
  //   - Null value
  //   - Empty string
  //   - False value
  //   - True value
  //   - /String maps
  //     \...
  //   - Symbol map
  //   - Meta-map
  //   - Undefined map
  //   - Null map
  //   - Boolean map
  //
  // This is so that:
  //   1. The falsy values are the first in the space, allowing ToBoolean false
  //      checks to be a single less-than.
  //   2. The true value is immediately after the falsy values, so that we can
  //      use a single compare's condition flags to check both falsy and true.
  //   3. The string maps are all together, and are the first maps, allowing
  //      them to be checked with a single less-than if we know we have a map.
  //   4. The symbol map is with the string maps, for similarly fast Name
  //      checks.

  Tagged<HeapObject> obj;
  {
    // We're a bit loose with raw pointers here for readability -- this is all
    // guaranteed to be safe anyway since the allocations can't cause a GC, so
    // disable gcmole in this range.
    DisableGCMole no_gc_mole;

    // First, set up the roots to all point to the right offset in the
    // allocation folded allocation.
#define ALLOCATE_AND_SET_ROOT(Type, name, Size)                            \
  {                                                                        \
    AllocationResult alloc = AllocateRaw(Size, AllocationType::kReadOnly); \
    if (!alloc.To(&obj)) return false;                                     \
  }                                                                        \
  Tagged<Type> name = UncheckedCast<Type>(obj);                            \
  set_##name(name)

    ALLOCATE_AND_SET_ROOT(Undefined, undefined_value, sizeof(Undefined));
    ALLOCATE_AND_SET_ROOT(Null, null_value, sizeof(Null));
    ALLOCATE_AND_SET_ROOT(SeqOneByteString, empty_string,
                          SeqOneByteString::SizeFor(0));
    ALLOCATE_AND_SET_ROOT(False, false_value, sizeof(False));
    ALLOCATE_AND_SET_ROOT(True, true_value, sizeof(True));

    for (const StringTypeInit& entry : kStringTypeTable) {
      {
        AllocationResult alloc =
            AllocateRaw(Map::kSize, AllocationType::kReadOnly);
        if (!alloc.To(&obj)) return false;
      }
      Tagged<Map> map = UncheckedCast<Map>(obj);
      roots_table()[entry.index] = map.ptr();
    }
    ALLOCATE_AND_SET_ROOT(Map, symbol_map, Map::kSize);

    ALLOCATE_AND_SET_ROOT(Map, meta_map, Map::kSize);
    // Keep HeapNumber and Oddball maps together for cheap NumberOrOddball
    // checks.
    ALLOCATE_AND_SET_ROOT(Map, undefined_map, Map::kSize);
    ALLOCATE_AND_SET_ROOT(Map, null_map, Map::kSize);
    // Keep HeapNumber and Boolean maps together for cheap NumberOrBoolean
    // checks.
    ALLOCATE_AND_SET_ROOT(Map, boolean_map, Map::kSize);
    // Keep HeapNumber and BigInt maps together for cheaper numerics checks.
    ALLOCATE_AND_SET_ROOT(Map, heap_number_map, Map::kSize);
    ALLOCATE_AND_SET_ROOT(Map, bigint_map, Map::kSize);

#undef ALLOCATE_AND_SET_ROOT

    // Then, initialise the initial maps.
    InitializePartialMap(isolate(), meta_map, meta_map, MAP_TYPE, Map::kSize);
    InitializePartialMap(isolate(), undefined_map, meta_map, ODDBALL_TYPE,
                         sizeof(Undefined));
    InitializePartialMap(isolate(), null_map, meta_map, ODDBALL_TYPE,
                         sizeof(Null));
    InitializePartialMap(isolate(), boolean_map, meta_map, ODDBALL_TYPE,
                         sizeof(Boolean));
    boolean_map->SetConstructorFunctionIndex(Context::BOOLEAN_FUNCTION_INDEX);
    InitializePartialMap(isolate(), heap_number_map, meta_map, HEAP_NUMBER_TYPE,
                         sizeof(HeapNumber));
    heap_number_map->SetConstructorFunctionIndex(
        Context::NUMBER_FUNCTION_INDEX);
    InitializePartialMap(isolate(), bigint_map, meta_map, BIGINT_TYPE,
                         kVariableSizeSentinel);

    for (const StringTypeInit& entry : kStringTypeTable) {
      Tagged<Map> map = UncheckedCast<Map>(roots.object_at(entry.index));
      InitializePartialMap(isolate(), map, meta_map, entry.type, entry.size);
      map->SetConstructorFunctionIndex(Context::STRING_FUNCTION_INDEX);
      if (StringShape(entry.type).IsCons()) map->mark_unstable();
    }
    InitializePartialMap(isolate(), symbol_map, meta_map, SYMBOL_TYPE,
                         sizeof(Symbol));
    symbol_map->SetConstructorFunctionIndex(Context::SYMBOL_FUNCTION_INDEX);

    // Finally, initialise the non-map objects using those maps.
    undefined_value->set_map_after_allocation(isolate(), undefined_map,
                                              SKIP_WRITE_BARRIER);
    undefined_value->set_kind(Oddball::kUndefined);

    null_value->set_map_after_allocation(isolate(), null_map,
                                         SKIP_WRITE_BARRIER);
    null_value->set_kind(Oddball::kNull);

    true_value->set_map_after_allocation(isolate(), boolean_map,
                                         SKIP_WRITE_BARRIER);
    true_value->set_kind(Oddball::kTrue);

    false_value->set_map_after_allocation(isolate(), boolean_map,
                                          SKIP_WRITE_BARRIER);
    false_value->set_kind(Oddball::kFalse);

    // The empty string is initialised with an empty hash despite being
    // internalized -- this will be calculated once the hashseed is available.
    // TODO(leszeks): Unify this initialisation with normal string
    // initialisation.
    empty_string->set_map_after_allocation(
        isolate(), roots.unchecked_internalized_one_byte_string_map(),
        SKIP_WRITE_BARRIER);
    empty_string->clear_padding_destructively(0);
    empty_string->set_length(0);
    empty_string->set_raw_hash_field(String::kEmptyHashField);
  }

  // Now that the initial objects are allocated, we can start allocating other
  // objects where the order matters less.

#define ALLOCATE_PARTIAL_MAP(instance_type, size, field_name)                \
  {                                                                          \
    Tagged<Map> map;                                                         \
    if (!AllocatePartialMap((instance_type), (size)).To(&map)) return false; \
    set_##field_name##_map(map);                                             \
  }

  {  // Partial map allocation
    ALLOCATE_PARTIAL_MAP(FIXED_ARRAY_TYPE, kVariableSizeSentinel, fixed_array);
    ALLOCATE_PARTIAL_MAP(TRUSTED_FIXED_ARRAY_TYPE, kVariableSizeSentinel,
                         trusted_fixed_array);
    ALLOCATE_PARTIAL_MAP(PROTECTED_FIXED_ARRAY_TYPE, kVariableSizeSentinel,
                         protected_fixed_array);
    ALLOCATE_PARTIAL_MAP(WEAK_FIXED_ARRAY_TYPE, kVariableSizeSentinel,
                         weak_fixed_array);
    ALLOCATE_PARTIAL_MAP(TRUSTED_WEAK_FIXED_ARRAY_TYPE, kVariableSizeSentinel,
                         trusted_weak_fixed_array);
    ALLOCATE_PARTIAL_MAP(WEAK_ARRAY_LIST_TYPE, kVariableSizeSentinel,
                         weak_array_list);
    ALLOCATE_PARTIAL_MAP(FIXED_ARRAY_TYPE, kVariableSizeSentinel,
                         fixed_cow_array)
    DCHECK_NE(roots.fixed_array_map(), roots.fixed_cow_array_map());

    ALLOCATE_PARTIAL_MAP(DESCRIPTOR_ARRAY_TYPE, kVariableSizeSentinel,
                         descriptor_array)

    ALLOCATE_PARTIAL_MAP(HOLE_TYPE, Hole::kSize, hole);

    // Some struct maps which we need for later dependencies
    for (const StructInit& entry : kStructTable) {
      if (!is_important_struct(entry.type)) continue;
      Tagged<Map> map;
      if (!AllocatePartialMap(entry.type, entry.size).To(&map)) return false;
      roots_table()[entry.index] = map.ptr();
    }
  }
#undef ALLOCATE_PARTIAL_MAP

  {
    AllocationResult alloc =
        AllocateRaw(FixedArray::SizeFor(0), AllocationType::kReadOnly);
    if (!alloc.To(&obj)) return false;
    obj->set_map_after_allocation(isolate(), roots.fixed_array_map(),
                                  SKIP_WRITE_BARRIER);
    Cast<FixedArray>(obj)->set_length(0);
  }
  set_empty_fixed_array(Cast<FixedArray>(obj));

  {
    AllocationResult alloc =
        AllocateRaw(WeakFixedArray::SizeFor(0), AllocationType::kReadOnly);
    if (!alloc.To(&obj)) return false;
    obj->set_map_after_allocation(isolate(), roots.weak_fixed_array_map(),
                                  SKIP_WRITE_BARRIER);
    Cast<WeakFixedArray>(obj)->set_length(0);
  }
  set_empty_weak_fixed_array(Cast<WeakFixedArray>(obj));

  {
    AllocationResult allocation = AllocateRaw(WeakArrayList::SizeForCapacity(0),
                                              AllocationType::kReadOnly);
    if (!allocation.To(&obj)) return false;
    obj->set_map_after_allocation(isolate(), roots.weak_array_list_map(),
                                  SKIP_WRITE_BARRIER);
    Cast<WeakArrayList>(obj)->set_capacity(0);
    Cast<WeakArrayList>(obj)->set_length(0);
  }
  set_empty_weak_array_list(Cast<WeakArrayList>(obj));

  DCHECK(!HeapLayout::InYoungGeneration(roots.undefined_value()));
  {
    AllocationResult allocation =
        Allocate(roots.hole_map_handle(), AllocationType::kReadOnly);
    if (!allocation.To(&obj)) return false;
  }
  set_the_hole_value(Cast<Hole>(obj));

  // Set preliminary exception sentinel value before actually initializing it.
  set_exception(Cast<Hole>(obj));

  // Allocate the empty enum cache.
  {
    AllocationResult allocation =
        Allocate(roots.enum_cache_map_handle(), AllocationType::kReadOnly);
    if (!allocation.To(&obj)) return false;
  }
  set_empty_enum_cache(Cast<EnumCache>(obj));
  Cast<EnumCache>(obj)->set_keys(roots.empty_fixed_array());
  Cast<EnumCache>(obj)->set_indices(roots.empty_fixed_array());

  // Allocate the empty descriptor array.
  {
    int size = DescriptorArray::SizeFor(0);
    if (!AllocateRaw(size, AllocationType::kReadOnly).To(&obj)) return false;
    obj->set_map_after_allocation(isolate(), roots.descriptor_array_map(),
                                  SKIP_WRITE_BARRIER);
    Tagged<DescriptorArray> array = Cast<DescriptorArray>(obj);
    array->Initialize(roots.empty_enum_cache(), roots.undefined_value(), 0, 0,
                      DescriptorArrayMarkingState::kInitialGCState);
  }
  set_empty_descriptor_array(Cast<DescriptorArray>(obj));

  // Fix the instance_descriptors for the existing maps.
  FinalizePartialMap(roots.meta_map());
  FinalizePartialMap(roots.fixed_array_map());
  FinalizePartialMap(roots.trusted_fixed_array_map());
  FinalizePartialMap(roots.protected_fixed_array_map());
  FinalizePartialMap(roots.weak_fixed_array_map());
  FinalizePartialMap(roots.weak_array_list_map());
  FinalizePartialMap(roots.trusted_weak_fixed_array_map());
  FinalizePartialMap(roots.fixed_cow_array_map());
  FinalizePartialMap(roots.descriptor_array_map());
  FinalizePartialMap(roots.undefined_map());
  roots.undefined_map()->set_is_undetectable(true);
  FinalizePartialMap(roots.null_map());
  roots.null_map()->set_is_undetectable(true);
  FinalizePartialMap(roots.boolean_map());
  FinalizePartialMap(roots.heap_number_map());
  FinalizePartialMap(roots.bigint_map());
  FinalizePartialMap(roots.hole_map());
  FinalizePartialMap(roots.symbol_map());
  for (const StructInit& entry : kStructTable) {
    if (!is_important_struct(entry.type)) continue;
    FinalizePartialMap(Cast<Map>(roots.object_at(entry.index)));
  }
  for (const StringTypeInit& entry : kStringTypeTable) {
    FinalizePartialMap(Cast<Map>(roots.object_at(entry.index)));
  }

#define ALLOCATE_MAP(instance_type, size, field_name)                  \
  {                                                                    \
    Tagged<Map> map;                                                   \
    if (!AllocateMap(AllocationType::kReadOnly, (instance_type), size) \
             .To(&map)) {                                              \
      return false;                                                    \
    }                                                                  \
    set_##field_name##_map(map);                                       \
  }

#define ALLOCATE_VARSIZE_MAP(instance_type, field_name) \
  ALLOCATE_MAP(instance_type, kVariableSizeSentinel, field_name)

#define ALLOCATE_PRIMITIVE_MAP(instance_type, size, field_name, \
                               constructor_function_index)      \
  {                                                             \
    ALLOCATE_MAP((instance_type), (size), field_name);          \
    roots.field_name##_map()->SetConstructorFunctionIndex(      \
        (constructor_function_index));                          \
  }

  {  // Map allocation
    ALLOCATE_VARSIZE_MAP(SCOPE_INFO_TYPE, scope_info)
    ALLOCATE_VARSIZE_MAP(FIXED_ARRAY_TYPE, module_info)
    ALLOCATE_VARSIZE_MAP(CLOSURE_FEEDBACK_CELL_ARRAY_TYPE,
                         closure_feedback_cell_array)
    ALLOCATE_VARSIZE_MAP(FEEDBACK_VECTOR_TYPE, feedback_vector)

    ALLOCATE_MAP(FOREIGN_TYPE, Foreign::kSize, foreign)
    ALLOCATE_MAP(TRUSTED_FOREIGN_TYPE, TrustedForeign::kSize, trusted_foreign)
    ALLOCATE_MAP(MEGA_DOM_HANDLER_TYPE, MegaDomHandler::kSize, mega_dom_handler)

    ALLOCATE_VARSIZE_MAP(FIXED_DOUBLE_ARRAY_TYPE, fixed_double_array)
    roots.fixed_double_array_map()->set_elements_kind(HOLEY_DOUBLE_ELEMENTS);
    ALLOCATE_VARSIZE_MAP(FEEDBACK_METADATA_TYPE, feedback_metadata)
    ALLOCATE_VARSIZE_MAP(BYTE_ARRAY_TYPE, byte_array)
    ALLOCATE_VARSIZE_MAP(TRUSTED_BYTE_ARRAY_TYPE, trusted_byte_array)
    ALLOCATE_VARSIZE_MAP(BYTECODE_ARRAY_TYPE, bytecode_array)
    ALLOCATE_VARSIZE_MAP(FREE_SPACE_TYPE, free_space)
    ALLOCATE_VARSIZE_MAP(PROPERTY_ARRAY_TYPE, property_array)
    ALLOCATE_VARSIZE_MAP(SMALL_ORDERED_HASH_MAP_TYPE, small_ordered_hash_map)
    ALLOCATE_VARSIZE_MAP(SMALL_ORDERED_HASH_SET_TYPE, small_ordered_hash_set)
    ALLOCATE_VARSIZE_MAP(SMALL_ORDERED_NAME_DICTIONARY_TYPE,
                         small_ordered_name_dictionary)

    ALLOCATE_VARSIZE_MAP(INSTRUCTION_STREAM_TYPE, instruction_stream)

    ALLOCATE_MAP(CELL_TYPE, Cell::kSize, cell);
    {
      // The invalid_prototype_validity_cell is needed for JSObject maps.
      Tagged<Smi> value = Smi::FromInt(Map::kPrototypeChainInvalid);
      AllocationResult alloc =
          AllocateRaw(Cell::kSize, AllocationType::kReadOnly);
      if (!alloc.To(&obj)) return false;
      obj->set_map_after_allocation(isolate(), roots.cell_map(),
                                    SKIP_WRITE_BARRIER);
      Cast<Cell>(obj)->set_value(value);
      set_invalid_prototype_validity_cell(Cast<Cell>(obj));
    }

    ALLOCATE_MAP(PROPERTY_CELL_TYPE, PropertyCell::kSize, global_property_cell)
    ALLOCATE_MAP(FILLER_TYPE, kTaggedSize, one_pointer_filler)
    ALLOCATE_MAP(FILLER_TYPE, 2 * kTaggedSize, two_pointer_filler)

    // The "no closures" and "one closure" FeedbackCell maps need
    // to be marked unstable because their objects can change maps.
    ALLOCATE_MAP(FEEDBACK_CELL_TYPE, FeedbackCell::kAlignedSize,
                 no_closures_cell)
    roots.no_closures_cell_map()->mark_unstable();
    ALLOCATE_MAP(FEEDBACK_CELL_TYPE, FeedbackCell::kAlignedSize,
                 one_closure_cell)
    roots.one_closure_cell_map()->mark_unstable();
    ALLOCATE_MAP(FEEDBACK_CELL_TYPE, FeedbackCell::kAlignedSize,
                 many_closures_cell)

    ALLOCATE_VARSIZE_MAP(TRANSITION_ARRAY_TYPE, transition_array)

    ALLOCATE_VARSIZE_MAP(HASH_TABLE_TYPE, hash_table)
    ALLOCATE_VARSIZE_MAP(ORDERED_NAME_DICTIONARY_TYPE, ordered_name_dictionary)
    ALLOCATE_VARSIZE_MAP(NAME_DICTIONARY_TYPE, name_dictionary)
    ALLOCATE_VARSIZE_MAP(SWISS_NAME_DICTIONARY_TYPE, swiss_name_dictionary)
    ALLOCATE_VARSIZE_MAP(GLOBAL_DICTIONARY_TYPE, global_dictionary)
    ALLOCATE_VARSIZE_MAP(NUMBER_DICTIONARY_TYPE, number_dictionary)

    ALLOCATE_VARSIZE_MAP(REGISTERED_SYMBOL_TABLE_TYPE, registered_symbol_table)

    ALLOCATE_VARSIZE_MAP(ARRAY_LIST_TYPE, array_list)

    ALLOCATE_MAP(ACCESSOR_INFO_TYPE, AccessorInfo::kSize, accessor_info)

    ALLOCATE_VARSIZE_MAP(PREPARSE_DATA_TYPE, preparse_data)
    ALLOCATE_MAP(SHARED_FUNCTION_INFO_TYPE, SharedFunctionInfo::kSize,
                 shared_function_info)
    ALLOCATE_MAP(CODE_TYPE, Code::kSize, code)

    return true;
  }
}

bool Heap::CreateLateReadOnlyNonJSReceiverMaps() {
  ReadOnlyRoots roots(this);
  {
    // Setup the struct maps.
    for (const StructInit& entry : kStructTable) {
      if (is_important_struct(entry.type)) continue;
      Tagged<Map> map;
      if (!AllocateMap(AllocationType::kReadOnly, entry.type, entry.size)
               .To(&map))
        return false;
      roots_table()[entry.index] = map.ptr();
    }

#define TORQUE_ALLOCATE_MAP(NAME, Name, name) \
  ALLOCATE_MAP(NAME, Name::SizeFor(), name)
    TORQUE_DEFINED_FIXED_INSTANCE_TYPE_LIST(TORQUE_ALLOCATE_MAP);
#undef TORQUE_ALLOCATE_MAP

#define TORQUE_ALLOCATE_VARSIZE_MAP(NAME, Name, name)                   \
  /* The DescriptorArray map is pre-allocated and initialized above. */ \
  if (NAME != DESCRIPTOR_ARRAY_TYPE) {                                  \
    ALLOCATE_VARSIZE_MAP(NAME, name)                                    \
  }
    TORQUE_DEFINED_VARSIZE_INSTANCE_TYPE_LIST(TORQUE_ALLOCATE_VARSIZE_MAP);
#undef TORQUE_ALLOCATE_VARSIZE_MAP

    ALLOCATE_VARSIZE_MAP(ORDERED_HASH_MAP_TYPE, ordered_hash_map)
    ALLOCATE_VARSIZE_MAP(ORDERED_HASH_SET_TYPE, ordered_hash_set)

    ALLOCATE_VARSIZE_MAP(SIMPLE_NUMBER_DICTIONARY_TYPE,
                         simple_number_dictionary)
    ALLOCATE_VARSIZE_MAP(NAME_TO_INDEX_HASH_TABLE_TYPE,
                         name_to_index_hash_table)

    ALLOCATE_VARSIZE_MAP(EMBEDDER_DATA_ARRAY_TYPE, embedder_data_array)
    ALLOCATE_VARSIZE_MAP(EPHEMERON_HASH_TABLE_TYPE, ephemeron_hash_table)

    ALLOCATE_VARSIZE_MAP(SCRIPT_CONTEXT_TABLE_TYPE, script_context_table)

    ALLOCATE_VARSIZE_MAP(OBJECT_BOILERPLATE_DESCRIPTION_TYPE,
                         object_boilerplate_description)

    ALLOCATE_VARSIZE_MAP(COVERAGE_INFO_TYPE, coverage_info);
    ALLOCATE_VARSIZE_MAP(REG_EXP_MATCH_INFO_TYPE, regexp_match_info);

    ALLOCATE_MAP(REG_EXP_DATA_TYPE, RegExpData::kSize, regexp_data);
    ALLOCATE_MAP(ATOM_REG_EXP_DATA_TYPE, AtomRegExpData::kSize,
                 atom_regexp_data);
    ALLOCATE_MAP(IR_REG_EXP_DATA_TYPE, IrRegExpData::kSize, ir_regexp_data);

    ALLOCATE_MAP(SOURCE_TEXT_MODULE_TYPE, SourceTextModule::kSize,
                 source_text_module)
    ALLOCATE_MAP(SYNTHETIC_MODULE_TYPE, SyntheticModule::kSize,
                 synthetic_module)

    ALLOCATE_MAP(CONTEXT_SIDE_PROPERTY_CELL_TYPE,
                 ContextSidePropertyCell::kSize,
                 global_context_side_property_cell)

    IF_WASM(ALLOCATE_MAP, WASM_IMPORT_DATA_TYPE, WasmImportData::kSize,
            wasm_import_data)
    IF_WASM(ALLOCATE_MAP, WASM_CAPI_FUNCTION_DATA_TYPE,
            WasmCapiFunctionData::kSize, wasm_capi_function_data)
    IF_WASM(ALLOCATE_MAP, WASM_EXPORTED_FUNCTION_DATA_TYPE,
            WasmExportedFunctionData::kSize, wasm_exported_function_data)
    IF_WASM(ALLOCATE_MAP, WASM_INTERNAL_FUNCTION_TYPE,
            WasmInternalFunction::kSize, wasm_internal_function)
    IF_WASM(ALLOCATE_MAP, WASM_FUNC_REF_TYPE, WasmFuncRef::kSize, wasm_func_ref)
    IF_WASM(ALLOCATE_MAP, WASM_JS_FUNCTION_DATA_TYPE, WasmJSFunctionData::kSize,
            wasm_js_function_data)
    IF_WASM(ALLOCATE_MAP, WASM_RESUME_DATA_TYPE, WasmResumeData::kSize,
            wasm_resume_data)
    IF_WASM(ALLOCATE_MAP, WASM_SUSPEN
```