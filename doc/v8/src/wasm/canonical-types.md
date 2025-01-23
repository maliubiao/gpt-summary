Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and its relationship to JavaScript, illustrated with examples. This means we need to identify the core purpose of the code and how it interacts with the larger V8 engine, specifically regarding WebAssembly (Wasm) and its type system.

2. **Initial Scan for Keywords and Concepts:**  I'd start by quickly scanning the code for keywords and concepts related to type systems, WebAssembly, and JavaScript. I'd look for things like:
    * `wasm`
    * `type` (and variations like `TypeDef`, `ValueType`, `FunctionSig`, `StructType`, `ArrayType`, `CanonicalType`)
    * `canonical` (appears frequently, suggesting a core concept)
    * `index`
    * `module`
    * `javascript` (though this won't be directly in the C++, the request mentions it)
    * Synchronization primitives (`Mutex`, `MutexGuard`) - indicating thread safety considerations.
    * Data structures (`vector`, `unordered_set`, `unordered_map`)

3. **Identify the Core Class:** The `TypeCanonicalizer` class is central. Its methods and data members likely hold the key to the file's functionality.

4. **Analyze Key Methods:** I'd focus on the public methods and those that seem important based on their names:
    * `GetTypeCanonicalizer()`:  A global accessor, indicating this is a singleton or globally accessible object.
    * Constructors (`TypeCanonicalizer()`):  Initializes predefined types.
    * `AddRecursiveGroup()`, `AddRecursiveSingletonGroup()`: These methods seem related to registering or grouping types, and the "recursive" part hints at handling potentially self-referential types.
    * `CanonicalizeTypeDef()`:  This is crucial. The name strongly suggests a process of converting type definitions into a canonical form.
    * `IsCanonicalSubtype()`:  Performs subtype checking between canonical types.
    * `LookupFunctionSignature()`: Retrieves the canonical signature of a function.
    * `FindCanonicalGroup()`: Searches for existing canonical representations of type groups.
    * `PrepareForCanonicalTypeId()`:  Interacts with the V8 heap, suggesting integration with JavaScript object representation.

5. **Infer the Purpose of "Canonicalization":** The term "canonical" suggests creating a single, standard representation for equivalent types. Why do this?
    * **Efficiency:** Comparing canonical representations is faster than comparing potentially complex type definitions directly.
    * **Uniqueness:** Ensures that semantically identical types are treated as the same.
    * **Interoperability:**  Provides a consistent way to represent types across different parts of the Wasm engine.

6. **Understand the Data Structures:**  The class uses various data structures:
    * `canonical_supertypes_`:  Likely stores the supertype relationships for canonical types.
    * `canonical_groups_`, `canonical_singleton_groups_`:  Store collections of canonical type groups, distinguishing between single types and groups of mutually recursive types.
    * `canonical_function_sigs_`:  Stores canonical function signatures, allowing for efficient lookup.
    * `Zone`:  A memory management mechanism within V8, suggesting that canonical types are allocated in a specific memory region.

7. **Connect to JavaScript:** The presence of methods like `PrepareForCanonicalTypeId()` and the interaction with the `Heap` and `WeakFixedArray` strongly indicate a connection to JavaScript. WebAssembly needs to interact with JavaScript, and this likely involves representing Wasm types in a way that JavaScript can understand or at least reference. The "wrappers" mentioned in `PrepareForCanonicalTypeId` are a key clue.

8. **Formulate the Summary:** Based on the analysis, I would synthesize a summary focusing on the core responsibility: managing and canonicalizing Wasm types within V8. I'd emphasize the benefits of canonicalization (efficiency, uniqueness). I'd also highlight the handling of recursive types and the connection to JavaScript interoperability.

9. **Craft JavaScript Examples:**  To illustrate the connection to JavaScript, I'd think about scenarios where type information is relevant in the Wasm/JS interaction:
    * **Passing data between Wasm and JS:**  Function parameters and return values have types.
    * **Creating Wasm instances in JS:**  JavaScript needs to understand the types of imported and exported functions and data.
    * **Using the WebAssembly API:**  Methods like `WebAssembly.instantiate` and the resulting instance's exports involve type information.

    I'd create simple, illustrative examples that demonstrate these scenarios, focusing on the *observable* behavior from the JavaScript side related to types. I wouldn't need to show *how* the canonicalization happens internally, but rather the *effects* of having a type system.

10. **Review and Refine:** I'd reread the summary and examples to ensure clarity, accuracy, and consistency with the code analysis. I'd double-check that the examples accurately reflect typical Wasm/JS interaction patterns. For instance, the initial thought might be to directly show the canonical types in JS, but since those are internal C++ representations, the examples should focus on the JS-visible side of type interaction.

This iterative process of scanning, analyzing, inferring, and connecting concepts would lead to the well-structured summary and illustrative JavaScript examples. The key is to progressively build an understanding of the code's purpose and its role within the larger V8 ecosystem.
这个C++源代码文件 `canonical-types.cc` 的主要功能是**管理和规范化 WebAssembly (Wasm) 的类型**。它定义了一个 `TypeCanonicalizer` 类，负责将不同的 Wasm 类型定义映射到唯一的、规范的表示形式。这对于提高类型比较的效率，以及处理递归类型定义至关重要。

以下是该文件的一些关键功能点：

* **类型规范化 (Type Canonicalization):** 这是核心功能。`TypeCanonicalizer` 维护着一套规范的类型表示，并将 Wasm 模块中定义的各种类型（如函数签名、结构体、数组）转换为这些规范的形式。
* **处理递归类型 (Handling Recursive Types):** Wasm 允许定义相互引用的递归类型。`TypeCanonicalizer` 能够正确地识别和规范化这些递归类型，确保相同结构的递归类型被映射到相同的规范表示。它使用“组 (group)”的概念来处理相互递归的类型。
* **类型比较优化 (Type Comparison Optimization):** 通过将类型转换为规范形式，比较两个类型是否相等或是否存在子类型关系变得更加高效，只需要比较它们的规范表示即可。
* **与 Wasm 模块集成 (Integration with Wasm Module):**  `TypeCanonicalizer` 与 `WasmModule` 紧密集成，它接收 `WasmModule` 作为输入，并为模块中的每个类型分配一个规范的类型 ID。
* **线程安全 (Thread Safety):**  代码中使用了 `base::Mutex` 进行互斥锁保护，表明 `TypeCanonicalizer` 的操作是线程安全的，允许多个线程并发注册和访问类型。
* **预定义类型 (Predefined Types):**  `AddPredefinedArrayTypes()` 函数添加了一些预定义的数组类型 (例如 `i8` 和 `i16` 数组) 的规范表示。
* **子类型检查 (Subtype Checking):** 提供了 `IsCanonicalSubtype()` 方法来检查两个规范类型之间是否存在子类型关系。
* **内存管理 (Memory Management):** 使用 `Zone` 进行内存分配，这是一种轻量级的内存管理机制，用于管理与类型规范化相关的内存。

**与 JavaScript 的关系以及 JavaScript 示例:**

虽然这段代码是 C++，但它的功能直接影响着 WebAssembly 与 JavaScript 之间的互操作性。JavaScript 需要理解和处理来自 WebAssembly 模块的类型信息，例如函数的参数和返回值类型、导出的全局变量类型等。`TypeCanonicalizer` 确保了在 V8 引擎内部，这些类型信息有一致且高效的表示方式，从而支持 Wasm 与 JS 的无缝集成。

当 JavaScript 代码与 WebAssembly 模块交互时，V8 引擎会使用 `TypeCanonicalizer` 来处理涉及的类型。例如，当调用一个 WebAssembly 导出的函数时，V8 需要验证 JavaScript 传递的参数类型是否与 WebAssembly 函数的参数类型兼容。

**JavaScript 示例:**

假设我们有一个简单的 WebAssembly 模块，其中定义了一个接受 i32 类型参数并返回 i32 类型的函数：

```wat
(module
  (func $add (param $p i32) (result i32)
    local.get $p
    i32.const 1
    i32.add
  )
  (export "add" (func $add))
)
```

在 JavaScript 中加载和调用这个模块：

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
  0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03,
  0x61, 0x64, 0x64, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00,
  0x41, 0x01, 0x6a, 0x0b,
]);

WebAssembly.instantiate(wasmCode).then(module => {
  const addFunc = module.instance.exports.add;

  // 调用 WebAssembly 函数
  const result = addFunc(10);
  console.log(result); // 输出 11

  // 如果传递错误类型的参数，会抛出 TypeError
  try {
    addFunc("hello"); // 尝试传递字符串
  } catch (e) {
    console.error(e); // 输出 TypeError: Argument to wasm function 'add' must be of type number
  }
});
```

在这个例子中，当 JavaScript 调用 `addFunc(10)` 时，V8 引擎内部会使用 `TypeCanonicalizer` 来确定 WebAssembly 函数 `add` 的参数类型是 `i32`，并且 JavaScript 传递的 `10` 可以安全地转换为 `i32`。

当尝试调用 `addFunc("hello")` 时，`TypeCanonicalizer` 会检测到 JavaScript 传递的字符串类型与 WebAssembly 函数期望的 `i32` 类型不兼容，从而导致 `TypeError` 异常。

**总结:**

`v8/src/wasm/canonical-types.cc` 中的 `TypeCanonicalizer` 类是 V8 引擎中处理 WebAssembly 类型系统的关键组件。它负责将各种 Wasm 类型定义转换为统一的规范表示，从而提高类型比较效率，支持递归类型，并确保 WebAssembly 与 JavaScript 之间的类型兼容性，使得二者能够安全有效地进行互操作。虽然 JavaScript 开发者不会直接与 `TypeCanonicalizer` 交互，但它的工作是 WebAssembly 功能在 JavaScript 中正确运行的基础。

### 提示词
```
这是目录为v8/src/wasm/canonical-types.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/canonical-types.h"

#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/init/v8.h"
#include "src/roots/roots-inl.h"
#include "src/utils/utils.h"
#include "src/wasm/std-object-sizes.h"
#include "src/wasm/wasm-engine.h"

namespace v8::internal::wasm {

TypeCanonicalizer* GetTypeCanonicalizer() {
  return GetWasmEngine()->type_canonicalizer();
}

TypeCanonicalizer::TypeCanonicalizer() { AddPredefinedArrayTypes(); }

void TypeCanonicalizer::CheckMaxCanonicalIndex() const {
  if (V8_UNLIKELY(canonical_supertypes_.size() > kMaxCanonicalTypes)) {
    V8::FatalProcessOutOfMemory(nullptr, "too many canonicalized types");
  }
}

void TypeCanonicalizer::AddRecursiveGroup(WasmModule* module, uint32_t size) {
  AddRecursiveGroup(module, size,
                    static_cast<uint32_t>(module->types.size() - size));
}

void TypeCanonicalizer::AddRecursiveGroup(WasmModule* module, uint32_t size,
                                          uint32_t start_index) {
  if (size == 0) return;
  // If the caller knows statically that {size == 1}, it should have called
  // {AddRecursiveSingletonGroup} directly. For cases where this is not
  // statically determined we add this dispatch here.
  if (size == 1) return AddRecursiveSingletonGroup(module, start_index);

  // Multiple threads could try to register recursive groups concurrently.
  // TODO(manoskouk): Investigate if we can fine-grain the synchronization.
  base::MutexGuard mutex_guard(&mutex_);
  // Compute the first canonical index in the recgroup in the case that it does
  // not already exist.
  CanonicalTypeIndex first_new_canonical_index{
      static_cast<uint32_t>(canonical_supertypes_.size())};

  DCHECK_GE(module->types.size(), start_index + size);
  CanonicalGroup group{&zone_, size, first_new_canonical_index};
  for (uint32_t i = 0; i < size; i++) {
    group.types[i] = CanonicalizeTypeDef(
        module, ModuleTypeIndex{start_index + i}, ModuleTypeIndex{start_index},
        first_new_canonical_index);
  }
  if (CanonicalTypeIndex canonical_index = FindCanonicalGroup(group);
      canonical_index.valid()) {
    // Identical group found. Map new types to the old types's canonical
    // representatives.
    for (uint32_t i = 0; i < size; i++) {
      module->isorecursive_canonical_type_ids[start_index + i] =
          CanonicalTypeIndex{canonical_index.index + i};
    }
    // TODO(clemensb): Avoid leaking the zone storage allocated for {group}
    // (both for the {Vector} in {CanonicalGroup}, but also the storage
    // allocated in {CanonicalizeTypeDef{).
    return;
  }
  canonical_supertypes_.resize(first_new_canonical_index.index + size);
  CheckMaxCanonicalIndex();
  for (uint32_t i = 0; i < size; i++) {
    CanonicalType& canonical_type = group.types[i];
    canonical_supertypes_[first_new_canonical_index.index + i] =
        canonical_type.supertype;
    CanonicalTypeIndex canonical_id{first_new_canonical_index.index + i};
    module->isorecursive_canonical_type_ids[start_index + i] = canonical_id;
    if (canonical_type.kind == CanonicalType::kFunction) {
      const CanonicalSig* sig = canonical_type.function_sig;
      CHECK(canonical_function_sigs_.emplace(canonical_id, sig).second);
    }
  }
  // Check that this canonical ID is not used yet.
  DCHECK(std::none_of(
      canonical_singleton_groups_.begin(), canonical_singleton_groups_.end(),
      [=](auto& entry) { return entry.index == first_new_canonical_index; }));
  DCHECK(std::none_of(
      canonical_groups_.begin(), canonical_groups_.end(),
      [=](auto& entry) { return entry.start == first_new_canonical_index; }));
  canonical_groups_.emplace(group);
}

void TypeCanonicalizer::AddRecursiveSingletonGroup(WasmModule* module) {
  uint32_t start_index = static_cast<uint32_t>(module->types.size() - 1);
  return AddRecursiveSingletonGroup(module, start_index);
}

void TypeCanonicalizer::AddRecursiveSingletonGroup(WasmModule* module,
                                                   uint32_t start_index) {
  base::MutexGuard guard(&mutex_);
  DCHECK_GT(module->types.size(), start_index);
  CanonicalTypeIndex first_new_canonical_index{
      static_cast<uint32_t>(canonical_supertypes_.size())};
  CanonicalTypeIndex canonical_index = AddRecursiveGroup(CanonicalizeTypeDef(
      module, ModuleTypeIndex{start_index}, ModuleTypeIndex{start_index},
      first_new_canonical_index));
  module->isorecursive_canonical_type_ids[start_index] = canonical_index;
}

CanonicalTypeIndex TypeCanonicalizer::AddRecursiveGroup(
    const FunctionSig* sig) {
// Types in the signature must be module-independent.
#if DEBUG
  for (ValueType type : sig->all()) DCHECK(!type.has_index());
#endif
  const bool kFinal = true;
  const bool kNotShared = false;
  // Because of the checks above, we can treat the type_def as canonical.
  // TODO(366180605): It would be nice to not have to rely on a cast here.
  // Is there a way to avoid it? In the meantime, these asserts provide at
  // least partial assurances that the cast is safe:
  static_assert(sizeof(CanonicalValueType) == sizeof(ValueType));
  static_assert(CanonicalValueType::Primitive(kI32).raw_bit_field() ==
                ValueType::Primitive(kI32).raw_bit_field());
  CanonicalType canonical{reinterpret_cast<const CanonicalSig*>(sig),
                          CanonicalTypeIndex{kNoSuperType}, kFinal, kNotShared};
  base::MutexGuard guard(&mutex_);
  // Fast path lookup before canonicalizing (== copying into the
  // TypeCanonicalizer's zone) the function signature.
  CanonicalTypeIndex hypothetical_new_canonical_index{
      static_cast<uint32_t>(canonical_supertypes_.size())};
  CanonicalTypeIndex index = FindCanonicalGroup(
      CanonicalSingletonGroup{canonical, hypothetical_new_canonical_index});
  if (index.valid()) return index;
  // Copy into this class's zone, then call the generic {AddRecursiveGroup}.
  CanonicalSig::Builder builder(&zone_, sig->return_count(),
                                sig->parameter_count());
  for (ValueType ret : sig->returns()) {
    builder.AddReturn(CanonicalValueType{ret});
  }
  for (ValueType param : sig->parameters()) {
    builder.AddParam(CanonicalValueType{param});
  }
  canonical.function_sig = builder.Get();
  CanonicalTypeIndex canonical_index = AddRecursiveGroup(canonical);
  DCHECK_EQ(canonical_index, hypothetical_new_canonical_index);
  return canonical_index;
}

CanonicalTypeIndex TypeCanonicalizer::AddRecursiveGroup(CanonicalType type) {
  mutex_.AssertHeld();  // The caller must hold the mutex.
  CanonicalTypeIndex new_canonical_index{
      static_cast<uint32_t>(canonical_supertypes_.size())};
  CanonicalSingletonGroup group{type, new_canonical_index};
  if (CanonicalTypeIndex index = FindCanonicalGroup(group); index.valid()) {
    //  Make sure this signature can be looked up later.
    DCHECK_IMPLIES(type.kind == CanonicalType::kFunction,
                   canonical_function_sigs_.count(index));
    return index;
  }
  static_assert(kMaxCanonicalTypes <= kMaxUInt32);
  // Check that this canonical ID is not used yet.
  DCHECK(std::none_of(
      canonical_singleton_groups_.begin(), canonical_singleton_groups_.end(),
      [=](auto& entry) { return entry.index == new_canonical_index; }));
  DCHECK(std::none_of(
      canonical_groups_.begin(), canonical_groups_.end(),
      [=](auto& entry) { return entry.start == new_canonical_index; }));
  canonical_singleton_groups_.emplace(group);
  canonical_supertypes_.push_back(type.supertype);
  if (type.kind == CanonicalType::kFunction) {
    const CanonicalSig* sig = type.function_sig;
    CHECK(canonical_function_sigs_.emplace(new_canonical_index, sig).second);
  }
  CheckMaxCanonicalIndex();
  return new_canonical_index;
}

const CanonicalSig* TypeCanonicalizer::LookupFunctionSignature(
    CanonicalTypeIndex index) const {
  base::MutexGuard mutex_guard(&mutex_);
  auto it = canonical_function_sigs_.find(index);
  CHECK(it != canonical_function_sigs_.end());
  return it->second;
}

void TypeCanonicalizer::AddPredefinedArrayTypes() {
  static constexpr std::pair<CanonicalTypeIndex, CanonicalValueType>
      kPredefinedArrayTypes[] = {{kPredefinedArrayI8Index, {kWasmI8}},
                                 {kPredefinedArrayI16Index, {kWasmI16}}};
  for (auto [index, element_type] : kPredefinedArrayTypes) {
    DCHECK_EQ(index.index, canonical_singleton_groups_.size());
    static constexpr bool kMutable = true;
    // TODO(jkummerow): Decide whether this should be final or nonfinal.
    static constexpr bool kFinal = true;
    static constexpr bool kShared = false;  // TODO(14616): Fix this.
    CanonicalArrayType* type =
        zone_.New<CanonicalArrayType>(element_type, kMutable);
    CanonicalSingletonGroup group{
        .type = CanonicalType(type, CanonicalTypeIndex{kNoSuperType}, kFinal,
                              kShared),
        .index = index};
    canonical_singleton_groups_.emplace(group);
    canonical_supertypes_.emplace_back(CanonicalTypeIndex{kNoSuperType});
    DCHECK_LE(canonical_supertypes_.size(), kMaxCanonicalTypes);
  }
}

bool TypeCanonicalizer::IsCanonicalSubtype(CanonicalTypeIndex sub_index,
                                           CanonicalTypeIndex super_index) {
  // Fast path without synchronization:
  if (sub_index == super_index) return true;

  // Multiple threads could try to register and access recursive groups
  // concurrently.
  // TODO(manoskouk): Investigate if we can improve this synchronization.
  base::MutexGuard mutex_guard(&mutex_);
  while (sub_index.valid()) {
    if (sub_index == super_index) return true;
    sub_index = canonical_supertypes_[sub_index.index];
  }
  return false;
}

bool TypeCanonicalizer::IsCanonicalSubtype(ModuleTypeIndex sub_index,
                                           ModuleTypeIndex super_index,
                                           const WasmModule* sub_module,
                                           const WasmModule* super_module) {
  CanonicalTypeIndex canonical_super =
      super_module->canonical_type_id(super_index);
  CanonicalTypeIndex canonical_sub = sub_module->canonical_type_id(sub_index);
  return IsCanonicalSubtype(canonical_sub, canonical_super);
}

void TypeCanonicalizer::EmptyStorageForTesting() {
  base::MutexGuard mutex_guard(&mutex_);
  canonical_supertypes_.clear();
  canonical_groups_.clear();
  canonical_singleton_groups_.clear();
  canonical_function_sigs_.clear();
  zone_.Reset();
  AddPredefinedArrayTypes();
}

TypeCanonicalizer::CanonicalType TypeCanonicalizer::CanonicalizeTypeDef(
    const WasmModule* module, ModuleTypeIndex module_type_idx,
    ModuleTypeIndex recgroup_start,
    CanonicalTypeIndex canonical_recgroup_start) {
  mutex_.AssertHeld();  // The caller must hold the mutex.

  auto CanonicalizeTypeIndex = [=](ModuleTypeIndex type_index) {
    DCHECK(type_index.valid());
    return type_index < recgroup_start
               // This references a type from an earlier recgroup; use the
               // already-canonicalized type index.
               ? module->canonical_type_id(type_index)
               // For types within the same recgroup, generate indexes assuming
               // that this is a new canonical recgroup.
               : CanonicalTypeIndex{canonical_recgroup_start.index +
                                    (type_index.index - recgroup_start.index)};
  };

  auto CanonicalizeValueType = [=](ValueType type) {
    if (!type.has_index()) return CanonicalValueType{type};
    static_assert(kMaxCanonicalTypes <= (1u << ValueType::kHeapTypeBits));
    return CanonicalValueType::FromIndex(
        type.kind(), CanonicalizeTypeIndex(type.ref_index()));
  };

  TypeDefinition type = module->type(module_type_idx);
  CanonicalTypeIndex supertype = type.supertype.valid()
                                     ? CanonicalizeTypeIndex(type.supertype)
                                     : CanonicalTypeIndex::Invalid();
  switch (type.kind) {
    case TypeDefinition::kFunction: {
      const FunctionSig* original_sig = type.function_sig;
      CanonicalSig::Builder builder(&zone_, original_sig->return_count(),
                                    original_sig->parameter_count());
      for (ValueType ret : original_sig->returns()) {
        builder.AddReturn(CanonicalizeValueType(ret));
      }
      for (ValueType param : original_sig->parameters()) {
        builder.AddParam(CanonicalizeValueType(param));
      }
      return CanonicalType(builder.Get(), supertype, type.is_final,
                           type.is_shared);
    }
    case TypeDefinition::kStruct: {
      const StructType* original_type = type.struct_type;
      CanonicalStructType::Builder builder(&zone_,
                                           original_type->field_count());
      for (uint32_t i = 0; i < original_type->field_count(); i++) {
        builder.AddField(CanonicalizeValueType(original_type->field(i)),
                         original_type->mutability(i),
                         original_type->field_offset(i));
      }
      builder.set_total_fields_size(original_type->total_fields_size());
      return CanonicalType(
          builder.Build(CanonicalStructType::Builder::kUseProvidedOffsets),
          supertype, type.is_final, type.is_shared);
    }
    case TypeDefinition::kArray: {
      CanonicalValueType element_type =
          CanonicalizeValueType(type.array_type->element_type());
      CanonicalArrayType* array_type = zone_.New<CanonicalArrayType>(
          element_type, type.array_type->mutability());
      return CanonicalType(array_type, supertype, type.is_final,
                           type.is_shared);
    }
  }
}

// Returns the index of the canonical representative of the first type in this
// group if it exists, and `CanonicalTypeIndex::Invalid()` otherwise.
CanonicalTypeIndex TypeCanonicalizer::FindCanonicalGroup(
    const CanonicalGroup& group) const {
  // Groups of size 0 do not make sense here; groups of size 1 should use
  // {CanonicalSingletonGroup} (see below).
  DCHECK_LT(1, group.types.size());
  auto it = canonical_groups_.find(group);
  return it == canonical_groups_.end() ? CanonicalTypeIndex::Invalid()
                                       : it->start;
}

// Returns the canonical index of the given group if it already exists.
CanonicalTypeIndex TypeCanonicalizer::FindCanonicalGroup(
    const CanonicalSingletonGroup& group) const {
  auto it = canonical_singleton_groups_.find(group);
  static_assert(kMaxCanonicalTypes <= kMaxInt);
  return it == canonical_singleton_groups_.end() ? CanonicalTypeIndex::Invalid()
                                                 : it->index;
}

size_t TypeCanonicalizer::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(TypeCanonicalizer, 296);
  // The storage of the canonical group's types is accounted for via the
  // allocator below (which tracks the zone memory).
  base::MutexGuard mutex_guard(&mutex_);
  size_t result = ContentSize(canonical_supertypes_);
  result += ContentSize(canonical_groups_);
  result += ContentSize(canonical_singleton_groups_);
  result += ContentSize(canonical_function_sigs_);
  result += allocator_.GetCurrentMemoryUsage();
  if (v8_flags.trace_wasm_offheap_memory) {
    PrintF("TypeCanonicalizer: %zu\n", result);
  }
  return result;
}

size_t TypeCanonicalizer::GetCurrentNumberOfTypes() const {
  base::MutexGuard mutex_guard(&mutex_);
  return canonical_supertypes_.size();
}

// static
void TypeCanonicalizer::PrepareForCanonicalTypeId(Isolate* isolate,
                                                  CanonicalTypeIndex id) {
  if (!id.valid()) return;
  Heap* heap = isolate->heap();
  // {2 * (id + 1)} needs to fit in an int.
  CHECK_LE(id.index, kMaxInt / 2 - 1);
  // Canonical types and wrappers are zero-indexed.
  const int length = id.index + 1;
  // The fast path is non-handlified.
  Tagged<WeakFixedArray> old_rtts_raw = heap->wasm_canonical_rtts();
  Tagged<WeakFixedArray> old_wrappers_raw = heap->js_to_wasm_wrappers();

  // Fast path: Lengths are sufficient.
  int old_length = old_rtts_raw->length();
  DCHECK_EQ(old_length, old_wrappers_raw->length());
  if (old_length >= length) return;

  // Allocate bigger WeakFixedArrays for rtts and wrappers. Grow them
  // exponentially.
  const int new_length = std::max(old_length * 3 / 2, length);
  CHECK_LT(old_length, new_length);

  // Allocation can invalidate previous unhandled pointers.
  Handle<WeakFixedArray> old_rtts{old_rtts_raw, isolate};
  Handle<WeakFixedArray> old_wrappers{old_wrappers_raw, isolate};
  old_rtts_raw = old_wrappers_raw = {};

  // We allocate the WeakFixedArray filled with undefined values, as we cannot
  // pass the cleared value in a Handle (see https://crbug.com/364591622). We
  // overwrite the new entries via {MemsetTagged} afterwards.
  Handle<WeakFixedArray> new_rtts =
      WeakFixedArray::New(isolate, new_length, AllocationType::kOld);
  WeakFixedArray::CopyElements(isolate, *new_rtts, 0, *old_rtts, 0, old_length);
  MemsetTagged(new_rtts->RawFieldOfFirstElement() + old_length,
               ClearedValue(isolate), new_length - old_length);
  Handle<WeakFixedArray> new_wrappers =
      WeakFixedArray::New(isolate, new_length, AllocationType::kOld);
  WeakFixedArray::CopyElements(isolate, *new_wrappers, 0, *old_wrappers, 0,
                               old_length);
  MemsetTagged(new_wrappers->RawFieldOfFirstElement() + old_length,
               ClearedValue(isolate), new_length - old_length);
  heap->SetWasmCanonicalRttsAndJSToWasmWrappers(*new_rtts, *new_wrappers);
}

// static
void TypeCanonicalizer::ClearWasmCanonicalTypesForTesting(Isolate* isolate) {
  ReadOnlyRoots roots(isolate);
  isolate->heap()->SetWasmCanonicalRttsAndJSToWasmWrappers(
      roots.empty_weak_fixed_array(), roots.empty_weak_fixed_array());
}

bool TypeCanonicalizer::IsFunctionSignature(CanonicalTypeIndex index) const {
  base::MutexGuard mutex_guard(&mutex_);
  auto it = canonical_function_sigs_.find(index);
  return it != canonical_function_sigs_.end();
}

CanonicalTypeIndex TypeCanonicalizer::FindIndex_Slow(
    const CanonicalSig* sig) const {
  // TODO(jkummerow): Make this faster. The plan is to allocate an extra
  // slot in the Zone immediately preceding each CanonicalSig, so we can
  // get from the sig's address to that slot's address via pointer arithmetic.
  // For now, just search through all known signatures, which is acceptable
  // as long as only the type-reflection proposal needs this.
  // TODO(42210967): Improve this before shipping Type Reflection.
  for (auto [key, value] : canonical_function_sigs_) {
    if (value == sig) return key;
  }
  // If callers have a CanonicalSig* to pass into this function, the
  // type canonicalizer must know about this sig.
  UNREACHABLE();
}

#ifdef DEBUG
bool TypeCanonicalizer::Contains(const CanonicalSig* sig) const {
  base::MutexGuard mutex_guard(&mutex_);
  return zone_.Contains(sig);
}
#endif

}  // namespace v8::internal::wasm
```