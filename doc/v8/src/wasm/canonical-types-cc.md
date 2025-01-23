Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request is to understand the functionality of `v8/src/wasm/canonical-types.cc`. Specifically, it asks for:
    * A summary of its functions.
    * Identification as Torque code (based on the `.tq` extension).
    * Connections to JavaScript and examples.
    * Logic reasoning with inputs/outputs.
    * Common programming errors.

2. **Initial Scan for Clues:**  Quickly skim the code for keywords and structure:
    * Includes: `canonical-types.h`, `execution/isolate.h`, `handles-inl.h`, `heap-inl.h`, `init/v8.h`, `roots-inl.h`, `utils/utils.h`, `wasm/std-object-sizes.h`, `wasm/wasm-engine.h`. These point to V8 internals, WASM specifics, memory management, and core V8 initialization.
    * Namespace: `v8::internal::wasm`. Confirms this is WASM-related within V8.
    * Class: `TypeCanonicalizer`. This seems to be the central class, and its methods will likely define the file's functionality.
    * Methods:  `GetTypeCanonicalizer`, `AddRecursiveGroup`, `AddRecursiveSingletonGroup`, `CanonicalizeTypeDef`, `IsCanonicalSubtype`, `LookupFunctionSignature`, etc. These method names suggest operations related to type management, especially with concepts like "canonical" and "recursive."
    * Data members: `canonical_supertypes_`, `canonical_groups_`, `canonical_singleton_groups_`, `canonical_function_sigs_`, `mutex_`, `zone_`. These appear to be data structures holding canonical type information and a mutex for thread safety.

3. **Deduce Core Functionality (Type Canonicalization):** The repeated use of "canonical" strongly suggests that this code is responsible for *canonicalizing* WASM types. Canonicalization, in this context, likely means finding a single, standard representation for equivalent types. This is important for efficiency and comparing types correctly.

4. **Analyze Key Methods:**  Focus on the most descriptive methods:
    * `AddRecursiveGroup`, `AddRecursiveSingletonGroup`: These likely handle the registration of possibly mutually recursive type definitions. The "recursive" part is a strong indicator.
    * `CanonicalizeTypeDef`: This seems to be the core logic for converting a WASM module's type definition into its canonical form.
    * `IsCanonicalSubtype`:  This directly addresses subtype relationships between canonical types.
    * `LookupFunctionSignature`:  Specific to function types, indicating the storage and retrieval of canonical function signatures.

5. **Address Specific Questions:**
    * **`.tq` Extension:** The code has `.cc` extension, so it's C++, not Torque. This is a direct contradiction to the prompt's assumption.
    * **JavaScript Relationship:**  Consider *why* WASM types need to be canonicalized. It's often to facilitate interoperability with JavaScript. When WASM code interacts with JS, their type systems need to be aligned. Canonicalization provides a common ground for this. Examples would involve passing WASM functions or data structures to JS, and vice-versa.
    * **Logic Reasoning:** Choose a relatively simple method like `IsCanonicalSubtype`. Think about how subtype relationships are determined based on the stored `canonical_supertypes_`. Define simple inputs (canonical type indices) and predict the output (true/false).
    * **Common Programming Errors:**  Think about potential issues with type systems and comparisons. Incorrect type checking, assuming structural equality when it doesn't exist, or mismatches between WASM and JS types are all possibilities.

6. **Structure the Answer:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * Address the `.tq` question directly and correct the assumption.
    * Explain the connection to JavaScript with relevant examples.
    * Provide a logic reasoning example with clear inputs and outputs.
    * List common programming errors related to type mismatches.

7. **Refine and Elaborate:**  Go back and add more detail:
    * Explain the role of the `TypeCanonicalizer` class.
    * Describe the data structures used for storing canonical types.
    * Elaborate on the implications of recursive types.
    * Ensure the JavaScript examples are clear and illustrate the concept.

8. **Review and Correct:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might just say "it manages WASM types." Refining this to "manages the canonical representation of WASM types" is more precise.

By following these steps, we can systematically analyze the code and generate a comprehensive answer that addresses all aspects of the request. The process involves understanding the code's structure, deducing its purpose, analyzing key components, and then relating the technical details to the broader context of WASM and JavaScript interoperability. The key is to move from general observations to specific examples and explanations.
好的，让我们来分析一下 `v8/src/wasm/canonical-types.cc` 这个文件的功能。

**功能概要:**

`v8/src/wasm/canonical-types.cc` 文件实现了 V8 中 WebAssembly 模块的类型规范化（canonicalization）功能。其核心目的是为 WebAssembly 模块中定义的类型找到一个唯一的、标准的表示形式，以便在比较和处理这些类型时能够保持一致性。

**详细功能分解:**

1. **类型规范化 (Type Canonicalization):** 这是该文件的主要功能。它负责将 WebAssembly 模块中定义的各种类型（例如，函数签名、结构体、数组等）转换为规范的表示形式。
    * **递归类型的处理:**  WebAssembly 允许定义递归类型，该文件能够正确处理这些类型的规范化，避免无限循环。
    * **结构体和数组的规范化:**  它会考虑结构体字段的类型和可变性，以及数组元素的类型和可变性来进行规范化。
    * **函数签名的规范化:**  它会考虑函数的参数类型和返回类型来进行规范化。

2. **维护规范类型集合:** `TypeCanonicalizer` 类内部维护了已规范化类型的集合，避免重复创建相同的规范类型，从而节省内存和提高效率。
    * `canonical_supertypes_`:  存储规范化类型的父类型关系，用于判断类型的子类型关系。
    * `canonical_groups_`:  存储规范化类型组，用于处理递归类型。
    * `canonical_singleton_groups_`: 存储单个规范化类型。
    * `canonical_function_sigs_`: 存储规范化的函数签名。

3. **判断类型关系:**  提供了方法来判断两个类型是否是子类型关系 (`IsCanonicalSubtype`)。这对于类型检查和优化非常重要。

4. **预定义类型:**  包含预定义的规范数组类型，例如 `i8` 数组和 `i16` 数组。

5. **内存管理:**  使用 `Zone` 进行内存管理，用于存储规范化的类型信息。

6. **线程安全:** 使用互斥锁 (`mutex_`) 来保证在多线程环境下的线程安全。

**关于文件扩展名 `.tq`:**

你提到的 `.tq` 扩展名通常用于 V8 的 Torque 语言源文件。  然而，根据你提供的代码内容，`v8/src/wasm/canonical-types.cc` 是一个 **C++** 源文件，因为它包含了 C++ 的头文件 (`#include`)，使用了 C++ 的命名空间 (`namespace`)，并且实现了 C++ 类 (`TypeCanonicalizer`)。因此，你的判断是错误的。

**与 JavaScript 的关系及示例:**

`v8/src/wasm/canonical-types.cc`  与 JavaScript 的功能有密切关系，因为它直接影响了 WebAssembly 和 JavaScript 之间的互操作性。当 JavaScript 调用 WebAssembly 函数或 WebAssembly 代码操作 JavaScript 对象时，类型系统的兼容性至关重要。

**示例说明:**

假设我们在 WebAssembly 中定义了一个类型：

```wat
(module
  (type $my_struct (struct (field i32) (field f64)))
  (func (export "get_struct") (result $my_struct)
    (struct.new $my_struct (i32.const 10) (f64.const 3.14))
  )
)
```

在 JavaScript 中，当我们调用 `get_struct` 函数时，V8 需要能够理解并表示 WebAssembly 返回的结构体类型。`TypeCanonicalizer` 的作用就是确保 WebAssembly 的 `$my_struct` 类型能够被 V8 内部表示为一个规范的形式，并且可以与 JavaScript 中的对象进行交互（例如，访问结构体的字段）。

**JavaScript 示例:**

```javascript
async function runWasm() {
  const response = await fetch('my_module.wasm'); // 假设有编译好的 wasm 文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  const myStruct = instance.exports.get_struct();
  // V8 内部会使用规范化的类型信息来处理 myStruct
  console.log(myStruct); //  可能需要特定的 API 或方式来访问结构体字段
}

runWasm();
```

在这个例子中，`TypeCanonicalizer` 确保了 WebAssembly 模块中定义的结构体类型 `$my_struct` 在 V8 内部有一个统一的表示，使得 JavaScript 能够安全地接收和处理来自 WebAssembly 的数据。  虽然 JavaScript 代码本身不会直接调用 `TypeCanonicalizer` 的方法，但它的工作对于 WebAssembly 模块在 V8 中的正确执行和与 JavaScript 的交互至关重要。

**代码逻辑推理及假设输入与输出:**

让我们以 `IsCanonicalSubtype` 方法为例进行代码逻辑推理。

**方法签名:**

```c++
bool TypeCanonicalizer::IsCanonicalSubtype(CanonicalTypeIndex sub_index,
                                           CanonicalTypeIndex super_index);
```

**假设输入:**

* `sub_index`: 一个有效的 `CanonicalTypeIndex`，例如表示一个特定的结构体类型。假设其 `index` 值为 `5`。
* `super_index`: 另一个有效的 `CanonicalTypeIndex`，例如表示该结构体类型的父类型（如果存在）。假设其 `index` 值为 `2`。

**内部状态假设:**

假设 `canonical_supertypes_` 数组中存储了以下父类型关系：

```
canonical_supertypes_[5] = { index: 2 } // 索引为 5 的类型的父类型索引为 2
canonical_supertypes_[2] = { index: 0 } // 索引为 2 的类型的父类型索引为 0
canonical_supertypes_[0] = { valid_: false } // 索引为 0 的类型没有父类型
```

**代码逻辑推理:**

1. 首先，会进行快速路径检查： `if (sub_index == super_index) return true;`。在本例中，`5 != 2`，所以跳过。

2. 获取互斥锁以保证线程安全。

3. 进入 `while (sub_index.valid())` 循环，因为 `sub_index` (5) 是有效的。

4. 循环第一次迭代：
   * 检查 `if (sub_index == super_index) return true;`。 `5 != 2`，所以继续。
   * 更新 `sub_index = canonical_supertypes_[sub_index.index];`，即 `sub_index` 变为 `canonical_supertypes_[5]`, 其值为 `{ index: 2 }`。

5. 循环第二次迭代：
   * 检查 `if (sub_index == super_index) return true;`。此时，`sub_index` 的 `index` 为 `2`，与 `super_index` 的 `index` 相等，所以返回 `true`。

**预期输出:** `true`，表示 `sub_index` 代表的类型是 `super_index` 代表的类型的子类型。

**假设输入 2 (非子类型):**

* `sub_index`:  `CanonicalTypeIndex`，`index` 值为 `7`。
* `super_index`: `CanonicalTypeIndex`，`index` 值为 `1`.

**内部状态假设:**

```
canonical_supertypes_[7] = { index: 8 }
canonical_supertypes_[8] = { index: 9 }
canonical_supertypes_[9] = { valid_: false }
```

**代码逻辑推理:**

循环会遍历 `7 -> 8 -> 9 -> Invalid()`，始终不会遇到 `super_index` 的值 `1`。

**预期输出:** `false`。

**用户常见的编程错误 (与类型相关):**

1. **WebAssembly 和 JavaScript 之间的类型不匹配:**  当 JavaScript 代码尝试向 WebAssembly 函数传递错误类型的参数，或者尝试以不兼容的方式处理 WebAssembly 返回的值时，会导致错误。

   **示例:**

   ```javascript
   // WebAssembly 函数期望接收 i32
   // (func (export "add") (param i32 i32) (result i32) ...)

   const result = instance.exports.add("hello", 10); // 错误：传递了字符串
   ```

2. **假设 WebAssembly 类型的结构与 JavaScript 对象相同:**  WebAssembly 的结构体和数组与 JavaScript 的对象和数组在内存布局和行为上可能不同。直接将 WebAssembly 的结构体或数组视为普通的 JavaScript 对象或数组可能会导致错误。

3. **忽略 WebAssembly 的类型约束:**  WebAssembly 是一门强类型语言，忽略其类型约束，例如尝试将一个 `f32` 的值赋给一个期望 `i32` 的变量，会导致错误。

4. **在 JavaScript 中错误地处理 WebAssembly 的引用类型 (ref):**  WebAssembly 的引用类型需要特殊处理，例如使用 `WebAssembly.Table` 或 `WebAssembly.Memory` 来管理和访问。直接将引用类型的值视为普通的数值或对象会导致错误。

5. **忘记考虑 WebAssembly 的数值类型范围:**  例如，JavaScript 的 `Number` 类型是双精度浮点数，而 WebAssembly 有多种整数和浮点数类型 (i32, i64, f32, f64)。在两者之间传递数据时，可能会发生精度损失或溢出。

`v8/src/wasm/canonical-types.cc` 的作用正是为了帮助 V8 运行时正确理解和处理 WebAssembly 的类型，从而减少这些由于类型不匹配导致的编程错误，并确保 WebAssembly 和 JavaScript 能够安全有效地互操作。

### 提示词
```
这是目录为v8/src/wasm/canonical-types.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/canonical-types.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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