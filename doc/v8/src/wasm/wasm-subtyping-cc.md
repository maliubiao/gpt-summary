Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Initial Understanding - The Big Picture:**  The file name `wasm-subtyping.cc` immediately suggests this code deals with type relationships (specifically subtyping) within the WebAssembly (Wasm) context in the V8 engine. The `#include` directives confirm this, pointing to other Wasm-related V8 components like `canonical-types.h` and `wasm-module.h`. The namespace `v8::internal::wasm` reinforces this.

2. **Deconstructing by Sections (Functions and Logic Blocks):**  The most effective way to understand code like this is to examine its constituent parts. I'll go through the code and identify the main functions and logical groupings.

   * **`EquivalentIndices`:**  This looks like a helper to check if two type indices (references to types within modules) from potentially different modules actually refer to the *same* canonical type. The `canonical_type_id` is the key here.

   * **`ValidStructSubtypeDefinition`:**  This function clearly implements the rules for determining if one Wasm struct type is a valid subtype of another. The checks for field count, mutability, and field type compatibility are the core logic. The use of `IsSubtypeOf` suggests a recursive relationship.

   * **`ValidArraySubtypeDefinition`:** Similar to structs, this function checks the validity of array subtyping based on mutability and the element type.

   * **`ValidFunctionSubtypeDefinition`:** This function implements the contravariant/covariant rules for function subtyping. Parameters are contravariant (supertype of the super), and return types are covariant (subtype of the super).

   * **`NullSentinelImpl` and `IsNullSentinel`:** These functions deal with the concept of "null sentinels" for various Wasm types. The `NullSentinelImpl` function maps a given heap type to its corresponding null representation. `IsNullSentinel` checks if a given heap type is a null sentinel. This is important for handling nullable references.

   * **`ValidSubtypeDefinition`:** This is a higher-level function that dispatches to the more specific `Valid...SubtypeDefinition` functions based on the type kind (function, struct, array). It also performs some initial checks (kind, finality, sharedness).

   * **`IsShared` (two versions):** These functions determine if a given Wasm type (either `HeapType` or `ValueType`) involves shared memory.

   * **`MaybeShared`:** This function appears to convert a non-shared heap type representation to its shared counterpart.

   * **`IsSubtypeOfImpl` (two versions):** This is the core subtyping check. It handles primitive types, the `top` and `bottom` types, and delegates to `IsHeapSubtypeOfImpl` for reference types. The logic for nullable references is handled here.

   * **`IsHeapSubtypeOfImpl`:** This function implements the subtyping rules for Wasm heap types. It has a large switch statement covering various heap type combinations and handles type indices by calling `GetTypeCanonicalizer()->IsCanonicalSubtype`.

   * **`EquivalentTypes`:** Checks if two `ValueType`s from potentially different modules are equivalent.

   * **`CommonAncestor` and `CommonAncestorWithAbstract`:** These functions calculate the least common ancestor (join) of two types, which is important for type unions. The `WithAbstract` version handles cases where one of the types is an abstract heap type.

   * **`Union`:** Calculates the union (least upper bound) of two `ValueType`s.

   * **`Intersection`:** Calculates the intersection (greatest lower bound) of two `ValueType`s.

   * **`ToNullSentinel`:**  Converts a `TypeInModule` to its corresponding null sentinel `ValueType`.

   * **`IsSameTypeHierarchy`:** Checks if two heap types belong to the same type hierarchy based on their null sentinels.

3. **Identifying Core Functionality:** By looking at the function names and their internal logic, the primary functions become clear:

   * **Determining Subtyping Relationships:** (`IsSubtypeOfImpl`, `IsHeapSubtypeOfImpl`, `Valid...SubtypeDefinition`).
   * **Checking Type Equivalence:** (`EquivalentTypes`, `EquivalentIndices`).
   * **Calculating Type Unions and Intersections:** (`Union`, `Intersection`).
   * **Handling Nullable Types:** (`NullSentinelImpl`, `IsNullSentinel`, logic within `IsSubtypeOfImpl`, `Intersection`, `ToNullSentinel`).
   * **Dealing with Shared Memory Types:** (`IsShared`, `MaybeShared`).

4. **Considering the ".tq" Question:** The prompt specifically asks about the `.tq` extension. Knowing that Torque is V8's internal language for performance-critical code, I recognize that this `.cc` file is *not* a Torque file. It's standard C++.

5. **Connecting to JavaScript (If Applicable):**  The prompt asks for JavaScript examples if the code relates to JavaScript functionality. Since WebAssembly directly interacts with JavaScript, the type system defined here has implications for how JavaScript interacts with Wasm modules. Specifically, when importing or exporting values between JavaScript and Wasm, type compatibility rules enforced by this code come into play. This leads to examples involving function calls with compatible signatures, passing objects with compatible structures, and handling nullable references.

6. **Inferring Logic and Providing Examples:**  For functions like `ValidStructSubtypeDefinition`, `ValidFunctionSubtypeDefinition`, `IsSubtypeOfImpl`, I can create hypothetical inputs (Wasm module structures and type indices) and predict the output (true/false). This demonstrates an understanding of the implemented rules.

7. **Identifying Potential User Errors:** Understanding the subtyping rules also helps in pinpointing common programming mistakes. For example, trying to pass an object with missing fields where a supertype is expected, or mismatching function parameter or return types.

8. **Structuring the Output:** Finally, organize the information clearly with headings like "Functionality," "Relation to JavaScript," "Code Logic," and "Common Programming Errors," as requested by the prompt. Use code blocks and clear explanations for the examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the `canonical_type_id` involves a complex canonicalization process. **Correction:** The code itself doesn't reveal the details of canonicalization, but its purpose is clearly to provide a stable identifier for type equivalence across modules.
* **Initial thought:** Focus heavily on low-level memory details. **Correction:** While V8 deals with memory management, this particular file is more concerned with the *logical* relationships between types. The examples should reflect these high-level relationships.
* **Initial thought:** Overcomplicate the JavaScript examples. **Correction:** Keep the JavaScript examples simple and directly related to the concepts demonstrated in the C++ code (function calls, object properties).

By following these steps, I can systematically analyze the provided C++ code, understand its purpose, and provide a comprehensive answer that addresses all the points raised in the prompt.
## 功能列举

`v8/src/wasm/wasm-subtyping.cc` 文件是 V8 引擎中 WebAssembly (Wasm) 子类型相关的实现代码。其主要功能包括：

1. **定义和实现 Wasm 类型的子类型关系:**  代码中包含了判断一个 Wasm 类型是否是另一个 Wasm 类型的子类型的逻辑。这包括对结构体 (struct)、数组 (array) 和函数 (function) 类型的子类型关系的特定判断规则。

2. **实现 Wasm 类型的等价性判断:**  `EquivalentIndices` 和 `EquivalentTypes` 函数用于判断两个 Wasm 类型是否等价，即使它们来自不同的模块。

3. **处理 Wasm 的可空引用 (nullable references):**  `NullSentinelImpl` 和 `IsNullSentinel` 函数与 Wasm 的可空引用处理相关，用于确定类型的“空哨兵”表示，这在子类型判断中很重要。

4. **计算 Wasm 类型的联合 (Union) 和交集 (Intersection):** `Union` 和 `Intersection` 函数用于计算两个 Wasm 类型的联合类型和交集类型，这在类型推断和优化中很有用。

5. **判断 Wasm 类型是否为共享类型 (shared type):** `IsShared` 函数用于判断一个 Wasm 类型是否是共享的，这与 Wasm 的多线程支持有关。

6. **提供判断 Wasm 类型定义的合法性:** `ValidSubtypeDefinition` 函数用于验证一个类型定义是否是另一个类型的合法子类型定义。

**总而言之，`v8/src/wasm/wasm-subtyping.cc` 负责 Wasm 类型系统中核心的子类型关系和类型运算的逻辑，确保 Wasm 代码的类型安全性和正确性。**

## 关于 .tq 结尾

如果 `v8/src/wasm/wasm-subtyping.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是 V8 内部使用的一种领域特定语言，用于编写性能关键的代码。然而，根据您提供的文件名，该文件以 `.cc` 结尾，所以它是一个 **C++ 源代码**文件。

## 与 JavaScript 的关系及举例

`v8/src/wasm/wasm-subtyping.cc` 中定义的 Wasm 类型系统与 JavaScript 存在直接关系，尤其是在以下方面：

1. **Wasm 模块的导入和导出:** 当 JavaScript 代码导入或导出 Wasm 模块的函数、全局变量或内存时，V8 需要确保 JavaScript 类型和 Wasm 类型之间的兼容性。子类型关系在确定这种兼容性方面起着关键作用。

2. **Wasm GC (垃圾回收) 集成:**  随着 Wasm GC 的引入，Wasm 可以直接操作具有复杂结构的堆对象。`wasm-subtyping.cc` 中的代码对于理解和验证这些对象的类型关系至关重要。

**JavaScript 示例:**

假设我们有一个 Wasm 模块定义了两个结构体类型：`Super` 和 `Sub`，其中 `Sub` 是 `Super` 的子类型（比如 `Sub` 拥有 `Super` 的所有字段，并可能添加了新的字段）。

**Wasm (伪代码):**

```wasm
(module
  (type $super_type (struct (field i32)))
  (type $sub_type (struct (field i32) (field f64)))

  (func (export "getSuper") (result (ref $super_type))
    (struct.new $super_type (i32.const 10)))

  (func (export "processSuper") (param (ref $super_type))
    ;; ... 处理 Super 类型的逻辑 ...
  )

  (func (export "getSub") (result (ref $sub_type))
    (struct.new $sub_type (i32.const 20) (f64.const 3.14)))
)
```

**JavaScript:**

```javascript
const wasmModule = await fetch('module.wasm'); // 假设加载了上面的 Wasm 模块
const instance = await WebAssembly.instantiateStreaming(wasmModule);
const exports = instance.instance.exports;

// 获取 Super 类型的实例
const superInstance = exports.getSuper();

// 获取 Sub 类型的实例
const subInstance = exports.getSub();

// JavaScript 可以将 Sub 类型的实例传递给期望 Super 类型参数的 Wasm 函数
exports.processSuper(subInstance); // 这是允许的，因为 Sub 是 Super 的子类型

// 反之则不然，如果 Wasm 有一个期望 Sub 类型的函数，
// 将 Super 类型的实例传递给它通常是不安全的，除非 Wasm 代码进行了额外的类型检查。
```

在这个例子中，`v8/src/wasm/wasm-subtyping.cc` 中实现的子类型逻辑会确保 JavaScript 可以安全地将 `subInstance` 传递给 `processSuper` 函数，因为 `Sub` 是 `Super` 的子类型。

## 代码逻辑推理及假设输入输出

**场景:** 判断一个结构体类型 `Sub` 是否是另一个结构体类型 `Super` 的子类型。

**使用的函数:** `ValidStructSubtypeDefinition`

**假设输入:**

* `subtype_index`: 指向 `Sub` 类型定义的索引 (假设为 `1`)
* `supertype_index`: 指向 `Super` 类型定义的索引 (假设为 `0`)
* `sub_module`: 指向包含 `Sub` 类型定义的 Wasm 模块的指针
* `super_module`: 指向包含 `Super` 类型定义的 Wasm 模块的指针

**假设 `Super` 类型的定义 (在 `super_module` 中):**

```
(type $super (struct
  (field i32 mutable)
  (field f32)
))
```

**假设 `Sub` 类型的定义 (在 `sub_module` 中):**

```
(type $sub (struct
  (field i32 mutable)
  (field f32)
  (field i64)
))
```

**代码逻辑推理:**

1. 获取 `Sub` 和 `Super` 的 `StructType` 对象。
2. 检查 `Sub` 的字段数量是否大于等于 `Super` 的字段数量 (3 >= 2，成立)。
3. 遍历 `Super` 的每个字段：
    * **字段 0:**
        * `sub_mut` (Sub 的字段 0 的可变性): true
        * `super_mut` (Super 的字段 0 的可变性): true
        * 可变性相同。
        * 使用 `EquivalentTypes` 判断 `Sub` 的字段 0 类型 (i32) 和 `Super` 的字段 0 类型 (i32) 是否等价 (假设等价，即使在不同模块)。
    * **字段 1:**
        * `sub_mut` (Sub 的字段 1 的可变性): false
        * `super_mut` (Super 的字段 1 的可变性): false
        * 可变性相同。
        * 使用 `IsSubtypeOf` 判断 `Sub` 的字段 1 类型 (f32) 是否是 `Super` 的字段 1 类型 (f32) 的子类型 (成立，因为类型相同)。

**假设输出:** `ValidStructSubtypeDefinition` 函数返回 `true`，因为 `Sub` 是 `Super` 的一个有效的子类型定义。

**如果 `Sub` 的定义是这样的:**

```
(type $sub (struct
  (field i32) ; 不可变
  (field f32)
))
```

**假设输出:** `ValidStructSubtypeDefinition` 函数返回 `false`，因为 `Sub` 的字段 0 是不可变的，而 `Super` 的字段 0 是可变的，这违反了子类型规则（子类型的可变性必须大于或等于超类型的可变性）。

## 用户常见的编程错误

与 `v8/src/wasm/wasm-subtyping.cc` 相关的用户常见编程错误通常发生在 Wasm 模块的类型定义或者 JavaScript 与 Wasm 之间的互操作中：

1. **在 JavaScript 中将不兼容类型的对象传递给 Wasm 函数:**

   ```javascript
   // 假设 Wasm 函数 processSuper 期望一个 Super 类型的对象
   const wrongObject = { value: 10 }; // 缺少 Super 类型要求的字段
   exports.processSuper(wrongObject); // 可能会导致 Wasm 内部错误或类型检查失败
   ```

   **原因:** JavaScript 对象的结构与 Wasm 期望的 `Super` 类型不匹配，违反了 Wasm 的类型安全规则。

2. **尝试在 Wasm 中定义不合法的子类型:**

   ```wasm
   ;; 错误示例：子类型的字段数量少于超类型
   (type $super (struct (field i32) (field f32)))
   (type $sub (struct (field i32))) ; 错误：缺少 f32 字段
   ```

   V8 在编译或实例化 Wasm 模块时会检测到这种错误，并抛出异常。

3. **函数参数或返回类型不匹配:**

   ```wasm
   (type $super_sig (func (param i32) (result f32)))
   (type $sub_sig (func (param i64) (result f64)))

   ;; 尝试将一个期望 $super_sig 的函数传递给一个期望 $sub_sig 的地方，
   ;; 或者反过来，都可能导致类型错误。
   ```

   子类型的函数参数是超类型函数参数的超类型（逆变），子类型的函数返回值是超类型函数返回值的子类型（协变）。不遵守这些规则会导致类型错误。

4. **忽视可变性:**

   ```wasm
   (type $super (struct (field i32)))
   (type $sub (struct (field i32 mutable)))

   ;; 如果 Wasm 代码期望一个不可变的 Super 对象，
   ;; 传递一个可变的 Sub 对象虽然类型上兼容，但在某些情况下可能导致意想不到的行为，
   ;; 因为 Wasm 代码可能假定该对象的状态不会被修改。
   ```

   虽然在子类型定义上 `Sub` 是 `Super` 的子类型，但可变性的差异可能导致逻辑上的错误。

理解 `v8/src/wasm/wasm-subtyping.cc` 中实现的子类型规则对于避免这些常见的编程错误至关重要，特别是在进行复杂的 Wasm 类型定义和 JavaScript 与 Wasm 的互操作时。

Prompt: 
```
这是目录为v8/src/wasm/wasm-subtyping.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-subtyping.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-subtyping.h"

#include "src/wasm/canonical-types.h"
#include "src/wasm/wasm-module.h"

namespace v8::internal::wasm {

namespace {

V8_INLINE bool EquivalentIndices(ModuleTypeIndex index1, ModuleTypeIndex index2,
                                 const WasmModule* module1,
                                 const WasmModule* module2) {
  DCHECK(index1 != index2 || module1 != module2);
  return module1->canonical_type_id(index1) ==
         module2->canonical_type_id(index2);
}

bool ValidStructSubtypeDefinition(ModuleTypeIndex subtype_index,
                                  ModuleTypeIndex supertype_index,
                                  const WasmModule* sub_module,
                                  const WasmModule* super_module) {
  const StructType* sub_struct = sub_module->type(subtype_index).struct_type;
  const StructType* super_struct =
      super_module->type(supertype_index).struct_type;

  if (sub_struct->field_count() < super_struct->field_count()) {
    return false;
  }

  for (uint32_t i = 0; i < super_struct->field_count(); i++) {
    bool sub_mut = sub_struct->mutability(i);
    bool super_mut = super_struct->mutability(i);
    if (sub_mut != super_mut ||
        (sub_mut &&
         !EquivalentTypes(sub_struct->field(i), super_struct->field(i),
                          sub_module, super_module)) ||
        (!sub_mut && !IsSubtypeOf(sub_struct->field(i), super_struct->field(i),
                                  sub_module, super_module))) {
      return false;
    }
  }
  return true;
}

bool ValidArraySubtypeDefinition(ModuleTypeIndex subtype_index,
                                 ModuleTypeIndex supertype_index,
                                 const WasmModule* sub_module,
                                 const WasmModule* super_module) {
  const ArrayType* sub_array = sub_module->type(subtype_index).array_type;
  const ArrayType* super_array = super_module->type(supertype_index).array_type;
  bool sub_mut = sub_array->mutability();
  bool super_mut = super_array->mutability();

  return (sub_mut && super_mut &&
          EquivalentTypes(sub_array->element_type(),
                          super_array->element_type(), sub_module,
                          super_module)) ||
         (!sub_mut && !super_mut &&
          IsSubtypeOf(sub_array->element_type(), super_array->element_type(),
                      sub_module, super_module));
}

bool ValidFunctionSubtypeDefinition(ModuleTypeIndex subtype_index,
                                    ModuleTypeIndex supertype_index,
                                    const WasmModule* sub_module,
                                    const WasmModule* super_module) {
  const FunctionSig* sub_func = sub_module->type(subtype_index).function_sig;
  const FunctionSig* super_func =
      super_module->type(supertype_index).function_sig;

  if (sub_func->parameter_count() != super_func->parameter_count() ||
      sub_func->return_count() != super_func->return_count()) {
    return false;
  }

  for (uint32_t i = 0; i < sub_func->parameter_count(); i++) {
    // Contravariance for params.
    if (!IsSubtypeOf(super_func->parameters()[i], sub_func->parameters()[i],
                     super_module, sub_module)) {
      return false;
    }
  }
  for (uint32_t i = 0; i < sub_func->return_count(); i++) {
    // Covariance for returns.
    if (!IsSubtypeOf(sub_func->returns()[i], super_func->returns()[i],
                     sub_module, super_module)) {
      return false;
    }
  }

  return true;
}

HeapType::Representation NullSentinelImpl(HeapType type,
                                          const WasmModule* module) {
  switch (type.representation()) {
    case HeapType::kI31:
    case HeapType::kNone:
    case HeapType::kEq:
    case HeapType::kStruct:
    case HeapType::kArray:
    case HeapType::kAny:
    case HeapType::kString:
    case HeapType::kStringViewWtf8:
    case HeapType::kStringViewWtf16:
    case HeapType::kStringViewIter:
      return HeapType::kNone;
    case HeapType::kExtern:
    case HeapType::kNoExtern:
    case HeapType::kExternString:
      return HeapType::kNoExtern;
    case HeapType::kExn:
    case HeapType::kNoExn:
      return HeapType::kNoExn;
    case HeapType::kFunc:
    case HeapType::kNoFunc:
      return HeapType::kNoFunc;
    case HeapType::kI31Shared:
    case HeapType::kNoneShared:
    case HeapType::kEqShared:
    case HeapType::kStructShared:
    case HeapType::kArrayShared:
    case HeapType::kAnyShared:
    case HeapType::kStringShared:
    case HeapType::kStringViewWtf8Shared:
    case HeapType::kStringViewWtf16Shared:
    case HeapType::kStringViewIterShared:
      return HeapType::kNoneShared;
    case HeapType::kExternShared:
    case HeapType::kNoExternShared:
    case HeapType::kExternStringShared:
      return HeapType::kNoExternShared;
    case HeapType::kExnShared:
    case HeapType::kNoExnShared:
      return HeapType::kNoExnShared;
    case HeapType::kFuncShared:
    case HeapType::kNoFuncShared:
      return HeapType::kNoFuncShared;
    default: {
      bool is_shared = module->type(type.ref_index()).is_shared;
      return module->has_signature(type.ref_index())
                 ? (is_shared ? HeapType::kNoFuncShared : HeapType::kNoFunc)
                 : (is_shared ? HeapType::kNoneShared : HeapType::kNone);
    }
  }
}

bool IsNullSentinel(HeapType type) {
  switch (type.representation()) {
    case HeapType::kNone:
    case HeapType::kNoExtern:
    case HeapType::kNoFunc:
    case HeapType::kNoExn:
    case HeapType::kNoneShared:
    case HeapType::kNoExternShared:
    case HeapType::kNoFuncShared:
    case HeapType::kNoExnShared:
      return true;
    default:
      return false;
  }
}

}  // namespace

bool ValidSubtypeDefinition(ModuleTypeIndex subtype_index,
                            ModuleTypeIndex supertype_index,
                            const WasmModule* sub_module,
                            const WasmModule* super_module) {
  const TypeDefinition& subtype = sub_module->type(subtype_index);
  const TypeDefinition& supertype = super_module->type(supertype_index);
  if (subtype.kind != supertype.kind) return false;
  if (supertype.is_final) return false;
  if (subtype.is_shared != supertype.is_shared) return false;
  switch (subtype.kind) {
    case TypeDefinition::kFunction:
      return ValidFunctionSubtypeDefinition(subtype_index, supertype_index,
                                            sub_module, super_module);
    case TypeDefinition::kStruct:
      return ValidStructSubtypeDefinition(subtype_index, supertype_index,
                                          sub_module, super_module);
    case TypeDefinition::kArray:
      return ValidArraySubtypeDefinition(subtype_index, supertype_index,
                                         sub_module, super_module);
  }
}

namespace {
bool IsShared(HeapType type, const WasmModule* module) {
  return type.is_abstract_shared() ||
         (type.is_index() && module->type(type.ref_index()).is_shared);
}

HeapType::Representation MaybeShared(HeapType::Representation base,
                                     bool shared) {
  DCHECK(HeapType(base).is_abstract_non_shared());
  if (!shared) return base;
  switch (base) {
    case HeapType::kFunc:
      return HeapType::kFuncShared;
    case HeapType::kEq:
      return HeapType::kEqShared;
    case HeapType::kI31:
      return HeapType::kI31Shared;
    case HeapType::kStruct:
      return HeapType::kStructShared;
    case HeapType::kArray:
      return HeapType::kArrayShared;
    case HeapType::kAny:
      return HeapType::kAnyShared;
    case HeapType::kExtern:
      return HeapType::kExternShared;
    case HeapType::kExternString:
      return HeapType::kExternStringShared;
    case HeapType::kExn:
      return HeapType::kExnShared;
    case HeapType::kString:
      return HeapType::kStringShared;
    case HeapType::kStringViewWtf8:
      return HeapType::kStringViewWtf8Shared;
    case HeapType::kStringViewWtf16:
      return HeapType::kStringViewWtf16Shared;
    case HeapType::kStringViewIter:
      return HeapType::kStringViewIterShared;
    case HeapType::kNone:
      return HeapType::kNoneShared;
    case HeapType::kNoFunc:
      return HeapType::kNoFuncShared;
    case HeapType::kNoExtern:
      return HeapType::kNoExternShared;
    case HeapType::kNoExn:
      return HeapType::kNoExnShared;
    default:
      UNREACHABLE();
  }
}
}  // namespace

V8_EXPORT_PRIVATE bool IsShared(ValueType type, const WasmModule* module) {
  switch (type.kind()) {
    case kRef:
    case kRefNull:
      return IsShared(type.heap_type(), module);
    default:
      return true;
  }
}

V8_NOINLINE V8_EXPORT_PRIVATE bool IsSubtypeOfImpl(
    ValueType subtype, ValueType supertype, const WasmModule* sub_module,
    const WasmModule* super_module) {
  DCHECK(subtype != supertype || sub_module != super_module);

  // The top type is the super type of all other types.
  if (supertype.kind() == kTop) return true;

  switch (subtype.kind()) {
    case kI32:
    case kI64:
    case kF16:
    case kF32:
    case kF64:
    case kS128:
    case kI8:
    case kI16:
    case kVoid:
    case kTop:
      return subtype == supertype;
    case kBottom:
      // The bottom type is a subtype of all types.
      return true;
    case kRtt:
      return supertype.kind() == kRtt &&
             EquivalentIndices(subtype.ref_index(), supertype.ref_index(),
                               sub_module, super_module);
    case kRef:
    case kRefNull:
      break;
  }

  DCHECK(subtype.is_object_reference());

  bool compatible_references = subtype.is_nullable()
                                   ? supertype.is_nullable()
                                   : supertype.is_object_reference();
  if (!compatible_references) return false;

  DCHECK(supertype.is_object_reference());

  // Now check that sub_heap and super_heap are subtype-related.

  HeapType sub_heap = subtype.heap_type();
  HeapType super_heap = supertype.heap_type();

  return IsHeapSubtypeOfImpl(sub_heap, super_heap, sub_module, super_module);
}

V8_NOINLINE V8_EXPORT_PRIVATE bool IsHeapSubtypeOfImpl(
    HeapType sub_heap, HeapType super_heap, const WasmModule* sub_module,
    const WasmModule* super_module) {
  if (IsShared(sub_heap, sub_module) != IsShared(super_heap, super_module)) {
    return false;
  }
  HeapType::Representation sub_repr_non_shared =
      sub_heap.representation_non_shared();
  HeapType::Representation super_repr_non_shared =
      super_heap.representation_non_shared();
  switch (sub_repr_non_shared) {
    case HeapType::kFunc:
    case HeapType::kAny:
    case HeapType::kExtern:
    case HeapType::kExn:
    case HeapType::kStringViewWtf8:
    case HeapType::kStringViewWtf16:
    case HeapType::kStringViewIter:
      return sub_repr_non_shared == super_repr_non_shared;
    case HeapType::kEq:
    case HeapType::kString:
      return sub_repr_non_shared == super_repr_non_shared ||
             super_repr_non_shared == HeapType::kAny;
    case HeapType::kExternString:
      return super_repr_non_shared == sub_repr_non_shared ||
             super_repr_non_shared == HeapType::kExtern;
    case HeapType::kI31:
    case HeapType::kStruct:
    case HeapType::kArray:
      return super_repr_non_shared == sub_repr_non_shared ||
             super_repr_non_shared == HeapType::kEq ||
             super_repr_non_shared == HeapType::kAny;
    case HeapType::kBottom:
    case HeapType::kTop:
      UNREACHABLE();
    case HeapType::kNone:
      // none is a subtype of every non-func, non-extern and non-exn reference
      // type under wasm-gc.
      if (super_heap.is_index()) {
        return !super_module->has_signature(super_heap.ref_index());
      }
      return super_repr_non_shared == HeapType::kAny ||
             super_repr_non_shared == HeapType::kEq ||
             super_repr_non_shared == HeapType::kI31 ||
             super_repr_non_shared == HeapType::kArray ||
             super_repr_non_shared == HeapType::kStruct ||
             super_repr_non_shared == HeapType::kString ||
             super_repr_non_shared == HeapType::kStringViewWtf16 ||
             super_repr_non_shared == HeapType::kStringViewWtf8 ||
             super_repr_non_shared == HeapType::kStringViewIter ||
             super_repr_non_shared == HeapType::kNone;
    case HeapType::kNoExtern:
      return super_repr_non_shared == HeapType::kNoExtern ||
             super_repr_non_shared == HeapType::kExtern ||
             super_repr_non_shared == HeapType::kExternString;
    case HeapType::kNoExn:
      return super_repr_non_shared == HeapType::kExn ||
             super_repr_non_shared == HeapType::kNoExn;
    case HeapType::kNoFunc:
      // nofunc is a subtype of every funcref type under wasm-gc.
      if (super_heap.is_index()) {
        return super_module->has_signature(super_heap.ref_index());
      }
      return super_repr_non_shared == HeapType::kNoFunc ||
             super_repr_non_shared == HeapType::kFunc;
    default:
      break;
  }

  DCHECK(sub_heap.is_index());
  ModuleTypeIndex sub_index = sub_heap.ref_index();
  DCHECK(sub_module->has_type(sub_index));

  switch (super_repr_non_shared) {
    case HeapType::kFunc:
      return sub_module->has_signature(sub_index);
    case HeapType::kStruct:
      return sub_module->has_struct(sub_index);
    case HeapType::kEq:
    case HeapType::kAny:
      return !sub_module->has_signature(sub_index);
    case HeapType::kArray:
      return sub_module->has_array(sub_index);
    case HeapType::kI31:
    case HeapType::kExtern:
    case HeapType::kExternString:
    case HeapType::kExn:
    case HeapType::kString:
    case HeapType::kStringViewWtf8:
    case HeapType::kStringViewWtf16:
    case HeapType::kStringViewIter:
    case HeapType::kNone:
    case HeapType::kNoExtern:
    case HeapType::kNoFunc:
    case HeapType::kNoExn:
      return false;
    case HeapType::kBottom:
    case HeapType::kTop:
      UNREACHABLE();
    default:
      break;
  }

  DCHECK(super_heap.is_index());
  ModuleTypeIndex super_index = super_heap.ref_index();
  DCHECK(super_module->has_type(super_index));
  // The {IsSubtypeOf} entry point already has a fast path checking ValueType
  // equality; here we catch (ref $x) being a subtype of (ref null $x).
  if (sub_module == super_module && sub_index == super_index) return true;
  return GetTypeCanonicalizer()->IsCanonicalSubtype(sub_index, super_index,
                                                    sub_module, super_module);
}

V8_NOINLINE bool EquivalentTypes(ValueType type1, ValueType type2,
                                 const WasmModule* module1,
                                 const WasmModule* module2) {
  if (type1 == type2 && module1 == module2) return true;
  if (!type1.has_index() || !type2.has_index()) return type1 == type2;
  if (type1.kind() != type2.kind()) return false;

  DCHECK(type1 != type2 || module1 != module2);
  DCHECK(type1.has_index() && module1->has_type(type1.ref_index()) &&
         type2.has_index() && module2->has_type(type2.ref_index()));

  return EquivalentIndices(type1.ref_index(), type2.ref_index(), module1,
                           module2);
}

namespace {
// Returns the least common ancestor of two type indices, as a type index in
// {module1}.
HeapType::Representation CommonAncestor(ModuleTypeIndex type_index1,
                                        ModuleTypeIndex type_index2,
                                        const WasmModule* module1,
                                        const WasmModule* module2) {
  TypeDefinition type1 = module1->type(type_index1);
  TypeDefinition type2 = module2->type(type_index2);
  TypeDefinition::Kind kind1 = type1.kind;
  TypeDefinition::Kind kind2 = type2.kind;
  if (type1.is_shared != type2.is_shared) {
    return HeapType::kTop;
  }
  bool both_shared = type1.is_shared;
  {
    int depth1 = GetSubtypingDepth(module1, type_index1);
    int depth2 = GetSubtypingDepth(module2, type_index2);
    while (depth1 > depth2) {
      type_index1 = module1->supertype(type_index1);
      depth1--;
    }
    while (depth2 > depth1) {
      type_index2 = module2->supertype(type_index2);
      depth2--;
    }
  }
  DCHECK_NE(type_index1, kNoSuperType);
  DCHECK_NE(type_index2, kNoSuperType);
  while (type_index1 != kNoSuperType &&
         !(type_index1 == type_index2 && module1 == module2) &&
         !EquivalentIndices(type_index1, type_index2, module1, module2)) {
    type_index1 = module1->supertype(type_index1);
    type_index2 = module2->supertype(type_index2);
  }
  DCHECK_EQ(type_index1 == kNoSuperType, type_index2 == kNoSuperType);
  if (type_index1 != kNoSuperType) {
    return static_cast<HeapType::Representation>(type_index1.index);
  }
  switch (kind1) {
    case TypeDefinition::kFunction:
      switch (kind2) {
        case TypeDefinition::kFunction:
          return MaybeShared(HeapType::kFunc, both_shared);
        case TypeDefinition::kStruct:
        case TypeDefinition::kArray:
          return HeapType::kTop;
      }
    case TypeDefinition::kStruct:
      switch (kind2) {
        case TypeDefinition::kFunction:
          return HeapType::kTop;
        case TypeDefinition::kStruct:
          return MaybeShared(HeapType::kStruct, both_shared);
        case TypeDefinition::kArray:
          return MaybeShared(HeapType::kEq, both_shared);
      }
    case TypeDefinition::kArray:
      switch (kind2) {
        case TypeDefinition::kFunction:
          return HeapType::kTop;
        case TypeDefinition::kStruct:
          return MaybeShared(HeapType::kEq, both_shared);
        case TypeDefinition::kArray:
          return MaybeShared(HeapType::kArray, both_shared);
      }
  }
}

// Returns the least common ancestor of an abstract HeapType {heap1}, and
// another HeapType {heap2}.
HeapType::Representation CommonAncestorWithAbstract(HeapType heap1,
                                                    HeapType heap2,
                                                    const WasmModule* module2) {
  DCHECK(heap1.is_abstract());
  // Passing {module2} with {heap1} below is fine since {heap1} is abstract.
  bool is_shared = IsShared(heap1, module2);
  if (is_shared != IsShared(heap2, module2)) {
    return HeapType::kTop;
  }

  // TODO(mliedtke): These types should be normalized to the value type kTop and
  // kBottom and therefore should never appear here. Can we convert these into
  // assertions?
  if (heap1.is_top() || heap2.is_top()) return HeapType::kTop;
  if (heap1.is_bottom()) return heap2.representation();
  if (heap2.is_bottom()) return heap1.representation();

  HeapType::Representation repr_non_shared2 = heap2.representation_non_shared();
  switch (heap1.representation_non_shared()) {
    case HeapType::kFunc: {
      if (repr_non_shared2 == HeapType::kFunc ||
          repr_non_shared2 == HeapType::kNoFunc ||
          (heap2.is_index() && module2->has_signature(heap2.ref_index()))) {
        return MaybeShared(HeapType::kFunc, is_shared);
      } else {
        return HeapType::kTop;
      }
    }
    case HeapType::kAny: {
      switch (repr_non_shared2) {
        case HeapType::kI31:
        case HeapType::kNone:
        case HeapType::kEq:
        case HeapType::kStruct:
        case HeapType::kArray:
        case HeapType::kAny:
        case HeapType::kString:
          return MaybeShared(HeapType::kAny, is_shared);
        case HeapType::kFunc:
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_signature(heap2.ref_index())
                     ? HeapType::kTop
                     : MaybeShared(HeapType::kAny, is_shared);
      }
    }
    case HeapType::kEq: {
      switch (repr_non_shared2) {
        case HeapType::kI31:
        case HeapType::kNone:
        case HeapType::kEq:
        case HeapType::kStruct:
        case HeapType::kArray:
          return MaybeShared(HeapType::kEq, is_shared);
        case HeapType::kAny:
        case HeapType::kString:
          return MaybeShared(HeapType::kAny, is_shared);
        case HeapType::kFunc:
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_signature(heap2.ref_index())
                     ? HeapType::kTop
                     : MaybeShared(HeapType::kEq, is_shared);
      }
    }
    case HeapType::kI31:
      switch (repr_non_shared2) {
        case HeapType::kI31:
        case HeapType::kNone:
          return MaybeShared(HeapType::kI31, is_shared);
        case HeapType::kEq:
        case HeapType::kStruct:
        case HeapType::kArray:
          return MaybeShared(HeapType::kEq, is_shared);
        case HeapType::kAny:
        case HeapType::kString:
          return MaybeShared(HeapType::kAny, is_shared);
        case HeapType::kFunc:
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_signature(heap2.ref_index())
                     ? HeapType::kTop
                     : MaybeShared(HeapType::kEq, is_shared);
      }
    case HeapType::kStruct:
      switch (repr_non_shared2) {
        case HeapType::kStruct:
        case HeapType::kNone:
          return MaybeShared(HeapType::kStruct, is_shared);
        case HeapType::kArray:
        case HeapType::kI31:
        case HeapType::kEq:
          return MaybeShared(HeapType::kEq, is_shared);
        case HeapType::kAny:
        case HeapType::kString:
          return MaybeShared(HeapType::kAny, is_shared);
        case HeapType::kFunc:
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_struct(heap2.ref_index())
                     ? MaybeShared(HeapType::kStruct, is_shared)
                 : module2->has_array(heap2.ref_index())
                     ? MaybeShared(HeapType::kEq, is_shared)
                     : HeapType::kTop;
      }
    case HeapType::kArray:
      switch (repr_non_shared2) {
        case HeapType::kArray:
        case HeapType::kNone:
          return MaybeShared(HeapType::kArray, is_shared);
        case HeapType::kStruct:
        case HeapType::kI31:
        case HeapType::kEq:
          return MaybeShared(HeapType::kEq, is_shared);
        case HeapType::kAny:
        case HeapType::kString:
          return MaybeShared(HeapType::kAny, is_shared);
        case HeapType::kFunc:
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_array(heap2.ref_index())
                     ? MaybeShared(HeapType::kArray, is_shared)
                 : module2->has_struct(heap2.ref_index())
                     ? MaybeShared(HeapType::kEq, is_shared)
                     : HeapType::kTop;
      }
    case HeapType::kNone:
      switch (repr_non_shared2) {
        case HeapType::kArray:
        case HeapType::kNone:
        case HeapType::kStruct:
        case HeapType::kI31:
        case HeapType::kEq:
        case HeapType::kAny:
        case HeapType::kString:
          return heap2.representation();
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_signature(heap2.ref_index())
                     ? HeapType::kTop
                     : heap2.representation();
      }
    case HeapType::kNoFunc:
      return (repr_non_shared2 == HeapType::kNoFunc ||
              repr_non_shared2 == HeapType::kFunc ||
              (heap2.is_index() && module2->has_signature(heap2.ref_index())))
                 ? heap2.representation()
                 : HeapType::kTop;
    case HeapType::kNoExtern:
      return repr_non_shared2 == HeapType::kExtern ||
                     repr_non_shared2 == HeapType::kNoExtern ||
                     repr_non_shared2 == HeapType::kExternString
                 ? heap2.representation()
                 : HeapType::kTop;
    case HeapType::kExtern:
      return repr_non_shared2 == HeapType::kExtern ||
                     repr_non_shared2 == HeapType::kNoExtern ||
                     repr_non_shared2 == HeapType::kExternString
                 ? MaybeShared(HeapType::kExtern, is_shared)
                 : HeapType::kTop;
    case HeapType::kExternString:
      return repr_non_shared2 == HeapType::kExtern
                 ? MaybeShared(HeapType::kExtern, is_shared)
             : (repr_non_shared2 == HeapType::kNoExtern ||
                repr_non_shared2 == HeapType::kExternString)
                 ? MaybeShared(HeapType::kExternString, is_shared)
                 : HeapType::kTop;
    case HeapType::kNoExn:
      return repr_non_shared2 == HeapType::kExn ||
                     repr_non_shared2 == HeapType::kNoExn
                 ? heap2.representation()
                 : HeapType::kTop;
    case HeapType::kExn:
      return repr_non_shared2 == HeapType::kExn ||
                     repr_non_shared2 == HeapType::kNoExn
                 ? MaybeShared(HeapType::kExn, is_shared)
                 : HeapType::kTop;
    case HeapType::kString: {
      switch (repr_non_shared2) {
        case HeapType::kI31:
        case HeapType::kEq:
        case HeapType::kStruct:
        case HeapType::kArray:
        case HeapType::kAny:
          return MaybeShared(HeapType::kAny, is_shared);
        case HeapType::kNone:
        case HeapType::kString:
          return MaybeShared(HeapType::kString, is_shared);
        case HeapType::kFunc:
        case HeapType::kExtern:
        case HeapType::kExternString:
        case HeapType::kNoExtern:
        case HeapType::kNoFunc:
        case HeapType::kStringViewIter:
        case HeapType::kStringViewWtf8:
        case HeapType::kStringViewWtf16:
        case HeapType::kExn:
        case HeapType::kNoExn:
          return HeapType::kTop;
        default:
          return module2->has_signature(heap2.ref_index())
                     ? HeapType::kTop
                     : MaybeShared(HeapType::kAny, is_shared);
      }
    }
    case HeapType::kStringViewIter:
    case HeapType::kStringViewWtf16:
    case HeapType::kStringViewWtf8:
      return heap1 == heap2 ? heap1.representation() : HeapType::kTop;
    default:
      UNREACHABLE();
  }
}
}  // namespace

V8_EXPORT_PRIVATE TypeInModule Union(ValueType type1, ValueType type2,
                                     const WasmModule* module1,
                                     const WasmModule* module2) {
  if (type1 == kWasmTop || type2 == kWasmTop) return {kWasmTop, module1};
  if (type1 == kWasmBottom) return {type2, module2};
  if (type2 == kWasmBottom) return {type1, module1};
  if (!type1.is_object_reference() || !type2.is_object_reference()) {
    return {EquivalentTypes(type1, type2, module1, module2) ? type1 : kWasmTop,
            module1};
  }
  Nullability nullability =
      type1.is_nullable() || type2.is_nullable() ? kNullable : kNonNullable;
  HeapType heap1 = type1.heap_type();
  HeapType heap2 = type2.heap_type();
  if (heap1 == heap2 && module1 == module2) {
    return {ValueType::RefMaybeNull(heap1, nullability), module1};
  }
  HeapType::Representation result_repr;
  const WasmModule* result_module;
  if (heap1.is_abstract()) {
    result_repr = CommonAncestorWithAbstract(heap1, heap2, module2);
    result_module = module2;
  } else if (heap2.is_abstract()) {
    result_repr = CommonAncestorWithAbstract(heap2, heap1, module1);
    result_module = module1;
  } else {
    result_repr =
        CommonAncestor(heap1.ref_index(), heap2.ref_index(), module1, module2);
    result_module = module1;
  }
  // The type could only be kBottom if the input was kBottom but any kBottom
  // HeapType should be "normalized" to kWasmBottom ValueType.
  DCHECK_NE(result_repr, HeapType::kBottom);
  return {result_repr == HeapType::kTop
              ? kWasmTop
              : ValueType::RefMaybeNull(result_repr, nullability),
          result_module};
}

TypeInModule Intersection(ValueType type1, ValueType type2,
                          const WasmModule* module1,
                          const WasmModule* module2) {
  if (type1 == kWasmTop) return {type2, module2};
  if (type2 == kWasmTop) return {type1, module1};
  if (!type1.is_object_reference() || !type2.is_object_reference()) {
    return {
        EquivalentTypes(type1, type2, module1, module2) ? type1 : kWasmBottom,
        module1};
  }
  Nullability nullability =
      type1.is_nullable() && type2.is_nullable() ? kNullable : kNonNullable;
  // non-nullable null type is not a valid type.
  if (nullability == kNonNullable && (IsNullSentinel(type1.heap_type()) ||
                                      IsNullSentinel(type2.heap_type()))) {
    return {kWasmBottom, module1};
  }
  if (IsHeapSubtypeOf(type1.heap_type(), type2.heap_type(), module1, module2)) {
    return TypeInModule{ValueType::RefMaybeNull(type1.heap_type(), nullability),
                        module1};
  }
  if (IsHeapSubtypeOf(type2.heap_type(), type1.heap_type(), module2, module1)) {
    return TypeInModule{ValueType::RefMaybeNull(type2.heap_type(), nullability),
                        module2};
  }
  if (nullability == kNonNullable) {
    return {kWasmBottom, module1};
  }
  // Check for common null representation.
  ValueType null_type1 = ToNullSentinel({type1, module1});
  if (null_type1 == ToNullSentinel({type2, module2})) {
    return {null_type1, module1};
  }
  return {kWasmBottom, module1};
}

ValueType ToNullSentinel(TypeInModule type) {
  HeapType::Representation null_heap =
      NullSentinelImpl(type.type.heap_type(), type.module);
  DCHECK(
      IsHeapSubtypeOf(HeapType(null_heap), type.type.heap_type(), type.module));
  return ValueType::RefNull(null_heap);
}

bool IsSameTypeHierarchy(HeapType type1, HeapType type2,
                         const WasmModule* module) {
  return NullSentinelImpl(type1, module) == NullSentinelImpl(type2, module);
}

}  // namespace v8::internal::wasm

"""

```