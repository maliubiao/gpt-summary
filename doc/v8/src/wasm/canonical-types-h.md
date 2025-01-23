Response:
My thinking process to analyze the `canonical-types.h` file went through these stages:

1. **Initial Skim and Keywords:** I first quickly scanned the code looking for obvious keywords and structural elements. Keywords like `class`, `struct`, `enum`, `static`, `constexpr`, `#define`, `#ifndef`, `namespace`, and comments like `// Copyright` and `// TODO` immediately jumped out. The `#ifndef V8_WASM_CANONICAL_TYPES_H_` pattern clearly indicates a header guard. The namespace `v8::internal::wasm` told me it's part of the V8 JavaScript engine's WebAssembly implementation.

2. **High-Level Purpose (Based on Filename and Initial Scan):**  The filename `canonical-types.h` strongly suggested this file deals with the concept of "canonical types" within the WebAssembly context. The presence of `TypeCanonicalizer` class further reinforced this. My initial guess was that it's about establishing a standard or unique representation for WebAssembly types.

3. **Analyzing the `TypeCanonicalizer` Class:** This is the central piece of the file. I broke down its members:
    * **Static Members:** `kPredefinedArrayI8Index`, `kPredefinedArrayI16Index`, `kNumberOfPredefinedTypes`, `PrepareForCanonicalTypeId`, `ClearWasmCanonicalTypesForTesting`, and `GetTypeCanonicalizer`. These hinted at predefined types, setup/cleanup routines, and a singleton pattern.
    * **Public Methods:** I read the names and brief comments of each public method to understand the class's API. Methods like `AddRecursiveGroup`, `LookupFunctionSignature`, `IsCanonicalSubtype`, and `EmptyStorageForTesting` gave strong clues about the core functionality: registering type groups (especially recursive ones), looking up signatures, checking subtype relationships, and managing memory.
    * **Private Members:** I noted the nested `struct`s (`CanonicalType`, `RecursionGroupRange`, `CanonicalHashing`, `CanonicalEquality`, `CanonicalGroup`, `CanonicalSingletonGroup`). These suggested internal data structures and algorithms used for canonicalization. The data members like `canonical_supertypes_`, `canonical_groups_`, `canonical_singleton_groups_`, and `canonical_function_sigs_` confirmed that the class is storing canonicalized type information. The presence of `mutex_` indicated potential thread-safety considerations.

4. **Understanding "Canonicalization":**  Based on the method names and comments about recursive groups and identical types, I inferred that "canonicalization" here means finding a unique representation for potentially complex and recursive WebAssembly type definitions. This is crucial for comparing types for equality and subtyping.

5. **Connecting to WebAssembly Concepts:**  I linked the terms and methods to my existing knowledge of WebAssembly. "Recursive groups" relate to how WebAssembly modules can define mutually recursive types. "Function signatures" are fundamental to WebAssembly functions. "Subtyping" is essential for type safety and polymorphism.

6. **Inferring the `.tq` Question:**  The question about `.tq` being a Torque file was a straightforward check of V8's build system knowledge. I knew Torque is used for defining built-in JavaScript and WebAssembly functions, so it's relevant in the V8 context.

7. **Considering JavaScript Relevance:** I thought about how canonicalization in WebAssembly might relate to JavaScript. The key connection is the interaction between JavaScript and WebAssembly modules. When calling WebAssembly functions from JavaScript or vice-versa, type compatibility is crucial. Canonicalization helps ensure these type checks are consistent.

8. **Developing Examples and Scenarios:** I started formulating examples to illustrate the concepts:
    * **JavaScript Interop:**  Show how canonical types are important when a JavaScript function calls a WebAssembly function with a specific signature.
    * **Recursive Types:** Create a simplified example of how recursive struct types in WebAssembly would be canonicalized to a single representation.
    * **Common Errors:**  Think about mistakes developers might make when defining or using WebAssembly types, particularly related to type mismatches.

9. **Addressing Specific Instructions:** I revisited the prompt's specific questions:
    * **Functionality Listing:**  I systematically listed the identified functions of the header file based on my analysis.
    * **`.tq` Extension:**  I directly answered the Torque question.
    * **JavaScript Relation:**  I focused on the interoperability aspect.
    * **Code Logic and Examples:** I created hypothetical scenarios with inputs and outputs for the canonicalization process.
    * **Common Errors:** I provided examples of typical WebAssembly type-related errors.

10. **Refinement and Organization:** I organized my findings into a clear and structured response, using headings and bullet points to improve readability. I ensured I addressed each part of the original prompt.

Essentially, my process was a combination of code reading, domain knowledge application, logical deduction, and example generation. I started broad and gradually focused on the specifics, using the structure of the code itself as a guide.
This header file, `v8/src/wasm/canonical-types.h`, in the V8 JavaScript engine's source code defines the `TypeCanonicalizer` class and related structures. Its primary function is to manage the **canonicalization of WebAssembly types**, particularly complex and recursive types. Canonicalization essentially means finding a unique, standardized representation for types that might be structurally equivalent but defined differently. This is crucial for efficiently comparing types for equality and subtyping in WebAssembly.

Here's a breakdown of its functionalities:

**Core Functionality: Canonicalization of WebAssembly Types**

* **Handling Recursive Types:**  A significant focus is on canonicalizing *isorecursive* types (mutually recursive types). The class identifies identical recursive groups of types within a WebAssembly module and assigns them a single canonical representation. This prevents redundant storage and simplifies type comparisons.
* **Canonical Type Indices:** The class assigns unique `CanonicalTypeIndex` values to each canonicalized type. These indices are used throughout the V8 WebAssembly implementation to refer to these canonical types.
* **Predefined Types:** It manages a set of predefined canonical types (currently array types of i8 and i16).
* **Function Signature Canonicalization:** It handles the canonicalization of function signatures (`FunctionSig`). Identical signatures across different modules are mapped to the same canonical representation.
* **Subtyping Checks:** The `IsCanonicalSubtype` methods allow checking if one canonical type is a subtype of another. This is essential for type safety in WebAssembly.

**Key Classes and Structures:**

* **`TypeCanonicalizer`:** The central class responsible for the canonicalization process. It's designed as a singleton.
* **`CanonicalType`:**  Represents a canonicalized type (function, struct, or array). It stores the underlying type information, its supertype (if any), and flags like `is_final` and `is_shared`.
* **`CanonicalSig`:** Represents a canonicalized function signature.
* **`CanonicalStructType`:** Represents a canonicalized struct type.
* **`CanonicalArrayType`:** Represents a canonicalized array type.
* **`CanonicalGroup`:** Represents a group of recursively defined canonical types.
* **`CanonicalSingletonGroup`:** Represents a single canonical type (when not part of a larger recursive group).
* **`RecursionGroupRange`, `CanonicalHashing`, `CanonicalEquality`:**  Helper structures used internally for efficiently hashing and comparing recursive groups of types.

**Regarding the `.tq` extension:**

No, if `v8/src/wasm/canonical-types.h` had a `.tq` extension (like `canonical-types.tq`), then it would be a **V8 Torque source file**. Torque is a domain-specific language used within V8 to generate highly optimized C++ code for built-in functions and runtime components. Since it has a `.h` extension, it's a standard C++ header file.

**Relationship to JavaScript and Examples:**

While `canonical-types.h` is a low-level C++ header within the V8 engine, its functionality directly impacts how JavaScript interacts with WebAssembly. Here's how:

1. **Type Compatibility:** When you call a WebAssembly function from JavaScript, the JavaScript values need to be compatible with the WebAssembly function's expected parameters. The canonicalization process ensures that the types are correctly understood and compared, even for complex WebAssembly types.

2. **Creating WebAssembly Instances:** When you instantiate a WebAssembly module in JavaScript, the engine uses the canonicalized type information to set up the module's memory and function tables.

3. **Sharing Types Across Modules:** If two WebAssembly modules define the same recursive type structure, the `TypeCanonicalizer` will ensure they are represented by the same canonical type. This allows instances of these modules to interact correctly.

**JavaScript Example (Illustrative):**

Imagine two different WebAssembly modules, `module1.wasm` and `module2.wasm`, both define a mutually recursive struct type.

```wasm
;; In module1.wasm
(type $A (struct (field i32)))
(type $B (struct (field (ref $A))))
(type $A_rec (sub $A (struct (field i32) (field (ref $B_rec)))))
(type $B_rec (sub $B (struct (field (ref $A_rec)))))

;; In module2.wasm (defined slightly differently but structurally the same)
(type $X (struct (field i32)))
(type $Y (struct (field (ref $X))))
(type $X_rec (sub $X (struct (field i32) (field (ref $Y_rec)))))
(type $Y_rec (sub $Y (struct (field (ref $X_rec)))))
```

Even though the type definitions have different names (`$A`, `$B` vs. `$X`, `$Y`), the `TypeCanonicalizer` will recognize their structural equivalence and assign them the same canonical representation. This allows JavaScript code to potentially pass objects created from `module1` to functions in `module2` that expect those recursive types (assuming other compatibility rules are met).

```javascript
// Assuming you've loaded and instantiated module1 and module2
const instance1 = await WebAssembly.instantiateStreaming(fetch('module1.wasm'));
const instance2 = await WebAssembly.instantiateStreaming(fetch('module2.wasm'));

// Assuming module1 has a function that returns an instance of the recursive struct
const structFromModule1 = instance1.exports.createRecursiveStruct();

// Assuming module2 has a function that takes the recursive struct as an argument
instance2.exports.processRecursiveStruct(structFromModule1); // This would work due to canonicalization
```

**Code Logic Inference (Hypothetical):**

Let's consider the `AddRecursiveGroup` function.

**Hypothetical Input:**

* `module`: A `WasmModule` object representing a WebAssembly module.
* `size`: 2 (indicating a recursive group of two types).
* `start_index`: 5 (the starting index of the recursive group within the module's type section).
* The module's type section at indices 5 and 6 defines two mutually recursive struct types.

**Hypothetical Output:**

1. The `TypeCanonicalizer` will iterate through the types in the recursive group (at indices 5 and 6 in the module).
2. It will create a `CanonicalGroup` representing these types.
3. It will check if an identical `CanonicalGroup` already exists in its internal storage (`canonical_groups_`).
4. **Scenario 1: Identical group exists:** If a match is found, the existing canonical type indices for that group will be associated with the types in the current module. The `module->isorecursive_canonical_type_ids` array will be updated to point to these existing canonical indices.
5. **Scenario 2: No identical group exists:** If no match is found, new canonical type indices will be assigned to the types in the new group. This new `CanonicalGroup` will be added to the `canonical_groups_` set, and the `module->isorecursive_canonical_type_ids` array will be updated with these newly generated indices.

**Common Programming Errors (Related to WebAssembly Types):**

While developers don't directly interact with `canonical-types.h`, the concepts it manages are relevant to common errors:

1. **Type Mismatches When Calling WebAssembly from JavaScript:**
   ```javascript
   // WebAssembly function expects an i32
   instance.exports.myFunction(true); // Error: Trying to pass a boolean
   ```
   The canonicalization ensures the engine understands the expected types and can throw appropriate errors.

2. **Incorrect Type Annotations in TypeScript (when interacting with WebAssembly):**
   If you're using TypeScript to define the interface with your WebAssembly module, incorrect type annotations can lead to runtime errors when the JavaScript and WebAssembly types don't align. Canonicalization helps ensure the underlying type system is consistent.

3. **Misunderstanding Recursive Types:**  Manually trying to compare or manipulate recursive types without understanding the canonicalization process can lead to logical errors. The engine's canonicalization handles the complexity of these comparisons.

4. **Memory Layout Issues (for Structs and Arrays):** While not directly caused by canonicalization, misunderstandings about how struct and array types are laid out in WebAssembly memory can lead to errors when interacting with them from JavaScript. Canonicalization helps define the structure that JavaScript needs to understand.

In summary, `v8/src/wasm/canonical-types.h` is a crucial piece of V8's WebAssembly implementation, responsible for efficiently managing and comparing complex WebAssembly types. It enables correct type checking and interaction between JavaScript and WebAssembly, even in the presence of recursive type definitions.

### 提示词
```
这是目录为v8/src/wasm/canonical-types.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/canonical-types.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_CANONICAL_TYPES_H_
#define V8_WASM_CANONICAL_TYPES_H_

#include <unordered_map>

#include "src/base/bounds.h"
#include "src/base/functional.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-module.h"

namespace v8::internal::wasm {

// We use ValueType instances constructed from canonical type indices, so we
// can't let them get bigger than what we have storage space for.
// TODO(jkummerow): Raise this limit. Possible options:
// - increase the size of ValueType::HeapTypeField, using currently-unused bits.
// - change the encoding of ValueType: one bit says whether it's a ref type,
//   the other bits then encode the index or the kind of non-ref type.
// - refactor the TypeCanonicalizer's internals to no longer use ValueTypes
//   and related infrastructure, and use a wider encoding of canonicalized
//   type indices only here.
// - wait for 32-bit platforms to no longer be relevant, and increase the
//   size of ValueType to 64 bits.
// None of this seems urgent, as we have no evidence of the current limit
// being an actual limitation in practice.
static constexpr size_t kMaxCanonicalTypes = kV8MaxWasmTypes;
// We don't want any valid modules to fail canonicalization.
static_assert(kMaxCanonicalTypes >= kV8MaxWasmTypes);
// We want the invalid index to fail any range checks.
static_assert(kInvalidCanonicalIndex > kMaxCanonicalTypes);
// Ensure that ValueType can hold all canonical type indexes.
static_assert(kMaxCanonicalTypes <= (1 << ValueType::kHeapTypeBits));

// A singleton class, responsible for isorecursive canonicalization of wasm
// types.
// A recursive group is a subsequence of types explicitly marked in the type
// section of a wasm module. Identical recursive groups have to be canonicalized
// to a single canonical group. Respective types in two identical groups are
// considered identical for all purposes.
// Two groups are considered identical if they have the same shape, and all
// type indices referenced in the same position in both groups reference:
// - identical types, if those do not belong to the rec. group,
// - types in the same relative position in the group, if those belong to the
//   rec. group.
class TypeCanonicalizer {
 public:
  static constexpr CanonicalTypeIndex kPredefinedArrayI8Index{0};
  static constexpr CanonicalTypeIndex kPredefinedArrayI16Index{1};
  static constexpr uint32_t kNumberOfPredefinedTypes = 2;

  TypeCanonicalizer();

  // Singleton class; no copying or moving allowed.
  TypeCanonicalizer(const TypeCanonicalizer& other) = delete;
  TypeCanonicalizer& operator=(const TypeCanonicalizer& other) = delete;
  TypeCanonicalizer(TypeCanonicalizer&& other) = delete;
  TypeCanonicalizer& operator=(TypeCanonicalizer&& other) = delete;

  // Registers {size} types of {module} as a recursive group, starting at
  // {start_index}, and possibly canonicalizes it if an identical one has been
  // found. Modifies {module->isorecursive_canonical_type_ids}.
  V8_EXPORT_PRIVATE void AddRecursiveGroup(WasmModule* module, uint32_t size,
                                           uint32_t start_index);

  // Same as above, except it registers the last {size} types in the module.
  V8_EXPORT_PRIVATE void AddRecursiveGroup(WasmModule* module, uint32_t size);

  // Same as above, but for a group of size 1 (using the last type in the
  // module).
  V8_EXPORT_PRIVATE void AddRecursiveSingletonGroup(WasmModule* module);

  // Same as above, but receives an explicit start index.
  V8_EXPORT_PRIVATE void AddRecursiveSingletonGroup(WasmModule* module,
                                                    uint32_t start_index);

  // Adds a module-independent signature as a recursive group, and canonicalizes
  // it if an identical is found. Returns the canonical index of the added
  // signature.
  V8_EXPORT_PRIVATE CanonicalTypeIndex
  AddRecursiveGroup(const FunctionSig* sig);

  // Retrieve back a function signature from a canonical index later.
  V8_EXPORT_PRIVATE const CanonicalSig* LookupFunctionSignature(
      CanonicalTypeIndex index) const;

  // Returns if {canonical_sub_index} is a canonical subtype of
  // {canonical_super_index}.
  V8_EXPORT_PRIVATE bool IsCanonicalSubtype(CanonicalTypeIndex sub_index,
                                            CanonicalTypeIndex super_index);

  // Returns if the type at {sub_index} in {sub_module} is a subtype of the
  // type at {super_index} in {super_module} after canonicalization.
  V8_EXPORT_PRIVATE bool IsCanonicalSubtype(ModuleTypeIndex sub_index,
                                            ModuleTypeIndex super_index,
                                            const WasmModule* sub_module,
                                            const WasmModule* super_module);

  // Deletes recursive groups. Used by fuzzers to avoid accumulating memory, and
  // used by specific tests e.g. for serialization / deserialization.
  V8_EXPORT_PRIVATE void EmptyStorageForTesting();

  size_t EstimateCurrentMemoryConsumption() const;

  size_t GetCurrentNumberOfTypes() const;

  // Prepares wasm for the provided canonical type index. This reserves enough
  // space in the canonical rtts and the JSToWasm wrappers on the isolate roots.
  V8_EXPORT_PRIVATE static void PrepareForCanonicalTypeId(
      Isolate* isolate, CanonicalTypeIndex id);
  // Reset the canonical rtts and JSToWasm wrappers on the isolate roots for
  // testing purposes (in production cases canonical type ids are never freed).
  V8_EXPORT_PRIVATE static void ClearWasmCanonicalTypesForTesting(
      Isolate* isolate);

  bool IsFunctionSignature(CanonicalTypeIndex index) const;

  CanonicalTypeIndex FindIndex_Slow(const CanonicalSig* sig) const;

#if DEBUG
  // Check whether a supposedly-canonicalized function signature does indeed
  // live in this class's storage. Useful for guarding casts of signatures
  // that are entering the typed world.
  V8_EXPORT_PRIVATE bool Contains(const CanonicalSig* sig) const;
#endif

 private:
  struct CanonicalType {
    enum Kind : int8_t { kFunction, kStruct, kArray };

    union {
      const CanonicalSig* function_sig = nullptr;
      const CanonicalStructType* struct_type;
      const CanonicalArrayType* array_type;
    };
    CanonicalTypeIndex supertype{kNoSuperType};
    Kind kind = kFunction;
    bool is_final = false;
    bool is_shared = false;
    uint8_t subtyping_depth = 0;

    constexpr CanonicalType(const CanonicalSig* sig,
                            CanonicalTypeIndex supertype, bool is_final,
                            bool is_shared)
        : function_sig(sig),
          supertype(supertype),
          kind(kFunction),
          is_final(is_final),
          is_shared(is_shared) {}

    constexpr CanonicalType(const CanonicalStructType* type,
                            CanonicalTypeIndex supertype, bool is_final,
                            bool is_shared)
        : struct_type(type),
          supertype(supertype),
          kind(kStruct),
          is_final(is_final),
          is_shared(is_shared) {}

    constexpr CanonicalType(const CanonicalArrayType* type,
                            CanonicalTypeIndex supertype, bool is_final,
                            bool is_shared)
        : array_type(type),
          supertype(supertype),
          kind(kArray),
          is_final(is_final),
          is_shared(is_shared) {}

    constexpr CanonicalType() = default;
  };

  // Define the range of a recursion group; for use in {CanonicalHashing} and
  // {CanonicalEquality}.
  struct RecursionGroupRange {
    const CanonicalTypeIndex start;
    const CanonicalTypeIndex end;

    bool Contains(CanonicalTypeIndex index) const {
      return base::IsInRange(index.index, start.index, end.index);
    }

    CanonicalTypeIndex RelativeIndex(CanonicalTypeIndex index) const {
      return Contains(index)
                 // Make the value_type relative within the recursion group.
                 ? CanonicalTypeIndex{index.index - start.index}
                 : index;
    }

    CanonicalValueType RelativeType(CanonicalValueType type) const {
      return type.has_index()
                 ? CanonicalValueType::FromIndex(
                       type.kind(), RelativeIndex(type.ref_index()))
                 : type;
    }
  };

  // Support for hashing of recursion groups, where type indexes have to be
  // hashed relative to the recursion group.
  struct CanonicalHashing {
    base::Hasher hasher;
    const RecursionGroupRange recgroup;

    explicit CanonicalHashing(RecursionGroupRange recgroup)
        : recgroup{recgroup} {}

    void Add(CanonicalType type) {
      CanonicalTypeIndex relative_supertype =
          recgroup.RelativeIndex(type.supertype);
      uint32_t metadata =
          (relative_supertype.index << 1) | (type.is_final ? 1 : 0);
      hasher.Add(metadata);
      switch (type.kind) {
        case CanonicalType::kFunction:
          Add(*type.function_sig);
          break;
        case CanonicalType::kStruct:
          Add(*type.struct_type);
          break;
        case CanonicalType::kArray:
          Add(*type.array_type);
          break;
      }
    }

    void Add(CanonicalValueType value_type) {
      hasher.Add(recgroup.RelativeType(value_type));
    }

    void Add(const CanonicalSig& sig) {
      hasher.Add(sig.parameter_count());
      for (CanonicalValueType type : sig.all()) Add(type);
    }

    void Add(const CanonicalStructType& struct_type) {
      hasher.AddRange(struct_type.mutabilities());
      for (const ValueTypeBase& field : struct_type.fields()) {
        Add(CanonicalValueType{field});
      }
    }

    void Add(const CanonicalArrayType& array_type) {
      hasher.Add(array_type.mutability());
      Add(array_type.element_type());
    }

    size_t hash() const { return hasher.hash(); }
  };

  // Support for equality checking of recursion groups, where type indexes have
  // to be compared relative to their respective recursion group.
  struct CanonicalEquality {
    // Recursion group bounds for LHS and RHS.
    const RecursionGroupRange recgroup1;
    const RecursionGroupRange recgroup2;

    CanonicalEquality(RecursionGroupRange recgroup1,
                      RecursionGroupRange recgroup2)
        : recgroup1{recgroup1}, recgroup2{recgroup2} {}

    bool EqualType(const CanonicalType& type1,
                   const CanonicalType& type2) const {
      if (recgroup1.RelativeIndex(type1.supertype) !=
          recgroup2.RelativeIndex(type2.supertype)) {
        return false;
      }
      if (type1.is_final != type2.is_final) return false;
      if (type1.is_shared != type2.is_shared) return false;
      switch (type1.kind) {
        case CanonicalType::kFunction:
          return type2.kind == CanonicalType::kFunction &&
                 EqualSig(*type1.function_sig, *type2.function_sig);
        case CanonicalType::kStruct:
          return type2.kind == CanonicalType::kStruct &&
                 EqualStructType(*type1.struct_type, *type2.struct_type);
        case CanonicalType::kArray:
          return type2.kind == CanonicalType::kArray &&
                 EqualArrayType(*type1.array_type, *type2.array_type);
      }
    }

    bool EqualTypes(base::Vector<const CanonicalType> types1,
                    base::Vector<const CanonicalType> types2) const {
      return std::equal(types1.begin(), types1.end(), types2.begin(),
                        types2.end(),
                        std::bind_front(&CanonicalEquality::EqualType, this));
    }

    bool EqualValueType(CanonicalValueType type1,
                        CanonicalValueType type2) const {
      return recgroup1.RelativeType(type1) == recgroup2.RelativeType(type2);
    }

    bool EqualSig(const CanonicalSig& sig1, const CanonicalSig& sig2) const {
      if (sig1.parameter_count() != sig2.parameter_count()) return false;
      return std::equal(
          sig1.all().begin(), sig1.all().end(), sig2.all().begin(),
          sig2.all().end(),
          std::bind_front(&CanonicalEquality::EqualValueType, this));
    }

    bool EqualStructType(const CanonicalStructType& type1,
                         const CanonicalStructType& type2) const {
      return std::equal(
          type1.fields().begin(), type1.fields().end(), type2.fields().begin(),
          type2.fields().end(),
          std::bind_front(&CanonicalEquality::EqualValueType, this));
    }

    bool EqualArrayType(const CanonicalArrayType& type1,
                        const CanonicalArrayType& type2) const {
      return type1.mutability() == type2.mutability() &&
             EqualValueType(type1.element_type(), type2.element_type());
    }
  };

  struct CanonicalGroup {
    CanonicalGroup(Zone* zone, size_t size, CanonicalTypeIndex start)
        : types(zone->AllocateVector<CanonicalType>(size)), start(start) {
      // size >= 2; otherwise a `CanonicalSingletonGroup` should have been used.
      DCHECK_LE(2, size);
    }

    bool operator==(const CanonicalGroup& other) const {
      CanonicalTypeIndex end{start.index +
                             static_cast<uint32_t>(types.size() - 1)};
      CanonicalTypeIndex other_end{
          other.start.index + static_cast<uint32_t>(other.types.size() - 1)};
      CanonicalEquality equality{{start, end}, {other.start, other_end}};
      return equality.EqualTypes(types, other.types);
    }

    size_t hash_value() const {
      CanonicalTypeIndex end{start.index + static_cast<uint32_t>(types.size()) -
                             1};
      CanonicalHashing hasher{{start, end}};
      for (CanonicalType t : types) {
        hasher.Add(t);
      }
      return hasher.hash();
    }

    // The storage of this vector is the TypeCanonicalizer's zone_.
    const base::Vector<CanonicalType> types;
    const CanonicalTypeIndex start;
  };

  struct CanonicalSingletonGroup {
    bool operator==(const CanonicalSingletonGroup& other) const {
      CanonicalEquality equality{{index, index}, {other.index, other.index}};
      return equality.EqualType(type, other.type);
    }

    size_t hash_value() const {
      CanonicalHashing hasher{{index, index}};
      hasher.Add(type);
      return hasher.hash();
    }

    CanonicalType type;
    CanonicalTypeIndex index;
  };

  void AddPredefinedArrayTypes();

  CanonicalTypeIndex FindCanonicalGroup(const CanonicalGroup&) const;
  CanonicalTypeIndex FindCanonicalGroup(const CanonicalSingletonGroup&) const;

  // Canonicalize the module-specific type at `module_type_idx` within the
  // recursion group starting at `recursion_group_start`, using
  // `canonical_recgroup_start` as the start offset of types within the
  // recursion group.
  CanonicalType CanonicalizeTypeDef(
      const WasmModule* module, ModuleTypeIndex module_type_idx,
      ModuleTypeIndex recgroup_start,
      CanonicalTypeIndex canonical_recgroup_start);

  CanonicalTypeIndex AddRecursiveGroup(CanonicalType type);

  void CheckMaxCanonicalIndex() const;

  std::vector<CanonicalTypeIndex> canonical_supertypes_;
  // Set of all known canonical recgroups of size >=2.
  std::unordered_set<CanonicalGroup, base::hash<CanonicalGroup>>
      canonical_groups_;
  // Set of all known canonical recgroups of size 1.
  std::unordered_set<CanonicalSingletonGroup,
                     base::hash<CanonicalSingletonGroup>>
      canonical_singleton_groups_;
  // Maps canonical indices back to the function signature.
  std::unordered_map<CanonicalTypeIndex, const CanonicalSig*,
                     base::hash<CanonicalTypeIndex>>
      canonical_function_sigs_;
  AccountingAllocator allocator_;
  Zone zone_{&allocator_, "canonical type zone"};
  mutable base::Mutex mutex_;
};

// Returns a reference to the TypeCanonicalizer shared by the entire process.
V8_EXPORT_PRIVATE TypeCanonicalizer* GetTypeCanonicalizer();

}  // namespace v8::internal::wasm

#endif  // V8_WASM_CANONICAL_TYPES_H_
```