Response: Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a summary of the functionality of a C++ file named `subtyping-unittest.cc` within the V8 (JavaScript engine) project's WebAssembly (Wasm) module. The "unittest" part immediately tells us this is a file containing tests. The "subtyping" part gives us the core concept being tested.

2. **Initial Scan for Key Elements:**  Quickly look through the code for prominent keywords and structures:
    * `#include`:  This section lists the dependencies. Notice `wasm/canonical-types.h` and `wasm/wasm-subtyping.h`—these are directly related to the core concept. The `test/` includes confirm it's a testing file.
    * `namespace`:  This helps organize the code. The namespace `v8::internal::wasm::subtyping_unittest` reinforces the file's purpose.
    * `class WasmSubtypingTest`: This is the main test fixture. It inherits from `TestWithPlatform`, suggesting it interacts with some platform-specific aspects (though the tests themselves might be platform-independent).
    * `using`: These lines define type aliases for brevity. `FieldInit`, `Idx` are important for understanding the test setup.
    * `constexpr`:  These define constants, often used for test data. `ref` and `refNull` are clearly related to Wasm reference types.
    * Functions like `DefineStruct`, `DefineArray`, `DefineSignature`:  These are helper functions to create Wasm types for testing. The parameters indicate the properties of these types (fields, supertypes, etc.).
    * `TEST_F`: This macro from the testing framework (likely Google Test) defines individual test cases. The test case name `Subtyping` is the central piece.
    * Loops and conditional statements within the `Subtyping` test: These indicate the various scenarios being tested.
    * Macros like `SUBTYPE`, `NOT_SUBTYPE`, `IDENTICAL`, `UNION`, `INTERSECTION`: These are custom macros to make the test assertions more readable and concise.

3. **Focus on the `Subtyping` Test Case:** This is where the core functionality is exercised.

4. **Analyze the Test Setup:** The code within the `Subtyping` test does the following:
    * Creates two `WasmModule` objects (`module1_`, `module2_`). The fact that there are *two* modules suggests cross-module subtyping relationships might be tested.
    * Uses the `Define...` functions to populate these modules with a variety of Wasm types: structs, arrays, and function signatures. The comments like `/* 0 */`, `/* 1 */`, etc., label these type definitions, making it easier to follow the test logic. The relationships between these types (e.g., supertypes) are crucial.
    * Defines constant arrays `numeric_types` and `ref_types`. These represent the basic value and reference types being tested.
    * Defines a series of macros for assertions, making the test logic clearer.

5. **Understand the Test Assertions:** The macros within the loops perform assertions about subtyping relationships:
    * `SUBTYPE(type1, type2)`: Asserts that `type1` is a subtype of `type2`.
    * `NOT_SUBTYPE(type1, type2)`: Asserts that `type1` is *not* a subtype of `type2`.
    * `VALID_SUBTYPE`, `NOT_VALID_SUBTYPE`: Likely test the validity of subtype *definitions* (as opposed to just the runtime subtype relationship).
    * `IDENTICAL`, `DISTINCT`: Test for type equivalence.
    * `UNION`, `INTERSECTION`: Test the results of type union and intersection operations.

6. **Identify the Key Areas Being Tested:** By looking at the loops and the assertions, we can pinpoint the specific aspects of subtyping being validated:
    * Subtyping relationships between numeric types.
    * Subtyping between numeric and reference types.
    * Subtyping within different categories of reference types (e.g., `eqref`, `structref`, `funcref`).
    * Handling of nullable reference types (`RefNull`).
    * Subtyping involving structs with different field mutability and inheritance.
    * Subtyping of arrays.
    * Subtyping of function signatures (contravariance of parameters, covariance of return types).
    * Handling of recursive types.
    * Testing type canonicalization (ensuring equivalent recursive types are treated the same).
    * Testing final types (types that cannot be further extended).
    * Testing shared types (types used in multithreading).
    * Testing abstract types (like `eqref`, `anyref`).
    * Testing the `Union` and `Intersection` operations on various type combinations.
    * Testing general properties of subtyping, union, and intersection (commutativity, associativity, transitivity, neutral elements, absorbing elements).

7. **Synthesize the Summary:**  Combine the observations into a concise description of the file's purpose and functionality. Focus on the "what" and "why" rather than the "how" (the specific code details). Use clear and understandable language.

8. **Refine and Organize:** Structure the summary logically, perhaps starting with a high-level overview and then going into more specific details about the tested areas. Use bullet points or numbered lists for better readability.

Self-Correction/Refinement during the process:

* **Initial thought:** "It's just testing subtyping."  **Correction:**  Realized it's testing *various aspects* of subtyping in the context of Wasm, including specific type categories, recursive types, shared types, and type operations like union and intersection.
* **Focus too much on individual macros:** **Correction:**  Shifted the focus to the *purpose* of the assertions rather than the exact implementation of the macros.
* **Miss the cross-module aspect:** **Correction:** Noticed the use of `module1` and `module2` in the assertions, indicating that subtyping *across* modules is also being tested. This is important for Wasm's module linking.
* **Overlook helper functions:** **Correction:** Recognized the importance of the `Define...` functions in setting up the test scenarios.

By following these steps, and iterating as needed, you can arrive at a comprehensive and accurate summary of the C++ code's functionality.
这个C++源代码文件 `subtyping-unittest.cc` 是 V8 JavaScript 引擎中 WebAssembly (Wasm) 模块的一部分，专门用于**测试 Wasm 类型系统的子类型关系 (Subtyping)**。

具体来说，它的功能可以归纳为以下几点：

1. **定义和创建 Wasm 类型：**
   - 使用辅助函数 (`DefineStruct`, `DefineArray`, `DefineSignature`) 来创建各种 Wasm 的结构体 (struct)、数组 (array) 和函数签名 (function signature) 类型。
   - 可以设置类型的属性，例如字段的可变性 (mutable/immutable)、父类型 (supertype)、是否为 final 类型、是否为共享类型等。
   - 支持定义相互递归的类型。

2. **测试各种子类型关系：**
   - 使用一系列的测试宏 (`SUBTYPE`, `NOT_SUBTYPE`, `SUBTYPE_IFF`, `VALID_SUBTYPE`, `NOT_VALID_SUBTYPE`) 来断言不同 Wasm 类型之间的子类型关系是否符合预期。
   - 测试了以下类型的子类型关系：
     - 基本数值类型 (i32, i64, f32, f64, s128)。
     - 各种引用类型 (ref)：`funcref`, `eqref`, `structref`, `arrayref`, `i31ref`, `anyref`, `externref`, `nullexternref`, `nullref`, `nullfuncref`, `stringref`, `stringview_iter`, `exnref`, `nullexnref`, 以及用户自定义的结构体、数组和函数签名引用。
     - 可空引用类型 (`ref null`) 和非空引用类型 (`ref`) 之间的关系。
     - 具有继承关系的结构体和函数签名之间的关系。
     - 具有不同可变性字段的结构体之间的关系。
     - 递归类型之间的关系。
     - final 类型和非 final 类型之间的关系。
     - 共享类型和非共享类型之间的关系。
     - 抽象类型 (`eqref`, `anyref` 等) 之间的关系。
     - RTT (Run-Time Type) 类型之间的关系。

3. **测试类型等价性：**
   - 使用 `IDENTICAL` 和 `DISTINCT` 宏来断言两个 Wasm 类型是否等价。
   - 测试了递归类型的规范化，确保等价的递归类型被视为相同。

4. **测试类型联合 (Union) 和交叉 (Intersection) 操作：**
   - 使用 `UNION` 和 `INTERSECTION` 宏来断言两个 Wasm 类型的联合和交叉结果是否符合预期。
   - 测试了各种类型组合的联合和交叉操作，包括数值类型、引用类型、可空类型、抽象类型以及用户自定义的类型。

5. **跨模块测试：**
   - 代码中创建了两个 `WasmModule` 对象 (`module1_`, `module2_`)，并在测试中同时使用这两个模块。这表明测试也涵盖了**跨模块的子类型关系**，即一个模块中定义的类型是否是另一个模块中定义的类型的子类型。

6. **通用子类型规则测试：**
   - 最后一部分代码使用嵌套循环遍历所有测试类型，并断言一些通用的子类型规则，例如：
     - 自反性 (一个类型是它自身的子类型)。
     - 传递性 (如果 A 是 B 的子类型，B 是 C 的子类型，那么 A 是 C 的子类型)。
     - 联合和交叉操作的交换律和结合律。
     - 联合类型是其所有组成类型的父类型。
     - 交叉类型是其所有组成类型的子类型。
     - 与 `kWasmTop` 和 `kWasmBottom` 的联合和交叉操作。

**总而言之，`subtyping-unittest.cc` 文件全面地测试了 V8 引擎中 WebAssembly 类型系统的子类型机制，确保了类型系统在各种场景下的正确性和一致性，这对于保证 Wasm 代码的类型安全性和互操作性至关重要。**

Prompt: ```这是目录为v8/test/unittests/wasm/subtyping-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/canonical-types.h"
#include "src/wasm/wasm-subtyping.h"
#include "test/common/flag-utils.h"
#include "test/common/wasm/flag-utils.h"
#include "test/unittests/test-utils.h"

namespace v8::internal::wasm::subtyping_unittest {

class WasmSubtypingTest : public TestWithPlatform {};
using FieldInit = std::pair<ValueType, bool>;
using Idx = ModuleTypeIndex;

constexpr ValueType ref(uint32_t index) { return ValueType::Ref(Idx{index}); }
constexpr ValueType refNull(uint32_t index) {
  return ValueType::RefNull(Idx{index});
}

FieldInit mut(ValueType type) { return FieldInit(type, true); }
FieldInit immut(ValueType type) { return FieldInit(type, false); }

void DefineStruct(WasmModule* module, std::initializer_list<FieldInit> fields,
                  ModuleTypeIndex supertype = kNoSuperType,
                  bool is_final = false, bool is_shared = false,
                  bool in_singleton_rec_group = true) {
  StructType::Builder builder(&module->signature_zone,
                              static_cast<uint32_t>(fields.size()));
  for (FieldInit field : fields) {
    builder.AddField(field.first, field.second);
  }
  module->AddStructTypeForTesting(builder.Build(), supertype, is_final,
                                  is_shared);
  if (in_singleton_rec_group) {
    GetTypeCanonicalizer()->AddRecursiveSingletonGroup(module);
  }
}

void DefineArray(WasmModule* module, FieldInit element_type,
                 ModuleTypeIndex supertype = kNoSuperType,
                 bool is_final = false, bool is_shared = false,
                 bool in_singleton_rec_group = true) {
  module->AddArrayTypeForTesting(module->signature_zone.New<ArrayType>(
                                     element_type.first, element_type.second),
                                 supertype, is_final, is_shared);
  if (in_singleton_rec_group) {
    GetTypeCanonicalizer()->AddRecursiveSingletonGroup(module);
  }
}

void DefineSignature(WasmModule* module,
                     std::initializer_list<ValueType> params,
                     std::initializer_list<ValueType> returns,
                     ModuleTypeIndex supertype = kNoSuperType,
                     bool is_final = false, bool is_shared = false,
                     bool in_singleton_rec_group = true) {
  module->AddSignatureForTesting(
      FunctionSig::Build(&module->signature_zone, returns, params), supertype,
      is_final, is_shared);
  if (in_singleton_rec_group) {
    GetTypeCanonicalizer()->AddRecursiveGroup(module, 1);
  }
}

TEST_F(WasmSubtypingTest, Subtyping) {
  v8::internal::AccountingAllocator allocator;
  WasmModule module1_;
  WasmModule module2_;

  WasmModule* module1 = &module1_;
  WasmModule* module2 = &module2_;

  // Set up two identical modules.
  for (WasmModule* module : {module1, module2}) {
    // Three mutually recursive types.
    /*  0 */ DefineStruct(module, {mut(ref(2)), immut(refNull(2))},
                          kNoSuperType, false, false, false);
    /*  1 */ DefineStruct(module, {mut(ref(2)), immut(ref(2))}, Idx{0}, false,
                          false, false);
    /*  2 */ DefineArray(module, immut(ref(0)), kNoSuperType, false, false,
                         false);
    GetTypeCanonicalizer()->AddRecursiveGroup(module, 3);

    /*  3 */ DefineArray(module, immut(ref(1)), Idx{2});
    /*  4 */ DefineStruct(module, {mut(ref(2)), immut(ref(3)), immut(kWasmF64)},
                          Idx{1});
    /*  5 */ DefineStruct(module, {mut(refNull(2)), immut(ref(2))});
    /*  6 */ DefineArray(module, mut(kWasmI32));
    /*  7 */ DefineArray(module, immut(kWasmI32));
    /*  8 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(8))});
    /*  9 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(8))}, Idx{8});
    /* 10 */ DefineSignature(module, {}, {});
    /* 11 */ DefineSignature(module, {kWasmI32}, {kWasmI32});
    /* 12 */ DefineSignature(module, {kWasmI32, kWasmI32}, {kWasmI32});
    /* 13 */ DefineSignature(module, {ref(1)}, {kWasmI32});
    /* 14 */ DefineSignature(module, {ref(0)}, {kWasmI32}, Idx{13});
    /* 15 */ DefineSignature(module, {ref(0)}, {ref(0)});
    /* 16 */ DefineSignature(module, {ref(0)}, {ref(4)}, Idx{15});
    /* 17 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(17))});

    // Rec. group.
    /* 18 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(17))}, Idx{17},
                          false, false, false);
    /* 19 */ DefineArray(module, {mut(refNull(21))}, kNoSuperType, false, false,
                         false);
    /* 20 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, kNoSuperType,
                             false, false, false);
    /* 21 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, Idx{20}, false,
                             false, false);
    GetTypeCanonicalizer()->AddRecursiveGroup(module, 4);

    // Identical rec. group.
    /* 22 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(17))}, Idx{17},
                          false, false, false);
    /* 23 */ DefineArray(module, {mut(refNull(25))}, kNoSuperType, false, false,
                         false);
    /* 24 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, kNoSuperType,
                             false, false, false);
    /* 25 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, Idx{24}, false,
                             false, false);
    GetTypeCanonicalizer()->AddRecursiveGroup(module, 4);

    // Nonidentical rec. group: the last function extends a type outside the
    // recursive group.
    /* 26 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(17))}, Idx{17},
                          false, false, false);
    /* 27 */ DefineArray(module, {mut(refNull(29))}, kNoSuperType, false, false,
                         false);
    /* 28 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, kNoSuperType,
                             false, false, false);
    /* 29 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, Idx{20}, false,
                             false, false);
    GetTypeCanonicalizer()->AddRecursiveGroup(module, 4);

    /* 30 */ DefineStruct(module, {mut(kWasmI32), immut(refNull(18))}, Idx{18});
    /* 31 */ DefineStruct(
        module, {mut(ref(2)), immut(refNull(2)), immut(kWasmS128)}, Idx{1});

    // Final types
    /* 32 */ DefineStruct(module, {mut(kWasmI32)}, kNoSuperType, true);
    /* 33 */ DefineStruct(module, {mut(kWasmI32), mut(kWasmI64)}, Idx{32},
                          true);
    /* 34 */ DefineStruct(module, {mut(kWasmI32)}, kNoSuperType, true);
    /* 35 */ DefineStruct(module, {mut(kWasmI32)}, kNoSuperType, false);

    // Shared types.
    /* 36 */ DefineStruct(module, {mut(kWasmI32)}, kNoSuperType);
    /* 37 */ DefineStruct(module, {mut(kWasmI32), mut(kWasmI64)}, Idx{36});
    /* 38 */ DefineStruct(module, {mut(kWasmI32)}, kNoSuperType, false, true);
    /* 39 */ DefineStruct(module, {mut(kWasmI32), mut(kWasmI64)}, Idx{38},
                          false, true);
    /* 40 */ DefineStruct(module, {mut(kWasmI32)}, kNoSuperType, false, true);
    /* 41 */ DefineSignature(module, {kWasmI32}, {kWasmI32}, kNoSuperType,
                             false, true, true);
  }

  constexpr ValueType numeric_types[] = {kWasmI32, kWasmI64, kWasmF32, kWasmF64,
                                         kWasmS128};
  constexpr ValueType ref_types[] = {
      kWasmFuncRef,     kWasmEqRef,         kWasmStructRef,
      kWasmArrayRef,    kWasmI31Ref,        kWasmAnyRef,
      kWasmExternRef,   kWasmNullExternRef, kWasmNullRef,
      kWasmNullFuncRef, kWasmStringRef,     kWasmStringViewIter,
      kWasmExnRef,      kWasmNullExnRef,    kWasmRefNullExternString,
      refNull(0),   // struct
      ref(0),       // struct
      refNull(2),   // array
      ref(2),       // array
      refNull(11),  // signature
      ref(11)       // signature
  };

// Some macros to help managing types and modules.
#define SUBTYPE(type1, type2) \
  EXPECT_TRUE(IsSubtypeOf(type1, type2, module1, module))
#define SUBTYPE_IFF(type1, type2, condition) \
  EXPECT_EQ(IsSubtypeOf(type1, type2, module1, module), condition)
#define NOT_SUBTYPE(type1, type2) \
  EXPECT_FALSE(IsSubtypeOf(type1, type2, module1, module))
// Use only with indexed types.
#define VALID_SUBTYPE(type1, type2)                                        \
  EXPECT_TRUE(ValidSubtypeDefinition(type1.ref_index(), type2.ref_index(), \
                                     module1, module));                    \
  EXPECT_TRUE(IsSubtypeOf(type1, type2, module1, module));
#define NOT_VALID_SUBTYPE(type1, type2)                                     \
  EXPECT_FALSE(ValidSubtypeDefinition(type1.ref_index(), type2.ref_index(), \
                                      module1, module));
#define IDENTICAL(index1, index2) \
  EXPECT_TRUE(                    \
      EquivalentTypes(refNull(index1), refNull(index2), module1, module));
#define DISTINCT(index1, index2) \
  EXPECT_FALSE(                  \
      EquivalentTypes(refNull(index1), refNull(index2), module1, module));
// For union and intersection, we have a version that also checks the module,
// and one that does not.
#define UNION(type1, type2, type_result) \
  EXPECT_EQ(Union(type1, type2, module1, module).type, type_result)
#define UNION_M(type1, type2, type_result, module_result) \
  EXPECT_EQ(Union(type1, type2, module1, module),         \
            TypeInModule(type_result, module_result))
#define INTERSECTION(type1, type2, type_result) \
  EXPECT_EQ(Intersection(type1, type2, module1, module).type, type_result)
#define INTERSECTION_M(type1, type2, type_result, module_result) \
  EXPECT_EQ(Intersection(type1, type2, module1, module),         \
            TypeInModule(type_result, module_result))

  for (WasmModule* module : {module1, module2}) {
    // Type judgements across modules should work the same as within one module.

    // Value types are unrelated, except if they are equal.
    for (ValueType subtype : numeric_types) {
      for (ValueType supertype : numeric_types) {
        SUBTYPE_IFF(subtype, supertype, subtype == supertype);
      }
    }

    // Value types are unrelated with reference types.
    for (ValueType value_type : numeric_types) {
      for (ValueType ref_type : ref_types) {
        NOT_SUBTYPE(value_type, ref_type);
        NOT_SUBTYPE(ref_type, value_type);
      }
    }

    for (ValueType ref_type : ref_types) {
      const bool is_extern = ref_type == kWasmExternRef ||
                             ref_type == kWasmNullExternRef ||
                             ref_type == kWasmRefNullExternString;
      const bool is_any_func = ref_type == kWasmFuncRef ||
                               ref_type == kWasmNullFuncRef ||
                               ref_type == refNull(11) || ref_type == ref(11);
      const bool is_string_view = ref_type == kWasmStringViewIter ||
                                  ref_type == kWasmStringViewWtf8 ||
                                  ref_type == kWasmStringViewWtf16;
      const bool is_exn =
          ref_type == kWasmExnRef || ref_type == kWasmNullExnRef;
      SCOPED_TRACE("ref_type: " + ref_type.name());
      // Concrete reference types, i31ref, structref and arrayref are subtypes
      // of eqref, externref/funcref/anyref/exnref/functions are not.
      SUBTYPE_IFF(ref_type, kWasmEqRef,
                  ref_type != kWasmAnyRef && !is_any_func && !is_extern &&
                      !is_string_view && ref_type != kWasmStringRef && !is_exn);
      // Struct types are subtypes of structref.
      SUBTYPE_IFF(ref_type, kWasmStructRef,
                  ref_type == kWasmStructRef || ref_type == kWasmNullRef ||
                      ref_type == ref(0) || ref_type == refNull(0));
      // Array types are subtypes of arrayref.
      SUBTYPE_IFF(ref_type, kWasmArrayRef,
                  ref_type == kWasmArrayRef || ref_type == ref(2) ||
                      ref_type == kWasmNullRef || ref_type == refNull(2));
      // Functions are subtypes of funcref.
      SUBTYPE_IFF(ref_type, kWasmFuncRef, is_any_func);
      // Each reference type is a subtype of itself.
      SUBTYPE(ref_type, ref_type);
      // Each non-func, non-extern, non-string-view, non-string-iter reference
      // type is a subtype of anyref.
      SUBTYPE_IFF(ref_type, kWasmAnyRef,
                  !is_any_func && !is_extern && !is_string_view && !is_exn);
      // Only anyref is a subtype of anyref.
      SUBTYPE_IFF(kWasmAnyRef, ref_type, ref_type == kWasmAnyRef);
      // Only externref and nullexternref are subtypes of externref.
      SUBTYPE_IFF(ref_type, kWasmExternRef, is_extern);
      // Only nullexternref is a subtype of nullexternref.
      SUBTYPE_IFF(ref_type, kWasmNullExternRef, ref_type == kWasmNullExternRef);
      // Each nullable non-func, non-extern reference type is a supertype of
      // nullref.
      SUBTYPE_IFF(
          kWasmNullRef, ref_type,
          ref_type.is_nullable() && !is_any_func && !is_extern && !is_exn);
      // Only nullref is a subtype of nullref.
      SUBTYPE_IFF(ref_type, kWasmNullRef, ref_type == kWasmNullRef);
      // Only nullable funcs are supertypes of nofunc.
      SUBTYPE_IFF(kWasmNullFuncRef, ref_type,
                  ref_type.is_nullable() && is_any_func);
      // Only nullfuncref is a subtype of nullfuncref.
      SUBTYPE_IFF(ref_type, kWasmNullFuncRef, ref_type == kWasmNullFuncRef);

      // Make sure symmetric relations are symmetric.
      for (ValueType ref_type2 : ref_types) {
        if (ref_type == ref_type2) {
          EXPECT_TRUE(EquivalentTypes(ref_type, ref_type2, module, module1));
          EXPECT_TRUE(EquivalentTypes(ref_type2, ref_type, module1, module));
        } else {
          EXPECT_FALSE(EquivalentTypes(ref_type, ref_type2, module, module1));
          EXPECT_FALSE(EquivalentTypes(ref_type2, ref_type, module1, module));
        }
      }
    }

    // The rest of ref. types are unrelated.
    for (ValueType type_1 :
         {kWasmFuncRef, kWasmI31Ref, kWasmArrayRef, kWasmExnRef}) {
      for (ValueType type_2 :
           {kWasmFuncRef, kWasmI31Ref, kWasmArrayRef, kWasmExnRef}) {
        SUBTYPE_IFF(type_1, type_2, type_1 == type_2);
      }
    }

    // Unrelated refs are unrelated.
    NOT_VALID_SUBTYPE(ref(0), ref(2));
    NOT_VALID_SUBTYPE(refNull(3), refNull(1));
    // ref is a subtype of ref null for the same struct/array.
    VALID_SUBTYPE(ref(0), refNull(0));
    VALID_SUBTYPE(ref(2), refNull(2));
    // ref null is not a subtype of ref for the same struct/array.
    NOT_SUBTYPE(refNull(0), ref(0));
    NOT_SUBTYPE(refNull(2), ref(2));
    // ref is a subtype of ref null if the same is true for the underlying
    // structs/arrays.
    VALID_SUBTYPE(ref(3), refNull(2));
    // Prefix subtyping for structs.
    VALID_SUBTYPE(refNull(4), refNull(0));
    // Mutable fields are invariant.
    NOT_VALID_SUBTYPE(ref(0), ref(5));
    // Immutable fields are covariant.
    VALID_SUBTYPE(ref(1), ref(0));
    // Prefix subtyping + immutable field covariance for structs.
    VALID_SUBTYPE(refNull(4), refNull(1));
    // No subtyping between mutable/immutable fields.
    NOT_VALID_SUBTYPE(ref(7), ref(6));
    NOT_VALID_SUBTYPE(ref(6), ref(7));
    // Recursive types.
    VALID_SUBTYPE(ref(9), ref(8));

    // Identical rtts are subtypes of each other.
    SUBTYPE(ValueType::Rtt(Idx{5}), ValueType::Rtt(Idx{5}));
    // Rtts of unrelated types are unrelated.
    NOT_SUBTYPE(ValueType::Rtt(Idx{1}), ValueType::Rtt(Idx{2}));
    // Rtts of subtypes are not related.
    NOT_SUBTYPE(ValueType::Rtt(Idx{1}), ValueType::Rtt(Idx{0}));

    // Function subtyping;
    // Unrelated function types are unrelated.
    NOT_VALID_SUBTYPE(ref(10), ref(11));
    // Function type with different parameter counts are unrelated.
    NOT_VALID_SUBTYPE(ref(12), ref(11));
    // Parameter contravariance holds.
    VALID_SUBTYPE(ref(14), ref(13));
    // Return type covariance holds.
    VALID_SUBTYPE(ref(16), ref(15));
    // Identical types are subtype-related.
    VALID_SUBTYPE(ref(10), ref(10));
    VALID_SUBTYPE(ref(11), ref(11));

    // Canonicalization tests.

    // Groups should only be canonicalized to identical groups.
    IDENTICAL(18, 22);
    IDENTICAL(19, 23);
    IDENTICAL(20, 24);
    IDENTICAL(21, 25);

    DISTINCT(18, 26);
    DISTINCT(19, 27);
    DISTINCT(20, 28);
    DISTINCT(21, 29);

    // A type should not be canonicalized to an identical one with a different
    // group structure.
    DISTINCT(18, 17);

    // A subtype should also be subtype of an equivalent type.
    VALID_SUBTYPE(ref(30), ref(18));
    VALID_SUBTYPE(ref(30), ref(22));
    NOT_SUBTYPE(ref(30), ref(26));

    // Final types

    // A type is not a valid subtype of a final type.
    NOT_VALID_SUBTYPE(ref(33), ref(32));
    IDENTICAL(32, 34);
    // A final and a non-final type are distinct.
    DISTINCT(32, 35);

    /* Shared types */
    // A shared type can be a subtype of a shared type.
    VALID_SUBTYPE(ref(39), ref(38));
    // A shared type is not a valid subtype of a non-shared type and vice versa.
    NOT_VALID_SUBTYPE(ref(39), ref(36));
    NOT_VALID_SUBTYPE(ref(37), ref(38));
    // Two shared types are identical. A shared and non-shared type are
    // distinct.
    IDENTICAL(38, 40);
    DISTINCT(36, 38);
    // Abstract types
    SUBTYPE(ValueType::Ref(HeapType::kEqShared),
            ValueType::Ref(HeapType::kAnyShared));
    NOT_SUBTYPE(ValueType::Ref(HeapType::kEqShared),
                ValueType::Ref(HeapType::kAny));
    NOT_SUBTYPE(ValueType::Ref(HeapType::kEq),
                ValueType::Ref(HeapType::kAnyShared));
    NOT_SUBTYPE(ValueType::Ref(HeapType::kFuncShared),
                ValueType::Ref(HeapType::kAnyShared));
    SUBTYPE(ValueType::RefNull(HeapType::kNoneShared),
            ValueType::RefNull(HeapType::kI31Shared));
    SUBTYPE(ValueType::RefNull(HeapType::kNoFuncShared),
            ValueType::RefNull(HeapType::kFuncShared));
    SUBTYPE(ref(40), ValueType::RefNull(HeapType::kEqShared));
    SUBTYPE(ValueType::RefNull(HeapType::kNoneShared), refNull(40));
    NOT_SUBTYPE(ref(40), ValueType::RefNull(HeapType::kEq));
    NOT_SUBTYPE(ref(40), ValueType::RefNull(HeapType::kExternShared));
    SUBTYPE(ref(41), ValueType::RefNull(HeapType::kFuncShared));
    SUBTYPE(ValueType::RefNull(HeapType::kNoFuncShared), refNull(41));
    NOT_SUBTYPE(ref(41), ValueType::RefNull(HeapType::kAnyShared));
    NOT_SUBTYPE(ref(41), ValueType::RefNull(HeapType::kFunc));
    NOT_SUBTYPE(ref(0), ValueType::Ref(HeapType::kStructShared));
    NOT_SUBTYPE(ref(2), ValueType::Ref(HeapType::kArrayShared));
    NOT_SUBTYPE(ref(10), ValueType::Ref(HeapType::kFuncShared));

    // Rtts of identical types are subtype-related.
    SUBTYPE(ValueType::Rtt(Idx{8}), ValueType::Rtt(Idx{17}));

    // Unions and intersections.

    // Distinct numeric types are unrelated.
    for (ValueType type1 : numeric_types) {
      for (ValueType type2 : numeric_types) {
        UNION(type1, type2, (type1 == type2 ? type1 : kWasmTop));
        INTERSECTION(type1, type2, (type1 == type2 ? type1 : kWasmBottom));
      }
    }
    // Numeric and reference types are unrelated.
    for (ValueType type1 : numeric_types) {
      for (ValueType type2 : ref_types) {
        UNION(type1, type2, kWasmTop);
        INTERSECTION(type1, type2, kWasmBottom);
      }
    }

    // Reference type vs. itself and anyref.
    for (ValueType type : ref_types) {
      SCOPED_TRACE(type.name());
      if (type == kWasmStringViewIter || type == kWasmStringViewWtf8 ||
          type == kWasmStringViewWtf16) {
        // String views aren't subtypes of any nor supertypes of null.
        INTERSECTION(type, kWasmAnyRef, kWasmBottom);
        INTERSECTION(type, kWasmNullRef, kWasmBottom);
        continue;
      }
      if (type == kWasmFuncRef || type == kWasmNullFuncRef || type == ref(11) ||
          type == refNull(11) || type == kWasmExternRef ||
          type == kWasmNullExternRef || type == kWasmRefNullExternString) {
        // func and extern types don't share the same type hierarchy as anyref.
        INTERSECTION(type, kWasmAnyRef, kWasmBottom);
        continue;
      }
      bool is_exn = type == kWasmExnRef || type == kWasmNullExnRef;
      UNION(kWasmAnyRef, type, is_exn ? kWasmTop : kWasmAnyRef);
      INTERSECTION(kWasmAnyRef, type, is_exn ? kWasmBottom : type);
      UNION(kWasmAnyRef.AsNonNull(), type,
            is_exn               ? kWasmTop
            : type.is_nullable() ? kWasmAnyRef
                                 : kWasmAnyRef.AsNonNull());
      INTERSECTION(kWasmAnyRef.AsNonNull(), type,
                   is_exn                 ? kWasmBottom
                   : type != kWasmNullRef ? type.AsNonNull()
                                          : kWasmBottom);
    }

    // Abstract types vs abstract types.
    UNION(kWasmEqRef, kWasmStructRef, kWasmEqRef);
    UNION(kWasmEqRef, kWasmI31Ref, kWasmEqRef);
    UNION(kWasmEqRef, kWasmArrayRef, kWasmEqRef);
    UNION(kWasmEqRef, kWasmNullRef, kWasmEqRef);
    UNION(kWasmStructRef, kWasmI31Ref, kWasmEqRef);
    UNION(kWasmStructRef, kWasmArrayRef, kWasmEqRef);
    UNION(kWasmStructRef, kWasmNullRef, kWasmStructRef.AsNullable());
    UNION(kWasmI31Ref.AsNonNull(), kWasmArrayRef.AsNonNull(),
          kWasmEqRef.AsNonNull());
    UNION(kWasmI31Ref, kWasmNullRef, kWasmI31Ref.AsNullable());
    UNION(kWasmArrayRef, kWasmNullRef, kWasmArrayRef.AsNullable());
    UNION(kWasmStructRef.AsNonNull(), kWasmI31Ref.AsNonNull(),
          kWasmEqRef.AsNonNull());
    UNION(kWasmI31Ref.AsNonNull(), kWasmArrayRef, kWasmEqRef);
    UNION(kWasmAnyRef, kWasmNullRef, kWasmAnyRef);
    UNION(kWasmExternRef, kWasmNullExternRef, kWasmExternRef);
    UNION(kWasmRefNullExternString, kWasmNullExternRef,
          kWasmRefNullExternString);
    UNION(kWasmRefNullExternString.AsNonNull(), kWasmNullExternRef,
          kWasmRefNullExternString);
    UNION(kWasmRefNullExternString, kWasmExternRef, kWasmExternRef);
    UNION(kWasmRefNullExternString, kWasmAnyRef, kWasmTop);
    UNION(kWasmRefNullExternString, kWasmFuncRef, kWasmTop);
    // Imported strings and stringref represent the same values. Still, they are
    // in different type hierarchies and therefore incompatible (e.g. due to
    // different null representation).
    // (There is no interoperability between stringref and imported strings as
    // they are competing proposals.)
    UNION(kWasmRefNullExternString, kWasmStringRef, kWasmTop);
    UNION(kWasmRefNullExternString.AsNonNull(), kWasmStringRef.AsNonNull(),
          kWasmTop);
    UNION(kWasmFuncRef, kWasmNullFuncRef, kWasmFuncRef);
    UNION(kWasmFuncRef, kWasmStructRef, kWasmTop);
    UNION(kWasmFuncRef, kWasmArrayRef, kWasmTop);
    UNION(kWasmFuncRef, kWasmAnyRef, kWasmTop);
    UNION(kWasmFuncRef, kWasmEqRef, kWasmTop);
    UNION(kWasmStringRef, kWasmAnyRef, kWasmAnyRef);
    UNION(kWasmStringRef, kWasmStructRef, kWasmAnyRef);
    UNION(kWasmStringRef, kWasmArrayRef, kWasmAnyRef);
    UNION(kWasmStringRef, kWasmFuncRef, kWasmTop);
    UNION(kWasmStringViewIter, kWasmStringRef, kWasmTop);
    UNION(kWasmStringViewWtf8, kWasmStringRef, kWasmTop);
    UNION(kWasmStringViewWtf16, kWasmStringRef, kWasmTop);
    UNION(kWasmStringViewIter, kWasmAnyRef, kWasmTop);
    UNION(kWasmStringViewWtf8, kWasmAnyRef, kWasmTop);
    UNION(kWasmStringViewWtf16, kWasmAnyRef, kWasmTop);
    UNION(kWasmNullFuncRef, kWasmEqRef, kWasmTop);

    INTERSECTION(kWasmExternRef, kWasmEqRef, kWasmBottom);
    INTERSECTION(kWasmExternRef, kWasmStructRef, kWasmBottom);
    INTERSECTION(kWasmExternRef, kWasmI31Ref.AsNonNull(), kWasmBottom);
    INTERSECTION(kWasmExternRef, kWasmArrayRef, kWasmBottom);
    INTERSECTION(kWasmExternRef, kWasmNullRef, kWasmBottom);
    INTERSECTION(kWasmExternRef, kWasmFuncRef, kWasmBottom);
    INTERSECTION(kWasmNullExternRef, kWasmEqRef, kWasmBottom);
    INTERSECTION(kWasmNullExternRef, kWasmStructRef, kWasmBottom);
    INTERSECTION(kWasmNullExternRef, kWasmI31Ref, kWasmBottom);
    INTERSECTION(kWasmNullExternRef, kWasmArrayRef, kWasmBottom);
    INTERSECTION(kWasmNullExternRef, kWasmNullRef, kWasmBottom);
    INTERSECTION(kWasmNullExternRef, kWasmExternRef, kWasmNullExternRef);
    INTERSECTION(kWasmNullExternRef, kWasmExternRef.AsNonNull(), kWasmBottom);
    INTERSECTION(kWasmRefNullExternString, kWasmEqRef, kWasmBottom);
    INTERSECTION(kWasmRefNullExternString, kWasmAnyRef, kWasmBottom);
    INTERSECTION(kWasmRefNullExternString, kWasmFuncRef.AsNonNull(),
                 kWasmBottom);
    INTERSECTION(kWasmRefNullExternString, kWasmNullRef, kWasmBottom);
    INTERSECTION(kWasmRefNullExternString, kWasmNullExternRef,
                 kWasmNullExternRef);
    INTERSECTION(kWasmRefNullExternString.AsNonNull(), kWasmNullExternRef,
                 kWasmBottom);
    INTERSECTION(kWasmRefNullExternString, kWasmExternRef,
                 kWasmRefNullExternString);
    INTERSECTION(kWasmRefNullExternString, kWasmExternRef.AsNonNull(),
                 kWasmRefNullExternString.AsNonNull());

    INTERSECTION(kWasmFuncRef, kWasmEqRef, kWasmBottom);
    INTERSECTION(kWasmFuncRef, kWasmStructRef, kWasmBottom);
    INTERSECTION(kWasmFuncRef, kWasmI31Ref.AsNonNull(), kWasmBottom);
    INTERSECTION(kWasmFuncRef, kWasmArrayRef, kWasmBottom);
    INTERSECTION(kWasmFuncRef, kWasmNullRef, kWasmBottom);
    INTERSECTION(kWasmFuncRef, kWasmNullExternRef, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmEqRef, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmStructRef, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmI31Ref, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmArrayRef, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmNullRef, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmFuncRef, kWasmNullFuncRef);
    INTERSECTION(kWasmNullFuncRef, kWasmFuncRef.AsNonNull(), kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, kWasmNullExternRef, kWasmBottom);

    INTERSECTION(kWasmEqRef, kWasmStructRef, kWasmStructRef);
    INTERSECTION(kWasmEqRef, kWasmI31Ref, kWasmI31Ref);
    INTERSECTION(kWasmEqRef, kWasmArrayRef, kWasmArrayRef);
    INTERSECTION(kWasmEqRef, kWasmNullRef, kWasmNullRef);
    INTERSECTION(kWasmEqRef, kWasmFuncRef, kWasmBottom);
    INTERSECTION(kWasmStructRef, kWasmI31Ref, kWasmNullRef);
    INTERSECTION(kWasmStructRef, kWasmArrayRef, kWasmNullRef);
    INTERSECTION(kWasmStructRef, kWasmNullRef, kWasmNullRef);
    INTERSECTION(kWasmI31Ref, kWasmArrayRef, kWasmNullRef);
    INTERSECTION(kWasmI31Ref.AsNonNull(), kWasmNullRef, kWasmBottom);
    INTERSECTION(kWasmArrayRef.AsNonNull(), kWasmNullRef, kWasmBottom);

    ValueType struct_type = ref(0);
    ValueType array_type = ref(2);
    ValueType function_type = ref(11);

    // Abstract vs indexed types.
    UNION(kWasmFuncRef, function_type, kWasmFuncRef);
    UNION(kWasmFuncRef, struct_type, kWasmTop);
    UNION(kWasmFuncRef, array_type, kWasmTop);
    INTERSECTION(kWasmFuncRef, struct_type, kWasmBottom);
    INTERSECTION(kWasmFuncRef, array_type, kWasmBottom);
    INTERSECTION_M(kWasmFuncRef, function_type, function_type, module);

    UNION(kWasmExnRef, struct_type, kWasmTop);
    UNION(kWasmExnRef, array_type, kWasmTop);
    UNION(kWasmExnRef, function_type, kWasmTop);
    INTERSECTION(kWasmExnRef, struct_type, kWasmBottom);
    INTERSECTION(kWasmExnRef, array_type, kWasmBottom);
    INTERSECTION(kWasmExnRef, function_type, kWasmBottom);

    UNION(kWasmNullFuncRef, function_type, function_type.AsNullable());
    UNION(kWasmNullFuncRef, struct_type, kWasmTop);
    UNION(kWasmNullFuncRef, array_type, kWasmTop);
    INTERSECTION(kWasmNullFuncRef, struct_type, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, struct_type.AsNullable(), kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, array_type, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, array_type.AsNullable(), kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, function_type, kWasmBottom);
    INTERSECTION(kWasmNullFuncRef, function_type.AsNullable(),
                 kWasmNullFuncRef);

    UNION(kWasmEqRef, struct_type, kWasmEqRef);
    UNION(kWasmEqRef, array_type, kWasmEqRef);
    INTERSECTION(kWasmEqRef, struct_type, struct_type);
    INTERSECTION(kWasmEqRef, array_type, array_type);
    INTERSECTION(kWasmEqRef, function_type, kWasmBottom);

    UNION(kWasmStructRef, struct_type, kWasmStructRef);
    UNION(kWasmStructRef, array_type, kWasmEqRef);
    UNION(kWasmStructRef, function_type, kWasmTop);
    INTERSECTION_M(kWasmStructRef, struct_type, struct_type, module);
    INTERSECTION(kWasmStructRef, array_type, kWasmBottom);
    INTERSECTION(kWasmStructRef, function_type, kWasmBottom);

    UNION(kWasmI31Ref, struct_type, kWasmEqRef);
    UNION(kWasmI31Ref, array_type, kWasmEqRef);
    INTERSECTION(kWasmI31Ref, struct_type, kWasmBottom);
    INTERSECTION(kWasmI31Ref, array_type, kWasmBottom);
    INTERSECTION(kWasmI31Ref, function_type, kWasmBottom);

    UNION(kWasmArrayRef, struct_type, kWasmEqRef);
    UNION(kWasmArrayRef, array_type, kWasmArrayRef);
    UNION(kWasmArrayRef, function_type, kWasmTop);
    INTERSECTION(kWasmArrayRef, struct_type, kWasmBottom);
    INTERSECTION_M(kWasmArrayRef, array_type, array_type, module);
    INTERSECTION(kWasmArrayRef, function_type, kWasmBottom);

    UNION_M(kWasmNullRef, struct_type, struct_type.AsNullable(), module);
    UNION_M(kWasmNullRef, array_type, array_type.AsNullable(), module);
    UNION(kWasmNullRef, function_type, kWasmTop);
    INTERSECTION(kWasmNullRef, struct_type, kWasmBottom);
    INTERSECTION(kWasmNullRef, array_type, kWasmBottom);
    INTERSECTION(kWasmNullRef, function_type, kWasmBottom);
    INTERSECTION(kWasmNullRef, struct_type.AsNullable(), kWasmNullRef);
    INTERSECTION(kWasmNullRef, array_type.AsNullable(), kWasmNullRef);
    INTERSECTION(kWasmNullRef, function_type.AsNullable(), kWasmBottom);

    UNION(struct_type, kWasmStringRef, kWasmAnyRef);
    UNION(array_type, kWasmStringRef, kWasmAnyRef);
    UNION(function_type, kWasmStringRef, kWasmTop);

    UNION(struct_type, kWasmRefNullExternString, kWasmTop);
    UNION(array_type, kWasmRefNullExternString, kWasmTop);
    UNION(function_type, kWasmRefNullExternString, kWasmTop);

    // Indexed types of different kinds.
    UNION(struct_type, array_type, kWasmEqRef.AsNonNull());
    INTERSECTION(struct_type, array_type, kWasmBottom);
    INTERSECTION(struct_type, function_type, kWasmBottom);
    INTERSECTION(array_type, function_type, kWasmBottom);

    // Nullable vs. non-nullable.
    UNION(struct_type, struct_type.AsNullable(), struct_type.AsNullable());
    INTERSECTION(struct_type, struct_type.AsNullable(), struct_type);
    UNION(kWasmStructRef, kWasmStructRef.AsNullable(),
          kWasmStructRef.AsNullable());
    INTERSECTION(kWasmStructRef, kWasmStructRef.AsNullable(), kWasmStructRef);

    // Concrete types of the same kind.
    // Subtyping relation.
    UNION_M(refNull(4), ref(1), refNull(1), module1);
    INTERSECTION_M(refNull(4), ref(1), ref(4), module1);
    INTERSECTION_M(refNull(1), refNull(4), refNull(4), module);
    // Common ancestor.
    UNION_M(ref(4), ref(31), ref(1), module1);
    INTERSECTION(ref(4), ref(31), kWasmBottom);
    // No common ancestor.
    UNION(ref(6), refNull(2), kWasmArrayRef.AsNullable());
    INTERSECTION(ref(6), refNull(2), kWasmBottom);
    UNION(ref(0), ref(17), kWasmStructRef.AsNonNull());
    INTERSECTION(ref(0), ref(17), kWasmBottom);
    UNION(ref(10), refNull(11), kWasmFuncRef);
    INTERSECTION(ref(10), refNull(11), kWasmBottom);

    // Shared types
    ValueType struct_shared = ref(40);
    ValueType function_shared = ref(41);
    UNION(struct_shared, struct_shared.AsNullable(),
          struct_shared.AsNullable());
    UNION(struct_shared, struct_type, kWasmTop);
    UNION(struct_shared, function_shared, kWasmTop);
    UNION(struct_shared, ValueType::Ref(HeapType::kI31Shared),
          ValueType::Ref(HeapType::kEqShared));
    UNION(struct_shared, ValueType::Ref(HeapType::kAnyShared),
          ValueType::Ref(HeapType::kAnyShared));
    UNION(struct_shared, ValueType::Ref(HeapType::kNoneShared), struct_shared);
    UNION(struct_shared, ValueType::Ref(HeapType::kAny), kWasmTop);
    INTERSECTION(struct_shared, struct_shared.AsNullable(), struct_shared);
    INTERSECTION(struct_shared, struct_type, kWasmBottom);
    INTERSECTION(struct_shared, function_shared, kWasmBottom);
    INTERSECTION(struct_shared.AsNullable(),
                 ValueType::RefNull(HeapType::kI31Shared),
                 ValueType::RefNull(HeapType::kNoneShared));
    INTERSECTION(struct_shared, ValueType::Ref(HeapType::kAnyShared),
                 struct_shared);
    INTERSECTION(struct_shared.AsNullable(),
                 ValueType::RefNull(HeapType::kNoneShared),
                 ValueType::RefNull(HeapType::kNoneShared));
    INTERSECTION(struct_shared, ValueType::Ref(HeapType::kAny), kWasmBottom);
    UNION(function_shared, ValueType::Ref(HeapType::kFuncShared),
          ValueType::Ref(HeapType::kFuncShared));
    UNION(function_shared, ValueType::Ref(HeapType::kFunc), kWasmTop);
    UNION(function_shared, ValueType::Ref(HeapType::kEqShared), kWasmTop);
    UNION(function_shared, ValueType::Ref(HeapType::kNoFuncShared),
          function_shared);
    UNION(function_shared, ValueType::Ref(HeapType::kNoExternShared), kWasmTop);
    INTERSECTION(function_shared, ValueType::Ref(HeapType::kFuncShared),
                 function_shared);
    INTERSECTION(function_shared, ValueType::Ref(HeapType::kFunc), kWasmBottom);
    INTERSECTION(function_shared, ValueType::Ref(HeapType::kEqShared),
                 kWasmBottom);
    INTERSECTION(function_shared.AsNullable(),
                 ValueType::RefNull(HeapType::kNoFuncShared),
                 ValueType::RefNull(HeapType::kNoFuncShared));
    INTERSECTION(function_shared, ValueType::Ref(HeapType::kNoExternShared),
                 kWasmBottom);
  }

  // Generic test covering all kinds of always applicable rules (like
  // commutativity).
  const WasmModule* module = module2;
  std::vector<ValueType> test_types;
  test_types.reserve(arraysize(numeric_types) + arraysize(ref_types));
  test_types.insert(test_types.end(), std::begin(numeric_types),
                    std::end(numeric_types));
  test_types.insert(test_types.end(), std::begin(ref_types),
                    std::end(ref_types));
  test_types.push_back(kWasmBottom);
  test_types.push_back(kWasmTop);
  for (const ValueType type_a : test_types) {
    SCOPED_TRACE("a = " + type_a.name());
    TypeInModule a(type_a, module1);
    // Neutral elements: kWasmTop wrt. intersection, kWasmBottom wrt. union.
    INTERSECTION(type_a, kWasmTop, type_a);
    UNION(type_a, kWasmBottom, type_a);
    // Absorbing element: kWasmTop wrt. union, kWasmBottom wrt. intersection.
    UNION(type_a, kWasmTop, kWasmTop);
    INTERSECTION(type_a, kWasmBottom, kWasmBottom);

    UNION(type_a, type_a, type_a);         // idempotency
    INTERSECTION(type_a, type_a, type_a);  // idempotency

    for (const ValueType type_b : test_types) {
      SCOPED_TRACE("b = " + type_b.name());
      TypeInModule b(type_b, module2);

      // There may not be any "cycles" in the type hierarchy.
      if (IsSubtypeOf(a.type, b.type, module1) && a.type != b.type) {
        EXPECT_FALSE(IsSubtypeOf(b.type, a.type, module1));
      }

      // The union of two types is always a super type of both types.
      TypeInModule union_ab = Union(a, b);
      EXPECT_TRUE(IsSubtypeOf(a.type, union_ab.type, module1));
      EXPECT_TRUE(IsSubtypeOf(b.type, union_ab.type, module1));

      // Test commutativity.
      EXPECT_EQ(Union(a, b).type, Union(b, a).type);
      EXPECT_EQ(Intersection(a, b).type, Intersection(b, a).type);

      // If the union of a and b is b, then a is a subtype of b, so the
      // intersection has to be a.
      EXPECT_EQ(Union(a, b).type == b.type, Intersection(a, b).type == a.type);

      for (const ValueType type_c : test_types) {
        SCOPED_TRACE("c = " + type_c.name());
        TypeInModule c(type_c, module1);
        // Test associativity.
        EXPECT_EQ(Union(a, Union(b, c)).type, Union(Union(a, b), c).type);
        EXPECT_EQ(Intersection(a, Intersection(b, c)).type,
                  Intersection(Intersection(a, b), c).type);

        // Test transitivity.
        if (IsSubtypeOf(a.type, b.type, module1) &&
            IsSubtypeOf(b.type, c.type, module1)) {
          EXPECT_TRUE(IsSubtypeOf(a.type, c.type, module1));
        }

        // The Union(a, b) is the most specific supertype of a and b.
        // Therefore there may not be any type c that is a supertype of a and b
        // but not a supertype of c.
        if (IsSubtypeOf(a.type, c.type, module1) &&
            IsSubtypeOf(b.type, c.type, module1)) {
          EXPECT_TRUE(IsSubtypeOf(union_ab.type, c.type, module1));
        }
      }
    }
  }

#undef SUBTYPE
#undef NOT_SUBTYPE
#undef SUBTYPE_IFF
#undef VALID_SUBTYPE
#undef NOT_VALID_SUBTYPE
#undef IDENTICAL
#undef DISTINCT
#undef UNION
#undef UNION_M
#undef INTERSECTION
#undef INTERSECTION_M
}

}  // namespace v8::internal::wasm::subtyping_unittest

"""
```