Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Request:**

The core request is to analyze a C++ source file (`subtyping-unittest.cc`) within the V8 project, specifically focusing on its functionality related to WebAssembly (Wasm) subtyping. The request also includes specific instructions about handling `.tq` files (Torque), JavaScript relevance, code logic inference, common programming errors, and a summary of the functionality.

**2. Initial Code Scan and Key Observations:**

My first step is to quickly scan the code to identify the major components and keywords. I immediately notice:

* **`// Copyright 2020 the V8 project authors...`**: This confirms it's V8 code.
* **`#include ...`**:  These include statements point to core Wasm and testing infrastructure within V8. Specifically, `#include "src/wasm/canonical-types.h"` and `#include "src/wasm/wasm-subtyping.h"` are strong indicators of the file's purpose. `test/common/...` headers suggest this is a unit test.
* **`namespace v8::internal::wasm::subtyping_unittest { ... }`**:  This clearly defines the scope and purpose of the code.
* **`class WasmSubtypingTest : public TestWithPlatform {};`**: This confirms it's a unit test class.
* **Helper Functions (`DefineStruct`, `DefineArray`, `DefineSignature`):** These functions are clearly for setting up test scenarios by defining Wasm module types (structs, arrays, and function signatures). The parameters like `supertype`, `is_final`, and `is_shared` suggest these are related to Wasm's type system features.
* **`TEST_F(WasmSubtypingTest, Subtyping) { ... }`**: This is the main test function.
* **`WasmModule module1_;`, `WasmModule module2_;`**: Two separate Wasm modules are being created, which suggests testing subtyping across module boundaries.
* **Looping and Defining Types:** The code then proceeds to define a series of structs, arrays, and signatures within both `module1` and `module2`. The comments like `/* 0 */`, `/* 1 */`, etc., are crucial for tracking the indices of these defined types. The recursive definitions hint at testing recursive type relationships.
* **`constexpr ValueType numeric_types[] = { ... };` and `constexpr ValueType ref_types[] = { ... };`**: These arrays define the different types that will be used for testing subtyping.
* **Macros (`SUBTYPE`, `SUBTYPE_IFF`, `NOT_SUBTYPE`, `VALID_SUBTYPE`, etc.):** These macros are used to simplify the assertion logic within the tests, making the tests more readable and concise. They clearly relate to checking subtyping relationships, type validity, and type equivalence.
* **Nested Loops and Assertions:** The core of the test involves nested loops iterating through the defined types and using the macros to assert various subtyping relationships.
* **Union and Intersection:** The code includes tests for the `Union` and `Intersection` operations on Wasm types.

**3. Answering Specific Parts of the Request:**

Now, I can address each point of the request systematically:

* **Functionality:** Based on the identified components, the main functionality is clearly **testing the correctness of Wasm subtyping rules**. It checks if one Wasm type is a subtype of another, including handling complex scenarios like recursive types, final types, shared types, and abstract types. It also tests the `Union` and `Intersection` operations on Wasm types.

* **`.tq` Files:** The request specifically asks about `.tq` files. I can confirm that the given file ends with `.cc`, so it's a **C++ file, not a Torque file**.

* **JavaScript Relevance:**  Wasm and JavaScript are tightly integrated in V8. While this specific C++ file doesn't directly *execute* JavaScript, it's testing the underlying logic that governs how Wasm types interact. I can provide a JavaScript example to illustrate the *concept* of subtyping, even if the direct implementation is in C++. This would involve showing how a more specific object can be used where a more general object is expected.

* **Code Logic Inference (Hypothetical Input/Output):**  I need to pick a specific test case within the `TEST_F` function and reason about the expected outcome. For example, the `VALID_SUBTYPE(ref(0), refNull(0))` test asserts that a non-nullable reference to struct type 0 is a subtype of a nullable reference to the same struct type.

* **Common Programming Errors:** I need to think about how developers might misuse or misunderstand subtyping concepts, even in a Wasm context. An example would be trying to treat a supertype as its subtype without proper casting or checking, leading to potential runtime errors.

* **Summary of Functionality (Part 1):**  I need to synthesize the above observations into a concise summary focusing on the core purpose of the code.

**4. Structuring the Output:**

Finally, I organize the information in a clear and structured manner, following the order of the request. I use headings and bullet points to enhance readability. I ensure to clearly distinguish between direct observations from the code and inferences or explanations.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretation:** I might initially focus too much on the individual type definitions. However, I realize that the *testing* aspect (the `TEST_F` function and the macros) is the core functionality to highlight.
* **Overly Technical Jargon:** I need to balance technical accuracy with clarity. While terms like "contravariance" are relevant, I should briefly explain them or provide context.
* **JavaScript Example Clarity:** The JavaScript example needs to be simple and clearly illustrate the subtyping *concept* without getting bogged down in Wasm-specific details.

By following this systematic approach, I can effectively analyze the given C++ code and provide a comprehensive and accurate response to the user's request.
好的，这是对提供的V8源代码文件 `v8/test/unittests/wasm/subtyping-unittest.cc` 的功能进行分析：

**文件功能归纳 (第 1 部分):**

`v8/test/unittests/wasm/subtyping-unittest.cc` 是一个 **V8 的 C++ 单元测试文件**，专门用于测试 **WebAssembly (Wasm) 的类型子类型 (Subtyping) 关系** 的实现是否正确。

**具体功能点：**

1. **定义和注册 Wasm 类型：**
   - 使用辅助函数 (`DefineStruct`, `DefineArray`, `DefineSignature`) 在测试中动态创建和定义 Wasm 的结构体 (struct)、数组 (array) 和函数签名 (signature) 类型。
   - 可以设置类型的属性，如父类型 (`supertype`)、是否为 final (`is_final`)、是否为共享类型 (`is_shared`)，以及是否在单例递归组中 (`in_singleton_rec_group`)。
   - 这些函数会将创建的类型添加到 `WasmModule` 对象中。

2. **测试类型子类型关系：**
   - 使用 `TEST_F` 宏定义了一个名为 `Subtyping` 的测试用例。
   - 在测试用例中创建了两个 `WasmModule` 对象 (`module1` 和 `module2`)，用于进行跨模块的类型关系测试。
   - 定义了各种 Wasm 的基础类型（数值类型 `numeric_types` 和引用类型 `ref_types`）。
   - 使用一系列宏 (`SUBTYPE`, `SUBTYPE_IFF`, `NOT_SUBTYPE`, `VALID_SUBTYPE`, `NOT_VALID_SUBTYPE`, `IDENTICAL`, `DISTINCT`, `UNION`, `INTERSECTION`) 来断言不同类型之间的子类型关系是否符合预期。

3. **测试各种子类型场景：**
   - **基本类型：** 测试数值类型之间以及数值类型和引用类型之间的子类型关系（通常数值类型之间只有相等才是子类型，数值类型和引用类型之间没有子类型关系）。
   - **引用类型：** 详细测试各种 Wasm 引用类型（如 `funcref`, `eqref`, `structref`, `arrayref`, `anyref`, `externref` 等）之间的子类型关系，包括可空与不可空引用。
   - **结构体和数组：** 测试结构体之间的前缀子类型、字段可变性对子类型的影响，以及数组元素类型对子类型的影响。
   - **递归类型：** 测试包含递归定义的结构体和数组之间的子类型关系。
   - **函数签名：** 测试函数签名的子类型关系，包括参数的逆变和返回值的协变。
   - **规范化 (Canonicalization)：** 测试类型规范化逻辑，确保相同的递归类型组被认为是相同的。
   - **Final 类型：** 测试 final 类型不能作为其他类型的父类型。
   - **Shared 类型：** 测试共享类型之间的子类型关系，以及共享类型和非共享类型之间的关系。
   - **抽象类型：** 测试 Wasm 的抽象引用类型（如 `eqref`, `anyref`, `func`, `extern` 的共享与非共享版本）之间的子类型关系。
   - **联合 (Union) 和交集 (Intersection) 类型：** 测试 `Union` 和 `Intersection` 操作在不同 Wasm 类型上的结果。

**如果 `v8/test/unittests/wasm/subtyping-unittest.cc` 以 `.tq` 结尾：**

如果该文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 自定义的类型化的中间语言，用于编写 V8 的内置函数和运行时代码。在这种情况下，该文件可能包含使用 Torque 语法实现的 Wasm 子类型检查逻辑或相关操作。

**与 JavaScript 的功能关系：**

虽然这个 C++ 文件是测试 Wasm 子类型功能的，但它直接影响了 JavaScript 中使用 Wasm 的行为。在 JavaScript 中加载和使用 Wasm 模块时，V8 引擎会进行类型检查，确保传递给 Wasm 函数的参数和从 Wasm 函数返回的值类型正确。Wasm 的子类型系统允许更灵活的类型匹配。

**JavaScript 示例：**

假设在 Wasm 模块中定义了两个结构体类型 `A` 和 `B`，其中 `B` 是 `A` 的子类型（例如，`B` 继承自 `A` 或拥有 `A` 的所有字段）：

```javascript
// 假设已经加载了一个 Wasm 模块 instance
const wasmInstance = ...;

// 假设 Wasm 模块导出了一个接受类型 A 的参数的函数 foo
const wasmFoo = wasmInstance.exports.foo;

// 在 JavaScript 中创建一个可以被视为类型 B 的对象 (或者从 Wasm 中获取)
const objectB = ...; // 假设这个对象符合 Wasm 模块中类型 B 的定义

// 因为 B 是 A 的子类型，所以可以将 objectB 传递给期望类型 A 的 wasmFoo 函数
wasmFoo(objectB);

// 如果 Wasm 模块导出了一个返回类型 B 的函数 bar
const wasmBar = wasmInstance.exports.bar;
const resultB = wasmBar();

// 在 JavaScript 中，可以将 resultB 赋值给期望类型 A 的变量 (如果需要)
const variableA = resultB;
```

在这个例子中，Wasm 的子类型规则允许我们将类型 `B` 的对象传递给期望类型 `A` 的 Wasm 函数，并且可以将返回类型 `B` 的值赋值给 JavaScript 中期望类型 `A` 的变量。这正是 `subtyping-unittest.cc` 中测试的核心概念。

**代码逻辑推理 (假设输入与输出):**

假设有以下测试用例：

```c++
SUBTYPE(ref(1), ref(0));
```

**假设输入：**

- `ref(1)` 代表模块中索引为 1 的结构体类型的不可空引用。
- `ref(0)` 代表模块中索引为 0 的结构体类型的不可空引用。
- 根据之前的 `DefineStruct` 调用，结构体 1 是结构体 0 的子类型（`Idx{0}` 作为父类型传入）。

**预期输出：**

- `EXPECT_TRUE` 将会执行，因为根据定义，结构体 1 是结构体 0 的子类型，所以 `IsSubtypeOf(ref(1), ref(0), module1, module)` 应该返回 `true`。

**用户常见的编程错误：**

1. **将父类型误认为子类型：** 用户可能会错误地认为父类型可以安全地用在期望子类型的地方，这在静态类型语言中会导致类型错误。

   ```javascript
   // 假设 wasmFooExpectedB 期望类型 B
   // const wasmFooExpectedB = wasmInstance.exports.fooExpectedB;

   // const objectA = ...; // 假设 objectA 符合类型 A 的定义

   // 错误！不能将父类型 A 的对象直接传递给期望子类型 B 的函数
   // wasmFooExpectedB(objectA); // 这可能会导致运行时错误或类型检查失败
   ```

2. **忽略可空性：** 用户可能会忘记处理 Wasm 引用类型的可空性，将不可空引用赋值给可空引用是安全的，反之则可能不安全。

   ```javascript
   // 假设 wasmBarReturnsNullableA 返回类型 A? (可空的 A)
   // const wasmBarReturnsNullableA = wasmInstance.exports.barReturnsNullableA;
   // const nullableA = wasmBarReturnsNullableA();

   // 错误！如果 nullableA 实际上是 null，则访问其属性会出错
   // nullableA.someProperty;

   // 正确的做法是先检查是否为 null
   // if (nullableA !== null) {
   //   nullableA.someProperty;
   // }
   ```

**总结：**

`v8/test/unittests/wasm/subtyping-unittest.cc` 的主要功能是 **全面测试 V8 中 WebAssembly 类型子类型关系的实现**，确保其逻辑正确性，这对于保证 JavaScript 与 WebAssembly 的互操作性和 Wasm 代码的类型安全至关重要。 它通过定义各种类型和断言它们之间的子类型关系来实现这一目标。

Prompt: 
```
这是目录为v8/test/unittests/wasm/subtyping-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/subtyping-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
               
"""


```