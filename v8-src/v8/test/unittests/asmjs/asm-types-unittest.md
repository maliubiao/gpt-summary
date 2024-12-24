Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript/asm.js.

1. **Understand the Goal:** The request asks for the functionality of the C++ file and its relation to JavaScript/asm.js. This means identifying the core purpose of the code and then bridging that to the JavaScript world.

2. **Initial Skim for Keywords and Structure:** Quickly read through the code, looking for recognizable terms and overall organization.
    * Includes:  `asmjs`, `gtest`, `gmock`. This strongly suggests it's a unit test file related to asm.js.
    * Namespaces: `v8::internal::wasm::asmjs`. Confirms the connection to V8's asm.js implementation.
    * Classes: `AsmTypeTest`. Indicates a test suite for `AsmType`.
    * Macros: `FOR_EACH_ASM_VALUE_TYPE_LIST`. Suggests a repetitive structure likely defining different asm.js types.
    * `TEST_F`:  Confirms it's using Google Test for unit testing.

3. **Focus on the Core Class Under Test:** The central element seems to be `AsmType`. The tests are named related to its properties (e.g., `ValidateBits`, `SensibleParentsMap`, `Names`, `IsA`).

4. **Analyze `AsmTypeTest`:**  Examine the setup and helper functions within this class.
    * `parents_`: A map defining the inheritance relationships between different `AsmType` instances. This is crucial for understanding the type system.
    * `ParentsOf`: A helper to easily access the parents of a given type.
    * `FunctionTypeBuilder`, `Function`, `Overload`: These seem to be helpers for creating complex function types and overloaded functions within the test environment. This suggests that `AsmType` needs to represent function signatures.

5. **Deconstruct `FOR_EACH_ASM_VALUE_TYPE_LIST`:** This macro is key to understanding the defined asm.js types. Look for how it's used in the tests (e.g., `ValidateBits`, `SensibleParentsMap`, `Names`). The macro likely iterates over a predefined list of asm.js types, allowing for systematic testing of each. The arguments to the implied function within the macro (`CamelName`, `string_name`, `number`, `parent_types`) are important for understanding how each type is represented.

6. **Connect to asm.js Concepts:** Now, bring in knowledge of asm.js. What are the core features and types in asm.js?
    * Integer types (signed, unsigned, specific bit widths)
    * Floating-point types (single, double)
    * Typed arrays
    * Functions

7. **Map C++ Code to asm.js Concepts:**  Relate the C++ types and tests back to the asm.js concepts.
    * `Type::Int`, `Type::Double`, `Type::Float`: Clearly map to JavaScript's `int`, `double`, and `float` when used within asm.js.
    * `Type::Uint8Array`, `Type::Int32Array`, etc.: Directly correspond to JavaScript's Typed Arrays.
    * `Function(Type::Int)(Type::Double)`: Represents a function in asm.js that takes a `double` and returns an `int`.
    * The inheritance relationships defined in `parents_` reflect how types can be implicitly converted or used in asm.js (e.g., an `int` can often be used where a more general numeric type is expected).

8. **Formulate the Functionality Summary:** Based on the analysis, describe the main purpose of the file. Emphasize that it's a unit test for the `AsmType` class, focusing on validating its representation of asm.js types, their names, inheritance, and properties like size and load/store types.

9. **Create JavaScript Examples:**  Illustrate the connection to JavaScript/asm.js with concrete examples.
    * Show how the C++ `AsmType` instances correspond to syntax and behavior in asm.js.
    * Demonstrate the type conversions and relationships tested in the C++ code (e.g., how an integer can be used where a float is expected).
    *  Highlight the role of Typed Arrays in both C++ and JavaScript/asm.js.
    *  Show a simple asm.js function signature and relate it to the C++ `Function` type representation.

10. **Review and Refine:** Read through the summary and examples to ensure clarity, accuracy, and completeness. Are there any ambiguities?  Are the examples easy to understand?

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this just about validating the *existence* of types?  **Correction:** The inheritance tests and the `IsA` test show it's about more than just existence; it's about the *relationships* between types.
* **Struggling with the function type builders:**  Realize that these are utility classes to make the tests more readable and less verbose, not necessarily a core part of the `AsmType` functionality itself. Focus on *what* they represent (function signatures) rather than the specific implementation details.
* **JavaScript example too complex?** Simplify the JavaScript examples to focus on the direct correspondence with the C++ concepts being tested. Avoid unnecessary complexity in the JavaScript code.
* **Missing the "why":**  Initially focused on *what* the code does. Add the "why"—explain *why* this type system is important for asm.js (type checking, performance).

By following this structured approach, combining code analysis with domain knowledge (asm.js), and performing self-correction, we can arrive at a comprehensive and accurate explanation of the C++ file's functionality and its relation to JavaScript.这个C++源代码文件 `asm-types-unittest.cc` 的功能是 **为 V8 JavaScript 引擎中用于表示 asm.js 类型的 `AsmType` 类编写单元测试**。

更具体地说，它测试了 `AsmType` 类的以下方面：

1. **类型表示和唯一性:**  验证了 `AsmType` 可以正确地表示各种 asm.js 的值类型（如 `int`, `double`, `float`, 以及各种类型的 Typed Array）和函数类型。它还确保了每个类型实例的唯一性。
2. **类型名称:** 验证了每个 `AsmType` 实例都有一个正确的字符串名称，方便调试和理解。
3. **类型继承关系 (`IsA`):**  测试了类型之间的继承关系，例如 `Int32Array` 是 `Heap` 的一种，`Float` 是 `Floatish` 的一种。这对于类型检查和代码优化至关重要。
4. **类型比较 (`IsExactly`):** 测试了两个 `AsmType` 实例是否完全相同。
5. **函数类型:** 测试了如何创建和比较函数类型，包括参数类型和返回类型。还测试了重载函数类型的表示。
6. **调用兼容性 (`CanBeInvokedWith`):**  测试了一个函数类型是否可以用给定的参数类型和返回类型进行调用。这模拟了 asm.js 函数调用的类型检查。
7. **元素大小 (`ElementSizeInBytes`):**  对于 Typed Array 类型，测试了其元素的字节大小。
8. **加载和存储类型 (`LoadType`, `StoreType`):**  对于 Typed Array 类型，测试了从数组加载或存储值时对应的基本类型。例如，从 `Int32Array` 加载会得到 `Intish` 类型。
9. **内部位表示:**  通过 `ValidateBits` 测试，验证了 `AsmType` 内部使用位掩码来表示类型和继承关系的方式是否正确。

**与 JavaScript 的关系以及 JavaScript 示例:**

`AsmType` 类是 V8 引擎内部用于处理 asm.js 代码的关键组件。asm.js 是 JavaScript 的一个严格子集，旨在提供接近本地代码的性能。  这个单元测试确保了 V8 能够正确地理解和处理 asm.js 代码中的类型信息。

在 JavaScript 中，asm.js 的类型信息是通过特定的语法结构来声明的。`AsmType` 类在 V8 引擎编译和执行 asm.js 代码时，会将这些 JavaScript 类型信息转换为内部的 `AsmType` 对象，用于类型检查、优化和代码生成。

**JavaScript 示例:**

考虑以下简单的 asm.js 代码片段：

```javascript
function Module(stdlib, foreign, heap) {
  "use asm";
  var i = 0;
  var f = 0.0;
  var arr = new stdlib.Int32Array(heap);

  function add(x, y) {
    x = x | 0;  // x 是一个 signed int
    y = y | 0;  // y 是一个 signed int
    return (x + y) | 0;
  }

  function multiply(a, b) {
    a = +a; // a 是一个 double
    b = +b; // b 是一个 double
    return +(a * b);
  }

  function setArray(index, value) {
    index = index | 0;
    value = value | 0;
    arr[index] = value;
  }

  return { add: add, multiply: multiply, setArray: setArray };
}
```

在这个例子中：

* **`i = 0;`**:  在 asm.js 内部，`i` 的类型会被推断为类似 `Type::FixNum()` 或 `Type::Int()`。
* **`f = 0.0;`**:  `f` 的类型会被推断为类似 `Type::Double()`。
* **`var arr = new stdlib.Int32Array(heap);`**: `arr` 的类型对应于 `Type::Int32Array()`。
* **`function add(x, y)`**:  `add` 函数的类型在 V8 内部会表示为一个 `AsmType` 的函数类型，其参数类型为 `Type::Int()`，返回类型为 `Type::Int()`。
* **`function multiply(a, b)`**: `multiply` 函数的类型在 V8 内部会表示为一个 `AsmType` 的函数类型，其参数类型为 `Type::Double()`，返回类型为 `Type::Double()`。
* **`function setArray(index, value)`**:  `arr[index] = value;` 这行代码涉及到 `Type::Int32Array()` 的存储操作，V8 会使用 `Type::Intish()` 作为存储类型进行类型检查。

`asm-types-unittest.cc` 中的测试，例如 `TEST_F(AsmTypeTest, IsA)` 会验证 `Type::Int()` 是 `Type::Intish()` 的一种。`TEST_F(AsmTypeTest, ElementSizeInBytes)` 会验证 `Type::Int32Array()` 的元素大小是 4 字节。`TEST_F(AsmTypeTest, StoreType)` 会验证 `Type::Int32Array()` 的存储类型是 `Type::Intish()`。

总而言之，`asm-types-unittest.cc` 通过单元测试确保了 V8 引擎能够准确地表示和处理 asm.js 代码中的类型信息，这对于 asm.js 代码的正确编译和高性能执行至关重要。 它验证了 `AsmType` 类的各种功能，这些功能直接对应了 asm.js 中类型系统的概念和行为。

Prompt: 
```
这是目录为v8/test/unittests/asmjs/asm-types-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/asmjs/asm-types.h"

#include <unordered_map>
#include <unordered_set>

#include "src/base/macros.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace {

using ::testing::StrEq;

class AsmTypeTest : public TestWithZone {
 public:
  using Type = AsmType;

  AsmTypeTest()
      : parents_({
            {Type::Uint8Array(), {Type::Heap()}},
            {Type::Int8Array(), {Type::Heap()}},
            {Type::Uint16Array(), {Type::Heap()}},
            {Type::Int16Array(), {Type::Heap()}},
            {Type::Uint32Array(), {Type::Heap()}},
            {Type::Int32Array(), {Type::Heap()}},
            {Type::Float32Array(), {Type::Heap()}},
            {Type::Float64Array(), {Type::Heap()}},
            {Type::Float(),
             {Type::FloatishDoubleQ(), Type::FloatQDoubleQ(), Type::FloatQ(),
              Type::Floatish()}},
            {Type::Floatish(), {Type::FloatishDoubleQ()}},
            {Type::FloatQ(),
             {Type::FloatishDoubleQ(), Type::FloatQDoubleQ(),
              Type::Floatish()}},
            {Type::FixNum(),
             {Type::Signed(), Type::Extern(), Type::Unsigned(), Type::Int(),
              Type::Intish()}},
            {Type::Unsigned(), {Type::Int(), Type::Intish()}},
            {Type::Signed(), {Type::Extern(), Type::Int(), Type::Intish()}},
            {Type::Int(), {Type::Intish()}},
            {Type::DoubleQ(), {Type::FloatishDoubleQ(), Type::FloatQDoubleQ()}},
            {Type::Double(),
             {Type::FloatishDoubleQ(), Type::FloatQDoubleQ(), Type::DoubleQ(),
              Type::Extern()}},
        }) {}

 protected:
  std::unordered_set<Type*> ParentsOf(Type* derived) const {
    const auto parents_iter = parents_.find(derived);
    if (parents_iter == parents_.end()) {
      return std::unordered_set<Type*>();
    }
    return parents_iter->second;
  }

  class FunctionTypeBuilder {
   public:
    FunctionTypeBuilder(FunctionTypeBuilder&& b) V8_NOEXCEPT
        : function_type_(b.function_type_) {
      b.function_type_ = nullptr;
    }

    FunctionTypeBuilder& operator=(FunctionTypeBuilder&& b) V8_NOEXCEPT {
      if (this != &b) {
        function_type_ = b.function_type_;
        b.function_type_ = nullptr;
      }
      return *this;
    }

    FunctionTypeBuilder(Zone* zone, Type* return_type)
        : function_type_(Type::Function(zone, return_type)) {}

   private:
    static void AddAllArguments(AsmFunctionType*) {}

    template <typename Arg, typename... Others>
    static void AddAllArguments(AsmFunctionType* function_type, Arg* arg,
                                Others... others) {
      CHECK_NOT_NULL(function_type);
      function_type->AddArgument((*arg)());
      AddAllArguments(function_type, others...);
    }

   public:
    template <typename... Args>
    Type* operator()(Args... args) {
      Type* ret = function_type_;
      function_type_ = nullptr;
      AddAllArguments(ret->AsFunctionType(), args...);
      return ret;
    }

   private:
    Type* function_type_;
  };

  FunctionTypeBuilder Function(Type* (*return_type)()) {
    return FunctionTypeBuilder(zone(), (*return_type)());
  }

  template <typename... Overloads>
  Type* Overload(Overloads... overloads) {
    auto* ret = Type::OverloadedFunction(zone());
    AddAllOverloads(ret->AsOverloadedFunctionType(), overloads...);
    return ret;
  }

 private:
  static void AddAllOverloads(AsmOverloadedFunctionType*) {}

  template <typename Overload, typename... Others>
  static void AddAllOverloads(AsmOverloadedFunctionType* function,
                              Overload* overload, Others... others) {
    CHECK_NOT_NULL(function);
    function->AddOverload(overload);
    AddAllOverloads(function, others...);
  }

  const std::unordered_map<Type*, std::unordered_set<Type*>> parents_;
};

// AsmValueTypeParents expose the bitmasks for the parents for each value type
// in asm's type system. It inherits from AsmValueType so that the kAsm<Foo>
// members are available when expanding the FOR_EACH_ASM_VALUE_TYPE_LIST macro.
class AsmValueTypeParents : private AsmValueType {
 public:
  enum : uint32_t {
#define V(CamelName, string_name, number, parent_types) \
  CamelName = parent_types,
    FOR_EACH_ASM_VALUE_TYPE_LIST(V)
#undef V
  };

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(AsmValueTypeParents);
};

TEST_F(AsmTypeTest, ValidateBits) {
  // Generic validation tests for the bits in the type system's type
  // definitions.

  std::unordered_set<Type*> seen_types;
  std::unordered_set<uint32_t> seen_numbers;
  uint32_t total_types = 0;
#define V(CamelName, string_name, number, parent_types)                      \
  do {                                                                       \
    ++total_types;                                                           \
    if (AsmValueTypeParents::CamelName != 0) {                               \
      EXPECT_NE(0u, ParentsOf(AsmType::CamelName()).size()) << #CamelName;   \
    }                                                                        \
    seen_types.insert(Type::CamelName());                                    \
    seen_numbers.insert(number);                                             \
    /* Every ASM type must have a valid number. */                           \
    EXPECT_NE(0, number) << Type::CamelName()->Name();                       \
    /* Inheritance cycles - unlikely, but we're paranoid and check for it */ \
    /* anyways.*/                                                            \
    EXPECT_EQ(0u, (1 << (number)) & AsmValueTypeParents::CamelName);         \
  } while (0);
  FOR_EACH_ASM_VALUE_TYPE_LIST(V)
#undef V

  // At least one type was expanded.
  EXPECT_GT(total_types, 0u);

  // Each value type is unique.
  EXPECT_EQ(total_types, seen_types.size());

  // Each number is unique.
  EXPECT_EQ(total_types, seen_numbers.size());
}

TEST_F(AsmTypeTest, SensibleParentsMap) {
  // This test ensures our parents map contains all the parents types that are
  // specified in the types' declaration. It does not report bogus inheritance.

  // Handy-dandy lambda for counting bits. Code borrowed from stack overflow.
  auto NumberOfSetBits = [](uintptr_t parent_mask) -> uint32_t {
    uint32_t parent_mask32 = static_cast<uint32_t>(parent_mask);
    CHECK_EQ(parent_mask, parent_mask32);
    parent_mask32 = parent_mask32 - ((parent_mask32 >> 1) & 0x55555555);
    parent_mask32 =
        (parent_mask32 & 0x33333333) + ((parent_mask32 >> 2) & 0x33333333);
    return (((parent_mask32 + (parent_mask32 >> 4)) & 0x0F0F0F0F) *
            0x01010101) >>
           24;
  };

#define V(CamelName, string_name, number, parent_types)                    \
  do {                                                                     \
    const uintptr_t parents =                                              \
        reinterpret_cast<uintptr_t>(Type::CamelName()) & ~(1 << (number)); \
    EXPECT_EQ(NumberOfSetBits(parents),                                    \
              1 + ParentsOf(Type::CamelName()).size())                     \
        << Type::CamelName()->Name() << ", parents "                       \
        << reinterpret_cast<void*>(parents) << ", type "                   \
        << static_cast<void*>(Type::CamelName());                          \
  } while (false);
  FOR_EACH_ASM_VALUE_TYPE_LIST(V)
#undef V
}

TEST_F(AsmTypeTest, Names) {
#define V(CamelName, string_name, number, parent_types)         \
  do {                                                          \
    EXPECT_THAT(Type::CamelName()->Name(), StrEq(string_name)); \
  } while (false);
  FOR_EACH_ASM_VALUE_TYPE_LIST(V)
#undef V

  EXPECT_THAT(Function(Type::Int)(Type::Double, Type::Float)->Name(),
              StrEq("(double, float) -> int"));

  EXPECT_THAT(Overload(Function(Type::Int)(Type::Double, Type::Float),
                       Function(Type::Int)(Type::Int))
                  ->Name(),
              StrEq("(double, float) -> int /\\ (int) -> int"));

  EXPECT_THAT(Type::FroundType(zone())->Name(), StrEq("fround"));

  EXPECT_THAT(Type::MinMaxType(zone(), Type::Signed(), Type::Int())->Name(),
              StrEq("(int, int...) -> signed"));
  EXPECT_THAT(Type::MinMaxType(zone(), Type::Float(), Type::Floatish())->Name(),
              StrEq("(floatish, floatish...) -> float"));
  EXPECT_THAT(Type::MinMaxType(zone(), Type::Double(), Type::DoubleQ())->Name(),
              StrEq("(double?, double?...) -> double"));
}

TEST_F(AsmTypeTest, IsExactly) {
  Type* test_types[] = {
#define CREATE(CamelName, string_name, number, parent_types) Type::CamelName(),
      FOR_EACH_ASM_VALUE_TYPE_LIST(CREATE)
#undef CREATE
          Function(Type::Int)(Type::Double),
      Function(Type::Int)(Type::DoubleQ),
      Overload(Function(Type::Int)(Type::Double)),
      Function(Type::Int)(Type::Int, Type::Int),
      Type::MinMaxType(zone(), Type::Signed(), Type::Int()),
      Function(Type::Int)(Type::Float),
      Type::FroundType(zone()),
  };

  for (size_t ii = 0; ii < arraysize(test_types); ++ii) {
    for (size_t jj = 0; jj < arraysize(test_types); ++jj) {
      EXPECT_EQ(ii == jj, AsmType::IsExactly(test_types[ii], test_types[jj]))
          << test_types[ii]->Name()
          << ((ii == jj) ? " is not exactly " : " is exactly ")
          << test_types[jj]->Name();
    }
  }
}

bool FunctionsWithSameSignature(AsmType* a, AsmType* b) {
  if (a->AsFunctionType()) {
    if (b->AsFunctionType()) {
      return a->IsA(b);
    }
  }
  return false;
}

TEST_F(AsmTypeTest, IsA) {
  Type* test_types[] = {
#define CREATE(CamelName, string_name, number, parent_types) Type::CamelName(),
      FOR_EACH_ASM_VALUE_TYPE_LIST(CREATE)
#undef CREATE
          Function(Type::Int)(Type::Double),
      Function(Type::Int)(Type::Int, Type::Int),
      Function(Type::Int)(Type::DoubleQ),
      Overload(Function(Type::Int)(Type::Double)),
      Function(Type::Int)(Type::Int, Type::Int),
      Type::MinMaxType(zone(), Type::Signed(), Type::Int()),
      Function(Type::Int)(Type::Float),
      Type::FroundType(zone()),
  };

  for (size_t ii = 0; ii < arraysize(test_types); ++ii) {
    for (size_t jj = 0; jj < arraysize(test_types); ++jj) {
      const bool Expected =
          (ii == jj) || ParentsOf(test_types[ii]).count(test_types[jj]) != 0 ||
          FunctionsWithSameSignature(test_types[ii], test_types[jj]);
      EXPECT_EQ(Expected, test_types[ii]->IsA(test_types[jj]))
          << test_types[ii]->Name() << (Expected ? " is not a " : " is a ")
          << test_types[jj]->Name();
    }
  }

  EXPECT_TRUE(Function(Type::Int)(Type::Int, Type::Int)
                  ->IsA(Function(Type::Int)(Type::Int, Type::Int)));

  EXPECT_FALSE(Function(Type::Int)(Type::Int, Type::Int)
                   ->IsA(Function(Type::Double)(Type::Int, Type::Int)));
  EXPECT_FALSE(Function(Type::Int)(Type::Int, Type::Int)
                   ->IsA(Function(Type::Int)(Type::Double, Type::Int)));
}

TEST_F(AsmTypeTest, CanBeInvokedWith) {
  auto* min_max_int = Type::MinMaxType(zone(), Type::Signed(), Type::Int());
  auto* i2s = Function(Type::Signed)(Type::Int);
  auto* ii2s = Function(Type::Signed)(Type::Int, Type::Int);
  auto* iii2s = Function(Type::Signed)(Type::Int, Type::Int, Type::Int);
  auto* iiii2s =
      Function(Type::Signed)(Type::Int, Type::Int, Type::Int, Type::Int);

  EXPECT_TRUE(min_max_int->AsCallableType()->CanBeInvokedWith(
      ii2s->AsFunctionType()->ReturnType(),
      ii2s->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max_int->AsCallableType()->CanBeInvokedWith(
      iii2s->AsFunctionType()->ReturnType(),
      iii2s->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max_int->AsCallableType()->CanBeInvokedWith(
      iiii2s->AsFunctionType()->ReturnType(),
      iiii2s->AsFunctionType()->Arguments()));
  EXPECT_FALSE(min_max_int->AsCallableType()->CanBeInvokedWith(
      i2s->AsFunctionType()->ReturnType(), i2s->AsFunctionType()->Arguments()));

  auto* min_max_double =
      Type::MinMaxType(zone(), Type::Double(), Type::Double());
  auto* d2d = Function(Type::Double)(Type::Double);
  auto* dd2d = Function(Type::Double)(Type::Double, Type::Double);
  auto* ddd2d =
      Function(Type::Double)(Type::Double, Type::Double, Type::Double);
  auto* dddd2d = Function(Type::Double)(Type::Double, Type::Double,
                                        Type::Double, Type::Double);
  EXPECT_TRUE(min_max_double->AsCallableType()->CanBeInvokedWith(
      dd2d->AsFunctionType()->ReturnType(),
      dd2d->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max_double->AsCallableType()->CanBeInvokedWith(
      ddd2d->AsFunctionType()->ReturnType(),
      ddd2d->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max_double->AsCallableType()->CanBeInvokedWith(
      dddd2d->AsFunctionType()->ReturnType(),
      dddd2d->AsFunctionType()->Arguments()));
  EXPECT_FALSE(min_max_double->AsCallableType()->CanBeInvokedWith(
      d2d->AsFunctionType()->ReturnType(), d2d->AsFunctionType()->Arguments()));

  auto* min_max = Overload(min_max_int, min_max_double);
  EXPECT_FALSE(min_max->AsCallableType()->CanBeInvokedWith(
      i2s->AsFunctionType()->ReturnType(), i2s->AsFunctionType()->Arguments()));
  EXPECT_FALSE(min_max->AsCallableType()->CanBeInvokedWith(
      d2d->AsFunctionType()->ReturnType(), d2d->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max->AsCallableType()->CanBeInvokedWith(
      ii2s->AsFunctionType()->ReturnType(),
      ii2s->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max->AsCallableType()->CanBeInvokedWith(
      iii2s->AsFunctionType()->ReturnType(),
      iii2s->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max->AsCallableType()->CanBeInvokedWith(
      iiii2s->AsFunctionType()->ReturnType(),
      iiii2s->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max->AsCallableType()->CanBeInvokedWith(
      dd2d->AsFunctionType()->ReturnType(),
      dd2d->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max->AsCallableType()->CanBeInvokedWith(
      ddd2d->AsFunctionType()->ReturnType(),
      ddd2d->AsFunctionType()->Arguments()));
  EXPECT_TRUE(min_max->AsCallableType()->CanBeInvokedWith(
      dddd2d->AsFunctionType()->ReturnType(),
      dddd2d->AsFunctionType()->Arguments()));

  auto* fround = Type::FroundType(zone());

  ZoneVector<AsmType*> arg(zone());
  arg.push_back(Type::Floatish());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::FloatQ());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::Float());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::DoubleQ());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::Double());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::Signed());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::Unsigned());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));
  arg.clear();
  arg.push_back(Type::FixNum());
  EXPECT_TRUE(fround->AsCallableType()->CanBeInvokedWith(Type::Float(), arg));

  auto* idf2v = Function(Type::Void)(Type::Int, Type::Double, Type::Float);
  auto* i2d = Function(Type::Double)(Type::Int);
  auto* i2f = Function(Type::Float)(Type::Int);
  auto* fi2d = Function(Type::Double)(Type::Float, Type::Int);
  auto* idif2i =
      Function(Type::Int)(Type::Int, Type::Double, Type::Int, Type::Float);
  auto* overload = Overload(idf2v, i2f, /*i2d missing, */ fi2d, idif2i);
  EXPECT_TRUE(overload->AsCallableType()->CanBeInvokedWith(
      idf2v->AsFunctionType()->ReturnType(),
      idf2v->AsFunctionType()->Arguments()));
  EXPECT_TRUE(overload->AsCallableType()->CanBeInvokedWith(
      i2f->AsFunctionType()->ReturnType(), i2f->AsFunctionType()->Arguments()));
  EXPECT_TRUE(overload->AsCallableType()->CanBeInvokedWith(
      fi2d->AsFunctionType()->ReturnType(),
      fi2d->AsFunctionType()->Arguments()));
  EXPECT_TRUE(overload->AsCallableType()->CanBeInvokedWith(
      idif2i->AsFunctionType()->ReturnType(),
      idif2i->AsFunctionType()->Arguments()));
  EXPECT_FALSE(overload->AsCallableType()->CanBeInvokedWith(
      i2d->AsFunctionType()->ReturnType(), i2d->AsFunctionType()->Arguments()));
  EXPECT_FALSE(i2f->AsCallableType()->CanBeInvokedWith(
      i2d->AsFunctionType()->ReturnType(), i2d->AsFunctionType()->Arguments()));
}

TEST_F(AsmTypeTest, ElementSizeInBytes) {
  Type* test_types[] = {
#define CREATE(CamelName, string_name, number, parent_types) Type::CamelName(),
      FOR_EACH_ASM_VALUE_TYPE_LIST(CREATE)
#undef CREATE
          Function(Type::Int)(Type::Double),
      Function(Type::Int)(Type::DoubleQ),
      Overload(Function(Type::Int)(Type::Double)),
      Function(Type::Int)(Type::Int, Type::Int),
      Type::MinMaxType(zone(), Type::Signed(), Type::Int()),
      Function(Type::Int)(Type::Float),
      Type::FroundType(zone()),
  };

  auto ElementSizeInBytesForType = [](Type* type) -> int32_t {
    if (type == Type::Int8Array() || type == Type::Uint8Array()) {
      return 1;
    }
    if (type == Type::Int16Array() || type == Type::Uint16Array()) {
      return 2;
    }
    if (type == Type::Int32Array() || type == Type::Uint32Array() ||
        type == Type::Float32Array()) {
      return 4;
    }
    if (type == Type::Float64Array()) {
      return 8;
    }
    return -1;
  };

  for (size_t ii = 0; ii < arraysize(test_types); ++ii) {
    EXPECT_EQ(ElementSizeInBytesForType(test_types[ii]),
              test_types[ii]->ElementSizeInBytes());
  }
}

TEST_F(AsmTypeTest, LoadType) {
  Type* test_types[] = {
#define CREATE(CamelName, string_name, number, parent_types) Type::CamelName(),
      FOR_EACH_ASM_VALUE_TYPE_LIST(CREATE)
#undef CREATE
          Function(Type::Int)(Type::Double),
      Function(Type::Int)(Type::DoubleQ),
      Overload(Function(Type::Int)(Type::Double)),
      Function(Type::Int)(Type::Int, Type::Int),
      Type::MinMaxType(zone(), Type::Signed(), Type::Int()),
      Function(Type::Int)(Type::Float),
      Type::FroundType(zone()),
  };

  auto LoadTypeForType = [](Type* type) -> Type* {
    if (type == Type::Int8Array() || type == Type::Uint8Array() ||
        type == Type::Int16Array() || type == Type::Uint16Array() ||
        type == Type::Int32Array() || type == Type::Uint32Array()) {
      return Type::Intish();
    }

    if (type == Type::Float32Array()) {
      return Type::FloatQ();
    }

    if (type == Type::Float64Array()) {
      return Type::DoubleQ();
    }

    return Type::None();
  };

  for (size_t ii = 0; ii < arraysize(test_types); ++ii) {
    EXPECT_EQ(LoadTypeForType(test_types[ii]), test_types[ii]->LoadType());
  }
}

TEST_F(AsmTypeTest, StoreType) {
  Type* test_types[] = {
#define CREATE(CamelName, string_name, number, parent_types) Type::CamelName(),
      FOR_EACH_ASM_VALUE_TYPE_LIST(CREATE)
#undef CREATE
          Function(Type::Int)(Type::Double),
      Function(Type::Int)(Type::DoubleQ),
      Overload(Function(Type::Int)(Type::Double)),
      Function(Type::Int)(Type::Int, Type::Int),
      Type::MinMaxType(zone(), Type::Signed(), Type::Int()),
      Function(Type::Int)(Type::Float),
      Type::FroundType(zone()),
  };

  auto StoreTypeForType = [](Type* type) -> Type* {
    if (type == Type::Int8Array() || type == Type::Uint8Array() ||
        type == Type::Int16Array() || type == Type::Uint16Array() ||
        type == Type::Int32Array() || type == Type::Uint32Array()) {
      return Type::Intish();
    }

    if (type == Type::Float32Array()) {
      return Type::FloatishDoubleQ();
    }

    if (type == Type::Float64Array()) {
      return Type::FloatQDoubleQ();
    }

    return Type::None();
  };

  for (size_t ii = 0; ii < arraysize(test_types); ++ii) {
    EXPECT_EQ(StoreTypeForType(test_types[ii]), test_types[ii]->StoreType())
        << test_types[ii]->Name();
  }
}

}  // namespace
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```