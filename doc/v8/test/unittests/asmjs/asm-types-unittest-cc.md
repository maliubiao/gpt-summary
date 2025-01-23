Response:
The user wants to understand the functionality of the C++ code `v8/test/unittests/asmjs/asm-types-unittest.cc`. I need to analyze the code and explain its purpose, especially in the context of asm.js types within the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file name `asm-types-unittest.cc` strongly suggests that this code contains unit tests for the `AsmType` class and related functionalities. Unit tests verify the behavior of specific code units in isolation.

2. **Examine Includes:** The included headers provide clues about the functionality being tested:
    * `"src/asmjs/asm-types.h"`: This is the primary header defining the `AsmType` class itself. The tests will likely validate the properties and methods of this class.
    * `<unordered_map>`, `<unordered_set>`: These indicate that the tests might involve working with collections of `AsmType` objects.
    * `"src/base/macros.h"`: This is a V8 internal header, likely used for common macros like `DISALLOW_IMPLICIT_CONSTRUCTORS`.
    * `"test/unittests/test-utils.h"`: This suggests the use of V8's testing framework.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: These are the Google Mock and Google Test frameworks, confirming that these are indeed unit tests.

3. **Analyze the `AsmTypeTest` Class:** This class inherits from `TestWithZone`, indicating that the tests will manage memory within a specific V8 zone. Key observations:
    * **`using Type = AsmType;`**:  A type alias for convenience.
    * **`parents_`:** This `unordered_map` seems to define the inheritance relationships between different `AsmType` instances. The keys are derived types, and the values are sets of their parent types. This structure is crucial for understanding the type hierarchy.
    * **`ParentsOf` method:**  A helper function to retrieve the parent types of a given `AsmType`.
    * **`FunctionTypeBuilder`:** This nested class is a builder pattern for creating `AsmType` objects representing function signatures. It handles adding argument types to the function type.
    * **`Function` method:** A helper function to create a `FunctionTypeBuilder`.
    * **`Overload` method:**  A helper function to create an `AsmType` representing an overloaded function (multiple function signatures with the same name).
    * **`AddAllOverloads`:** A private helper for the `Overload` method.

4. **Examine the Tests:** The `TEST_F` macros define individual test cases within the `AsmTypeTest` fixture. Each test focuses on a specific aspect of `AsmType` functionality:
    * **`ValidateBits`:** Checks the internal bit representation of `AsmType` values, ensuring uniqueness and detecting potential inheritance cycles.
    * **`SensibleParentsMap`:** Verifies that the `parents_` map accurately reflects the parent-child relationships defined in the type system.
    * **`Names`:** Checks that the `Name()` method of `AsmType` returns the correct string representation for different types and function signatures.
    * **`IsExactly`:** Tests the `IsExactly()` method, which determines if two `AsmType` objects represent the exact same type.
    * **`IsA`:** Tests the `IsA()` method, which determines if one `AsmType` is a subtype of another (inheritance).
    * **`CanBeInvokedWith`:** Tests if a callable type (function or overloaded function) can be invoked with a given return type and argument types.
    * **`ElementSizeInBytes`:** Tests the `ElementSizeInBytes()` method, which returns the size of the underlying element for typed array types.
    * **`LoadType`:** Tests the `LoadType()` method, which returns the type of value loaded from a given memory type.
    * **`StoreType`:** Tests the `StoreType()` method, which returns the type of value stored into a given memory type.

5. **Connect to JavaScript and asm.js:** Recognize that asm.js is a strict subset of JavaScript that allows for ahead-of-time optimization. The `AsmType` class represents the types used within asm.js modules (e.g., `int`, `double`, typed arrays). The tests are verifying the correctness of V8's internal representation and manipulation of these types.

6. **Address Specific Questions:**  Now, address the user's specific requests:
    * **Functionality:** Summarize the purpose of each test case.
    * **`.tq` extension:** Explain that `.tq` indicates Torque code, which is a different V8-specific language for defining built-in functions. This file is `.cc`, so it's C++.
    * **Relationship to JavaScript:** Explain how `AsmType` relates to JavaScript, particularly within the context of asm.js. Provide JavaScript examples demonstrating the asm.js type system (even though this C++ code doesn't *directly* execute JavaScript).
    * **Code Logic/Input/Output:**  For tests with clear logical checks (like `IsA`), provide hypothetical scenarios and the expected outcomes.
    * **Common Programming Errors:**  Relate the tested functionalities to common errors developers might encounter when working with asm.js or similar typed systems in JavaScript (e.g., type mismatches, incorrect function signatures).

By following these steps, a comprehensive explanation of the C++ code can be generated, addressing all aspects of the user's request.
`v8/test/unittests/asmjs/asm-types-unittest.cc` 是 V8 引擎中用于测试 asm.js 类型系统的单元测试文件。它的主要功能是验证 `src/asmjs/asm-types.h` 中定义的 `AsmType` 类的各种属性和方法是否按预期工作。

以下是该文件的具体功能列表：

1. **定义和测试 asm.js 类型之间的继承关系:**  代码中定义了一个 `parents_` 的 `std::unordered_map`，用于显式地声明不同 asm.js 类型之间的父子关系。例如，`Type::Uint8Array()` 继承自 `Type::Heap()`。测试用例会验证这些继承关系是否正确。

2. **验证类型位表示的正确性:**  `ValidateBits` 测试用例检查每个 asm.js 类型的内部位表示（由 `number` 宏定义）是否唯一且有效。它还会检查是否存在循环继承。

3. **验证 `parents_` 映射的完整性:** `SensibleParentsMap` 测试用例确保 `parents_` 映射包含了所有在类型声明中指定的父类型。

4. **测试类型名称的正确性:** `Names` 测试用例验证 `AsmType` 的 `Name()` 方法是否返回预期的字符串表示，包括基本类型、函数类型和重载函数类型。

5. **测试 `IsExactly()` 方法:** `IsExactly` 测试用例验证 `AsmType::IsExactly()` 方法是否能正确判断两个 `AsmType` 对象是否表示完全相同的类型。

6. **测试 `IsA()` 方法:** `IsA` 测试用例验证 `AsmType` 的 `IsA()` 方法是否能正确判断一个类型是否是另一个类型的子类型（包括直接继承和间接继承）。

7. **测试 `CanBeInvokedWith()` 方法:** `CanBeInvokedWith` 测试用例验证函数类型和重载函数类型的 `CanBeInvokedWith()` 方法，该方法用于判断一个函数是否可以使用给定的返回类型和参数列表进行调用。

8. **测试 `ElementSizeInBytes()` 方法:** `ElementSizeInBytes` 测试用例验证对于 TypedArray 类型，`ElementSizeInBytes()` 方法是否返回正确的元素大小（以字节为单位）。

9. **测试 `LoadType()` 方法:** `LoadType` 测试用例验证对于 TypedArray 类型，`LoadType()` 方法是否返回从该类型数组加载元素后得到的类型。

10. **测试 `StoreType()` 方法:** `StoreType` 测试用例验证对于 TypedArray 类型，`StoreType()` 方法是否返回可以存储到该类型数组的元素的类型。

**如果 `v8/test/unittests/asmjs/asm-types-unittest.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种 V8 内部使用的领域特定语言，用于定义内置函数和运行时代码。在这种情况下，该文件将包含使用 Torque 语法编写的单元测试，用于测试 asm.js 类型系统的相关功能。但是，根据您提供的信息，该文件以 `.cc` 结尾，所以它是 **C++ 源代码**。

**与 JavaScript 的功能关系：**

`asm-types-unittest.cc` 中测试的 `AsmType` 类是 V8 引擎处理 **asm.js** 代码的关键部分。asm.js 是 JavaScript 的一个严格子集，允许 JavaScript 引擎进行更积极的优化，接近原生代码的性能。

`AsmType` 类代表了 asm.js 中使用的各种数据类型，例如：

* **数值类型:** `int`, `double`, `float`, `signed`, `unsigned`, `fixnum` 等。
* **Typed Arrays:** `Int8Array`, `Uint8Array`, `Float32Array` 等。
* **特殊类型:** `void`, `extern` 等。
* **函数类型:** 表示函数的参数类型和返回类型。

当 V8 引擎解析和编译 asm.js 代码时，它会使用 `AsmType` 来跟踪变量和表达式的类型，并进行类型检查和优化。

**JavaScript 示例说明：**

虽然 `asm-types-unittest.cc` 是 C++ 代码，但它测试的类型系统直接对应于在 asm.js 代码中使用的类型。例如：

```javascript
function asmModule(stdlib, foreign, heap) {
  "use asm";

  var i = 0;
  var f = 0.0;
  var arr = new stdlib.Int32Array(heap);

  function add(a, b) {
    a = a | 0; // 将 a 转换为 int
    b = b | 0; // 将 b 转换为 int
    return (a + b) | 0; // 返回 int
  }

  function multiply(a, b) {
    a = +a; // 将 a 转换为 double
    b = +b; // 将 b 转换为 double
    return +(a * b); // 返回 double
  }

  function setArray(index, value) {
    index = index | 0;
    value = value | 0;
    arr[index] = value; // 对 Int32Array 进行操作
  }

  return {
    add: add,
    multiply: multiply,
    setArray: setArray
  };
}

// 创建一个堆缓冲区
var heap = new ArrayBuffer(256);
var module = asmModule(window, null, heap);

console.log(module.add(10, 20)); // 在 C++ 侧，类型将是 AsmType::Int()
console.log(module.multiply(3.14, 2.71)); // 在 C++ 侧，类型将是 AsmType::Double()
module.setArray(0, 100); // 在 C++ 侧，arr 的类型将是 AsmType::Int32Array()
```

在这个 JavaScript 示例中，`asmModule` 函数内部使用了 asm.js 的类型转换操作符（例如 `| 0` 将数值转换为 int，`+` 将数值转换为 double）。V8 引擎在编译这段代码时，会使用类似于 `AsmType::Int()`、`AsmType::Double()` 和 `AsmType::Int32Array()` 的类型来表示变量 `a`、`b` 和 `arr`。`asm-types-unittest.cc` 中的测试正是为了确保 V8 引擎正确地处理和理解这些类型。

**代码逻辑推理与假设输入/输出：**

以 `IsA` 测试为例，我们可以进行一些逻辑推理：

**假设输入：**

* `type1` = `AsmType::Int()`
* `type2` = `AsmType::Intish()`

根据 `parents_` 的定义：

```c++
{Type::Int(), {Type::Intish()}},
```

这意味着 `Int` 继承自 `Intish`。

**预期输出：**

`type1->IsA(type2)` 应该返回 `true`，因为 `Int` 是 `Intish` 的子类型。

**假设输入：**

* `type1` = `AsmType::Double()`
* `type2` = `AsmType::Int()`

根据 `parents_` 的定义，`Double` 和 `Int` 之间没有直接或间接的继承关系。

**预期输出：**

`type1->IsA(type2)` 应该返回 `false`。

**涉及用户常见的编程错误：**

测试用例可以帮助发现和防止用户在使用 asm.js 或类似类型系统时可能犯的编程错误，例如：

1. **类型不匹配：**  尝试将一个类型的值赋给另一个不兼容的类型。例如，在 asm.js 中将一个浮点数直接赋值给一个整型变量，而没有进行显式的类型转换。

   ```javascript
   function asmModule(stdlib, foreign, heap) {
     "use asm";
     var i = 0;
     function setValue(val) {
       i = val; // 错误：val 可能是浮点数，不能直接赋值给 int
       return i;
     }
     return { setValue: setValue };
   }
   ```
   `IsA` 等测试可以帮助确保 V8 在这种情况下能正确地进行类型检查或推断。

2. **函数参数类型错误：**  调用函数时传递了错误类型的参数。

   ```javascript
   function asmModule(stdlib, foreign, heap) {
     "use asm";
     function add(a, b) {
       a = a | 0;
       b = b | 0;
       return (a + b) | 0;
     }
     return { add: add };
   }
   var module = asmModule(window, null, null);
   module.add(3.14, 2.71); // 错误：应该传递整数
   ```
   `CanBeInvokedWith` 测试可以帮助验证 V8 能否正确地检查函数调用的参数类型是否匹配。

3. **Typed Array 的类型错误：**  尝试对 Typed Array 进行不兼容类型的操作。

   ```javascript
   function asmModule(stdlib, foreign, heap) {
     "use asm";
     var arr = new stdlib.Int32Array(heap);
     function set(index, value) {
       index = index | 0;
       arr[index] = value + 0.5; // 错误：尝试将浮点数存储到 Int32Array
     }
     return { set: set };
   }
   ```
   `LoadType` 和 `StoreType` 测试可以帮助确保 V8 对 Typed Array 的类型操作进行正确的验证。

总而言之，`v8/test/unittests/asmjs/asm-types-unittest.cc` 是 V8 引擎中一个重要的测试文件，它确保了 asm.js 类型系统的正确性和健壮性，从而帮助开发者编写出性能更高的 JavaScript 代码，并避免常见的类型相关的编程错误。

### 提示词
```
这是目录为v8/test/unittests/asmjs/asm-types-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/asmjs/asm-types-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```