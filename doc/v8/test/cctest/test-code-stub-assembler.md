Response: The user wants to understand the functionality of the C++ code in `v8/test/cctest/test-code-stub-assembler.cc`.
Specifically, for this first part of the file, I need to:
1. **Summarize the code's purpose**: What does this part of the test file aim to verify?
2. **Identify its relation to JavaScript**: Does it test features or mechanisms used in JavaScript?
3. **Provide JavaScript examples**: If there's a connection to JavaScript, illustrate it with code examples.

**Code Analysis (Part 1):**

- The file includes headers related to V8's internal components like `CodeStubAssembler`, `compiler`, `objects`, and `builtins`.
- It defines several test cases using the `TEST` macro, which is likely from a testing framework.
- Many tests involve creating a `CodeAssemblerTester` and `CodeStubAssembler`. This suggests the file is testing the functionality of the `CodeStubAssembler`, a component used for generating machine code stubs.
- The tests call various methods of the `CodeStubAssembler` (e.g., `CallCFunction`, `NumberToString`, `ToUint32`, `LoadFixedArrayElement`, `ToStringImpl`, `TryToName`, dictionary lookups, property access, element access).
- Several tests interact with JavaScript concepts like numbers, strings, objects, arrays, and symbols.

**Hypothesizing Functionality:**

This part of the test file appears to be testing the core functionalities provided by the `CodeStubAssembler`. It checks if the assembler can correctly generate code for:

- Calling C++ functions from generated code.
- Converting JavaScript values (numbers, objects) to different representations.
- Accessing properties and elements of JavaScript objects.
- Performing dictionary lookups (for objects).
- Handling transitions in object structures.

**Connecting to JavaScript:**

The `CodeStubAssembler` is used internally by V8 to generate optimized machine code for various JavaScript operations. The tests are essentially simulating these JavaScript operations at a lower level using the assembler.

**JavaScript Examples:**

For each of the tested `CodeStubAssembler` functionalities, I can provide a corresponding JavaScript example that would internally utilize that functionality.
这是文件 `v8/test/cctest/test-code-stub-assembler.cc` 的第一部分，它是一个 C++ 源代码文件，主要功能是**测试 V8 JavaScript 引擎中 `CodeStubAssembler` 的各种功能**。

`CodeStubAssembler` 是 V8 引擎中一个重要的组件，它提供了一种用于**生成机器代码片段 (code stubs)** 的高级接口。这些代码片段通常用于实现 V8 的内置函数、运行时函数以及优化的代码路径。

这个文件中的各个 `TEST` 宏定义了不同的测试用例，每个测试用例都针对 `CodeStubAssembler` 的一个或多个特定功能。这些测试用例通过以下步骤来验证 `CodeStubAssembler` 的正确性：

1. **初始化测试环境**: 创建 `Isolate`（V8 引擎的实例）和 `CodeAssemblerTester`。
2. **使用 `CodeStubAssembler` 生成代码**: 在 `CodeAssemblerTester` 的上下文中，使用 `CodeStubAssembler` 的各种方法（例如 `CallCFunction`, `NumberToString`, `ToUint32`, `LoadFixedArrayElement` 等）来构建一段机器代码逻辑。
3. **执行生成的代码**: 使用 `FunctionTester` 执行刚刚生成的机器代码。
4. **验证结果**: 比较执行结果和预期结果，以确保 `CodeStubAssembler` 生成的代码能够正确地执行预期的操作。

**与 JavaScript 功能的关系和 JavaScript 示例:**

这个文件测试的 `CodeStubAssembler` 的功能与许多底层的 JavaScript 操作直接相关。以下是一些测试用例及其对应的 JavaScript 功能示例：

1. **`TEST(CallCFunction)`**: 测试从 `CodeStubAssembler` 生成的代码中调用 C++ 函数的能力。
   ```javascript
   // 虽然 JavaScript 不能直接调用任意 C++ 函数，但 V8 引擎内部会使用类似机制
   // 来调用其自身的 C++ 实现。例如，某些内置函数的实现可能涉及调用 C++ 代码。
   // 在 V8 内部，当执行类似 Array.prototype.push 这样的操作时，可能会通过
   // CodeStubAssembler 生成的代码来调用底层的 C++ 实现。
   const arr = [];
   arr.push(1); // V8 内部可能会使用 CodeStubAssembler 生成的代码来执行 push 操作。
   ```

2. **`TEST(CallCFunctionWithCallerSavedRegisters)`**: 类似于 `CallCFunction`，但涉及到调用者保存寄存器的场景。这在处理函数调用约定和栈帧管理时很重要。

3. **`TEST(NumberToString)`**: 测试将 JavaScript 数字转换为字符串的功能。
   ```javascript
   const num = 123;
   const str = num.toString(); // JavaScript 的 toString() 方法在底层可能使用了 CodeStubAssembler 生成的代码。
   console.log(str); // 输出 "123"
   ```

4. **`TEST(ToUint32)`**: 测试将 JavaScript 值转换为 32 位无符号整数的功能。
   ```javascript
   const value = 4294967297;
   const uint32 = value >>> 0; // JavaScript 的无符号右移操作符 >>> 在底层可能使用了类似的功能。
   console.log(uint32); // 输出 1
   ```

5. **`TEST(IsValidPositiveSmi)`**: 测试判断一个整数是否是有效的正 Smi (Small Integer) 的功能。Smi 是 V8 中对小整数的优化表示。
   ```javascript
   const smallInt = 10; // V8 会将小整数优化为 Smi
   // V8 内部需要判断一个数值是否可以表示为 Smi

   const largeInt = 10000000000; // 超过 Smi 范围的整数
   ```

6. **`TEST(ConvertAndClampRelativeIndex)`**: 测试将相对索引转换为绝对索引，并进行边界 clamping 的功能。这在处理数组的负索引时用到。
   ```javascript
   const arr = [1, 2, 3, 4, 5];
   const lastElement = arr[-1 + arr.length]; // 访问最后一个元素
   console.log(lastElement); // 输出 5
   ```

7. **`TEST(FixedArrayAccessSmiIndex)`**: 测试访问 `FixedArray` 中元素的功能。`FixedArray` 是 V8 中用于存储对象属性和数组元素的底层数据结构。
   ```javascript
   const arr = [10, 20, 30]; // JavaScript 数组在底层可能会使用 FixedArray
   const element = arr[1]; // 访问索引为 1 的元素
   console.log(element); // 输出 20
   ```

8. **`TEST(LoadHeapNumberValue)`**: 测试加载 `HeapNumber`（V8 中表示浮点数和超出 Smi 范围的整数的对象）的值的功能。
   ```javascript
   const bigNumber = 9007199254740992; // 超出 Smi 范围，会被表示为 HeapNumber
   // V8 内部需要加载 HeapNumber 存储的实际数值
   ```

9. **`TEST(LoadInstanceType)`**: 测试加载对象的实例类型的功能。
   ```javascript
   const obj = {};
   // V8 内部会记录对象的类型信息
   ```

10. **`TEST(DecodeWordFromWord32)`**: 测试从一个 32 位字中解码特定位域的功能。这在处理对象布局和标记时可能用到。

11. **`TEST(JSFunction)`**: 测试调用 JavaScript 函数的功能。
    ```javascript
    function add(a, b) {
      return a + b;
    }
    const result = add(5, 3); // JavaScript 函数调用
    console.log(result); // 输出 8
    ```

12. **`TEST(ComputeIntegerHash)`**: 测试计算整数哈希值的功能。这在实现对象属性查找等操作时用到。
    ```javascript
    const obj = { key: 'value' };
    // 当访问 obj.key 时，V8 内部会计算属性名的哈希值来快速定位属性。
    ```

13. **`TEST(ToString)`**: 测试将各种 JavaScript 值转换为字符串的功能。
    ```javascript
    const value1 = 123;
    const str1 = String(value1); // 显式转换为字符串
    const value2 = true;
    const str2 = '' + value2; // 隐式转换为字符串
    ```

14. **`TEST(TryToName)`**: 测试尝试将 JavaScript 值转换为名称 (Name) 的功能。Name 是 V8 中字符串和 Symbol 的基类。这在处理对象属性名时很重要。
    ```javascript
    const obj = {};
    const key1 = 'property';
    obj[key1] = 1; // 属性名 'property' 是一个 Name
    const key2 = Symbol('mySymbol');
    obj[key2] = 2; // Symbol 'mySymbol' 也是一个 Name
    ```

总而言之，这个代码文件的第一部分专注于测试 `CodeStubAssembler` 的基础能力，这些能力是 V8 引擎实现各种 JavaScript 核心功能的基础。它涵盖了函数调用、类型转换、内存访问、哈希计算以及对象属性操作等多个方面。理解这些测试用例有助于深入了解 V8 引擎的内部工作原理。

### 提示词
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <optional>

#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins-promise-gen.h"
#include "src/builtins/builtins-promise.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/builtins/builtins-utils-inl.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/compiler/node.h"
#include "src/debug/debug.h"
#include "src/execution/isolate.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/smi.h"
#include "src/objects/transitions-inl.h"
#include "src/strings/char-predicates.h"
#include "test/cctest/cctest-utils.h"
#include "test/cctest/compiler/function-tester.h"
#include "test/common/code-assembler-tester.h"

namespace v8 {
namespace internal {
namespace compiler {

#include "src/codegen/define-code-stub-assembler-macros.inc"

namespace {

using Label = CodeAssemblerLabel;
template <class T>
using TVariable = TypedCodeAssemblerVariable<T>;
using PromiseResolvingFunctions = TorqueStructPromiseResolvingFunctions;

intptr_t sum10(intptr_t a0, intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4,
               intptr_t a5, intptr_t a6, intptr_t a7, intptr_t a8,
               intptr_t a9) {
  return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9;
}

static int sum3(int a0, int a1, int a2) { return a0 + a1 + a2; }

}  // namespace

TEST(CallCFunction) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    const TNode<ExternalReference> fun_constant = m.ExternalConstant(
        ExternalReference::Create(reinterpret_cast<Address>(sum10)));

    MachineType type_intptr = MachineType::IntPtr();

    TNode<IntPtrT> const result = m.UncheckedCast<IntPtrT>(
        m.CallCFunction(fun_constant, type_intptr,
                        std::make_pair(type_intptr, m.IntPtrConstant(0)),
                        std::make_pair(type_intptr, m.IntPtrConstant(1)),
                        std::make_pair(type_intptr, m.IntPtrConstant(2)),
                        std::make_pair(type_intptr, m.IntPtrConstant(3)),
                        std::make_pair(type_intptr, m.IntPtrConstant(4)),
                        std::make_pair(type_intptr, m.IntPtrConstant(5)),
                        std::make_pair(type_intptr, m.IntPtrConstant(6)),
                        std::make_pair(type_intptr, m.IntPtrConstant(7)),
                        std::make_pair(type_intptr, m.IntPtrConstant(8)),
                        std::make_pair(type_intptr, m.IntPtrConstant(9))));
    m.Return(m.SmiTag(result));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  DirectHandle<Object> result = ft.Call().ToHandleChecked();
  CHECK_EQ(45, Cast<Smi>(*result).value());
}

TEST(CallCFunctionWithCallerSavedRegisters) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    const TNode<ExternalReference> fun_constant = m.ExternalConstant(
        ExternalReference::Create(reinterpret_cast<Address>(sum3)));

    MachineType type_intptr = MachineType::IntPtr();

    TNode<IntPtrT> const result =
        m.UncheckedCast<IntPtrT>(m.CallCFunctionWithCallerSavedRegisters(
            fun_constant, type_intptr, SaveFPRegsMode::kSave,
            std::make_pair(type_intptr, m.IntPtrConstant(0)),
            std::make_pair(type_intptr, m.IntPtrConstant(1)),
            std::make_pair(type_intptr, m.IntPtrConstant(2))));
    m.Return(m.SmiTag(result));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  DirectHandle<Object> result = ft.Call().ToHandleChecked();
  CHECK_EQ(3, Cast<Smi>(*result).value());
}

TEST(NumberToString) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    auto input = m.Parameter<Number>(1);

    Label bailout(&m);
    m.Return(m.NumberToString(input, &bailout));

    m.BIND(&bailout);
    m.Return(m.UndefinedConstant());
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // clang-format off
  double inputs[] = {
     1, 2, 42, 153, -1, -100, 0, 51095154, -1241950,
     std::nan("-1"), std::nan("1"), std::nan("2"),
    -std::numeric_limits<double>::infinity(),
     std::numeric_limits<double>::infinity(),
    -0.0, -0.001, -0.5, -0.999, -1.0,
     0.0,  0.001,  0.5,  0.999,  1.0,
    -2147483647.9, -2147483648.0, -2147483648.5, -2147483648.9,  // SmiMin.
     2147483646.9,  2147483647.0,  2147483647.5,  2147483647.9,  // SmiMax.
    -4294967295.9, -4294967296.0, -4294967296.5, -4294967297.0,  // - 2^32.
     4294967295.9,  4294967296.0,  4294967296.5,  4294967297.0,  //   2^32.
  };
  // clang-format on

  const int kFullCacheSize = isolate->heap()->MaxNumberToStringCacheSize();
  const int test_count = arraysize(inputs);
  for (int i = 0; i < test_count; i++) {
    int cache_length_before_addition = factory->number_string_cache()->length();
    Handle<Object> input = factory->NewNumber(inputs[i]);
    DirectHandle<String> expected = factory->NumberToString(input);

    DirectHandle<Object> result = ft.Call(input).ToHandleChecked();
    if (IsUndefined(*result, isolate)) {
      // Query may fail if cache was resized, in which case the entry is not
      // added to the cache.
      CHECK_LT(cache_length_before_addition, kFullCacheSize);
      CHECK_EQ(factory->number_string_cache()->length(), kFullCacheSize);
      expected = factory->NumberToString(input);
      result = ft.Call(input).ToHandleChecked();
    }
    CHECK(!IsUndefined(*result, isolate));
    CHECK_EQ(*expected, *result);
  }
}

namespace {

void CheckToUint32Result(uint32_t expected, DirectHandle<Object> result) {
  const int64_t result_int64 = NumberToInt64(*result);
  const uint32_t result_uint32 = NumberToUint32(*result);

  CHECK_EQ(static_cast<int64_t>(result_uint32), result_int64);
  CHECK_EQ(expected, result_uint32);

  // Ensure that the result is normalized to a Smi, i.e. a HeapNumber is only
  // returned if the result is not within Smi range.
  const bool expected_fits_into_intptr =
      static_cast<int64_t>(expected) <=
      static_cast<int64_t>(std::numeric_limits<intptr_t>::max());
  if (expected_fits_into_intptr &&
      Smi::IsValid(static_cast<intptr_t>(expected))) {
    CHECK(IsSmi(*result));
  } else {
    CHECK(IsHeapNumber(*result));
  }
}

}  // namespace

TEST(ToUint32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    auto context = m.GetJSContextParameter();
    auto input = m.Parameter<Object>(1);
    m.Return(m.ToUint32(context, input));
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // clang-format off
  double inputs[] = {
     std::nan("-1"), std::nan("1"), std::nan("2"),
    -std::numeric_limits<double>::infinity(),
     std::numeric_limits<double>::infinity(),
    -0.0, -0.001, -0.5, -0.999, -1.0,
     0.0,  0.001,  0.5,  0.999,  1.0,
    -2147483647.9, -2147483648.0, -2147483648.5, -2147483648.9,  // SmiMin.
     2147483646.9,  2147483647.0,  2147483647.5,  2147483647.9,  // SmiMax.
    -4294967295.9, -4294967296.0, -4294967296.5, -4294967297.0,  // - 2^32.
     4294967295.9,  4294967296.0,  4294967296.5,  4294967297.0,  //   2^32.
  };

  uint32_t expectations[] = {
     0, 0, 0,
     0,
     0,
     0, 0, 0, 0, 4294967295,
     0, 0, 0, 0, 1,
     2147483649, 2147483648, 2147483648, 2147483648,
     2147483646, 2147483647, 2147483647, 2147483647,
     1, 0, 0, 4294967295,
     4294967295, 0, 0, 1,
  };
  // clang-format on

  static_assert(arraysize(inputs) == arraysize(expectations));

  const int test_count = arraysize(inputs);
  for (int i = 0; i < test_count; i++) {
    Handle<Object> input_obj = factory->NewNumber(inputs[i]);
    Handle<HeapNumber> input_num;

    // Check with Smi input.
    if (IsSmi(*input_obj)) {
      Handle<Smi> input_smi = Cast<Smi>(input_obj);
      DirectHandle<Object> result = ft.Call(input_smi).ToHandleChecked();
      CheckToUint32Result(expectations[i], result);
      input_num = factory->NewHeapNumber(inputs[i]);
    } else {
      input_num = Cast<HeapNumber>(input_obj);
    }

    // Check with HeapNumber input.
    {
      CHECK(IsHeapNumber(*input_num));
      DirectHandle<Object> result = ft.Call(input_num).ToHandleChecked();
      CheckToUint32Result(expectations[i], result);
    }
  }

  // A couple of final cases for ToNumber conversions.
  CheckToUint32Result(0, ft.Call(factory->undefined_value()).ToHandleChecked());
  CheckToUint32Result(0, ft.Call(factory->null_value()).ToHandleChecked());
  CheckToUint32Result(0, ft.Call(factory->false_value()).ToHandleChecked());
  CheckToUint32Result(1, ft.Call(factory->true_value()).ToHandleChecked());
  CheckToUint32Result(
      42,
      ft.Call(factory->NewStringFromAsciiChecked("0x2A")).ToHandleChecked());

  ft.CheckThrows(factory->match_symbol());
}

namespace {
void IsValidPositiveSmiCase(Isolate* isolate, intptr_t value) {
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));

  CodeStubAssembler m(asm_tester.state());
  m.Return(
      m.SelectBooleanConstant(m.IsValidPositiveSmi(m.IntPtrConstant(value))));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  MaybeHandle<Object> maybe_handle = ft.Call();

  bool expected = i::PlatformSmiTagging::IsValidSmi(value) && (value >= 0);
  if (expected) {
    CHECK(IsTrue(*maybe_handle.ToHandleChecked(), isolate));
  } else {
    CHECK(IsFalse(*maybe_handle.ToHandleChecked(), isolate));
  }
}
}  // namespace

TEST(IsValidPositiveSmi) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  IsValidPositiveSmiCase(isolate, -1);
  IsValidPositiveSmiCase(isolate, 0);
  IsValidPositiveSmiCase(isolate, 1);

  IsValidPositiveSmiCase(isolate, 0x3FFFFFFFU);
  IsValidPositiveSmiCase(isolate, 0xC0000000U);
  IsValidPositiveSmiCase(isolate, 0x40000000U);
  IsValidPositiveSmiCase(isolate, 0xBFFFFFFFU);

  using int32_limits = std::numeric_limits<int32_t>;
  IsValidPositiveSmiCase(isolate, int32_limits::max());
  IsValidPositiveSmiCase(isolate, int32_limits::min());
#if V8_TARGET_ARCH_64_BIT
  IsValidPositiveSmiCase(isolate,
                         static_cast<intptr_t>(int32_limits::max()) + 1);
  IsValidPositiveSmiCase(isolate,
                         static_cast<intptr_t>(int32_limits::min()) - 1);
#endif
}

TEST(ConvertAndClampRelativeIndex) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kNotFound };
  {
    auto index = m.Parameter<Number>(1);
    auto length_number = m.Parameter<Number>(2);
    auto expected_relative_index = m.Parameter<Number>(3);

    TNode<UintPtrT> length = m.ChangeUintPtrNumberToUintPtr(length_number);
    TNode<UintPtrT> expected =
        m.ChangeUintPtrNumberToUintPtr(expected_relative_index);

    TNode<UintPtrT> result = m.ConvertAndClampRelativeIndex(index, length);

    m.Return(m.SelectBooleanConstant(m.WordEqual(result, expected)));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  const double kMaxSmi = static_cast<double>(kSmiMaxValue);
  const double kMaxInt32 =
      static_cast<double>(std::numeric_limits<int32_t>::max());
  const double kMaxUInt32 =
      static_cast<double>(std::numeric_limits<uint32_t>::max());
  const double kMaxUIntPtr =
      static_cast<double>(std::numeric_limits<uintptr_t>::max());

  struct {
    double index;
    double length;
    double expected_result;
  } test_cases[] = {
      // Simple Smi-range cases.
      {0, 0, 0},
      {0, 42, 0},
      {5, 42, 5},
      {100, 42, 42},
      {-10, 153, 153 - 10},
      {-200, 153, 0},
      // Beyond Smi-range index cases.
      {0, kMaxSmi, 0},
      {-153, kMaxSmi, kMaxSmi - 153},
      {kMaxSmi + 153, kMaxSmi, kMaxSmi},
      {kMaxSmi * 33, kMaxSmi, kMaxSmi},
      {-kMaxSmi, kMaxSmi, 0},
      {-kMaxSmi - 1, kMaxSmi, 0},
      {-kMaxSmi - 153, kMaxSmi, 0},
      {-kMaxSmi * 33, kMaxSmi, 0},
      {-std::numeric_limits<double>::infinity(), 153, 0},
      {std::numeric_limits<double>::infinity(), 424242, 424242},
      // Beyond Smi-range length cases.
      {kMaxSmi + 2, kMaxSmi + 1, kMaxSmi + 1},
      {-kMaxSmi + 2, kMaxSmi + 1, 3},
      {kMaxInt32 + 1, kMaxInt32, kMaxInt32},
      {-kMaxInt32 + 1, kMaxInt32, 1},
      {kMaxUInt32 + 1, kMaxUInt32, kMaxUInt32},
      {-42, kMaxUInt32, kMaxUInt32 - 42},
      {-kMaxUInt32 - 1, kMaxUInt32, 0},
      {-kMaxUInt32, kMaxUInt32, 0},
      {-kMaxUInt32 + 1, kMaxUInt32, 1},
      {-kMaxUInt32 + 5, kMaxUInt32, 5},
      {-kMaxUInt32 + 5, kMaxUInt32 + 1, 6},
      {-kMaxSmi * 33, kMaxSmi * 153, kMaxSmi * (153 - 33)},
      {0, kMaxSafeInteger, 0},
      {kMaxSmi, kMaxSafeInteger, kMaxSmi},
      {kMaxSmi * 153, kMaxSafeInteger, kMaxSmi * 153},
      {-10, kMaxSafeInteger, kMaxSafeInteger - 10},
      {-kMaxSafeInteger, kMaxSafeInteger, 0},
      {-kMaxSafeInteger + 1, kMaxSafeInteger, 1},
      {-kMaxSafeInteger + 42, kMaxSafeInteger, 42},
      {kMaxSafeInteger - 153, kMaxSafeInteger, kMaxSafeInteger - 153},
      {kMaxSafeInteger - 1, kMaxSafeInteger, kMaxSafeInteger - 1},
      {kMaxSafeInteger, kMaxSafeInteger, kMaxSafeInteger},
      {kMaxSafeInteger + 1, kMaxSafeInteger, kMaxSafeInteger},
      {kMaxSafeInteger + 42, kMaxSafeInteger, kMaxSafeInteger},
      {kMaxSafeInteger * 11, kMaxSafeInteger, kMaxSafeInteger},
  };

  Factory* factory = isolate->factory();
  for (size_t i = 0; i < arraysize(test_cases); i++) {
    if (test_cases[i].length > kMaxUIntPtr) {
      // Test cases where length does not fit into uintptr are not valid, so
      // skip them instead of ifdef'ing the test cases above.
      continue;
    }
    Handle<Object> index = factory->NewNumber(test_cases[i].index);
    Handle<Object> length = factory->NewNumber(test_cases[i].length);
    Handle<Object> expected = factory->NewNumber(test_cases[i].expected_result);

    ft.CheckTrue(index, length, expected);
  }
}

TEST(FixedArrayAccessSmiIndex) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());
  Handle<FixedArray> array = isolate->factory()->NewFixedArray(5);
  array->set(4, Smi::FromInt(733));
  m.Return(m.LoadFixedArrayElement(m.HeapConstantNoHole(array),
                                   m.SmiTag(m.IntPtrConstant(4)), 0));
  FunctionTester ft(asm_tester.GenerateCode());
  MaybeHandle<Object> result = ft.Call();
  CHECK_EQ(733, Cast<Smi>(*result.ToHandleChecked()).value());
}

TEST(LoadHeapNumberValue) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());
  Handle<HeapNumber> number = isolate->factory()->NewHeapNumber(1234);
  m.Return(m.SmiFromInt32(m.Signed(m.ChangeFloat64ToUint32(
      m.LoadHeapNumberValue(m.HeapConstantNoHole(number))))));
  FunctionTester ft(asm_tester.GenerateCode());
  MaybeHandle<Object> result = ft.Call();
  CHECK_EQ(1234, Cast<Smi>(*result.ToHandleChecked()).value());
}

TEST(LoadInstanceType) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());
  Handle<HeapObject> undefined = isolate->factory()->undefined_value();
  m.Return(m.SmiFromInt32(m.LoadInstanceType(m.HeapConstantNoHole(undefined))));
  FunctionTester ft(asm_tester.GenerateCode());
  MaybeHandle<Object> result = ft.Call();
  CHECK_EQ(InstanceType::ODDBALL_TYPE,
           Cast<Smi>(*result.ToHandleChecked()).value());
}

TEST(DecodeWordFromWord32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate);
  CodeStubAssembler m(asm_tester.state());

  using TestBitField = base::BitField<unsigned, 3, 3>;
  m.Return(m.SmiTag(
      m.Signed(m.DecodeWordFromWord32<TestBitField>(m.Int32Constant(0x2F)))));
  FunctionTester ft(asm_tester.GenerateCode());
  MaybeHandle<Object> result = ft.Call();
  // value  = 00101111
  // mask   = 00111000
  // result = 101
  CHECK_EQ(5, Cast<Smi>(*result.ToHandleChecked()).value());
}

TEST(JSFunction) {
  const int kNumParams = 2;  // left, right.
  Isolate* isolate(CcTest::InitIsolateOnce());
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.SmiFromInt32(m.Int32Add(m.SmiToInt32(m.Parameter<Smi>(1)),
                                     m.SmiToInt32(m.Parameter<Smi>(2)))));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  MaybeHandle<Object> result = ft.Call(handle(Smi::FromInt(23), isolate),
                                       handle(Smi::FromInt(34), isolate));
  CHECK_EQ(57, Cast<Smi>(*result.ToHandleChecked()).value());
}

TEST(ComputeIntegerHash) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  m.Return(m.SmiFromInt32(m.UncheckedCast<Int32T>(
      m.ComputeSeededHash(m.SmiUntag(m.Parameter<Smi>(1))))));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  for (int i = 0; i < 1024; i++) {
    int k = rand_gen.NextInt(Smi::kMaxValue);

    Handle<Smi> key(Smi::FromInt(k), isolate);
    DirectHandle<Object> result = ft.Call(key).ToHandleChecked();

    uint32_t hash = ComputeSeededHash(k, HashSeed(isolate));
    Tagged<Smi> expected = Smi::FromInt(hash);
    CHECK_EQ(expected, Cast<Smi>(*result));
  }
}

TEST(ToString) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.ToStringImpl(m.GetJSContextParameter(), m.Parameter<Object>(1)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  DirectHandle<FixedArray> test_cases = isolate->factory()->NewFixedArray(5);
  DirectHandle<FixedArray> smi_test = isolate->factory()->NewFixedArray(2);
  smi_test->set(0, Smi::FromInt(42));
  DirectHandle<String> str(isolate->factory()->InternalizeUtf8String("42"));
  smi_test->set(1, *str);
  test_cases->set(0, *smi_test);

  DirectHandle<FixedArray> number_test = isolate->factory()->NewFixedArray(2);
  DirectHandle<HeapNumber> num(isolate->factory()->NewHeapNumber(3.14));
  number_test->set(0, *num);
  str = isolate->factory()->InternalizeUtf8String("3.14");
  number_test->set(1, *str);
  test_cases->set(1, *number_test);

  DirectHandle<FixedArray> string_test = isolate->factory()->NewFixedArray(2);
  str = isolate->factory()->InternalizeUtf8String("test");
  string_test->set(0, *str);
  string_test->set(1, *str);
  test_cases->set(2, *string_test);

  DirectHandle<FixedArray> oddball_test = isolate->factory()->NewFixedArray(2);
  oddball_test->set(0, ReadOnlyRoots(isolate).undefined_value());
  str = isolate->factory()->InternalizeUtf8String("undefined");
  oddball_test->set(1, *str);
  test_cases->set(3, *oddball_test);

  DirectHandle<FixedArray> tostring_test = isolate->factory()->NewFixedArray(2);
  Handle<FixedArray> js_array_storage = isolate->factory()->NewFixedArray(2);
  js_array_storage->set(0, Smi::FromInt(1));
  js_array_storage->set(1, Smi::FromInt(2));
  Handle<JSArray> js_array = isolate->factory()->NewJSArray(2);
  JSArray::SetContent(js_array, js_array_storage);
  tostring_test->set(0, *js_array);
  str = isolate->factory()->InternalizeUtf8String("1,2");
  tostring_test->set(1, *str);
  test_cases->set(4, *tostring_test);

  for (int i = 0; i < 5; ++i) {
    DirectHandle<FixedArray> test(Cast<FixedArray>(test_cases->get(i)),
                                  isolate);
    Handle<Object> obj(test->get(0), isolate);
    Handle<String> expected(Cast<String>(test->get(1)), isolate);
    Handle<Object> result = ft.Call(obj).ToHandleChecked();
    CHECK(IsString(*result));
    CHECK(String::Equals(isolate, Cast<String>(result), expected));
  }
}

TEST(TryToName) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kKeyIsIndex, kKeyIsUnique, kBailout };
  {
    auto key = m.Parameter<Object>(1);
    auto expected_result = m.UncheckedParameter<MaybeObject>(2);
    auto expected_arg = m.Parameter<Object>(3);

    Label passed(&m), failed(&m);
    Label if_keyisindex(&m), if_keyisunique(&m), if_bailout(&m);
    {
      TYPED_VARIABLE_DEF(IntPtrT, var_index, &m);
      TYPED_VARIABLE_DEF(Name, var_unique, &m);
      TYPED_VARIABLE_DEF(IntPtrT, var_expected, &m);

      m.TryToName(key, &if_keyisindex, &var_index, &if_keyisunique, &var_unique,
                  &if_bailout);

      m.BIND(&if_keyisindex);
      m.GotoIfNot(m.TaggedEqual(expected_result,
                                m.SmiConstant(Smi::FromInt(kKeyIsIndex))),
                  &failed);

      Label if_expectedissmi(&m), if_expectedisheapnumber(&m), check_result(&m);
      m.Branch(m.TaggedIsSmi(expected_arg), &if_expectedissmi,
               &if_expectedisheapnumber);

      m.BIND(&if_expectedissmi);
      var_expected = m.SmiUntag(m.CAST(expected_arg));
      m.Goto(&check_result);

      m.BIND(&if_expectedisheapnumber);
      CSA_DCHECK(&m, m.IsHeapNumber(m.CAST(expected_arg)));
      TNode<Float64T> value = m.LoadHeapNumberValue(m.CAST(expected_arg));
      // We know this to be safe as all expected values are in intptr
      // range.
      var_expected = m.UncheckedCast<IntPtrT>(m.ChangeFloat64ToUintPtr(value));
      m.Goto(&check_result);

      m.BIND(&check_result);
      m.Branch(m.IntPtrEqual(var_expected.value(), var_index.value()), &passed,
               &failed);

      m.BIND(&if_keyisunique);
      m.GotoIfNot(m.TaggedEqual(expected_result,
                                m.SmiConstant(Smi::FromInt(kKeyIsUnique))),
                  &failed);
      m.Branch(m.TaggedEqual(expected_arg, var_unique.value()), &passed,
               &failed);
    }

    m.BIND(&if_bailout);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kBailout))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_index(Smi::FromInt(kKeyIsIndex), isolate);
  Handle<Object> expect_unique(Smi::FromInt(kKeyIsUnique), isolate);
  Handle<Object> expect_bailout(Smi::FromInt(kBailout), isolate);

  {
    // TryToName(<zero smi>) => if_keyisindex: smi value.
    Handle<Object> key(Smi::zero(), isolate);
    ft.CheckTrue(key, expect_index, key);
  }

  {
    // TryToName(<positive smi>) => if_keyisindex: smi value.
    Handle<Object> key(Smi::FromInt(153), isolate);
    ft.CheckTrue(key, expect_index, key);
  }

  {
    // TryToName(<negative smi>) => if_keyisindex: smi value.
    // A subsequent bounds check needs to take care of this case.
    Handle<Object> key(Smi::FromInt(-1), isolate);
    ft.CheckTrue(key, expect_index, key);
  }

  {
    // TryToName(<heap number with int value>) => if_keyisindex: number.
    Handle<Object> key(isolate->factory()->NewHeapNumber(153));
    Handle<Object> index(Smi::FromInt(153), isolate);
    ft.CheckTrue(key, expect_index, index);
  }

  {
    // TryToName(<true>) => if_keyisunique: "true".
    Handle<Object> key = isolate->factory()->true_value();
    Handle<Object> unique = isolate->factory()->InternalizeUtf8String("true");
    ft.CheckTrue(key, expect_unique, unique);
  }

  {
    // TryToName(<false>) => if_keyisunique: "false".
    Handle<Object> key = isolate->factory()->false_value();
    Handle<Object> unique = isolate->factory()->InternalizeUtf8String("false");
    ft.CheckTrue(key, expect_unique, unique);
  }

  {
    // TryToName(<null>) => if_keyisunique: "null".
    Handle<Object> key = isolate->factory()->null_value();
    Handle<Object> unique = isolate->factory()->InternalizeUtf8String("null");
    ft.CheckTrue(key, expect_unique, unique);
  }

  {
    // TryToName(<undefined>) => if_keyisunique: "undefined".
    Handle<Object> key = isolate->factory()->undefined_value();
    Handle<Object> unique =
        isolate->factory()->InternalizeUtf8String("undefined");
    ft.CheckTrue(key, expect_unique, unique);
  }

  {
    // TryToName(<symbol>) => if_keyisunique: <symbol>.
    Handle<Object> key = isolate->factory()->NewSymbol();
    ft.CheckTrue(key, expect_unique, key);
  }

  {
    // TryToName(<internalized string>) => if_keyisunique: <internalized string>
    Handle<Object> key = isolate->factory()->InternalizeUtf8String("test");
    ft.CheckTrue(key, expect_unique, key);
  }

  {
    // TryToName(<internalized number string>) => if_keyisindex: number.
    Handle<Object> key = isolate->factory()->InternalizeUtf8String("153");
    Handle<Object> index(Smi::FromInt(153), isolate);
    ft.CheckTrue(key, expect_index, index);
  }

  {
    // TryToName(<internalized uncacheable number string greater than
    // array index but less than MAX_SAFE_INTEGER>) => 32-bit platforms
    // take the if_keyisunique path, 64-bit platforms bail out because they
    // let the runtime handle the string-to-size_t parsing.
    Handle<Object> key =
        isolate->factory()->InternalizeUtf8String("4294967296");
#if V8_TARGET_ARCH_64_BIT
    ft.CheckTrue(key, expect_bailout);
#else
    ft.CheckTrue(key, expect_unique, key);
#endif
  }

  {
    // TryToName(<internalized uncacheable number string greater than
    // INT_MAX but less than array index>) => bailout.
    Handle<Object> key =
        isolate->factory()->InternalizeUtf8String("4294967294");
    ft.CheckTrue(key, expect_bailout);
  }

  {
    // TryToName(<internalized uncacheable number string less than
    // INT_MAX>) => bailout
    Handle<Object> key =
        isolate->factory()->InternalizeUtf8String("2147483647");
    ft.CheckTrue(key, expect_bailout);
  }

  {
    // TryToName(<non-internalized number string>) => if_keyisindex: number.
    Handle<String> key = isolate->factory()->NewStringFromAsciiChecked("153");
    uint32_t dummy;
    CHECK(key->AsArrayIndex(&dummy));
    CHECK(key->HasHashCode());
    CHECK(!IsInternalizedString(*key));
    Handle<Object> index(Smi::FromInt(153), isolate);
    ft.CheckTrue(key, expect_index, index);
  }

  {
    // TryToName(<number string without cached index>) => is_keyisindex: number.
    Handle<String> key = isolate->factory()->NewStringFromAsciiChecked("153");
    CHECK(!key->HasHashCode());
    ft.CheckTrue(key, expect_bailout);
  }

  {
    // TryToName(<non-internalized string>) => bailout.
    Handle<Object> key = isolate->factory()->NewStringFromAsciiChecked("test");
    ft.CheckTrue(key, expect_bailout);
  }

  {
    // TryToName(<thin string>) => internalized version.
    Handle<String> s = isolate->factory()->NewStringFromAsciiChecked("foo");
    Handle<String> internalized = isolate->factory()->InternalizeString(s);
    ft.CheckTrue(s, expect_unique, internalized);
  }

  {
    // TryToName(<thin two-byte string>) => internalized version.
    base::uc16 array1[] = {2001, 2002, 2003};
    Handle<String> s = isolate->factory()
                           ->NewStringFromTwoByte(base::ArrayVector(array1))
                           .ToHandleChecked();
    Handle<String> internalized = isolate->factory()->InternalizeString(s);
    ft.CheckTrue(s, expect_unique, internalized);
  }
}

namespace {

template <typename Dictionary>
void TestEntryToIndex() {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  {
    TNode<IntPtrT> entry = m.SmiUntag(m.Parameter<Smi>(1));
    TNode<IntPtrT> result = m.EntryToIndex<Dictionary>(entry);
    m.Return(m.SmiTag(result));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  // Test a wide range of entries but staying linear in the first 100 entries.
  for (int entry = 0; entry < Dictionary::kMaxCapacity;
       entry = entry * 1.01 + 1) {
    DirectHandle<Object> result =
        ft.Call(handle(Smi::FromInt(entry), isolate)).ToHandleChecked();
    CHECK_EQ(Dictionary::EntryToIndex(InternalIndex(entry)),
             Smi::ToInt(*result));
  }
}

TEST(NameDictionaryEntryToIndex) { TestEntryToIndex<NameDictionary>(); }
TEST(GlobalDictionaryEntryToIndex) { TestEntryToIndex<GlobalDictionary>(); }

}  // namespace

namespace {

template <typename Dictionary>
void TestNameDictionaryLookup() {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 4;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kNotFound };
  {
    auto dictionary = m.Parameter<Dictionary>(1);
    auto unique_name = m.Parameter<Name>(2);
    auto expected_result = m.Parameter<Smi>(3);
    auto expected_arg = m.Parameter<Object>(4);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m);
    TVariable<IntPtrT> var_name_index(&m);

    m.NameDictionaryLookup<Dictionary>(dictionary, unique_name, &if_found,
                                       &var_name_index, &if_not_found);
    m.BIND(&if_found);
    m.GotoIfNot(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &failed);
    m.Branch(
        m.WordEqual(m.SmiUntag(m.CAST(expected_arg)), var_name_index.value()),
        &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);

  Handle<Dictionary> dictionary = Dictionary::New(isolate, 40);
  PropertyDetails fake_details = PropertyDetails::Empty();

  Factory* factory = isolate->factory();
  Handle<Name> keys[] = {
      factory->InternalizeUtf8String("0"),
      factory->InternalizeUtf8String("42"),
      factory->InternalizeUtf8String("-153"),
      factory->InternalizeUtf8String("0.0"),
      factory->InternalizeUtf8String("4.2"),
      factory->InternalizeUtf8String(""),
      factory->InternalizeUtf8String("name"),
      factory->NewSymbol(),
      factory->NewPrivateSymbol(),
  };

  for (size_t i = 0; i < arraysize(keys); i++) {
    Handle<Object> value =
        factory->NewPropertyCell(keys[i], fake_details, keys[i]);
    dictionary =
        Dictionary::Add(isolate, dictionary, keys[i], value, fake_details);
  }

  for (size_t i = 0; i < arraysize(keys); i++) {
    InternalIndex entry = dictionary->FindEntry(isolate, keys[i]);
    int name_index =
        Dictionary::EntryToIndex(entry) + Dictionary::kEntryKeyIndex;
    CHECK(entry.is_found());

    Handle<Object> expected_name_index(Smi::FromInt(name_index), isolate);
    ft.CheckTrue(dictionary, keys[i], expect_found, expected_name_index);
  }

  Handle<Name> non_existing_keys[] = {
      factory->InternalizeUtf8String("1"),
      factory->InternalizeUtf8String("-42"),
      factory->InternalizeUtf8String("153"),
      factory->InternalizeUtf8String("-1.0"),
      factory->InternalizeUtf8String("1.3"),
      factory->InternalizeUtf8String("a"),
      factory->InternalizeUtf8String("boom"),
      factory->NewSymbol(),
      factory->NewPrivateSymbol(),
  };

  for (size_t i = 0; i < arraysize(non_existing_keys); i++) {
    InternalIndex entry = dictionary->FindEntry(isolate, non_existing_keys[i]);
    CHECK(entry.is_not_found());

    ft.CheckTrue(dictionary, non_existing_keys[i], expect_not_found);
  }
}

}  // namespace

TEST(NameDictionaryLookup) { TestNameDictionaryLookup<NameDictionary>(); }

TEST(GlobalDictionaryLookup) { TestNameDictionaryLookup<GlobalDictionary>(); }

TEST(NumberDictionaryLookup) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 4;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kNotFound };
  {
    auto dictionary = m.Parameter<NumberDictionary>(1);
    TNode<IntPtrT> key = m.SmiUntag(m.Parameter<Smi>(2));
    auto expected_result = m.Parameter<Smi>(3);
    auto expected_arg = m.Parameter<Object>(4);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m);
    TVariable<IntPtrT> var_entry(&m);

    m.NumberDictionaryLookup(dictionary, key, &if_found, &var_entry,
                             &if_not_found);
    m.BIND(&if_found);
    m.GotoIfNot(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &failed);
    m.Branch(m.WordEqual(m.SmiUntag(m.CAST(expected_arg)), var_entry.value()),
             &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);

  const int kKeysCount = 1000;
  Handle<NumberDictionary> dictionary =
      NumberDictionary::New(isolate, kKeysCount);
  uint32_t keys[kKeysCount];

  DirectHandle<Object> fake_value(Smi::FromInt(42), isolate);
  PropertyDetails fake_details = PropertyDetails::Empty();

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  for (int i = 0; i < kKeysCount; i++) {
    int random_key = rand_gen.NextInt(Smi::kMaxValue);
    keys[i] = static_cast<uint32_t>(random_key);
    if (dictionary->FindEntry(isolate, keys[i]).is_found()) continue;

    dictionary = NumberDictionary::Add(isolate, dictionary, keys[i], fake_value,
                                       fake_details);
  }

  // Now try querying existing keys.
  for (int i = 0; i < kKeysCount; i++) {
    InternalIndex entry = dictionary->FindEntry(isolate, keys[i]);
    CHECK(entry.is_found());

    Handle<Object> key(Smi::FromInt(keys[i]), isolate);
    Handle<Object> expected_entry(Smi::FromInt(entry.as_int()), isolate);
    ft.CheckTrue(dictionary, key, expect_found, expected_entry);
  }

  // Now try querying random keys which do not exist in the dictionary.
  for (int i = 0; i < kKeysCount;) {
    int random_key = rand_gen.NextInt(Smi::kMaxValue);
    InternalIndex entry = dictionary->FindEntry(isolate, random_key);
    if (entry.is_found()) continue;
    i++;

    Handle<Object> key(Smi::FromInt(random_key), isolate);
    ft.CheckTrue(dictionary, key, expect_not_found);
  }
}

TEST(TransitionLookup) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 4;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));

  enum Result { kFound, kNotFound };

  class TempAssembler : public CodeStubAssembler {
   public:
    explicit TempAssembler(compiler::CodeAssemblerState* state)
        : CodeStubAssembler(state) {}

    void Generate() {
      auto transitions = Parameter<TransitionArray>(1);
      auto name = Parameter<Name>(2);
      auto expected_result = Parameter<Smi>(3);
      auto expected_arg = Parameter<Object>(4);

      Label passed(this), failed(this);
      Label if_found(this), if_not_found(this);
      TVARIABLE(IntPtrT, var_transition_index);

      TransitionLookup(name, transitions, &if_found, &var_transition_index,
                       &if_not_found);

      BIND(&if_found);
      GotoIfNot(TaggedEqual(expected_result, SmiConstant(kFound)), &failed);
      Branch(TaggedEqual(expected_arg, SmiTag(var_transition_index.value())),
             &passed, &failed);

      BIND(&if_not_found);
      Branch(TaggedEqual(expected_result, SmiConstant(kNotFound)), &passed,
             &failed);

      BIND(&passed);
      Return(BooleanConstant(true));

      BIND(&failed);
      Return(BooleanConstant(false));
    }
  };
  TempAssembler(asm_tester.state()).Generate();

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);

  const int ATTRS_COUNT = (READ_ONLY | DONT_ENUM | DONT_DELETE) + 1;
  static_assert(ATTRS_COUNT == 8);

  const int kKeysCount = 300;
  Handle<Map> root_map = Map::Create(isolate, 0);
  Handle<Name> keys[kKeysCount];

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  Factory* factory = isolate->factory();
  Handle<FieldType> any = FieldType::Any(isolate);

  for (int i = 0; i < kKeysCount; i++) {
    Handle<Name> name;
    if (i % 30 == 0) {
      name = factory->NewPrivateSymbol();
    } else if (i % 10 == 0) {
      name = factory->NewSymbol();
    } else {
      int random_key = rand_gen.NextInt(Smi::kMaxValue);
      name = CcTest::MakeName("p", random_key);
    }
    keys[i] = name;

    bool is_private = name->IsPrivate();
    PropertyAttributes base_attributes = is_private ? DONT_ENUM : NONE;

    // Ensure that all the combinations of cases are covered:
    // 1) there is a "base" attributes transition
    // 2) there are other non-base attributes transitions
    if ((i & 1) == 0) {
      CHECK(!Map::CopyWithField(isolate, root_map, name, any, base_attributes,
                                PropertyConstness::kMutable,
                                Representation::Tagged(), INSERT_TRANSITION)
                 .is_null());
    }

    if ((i & 2) == 0) {
      for (int j = 0; j < ATTRS_COUNT; j++) {
        auto attributes = PropertyAttributesFromInt(j);
        if (attributes == base_attributes) continue;
        // Don't add private symbols with enumerable attributes.
        if (is_private && ((attributes & DONT_ENUM) == 0)) continue;
        CHECK(!Map::CopyWithField(isolate, root_map, name, any, attributes,
                                  PropertyConstness::kMutable,
                                  Representation::Tagged(), INSERT_TRANSITION)
                   .is_null());
      }
    }
  }

  CHECK(IsTransitionArray(
      root_map->raw_transitions().GetHeapObjectAssumeStrong()));
  Handle<TransitionArray> transitions(
      Cast<TransitionArray>(
          root_map->raw_transitions().GetHeapObjectAssumeStrong()),
      isolate);
  DCHECK(transitions->IsSortedNoDuplicates());

  // Ensure we didn't overflow transition array and therefore all the
  // combinations of cases are covered.
  CHECK(TransitionsAccessor::CanHaveMoreTransitions(isolate, root_map));

  // Now try querying keys.
  bool positive_lookup_tested = false;
  bool negative_lookup_tested = false;
  for (int i = 0; i < kKeysCount; i++) {
    Handle<Name> name = keys[i];

    int transition_number = transitions->SearchNameForTesting(*name);

    if (transition_number != TransitionArray::kNotFound) {
      Handle<Smi> expected_value(
          Smi::FromInt(TransitionArray::ToKeyIndex(transition_number)),
          isolate);
      ft.CheckTrue(transitions, name, expect_found, expected_value);
      positive_lookup_tested = true;
    } else {
      ft.CheckTrue(transitions, name, expect_not_found);
      negative_lookup_tested = true;
    }
  }
  CHECK(positive_lookup_tested);
  CHECK(negative_lookup_tested);
}

namespace {

void AddProperties(Handle<JSObject> object, Handle<Name> names[],
                   size_t count) {
  Isolate* isolate = object->GetIsolate();
  for (size_t i = 0; i < count; i++) {
    DirectHandle<Object> value(Smi::FromInt(static_cast<int>(42 + i)), isolate);
    JSObject::AddProperty(isolate, object, names[i], value, NONE);
  }
}

Handle<AccessorPair> CreateAccessorPair(FunctionTester* ft,
                                        const char* getter_body,
                                        const char* setter_body) {
  Handle<AccessorPair> pair = ft->isolate->factory()->NewAccessorPair();
  if (getter_body) {
    pair->set_getter(*ft->NewFunction(getter_body));
  }
  if (setter_body) {
    pair->set_setter(*ft->NewFunction(setter_body));
  }
  return pair;
}

void AddProperties(Handle<JSObject> object, Handle<Name> names[],
                   size_t names_count, Handle<Object> values[],
                   size_t values_count, int seed = 0) {
  Isolate* isolate = object->GetIsolate();
  for (size_t i = 0; i < names_count; i++) {
    Handle<Object> value = values[(seed + i) % values_count];
    if (IsAccessorPair(*value)) {
      DirectHandle<AccessorPair> pair = Cast<AccessorPair>(value);
      DirectHandle<Object> getter(pair->getter(), isolate);
      DirectHandle<Object> setter(pair->setter(), isolate);
      JSObject::DefineOwnAccessorIgnoreAttributes(object, names[i], getter,
                                                  setter, NONE)
          .Check();
    } else {
      JSObject::AddProperty(isolate, object, names[i], value, NONE);
    }
  }
}

}  // namespace

TEST(TryHasOwnProperty) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kNotFound, kBailout };
  {
    auto object = m.Parameter<HeapObject>(1);
    auto unique_name = m.Parameter<Name>(2);
    TNode<MaybeObject> expected_result = m.UncheckedParameter<MaybeObject>(3);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m), if_bailout(&m);

    TNode<Map> map = m.LoadMap(object);
    TNode<Uint16T> instance_type = m.LoadMapInstanceType(map);

    m.TryHasOwnProperty(object, map, instance_type, unique_name, &if_found,
                        &if_not_found, &if_bailout);

    m.BIND(&if_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&if_bailout);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kBailout))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);
  Handle<Object> expect_bailout(Smi::FromInt(kBailout), isolate);

  Factory* factory = isolate->factory();

  Handle<Name> deleted_property_name =
      factory->InternalizeUtf8String("deleted");

  Handle<Name> names[] = {
      factory->InternalizeUtf8String("a"),
      factory->InternalizeUtf8String("bb"),
      factory->InternalizeUtf8String("ccc"),
      factory->InternalizeUtf8String("dddd"),
      factory->InternalizeUtf8String("eeeee"),
      factory->InternalizeUtf8String(""),
      factory->InternalizeUtf8String("name"),
      factory->NewSymbol(),
      factory->NewPrivateSymbol(),
  };

  std::vector<Handle<JSObject>> objects;

  {
    // Fast object, no inobject properties.
    int inobject_properties = 0;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names));
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, all inobject properties.
    int inobject_properties = arraysize(names) * 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names));
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, half inobject properties.
    int inobject_properties = arraysize(names) / 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names));
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Dictionary mode object.
    Handle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSObject> object = factory->NewJSObject(function);
    AddProperties(object, names, arraysize(names));
    JSObject::NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                                  "test");

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Global object.
    Handle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    JSFunction::EnsureHasInitialMap(function);
    function->initial_map()->set_instance_type(JS_GLOBAL_OBJECT_TYPE);
    function->initial_map()->set_instance_size(JSGlobalObject::kHeaderSize);
    function->initial_map()->SetInObjectUnusedPropertyFields(0);
    function->initial_map()->SetInObjectPropertiesStartInWords(
        function->initial_map()->instance_size_in_words());
    function->initial_map()->set_is_prototype_map(true);
    function->initial_map()->set_is_dictionary_map(true);
    function->initial_map()->set_may_have_interesting_properties(true);
    Handle<JSObject> object = factory->NewJSGlobalObject(function);
    AddProperties(object, names, arraysize(names));

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_GLOBAL_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    for (Handle<JSObject> object : objects) {
      for (size_t name_index = 0; name_index < arraysize(names); name_index++) {
        Handle<Name> name = names[name_index];
        CHECK(JSReceiver::HasProperty(isolate, object, name).FromJust());
        ft.CheckTrue(object, name, expect_found);
      }
    }
  }

  {
    Handle<Name> non_existing_names[] = {
        factory->NewSymbol(),
        factory->InternalizeUtf8String("ne_a"),
        factory->InternalizeUtf8String("ne_bb"),
        factory->NewPrivateSymbol(),
        factory->InternalizeUtf8String("ne_ccc"),
        factory->InternalizeUtf8String("ne_dddd"),
        deleted_property_name,
    };
    for (Handle<JSObject> object : objects) {
      for (size_t key_index = 0; key_index < arraysize(non_existing_names);
           key_index++) {
        Handle<Name> name = non_existing_names[key_index];
        CHECK(!JSReceiver::HasProperty(isolate, object, name).FromJust());
        ft.CheckTrue(object, name, expect_not_found);
      }
    }
  }

  {
    DirectHandle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSProxy> object = factory->NewJSProxy(function, objects[0]);
    CHECK_EQ(JS_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, names[0], expect_bailout);
  }

  {
    Handle<JSObject> object = isolate->global_proxy();
    CHECK_EQ(JS_GLOBAL_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, names[0], expect_bailout);
  }
}

TEST(TryGetOwnProperty) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  Handle<Symbol> not_found_symbol = factory->NewSymbol();
  Handle<Symbol> bailout_symbol = factory->NewSymbol();
  {
    auto object = m.Parameter<JSReceiver>(1);
    auto unique_name = m.Parameter<Name>(2);
    auto context = m.GetJSContextParameter();

    TVariable<Object> var_value(&m);
    Label if_found(&m), if_not_found(&m), if_bailout(&m);

    TNode<Map> map = m.LoadMap(object);
    TNode<Uint16T> instance_type = m.LoadMapInstanceType(map);

    m.TryGetOwnProperty(context, object, object, map, instance_type,
                        unique_name, &if_found, &var_value, &if_not_found,
                        &if_bailout);

    m.BIND(&if_found);
    m.Return(m.UncheckedCast<Object>(var_value.value()));

    m.BIND(&if_not_found);
    m.Return(m.HeapConstantNoHole(not_found_symbol));

    m.BIND(&if_bailout);
    m.Return(m.HeapConstantNoHole(bailout_symbol));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Name> deleted_property_name =
      factory->InternalizeUtf8String("deleted");

  Handle<Name> names[] = {
      factory->InternalizeUtf8String("bb"),
      factory->NewSymbol(),
      factory->InternalizeUtf8String("a"),
      factory->InternalizeUtf8String("ccc"),
      factory->InternalizeUtf8String("esajefe"),
      factory->NewPrivateSymbol(),
      factory->InternalizeUtf8String("eeeee"),
      factory->InternalizeUtf8String("p1"),
      factory->InternalizeUtf8String("acshw23e"),
      factory->InternalizeUtf8String(""),
      factory->InternalizeUtf8String("dddd"),
      factory->NewPrivateSymbol(),
      factory->InternalizeUtf8String("name"),
      factory->InternalizeUtf8String("p2"),
      factory->InternalizeUtf8String("p3"),
      factory->InternalizeUtf8String("p4"),
      factory->NewPrivateSymbol(),
  };
  Handle<Object> values[] = {
      factory->NewFunctionForTesting(factory->empty_string()),
      factory->NewSymbol(),
      factory->InternalizeUtf8String("a"),
      CreateAccessorPair(&ft, "() => 188;", "() => 199;"),
      factory->NewFunctionForTesting(factory->InternalizeUtf8String("bb")),
      factory->InternalizeUtf8String("ccc"),
      CreateAccessorPair(&ft, "() => 88;", nullptr),
      handle(Smi::FromInt(1), isolate),
      factory->InternalizeUtf8String(""),
      CreateAccessorPair(&ft, nullptr, "() => 99;"),
      factory->NewHeapNumber(4.2),
      handle(Smi::FromInt(153), isolate),
      factory->NewJSObject(
          factory->NewFunctionForTesting(factory->empty_string())),
      factory->NewPrivateSymbol(),
  };
  static_assert(arraysize(values) < arraysize(names));

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  std::vector<Handle<JSObject>> objects;

  {
    // Fast object, no inobject properties.
    int inobject_properties = 0;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, all inobject properties.
    int inobject_properties = arraysize(names) * 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, half inobject properties.
    int inobject_properties = arraysize(names) / 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Dictionary mode object.
    Handle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSObject> object = factory->NewJSObject(function);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    JSObject::NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                                  "test");

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Global object.
    Handle<JSGlobalObject> object = isolate->global_object();
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_GLOBAL_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  // TODO(ishell): test proxy and interceptors when they are supported.

  {
    for (Handle<JSObject> object : objects) {
      for (size_t name_index = 0; name_index < arraysize(names); name_index++) {
        Handle<Name> name = names[name_index];
        DirectHandle<Object> expected_value =
            JSReceiver::GetProperty(isolate, object, name).ToHandleChecked();
        DirectHandle<Object> value = ft.Call(object, name).ToHandleChecked();
        CHECK(Object::SameValue(*expected_value, *value));
      }
    }
  }

  {
    Handle<Name> non_existing_names[] = {
        factory->NewSymbol(),
        factory->InternalizeUtf8String("ne_a"),
        factory->InternalizeUtf8String("ne_bb"),
        factory->NewPrivateSymbol(),
        factory->InternalizeUtf8String("ne_ccc"),
        factory->InternalizeUtf8String("ne_dddd"),
        deleted_property_name,
    };
    for (Handle<JSObject> object : objects) {
      for (size_t key_index = 0; key_index < arraysize(non_existing_names);
           key_index++) {
        Handle<Name> name = non_existing_names[key_index];
        DirectHandle<Object> expected_value =
            JSReceiver::GetProperty(isolate, object, name).ToHandleChecked();
        CHECK(IsUndefined(*expected_value, isolate));
        DirectHandle<Object> value = ft.Call(object, name).ToHandleChecked();
        CHECK_EQ(*not_found_symbol, *value);
      }
    }
  }

  {
    DirectHandle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSProxy> object = factory->NewJSProxy(function, objects[0]);
    CHECK_EQ(JS_PROXY_TYPE, object->map()->instance_type());
    DirectHandle<Object> value = ft.Call(object, names[0]).ToHandleChecked();
    // Proxies are not supported yet.
    CHECK_EQ(*bailout_symbol, *value);
  }

  {
    Handle<JSObject> object = isolate->global_proxy();
    CHECK_EQ(JS_GLOBAL_PROXY_TYPE, object->map()->instance_type());
    // Global proxies are not supported yet.
    DirectHandle<Object> value = ft.Call(object, names[0]).ToHandleChecked();
    CHECK_EQ(*bailout_symbol, *value);
  }
}

namespace {

void AddElement(Handle<JSObject> object, uint32_t index,
                DirectHandle<Object> value,
                PropertyAttributes attributes = NONE) {
  JSObject::AddDataElement(object, index, value, attributes);
}

}  // namespace

TEST(TryLookupElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kAbsent, kNotFound, kBailout };
  {
    auto object = m.Parameter<HeapObject>(1);
    TNode<IntPtrT> index = m.SmiUntag(m.Parameter<Smi>(2));
    TNode<MaybeObject> expected_result = m.UncheckedParameter<MaybeObject>(3);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m), if_bailout(&m), if_absent(&m);

    TNode<Map> map = m.LoadMap(object);
    TNode<Uint16T> instance_type = m.LoadMapInstanceType(map);

    m.TryLookupElement(object, map, instance_type, index, &if_found, &if_absent,
                       &if_not_found, &if_bailout);

    m.BIND(&if_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &passed, &failed);

    m.BIND(&if_absent);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kAbsent))),
        &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&if_bailout);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kBailout))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Factory* factory = isolate->factory();
  Handle<Object> smi0(Smi::zero(), isolate);
  Handle<Object> smi1(Smi::FromInt(1), isolate);
  Handle<Object> smi7(Smi::FromInt(7), isolate);
  Handle<Object> smi13(Smi::FromInt(13), isolate);
  Handle<Object> smi42(Smi::FromInt(42), isolate);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_absent(Smi::FromInt(kAbsent), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);
  Handle<Object> expect_bailout(Smi::FromInt(kBailout), isolate);

#define CHECK_FOUND(object, index)                                  \
  CHECK(JSReceiver::HasElement(isolate, object, index).FromJust()); \
  ft.CheckTrue(object, smi##index, expect_found);

#define CHECK_NOT_FOUND(object, index)                               \
  CHECK(!JSReceiver::HasElement(isolate, object, index).FromJust()); \
  ft.CheckTrue(object, smi##index, expect_not_found);

#define CHECK_ABSENT(object, index)                  \
  {                                                  \
    Handle<Smi> smi(Smi::FromInt(index), isolate);   \
    PropertyKey key(isolate, smi);                   \
    LookupIterator it(isolate, object, key);         \
    CHECK(!JSReceiver::HasProperty(&it).FromJust()); \
    ft.CheckTrue(object, smi, expect_absent);        \
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, PACKED_SMI_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 1, smi0);
    CHECK_EQ(PACKED_SMI_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_NOT_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, HOLEY_SMI_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 13, smi0);
    CHECK_EQ(HOLEY_SMI_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_NOT_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, PACKED_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 1, smi0);
    CHECK_EQ(PACKED_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_NOT_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, HOLEY_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 13, smi0);
    CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_NOT_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    v8::Local<v8::ArrayBuffer> buffer =
        v8::ArrayBuffer::New(reinterpret_cast<v8::Isolate*>(isolate), 8);
    Handle<JSTypedArray> object = factory->NewJSTypedArray(
        kExternalInt32Array, v8::Utils::OpenHandle(*buffer), 0, 2);

    CHECK_EQ(INT32_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_ABSENT(object, -10);
    CHECK_ABSENT(object, 13);
    CHECK_ABSENT(object, 42);

    {
      std::shared_ptr<v8::BackingStore> backing_store =
          buffer->GetBackingStore();
      buffer->Detach(v8::Local<v8::Value>()).Check();
    }
    CHECK_ABSENT(object, 0);
    CHECK_ABSENT(object, 1);
    CHECK_ABSENT(object, -10);
    CHECK_ABSENT(object, 13);
    CHECK_ABSENT(object, 42);
  }

  {
    Handle<JSFunction> constructor = isolate->string_function();
    Handle<JSObject> object = factory->NewJSObject(constructor);
    DirectHandle<String> str = factory->InternalizeUtf8String("ab");
    Cast<JSPrimitiveWrapper>(object)->set_value(*str);
    AddElement(object, 13, smi0);
    CHECK_EQ(FAST_STRING_WRAPPER_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSFunction> constructor = isolate->string_function();
    Handle<JSObject> object = factory->NewJSObject(constructor);
    DirectHandle<String> str = factory->InternalizeUtf8String("ab");
    Cast<JSPrimitiveWrapper>(object)->set_value(*str);
    AddElement(object, 13, smi0);
    JSObject::NormalizeElements(object);
    CHECK_EQ(SLOW_STRING_WRAPPER_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  // TODO(ishell): uncomment once NO_ELEMENTS kind is supported.
  //  {
  //    Handle<Map> map = Map::Create(isolate, 0);
  //    map->set_elements_kind(NO_ELEMENTS);
  //    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
  //    CHECK_EQ(NO_ELEMENTS, object->map()->elements_kind());
  //
  //    CHECK_NOT_FOUND(object, 0);
  //    CHECK_NOT_FOUND(object, 1);
  //    CHECK_NOT_FOUND(object, 7);
  //    CHECK_NOT_FOUND(object, 13);
  //    CHECK_NOT_FOUND(object, 42);
  //  }

#undef CHECK_FOUND
#undef CHECK_NOT_FOUND
#undef CHECK_ABSENT

  {
    DirectHandle<JSArray> handler = factory->NewJSArray(0);
    DirectHandle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSProxy> object = factory->NewJSProxy(function, handler);
    CHECK_EQ(JS_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, smi0, expect_bailout);
  }

  {
    Handle<JSObject> object = isolate->global_object();
    CHECK_EQ(JS_GLOBAL_OBJECT_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, smi0, expect_bailout);
  }

  {
    Handle<JSObject> object = isolate->global_proxy();
    CHECK_EQ(JS_GLOBAL_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, smi0, expect_bailout);
  }
}

TEST(AllocateJSObjectFromMap) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();

  const int kNumParams = 3;
  CodeAss
```