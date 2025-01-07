Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality within the V8 JavaScript engine. Key aspects to identify are: what it tests, how it tests, and any related JavaScript concepts.

2. **Initial Scan for Keywords and Structure:**  A quick scan reveals:
    * `#include`:  Indicates dependencies and functionality being used. Notice includes like `code-stub-assembler-inl.h`, `cctest-utils.h`, `function-tester.h`. These strongly suggest this is a *testing* file.
    * `namespace v8::internal::compiler`:  Confirms it's part of V8's internal compiler.
    * `TEST(...)`: This is the primary indicator of a testing framework (likely Google Test, commonly used in Chromium/V8). Each `TEST` block defines an individual test case.
    * Function names like `CallCFunction`, `NumberToString`, `ToUint32`, `IsValidPositiveSmi`, `ConvertAndClampRelativeIndex`, etc. These are the core functionalities being tested.

3. **Analyze Individual Tests:**  Now, focus on each `TEST` block.

    * **`TEST(CallCFunction)`:**
        * Calls a C function (`sum10`).
        * Uses `CodeAssemblerTester` and `CodeStubAssembler`. This points to testing code generation.
        * `m.CallCFunction`:  Explicitly tests the ability to call C functions from generated code.
        * The test sets up arguments (integers) and verifies the return value.

    * **`TEST(CallCFunctionWithCallerSavedRegisters)`:** Similar to the above, but focuses on calling C functions while ensuring caller-saved registers are handled correctly.

    * **`TEST(NumberToString)`:**
        * Uses `m.NumberToString`.
        * Tests a wide range of numeric inputs (integers, decimals, special values like NaN and Infinity).
        * Checks against `factory->NumberToString`, suggesting it's validating the code assembler's `NumberToString` implementation against the standard V8 behavior.

    * **`TEST(ToUint32)`:**
        * Tests `m.ToUint32`.
        * Again, uses various numeric inputs, including edge cases.
        * Checks the output against expected `uint32_t` values, highlighting integer conversion.
        * Also tests non-numeric inputs (undefined, null, booleans, strings).

    * **`TEST(IsValidPositiveSmi)`:**
        * Tests `m.IsValidPositiveSmi`.
        * Checks a range of integer values, focusing on the Small Integer (Smi) representation in V8.

    * **`TEST(ConvertAndClampRelativeIndex)`:**
        * Tests `m.ConvertAndClampRelativeIndex`.
        * Involves calculating relative indices, often used in array manipulation.
        * Uses a table of test cases with different index and length values.

    * **`TEST(FixedArrayAccessSmiIndex)`:**
        * Tests loading elements from a `FixedArray` using a Smi index.

    * **`TEST(LoadHeapNumberValue)`:**
        * Tests loading the value from a `HeapNumber`.

    * **`TEST(LoadInstanceType)`:**
        * Tests loading the instance type of a `HeapObject`.

    * **`TEST(DecodeWordFromWord32)`:**
        * Tests bitfield manipulation using `m.DecodeWordFromWord32`.

    * **`TEST(JSFunction)`:**
        * Shows basic arithmetic operations on Smis within a generated function.

    * **`TEST(ComputeIntegerHash)`:**
        * Tests the `m.ComputeSeededHash` function.

    * **`TEST(ToString)`:**
        * Tests the `m.ToStringImpl` function.
        * Uses various JavaScript types as input and compares the results to their string representations.

    * **`TEST(TryToName)`:**
        * Tests `m.TryToName`, which seems to be related to converting objects to property names (either indices or strings). It handles different object types.

    * **`TEST(NameDictionaryEntryToIndex)` and `TEST(GlobalDictionaryEntryToIndex)`:**
        * Test functions to calculate indices within dictionaries (hash tables used in V8).

    * **`TEST(NameDictionaryLookup)`:**
        * Tests looking up entries in a `NameDictionary`.

4. **Identify Common Themes and Concepts:**

    * **CodeStubAssembler:** This is clearly central. The file tests its various methods for generating machine code.
    * **Machine Types:** The use of `MachineType::IntPtr()` etc., is important for low-level code generation.
    * **Smis (Small Integers):** Many tests specifically involve Smis, a performance optimization in V8.
    * **Heap Objects:**  Testing interaction with various V8 heap objects (FixedArray, HeapNumber, Strings, etc.).
    * **Type Conversions:**  Several tests focus on type conversions (`ToUint32`, `NumberToString`).
    * **Hashing:**  The `ComputeIntegerHash` test is relevant to object property lookups.
    * **Dictionaries:** Testing dictionary operations is crucial for object property management.

5. **Relate to JavaScript (if applicable):**

    * **`NumberToString`:** Directly relates to JavaScript's `toString()` method for numbers. Example: `(42).toString()`.
    * **`ToUint32`:**  Connects to the abstract operation `ToUint32` in the JavaScript specification, often implicitly used in bitwise operations and array index conversions. Example: `0xFFFFFFFF >>> 0`.
    * **`ToString`:**  Relates to the general `toString()` method in JavaScript, applicable to various object types. Example: `[1, 2].toString()`.
    * **`TryToName`:**  Related to how JavaScript converts keys to property names (e.g., accessing `obj[0]` vs. `obj["property"]`).

6. **Infer Code Logic and Examples:**  For tests like `CallCFunction` and `ConvertAndClampRelativeIndex`,  you can create simple input/output examples to illustrate the functionality.

7. **Consider Common Errors:**  Think about common JavaScript mistakes related to the tested functionalities. For example, incorrect assumptions about integer limits in conversions or issues with string conversions.

8. **Synthesize the Summary:** Combine the findings from the individual tests and the overall themes. Emphasize the purpose of the file (testing `CodeStubAssembler`), the types of operations tested, and any connections to JavaScript.

9. **Structure the Output:**  Organize the information clearly using headings and bullet points as in the provided good answer. Address all parts of the initial request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like a file about assembling code."  **Refinement:** "It's *testing* the code assembler."
* **Initial thought:** "Some of these tests are very low-level." **Refinement:** "Yes, because `CodeStubAssembler` operates at a low level, generating machine code."
* **Initial thought:** "How does this relate to JavaScript?" **Refinement:**  Focus on the tests for type conversions and the `ToString` functionality, which have direct JavaScript counterparts. Also, consider how dictionaries are used in JavaScript object implementation.

By following this systematic approach, you can effectively analyze and summarize complex source code.
这个C++源代码文件 `v8/test/cctest/test-code-stub-assembler.cc` 的主要功能是**测试 V8 引擎中 `CodeStubAssembler` 的各种功能和 API**。

**核心功能归纳:**

* **测试代码生成能力:** `CodeStubAssembler` 是 V8 中一个用于生成机器码的工具。这个文件通过编写各种测试用例，来验证 `CodeStubAssembler` 能否正确地生成执行特定任务的代码片段。
* **测试 C++ 函数调用:** 验证 `CodeStubAssembler` 生成的代码能否正确地调用 C++ 函数 (`CallCFunction`, `CallCFunctionWithCallerSavedRegisters`)。
* **测试类型转换操作:**  测试 `CodeStubAssembler` 提供的类型转换方法，例如数字转字符串 (`NumberToString`),  转换为无符号 32 位整数 (`ToUint32`)。
* **测试数值和布尔值操作:** 验证对整数、浮点数和布尔值的操作，例如判断是否为正 Smi (`IsValidPositiveSmi`)。
* **测试数组和对象操作:**  测试访问固定数组元素 (`FixedArrayAccessSmiIndex`)，加载堆数字的值 (`LoadHeapNumberValue`)，加载对象类型 (`LoadInstanceType`)。
* **测试位运算:**  测试从 32 位字中解码特定位域 (`DecodeWordFromWord32`)。
* **测试 JavaScript 函数调用:**  验证生成的代码能否正确地处理 JavaScript 函数的调用和参数传递 (`JSFunction`)。
* **测试哈希计算:**  测试整数的哈希计算 (`ComputeIntegerHash`)。
* **测试对象到字符串的转换:**  验证将不同类型的 JavaScript 对象转换为字符串的功能 (`ToString`).
* **测试将对象尝试转换为名称:** 验证 `TryToName` 方法，该方法尝试将对象转换为属性名称（可以是字符串或数字索引）。
* **测试字典（哈希表）操作:**  测试在 V8 的字典数据结构（如 `NameDictionary`, `GlobalDictionary`）中查找条目的功能 (`NameDictionaryEntryToIndex`, `GlobalDictionaryEntryToIndex`, `NameDictionaryLookup`)。
* **使用 `FunctionTester` 进行测试:**  该文件使用 `FunctionTester` 类来执行生成的代码，并验证其结果是否符合预期。

**关于文件后缀和 JavaScript 关系:**

* **`.tq` 后缀:** 如果文件以 `.tq` 结尾，它才是 V8 Torque 源代码。Torque 是一种 V8 用于定义内置函数和运行时调用的领域特定语言。`test-code-stub-assembler.cc` 是 `.cc` 文件，所以它是 C++ 源代码。
* **JavaScript 关系:** 虽然该文件本身是 C++ 代码，但它测试的 `CodeStubAssembler` 被用于生成执行 JavaScript 代码所需的底层机器码。因此，它的功能与 JavaScript 的执行密切相关。

**JavaScript 举例说明:**

* **`NumberToString` 测试的功能对应于 JavaScript 中的 `(number).toString()` 方法。**
  ```javascript
  console.log((123).toString()); // 输出 "123"
  console.log((3.14).toString()); // 输出 "3.14"
  ```

* **`ToUint32` 测试的功能对应于 JavaScript 中将值转换为无符号 32 位整数的操作，例如位运算中的无符号右移 `>>> 0`。**
  ```javascript
  console.log(-1 >>> 0); // 输出 4294967295
  console.log(3.14 >>> 0); // 输出 3
  ```

* **`ToString` 测试的功能对应于 JavaScript 中各种对象的 `toString()` 方法。**
  ```javascript
  console.log([1, 2].toString());    // 输出 "1,2"
  console.log(undefined.toString()); // 输出 "undefined"
  console.log(null.toString());      // 输出 "null" (注意：直接调用 null.toString() 会报错，这里指在特定上下文中，例如作为对象属性值)
  ```

* **`TryToName` 测试的功能与 JavaScript 中属性访问时的键转换有关。**
  ```javascript
  const obj = { 153: 'value' };
  console.log(obj[153]);    // 访问数字键
  console.log(obj['153']);  // 访问字符串键，会被转换为数字

  const obj2 = { true: 'yes', undefined: 'maybe' };
  console.log(obj2[true]);      // 访问布尔值键，会被转换为字符串 "true"
  console.log(obj2[undefined]); // 访问 undefined 键，会被转换为字符串 "undefined"
  ```

**代码逻辑推理 (假设输入与输出):**

* **`TEST(CallCFunction)`:**
    * **假设输入:** 调用生成的代码。
    * **预期输出:** C++ 函数 `sum10` 被调用，参数为 0 到 9，返回它们的和 45。测试会检查返回的 Smi 值是否为 45。

* **`TEST(ToUint32)`:**
    * **假设输入:**  将 HeapNumber 对象表示的浮点数 `-1.5` 传递给生成的代码。
    * **预期输出:** `ToUint32` 操作会将 `-1.5` 转换为无符号 32 位整数，结果为 `4294967295`。测试会检查返回的 Smi 或 HeapNumber 是否表示这个值。

**用户常见的编程错误 (与测试功能相关):**

* **类型转换错误:**
    * **错误示例 (JavaScript):**
      ```javascript
      const numStr = "abc";
      const num = parseInt(numStr); // num 为 NaN
      console.log(num >>> 0);      // 输出 0，可能不是期望的结果
      ```
      与 `ToUint32` 相关，用户可能没有考虑到非数字字符串转换为数字后的行为。

    * **错误示例 (JavaScript):**
      ```javascript
      const obj = {};
      console.log(obj[undefined]); // 访问 obj["undefined"]，而不是期望的通过变量访问
      ```
      与 `TryToName` 相关，用户可能没有意识到 JavaScript 在属性访问时会将某些非字符串键转换为字符串。

* **数值溢出和范围问题:**
    * **错误示例 (JavaScript):**
      ```javascript
      const largeNumber = 2**32;
      console.log(largeNumber >>> 0); // 输出 0，因为超过了 uint32 的最大值
      ```
      与 `ToUint32` 相关，用户可能没有考虑到数值溢出对无符号整数转换的影响。

**第 1 部分功能归纳:**

这部分代码主要集中在测试 `CodeStubAssembler` 的以下核心功能：

1. **调用 C++ 函数:** 验证其基本的代码生成和函数调用能力。
2. **基本的类型转换:**  测试数字到字符串以及到无符号 32 位整数的转换。
3. **简单的数值和布尔值操作:**  验证对基本数据类型的处理能力。
4. **基础的数组和对象操作:**  测试访问数组元素和加载对象属性。
5. **位运算:** 验证基本的位操作功能。

总而言之，这部分是 `test-code-stub-assembler.cc` 文件中测试 `CodeStubAssembler` 基本功能的起始部分，涵盖了函数调用、基本类型转换和一些基础的数据结构操作。它为后续更复杂的测试用例奠定了基础。

Prompt: 
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
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

  for (size_t i = 0; i < arraysize(non_existing_ke
"""


```