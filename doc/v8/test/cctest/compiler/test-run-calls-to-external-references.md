Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan looking for recognizable keywords and patterns. Things that jump out are:

* `#include`:  Indicates header files, which can give clues about the code's dependencies and purpose. `src/base/memory.h`, `src/codegen/external-reference.h`, `test/cctest/cctest.h`, `test/cctest/compiler/codegen-tester.h`, `test/common/value-helper.h` suggest testing, compiler interaction, and memory management. The `#if V8_ENABLE_WEBASSEMBLY` block points to WebAssembly related functionality.
* `namespace v8 { namespace internal { namespace compiler { ... }}}`: This clearly defines the code's location within the V8 project's structure, specifically in the compiler component.
* `template <typename ...>`:  Heavy use of templates indicates generic programming, making the functions reusable for different data types.
* `TestExternalReference_...`: Function names starting with `Test` strongly suggest this is a test file. The `ExternalReference` part is significant.
* `ExternalReference ref`: This variable appears frequently, confirming the focus on external references.
* `CallCFunction`: This function name is a key indicator of calling external C functions from within the V8 compiler's code.
* `BufferedRawMachineAssemblerTester`:  This class name suggests low-level code generation and testing, likely involving machine code.
* `CHECK_EQ`: This macro is a standard testing assertion, verifying equality.
* `TEST(...) { ... }`:  This macro is part of the `cctest` framework and defines individual test cases.
* Specific function names like `wasm_f32_trunc`, `wasm_int64_to_float64`, `base::bits::CountTrailingZeros`: These are names of specific external functions being tested.

**2. Deeper Dive into Templates:**

The template functions (`TestExternalReference_ConvertOp`, `TestExternalReference_UnOp`, `TestExternalReference_BinOp`, etc.) are the core logic. Analyzing their structure reveals a common pattern:

* They take an `ExternalReference`, a wrapper function (pointer to a function), and a collection of input values.
* They use `BufferedRawMachineAssemblerTester` to create a test environment where they can generate code that calls the external reference.
* They allocate a buffer in memory.
* They write input values into the buffer.
* They generate code to call the external function with the buffer's address as an argument.
* They execute the generated code (`m.Call()`).
* They read the output from the buffer.
* They also call the `wrapper` function directly to get the *expected* output.
* They compare the output from the generated code with the expected output using `CHECK_EQ`.

**3. Understanding `ExternalReference`:**

The frequent use of `ExternalReference` and the way it's used with `CallCFunction` suggests that the code is testing the ability of the V8 compiler to correctly call external C/C++ functions. The `ExternalReference` likely acts as a handle or pointer to these external functions.

**4. Focusing on the Test Cases:**

The `TEST(...)` blocks provide concrete examples of what's being tested. The names of these tests (`RunCallF32Trunc`, `RunCallInt64ToFloat64`, etc.) clearly indicate the specific external functions being targeted. The `ExternalReference::wasm_...` calls confirm that these are WebAssembly-related external functions.

**5. Connecting to JavaScript (If Applicable):**

Since the prompt asks about the relationship to JavaScript, the WebAssembly connection is the key. WebAssembly allows running code written in languages other than JavaScript in the browser. The external references being tested here are likely the implementations of WebAssembly instructions that the V8 engine needs to call. Thinking about common WebAssembly operations like `trunc`, `floor`, type conversions, and arithmetic helps to understand the purpose of these specific tests.

**6. Code Logic and Assumptions:**

The code's logic is essentially about setting up a controlled environment to call external functions and verify their results. The primary assumption is that the `wrapper` functions provide the correct, expected behavior of the external functions. The input and output are determined by the `ValueHelper` class and the specific test case being run.

**7. Common Programming Errors (If Applicable):**

While this specific test code doesn't directly *demonstrate* user programming errors, it *tests* the V8 compiler's ability to handle calls to external functions correctly. Errors that *could* occur if the compiler or the external function implementation were buggy include:

* **Incorrect argument passing:**  Passing the wrong data types or sizes to the external function.
* **Incorrect return value handling:**  Not correctly interpreting the return value from the external function.
* **Memory corruption:**  If the external function writes to memory it shouldn't, or if the buffer setup is incorrect.
* **Type conversion errors:** Incorrectly converting between different data types (as many tests here focus on).

**8. Considering `.tq` Files:**

The prompt mentions `.tq` files. Knowing that Torque is V8's internal domain-specific language for implementing built-in functions, it's important to note that this file is `.cc`, *not* `.tq`. This means it's standard C++ code, not Torque.

**9. Synthesizing the Summary:**

Finally, putting all the pieces together leads to a summary that captures the main purpose of the code: testing the V8 compiler's ability to call external C/C++ functions, specifically focusing on WebAssembly-related functions, by setting up test environments, executing generated code, and verifying the results against known correct implementations.好的，让我们来分析一下 `v8/test/cctest/compiler/test-run-calls-to-external-references.cc` 这个 C++ 源代码文件的功能。

**文件功能归纳：**

这个 C++ 文件是 V8 JavaScript 引擎的测试文件，其主要功能是**测试 V8 编译器正确生成调用外部 C/C++ 函数的代码的能力**。更具体地说，它测试了在编译过程中，当遇到需要调用外部函数时，编译器能否生成正确的机器码，并且这些外部函数能够被正确调用并返回预期结果。

**详细功能拆解：**

1. **测试调用各种类型的外部函数：** 文件中定义了多个测试用例（以 `TEST(...)` 宏开始），每个测试用例针对一个特定的外部函数或一类外部函数。这些外部函数通常与 WebAssembly 相关（通过 `#if V8_ENABLE_WEBASSEMBLY` 可以看出），涵盖了各种操作，例如：
    * 浮点数运算（`f32_trunc`, `f32_floor`, `f64_ceil` 等）
    * 类型转换（`int64_to_float32`, `float32_to_int64` 等）
    * 整数运算（`int64_div`, `uint64_mod` 等）
    * 位操作（`word32_ctz`, `word64_popcnt` 等）
    * 其他数学函数（`float64_pow`）

2. **使用模板化的测试框架：** 文件中定义了一些模板函数（例如 `TestExternalReference_ConvertOp`, `TestExternalReference_UnOp`, `TestExternalReference_BinOp` 等），这些模板函数提供了一种通用的测试框架，可以方便地针对不同类型的外部函数进行测试。这些模板函数的主要逻辑是：
    * 创建一个 `BufferedRawMachineAssemblerTester` 对象，用于生成测试代码。
    * 获取外部函数的 `ExternalReference`。
    * 使用 `CallCFunction` 指令生成调用外部函数的代码。
    * 设置输入参数，调用生成的代码。
    * 将生成的代码的输出与直接调用外部函数的结果进行比较，以验证编译器生成的代码是否正确。

3. **模拟外部函数调用：**  测试框架使用 `ExternalReference` 来代表外部函数的引用。在实际执行测试时，V8 编译器会生成调用这些外部引用的代码。

4. **覆盖不同的调用签名：** 文件中还包含了一系列 `SIGNATURE_TEST` 宏定义的测试用例，这些用例旨在测试 V8 编译器处理不同 C 函数签名（参数类型和数量）的能力。这些测试用例涵盖了只包含整数参数、只包含浮点数参数以及混合参数类型的 C 函数调用。

**关于文件后缀名和 Torque：**

你提供的描述中提到，如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。**这个文件 `test-run-calls-to-external-references.cc` 以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件，而不是 Torque 文件。**

Torque 是 V8 内部使用的一种领域特定语言，用于定义内置函数和运行时库。`.tq` 文件会编译成 C++ 代码。

**与 JavaScript 的关系：**

这个文件直接测试的是 V8 编译器在生成机器码时的行为，特别是如何调用外部函数。  这些外部函数很多都与 WebAssembly 的实现密切相关。当 JavaScript 代码执行涉及到 WebAssembly 模块时，V8 需要调用这些底层的外部函数来执行 WebAssembly 指令。

**JavaScript 例子说明 (与 WebAssembly 相关)：**

假设你在 JavaScript 中使用了一个 WebAssembly 模块，并且该模块中包含一个计算浮点数截断的函数：

```javascript
// 假设已经加载了一个 WebAssembly 模块 'wasmModule'
const instance = wasmModule.instance;
const truncateFunction = instance.exports.f32_trunc; // 假设导出了名为 f32_trunc 的函数

let result = truncateFunction(3.14);
console.log(result); // 输出 3
```

在这个例子中，当 JavaScript 调用 `truncateFunction(3.14)` 时，V8 引擎会执行以下步骤：

1. 查找 `truncateFunction` 对应的 WebAssembly 函数实现。
2. 确定该函数需要调用底层的 C++ 实现（这可能就是 `wasm::f32_trunc_wrapper` 对应的 C++ 函数）。
3. V8 编译器需要生成能够正确调用这个 C++ 函数的机器码。

`test-run-calls-to-external-references.cc` 这个测试文件就是用来确保 V8 编译器在生成这类调用外部函数的机器码时不出错。

**代码逻辑推理 (假设输入与输出)：**

以 `TEST(RunCallF32Trunc)` 这个测试用例为例：

* **假设输入:** `ValueHelper::float32_vector()` 返回一个包含多个 `float` 值的向量，例如 `[3.14, -2.7, 0.0, ...]`.
* **外部函数:** `wasm::f32_trunc_wrapper` 是一个 C++ 函数，它接收一个 `float` 值的地址，并将其截断为整数部分（向零取整），结果写回该地址。
* **测试逻辑:**  对于输入向量中的每个 `float` 值，测试代码会：
    1. 将该值写入缓冲区。
    2. 调用 V8 编译器生成的代码，该代码会调用 `wasm::f32_trunc_wrapper`。
    3. 读取缓冲区中的结果。
    4. 直接调用 `wasm::f32_trunc_wrapper` 计算期望的输出。
    5. 使用 `CHECK_EQ` 宏比较实际输出和期望输出。

* **假设输入示例:** `input = 3.14f`
* **预期输出:** `expected_output = 3.0f` (因为截断操作会移除小数部分)

**用户常见的编程错误举例 (虽然此文件不直接涉及用户代码)：**

虽然这个文件是测试编译器功能的，但它所测试的场景与用户在使用 WebAssembly 时可能遇到的问题相关。 例如，用户在编写 WebAssembly 模块时，可能会遇到以下错误，这些错误可能导致 V8 调用外部函数时产生非预期结果：

1. **类型不匹配:** WebAssembly 函数的签名与 JavaScript 调用时传递的参数类型不匹配。例如，WebAssembly 函数期望接收一个 `i32` (32位整数)，但 JavaScript 传递了一个浮点数。
2. **内存访问错误:** WebAssembly 代码尝试访问超出其线性内存范围的地址。这可能导致 V8 尝试调用外部函数时传递错误的内存地址。
3. **未定义的行为:** WebAssembly 代码中存在未定义的行为（例如，除零操作），这可能导致 V8 调用的外部函数产生不可预测的结果。

**总结：**

`v8/test/cctest/compiler/test-run-calls-to-external-references.cc` 是一个关键的测试文件，用于验证 V8 编译器在处理外部 C/C++ 函数调用时的正确性。它通过一系列精心设计的测试用例，覆盖了不同类型的外部函数和调用签名，特别是与 WebAssembly 相关的函数。这个文件的存在有助于确保 V8 能够正确高效地执行涉及外部函数调用的代码，包括 WebAssembly 模块。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-calls-to-external-references.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-calls-to-external-references.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

#include "src/base/memory.h"
#include "src/codegen/external-reference.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/value-helper.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-external-refs.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

template <typename InType, typename OutType, typename Iterable>
void TestExternalReference_ConvertOp(ExternalReference ref,
                                     void (*wrapper)(Address),
                                     Iterable inputs) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  constexpr size_t kBufferSize = std::max(sizeof(InType), sizeof(OutType));
  uint8_t buffer[kBufferSize] = {0};
  Address buffer_addr = reinterpret_cast<Address>(buffer);

  Node* function = m.ExternalConstant(ref);
  m.CallCFunction(
      function, MachineType::Pointer(),
      std::make_pair(MachineType::Pointer(), m.PointerConstant(buffer)));
  m.Return(m.Int32Constant(4356));

  for (InType input : inputs) {
    WriteUnalignedValue<InType>(buffer_addr, input);

    CHECK_EQ(4356, m.Call());
    OutType output = ReadUnalignedValue<OutType>(buffer_addr);

    WriteUnalignedValue<InType>(buffer_addr, input);
    wrapper(buffer_addr);
    OutType expected_output = ReadUnalignedValue<OutType>(buffer_addr);

    CHECK_EQ(expected_output, output);
  }
}

template <typename InType, typename OutType, typename Iterable>
void TestExternalReference_ConvertOpWithOutputAndReturn(
    ExternalReference ref, int32_t (*wrapper)(Address), Iterable inputs) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  constexpr size_t kBufferSize = std::max(sizeof(InType), sizeof(OutType));
  uint8_t buffer[kBufferSize] = {0};
  Address buffer_addr = reinterpret_cast<Address>(buffer);

  Node* function = m.ExternalConstant(ref);
  m.Return(m.CallCFunction(
      function, MachineType::Int32(),
      std::make_pair(MachineType::Pointer(), m.PointerConstant(buffer))));

  for (InType input : inputs) {
    WriteUnalignedValue<InType>(buffer_addr, input);

    int32_t ret = m.Call();
    OutType output = ReadUnalignedValue<OutType>(buffer_addr);

    WriteUnalignedValue<InType>(buffer_addr, input);
    int32_t expected_ret = wrapper(buffer_addr);
    OutType expected_output = ReadUnalignedValue<OutType>(buffer_addr);

    CHECK_EQ(expected_ret, ret);
    CHECK_EQ(expected_output, output);
  }
}

template <typename InType, typename OutType, typename Iterable>
void TestExternalReference_ConvertOpWithReturn(ExternalReference ref,
                                               OutType (*wrapper)(InType),
                                               Iterable inputs) {
  static_assert(std::is_same_v<uint32_t, InType> ||
                std::is_same_v<uint64_t, InType>);
  MachineType input_type = std::is_same_v<uint32_t, InType>
                               ? MachineType::Uint32()
                               : MachineType::Uint64();
  BufferedRawMachineAssemblerTester<uint32_t> m(input_type);
  Node* function = m.ExternalConstant(ref);
  m.Return(m.CallCFunction(function, MachineType::Int32(),
                           {{input_type, m.Parameter(0)}}));

  for (InType input : inputs) {
    OutType ret = m.Call(input);
    OutType expected_ret = wrapper(input);
    CHECK_EQ(expected_ret, ret);
  }
}

template <typename Type>
bool isnan(Type value) {
  return false;
}
template <>
bool isnan<float>(float value) {
  return std::isnan(value);
}
template <>
bool isnan<double>(double value) {
  return std::isnan(value);
}

template <typename Type, typename Iterable>
void TestExternalReference_UnOp(ExternalReference ref, void (*wrapper)(Address),
                                Iterable inputs) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  constexpr size_t kBufferSize = sizeof(Type);
  uint8_t buffer[kBufferSize] = {0};
  Address buffer_addr = reinterpret_cast<Address>(buffer);

  Node* function = m.ExternalConstant(ref);
  m.CallCFunction(
      function, MachineType::Int32(),
      std::make_pair(MachineType::Pointer(), m.PointerConstant(buffer)));
  m.Return(m.Int32Constant(4356));

  for (Type input : inputs) {
    WriteUnalignedValue<Type>(buffer_addr, input);
    CHECK_EQ(4356, m.Call());
    Type output = ReadUnalignedValue<Type>(buffer_addr);

    WriteUnalignedValue<Type>(buffer_addr, input);
    wrapper(buffer_addr);
    Type expected_output = ReadUnalignedValue<Type>(buffer_addr);

    if (isnan(expected_output) && isnan(output)) continue;
    CHECK_EQ(expected_output, output);
  }
}

template <typename Type, typename Iterable>
void TestExternalReference_BinOp(ExternalReference ref,
                                 void (*wrapper)(Address), Iterable inputs) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  constexpr size_t kBufferSize = 2 * sizeof(Type);
  uint8_t buffer[kBufferSize] = {0};
  Address buffer_addr = reinterpret_cast<Address>(buffer);

  Node* function = m.ExternalConstant(ref);
  m.CallCFunction(
      function, MachineType::Int32(),
      std::make_pair(MachineType::Pointer(), m.PointerConstant(buffer)));
  m.Return(m.Int32Constant(4356));

  for (Type input1 : inputs) {
    for (Type input2 : inputs) {
      WriteUnalignedValue<Type>(buffer_addr, input1);
      WriteUnalignedValue<Type>(buffer_addr + sizeof(Type), input2);
      CHECK_EQ(4356, m.Call());
      Type output = ReadUnalignedValue<Type>(buffer_addr);

      WriteUnalignedValue<Type>(buffer_addr, input1);
      WriteUnalignedValue<Type>(buffer_addr + sizeof(Type), input2);
      wrapper(buffer_addr);
      Type expected_output = ReadUnalignedValue<Type>(buffer_addr);

      if (isnan(expected_output) && isnan(output)) continue;
      CHECK_EQ(expected_output, output);
    }
  }
}

template <typename Type, typename Iterable>
void TestExternalReference_BinOpWithReturn(ExternalReference ref,
                                           int32_t (*wrapper)(Address),
                                           Iterable inputs) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  constexpr size_t kBufferSize = 2 * sizeof(Type);
  uint8_t buffer[kBufferSize] = {0};
  Address buffer_addr = reinterpret_cast<Address>(buffer);

  Node* function = m.ExternalConstant(ref);
  m.Return(m.CallCFunction(
      function, MachineType::Int32(),
      std::make_pair(MachineType::Pointer(), m.PointerConstant(buffer))));

  for (Type input1 : inputs) {
    for (Type input2 : inputs) {
      WriteUnalignedValue<Type>(buffer_addr, input1);
      WriteUnalignedValue<Type>(buffer_addr + sizeof(Type), input2);
      int32_t ret = m.Call();
      Type output = ReadUnalignedValue<Type>(buffer_addr);

      WriteUnalignedValue<Type>(buffer_addr, input1);
      WriteUnalignedValue<Type>(buffer_addr + sizeof(Type), input2);
      int32_t expected_ret = wrapper(buffer_addr);
      Type expected_output = ReadUnalignedValue<Type>(buffer_addr);

      CHECK_EQ(expected_ret, ret);
      if (isnan(expected_output) && isnan(output)) continue;
      CHECK_EQ(expected_output, output);
    }
  }
}

#if V8_ENABLE_WEBASSEMBLY
TEST(RunCallF32Trunc) {
  ExternalReference ref = ExternalReference::wasm_f32_trunc();
  TestExternalReference_UnOp<float>(ref, wasm::f32_trunc_wrapper,
                                    ValueHelper::float32_vector());
}

TEST(RunCallF32Floor) {
  ExternalReference ref = ExternalReference::wasm_f32_floor();
  TestExternalReference_UnOp<float>(ref, wasm::f32_floor_wrapper,
                                    ValueHelper::float32_vector());
}

TEST(RunCallF32Ceil) {
  ExternalReference ref = ExternalReference::wasm_f32_ceil();
  TestExternalReference_UnOp<float>(ref, wasm::f32_ceil_wrapper,
                                    ValueHelper::float32_vector());
}

TEST(RunCallF32RoundTiesEven) {
  ExternalReference ref = ExternalReference::wasm_f32_nearest_int();
  TestExternalReference_UnOp<float>(ref, wasm::f32_nearest_int_wrapper,
                                    ValueHelper::float32_vector());
}

TEST(RunCallF64Trunc) {
  ExternalReference ref = ExternalReference::wasm_f64_trunc();
  TestExternalReference_UnOp<double>(ref, wasm::f64_trunc_wrapper,
                                     ValueHelper::float64_vector());
}

TEST(RunCallF64Floor) {
  ExternalReference ref = ExternalReference::wasm_f64_floor();
  TestExternalReference_UnOp<double>(ref, wasm::f64_floor_wrapper,
                                     ValueHelper::float64_vector());
}

TEST(RunCallF64Ceil) {
  ExternalReference ref = ExternalReference::wasm_f64_ceil();
  TestExternalReference_UnOp<double>(ref, wasm::f64_ceil_wrapper,
                                     ValueHelper::float64_vector());
}

TEST(RunCallF64RoundTiesEven) {
  ExternalReference ref = ExternalReference::wasm_f64_nearest_int();
  TestExternalReference_UnOp<double>(ref, wasm::f64_nearest_int_wrapper,
                                     ValueHelper::float64_vector());
}

TEST(RunCallInt64ToFloat32) {
  ExternalReference ref = ExternalReference::wasm_int64_to_float32();
  TestExternalReference_ConvertOp<int64_t, float>(
      ref, wasm::int64_to_float32_wrapper, ValueHelper::int64_vector());
}

TEST(RunCallUint64ToFloat32) {
  ExternalReference ref = ExternalReference::wasm_uint64_to_float32();
  TestExternalReference_ConvertOp<uint64_t, float>(
      ref, wasm::uint64_to_float32_wrapper, ValueHelper::uint64_vector());
}

TEST(RunCallInt64ToFloat64) {
  ExternalReference ref = ExternalReference::wasm_int64_to_float64();
  TestExternalReference_ConvertOp<int64_t, double>(
      ref, wasm::int64_to_float64_wrapper, ValueHelper::int64_vector());
}

TEST(RunCallUint64ToFloat64) {
  ExternalReference ref = ExternalReference::wasm_uint64_to_float64();
  TestExternalReference_ConvertOp<uint64_t, double>(
      ref, wasm::uint64_to_float64_wrapper, ValueHelper::uint64_vector());
}

TEST(RunCallFloat32ToInt64) {
  ExternalReference ref = ExternalReference::wasm_float32_to_int64();
  TestExternalReference_ConvertOpWithOutputAndReturn<float, int64_t>(
      ref, wasm::float32_to_int64_wrapper, ValueHelper::float32_vector());
}

TEST(RunCallFloat32ToUint64) {
  ExternalReference ref = ExternalReference::wasm_float32_to_uint64();
  TestExternalReference_ConvertOpWithOutputAndReturn<float, uint64_t>(
      ref, wasm::float32_to_uint64_wrapper, ValueHelper::float32_vector());
}

TEST(RunCallFloat64ToInt64) {
  ExternalReference ref = ExternalReference::wasm_float64_to_int64();
  TestExternalReference_ConvertOpWithOutputAndReturn<double, int64_t>(
      ref, wasm::float64_to_int64_wrapper, ValueHelper::float64_vector());
}

TEST(RunCallFloat64ToUint64) {
  ExternalReference ref = ExternalReference::wasm_float64_to_uint64();
  TestExternalReference_ConvertOpWithOutputAndReturn<double, uint64_t>(
      ref, wasm::float64_to_uint64_wrapper, ValueHelper::float64_vector());
}

TEST(RunCallInt64Div) {
  ExternalReference ref = ExternalReference::wasm_int64_div();
  TestExternalReference_BinOpWithReturn<int64_t>(ref, wasm::int64_div_wrapper,
                                                 ValueHelper::int64_vector());
}

TEST(RunCallInt64Mod) {
  ExternalReference ref = ExternalReference::wasm_int64_mod();
  TestExternalReference_BinOpWithReturn<int64_t>(ref, wasm::int64_mod_wrapper,
                                                 ValueHelper::int64_vector());
}

TEST(RunCallUint64Div) {
  ExternalReference ref = ExternalReference::wasm_uint64_div();
  TestExternalReference_BinOpWithReturn<uint64_t>(ref, wasm::uint64_div_wrapper,
                                                  ValueHelper::uint64_vector());
}

TEST(RunCallUint64Mod) {
  ExternalReference ref = ExternalReference::wasm_uint64_mod();
  TestExternalReference_BinOpWithReturn<uint64_t>(ref, wasm::uint64_mod_wrapper,
                                                  ValueHelper::uint64_vector());
}

TEST(RunCallWord32Ctz) {
  ExternalReference ref = ExternalReference::wasm_word32_ctz();
  TestExternalReference_ConvertOpWithReturn<uint32_t, uint32_t>(
      ref, base::bits::CountTrailingZeros, ValueHelper::int32_vector());
}

TEST(RunCallWord64Ctz) {
  // Word64 operations are not supported on 32 bit.
  if (kSystemPointerSize == 4) return;
  ExternalReference ref = ExternalReference::wasm_word64_ctz();
  TestExternalReference_ConvertOpWithReturn<uint64_t, uint32_t>(
      ref, base::bits::CountTrailingZeros, ValueHelper::int64_vector());
}

TEST(RunCallWord32Popcnt) {
  ExternalReference ref = ExternalReference::wasm_word32_popcnt();
  TestExternalReference_ConvertOpWithReturn<uint32_t, uint32_t>(
      ref, base::bits::CountPopulation, ValueHelper::int32_vector());
}

TEST(RunCallWord64Popcnt) {
  // Word64 operations are not supported on 32 bit.
  if (kSystemPointerSize == 4) return;
  ExternalReference ref = ExternalReference::wasm_word64_popcnt();
  TestExternalReference_ConvertOpWithReturn<uint64_t, uint32_t>(
      ref, base::bits::CountPopulation, ValueHelper::int64_vector());
}

TEST(RunCallFloat64Pow) {
  ExternalReference ref = ExternalReference::wasm_float64_pow();
  TestExternalReference_BinOp<double>(ref, wasm::float64_pow_wrapper,
                                      ValueHelper::float64_vector());
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename T>
MachineType MachineTypeForCType() {
  return MachineType::AnyTagged();
}

template <>
MachineType MachineTypeForCType<int64_t>() {
  return MachineType::Int64();
}

template <>
MachineType MachineTypeForCType<int32_t>() {
  return MachineType::Int32();
}

template <>
MachineType MachineTypeForCType<double>() {
  return MachineType::Float64();
}

#define SIGNATURE_TYPES(TYPE, IDX, VALUE) MachineTypeForCType<TYPE>()

#define PARAM_PAIRS(TYPE, IDX, VALUE) \
  std::make_pair(MachineTypeForCType<TYPE>(), m.Parameter(IDX))

#define CALL_ARGS(TYPE, IDX, VALUE) static_cast<TYPE>(VALUE)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
union Int64OrDoubleUnion {
  int64_t int64_t_value;
  double double_value;
};

#define CHECK_ARG_I(TYPE, IDX, VALUE) \
  (result = result && (arg##IDX.TYPE##_value == VALUE))

#define ReturnType v8::AnyCType
MachineType machine_type = MachineType::Int64();

#define CHECK_RESULT(CALL, EXPECT) \
  v8::AnyCType ret = CALL;         \
  CHECK_EQ(ret.int64_value, EXPECT);

#define IF_SIMULATOR_ADD_SIGNATURE                                     \
  EncodedCSignature sig = m.call_descriptor()->ToEncodedCSignature();  \
  m.main_isolate()->simulator_data()->AddSignatureForTargetForTesting( \
      func_address, sig);
#else  // def V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
#define IF_SIMULATOR_ADD_SIGNATURE

#ifdef V8_TARGET_ARCH_64_BIT
#define ReturnType int64_t
MachineType machine_type = MachineType::Int64();
#else  // V8_TARGET_ARCH_64_BIT
#define ReturnType int32_t
MachineType machine_type = MachineType::Int32();
#endif  // V8_TARGET_ARCH_64_BIT

#define CHECK_ARG_I(TYPE, IDX, VALUE) (result = result && (arg##IDX == VALUE))

#define CHECK_RESULT(CALL, EXPECT) \
  int64_t ret = CALL;              \
  CHECK_EQ(ret, EXPECT);

#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

#define SIGNATURE_TEST(NAME, SIGNATURE, FUNC)                                  \
  TEST(NAME) {                                                                 \
    RawMachineAssemblerTester<ReturnType> m(SIGNATURE(SIGNATURE_TYPES));       \
                                                                               \
    Address func_address = FUNCTION_ADDR(&FUNC);                               \
    ExternalReference::Type func_type = ExternalReference::FAST_C_CALL;        \
    ApiFunction func(func_address);                                            \
    ExternalReference ref = ExternalReference::Create(&func, func_type);       \
                                                                               \
    IF_SIMULATOR_ADD_SIGNATURE                                                 \
                                                                               \
    Node* function = m.ExternalConstant(ref);                                  \
    m.Return(m.CallCFunction(function, machine_type, SIGNATURE(PARAM_PAIRS))); \
                                                                               \
    CHECK_RESULT(m.Call(SIGNATURE(CALL_ARGS)), 42);                            \
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
#define SIGNATURE_ONLY_INT(V)                                                 \
  V(int64_t, 0, 0), V(int64_t, 1, 1), V(int64_t, 2, 2), V(int64_t, 3, 3),     \
      V(int64_t, 4, 4), V(int64_t, 5, 5), V(int64_t, 6, 6), V(int64_t, 7, 7), \
      V(int64_t, 8, 8), V(int64_t, 9, 9)

Int64OrDoubleUnion func_only_int(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9) {
#elif defined(V8_TARGET_ARCH_64_BIT)
#define SIGNATURE_ONLY_INT(V)                                                 \
  V(int64_t, 0, 0), V(int64_t, 1, 1), V(int64_t, 2, 2), V(int64_t, 3, 3),     \
      V(int64_t, 4, 4), V(int64_t, 5, 5), V(int64_t, 6, 6), V(int64_t, 7, 7), \
      V(int64_t, 8, 8), V(int64_t, 9, 9)

ReturnType func_only_int(int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3,
                         int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg7,
                         int64_t arg8, int64_t arg9) {
#else  // defined(V8_TARGET_ARCH_64_BIT)
#define SIGNATURE_ONLY_INT(V)                                                 \
  V(int32_t, 0, 0), V(int32_t, 1, 1), V(int32_t, 2, 2), V(int32_t, 3, 3),     \
      V(int32_t, 4, 4), V(int32_t, 5, 5), V(int32_t, 6, 6), V(int32_t, 7, 7), \
      V(int32_t, 8, 8), V(int32_t, 9, 9)

ReturnType func_only_int(int32_t arg0, int32_t arg1, int32_t arg2, int32_t arg3,
                         int32_t arg4, int32_t arg5, int32_t arg6, int32_t arg7,
                         int32_t arg8, int32_t arg9) {
#endif
  bool result = true;
  SIGNATURE_ONLY_INT(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithSignatureOnlyInt, SIGNATURE_ONLY_INT, func_only_int)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
#define SIGNATURE_ONLY_INT_20(V)                                              \
  V(int64_t, 0, 0), V(int64_t, 1, 1), V(int64_t, 2, 2), V(int64_t, 3, 3),     \
      V(int64_t, 4, 4), V(int64_t, 5, 5), V(int64_t, 6, 6), V(int64_t, 7, 7), \
      V(int64_t, 8, 8), V(int64_t, 9, 9), V(int64_t, 10, 10),                 \
      V(int64_t, 11, 11), V(int64_t, 12, 12), V(int64_t, 13, 13),             \
      V(int64_t, 14, 14), V(int64_t, 15, 15), V(int64_t, 16, 16),             \
      V(int64_t, 17, 17), V(int64_t, 18, 18), V(int64_t, 19, 19)

Int64OrDoubleUnion func_only_int_20(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9, Int64OrDoubleUnion arg10, Int64OrDoubleUnion arg11,
    Int64OrDoubleUnion arg12, Int64OrDoubleUnion arg13,
    Int64OrDoubleUnion arg14, Int64OrDoubleUnion arg15,
    Int64OrDoubleUnion arg16, Int64OrDoubleUnion arg17,
    Int64OrDoubleUnion arg18, Int64OrDoubleUnion arg19) {
#elif defined(V8_TARGET_ARCH_64_BIT)
#define SIGNATURE_ONLY_INT_20(V)                                              \
  V(int64_t, 0, 0), V(int64_t, 1, 1), V(int64_t, 2, 2), V(int64_t, 3, 3),     \
      V(int64_t, 4, 4), V(int64_t, 5, 5), V(int64_t, 6, 6), V(int64_t, 7, 7), \
      V(int64_t, 8, 8), V(int64_t, 9, 9), V(int64_t, 10, 10),                 \
      V(int64_t, 11, 11), V(int64_t, 12, 12), V(int64_t, 13, 13),             \
      V(int64_t, 14, 14), V(int64_t, 15, 15), V(int64_t, 16, 16),             \
      V(int64_t, 17, 17), V(int64_t, 18, 18), V(int64_t, 19, 19)

ReturnType func_only_int_20(int64_t arg0, int64_t arg1, int64_t arg2,
                            int64_t arg3, int64_t arg4, int64_t arg5,
                            int64_t arg6, int64_t arg7, int64_t arg8,
                            int64_t arg9, int64_t arg10, int64_t arg11,
                            int64_t arg12, int64_t arg13, int64_t arg14,
                            int64_t arg15, int64_t arg16, int64_t arg17,
                            int64_t arg18, int64_t arg19) {
#else  // defined(V8_TARGET_ARCH_64_BIT)
#define SIGNATURE_ONLY_INT_20(V)                                              \
  V(int32_t, 0, 0), V(int32_t, 1, 1), V(int32_t, 2, 2), V(int32_t, 3, 3),     \
      V(int32_t, 4, 4), V(int32_t, 5, 5), V(int32_t, 6, 6), V(int32_t, 7, 7), \
      V(int32_t, 8, 8), V(int32_t, 9, 9), V(int32_t, 10, 10),                 \
      V(int32_t, 11, 11), V(int32_t, 12, 12), V(int32_t, 13, 13),             \
      V(int32_t, 14, 14), V(int32_t, 15, 15), V(int32_t, 16, 16),             \
      V(int32_t, 17, 17), V(int32_t, 18, 18), V(int32_t, 19, 19)

ReturnType func_only_int_20(int32_t arg0, int32_t arg1, int32_t arg2,
                            int32_t arg3, int32_t arg4, int32_t arg5,
                            int32_t arg6, int32_t arg7, int32_t arg8,
                            int32_t arg9, int32_t arg10, int32_t arg11,
                            int32_t arg12, int32_t arg13, int32_t arg14,
                            int32_t arg15, int32_t arg16, int32_t arg17,
                            int32_t arg18, int32_t arg19) {
#endif
  bool result = true;
  SIGNATURE_ONLY_INT_20(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithSignatureOnlyInt20, SIGNATURE_ONLY_INT_20,
               func_only_int_20)

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

#define MIXED_SIGNATURE_SIMPLE(V) \
  V(int64_t, 0, 0), V(double, 1, 1.5), V(int64_t, 2, 2)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
Int64OrDoubleUnion test_api_func_simple(Int64OrDoubleUnion arg0,
                                        Int64OrDoubleUnion arg1,
                                        Int64OrDoubleUnion arg2) {
#else
ReturnType test_api_func_simple(int64_t arg0, double arg1, int64_t arg2) {
#endif
  bool result = true;
  MIXED_SIGNATURE_SIMPLE(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithMixedSignatureSimple, MIXED_SIGNATURE_SIMPLE,
               test_api_func_simple)

#define MIXED_SIGNATURE(V)                                                  \
  V(int64_t, 0, 0), V(double, 1, 1.5), V(int64_t, 2, 2), V(double, 3, 3.5), \
      V(int64_t, 4, 4), V(double, 5, 5.5), V(int64_t, 6, 6),                \
      V(double, 7, 7.5), V(int64_t, 8, 8), V(double, 9, 9.5),               \
      V(int64_t, 10, 10)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
Int64OrDoubleUnion test_api_func(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9, Int64OrDoubleUnion arg10) {
#else
ReturnType test_api_func(int64_t arg0, double arg1, int64_t arg2, double arg3,
                         int64_t arg4, double arg5, int64_t arg6, double arg7,
                         int64_t arg8, double arg9, int64_t arg10) {
#endif
  bool result = true;
  MIXED_SIGNATURE(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithMixedSignature, MIXED_SIGNATURE, test_api_func)

#define MIXED_SIGNATURE_DOUBLE_INT(V)                                         \
  V(double, 0, 0.5), V(double, 1, 1.5), V(double, 2, 2.5), V(double, 3, 3.5), \
      V(double, 4, 4.5), V(double, 5, 5.5), V(double, 6, 6.5),                \
      V(double, 7, 7.5), V(double, 8, 8.5), V(double, 9, 9.5),                \
      V(int64_t, 10, 10), V(int64_t, 11, 11), V(int64_t, 12, 12),             \
      V(int64_t, 13, 13), V(int64_t, 14, 14), V(int64_t, 15, 15),             \
      V(int64_t, 16, 16), V(int64_t, 17, 17), V(int64_t, 18, 18),             \
      V(int64_t, 19, 19)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
Int64OrDoubleUnion func_mixed_double_int(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9, Int64OrDoubleUnion arg10, Int64OrDoubleUnion arg11,
    Int64OrDoubleUnion arg12, Int64OrDoubleUnion arg13,
    Int64OrDoubleUnion arg14, Int64OrDoubleUnion arg15,
    Int64OrDoubleUnion arg16, Int64OrDoubleUnion arg17,
    Int64OrDoubleUnion arg18, Int64OrDoubleUnion arg19) {
#else
ReturnType func_mixed_double_int(double arg0, double arg1, double arg2,
                                 double arg3, double arg4, double arg5,
                                 double arg6, double arg7, double arg8,
                                 double arg9, int64_t arg10, int64_t arg11,
                                 int64_t arg12, int64_t arg13, int64_t arg14,
                                 int64_t arg15, int64_t arg16, int64_t arg17,
                                 int64_t arg18, int64_t arg19) {
#endif
  bool result = true;
  MIXED_SIGNATURE_DOUBLE_INT(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithMixedSignatureDoubleInt, MIXED_SIGNATURE_DOUBLE_INT,
               func_mixed_double_int)

#define MIXED_SIGNATURE_DOUBLE_INT_ALT(V)                                     \
  V(double, 0, 0.5)                                                           \
  , V(int64_t, 1, 1), V(double, 2, 2.5), V(int64_t, 3, 3), V(double, 4, 4.5), \
      V(int64_t, 5, 5), V(double, 6, 6.5), V(int64_t, 7, 7),                  \
      V(double, 8, 8.5), V(int64_t, 9, 9), V(double, 10, 10.5),               \
      V(int64_t, 11, 11), V(double, 12, 12.5), V(int64_t, 13, 13),            \
      V(double, 14, 14.5), V(int64_t, 15, 15), V(double, 16, 16.5),           \
      V(int64_t, 17, 17), V(double, 18, 18.5), V(int64_t, 19, 19)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
Int64OrDoubleUnion func_mixed_double_int_alt(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9, Int64OrDoubleUnion arg10, Int64OrDoubleUnion arg11,
    Int64OrDoubleUnion arg12, Int64OrDoubleUnion arg13,
    Int64OrDoubleUnion arg14, Int64OrDoubleUnion arg15,
    Int64OrDoubleUnion arg16, Int64OrDoubleUnion arg17,
    Int64OrDoubleUnion arg18, Int64OrDoubleUnion arg19) {
#else
ReturnType func_mixed_double_int_alt(double arg0, int64_t arg1, double arg2,
                                     int64_t arg3, double arg4, int64_t arg5,
                                     double arg6, int64_t arg7, double arg8,
                                     int64_t arg9, double arg10, int64_t arg11,
                                     double arg12, int64_t arg13, double arg14,
                                     int64_t arg15, double arg16, int64_t arg17,
                                     double arg18, int64_t arg19) {
#endif
  bool result = true;
  MIXED_SIGNATURE_DOUBLE_INT_ALT(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithMixedSignatureDoubleIntAlt,
               MIXED_SIGNATURE_DOUBLE_INT_ALT, func_mixed_double_int_alt)

#define MIXED_SIGNATURE_INT_DOUBLE(V)                                         \
  V(int64_t, 0, 0), V(int64_t, 1, 1), V(int64_t, 2, 2), V(int64_t, 3, 3),     \
      V(int64_t, 4, 4), V(int64_t, 5, 5), V(int64_t, 6, 6), V(int64_t, 7, 7), \
      V(int64_t, 8, 8), V(int64_t, 9, 9), V(double, 10, 10.5),                \
      V(double, 11, 11.5), V(double, 12, 12.5), V(double, 13, 13.5),          \
      V(double, 14, 14.5), V(double, 15, 15.5), V(double, 16, 16.5),          \
      V(double, 17, 17.5), V(double, 18, 18.5), V(double, 19, 19.5)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
Int64OrDoubleUnion func_mixed_int_double(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9, Int64OrDoubleUnion arg10, Int64OrDoubleUnion arg11,
    Int64OrDoubleUnion arg12, Int64OrDoubleUnion arg13,
    Int64OrDoubleUnion arg14, Int64OrDoubleUnion arg15,
    Int64OrDoubleUnion arg16, Int64OrDoubleUnion arg17,
    Int64OrDoubleUnion arg18, Int64OrDoubleUnion arg19) {
#else
ReturnType func_mixed_int_double(int64_t arg0, int64_t arg1, int64_t arg2,
                                 int64_t arg3, int64_t arg4, int64_t arg5,
                                 int64_t arg6, int64_t arg7, int64_t arg8,
                                 int64_t arg9, double arg10, double arg11,
                                 double arg12, double arg13, double arg14,
                                 double arg15, double arg16, double arg17,
                                 double arg18, double arg19) {
#endif
  bool result = true;
  MIXED_SIGNATURE_INT_DOUBLE(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithMixedSignatureIntDouble, MIXED_SIGNATURE_INT_DOUBLE,
               func_mixed_int_double)

#define MIXED_SIGNATURE_INT_DOUBLE_ALT(V)                                   \
  V(int64_t, 0, 0), V(double, 1, 1.5), V(int64_t, 2, 2), V(double, 3, 3.5), \
      V(int64_t, 4, 4), V(double, 5, 5.5), V(int64_t, 6, 6),                \
      V(double, 7, 7.5), V(int64_t, 8, 8), V(double, 9, 9.5),               \
      V(int64_t, 10, 10), V(double, 11, 11.5), V(int64_t, 12, 12),          \
      V(double, 13, 13.5), V(int64_t, 14, 14), V(double, 15, 15.5),         \
      V(int64_t, 16, 16), V(double, 17, 17.5), V(int64_t, 18, 18),          \
      V(double, 19, 19.5)

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
Int64OrDoubleUnion func_mixed_int_double_alt(
    Int64OrDoubleUnion arg0, Int64OrDoubleUnion arg1, Int64OrDoubleUnion arg2,
    Int64OrDoubleUnion arg3, Int64OrDoubleUnion arg4, Int64OrDoubleUnion arg5,
    Int64OrDoubleUnion arg6, Int64OrDoubleUnion arg7, Int64OrDoubleUnion arg8,
    Int64OrDoubleUnion arg9, Int64OrDoubleUnion arg10, Int64OrDoubleUnion arg11,
    Int64OrDoubleUnion arg12, Int64OrDoubleUnion arg13,
    Int64OrDoubleUnion arg14, Int64OrDoubleUnion arg15,
    Int64OrDoubleUnion arg16, Int64OrDoubleUnion arg17,
    Int64OrDoubleUnion arg18, Int64OrDoubleUnion arg19) {
#else
ReturnType func_mixed_int_double_alt(int64_t arg0, double arg1, int64_t arg2,
                                     double arg3, int64_t arg4, double arg5,
                                     int64_t arg6, double arg7, int64_t arg8,
                                     double arg9, int64_t arg10, double arg11,
                                     int64_t arg12, double arg13, int64_t arg14,
                                     double arg15, int64_t arg16, double arg17,
                                     int64_t arg18, double arg19) {
#endif
  bool result = true;
  MIXED_SIGNATURE_INT_DOUBLE_ALT(CHECK_ARG_I);
  CHECK(result);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  Int64OrDoubleUnion ret;
  ret.int64_t_value = 42;
  return ret;
#else
  return 42;
#endif
}

SIGNATURE_TEST(RunCallWithMixedSignatureIntDoubleAlt,
               MIXED_SIGNATURE_INT_DOUBLE_ALT, func_mixed_int_double_alt)

#define SIGNATURE_ONLY_DOUBLE(V)                                              \
  V(double, 0, 0.5), V(double, 1, 1.5), V(double, 2, 2.5), V(double, 3, 3.5), \
      V(double, 4, 4.5), V(double, 5, 5.5),
```