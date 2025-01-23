Response:
The user wants to understand the functionality of the provided C++ code, which is a test file for the V8 JavaScript engine. The file `test-multiple-return.cc` is located in the `v8/test/cctest/compiler` directory.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `test-multiple-return.cc` strongly suggests that the code tests the ability of the V8 compiler to handle functions that return multiple values.

2. **Analyze the includes:** The included headers provide clues about the code's context:
    - `src/codegen/...`: Indicates code generation and low-level operations.
    - `src/compiler/...`:  Points to compiler-related functionalities.
    - `src/wasm/...`:  Suggests interaction with WebAssembly.
    - `test/cctest/...`:  Confirms this is a compiler test.

3. **Examine the `CreateCallDescriptor` function:** This function builds a description of a function's signature, including the number and types of parameters and return values. The use of `wasm::FunctionSig::Builder` reinforces the connection to WebAssembly.

4. **Analyze the `MakeConstant`, `Add`, `Sub`, `Mul`, `ToInt32` functions:** These are helper functions that create nodes in the compiler's intermediate representation (IR) for basic operations like creating constants, addition, subtraction, multiplication, and type conversion to 32-bit integers. The switch statements based on `MachineType` are crucial here.

5. **Understand `AllocateNativeModule`:** This function sets up a basic WebAssembly module environment, essential for testing WebAssembly code generation.

6. **Focus on the `TestReturnMultipleValues` template function:** This is the core test logic.
    - It iterates through different parameter counts and return value counts.
    - It creates a `CallDescriptor` for the function under test.
    - It uses `RawMachineAssembler` to build a simple function that performs arithmetic operations on input parameters and returns multiple values.
    - It compiles this function using `Pipeline::GenerateCodeForTesting`.
    - It generates a *caller* function using `RawMachineAssemblerTester` that calls the compiled function and verifies the returned values.
    - The caller calculates an expected result and compares it to the actual result of the call.

7. **Examine the `TEST_MULTI` macro:** This macro simplifies the creation of test cases for different machine types (Int32, Int64, Float32, Float64).

8. **Analyze `TestReturnMultipleValuesLargeFrame`:** This test specifically checks how the compiler handles functions with a large stack frame when returning multiple values.

9. **Understand `ReturnLastValue`:** This test focuses on verifying that the last returned value is correctly retrieved when a function returns many values.

10. **Understand `ReturnSumOfReturns`:** This test checks if the sum of all the returned values is correctly calculated in the caller.

11. **Infer the overall functionality:** Based on the individual parts, the test suite verifies the V8 compiler's ability to:
    - Generate correct code for WebAssembly functions returning multiple values.
    - Handle different data types for return values (integers and floating-point numbers).
    - Manage stack frames correctly when dealing with multiple return values, including cases with large frames.
    - Retrieve and process individual return values from a multi-value return.

12. **Address the specific questions in the prompt:**
    - **Functionality:** Summarize the core purpose of testing multiple return values in the compiler.
    - **.tq extension:** Explain that `.tq` indicates Torque source code, and this file is C++, so the condition is false.
    - **JavaScript relevance:** Connect the concept of multiple return values to JavaScript's destructuring assignment.
    - **Code logic and examples:**  Use the `TestReturnMultipleValues` function as the basis for a logic explanation and provide a concrete input/output example.
    - **Common programming errors:** Relate the concept to potential misunderstandings about how functions return values in general and highlight the importance of correctly handling multiple returns.

13. **Refine the language:** Ensure the explanation is clear, concise, and uses appropriate terminology. Provide concrete examples where needed.

This detailed analysis allows for the generation of a comprehensive answer that addresses all aspects of the user's request.这个C++源代码文件 `v8/test/cctest/compiler/test-multiple-return.cc` 的主要功能是 **测试V8 JavaScript引擎编译器在处理返回多个值的函数时的正确性**。

更具体地说，它通过以下方式进行测试：

1. **模拟 WebAssembly 函数:**  代码使用 V8 的内部 API (如 `RawMachineAssembler`) 来构建简单的 WebAssembly 函数，这些函数可以返回多个值。
2. **生成不同类型的函数:**  测试涵盖了返回不同数据类型（如 32 位整数、64 位整数、单精度浮点数、双精度浮点数）的多个值的函数。
3. **测试不同数量的返回值:**  测试用例会创建返回不同数量值的函数，以确保编译器能够处理各种情况。
4. **生成调用这些函数的代码:**  测试代码还会生成调用这些多返回值 WebAssembly 函数的代码。
5. **验证返回值的正确性:**  测试用例会计算预期的返回值，并与实际从编译后的代码中获得的返回值进行比较，以验证编译器的正确性。
6. **测试边缘情况:** 例如，`TestReturnMultipleValuesLargeFrame` 测试了当返回多个值导致需要较大的栈帧时编译器的行为。

**关于文件扩展名 `.tq`:**

你提到的 `.tq` 扩展名通常用于 V8 的 Torque 语言源代码。然而，`v8/test/cctest/compiler/test-multiple-return.cc` 的扩展名是 `.cc`，这表明它是 **C++ 源代码**，而不是 Torque 源代码。

**与 JavaScript 的功能关系:**

虽然这个测试文件直接测试的是 V8 编译器对 WebAssembly 多返回值的支持，但这与 JavaScript 的功能息息相关。这是因为：

* **WebAssembly 与 JavaScript 的互操作性:** WebAssembly 模块可以在 JavaScript 环境中运行，并且 JavaScript 可以调用 WebAssembly 函数，反之亦然。如果 WebAssembly 函数返回多个值，JavaScript 需要能够正确接收和处理这些值.
* **JavaScript 的解构赋值:**  JavaScript 提供了**解构赋值**的语法，可以方便地从数组或对象中提取多个值。当调用一个返回多个值的 WebAssembly 函数时，JavaScript 可以使用解构赋值来接收这些返回值。

**JavaScript 示例:**

假设有一个 WebAssembly 函数 (在 C++ 测试代码中定义) 返回两个整数的和与差。在 JavaScript 中，我们可以这样调用并接收返回值：

```javascript
// 假设已经加载了 WebAssembly 模块，并且导出了一个名为 'addAndSubtract' 的函数
const { addAndSubtract } = wasmModule.exports;

// 调用 WebAssembly 函数
const [sum, difference] = addAndSubtract(5, 3);

console.log("Sum:", sum);      // 输出: Sum: 8
console.log("Difference:", difference); // 输出: Difference: 2
```

在这个例子中，`addAndSubtract(5, 3)` 实际上调用了 C++ 测试代码中构建的 WebAssembly 函数，该函数返回两个值。JavaScript 的解构赋值 `[sum, difference]` 将这两个返回值分别赋给了 `sum` 和 `difference` 变量。

**代码逻辑推理 (假设输入与输出):**

让我们以 `TestReturnMultipleValues` 函数为例，假设 `type` 是 `MachineType::Int32()`，`param_count` 是 2，`count` 是 2。

**假设输入:**

* 被测试的 WebAssembly 函数接收两个 `int32_t` 类型的参数。
* 该函数返回两个 `int32_t` 类型的值。
* 在测试用例中，我们传递给 WebAssembly 函数的两个参数值分别是 `a = 47` 和 `b = 12`。

**代码逻辑:**

在 `TestReturnMultipleValues` 中，对于 `count = 2` 的情况，返回值的计算逻辑如下：

* `returns[0] = Add(&m, type, p0, p1);`  (p0 对应参数 a，p1 对应参数 b) => 返回 `a + b`
* `returns[1] = Sub(&m, type, p0, p1);` => 返回 `a - b`

然后，在调用 WebAssembly 函数的代码中，会计算一个期望值 `expect`。对于 `count = 2` 的情况，期望值的计算如下：

* 第一次迭代 (i=0): `expect += (a + b)`  (因为 i % 3 == 0)
* 第二次迭代 (i=1): `expect += (a - b)`  (因为 i % 3 == 1)

最后，调用 WebAssembly 函数后，测试代码会从返回的多个值中取出这两个值，并计算它们的和（或差，取决于 `sign` 变量）。最终会将计算结果与 `expect` 进行比较。

**预期输出:**

在这种情况下：

* WebAssembly 函数的返回值应该是 `47 + 12 = 59` 和 `47 - 12 = 35`。
* `expect` 的值应该是 `(47 + 12) + (47 - 12) = 59 + 35 = 94`。
* `mt.Call()` 的结果应该等于 `expect`，即 `94`。

**涉及用户常见的编程错误:**

这个测试文件主要关注编译器内部的正确性，但与用户常见的编程错误也有间接关系，例如：

1. **错误地处理多返回值:** 在 JavaScript 中调用返回多个值的 WebAssembly 函数时，如果用户不使用解构赋值或以其他方式正确处理返回的数组，可能会导致错误。

   **错误示例 (JavaScript):**

   ```javascript
   const result = addAndSubtract(5, 3);
   console.log("Sum:", result[0]); // 正确
   console.log("Difference:", result[1]); // 正确

   console.log("Sum:", result); // 错误：会输出整个数组 [8, 2] 而不是单个和
   ```

2. **类型不匹配:**  如果 WebAssembly 函数返回特定类型的值，而 JavaScript 代码尝试将其解释为不同的类型，可能会导致错误或意外行为。虽然 JavaScript 是动态类型的，但在与 WebAssembly 交互时，理解数据类型的边界仍然很重要。

3. **假设返回值的数量:**  如果用户假设 WebAssembly 函数返回固定数量的值，但实际情况并非如此，可能会导致代码出错。

   **错误示例 (JavaScript):**

   ```javascript
   // 假设 addAndSubtract 只返回一个值
   const sum = addAndSubtract(5, 3);
   console.log("Sum:", sum); // 可能会得到 [8, 2] 数组，导致后续使用出错
   ```

**总结:**

`v8/test/cctest/compiler/test-multiple-return.cc` 是一个关键的测试文件，用于验证 V8 编译器正确处理 WebAssembly 函数返回多个值的能力。这对于确保 JavaScript 能够可靠地与 WebAssembly 模块进行互操作至关重要，并且间接地与用户在 JavaScript 中处理多返回值时可能遇到的编程错误相关。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-multiple-return.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-multiple-return.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <functional>
#include <limits>
#include <memory>

#include "src/base/bits.h"
#include "src/codegen/assembler.h"
#include "src/codegen/compiler.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/compiler/linkage.h"
#include "src/compiler/wasm-compiler.h"
#include "src/objects/objects-inl.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

CallDescriptor* CreateCallDescriptor(Zone* zone, int return_count,
                                     int param_count, MachineType type) {
  wasm::FunctionSig::Builder builder(zone, return_count, param_count);

  for (int i = 0; i < param_count; i++) {
    builder.AddParam(wasm::ValueType::For(type));
  }

  for (int i = 0; i < return_count; i++) {
    builder.AddReturn(wasm::ValueType::For(type));
  }
  return compiler::GetWasmCallDescriptor(zone, builder.Get());
}

Node* MakeConstant(RawMachineAssembler* m, MachineType type, int value) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Constant(static_cast<int32_t>(value));
    case MachineRepresentation::kWord64:
      return m->Int64Constant(static_cast<int64_t>(value));
    case MachineRepresentation::kFloat32:
      return m->Float32Constant(static_cast<float>(value));
    case MachineRepresentation::kFloat64:
      return m->Float64Constant(static_cast<double>(value));
    default:
      UNREACHABLE();
  }
}

Node* Add(RawMachineAssembler* m, MachineType type, Node* a, Node* b) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Add(a, b);
    case MachineRepresentation::kWord64:
      return m->Int64Add(a, b);
    case MachineRepresentation::kFloat32:
      return m->Float32Add(a, b);
    case MachineRepresentation::kFloat64:
      return m->Float64Add(a, b);
    default:
      UNREACHABLE();
  }
}

Node* Sub(RawMachineAssembler* m, MachineType type, Node* a, Node* b) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Sub(a, b);
    case MachineRepresentation::kWord64:
      return m->Int64Sub(a, b);
    case MachineRepresentation::kFloat32:
      return m->Float32Sub(a, b);
    case MachineRepresentation::kFloat64:
      return m->Float64Sub(a, b);
    default:
      UNREACHABLE();
  }
}

Node* Mul(RawMachineAssembler* m, MachineType type, Node* a, Node* b) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Mul(a, b);
    case MachineRepresentation::kWord64:
      return m->Int64Mul(a, b);
    case MachineRepresentation::kFloat32:
      return m->Float32Mul(a, b);
    case MachineRepresentation::kFloat64:
      return m->Float64Mul(a, b);
    default:
      UNREACHABLE();
  }
}

Node* ToInt32(RawMachineAssembler* m, MachineType type, Node* a) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return a;
    case MachineRepresentation::kWord64:
      return m->TruncateInt64ToInt32(a);
    case MachineRepresentation::kFloat32:
      return m->TruncateFloat32ToInt32(a, TruncateKind::kArchitectureDefault);
    case MachineRepresentation::kFloat64:
      return m->RoundFloat64ToInt32(a);
    default:
      UNREACHABLE();
  }
}

std::shared_ptr<wasm::NativeModule> AllocateNativeModule(Isolate* isolate,
                                                         size_t code_size) {
  auto module = std::make_shared<wasm::WasmModule>(wasm::kWasmOrigin);
  module->num_declared_functions = 1;
  // We have to add the code object to a NativeModule, because the
  // WasmCallDescriptor assumes that code is on the native heap and not
  // within a code object.
  auto native_module = wasm::GetWasmEngine()->NewNativeModule(
      isolate, wasm::WasmEnabledFeatures::All(), wasm::WasmDetectedFeatures{},
      wasm::CompileTimeImports{}, std::move(module), code_size);
  native_module->SetWireBytes({});
  return native_module;
}

template <int kMinParamCount, int kMaxParamCount>
void TestReturnMultipleValues(MachineType type, int min_count, int max_count) {
  for (int param_count : {kMinParamCount, kMaxParamCount}) {
    for (int count = min_count; count < max_count; ++count) {
      printf("\n==== type = %s, parameter_count = %d, count = %d ====\n\n\n",
             MachineReprToString(type.representation()), param_count, count);
      v8::internal::AccountingAllocator allocator;
      Zone zone(&allocator, ZONE_NAME);
      CallDescriptor* desc =
          CreateCallDescriptor(&zone, count, param_count, type);
      HandleAndZoneScope handles(kCompressGraphZone);
      RawMachineAssembler m(
          handles.main_isolate(),
          handles.main_zone()->New<Graph>(handles.main_zone()), desc,
          MachineType::PointerRepresentation(),
          InstructionSelector::SupportedMachineOperatorFlags());

      // m.Parameter(0) is the WasmContext.
      Node* p0 = m.Parameter(1);
      Node* p1 = m.Parameter(2);
      using Node_ptr = Node*;
      std::unique_ptr<Node_ptr[]> returns(new Node_ptr[count]);
      for (int i = 0; i < count; ++i) {
        if (i % 3 == 0) returns[i] = Add(&m, type, p0, p1);
        if (i % 3 == 1) returns[i] = Sub(&m, type, p0, p1);
        if (i % 3 == 2) returns[i] = Mul(&m, type, p0, p1);
      }
      m.Return(count, returns.get());

      OptimizedCompilationInfo info(base::ArrayVector("testing"),
                                    handles.main_zone(),
                                    CodeKind::WASM_FUNCTION);
      DirectHandle<Code> code =
          Pipeline::GenerateCodeForTesting(
              &info, handles.main_isolate(), desc, m.graph(),
              AssemblerOptions::Default(handles.main_isolate()),
              m.ExportForTest())
              .ToHandleChecked();
#ifdef ENABLE_DISASSEMBLER
      if (v8_flags.print_code) {
        StdoutStream os;
        code->Disassemble("multi_value", os, handles.main_isolate());
      }
#endif

      const int a = 47, b = 12;
      int expect = 0;
      for (int i = 0, sign = +1; i < count; ++i) {
        if (i % 3 == 0) expect += sign * (a + b);
        if (i % 3 == 1) expect += sign * (a - b);
        if (i % 3 == 2) expect += sign * (a * b);
        if (i % 4 == 0) sign = -sign;
      }

      std::shared_ptr<wasm::NativeModule> module = AllocateNativeModule(
          handles.main_isolate(), code->instruction_size());
      wasm::WasmCodeRefScope wasm_code_ref_scope;
      wasm::WasmCode* wasm_code = module->AddCodeForTesting(code);
      WasmCodePointer code_pointer = wasm_code->code_pointer();

      RawMachineAssemblerTester<int32_t> mt(CodeKind::JS_TO_WASM_FUNCTION);
      const int input_count = 2 + param_count;
      Node* call_inputs[2 + kMaxParamCount];
      call_inputs[0] = mt.IntPtrConstant(code_pointer);
      // WasmContext dummy
      call_inputs[1] = mt.PointerConstant(nullptr);
      // Special inputs for the test.
      call_inputs[2] = MakeConstant(&mt, type, a);
      call_inputs[3] = MakeConstant(&mt, type, b);
      for (int i = 2; i < param_count; i++) {
        call_inputs[2 + i] = MakeConstant(&mt, type, i);
      }

      Node* ret_multi = mt.AddNode(mt.common()->Call(desc),
                                   input_count, call_inputs);
      Node* ret = MakeConstant(&mt, type, 0);
      bool sign = false;
      for (int i = 0; i < count; ++i) {
        Node* x = (count == 1)
                      ? ret_multi
                      : mt.AddNode(mt.common()->Projection(i), ret_multi);
        ret = sign ? Sub(&mt, type, ret, x) : Add(&mt, type, ret, x);
        if (i % 4 == 0) sign = !sign;
      }
      mt.Return(ToInt32(&mt, type, ret));
#ifdef ENABLE_DISASSEMBLER
      if (v8_flags.print_code) {
        StdoutStream os;
        DirectHandle<Code> code2 = mt.GetCode();
        code2->Disassemble("multi_value_call", os, handles.main_isolate());
      }
#endif
      CHECK_EQ(expect, mt.Call());
    }
  }
}

}  // namespace

// Use 9 parameters as a regression test or https://crbug.com/838098.
#define TEST_MULTI(Type, type) \
  TEST(ReturnMultiple##Type) { TestReturnMultipleValues<2, 9>(type, 0, 20); }

// Create a frame larger than UINT16_MAX to force TF to use an extra register
// when popping the frame.
TEST(TestReturnMultipleValuesLargeFrame) {
  TestReturnMultipleValues<20000, 20000>(MachineType::Int32(), 2, 3);
}

TEST_MULTI(Int32, MachineType::Int32())
#if (!V8_TARGET_ARCH_32_BIT)
TEST_MULTI(Int64, MachineType::Int64())
#endif
TEST_MULTI(Float32, MachineType::Float32())
TEST_MULTI(Float64, MachineType::Float64())

#undef TEST_MULTI

void ReturnLastValue(MachineType type) {
  int slot_counts[] = {1, 2, 3, 600};
  for (auto slot_count : slot_counts) {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    // The wasm-linkage provides 2 return registers at the moment, on all
    // platforms.
    const int return_count = 2 + slot_count;

    CallDescriptor* desc = CreateCallDescriptor(&zone, return_count, 0, type);

    HandleAndZoneScope handles(kCompressGraphZone);
    RawMachineAssembler m(handles.main_isolate(),
                          handles.main_zone()->New<Graph>(handles.main_zone()),
                          desc, MachineType::PointerRepresentation(),
                          InstructionSelector::SupportedMachineOperatorFlags());

    std::unique_ptr<Node* []> returns(new Node*[return_count]);

    for (int i = 0; i < return_count; ++i) {
      returns[i] = MakeConstant(&m, type, i);
    }

    m.Return(return_count, returns.get());

    OptimizedCompilationInfo info(base::ArrayVector("testing"),
                                  handles.main_zone(), CodeKind::WASM_FUNCTION);
    DirectHandle<Code> code =
        Pipeline::GenerateCodeForTesting(
            &info, handles.main_isolate(), desc, m.graph(),
            AssemblerOptions::Default(handles.main_isolate()),
            m.ExportForTest())
            .ToHandleChecked();

    std::shared_ptr<wasm::NativeModule> module =
        AllocateNativeModule(handles.main_isolate(), code->instruction_size());
    wasm::WasmCodeRefScope wasm_code_ref_scope;
    wasm::WasmCode* wasm_code = module->AddCodeForTesting(code);
    WasmCodePointer code_pointer = wasm_code->code_pointer();

    // Generate caller.
    int expect = return_count - 1;
    RawMachineAssemblerTester<int32_t> mt;
    Node* inputs[] = {mt.IntPtrConstant(code_pointer),
                      // WasmContext dummy
                      mt.PointerConstant(nullptr)};

    Node* call = mt.AddNode(mt.common()->Call(desc), 2, inputs);

    mt.Return(
        ToInt32(&mt, type,
                mt.AddNode(mt.common()->Projection(return_count - 1), call)));

    CHECK_EQ(expect, mt.Call());
  }
}

TEST(ReturnLastValueInt32) { ReturnLastValue(MachineType::Int32()); }
#if (!V8_TARGET_ARCH_32_BIT)
TEST(ReturnLastValueInt64) { ReturnLastValue(MachineType::Int64()); }
#endif
TEST(ReturnLastValueFloat32) { ReturnLastValue(MachineType::Float32()); }
TEST(ReturnLastValueFloat64) { ReturnLastValue(MachineType::Float64()); }

void ReturnSumOfReturns(MachineType type) {
  for (int unused_stack_slots = 0; unused_stack_slots <= 2;
       ++unused_stack_slots) {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    // Let {unused_stack_slots + 1} returns be on the stack.
    // The wasm-linkage provides 2 return registers at the moment, on all
    // platforms.
    const int return_count = 2 + unused_stack_slots + 1;

    CallDescriptor* desc = CreateCallDescriptor(&zone, return_count, 0, type);

    HandleAndZoneScope handles(kCompressGraphZone);
    RawMachineAssembler m(handles.main_isolate(),
                          handles.main_zone()->New<Graph>(handles.main_zone()),
                          desc, MachineType::PointerRepresentation(),
                          InstructionSelector::SupportedMachineOperatorFlags());

    std::unique_ptr<Node* []> returns(new Node*[return_count]);

    for (int i = 0; i < return_count; ++i) {
      returns[i] = MakeConstant(&m, type, i);
    }

    m.Return(return_count, returns.get());

    OptimizedCompilationInfo info(base::ArrayVector("testing"),
                                  handles.main_zone(), CodeKind::WASM_FUNCTION);
    DirectHandle<Code> code =
        Pipeline::GenerateCodeForTesting(
            &info, handles.main_isolate(), desc, m.graph(),
            AssemblerOptions::Default(handles.main_isolate()),
            m.ExportForTest())
            .ToHandleChecked();

    std::shared_ptr<wasm::NativeModule> module =
        AllocateNativeModule(handles.main_isolate(), code->instruction_size());
    wasm::WasmCodeRefScope wasm_code_ref_scope;
    wasm::WasmCode* wasm_code = module->AddCodeForTesting(code);
    WasmCodePointer code_pointer = wasm_code->code_pointer();

    // Generate caller.
    RawMachineAssemblerTester<int32_t> mt;
    Node* call_inputs[] = {mt.IntPtrConstant(code_pointer),
                           // WasmContext dummy
                           mt.PointerConstant(nullptr)};

    Node* call = mt.AddNode(mt.common()->Call(desc), 2, call_inputs);

    uint32_t expect = 0;
    Node* result = mt.Int32Constant(0);

    for (int i = 0; i < return_count; ++i) {
      expect += i;
      result = mt.Int32Add(
          result,
          ToInt32(&mt, type, mt.AddNode(mt.common()->Projection(i), call)));
    }

    mt.Return(result);

    CHECK_EQ(expect, mt.Call());
  }
}

TEST(ReturnSumOfReturnsInt32) { ReturnSumOfReturns(MachineType::Int32()); }
#if (!V8_TARGET_ARCH_32_BIT)
TEST(ReturnSumOfReturnsInt64) { ReturnSumOfReturns(MachineType::Int64()); }
#endif
TEST(ReturnSumOfReturnsFloat32) { ReturnSumOfReturns(MachineType::Float32()); }
TEST(ReturnSumOfReturnsFloat64) { ReturnSumOfReturns(MachineType::Float64()); }

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```