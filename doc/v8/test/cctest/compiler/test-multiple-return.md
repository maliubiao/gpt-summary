Response: Let's break down the thought process for analyzing the C++ code and connecting it to JavaScript.

**1. Understanding the Goal:**

The first step is to understand the request: analyze a C++ file (`test-multiple-return.cc`) related to the V8 JavaScript engine and explain its functionality, especially concerning multiple return values. If it relates to JavaScript, provide an example.

**2. Initial Scan for Keywords and Structure:**

I quickly scan the code for significant keywords and structural elements:

* **`Copyright 2014 the V8 project authors`**:  Confirms it's part of V8.
* **`#include` directives**:  These reveal the dependencies and the general area of V8 the code deals with (e.g., `compiler`, `codegen`, `wasm`). The presence of `wasm` related includes is a strong hint.
* **`namespace v8 { namespace internal { namespace compiler { ... } } }`**:  Indicates the code belongs to the V8 compiler's internal implementation.
* **`TEST(...)` macros**:  This is a common pattern in C++ testing frameworks, suggesting this file is for testing a specific compiler feature.
* **Function definitions (e.g., `CreateCallDescriptor`, `MakeConstant`, `Add`, `Sub`, `Mul`, `ToInt32`, `AllocateNativeModule`, `TestReturnMultipleValues`, `ReturnLastValue`, `ReturnSumOfReturns`)**: These functions encapsulate specific actions, and their names often provide clues about their purpose.
* **Loops and conditional statements**: These indicate control flow and logic within the tests.
* **Variables like `return_count`, `param_count`**: These suggest the tests are dealing with function signatures and how values are passed and returned.
* **Calls to `Pipeline::GenerateCodeForTesting`**: This confirms the code is about generating and testing compiled code.
* **Use of `RawMachineAssembler` and `RawMachineAssemblerTester`**: This strongly indicates the tests are operating at a low level, likely generating machine code or an intermediate representation.

**3. Focusing on Key Functions and Concepts:**

Based on the initial scan, I identify the most important functions and concepts:

* **`CreateCallDescriptor`**:  Clearly related to defining the signature of a function (number of parameters and return values, their types). The mention of `wasm::FunctionSig::Builder` is a key connection to WebAssembly.
* **`MakeConstant`, `Add`, `Sub`, `Mul`, `ToInt32`**: These are helper functions for creating and manipulating values at the machine level. The `MachineType` parameter is crucial.
* **`AllocateNativeModule`**:  This function is specific to WebAssembly and deals with allocating memory for compiled WASM code.
* **`TestReturnMultipleValues`**: This test function's name is a direct indication of the file's primary purpose. The nested loops iterating through different parameter and return counts confirm this.
* **`ReturnLastValue` and `ReturnSumOfReturns`**: These are more specialized test cases focusing on specific aspects of multiple return values.
* **`MachineType`**:  This enum represents low-level data types (int32, int64, float32, float64), further reinforcing the low-level nature of the tests.

**4. Inferring the Functionality:**

By examining the code, especially the `TestReturnMultipleValues` function, I can infer the core functionality:

* **Testing the V8 compiler's ability to handle functions returning multiple values.**  The loops iterating through different `return_count` values are the strongest evidence for this.
* **Specifically testing this in the context of WebAssembly (WASM).** The inclusion of WASM-related headers, function names, and the use of `wasm::FunctionSig` and `wasm::NativeModule` make this clear.
* **Generating simple arithmetic operations for the function body.** The `Add`, `Sub`, and `Mul` calls within the loops suggest the generated WASM functions perform basic calculations.
* **Verifying the returned values.** The code calculates an `expect` value and then uses `RawMachineAssemblerTester` to execute the generated code and compare the results.

**5. Connecting to JavaScript (Crucial Step):**

The key insight is that while this C++ code is about *compiler implementation*, the feature being tested—multiple return values—*does* exist in JavaScript, albeit indirectly, through **destructuring assignment**.

* **Recall WASM's relationship to JavaScript:** WASM is designed to run alongside JavaScript in the browser. V8 is the engine that executes both.
* **Consider how WASM's multiple return values are exposed in JS:** When calling a WASM function that returns multiple values from JavaScript, those values are typically returned as an array or an object. Destructuring assignment provides a convenient syntax to unpack these multiple return values.

**6. Crafting the JavaScript Example:**

Based on the connection to destructuring assignment, I construct a simple JavaScript example that demonstrates the concept:

```javascript
function wasmLikeFunction() {
  return [10, 20];
}

const [a, b] = wasmLikeFunction();
console.log(a, b); // Output: 10 20
```

This example directly mirrors the functionality being tested in the C++ code: a function conceptually returning multiple values, and those values being accessed individually. It highlights the *user-facing* JavaScript feature that aligns with the *internal compiler feature* being tested.

**7. Refining the Explanation:**

Finally, I structure the explanation clearly, starting with a concise summary of the C++ file's purpose, then elaborating on the connection to JavaScript with the example, and finally providing more detailed points about the internal implementation. This layered approach helps the reader understand the code at different levels of detail.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the code is directly testing a JavaScript feature.
* **Correction:** The `#include` directives and namespaces strongly suggest it's about the *compiler*, specifically the WASM compiler.
* **Initial thought about JS example:** Directly mapping to a hypothetical JS function returning multiple comma-separated values (which isn't valid JS syntax).
* **Correction:**  Realizing that destructuring assignment is the correct way to handle multiple "returns" in JavaScript when interacting with functions that might conceptually return multiple values (like WASM functions).

This iterative process of scanning, identifying key elements, inferring functionality, making connections, and refining the explanation is crucial for understanding complex code and fulfilling the request.
这个C++源代码文件 `test-multiple-return.cc` 是 **V8 JavaScript 引擎** 的一部分，专门用于测试 **编译器** 在处理 **返回多个值** 的函数时的能力。更具体地说，它主要关注 **WebAssembly (Wasm)** 函数的多个返回值。

**功能归纳:**

1. **测试 WebAssembly 函数的多返回值:** 该文件定义了一系列的测试用例，用于验证 V8 的编译器是否能够正确地编译和执行返回多个值的 WebAssembly 函数。

2. **模拟和生成 WebAssembly 代码:**  测试用例使用 `RawMachineAssembler` 来创建底层的机器码指令序列，模拟简单的 WebAssembly 函数，这些函数执行一些基本操作（如加法、减法、乘法）并返回多个结果。

3. **创建调用描述符:** 使用 `CreateCallDescriptor` 函数来定义被测试的 WebAssembly 函数的签名，包括参数类型和返回值的数量和类型。

4. **生成调用 WebAssembly 函数的代码:** 测试用例还使用 `RawMachineAssemblerTester` 创建调用这些模拟 WebAssembly 函数的 JavaScript 代码（实际上是在编译器的测试框架中模拟 JavaScript 调用）。

5. **验证返回值:**  测试用例执行生成的代码，并检查 WebAssembly 函数返回的多个值是否与预期结果一致。

6. **测试不同数据类型:** 测试覆盖了多种数据类型，包括 `int32`, `int64`, `float32`, 和 `float64`。

7. **测试不同数量的返回值和参数:** 测试用例会尝试不同数量的返回值和参数，以确保编译器在各种情况下都能正确处理多返回值。

8. **关注栈帧大小:** 其中一个测试用例 (`TestReturnMultipleValuesLargeFrame`) 特别关注了栈帧大小对多返回值处理的影响，这可能涉及到编译器如何管理寄存器和栈空间。

**与 JavaScript 的关系及示例:**

虽然这个 C++ 文件是测试 V8 编译器内部的 WebAssembly 功能，但它直接关系到 **JavaScript 如何调用返回多个值的 WebAssembly 函数**。

在 WebAssembly 中，函数可以明确声明返回多个值。当 JavaScript 调用这样的 WebAssembly 函数时，返回的多个值会以某种方式传递回 JavaScript。通常，这些值会以 **数组** 的形式返回。

**JavaScript 示例:**

假设我们有一个 WebAssembly 模块，其中定义了一个名为 `addAndSubtract` 的函数，它接收两个数字并返回它们的和与差：

```wat
(module
  (func (export "addAndSubtract") (param $a i32) (param $b i32) (result i32 i32)
    local.get $a
    local.get $b
    i32.add
    local.get $a
    local.get $b
    i32.sub
  )
)
```

在 JavaScript 中，我们可以加载并调用这个 WebAssembly 函数：

```javascript
async function loadWasm() {
  const response = await fetch('your_wasm_module.wasm'); // 替换为你的 wasm 文件路径
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  const result = instance.exports.addAndSubtract(10, 5);

  // 返回的结果是一个数组，包含了 WebAssembly 函数返回的多个值
  console.log(result); // 输出: [15, 5]
  console.log("Sum:", result[0]); // 输出: Sum: 15
  console.log("Difference:", result[1]); // 输出: Difference: 5
}

loadWasm();
```

**解释:**

* 在 WebAssembly 中，`addAndSubtract` 函数声明了返回两个 `i32` 类型的值。
* 在 JavaScript 中调用 `instance.exports.addAndSubtract(10, 5)` 后，返回的 `result` 是一个 **数组** `[15, 5]`。
* 我们可以通过索引来访问数组中的元素，分别对应 WebAssembly 函数返回的每个值。

**总结:**

`test-multiple-return.cc` 这个 C++ 文件在 V8 引擎的内部，负责测试编译器正确处理 WebAssembly 函数返回多个值的情况。这直接影响了 JavaScript 如何接收和使用这些来自 WebAssembly 的多返回值，通常是通过数组的形式。  该测试确保了当 JavaScript 代码调用返回多个值的 WebAssembly 函数时，V8 引擎能够正确地传递和处理这些返回值。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-multiple-return.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```