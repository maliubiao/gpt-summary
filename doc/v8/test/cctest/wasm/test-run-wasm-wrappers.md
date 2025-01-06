Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example if it relates to JavaScript. The filename `test-run-wasm-wrappers.cc` strongly suggests it's testing something related to how JavaScript interacts with WebAssembly functions. Specifically, "wrappers" hints at the mechanism that bridges the gap between the two environments.

2. **Initial Scan for Key Terms:**  Look for recurring keywords and concepts. "Wasm," "wrapper," "export," "function," "budget," "replacement," "generic," "specific," "JSToWasmWrapper," "garbage collection" stand out. These words provide a high-level understanding of the topics being covered.

3. **Identify Core Functionality through Test Cases:** The code is structured as a series of `TEST()` blocks. Each `TEST()` likely focuses on a specific aspect of the wrapper functionality. Analyzing the names of the tests is crucial:
    * `WrapperBudget`:  Suggests testing a mechanism that limits or tracks wrapper usage.
    * `WrapperReplacement`: Implies testing how one type of wrapper can be replaced by another.
    * `EagerWrapperReplacement`:  Similar to the above, but with "eager" suggesting a more proactive replacement strategy.
    * `WrapperReplacement_IndirectExport`: Focuses on wrappers for functions exported indirectly through tables.
    * `JSToWasmWrapperGarbageCollection`:  Clearly tests the garbage collection behavior of the JavaScript-to-WebAssembly wrappers.

4. **Examine Code Within Tests:**  Dive into the code within each `TEST()` block. Look for:
    * **Setup:** How is the WebAssembly module created (`WasmModuleBuilder`)?  What functions are defined and exported?
    * **Execution:** How are the WebAssembly functions called from the C++ test environment (`SmiCall`)? What parameters are passed? What are the expected results?
    * **Assertions/Checks:** What conditions are being verified using `CHECK` or `CHECK_EQ`?  These reveal the specific behavior being tested. Pay close attention to checks involving `wrapper_budget`, `wrapper_code`, `IsGeneric`, and `IsSpecific`.

5. **Infer High-Level Concepts:**  Based on the test cases and the code within them, start forming conclusions about the file's purpose:
    * **Generic Wrappers:**  The tests repeatedly use `v8_flags.wasm_generic_wrapper`. This indicates the existence of a generic, less optimized wrapper that's used initially.
    * **Specific Wrappers:** The replacement tests show that the generic wrapper is later replaced by a more specialized wrapper (`CodeKind::JS_TO_WASM_FUNCTION`).
    * **Wrapper Budget:** The `wrapper_budget` seems to be a counter that determines when the generic wrapper is replaced.
    * **Optimization:** The transition from generic to specific wrappers likely represents an optimization strategy.
    * **Indirect Exports:**  The specific test for indirect exports shows that the wrapper mechanism applies to functions called through tables as well.
    * **Garbage Collection:** The garbage collection test verifies that wrappers are cleaned up when no longer needed, preventing memory leaks.

6. **Relate to JavaScript (if applicable):**  The keywords "JSToWasmWrapper" and the act of calling WebAssembly functions from C++ using constructs that resemble JavaScript calls strongly suggest a connection to JavaScript. The core idea is how JavaScript code interacts with compiled WebAssembly functions.

7. **Construct the Summary:**  Organize the findings into a clear and concise summary. Start with the main function and then elaborate on the specific aspects tested. Use clear language and avoid overly technical jargon where possible.

8. **Create the JavaScript Example:**  Develop a simple JavaScript example that demonstrates the concepts being tested in the C++ code. The core idea is to show how calling a WebAssembly function from JavaScript might initially use a generic wrapper and how V8 might optimize this over time. Keep the JavaScript example simple and focused on illustrating the core concept. Highlight the analogous actions (importing and calling the WebAssembly function). Emphasize that the wrapper mechanism is an internal optimization detail.

9. **Review and Refine:** Read through the summary and the JavaScript example to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where further explanation might be needed. For example, initially, I might have focused too much on the C++ testing framework. Refining the summary would involve shifting the focus to the *functionality being tested* rather than the testing mechanism itself. Similarly, ensure the JavaScript example is a valid and understandable demonstration of the concept.

This systematic approach, moving from a broad overview to specific details and then synthesizing the information, helps in understanding complex code like this and explaining its functionality effectively.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-wrappers.cc` 的主要功能是**测试 V8 引擎中用于运行 WebAssembly (Wasm) 模块的 JavaScript 到 Wasm 的包装器 (wrappers) 的行为和机制。**

更具体地说，它测试了以下几个方面：

1. **包装器的预算 (Wrapper Budget):**
   - 当 JavaScript 调用 Wasm 导出函数时，V8 最初可能会使用一个通用的包装器。
   - 这个通用包装器有一个预算，每次调用都会消耗一部分预算。
   - 测试验证了预算的初始值和每次调用后的递减。

2. **包装器的替换 (Wrapper Replacement):**
   - 当通用包装器的预算耗尽时，V8 会将其替换为一个更具体的、优化的包装器。
   - 测试验证了通用包装器被替换为特定包装器的过程，以及替换后再次调用 Wasm 函数时使用的是特定包装器。

3. **急切的包装器替换 (Eager Wrapper Replacement):**
   - 测试了当多个具有相同签名的 Wasm 函数导出时，如果其中一个函数的通用包装器预算耗尽并被替换，是否会影响其他具有相同签名的函数的包装器。
   - 它验证了替换会影响到所有具有相同签名的函数，从而避免为每个函数都单独生成特定的包装器。

4. **间接导出的包装器替换 (Wrapper Replacement with Indirect Export):**
   - 测试了通过 Wasm 表间接导出的函数的包装器行为。
   - 验证了即使是通过表间接调用的 Wasm 函数，其通用包装器也会在预算耗尽后被替换为特定的包装器。

5. **JavaScript 到 Wasm 包装器的垃圾回收 (JSToWasmWrapper Garbage Collection):**
   - 测试了当没有 JavaScript 代码持有对 Wasm 导出函数的引用时，V8 是否能够正确地回收为这些函数生成的特定包装器。
   - 这确保了内存不会因为不再使用的包装器而泄漏。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个 C++ 文件测试的是 V8 引擎内部的机制，这个机制是用来连接 JavaScript 和 WebAssembly 的。当 JavaScript 代码调用一个 WebAssembly 模块中导出的函数时，V8 需要创建一个“桥梁”来实现这种调用，这个“桥梁”就是所谓的 JavaScript 到 Wasm 的包装器。

**JavaScript 示例:**

假设我们有一个简单的 WebAssembly 模块 `module.wasm`，它导出一个名为 `add` 的函数，该函数接受两个整数并返回它们的和。

```javascript
// 加载 WebAssembly 模块
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    const add = instance.exports.add; // 获取导出的 add 函数

    // 第一次调用 add 函数
    console.log(add(5, 3)); // 输出 8

    // 多次调用 add 函数
    for (let i = 0; i < 10; i++) {
      console.log(add(i, i + 1));
    }
  });
```

**C++ 代码测试与 JavaScript 示例的对应关系:**

- **通用包装器和预算:**  当 JavaScript 首次调用 `add` 函数时，V8 可能会使用一个通用的 `JSToWasmWrapper`。`WrapperBudget` 测试的就是这个通用包装器的行为。随着 `add` 函数被多次调用，通用包装器的预算会逐渐减少。

- **包装器替换:**  当通用包装器的预算耗尽时（在多次调用之后），V8 会将其替换为一个针对 `add` 函数的特定优化过的包装器。`WrapperReplacement` 和 `EagerWrapperReplacement` 测试的就是这个替换过程。替换后，后续对 `add` 的调用将直接使用这个优化的包装器，通常会更快。

- **垃圾回收:** 如果在 JavaScript 代码中，我们不再持有对 `instance.exports.add` 的引用，并且 `instance` 本身也不再被引用，那么 `JSToWasmWrapperGarbageCollection` 测试验证了 V8 能够回收之前为 `add` 函数生成的特定包装器，释放内存。

**总结:**

`test-run-wasm-wrappers.cc` 通过一系列的单元测试，深入验证了 V8 引擎在处理 JavaScript 调用 WebAssembly 函数时所使用的包装器机制的正确性和效率。它涵盖了包装器的生命周期，从最初的通用包装器到优化后的特定包装器，再到最终的垃圾回收，确保了 JavaScript 和 WebAssembly 能够高效且可靠地协同工作。这些测试对于确保 V8 引擎作为 JavaScript 和 WebAssembly 运行时环境的稳定性和性能至关重要。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-wrappers.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_wrappers {

using testing::CompileAndInstantiateForTesting;

#if V8_COMPRESS_POINTERS &&                                               \
    (V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_IA32 || \
     V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_LOONG64)
namespace {
Handle<WasmInstanceObject> CompileModule(Zone* zone, Isolate* isolate,
                                         WasmModuleBuilder* builder) {
  ZoneBuffer buffer(zone);
  builder->WriteTo(&buffer);
  testing::SetupIsolateForWasmModule(isolate);
  ErrorThrower thrower(isolate, "CompileAndRunWasmModule");
  MaybeHandle<WasmInstanceObject> maybe_instance =
      CompileAndInstantiateForTesting(
          isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
  CHECK_WITH_MSG(!thrower.error(), thrower.error_msg());
  return maybe_instance.ToHandleChecked();
}

bool IsGeneric(Tagged<Code> wrapper) {
  return wrapper->is_builtin() &&
         wrapper->builtin_id() == Builtin::kJSToWasmWrapper;
}

bool IsSpecific(Tagged<Code> wrapper) {
  return wrapper->kind() == CodeKind::JS_TO_WASM_FUNCTION;
}

Handle<Object> SmiHandle(Isolate* isolate, int value) {
  return Handle<Object>(Smi::FromInt(value), isolate);
}

void SmiCall(Isolate* isolate, Handle<WasmExportedFunction> exported_function,
             int argc, Handle<Object>* argv, int expected_result) {
  Handle<Object> receiver = isolate->factory()->undefined_value();
  DirectHandle<Object> result =
      Execution::Call(isolate, exported_function, receiver, argc, argv)
          .ToHandleChecked();
  CHECK(IsSmi(*result));
  CHECK_EQ(expected_result, Smi::ToInt(*result));
}

void Cleanup() {
  // By sending a low memory notifications, we will try hard to collect all
  // garbage and will therefore also invoke all weak callbacks of actually
  // unreachable persistent handles.
  Isolate* isolate = CcTest::InitIsolateOnce();
  reinterpret_cast<v8::Isolate*>(isolate)->LowMemoryNotification();
}

}  // namespace

TEST(WrapperBudget) {
  {
    // This test assumes use of the generic wrapper.
    FlagScope<bool> use_wasm_generic_wrapper(&v8_flags.wasm_generic_wrapper,
                                             true);

    // Initialize the environment and create a module builder.
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);

    // Define the Wasm function.
    TestSignatures sigs;
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_ii());
    f->builder()->AddExport(base::CStrVector("main"), f);
    f->EmitCode({WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_END});

    // Compile the module.
    Handle<WasmInstanceObject> instance =
        CompileModule(&zone, isolate, builder);

    // Get the exported function and the function data.
    Handle<WasmExportedFunction> main_export =
        testing::GetExportedFunction(isolate, instance, "main")
            .ToHandleChecked();
    DirectHandle<WasmExportedFunctionData> main_function_data(
        main_export->shared()->wasm_exported_function_data(), isolate);

    // Check that the generic-wrapper budget has initially a value of
    // kGenericWrapperBudget.
    CHECK_EQ(Smi::ToInt(main_function_data->wrapper_budget()->value()),
             kGenericWrapperBudget);
    static_assert(kGenericWrapperBudget > 0);

    // Call the exported Wasm function.
    Handle<Object> params[2] = {SmiHandle(isolate, 6), SmiHandle(isolate, 7)};
    SmiCall(isolate, main_export, 2, params, 42);

    // Check that the budget has now a value of (kGenericWrapperBudget - 1).
    CHECK_EQ(Smi::ToInt(main_function_data->wrapper_budget()->value()),
             kGenericWrapperBudget - 1);
  }
  Cleanup();
}

TEST(WrapperReplacement) {
  {
    // This test assumes use of the generic wrapper.
    FlagScope<bool> use_wasm_generic_wrapper(&v8_flags.wasm_generic_wrapper,
                                             true);

    // Initialize the environment and create a module builder.
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);

    // Define the Wasm function.
    TestSignatures sigs;
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_i());
    f->builder()->AddExport(base::CStrVector("main"), f);
    f->EmitCode({WASM_LOCAL_GET(0), WASM_END});

    // Compile the module.
    Handle<WasmInstanceObject> instance =
        CompileModule(&zone, isolate, builder);

    // Get the exported function and the function data.
    Handle<WasmExportedFunction> main_export =
        testing::GetExportedFunction(isolate, instance, "main")
            .ToHandleChecked();
    DirectHandle<WasmExportedFunctionData> main_function_data(
        main_export->shared()->wasm_exported_function_data(), isolate);

    // Check that the generic-wrapper budget has initially a value of
    // kGenericWrapperBudget.
    CHECK_EQ(Smi::ToInt(main_function_data->wrapper_budget()->value()),
             kGenericWrapperBudget);
    static_assert(kGenericWrapperBudget > 0);

    // Set the generic-wrapper budget to a value that allows for a few
    // more calls through the generic wrapper.
    const int remaining_budget =
        std::min(static_cast<int>(kGenericWrapperBudget), 2);
    main_function_data->wrapper_budget()->set_value(
        Smi::FromInt(remaining_budget));

    // Call the exported Wasm function as many times as required to almost
    // exhaust the remaining budget for using the generic wrapper.
    DirectHandle<Code> wrapper_before_call;
    for (int i = remaining_budget; i > 0; --i) {
      // Verify that the wrapper to be used is the generic one.
      wrapper_before_call =
          direct_handle(main_function_data->wrapper_code(isolate), isolate);
      CHECK(IsGeneric(*wrapper_before_call));
      // Call the function.
      Handle<Object> params[1] = {SmiHandle(isolate, i)};
      SmiCall(isolate, main_export, 1, params, i);
      // Verify that the budget has now a value of (i - 1).
      CHECK_EQ(Smi::ToInt(main_function_data->wrapper_budget()->value()),
               i - 1);
    }

    // Get the wrapper-code object after the wrapper replacement.
    Tagged<Code> wrapper_after_call = main_function_data->wrapper_code(isolate);

    // Verify that the budget has been exhausted.
    CHECK_EQ(Smi::ToInt(main_function_data->wrapper_budget()->value()), 0);
    // Verify that the wrapper-code object has changed and the wrapper is now a
    // specific one.
    // TODO(saelo): here we have to use full pointer comparison while not all
    // Code objects have been moved into trusted space.
    static_assert(!kAllCodeObjectsLiveInTrustedSpace);
    CHECK(!wrapper_after_call.SafeEquals(*wrapper_before_call));
    CHECK(IsSpecific(wrapper_after_call));
  }
  Cleanup();
}

TEST(EagerWrapperReplacement) {
  {
    // This test assumes use of the generic wrapper.
    FlagScope<bool> use_wasm_generic_wrapper(&v8_flags.wasm_generic_wrapper,
                                             true);

    // Initialize the environment and create a module builder.
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);

    // Define three Wasm functions.
    // Two of these functions (add and mult) will share the same signature,
    // while the other one (id) won't.
    TestSignatures sigs;
    WasmFunctionBuilder* add = builder->AddFunction(sigs.i_ii());
    add->builder()->AddExport(base::CStrVector("add"), add);
    add->EmitCode(
        {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_END});
    WasmFunctionBuilder* mult = builder->AddFunction(sigs.i_ii());
    mult->builder()->AddExport(base::CStrVector("mult"), mult);
    mult->EmitCode(
        {WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_END});
    WasmFunctionBuilder* id = builder->AddFunction(sigs.i_i());
    id->builder()->AddExport(base::CStrVector("id"), id);
    id->EmitCode({WASM_LOCAL_GET(0), WASM_END});

    // Compile the module.
    Handle<WasmInstanceObject> instance =
        CompileModule(&zone, isolate, builder);

    // Get the exported functions.
    Handle<WasmExportedFunction> add_export =
        testing::GetExportedFunction(isolate, instance, "add")
            .ToHandleChecked();
    Handle<WasmExportedFunction> mult_export =
        testing::GetExportedFunction(isolate, instance, "mult")
            .ToHandleChecked();
    Handle<WasmExportedFunction> id_export =
        testing::GetExportedFunction(isolate, instance, "id").ToHandleChecked();

    // Get the function data for all exported functions.
    DirectHandle<WasmExportedFunctionData> add_function_data(
        add_export->shared()->wasm_exported_function_data(), isolate);
    DirectHandle<WasmExportedFunctionData> mult_function_data(
        mult_export->shared()->wasm_exported_function_data(), isolate);
    DirectHandle<WasmExportedFunctionData> id_function_data(
        id_export->shared()->wasm_exported_function_data(), isolate);

    // Set the remaining generic-wrapper budget for add to 1,
    // so that the next call to it will cause the function to tier up.
    add_function_data->wrapper_budget()->set_value(Smi::FromInt(1));

    // Verify that the generic-wrapper budgets for all functions are correct.
    CHECK_EQ(Smi::ToInt(add_function_data->wrapper_budget()->value()), 1);
    CHECK_EQ(Smi::ToInt(mult_function_data->wrapper_budget()->value()),
             kGenericWrapperBudget);
    CHECK_EQ(Smi::ToInt(id_function_data->wrapper_budget()->value()),
             kGenericWrapperBudget);

    // Verify that all functions are set to use the generic wrapper.
    CHECK(IsGeneric(add_function_data->wrapper_code(isolate)));
    CHECK(IsGeneric(mult_function_data->wrapper_code(isolate)));
    CHECK(IsGeneric(id_function_data->wrapper_code(isolate)));

    // Call the add function to trigger the tier up.
    {
      Handle<Object> params[2] = {SmiHandle(isolate, 10),
                                  SmiHandle(isolate, 11)};
      SmiCall(isolate, add_export, 2, params, 21);
      // Verify that the generic-wrapper budgets for all functions are correct.
      CHECK_EQ(Smi::ToInt(add_function_data->wrapper_budget()->value()), 0);
      CHECK_EQ(Smi::ToInt(mult_function_data->wrapper_budget()->value()),
               kGenericWrapperBudget);
      CHECK_EQ(Smi::ToInt(id_function_data->wrapper_budget()->value()),
               kGenericWrapperBudget);
      // Verify that the tier-up of the add function replaced the wrapper
      // for both the add and the mult functions, but not the id function.
      CHECK(IsSpecific(add_function_data->wrapper_code(isolate)));
      CHECK(IsSpecific(mult_function_data->wrapper_code(isolate)));
      CHECK(IsGeneric(id_function_data->wrapper_code(isolate)));
    }

    // Call the mult function to verify that the compiled wrapper is used.
    {
      Handle<Object> params[2] = {SmiHandle(isolate, 6), SmiHandle(isolate, 7)};
      SmiCall(isolate, mult_export, 2, params, 42);
      // Verify that mult's budget is still intact, which means that the call
      // didn't go through the generic wrapper.
      CHECK_EQ(Smi::ToInt(mult_function_data->wrapper_budget()->value()),
               kGenericWrapperBudget);
    }

    // Call the id function to verify that the generic wrapper is used.
    {
      Handle<Object> params[1] = {SmiHandle(isolate, 6)};
      SmiCall(isolate, id_export, 1, params, 6);
      // Verify that id's budget decreased by 1, which means that the call
      // used the generic wrapper.
      CHECK_EQ(Smi::ToInt(id_function_data->wrapper_budget()->value()),
               kGenericWrapperBudget - 1);
    }
  }
  Cleanup();
}

TEST(WrapperReplacement_IndirectExport) {
  {
    // This test assumes use of the generic wrapper.
    FlagScope<bool> use_wasm_generic_wrapper(&v8_flags.wasm_generic_wrapper,
                                             true);

    // Initialize the environment and create a module builder.
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);

    // Define a Wasm function, but do not add it to the exports.
    TestSignatures sigs;
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_i());
    f->EmitCode({WASM_LOCAL_GET(0), WASM_END});
    uint32_t function_index = f->func_index();

    // Export a table of indirect functions.
    const uint32_t table_size = 2;
    const uint32_t table_index =
        builder->AddTable(kWasmFuncRef, table_size, table_size);
    builder->AddExport(base::CStrVector("exported_table"), kExternalTable, 0);

    // Point from the exported table to the Wasm function.
    builder->SetIndirectFunction(
        table_index, 0, function_index,
        WasmModuleBuilder::WasmElemSegment::kRelativeToImports);

    // Compile the module.
    DirectHandle<WasmInstanceObject> instance =
        CompileModule(&zone, isolate, builder);

    // Get the exported table.
    DirectHandle<WasmTableObject> table(
        Cast<WasmTableObject>(
            instance->trusted_data(isolate)->tables()->get(table_index)),
        isolate);
    // Get the Wasm function through the exported table.
    DirectHandle<WasmFuncRef> func_ref =
        Cast<WasmFuncRef>(WasmTableObject::Get(isolate, table, function_index));
    DirectHandle<WasmInternalFunction> internal_function{
        func_ref->internal(isolate), isolate};
    Handle<WasmExportedFunction> indirect_function = Cast<WasmExportedFunction>(
        WasmInternalFunction::GetOrCreateExternal(internal_function));
    // Get the function data.
    DirectHandle<WasmExportedFunctionData> indirect_function_data(
        indirect_function->shared()->wasm_exported_function_data(), isolate);

    // Verify that the generic-wrapper budget has initially a value of
    // kGenericWrapperBudget and the wrapper to be used for calls to the
    // indirect function is the generic one.
    CHECK(IsGeneric(indirect_function_data->wrapper_code(isolate)));
    CHECK(Smi::ToInt(indirect_function_data->wrapper_budget()->value()) ==
          kGenericWrapperBudget);

    // Set the remaining generic-wrapper budget for the indirect function to 1,
    // so that the next call to it will cause the function to tier up.
    indirect_function_data->wrapper_budget()->set_value(Smi::FromInt(1));

    // Call the Wasm function.
    Handle<Object> params[1] = {SmiHandle(isolate, 6)};
    SmiCall(isolate, indirect_function, 1, params, 6);

    // Verify that the budget is now exhausted and the generic wrapper has been
    // replaced by a specific one.
    CHECK_EQ(Smi::ToInt(indirect_function_data->wrapper_budget()->value()), 0);
    CHECK(IsSpecific(indirect_function_data->wrapper_code(isolate)));
  }
  Cleanup();
}

TEST(JSToWasmWrapperGarbageCollection) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  auto NumCompiledJSToWasmWrappers = [isolate]() {
    int num_wrappers = 0;
    Tagged<WeakFixedArray> wrappers = isolate->heap()->js_to_wasm_wrappers();
    for (int i = 0, e = wrappers->length(); i < e; ++i) {
      // Entries are either weak code wrappers, cleared entries, or undefined.
      Tagged<MaybeObject> maybe_wrapper = wrappers->get(i);
      if (maybe_wrapper.IsCleared()) continue;
      CHECK(maybe_wrapper.IsWeak());
      CHECK(IsCodeWrapper(maybe_wrapper.GetHeapObjectAssumeWeak()));
      Tagged<Code> code =
          Cast<CodeWrapper>(maybe_wrapper.GetHeapObjectAssumeWeak())
              ->code(isolate);
      CHECK_EQ(CodeKind::JS_TO_WASM_FUNCTION, code->kind());
      ++num_wrappers;
    }
    return num_wrappers;
  };

  {
    // Initialize the environment and create a module builder.
    AccountingAllocator allocator;
    Zone zone{&allocator, ZONE_NAME};
    HandleScope scope{isolate};
    WasmModuleBuilder builder{&zone};

    // Define an exported Wasm function.
    TestSignatures sigs;
    WasmFunctionBuilder* f = builder.AddFunction(sigs.i_v());
    builder.AddExport(base::CStrVector("main"), f);
    f->EmitCode({WASM_ONE, WASM_END});

    // Before compilation there should be no compiled wrappers.
    CHECK_EQ(0, NumCompiledJSToWasmWrappers());

    // Compile the module.
    Handle<WasmInstanceObject> instance =
        CompileModule(&zone, isolate, &builder);

    // If the generic wrapper is disabled, this should have compiled a wrapper.
    CHECK_EQ(v8_flags.wasm_generic_wrapper ? 0 : 1,
             NumCompiledJSToWasmWrappers());

    // Get the exported function and the function data.
    Handle<WasmExportedFunction> main_function =
        testing::GetExportedFunction(isolate, instance, "main")
            .ToHandleChecked();
    Handle<WasmExportedFunctionData> main_function_data(
        main_function->shared()->wasm_exported_function_data(), isolate);

    // Set the remaining generic-wrapper budget for add to 1,
    // so that the next call to it will cause the function to tier up.
    main_function_data->wrapper_budget()->set_value(Smi::FromInt(1));

    // Call the Wasm function.
    SmiCall(isolate, main_function, 0, nullptr, 1);

    // There should be exactly one compiled wrapper now.
    CHECK_EQ(1, NumCompiledJSToWasmWrappers());
  }

  // After GC all compiled wrappers must be cleared again.
  {
    // Disable stack scanning in case CSS is being used to prevent references
    // that leaked to the C++ stack from keeping the wrapper alive.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        isolate->heap());
    Cleanup();
  }

  CHECK_EQ(0, NumCompiledJSToWasmWrappers());
}
#endif

}  // namespace test_run_wasm_wrappers
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```