Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

1. **Understand the Core Task:** The primary goal is to analyze a V8 test file (`test-run-wasm-wrappers.cc`) and explain its functionality, especially concerning WASM wrappers.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for important keywords related to WASM and testing. Keywords like `WasmModuleBuilder`, `WasmExportedFunction`, `TEST`, `CHECK`, `FlagScope`, and concepts like "wrapper" are good indicators of the file's purpose. Notice the namespace structure (`v8::internal::wasm::test_run_wasm_wrappers`). This tells you it's an internal V8 test specifically for WASM wrapper functionality.

3. **Identify the Focus: WASM Wrappers:** The filename itself is a strong clue: "test-run-wasm-wrappers.cc". The code repeatedly mentions "generic wrapper" and "specific wrapper." This tells us the file is about testing how JavaScript interacts with WASM through these wrappers.

4. **Analyze Individual Test Cases:**  The file is organized into `TEST` blocks. Each `TEST` likely focuses on a specific aspect of WASM wrapper behavior.

    * **`WrapperBudget`:**  The name suggests it's testing some kind of "budget" associated with wrappers. The code checks `main_function_data->wrapper_budget()`. This likely refers to a counter or limit on how many times a certain type of wrapper can be used.

    * **`WrapperReplacement`:** This clearly indicates a test about replacing one type of wrapper with another. The code checks the `wrapper_code` before and after calls, verifying if it changes from `IsGeneric` to `IsSpecific`.

    * **`EagerWrapperReplacement`:** The "Eager" suggests it's testing a scenario where wrapper replacement happens proactively or under specific conditions, potentially involving multiple exported functions. The test sets a low budget for one function and observes the impact on other functions with the same signature.

    * **`WrapperReplacement_IndirectExport`:**  The "IndirectExport" points to testing wrapper behavior when calling WASM functions indirectly through a table.

    * **`JSToWasmWrapperGarbageCollection`:** This clearly focuses on the lifecycle and garbage collection of the wrappers. The `NumCompiledJSToWasmWrappers` function and the `Cleanup()` call are key here.

5. **Understand the Code Snippets within Tests:** Carefully examine the code within each `TEST`.

    * **`WasmModuleBuilder`:**  This is how WASM modules are created programmatically in the test. Pay attention to how functions are added, exported, and how code is emitted using WASM opcodes.

    * **`CompileModule`:** This function compiles and instantiates the WASM module.

    * **`IsGeneric` and `IsSpecific`:** These functions determine the type of wrapper being used.

    * **`SmiCall`:** This function calls the exported WASM function from the C++ test, passing and checking integer (Smi) arguments.

    * **`FlagScope`:** This is used to temporarily enable or disable V8 flags like `wasm_generic_wrapper`. This is crucial for testing different scenarios.

6. **Infer the Purpose of Generic and Specific Wrappers:**  Based on the test names and code, it becomes clear that:

    * **Generic Wrappers:**  Are likely less optimized and have a "budget" associated with them. They are probably used initially to handle calls to WASM functions.
    * **Specific Wrappers:**  Are more optimized and are created after the generic wrapper's budget is exhausted or under certain conditions.

7. **Connect to JavaScript:**  Think about how these wrappers relate to JavaScript. When JavaScript calls a WASM function, it needs an intermediary to handle the transition between the two environments. The wrappers are this intermediary. The generic wrapper is a fallback, while the specific wrapper is tailored to the function's signature for better performance. This leads to the JavaScript example of calling a WASM function.

8. **Consider Potential Programming Errors:** Think about what could go wrong when interacting with WASM from JavaScript. Incorrect argument types or numbers are common mistakes.

9. **Code Logic and Assumptions:**  For each test, try to determine the input (WASM module structure, initial wrapper budget) and the expected output (wrapper type after calls, budget value). This involves tracing the execution flow within the test.

10. **Structure the Explanation:** Organize the findings logically. Start with a general overview of the file's purpose. Then, explain each test case individually, highlighting its specific focus. Include the JavaScript examples and common errors sections as requested.

11. **Refine and Elaborate:** Review the explanation for clarity and accuracy. Add details and context where needed. For example, explicitly mention the role of `kGenericWrapperBudget`.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the wrappers are about security. **Correction:**  The "budget" concept and the transition from generic to specific suggest optimization is a key factor.
* **Initial thought:** The JavaScript example might need complex WASM API usage. **Correction:** A simple example of calling an exported function is sufficient to illustrate the interaction.
* **Realization:**  The `Cleanup()` function is important. It triggers garbage collection, which is essential for the `JSToWasmWrapperGarbageCollection` test.

By following this structured approach, combining code analysis with reasoning about the underlying concepts of WASM and V8, and iteratively refining the understanding, we can arrive at a comprehensive explanation of the provided C++ test file.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-wrappers.cc` 的功能是 **测试 V8 引擎中 WebAssembly (Wasm) 模块的 JavaScript 到 Wasm 的调用包装器 (wrappers) 的行为**。

具体来说，它测试了以下几个方面：

1. **包装器预算 (Wrapper Budget):**  测试了当使用通用 (generic) 的 JavaScript 到 Wasm 包装器时，调用 Wasm 函数会消耗一定的预算。这个预算可以控制何时将通用的包装器替换为更特定的包装器，以提高性能。

2. **包装器替换 (Wrapper Replacement):** 测试了当通用包装器的预算耗尽时，V8 会将该包装器替换为针对特定 Wasm 函数签名的优化包装器。

3. **积极的包装器替换 (Eager Wrapper Replacement):** 测试了当多个具有相同签名的 Wasm 函数共享一个通用包装器时，对其中一个函数的调用导致包装器升级为特定包装器，会影响到其他共享相同通用包装器的函数。

4. **间接导出的包装器替换 (Wrapper Replacement with Indirect Export):** 测试了通过 Wasm 表 (table) 间接导出的函数，其包装器的替换行为。

5. **JavaScript 到 Wasm 包装器的垃圾回收 (JSToWasmWrapperGarbageCollection):**  测试了当不再有对已编译的 JavaScript 到 Wasm 包装器的引用时，垃圾回收器能够正确地回收这些包装器。

**如果 `v8/test/cctest/wasm/test-run-wasm-wrappers.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码。** Torque 是一种用于编写 V8 内部函数的领域特定语言，它比 C++ 更高级，更安全，并且可以生成优化的机器码。  然而，当前的这个文件是以 `.cc` 结尾，所以它是 C++ 源代码。

**与 JavaScript 的功能关系及示例：**

这个测试文件直接测试了 JavaScript 调用 WebAssembly 函数的机制。当 JavaScript 代码调用一个导出的 Wasm 函数时，V8 引擎需要一个桥梁来处理数据类型的转换和调用约定。这个桥梁就是 JavaScript 到 Wasm 的包装器。

**JavaScript 示例：**

假设在 C++ 测试文件中编译了一个 Wasm 模块，其中包含一个名为 `add` 的导出函数，它接受两个整数参数并返回它们的和。

```javascript
// 假设已经加载了 Wasm 模块实例
const wasmInstance = ...;
const addFunction = wasmInstance.exports.add;

// 调用 Wasm 函数
const result = addFunction(5, 3);
console.log(result); // 输出 8
```

在这个 JavaScript 例子中，`wasmInstance.exports.add` 获取的就是由 V8 创建的 JavaScript 函数，它内部使用了 JavaScript 到 Wasm 的包装器来调用实际的 Wasm 函数。  这个测试文件就是为了确保 V8 在创建和管理这些包装器时的行为是正确的，例如预算控制和替换优化。

**代码逻辑推理及假设输入与输出：**

以 `TEST(WrapperBudget)` 为例：

**假设输入：**

1. 一个简单的 Wasm 模块，导出一个名为 `main` 的函数，该函数接受两个整数参数并返回它们的乘积。
2. 启用了通用 Wasm 包装器 (`v8_flags.wasm_generic_wrapper = true`)。
3. 通用包装器的初始预算为 `kGenericWrapperBudget` (假设为 2)。

**代码逻辑：**

1. 获取导出的 `main` 函数。
2. 第一次调用 `main` 函数。
3. 检查包装器的预算是否减少了 1。
4. 第二次调用 `main` 函数。
5. 检查包装器的预算是否又减少了 1。

**预期输出：**

1. 第一次调用后，包装器预算为 `kGenericWrapperBudget - 1`。
2. 第二次调用后，包装器预算为 `kGenericWrapperBudget - 2`。

**涉及用户常见的编程错误：**

虽然这个测试文件主要关注 V8 内部的机制，但与用户常见的编程错误也有关联，例如：

1. **参数类型不匹配：** 如果 JavaScript 代码传递给 Wasm 函数的参数类型与 Wasm 函数期望的类型不匹配，V8 的包装器需要能够处理这种情况，并可能抛出错误。

   **JavaScript 错误示例：**

   假设 Wasm 的 `add` 函数期望两个整数，但 JavaScript 传递了字符串：

   ```javascript
   const result = addFunction("5", "3"); // 可能会导致错误或意外行为
   ```

2. **参数数量不正确：**  如果 JavaScript 代码传递的参数数量与 Wasm 函数期望的数量不符，也会导致错误。

   **JavaScript 错误示例：**

   ```javascript
   const result = addFunction(5); // 缺少一个参数
   const result2 = addFunction(5, 3, 1); // 多余一个参数
   ```

3. **未正确处理返回值：** 虽然不是包装器直接导致的错误，但用户可能会错误地假设 Wasm 函数的返回值类型，导致在 JavaScript 中使用时出现问题。

**总结：**

`v8/test/cctest/wasm/test-run-wasm-wrappers.cc` 是一个重要的 V8 内部测试文件，它专注于验证 JavaScript 与 WebAssembly 交互的核心机制——JavaScript 到 Wasm 的调用包装器。它通过模拟不同的调用场景和配置，确保 V8 能够正确地创建、管理和优化这些包装器，从而保证 WebAssembly 模块在 V8 引擎中的高效和可靠运行。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-wrappers.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-wrappers.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```