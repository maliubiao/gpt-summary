Response:
Let's break down the thought process for analyzing this C++ code and generating the summary.

1. **Understand the Goal:** The request is to understand the functionality of a specific V8 source code file (`v8/test/cctest/wasm/test-run-wasm-module.cc`). It also asks for connections to JavaScript, code logic examples, common errors, and finally, a summary of the functionality for the provided first part of the code.

2. **Initial Scan and Keywords:** First, quickly scan the code for important keywords and patterns. This gives a high-level overview:
    * `#include`:  Lots of includes related to V8 internals (`src/api`, `src/objects`, `src/wasm`, `test/cctest`, `test/common/wasm`). This confirms it's a C++ test file within the V8 project.
    * `namespace v8::internal::wasm::test_run_wasm_module`: This clearly indicates the file's purpose: testing the execution of WebAssembly modules.
    * `TEST(...)`:  This is the Google Test framework macro, indicating this file contains a series of unit tests. Each `TEST` block represents an individual test case.
    * `WasmModuleBuilder`: This class is used extensively, suggesting the tests involve creating and manipulating WASM modules programmatically.
    * `CompileAndRunWasmModule`, `CompileForTesting`, `CallWasmFunctionForTesting`: These are helper functions for compiling and running WASM code within the tests.
    * `ExportAsMain`:  This function suggests the tests are executing WASM modules where a function named "main" is being called.
    * `WASM_...`:  A lot of macros starting with `WASM_`. These likely represent WASM opcodes or ways to generate WASM bytecode.
    * `MemorySize`, `MemoryGrow`:  These keywords suggest tests related to WASM memory management.
    * `Global`:  Keywords related to WASM globals are present.
    * `Interrupt`:  There's a test related to interrupting WASM execution.
    * `TryCatch`:  Exception handling is being tested.
    * `CompilationHint`:  Features related to WASM compilation hints are being tested.

3. **Analyze Individual Test Cases:**  Go through each `TEST` block and try to understand what it's testing. Focus on:
    * **Test Name:** The name often gives a good hint about the test's purpose (e.g., `Run_WasmModule_Return114`, `Run_WasmModule_CallAdd`, `Run_WasmModule_MemoryGrowInIf`).
    * **WASM Module Construction:** Look at how the `WasmModuleBuilder` is being used. What functions are being added? What code is being emitted? What memory or globals are being defined?
    * **Expected Outcome:** What is the test expecting to happen?  Is it checking for a specific return value, an exception, or a side effect?
    * **Helper Functions:** How are `CompileAndRunWasmModule`, etc., being used? What inputs are they given?

4. **Identify Common Themes and Functionality:** As you analyze the test cases, group them by the functionality they are testing:
    * **Basic Execution:** Running a simple WASM module and checking the return value.
    * **Function Calls:** Calling one WASM function from another.
    * **Memory Access:** Reading and writing to WASM memory, including data segments.
    * **Memory Management:** Testing `memory.size` and `memory.grow`.
    * **Globals:** Getting and setting WASM global variables.
    * **Control Flow:** Testing `if`, `else`, `loop`, and `block` constructs.
    * **Compilation Hints:** Testing different compilation strategies (lazy, eager, tiering).
    * **Interrupts:**  Testing the ability to interrupt WASM execution.
    * **Error Handling:**  Testing scenarios that should throw exceptions (e.g., out-of-bounds memory access).
    * **Module Loading and Instantiation:** How modules are compiled and instantiated.

5. **Connect to JavaScript (if applicable):** For functionalities that have a direct JavaScript counterpart, provide examples:
    * WASM modules are loaded and instantiated using the `WebAssembly` API in JavaScript.
    * WASM memory corresponds to `WebAssembly.Memory`.
    * WASM globals correspond to `WebAssembly.Global`.
    * Calling WASM functions from JavaScript.

6. **Illustrate Code Logic with Examples:**  For tests involving specific WASM logic, create simplified input and output scenarios:
    * Example: A function that adds two numbers. Show the input values and the expected output.

7. **Highlight Common Programming Errors:** Based on the tests that check for exceptions or specific behavior, identify potential common errors:
    * Out-of-bounds memory access.
    * Incorrect function calls.
    * Issues with global variable initialization.

8. **Address Specific Questions:**  Answer the direct questions in the prompt:
    * Is it Torque? (No, it's C++)
    * Relationship to JavaScript (provide examples).

9. **Synthesize the Summary:**  Combine the identified themes and functionalities into a concise summary of the code's purpose. Emphasize that it's a test suite for verifying the correct execution of various WASM features within the V8 engine.

10. **Review and Refine:** Read through the generated summary and examples. Ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might just list "memory tests," but refining it to "testing memory access, `memory.size`, and `memory.grow`" is more informative.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and accurate summary that addresses all aspects of the request. The iterative process of scanning, analyzing, identifying themes, and then synthesizing the information is crucial for understanding complex codebases.
好的，让我们来分析一下 `v8/test/cctest/wasm/test-run-wasm-module.cc` 这个文件的功能。

**功能归纳:**

总的来说，`v8/test/cctest/wasm/test-run-wasm-module.cc`  是 V8 引擎中用于测试 WebAssembly (Wasm) 模块运行的核心测试文件。 它包含了大量的单元测试，用于验证 V8 的 Wasm 引擎在执行各种 Wasm 模块时的行为是否符合预期。

**具体功能点:**

1. **Wasm 模块的编译和运行:**  该文件中的测试用例会创建不同的 Wasm 模块（通过 `WasmModuleBuilder`），然后使用 V8 的接口编译和运行这些模块。这包括：
    * **成功执行:** 测试 Wasm 模块在正常情况下的执行结果是否正确。例如，测试返回特定值的函数。
    * **异常处理:** 测试当 Wasm 模块执行出错时，V8 能否正确捕获和处理异常。

2. **Wasm 指令的测试:**  每个测试用例通常会关注 Wasm 的一个或多个指令或特性，例如：
    * **基本算术运算:**  测试加法 (`i32.add`) 等指令。
    * **函数调用:** 测试 Wasm 模块内部的函数调用 (`call`)。
    * **内存访问:** 测试从 Wasm 线性内存中加载 (`load`) 和存储 (`store`) 数据。
    * **全局变量:** 测试 Wasm 的全局变量的读取 (`global.get`) 和写入 (`global.set`)。
    * **内存管理:** 测试 `memory.size` 和 `memory.grow` 指令，以及内存增长的边界情况。
    * **控制流:** 测试 `if`, `else`, `loop`, `block` 等控制流指令。

3. **Wasm 模块的元数据测试:**  测试与 Wasm 模块结构相关的特性，例如：
    * **数据段 (Data Segment):** 测试 Wasm 模块加载时，数据段是否被正确初始化到内存中。
    * **内存大小:** 测试 Wasm 模块初始内存大小和增长后的内存大小是否符合预期。
    * **全局变量初始化:** 测试全局变量的初始值是否被正确设置。

4. **Wasm 编译优化的测试 (涉及 Compilation Hints):**  测试 V8 的 Wasm 编译器提供的编译提示功能，例如：
    * **Lazy Compilation (延迟编译):**  测试函数是否在第一次调用时才被编译。
    * **Tiering Compilation (分层编译):** 测试 Wasm 代码是否会根据执行情况进行优化，从 Baseline (Liftoff) 逐步升级到 Optimized (TurboFan)。
    * **Eager Compilation (立即编译):** 测试函数是否在模块加载时就被编译。

5. **中断 (Interrupt) 功能测试:**  测试在执行长时间运行的 Wasm 代码时，V8 是否能够正确地中断执行。

**关于文件后缀和 Torque:**

你提到如果文件以 `.tq` 结尾，则它是 Torque 源代码。`v8/test/cctest/wasm/test-run-wasm-module.cc` 的后缀是 `.cc`，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 TurboFan 代码。

**与 JavaScript 的关系及示例:**

WebAssembly 的主要目标之一是作为 JavaScript 的补充，提供接近原生的性能。 `v8/test/cctest/wasm/test-run-wasm-module.cc` 中测试的许多 Wasm 功能都可以在 JavaScript 中通过 `WebAssembly` API 来使用。

**JavaScript 示例:**

```javascript
// 假设我们有一个简单的 Wasm 模块，它导出一个名为 "add" 的函数，
// 该函数接受两个 i32 类型的参数并返回它们的和。

// Wasm 模块的二进制表示 (简化示例)
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // 模块头
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 类型定义: (i32, i32) => i32
  0x03, 0x02, 0x01, 0x00, // 函数定义: 索引 0 使用类型索引 0
  0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00, // 导出 "add" 函数 (索引 0)
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // 函数体: local.get 0, local.get 1, i32.add, end
]);

WebAssembly.instantiate(wasmCode)
  .then(result => {
    const addFunction = result.instance.exports.add;
    const sum = addFunction(5, 10);
    console.log(sum); // 输出: 15
  });
```

在这个 JavaScript 示例中：

* `wasmCode` 代表一个简单的 Wasm 模块的二进制数据。
* `WebAssembly.instantiate` 用于编译和实例化 Wasm 模块。
* `result.instance.exports.add` 获取导出的 `add` 函数。
* 我们可以像调用普通的 JavaScript 函数一样调用 Wasm 函数。

`v8/test/cctest/wasm/test-run-wasm-module.cc` 中的许多测试用例，比如测试 `i32.add`，实际上就是在 V8 内部测试这种 JavaScript 与 Wasm 交互的基础功能是否正常工作。

**代码逻辑推理示例 (假设输入与输出):**

假设 `v8/test/cctest/wasm/test-run-wasm-module.cc` 中有一个测试用例名为 `Run_WasmModule_AddIntegers`，其代码逻辑大致如下：

```c++
TEST(Run_WasmModule_AddIntegers) {
  // ... (创建 Zone, TestSignatures 等) ...

  WasmModuleBuilder builder(&zone);
  WasmFunctionBuilder* f = builder.AddFunction(sigs.i_ii()); // 接受两个 i32，返回 i32
  ExportAsMain(f);
  uint8_t code[] = {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_I32_ADD};
  EMIT_CODE_WITH_END(f, code);

  // ... (编译和运行模块) ...
  int32_t result = testing::CompileAndRunWasmModule(isolate, buffer.begin(), buffer.end(), {10, 20});
  CHECK_EQ(30, result);
}
```

**假设输入:**  如果我们将这个编译后的 Wasm 模块运行，并传递输入参数 10 和 20。

**输出:**  该 Wasm 模块（包含一个将两个输入相加的函数）的预期输出是 `30`。

**用户常见的编程错误示例:**

当用户编写 Wasm 代码或与 Wasm 交互时，可能会遇到以下常见错误，而 `v8/test/cctest/wasm/test-run-wasm-module.cc` 中的测试也在一定程度上覆盖了这些情况：

1. **内存越界访问:** Wasm 内存是线性的，如果尝试访问超出分配内存范围的地址，会导致错误。
   ```javascript
   // JavaScript 中尝试越界写入 Wasm 内存
   const memory = new WebAssembly.Memory({ initial: 1 }); // 1 页内存 (64KB)
   const buffer = new Uint8Array(memory.buffer);
   buffer[65536] = 0; // 错误：访问超出范围
   ```
   `Run_WasmModule_GrowMemOobOffset` 和 `Run_WasmModule_GrowMemOobVariableIndex` 等测试用例就在测试 V8 是否能正确处理 Wasm 代码中的内存越界访问。

2. **类型不匹配:**  在调用 Wasm 函数时，传递的参数类型必须与函数签名匹配。
   ```javascript
   // 假设 Wasm 函数接受一个 i32 参数
   const wasmCode = // ... (定义一个接受 i32 的 Wasm 函数)
   WebAssembly.instantiate(wasmCode)
     .then(result => {
       const func = result.instance.exports.myFunc;
       func("hello"); // 错误：传递了字符串而不是数字
     });
   ```
   虽然 `v8/test/cctest/wasm/test-run-wasm-module.cc` 主要侧重于 Wasm 内部的执行，但其确保了 V8 能够正确处理函数调用和类型。

3. **未导出的函数或变量:**  尝试访问 Wasm 模块中未显式导出的函数或全局变量。
   ```javascript
   const wasmCode = // ... (定义一个没有导出任何东西的 Wasm 模块)
   WebAssembly.instantiate(wasmCode)
     .then(result => {
       console.log(result.instance.exports.myFunc); // 错误：myFunc 未定义
     });
   ```

**总结 `v8/test/cctest/wasm/test-run-wasm-module.cc` 的功能 (第 1 部分):**

`v8/test/cctest/wasm/test-run-wasm-module.cc` 的第 1 部分主要关注于测试 V8 引擎执行基本 WebAssembly 模块的能力，包括：

* **执行简单的 Wasm 函数并验证返回值。**
* **测试 Wasm 编译提示 (Compilation Hints) 的不同策略 (Lazy, Eager, Tier-Up) 的行为。**
* **测试 Wasm 模块内部的函数调用。**
* **测试从 Wasm 模块的数据段加载数据到内存。**
* **测试基本的 Wasm 控制流结构 (如循环和条件语句)。**
* **测试 Wasm 全局变量的读取和写入。**
* **测试 Wasm 内存的查询大小和增长操作，并验证边界情况下的行为 (如内存越界)。**
* **测试在 Wasm 代码执行过程中进行中断的能力。**

总而言之，这部分测试旨在确保 V8 的 Wasm 引擎能够正确、高效地执行各种基本的 Wasm 功能，为更复杂的 Wasm 应用提供坚实的基础。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-module.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-module.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>
#include <string.h>

#include <atomic>

#include "src/api/api-inl.h"
#include "src/objects/objects-inl.h"
#include "src/snapshot/code-serializer.h"
#include "src/utils/version.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/cctest.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_module {

using base::ReadLittleEndianValue;
using base::WriteLittleEndianValue;
using testing::CompileAndInstantiateForTesting;

namespace {
void Cleanup(Isolate* isolate = CcTest::InitIsolateOnce()) {
  // By sending a low memory notifications, we will try hard to collect all
  // garbage and will therefore also invoke all weak callbacks of actually
  // unreachable persistent handles.
  reinterpret_cast<v8::Isolate*>(isolate)->LowMemoryNotification();
}

void TestModule(Zone* zone, WasmModuleBuilder* builder,
                int32_t expected_result) {
  ZoneBuffer buffer(zone);
  builder->WriteTo(&buffer);

  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  testing::SetupIsolateForWasmModule(isolate);
  int32_t result =
      testing::CompileAndRunWasmModule(isolate, buffer.begin(), buffer.end());
  CHECK_EQ(expected_result, result);
}

void TestModuleException(Zone* zone, WasmModuleBuilder* builder) {
  ZoneBuffer buffer(zone);
  builder->WriteTo(&buffer);

  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  testing::SetupIsolateForWasmModule(isolate);
  v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  testing::CompileAndRunWasmModule(isolate, buffer.begin(), buffer.end());
  CHECK(try_catch.HasCaught());
  isolate->clear_exception();
}

void ExportAsMain(WasmFunctionBuilder* f) {
  f->builder()->AddExport(base::CStrVector("main"), f);
}

#define EMIT_CODE_WITH_END(f, code)  \
  do {                               \
    f->EmitCode(code, sizeof(code)); \
    f->Emit(kExprEnd);               \
  } while (false)

}  // namespace

TEST(Run_WasmModule_Return114) {
  {
    static const int32_t kReturnValue = 114;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_I32V_2(kReturnValue)};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, kReturnValue);
  }
  Cleanup();
}

TEST(Run_WasmModule_CompilationHintsLazy) {
  if (!v8_flags.wasm_tier_up || !v8_flags.liftoff) return;
  {
    EXPERIMENTAL_FLAG_SCOPE(compilation_hints);

    static const int32_t kReturnValue = 114;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    // Build module with one lazy function.
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_I32V_2(kReturnValue)};
    EMIT_CODE_WITH_END(f, code);
    f->SetCompilationHint(WasmCompilationHintStrategy::kLazy,
                          WasmCompilationHintTier::kBaseline,
                          WasmCompilationHintTier::kOptimized);

    // Compile module. No function is actually compiled as the function is lazy.
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);
    ErrorThrower thrower(isolate, "CompileAndRunWasmModule");
    MaybeHandle<WasmModuleObject> module = testing::CompileForTesting(
        isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
    CHECK(!module.is_null());

    // Lazy function was not invoked and therefore not compiled yet.
    static const int kFuncIndex = 0;
    NativeModule* native_module = module.ToHandleChecked()->native_module();
    CHECK(!native_module->HasCode(kFuncIndex));
    auto* compilation_state = native_module->compilation_state();
    CHECK(compilation_state->baseline_compilation_finished());

    // Instantiate and invoke function.
    MaybeHandle<WasmInstanceObject> instance = GetWasmEngine()->SyncInstantiate(
        isolate, &thrower, module.ToHandleChecked(), {}, {});
    CHECK(!instance.is_null());
    int32_t result = testing::CallWasmFunctionForTesting(
        isolate, instance.ToHandleChecked(), "main", {});
    CHECK_EQ(kReturnValue, result);

    // Lazy function was invoked and therefore compiled.
    CHECK(native_module->HasCode(kFuncIndex));
    WasmCodeRefScope code_ref_scope;
    ExecutionTier actual_tier = native_module->GetCode(kFuncIndex)->tier();
    static_assert(ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                  "Assume an order on execution tiers");
    ExecutionTier baseline_tier = ExecutionTier::kLiftoff;
    CHECK_LE(baseline_tier, actual_tier);
    CHECK(compilation_state->baseline_compilation_finished());
  }
  Cleanup();
}

TEST(Run_WasmModule_CompilationHintsNoTiering) {
  FlagScope<bool> no_lazy_compilation(&v8_flags.wasm_lazy_compilation, false);
  if (!v8_flags.wasm_tier_up || !v8_flags.liftoff) return;
  {
    EXPERIMENTAL_FLAG_SCOPE(compilation_hints);

    static const int32_t kReturnValue = 114;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    // Build module with regularly compiled function (no tiering).
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_I32V_2(kReturnValue)};
    EMIT_CODE_WITH_END(f, code);
    f->SetCompilationHint(WasmCompilationHintStrategy::kEager,
                          WasmCompilationHintTier::kBaseline,
                          WasmCompilationHintTier::kBaseline);

    // Compile module.
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);
    ErrorThrower thrower(isolate, "CompileAndRunWasmModule");
    MaybeHandle<WasmModuleObject> module = testing::CompileForTesting(
        isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
    CHECK(!module.is_null());

    // Synchronous compilation finished and no tiering units were initialized.
    static const int kFuncIndex = 0;
    NativeModule* native_module = module.ToHandleChecked()->native_module();
    CHECK(native_module->HasCode(kFuncIndex));
    ExecutionTier expected_tier = ExecutionTier::kLiftoff;
    WasmCodeRefScope code_ref_scope;
    ExecutionTier actual_tier = native_module->GetCode(kFuncIndex)->tier();
    CHECK_EQ(expected_tier, actual_tier);
    auto* compilation_state = native_module->compilation_state();
    CHECK(compilation_state->baseline_compilation_finished());
  }
  Cleanup();
}

TEST(Run_WasmModule_CompilationHintsTierUp) {
  FlagScope<bool> no_wasm_dynamic_tiering(&v8_flags.wasm_dynamic_tiering,
                                          false);
  FlagScope<bool> no_lazy_compilation(&v8_flags.wasm_lazy_compilation, false);
  if (!v8_flags.wasm_tier_up || !v8_flags.liftoff) return;
  {
    EXPERIMENTAL_FLAG_SCOPE(compilation_hints);

    static const int32_t kReturnValue = 114;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    // Build module with tiering compilation hint.
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_I32V_2(kReturnValue)};
    EMIT_CODE_WITH_END(f, code);
    f->SetCompilationHint(WasmCompilationHintStrategy::kEager,
                          WasmCompilationHintTier::kBaseline,
                          WasmCompilationHintTier::kOptimized);

    // Compile module.
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);
    ErrorThrower thrower(isolate, "CompileAndRunWasmModule");
    MaybeHandle<WasmModuleObject> module = testing::CompileForTesting(
        isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
    CHECK(!module.is_null());

    // Expect baseline or top tier code.
    static const int kFuncIndex = 0;
    NativeModule* native_module = module.ToHandleChecked()->native_module();
    auto* compilation_state = native_module->compilation_state();
    static_assert(ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                  "Assume an order on execution tiers");
    ExecutionTier baseline_tier = ExecutionTier::kLiftoff;
    {
      CHECK(native_module->HasCode(kFuncIndex));
      WasmCodeRefScope code_ref_scope;
      ExecutionTier actual_tier = native_module->GetCode(kFuncIndex)->tier();
      CHECK_LE(baseline_tier, actual_tier);
      CHECK(compilation_state->baseline_compilation_finished());
    }

    // Tier-up is happening in the background. Eventually we should have top
    // tier code.
    ExecutionTier top_tier = ExecutionTier::kTurbofan;
    ExecutionTier actual_tier = ExecutionTier::kNone;
    while (actual_tier != top_tier) {
      CHECK(native_module->HasCode(kFuncIndex));
      WasmCodeRefScope code_ref_scope;
      actual_tier = native_module->GetCode(kFuncIndex)->tier();
    }
  }
  Cleanup();
}

TEST(Run_WasmModule_CompilationHintsLazyBaselineEagerTopTier) {
  FlagScope<bool> no_wasm_dynamic_tiering(&v8_flags.wasm_dynamic_tiering,
                                          false);
  FlagScope<bool> no_lazy_compilation(&v8_flags.wasm_lazy_compilation, false);
  if (!v8_flags.wasm_tier_up || !v8_flags.liftoff) return;
  {
    EXPERIMENTAL_FLAG_SCOPE(compilation_hints);

    static const int32_t kReturnValue = 114;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    // Build module with tiering compilation hint.
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_I32V_2(kReturnValue)};
    EMIT_CODE_WITH_END(f, code);
    f->SetCompilationHint(
        WasmCompilationHintStrategy::kLazyBaselineEagerTopTier,
        WasmCompilationHintTier::kBaseline,
        WasmCompilationHintTier::kOptimized);

    // Compile module.
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);
    ErrorThrower thrower(isolate, "CompileAndRunWasmModule");
    MaybeHandle<WasmModuleObject> module = testing::CompileForTesting(
        isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
    CHECK(!module.is_null());

    NativeModule* native_module = module.ToHandleChecked()->native_module();
    auto* compilation_state = native_module->compilation_state();

    // We have no code initially (because of lazy baseline), but eventually we
    // should have TurboFan ready (because of eager top tier).
    static_assert(ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                  "Assume an order on execution tiers");
    constexpr int kFuncIndex = 0;
    WasmCodeRefScope code_ref_scope;
    while (true) {
      auto* code = native_module->GetCode(kFuncIndex);
      if (!code) continue;
      CHECK_EQ(ExecutionTier::kTurbofan, code->tier());
      break;
    }
    CHECK(compilation_state->baseline_compilation_finished());
  }
  Cleanup();
}

TEST(Run_WasmModule_CallAdd) {
  {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    TestSignatures sigs;

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);

    WasmFunctionBuilder* f1 = builder->AddFunction(sigs.i_ii());
    uint16_t param1 = 0;
    uint16_t param2 = 1;
    uint8_t code1[] = {
        WASM_I32_ADD(WASM_LOCAL_GET(param1), WASM_LOCAL_GET(param2))};
    EMIT_CODE_WITH_END(f1, code1);

    WasmFunctionBuilder* f2 = builder->AddFunction(sigs.i_v());

    ExportAsMain(f2);
    uint8_t code2[] = {
        WASM_CALL_FUNCTION(f1->func_index(), WASM_I32V_2(77), WASM_I32V_1(22))};
    EMIT_CODE_WITH_END(f2, code2);
    TestModule(&zone, builder, 99);
  }
  Cleanup();
}

TEST(Run_WasmModule_ReadLoadedDataSegment) {
  {
    static const uint8_t kDataSegmentDest0 = 12;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    TestSignatures sigs;

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());

    ExportAsMain(f);
    uint8_t code[] = {
        WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V_1(kDataSegmentDest0))};
    EMIT_CODE_WITH_END(f, code);
    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    builder->AddDataSegment(data, sizeof(data), kDataSegmentDest0);
    TestModule(&zone, builder, 0xDDCCBBAA);
  }
  Cleanup();
}

TEST(Run_WasmModule_CheckMemoryIsZero) {
  {
    static const int kCheckSize = 16 * 1024;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    TestSignatures sigs;

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());

    uint16_t localIndex = f->AddLocal(kWasmI32);
    ExportAsMain(f);
    uint8_t code[] = {WASM_BLOCK_I(
        WASM_WHILE(
            WASM_I32_LTS(WASM_LOCAL_GET(localIndex), WASM_I32V_3(kCheckSize)),
            WASM_IF_ELSE(
                WASM_LOAD_MEM(MachineType::Int32(), WASM_LOCAL_GET(localIndex)),
                WASM_BRV(3, WASM_I32V_1(-1)),
                WASM_INC_LOCAL_BY(localIndex, 4))),
        WASM_I32V_1(11))};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, 11);
  }
  Cleanup();
}

TEST(Run_WasmModule_CallMain_recursive) {
  {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    TestSignatures sigs;

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());

    uint16_t localIndex = f->AddLocal(kWasmI32);
    ExportAsMain(f);
    uint8_t code[] = {
        WASM_LOCAL_SET(localIndex,
                       WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)),
        WASM_IF_ELSE_I(WASM_I32_LTS(WASM_LOCAL_GET(localIndex), WASM_I32V_1(5)),
                       WASM_SEQ(WASM_STORE_MEM(MachineType::Int32(), WASM_ZERO,
                                               WASM_INC_LOCAL(localIndex)),
                                WASM_CALL_FUNCTION0(0)),
                       WASM_I32V_1(55))};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, 55);
  }
  Cleanup();
}

TEST(Run_WasmModule_Global) {
  {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    TestSignatures sigs;

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    uint32_t global1 = builder->AddGlobal(kWasmI32, true, WasmInitExpr(0));
    uint32_t global2 = builder->AddGlobal(kWasmI32, true, WasmInitExpr(0));
    WasmFunctionBuilder* f1 = builder->AddFunction(sigs.i_v());
    uint8_t code1[] = {
        WASM_I32_ADD(WASM_GLOBAL_GET(global1), WASM_GLOBAL_GET(global2))};
    EMIT_CODE_WITH_END(f1, code1);
    WasmFunctionBuilder* f2 = builder->AddFunction(sigs.i_v());
    ExportAsMain(f2);
    uint8_t code2[] = {WASM_GLOBAL_SET(global1, WASM_I32V_1(56)),
                       WASM_GLOBAL_SET(global2, WASM_I32V_1(41)),
                       WASM_RETURN(WASM_CALL_FUNCTION0(f1->func_index()))};
    EMIT_CODE_WITH_END(f2, code2);
    TestModule(&zone, builder, 97);
  }
  Cleanup();
}

TEST(MemorySize) {
  {
    // Initial memory size is 16, see wasm-module-builder.cc
    static const int kExpectedValue = 16;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_MEMORY_SIZE};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, kExpectedValue);
  }
  Cleanup();
}

TEST(Run_WasmModule_MemSize_GrowMem) {
  {
    // Initial memory size = 16 + MemoryGrow(10)
    static const int kExpectedValue = 26;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_MEMORY_GROW(WASM_I32V_1(10)), WASM_DROP,
                      WASM_MEMORY_SIZE};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, kExpectedValue);
  }
  Cleanup();
}

TEST(MemoryGrowZero) {
  {
    // Initial memory size is 16, see wasm-module-builder.cc
    static const int kExpectedValue = 16;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_MEMORY_GROW(WASM_I32V(0))};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, kExpectedValue);
  }
  Cleanup();
}

class InterruptThread : public v8::base::Thread {
 public:
  explicit InterruptThread(Isolate* isolate, std::atomic<int32_t>* memory)
      : Thread(Options("TestInterruptLoop")),
        isolate_(isolate),
        memory_(memory) {}

  static void OnInterrupt(v8::Isolate* isolate, void* data) {
    int32_t* m = reinterpret_cast<int32_t*>(data);
    // Set the interrupt location to 0 to break the loop in {TestInterruptLoop}.
    Address ptr = reinterpret_cast<Address>(&m[interrupt_location_]);
    WriteLittleEndianValue<int32_t>(ptr, interrupt_value_);
  }

  void Run() override {
    // Wait for the main thread to write the signal value.
    int32_t val = 0;
    do {
      val = memory_[0].load(std::memory_order_relaxed);
      val = ReadLittleEndianValue<int32_t>(reinterpret_cast<Address>(&val));
    } while (val != signal_value_);
    isolate_->RequestInterrupt(&OnInterrupt, memory_);
  }

  Isolate* isolate_;
  std::atomic<int32_t>* memory_;
  static const int32_t interrupt_location_ = 10;
  static const int32_t interrupt_value_ = 154;
  static const int32_t signal_value_ = 1221;
};

TEST(TestInterruptLoop) {
  {
    // Do not dump the module of this test because it contains an infinite loop.
    if (v8_flags.dump_wasm_module) return;

    // This test tests that WebAssembly loops can be interrupted, i.e. that if
    // an
    // InterruptCallback is registered by {Isolate::RequestInterrupt}, then the
    // InterruptCallback is eventually called even if a loop in WebAssembly code
    // is executed.
    // Test setup:
    // The main thread executes a WebAssembly function with a loop. In the loop
    // {signal_value_} is written to memory to signal a helper thread that the
    // main thread reached the loop in the WebAssembly program. When the helper
    // thread reads {signal_value_} from memory, it registers the
    // InterruptCallback. Upon exeution, the InterruptCallback write into the
    // WebAssemblyMemory to end the loop in the WebAssembly program.
    TestSignatures sigs;
    Isolate* isolate = CcTest::InitIsolateOnce();
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {
        WASM_LOOP(
            WASM_IF(WASM_NOT(WASM_LOAD_MEM(
                        MachineType::Int32(),
                        WASM_I32V(InterruptThread::interrupt_location_ * 4))),
                    WASM_STORE_MEM(MachineType::Int32(), WASM_ZERO,
                                   WASM_I32V(InterruptThread::signal_value_)),
                    WASM_BR(1))),
        WASM_I32V(121)};
    EMIT_CODE_WITH_END(f, code);
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);

    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);
    ErrorThrower thrower(isolate, "Test");
    const Handle<WasmInstanceObject> instance =
        CompileAndInstantiateForTesting(
            isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()))
            .ToHandleChecked();

    DirectHandle<JSArrayBuffer> memory(
        instance->trusted_data(isolate)->memory_object(0)->array_buffer(),
        isolate);
    std::atomic<int32_t>* memory_array =
        reinterpret_cast<std::atomic<int32_t>*>(memory->backing_store());

    InterruptThread thread(isolate, memory_array);
    CHECK(thread.Start());
    testing::CallWasmFunctionForTesting(isolate, instance, "main", {});
    Address address = reinterpret_cast<Address>(
        &memory_array[InterruptThread::interrupt_location_]);
    CHECK_EQ(InterruptThread::interrupt_value_,
             ReadLittleEndianValue<int32_t>(address));
  }
  Cleanup();
}

TEST(Run_WasmModule_MemoryGrowInIf) {
  {
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_IF_ELSE_I(
        WASM_I32V(0), WASM_MEMORY_GROW(WASM_I32V(1)), WASM_I32V(12))};
    EMIT_CODE_WITH_END(f, code);
    TestModule(&zone, builder, 12);
  }
  Cleanup();
}

TEST(Run_WasmModule_GrowMemOobOffset) {
  {
    static const int kPageSize = 0x10000;
    // Initial memory size = 16 + MemoryGrow(10)
    static const int index = kPageSize * 17 + 4;
    int value = 0xACED;
    TestSignatures sigs;
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
    ExportAsMain(f);
    uint8_t code[] = {WASM_MEMORY_GROW(WASM_I32V_1(1)),
                      WASM_STORE_MEM(MachineType::Int32(), WASM_I32V(index),
                                     WASM_I32V(value))};
    EMIT_CODE_WITH_END(f, code);
    TestModuleException(&zone, builder);
  }
  Cleanup();
}

TEST(Run_WasmModule_GrowMemOobFixedIndex) {
  {
    static const int kPageSize = 0x10000;
    // Initial memory size = 16 + MemoryGrow(10)
    static const int index = kPageSize * 26 + 4;
    int value = 0xACED;
    TestSignatures sigs;
    Isolate* isolate = CcTest::InitIsolateOnce();
    Zone zone(isolate->allocator(), ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_i());
    ExportAsMain(f);
    uint8_t code[] = {WASM_MEMORY_GROW(WASM_LOCAL_GET(0)), WASM_DROP,
                      WASM_STORE_MEM(MachineType::Int32(), WASM_I32V(index),
                                     WASM_I32V(value)),
                      WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V(index))};
    EMIT_CODE_WITH_END(f, code);

    HandleScope scope(isolate);
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);
    testing::SetupIsolateForWasmModule(isolate);

    ErrorThrower thrower(isolate, "Test");
    Handle<WasmInstanceObject> instance =
        CompileAndInstantiateForTesting(
            isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()))
            .ToHandleChecked();

    // Initial memory size is 16 pages, should trap till index > MemSize on
    // consecutive GrowMem calls
    for (uint32_t i = 1; i < 5; i++) {
      Handle<Object> params[1] = {handle(Smi::FromInt(i), isolate)};
      v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
      testing::CallWasmFunctionForTesting(isolate, instance, "main",
                                          base::ArrayVector(params));
      CHECK(try_catch.HasCaught());
      isolate->clear_exception();
    }

    Handle<Object> params[1] = {handle(Smi::FromInt(1), isolate)};
    int32_t result = testing::CallWasmFunctionForTesting(
        isolate, instance, "main", base::ArrayVector(params));
    CHECK_EQ(0xACED, result);
  }
  Cleanup();
}

TEST(Run_WasmModule_GrowMemOobVariableIndex) {
  {
    static const int kPageSize = 0x10000;
    int value = 0xACED;
    TestSignatures sigs;
    Isolate* isolate = CcTest::InitIsolateOnce();
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    builder->AddMemory(16);
    WasmFunctionBuilder* f = builder->AddFunction(sigs.i_i());
    ExportAsMain(f);
    uint8_t code[] = {WASM_MEMORY_GROW(WASM_I32V_1(1)), WASM_DROP,
                      WASM_STORE_MEM(MachineType::Int32(), WASM_LOCAL_GET(0),
                                     WASM_I32V(value)),
                      WASM_LOAD_MEM(MachineType::Int32(), WASM_LOCAL_GET(0))};
    EMIT_CODE_WITH_END(f, code);

    HandleScope scope(isolate);
    ZoneBuffer buffer(&zone);
    builder->WriteTo(&buffer);
    testing::SetupIsolateForWasmModule(isolate);

    ErrorThrower thrower(isolate, "Test");
    Handle<WasmInstanceObject> instance =
        CompileAndInstantiateForTesting(
            isolate, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()))
            .ToHandleChecked();

    // Initial memory size is 16 pages, should trap till index > MemSize on
    // consecutive GrowMem calls
    for (int i = 1; i < 5; i++) {
      Handle<Object> params[1] = {
          Handle<Object>(Smi::FromInt((16 + i) * kPageSize - 3), isolate)};
      v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
      testing::CallWasmFunctionForTesting(isolate, instance, "main",
                                          base::ArrayVector(params));
      CHECK(try_catch.HasCaught());
      isolate->clear_exception();
    }

    for (int i = 1; i < 5; i++) {
      Handle<Object> params[1] = {
          handle(Smi::FromInt((20 + i) * kPageSize - 4), isolate)};
      int32_t result = testing::CallWasmFunctionForTesting(
          isolate, instance, "main", base::ArrayVector(params));
      CHECK_EQ(0xACED, result);
    }

    v8::TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
    Handle<Object> params[1] = {handle(Smi::FromInt(25 * kPageSize), isolate)};
    testing::CallWasmFunctionForTesting(isolate, instance, "main",
                                        base::ArrayVector(params));
    CHECK(try_catch.HasCaught());
    isolate->clear_exception();
  }
  Cleanup();
}

TEST(Run_WasmModule_Global_init) {
  {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    TestSignatures sigs;

    WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
    uint32_t global1 =
        builder->AddGlobal(kWasmI32, false, WasmInitExpr(777777));
    uint32_t global2 =
        builder->AddGlobal(kWasmI32, false, WasmInitExpr(222222));
    WasmFunctionBuilder* f1 = builder->AddFunction(sigs.i_v());
    uint8_t code[] = {
        WASM_I32_ADD(WASM_GLOBAL_GET(global1), WASM_GLOBAL_GET(global2))};
    EMIT_CODE_WITH_END(f1, code);
    ExportAsMain(f1);
    TestModule(&zone, builder, 999999);
  }
  Cleanup();
}

template <typename CType>
static void RunWasmModuleGlobalInitTest(ValueType type, CType expected) {
  {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);

    ValueType types[] = {type};
    FunctionSig sig(1, 0, types);

    for (int padding = 0; padding < 5; padding++) {
      // Test with a simple initializer
      WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);

      for (int i = 0; i < padding; i++) {  // pad global before
        builder->AddGlobal(kWasmI32, false, WasmInitExpr(i + 20000));
      }
      uint32_t global = builder->AddGlobal(type, false, WasmInitExpr(expected));
      for (int i = 0; i < padding; i++) {  // pad global after
        builder->AddGlobal(kWasmI32, false, WasmInitExpr(i + 30000));
      }

      WasmFunctionBuilder* f1 = builder->AddFunction(&sig);
      uint8_t code[] = {WASM_GLOBAL_GET(global)};
      EMIT_CODE_WITH_END(f1, code);
      ExportAsMain(f1);
      TestModule(&zone, builder, expected);
    }
  }
  Cleanup();
}

TEST(Run_WasmModule_Global_i32) {
  RunWasmModuleGlobalInitTest<int32_t>(kWasmI32, -983489);
  RunWasmModuleGlobalInitTest<int32_t>(kWasmI32, 11223344);
}

TEST(Run_WasmModule_Global_f32) {
  RunWasmModuleGlobalInitTest<float>(kWasmF32, -983.9f);
  RunWasmModuleGlobalInitTest<float>(kWasmF32, 1122.99f);
}

TEST(Run_WasmModule_Global_f64) {
  RunWasmModuleGlobalInitTest<double>(kWasmF64, -833.9);
  RunWasmModuleGlobalInitTest<double>(kWasmF64, 86374.25);
}

TEST(InitDataAtTheUpperLimit) {
  {
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);

    ErrorThrower thrower(isolate, "Run_WasmModule_InitDataAtTheUpperLimit");

    const uint8_t data[] = {
        WASM_MODULE_HEADER,   // --
        kMemorySectionCode,   // --
        U32V_1(4),            // section size
        ENTRY_COUNT(1),       // --
        kWithMaximum,         // --
        1,                    // initial size
        2,                    // maximum size
        kDataSectionCode,     // --
        U32V_1(9),            // section size
        ENTRY_COUNT(1),       // --
        0,                    // linear memory index
        WASM_I32V_3(0xFFFF),  // destination offset
        kExprEnd,
        U32V_1(1),  // source size
        'c'         // data bytes
    };

    CompileAndInstantiateForTesting(
        isolate, &thrower, ModuleWireBytes(data, data + arraysize(data)));
    if (thrower.error()) {
      Print(*thrower.Reify());
      FATAL("compile or instantiate error");
    }
  }
  Cleanup();
}

TEST(EmptyMemoryNonEmptyDataSegment) {
  {
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);

    ErrorThrower thrower(isolate, "Run_WasmModule_InitDataAtTheUpperLimit");

    const uint8_t data[] = {
        WASM_MODULE_HEADER,  // --
        kMemorySectionCode,  // --
        U32V_1(4),           // section size
        ENTRY_COUNT(1),      // --
        kWithMaximum,        // --
        0,                   // initial size
        0,                   // maximum size
        kDataSectionCode,    // --
        U32V_1(7),           // section size
        ENTRY_COUNT(1),      // --
        0,                   // linear memory index
        WASM_I32V_1(8),      // destination offset
        kExprEnd,
        U32V_1(1),  // source size
        'c'         // data bytes
    };

    CompileAndInstantiateForTesting(
        isolate, &thrower, ModuleWireBytes(data, data + arraysize(data)));
    // It should not be possible to instantiate this module.
    CHECK(thrower.error());
  }
  Cleanup();
}

TEST(EmptyMemoryEmptyDataSegment) {
  {
    Isolate* isolate = CcTest::InitIsolateOnce();
    HandleScope scope(isolate);
    testing::SetupIsolateForWasmModule(isolate);

    ErrorThrower thrower(isolate, "Run_WasmModule_InitDataAtTheUpperLimit");

    const uint8_t data[] = {
        WASM_MODULE_HEADER,  // --
        kMemorySectionCode,  // --
        U32V_1(4),           // section size
        ENTRY_COUNT(1),      // --
        kWithMaximum,        // --
        0,                   // initial size
        0,                   // maximum size
        kDataSectionCode,    // --
        U32V_1(6),           // section size
        ENTRY_COUNT(1),      // --
    
"""


```