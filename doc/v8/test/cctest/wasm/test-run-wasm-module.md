Response: The user wants to understand the functionality of the C++ code provided, which is a test file for running WebAssembly modules within the V8 JavaScript engine. I need to analyze the code, identify its core purpose, and then illustrate its interaction with JavaScript, if any.

**Plan:**

1. **Identify the main goal:** The file name and the `TEST` macros strongly suggest this is a testing file. The functions within the tests likely validate the behavior of the WebAssembly runtime.
2. **Analyze individual tests:**  Each `TEST` block seems to focus on a specific aspect of running a WebAssembly module. I'll categorize these aspects.
3. **Look for interactions with JavaScript:**  The file includes headers like `src/api/api-inl.h`, suggesting integration with V8's JavaScript API. The functions like `CompileAndRunWasmModule` and `CallWasmFunctionForTesting` point to this interaction.
4. **Construct JavaScript examples:** Based on the identified functionalities and interactions, create illustrative JavaScript code snippets.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-module.cc` 的主要功能是**测试 V8 引擎运行 WebAssembly 模块的能力**。 它通过构建不同的 WebAssembly 模块，然后使用 V8 引擎编译并运行这些模块，并检查运行结果或是否抛出异常，以此来验证 V8 的 WebAssembly 实现是否正确。

更具体地说，这个文件包含了一系列独立的测试用例 (通过 `TEST` 宏定义)，每个测试用例都关注 WebAssembly 模块运行的某个特定方面，例如：

*   **基本的函数调用和返回:** 测试 WebAssembly 函数能否被正确调用并返回预期值。
*   **编译提示 (Compilation Hints):** 测试 V8 引擎对 WebAssembly 模块的编译优化策略，例如延迟编译 (lazy compilation) 和分层编译 (tier-up compilation)。
*   **调用其他 WebAssembly 函数:** 测试 WebAssembly 模块内部的函数调用机制。
*   **访问和修改内存:** 测试 WebAssembly 模块对线性内存的读写操作，包括从数据段加载数据以及在运行时增长内存。
*   **使用全局变量:** 测试 WebAssembly 模块中全局变量的定义、初始化和访问。
*   **`memory.size` 和 `memory.grow` 指令:** 测试获取内存大小和增长内存的功能。
*   **中断 (Interrupts):** 测试 V8 引擎是否能够中断正在执行的 WebAssembly 代码。
*   **内存访问越界:** 测试 WebAssembly 模块尝试访问超出内存边界时是否会抛出异常。
*   **模块初始化:** 测试 WebAssembly 模块的数据段和全局变量的初始化过程。
*   **处理没有内存但有数据段的模块:** 测试当 WebAssembly 模块定义了数据段但没有定义内存时 V8 的处理方式。

**它与 JavaScript 的功能关系密切，因为 WebAssembly 旨在与 JavaScript 一起运行在 Web 平台上。**  V8 引擎是 Google Chrome 和 Node.js 的 JavaScript 引擎，它负责执行 JavaScript 代码，同时也支持编译和运行 WebAssembly 代码。

**JavaScript 举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能直接关系到如何在 JavaScript 中加载和运行 WebAssembly 模块。 我们可以用 JavaScript 代码来创建一个简单的 WebAssembly 模块，其功能与该 C++ 文件中的某些测试用例类似。

**例如，测试 WebAssembly 函数返回一个常数值的 C++ 代码 (`TEST(Run_WasmModule_Return114)`) 可以用以下 JavaScript 代码来实现和测试:**

```javascript
async function runWasm() {
  const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // 魔数和版本
    0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7f,       // 类型段：定义一个无参数返回 i32 的函数类型
    0x03, 0x02, 0x01, 0x00,                         // 函数段：定义一个函数，使用上面的函数类型
    0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, // 导出段：导出名为 "main" 的函数
    0x0a, 0x05, 0x01, 0x03, 0x41, 0x72, 0x0b        // 代码段：函数 "main" 返回常量 114 (0x72)
  ]);

  const wasmModule = await WebAssembly.compile(wasmCode);
  const wasmInstance = await WebAssembly.instantiate(wasmModule);

  const result = wasmInstance.exports.main();
  console.log("WebAssembly 函数返回:", result); // 输出: WebAssembly 函数返回: 114
  if (result === 114) {
    console.log("测试通过!");
  } else {
    console.error("测试失败!");
  }
}

runWasm();
```

**再例如，测试 WebAssembly 函数调用另一个函数的 C++ 代码 (`TEST(Run_WasmModule_CallAdd)`) 可以用以下 JavaScript 代码来实现和测试:**

```javascript
async function runWasm() {
  const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // 魔数和版本
    0x01, 0x0e, 0x02, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 类型段：定义一个接收两个 i32 返回一个 i32 的函数类型
                                      0x60, 0x00, 0x01, 0x7f, // 定义一个无参数返回 i32 的函数类型
    0x03, 0x03, 0x02, 0x00, 0x01,                         // 函数段：定义两个函数，分别使用上面的函数类型
    0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x01, 0x01, // 导出段：导出名为 "main" 的函数
    0x0a, 0x0d, 0x02, 0x06, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, // 代码段：函数 0 (add) 实现加法
                 0x05, 0x00, 0x10, 0x00, 0x41, 0x4d, 0x41, 0x16, 0x10, 0x00, 0x0b  // 代码段：函数 1 (main) 调用函数 0
  ]);

  const wasmModule = await WebAssembly.compile(wasmCode);
  const wasmInstance = await WebAssembly.instantiate(wasmModule);

  const result = wasmInstance.exports.main();
  console.log("WebAssembly 函数返回:", result); // 输出: WebAssembly 函数返回: 99
  if (result === 99) {
    console.log("测试通过!");
  } else {
    console.error("测试失败!");
  }
}

runWasm();
```

这些 JavaScript 例子演示了如何编译和实例化 WebAssembly 模块，并调用导出的函数。  `test-run-wasm-module.cc` 中的 C++ 测试用例实际上是在 V8 引擎的内部测试这些相同的基本功能以及更复杂的场景，以确保 V8 能够正确地处理各种 WebAssembly 模块。

总而言之，`v8/test/cctest/wasm/test-run-wasm-module.cc` 是 V8 引擎中一个关键的测试文件，它专注于验证 V8 引擎运行 WebAssembly 模块的核心功能，这对于 WebAssembly 与 JavaScript 的互操作性至关重要。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-module.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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
        0,                   // linear memory index
        WASM_I32V_1(0),      // destination offset
        kExprEnd,
        U32V_1(0),  // source size
    };

    CompileAndInstantiateForTesting(
        isolate, &thrower, ModuleWireBytes(data, data + arraysize(data)));
    // It should be possible to instantiate this module.
    CHECK(!thrower.error());
  }
  Cleanup();
}

#undef EMIT_CODE_WITH_END

}  // namespace test_run_wasm_module
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```