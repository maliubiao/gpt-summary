Response: The user wants to understand the functionality of the C++ code in `v8/test/cctest/wasm/test-run-wasm-js.cc`. I need to analyze the code, focusing on its purpose and how it relates to JavaScript.

**Plan:**

1. **Identify the main purpose of the file:**  The filename suggests it's testing the interaction between WebAssembly and JavaScript within the V8 engine.
2. **Look for key components:**
    * Test fixtures (`WASM_COMPILED_EXEC_TEST`).
    * Functions that interact with JavaScript (`CheckCallViaJS`, `CheckCallApplyViaJS`).
    * Functions that create JavaScript functions (`CreateJSSelector`).
    * Use of the `WasmRunner` class, which likely facilitates WASM execution and interaction.
    * Examples of WASM bytecode being generated and executed.
3. **Analyze specific test cases:**  Understand what each test case is verifying. Pay attention to how JavaScript functions are being called from WASM and vice-versa.
4. **Explain the relationship with JavaScript:**  Illustrate how WASM modules can import and call JavaScript functions, and how JavaScript can call functions defined in WASM modules.
5. **Provide JavaScript examples:** Create simple JavaScript code snippets that demonstrate the concepts illustrated in the C++ tests.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-js.cc` 的主要功能是**测试 WebAssembly (Wasm) 模块与 JavaScript 之间的互操作性**。它使用 V8 JavaScript 引擎的测试框架来验证 Wasm 模块能否正确地调用 JavaScript 函数，以及 JavaScript 能否正确地调用 Wasm 模块导出的函数。

更具体地说，这个文件包含了多个测试用例，每个测试用例都演示了不同的 Wasm 和 JavaScript 交互场景：

1. **从 Wasm 调用 JavaScript 函数:**
   - 测试 Wasm 模块可以导入并调用 JavaScript 函数。
   - 这些 JavaScript 函数可以是简单的函数，例如执行加法运算，或者更复杂的函数，例如从一组参数中选择一个参数。
   - 使用 `ManuallyImportedJSFunction` 结构体将 JavaScript 函数导入到 Wasm 模块中。
   - 使用 `WASM_CALL_FUNCTION` 指令在 Wasm 代码中调用导入的 JavaScript 函数。
   - 使用 `CheckCallViaJS` 和 `CheckCallApplyViaJS` 来验证 Wasm 调用 JavaScript 函数后的返回值是否正确。

2. **从 JavaScript 调用 Wasm 函数:**
   - 测试 JavaScript 可以调用由 Wasm 模块导出的函数。
   - 通过 `WasmRunner` 类构建和执行 Wasm 模块。
   - 使用 `CheckCallViaJS` 和 `CheckCallApplyViaJS` 来验证 JavaScript 调用 Wasm 函数后的返回值是否正确。

3. **测试不同类型的 Wasm 操作与 JavaScript 的交互:**
   - 文件中包含测试用例，测试了基本的 Wasm 算术运算（如 `i32.sub`, `f32.div`, `f64.add`）以及位操作（如 `i32.popcnt`）在与 JavaScript 交互时的正确性。

4. **测试参数传递和对齐:**
   - `RunJSSelectTest`, `RunWASMSelectTest`, `RunWASMSelectAlignTest`, 和 `RunJSSelectAlignTest` 等测试用例专注于测试在 Wasm 和 JavaScript 之间传递不同数量和类型的参数时，参数的传递和内存对齐是否正确。

5. **测试 `return_call` 指令:**
   - `Run_ReturnCallImportedFunction` 测试用例演示了 Wasm 的 `return_call` 和 `return_call_indirect` 指令，允许 Wasm 函数直接跳转到导入的 JavaScript 函数并返回其结果，而无需返回到调用者。

**与 JavaScript 的关系和 JavaScript 示例:**

这个文件的核心在于测试 Wasm 和 JavaScript 的集成。Wasm 旨在作为 JavaScript 的补充，提供接近原生的性能，而 JavaScript 则擅长动态性和 Web API 的访问。

**JavaScript 示例:**

以下是一些 JavaScript 代码片段，它们与 `test-run-wasm-js.cc` 中的概念相对应：

**1. JavaScript 函数被 Wasm 调用:**

```javascript
// 定义一个将被 Wasm 调用的 JavaScript 函数
function add99(a) {
  return a + 99;
}
```

在 C++ 代码中，`WASM_COMPILED_EXEC_TEST(Run_CallJS_Add_jswrapped)` 就测试了这种情况。它创建了一个执行 `a + 99` 的 JavaScript 函数，并将其导入到 Wasm 模块中，然后在 Wasm 中调用它。

**2. JavaScript 调用 Wasm 导出的函数:**

假设有一个 Wasm 模块导出了一个名为 `subtract` 的函数，它接受两个整数并返回它们的差。在 JavaScript 中，你可以这样调用它：

```javascript
// 假设 'wasmModule' 是一个已加载和实例化的 WebAssembly.Module 实例
const instance = await WebAssembly.instantiate(wasmModule);

// 调用 Wasm 模块导出的 'subtract' 函数
const result = instance.exports.subtract(44, 11);
console.log(result); // 输出 33
```

在 C++ 代码中，例如 `WASM_COMPILED_EXEC_TEST(Run_Int32Sub_jswrapped)`， 虽然不是直接从 JS 调用，但是它构建了一个 Wasm 模块，然后使用 `CheckCallViaJS` 来模拟 JavaScript 环境下的调用，验证了 Wasm 函数的正确性。

**3. 使用 JavaScript 函数作为选择器:**

在 `RunJSSelectTest` 系列的测试中，C++ 代码动态地创建了一些简单的 JavaScript 函数，这些函数只是简单地返回它们的某个参数。例如，如果一个 JavaScript 函数接受三个参数 `a`, `b`, `c`，那么 `CreateJSSelector` 可以创建一个函数，当 `which` 为 1 时，该函数返回 `b`。

对应的 JavaScript 代码可能如下所示（但这部分是由 C++ 代码动态生成的）：

```javascript
// 当 which 为 1 时，生成的 JavaScript 函数可能像这样
function(a, b, c) {
  return b;
}
```

总而言之，`v8/test/cctest/wasm/test-run-wasm-js.cc` 是 V8 引擎中一个关键的测试文件，它专注于验证 WebAssembly 和 JavaScript 之间的无缝集成，确保这两种技术能够正确地协同工作。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-js.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/objects/heap-number-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {
// A helper for generating predictable but unique argument values that
// are easy to debug (e.g. with misaligned stacks).
class PredictableInputValues {
 public:
  int base_;
  explicit PredictableInputValues(int base) : base_(base) {}
  double arg_d(int which) { return base_ * which + ((which & 1) * 0.5); }
  float arg_f(int which) { return base_ * which + ((which & 1) * 0.25); }
  int32_t arg_i(int which) { return base_ * which + ((which & 1) * kMinInt); }
  int64_t arg_l(int which) {
    return base_ * which + ((which & 1) * (0x04030201LL << 32));
  }
};

ManuallyImportedJSFunction CreateJSSelector(FunctionSig* sig, int which) {
  const int kMaxParams = 11;
  static const char* formals[kMaxParams] = {"",
                                            "a",
                                            "a,b",
                                            "a,b,c",
                                            "a,b,c,d",
                                            "a,b,c,d,e",
                                            "a,b,c,d,e,f",
                                            "a,b,c,d,e,f,g",
                                            "a,b,c,d,e,f,g,h",
                                            "a,b,c,d,e,f,g,h,i",
                                            "a,b,c,d,e,f,g,h,i,j"};
  CHECK_LT(which, static_cast<int>(sig->parameter_count()));
  CHECK_LT(static_cast<int>(sig->parameter_count()), kMaxParams);

  base::EmbeddedVector<char, 256> source;
  char param = 'a' + which;
  SNPrintF(source, "(function(%s) { return %c; })",
           formals[sig->parameter_count()], param);

  Handle<JSFunction> js_function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source.begin()))));
  ManuallyImportedJSFunction import = {sig, js_function};

  return import;
}
}  // namespace

WASM_COMPILED_EXEC_TEST(Run_Int32Sub_jswrapped) {
  WasmRunner<int, int, int> r(execution_tier);
  r.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  r.CheckCallViaJS(33, 44, 11);
  r.CheckCallViaJS(-8723487, -8000000, 723487);
}

WASM_COMPILED_EXEC_TEST(Run_Float32Div_jswrapped) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_DIV(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  r.CheckCallViaJS(92, 46, 0.5);
  r.CheckCallViaJS(64, -16, -0.25);
}

WASM_COMPILED_EXEC_TEST(Run_Float64Add_jswrapped) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  r.CheckCallViaJS(3, 2, 1);
  r.CheckCallViaJS(-5.5, -5.25, -0.25);
}

WASM_COMPILED_EXEC_TEST(Run_I32Popcount_jswrapped) {
  WasmRunner<int, int> r(execution_tier);
  r.Build({WASM_I32_POPCNT(WASM_LOCAL_GET(0))});

  r.CheckCallViaJS(2, 9);
  r.CheckCallViaJS(3, 11);
  r.CheckCallViaJS(6, 0x3F);
}

WASM_COMPILED_EXEC_TEST(Run_CallJS_Add_jswrapped) {
  TestSignatures sigs;
  HandleScope scope(CcTest::InitIsolateOnce());
  const char* source = "(function(a) { return a + 99; })";
  Handle<JSFunction> js_function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source))));
  ManuallyImportedJSFunction import = {sigs.i_i(), js_function};
  WasmRunner<int, int> r(execution_tier, kWasmOrigin, &import);
  uint32_t js_index = 0;
  r.Build({WASM_CALL_FUNCTION(js_index, WASM_LOCAL_GET(0))});

  r.CheckCallViaJS(101, 2);
  r.CheckCallViaJS(199, 100);
  r.CheckCallViaJS(-666666801, -666666900);
}

void RunJSSelectTest(TestExecutionTier tier, int which) {
  const int kMaxParams = 8;
  PredictableInputValues inputs(0x100);
  ValueType type = kWasmF64;
  ValueType types[kMaxParams + 1] = {type, type, type, type, type,
                                     type, type, type, type};
  for (int num_params = which + 1; num_params < kMaxParams; num_params++) {
    HandleScope scope(CcTest::InitIsolateOnce());
    FunctionSig sig(1, num_params, types);

    ManuallyImportedJSFunction import = CreateJSSelector(&sig, which);
    WasmRunner<void> r(tier, kWasmOrigin, &import);
    uint32_t js_index = 0;

    WasmFunctionCompiler& t = r.NewFunction(&sig);

    {
      std::vector<uint8_t> code;

      for (int i = 0; i < num_params; i++) {
        ADD_CODE(code, WASM_F64(inputs.arg_d(i)));
      }

      ADD_CODE(code, kExprCallFunction, static_cast<uint8_t>(js_index));

      size_t end = code.size();
      code.push_back(0);
      t.Build(base::VectorOf(code.data(), end));
    }

    double expected = inputs.arg_d(which);
    r.CheckCallApplyViaJS(expected, t.function_index(), nullptr, 0);
  }
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_0) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 0);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_1) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 1);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_2) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 2);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_3) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 3);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_4) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 4);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_5) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 5);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_6) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 6);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelect_7) {
  CcTest::InitializeVM();
  RunJSSelectTest(execution_tier, 7);
}

void RunWASMSelectTest(TestExecutionTier tier, int which) {
  PredictableInputValues inputs(0x200);
  Isolate* isolate = CcTest::InitIsolateOnce();
  const int kMaxParams = 8;
  for (int num_params = which + 1; num_params < kMaxParams; num_params++) {
    ValueType type = kWasmF64;
    ValueType types[kMaxParams + 1] = {type, type, type, type, type,
                                       type, type, type, type};
    FunctionSig sig(1, num_params, types);

    WasmRunner<void> r(tier);
    WasmFunctionCompiler& t = r.NewFunction(&sig);
    t.Build({WASM_LOCAL_GET(which)});

    Handle<Object> args[] = {
        isolate->factory()->NewNumber(inputs.arg_d(0)),
        isolate->factory()->NewNumber(inputs.arg_d(1)),
        isolate->factory()->NewNumber(inputs.arg_d(2)),
        isolate->factory()->NewNumber(inputs.arg_d(3)),
        isolate->factory()->NewNumber(inputs.arg_d(4)),
        isolate->factory()->NewNumber(inputs.arg_d(5)),
        isolate->factory()->NewNumber(inputs.arg_d(6)),
        isolate->factory()->NewNumber(inputs.arg_d(7)),
    };

    double expected = inputs.arg_d(which);
    r.CheckCallApplyViaJS(expected, t.function_index(), args, kMaxParams);
  }
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_0) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 0);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_1) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 1);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_2) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 2);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_3) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 3);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_4) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 4);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_5) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 5);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_6) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 6);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelect_7) {
  CcTest::InitializeVM();
  RunWASMSelectTest(execution_tier, 7);
}

void RunWASMSelectAlignTest(TestExecutionTier tier, int num_args,
                            int num_params) {
  PredictableInputValues inputs(0x300);
  Isolate* isolate = CcTest::InitIsolateOnce();
  const int kMaxParams = 10;
  DCHECK_LE(num_args, kMaxParams);
  ValueType type = kWasmF64;
  ValueType types[kMaxParams + 1] = {type, type, type, type, type, type,
                                     type, type, type, type, type};
  FunctionSig sig(1, num_params, types);

  for (int which = 0; which < num_params; which++) {
    WasmRunner<void> r(tier);
    WasmFunctionCompiler& t = r.NewFunction(&sig);
    t.Build({WASM_LOCAL_GET(which)});

    Handle<Object> args[] = {isolate->factory()->NewNumber(inputs.arg_d(0)),
                             isolate->factory()->NewNumber(inputs.arg_d(1)),
                             isolate->factory()->NewNumber(inputs.arg_d(2)),
                             isolate->factory()->NewNumber(inputs.arg_d(3)),
                             isolate->factory()->NewNumber(inputs.arg_d(4)),
                             isolate->factory()->NewNumber(inputs.arg_d(5)),
                             isolate->factory()->NewNumber(inputs.arg_d(6)),
                             isolate->factory()->NewNumber(inputs.arg_d(7)),
                             isolate->factory()->NewNumber(inputs.arg_d(8)),
                             isolate->factory()->NewNumber(inputs.arg_d(9))};

    double nan = std::numeric_limits<double>::quiet_NaN();
    double expected = which < num_args ? inputs.arg_d(which) : nan;
    r.CheckCallApplyViaJS(expected, t.function_index(), args, num_args);
  }
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_0) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 0, 1);
  RunWASMSelectAlignTest(execution_tier, 0, 2);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_1) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 1, 2);
  RunWASMSelectAlignTest(execution_tier, 1, 3);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_2) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 2, 3);
  RunWASMSelectAlignTest(execution_tier, 2, 4);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_3) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 3, 3);
  RunWASMSelectAlignTest(execution_tier, 3, 4);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_4) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 4, 3);
  RunWASMSelectAlignTest(execution_tier, 4, 4);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_7) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 7, 5);
  RunWASMSelectAlignTest(execution_tier, 7, 6);
  RunWASMSelectAlignTest(execution_tier, 7, 7);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_8) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 8, 5);
  RunWASMSelectAlignTest(execution_tier, 8, 6);
  RunWASMSelectAlignTest(execution_tier, 8, 7);
  RunWASMSelectAlignTest(execution_tier, 8, 8);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_9) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 9, 6);
  RunWASMSelectAlignTest(execution_tier, 9, 7);
  RunWASMSelectAlignTest(execution_tier, 9, 8);
  RunWASMSelectAlignTest(execution_tier, 9, 9);
}

WASM_COMPILED_EXEC_TEST(Run_WASMSelectAlign_10) {
  CcTest::InitializeVM();
  RunWASMSelectAlignTest(execution_tier, 10, 7);
  RunWASMSelectAlignTest(execution_tier, 10, 8);
  RunWASMSelectAlignTest(execution_tier, 10, 9);
  RunWASMSelectAlignTest(execution_tier, 10, 10);
}

void RunJSSelectAlignTest(TestExecutionTier tier, int num_args,
                          int num_params) {
  PredictableInputValues inputs(0x400);
  Isolate* isolate = CcTest::InitIsolateOnce();
  Factory* factory = isolate->factory();
  const int kMaxParams = 10;
  CHECK_LE(num_args, kMaxParams);
  CHECK_LE(num_params, kMaxParams);
  ValueType type = kWasmF64;
  ValueType types[kMaxParams + 1] = {type, type, type, type, type, type,
                                     type, type, type, type, type};
  FunctionSig sig(1, num_params, types);
  i::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  // Build the calling code.
  std::vector<uint8_t> code;

  for (int i = 0; i < num_params; i++) {
    ADD_CODE(code, WASM_LOCAL_GET(i));
  }

  uint8_t imported_js_index = 0;
  ADD_CODE(code, kExprCallFunction, imported_js_index);

  size_t end = code.size();
  code.push_back(0);

  // Call different select JS functions.
  for (int which = 0; which < num_params; which++) {
    HandleScope scope(isolate);
    ManuallyImportedJSFunction import = CreateJSSelector(&sig, which);
    WasmRunner<void> r(tier, kWasmOrigin, &import);
    WasmFunctionCompiler& t = r.NewFunction(&sig);
    t.Build(base::VectorOf(code.data(), end));

    Handle<Object> args[] = {
        factory->NewNumber(inputs.arg_d(0)),
        factory->NewNumber(inputs.arg_d(1)),
        factory->NewNumber(inputs.arg_d(2)),
        factory->NewNumber(inputs.arg_d(3)),
        factory->NewNumber(inputs.arg_d(4)),
        factory->NewNumber(inputs.arg_d(5)),
        factory->NewNumber(inputs.arg_d(6)),
        factory->NewNumber(inputs.arg_d(7)),
        factory->NewNumber(inputs.arg_d(8)),
        factory->NewNumber(inputs.arg_d(9)),
    };

    double nan = std::numeric_limits<double>::quiet_NaN();
    double expected = which < num_args ? inputs.arg_d(which) : nan;
    r.CheckCallApplyViaJS(expected, t.function_index(), args, num_args);
  }
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_0) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 0, 1);
  RunJSSelectAlignTest(execution_tier, 0, 2);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_1) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 1, 2);
  RunJSSelectAlignTest(execution_tier, 1, 3);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_2) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 2, 3);
  RunJSSelectAlignTest(execution_tier, 2, 4);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_3) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 3, 3);
  RunJSSelectAlignTest(execution_tier, 3, 4);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_4) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 4, 3);
  RunJSSelectAlignTest(execution_tier, 4, 4);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_7) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 7, 3);
  RunJSSelectAlignTest(execution_tier, 7, 4);
  RunJSSelectAlignTest(execution_tier, 7, 4);
  RunJSSelectAlignTest(execution_tier, 7, 4);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_8) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 8, 5);
  RunJSSelectAlignTest(execution_tier, 8, 6);
  RunJSSelectAlignTest(execution_tier, 8, 7);
  RunJSSelectAlignTest(execution_tier, 8, 8);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_9) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 9, 6);
  RunJSSelectAlignTest(execution_tier, 9, 7);
  RunJSSelectAlignTest(execution_tier, 9, 8);
  RunJSSelectAlignTest(execution_tier, 9, 9);
}

WASM_COMPILED_EXEC_TEST(Run_JSSelectAlign_10) {
  CcTest::InitializeVM();
  RunJSSelectAlignTest(execution_tier, 10, 7);
  RunJSSelectAlignTest(execution_tier, 10, 8);
  RunJSSelectAlignTest(execution_tier, 10, 9);
  RunJSSelectAlignTest(execution_tier, 10, 10);
}

// Set up a test with an import, so we can return call it.
// Create a javascript function that returns left or right arguments
// depending on the value of the third argument
// function (a,b,c){ if(c)return a; return b; }

void RunPickerTest(TestExecutionTier tier, bool indirect) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  TestSignatures sigs;

  const char* source = "(function(a,b,c) { if(c)return a; return b; })";
  Handle<JSFunction> js_function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source))));

  ManuallyImportedJSFunction import = {sigs.i_iii(), js_function};

  WasmRunner<int32_t, int32_t> r(tier, kWasmOrigin, &import);

  const uint32_t js_index = 0;
  const int32_t left = -2;
  const int32_t right = 3;

  WasmFunctionCompiler& rc_fn = r.NewFunction(sigs.i_i(), "rc");

  if (indirect) {
    ModuleTypeIndex sig_index = r.builder().AddSignature(sigs.i_iii());
    uint16_t indirect_function_table[] = {static_cast<uint16_t>(js_index)};

    r.builder().AddIndirectFunctionTable(indirect_function_table,
                                         arraysize(indirect_function_table));

    rc_fn.Build(
        {WASM_RETURN_CALL_INDIRECT(sig_index, WASM_I32V(left), WASM_I32V(right),
                                   WASM_LOCAL_GET(0), WASM_I32V(js_index))});
  } else {
    rc_fn.Build({WASM_RETURN_CALL_FUNCTION(
        js_index, WASM_I32V(left), WASM_I32V(right), WASM_LOCAL_GET(0))});
  }

  Handle<Object> args_left[] = {isolate->factory()->NewNumber(1)};
  r.CheckCallApplyViaJS(left, rc_fn.function_index(), args_left, 1);

  Handle<Object> args_right[] = {isolate->factory()->NewNumber(0)};
  r.CheckCallApplyViaJS(right, rc_fn.function_index(), args_right, 1);
}

WASM_COMPILED_EXEC_TEST(Run_ReturnCallImportedFunction) {
  RunPickerTest(execution_tier, false);
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```