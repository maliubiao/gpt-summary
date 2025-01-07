Response:
Let's break down the thought process for analyzing the C++ code.

1. **Understand the Goal:** The primary goal is to understand the functionality of the given C++ code. The filename `test-run-wasm-js.cc` strongly suggests it's testing the interaction between WebAssembly (Wasm) and JavaScript (JS). The presence of `WasmRunner` further confirms this.

2. **Initial Scan for Key Components:**  Quickly scan the code for important keywords, classes, and namespaces:
    * `namespace wasm`:  Confirms it's Wasm related.
    * `WasmRunner`:  A test fixture for running Wasm code. This is a crucial element to understand the overall testing structure.
    * `WASM_COMPILED_EXEC_TEST`:  Macros indicating individual test cases. Each of these is a distinct test.
    * `CheckCallViaJS`, `CheckCallApplyViaJS`:  Methods suggesting the interaction with JavaScript. Wasm functions are being called from JS.
    * `CreateJSSelector`, `RunJSSelectTest`, `RunWASMSelectTest`, `RunJSSelectAlignTest`, `RunWASMSelectAlignTest`, `RunPickerTest`: Functions indicating specific test scenarios. These need closer examination.
    * `ManuallyImportedJSFunction`:  Suggests importing JavaScript functions into the Wasm environment.
    * `PredictableInputValues`: A helper class for generating test inputs. This is important for understanding the test data.
    * WASM opcodes (`WASM_I32_SUB`, `WASM_F32_DIV`, etc.):  These define the Wasm instructions being tested.

3. **Analyze Individual Test Cases (`WASM_COMPILED_EXEC_TEST`):**  Go through each test case and try to decipher what it's doing.

    * **Simple Arithmetic Operations (`Run_Int32Sub_jswrapped`, `Run_Float32Div_jswrapped`, `Run_Float64Add_jswrapped`):** These are straightforward. They define a simple Wasm function (subtraction, division, addition) and then call it from JavaScript with specific inputs and expected outputs using `CheckCallViaJS`.

    * **Bit Manipulation (`Run_I32Popcount_jswrapped`):** Similar to the arithmetic tests, but testing the `popcount` instruction.

    * **Calling JavaScript from Wasm (`Run_CallJS_Add_jswrapped`):** This test imports a simple JavaScript function (`(function(a) { return a + 99; })`) into the Wasm module and then calls it from the Wasm code. This showcases the Wasm-to-JS calling mechanism.

    * **`Run_JSSelect_*` Tests:** These tests introduce the `CreateJSSelector` function. This function dynamically creates a JavaScript function that returns a specific argument based on its index. The Wasm code then calls this imported JS function. The purpose is likely to test passing arguments from Wasm to JS and selecting a specific argument within JS.

    * **`Run_WASMSelect_*` Tests:** These tests are simpler. The Wasm code itself just returns one of its arguments. The tests verify that the correct argument is returned when called from JavaScript. This checks basic Wasm function calls with multiple arguments.

    * **`Run_WASMSelectAlign_*` and `Run_JSSelectAlign_*` Tests:** The "Align" suffix and the varying `num_args` and `num_params` suggest these tests are checking how arguments are passed and handled when the number of arguments passed from JS differs from the number of parameters the Wasm/JS function expects. The use of `std::numeric_limits<double>::quiet_NaN()` as the expected value when `which < num_args` is false indicates how missing arguments are handled (likely as NaN).

    * **`Run_ReturnCallImportedFunction`:** This test focuses on calling an imported JavaScript function from Wasm and directly returning the result. The `RunPickerTest` function uses a JS function that selects one of its first two arguments based on the third. The `indirect` parameter suggests a variation testing indirect function calls, which involves a function table.

4. **Analyze Helper Functions:**

    * **`PredictableInputValues`:** This class generates predictable double, float, int32_t, and int64_t values. This is useful for debugging as the values are not random.

    * **`CreateJSSelector`:** This function is key to the `Run_JSSelect_*` tests. It dynamically creates a JavaScript function that takes a variable number of arguments and returns a specific one. This is done using string manipulation to create the JS source code.

5. **Identify JavaScript Interactions:**  Look for places where JavaScript code is either being called from Wasm or where Wasm functions are being called from JavaScript. The `CheckCallViaJS`, `CheckCallApplyViaJS`, and the use of `CompileRun` to create JavaScript functions are strong indicators.

6. **Infer Purpose and Functionality:** Based on the individual test cases and helper functions, piece together the overall functionality of the code. It's a test suite for verifying the correct execution of Wasm modules, particularly when interacting with JavaScript. It covers:
    * Basic Wasm arithmetic and bitwise operations.
    * Calling JavaScript functions from Wasm.
    * Passing arguments between Wasm and JavaScript (in both directions).
    * Handling different numbers of arguments in function calls.
    * Indirect function calls in Wasm.

7. **Consider Potential Errors:**  Think about the kinds of errors this code is designed to catch. Argument mismatches (too few or too many arguments), incorrect handling of return values, issues with calling conventions between Wasm and JS, and errors in basic Wasm opcodes are likely targets.

8. **Structure the Explanation:** Organize the findings into a coherent explanation, addressing the specific points requested in the prompt (functionality, `.tq` check, JavaScript examples, code logic, common errors).

This systematic approach, starting with a high-level overview and then drilling down into the details of each test case and helper function, is crucial for understanding complex C++ code like this.
```cpp
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
```

### 功能列举

`v8/test/cctest/wasm/test-run-wasm-js.cc` 的主要功能是 **测试 WebAssembly (Wasm) 模块与 JavaScript 之间的互操作性**。 具体来说，它涵盖了以下几个方面的测试：

1. **调用简单的 Wasm 函数并从 JavaScript 获取结果**:  测试了从 JavaScript 中调用编译后的 Wasm 函数，并验证其返回结果的正确性。 这些 Wasm 函数执行简单的算术运算 (加减乘除) 和位运算 (popcount)。

2. **将 JavaScript 函数导入到 Wasm 模块并调用**:  测试了将 JavaScript 函数作为 import 导入到 Wasm 模块中，并在 Wasm 代码中调用这些导入的 JavaScript 函数。

3. **从 Wasm 中调用导入的 JavaScript 函数并返回结果**: 测试了 Wasm 代码调用导入的 JavaScript 函数，并将 JavaScript 函数的返回值作为 Wasm 函数的返回值返回给 JavaScript 调用者。

4. **测试 Wasm 和 JavaScript 之间参数传递**:  通过不同的测试用例，验证了 Wasm 和 JavaScript 之间各种数据类型的参数传递，包括 `int32_t`, `float`, `double` 等。

5. **测试函数调用的参数对齐 (Alignment)**: `RunWASMSelectAlignTest` 和 `RunJSSelectAlignTest` 这类测试用例专门用于测试当从 JavaScript 调用 Wasm 函数或从 Wasm 调用 JavaScript 函数时，参数的数量和类型与函数签名不完全匹配的情况下的行为，特别是涉及到浮点数等需要特定内存对齐的数据类型。

6. **测试 Wasm 的间接调用**: `RunPickerTest` 中 `indirect = true` 的情况测试了 Wasm 的 `call_indirect` 指令，它允许通过函数表来调用函数，这里特别测试了调用导入的 JavaScript 函数。

### 关于 .tq 结尾

如果 `v8/test/cctest/wasm/test-run-wasm-js.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种用于定义 V8 内部函数（特别是内置函数）的领域特定语言。  这个文件会包含用 Torque 编写的代码，用于定义或测试某些与 Wasm 和
Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-js.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-js.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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