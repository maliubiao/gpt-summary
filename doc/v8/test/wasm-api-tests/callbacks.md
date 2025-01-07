Response: Let's break down the thought process for analyzing this C++ code and connecting it to JavaScript/WebAssembly.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and its relation to JavaScript, specifically through WebAssembly. The key is identifying how C++ functions interact with the WebAssembly environment.

2. **Initial Skim for Keywords:**  Look for keywords related to WebAssembly and interaction:
    * `wasm_api_tests` in the file path is a strong indicator.
    * `wasm` namespace appears frequently.
    * `Func`, `Trap`, `Val`, `Store`, `Module`, `Instance`, `Extern`, `FuncType` are likely related to the WebAssembly C API.
    * `AddImport`, `AddExportedFunction`, `call`, `Instantiate` suggest interaction between C++ and WebAssembly functions.
    * `printf` indicates console output, likely for debugging or demonstration.
    * `TEST_F` hints at unit tests.

3. **Identify Core Components:** The code seems to define several tests. Focus on understanding the structure of a single test to generalize. Let's take `TEST_F(WasmCapiCallbacksTest, Trap)` as an example.

4. **Analyze a Single Test (Trap):**
    * **Setup (`WasmCapiCallbacksTest`)**:  This class seems to set up the WebAssembly environment. It imports a function named "stage2" and defines an exported function "stage1" that calls "stage2". The `Stage2` function is implemented in C++.
    * **Specific Test Logic:** The `Trap` test defines another exported function "stage3_trap" that does `WASM_UNREACHABLE`. It then imports the C++ `stage2` function. It instantiates the module, calls the exported "stage1" function, and expects a `Trap` because the call chain goes through `Stage2` which calls `stage3_trap`.
    * **Key Interaction:**  The C++ `Stage2` function calls a WebAssembly function (`stage3`). This demonstrates a C++ callback into WebAssembly.

5. **Analyze Other Tests and Identify Patterns:**
    * **GC Test:**  This shows C++ calling a WebAssembly function ("stage3_to4") and a C++ function ("Stage4_GC") being called *by* WebAssembly. `Stage4_GC` also interacts with the V8 JavaScript engine's garbage collector (`isolate->heap()->PreciseCollectAllGarbage`). This is a crucial link between C++ and the underlying JavaScript environment.
    * **Recursion Test:** This shows a C++ function (`FibonacciC`) calling a WebAssembly function (`fibonacci_wasm`) recursively. This illustrates how C++ can act as a helper function for WebAssembly.
    * **DirectCallCapiFunction(s):**  These tests demonstrate calling C++ functions directly from C++ using the WebAssembly C API (`Func::call`). They also show how these C++ functions can be imported and exported, allowing them to be called *indirectly* through the WebAssembly instance. The "many args" test specifically targets the handling of function calls with a large number of parameters.

6. **Generalize the Functionality:** Based on the test analysis, the core functionality is:
    * **Defining C++ functions that can be called from WebAssembly.**  These act as "imports" to the WebAssembly module.
    * **Defining WebAssembly functions that can call back into C++ functions.**  This is the callback mechanism.
    * **Directly calling C++ functions using the WebAssembly C API.**
    * **Testing different scenarios:** trapping, garbage collection interaction, recursion, and handling various argument types and counts.

7. **Connect to JavaScript/WebAssembly:**
    * **Imports:** The C++ functions registered as imports would be provided to the `WebAssembly.instantiate` function in JavaScript.
    * **Callbacks:** When the WebAssembly code calls an imported function, it executes the corresponding C++ code.
    * **Direct Calls (Less Common from JS):** While the C++ code shows direct calls, this isn't the typical interaction from JavaScript. JavaScript usually interacts with WebAssembly through exported functions. The C++ direct call tests are more about verifying the C API itself.
    * **Garbage Collection:**  The GC interaction highlights that WebAssembly runs within a JavaScript engine and is subject to its memory management.

8. **Construct the JavaScript Example:**  The JavaScript example should demonstrate the core concept of importing a C++ function into WebAssembly. A simple example with a function that adds one is sufficient. Explain the connection: the C++ `PlusOne` function is analogous to the JavaScript import.

9. **Refine and Organize:**  Structure the explanation clearly, starting with a general summary, then delving into specifics of each test, and finally providing the JavaScript example and explanation. Use clear language and avoid overly technical jargon where possible. Emphasize the key interactions and the relationship between C++ and WebAssembly. For instance, explicitly state that C++ functions act as "imports" and are provided during instantiation.

10. **Review:** Reread the explanation and the code to ensure accuracy and completeness. Check if all aspects of the request have been addressed. Make sure the JavaScript example clearly illustrates the concept.
这个C++源代码文件 `callbacks.cc` 是 WebAssembly C API 的一个测试文件，主要用于测试 **WebAssembly 模块与外部 C++ 代码之间的回调机制**。它演示了如何在 WebAssembly 模块中调用 C++ 函数，以及如何在 C++ 代码中调用 WebAssembly 模块中的函数。

以下是该文件功能的归纳：

1. **定义 C++ 回调函数:** 文件中定义了多个 C++ 函数，例如 `Stage2`, `Stage4_GC`, `FibonacciC`, `PlusOne`, `PlusOneWithManyArgs`。这些函数可以作为回调函数被 WebAssembly 模块调用。

2. **创建 WebAssembly 模块并导入 C++ 函数:**  测试用例使用 `WasmCapiTest` 类来构建 WebAssembly 模块。通过 `builder()->AddImport()` 方法将 C++ 函数注册为 WebAssembly 模块的导入项。

3. **在 WebAssembly 代码中调用导入的 C++ 函数:**  在 WebAssembly 模块的代码中，使用 `WASM_CALL_FUNCTION` 指令来调用之前导入的 C++ 函数。

4. **在 C++ 代码中调用导出的 WebAssembly 函数:**  C++ 代码通过 `GetExportedFunction()` 获取 WebAssembly 模块导出的函数，并使用 `call()` 方法来执行这些函数。

5. **测试不同的回调场景:**
    * **Trap (异常):** 测试从 C++ 回调函数中调用会触发 WebAssembly 异常的函数，并捕获这个异常。
    * **GC (垃圾回收):** 测试在 C++ 回调函数中触发 JavaScript 引擎的垃圾回收，验证回调机制在垃圾回收期间的稳定性。
    * **Recursion (递归):** 测试 C++ 函数和 WebAssembly 函数之间的相互递归调用。
    * **Direct Call (直接调用):** 测试直接使用 WebAssembly C API 调用 C++ 函数，无需通过 WebAssembly 模块。
    * **Multiple Arguments (多参数):** 测试 C++ 回调函数和 WebAssembly 函数在传递多个参数时的正确性。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个文件直接测试了 V8 JavaScript 引擎中 WebAssembly 的 C API 实现。当 JavaScript 代码加载并实例化一个 WebAssembly 模块时，它可以通过 imports 对象将 JavaScript 函数或者使用 C API 编译的 C++ 函数传递给 WebAssembly 模块作为导入项。

这个 `callbacks.cc` 文件中的 C++ 函数就相当于可以被 JavaScript 导入的外部函数。

**JavaScript 示例:**

假设 `callbacks.cc` 中的 `PlusOne` 函数被编译成一个 WebAssembly 模块，并且导出了一个调用 `PlusOne` 的 WebAssembly 函数，那么在 JavaScript 中可以这样使用：

```javascript
// 假设我们有一个编译好的 WebAssembly 模块的 ArrayBuffer
const wasmCode = /* ... wasm 模块的二进制数据 ... */;

// 定义导入对象，将 C++ 函数 "func" (对应 PlusOne) 传递给 WebAssembly 模块
const importObject = {
  env: {
    func: (a0, a1, a2, a3, a4) => { // 参数对应 PlusOne 的参数类型
      console.log("C++ PlusOne 函数被调用:", a0, a1, a2, a3, a4);
      // 这里实际上是 WebAssembly 模块内部调用了 C++ 的 PlusOne
      // 因为 PlusOne 会返回结果，理想情况下这里应该处理返回值
      return a0 + 1; // 简化示例，假设只处理第一个 i32 参数
    }
  }
};

WebAssembly.instantiate(wasmCode, importObject)
  .then(wasmModule => {
    // 获取 WebAssembly 模块导出的函数 (假设导出的函数也叫 'func')
    const exportedFunc = wasmModule.instance.exports.func;

    // 调用导出的 WebAssembly 函数，它会反过来调用我们提供的导入函数 (C++ 的 PlusOne)
    const result = exportedFunc(42, 123n, 3.14, 2.71, {});
    console.log("WebAssembly 函数调用结果:", result);
  });
```

**解释 JavaScript 示例:**

1. **`wasmCode`:**  代表编译后的 WebAssembly 模块的二进制数据。
2. **`importObject`:**  这是一个 JavaScript 对象，用于定义 WebAssembly 模块的导入。
3. **`env.func`:**  这里 `env` 是一个常见的导入命名空间，`func` 是 C++ 代码中通过 `builder()->AddImport(base::CStrVector("func"), ...)` 声明的导入名称。JavaScript 中的这个函数将作为 WebAssembly 模块中 `func` 的具体实现。
4. **`WebAssembly.instantiate(wasmCode, importObject)`:**  这个方法负责编译和实例化 WebAssembly 模块，并将 `importObject` 中定义的函数链接到 WebAssembly 模块的导入项。
5. **`wasmModule.instance.exports.func`:**  假设 WebAssembly 模块导出了一个名为 `func` 的函数，我们可以通过这种方式获取它。
6. **`exportedFunc(42, 123n, 3.14, 2.71, {})`:**  调用导出的 WebAssembly 函数，这个调用会触发 WebAssembly 模块内部对导入函数 `func` (也就是我们在 `importObject` 中提供的 JavaScript 函数，但实际上对应的是 C++ 的 `PlusOne` 在 WebAssembly 层的封装) 的调用。

**总结:**

`callbacks.cc` 文件主要验证了 WebAssembly C API 中关于回调机制的实现。它通过 C++ 代码模拟了 WebAssembly 模块和外部函数交互的各种场景，这直接关系到 JavaScript 中如何通过 `importObject` 将 JavaScript 函数或使用 C API 编译的 C++ 函数提供给 WebAssembly 模块使用。JavaScript 示例展示了如何通过导入对象将一个 JavaScript 函数 (模拟 C++ 函数) 传递给 WebAssembly 模块，并在 WebAssembly 代码执行时被调用。

Prompt: 
```
这是目录为v8/test/wasm-api-tests/callbacks.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/wasm-api-tests/wasm-api-test.h"

#include "src/execution/isolate.h"
#include "src/heap/heap.h"
#include "src/wasm/c-api.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {

own<Trap> Stage2(void* env, const Val args[], Val results[]) {
  printf("Stage2...\n");
  WasmCapiTest* self = reinterpret_cast<WasmCapiTest*>(env);
  Func* stage3 = self->GetExportedFunction(1);
  own<Trap> trap = stage3->call(args, results);
  if (trap) {
    printf("Stage2: got exception: %s\n", trap->message().get());
  } else {
    printf("Stage2: call successful\n");
  }
  return trap;
}

own<Trap> Stage4_GC(void* env, const Val args[], Val results[]) {
  printf("Stage4...\n");
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(env);
  isolate->heap()->PreciseCollectAllGarbage(GCFlag::kForced,
                                            GarbageCollectionReason::kTesting);
  results[0] = Val::i32(args[0].i32() + 1);
  return nullptr;
}

class WasmCapiCallbacksTest : public WasmCapiTest {
 public:
  WasmCapiCallbacksTest() : WasmCapiTest() {
    // Build the following function:
    // int32 stage1(int32 arg0) { return stage2(arg0); }
    uint32_t stage2_index =
        builder()->AddImport(base::CStrVector("stage2"), wasm_i_i_sig());
    uint8_t code[] = {WASM_CALL_FUNCTION(stage2_index, WASM_LOCAL_GET(0))};
    AddExportedFunction(base::CStrVector("stage1"), code, sizeof(code));

    stage2_ = Func::make(store(), cpp_i_i_sig(), Stage2, this);
  }

  Func* stage2() { return stage2_.get(); }
  void AddExportedFunction(base::Vector<const char> name, uint8_t code[],
                           size_t code_size) {
    WasmCapiTest::AddExportedFunction(name, code, code_size, wasm_i_i_sig());
  }

 private:
  own<Func> stage2_;
};

}  // namespace

TEST_F(WasmCapiCallbacksTest, Trap) {
  // Build the following function:
  // int32 stage3_trap(int32 arg0) { unreachable(); }
  uint8_t code[] = {WASM_UNREACHABLE};
  AddExportedFunction(base::CStrVector("stage3_trap"), code, sizeof(code));

  Extern* imports[] = {stage2()};
  Instantiate(imports);
  Val args[] = {Val::i32(42)};
  Val results[1];
  own<Trap> trap = GetExportedFunction(0)->call(args, results);
  EXPECT_NE(trap, nullptr);
  printf("Stage0: Got trap as expected: %s\n", trap->message().get());
}

TEST_F(WasmCapiCallbacksTest, GC) {
  // Build the following function:
  // int32 stage3_to4(int32 arg0) { return stage4(arg0); }
  uint32_t stage4_index =
      builder()->AddImport(base::CStrVector("stage4"), wasm_i_i_sig());
  uint8_t code[] = {WASM_CALL_FUNCTION(stage4_index, WASM_LOCAL_GET(0))};
  AddExportedFunction(base::CStrVector("stage3_to4"), code, sizeof(code));

  i::Isolate* isolate =
      reinterpret_cast<::wasm::StoreImpl*>(store())->i_isolate();
  own<Func> stage4 = Func::make(store(), cpp_i_i_sig(), Stage4_GC, isolate);
  EXPECT_EQ(cpp_i_i_sig()->params().size(), stage4->type()->params().size());
  EXPECT_EQ(cpp_i_i_sig()->results().size(), stage4->type()->results().size());
  Extern* imports[] = {stage2(), stage4.get()};
  Instantiate(imports);
  Val args[] = {Val::i32(42)};
  Val results[1];
  own<Trap> trap = GetExportedFunction(0)->call(args, results);
  EXPECT_EQ(trap, nullptr);
  EXPECT_EQ(43, results[0].i32());
}

namespace {

own<Trap> FibonacciC(void* env, const Val args[], Val results[]) {
  int32_t x = args[0].i32();
  if (x == 0 || x == 1) {
    results[0] = Val::i32(x);
    return nullptr;
  }
  WasmCapiTest* self = reinterpret_cast<WasmCapiTest*>(env);
  Func* fibo_wasm = self->GetExportedFunction(0);
  // Aggressively re-use existing arrays. That's maybe not great coding
  // style, but this test intentionally ensures that it works if someone
  // insists on doing it.
  Val recursive_args[] = {Val::i32(x - 1)};
  own<Trap> trap = fibo_wasm->call(recursive_args, results);
  DCHECK_NULL(trap);
  int32_t x1 = results[0].i32();
  recursive_args[0] = Val::i32(x - 2);
  trap = fibo_wasm->call(recursive_args, results);
  DCHECK_NULL(trap);
  int32_t x2 = results[0].i32();
  results[0] = Val::i32(x1 + x2);
  return nullptr;
}

}  // namespace

TEST_F(WasmCapiTest, Recursion) {
  // Build the following function:
  // int32 fibonacci_wasm(int32 arg0) {
  //   if (arg0 == 0) return 0;
  //   if (arg0 == 1) return 1;
  //   return fibonacci_c(arg0 - 1) + fibonacci_c(arg0 - 2);
  // }
  uint32_t fibo_c_index =
      builder()->AddImport(base::CStrVector("fibonacci_c"), wasm_i_i_sig());
  uint8_t code_fibo[] = {
      WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_ZERO),
              WASM_RETURN(WASM_ZERO)),
      WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_ONE), WASM_RETURN(WASM_ONE)),
      // Muck with the parameter to ensure callers don't depend on its value.
      WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_ONE)),
      WASM_RETURN(WASM_I32_ADD(
          WASM_CALL_FUNCTION(fibo_c_index, WASM_LOCAL_GET(0)),
          WASM_CALL_FUNCTION(fibo_c_index,
                             WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_ONE))))};
  AddExportedFunction(base::CStrVector("fibonacci_wasm"), code_fibo,
                      sizeof(code_fibo), wasm_i_i_sig());

  own<Func> fibonacci = Func::make(store(), cpp_i_i_sig(), FibonacciC, this);
  Extern* imports[] = {fibonacci.get()};
  Instantiate(imports);
  // Enough iterations to make it interesting, few enough to keep it fast.
  Val args[] = {Val::i32(15)};
  Val results[1];
  own<Trap> result = GetExportedFunction(0)->call(args, results);
  EXPECT_EQ(result, nullptr);
  EXPECT_EQ(610, results[0].i32());
}

namespace {

own<Trap> PlusOne(const Val args[], Val results[]) {
  int32_t a0 = args[0].i32();
  results[0] = Val::i32(a0 + 1);
  int64_t a1 = args[1].i64();
  results[1] = Val::i64(a1 + 1);
  float a2 = args[2].f32();
  results[2] = Val::f32(a2 + 1);
  double a3 = args[3].f64();
  results[3] = Val::f64(a3 + 1);
  results[4] = Val::ref(args[4].ref()->copy());  // No +1 for Refs.
  return nullptr;
}

own<Trap> PlusOneWithManyArgs(const Val args[], Val results[]) {
  int32_t a0 = args[0].i32();
  results[0] = Val::i32(a0 + 1);
  int64_t a1 = args[1].i64();
  results[1] = Val::i64(a1 + 1);
  float a2 = args[2].f32();
  results[2] = Val::f32(a2 + 1);
  double a3 = args[3].f64();
  results[3] = Val::f64(a3 + 1);
  results[4] = Val::ref(args[4].ref()->copy());  // No +1 for Refs.
  int32_t a5 = args[5].i32();
  results[5] = Val::i32(a5 + 1);
  int64_t a6 = args[6].i64();
  results[6] = Val::i64(a6 + 1);
  float a7 = args[7].f32();
  results[7] = Val::f32(a7 + 1);
  double a8 = args[8].f64();
  results[8] = Val::f64(a8 + 1);
  int32_t a9 = args[9].i32();
  results[9] = Val::i32(a9 + 1);
  int64_t a10 = args[10].i64();
  results[10] = Val::i64(a10 + 1);
  float a11 = args[11].f32();
  results[11] = Val::f32(a11 + 1);
  double a12 = args[12].f64();
  results[12] = Val::f64(a12 + 1);
  int32_t a13 = args[13].i32();
  results[13] = Val::i32(a13 + 1);
  return nullptr;
}
}  // namespace

TEST_F(WasmCapiTest, DirectCallCapiFunction) {
  own<FuncType> cpp_sig =
      FuncType::make(ownvec<ValType>::make(
                         ValType::make(::wasm::I32), ValType::make(::wasm::I64),
                         ValType::make(::wasm::F32), ValType::make(::wasm::F64),
                         ValType::make(::wasm::ANYREF)),
                     ownvec<ValType>::make(
                         ValType::make(::wasm::I32), ValType::make(::wasm::I64),
                         ValType::make(::wasm::F32), ValType::make(::wasm::F64),
                         ValType::make(::wasm::ANYREF)));
  own<Func> func = Func::make(store(), cpp_sig.get(), PlusOne);
  Extern* imports[] = {func.get()};
  ValueType wasm_types[] = {kWasmI32,       kWasmI64,      kWasmF32, kWasmF64,
                            kWasmExternRef, kWasmI32,      kWasmI64, kWasmF32,
                            kWasmF64,       kWasmExternRef};
  FunctionSig wasm_sig(5, 5, wasm_types);
  int func_index = builder()->AddImport(base::CStrVector("func"), &wasm_sig);
  builder()->ExportImportedFunction(base::CStrVector("func"), func_index);
  Instantiate(imports);
  int32_t a0 = 42;
  int64_t a1 = 0x1234c0ffee;
  float a2 = 1234.5;
  double a3 = 123.45;
  Val args[] = {Val::i32(a0), Val::i64(a1), Val::f32(a2), Val::f64(a3),
                Val::ref(func->copy())};
  Val results[5];
  // Test that {func} can be called directly.
  own<Trap> trap = func->call(args, results);
  EXPECT_EQ(nullptr, trap);
  EXPECT_EQ(a0 + 1, results[0].i32());
  EXPECT_EQ(a1 + 1, results[1].i64());
  EXPECT_EQ(a2 + 1, results[2].f32());
  EXPECT_EQ(a3 + 1, results[3].f64());
  EXPECT_TRUE(func->same(results[4].ref()));

  // Test that {func} can be called after import/export round-tripping.
  trap = GetExportedFunction(0)->call(args, results);
  EXPECT_EQ(nullptr, trap);
  EXPECT_EQ(a0 + 1, results[0].i32());
  EXPECT_EQ(a1 + 1, results[1].i64());
  EXPECT_EQ(a2 + 1, results[2].f32());
  EXPECT_EQ(a3 + 1, results[3].f64());
  EXPECT_TRUE(func->same(results[4].ref()));
}

TEST_F(WasmCapiTest, DirectCallCapiFunctionWithManyArgs) {
  // Test with many arguments to make sure that CWasmArgumentsPacker won't use
  // its buffer-on-stack optimization.
  own<FuncType> cpp_sig = FuncType::make(
      ownvec<ValType>::make(
          ValType::make(::wasm::I32), ValType::make(::wasm::I64),
          ValType::make(::wasm::F32), ValType::make(::wasm::F64),
          ValType::make(::wasm::ANYREF), ValType::make(::wasm::I32),
          ValType::make(::wasm::I64), ValType::make(::wasm::F32),
          ValType::make(::wasm::F64), ValType::make(::wasm::I32),
          ValType::make(::wasm::I64), ValType::make(::wasm::F32),
          ValType::make(::wasm::F64), ValType::make(::wasm::I32)),
      ownvec<ValType>::make(
          ValType::make(::wasm::I32), ValType::make(::wasm::I64),
          ValType::make(::wasm::F32), ValType::make(::wasm::F64),
          ValType::make(::wasm::ANYREF), ValType::make(::wasm::I32),
          ValType::make(::wasm::I64), ValType::make(::wasm::F32),
          ValType::make(::wasm::F64), ValType::make(::wasm::I32),
          ValType::make(::wasm::I64), ValType::make(::wasm::F32),
          ValType::make(::wasm::F64), ValType::make(::wasm::I32)));
  own<Func> func = Func::make(store(), cpp_sig.get(), PlusOneWithManyArgs);
  Extern* imports[] = {func.get()};
  ValueType wasm_types[] = {
      kWasmI32,       kWasmI64, kWasmF32, kWasmF64, kWasmExternRef, kWasmI32,
      kWasmI64,       kWasmF32, kWasmF64, kWasmI32, kWasmI64,       kWasmF32,
      kWasmF64,       kWasmI32, kWasmI32, kWasmI64, kWasmF32,       kWasmF64,
      kWasmExternRef, kWasmI32, kWasmI64, kWasmF32, kWasmF64,       kWasmI32,
      kWasmI64,       kWasmF32, kWasmF64, kWasmI32};
  FunctionSig wasm_sig(14, 14, wasm_types);
  int func_index = builder()->AddImport(base::CStrVector("func"), &wasm_sig);
  builder()->ExportImportedFunction(base::CStrVector("func"), func_index);
  Instantiate(imports);
  int32_t a0 = 42;
  int64_t a1 = 0x1234c0ffee;
  float a2 = 1234.5;
  double a3 = 123.45;
  Val args[] = {
      Val::i32(a0),           Val::i64(a1), Val::f32(a2), Val::f64(a3),
      Val::ref(func->copy()), Val::i32(a0), Val::i64(a1), Val::f32(a2),
      Val::f64(a3),           Val::i32(a0), Val::i64(a1), Val::f32(a2),
      Val::f64(a3),           Val::i32(a0)};
  Val results[14];
  // Test that {func} can be called directly.
  own<Trap> trap = func->call(args, results);
  EXPECT_EQ(nullptr, trap);
  EXPECT_EQ(a0 + 1, results[0].i32());
  EXPECT_EQ(a1 + 1, results[1].i64());
  EXPECT_EQ(a2 + 1, results[2].f32());
  EXPECT_EQ(a3 + 1, results[3].f64());
  EXPECT_TRUE(func->same(results[4].ref()));
  EXPECT_EQ(a0 + 1, results[5].i32());
  EXPECT_EQ(a1 + 1, results[6].i64());
  EXPECT_EQ(a2 + 1, results[7].f32());
  EXPECT_EQ(a3 + 1, results[8].f64());
  EXPECT_EQ(a0 + 1, results[9].i32());
  EXPECT_EQ(a1 + 1, results[10].i64());
  EXPECT_EQ(a2 + 1, results[11].f32());
  EXPECT_EQ(a3 + 1, results[12].f64());
  EXPECT_EQ(a0 + 1, results[13].i32());

  // Test that {func} can be called after import/export round-tripping.
  trap = GetExportedFunction(0)->call(args, results);
  EXPECT_EQ(nullptr, trap);
  EXPECT_EQ(a0 + 1, results[0].i32());
  EXPECT_EQ(a1 + 1, results[1].i64());
  EXPECT_EQ(a2 + 1, results[2].f32());
  EXPECT_EQ(a3 + 1, results[3].f64());
  EXPECT_TRUE(func->same(results[4].ref()));
  EXPECT_EQ(a0 + 1, results[5].i32());
  EXPECT_EQ(a1 + 1, results[6].i64());
  EXPECT_EQ(a2 + 1, results[7].f32());
  EXPECT_EQ(a3 + 1, results[8].f64());
  EXPECT_EQ(a0 + 1, results[9].i32());
  EXPECT_EQ(a1 + 1, results[10].i64());
  EXPECT_EQ(a2 + 1, results[11].f32());
  EXPECT_EQ(a3 + 1, results[12].f64());
  EXPECT_EQ(a0 + 1, results[13].i32());
}
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```