Response:
Let's break down the thought process for analyzing the C++ code and generating the detailed explanation.

1. **Understanding the Goal:** The request is to analyze a C++ file related to WebAssembly (Wasm) within the V8 JavaScript engine. The goal is to identify its functionality, relate it to JavaScript if possible, illustrate with examples, and highlight common programming errors.

2. **Initial Scan and High-Level Overview:**  A quick skim of the code reveals several key elements:
    * Includes:  `wasm-api-test.h`, `isolate.h`, `heap.h`, `c-api.h` strongly suggest this is a test file exercising the Wasm C API within the V8 context.
    * Namespaces: `v8::internal::wasm` confirms the Wasm focus.
    * `TEST_F`: This macro indicates the use of Google Test framework, confirming it's a test file.
    * Function names like `Stage2`, `Stage4_GC`, `FibonacciC`, `PlusOne`, `PlusOneWithManyArgs` provide hints about their purpose.
    * Usage of `Func`, `Val`, `Trap`, `Store`, `Module`, `Instance`: These are core Wasm C API types.
    * `WASM_...` macros:  These are likely Wasm bytecode instructions.

3. **Analyzing Individual Test Cases:**  The `TEST_F` macros define individual test cases. It's beneficial to examine each one separately.

    * **`Trap` Test:**
        * Focus on `Stage2` function: It calls another Wasm function (`stage3`).
        * Focus on `stage3_trap`: It contains `WASM_UNREACHABLE`, which will cause a trap.
        * The test imports `stage2` and calls the exported function `stage1` which internally calls `stage2`. The expectation is a trap.
        * **Hypothesis:** This test verifies that traps originating from Wasm code are correctly propagated and handled through the C API.

    * **`GC` Test:**
        * Focus on `Stage4_GC`: It performs a garbage collection using V8's internal API (`isolate->heap()->PreciseCollectAllGarbage`). It also increments an integer argument.
        * The test imports `stage2` and `stage4`. `stage3_to4` calls `stage4`.
        * **Hypothesis:** This test checks if calling a C++ callback that triggers garbage collection interacts correctly with the Wasm execution environment. It also verifies passing arguments and returning values between Wasm and C++.

    * **`Recursion` Test:**
        * Focus on `FibonacciC`: It implements the Fibonacci sequence recursively, calling back into Wasm.
        * The Wasm function `fibonacci_wasm` imports `fibonacci_c` and calls it.
        * **Hypothesis:** This test confirms that Wasm modules can call back into C++ functions, which in turn can recursively call back into the same Wasm module. It's a test of the interop and call stack management.

    * **`DirectCallCapiFunction` Test:**
        * Focus on `PlusOne`: It takes various primitive types and a `ref` as input, increments the primitives, and returns them.
        * The test directly creates a `Func` using `Func::make` and then calls it directly using `func->call`. It also imports and exports this function to test the round-trip.
        * **Hypothesis:** This test verifies the basic functionality of calling C++ functions directly from the C API and also after importing and exporting them to Wasm. It covers various data types.

    * **`DirectCallCapiFunctionWithManyArgs` Test:**
        * Focus on `PlusOneWithManyArgs`: Similar to `PlusOne`, but with many more arguments.
        * **Hypothesis:** This test likely aims to stress the argument passing mechanisms, especially for cases where optimizations like stack-based argument packing might be bypassed (as hinted by the comment about `CWasmArgumentsPacker`).

4. **Identifying Functionality of the File:** Based on the test cases, the primary function of `callbacks.cc` is to test the interaction between Wasm modules and C++ functions through callbacks provided via the Wasm C API. This includes:
    * Calling C++ functions from Wasm.
    * Handling traps originating in Wasm within C++ callbacks.
    * Triggering garbage collection from C++ callbacks called by Wasm.
    * Recursive calls between Wasm and C++.
    * Passing various data types as arguments and return values.
    * Testing direct invocation of C++ functions registered via the C API.
    * Testing scenarios with a large number of arguments.

5. **Relating to JavaScript (and Potential Torque):**
    * The file is C++, so it's not directly Torque (`.tq`).
    * The functionality is directly related to how JavaScript (running on V8) interacts with Wasm. When JavaScript calls a Wasm function that imports a C++ function, the execution flow goes through the mechanisms tested here.
    * **JavaScript Example:**  Illustrate how a JavaScript environment might import and call a Wasm module that relies on these C++ callbacks.

6. **Code Logic and Examples (Hypothetical Input/Output):** For each test case, define a simple input and trace the execution to predict the output. This helps solidify understanding.

7. **Common Programming Errors:** Think about what could go wrong when using callbacks between Wasm and C++.
    * Mismatched function signatures (argument types, return types).
    * Incorrectly handling `Trap` objects (not checking for null).
    * Memory management issues (though the C API tries to abstract this, incorrect usage could still lead to problems).
    * Re-entrancy issues if the C++ callback has side effects that interfere with Wasm's state (though not explicitly shown here, it's a potential concern).

8. **Structuring the Explanation:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Describe the functionality of each key function (`Stage2`, `Stage4_GC`, etc.).
    * Explain each test case, its purpose, and expected behavior.
    * Provide the JavaScript example.
    * Detail the hypothetical input/output scenarios.
    * List common programming errors.

9. **Refinement and Clarity:** Review the explanation for clarity, accuracy, and completeness. Ensure the language is precise and easy to understand. For example, explaining the role of `WasmCapiTest` as a helper class that simplifies Wasm module creation and instantiation is important.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and informative explanation that addresses all aspects of the original request. The key is to break down the problem into smaller, manageable parts and to use the available information (function names, API usage, test structure) to infer the overall functionality and purpose.
这个C++源代码文件 `v8/test/wasm-api-tests/callbacks.cc` 是 V8 JavaScript 引擎中用于测试 WebAssembly (Wasm) C API 回调功能的测试文件。

**功能列表:**

1. **测试从 Wasm 模块调用 C++ 函数 (Callbacks):**  该文件主要测试了 Wasm 模块如何通过导入函数的方式调用在 C++ 中定义的函数（回调函数）。

2. **测试不同类型的回调:**  文件中定义了多个不同的 C++ 回调函数，用于测试各种场景，包括：
   - 简单的函数调用 (`Stage2`).
   - 触发垃圾回收的函数调用 (`Stage4_GC`).
   - 递归调用的函数 (`FibonacciC`).
   - 接受和返回不同类型参数的函数 (`PlusOne`, `PlusOneWithManyArgs`).

3. **测试 Wasm 中的 Trap (异常) 处理:**  测试了当 C++ 回调函数被 Wasm 调用时，如果回调函数内部发生错误（例如调用了可能抛出异常的 Wasm 函数并捕获了异常），Wasm 侧如何处理这个 Trap。

4. **测试垃圾回收与 Wasm 的交互:**  `Stage4_GC` 函数显式地触发了 V8 的垃圾回收器，用于测试在 Wasm 执行过程中，由回调函数触发垃圾回收是否会引起问题，以及是否能正常返回。

5. **测试递归调用:** `Recursion` 测试用例通过 `FibonacciC` 回调函数展示了 C++ 函数如何调用 Wasm 函数，以及 Wasm 函数如何再次调用 C++ 函数，从而实现递归。

6. **测试不同数量和类型的参数传递:** `PlusOne` 和 `PlusOneWithManyArgs` 测试用例测试了 C++ 回调函数与 Wasm 模块之间传递不同数据类型（int32, int64, float, double, 引用）以及不同数量的参数时的正确性。

7. **测试直接调用 C API 函数:**  `DirectCallCapiFunction` 和 `DirectCallCapiFunctionWithManyArgs` 测试了直接通过 C API 获取 `Func` 对象并调用，以及通过导入导出后再调用的情况。

**关于 `.tq` 结尾:**

`v8/test/wasm-api-tests/callbacks.cc` 以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系 (示例):**

该 C++ 文件测试的功能是 WebAssembly 和宿主环境（通常是 JavaScript 环境）交互的核心部分。当你在 JavaScript 中加载并运行一个 Wasm 模块时，如果该 Wasm 模块导入了一些在 JavaScript 或宿主环境提供的函数，那么这些函数的实现就类似于此文件中定义的回调函数。

**JavaScript 示例:**

```javascript
// 假设你有一个编译好的 Wasm 模块 (callbacks.wasm)
fetch('callbacks.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes, {
    env: { // 导入的对象，包含 C++ 中定义的回调函数对应的 JavaScript 函数
      stage2: function(arg) {
        console.log("JavaScript: stage2 called with", arg);
        // 这里可以调用 Wasm 模块中导出的另一个函数
        // 假设 module.instance.exports.stage3 存在
        try {
          const result = module.instance.exports.stage3(arg);
          console.log("JavaScript: stage2 got result from stage3:", result);
          return result;
        } catch (e) {
          console.error("JavaScript: stage2 caught exception from stage3:", e);
          throw e; // 将异常抛回 Wasm
        }
      },
      stage4: function(arg) {
        console.log("JavaScript: stage4 called with", arg);
        // 在 JavaScript 中执行一些操作，例如触发垃圾回收
        if (global.gc) {
          global.gc();
          console.log("JavaScript: Garbage collection triggered.");
        }
        return arg + 1;
      },
      fibonacci_c: function(n) {
        console.log("JavaScript: fibonacci_c called with", n);
        if (n <= 1) return n;
        return module.instance.exports.fibonacci_wasm(n - 1) + module.instance.exports.fibonacci_wasm(n - 2);
      },
      func: function(a0, a1, a2, a3, a4) {
        console.log("JavaScript: func called with", a0, a1, a2, a3, a4);
        return [a0 + 1, BigInt(a1) + 1n, a2 + 1, a3 + 1, a4];
      }
      // ... 其他导入的函数
    }
  }))
  .then(module => {
    console.log("Wasm module loaded:", module);
    // 调用 Wasm 模块中导出的函数，它会间接调用到 JavaScript 定义的回调函数
    const result1 = module.instance.exports.stage1(10);
    console.log("Result of stage1:", result1);

    const result_gc = module.instance.exports.stage3_to4(20);
    console.log("Result of stage3_to4:", result_gc);

    const fibonacci_result = module.instance.exports.fibonacci_wasm(5);
    console.log("Fibonacci result:", fibonacci_result);

    const direct_call_result = module.instance.exports.func(1, 2n, 3.0, 4.0, "hello");
    console.log("Direct call result:", direct_call_result);
  });
```

在这个 JavaScript 示例中，`env` 对象包含了提供给 Wasm 模块的导入函数。当 Wasm 代码调用 `stage2`、`stage4` 或 `fibonacci_c` 等导入函数时，实际上会调用到 JavaScript 中对应的函数。这与 C++ 代码中定义的回调函数被 Wasm 调用的机制类似。

**代码逻辑推理 (假设输入与输出):**

**`TEST_F(WasmCapiCallbacksTest, Trap)`:**

* **假设输入:** 调用 `GetExportedFunction(0)` (即 `stage1`)，并传入参数 `args = {Val::i32(42)}`。
* **执行流程:**
    1. `stage1` 被调用，它会调用导入的 `stage2`。
    2. `Stage2` C++ 回调函数被调用，它会打印 "Stage2..."。
    3. `Stage2` 调用 `GetExportedFunction(1)` (即 `stage3_trap`)。
    4. `stage3_trap` 内部执行 `WASM_UNREACHABLE`，这会产生一个 Trap。
    5. Trap 返回到 `Stage2`，`Stage2` 打印 "Stage2: got exception: ..."。
    6. Trap 从 `Stage2` 返回到 `stage1` 的调用点。
* **预期输出:** `trap` 不为 `nullptr`，并且打印 "Stage0: Got trap as expected: ..."。

**`TEST_F(WasmCapiCallbacksTest, GC)`:**

* **假设输入:** 调用 `GetExportedFunction(0)` (即 `stage1`)，并传入参数 `args = {Val::i32(42)}`。
* **执行流程:**
    1. `stage1` 被调用，它会调用导入的 `stage2`。
    2. `Stage2` C++ 回调函数被调用，它会打印 "Stage2..."。
    3. `Stage2` 调用 `GetExportedFunction(1)` (即 `stage3_to4`)。
    4. `stage3_to4` 被调用，它会调用导入的 `stage4`。
    5. `Stage4_GC` C++ 回调函数被调用，它会打印 "Stage4..."，并执行垃圾回收。
    6. `Stage4_GC` 将参数加 1，并将结果 `Val::i32(43)` 写入 `results[0]`.
    7. 返回值 `nullptr` 表示没有 Trap。
    8. 执行流程返回到 `Stage2`，打印 "Stage2: call successful"。
    9. 执行流程返回到 `stage1` 的调用点。
* **预期输出:** `trap` 为 `nullptr`，并且 `results[0].i32()` 的值为 `43`。

**`TEST_F(WasmCapiTest, Recursion)`:**

* **假设输入:** 调用 `GetExportedFunction(0)` (即 `fibonacci_wasm`)，并传入参数 `args = {Val::i32(15)}`。
* **执行流程:**  `fibonacci_wasm` 会递归地调用 `FibonacciC`，直到基线条件 (arg0 == 0 或 1)。`FibonacciC` 也会递归地调用 `fibonacci_wasm`。
* **预期输出:** `result` 为 `nullptr`，并且 `results[0].i32()` 的值为斐波那契数列的第 15 项，即 `610`。

**用户常见的编程错误 (涉及回调):**

1. **函数签名不匹配:**  在 Wasm 模块中导入的函数签名（参数类型和返回值类型）必须与 C++ 中提供的回调函数的签名完全一致。如果不匹配，会导致链接错误或运行时错误。

   ```c++
   // C++ 回调函数
   own<Trap> MyCallback(void* env, const Val args[], Val results[]) {
       // ...
       results[0] = Val::i32(10);
       return nullptr;
   }
   ```

   ```javascript
   // JavaScript 导入
   const importObject = {
       env: {
           myCallback: function() { // 错误：参数数量不匹配
               return 10;
           }
       }
   };
   ```

2. **未处理 Trap 对象:** 当从 C++ 回调函数中调用 Wasm 函数时，`call` 方法会返回一个 `own<Trap>` 对象。如果调用的 Wasm 函数抛出了异常，则该对象不为 `nullptr`。开发者需要检查并处理这个 `Trap` 对象，否则可能会导致程序崩溃或行为异常。

   ```c++
   own<Trap> Stage2(void* env, const Val args[], Val results[]) {
       // ...
       own<Trap> trap = stage3->call(args, results);
       // 忘记检查 trap
       printf("Stage2: call successful\n"); // 如果 stage3 抛出异常，这行代码仍然会执行
       return nullptr;
   }
   ```

   **正确的做法:**

   ```c++
   own<Trap> Stage2(void* env, const Val args[], Val results[]) {
       // ...
       own<Trap> trap = stage3->call(args, results);
       if (trap) {
           printf("Stage2: got exception: %s\n", trap->message().get());
           return trap; // 将 Trap 传递回去
       } else {
           printf("Stage2: call successful\n");
           return nullptr;
       }
   }
   ```

3. **在回调函数中访问无效的内存或资源:**  如果 C++ 回调函数依赖于特定的环境或状态，而 Wasm 的调用发生在不恰当的时机，可能会导致访问无效的内存或资源。

4. **在回调函数中进行不安全的操作:**  例如，在回调函数中直接操作 V8 的内部数据结构而不遵循其 API 规则，可能会导致 V8 的状态损坏。

5. **忘记正确设置 `env` 指针:**  回调函数的第一个参数 `void* env` 是一个用户提供的环境指针。在创建 `Func` 对象时需要正确设置这个指针，以便在回调函数中使用。

   ```c++
   own<Func> stage2_ = Func::make(store(), cpp_i_i_sig(), Stage2, nullptr); // 错误：env 为 nullptr，Stage2 中访问 self 会出错
   ```

   **正确的做法:**

   ```c++
   own<Func> stage2_ = Func::make(store(), cpp_i_i_sig(), Stage2, this);
   ```

理解这些测试用例和可能出现的错误，对于开发和调试涉及 WebAssembly 和 C++ 交互的程序至关重要。`callbacks.cc` 提供了一组很好的示例，展示了如何正确地使用 V8 的 Wasm C API 来实现回调功能。

### 提示词
```
这是目录为v8/test/wasm-api-tests/callbacks.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/wasm-api-tests/callbacks.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```