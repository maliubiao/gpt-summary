Response:
The user wants a summary of the functionalities of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite for WebAssembly.

Here's a breakdown of the request and how to address it:

1. **Identify the file's purpose:** The file `v8/test/cctest/wasm/test-run-wasm.cc` suggests it contains tests for running WebAssembly code. The `cctest` directory further indicates that these are component tests.

2. **Analyze individual tests:** Each `WASM_EXEC_TEST` or `WASM_COMPILED_EXEC_TEST` macro defines a single test case. We need to examine the code within each test to understand what it's testing.

3. **Look for patterns and themes:** Group similar tests to identify broader functionalities being tested. Keywords like "Mem," "Loop," "Unreachable," "Global," and "Call" are strong indicators.

4. **Check for Torque relevance:** The prompt mentions `.tq` files, but this file is `.cc`. So, Torque is not relevant here.

5. **Connect to JavaScript (if applicable):**  WebAssembly executes within a JavaScript environment. If a test demonstrates a concept that has a direct parallel in JavaScript, provide an example.

6. **Analyze code logic and provide examples:** For tests involving specific operations or control flow, create simple "what-if" scenarios with example inputs and expected outputs.

7. **Highlight common programming errors:**  If a test implicitly or explicitly demonstrates a potential programming mistake, point it out with an example.

8. **Focus on the provided snippet:** The request specifically asks for the functionalities *within this particular code block* (part 3 of 5).

**Mental Walkthrough of the Code Snippet:**

* **Memory Access:**  Several tests involve reading and writing to memory (`kExprI32LoadMem`, `WASM_LOAD_MEM`, `WASM_STORE_MEM`). They test different data types (int32, float32, float64).
* **Loops:**  The code uses `kExprLoop` and `WASM_WHILE` to test loop constructs in WebAssembly.
* **Conditionals:** `kExprIf` and `WASM_IF`, `WASM_IF_ELSE` are used for testing conditional branching.
* **Unreachable Code:**  Tests named "Unreachable" examine how the engine handles unreachable instructions.
* **Globals:** Tests with "Global" manipulate WebAssembly global variables.
* **Function Calls:** Tests with "Call" explore different aspects of function calls (empty calls, calls with parameters, calls with return values, recursive calls).
* **Return Call Optimization:** Tests with "ReturnCall" specifically target tail-call optimization.
* **Indirect Calls:** The "ReturnCall_IndirectFactorial" test uses an indirect function call.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. v8/test/cctest/wasm/test-run-wasm.cc以.tq结尾: No
3. 与javascript的功能有关系，请用javascript举例说明: Yes (WebAssembly in JS environment)
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第3部分，共5部分，请归纳一下它的功能: Yes

Confidence Score: 5/5  All constraints can be met.

**Plan of Action:**

1. Summarize the general purpose of the file.
2. Group the tests by functionality (memory access, loops, conditionals, globals, function calls, etc.).
3. For each functionality group, describe what the tests aim to verify.
4. Provide JavaScript examples where relevant, focusing on how these WebAssembly features interact with or are represented in JavaScript.
5. For code logic examples, select representative tests and provide input/output scenarios.
6. Point out potential programming errors illustrated by the tests (e.g., uninitialized memory, infinite loops).
7. Conclude with a concise summary of the functionalities covered in this specific part of the file.
这是 `v8/test/cctest/wasm/test-run-wasm.cc` 源代码的第三部分，它主要的功能是 **测试 WebAssembly 代码的执行和编译的各种场景，包括内存操作、控制流、全局变量、函数调用（包括直接调用、尾调用、间接调用）以及混合类型的参数和返回值处理**。

由于 `v8/test/cctest/wasm/test-run-wasm.cc` 以 `.cc` 结尾，它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

以下对代码片段中的功能进行归纳和解释：

**功能归纳:**

1. **内存操作测试:**
   - 测试从内存中加载和存储不同大小和类型的数值 (`i32`, `f32`, `f64`, `i8`, `u8`, `i16`, `u16`)。
   - 测试内存的初始化和随机化。
   - 测试内存操作与循环的结合。

2. **控制流测试:**
   - 测试 `loop` 循环结构，包括在循环中提前返回的情况。
   - 测试 `while` 循环结构。
   - 测试 `if` 条件语句，包括 `if-else` 结构。
   - 测试 `unreachable` 指令，验证代码执行到不可达指令时的行为。
   - 测试 `br` (break) 指令，包括带返回值的 `brv`。
   - 测试无限循环 (`WASM_INFINITE_LOOP`) 以及不进入无限循环的情况。

3. **全局变量测试:**
   - 测试整型 (`i32`) 全局变量的读取和写入。
   - 测试浮点型 (`f32`, `f64`) 全局变量的读取和写入。
   - 测试多个全局变量同时存在且不互相干扰的情况。
   - 测试不同类型的全局变量混合使用。

4. **函数调用测试:**
   - 测试无参数无返回值的函数调用。
   - 测试带有浮点数 (`f32`, `f64`) 栈参数的函数调用。
   - 测试调用无返回值函数并验证内存变化。
   - 测试带有整型 (`i32`) 参数和返回值的函数调用。
   - 测试带有浮点数 (`f32`) 参数和返回值的函数调用。
   - 测试函数调用中参数和返回值的类型转换。

5. **尾调用优化测试 (Return Call):**
   - 测试尾递归阶乘函数的尾调用优化。
   - 测试相互递归阶乘函数的尾调用优化。
   - 测试间接尾调用优化。
   - 测试尾递归求和函数的尾调用优化。
   - 测试相互递归求和函数的尾调用优化。

6. **混合类型函数调用测试:**
   - 测试带有多种不同类型参数（`i32`, `f32`, `f64`) 的函数调用，并验证返回值类型。

7. **多返回值函数测试:**
   - 测试具有多个返回值的函数调用，并选择其中一个返回值。

**与 JavaScript 的关系 (示例):**

WebAssembly 模块通常在 JavaScript 环境中加载和执行。这些测试验证了 WebAssembly 模块内部的各种操作，这些操作可以通过 JavaScript API 调用 WebAssembly 导出的函数来触发。

**JavaScript 示例 (模拟内存加载):**

```javascript
const wasmCode = new Uint8Array([
  // ... wasm 字节码 ...
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });
const memory = wasmInstance.exports.memory; // 获取 WebAssembly 内存

// 假设 WebAssembly 代码中有加载内存的操作，如下代码模拟了从 wasm 内存中读取一个 i32
const offset = 8; // 假设要读取的内存偏移量
const view = new Int32Array(memory.buffer);
const value = view[offset / Int32Array.BYTES_PER_ELEMENT];
console.log(value);
```

**代码逻辑推理 (示例):**

**测试用例:** `WASM_EXEC_TEST(MemF32_Sum)`

**假设输入:**
- 内存中偏移量为 0 的位置存储浮点数 -99.25
- 内存中偏移量为 4 的位置存储浮点数 -888.25
- 内存中偏移量为 8 的位置存储浮点数 -77.25
- 内存中偏移量为 12 的位置存储浮点数 66666.25
- 内存中偏移量为 16 的位置存储浮点数 5555.25
- 调用函数时传入参数 `4 * (5 - 1) = 16`

**代码逻辑:**
- 循环从传入的参数值 (16) 开始，每次减 4，直到参数为 0。
- 在循环中，从内存中加载浮点数，并累加到一个局部变量 `kSum` 中。加载的地址由当前的参数值决定。
- 循环结束后，将 `kSum` 的值存储回内存偏移量为 0 的位置。

**预期输出:**
- 调用函数返回 0。
- 内存偏移量为 0 的位置存储的值为 -99.25 + (-888.25) + (-77.25) + 66666.25 + 5555.25 = 71256.0。

**用户常见的编程错误 (示例):**

**测试用例:**  与内存访问相关的测试，例如 `WASM_EXEC_TEST(LoadMemOutOfBounds)` (虽然这个特定的测试用例没有在这个片段中，但可以推断出类似的测试存在于其他部分)。

**错误示例:**

```c++
// 假设 WebAssembly 代码尝试访问超出内存边界的地址
kExprLocalGet, 0,      // 获取偏移量 (例如，一个很大的值)
kExprI32LoadMem, 0, 0, // 尝试加载该偏移量的内存
```

**JavaScript 场景:**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 }); // 1 页内存
const instance = new WebAssembly.Instance(module, { /* imports */ });

// 尝试访问超出内存边界的地址
const offset = 65536; // 大于 1 页内存的大小
const view = new Int32Array(memory.buffer);
const value = view[offset / Int32Array.BYTES_PER_ELEMENT]; // 这将导致 RangeError
```

**常见的编程错误:**
- **越界内存访问:** 尝试读取或写入超出分配内存范围的地址，导致程序崩溃或未定义的行为。
- **类型不匹配:** 尝试以错误的类型解释内存中的数据。
- **未初始化的内存:**  读取未被赋值的内存区域，导致不可预测的结果.
- **无限循环:**  编写了永远无法退出的循环，导致程序卡死。

**总结 (针对提供的第三部分代码):**

这部分代码着重于测试 V8 引擎执行 WebAssembly 代码时，对于**内存访问、各种控制流结构、全局变量的管理以及不同类型的函数调用**的正确性。它涵盖了从简单的内存读写到复杂的尾调用优化等多个方面，旨在确保 V8 能够可靠地运行各种 WebAssembly 代码。这些测试用例覆盖了 WebAssembly 规范中的重要特性，并帮助开发者发现和修复潜在的引擎缺陷。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
t int kNumElems = 55;
  WasmRunner<uint32_t, int32_t> r(execution_tier);
  r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));

  r.Build({
      // clang-format off
      kExprLoop, kVoidCode,
        kExprLocalGet, 0,
        kExprIf, kVoidCode,
          kExprLocalGet, 0,
          kExprI32LoadMem, 0, 0,
          kExprIf, kVoidCode,
            kExprI32Const, 127,
            kExprReturn,
          kExprEnd,
          kExprLocalGet, 0,
          kExprI32Const, 4,
          kExprI32Sub,
          kExprLocalTee, 0,
          kExprBr, DEPTH_0,
        kExprEnd,
      kExprEnd,
      kExprI32Const, 0
      // clang-format on
  });

  r.builder().BlankMemory();
  CHECK_EQ(0, r.Call((kNumElems - 1) * 4));
}

WASM_EXEC_TEST(MemF32_Sum) {
  const int kSize = 5;
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  float* buffer = r.builder().raw_mem_start<float>();
  r.builder().WriteMemory(&buffer[0], -99.25f);
  r.builder().WriteMemory(&buffer[1], -888.25f);
  r.builder().WriteMemory(&buffer[2], -77.25f);
  r.builder().WriteMemory(&buffer[3], 66666.25f);
  r.builder().WriteMemory(&buffer[4], 5555.25f);
  const uint8_t kSum = r.AllocateLocal(kWasmF32);

  r.Build(
      {WASM_WHILE(WASM_LOCAL_GET(0),
                  WASM_BLOCK(WASM_LOCAL_SET(
                                 kSum, WASM_F32_ADD(
                                           WASM_LOCAL_GET(kSum),
                                           WASM_LOAD_MEM(MachineType::Float32(),
                                                         WASM_LOCAL_GET(0)))),
                             WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0),
                                                            WASM_I32V_1(4))))),
       WASM_STORE_MEM(MachineType::Float32(), WASM_ZERO, WASM_LOCAL_GET(kSum)),
       WASM_LOCAL_GET(0)});

  CHECK_EQ(0, r.Call(4 * (kSize - 1)));
  CHECK_NE(-99.25f, r.builder().ReadMemory(&buffer[0]));
  CHECK_EQ(71256.0f, r.builder().ReadMemory(&buffer[0]));
}

template <typename T>
T GenerateAndRunFold(TestExecutionTier execution_tier, WasmOpcode binop,
                     T* buffer, uint32_t size, ValueType astType,
                     MachineType memType) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  T* memory = r.builder().AddMemoryElems<T>(static_cast<uint32_t>(
      RoundUp(size * sizeof(T), kWasmPageSize) / sizeof(sizeof(T))));
  for (uint32_t i = 0; i < size; ++i) {
    r.builder().WriteMemory(&memory[i], buffer[i]);
  }
  const uint8_t kAccum = r.AllocateLocal(astType);

  r.Build(
      {WASM_LOCAL_SET(kAccum, WASM_LOAD_MEM(memType, WASM_ZERO)),
       WASM_WHILE(
           WASM_LOCAL_GET(0),
           WASM_BLOCK(WASM_LOCAL_SET(
                          kAccum, WASM_BINOP(binop, WASM_LOCAL_GET(kAccum),
                                             WASM_LOAD_MEM(memType,
                                                           WASM_LOCAL_GET(0)))),
                      WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0),
                                                     WASM_I32V_1(sizeof(T)))))),
       WASM_STORE_MEM(memType, WASM_ZERO, WASM_LOCAL_GET(kAccum)),
       WASM_LOCAL_GET(0)});
  r.Call(static_cast<int>(sizeof(T) * (size - 1)));
  return r.builder().ReadMemory(&memory[0]);
}

WASM_EXEC_TEST(MemF64_Mul) {
  const size_t kSize = 6;
  double buffer[kSize] = {1, 2, 2, 2, 2, 2};
  double result =
      GenerateAndRunFold<double>(execution_tier, kExprF64Mul, buffer, kSize,
                                 kWasmF64, MachineType::Float64());
  CHECK_EQ(32, result);
}

WASM_EXEC_TEST(Build_Wasm_Infinite_Loop) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Only build the graph and compile, don't run.
  r.Build({WASM_INFINITE_LOOP, WASM_ZERO});
}

WASM_EXEC_TEST(Build_Wasm_Infinite_Loop_effect) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);

  // Only build the graph and compile, don't run.
  r.Build({WASM_LOOP(WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO), WASM_DROP),
           WASM_ZERO});
}

WASM_EXEC_TEST(Unreachable0a) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV(0, WASM_I32V_1(9)), RET(WASM_LOCAL_GET(0)))});
  CHECK_EQ(9, r.Call(0));
  CHECK_EQ(9, r.Call(1));
}

WASM_EXEC_TEST(Unreachable0b) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV(0, WASM_I32V_1(7)), WASM_UNREACHABLE)});
  CHECK_EQ(7, r.Call(0));
  CHECK_EQ(7, r.Call(1));
}

WASM_COMPILED_EXEC_TEST(Build_Wasm_Unreachable1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_UNREACHABLE});
}

WASM_COMPILED_EXEC_TEST(Build_Wasm_Unreachable2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_UNREACHABLE, WASM_UNREACHABLE});
}

WASM_COMPILED_EXEC_TEST(Build_Wasm_Unreachable3) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_UNREACHABLE, WASM_UNREACHABLE, WASM_UNREACHABLE});
}

WASM_COMPILED_EXEC_TEST(Build_Wasm_UnreachableIf1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_UNREACHABLE,
           WASM_IF(WASM_LOCAL_GET(0), WASM_SEQ(WASM_LOCAL_GET(0), WASM_DROP)),
           WASM_ZERO});
}

WASM_COMPILED_EXEC_TEST(Build_Wasm_UnreachableIf2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {WASM_UNREACHABLE,
       WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_UNREACHABLE)});
}

WASM_EXEC_TEST(Unreachable_Load) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build(
      {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)),
                    WASM_LOAD_MEM(MachineType::Int8(), WASM_LOCAL_GET(0)))});
  CHECK_EQ(11, r.Call(11));
  CHECK_EQ(21, r.Call(21));
}

WASM_EXEC_TEST(BrV_Fallthrough) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BLOCK(WASM_BRV(1, WASM_I32V_1(42))),
                        WASM_I32V_1(22))});
  CHECK_EQ(42, r.Call());
}

WASM_EXEC_TEST(Infinite_Loop_not_taken1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_INFINITE_LOOP), WASM_I32V_1(45)});
  // Run the code, but don't go into the infinite loop.
  CHECK_EQ(45, r.Call(0));
}

WASM_EXEC_TEST(Infinite_Loop_not_taken2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_BRV(1, WASM_I32V_1(45)),
                   WASM_INFINITE_LOOP),
      WASM_ZERO)});
  // Run the code, but don't go into the infinite loop.
  CHECK_EQ(45, r.Call(1));
}

WASM_EXEC_TEST(Infinite_Loop_not_taken2_brif) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IF(0, WASM_I32V_1(45), WASM_LOCAL_GET(0)),
                        WASM_INFINITE_LOOP)});
  // Run the code, but don't go into the infinite loop.
  CHECK_EQ(45, r.Call(1));
}

WASM_EXEC_TEST(Int32LoadInt8_signext) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  const int kNumElems = kWasmPageSize;
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(kNumElems);
  r.builder().RandomizeMemory();
  memory[0] = -1;
  r.Build({WASM_LOAD_MEM(MachineType::Int8(), WASM_LOCAL_GET(0))});

  for (int i = 0; i < kNumElems; ++i) {
    CHECK_EQ(memory[i], r.Call(i));
  }
}

WASM_EXEC_TEST(Int32LoadInt8_zeroext) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  const int kNumElems = kWasmPageSize;
  uint8_t* memory = r.builder().AddMemory(kNumElems);
  r.builder().RandomizeMemory(77);
  memory[0] = 255;
  r.Build({WASM_LOAD_MEM(MachineType::Uint8(), WASM_LOCAL_GET(0))});

  for (int i = 0; i < kNumElems; ++i) {
    CHECK_EQ(memory[i], r.Call(i));
  }
}

WASM_EXEC_TEST(Int32LoadInt16_signext) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  const int kNumBytes = kWasmPageSize;
  uint8_t* memory = r.builder().AddMemory(kNumBytes);
  r.builder().RandomizeMemory(888);
  memory[1] = 200;
  r.Build({WASM_LOAD_MEM(MachineType::Int16(), WASM_LOCAL_GET(0))});

  for (int i = 0; i < kNumBytes; i += 2) {
    int32_t expected = static_cast<int16_t>(memory[i] | (memory[i + 1] << 8));
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Int32LoadInt16_zeroext) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  const int kNumBytes = kWasmPageSize;
  uint8_t* memory = r.builder().AddMemory(kNumBytes);
  r.builder().RandomizeMemory(9999);
  memory[1] = 204;
  r.Build({WASM_LOAD_MEM(MachineType::Uint16(), WASM_LOCAL_GET(0))});

  for (int i = 0; i < kNumBytes; i += 2) {
    int32_t expected = memory[i] | (memory[i + 1] << 8);
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Int32Global) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* global = r.builder().AddGlobal<int32_t>();
  // global = global + p0
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_I32_ADD(WASM_GLOBAL_GET(0), WASM_LOCAL_GET(0))),
       WASM_ZERO});

  *global = 116;
  for (int i = 9; i < 444444; i += 111111) {
    int32_t expected = *global + i;
    r.Call(i);
    CHECK_EQ(expected, *global);
  }
}

WASM_EXEC_TEST(Int32Globals_DontAlias) {
  const int kNumGlobals = 3;
  for (int g = 0; g < kNumGlobals; ++g) {
    // global = global + p0
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* globals[] = {r.builder().AddGlobal<int32_t>(),
                          r.builder().AddGlobal<int32_t>(),
                          r.builder().AddGlobal<int32_t>()};

    r.Build({WASM_GLOBAL_SET(
                 g, WASM_I32_ADD(WASM_GLOBAL_GET(g), WASM_LOCAL_GET(0))),
             WASM_GLOBAL_GET(g)});

    // Check that reading/writing global number {g} doesn't alter the others.
    *(globals[g]) = 116 * g;
    int32_t before[kNumGlobals];
    for (int i = 9; i < 444444; i += 111113) {
      int32_t sum = *(globals[g]) + i;
      for (int j = 0; j < kNumGlobals; ++j) before[j] = *(globals[j]);
      int32_t result = r.Call(i);
      CHECK_EQ(sum, result);
      for (int j = 0; j < kNumGlobals; ++j) {
        int32_t expected = j == g ? sum : before[j];
        CHECK_EQ(expected, *(globals[j]));
      }
    }
  }
}

WASM_EXEC_TEST(Float32Global) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  float* global = r.builder().AddGlobal<float>();
  // global = global + p0
  r.Build({WASM_GLOBAL_SET(
               0, WASM_F32_ADD(WASM_GLOBAL_GET(0),
                               WASM_F32_SCONVERT_I32(WASM_LOCAL_GET(0)))),
           WASM_ZERO});

  *global = 1.25;
  for (int i = 9; i < 4444; i += 1111) {
    volatile float expected = *global + i;
    r.Call(i);
    CHECK_EQ(expected, *global);
  }
}

WASM_EXEC_TEST(Float64Global) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  double* global = r.builder().AddGlobal<double>();
  // global = global + p0
  r.Build({WASM_GLOBAL_SET(
               0, WASM_F64_ADD(WASM_GLOBAL_GET(0),
                               WASM_F64_SCONVERT_I32(WASM_LOCAL_GET(0)))),
           WASM_ZERO});

  *global = 1.25;
  for (int i = 9; i < 4444; i += 1111) {
    volatile double expected = *global + i;
    r.Call(i);
    CHECK_EQ(expected, *global);
  }
}

WASM_EXEC_TEST(MixedGlobals) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  int32_t* unused = r.builder().AddGlobal<int32_t>();
  uint8_t* memory = r.builder().AddMemory(kWasmPageSize);

  int32_t* var_int32 = r.builder().AddGlobal<int32_t>();
  uint32_t* var_uint32 = r.builder().AddGlobal<uint32_t>();
  float* var_float = r.builder().AddGlobal<float>();
  double* var_double = r.builder().AddGlobal<double>();

  r.Build({WASM_GLOBAL_SET(1, WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)),
           WASM_GLOBAL_SET(2, WASM_LOAD_MEM(MachineType::Uint32(), WASM_ZERO)),
           WASM_GLOBAL_SET(3, WASM_LOAD_MEM(MachineType::Float32(), WASM_ZERO)),
           WASM_GLOBAL_SET(4, WASM_LOAD_MEM(MachineType::Float64(), WASM_ZERO)),
           WASM_ZERO});

  memory[0] = 0xAA;
  memory[1] = 0xCC;
  memory[2] = 0x55;
  memory[3] = 0xEE;
  memory[4] = 0x33;
  memory[5] = 0x22;
  memory[6] = 0x11;
  memory[7] = 0x99;
  r.Call(1);

  CHECK_EQ(static_cast<int32_t>(0xEE55CCAA), *var_int32);
  CHECK_EQ(static_cast<uint32_t>(0xEE55CCAA), *var_uint32);
  CHECK_EQ(base::bit_cast<float>(0xEE55CCAA), *var_float);
  CHECK_EQ(base::bit_cast<double>(0x99112233EE55CCAAULL), *var_double);

  USE(unused);
}

WASM_EXEC_TEST(CallEmpty) {
  const int32_t kExpected = -414444;
  WasmRunner<int32_t> r(execution_tier);

  // Build the target function.
  WasmFunctionCompiler& target_func = r.NewFunction<int>();
  target_func.Build({WASM_I32V_3(kExpected)});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION0(target_func.function_index())});

  int32_t result = r.Call();
  CHECK_EQ(kExpected, result);
}

WASM_EXEC_TEST(CallF32StackParameter) {
  WasmRunner<float> r(execution_tier);

  // Build the target function.
  ValueType param_types[20];
  for (int i = 0; i < 20; ++i) param_types[i] = kWasmF32;
  FunctionSig sig(1, 19, param_types);
  WasmFunctionCompiler& t = r.NewFunction(&sig);
  t.Build({WASM_LOCAL_GET(17)});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION(
      t.function_index(), WASM_F32(1.0f), WASM_F32(2.0f), WASM_F32(4.0f),
      WASM_F32(8.0f), WASM_F32(16.0f), WASM_F32(32.0f), WASM_F32(64.0f),
      WASM_F32(128.0f), WASM_F32(256.0f), WASM_F32(1.5f), WASM_F32(2.5f),
      WASM_F32(4.5f), WASM_F32(8.5f), WASM_F32(16.5f), WASM_F32(32.5f),
      WASM_F32(64.5f), WASM_F32(128.5f), WASM_F32(256.5f), WASM_F32(512.5f))});

  float result = r.Call();
  CHECK_EQ(256.5f, result);
}

WASM_EXEC_TEST(CallF64StackParameter) {
  WasmRunner<double> r(execution_tier);

  // Build the target function.
  ValueType param_types[20];
  for (int i = 0; i < 20; ++i) param_types[i] = kWasmF64;
  FunctionSig sig(1, 19, param_types);
  WasmFunctionCompiler& t = r.NewFunction(&sig);
  t.Build({WASM_LOCAL_GET(17)});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION(
      t.function_index(), WASM_F64(1.0), WASM_F64(2.0), WASM_F64(4.0),
      WASM_F64(8.0), WASM_F64(16.0), WASM_F64(32.0), WASM_F64(64.0),
      WASM_F64(128.0), WASM_F64(256.0), WASM_F64(1.5), WASM_F64(2.5),
      WASM_F64(4.5), WASM_F64(8.5), WASM_F64(16.5), WASM_F64(32.5),
      WASM_F64(64.5), WASM_F64(128.5), WASM_F64(256.5), WASM_F64(512.5))});

  float result = r.Call();
  CHECK_EQ(256.5, result);
}

WASM_EXEC_TEST(CallVoid) {
  WasmRunner<int32_t> r(execution_tier);

  const uint8_t kMemOffset = 8;
  const int32_t kElemNum = kMemOffset / sizeof(int32_t);
  const int32_t kExpected = 414444;
  // Build the target function.
  TestSignatures sigs;
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory();
  WasmFunctionCompiler& t = r.NewFunction(sigs.v_v());
  t.Build({WASM_STORE_MEM(MachineType::Int32(), WASM_I32V_1(kMemOffset),
                          WASM_I32V_3(kExpected))});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION0(t.function_index()),
           WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V_1(kMemOffset))});

  int32_t result = r.Call();
  CHECK_EQ(kExpected, result);
  CHECK_EQ(static_cast<int64_t>(kExpected),
           static_cast<int64_t>(r.builder().ReadMemory(&memory[kElemNum])));
}

WASM_EXEC_TEST(Call_Int32Add) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  // Build the target function.
  WasmFunctionCompiler& t = r.NewFunction<int32_t, int32_t, int32_t>();
  t.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  // Build the caller function.
  r.Build({WASM_CALL_FUNCTION(t.function_index(), WASM_LOCAL_GET(0),
                              WASM_LOCAL_GET(1))});

  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(static_cast<uint32_t>(i) +
                                              static_cast<uint32_t>(j));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(Call_Float32Sub) {
  WasmRunner<float, float, float> r(execution_tier);

  // Build the target function.
  WasmFunctionCompiler& target_func = r.NewFunction<float, float, float>();
  target_func.Build({WASM_F32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  // Build the caller function.
  r.Build({WASM_CALL_FUNCTION(target_func.function_index(), WASM_LOCAL_GET(0),
                              WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(i - j, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(Call_Float64Sub) {
  WasmRunner<int32_t> r(execution_tier);
  double* memory =
      r.builder().AddMemoryElems<double>(kWasmPageSize / sizeof(double));

  r.Build(
      {WASM_STORE_MEM(
           MachineType::Float64(), WASM_ZERO,
           WASM_F64_SUB(WASM_LOAD_MEM(MachineType::Float64(), WASM_ZERO),
                        WASM_LOAD_MEM(MachineType::Float64(), WASM_I32V_1(8)))),
       WASM_I32V_2(107)});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], i);
      r.builder().WriteMemory(&memory[1], j);
      double expected = i - j;
      CHECK_EQ(107, r.Call());

      if (expected != expected) {
        CHECK(r.builder().ReadMemory(&memory[0]) !=
              r.builder().ReadMemory(&memory[0]));
      } else {
        CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
      }
    }
  }
}

template <typename T>
static T factorial(T v) {
  T expected = 1;
  for (T i = v; i > 1; i--) {
    expected *= i;
  }
  return expected;
}

template <typename T>
static T sum_1_to_n(T v) {
  return v * (v + 1) / 2;
}

// We use unsigned arithmetic because of ubsan validation.
WASM_EXEC_TEST(Regular_Factorial) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);

  WasmFunctionCompiler& fact_aux_fn =
      r.NewFunction<uint32_t, uint32_t, uint32_t>("fact_aux");
  r.Build({WASM_CALL_FUNCTION(fact_aux_fn.function_index(), WASM_LOCAL_GET(0),
                              WASM_I32V(1))});

  fact_aux_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LES(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(1),
      WASM_CALL_FUNCTION(fact_aux_fn.function_index(),
                         WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
                         WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))))});

  uint32_t test_values[] = {1, 2, 5, 10, 20};

  for (uint32_t v : test_values) {
    CHECK_EQ(factorial(v), r.Call(v));
  }
}

namespace {
// TODO(cleanup): Define in cctest.h and re-use where appropriate.
class IsolateScope {
 public:
  IsolateScope() {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    isolate_ = v8::Isolate::New(create_params);
    isolate_->Enter();
  }

  ~IsolateScope() {
    isolate_->Exit();
    isolate_->Dispose();
  }

  v8::Isolate* isolate() { return isolate_; }
  Isolate* i_isolate() { return reinterpret_cast<Isolate*>(isolate_); }

 private:
  v8::Isolate* isolate_;
};
}  // namespace

// Tail-recursive variation on factorial:
// fact(N) => f(N,1).
//
// f(N,X) where N=<1 => X
// f(N,X) => f(N-1,X*N).

UNINITIALIZED_WASM_EXEC_TEST(ReturnCall_Factorial) {
  // Run in bounded amount of stack - 8kb.
  FlagScope<int32_t> stack_size(&v8_flags.stack_size, 8);

  IsolateScope isolate_scope;
  LocalContext current(isolate_scope.isolate());

  WasmRunner<uint32_t, uint32_t> r(execution_tier, kWasmOrigin, nullptr, "main",
                                   isolate_scope.i_isolate());

  WasmFunctionCompiler& fact_aux_fn =
      r.NewFunction<uint32_t, uint32_t, uint32_t>("fact_aux");
  r.Build({WASM_RETURN_CALL_FUNCTION(fact_aux_fn.function_index(),
                                     WASM_LOCAL_GET(0), WASM_I32V(1))});

  fact_aux_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LES(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(1),
      WASM_RETURN_CALL_FUNCTION(
          fact_aux_fn.function_index(),
          WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
          WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))))});

  uint32_t test_values[] = {1, 2, 5, 10, 20, 2000};

  for (uint32_t v : test_values) {
    CHECK_EQ(factorial<uint32_t>(v), r.Call(v));
  }
}

// Mutually recursive factorial mixing it up
// f(0,X)=>X
// f(N,X) => g(X*N,N-1)
// g(X,0) => X.
// g(X,N) => f(N-1,X*N).

UNINITIALIZED_WASM_EXEC_TEST(ReturnCall_MutualFactorial) {
  // Run in bounded amount of stack - 8kb.
  FlagScope<int32_t> stack_size(&v8_flags.stack_size, 8);

  IsolateScope isolate_scope;
  LocalContext current(isolate_scope.isolate());

  WasmRunner<uint32_t, uint32_t> r(execution_tier, kWasmOrigin, nullptr, "main",
                                   isolate_scope.i_isolate());

  WasmFunctionCompiler& f_fn = r.NewFunction<uint32_t, uint32_t, uint32_t>("f");
  WasmFunctionCompiler& g_fn = r.NewFunction<uint32_t, uint32_t, uint32_t>("g");

  r.Build({WASM_RETURN_CALL_FUNCTION(f_fn.function_index(), WASM_LOCAL_GET(0),
                                     WASM_I32V(1))});

  f_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LES(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(1),
      WASM_RETURN_CALL_FUNCTION(
          g_fn.function_index(),
          WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
          WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1))))});

  g_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LES(WASM_LOCAL_GET(1), WASM_I32V(1)), WASM_LOCAL_GET(0),
      WASM_RETURN_CALL_FUNCTION(
          f_fn.function_index(), WASM_I32_SUB(WASM_LOCAL_GET(1), WASM_I32V(1)),
          WASM_I32_MUL(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))))});

  uint32_t test_values[] = {1, 2, 5, 10, 20, 2000};

  for (uint32_t v : test_values) {
    CHECK_EQ(factorial(v), r.Call(v));
  }
}

// Indirect variant of factorial. Pass the function ID as an argument:
// fact(N) => f(N,1,f).
//
// f(N,X,_) where N=<1 => X
// f(N,X,F) => F(N-1,X*N,F).

UNINITIALIZED_WASM_EXEC_TEST(ReturnCall_IndirectFactorial) {
  // Run in bounded amount of stack - 8kb.
  FlagScope<int32_t> stack_size(&v8_flags.stack_size, 8);

  IsolateScope isolate_scope;
  LocalContext current(isolate_scope.isolate());

  WasmRunner<uint32_t, uint32_t> r(execution_tier, kWasmOrigin, nullptr, "main",
                                   isolate_scope.i_isolate());

  TestSignatures sigs;

  WasmFunctionCompiler& f_ind_fn = r.NewFunction(sigs.i_iii(), "f_ind");
  ModuleTypeIndex sig_index = r.builder().AddSignature(sigs.i_iii());
  f_ind_fn.SetSigIndex(sig_index);

  // Function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(f_ind_fn.function_index())};
  const int f_ind_index = 0;

  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  r.Build(
      {WASM_RETURN_CALL_FUNCTION(f_ind_fn.function_index(), WASM_LOCAL_GET(0),
                                 WASM_I32V(1), WASM_I32V(f_ind_index))});

  f_ind_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LES(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(1),
      WASM_RETURN_CALL_INDIRECT(
          sig_index, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
          WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_LOCAL_GET(2),
          WASM_LOCAL_GET(2)))});

  uint32_t test_values[] = {1, 2, 5, 10, 10000};

  for (uint32_t v : test_values) {
    CHECK_EQ(factorial(v), r.Call(v));
  }
}

// This is 'more stable' (does not degenerate so quickly) than factorial
// sum(N,k) where N<1 =>k.
// sum(N,k) => sum(N-1,k+N).

UNINITIALIZED_WASM_EXEC_TEST(ReturnCall_Sum) {
  // Run in bounded amount of stack - 8kb.
  FlagScope<int32_t> stack_size(&v8_flags.stack_size, 8);

  IsolateScope isolate_scope;
  LocalContext current(isolate_scope.isolate());

  WasmRunner<int32_t, int32_t> r(execution_tier, kWasmOrigin, nullptr, "main",
                                 isolate_scope.i_isolate());
  TestSignatures sigs;

  WasmFunctionCompiler& sum_aux_fn = r.NewFunction(sigs.i_ii(), "sum_aux");
  r.Build({WASM_RETURN_CALL_FUNCTION(sum_aux_fn.function_index(),
                                     WASM_LOCAL_GET(0), WASM_I32V(0))});

  sum_aux_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LTS(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(1),
      WASM_RETURN_CALL_FUNCTION(
          sum_aux_fn.function_index(),
          WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
          WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))))});

  int32_t test_values[] = {1, 2, 5, 10, 1000};

  for (int32_t v : test_values) {
    CHECK_EQ(sum_1_to_n(v), r.Call(v));
  }
}

// 'Bouncing' mutual recursive sum with different #s of arguments
// b1(N,k) where N<1 =>k.
// b1(N,k) => b2(N-1,N,k+N).

// b2(N,_,k) where N<1 =>k.
// b2(N,l,k) => b3(N-1,N,l,k+N).

// b3(N,_,_,k) where N<1 =>k.
// b3(N,_,_,k) => b1(N-1,k+N).

UNINITIALIZED_WASM_EXEC_TEST(ReturnCall_Bounce_Sum) {
  // Run in bounded amount of stack - 8kb.
  FlagScope<int32_t> stack_size(&v8_flags.stack_size, 8);

  IsolateScope isolate_scope;
  LocalContext current(isolate_scope.isolate());

  WasmRunner<int32_t, int32_t> r(execution_tier, kWasmOrigin, nullptr, "main",
                                 isolate_scope.i_isolate());
  TestSignatures sigs;

  WasmFunctionCompiler& b1_fn = r.NewFunction(sigs.i_ii(), "b1");
  WasmFunctionCompiler& b2_fn = r.NewFunction(sigs.i_iii(), "b2");
  WasmFunctionCompiler& b3_fn =
      r.NewFunction<int32_t, int32_t, int32_t, int32_t, int32_t>("b3");

  r.Build({WASM_RETURN_CALL_FUNCTION(b1_fn.function_index(), WASM_LOCAL_GET(0),
                                     WASM_I32V(0))});

  b1_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LTS(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(1),
      WASM_RETURN_CALL_FUNCTION(
          b2_fn.function_index(), WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
          WASM_LOCAL_GET(0),
          WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))))});

  b2_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LTS(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(2),
      WASM_RETURN_CALL_FUNCTION(
          b3_fn.function_index(), WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
          WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
          WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(2))))});

  b3_fn.Build({WASM_IF_ELSE_I(
      WASM_I32_LTS(WASM_LOCAL_GET(0), WASM_I32V(1)), WASM_LOCAL_GET(3),
      WASM_RETURN_CALL_FUNCTION(
          b1_fn.function_index(), WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V(1)),
          WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(3))))});

  int32_t test_values[] = {1, 2, 5, 10, 1000};

  for (int32_t v : test_values) {
    CHECK_EQ(sum_1_to_n(v), r.Call(v));
  }
}

static void Run_WasmMixedCall_N(TestExecutionTier execution_tier, int start) {
  const int kExpected = 6333;
  const int kElemSize = 8;

  // 64-bit cases handled in test-run-wasm-64.cc.
  static MachineType mixed[] = {
      MachineType::Int32(),   MachineType::Float32(), MachineType::Float64(),
      MachineType::Float32(), MachineType::Int32(),   MachineType::Float64(),
      MachineType::Float32(), MachineType::Float64(), MachineType::Int32(),
      MachineType::Int32(),   MachineType::Int32()};

  int num_params = static_cast<int>(arraysize(mixed)) - start;
  for (int which = 0; which < num_params; ++which) {
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    WasmRunner<int32_t> r(execution_tier);
    r.builder().AddMemory(kWasmPageSize);
    MachineType* memtypes = &mixed[start];
    MachineType result = memtypes[which];

    // =========================================================================
    // Build the selector function.
    // =========================================================================
    FunctionSig::Builder b(&zone, 1, num_params);
    b.AddReturn(ValueType::For(result));
    for (int i = 0; i < num_params; ++i) {
      b.AddParam(ValueType::For(memtypes[i]));
    }
    WasmFunctionCompiler& f = r.NewFunction(b.Get());
    f.Build({WASM_LOCAL_GET(which)});

    // =========================================================================
    // Build the calling function.
    // =========================================================================
    std::vector<uint8_t> code;

    // Load the arguments.
    for (int i = 0; i < num_params; ++i) {
      int offset = (i + 1) * kElemSize;
      ADD_CODE(code, WASM_LOAD_MEM(memtypes[i], WASM_I32V_2(offset)));
    }

    // Call the selector function.
    ADD_CODE(code, WASM_CALL_FUNCTION0(f.function_index()));

    // Store the result in a local.
    uint8_t local_index = r.AllocateLocal(ValueType::For(result));
    ADD_CODE(code, kExprLocalSet, local_index);

    // Store the result in memory.
    ADD_CODE(code,
             WASM_STORE_MEM(result, WASM_ZERO, WASM_LOCAL_GET(local_index)));

    // Return the expected value.
    ADD_CODE(code, WASM_I32V_2(kExpected));

    r.Build(base::VectorOf(code));

    // Run the code.
    for (int t = 0; t < 10; ++t) {
      r.builder().RandomizeMemory();
      CHECK_EQ(kExpected, r.Call());

      int size = result.MemSize();
      for (int i = 0; i < size; ++i) {
        int base = (which + 1) * kElemSize;
        uint8_t expected = r.builder().raw_mem_at<uint8_t>(base + i);
        uint8_t actual = r.builder().raw_mem_at<uint8_t>(i);
        CHECK_EQ(expected, actual);
      }
    }
  }
}

WASM_EXEC_TEST(MixedCall_0) { Run_WasmMixedCall_N(execution_tier, 0); }
WASM_EXEC_TEST(MixedCall_1) { Run_WasmMixedCall_N(execution_tier, 1); }
WASM_EXEC_TEST(MixedCall_2) { Run_WasmMixedCall_N(execution_tier, 2); }
WASM_EXEC_TEST(MixedCall_3) { Run_WasmMixedCall_N(execution_tier, 3); }

WASM_EXEC_TEST(AddCall) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  WasmFunctionCompiler& t1 = r.NewFunction<int32_t, int32_t, int32_t>();
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  uint8_t local = r.AllocateLocal(kWasmI32);
  r.Build({WASM_LOCAL_SET(local, WASM_I32V_2(99)),
           WASM_I32_ADD(
               WASM_CALL_FUNCTION(t1.function_index(), WASM_LOCAL_GET(0),
                                  WASM_LOCAL_GET(0)),
               WASM_CALL_FUNCTION(t1.function_index(), WASM_LOCAL_GET(local),
                                  WASM_LOCAL_GET(local)))});

  CHECK_EQ(198, r.Call(0));
  CHECK_EQ(200, r.Call(1));
  CHECK_EQ(100, r.Call(-49));
}

WASM_EXEC_TEST(MultiReturnSub) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  ValueType storage[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32};
  FunctionSig sig_ii_ii(2, 2, storage);
  WasmFunctionCompiler& t1 = r.NewFunction(&sig_ii_ii);
  t1.Build({WASM_LOCAL_GET(1), WASM_LOCAL_GET(0)});

  r.Build({WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
           WASM_CALL_FUNCTION0(t1.function_index()), kExprI32Sub});

  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(static_cast<uint32_t>(j) -
                                              static_cast<uint32_t>(i));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

template <typename T>
void RunMultiReturnSelect(TestExecutionTier execution_tier, const T* inputs) {
  ValueType type = ValueType::For(MachineTypeForC<T>());
  ValueType storage[] = {type, type, type, type, type, type};
  const size_t kNumReturns = 2;
  const size_t kNumParams = arraysize(storage) - kNumReturns;
  FunctionSig sig(kNumReturns, kNumParams, storage);

  for (size_t i = 0; i < kNumParams; i++) {
    for (size_t j = 0; j < kNumParams; j++) {
      for (int k = 0; k < 2; k++) {
        WasmRunner<T, T, T, T, T> r(execution_tier);
        WasmFunctionCompiler& r1 = r.NewFunction(&sig);

        r1.Build({WASM_LOCAL_GET(i), WASM_LOCAL_GET(j)});

        if (k == 0) {
          r.Build({WASM_CALL_FUNCTION(r1.function_index(), WASM_LOCAL_GET(0),
                                      WASM_LOCAL_GET(1), WASM_LOCAL_GET(2),
                                      WASM_LOCAL_GET(3)),
                   WASM_DROP});
        } else {
          r.Build({WASM_CALL_FUNCTION(r1.function_index(), WASM_LOCAL_GET(0),
                                      WASM_LOCAL_GET(1), WASM_LOCAL_GET(2),
                                      WASM_LOCAL_GET(3)),
                   kExprLocalSet, 0, WASM_DROP, WASM_LOCAL_GET(0)});
        }

        T expected = inputs[k == 0 ? i : j];
        CHECK_EQ(expected, r.Call(inputs[0], inputs[1], inputs[2], inputs[3]));
      }
    }
  }
}

WASM_EXEC_TEST(MultiReturnSelect_i32) {
  static const int32_t inputs[] = {3333333, 4444444, -55555555, -7777777};
  RunMultiReturnSelect<int32_t>(execution_tier, inputs);
}

WASM_EXEC_TEST(MultiReturnSelect_f32) {
  static const float inputs[] = {33.33333f, 444.4444f, -55555.555f, -77777.77f};
  RunMultiReturnSelect<float>(execution_tier, inputs);
}

WASM_EXEC_TEST(MultiReturnSelect_i64) {
#if !V8_TARGET_ARCH_32_BIT || V8_TARGET_ARCH_X64
  // TODO(titzer): implement int64-lowering for multiple return values
  static const int6
```