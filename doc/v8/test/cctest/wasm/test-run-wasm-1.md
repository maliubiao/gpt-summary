Response: The user wants a summary of the functionality of the provided C++ code snippet. This code appears to be a set of tests for a WebAssembly (Wasm) runtime environment, likely part of the V8 JavaScript engine.

Here's a plan to summarize the code:
1. **Identify the core purpose:** The code tests the execution of various Wasm instructions and control flow structures.
2. **Categorize the tests:** Group the tests based on the Wasm features they target.
3. **Provide examples:** If a test relates to a JavaScript feature or a Wasm concept easily demonstrable in JavaScript, provide a concise example.
这是针对WebAssembly (Wasm) 内存操作和数值运算进行测试的代码片段。它测试了以下功能：

* **内存加载和存储 (Load and Store):**
    * `MemLoop`:  测试在一个循环中加载和跳转的场景。
    * `MemF32_Sum`: 测试加载多个浮点数并进行累加的功能。它模拟了从内存中读取数据并进行计算的过程。
    * `MemF64_Mul`:  类似于 `MemF32_Sum`，但针对双精度浮点数的乘法。它使用了 `GenerateAndRunFold` 模板函数，展示了通用的内存折叠操作。
* **无限循环 (Infinite Loops):**
    * `Build_Wasm_Infinite_Loop`: 测试构建一个无限循环的 WebAssembly 代码，但并不实际运行它。这可能用于测试编译器的处理能力。
    * `Build_Wasm_Infinite_Loop_effect`: 类似于上一个测试，但循环内部包含内存加载操作，用于测试具有副作用的无限循环。
* **不可达代码 (Unreachable Code):**
    * `Unreachable0a`, `Unreachable0b`, `Build_Wasm_Unreachable1` 等一系列测试：验证 `unreachable` 指令的行为，以及在不同控制流结构中（如 `block`, `if`）遇到 `unreachable` 指令时的处理。
* **分支指令 (Branch Instructions):**
    * `Unreachable_Load`: 测试在 `br` 指令之后出现内存加载的情况，验证控制流是否正确。
    * `BrV_Fallthrough`: 测试带有返回值的 `br` 指令的正常执行流程。
    * `Infinite_Loop_not_taken1`, `Infinite_Loop_not_taken2`, `Infinite_Loop_not_taken2_brif`: 测试在条件分支中避免执行无限循环的情况。
* **有符号和无符号扩展加载 (Sign and Zero Extension Loads):**
    * `Int32LoadInt8_signext`, `Int32LoadInt8_zeroext`, `Int32LoadInt16_signext`, `Int32LoadInt16_zeroext`:  测试从内存中加载不同大小的整数，并验证有符号和无符号扩展是否正确。
* **全局变量 (Globals):**
    * `Int32Global`, `Int32Globals_DontAlias`, `Float32Global`, `Float64Global`, `MixedGlobals`: 测试全局变量的读写操作，包括不同数据类型的全局变量以及验证全局变量之间不会互相干扰（aliasing）。

**与 JavaScript 的关系及示例:**

这段 C++ 代码是 V8 引擎的一部分，V8 是执行 JavaScript 代码的引擎。WebAssembly 旨在作为 JavaScript 的补充，提供接近原生的性能。因此，这段代码直接测试了 V8 中 WebAssembly 运行时的功能。

例如，`MemF32_Sum` 测试了 WebAssembly 中加载和操作浮点数的能力。在 JavaScript 中，你可以通过 `WebAssembly.Memory` 对象访问 WebAssembly 的线性内存，并使用 `Float32Array` 视图来读写 32 位浮点数。

```javascript
// 假设你已经加载并实例化了一个 WebAssembly 模块，其中包含一个名为 'run' 的函数
// 并且该模块有一个名为 'memory' 的内存实例

const memory = instance.exports.memory;
const float32Array = new Float32Array(memory.buffer);

// 模拟 C++ 代码中写入内存的操作
float32Array[0] = -99.25;
float32Array[1] = -888.25;
float32Array[2] = -77.25;
float32Array[3] = 66666.25;
float32Array[4] = 5555.25;

// 调用 WebAssembly 模块中的函数，该函数会执行类似 C++ 代码中的累加操作
instance.exports.run(4 * 4); // 假设 'run' 函数接收内存偏移量作为参数

// 检查内存中累加的结果
console.log(float32Array[0]); // 应该输出累加后的结果，类似于 C++ 代码中的 CHECK_EQ(71256.0f, ...)
```

在这个 JavaScript 示例中，我们手动在 JavaScript 中模拟了 C++ 代码中向 WebAssembly 内存写入数据的过程，然后调用了 WebAssembly 函数来执行类似的浮点数累加操作。这展示了 WebAssembly 的内存模型以及如何与 JavaScript 互动。

总而言之，这个代码片段是 WebAssembly 功能的底层测试，确保了 V8 引擎能够正确地执行各种 WebAssembly 指令和操作，包括内存访问、控制流和数值计算。它对于保证 WebAssembly 在 V8 中的正确性和性能至关重要。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
  static const int64_t inputs[] = {33333338888, 44444446666, -555555553333,
                                   -77777771111};
  RunMultiReturnSelect<int64_t>(execution_tier, inputs);
#endif
}

WASM_EXEC_TEST(MultiReturnSelect_f64) {
  static const double inputs[] = {3.333333, 44444.44, -55.555555, -7777.777};
  RunMultiReturnSelect<double>(execution_tier, inputs);
}

WASM_EXEC_TEST(ExprBlock2a) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(1, WASM_I32V_1(1))),
                        WASM_I32V_1(1))});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock2b) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(1, WASM_I32V_1(1))),
                        WASM_I32V_1(2))});
  CHECK_EQ(2, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock2c) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IFD(0, WASM_I32V_1(1), WASM_LOCAL_GET(0)),
                        WASM_I32V_1(1))});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock2d) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IFD(0, WASM_I32V_1(1), WASM_LOCAL_GET(0)),
                        WASM_I32V_1(2))});
  CHECK_EQ(2, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock_ManualSwitch) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(1)),
                                WASM_BRV(1, WASM_I32V_1(11))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(2)),
                                WASM_BRV(1, WASM_I32V_1(12))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(3)),
                                WASM_BRV(1, WASM_I32V_1(13))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(4)),
                                WASM_BRV(1, WASM_I32V_1(14))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(5)),
                                WASM_BRV(1, WASM_I32V_1(15))),
                        WASM_I32V_2(99))});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(11, r.Call(1));
  CHECK_EQ(12, r.Call(2));
  CHECK_EQ(13, r.Call(3));
  CHECK_EQ(14, r.Call(4));
  CHECK_EQ(15, r.Call(5));
  CHECK_EQ(99, r.Call(6));
}

WASM_EXEC_TEST(ExprBlock_ManualSwitch_brif) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_BRV_IFD(0, WASM_I32V_1(11),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(1))),
      WASM_BRV_IFD(0, WASM_I32V_1(12),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(2))),
      WASM_BRV_IFD(0, WASM_I32V_1(13),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(3))),
      WASM_BRV_IFD(0, WASM_I32V_1(14),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(4))),
      WASM_BRV_IFD(0, WASM_I32V_1(15),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(5))),
      WASM_I32V_2(99))});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(11, r.Call(1));
  CHECK_EQ(12, r.Call(2));
  CHECK_EQ(13, r.Call(3));
  CHECK_EQ(14, r.Call(4));
  CHECK_EQ(15, r.Call(5));
  CHECK_EQ(99, r.Call(6));
}

WASM_EXEC_TEST(If_nested) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  r.Build({WASM_IF_ELSE_I(
      WASM_LOCAL_GET(0),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_I32V_1(11), WASM_I32V_1(12)),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_I32V_1(13), WASM_I32V_1(14)))});

  CHECK_EQ(11, r.Call(1, 1));
  CHECK_EQ(12, r.Call(1, 0));
  CHECK_EQ(13, r.Call(0, 1));
  CHECK_EQ(14, r.Call(0, 0));
}

WASM_EXEC_TEST(ExprBlock_if) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  r.Build({WASM_BLOCK_I(WASM_IF_ELSE_I(WASM_LOCAL_GET(0),
                                       WASM_BRV(0, WASM_I32V_1(11)),
                                       WASM_BRV(1, WASM_I32V_1(14))))});

  CHECK_EQ(11, r.Call(1));
  CHECK_EQ(14, r.Call(0));
}

WASM_EXEC_TEST(ExprBlock_nested_ifs) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  r.Build({WASM_BLOCK_I(WASM_IF_ELSE_I(
      WASM_LOCAL_GET(0),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_BRV(0, WASM_I32V_1(11)),
                     WASM_BRV(1, WASM_I32V_1(12))),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_BRV(0, WASM_I32V_1(13)),
                     WASM_BRV(1, WASM_I32V_1(14)))))});

  CHECK_EQ(11, r.Call(1, 1));
  CHECK_EQ(12, r.Call(1, 0));
  CHECK_EQ(13, r.Call(0, 1));
  CHECK_EQ(14, r.Call(0, 0));
}

WASM_EXEC_TEST(SimpleCallIndirect) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t1.SetSigIndex(ModuleTypeIndex{1});

  WasmFunctionCompiler& t2 = r.NewFunction(sigs.i_ii());
  t2.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t2.SetSigIndex(ModuleTypeIndex{1});

  // Signature table.
  r.builder().AddSignature(sigs.f_ff());
  r.builder().AddSignature(sigs.i_ii());
  r.builder().AddSignature(sigs.d_dd());

  // Function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(t1.function_index()),
      static_cast<uint16_t>(t2.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the caller function.
  r.Build({WASM_CALL_INDIRECT(1, WASM_I32V_2(66), WASM_I32V_1(22),
                              WASM_LOCAL_GET(0))});

  CHECK_EQ(88, r.Call(0));
  CHECK_EQ(44, r.Call(1));
  CHECK_TRAP(r.Call(2));
}

WASM_EXEC_TEST(MultipleCallIndirect) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t1.SetSigIndex(ModuleTypeIndex{1});

  WasmFunctionCompiler& t2 = r.NewFunction(sigs.i_ii());
  t2.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t2.SetSigIndex(ModuleTypeIndex{1});

  // Signature table.
  r.builder().AddSignature(sigs.f_ff());
  r.builder().AddSignature(sigs.i_ii());
  r.builder().AddSignature(sigs.d_dd());

  // Function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(t1.function_index()),
      static_cast<uint16_t>(t2.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the caller function.
  r.Build(
      {WASM_I32_ADD(WASM_CALL_INDIRECT(1, WASM_LOCAL_GET(1), WASM_LOCAL_GET(2),
                                       WASM_LOCAL_GET(0)),
                    WASM_CALL_INDIRECT(1, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0),
                                       WASM_LOCAL_GET(1)))});

  CHECK_EQ(5, r.Call(0, 1, 2));
  CHECK_EQ(19, r.Call(0, 1, 9));
  CHECK_EQ(1, r.Call(1, 0, 2));
  CHECK_EQ(1, r.Call(1, 0, 9));

  CHECK_TRAP(r.Call(0, 2, 1));
  CHECK_TRAP(r.Call(1, 2, 0));
  CHECK_TRAP(r.Call(2, 0, 1));
  CHECK_TRAP(r.Call(2, 1, 0));
}

WASM_EXEC_TEST(CallIndirect_EmptyTable) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  // One function.
  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t1.SetSigIndex(ModuleTypeIndex{1});

  // Signature table.
  r.builder().AddSignature(sigs.f_ff());
  r.builder().AddSignature(sigs.i_ii());
  r.builder().AddIndirectFunctionTable(nullptr, 0);

  // Build the caller function.
  r.Build({WASM_CALL_INDIRECT(1, WASM_I32V_2(66), WASM_I32V_1(22),
                              WASM_LOCAL_GET(0))});

  CHECK_TRAP(r.Call(0));
  CHECK_TRAP(r.Call(1));
  CHECK_TRAP(r.Call(2));
}

WASM_EXEC_TEST(CallIndirect_canonical) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  WasmFunctionCompiler& t2 = r.NewFunction(sigs.i_ii());
  t2.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  WasmFunctionCompiler& t3 = r.NewFunction(sigs.f_ff());
  t3.Build({WASM_F32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  // Function table.
  uint16_t i1 = static_cast<uint16_t>(t1.function_index());
  uint16_t i2 = static_cast<uint16_t>(t2.function_index());
  uint16_t i3 = static_cast<uint16_t>(t3.function_index());
  uint16_t indirect_function_table[] = {i1, i2, i3, i1, i2};

  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the caller function.
  r.Build({WASM_CALL_INDIRECT(1, WASM_I32V_2(77), WASM_I32V_1(11),
                              WASM_LOCAL_GET(0))});

  CHECK_EQ(88, r.Call(0));
  CHECK_EQ(66, r.Call(1));
  CHECK_TRAP(r.Call(2));
  CHECK_EQ(88, r.Call(3));
  CHECK_EQ(66, r.Call(4));
  CHECK_TRAP(r.Call(5));
}

WASM_EXEC_TEST(Regress_PushReturns) {
  ValueType kSigTypes[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32};
  FunctionSig sig(12, 0, kSigTypes);
  WasmRunner<int32_t> r(execution_tier);

  WasmFunctionCompiler& f1 = r.NewFunction(&sig);
  f1.Build({WASM_I32V(1), WASM_I32V(2), WASM_I32V(3), WASM_I32V(4),
            WASM_I32V(5), WASM_I32V(6), WASM_I32V(7), WASM_I32V(8),
            WASM_I32V(9), WASM_I32V(10), WASM_I32V(11), WASM_I32V(12)});

  r.Build({WASM_CALL_FUNCTION0(f1.function_index()), WASM_DROP, WASM_DROP,
           WASM_DROP, WASM_DROP, WASM_DROP, WASM_DROP, WASM_DROP, WASM_DROP,
           WASM_DROP, WASM_DROP, WASM_DROP});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(Regress_EnsureArguments) {
  ValueType kSigTypes[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32};
  FunctionSig sig(0, 12, kSigTypes);
  WasmRunner<int32_t> r(execution_tier);

  WasmFunctionCompiler& f2 = r.NewFunction(&sig);
  f2.Build({kExprReturn});

  r.Build({WASM_I32V(42), kExprReturn,
           WASM_CALL_FUNCTION(f2.function_index(), WASM_I32V(1))});
  CHECK_EQ(42, r.Call());
}

WASM_EXEC_TEST(Regress_PushControl) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_I32V(42), WASM_IF(WASM_I32V(0), WASM_UNREACHABLE, kExprIf,
                                  kVoidCode, kExprEnd)});
  CHECK_EQ(42, r.Call());
}

WASM_EXEC_TEST(F32Floor) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_FLOOR(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(floorf(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32Ceil) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_CEIL(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(ceilf(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32Trunc) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_TRUNC(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(truncf(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32NearestInt) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_NEARESTINT(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    float value = nearbyintf(i);
#if V8_OS_AIX
    value = FpOpWorkaround<float>(i, value);
#endif
    CHECK_FLOAT_EQ(value, r.Call(i));
  }
}

WASM_EXEC_TEST(F64Floor) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_FLOOR(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(floor(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64Ceil) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_CEIL(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(ceil(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64Trunc) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_TRUNC(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(trunc(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64NearestInt) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_NEARESTINT(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    double value = nearbyint(i);
#if V8_OS_AIX
    value = FpOpWorkaround<double>(i, value);
#endif
    CHECK_DOUBLE_EQ(value, r.Call(i));
  }
}

WASM_EXEC_TEST(F32Min) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_DOUBLE_EQ(JSMin(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F32MinSameValue) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  float result = r.Call(5.0f);
  CHECK_FLOAT_EQ(5.0f, result);
}

WASM_EXEC_TEST(F64Min) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(JSMin(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F64MinSameValue) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  double result = r.Call(5.0);
  CHECK_DOUBLE_EQ(5.0, result);
}

WASM_EXEC_TEST(F32Max) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(JSMax(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F32MaxSameValue) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  float result = r.Call(5.0f);
  CHECK_FLOAT_EQ(5.0f, result);
}

WASM_EXEC_TEST(F64Max) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      double result = r.Call(i, j);
      CHECK_DOUBLE_EQ(JSMax(i, j), result);
    }
  }
}

WASM_EXEC_TEST(F64MaxSameValue) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  double result = r.Call(5.0);
  CHECK_DOUBLE_EQ(5.0, result);
}

WASM_EXEC_TEST(I32SConvertF32) {
  WasmRunner<int32_t, float> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_F32(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    if (is_inbounds<int32_t>(i)) {
      CHECK_EQ(static_cast<int32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32SConvertSatF32) {
  WasmRunner<int32_t, float> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_SAT_F32(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    int32_t expected =
        is_inbounds<int32_t>(i)
            ? static_cast<int32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<int32_t>::min()
                                      : std::numeric_limits<int32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I32SConvertF64) {
  WasmRunner<int32_t, double> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_F64(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    if (is_inbounds<int32_t>(i)) {
      CHECK_EQ(static_cast<int32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32SConvertSatF64) {
  WasmRunner<int32_t, double> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_SAT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    int32_t expected =
        is_inbounds<int32_t>(i)
            ? static_cast<int32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<int32_t>::min()
                                      : std::numeric_limits<int32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I32UConvertF32) {
  WasmRunner<uint32_t, float> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_F32(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) {
    if (is_inbounds<uint32_t>(i)) {
      CHECK_EQ(static_cast<uint32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32UConvertSatF32) {
  WasmRunner<uint32_t, float> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_SAT_F32(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) {
    int32_t expected =
        is_inbounds<uint32_t>(i)
            ? static_cast<uint32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<uint32_t>::min()
                                      : std::numeric_limits<uint32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I32UConvertF64) {
  WasmRunner<uint32_t, double> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    if (is_inbounds<uint32_t>(i)) {
      CHECK_EQ(static_cast<uint32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32UConvertSatF64) {
  WasmRunner<uint32_t, double> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_SAT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    int32_t expected =
        is_inbounds<uint32_t>(i)
            ? static_cast<uint32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<uint32_t>::min()
                                      : std::numeric_limits<uint32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(F64CopySign) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_COPYSIGN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(copysign(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F32CopySign) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_COPYSIGN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(copysignf(i, j), r.Call(i, j)); }
  }
}

static void CompileCallIndirectMany(TestExecutionTier tier, ValueType param) {
  // Make sure we don't run out of registers when compiling indirect calls
  // with many many parameters.
  TestSignatures sigs;
  for (uint8_t num_params = 0; num_params < 40; ++num_params) {
    WasmRunner<void> r(tier);
    FunctionSig* sig = sigs.many(r.zone(), kWasmVoid, param, num_params);

    r.builder().AddSignature(sig);
    r.builder().AddSignature(sig);
    r.builder().AddIndirectFunctionTable(nullptr, 0);

    WasmFunctionCompiler& t = r.NewFunction(sig);

    std::vector<uint8_t> code;
    for (uint8_t p = 0; p < num_params; ++p) {
      ADD_CODE(code, kExprLocalGet, p);
    }
    ADD_CODE(code, kExprI32Const, 0);
    ADD_CODE(code, kExprCallIndirect, 1, TABLE_ZERO);

    t.Build(base::VectorOf(code));
  }
}

WASM_COMPILED_EXEC_TEST(Compile_Wasm_CallIndirect_Many_i32) {
  CompileCallIndirectMany(execution_tier, kWasmI32);
}

WASM_COMPILED_EXEC_TEST(Compile_Wasm_CallIndirect_Many_f32) {
  CompileCallIndirectMany(execution_tier, kWasmF32);
}

WASM_COMPILED_EXEC_TEST(Compile_Wasm_CallIndirect_Many_f64) {
  CompileCallIndirectMany(execution_tier, kWasmF64);
}

WASM_EXEC_TEST(Int32RemS_dead) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_DROP,
           WASM_ZERO});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(133, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_EQ(0, r.Call(0, 1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(BrToLoopWithValue) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // Subtracts <1> times 3 from <0> and returns the result.
  r.Build({// loop i32
           kExprLoop, kI32Code,
           // decrement <0> by 3.
           WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(3))),
           // decrement <1> by 1.
           WASM_LOCAL_SET(1, WASM_I32_SUB(WASM_LOCAL_GET(1), WASM_ONE)),
           // load return value <0>, br_if will drop if if the branch is taken.
           WASM_LOCAL_GET(0),
           // continue loop if <1> is != 0.
           WASM_BR_IF(0, WASM_LOCAL_GET(1)),
           // end of loop, value loaded above is the return value.
           kExprEnd});
  CHECK_EQ(12, r.Call(27, 5));
}

WASM_EXEC_TEST(BrToLoopWithoutValue) {
  // This was broken in the interpreter, see http://crbug.com/715454
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {kExprLoop, kI32Code,  // loop i32
       WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_ONE)),  // dec <0>
       WASM_BR_IF(0, WASM_LOCAL_GET(0)),  // br_if <0> != 0
       kExprUnreachable,                  // unreachable
       kExprEnd});                        // end
  CHECK_TRAP32(r.Call(2));
}

WASM_EXEC_TEST(LoopsWithValues) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_LOOP_I(WASM_LOOP_I(WASM_ONE), WASM_ONE, kExprI32Add)});
  CHECK_EQ(2, r.Call());
}

WASM_EXEC_TEST(InvalidStackAfterUnreachable) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({kExprUnreachable, kExprI32Add});
  CHECK_TRAP32(r.Call());
}

WASM_EXEC_TEST(InvalidStackAfterBr) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BRV(0, WASM_I32V_1(27)), kExprI32Add});
  CHECK_EQ(27, r.Call());
}

WASM_EXEC_TEST(InvalidStackAfterReturn) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_RETURN(WASM_I32V_1(17)), kExprI32Add});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCode) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({// Start a block which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this block.
           WASM_BLOCK_I(WASM_BRV(0, WASM_I32V_1(17)), kExprI32Add),
           // Add one to the 17 returned from the block.
           WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCodeInLoop0) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_BLOCK_I(
           // Start a loop which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this loop.
           // This should validate even though there is no value on the stack
           // at the end of the loop.
           WASM_LOOP_I(WASM_BRV(1, WASM_I32V_1(17)))),
       // Add one to the 17 returned from the block.
       WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCodeInLoop1) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_BLOCK_I(
           // Start a loop which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this loop.
           // Even though unreachable, the loop leaves one value on the stack.
           WASM_LOOP_I(WASM_BRV(1, WASM_I32V_1(17)), WASM_ONE)),
       // Add one to the 17 returned from the block.
       WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCodeInLoop2) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_BLOCK_I(
           // Start a loop which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this loop.
           // The unreachable code is allowed to pop non-existing values off
           // the stack and push back the result.
           WASM_LOOP_I(WASM_BRV(1, WASM_I32V_1(17)), kExprI32Add)),
       // Add one to the 17 returned from the block.
       WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BlockInsideUnreachable) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_RETURN(WASM_I32V_1(17)), WASM_BLOCK(WASM_BR(0))});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(IfInsideUnreachable) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_RETURN(WASM_I32V_1(17)),
       WASM_IF_ELSE_I(WASM_ONE, WASM_BRV(0, WASM_ONE), WASM_RETURN(WASM_ONE))});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(IndirectNull) {
  WasmRunner<int32_t> r(execution_tier);
  FunctionSig sig(1, 0, &kWasmI32);
  ModuleTypeIndex sig_index = r.builder().AddSignature(&sig);
  r.builder().AddIndirectFunctionTable(nullptr, 1);

  r.Build({WASM_CALL_INDIRECT(sig_index, WASM_I32V(0))});

  CHECK_TRAP(r.Call());
}

WASM_EXEC_TEST(IndirectNullTyped) {
  WasmRunner<int32_t> r(execution_tier);
  FunctionSig sig(1, 0, &kWasmI32);
  ModuleTypeIndex sig_index = r.builder().AddSignature(&sig);
  r.builder().AddIndirectFunctionTable(nullptr, 1,
                                       ValueType::RefNull(sig_index));

  r.Build({WASM_CALL_INDIRECT(sig_index, WASM_I32V(0))});

  CHECK_TRAP(r.Call());
}

// This test targets binops in Liftoff.
// Initialize a number of local variables to force them into different
// registers, then perform a binary operation on two of the locals.
// Afterwards, write back all locals to memory, to check that their value was
// not overwritten.
template <typename ctype>
void BinOpOnDifferentRegisters(
    TestExecutionTier execution_tier, ValueType type,
    base::Vector<const ctype> inputs, WasmOpcode opcode,
    std::function<ctype(ctype, ctype, bool*)> expect_fn) {
  static constexpr int kMaxNumLocals = 8;
  for (int num_locals = 1; num_locals < kMaxNumLocals; ++num_locals) {
    // {init_locals_code} is shared by all code generated in the loop below.
    std::vector<uint8_t> init_locals_code;
    // Load from memory into the locals.
    for (int i = 0; i < num_locals; ++i) {
      ADD_CODE(
          init_locals_code,
          WASM_LOCAL_SET(i, WASM_LOAD_MEM(type.machine_type(),
                                          WASM_I32V_2(sizeof(ctype) * i))));
    }
    // {write_locals_code} is shared by all code generated in the loop below.
    std::vector<uint8_t> write_locals_code;
    // Write locals back into memory, shifted by one element to the right.
    for (int i = 0; i < num_locals; ++i) {
      ADD_CODE(write_locals_code,
               WASM_STORE_MEM(type.machine_type(),
                              WASM_I32V_2(sizeof(ctype) * (i + 1)),
                              WASM_LOCAL_GET(i)));
    }
    for (int lhs = 0; lhs < num_locals; ++lhs) {
      for (int rhs = 0; rhs < num_locals; ++rhs) {
        WasmRunner<int32_t> r(execution_tier);
        ctype* memory =
            r.builder().AddMemoryElems<ctype>(kWasmPageSize / sizeof(ctype));
        for (int i = 0; i < num_locals; ++i) {
          r.AllocateLocal(type);
        }
        std::vector<uint8_t> code(init_locals_code);
        ADD_CODE(code,
                 // Store the result of the binary operation at memory[0].
                 WASM_STORE_MEM(type.machine_type(), WASM_ZERO,
                                WASM_BINOP(opcode, WASM_LOCAL_GET(lhs),
                                           WASM_LOCAL_GET(rhs))),
                 // Return 0.
                 WASM_ZERO);
        code.insert(code.end(), write_locals_code.begin(),
                    write_locals_code.end());
        r.Build(base::VectorOf(code));
        for (ctype lhs_value : inputs) {
          for (ctype rhs_value : inputs) {
            if (lhs == rhs) lhs_value = rhs_value;
            for (int i = 0; i < num_locals; ++i) {
              ctype value =
                  i == lhs ? lhs_value
                           : i == rhs ? rhs_value : static_cast<ctype>(i + 47);
              WriteLittleEndianValue<ctype>(&memory[i], value);
            }
            bool trap = false;
            int64_t expect = expect_fn(lhs_value, rhs_value, &trap);
            if (trap) {
              CHECK_TRAP(r.Call());
              continue;
            }
            CHECK_EQ(0, r.Call());
            CHECK_EQ(expect, ReadLittleEndianValue<ctype>(&memory[0]));
            for (int i = 0; i < num_locals; ++i) {
              ctype value =
                  i == lhs ? lhs_value
                           : i == rhs ? rhs_value : static_cast<ctype>(i + 47);
              CHECK_EQ(value, ReadLittleEndianValue<ctype>(&memory[i + 1]));
            }
          }
        }
      }
    }
  }
}

// Keep this list small, the BinOpOnDifferentRegisters test is running long
// enough already.
static constexpr int32_t kSome32BitInputs[] = {
    0, 1, -1, 31, static_cast<int32_t>(0xff112233)};
static constexpr int64_t kSome64BitInputs[] = {
    0, 1, -1, 31, 63, 0x100000000, static_cast<int64_t>(0xff11223344556677)};

WASM_EXEC_TEST(I32AddOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Add,
      [](int32_t lhs, int32_t rhs, bool* trap) { return lhs + rhs; });
}

WASM_EXEC_TEST(I32SubOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Sub,
      [](int32_t lhs, int32_t rhs, bool* trap) { return lhs - rhs; });
}

WASM_EXEC_TEST(I32MulOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Mul, [](int32_t lhs, int32_t rhs, bool* trap) {
        return base::MulWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I32ShlOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Shl, [](int32_t lhs, int32_t rhs, bool* trap) {
        return base::ShlWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I32ShrSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32ShrS,
      [](int32_t lhs, int32_t rhs, bool* trap) { return lhs >> (rhs & 31); });
}

WASM_EXEC_TEST(I32ShrUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32ShrU, [](int32_t lhs, int32_t rhs, bool* trap) {
        return static_cast<uint32_t>(lhs) >> (rhs & 31);
      });
}

WASM_EXEC_TEST(I32DivSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32DivS, [](int32_t lhs, int32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap ? 0 : lhs / rhs;
      });
}

WASM_EXEC_TEST(I32DivUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32DivU, [](uint32_t lhs, uint32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap ? 0 : lhs / rhs;
      });
}

WASM_EXEC_TEST(I32RemSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32RemS, [](int32_t lhs, int32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap || rhs == -1 ? 0 : lhs % rhs;
      });
}

WASM_EXEC_TEST(I32RemUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32RemU, [](uint32_t lhs, uint32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap ? 0 : lhs % rhs;
      });
}

WASM_EXEC_TEST(I64AddOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Add,
      [](int64_t lhs, int64_t rhs, bool* trap) { return lhs + rhs; });
}

WASM_EXEC_TEST(I64SubOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Sub,
      [](int64_t lhs, int64_t rhs, bool* trap) { return lhs - rhs; });
}

WASM_EXEC_TEST(I64MulOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Mul, [](int64_t lhs, int64_t rhs, bool* trap) {
        return base::MulWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I64ShlOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Shl, [](int64_t lhs, int64_t rhs, bool* trap) {
        return base::ShlWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I64ShrSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64ShrS,
      [](int64_t lhs, int64_t rhs, bool* trap) { return lhs >> (rhs & 63); });
}

WASM_EXEC_TEST(I64ShrUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWa
```