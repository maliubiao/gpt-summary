Response: The user wants me to summarize the functionality of the provided C++ code snippet.
This is part 4 of 5, suggesting this file likely focuses on a specific set of features within a larger context.
The code heavily utilizes the `WasmRunner` class and WASM opcodes, indicating it's testing WebAssembly SIMD (Single Instruction, Multiple Data) functionalities in the V8 JavaScript engine.
Specifically, it seems to be testing SIMD operations with 256-bit vectors (indicated by "S256" in test names and the use of AVX2 CPU features).
The tests cover various aspects of 256-bit SIMD in WebAssembly, such as:
- Loading and storing data (including `Load8x8U`, `LoadSplat`, `LoadExtend`).
- Splatting (creating a vector with the same value in all lanes).
- Shuffling.
- Revectorization (optimizing SIMD operations).
- Force-packing (combining 128-bit operations into 256-bit).
- Handling of `phi` nodes in loops.
- Conversions between integer types.
- Conversions between integer and floating-point types.
- Operations with commutative properties.
- Interaction of force-packing with `replace_lane` operations.
- Merging of "intersect pack nodes".

To illustrate the connection with JavaScript, I need to provide a JavaScript example demonstrating a similar SIMD operation that this C++ code tests. A good example would be a load and shuffle operation.
这个C++代码文件（`test-run-wasm-simd.cc` 的第 4 部分）主要功能是**测试 V8 JavaScript 引擎中 WebAssembly SIMD (Single Instruction, Multiple Data) 扩展的 256 位向量操作在 Turbofan 优化器下的执行情况**。

具体来说，它测试了以下 256 位 SIMD 相关的功能：

* **加载操作:**
    * `S256Load8x8U`: 从内存加载 8 个 8 位无符号整数并扩展为 16 位整数到 256 位向量。
    * `S256Load{8, 16, 32, 64}Splat`: 从内存加载单个标量值并将其复制到 256 位向量的所有通道。
* **加载并扩展操作:**
    * `S128Load8x8{U, S}`: 从内存加载 8 个 8 位整数，并将其符号扩展或零扩展到 16 位，结果放入 128 位向量。
    * `S128Load16x4{U, S}`: 从内存加载 4 个 16 位整数，并将其符号扩展或零扩展到 32 位，结果放入 128 位向量。
    * `S128Load32x2{U, S}`: 从内存加载 2 个 32 位整数，并将其符号扩展或零扩展到 64 位，结果放入 128 位向量。
* **存储操作:** 将 256 位 SIMD 向量存储回内存。
* **向量 Splat 操作:** 创建一个 256 位向量，其中所有通道都具有相同的值。
* **向量 Shuffle 操作:** 重新排列向量中的元素。
* **Revectorization (向量化):**  测试 Turbofan 编译器是否能够将标量操作优化为 256 位向量操作。
* **Force Pack (强制打包):** 测试 Turbofan 编译器是否能够将多个 128 位 SIMD 操作打包成单个 256 位 SIMD 操作以提高效率。这通常发生在操作涉及连续或部分连续的内存访问时。
* **Phi 节点处理:** 测试在包含 SIMD 操作的循环中对 Phi 节点的处理。
* **不同数据类型之间的转换:**
    * 窄化转换 (`I16x16SConvertI32x8`, `I16x16UConvertI32x8`, `I8x32SConvertI16x16`, `I8x32UConvertI16x16`)：将较大元素类型的向量转换为较小元素类型的向量。
    * 扩展转换 (`Extend...ConvertF32x8`)：将整型向量转换为浮点型向量。
* **交换律操作:** 测试对满足交换律的 SIMD 操作的优化。
* **Intersect Pack Node (交集打包节点):** 测试在 Turbofan 优化过程中，如何处理涉及多个 `replace_lane` 操作的场景，特别是当这些操作存在交集时。

**与 JavaScript 的关系 (示例):**

虽然 WebAssembly 是一个独立的字节码格式，但它通常在 JavaScript 引擎中执行。这些 C++ 测试确保了 V8 的 Turbofan 编译器能够正确高效地执行 WebAssembly 的 SIMD 指令。

例如，C++ 代码中测试的 `WASM_SIMD_I8x16_SHUFFLE_OP` 功能，在 JavaScript 中可以通过 `Uint8x16` 类型的数组和 SIMD 操作来实现类似的功能：

```javascript
const a = Uint8x16(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
const shuffleIndices = Uint8x16(16, 1, 2, 3, 17, 5, 6, 7, 18, 9, 10, 11, 19, 13, 14, 15); // 假设 16, 17, 18, 19 代表加载另一个向量的元素

// 注意: JavaScript 的 SIMD API 目前没有直接的跨向量 shuffle，
// 但可以通过其他操作组合来实现类似的效果。
// 这里的例子是为了说明概念，实际的 WASM 指令可能更强大。

// 假设我们有另一个向量 b
const b_values = [100, 101, 102, 103]; // 假设 shuffleIndices 指向 b 的元素

const shuffled = Uint8x16(
  (shuffleIndices.extractLane(0) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(0) % 16),
  (shuffleIndices.extractLane(1) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(1) % 16),
  (shuffleIndices.extractLane(2) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(2) % 16),
  (shuffleIndices.extractLane(3) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(3) % 16),
  (shuffleIndices.extractLane(4) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(4) % 16),
  (shuffleIndices.extractLane(5) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(5) % 16),
  (shuffleIndices.extractLane(6) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(6) % 16),
  (shuffleIndices.extractLane(7) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(7) % 16),
  (shuffleIndices.extractLane(8) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(8) % 16),
  (shuffleIndices.extractLane(9) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(9) % 16),
  (shuffleIndices.extractLane(10) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(10) % 16),
  (shuffleIndices.extractLane(11) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(11) % 16),
  (shuffleIndices.extractLane(12) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(12) % 16),
  (shuffleIndices.extractLane(13) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(13) % 16),
  (shuffleIndices.extractLane(14) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(14) % 16),
  (shuffleIndices.extractLane(15) < 16 ? a : Uint8x16(...b_values)).extractLane(shuffleIndices.extractLane(15) % 16)
);

console.log(shuffled);
```

这个 JavaScript 例子展示了如何使用 `Uint8x16` 和 `extractLane` 来模拟 C++ 代码中 `WASM_SIMD_I8x16_SHUFFLE_OP` 的部分功能。 实际的 WebAssembly SIMD 指令可以通过更简洁和高效的方式实现跨向量的 shuffle。 重要的是理解，这个 C++ 文件中的测试确保了当 WebAssembly 代码在 JavaScript 引擎中运行时，这些 SIMD 操作能够按照预期工作并得到有效的优化。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
res::IsSupported(AVX2)) return;
  WasmRunner<int8_t> r(TestExecutionTier::kTurbofan);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(40);

  constexpr std::array<int8_t, 16> shuffle0 = {16, 1, 2,  3,  17, 5,  6,  7,
                                               18, 9, 10, 11, 19, 13, 14, 15};
  constexpr std::array<int8_t, 16> shuffle1 = {4, 17, 18, 19, 5, 21, 22, 23,
                                               6, 25, 26, 27, 7, 29, 30, 31};
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  std::array<uint8_t, kSimd128Size> all_zero = {0};

  {
    auto verify_s256load8x8u = [](const compiler::turboshaft::Graph& graph) {
      for (const compiler::turboshaft::Operation& op : graph.AllOperations()) {
        if (const compiler::turboshaft::Simd256LoadTransformOp* load_op =
                op.TryCast<compiler::turboshaft::Simd256LoadTransformOp>()) {
          if (load_op->transform_kind ==
              compiler::turboshaft::Simd256LoadTransformOp::TransformKind::
                  k8x8U) {
            return true;
          }
        }
      }
      return false;
    };

    TSSimd256VerifyScope ts_scope(r.zone(), verify_s256load8x8u);
    r.Build({WASM_LOCAL_SET(temp1,
                            WASM_SIMD_LOAD_OP(kExprS128Load64Zero, WASM_ZERO)),
             WASM_SIMD_STORE_MEM_OFFSET(
                 8, WASM_ZERO,
                 WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle0,
                                            WASM_SIMD_CONSTANT(all_zero),
                                            WASM_LOCAL_GET(temp1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 24, WASM_ZERO,
                 WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle1,
                                            WASM_LOCAL_GET(temp1),
                                            WASM_SIMD_CONSTANT(all_zero))),
             WASM_ONE});
  }
  std::pair<std::vector<int8_t>, std::vector<int32_t>> test_case = {
      {0, 1, 2, 3, 4, 5, 6, -1}, {0, 1, 2, 3, 4, 5, 6, 255}};
  auto input = test_case.first;
  auto expected_output = test_case.second;
  for (int i = 0; i < 8; ++i) {
    r.builder().WriteMemory(&memory[i], input[i]);
  }
  r.Call();
  int32_t* memory_int32_t = reinterpret_cast<int32_t*>(memory);
  for (int i = 0; i < 8; ++i) {
    CHECK_EQ(expected_output[i],
             r.builder().ReadMemory(&memory_int32_t[i + 2]));
  }
}

template <typename T>
void RunLoadSplatRevecTest(WasmOpcode op, WasmOpcode bin_op,
                           compiler::IrOpcode::Value revec_opcode,
                           T (*expected_op)(T, T)) {
  if (!CpuFeatures::IsSupported(AVX2)) return;

  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  constexpr int lanes = 16 / sizeof(T);
  constexpr int mem_index = 64;  // LoadSplat from mem index 64 (bytes).
  constexpr uint8_t offset = 16;

#define BUILD_LOADSPLAT(get_op, index)                                         \
  T* memory = r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));        \
  uint8_t temp1 = r.AllocateLocal(kWasmS128);                                  \
  uint8_t temp2 = r.AllocateLocal(kWasmS128);                                  \
  uint8_t temp3 = r.AllocateLocal(kWasmS128);                                  \
                                                                               \
  BUILD_AND_CHECK_REVEC_NODE(                                                  \
      r, revec_opcode,                                                         \
      WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_OP(op, get_op(index))),             \
      WASM_LOCAL_SET(temp2,                                                    \
                     WASM_SIMD_BINOP(bin_op, WASM_SIMD_LOAD_MEM(WASM_I32V(0)), \
                                     WASM_LOCAL_GET(temp1))),                  \
      WASM_LOCAL_SET(                                                          \
          temp3, WASM_SIMD_BINOP(                                              \
                     bin_op, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_I32V(0)),  \
                     WASM_LOCAL_GET(temp1))),                                  \
                                                                               \
      /* Store the result to the 32-th byte, which is 2*lanes-th element (size \
         T) of memory */                                                       \
      WASM_SIMD_STORE_MEM(WASM_I32V(32), WASM_LOCAL_GET(temp2)),               \
      WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_I32V(32),                        \
                                 WASM_LOCAL_GET(temp3)),                       \
      WASM_ONE);                                                               \
                                                                               \
  r.builder().WriteMemory(&memory[1], T(1));                                   \
  r.builder().WriteMemory(&memory[lanes + 1], T(1));

  {
    WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
    TSSimd256VerifyScope ts_scope(r.zone());
    BUILD_LOADSPLAT(WASM_I32V, mem_index)

    for (T x : compiler::ValueHelper::GetVector<T>()) {
      // 64-th byte in memory is 4*lanes-th element (size T) of memory.
      r.builder().WriteMemory(&memory[4 * lanes], x);
      r.Call();
      T expected = expected_op(1, x);
      CHECK_EQ(expected, memory[2 * lanes + 1]);
      CHECK_EQ(expected, memory[3 * lanes + 1]);
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, int32_t> r(TestExecutionTier::kTurbofan);
    TSSimd256VerifyScope ts_scope(r.zone());
    BUILD_LOADSPLAT(WASM_LOCAL_GET, 0)

    // Load splats load sizeof(T) bytes.
    for (uint32_t offset = kWasmPageSize - (sizeof(T) - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
#undef BUILD_RUN
}

TEST(RunWasmTurbofan_S256Load8Splat) {
  RunLoadSplatRevecTest<int8_t>(kExprS128Load8Splat, kExprI32x4Add,
                                compiler::IrOpcode::kI32x8Add,
                                base::AddWithWraparound);
}

TEST(RunWasmTurbofan_S256Load16Splat) {
  RunLoadSplatRevecTest<int16_t>(kExprS128Load16Splat, kExprI16x8Add,
                                 compiler::IrOpcode::kI16x16Add,
                                 base::AddWithWraparound);
}

TEST(RunWasmTurbofan_S256Load32Splat) {
  RunLoadSplatRevecTest<int32_t>(kExprS128Load32Splat, kExprI32x4Add,
                                 compiler::IrOpcode::kI32x8Add,
                                 base::AddWithWraparound);
}

TEST(RunWasmTurbofan_S256Load64Splat) {
  RunLoadSplatRevecTest<int64_t>(kExprS128Load64Splat, kExprI64x2Add,
                                 compiler::IrOpcode::kI64x4Add,
                                 base::AddWithWraparound);
}

template <typename S, typename T>
void RunLoadExtendRevecTest(WasmOpcode op) {
  if (!CpuFeatures::IsSupported(AVX2)) return;

  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  static_assert(sizeof(S) < sizeof(T),
                "load extend should go from smaller to larger type");
  constexpr int lanes_s = 16 / sizeof(S);
  constexpr int lanes_t = 16 / sizeof(T);
  constexpr uint8_t offset_s = 8;  // Load extend accesses 8 bytes value.
  constexpr uint8_t offset = 16;
  constexpr int mem_index = 0;  // Load from mem index 0 (bytes).

#define BUILD_LOADEXTEND(get_op, index)                                      \
  uint8_t temp1 = r.AllocateLocal(kWasmS128);                                \
  uint8_t temp2 = r.AllocateLocal(kWasmS128);                                \
                                                                             \
  BUILD_AND_CHECK_REVEC_NODE(                                                \
      r, compiler::IrOpcode::kStore,                                         \
      WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_OP(op, get_op(index))),           \
      WASM_LOCAL_SET(temp2,                                                  \
                     WASM_SIMD_LOAD_OP_OFFSET(op, get_op(index), offset_s)), \
                                                                             \
      /* Store the result to the 16-th byte, which is lanes-th element (size \
         S) of memory. */                                                    \
      WASM_SIMD_STORE_MEM(WASM_I32V(16), WASM_LOCAL_GET(temp1)),             \
      WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_I32V(16),                      \
                                 WASM_LOCAL_GET(temp2)),                     \
      WASM_ONE);

  {
    WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
    TSSimd256VerifyScope ts_scope(r.zone());
    S* memory = r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    BUILD_LOADEXTEND(WASM_I32V, mem_index)

    for (S x : compiler::ValueHelper::GetVector<S>()) {
      for (int i = 0; i < lanes_s; i++) {
        r.builder().WriteMemory(&memory[i], x);
      }
      r.Call();
      for (int i = 0; i < 2 * lanes_t; i++) {
        CHECK_EQ(static_cast<T>(x), reinterpret_cast<T*>(&memory[lanes_s])[i]);
      }
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(TestExecutionTier::kTurbofan);
    TSSimd256VerifyScope ts_scope(r.zone());
    r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    BUILD_LOADEXTEND(WASM_LOCAL_GET, 0)

    // Load extends load 8 bytes, so should trap from -7.
    for (uint32_t offset = kWasmPageSize - 7; offset < kWasmPageSize;
         ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

TEST(S128Load8x8U) {
  RunLoadExtendRevecTest<uint8_t, uint16_t>(kExprS128Load8x8U);
}

TEST(S128Load8x8S) {
  RunLoadExtendRevecTest<int8_t, int16_t>(kExprS128Load8x8S);
}

TEST(S128Load16x4U) {
  RunLoadExtendRevecTest<uint16_t, uint32_t>(kExprS128Load16x4U);
}

TEST(S128Load16x4S) {
  RunLoadExtendRevecTest<int16_t, int32_t>(kExprS128Load16x4S);
}

TEST(S128Load32x2U) {
  RunLoadExtendRevecTest<uint32_t, uint64_t>(kExprS128Load32x2U);
}

TEST(S128Load32x2S) {
  RunLoadExtendRevecTest<int32_t, int64_t>(kExprS128Load32x2S);
}

TEST(RunWasmTurbofan_I8x32Splat) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int8_t> r(TestExecutionTier::kTurbofan);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(32);
  int8_t param1 = 0;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256SplatOp,
                      compiler::turboshaft::Simd256SplatOp::Kind::kI8x32>);
    r.Build({WASM_SIMD_STORE_MEM(WASM_ZERO,
                                 WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 16, WASM_ZERO, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_ONE});
  }
  FOR_INT8_INPUTS(x) {
    r.Call(x);
    for (int i = 0; i < 32; ++i) {
      CHECK_EQ(x, r.builder().ReadMemory(&memory[i]));
    }
  }
}

TEST(RunWasmTurbofan_I16x16Splat) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int16_t> r(TestExecutionTier::kTurbofan);
  int16_t* memory = r.builder().AddMemoryElems<int16_t>(16);
  int16_t param1 = 0;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256SplatOp,
                      compiler::turboshaft::Simd256SplatOp::Kind::kI16x16>);
    r.Build({WASM_SIMD_STORE_MEM(WASM_ZERO,
                                 WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 16, WASM_ZERO, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_ONE});
  }
  FOR_INT16_INPUTS(x) {
    r.Call(x);
    for (int i = 0; i < 16; ++i) {
      CHECK_EQ(x, r.builder().ReadMemory(&memory[i]));
    }
  }
}

TEST(RunWasmTurbofan_I32x8Splat) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(8);
  int32_t param1 = 0;

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256SplatOp,
                      compiler::turboshaft::Simd256SplatOp::Kind::kI32x8>);
    r.Build({WASM_SIMD_STORE_MEM(WASM_ZERO,
                                 WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 16, WASM_ZERO, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_ONE});
  }

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    for (int i = 0; i < 8; ++i) {
      CHECK_EQ(x, r.builder().ReadMemory(&memory[i]));
    }
  }
}

TEST(RunWasmTurbofan_I64x4Splat) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int64_t> r(TestExecutionTier::kTurbofan);
  int64_t* memory = r.builder().AddMemoryElems<int64_t>(4);
  int64_t param1 = 0;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256SplatOp,
                      compiler::turboshaft::Simd256SplatOp::Kind::kI64x4>);
    r.Build({WASM_SIMD_STORE_MEM(WASM_ZERO,
                                 WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 16, WASM_ZERO, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_ONE});
  }

  FOR_INT64_INPUTS(x) {
    r.Call(x);
    for (int i = 0; i < 4; ++i) {
      CHECK_EQ(x, r.builder().ReadMemory(&memory[i]));
    }
  }
}

TEST(RunWasmTurbofan_F32x8Splat) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, float> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(8);
  float param1 = 0;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256SplatOp,
                      compiler::turboshaft::Simd256SplatOp::Kind::kF32x8>);
    r.Build({WASM_SIMD_STORE_MEM(WASM_ZERO,
                                 WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 16, WASM_ZERO, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_ONE});
  }

  FOR_FLOAT32_INPUTS(x) {
    r.Call(x);
    for (int i = 0; i < 8; ++i) {
      if (std::isnan(x)) {
        CHECK(std::isnan(r.builder().ReadMemory(&memory[i])));
      } else {
        CHECK_EQ(x, r.builder().ReadMemory(&memory[i]));
      }
    }
  }
}

TEST(RunWasmTurbofan_F64x4Splat) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, double> r(TestExecutionTier::kTurbofan);
  double* memory = r.builder().AddMemoryElems<double>(4);
  double param1 = 0;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256SplatOp,
                      compiler::turboshaft::Simd256SplatOp::Kind::kF64x4>);
    r.Build({WASM_SIMD_STORE_MEM(WASM_ZERO,
                                 WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 16, WASM_ZERO, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1))),
             WASM_ONE});
  }

  FOR_FLOAT64_INPUTS(x) {
    r.Call(x);
    for (int i = 0; i < 4; ++i) {
      if (std::isnan(x)) {
        CHECK(std::isnan(r.builder().ReadMemory(&memory[i])));
      } else {
        CHECK_EQ(x, r.builder().ReadMemory(&memory[i]));
      }
    }
  }
}

TEST(RunWasmTurbofan_Phi) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  constexpr int32_t iteration = 8;
  constexpr uint32_t lanes = kSimd128Size / sizeof(int32_t);
  constexpr int32_t count = 2 * iteration * lanes;
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(count);
  // Build fn perform add on 128 bit vectors a, store the result in b:
  // int32_t func(simd128* a, simd128* b) {
  //   simd128 sum1 = sum2 = 0;
  //   for (int i = 0; i < 8; i++) {
  //     sum1 += *a;
  //     sum2 += *(a+1);
  //     a += 2;
  //   }
  //   *b = sum1;
  //   *(b+1) = sum2;
  // }
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t index = r.AllocateLocal(kWasmI32);
  uint8_t sum1 = r.AllocateLocal(kWasmS128);
  uint8_t sum2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    BUILD_AND_CHECK_REVEC_NODE(
        r, compiler::IrOpcode::kPhi, WASM_LOCAL_SET(index, WASM_I32V(0)),
        WASM_LOCAL_SET(sum1, WASM_SIMD_I32x4_SPLAT(WASM_I32V(0))),
        WASM_LOCAL_SET(sum2, WASM_LOCAL_GET(sum1)),
        WASM_LOOP(
            WASM_LOCAL_SET(
                sum1,
                WASM_SIMD_BINOP(kExprI32x4Add, WASM_LOCAL_GET(sum1),
                                WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)))),
            WASM_LOCAL_SET(
                sum2, WASM_SIMD_BINOP(kExprI32x4Add, WASM_LOCAL_GET(sum2),
                                      WASM_SIMD_LOAD_MEM_OFFSET(
                                          offset, WASM_LOCAL_GET(param1)))),
            WASM_IF(WASM_I32_LTS(WASM_INC_LOCAL(index), WASM_I32V(iteration)),
                    WASM_BR(1))),
        WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(sum1)),
        WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                   WASM_LOCAL_GET(sum2)),
        WASM_ONE);
  }
  for (int32_t x : compiler::ValueHelper::GetVector<int32_t>()) {
    for (int32_t y : compiler::ValueHelper::GetVector<int32_t>()) {
      for (int32_t i = 0; i < iteration; i++) {
        for (uint32_t j = 0; j < lanes; j++) {
          r.builder().WriteMemory(&memory[i * 2 * lanes + j], x);
          r.builder().WriteMemory(&memory[i * 2 * lanes + j + lanes], y);
        }
      }
      r.Call(0, iteration * 2 * kSimd128Size);
      int32_t* output = reinterpret_cast<int32_t*>(memory + count);
      for (uint32_t i = 0; i < lanes; i++) {
        CHECK_EQ(x * iteration, output[i]);
        CHECK_EQ(y * iteration, output[i + lanes]);
      }
    }
  }
}

TEST(RunWasmTurbofan_ForcePackIdenticalLoad) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    // Load from [0:15], the two loads are indentical.
    r.Build({WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
             WASM_LOCAL_SET(
                 temp1, WASM_SIMD_UNOP(kExprI32x4Abs,
                                       WASM_SIMD_UNOP(kExprS128Not,
                                                      WASM_LOCAL_GET(temp3)))),
             WASM_LOCAL_SET(
                 temp2, WASM_SIMD_UNOP(kExprI32x4Abs,
                                       WASM_SIMD_UNOP(kExprS128Not,
                                                      WASM_LOCAL_GET(temp3)))),

             WASM_SIMD_STORE_MEM_OFFSET(16, WASM_ZERO, WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(32, WASM_ZERO, WASM_LOCAL_GET(temp2)),

             WASM_ONE});
  }
  FOR_INT32_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[13], x);
    r.Call();
    int32_t expected = std::abs(~x);
    CHECK_EQ(expected, memory[5]);
    CHECK_EQ(expected, memory[9]);
  }
}

TEST(RunWasmTurbofan_ForcePackLoadsAtSameAddr) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    // Load from [0:15], the two loads are identical.
    r.Build({WASM_LOCAL_SET(
                 temp1,
                 WASM_SIMD_UNOP(kExprI32x4Abs,
                                WASM_SIMD_UNOP(kExprS128Not,
                                               WASM_SIMD_LOAD_MEM(WASM_ZERO)))),
             WASM_LOCAL_SET(
                 temp2,
                 WASM_SIMD_UNOP(kExprI32x4Abs,
                                WASM_SIMD_UNOP(kExprS128Not,
                                               WASM_SIMD_LOAD_MEM(WASM_ZERO)))),

             WASM_SIMD_STORE_MEM_OFFSET(16, WASM_ZERO, WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(32, WASM_ZERO, WASM_LOCAL_GET(temp2)),

             WASM_ONE});
  }
  FOR_INT32_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[13], x);
    r.Call();
    int32_t expected = std::abs(~x);
    CHECK_EQ(expected, memory[5]);
    CHECK_EQ(expected, memory[9]);
  }
}

TEST(RunWasmTurbofan_ForcePackInContinuousLoad) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    // Load from [0:15] and [48:63] which are incontinuous, calculate the data
    // by Not and Abs and stores the results to [16:31] and [32:47] which are
    // continuous. By force-packing the incontinuous loads, we still revectorize
    // all the operations.
    //   simd128 *a,*b;
    //   simd128 temp1 = abs(!(*a));
    //   simd128 temp2 = abs(!(*(a + 3)));
    //   *b = temp1;
    //   *(b+1) = temp2;
    r.Build({WASM_LOCAL_SET(
                 temp1,
                 WASM_SIMD_UNOP(kExprI32x4Abs,
                                WASM_SIMD_UNOP(kExprS128Not,
                                               WASM_SIMD_LOAD_MEM(WASM_ZERO)))),
             WASM_LOCAL_SET(
                 temp2, WASM_SIMD_UNOP(kExprI32x4Abs,
                                       WASM_SIMD_UNOP(kExprS128Not,
                                                      WASM_SIMD_LOAD_MEM_OFFSET(
                                                          48, WASM_ZERO)))),

             WASM_SIMD_STORE_MEM_OFFSET(16, WASM_ZERO, WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(32, WASM_ZERO, WASM_LOCAL_GET(temp2)),

             WASM_ONE});
  }
  FOR_INT32_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[13], 2 * x);
    r.Call();
    CHECK_EQ(std::abs(~x), memory[5]);
    CHECK_EQ(std::abs(~(2 * x)), memory[9]);
  }
}

TEST(RunWasmTurbofan_ForcePackIncontinuousLoadsReversed) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    // Loads from [48:63] and [0:15] which are incontinuous, calculate the data
    // by Not and Abs and stores the results in reversed order to [16:31] and
    // [32:47] which are continuous. By force-packing the incontinuous loads, we
    // still revectorize all the operations.
    //   simd128 *a,*b;
    //   simd128 temp1 = abs(!(*(a + 3)));
    //   simd128 temp2 = abs(!(*a));
    //   *b = temp2;
    //   *(b+1) = temp1;
    r.Build({WASM_LOCAL_SET(
                 temp1, WASM_SIMD_UNOP(kExprI32x4Abs,
                                       WASM_SIMD_UNOP(kExprS128Not,
                                                      WASM_SIMD_LOAD_MEM_OFFSET(
                                                          48, WASM_ZERO)))),
             WASM_LOCAL_SET(
                 temp2,
                 WASM_SIMD_UNOP(kExprI32x4Abs,
                                WASM_SIMD_UNOP(kExprS128Not,
                                               WASM_SIMD_LOAD_MEM(WASM_ZERO)))),
             WASM_SIMD_STORE_MEM_OFFSET(16, WASM_ZERO, WASM_LOCAL_GET(temp2)),
             WASM_SIMD_STORE_MEM_OFFSET(32, WASM_ZERO, WASM_LOCAL_GET(temp1)),
             WASM_ONE});
  }
  FOR_INT32_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[14], 2 * x);
    r.Call();
    CHECK_EQ(std::abs(~x), memory[5]);
    CHECK_EQ(std::abs(~(2 * x)), memory[10]);
  }
}

TEST(RunWasmTurbofan_RevecReduce) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int64_t, int32_t> r(TestExecutionTier::kTurbofan);
  uint32_t count = 8;
  int64_t* memory = r.builder().AddMemoryElems<int64_t>(count);
  // Build fn perform sum up 128 bit vectors a, return the result:
  // int64_t sum(simd128* a) {
  //   simd128 sum128 = a[0] + a[1] + a[2] + a[3];
  //   return LANE(sum128, 0) + LANE(sum128, 1);
  // }
  uint8_t param1 = 0;
  uint8_t sum1 = r.AllocateLocal(kWasmS128);
  uint8_t sum2 = r.AllocateLocal(kWasmS128);
  uint8_t sum = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    r.Build(
        {WASM_LOCAL_SET(
             sum1, WASM_SIMD_BINOP(kExprI64x2Add,
                                   WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                                   WASM_SIMD_LOAD_MEM_OFFSET(
                                       offset * 2, WASM_LOCAL_GET(param1)))),
         WASM_LOCAL_SET(
             sum2, WASM_SIMD_BINOP(kExprI64x2Add,
                                   WASM_SIMD_LOAD_MEM_OFFSET(
                                       offset, WASM_LOCAL_GET(param1)),
                                   WASM_SIMD_LOAD_MEM_OFFSET(
                                       offset * 3, WASM_LOCAL_GET(param1)))),
         WASM_LOCAL_SET(sum,
                        WASM_SIMD_BINOP(kExprI64x2Add, WASM_LOCAL_GET(sum1),
                                        WASM_LOCAL_GET(sum2))),
         WASM_I64_ADD(WASM_SIMD_I64x2_EXTRACT_LANE(0, WASM_LOCAL_GET(sum)),
                      WASM_SIMD_I64x2_EXTRACT_LANE(1, WASM_LOCAL_GET(sum)))});
  }
  for (int64_t x : compiler::ValueHelper::GetVector<int64_t>()) {
    for (uint32_t i = 0; i < count; i++) {
      r.builder().WriteMemory(&memory[i], x);
    }
    int64_t expected = count * x;
    CHECK_EQ(r.Call(0), expected);
  }
}

TEST(RunWasmTurbofan_ForcePackLoadSplat) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  // Use Load32Splat for the force packing test.

  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(10);
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    r.Build({WASM_LOCAL_SET(
                 temp1, WASM_SIMD_UNOP(kExprI32x4Abs,
                                       WASM_SIMD_UNOP(kExprS128Not,
                                                      WASM_SIMD_LOAD_OP(
                                                          kExprS128Load32Splat,
                                                          WASM_ZERO)))),
             WASM_LOCAL_SET(
                 temp2, WASM_SIMD_UNOP(kExprI32x4Abs,
                                       WASM_SIMD_UNOP(kExprS128Not,
                                                      WASM_SIMD_LOAD_OP_OFFSET(
                                                          kExprS128Load32Splat,
                                                          WASM_ZERO, 4)))),

             WASM_SIMD_STORE_MEM_OFFSET(8, WASM_ZERO, WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(24, WASM_ZERO, WASM_LOCAL_GET(temp2)),

             WASM_ONE});
  }

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      r.builder().WriteMemory(&memory[0], x);
      r.builder().WriteMemory(&memory[1], y);
      r.Call();
      int expected_x = std::abs(~x);
      int expected_y = std::abs(~y);
      for (int i = 0; i < 4; ++i) {
        CHECK_EQ(expected_x, memory[i + 2]);
        CHECK_EQ(expected_y, memory[i + 6]);
      }
    }
  }
}

TEST(RunWasmTurbofan_ForcePackLoadExtend) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  // Use load32x2_s for the force packing test.
  {
    // Test ForcePackType::kSplat
    WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(10);
    uint8_t temp1 = r.AllocateLocal(kWasmS128);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    {
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimdPack128To256>);
      r.Build(
          {WASM_LOCAL_SET(
               temp1, WASM_SIMD_SHIFT_OP(
                          kExprI64x2Shl,
                          WASM_SIMD_UNOP(
                              kExprS128Not,
                              WASM_SIMD_LOAD_OP(kExprS128Load32x2S, WASM_ZERO)),
                          WASM_I32V(1))),
           WASM_LOCAL_SET(
               temp2, WASM_SIMD_SHIFT_OP(
                          kExprI64x2Shl,
                          WASM_SIMD_UNOP(
                              kExprS128Not,
                              WASM_SIMD_LOAD_OP(kExprS128Load32x2S, WASM_ZERO)),
                          WASM_I32V(1))),

           WASM_SIMD_STORE_MEM_OFFSET(8, WASM_ZERO, WASM_LOCAL_GET(temp1)),
           WASM_SIMD_STORE_MEM_OFFSET(24, WASM_ZERO, WASM_LOCAL_GET(temp2)),

           WASM_ONE});
    }

    FOR_INT32_INPUTS(x) {
      FOR_INT32_INPUTS(y) {
        r.builder().WriteMemory(&memory[0], x);
        r.builder().WriteMemory(&memory[1], y);
        r.Call();
        const int64_t expected_x =
            LogicalShiftLeft(~static_cast<int64_t>(x), 1);
        const int64_t expected_y =
            LogicalShiftLeft(~static_cast<int64_t>(y), 1);
        const int64_t* const output_mem =
            reinterpret_cast<const int64_t*>(&memory[2]);
        for (int i = 0; i < 2; ++i) {
          const int64_t actual_x = output_mem[i * 2];
          const int64_t actual_y = output_mem[i * 2 + 1];
          CHECK_EQ(expected_x, actual_x);
          CHECK_EQ(expected_y, actual_y);
        }
      }
    }
  }

  {
    // Test ForcePackType::kGeneral
    WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(12);
    uint8_t temp1 = r.AllocateLocal(kWasmS128);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    {
      // incontinuous load32x2_s
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimdPack128To256>);
      r.Build(
          {WASM_LOCAL_SET(
               temp1, WASM_SIMD_SHIFT_OP(
                          kExprI64x2ShrU,
                          WASM_SIMD_UNOP(
                              kExprS128Not,
                              WASM_SIMD_LOAD_OP(kExprS128Load32x2S, WASM_ZERO)),
                          WASM_I32V(1))),
           WASM_LOCAL_SET(
               temp2, WASM_SIMD_SHIFT_OP(
                          kExprI64x2ShrU,
                          WASM_SIMD_UNOP(kExprS128Not, WASM_SIMD_LOAD_OP_OFFSET(
                                                           kExprS128Load32x2S,
                                                           WASM_ZERO, 40)),
                          WASM_I32V(1))),

           WASM_SIMD_STORE_MEM_OFFSET(8, WASM_ZERO, WASM_LOCAL_GET(temp1)),
           WASM_SIMD_STORE_MEM_OFFSET(24, WASM_ZERO, WASM_LOCAL_GET(temp2)),

           WASM_ONE});
    }
    FOR_INT32_INPUTS(a) {
      FOR_INT32_INPUTS(b) {
        // Don't loop over setting c and d, because an O(n^4) test takes too
        // much time.
        int32_t c = a + b;
        int32_t d = a - b;
        r.builder().WriteMemory(&memory[0], a);
        r.builder().WriteMemory(&memory[1], b);
        r.builder().WriteMemory(&memory[10], c);
        r.builder().WriteMemory(&memory[11], d);
        r.Call();
        const int64_t expected_a =
            LogicalShiftRight(~static_cast<int64_t>(a), 1);
        const int64_t expected_b =
            LogicalShiftRight(~static_cast<int64_t>(b), 1);
        const int64_t expected_c =
            LogicalShiftRight(~static_cast<int64_t>(c), 1);
        const int64_t expected_d =
            LogicalShiftRight(~static_cast<int64_t>(d), 1);
        const int64_t* const output_mem =
            reinterpret_cast<const int64_t*>(&memory[2]);
        const int64_t actual_a = output_mem[0];
        const int64_t actual_b = output_mem[1];
        const int64_t actual_c = output_mem[2];
        const int64_t actual_d = output_mem[3];
        CHECK_EQ(expected_a, actual_a);
        CHECK_EQ(expected_b, actual_b);
        CHECK_EQ(expected_c, actual_c);
        CHECK_EQ(expected_d, actual_d);
      }
    }
  }
}

TEST(RunWasmTurbofan_ForcePackI16x16ConvertI8x16) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(48);
  uint8_t param1 = 0;
  uint8_t param2 = 1;

  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    r.Build({WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(
                 temp1,
                 WASM_SIMD_UNOP(
                     kExprI16x8Neg,
                     WASM_SIMD_UNOP(kExprS128Not,
                                    WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                                   WASM_LOCAL_GET(temp3))))),
             WASM_LOCAL_SET(
                 temp2,
                 WASM_SIMD_UNOP(
                     kExprI16x8Neg,
                     WASM_SIMD_UNOP(kExprS128Not,
                                    WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                                   WASM_LOCAL_GET(temp3))))),
             WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                        WASM_LOCAL_GET(temp2)),
             WASM_ONE});
  }
  FOR_INT8_INPUTS(x) {
    for (int i = 0; i < 16; i++) {
      r.builder().WriteMemory(&memory[i], x);
    }
    r.Call(0, 16);
    int16_t expected_signed = -(~static_cast<int16_t>(x));
    int16_t* out_memory = reinterpret_cast<int16_t*>(memory);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, out_memory[8 + i]);
      CHECK_EQ(expected_signed, out_memory[16 + i]);
    }
  }
}

TEST(RunWasmTurbofan_ForcePackI16x16ConvertI8x16ExpectFail) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  r.builder().AddMemoryElems<int8_t>(48);
  uint8_t param1 = 0;
  uint8_t param2 = 1;

  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(),
        TSSimd256VerifyScope::VerifyHaveOpcode<
            compiler::turboshaft::Opcode::kSimdPack128To256>,
        ExpectedResult::kFail);
    // ExprI16x8SConvertI8x16Low use the result of another
    // ExprI16x8SConvertI8x16Low so the force pack should fail.
    r.Build({WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(
                 temp1,
                 WASM_SIMD_UNOP(
                     kExprI16x8Neg,
                     WASM_SIMD_UNOP(kExprS128Not,
                                    WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                                   WASM_LOCAL_GET(temp3))))),
             WASM_LOCAL_SET(
                 temp2,
                 WASM_SIMD_UNOP(
                     kExprI16x8Neg,
                     WASM_SIMD_UNOP(kExprS128Not,
                                    WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                                   WASM_LOCAL_GET(temp1))))),
             WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                        WASM_LOCAL_GET(temp2)),
             WASM_ONE});
  }
}

TEST(RunWasmTurbofan_ForcePackInternalI16x16ConvertI8x16) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(64);
  uint8_t param1 = 0;
  uint8_t param2 = 1;

  // Load a i16x8 vector from memory, convert it to i8x16, and add the result
  // back to the original vector. This means that kExprI16x8SConvertI8x16Low
  // will be in an internal packed node, whose inputs are also packed nodes. In
  // this case we should properly handle the inputs by Simd256Extract128Lane.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  uint8_t temp5 = r.AllocateLocal(kWasmS128);
  uint8_t temp6 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    r.Build(
        {WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
         WASM_LOCAL_SET(
             temp4, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1))),
         WASM_LOCAL_SET(
             temp1, WASM_SIMD_UNOP(kExprI16x8Neg,
                                   WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                                  WASM_LOCAL_GET(temp3)))),
         WASM_LOCAL_SET(
             temp2, WASM_SIMD_UNOP(kExprI16x8Neg,
                                   WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                                  WASM_LOCAL_GET(temp3)))),
         WASM_LOCAL_SET(temp5,
                        WASM_SIMD_BINOP(kExprI16x8Add, WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp3))),
         WASM_LOCAL_SET(temp6,
                        WASM_SIMD_BINOP(kExprI16x8Add, WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp4))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp5)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                    WASM_LOCAL_GET(temp6)),
         WASM_ONE});
  }
  FOR_INT8_INPUTS(x) {
    for (int i = 0; i < 16; i++) {
      r.builder().WriteMemory(&memory[i], x);
      r.builder().WriteMemory(&memory[i + 16], x);
    }
    r.Call(0, 32);
    int16_t extended_x = static_cast<int16_t>(x);
    int16_t expected_signed =
        -extended_x + ((extended_x << 8) + (extended_x & 0xFF));
    int16_t* out_memory = reinterpret_cast<int16_t*>(memory);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, out_memory[16 + i]);
      CHECK_EQ(expected_signed, out_memory[24 + i]);
    }
  }
}

TEST(RunWasmTurbofan_ForcePackLoadZero) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  // Use load32_zero for the force packing test.
  {
    // Test ForcePackType::kSplat
    WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(9);
    uint8_t temp1 = r.AllocateLocal(kWasmS128);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    {
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimdPack128To256>);
      r.Build({WASM_LOCAL_SET(
                   temp1, WASM_SIMD_UNOP(kExprS128Not,
                                         WASM_SIMD_LOAD_OP(kExprS128Load32Zero,
                                                           WASM_ZERO))),
               WASM_LOCAL_SET(
                   temp2, WASM_SIMD_UNOP(kExprS128Not,
                                         WASM_SIMD_LOAD_OP(kExprS128Load32Zero,
                                                           WASM_ZERO))),

               WASM_SIMD_STORE_MEM_OFFSET(20, WASM_ZERO, WASM_LOCAL_GET(temp2)),
               WASM_SIMD_STORE_MEM_OFFSET(4, WASM_ZERO, WASM_LOCAL_GET(temp1)),

               WASM_ONE});
    }

    FOR_INT32_INPUTS(a) {
      int32_t expected_a = ~a;
      constexpr int32_t expected_padding = ~0;
      r.builder().WriteMemory(&memory[0], a);
      r.Call();
      CHECK_EQ(memory[1], expected_a);
      CHECK_EQ(memory[2], expected_padding);
      CHECK_EQ(memory[3], expected_padding);
      CHECK_EQ(memory[4], expected_padding);
      CHECK_EQ(memory[5], expected_a);
      CHECK_EQ(memory[6], expected_padding);
      CHECK_EQ(memory[7], expected_padding);
      CHECK_EQ(memory[8], expected_padding);
    }
  }

  {
    // Test ForcePackType::kGeneral
    WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(10);
    uint8_t temp1 = r.AllocateLocal(kWasmS128);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    {
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimdPack128To256>);
      r.Build({WASM_LOCAL_SET(
                   temp1, WASM_SIMD_UNOP(kExprS128Not,
                                         WASM_SIMD_LOAD_OP(kExprS128Load32Zero,
                                                           WASM_ZERO))),
               WASM_LOCAL_SET(
                   temp2, WASM_SIMD_UNOP(kExprS128Not, WASM_SIMD_LOAD_OP_OFFSET(
                                                           kExprS128Load32Zero,
                                                           WASM_ZERO, 4))),

               WASM_SIMD_STORE_MEM_OFFSET(24, WASM_ZERO, WASM_LOCAL_GET(temp2)),
               WASM_SIMD_STORE_MEM_OFFSET(8, WASM_ZERO, WASM_LOCAL_GET(temp1)),

               WASM_ONE});
    }

    FOR_INT32_INPUTS(x) {
      FOR_INT32_INPUTS(y) {
        r.builder().WriteMemory(&memory[0], x);
        r.builder().WriteMemory(&memory[1], y);
        r.Call();
        int expected_x = ~x;
        int expected_y = ~y;
        constexpr int32_t expected_padding = ~0;
        CHECK_EQ(memory[2], expected_x);
        CHECK_EQ(memory[3], expected_padding);
        CHECK_EQ(memory[4], expected_padding);
        CHECK_EQ(memory[5], expected_padding);
        CHECK_EQ(memory[6], expected_y);
        CHECK_EQ(memory[7], expected_padding);
        CHECK_EQ(memory[8], expected_padding);
        CHECK_EQ(memory[8], expected_padding);
      }
    }
  }
}

template <bool inputs_swapped = false>
void RunForcePackF32x4ReplaceLaneIntersectTest() {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(16);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  uint8_t temp5 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  uint8_t add1, add2, add3, add4;
  if constexpr (inputs_swapped) {
    add1 = temp3;
    add2 = temp2;
    add3 = temp4;
    add4 = temp3;
  } else {
    add1 = temp2;
    add2 = temp3;
    add3 = temp3;
    add4 = temp4;
  }

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    // Test force-packing two f32x4 replace_lanes(2, 3) or (3, 4) in
    // ForcePackNode, and intersected replace_lanes(3, 4) or (2, 3) in
    // IntersectPackNode. Reduce the ForcePackNode and IntersectPackNode in
    // different order.
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_F32(3.14f))),
         WASM_LOCAL_SET(temp2, WASM_SIMD_F32x4_REPLACE_LANE(
                                   0, WASM_LOCAL_GET(temp1), WASM_F32(0.0f))),
         WASM_LOCAL_SET(temp3, WASM_SIMD_F32x4_REPLACE_LANE(
                                   1, WASM_LOCAL_GET(temp1), WASM_F32(1.0f))),
         WASM_LOCAL_SET(temp4, WASM_SIMD_F32x4_REPLACE_LANE(
                                   2, WASM_LOCAL_GET(temp1), WASM_F32(2.0f))),
         WASM_LOCAL_SET(
             temp5,
             WASM_SIMD_BINOP(
                 kExprF32x4Mul, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                 WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(add1),
                                 WASM_LOCAL_GET(add2)))),
         WASM_LOCAL_SET(
             temp4,
             WASM_SIMD_BINOP(
                 kExprF32x4Mul,
                 WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1)),
                 WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(add3),
                                 WASM_LOCAL_GET(add4)))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp5)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                    WASM_LOCAL_GET(temp4)),
         WASM_ONE});
  }

  for (int i = 0; i < 8; i++) {
    r.builder().WriteMemory(&memory[i], 2.0f);
  }
  r.Call(0, 32);
  CHECK_EQ(Mul(Add(3.14f, 0.0f), 2.0f), memory[8]);
  CHECK_EQ(Mul(Add(3.14f, 1.0f), 2.0f), memory[9]);
  CHECK_EQ(Mul(Add(3.14f, 1.0f), 2.0f), memory[13]);
  CHECK_EQ(Mul(Add(3.14f, 2.0f), 2.0f), memory[14]);
}

TEST(RunWasmTurbofan_ForcePackF32x4ReplaceLaneIntersect1) {
  RunForcePackF32x4ReplaceLaneIntersectTest<false>();
}

TEST(RunWasmTurbofan_ForcePackF32x4ReplaceLaneIntersect2) {
  RunForcePackF32x4ReplaceLaneIntersectTest<true>();
}

TEST(RunWasmTurbofan_IntersectPackNodeMerge1) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(24);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  uint8_t temp5 = r.AllocateLocal(kWasmS128);
  uint8_t temp6 = r.AllocateLocal(kWasmS128);
  uint8_t temp7 = r.AllocateLocal(kWasmS128);
  uint8_t temp8 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  // Build an SLPTree with default, ForcePackNode and IntersectPackNode. Build
  // another SLPTree that will merge with the default and IntersectPackNode.
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_F32(3.14f))),
         WASM_LOCAL_SET(temp2, WASM_SIMD_F32x4_REPLACE_LANE(
                                   0, WASM_LOCAL_GET(temp1), WASM_F32(0.0f))),
         WASM_LOCAL_SET(temp3, WASM_SIMD_F32x4_REPLACE_LANE(
                                   1, WASM_LOCAL_GET(temp1), WASM_F32(1.0f))),
         WASM_LOCAL_SET(temp4, WASM_SIMD_F32x4_REPLACE_LANE(
                                   2, WASM_LOCAL_GET(temp1), WASM_F32(2.0f))),
         WASM_LOCAL_SET(temp5, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_LOCAL_SET(temp6, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_ZERO)),
         WASM_LOCAL_SET(
             temp7, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp5),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp3)))),
         WASM_LOCAL_SET(
             temp8, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp6),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp3),
                                        WASM_LOCAL_GET(temp4)))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param1), WASM_LOCAL_GET(temp7)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param1),
                                    WASM_LOCAL_GET(temp8)),
         WASM_LOCAL_SET(
             temp7, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp5),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp3)))),
         WASM_LOCAL_SET(
             temp8, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp6),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp4),
                                        WASM_LOCAL_GET(temp4)))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp7)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                    WASM_LOCAL_GET(temp8)),
         WASM_ONE});
  }
  for (int i = 0; i < 8; i++) {
    r.builder().WriteMemory(&memory[i], 2.0f);
  }

  r.Call(32, 64);
  CHECK_EQ(Add(Add(3.14f, 0.0f), 2.0f), memory[8]);
  CHECK_EQ(Add(Add(3.14f, 1.0f), 2.0f), memory[9]);
  CHECK_EQ(Add(Add(3.14f, 1.0f), 2.0f), memory[13]);
  CHECK_EQ(Add(Add(3.14f, 2.0f), 2.0f), memory[14]);
  CHECK_EQ(Add(Add(3.14f, 0.0f), 2.0f), memory[16]);
  CHECK_EQ(Add(Add(3.14f, 1.0f), 2.0f), memory[17]);
  CHECK_EQ(Add(Add(2.0f, 2.0f), 2.0f), memory[22]);
}

TEST(RunWasmTurbofan_IntersectPackNodeMerge2) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(24);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  uint8_t temp5 = r.AllocateLocal(kWasmS128);
  uint8_t temp6 = r.AllocateLocal(kWasmS128);
  uint8_t temp7 = r.AllocateLocal(kWasmS128);
  uint8_t temp8 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  // Build an SLPTree with default, ForcePackNode(2, 3) and IntersectPackNode(3,
  // 4). Build another SLPTree that will create new IntersectPackNode(1, 3) and
  // (4, 4) and expand the existing revetorizable_intersect_node map entries.
  // This test will ensure no missing IntersectPackNode after the merge.
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimdPack128To256>);
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_F32(3.14f))),
         WASM_LOCAL_SET(temp2, WASM_SIMD_F32x4_REPLACE_LANE(
                                   0, WASM_LOCAL_GET(temp1), WASM_F32(0.0f))),
         WASM_LOCAL_SET(temp3, WASM_SIMD_F32x4_REPLACE_LANE(
                                   1, WASM_LOCAL_GET(temp1), WASM_F32(1.0f))),
         WASM_LOCAL_SET(temp4, WASM_SIMD_F32x4_REPLACE_LANE(
                                   2, WASM_LOCAL_GET(temp1), WASM_F32(2.0f))),
         WASM_LOCAL_SET(temp5, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_LOCAL_SET(temp6, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_ZERO)),
         WASM_LOCAL_SET(
             temp7, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp5),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp3)))),
         WASM_LOCAL_SET(
             temp8, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp6),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp3),
                                        WASM_LOCAL_GET(temp4)))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param1), WASM_LOCAL_GET(temp7)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param1),
                                    WASM_LOCAL_GET(temp8)),
         WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_REPLACE_LANE(
                                   3, WASM_LOCAL_GET(temp1), WASM_F32(3.0f))),
         WASM_LOCAL_SET(
             temp7, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp5),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp4)))),
         WASM_LOCAL_SET(
             temp8, WASM_SIMD_BINOP(
                        kExprF32x4Add, WASM_LOCAL_GET(temp6),
                        WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp3),
                                        WASM_LOCAL_GET(temp4)))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp7)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                    WASM_LOCAL_GET(temp8)),
         WASM_ONE});
  }
  for (int i = 0; i < 8; i++) {
    r.builder().WriteMemory(&memory[i], 2.0f);
  }

  r.Call(32, 64);
  CHECK_EQ(Add(Add(3.14f, 0.0f), 2.0f), memory[8]);
  CHECK_EQ(Add(Add(3.14f, 1.0f), 2.0f), memory[9]);
  CHECK_EQ(Add(Add(3.14f, 1.0f), 2.0f), memory[13]);
  CHECK_EQ(Add(Add(3.14f, 2.0f), 2.0f), memory[14]);
  CHECK_EQ(Add(Add(3.14f, 2.0f), 2.0f), memory[18]);
  CHECK_EQ(Add(Add(3.14f, 3.0f), 2.0f), memory[19]);
  CHECK_EQ(Add(Add(3.14f, 1.0f), 2.0f), memory[21]);
  CHECK_EQ(Add(Add(3.14f, 2.0f), 2.0f), memory[22]);
}

TEST(RunWasmTurbofan_RevecCommutativeOp) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  // Add int variable a to each element of 256 bit vectors b, store the result
  // in c
  //   int32_t a,
  //   simd128 *b,*c;
  //   *c = splat(a) + *b;
  //   *(c+1) = *(b+1) + splat(a);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;

  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256BinopOp,
                      compiler::turboshaft::Simd256BinopOp::Kind::kI32x8Add>);
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param1))),
         WASM_LOCAL_SET(temp2, WASM_SIMD_BINOP(
                                   kExprI32x4Add, WASM_LOCAL_GET(temp1),
                                   WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
         WASM_LOCAL_SET(temp3,
                        WASM_SIMD_BINOP(kExprI32x4Add,
                                        WASM_SIMD_LOAD_MEM_OFFSET(
                                            offset, WASM_LOCAL_GET(param2)),
                                        WASM_LOCAL_GET(temp1))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param3), WASM_LOCAL_GET(temp2)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param3),
                                    WASM_LOCAL_GET(temp3)),
         WASM_ONE});
  }

  for (int32_t x : compiler::ValueHelper::GetVector<int32_t>()) {
    for (int32_t y : compiler::ValueHelper::GetVector<int32_t>()) {
      for (int i = 0; i < 8; i++) {
        r.builder().WriteMemory(&memory[i], y);
      }
      int64_t expected = base::AddWithWraparound(x, y);
      CHECK_EQ(r.Call(x, 0, 32), 1);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, memory[i + 8]);
      }
    }
  }
}

TEST(RunWasmTurbofan_I16x16SConvertI32x8) {
  RunIntToIntNarrowingRevecTest<int32_t, int16_t>(
      kExprI16x8SConvertI32x4, compiler::IrOpcode::kI16x16SConvertI32x8);
}

TEST(RunWasmTurbofan_I16x16UConvertI32x8) {
  RunIntToIntNarrowingRevecTest<int32_t, uint16_t>(
      kExprI16x8UConvertI32x4, compiler::IrOpcode::kI16x16UConvertI32x8);
}

TEST(RunWasmTurbofan_I8x32SConvertI16x16) {
  RunIntToIntNarrowingRevecTest<int16_t, int8_t>(
      kExprI8x16SConvertI16x8, compiler::IrOpcode::kI8x32SConvertI16x16);
}

TEST(RunWasmTurbofan_I8x32UConvertI16x16) {
  RunIntToIntNarrowingRevecTest<int16_t, uint8_t>(
      kExprI8x16UConvertI16x8, compiler::IrOpcode::kI8x32UConvertI16x16);
}

#define RunExtendIntToF32x4RevecTest(format, sign, convert_opcode,             \
                                     convert_sign, param_type, extract_type,   \
                                     convert_type)                             \
  TEST(RunWasmTurbofan_Extend##format##sign##ConvertF32x8##convert_sign) {     \
    SKIP_TEST_IF_NO_TURBOSHAFT;                                                \
    EXPERIMENTAL_FLAG_SCOPE(revectorize);                                      \
    if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2))     \
      return;                                                                  \
    WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);     \
    param_type* memory =                                                       \
        r.builder().AddMemoryElems<param_type>(48 / sizeof(param_type));       \
    uint8_t param1 = 0;                                                        \
    uint8_t param2 = 1;                                                        \
    uint8_t input = r.AllocateLocal(kWasmS128);                                \
    uint8_t output1 = r.AllocateLocal(kWasmS128);                              \
    uint8_t output2 = r.AllocateLocal(kWasmS128);                              \
    constexpr uint8_t offset = 16;                                             \
    {                                                                          \
      TSSimd256VerifyScope ts_scope(                                           \
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<                \
                        compiler::turboshaft::Simd256UnaryOp,                  \
                        compiler::turboshaft::Simd256UnaryOp::Kind::           \
                            kF32x8##convert_sign##ConvertI32x8>);              \
      r.Build(                                                                 \
          {WASM_LOCAL_SET(input, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),  \
           WASM_LOCAL_SET(                                                     \
               output1,                                                        \
               WASM_SIMD_F32x4_SPLAT(WASM_UNOP(                                \
                   convert_opcode, WASM_SIMD_##format##_EXTRACT_LANE##sign(    \
                                       0, WASM_LOCAL_GET(input))))),           \
           WASM_LOCAL_SET(                                                     \
               output1, WASM_SIMD_F32x4_REPLACE_LANE(                          \
                            1, WASM_LOCAL_GET(output1),                        \
                            WASM_UNOP(convert_opcode,                          \
                                      WASM_SIMD_##format##_EXTRACT_LANE##sign( \
                                          1, WASM_LOCAL_GET(input))))),        \
           WASM_LOCAL_SET(                                                     \
               output1, WASM_SIMD_F32x4_REPLACE_LANE(                          \
                            2, WASM_LOCAL_GET(output1),                        \
                            WASM_UNOP(convert_opcode,                          \
                                      WASM_SIMD_##format##_EXTRACT_LANE##sign( \
                                          2, WASM_LOCAL_GET(input))))),        \
           WASM_LOCAL_SET(                                                     \
               output1, WASM_SIMD_F32x4_REPLACE_LANE(                          \
                            3, WASM_LOCAL_GET(output1),                        \
                            WASM_UNOP(convert_opcode,                          \
                                      WASM_SIMD_##format##_EXTRACT_LANE##sign( \
                                          3, WASM_LOCAL_GET(input))))),        \
           WASM_LOCAL_SET(                                                     \
               output2,                                                        \
               WASM_SIMD_F32x4_SPLAT(WASM_UNOP(                                \
                   convert_opcode, WASM_SIMD_##format##_EXTRACT_LANE##sign(    \
                                       4, WASM_LOCAL_GET(input))))),           \
           WASM_LOCAL_SET(                                                     \
               output2, WASM_SIMD_F32x4_REPLACE_LANE(                          \
                            1, WASM_LOCAL_GET(output2),                        \
                            WASM_UNOP(convert_opcode,                          \
                                      WASM_SIMD_##format##_EXTRACT_LANE##sign( \
                                          5, WASM_LOCAL_GET(input))))),        \
           WASM_LOCAL_SET(                                                     \
               output2, WASM_SIMD_F32x4_REPLACE_LANE(                          \
                            2, WASM_LOCAL_GET(output2),                        \
                            WASM_UNOP(convert_opcode,                          \
                                      WASM_SIMD_##format##_EXTRACT_LANE##sign( \
                                          6, WASM_LOCAL_GET(input))))),        \
           WASM_LOCAL_SET(                                                     \
               output2, WASM_SIMD_F32x4_REPLACE_LANE(                          \
                            3, WASM_LOCAL_GET(output2),                        \
                            WASM_UNOP(convert_opcode,                          \
                                      WASM_SIMD_##format##_EXTRACT_LANE##sign( \
                                          7, WASM_LOCAL_GET(input))))),        \
           WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2),                         \
                               WASM_LOCAL_GET(output1)),                       \
           WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),          \
                                      WASM_LOCAL_GET(output2)),                \
           WASM_ONE});                                                         \
    }                                                                          \
                                                                               \
    constexpr uint32_t lanes = kSimd128Size / sizeof(param_type);              \
    auto values = compiler::ValueHelper::GetVector<param_type>();              \
    float* output = (float*)(memory + lanes);                                  \
    for (uint32_t i = 0; i + lanes <= values.size(); i++) {                    \
      for (uint32_t j = 0; j < lanes; j++) {                                   \
        r.builder().WriteMemory(&memory[j], values[i + j]);                    \
      }                                                                        \
      r.Call(0, 16);                                                           \
```