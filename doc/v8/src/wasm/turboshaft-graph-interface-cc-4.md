Response:
Let's break down the thought process for analyzing this V8 Turboshaft code snippet.

1. **Initial Understanding of the File's Purpose:** The filename `v8/src/wasm/turboshaft-graph-interface.cc` immediately suggests that this file bridges the gap between the WebAssembly bytecode and the Turboshaft compiler's internal graph representation. The "graph interface" part is key – it's responsible for translating WASM operations into Turboshaft's nodes and edges.

2. **Code Structure Observation:**  Scanning the provided code, I see a lot of `case kExpr...:` statements within a `switch` block. This strongly indicates that the code is handling different WASM opcodes. The `HANDLE_*_OPCODE` macros further confirm this. There's a clear pattern of taking WASM opcodes and generating corresponding Turboshaft operations (like `__ Simd128Binop`, `__ Simd128Unary`, etc.).

3. **Focusing on Key Functionality:**  The prevalence of `Simd128` related opcodes (`kExprI8x16...`, `kExprF32x4...`) tells me that a significant portion of this code deals with SIMD (Single Instruction, Multiple Data) operations in WebAssembly. The presence of `F16x8` opcodes also highlights support for the Float16 extension.

4. **Analyzing the Macros:** The macros like `HANDLE_BINARY_OPCODE`, `HANDLE_UNARY_OPTIONAL_OPCODE`, etc., are crucial. They encapsulate the common logic for handling different categories of opcodes. The "optional" distinction often involves checking for feature support (`SupportedOperations::float16()`) and potentially falling back to C++ runtime calls (`CallCStackSlotToStackSlot`). This hints at how V8 handles features that might not be universally supported on all hardware.

5. **Connecting to JavaScript:**  WebAssembly's primary purpose is to run alongside JavaScript in web browsers and Node.js. Therefore, I consider how these SIMD operations might be exposed or used from JavaScript. The `WebAssembly.SIMD` API comes to mind. I then construct a simple JavaScript example demonstrating basic SIMD addition to illustrate the connection.

6. **Identifying Potential Programming Errors:**  The conditional logic related to feature support (`SupportedOperations::float16()`) points to a common programming error: using features that are not available in the current environment. I create an example of trying to use Float16 SIMD in an environment that doesn't support it, demonstrating the error.

7. **Tracing Data Flow and Logic (Hypothetical Input/Output):**  I imagine a simple binary SIMD operation, like adding two `i32x4` vectors.

    * **Input:** WASM opcode `kExprI32x4Add`, two `Simd128` values representing the vectors.
    * **Processing:** The code would hit the `kExprI32x4Add` case, use the `HANDLE_BINARY_OPCODE` macro, and generate a `compiler::turboshaft::Simd128Binop` with the `kI32x4Add` kind.
    * **Output:** A Turboshaft `Simd128Binop` operation representing the addition.

8. **Considering `.tq` Files:** The prompt mentions `.tq` files (Torque). I know Torque is V8's internal language for implementing built-in functions. The fact that this file is `.cc` (C++) tells me it's *not* a Torque file. I need to explicitly state that.

9. **Focusing on the Provided Snippet (Part 5):**  The prompt explicitly mentions this is "Part 5". I review the specific code provided, noting the handling of various SIMD binary, unary, shift, test, splat, and ternary operations. This reinforces the central theme of translating WASM SIMD instructions.

10. **Synthesizing the Summary:**  Based on the analysis, I formulate a concise summary highlighting the core function: converting WASM SIMD opcodes to Turboshaft graph nodes. I also mention the handling of feature-dependent operations and the connection to the `WebAssembly.SIMD` API.

11. **Refining and Structuring the Answer:**  I organize the information logically, starting with the main function, then elaborating on specific aspects like JavaScript integration, potential errors, and the hypothetical input/output. I ensure to address all points raised in the prompt, including the `.tq` file check and the "Part 5" context. I use clear and concise language, avoiding overly technical jargon where possible.
好的，让我们来分析一下 `v8/src/wasm/turboshaft-graph-interface.cc` 这个代码片段的功能。

**功能归纳：**

这段代码的主要功能是 **将 WebAssembly 的 SIMD (Single Instruction, Multiple Data) 操作码转换为 Turboshaft 编译器内部图表示中的相应操作**。它是 Turboshaft 编译器处理 WASM SIMD 指令的关键部分。

**详细功能分解：**

1. **SIMD 二元操作处理 (`FOREACH_SIMD_128_BINARY_MANDATORY_OPCODE` 和 `HANDLE_BINARY_OPCODE` 等宏):**
   - 这部分代码处理诸如加法、减法、乘法、除法、比较等 SIMD 二元运算。
   - 它根据 WASM 的操作码 (`kExprI32x4Add`, `kExprF32x4Sub` 等) 创建 Turboshaft 编译器中对应的 `Simd128Binop` 节点。
   - 例如，`kExprI32x4Add` 会被转换为 `compiler::turboshaft::Simd128BinopOp::Kind::kI32x4Add`。

2. **SIMD 可选二元操作处理 (`HANDLE_F16X8_BIN_OPTIONAL_OPCODE`):**
   - 这部分专门处理 `F16x8` (16位浮点数) 类型的 SIMD 二元操作。
   - 它会检查当前平台是否支持 `float16` 特性 (`SupportedOperations::float16()`)。
   - 如果支持，则直接创建 `Simd128Binop` 节点。
   - 如果不支持，则会生成一个调用 C++ runtime 函数 (`CallCStackSlotToStackSlot`) 的操作，以模拟这些操作。这是一种降级处理方式。

3. **SIMD 逆向比较操作处理 (`HANDLE_INVERSE_COMPARISON`):**
   - 这部分处理一些比较操作的反向情况，例如将 `I8x16LtS` (小于) 转换为 `I8x16GtS` (大于) 并交换操作数，这可能是一种优化或简化内部表示的方式。

4. **SIMD 一元操作处理 (`FOREACH_SIMD_128_UNARY_NON_OPTIONAL_OPCODE`, `HANDLE_UNARY_OPTIONAL_OPCODE`):**
   - 处理诸如取绝对值、取反、平方根等 SIMD 一元运算。
   - 类似于二元操作，可选的操作会检查特性支持，并在不支持时调用 C++ runtime 函数。

5. **SIMD 移位操作处理 (`FOREACH_SIMD_128_SHIFT_OPCODE`, `HANDLE_SHIFT_OPCODE`):**
   - 处理 SIMD 向量的移位操作。

6. **SIMD 测试操作处理 (`FOREACH_SIMD_128_TEST_OPCODE`, `HANDLE_TEST_OPCODE`):**
   - 处理 SIMD 向量的测试操作，通常用于生成掩码。

7. **SIMD Splat 操作处理 (`FOREACH_SIMD_128_SPLAT_MANDATORY_OPCODE`, `HANDLE_SPLAT_OPCODE`):**
   - 处理将单个标量值复制到 SIMD 向量所有通道的操作。
   - `F16x8Splat` 的处理比较特殊，如果不支持 `float16`，会先将浮点数转换为 `i16` 再进行 splat。

8. **SIMD 三元操作处理 (`FOREACH_SIMD_128_TERNARY_MASK_OPCODE`, `FOREACH_SIMD_128_TERNARY_OTHER_OPCODE`, `HANDLE_F16X8_TERN_OPCODE`):**
   - 处理需要三个操作数的 SIMD 操作，例如 `select` (根据掩码选择) 和一些 fused multiply-add 操作 (`F16x8Qfma`, `F16x8Qfms`)。
   - `F16x8` 的三元操作也需要检查特性支持。

**关于文件类型和 JavaScript 关系：**

* **文件类型:**  由于文件名为 `turboshaft-graph-interface.cc`，以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。
* **JavaScript 关系:**  这段代码直接关系到 JavaScript 中 WebAssembly 的 SIMD 功能。JavaScript 通过 `WebAssembly.SIMD` API 来使用这些功能。

**JavaScript 示例：**

```javascript
// 假设你有一个 WebAssembly 模块，其中定义了一个导出函数来执行 i32x4 的加法
const wasmCode = `
  (module
    (memory (export "memory") 1)
    (func (export "add_i32x4") (param $a v128) (param $b v128) (result v128)
      local.get $a
      local.get $b
      i32x4.add
    )
  )
`;

const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 创建两个 i32x4 类型的 SIMD 值
const a = new Uint32Array([1, 2, 3, 4]);
const b = new Uint32Array([5, 6, 7, 8]);
const simd_a = WebAssembly.SIMD.int32x4(a[0], a[1], a[2], a[3]);
const simd_b = WebAssembly.SIMD.int32x4(b[0], b[1], b[2], b[3]);

// 调用 WebAssembly 函数进行 SIMD 加法
const result = wasmInstance.exports.add_i32x4(simd_a, simd_b);

// 查看结果
console.log(result); // 输出: Int32x4 {0: 6, 1: 8, 2: 10, 3: 12}
```

在这个例子中，JavaScript 代码创建了两个 `WebAssembly.SIMD.int32x4` 的实例，并将它们传递给 WebAssembly 模块中的 `add_i32x4` 函数。  `v8/src/wasm/turboshaft-graph-interface.cc` 中的代码负责将 WASM 的 `i32x4.add` 操作码转换为 Turboshaft 可以理解和执行的形式。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `decoder`:  一个用于解码 WASM 指令的解码器对象。
* `opcode`: `kExprI32x4Add` (表示 i32x4 的加法操作码)。
* `args`: 一个包含两个 `Value` 对象的数组，分别代表两个 `i32x4` 类型的操作数。假设 `args[0].op` 和 `args[1].op` 是表示这两个 SIMD 值的 Turboshaft 节点。
* `result`: 一个 `Value` 对象，用于存储操作的结果。

**处理过程 (基于代码片段):**

1. 代码会进入 `switch (opcode)` 语句，匹配到 `case kExprI32x4Add:`。
2. `HANDLE_BINARY_OPCODE(I32x4, Add)` 宏会被展开。
3. `result->op` 会被赋值为 `__ Simd128Binop(...)` 的返回值。
4. `__ Simd128Binop` 函数（在 Turboshaft 的其他地方定义）会创建一个新的 `Simd128Binop` 节点，其类型为 `compiler::turboshaft::Simd128BinopOp::Kind::kI32x4Add`，并且将 `args[0].op` 和 `args[1].op` 作为其输入。

**假设输出:**

* `result->op` 将会是一个指向新创建的 `Simd128Binop` 节点的指针。这个节点表示了 i32x4 的加法操作，可以被 Turboshaft 编译器的后续阶段处理。

**用户常见的编程错误举例:**

1. **使用了不支持的 SIMD 特性:**
   ```javascript
   // 假设在不支持 Float16 的环境下
   const a = new Float32Array([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
   const f16_a = WebAssembly.SIMD.float16x8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); // 可能会抛出错误
   ```
   如果 JavaScript 引擎或运行环境不支持 `float16` SIMD 类型，尝试创建 `WebAssembly.SIMD.float16x8` 的实例将会导致错误。这段 C++ 代码中的 `HANDLE_F16X8_BIN_OPTIONAL_OPCODE` 正是为了处理这种情况，在不支持 `float16` 时会采取降级策略。

2. **SIMD 操作数类型不匹配:**
   ```javascript
   const i32_vec = WebAssembly.SIMD.int32x4(1, 2, 3, 4);
   const f32_vec = WebAssembly.SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
   // 尝试将 i32x4 和 f32x4 相加，这在 WASM 中通常是不允许的
   // 对应的 WASM 指令也会在编译阶段或执行阶段报错
   ```
   WebAssembly 对 SIMD 操作的类型有严格的要求。尝试对不同类型的 SIMD 向量执行操作（除非有显式的类型转换）会导致错误。

**总结 (基于提供的代码片段，第 5 部分):**

这段代码（作为 Turboshaft 图接口的一部分）专注于将 WebAssembly 的 **SIMD 相关的操作码** 转换为 Turboshaft 编译器内部图表示。它涵盖了多种 SIMD 操作，包括二元运算、一元运算、移位、测试、splat 和三元运算，并且特别处理了 `float16` 类型的 SIMD 操作，在不支持该特性时会进行降级处理。这部分代码是 V8 引擎支持 WebAssembly SIMD 功能的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
),   \
                        V<compiler::turboshaft::Simd128>::Cast(args[1].op),   \
                        compiler::turboshaft::Simd128BinopOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_BINARY_MANDATORY_OPCODE(HANDLE_BINARY_OPCODE)
#undef HANDLE_BINARY_OPCODE
#define HANDLE_F16X8_BIN_OPTIONAL_OPCODE(kind, extern_ref)                     \
  case kExprF16x8##kind:                                                       \
    if (SupportedOperations::float16()) {                                      \
      result->op = __ Simd128Binop(                                            \
          V<compiler::turboshaft::Simd128>::Cast(args[0].op),                  \
          V<compiler::turboshaft::Simd128>::Cast(args[1].op),                  \
          compiler::turboshaft::Simd128BinopOp::Kind::kF16x8##kind);           \
    } else {                                                                   \
      result->op = CallCStackSlotToStackSlot(args[0].op, args[1].op,           \
                                             ExternalReference::extern_ref(),  \
                                             MemoryRepresentation::Simd128()); \
    }                                                                          \
    break;

      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Add, wasm_f16x8_add)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Sub, wasm_f16x8_sub)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Mul, wasm_f16x8_mul)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Div, wasm_f16x8_div)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Min, wasm_f16x8_min)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Max, wasm_f16x8_max)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Pmin, wasm_f16x8_pmin)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Pmax, wasm_f16x8_pmax)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Eq, wasm_f16x8_eq)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Ne, wasm_f16x8_ne)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Lt, wasm_f16x8_lt)
      HANDLE_F16X8_BIN_OPTIONAL_OPCODE(Le, wasm_f16x8_le)
#undef HANDLE_F16X8_BIN_OPCODE

#define HANDLE_F16X8_INVERSE_COMPARISON(kind, ts_kind, extern_ref)             \
  case kExprF16x8##kind:                                                       \
    if (SupportedOperations::float16()) {                                      \
      result->op = __ Simd128Binop(                                            \
          V<compiler::turboshaft::Simd128>::Cast(args[1].op),                  \
          V<compiler::turboshaft::Simd128>::Cast(args[0].op),                  \
          compiler::turboshaft::Simd128BinopOp::Kind::kF16x8##ts_kind);        \
    } else {                                                                   \
      result->op = CallCStackSlotToStackSlot(args[1].op, args[0].op,           \
                                             ExternalReference::extern_ref(),  \
                                             MemoryRepresentation::Simd128()); \
    }                                                                          \
    break;

      HANDLE_F16X8_INVERSE_COMPARISON(Gt, Lt, wasm_f16x8_lt)
      HANDLE_F16X8_INVERSE_COMPARISON(Ge, Le, wasm_f16x8_le)
#undef HANDLE_F16X8_INVERSE_COMPARISON

#define HANDLE_INVERSE_COMPARISON(wasm_kind, ts_kind)            \
  case kExpr##wasm_kind:                                         \
    result->op = __ Simd128Binop(                                \
        V<compiler::turboshaft::Simd128>::Cast(args[1].op),      \
        V<compiler::turboshaft::Simd128>::Cast(args[0].op),      \
        compiler::turboshaft::Simd128BinopOp::Kind::k##ts_kind); \
    break;

      HANDLE_INVERSE_COMPARISON(I8x16LtS, I8x16GtS)
      HANDLE_INVERSE_COMPARISON(I8x16LtU, I8x16GtU)
      HANDLE_INVERSE_COMPARISON(I8x16LeS, I8x16GeS)
      HANDLE_INVERSE_COMPARISON(I8x16LeU, I8x16GeU)

      HANDLE_INVERSE_COMPARISON(I16x8LtS, I16x8GtS)
      HANDLE_INVERSE_COMPARISON(I16x8LtU, I16x8GtU)
      HANDLE_INVERSE_COMPARISON(I16x8LeS, I16x8GeS)
      HANDLE_INVERSE_COMPARISON(I16x8LeU, I16x8GeU)

      HANDLE_INVERSE_COMPARISON(I32x4LtS, I32x4GtS)
      HANDLE_INVERSE_COMPARISON(I32x4LtU, I32x4GtU)
      HANDLE_INVERSE_COMPARISON(I32x4LeS, I32x4GeS)
      HANDLE_INVERSE_COMPARISON(I32x4LeU, I32x4GeU)

      HANDLE_INVERSE_COMPARISON(I64x2LtS, I64x2GtS)
      HANDLE_INVERSE_COMPARISON(I64x2LeS, I64x2GeS)

      HANDLE_INVERSE_COMPARISON(F32x4Gt, F32x4Lt)
      HANDLE_INVERSE_COMPARISON(F32x4Ge, F32x4Le)
      HANDLE_INVERSE_COMPARISON(F64x2Gt, F64x2Lt)
      HANDLE_INVERSE_COMPARISON(F64x2Ge, F64x2Le)

#undef HANDLE_INVERSE_COMPARISON

#define HANDLE_UNARY_NON_OPTIONAL_OPCODE(kind)                                \
  case kExpr##kind:                                                           \
    result->op =                                                              \
        __ Simd128Unary(V<compiler::turboshaft::Simd128>::Cast(args[0].op),   \
                        compiler::turboshaft::Simd128UnaryOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_UNARY_NON_OPTIONAL_OPCODE(
          HANDLE_UNARY_NON_OPTIONAL_OPCODE)
#undef HANDLE_UNARY_NON_OPTIONAL_OPCODE

#define HANDLE_UNARY_OPTIONAL_OPCODE(kind, feature, external_ref) \
  case kExpr##kind:                                               \
    if (SupportedOperations::feature()) {                         \
      result->op = __ Simd128Unary(                               \
          V<compiler::turboshaft::Simd128>::Cast(args[0].op),     \
          compiler::turboshaft::Simd128UnaryOp::Kind::k##kind);   \
    } else {                                                      \
      result->op = CallCStackSlotToStackSlot(                     \
          args[0].op, ExternalReference::external_ref(),          \
          MemoryRepresentation::Simd128());                       \
    }                                                             \
    break;
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8Abs, float16, wasm_f16x8_abs)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8Neg, float16, wasm_f16x8_neg)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8Sqrt, float16, wasm_f16x8_sqrt)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8Ceil, float16, wasm_f16x8_ceil)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8Floor, float16, wasm_f16x8_floor)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8Trunc, float16, wasm_f16x8_trunc)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8NearestInt, float16,
                                   wasm_f16x8_nearest_int)
      HANDLE_UNARY_OPTIONAL_OPCODE(I16x8SConvertF16x8, float16,
                                   wasm_i16x8_sconvert_f16x8)
      HANDLE_UNARY_OPTIONAL_OPCODE(I16x8UConvertF16x8, float16,
                                   wasm_i16x8_uconvert_f16x8)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8SConvertI16x8, float16,
                                   wasm_f16x8_sconvert_i16x8)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8UConvertI16x8, float16,
                                   wasm_f16x8_uconvert_i16x8)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8DemoteF32x4Zero, float16,
                                   wasm_f16x8_demote_f32x4_zero)
      HANDLE_UNARY_OPTIONAL_OPCODE(F16x8DemoteF64x2Zero,
                                   float64_to_float16_raw_bits,
                                   wasm_f16x8_demote_f64x2_zero)
      HANDLE_UNARY_OPTIONAL_OPCODE(F32x4PromoteLowF16x8, float16,
                                   wasm_f32x4_promote_low_f16x8)
      HANDLE_UNARY_OPTIONAL_OPCODE(F32x4Ceil, float32_round_up, wasm_f32x4_ceil)
      HANDLE_UNARY_OPTIONAL_OPCODE(F32x4Floor, float32_round_down,
                                   wasm_f32x4_floor)
      HANDLE_UNARY_OPTIONAL_OPCODE(F32x4Trunc, float32_round_to_zero,
                                   wasm_f32x4_trunc)
      HANDLE_UNARY_OPTIONAL_OPCODE(F32x4NearestInt, float32_round_ties_even,
                                   wasm_f32x4_nearest_int)
      HANDLE_UNARY_OPTIONAL_OPCODE(F64x2Ceil, float64_round_up, wasm_f64x2_ceil)
      HANDLE_UNARY_OPTIONAL_OPCODE(F64x2Floor, float64_round_down,
                                   wasm_f64x2_floor)
      HANDLE_UNARY_OPTIONAL_OPCODE(F64x2Trunc, float64_round_to_zero,
                                   wasm_f64x2_trunc)
      HANDLE_UNARY_OPTIONAL_OPCODE(F64x2NearestInt, float64_round_ties_even,
                                   wasm_f64x2_nearest_int)
#undef HANDLE_UNARY_OPTIONAL_OPCODE

#define HANDLE_SHIFT_OPCODE(kind)                                             \
  case kExpr##kind:                                                           \
    result->op =                                                              \
        __ Simd128Shift(V<compiler::turboshaft::Simd128>::Cast(args[0].op),   \
                        V<Word32>::Cast(args[1].op),                          \
                        compiler::turboshaft::Simd128ShiftOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_SHIFT_OPCODE(HANDLE_SHIFT_OPCODE)
#undef HANDLE_SHIFT_OPCODE

#define HANDLE_TEST_OPCODE(kind)                                            \
  case kExpr##kind:                                                         \
    result->op =                                                            \
        __ Simd128Test(V<compiler::turboshaft::Simd128>::Cast(args[0].op),  \
                       compiler::turboshaft::Simd128TestOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_TEST_OPCODE(HANDLE_TEST_OPCODE)
#undef HANDLE_TEST_OPCODE

#define HANDLE_SPLAT_OPCODE(kind)                                             \
  case kExpr##kind##Splat:                                                    \
    result->op =                                                              \
        __ Simd128Splat(V<Any>::Cast(args[0].op),                             \
                        compiler::turboshaft::Simd128SplatOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_SPLAT_MANDATORY_OPCODE(HANDLE_SPLAT_OPCODE)
#undef HANDLE_SPLAT_OPCODE
      case kExprF16x8Splat:
        if (SupportedOperations::float16()) {
          result->op = __ Simd128Splat(
              V<Any>::Cast(args[0].op),
              compiler::turboshaft::Simd128SplatOp::Kind::kF16x8);
        } else {
          auto f16 = CallCStackSlotToStackSlot(
              args[0].op, ExternalReference::wasm_float32_to_float16(),
              MemoryRepresentation::Float32(), MemoryRepresentation::Int16());
          result->op = __ Simd128Splat(
              V<Any>::Cast(f16),
              compiler::turboshaft::Simd128SplatOp::Kind::kI16x8);
        }
        break;

// Ternary mask operators put the mask as first input.
#define HANDLE_TERNARY_MASK_OPCODE(kind)                        \
  case kExpr##kind:                                             \
    result->op = __ Simd128Ternary(                             \
        V<compiler::turboshaft::Simd128>::Cast(args[2].op),     \
        V<compiler::turboshaft::Simd128>::Cast(args[0].op),     \
        V<compiler::turboshaft::Simd128>::Cast(args[1].op),     \
        compiler::turboshaft::Simd128TernaryOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_TERNARY_MASK_OPCODE(HANDLE_TERNARY_MASK_OPCODE)
#undef HANDLE_TERNARY_MASK_OPCODE

#define HANDLE_TERNARY_OTHER_OPCODE(kind)                       \
  case kExpr##kind:                                             \
    result->op = __ Simd128Ternary(                             \
        V<compiler::turboshaft::Simd128>::Cast(args[0].op),     \
        V<compiler::turboshaft::Simd128>::Cast(args[1].op),     \
        V<compiler::turboshaft::Simd128>::Cast(args[2].op),     \
        compiler::turboshaft::Simd128TernaryOp::Kind::k##kind); \
    break;
      FOREACH_SIMD_128_TERNARY_OTHER_OPCODE(HANDLE_TERNARY_OTHER_OPCODE)
#undef HANDLE_TERNARY_OTHER_OPCODE

#define HANDLE_F16X8_TERN_OPCODE(kind, extern_ref)                          \
  case kExpr##kind:                                                         \
    if (SupportedOperations::float16()) {                                   \
      result->op = __ Simd128Ternary(                                       \
          V<compiler::turboshaft::Simd128>::Cast(args[0].op),               \
          V<compiler::turboshaft::Simd128>::Cast(args[1].op),               \
          V<compiler::turboshaft::Simd128>::Cast(args[2].op),               \
          compiler::turboshaft::Simd128TernaryOp::Kind::k##kind);           \
    } else {                                                                \
      result->op = CallCStackSlotToStackSlot(                               \
          ExternalReference::extern_ref(), MemoryRepresentation::Simd128(), \
          {{args[0].op, MemoryRepresentation::Simd128()},                   \
           {args[1].op, MemoryRepresentation::Simd128()},                   \
           {args[2].op, MemoryRepresentation::Simd128()}});                 \
    }                                                                       \
    break;
        HANDLE_F16X8_TERN_OPCODE(F16x8Qfma, wasm_f16x8_qfma)
        HANDLE_F16X8_TERN_OPCODE(F16x8Qfms, wasm_f16x8_qfms)
#undef HANDLE_F16X8_TERN_OPCODE
      default:
        UNREACHABLE();
    }
  }

  void SimdLaneOp(FullDecoder* decoder, WasmOpcode opcode,
                  const SimdLaneImmediate& imm,
                  base::Vector<const Value> inputs, Value* result) {
    using compiler::turboshaft::Simd128ExtractLaneOp;
    using compiler::turboshaft::Simd128ReplaceLaneOp;
    using Simd128 = compiler::turboshaft::Simd128;
    V<Simd128> input_val = V<Simd128>::Cast(inputs[0].op);
    switch (opcode) {
      case kExprI8x16ExtractLaneS:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kI8x16S, imm.lane);
        break;
      case kExprI8x16ExtractLaneU:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kI8x16U, imm.lane);
        break;
      case kExprI16x8ExtractLaneS:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kI16x8S, imm.lane);
        break;
      case kExprI16x8ExtractLaneU:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kI16x8U, imm.lane);
        break;
      case kExprI32x4ExtractLane:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kI32x4, imm.lane);
        break;
      case kExprI64x2ExtractLane:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kI64x2, imm.lane);
        break;
      case kExprF16x8ExtractLane:
        if (SupportedOperations::float16()) {
          result->op = __ Simd128ExtractLane(
              input_val, Simd128ExtractLaneOp::Kind::kF16x8, imm.lane);
        } else {
          auto f16 = __ Simd128ExtractLane(
              input_val, Simd128ExtractLaneOp::Kind::kI16x8S, imm.lane);
          result->op = CallCStackSlotToStackSlot(
              f16, ExternalReference::wasm_float16_to_float32(),
              MemoryRepresentation::Int16(), MemoryRepresentation::Float32());
        }
        break;
      case kExprF32x4ExtractLane:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kF32x4, imm.lane);
        break;
      case kExprF64x2ExtractLane:
        result->op = __ Simd128ExtractLane(
            input_val, Simd128ExtractLaneOp::Kind::kF64x2, imm.lane);
        break;
      case kExprI8x16ReplaceLane:
        result->op =
            __ Simd128ReplaceLane(input_val, V<Any>::Cast(inputs[1].op),
                                  Simd128ReplaceLaneOp::Kind::kI8x16, imm.lane);
        break;
      case kExprI16x8ReplaceLane:
        result->op =
            __ Simd128ReplaceLane(input_val, V<Simd128>::Cast(inputs[1].op),
                                  Simd128ReplaceLaneOp::Kind::kI16x8, imm.lane);
        break;
      case kExprI32x4ReplaceLane:
        result->op =
            __ Simd128ReplaceLane(input_val, V<Any>::Cast(inputs[1].op),
                                  Simd128ReplaceLaneOp::Kind::kI32x4, imm.lane);
        break;
      case kExprI64x2ReplaceLane:
        result->op =
            __ Simd128ReplaceLane(input_val, V<Any>::Cast(inputs[1].op),
                                  Simd128ReplaceLaneOp::Kind::kI64x2, imm.lane);
        break;
      case kExprF16x8ReplaceLane:
        if (SupportedOperations::float16()) {
          result->op = __ Simd128ReplaceLane(
              input_val, V<Any>::Cast(inputs[1].op),
              Simd128ReplaceLaneOp::Kind::kF16x8, imm.lane);
        } else {
          auto f16 = CallCStackSlotToStackSlot(
              inputs[1].op, ExternalReference::wasm_float32_to_float16(),
              MemoryRepresentation::Float32(), MemoryRepresentation::Int16());
          result->op = __ Simd128ReplaceLane(input_val, V<Any>::Cast(f16),
                                             Simd128ReplaceLaneOp::Kind::kI16x8,
                                             imm.lane);
        }
        break;
      case kExprF32x4ReplaceLane:
        result->op =
            __ Simd128ReplaceLane(input_val, V<Any>::Cast(inputs[1].op),
                                  Simd128ReplaceLaneOp::Kind::kF32x4, imm.lane);
        break;
      case kExprF64x2ReplaceLane:
        result->op =
            __ Simd128ReplaceLane(input_val, V<Any>::Cast(inputs[1].op),
                                  Simd128ReplaceLaneOp::Kind::kF64x2, imm.lane);
        break;
      default:
        UNREACHABLE();
    }
  }

  void Simd8x16ShuffleOp(FullDecoder* decoder, const Simd128Immediate& imm,
                         const Value& input0, const Value& input1,
                         Value* result) {
    result->op = __ Simd128Shuffle(
        V<compiler::turboshaft::Simd128>::Cast(input0.op),
        V<compiler::turboshaft::Simd128>::Cast(input1.op), imm.value);
  }

  void Try(FullDecoder* decoder, Control* block) {
    block->false_or_loop_or_catch_block = NewBlockWithPhis(decoder, nullptr);
    block->merge_block = NewBlockWithPhis(decoder, block->br_merge());
  }

  void Throw(FullDecoder* decoder, const TagIndexImmediate& imm,
             const Value arg_values[]) {
    size_t count = imm.tag->sig->parameter_count();
    SmallZoneVector<OpIndex, 16> values(count, decoder->zone_);
    for (size_t index = 0; index < count; index++) {
      values[index] = arg_values[index].op;
    }

    uint32_t encoded_size = WasmExceptionPackage::GetEncodedSize(imm.tag);

    V<FixedArray> values_array = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmAllocateFixedArray>(
        decoder, {__ IntPtrConstant(encoded_size)});
    uint32_t index = 0;
    const wasm::WasmTagSig* sig = imm.tag->sig;

    // Encode the exception values in {values_array}.
    for (size_t i = 0; i < count; i++) {
      OpIndex value = values[i];
      switch (sig->GetParam(i).kind()) {
        case kF32:
          value = __ BitcastFloat32ToWord32(value);
          [[fallthrough]];
        case kI32:
          BuildEncodeException32BitValue(values_array, index, value);
          // We need 2 Smis to encode a 32-bit value.
          index += 2;
          break;
        case kF64:
          value = __ BitcastFloat64ToWord64(value);
          [[fallthrough]];
        case kI64: {
          OpIndex upper_half =
              __ TruncateWord64ToWord32(__ Word64ShiftRightLogical(value, 32));
          BuildEncodeException32BitValue(values_array, index, upper_half);
          index += 2;
          OpIndex lower_half = __ TruncateWord64ToWord32(value);
          BuildEncodeException32BitValue(values_array, index, lower_half);
          index += 2;
          break;
        }
        case wasm::kRef:
        case wasm::kRefNull:
        case wasm::kRtt:
          __ StoreFixedArrayElement(values_array, index, value,
                                    compiler::kFullWriteBarrier);
          index++;
          break;
        case kS128: {
          using Simd128 = compiler::turboshaft::Simd128;
          V<Simd128> value_s128 = V<Simd128>::Cast(value);
          using Kind = compiler::turboshaft::Simd128ExtractLaneOp::Kind;
          BuildEncodeException32BitValue(values_array, index,
                                         V<Word32>::Cast(__ Simd128ExtractLane(
                                             value_s128, Kind::kI32x4, 0)));
          index += 2;
          BuildEncodeException32BitValue(values_array, index,
                                         V<Word32>::Cast(__ Simd128ExtractLane(
                                             value_s128, Kind::kI32x4, 1)));
          index += 2;
          BuildEncodeException32BitValue(values_array, index,
                                         V<Word32>::Cast(__ Simd128ExtractLane(
                                             value_s128, Kind::kI32x4, 2)));
          index += 2;
          BuildEncodeException32BitValue(values_array, index,
                                         V<Word32>::Cast(__ Simd128ExtractLane(
                                             value_s128, Kind::kI32x4, 3)));
          index += 2;
          break;
        }
        case kI8:
        case kI16:
        case kF16:
        case kVoid:
        case kTop:
        case kBottom:
          UNREACHABLE();
      }
    }

    // TODO(14616): Support shared tags.
    V<FixedArray> instance_tags =
        LOAD_IMMUTABLE_INSTANCE_FIELD(trusted_instance_data(false), TagsTable,
                                      MemoryRepresentation::TaggedPointer());
    auto tag = V<WasmTagObject>::Cast(
        __ LoadFixedArrayElement(instance_tags, imm.index));

    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmThrow>(
        decoder, {tag, values_array}, CheckForException::kCatchInThisFrame);
    __ Unreachable();
  }

  void Rethrow(FullDecoder* decoder, Control* block) {
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmRethrow>(
        decoder, {block->exception}, CheckForException::kCatchInThisFrame);
    __ Unreachable();
  }

  void CatchException(FullDecoder* decoder, const TagIndexImmediate& imm,
                      Control* block, base::Vector<Value> values) {
    if (deopts_enabled_) {
      if (v8_flags.trace_wasm_inlining) {
        PrintF(
            "[function %d%s: Disabling deoptimizations for speculative "
            "inlineing due to legacy exception handling usage]\n",
            func_index_, mode_ == kRegular ? "" : " (inlined)");
      }
      deopts_enabled_ = false;
    }

    BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                             nullptr, &block->exception);
    V<NativeContext> native_context = instance_cache_.native_context();
    V<WasmTagObject> caught_tag = V<WasmTagObject>::Cast(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmGetOwnProperty>(
            decoder, native_context,
            {block->exception, LOAD_ROOT(wasm_exception_tag_symbol)}));
    // TODO(14616): Support shared tags.
    V<FixedArray> instance_tags =
        LOAD_IMMUTABLE_INSTANCE_FIELD(trusted_instance_data(false), TagsTable,
                                      MemoryRepresentation::TaggedPointer());
    auto expected_tag = V<WasmTagObject>::Cast(
        __ LoadFixedArrayElement(instance_tags, imm.index));
    TSBlock* if_catch = __ NewBlock();
    TSBlock* if_no_catch = NewBlockWithPhis(decoder, nullptr);
    SetupControlFlowEdge(decoder, if_no_catch);

    // If the tags don't match we continue with the next tag by setting the
    // no-catch environment as the new {block->false_or_loop_or_catch_block}
    // here.
    block->false_or_loop_or_catch_block = if_no_catch;

    if (imm.tag->sig->parameter_count() == 1 &&
        imm.tag->sig->GetParam(0).is_reference_to(HeapType::kExtern)) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref or (ref extern), otherwise
      // we know statically that it cannot be the JSTag.
      V<Word32> caught_tag_undefined =
          __ TaggedEqual(caught_tag, LOAD_ROOT(UndefinedValue));
      Label<Object> if_catch(&asm_);
      Label<> no_catch_merge(&asm_);

      IF (UNLIKELY(caught_tag_undefined)) {
        V<Object> tag_object = __ Load(
            native_context, LoadOp::Kind::TaggedBase(),
            MemoryRepresentation::TaggedPointer(),
            NativeContext::OffsetOfElementAt(Context::WASM_JS_TAG_INDEX));
        V<Object> js_tag = __ Load(tag_object, LoadOp::Kind::TaggedBase(),
                                   MemoryRepresentation::TaggedPointer(),
                                   WasmTagObject::kTagOffset);
        GOTO_IF(__ TaggedEqual(expected_tag, js_tag), if_catch,
                block->exception);
        GOTO(no_catch_merge);
      } ELSE {
        IF (__ TaggedEqual(caught_tag, expected_tag)) {
          UnpackWasmException(decoder, block->exception, values);
          GOTO(if_catch, values[0].op);
        }
        GOTO(no_catch_merge);
      }

      BIND(no_catch_merge);
      __ Goto(if_no_catch);

      BIND(if_catch, caught_exception);
      // The first unpacked value is the exception itself in the case of a JS
      // exception.
      values[0].op = caught_exception;
    } else {
      __ Branch(ConditionWithHint(__ TaggedEqual(caught_tag, expected_tag)),
                if_catch, if_no_catch);
      __ Bind(if_catch);
      UnpackWasmException(decoder, block->exception, values);
    }
  }

  void Delegate(FullDecoder* decoder, uint32_t depth, Control* block) {
    BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                             nullptr, &block->exception);
    if (depth == decoder->control_depth() - 1) {
      if (mode_ == kInlinedWithCatch) {
        if (block->exception.valid()) {
          return_phis_->AddIncomingException(block->exception);
        }
        __ Goto(return_catch_block_);
      } else {
        // We just throw to the caller, no need to handle the exception in this
        // frame.
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmRethrow>(
            decoder, {block->exception});
        __ Unreachable();
      }
    } else {
      DCHECK(decoder->control_at(depth)->is_try());
      TSBlock* target_catch =
          decoder->control_at(depth)->false_or_loop_or_catch_block;
      SetupControlFlowEdge(decoder, target_catch, 0, block->exception);
      __ Goto(target_catch);
    }
  }

  void CatchAll(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    DCHECK_EQ(decoder->control_at(0), block);

    if (deopts_enabled_) {
      if (v8_flags.trace_wasm_inlining) {
        // TODO(42204618): Would it be worthwhile to add support for this?
        // The difficulty is the handling of the exception which is handled as a
        // value on the value stack in Liftoff but handled very differently in
        // Turboshaft (and it would need to be passed on in the FrameState).
        PrintF(
            "[function %d%s: Disabling deoptimizations for speculative "
            "inlineing due to legacy exception handling usage]\n",
            func_index_, mode_ == kRegular ? "" : " (inlined)");
      }
      deopts_enabled_ = false;
    }

    BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                             nullptr, &block->exception);
  }

  void TryTable(FullDecoder* decoder, Control* block) { Try(decoder, block); }

  void CatchCase(FullDecoder* decoder, Control* block,
                 const CatchCase& catch_case, base::Vector<Value> values) {
    // If this is the first catch case, {block->false_or_loop_or_catch_block} is
    // the block that was created on block entry, and is where all throwing
    // instructions in the try-table jump to if they throw.
    // Otherwise, {block->false_or_loop_or_catch_block} has been overwritten by
    // the previous handler, and is where we jump to if we did not catch the
    // exception yet.
    BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                             nullptr, &block->exception);
    if (catch_case.kind == kCatchAll || catch_case.kind == kCatchAllRef) {
      if (catch_case.kind == kCatchAllRef) {
        DCHECK_EQ(values.size(), 1);
        values.last().op = block->exception;
      }
      BrOrRet(decoder, catch_case.br_imm.depth);
      return;
    }
    V<NativeContext> native_context = instance_cache_.native_context();
    V<WasmTagObject> caught_tag = V<WasmTagObject>::Cast(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmGetOwnProperty>(
            decoder, native_context,
            {block->exception, LOAD_ROOT(wasm_exception_tag_symbol)}));
    // TODO(14616): Support shared tags.
    V<FixedArray> instance_tags =
        LOAD_IMMUTABLE_INSTANCE_FIELD(trusted_instance_data(false), TagsTable,
                                      MemoryRepresentation::TaggedPointer());
    auto expected_tag = V<WasmTagObject>::Cast(__ LoadFixedArrayElement(
        instance_tags, catch_case.maybe_tag.tag_imm.index));
    TSBlock* if_catch = __ NewBlock();
    TSBlock* if_no_catch = NewBlockWithPhis(decoder, nullptr);
    SetupControlFlowEdge(decoder, if_no_catch);

    // If the tags don't match we continue with the next tag by setting the
    // no-catch environment as the new {block->false_or_loop_or_catch_block}
    // here.
    block->false_or_loop_or_catch_block = if_no_catch;

    if (catch_case.maybe_tag.tag_imm.tag->sig->parameter_count() == 1 &&
        catch_case.maybe_tag.tag_imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise
      // we know statically that it cannot be the JSTag.
      V<Word32> caught_tag_undefined =
          __ TaggedEqual(caught_tag, LOAD_ROOT(UndefinedValue));
      Label<Object> if_catch(&asm_);
      Label<> no_catch_merge(&asm_);

      IF (UNLIKELY(caught_tag_undefined)) {
        V<Object> tag_object = __ Load(
            native_context, LoadOp::Kind::TaggedBase(),
            MemoryRepresentation::TaggedPointer(),
            NativeContext::OffsetOfElementAt(Context::WASM_JS_TAG_INDEX));
        V<Object> js_tag = __ Load(tag_object, LoadOp::Kind::TaggedBase(),
                                   MemoryRepresentation::TaggedPointer(),
                                   WasmTagObject::kTagOffset);
        GOTO_IF(__ TaggedEqual(expected_tag, js_tag), if_catch,
                block->exception);
        GOTO(no_catch_merge);
      } ELSE {
        IF (__ TaggedEqual(caught_tag, expected_tag)) {
          if (catch_case.kind == kCatchRef) {
            UnpackWasmException(decoder, block->exception,
                                values.SubVector(0, values.size() - 1));
            values.last().op = block->exception;
          } else {
            UnpackWasmException(decoder, block->exception, values);
          }
          GOTO(if_catch, values[0].op);
        }
        GOTO(no_catch_merge);
      }

      BIND(no_catch_merge);
      __ Goto(if_no_catch);

      BIND(if_catch, caught_exception);
      // The first unpacked value is the exception itself in the case of a JS
      // exception.
      values[0].op = caught_exception;
    } else {
      __ Branch(ConditionWithHint(__ TaggedEqual(caught_tag, expected_tag)),
                if_catch, if_no_catch);
      __ Bind(if_catch);
      if (catch_case.kind == kCatchRef) {
        UnpackWasmException(decoder, block->exception,
                            values.SubVector(0, values.size() - 1));
        values.last().op = block->exception;
      } else {
        UnpackWasmException(decoder, block->exception, values);
      }
    }

    BrOrRet(decoder, catch_case.br_imm.depth);

    bool is_last = &catch_case == &block->catch_cases.last();
    if (is_last && !decoder->HasCatchAll(block)) {
      BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                               nullptr, &block->exception);
      ThrowRef(decoder, block->exception);
    }
  }

  void ThrowRef(FullDecoder* decoder, Value* value) {
    ThrowRef(decoder, value->op);
  }

  void AtomicNotify(FullDecoder* decoder, const MemoryAccessImmediate& imm,
                    OpIndex index, OpIndex num_waiters_to_wake, Value* result) {
    V<WordPtr> converted_index;
```