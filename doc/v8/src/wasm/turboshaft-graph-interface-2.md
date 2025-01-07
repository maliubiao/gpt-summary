Response: The user wants me to summarize the functionality of the C++ source code file `v8/src/wasm/turboshaft-graph-interface.cc`, specifically the part provided in the prompt (part 3 of 6). I also need to illustrate its connection to JavaScript with an example.

**Plan:**

1. **Analyze the provided C++ code:**  Identify the main purpose of the code block by examining the function calls and logic. The code seems to be handling various WebAssembly (Wasm) SIMD (Single Instruction, Multiple Data) operations. It defines how these operations are translated into the Turboshaft intermediate representation (IR) used by the V8 compiler. It also includes logic to handle cases where certain features (like float16) are not supported, falling back to C++ runtime calls.
2. **Identify the connection to JavaScript:**  Wasm modules are executed within a JavaScript environment in browsers and Node.js. The SIMD operations defined in this C++ code are directly related to the Wasm SIMD proposal, which allows performing parallel operations on vector data. JavaScript provides an API to interact with Wasm modules, including those utilizing SIMD.
3. **Construct a JavaScript example:**  Create a simple JavaScript snippet that demonstrates the use of Wasm SIMD instructions, corresponding to the operations handled in the C++ code. Focus on a few representative examples like binary operations (addition, subtraction), unary operations (negation), and lane operations (extract, replace).
4. **Summarize the functionality:**  Describe the role of this code in bridging the gap between Wasm SIMD instructions and the V8 Turboshaft compiler. Highlight the conditional logic for feature support and the fallback mechanism.
5. **Explain the JavaScript example:** Clearly articulate how the JavaScript code interacts with the Wasm SIMD functionality implemented in the C++ code.
这是 `v8/src/wasm/turboshaft-graph-interface.cc` 文件的第三部分，主要负责将 WebAssembly (Wasm) 的 SIMD (Single Instruction, Multiple Data) 操作转换为 Turboshaft 图形表示。Turboshaft 是 V8 引擎中用于编译 WebAssembly 代码的下一代编译器。

**具体功能归纳:**

1. **处理 SIMD 二元操作:**  这部分代码定义了如何将各种 Wasm SIMD 二元操作符（例如加法、减法、乘法、除法、比较等）转换为 Turboshaft 中的 `Simd128Binop` 节点。
2. **处理可选的 float16 SIMD 操作:** 对于一些可选的 `float16` 类型的 SIMD 二元操作，代码会检查当前环境是否支持 `float16` 功能。如果支持，则直接生成 `Simd128Binop` 节点；否则，会生成一个调用 C++ 运行时函数的 `CallCStackSlotToStackSlot` 节点来模拟该操作。
3. **处理 SIMD 比较操作的反转:**  对于某些比较操作（例如 `I8x16LtS`），如果直接使用，则会转换为相应的 Turboshaft 操作；而对于其反向比较（例如 `I8x16GtS`），则会交换操作数的顺序，并使用反向的 Turboshaft 操作符（例如 `kI8x16GtS` 对应 `kI8x16LtS`）。
4. **处理 SIMD 一元操作:**  这部分代码定义了如何将 Wasm SIMD 一元操作符（例如绝对值、取反、平方根等）转换为 Turboshaft 中的 `Simd128Unary` 节点。
5. **处理可选的 float16 SIMD 一元操作:** 类似于二元操作，对于可选的 `float16` 类型的 SIMD 一元操作，会根据环境是否支持 `float16` 特性来决定是生成 `Simd128Unary` 节点还是调用 C++ 运行时函数。
6. **处理 SIMD 移位操作:** 定义了如何将 SIMD 移位操作符（例如左移、右移）转换为 Turboshaft 中的 `Simd128Shift` 节点。
7. **处理 SIMD 测试操作:** 定义了如何将 SIMD 测试操作符（例如检查所有位是否为零或非零）转换为 Turboshaft 中的 `Simd128Test` 节点。
8. **处理 SIMD Splat 操作:**  定义了如何将 SIMD Splat 操作（将一个标量值复制到 SIMD 向量的所有通道）转换为 Turboshaft 中的 `Simd128Splat` 节点。对于 `f16x8.splat`，如果不支持 `float16`，则会先将 `float32` 转换为 `float16`，然后再进行 Splat 操作。
9. **处理 SIMD 三元操作:** 定义了如何将 SIMD 三元操作符（例如 `vselect`）转换为 Turboshaft 中的 `Simd128Ternary` 节点。
10. **处理 float16 SIMD 三元操作:** 类似于之前的处理方式，对于 `float16` 类型的 SIMD 三元操作，会根据环境支持情况选择直接生成 Turboshaft 节点还是调用 C++ 运行时函数。

**与 JavaScript 的关系以及示例:**

这段 C++ 代码的功能是为 V8 引擎的 Turboshaft 编译器提供将 Wasm SIMD 指令转换为其内部表示的能力。当 JavaScript 代码执行一个使用了 Wasm SIMD 功能的 Wasm 模块时，V8 引擎会调用这里的代码来将这些 SIMD 指令编译成高效的机器码。

**JavaScript 示例:**

假设我们有一个包含以下 Wasm 代码的模块（以 WAT 格式表示）：

```wat
(module
  (memory (export "memory") 1)
  (func (export "add_vectors") (param $a v128) (param $b v128) (result v128)
    local.get $a
    local.get $b
    f32x4.add
  )
)
```

这个 Wasm 模块导出一个名为 `add_vectors` 的函数，它接收两个 `v128` 类型的参数（代表 SIMD 向量），并将它们相加后返回结果。

在 JavaScript 中，我们可以加载并使用这个 Wasm 模块：

```javascript
const wasmCode = await fetch('your_wasm_module.wasm'); // 假设你的 Wasm 模块文件名为 your_wasm_module.wasm
const wasmArrayBuffer = await wasmCode.arrayBuffer();
const wasmModule = await WebAssembly.compile(wasmArrayBuffer);
const wasmInstance = await WebAssembly.instantiate(wasmModule);

const a = new Float32Array([1, 2, 3, 4]);
const b = new Float32Array([5, 6, 7, 8]);

// 将 JavaScript 的 Float32Array 转换为 WebAssembly 的 v128 类型
const a_v128 = new Uint8Array(a.buffer);
const b_v128 = new Uint8Array(b.buffer);

// 调用 Wasm 模块中的 add_vectors 函数
const result_v128_buffer = wasmInstance.exports.add_vectors(a_v128, b_v128);

// 将 WebAssembly 的 v128 类型的结果转换回 JavaScript 的 Float32Array
const result_array = new Float32Array(result_v128_buffer.buffer);

console.log(result_array); // 输出: Float32Array [6, 8, 10, 12]
```

**解释:**

1. JavaScript 代码首先加载并实例化了 Wasm 模块。
2. 它创建了两个 JavaScript 的 `Float32Array`，代表要相加的向量数据。
3. 这些 `Float32Array` 的 `buffer` 被转换为 `Uint8Array`，因为 Wasm 的 `v128` 类型在 JavaScript 中通常通过 `Uint8Array` 的 `buffer` 来传递。
4. 当 JavaScript 调用 `wasmInstance.exports.add_vectors(a_v128, b_v128)` 时，V8 引擎会执行 Wasm 模块中的 `f32x4.add` 指令。
5. 在编译阶段，Turboshaft 编译器会使用 `v8/src/wasm/turboshaft-graph-interface.cc` 中相应的代码（在这个例子中，会匹配到处理 `kExprF32x4Add` 的部分）将 `f32x4.add` 指令转换为 Turboshaft 的 `Simd128Binop` 节点。
6. Turboshaft 随后会将这个节点编译成高效的机器码，以便 CPU 可以执行 SIMD 加法操作。
7. 最终，Wasm 函数返回的 `v128` 结果被转换回 JavaScript 的 `Float32Array`。

总而言之，`v8/src/wasm/turboshaft-graph-interface.cc` 的这部分代码是 V8 引擎将 Wasm SIMD 功能转化为底层可执行代码的关键桥梁，使得 JavaScript 可以有效地利用 WebAssembly 提供的 SIMD 并行计算能力。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
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
    compiler::BoundsCheckResult bounds_check_result;
    std::tie(converted_index, bounds_check_result) = BoundsCheckMem(
        imm.memory, MemoryRepresentation::Int32(), index, imm.offset,
        compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
        compiler::AlignmentCheck::kYes);

    OpIndex effective_offset = __ WordPtrAdd(converted_index, imm.offset);
    OpIndex addr = __ WordPtrAdd(MemStart(imm.mem_index), effective_offset);

    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32());
    result->op = CallC(&sig, ExternalReference::wasm_atomic_notify(),
                       {addr, num_waiters_to_wake});
  }

  void AtomicWait(FullDecoder* decoder, WasmOpcode opcode,
                  const MemoryAccessImmediate& imm, OpIndex index,
                  OpIndex expected, V<Word64> timeout, Value* result) {
    constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
    V<WordPtr> converted_index;
    compiler::BoundsCheckResult bounds_check_result;
    std::tie(converted_index, bounds_check_result) = BoundsCheckMem(
        imm.memory,
        opcode == kExprI32AtomicWait ? MemoryRepresentation::Int32()
                                     : MemoryRepresentation::Int64(),
        index, imm.offset, compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
        compiler::AlignmentCheck::kYes);

    OpIndex effective_offset = __ WordPtrAdd(converted_index, imm.offset);
    V<BigInt> bigint_timeout = BuildChangeInt64ToBigInt(timeout, kStubMode);

    if (opcode == kExprI32AtomicWait) {
      result->op =
          CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmI32AtomicWait>(
              decoder, {__ Word32Constant(imm.memory->index), effective_offset,
                        expected, bigint_timeout});
      return;
    }
    DCHECK_EQ(opcode, kExprI64AtomicWait);
    V<BigInt> bigint_expected = BuildChangeInt64ToBigInt(expected, kStubMode);
    result->op =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmI64AtomicWait>(
            decoder, {__ Word32Constant(imm.memory->index), effective_offset,
                      bigint_expected, bigint_timeout});
  }

  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    if (opcode == WasmOpcode::kExprAtomicNotify) {
      return AtomicNotify(decoder, imm, args[0].op, args[1].op, result);
    }
    if (opcode == WasmOpcode::kExprI32AtomicWait ||
        opcode == WasmOpcode::kExprI64AtomicWait) {
      return AtomicWait(decoder, opcode, imm, args[0].op, args[1].op,
                        args[2].op, result);
    }
    using Binop = compiler::turboshaft::AtomicRMWOp::BinOp;
    enum OpType { kBinop, kLoad, kStore };
    struct AtomicOpInfo {
      OpType op_type;
      // Initialize with a default value, to allow constexpr constructors.
      Binop bin_op = Binop::kAdd;
      RegisterRepresentation in_out_rep;
      MemoryRepresentation memory_rep;

      constexpr AtomicOpInfo(Binop bin_op, RegisterRepresentation in_out_rep,
                             MemoryRepresentation memory_rep)
          : op_type(kBinop),
            bin_op(bin_op),
            in_out_rep(in_out_rep),
            memory_rep(memory_rep) {}

      constexpr AtomicOpInfo(OpType op_type, RegisterRepresentation in_out_rep,
                             MemoryRepresentation memory_rep)
          : op_type(op_type), in_out_rep(in_out_rep), memory_rep(memory_rep) {}

      static constexpr AtomicOpInfo Get(wasm::WasmOpcode opcode) {
        switch (opcode) {
#define CASE_BINOP(OPCODE, BINOP, RESULT, INPUT)                           \
  case WasmOpcode::kExpr##OPCODE:                                          \
    return AtomicOpInfo(Binop::k##BINOP, RegisterRepresentation::RESULT(), \
                        MemoryRepresentation::INPUT());
#define RMW_OPERATION(V)                                          \
  V(I32AtomicAdd, Add, Word32, Uint32)                            \
  V(I32AtomicAdd8U, Add, Word32, Uint8)                           \
  V(I32AtomicAdd16U, Add, Word32, Uint16)                         \
  V(I32AtomicSub, Sub, Word32, Uint32)                            \
  V(I32AtomicSub8U, Sub, Word32, Uint8)                           \
  V(I32AtomicSub16U, Sub, Word32, Uint16)                         \
  V(I32AtomicAnd, And, Word32, Uint32)                            \
  V(I32AtomicAnd8U, And, Word32, Uint8)                           \
  V(I32AtomicAnd16U, And, Word32, Uint16)                         \
  V(I32AtomicOr, Or, Word32, Uint32)                              \
  V(I32AtomicOr8U, Or, Word32, Uint8)                             \
  V(I32AtomicOr16U, Or, Word32, Uint16)                           \
  V(I32AtomicXor, Xor, Word32, Uint32)                            \
  V(I32AtomicXor8U, Xor, Word32, Uint8)                           \
  V(I32AtomicXor16U, Xor, Word32, Uint16)                         \
  V(I32AtomicExchange, Exchange, Word32, Uint32)                  \
  V(I32AtomicExchange8U, Exchange, Word32, Uint8)                 \
  V(I32AtomicExchange16U, Exchange, Word32, Uint16)               \
  V(I32AtomicCompareExchange, CompareExchange, Word32, Uint32)    \
  V(I32AtomicCompareExchange8U, CompareExchange, Word32, Uint8)   \
  V(I32AtomicCompareExchange16U, CompareExchange, Word32, Uint16) \
  V(I64AtomicAdd, Add, Word64, Uint64)                            \
  V(I64AtomicAdd8U, Add, Word64, Uint8)                           \
  V(I64AtomicAdd16U, Add, Word64, Uint16)                         \
  V(I64AtomicAdd32U, Add, Word64, Uint32)                         \
  V(I64AtomicSub, Sub, Word64, Uint64)                            \
  V(I64AtomicSub8U, Sub, Word64, Uint8)                           \
  V(I64AtomicSub16U, Sub, Word64, Uint16)                         \
  V(I64AtomicSub32U, Sub, Word64, Uint32)                         \
  V(I64AtomicAnd, And, Word64, Uint64)                            \
  V(I64AtomicAnd8U, And, Word64, Uint8)                           \
  V(I64AtomicAnd16U, And, Word64, Uint16)                         \
  V(I64AtomicAnd32U, And, Word64, Uint32)                         \
  V(I64AtomicOr, Or, Word64, Uint64)                              \
  V(I64AtomicOr8U, Or, Word64, Uint8)                             \
  V(I64AtomicOr16U, Or, Word64, Uint16)                           \
  V(I64AtomicOr32U, Or, Word64, Uint32)                           \
  V(I64AtomicXor, Xor, Word64, Uint64)                            \
  V(I64AtomicXor8U, Xor, Word64, Uint8)                           \
  V(I64AtomicXor16U, Xor, Word64, Uint16)                         \
  V(I64AtomicXor32U, Xor, Word64, Uint32)                         \
  V(I64AtomicExchange, Exchange, Word64, Uint64)                  \
  V(I64AtomicExchange8U, Exchange, Word64, Uint8)                 \
  V(I64AtomicExchange16U, Exchange, Word64, Uint16)               \
  V(I64AtomicExchange32U, Exchange, Word64, Uint32)               \
  V(I64AtomicCompareExchange, CompareExchange, Word64, Uint64)    \
  V(I64AtomicCompareExchange8U, CompareExchange, Word64, Uint8)   \
  V(I64AtomicCompareExchange16U, CompareExchange, Word64, Uint16) \
  V(I64AtomicCompareExchange32U, CompareExchange, Word64, Uint32)

          RMW_OPERATION(CASE_BINOP)
#undef RMW_OPERATION
#undef CASE
#define CASE_LOAD(OPCODE, RESULT, INPUT)                         \
  case WasmOpcode::kExpr##OPCODE:                                \
    return AtomicOpInfo(kLoad, RegisterRepresentation::RESULT(), \
                        MemoryRepresentation::INPUT());
#define LOAD_OPERATION(V)             \
  V(I32AtomicLoad, Word32, Uint32)    \
  V(I32AtomicLoad16U, Word32, Uint16) \
  V(I32AtomicLoad8U, Word32, Uint8)   \
  V(I64AtomicLoad, Word64, Uint64)    \
  V(I64AtomicLoad32U, Word64, Uint32) \
  V(I64AtomicLoad16U, Word64, Uint16) \
  V(I64AtomicLoad8U, Word64, Uint8)
          LOAD_OPERATION(CASE_LOAD)
#undef LOAD_OPERATION
#undef CASE_LOAD
#define CASE_STORE(OPCODE, INPUT, OUTPUT)                        \
  case WasmOpcode::kExpr##OPCODE:                                \
    return AtomicOpInfo(kStore, RegisterRepresentation::INPUT(), \
                        MemoryRepresentation::OUTPUT());
#define STORE_OPERATION(V)             \
  V(I32AtomicStore, Word32, Uint32)    \
  V(I32AtomicStore16U, Word32, Uint16) \
  V(I32AtomicStore8U, Word32, Uint8)   \
  V(I64AtomicStore, Word64, Uint64)    \
  V(I64AtomicStore32U, Word64, Uint32) \
  V(I64AtomicStore16U, Word64, Uint16) \
  V(I64AtomicStore8U, Word64, Uint8)
          STORE_OPERATION(CASE_STORE)
#undef STORE_OPERATION_OPERATION
#undef CASE_STORE
          default:
            UNREACHABLE();
        }
      }
    };

    AtomicOpInfo info = AtomicOpInfo::Get(opcode);
    V<WordPtr> index;
    compiler::BoundsCheckResult bounds_check_result;
    std::tie(index, bounds_check_result) =
        BoundsCheckMem(imm.memory, info.memory_rep, args[0].op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kYes);
    // MemoryAccessKind::kUnaligned is impossible due to explicit aligment
    // check.
    MemoryAccessKind access_kind =
        bounds_check_result == compiler::BoundsCheckResult::kTrapHandler
            ? MemoryAccessKind::kProtectedByTrapHandler
            : MemoryAccessKind::kNormal;

    if (info.op_type == kBinop) {
      if (info.bin_op == Binop::kCompareExchange) {
        result->op = __ AtomicCompareExchange(
            MemBuffer(imm.memory->index, imm.offset), index, args[1].op,
            args[2].op, info.in_out_rep, info.memory_rep, access_kind);
        return;
      }
      result->op = __ AtomicRMW(MemBuffer(imm.memory->index, imm.offset), index,
                                args[1].op, info.bin_op, info.in_out_rep,
                                info.memory_rep, access_kind);
      return;
    }
    if (info.op_type == kStore) {
      OpIndex value = args[1].op;
      if (info.in_out_rep == RegisterRepresentation::Word64() &&
          info.memory_rep != MemoryRepresentation::Uint64()) {
        value = __ TruncateWord64ToWord32(value);
      }
#ifdef V8_TARGET_BIG_ENDIAN
      // Reverse the value bytes before storing.
      DCHECK(info.in_out_rep == RegisterRepresentation::Word32() ||
             info.in_out_rep == RegisterRepresentation::Word64());
      wasm::ValueType wasm_type =
          info.in_out_rep == RegisterRepresentation::Word32() ? wasm::kWasmI32
                                                              : wasm::kWasmI64;
      value = BuildChangeEndiannessStore(
          value, info.memory_rep.ToMachineType().representation(), wasm_type);
#endif
      __ Store(MemBuffer(imm.memory->index, imm.offset), index, value,
               access_kind == MemoryAccessKind::kProtectedByTrapHandler
                   ? LoadOp::Kind::Protected().Atomic()
                   : LoadOp::Kind::RawAligned().Atomic(),
               info.memory_rep, compiler::kNoWriteBarrier);
      return;
    }
    DCHECK_EQ(info.op_type, kLoad);
    RegisterRepresentation loaded_value_rep = info.in_out_rep;
#if V8_TARGET_BIG_ENDIAN
    // Do not sign-extend / zero-extend the value to 64 bits as the bytes need
    // to be reversed first to keep little-endian load / store semantics. Still
    // extend for 1 byte loads as it doesn't require reversing any bytes.
    bool needs_zero_extension_64 = false;
    if (info.in_out_rep == RegisterRepresentation::Word64() &&
        info.memory_rep.SizeInBytes() < 8 &&
        info.memory_rep.SizeInBytes() != 1) {
      needs_zero_extension_64 = true;
      loaded_value_rep = RegisterRepresentation::Word32();
    }
#endif
    result->op =
        __ Load(MemBuffer(imm.memory->index, imm.offset), index,
                access_kind == MemoryAccessKind::kProtectedByTrapHandler
                    ? LoadOp::Kind::Protected().Atomic()
                    : LoadOp::Kind::RawAligned().Atomic(),
                info.memory_rep, loaded_value_rep);

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes after load.
    DCHECK(info.in_out_rep == RegisterRepresentation::Word32() ||
           info.in_out_rep == RegisterRepresentation::Word64());
    wasm::ValueType wasm_type =
        info.in_out_rep == RegisterRepresentation::Word32() ? wasm::kWasmI32
                                                            : wasm::kWasmI64;
    result->op = BuildChangeEndiannessLoad(
        result->op, info.memory_rep.ToMachineType(), wasm_type);

    if (needs_zero_extension_64) {
      result->op = __ ChangeUint32ToUint64(result->op);
    }
#endif
  }

  void AtomicFence(FullDecoder* decoder) {
    __ MemoryBarrier(AtomicMemoryOrder::kSeqCst);
  }

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    V<WordPtr> dst_uintptr = MemoryAddressToUintPtrOrOOBTrap(
        imm.memory.memory->address_type, dst.op);
    DCHECK_EQ(size.type, kWasmI32);
    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32(),
                           MachineType::UintPtr(), MachineType::Uint32(),
                           MachineType::Uint32(), MachineType::Uint32());
    // TODO(14616): Fix sharedness.
    V<Word32> result =
        CallC(&sig, ExternalReference::wasm_memory_init(),
              {__ BitcastHeapObjectToWordPtr(trusted_instance_data(false)),
               __ Word32Constant(imm.memory.index), dst_uintptr, src.op,
               __ Word32Constant(imm.data_segment.index), size.op});
    __ TrapIfNot(result, TrapId::kTrapMemOutOfBounds);
  }

  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    const WasmMemory* dst_memory = imm.memory_dst.memory;
    const WasmMemory* src_memory = imm.memory_src.memory;
    V<WordPtr> dst_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(dst_memory->address_type, dst.op);
    V<WordPtr> src_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(src_memory->address_type, src.op);
    AddressType min_address_type =
        dst_memory->is_memory64() && src_memory->is_memory64()
            ? AddressType::kI64
            : AddressType::kI32;
    V<WordPtr> size_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(min_address_type, size.op);
    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32(),
                           MachineType::Uint32(), MachineType::UintPtr(),
                           MachineType::UintPtr(), MachineType::UintPtr());
    // TODO(14616): Fix sharedness.
    V<Word32> result =
        CallC(&sig, ExternalReference::wasm_memory_copy(),
              {__ BitcastHeapObjectToWordPtr(trusted_instance_data(false)),
               __ Word32Constant(imm.memory_dst.index),
               __ Word32Constant(imm.memory_src.index), dst_uintptr,
               src_uintptr, size_uintptr});
    __ TrapIfNot(result, TrapId::kTrapMemOutOfBounds);
  }

  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& dst, const Value& value, const Value& size) {
    AddressType address_type = imm.memory->address_type;
    V<WordPtr> dst_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(address_type, dst.op);
    V<WordPtr> size_uintptr =
        MemoryAddressToUintPtrOrOOBTrap(address_type, size.op);
    auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                   .Params(MachineType::Pointer(), MachineType::Uint32(),
                           MachineType::UintPtr(), MachineType::Uint8(),
                           MachineType::UintPtr());
    // TODO(14616): Fix sharedness.
    V<Word32> result = CallC(
        &sig, ExternalReference::wasm_memory_fill(),
        {__ BitcastHeapObjectToWordPtr(trusted_instance_data(false)),
         __ Word32Constant(imm.index), dst_uintptr, value.op, size_uintptr});

    __ TrapIfNot(result, TrapId::kTrapMemOutOfBounds);
  }

  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    // TODO(14616): Data segments aren't available during streaming compilation.
    // Discussion: github.com/WebAssembly/shared-everything-threads/issues/83
    bool shared = decoder->enabled_.has_shared() &&
                  decoder->module_->data_segments[imm.index].shared;
    V<FixedUInt32Array> data_segment_sizes = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(shared), DataSegmentSizes,
        MemoryRepresentation::TaggedPointer());
    __ Store(data_segment_sizes, __ Word32Constant(0),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::Int32(),
             compiler::kNoWriteBarrier,
             FixedUInt32Array::OffsetOfElementAt(imm.index));
  }

  void TableGet(FullDecoder* decoder, const Value& index, Value* result,
                const TableIndexImmediate& imm) {
    V<WasmTableObject> table = LoadTable(decoder, imm);
    V<Smi> size_smi = __ Load(table, LoadOp::Kind::TaggedBase(),
                              MemoryRepresentation::TaggedSigned(),
                              WasmTableObject::kCurrentLengthOffset);
    V<WordPtr> index_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, index.op);
    DCHECK_GE(kSmiMaxValue, v8_flags.wasm_max_table_size.value());
    V<Word32> in_bounds = __ UintPtrLessThan(
        index_wordptr, __ ChangeUint32ToUintPtr(__ UntagSmi(size_smi)));
    __ TrapIfNot(in_bounds, TrapId::kTrapTableOutOfBounds);
    V<FixedArray> entries = __ Load(table, LoadOp::Kind::TaggedBase(),
                                    MemoryRepresentation::TaggedPointer(),
                                    WasmTableObject::kEntriesOffset);
    OpIndex entry = __ LoadFixedArrayElement(entries, index_wordptr);

    if (IsSubtypeOf(imm.table->type, kWasmFuncRef, decoder->module_) ||
        IsSubtypeOf(imm.table->type, ValueType::RefNull(HeapType::kFuncShared),
                    decoder->module_)) {
      // If the entry has map type Tuple2, call WasmFunctionTableGet which will
      // initialize the function table entry.
      Label<Object> resolved(&asm_);
      Label<> call_runtime(&asm_);
      // The entry is a WasmFuncRef, WasmNull, or Tuple2. Hence
      // it is safe to cast it to HeapObject.
      V<Map> entry_map = __ LoadMapField(V<HeapObject>::Cast(entry));
      V<Word32> instance_type = __ LoadInstanceTypeField(entry_map);
      GOTO_IF(
          UNLIKELY(__ Word32Equal(instance_type, InstanceType::TUPLE2_TYPE)),
          call_runtime);
      // Otherwise the entry is WasmFuncRef or WasmNull; we are done.
      GOTO(resolved, entry);

      BIND(call_runtime);
      bool extract_shared_data = !shared_ && imm.table->shared;
      GOTO(resolved,
           CallBuiltinThroughJumptable<
               BuiltinCallDescriptor::WasmFunctionTableGet>(
               decoder, {__ IntPtrConstant(imm.index), index_wordptr,
                         __ Word32Constant(extract_shared_data ? 1 : 0)}));

      BIND(resolved, resolved_entry);
      result->op = resolved_entry;
    } else {
      result->op = entry;
    }
    result->op = AnnotateResultIfReference(result->op, imm.table->type);
  }

  void TableSet(FullDecoder* decoder, const Value& index, const Value& value,
                const TableIndexImmediate& imm) {
    bool extract_shared_data = !shared_ && imm.table->shared;

    V<WordPtr> index_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, index.op);

    if (IsSubtypeOf(imm.table->type, kWasmFuncRef, decoder->module_) ||
        IsSubtypeOf(imm.table->type, ValueType::RefNull(HeapType::kFuncShared),
                    decoder->module_)) {
      CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableSetFuncRef>(
          decoder, {__ IntPtrConstant(imm.index),
                    __ Word32Constant(extract_shared_data ? 1 : 0),
                    index_wordptr, value.op});
    } else {
      CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableSet>(
          decoder, {__ IntPtrConstant(imm.index),
                    __ Word32Constant(extract_shared_data ? 1 : 0),
                    index_wordptr, value.op});
    }
  }

  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value& dst_val, const Value& src_val,
                 const Value& size_val) {
    const WasmTable* table = imm.table.table;
    V<WordPtr> dst_wordptr =
        TableAddressToUintPtrOrOOBTrap(table->address_type, dst_val.op);
    V<Word32> src = src_val.op;
    V<Word32> size = size_val.op;
    DCHECK_EQ(table->shared, table->shared);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableInit>(
        decoder, {
                     dst_wordptr,
                     src,
                     size,
                     __ NumberConstant(imm.table.index),
                     __ NumberConstant(imm.element_segment.index),
                     __ NumberConstant((!shared_ && table->shared) ? 1 : 0),
                 });
  }

  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value& dst_val, const Value& src_val,
                 const Value& size_val) {
    const WasmTable* dst_table = imm.table_dst.table;
    const WasmTable* src_table = imm.table_src.table;
    V<WordPtr> dst_wordptr =
        TableAddressToUintPtrOrOOBTrap(dst_table->address_type, dst_val.op);
    V<WordPtr> src_wordptr =
        TableAddressToUintPtrOrOOBTrap(src_table->address_type, src_val.op);
    AddressType min_address_type =
        dst_table->is_table64() && src_table->is_table64() ? AddressType::kI64
                                                           : AddressType::kI32;
    V<WordPtr> size_wordptr =
        TableAddressToUintPtrOrOOBTrap(min_address_type, size_val.op);
    bool table_is_shared = imm.table_dst.table->shared;
    // TODO(14616): Is this too restrictive?
    DCHECK_EQ(table_is_shared, imm.table_src.table->shared);
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableCopy>(
        decoder, {dst_wordptr, src_wordptr, size_wordptr,
                  __ NumberConstant(imm.table_dst.index),
                  __ NumberConstant(imm.table_src.index),
                  __ NumberConstant((!shared_ && table_is_shared) ? 1 : 0)});
  }

  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& value, const Value& delta, Value* result) {
    Label<Word32> end(&asm_);
    V<WordPtr> delta_wordptr;

    // If `delta` is OOB, return -1.
    if (!imm.table->is_table64()) {
      delta_wordptr = __ ChangeUint32ToUintPtr(delta.op);
    } else if constexpr (Is64()) {
      delta_wordptr = delta.op;
    } else {
      GOTO_IF(UNLIKELY(__ TruncateWord64ToWord32(
                  __ Word64ShiftRightLogical(delta.op, 32))),
              end, __ Word32Constant(-1));
      delta_wordptr = V<WordPtr>::Cast(__ TruncateWord64ToWord32(delta.op));
    }

    bool extract_shared_data = !shared_ && imm.table->shared;
    DCHECK_GE(kSmiMaxValue, v8_flags.wasm_max_table_size.value());
    V<Word32> call_result = __ UntagSmi(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableGrow>(
            decoder, {__ NumberConstant(imm.index), delta_wordptr,
                      __ Word32Constant(extract_shared_data), value.op}));
    GOTO(end, call_result);

    BIND(end, result_i32);
    if (imm.table->is_table64()) {
      result->op = __ ChangeInt32ToInt64(result_i32);
    } else {
      result->op = result_i32;
    }
  }

  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& start, const Value& value, const Value& count) {
    V<WordPtr> start_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, start.op);
    V<WordPtr> count_wordptr =
        TableAddressToUintPtrOrOOBTrap(imm.table->address_type, count.op);
    bool extract_shared_data = !shared_ && imm.table->shared;
    CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmTableFill>(
        decoder,
        {start_wordptr, count_wordptr, __ Word32Constant(extract_shared_data),
         __ NumberConstant(imm.index), value.op});
  }

  V<WasmTableObject> LoadTable(FullDecoder* decoder,
                               const TableIndexImmediate& imm) {
    V<FixedArray> tables = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(imm.table->shared), Tables,
        MemoryRepresentation::TaggedPointer());
    return V<WasmTableObject>::Cast(
        __ LoadFixedArrayElement(tables, imm.index));
  }

  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm,
                 Value* result) {
    V<WasmTableObject> table = LoadTable(decoder, imm);
    V<Word32> size_word32 = __ UntagSmi(__ Load(
        table, LoadOp::Kind::TaggedBase(), MemoryRepresentation::TaggedSigned(),
        WasmTableObject::kCurrentLengthOffset));
    if (imm.table->is_table64()) {
      result->op = __ ChangeUint32ToUint64(size_word32);
    } else {
      result->op = size_word32;
    }
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    // Note: Contrary to data segments, elem segments occur before the code
    // section, so we can be sure that they're available even during streaming
    // compilation.
    bool shared = decoder->module_->elem_segments[imm.index].shared;
    V<FixedArray> elem_segments = LOAD_IMMUTABLE_INSTANCE_FIELD(
        trusted_instance_data(shared), ElementSegments,
        MemoryRepresentation::TaggedPointer());
    __ StoreFixedArrayElement(elem_segments, imm.index,
                              LOAD_ROOT(EmptyFixedArray),
                              compiler::kFullWriteBarrier);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    uint32_t field_count = imm.struct_type->field_count();
    SmallZoneVector<OpIndex, 16> args_vector(field_count, decoder->zone_);
    for (uint32_t i = 0; i < field_count; ++i) {
      args_vector[i] = args[i].op;
    }
    result->op = StructNewImpl(decoder, imm, args_vector.data());
  }

  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    uint32_t field_count = imm.struct_type->field_count();
    SmallZoneVector<OpIndex, 16> args(field_count, decoder->zone_);
    for (uint32_t i = 0; i < field_count; i++) {
      ValueType field_type = imm.struct_type->field(i);
      args[i] = DefaultValue(field_type);
    }
    result->op = StructNewImpl(decoder, imm, args.data());
  }

  void StructGet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, bool is_signed, Value* result) {
    result->op = __ StructGet(
        V<WasmStructNullable>::Cast(struct_object.op),
        field.struct_imm.struct_type, field.struct_imm.index,
        field.field_imm.index, is_signed,
        struct_object.type.is_nullable() ? compiler::kWithNullCheck
                                         : compiler::kWithoutNullCheck);
  }

  void StructSet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, const Value& field_value) {
    __ StructSet(V<WasmStructNullable>::Cast(struct_object.op), field_value.op,
                 field.struct_imm.struct_type, field.struct_imm.index,
                 field.field_imm.index,
                 struct_object.type.is_nullable()
                     ? compiler::kWithNullCheck
                     : compiler::kWithoutNullCheck);
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                const Value& length, const Value& initial_value,
                Value* result) {
    result->op = ArrayNewImpl(decoder, imm.index, imm.array_type,
                              V<Word32>::Cast(length.op),
                              V<Any>::Cast(initial_value.op));
  }

  void ArrayNewDefault(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                       const Value& length, Value* result) {
    V<Any> initial_value = DefaultValue(imm.array_type->element_type());
    result->op = ArrayNewImpl(decoder, imm.index, imm.array_type,
                              V<Word32>::Cast(length.op), initial_value);
  }

  void ArrayGet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                bool is_signed, Value* result) {
    auto array_value = V<WasmArrayNullable>::Cast(array_obj.op);
    BoundsCheckArray(array_value, index.op, array_obj.type);
    result->op = __ ArrayGet(array_value, V<Word32>::Cast(index.op),
                             imm.array_type, is_signed);
  }

  void ArraySet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                const Value& value) {
    auto array_value = V<WasmArrayNullable>::Cast(array_obj.op);
    BoundsCheckArray(array_value, index.op, array_obj.type);
    __ ArraySet(array_value, V<Word32>::Cast(index.op), V<Any>::Cast(value.op),
                imm.array_type->element_type());
  }

  void ArrayLen(FullDecoder* decoder, const Value& array_obj, Value* result) {
    result->op = __ ArrayLength(V<WasmArrayNullable>::Cast(array_obj.op),
                                array_obj.type.is_nullable()
                                    ? compiler::kWithNullCheck
                                    : compiler::kWithoutNullCheck);
  }

  void ArrayCopy(FullDecoder* decoder, const Value& dst, const Value& dst_index,
                 const Value& src, const Value& src_index,
                 const ArrayIndexImmediate& src_imm, const Value& length) {
    V<WasmArrayNullable> src_array = V<WasmArrayNullable>::Cast(src.op);
    V<WasmArrayNullable> dst_array = V<WasmArrayNullable>::Cast(dst.op);
    BoundsCheckArrayWithLength(dst_array, dst_index.op, length.op,
                               dst.type.is_nullable()
                                   ? compiler::kWithNullCheck
                                   : compiler::kWithoutNullCheck);
    BoundsCheckArrayWithLength(src_array, src_index.op, length.op,
                               src.type.is_nullable()
                                   ? compiler::kWithNullCheck
                                   : compiler::kWithoutNullCheck);

    ValueType element_type = src_imm.array_type->element_type();

    IF_NOT (__ Word32Equal(length.op, 0)) {
      // Values determined by test/mjsunit/wasm/array-copy-benchmark.js on x64.
      int array_copy_max_loop_length;
      switch (element_type.kind()) {
        case wasm::kI32:
        case wasm::kI64:
        case wasm::kI8:
        case wasm::kI16:
          array_copy_max_loop_length = 20;
          break;
        case wasm::kF16:  // TODO(irezvov): verify the threshold for F16.
        case wasm::kF32:
        case wasm::kF64:
          array_copy_max_loop_length = 35;
          break;
        case wasm::kS128:
          array_copy_max_loop_length = 100;
          break;
        case wasm::kRtt:
        case wasm::kRef:
        case wasm::kRefNull:
          array_copy_max_loop_length = 15;
          break;
        case wasm::kVoid:
        case kTop:
        case wasm::kBottom:
          UNREACHABLE();
      }

      IF (__ Uint32LessThan(array_copy_max_loop_length, length.op)) {
        // Builtin
        MachineType arg_types[]{MachineType::TaggedPointer(),
                                MachineType::Uint32(),
                                MachineType::TaggedPointer(),
                                MachineType::Uint32(), MachineType::Uint32()};
        MachineSignature sig(0, 5, arg_types);

        CallC(&sig, ExternalReference::wasm_array_copy(),
              {dst_array, dst_index.op, src_array, src_index.op, length.op});
      } ELSE {
        V<Word32> src_end_index =
            __ Word32Sub(__ Word32Add(src_index.op, length.op), 1);

        IF (__ Uint32LessThan(src_index.op, dst_index.op)) {
          // Reverse
          V<Word32> dst_end_index =
              __ Word32Sub(__ Word32Add(dst_index.op, length.op), 1);
          ScopedVar<Word32> src_index_loop(this, src_end_index);
          ScopedVar<Word32> dst_index_loop(this, dst_end_index);

          WHILE(__ Word32Constant(1)) {
            V<Any> value = __ ArrayGet(src_array, src_index_loop,
                                       src_imm.array_type, true);
       
"""


```