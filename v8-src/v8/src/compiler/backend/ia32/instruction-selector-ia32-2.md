Response: The user wants to understand the functionality of the provided C++ code snippet, which is part 3 of a larger file related to instruction selection for the IA32 architecture in the V8 JavaScript engine.

**Plan:**

1. **Identify the main purpose of the code:**  The code consists of template specializations of the `InstructionSelectorT` class for different node types, primarily focusing on SIMD (Single Instruction, Multiple Data) operations. This suggests its role is to select appropriate IA32 instructions for these operations.
2. **Group functionalities:**  The code handles various SIMD operations like splatting, extracting lanes, replacing lanes, arithmetic operations (min, max, neg, mul), shifts, logical operations (and not, select), conversions, shuffles, and more.
3. **Highlight conditional compilation:** Note the use of `V8_ENABLE_WEBASSEMBLY` and different `Adapter` types (`TurbofanAdapter`, `TurboshaftAdapter`), indicating that the code handles different compilation pipelines and features.
4. **Explain the relationship with JavaScript:**  SIMD operations in JavaScript are supported through the WebAssembly SIMD proposal, now integrated into the language. Illustrate with a JavaScript example that directly corresponds to the C++ code's functionality.
这是 `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 文件的一部分，专门负责为 **SIMD (Single Instruction, Multiple Data)** 和一些其他特定的操作选择合适的 IA-32 汇编指令。这是针对 V8 引擎的编译后端，用于将中间表示 (例如，TurboFan 或 TurboShaft 生成的图) 转换为底层的机器指令。

**具体功能归纳：**

* **SIMD 指令选择:**  该部分代码主要针对各种 SIMD 操作，例如：
    * **创建 SIMD 值:**  `Splat` (将单个标量值复制到 SIMD 向量的所有通道), `Const` (创建 SIMD 常量).
    * **访问 SIMD 通道:** `ExtractLane` (提取 SIMD 向量的特定通道).
    * **修改 SIMD 通道:** `ReplaceLane` (替换 SIMD 向量的特定通道).
    * **SIMD 算术运算:**  `Min`, `Max`, `Neg`, `Mul`, `Add`, `Sub`, `Div`, `Sqrt`.
    * **SIMD 位运算:** `And`, `Or`, `Xor`, `Not`, `AndNot`, `Select`.
    * **SIMD 比较运算:** `Eq`, `Ne`, `Gt`, `Ge`, `Lt`, `Le`.
    * **SIMD 类型转换:**  例如，整数和浮点数之间的转换 (`F32x4UConvertI32x4`, `I32x4SConvertF32x4`).
    * **SIMD 位移操作:** `Shl`, `ShrS`, `ShrU`.
    * **SIMD 重排操作:** `Shuffle` (非常复杂，涉及到各种优化，包括 `Concat`, `Rotate`, `Unpack`, `Zip`, `Transpose`, `Reverse`, `Blend`, `Dup`).
    * **SIMD Swizzle:**  类似于 Shuffle，但通常只使用一个输入向量进行通道重排。
    * **SIMD 规约操作:** `AnyTrue`, `AllTrue`, `BitMask`.
    * **SIMD 扩展加法:** `ExtAddPairwise`.
    * **SIMD 点积运算:** `Dot`.
    * **SIMD 融合乘加/减运算:** `Qfma`, `Qfms`.
    * **SIMD Relaxed 操作:**  针对一些精度要求不高的场景，选择更高效的指令，例如 `RelaxedMin`, `RelaxedMax`, `RelaxedLaneSelect`, `RelaxedTrunc`.
* **条件编译和优化:** 代码中大量使用了 `if constexpr` 和 `IsSupported(AVX)` 等条件编译指令，表明会根据目标 CPU 的特性 (例如是否支持 AVX 指令集) 选择不同的指令，以实现性能优化。
* **适配器模式:** 使用了模板参数 `Adapter`，这是一种适配器模式，允许代码在不同的编译流程 (`TurbofanAdapter`, `TurboshaftAdapter`) 中重用，可能针对不同的中间表示或优化策略。
* **与 WebAssembly 的关联:**  代码中包含了 `#if V8_ENABLE_WEBASSEMBLY`，说明这部分代码也负责为 WebAssembly 的 SIMD 指令选择合适的 IA-32 指令。
* **栈指针操作:** 包含 `SetStackPointer` 的处理。
* **辅助函数和宏:**  定义了一些辅助函数 (如 `VisitRRSimd`, `VisitRROSimdShift`) 和宏 (如 `VISIT_SIMD_SPLAT`, `VISIT_SIMD_BINOP`) 来简化代码并减少重复。

**与 JavaScript 的关系 (WebAssembly SIMD)：**

这部分 C++ 代码的功能直接对应于 JavaScript 中通过 **WebAssembly 的 SIMD 扩展** 可以实现的操作。WebAssembly 允许开发者编写高性能的、接近机器码的代码，并在现代浏览器中运行。

**JavaScript 例子:**

假设我们在 WebAssembly 中使用了 SIMD 指令，例如进行两个 `float32x4` 类型的向量的加法：

**WebAssembly (Text 格式示例):**

```wasm
(module
  (func $add_vectors (param $a v128) (param $b v128) (result v128)
    local.get $a
    local.get $b
    f32x4.add
  )
  (export "add_vectors" (func $add_vectors))
)
```

当 V8 引擎编译这段 WebAssembly 代码并针对 IA-32 架构时，`InstructionSelectorT<Adapter>::VisitF32x4Add` 函数 (或其他类似的函数，取决于具体的适配器) 将会被调用。该函数会根据 CPU 的特性 (是否支持 AVX 等) 选择合适的 IA-32 指令，例如 `addps` (SSE 指令) 或 `vaddps` (AVX 指令) 来执行这两个向量的加法操作。

**更直接的 JavaScript 对应 (使用 JavaScript API 操作 SIMD):**

虽然 JavaScript 本身没有直接的 `f32x4.add` 语法，但可以通过 WebAssembly 的 JavaScript API 来操作 SIMD 值：

```javascript
const wasmCode = `
  (module
    (func $add_vectors (param $a v128) (param $b v128) (result v128)
      local.get $a
      local.get $b
      f32x4.add
    )
    (export "add_vectors" (func $add_vectors))
  )
`;

const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule);

const vectorA = new Float32Array([1, 2, 3, 4]);
const vectorB = new Float32Array([5, 6, 7, 8]);

const wasmVectorA = new Uint8Array(vectorA.buffer);
const wasmVectorB = new Uint8Array(vectorB.buffer);

const resultVector = wasmInstance.exports.add_vectors(wasmVectorA, wasmVectorB);

const resultArray = new Float32Array(resultVector.buffer);
console.log(resultArray); // 输出类似 [6, 8, 10, 12]
```

在这个 JavaScript 例子中，虽然我们没有直接在 JavaScript 中写 `f32x4.add`，但我们加载并执行了包含该 WebAssembly 指令的模块。V8 引擎在编译和执行这段 WebAssembly 代码时，就会使用 `instruction-selector-ia32.cc` 中的代码来选择对应的 IA-32 加法指令。

**总结:**

这部分 `instruction-selector-ia32.cc` 代码是 V8 引擎中至关重要的一部分，它负责将高级的 SIMD 操作 (无论是来自 JavaScript 的 WebAssembly 还是 V8 内部的优化) 转换为实际可以在 IA-32 架构的 CPU 上执行的机器指令，从而实现高性能的计算。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 IA32OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kIA32S128Zero, dst);
  } else if (all_ones) {
    Emit(kIA32S128AllOnes, dst);
  } else {
    InstructionOperand inputs[kUint32Immediates];
    for (int i = 0; i < kUint32Immediates; ++i) {
      inputs[i] = g.UseImmediate(val[i]);
    }
    InstructionOperand temp(g.TempRegister());
    Emit(kIA32S128Const, 1, &dst, kUint32Immediates, inputs, 1, &temp);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Min(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand operand0 = g.UseRegister(this->input_at(node, 0));
  InstructionOperand operand1 = g.UseRegister(this->input_at(node, 1));

  if (IsSupported(AVX)) {
    Emit(kIA32F64x2Min, g.DefineAsRegister(node), operand0, operand1);
  } else {
    Emit(kIA32F64x2Min, g.DefineSameAsFirst(node), operand0, operand1);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Max(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand operand0 = g.UseRegister(this->input_at(node, 0));
  InstructionOperand operand1 = g.UseRegister(this->input_at(node, 1));
  if (IsSupported(AVX)) {
    Emit(kIA32F64x2Max, g.DefineAsRegister(node), operand0, operand1);
  } else {
    Emit(kIA32F64x2Max, g.DefineSameAsFirst(node), operand0, operand1);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Splat(node_t node) {
  VisitRRSimd(this, node, kIA32F64x2Splat);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ExtractLane(node_t node) {
  VisitRRISimd(this, node, kIA32F64x2ExtractLane, kIA32F64x2ExtractLane);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI64x2SplatI32Pair(
    node_t node) {
  // In turboshaft it gets lowered to an I32x4Splat.
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI64x2SplatI32Pair(Node* node) {
  IA32OperandGeneratorT<TurbofanAdapter> g(this);
  Int32Matcher match_left(node->InputAt(0));
  Int32Matcher match_right(node->InputAt(1));
  if (match_left.Is(0) && match_right.Is(0)) {
    Emit(kIA32S128Zero, g.DefineAsRegister(node));
  } else {
    InstructionOperand operand0 = g.UseRegister(node->InputAt(0));
    InstructionOperand operand1 = g.Use(node->InputAt(1));
    Emit(kIA32I64x2SplatI32Pair, g.DefineAsRegister(node), operand0, operand1);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI64x2ReplaceLaneI32Pair(
    node_t node) {
  // In turboshaft it gets lowered to an I32x4ReplaceLane.
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI64x2ReplaceLaneI32Pair(
    Node* node) {
  IA32OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand operand = g.UseRegister(node->InputAt(0));
  InstructionOperand lane = g.UseImmediate(OpParameter<int32_t>(node->op()));
  InstructionOperand low = g.Use(node->InputAt(1));
  InstructionOperand high = g.Use(node->InputAt(2));
  Emit(kIA32I64x2ReplaceLaneI32Pair, g.DefineSameAsFirst(node), operand, lane,
       low, high);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Neg(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  // If AVX unsupported, make sure dst != src to avoid a move.
  InstructionOperand operand0 =
      IsSupported(AVX) ? g.UseRegister(this->input_at(node, 0))
                       : g.UseUniqueRegister(this->input_at(node, 0));
  Emit(kIA32I64x2Neg, g.DefineAsRegister(node), operand0);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ShrS(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);

  if (g.CanBeImmediate(this->input_at(node, 1))) {
    Emit(kIA32I64x2ShrS, dst, g.UseRegister(this->input_at(node, 0)),
         g.UseImmediate(this->input_at(node, 1)));
  } else {
    InstructionOperand temps[] = {g.TempSimd128Register(), g.TempRegister()};
    Emit(kIA32I64x2ShrS, dst, g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Mul(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register(),
                                g.TempSimd128Register()};
  Emit(kIA32I64x2Mul, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Splat(node_t node) {
  VisitRRSimd(this, node, kIA32F32x4Splat);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4ExtractLane(node_t node) {
  VisitRRISimd(this, node, kIA32F32x4ExtractLane);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4UConvertI32x4(node_t node) {
  VisitRRSimd(this, node, kIA32F32x4UConvertI32x4);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertF32x4(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32I32x4SConvertF32x4, dst, g.UseRegister(this->input_at(node, 0)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertF32x4(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register(),
                                g.TempSimd128Register()};
  InstructionCode opcode =
      IsSupported(AVX) ? kAVXI32x4UConvertF32x4 : kSSEI32x4UConvertF32x4;
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kIA32S128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32S128Select, dst, g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128AndNot(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  // andnps a b does ~a & b, but we want a & !b, so flip the input.
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32S128AndNot, dst, g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 0)));
}

#define VISIT_SIMD_SPLAT(Type)                                          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) { \
    bool set_zero;                                                      \
    if constexpr (Adapter::IsTurboshaft) {                              \
      set_zero = this->MatchIntegralZero(this->input_at(node, 0));      \
    } else {                                                            \
      set_zero = Int32Matcher(node->InputAt(0)).Is(0);                  \
    }                                                                   \
    if (set_zero) {                                                     \
      IA32OperandGeneratorT<Adapter> g(this);                           \
      Emit(kIA32S128Zero, g.DefineAsRegister(node));                    \
    } else {                                                            \
      VisitRO(this, node, kIA32##Type##Splat);                          \
    }                                                                   \
  }
SIMD_INT_TYPES(VISIT_SIMD_SPLAT)
#undef SIMD_INT_TYPES
#undef VISIT_SIMD_SPLAT

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Splat(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ExtractLaneU(node_t node) {
  VisitRRISimd(this, node, kIA32Pextrb);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ExtractLaneS(node_t node) {
  VisitRRISimd(this, node, kIA32I8x16ExtractLaneS);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtractLaneU(node_t node) {
  VisitRRISimd(this, node, kIA32Pextrw);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtractLaneS(node_t node) {
  VisitRRISimd(this, node, kIA32I16x8ExtractLaneS);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtractLane(node_t node) {
  VisitRRISimd(this, node, kIA32I32x4ExtractLane);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ExtractLane(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ReplaceLane(node_t node) {
  UNIMPLEMENTED();
}

#define SIMD_REPLACE_LANE_TYPE_OP(V) \
  V(I32x4, kIA32Pinsrd)              \
  V(I16x8, kIA32Pinsrw)              \
  V(I8x16, kIA32Pinsrb)              \
  V(F32x4, kIA32Insertps)            \
  V(F64x2, kIA32F64x2ReplaceLane)

#define VISIT_SIMD_REPLACE_LANE(TYPE, OPCODE)                                 \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##TYPE##ReplaceLane(node_t node) { \
    IA32OperandGeneratorT<Adapter> g(this);                                   \
    int lane;                                                                 \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      const turboshaft::Simd128ReplaceLaneOp& op =                            \
          this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();  \
      lane = op.lane;                                                         \
    } else {                                                                  \
      lane = OpParameter<int32_t>(node->op());                                \
    }                                                                         \
    InstructionOperand operand0 = g.UseRegister(this->input_at(node, 0));     \
    InstructionOperand operand1 = g.UseImmediate(lane);                       \
    auto input1 = this->input_at(node, 1);                                    \
    InstructionOperand operand2;                                              \
    if constexpr (OPCODE == kIA32F64x2ReplaceLane) {                          \
      operand2 = g.UseRegister(input1);                                       \
    } else {                                                                  \
      operand2 = g.Use(input1);                                               \
    }                                                                         \
    /* When no-AVX, define dst == src to save a move. */                      \
    InstructionOperand dst = IsSupported(AVX) ? g.DefineAsRegister(node)      \
                                              : g.DefineSameAsFirst(node);    \
    Emit(OPCODE, dst, operand0, operand1, operand2);                          \
  }
SIMD_REPLACE_LANE_TYPE_OP(VISIT_SIMD_REPLACE_LANE)
#undef VISIT_SIMD_REPLACE_LANE
#undef SIMD_REPLACE_LANE_TYPE_OP

#define VISIT_SIMD_SHIFT_UNIFIED_SSE_AVX(Opcode)                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    VisitRROSimdShift(this, node, kIA32##Opcode);                  \
  }
SIMD_SHIFT_OPCODES_UNIFED_SSE_AVX(VISIT_SIMD_SHIFT_UNIFIED_SSE_AVX)
#undef VISIT_SIMD_SHIFT_UNIFIED_SSE_AVX
#undef SIMD_SHIFT_OPCODES_UNIFED_SSE_AVX

// TODO(v8:9198): SSE requires operand0 to be a register as we don't have memory
// alignment yet. For AVX, memory operands are fine, but can have performance
// issues if not aligned to 16/32 bytes (based on load size), see SDM Vol 1,
// chapter 14.9
#define VISIT_SIMD_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    IA32OperandGeneratorT<Adapter> g(this);                        \
    Emit(kIA32##Opcode, g.DefineAsRegister(node),                  \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(VISIT_SIMD_UNOP)
#undef VISIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_UNOP_LIST(V) \
  V(F16x8Abs)                           \
  V(F16x8Neg)                           \
  V(F16x8Sqrt)                          \
  V(F16x8Floor)                         \
  V(F16x8Ceil)                          \
  V(F16x8Trunc)                         \
  V(F16x8NearestInt)

#define SIMD_VISIT_UNIMPL_UNOP(Name)                             \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_UNOP_LIST(SIMD_VISIT_UNIMPL_UNOP)
#undef SIMD_VISIT_UNIMPL_UNOP
#undef UNIMPLEMENTED_SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_CVTOP_LIST(V) \
  V(F16x8SConvertI16x8)                  \
  V(F16x8UConvertI16x8)                  \
  V(I16x8SConvertF16x8)                  \
  V(I16x8UConvertF16x8)                  \
  V(F32x4PromoteLowF16x8)                \
  V(F16x8DemoteF32x4Zero)                \
  V(F16x8DemoteF64x2Zero)

#define SIMD_VISIT_UNIMPL_CVTOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_CVTOP_LIST(SIMD_VISIT_UNIMPL_CVTOP)
#undef SIMD_VISIT_UNIMPL_CVTOP
#undef UNIMPLEMENTED_SIMD_CVTOP_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitV128AnyTrue(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32S128AnyTrue, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

#define VISIT_SIMD_ALLTRUE(Opcode)                                            \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {            \
    IA32OperandGeneratorT<Adapter> g(this);                                   \
    InstructionOperand temps[] = {g.TempRegister(), g.TempSimd128Register()}; \
    Emit(kIA32##Opcode, g.DefineAsRegister(node),                             \
         g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps),      \
         temps);                                                              \
  }
SIMD_ALLTRUE_LIST(VISIT_SIMD_ALLTRUE)
#undef VISIT_SIMD_ALLTRUE
#undef SIMD_ALLTRUE_LIST

#define VISIT_SIMD_BINOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    VisitRROSimd(this, node, kAVX##Opcode, kSSE##Opcode);          \
  }
SIMD_BINOP_LIST(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define UNIMPLEMENTED_SIMD_BINOP_LIST(V) \
  V(F16x8Add)                            \
  V(F16x8Sub)                            \
  V(F16x8Mul)                            \
  V(F16x8Div)                            \
  V(F16x8Min)                            \
  V(F16x8Max)                            \
  V(F16x8Pmin)                           \
  V(F16x8Pmax)                           \
  V(F16x8Eq)                             \
  V(F16x8Ne)                             \
  V(F16x8Lt)                             \
  V(F16x8Le)

#define SIMD_VISIT_UNIMPL_BINOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_BINOP_LIST(SIMD_VISIT_UNIMPL_BINOP)
#undef SIMD_VISIT_UNIMPL_BINOP
#undef UNIMPLEMENTED_SIMD_BINOP_LIST

#define VISIT_SIMD_BINOP_UNIFIED_SSE_AVX(Opcode)                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    VisitRROSimd(this, node, kIA32##Opcode, kIA32##Opcode);        \
  }
SIMD_BINOP_UNIFIED_SSE_AVX_LIST(VISIT_SIMD_BINOP_UNIFIED_SSE_AVX)
#undef VISIT_SIMD_BINOP_UNIFIED_SSE_AVX
#undef SIMD_BINOP_UNIFIED_SSE_AVX_LIST

#define VISIT_SIMD_BINOP_RRR(OPCODE)                               \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    VisitRRRSimd(this, node, kIA32##OPCODE);                       \
  }
SIMD_BINOP_RRR(VISIT_SIMD_BINOP_RRR)
#undef VISIT_SIMD_BINOP_RRR
#undef SIMD_BINOP_RRR

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8BitMask(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kIA32I16x8BitMask, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shl(node_t node) {
  VisitI8x16Shift(this, node, kIA32I8x16Shl);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ShrS(node_t node) {
  VisitI8x16Shift(this, node, kIA32I8x16ShrS);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ShrU(node_t node) {
  VisitI8x16Shift(this, node, kIA32I8x16ShrU);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
namespace {

// Returns true if shuffle can be decomposed into two 16x4 half shuffles
// followed by a 16x8 blend.
// E.g. [3 2 1 0 15 14 13 12].
bool TryMatch16x8HalfShuffle(uint8_t* shuffle16x8, uint8_t* blend_mask) {
  *blend_mask = 0;
  for (int i = 0; i < 8; i++) {
    if ((shuffle16x8[i] & 0x4) != (i & 0x4)) return false;
    *blend_mask |= (shuffle16x8[i] > 7 ? 1 : 0) << i;
  }
  return true;
}

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
  ArchOpcode avx_opcode;
  bool src0_needs_reg;
  bool src1_needs_reg;
};

// Shuffles that map to architecture-specific instruction sequences. These are
// matched very early, so we shouldn't include shuffles that match better in
// later tests, like 32x4 and 16x8 shuffles. In general, these patterns should
// map to either a single instruction, or be finer grained, such as zip/unzip or
// transpose patterns.
static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23},
     kIA32S64x2UnpackLow,
     kIA32S64x2UnpackLow,
     true,
     false},
    {{8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31},
     kIA32S64x2UnpackHigh,
     kIA32S64x2UnpackHigh,
     true,
     false},
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kIA32S32x4UnpackLow,
     kIA32S32x4UnpackLow,
     true,
     false},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kIA32S32x4UnpackHigh,
     kIA32S32x4UnpackHigh,
     true,
     false},
    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kIA32S16x8UnpackLow,
     kIA32S16x8UnpackLow,
     true,
     false},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kIA32S16x8UnpackHigh,
     kIA32S16x8UnpackHigh,
     true,
     false},
    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kIA32S8x16UnpackLow,
     kIA32S8x16UnpackLow,
     true,
     false},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kIA32S8x16UnpackHigh,
     kIA32S8x16UnpackHigh,
     true,
     false},

    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kSSES16x8UnzipLow,
     kAVXS16x8UnzipLow,
     true,
     false},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kSSES16x8UnzipHigh,
     kAVXS16x8UnzipHigh,
     true,
     true},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kSSES8x16UnzipLow,
     kAVXS8x16UnzipLow,
     true,
     true},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kSSES8x16UnzipHigh,
     kAVXS8x16UnzipHigh,
     true,
     true},

    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kSSES8x16TransposeLow,
     kAVXS8x16TransposeLow,
     true,
     true},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kSSES8x16TransposeHigh,
     kAVXS8x16TransposeHigh,
     true,
     true},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
     kSSES8x8Reverse,
     kAVXS8x8Reverse,
     true,
     true},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
     kSSES8x4Reverse,
     kAVXS8x4Reverse,
     true,
     true},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kSSES8x2Reverse,
     kAVXS8x2Reverse,
     true,
     true}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         const ShuffleEntry** arch_shuffle) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; ++i) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; ++j) {
      if ((entry.shuffle[j] & mask) != (shuffle[j] & mask)) {
        break;
      }
    }
    if (j == kSimd128Size) {
      *arch_shuffle = &entry;
      return true;
    }
  }
  return false;
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);

  int imm_count = 0;
  static const int kMaxImms = 6;
  uint32_t imms[kMaxImms];
  int temp_count = 0;
  static const int kMaxTemps = 2;
  InstructionOperand temps[kMaxTemps];

  IA32OperandGeneratorT<Adapter> g(this);
  bool use_avx = CpuFeatures::IsSupported(AVX);
  // AVX and swizzles don't generally need DefineSameAsFirst to avoid a move.
  bool no_same_as_first = use_avx || is_swizzle;
  // We generally need UseRegister for input0, Use for input1.
  // TODO(v8:9198): We don't have 16-byte alignment for SIMD operands yet, but
  // we retain this logic (continue setting these in the various shuffle match
  // clauses), but ignore it when selecting registers or slots.
  bool src0_needs_reg = true;
  bool src1_needs_reg = false;
  ArchOpcode opcode = kIA32I8x16Shuffle;  // general shuffle is the default

  uint8_t offset;
  uint8_t shuffle32x4[4];
  uint8_t shuffle16x8[8];
  int index;
  const ShuffleEntry* arch_shuffle;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    if (wasm::SimdShuffle::TryMatch32x4Rotate(shuffle, shuffle32x4,
                                              is_swizzle)) {
      uint8_t shuffle_mask = wasm::SimdShuffle::PackShuffle4(shuffle32x4);
      opcode = kIA32S32x4Rotate;
      imms[imm_count++] = shuffle_mask;
    } else {
      // Swap inputs from the normal order for (v)palignr.
      SwapShuffleInputs(view);
      is_swizzle = false;  // It's simpler to just handle the general case.
      no_same_as_first = use_avx;  // SSE requires same-as-first.
      opcode = kIA32S8x16Alignr;
      // palignr takes a single imm8 offset.
      imms[imm_count++] = offset;
    }
  } else if (TryMatchArchShuffle(shuffle, arch_shuffles,
                                 arraysize(arch_shuffles), is_swizzle,
                                 &arch_shuffle)) {
    opcode = use_avx ? arch_shuffle->avx_opcode : arch_shuffle->opcode;
    src0_needs_reg = !use_avx || arch_shuffle->src0_needs_reg;
    // SSE can't take advantage of both operands in registers and needs
    // same-as-first.
    src1_needs_reg = use_avx && arch_shuffle->src1_needs_reg;
    no_same_as_first = use_avx;
  } else if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    uint8_t shuffle_mask = wasm::SimdShuffle::PackShuffle4(shuffle32x4);
    if (is_swizzle) {
      if (wasm::SimdShuffle::TryMatchIdentity(shuffle)) {
        // Bypass normal shuffle code generation in this case.
        node_t input = view.input(0);
        // EmitIdentity
        MarkAsUsed(input);
        MarkAsDefined(node);
        SetRename(node, input);
        return;
      } else {
        // pshufd takes a single imm8 shuffle mask.
        opcode = kIA32S32x4Swizzle;
        no_same_as_first = true;
        // TODO(v8:9198): This doesn't strictly require a register, forcing the
        // swizzles to always use registers until generation of incorrect memory
        // operands can be fixed.
        src0_needs_reg = true;
        imms[imm_count++] = shuffle_mask;
      }
    } else {
      // 2 operand shuffle
      // A blend is more efficient than a general 32x4 shuffle; try it first.
      if (wasm::SimdShuffle::TryMatchBlend(shuffle)) {
        opcode = kIA32S16x8Blend;
        uint8_t blend_mask = wasm::SimdShuffle::PackBlend4(shuffle32x4);
        imms[imm_count++] = blend_mask;
      } else {
        opcode = kIA32S32x4Shuffle;
        no_same_as_first = true;
        // TODO(v8:9198): src0 and src1 is used by pshufd in codegen, which
        // requires memory to be 16-byte aligned, since we cannot guarantee that
        // yet, force using a register here.
        src0_needs_reg = true;
        src1_needs_reg = true;
        imms[imm_count++] = shuffle_mask;
        int8_t blend_mask = wasm::SimdShuffle::PackBlend4(shuffle32x4);
        imms[imm_count++] = blend_mask;
      }
    }
  } else if (wasm::SimdShuffle::TryMatch16x8Shuffle(shuffle, shuffle16x8)) {
    uint8_t blend_mask;
    if (wasm::SimdShuffle::TryMatchBlend(shuffle)) {
      opcode = kIA32S16x8Blend;
      blend_mask = wasm::SimdShuffle::PackBlend8(shuffle16x8);
      imms[imm_count++] = blend_mask;
    } else if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
      opcode = kIA32S16x8Dup;
      src0_needs_reg = false;
      imms[imm_count++] = index;
    } else if (TryMatch16x8HalfShuffle(shuffle16x8, &blend_mask)) {
      opcode = is_swizzle ? kIA32S16x8HalfShuffle1 : kIA32S16x8HalfShuffle2;
      // Half-shuffles don't need DefineSameAsFirst or UseRegister(src0).
      no_same_as_first = true;
      src0_needs_reg = false;
      uint8_t mask_lo = wasm::SimdShuffle::PackShuffle4(shuffle16x8);
      uint8_t mask_hi = wasm::SimdShuffle::PackShuffle4(shuffle16x8 + 4);
      imms[imm_count++] = mask_lo;
      imms[imm_count++] = mask_hi;
      if (!is_swizzle) imms[imm_count++] = blend_mask;
    }
  } else if (wasm::SimdShuffle::TryMatchSplat<16>(shuffle, &index)) {
    opcode = kIA32S8x16Dup;
    no_same_as_first = use_avx;
    src0_needs_reg = true;
    imms[imm_count++] = index;
  }
  if (opcode == kIA32I8x16Shuffle) {
    // Use same-as-first for general swizzle, but not shuffle.
    no_same_as_first = !is_swizzle;
    src0_needs_reg = !no_same_as_first;
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 4);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 8);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 12);
    temps[temp_count++] = g.TempRegister();
  }

  // Use DefineAsRegister(node) and Use(src0) if we can without forcing an extra
  // move instruction in the CodeGenerator.
  node_t input0 = view.input(0);
  InstructionOperand dst =
      no_same_as_first ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  // TODO(v8:9198): Use src0_needs_reg when we have memory alignment for SIMD.
  InstructionOperand src0 = g.UseRegister(input0);
  USE(src0_needs_reg);

  int input_count = 0;
  InstructionOperand inputs[2 + kMaxImms + kMaxTemps];
  inputs[input_count++] = src0;
  if (!is_swizzle) {
    node_t input1 = view.input(1);
    // TODO(v8:9198): Use src1_needs_reg when we have memory alignment for SIMD.
    inputs[input_count++] = g.UseRegister(input1);
    USE(src1_needs_reg);
  }
  for (int i = 0; i < imm_count; ++i) {
    inputs[input_count++] = g.UseImmediate(imms[i]);
  }
  Emit(opcode, 1, &dst, input_count, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  InstructionCode op = kIA32I8x16Swizzle;

  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128BinopOp& binop =
        this->Get(node).template Cast<turboshaft::Simd128BinopOp>();
    DCHECK(binop.kind ==
           turboshaft::any_of(
               turboshaft::Simd128BinopOp::Kind::kI8x16Swizzle,
               turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle));
    bool relaxed =
        binop.kind == turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle;
    if (relaxed) {
      op |= MiscField::encode(true);
    } else {
      // If the indices vector is a const, check if they are in range, or if the
      // top bit is set, then we can avoid the paddusb in the codegen and simply
      // emit a pshufb.
      const turboshaft::Operation& right_op = this->Get(right);
      if (auto c = right_op.TryCast<turboshaft::Simd128ConstantOp>()) {
        std::array<uint8_t, kSimd128Size> imms;
        std::memcpy(&imms, c->value, kSimd128Size);
        op |= MiscField::encode(wasm::SimdSwizzle::AllInRangeOrTopBitSet(imms));
      }
    }
  } else {
    // Turbofan.
    bool relaxed = OpParameter<bool>(node->op());
    if (relaxed) {
      op |= MiscField::encode(true);
    } else {
      auto m = V128ConstMatcher(node->InputAt(1));
      if (m.HasResolvedValue()) {
        // If the indices vector is a const, check if they are in range, or if
        // the top bit is set, then we can avoid the paddusb in the codegen and
        // simply emit a pshufb.
        auto imms = m.ResolvedValue().immediate();
        op |= MiscField::encode(wasm::SimdSwizzle::AllInRangeOrTopBitSet(imms));
      }
    }
  }

  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(op,
       IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseAny(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

namespace {

template <typename Adapter>
void VisitMinOrMax(InstructionSelectorT<Adapter>* selector,
                   typename Adapter::node_t node, ArchOpcode opcode,
                   bool flip_inputs) {
  // Due to the way minps/minpd work, we want the dst to be same as the second
  // input: b = pmin(a, b) directly maps to minps b a.
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand dst = selector->IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  if (flip_inputs) {
    // Due to the way minps/minpd work, we want the dst to be same as the second
    // input: b = pmin(a, b) directly maps to minps b a.
    selector->Emit(opcode, dst, g.UseRegister(selector->input_at(node, 1)),
                   g.UseRegister(selector->input_at(node, 0)));
  } else {
    selector->Emit(opcode, dst, g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitMinOrMax(this, node, kIA32Minps, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitMinOrMax(this, node, kIA32Maxps, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitMinOrMax(this, node, kIA32Minpd, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitMinOrMax(this, node, kIA32Maxpd, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4RelaxedMin(node_t node) {
  VisitMinOrMax(this, node, kIA32Minps, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4RelaxedMax(node_t node) {
  VisitMinOrMax(this, node, kIA32Maxps, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMin(node_t node) {
  VisitMinOrMax(this, node, kIA32Minpd, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMax(node_t node) {
  VisitMinOrMax(this, node, kIA32Maxpd, false);
}

namespace {

template <typename Adapter>
void VisitExtAddPairwise(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         bool need_temp) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand dst = (selector->IsSupported(AVX))
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  if (need_temp) {
    InstructionOperand temps[] = {g.TempRegister()};
    selector->Emit(opcode, dst, operand0, arraysize(temps), temps);
  } else {
    selector->Emit(opcode, dst, operand0);
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8S(
    node_t node) {
  VisitExtAddPairwise(this, node, kIA32I32x4ExtAddPairwiseI16x8S, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8U(
    node_t node) {
  VisitExtAddPairwise(this, node, kIA32I32x4ExtAddPairwiseI16x8U, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16S(
    node_t node) {
  VisitExtAddPairwise(this, node, kIA32I16x8ExtAddPairwiseI8x16S, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16U(
    node_t node) {
  VisitExtAddPairwise(this, node, kIA32I16x8ExtAddPairwiseI8x16U, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Popcnt(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand dst = CpuFeatures::IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineAsRegister(node);
  InstructionOperand temps[] = {g.TempSimd128Register(), g.TempRegister()};
  Emit(kIA32I8x16Popcnt, dst, g.UseUniqueRegister(this->input_at(node, 0)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ConvertLowI32x4U(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32F64x2ConvertLowI32x4U, dst, g.UseRegister(this->input_at(node, 0)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2SZero(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  if (IsSupported(AVX)) {
    // Requires dst != src.
    Emit(kIA32I32x4TruncSatF64x2SZero, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), temps);
  } else {
    Emit(kIA32I32x4TruncSatF64x2SZero, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2UZero(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32I32x4TruncSatF64x2UZero, dst,
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2SZero(
    node_t node) {
  VisitRRSimd(this, node, kIA32Cvttpd2dq);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2UZero(
    node_t node) {
  VisitFloatUnop(this, node, this->input_at(node, 0),
                 kIA32I32x4TruncF64x2UZero);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF32x4S(node_t node) {
  VisitRRSimd(this, node, kIA32Cvttps2dq);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF32x4U(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  node_t input = this->input_at(node, 0);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  // No need for unique because inputs are float but temp is general.
  if (IsSupported(AVX)) {
    Emit(kIA32I32x4TruncF32x4U, g.DefineAsRegister(node), g.UseRegister(input),
         arraysize(temps), temps);
  } else {
    Emit(kIA32I32x4TruncF32x4U, g.DefineSameAsFirst(node), g.UseRegister(input),
         arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2GtS(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  if (CpuFeatures::IsSupported(AVX)) {
    Emit(kIA32I64x2GtS, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    Emit(kIA32I64x2GtS, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else {
    Emit(kIA32I64x2GtS, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2GeS(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  if (CpuFeatures::IsSupported(AVX)) {
    Emit(kIA32I64x2GeS, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    Emit(kIA32I64x2GeS, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else {
    Emit(kIA32I64x2GeS, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Abs(node_t node) {
  VisitRRSimd(this, node, kIA32I64x2Abs, kIA32I64x2Abs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2PromoteLowF32x4(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionCode code = kIA32F64x2PromoteLowF32x4;
  node_t input = this->input_at(node, 0);
  if constexpr (Adapter::IsTurboshaft) {
    // TODO(nicohartmann@): Implement this special case for turboshaft. Note
    // that this special case may require adaptions in instruction-selector.cc
    // in `FinishEmittedInstructions`, similar to what exists for TurboFan.
  } else {
    LoadTransformMatcher m(input);

    if (m.Is(LoadTransformation::kS128Load64Zero) && CanCover(node, input)) {
      // Trap handler is not supported on IA32.
      DCHECK_NE(m.ResolvedValue().kind,
                MemoryAccessKind::kProtectedByTrapHandler);
      // LoadTransforms cannot be eliminated, so they are visited even if
      // unused. Mark it as defined so that we don't visit it.
      MarkAsDefined(input);
      VisitLoad(node, input, code);
      return;
    }
  }

  VisitRR(this, node, code);
}

namespace {
template <typename Adapter>
void VisitRelaxedLaneSelect(InstructionSelectorT<Adapter>* selector,
                            typename Adapter::node_t node,
                            InstructionCode code = kIA32Pblendvb) {
  IA32OperandGeneratorT<Adapter> g(selector);
  // pblendvb/blendvps/blendvpd copies src2 when mask is set, opposite from Wasm
  // semantics. node's inputs are: mask, lhs, rhs (determined in
  // wasm-compiler.cc).
  if (selector->IsSupported(AVX)) {
    selector->Emit(code, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 2)),
                   g.UseRegister(selector->input_at(node, 1)),
                   g.UseRegister(selector->input_at(node, 0)));
  } else {
    // SSE4.1 pblendvb/blendvps/blendvpd requires xmm0 to hold the mask as an
    // implicit operand.
    selector->Emit(code, g.DefineSameAsFirst(node),
                   g.UseRegister(selector->input_at(node, 2)),
                   g.UseRegister(selector->input_at(node, 1)),
                   g.UseFixed(selector->input_at(node, 0), xmm0));
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node, kIA32Blendvps);
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node, kIA32Blendvpd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Qfma(node_t node) {
  VisitRRRR(this, node, kIA32F64x2Qfma);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Qfms(node_t node) {
  VisitRRRR(this, node, kIA32F64x2Qfms);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Qfma(node_t node) {
  VisitRRRR(this, node, kIA32F32x4Qfma);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Qfms(node_t node) {
  VisitRRRR(this, node, kIA32F32x4Qfms);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Qfma(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Qfms(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kIA32I16x8DotI8x16I7x16S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kIA32I32x4DotI8x16I7x16AddS, g.DefineSameAsInput(node, 2),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)),
       g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGeneratorT<Adapter>* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags =
      MachineOperatorBuilder::kWord32ShiftIsSafe |
      MachineOperatorBuilder::kWord32Ctz | MachineOperatorBuilder::kWord32Rol;
  if (CpuFeatures::IsSupported(POPCNT)) {
    flags |= MachineOperatorBuilder::kWord32Popcnt;
  }
  if (CpuFeatures::IsSupported(SSE4_1)) {
    flags |= MachineOperatorBuilder::kFloat32RoundDown |
             MachineOperatorBuilder::kFloat64RoundDown |
             MachineOperatorBuilder::kFloat32RoundUp |
             MachineOperatorBuilder::kFloat64RoundUp |
             MachineOperatorBuilder::kFloat32RoundTruncate |
             MachineOperatorBuilder::kFloat64RoundTruncate |
             MachineOperatorBuilder::kFloat32RoundTiesEven |
             MachineOperatorBuilder::kFloat64RoundTiesEven;
  }
  return flags;
}

// static
MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
  return MachineOperatorBuilder::AlignmentRequirements::
      FullUnalignedAccessSupport();
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```