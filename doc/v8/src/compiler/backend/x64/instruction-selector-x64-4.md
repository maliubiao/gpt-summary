Response: The user wants to understand the functionality of the C++ code provided, which is a part of the V8 JavaScript engine. Specifically, they are interested in how this code contributes to the compilation process and if it has any direct relation to JavaScript features.

**Plan:**

1. **Identify the core purpose of the file:** Based on the file name (`instruction-selector-x64.cc`) and the context (part 5 of 5), it's clear that this file is responsible for selecting specific x64 machine instructions for operations represented in an intermediate representation (likely from Turbofan or Turboshaft, the V8 compilers).

2. **Analyze the code structure:** The code is organized as a template class `InstructionSelectorT` parameterized by an `Adapter` type (likely distinguishing between Turbofan and Turboshaft). It contains many `Visit` methods for different operation types (e.g., `VisitS128Select`, `VisitI8x16Shuffle`).

3. **Summarize the functionality:** The `InstructionSelectorT` class takes high-level operations and translates them into low-level x64 instructions. This involves:
    * **Pattern Matching:** Recognizing specific operation patterns and choosing optimal instruction sequences.
    * **Operand Generation:** Creating operands (registers, immediates, memory locations) for the selected instructions.
    * **Instruction Emission:** Generating the actual machine code instructions.
    * **Handling SIMD:**  A significant portion of the code deals with SIMD (Single Instruction, Multiple Data) operations, crucial for performance in JavaScript.
    * **Handling different CPU features:** The code checks for CPU feature support (like AVX, SSE4.1, etc.) to utilize the most efficient instructions.
    * **Handling WebAssembly:**  Specific sections are dedicated to WebAssembly operations.

4. **Relate to JavaScript functionality:**  The operations handled in this file directly correspond to JavaScript language features, particularly those involving:
    * **SIMD:**  JavaScript's SIMD API maps directly to the SIMD operations being compiled here.
    * **Mathematical Operations:**  Basic arithmetic, logical, and bitwise operations.
    * **WebAssembly:** When JavaScript interacts with WebAssembly, the WebAssembly instructions need to be translated to machine code.

5. **Provide a JavaScript example:** Illustrate the connection between a JavaScript SIMD operation and the corresponding C++ code.

**Self-Correction during thought process:**

* Initially, I might focus solely on the x64 instruction selection aspect. However, the prompt specifically asks about the relationship with JavaScript. Therefore, I need to explicitly connect the compiled operations back to JavaScript features.
* The "part 5 of 5" hints that this is the final stage of instruction selection or a related process. This reinforces the idea that this code generates the final machine instructions.
* The presence of both `TurbofanAdapter` and `TurboshaftAdapter` suggests that the instruction selection logic might have some differences depending on the compiler pipeline used.

By following these steps, I can construct a comprehensive and accurate summary of the provided C++ code.
这是 `v8/src/compiler/backend/x64/instruction-selector-x64.cc` 文件的第五部分，也是最后一部分。综合之前的部分，这个文件的主要功能是 **将 V8 编译器（Turbofan 或 Turboshaft）生成的中间表示（IR）代码，针对 x64 架构，选择并生成对应的机器指令**。

作为最后一部分，这部分代码主要涵盖了以下功能：

1. **SIMD (Single Instruction, Multiple Data) 指令的选择和生成：** 包含了大量针对不同 SIMD 操作（例如，`S128Select`, `S128AndNot`, `F64x2Abs`, `I8x16Shuffle` 等）的 `Visit` 方法。这些方法负责识别 IR 中的 SIMD 操作，并选择合适的 x64 SIMD 指令（例如，SSE、AVX 等指令集中的指令）来实现这些操作。
2. **WebAssembly SIMD 指令的支持：**  代码中存在 `#ifdef V8_ENABLE_WEBASSEMBLY` 的条件编译块，表明这部分代码也负责处理 WebAssembly 中的 SIMD 指令。例如，`VisitI8x16Shuffle` 方法中有针对 WebAssembly SIMD shuffle 操作的具体实现。
3. **处理特殊的算术和逻辑运算：**  例如，`VisitInt32AbsWithOverflow` 和 `VisitInt64AbsWithOverflow` 虽然目前 `UNREACHABLE()`，但表明代码结构上考虑了这些可能需要特殊处理的情况。
4. **指令的优化：**  代码中可以看到针对特定模式的优化，例如 `VisitS128Select` 中对于选择常量的优化。
5. **与 Turboshaft 和 Turbofan 编译器的适配：** 通过模板类 `InstructionSelectorT` 和不同的 `Adapter` 类型（`TurbofanAdapter` 和 `TurboshaftAdapter`），代码能够适应 V8 中两种不同的编译器 pipeline。
6. **处理栈指针操作：**  `VisitSetStackPointer` 方法用于生成设置栈指针的指令。
7. **定义支持的机器操作符标志：** `SupportedMachineOperatorFlags` 函数定义了当前指令选择器支持的机器操作符标志，这决定了 V8 编译器能够处理哪些高级操作。
8. **定义内存对齐要求：** `AlignmentRequirements` 函数定义了内存对齐的要求。

**与 JavaScript 的关系及 JavaScript 示例：**

这个文件的功能直接关系到 JavaScript 的执行性能。当 JavaScript 代码（特别是涉及到大量数值计算或并行处理的代码）使用到 SIMD API 时，这个文件中的代码就负责将这些高级的 SIMD 操作翻译成底层的、高效的 x64 SIMD 指令。

**JavaScript 示例（使用 SIMD API）：**

```javascript
// 创建两个 Float32x4 类型的 SIMD 值
const a = SIMD.Float32x4(1.0, 2.0, 3.0, 4.0);
const b = SIMD.Float32x4(5.0, 6.0, 7.0, 8.0);

// 执行 SIMD 加法
const sum = SIMD.Float32x4.add(a, b);

console.log(sum); // 输出: Float32x4(6, 8, 10, 12)
```

在这个 JavaScript 示例中，`SIMD.Float32x4.add(a, b)` 操作会在 V8 编译器的处理过程中，最终由 `instruction-selector-x64.cc` 文件中的相关 `Visit` 方法（例如，可能类似于一个通用的 `VisitSIMDBinaryOp` 方法，然后根据操作类型和数据类型选择具体的指令）翻译成 x64 的 SIMD 加法指令，例如 `addps` (SSE) 或 `vaddps` (AVX)。

**总结来说，`v8/src/compiler/backend/x64/instruction-selector-x64.cc` 文件的这最后一部分以及整个文件，是 V8 编译器将高级的、平台无关的中间表示代码转换为可以在 x64 架构上高效执行的机器代码的关键组成部分，特别是对于 JavaScript 的 SIMD 功能和 WebAssembly 的支持至关重要。**

### 提示词
```
这是目录为v8/src/compiler/backend/x64/instruction-selector-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```
e paddusb in the codegen and simply
    // emit a pshufb.
    *constant = m.ResolvedValue().immediate();
    return true;
  }
  return false;
}

static bool MatchSimd128Constant(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex node,
    std::array<uint8_t, kSimd128Size>* constant) {
  DCHECK_NOT_NULL(constant);
  const turboshaft::Operation& op = selector->Get(node);
  if (auto c = op.TryCast<turboshaft::Simd128ConstantOp>()) {
    std::memcpy(constant, c->value, kSimd128Size);
    return true;
  }
  return false;
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 3);

  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  if (IsV128ZeroConst(this, this->input_at(node, 2))) {
    // select(cond, input1, 0) -> and(cond, input1)
    Emit(kX64SAnd | VectorLengthField::encode(kV128), dst,
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else if (IsV128ZeroConst(this, this->input_at(node, 1))) {
    // select(cond, 0, input2) -> and(not(cond), input2)
    Emit(kX64SAndNot | VectorLengthField::encode(kV128), dst,
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  } else {
    Emit(kX64SSelect | VectorLengthField::encode(kV128), dst,
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitS256Select(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  Emit(kX64SSelect | VectorLengthField::encode(kV256), g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitS256Select(node_t node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  Emit(kX64SSelect | VectorLengthField::encode(kV256), g.DefineAsRegister(node),
       g.UseRegister(node->InputAt(0)), g.UseRegister(node->InputAt(1)),
       g.UseRegister(node->InputAt(2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128AndNot(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  // andnps a b does ~a & b, but we want a & !b, so flip the input.
  Emit(kX64SAndNot | VectorLengthField::encode(kV128),
       IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS256AndNot(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  // andnps a b does ~a & b, but we want a & !b, so flip the input.
  Emit(kX64SAndNot | VectorLengthField::encode(kV256),
       IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Abs(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0),
                 kX64FAbs | LaneSizeField::encode(kL64) |
                     VectorLengthField::encode(kV128));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Neg(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0),
                 kX64FNeg | LaneSizeField::encode(kL64) |
                     VectorLengthField::encode(kV128));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4UConvertI32x4(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  node_t value = this->input_at(node, 0);

  // F32x4SConvertI32x4 is more efficient than F32x4UConvertI32x4 on x64,
  // if the u32x4 input can fit into i32x4, we can use F32x4SConvertI32x4
  // instead. Input node with I32x4UConvertI16x8Low/I32x4UConvertI16x8High
  // opcode is one of this kinds.
  bool can_use_sign_convert = false;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    if (const Simd128UnaryOp* unop =
            this->Get(value).template TryCast<Simd128UnaryOp>()) {
      if (unop->kind == Simd128UnaryOp::Kind::kI32x4UConvertI16x8Low ||
          unop->kind == Simd128UnaryOp::Kind::kI32x4UConvertI16x8High) {
        can_use_sign_convert = true;
      }
    }
  } else {
    if (value->opcode() == IrOpcode::kI32x4UConvertI16x8Low ||
        value->opcode() == IrOpcode::kI32x4UConvertI16x8High) {
      can_use_sign_convert = true;
    }
  }

  if (can_use_sign_convert) {
    Emit(kX64F32x4SConvertI32x4, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    Emit(kX64F32x4UConvertI32x4, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

#define VISIT_SIMD_QFMOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    X64OperandGeneratorT<Adapter> g(this);                         \
    DCHECK_EQ(this->value_input_count(node), 3);                   \
    Emit(kX64##Opcode, g.UseRegister(node),                        \
         g.UseRegister(this->input_at(node, 0)),                   \
         g.UseRegister(this->input_at(node, 1)),                   \
         g.UseRegister(this->input_at(node, 2)));                  \
  }
VISIT_SIMD_QFMOP(F64x2Qfma)
VISIT_SIMD_QFMOP(F64x2Qfms)
VISIT_SIMD_QFMOP(F32x4Qfma)
VISIT_SIMD_QFMOP(F32x4Qfms)

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
VISIT_SIMD_QFMOP(F64x4Qfma)
VISIT_SIMD_QFMOP(F64x4Qfms)
VISIT_SIMD_QFMOP(F32x8Qfma)
VISIT_SIMD_QFMOP(F32x8Qfms)
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
#undef VISIT_SIMD_QFMOP

#define VISIT_SIMD_F16x8_QFMOP(Opcode)                                   \
  template <typename Adapter>                                            \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {       \
    X64OperandGeneratorT<Adapter> g(this);                               \
    DCHECK_EQ(this->value_input_count(node), 3);                         \
    InstructionOperand temps[] = {g.TempSimd256Register(),               \
                                  g.TempSimd256Register()};              \
    Emit(kX64##Opcode, g.UseRegister(node),                              \
         g.UseUniqueRegister(this->input_at(node, 0)),                   \
         g.UseUniqueRegister(this->input_at(node, 1)),                   \
         g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), \
         temps);                                                         \
  }

VISIT_SIMD_F16x8_QFMOP(F16x8Qfma) VISIT_SIMD_F16x8_QFMOP(F16x8Qfms)
#undef VISIT_SIMD_F16x8_QFMOP

    template <typename Adapter>
    void InstructionSelectorT<Adapter>::VisitI64x2Neg(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  // If AVX unsupported, make sure dst != src to avoid a move.
  InstructionOperand operand0 =
      IsSupported(AVX) ? g.UseRegister(this->input_at(node, 0))
                       : g.UseUniqueRegister(this->input_at(node, 0));
  Emit(
      kX64INeg | LaneSizeField::encode(kL64) | VectorLengthField::encode(kV128),
      g.DefineAsRegister(node), operand0);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ShrS(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);

  if (g.CanBeImmediate(this->input_at(node, 1))) {
    Emit(kX64IShrS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         dst, g.UseRegister(this->input_at(node, 0)),
         g.UseImmediate(this->input_at(node, 1)));
  } else {
    InstructionOperand temps[] = {g.TempSimd128Register()};
    Emit(kX64IShrS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         dst, g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Mul(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(
      kX64IMul | LaneSizeField::encode(kL64) | VectorLengthField::encode(kV128),
      g.DefineAsRegister(node), g.UseUniqueRegister(this->input_at(node, 0)),
      g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x4Mul(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  InstructionOperand temps[] = {g.TempSimd256Register()};
  Emit(
      kX64IMul | LaneSizeField::encode(kL64) | VectorLengthField::encode(kV256),
      g.DefineAsRegister(node), g.UseUniqueRegister(this->input_at(node, 0)),
      g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertF32x4(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64I32x4SConvertF32x4,
       IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8SConvertF32x8(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64I32x8SConvertF32x8, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertF32x4(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand temps[] = {g.TempSimd128Register(),
                                g.TempSimd128Register()};
  Emit(kX64I32x4UConvertF32x4, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8UConvertF32x8(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand temps[] = {g.TempSimd256Register(),
                                g.TempSimd256Register()};
  Emit(kX64I32x8UConvertF32x8, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitExtractF128(node_t node) {
  X64OperandGeneratorT<TurbofanAdapter> g(this);
  int32_t lane = OpParameter<int32_t>(node->op());
  if (lane == 0) {
    EmitIdentity(node);
  } else {
    Emit(kX64ExtractF128, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.UseImmediate(lane));
  }
}

#if V8_ENABLE_WASM_SIMD256_REVEC
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x8UConvertI32x8(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);

  node_t value = this->input_at(node, 0);

  // F32x8SConvertI32x8 is more efficient than F32x8UConvertI32x8 on x64.
  bool can_use_sign_convert = false;
  if constexpr (Adapter::IsTurboshaft) {
    if (this->Get(value)
            .template Is<turboshaft::Opmask::kSimd256I32x8UConvertI16x8>()) {
      can_use_sign_convert = true;
    }
  } else {
    if (value->opcode() == IrOpcode::kI32x8UConvertI16x8) {
      can_use_sign_convert = true;
    }
  }

  if (can_use_sign_convert) {
    Emit(kX64F32x8SConvertI32x8, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    Emit(kX64F32x8UConvertI32x8, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitExtractF128(node_t node) {
  X64OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::Simd256Extract128LaneOp& op =
      this->Get(node).template Cast<turboshaft::Simd256Extract128LaneOp>();
  if (op.lane == 0) {
    EmitIdentity(node);
  } else {
    Emit(kX64ExtractF128, g.DefineAsRegister(node), g.UseRegister(op.input()),
         g.UseImmediate(op.lane));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI8x32Shuffle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
#endif

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

bool TryMatchShufps(const uint8_t* shuffle32x4) {
  DCHECK_GT(8, shuffle32x4[2]);
  DCHECK_GT(8, shuffle32x4[3]);
  // shufps can be used if the first 2 indices select the first input [0-3], and
  // the other 2 indices select the second input [4-7].
  return shuffle32x4[0] < 4 && shuffle32x4[1] < 4 && shuffle32x4[2] > 3 &&
         shuffle32x4[3] > 3;
}

template <typename Adapter>
static bool TryMatchOneInputIsZeros(InstructionSelectorT<Adapter>* selector,
                                    typename Adapter::SimdShuffleView& view,
                                    uint8_t* shuffle, bool* needs_swap) {
  *needs_swap = false;
  bool input0_is_zero = IsV128ZeroConst(selector, view.input(0));
  bool input1_is_zero = IsV128ZeroConst(selector, view.input(1));
  if (!input0_is_zero && !input1_is_zero) {
    return false;
  }

  if (input0_is_zero) {
    *needs_swap = true;
  }
  return true;
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

  X64OperandGeneratorT<Adapter> g(this);
  // Swizzles don't generally need DefineSameAsFirst to avoid a move.
  bool no_same_as_first = is_swizzle;
  // We generally need UseRegister for input0, Use for input1.
  // TODO(v8:9198): We don't have 16-byte alignment for SIMD operands yet, but
  // we retain this logic (continue setting these in the various shuffle match
  // clauses), but ignore it when selecting registers or slots.
  bool src0_needs_reg = true;
  bool src1_needs_reg = false;
  ArchOpcode opcode = kX64I8x16Shuffle;  // general shuffle is the default

  uint8_t offset;
  uint8_t shuffle32x4[4];
  uint8_t shuffle16x8[8];
  int index;
  const wasm::ShuffleEntry<kSimd128Size>* arch_shuffle;
  bool needs_swap;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    if (wasm::SimdShuffle::TryMatch32x4Rotate(shuffle, shuffle32x4,
                                              is_swizzle)) {
      uint8_t shuffle_mask = wasm::SimdShuffle::PackShuffle4(shuffle32x4);
      opcode = kX64S32x4Rotate;
      imms[imm_count++] = shuffle_mask;
    } else {
      // Swap inputs from the normal order for (v)palignr.
      SwapShuffleInputs(view);
      is_swizzle = false;  // It's simpler to just handle the general case.
      no_same_as_first = CpuFeatures::IsSupported(AVX);
      // TODO(v8:9608): also see v8:9083
      src1_needs_reg = true;
      opcode = kX64S8x16Alignr;
      // palignr takes a single imm8 offset.
      imms[imm_count++] = offset;
    }
  } else if (wasm::SimdShuffle::TryMatchArchShuffle(shuffle, is_swizzle,
                                                    &arch_shuffle)) {
    opcode = arch_shuffle->opcode;
    src0_needs_reg = arch_shuffle->src0_needs_reg;
    // SSE can't take advantage of both operands in registers and needs
    // same-as-first.
    src1_needs_reg = arch_shuffle->src1_needs_reg;
    no_same_as_first =
        IsSupported(AVX) && arch_shuffle->no_same_as_first_if_avx;
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
        opcode = kX64S32x4Swizzle;
        no_same_as_first = true;
        // TODO(v8:9083): This doesn't strictly require a register, forcing the
        // swizzles to always use registers until generation of incorrect memory
        // operands can be fixed.
        src0_needs_reg = true;
        imms[imm_count++] = shuffle_mask;
      }
    } else {
      // 2 operand shuffle
      // A blend is more efficient than a general 32x4 shuffle; try it first.
      if (wasm::SimdShuffle::TryMatchBlend(shuffle)) {
        opcode = kX64S16x8Blend;
        uint8_t blend_mask = wasm::SimdShuffle::PackBlend4(shuffle32x4);
        imms[imm_count++] = blend_mask;
        no_same_as_first = CpuFeatures::IsSupported(AVX);
      } else if (TryMatchShufps(shuffle32x4)) {
        opcode = kX64Shufps;
        uint8_t mask = wasm::SimdShuffle::PackShuffle4(shuffle32x4);
        imms[imm_count++] = mask;
        src1_needs_reg = true;
        no_same_as_first = IsSupported(AVX);
      } else {
        opcode = kX64S32x4Shuffle;
        no_same_as_first = true;
        // TODO(v8:9083): src0 and src1 is used by pshufd in codegen, which
        // requires memory to be 16-byte aligned, since we cannot guarantee that
        // yet, force using a register here.
        src0_needs_reg = true;
        src1_needs_reg = true;
        imms[imm_count++] = shuffle_mask;
        uint8_t blend_mask = wasm::SimdShuffle::PackBlend4(shuffle32x4);
        imms[imm_count++] = blend_mask;
      }
    }
  } else if (wasm::SimdShuffle::TryMatch16x8Shuffle(shuffle, shuffle16x8)) {
    uint8_t blend_mask;
    if (wasm::SimdShuffle::TryMatchBlend(shuffle)) {
      opcode = kX64S16x8Blend;
      blend_mask = wasm::SimdShuffle::PackBlend8(shuffle16x8);
      imms[imm_count++] = blend_mask;
      no_same_as_first = CpuFeatures::IsSupported(AVX);
    } else if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
      opcode = kX64S16x8Dup;
      src0_needs_reg = false;
      imms[imm_count++] = index;
    } else if (TryMatch16x8HalfShuffle(shuffle16x8, &blend_mask)) {
      opcode = is_swizzle ? kX64S16x8HalfShuffle1 : kX64S16x8HalfShuffle2;
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
    opcode = kX64S8x16Dup;
    no_same_as_first = false;
    src0_needs_reg = true;
    imms[imm_count++] = index;
  } else if (TryMatchOneInputIsZeros(this, view, shuffle, &needs_swap)) {
    is_swizzle = true;
    // Swap zeros to input1
    if (needs_swap) {
      SwapShuffleInputs(view);
      for (int i = 0; i < kSimd128Size; ++i) {
        shuffle[i] ^= kSimd128Size;
      }
    }
    if (wasm::SimdShuffle::TryMatchByteToDwordZeroExtend(shuffle)) {
      opcode = kX64I32X4ShiftZeroExtendI8x16;
      no_same_as_first = true;
      src0_needs_reg = true;
      imms[imm_count++] = shuffle[0];
    } else {
      // If the most significant bit (bit 7) of each byte of the shuffle control
      // mask is set, then constant zero is written in the result byte. Input1
      // is zeros now, we can avoid using input1 by setting bit 7 of shuffle[i]
      // to 1.
      for (int i = 0; i < kSimd128Size; ++i) {
        if (shuffle[i] >= kSimd128Size) {
          shuffle[i] = 0x80;
        }
      }
    }
  }
  if (opcode == kX64I8x16Shuffle) {
    // Use same-as-first for general swizzle, but not shuffle.
    no_same_as_first = !is_swizzle;
    src0_needs_reg = !no_same_as_first;
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 4);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 8);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 12);
    temps[temp_count++] = g.TempSimd128Register();
  }

  // Use DefineAsRegister(node) and Use(src0) if we can without forcing an extra
  // move instruction in the CodeGenerator.
  node_t input0 = view.input(0);
  InstructionOperand dst =
      no_same_as_first ? g.DefineAsRegister(view) : g.DefineSameAsFirst(view);
  // TODO(v8:9198): Use src0_needs_reg when we have memory alignment for SIMD.
  // We only need a unique register for input0 if we use temp registers.
  InstructionOperand src0 =
      temp_count ? g.UseUniqueRegister(input0) : g.UseRegister(input0);
  USE(src0_needs_reg);

  int input_count = 0;
  InstructionOperand inputs[2 + kMaxImms + kMaxTemps];
  inputs[input_count++] = src0;
  if (!is_swizzle) {
    node_t input1 = view.input(1);
    // TODO(v8:9198): Use src1_needs_reg when we have memory alignment for SIMD.
    // We only need a unique register for input1 if we use temp registers.
    inputs[input_count++] =
        temp_count ? g.UseUniqueRegister(input1) : g.UseRegister(input1);
    USE(src1_needs_reg);
  }
  for (int i = 0; i < imm_count; ++i) {
    inputs[input_count++] = g.UseImmediate(imms[i]);
  }
  Emit(opcode, 1, &dst, input_count, inputs, temp_count, temps);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI8x32Shuffle(node_t node) {
  uint8_t shuffle[kSimd256Size];
  bool is_swizzle;
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle<kSimd256Size>(view, shuffle, &is_swizzle);

  X64OperandGeneratorT<TurbofanAdapter> g(this);

  if (uint8_t shuffle32x8[8];
      wasm::SimdShuffle::TryMatch32x8Shuffle(shuffle, shuffle32x8)) {
    if (is_swizzle) {
      Node* input0 = node->InputAt(0);
      InstructionOperand dst = g.DefineAsRegister(node);
      InstructionOperand src = g.UseUniqueRegister(input0);
      uint8_t control;
      if (wasm::SimdShuffle::TryMatchVpshufd(shuffle32x8, &control)) {
        InstructionOperand imm = g.UseImmediate(control);
        InstructionOperand inputs[] = {src, imm};
        Emit(kX64Vpshufd, 1, &dst, 2, inputs);
        return;
      }
    }
  }

  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  InstructionCode op = kX64I8x16Swizzle;
  DCHECK_EQ(this->value_input_count(node), 2);
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);

  bool relaxed;
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128BinopOp& binop =
        this->Get(node).template Cast<turboshaft::Simd128BinopOp>();
    DCHECK(binop.kind ==
           turboshaft::any_of(
               turboshaft::Simd128BinopOp::Kind::kI8x16Swizzle,
               turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle));
    relaxed =
        binop.kind == turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle;
  } else {
    relaxed = OpParameter<bool>(node->op());
  }

  if (relaxed) {
    op |= MiscField::encode(true);
  } else {
    std::array<uint8_t, kSimd128Size> imms;
    if (MatchSimd128Constant(this, right, &imms)) {
      // If the indices vector is a const, check if they are in range, or if the
      // top bit is set, then we can avoid the paddusb in the codegen and simply
      // emit a pshufb.
      op |= MiscField::encode(wasm::SimdSwizzle::AllInRangeOrTopBitSet(imms));
    }
  }

  X64OperandGeneratorT<Adapter> g(this);
  Emit(op,
       IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right));
}

namespace {
template <typename Adapter>
void VisitRelaxedLaneSelect(InstructionSelectorT<Adapter>* selector,
                            typename Adapter::node_t node,
                            InstructionCode code) {
  X64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 3);
  // pblendvb/blendvps/blendvpd copies src2 when mask is set, opposite from Wasm
  // semantics. Node's inputs are: mask, lhs, rhs (determined in
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
  VisitRelaxedLaneSelect(this, node,
                         kX64Pblendvb | VectorLengthField::encode(kV128));
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Pblendvb | VectorLengthField::encode(kV128));
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Blendvps | VectorLengthField::encode(kV128));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Blendvpd | VectorLengthField::encode(kV128));
}

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x32RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Pblendvb | VectorLengthField::encode(kV256));
}
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x16RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Pblendvb | VectorLengthField::encode(kV256));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Blendvps | VectorLengthField::encode(kV256));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x4RelaxedLaneSelect(node_t node) {
  VisitRelaxedLaneSelect(this, node,
                         kX64Blendvpd | VectorLengthField::encode(kV256));
}
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Pmin(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionCode instr_code = kX64Minph | VectorLengthField::encode(kV128);
  InstructionOperand temps[] = {g.TempSimd256Register(),
                                g.TempSimd256Register()};
  size_t temp_count = arraysize(temps);

  Emit(instr_code, dst, g.UseUniqueRegister(this->input_at(node, 1)),
       g.UseUniqueRegister(this->input_at(node, 0)), temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Pmax(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  InstructionOperand dst = g.DefineAsRegister(node);
  InstructionCode instr_code = kX64Maxph | VectorLengthField::encode(kV128);
  InstructionOperand temps[] = {g.TempSimd256Register(),
                                g.TempSimd256Register()};
  size_t temp_count = arraysize(temps);

  Emit(instr_code, dst, g.UseUniqueRegister(this->input_at(node, 1)),
       g.UseUniqueRegister(this->input_at(node, 0)), temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8DemoteF64x2Zero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand temps[] = {g.TempRegister(), g.TempSimd128Register(),
                                g.TempSimd128Register()};
  size_t temp_count = arraysize(temps);

  Emit(kX64F16x8DemoteF64x2Zero, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)), temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Minps, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Maxps, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Minpd, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Maxpd, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x8Pmin(node_t node) {
  VisitMinOrMax<Adapter, kV256>(this, node, kX64F32x8Pmin, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x8Pmax(node_t node) {
  VisitMinOrMax<Adapter, kV256>(this, node, kX64F32x8Pmax, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x4Pmin(node_t node) {
  VisitMinOrMax<Adapter, kV256>(this, node, kX64F64x4Pmin, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x4Pmax(node_t node) {
  VisitMinOrMax<Adapter, kV256>(this, node, kX64F64x4Pmax, true);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4RelaxedMin(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Minps, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4RelaxedMax(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Maxps, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMin(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Minpd, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMax(node_t node) {
  VisitMinOrMax<Adapter, kV128>(this, node, kX64Maxpd, false);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8S(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand dst = CpuFeatures::IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  Emit(kX64I32x4ExtAddPairwiseI16x8S, dst,
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8ExtAddPairwiseI16x16S(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64I32x8ExtAddPairwiseI16x16S, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8U(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand dst = CpuFeatures::IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  Emit(kX64I32x4ExtAddPairwiseI16x8U, dst,
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8ExtAddPairwiseI16x16U(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64I32x8ExtAddPairwiseI16x16U, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16S(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  // Codegen depends on dst != src.
  Emit(kX64I16x8ExtAddPairwiseI8x16S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x16ExtAddPairwiseI8x32S(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kX64I16x16ExtAddPairwiseI8x32S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16U(
    node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand dst = CpuFeatures::IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  Emit(kX64I16x8ExtAddPairwiseI8x16U, dst,
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x16ExtAddPairwiseI8x32U(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  Emit(kX64I16x16ExtAddPairwiseI8x32U, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Popcnt(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kX64I8x16Popcnt, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ConvertLowI32x4U(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kX64F64x2ConvertLowI32x4U, dst, g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2SZero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  if (CpuFeatures::IsSupported(AVX)) {
    // Requires dst != src.
    Emit(kX64I32x4TruncSatF64x2SZero, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)));
  } else {
    Emit(kX64I32x4TruncSatF64x2SZero, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4TruncSatF64x2UZero(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionOperand dst = CpuFeatures::IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  Emit(kX64I32x4TruncSatF64x2UZero, dst,
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2SZero(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64Cvttpd2dq);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF64x2UZero(
    node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64I32x4TruncF64x2UZero);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF32x4S(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0), kX64Cvttps2dq);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedTruncF32x4U(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  X64OperandGeneratorT<Adapter> g(this);
  node_t input = this->input_at(node, 0);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  if (IsSupported(AVX)) {
    Emit(kX64I32x4TruncF32x4U, g.DefineAsRegister(node), g.UseRegister(input),
         arraysize(temps), temps);
  } else {
    Emit(kX64I32x4TruncF32x4U, g.DefineSameAsFirst(node), g.UseRegister(input),
         arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8RelaxedTruncF32x8S(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  VisitFloatUnop(this, node, this->input_at(node, 0),
                 kX64Cvttps2dq | VectorLengthField::encode(kV256));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8RelaxedTruncF32x8U(node_t node) {
  DCHECK_EQ(this->value_input_count(node), 1);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  X64OperandGeneratorT<Adapter> g(this);
  node_t input = this->input_at(node, 0);
  InstructionOperand temps[] = {g.TempSimd256Register()};
  Emit(kX64I32x8TruncF32x8U, g.DefineAsRegister(node), g.UseRegister(input),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2GtS(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  if (CpuFeatures::IsSupported(AVX)) {
    Emit(kX64IGtS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    Emit(kX64IGtS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else {
    Emit(kX64IGtS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineAsRegister(node), g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2GeS(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  if (CpuFeatures::IsSupported(AVX)) {
    Emit(kX64IGeS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    Emit(kX64IGeS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineAsRegister(node), g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)));
  } else {
    Emit(kX64IGeS | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineAsRegister(node), g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x4GeS(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  Emit(
      kX64IGeS | LaneSizeField::encode(kL64) | VectorLengthField::encode(kV256),
      g.DefineAsRegister(node), g.UseRegister(this->input_at(node, 0)),
      g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Abs(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  if (CpuFeatures::IsSupported(AVX)) {
    Emit(kX64IAbs | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)));
  } else {
    Emit(kX64IAbs | LaneSizeField::encode(kL64) |
             VectorLengthField::encode(kV128),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)));
  }
}

template <>
bool InstructionSelectorT<TurboshaftAdapter>::CanOptimizeF64x2PromoteLowF32x4(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(this->Get(node).Is<Opmask::kSimd128F64x2PromoteLowF32x4>());
  V<Simd128> input = this->input_at(node, 0);
  return this->Get(input).template Is<Opmask::kSimd128LoadTransform64Zero>() &&
         CanCover(node, input);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2PromoteLowF32x4(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  InstructionCode code = kX64F64x2PromoteLowF32x4;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    if (CanOptimizeF64x2PromoteLowF32x4(node)) {
      V<Simd128> input = this->input_at(node, 0);
      const Simd128LoadTransformOp& load_transform =
          this->Get(input).template Cast<Simd128LoadTransformOp>();
      if (load_transform.load_kind.with_trap_handler) {
        code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      // LoadTransforms cannot be eliminated, so they are visited even if
      // unused. Mark it as defined so that we don't visit it.
      MarkAsDefined(input);
      VisitLoad(node, input, code);
      return;
    }
  } else {
    node_t input = this->input_at(node, 0);
    LoadTransformMatcher m(input);

    if (m.Is(LoadTransformation::kS128Load64Zero) && CanCover(node, input)) {
      if (m.ResolvedValue().kind == MemoryAccessKind::kProtectedByTrapHandler) {
        code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      // LoadTransforms cannot be eliminated, so they are visited even if
      // unused. Mark it as defined so that we don't visit it.
      MarkAsDefined(input);
      VisitLoad(node, input, code);
      return;
    }
  }

  VisitRR(this, node, code);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  Emit(kX64I16x8DotI8x16I7x16S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 3);
  if (CpuFeatures::IsSupported(AVX_VNNI)) {
    Emit(kX64I32x4DotI8x16I7x16AddS, g.DefineSameAsInput(node, 2),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)),
         g.UseRegister(this->input_at(node, 2)));
  } else {
    InstructionOperand temps[] = {g.TempSimd128Register()};
    Emit(kX64I32x4DotI8x16I7x16AddS, g.DefineSameAsInput(node, 2),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)),
         g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
  }
}

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x16DotI8x32I7x32S(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 2);
  Emit(kX64I16x16DotI8x32I7x32S, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x8DotI8x32I7x32AddS(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 3);
  if (CpuFeatures::IsSupported(AVX_VNNI)) {
    Emit(kX64I32x8DotI8x32I7x32AddS, g.DefineSameAsInput(node, 2),
         g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)),
         g.UseRegister(this->input_at(node, 2)));
  } else {
    InstructionOperand temps[] = {g.TempSimd256Register()};
    Emit(kX64I32x8DotI8x32I7x32AddS, g.DefineSameAsInput(node, 2),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)),
         g.UseUniqueRegister(this->input_at(node, 2)), arraysize(temps), temps);
  }
}
#endif

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  X64OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  auto input = g.UseAny(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

#endif  // V8_ENABLE_WEBASSEMBLY

#ifndef V8_ENABLE_WEBASSEMBLY
#define VISIT_UNSUPPORTED_OP(op)                          \
  template <typename Adapter>                             \
  void InstructionSelectorT<Adapter>::Visit##op(node_t) { \
    UNREACHABLE();                                        \
  }
MACHINE_SIMD128_OP_LIST(VISIT_UNSUPPORTED_OP)
MACHINE_SIMD256_OP_LIST(VISIT_UNSUPPORTED_OP)
#endif

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  continuation_outputs_.push_back(
      g->DefineSameAsInput(node, first_input_index));
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags =
      MachineOperatorBuilder::kWord32ShiftIsSafe |
      MachineOperatorBuilder::kWord32Ctz | MachineOperatorBuilder::kWord64Ctz |
      MachineOperatorBuilder::kWord32Rol | MachineOperatorBuilder::kWord64Rol |
      MachineOperatorBuilder::kWord32Select |
      MachineOperatorBuilder::kWord64Select;
  if (CpuFeatures::IsSupported(POPCNT)) {
    flags |= MachineOperatorBuilder::kWord32Popcnt |
             MachineOperatorBuilder::kWord64Popcnt;
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
  if (CpuFeatures::IsSupported(F16C)) {
    flags |= MachineOperatorBuilder::kFloat16;
    if (CpuFeatures::IsSupported(AVX)) {
      flags |= MachineOperatorBuilder::kTruncateFloat64ToFloat16RawBits;
    }
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
```