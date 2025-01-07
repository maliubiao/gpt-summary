Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is part of the V8 JavaScript engine, specifically the instruction selector for the ARM64 architecture.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the file's purpose:** The filename `instruction-selector-arm64.cc` clearly indicates this code is responsible for selecting specific ARM64 instructions to implement higher-level operations. The "backend/arm64" path reinforces that this is part of the architecture-specific code generation.

2. **Scan for key functionalities:**  Look for `Visit...` functions. These strongly suggest the code handles different types of operations (nodes in the compiler's intermediate representation). The names of these functions (`VisitWord64Shr`, `VisitWord32Sar`, `VisitInt32Add`, etc.) directly reveal the kinds of operations being handled.

3. **Group related functionalities:**  Notice patterns in the `Visit...` function names. For example, there are many functions related to bitwise operations (`Shr`, `Sar`, `Rol`, `Ror`, `Clz`, `Popcnt`, `ReverseBits`, `ReverseBytes`), arithmetic operations (`Add`, `Sub`, `Mul`, `Div`, `Mod`), and floating-point operations (`Float32Sqrt`, `Float64RoundDown`, etc.).

4. **Identify template usage:** Observe the use of `template <typename Adapter>`. This indicates the code is designed to be used with different "adapters," likely representing different stages or configurations within the V8 compilation pipeline (e.g., Turbofan and Turboshaft).

5. **Look for specific instruction emission:** Pay attention to `Emit(...)` calls. These lines directly generate ARM64 assembly instructions. The first argument to `Emit` is the instruction opcode (e.g., `kArm64Ubfx`, `kArm64Lsr`, `kArm64Smull`). This provides concrete examples of the instructions being selected.

6. **Recognize optimization patterns:**  Notice sections of code that attempt to optimize certain operation combinations. For instance, the `VisitWord64Shr` and `VisitWord32Sar` functions have logic to select the `Ubfx` instruction for specific patterns involving bitwise AND and shifts. The `VisitInt32Add` and `VisitInt64Add` functions look for opportunities to use the `Madd` instruction. These optimizations are key functions of the instruction selector.

7. **Check for architecture-specific details:** The presence of "arm64" in the code and the specific ARM64 instruction opcodes confirm its architecture-specific nature.

8. **Address the ".tq" question:** The prompt asks about ".tq" files. The code doesn't end in ".tq", so it's not a Torque file.

9. **Consider JavaScript relevance and examples:**  Since this is part of a JavaScript engine, the operations being handled correspond directly to JavaScript language features. Provide examples of JavaScript code that would result in these operations (e.g., `>>`, `<<`, `+`, `-`, `*`, `Math.sqrt()`).

10. **Address code logic and examples:**  The optimization patterns offer opportunities for demonstrating code logic. Select a specific optimization (like the `Ubfx` selection) and provide a hypothetical input and output to illustrate the transformation.

11. **Address common programming errors:** Think about how the optimizations relate to common programming mistakes. The bitwise AND and shift optimization could be relevant to incorrect masking or bit manipulation, where a programmer might not realize the underlying instruction being used.

12. **Structure the summary:** Organize the findings into clear categories: general function, operation handling, architecture specifics, optimization, JavaScript relationship, code logic examples, and potential errors.

13. **Review and refine:** Ensure the summary is accurate, concise, and addresses all parts of the user's prompt. Specifically, double-check that the "part 5 of 11" information is included in the final summary.
```cpp
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& op = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(op.left());
  if (lhs.Is<Opmask::kWord64BitwiseAnd>() && is_integer_constant(op.right())) {
    uint32_t lsb = integer_constant(op.right()) & 0x3F;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    uint64_t constant_and_rhs;
    if (MatchIntegralWord64Constant(bitwise_and.right(), &constant_and_rhs) &&
        constant_and_rhs != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint64_t mask = static_cast<uint64_t>(constant_and_rhs >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_msb + mask_width + lsb) == 64) {
        Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros64(mask));
        Emit(kArm64Ubfx, g.DefineAsRegister(node),
             g.UseRegister(bitwise_and.left()),
             g.UseImmediateOrTemp(op.right(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kArm64Lsr, node, kShift64Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64Shr(Node* node) {
  Int64BinopMatcher m(node);
  if (m.left().IsWord64And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x3F;
    Int64BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint64_t mask =
          static_cast<uint64_t>(mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_msb + mask_width + lsb) == 64) {
        Arm64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros64(mask));
        Emit(kArm64Ubfx, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(m.right().node(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kArm64Lsr, node, kShift64Imm);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Sar(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  const ShiftOp& shift = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shift.left());
  if (lhs.Is<Opmask::kWord32SignedMulOverflownBits>() &&
      is_integer_constant(shift.right()) && CanCover(node, shift.left())) {
    // Combine this shift with the multiply and shift that would be generated
    // by Int32MulHigh.
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    const WordBinopOp& mul_overflow = lhs.Cast<WordBinopOp>();
    int shift_by = integer_constant(shift.right()) & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Smull, smull_operand, g.UseRegister(mul_overflow.left()),
         g.UseRegister(mul_overflow.right()));
    Emit(kArm64Asr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift_by));
    return;
  }

  if (lhs.Is<Opmask::kWord32Add>() && is_integer_constant(shift.right()) &&
      CanCover(node, shift.left())) {
    const WordBinopOp& add = Get(shift.left()).Cast<WordBinopOp>();
    const Operation& lhs = Get(add.left());
    if (lhs.Is<Opmask::kWord32SignedMulOverflownBits>() &&
        CanCover(shift.left(), add.left())) {
      // Combine the shift that would be generated by Int32MulHigh with the add
      // on the left of this Sar operation. We do it here, as the result of the
      // add potentially has 33 bits, so we have to ensure the result is
      // truncated by being the input to this 32-bit Sar operation.
      Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
      const WordBinopOp& mul = lhs.Cast<WordBinopOp>();

      InstructionOperand const smull_operand = g.TempRegister();
      Emit(kArm64Smull, smull_operand, g.UseRegister(mul.left()),
           g.UseRegister(mul.right()));

      InstructionOperand const add_operand = g.TempRegister();
      Emit(kArm64Add | AddressingModeField::encode(kMode_Operand2_R_ASR_I),
           add_operand, g.UseRegister(add.right()), smull_operand,
           g.TempImmediate(32));

      Emit(kArm64Asr32, g.DefineAsRegister(node), add_operand,
           g.UseImmediate(shift.right()));
      return;
    }
  }

  VisitRRO(this, kArm64Asr32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Sar(Node* node) {
  if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  Int32BinopMatcher m(node);
  if (m.left().IsInt32MulHigh() && m.right().HasResolvedValue() &&
      CanCover(node, node->InputAt(0))) {
    // Combine this shift with the multiply and shift that would be generated
    // by Int32MulHigh.
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Node* left = m.left().node();
    int shift = m.right().ResolvedValue() & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Smull, smull_operand, g.UseRegister(left->InputAt(0)),
         g.UseRegister(left->InputAt(1)));
    Emit(kArm64Asr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift));
    return;
  }

  if (m.left().IsInt32Add() && m.right().HasResolvedValue() &&
      CanCover(node, node->InputAt(0))) {
    Node* add_node = m.left().node();
    Int32BinopMatcher madd_node(add_node);
    if (madd_node.left().IsInt32MulHigh() &&
        CanCover(add_node, madd_node.left().node())) {
      // Combine the shift that would be generated by Int32MulHigh with the add
      // on the left of this Sar operation. We do it here, as the result of the
      // add potentially has 33 bits, so we have to ensure the result is
      // truncated by being the input to this 32-bit Sar operation.
      Arm64OperandGeneratorT<TurbofanAdapter> g(this);
      Node* mul_node = madd_node.left().node();

      InstructionOperand const smull_operand = g.TempRegister();
      Emit(kArm64Smull, smull_operand, g.UseRegister(mul_node->InputAt(0)),
           g.UseRegister(mul_node->InputAt(1)));

      InstructionOperand const add_operand = g.TempRegister();
      Emit(kArm64Add | AddressingModeField::encode(kMode_Operand2_R_ASR_I),
           add_operand, g.UseRegister(add_node->InputAt(1)), smull_operand,
           g.TempImmediate(32));

      Emit(kArm64Asr32, g.DefineAsRegister(node), add_operand,
           g.UseImmediate(node->InputAt(1)));
      return;
    }
  }

  VisitRRO(this, kArm64Asr32, node, kShift32Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
  {
    if (TryEmitExtendingLoad(this, node)) return;

    // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
    // where possible
    Int64BinopMatcher m(node);
    if (m.left().IsChangeInt32ToInt64() && m.right().HasResolvedValue() &&
        is_uint5(m.right().ResolvedValue()) &&
        CanCover(node, m.left().node())) {
      // Don't select Sbfx here if Asr(Ldrsw(x), imm) can be selected for
      // Word64Sar(ChangeInt32ToInt64(Load(x)), imm)
      if ((m.left().InputAt(0)->opcode() != IrOpcode::kLoad &&
           m.left().InputAt(0)->opcode() != IrOpcode::kLoadImmutable) ||
          !CanCover(m.left().node(), m.left().InputAt(0))) {
        Arm64OperandGeneratorT<Adapter> g(this);
        int right = static_cast<int>(m.right().ResolvedValue());
        Emit(kArm64Sbfx, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()->InputAt(0)),
             g.UseImmediate(m.right().node()), g.UseImmediate(32 - right));
        return;
      }
    }

    VisitRRO(this, kArm64Asr, node, kShift64Imm);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Sar(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitExtendingLoad(this, node)) return;

  // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
  // where possible
  const ShiftOp& shiftop = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shiftop.left());

  int64_t constant_rhs;
  if (lhs.Is<Opmask::kChangeInt32ToInt64>() &&
      MatchIntegralWord64Constant(shiftop.right(), &constant_rhs) &&
      is_uint5(constant_rhs) && CanCover(node, shiftop.left())) {
    // Don't select Sbfx here if Asr(Ldrsw(x), imm) can be selected for
    // Word64Sar(ChangeInt32ToInt64(Load(x)), imm)
    OpIndex input = lhs.Cast<ChangeOp>().input();
    if (!Get(input).Is<LoadOp>() || !CanCover(shiftop.left(), input)) {
      Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
      int right = static_cast<int>(constant_rhs);
      Emit(kArm64Sbfx, g.DefineAsRegister(node), g.UseRegister(input),
           g.UseImmediate(right), g.UseImmediate(32 - right));
      return;
    }
  }

  VisitRRO(this, kArm64Asr, node, kShift64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitRRO(this, kArm64Ror32, node, kShift32Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
  VisitRRO(this, kArm64Ror, node, kShift64Imm);
}

#define RR_OP_T_LIST(V)                                       \
  V(Float32Sqrt, kArm64Float32Sqrt)                           \
  V(Float64Sqrt, kArm64Float64Sqrt)                           \
  V(Float32RoundDown, kArm64Float32RoundDown)                 \
  V(Float64RoundDown, kArm64Float64RoundDown)                 \
  V(Float32RoundUp, kArm64Float32RoundUp)                     \
  V(Float64RoundUp, kArm64Float64RoundUp)                     \
  V(Float32RoundTruncate, kArm64Float32RoundTruncate)         \
  V(Float64RoundTruncate, kArm64Float64RoundTruncate)         \
  V(Float64RoundTiesAway, kArm64Float64RoundTiesAway)         \
  V(Float32RoundTiesEven, kArm64Float32RoundTiesEven)         \
  V(Float64RoundTiesEven, kArm64Float64RoundTiesEven)         \
  V(Float64SilenceNaN, kArm64Float64SilenceNaN)               \
  V(ChangeInt32ToFloat64, kArm64Int32ToFloat64)               \
  V(RoundFloat64ToInt32, kArm64Float64ToInt32)                \
  V(ChangeFloat32ToFloat64, kArm64Float32ToFloat64)           \
  V(RoundInt32ToFloat32, kArm64Int32ToFloat32)                \
  V(RoundUint32ToFloat32, kArm64Uint32ToFloat32)              \
  V(ChangeInt64ToFloat64, kArm64Int64ToFloat64)               \
  V(ChangeUint32ToFloat64, kArm64Uint32ToFloat64)             \
  V(ChangeFloat64ToInt32, kArm64Float64ToInt32)               \
  V(ChangeFloat64ToInt64, kArm64Float64ToInt64)               \
  V(ChangeFloat64ToUint32, kArm64Float64ToUint32)             \
  V(ChangeFloat64ToUint64, kArm64Float64ToUint64)             \
  V(RoundInt64ToFloat32, kArm64Int64ToFloat32)                \
  V(RoundInt64ToFloat64, kArm64Int64ToFloat64)                \
  V(RoundUint64ToFloat32, kArm64Uint64ToFloat32)              \
  V(RoundUint64ToFloat64, kArm64Uint64ToFloat64)              \
  V(BitcastFloat32ToInt32, kArm64Float64ExtractLowWord32)     \
  V(BitcastFloat64ToInt64, kArm64U64MoveFloat64)              \
  V(BitcastInt32ToFloat32, kArm64Float64MoveU64)              \
  V(BitcastInt64ToFloat64, kArm64Float64MoveU64)              \
  V(TruncateFloat64ToFloat32, kArm64Float64ToFloat32)         \
  V(TruncateFloat64ToWord32, kArchTruncateDoubleToI)          \
  V(TruncateFloat64ToUint32, kArm64Float64ToUint32)           \
  V(Float64ExtractLowWord32, kArm64Float64ExtractLowWord32)   \
  V(Float64ExtractHighWord32, kArm64Float64ExtractHighWord32) \
  V(Word64Clz, kArm64Clz)                                     \
  V(Word32Clz, kArm64Clz32)                                   \
  V(Word32Popcnt, kArm64Cnt32)                                \
  V(Word64Popcnt, kArm64Cnt64)                                \
  V(Word32ReverseBits, kArm64Rbit32)                          \
  V(Word64ReverseBits, kArm64Rbit)                            \
  V(Word32ReverseBytes, kArm64Rev32)                          \
  V(Word64ReverseBytes, kArm64Rev)                            \
  IF_WASM(V, F16x8Ceil, kArm64Float16RoundUp)                 \
  IF_WASM(V, F16x8Floor, kArm64Float16RoundDown)              \
  IF_WASM(V, F16x8Trunc, kArm64Float16RoundTruncate)          \
  IF_WASM(V, F16x8NearestInt, kArm64Float16RoundTiesEven)     \
  IF_WASM(V, F32x4Ceil, kArm64Float32RoundUp)                 \
  IF_WASM(V, F32x4Floor, kArm64Float32RoundDown)              \
  IF_WASM(V, F32x4Trunc, kArm64Float32RoundTruncate)          \
  IF_WASM(V, F32x4NearestInt, kArm64Float32RoundTiesEven)     \
  IF_WASM(V, F64x2Ceil, kArm64Float64RoundUp)                 \
  IF_WASM(V, F64x2Floor, kArm64Float64RoundDown)              \
  IF_WASM(V, F64x2Trunc, kArm64Float64RoundTruncate)          \
  IF_WASM(V, F64x2NearestInt, kArm64Float64RoundTiesEven)

#define RRR_OP_T_LIST(V)          \
  V(Int32Div, kArm64Idiv32)       \
  V(Int64Div, kArm64Idiv)         \
  V(Uint32Div, kArm64Udiv32)      \
  V(Uint64Div, kArm64Udiv)        \
  V(Int32Mod, kArm64Imod32)       \
  V(Int64Mod, kArm64Imod)         \
  V(Uint32Mod, kArm64Umod32)      \
  V(Uint64Mod, kArm64Umod)        \
  V(Float32Add, kArm64Float32Add) \
  V(Float64Add, kArm64Float64Add) \
  V(Float32Sub, kArm64Float32Sub) \
  V(Float64Sub, kArm64Float64Sub) \
  V(Float32Div, kArm64Float32Div) \
  V(Float64Div, kArm64Float64Div) \
  V(Float32Max, kArm64Float32Max) \
  V(Float64Max, kArm64Float64Max) \
  V(Float32Min, kArm64Float32Min) \
  V(Float64Min, kArm64Float64Min) \
  IF_WASM(V, I8x16Swizzle, kArm64I8x16Swizzle)

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, opcode, node);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

#define RRR_VISITOR(Name, opcode)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, opcode, node);                                \
  }
RRR_OP_T_LIST(RRR_VISITOR)
#undef RRR_VISITOR
#undef RRR_OP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const WordBinopOp& add = this->Get(node).Cast<WordBinopOp>();
  DCHECK(add.Is<Opmask::kWord32Add>());
  V<Word32> left = add.left<Word32>();
  V<Word32> right = add.right<Word32>();
  // Select Madd(x, y, z) for Add(Mul(x, y), z) or Add(z, Mul(x, y)).
  if (TryEmitMultiplyAddInt32(this, node, left, right) ||
      TryEmitMultiplyAddInt32(this, node, right, left)) {
    return;
  }
  VisitAddSub(this, node, kArm64Add32, kArm64Sub32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  // Select Madd(x, y, z) for Add(Mul(x, y), z).
  if (m.left().IsInt32Mul() && CanCover(node, m.left().node())) {
    Int32BinopMatcher mleft(m.left().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mleft) == 0) {
      Emit(kArm64Madd32, g.DefineAsRegister(node),
           g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()),
           g.UseRegister(m.right().node()));
      return;
    }
  }
  // Select Madd(x, y, z) for Add(z, Mul(x, y)).
  if (m.right().IsInt32Mul() && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Madd32, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }
  VisitAddSub<TurbofanAdapter, Int32BinopMatcher>(this, node, kArm64Add32,
                                                  kArm64Sub32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Add(node_t node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  // Select Madd(x, y, z) for Add(Mul(x, y), z).
  if (m.left().IsInt64Mul() && CanCover(node, m.left().node())) {
    Int64BinopMatcher mleft(m.left().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mleft) == 0) {
      Emit(kArm64Madd, g.DefineAsRegister(node),
           g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()),
           g.UseRegister(m.right().node()));
      return;
    }
  }
  // Select Madd(x, y, z) for Add(z, Mul(x, y)).
  if (m.right().IsInt64Mul() && CanCover(node, m.right().node())) {
    Int64BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Madd, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }
  VisitAddSub<TurbofanAdapter, Int64BinopMatcher>(this, node, kArm64Add,
                                                  kArm64Sub);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const WordBinopOp& add = this->Get(node).Cast<WordBinopOp>();
  DCHECK(add.Is<Opmask::kWord64Add>());
  V<Word64> left = add.left<Word64>();
  V<Word64> right = add.right<Word64>();
  // Select Madd(x, y, z) for Add(Mul(x, y), z) or Add(z, Mul(x, y)).
  if (TryEmitMultiplyAddInt64(this, node, left, right) ||
      TryEmitMultiplyAddInt64(this, node, right, left)) {
    return;
  }
  VisitAddSub(this, node, kArm64Add, kArm64Sub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (m.right().IsInt32Mul() && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Msub32, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }

  VisitAddSub<Adapter, Int32BinopMatcher>(this, node, kArm64Sub32, kArm64Add32);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Sub(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(this->Get(node).Is<Opmask::kWord32Sub>());

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (TryEmitMultiplySub<Opmask::kWord32Mul>(this, node, kArm64Msub32)) {
    return;
  }

  VisitAddSub(this, node, kArm64Sub32, kArm64Add32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Int64BinopMatcher m(node);

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (m.right().IsInt64Mul() && CanCover(node, m.right().node())) {
    Int64BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply
Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共11部分，请归纳一下它的功能

"""
e_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& op = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(op.left());
  if (lhs.Is<Opmask::kWord64BitwiseAnd>() && is_integer_constant(op.right())) {
    uint32_t lsb = integer_constant(op.right()) & 0x3F;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    uint64_t constant_and_rhs;
    if (MatchIntegralWord64Constant(bitwise_and.right(), &constant_and_rhs) &&
        constant_and_rhs != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint64_t mask = static_cast<uint64_t>(constant_and_rhs >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_msb + mask_width + lsb) == 64) {
        Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros64(mask));
        Emit(kArm64Ubfx, g.DefineAsRegister(node),
             g.UseRegister(bitwise_and.left()),
             g.UseImmediateOrTemp(op.right(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kArm64Lsr, node, kShift64Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64Shr(Node* node) {
  Int64BinopMatcher m(node);
  if (m.left().IsWord64And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x3F;
    Int64BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint64_t mask =
          static_cast<uint64_t>(mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_msb + mask_width + lsb) == 64) {
        Arm64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros64(mask));
        Emit(kArm64Ubfx, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(m.right().node(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kArm64Lsr, node, kShift64Imm);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Sar(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  const ShiftOp& shift = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shift.left());
  if (lhs.Is<Opmask::kWord32SignedMulOverflownBits>() &&
      is_integer_constant(shift.right()) && CanCover(node, shift.left())) {
    // Combine this shift with the multiply and shift that would be generated
    // by Int32MulHigh.
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    const WordBinopOp& mul_overflow = lhs.Cast<WordBinopOp>();
    int shift_by = integer_constant(shift.right()) & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Smull, smull_operand, g.UseRegister(mul_overflow.left()),
         g.UseRegister(mul_overflow.right()));
    Emit(kArm64Asr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift_by));
    return;
  }

  if (lhs.Is<Opmask::kWord32Add>() && is_integer_constant(shift.right()) &&
      CanCover(node, shift.left())) {
    const WordBinopOp& add = Get(shift.left()).Cast<WordBinopOp>();
    const Operation& lhs = Get(add.left());
    if (lhs.Is<Opmask::kWord32SignedMulOverflownBits>() &&
        CanCover(shift.left(), add.left())) {
      // Combine the shift that would be generated by Int32MulHigh with the add
      // on the left of this Sar operation. We do it here, as the result of the
      // add potentially has 33 bits, so we have to ensure the result is
      // truncated by being the input to this 32-bit Sar operation.
      Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
      const WordBinopOp& mul = lhs.Cast<WordBinopOp>();

      InstructionOperand const smull_operand = g.TempRegister();
      Emit(kArm64Smull, smull_operand, g.UseRegister(mul.left()),
           g.UseRegister(mul.right()));

      InstructionOperand const add_operand = g.TempRegister();
      Emit(kArm64Add | AddressingModeField::encode(kMode_Operand2_R_ASR_I),
           add_operand, g.UseRegister(add.right()), smull_operand,
           g.TempImmediate(32));

      Emit(kArm64Asr32, g.DefineAsRegister(node), add_operand,
           g.UseImmediate(shift.right()));
      return;
    }
  }

  VisitRRO(this, kArm64Asr32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Sar(Node* node) {
  if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  Int32BinopMatcher m(node);
  if (m.left().IsInt32MulHigh() && m.right().HasResolvedValue() &&
      CanCover(node, node->InputAt(0))) {
    // Combine this shift with the multiply and shift that would be generated
    // by Int32MulHigh.
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Node* left = m.left().node();
    int shift = m.right().ResolvedValue() & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Smull, smull_operand, g.UseRegister(left->InputAt(0)),
         g.UseRegister(left->InputAt(1)));
    Emit(kArm64Asr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift));
    return;
  }

  if (m.left().IsInt32Add() && m.right().HasResolvedValue() &&
      CanCover(node, node->InputAt(0))) {
    Node* add_node = m.left().node();
    Int32BinopMatcher madd_node(add_node);
    if (madd_node.left().IsInt32MulHigh() &&
        CanCover(add_node, madd_node.left().node())) {
      // Combine the shift that would be generated by Int32MulHigh with the add
      // on the left of this Sar operation. We do it here, as the result of the
      // add potentially has 33 bits, so we have to ensure the result is
      // truncated by being the input to this 32-bit Sar operation.
      Arm64OperandGeneratorT<TurbofanAdapter> g(this);
      Node* mul_node = madd_node.left().node();

      InstructionOperand const smull_operand = g.TempRegister();
      Emit(kArm64Smull, smull_operand, g.UseRegister(mul_node->InputAt(0)),
           g.UseRegister(mul_node->InputAt(1)));

      InstructionOperand const add_operand = g.TempRegister();
      Emit(kArm64Add | AddressingModeField::encode(kMode_Operand2_R_ASR_I),
           add_operand, g.UseRegister(add_node->InputAt(1)), smull_operand,
           g.TempImmediate(32));

      Emit(kArm64Asr32, g.DefineAsRegister(node), add_operand,
           g.UseImmediate(node->InputAt(1)));
      return;
    }
  }

  VisitRRO(this, kArm64Asr32, node, kShift32Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
  {
    if (TryEmitExtendingLoad(this, node)) return;

    // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
    // where possible
    Int64BinopMatcher m(node);
    if (m.left().IsChangeInt32ToInt64() && m.right().HasResolvedValue() &&
        is_uint5(m.right().ResolvedValue()) &&
        CanCover(node, m.left().node())) {
      // Don't select Sbfx here if Asr(Ldrsw(x), imm) can be selected for
      // Word64Sar(ChangeInt32ToInt64(Load(x)), imm)
      if ((m.left().InputAt(0)->opcode() != IrOpcode::kLoad &&
           m.left().InputAt(0)->opcode() != IrOpcode::kLoadImmutable) ||
          !CanCover(m.left().node(), m.left().InputAt(0))) {
        Arm64OperandGeneratorT<Adapter> g(this);
        int right = static_cast<int>(m.right().ResolvedValue());
        Emit(kArm64Sbfx, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()->InputAt(0)),
             g.UseImmediate(m.right().node()), g.UseImmediate(32 - right));
        return;
      }
    }

    VisitRRO(this, kArm64Asr, node, kShift64Imm);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Sar(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitExtendingLoad(this, node)) return;

  // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
  // where possible
  const ShiftOp& shiftop = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shiftop.left());

  int64_t constant_rhs;
  if (lhs.Is<Opmask::kChangeInt32ToInt64>() &&
      MatchIntegralWord64Constant(shiftop.right(), &constant_rhs) &&
      is_uint5(constant_rhs) && CanCover(node, shiftop.left())) {
    // Don't select Sbfx here if Asr(Ldrsw(x), imm) can be selected for
    // Word64Sar(ChangeInt32ToInt64(Load(x)), imm)
    OpIndex input = lhs.Cast<ChangeOp>().input();
    if (!Get(input).Is<LoadOp>() || !CanCover(shiftop.left(), input)) {
      Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
      int right = static_cast<int>(constant_rhs);
      Emit(kArm64Sbfx, g.DefineAsRegister(node), g.UseRegister(input),
           g.UseImmediate(right), g.UseImmediate(32 - right));
      return;
    }
  }

  VisitRRO(this, kArm64Asr, node, kShift64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitRRO(this, kArm64Ror32, node, kShift32Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
  VisitRRO(this, kArm64Ror, node, kShift64Imm);
}

#define RR_OP_T_LIST(V)                                       \
  V(Float32Sqrt, kArm64Float32Sqrt)                           \
  V(Float64Sqrt, kArm64Float64Sqrt)                           \
  V(Float32RoundDown, kArm64Float32RoundDown)                 \
  V(Float64RoundDown, kArm64Float64RoundDown)                 \
  V(Float32RoundUp, kArm64Float32RoundUp)                     \
  V(Float64RoundUp, kArm64Float64RoundUp)                     \
  V(Float32RoundTruncate, kArm64Float32RoundTruncate)         \
  V(Float64RoundTruncate, kArm64Float64RoundTruncate)         \
  V(Float64RoundTiesAway, kArm64Float64RoundTiesAway)         \
  V(Float32RoundTiesEven, kArm64Float32RoundTiesEven)         \
  V(Float64RoundTiesEven, kArm64Float64RoundTiesEven)         \
  V(Float64SilenceNaN, kArm64Float64SilenceNaN)               \
  V(ChangeInt32ToFloat64, kArm64Int32ToFloat64)               \
  V(RoundFloat64ToInt32, kArm64Float64ToInt32)                \
  V(ChangeFloat32ToFloat64, kArm64Float32ToFloat64)           \
  V(RoundInt32ToFloat32, kArm64Int32ToFloat32)                \
  V(RoundUint32ToFloat32, kArm64Uint32ToFloat32)              \
  V(ChangeInt64ToFloat64, kArm64Int64ToFloat64)               \
  V(ChangeUint32ToFloat64, kArm64Uint32ToFloat64)             \
  V(ChangeFloat64ToInt32, kArm64Float64ToInt32)               \
  V(ChangeFloat64ToInt64, kArm64Float64ToInt64)               \
  V(ChangeFloat64ToUint32, kArm64Float64ToUint32)             \
  V(ChangeFloat64ToUint64, kArm64Float64ToUint64)             \
  V(RoundInt64ToFloat32, kArm64Int64ToFloat32)                \
  V(RoundInt64ToFloat64, kArm64Int64ToFloat64)                \
  V(RoundUint64ToFloat32, kArm64Uint64ToFloat32)              \
  V(RoundUint64ToFloat64, kArm64Uint64ToFloat64)              \
  V(BitcastFloat32ToInt32, kArm64Float64ExtractLowWord32)     \
  V(BitcastFloat64ToInt64, kArm64U64MoveFloat64)              \
  V(BitcastInt32ToFloat32, kArm64Float64MoveU64)              \
  V(BitcastInt64ToFloat64, kArm64Float64MoveU64)              \
  V(TruncateFloat64ToFloat32, kArm64Float64ToFloat32)         \
  V(TruncateFloat64ToWord32, kArchTruncateDoubleToI)          \
  V(TruncateFloat64ToUint32, kArm64Float64ToUint32)           \
  V(Float64ExtractLowWord32, kArm64Float64ExtractLowWord32)   \
  V(Float64ExtractHighWord32, kArm64Float64ExtractHighWord32) \
  V(Word64Clz, kArm64Clz)                                     \
  V(Word32Clz, kArm64Clz32)                                   \
  V(Word32Popcnt, kArm64Cnt32)                                \
  V(Word64Popcnt, kArm64Cnt64)                                \
  V(Word32ReverseBits, kArm64Rbit32)                          \
  V(Word64ReverseBits, kArm64Rbit)                            \
  V(Word32ReverseBytes, kArm64Rev32)                          \
  V(Word64ReverseBytes, kArm64Rev)                            \
  IF_WASM(V, F16x8Ceil, kArm64Float16RoundUp)                 \
  IF_WASM(V, F16x8Floor, kArm64Float16RoundDown)              \
  IF_WASM(V, F16x8Trunc, kArm64Float16RoundTruncate)          \
  IF_WASM(V, F16x8NearestInt, kArm64Float16RoundTiesEven)     \
  IF_WASM(V, F32x4Ceil, kArm64Float32RoundUp)                 \
  IF_WASM(V, F32x4Floor, kArm64Float32RoundDown)              \
  IF_WASM(V, F32x4Trunc, kArm64Float32RoundTruncate)          \
  IF_WASM(V, F32x4NearestInt, kArm64Float32RoundTiesEven)     \
  IF_WASM(V, F64x2Ceil, kArm64Float64RoundUp)                 \
  IF_WASM(V, F64x2Floor, kArm64Float64RoundDown)              \
  IF_WASM(V, F64x2Trunc, kArm64Float64RoundTruncate)          \
  IF_WASM(V, F64x2NearestInt, kArm64Float64RoundTiesEven)

#define RRR_OP_T_LIST(V)          \
  V(Int32Div, kArm64Idiv32)       \
  V(Int64Div, kArm64Idiv)         \
  V(Uint32Div, kArm64Udiv32)      \
  V(Uint64Div, kArm64Udiv)        \
  V(Int32Mod, kArm64Imod32)       \
  V(Int64Mod, kArm64Imod)         \
  V(Uint32Mod, kArm64Umod32)      \
  V(Uint64Mod, kArm64Umod)        \
  V(Float32Add, kArm64Float32Add) \
  V(Float64Add, kArm64Float64Add) \
  V(Float32Sub, kArm64Float32Sub) \
  V(Float64Sub, kArm64Float64Sub) \
  V(Float32Div, kArm64Float32Div) \
  V(Float64Div, kArm64Float64Div) \
  V(Float32Max, kArm64Float32Max) \
  V(Float64Max, kArm64Float64Max) \
  V(Float32Min, kArm64Float32Min) \
  V(Float64Min, kArm64Float64Min) \
  IF_WASM(V, I8x16Swizzle, kArm64I8x16Swizzle)

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, opcode, node);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

#define RRR_VISITOR(Name, opcode)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, opcode, node);                                \
  }
RRR_OP_T_LIST(RRR_VISITOR)
#undef RRR_VISITOR
#undef RRR_OP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const WordBinopOp& add = this->Get(node).Cast<WordBinopOp>();
  DCHECK(add.Is<Opmask::kWord32Add>());
  V<Word32> left = add.left<Word32>();
  V<Word32> right = add.right<Word32>();
  // Select Madd(x, y, z) for Add(Mul(x, y), z) or Add(z, Mul(x, y)).
  if (TryEmitMultiplyAddInt32(this, node, left, right) ||
      TryEmitMultiplyAddInt32(this, node, right, left)) {
    return;
  }
  VisitAddSub(this, node, kArm64Add32, kArm64Sub32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  // Select Madd(x, y, z) for Add(Mul(x, y), z).
  if (m.left().IsInt32Mul() && CanCover(node, m.left().node())) {
    Int32BinopMatcher mleft(m.left().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mleft) == 0) {
      Emit(kArm64Madd32, g.DefineAsRegister(node),
           g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()),
           g.UseRegister(m.right().node()));
      return;
    }
  }
  // Select Madd(x, y, z) for Add(z, Mul(x, y)).
  if (m.right().IsInt32Mul() && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Madd32, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }
  VisitAddSub<TurbofanAdapter, Int32BinopMatcher>(this, node, kArm64Add32,
                                                  kArm64Sub32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Add(node_t node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  // Select Madd(x, y, z) for Add(Mul(x, y), z).
  if (m.left().IsInt64Mul() && CanCover(node, m.left().node())) {
    Int64BinopMatcher mleft(m.left().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mleft) == 0) {
      Emit(kArm64Madd, g.DefineAsRegister(node),
           g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()),
           g.UseRegister(m.right().node()));
      return;
    }
  }
  // Select Madd(x, y, z) for Add(z, Mul(x, y)).
  if (m.right().IsInt64Mul() && CanCover(node, m.right().node())) {
    Int64BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Madd, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }
  VisitAddSub<TurbofanAdapter, Int64BinopMatcher>(this, node, kArm64Add,
                                                  kArm64Sub);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const WordBinopOp& add = this->Get(node).Cast<WordBinopOp>();
  DCHECK(add.Is<Opmask::kWord64Add>());
  V<Word64> left = add.left<Word64>();
  V<Word64> right = add.right<Word64>();
  // Select Madd(x, y, z) for Add(Mul(x, y), z) or Add(z, Mul(x, y)).
  if (TryEmitMultiplyAddInt64(this, node, left, right) ||
      TryEmitMultiplyAddInt64(this, node, right, left)) {
    return;
  }
  VisitAddSub(this, node, kArm64Add, kArm64Sub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (m.right().IsInt32Mul() && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Msub32, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }

  VisitAddSub<Adapter, Int32BinopMatcher>(this, node, kArm64Sub32, kArm64Add32);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Sub(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(this->Get(node).Is<Opmask::kWord32Sub>());

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (TryEmitMultiplySub<Opmask::kWord32Mul>(this, node, kArm64Msub32)) {
    return;
  }

  VisitAddSub(this, node, kArm64Sub32, kArm64Add32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Int64BinopMatcher m(node);

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (m.right().IsInt64Mul() && CanCover(node, m.right().node())) {
    Int64BinopMatcher mright(m.right().node());
    // Check multiply can't be later reduced to addition with shift.
    if (LeftShiftForReducedMultiply(&mright) == 0) {
      Emit(kArm64Msub, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
  }

  VisitAddSub<Adapter, Int64BinopMatcher>(this, node, kArm64Sub, kArm64Add);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Sub(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(this->Get(node).Is<Opmask::kWord64Sub>());

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  if (TryEmitMultiplySub<Opmask::kWord64Mul>(this, node, kArm64Msub)) {
    return;
  }

  VisitAddSub(this, node, kArm64Sub, kArm64Add);
}

namespace {

template <typename Adapter>
void EmitInt32MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  InstructionOperand result = g.DefineAsRegister(node);
  InstructionOperand left = g.UseRegister(m.left().node());

  if (m.right().HasResolvedValue() &&
      base::bits::IsPowerOfTwo(m.right().ResolvedValue())) {
    // Sign extend the bottom 32 bits and shift left.
    int32_t shift = base::bits::WhichPowerOfTwo(m.right().ResolvedValue());
    selector->Emit(kArm64Sbfiz, result, left, g.TempImmediate(shift),
                   g.TempImmediate(32));
  } else {
    InstructionOperand right = g.UseRegister(m.right().node());
    selector->Emit(kArm64Smull, result, left, right);
  }

  InstructionCode opcode =
      kArm64Cmp | AddressingModeField::encode(kMode_Operand2_R_SXTW);
  selector->EmitWithContinuation(opcode, result, result, cont);
}

void EmitInt32MulWithOverflow(InstructionSelectorT<TurboshaftAdapter>* selector,
                              turboshaft::OpIndex node,
                              FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const OverflowCheckedBinopOp& mul =
      selector->Get(node).Cast<OverflowCheckedBinopOp>();
  InstructionOperand result = g.DefineAsRegister(node);
  InstructionOperand left = g.UseRegister(mul.left());

  int32_t constant_rhs;
  if (selector->MatchIntegralWord32Constant(mul.right(), &constant_rhs) &&
      base::bits::IsPowerOfTwo(constant_rhs)) {
    // Sign extend the bottom 32 bits and shift left.
    int32_t shift = base::bits::WhichPowerOfTwo(constant_rhs);
    selector->Emit(kArm64Sbfiz, result, left, g.TempImmediate(shift),
                   g.TempImmediate(32));
  } else {
    InstructionOperand right = g.UseRegister(mul.right());
    selector->Emit(kArm64Smull, result, left, right);
  }

  InstructionCode opcode =
      kArm64Cmp | AddressingModeField::encode(kMode_Operand2_R_SXTW);
  selector->EmitWithContinuation(opcode, result, result, cont);
}

template <typename Adapter>
void EmitInt64MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand result = g.DefineAsRegister(node);
  InstructionOperand left = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand high = g.TempRegister();

  InstructionOperand right = g.UseRegister(selector->input_at(node, 1));
  selector->Emit(kArm64Mul, result, left, right);
  selector->Emit(kArm64Smulh, high, left, right);

  // Test whether {high} is a sign-extension of {result}.
  InstructionCode opcode =
      kArm64Cmp | AddressingModeField::encode(kMode_Operand2_R_ASR_I);
  selector->EmitWithContinuation(opcode, high, result, g.TempImmediate(63),
                                 cont);
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& mul = Get(node).Cast<WordBinopOp>();
  DCHECK(mul.Is<Opmask::kWord32Mul>());

  // First, try to reduce the multiplication to addition with left shift.
  // x * (2^k + 1) -> x + (x << k)
  int32_t shift = LeftShiftForReducedMultiply(this, mul.right());
  if (shift > 0) {
    Emit(kArm64Add32 | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
         g.DefineAsRegister(node), g.UseRegister(mul.left()),
         g.UseRegister(mul.left()), g.TempImmediate(shift));
    return;
  }

  // Select Mneg(x, y) for Mul(Sub(0, x), y) or Mul(y, Sub(0, x)).
  if (TryEmitMultiplyNegateInt32(this, node, mul.left(), mul.right()) ||
      TryEmitMultiplyNegateInt32(this, node, mul.right(), mul.left())) {
    return;
  }

  VisitRRR(this, kArm64Mul32, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Mul(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);

  // First, try to reduce the multiplication to addition with left shift.
  // x * (2^k + 1) -> x + (x << k)
  int32_t shift = LeftShiftForReducedMultiply(&m);
  if (shift > 0) {
    Emit(kArm64Add32 | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
         g.DefineAsRegister(node), g.UseRegister(m.left().node()),
         g.UseRegister(m.left().node()), g.TempImmediate(shift));
    return;
  }

  if (m.left().IsInt32Sub() && CanCover(node, m.left().node())) {
    Int32BinopMatcher mleft(m.left().node());

    // Select Mneg(x, y) for Mul(Sub(0, x), y).
    if (mleft.left().Is(0)) {
      Emit(kArm64Mneg32, g.DefineAsRegister(node),
           g.UseRegister(mleft.right().node()),
           g.UseRegister(m.right().node()));
      return;
    }
  }

  if (m.right().IsInt32Sub() && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());

    // Select Mneg(x, y) for Mul(x, Sub(0, y)).
    if (mright.left().Is(0)) {
      Emit(kArm64Mneg32, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
  }

  VisitRRR(this, kArm64Mul32, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Mul(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& mul = Get(node).Cast<WordBinopOp>();
  DCHECK(mul.Is<Opmask::kWord64Mul>());

  // First, try to reduce the multiplication to addition with left shift.
  // x * (2^k + 1) -> x + (x << k)
  int32_t shift = LeftShiftForReducedMultiply(this, mul.right());
  if (shift > 0) {
    Emit(kArm64Add | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
         g.DefineAsRegister(node), g.UseRegister(mul.left()),
         g.UseRegister(mul.left()), g.TempImmediate(shift));
    return;
  }

  // Select Mneg(x, y) for Mul(Sub(0, x), y) or Mul(y, Sub(0, x)).
  if (TryEmitMultiplyNegateInt64(this, node, mul.left(), mul.right()) ||
      TryEmitMultiplyNegateInt64(this, node, mul.right(), mul.left())) {
    return;
  }

  VisitRRR(this, kArm64Mul, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Mul(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);

  // First, try to reduce the multiplication to addition with left shift.
  // x * (2^k + 1) -> x + (x << k)
  int32_t shift = LeftShiftForReducedMultiply(&m);
  if (shift > 0) {
    Emit(kArm64Add | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
         g.DefineAsRegister(node), g.UseRegister(m.left().node()),
         g.UseRegister(m.left().node()), g.TempImmediate(shift));
    return;
  }

  if (m.left().IsInt64Sub() && CanCover(node, m.left().node())) {
    Int64BinopMatcher mleft(m.left().node());

    // Select Mneg(x, y) for Mul(Sub(0, x), y).
    if (mleft.left().Is(0)) {
      Emit(kArm64Mneg, g.DefineAsRegister(node),
           g.UseRegister(mleft.right().node()),
           g.UseRegister(m.right().node()));
      return;
    }
  }

  if (m.right().IsInt64Sub() && CanCover(node, m.right().node())) {
    Int64BinopMatcher mright(m.right().node());

    // Select Mneg(x, y) for Mul(x, Sub(0, y)).
    if (mright.left().Is(0)) {
      Emit(kArm64Mneg, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
  }

  VisitRRR(this, kArm64Mul, node);
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
template <typename Adapter>
void VisitExtMul(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                 typename Adapter::node_t node, int dst_lane_size) {
  InstructionCode code = opcode;
  code |= LaneSizeField::encode(dst_lane_size);
  VisitRRR(selector, code, node);
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtMulLowI8x16S(node_t node) {
  VisitExtMul(this, kArm64Smull, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtMulHighI8x16S(node_t node) {
  VisitExtMul(this, kArm64Smull2, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtMulLowI8x16U(node_t node) {
  VisitExtMul(this, kArm64Umull, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtMulHighI8x16U(node_t node) {
  VisitExtMul(this, kArm64Umull2, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtMulLowI16x8S(node_t node) {
  VisitExtMul(this, kArm64Smull, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtMulHighI16x8S(node_t node) {
  VisitExtMul(this, kArm64Smull2, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtMulLowI16x8U(node_t node) {
  VisitExtMul(this, kArm64Umull, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtMulHighI16x8U(node_t node) {
  VisitExtMul(this, kArm64Umull2, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ExtMulLowI32x4S(node_t node) {
  VisitExtMul(this, kArm64Smull, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ExtMulHighI32x4S(node_t node) {
  VisitExtMul(this, kArm64Smull2, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ExtMulLowI32x4U(node_t node) {
  VisitExtMul(this, kArm64Umull, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ExtMulHighI32x4U(node_t node) {
  VisitExtMul(this, kArm64Umull2, node, 64);
}
#endif  // V8_ENABLE_WEBASSEMBLY

#if V8_ENABLE_WEBASSEMBLY
namespace {
template <typename Adapter>
void VisitExtAddPairwise(InstructionSelectorT<Adapter>* selector,
                         ArchOpcode opcode, typename Adapter::node_t node,
                         int dst_lane_size) {
  InstructionCode code = opcode;
  code |= LaneSizeField::encode(dst_lane_size);
  VisitRR(selector, code, node);
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8S(
    node_t node) {
  VisitExtAddPairwise(this, kArm64Saddlp, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtAddPairwiseI16x8U(
    node_t node) {
  VisitExtAddPairwise(this, kArm64Uaddlp, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16S(
    node_t node) {
  VisitExtAddPairwise(this, kArm64Saddlp, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtAddPairwiseI8x16U(
    node_t node) {
  VisitExtAddPairwise(this, kArm64Uaddlp, node, 16);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand const smull_operand = g.TempRegister();
  Emit(kArm64Smull, smull_operand, g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
  Emit(kArm64Asr, g.DefineAsRegister(node), smull_operand, g.TempImmediate(32));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(nod
"""


```