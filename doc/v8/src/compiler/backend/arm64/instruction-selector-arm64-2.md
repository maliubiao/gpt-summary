Response: The user wants me to summarize the functionality of the C++ code snippet. This is part 3 of 6 of a larger file. The code seems to be related to instruction selection for the ARM64 architecture within the V8 JavaScript engine.

I need to:
1. Understand the purpose of the code.
2. Identify key functionalities and patterns.
3. Summarize the functionality in a concise manner.
4. Check for any connection to JavaScript and provide an example if applicable.
This code snippet is a part of the instruction selector for the ARM64 architecture in V8's Turboshaft and Turbofan compilers. Its primary function is to **translate high-level intermediate representation (IR) operations into specific ARM64 machine instructions**.

Here's a breakdown of the functionalities demonstrated in this section:

* **Handling of Shift Operations:**  It contains specific logic for selecting efficient ARM64 instructions like `Ubfx` (bitfield extract) for certain patterns involving shift and bitwise AND operations. This optimizes scenarios where a masked value is shifted to the least significant bits.

* **Handling of Arithmetic Operations:**  It provides instruction selection for addition, subtraction, and multiplication operations (`Add`, `Sub`, `Mul`). It also attempts to identify and utilize fused multiply-add instructions (`Madd`, `Msub`) for improved performance.

* **Handling of Integer Multiplication with Overflow:** It includes specific code to generate instructions for integer multiplication where overflow needs to be checked.

* **Handling of Type Conversions:**  It selects instructions for converting between different integer and floating-point types (e.g., `ChangeInt32ToFloat64`, `TruncateFloat64ToInt32`). It also handles cases where a sign-extending load can be used directly instead of a separate conversion instruction.

* **Handling of Bit Manipulation Operations:** It provides instruction selection for bitwise operations like counting leading zeros (`Clz`), population count (`Popcnt`), reversing bits (`ReverseBits`), and reversing bytes (`ReverseBytes`).

* **Handling of Floating-Point Operations:** It includes instruction selection for various floating-point operations like square root, rounding, and conversions. It also handles specific IEEE 754 operations.

* **Handling of WebAssembly SIMD Instructions (if enabled):**  It provides instruction selection for specific WebAssembly SIMD operations like extended multiplication and pairwise addition.

* **Optimization Techniques:** The code employs various optimization techniques:
    * **Instruction Fusion:** Combining multiple IR operations into a single, more efficient machine instruction (e.g., multiply-add).
    * **Pattern Matching:** Recognizing specific sequences of IR operations to select specialized instructions (e.g., `Ubfx` for shifted and masked values).
    * **Load Optimization:** Using sign-extending load instructions to combine loading and type conversion.
    * **Zero Extension Optimization:** Recognizing when a 32-bit operation implicitly zero-extends to 64-bits, avoiding explicit zero-extension instructions.

* **Helper Functions and Templates:**  The code uses templates (`InstructionSelectorT`) and helper functions (`VisitRRO`, `VisitRRR`, `TryEmitBitfieldExtract32`, etc.) to structure the instruction selection process and reduce code duplication.

**Relationship to JavaScript and Examples:**

This code directly impacts the performance of JavaScript execution in V8. JavaScript engines rely on efficient code generation to translate JavaScript code into machine instructions. The instruction selector is a crucial component in this process.

Here are a few examples of how the C++ code relates to JavaScript functionality:

**1. Integer Arithmetic:**

```javascript
function add(a, b) {
  return a + b;
}
```

When the V8 compiler processes this JavaScript function, the `a + b` operation will be represented as an `Int32Add` or `Int64Add` IR node. The `VisitInt32Add` or `VisitInt64Add` functions in the C++ code will be responsible for selecting the appropriate ARM64 `ADD` instruction. The code might even identify opportunities to use `Madd` if the addition is part of a multiply-add pattern.

**2. Bitwise Operations:**

```javascript
function maskAndShift(value, mask, shift) {
  return (value & mask) >> shift;
}
```

If the compiler recognizes a pattern where the `mask` is a constant, and the `shift` is also a constant, the code in `VisitWord64Shr` (or `VisitWord32Shr`) might select the `Ubfx` instruction. This is a more efficient way to extract a bitfield than performing the AND and shift operations separately.

**3. Type Conversions:**

```javascript
function floatToInt(x) {
  return Math.trunc(x);
}
```

The `Math.trunc()` function performs a truncation of a floating-point number to an integer. This will be represented by a `TruncateFloat64ToInt32` or `TruncateFloat64ToInt64` IR node. The corresponding `VisitTruncateFloat64ToInt32` or `VisitTruncateFloat64ToInt64` function will select the appropriate ARM64 instruction (like `FCVTZS`) to perform this conversion.

**4. Floating-Point Arithmetic:**

```javascript
function squareRoot(x) {
  return Math.sqrt(x);
}
```

The `Math.sqrt()` function will be represented by a `Float64Sqrt` IR node. The `VisitFloat64Sqrt` function will select the ARM64 floating-point square root instruction (`FSQRTD`).

In summary, this section of the C++ code is a vital part of V8's code generation pipeline for ARM64. It maps high-level operations to low-level machine instructions, implementing optimizations to ensure JavaScript code runs efficiently on ARM64-based devices.

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共6部分，请归纳一下它的功能

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
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
  return VisitRRR(this, kArm64Smulh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand const smull_operand = g.TempRegister();
  Emit(kArm64Umull, smull_operand, g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)));
  Emit(kArm64Lsr, g.DefineAsRegister(node), smull_operand, g.TempImmediate(32));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
  return VisitRRR(this, kArm64Umulh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kArm64Float32ToInt32;
    opcode |= MiscField::encode(
        op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>());
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kArm64Float32ToInt32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    opcode |= MiscField::encode(kind == TruncateKind::kSetOverflowToMin);
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kArm64Float32ToUint32;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));

  } else {
    InstructionCode opcode = kArm64Float32ToUint32;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
    Arm64OperandGeneratorT<Adapter> g(this);

    InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
    InstructionOperand outputs[2];
    size_t output_count = 0;
    outputs[output_count++] = g.DefineAsRegister(node);

    node_t success_output = FindProjection(node, 1);
    if (this->valid(success_output)) {
      outputs[output_count++] = g.DefineAsRegister(success_output);
    }

    Emit(kArm64Float32ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kArm64Float64ToInt64;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kArm64Float64ToInt64;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToInt64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[] = {g.DefineAsRegister(node)};
  InstructionOperand temps[] = {g.TempDoubleRegister()};
  Emit(kArm64Float64ToFloat16RawBits, arraysize(outputs), outputs,
       arraysize(inputs), inputs, arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float32ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToUint64, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToInt32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kArm64Float64ToUint32, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
  DCHECK(SmiValuesAre31Bits());
  DCHECK(COMPRESS_POINTERS_BOOL);
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    const Operation& input_op = this->Get(change_op.input());
    if (input_op.Is<LoadOp>() && CanCover(node, change_op.input())) {
      // Generate sign-extending load.
      LoadRepresentation load_rep =
          this->load_view(change_op.input()).loaded_rep();
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      ImmediateMode immediate_mode = kNoImmediate;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsSigned() ? kArm64Ldrsb : kArm64Ldrb;
          immediate_mode = kLoadStoreImm8;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsSigned() ? kArm64Ldrsh : kArm64Ldrh;
          immediate_mode = kLoadStoreImm16;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kArm64Ldrsw;
          immediate_mode = kLoadStoreImm32;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, immediate_mode, rep, node);
      return;
    }
    if ((input_op.Is<Opmask::kWord32ShiftRightArithmetic>() ||
         input_op.Is<Opmask::kWord32ShiftRightArithmeticShiftOutZeros>()) &&
        CanCover(node, change_op.input())) {
      const ShiftOp& sar = input_op.Cast<ShiftOp>();
      if (this->is_integer_constant(sar.right())) {
        Arm64OperandGeneratorT<Adapter> g(this);
        // Mask the shift amount, to keep the same semantics as Word32Sar.
        int right = this->integer_constant(sar.right()) & 0x1F;
        Emit(kArm64Sbfx, g.DefineAsRegister(node), g.UseRegister(sar.left()),
             g.TempImmediate(right), g.TempImmediate(32 - right));
        return;
      }
    }
    VisitRR(this, kArm64Sxtw, node);
  } else {
    Node* value = node->InputAt(0);
    if ((value->opcode() == IrOpcode::kLoad ||
         value->opcode() == IrOpcode::kLoadImmutable) &&
        CanCover(node, value)) {
      // Generate sign-extending load.
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      ImmediateMode immediate_mode = kNoImmediate;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsSigned() ? kArm64Ldrsb : kArm64Ldrb;
          immediate_mode = kLoadStoreImm8;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsSigned() ? kArm64Ldrsh : kArm64Ldrh;
          immediate_mode = kLoadStoreImm16;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTagged:
        case MachineRepresentation::kTaggedPointer:
          opcode = kArm64Ldrsw;
          immediate_mode = kLoadStoreImm32;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, value, opcode, immediate_mode, rep, node);
      return;
    }

    if (value->opcode() == IrOpcode::kWord32Sar && CanCover(node, value)) {
      Int32BinopMatcher m(value);
      if (m.right().HasResolvedValue()) {
        Arm64OperandGeneratorT<Adapter> g(this);
        // Mask the shift amount, to keep the same semantics as Word32Sar.
        int right = m.right().ResolvedValue() & 0x1F;
        Emit(kArm64Sbfx, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()), g.TempImmediate(right),
             g.TempImmediate(32 - right));
        return;
      }
    }

    VisitRR(this, kArm64Sxtw, node);
  }
}
template <>
bool InstructionSelectorT<TurboshaftAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  DCHECK(!this->Get(node).Is<PhiOp>());
  const Operation& op = this->Get(node);
  // 32-bit operations will write their result in a W register (implicitly
  // clearing the top 32-bit of the corresponding X register) so the
  // zero-extension is a no-op.
  switch (op.opcode) {
    case Opcode::kWordBinop:
      return op.Cast<WordBinopOp>().rep == WordRepresentation::Word32();
    case Opcode::kShift:
      return op.Cast<ShiftOp>().rep == WordRepresentation::Word32();
    case Opcode::kComparison:
      return op.Cast<ComparisonOp>().rep == RegisterRepresentation::Word32();
    case Opcode::kOverflowCheckedBinop:
      return op.Cast<OverflowCheckedBinopOp>().rep ==
             WordRepresentation::Word32();
    case Opcode::kProjection:
      return ZeroExtendsWord32ToWord64NoPhis(op.Cast<ProjectionOp>().input());
    case Opcode::kLoad: {
      RegisterRepresentation rep =
          op.Cast<LoadOp>().loaded_rep.ToRegisterRepresentation();
      return rep == RegisterRepresentation::Word32();
    }
    default:
      return false;
  }
}

template <>
bool InstructionSelectorT<TurbofanAdapter>::ZeroExtendsWord32ToWord64NoPhis(
    Node* node) {
  DCHECK_NE(node->opcode(), IrOpcode::kPhi);
  switch (node->opcode()) {
    case IrOpcode::kWord32And:
    case IrOpcode::kWord32Or:
    case IrOpcode::kWord32Xor:
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord32Sar:
    case IrOpcode::kWord32Ror:
    case IrOpcode::kWord32Equal:
    case IrOpcode::kInt32Add:
    case IrOpcode::kInt32AddWithOverflow:
    case IrOpcode::kInt32Sub:
    case IrOpcode::kInt32SubWithOverflow:
    case IrOpcode::kInt32Mul:
    case IrOpcode::kInt32MulHigh:
    case IrOpcode::kInt32Div:
    case IrOpcode::kInt32Mod:
    case IrOpcode::kInt32LessThan:
    case IrOpcode::kInt32LessThanOrEqual:
    case IrOpcode::kUint32Div:
    case IrOpcode::kUint32LessThan:
    case IrOpcode::kUint32LessThanOrEqual:
    case IrOpcode::kUint32Mod:
    case IrOpcode::kUint32MulHigh: {
      // 32-bit operations will write their result in a W register (implicitly
      // clearing the top 32-bit of the corresponding X register) so the
      // zero-extension is a no-op.
      return true;
    }
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable: {
      // As for the operations above, a 32-bit load will implicitly clear the
      // top 32 bits of the destination register.
      LoadRepresentation load_rep = LoadRepresentationOf(node->op());
      switch (load_rep.representation()) {
        case MachineRepresentation::kWord8:
        case MachineRepresentation::kWord16:
        case MachineRepresentation::kWord32:
          return true;
        default:
          return false;
      }
    }
    default:
      return false;
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToUint64(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  node_t value = this->input_at(node, 0);
  if (ZeroExtendsWord32ToWord64(value)) {
    return EmitIdentity(node);
  }
  Emit(kArm64Mov32, g.DefineAsRegister(node), g.UseRegister(value));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateInt64ToInt32(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  // The top 32 bits in the 64-bit register will be undefined, and
  // must not be used by a dependent node.
  EmitIdentity(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArm64Float64Mod, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveParamToFPR(node_t node, int index) {
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitMoveFPRToParam(
    InstructionOperand* op, LinkageLocation location) {}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  // `arguments` includes alignment "holes". This means that slots bigger than
  // kSystemPointerSize, e.g. Simd128, will span across multiple arguments.
  int claim_count = static_cast<int>(arguments->size());
  bool needs_padding = claim_count % 2 != 0;
  int slot = claim_count - 1;
  claim_count = RoundUp(claim_count, 2);
  // Bump the stack pointer.
  if (claim_count > 0) {
    // TODO(titzer): claim and poke probably take small immediates.
    // TODO(titzer): it would be better to bump the sp here only
    //               and emit paired stores with increment for non c frames.
    Emit(kArm64Claim, g.NoOutput(), g.TempImmediate(claim_count));

    if (needs_padding) {
      Emit(kArm64Poke, g.NoOutput(), g.UseImmediate(0),
           g.TempImmediate(claim_count - 1));
    }
  }

  // Poke the arguments into the stack.
  while (slot >= 0) {
    PushParameter input0 = (*arguments)[slot];
    // Skip holes in the param array. These represent both extra slots for
    // multi-slot values and padding slots for alignment.
    if (!this->valid(input0.node)) {
      slot--;
      continue;
    }
    PushParameter input1 = slot > 0 ? (*arguments)[slot - 1] : PushParameter();
    // Emit a poke-pair if consecutive parameters have the same type.
    // TODO(arm): Support consecutive Simd128 parameters.
    if (this->valid(input1.node) &&
        input0.location.GetType() == input1.location.GetType()) {
      Emit(kArm64PokePair, g.NoOutput(), g.UseRegister(input0.node),
           g.UseRegister(input1.node), g.TempImmediate(slot));
      slot -= 2;
    } else {
      Emit(kArm64Poke, g.NoOutput(), g.UseRegister(input0.node),
           g.TempImmediate(slot));
      slot--;
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);

  for (PushParameter output : *results) {
    if (!output.location.IsCallerFrameSlot()) continue;
    // Skip any alignment holes in nodes.
    if (this->valid(output.node)) {
      DCHECK(!call_descriptor->IsCFunctionCall());

      if (output.location.GetType() == MachineType::Float32()) {
        MarkAsFloat32(output.node);
      } else if (output.location.GetType() == MachineType::Float64()) {
        MarkAsFloat64(output.node);
      } else if (output.location.GetType() == MachineType::Simd128()) {
        MarkAsSimd128(output.node);
      }

      int offset = call_descriptor->GetOffsetToReturns();
      int reverse_slot = -output.location.GetLocation() - offset;
      Emit(kArm64Peek, g.DefineAsRegister(output.node),
           g.UseImmediate(reverse_slot));
    }
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return false;
}

namespace {

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  if (cont->IsSelect()) {
    Arm64OperandGeneratorT<Adapter> g(selector);
    InstructionOperand inputs[] = {
        left, right, g.UseRegisterOrImmediateZero(cont->true_value()),
        g.UseRegisterOrImmediateZero(cont->false_value())};
    selector->EmitWithContinuation(opcode, 0, nullptr, 4, inputs, cont);
  } else {
    selector->EmitWithContinuation(opcode, left, right, cont);
  }
}

// This function checks whether we can convert:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>.
// We only generate conditions <cond'> that are a combination of the N
// and Z flags. This avoids the need to make this function dependent on
// the flag-setting operation.
bool CanUseFlagSettingBinop(FlagsCondition cond) {
  switch (cond) {
    case kEqual:
    case kNotEqual:
    case kSignedLessThan:
    case kSignedGreaterThanOrEqual:
    case kUnsignedLessThanOrEqual:  // x <= 0 -> x == 0
    case kUnsignedGreaterThan:      // x > 0 -> x != 0
      return true;
    default:
      return false;
  }
}

// Map <cond> to <cond'> so that the following transformation is possible:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>.
FlagsCondition MapForFlagSettingBinop(FlagsCondition cond) {
  DCHECK(CanUseFlagSettingBinop(cond));
  switch (cond) {
    case kEqual:
    case kNotEqual:
      return cond;
    case kSignedLessThan:
      return kNegative;
    case kSignedGreaterThanOrEqual:
      return kPositiveOrZero;
    case kUnsignedLessThanOrEqual:  // x <= 0 -> x == 0
      return kEqual;
    case kUnsignedGreaterThan:  // x > 0 -> x != 0
      return kNotEqual;
    default:
      UNREACHABLE();
  }
}

// This function checks if we can perform the transformation:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>, and if so,
// updates {node}, {opcode} and {cont} accordingly.
template <typename Adapter>
void MaybeReplaceCmpZeroWithFlagSettingBinop(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t* node,
    typename Adapter::node_t binop, ArchOpcode* opcode, FlagsCondition cond,
    FlagsContinuationT<Adapter>* cont, ImmediateMode* immediate_mode) {
  ArchOpcode binop_opcode;
  ArchOpcode no_output_opcode;
  ImmediateMode binop_immediate_mode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(binop);
    if (op.Is<Opmask::kWord32Add>()) {
      binop_opcode = kArm64Add32;
      no_output_opcode = kArm64Cmn32;
      binop_immediate_mode = kArithmeticImm;
    } else if (op.Is<Opmask::kWord32BitwiseAnd>()) {
      binop_opcode = kArm64And32;
      no_output_opcode = kArm64Tst32;
      binop_immediate_mode = kLogical32Imm;
    } else {
      UNREACHABLE();
    }
  } else {
    switch (binop->opcode()) {
      case IrOpcode::kInt32Add:
        binop_opcode = kArm64Add32;
        no_output_opcode = kArm64Cmn32;
        binop_immediate_mode = kArithmeticImm;
        break;
      case IrOpcode::kWord32And:
        binop_opcode = kArm64And32;
        no_output_opcode = kArm64Tst32;
        binop_immediate_mode = kLogical32Imm;
        break;
      default:
        UNREACHABLE();
    }
  }
  if (selector->CanCover(*node, binop)) {
    // The comparison is the only user of the add or and, so we can generate
    // a cmn or tst instead.
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = no_output_opcode;
    *node = binop;
    *immediate_mode = binop_immediate_mode;
  } else if (selector->IsOnlyUserOfNodeInSameBlock(*node, binop)) {
    // We can also handle the case where the add and the compare are in the
    // same basic block, and the compare is the only use of add in this basic
    // block (the add has users in other basic blocks).
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = binop_opcode;
    *node = binop;
    *immediate_mode = binop_immediate_mode;
  }
}

// Map {cond} to kEqual or kNotEqual, so that we can select
// either TBZ or TBNZ when generating code for:
// (x cmp 0), b.{cond}
FlagsCondition MapForTbz(FlagsCondition cond) {
  switch (cond) {
    case kSignedLessThan:  // generate TBNZ
      return kNotEqual;
    case kSignedGreaterThanOrEqual:  // generate TBZ
      return kEqual;
    default:
      UNREACHABLE();
  }
}

// Map {cond} to kEqual or kNotEqual, so that we can select
// either CBZ or CBNZ when generating code for:
// (x cmp 0), b.{cond}
FlagsCondition MapForCbz(FlagsCondition cond) {
  switch (cond) {
    case kEqual:     // generate CBZ
    case kNotEqual:  // generate CBNZ
      return cond;
    case kUnsignedLessThanOrEqual:  // generate CBZ
      return kEqual;
    case kUnsignedGreaterThan:  // generate CBNZ
      return kNotEqual;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void EmitBranchOrDeoptimize(InstructionSelectorT<Adapter>* selector,
                            InstructionCode opcode, InstructionOperand value,
                            FlagsContinuationT<Adapter>* cont) {
  DCHECK(cont->IsBranch() || cont->IsDeoptimize());
  selector->EmitWithContinuation(opcode, value, cont);
}

template <int N>
struct CbzOrTbzMatchTrait {};

template <>
struct CbzOrTbzMatchTrait<32> {
  using IntegralType = uint32_t;
  using BinopMatcher = Int32BinopMatcher;
  static constexpr IrOpcode::Value kAndOpcode = IrOpcode::kWord32And;
  static constexpr ArchOpcode kTestAndBranchOpcode = kArm64TestAndBranch32;
  static constexpr ArchOpcode kCompareAndBranchOpcode =
      kArm64CompareAndBranch32;
  static constexpr unsigned kSignBit = kWSignBit;
};

template <>
struct CbzOrTbzMatchTrait<64> {
  using IntegralType = uint64_t;
  using BinopMatcher = Int64BinopMatcher;
  static constexpr IrOpcode::Value kAndOpcode = IrOpcode::kWord64And;
  static constexpr ArchOpcode kTestAndBranchOpcode = kArm64TestAndBranch;
  static constexpr ArchOpcode kCompareAndBranchOpcode = kArm64CompareAndBranch;
  static constexpr unsigned kSignBit = kXSignBit;
};

// Try to emit TBZ, TBNZ, CBZ or CBNZ for certain comparisons of {node}
// against {value}, depending on the condition.
template <typename Adapter, int N>
bool TryEmitCbzOrTbz(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node,
                     typename CbzOrTbzMatchTrait<N>::IntegralType value,
                     typename Adapter::node_t user, FlagsCondition cond,
                     FlagsContinuationT<Adapter>* cont) {
  // Only handle branches and deoptimisations.
  if (!cont->IsBranch() && !cont->IsDeoptimize()) return false;

  switch (cond) {
    case kSignedLessThan:
    case kSignedGreaterThanOrEqual: {
      // Here we handle sign tests, aka. comparisons with zero.
      if (value != 0) return false;
      // We don't generate TBZ/TBNZ for deoptimisations, as they have a
      // shorter range than conditional branches and generating them for
      // deoptimisations results in more veneers.
      if (cont->IsDeoptimize()) return false;
      Arm64OperandGeneratorT<Adapter> g(selector);
      cont->Overwrite(MapForTbz(cond));

      if (N == 32) {
        if constexpr (Adapter::IsTurboshaft) {
          using namespace turboshaft;  // NOLINT(build/namespaces)
          const Operation& op = selector->Get(node);
          if (op.Is<Opmask::kFloat64ExtractHighWord32>() &&
              selector->CanCover(user, node)) {
            // SignedLessThan(Float64ExtractHighWord32(x), 0) and
            // SignedGreaterThanOrEqual(Float64ExtractHighWord32(x), 0)
            // essentially check the sign bit of a 64-bit floating point value.
            InstructionOperand temp = g.TempRegister();
            selector->Emit(kArm64U64MoveFloat64, temp,
                           g.UseRegister(selector->input_at(node, 0)));
            selector->EmitWithContinuation(kArm64TestAndBranch, temp,
                                           g.TempImmediate(kDSignBit), cont);
            return true;
          }
        } else {
          Int32Matcher m(node);
          if (m.IsFloat64ExtractHighWord32() &&
              selector->CanCover(user, node)) {
            // SignedLessThan(Float64ExtractHighWord32(x), 0) and
            // SignedGreaterThanOrEqual(Float64ExtractHighWord32(x), 0)
            // essentially check the sign bit of a 64-bit floating point value.
            InstructionOperand temp = g.TempRegister();
            selector->Emit(kArm64U64MoveFloat64, temp,
                           g.UseRegister(node->InputAt(0)));
            selector->EmitWithContinuation(kArm64TestAndBranch, temp,
                                           g.TempImmediate(kDSignBit), cont);
            return true;
          }
        }
      }

      selector->EmitWithContinuation(
          CbzOrTbzMatchTrait<N>::kTestAndBranchOpcode, g.UseRegister(node),
          g.TempImmediate(CbzOrTbzMatchTrait<N>::kSignBit), cont);
      return true;
    }
    case kEqual:
    case kNotEqual: {
      if constexpr (Adapter::IsTurboshaft) {
        using namespace turboshaft;  // NOLINT(build/namespaces)
        const Operation& op = selector->Get(node);
        if (const WordBinopOp* bitwise_and =
                op.TryCast<Opmask::kBitwiseAnd>()) {
          // Emit a tbz/tbnz if we are comparing with a single-bit mask:
          //   Branch(WordEqual(WordAnd(x, 1 << N), 1 << N), true, false)
          uint64_t actual_value;
          if (cont->IsBranch() && base::bits::IsPowerOfTwo(value) &&
              selector->MatchUnsignedIntegralConstant(bitwise_and->right(),
                                                      &actual_value) &&
              actual_value == value && selector->CanCover(user, node)) {
            Arm64OperandGeneratorT<Adapter> g(selector);
            // In the code generator, Equal refers to a bit being cleared. We
            // want the opposite here so negate the condition.
            cont->Negate();
            selector->EmitWithContinuation(
                CbzOrTbzMatchTrait<N>::kTestAndBranchOpcode,
                g.UseRegister(bitwise_and->left()),
                g.TempImmediate(base::bits::CountTrailingZeros(value)), cont);
            return true;
          }
        }
      } else {
        if (node->opcode() == CbzOrTbzMatchTrait<N>::kAndOpcode) {
          // Emit a tbz/tbnz if we are comparing with a single-bit mask:
          //   Branch(WordEqual(WordAnd(x, 1 << N), 1 << N), true, false)
          typename CbzOrTbzMatchTrait<N>::BinopMatcher m_and(node);
          if (cont->IsBranch() && base::bits::IsPowerOfTwo(value) &&
              m_and.right().Is(value) && selector->CanCover(user, node)) {
            Arm64OperandGeneratorT<Adapter> g(selector);
            // In the code generator, Equal refers to a bit being cleared. We
            // want the opposite here so negate the condition.
            cont->Negate();
            selector->EmitWithContinuation(
                CbzOrTbzMatchTrait<N>::kTestAndBranchOpcode,
                g.UseRegister(m_and.left().node()),
                g.TempImmediate(base::bits::CountTrailingZeros(value)), cont);
            return true;
          }
        }
      }
      [[fallthrough]];
    }
    case kUnsignedLessThanOrEqual:
    case kUnsignedGreaterThan: {
      if (value != 0) return false;
      Arm64OperandGeneratorT<Adapter> g(selector);
      cont->Overwrite(MapForCbz(cond));
      EmitBranchOrDeoptimize(selector,
                             CbzOrTbzMatchTrait<N>::kCompareAndBranchOpcode,
                             g.UseRegister(node), cont);
      return true;
    }
    default:
      return false;
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont,
                      ImmediateMode immediate_mode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  // If one of the two inputs is an immediate, make sure it's on the right.
  if (!g.CanBeImmediate(right, immediate_mode) &&
      g.CanBeImmediate(left, immediate_mode)) {
    cont->Commute();
    std::swap(left, right);
  }

  if (opcode == kArm64Cmp && selector->is_constant(right)) {
    auto constant = selector->constant_view(right);
    if (g.IsIntegerConstant(constant)) {
      if (TryEmitCbzOrTbz<Adapter, 64>(selector, left,
                                       g.GetIntegerConstantValue(constant),
        
"""


```