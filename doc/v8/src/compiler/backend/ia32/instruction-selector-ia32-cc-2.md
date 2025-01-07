Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core function:** The code is part of an `InstructionSelectorT` class template, specifically for the IA32 architecture. This suggests its primary role is to select appropriate machine instructions based on higher-level operations.

2. **Analyze the structure:** The code consists of various `Visit...` methods and helper functions. These methods seem to correspond to different types of operations or nodes in an abstract syntax tree (likely the V8 intermediate representation). The `#define` macros suggest a way to generate these `Visit` methods for common patterns.

3. **Examine individual `Visit` methods:**
    * `VisitWord32PairShl`, `VisitWord32PairShr`, `VisitWord32PairSar`: These clearly handle 64-bit shifts using two 32-bit registers (eax and edx). The `FindProjection` indicates accessing the results of a previous operation that produced a pair of values.
    * `VisitWord32Rol`, `VisitWord32Ror`: These handle simple 32-bit rotate operations.
    * The macros `RO_OP_T_LIST`, `RO_WITH_TEMP_OP_T_LIST`, `RR_OP_T_LIST`, `RRO_FLOAT_OP_T_LIST`, `FLOAT_UNOP_T_LIST`: These lists define various unary and binary operations, including floating-point operations, integer conversions, bit manipulation, and SIMD operations. The associated `VISITOR` macros generate the corresponding `Visit` methods.
    * `VisitInt32Add`: This has specific handling for matching "lea" (load effective address) instructions, which are often used for address calculations but can also perform addition. There are separate implementations for `TurboshaftAdapter` and `TurbofanAdapter`, likely representing different compiler pipelines.
    * `VisitInt32Sub`, `VisitInt32Mul`: These handle basic arithmetic operations, with optimizations like using `neg` for subtracting from zero and `imul` with immediate operands.
    * `VisitInt32Div`, `VisitUint32Div`, `VisitInt32Mod`, `VisitUint32Mod`: These handle division and modulo operations, using the `idiv` and `udiv` instructions, which involve specific registers (eax and edx).
    * Floating-point `Visit` methods (`VisitFloat64Mod`, `VisitFloat32Max`, etc.): These map directly to corresponding IA32 floating-point instructions.
    * `VisitWord32ReverseBytes`: This uses the `bswap` instruction to reverse the byte order of a 32-bit value.
    * `EmitPrepareArguments`, `EmitPrepareResults`: These methods deal with setting up and retrieving arguments for function calls, considering both C function calls and standard JavaScript calls.
    * The `VisitCompare...` functions and the `VisitWordCompareZero`: These handle comparison operations, including optimizations for comparing against zero and using narrower operand sizes when possible.
    * `VisitAtomicBinOp`, `VisitPairAtomicBinOp`: These deal with atomic operations for multi-threaded scenarios.

4. **Infer the overall functionality:** Based on the individual methods, the primary function of this code is to translate intermediate representation (IR) nodes representing various operations into corresponding IA32 machine instructions. It handles different data types (integers, floats, SIMD), various arithmetic, logical, and bitwise operations, function call setup, and atomic operations.

5. **Address specific parts of the request:**
    * **Listing functionalities:** This is addressed by summarizing the types of operations handled.
    * **Torque source:** The code does *not* end with `.tq`, so it's not Torque.
    * **Relationship to JavaScript:**  Many of the operations directly correspond to JavaScript language features (arithmetic operators, bitwise operators, Math functions, etc.).
    * **JavaScript examples:**  Provide simple JavaScript code snippets that would lead to the execution of the C++ functions.
    * **Code logic reasoning:**  Focus on the `VisitWord32Pair...` methods as a good example of how the code handles operations involving multiple registers. Provide a concrete input and output scenario.
    * **Common programming errors:**  Relate the integer division and modulo operations to potential errors like division by zero.
    * **Summary of functionality:**  Concisely reiterate the main purpose of the code.

6. **Structure the answer:** Organize the information into logical sections, addressing each point of the user's request. Use clear and concise language. Highlight keywords and code snippets for better readability.
```cpp
Fixed(node, eax);
  node_t projection1 = selector->FindProjection(node, 1);
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, edx);
  } else {
    temps[temp_count++] = g.TempRegister(edx);
  }

  selector->Emit(opcode, output_count, outputs, 3, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShl(node_t node) {
  VisitWord32PairShift(this, kIA32ShlPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShr(node_t node) {
  VisitWord32PairShift(this, kIA32ShrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairSar(node_t node) {
  VisitWord32PairShift(this, kIA32SarPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  VisitShift(this, node, kIA32Rol);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitShift(this, node, kIA32Ror);
}

#define RO_OP_T_LIST(V)                                      \
  V(Float32Sqrt, kIA32Float32Sqrt)                           \
  V(Float64Sqrt, kIA32Float64Sqrt)                           \
  V(ChangeInt32ToFloat64, kSSEInt32ToFloat64)                \
  V(TruncateFloat32ToInt32, kIA32Float32ToInt32)             \
  V(TruncateFloat64ToFloat32, kIA32Float64ToFloat32)         \
  V(BitcastFloat32ToInt32, kIA32BitcastFI)                   \
  V(BitcastInt32ToFloat32, kIA32BitcastIF)                   \
  V(Float64ExtractLowWord32, kIA32Float64ExtractLowWord32)   \
  V(Float64ExtractHighWord32, kIA32Float64ExtractHighWord32) \
  V(ChangeFloat64ToInt32, kIA32Float64ToInt32)               \
  V(ChangeFloat32ToFloat64, kIA32Float32ToFloat64)           \
  V(RoundInt32ToFloat32, kSSEInt32ToFloat32)                 \
  V(RoundFloat64ToInt32, kIA32Float64ToInt32)                \
  V(Word32Clz, kIA32Lzcnt)                                   \
  V(Word32Ctz, kIA32Tzcnt)                                   \
  V(Word32Popcnt, kIA32Popcnt)                               \
  V(SignExtendWord8ToInt32, kIA32Movsxbl)                    \
  V(SignExtendWord16ToInt32, kIA32Movsxwl)                   \
  IF_WASM(V, F64x2Sqrt, kIA32F64x2Sqrt)

#define RO_WITH_TEMP_OP_T_LIST(V) V(ChangeUint32ToFloat64, kIA32Uint32ToFloat64)

#define RO_WITH_TEMP_SIMD_OP_T_LIST(V)             \
  V(TruncateFloat64ToUint32, kIA32Float64ToUint32) \
  V(TruncateFloat32ToUint32, kIA32Float32ToUint32) \
  V(ChangeFloat64ToUint32, kIA32Float64ToUint32)

#define RR_OP_T_LIST(V)                                                        \
  V(Float32RoundDown, kIA32Float32Round | MiscField::encode(kRoundDown))       \
  V(Float64RoundDown, kIA32Float64Round | MiscField::encode(kRoundDown))       \
  V(Float32RoundUp, kIA32Float32Round | MiscField::encode(kRoundUp))           \
  V(Float64RoundUp, kIA32Float64Round | MiscField::encode(kRoundUp))           \
  V(Float32RoundTruncate, kIA32Float32Round | MiscField::encode(kRoundToZero)) \
  V(Float64RoundTruncate, kIA32Float64Round | MiscField::encode(kRoundToZero)) \
  V(Float32RoundTiesEven,                                                      \
    kIA32Float32Round | MiscField::encode(kRoundToNearest))                    \
  V(Float64RoundTiesEven,                                                      \
    kIA32Float64Round | MiscField::encode(kRoundToNearest))                    \
  V(TruncateFloat64ToWord32, kArchTruncateDoubleToI)                           \
  IF_WASM(V, F32x4Ceil, kIA32F32x4Round | MiscField::encode(kRoundUp))         \
  IF_WASM(V, F32x4Floor, kIA32F32x4Round | MiscField::encode(kRoundDown))      \
  IF_WASM(V, F32x4Trunc, kIA32F32x4Round | MiscField::encode(kRoundToZero))    \
  IF_WASM(V, F32x4NearestInt,                                                  \
          kIA32F32x4Round | MiscField::encode(kRoundToNearest))                \
  IF_WASM(V, F64x2Ceil, kIA32F64x2Round | MiscField::encode(kRoundUp))         \
  IF_WASM(V, F64x2Floor, kIA32F64x2Round | MiscField::encode(kRoundDown))      \
  IF_WASM(V, F64x2Trunc, kIA32F64x2Round | MiscField::encode(kRoundToZero))    \
  IF_WASM(V, F64x2NearestInt,                                                  \
          kIA32F64x2Round | MiscField::encode(kRoundToNearest))

#define RRO_FLOAT_OP_T_LIST(V)        \
  V(Float32Add, kFloat32Add)          \
  V(Float64Add, kFloat64Add)          \
  V(Float32Sub, kFloat32Sub)          \
  V(Float64Sub, kFloat64Sub)          \
  V(Float32Mul, kFloat32Mul)          \
  V(Float64Mul, kFloat64Mul)          \
  V(Float32Div, kFloat32Div)          \
  V(Float64Div, kFloat64Div)          \
  IF_WASM(V, F64x2Add, kIA32F64x2Add) \
  IF_WASM(V, F64x2Sub, kIA32F64x2Sub) \
  IF_WASM(V, F64x2Mul, kIA32F64x2Mul) \
  IF_WASM(V, F64x2Div, kIA32F64x2Div) \
  IF_WASM(V, F64x2Eq, kIA32F64x2Eq)   \
  IF_WASM(V, F64x2Ne, kIA32F64x2Ne)   \
  IF_WASM(V, F64x2Lt, kIA32F64x2Lt)   \
  IF_WASM(V, F64x2Le, kIA32F64x2Le)

#define FLOAT_UNOP_T_LIST(V)        \
  V(Float32Abs, kFloat32Abs)        \
  V(Float64Abs, kFloat64Abs)        \
  V(Float32Neg, kFloat32Neg)        \
  V(Float64Neg, kFloat64Neg)        \
  IF_WASM(V, F32x4Abs, kFloat32Abs) \
  IF_WASM(V, F32x4Neg, kFloat32Neg) \
  IF_WASM(V, F64x2Abs, kFloat64Abs) \
  IF_WASM(V, F64x2Neg, kFloat64Neg)

#define RO_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRO(this, node, opcode);                                 \
  }
RO_OP_T_LIST(RO_VISITOR)
#undef RO_VISITOR
#undef RO_OP_T_LIST

#define RO_WITH_TEMP_VISITOR(Name, opcode)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitROWithTemp(this, node, opcode);                         \
  }
RO_WITH_TEMP_OP_T_LIST(RO_WITH_TEMP_VISITOR)
#undef RO_WITH_TEMP_VISITOR
#undef RO_WITH_TEMP_OP_T_LIST

#define RO_WITH_TEMP_SIMD_VISITOR(Name, opcode)                  \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitROWithTempSimd(this, node, opcode);                     \
  }
RO_WITH_TEMP_SIMD_OP_T_LIST(RO_WITH_TEMP_SIMD_VISITOR)
#undef RO_WITH_TEMP_SIMD_VISITOR
#undef RO_WITH_TEMP_SIMD_OP_T_LIST

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, node, opcode);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

#define RRO_FLOAT_VISITOR(Name, opcode)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRROFloat(this, node, opcode);                           \
  }
RRO_FLOAT_OP_T_LIST(RRO_FLOAT_VISITOR)
#undef RRO_FLOAT_VISITOR
#undef RRO_FLOAT_OP_T_LIST

#define FLOAT_UNOP_VISITOR(Name, opcode)                         \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    DCHECK_EQ(this->value_input_count(node), 1);                 \
    VisitFloatUnop(this, node, this->input_at(node, 0), opcode); \
  }
FLOAT_UNOP_T_LIST(FLOAT_UNOP_VISITOR)
#undef FLOAT_UNOP_VISITOR
#undef FLOAT_UNOP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kIA32Bswap, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  IA32OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::WordBinopOp& add =
      this->Get(node).template Cast<turboshaft::WordBinopOp>();
  turboshaft::OpIndex left = add.left();
  turboshaft::OpIndex right = add.right();

  std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>> m =
      TryMatchBaseWithScaledIndexAndDisplacementForWordBinop(this, left, right);
  if (m.has_value()) {
    if (g.ValueFitsIntoImmediate(m->displacement)) {
      EmitLea(this, node, m->index, m->scale, m->base, m->displacement,
              m->displacement_mode);
      return;
    }
  }
  // No lea pattern, use add.
  VisitBinop(this, node, kIA32Add);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  IA32OperandGeneratorT<TurbofanAdapter> g(this);

  // Try to match the Add to a lea pattern
  BaseWithIndexAndDisplacement32Matcher m(node);
  if (m.matches() &&
      (m.displacement() == nullptr || g.CanBeImmediate(m.displacement()))) {
    InstructionOperand inputs[4];
    size_t input_count = 0;
    AddressingMode mode = g.GenerateMemoryOperandInputs(
        m.index(), m.scale(), m.base(), m.displacement(), m.displacement_mode(),
        inputs, &input_count);

    DCHECK_NE(0u, input_count);
    DCHECK_GE(arraysize(inputs), input_count);

    InstructionOperand outputs[1];
    outputs[0] = g.DefineAsRegister(node);

    InstructionCode opcode = AddressingModeField::encode(mode) | kIA32Lea;
    Emit(opcode, 1, outputs, input_count, inputs);
    return;
  }

  // No lea pattern match, use add
  VisitBinop(this, node, kIA32Add);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    IA32OperandGeneratorT<Adapter> g(this);
    auto binop = this->word_binop_view(node);
    auto left = binop.left();
    auto right = binop.right();
    if (this->MatchIntegralZero(left)) {
      Emit(kIA32Neg, g.DefineSameAsFirst(node), g.Use(right));
    } else {
      VisitBinop(this, node, kIA32Sub);
    }
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    Int32BinopMatcher m(node);
    if (m.left().Is(0)) {
      Emit(kIA32Neg, g.DefineSameAsFirst(node), g.Use(m.right().node()));
    } else {
      VisitBinop(this, node, kIA32Sub);
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mul(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    if (auto m = TryMatchScaledIndex(this, node, true)) {
      EmitLea(this, node, m->index, m->scale, m->base, 0,
              kPositiveDisplacement);
      return;
    }
  } else {
    Int32ScaleMatcher m(node, true);
    if (m.matches()) {
      Node* index = node->InputAt(0);
      Node* base = m.power_of_two_plus_one() ? index : nullptr;
      EmitLea(this, node, index, m.scale(), base, nullptr,
              kPositiveDisplacement);
      return;
    }
  }
  IA32OperandGeneratorT<Adapter> g(this);
  auto left = this->input_at(node, 0);
  auto right = this->input_at(node, 1);
  if (g.CanBeImmediate(right)) {
    Emit(kIA32Imul, g.DefineAsRegister(node), g.Use(left),
         g.UseImmediate(right));
  } else {
    if (g.CanBeBetterLeftOperand(right)) {
      std::swap(left, right);
    }
    Emit(kIA32Imul, g.DefineSameAsFirst(node), g.UseRegister(left),
         g.Use(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitMulHigh(this, node, kIA32ImulHigh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitMulHigh(this, node, kIA32UmulHigh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitDiv(this, node, kIA32Idiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitDiv(this, node, kIA32Udiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitMod(this, node, kIA32Idiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitMod(this, node, kIA32Udiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Uint32ToFloat32, g.DefineAsRegister(node),
       g.Use(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister(eax), g.TempRegister()};
  Emit(kIA32Float64Mod, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float32Max, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float64Max, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float32Min, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float64Min, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)))
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
  IA32OperandGeneratorT<Adapter> g(this);

  {  // Temporary scope to minimize indentation change churn below.
    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      InstructionOperand temps[] = {g.TempRegister()};
      size_t const temp_count = arraysize(temps);
      Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                           call_descriptor->ParameterCount())),
           0, nullptr, 0, nullptr, temp_count, temps);

      // Poke any stack arguments.
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          int const slot = static_cast<int>(n);
          // TODO(jkummerow): The next line should use `input.node`, but
          // fixing it causes mksnapshot failures. Investigate.
          InstructionOperand value = g.CanBeImmediate(node)
                                         ? g.UseImmediate(input.node)
                                         : g.UseRegister(input.node);
          Emit(kIA32Poke | MiscField::encode(slot), g.NoOutput(), value);
        }
      }
    } else {
      // Push any stack arguments.
      int effect_level = GetEffectLevel(node);
      int stack_decrement = 0;
      for (PushParameter input : base::Reversed(*arguments)) {
        stack_decrement += kSystemPointerSize;
        // Skip holes in the param array. These represent both extra slots for
        // multi-slot values and padding slots for alignment.
        if (!this->valid(input.node)) continue;
        InstructionOperand decrement = g.UseImmediate(stack_decrement);
        stack_decrement = 0;
        if (g.CanBeImmediate(input.node)) {
          Emit(kIA32Push, g.NoOutput(), decrement, g.UseImmediate(input.node));
        } else if (IsSupported(INTEL_ATOM) ||
                   sequence()->IsFP(GetVirtualRegister(input.node))) {
          // TODO(bbudge): IA32Push cannot handle stack->stack double moves
          // because there is no way to encode fixed double slots.
          Emit(kIA32Push, g.NoOutput(), decrement, g.UseRegister(input.node));
        } else if (g.CanBeMemoryOperand(kIA32Push, node, input.node,
                                        effect_level)) {
          InstructionOperand outputs[1];
          InstructionOperand inputs[5];
          size_t input_count = 0;
          inputs[input_count++] = decrement;
          AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
              input.node, inputs, &input_count);
          InstructionCode opcode =
              kIA32Push | AddressingModeField::encode(mode);
          Emit(opcode, 0, outputs, input_count, inputs);
        } else {
          Emit(kIA32Push, g.NoOutput(), decrement, g.UseAny(input.node));
        }
      }
    }  // End of temporary scope.
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  {  // Temporary scope to minimize indentation change churn below.
    IA32OperandGeneratorT<Adapter> g(this);

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
        Emit(kIA32Peek, g.DefineAsRegister(output.node),
             g.UseImmediate(reverse_slot));
      }
    }
  }  // End of temporary scope.
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return true;
}

namespace {

template <typename Adapter>
void VisitCompareWithMemoryOperand(InstructionSelectorT<Adapter>* selector,
                                   InstructionCode opcode,
                                   typename Adapter::node_t left,
                                   InstructionOperand right,
                                   FlagsContinuationT<Adapter>* cont) {
  DCHECK(selector->IsLoadOrLoadImmutable(left));
  IA32OperandGeneratorT<Adapter> g(selector);
  size_t input_count = 0;
  InstructionOperand inputs[4];
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(left, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);
  inputs[input_count++] = right;

  selector->EmitWithContinuation(opcode, 0, nullptr, input_count, inputs, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, typename Adapter::node_t left,
                  typename Adapter::node_t right,
                  FlagsContinuationT<Adapter>* cont, bool commutative) {
  IA32OperandGeneratorT<Adapter> g(selector);
  if (commutative && g.CanBeBetterLeftOperand(right)) {
    std::swap(left, right);
  }
  VisitCompare(selector, opcode, g.UseRegister(left), g.Use(right), cont);
}

template <typename Adapter>
MachineType MachineTypeForNarrow(InstructionSelectorT<Adapter>* selector,
                                 typename Adapter::node_t node,
                                 typename Adapter::node_t hint_node) {
  if (selector->IsLoadOrLoadImmutable(hint_node)) {
    MachineType hint = selector->load_view(hint_
Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/instruction-selector-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
Fixed(node, eax);
  node_t projection1 = selector->FindProjection(node, 1);
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, edx);
  } else {
    temps[temp_count++] = g.TempRegister(edx);
  }

  selector->Emit(opcode, output_count, outputs, 3, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShl(node_t node) {
  VisitWord32PairShift(this, kIA32ShlPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShr(node_t node) {
  VisitWord32PairShift(this, kIA32ShrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairSar(node_t node) {
  VisitWord32PairShift(this, kIA32SarPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  VisitShift(this, node, kIA32Rol);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitShift(this, node, kIA32Ror);
}

#define RO_OP_T_LIST(V)                                      \
  V(Float32Sqrt, kIA32Float32Sqrt)                           \
  V(Float64Sqrt, kIA32Float64Sqrt)                           \
  V(ChangeInt32ToFloat64, kSSEInt32ToFloat64)                \
  V(TruncateFloat32ToInt32, kIA32Float32ToInt32)             \
  V(TruncateFloat64ToFloat32, kIA32Float64ToFloat32)         \
  V(BitcastFloat32ToInt32, kIA32BitcastFI)                   \
  V(BitcastInt32ToFloat32, kIA32BitcastIF)                   \
  V(Float64ExtractLowWord32, kIA32Float64ExtractLowWord32)   \
  V(Float64ExtractHighWord32, kIA32Float64ExtractHighWord32) \
  V(ChangeFloat64ToInt32, kIA32Float64ToInt32)               \
  V(ChangeFloat32ToFloat64, kIA32Float32ToFloat64)           \
  V(RoundInt32ToFloat32, kSSEInt32ToFloat32)                 \
  V(RoundFloat64ToInt32, kIA32Float64ToInt32)                \
  V(Word32Clz, kIA32Lzcnt)                                   \
  V(Word32Ctz, kIA32Tzcnt)                                   \
  V(Word32Popcnt, kIA32Popcnt)                               \
  V(SignExtendWord8ToInt32, kIA32Movsxbl)                    \
  V(SignExtendWord16ToInt32, kIA32Movsxwl)                   \
  IF_WASM(V, F64x2Sqrt, kIA32F64x2Sqrt)

#define RO_WITH_TEMP_OP_T_LIST(V) V(ChangeUint32ToFloat64, kIA32Uint32ToFloat64)

#define RO_WITH_TEMP_SIMD_OP_T_LIST(V)             \
  V(TruncateFloat64ToUint32, kIA32Float64ToUint32) \
  V(TruncateFloat32ToUint32, kIA32Float32ToUint32) \
  V(ChangeFloat64ToUint32, kIA32Float64ToUint32)

#define RR_OP_T_LIST(V)                                                        \
  V(Float32RoundDown, kIA32Float32Round | MiscField::encode(kRoundDown))       \
  V(Float64RoundDown, kIA32Float64Round | MiscField::encode(kRoundDown))       \
  V(Float32RoundUp, kIA32Float32Round | MiscField::encode(kRoundUp))           \
  V(Float64RoundUp, kIA32Float64Round | MiscField::encode(kRoundUp))           \
  V(Float32RoundTruncate, kIA32Float32Round | MiscField::encode(kRoundToZero)) \
  V(Float64RoundTruncate, kIA32Float64Round | MiscField::encode(kRoundToZero)) \
  V(Float32RoundTiesEven,                                                      \
    kIA32Float32Round | MiscField::encode(kRoundToNearest))                    \
  V(Float64RoundTiesEven,                                                      \
    kIA32Float64Round | MiscField::encode(kRoundToNearest))                    \
  V(TruncateFloat64ToWord32, kArchTruncateDoubleToI)                           \
  IF_WASM(V, F32x4Ceil, kIA32F32x4Round | MiscField::encode(kRoundUp))         \
  IF_WASM(V, F32x4Floor, kIA32F32x4Round | MiscField::encode(kRoundDown))      \
  IF_WASM(V, F32x4Trunc, kIA32F32x4Round | MiscField::encode(kRoundToZero))    \
  IF_WASM(V, F32x4NearestInt,                                                  \
          kIA32F32x4Round | MiscField::encode(kRoundToNearest))                \
  IF_WASM(V, F64x2Ceil, kIA32F64x2Round | MiscField::encode(kRoundUp))         \
  IF_WASM(V, F64x2Floor, kIA32F64x2Round | MiscField::encode(kRoundDown))      \
  IF_WASM(V, F64x2Trunc, kIA32F64x2Round | MiscField::encode(kRoundToZero))    \
  IF_WASM(V, F64x2NearestInt,                                                  \
          kIA32F64x2Round | MiscField::encode(kRoundToNearest))

#define RRO_FLOAT_OP_T_LIST(V)        \
  V(Float32Add, kFloat32Add)          \
  V(Float64Add, kFloat64Add)          \
  V(Float32Sub, kFloat32Sub)          \
  V(Float64Sub, kFloat64Sub)          \
  V(Float32Mul, kFloat32Mul)          \
  V(Float64Mul, kFloat64Mul)          \
  V(Float32Div, kFloat32Div)          \
  V(Float64Div, kFloat64Div)          \
  IF_WASM(V, F64x2Add, kIA32F64x2Add) \
  IF_WASM(V, F64x2Sub, kIA32F64x2Sub) \
  IF_WASM(V, F64x2Mul, kIA32F64x2Mul) \
  IF_WASM(V, F64x2Div, kIA32F64x2Div) \
  IF_WASM(V, F64x2Eq, kIA32F64x2Eq)   \
  IF_WASM(V, F64x2Ne, kIA32F64x2Ne)   \
  IF_WASM(V, F64x2Lt, kIA32F64x2Lt)   \
  IF_WASM(V, F64x2Le, kIA32F64x2Le)

#define FLOAT_UNOP_T_LIST(V)        \
  V(Float32Abs, kFloat32Abs)        \
  V(Float64Abs, kFloat64Abs)        \
  V(Float32Neg, kFloat32Neg)        \
  V(Float64Neg, kFloat64Neg)        \
  IF_WASM(V, F32x4Abs, kFloat32Abs) \
  IF_WASM(V, F32x4Neg, kFloat32Neg) \
  IF_WASM(V, F64x2Abs, kFloat64Abs) \
  IF_WASM(V, F64x2Neg, kFloat64Neg)

#define RO_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRO(this, node, opcode);                                 \
  }
RO_OP_T_LIST(RO_VISITOR)
#undef RO_VISITOR
#undef RO_OP_T_LIST

#define RO_WITH_TEMP_VISITOR(Name, opcode)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitROWithTemp(this, node, opcode);                         \
  }
RO_WITH_TEMP_OP_T_LIST(RO_WITH_TEMP_VISITOR)
#undef RO_WITH_TEMP_VISITOR
#undef RO_WITH_TEMP_OP_T_LIST

#define RO_WITH_TEMP_SIMD_VISITOR(Name, opcode)                  \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitROWithTempSimd(this, node, opcode);                     \
  }
RO_WITH_TEMP_SIMD_OP_T_LIST(RO_WITH_TEMP_SIMD_VISITOR)
#undef RO_WITH_TEMP_SIMD_VISITOR
#undef RO_WITH_TEMP_SIMD_OP_T_LIST

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, node, opcode);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

#define RRO_FLOAT_VISITOR(Name, opcode)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRROFloat(this, node, opcode);                           \
  }
RRO_FLOAT_OP_T_LIST(RRO_FLOAT_VISITOR)
#undef RRO_FLOAT_VISITOR
#undef RRO_FLOAT_OP_T_LIST

#define FLOAT_UNOP_VISITOR(Name, opcode)                         \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    DCHECK_EQ(this->value_input_count(node), 1);                 \
    VisitFloatUnop(this, node, this->input_at(node, 0), opcode); \
  }
FLOAT_UNOP_T_LIST(FLOAT_UNOP_VISITOR)
#undef FLOAT_UNOP_VISITOR
#undef FLOAT_UNOP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  DCHECK_EQ(this->value_input_count(node), 1);
  Emit(kIA32Bswap, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  IA32OperandGeneratorT<TurboshaftAdapter> g(this);
  const turboshaft::WordBinopOp& add =
      this->Get(node).template Cast<turboshaft::WordBinopOp>();
  turboshaft::OpIndex left = add.left();
  turboshaft::OpIndex right = add.right();

  std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>> m =
      TryMatchBaseWithScaledIndexAndDisplacementForWordBinop(this, left, right);
  if (m.has_value()) {
    if (g.ValueFitsIntoImmediate(m->displacement)) {
      EmitLea(this, node, m->index, m->scale, m->base, m->displacement,
              m->displacement_mode);
      return;
    }
  }
  // No lea pattern, use add.
  VisitBinop(this, node, kIA32Add);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  IA32OperandGeneratorT<TurbofanAdapter> g(this);

  // Try to match the Add to a lea pattern
  BaseWithIndexAndDisplacement32Matcher m(node);
  if (m.matches() &&
      (m.displacement() == nullptr || g.CanBeImmediate(m.displacement()))) {
    InstructionOperand inputs[4];
    size_t input_count = 0;
    AddressingMode mode = g.GenerateMemoryOperandInputs(
        m.index(), m.scale(), m.base(), m.displacement(), m.displacement_mode(),
        inputs, &input_count);

    DCHECK_NE(0u, input_count);
    DCHECK_GE(arraysize(inputs), input_count);

    InstructionOperand outputs[1];
    outputs[0] = g.DefineAsRegister(node);

    InstructionCode opcode = AddressingModeField::encode(mode) | kIA32Lea;
    Emit(opcode, 1, outputs, input_count, inputs);
    return;
  }

  // No lea pattern match, use add
  VisitBinop(this, node, kIA32Add);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    IA32OperandGeneratorT<Adapter> g(this);
    auto binop = this->word_binop_view(node);
    auto left = binop.left();
    auto right = binop.right();
    if (this->MatchIntegralZero(left)) {
      Emit(kIA32Neg, g.DefineSameAsFirst(node), g.Use(right));
    } else {
      VisitBinop(this, node, kIA32Sub);
    }
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    Int32BinopMatcher m(node);
    if (m.left().Is(0)) {
      Emit(kIA32Neg, g.DefineSameAsFirst(node), g.Use(m.right().node()));
    } else {
      VisitBinop(this, node, kIA32Sub);
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mul(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    if (auto m = TryMatchScaledIndex(this, node, true)) {
      EmitLea(this, node, m->index, m->scale, m->base, 0,
              kPositiveDisplacement);
      return;
    }
  } else {
    Int32ScaleMatcher m(node, true);
    if (m.matches()) {
      Node* index = node->InputAt(0);
      Node* base = m.power_of_two_plus_one() ? index : nullptr;
      EmitLea(this, node, index, m.scale(), base, nullptr,
              kPositiveDisplacement);
      return;
    }
  }
  IA32OperandGeneratorT<Adapter> g(this);
  auto left = this->input_at(node, 0);
  auto right = this->input_at(node, 1);
  if (g.CanBeImmediate(right)) {
    Emit(kIA32Imul, g.DefineAsRegister(node), g.Use(left),
         g.UseImmediate(right));
  } else {
    if (g.CanBeBetterLeftOperand(right)) {
      std::swap(left, right);
    }
    Emit(kIA32Imul, g.DefineSameAsFirst(node), g.UseRegister(left),
         g.Use(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitMulHigh(this, node, kIA32ImulHigh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitMulHigh(this, node, kIA32UmulHigh);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitDiv(this, node, kIA32Idiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitDiv(this, node, kIA32Udiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitMod(this, node, kIA32Idiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitMod(this, node, kIA32Udiv);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Uint32ToFloat32, g.DefineAsRegister(node),
       g.Use(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister(eax), g.TempRegister()};
  Emit(kIA32Float64Mod, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Max(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float32Max, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Max(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float64Max, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Min(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float32Min, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Min(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32Float64Min, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), g.Use(this->input_at(node, 1)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)))
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
  IA32OperandGeneratorT<Adapter> g(this);

  {  // Temporary scope to minimize indentation change churn below.
    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      InstructionOperand temps[] = {g.TempRegister()};
      size_t const temp_count = arraysize(temps);
      Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                           call_descriptor->ParameterCount())),
           0, nullptr, 0, nullptr, temp_count, temps);

      // Poke any stack arguments.
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          int const slot = static_cast<int>(n);
          // TODO(jkummerow): The next line should use `input.node`, but
          // fixing it causes mksnapshot failures. Investigate.
          InstructionOperand value = g.CanBeImmediate(node)
                                         ? g.UseImmediate(input.node)
                                         : g.UseRegister(input.node);
          Emit(kIA32Poke | MiscField::encode(slot), g.NoOutput(), value);
        }
      }
    } else {
      // Push any stack arguments.
      int effect_level = GetEffectLevel(node);
      int stack_decrement = 0;
      for (PushParameter input : base::Reversed(*arguments)) {
        stack_decrement += kSystemPointerSize;
        // Skip holes in the param array. These represent both extra slots for
        // multi-slot values and padding slots for alignment.
        if (!this->valid(input.node)) continue;
        InstructionOperand decrement = g.UseImmediate(stack_decrement);
        stack_decrement = 0;
        if (g.CanBeImmediate(input.node)) {
          Emit(kIA32Push, g.NoOutput(), decrement, g.UseImmediate(input.node));
        } else if (IsSupported(INTEL_ATOM) ||
                   sequence()->IsFP(GetVirtualRegister(input.node))) {
          // TODO(bbudge): IA32Push cannot handle stack->stack double moves
          // because there is no way to encode fixed double slots.
          Emit(kIA32Push, g.NoOutput(), decrement, g.UseRegister(input.node));
        } else if (g.CanBeMemoryOperand(kIA32Push, node, input.node,
                                        effect_level)) {
          InstructionOperand outputs[1];
          InstructionOperand inputs[5];
          size_t input_count = 0;
          inputs[input_count++] = decrement;
          AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
              input.node, inputs, &input_count);
          InstructionCode opcode =
              kIA32Push | AddressingModeField::encode(mode);
          Emit(opcode, 0, outputs, input_count, inputs);
        } else {
          Emit(kIA32Push, g.NoOutput(), decrement, g.UseAny(input.node));
        }
      }
    }  // End of temporary scope.
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
  {  // Temporary scope to minimize indentation change churn below.
    IA32OperandGeneratorT<Adapter> g(this);

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
        Emit(kIA32Peek, g.DefineAsRegister(output.node),
             g.UseImmediate(reverse_slot));
      }
    }
  }  // End of temporary scope.
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsTailCallAddressImmediate() {
  return true;
}

namespace {

template <typename Adapter>
void VisitCompareWithMemoryOperand(InstructionSelectorT<Adapter>* selector,
                                   InstructionCode opcode,
                                   typename Adapter::node_t left,
                                   InstructionOperand right,
                                   FlagsContinuationT<Adapter>* cont) {
  DCHECK(selector->IsLoadOrLoadImmutable(left));
  IA32OperandGeneratorT<Adapter> g(selector);
  size_t input_count = 0;
  InstructionOperand inputs[4];
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(left, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);
  inputs[input_count++] = right;

  selector->EmitWithContinuation(opcode, 0, nullptr, input_count, inputs, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, InstructionOperand left,
                  InstructionOperand right, FlagsContinuationT<Adapter>* cont) {
  selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
void VisitCompare(InstructionSelectorT<Adapter>* selector,
                  InstructionCode opcode, typename Adapter::node_t left,
                  typename Adapter::node_t right,
                  FlagsContinuationT<Adapter>* cont, bool commutative) {
  IA32OperandGeneratorT<Adapter> g(selector);
  if (commutative && g.CanBeBetterLeftOperand(right)) {
    std::swap(left, right);
  }
  VisitCompare(selector, opcode, g.UseRegister(left), g.Use(right), cont);
}

template <typename Adapter>
MachineType MachineTypeForNarrow(InstructionSelectorT<Adapter>* selector,
                                 typename Adapter::node_t node,
                                 typename Adapter::node_t hint_node) {
  if (selector->IsLoadOrLoadImmutable(hint_node)) {
    MachineType hint = selector->load_view(hint_node).loaded_rep();
    if (selector->is_integer_constant(node)) {
      int64_t constant = selector->integer_constant(node);
      if (hint == MachineType::Int8()) {
        if (constant >= std::numeric_limits<int8_t>::min() &&
            constant <= std::numeric_limits<int8_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Uint8()) {
        if (constant >= std::numeric_limits<uint8_t>::min() &&
            constant <= std::numeric_limits<uint8_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Int16()) {
        if (constant >= std::numeric_limits<int16_t>::min() &&
            constant <= std::numeric_limits<int16_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Uint16()) {
        if (constant >= std::numeric_limits<uint16_t>::min() &&
            constant <= std::numeric_limits<uint16_t>::max()) {
          return hint;
        }
      } else if (hint == MachineType::Int32()) {
        return hint;
      } else if (hint == MachineType::Uint32()) {
        if (constant >= 0) return hint;
      }
    }
  }
  return selector->IsLoadOrLoadImmutable(node)
             ? selector->load_view(node).loaded_rep()
             : MachineType::None();
}

// Tries to match the size of the given opcode to that of the operands, if
// possible.
template <typename Adapter>
InstructionCode TryNarrowOpcodeSize(InstructionSelectorT<Adapter>* selector,
                                    InstructionCode opcode,
                                    typename Adapter::node_t left,
                                    typename Adapter::node_t right,
                                    FlagsContinuationT<Adapter>* cont) {
  // TODO(epertoso): we can probably get some size information out of phi nodes.
  // If the load representations don't match, both operands will be
  // zero/sign-extended to 32bit.
  MachineType left_type = MachineTypeForNarrow(selector, left, right);
  MachineType right_type = MachineTypeForNarrow(selector, right, left);
  if (left_type == right_type) {
    switch (left_type.representation()) {
      case MachineRepresentation::kBit:
      case MachineRepresentation::kWord8: {
        if (opcode == kIA32Test) return kIA32Test8;
        if (opcode == kIA32Cmp) {
          if (left_type.semantic() == MachineSemantic::kUint32) {
            cont->OverwriteUnsignedIfSigned();
          } else {
            CHECK_EQ(MachineSemantic::kInt32, left_type.semantic());
          }
          return kIA32Cmp8;
        }
        break;
      }
      case MachineRepresentation::kWord16:
        if (opcode == kIA32Test) return kIA32Test16;
        if (opcode == kIA32Cmp) {
          if (left_type.semantic() == MachineSemantic::kUint32) {
            cont->OverwriteUnsignedIfSigned();
          } else {
            CHECK_EQ(MachineSemantic::kInt32, left_type.semantic());
          }
          return kIA32Cmp16;
        }
        break;
      default:
        break;
    }
  }
  return opcode;
}

// Shared routine for multiple float32 compare operations (inputs commuted).
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  VisitCompare(selector, kIA32Float32Cmp, right, left, cont, false);
}

// Shared routine for multiple float64 compare operations (inputs commuted).
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  VisitCompare(selector, kIA32Float64Cmp, right, left, cont, false);
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont) {
  {  // Temporary scope to minimize indentation change churn below.
    IA32OperandGeneratorT<Adapter> g(selector);
    auto left = selector->input_at(node, 0);
    auto right = selector->input_at(node, 1);

    InstructionCode narrowed_opcode =
        TryNarrowOpcodeSize(selector, opcode, left, right, cont);

    int effect_level = selector->GetEffectLevel(node, cont);

    // If one of the two inputs is an immediate, make sure it's on the right, or
    // if one of the two inputs is a memory operand, make sure it's on the left.
    if ((!g.CanBeImmediate(right) && g.CanBeImmediate(left)) ||
        (g.CanBeMemoryOperand(narrowed_opcode, node, right, effect_level) &&
         !g.CanBeMemoryOperand(narrowed_opcode, node, left, effect_level))) {
      if (!selector->IsCommutative(node)) cont->Commute();
      std::swap(left, right);
    }

    // Match immediates on right side of comparison.
    if (g.CanBeImmediate(right)) {
      if (g.CanBeMemoryOperand(narrowed_opcode, node, left, effect_level)) {
        return VisitCompareWithMemoryOperand(selector, narrowed_opcode, left,
                                             g.UseImmediate(right), cont);
      }
      return VisitCompare(selector, opcode, g.Use(left), g.UseImmediate(right),
                          cont);
    }

    // Match memory operands on left side of comparison.
    if (g.CanBeMemoryOperand(narrowed_opcode, node, left, effect_level)) {
      bool needs_byte_register =
          narrowed_opcode == kIA32Test8 || narrowed_opcode == kIA32Cmp8;
      return VisitCompareWithMemoryOperand(
          selector, narrowed_opcode, left,
          needs_byte_register ? g.UseByteRegister(right) : g.UseRegister(right),
          cont);
    }

    return VisitCompare(selector, opcode, left, right, cont,
                        selector->IsCommutative(node));
  }
}

template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node,
                      FlagsContinuationT<Adapter>* cont) {
  VisitWordCompare(selector, node, kIA32Cmp, cont);
}

template <typename Adapter>
void VisitAtomicBinOp(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      MachineRepresentation rep) {
  using node_t = typename Adapter::node_t;
  AddressingMode addressing_mode;
  IA32OperandGeneratorT<Adapter> g(selector);
  node_t base = selector->input_at(node, 0);
  node_t index = selector->input_at(node, 1);
  node_t value = selector->input_at(node, 2);
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(value), g.UseUniqueRegister(base),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, eax)};
  InstructionOperand temp[] = {(rep == MachineRepresentation::kWord8)
                                   ? g.UseByteRegister(node)
                                   : g.TempRegister()};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  selector->Emit(code, arraysize(outputs), outputs, arraysize(inputs), inputs,
                 arraysize(temp), temp);
}

template <typename Adapter>
void VisitPairAtomicBinOp(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node, ArchOpcode opcode) {
  using node_t = typename Adapter::node_t;
  IA32OperandGeneratorT<Adapter> g(selector);
  node_t base = selector->input_at(node, 0);
  node_t index = selector->input_at(node, 1);
  node_t value = selector->input_at(node, 2);
  // For Word64 operations, the value input is split into the a high node,
  // and a low node in the int64-lowering phase.
  node_t value_high = selector->input_at(node, 3);

  // Wasm lives in 32-bit address space, so we do not need to worry about
  // base/index lowering. This will need to be fixed for Wasm64.
  AddressingMode addressing_mode;
  InstructionOperand inputs[] = {
      g.UseUniqueRegisterOrSlotOrConstant(value), g.UseFixed(value_high, ecx),
      g.UseUniqueRegister(base),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  node_t projection0 = selector->FindProjection(node, 0);
  node_t projection1 = selector->FindProjection(node, 1);
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[2];
  size_t temp_count = 0;
  if (selector->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, eax);
  } else {
    temps[temp_count++] = g.TempRegister(eax);
  }
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, edx);
  } else {
    temps[temp_count++] = g.TempRegister(edx);
  }
  selector->Emit(code, output_count, outputs, arraysize(inputs), inputs,
                 temp_count, temps);
}

}  // namespace

// Shared routine for word comparison with zero.
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  ConsumeEqualZero(&user, &value, cont);

  if (CanCover(user, value)) {
    const Operation& value_op = Get(value);
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.MapTaggedToWord().value()) {
        case RegisterRepresentation::Word32():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));
          return VisitWordCompare(this, value, cont);
        case RegisterRepresentation::Float32():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        case RegisterRepresentation::Float64():
"""


```