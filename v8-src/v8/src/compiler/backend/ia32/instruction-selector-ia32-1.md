Response: The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the `instruction-selector-ia32.cc` file in the V8 JavaScript engine.

This code snippet appears to be responsible for selecting and emitting IA32 assembly instructions for various operations represented in V8's intermediate representation (IR).

Specifically, this part seems to handle:

- **Pair operations:** Operations involving pairs of 32-bit values (e.g., shifts).
- **Unary and binary operations:**  A wide range of arithmetic, logical, and bitwise operations on integers and floating-point numbers.
- **Conversions:**  Conversions between different data types (integer to float, float to integer, etc.).
- **SIMD operations:**  Some initial handling of SIMD (Single Instruction, Multiple Data) operations.

I need to summarize these functionalities concisely and provide a JavaScript example if any of these operations are directly related to JavaScript features.
这是 `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 文件的一部分，主要负责为 V8 的中间表示 (IR) 节点选择并生成对应的 IA32 汇编指令。

这部分代码主要关注以下功能：

1. **处理 32 位整数对 (Word32Pair) 的操作:** 包括左移、右移（逻辑和算术）。这些操作通常用于处理 64 位数据的低 32 位和高 32 位。
2. **处理位旋转操作:**  包括左旋 (`Rol`) 和右旋 (`Ror`)。
3. **定义并处理各种单操作数指令 (RO - Register Output):**  通过宏 `RO_OP_T_LIST` 定义了一系列单操作数指令，例如平方根、类型转换、位运算（计算前导零、尾随零、人口计数）、符号扩展等。这些操作接收一个输入，并将结果输出到一个寄存器。
4. **定义并处理需要临时寄存器的单操作数指令 (RO_WITH_TEMP):**  通过宏 `RO_WITH_TEMP_OP_T_LIST` 定义了需要临时寄存器辅助的单操作数指令，例如无符号整数到浮点数的转换。
5. **定义并处理需要临时寄存器的 SIMD 单操作数指令 (RO_WITH_TEMP_SIMD):** 通过宏 `RO_WITH_TEMP_SIMD_OP_T_LIST` 定义了需要临时寄存器的 SIMD 单操作数指令，例如浮点数截断为无符号整数。
6. **定义并处理寄存器到寄存器的双操作数指令 (RR - Register to Register):** 通过宏 `RR_OP_T_LIST` 定义了一系列寄存器到寄存器的双操作数指令，例如浮点数舍入和截断操作。
7. **定义并处理浮点数寄存器到寄存器的双操作数指令 (RRO_FLOAT):** 通过宏 `RRO_FLOAT_OP_T_LIST` 定义了一系列浮点数寄存器到寄存器的双操作数指令，例如浮点数的加减乘除比较等。
8. **定义并处理浮点数单操作数指令 (FLOAT_UNOP):** 通过宏 `FLOAT_UNOP_T_LIST` 定义了一系列浮点数单操作数指令，例如取绝对值和取反。
9. **实现上述定义的指令的 Visit 方法:**  使用宏 `RO_VISITOR`, `RO_WITH_TEMP_VISITOR`, `RR_VISITOR`, `RRO_FLOAT_VISITOR`, `FLOAT_UNOP_VISITOR` 为每种指令类型生成对应的 `Visit` 函数。`Visit` 函数负责从 IR 节点中提取操作数，并调用 `Emit` 方法生成相应的汇编指令。
10. **处理一些特殊的指令:**  例如 `TruncateFloat64ToFloat16RawBits` (未实现), `Word32ReverseBits` (不可达), `Word64ReverseBytes` (不可达), `Word32ReverseBytes` (字节反转) 和 `Simd128ReverseBytes` (不可达)。
11. **特定于 Turboshaft 和 Turbofan 的 `Int32Add` 实现:**  这部分尝试将加法操作匹配到 `lea` (load effective address) 指令，以进行更高效的地址计算。如果无法匹配，则使用标准的 `add` 指令。
12. **处理整数减法 (`Int32Sub`):**  如果减数是 0，则使用 `neg` 指令取反。
13. **处理整数乘法 (`Int32Mul`):**  尝试匹配到 `lea` 指令进行优化，否则使用 `imul` 指令。对于立即数乘法和寄存器乘法有不同的处理。
14. **处理高位乘法 (`Int32MulHigh`, `Uint32MulHigh`):**  调用 `VisitMulHigh` 生成高位乘法指令。
15. **处理除法和取模运算 (`Int32Div`, `Uint32Div`, `Int32Mod`, `Uint32Mod`):** 调用 `VisitDiv` 和 `VisitMod` 生成相应的除法和取模指令。
16. **处理浮点数取模 (`Float64Mod`)、最大值 (`Float32Max`, `Float64Max`)、最小值 (`Float32Min`, `Float64Min`) 等操作:** 生成相应的浮点数运算指令。
17. **处理浮点数的 IEEE 754 标准运算:**  为指定的 IEEE 754 二元和一元操作生成调用指令。
18. **处理函数调用相关的参数准备和结果准备:**  `EmitPrepareArguments` 和 `EmitPrepareResults` 负责在函数调用前后处理参数的压栈和结果的读取。
19. **实现尾调用地址是否为立即数的判断:** `IsTailCallAddressImmediate` 返回 `true`。

**与 JavaScript 的关系及示例:**

这些代码直接对应 JavaScript 中执行的各种操作。例如：

* **位运算:** JavaScript 中的 `<<`, `>>`, `>>>`, `|`, `&`, `^`, `~` 等位运算符会对应到这里的 `VisitWord32PairShl`, `VisitWord32PairShr`, 以及各种 `VisitWord32...` 的位运算指令。
* **算术运算:** JavaScript 中的 `+`, `-`, `*`, `/`, `%` 等算术运算符会对应到 `VisitInt32Add`, `VisitInt32Sub`, `VisitInt32Mul`, `VisitInt32Div`, `VisitInt32Mod` 等函数。
* **浮点数运算:** JavaScript 中的浮点数运算，例如 `Math.sqrt()`, `Math.floor()`, 以及基本的 `+`, `-`, `*`, `/` 等会对应到 `VisitFloat64Sqrt`, `VisitFloat64RoundDown`, `VisitFloat64Add` 等函数。
* **类型转换:** JavaScript 中 Number 类型的转换，例如 `parseInt()`, `parseFloat()`, 以及显式或隐式的类型转换，会对应到 `VisitChangeInt32ToFloat64`, `VisitTruncateFloat64ToInt32` 等函数。
* **SIMD 操作:** WebAssembly 的 SIMD 指令集，例如 `f64x2.add`, `i32x4.add` 等，会对应到 `VisitF64x2Add`, `VisitI32x4Add` 等函数。

**JavaScript 示例:**

```javascript
// 位运算
let a = 5 << 2;  // 对应 VisitWord32PairShl (如果处理的是 64 位整数) 或其他位移指令
let b = 10 & 3;  // 对应 VisitWord32And

// 算术运算
let sum = 5 + 3; // 对应 VisitInt32Add
let diff = 10 - 2; // 对应 VisitInt32Sub
let product = 4 * 6; // 对应 VisitInt32Mul
let quotient = 15 / 4; // 对应 VisitInt32Div 或浮点数除法

// 浮点数运算
let sqrtValue = Math.sqrt(25); // 对应 VisitFloat64Sqrt
let roundedValue = Math.floor(3.7); // 对应 VisitFloat64RoundDown

// 类型转换
let intValue = parseInt("10"); // 可能会对应到相关的类型转换指令
let floatValue = parseFloat("3.14"); // 可能会对应到相关的类型转换指令

// WebAssembly SIMD (如果代码在处理 WebAssembly)
// const a = f64x2(1.0, 2.0);
// const b = f64x2(3.0, 4.0);
// const sum_simd = f64x2.add(a, b); // 对应 VisitF64x2Add
```

总而言之，这部分代码是 V8 引擎将 JavaScript 代码转换成底层机器码的关键部分，它负责将高级的抽象操作映射到具体的 IA32 汇编指令，以便 CPU 可以执行。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        default:
          break;
      }
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWordCompare(this, value, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kIA32Test, cont);
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // OverflowCheckedBinop operation.
      if (projection->index == 1u) {
        // We cannot combine the OverflowCheckedBinop operation with this branch
        // unless the 0th projection (the use of the actual value of the
        // operation is either {OpIndex::Invalid()}, which means there's no use
        // of the actual value, or was already defined, which means it is
        // scheduled *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  this->TryCast<OverflowCheckedBinopOp>(node)) {
            DCHECK_EQ(binop->rep, WordRepresentation::Word32());
            cont->OverwriteAndNegateIfEqual(kOverflow);
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                return VisitBinop(this, node, kIA32Add, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                return VisitBinop(this, node, kIA32Sub, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                return VisitBinop(this, node, kIA32Imul, cont);
            }
            UNREACHABLE();
          }
        }
      }
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  // Branch could not be combined with a compare, emit compare against 0.
  IA32OperandGeneratorT<TurboshaftAdapter> g(this);
  VisitCompare(this, kIA32Cmp, g.Use(value), g.TempImmediate(0), cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    UNREACHABLE();  // Template-specialized above.
  } else {
    // Try to combine with comparisons against 0 by simply inverting the branch.
    while (value->opcode() == IrOpcode::kWord32Equal && CanCover(user, value)) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;

      user = value;
      value = m.left().node();
      cont->Negate();
    }

    if (CanCover(user, value)) {
      switch (value->opcode()) {
        case IrOpcode::kWord32Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kInt32LessThan:
          cont->OverwriteAndNegateIfEqual(kSignedLessThan);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kInt32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kUint32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kUint32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kFloat32Equal:
          cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat64Equal:
          cont->OverwriteAndNegateIfEqual(kUnorderedEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThan:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThan);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kUnsignedGreaterThanOrEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kProjection:
          // Check if this is the overflow output projection of an
          // <Operation>WithOverflow node.
          if (ProjectionIndexOf(value->op()) == 1u) {
            // We cannot combine the <Operation>WithOverflow with this branch
            // unless the 0th projection (the use of the actual value of the
            // <Operation> is either nullptr, which means there's no use of the
            // actual value, or was already defined, which means it is scheduled
            // *AFTER* this branch).
            Node* const node = value->InputAt(0);
            Node* const result = NodeProperties::FindProjection(node, 0);
            if (result == nullptr || IsDefined(result)) {
              switch (node->opcode()) {
                case IrOpcode::kInt32AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kIA32Add, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kIA32Sub, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kIA32Imul, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kInt32Sub:
          return VisitWordCompare(this, value, cont);
        case IrOpcode::kWord32And:
          return VisitWordCompare(this, value, kIA32Test, cont);
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    IA32OperandGeneratorT<Adapter> g(this);
    VisitCompare(this, kIA32Cmp, g.Use(value), g.TempImmediate(0), cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
  {  // Temporary scope to minimize indentation change churn below.
    IA32OperandGeneratorT<Adapter> g(this);
    InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

    // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
    if (enable_switch_jump_table_ ==
        InstructionSelector::kEnableSwitchJumpTable) {
      static const size_t kMaxTableSwitchValueRange = 2 << 16;
      size_t table_space_cost = 4 + sw.value_range();
      size_t table_time_cost = 3;
      size_t lookup_space_cost = 3 + 2 * sw.case_count();
      size_t lookup_time_cost = sw.case_count();
      if (sw.case_count() > 4 &&
          table_space_cost + 3 * table_time_cost <=
              lookup_space_cost + 3 * lookup_time_cost &&
          sw.min_value() > std::numeric_limits<int32_t>::min() &&
          sw.value_range() <= kMaxTableSwitchValueRange) {
        InstructionOperand index_operand = value_operand;
        if (sw.min_value()) {
          index_operand = g.TempRegister();
          Emit(kIA32Lea | AddressingModeField::encode(kMode_MRI), index_operand,
               value_operand, g.TempImmediate(-sw.min_value()));
        }
        // Generate a table lookup.
        return EmitTableSwitch(sw, index_operand);
      }
    }

    // Generate a tree of conditional jumps.
    return EmitBinarySearchSwitch(sw, value_operand);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::ComparisonOp& comparison =
        this->Get(node).template Cast<turboshaft::ComparisonOp>();
    if (this->MatchIntegralZero(comparison.right())) {
      return VisitWordCompareZero(node, comparison.left(), &cont);
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }
  }
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kIA32Add, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kIA32Add, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kIA32Sub, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kIA32Sub, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop(this, node, kIA32Imul, &cont);
  }
  FlagsContinuation cont;
  VisitBinop(this, node, kIA32Imul, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnorderedEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThan(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThan, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThanOrEqual, node);
  VisitFloat32Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Equal(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnorderedEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThan(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThan, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedGreaterThanOrEqual, node);
  VisitFloat64Compare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertLowWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // Turboshaft uses {BitcastWord32PairToFloat64}.
    UNREACHABLE();
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Float64Matcher mleft(left);
    if (mleft.HasResolvedValue() &&
        (base::bit_cast<uint64_t>(mleft.ResolvedValue()) >> 32) == 0u) {
      Emit(kIA32Float64LoadLowWord32, g.DefineAsRegister(node), g.Use(right));
      return;
    }
    Emit(kIA32Float64InsertLowWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.Use(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64InsertHighWord32(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // Turboshaft uses {BitcastWord32PairToFloat64}.
    UNREACHABLE();
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    Node* left = node->InputAt(0);
    Node* right = node->InputAt(1);
    Emit(kIA32Float64InsertHighWord32, g.DefineSameAsFirst(node),
         g.UseRegister(left), g.Use(right));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32PairToFloat64(
    node_t node) {
  if constexpr (Adapter::IsTurbofan) {
    // Turbofan uses {Float64Insert{High,Low}Word32}.
    UNREACHABLE();
  } else {
    IA32OperandGeneratorT<Adapter> g(this);
    const turboshaft::BitcastWord32PairToFloat64Op& cast_op =
        this->Get(node)
            .template Cast<turboshaft::BitcastWord32PairToFloat64Op>();
    Emit(kIA32Float64FromWord32Pair, g.DefineAsRegister(node),
         g.Use(cast_op.low_word32()), g.Use(cast_op.high_word32()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64SilenceNaN(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kIA32Float64SilenceNaN, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitMemoryBarrier(node_t node) {
  // ia32 is no weaker than release-acquire and only needs to emit an
  // instruction for SeqCst memory barriers.
  AtomicMemoryOrder order = AtomicOrder(this, node);
  if (order == AtomicMemoryOrder::kSeqCst) {
    IA32OperandGeneratorT<Adapter> g(this);
    Emit(kIA32MFence, g.NoOutput());
    return;
  }
  DCHECK_EQ(AtomicMemoryOrder::kAcqRel, order);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(load_rep.representation() == MachineRepresentation::kWord8 ||
         load_rep.representation() == MachineRepresentation::kWord16 ||
         load_rep.representation() == MachineRepresentation::kWord32 ||
         load_rep.representation() == MachineRepresentation::kTaggedSigned ||
         load_rep.representation() == MachineRepresentation::kTaggedPointer ||
         load_rep.representation() == MachineRepresentation::kTagged);
  // The memory order is ignored as both acquire and sequentially consistent
  // loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  VisitStoreCommon(this, this->store_view(node));
}

MachineType AtomicOpType(InstructionSelectorT<TurboshaftAdapter>* selector,
                         turboshaft::OpIndex node) {
  const turboshaft::AtomicRMWOp& atomic_op =
      selector->Get(node).template Cast<turboshaft::AtomicRMWOp>();
  return atomic_op.memory_rep.ToMachineType();
}

MachineType AtomicOpType(InstructionSelectorT<TurbofanAdapter>* selector,
                         Node* node) {
  return AtomicOpType(node->op());
}

AtomicMemoryOrder AtomicOrder(InstructionSelectorT<TurboshaftAdapter>* selector,
                              turboshaft::OpIndex node) {
  const turboshaft::Operation& op = selector->Get(node);
  if (op.Is<turboshaft::AtomicWord32PairOp>()) {
    // TODO(nicohartmann): Turboshaft doesn't support configurable memory
    // orders yet; see also {TurboshaftAdapter::StoreView}.
    return AtomicMemoryOrder::kSeqCst;
  }
  if (const turboshaft::MemoryBarrierOp* barrier =
          op.TryCast<turboshaft::MemoryBarrierOp>()) {
    return barrier->memory_order;
  }
  UNREACHABLE();
}

AtomicMemoryOrder AtomicOrder(InstructionSelectorT<TurbofanAdapter>* selector,
                              Node* node) {
  return OpParameter<AtomicMemoryOrder>(node->op());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  MachineType type = AtomicOpType(this, node);
  ArchOpcode opcode;
  if (type == MachineType::Int8()) {
    opcode = kAtomicExchangeInt8;
  } else if (type == MachineType::Uint8()) {
    opcode = kAtomicExchangeUint8;
  } else if (type == MachineType::Int16()) {
    opcode = kAtomicExchangeInt16;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicExchangeUint16;
  } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
    opcode = kAtomicExchangeWord32;
  } else {
    UNREACHABLE();
  }
  VisitAtomicExchange(this, node, opcode, type.representation());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  auto atomic_op = this->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  MachineType type = AtomicOpType(this, node);
  ArchOpcode opcode;
  if (type == MachineType::Int8()) {
    opcode = kAtomicCompareExchangeInt8;
  } else if (type == MachineType::Uint8()) {
    opcode = kAtomicCompareExchangeUint8;
  } else if (type == MachineType::Int16()) {
    opcode = kAtomicCompareExchangeInt16;
  } else if (type == MachineType::Uint16()) {
    opcode = kAtomicCompareExchangeUint16;
  } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
    opcode = kAtomicCompareExchangeWord32;
  } else {
    UNREACHABLE();
  }
  AddressingMode addressing_mode;
  InstructionOperand new_val_operand =
      (type.representation() == MachineRepresentation::kWord8)
          ? g.UseByteRegister(new_value)
          : g.UseUniqueRegister(new_value);
  InstructionOperand inputs[] = {
      g.UseFixed(old_value, eax), new_val_operand, g.UseUniqueRegister(base),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  InstructionOperand outputs[] = {g.DefineAsFixed(node, eax)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  Emit(code, 1, outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  {  // Temporary scope to minimize indentation change churn below.
    MachineType type = AtomicOpType(this, node);
    ArchOpcode opcode;
    if (type == MachineType::Int8()) {
      opcode = int8_op;
    } else if (type == MachineType::Uint8()) {
      opcode = uint8_op;
    } else if (type == MachineType::Int16()) {
      opcode = int16_op;
    } else if (type == MachineType::Uint16()) {
      opcode = uint16_op;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = word32_op;
    } else {
      UNREACHABLE();
    }
    VisitAtomicBinOp(this, node, opcode, type.representation());
  }
}

#define VISIT_ATOMIC_BINOP(op)                                             \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::VisitWord32Atomic##op(node_t node) { \
    VisitWord32AtomicBinaryOperation(                                      \
        node, kAtomic##op##Int8, kAtomic##op##Uint8, kAtomic##op##Int16,   \
        kAtomic##op##Uint16, kAtomic##op##Word32);                         \
  }
VISIT_ATOMIC_BINOP(Add)
VISIT_ATOMIC_BINOP(Sub)
VISIT_ATOMIC_BINOP(And)
VISIT_ATOMIC_BINOP(Or)
VISIT_ATOMIC_BINOP(Xor)
#undef VISIT_ATOMIC_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairLoad(node_t node) {
  // Both acquire and sequentially consistent loads can emit MOV.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
  IA32OperandGeneratorT<Adapter> g(this);
  AddressingMode mode;
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection0) && this->valid(projection1)) {
    InstructionOperand inputs[] = {g.UseUniqueRegister(base),
                                   g.GetEffectiveIndexOperand(index, &mode)};
    InstructionCode code =
        kIA32Word32AtomicPairLoad | AddressingModeField::encode(mode);
    InstructionOperand outputs[] = {g.DefineAsRegister(projection0),
                                    g.DefineAsRegister(projection1)};
    Emit(code, 2, outputs, 2, inputs);
  } else if (this->valid(projection0) || this->valid(projection1)) {
    // Only one word is needed, so it's enough to load just that.
    ArchOpcode opcode = kIA32Movl;

    InstructionOperand outputs[] = {g.DefineAsRegister(
        this->valid(projection0) ? projection0 : projection1)};
    InstructionOperand inputs[3];
    size_t input_count = 0;
    // TODO(ahaas): Introduce an enum for {scale} instead of an integer.
    // {scale = 0} means *1 in the generated code.
    int scale = 0;
    AddressingMode mode = g.GenerateMemoryOperandInputs(
        index, scale, base, this->valid(projection0) ? 0 : 4,
        kPositiveDisplacement, inputs, &input_count);
    InstructionCode code = opcode | AddressingModeField::encode(mode);
    Emit(code, 1, outputs, input_count, inputs);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairStore(node_t node) {
  // Release pair stores emit a MOVQ via a double register, and sequentially
  // consistent stores emit CMPXCHG8B.
  // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html

  IA32OperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  node_t value = this->input_at(node, 2);
  node_t value_high = this->input_at(node, 3);

  AtomicMemoryOrder order = AtomicOrder(this, node);
  if (order == AtomicMemoryOrder::kAcqRel) {
    AddressingMode addressing_mode;
    InstructionOperand inputs[] = {
        g.UseUniqueRegisterOrSlotOrConstant(value),
        g.UseUniqueRegisterOrSlotOrConstant(value_high),
        g.UseUniqueRegister(base),
        g.GetEffectiveIndexOperand(index, &addressing_mode),
    };
    InstructionCode code = kIA32Word32ReleasePairStore |
                           AddressingModeField::encode(addressing_mode);
    Emit(code, 0, nullptr, arraysize(inputs), inputs);
  } else {
    DCHECK_EQ(order, AtomicMemoryOrder::kSeqCst);

    AddressingMode addressing_mode;
    InstructionOperand inputs[] = {
        g.UseUniqueRegisterOrSlotOrConstant(value), g.UseFixed(value_high, ecx),
        g.UseUniqueRegister(base),
        g.GetEffectiveIndexOperand(index, &addressing_mode)};
    // Allocating temp registers here as stores are performed using an atomic
    // exchange, the output of which is stored in edx:eax, which should be saved
    // and restored at the end of the instruction.
    InstructionOperand temps[] = {g.TempRegister(eax), g.TempRegister(edx)};
    const int num_temps = arraysize(temps);
    InstructionCode code = kIA32Word32SeqCstPairStore |
                           AddressingModeField::encode(addressing_mode);
    Emit(code, 0, nullptr, arraysize(inputs), inputs, num_temps, temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAdd(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairSub(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairSub);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairAnd(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairOr(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairXor(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairXor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairExchange(node_t node) {
  VisitPairAtomicBinOp(this, node, kIA32Word32AtomicPairExchange);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicPairCompareExchange(
    node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  node_t index = this->input_at(node, 1);
  AddressingMode addressing_mode;

  // In the Turbofan and the Turboshaft graph the order of expected and value is
  // swapped.
  const size_t expected_offset = Adapter::IsTurboshaft ? 4 : 2;
  const size_t value_offset = Adapter::IsTurboshaft ? 2 : 4;
  InstructionOperand inputs[] = {
      // High, Low values of old value
      g.UseFixed(this->input_at(node, expected_offset), eax),
      g.UseFixed(this->input_at(node, expected_offset + 1), edx),
      // High, Low values of new value
      g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, value_offset)),
      g.UseFixed(this->input_at(node, value_offset + 1), ecx),
      // InputAt(0) => base
      g.UseUniqueRegister(this->input_at(node, 0)),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  node_t projection0 = FindProjection(node, 0);
  node_t projection1 = FindProjection(node, 1);
  InstructionCode code = kIA32Word32AtomicPairCompareExchange |
                         AddressingModeField::encode(addressing_mode);

  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[2];
  size_t temp_count = 0;
  if (this->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, eax);
  } else {
    temps[temp_count++] = g.TempRegister(eax);
  }
  if (this->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, edx);
  } else {
    temps[temp_count++] = g.TempRegister(edx);
  }
  Emit(code, output_count, outputs, arraysize(inputs), inputs, temp_count,
       temps);
}

#define SIMD_INT_TYPES(V) \
  V(I32x4)                \
  V(I16x8)                \
  V(I8x16)

#define SIMD_BINOP_LIST(V) \
  V(I32x4GtU)              \
  V(I32x4GeU)              \
  V(I16x8Ne)               \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8GeU)              \
  V(I8x16Ne)               \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16GeU)

#define SIMD_BINOP_UNIFIED_SSE_AVX_LIST(V) \
  V(F32x4Add)                              \
  V(F32x4Sub)                              \
  V(F32x4Mul)                              \
  V(F32x4Div)                              \
  V(F32x4Eq)                               \
  V(F32x4Ne)                               \
  V(F32x4Lt)                               \
  V(F32x4Le)                               \
  V(F32x4Min)                              \
  V(F32x4Max)                              \
  V(I64x2Add)                              \
  V(I64x2Sub)                              \
  V(I64x2Eq)                               \
  V(I64x2Ne)                               \
  V(I32x4Add)                              \
  V(I32x4Sub)                              \
  V(I32x4Mul)                              \
  V(I32x4MinS)                             \
  V(I32x4MaxS)                             \
  V(I32x4Eq)                               \
  V(I32x4Ne)                               \
  V(I32x4GtS)                              \
  V(I32x4GeS)                              \
  V(I32x4MinU)                             \
  V(I32x4MaxU)                             \
  V(I32x4DotI16x8S)                        \
  V(I16x8Add)                              \
  V(I16x8AddSatS)                          \
  V(I16x8Sub)                              \
  V(I16x8SubSatS)                          \
  V(I16x8Mul)                              \
  V(I16x8Eq)                               \
  V(I16x8GtS)                              \
  V(I16x8MinS)                             \
  V(I16x8MaxS)                             \
  V(I16x8AddSatU)                          \
  V(I16x8SubSatU)                          \
  V(I16x8MinU)                             \
  V(I16x8MaxU)                             \
  V(I16x8SConvertI32x4)                    \
  V(I16x8UConvertI32x4)                    \
  V(I16x8RoundingAverageU)                 \
  V(I8x16Add)                              \
  V(I8x16AddSatS)                          \
  V(I8x16Sub)                              \
  V(I8x16SubSatS)                          \
  V(I8x16MinS)                             \
  V(I8x16MaxS)                             \
  V(I8x16Eq)                               \
  V(I8x16GtS)                              \
  V(I8x16AddSatU)                          \
  V(I8x16SubSatU)                          \
  V(I8x16MinU)                             \
  V(I8x16MaxU)                             \
  V(I8x16SConvertI16x8)                    \
  V(I8x16UConvertI16x8)                    \
  V(I8x16RoundingAverageU)                 \
  V(S128And)                               \
  V(S128Or)                                \
  V(S128Xor)

// These opcodes require all inputs to be registers because the codegen is
// simpler with all registers.
#define SIMD_BINOP_RRR(V)  \
  V(I64x2ExtMulLowI32x4S)  \
  V(I64x2ExtMulHighI32x4S) \
  V(I64x2ExtMulLowI32x4U)  \
  V(I64x2ExtMulHighI32x4U) \
  V(I32x4ExtMulLowI16x8S)  \
  V(I32x4ExtMulHighI16x8S) \
  V(I32x4ExtMulLowI16x8U)  \
  V(I32x4ExtMulHighI16x8U) \
  V(I16x8ExtMulLowI8x16S)  \
  V(I16x8ExtMulHighI8x16S) \
  V(I16x8ExtMulLowI8x16U)  \
  V(I16x8ExtMulHighI8x16U) \
  V(I16x8Q15MulRSatS)      \
  V(I16x8RelaxedQ15MulRS)

#define SIMD_UNOP_LIST(V)   \
  V(F64x2ConvertLowI32x4S)  \
  V(F32x4DemoteF64x2Zero)   \
  V(F32x4Sqrt)              \
  V(F32x4SConvertI32x4)     \
  V(I64x2BitMask)           \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I64x2UConvertI32x4Low)  \
  V(I64x2UConvertI32x4High) \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x4Neg)               \
  V(I32x4UConvertI16x8Low)  \
  V(I32x4UConvertI16x8High) \
  V(I32x4Abs)               \
  V(I32x4BitMask)           \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I16x8Neg)               \
  V(I16x8UConvertI8x16Low)  \
  V(I16x8UConvertI8x16High) \
  V(I16x8Abs)               \
  V(I8x16Neg)               \
  V(I8x16Abs)               \
  V(I8x16BitMask)           \
  V(S128Not)

#define SIMD_ALLTRUE_LIST(V) \
  V(I64x2AllTrue)            \
  V(I32x4AllTrue)            \
  V(I16x8AllTrue)            \
  V(I8x16AllTrue)

#define SIMD_SHIFT_OPCODES_UNIFED_SSE_AVX(V) \
  V(I64x2Shl)                                \
  V(I64x2ShrU)                               \
  V(I32x4Shl)                                \
  V(I32x4ShrS)                               \
  V(I32x4ShrU)                               \
  V(I16x8Shl)                                \
  V(I16x8ShrS)                               \
  V(I16x8ShrU)

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Const(node_t node) {
 
"""


```