Response: The user wants to understand the functionality of the C++ code snippet provided.
This is the second part of a four-part series, implying that the complete file is large and handles various aspects of instruction selection for the ARM architecture within a compiler.

The current snippet focuses on:

1. **Stack Pointer Checks:** Handling comparisons of the stack pointer against a limit.
2. **Bitwise Shifts:** Implementing left shift, right shift logical, and right shift arithmetic operations. It includes optimizations for specific patterns involving `AND` and other bitwise operations.
3. **Pairwise Integer Operations:** Implementing addition, subtraction, and multiplication for pairs of 32-bit integers, potentially used for handling 64-bit values or multi-word results.
4. **Pairwise Shift Operations:** Implementing shift operations for pairs of 32-bit integers.
5. **Bit Manipulation Operations:** Handling rotate right, reverse bits, and reverse bytes operations.
6. **Integer Arithmetic Operations:** Implementing addition, subtraction, and multiplication for 32-bit integers, including special cases and optimizations (like combining with multiplication for fused multiply-add).
7. **Integer Division and Modulo:**  Functionality for integer division and modulo operations (though the implementations are not fully shown in this snippet).
8. **Type Conversions:** Handling conversions between integer and floating-point types, as well as bitwise casting.
9. **Floating-Point Arithmetic Operations:** Implementing addition, subtraction, multiplication, division, min, max, absolute value, negation, and square root for single-precision (float32) and double-precision (float64) floating-point numbers. It includes optimizations for fused multiply-add.
10. **Floating-Point Comparisons:** Implementing comparisons between floating-point numbers.
11. **Function Call Preparation:** Handling the setup of arguments and results for function calls.
12. **Conditional Code Generation:** Implementing conditional execution based on comparisons, with a focus on optimizing comparisons against zero and combining comparisons with preceding arithmetic or bitwise operations.

The code appears to be part of the instruction selection phase of a compiler, responsible for translating high-level intermediate representations (like those from Turbofan or Turboshaft) into low-level ARM instructions.

To illustrate the relationship with JavaScript, I need to identify functionalities in the C++ code that directly correspond to common JavaScript operations.
这是文件 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 的第二部分，它主要负责将**中间表示 (Intermediate Representation - IR) 的节点**转换为 **ARM 汇编指令**。

更具体地说，这部分代码涵盖了以下功能：

**1. 栈指针检查 (Stack Pointer Checks):**

*  `VisitStackPointerGreaterThan`:  处理检查栈指针是否大于某个值的操作。这通常用于防止栈溢出。

**2. 位移操作 (Shift Operations):**

* `VisitWord32Shl`: 处理 32 位左移操作。
* `VisitWord32Shr`: 处理 32 位逻辑右移操作。它包含针对特定模式的优化，例如当右移与按位与操作结合时，可以生成更高效的 `ubfx` 指令来提取位域。
* `VisitWord32Sar`: 处理 32 位算术右移操作。它也包含针对特定模式的优化，特别是当算术右移紧跟逻辑左移时，可以生成更高效的符号扩展指令 (`sxth`, `sxtb`, `sbfx`)。
* `VisitWord32PairShl`, `VisitWord32PairShr`, `VisitWord32PairSar`: 处理 64 位（由两个 32 位字组成）的移位操作。
* `VisitWord32Ror`: 处理 32 位循环右移操作。

**3. 成对整数操作 (Pairwise Integer Operations):**

* `VisitInt32PairAdd`, `VisitInt32PairSub`, `VisitInt32PairMul`: 处理两个 32 位整数对的加法、减法和乘法。这通常用于模拟 64 位运算。

**4. 位操作 (Bit Manipulation Operations):**

* `VisitWord32ReverseBits`: 反转 32 位整数的位。
* `VisitWord32ReverseBytes`: 反转 32 位整数的字节顺序。

**5. 整数运算 (Integer Arithmetic Operations):**

* `VisitInt32Add`: 处理 32 位整数加法。包含针对特定模式的优化，例如与乘法结合生成 `mla` 指令（multiply-accumulate），以及与按位与和移位结合生成符号扩展指令。
* `VisitInt32Sub`: 处理 32 位整数减法。包含与乘法结合生成 `mls` 指令（multiply-subtract）的优化。
* `VisitInt32Mul`: 处理 32 位整数乘法。包含针对乘以小常数的优化，将其转换为移位和加/减操作。
* `VisitUint32MulHigh`: 处理 32 位无符号乘法的高 32 位结果。
* `VisitInt32Div`, `VisitUint32Div`: 处理 32 位有符号和无符号除法。 (实现细节可能在其他部分)
* `VisitInt32Mod`, `VisitUint32Mod`: 处理 32 位有符号和无符号取模。(实现细节可能在其他部分)

**6. 类型转换 (Type Conversions):**

* 涵盖了各种整数和浮点数之间的类型转换，例如 `ChangeInt32ToFloat64`， `ChangeFloat64ToInt32` 等。

**7. 浮点运算 (Floating-Point Arithmetic Operations):**

* `VisitFloat32Add`, `VisitFloat64Add`, `VisitFloat32Sub`, `VisitFloat64Sub`, `VisitFloat64Mod`: 处理单精度和双精度浮点数的加法、减法和取模运算。 包含与乘法结合生成 `vmla` 和 `vmls` 指令的优化（向量 multiply-accumulate/subtract）。
* 其他浮点运算，例如绝对值、取反、平方根、除法、最大值、最小值等。

**8. 函数调用准备 (Function Call Preparation):**

* `EmitPrepareArguments`:  处理函数调用前的参数准备，包括将参数放入寄存器或栈中。
* `EmitPrepareResults`: 处理函数调用后的结果准备，例如从栈中恢复返回值。

**9. 条件码生成 (Conditional Code Generation):**

* `VisitWordCompareZero`: 处理与零的比较，并尝试将比较操作与之前的算术或位运算合并以提高效率。
* `VisitWordCompare`, `VisitFloat32Compare`, `VisitFloat64Compare`: 处理各种类型的比较操作。

**与 JavaScript 的关系 (Relationship with JavaScript):**

这些 C++ 代码直接负责将 V8 引擎执行 JavaScript 代码时生成的中间表示翻译成底层的 ARM 机器码。例如：

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = 5;
let sum = add(x, y); // JavaScript 加法操作
```

当 V8 编译这段 JavaScript 代码时，会生成一个表示加法操作的 IR 节点。`VisitInt32Add` 函数（在 Turbofan 适配器中）就会处理这个节点，并将其转换为相应的 ARM 加法指令（例如 `add r0, r1, r2`）。

再例如位移操作：

```javascript
let num = 8;
let shifted = num << 2; // JavaScript 左移操作
```

这段 JavaScript 代码中的左移操作会被编译成一个 IR 节点，然后 `VisitWord32Shl` 函数会负责将其转换为 ARM 的左移指令（例如 `lsl r0, r1, #2`）。

对于浮点数操作：

```javascript
let float1 = 3.14;
let float2 = 2.71;
let product = float1 * float2; // JavaScript 浮点数乘法
```

`VisitFloat64Mul` 函数会将这个乘法操作的 IR 节点转换为 ARM 的浮点数乘法指令（例如 `vmul.f64 d0, d1, d2`）。

**总结 (Summary):**

这部分 `instruction-selector-arm.cc` 代码是 V8 引擎中将 JavaScript 代码转换为可执行的 ARM 机器码的关键部分。它实现了各种 JavaScript 操作在 ARM 架构上的指令选择逻辑，并包含针对特定模式的优化以提高性能。 它处理了包括基本算术运算、位操作、类型转换、浮点运算以及函数调用准备等关键的语言特性。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
onSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuation* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = node->InputAt(0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  ArmOperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry) ? 1 : 0;
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

namespace {

template <typename TryMatchShift, typename Adapter>
void VisitShift(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, TryMatchShift try_match_shift,
                FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  InstructionCode opcode = kArmMov;
  InstructionOperand inputs[2];
  size_t input_count = 2;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  CHECK(try_match_shift(selector, &opcode, node, &inputs[0], &inputs[1]));

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);
  DCHECK_NE(kMode_None, AddressingModeField::decode(opcode));

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename TryMatchShift, typename Adapter>
void VisitShift(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, TryMatchShift try_match_shift) {
  FlagsContinuationT<Adapter> cont;
  VisitShift(selector, node, try_match_shift, &cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  VisitShift(this, node, TryMatchLSL<Adapter>);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shr.left());
    if (IsSupported(ARMv7) && lhs.Is<Opmask::kWord32BitwiseAnd>() &&
        this->is_integer_constant(shr.right()) &&
        base::IsInRange(this->integer_constant(shr.right()), 0, 31)) {
      uint32_t lsb = this->integer_constant(shr.right());
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (this->is_integer_constant(bitwise_and.right())) {
        uint32_t value = static_cast<uint32_t>(
                             this->integer_constant(bitwise_and.right())) >>
                         lsb << lsb;
        uint32_t width = base::bits::CountPopulation(value);
        uint32_t msb = base::bits::CountLeadingZeros32(value);
        if ((width != 0) && (msb + width + lsb == 32)) {
          DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(value));
          return EmitUbfx(this, node, bitwise_and.left(), lsb, width);
        }
      }
    }
    VisitShift(this, node, TryMatchLSR<Adapter>);
  } else {
    Int32BinopMatcher m(node);
    if (IsSupported(ARMv7) && m.left().IsWord32And() &&
        m.right().IsInRange(0, 31)) {
      uint32_t lsb = m.right().ResolvedValue();
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        uint32_t value =
            static_cast<uint32_t>(mleft.right().ResolvedValue() >> lsb) << lsb;
        uint32_t width = base::bits::CountPopulation(value);
        uint32_t msb = base::bits::CountLeadingZeros32(value);
        if ((width != 0) && (msb + width + lsb == 32)) {
          DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(value));
          return EmitUbfx(this, node, mleft.left().node(), lsb, width);
        }
      }
    }
    VisitShift(this, node, TryMatchLSR<Adapter>);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& sar = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(sar.left());
    if (CanCover(node, sar.left()) && lhs.Is<Opmask::kWord32ShiftLeft>()) {
      const ShiftOp& shl = lhs.Cast<ShiftOp>();
      if (this->is_integer_constant(sar.right()) &&
          this->is_integer_constant(shl.right())) {
        uint32_t sar_by = this->integer_constant(sar.right());
        uint32_t shl_by = this->integer_constant(shl.right());
        if ((sar_by == shl_by) && (sar_by == 16)) {
          Emit(kArmSxth, g.DefineAsRegister(node), g.UseRegister(shl.left()),
               g.TempImmediate(0));
          return;
        } else if ((sar_by == shl_by) && (sar_by == 24)) {
          Emit(kArmSxtb, g.DefineAsRegister(node), g.UseRegister(shl.left()),
               g.TempImmediate(0));
          return;
        } else if (IsSupported(ARMv7) && (sar_by >= shl_by)) {
          Emit(kArmSbfx, g.DefineAsRegister(node), g.UseRegister(shl.left()),
               g.TempImmediate(sar_by - shl_by), g.TempImmediate(32 - sar_by));
          return;
        }
      }
    }
    VisitShift(this, node, TryMatchASR<Adapter>);
  } else {
    Int32BinopMatcher m(node);
    if (CanCover(m.node(), m.left().node()) && m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (m.right().HasResolvedValue() && mleft.right().HasResolvedValue()) {
        uint32_t sar = m.right().ResolvedValue();
        uint32_t shl = mleft.right().ResolvedValue();
        if ((sar == shl) && (sar == 16)) {
          Emit(kArmSxth, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        } else if ((sar == shl) && (sar == 24)) {
          Emit(kArmSxtb, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        } else if (IsSupported(ARMv7) && (sar >= shl)) {
          Emit(kArmSbfx, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(sar - shl),
               g.TempImmediate(32 - sar));
          return;
        }
      }
    }
    VisitShift(this, node, TryMatchASR<Adapter>);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairAdd(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);

  node_t projection1 = this->FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the output
    // registers.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegister(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineAsRegister(node),
                                    g.DefineAsRegister(projection1)};

    Emit(kArmAddPair, 2, outputs, 4, inputs);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairSub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);

  node_t projection1 = this->FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the output
    // register.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegister(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineAsRegister(node),
                                    g.DefineAsRegister(projection1)};

    Emit(kArmSubPair, 2, outputs, 4, inputs);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kArmSub | AddressingModeField::encode(kMode_Operand2_R),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairMul(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    InstructionOperand inputs[] = {
        g.UseUniqueRegister(this->input_at(node, 0)),
        g.UseUniqueRegister(this->input_at(node, 1)),
        g.UseUniqueRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineAsRegister(node),
                                    g.DefineAsRegister(projection1)};

    Emit(kArmMulPair, 2, outputs, 4, inputs);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kArmMul | AddressingModeField::encode(kMode_Operand2_R),
         g.DefineSameAsFirst(node), g.UseRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 2)));
  }
}

namespace {
// Shared routine for multiple shift operations.
template <typename Adapter>
void VisitWord32PairShift(InstructionSelectorT<Adapter>* selector,
                          InstructionCode opcode,
                          typename Adapter::node_t node) {
  ArmOperandGeneratorT<Adapter> g(selector);
  // We use g.UseUniqueRegister here to guarantee that there is
  // no register aliasing of input registers with output registers.
  InstructionOperand shift_operand;
  typename Adapter::node_t shift_by = selector->input_at(node, 2);
  if (selector->is_integer_constant(shift_by)) {
    shift_operand = g.UseImmediate(shift_by);
  } else {
    shift_operand = g.UseUniqueRegister(shift_by);
  }

  InstructionOperand inputs[] = {
      g.UseUniqueRegister(selector->input_at(node, 0)),
      g.UseUniqueRegister(selector->input_at(node, 1)), shift_operand};

  typename Adapter::node_t projection1 = selector->FindProjection(node, 1);

  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  int32_t output_count = 0;
  int32_t temp_count = 0;

  outputs[output_count++] = g.DefineAsRegister(node);
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsRegister(projection1);
  } else {
    temps[temp_count++] = g.TempRegister();
  }

  selector->Emit(opcode, output_count, outputs, 3, inputs, temp_count, temps);
}
}  // namespace
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShl(node_t node) {
  VisitWord32PairShift(this, kArmLslPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairShr(node_t node) {
  VisitWord32PairShift(this, kArmLsrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32PairSar(node_t node) {
  VisitWord32PairShift(this, kArmAsrPair, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitShift(this, node, TryMatchROR<Adapter>);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  DCHECK(IsSupported(ARMv7));
  VisitRR(this, kArmRbit, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  VisitRR(this, kArmRev, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& add = this->Get(node).Cast<WordBinopOp>();
  DCHECK(add.Is<Opmask::kWord32Add>());
  const Operation& left = this->Get(add.left());

  if (CanCover(node, add.left())) {
    if (left.Is<Opmask::kWord32Mul>()) {
      const WordBinopOp& mul = left.Cast<WordBinopOp>();
      Emit(kArmMla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.right()));
      return;
    }
    if (left.Is<Opmask::kWord32SignedMulOverflownBits>()) {
      const WordBinopOp& mul = left.Cast<WordBinopOp>();
      Emit(kArmSmmla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.right()));
      return;
    }
    if (left.Is<Opmask::kWord32BitwiseAnd>()) {
      const WordBinopOp& bitwise_and = left.Cast<WordBinopOp>();
      uint32_t mask;
      if (MatchIntegralWord32Constant(bitwise_and.right(), &mask)) {
        if (mask == 0xFF) {
          Emit(kArmUxtab, g.DefineAsRegister(node), g.UseRegister(add.right()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        } else if (mask == 0xFFFF) {
          Emit(kArmUxtah, g.DefineAsRegister(node), g.UseRegister(add.right()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        }
      }
    } else if (left.Is<Opmask::kWord32ShiftRightArithmetic>()) {
      const ShiftOp& lhs_shift = left.Cast<ShiftOp>();
      if (CanCover(add.left(), lhs_shift.left()) &&
          Get(lhs_shift.left()).Is<Opmask::kWord32ShiftLeft>()) {
        const ShiftOp& lhs_shift_lhs_shift =
            Get(lhs_shift.left()).Cast<ShiftOp>();
        uint32_t sar_by, shl_by;
        if (MatchIntegralWord32Constant(lhs_shift.right(), &sar_by) &&
            MatchIntegralWord32Constant(lhs_shift_lhs_shift.right(), &shl_by)) {
          if (sar_by == 24 && shl_by == 24) {
            Emit(kArmSxtab, g.DefineAsRegister(node),
                 g.UseRegister(add.right()),
                 g.UseRegister(lhs_shift_lhs_shift.left()), g.TempImmediate(0));
            return;
          }
          if (sar_by == 16 && shl_by == 16) {
            Emit(kArmSxtah, g.DefineAsRegister(node),
                 g.UseRegister(add.right()),
                 g.UseRegister(lhs_shift_lhs_shift.left()), g.TempImmediate(0));
            return;
          }
        }
      }
    }
  }

  const Operation& right = this->Get(add.right());
  if (CanCover(node, add.right())) {
    if (right.Is<Opmask::kWord32Mul>()) {
      const WordBinopOp& mul = right.Cast<WordBinopOp>();
      Emit(kArmMla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.left()));
      return;
    }
    if (right.Is<Opmask::kWord32SignedMulOverflownBits>()) {
      const WordBinopOp& mul = right.Cast<WordBinopOp>();
      Emit(kArmSmmla, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(add.left()));
      return;
    }
    if (right.Is<Opmask::kWord32BitwiseAnd>()) {
      const WordBinopOp& bitwise_and = right.Cast<WordBinopOp>();
      uint32_t mask;
      if (MatchIntegralWord32Constant(bitwise_and.right(), &mask)) {
        if (mask == 0xFF) {
          Emit(kArmUxtab, g.DefineAsRegister(node), g.UseRegister(add.left()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        } else if (mask == 0xFFFF) {
          Emit(kArmUxtah, g.DefineAsRegister(node), g.UseRegister(add.left()),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
          return;
        }
      }
    } else if (right.Is<Opmask::kWord32ShiftRightArithmetic>()) {
      const ShiftOp& rhs_shift = right.Cast<ShiftOp>();
      if (CanCover(add.right(), rhs_shift.left()) &&
          Get(rhs_shift.left()).Is<Opmask::kWord32ShiftLeft>()) {
        const ShiftOp& rhs_shift_left = Get(rhs_shift.left()).Cast<ShiftOp>();
        uint32_t sar_by, shl_by;
        if (MatchIntegralWord32Constant(rhs_shift.right(), &sar_by) &&
            MatchIntegralWord32Constant(rhs_shift_left.right(), &shl_by)) {
          if (sar_by == 24 && shl_by == 24) {
            Emit(kArmSxtab, g.DefineAsRegister(node), g.UseRegister(add.left()),
                 g.UseRegister(rhs_shift_left.left()), g.TempImmediate(0));
            return;
          } else if (sar_by == 16 && shl_by == 16) {
            Emit(kArmSxtah, g.DefineAsRegister(node), g.UseRegister(add.left()),
                 g.UseRegister(rhs_shift_left.left()), g.TempImmediate(0));
            return;
          }
        }
      }
    }
  }
  VisitBinop(this, node, kArmAdd, kArmAdd);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (CanCover(node, m.left().node())) {
    switch (m.left().opcode()) {
      case IrOpcode::kInt32Mul: {
        Int32BinopMatcher mleft(m.left().node());
        Emit(kArmMla, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()),
             g.UseRegister(m.right().node()));
        return;
      }
      case IrOpcode::kInt32MulHigh: {
        Int32BinopMatcher mleft(m.left().node());
        Emit(kArmSmmla, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()),
             g.UseRegister(m.right().node()));
        return;
      }
      case IrOpcode::kWord32And: {
        Int32BinopMatcher mleft(m.left().node());
        if (mleft.right().Is(0xFF)) {
          Emit(kArmUxtab, g.DefineAsRegister(node),
               g.UseRegister(m.right().node()),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        } else if (mleft.right().Is(0xFFFF)) {
          Emit(kArmUxtah, g.DefineAsRegister(node),
               g.UseRegister(m.right().node()),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        }
        break;
      }
      case IrOpcode::kWord32Sar: {
        Int32BinopMatcher mleft(m.left().node());
        if (CanCover(mleft.node(), mleft.left().node()) &&
            mleft.left().IsWord32Shl()) {
          Int32BinopMatcher mleftleft(mleft.left().node());
          if (mleft.right().Is(24) && mleftleft.right().Is(24)) {
            Emit(kArmSxtab, g.DefineAsRegister(node),
                 g.UseRegister(m.right().node()),
                 g.UseRegister(mleftleft.left().node()), g.TempImmediate(0));
            return;
          } else if (mleft.right().Is(16) && mleftleft.right().Is(16)) {
            Emit(kArmSxtah, g.DefineAsRegister(node),
                 g.UseRegister(m.right().node()),
                 g.UseRegister(mleftleft.left().node()), g.TempImmediate(0));
            return;
          }
        }
        break;
      }
      default:
        break;
    }
  }
  if (CanCover(node, m.right().node())) {
    switch (m.right().opcode()) {
      case IrOpcode::kInt32Mul: {
        Int32BinopMatcher mright(m.right().node());
        Emit(kArmMla, g.DefineAsRegister(node),
             g.UseRegister(mright.left().node()),
             g.UseRegister(mright.right().node()),
             g.UseRegister(m.left().node()));
        return;
      }
      case IrOpcode::kInt32MulHigh: {
        Int32BinopMatcher mright(m.right().node());
        Emit(kArmSmmla, g.DefineAsRegister(node),
             g.UseRegister(mright.left().node()),
             g.UseRegister(mright.right().node()),
             g.UseRegister(m.left().node()));
        return;
      }
      case IrOpcode::kWord32And: {
        Int32BinopMatcher mright(m.right().node());
        if (mright.right().Is(0xFF)) {
          Emit(kArmUxtab, g.DefineAsRegister(node),
               g.UseRegister(m.left().node()),
               g.UseRegister(mright.left().node()), g.TempImmediate(0));
          return;
        } else if (mright.right().Is(0xFFFF)) {
          Emit(kArmUxtah, g.DefineAsRegister(node),
               g.UseRegister(m.left().node()),
               g.UseRegister(mright.left().node()), g.TempImmediate(0));
          return;
        }
        break;
      }
      case IrOpcode::kWord32Sar: {
        Int32BinopMatcher mright(m.right().node());
        if (CanCover(mright.node(), mright.left().node()) &&
            mright.left().IsWord32Shl()) {
          Int32BinopMatcher mrightleft(mright.left().node());
          if (mright.right().Is(24) && mrightleft.right().Is(24)) {
            Emit(kArmSxtab, g.DefineAsRegister(node),
                 g.UseRegister(m.left().node()),
                 g.UseRegister(mrightleft.left().node()), g.TempImmediate(0));
            return;
          } else if (mright.right().Is(16) && mrightleft.right().Is(16)) {
            Emit(kArmSxtah, g.DefineAsRegister(node),
                 g.UseRegister(m.left().node()),
                 g.UseRegister(mrightleft.left().node()), g.TempImmediate(0));
            return;
          }
        }
        break;
      }
      default:
        break;
    }
  }
  VisitBinop(this, node, kArmAdd, kArmAdd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& sub = this->Get(node).template Cast<WordBinopOp>();
    const Operation& rhs = this->Get(sub.right());
    if (IsSupported(ARMv7) && rhs.Is<Opmask::kWord32Mul>() &&
        CanCover(node, sub.right())) {
      const WordBinopOp& mul = rhs.Cast<WordBinopOp>();
      Emit(kArmMls, g.DefineAsRegister(node), g.UseRegister(mul.left()),
           g.UseRegister(mul.right()), g.UseRegister(sub.left()));
      return;
    }
    VisitBinop(this, node, kArmSub, kArmRsb);
  } else {
    Int32BinopMatcher m(node);
    if (IsSupported(ARMv7) && m.right().IsInt32Mul() &&
        CanCover(node, m.right().node())) {
      Int32BinopMatcher mright(m.right().node());
      Emit(kArmMls, g.DefineAsRegister(node),
           g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()),
           g.UseRegister(m.left().node()));
      return;
    }
    VisitBinop(this, node, kArmSub, kArmRsb);
  }
}

namespace {

template <typename Adapter>
void EmitInt32MulWithOverflow(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t lhs = selector->input_at(node, 0);
  typename Adapter::node_t rhs = selector->input_at(node, 1);
  InstructionOperand result_operand = g.DefineAsRegister(node);
  InstructionOperand temp_operand = g.TempRegister();
  InstructionOperand outputs[] = {result_operand, temp_operand};
  InstructionOperand inputs[] = {g.UseRegister(lhs), g.UseRegister(rhs)};
  selector->Emit(kArmSmull, 2, outputs, 2, inputs);

  // result operand needs shift operator.
  InstructionOperand shift_31 = g.UseImmediate(31);
  InstructionCode opcode =
      kArmCmp | AddressingModeField::encode(kMode_Operand2_R_ASR_I);
  selector->EmitWithContinuation(opcode, temp_operand, result_operand, shift_31,
                                 cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mul(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& mul = this->Get(node).template Cast<WordBinopOp>();
    int32_t constant_rhs;
    if (this->MatchIntegralWord32Constant(mul.right(), &constant_rhs) &&
        constant_rhs > 0) {
      if (base::bits::IsPowerOfTwo(constant_rhs - 1)) {
        Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(mul.left()),
             g.UseRegister(mul.left()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(constant_rhs - 1)));
        return;
      }
      if (constant_rhs < kMaxInt &&
          base::bits::IsPowerOfTwo(constant_rhs + 1)) {
        Emit(kArmRsb | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(mul.left()),
             g.UseRegister(mul.left()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(constant_rhs + 1)));
        return;
      }
    }
    VisitRRR(this, kArmMul, node);
  } else {
    Int32BinopMatcher m(node);
    if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
      int32_t value = m.right().ResolvedValue();
      if (base::bits::IsPowerOfTwo(value - 1)) {
        Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(m.left().node()),
             g.UseRegister(m.left().node()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(value - 1)));
        return;
      }
      if (value < kMaxInt && base::bits::IsPowerOfTwo(value + 1)) {
        Emit(kArmRsb | AddressingModeField::encode(kMode_Operand2_R_LSL_I),
             g.DefineAsRegister(node), g.UseRegister(m.left().node()),
             g.UseRegister(m.left().node()),
             g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
        return;
      }
    }
    VisitRRR(this, kArmMul, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  auto binop = this->word_binop_view(node);
  ArmOperandGeneratorT<Adapter> g(this);
  InstructionOperand outputs[] = {g.TempRegister(), g.DefineAsRegister(node)};
  InstructionOperand inputs[] = {g.UseRegister(binop.left()),
                                 g.UseRegister(binop.right())};
  Emit(kArmUmull, arraysize(outputs), outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitDiv(this, node, kArmSdiv, kArmVcvtF64S32, kArmVcvtS32F64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitDiv(this, node, kArmUdiv, kArmVcvtF64U32, kArmVcvtU32F64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitMod(this, node, kArmSdiv, kArmVcvtF64S32, kArmVcvtS32F64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitMod(this, node, kArmUdiv, kArmVcvtF64U32, kArmVcvtU32F64);
}

#define RR_OP_T_LIST(V)                              \
  V(ChangeInt32ToFloat64, kArmVcvtF64S32)            \
  V(ChangeUint32ToFloat64, kArmVcvtF64U32)           \
  V(ChangeFloat32ToFloat64, kArmVcvtF64F32)          \
  V(ChangeFloat64ToInt32, kArmVcvtS32F64)            \
  V(ChangeFloat64ToUint32, kArmVcvtU32F64)           \
  V(RoundInt32ToFloat32, kArmVcvtF32S32)             \
  V(RoundUint32ToFloat32, kArmVcvtF32U32)            \
  V(Float64ExtractLowWord32, kArmVmovLowU32F64)      \
  V(Float64ExtractHighWord32, kArmVmovHighU32F64)    \
  V(TruncateFloat64ToFloat32, kArmVcvtF32F64)        \
  V(TruncateFloat64ToWord32, kArchTruncateDoubleToI) \
  V(TruncateFloat64ToUint32, kArmVcvtU32F64)         \
  V(BitcastFloat32ToInt32, kArmVmovU32F32)           \
  V(BitcastInt32ToFloat32, kArmVmovF32U32)           \
  V(RoundFloat64ToInt32, kArmVcvtS32F64)             \
  V(Float64SilenceNaN, kArmFloat64SilenceNaN)        \
  V(Float32Abs, kArmVabsF32)                         \
  V(Float64Abs, kArmVabsF64)                         \
  V(Float32Neg, kArmVnegF32)                         \
  V(Float64Neg, kArmVnegF64)                         \
  V(Float32Sqrt, kArmVsqrtF32)                       \
  V(Float64Sqrt, kArmVsqrtF64)                       \
  V(Word32Clz, kArmClz)

#define RR_OP_T_LIST_V8(V)                         \
  V(Float32RoundDown, kArmVrintmF32)               \
  V(Float64RoundDown, kArmVrintmF64)               \
  V(Float32RoundUp, kArmVrintpF32)                 \
  V(Float64RoundUp, kArmVrintpF64)                 \
  V(Float32RoundTruncate, kArmVrintzF32)           \
  V(Float64RoundTruncate, kArmVrintzF64)           \
  V(Float64RoundTiesAway, kArmVrintaF64)           \
  V(Float32RoundTiesEven, kArmVrintnF32)           \
  V(Float64RoundTiesEven, kArmVrintnF64)           \
  IF_WASM(V, F64x2Ceil, kArmF64x2Ceil)             \
  IF_WASM(V, F64x2Floor, kArmF64x2Floor)           \
  IF_WASM(V, F64x2Trunc, kArmF64x2Trunc)           \
  IF_WASM(V, F64x2NearestInt, kArmF64x2NearestInt) \
  IF_WASM(V, F32x4Ceil, kArmVrintpF32)             \
  IF_WASM(V, F32x4Floor, kArmVrintmF32)            \
  IF_WASM(V, F32x4Trunc, kArmVrintzF32)            \
  IF_WASM(V, F32x4NearestInt, kArmVrintnF32)

#define RRR_OP_T_LIST(V)        \
  V(Float64Div, kArmVdivF64)    \
  V(Float32Mul, kArmVmulF32)    \
  V(Float64Mul, kArmVmulF64)    \
  V(Float32Div, kArmVdivF32)    \
  V(Float32Max, kArmFloat32Max) \
  V(Float64Max, kArmFloat64Max) \
  V(Float32Min, kArmFloat32Min) \
  V(Float64Min, kArmFloat64Min) \
  V(Int32MulHigh, kArmSmmul)

#define RR_VISITOR(Name, opcode)                                 \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, opcode, node);                                 \
  }
RR_OP_T_LIST(RR_VISITOR)
#undef RR_VISITOR
#undef RR_OP_T_LIST

#define RR_VISITOR_V8(Name, opcode)                              \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    DCHECK(CpuFeatures::IsSupported(ARMv8));                     \
    VisitRR(this, opcode, node);                                 \
  }
RR_OP_T_LIST_V8(RR_VISITOR_V8)
#undef RR_VISITOR_V8
#undef RR_OP_T_LIST_V8

#define RRR_VISITOR(Name, opcode)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, opcode, node);                                \
  }
RRR_OP_T_LIST(RRR_VISITOR)
#undef RRR_VISITOR
#undef RRR_OP_T_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Add(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& add = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(add.left());
    if (lhs.Is<Opmask::kFloat32Mul>() && CanCover(node, add.left())) {
      const FloatBinopOp& mul = lhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node), g.UseRegister(add.right()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    const Operation& rhs = this->Get(add.right());
    if (rhs.Is<Opmask::kFloat32Mul>() && CanCover(node, add.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node), g.UseRegister(add.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVaddF32, node);
  } else {
    Float32BinopMatcher m(node);
    if (m.left().IsFloat32Mul() && CanCover(node, m.left().node())) {
      Float32BinopMatcher mleft(m.left().node());
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node),
           g.UseRegister(m.right().node()), g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()));
      return;
    }
    if (m.right().IsFloat32Mul() && CanCover(node, m.right().node())) {
      Float32BinopMatcher mright(m.right().node());
      Emit(kArmVmlaF32, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVaddF32, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Add(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& add = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& lhs = this->Get(add.left());
    if (lhs.Is<Opmask::kFloat64Mul>() && CanCover(node, add.left())) {
      const FloatBinopOp& mul = lhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node), g.UseRegister(add.right()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    const Operation& rhs = this->Get(add.right());
    if (rhs.Is<Opmask::kFloat64Mul>() && CanCover(node, add.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node), g.UseRegister(add.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVaddF64, node);
  } else {
    Float64BinopMatcher m(node);
    if (m.left().IsFloat64Mul() && CanCover(node, m.left().node())) {
      Float64BinopMatcher mleft(m.left().node());
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node),
           g.UseRegister(m.right().node()), g.UseRegister(mleft.left().node()),
           g.UseRegister(mleft.right().node()));
      return;
    }
    if (m.right().IsFloat64Mul() && CanCover(node, m.right().node())) {
      Float64BinopMatcher mright(m.right().node());
      Emit(kArmVmlaF64, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVaddF64, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Sub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& sub = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& rhs = this->Get(sub.right());
    if (rhs.Is<Opmask::kFloat32Mul>() && CanCover(node, sub.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlsF32, g.DefineSameAsFirst(node), g.UseRegister(sub.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVsubF32, node);
  } else {
    Float32BinopMatcher m(node);
    if (m.right().IsFloat32Mul() && CanCover(node, m.right().node())) {
      Float32BinopMatcher mright(m.right().node());
      Emit(kArmVmlsF32, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVsubF32, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Sub(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const FloatBinopOp& sub = this->Get(node).template Cast<FloatBinopOp>();
    const Operation& rhs = this->Get(sub.right());
    if (rhs.Is<Opmask::kFloat64Mul>() && CanCover(node, sub.right())) {
      const FloatBinopOp& mul = rhs.Cast<FloatBinopOp>();
      Emit(kArmVmlsF64, g.DefineSameAsFirst(node), g.UseRegister(sub.left()),
           g.UseRegister(mul.left()), g.UseRegister(mul.right()));
      return;
    }
    VisitRRR(this, kArmVsubF64, node);
  } else {
    Float64BinopMatcher m(node);
    if (m.right().IsFloat64Mul() && CanCover(node, m.right().node())) {
      Float64BinopMatcher mright(m.right().node());
      Emit(kArmVmlsF64, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.UseRegister(mright.left().node()),
           g.UseRegister(mright.right().node()));
      return;
    }
    VisitRRR(this, kArmVsubF64, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Mod(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArmVmodF64, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, d0),
       g.UseFixed(this->input_at(node, 0), d0),
       g.UseFixed(this->input_at(node, 1), d1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  ArmOperandGeneratorT<Adapter> g(this);
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
    ArmOperandGeneratorT<Adapter> g(this);

    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                           call_descriptor->ParameterCount())),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          int slot = static_cast<int>(n);
          Emit(kArmPoke | MiscField::encode(slot), g.NoOutput(),
               g.UseRegister(input.node));
        }
      }
    } else {
      // Push any stack arguments.
      int stack_decrement = 0;
      for (PushParameter input : base::Reversed(*arguments)) {
        stack_decrement += kSystemPointerSize;
        // Skip any alignment holes in pushed nodes.
        if (!this->valid(input.node)) continue;
        InstructionOperand decrement = g.UseImmediate(stack_decrement);
        stack_decrement = 0;
        Emit(kArmPush, g.NoOutput(), decrement, g.UseRegister(input.node));
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareResults(
    ZoneVector<PushParameter>* results, const CallDescriptor* call_descriptor,
    node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);

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
        Emit(kArmPeek, g.DefineAsRegister(output.node),
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
  selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& cmp = selector->Get(node).template Cast<ComparisonOp>();
    if (selector->MatchZero(cmp.right())) {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(cmp.left()),
                   g.UseImmediate(cmp.right()), cont);
    } else if (selector->MatchZero(cmp.left())) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(cmp.right()),
                   g.UseImmediate(cmp.left()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(cmp.left()),
                   g.UseRegister(cmp.right()), cont);
    }
  } else {
    Float32BinopMatcher m(node);
    if (m.right().Is(0.0f)) {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()), cont);
    } else if (m.left().Is(0.0f)) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(m.right().node()),
                   g.UseImmediate(m.left().node()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF32, g.UseRegister(m.left().node()),
                   g.UseRegister(m.right().node()), cont);
    }
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = selector->Get(node).template Cast<ComparisonOp>();
    if (selector->MatchZero(op.right())) {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(op.left()),
                   g.UseImmediate(op.right()), cont);
    } else if (selector->MatchZero(op.left())) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(op.right()),
                   g.UseImmediate(op.left()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(op.left()),
                   g.UseRegister(op.right()), cont);
    }
  } else {
    Float64BinopMatcher m(node);
    if (m.right().Is(0.0)) {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(m.left().node()),
                   g.UseImmediate(m.right().node()), cont);
    } else if (m.left().Is(0.0)) {
      cont->Commute();
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(m.right().node()),
                   g.UseImmediate(m.left().node()), cont);
    } else {
      VisitCompare(selector, kArmVcmpF64, g.UseRegister(m.left().node()),
                   g.UseRegister(m.right().node()), cont);
    }
  }
}

// Check whether we can convert:
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

// Check if we can perform the transformation:
// ((a <op> b) cmp 0), b.<cond>
// to:
// (a <ops> b), b.<cond'>
// where <ops> is the flag setting version of <op>, and if so,
// updates {node}, {opcode} and {cont} accordingly.
template <typename Adapter>
void MaybeReplaceCmpZeroWithFlagSettingBinop(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t* node,
    typename Adapter::node_t binop, InstructionCode* opcode,
    FlagsCondition cond, FlagsContinuationT<Adapter>* cont) {
  InstructionCode binop_opcode;
  InstructionCode no_output_opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(binop);
    if (op.Is<Opmask::kWord32Add>()) {
      binop_opcode = kArmAdd;
      no_output_opcode = kArmCmn;
    } else if (op.Is<Opmask::kWord32BitwiseAnd>()) {
      binop_opcode = kArmAnd;
      no_output_opcode = kArmTst;
    } else if (op.Is<Opmask::kWord32BitwiseOr>()) {
      binop_opcode = kArmOrr;
      no_output_opcode = kArmOrr;
    } else if (op.Is<Opmask::kWord32BitwiseXor>()) {
      binop_opcode = kArmEor;
      no_output_opcode = kArmTeq;
    }
  } else {
    switch (binop->opcode()) {
      case IrOpcode::kInt32Add:
        binop_opcode = kArmAdd;
        no_output_opcode = kArmCmn;
        break;
      case IrOpcode::kWord32And:
        binop_opcode = kArmAnd;
        no_output_opcode = kArmTst;
        break;
      case IrOpcode::kWord32Or:
        binop_opcode = kArmOrr;
        no_output_opcode = kArmOrr;
        break;
      case IrOpcode::kWord32Xor:
        binop_opcode = kArmEor;
        no_output_opcode = kArmTeq;
        break;
      default:
        UNREACHABLE();
    }
  }

  if (selector->CanCover(*node, binop)) {
    // The comparison is the only user of {node}.
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = no_output_opcode;
    *node = binop;
  } else if (selector->IsOnlyUserOfNodeInSameBlock(*node, binop)) {
    // We can also handle the case where the {node} and the comparison are in
    // the same basic block, and the comparison is the only user of {node} in
    // this basic block ({node} has users in other basic blocks).
    cont->Overwrite(MapForFlagSettingBinop(cond));
    *opcode = binop_opcode;
    *node = binop;
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, InstructionCode opcode,
                      FlagsContinuationT<Adapter>* cont) {
    ArmOperandGeneratorT<Adapter> g(selector);
    typename Adapter::node_t lhs = selector->input_at(node, 0);
    typename Adapter::node_t rhs = selector->input_at(node, 1);
    InstructionOperand inputs[3];
    size_t input_count = 0;
    InstructionOperand outputs[2];
    size_t output_count = 0;
    bool has_result = (opcode != kArmCmp) && (opcode != kArmCmn) &&
                      (opcode != kArmTst) && (opcode != kArmTeq);

    if (TryMatchImmediateOrShift(selector, &opcode, rhs, &input_count,
                                 &inputs[1])) {
      inputs[0] = g.UseRegister(lhs);
      input_count++;
    } else if (TryMatchImmediateOrShift(selector, &opcode, lhs, &input_count,
                                        &inputs[1])) {
      if constexpr (Adapter::IsTurboshaft) {
        using namespace turboshaft;  // NOLINT(build/namespaces)
        const Operation& op = selector->Get(node);
        if (const ComparisonOp* cmp = op.TryCast<ComparisonOp>()) {
          if (!ComparisonOp::IsCommutative(cmp->kind)) cont->Commute();
        } else if (const WordBinopOp* binop = op.TryCast<WordBinopOp>()) {
          if (!WordBinopOp::IsCommutative(binop->kind)) cont->Commute();
        } else {
          UNREACHABLE();
        }
      } else {
        if (!node->op()->HasProperty(Operator::kCommutative)) cont->Commute();
      }
      inputs[0] = g.UseRegister(rhs);
      input_count++;
    } else {
      opcode |= AddressingModeField::encode(kMode_Operand2_R);
      inputs[input_count++] = g.UseRegister(lhs);
      inputs[input_count++] = g.UseRegister(rhs);
    }

    if (has_result) {
      if (cont->IsDeoptimize()) {
        // If we can deoptimize as a result of the binop, we need to make sure
        // that the deopt inputs are not overwritten by the binop result. One
        // way to achieve that is to declare the output register as
        // same-as-first.
        outputs[output_count++] = g.DefineSameAsFirst(node);
      } else {
        outputs[output_count++] = g.DefineAsRegister(node);
      }
    }

    DCHECK_NE(0u, input_count);
    DCHECK_GE(arraysize(inputs), input_count);
    DCHECK_GE(arraysize(outputs), output_count);

    selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                   inputs, cont);
}

template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node,
                      FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kArmCmp;
    const ComparisonOp& comparison =
        selector->Get(node).template Cast<ComparisonOp>();
    const Operation& lhs = selector->Get(comparison.left());
    const Operation& rhs = selector->Get(comparison.right());

    FlagsCondition cond = cont->condition();
    if (selector->MatchIntegralZero(comparison.right()) &&
        (lhs.Is<Opmask::kWord32Add>() || lhs.Is<Opmask::kWord32BitwiseOr>() ||
         lhs.Is<Opmask::kWord32BitwiseAnd>() ||
         lhs.Is<Opmask::kWord32BitwiseXor>())) {
      // Emit flag setting instructions for comparisons against zero.
      if (CanUseFlagSettingBinop(cond)) {
        MaybeReplaceCmpZeroWithFlagSettingBinop(
            selector, &node, comparison.left(), &opcode, cond, cont);
      }
    } else if (selector->MatchIntegralZero(comparison.left()) &&
               (rhs.Is<Opmask::kWord32Add>() ||
                rhs.Is<Opmask::kWord32BitwiseOr>() ||
                rhs.Is<Opmask::kWord32BitwiseAnd>() ||
                rhs.Is<Opmask::kWord32BitwiseXor>())) {
      // Same as above, but we need to commute the condition before we
      // continue with the rest of the checks.
      cond = CommuteFlagsCondition(cond);
      if (CanUseFlagSettingBinop(cond)) {
        MaybeReplaceCmpZeroWithFlagSettingBinop(
            selector, &node, comparison.right(), &opcode, cond, cont);
      }
    }

    VisitWordCompare(selector, node, opcode, cont);
  } else {
    InstructionCode opcode = kArmCmp;
    Int32BinopMatcher m(node);

    FlagsCondition cond = cont->condition();
    if (m.right().Is(0) && (m.left().IsInt32Add() || m.left().IsWord32Or() ||
                            m.left().IsWord32And() || m.left().IsWord32Xor())) {
      // Emit flag setting instructions for comparisons against zero.
      if (CanUseFlagSettingBinop(cond)) {
        Node* binop = m.left().node();
        MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, binop, &opcode,
                                                cond, cont);
      }
    } else if (m.left().Is(0) &&
               (m.right().IsInt32Add() || m.right().IsWord32Or() ||
                m.right().IsWord32And() || m.right().IsWord32Xor())) {
      // Same as above, but we need to commute the condition before we
      // continue with the rest of the checks.
      cond = CommuteFlagsCondition(cond);
      if (CanUseFlagSettingBinop(cond)) {
        Node* binop = m.right().node();
        MaybeReplaceCmpZeroWithFlagSettingBinop(selector, &node, binop, &opcode,
                                                cond, cont);
      }
    }

    VisitWordCompare(selector, node, opcode, cont);
  }
}

}  // namespace

// Shared routine for word comparisons against zero.
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
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
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThan:
          cont->OverwriteAndNegateIfEqual(kFloatLessThan);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat32LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
          return VisitFloat32Compare(this, value, cont);
        case IrOpcode::kFloat64Equal:
          cont->OverwriteAndNegateIfEqual(kEqual);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThan:
          cont->OverwriteAndNegateIfEqual(kFloatLessThan);
          return VisitFloat64Compare(this, value, cont);
        case IrOpcode::kFloat64LessThanOrEqual:
          cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
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
            if (!result || IsDefined(result)) {
              switch (node->opcode()) {
                case IrOpcode::kInt32AddWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kArmAdd, kArmAdd, cont);
                case IrOpcode::kInt32SubWithOverflow:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop(this, node, kArmSub, kArmRsb, cont);
                case IrOpcode::kInt32MulWithOverflow:
                  // ARM doesn't set the overflow flag for multiplication, so we
                  // need to test on kNotEqual. Here is the code sequence used:
                  //   smull resultlow, resulthigh, left, right
                  //   cmp resulthigh, Operand(resultlow, ASR, 31)
                  cont->OverwriteAndNegateIfEqual(kNotEqual);
                  return EmitInt32MulWithOverflow(this, node, cont);
                default:
                  break;
              }
            }
          }
          break;
        case IrOpcode::kInt32Add:
          return VisitWordCompare(this, value, kArmCmn, cont);
        case IrOpcode::kInt32Sub:
          return VisitWordCompare(this, value, kArmCmp, cont);
        case IrOpcode::kWord32And:
          return VisitWordCompare(this, value, kArmTst, cont);
        case IrOpcode::kWord32Or:
          return VisitBinop(this, value, kArmOrr, kArmOrr, cont);
        case IrOpcode::kWord32Xor:
          return VisitWordCompare(this, value, kArmTeq, cont);
        case IrOpcode::kWord32Sar:
          return VisitShift(this, value, TryMatchASR<Adapter>, cont);
        case IrOpcode::kWord32Shl:
          return VisitShift(this, value, TryMatchLSL<Adapter>, cont);
        case IrOpcode::kWord32Shr:
          return VisitShift(this, value, TryMatchLSR<Adapter>, cont);
        case IrOpcode::kWord32Ror:
          return VisitShift(this, value, TryMatchROR<Adapter>, cont);
        case IrOpcode::kStackPointerGreaterThan:
          cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
          return VisitStackPointerGreaterThan(value, cont);
        default:
          break;
      }
    }

    if (user->opcode() == IrOpcode::kWord32Equal) {
      return VisitWordCompare(this, user, cont);
    }

    // Continuation could not be combined with a compare, emit compare against
    // 0.
    ArmOperandGeneratorT<Adapter> g(this);
    InstructionCode const opcode =
        kArmTst | AddressingModeField::encode(kMode_Operand2_R);
    InstructionOperand const value_operand = g.UseRegister(value);
    EmitWithContinuation(opcode, value_operand, value_operand, cont);
}

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
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kFloatLessThan);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        case RegisterRepresentation::Float64():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kFloatLessThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        default:
          break;
      }
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // <Operation>WithOverflow node.
      if (projection->index == 1u) {
        // We cannot combine the <Operation>WithOverflow with this branch
        // unless the 0th projection (the use of the actual value of the
        // <Operation> is either nullptr, which means there's no use of the
        // actual value, or was already defined, which means it is scheduled
        // *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  TryCast<OverflowCheckedBinopOp>(node)) {
            DCHECK_EQ(binop->rep, WordRepresentation::Word32());
            switch (binop->kind) {
              case OverflowCheckedBinopOp::Kind::kSignedAdd:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kArmAdd, kArmAdd, cont);
              case OverflowCheckedBinopOp::Kind::kSignedSub:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop(this, node, kArmSub, kArmRsb, cont);
              case OverflowCheckedBinopOp::Kind::kSignedMul:
                // ARM doesn't set the overflow flag for multiplication, so we
                // need to test on kNotEqual. Here is the code sequence used:
                //   smull resultlow, resulthigh, left, right
                //   cmp resulthigh, Operand(resultlow, ASR, 31)
                cont->OverwriteAndNegateIfEqual(kNotEqual);
                return EmitInt32MulWithOverflow(this, node, cont);
            }
          }
        }
      }
    } else if (value_op.Is<Opmask::kWord32Add>()) {
      return VisitWordCompare(this, value, kArmCmn, cont);
    } else if (value_op.Is<Opmask::kWord32Sub>()) {
      return VisitWordCompare(this, value, kArmCmp, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseAnd>()) {
      return VisitWordCompare(this, value, kArmTst, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseOr>()) {
      return VisitBinop(this, value, kArmOrr, kArmOrr, cont);
    } else if (value_op.Is<Opmask::kWord32BitwiseXor>()) {
      return VisitWordCompare(this, value, kArmTeq, cont);
    } else if (value_op.Is<Opmask::kWord32ShiftRightArithmetic>()) {
      return VisitShift(this, value, TryMatchASR<TurboshaftAdapter>, cont);
    } else if (value_op.Is<Opmask::kWord32ShiftLeft>()) {
      return VisitShift(this, value, TryMatchLSL<TurboshaftAdapter>, cont);
    } else if (value_op.Is<Opmask::kWord32ShiftRightLogical>()) {
      return VisitShift(this, value, TryMatchLSR<TurboshaftAdapter>, cont);
    } else if (value_op.Is<Opmask::kWord32RotateRight>()) {
      return VisitShift(this, value, TryMatchROR<TurboshaftAdapter>, cont);
    } else if (value_op.Is<StackPointerGreaterThanOp>()) {
      cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
      return VisitStackPointerGreaterThan(value, cont);
    }
  }

  if (Get(user).Is<Opmask::kWord32Equal>()) {
    return VisitWordCompare(this, user, cont);
  }

  // Continuation could not be combined with a compare, emit compare against
  // 0.
  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionCode const opcode =
      kArmTst | AddressingModeField::encode(kMode_Operand2_R);
  InstructionOperand const value_o
"""


```