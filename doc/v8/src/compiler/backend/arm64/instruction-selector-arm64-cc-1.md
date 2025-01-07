Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of an 11-part series.

I need to go through the code and identify the key functions and their purposes. The code heavily involves instruction selection for the ARM64 architecture within the V8 JavaScript engine.

Here's a breakdown of the code's functionalities:

1. **Binary Operations (Binop):**  `VisitBinop` functions handle binary operations like addition, subtraction, multiplication, etc. They aim to generate the most efficient ARM64 instructions based on operand types (registers, immediates, shifts, extensions).
2. **Commutation:** The code considers the commutative property of some operations to optimize instruction generation, potentially swapping operands if it allows for using immediates.
3. **Immediate Handling:**  The code checks if operands can be represented as immediates and uses appropriate instruction forms when possible.
4. **Shift Operations:** It detects shift operations and generates corresponding ARM64 shift instructions.
5. **Conditional Flags:**  It handles instructions that set or depend on CPU flags, integrating with a `FlagsContinuationT` mechanism for conditional execution.
6. **Add/Subtract Optimization:** `VisitAddSub` optimizes cases where a subtraction with a negative immediate can be represented as an addition with a positive immediate.
7. **Multiplication Optimizations:**
    - **Reduced Multiplication:**  Identifies multiplications by (2^k + 1) and replaces them with additions and shifts.
    - **Multiply-Add (Madd):** Detects `Add(Mul(x, y), z)` patterns and emits `Madd` instructions.
    - **Multiply-Negate (Mneg):** Detects `Mul(Sub(0, x), y)` patterns and emits `Mneg` instructions.
    - **Multiply-Subtract (Msub):** Detects `Sub(a, Mul(x, y))` patterns and emits `Msub` instructions.
8. **Store Instructions:** `GetStoreOpcodeAndImmediate` determines the correct ARM64 store instruction and immediate mode based on the data type and whether it's a paired store.
9. **Load Instructions:** `EmitLoad` generates ARM64 load instructions, optimizing for cases involving root registers and immediates.
10. **Load/Store with Lane (SIMD):**  `VisitLoadLane` and `VisitStoreLane` handle loading and storing individual lanes of SIMD registers.
11. **Load Transform (SIMD):** `VisitLoadTransform` handles various SIMD load and transform operations like splatting and extending.
这段代码是V8 JavaScript引擎中，针对ARM64架构的指令选择器（Instruction Selector）的一部分。它负责将高级的中间表示（IR - Intermediate Representation）操作转换为底层的ARM64机器指令。

以下是这段代码的主要功能归纳：

1. **二元运算（Binop）处理：**
   - `VisitBinop` 及其相关的 `VisitBinopImpl` 函数负责处理各种二元运算操作，例如加法、减法、按位与、按位或等。
   - 它会根据操作数的类型（寄存器、立即数）以及是否可以交换操作数来选择合适的ARM64指令。
   - 特别地，它会尝试将一个操作数优化为立即数，以生成更紧凑和高效的指令。
   - 它还处理带有条件标志的二元运算，这些运算的结果会影响处理器的条件码。

2. **加法和减法优化：**
   - `VisitAddSub` 函数专门处理加法和减法操作。
   - 它会检测减去一个负立即数的情况，并将其转换为加上一个正立即数，利用ARM64指令的特性。

3. **乘法优化：**
   - `LeftShiftForReducedMultiply` 函数检测乘以特定立即数（形如 2<sup>k</sup> + 1）的乘法，并返回 k 值。这种乘法可以优化为移位和加法操作。
   - `TryEmitMulitplyAdd` 函数尝试匹配 `Add(Mul(x, y), z)` 模式，并生成 `Madd` (Multiply-Add) 指令，这是一个融合的乘法和加法指令，在ARM64上更高效。
   - `TryEmitMultiplyNegate` 函数尝试匹配 `Mul(Sub(0, x), y)` 模式，并生成 `Mneg` (Multiply-Negate) 指令。
   - `TryEmitMultiplySub` 函数尝试匹配 `Sub(a, Mul(x, y))` 模式，并生成 `Msub` (Multiply-Subtract) 指令。

4. **存储指令选择：**
   - `GetStoreOpcodeAndImmediate` 函数根据存储的数据类型（`MemoryRepresentation`）和是否是成对存储来确定合适的ARM64存储指令（例如 `strb`, `strh`, `strw`, `str`, `strpair` 等）和立即数模式。
   - 它考虑了压缩指针等V8的特殊数据表示。

5. **加载指令生成：**
   - `EmitLoad` 函数负责生成ARM64的加载指令。
   - 它会优化从根寄存器加载数据的情况，并尝试将偏移量作为立即数编码到指令中。
   - 它还支持带有移位操作的加载寻址模式。

6. **SIMD（单指令多数据）指令处理（WebAssembly相关）：**
   - `VisitLoadLane` 和 `VisitStoreLane` 函数处理从SIMD寄存器加载和存储特定通道（lane）的操作。
   - `VisitLoadTransform` 函数处理更复杂的SIMD加载和转换操作，例如将一个元素复制到整个SIMD寄存器（splat）、有符号/无符号扩展加载等。

**如果 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.tq` 结尾，那它就是 V8 Torque 源代码。**  然而，根据提供的文件名 `.cc`，它是一个 **C++** 源代码文件。 Torque 是一种 V8 特有的 DSL (Domain Specific Language)，用于生成编译器代码。

**与 JavaScript 功能的关系：**

这段代码直接关系到 V8 如何执行 JavaScript 代码。当 V8 编译 JavaScript 代码时，它会生成中间表示（IR）。指令选择器负责将这些 IR 操作转换为目标架构（在这里是 ARM64）的机器指令。

例如，考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个函数时，`a + b` 这个操作会被表示为一个 IR 二元加法操作。 `VisitBinop` 函数会负责将这个 IR 操作转换为相应的 ARM64 加法指令，例如 `add x0, x1, x2`（假设 `a` 和 `b` 分别在寄存器 `x1` 和 `x2` 中，结果要放到 `x0` 中）。

再例如，考虑一个简单的存储操作：

```javascript
let arr = [1, 2];
arr[0] = 5;
```

`arr[0] = 5;` 这个操作会被表示为一个存储操作。 `GetStoreOpcodeAndImmediate` 和相关的代码会生成 ARM64 的存储指令，将值 `5` 存储到数组 `arr` 的指定内存位置。

**代码逻辑推理的假设输入与输出：**

假设 `VisitBinopImpl` 函数接收以下输入：

* `binop_idx`: 代表加法操作的 IR 节点索引。
* `left_node`: 代表左操作数的 IR 节点索引。
* `right_node`: 代表右操作数的 IR 节点索引。
* `rep`: 操作数的寄存器表示（例如，64位整数）。
* `opcode`: 预先确定的操作码基类型（例如，加法）。
* `operand_mode`: 立即数模式。
* `cont`: 条件延续信息，这里假设为空。

并且假设 `right_node` 可以被表示为一个立即数。

**输出：**

该函数可能会生成如下 ARM64 指令：

`add <output_register>, <left_register>, #<immediate_value>`

其中：
* `<output_register>` 是用于存储结果的寄存器。
* `<left_register>` 是左操作数所在的寄存器。
* `<immediate_value>` 是右操作数的值。

**用户常见的编程错误举例：**

这段代码本身是编译器内部的代码，直接与用户编程错误的关系较少。但是，它所生成的机器指令的效率会受到 JavaScript 代码的影响。

例如，在 JavaScript 中进行大量的数值计算时，如果 V8 无法有效地将这些计算映射到高性能的 ARM64 指令（例如，没有利用 SIMD 指令），那么程序的执行效率可能会下降。这并不是一个直接的“编程错误”，而是一个性能优化的考量。

然而，在与 WebAssembly 交互时，如果 WebAssembly 代码尝试进行超出内存边界的访问，那么 `VisitLoadLane` 和 `VisitStoreLane` 中处理的受保护内存访问机制就会发挥作用，防止程序崩溃。

**总结这段代码的功能：**

这段代码是 V8 JavaScript 引擎中 ARM64 架构的指令选择器的核心部分，主要负责将高级的中间表示（IR）操作转换为高效的 ARM64 机器指令，包括：

- 处理各种二元运算，并尽可能优化为使用立即数或移位操作。
- 针对加法、减法和乘法进行特定的优化，生成更高效的指令，如 `Madd`, `Mneg`, `Msub`。
- 根据数据类型和存储方式选择合适的存储指令。
- 生成优化的加载指令，特别是针对根寄存器和立即数偏移。
- 处理 SIMD 相关的加载和存储操作，包括通道访问和数据转换，尤其与 WebAssembly 的支持相关。

总而言之，这段代码是 V8 将 JavaScript 代码高效执行在 ARM64 架构上的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共11部分，请归纳一下它的功能

"""
ename Matcher>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, ArchOpcode opcode,
                ImmediateMode operand_mode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop<Adapter, Matcher>(selector, node, opcode, operand_mode, &cont);
}

void VisitBinopImpl(InstructionSelectorT<TurboshaftAdapter>* selector,
                    turboshaft::OpIndex binop_idx,
                    turboshaft::OpIndex left_node,
                    turboshaft::OpIndex right_node,
                    turboshaft::RegisterRepresentation rep,
                    InstructionCode opcode, ImmediateMode operand_mode,
                    FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  constexpr uint32_t kMaxFlagSetInputs = 3;
  constexpr uint32_t kMaxCcmpOperands =
      FlagsContinuationT<TurboshaftAdapter>::kMaxCompareChainSize *
      kNumCcmpOperands;
  constexpr uint32_t kExtraCcmpInputs = 2;
  constexpr uint32_t kMaxInputs =
      kMaxFlagSetInputs + kMaxCcmpOperands + kExtraCcmpInputs;
  InstructionOperand inputs[kMaxInputs];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  uint8_t properties = GetBinopProperties(opcode);
  bool can_commute = CanCommuteField::decode(properties);
  bool must_commute_cond = MustCommuteCondField::decode(properties);
  bool is_add_sub = IsAddSubField::decode(properties);

  // We've already commuted the flags while searching for the pattern.
  if (cont->IsConditionalSet() || cont->IsConditionalBranch()) {
    can_commute = false;
  }
  if (g.CanBeImmediate(right_node, operand_mode)) {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseImmediate(right_node);
  } else if (can_commute && g.CanBeImmediate(left_node, operand_mode)) {
    if (must_commute_cond) cont->Commute();
    inputs[input_count++] = g.UseRegister(right_node);
    inputs[input_count++] = g.UseImmediate(left_node);
  } else if (is_add_sub &&
             TryMatchAnyExtend(&g, selector, binop_idx, left_node, right_node,
                               &inputs[0], &inputs[1], &opcode)) {
    input_count += 2;
  } else if (is_add_sub && can_commute &&
             TryMatchAnyExtend(&g, selector, binop_idx, right_node, left_node,
                               &inputs[0], &inputs[1], &opcode)) {
    if (must_commute_cond) cont->Commute();
    input_count += 2;
  } else if (TryMatchAnyShift(selector, binop_idx, right_node, &opcode,
                              !is_add_sub, rep)) {
    const ShiftOp& shift = selector->Get(right_node).Cast<ShiftOp>();
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(shift.left());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(
        static_cast<int>(selector->integer_constant(shift.right()) & 0x3F));
  } else if (can_commute && TryMatchAnyShift(selector, binop_idx, left_node,
                                             &opcode, !is_add_sub, rep)) {
    if (must_commute_cond) cont->Commute();
    const ShiftOp& shift = selector->Get(left_node).Cast<ShiftOp>();
    inputs[input_count++] = g.UseRegisterOrImmediateZero(right_node);
    inputs[input_count++] = g.UseRegister(shift.left());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(
        static_cast<int>(selector->integer_constant(shift.right()) & 0x3F));
  } else {
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(right_node);
  }

  if (!IsComparisonField::decode(properties)) {
    outputs[output_count++] = g.DefineAsRegister(binop_idx);
  }

  if (cont->IsSelect()) {
    // Keep the values live until the end so that we can use operations that
    // write registers to generate the condition, without accidently
    // overwriting the inputs.
    inputs[input_count++] = g.UseRegisterAtEnd(cont->true_value());
    inputs[input_count++] = g.UseRegisterAtEnd(cont->false_value());
  } else if (cont->IsConditionalSet() || cont->IsConditionalBranch()) {
    DCHECK_LE(input_count, kMaxInputs);
    auto& compares = cont->compares();
    for (unsigned i = 0; i < cont->num_conditional_compares(); ++i) {
      auto compare = compares[i];
      inputs[input_count + kCcmpOffsetOfOpcode] = g.TempImmediate(compare.code);
      inputs[input_count + kCcmpOffsetOfLhs] = g.UseRegisterAtEnd(compare.lhs);
      if (g.CanBeImmediate(compare.rhs, kConditionalCompareImm)) {
        inputs[input_count + kCcmpOffsetOfRhs] = g.UseImmediate(compare.rhs);
      } else {
        inputs[input_count + kCcmpOffsetOfRhs] =
            g.UseRegisterAtEnd(compare.rhs);
      }
      inputs[input_count + kCcmpOffsetOfDefaultFlags] =
          g.TempImmediate(compare.default_flags);
      inputs[input_count + kCcmpOffsetOfCompareCondition] =
          g.TempImmediate(compare.compare_condition);
      input_count += kNumCcmpOperands;
    }
    inputs[input_count++] = g.TempImmediate(cont->final_condition());
    inputs[input_count++] =
        g.TempImmediate(static_cast<int32_t>(cont->num_conditional_compares()));
  }

  DCHECK_NE(0u, input_count);
  DCHECK((output_count != 0) || IsComparisonField::decode(properties));
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

// Shared routine for multiple binary operations.
void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                turboshaft::OpIndex binop_idx,
                turboshaft::RegisterRepresentation rep, InstructionCode opcode,
                ImmediateMode operand_mode,
                FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& binop = selector->Get(binop_idx);
  OpIndex left_node = binop.input(0);
  OpIndex right_node = binop.input(1);
  return VisitBinopImpl(selector, binop_idx, left_node, right_node, rep, opcode,
                        operand_mode, cont);
}

void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                turboshaft::OpIndex node,
                turboshaft::RegisterRepresentation rep, ArchOpcode opcode,
                ImmediateMode operand_mode) {
  FlagsContinuationT<TurboshaftAdapter> cont;
  VisitBinop(selector, node, rep, opcode, operand_mode, &cont);
}

template <typename Adapter, typename Matcher>
void VisitAddSub(InstructionSelectorT<Adapter>* selector, Node* node,
                 ArchOpcode opcode, ArchOpcode negate_opcode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Matcher m(node);
  if (m.right().HasResolvedValue() && (m.right().ResolvedValue() < 0) &&
      (m.right().ResolvedValue() > std::numeric_limits<int>::min()) &&
      g.CanBeImmediate(-m.right().ResolvedValue(), kArithmeticImm)) {
    selector->Emit(
        negate_opcode, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
        g.TempImmediate(static_cast<int32_t>(-m.right().ResolvedValue())));
  } else {
    VisitBinop<Adapter, Matcher>(selector, node, opcode, kArithmeticImm);
  }
}

std::tuple<turboshaft::OpIndex, turboshaft::OpIndex>
GetBinopLeftRightCstOnTheRight(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    const turboshaft::WordBinopOp& binop) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  OpIndex left = binop.left();
  OpIndex right = binop.right();
  if (!selector->Is<ConstantOp>(right) &&
      WordBinopOp::IsCommutative(binop.kind) &&
      selector->Is<ConstantOp>(left)) {
    std::swap(left, right);
  }
  return {left, right};
}

void VisitAddSub(InstructionSelectorT<TurboshaftAdapter>* selector,
                 turboshaft::OpIndex node, ArchOpcode opcode,
                 ArchOpcode negate_opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const WordBinopOp& add_sub = selector->Get(node).Cast<WordBinopOp>();
  auto [left, right] = GetBinopLeftRightCstOnTheRight(selector, add_sub);

  if (std::optional<int64_t> constant_rhs =
          g.GetOptionalIntegerConstant(right)) {
    if (constant_rhs < 0 && constant_rhs > std::numeric_limits<int>::min() &&
        g.CanBeImmediate(-*constant_rhs, kArithmeticImm)) {
      selector->Emit(negate_opcode, g.DefineAsRegister(node),
                     g.UseRegister(left),
                     g.TempImmediate(static_cast<int32_t>(-*constant_rhs)));
      return;
    }
  }
  VisitBinop(selector, node, add_sub.rep, opcode, kArithmeticImm);
}

// For multiplications by immediate of the form x * (2^k + 1), where k > 0,
// return the value of k, otherwise return zero. This is used to reduce the
// multiplication to addition with left shift: x + (x << k).
template <typename Matcher>
int32_t LeftShiftForReducedMultiply(Matcher* m) {
  DCHECK(m->IsInt32Mul() || m->IsInt64Mul());
  if (m->right().HasResolvedValue() && m->right().ResolvedValue() >= 3) {
    uint64_t value_minus_one = m->right().ResolvedValue() - 1;
    if (base::bits::IsPowerOfTwo(value_minus_one)) {
      return base::bits::WhichPowerOfTwo(value_minus_one);
    }
  }
  return 0;
}

// For multiplications by immediate of the form x * (2^k + 1), where k > 0,
// return the value of k, otherwise return zero. This is used to reduce the
// multiplication to addition with left shift: x + (x << k).
int32_t LeftShiftForReducedMultiply(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex rhs) {
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  if (auto constant = g.GetOptionalIntegerConstant(rhs)) {
    int64_t value_minus_one = constant.value() - 1;
    if (base::bits::IsPowerOfTwo(value_minus_one)) {
      return base::bits::WhichPowerOfTwo(value_minus_one);
    }
  }
  return 0;
}

// Try to match Add(Mul(x, y), z) and emit Madd(x, y, z) for it.
template <typename MultiplyOpmaskT>
bool TryEmitMulitplyAdd(InstructionSelectorT<TurboshaftAdapter>* selector,
                        turboshaft::OpIndex add, turboshaft::OpIndex lhs,
                        turboshaft::OpIndex rhs, InstructionCode madd_opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& add_lhs = selector->Get(lhs);
  if (!add_lhs.Is<MultiplyOpmaskT>() || !selector->CanCover(add, lhs)) {
    return false;
  }
  // Check that multiply can't be reduced to an addition with shift later on.
  const WordBinopOp& mul = add_lhs.Cast<WordBinopOp>();
  if (LeftShiftForReducedMultiply(selector, mul.right()) != 0) return false;

  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  selector->Emit(madd_opcode, g.DefineAsRegister(add),
                 g.UseRegister(mul.left()), g.UseRegister(mul.right()),
                 g.UseRegister(rhs));
  return true;
}

bool TryEmitMultiplyAddInt32(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex add, turboshaft::OpIndex lhs,
                             turboshaft::OpIndex rhs) {
  return TryEmitMulitplyAdd<turboshaft::Opmask::kWord32Mul>(selector, add, lhs,
                                                            rhs, kArm64Madd32);
}

bool TryEmitMultiplyAddInt64(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex add, turboshaft::OpIndex lhs,
                             turboshaft::OpIndex rhs) {
  return TryEmitMulitplyAdd<turboshaft::Opmask::kWord64Mul>(selector, add, lhs,
                                                            rhs, kArm64Madd);
}

// Try to match Mul(Sub(0, x), y) and emit Mneg(x, y) for it.
template <typename SubtractOpmaskT>
bool TryEmitMultiplyNegate(InstructionSelectorT<TurboshaftAdapter>* selector,
                           turboshaft::OpIndex mul, turboshaft::OpIndex lhs,
                           turboshaft::OpIndex rhs,
                           InstructionCode mneg_opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& mul_lhs = selector->Get(lhs);
  if (!mul_lhs.Is<SubtractOpmaskT>() || !selector->CanCover(mul, lhs)) {
    return false;
  }
  const WordBinopOp& sub = mul_lhs.Cast<WordBinopOp>();
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  std::optional<int64_t> sub_lhs_constant =
      g.GetOptionalIntegerConstant(sub.left());
  if (!sub_lhs_constant.has_value() || sub_lhs_constant != 0) return false;
  selector->Emit(mneg_opcode, g.DefineAsRegister(mul),
                 g.UseRegister(sub.right()), g.UseRegister(rhs));
  return true;
}

bool TryEmitMultiplyNegateInt32(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex mul,
    turboshaft::OpIndex lhs, turboshaft::OpIndex rhs) {
  return TryEmitMultiplyNegate<turboshaft::Opmask::kWord32Sub>(
      selector, mul, lhs, rhs, kArm64Mneg32);
}

bool TryEmitMultiplyNegateInt64(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex mul,
    turboshaft::OpIndex lhs, turboshaft::OpIndex rhs) {
  return TryEmitMultiplyNegate<turboshaft::Opmask::kWord64Sub>(
      selector, mul, lhs, rhs, kArm64Mneg);
}

// Try to match Sub(a, Mul(x, y)) and emit Msub(x, y, a) for it.
template <typename MultiplyOpmaskT>
bool TryEmitMultiplySub(InstructionSelectorT<TurboshaftAdapter>* selector,
                        turboshaft::OpIndex node,
                        InstructionCode msub_opbocde) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const WordBinopOp& sub = selector->Get(node).Cast<WordBinopOp>();
  DCHECK_EQ(sub.kind, WordBinopOp::Kind::kSub);

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  const Operation& sub_rhs = selector->Get(sub.right());
  if (sub_rhs.Is<MultiplyOpmaskT>() && selector->CanCover(node, sub.right())) {
    const WordBinopOp& mul = sub_rhs.Cast<WordBinopOp>();
    if (LeftShiftForReducedMultiply(selector, mul.right()) == 0) {
      Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
      selector->Emit(msub_opbocde, g.DefineAsRegister(node),
                     g.UseRegister(mul.left()), g.UseRegister(mul.right()),
                     g.UseRegister(sub.left()));
      return true;
    }
  }
  return false;
}

std::tuple<InstructionCode, ImmediateMode> GetStoreOpcodeAndImmediate(
    turboshaft::MemoryRepresentation stored_rep, bool paired) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (stored_rep) {
    case MemoryRepresentation::Int8():
    case MemoryRepresentation::Uint8():
      CHECK(!paired);
      return {kArm64Strb, kLoadStoreImm8};
    case MemoryRepresentation::Int16():
    case MemoryRepresentation::Uint16():
      CHECK(!paired);
      return {kArm64Strh, kLoadStoreImm16};
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      return {paired ? kArm64StrWPair : kArm64StrW, kLoadStoreImm32};
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      return {paired ? kArm64StrPair : kArm64Str, kLoadStoreImm64};
    case MemoryRepresentation::Float16():
      CHECK(!paired);
      return {kArm64StrH, kLoadStoreImm16};
    case MemoryRepresentation::Float32():
      CHECK(!paired);
      return {kArm64StrS, kLoadStoreImm32};
    case MemoryRepresentation::Float64():
      CHECK(!paired);
      return {kArm64StrD, kLoadStoreImm64};
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      if (paired) {
        // There is an inconsistency here on how we treat stores vs. paired
        // stores. In the normal store case we have special opcodes for
        // compressed fields and the backend decides whether to write 32 or 64
        // bits. However, for pairs this does not make sense, since the
        // paired values could have different representations (e.g.,
        // compressed paired with word32). Therefore, we decide on the actual
        // machine representation already in instruction selection.
#ifdef V8_COMPRESS_POINTERS
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 2);
        return {kArm64StrWPair, kLoadStoreImm32};
#else
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 3);
        return {kArm64StrPair, kLoadStoreImm64};
#endif
      }
      return {kArm64StrCompressTagged,
              COMPRESS_POINTERS_BOOL ? kLoadStoreImm32 : kLoadStoreImm64};
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      CHECK(!paired);
      return {kArm64Str, kLoadStoreImm64};
    case MemoryRepresentation::ProtectedPointer():
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
    case MemoryRepresentation::IndirectPointer():
      return {kArm64StrIndirectPointer, kLoadStoreImm32};
    case MemoryRepresentation::SandboxedPointer():
      CHECK(!paired);
      return {kArm64StrEncodeSandboxedPointer, kLoadStoreImm64};
    case MemoryRepresentation::Simd128():
      CHECK(!paired);
      return {kArm64StrQ, kNoImmediate};
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

std::tuple<InstructionCode, ImmediateMode> GetStoreOpcodeAndImmediate(
    MachineRepresentation rep, bool paired) {
  InstructionCode opcode = kArchNop;
  ImmediateMode immediate_mode = kNoImmediate;
  switch (rep) {
    case MachineRepresentation::kFloat16:
      CHECK(!paired);
      opcode = kArm64StrH;
      immediate_mode = kLoadStoreImm16;
      break;
    case MachineRepresentation::kFloat32:
      CHECK(!paired);
      opcode = kArm64StrS;
      immediate_mode = kLoadStoreImm32;
      break;
    case MachineRepresentation::kFloat64:
      CHECK(!paired);
      opcode = kArm64StrD;
      immediate_mode = kLoadStoreImm64;
      break;
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
      CHECK(!paired);
      opcode = kArm64Strb;
      immediate_mode = kLoadStoreImm8;
      break;
    case MachineRepresentation::kWord16:
      CHECK(!paired);
      opcode = kArm64Strh;
      immediate_mode = kLoadStoreImm16;
      break;
    case MachineRepresentation::kWord32:
      opcode = paired ? kArm64StrWPair : kArm64StrW;
      immediate_mode = kLoadStoreImm32;
      break;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      opcode = paired ? kArm64StrWPair : kArm64StrCompressTagged;
      immediate_mode = kLoadStoreImm32;
      break;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      if (paired) {
        // There is an inconsistency here on how we treat stores vs. paired
        // stores. In the normal store case we have special opcodes for
        // compressed fields and the backend decides whether to write 32 or 64
        // bits. However, for pairs this does not make sense, since the
        // paired values could have different representations (e.g.,
        // compressed paired with word32). Therefore, we decide on the actual
        // machine representation already in instruction selection.
#ifdef V8_COMPRESS_POINTERS
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 2);
        opcode = kArm64StrWPair;
#else
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 3);
        opcode = kArm64StrPair;
#endif
      } else {
        opcode = kArm64StrCompressTagged;
      }
      immediate_mode =
          COMPRESS_POINTERS_BOOL ? kLoadStoreImm32 : kLoadStoreImm64;
      break;
    case MachineRepresentation::kIndirectPointer:
      opcode = kArm64StrIndirectPointer;
      immediate_mode = kLoadStoreImm32;
      break;
    case MachineRepresentation::kSandboxedPointer:
      CHECK(!paired);
      opcode = kArm64StrEncodeSandboxedPointer;
      immediate_mode = kLoadStoreImm64;
      break;
    case MachineRepresentation::kWord64:
      opcode = paired ? kArm64StrPair : kArm64Str;
      immediate_mode = kLoadStoreImm64;
      break;
    case MachineRepresentation::kSimd128:
      CHECK(!paired);
      opcode = kArm64StrQ;
      immediate_mode = kNoImmediate;
      break;
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kProtectedPointer:
      // We never store directly to protected pointers from generated code.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
  return std::tuple{opcode, immediate_mode};
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTraceInstruction(node_t node) {}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  StackSlotRepresentation rep = this->stack_slot_representation_of(node);
  int slot =
      frame_->AllocateSpillSlot(rep.size(), rep.alignment(), rep.is_tagged());
  OperandGenerator g(this);

  Emit(kArchStackSlot, g.DefineAsRegister(node),
       sequence()->AddImmediate(Constant(slot)), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), x1));
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              ImmediateMode immediate_mode, MachineRepresentation rep,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand outputs[1];

  // If output is not nullptr, use that as the output register. This
  // is used when we merge a conversion into the load.
  outputs[0] = g.DefineAsRegister(output == nullptr ? node : output);

  ExternalReferenceMatcher m(base);
  if (m.HasResolvedValue() && g.IsIntegerConstant(index) &&
      selector->CanAddressRelativeToRootsRegister(m.ResolvedValue())) {
    ptrdiff_t const delta =
        g.GetIntegerConstantValue(index) +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            selector->isolate(), m.ResolvedValue());
    input_count = 1;
    // Check that the delta is a 32-bit integer due to the limitations of
    // immediate operands.
    if (is_int32(delta)) {
      inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode, arraysize(outputs), outputs, input_count, inputs);
      return;
    }
  }

  if (base->opcode() == IrOpcode::kLoadRootRegister) {
    input_count = 1;
    inputs[0] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, arraysize(outputs), outputs, input_count, inputs);
    return;
  }

  inputs[0] = g.UseRegister(base);

  if (g.CanBeImmediate(index, immediate_mode)) {
    input_count = 2;
    inputs[1] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_MRI);
  } else if (TryMatchLoadStoreShift(&g, selector, rep, node, index, &inputs[1],
                                    &inputs[2])) {
    input_count = 3;
    opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
  } else {
    input_count = 2;
    inputs[1] = g.UseRegister(index);
    opcode |= AddressingModeField::encode(kMode_MRR);
  }

  selector->Emit(opcode, arraysize(outputs), outputs, input_count, inputs);
}

template <>
void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              typename TurboshaftAdapter::node_t node, InstructionCode opcode,
              ImmediateMode immediate_mode, MachineRepresentation rep,
              typename TurboshaftAdapter::node_t output) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const LoadOp& load = selector->Get(node).Cast<LoadOp>();

  // The LoadStoreSimplificationReducer transforms all loads into
  // *(base + index).
  OpIndex base = load.base();
  OpIndex index = load.index().value();
  DCHECK_EQ(load.offset, 0);
  DCHECK_EQ(load.element_size_log2, 0);

  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand output_op;

  // If output is valid, use that as the output register. This is used when we
  // merge a conversion into the load.
  output_op = g.DefineAsRegister(output.valid() ? output : node);

  const Operation& base_op = selector->Get(base);
  if (base_op.Is<Opmask::kExternalConstant>() &&
      selector->is_integer_constant(index)) {
    const ConstantOp& constant_base = base_op.Cast<ConstantOp>();
    if (selector->CanAddressRelativeToRootsRegister(
            constant_base.external_reference())) {
      ptrdiff_t const delta =
          selector->integer_constant(index) +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector->isolate(), constant_base.external_reference());
      input_count = 1;
      // Check that the delta is a 32-bit integer due to the limitations of
      // immediate operands.
      if (is_int32(delta)) {
        inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
        opcode |= AddressingModeField::encode(kMode_Root);
        selector->Emit(opcode, 1, &output_op, input_count, inputs);
        return;
      }
    }
  }

  if (base_op.Is<LoadRootRegisterOp>()) {
    DCHECK(selector->is_integer_constant(index));
    input_count = 1;
    inputs[0] = g.UseImmediate64(selector->integer_constant(index));
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, &output_op, input_count, inputs);
    return;
  }

  inputs[0] = g.UseRegister(base);

  if (selector->is_integer_constant(index)) {
    int64_t offset = selector->integer_constant(index);
    if (g.CanBeImmediate(offset, immediate_mode)) {
      input_count = 2;
      inputs[1] = g.UseImmediate64(offset);
      opcode |= AddressingModeField::encode(kMode_MRI);
    } else {
      input_count = 2;
      inputs[1] = g.UseRegister(index);
      opcode |= AddressingModeField::encode(kMode_MRR);
    }
  } else {
    if (TryMatchLoadStoreShift(&g, selector, rep, node, index, &inputs[1],
                               &inputs[2])) {
      input_count = 3;
      opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
    } else {
      input_count = 2;
      inputs[1] = g.UseRegister(index);
      opcode |= AddressingModeField::encode(kMode_MRR);
    }
  }
  selector->Emit(opcode, 1, &output_op, input_count, inputs);
}

namespace {
// Manually add base and index into a register to get the actual address.
// This should be used prior to instructions that only support
// immediate/post-index addressing, like ld1 and st1.
template <typename Adapter>
InstructionOperand EmitAddBeforeLoadOrStore(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    InstructionCode* opcode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand addr = g.TempRegister();
  selector->Emit(kArm64Add, addr, g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
  *opcode |= AddressingModeField::encode(kMode_MRI);
  return addr;
}
}  // namespace

#if V8_ENABLE_WEBASSEMBLY
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArm64LoadLane;
  opcode |= LaneSizeField::encode(load.lane_size() * kBitsPerByte);
  if (load.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(input_at(node, 2)),
       g.UseImmediate(load.lane), addr, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  DCHECK(
      params.rep == MachineType::Int8() || params.rep == MachineType::Int16() ||
      params.rep == MachineType::Int32() || params.rep == MachineType::Int64());

  InstructionCode opcode = kArm64LoadLane;
  opcode |= LaneSizeField::encode(params.rep.MemSize() * kBitsPerByte);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
       g.UseImmediate(params.laneidx), addr, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& store = Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArm64StoreLane;
  opcode |= LaneSizeField::encode(store.lane_size() * kBitsPerByte);
  if (store.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  InstructionOperand inputs[4] = {
      g.UseRegister(input_at(node, 2)),
      g.UseImmediate(store.lane),
      addr,
      g.TempImmediate(0),
  };

  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  DCHECK_LE(MachineRepresentation::kWord8, params.rep);
  DCHECK_GE(MachineRepresentation::kWord64, params.rep);

  InstructionCode opcode = kArm64StoreLane;
  opcode |=
      LaneSizeField::encode(ElementSizeInBytes(params.rep) * kBitsPerByte);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  InstructionOperand inputs[4] = {
      g.UseRegister(node->InputAt(2)),
      g.UseImmediate(params.laneidx),
      addr,
      g.TempImmediate(0),
  };

  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  InstructionCode opcode = kArchNop;
  bool require_add = false;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(8);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(16);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(32);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(64);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kArm64S128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kArm64S128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kArm64S128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kArm64S128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kArm64S128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kArm64S128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kArm64LdrS;
      break;
    case Simd1
"""


```