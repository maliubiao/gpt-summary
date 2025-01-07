Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`. They have specific constraints:

1. **List Functionalities:**  Identify what the code does.
2. **Torque Check:** Determine if the file could be a Torque file based on its extension.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Logic Inference:** If there's code logic, provide an example with input and output.
5. **Common Programming Errors:** Identify potential user programming errors this code might be related to.
6. **Part Number:** Acknowledge this is part 4 of 11.
7. **Summarize Functionality:** Provide a concise summary of the code's purpose.

Let's break down the code and address each point:

* **`TryMatchConditionalCompareChainShared` and related functions:** These functions are clearly about optimizing sequences of comparisons and conditional sets/branches. They aim to combine multiple simple comparisons into a single conditional compare instruction (`ccmp`). This improves efficiency by reducing instruction count.

* **`VisitLogical` functions:** These functions handle logical operations (AND, OR, XOR, NOT). They look for specific patterns (like XOR with -1 for NOT) to emit more efficient instructions. They also call `TryMatchConditionalCompareChainSet`, indicating an integration with the conditional compare chain optimization.

* **`VisitWord32And`, `VisitWord64And`, `VisitWord32Or`, `VisitWord64Or`, `VisitWord32Xor`, `VisitWord64Xor`:** These are specific implementations for different logical operations on 32-bit and 64-bit words. They often look for opportunities for optimization, like using `Ubfx` (bitfield extract) for specific AND patterns.

* **`VisitWord32Shl`, `VisitWord64Shl`, `VisitWord32Shr`, `VisitWord64Shr`:** These handle shift left and shift right operations, again with optimizations for specific patterns, often involving AND operations and bitfield manipulation.

* **`VisitStackPointerGreaterThan`:** This function seems related to stack overflow checks.

* **Template usage:** The code uses templates extensively (`InstructionSelectorT<Adapter>`), suggesting it's designed to work with different compiler adapters (like Turbofan and Turboshaft).

**Addressing the constraints:**

1. **Functionalities:**  Instruction selection for logical and shift operations on ARM64, optimization of conditional compare sequences, handling stack overflow checks, bitfield extraction optimizations.

2. **Torque Check:** The file extension is `.cc`, not `.tq`. So, it's not a Torque source file.

3. **JavaScript Relation:** Logical and bitwise operations are fundamental in JavaScript. Conditional logic (`if`, `else`) also relies on comparisons.

4. **Logic Inference:**  The conditional compare chain logic is a prime example. We can create a scenario.

5. **Common Programming Errors:**  Incorrectly assuming the order of operations in bit manipulation, leading to unexpected results, or not understanding the implications of signed vs. unsigned operations are relevant.

6. **Part Number:** Acknowledge it's part 4/11.

7. **Summarize Functionality:** The code is responsible for selecting the appropriate ARM64 instructions for logical, shift, and comparison operations within the V8 JavaScript engine's compiler backend, focusing on optimization techniques like combining conditional comparisons and efficient bitfield manipulation.

Now, let's generate the specific examples and refine the summary.
这是 V8 JavaScript 引擎中用于 ARM64 架构的代码生成器的一部分，具体来说是指令选择器。它的主要功能是将中间表示 (IR) 的操作转换为目标机器 (ARM64) 的指令。

以下是它的一些关键功能：

1. **优化条件比较链:**  代码尝试将一系列独立的比较操作（`cmp`）和条件设置指令（`cset`）或条件分支指令组合成更高效的条件比较指令链（`ccmp`），最终使用一个 `cset` 或条件分支。这减少了指令数量，提高了执行效率。

2. **处理逻辑运算:**  它负责为逻辑运算（AND, OR, XOR, NOT）选择合适的 ARM64 指令。它会识别一些特定的模式，例如 `Logical(Xor(x, -1), y)` 对应于 `Logical(y, ~x)`，并使用更优化的指令（如 `bic`, `orn`, `eon`, `not`）。

3. **优化位域操作:**  对于特定的 AND 和移位操作组合，例如 `And(Shr(x, imm), mask)`，如果掩码位于最低有效位，则会使用 `ubfx` (unsigned bitfield extract) 指令来高效地提取位域。类似地，对于 `Shl(And(x, mask), imm)`，如果满足特定条件，会使用 `ubfiz` (unsigned bitfield insert in zero) 指令。

4. **处理移位操作:** 它为左移 (`shl`) 和右移 (`shr`) 操作选择合适的 ARM64 指令，并针对某些特定情况进行优化，例如在进行左移操作前，如果操作数进行了 AND 操作，可能会使用 `ubfiz` 指令。

5. **处理栈指针检查:**  `VisitStackPointerGreaterThan` 函数用于生成检查栈指针是否超出限制的指令，用于防止栈溢出。

如果 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码。但根据您提供的信息，它的扩展名是 `.cc`，所以它是一个 C++ 源代码。

是的，这段代码的功能与 JavaScript 的功能有密切关系。JavaScript 中的比较运算符（如 `==`, `!=`, `<`, `>` 等）、逻辑运算符（如 `&&`, `||`, `!`）和位运算符（如 `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`）都需要通过这样的代码转换成底层的机器指令才能执行。

**JavaScript 示例 (与逻辑运算和条件比较相关):**

```javascript
function test(a, b, c, d) {
  if ((a > b) && (c < d)) {
    return 1;
  } else {
    return 0;
  }
}

// 或者使用位运算
function bitwise(x, y) {
  return (x & 0xFF) | (y << 8);
}
```

在 V8 编译执行上述 JavaScript 代码时，`instruction-selector-arm64.cc` 中的代码会参与将 `a > b` 和 `c < d` 的比较操作转换成 ARM64 的比较指令，并尝试将 `&&` 逻辑运算符对应的条件组合优化成 `ccmp` 指令。对于 `bitwise` 函数，位运算符 `&` 和 `<<` 会被转换成相应的 ARM64 位运算指令。

**代码逻辑推理示例 (针对条件比较链优化):**

**假设输入 (Turboshaft IR 节点):**

* `node1`:  比较操作 `a > 5`，设置条件码 `cc0`
* `node2`:  比较操作 `b < 10`，设置条件码 `cc1`
* `node3`:  逻辑 AND 操作，基于 `cc0` 和 `cc1` 的结果进行判断，并根据最终结果条件跳转到某个代码块。

**`TryMatchConditionalCompareChainBranch` 函数的目标是识别这样的模式并生成如下的 ARM64 指令序列：**

```assembly
    cmp a, #5        // 比较 a 和 5，设置条件码
    ccmp b, #10, ne, cs,  // 如果前一个比较结果为不相等 (ne)，并且当前比较结果为进位设置 (cs, 表示小于)，则更新条件码
    b.eq target_block  // 如果最终条件码表示相等 (两个条件都满足)，则跳转到 target_block
```

**假设输入 (Turboshaft IR 节点):**

* `node1`:  比较操作 `x == 0`，设置条件码 `cc0`
* `node2`:  比较操作 `y != null`，设置条件码 `cc1`
* `node3`:  逻辑 OR 操作，基于 `cc0` 或 `cc1` 的结果设置某个寄存器的值 (0 或 1)。

**`TryMatchConditionalCompareChainSet` 函数的目标是识别这样的模式并生成如下的 ARM64 指令序列：**

```assembly
    cmp x, #0
    ccmp y, #0, eq, ne  // 如果前一个比较结果为相等 (eq)，或者当前比较结果为不相等 (ne)，则更新条件码
    cset w0, eq         // 如果最终条件码表示相等 (至少一个条件满足)，则设置 w0 为 1，否则为 0
```

**用户常见的编程错误示例 (与位运算相关):**

1. **错误理解有符号和无符号右移:**

   ```javascript
   let x = -10;
   let result1 = x >> 2;   // 有符号右移，结果仍然是负数（符号位不变）
   let result2 = x >>> 2;  // 无符号右移，结果变成一个很大的正数
   ```
   程序员可能期望 `>>>` 和 `>>` 得到相同的结果，但符号位的处理方式不同会导致意外的值。

2. **位运算优先级错误:**

   ```javascript
   let result = 1 << 2 + 3; // 期望 (1 << 2) + 3 = 7，但实际是 1 << 5 = 32，因为 + 的优先级高于 <<
   let correctResult = (1 << 2) + 3;
   ```
   忘记使用括号来明确运算顺序可能导致位运算结果错误。

3. **位掩码错误:**

   ```javascript
   let flags = 0b00010001;
   let mask = 0b00001110; // 期望提取中间两位
   let extracted = flags & mask; // 结果是 0b00000000，因为掩码没有对齐
   let correctMask = 0b00000110;
   let correctExtracted = flags & correctMask; // 结果是 0b00000000
   ```
   位掩码设计错误导致无法正确提取或修改目标位。

这是第 4 部分，共 11 部分。

**归纳一下 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 的功能:**

该代码文件是 V8 JavaScript 引擎中 ARM64 架构的指令选择器，负责将高级的中间表示操作转换为底层的 ARM64 机器指令。它专注于优化常见的模式，例如条件比较链和位操作，以生成更高效的代码。 这包括识别可以合并的比较操作、使用特定的位域提取和插入指令，以及处理栈指针检查等任务，最终目标是提升 JavaScript 代码在 ARM64 平台上的执行性能。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共11部分，请归纳一下它的功能

"""
ser_condition is kept up-to-date for the next ccmp/cset.
  logic_node->SetCondition(user_condition);
}

static std::optional<FlagsCondition> TryMatchConditionalCompareChainShared(
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone, OpIndex node,
    CompareSequence* sequence) {
  // Instead of:
  //  cmp x0, y0
  //  cset cc0
  //  cmp x1, y1
  //  cset cc1
  //  and/orr
  // Try to merge logical combinations of flags into:
  //  cmp x0, y0
  //  ccmp x1, y1 ..
  //  cset ..
  // So, for AND:
  //  (cset cc1 (ccmp x1 y1 !cc1 cc0 (cmp x0, y0)))
  // and for ORR:
  //  (cset cc1 (ccmp x1 y1 cc1 !cc0 (cmp x0, y0))

  // Look for a potential chain.
  ZoneVector<CompareChainNode*> logic_nodes(zone);
  auto root =
      FindCompareChain(OpIndex::Invalid(), node, selector, zone, logic_nodes);
  if (!root.has_value()) return std::nullopt;

  if (logic_nodes.size() >
      FlagsContinuationT<TurboshaftAdapter>::kMaxCompareChainSize) {
    return std::nullopt;
  }
  if (!logic_nodes.front()->IsLegalFirstCombine()) {
    return std::nullopt;
  }

  for (auto* logic_node : logic_nodes) {
    CombineFlagSettingOps(logic_node, selector, sequence);
  }
  DCHECK_LE(sequence->num_ccmps(),
            FlagsContinuationT<TurboshaftAdapter>::kMaxCompareChainSize);
  return logic_nodes.back()->user_condition();
}

static bool TryMatchConditionalCompareChainBranch(
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone, OpIndex node,
    FlagsContinuationT<TurboshaftAdapter>* cont) {
  if (!cont->IsBranch()) return false;
  DCHECK(cont->condition() == kNotEqual || cont->condition() == kEqual);

  CompareSequence sequence;
  auto final_cond =
      TryMatchConditionalCompareChainShared(selector, zone, node, &sequence);
  if (final_cond.has_value()) {
    FlagsCondition condition = cont->condition() == kNotEqual
                                   ? final_cond.value()
                                   : NegateFlagsCondition(final_cond.value());
    FlagsContinuationT<TurboshaftAdapter> new_cont =
        FlagsContinuationT<TurboshaftAdapter>::ForConditionalBranch(
            sequence.ccmps(), sequence.num_ccmps(), condition,
            cont->true_block(), cont->false_block());

    VisitBinopImpl(selector, sequence.cmp(), sequence.left(), sequence.right(),
                   selector->Get(sequence.cmp()).Cast<ComparisonOp>().rep,
                   sequence.opcode(), kArithmeticImm, &new_cont);

    return true;
  }
  return false;
}

static bool TryMatchConditionalCompareChainSet(
    InstructionSelectorT<TurboshaftAdapter>* selector, Zone* zone,
    OpIndex node) {
  // Create the cmp + ccmp ... sequence.
  CompareSequence sequence;
  auto final_cond =
      TryMatchConditionalCompareChainShared(selector, zone, node, &sequence);
  if (final_cond.has_value()) {
    // The continuation performs the conditional compare and cset.
    FlagsContinuationT<TurboshaftAdapter> cont =
        FlagsContinuationT<TurboshaftAdapter>::ForConditionalSet(
            sequence.ccmps(), sequence.num_ccmps(), final_cond.value(), node);

    VisitBinopImpl(selector, sequence.cmp(), sequence.left(), sequence.right(),
                   selector->Get(sequence.cmp()).Cast<ComparisonOp>().rep,
                   sequence.opcode(), kArithmeticImm, &cont);
    return true;
  }
  return false;
}

}  // end namespace turboshaft

template <typename Adapter, typename Matcher>
static void VisitLogical(InstructionSelectorT<Adapter>* selector, Node* node,
                         Matcher* m, ArchOpcode opcode, bool left_can_cover,
                         bool right_can_cover, ImmediateMode imm_mode) {
  Arm64OperandGeneratorT<Adapter> g(selector);

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kArm64And32:
      inv_opcode = kArm64Bic32;
      break;
    case kArm64And:
      inv_opcode = kArm64Bic;
      break;
    case kArm64Or32:
      inv_opcode = kArm64Orn32;
      break;
    case kArm64Or:
      inv_opcode = kArm64Orn;
      break;
    case kArm64Eor32:
      inv_opcode = kArm64Eon32;
      break;
    case kArm64Eor:
      inv_opcode = kArm64Eon;
      break;
    default:
      UNREACHABLE();
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if ((m->left().IsWord32Xor() || m->left().IsWord64Xor()) && left_can_cover) {
    Matcher mleft(m->left().node());
    if (mleft.right().Is(-1)) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(m->right().node()),
                     g.UseRegister(mleft.left().node()));
      return;
    }
  }

  // Select Logical(x, ~y) for Logical(x, Xor(y, -1)).
  if ((m->right().IsWord32Xor() || m->right().IsWord64Xor()) &&
      right_can_cover) {
    Matcher mright(m->right().node());
    if (mright.right().Is(-1)) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(m->left().node()),
                     g.UseRegister(mright.left().node()));
      return;
    }
  }

  if (m->IsWord32Xor() && m->right().Is(-1)) {
    selector->Emit(kArm64Not32, g.DefineAsRegister(node),
                   g.UseRegister(m->left().node()));
  } else if (m->IsWord64Xor() && m->right().Is(-1)) {
    selector->Emit(kArm64Not, g.DefineAsRegister(node),
                   g.UseRegister(m->left().node()));
  } else {
    VisitBinop<Adapter, Matcher>(selector, node, opcode, imm_mode);
  }
}

static void VisitLogical(InstructionSelectorT<TurboshaftAdapter>* selector,
                         Zone* zone, turboshaft::OpIndex node,
                         turboshaft::WordRepresentation rep, ArchOpcode opcode,
                         bool left_can_cover, bool right_can_cover,
                         ImmediateMode imm_mode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const WordBinopOp& logical_op = selector->Get(node).Cast<WordBinopOp>();
  const Operation& lhs = selector->Get(logical_op.left());
  const Operation& rhs = selector->Get(logical_op.right());

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kArm64And32:
      inv_opcode = kArm64Bic32;
      break;
    case kArm64And:
      inv_opcode = kArm64Bic;
      break;
    case kArm64Or32:
      inv_opcode = kArm64Orn32;
      break;
    case kArm64Or:
      inv_opcode = kArm64Orn;
      break;
    case kArm64Eor32:
      inv_opcode = kArm64Eon32;
      break;
    case kArm64Eor:
      inv_opcode = kArm64Eon;
      break;
    default:
      UNREACHABLE();
  }

  if (turboshaft::TryMatchConditionalCompareChainSet(selector, zone, node)) {
    return;
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if (lhs.Is<Opmask::kBitwiseXor>() && left_can_cover) {
    const WordBinopOp& xor_op = lhs.Cast<WordBinopOp>();
    int64_t xor_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.right()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  // Select Logical(x, ~y) for Logical(x, Xor(y, -1)).
  if (rhs.Is<Opmask::kBitwiseXor>() && right_can_cover) {
    const WordBinopOp& xor_op = rhs.Cast<WordBinopOp>();
    int64_t xor_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.left()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  int64_t xor_rhs_val;
  if (logical_op.Is<Opmask::kBitwiseXor>() &&
      selector->MatchSignedIntegralConstant(logical_op.right(), &xor_rhs_val) &&
      xor_rhs_val == -1) {
    const WordBinopOp& xor_op = logical_op.Cast<Opmask::kBitwiseXor>();
    bool is32 = rep == WordRepresentation::Word32();
    ArchOpcode opcode = is32 ? kArm64Not32 : kArm64Not;
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(xor_op.left()));
  } else {
    VisitBinop(selector, node, rep, opcode, imm_mode);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  const WordBinopOp& bitwise_and =
      this->Get(node).Cast<Opmask::kWord32BitwiseAnd>();
  const Operation& lhs = this->Get(bitwise_and.left());
  if (lhs.Is<Opmask::kWord32ShiftRightLogical>() &&
      CanCover(node, bitwise_and.left()) &&
      this->is_integer_constant(bitwise_and.right())) {
    int64_t constant_rhs = this->integer_constant(bitwise_and.right());
    DCHECK(base::IsInRange(constant_rhs, std::numeric_limits<int32_t>::min(),
                           std::numeric_limits<int32_t>::max()));
    uint32_t mask = static_cast<uint32_t>(constant_rhs);
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
    if ((mask_width != 0) && (mask_width != 32) &&
        (mask_msb + mask_width == 32)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      const ShiftOp& lhs_shift = lhs.Cast<Opmask::kWord32ShiftRightLogical>();
      if (this->is_integer_constant(lhs_shift.right())) {
        // Any shift value can match; int32 shifts use `value % 32`.
        uint32_t lsb = this->integer_constant(lhs_shift.right()) & 0x1F;

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 32) mask_width = 32 - lsb;

        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(lhs_shift.left()),
             g.UseImmediateOrTemp(lhs_shift.right(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical(this, zone(), node, bitwise_and.rep, kArm64And32,
               CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kLogical32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32And(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.left().IsWord32Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint32_t mask = m.right().ResolvedValue();
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
    if ((mask_width != 0) && (mask_width != 32) &&
        (mask_msb + mask_width == 32)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int32 shifts use `value % 32`.
        uint32_t lsb = mleft.right().ResolvedValue() & 0x1F;

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 32) mask_width = 32 - lsb;

        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(mleft.right().node(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical<TurbofanAdapter, Int32BinopMatcher>(
      this, node, &m, kArm64And32, CanCover(node, m.left().node()),
      CanCover(node, m.right().node()), kLogical32Imm);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<Opmask::kWord64BitwiseAnd>();
  const Operation& lhs = Get(bitwise_and.left());

  if (lhs.Is<Opmask::kWord64ShiftRightLogical>() &&
      CanCover(node, bitwise_and.left()) &&
      is_integer_constant(bitwise_and.right())) {
    uint64_t mask = integer_constant(bitwise_and.right());
    uint64_t mask_width = base::bits::CountPopulation(mask);
    uint64_t mask_msb = base::bits::CountLeadingZeros64(mask);
    if ((mask_width != 0) && (mask_width != 64) &&
        (mask_msb + mask_width == 64)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      const ShiftOp& shift = lhs.Cast<ShiftOp>();
      if (is_integer_constant(shift.right())) {
        int64_t shift_by = integer_constant(shift.right());
        // Any shift value can match; int64 shifts use `value % 64`.
        uint32_t lsb = static_cast<uint32_t>(shift_by & 0x3F);

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 64) mask_width = 64 - lsb;

        Emit(kArm64Ubfx, g.DefineAsRegister(node), g.UseRegister(shift.left()),
             g.UseImmediateOrTemp(shift.right(), lsb),
             g.TempImmediate(static_cast<int32_t>(mask_width)));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical(this, zone(), node, bitwise_and.rep, kArm64And,
               CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kLogical64Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64And(Node* node) {
  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.left().IsWord64Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint64_t mask = m.right().ResolvedValue();
    uint64_t mask_width = base::bits::CountPopulation(mask);
    uint64_t mask_msb = base::bits::CountLeadingZeros64(mask);
    if ((mask_width != 0) && (mask_width != 64) &&
        (mask_msb + mask_width == 64)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

      // Select Ubfx for And(Shr(x, imm), mask) where the mask is in the least
      // significant bits.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int64 shifts use `value % 64`.
        uint32_t lsb =
            static_cast<uint32_t>(mleft.right().ResolvedValue() & 0x3F);

        // Ubfx cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use ubfx with a smaller mask and the remaining bits will be
        // zeros.
        if (lsb + mask_width > 64) mask_width = 64 - lsb;

        Emit(kArm64Ubfx, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(mleft.right().node(), lsb),
             g.TempImmediate(static_cast<int32_t>(mask_width)));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  VisitLogical<TurbofanAdapter, Int64BinopMatcher>(
      this, node, &m, kArm64And, CanCover(node, m.left().node()),
      CanCover(node, m.right().node()), kLogical64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Or32,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical32Imm);
  } else {
    Int32BinopMatcher m(node);
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kArm64Or32, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Or,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical64Imm);
  } else {
    Int64BinopMatcher m(node);
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kArm64Or, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical64Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Eor32,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical32Imm);
  } else {
    Int32BinopMatcher m(node);
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kArm64Eor32, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, zone(), node, op.rep, kArm64Eor,
                 CanCover(node, op.left()), CanCover(node, op.right()),
                 kLogical64Imm);
  } else {
    Int64BinopMatcher m(node);
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kArm64Eor, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kLogical64Imm);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shl(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shift_op = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shift_op.left());
  if (lhs.Is<Opmask::kWord32BitwiseAnd>() && CanCover(node, shift_op.left()) &&
      is_integer_constant(shift_op.right())) {
    uint32_t shift_by =
        static_cast<uint32_t>(integer_constant(shift_op.right()));
    if (base::IsInRange(shift_by, 1, 31)) {
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (is_integer_constant(bitwise_and.right())) {
        uint32_t mask =
            static_cast<uint32_t>(integer_constant(bitwise_and.right()));

        uint32_t mask_width = base::bits::CountPopulation(mask);
        uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
        if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
          DCHECK_NE(0u, shift_by);
          Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
          if ((shift_by + mask_width) >= 32) {
            // If the mask is contiguous and reaches or extends beyond the top
            // bit, only the shift is needed.
            Emit(kArm64Lsl32, g.DefineAsRegister(node),
                 g.UseRegister(bitwise_and.left()), g.UseImmediate(shift_by));
            return;
          } else {
            // Select Ubfiz for Shl(And(x, mask), imm) where the mask is
            // contiguous, and the shift immediate non-zero.
            Emit(kArm64Ubfiz32, g.DefineAsRegister(node),
                 g.UseRegister(bitwise_and.left()), g.UseImmediate(shift_by),
                 g.TempImmediate(mask_width));
            return;
          }
        }
      }
    }
  }
  VisitRRO(this, kArm64Lsl32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shl(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && CanCover(node, m.left().node()) &&
      m.right().IsInRange(1, 31)) {
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue()) {
      uint32_t mask = mleft.right().ResolvedValue();
      uint32_t mask_width = base::bits::CountPopulation(mask);
      uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
        uint32_t shift = m.right().ResolvedValue();
        DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
        DCHECK_NE(0u, shift);

        if ((shift + mask_width) >= 32) {
          // If the mask is contiguous and reaches or extends beyond the top
          // bit, only the shift is needed.
          Emit(kArm64Lsl32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseImmediate(m.right().node()));
          return;
        } else {
          // Select Ubfiz for Shl(And(x, mask), imm) where the mask is
          // contiguous, and the shift immediate non-zero.
          Emit(kArm64Ubfiz32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseImmediate(m.right().node()), g.TempImmediate(mask_width));
          return;
        }
      }
    }
  }
  VisitRRO(this, kArm64Lsl32, node, kShift32Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
  Arm64OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shift_op = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shift_op.left());
    const Operation& rhs = this->Get(shift_op.right());
    if ((lhs.Is<Opmask::kChangeInt32ToInt64>() ||
         lhs.Is<Opmask::kChangeUint32ToUint64>()) &&
        rhs.Is<Opmask::kWord32Constant>()) {
      int64_t shift_by = rhs.Cast<ConstantOp>().signed_integral();
      if (base::IsInRange(shift_by, 32, 63) &&
          CanCover(node, shift_op.left())) {
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kArm64Lsl, g.DefineAsRegister(node),
             g.UseRegister(lhs.Cast<ChangeOp>().input()),
             g.UseImmediate64(shift_by));
        return;
      }
    }
    VisitRRO(this, kArm64Lsl, node, kShift64Imm);
  } else {
    Int64BinopMatcher m(node);
    if ((m.left().IsChangeInt32ToInt64() ||
         m.left().IsChangeUint32ToUint64()) &&
        m.right().IsInRange(32, 63) && CanCover(node, m.left().node())) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the upper
      // 32 bits anyway.
      Emit(kArm64Lsl, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseImmediate(m.right().node()));
      return;
    }
    VisitRRO(this, kArm64Lsl, node, kShift64Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuationT<Adapter>* cont) {
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

  Arm64OperandGeneratorT<Adapter> g(this);

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

template <typename Adapter>
bool TryEmitBitfieldExtract32(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  if (selector->CanCover(node, m.left().node()) && m.left().IsWord32Shl()) {
    // Select Ubfx or Sbfx for (x << (K & 0x1F)) OP (K & 0x1F), where
    // OP is >>> or >> and (K & 0x1F) != 0.
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() && m.right().HasResolvedValue() &&
        (mleft.right().ResolvedValue() & 0x1F) != 0 &&
        (mleft.right().ResolvedValue() & 0x1F) ==
            (m.right().ResolvedValue() & 0x1F)) {
      DCHECK(m.IsWord32Shr() || m.IsWord32Sar());
      ArchOpcode opcode = m.IsWord32Sar() ? kArm64Sbfx32 : kArm64Ubfx32;

      int right_val = m.right().ResolvedValue() & 0x1F;
      DCHECK_NE(right_val, 0);

      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(mleft.left().node()), g.TempImmediate(0),
                     g.TempImmediate(32 - right_val));
      return true;
    }
  }
  return false;
}

template <>
bool TryEmitBitfieldExtract32(InstructionSelectorT<TurboshaftAdapter>* selector,
                              turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const ShiftOp& shift = selector->Get(node).Cast<ShiftOp>();
  const Operation& lhs = selector->Get(shift.left());
  if (selector->CanCover(node, shift.left()) &&
      lhs.Is<Opmask::kWord32ShiftLeft>()) {
    // Select Ubfx or Sbfx for (x << (K & 0x1F)) OP (K & 0x1F), where
    // OP is >>> or >> and (K & 0x1F) != 0.
    const ShiftOp& lhs_shift = lhs.Cast<ShiftOp>();
    int64_t lhs_shift_by_constant, shift_by_constant;
    if (selector->MatchSignedIntegralConstant(lhs_shift.right(),
                                              &lhs_shift_by_constant) &&
        selector->MatchSignedIntegralConstant(shift.right(),
                                              &shift_by_constant) &&
        (lhs_shift_by_constant & 0x1F) != 0 &&
        (lhs_shift_by_constant & 0x1F) == (shift_by_constant & 0x1F)) {
      DCHECK(shift.Is<Opmask::kWord32ShiftRightArithmetic>() ||
             shift.Is<Opmask::kWord32ShiftRightArithmeticShiftOutZeros>() ||
             shift.Is<Opmask::kWord32ShiftRightLogical>());

      ArchOpcode opcode = shift.kind == ShiftOp::Kind::kShiftRightLogical
                              ? kArm64Ubfx32
                              : kArm64Sbfx32;

      int right_val = shift_by_constant & 0x1F;
      DCHECK_NE(right_val, 0);

      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(lhs_shift.left()), g.TempImmediate(0),
                     g.TempImmediate(32 - right_val));
      return true;
    }
  }
  return false;
}

}  // namespace
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shr(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shift = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shift.left());
  if (lhs.Is<Opmask::kWord32BitwiseAnd>() &&
      is_integer_constant(shift.right())) {
    uint32_t lsb = integer_constant(shift.right()) & 0x1F;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    uint32_t constant_bitmask;
    if (MatchIntegralWord32Constant(bitwise_and.right(), &constant_bitmask) &&
        constant_bitmask != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint32_t mask = (constant_bitmask >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_msb + mask_width + lsb) == 32) {
        Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(mask));
        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(bitwise_and.left()),
             g.UseImmediateOrTemp(shift.right(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  } else if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  if (lhs.Is<Opmask::kWord32UnsignedMulOverflownBits>() &&
      is_integer_constant(shift.right()) && CanCover(node, shift.left())) {
    // Combine this shift with the multiply and shift that would be generated
    // by Uint32MulHigh.
    Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
    const WordBinopOp& mul = lhs.Cast<WordBinopOp>();
    int shift_by = integer_constant(shift.right()) & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Umull, smull_operand, g.UseRegister(mul.left()),
         g.UseRegister(mul.right()));
    Emit(kArm64Lsr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift_by));
    return;
  }

  VisitRRO(this, kArm64Lsr32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shr(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x1F;
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Ubfx for Shr(And(x, mask), imm) where the result of the mask is
      // shifted into the least-significant bits.
      uint32_t mask =
          static_cast<uint32_t>(mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_msb + mask_width + lsb) == 32) {
        Arm64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(mask));
        Emit(kArm64Ubfx32, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseImmediateOrTemp(m.right().node(), lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  } else if (TryEmitBitfieldExtract32(this, node)) {
    return;
  }

  if (m.left().IsUint32MulHigh() && m.right().HasResolvedValue() &&
      CanCover(node, node->InputAt(0))) {
    // Combine this shift with the multiply and shift that would be generated
    // by Uint32MulHigh.
    Arm64OperandGeneratorT<TurbofanAdapter> g(this);
    Node* left = m.left().node();
    int shift = m.right().ResolvedValue() & 0x1F;
    InstructionOperand const smull_operand = g.TempRegister();
    Emit(kArm64Umull, smull_operand, g.UseRegister(left->InputAt(0)),
         g.UseRegister(left->InputAt(1)));
    Emit(kArm64Lsr, g.DefineAsRegister(node), smull_operand,
         g.TempImmediate(32 + shift));
    return;
  }

  VisitRRO(this, kArm64Lsr32, node, kShift32Imm);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(nod
"""


```