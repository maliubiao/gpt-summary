Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This is the second part of a five-part code snippet.

The code defines functions within the `v8::internal::compiler` namespace, specifically for the PPC architecture. These functions are part of the instruction selection phase of the compiler. They aim to translate high-level intermediate representation (IR) nodes (like `Word32And`, `Word64Or`, `Word32Shl`, etc.) into specific PPC assembly instructions.

Key observations:

1. **Instruction Selection for Binary Operations:** The code includes functions like `VisitWord32And`, `VisitWord64Or`, `VisitWord32Xor`, etc. These functions handle different bitwise logical operations.
2. **Pattern Matching and Optimization:** The code performs pattern matching on the IR nodes. For example, it checks if a `Word32And` operation involves a contiguous mask and potentially optimizes it into a `rlwinm` (rotate left and mask) instruction. It also looks for opportunities to combine shifts and masks.
3. **Handling of Constants:** The code frequently checks if operands are constant values and uses appropriate immediate forms of instructions when possible.
4. **Turboshaft and Legacy Pipeline Support:** The code uses templates (`template <typename Adapter>`) and `if constexpr` to support both the Turboshaft and the older (legacy) V8 compilation pipelines.
5. **Stack Checks:** The `VisitStackPointerGreaterThan` function deals with generating code for stack overflow checks.
6. **Shift Operations:**  Functions like `VisitWord32Shl`, `VisitWord64Shr`, `VisitWord32Sar` handle left and right shift operations, including arithmetic shifts. They also attempt to optimize shift operations in combination with AND operations.
7. **Bit Manipulation Instructions:**  Functions like `VisitWord32Clz` (count leading zeros) and `VisitWord32Popcnt` (population count) are present.
8. **Contiguous Masks:** Helper functions `IsContiguousMask32` and `IsContiguousMask64` are used to identify bitmasks that can be efficiently handled by PPC's rotate and mask instructions.

Based on this, the main functionality is to **select and emit efficient PPC instructions for various bitwise logical and shift operations represented in the compiler's intermediate representation, with specific optimizations for constant operands and contiguous masks.**
这是 `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 源代码的第 2 部分，主要功能是**为 PowerPC 架构选择和生成指令，特别是针对位运算相关的操作进行优化**。

以下是更详细的功能归纳：

1. **处理逻辑运算 (`And`, `Or`, `Xor`)：**
    *   针对 `And` 和 `Or` 操作，尝试识别将右操作数取反的情况 (`Logical(y, ~x)` 对应 `Logical(Xor(x, -1), y)`)，并生成相应的 `And Complement` 或 `Or Complement` 指令。
    *   针对包含连续位掩码的 `And` 操作，尝试使用 `RotLeftAndMask32` 和 `RotLeftAndClear` 等指令进行优化，这些指令可以将移位和掩码操作合并为一个指令。
    *   `VisitLogical` 函数作为一个辅助函数，处理逻辑运算的通用逻辑，包括对右操作数取反的优化。

2. **处理移位运算 (`Shl`, `Shr`, `Sar`)：**
    *   针对左移 (`Shl`) 和右移 (`Shr`) 操作，如果左操作数是 `And` 运算，并且右操作数是常量，则尝试将移位操作融入 `RotLeftAndMask32` 或 `RotLeftAndClear` 指令中。这是一种常见的位域提取优化。
    *   针对算术右移 (`Sar`) 操作，如果左操作数是左移操作，且左右移位的位数相同（例如 `(x << 16) >> 16`），则将其替换为符号扩展指令 (`ExtendSignWord16` 或 `ExtendSignWord8`)。
    *   针对 64 位算术右移 (`Sar`)，如果左操作数是 Load 操作且右移 32 位，则尝试直接加载并符号扩展 32 位数据，这通常用于加载和解标记小的整数 (SMIs)。

3. **处理其他位操作 (`Clz`, `Popcnt`)：**
    *   实现了对计算前导零 (`Clz`) 和计算置位位数 (`Popcnt`) 的指令选择。

4. **处理栈指针比较 (`StackPointerGreaterThan`)：**
    *   生成用于检查栈是否溢出的指令。

5. **区分 Turboshaft 和旧版 Pipeline：**
    *   使用了模板和 `if constexpr` 来区分 Turboshaft 编译器和旧版的编译器 pipeline，针对不同的 pipeline 采取不同的处理方式。

**如果 `v8/src/compiler/backend/ppc/instruction-selector-ppc.cc` 以 `.tq` 结尾，那它是个 v8 Torque 源代码**

当前提供的代码片段是 C++ 代码 (`.cc`)，而不是 Torque 代码 (`.tq`)。Torque 是一种 V8 特有的领域特定语言，用于定义 V8 的内置函数和类型。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明**

这些底层的指令选择最终服务于 JavaScript 的执行。位运算在 JavaScript 中很常见，尤其是在处理底层数据、算法优化等方面。

例如，JavaScript 中的按位与、按位或、按位异或、左移、右移等操作，最终会通过 V8 的编译器转换成机器码执行。

```javascript
// JavaScript 例子

// 按位与
let a = 10;   // 二进制 1010
let b = 5;    // 二进制 0101
let result_and = a & b; // 结果为 0，因为 1010 & 0101 = 0000

// 按位或
let result_or = a | b;  // 结果为 15，因为 1010 | 0101 = 1111

// 左移
let c = 2;    // 二进制 10
let result_shl = c << 2; // 结果为 8，因为 10 << 2 = 1000

// 有符号右移
let d = -8;   // 二进制 ...11111000 (补码)
let result_shr = d >> 2; // 结果为 -2，因为 ...11111000 >> 2 = ...11111110

// 无符号右移
let result_ushr = d >>> 2; // 结果为一个很大的正数，因为无符号右移会在高位补 0
```

`instruction-selector-ppc.cc` 的代码逻辑就是负责将这些 JavaScript 的位运算操作翻译成高效的 PowerPC 汇编指令。 例如，上面的 `a & b` 操作可能会对应到 `VisitWord32And` 函数中的逻辑，并最终生成 PowerPC 的 `and` 指令。  如果 `b` 的值是一个可以编码为立即数的常量，编译器甚至可能会生成使用立即数的 `andi.` 指令。

**如果有代码逻辑推理，请给出假设输入与输出**

假设一个 `Word32And` 节点，其左操作数是一个寄存器，右操作数是一个常量 `0xFF` (二进制 `00000000000000000000000011111111`)。

*   **假设输入：**
    *   IR 节点类型：`Word32And`
    *   左操作数：一个表示变量的寄存器，假设其值为 `0b10101010111100001100110000110011`
    *   右操作数：常量 `0xFF` (十进制 255)

*   **代码逻辑推理：**
    *   `VisitWord32And` 函数会被调用。
    *   `IsContiguousMask32(0xFF, &mb, &me)` 会返回 `true`，`mb` 为 7，`me` 为 0。
    *   因为没有涉及移位优化，最终会调用 `Emit(kPPC_RotLeftAndMask32, ...)` 生成一个带掩码的旋转指令，虽然在这个例子中旋转量为 0，本质上就是一个 `and` 指令。  更准确地说，如果右操作数可以直接作为立即数，则会生成 `andi.` 指令。

*   **可能的输出 (PowerPC 汇编指令):**
    ```assembly
    andi. rD, rS, 255  //  假设左操作数在 rS 寄存器，结果写入 rD 寄存器
    ```
    或者如果进行了更复杂的优化，可能会是 `rlwinm` 的形式。

**如果涉及用户常见的编程错误，请举例说明**

与这些代码相关的用户常见编程错误通常涉及到对位运算的误解或使用不当：

1. **优先级错误：** 忘记位运算符的优先级低于算术运算符，导致计算结果错误。

    ```javascript
    let result = 2 + 4 & 8; // 错误：期望 (2 + 4) & 8，实际是 2 + (4 & 8)
    console.log(result);    // 输出 2，而不是期望的 0
    ```

2. **有符号和无符号右移的混淆：**  `>>` 是有符号右移，`>>>` 是无符号右移。对负数进行右移时，两者的结果可能完全不同。

    ```javascript
    let negativeNumber = -8;
    console.log(negativeNumber >> 2);  // 输出 -2
    console.log(negativeNumber >>> 2); // 输出一个很大的正数
    ```

3. **位掩码错误：**  错误地构造或使用位掩码，导致提取或设置位时出现问题。

    ```javascript
    // 错误地提取低 4 位
    let value = 0b10110101;
    let mask = 0b000011110; // 错误的掩码
    let lowBits = value & mask;
    console.log(lowBits.toString(2)); // 输出 10100，期望 0101
    ```

4. **边界条件错误：**  在移位操作中，移位量超出范围 (0-31 对于 32 位整数，0-63 对于 64 位整数) 可能导致未定义的行为或非预期的结果。虽然 JavaScript 规范中对移位操作的移位量做了处理 (取模)，但在某些底层操作中仍然需要注意。

**功能归纳 (针对第 2 部分):**

这部分代码主要负责 PowerPC 架构中**位运算和部分移位操作**的指令选择和优化。它针对 `And`、`Or`、`Xor`、`Shl`、`Shr`、`Sar` 等操作，尝试识别可以进行优化的模式，例如带有连续掩码的 `And` 操作和可以转化为符号扩展的移位操作，并生成相应的 PowerPC 指令。此外，还处理了栈指针比较和一些其他的位操作指令。 这部分代码是 V8 编译器将 JavaScript 的位运算操作高效地转化为 PowerPC 机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/ppc/instruction-selector-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ppc/instruction-selector-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.left()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  VisitBinop<TurboshaftAdapter>(selector, node, opcode, imm_mode);
}

template <typename Adapter, typename Matcher>
static void VisitLogical(InstructionSelectorT<Adapter>* selector, Node* node,
                         Matcher* m, ArchOpcode opcode, bool left_can_cover,
                         bool right_can_cover, ImmediateMode imm_mode) {
  PPCOperandGeneratorT<Adapter> g(selector);

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kPPC_And:
      inv_opcode = kPPC_AndComplement;
      break;
    case kPPC_Or:
      inv_opcode = kPPC_OrComplement;
      break;
    default:
      UNREACHABLE();
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if ((m->left().IsWord32Xor() || m->left().IsWord64Xor()) && left_can_cover) {
    Matcher mleft(m->left().node());
    if (mleft.right().Is(-1)) {
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

  VisitBinop<Adapter>(selector, node, opcode, imm_mode);
}

static inline bool IsContiguousMask32(uint32_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros32(value);
  int mask_lsb = base::bits::CountTrailingZeros32(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 32))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}

static inline bool IsContiguousMask64(uint64_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros64(value);
  int mask_lsb = base::bits::CountTrailingZeros64(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 64))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  int mb = 0;
  int me = 0;
  if (is_integer_constant(bitwise_and.right()) &&
      IsContiguousMask32(integer_constant(bitwise_and.right()), &mb, &me)) {
    int sh = 0;
    node_t left = bitwise_and.left();
    const Operation& lhs = Get(left);
    if ((lhs.Is<Opmask::kWord32ShiftRightLogical>() ||
         lhs.Is<Opmask::kWord32ShiftLeft>()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rlwinm
      int32_t shift_by;
      const ShiftOp& shift_op = lhs.Cast<ShiftOp>();
      if (MatchIntegralWord32Constant(shift_op.right(), &shift_by) &&
          base::IsInRange(shift_by, 0, 31)) {
        left = shift_op.left();
        sh = integer_constant(shift_op.right());
        if (lhs.Is<Opmask::kWord32ShiftRightLogical>()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 31 - sh) mb = 31 - sh;
          sh = (32 - sh) & 0x1F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node), g.UseRegister(left),
           g.TempImmediate(sh), g.TempImmediate(mb), g.TempImmediate(me));
      return;
    }
  }
  VisitLogical(this, node, kPPC_And, CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kInt16Imm_Unsigned);
}

// TODO(mbrandy): Absorb rotate-right into rlwinm?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);
  int mb = 0;
  int me = 0;
  if (m.right().HasResolvedValue() &&
      IsContiguousMask32(m.right().ResolvedValue(), &mb, &me)) {
    int sh = 0;
    Node* left = m.left().node();
    if ((m.left().IsWord32Shr() || m.left().IsWord32Shl()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rlwinm
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().IsInRange(0, 31)) {
        left = mleft.left().node();
        sh = mleft.right().ResolvedValue();
        if (m.left().IsWord32Shr()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 31 - sh) mb = 31 - sh;
          sh = (32 - sh) & 0x1F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node), g.UseRegister(left),
           g.TempImmediate(sh), g.TempImmediate(mb), g.TempImmediate(me));
      return;
    }
  }
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kPPC_And, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  int mb = 0;
  int me = 0;
  if (is_integer_constant(bitwise_and.right()) &&
      IsContiguousMask64(integer_constant(bitwise_and.right()), &mb, &me)) {
    int sh = 0;
    node_t left = bitwise_and.left();
    const Operation& lhs = Get(left);
    if ((lhs.Is<Opmask::kWord64ShiftRightLogical>() ||
         lhs.Is<Opmask::kWord64ShiftLeft>()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rldic
      int64_t shift_by;
      const ShiftOp& shift_op = lhs.Cast<ShiftOp>();
      if (MatchIntegralWord64Constant(shift_op.right(), &shift_by) &&
          base::IsInRange(shift_by, 0, 63)) {
        left = shift_op.left();
        sh = integer_constant(shift_op.right());
        if (lhs.Is<Opmask::kWord64ShiftRightLogical>()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      bool match = false;
      ArchOpcode opcode;
      int mask;
      if (me == 0) {
        match = true;
        opcode = kPPC_RotLeftAndClearLeft64;
        mask = mb;
      } else if (mb == 63) {
        match = true;
        opcode = kPPC_RotLeftAndClearRight64;
        mask = me;
      } else if (sh && me <= sh && lhs.Is<Opmask::kWord64ShiftLeft>()) {
        match = true;
        opcode = kPPC_RotLeftAndClear64;
        mask = mb;
      }
      if (match) {
        Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
             g.TempImmediate(sh), g.TempImmediate(mask));
        return;
      }
    }
  }
  VisitLogical(this, node, kPPC_And, CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kInt16Imm_Unsigned);
}

// TODO(mbrandy): Absorb rotate-right into rldic?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64And(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    int mb = 0;
    int me = 0;
    if (m.right().HasResolvedValue() &&
        IsContiguousMask64(m.right().ResolvedValue(), &mb, &me)) {
      int sh = 0;
      Node* left = m.left().node();
      if ((m.left().IsWord64Shr() || m.left().IsWord64Shl()) &&
          CanCover(node, left)) {
        // Try to absorb left/right shift into rldic
        Int64BinopMatcher mleft(m.left().node());
        if (mleft.right().IsInRange(0, 63)) {
          left = mleft.left().node();
          sh = mleft.right().ResolvedValue();
          if (m.left().IsWord64Shr()) {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (mb > 63 - sh) mb = 63 - sh;
            sh = (64 - sh) & 0x3F;
          } else {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (me < sh) me = sh;
          }
        }
      }
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kPPC_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kPPC_RotLeftAndClearRight64;
          mask = me;
        } else if (sh && me <= sh && m.left().IsWord64Shl()) {
          match = true;
          opcode = kPPC_RotLeftAndClear64;
          mask = mb;
        }
        if (match) {
          Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
               g.TempImmediate(sh), g.TempImmediate(mask));
          return;
        }
      }
    }
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kPPC_And, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, node, kPPC_Or, CanCover(node, op.left()),
                 CanCover(node, op.right()), kInt16Imm_Unsigned);
  } else {
    Int32BinopMatcher m(node);
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kPPC_Or, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, node, kPPC_Or, CanCover(node, op.left()),
                 CanCover(node, op.right()), kInt16Imm_Unsigned);
  } else {
    Int64BinopMatcher m(node);
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kPPC_Or, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& bitwise_xor =
        this->Get(node).template Cast<WordBinopOp>();
    int32_t mask;
    if (this->MatchIntegralWord32Constant(bitwise_xor.right(), &mask) &&
        mask == -1) {
      Emit(kPPC_Not, g.DefineAsRegister(node),
           g.UseRegister(bitwise_xor.left()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(-1)) {
      Emit(kPPC_Not, g.DefineAsRegister(node), g.UseRegister(m.left().node()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
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

  PPCOperandGeneratorT<Adapter> g(this);

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

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& bitwise_xor =
        this->Get(node).template Cast<WordBinopOp>();
    int64_t mask;
    if (this->MatchIntegralWord64Constant(bitwise_xor.right(), &mask) &&
        mask == -1) {
      Emit(kPPC_Not, g.DefineAsRegister(node),
           g.UseRegister(bitwise_xor.left()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  } else {
    Int64BinopMatcher m(node);
    if (m.right().Is(-1)) {
      Emit(kPPC_Not, g.DefineAsRegister(node), g.UseRegister(m.left().node()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shl = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shl.left());
    if (lhs.Is<Opmask::kWord32BitwiseAnd>() &&
        this->is_integer_constant(shl.right()) &&
        base::IsInRange(this->integer_constant(shl.right()), 0, 31)) {
      int sh = this->integer_constant(shl.right());
      int mb;
      int me;
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (this->is_integer_constant(bitwise_and.right()) &&
          IsContiguousMask32(this->integer_constant(bitwise_and.right()) << sh,
                             &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (me < sh) me = sh;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftLeft32, node, kShift32Imm);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32And() && m.right().IsInRange(0, 31)) {
      // Try to absorb logical-and into rlwinm
      Int32BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask32(mleft.right().ResolvedValue() << sh, &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (me < sh) me = sh;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftLeft32, node, kShift32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const ShiftOp& shl = this->Get(node).template Cast<ShiftOp>();
      const Operation& lhs = this->Get(shl.left());
      if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
          this->is_integer_constant(shl.right()) &&
          base::IsInRange(this->integer_constant(shl.right()), 0, 63)) {
        int sh = this->integer_constant(shl.right());
        int mb;
        int me;
        const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
        if (this->is_integer_constant(bitwise_and.right()) &&
            IsContiguousMask64(
                this->integer_constant(bitwise_and.right()) << sh, &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            } else if (sh && me <= sh) {
              match = true;
              opcode = kPPC_RotLeftAndClear64;
              mask = mb;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftLeft64, node, kShift64Imm);
    } else {
      Int64BinopMatcher m(node);
      // TODO(mbrandy): eliminate left sign extension if right >= 32
      if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
        // Try to absorb logical-and into rldic
        Int64BinopMatcher mleft(m.left().node());
        int sh = m.right().ResolvedValue();
        int mb;
        int me;
        if (mleft.right().HasResolvedValue() &&
            IsContiguousMask64(mleft.right().ResolvedValue() << sh, &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            } else if (sh && me <= sh) {
              match = true;
              opcode = kPPC_RotLeftAndClear64;
              mask = mb;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftLeft64, node, kShift64Imm);
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shr.left());
    if (lhs.Is<Opmask::kWord32BitwiseAnd>() &&
        this->is_integer_constant(shr.right()) &&
        base::IsInRange(this->integer_constant(shr.right()), 0, 31)) {
      int sh = this->integer_constant(shr.right());
      int mb;
      int me;
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (this->is_integer_constant(bitwise_and.right()) &&
          IsContiguousMask32(
              static_cast<uint32_t>(
                  this->integer_constant(bitwise_and.right()) >> sh),
              &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (mb > 31 - sh) mb = 31 - sh;
        sh = (32 - sh) & 0x1F;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRight32, node, kShift32Imm);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32And() && m.right().IsInRange(0, 31)) {
      // Try to absorb logical-and into rlwinm
      Int32BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask32((uint32_t)(mleft.right().ResolvedValue()) >> sh,
                             &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (mb > 31 - sh) mb = 31 - sh;
        sh = (32 - sh) & 0x1F;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRight32, node, kShift32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
      const Operation& lhs = this->Get(shr.left());
      if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
          this->is_integer_constant(shr.right()) &&
          base::IsInRange(this->integer_constant(shr.right()), 0, 63)) {
        int sh = this->integer_constant(shr.right());
        int mb;
        int me;
        const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
        if (this->is_integer_constant(bitwise_and.right()) &&
            IsContiguousMask64(
                static_cast<uint64_t>(
                    this->integer_constant(bitwise_and.right()) >> sh),
                &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftRight64, node, kShift64Imm);
    } else {
      Int64BinopMatcher m(node);
      if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
        // Try to absorb logical-and into rldic
        Int64BinopMatcher mleft(m.left().node());
        int sh = m.right().ResolvedValue();
        int mb;
        int me;
        if (mleft.right().HasResolvedValue() &&
            IsContiguousMask64((uint64_t)(mleft.right().ResolvedValue()) >> sh,
                               &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftRight64, node, kShift64Imm);
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
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
          Emit(kPPC_ExtendSignWord16, g.DefineAsRegister(node),
               g.UseRegister(shl.left()));
          return;
        } else if ((sar_by == shl_by) && (sar_by == 24)) {
          Emit(kPPC_ExtendSignWord8, g.DefineAsRegister(node),
               g.UseRegister(shl.left()));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRightAlg32, node, kShift32Imm);
  } else {
    Int32BinopMatcher m(node);
    // Replace with sign extension for (x << K) >> K where K is 16 or 24.
    if (CanCover(node, m.left().node()) && m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().Is(16) && m.right().Is(16)) {
        Emit(kPPC_ExtendSignWord16, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()));
        return;
      } else if (mleft.right().Is(24) && m.right().Is(24)) {
        Emit(kPPC_ExtendSignWord8, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()));
        return;
      }
    }
    VisitRRO(this, kPPC_ShiftRightAlg32, node, kShift32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      DCHECK(this->Get(node).template Cast<ShiftOp>().IsRightShift());
      const ShiftOp& shift = this->Get(node).template Cast<ShiftOp>();
      const Operation& lhs = this->Get(shift.left());
      int64_t constant_rhs;

      if (lhs.Is<LoadOp>() &&
          this->MatchIntegralWord64Constant(shift.right(), &constant_rhs) &&
          constant_rhs == 32 && this->CanCover(node, shift.left())) {
        // Just load and sign-extend the interesting 4 bytes instead. This
        // happens, for example, when we're loading and untagging SMIs.
        const LoadOp& load = lhs.Cast<LoadOp>();
        int64_t offset = 0;
        if (load.index().has_value()) {
          int64_t index_constant;
          if (this->MatchIntegralWord64Constant(load.index().value(),
                                                &index_constant)) {
            DCHECK_EQ(load.element_size_log2, 0);
            offset = index_constant;
          }
        } else {
          offset = load.offset;
        }
        offset = SmiWordOffset(offset);
        if (g.CanBeImmediate(offset, kInt16Imm_4ByteAligned)) {
          Emit(kPPC_LoadWordS32 | AddressingModeField::encode(kMode_MRI),
               g.DefineAsRegister(node), g.UseRegister(load.base()),
               g.TempImmediate(offset), g.UseImmediate(0));
          return;
        }
      }
    } else {
      Int64BinopMatcher m(node);
      if (CanCover(m.node(), m.left().node()) && m.left().IsLoad() &&
          m.right().Is(32)) {
        // Just load and sign-extend the interesting 4 bytes instead. This
        // happens, for example, when we're loading and untagging SMIs.
        BaseWithIndexAndDisplacement64Matcher mleft(m.left().node(),
                                                    AddressOption::kAllowAll);
        if (mleft.matches() && mleft.index() == nullptr) {
          int64_t offset = 0;
          Node* displacement = mleft.displacement();
          if (displacement != nullptr) {
            Int64Matcher mdisplacement(displacement);
            DCHECK(mdisplacement.HasResolvedValue());
            offset = mdisplacement.ResolvedValue();
          }
          offset = SmiWordOffset(offset);
          if (g.CanBeImmediate(offset, kInt16Imm_4ByteAligned)) {
            Emit(kPPC_LoadWordS32 | AddressingModeField::encode(kMode_MRI),
                 g.DefineAsRegister(node), g.UseRegister(mleft.base()),
                 g.TempImmediate(offset), g.UseImmediate(0));
            return;
          }
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRightAlg64, node, kShift64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
    UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

// TODO(mbrandy): Absorb logical-and into rlwinm?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
    VisitRRO(this, kPPC_RotRight32, node, kShift32Imm);
}

// TODO(mbrandy): Absorb logical-and into rldic?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
    VisitRRO(this, kPPC_RotRight64, node, kShift64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Clz(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Cntlz32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Clz(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Cntlz64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Popcnt32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Popcnt(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Popcnt64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    PPCOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp[] = {g.TempRegister()};
    node_t input = this->Get(node).input(0);
    const Operation& input_op = this->Get(input);
    if (CanCover(node, input) && input_op.Is<LoadOp>()) {
      auto load = this->load_view(input);
      LoadRepresentation load_rep = load.loaded_rep();
      if (load_rep.representation() == MachineRepresentation::kWord64) {
        node_t base = load.base();
        node_t offset = load.index();
        bool is_
"""


```