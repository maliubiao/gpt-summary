Response:
The user wants to understand the functionality of a specific part of a V8 source code file: `v8/src/codegen/mips64/macro-assembler-mips64.cc`. This is the 4th of 7 parts.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Functionality:** The provided code snippet primarily deals with conditional branching in MIPS64 assembly. It defines functions for generating different types of branch instructions (short and long), with and without link (for function calls), and for various conditional checks.

2. **Check for Torque (.tq):**  The filename ends in `.cc`, not `.tq`. So, this is C++ code, not Torque.

3. **Relate to JavaScript (if applicable):** Conditional branching in assembly directly relates to control flow in JavaScript. `if`, `else`, `while`, `for`, and other control flow statements in JavaScript are implemented using conditional branches at the assembly level.

4. **Provide JavaScript Examples:**  Illustrate the connection between JavaScript control flow structures and the underlying assembly concepts. A simple `if` statement is a good starting point.

5. **Demonstrate Code Logic with Assumptions:**  Select a simple function, like `BranchShort`, and illustrate its behavior with hypothetical inputs (offset, branch delay slot). Explain what the function does based on the inputs.

6. **Address Common Programming Errors:** Think about common mistakes related to branching, such as incorrect conditional checks or not understanding branch delay slots (although the code handles the latter internally). A simple example is using the wrong comparison operator.

7. **Summarize the Functionality:** Based on the analysis, condense the purpose of the provided code into a concise summary, focusing on conditional branching and related helpers.

8. **Consider the "Part 4 of 7" Context:**  Since this is a segment, the summary should reflect a part of a larger whole. It's likely this file provides a set of utilities for generating MIPS64 assembly instructions, and this part specifically handles branching.

**Pre-computation/Pre-analysis (Internal):**

* **Instruction Mnemonics:** Recognize MIPS64 assembly instructions like `Sltu`, `Daddu`, `Xor`, `Slt`, `Sgt`, `Sle`, `Sge`, `beq`, `bne`, `bltz`, `bgtz`, `blez`, `bgez`, `bc`, `bal`, `beqzalc`, `bnezalc`, etc. Understand their basic behavior.
* **Registers:** Understand the roles of registers like `dst`, `lhs`, `rhs`, `zero_reg`, and temporary registers.
* **Condition Codes:** Know the meaning of condition codes like `eq`, `ne`, `lt`, `gt`, `le`, `ge`, `lo`, `hs`, `hi`, `ls`.
* **Branch Delay Slots:** Be aware of the MIPS architecture's branch delay slot and how the assembler might handle it (emitting a `nop`).
* **Short vs. Long Branches:** Understand the limitations of short branches and when long branches are necessary.
* **Labels:** Recognize the use of labels for branching targets.

By following these steps and leveraging knowledge of assembly programming and the MIPS64 architecture, a comprehensive and accurate answer can be constructed.
这是 `v8/src/codegen/mips64/macro-assembler-mips64.cc` 源代码的一部分，主要负责实现 **MIPS64 架构的宏汇编器** 的功能，特别是关于 **条件设置和分支指令** 的生成。

**功能归纳:**

这部分代码的主要功能是提供高级接口，用于生成 MIPS64 的条件设置指令（例如 `slt`, `sgt` 等）和各种类型的分支指令（例如 `beq`, `bne`, `bltz`, `bgez`, `bal` 等）。它封装了底层的汇编指令，使得代码生成器可以更方便地生成控制流相关的指令。

**详细功能列表:**

1. **条件设置指令生成:**
   - `CompareAndSet`:  根据不同的条件码（例如相等、不等、小于、大于等），生成相应的 MIPS64 指令来比较两个操作数，并将结果（0 或 1）写入目标寄存器。它考虑了操作数是立即数还是寄存器的情况，并进行了优化，例如当比较立即数为 0 时使用更简洁的指令。
   - 生成 `slt`, `sgt`, `sle`, `sge`, `sltu`, `sgeu`, `sgtu`, `sleu` 等指令。

2. **分支指令生成:**
   - `Branch`:  生成无条件分支指令，可以跳转到相对于当前指令的偏移地址，也可以跳转到指定的标签位置。它支持短跳转和长跳转，并根据目标地址是否已绑定来选择合适的跳转方式。
   - `Branch`: 生成条件分支指令，根据指定的条件码和比较的寄存器/操作数，来决定是否跳转到目标地址。它同样支持短跳转和长跳转，并根据目标地址是否已绑定以及是否需要 trampoline 来选择合适的跳转方式。
   - `BranchShortHelper`, `BranchShortHelperR6`:  辅助函数，用于生成短跳转指令。`R6` 后缀表示针对 MIPS64 Release 6 架构的优化。
   - `BranchShort`, `BranchShortCheck`:  生成短跳转指令的接口，`Check` 版本用于内部检查参数。

3. **带链接的分支指令生成 (用于函数调用):**
   - `BranchAndLink`: 生成带链接的无条件分支指令，跳转到目标地址并将返回地址保存在 `ra` 寄存器中。它也支持短跳转和长跳转。
   - `BranchAndLink`: 生成带链接的条件分支指令，根据条件决定是否跳转并保存返回地址。
   - `BranchAndLinkShortHelper`, `BranchAndLinkShortHelperR6`:  辅助函数，用于生成带链接的短跳转指令。
   - `BranchAndLinkShort`, `BranchAndLinkShortCheck`: 生成带链接的短跳转指令的接口。

4. **辅助功能:**
   - `GetOffset`: 计算跳转指令的偏移量。
   - `GetRtAsRegisterHelper`:  将操作数转换为寄存器，如果操作数是立即数，则将其加载到临时寄存器中。
   - `CalculateOffset`: 检查跳转是否是短跳转并计算偏移量。
   - `NegateCondition`:  返回与给定条件相反的条件码。
   - `BRANCH_ARGS_CHECK`:  宏定义，用于检查分支指令参数的正确性。
   - 对 Branch Delay Slot 的处理 (通过 `BranchDelaySlot` 枚举和 `nop()` 指令)。

**关于 .tq 文件:**

代码中提到： "如果 `v8/src/codegen/mips64/macro-assembler-mips64.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码"。 然而，**当前文件的扩展名是 `.cc`，因此它是一个 C++ 源代码文件，而不是 Torque 文件。** Torque 文件通常用于定义类型和生成一些样板代码。

**与 JavaScript 功能的关系:**

这部分代码与 JavaScript 的控制流功能密切相关。JavaScript 中的 `if`, `else`, `for`, `while` 等控制结构在底层会被编译成类似这里生成的条件分支指令。

**JavaScript 示例:**

```javascript
function compare(a, b) {
  if (a > b) {
    return "a is greater";
  } else if (a < b) {
    return "b is greater";
  } else {
    return "a and b are equal";
  }
}
```

当 V8 编译 `compare` 函数时，其中的 `if` 和 `else if` 语句会转化为一系列的比较指令和条件分支指令，类似于 `MacroAssembler::CompareAndSet` 和 `MacroAssembler::Branch` 生成的指令。

**代码逻辑推理示例:**

**假设输入:**

- `dst` 为寄存器 `t0`
- `lhs` 为寄存器 `a0`，其值为 10
- `rhs` 为操作数，表示立即数 5
- `cond` 为 `gt` (大于)

**执行 `CompareAndSet(gt, dst, lhs, rhs)`:**

由于 `cond` 是 `gt`，`rhs` 是立即数，且不是 0 或 -int16，代码会执行到 `case gt:` 分支：

```c++
case gt:
  Sgt(dst, lhs, rhs);
  break;
```

这将生成 MIPS64 的 `sgt t0, a0, 5` 指令。

**输出:**

- 如果 `a0` 的值 (10) 大于 5，则 `t0` 寄存器的值将被设置为 1。
- 否则，`t0` 寄存器的值将被设置为 0。

**用户常见的编程错误示例:**

一个常见的编程错误是 **在条件判断中使用错误的比较运算符**，导致程序逻辑出错。

**例如:**

在 JavaScript 中，如果程序员想判断一个数是否大于等于 10，但错误地使用了 `>` 运算符：

```javascript
let num = 9;
if (num > 10) { // 错误地使用了 >
  console.log("Number is greater than 10");
} else {
  console.log("Number is not greater than 10");
}
```

在这个例子中，当 `num` 为 10 时，条件判断会失败，因为 10 不大于 10。 正确的做法是使用 `>=`。

在汇编层面，这可能对应于使用了错误的条件码，例如本应该使用 `ge` (大于等于) 的地方使用了 `gt` (大于)。

**第 4 部分功能归纳:**

作为宏汇编器的第 4 部分，这段代码集中实现了 MIPS64 架构中 **条件设置和各种类型的分支指令的生成逻辑**。它提供了高级的 C++ 接口，方便 V8 的其他代码生成模块生成用于控制程序流程的汇编代码。 这部分是实现 JavaScript 控制结构（如 `if`, `else`, 循环等）的基础。

### 提示词
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
if (rhs.immediate() == 0) {
          if (cond == eq) {
            Sltu(dst, lhs, 1);
          } else {
            Sltu(dst, zero_reg, lhs);
          }
        } else if (is_int16(-rhs.immediate())) {
          Daddu(dst, lhs, Operand(-rhs.immediate()));
          if (cond == eq) {
            Sltu(dst, dst, 1);
          } else {
            Sltu(dst, zero_reg, dst);
          }
        } else {
          Xor(dst, lhs, rhs);
          if (cond == eq) {
            Sltu(dst, dst, 1);
          } else {
            Sltu(dst, zero_reg, dst);
          }
        }
      } else {
        Xor(dst, lhs, rhs);
        if (cond == eq) {
          Sltu(dst, dst, 1);
        } else {
          Sltu(dst, zero_reg, dst);
        }
      }
      break;
    }
    case lt:
      Slt(dst, lhs, rhs);
      break;
    case gt:
      Sgt(dst, lhs, rhs);
      break;
    case le:
      Sle(dst, lhs, rhs);
      break;
    case ge:
      Sge(dst, lhs, rhs);
      break;
    case lo:
      Sltu(dst, lhs, rhs);
      break;
    case hs:
      Sgeu(dst, lhs, rhs);
      break;
    case hi:
      Sgtu(dst, lhs, rhs);
      break;
    case ls:
      Sleu(dst, lhs, rhs);
      break;
    default:
      UNREACHABLE();
  }
}

// Emulated condtional branches do not emit a nop in the branch delay slot.
//
// BRANCH_ARGS_CHECK checks that conditional jump arguments are correct.
#define BRANCH_ARGS_CHECK(cond, rs, rt)                                  \
  DCHECK((cond == cc_always && rs == zero_reg && rt.rm() == zero_reg) || \
         (cond != cc_always && (rs != zero_reg || rt.rm() != zero_reg)))

void MacroAssembler::Branch(int32_t offset, BranchDelaySlot bdslot) {
  DCHECK_EQ(kArchVariant, kMips64r6 ? is_int26(offset) : is_int16(offset));
  BranchShort(offset, bdslot);
}

void MacroAssembler::Branch(int32_t offset, Condition cond, Register rs,
                            const Operand& rt, BranchDelaySlot bdslot) {
  bool is_near = BranchShortCheck(offset, nullptr, cond, rs, rt, bdslot);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::Branch(Label* L, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (is_near_branch(L)) {
      BranchShort(L, bdslot);
    } else {
      BranchLong(L, bdslot);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchLong(L, bdslot);
    } else {
      BranchShort(L, bdslot);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            const Operand& rt, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (!BranchShortCheck(0, L, cond, rs, rt, bdslot)) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L, bdslot);
        bind(&skip);
      } else {
        BranchLong(L, bdslot);
      }
    }
  } else {
    if (is_trampoline_emitted()) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L, bdslot);
        bind(&skip);
      } else {
        BranchLong(L, bdslot);
      }
    } else {
      BranchShort(L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            RootIndex index, BranchDelaySlot bdslot) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  LoadRoot(scratch, index);
  Branch(L, cond, rs, Operand(scratch), bdslot);
}

void MacroAssembler::BranchShortHelper(int16_t offset, Label* L,
                                       BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset16);
  b(offset);

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();
}

void MacroAssembler::BranchShortHelperR6(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset26);
  bc(offset);
}

void MacroAssembler::BranchShort(int32_t offset, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    DCHECK(is_int26(offset));
    BranchShortHelperR6(offset, nullptr);
  } else {
    DCHECK(is_int16(offset));
    BranchShortHelper(offset, nullptr, bdslot);
  }
}

void MacroAssembler::BranchShort(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    BranchShortHelperR6(0, L);
  } else {
    BranchShortHelper(0, L, bdslot);
  }
}

int32_t MacroAssembler::GetOffset(int32_t offset, Label* L, OffsetSize bits) {
  if (L) {
    offset = branch_offset_helper(L, bits) >> 2;
  } else {
    DCHECK(is_intn(offset, bits));
  }
  return offset;
}

Register MacroAssembler::GetRtAsRegisterHelper(const Operand& rt,
                                               Register scratch) {
  Register r2 = no_reg;
  if (rt.is_reg()) {
    r2 = rt.rm();
  } else {
    r2 = scratch;
    li(r2, rt);
  }

  return r2;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset,
                                     OffsetSize bits) {
  if (!is_near(L, bits)) return false;
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset, OffsetSize bits,
                                     Register* scratch, const Operand& rt) {
  if (!is_near(L, bits)) return false;
  *scratch = GetRtAsRegisterHelper(rt, *scratch);
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::BranchShortHelperR6(int32_t offset, Label* L,
                                         Condition cond, Register rs,
                                         const Operand& rt) {
  DCHECK(L == nullptr || offset == 0);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;

  // Be careful to always use shifted_branch_offset only just before the
  // branch instruction, as the location will be remember for patching the
  // target.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    switch (cond) {
      case cc_always:
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
        bc(offset);
        break;
      case eq:
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          // Pre R6 beq is used here to make the code patchable. Otherwise bc
          // should be used which has no condition field so is not patchable.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          beq(rs, scratch, offset);
          nop();
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          beqzc(rs, offset);
        } else {
          // We don't want any other register but scratch clobbered.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          beqc(rs, scratch, offset);
        }
        break;
      case ne:
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          // Pre R6 bne is used here to make the code patchable. Otherwise we
          // should not generate any instruction.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bne(rs, scratch, offset);
          nop();
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          bnezc(rs, offset);
        } else {
          // We don't want any other register but scratch clobbered.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bnec(rs, scratch, offset);
        }
        break;

      // Signed comparison.
      case greater:
        // rs > rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bltzc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          bgtzc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltc(scratch, rs, offset);
        }
        break;
      case greater_equal:
        // rs >= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          blezc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          bgezc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgec(rs, scratch, offset);
        }
        break;
      case less:
        // rs < rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bgtzc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          bltzc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltc(rs, scratch, offset);
        }
        break;
      case less_equal:
        // rs <= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bgezc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          blezc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgec(scratch, rs, offset);
        }
        break;

      // Unsigned comparison.
      case Ugreater:
        // rs > rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21, &scratch, rt))
            return false;
          bnezc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          bnezc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltuc(scratch, rs, offset);
        }
        break;
      case Ugreater_equal:
        // rs >= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21, &scratch, rt))
            return false;
          beqzc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgeuc(rs, scratch, offset);
        }
        break;
      case Uless:
        // rs < rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21, &scratch, rt))
            return false;
          bnezc(scratch, offset);
        } else if (IsZero(rt)) {
          break;  // No code needs to be emitted.
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltuc(rs, scratch, offset);
        }
        break;
      case Uless_equal:
        // rs <= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26, &scratch, rt))
            return false;
          bc(offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          beqzc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgeuc(scratch, rs, offset);
        }
        break;
      default:
        UNREACHABLE();
    }
  }
  CheckTrampolinePoolQuick(1);
  return true;
}

bool MacroAssembler::BranchShortHelper(int16_t offset, Label* L, Condition cond,
                                       Register rs, const Operand& rt,
                                       BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  if (!is_near(L, OffsetSize::kOffset16)) return false;

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
  int32_t offset32;

  // Be careful to always use shifted_branch_offset only just before the
  // branch instruction, as the location will be remember for patching the
  // target.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    switch (cond) {
      case cc_always:
        offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
        b(offset32);
        break;
      case eq:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(rs, zero_reg, offset32);
        } else {
          // We don't want any other register but scratch clobbered.
          scratch = GetRtAsRegisterHelper(rt, scratch);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(rs, scratch, offset32);
        }
        break;
      case ne:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(rs, zero_reg, offset32);
        } else {
          // We don't want any other register but scratch clobbered.
          scratch = GetRtAsRegisterHelper(rt, scratch);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(rs, scratch, offset32);
        }
        break;

      // Signed comparison.
      case greater:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bgtz(rs, offset32);
        } else {
          Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case greater_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bgez(rs, offset32);
        } else {
          Slt(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;
      case less:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bltz(rs, offset32);
        } else {
          Slt(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case less_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          blez(rs, offset32);
        } else {
          Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;

      // Unsigned comparison.
      case Ugreater:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(rs, zero_reg, offset32);
        } else {
          Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case Ugreater_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          b(offset32);
        } else {
          Sltu(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;
      case Uless:
        if (IsZero(rt)) {
          return true;  // No code needs to be emitted.
        } else {
          Sltu(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case Uless_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(rs, zero_reg, offset32);
        } else {
          Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;
      default:
        UNREACHABLE();
    }
  }

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();

  return true;
}

bool MacroAssembler::BranchShortCheck(int32_t offset, Label* L, Condition cond,
                                      Register rs, const Operand& rt,
                                      BranchDelaySlot bdslot) {
  BRANCH_ARGS_CHECK(cond, rs, rt);

  if (!L) {
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      DCHECK(is_int26(offset));
      return BranchShortHelperR6(offset, nullptr, cond, rs, rt);
    } else {
      DCHECK(is_int16(offset));
      return BranchShortHelper(offset, nullptr, cond, rs, rt, bdslot);
    }
  } else {
    DCHECK_EQ(offset, 0);
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      return BranchShortHelperR6(0, L, cond, rs, rt);
    } else {
      return BranchShortHelper(0, L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::BranchShort(int32_t offset, Condition cond, Register rs,
                                 const Operand& rt, BranchDelaySlot bdslot) {
  BranchShortCheck(offset, nullptr, cond, rs, rt, bdslot);
}

void MacroAssembler::BranchShort(Label* L, Condition cond, Register rs,
                                 const Operand& rt, BranchDelaySlot bdslot) {
  BranchShortCheck(0, L, cond, rs, rt, bdslot);
}

void MacroAssembler::BranchAndLink(int32_t offset, BranchDelaySlot bdslot) {
  BranchAndLinkShort(offset, bdslot);
}

void MacroAssembler::BranchAndLink(int32_t offset, Condition cond, Register rs,
                                   const Operand& rt, BranchDelaySlot bdslot) {
  bool is_near = BranchAndLinkShortCheck(offset, nullptr, cond, rs, rt, bdslot);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::BranchAndLink(Label* L, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (is_near_branch(L)) {
      BranchAndLinkShort(L, bdslot);
    } else {
      BranchAndLinkLong(L, bdslot);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchAndLinkLong(L, bdslot);
    } else {
      BranchAndLinkShort(L, bdslot);
    }
  }
}

void MacroAssembler::BranchAndLink(Label* L, Condition cond, Register rs,
                                   const Operand& rt, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (!BranchAndLinkShortCheck(0, L, cond, rs, rt, bdslot)) {
      Label skip;
      Condition neg_cond = NegateCondition(cond);
      BranchShort(&skip, neg_cond, rs, rt);
      BranchAndLinkLong(L, bdslot);
      bind(&skip);
    }
  } else {
    if (is_trampoline_emitted()) {
      Label skip;
      Condition neg_cond = NegateCondition(cond);
      BranchShort(&skip, neg_cond, rs, rt);
      BranchAndLinkLong(L, bdslot);
      bind(&skip);
    } else {
      BranchAndLinkShortCheck(0, L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::BranchAndLinkShortHelper(int16_t offset, Label* L,
                                              BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset16);
  bal(offset);

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();
}

void MacroAssembler::BranchAndLinkShortHelperR6(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset26);
  balc(offset);
}

void MacroAssembler::BranchAndLinkShort(int32_t offset,
                                        BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    DCHECK(is_int26(offset));
    BranchAndLinkShortHelperR6(offset, nullptr);
  } else {
    DCHECK(is_int16(offset));
    BranchAndLinkShortHelper(offset, nullptr, bdslot);
  }
}

void MacroAssembler::BranchAndLinkShort(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    BranchAndLinkShortHelperR6(0, L);
  } else {
    BranchAndLinkShortHelper(0, L, bdslot);
  }
}

bool MacroAssembler::BranchAndLinkShortHelperR6(int32_t offset, Label* L,
                                                Condition cond, Register rs,
                                                const Operand& rt) {
  DCHECK(L == nullptr || offset == 0);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
  OffsetSize bits = OffsetSize::kOffset16;

  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK((cond == cc_always && is_int26(offset)) || is_int16(offset));
  switch (cond) {
    case cc_always:
      if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
      balc(offset);
      break;
    case eq:
      if (!is_near(L, bits)) return false;
      Subu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      beqzalc(scratch, offset);
      break;
    case ne:
      if (!is_near(L, bits)) return false;
      Subu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      bnezalc(scratch, offset);
      break;

    // Signed comparison.
    case greater:
      // rs > rt
      if (rs.code() == rt.rm().code()) {
        break;  // No code needs to be emitted.
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        bltzalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        bgtzalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
        offset = GetOffset(offset, L, bits);
        bnezalc(scratch, offset);
      }
      break;
    case greater_equal:
      // rs >= rt
      if (rs.code() == rt.rm().code()) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
        balc(offset);
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        blezalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        bgezalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, rs, rt);
        offset = GetOffset(offset, L, bits);
        beqzalc(scratch, offset);
      }
      break;
    case less:
      // rs < rt
      if (rs.code() == rt.rm().code()) {
        break;  // No code needs to be emitted.
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        bgtzalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        bltzalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, rs, rt);
        offset = GetOffset(offset, L, bits);
        bnezalc(scratch, offset);
      }
      break;
    case less_equal:
      // rs <= r2
      if (rs.code() == rt.rm().code()) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
        balc(offset);
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        bgezalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        blezalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
        offset = GetOffset(offset, L, bits);
        beqzalc(scratch, offset);
      }
      break;

    // Unsigned comparison.
    case Ugreater:
      // rs > r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      offset = GetOffset(offset, L, bits);
      bnezalc(scratch, offset);
      break;
    case Ugreater_equal:
      // rs >= r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      beqzalc(scratch, offset);
      break;
    case Uless:
      // rs < r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      bnezalc(scratch, offset);
      break;
    case Uless_equal:
      // rs <= r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      offset = GetOffset(offset, L, bits);
      beqzalc(scratch, offset);
      break;
    default:
      UNREACHABLE();
  }
  return true;
}

// Pre r6 we need to use a bgezal or bltzal, but they can't be used directly
// with the slt instructions. We could use sub or add instead but we would miss
// overflow cases, so we keep slt and add an intermediate third instruction.
bool MacroAssembler::BranchAndLinkShortHelper(int16_t offset, Label* L,
                                              Condition cond, Register rs,
                                              const Operand& rt,
                                              BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  if (!is_near(L, OffsetSize::kOffset16)) return false;

  Register scratch = t8;
  BlockTrampolinePoolScope block_trampoline_pool(this);

  switch (cond) {
    case cc_always:
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bal(offset);
      break;
    case eq:
      bne(rs, GetRtAsRegisterHelper(rt, scratch), 2);
      nop();
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bal(offset);
      break;
    case ne:
      beq(rs, GetRtAsRegisterHelper(rt, scratch), 2);
      nop();
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bal(offset);
      break;

    // Signed comparison.
    case greater:
      Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case greater_equal:
      Slt(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;
    case less:
      Slt(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case less_equal:
      Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;

    // Unsigned comparison.
    case Ugreater:
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case Ugreater_equal:
      Sltu(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;
    case Uless:
      Sltu(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case Uless_equal:
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;

    default:
      UNREACHABLE();
  }

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();

  return true;
}

bool MacroAssembler::BranchAndLinkShortCheck(int32_t offset, Label* L,
                                             Condition cond, Register rs,
                                             const Operand& rt,
                                             BranchDelaySlot bdslot) {
  BRANCH_ARGS_CHECK(cond, rs, rt);

  if (!L) {
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      DCHECK(is_int26(offset));
      return BranchAndLinkShortHelperR6(offset, nullptr, cond, rs, rt);
    } else {
      DCHECK(is_int16(offset));
      return BranchAndLinkShortHelper(offset, nullptr, cond, rs, rt, bdslot);
    }
  } else {
    DCHECK_EQ(offset, 0);
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      return BranchAndLinkShortHelperR6(0, L, cond, rs, rt);
    } else {
      return BranchAndLinkShortHelper(0, L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  ASM_CODE_COMMENT(this);
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  Ld(destination,
     FieldMemOperand(destination, OFFSET_OF_DATA_START(FixedArray) +
                                      constant_index * kPointerSize));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  Ld(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  Sd(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    Daddu(destination, kRootRegister, Operand(offset));
  }
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      int64_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (root_array_available_ && options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        DCHECK(scratch.is_valid());
        Ld(scratch, MemOperand(kRootRegister,
```