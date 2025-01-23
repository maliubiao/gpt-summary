Response: The user wants a summary of the C++ code provided, which is part of a larger file.
This part of the code seems to be handling the execution of various LoongArch64 instructions within a simulator.
The code iterates through different instruction types and performs the corresponding actions.
It interacts with registers (both general-purpose and floating-point), memory, and a floating-point control and status register (FCSR).

**Plan:**
1. Identify the main functionality of the code.
2. Summarize the actions performed for different instruction types.
3. Explain the relationship with Javascript (via V8).
4. Provide a Javascript example to illustrate the connection.
这是目录为v8/src/execution/loong64/simulator-loong64.cc 的一个 c++ 源代码文件的第 3 部分，共 4 部分。

**功能归纳:**

这部分代码主要负责 **模拟执行 LoongArch64 架构的指令**。它具体实现了多种指令的操作逻辑，包括：

* **算术运算指令 (Integer Arithmetic):**  例如 ADD_W, ADD_D, SUB_W, SUB_D, MUL_W, MUL_D, DIV_W, DIV_D, MOD_W, MOD_D 等，涵盖了有符号和无符号的 32 位和 64 位整数的加减乘除模运算。
* **逻辑运算指令 (Logical Operations):** 例如 AND, OR, XOR, NOR, ANDN, ORN 等，执行位与、或、异或、或非、与非等逻辑操作。
* **移位和旋转指令 (Shift and Rotate):** 例如 SLL_W, SRL_W, SRA_W, SLL_D, SRL_D, SRA_D, ROTR_W, ROTR_D 等，实现逻辑左移、逻辑右移、算术右移和循环右移。
* **比较指令 (Comparison):** 例如 SLT (Set Less Than), SLTU (Set Less Than Unsigned)，比较两个寄存器的值。
* **掩码指令 (Mask):** 例如 MASKEQZ (Mask Equal Zero), MASKNEZ (Mask Not Equal Zero)，根据条件选择性地更新寄存器。
* **浮点运算指令 (Floating-Point Arithmetic):** 例如 FADD_S, FADD_D, FSUB_S, FSUB_D, FMUL_S, FMUL_D, FDIV_S, FDIV_D, FMAX_S, FMAX_D, FMIN_S, FMIN_D 等，执行单精度和双精度浮点数的加减乘除、最大值、最小值等运算。
* **加载和存储指令 (Load and Store):** 例如 LDX_B, LDX_H, LDX_W, LDX_D, STX_B, STX_H, STX_W, STX_D, FLDX_S, FLDX_D, FSTX_S, FSTX_D 等，负责从内存中读取数据到寄存器，或将寄存器中的数据写入内存。这些指令支持不同大小的数据 (字节、半字、字、双字)。
* **原子操作指令 (Atomic Operations):** 例如 AMSWAP_W, AMSWAP_D, AMADD_W, AMADD_D, AMAND_W, AMAND_D, AMOR_W, AMOR_D, AMXOR_W, AMXOR_D 等，用于在多线程或多进程环境中安全地修改共享内存。
* **类型转换指令 (Type Conversion):** 例如 FCVT_S_D, FCVT_D_S，在单精度和双精度浮点数之间进行转换。 FTINTRM_W_S, FTINTRM_W_D 等将浮点数转换为整数。
* **位操作指令 (Bit Manipulation):** 例如 CLZ_W, CTZ_W, CLZ_D, CTZ_D (计算前导零和尾随零), REVB (字节序反转), BITREV (位反转), EXT (符号扩展)。
* **浮点寄存器和通用寄存器之间的数据传输指令 (Move between General and Floating-Point Registers):** 例如 MOVGR2FR_W, MOVGR2FR_D, MOVFR2GR_S, MOVFR2GR_D。
* **浮点控制状态寄存器 (FCSR) 相关指令:** 例如 MOVGR2FCSR, MOVFCSR2GR，用于读写浮点处理器的控制和状态信息。
* **杂项指令:** 例如 BREAK (触发软件中断), DBAR (数据屏障)。

**与 Javascript 的关系 (通过 V8):**

V8 是 Google 开发的 JavaScript 引擎，用于 Chrome 浏览器和 Node.js 等环境。这个 `simulator-loong64.cc` 文件是 V8 引擎的一部分，它的作用是 **在非 LoongArch64 架构的机器上模拟 LoongArch64 的指令执行**。

当 V8 需要在不支持 LoongArch64 指令集的平台上运行 JavaScript 代码时，它会将 JavaScript 代码编译成 LoongArch64 的机器码（或者更准确地说，是 V8 的中间表示，然后由模拟器执行）。然后，这个模拟器（`simulator-loong64.cc` 中的代码）会逐条解释和执行这些 LoongArch64 指令。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // 输出 15
```

**模拟器的工作方式 (简化说明):**

1. 当 V8 执行 `add(5, 10)` 时，它可能会将这个加法操作编译成类似 LoongArch64 的 `ADD_W` 指令（假设操作数是 32 位整数）。
2. `simulator-loong64.cc` 中的代码会接收到这个 `ADD_W` 指令，并提取出操作数和目标寄存器等信息。
3. 它会读取模拟的 LoongArch64 寄存器中存储的 `a` 和 `b` 的值 (5 和 10)。
4. 它会执行加法操作 `5 + 10`。
5. 它会将结果 (15) 写入模拟的目标寄存器中。

**这部分代码的功能总结:**

总而言之，这部分 `simulator-loong64.cc` 代码是 V8 引擎在非 LoongArch64 平台上运行 JavaScript 代码的关键组成部分。它通过软件模拟的方式，实现了 LoongArch64 架构指令的执行，使得 V8 能够在更广泛的硬件上运行。

请注意，这只是第 3 部分，可能还有其他部分负责指令的获取、解码、分支预测、异常处理等功能。

### 提示词
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
e(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      int32_t alu32_out = static_cast<int32_t>(rj() + rk());
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      break;
    }
    case ADD_D:
      printf_instr("ADD_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() + rk());
      break;
    case SUB_W: {
      printf_instr("SUB_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      int32_t alu32_out = static_cast<int32_t>(rj() - rk());
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      break;
    }
    case SUB_D:
      printf_instr("SUB_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() - rk());
      break;
    case SLT:
      printf_instr("SLT\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() < rk() ? 1 : 0);
      break;
    case SLTU:
      printf_instr("SLTU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj_u() < rk_u() ? 1 : 0);
      break;
    case MASKEQZ:
      printf_instr("MASKEQZ\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rk() == 0 ? 0 : rj());
      break;
    case MASKNEZ:
      printf_instr("MASKNEZ\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rk() != 0 ? 0 : rj());
      break;
    case NOR:
      printf_instr("NOR\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), ~(rj() | rk()));
      break;
    case AND:
      printf_instr("AND\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() & rk());
      break;
    case OR:
      printf_instr("OR\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() | rk());
      break;
    case XOR:
      printf_instr("XOR\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() ^ rk());
      break;
    case ORN:
      printf_instr("ORN\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() | (~rk()));
      break;
    case ANDN:
      printf_instr("ANDN\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() & (~rk()));
      break;
    case SLL_W:
      printf_instr("SLL_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), (int32_t)rj() << (rk_u() % 32));
      break;
    case SRL_W: {
      printf_instr("SRL_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      alu_out = static_cast<int32_t>((uint32_t)rj_u() >> (rk_u() % 32));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case SRA_W:
      printf_instr("SRA_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), (int32_t)rj() >> (rk_u() % 32));
      break;
    case SLL_D:
      printf_instr("SLL_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() << (rk_u() % 64));
      break;
    case SRL_D: {
      printf_instr("SRL_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      alu_out = static_cast<int64_t>(rj_u() >> (rk_u() % 64));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case SRA_D:
      printf_instr("SRA_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() >> (rk_u() % 64));
      break;
    case ROTR_W: {
      printf_instr("ROTR_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      alu_out = static_cast<int32_t>(
          base::bits::RotateRight32(static_cast<const uint32_t>(rj_u()),
                                    static_cast<const uint32_t>(rk_u() % 32)));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case ROTR_D: {
      printf_instr("ROTR_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      alu_out = static_cast<int64_t>(
          base::bits::RotateRight64((rj_u()), (rk_u() % 64)));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case MUL_W: {
      printf_instr("MUL_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      alu_out = static_cast<int32_t>(rj()) * static_cast<int32_t>(rk());
      SetResult(rd_reg(), alu_out);
      break;
    }
    case MULH_W: {
      printf_instr("MULH_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      int32_t rj_lo = static_cast<int32_t>(rj());
      int32_t rk_lo = static_cast<int32_t>(rk());
      alu_out = static_cast<int64_t>(rj_lo) * static_cast<int64_t>(rk_lo);
      SetResult(rd_reg(), alu_out >> 32);
      break;
    }
    case MULH_WU: {
      printf_instr("MULH_WU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      uint32_t rj_lo = static_cast<uint32_t>(rj_u());
      uint32_t rk_lo = static_cast<uint32_t>(rk_u());
      alu_out = static_cast<uint64_t>(rj_lo) * static_cast<uint64_t>(rk_lo);
      SetResult(rd_reg(), alu_out >> 32);
      break;
    }
    case MUL_D:
      printf_instr("MUL_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), rj() * rk());
      break;
    case MULH_D:
      printf_instr("MULH_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), base::bits::SignedMulHigh64(rj(), rk()));
      break;
    case MULH_DU:
      printf_instr("MULH_DU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      SetResult(rd_reg(), base::bits::UnsignedMulHigh64(rj_u(), rk_u()));
      break;
    case MULW_D_W: {
      printf_instr("MULW_D_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      int64_t rj_i32 = static_cast<int32_t>(rj());
      int64_t rk_i32 = static_cast<int32_t>(rk());
      SetResult(rd_reg(), rj_i32 * rk_i32);
      break;
    }
    case MULW_D_WU: {
      printf_instr("MULW_D_WU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      uint64_t rj_u32 = static_cast<uint32_t>(rj_u());
      uint64_t rk_u32 = static_cast<uint32_t>(rk_u());
      SetResult(rd_reg(), rj_u32 * rk_u32);
      break;
    }
    case DIV_W: {
      printf_instr("DIV_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      int32_t rj_i32 = static_cast<int32_t>(rj());
      int32_t rk_i32 = static_cast<int32_t>(rk());
      if (rj_i32 == INT_MIN && rk_i32 == -1) {
        SetResult(rd_reg(), INT_MIN);
      } else if (rk_i32 != 0) {
        SetResult(rd_reg(), rj_i32 / rk_i32);
      }
      break;
    }
    case MOD_W: {
      printf_instr("MOD_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      int32_t rj_i32 = static_cast<int32_t>(rj());
      int32_t rk_i32 = static_cast<int32_t>(rk());
      if (rj_i32 == INT_MIN && rk_i32 == -1) {
        SetResult(rd_reg(), 0);
      } else if (rk_i32 != 0) {
        SetResult(rd_reg(), rj_i32 % rk_i32);
      }
      break;
    }
    case DIV_WU: {
      printf_instr("DIV_WU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      uint32_t rj_u32 = static_cast<uint32_t>(rj());
      uint32_t rk_u32 = static_cast<uint32_t>(rk());
      if (rk_u32 != 0) {
        SetResult(rd_reg(), static_cast<int32_t>(rj_u32 / rk_u32));
      }
      break;
    }
    case MOD_WU: {
      printf_instr("MOD_WU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      uint32_t rj_u32 = static_cast<uint32_t>(rj());
      uint32_t rk_u32 = static_cast<uint32_t>(rk());
      if (rk_u32 != 0) {
        SetResult(rd_reg(), static_cast<int32_t>(rj_u32 % rk_u32));
      }
      break;
    }
    case DIV_D: {
      printf_instr("DIV_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (rj() == LONG_MIN && rk() == -1) {
        SetResult(rd_reg(), LONG_MIN);
      } else if (rk() != 0) {
        SetResult(rd_reg(), rj() / rk());
      }
      break;
    }
    case MOD_D: {
      printf_instr("MOD_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (rj() == LONG_MIN && rk() == -1) {
        SetResult(rd_reg(), 0);
      } else if (rk() != 0) {
        SetResult(rd_reg(), rj() % rk());
      }
      break;
    }
    case DIV_DU: {
      printf_instr("DIV_DU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (rk_u() != 0) {
        SetResult(rd_reg(), static_cast<int64_t>(rj_u() / rk_u()));
      }
      break;
    }
    case MOD_DU: {
      printf_instr("MOD_DU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (rk_u() != 0) {
        SetResult(rd_reg(), static_cast<int64_t>(rj_u() % rk_u()));
      }
      break;
    }
    case BREAK:
      printf_instr("BREAK\t code: %x\n", instr_.Bits(14, 0));
      SoftwareInterrupt();
      break;
    case FADD_S: {
      printf_instr("FADD_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs + rhs; },
                                 fj_float(), fk_float()));
      break;
    }
    case FADD_D: {
      printf_instr("FADD_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(),
                         FPUCanonalizeOperation(
                             [](double lhs, double rhs) { return lhs + rhs; },
                             fj_double(), fk_double()));
      break;
    }
    case FSUB_S: {
      printf_instr("FSUB_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(fd_reg(), fj_float() - fk_float());
      break;
    }
    case FSUB_D: {
      printf_instr("FSUB_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(), fj_double() - fk_double());
      break;
    }
    case FMUL_S: {
      printf_instr("FMUL_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs * rhs; },
                                 fj_float(), fk_float()));
      break;
    }
    case FMUL_D: {
      printf_instr("FMUL_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(),
                         FPUCanonalizeOperation(
                             [](double lhs, double rhs) { return lhs * rhs; },
                             fj_double(), fk_double()));
      break;
    }
    case FDIV_S: {
      printf_instr("FDIV_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs / rhs; },
                                 fj_float(), fk_float()));
      break;
    }
    case FDIV_D: {
      printf_instr("FDIV_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(),
                         FPUCanonalizeOperation(
                             [](double lhs, double rhs) { return lhs / rhs; },
                             fj_double(), fk_double()));
      break;
    }
    case FMAX_S:
      printf_instr("FMAX_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(fd_reg(), FPUMax(fk_float(), fj_float()));
      break;
    case FMAX_D:
      printf_instr("FMAX_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(), FPUMax(fk_double(), fj_double()));
      break;
    case FMIN_S:
      printf_instr("FMIN_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(fd_reg(), FPUMin(fk_float(), fj_float()));
      break;
    case FMIN_D:
      printf_instr("FMIN_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(), FPUMin(fk_double(), fj_double()));
      break;
    case FMAXA_S:
      printf_instr("FMAXA_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(fd_reg(), FPUMaxA(fk_float(), fj_float()));
      break;
    case FMAXA_D:
      printf_instr("FMAXA_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(), FPUMaxA(fk_double(), fj_double()));
      break;
    case FMINA_S:
      printf_instr("FMINA_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(fd_reg(), FPUMinA(fk_float(), fj_float()));
      break;
    case FMINA_D:
      printf_instr("FMINA_D\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(), FPUMinA(fk_double(), fj_double()));
      break;
    case LDX_B:
      printf_instr("LDX_B\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int8_t))) return;
      set_register(rd_reg(), ReadB(rj() + rk()));
      break;
    case LDX_H:
      printf_instr("LDX_H\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int16_t))) return;
      set_register(rd_reg(), ReadH(rj() + rk(), instr_.instr()));
      break;
    case LDX_W:
      printf_instr("LDX_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int32_t))) return;
      set_register(rd_reg(), ReadW(rj() + rk(), instr_.instr()));
      break;
    case LDX_D:
      printf_instr("LDX_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int64_t))) return;
      set_register(rd_reg(), Read2W(rj() + rk(), instr_.instr()));
      break;
    case STX_B:
      printf_instr("STX_B\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int8_t))) return;
      WriteB(rj() + rk(), static_cast<int8_t>(rd()));
      break;
    case STX_H:
      printf_instr("STX_H\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int16_t))) return;
      WriteH(rj() + rk(), static_cast<int16_t>(rd()), instr_.instr());
      break;
    case STX_W:
      printf_instr("STX_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int32_t))) return;
      WriteW(rj() + rk(), static_cast<int32_t>(rd()), instr_.instr());
      break;
    case STX_D:
      printf_instr("STX_D\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(int64_t))) return;
      Write2W(rj() + rk(), rd(), instr_.instr());
      break;
    case LDX_BU:
      printf_instr("LDX_BU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(uint8_t))) return;
      set_register(rd_reg(), ReadBU(rj() + rk()));
      break;
    case LDX_HU:
      printf_instr("LDX_HU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(uint16_t))) return;
      set_register(rd_reg(), ReadHU(rj() + rk(), instr_.instr()));
      break;
    case LDX_WU:
      printf_instr("LDX_WU\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk());
      if (!ProbeMemory(rj() + rk(), sizeof(uint32_t))) return;
      set_register(rd_reg(), ReadWU(rj() + rk(), instr_.instr()));
      break;
    case FLDX_S:
      printf_instr("FLDX_S\t %s: %016f, %s: %016lx, %s: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   Registers::Name(rj_reg()), rj(), Registers::Name(rk_reg()),
                   rk());
      if (!ProbeMemory(rj() + rk(), sizeof(float))) return;
      set_fpu_register(fd_reg(), kFPUInvalidResult);  // Trash upper 32 bits.
      set_fpu_register_word(fd_reg(),
                            ReadW(rj() + rk(), instr_.instr(), FLOAT_DOUBLE));
      break;
    case FLDX_D:
      printf_instr("FLDX_D\t %s: %016f, %s: %016lx, %s: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj(), Registers::Name(rk_reg()),
                   rk());
      if (!ProbeMemory(rj() + rk(), sizeof(double))) return;
      set_fpu_register_double(fd_reg(), ReadD(rj() + rk(), instr_.instr()));
      break;
    case FSTX_S:
      printf_instr("FSTX_S\t %s: %016f, %s: %016lx, %s: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   Registers::Name(rj_reg()), rj(), Registers::Name(rk_reg()),
                   rk());
      if (!ProbeMemory(rj() + rk(), sizeof(float))) return;
      WriteW(rj() + rk(), static_cast<int32_t>(get_fpu_register(fd_reg())),
             instr_.instr());
      break;
    case FSTX_D:
      printf_instr("FSTX_D\t %s: %016f, %s: %016lx, %s: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj(), Registers::Name(rk_reg()),
                   rk());
      if (!ProbeMemory(rj() + rk(), sizeof(double))) return;
      WriteD(rj() + rk(), get_fpu_register_double(fd_reg()), instr_.instr());
      break;
    case AMSWAP_W:
      printf("Sim UNIMPLEMENTED: AMSWAP_W\n");
      UNIMPLEMENTED();
    case AMSWAP_D:
      printf("Sim UNIMPLEMENTED: AMSWAP_D\n");
      UNIMPLEMENTED();
    case AMADD_W:
      printf("Sim UNIMPLEMENTED: AMADD_W\n");
      UNIMPLEMENTED();
    case AMADD_D:
      printf("Sim UNIMPLEMENTED: AMADD_D\n");
      UNIMPLEMENTED();
    case AMAND_W:
      printf("Sim UNIMPLEMENTED: AMAND_W\n");
      UNIMPLEMENTED();
    case AMAND_D:
      printf("Sim UNIMPLEMENTED: AMAND_D\n");
      UNIMPLEMENTED();
    case AMOR_W:
      printf("Sim UNIMPLEMENTED: AMOR_W\n");
      UNIMPLEMENTED();
    case AMOR_D:
      printf("Sim UNIMPLEMENTED: AMOR_D\n");
      UNIMPLEMENTED();
    case AMXOR_W:
      printf("Sim UNIMPLEMENTED: AMXOR_W\n");
      UNIMPLEMENTED();
    case AMXOR_D:
      printf("Sim UNIMPLEMENTED: AMXOR_D\n");
      UNIMPLEMENTED();
    case AMMAX_W:
      printf("Sim UNIMPLEMENTED: AMMAX_W\n");
      UNIMPLEMENTED();
    case AMMAX_D:
      printf("Sim UNIMPLEMENTED: AMMAX_D\n");
      UNIMPLEMENTED();
    case AMMIN_W:
      printf("Sim UNIMPLEMENTED: AMMIN_W\n");
      UNIMPLEMENTED();
    case AMMIN_D:
      printf("Sim UNIMPLEMENTED: AMMIN_D\n");
      UNIMPLEMENTED();
    case AMMAX_WU:
      printf("Sim UNIMPLEMENTED: AMMAX_WU\n");
      UNIMPLEMENTED();
    case AMMAX_DU:
      printf("Sim UNIMPLEMENTED: AMMAX_DU\n");
      UNIMPLEMENTED();
    case AMMIN_WU:
      printf("Sim UNIMPLEMENTED: AMMIN_WU\n");
      UNIMPLEMENTED();
    case AMMIN_DU:
      printf("Sim UNIMPLEMENTED: AMMIN_DU\n");
      UNIMPLEMENTED();
    case AMSWAP_DB_W: {
      printf_instr("AMSWAP_DB_W:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int32_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), ReadW(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditionalW(rj(), static_cast<int32_t>(rk()), instr_.instr(),
                          &success);
      } while (!success);
    } break;
    case AMSWAP_DB_D: {
      printf_instr("AMSWAP_DB_D:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int64_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), Read2W(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditional2W(rj(), rk(), instr_.instr(), &success);
      } while (!success);
    } break;
    case AMADD_DB_W: {
      printf_instr("AMADD_DB_W:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int32_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), ReadW(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditionalW(rj(),
                          static_cast<int32_t>(static_cast<int32_t>(rk()) +
                                               static_cast<int32_t>(rd())),
                          instr_.instr(), &success);
      } while (!success);
    } break;
    case AMADD_DB_D: {
      printf_instr("AMADD_DB_D:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int64_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), Read2W(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditional2W(rj(), rk() + rd(), instr_.instr(), &success);
      } while (!success);
    } break;
    case AMAND_DB_W: {
      printf_instr("AMAND_DB_W:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int32_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), ReadW(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditionalW(rj(),
                          static_cast<int32_t>(static_cast<int32_t>(rk()) &
                                               static_cast<int32_t>(rd())),
                          instr_.instr(), &success);
      } while (!success);
    } break;
    case AMAND_DB_D: {
      printf_instr("AMAND_DB_D:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int64_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), Read2W(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditional2W(rj(), rk() & rd(), instr_.instr(), &success);
      } while (!success);
    } break;
    case AMOR_DB_W: {
      printf_instr("AMOR_DB_W:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int32_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), ReadW(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditionalW(rj(),
                          static_cast<int32_t>(static_cast<int32_t>(rk()) |
                                               static_cast<int32_t>(rd())),
                          instr_.instr(), &success);
      } while (!success);
    } break;
    case AMOR_DB_D: {
      printf_instr("AMOR_DB_D:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int64_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), Read2W(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditional2W(rj(), rk() | rd(), instr_.instr(), &success);
      } while (!success);
    } break;
    case AMXOR_DB_W: {
      printf_instr("AMXOR_DB_W:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int32_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), ReadW(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditionalW(rj(),
                          static_cast<int32_t>(static_cast<int32_t>(rk()) ^
                                               static_cast<int32_t>(rd())),
                          instr_.instr(), &success);
      } while (!success);
    } break;
    case AMXOR_DB_D: {
      printf_instr("AMXOR_DB_D:\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rk_reg()),
                   rk(), Registers::Name(rj_reg()), rj());
      if (!ProbeMemory(rj(), sizeof(int64_t))) return;
      int32_t success = 0;
      do {
        {
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          set_register(rd_reg(), Read2W(rj(), instr_.instr()));
          local_monitor_.NotifyLoadLinked(rj(), TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              rj(), &global_monitor_thread_);
        }
        WriteConditional2W(rj(), rk() ^ rd(), instr_.instr(), &success);
      } while (!success);
    } break;
    case AMMAX_DB_W:
      printf("Sim UNIMPLEMENTED: AMMAX_DB_W\n");
      UNIMPLEMENTED();
    case AMMAX_DB_D:
      printf("Sim UNIMPLEMENTED: AMMAX_DB_D\n");
      UNIMPLEMENTED();
    case AMMIN_DB_W:
      printf("Sim UNIMPLEMENTED: AMMIN_DB_W\n");
      UNIMPLEMENTED();
    case AMMIN_DB_D:
      printf("Sim UNIMPLEMENTED: AMMIN_DB_D\n");
      UNIMPLEMENTED();
    case AMMAX_DB_WU:
      printf("Sim UNIMPLEMENTED: AMMAX_DB_WU\n");
      UNIMPLEMENTED();
    case AMMAX_DB_DU:
      printf("Sim UNIMPLEMENTED: AMMAX_DB_DU\n");
      UNIMPLEMENTED();
    case AMMIN_DB_WU:
      printf("Sim UNIMPLEMENTED: AMMIN_DB_WU\n");
      UNIMPLEMENTED();
    case AMMIN_DB_DU:
      printf("Sim UNIMPLEMENTED: AMMIN_DB_DU\n");
      UNIMPLEMENTED();
    case DBAR:
      printf_instr("DBAR\n");
      break;
    case IBAR:
      printf("Sim UNIMPLEMENTED: IBAR\n");
      UNIMPLEMENTED();
    case FSCALEB_S:
      printf("Sim UNIMPLEMENTED: FSCALEB_S\n");
      UNIMPLEMENTED();
    case FSCALEB_D:
      printf("Sim UNIMPLEMENTED: FSCALEB_D\n");
      UNIMPLEMENTED();
    case FCOPYSIGN_S: {
      printf_instr("FCOPYSIGN_S\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float(),
                   FPURegisters::Name(fk_reg()), fk_float());
      SetFPUFloatResult(fd_reg(), std::copysign(fj_float(), fk_float()));
    } break;
    case FCOPYSIGN_D: {
      printf_instr("FCOPYSIGN_d\t %s: %016f, %s, %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      SetFPUDoubleResult(fd_reg(), std::copysign(fj_double(), fk_double()));
    } break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp22() {
  int64_t alu_out;

  switch (instr_.Bits(31, 10) << 10) {
    case CLZ_W: {
      printf_instr("CLZ_W\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      alu_out = base::bits::CountLeadingZeros32(static_cast<int32_t>(rj_u()));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case CTZ_W: {
      printf_instr("CTZ_W\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      alu_out = base::bits::CountTrailingZeros32(static_cast<int32_t>(rj_u()));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case CLZ_D: {
      printf_instr("CLZ_D\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      alu_out = base::bits::CountLeadingZeros64(static_cast<int64_t>(rj_u()));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case CTZ_D: {
      printf_instr("CTZ_D\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      alu_out = base::bits::CountTrailingZeros64(static_cast<int64_t>(rj_u()));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case REVB_2H: {
      printf_instr("REVB_2H\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint32_t input = static_cast<uint32_t>(rj());
      uint64_t output = 0;

      uint32_t mask = 0xFF000000;
      for (int i = 0; i < 4; i++) {
        uint32_t tmp = mask & input;
        if (i % 2 == 0) {
          tmp = tmp >> 8;
        } else {
          tmp = tmp << 8;
        }
        output = output | tmp;
        mask = mask >> 8;
      }

      alu_out = static_cast<int64_t>(static_cast<int32_t>(output));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case REVB_4H: {
      printf_instr("REVB_4H\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint64_t input = rj_u();
      uint64_t output = 0;

      uint64_t mask = 0xFF00000000000000;
      for (int i = 0; i < 8; i++) {
        uint64_t tmp = mask & input;
        if (i % 2 == 0) {
          tmp = tmp >> 8;
        } else {
          tmp = tmp << 8;
        }
        output = output | tmp;
        mask = mask >> 8;
      }

      alu_out = static_cast<int64_t>(output);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case REVB_2W: {
      printf_instr("REVB_2W\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint64_t input = rj_u();
      uint64_t output = 0;

      uint64_t mask = 0xFF000000FF000000;
      for (int i = 0; i < 4; i++) {
        uint64_t tmp = mask & input;
        if (i <= 1) {
          tmp = tmp >> (24 - i * 16);
        } else {
          tmp = tmp << (i * 16 - 24);
        }
        output = output | tmp;
        mask = mask >> 8;
      }

      alu_out = static_cast<int64_t>(output);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case REVB_D: {
      printf_instr("REVB_D\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint64_t input = rj_u();
      uint64_t output = 0;

      uint64_t mask = 0xFF00000000000000;
      for (int i = 0; i < 8; i++) {
        uint64_t tmp = mask & input;
        if (i <= 3) {
          tmp = tmp >> (56 - i * 16);
        } else {
          tmp = tmp << (i * 16 - 56);
        }
        output = output | tmp;
        mask = mask >> 8;
      }

      alu_out = static_cast<int64_t>(output);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case REVH_2W: {
      printf_instr("REVH_2W\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint64_t input = rj_u();
      uint64_t output = 0;

      uint64_t mask = 0xFFFF000000000000;
      for (int i = 0; i < 4; i++) {
        uint64_t tmp = mask & input;
        if (i % 2 == 0) {
          tmp = tmp >> 16;
        } else {
          tmp = tmp << 16;
        }
        output = output | tmp;
        mask = mask >> 16;
      }

      alu_out = static_cast<int64_t>(output);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case REVH_D: {
      printf_instr("REVH_D\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint64_t input = rj_u();
      uint64_t output = 0;

      uint64_t mask = 0xFFFF000000000000;
      for (int i = 0; i < 4; i++) {
        uint64_t tmp = mask & input;
        if (i <= 1) {
          tmp = tmp >> (48 - i * 32);
        } else {
          tmp = tmp << (i * 32 - 48);
        }
        output = output | tmp;
        mask = mask >> 16;
      }

      alu_out = static_cast<int64_t>(output);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case BITREV_4B: {
      printf_instr("BITREV_4B\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint32_t input = static_cast<uint32_t>(rj());
      uint32_t output = 0;
      uint8_t i_byte, o_byte;

      // Reverse the bit in byte for each individual byte
      for (int i = 0; i < 4; i++) {
        output = output >> 8;
        i_byte = input & 0xFF;

        // Fast way to reverse bits in byte
        // Devised by Sean Anderson, July 13, 2001
        o_byte = static_cast<uint8_t>(((i_byte * 0x0802LU & 0x22110LU) |
                                       (i_byte * 0x8020LU & 0x88440LU)) *
                                          0x10101LU >>
                                      16);

        output = output | (static_cast<uint32_t>(o_byte << 24));
        input = input >> 8;
      }

      alu_out = static_cast<int64_t>(static_cast<int32_t>(output));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case BITREV_8B: {
      printf_instr("BITREV_8B\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint64_t input = rj_u();
      uint64_t output = 0;
      uint8_t i_byte, o_byte;

      // Reverse the bit in byte for each individual byte
      for (int i = 0; i < 8; i++) {
        output = output >> 8;
        i_byte = input & 0xFF;

        // Fast way to reverse bits in byte
        // Devised by Sean Anderson, July 13, 2001
        o_byte = static_cast<uint8_t>(((i_byte * 0x0802LU & 0x22110LU) |
                                       (i_byte * 0x8020LU & 0x88440LU)) *
                                          0x10101LU >>
                                      16);

        output = output | (static_cast<uint64_t>(o_byte) << 56);
        input = input >> 8;
      }

      alu_out = static_cast<int64_t>(output);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case BITREV_W: {
      printf_instr("BITREV_W\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint32_t input = static_cast<uint32_t>(rj());
      uint32_t output = 0;
      output = base::bits::ReverseBits(input);
      alu_out = static_cast<int64_t>(static_cast<int32_t>(output));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case BITREV_D: {
      printf_instr("BITREV_D\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      alu_out = static_cast<int64_t>(base::bits::ReverseBits(rj_u()));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case EXT_W_B: {
      printf_instr("EXT_W_B\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint8_t input = static_cast<uint8_t>(rj());
      alu_out = static_cast<int64_t>(static_cast<int8_t>(input));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case EXT_W_H: {
      printf_instr("EXT_W_H\t %s: %016lx, %s, %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj());
      uint16_t input = static_cast<uint16_t>(rj());
      alu_out = static_cast<int64_t>(static_cast<int16_t>(input));
      SetResult(rd_reg(), alu_out);
      break;
    }
    case FABS_S:
      printf_instr("FABS_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(), std::abs(fj_float()));
      break;
    case FABS_D:
      printf_instr("FABS_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUDoubleResult(fd_reg(), std::abs(fj_double()));
      break;
    case FNEG_S:
      printf_instr("FNEG_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(), -fj_float());
      break;
    case FNEG_D:
      printf_instr("FNEG_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUDoubleResult(fd_reg(), -fj_double());
      break;
    case FSQRT_S: {
      printf_instr("FSQRT_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      if (fj_float() >= 0) {
        SetFPUFloatResult(fd_reg(), std::sqrt(fj_float()));
        set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
      } else {
        SetFPUFloatResult(fd_reg(), std::sqrt(-1));  // qnan
        set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
      }
      break;
    }
    case FSQRT_D: {
      printf_instr("FSQRT_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      if (fj_double() >= 0) {
        SetFPUDoubleResult(fd_reg(), std::sqrt(fj_double()));
        set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
      } else {
        SetFPUDoubleResult(fd_reg(), std::sqrt(-1));  // qnan
        set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
      }
      break;
    }
    case FMOV_S:
      printf_instr("FMOV_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(), fj_float());
      break;
    case FMOV_D:
      printf_instr("FMOV_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUDoubleResult(fd_reg(), fj_double());
      break;
    case MOVGR2FR_W: {
      printf_instr("MOVGR2FR_W\t %s: %016f, %s, %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj());
      set_fpu_register_word(fd_reg(), static_cast<int32_t>(rj()));
      TraceRegWr(get_fpu_register(fd_reg()), FLOAT_DOUBLE);
      break;
    }
    case MOVGR2FR_D:
      printf_instr("MOVGR2FR_D\t %s: %016f, %s, %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj());
      SetFPUResult2(fd_reg(), rj());
      break;
    case MOVGR2FRH_W: {
      printf_instr("MOVGR2FRH_W\t %s: %016f, %s, %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj());
      set_fpu_register_hi_word(fd_reg(), static_cast<int32_t>(rj()));
      TraceRegWr(get_fpu_register(fd_reg()), DOUBLE);
      break;
    }
    case MOVFR2GR_S: {
      printf_instr("MOVFR2GR_S\t %s: %016lx, %s, %016f\n",
                   Registers::Name(rd_reg()), rd(),
                   FPURegisters::Name(fj_reg()), fj_float());
      set_register(rd_reg(),
                   static_cast<int64_t>(get_fpu_register_word(fj_reg())));
      TraceRegWr(get_register(rd_reg()), WORD_DWORD);
      break;
    }
    case MOVFR2GR_D:
      printf_instr("MOVFR2GR_D\t %s: %016lx, %s, %016f\n",
                   Registers::Name(rd_reg()), rd(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetResult(rd_reg(), get_fpu_register(fj_reg()));
      break;
    case MOVFRH2GR_S:
      printf_instr("MOVFRH2GR_S\t %s: %016lx, %s, %016f\n",
                   Registers::Name(rd_reg()), rd(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetResult(rd_reg(), get_fpu_register_hi_word(fj_reg()));
      break;
    case MOVGR2FCSR: {
      printf_instr("MOVGR2FCSR\t fcsr: %016x, %s, %016lx\n", FCSR_,
                   Registers::Name(rj_reg()), rj());
      // fcsr could be 0-3
      CHECK_LT(rd_reg(), 4);
      FCSR_ = static_cast<uint32_t>(rj());
      TraceRegWr(FCSR_);
      break;
    }
    case MOVFCSR2GR: {
      printf_instr("MOVFCSR2GR\t %s, %016lx, FCSR: %016x\n",
                   Registers::Name(rd_reg()), rd(), FCSR_);
      // fcsr could be 0-3
      CHECK_LT(rj_reg(), 4);
      SetResult(rd_reg(), FCSR_);
      break;
    }
    case FCVT_S_D:
      printf_instr("FCVT_S_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUFloatResult(fd_reg(), static_cast<float>(fj_double()));
      break;
    case FCVT_D_S:
      printf_instr("FCVT_D_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUDoubleResult(fd_reg(), static_cast<double>(fj_float()));
      break;
    case FTINTRM_W_S: {
      printf_instr("FTINTRM_W_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = floor(fj);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_word_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRM_W_D: {
      printf_instr("FTINTRM_W_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = floor(fj);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRM_L_S: {
      printf_instr("FTINTRM_L_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = floor(fj);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRM_L_D: {
      printf_instr("FTINTRM_L_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = floor(fj);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRP_W_S: {
      printf_instr("FTINTRP_W_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = ceil(fj);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_word_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRP_W_D: {
      printf_instr("FTINTRP_W_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = ceil(fj);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRP_L_S: {
      printf_instr("FTINTRP_L_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = ceil(fj);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRP_L_D: {
      printf_instr("FTINTRP_L_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = ceil(fj);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRZ_W_S: {
      printf_instr("FTINTRZ_W_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = trunc(fj);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_word_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRZ_W_D: {
      printf_instr("FTINTRZ_W_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = trunc(fj);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRZ_L_S: {
      printf_instr("FTINTRZ_L_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = trunc(fj);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRZ_L_D: {
      printf_instr("FTINTRZ_L_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = trunc(fj);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRNE_W_S: {
      printf_instr("FTINTRNE_W_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = floor(fj + 0.5);
      int32_t result = static_cast<int32_t>(rounded);
      if ((result & 1) != 0 && result - fj == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_word_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRNE_W_D: {
      printf_instr("FTINTRNE_W_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = floor(fj + 0.5);
      int32_t result = static_cast<int32_t>(rounded);
      if ((result & 1) != 0 && result - fj == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINTRNE_L_S: {
      printf_instr("FTINTRNE_L_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded = floor(fj + 0.5);
      int64_t result = static_cast<int64_t>(rounded);
      if ((result & 1) != 0 && result - fj == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINTRNE_L_D: {
      printf_instr("FTINTRNE_L_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded = floor(fj + 0.5);
      int64_t result = static_cast<int64_t>(rounded);
      if ((result & 1) != 0 && result - fj == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINT_W_S: {
      printf_instr("FTINT_W_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded;
      int32_t result;
      round_according_to_fcsr(fj, &rounded, &result);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_word_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINT_W_D: {
      printf_instr("FTINT_W_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded;
      int32_t result;
      round_according_to_fcsr(fj, &rounded, &result);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fj, rounded)) {
        set_fpu_register_word_invalid_result(fj, rounded);
      }
      break;
    }
    case FTINT_L_S: {
      printf_instr("FTINT_L_S\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float rounded;
      int64_t result;
      round64_according_to_fcsr(fj, &rounded, &result);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FTINT_L_D: {
      printf_instr("FTINT_L_D\t %s: %016f, %s, %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double rounded;
      int64_t result;
      round64_according_to_fcsr(fj, &rounded, &result);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fj, rounded)) {
        set_fpu_register_invalid_result64(fj, rounded);
      }
      break;
    }
    case FFINT_S_W: {
      alu_out = get_fpu_register_signed_word(fj_reg());
      printf_instr("FFINT_S_W\t %s: %016f, %s, %016x\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), static_cast<int>(alu_out));
      SetFPUFloatResult(fd_reg(), static_cast<float>(alu_out));
      break;
    }
    case FFINT_S_L: {
      alu_out = get_fpu_register(fj_reg());
      printf_instr("FFINT_S_L\t %s: %016f, %s, %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), alu_out);
      SetFPUFloatResult(fd_reg(), static_cast<float>(alu_out));
      break;
    }
    case FFINT_D_W: {
      alu_out = get_fpu_register_signed_word(fj_reg());
      printf_instr("FFINT_D_W\t %s: %016f, %s, %016x\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), static_cast<int>(alu_out));
      SetFPUDoubleResult(fd_reg(), static_cast<double>(alu_out));
      break;
    }
    case FFINT_D_L: {
      alu_out = get_fpu_register(fj_reg());
      printf_instr("FFINT_D_L\t %s: %016f, %s, %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), alu_out);
      SetFPUDoubleResult(fd_reg(), static_cast<double>(alu_out));
      break;
    }
    case FRINT_S: {
      printf_instr("FRINT_S\t %s: %016f, %s, %016f mode : ",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      float fj = fj_float();
      float result, temp_result;
      double temp;
      float upper = ceil(fj);
      float lower = floor(fj);
      switch (get_fcsr_rounding_mode()) {
        case kRoundToNearest:
          printf_instr(" kRoundToNearest\n");
          if (upper - fj < fj - lower) {
            result = upper;
          } else if (upper - fj > fj - lower) {
            result = lower;
          } else {
            temp_result = upper / 2;
            float reminder = std::modf(temp_result, &temp);
            if (reminder == 0) {
              result = upper;
            } else {
              result = lower;
            }
          }
          break;
        case kRoundToZero:
          printf_instr(" kRoundToZero\n");
          result = (fj > 0 ? lower : upper);
          break;
        case kRoundToPlusInf:
          printf_instr(" kRoundToPlusInf\n");
          result = upper;
          break;
        case kRoundToMinusInf:
          printf_instr(" kRoundToMinusInf\n");
          result = lower;
          break;
      }
      SetFPUFloatResult(fd_reg(), result);
      set_fcsr_bit(kFCSRInexactCauseBit, result != fj);
      break;
    }
    case FRINT_D: {
      printf_instr("FRINT_D\t %s: %016f, %s, %016f mode : ",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      double fj = fj_double();
      double result, temp, temp_result;
      double upper = ceil(fj);
      double lower = floor(fj);
      switch (get_fcsr_rounding_mode()) {
        case kRoundToNearest:
          printf_instr(" kRoundToNearest\n");
          if (upper - fj < fj - lower) {
            result = upper;
          } else if (upper - fj > fj - lower) {
            result = lower;
          } else {
            temp_result = upper / 2;
            double reminder = std::modf(temp_result, &temp);
            if (reminder == 0)
```