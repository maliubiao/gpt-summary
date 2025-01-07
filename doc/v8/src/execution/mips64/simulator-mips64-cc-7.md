Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a simulator for the MIPS64 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename `simulator-mips64.cc` immediately suggests that this code simulates the behavior of MIPS64 instructions.

2. **Analyze Key Structures and Variables:**
    * Look for major data structures and their roles. The code uses `instr_` (an `Instruction` object), which holds the current instruction being processed.
    * Identify helper functions like `BranchHelper`, `BranchAndLinkHelper`, etc. These indicate different types of instruction execution.
    * Notice the `switch` statements based on `op` and other fields. This implies instruction decoding and dispatch.
    * Observe access to registers (e.g., `get_register`, `set_register`) and memory (`ReadB`, `WriteW`, etc.).

3. **Trace the Flow of Execution:**
    * Start with the `InstructionDecode` function. It takes an `Instruction*` and uses a `switch` based on `InstructionType()`. This shows how different instruction formats are handled.
    * Within each `DecodeType...` function, look for `switch` statements based on opcodes or function codes. This is the core of the instruction simulation.
    * Follow the logic for specific instruction types (e.g., branches, arithmetic, memory access).

4. **Identify Specific Instruction Categories:** The code explicitly handles:
    * **Control flow:** Branch instructions (conditional and unconditional jumps, calls). The helpers like `BranchHelper` are crucial here.
    * **Arithmetic and logical operations:**  Instructions like `ADDIU`, `DADDIU`, `ANDI`, `ORI`, `XORI`, `LUI`, `DAUI`.
    * **Memory access:** Load instructions (`LB`, `LH`, `LW`, `LD`, `LBU`, `LHU`, `LWL`, `LWR`, `LDL`, `LDR`, `LWC1`, `LDC1`) and store instructions (`SB`, `SH`, `SW`, `SD`, `SWL`, `SWR`, `SDL`, `SDR`, `SWC1`, `SDC1`). Pay attention to aligned/unaligned access.
    * **Atomic operations:**  Load-linked (`LL`, `LLD`, `LL_R6`, `LLD_R6`) and store-conditional (`SC`, `SCD`, `SC_R6`, `SCD_R6`).
    * **Floating-point operations:** Instructions involving `COP1` (coprocessor 1).
    * **MSA (MIPS SIMD Architecture) instructions:** The `MSA` case with its `DecodeTypeMsa...` functions indicates support for SIMD operations.
    * **PC-relative addressing:** Instructions within the `PCREL` case.

5. **Look for Simulator-Specific Features:**
    * The `Execute` function contains the main simulation loop.
    * `CallInternal` and `CallImpl` are used for simulating function calls.
    * The `LocalMonitor` and `GlobalMonitor` classes suggest support for simulating memory access synchronization (for atomic operations).
    * The handling of branch delay slots is explicitly mentioned.

6. **Address the Specific Questions:**
    * **Functionality:** Summarize the ability to interpret and execute MIPS64 instructions.
    * **`.tq` extension:**  State that this file is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:** Explain that simulators are used to test JavaScript engine behavior on different architectures. Provide a simple JavaScript example that might rely on these low-level instructions.
    * **Code Logic and I/O:**  Illustrate a simple instruction (like `ADDIU`) with input and output registers.
    * **Common Programming Errors:** Provide examples of errors related to memory access (alignment, out-of-bounds) that the simulator might help catch.

7. **Context of Part 8/9:** Acknowledge the part number and infer that this section likely deals with the core instruction execution logic, building upon earlier setup and leading to finalization.

8. **Refine and Organize:**  Structure the summary logically with clear headings for each aspect of the functionality and the user's questions. Use precise language and avoid jargon where possible.
这是目录为 `v8/src/execution/mips64/simulator-mips64.cc` 的一个 V8 源代码文件，它主要的功能是 **模拟 MIPS64 架构的 CPU 指令执行**。

根据你提供的信息：

* **功能列举:**
    * **指令解码:**  代码包含了各种 MIPS64 指令的解码逻辑，例如：
        * **COP1:** 协处理器指令，用于浮点运算和 MSA (MIPS SIMD Architecture) 指令。
        * **REGIMM:** 寄存器立即数指令，用于条件分支。
        * **分支指令 (BEQ, BNE, BLEZ, BGTZ 等):**  模拟条件和无条件分支，包括紧凑型分支指令 (针对 MIPS64r6)。
        * **算术指令 (ADDIU, DADDIU, SLTI, SLTIU, ANDI, ORI, XORI, LUI, DAUI):**  模拟整数算术和逻辑运算。
        * **内存访问指令 (LB, LH, LW, LD, LBU, LHU, LWL, LWR, LDL, LDR, SB, SH, SW, SD, SWL, SWR, SDL, SDR):**  模拟从内存读取和写入数据。
        * **原子操作指令 (LL, SC, LLD, SCD, LL_R6, LLD_R6, SC_R6, SCD_R6):** 模拟加载链接和条件存储，用于实现并发控制。
        * **PC 相对寻址指令 (PCREL, ALUIPC, AUIPC, LDPC, LWUPC, LWPC, ADDIUPC):** 模拟基于程序计数器的寻址方式。
        * **MSA 指令:**  通过 `DecodeTypeMsaI8`, `DecodeTypeMsaI5` 等函数处理 MIPS SIMD 架构的指令。
    * **寄存器管理:**  模拟 MIPS64 的通用寄存器和浮点寄存器的读写操作。
    * **程序计数器 (PC) 管理:**  控制指令执行的顺序，处理分支和跳转。
    * **内存访问模拟:**  提供 `ReadB`, `ReadW`, `Read2W`, `WriteB`, `WriteW`, `Write2W` 等函数来模拟内存的读取和写入。
    * **分支延迟槽处理:**  MIPS 架构的特性，在分支指令后执行一条延迟槽指令。代码中可以看到对延迟槽的处理。
    * **函数调用模拟:**  `CallInternal` 和 `CallImpl` 函数用于模拟函数调用，包括参数传递和栈帧管理。
    * **本地和全局监控器 (LocalMonitor, GlobalMonitor):** 用于模拟原子操作的正确性，跟踪加载链接的状态。
    * **调试支持:**  可能包含一些用于调试模拟器的功能（尽管这段代码中没有直接体现）。

* **关于 `.tq` 结尾:** 你的描述是正确的，如果文件以 `.tq` 结尾，那将是 V8 Torque 源代码。由于这个文件是 `.cc` 结尾，所以它是 **C++ 源代码**。

* **与 JavaScript 的关系及示例:**
    这个模拟器是 V8 引擎的一部分，用于在 **没有实际 MIPS64 硬件** 的环境下 **测试和调试** V8 的 MIPS64 代码生成器（compiler）。当 V8 需要在 MIPS64 架构上运行时，它会将 JavaScript 代码编译成 MIPS64 汇编指令。这个模拟器可以执行这些编译后的指令，验证代码的正确性。

    **JavaScript 示例:**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    let result = add(5, 10);
    console.log(result); // 输出 15
    ```

    当 V8 编译这段 JavaScript 代码并在 MIPS64 架构上执行时，`add` 函数中的加法操作最终会被翻译成类似 MIPS64 的 `ADDU` 或 `DADDU` 指令。这个 `simulator-mips64.cc` 文件中的代码就能模拟这些指令的执行，计算出 `5 + 10` 的结果。

* **代码逻辑推理 (假设输入与输出):**

    **假设输入:**  一个表示 MIPS64 `ADDIU` 指令的 `instr_` 对象，其内容为：
    * `rt_reg` (目标寄存器): 5
    * `rs_reg` (源寄存器): 3，假设寄存器 3 的值为 20
    * `se_imm16` (带符号立即数): 15

    **代码段:**

    ```c++
    case ADDIU: {
      int32_t alu32_out = static_cast<int32_t>(rs + se_imm16);
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      break;
    }
    ```

    **推理过程:**
    1. `rs` 的值从寄存器 3 获取，为 20。
    2. `se_imm16` 的值为 15。
    3. `alu32_out` 计算为 `20 + 15 = 35`。
    4. `alu32_out` 被符号扩展为 64 位整数。
    5. 结果 `35` 被写入目标寄存器 5。

    **输出:** 寄存器 5 的值变为 35。

* **用户常见的编程错误举例:**

    * **内存对齐错误:** MIPS64 对某些数据类型的内存访问有对齐要求。例如，访问一个 word (4 字节) 必须在 4 字节的边界上。如果 JavaScript 代码导致了未对齐的内存访问，模拟器可能会触发错误。

      ```javascript
      // 假设 arr 是一个 Uint8Array
      let arr = new Uint8Array(8);
      let view = new DataView(arr.buffer);

      // 尝试从地址 1 读取一个 32 位整数 (未对齐)
      // 这在真实的 MIPS64 硬件上可能会导致异常
      let value = view.getInt32(1);
      ```

      在模拟器中，相关的 `ReadW` 或 `WriteW` 函数可能会检测到未对齐的访问并报告错误。

    * **整数溢出/下溢:**  在进行算术运算时，如果结果超出整数类型的范围，可能会导致溢出或下溢。

      ```javascript
      let maxInt = 2147483647;
      let result = maxInt + 1; // 应该溢出

      // 或者

      let minInt = -2147483648;
      result = minInt - 1; // 应该下溢
      ```

      虽然 JavaScript 的数字类型是双精度浮点数，但在编译为 MIPS64 指令后，可能会涉及到 32 位或 64 位整数运算。模拟器可以帮助验证 V8 在处理这些情况时的行为是否符合预期。

* **第 8 部分功能归纳:**

    作为 9 个部分中的第 8 部分，这个文件很可能是 **模拟器核心执行循环和指令解码/执行逻辑** 的主要组成部分。它接收解码后的指令，根据指令类型和操作码执行相应的模拟操作，更新模拟的 CPU 状态（寄存器、PC 等），并模拟内存访问。 可以推测，前面的部分可能负责模拟器的初始化和环境设置，而后面的部分可能涉及更高级的模拟功能或测试框架。

总而言之，`v8/src/execution/mips64/simulator-mips64.cc` 是 V8 引擎中一个至关重要的组成部分，它允许开发者在非 MIPS64 平台上开发、测试和调试 V8 的 MIPS64 代码生成功能，确保 JavaScript 代码在 MIPS64 架构上的正确执行。

Prompt: 
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/mips64/simulator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能

"""
strSize;
    }
  };

  auto BranchAndLinkCompactHelper = [this, &next_pc](bool do_branch, int bits) {
    int64_t current_pc = get_pc();
    CheckForbiddenSlot(current_pc);
    if (do_branch) {
      int32_t imm = instr_.ImmValue(bits);
      imm <<= 32 - bits;
      imm >>= 32 - bits;
      next_pc = current_pc + (imm << 2) + kInstrSize;
      set_register(31, current_pc + kInstrSize);
    }
  };

  auto BranchCompactHelper = [this, &next_pc](bool do_branch, int bits) {
    int64_t current_pc = get_pc();
    CheckForbiddenSlot(current_pc);
    if (do_branch) {
      int32_t imm = instr_.ImmValue(bits);
      imm <<= 32 - bits;
      imm >>= 32 - bits;
      next_pc = get_pc() + (imm << 2) + kInstrSize;
    }
  };

  switch (op) {
    // ------------- COP1. Coprocessor instructions.
    case COP1:
      switch (instr_.RsFieldRaw()) {
        case BC1: {  // Branch on coprocessor condition.
          uint32_t cc = instr_.FBccValue();
          uint32_t fcsr_cc = get_fcsr_condition_bit(cc);
          uint32_t cc_value = test_fcsr_bit(fcsr_cc);
          bool do_branch = (instr_.FBtrueValue()) ? cc_value : !cc_value;
          BranchHelper(do_branch);
          break;
        }
        case BC1EQZ:
          BranchHelper(!(get_fpu_register(ft_reg) & 0x1));
          break;
        case BC1NEZ:
          BranchHelper(get_fpu_register(ft_reg) & 0x1);
          break;
        case BZ_V: {
          msa_reg_t wt;
          get_msa_register(wt_reg(), &wt);
          BranchHelper_MSA(wt.d[0] == 0 && wt.d[1] == 0);
        } break;
#define BZ_DF(witdh, lanes)          \
  {                                  \
    msa_reg_t wt;                    \
    get_msa_register(wt_reg(), &wt); \
    int i;                           \
    for (i = 0; i < lanes; ++i) {    \
      if (wt.witdh[i] == 0) {        \
        break;                       \
      }                              \
    }                                \
    BranchHelper_MSA(i != lanes);    \
  }
        case BZ_B:
          BZ_DF(b, kMSALanesByte)
          break;
        case BZ_H:
          BZ_DF(h, kMSALanesHalf)
          break;
        case BZ_W:
          BZ_DF(w, kMSALanesWord)
          break;
        case BZ_D:
          BZ_DF(d, kMSALanesDword)
          break;
#undef BZ_DF
        case BNZ_V: {
          msa_reg_t wt;
          get_msa_register(wt_reg(), &wt);
          BranchHelper_MSA(wt.d[0] != 0 || wt.d[1] != 0);
        } break;
#define BNZ_DF(witdh, lanes)         \
  {                                  \
    msa_reg_t wt;                    \
    get_msa_register(wt_reg(), &wt); \
    int i;                           \
    for (i = 0; i < lanes; ++i) {    \
      if (wt.witdh[i] == 0) {        \
        break;                       \
      }                              \
    }                                \
    BranchHelper_MSA(i == lanes);    \
  }
        case BNZ_B:
          BNZ_DF(b, kMSALanesByte)
          break;
        case BNZ_H:
          BNZ_DF(h, kMSALanesHalf)
          break;
        case BNZ_W:
          BNZ_DF(w, kMSALanesWord)
          break;
        case BNZ_D:
          BNZ_DF(d, kMSALanesDword)
          break;
#undef BNZ_DF
        default:
          UNREACHABLE();
      }
      break;
    // ------------- REGIMM class.
    case REGIMM:
      switch (instr_.RtFieldRaw()) {
        case BLTZ:
          BranchHelper(rs < 0);
          break;
        case BGEZ:
          BranchHelper(rs >= 0);
          break;
        case BLTZAL:
          BranchAndLinkHelper(rs < 0);
          break;
        case BGEZAL:
          BranchAndLinkHelper(rs >= 0);
          break;
        case DAHI:
          SetResult(rs_reg, rs + (se_imm16 << 32));
          break;
        case DATI:
          SetResult(rs_reg, rs + (se_imm16 << 48));
          break;
        default:
          UNREACHABLE();
      }
      break;  // case REGIMM.
    // ------------- Branch instructions.
    // When comparing to zero, the encoding of rt field is always 0, so we don't
    // need to replace rt with zero.
    case BEQ:
      BranchHelper(rs == rt);
      break;
    case BNE:
      BranchHelper(rs != rt);
      break;
    case POP06:  // BLEZALC, BGEZALC, BGEUC, BLEZ (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BLEZALC
            BranchAndLinkCompactHelper(rt <= 0, 16);
          } else {
            if (rs_reg == rt_reg) {  // BGEZALC
              BranchAndLinkCompactHelper(rt >= 0, 16);
            } else {  // BGEUC
              BranchCompactHelper(
                  static_cast<uint64_t>(rs) >= static_cast<uint64_t>(rt), 16);
            }
          }
        } else {  // BLEZ
          BranchHelper(rs <= 0);
        }
      } else {  // BLEZ
        BranchHelper(rs <= 0);
      }
      break;
    case POP07:  // BGTZALC, BLTZALC, BLTUC, BGTZ (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BGTZALC
            BranchAndLinkCompactHelper(rt > 0, 16);
          } else {
            if (rt_reg == rs_reg) {  // BLTZALC
              BranchAndLinkCompactHelper(rt < 0, 16);
            } else {  // BLTUC
              BranchCompactHelper(
                  static_cast<uint64_t>(rs) < static_cast<uint64_t>(rt), 16);
            }
          }
        } else {  // BGTZ
          BranchHelper(rs > 0);
        }
      } else {  // BGTZ
        BranchHelper(rs > 0);
      }
      break;
    case POP26:  // BLEZC, BGEZC, BGEC/BLEC / BLEZL (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BLEZC
            BranchCompactHelper(rt <= 0, 16);
          } else {
            if (rs_reg == rt_reg) {  // BGEZC
              BranchCompactHelper(rt >= 0, 16);
            } else {  // BGEC/BLEC
              BranchCompactHelper(rs >= rt, 16);
            }
          }
        }
      } else {  // BLEZL
        BranchAndLinkHelper(rs <= 0);
      }
      break;
    case POP27:  // BGTZC, BLTZC, BLTC/BGTC / BGTZL (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BGTZC
            BranchCompactHelper(rt > 0, 16);
          } else {
            if (rs_reg == rt_reg) {  // BLTZC
              BranchCompactHelper(rt < 0, 16);
            } else {  // BLTC/BGTC
              BranchCompactHelper(rs < rt, 16);
            }
          }
        }
      } else {  // BGTZL
        BranchAndLinkHelper(rs > 0);
      }
      break;
    case POP66:           // BEQZC, JIC
      if (rs_reg != 0) {  // BEQZC
        BranchCompactHelper(rs == 0, 21);
      } else {  // JIC
        next_pc = rt + imm16;
      }
      break;
    case POP76:           // BNEZC, JIALC
      if (rs_reg != 0) {  // BNEZC
        BranchCompactHelper(rs != 0, 21);
      } else {  // JIALC
        int64_t current_pc = get_pc();
        set_register(31, current_pc + kInstrSize);
        next_pc = rt + imm16;
      }
      break;
    case BC:
      BranchCompactHelper(true, 26);
      break;
    case BALC:
      BranchAndLinkCompactHelper(true, 26);
      break;
    case POP10:  // BOVC, BEQZALC, BEQC / ADDI (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rs_reg >= rt_reg) {  // BOVC
          bool condition = !is_int32(rs) || !is_int32(rt) || !is_int32(rs + rt);
          BranchCompactHelper(condition, 16);
        } else {
          if (rs_reg == 0) {  // BEQZALC
            BranchAndLinkCompactHelper(rt == 0, 16);
          } else {  // BEQC
            BranchCompactHelper(rt == rs, 16);
          }
        }
      } else {  // ADDI
        if (HaveSameSign(rs, se_imm16)) {
          if (rs > 0) {
            if (rs <= Registers::kMaxValue - se_imm16) {
              SignalException(kIntegerOverflow);
            }
          } else if (rs < 0) {
            if (rs >= Registers::kMinValue - se_imm16) {
              SignalException(kIntegerUnderflow);
            }
          }
        }
        SetResult(rt_reg, rs + se_imm16);
      }
      break;
    case POP30:  // BNVC, BNEZALC, BNEC / DADDI (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rs_reg >= rt_reg) {  // BNVC
          bool condition = is_int32(rs) && is_int32(rt) && is_int32(rs + rt);
          BranchCompactHelper(condition, 16);
        } else {
          if (rs_reg == 0) {  // BNEZALC
            BranchAndLinkCompactHelper(rt != 0, 16);
          } else {  // BNEC
            BranchCompactHelper(rt != rs, 16);
          }
        }
      }
      break;
    // ------------- Arithmetic instructions.
    case ADDIU: {
      int32_t alu32_out = static_cast<int32_t>(rs + se_imm16);
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      break;
    }
    case DADDIU:
      SetResult(rt_reg, rs + se_imm16);
      break;
    case SLTI:
      SetResult(rt_reg, rs < se_imm16 ? 1 : 0);
      break;
    case SLTIU:
      SetResult(rt_reg, rs_u < static_cast<uint64_t>(se_imm16) ? 1 : 0);
      break;
    case ANDI:
      SetResult(rt_reg, rs & oe_imm16);
      break;
    case ORI:
      SetResult(rt_reg, rs | oe_imm16);
      break;
    case XORI:
      SetResult(rt_reg, rs ^ oe_imm16);
      break;
    case LUI:
      if (rs_reg != 0) {
        // AUI instruction.
        DCHECK_EQ(kArchVariant, kMips64r6);
        int32_t alu32_out = static_cast<int32_t>(rs + (se_imm16 << 16));
        SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      } else {
        // LUI instruction.
        int32_t alu32_out = static_cast<int32_t>(oe_imm16 << 16);
        // Sign-extend result of 32bit operation into 64bit register.
        SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      }
      break;
    case DAUI:
      DCHECK_EQ(kArchVariant, kMips64r6);
      DCHECK_NE(rs_reg, 0);
      SetResult(rt_reg, rs + (se_imm16 << 16));
      break;
    // ------------- Memory instructions.
    case LB:
      set_register(rt_reg, ReadB(rs + se_imm16));
      break;
    case LH:
      set_register(rt_reg, ReadH(rs + se_imm16, instr_.instr()));
      break;
    case LWL: {
      local_monitor_.NotifyLoad();
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint8_t byte_shift = kInt32AlignmentMask - al_offset;
      uint32_t mask = (1 << byte_shift * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      int32_t val = ReadW(addr, instr_.instr());
      val <<= byte_shift * 8;
      val |= rt & mask;
      set_register(rt_reg, static_cast<int64_t>(val));
      break;
    }
    case LW:
      set_register(rt_reg, ReadW(rs + se_imm16, instr_.instr()));
      break;
    case LWU:
      set_register(rt_reg, ReadWU(rs + se_imm16, instr_.instr()));
      break;
    case LD:
      set_register(rt_reg, Read2W(rs + se_imm16, instr_.instr()));
      break;
    case LBU:
      set_register(rt_reg, ReadBU(rs + se_imm16));
      break;
    case LHU:
      set_register(rt_reg, ReadHU(rs + se_imm16, instr_.instr()));
      break;
    case LWR: {
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint8_t byte_shift = kInt32AlignmentMask - al_offset;
      uint32_t mask = al_offset ? (~0 << (byte_shift + 1) * 8) : 0;
      addr = rs + se_imm16 - al_offset;
      alu_out = ReadW(addr, instr_.instr());
      alu_out = static_cast<uint32_t>(alu_out) >> al_offset * 8;
      alu_out |= rt & mask;
      set_register(rt_reg, alu_out);
      break;
    }
    case LDL: {
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint8_t byte_shift = kInt64AlignmentMask - al_offset;
      uint64_t mask = (1UL << byte_shift * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      alu_out = Read2W(addr, instr_.instr());
      alu_out <<= byte_shift * 8;
      alu_out |= rt & mask;
      set_register(rt_reg, alu_out);
      break;
    }
    case LDR: {
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint8_t byte_shift = kInt64AlignmentMask - al_offset;
      uint64_t mask = al_offset ? (~0UL << (byte_shift + 1) * 8) : 0UL;
      addr = rs + se_imm16 - al_offset;
      alu_out = Read2W(addr, instr_.instr());
      alu_out = alu_out >> al_offset * 8;
      alu_out |= rt & mask;
      set_register(rt_reg, alu_out);
      break;
    }
    case SB:
      WriteB(rs + se_imm16, static_cast<int8_t>(rt));
      break;
    case SH:
      WriteH(rs + se_imm16, static_cast<uint16_t>(rt), instr_.instr());
      break;
    case SWL: {
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint8_t byte_shift = kInt32AlignmentMask - al_offset;
      uint32_t mask = byte_shift ? (~0 << (al_offset + 1) * 8) : 0;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = ReadW(addr, instr_.instr()) & mask;
      mem_value |= static_cast<uint32_t>(rt) >> byte_shift * 8;
      WriteW(addr, static_cast<int32_t>(mem_value), instr_.instr());
      break;
    }
    case SW:
      WriteW(rs + se_imm16, static_cast<int32_t>(rt), instr_.instr());
      break;
    case SD:
      Write2W(rs + se_imm16, rt, instr_.instr());
      break;
    case SWR: {
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint32_t mask = (1 << al_offset * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = ReadW(addr, instr_.instr());
      mem_value = (rt << al_offset * 8) | (mem_value & mask);
      WriteW(addr, static_cast<int32_t>(mem_value), instr_.instr());
      break;
    }
    case SDL: {
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint8_t byte_shift = kInt64AlignmentMask - al_offset;
      uint64_t mask = byte_shift ? (~0UL << (al_offset + 1) * 8) : 0;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = Read2W(addr, instr_.instr()) & mask;
      mem_value |= static_cast<uint64_t>(rt) >> byte_shift * 8;
      Write2W(addr, mem_value, instr_.instr());
      break;
    }
    case SDR: {
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint64_t mask = (1UL << al_offset * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = Read2W(addr, instr_.instr());
      mem_value = (rt << al_offset * 8) | (mem_value & mask);
      Write2W(addr, mem_value, instr_.instr());
      break;
    }
    case LL: {
      DCHECK(kArchVariant != kMips64r6);
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      addr = rs + se_imm16;
      set_register(rt_reg, ReadW(addr, instr_.instr()));
      local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
      GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                    &global_monitor_thread_);
      break;
    }
    case SC: {
      DCHECK(kArchVariant != kMips64r6);
      addr = rs + se_imm16;
      WriteConditionalW(addr, static_cast<int32_t>(rt), instr_.instr(), rt_reg);
      break;
    }
    case LLD: {
      DCHECK(kArchVariant != kMips64r6);
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      addr = rs + se_imm16;
      set_register(rt_reg, Read2W(addr, instr_.instr()));
      local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
      GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                    &global_monitor_thread_);
      break;
    }
    case SCD: {
      DCHECK(kArchVariant != kMips64r6);
      addr = rs + se_imm16;
      WriteConditional2W(addr, rt, instr_.instr(), rt_reg);
      break;
    }
    case LWC1:
      set_fpu_register(ft_reg, kFPUInvalidResult);  // Trash upper 32 bits.
      set_fpu_register_word(ft_reg,
                            ReadW(rs + se_imm16, instr_.instr(), FLOAT_DOUBLE));
      break;
    case LDC1:
      set_fpu_register_double(ft_reg, ReadD(rs + se_imm16, instr_.instr()));
      TraceMemRd(addr, get_fpu_register(ft_reg), DOUBLE);
      break;
    case SWC1: {
      int32_t alu_out_32 = static_cast<int32_t>(get_fpu_register(ft_reg));
      WriteW(rs + se_imm16, alu_out_32, instr_.instr());
      break;
    }
    case SDC1:
      WriteD(rs + se_imm16, get_fpu_register_double(ft_reg), instr_.instr());
      TraceMemWr(rs + se_imm16, get_fpu_register(ft_reg), DWORD);
      break;
    // ------------- PC-Relative instructions.
    case PCREL: {
      // rt field: checking 5-bits.
      int32_t imm21 = instr_.Imm21Value();
      int64_t current_pc = get_pc();
      uint8_t rt = (imm21 >> kImm16Bits);
      switch (rt) {
        case ALUIPC:
          addr = current_pc + (se_imm16 << 16);
          alu_out = static_cast<int64_t>(~0x0FFFF) & addr;
          break;
        case AUIPC:
          alu_out = current_pc + (se_imm16 << 16);
          break;
        default: {
          int32_t imm19 = instr_.Imm19Value();
          // rt field: checking the most significant 3-bits.
          rt = (imm21 >> kImm18Bits);
          switch (rt) {
            case LDPC:
              addr =
                  (current_pc & static_cast<int64_t>(~0x7)) + (se_imm18 << 3);
              alu_out = Read2W(addr, instr_.instr());
              break;
            default: {
              // rt field: checking the most significant 2-bits.
              rt = (imm21 >> kImm19Bits);
              switch (rt) {
                case LWUPC: {
                  // Set sign.
                  imm19 <<= (kOpcodeBits + kRsBits + 2);
                  imm19 >>= (kOpcodeBits + kRsBits + 2);
                  addr = current_pc + (imm19 << 2);
                  alu_out = ReadWU(addr, instr_.instr());
                  break;
                }
                case LWPC: {
                  // Set sign.
                  imm19 <<= (kOpcodeBits + kRsBits + 2);
                  imm19 >>= (kOpcodeBits + kRsBits + 2);
                  addr = current_pc + (imm19 << 2);
                  alu_out = ReadW(addr, instr_.instr());
                  break;
                }
                case ADDIUPC: {
                  int64_t se_imm19 =
                      imm19 | ((imm19 & 0x40000) ? 0xFFFFFFFFFFF80000 : 0);
                  alu_out = current_pc + (se_imm19 << 2);
                  break;
                }
                default:
                  UNREACHABLE();
              }
              break;
            }
          }
          break;
        }
      }
      SetResult(rs_reg, alu_out);
      break;
    }
    case SPECIAL3: {
      switch (instr_.FunctionFieldRaw()) {
        case LL_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & 0x3, 0);
          set_register(rt_reg, ReadW(addr, instr_.instr()));
          local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              addr, &global_monitor_thread_);
          break;
        }
        case LLD_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & kPointerAlignmentMask, 0);
          set_register(rt_reg, Read2W(addr, instr_.instr()));
          local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              addr, &global_monitor_thread_);
          break;
        }
        case SC_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & 0x3, 0);
          WriteConditionalW(addr, static_cast<int32_t>(rt), instr_.instr(),
                            rt_reg);
          break;
        }
        case SCD_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & kPointerAlignmentMask, 0);
          WriteConditional2W(addr, rt, instr_.instr(), rt_reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }

    case MSA:
      switch (instr_.MSAMinorOpcodeField()) {
        case kMsaMinorI8:
          DecodeTypeMsaI8();
          break;
        case kMsaMinorI5:
          DecodeTypeMsaI5();
          break;
        case kMsaMinorI10:
          DecodeTypeMsaI10();
          break;
        case kMsaMinorELM:
          DecodeTypeMsaELM();
          break;
        case kMsaMinorBIT:
          DecodeTypeMsaBIT();
          break;
        case kMsaMinorMI10:
          DecodeTypeMsaMI10();
          break;
        default:
          UNREACHABLE();
      }
      break;
    default:
      UNREACHABLE();
  }

  if (execute_branch_delay_instruction) {
    // Execute branch delay slot
    // We don't check for end_sim_pc. First it should not be met as the current
    // pc is valid. Secondly a jump should always execute its branch delay slot.
    Instruction* branch_delay_instr =
        reinterpret_cast<Instruction*>(get_pc() + kInstrSize);
    BranchDelayInstructionDecode(branch_delay_instr);
  }

  // If needed update pc after the branch delay execution.
  if (next_pc != bad_ra) {
    set_pc(next_pc);
  }
}

// Type 3: instructions using a 26 bytes immediate. (e.g. j, jal).
void Simulator::DecodeTypeJump() {
  // instr_ will be overwritten by BranchDelayInstructionDecode(), so we save
  // the result of IsLinkingInstruction now.
  bool isLinkingInstr = instr_.IsLinkingInstruction();
  // Get current pc.
  int64_t current_pc = get_pc();
  // Get unchanged bits of pc.
  int64_t pc_high_bits = current_pc & 0xFFFFFFFFF0000000;
  // Next pc.
  int64_t next_pc = pc_high_bits | (instr_.Imm26Value() << 2);

  // Execute branch delay slot.
  // We don't check for end_sim_pc. First it should not be met as the current pc
  // is valid. Secondly a jump should always execute its branch delay slot.
  Instruction* branch_delay_instr =
      reinterpret_cast<Instruction*>(current_pc + kInstrSize);
  BranchDelayInstructionDecode(branch_delay_instr);

  // Update pc and ra if necessary.
  // Do this after the branch delay execution.
  if (isLinkingInstr) {
    set_register(31, current_pc + 2 * kInstrSize);
  }
  set_pc(next_pc);
  pc_modified_ = true;
}

// Executes the current instruction.
void Simulator::InstructionDecode(Instruction* instr) {
  if (v8_flags.check_icache) {
    CheckICache(i_cache(), instr);
  }
  pc_modified_ = false;

  v8::base::EmbeddedVector<char, 256> buffer;

  if (v8_flags.trace_sim) {
    base::SNPrintF(trace_buf_, " ");
    disasm::NameConverter converter;
    disasm::Disassembler dasm(converter);
    // Use a reasonably large buffer.
    dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(instr));
  }

  instr_ = instr;
  switch (instr_.InstructionType()) {
    case Instruction::kRegisterType:
      DecodeTypeRegister();
      break;
    case Instruction::kImmediateType:
      DecodeTypeImmediate();
      break;
    case Instruction::kJumpType:
      DecodeTypeJump();
      break;
    default:
      UNSUPPORTED();
  }

  if (v8_flags.trace_sim) {
    PrintF("  0x%08" PRIxPTR "   %-44s   %s\n",
           reinterpret_cast<intptr_t>(instr), buffer.begin(),
           trace_buf_.begin());
  }

  if (!pc_modified_) {
    set_register(pc, reinterpret_cast<int64_t>(instr) + kInstrSize);
  }
}

void Simulator::Execute() {
  // Get the PC to simulate. Cannot use the accessor here as we need the
  // raw PC value and not the one used as input to arithmetic instructions.
  int64_t program_counter = get_pc();
  if (v8_flags.stop_sim_at == 0) {
    // Fast version of the dispatch loop without checking whether the simulator
    // should be stopping at a particular executed instruction.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_++;
      InstructionDecode(instr);
      program_counter = get_pc();
    }
  } else {
    // v8_flags.stop_sim_at is at the non-default value. Stop in the debugger
    // when we reach the particular instruction count.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_++;
      if (icount_ == static_cast<int64_t>(v8_flags.stop_sim_at)) {
        MipsDebugger dbg(this);
        dbg.Debug();
      } else {
        InstructionDecode(instr);
      }
      program_counter = get_pc();
    }
  }
}

void Simulator::CallInternal(Address entry) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Prepare to execute the code at entry.
  set_register(pc, static_cast<int64_t>(entry));
  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  set_register(ra, end_sim_pc);

  // Remember the values of callee-saved registers.
  // The code below assumes that r9 is not used as sb (static base) in
  // simulator code and therefore is regarded as a callee-saved register.
  int64_t s0_val = get_register(s0);
  int64_t s1_val = get_register(s1);
  int64_t s2_val = get_register(s2);
  int64_t s3_val = get_register(s3);
  int64_t s4_val = get_register(s4);
  int64_t s5_val = get_register(s5);
  int64_t s6_val = get_register(s6);
  int64_t s7_val = get_register(s7);
  int64_t gp_val = get_register(gp);
  int64_t sp_val = get_register(sp);
  int64_t fp_val = get_register(fp);

  // Set up the callee-saved registers with a known value. To be able to check
  // that they are preserved properly across JS execution.
  int64_t callee_saved_value = icount_;
  set_register(s0, callee_saved_value);
  set_register(s1, callee_saved_value);
  set_register(s2, callee_saved_value);
  set_register(s3, callee_saved_value);
  set_register(s4, callee_saved_value);
  set_register(s5, callee_saved_value);
  set_register(s6, callee_saved_value);
  set_register(s7, callee_saved_value);
  set_register(gp, callee_saved_value);
  set_register(fp, callee_saved_value);

  // Start the simulation.
  Execute();

  // Check that the callee-saved registers have been preserved.
  CHECK_EQ(callee_saved_value, get_register(s0));
  CHECK_EQ(callee_saved_value, get_register(s1));
  CHECK_EQ(callee_saved_value, get_register(s2));
  CHECK_EQ(callee_saved_value, get_register(s3));
  CHECK_EQ(callee_saved_value, get_register(s4));
  CHECK_EQ(callee_saved_value, get_register(s5));
  CHECK_EQ(callee_saved_value, get_register(s6));
  CHECK_EQ(callee_saved_value, get_register(s7));
  CHECK_EQ(callee_saved_value, get_register(gp));
  CHECK_EQ(callee_saved_value, get_register(fp));

  // Restore callee-saved registers with the original value.
  set_register(s0, s0_val);
  set_register(s1, s1_val);
  set_register(s2, s2_val);
  set_register(s3, s3_val);
  set_register(s4, s4_val);
  set_register(s5, s5_val);
  set_register(s6, s6_val);
  set_register(s7, s7_val);
  set_register(gp, gp_val);
  set_register(sp, sp_val);
  set_register(fp, fp_val);
}

void Simulator::CallImpl(Address entry, CallArgument* args) {
  std::vector<int64_t> stack_args(0);
  for (int i = 0; !args[i].IsEnd(); i++) {
    CallArgument arg = args[i];
    if (i < 8) {
      if (arg.IsGP()) {
        set_register(i + 4, arg.bits());
      } else {
        DCHECK(arg.IsFP());
        set_fpu_register(i + 12, arg.bits());
      }
    } else {
      DCHECK(arg.IsFP() || arg.IsGP());
      stack_args.push_back(arg.bits());
    }
  }

  // Remaining arguments passed on stack.
  int64_t original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  int64_t stack_args_size =
      stack_args.size() * sizeof(stack_args[0]) + kCArgsSlotsSize;
  int64_t entry_stack = original_stack - stack_args_size;

  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  // Store remaining arguments on stack, from low to high memory.
  char* stack_argument = reinterpret_cast<char*>(entry_stack);
  memcpy(stack_argument + kCArgSlotCount, stack_args.data(),
         stack_args.size() * sizeof(int64_t));
  set_register(sp, entry_stack);

  CallInternal(entry);

  // Pop stack passed arguments.
  CHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);
}

double Simulator::CallFP(Address entry, double d0, double d1) {
  if (!IsMipsSoftFloatABI) {
    const FPURegister fparg2 = f13;
    set_fpu_register_double(f12, d0);
    set_fpu_register_double(fparg2, d1);
  } else {
    int buffer[2];
    DCHECK(sizeof(buffer[0]) * 2 == sizeof(d0));
    memcpy(buffer, &d0, sizeof(d0));
    set_dw_register(a0, buffer);
    memcpy(buffer, &d1, sizeof(d1));
    set_dw_register(a2, buffer);
  }
  CallInternal(entry);
  if (!IsMipsSoftFloatABI) {
    return get_fpu_register_double(f0);
  } else {
    return get_double_from_register_pair(v0);
  }
}

uintptr_t Simulator::PushAddress(uintptr_t address) {
  int64_t new_sp = get_register(sp) - sizeof(uintptr_t);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  *stack_slot = address;
  set_register(sp, new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  int64_t current_sp = get_register(sp);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  set_register(sp, current_sp + sizeof(uintptr_t));
  return address;
}

Simulator::LocalMonitor::LocalMonitor()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      size_(TransactionSize::None) {}

void Simulator::LocalMonitor::Clear() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
  size_ = TransactionSize::None;
}

void Simulator::LocalMonitor::NotifyLoad() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non linked load could clear the local monitor. As a result, it's
    // most strict to unconditionally clear the local monitor on load.
    Clear();
  }
}

void Simulator::LocalMonitor::NotifyLoadLinked(uintptr_t addr,
                                               TransactionSize size) {
  access_state_ = MonitorAccess::RMW;
  tagged_addr_ = addr;
  size_ = size;
}

void Simulator::LocalMonitor::NotifyStore() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non exclusive store could clear the local monitor. As a result, it's
    // most strict to unconditionally clear the local monitor on store.
    Clear();
  }
}

bool Simulator::LocalMonitor::NotifyStoreConditional(uintptr_t addr,
                                                     TransactionSize size) {
  if (access_state_ == MonitorAccess::RMW) {
    if (addr == tagged_addr_ && size_ == size) {
      Clear();
      return true;
    } else {
      return false;
    }
  } else {
    DCHECK(access_state_ == MonitorAccess::Open);
    return false;
  }
}

Simulator::GlobalMonitor::LinkedAddress::LinkedAddress()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      next_(nullptr),
      prev_(nullptr),
      failure_counter_(0) {}

void Simulator::GlobalMonitor::LinkedAddress::Clear_Locked() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
}

void Simulator::GlobalMonitor::LinkedAddress::NotifyLoadLinked_Locked(
    uintptr_t addr) {
  access_state_ = MonitorAccess::RMW;
  tagged_addr_ = addr;
}

void Simulator::GlobalMonitor::LinkedAddress::NotifyStore_Locked() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non exclusive store could clear the global monitor. As a result, it's
    // most strict to unconditionally clear global monitors on store.
    Clear_Locked();
  }
}

bool Simulator::GlobalMonitor::LinkedAddress::NotifyStoreConditional_Locked(
    uintptr_t addr, bool is_requesting_thread) {
  if (access_state_ == MonitorAccess::RMW) {
    if (is_requesting_thread) {
      if (addr == tagged_addr_) {
        Clear_Locked();
        // Introduce occasional sc/scd failures. This is to simulate the
        // behavior of hardware, which can randomly fail due to background
        // cache evictions.
        if (failure_counter_++ >= kMaxFailureCounter) {
"""


```