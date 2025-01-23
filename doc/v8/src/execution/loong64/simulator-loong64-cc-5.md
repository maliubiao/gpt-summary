Response:
The user wants to understand the functionality of a specific part of the V8 simulator for the LoongArch64 architecture. This part seems to handle the execution of various LoongArch64 instructions.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Function:** The code snippet contains `switch` statements based on instruction opcodes. Each `case` within the `switch` corresponds to a specific LoongArch64 instruction (like `AMOR_DB_D`, `CLZ_W`, `FABS_S`, etc.). The code within each case simulates the behavior of that instruction. Therefore, the core function is *simulating the execution of LoongArch64 instructions*.

2. **Check for `.tq` extension:** The prompt explicitly asks about the `.tq` extension. The provided code is `.cc`, so it's a C++ source file, not a Torque file.

3. **Relate to JavaScript:**  The simulator is part of V8, which executes JavaScript. The LoongArch64 instructions being simulated are the *target* architecture for compiled JavaScript code when running on LoongArch64. Therefore, this code is indirectly related to JavaScript. A simple example would be an addition in JavaScript being compiled to an `ADD` instruction that this simulator would then execute.

4. **Identify Code Logic and Provide Examples:**  Many of the instructions perform specific bitwise operations, arithmetic operations, or floating-point operations. For example, `CLZ_W` counts leading zeros. To demonstrate this, choose a simple instruction and show the input and output.

5. **Consider Common Programming Errors:**  Think about how the simulated instructions interact with memory and registers. A common error is accessing invalid memory. The code includes `ProbeMemory` checks, suggesting this is a concern. Give an example of trying to access an invalid memory address.

6. **Address "Part 6 of 7":** This implies that this code handles a *subset* of the total instructions. The provided snippet seems to focus on atomic memory operations, bit manipulation instructions, and floating-point operations.

7. **Structure the Response:** Organize the information into clear sections addressing each point raised in the prompt. Use formatting like bullet points and code blocks to improve readability.

8. **Refine and Clarify:** Review the generated response to ensure accuracy and clarity. For instance, emphasize the *simulation* aspect, and clarify the *indirect* relationship with JavaScript. Ensure the examples are easy to understand. Specifically for the "Part 6 of 7" point, avoid stating definitively what the other parts do without having seen them, but rather focus on what this part *seems* to be handling.
这是目录为 `v8/src/execution/loong64/simulator-loong64.cc` 的一个 V8 源代码文件的第 6 部分，总共 7 部分。从提供的代码片段来看，这个文件的主要功能是 **模拟执行 LoongArch64 架构的指令**。

**功能归纳:**

这部分代码主要负责模拟以下类型的 LoongArch64 指令：

* **原子内存操作 (Atomic Memory Operations):**  如 `AMOR_DB_W`, `AMOR_DB_D`, `AMXOR_DB_W`, `AMXOR_DB_D` 等。这些指令用于在多线程环境下安全地修改内存中的数据，保证操作的原子性。
* **部分位操作 (Bit Manipulation Operations):** 如 `CLZ_W`, `CTZ_W`, `REVB_2H`, `REVB_4H`, `BITREV_4B`, `BITREV_8B` 等。这些指令用于进行位级的计数、反转和提取等操作。
* **浮点运算操作 (Floating-Point Operations):** 如 `FSCALEB_S`, `FCOPYSIGN_S`, `FABS_S`, `FNEG_S`, `FSQRT_S`, `FMOV_S`, `FCVT_S_D`, `FTINTRM_W_S`, `FTINTRP_W_S`, `FTINTRZ_W_S`, `FTINTRNE_W_S`, `FTINT_W_S`, `FFINT_S_W`, `FRINT_S` 等。这些指令用于执行浮点数的算术、转换和舍入等操作。
* **控制流指令 (Control Flow Instructions，虽然片段中只看到了 `DBAR` 和 `IBAR`):** `DBAR` (Data Barrier) 和 `IBAR` (Instruction Barrier) 用于保证内存操作的顺序性。
* **浮点寄存器和通用寄存器之间的数据传输 (Data Transfer between Floating-Point and General-Purpose Registers):** 如 `MOVGR2FR_W`, `MOVFR2GR_S` 等。
* **浮点控制状态寄存器 (FCSR) 的操作:** 如 `MOVGR2FCSR`, `MOVFCSR2GR`。

**关于文件扩展名和 Torque:**

代码片段显示文件名为 `simulator-loong64.cc`，以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的关系:**

V8 是一个 JavaScript 引擎，负责解释和执行 JavaScript 代码。当 JavaScript 代码在 LoongArch64 架构上运行时，V8 会将 JavaScript 代码编译成 LoongArch64 的机器指令。  `simulator-loong64.cc` 中的代码用于 **模拟执行这些编译后的 LoongArch64 指令**。这主要用于开发、测试和调试 V8 引擎在 LoongArch64 架构上的实现，而无需实际的 LoongArch64 硬件。

**JavaScript 示例:**

以下 JavaScript 代码可能会被 V8 编译成涉及到这里模拟指令的 LoongArch64 代码：

```javascript
// 原子操作示例
let counter = new Atomics.Int32Array(new SharedArrayBuffer(4));
Atomics.add(counter, 0, 1);

// 位操作示例
let num = 10; // 二进制 1010
let leadingZeros = Math.clz32(num); // 对应 CLZ_W

// 浮点运算示例
let a = 3.14;
let b = Math.sqrt(a); // 对应 FSQRT_D 或 FSQRT_S

// 类型转换示例
let floatNum = 3.14;
let intNum = Math.trunc(floatNum); // 对应 FTINTRZ_W_D 或 FTINTRZ_W_S
```

**代码逻辑推理和假设输入/输出:**

以 `CLZ_W` 指令为例（Count Leading Zeros Word）：

**假设输入:**

* `rd_reg()` (目标寄存器):  假设为寄存器 `r10`
* `rj_reg()` (源寄存器): 假设为寄存器 `r11`
* 寄存器 `r11` 的值为 `0x0000000A` (二进制 `0000 0000 0000 0000 0000 0000 0000 1010`)

**代码逻辑:**

`alu_out = base::bits::CountLeadingZeros32(static_cast<int32_t>(rj_u()));`

这行代码会计算 `r11` 中 32 位值的（无符号）前导零的个数。

**预期输出:**

* `alu_out` 的值为 28 (因为前 28 位都是 0)。
* 寄存器 `r10` 的值将被设置为 28。

**涉及用户常见的编程错误:**

* **原子操作使用不当:**  在多线程环境下，如果没有正确使用原子操作，可能会导致数据竞争和不一致性。例如，多个线程同时对一个共享变量进行非原子性的加法操作，可能导致最终结果错误。

  ```javascript
  // 错误示例 (非原子操作)
  let counter = 0;
  function increment() {
    counter++; // 多个线程同时执行可能导致错误
  }
  ```

* **浮点数精度问题:**  用户可能不理解浮点数的内部表示，导致在进行浮点数比较或运算时出现意想不到的结果。例如，两个看似相等的浮点数，由于精度问题，可能不相等。

  ```javascript
  let a = 0.1 + 0.2;
  let b = 0.3;
  console.log(a === b); // 输出 false，因为浮点数精度问题
  ```

* **类型转换错误:** 在进行浮点数到整数的转换时，如果没有明确指定舍入方式，可能会得到非预期的结果。例如，使用 `parseInt()` 或简单的类型转换可能会导致截断，而用户可能期望四舍五入。

  ```javascript
  let floatNum = 3.9;
  let intNum1 = parseInt(floatNum); // 结果为 3 (截断)
  let intNum2 = Math.round(floatNum); // 结果为 4 (四舍五入)
  ```

**总结第 6 部分的功能:**

这部分 `simulator-loong64.cc` 的代码专注于 **模拟 LoongArch64 架构中与原子内存操作、位操作和浮点运算相关的指令**。它涵盖了在多线程编程中保证数据一致性的原子操作，对数据进行位级处理的指令，以及执行各种浮点数运算和转换的指令。这部分还涉及了浮点控制状态寄存器的操作以及浮点寄存器和通用寄存器之间的数据传输。 这对于 V8 引擎在 LoongArch64 平台上的正确执行至关重要。

### 提示词
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/loong64/simulator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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