Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/execution/loong64/simulator-loong64.cc`. They have several specific questions about its nature and relationship to JavaScript, and expect a summary of its purpose.

Here's a breakdown of the thinking process to address the request:

1. **Identify the core purpose of the code:** The code consists of a large `switch` statement processing different instruction opcodes. Each `case` corresponds to a specific LoongArch64 instruction. The code simulates the execution of these instructions. This strongly suggests the file is part of a *simulator* for the LoongArch64 architecture within the V8 JavaScript engine.

2. **Address the `.tq` check:** The user asks if the file ending in `.tq` would indicate a Torque file. The filename ends in `.cc`, which is a standard C++ file extension. Therefore, it's not a Torque file.

3. **Analyze the relationship with JavaScript:**  Simulators, while not directly JavaScript code, are crucial for executing JavaScript on platforms where a native V8 implementation for that architecture doesn't exist yet, or for testing and debugging. The simulator interprets the generated machine code (or intermediate representation) for the target architecture.

4. **Provide a JavaScript example:**  To illustrate the connection, a simple JavaScript addition can be used. V8 compiles this JavaScript to machine code. On a LoongArch64 system (or when using the simulator), the *simulated* ADD instruction (like the `ADD_W` or `ADD_D` cases in the code) would be involved in performing this addition.

5. **Address code logic reasoning with input/output:**  Pick a simple instruction, like `ADD_W`. Explain what it does (adds two registers). Provide hypothetical input register values and show the expected output in the destination register. Highlight the sign-extension behavior for 32-bit operations.

6. **Identify common programming errors:**  Focus on errors related to the simulated instructions. A common error would be assuming 32-bit arithmetic on a 64-bit architecture without proper handling (the sign-extension in the code demonstrates this potential pitfall). Another common error with division is division by zero.

7. **Formulate the summary:** Combine the key findings. The file simulates LoongArch64 instructions. This allows V8 to run on LoongArch64 by interpreting the instructions. Mention the debugging and testing aspects of simulators.

8. **Structure the answer:** Organize the information clearly, addressing each point in the user's request systematically. Use headings and bullet points for better readability. Highlight code snippets and their explanations.

**Self-Correction/Refinement:**

* **Initial thought:**  Perhaps the simulator is only used for testing.
* **Correction:**  Simulators are also used for porting V8 to new architectures before a full native implementation is available. This is a more accurate and complete description of the simulator's role.
* **Initial thought:** Provide a very complex JavaScript example.
* **Correction:** A simple example is better for illustrating the core concept of how JavaScript execution relates to the simulated instructions. Keep it concise and focused.
* **Initial thought:** Focus solely on the functional description of each instruction.
* **Correction:**  The user also asked about the broader purpose and context. Emphasize the role of the simulator in the V8 ecosystem.

By following these steps and refining the initial thoughts, a comprehensive and accurate answer can be constructed that directly addresses the user's request.
好的，让我们来分析一下 `v8/src/execution/loong64/simulator-loong64.cc` 这部分代码的功能。

**功能列举：**

从提供的代码片段来看，`v8/src/execution/loong64/simulator-loong64.cc` 的主要功能是 **模拟执行 LoongArch64 架构的指令集**。  具体来说，这段代码实现了以下操作：

1. **指令分发 (Instruction Dispatch):**  通过一个 `switch` 语句，根据当前指令的操作码 (opcode) 来执行相应的模拟逻辑。
2. **算术和逻辑运算:**  模拟了各种整数和浮点数的算术运算（加、减、乘、除、取模）、逻辑运算（与、或、异或、非）、比较运算（小于、小于等于）和移位/循环操作。
3. **内存访问:**  模拟了从内存中加载 (LDX) 数据到寄存器以及将寄存器数据存储 (STX) 到内存的操作，包括不同数据大小（字节、半字、字、双字）的有符号和无符号版本。
4. **原子操作:** 模拟了一些原子操作 (AMSWAP, AMADD, AMAND, AMOR, AMXOR, AMMAX, AMMIN)，这些操作用于多线程环境中的同步。
5. **浮点运算:**  模拟了单精度和双精度浮点数的加、减、乘、除、最大值、最小值以及绝对值最大/最小值运算。
6. **打印指令信息 (Debugging):**  在执行每条指令时，会通过 `printf_instr` 打印出指令的名称、操作数以及操作数的值，这对于调试模拟器本身或模拟执行的代码非常有帮助。
7. **软件中断:**  模拟了 `BREAK` 指令，用于触发软件中断。
8. **寄存器和内存管理:**  代码中使用了 `rd_reg()`, `rj()`, `rk()` 等函数来访问和操作模拟的通用寄存器和浮点寄存器。 `ReadB()`, `ReadW()`, `Read2W()`, `WriteB()`, `WriteW()`, `Write2W()` 等函数用于模拟内存的读写操作。
9. **内存探测:** `ProbeMemory()` 函数用于检查内存访问是否在有效范围内。

**关于文件类型：**

`v8/src/execution/loong64/simulator-loong64.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。你提到的 `.tq` 结尾的文件是 V8 的 Torque 语言源代码，用于定义 V8 的内置函数和类型系统。因此，这个文件不是 Torque 文件。

**与 JavaScript 的关系：**

`v8/src/execution/loong64/simulator-loong64.cc` 与 JavaScript 的执行密切相关。当 V8 需要在 LoongArch64 架构上运行，但又没有底层的硬件支持或者需要进行测试和调试时，这个模拟器就派上了用场。

**工作流程：**

1. V8 的 JavaScript 代码会被编译成针对目标架构（这里是 LoongArch64）的机器码。
2. 如果没有真正的 LoongArch64 硬件，或者为了调试，V8 会使用这个模拟器来执行这些机器码。
3. 模拟器会逐条读取机器码指令，并根据指令的操作码，执行相应的 C++ 代码来模拟指令的行为，例如更新模拟的寄存器和内存状态。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 执行这段 JavaScript 代码时，`a + b` 这个加法操作会被编译成 LoongArch64 的加法指令，例如 `ADD_W` 或 `ADD_D`。  在模拟器中，当执行到这条指令时，会进入 `simulator-loong64.cc` 中 `case ADD_W:` 或 `case ADD_D:` 分支的代码，模拟寄存器相加并将结果存回寄存器的过程。

**代码逻辑推理和假设输入/输出：**

让我们以 `ADD_W` 指令为例：

**假设输入：**

* `rd_reg()` (目标寄存器) 为 `r10`
* `rj_reg()` (源寄存器 1) 为 `r11`，其值为 `0x0000000000000005` (十进制 5)
* `rk_reg()` (源寄存器 2) 为 `r12`，其值为 `0x0000000000000003` (十进制 3)

**代码逻辑：**

```c++
case ADD_W: {
  printf_instr("ADD_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
               Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
               rj(), Registers::Name(rk_reg()), rk());
  int32_t alu32_out = static_cast<int32_t>(rj() + rk());
  // Sign-extend result of 32bit operation into 64bit register.
  SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
  break;
}
```

1. 打印指令信息，显示 `ADD_W` 操作以及操作数和它们的值。
2. 从 `rj()` 和 `rk()` 获取寄存器 `r11` 和 `r12` 的值。
3. 将这两个值作为 32 位整数相加： `5 + 3 = 8`。
4. 将 32 位的结果 `8` ( `0x00000008`) 符号扩展为 64 位整数：`0x0000000000000008`。
5. 将结果设置到目标寄存器 `r10` 中。

**预期输出：**

* 寄存器 `r10` 的值为 `0x0000000000000008`。

**用户常见的编程错误：**

在使用类似 LoongArch64 架构进行编程时，或者在理解模拟器行为时，用户可能犯以下错误：

1. **忽略 32 位操作的符号扩展：**  例如，`ADD_W` 是一个 32 位加法，其结果会被符号扩展到 64 位寄存器。如果程序员期望得到一个无符号扩展的结果，可能会出错。

   ```c++
   // 模拟器代码中的 ADD_W
   int32_t alu32_out = static_cast<int32_t>(rj() + rk());
   SetResult(rd_reg(), static_cast<int64_t>(alu32_out)); // 注意符号扩展

   // 用户可能错误的假设
   // 假设 rj() = 0xFFFFFFFF (unsigned -1 in 32-bit)
   // 假设 rk() = 0x00000001
   // alu32_out 结果是 0x00000000 (溢出)
   // 但 SetResult 会将其符号扩展为 0x0000000000000000，而不是用户可能期望的 0xFFFFFFFF00000000。
   ```

2. **除零错误：** 在 `DIV_W`, `DIV_WU`, `DIV_D`, `DIV_DU` 等除法指令中，如果除数为零，会导致错误。模拟器通常会检查这种情况，但实际硬件的行为可能有所不同。

   ```c++
   case DIV_W: {
     // ...
     if (rk_i32 != 0) {
       SetResult(rd_reg(), rj_i32 / rk_i32);
     }
     // 如果 rk_i32 是 0，SetResult 不会被调用，目标寄存器的值不会被修改。
   }
   ```

3. **位运算的优先级问题：**  在复杂的位运算中，如果没有正确理解运算符的优先级，可能会得到意想不到的结果。例如，`rj() | (~rk())` 和 `(rj() | ~rk())` 是等价的，但如果不小心写成其他形式，可能会出错。

4. **内存访问越界：** 虽然模拟器中有 `ProbeMemory` 函数进行检查，但在实际编程中，内存访问越界是一个常见的错误，会导致程序崩溃或产生未定义的行为。

**总结 (针对第 5 部分):**

这段代码片段是 `v8/src/execution/loong64/simulator-loong64.cc` 文件的核心部分，专注于 **模拟 LoongArch64 架构的算术、逻辑、内存访问和浮点运算指令**。它通过一个大的 `switch` 语句来分发指令并执行相应的模拟逻辑。 这部分代码是 V8 引擎在缺乏原生 LoongArch64 支持时，或者在进行调试和测试时，能够执行 JavaScript 代码的关键组成部分。它详细地展示了如何用 C++ 代码来精确地模拟底层硬件指令的行为，包括对 32 位和 64 位整数以及浮点数的处理，以及对内存访问和原子操作的模拟。

Prompt: 
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/loong64/simulator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能

"""
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
                                           
"""


```