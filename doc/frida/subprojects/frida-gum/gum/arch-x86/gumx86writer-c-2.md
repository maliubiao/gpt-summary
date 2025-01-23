Response:
The user wants a summary of the functionalities provided by the C code of `gumx86writer.c`. They also want to understand how these functionalities relate to reverse engineering, low-level binary manipulation, Linux/Android kernel/framework knowledge, logical reasoning, and potential user errors. Finally, they want to understand how a user's actions might lead to this code being executed.

Here's a breakdown of how to address each point:

1. **List Functionalities:**  Go through each function in the code and describe what it does in terms of writing x86 instructions. Focus on the core action of each function.

2. **Relation to Reverse Engineering:**  Think about how the ability to write specific x86 instructions is useful in reverse engineering. Consider scenarios like:
    * Modifying code execution flow (e.g., inserting jumps).
    * Inspecting register values.
    * Injecting custom logic.

3. **Binary/Low-Level Details:**  Highlight aspects of the code that directly deal with manipulating raw bytes representing x86 instructions. Point out how the code constructs these byte sequences based on instruction parameters. Mention the handling of prefixes and opcodes.

4. **Linux/Android Kernel/Framework:** Consider where this type of code manipulation might be used in the context of Linux and Android. Frida is a dynamic instrumentation framework, so think about how it might interact with running processes.
    * Hooking functions.
    * Intercepting system calls.

5. **Logical Reasoning (Hypothetical Input/Output):** For some functions, it's possible to demonstrate the effect of the function by providing example input and the resulting x86 instruction (output). Choose functions that are relatively straightforward.

6. **User/Programming Errors:** Identify potential mistakes a developer using this code might make, such as:
    * Incorrect register sizes.
    * Providing out-of-range immediate values.
    * Using the wrong function for a specific purpose.

7. **User Actions and Debugging:** Explain how a user interacting with Frida (the tool this code is part of) might indirectly trigger the execution of these functions. Trace the path from a high-level Frida action down to the low-level instruction writing.

8. **Summarize Functionality:** Combine the information from point 1 into a concise summary of the overall purpose of the code.

**Mental Walkthrough of the Code:**

Iterate through the provided functions:

* **`gum_x86_writer_put_xchg_reg_reg`:**  Writes the `xchg` instruction to swap register contents.
* **`gum_x86_writer_put_push_u32`:** Writes the `push imm32` instruction.
* **`gum_x86_writer_put_push_near_ptr`:** Writes `push address` instruction, handling 32-bit and 64-bit differences.
* **`gum_x86_writer_put_push_reg`:** Writes `push reg` instruction.
* **`gum_x86_writer_put_pop_reg`:** Writes `pop reg` instruction.
* **`gum_x86_writer_put_push_imm_ptr`:**  Writes `push dword ptr [address]`.
* **`gum_x86_writer_put_pushax`:**  Writes code to push all general-purpose registers (handling 32-bit and 64-bit differences).
* **`gum_x86_writer_put_popax`:** Writes code to pop all general-purpose registers.
* **`gum_x86_writer_put_pushfx`:** Writes `pushfd` or `pushfq`.
* **`gum_x86_writer_put_popfx`:** Writes `popfd` or `popfq`.
* **`gum_x86_writer_put_sahf`:** Writes `sahf`.
* **`gum_x86_writer_put_lahf`:** Writes `lahf`.
* **`gum_x86_writer_put_test_reg_reg`:** Writes `test reg, reg`.
* **`gum_x86_writer_put_test_reg_u32`:** Writes `test reg, imm32`.
* **`gum_x86_writer_put_cmp_reg_i32`:** Writes `cmp reg, imm32`.
* **`gum_x86_writer_put_cmp_reg_offset_ptr_reg`:** Writes `cmp [reg+offset], reg`.
* **`gum_x86_writer_put_cmp_imm_ptr_imm_u32`:** Writes `cmp dword ptr [address], imm32`.
* **`gum_x86_writer_put_cmp_reg_reg`:** Writes `cmp reg, reg`.
* **`gum_x86_writer_put_clc`, `stc`, `cld`, `std`:** Writes instructions to manipulate flag bits.
* **`gum_x86_writer_put_cpuid`:** Writes `cpuid`.
* **`gum_x86_writer_put_lfence`:** Writes `lfence`.
* **`gum_x86_writer_put_rdtsc`:** Writes `rdtsc`.
* **`gum_x86_writer_put_pause`:** Writes `pause`.
* **`gum_x86_writer_put_nop`:** Writes `nop`.
* **`gum_x86_writer_put_breakpoint`:** Writes `int 3`.
* **`gum_x86_writer_put_padding`, `gum_x86_writer_put_nop_padding`:** Writes padding bytes or optimized NOP sequences.
* **`gum_x86_writer_put_fxsave_reg_ptr`, `gum_x86_writer_put_fxrstor_reg_ptr`:** Writes `fxsave` and `fxrstor`.
* **`gum_x86_writer_put_fx_save_or_restore_reg_ptr`:** Helper for `fxsave` and `fxrstor`.
* **`gum_x86_writer_put_u8`, `gum_x86_writer_put_s8`, `gum_x86_writer_put_bytes`:**  Writes raw byte values.
* **`gum_x86_writer_describe_cpu_reg`, `gum_meta_reg_from_cpu_reg`:** Helper functions to get register information.
* **`gum_x86_writer_put_prefix_for_reg_info`, `gum_x86_writer_put_prefix_for_registers`:** Helper functions to write instruction prefixes.
* **`gum_get_jcc_opcode`:** Helper function to get opcode for conditional jumps.

Now, structure the response based on the initial requirements.
这是 `frida/subprojects/frida-gum/gum/arch-x86/gumx86writer.c` 文件的第三部分，延续了之前两个部分的功能，主要负责生成 x86 架构的机器码指令。以下是这部分代码的功能归纳和相关说明：

**功能归纳:**

这部分代码主要提供了以下功能，用于向内存中写入特定的 x86 指令序列：

* **交换寄存器值:** `gum_x86_writer_put_xchg_reg_reg` 用于生成 `xchg` 指令，交换两个寄存器的内容。
* **压栈操作:**
    * `gum_x86_writer_put_push_u32`: 生成 `push imm32` 指令，将一个 32 位立即数压入栈。
    * `gum_x86_writer_put_push_near_ptr`: 生成 `push address` 指令，将一个近指针（地址）压入栈。根据目标 CPU 是 32 位还是 64 位，地址的处理方式不同。
    * `gum_x86_writer_put_push_reg`: 生成 `push reg` 指令，将一个寄存器的值压入栈。
    * `gum_x86_writer_put_push_imm_ptr`: 生成 `push dword ptr [address]` 指令，将指定内存地址的内容（32 位）压入栈。
    * `gum_x86_writer_put_pushax`:  根据目标 CPU 生成压入所有通用寄存器的指令序列。在 32 位系统上是 `pusha`，在 64 位系统上会逐个压入 `rax`, `rcx`, `rdx`, `rbx`, `rsp`, `rbp`, `rsi`, `rdi`, `r8`-`r15`。
* **出栈操作:** `gum_x86_writer_put_pop_reg`: 生成 `pop reg` 指令，将栈顶的值弹出到指定寄存器。
    * `gum_x86_writer_put_popax`: 根据目标 CPU 生成弹出所有通用寄存器的指令序列，与 `gum_x86_writer_put_pushax` 相对应。
* **标志位操作:**
    * `gum_x86_writer_put_pushfx`: 生成 `pushfd` (32 位) 或 `pushfq` (64 位) 指令，将标志寄存器压入栈。
    * `gum_x86_writer_put_popfx`: 生成 `popfd` 或 `popfq` 指令，将栈顶值弹出到标志寄存器。
    * `gum_x86_writer_put_sahf`: 生成 `sahf` 指令，将 `ah` 寄存器的低 8 位加载到标志寄存器的低 8 位。
    * `gum_x86_writer_put_lahf`: 生成 `lahf` 指令，将标志寄存器的低 8 位加载到 `ah` 寄存器。
* **测试指令:**
    * `gum_x86_writer_put_test_reg_reg`: 生成 `test reg, reg` 指令，对两个寄存器的值进行按位与操作，并根据结果设置标志位。
    * `gum_x86_writer_put_test_reg_u32`: 生成 `test reg, imm32` 指令，对寄存器值和 32 位立即数进行按位与操作。
* **比较指令:**
    * `gum_x86_writer_put_cmp_reg_i32`: 生成 `cmp reg, imm32` 指令，比较寄存器值和 32 位有符号立即数。
    * `gum_x86_writer_put_cmp_reg_offset_ptr_reg`: 生成 `cmp [reg+offset], reg` 指令，比较内存地址的值和寄存器的值。
    * `gum_x86_writer_put_cmp_imm_ptr_imm_u32`: 生成 `cmp dword ptr [address], imm32` 指令，比较内存地址的值和 32 位立即数。
    * `gum_x86_writer_put_cmp_reg_reg`: 生成 `cmp reg, reg` 指令，比较两个寄存器的值。
* **标志位设置/清除指令:**
    * `gum_x86_writer_put_clc`: 生成 `clc` 指令，清除进位标志位。
    * `gum_x86_writer_put_stc`: 生成 `stc` 指令，设置进位标志位。
    * `gum_x86_writer_put_cld`: 生成 `cld` 指令，清除方向标志位。
    * `gum_x86_writer_put_std`: 生成 `std` 指令，设置方向标志位。
* **其他指令:**
    * `gum_x86_writer_put_cpuid`: 生成 `cpuid` 指令，获取 CPU 信息。
    * `gum_x86_writer_put_lfence`: 生成 `lfence` 指令，内存屏障，保证之前的加载操作完成。
    * `gum_x86_writer_put_rdtsc`: 生成 `rdtsc` 指令，读取时间戳计数器。
    * `gum_x86_writer_put_pause`: 生成 `pause` 指令，用于优化自旋锁。
    * `gum_x86_writer_put_nop`: 生成 `nop` 指令，空操作。
    * `gum_x86_writer_put_breakpoint`: 生成 `int 3` 指令，断点。
    * `gum_x86_writer_put_padding`: 写入指定数量的 `0xcc` 字节，通常用于填充。
    * `gum_x86_writer_put_nop_padding`: 写入优化的 `nop` 指令序列，以更有效地进行填充。
    * `gum_x86_writer_put_fxsave_reg_ptr`: 生成 `fxsave [reg]` 指令，保存 FPU/SSE 状态到指定内存地址。
    * `gum_x86_writer_put_fxrstor_reg_ptr`: 生成 `fxrstor [reg]` 指令，从指定内存地址恢复 FPU/SSE 状态。
* **底层写入:**
    * `gum_x86_writer_put_u8`, `gum_x86_writer_put_s8`, `gum_x86_writer_put_bytes`: 直接写入字节数据。
* **辅助函数:**
    * `gum_x86_writer_describe_cpu_reg`: 获取寄存器的信息，如宽度、索引等。
    * `gum_meta_reg_from_cpu_reg`: 将 CPU 寄存器枚举转换为元寄存器枚举。
    * `gum_x86_writer_put_prefix_for_reg_info`, `gum_x86_writer_put_prefix_for_registers`:  处理指令前缀，例如用于访问扩展寄存器或指定操作数大小。
    * `gum_get_jcc_opcode`: 获取条件跳转指令的 opcode。

**与逆向方法的关联及举例说明:**

这个文件是 Frida 动态插桩工具的核心组成部分，其功能与逆向工程紧密相关。逆向工程师经常需要动态地修改目标程序的执行流程或插入自定义代码来分析其行为。`gumx86writer.c` 提供的功能正是实现这些目标的基础。

* **代码注入和Hook:**  逆向工程师可以使用这些函数生成跳转指令 (`jmp`, `call`) 或其他指令来替换目标程序原有的指令，实现函数 Hook。
    * **例子:**  假设要 Hook 函数 `foo`，可以在 `foo` 函数的入口处写入 `gum_x86_writer_put_jmp_near` 指令，使其跳转到自定义的 Hook 函数。
* **动态修改寄存器和内存:**  通过生成 `mov` 指令修改寄存器的值，或者通过 `push` 和 `pop` 指令在栈上操作数据，可以观察或改变程序的运行状态。
    * **例子:** 使用 `gum_x86_writer_put_mov_reg_imm` 在目标函数执行前修改某个关键寄存器的值，观察程序行为的变化。
* **插入断点:** 使用 `gum_x86_writer_put_breakpoint` 插入 `int 3` 指令，当程序执行到此处时会触发调试器，方便逆向分析。
* **分析代码逻辑:**  生成 `cmp` 和 `test` 指令可以用来检查特定条件是否满足，这在动态分析程序分支逻辑时很有用。
    * **例子:**  在某个条件判断语句之前插入 `gum_x86_writer_put_cmp_reg_imm`，比较关键寄存器的值，并根据标志位判断程序接下来会执行哪个分支。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制指令编码:**  代码直接操作字节码，例如 `self->code[0] = 0x87; self->code[1] = 0x00 | (left.index << 3) | right.index;`  就是直接构造 `xchg` 指令的二进制编码。理解 x86 指令集的编码格式是使用这些功能的基础。
* **寄存器和内存操作:** 代码中大量使用了 `GumX86Reg` 枚举来表示 x86 寄存器，并根据目标 CPU 的架构（32 位或 64 位）生成不同的指令。这需要了解不同架构下的寄存器命名和宽度。
* **栈的操作:** `push` 和 `pop` 指令直接操作程序的栈，理解栈的增长方向和用途对于使用这些函数至关重要。
* **函数调用约定:**  `gum_x86_writer_put_pushax` 和 `gum_x86_writer_put_popax` 的实现体现了对函数调用约定的理解。在 64 位系统中，需要保存和恢复更多的寄存器。
* **内存地址表示:** `GumAddress` 用于表示内存地址，并且在 `gum_x86_writer_put_push_near_ptr` 中，根据目标架构的不同，地址的处理方式也不同，体现了对内存寻址方式的理解。
* **Linux/Android 进程内存空间:** Frida 作为用户态工具，其插桩操作涉及到对目标进程内存空间的修改。这些函数生成的指令会被写入到目标进程的内存中并执行。
* **内核交互 (间接):** 虽然这些代码本身运行在用户态，但 Frida 的动态插桩机制可能需要通过系统调用与内核进行交互，例如修改进程的内存保护属性，以便写入和执行注入的代码。

**逻辑推理及假设输入与输出:**

以 `gum_x86_writer_put_push_u32` 函数为例：

* **假设输入:** `self->target_cpu = GUM_CPU_IA32` (32位架构), `imm_value = 0x12345678`
* **输出:**  `self->code` 数组的前 5 个字节将被填充为 `0x68 0x78 0x56 0x34 0x12` (小端序)。
    * `0x68` 是 `push imm32` 的 opcode。
    * `0x78 0x56 0x34 0x12` 是 `0x12345678` 的小端序表示。

以 `gum_x86_writer_put_xchg_reg_reg` 函数为例：

* **假设输入:** `left.index = 0` (代表 `eax`/`rax`), `right.index = 1` (代表 `ecx`/`rcx`), `self->target_cpu = GUM_CPU_IA32`
* **输出:** `self->code` 数组的前 2 个字节将被填充为 `0x87 0xc8`。
    * `0x87` 是 `xchg r/m32, r32` 的 opcode。
    * `0xc8` 是 ModR/M 字节，其中 Mod=11（寄存器模式），Reg=000 (eax)，R/M=001 (ecx)。

**涉及用户或者编程常见的使用错误及举例说明:**

* **寄存器宽度不匹配:**  在调用某些函数时，如果提供的寄存器宽度与目标 CPU 不符，函数会返回 `FALSE`。
    * **例子:** 在 64 位系统上调用 `gum_x86_writer_put_push_reg(self, GUM_X86_EAX)`，由于 `EAX` 是 32 位寄存器，该函数会返回 `FALSE`，因为期望的是 64 位寄存器。
* **立即数超出范围:** 对于需要指定立即数的指令，如果提供的立即数超出了该指令所能表示的范围，可能会导致生成的指令不正确或无法执行。虽然代码中对部分情况有检查（例如 `gum_x86_writer_put_push_near_ptr` 对 32 位地址的检查），但并非所有情况都有完善的错误处理。
* **错误地使用辅助函数:**  错误地使用 `gum_x86_writer_put_prefix_for_registers` 可能会导致生成错误的指令前缀。
* **目标缓冲区溢出:** 如果用户提供的缓冲区空间不足以容纳生成的指令序列，可能会导致内存溢出。`gum_x86_writer_commit` 函数负责更新写入位置，但调用者需要确保缓冲区足够大。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户使用 Frida API:** 用户通过 Python 或 JavaScript 编写 Frida 脚本，调用 Frida 提供的 API 来进行动态插桩。例如，使用 `Interceptor.attach` 来 Hook 某个函数。
2. **Frida Core 处理用户请求:** Frida 的核心组件接收到用户的 Hook 请求，并分析目标进程和目标函数的信息。
3. **Gum 框架介入:** Frida 的核心会调用 Gum 框架（Frida Gum）提供的功能来实现底层的插桩操作。
4. **GumX86Writer 的使用:**  在需要修改目标进程的代码时，Gum 框架会使用 `GumX86Writer` 提供的函数来生成 x86 指令。例如，在 Hook 函数时，需要生成跳转到 Hook 函数的指令，或者在函数入口处保存寄存器状态。
5. **调用 `gumx86writer.c` 中的函数:**  根据需要生成的具体指令，Gum 框架会调用 `gumx86writer.c` 中相应的函数，例如 `gum_x86_writer_put_jmp_near` 或 `gum_x86_writer_put_push_reg`。
6. **写入目标进程内存:**  `GumX86Writer` 的函数会将生成的机器码写入到与目标进程关联的内存缓冲区中。
7. **激活修改后的代码:** Frida 会确保修改后的代码能够被目标进程执行，例如通过修改内存保护属性或刷新指令缓存。

**调试线索:** 当你在调试 Frida 脚本时，如果发现目标进程执行了意想不到的代码，或者发生了崩溃，可以检查 Frida 生成的机器码是否正确。你可以通过以下方式作为调试线索：

* **查看 Frida 的日志输出:** Frida 可能会输出一些关于代码修改的信息。
* **使用反汇编工具:** 在调试器中查看目标进程被修改的内存区域，反汇编这些代码，看是否与 `gumx86writer.c` 生成的指令一致。
* **单步执行:** 在调试器中单步执行目标进程的代码，观察其执行流程是否符合预期。
* **检查 `GumX86Writer` 的使用方式:** 确认 Frida 内部调用 `GumX86Writer` 的参数是否正确，例如目标地址、寄存器参数、立即数值等。

总而言之，`gumx86writer.c` 的这部分代码是 Frida 实现动态代码生成和修改的关键，它提供了丰富的接口来构建各种 x86 指令序列，使得 Frida 能够灵活地对目标进程进行插桩和分析。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/arch-x86/gumx86writer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
_reg (self, right_reg, &right);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (right.width != 32)
      return FALSE;
  }
  else
  {
    if (right.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_reg_info (self, &left, 1))
    return FALSE;

  self->code[0] = 0x87;
  self->code[1] = 0x00 | (left.index << 3) | right.index;
  gum_x86_writer_commit (self, 2);

  if (right.meta == GUM_X86_META_XSP)
  {
    gum_x86_writer_put_u8 (self, 0x24);
  }
  else if (right.meta == GUM_X86_META_XBP)
  {
    self->code[-1] |= 0x40;
    gum_x86_writer_put_u8 (self, 0x00);
  }

  return TRUE;
}

void
gum_x86_writer_put_push_u32 (GumX86Writer * self,
                             guint32 imm_value)
{
  self->code[0] = 0x68;
  *((guint32 *) (self->code + 1)) = GUINT32_TO_LE (imm_value);
  gum_x86_writer_commit (self, 5);
}

gboolean
gum_x86_writer_put_push_near_ptr (GumX86Writer * self,
                                  GumAddress address)
{
  self->code[0] = 0xff;
  self->code[1] = 0x35;

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (address > G_MAXUINT32)
      return FALSE;
    *((guint32 *) (self->code + 2)) = GUINT32_TO_LE ((guint32) address);
  }
  else
  {
    gint64 distance = (gint64) address - (gint64) (self->pc + 6);
    if (distance < G_MININT32 || distance > G_MAXINT32)
      return FALSE;
    *((gint32 *) (self->code + 2)) = GINT32_TO_LE ((gint32) distance);
  }

  gum_x86_writer_commit (self, 6);

  return TRUE;
}

gboolean
gum_x86_writer_put_push_reg (GumX86Writer * self,
                             GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  gum_x86_writer_put_u8 (self, 0x50 | ri.index);

  return TRUE;
}

gboolean
gum_x86_writer_put_pop_reg (GumX86Writer * self,
                            GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  gum_x86_writer_put_u8 (self, 0x58 | ri.index);

  return TRUE;
}

void
gum_x86_writer_put_push_imm_ptr (GumX86Writer * self,
                                 gconstpointer imm_ptr)
{
  self->code[0] = 0xff;
  self->code[1] = 0x35;
  *((guint32 *) (self->code + 2)) = GUINT32_TO_LE (GUM_ADDRESS (imm_ptr));
  gum_x86_writer_commit (self, 6);
}

void
gum_x86_writer_put_pushax (GumX86Writer * self)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    gum_x86_writer_put_u8 (self, 0x60);
  }
  else
  {
    gum_x86_writer_put_push_reg (self, GUM_X86_RAX);
    gum_x86_writer_put_push_reg (self, GUM_X86_RCX);
    gum_x86_writer_put_push_reg (self, GUM_X86_RDX);
    gum_x86_writer_put_push_reg (self, GUM_X86_RBX);

    gum_x86_writer_put_lea_reg_reg_offset (self, GUM_X86_RAX,
        GUM_X86_RSP, 4 * 8);
    gum_x86_writer_put_push_reg (self, GUM_X86_RAX);
    gum_x86_writer_put_mov_reg_reg_offset_ptr (self, GUM_X86_RAX,
        GUM_X86_RSP, 4 * 8);

    gum_x86_writer_put_push_reg (self, GUM_X86_RBP);
    gum_x86_writer_put_push_reg (self, GUM_X86_RSI);
    gum_x86_writer_put_push_reg (self, GUM_X86_RDI);

    gum_x86_writer_put_push_reg (self, GUM_X86_R8);
    gum_x86_writer_put_push_reg (self, GUM_X86_R9);
    gum_x86_writer_put_push_reg (self, GUM_X86_R10);
    gum_x86_writer_put_push_reg (self, GUM_X86_R11);
    gum_x86_writer_put_push_reg (self, GUM_X86_R12);
    gum_x86_writer_put_push_reg (self, GUM_X86_R13);
    gum_x86_writer_put_push_reg (self, GUM_X86_R14);
    gum_x86_writer_put_push_reg (self, GUM_X86_R15);
  }
}

void
gum_x86_writer_put_popax (GumX86Writer * self)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    gum_x86_writer_put_u8 (self, 0x61);
  }
  else
  {
    gum_x86_writer_put_pop_reg (self, GUM_X86_R15);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R14);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R13);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R12);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R11);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R10);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R9);
    gum_x86_writer_put_pop_reg (self, GUM_X86_R8);

    gum_x86_writer_put_pop_reg (self, GUM_X86_RDI);
    gum_x86_writer_put_pop_reg (self, GUM_X86_RSI);
    gum_x86_writer_put_pop_reg (self, GUM_X86_RBP);
    gum_x86_writer_put_lea_reg_reg_offset (self, GUM_X86_RSP, GUM_X86_RSP, 8);
    gum_x86_writer_put_pop_reg (self, GUM_X86_RBX);
    gum_x86_writer_put_pop_reg (self, GUM_X86_RDX);
    gum_x86_writer_put_pop_reg (self, GUM_X86_RCX);
    gum_x86_writer_put_pop_reg (self, GUM_X86_RAX);
  }
}

void
gum_x86_writer_put_pushfx (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0x9c);
}

void
gum_x86_writer_put_popfx (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0x9d);
}

void
gum_x86_writer_put_sahf (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0x9e);
}

void
gum_x86_writer_put_lahf (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0x9f);
}

gboolean
gum_x86_writer_put_test_reg_reg (GumX86Writer * self,
                                 GumX86Reg reg_a,
                                 GumX86Reg reg_b)
{
  GumX86RegInfo a, b;

  gum_x86_writer_describe_cpu_reg (self, reg_a, &a);
  gum_x86_writer_describe_cpu_reg (self, reg_b, &b);

  if (a.width != b.width)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_registers (self, &a, 32, &a, &b, NULL))
    return FALSE;

  self->code[0] = 0x85;
  self->code[1] = 0xc0 | (b.index << 3) | a.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_test_reg_u32 (GumX86Writer * self,
                                 GumX86Reg reg,
                                 guint32 imm_value)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  if (ri.meta == GUM_X86_META_XAX)
  {
    self->code[0] = 0xa9;
    *((guint32 *) (self->code + 1)) = GUINT32_TO_LE (imm_value);
    gum_x86_writer_commit (self, 5);
  }
  else
  {
    self->code[0] = 0xf7;
    self->code[1] = 0xc0 | ri.index;
    *((guint32 *) (self->code + 2)) = GUINT32_TO_LE (imm_value);
    gum_x86_writer_commit (self, 6);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_cmp_reg_i32 (GumX86Writer * self,
                                GumX86Reg reg,
                                gint32 imm_value)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  if (ri.meta == GUM_X86_META_XAX)
  {
    gum_x86_writer_put_u8 (self, 0x3d);
  }
  else
  {
    self->code[0] = 0x81;
    self->code[1] = 0xf8 | ri.index;
    gum_x86_writer_commit (self, 2);
  }

  *((gint32 *) self->code) = GINT32_TO_LE (imm_value);
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

gboolean
gum_x86_writer_put_cmp_reg_offset_ptr_reg (GumX86Writer * self,
                                           GumX86Reg reg_a,
                                           gssize offset,
                                           GumX86Reg reg_b)
{
  GumX86RegInfo a, b;
  gboolean offset_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, reg_a, &a);
  gum_x86_writer_describe_cpu_reg (self, reg_b, &b);

  if (!gum_x86_writer_put_prefix_for_registers (self, &a, 32, &a, &b, NULL))
    return FALSE;

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (offset);

  self->code[0] = 0x39;
  self->code[1] = (offset_fits_in_i8 ? 0x40 : 0x80) | (b.index << 3) | a.index;
  gum_x86_writer_commit (self, 2);

  if (a.index == 4)
    gum_x86_writer_put_u8 (self, 0x24);

  if (offset_fits_in_i8)
  {
    gum_x86_writer_put_s8 (self, offset);
  }
  else
  {
    *((gint32 *) self->code) = GINT32_TO_LE (offset);
    gum_x86_writer_commit (self, 4);
  }

  return TRUE;
}

void
gum_x86_writer_put_cmp_imm_ptr_imm_u32 (GumX86Writer * self,
                                        gconstpointer imm_ptr,
                                        guint32 imm_value)
{
  self->code[0] = 0x81;
  self->code[1] = 0x3d;
  *((guint32 *) (self->code + 2)) = GUINT32_TO_LE (GUM_ADDRESS (imm_ptr));
  *((guint32 *) (self->code + 6)) = GUINT32_TO_LE (imm_value);
  gum_x86_writer_commit (self, 10);
}

gboolean
gum_x86_writer_put_cmp_reg_reg (GumX86Writer * self,
                                GumX86Reg reg_a,
                                GumX86Reg reg_b)
{
  GumX86RegInfo a, b;

  gum_x86_writer_describe_cpu_reg (self, reg_a, &a);
  gum_x86_writer_describe_cpu_reg (self, reg_b, &b);

  if (a.width != b.width)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_registers (self, &a, 32, &a, &b, NULL))
    return FALSE;

  self->code[0] = 0x39;
  self->code[1] = 0xc0 | (b.index << 3) | a.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

void
gum_x86_writer_put_clc (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xf8);
}

void
gum_x86_writer_put_stc (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xf9);
}

void
gum_x86_writer_put_cld (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xfc);
}

void
gum_x86_writer_put_std (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xfd);
}

void
gum_x86_writer_put_cpuid (GumX86Writer * self)
{
  self->code[0] = 0x0f;
  self->code[1] = 0xa2;
  gum_x86_writer_commit (self, 2);
}

void
gum_x86_writer_put_lfence (GumX86Writer * self)
{
  self->code[0] = 0x0f;
  self->code[1] = 0xae;
  self->code[2] = 0xe8;
  gum_x86_writer_commit (self, 3);
}

void
gum_x86_writer_put_rdtsc (GumX86Writer * self)
{
  self->code[0] = 0x0f;
  self->code[1] = 0x31;
  gum_x86_writer_commit (self, 2);
}

void
gum_x86_writer_put_pause (GumX86Writer * self)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x90;
  gum_x86_writer_commit (self, 2);
}

void
gum_x86_writer_put_nop (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0x90);
}

void
gum_x86_writer_put_breakpoint (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xcc);
}

void
gum_x86_writer_put_padding (GumX86Writer * self,
                            guint n)
{
  gum_memset (self->code, 0xcc, n);
  gum_x86_writer_commit (self, n);
}

/*
 * Whilst the 0x90 opcode for NOP is commonly known, the Intel Optimization
 * Manual actually lists a number of different NOP instructions ranging from
 * one to nine bytes in length. By using longer NOP instructions, we can more
 * efficiently pad unused space with the processor being able to skip more
 * bytes per execution cycle.
 */
void
gum_x86_writer_put_nop_padding (GumX86Writer * self,
                                guint n)
{
  static const struct {
    guint8 one[1];
    guint8 two[2];
    guint8 three[3];
    guint8 four[4];
    guint8 five[5];
    guint8 six[6];
    guint8 seven[7];
    guint8 eight[8];
    guint8 nine[9];
  } nops = {
    /* NOP */
    .one =   { 0x90 },
    /* 66 NOP */
    .two =   { 0x66, 0x90 },
    /* NOP DWORD ptr [EAX] */
    .three = { 0x0f, 0x1f, 0x00 },
    /* NOP DWORD ptr [EAX + 00H] */
    .four =  { 0x0f, 0x1f, 0x40, 0x00 },
    /* NOP DWORD ptr [EAX + EAX*1 + 00H] */
    .five =  { 0x0f, 0x1f, 0x44, 0x00, 0x00 },
    /* 66 NOP DWORD ptr [EAX + EAX*1 + 00H] */
    .six =   { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 },
    /* NOP DWORD ptr [EAX + 00000000H] */
    .seven = { 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 },
    /* NOP DWORD ptr [EAX + EAX*1 + 00000000H] */
    .eight = { 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 66 NOP DWORD ptr [EAX + EAX*1 + 00000000H] */
    .nine =  { 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
  };
  static const guint8 * nop_index[9] = {
    nops.one,
    nops.two,
    nops.three,
    nops.four,
    nops.five,
    nops.six,
    nops.seven,
    nops.eight,
    nops.nine,
  };
  static const guint max_nop = G_N_ELEMENTS (nop_index);
  guint remaining;

  for (remaining = n; remaining != 0; remaining -= max_nop)
  {
    if (remaining < max_nop)
    {
      gum_memcpy (self->code, nop_index[remaining - 1], remaining);
      gum_x86_writer_commit (self, remaining);
      break;
    }

    gum_memcpy (self->code, nop_index[max_nop - 1], max_nop);
    gum_x86_writer_commit (self, max_nop);
  }
}

gboolean
gum_x86_writer_put_fxsave_reg_ptr (GumX86Writer * self,
                                   GumX86Reg reg)
{
  return gum_x86_writer_put_fx_save_or_restore_reg_ptr (self, 0, reg);
}

gboolean
gum_x86_writer_put_fxrstor_reg_ptr (GumX86Writer * self,
                                    GumX86Reg reg)
{
  return gum_x86_writer_put_fx_save_or_restore_reg_ptr (self, 1, reg);
}

static gboolean
gum_x86_writer_put_fx_save_or_restore_reg_ptr (GumX86Writer * self,
                                               guint8 operation,
                                               GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32 || ri.index_is_extended)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  self->code[0] = 0x0f;
  self->code[1] = 0xae;
  self->code[2] = (operation << 3) | ri.index;
  gum_x86_writer_commit (self, 3);

  if (ri.index == 4)
    gum_x86_writer_put_u8 (self, 0x24);

  return TRUE;
}

void
gum_x86_writer_put_u8 (GumX86Writer * self,
                       guint8 value)
{
  *self->code = value;
  gum_x86_writer_commit (self, 1);
}

void
gum_x86_writer_put_s8 (GumX86Writer * self,
                       gint8 value)
{
  *((gint8 *) self->code) = value;
  gum_x86_writer_commit (self, 1);
}

void
gum_x86_writer_put_bytes (GumX86Writer * self,
                          const guint8 * data,
                          guint n)
{
  gum_memcpy (self->code, data, n);
  gum_x86_writer_commit (self, n);
}

static void
gum_x86_writer_describe_cpu_reg (GumX86Writer * self,
                                 GumX86Reg reg,
                                 GumX86RegInfo * ri)
{
  if (reg >= GUM_X86_XAX && reg <= GUM_X86_XDI)
  {
    if (self->target_cpu == GUM_CPU_IA32)
      reg = (GumX86Reg) (GUM_X86_EAX + reg - GUM_X86_XAX);
    else
      reg = (GumX86Reg) (GUM_X86_RAX + reg - GUM_X86_XAX);
  }

  ri->meta = gum_meta_reg_from_cpu_reg (reg);

  if (reg >= GUM_X86_RAX && reg <= GUM_X86_R15)
  {
    ri->width = 64;

    if (reg < GUM_X86_R8)
    {
      ri->index = reg - GUM_X86_RAX;
      ri->index_is_extended = FALSE;
    }
    else
    {
      ri->index = reg - GUM_X86_R8;
      ri->index_is_extended = TRUE;
    }
  }
  else
  {
    ri->width = 32;

    if (reg < GUM_X86_R8D)
    {
      ri->index = reg - GUM_X86_EAX;
      ri->index_is_extended = FALSE;
    }
    else
    {
      ri->index = reg - GUM_X86_R8D;
      ri->index_is_extended = TRUE;
    }
  }
}

static GumX86MetaReg
gum_meta_reg_from_cpu_reg (GumX86Reg reg)
{
  if (reg >= GUM_X86_EAX && reg <= GUM_X86_R15D)
    return (GumX86MetaReg) (GUM_X86_META_XAX + reg - GUM_X86_EAX);

  if (reg >= GUM_X86_RAX && reg <= GUM_X86_R15)
    return (GumX86MetaReg) (GUM_X86_META_XAX + reg - GUM_X86_RAX);

  return (GumX86MetaReg) (GUM_X86_META_XAX + reg - GUM_X86_XAX);
}

static gboolean
gum_x86_writer_put_prefix_for_reg_info (GumX86Writer * self,
                                        const GumX86RegInfo * ri,
                                        guint operand_index)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri->width != 32 || ri->index_is_extended)
      return FALSE;
  }
  else
  {
    guint mask;

    mask = 1 << (operand_index * 2);

    if (ri->width == 32)
    {
      if (ri->index_is_extended)
        gum_x86_writer_put_u8 (self, 0x40 | mask);
    }
    else
    {
      gum_x86_writer_put_u8 (self,
          (ri->index_is_extended) ? 0x48 | mask : 0x48);
    }
  }

  return TRUE;
}

/* TODO: improve this function and get rid of the one above */
static gboolean
gum_x86_writer_put_prefix_for_registers (GumX86Writer * self,
                                         const GumX86RegInfo * width_reg,
                                         guint default_width,
                                         ...)
{
  const GumX86RegInfo * ra, * rb, * rc;
  va_list args;

  va_start (args, default_width);

  ra = va_arg (args, const GumX86RegInfo *);
  g_assert (ra != NULL);

  rb = va_arg (args, const GumX86RegInfo *);
  if (rb != NULL)
  {
    rc = va_arg (args, const GumX86RegInfo *);
  }
  else
  {
    rc = NULL;
  }

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ra->width != 32 || ra->index_is_extended)
      return FALSE;
    if (rb != NULL && (rb->width != 32 || rb->index_is_extended))
      return FALSE;
    if (rc != NULL && (rc->width != 32 || rc->index_is_extended))
      return FALSE;
  }
  else
  {
    guint nibble = 0;

    if (width_reg->width != default_width)
      nibble |= 0x8;
    if (rb != NULL && rb->index_is_extended)
      nibble |= 0x4;
    if (rc != NULL && rc->index_is_extended)
      nibble |= 0x2;
    if (ra->index_is_extended)
      nibble |= 0x1;

    if (nibble != 0)
      gum_x86_writer_put_u8 (self, 0x40 | nibble);
  }

  return TRUE;
}

static guint8
gum_get_jcc_opcode (x86_insn instruction_id)
{
  switch (instruction_id)
  {
    case X86_INS_JO:
      return 0x70;
    case X86_INS_JNO:
      return 0x71;
    case X86_INS_JB:
      return 0x72;
    case X86_INS_JAE:
      return 0x73;
    case X86_INS_JE:
      return 0x74;
    case X86_INS_JNE:
      return 0x75;
    case X86_INS_JBE:
      return 0x76;
    case X86_INS_JA:
      return 0x77;
    case X86_INS_JS:
      return 0x78;
    case X86_INS_JNS:
      return 0x79;
    case X86_INS_JP:
      return 0x7a;
    case X86_INS_JNP:
      return 0x7b;
    case X86_INS_JL:
      return 0x7c;
    case X86_INS_JGE:
      return 0x7d;
    case X86_INS_JLE:
      return 0x7e;
    case X86_INS_JG:
      return 0x7f;
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    default:
      return 0xe3;
  }
}
```