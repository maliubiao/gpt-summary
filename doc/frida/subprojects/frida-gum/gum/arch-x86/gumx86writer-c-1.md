Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of Frida, a dynamic instrumentation toolkit. I need to identify the core purpose of the code and relate it to reverse engineering concepts, low-level details, and potential user errors.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The code contains functions with names like `gum_x86_writer_put_...`. The `put_` prefix strongly suggests these functions are responsible for writing specific x86 instructions to a buffer. The `GumX86Writer` likely manages this buffer and keeps track of the current position. Therefore, the primary function is **dynamically generating x86 machine code**.

2. **Relate to reverse engineering:** Dynamic code generation is crucial for instrumentation. To modify the behavior of a running program, Frida needs to insert its own code. This code often intercepts function calls, modifies data, or alters control flow. This directly relates to reverse engineering by enabling *dynamic analysis*, where you observe program behavior as it runs.

3. **Identify low-level aspects:**
    * **Binary/Machine Code:** The functions operate on opcodes (e.g., `0x0f`, `0x0b`) and handle instruction formats. This is inherently low-level.
    * **x86 Architecture:** The code is specific to the x86 architecture, dealing with registers (`GumX86Reg`), instruction encodings, and addressing modes.
    * **Memory Management:**  The writer manages a buffer (`self->code`) and keeps track of the program counter (`self->pc`). This involves low-level memory manipulation.
    * **Endianness:** The use of `GINT32_TO_LE` indicates awareness of little-endian byte order.
    * **Branch Prediction:** The comment about `UD2` explicitly mentions branch prediction, a microarchitectural detail.

4. **Consider Linux/Android relevance:** While the code itself isn't OS-specific, dynamic instrumentation is heavily used in these environments for tasks like debugging, security analysis, and API hooking. Frida, in particular, is popular on both platforms. The concepts of process memory and code injection are relevant here.

5. **Look for logic and potential input/output:** The functions generally take an instruction type (`x86_insn`), target address/label, and sometimes hints. They output boolean values indicating success or failure. For example, `gum_x86_writer_put_jcc_short` attempts to write a short jump; if the target is too far, it returns `FALSE`. I can create an example of a successful and unsuccessful call.

6. **Identify potential user errors:**  The functions have preconditions, like register width matching or offsets being within a certain range. Trying to add registers of different sizes or providing an out-of-range jump target will lead to `FALSE` being returned. This represents a programming error by the user of the `GumX86Writer` API.

7. **Trace user operations:**  How does a user's action lead to this code?  A user interacting with Frida's Python API might request to intercept a function. Frida would then use this `gumx86writer.c` code to generate the necessary detour instructions to redirect execution to Frida's handler.

8. **Summarize the functionality:** Based on the above points, I can now synthesize a concise summary of the code's purpose and its role in Frida.

9. **Structure the answer:** Organize the information into clear sections addressing each aspect of the prompt (functionality, reverse engineering, low-level details, logic/I-O, user errors, user operations, and finally, a concise summary for part 2).

**(Self-Correction/Refinement):** Initially, I might focus too much on the individual instruction writing functions. It's important to step back and recognize the *higher-level* goal of dynamic code generation for instrumentation. Also, while the code doesn't directly interact with the Linux/Android kernel, the *context* of its usage (Frida) is strongly tied to these platforms. I need to make that connection explicit.
这是 frida 动态 instrumentation 工具中 `gumx86writer.c` 文件的一部分，主要负责 **生成 x86 架构的机器码指令**。  它提供了一系列函数，用于将各种 x86 指令以二进制形式写入到内存缓冲区中。

**以下是这段代码的功能归纳：**

* **条件跳转指令生成 (Conditional Jumps):**
    * `gum_x86_writer_put_jcc_short`: 生成短跳转指令（目标地址在 -128 到 127 字节范围内）。
    * `gum_x86_writer_put_jcc_near`: 生成近跳转指令（目标地址在 -2GB 到 2GB 范围内）。
    * `gum_x86_writer_put_jcc_short_label`, `gum_x86_writer_put_jcc_near_label`: 生成基于标签的条件跳转指令，在生成指令时先占位，后续通过标签解析确定跳转目标地址。
* **算术运算指令生成 (Arithmetic Operations):**
    * `gum_x86_writer_put_add_reg_imm`, `gum_x86_writer_put_sub_reg_imm`:  生成寄存器与立即数之间的加法和减法指令。
    * `gum_x86_writer_put_add_reg_reg`, `gum_x86_writer_put_sub_reg_reg`: 生成寄存器与寄存器之间的加法和减法指令。
    * `gum_x86_writer_put_add_reg_near_ptr`, `gum_x86_writer_put_sub_reg_near_ptr`: 生成寄存器与内存地址内容之间的加法和减法指令。
    * `gum_x86_writer_put_inc_reg`, `gum_x86_writer_put_dec_reg`: 生成递增和递减寄存器值的指令。
    * `gum_x86_writer_put_inc_reg_ptr`, `gum_x86_writer_put_dec_reg_ptr`: 生成递增和递减内存地址内容的指令。
* **原子操作指令生成 (Atomic Operations):**
    * `gum_x86_writer_put_lock_xadd_reg_ptr_reg`: 生成原子加法并交换指令（`lock xadd`）。
    * `gum_x86_writer_put_lock_cmpxchg_reg_ptr_reg`: 生成原子比较并交换指令（`lock cmpxchg`）。
    * `gum_x86_writer_put_lock_inc_imm32_ptr`, `gum_x86_writer_put_lock_dec_imm32_ptr`: 生成原子递增和递减内存地址内容的指令。
* **位运算指令生成 (Bitwise Operations):**
    * `gum_x86_writer_put_and_reg_reg`: 生成寄存器与寄存器之间的按位与指令。
    * `gum_x86_writer_put_and_reg_u32`: 生成寄存器与 32 位立即数之间的按位与指令。
    * `gum_x86_writer_put_shl_reg_u8`, `gum_x86_writer_put_shr_reg_u8`: 生成寄存器左移和右移指令。
    * `gum_x86_writer_put_xor_reg_reg`: 生成寄存器与寄存器之间的按位异或指令。
* **数据移动指令生成 (Data Movement Operations):**
    * `gum_x86_writer_put_mov_reg_reg`: 生成寄存器到寄存器的数据移动指令。
    * `gum_x86_writer_put_mov_reg_u32`, `gum_x86_writer_put_mov_reg_u64`: 生成将 32 位或 64 位立即数移动到寄存器的指令。
    * `gum_x86_writer_put_mov_reg_address`:  根据目标寄存器宽度，选择生成移动 32 位或 64 位地址到寄存器的指令。
    * `gum_x86_writer_put_mov_reg_ptr_u32`, `gum_x86_writer_put_mov_reg_offset_ptr_u32`: 生成将 32 位立即数移动到寄存器指向的内存地址的指令（可带偏移）。
    * `gum_x86_writer_put_mov_reg_ptr_reg`, `gum_x86_writer_put_mov_reg_offset_ptr_reg`: 生成将寄存器的值移动到另一个寄存器指向的内存地址的指令（可带偏移）。
    * `gum_x86_writer_put_mov_reg_reg_ptr`, `gum_x86_writer_put_mov_reg_reg_offset_ptr`: 生成将寄存器指向的内存地址的值移动到另一个寄存器的指令（可带偏移）。
    * `gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr`: 生成使用基址寄存器、索引寄存器、比例因子和偏移量计算有效地址，并将该地址的值移动到目标寄存器的指令。
    * `gum_x86_writer_put_mov_reg_near_ptr`, `gum_x86_writer_put_mov_near_ptr_reg`: 生成寄存器与近指针内存地址之间的数据移动指令。
    * `gum_x86_writer_put_mov_fs_u32_ptr_reg`, `gum_x86_writer_put_reg_fs_u32_ptr`, `gum_x86_writer_put_mov_gs_u32_ptr_reg`, `gum_x86_writer_put_reg_gs_u32_ptr`: 生成涉及 FS 和 GS 段寄存器的内存数据移动指令。
    * `gum_x86_writer_put_movq_xmm0_esp_offset_ptr`, `gum_x86_writer_put_movq_eax_offset_ptr_xmm0`, `gum_x86_writer_put_movdqu_xmm0_esp_offset_ptr`, `gum_x86_writer_put_movdqu_eax_offset_ptr_xmm0`: 生成特定 SSE 指令。
* **加载有效地址指令生成 (Load Effective Address):**
    * `gum_x86_writer_put_lea_reg_reg_offset`: 生成加载有效地址指令，将计算出的地址存储到目标寄存器中。
* **交换指令生成 (Exchange):**
    * `gum_x86_writer_put_xchg_reg_reg_ptr`: 生成交换寄存器和内存地址内容的指令。
* **UD2 指令生成:**
    * `gum_x86_writer_put_ud2`: 生成 `UD2` 指令，该指令会触发未定义指令异常，常用于阻止 CPU 的投机执行。
* **辅助功能:**
    * `gum_x86_writer_commit`:  将缓冲区中的代码提交，更新程序计数器 (PC)。
    * `gum_x86_writer_put_u8`, `gum_x86_writer_put_s8`: 向缓冲区写入单字节数据。
    * `gum_x86_writer_describe_cpu_reg`:  获取寄存器的信息（宽度、索引等）。
    * `gum_x86_writer_put_prefix_for_registers`, `gum_x86_writer_put_prefix_for_reg_info`:  处理指令前缀，例如操作码扩展、地址大小覆盖等。
    * `gum_get_jcc_opcode`:  获取条件跳转指令的操作码。
    * `GUM_IS_WITHIN_INT8_RANGE`, `GUM_IS_WITHIN_INT32_RANGE`:  检查数值是否在特定范围内。
    * `GINT32_TO_LE`, `GUINT32_TO_LE`, `GUINT64_TO_LE`:  将整数转换为小端字节序。
    * `gum_x86_writer_add_label_reference_here`:  添加对标签的引用，用于后续解析跳转目标地址。

**与逆向方法的关联举例说明：**

* **动态代码插桩 (Dynamic Code Instrumentation):**  这是此代码最直接的应用。在逆向分析中，我们常常需要在目标程序运行时插入自己的代码来监控其行为、修改其逻辑或进行 hook 操作。`gum_x86_writer.c` 提供的功能正是生成这些插桩代码的关键。例如，要 hook 一个函数，你需要生成跳转到你 hook 函数的指令。`gum_x86_writer_put_jmp_near` 或相关的条件跳转函数就会被使用。

   * **例子：** 假设你想在函数 `foo` 的开头插入代码，在执行 `foo` 的原始指令前打印一条消息。你可以使用 `gum_x86_writer` 生成以下指令序列：
      1. `push ebp`
      2. `mov ebp, esp`
      3. `pushad`  // 保存所有通用寄存器
      4. ... 调用打印消息的函数的指令 ...
      5. `popad`   // 恢复所有通用寄存器
      6. `jmp` 到 `foo` 函数被覆盖指令之后的位置。

* **代码重写 (Code Rewriting):** 在某些高级逆向场景中，你可能需要修改目标程序现有的代码，而不是仅仅插入代码。`gum_x86_writer` 可以用于生成新的指令序列来替换旧的指令。

   * **例子：** 假设你想移除函数 `bar` 中的某个安全检查。你可以分析 `bar` 的汇编代码，找到执行安全检查的指令，然后使用 `gum_x86_writer` 生成等效的无操作指令 (NOP) 或者直接生成跳过安全检查的指令。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明：**

* **二进制指令编码:**  代码中直接操作字节码，例如 `gum_x86_writer_put_u8 (self, 0x0f);` 和 `gum_x86_writer_put_u8 (self, 0x0b);`  用于生成 `UD2` 指令，这需要对 x86 指令的二进制编码格式有深入的理解。
* **寄存器操作:** 函数如 `gum_x86_writer_put_mov_reg_reg` 需要理解不同 x86 寄存器的编码方式，以及如何通过 ModR/M 和 SIB 字节来指定操作的寄存器。
* **寻址模式:**  `gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr` 涉及基址寄存器、索引寄存器、比例因子和偏移量的组合，这对应于 x86 的复杂寻址模式。
* **调用约定 (Calling Conventions):**  虽然这段代码本身没有直接体现调用约定，但在实际使用 `gum_x86_writer` 生成 hook 代码时，必须考虑到目标平台的调用约定（例如，函数参数如何传递、返回值如何处理、寄存器如何保存等）。这在 Linux 和 Android 上有所不同。
* **内存管理:**  `GumX86Writer` 需要管理一段内存缓冲区来存放生成的指令，这涉及到基本的内存分配和写入操作。在 Linux 和 Android 上，这通常涉及到进程的地址空间管理。
* **原子操作和锁:**  `gum_x86_writer_put_lock_...` 系列函数生成带有 `LOCK` 前缀的指令，这在多线程环境中至关重要，用于保证对共享内存的互斥访问。这与操作系统内核提供的同步机制紧密相关。
* **段寄存器 (FS/GS):** `gum_x86_writer_put_mov_fs_...` 和 `gum_x86_writer_put_mov_gs_...`  操作 FS 和 GS 段寄存器，这些寄存器在操作系统内核和用户空间有特殊的用途（例如，线程局部存储 TLS）。理解这些段寄存器的作用对于某些底层的逆向分析非常重要。

**逻辑推理的假设输入与输出：**

假设输入：
* `self`: 一个已经初始化的 `GumX86Writer` 结构体，其内部缓冲区有足够的空间。
* `instruction_id`:  `X86_INS_JE` (条件跳转：相等则跳转)
* `target`:  指向内存地址 `0x1000` 的指针。
* `hint`: `GUM_LIKELY` (分支预测提示：很可能跳转)

输出：
* `gum_x86_writer_put_jcc_short(self, instruction_id, target, hint)` 返回 `TRUE` (假设 `0x1000` 距离当前 PC 在 -128 到 127 字节之间)。
* `self->code` 缓冲区中会写入以下字节码（示例）： `0x3e 0x74 XX`  (`0x3e` 是 `GUM_LIKELY` 前缀， `0x74` 是 `JE` 的短跳转操作码， `XX` 是相对于当前 PC 的偏移量）。
* `self->pc` 会增加 2 (指令长度)。

假设输入：
* `self`: 一个已经初始化的 `GumX86Writer` 结构体。
* `reg`: `GUM_X86_REG_EAX`
* `imm_value`: `0x12345678`

输出：
* `gum_x86_writer_put_add_reg_imm(self, reg, imm_value)` 返回 `TRUE`.
* `self->code` 缓冲区中会写入以下字节码： `0x05 0x78 0x56 0x34 0x12` (`0x05` 是 `add eax, imm32` 的操作码，后面是立即数的小端表示)。
* `self->pc` 会增加 5。

**涉及用户或者编程常见的使用错误举例说明：**

* **目标地址超出范围:** 调用 `gum_x86_writer_put_jcc_short` 时，如果 `target` 地址距离当前 PC 的距离超过了 `int8` 的范围，函数会返回 `FALSE`，表示无法生成短跳转指令。用户需要检查目标地址，或者使用 `gum_x86_writer_put_jcc_near`。
* **寄存器宽度不匹配:**  例如，尝试使用 `gum_x86_writer_put_add_reg_reg` 将一个 8 位寄存器加到一个 32 位寄存器上，这会导致函数返回 `FALSE`。用户需要确保操作的寄存器宽度一致。
* **无效的立即数:** 某些指令对立即数的大小有限制。如果传递的立即数超出限制，相关的写入函数可能会返回 `FALSE` 或生成错误的指令。
* **缓冲区溢出:**  如果用户分配给 `GumX86Writer` 的缓冲区太小，连续写入指令可能会导致缓冲区溢出，这是一种常见的内存错误。Frida 内部会处理这种情况，但用户在自定义使用 `GumX86Writer` 时需要注意。
* **在不支持的架构上使用特定指令:**  某些指令可能只在特定的 x86 架构（例如，仅限 64 位）上可用。如果在 32 位环境下尝试生成这些指令，可能会失败。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户使用 Frida 的 Python API 或 C API，请求对目标进程进行插桩。** 例如，用户可能想 hook 某个特定的函数。
2. **Frida 框架接收到用户的请求，并确定需要在目标进程中注入代码。**
3. **Frida 会分配一块可执行的内存区域，用于存放要注入的代码。**
4. **根据用户的 hook 需求，Frida 需要生成相应的 x86 机器码指令。** 例如，生成跳转到 hook 函数的指令，或者在 hook 函数执行前后保存和恢复寄存器的指令。
5. **Frida 内部会创建或使用一个 `GumX86Writer` 实例，并将指向目标内存区域的指针传递给它。**
6. **Frida 会调用 `gum_x86_writer_put_...` 系列函数，根据需要生成的指令类型，逐步将指令的字节码写入到 `GumX86Writer` 管理的内存缓冲区中。**  例如，如果需要生成一个 `jmp` 指令，可能会调用 `gum_x86_writer_put_jmp_near`。
7. **`GumX86Writer` 的内部逻辑会将操作码、寄存器编码、立即数等信息编码成二进制指令，并写入到缓冲区。**
8. **`gum_x86_writer_commit` 函数会被调用，更新 `GumX86Writer` 的内部状态，例如程序计数器 (PC)。**
9. **一旦所有需要的指令都生成完毕，Frida 会将生成的机器码写入到目标进程的内存中，并修改目标程序的执行流程，使其执行注入的代码。**

在调试过程中，如果发现注入的代码没有按预期执行，或者目标程序崩溃，开发者可能需要检查以下几点：

* **生成的指令是否正确:** 可以通过反汇编 Frida 注入的内存区域来查看生成的指令是否符合预期。
* **寄存器使用是否正确:** 检查生成的代码是否正确地保存和恢复了寄存器。
* **跳转目标地址是否正确:**  对于跳转指令，需要确保跳转的目标地址计算正确。
* **内存访问是否越界:** 检查生成的代码是否访问了无效的内存地址。

这段代码是 Frida 动态插桩功能的核心组成部分，理解它的工作原理对于深入理解 Frida 的实现和进行高级的插桩操作至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/arch-x86/gumx86writer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
2 (self);

  return TRUE;
}

/*
 * This instruction causes a UD exception when executed, which isn't very
 * useful, however its presence also stalls the branch predictor. e.g. if the
 * CPU encounters a `JMP [reg]` instruction, and there is no entry in its branch
 * target buffer (cache of previous branches) it will assume that execution
 * continues with the next instruction (which is where compilers will typically
 * place the most common branch of a switch statement). However, in most cases
 * (e.g. Stalker) such indirect branches will typically be used to divert
 * control flow to an address which can only be determined at runtime. As such
 * by following these branches with `UD2`, we can prevent the speculative
 * execution of subsequent instructions and hence the overhead of unwinding
 * them.
 */
static void
gum_x86_writer_put_ud2 (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0x0f);
  gum_x86_writer_put_u8 (self, 0x0b);
}

gboolean
gum_x86_writer_put_jcc_short (GumX86Writer * self,
                              x86_insn instruction_id,
                              gconstpointer target,
                              GumBranchHint hint)
{
  gssize distance;

  if (hint != GUM_NO_HINT)
    gum_x86_writer_put_u8 (self, (hint == GUM_LIKELY) ? 0x3e : 0x2e);
  self->code[0] = gum_get_jcc_opcode (instruction_id);
  distance = (gssize) target - (gssize) (self->pc + 2);
  if (!GUM_IS_WITHIN_INT8_RANGE (distance))
    return FALSE;
  *((gint8 *) (self->code + 1)) = distance;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_jcc_near (GumX86Writer * self,
                             x86_insn instruction_id,
                             gconstpointer target,
                             GumBranchHint hint)
{
  gssize distance;

  if (hint != GUM_NO_HINT)
    gum_x86_writer_put_u8 (self, (hint == GUM_LIKELY) ? 0x3e : 0x2e);
  self->code[0] = 0x0f;
  self->code[1] = 0x10 + gum_get_jcc_opcode (instruction_id);
  distance = (gssize) target - (gssize) (self->pc + 6);
  if (!GUM_IS_WITHIN_INT32_RANGE (distance))
    return FALSE;
  *((gint32 *) (self->code + 2)) = GINT32_TO_LE (distance);
  gum_x86_writer_commit (self, 6);

  return TRUE;
}

void
gum_x86_writer_put_jcc_short_label (GumX86Writer * self,
                                    x86_insn instruction_id,
                                    gconstpointer label_id,
                                    GumBranchHint hint)
{
  gum_x86_writer_put_jcc_short (self, instruction_id,
      GSIZE_TO_POINTER (self->pc), hint);
  gum_x86_writer_add_label_reference_here (self, label_id, GUM_LREF_SHORT);
}

void
gum_x86_writer_put_jcc_near_label (GumX86Writer * self,
                                   x86_insn instruction_id,
                                   gconstpointer label_id,
                                   GumBranchHint hint)
{
  gum_x86_writer_put_jcc_near (self, instruction_id,
      GSIZE_TO_POINTER (self->pc), hint);
  gum_x86_writer_add_label_reference_here (self, label_id, GUM_LREF_NEAR);
}

static gboolean
gum_x86_writer_put_add_or_sub_reg_imm (GumX86Writer * self,
                                       GumX86Reg reg,
                                       gssize imm_value,
                                       gboolean add)
{
  GumX86RegInfo ri;
  gboolean immediate_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  immediate_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (imm_value);

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  if (ri.meta == GUM_X86_META_XAX && !immediate_fits_in_i8)
  {
    gum_x86_writer_put_u8 (self, add ? 0x05 : 0x2d);
  }
  else
  {
    self->code[0] = immediate_fits_in_i8 ? 0x83 : 0x81;
    self->code[1] = (add ? 0xc0 : 0xe8) | ri.index;
    gum_x86_writer_commit (self, 2);
  }

  if (immediate_fits_in_i8)
  {
    gum_x86_writer_put_s8 (self, imm_value);
  }
  else
  {
    *((gint32 *) self->code) = GINT32_TO_LE (imm_value);
    gum_x86_writer_commit (self, 4);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_add_reg_imm (GumX86Writer * self,
                                GumX86Reg reg,
                                gssize imm_value)
{
  return gum_x86_writer_put_add_or_sub_reg_imm (self, reg, imm_value, TRUE);
}

gboolean
gum_x86_writer_put_add_reg_reg (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (src.width != dst.width)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, &src,
      NULL))
    return FALSE;

  self->code[0] = 0x01;
  self->code[1] = 0xc0 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_add_reg_near_ptr (GumX86Writer * self,
                                     GumX86Reg dst_reg,
                                     GumAddress src_address)
{
  GumX86RegInfo dst;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, NULL))
    return FALSE;

  self->code[0] = 0x03;
  self->code[1] = 0x05 | (dst.index << 3);
  gum_x86_writer_commit (self, 2);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (src_address > G_MAXUINT32)
      return FALSE;
    *((guint32 *) self->code) = GUINT32_TO_LE ((guint32) src_address);
  }
  else
  {
    gint64 distance = (gint64) src_address - (gint64) (self->pc + 4);
    if (distance < G_MININT32 || distance > G_MAXINT32)
      return FALSE;
    *((gint32 *) self->code) = GINT32_TO_LE ((gint32) distance);
  }
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

gboolean
gum_x86_writer_put_sub_reg_imm (GumX86Writer * self,
                                GumX86Reg reg,
                                gssize imm_value)
{
  return gum_x86_writer_put_add_or_sub_reg_imm (self, reg, imm_value, FALSE);
}

gboolean
gum_x86_writer_put_sub_reg_reg (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (src.width != dst.width)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, &src,
      NULL))
    return FALSE;

  self->code[0] = 0x29;
  self->code[1] = 0xc0 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_sub_reg_near_ptr (GumX86Writer * self,
                                     GumX86Reg dst_reg,
                                     GumAddress src_address)
{
  GumX86RegInfo dst;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, NULL))
    return FALSE;

  self->code[0] = 0x2b;
  self->code[1] = 0x05 | (dst.index << 3);
  gum_x86_writer_commit (self, 2);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (src_address > G_MAXUINT32)
      return FALSE;
    *((guint32 *) self->code) = GUINT32_TO_LE ((guint32) src_address);
  }
  else
  {
    gint64 distance = (gint64) src_address - (gint64) (self->pc + 4);
    if (distance < G_MININT32 || distance > G_MAXINT32)
      return FALSE;
    *((gint32 *) self->code) = GINT32_TO_LE ((gint32) distance);
  }
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

gboolean
gum_x86_writer_put_inc_reg (GumX86Writer * self,
                            GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu != GUM_CPU_AMD64 &&
      (ri.width != 32 || ri.index_is_extended))
  {
    return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  self->code[0] = 0xff;
  self->code[1] = 0xc0 | ri.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_dec_reg (GumX86Writer * self,
                            GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu != GUM_CPU_AMD64 &&
      (ri.width != 32 || ri.index_is_extended))
  {
    return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  self->code[0] = 0xff;
  self->code[1] = 0xc8 | ri.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

static gboolean
gum_x86_writer_put_inc_or_dec_reg_ptr (GumX86Writer * self,
                                       GumX86PtrTarget target,
                                       GumX86Reg reg,
                                       gboolean increment)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_AMD64)
  {
    if (target == GUM_X86_PTR_QWORD)
      gum_x86_writer_put_u8 (self, 0x48 | (ri.index_is_extended ? 0x01 : 0x00));
    else if (ri.index_is_extended)
      gum_x86_writer_put_u8 (self, 0x41);
  }

  switch (target)
  {
    case GUM_X86_PTR_BYTE:
      gum_x86_writer_put_u8 (self, 0xfe);
      break;
    case GUM_X86_PTR_QWORD:
      if (self->target_cpu != GUM_CPU_AMD64)
        return FALSE;
    case GUM_X86_PTR_DWORD:
      gum_x86_writer_put_u8 (self, 0xff);
      break;
  }

  gum_x86_writer_put_u8 (self, (increment ? 0x00 : 0x08) | ri.index);

  return TRUE;
}

gboolean
gum_x86_writer_put_inc_reg_ptr (GumX86Writer * self,
                                GumX86PtrTarget target,
                                GumX86Reg reg)
{
  return gum_x86_writer_put_inc_or_dec_reg_ptr (self, target, reg, TRUE);
}

gboolean
gum_x86_writer_put_dec_reg_ptr (GumX86Writer * self,
                                GumX86PtrTarget target,
                                GumX86Reg reg)
{
  return gum_x86_writer_put_inc_or_dec_reg_ptr (self, target, reg, FALSE);
}

gboolean
gum_x86_writer_put_lock_xadd_reg_ptr_reg (GumX86Writer * self,
                                          GumX86Reg dst_reg,
                                          GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  gum_x86_writer_put_u8 (self, 0xf0); /* lock prefix */

  if (!gum_x86_writer_put_prefix_for_registers (self, &src, 32, &dst, &src,
      NULL))
    return FALSE;

  self->code[0] = 0x0f;
  self->code[1] = 0xc1;
  self->code[2] = 0x00 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 3);

  if (dst.meta == GUM_X86_META_XSP)
  {
    gum_x86_writer_put_u8 (self, 0x24);
  }
  else if (dst.meta == GUM_X86_META_XBP)
  {
    self->code[-1] |= 0x40;
    gum_x86_writer_put_u8 (self, 0x00);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_lock_cmpxchg_reg_ptr_reg (GumX86Writer * self,
                                             GumX86Reg dst_reg,
                                             GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (dst.width != 32)
      return FALSE;
  }
  else
  {
    if (dst.width != 64)
      return FALSE;
  }
  if (dst.index_is_extended)
    return FALSE;
  if (src.width != 32 || src.index_is_extended)
    return FALSE;

  self->code[0] = 0xf0; /* lock prefix */
  self->code[1] = 0x0f;
  self->code[2] = 0xb1;
  self->code[3] = 0x00 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 4);

  if (dst.meta == GUM_X86_META_XSP)
  {
    gum_x86_writer_put_u8 (self, 0x24);
  }
  else if (dst.meta == GUM_X86_META_XBP)
  {
    self->code[-1] |= 0x40;
    gum_x86_writer_put_u8 (self, 0x00);
  }

  return TRUE;
}

static gboolean
gum_x86_writer_put_lock_inc_or_dec_imm32_ptr (GumX86Writer * self,
                                              gpointer target,
                                              gboolean increment)
{
  self->code[0] = 0xf0;
  self->code[1] = 0xff;
  self->code[2] = increment ? 0x05 : 0x0d;

  if (self->target_cpu == GUM_CPU_IA32)
  {
    *((guint32 *) (self->code + 3)) = GUINT32_TO_LE (GPOINTER_TO_SIZE (target));
  }
  else
  {
    gint64 distance = (gssize) target - (gssize) (self->pc + 7);
    if (!GUM_IS_WITHIN_INT32_RANGE (distance))
      return FALSE;
    *((gint32 *) (self->code + 3)) = GINT32_TO_LE (distance);
  }

  gum_x86_writer_commit (self, 7);

  return TRUE;
}

gboolean
gum_x86_writer_put_lock_inc_imm32_ptr (GumX86Writer * self,
                                       gpointer target)
{
  return gum_x86_writer_put_lock_inc_or_dec_imm32_ptr (self, target, TRUE);
}

gboolean
gum_x86_writer_put_lock_dec_imm32_ptr (GumX86Writer * self,
                                       gpointer target)
{
  return gum_x86_writer_put_lock_inc_or_dec_imm32_ptr (self, target, FALSE);
}

gboolean
gum_x86_writer_put_and_reg_reg (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (dst.width != src.width)
    return FALSE;
  if (dst.index_is_extended || src.index_is_extended)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_reg_info (self, &dst, 0))
    return FALSE;

  self->code[0] = 0x21;
  self->code[1] = 0xc0 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_and_reg_u32 (GumX86Writer * self,
                                GumX86Reg reg,
                                guint32 imm_value)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  if (ri.meta == GUM_X86_META_XAX)
  {
    self->code[0] = 0x25;
    *((guint32 *) (self->code + 1)) = GUINT32_TO_LE (imm_value);
    gum_x86_writer_commit (self, 5);
  }
  else
  {
    self->code[0] = 0x81;
    self->code[1] = 0xe0 | ri.index;
    *((guint32 *) (self->code + 2)) = GUINT32_TO_LE (imm_value);
    gum_x86_writer_commit (self, 6);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_shl_reg_u8 (GumX86Writer * self,
                               GumX86Reg reg,
                               guint8 imm_value)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  self->code[0] = 0xc1;
  self->code[1] = 0xe0 | ri.index;
  self->code[2] = imm_value;
  gum_x86_writer_commit (self, 3);

  return TRUE;
}

gboolean
gum_x86_writer_put_shr_reg_u8 (GumX86Writer * self,
                               GumX86Reg reg,
                               guint8 imm_value)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 32, &ri, NULL))
    return FALSE;

  self->code[0] = 0xc1;
  self->code[1] = 0xe8 | ri.index;
  self->code[2] = imm_value;
  gum_x86_writer_commit (self, 3);

  return TRUE;
}

gboolean
gum_x86_writer_put_xor_reg_reg (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (dst.width != src.width)
    return FALSE;
  if (dst.index_is_extended || src.index_is_extended)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_reg_info (self, &dst, 0))
    return FALSE;

  self->code[0] = 0x31;
  self->code[1] = 0xc0 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_mov_reg_reg (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (dst.width != src.width)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, &src,
      NULL))
    return FALSE;

  self->code[0] = 0x89;
  self->code[1] = 0xc0 | (src.index << 3) | dst.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_mov_reg_u32 (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                guint32 imm_value)
{
  GumX86RegInfo dst;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (dst.width != 32)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_reg_info (self, &dst, 0))
    return FALSE;

  self->code[0] = 0xb8 | dst.index;
  *((guint32 *) (self->code + 1)) = GUINT32_TO_LE (imm_value);
  gum_x86_writer_commit (self, 5);

  return TRUE;
}

gboolean
gum_x86_writer_put_mov_reg_u64 (GumX86Writer * self,
                                GumX86Reg dst_reg,
                                guint64 imm_value)
{
  GumX86RegInfo dst;

  if (self->target_cpu != GUM_CPU_AMD64)
    return FALSE;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (dst.width != 64)
    return FALSE;

  if (!gum_x86_writer_put_prefix_for_reg_info (self, &dst, 0))
    return FALSE;

  self->code[0] = 0xb8 | dst.index;
  *((guint64 *) (self->code + 1)) = GUINT64_TO_LE (imm_value);
  gum_x86_writer_commit (self, 9);

  return TRUE;
}

void
gum_x86_writer_put_mov_reg_address (GumX86Writer * self,
                                    GumX86Reg dst_reg,
                                    GumAddress address)
{
  GumX86RegInfo dst;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (dst.width == 32)
    gum_x86_writer_put_mov_reg_u32 (self, dst_reg, (guint32) address);
  else
    gum_x86_writer_put_mov_reg_u64 (self, dst_reg, (guint64) address);
}

void
gum_x86_writer_put_mov_reg_ptr_u32 (GumX86Writer * self,
                                    GumX86Reg dst_reg,
                                    guint32 imm_value)
{
  gum_x86_writer_put_mov_reg_offset_ptr_u32 (self, dst_reg, 0, imm_value);
}

gboolean
gum_x86_writer_put_mov_reg_offset_ptr_u32 (GumX86Writer * self,
                                           GumX86Reg dst_reg,
                                           gssize dst_offset,
                                           guint32 imm_value)
{
  GumX86RegInfo dst;
  gboolean offset_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (dst.width != 32)
      return FALSE;
  }
  else
  {
    if (dst.width != 64)
      return FALSE;
  }

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (dst_offset);

  gum_x86_writer_put_u8 (self, 0xc7);

  if (dst_offset == 0 && dst.meta != GUM_X86_META_XBP)
  {
    gum_x86_writer_put_u8 (self, 0x00 | dst.index);
    if (dst.meta == GUM_X86_META_XSP)
      gum_x86_writer_put_u8 (self, 0x24);
  }
  else
  {
    gum_x86_writer_put_u8 (self,
        (offset_fits_in_i8 ? 0x40 : 0x80) | dst.index);

    if (dst.meta == GUM_X86_META_XSP)
      gum_x86_writer_put_u8 (self, 0x24);

    if (offset_fits_in_i8)
    {
      gum_x86_writer_put_u8 (self, dst_offset);
    }
    else
    {
      *((gint32 *) self->code) = GINT32_TO_LE (dst_offset);
      gum_x86_writer_commit (self, 4);
    }
  }

  *((guint32 *) self->code) = GUINT32_TO_LE (imm_value);
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

void
gum_x86_writer_put_mov_reg_ptr_reg (GumX86Writer * self,
                                    GumX86Reg dst_reg,
                                    GumX86Reg src_reg)
{
  gum_x86_writer_put_mov_reg_offset_ptr_reg (self, dst_reg, 0, src_reg);
}

gboolean
gum_x86_writer_put_mov_reg_offset_ptr_reg (GumX86Writer * self,
                                           GumX86Reg dst_reg,
                                           gssize dst_offset,
                                           GumX86Reg src_reg)
{
  GumX86RegInfo dst, src;
  gboolean offset_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (dst.width != 32 || src.width != 32)
      return FALSE;
  }
  else
  {
    if (dst.width != 64)
      return FALSE;
  }

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (dst_offset);

  if (!gum_x86_writer_put_prefix_for_registers (self, &src, 32, &dst, &src,
      NULL))
    return FALSE;

  gum_x86_writer_put_u8 (self, 0x89);

  if (dst_offset == 0 && dst.meta != GUM_X86_META_XBP)
  {
    gum_x86_writer_put_u8 (self, 0x00 | (src.index << 3) | dst.index);
    if (dst.meta == GUM_X86_META_XSP)
      gum_x86_writer_put_u8 (self, 0x24);
  }
  else
  {
    gum_x86_writer_put_u8 (self, (offset_fits_in_i8 ? 0x40 : 0x80) |
        (src.index << 3) | dst.index);

    if (dst.meta == GUM_X86_META_XSP)
      gum_x86_writer_put_u8 (self, 0x24);

    if (offset_fits_in_i8)
    {
      gum_x86_writer_put_s8 (self, dst_offset);
    }
    else
    {
      *((gint32 *) self->code) = GINT32_TO_LE (dst_offset);
      gum_x86_writer_commit (self, 4);
    }
  }

  return TRUE;
}

void
gum_x86_writer_put_mov_reg_reg_ptr (GumX86Writer * self,
                                    GumX86Reg dst_reg,
                                    GumX86Reg src_reg)
{
  gum_x86_writer_put_mov_reg_reg_offset_ptr (self, dst_reg, src_reg, 0);
}

gboolean
gum_x86_writer_put_mov_reg_reg_offset_ptr (GumX86Writer * self,
                                           GumX86Reg dst_reg,
                                           GumX86Reg src_reg,
                                           gssize src_offset)
{
  GumX86RegInfo dst, src;
  gboolean offset_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (dst.width != 32 || src.width != 32)
      return FALSE;
  }
  else
  {
    if (src.width != 64)
      return FALSE;
  }

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (src_offset);

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &src, &dst,
      NULL))
    return FALSE;

  self->code[0] = 0x8b;
  self->code[1] = ((offset_fits_in_i8) ? 0x40 : 0x80)
      | (dst.index << 3) | src.index;
  gum_x86_writer_commit (self, 2);

  if (src.meta == GUM_X86_META_XSP)
    gum_x86_writer_put_u8 (self, 0x24);

  if (offset_fits_in_i8)
  {
    gum_x86_writer_put_s8 (self, src_offset);
  }
  else
  {
    *((gint32 *) self->code) = GINT32_TO_LE (src_offset);
    gum_x86_writer_commit (self, 4);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr (GumX86Writer * self,
                                                        GumX86Reg dst_reg,
                                                        GumX86Reg base_reg,
                                                        GumX86Reg index_reg,
                                                        guint8 scale,
                                                        gssize offset)
{
  GumX86RegInfo dst, base, index;
  gboolean offset_fits_in_i8;
  const guint8 scale_lookup[] = {
      /* 0: */ 0xff,
      /* 1: */    0,
      /* 2: */    1,
      /* 3: */ 0xff,
      /* 4: */    2,
      /* 5: */ 0xff,
      /* 6: */ 0xff,
      /* 7: */ 0xff,
      /* 8: */    3
  };

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, base_reg, &base);
  gum_x86_writer_describe_cpu_reg (self, index_reg, &index);

  if (dst.index_is_extended)
    return FALSE;
  if (base.width != index.width)
    return FALSE;
  if (base.index_is_extended || index.index_is_extended)
    return FALSE;
  if (index.meta == GUM_X86_META_XSP)
    return FALSE;
  if (scale != 1 && scale != 2 && scale != 4 && scale != 8)
    return FALSE;

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (offset);

  if (self->target_cpu == GUM_CPU_AMD64)
  {
    if (dst.width != 64 || base.width != 64 || index.width != 64)
      return FALSE;

    gum_x86_writer_put_u8 (self, 0x48);
  }

  self->code[0] = 0x8b;
  self->code[1] = (offset_fits_in_i8 ? 0x40 : 0x80) | (dst.index << 3) | 0x04;
  self->code[2] = (scale_lookup[scale] << 6) | (index.index << 3) | base.index;
  gum_x86_writer_commit (self, 3);

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

gboolean
gum_x86_writer_put_mov_reg_near_ptr (GumX86Writer * self,
                                     GumX86Reg dst_reg,
                                     GumAddress src_address)
{
  GumX86RegInfo dst;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, NULL))
    return FALSE;

  if (self->target_cpu == GUM_CPU_IA32 && dst.meta == GUM_X86_META_XAX)
  {
    gum_x86_writer_put_u8 (self, 0xa1);
  }
  else
  {
    self->code[0] = 0x8b;
    self->code[1] = (dst.index << 3) | 0x05;
    gum_x86_writer_commit (self, 2);
  }

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (src_address > G_MAXUINT32)
      return FALSE;
    *((guint32 *) self->code) = GUINT32_TO_LE ((guint32) src_address);
  }
  else
  {
    gint64 distance = (gint64) src_address - (gint64) (self->pc + 4);
    if (distance < G_MININT32 || distance > G_MAXINT32)
      return FALSE;
    *((gint32 *) self->code) = GINT32_TO_LE ((gint32) distance);
  }
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

gboolean
gum_x86_writer_put_mov_near_ptr_reg (GumX86Writer * self,
                                     GumAddress dst_address,
                                     GumX86Reg src_reg)
{
  GumX86RegInfo src;

  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (!gum_x86_writer_put_prefix_for_registers (self, &src, 32, &src, NULL))
    return FALSE;

  if (self->target_cpu == GUM_CPU_IA32 && src.meta == GUM_X86_META_XAX)
  {
    gum_x86_writer_put_u8 (self, 0xa3);
  }
  else
  {
    self->code[0] = 0x89;
    self->code[1] = (src.index << 3) | 0x05;
    gum_x86_writer_commit (self, 2);
  }

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (dst_address > G_MAXUINT32)
      return FALSE;
    *((guint32 *) self->code) = GUINT32_TO_LE ((guint32) dst_address);
  }
  else
  {
    gint64 distance = (gint64) dst_address - (gint64) (self->pc + 4);
    if (distance < G_MININT32 || distance > G_MAXINT32)
      return FALSE;
    *((gint32 *) self->code) = GINT32_TO_LE ((gint32) distance);
  }
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

static gboolean
gum_x86_writer_put_mov_reg_imm_ptr (GumX86Writer * self,
                                    GumX86Reg dst_reg,
                                    guint32 address)
{
  GumX86RegInfo dst;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);

  if (!gum_x86_writer_put_prefix_for_registers (self, &dst, 32, &dst, NULL))
    return FALSE;

  self->code[0] = 0x8b;
  self->code[1] = (dst.index << 3) | 0x04;
  self->code[2] = 0x25;
  *((guint32 *) (self->code + 3)) = GUINT32_TO_LE (address);
  gum_x86_writer_commit (self, 7);

  return TRUE;
}

static gboolean
gum_x86_writer_put_mov_imm_ptr_reg (GumX86Writer * self,
                                    guint32 address,
                                    GumX86Reg src_reg)
{
  GumX86RegInfo src;

  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (!gum_x86_writer_put_prefix_for_registers (self, &src, 32, &src, NULL))
    return FALSE;

  self->code[0] = 0x89;
  self->code[1] = (src.index << 3) | 0x04;
  self->code[2] = 0x25;
  *((guint32 *) (self->code + 3)) = GUINT32_TO_LE (address);
  gum_x86_writer_commit (self, 7);

  return TRUE;
}

gboolean
gum_x86_writer_put_mov_fs_u32_ptr_reg (GumX86Writer * self,
                                       guint32 fs_offset,
                                       GumX86Reg src_reg)
{
  gum_x86_writer_put_u8 (self, 0x64);
  return gum_x86_writer_put_mov_imm_ptr_reg (self, fs_offset, src_reg);
}

gboolean
gum_x86_writer_put_mov_reg_fs_u32_ptr (GumX86Writer * self,
                                       GumX86Reg dst_reg,
                                       guint32 fs_offset)
{
  gum_x86_writer_put_u8 (self, 0x64);
  return gum_x86_writer_put_mov_reg_imm_ptr (self, dst_reg, fs_offset);
}

void
gum_x86_writer_put_mov_fs_reg_ptr_reg (GumX86Writer * self,
                                       GumX86Reg fs_offset,
                                       GumX86Reg src_reg)
{
  gum_x86_writer_put_u8 (self, 0x65);
  gum_x86_writer_put_mov_reg_ptr_reg (self, fs_offset, src_reg);
}

void
gum_x86_writer_put_mov_reg_fs_reg_ptr (GumX86Writer * self,
                                       GumX86Reg dst_reg,
                                       GumX86Reg fs_offset)
{
  gum_x86_writer_put_u8 (self, 0x65);
  gum_x86_writer_put_mov_reg_reg_ptr (self, dst_reg, fs_offset);
}

gboolean
gum_x86_writer_put_mov_gs_u32_ptr_reg (GumX86Writer * self,
                                       guint32 fs_offset,
                                       GumX86Reg src_reg)
{
  gum_x86_writer_put_u8 (self, 0x65);
  return gum_x86_writer_put_mov_imm_ptr_reg (self, fs_offset, src_reg);
}

gboolean
gum_x86_writer_put_mov_reg_gs_u32_ptr (GumX86Writer * self,
                                       GumX86Reg dst_reg,
                                       guint32 fs_offset)
{
  gum_x86_writer_put_u8 (self, 0x65);
  return gum_x86_writer_put_mov_reg_imm_ptr (self, dst_reg, fs_offset);
}

void
gum_x86_writer_put_mov_gs_reg_ptr_reg (GumX86Writer * self,
                                       GumX86Reg gs_offset,
                                       GumX86Reg src_reg)
{
  gum_x86_writer_put_u8 (self, 0x65);
  gum_x86_writer_put_mov_reg_ptr_reg (self, gs_offset, src_reg);
}

void
gum_x86_writer_put_mov_reg_gs_reg_ptr (GumX86Writer * self,
                                       GumX86Reg dst_reg,
                                       GumX86Reg gs_offset)
{
  gum_x86_writer_put_u8 (self, 0x65);
  gum_x86_writer_put_mov_reg_reg_ptr (self, dst_reg, gs_offset);
}

void
gum_x86_writer_put_movq_xmm0_esp_offset_ptr (GumX86Writer * self,
                                             gint8 offset)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x0f;
  self->code[2] = 0x7e;
  self->code[3] = 0x44;
  self->code[4] = 0x24;
  self->code[5] = offset;
  gum_x86_writer_commit (self, 6);
}

void
gum_x86_writer_put_movq_eax_offset_ptr_xmm0 (GumX86Writer * self,
                                             gint8 offset)
{
  self->code[0] = 0x66;
  self->code[1] = 0x0f;
  self->code[2] = 0xd6;
  self->code[3] = 0x40;
  self->code[4] = offset;
  gum_x86_writer_commit (self, 5);
}

void
gum_x86_writer_put_movdqu_xmm0_esp_offset_ptr (GumX86Writer * self,
                                               gint8 offset)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x0f;
  self->code[2] = 0x6f;
  self->code[3] = 0x44;
  self->code[4] = 0x24;
  self->code[5] = offset;
  gum_x86_writer_commit (self, 6);
}

void
gum_x86_writer_put_movdqu_eax_offset_ptr_xmm0 (GumX86Writer * self,
                                               gint8 offset)
{
  self->code[0] = 0xf3;
  self->code[1] = 0x0f;
  self->code[2] = 0x7f;
  self->code[3] = 0x40;
  self->code[4] = offset;
  gum_x86_writer_commit (self, 5);
}

gboolean
gum_x86_writer_put_lea_reg_reg_offset (GumX86Writer * self,
                                       GumX86Reg dst_reg,
                                       GumX86Reg src_reg,
                                       gssize src_offset)
{
  GumX86RegInfo dst, src;

  gum_x86_writer_describe_cpu_reg (self, dst_reg, &dst);
  gum_x86_writer_describe_cpu_reg (self, src_reg, &src);

  if (dst.index_is_extended || src.index_is_extended)
    return FALSE;

  if (self->target_cpu == GUM_CPU_AMD64)
  {
    if (src.width == 32)
      gum_x86_writer_put_u8 (self, 0x67);
    if (dst.width == 64)
      gum_x86_writer_put_u8 (self, 0x48);
  }

  self->code[0] = 0x8d;
  self->code[1] = 0x80 | (dst.index << 3) | src.index;
  gum_x86_writer_commit (self, 2);

  if (src.meta == GUM_X86_META_XSP)
    gum_x86_writer_put_u8 (self, 0x24);

  *((gint32 *) self->code) = GINT32_TO_LE (src_offset);
  gum_x86_writer_commit (self, 4);

  return TRUE;
}

gboolean
gum_x86_writer_put_xchg_reg_reg_ptr (GumX86Writer * self,
                                     GumX86Reg left_reg,
                                     GumX86Reg right_reg)
{
  GumX86RegInfo left, right;

  gum_x86_writer_describe_cpu_reg (self, left_reg, &left);
  gum_x86_writer_describe_cpu
"""


```