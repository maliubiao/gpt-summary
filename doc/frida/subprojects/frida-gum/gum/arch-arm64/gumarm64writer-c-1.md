Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the `gumarm64writer.c` file in the Frida dynamic instrumentation tool. The request also asks to highlight connections to reverse engineering, low-level binary manipulation, Linux/Android kernel/framework knowledge, logical reasoning, common user errors, and debugging.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The code is clearly about writing ARM64 instructions. Functions have names like `gum_arm64_writer_put_ldr_reg_reg_offset_mode`, `gum_arm64_writer_put_str_reg_reg`, etc., which correspond to ARM64 assembly instructions.

2. **Categorize the functions:** Group the functions by the type of ARM64 instruction they generate (load, store, arithmetic, logical, branch, etc.). This helps in understanding the overall capabilities of the writer.

3. **Examine individual functions:**  For each function, understand its parameters (registers, offsets, immediate values) and how they translate into the final instruction encoding. Pay attention to bitwise operations and shifts.

4. **Relate to reverse engineering:**  Consider how this code could be used in reverse engineering. For example, dynamically patching code requires the ability to write new instructions. Intercepting function calls involves inserting jump instructions.

5. **Connect to low-level knowledge:** Identify where the code interacts with the underlying hardware architecture (ARM64 registers, instruction formats, memory addressing modes). Note any dependencies on operating system concepts (like memory management, though less directly visible in this snippet).

6. **Look for logical reasoning:** Analyze functions that make decisions or calculations based on input parameters. The immediate encoding functions are good examples here.

7. **Consider user errors:** Think about common mistakes a user might make when using this API. Providing invalid register names or out-of-range immediate values are potential issues.

8. **Trace the user path:** Imagine a user wanting to use Frida to modify the behavior of an ARM64 application. How would they end up calling these writer functions? This involves steps like finding the target code, determining the necessary modifications, and using Frida's API to perform those modifications.

9. **Summarize the functionality:**  Synthesize the findings into a concise description of what the code does.

10. **Address specific points from the prompt:** Ensure each aspect of the user's request (reverse engineering, low-level, logic, errors, debugging) is addressed with concrete examples.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus heavily on individual instruction encoding.
* **Correction:**  Shift focus to the *purpose* of these functions within the larger Frida context. Why would someone need to generate these instructions?
* **Initial thought:** List all functions individually in the summary.
* **Correction:** Group functions by category for better readability and understanding of the overall functionality.
* **Initial thought:** Only consider direct mapping between function and instruction.
* **Correction:**  Think about higher-level operations enabled by these primitives, such as function hooking and code patching.
* **Initial thought:**  Assume deep knowledge of ARM64 assembly from the user.
* **Correction:** Explain concepts in a way that's accessible to someone with some programming experience but maybe less direct ARM64 experience.

By following these steps and incorporating the self-corrections, a comprehensive and informative answer can be generated.
这是对`frida/subprojects/frida-gum/gum/arch-arm64/gumarm64writer.c` 文件代码片段的第二部分的功能归纳。结合之前分析的第一部分，我们可以总结出 `GumArm64Writer` 的完整功能。

**`GumArm64Writer` 的综合功能归纳：**

`GumArm64Writer` 是 Frida Gum 库中用于在 ARM64 架构上动态生成和写入机器码的核心组件。它提供了一系列函数，允许开发者以编程方式构建 ARM64 指令，并将这些指令写入到内存中。这使得 Frida 能够在运行时修改目标进程的代码，实现动态插桩。

**具体功能点包括：**

1. **指令生成：** 提供了大量以 `gum_arm64_writer_put_` 开头的函数，用于生成各种 ARM64 指令，涵盖了数据加载、存储、算术运算、逻辑运算、比较、跳转、位操作等。
    * **加载和存储指令 (Load and Store):**  如 `put_ldr_reg_reg_offset_mode`, `put_str_reg_reg_offset_mode`, `put_ldp_reg_reg_reg_offset`, `put_stp_reg_reg_reg_offset`，用于在寄存器和内存之间传输数据。支持不同的寻址模式（偏移量、预索引、后索引）。
    * **数据移动指令 (Move):** 如 `put_mov_reg_reg`, `put_mov_reg_nzcv`, `put_mov_nzcv_reg`，用于在寄存器之间移动数据或将特定值加载到寄存器。
    * **算术和逻辑运算指令 (Arithmetic and Logical):** 如 `put_add_reg_reg_imm`, `put_sub_reg_reg_reg`, `put_and_reg_reg_imm`, `put_eor_reg_reg_reg`，用于执行基本的算术和逻辑运算。
    * **位操作指令 (Bit Manipulation):** 如 `put_uxtw_reg_reg`, `put_ubfm`, `put_lsl_reg_imm`, `put_lsr_reg_imm`，用于执行位扩展、位域提取和移位操作。
    * **比较指令 (Compare):** 如 `put_cmp_reg_reg`, `put_tst_reg_imm`，用于比较寄存器或寄存器与立即数的值，并设置条件码。
    * **地址计算指令 (Address Calculation):** 如 `put_adrp_reg_address`，用于计算与程序计数器相对的地址，常用于加载全局变量的地址。
    * **分支指令 (Branch):**  在第一部分中涵盖，用于控制程序的执行流程，跳转到不同的代码位置。
    * **特殊指令 (Special):** 如 `put_nop` (空操作), `put_brk_imm` (断点指令), `put_mrs` (读取系统寄存器), `put_xpaci_reg` (指针认证指令)。

2. **指令编码：**  `GumArm64Writer` 内部负责将抽象的指令参数（如寄存器、偏移量、立即数）编码成实际的 ARM64 机器码。这涉及到对 ARM64 指令格式的深入理解和位域操作。

3. **内存写入：**  `gum_arm64_writer_put_instruction` 和 `gum_arm64_writer_put_bytes` 函数将生成的机器码写入到 `GumArm64Writer` 结构体内部的缓冲区，这个缓冲区最终会被提交到目标进程的内存中。

4. **标签和字面量管理：**  （在第一部分和第二部分都有体现）`GumArm64Writer` 具有处理代码标签和字面量的能力。它允许在生成代码时使用标签作为跳转目标，并在后续解析这些标签，计算实际的跳转偏移。类似地，它可以暂存需要加载的常量值（字面量），并在适当的时机将其放置在代码附近，并生成加载这些字面量的指令。

5. **指针认证支持：**  `gum_arm64_writer_sign` 和 `gum_arm64_writer_strip` 函数处理了 ARM64 的指针认证功能。这在支持指针认证的系统上（如较新版本的 macOS 和 iOS）非常重要，能够正确地签名和剥离指针的 PAC (Pointer Authentication Code) 签名。

6. **辅助函数：**  提供了一些内部辅助函数，如 `gum_arm64_writer_describe_reg` 用于获取寄存器的属性信息（大小、类型等），`gum_arm64_mem_operand_type_from_reg_info` 用于根据寄存器信息确定内存操作数类型，以及 `gum_arm64_try_encode_logical_immediate` 等函数用于将立即数编码成 ARM64 指令所需的格式。

**与逆向方法的关联举例：**

* **动态代码注入 (Dynamic Code Injection):** 逆向工程师可以使用 `GumArm64Writer` 构建 shellcode 或 payload，并将其注入到目标进程的内存中。例如，可以使用 `put_mov_reg_imm` 将一个地址加载到寄存器，然后使用 `put_blr_reg` 跳转到该地址执行注入的代码。
* **Hook 函数 (Function Hooking):**  当需要拦截和修改目标函数的行为时，可以使用 `GumArm64Writer` 在目标函数的入口处写入跳转指令，跳转到自定义的处理函数。例如，可以使用 `put_ldr_reg_address` 加载自定义处理函数的地址，然后使用 `put_br_reg` 进行跳转。
* **代码 Patching (Code Patching):**  逆向工程师可以使用 `GumArm64Writer` 修改目标进程现有的指令。例如，可以使用 `put_nop` 指令替换掉不需要执行的指令，或者用新的指令序列替换掉原有的指令序列来改变程序的行为。
* **运行时调试 (Runtime Debugging):** 可以使用 `put_brk_imm` 在特定的代码位置插入断点，当程序执行到这些位置时会触发调试器。

**涉及二进制底层、Linux、Android 内核及框架的知识举例：**

* **ARM64 指令集架构：**  `GumArm64Writer` 的核心功能是生成 ARM64 指令，因此需要深入理解 ARM64 指令的格式、寻址模式、操作码等二进制编码细节。例如，代码中大量的位运算和移位操作就是为了构建符合 ARM64 指令格式的机器码。
* **寄存器约定：**  代码中使用了 `arm64_reg` 枚举类型来表示 ARM64 寄存器，并根据寄存器的类型和大小生成不同的指令。这涉及到理解 ARM64 的寄存器命名约定（如 X0-X30, W0-W30, SP, LR 等）。
* **内存寻址模式：**  `put_ldr_reg_reg_offset_mode` 和 `put_str_reg_reg_offset_mode` 等函数支持不同的内存寻址模式 (Pre-index, Post-index, Offset)，这需要了解 ARM64 如何通过寄存器和偏移量计算内存地址。
* **函数调用约定 (Calling Convention):**  在进行函数 Hooking 或代码注入时，需要遵循 ARM64 的函数调用约定，例如参数的传递方式、返回值的存放位置等。`GumArm64Writer` 生成的指令需要符合这些约定才能正确地调用函数。
* **Thumb-2 指令集：** 虽然这个代码片段主要关注 A64 指令集，但在实际应用中，Frida 也需要处理 Thumb-2 指令集，这涉及到不同的指令编码和执行模式。
* **Linux/Android 内存管理：**  Frida 需要将生成的代码写入到目标进程的内存空间，这涉及到对操作系统内存管理机制的理解，例如虚拟地址空间、内存保护等。
* **共享库和动态链接：**  在 Hook 共享库中的函数时，需要考虑动态链接的过程和地址重定位等问题。
* **Android Runtime (ART):**  在 Android 环境下，如果目标是 Java 代码，则需要与 ART 虚拟机进行交互，理解 ART 的内部机制，例如方法调用、对象内存布局等。

**逻辑推理的假设输入与输出举例：**

以 `gum_arm64_writer_put_add_reg_reg_imm` 函数为例：

* **假设输入：**
    * `dst_reg`: `ARM64_REG_X0` (目标寄存器)
    * `left_reg`: `ARM64_REG_X1` (左操作数寄存器)
    * `right_value`: `100` (立即数)
* **逻辑推理：** 函数会根据目标寄存器和左操作数寄存器的宽度（这里都是 64 位）以及立即数的值，构建 `ADD` 指令的机器码。
* **输出（近似）：**  生成的机器码会类似于 `0x91000420` (实际编码可能略有不同，取决于具体的汇编器和编码规则)。这个机器码代表了将寄存器 X1 的值加上立即数 100，结果存储到寄存器 X0 的操作。

**涉及用户或编程常见的使用错误举例：**

* **寄存器类型不匹配：** 例如，尝试使用 `gum_arm64_writer_put_add_reg_reg_reg` 将一个 32 位寄存器和一个 64 位寄存器相加，该函数会返回 `FALSE`，因为其内部会检查寄存器宽度是否一致。
* **立即数超出范围：** 某些指令的立即数有取值范围限制。例如，`gum_arm64_writer_put_ldr_reg_imm` 的立即数偏移量通常有最大值限制。如果用户提供的立即数超出范围，函数可能会返回 `FALSE` 或者生成错误的指令。
* **错误的内存偏移量：** 在使用加载和存储指令时，提供的内存偏移量可能导致访问越界或未映射的内存区域，这会在目标进程运行时导致崩溃。
* **不正确的指令序列：** 用户可能生成了逻辑上不正确的指令序列，例如在没有设置跳转目标的情况下使用跳转指令，或者在没有保存寄存器的情况下修改了重要寄存器的值。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本：** 用户首先会编写一个 JavaScript 或 Python 的 Frida 脚本，用于hook目标应用程序的某个函数。
2. **Frida 脚本调用 Gum API：** 在脚本中，用户会使用 Frida 提供的 Gum API 来获取目标函数的地址，并创建一个 `Interceptor` 来拦截该函数的调用。
3. **构建新的代码逻辑：** 在 `Interceptor` 的回调函数中，用户可能需要修改函数的行为。这通常涉及到使用 `Gum.CodeWriter` 来生成新的 ARM64 指令。
4. **调用 `GumArm64Writer` 的 put 函数：**  `Gum.CodeWriter` 内部会调用 `GumArm64Writer` 提供的各种 `put_` 函数，根据用户的意图生成相应的 ARM64 机器码。例如，如果用户想要在函数入口处保存某些寄存器的值，`GumArm64Writer` 的 `put_stp_reg_reg_reg_offset` 函数会被调用。
5. **写入内存：** 生成的机器码最终会被写入到目标进程的内存中，替换或插入到原来的代码位置。

**作为调试线索，如果用户在 Frida 脚本中遇到了问题，例如目标程序崩溃或行为异常，他们可以：**

* **检查生成的机器码：**  可以使用 Frida 提供的工具或手动解析内存中的指令，查看 `GumArm64Writer` 生成的机器码是否符合预期。
* **单步调试注入的代码：**  可以使用调试器附加到目标进程，并在注入的代码处设置断点，单步执行来查看程序的执行流程和寄存器的状态。
* **检查 `GumArm64Writer` 的返回值：**  许多 `GumArm64Writer` 的函数会返回布尔值，指示指令生成是否成功。用户可以检查这些返回值来判断是否有参数错误或指令编码问题。
* **查看 Frida 的日志输出：**  Frida 可能会输出一些调试信息，帮助用户定位问题。

总而言之，`GumArm64Writer` 是 Frida 实现动态插桩的核心引擎之一，它将底层的 ARM64 指令编码细节抽象出来，为开发者提供了一个方便的接口来动态修改目标进程的行为。 理解其功能和限制对于有效使用 Frida 进行逆向工程和动态分析至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/arch-arm64/gumarm64writer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
_writer_describe_reg (self, src_reg, &rs);

  opc = 1;
  if (rd.is_integer)
  {
    size = (rd.width == 64) ? 3 : 2;
    v = 0;
  }
  else
  {
    if (rd.width == 128)
    {
      size = 0;
      opc |= 2;
    }
    else
    {
      size = (rd.width == 64) ? 3 : 2;
    }
    v = 1;
  }

  if (rs.width != 64)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0x39000000 |
      (size << 30) | (v << 26) | (opc << 22) |
      ((guint32) src_offset / (rd.width / 8)) << 10 |
      (rs.index << 5) | rd.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ldr_reg_reg_offset_mode (GumArm64Writer * self,
                                              arm64_reg dst_reg,
                                              arm64_reg src_reg,
                                              gssize src_offset,
                                              GumArm64IndexMode mode)
{
  GumArm64RegInfo rd, rs;
  guint32 opc, size, v;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  opc = 1;
  if (rd.is_integer)
  {
    size = (rd.width == 64) ? 3 : 2;
    v = 0;
  }
  else
  {
    if (rd.width == 128)
    {
      size = 0;
      opc |= 2;
    }
    else
    {
      size = (rd.width == 64) ? 3 : 2;
    }
    v = 1;
  }

  if (rs.width != 64)
    return FALSE;

  if (src_offset < -256 || src_offset > 255)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0x38000000 |
      (size << 30) | (v << 26) | (opc << 22) |
      (((guint32) src_offset) & 0x1ff) << 12 |
      mode << 10 |
      (rs.index << 5) | rd.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ldrsw_reg_reg_offset (GumArm64Writer * self,
                                           arm64_reg dst_reg,
                                           arm64_reg src_reg,
                                           gsize src_offset)
{
  GumArm64RegInfo rd, rs;
  gsize immediate;
  gboolean immediate_fits_in_12_bits;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  if (rd.width != 64 || rs.width != 64)
    return FALSE;
  if (!rd.is_integer || !rs.is_integer)
    return FALSE;

  immediate = src_offset / sizeof (guint32);

  immediate_fits_in_12_bits = (immediate >> 12) == 0;
  if (!immediate_fits_in_12_bits)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0xb9800000 | (immediate << 10) |
      (rs.index << 5) | rd.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_adrp_reg_address (GumArm64Writer * self,
                                       arm64_reg reg,
                                       GumAddress address)
{
  GumArm64RegInfo ri;
  union
  {
    gint64 i;
    guint64 u;
  } distance;
  guint32 imm_hi, imm_lo;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  distance.i = (gint64) gum_arm64_writer_strip (self, address) -
      (gint64) (self->pc & ~((GumAddress) (4096 - 1)));
  if (distance.i % 4096 != 0)
    return FALSE;
  distance.i /= 4096;

  if (!GUM_IS_WITHIN_INT21_RANGE (distance.i))
    return FALSE;

  imm_hi = (distance.u & G_GUINT64_CONSTANT (0x1ffffc)) >> 2;
  imm_lo = (distance.u & G_GUINT64_CONSTANT (0x3));

  gum_arm64_writer_put_instruction (self, 0x90000000 |
      (imm_lo << 29) | (imm_hi << 5) | ri.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_str_reg_reg (GumArm64Writer * self,
                                  arm64_reg src_reg,
                                  arm64_reg dst_reg)
{
  return gum_arm64_writer_put_str_reg_reg_offset (self, src_reg, dst_reg, 0);
}

gboolean
gum_arm64_writer_put_str_reg_reg_offset (GumArm64Writer * self,
                                         arm64_reg src_reg,
                                         arm64_reg dst_reg,
                                         gsize dst_offset)
{
  GumArm64RegInfo rs, rd;
  guint32 size, v, opc;

  gum_arm64_writer_describe_reg (self, src_reg, &rs);
  gum_arm64_writer_describe_reg (self, dst_reg, &rd);

  opc = 0;
  if (rs.is_integer)
  {
    size = (rs.width == 64) ? 3 : 2;
    v = 0;
  }
  else
  {
    if (rs.width == 128)
    {
      size = 0;
      opc |= 2;
    }
    else
    {
      size = (rs.width == 64) ? 3 : 2;
    }
    v = 1;
  }

  if (rd.width != 64)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0x39000000 |
      (size << 30) | (v << 26) | (opc << 22) |
      ((guint32) dst_offset / (rs.width / 8)) << 10 |
      (rd.index << 5) | rs.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_str_reg_reg_offset_mode (GumArm64Writer * self,
                                              arm64_reg src_reg,
                                              arm64_reg dst_reg,
                                              gssize dst_offset,
                                              GumArm64IndexMode mode)
{
  GumArm64RegInfo rs, rd;
  guint32 opc, size, v;

  gum_arm64_writer_describe_reg (self, src_reg, &rs);
  gum_arm64_writer_describe_reg (self, dst_reg, &rd);

  opc = 0;
  if (rs.is_integer)
  {
    size = (rs.width == 64) ? 3 : 2;
    v = 0;
  }
  else
  {
    if (rs.width == 128)
    {
      size = 0;
      opc |= 2;
    }
    else
    {
      size = (rs.width == 64) ? 3 : 2;
    }
    v = 1;
  }

  if (rd.width != 64)
    return FALSE;

  if (dst_offset < -256 || dst_offset > 255)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0x38000000 |
      (size << 30) | (v << 26) | (opc << 22) |
      (((guint32) dst_offset) & 0x1ff) << 12 |
      mode << 10 |
      (rd.index << 5) | rs.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ldp_reg_reg_reg_offset (GumArm64Writer * self,
                                             arm64_reg reg_a,
                                             arm64_reg reg_b,
                                             arm64_reg reg_src,
                                             gssize src_offset,
                                             GumArm64IndexMode mode)
{
  GumArm64RegInfo ra, rb, rs;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);
  gum_arm64_writer_describe_reg (self, reg_src, &rs);

  if (ra.width != rb.width)
    return FALSE;

  gum_arm64_writer_put_load_store_pair (self, GUM_MEM_OPERATION_LOAD,
      gum_arm64_mem_operand_type_from_reg_info (&ra), ra.index, rb.index,
      rs.index, src_offset, mode);

  return TRUE;
}

gboolean
gum_arm64_writer_put_stp_reg_reg_reg_offset (GumArm64Writer * self,
                                             arm64_reg reg_a,
                                             arm64_reg reg_b,
                                             arm64_reg reg_dst,
                                             gssize dst_offset,
                                             GumArm64IndexMode mode)
{
  GumArm64RegInfo ra, rb, rd;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);
  gum_arm64_writer_describe_reg (self, reg_dst, &rd);

  if (ra.width != rb.width)
    return FALSE;

  gum_arm64_writer_put_load_store_pair (self, GUM_MEM_OPERATION_STORE,
      gum_arm64_mem_operand_type_from_reg_info (&ra), ra.index, rb.index,
      rd.index, dst_offset, mode);

  return TRUE;
}

gboolean
gum_arm64_writer_put_mov_reg_reg (GumArm64Writer * self,
                                  arm64_reg dst_reg,
                                  arm64_reg src_reg)
{
  GumArm64RegInfo rd, rs;
  gboolean src_is_zero_reg;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  if (rd.width != rs.width)
    return FALSE;

  src_is_zero_reg = src_reg == ARM64_REG_XZR || src_reg == ARM64_REG_WZR;

  if (rd.meta == GUM_MREG_SP || (!src_is_zero_reg && rs.meta == GUM_MREG_SP))
  {
    gum_arm64_writer_put_instruction (self, 0x91000000 | rd.index |
        (rs.index << 5));
  }
  else
  {
    gum_arm64_writer_put_instruction (self, rd.sf | 0x2a000000 | rd.index |
        (GUM_MREG_ZR << 5) | (rs.index << 16));
  }

  return TRUE;
}

void
gum_arm64_writer_put_mov_reg_nzcv (GumArm64Writer * self,
                                   arm64_reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_put_instruction (self, 0xd53b4200 | ri.index);
}

void
gum_arm64_writer_put_mov_nzcv_reg (GumArm64Writer * self,
                                   arm64_reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  gum_arm64_writer_put_instruction (self, 0xd51b4200 | ri.index);
}

gboolean
gum_arm64_writer_put_uxtw_reg_reg (GumArm64Writer * self,
                                   arm64_reg dst_reg,
                                   arm64_reg src_reg)
{
  GumArm64RegInfo rd, rs;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rs);

  if (rd.width != 64 || rs.width != 32)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0xd3407c00 | (rs.index << 5) |
      rd.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_add_reg_reg_imm (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      gsize right_value)
{
  GumArm64RegInfo rd, rl;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);

  if (rd.width != rl.width)
    return FALSE;

  gum_arm64_writer_put_instruction (self, rd.sf | 0x11000000 | rd.index |
      (rl.index << 5) | (right_value << 10));

  return TRUE;
}

gboolean
gum_arm64_writer_put_add_reg_reg_reg (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      arm64_reg right_reg)
{
  GumArm64RegInfo rd, rl, rr;
  guint32 flags = 0;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);
  gum_arm64_writer_describe_reg (self, right_reg, &rr);

  if (rd.width != rl.width || rd.width != rr.width)
    return FALSE;

  if (rd.width == 64)
    flags |= 0x8000000;

  gum_arm64_writer_put_instruction (self, rd.sf | 0xb000000 | flags | rd.index |
      (rl.index << 5) | (rr.index << 16));

  return TRUE;
}

gboolean
gum_arm64_writer_put_sub_reg_reg_imm (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      gsize right_value)
{
  GumArm64RegInfo rd, rl;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);

  if (rd.width != rl.width)
    return FALSE;

  gum_arm64_writer_put_instruction (self, rd.sf | 0x51000000 | rd.index |
      (rl.index << 5) | (right_value << 10));

  return TRUE;
}

gboolean
gum_arm64_writer_put_sub_reg_reg_reg (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      arm64_reg right_reg)
{
  GumArm64RegInfo rd, rl, rr;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);
  gum_arm64_writer_describe_reg (self, right_reg, &rr);

  if (rd.width != rl.width || rd.width != rr.width)
    return FALSE;

  gum_arm64_writer_put_instruction (self, rd.sf | 0x4b000000 | rd.index |
      (rl.index << 5) | (rr.index << 16));

  return TRUE;
}

gboolean
gum_arm64_writer_put_and_reg_reg_imm (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      guint64 right_value)
{
  GumArm64RegInfo rd, rl;
  guint right_value_encoded;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);

  if (rd.width != rl.width)
    return FALSE;

  if (!gum_arm64_try_encode_logical_immediate (right_value, rd.width,
      &right_value_encoded))
    return FALSE;

  gum_arm64_writer_put_instruction (self, rd.sf | 0x12000000 | rd.index |
      (rl.index << 5) | (right_value_encoded << 10));

  return TRUE;
}

gboolean
gum_arm64_writer_put_eor_reg_reg_reg (GumArm64Writer * self,
                                      arm64_reg dst_reg,
                                      arm64_reg left_reg,
                                      arm64_reg right_reg)
{
  GumArm64RegInfo rd, rl, rr;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, left_reg, &rl);
  gum_arm64_writer_describe_reg (self, right_reg, &rr);

  if (rl.width != rd.width || rr.width != rd.width)
    return FALSE;

  gum_arm64_writer_put_instruction (self,
      (rd.width == 64 ? 0x80000000 : 0x00000000) |
      0x4a000000 |
      (rr.index << 16) |
      (rl.index << 5) |
      rd.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ubfm (GumArm64Writer * self,
                           arm64_reg dst_reg,
                           arm64_reg src_reg,
                           guint8 immr,
                           guint8 imms)
{
  GumArm64RegInfo rd, rn;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64_writer_describe_reg (self, src_reg, &rn);

  if (rn.width != rd.width)
    return FALSE;

  if (((imms | immr) & 0xc0) != 0)
    return FALSE;

  gum_arm64_writer_put_instruction (self,
      (rd.width == 64 ? 0x80400000 : 0x00000000) |
      0x53000000 |
      (immr << 16) |
      (imms << 10) |
      (rn.index << 5) |
      rd.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_lsl_reg_imm (GumArm64Writer * self,
                                  arm64_reg dst_reg,
                                  arm64_reg src_reg,
                                  guint8 shift)
{
  GumArm64RegInfo rd;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);

  if (rd.width == 32 && (shift & 0xe0) != 0)
    return FALSE;

  if (rd.width == 64 && (shift & 0xc0) != 0)
    return FALSE;

  return gum_arm64_writer_put_ubfm (self, dst_reg, src_reg,
      -shift % rd.width, (rd.width - 1) - shift);
}

gboolean
gum_arm64_writer_put_lsr_reg_imm (GumArm64Writer * self,
                                  arm64_reg dst_reg,
                                  arm64_reg src_reg,
                                  guint8 shift)
{
  GumArm64RegInfo rd;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);

  if (rd.width == 32 && (shift & 0xe0) != 0)
    return FALSE;

  return gum_arm64_writer_put_ubfm (self, dst_reg, src_reg,
      shift, rd.width - 1);
}

gboolean
gum_arm64_writer_put_tst_reg_imm (GumArm64Writer * self,
                                  arm64_reg reg,
                                  guint64 imm_value)
{
  GumArm64RegInfo ri;
  guint imm_value_encoded;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (!gum_arm64_try_encode_logical_immediate (imm_value, ri.width,
      &imm_value_encoded))
    return FALSE;

  gum_arm64_writer_put_instruction (self, ri.sf | 0x7200001f | (ri.index << 5) |
      (imm_value_encoded << 10));

  return TRUE;
}

gboolean
gum_arm64_writer_put_cmp_reg_reg (GumArm64Writer * self,
                                  arm64_reg reg_a,
                                  arm64_reg reg_b)
{
  GumArm64RegInfo ra, rb;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);

  if (ra.width != rb.width)
    return FALSE;

  gum_arm64_writer_put_instruction (self, ra.sf | 0x6b00001f | (ra.index << 5) |
      (rb.index << 16));

  return TRUE;
}

gboolean
gum_arm64_writer_put_xpaci_reg (GumArm64Writer * self,
                                arm64_reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0xdac143e0 | ri.index);

  return TRUE;
}

void
gum_arm64_writer_put_nop (GumArm64Writer * self)
{
  gum_arm64_writer_put_instruction (self, 0xd503201f);
}

void
gum_arm64_writer_put_brk_imm (GumArm64Writer * self,
                              guint16 imm)
{
  gum_arm64_writer_put_instruction (self, 0xd4200000 | (imm << 5));
}

gboolean
gum_arm64_writer_put_mrs (GumArm64Writer * self,
                          arm64_reg dst_reg,
                          guint16 system_reg)
{
  GumArm64RegInfo rt;

  gum_arm64_writer_describe_reg (self, dst_reg, &rt);

  if (rt.width != 64 || (system_reg & 0x8000) != 0)
    return FALSE;

  gum_arm64_writer_put_instruction (self,
      0xd5300000 |
      (system_reg << 5) |
      rt.index);

  return TRUE;
}

static void
gum_arm64_writer_put_load_store_pair (GumArm64Writer * self,
                                      GumArm64MemOperationType operation_type,
                                      GumArm64MemOperandType operand_type,
                                      guint rt,
                                      guint rt2,
                                      guint rn,
                                      gssize rn_offset,
                                      GumArm64IndexMode mode)
{
  guint opc;
  gboolean is_vector;
  gsize shift;

  switch (operand_type)
  {
    case GUM_MEM_OPERAND_I32:
      opc = 0;
      is_vector = FALSE;
      shift = 2;
      break;
    case GUM_MEM_OPERAND_I64:
      opc = 2;
      is_vector = FALSE;
      shift = 3;
      break;
    case GUM_MEM_OPERAND_S32:
      opc = 0;
      is_vector = TRUE;
      shift = 2;
      break;
    case GUM_MEM_OPERAND_D64:
      opc = 1;
      is_vector = TRUE;
      shift = 3;
      break;
    case GUM_MEM_OPERAND_Q128:
      opc = 2;
      is_vector = TRUE;
      shift = 4;
      break;
    default:
      opc = 0;
      is_vector = FALSE;
      shift = 0;
      g_assert_not_reached ();
  }

  gum_arm64_writer_put_instruction (self, (opc << 30) | (5 << 27) |
      (is_vector << 26) | (mode << 23) | (operation_type << 22) |
      (((rn_offset >> shift) & 0x7f) << 15) |
      (rt2 << 10) | (rn << 5) | rt);
}

void
gum_arm64_writer_put_instruction (GumArm64Writer * self,
                                  guint32 insn)
{
  *self->code++ = GUINT32_TO_LE (insn);
  self->pc += 4;

  gum_arm64_writer_maybe_commit_literals (self);
}

gboolean
gum_arm64_writer_put_bytes (GumArm64Writer * self,
                            const guint8 * data,
                            guint n)
{
  if (n % 4 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;

  gum_arm64_writer_maybe_commit_literals (self);

  return TRUE;
}

GumAddress
gum_arm64_writer_sign (GumArm64Writer * self,
                       GumAddress value)
{
  if (self->ptrauth_support != GUM_PTRAUTH_SUPPORTED)
    return value;

  return self->sign (value);
}

static GumAddress
gum_arm64_writer_strip (GumArm64Writer * self,
                        GumAddress value)
{
  if (self->ptrauth_support != GUM_PTRAUTH_SUPPORTED)
    return value;

  if (self->target_os == GUM_OS_MACOS || self->target_os == GUM_OS_IOS)
    return value & G_GUINT64_CONSTANT (0x7fffffffff);

  return value;
}

static gboolean
gum_arm64_writer_try_commit_label_refs (GumArm64Writer * self)
{
  guint num_refs, ref_index;

  if (!gum_arm64_writer_has_label_refs (self))
    return TRUE;

  if (!gum_arm64_writer_has_label_defs (self))
    return FALSE;

  num_refs = self->label_refs.length;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumArm64LabelRef * r;
    const guint32 * target_insn;
    gssize distance;
    guint32 insn;

    r = gum_metal_array_element_at (&self->label_refs, ref_index);

    target_insn = gum_metal_hash_table_lookup (self->label_defs, r->id);
    if (target_insn == NULL)
      return FALSE;

    distance = target_insn - r->insn;

    insn = GUINT32_FROM_LE (*r->insn);
    switch (r->type)
    {
      case GUM_ARM64_B:
      case GUM_ARM64_BL:
        if (!GUM_IS_WITHIN_INT26_RANGE (distance))
          return FALSE;
        insn |= distance & GUM_INT26_MASK;
        break;
      case GUM_ARM64_B_COND:
      case GUM_ARM64_CBZ:
      case GUM_ARM64_CBNZ:
        if (!GUM_IS_WITHIN_INT19_RANGE (distance))
          return FALSE;
        insn |= (distance & GUM_INT19_MASK) << 5;
        break;
      case GUM_ARM64_TBZ:
      case GUM_ARM64_TBNZ:
        if (!GUM_IS_WITHIN_INT14_RANGE (distance))
          return FALSE;
        insn |= (distance & GUM_INT14_MASK) << 5;
        break;
      default:
        g_assert_not_reached ();
    }

    *r->insn = GUINT32_TO_LE (insn);
  }

  gum_metal_array_remove_all (&self->label_refs);

  return TRUE;
}

static void
gum_arm64_writer_maybe_commit_literals (GumArm64Writer * self)
{
  gsize space_used;
  gconstpointer after_literals = self->code;

  if (self->earliest_literal_insn == NULL)
    return;

  space_used = (self->code - self->earliest_literal_insn) * sizeof (guint32);
  space_used += self->literal_refs.length * sizeof (guint64);
  if (space_used <= 1048572)
    return;

  self->earliest_literal_insn = NULL;

  gum_arm64_writer_put_b_label (self, after_literals);
  gum_arm64_writer_commit_literals (self);
  gum_arm64_writer_put_label (self, after_literals);
}

static void
gum_arm64_writer_commit_literals (GumArm64Writer * self)
{
  guint num_refs, ref_index;
  gpointer first_slot, last_slot;

  if (!gum_arm64_writer_has_literal_refs (self))
    return;

  num_refs = self->literal_refs.length;
  if (num_refs == 0)
    return;

  first_slot = self->code;
  last_slot = first_slot;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumArm64LiteralRef * r;
    gint64 * slot;
    gint64 distance;
    guint32 insn;

    r = gum_metal_array_element_at (&self->literal_refs, ref_index);

    if (r->width != GUM_LITERAL_64BIT)
      continue;

    for (slot = first_slot; slot != last_slot; slot++)
    {
      if (GINT64_FROM_LE (*slot) == r->val)
        break;
    }

    if (slot == last_slot)
    {
      *slot = GINT64_TO_LE (r->val);
      last_slot = slot + 1;
    }

    distance = (gint64) GPOINTER_TO_SIZE (slot) -
        (gint64) GPOINTER_TO_SIZE (r->insn);

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= ((distance / 4) & GUM_INT19_MASK) << 5;
    *r->insn = GUINT32_TO_LE (insn);
  }

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumArm64LiteralRef * r;
    gint32 * slot;
    gint64 distance;
    guint32 insn;

    r = gum_metal_array_element_at (&self->literal_refs, ref_index);

    if (r->width != GUM_LITERAL_32BIT)
      continue;

    for (slot = first_slot; slot != last_slot; slot++)
    {
      if (GINT32_FROM_LE (*slot) == r->val)
        break;
    }

    if (slot == last_slot)
    {
      *slot = GINT32_TO_LE (r->val);
      last_slot = slot + 1;
    }

    distance = (gint64) GPOINTER_TO_SIZE (slot) -
        (gint64) GPOINTER_TO_SIZE (r->insn);

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= ((distance / 4) & GUM_INT19_MASK) << 5;
    *r->insn = GUINT32_TO_LE (insn);
  }

  self->code = (guint32 *) last_slot;
  self->pc += (guint8 *) last_slot - (guint8 *) first_slot;

  gum_metal_array_remove_all (&self->literal_refs);
}

static void
gum_arm64_writer_describe_reg (GumArm64Writer * self,
                               arm64_reg reg,
                               GumArm64RegInfo * ri)
{
  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_X0);
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_X29)
  {
    ri->meta = GUM_MREG_R29;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_X30)
  {
    ri->meta = GUM_MREG_R30;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_SP)
  {
    ri->meta = GUM_MREG_SP;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_W0);
    ri->is_integer = TRUE;
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_S0);
    ri->is_integer = FALSE;
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_D0);
    ri->is_integer = FALSE;
    ri->width = 64;
    ri->sf = 0x00000000;
  }
  else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
  {
    ri->meta = GUM_MREG_R0 + (reg - ARM64_REG_Q0);
    ri->is_integer = FALSE;
    ri->width = 128;
    ri->sf = 0x00000000;
  }
  else if (reg == ARM64_REG_XZR)
  {
    ri->meta = GUM_MREG_ZR;
    ri->is_integer = TRUE;
    ri->width = 64;
    ri->sf = 0x80000000;
  }
  else if (reg == ARM64_REG_WZR)
  {
    ri->meta = GUM_MREG_ZR;
    ri->is_integer = TRUE;
    ri->width = 32;
    ri->sf = 0x00000000;
  }
  else
  {
    g_assert_not_reached ();
  }
  ri->index = ri->meta - GUM_MREG_R0;
}

static GumArm64MemOperandType
gum_arm64_mem_operand_type_from_reg_info (const GumArm64RegInfo * ri)
{
  if (ri->is_integer)
  {
    switch (ri->width)
    {
      case 32: return GUM_MEM_OPERAND_I32;
      case 64: return GUM_MEM_OPERAND_I64;
    }
  }
  else
  {
    switch (ri->width)
    {
      case 32: return GUM_MEM_OPERAND_S32;
      case 64: return GUM_MEM_OPERAND_D64;
      case 128: return GUM_MEM_OPERAND_Q128;
    }
  }

  g_assert_not_reached ();
  return GUM_MEM_OPERAND_I32;
}

static gboolean
gum_arm64_try_encode_logical_immediate (guint64 imm_value,
                                        guint reg_width,
                                        guint * imm_enc)
{
  guint element_size, num_rotations, num_trailing_ones;
  guint immr, imms, n;

  if (imm_value == 0 || imm_value == ~G_GUINT64_CONSTANT (0))
    return FALSE;
  if (reg_width == 32)
  {
    if ((imm_value >> 32) != 0 || imm_value == ~0U)
      return FALSE;
  }

  element_size =
      gum_arm64_determine_logical_element_size (imm_value, reg_width);

  if (!gum_arm64_try_determine_logical_rotation (imm_value, element_size,
      &num_rotations, &num_trailing_ones))
    return FALSE;

  immr = (element_size - num_rotations) & (element_size - 1);

  imms = ~(element_size - 1) << 1;
  imms |= num_trailing_ones - 1;

  n = ((imms >> 6) & 1) ^ 1;

  *imm_enc = (n << 12) | (immr << 6) | (imms & 0x3f);

  return TRUE;
}

static guint
gum_arm64_determine_logical_element_size (guint64 imm_value,
                                          guint reg_width)
{
  guint size = reg_width;

  do
  {
    guint next_size;
    guint64 mask;

    next_size = size / 2;

    mask = (G_GUINT64_CONSTANT (1) << next_size) - 1;
    if ((imm_value & mask) != ((imm_value >> next_size) & mask))
      break;

    size = next_size;
  }
  while (size > 2);

  return size;
}

static gboolean
gum_arm64_try_determine_logical_rotation (guint64 imm_value,
                                          guint element_size,
                                          guint * num_rotations,
                                          guint * num_trailing_ones)
{
  guint64 mask;

  mask = ((guint64) G_GINT64_CONSTANT (-1)) >> (64 - element_size);

  imm_value &= mask;

  if (gum_is_shifted_mask_64 (imm_value))
  {
    *num_rotations = gum_count_trailing_zeros (imm_value);
    *num_trailing_ones = gum_count_trailing_ones (imm_value >> *num_rotations);
  }
  else
  {
    guint num_leading_ones;

    imm_value |= ~mask;
    if (!gum_is_shifted_mask_64 (~imm_value))
      return FALSE;

    num_leading_ones = gum_count_leading_ones (imm_value);
    *num_rotations = 64 - num_leading_ones;
    *num_trailing_ones = num_leading_ones +
        gum_count_trailing_ones (imm_value) -
        (64 - element_size);
  }

  return TRUE;
}

static gboolean
gum_is_shifted_mask_64 (guint64 value)
{
  if (value == 0)
    return FALSE;

  return gum_is_mask_64 ((value - 1) | value);
}

static gboolean
gum_is_mask_64 (guint64 value)
{
  if (value == 0)
    return FALSE;

  return ((value + 1) & value) == 0;
}

static guint
gum_count_leading_zeros (guint64 value)
{
  if (value == 0)
    return 64;

#if defined (_MSC_VER) && GLIB_SIZEOF_VOID_P == 4
  {
    unsigned long index;

    if (_BitScanReverse (&index, value >> 32))
      return 31 - index;

    _BitScanReverse (&index, value & 0xffffffff);

    return 63 - index;
  }
#elif defined (_MSC_VER) && GLIB_SIZEOF_VOID_P == 8
  {
    unsigned long index;

    _BitScanReverse64 (&index, value);

    return 63 - index;
  }
#elif defined (HAVE_CLTZ)
  return __builtin_clzll (value);
#else
  guint num_zeros = 0;
  guint64 bits = value;

  while ((bits & (G_GUINT64_CONSTANT (1) << 63)) == 0)
  {
    num_zeros++;
    bits <<= 1;
  }

  return num_zeros;
#endif
}

static guint
gum_count_trailing_zeros (guint64 value)
{
  if (value == 0)
    return 64;

#if defined (_MSC_VER) && GLIB_SIZEOF_VOID_P == 4
  {
    unsigned long index;

    if (_BitScanForward (&index, value & 0xffffffff))
      return index;

    _BitScanForward (&index, value >> 32);

    return 32 + index;
  }
#elif defined (_MSC_VER) && GLIB_SIZEOF_VOID_P == 8
  {
    unsigned long index;

    _BitScanForward64 (&index, value);

    return index;
  }
#elif defined (HAVE_CLTZ)
  return __builtin_ctzll (value);
#else
  guint num_zeros = 0;
  guint64 bits = value;

  while ((bits & G_GUINT64_CONSTANT (1)) == 0)
  {
    num_zeros++;
    bits >>= 1;
  }

  return num_zeros;
#endif
}

static guint
gum_count_leading_ones (guint64 value)
{
  return gum_count_leading_zeros (~value);
}

static guint
gum_count_trailing_ones (guint64 value)
{
  return gum_count_trailing_zeros (~value);
}

"""


```