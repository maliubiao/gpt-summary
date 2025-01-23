Response:
The user wants a functional summary of the provided C code snippet, which is part of Frida's dynamic instrumentation tools. I need to identify the core functionalities, explain their relation to reverse engineering and low-level concepts, and provide illustrative examples including potential user errors. Finally, I need to summarise the functionalities.

**Plan:**

1. **Identify Core Functionalities:** Analyze the function names and their implementations to understand the operations performed. The prefix `gum_thumb_writer_put_` suggests these functions write specific Thumb instructions.
2. **Relate to Reverse Engineering:** Explain how generating and injecting code relates to dynamic analysis and code manipulation in reverse engineering.
3. **Explain Low-Level Concepts:** Point out the usage of ARM-specific registers, instructions (Thumb), and memory manipulation. Mention the relevance of operating system concepts (Linux/Android breakpoints).
4. **Provide Logic Examples:** For a few representative functions, provide example inputs (register names, immediate values) and predict the generated Thumb instruction.
5. **Illustrate User Errors:** Identify common mistakes users might make when using these functions, such as providing out-of-range values for immediate operands or incorrect register types.
6. **Explain User Path (Debugging Context):** Describe how a user interacting with Frida's API might trigger the execution of these low-level instruction writing functions.
7. **Summarize Functionality:**  Provide a concise overview of the module's purpose.
这是frida-gum库中用于生成ARM Thumb指令的C代码，主要功能是提供了一系列函数，用于将不同的ARM Thumb指令编码并写入到内存中。这在动态 instrumentation中非常关键，因为它允许Frida在运行时修改目标进程的代码。

**功能归纳：**

1. **指令写入核心功能：**
   - `gum_thumb_writer_put_instruction`: 将一个16位的Thumb指令写入内存。
   - `gum_thumb_writer_put_instruction_wide`: 将一个32位的Thumb指令（由两个16位组成）写入内存。
   - `gum_thumb_writer_put_bytes`: 将原始字节数据写入内存，用于直接插入指令或数据。

2. **常用 Thumb 指令的封装：** 提供了一系列以 `gum_thumb_writer_put_` 开头的函数，封装了常见的 Thumb 指令，例如：
   - **算术运算指令:** `gum_thumb_writer_put_add_reg_imm`, `gum_thumb_writer_put_add_reg_reg`, `gum_thumb_writer_put_add_reg_reg_imm`, `gum_thumb_writer_put_sub_reg_imm`, `gum_thumb_writer_put_sub_reg_reg`, `gum_thumb_writer_put_sub_reg_reg_reg`, `gum_thumb_writer_put_sub_reg_reg_imm` (加减运算)。
   - **逻辑运算指令:** `gum_thumb_writer_put_and_reg_reg_imm`, `gum_thumb_writer_put_or_reg_reg_imm` (与或运算)。
   - **移位指令:** `gum_thumb_writer_put_lsl_reg_reg_imm`, `gum_thumb_writer_put_lsls_reg_reg_imm`, `gum_thumb_writer_put_lsrs_reg_reg_imm` (逻辑左移和逻辑右移)。
   - **寄存器操作指令:** `gum_thumb_writer_put_mrs_reg_reg`, `gum_thumb_writer_put_msr_reg_reg` (在通用寄存器和特殊寄存器之间移动数据)。
   - **控制流指令:**  虽然这段代码没有直接体现跳转指令，但其写入指令的能力是构建跳转的基础。例如，`gum_thumb_writer_put_add_reg_reg_imm` 可以用来计算跳转目标地址。
   - **其他指令:** `gum_thumb_writer_put_nop` (空操作), `gum_thumb_writer_put_bkpt_imm`, `gum_thumb_writer_put_breakpoint` (断点指令)。

3. **标签 (Label) 管理：**  提供了用于处理代码标签的功能，允许在生成代码时引用尚未确定地址的代码位置，并在后续进行地址回填。
   - `gum_thumb_writer_try_commit_label_refs`: 尝试解析并提交标签引用。
   - `gum_thumb_writer_do_commit_label`: 执行标签的提交，计算偏移并更新指令。

4. **字面量 (Literal) 池管理：** 提供了将立即数加载到寄存器的机制，当需要加载的立即数无法直接编码在指令中时，会将其放置在代码段的字面量池中，并通过PC相对寻址加载。
   - `gum_thumb_writer_maybe_commit_literals`: 检查是否需要提交字面量。
   - `gum_thumb_writer_commit_literals`: 将字面量数据写入内存并更新相关的加载指令。
   - `gum_instruction_is_t1_load`: 检查是否是T1加载指令。

5. **辅助功能：**
   - `gum_thumb_writer_put_it_al`:  用于写入 IT (If-Then) 代码块的 "always" 条件，在某些 Thumb 指令序列中需要。

**与逆向方法的关系及举例说明：**

这段代码是 Frida 实现动态插桩的核心组件。逆向工程师可以使用 Frida 的 API 来调用这些函数，从而在目标进程的内存中注入自定义的 Thumb 代码，以达到以下目的：

* **Hook 函数执行:**  在目标函数的入口处插入代码，例如使用 `gum_thumb_writer_put_bytes` 写入 `push {r0-r7, lr}` 保存寄存器状态，然后调用自定义的 JavaScript 函数进行分析或修改参数，最后再使用 `gum_thumb_writer_put_bytes` 写入 `pop {r0-r7, pc}` 恢复寄存器状态并返回。
* **修改函数行为:**  替换目标函数的部分指令，例如使用 `gum_thumb_writer_put_mov_reg_imm` 将返回值寄存器设置为特定的值，从而改变函数的执行结果。
* **跟踪程序流程:**  在关键代码路径上插入断点指令 (`gum_thumb_writer_put_breakpoint`)，当程序执行到这些位置时，Frida 可以捕获并通知逆向工程师。
* **动态修改数据:** 虽然代码本身不直接修改数据，但生成的指令可以实现数据修改，例如使用 `gum_thumb_writer_put_str_reg_reg_offset` 指令将寄存器的值存储到内存中的特定位置。

**涉及到的二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **ARM Thumb 指令集:** 代码直接操作 ARM Thumb 指令的编码格式，例如 `gum_thumb_writer_put_add_reg_imm` 函数根据寄存器和立即数的值，构建出符合 Thumb 指令格式的 16 位二进制码。这需要对 ARM 架构和 Thumb 指令集有深入的了解。
* **寄存器操作:** 代码中大量使用了 ARM 寄存器 (如 `ARM_REG_R0` 到 `ARM_REG_R7`, `ARM_REG_SP`, `ARM_REG_PC`, `ARM_SYSREG_APSR_NZCVQ`)，并根据寄存器的类型和索引进行不同的编码。这涉及到 ARM 架构的寄存器组织和用途。
* **内存操作:**  `*self->code++ = GUINT16_TO_LE (insn);` 这行代码直接将生成的指令写入到内存中，`self->code` 指向的是目标进程中分配的可执行内存区域。
* **字节序 (Endianness):**  `GUINT16_TO_LE` 表明代码考虑了小端字节序，这是 ARM 架构常见的字节序。
* **操作系统接口 (Linux/Android):** `gum_thumb_writer_put_breakpoint` 函数根据目标操作系统选择不同的断点指令 (`0xde01` for Linux/Android)，这说明了 Frida 需要处理不同操作系统的差异。`0xde01` 对应 Linux/Android 系统调用中的 `SYS_breakpoint`。
* **地址计算和重定位:** 标签 (Label) 和字面量 (Literal) 的处理涉及到地址的计算和重定位，确保插入的代码在目标进程的内存中能够正确执行。例如，计算跳转指令的目标地址偏移量。

**逻辑推理、假设输入与输出：**

以 `gum_thumb_writer_put_add_reg_imm` 函数为例：

**假设输入：**

* `self`: 指向 `GumThumbWriter` 结构体的指针。
* `dst_reg`: `ARM_REG_R0` (目标寄存器)。
* `imm_value`: `5` (立即数)。

**逻辑推理：**

该函数旨在生成将立即数加到寄存器的 Thumb 指令。对于小的正立即数，Thumb 指令集有特定的编码方式。查阅 ARM Thumb 指令集手册，`add r<n>, #<imm>`  的编码格式为 `00110 <imm3> <Rn> <Rm>` (其中 `<Rm>` 和 `<Rn>` 是相同的)。

**输出 (推测的机器码):**

根据目标寄存器 R0 和立即数 5 (二进制 101)，推测生成的 16 位指令码的二进制表示可能类似于 `00110 101 000 000`，转换为十六进制可能是 `0x3100` (实际编码可能略有不同，需要精确查阅 Thumb 指令集手册)。

**涉及用户或者编程常见的使用错误及举例说明：**

* **立即数超出范围:** 例如，`gum_thumb_writer_put_add_reg_imm(self, ARM_REG_R0, 256)`。Thumb 中某些加法指令的立即数范围有限，超出范围会导致函数返回 `FALSE` 或生成错误的指令。
* **使用错误的寄存器类型:** 例如，某些指令只能操作低寄存器 (R0-R7)，如果传入高寄存器 (R8-R12) 可能会导致错误，如 `gum_thumb_writer_put_add_reg_reg_imm(self, ARM_REG_R8, ARM_REG_R0, 5)` 可能会返回 `FALSE`。
* **在需要对齐的地址写入非对齐的数据:** 虽然 `gum_thumb_writer_put_instruction` 每次写入 2 字节，但如果用户通过其他方式操作 `self->code` 指针，可能导致写入地址未对齐，在某些架构上会引起错误。
* **尝试写入只读内存:** 如果 `self->code` 指向的内存区域没有写入权限，会导致程序崩溃。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户使用 Frida 的 Python API。** 例如，用户编写了一个 Frida 脚本，想要 hook 一个 Android 应用的某个函数。
2. **用户调用 `Interceptor.attach` 方法。**  指定要 hook 的函数地址或名称，并提供一个 JavaScript 回调函数。
3. **Frida 的 JavaScript 引擎执行用户的回调函数。** 在回调函数中，用户可能会使用 `Stalker` API 来跟踪代码执行，或者直接使用 `Instruction.replace` 或 `Memory.patchCode` 等 API 来修改目标代码。
4. **当需要修改目标代码时，Frida 会调用 `frida-gum` 库的相应功能。** 例如，如果用户使用 `Instruction.replace`，Frida 会根据用户提供的新的指令，调用 `gum_thumb_writer_t` 相关的函数来生成对应的机器码。
5. **`gum_thumb_writer_put_add_reg_imm` 等函数被调用。**  Frida 会根据需要生成的 ARM Thumb 指令类型，调用相应的 `gum_thumb_writer_put_` 函数，将指令编码并写入到目标进程的内存中。
6. **`self->code` 指针指向目标进程中分配的可写可执行内存。** Frida 负责在目标进程中分配和管理这些内存区域。

**总结它的功能：**

总而言之，`gumthumbwriter.c` 文件的核心功能是提供了一组底层的 C 函数，用于方便且正确地生成 ARM Thumb 指令序列，并将其写入到内存中。它是 Frida 实现动态代码插桩的关键组成部分，为高级 API 提供了底层的指令编码能力。通过这些函数，Frida 能够在运行时修改目标进程的代码，实现诸如 hook 函数、修改程序行为、跟踪执行流程等逆向分析和动态 instrumentation 的目标。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/arch-arm/gumthumbwriter.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
um_thumb_writer_put_it_al (self);
  }

  gum_thumb_writer_put_instruction (self, insn);
}

gboolean
gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self,
                                      arm_reg dst_reg,
                                      arm_reg left_reg,
                                      gssize right_value)
{
  GumArmRegInfo dst, left;
  guint16 insn;

  gum_arm_reg_describe (dst_reg, &dst);
  gum_arm_reg_describe (left_reg, &left);

  if (left.meta == dst.meta)
  {
    return gum_thumb_writer_put_add_reg_imm (self, dst_reg, right_value);
  }

  if (dst_reg < ARM_REG_R0 || dst_reg > ARM_REG_R7)
    return FALSE;

  if (left_reg != ARM_REG_SP && left_reg != ARM_REG_PC &&
      (left_reg < ARM_REG_R0 || left_reg > ARM_REG_R7))
  {
    return FALSE;
  }

  if (left.meta == GUM_ARM_MREG_SP || left.meta == GUM_ARM_MREG_PC)
  {
    guint16 base_mask;

    if (right_value < 0 || right_value % 4 != 0)
      return FALSE;

    if (left.meta == GUM_ARM_MREG_SP)
      base_mask = 0x0800;
    else
      base_mask = 0x0000;

    /* ADR instruction doesn't modify flags */
    insn = 0xa000 | base_mask | (dst.index << 8) | (right_value / 4);
  }
  else
  {
    guint16 sign_mask = 0x0000;

    if (ABS (right_value) > 7)
      return FALSE;

    if (right_value < 0)
      sign_mask = 0x0200;

    insn = 0x1c00 | sign_mask | (ABS (right_value) << 6) | (left.index << 3) |
        dst.index;
    gum_thumb_writer_put_it_al (self);
  }

  gum_thumb_writer_put_instruction (self, insn);

  return TRUE;
}

static void
gum_thumb_writer_put_it_al (GumThumbWriter * self)
{
  gum_thumb_writer_put_instruction (self, 0xbfe8);
}

gboolean
gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self,
                                  arm_reg dst_reg,
                                  gssize imm_value)
{
  return gum_thumb_writer_put_add_reg_imm (self, dst_reg, -imm_value);
}

void
gum_thumb_writer_put_sub_reg_reg (GumThumbWriter * self,
                                  arm_reg dst_reg,
                                  arm_reg src_reg)
{
  gum_thumb_writer_put_sub_reg_reg_reg (self, dst_reg, dst_reg, src_reg);
}

void
gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self,
                                      arm_reg dst_reg,
                                      arm_reg left_reg,
                                      arm_reg right_reg)
{
  GumArmRegInfo dst, left, right;
  guint16 insn;

  gum_arm_reg_describe (dst_reg, &dst);
  gum_arm_reg_describe (left_reg, &left);
  gum_arm_reg_describe (right_reg, &right);

  insn = 0x1a00 | (right.index << 6) | (left.index << 3) | dst.index;

  gum_thumb_writer_put_it_al (self);
  gum_thumb_writer_put_instruction (self, insn);
}

gboolean
gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self,
                                      arm_reg dst_reg,
                                      arm_reg left_reg,
                                      gssize right_value)
{
  return gum_thumb_writer_put_add_reg_reg_imm (self, dst_reg, left_reg,
      -right_value);
}

gboolean
gum_thumb_writer_put_and_reg_reg_imm (GumThumbWriter * self,
                                      arm_reg dst_reg,
                                      arm_reg left_reg,
                                      gssize right_value)
{
  GumArmRegInfo dst, left;
  guint16 imm8, insn_high, insn_low;

  gum_arm_reg_describe (dst_reg, &dst);
  gum_arm_reg_describe (left_reg, &left);

  /*
   * Thumb does allow up to a 12bit immediate, but the encoded form for this is
   * complex and we don't yet need it for our use-cases.
   */
  if (!GUM_IS_WITHIN_UINT8_RANGE (right_value))
    return FALSE;

  imm8 = right_value & 0xff;
  insn_high = 0xf000 | left.index;
  insn_low = (dst.index << 8) | imm8;

  gum_thumb_writer_put_instruction_wide (self, insn_high, insn_low);

  return TRUE;
}

gboolean
gum_thumb_writer_put_or_reg_reg_imm (GumThumbWriter * self,
                                     arm_reg dst_reg,
                                     arm_reg left_reg,
                                     gssize right_value)
{
  GumArmRegInfo dst, left;
  guint16 imm8, insn_high, insn_low;

  gum_arm_reg_describe (dst_reg, &dst);
  gum_arm_reg_describe (left_reg, &left);

  /*
   * Thumb does allow up to a 12bit immediate, but the encoded form for this is
   * complex and we don't yet need it for our use-cases.
   */
  if (!GUM_IS_WITHIN_UINT8_RANGE (right_value))
    return FALSE;

  imm8 = right_value & 0xff;
  insn_high = 0xf040 | left.index;
  insn_low = (dst.index << 8) | imm8;

  gum_thumb_writer_put_instruction_wide (self, insn_high, insn_low);

  return TRUE;
}

gboolean
gum_thumb_writer_put_lsl_reg_reg_imm (GumThumbWriter * self,
                                      arm_reg dst_reg,
                                      arm_reg left_reg,
                                      guint8 right_value)
{
  gum_thumb_writer_put_it_al (self);

  return gum_thumb_writer_put_lsls_reg_reg_imm (self, dst_reg, left_reg,
      right_value);
}

gboolean
gum_thumb_writer_put_lsls_reg_reg_imm (GumThumbWriter * self,
                                       arm_reg dst_reg,
                                       arm_reg left_reg,
                                       guint8 right_value)
{
  GumArmRegInfo dst, left;

  if (right_value == 0 || right_value > 31)
    return FALSE;

  gum_arm_reg_describe (dst_reg, &dst);
  gum_arm_reg_describe (left_reg, &left);

  gum_thumb_writer_put_instruction (self, 0x0000 | (right_value << 6) |
      (left.index << 3) | dst.index);

  return TRUE;
}

gboolean
gum_thumb_writer_put_lsrs_reg_reg_imm (GumThumbWriter * self,
                                       arm_reg dst_reg,
                                       arm_reg left_reg,
                                       guint8 right_value)
{
  GumArmRegInfo dst, left;

  if (right_value == 0 || right_value > 31)
    return FALSE;

  gum_arm_reg_describe (dst_reg, &dst);
  gum_arm_reg_describe (left_reg, &left);

  gum_thumb_writer_put_instruction (self, 0x0800 | (right_value << 6) |
      (left.index << 3) | dst.index);

  return TRUE;
}

gboolean
gum_thumb_writer_put_mrs_reg_reg (GumThumbWriter * self,
                                  arm_reg dst_reg,
                                  arm_sysreg src_reg)
{
  GumArmRegInfo dst;

  gum_arm_reg_describe (dst_reg, &dst);

  if (dst.meta > GUM_ARM_MREG_R12)
    return FALSE;
  if (src_reg != ARM_SYSREG_APSR_NZCVQ)
    return FALSE;

  gum_thumb_writer_put_instruction_wide (self,
      0xf3ef,
      0x8000 | (dst.index << 8));

  return TRUE;
}

gboolean
gum_thumb_writer_put_msr_reg_reg (GumThumbWriter * self,
                                  arm_sysreg dst_reg,
                                  arm_reg src_reg)
{
  GumArmRegInfo src;

  gum_arm_reg_describe (src_reg, &src);

  if (dst_reg != ARM_SYSREG_APSR_NZCVQ)
    return FALSE;
  if (src.meta > GUM_ARM_MREG_R12)
    return FALSE;

  gum_thumb_writer_put_instruction_wide (self,
      0xf380 | src.index,
      0x8800);

  return TRUE;
}

void
gum_thumb_writer_put_nop (GumThumbWriter * self)
{
  gum_thumb_writer_put_instruction (self, 0xbf00);
}

void
gum_thumb_writer_put_bkpt_imm (GumThumbWriter * self,
                               guint8 imm)
{
  gum_thumb_writer_put_instruction (self, 0xbe00 | imm);
}

void
gum_thumb_writer_put_breakpoint (GumThumbWriter * self)
{
  switch (self->target_os)
  {
    case GUM_OS_LINUX:
    case GUM_OS_ANDROID:
      gum_thumb_writer_put_instruction (self, 0xde01);
      break;
    default:
      gum_thumb_writer_put_bkpt_imm (self, 0);
      gum_thumb_writer_put_bx_reg (self, ARM_REG_LR);
      break;
  }
}

void
gum_thumb_writer_put_instruction (GumThumbWriter * self,
                                  guint16 insn)
{
  *self->code++ = GUINT16_TO_LE (insn);
  self->pc += 2;

  gum_thumb_writer_maybe_commit_literals (self);
}

void
gum_thumb_writer_put_instruction_wide (GumThumbWriter * self,
                                       guint16 upper,
                                       guint16 lower)
{
  *self->code++ = GUINT16_TO_LE (upper);
  *self->code++ = GUINT16_TO_LE (lower);
  self->pc += 4;

  gum_thumb_writer_maybe_commit_literals (self);
}

gboolean
gum_thumb_writer_put_bytes (GumThumbWriter * self,
                            const guint8 * data,
                            guint n)
{
  if (n % 2 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint16);
  self->pc += n;

  gum_thumb_writer_maybe_commit_literals (self);

  return TRUE;
}

static gboolean
gum_thumb_writer_try_commit_label_refs (GumThumbWriter * self)
{
  guint num_refs, ref_index;

  if (!gum_thumb_writer_has_label_refs (self))
    return TRUE;

  if (!gum_thumb_writer_has_label_defs (self))
    return FALSE;

  num_refs = self->label_refs.length;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumThumbLabelRef * r;
    const guint16 * target_insn;

    r = gum_metal_array_element_at (&self->label_refs, ref_index);

    target_insn = gum_metal_hash_table_lookup (self->label_defs, r->id);
    if (target_insn == NULL)
      return FALSE;

    if (!gum_thumb_writer_do_commit_label (r, target_insn))
      return FALSE;
  }

  gum_metal_array_remove_all (&self->label_refs);

  return TRUE;
}

static gboolean
gum_thumb_writer_do_commit_label (GumThumbLabelRef * r,
                                  const guint16 * target_insn)
{
  gssize distance;
  guint16 insn;

  distance = target_insn - (r->insn + 2);

  insn = GUINT16_FROM_LE (*r->insn);
  switch (r->type)
  {
    case GUM_THUMB_B_T1:
      if (!GUM_IS_WITHIN_INT8_RANGE (distance))
        return FALSE;
      insn |= distance & GUM_INT8_MASK;
      break;
    case GUM_THUMB_B_T2:
      if (!GUM_IS_WITHIN_INT11_RANGE (distance))
        return FALSE;
      insn |= distance & GUM_INT11_MASK;
      break;
    case GUM_THUMB_B_T3:
    {
      union
      {
        gint32 i;
        guint32 u;
      } distance_word;
      guint32 s, j2, j1, imm6, imm11;
      guint16 insn_low;

      if (!GUM_IS_WITHIN_INT20_RANGE (distance))
        return FALSE;

      insn_low = GUINT16_FROM_LE (r->insn[1]);

      distance_word.i = distance;

      s =  (distance_word.u >> 23) & 1;
      j2 = (distance_word.u >> 18) & 1;
      j1 = (distance_word.u >> 17) & 1;
      imm6 = (distance_word.u >> 11) & GUM_INT6_MASK;
      imm11 = distance_word.u        & GUM_INT11_MASK;

      insn     |=  (s << 10) | imm6;
      insn_low |= (j1 << 13) | (j2 << 11) | imm11;

      r->insn[1] = GUINT16_TO_LE (insn_low);

      break;
    }
    case GUM_THUMB_B_T4:
    case GUM_THUMB_BL_T1:
    {
      union
      {
        gint32 i;
        guint32 u;
      } distance_word;
      guint16 s, i1, i2, j1, j2, imm10, imm11;
      guint16 insn_low;

      if (!GUM_IS_WITHIN_INT24_RANGE (distance))
        return FALSE;

      insn_low = GUINT16_FROM_LE (r->insn[1]);

      distance_word.i = distance;

      s =  (distance_word.u >> 23) & 1;
      i1 = (distance_word.u >> 22) & 1;
      i2 = (distance_word.u >> 21) & 1;
      j1 = (i1 ^ 1) ^ s;
      j2 = (i2 ^ 1) ^ s;

      imm10 = (distance_word.u >> 11) & GUM_INT10_MASK;
      imm11 =  distance_word.u        & GUM_INT11_MASK;

      insn     |=  (s << 10) | imm10;
      insn_low |= (j1 << 13) | (j2 << 11) | imm11;

      r->insn[1] = GUINT16_TO_LE (insn_low);

      break;
    }
    case GUM_THUMB_CBZ_T1:
    case GUM_THUMB_CBNZ_T1:
    {
      guint16 i, imm5;

      if (!GUM_IS_WITHIN_UINT7_RANGE (distance * sizeof (guint16)))
        return FALSE;

      i = (distance >> 5) & 1;
      imm5 = distance & GUM_INT5_MASK;

      insn |= (i << 9) | (imm5 << 3);

      break;
    }
    default:
      g_assert_not_reached ();
  }

  *r->insn = GUINT16_TO_LE (insn);

  return TRUE;
}

static void
gum_thumb_writer_maybe_commit_literals (GumThumbWriter * self)
{
  gsize space_used;
  gconstpointer after_literals = self->code;

  if (self->earliest_literal_insn == NULL)
    return;

  space_used = (self->code - self->earliest_literal_insn) * sizeof (guint16);
  space_used += self->literal_refs.length * sizeof (guint32);
  if (space_used <= 1024)
    return;

  self->earliest_literal_insn = NULL;

  gum_thumb_writer_put_b_label (self, after_literals);
  gum_thumb_writer_commit_literals (self);
  gum_thumb_writer_put_label (self, after_literals);
}

static void
gum_thumb_writer_commit_literals (GumThumbWriter * self)
{
  guint num_refs, ref_index;
  gboolean need_alignment_padding;
  guint32 * first_slot, * last_slot;

  if (!gum_thumb_writer_has_literal_refs (self))
    return;

  num_refs = self->literal_refs.length;
  if (num_refs == 0)
    return;

  need_alignment_padding = (self->pc & 3) != 0;
  if (need_alignment_padding)
  {
    gum_thumb_writer_put_nop (self);
  }

  first_slot = (guint32 *) self->code;
  last_slot = first_slot;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumThumbLiteralRef * r;
    guint16 insn;
    guint32 * cur_slot;
    GumAddress slot_pc;
    gsize distance_in_bytes;

    r = gum_metal_array_element_at (&self->literal_refs, ref_index);
    insn = GUINT16_FROM_LE (r->insn[0]);

    for (cur_slot = first_slot; cur_slot != last_slot; cur_slot++)
    {
      if (*cur_slot == r->val)
        break;
    }

    if (cur_slot == last_slot)
    {
      *cur_slot = r->val;
      self->code += 2;
      self->pc += 4;
      last_slot++;
    }

    slot_pc = self->pc - ((guint8 *) last_slot - (guint8 *) first_slot) +
        ((guint8 *) cur_slot - (guint8 *) first_slot);

    distance_in_bytes = slot_pc - (r->pc & ~((GumAddress) 3));

    if (gum_instruction_is_t1_load (insn))
    {
      r->insn[0] = GUINT16_TO_LE (insn | (distance_in_bytes / 4));
    }
    else
    {
      r->insn[1] = GUINT16_TO_LE (GUINT16_FROM_LE (r->insn[1]) |
          distance_in_bytes);
    }
  }

  gum_metal_array_remove_all (&self->literal_refs);
}

static gboolean
gum_instruction_is_t1_load (guint16 instruction)
{
  return (instruction & 0xf800) == 0x4800;
}
```