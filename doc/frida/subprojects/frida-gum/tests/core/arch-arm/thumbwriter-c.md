Response:
Let's break down the thought process for analyzing this C code and answering the prompt.

1. **Understand the Core Purpose:** The filename `thumbwriter.c` and the inclusion of `thumbwriter-fixture.c` immediately suggest this code is about *generating* ARM Thumb instructions. The presence of `TESTLIST_BEGIN` and `TESTENTRY` strongly indicates this is a unit testing file. Therefore, the primary function is to test the `GumThumbWriter` API.

2. **Identify Key Components:**  Scan the code for important structures, functions, and macros.
    * **`GumThumbWriter`:** This is clearly the central data structure for writing Thumb instructions.
    * **`gum_thumb_writer_put_*` functions:** These are the API for emitting specific Thumb instructions. The names are very descriptive (e.g., `gum_thumb_writer_put_cmp_reg_imm`).
    * **`gum_thumb_writer_put_label`:**  Deals with code labels for branching.
    * **`gum_thumb_writer_flush`:**  Likely writes the generated instructions to the output buffer.
    * **`assert_output_*` macros:**  Used for verifying the generated instruction bytes.
    * **`TESTCASE` macro:**  Defines individual test cases.
    * **`TESTLIST_BEGIN`/`TESTLIST_END`:**  Structure for organizing tests.
    * **`HAVE_ARM` conditional compilation:** Indicates some tests might be architecture-specific.

3. **Analyze Functionality by Grouping:** Instead of going line by line, group the test cases by the type of Thumb instruction they test. This provides a higher-level understanding of the `GumThumbWriter`'s capabilities. For example, there are groups of tests for:
    * Comparisons (`cmp_reg_imm`)
    * Conditional branches (`beq_label`, `bne_label`, `b_cond_label_wide`, `cbz_reg_label`, `cbnz_reg_label`)
    * Unconditional branches (`b_label_wide`)
    * Register transfers (`bx_reg`, `blx_reg`)
    * Function calls (`bl_label`)
    * Stack operations (`push_regs`, `pop_regs`, `vpush_range`, `vpop_range`)
    * Data loading (`ldr_*`)
    * Data storing (`str_*`)
    * Data movement (`mov_*`)
    * Arithmetic operations (`add_*`, `sub_*`)
    * Logical operations (`and_reg_reg_imm`)
    * Shift operations (`lsls_reg_reg_imm`, `lsrs_reg_reg_imm`)
    * System register access (`mrs_reg_reg`, `msr_reg_reg`)
    * No-operation (`nop`)

4. **Relate to Reverse Engineering:**  Think about how generating these instructions is the *opposite* of reverse engineering. Reverse engineers *disassemble* binary code to understand the original instructions. This code *assembles* instructions into their binary representation. Examples of the relationship:
    *  The `assert_output_n_equals` checks are essentially verifying the correct *encoding* of Thumb instructions, which is what a disassembler would try to decode.
    *  Labels and branching instructions are fundamental to understanding control flow in reverse engineering. This code demonstrates how to create those structures.

5. **Consider Binary/Low-Level Aspects:** Recognize that this code deals directly with the binary representation of instructions.
    * The `assert_output_n_equals` checks are against specific hexadecimal values, which are the byte representations of the instructions.
    * The code implicitly uses the Thumb instruction set encoding rules.
    * The `HAVE_ARM` conditional compilation points to architecture-specific details.

6. **Think About Kernel/Framework Connections (If Any):**  While this specific file is low-level, the context of Frida suggests it's used for dynamic instrumentation. This implies that the generated code will be injected into running processes. This connects to concepts like:
    * **Code injection:**  The generated Thumb code will be placed in memory.
    * **Process memory management:**  Understanding how memory is allocated and managed is crucial for instrumentation.
    * **System calls:** While not directly in this file, injected code often interacts with the OS through system calls.

7. **Analyze Logical Reasoning and Assumptions:** Look for test cases that illustrate specific constraints or edge cases of the `GumThumbWriter` API.
    * The `cbz_reg_label_too_short`, `cbz_reg_label_minimum`, `cbz_reg_label_maximum`, and `cbz_reg_label_too_long` tests are excellent examples of testing the limitations of the conditional branch instruction's range. The assumptions are about the maximum offset a `cbz` instruction can handle.

8. **Identify Potential User Errors:** Consider common mistakes a programmer might make when using an API like this.
    * Incorrect register selection.
    * Providing out-of-range immediate values.
    * Not flushing the writer.
    * Misunderstanding the limitations of short vs. wide instructions.

9. **Trace User Actions (Debugging Context):** Imagine a developer using Frida. How might they end up looking at this code?
    * They might be developing a Frida gadget or script.
    * They might encounter an issue with code generation.
    * They might be contributing to the Frida project and need to understand how the Thumb writer works.
    * They might be debugging an instrumentation script and need to see the exact assembly generated.

10. **Structure the Answer:** Organize the information into the requested categories (functionality, relation to reverse engineering, binary/low-level details, logical reasoning, user errors, debugging context). Use clear headings and examples.

11. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. For example, initially, I might have missed explicitly mentioning the connection to code injection and process memory, so a review would help catch that.
这个 `thumbwriter.c` 文件是 Frida 动态插桩工具中用于生成 ARM Thumb 指令集的代码的测试文件。它主要功能是测试 `GumThumbWriter` API 的各种函数，以确保能够正确地生成各种 Thumb 指令。

下面我们分点来详细列举它的功能，并根据你的要求进行说明：

**1. 功能列举:**

* **测试 Thumb 指令生成:** 该文件包含了大量的测试用例（`TESTCASE`），每个测试用例都针对 `GumThumbWriter` API 的一个特定函数，用于生成特定的 Thumb 指令。
* **覆盖多种 Thumb 指令:**  测试用例覆盖了 Thumb 指令集的多种指令，包括：
    * **比较指令:** `cmp_reg_imm` (比较寄存器和立即数)
    * **条件跳转指令:** `beq_label` (相等跳转), `bne_label` (不等跳转), `b_cond_label_wide` (带条件的宽跳转), `cbz_reg_label` (为零跳转), `cbnz_reg_label` (非零跳转)
    * **无条件跳转指令:** `b_label_wide` (宽跳转)
    * **寄存器跳转指令:** `bx_reg` (跳转到寄存器地址), `blx_reg` (带链接跳转到寄存器地址)
    * **函数调用指令:** `bl_label` (带链接的跳转)
    * **栈操作指令:** `push_regs` (压栈), `pop_regs` (出栈), `vpush_range` (压栈 VFP 寄存器范围), `vpop_range` (出栈 VFP 寄存器范围)
    * **加载指令:** `ldr_u32` (加载 32 位立即数), `ldr_reg_reg_offset` (加载寄存器偏移地址的值), `ldr_reg_reg` (加载寄存器地址的值), `ldrb_reg_reg` (加载字节), `ldrh_reg_reg` (加载半字), `vldr_reg_reg_offset` (加载 VFP 寄存器)
    * **存储指令:** `str_reg_reg_offset` (存储寄存器偏移地址的值), `str_reg_reg` (存储寄存器地址的值)
    * **数据移动指令:** `mov_reg_reg` (寄存器之间移动数据), `mov_reg_u8` (移动 8 位立即数到寄存器)
    * **算术运算指令:** `add_reg_imm` (加立即数), `add_reg_reg_reg` (寄存器相加), `add_reg_reg` (寄存器相加), `add_reg_reg_imm` (寄存器加立即数), `sub_reg_imm` (减立即数), `sub_reg_reg_reg` (寄存器相减), `sub_reg_reg_imm` (寄存器减立即数)
    * **逻辑运算指令:** `and_reg_reg_imm` (与立即数)
    * **移位指令:** `lsls_reg_reg_imm` (逻辑左移), `lsrs_reg_reg_imm` (逻辑右移)
    * **系统寄存器访问指令:** `mrs_reg_reg` (读取系统寄存器), `msr_reg_reg` (写入系统寄存器)
    * **空操作指令:** `nop` (无操作)
* **断言验证:** 每个测试用例都使用 `assert_output_n_equals` 或 `assert_output_equals` 宏来断言生成的二进制代码是否与预期的结果一致。
* **标签管理:** 使用 `gum_thumb_writer_put_label` 函数定义代码标签，并用于跳转指令，测试跳转指令的正确性。
* **错误处理测试:** 包含了一些测试用例，例如 `cbz_reg_label_too_short`、`cbz_reg_label_too_long` 等，用于测试 API 在处理边界情况或错误输入时的行为。
* **架构特定测试:** 使用 `#ifdef HAVE_ARM` 包含了一些只在 ARM 架构下运行的测试用例，例如 `ldr_in_large_block`，这可能涉及到更底层的内存布局和寻址方式。

**2. 与逆向方法的关系及举例:**

该文件生成 Thumb 指令，这与逆向工程是互补的关系。逆向工程的目标是从二进制代码中还原出高级语言或汇编代码，而这个文件则是从抽象的指令操作生成具体的二进制代码。

**举例说明:**

* **逆向分析跳转指令:** 逆向工程师在分析一段 Thumb 代码时，可能会遇到 `beq` 或 `bne` 等条件跳转指令。他们需要理解这些指令的条件和目标地址。这个文件中的 `beq_label` 和 `bne_label` 测试用例展示了如何生成这些指令，以及它们在二进制层面的表示 (例如 `0xd0fb` 代表 `beq again`)。逆向工程师通过反汇编器看到 `0xd0fb` 后，会知道这是一个 `beq` 指令，并计算出跳转的目标地址 `again`。
* **逆向分析数据加载:** 逆向工程师在分析时会遇到 `ldr` 指令，需要理解它从哪里加载数据到哪个寄存器。例如，`ldr r0, [r1, #4]` 指令表示从 `r1` 寄存器指向的地址加上 4 的偏移处加载数据到 `r0` 寄存器。这个文件中的 `ldr_reg_reg_offset` 测试用例生成了类似的指令，例如 `assert_output_n_equals (0, 0x6800);` 对应 `ldr r0, [r0, #0]`。逆向工程师看到 `0x6800` 就能识别出这是一个加载指令。

**3. 涉及的二进制底层，Linux, Android 内核及框架的知识及举例:**

* **二进制底层知识:**
    * **Thumb 指令集编码:**  文件中的断言直接比较生成的二进制码，例如 `assert_output_n_equals (0, 0x2f07);`，这需要对 Thumb 指令的编码格式有深入的了解。每条 Thumb 指令都有其特定的二进制编码格式。
    * **寄存器表示:** 代码中使用 `ARM_REG_R0`、`ARM_REG_LR` 等常量来表示 ARM 寄存器，这些常量在底层对应着特定的二进制编码。
    * **内存地址和偏移:**  像 `ldr_reg_reg_offset` 和 `str_reg_reg_offset` 这样的测试用例涉及到内存地址的计算和偏移量的编码。

* **Linux/Android 内核及框架知识 (间接相关):**
    * **代码注入:** Frida 是一个动态插桩工具，它需要将生成的代码注入到目标进程中。这个文件生成的 Thumb 指令最终会被注入到 Android 或 Linux 进程的内存空间中执行。
    * **进程内存布局:**  `ldr_in_large_block` 这个测试用例，特别是涉及到 `gum_query_page_size()` 和 `gum_alloc_n_pages()`，暗示了与进程内存管理和页面大小相关的知识。在 Linux 和 Android 中，内存是以页为单位进行管理的。
    * **函数调用约定:** `bl_label` 和 `blx_reg` 等指令涉及到函数调用，需要理解 ARM 的函数调用约定，例如 `LR` 寄存器（Link Register）用于存储返回地址。
    * **系统调用:** 虽然这个文件本身没有直接涉及系统调用，但 Frida 最终可能会使用生成的指令来拦截或修改系统调用。

**4. 逻辑推理及假设输入与输出:**

大多数测试用例都是直接的指令生成和断言，逻辑推理相对简单。但有些测试用例涉及到边界条件或需要一定的计算。

**举例说明:**

* **`cbz_reg_label` 系列测试用例:** 这些测试用例用于验证 `cbz` (Compare and Branch if Zero) 指令的跳转范围。
    * **假设输入:**  `gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);`，其中 `beach_lbl` 是一个标签，位于 `cbz` 指令之后的不同距离。
    * **逻辑推理:** `cbz` 指令的偏移量是有限制的，如果标签距离太远或太近，指令可能无法正确编码。
    * **输出:**  `cbz_reg_label_too_short` 测试用例中，如果标签太近，`gum_thumb_writer_flush` 将返回 `false`，表示生成失败。`cbz_reg_label_minimum` 和 `cbz_reg_label_maximum` 测试了偏移量的最小值和最大值。

* **`ldr_u32` 测试用例:**
    * **假设输入:**  `gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R0, 0x1337);`
    * **逻辑推理:** `ldr_u32` 指令会将 32 位立即数加载到寄存器中，但 Thumb 指令通常是 16 位的。因此，这个 API 可能会生成多条指令或者将立即数存储在代码段附近，然后加载。
    * **输出:** 断言验证了生成的指令 (`0x4801`) 以及在代码段中存储的立即数 (`0x1337`)。

**5. 涉及用户或编程常见的使用错误及举例:**

* **立即数超出范围:**  某些 Thumb 指令对立即数的范围有限制。例如，`movs` 指令的 8 位立即数只能表示 0-255。如果用户尝试生成超出范围的立即数，`GumThumbWriter` API 可能会返回错误或生成不正确的代码。
    * **例子:**  虽然这个文件中没有直接展示用户错误，但可以想象，如果用户错误地使用 `gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R0, 256);`，则这个 API 应该处理这种情况（虽然在当前的测试用例中，它被限制在 0-255）。

* **跳转目标过远:**  条件跳转指令的跳转范围是有限的。如果用户尝试跳转到距离当前指令太远的标签，可能需要使用宽跳转指令。如果 `GumThumbWriter` 没有正确处理这种情况，可能会导致生成错误的跳转指令。
    * **例子:** `cbz_reg_label_too_long` 测试用例模拟了这种情况，当标签距离过远时，`gum_thumb_writer_flush` 返回 `false`。

* **寄存器选择错误:**  某些指令只能操作特定的寄存器。例如，栈操作指令通常使用 SP (Stack Pointer) 寄存器。如果用户尝试使用错误的寄存器，API 可能会报错或生成无效指令。

* **忘记 flush:** 用户可能在使用 `GumThumbWriter` 生成指令后，忘记调用 `gum_thumb_writer_flush` 将指令刷新到输出缓冲区，导致生成的代码为空或不完整。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发者，你可能会因为以下原因查看或调试这个文件：

1. **开发 Frida 模块/Gadget:**  当你使用 Frida 框架进行动态插桩时，你可能需要生成自定义的 Thumb 代码来修改目标程序的行为。你可能会查阅 `GumThumbWriter` 的文档或示例，并最终找到这个测试文件，以了解如何使用 API 生成特定的指令。

2. **调试 Frida 代码生成器:** 如果你在使用 Frida 时遇到了代码生成的问题，例如生成的代码不符合预期或导致程序崩溃，你可能会深入 Frida 的源代码进行调试，`thumbwriter.c` 就是一个很好的入口点，可以帮助你理解 `GumThumbWriter` 的工作原理，并验证是否是代码生成器本身的问题。

3. **为 Frida 贡献代码:** 如果你希望为 Frida 项目做出贡献，例如添加对新的 Thumb 指令的支持或修复现有的 bug，你需要理解现有的代码生成机制，`thumbwriter.c` 是理解和修改这部分代码的关键。

4. **学习 ARM Thumb 指令集:**  即使不直接参与 Frida 的开发，这个文件也是一个学习 ARM Thumb 指令集及其二进制编码的很好的资源。每个测试用例都展示了如何生成特定的指令，并验证了其二进制表示。

**调试线索:**

* **编译错误/链接错误:** 如果你在编译或链接使用了 `GumThumbWriter` 的代码时遇到错误，可能是头文件包含不正确或者链接库缺失。
* **运行时错误/崩溃:** 如果你注入的 Frida 脚本导致目标程序崩溃，并且怀疑是生成的 Thumb 代码有问题，你可以使用 Frida 的日志功能或调试工具（如 GDB）来查看实际生成的二进制代码，并与 `thumbwriter.c` 中的预期输出进行对比，从而定位问题。
* **插桩行为不符合预期:**  如果你的 Frida 脚本运行正常，但插桩效果不符合预期，可能是你生成的 Thumb 代码逻辑错误。这时，你可以仔细检查你使用的 `GumThumbWriter` API 函数以及它们生成的指令，`thumbwriter.c` 可以作为参考，确保你生成了正确的指令序列。

总而言之，`thumbwriter.c` 是 Frida 中用于测试 Thumb 指令生成功能的核心文件，它不仅验证了 `GumThumbWriter` API 的正确性，也为开发者提供了学习和理解 ARM Thumb 指令集的宝贵资源。当你需要深入了解 Frida 的代码生成机制或调试相关的错误时，这个文件是不可或缺的。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/thumbwriter.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "thumbwriter-fixture.c"

TESTLIST_BEGIN (thumbwriter)
  TESTENTRY (cmp_reg_imm)
  TESTENTRY (beq_label)
  TESTENTRY (bne_label)
  TESTENTRY (b_cond_label_wide)
  TESTENTRY (cbz_reg_label)
  TESTENTRY (cbz_reg_label_too_short)
  TESTENTRY (cbz_reg_label_minimum)
  TESTENTRY (cbz_reg_label_maximum)
  TESTENTRY (cbz_reg_label_too_long)
  TESTENTRY (cbnz_reg_label)

  TESTENTRY (b_label_wide)
  TESTENTRY (bx_reg)
  TESTENTRY (bl_label)
  TESTENTRY (blx_reg)

  TESTENTRY (push_regs)
  TESTENTRY (pop_regs)
  TESTENTRY (vpush_range)
  TESTENTRY (vpop_range)
  TESTENTRY (ldr_u32)
#ifdef HAVE_ARM
  TESTENTRY (ldr_in_large_block)
#endif
  TESTENTRY (ldr_reg_reg_offset)
  TESTENTRY (ldr_reg_reg)
  TESTENTRY (ldrb_reg_reg)
  TESTENTRY (ldrh_reg_reg)
  TESTENTRY (vldr_reg_reg_offset)
  TESTENTRY (str_reg_reg_offset)
  TESTENTRY (str_reg_reg)
  TESTENTRY (mov_reg_reg)
  TESTENTRY (mov_reg_u8)
  TESTENTRY (add_reg_imm)
  TESTENTRY (add_reg_reg_reg)
  TESTENTRY (add_reg_reg)
  TESTENTRY (add_reg_reg_imm)
  TESTENTRY (sub_reg_imm)
  TESTENTRY (sub_reg_reg_reg)
  TESTENTRY (sub_reg_reg_imm)
  TESTENTRY (and_reg_reg_imm)
  TESTENTRY (lsls_reg_reg_imm)
  TESTENTRY (lsrs_reg_reg_imm)

  TESTENTRY (mrs_reg_reg)
  TESTENTRY (msr_reg_reg)

  TESTENTRY (nop)
TESTLIST_END ()

#ifdef HAVE_ARM
static void gum_emit_ldr_in_large_block (gpointer mem, gpointer user_data);
#endif

TESTCASE (cmp_reg_imm)
{
  gum_thumb_writer_put_cmp_reg_imm (&fixture->tw, ARM_REG_R7, 7);
  assert_output_n_equals (0, 0x2f07); /* cmp r7, 7 */
}

TESTCASE (beq_label)
{
  const gchar * again_lbl = "again";

  gum_thumb_writer_put_label (&fixture->tw, again_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_beq_label (&fixture->tw, again_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  /* again: */
  assert_output_n_equals (0, 0xbf00); /* nop */
  assert_output_n_equals (1, 0xbf00); /* nop */
  assert_output_n_equals (2, 0xbf00); /* nop */
  assert_output_n_equals (3, 0xd0fb); /* beq again */
}

TESTCASE (bne_label)
{
  const gchar * again_lbl = "again";

  gum_thumb_writer_put_label (&fixture->tw, again_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_bne_label (&fixture->tw, again_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  /* again: */
  assert_output_n_equals (0, 0xbf00); /* nop */
  assert_output_n_equals (1, 0xbf00); /* nop */
  assert_output_n_equals (2, 0xbf00); /* nop */
  assert_output_n_equals (3, 0xd1fb); /* bne again */
}

TESTCASE (b_cond_label_wide)
{
  const gchar * again_lbl = "again";

  gum_thumb_writer_put_label (&fixture->tw, again_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_b_cond_label_wide (&fixture->tw, ARM_CC_NE, again_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  /* again: */
  assert_output_n_equals (0, 0xbf00); /* nop */
  assert_output_n_equals (1, 0xbf00); /* nop */
  assert_output_n_equals (2, 0xbf00); /* nop */
  assert_output_n_equals (3, 0xf47f); /* bne.w again */
  assert_output_n_equals (4, 0xaffb);
}

TESTCASE (cbz_reg_label)
{
  const gchar * beach_lbl = "beach";

  gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);
  gum_thumb_writer_put_blx_reg (&fixture->tw, ARM_REG_R1);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);

  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_PC);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xb11f); /* cbz r7, beach */
  assert_output_n_equals (1, 0x4788); /* blx r1 */
  assert_output_n_equals (2, 0xbf00); /* nop */
  assert_output_n_equals (3, 0xbf00); /* nop */
  assert_output_n_equals (4, 0xbf00); /* nop */
  /* beach: */
  assert_output_n_equals (5, 0xbd00); /* pop {pc} */
}

TESTCASE (cbz_reg_label_too_short)
{
  const gchar * beach_lbl = "beach";

  gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);
  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);

  g_assert_false (gum_thumb_writer_flush (&fixture->tw));
}

TESTCASE (cbz_reg_label_minimum)
{
  const gchar * beach_lbl = "beach";

  gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);

  g_assert_true (gum_thumb_writer_flush (&fixture->tw));
  assert_output_n_equals (0, 0xb107); /* cbz r7, beach */
}

TESTCASE (cbz_reg_label_maximum)
{
  const gchar * beach_lbl = "beach";
  guint i;

  gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);
  for (i = 0; i != 64; i++)
    gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);

  g_assert_true (gum_thumb_writer_flush (&fixture->tw));
  assert_output_n_equals (0, 0xb3ff); /* cbz r7, beach */
}

TESTCASE (cbz_reg_label_too_long)
{
  const gchar * beach_lbl = "beach";
  guint i;

  gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);
  for (i = 0; i != 64; i++)
    gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);

  g_assert_false (gum_thumb_writer_flush (&fixture->tw));
}

TESTCASE (cbnz_reg_label)
{
  const gchar * beach_lbl = "beach";

  gum_thumb_writer_put_cbnz_reg_label (&fixture->tw, ARM_REG_R0, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xb910); /* cbnz r0, beach */
  assert_output_n_equals (1, 0xbf00); /* nop */
  assert_output_n_equals (2, 0xbf00); /* nop */
  assert_output_n_equals (3, 0xbf00); /* nop */
  /* beach: */
}

TESTCASE (b_label_wide)
{
  const gchar * next_lbl = "next";

  gum_thumb_writer_put_b_label_wide (&fixture->tw, next_lbl);
  gum_thumb_writer_put_label (&fixture->tw, next_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xf000); /* b.w next */
  assert_output_n_equals (1, 0xb800);
  /* next: */
  assert_output_n_equals (2, 0xbf00); /* nop */
}

TESTCASE (bx_reg)
{
  gum_thumb_writer_put_bx_reg (&fixture->tw, ARM_REG_R0);
  assert_output_n_equals (0, 0x4700);

  gum_thumb_writer_put_bx_reg (&fixture->tw, ARM_REG_R7);
  assert_output_n_equals (1, 0x4738);
}

TESTCASE (blx_reg)
{
  gum_thumb_writer_put_blx_reg (&fixture->tw, ARM_REG_R0);
  assert_output_n_equals (0, 0x4780);

  gum_thumb_writer_put_blx_reg (&fixture->tw, ARM_REG_R3);
  assert_output_n_equals (1, 0x4798);
}

TESTCASE (bl_label)
{
  const gchar * next_lbl = "next";

  gum_thumb_writer_put_push_regs (&fixture->tw, 1, ARM_REG_LR);
  gum_thumb_writer_put_bl_label (&fixture->tw, next_lbl);
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_PC);
  gum_thumb_writer_put_label (&fixture->tw, next_lbl);
  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R2, 0);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xb500); /* push {lr} */
  assert_output_n_equals (1, 0xf000); /* bl next */
  assert_output_n_equals (2, 0xf801);
  assert_output_n_equals (3, 0xbd00); /* pop {pc} */
  /* next: */
  assert_output_n_equals (4, 0xbfe8); /* it al */
  assert_output_n_equals (5, 0x2200); /* movs r2, 0 */
}

TESTCASE (push_regs)
{
  gum_thumb_writer_put_push_regs (&fixture->tw, 1, ARM_REG_R0);
  assert_output_n_equals (0, 0xb401);

  gum_thumb_writer_put_push_regs (&fixture->tw, 1, ARM_REG_R7);
  assert_output_n_equals (1, 0xb480);

  gum_thumb_writer_put_push_regs (&fixture->tw, 9, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);
  assert_output_n_equals (2, 0xb5ff);

  gum_thumb_writer_put_push_regs (&fixture->tw, 2, ARM_REG_R8, ARM_REG_R9);
  assert_output_n_equals (3, 0xe92d);
  assert_output_n_equals (4, 0x0300);
}

TESTCASE (pop_regs)
{
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_R0);
  assert_output_n_equals (0, 0xbc01);

  gum_thumb_writer_put_pop_regs (&fixture->tw, 9, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);
  assert_output_n_equals (1, 0xbdff);

  gum_thumb_writer_put_pop_regs (&fixture->tw, 2, ARM_REG_R8, ARM_REG_R9);
  assert_output_n_equals (2, 0xe8bd);
  assert_output_n_equals (3, 0x0300);
}

TESTCASE (vpush_range)
{
  gum_thumb_writer_put_vpush_range (&fixture->tw, ARM_REG_Q8, ARM_REG_Q15);
  assert_output_n_equals (0, 0xed6d);
  assert_output_n_equals (1, 0x0b20);

  gum_thumb_writer_put_vpush_range (&fixture->tw, ARM_REG_D0, ARM_REG_D15);
  assert_output_n_equals (2, 0xed2d);
  assert_output_n_equals (3, 0x0b20);

  gum_thumb_writer_put_vpush_range (&fixture->tw, ARM_REG_D16, ARM_REG_D31);
  assert_output_n_equals (4, 0xed6d);
  assert_output_n_equals (5, 0x0b20);

  gum_thumb_writer_put_vpush_range (&fixture->tw, ARM_REG_S0, ARM_REG_S31);
  assert_output_n_equals (6, 0xed2d);
  assert_output_n_equals (7, 0x0a20);
}

TESTCASE (vpop_range)
{
  gum_thumb_writer_put_vpop_range (&fixture->tw, ARM_REG_Q8, ARM_REG_Q15);
  assert_output_n_equals (0, 0xecfd);
  assert_output_n_equals (1, 0x0b20);

  gum_thumb_writer_put_vpop_range (&fixture->tw, ARM_REG_D0, ARM_REG_D15);
  assert_output_n_equals (2, 0xecbd);
  assert_output_n_equals (3, 0x0b20);

  gum_thumb_writer_put_vpop_range (&fixture->tw, ARM_REG_D16, ARM_REG_D31);
  assert_output_n_equals (4, 0xecfd);
  assert_output_n_equals (5, 0x0b20);

  gum_thumb_writer_put_vpop_range (&fixture->tw, ARM_REG_S0, ARM_REG_S31);
  assert_output_n_equals (6, 0xecbd);
  assert_output_n_equals (7, 0x0a20);
}

TESTCASE (ldr_u32)
{
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R0, 0x1337);
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R1, 0x1227);
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R2, 0x1337);
  gum_thumb_writer_flush (&fixture->tw);
  assert_output_n_equals (0, 0x4801);
  assert_output_n_equals (1, 0x4902);
  assert_output_n_equals (2, 0x4a00);
  g_assert_cmphex (((guint32 *) fixture->output)[2], ==, 0x1337);
  g_assert_cmphex (((guint32 *) fixture->output)[3], ==, 0x1227);
}

#ifdef HAVE_ARM

TESTCASE (ldr_in_large_block)
{
  const gsize code_size_in_pages = 1;
  gsize code_size;
  gpointer code;
  gint (* impl) (void);

  code_size = code_size_in_pages * gum_query_page_size ();
  code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  gum_memory_patch_code (code, code_size, gum_emit_ldr_in_large_block, code);

  impl = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (code) | 1);
  g_assert_cmpint (impl (), ==, 0x1337);

  gum_free_pages (code);
}

static void
gum_emit_ldr_in_large_block (gpointer mem,
                             gpointer user_data)
{
  gpointer code = user_data;
  GumThumbWriter tw;
  guint i;

  gum_thumb_writer_init (&tw, mem);
  tw.pc = GUM_ADDRESS (code);

  gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 0x1337);
  for (i = 0; i != 511; i++)
    gum_thumb_writer_put_nop (&tw);
  gum_thumb_writer_put_bx_reg (&tw, ARM_REG_LR);

  gum_thumb_writer_clear (&tw);
}

#endif

TESTCASE (ldr_reg_reg_offset)
{
  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 0);
  assert_output_n_equals (0, 0x6800);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_R0, 0);
  assert_output_n_equals (1, 0x6803);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R3, 0);
  assert_output_n_equals (2, 0x6818);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 12);
  assert_output_n_equals (3, 0x68c0);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_R12, 16);
  assert_output_n_equals (4, 0xf8dc);
  assert_output_n_equals (5, 0x3010);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 0);
  assert_output_n_equals (6, 0x9800);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R5,
      ARM_REG_SP, 0);
  assert_output_n_equals (7, 0x9d00);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 12);
  assert_output_n_equals (8, 0x9803);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R12,
      ARM_REG_SP, 12);
  assert_output_n_equals (9, 0xf8dd);
  assert_output_n_equals (10, 0xc00c);
}

TESTCASE (ldr_reg_reg)
{
  gum_thumb_writer_put_ldr_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R0);
  assert_output_n_equals (0, 0x6800);

  gum_thumb_writer_put_ldr_reg_reg (&fixture->tw, ARM_REG_R12, ARM_REG_R12);
  assert_output_n_equals (1, 0xf8dc);
  assert_output_n_equals (2, 0xc000);
}

TESTCASE (ldrb_reg_reg)
{
  gum_thumb_writer_put_ldrb_reg_reg (&fixture->tw, ARM_REG_R1, ARM_REG_R3);
  assert_output_n_equals (0, 0x7819);
}

TESTCASE (ldrh_reg_reg)
{
  gum_thumb_writer_put_ldrh_reg_reg (&fixture->tw, ARM_REG_R1, ARM_REG_R3);
  assert_output_n_equals (0, 0x8819);
}

TESTCASE (vldr_reg_reg_offset)
{
  gum_thumb_writer_put_vldr_reg_reg_offset (&fixture->tw, ARM_REG_S1,
      ARM_REG_R2, 4);
  assert_output_n_equals (0, 0xedd2);
  assert_output_n_equals (1, 0x0a01);

  gum_thumb_writer_put_vldr_reg_reg_offset (&fixture->tw, ARM_REG_D2,
      ARM_REG_R3, 8);
  assert_output_n_equals (2, 0xed93);
  assert_output_n_equals (3, 0x2b02);

  gum_thumb_writer_put_vldr_reg_reg_offset (&fixture->tw, ARM_REG_D3,
      ARM_REG_R4, -4);
  assert_output_n_equals (4, 0xed14);
  assert_output_n_equals (5, 0x3b01);

  gum_thumb_writer_put_vldr_reg_reg_offset (&fixture->tw, ARM_REG_D17,
      ARM_REG_R5, -8);
  assert_output_n_equals (6, 0xed55);
  assert_output_n_equals (7, 0x1b02);
}

TESTCASE (str_reg_reg_offset)
{
  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 0);
  assert_output_n_equals (0, 0x6000);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R7,
      ARM_REG_R0, 0);
  assert_output_n_equals (1, 0x6007);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R7, 0);
  assert_output_n_equals (2, 0x6038);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 24);
  assert_output_n_equals (3, 0x6180);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R4,
      ARM_REG_R11, 28);
  assert_output_n_equals (4, 0xf8cb);
  assert_output_n_equals (5, 0x401c);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 0);
  assert_output_n_equals (6, 0x9000);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_SP, 0);
  assert_output_n_equals (7, 0x9300);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 24);
  assert_output_n_equals (8, 0x9006);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R12,
      ARM_REG_SP, 24);
  assert_output_n_equals (9, 0xf8cd);
  assert_output_n_equals (10, 0xc018);
}

TESTCASE (str_reg_reg)
{
  gum_thumb_writer_put_str_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R0);
  assert_output_equals (0x6000);
}

TESTCASE (mov_reg_reg)
{
  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1);
  /* it al */
  assert_output_n_equals (0, 0xbfe8);
  /* adds r0, r1, #0 */
  assert_output_n_equals (1, 0x1c08);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R7);
  assert_output_n_equals (2, 0xbfe8);
  assert_output_n_equals (3, 0x1c38);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R7, ARM_REG_R0);
  assert_output_n_equals (4, 0xbfe8);
  assert_output_n_equals (5, 0x1c07);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_SP);
  assert_output_n_equals (6, 0x4668);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R1, ARM_REG_SP);
  assert_output_n_equals (7, 0x4669);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_LR);
  assert_output_n_equals (8, 0x4670);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_LR, ARM_REG_R0);
  assert_output_n_equals (9, 0x4686);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_LR, ARM_REG_SP);
  assert_output_n_equals (10, 0x46ee);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_PC, ARM_REG_LR);
  assert_output_n_equals (11, 0x46f7);
}

TESTCASE (mov_reg_u8)
{
  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R0, 7);
  /* it al */
  assert_output_n_equals (0, 0xbfe8);
  /* movs r0, #7 */
  assert_output_n_equals (1, 0x2007);

  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R0, 255);
  assert_output_n_equals (2, 0xbfe8);
  assert_output_n_equals (3, 0x20ff);

  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R2, 5);
  assert_output_n_equals (4, 0xbfe8);
  assert_output_n_equals (5, 0x2205);
}

TESTCASE (add_reg_imm)
{
  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R0, 255);
  assert_output_n_equals (0, 0xbfe8);
  assert_output_n_equals (1, 0x30ff);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R3, 255);
  assert_output_n_equals (2, 0xbfe8);
  assert_output_n_equals (3, 0x33ff);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R0, 42);
  assert_output_n_equals (4, 0xbfe8);
  assert_output_n_equals (5, 0x302a);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R0, -42);
  assert_output_n_equals (6, 0xbfe8);
  assert_output_n_equals (7, 0x382a);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_SP, 12);
  assert_output_n_equals (8, 0xb003);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_SP, -12);
  assert_output_n_equals (9, 0xb083);

  g_assert_false (gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R8,
      4));
}

TESTCASE (add_reg_reg_reg)
{
  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2);
  /* it al */
  assert_output_n_equals (0, 0xbfe8);
  /* adds r0, r1, r2 */
  assert_output_n_equals (1, 0x1888);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R7, ARM_REG_R1,
      ARM_REG_R2);
  assert_output_n_equals (2, 0xbfe8);
  assert_output_n_equals (3, 0x188f);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R7,
      ARM_REG_R2);
  assert_output_n_equals (4, 0xbfe8);
  assert_output_n_equals (5, 0x18b8);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R7);
  assert_output_n_equals (6, 0xbfe8);
  assert_output_n_equals (7, 0x19c8);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R9, ARM_REG_R9,
      ARM_REG_R0);
  assert_output_n_equals (8, 0x4481);
}

TESTCASE (add_reg_reg)
{
  gum_thumb_writer_put_add_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1);
  assert_output_n_equals (0, 0x4408);

  gum_thumb_writer_put_add_reg_reg (&fixture->tw, ARM_REG_R12, ARM_REG_R1);
  assert_output_n_equals (1, 0x448c);

  gum_thumb_writer_put_add_reg_reg (&fixture->tw, ARM_REG_R3, ARM_REG_R12);
  assert_output_n_equals (2, 0x4463);
}

TESTCASE (add_reg_reg_imm)
{
  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_SP,
      36);
  assert_output_n_equals (0, 0xa909);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R7, ARM_REG_SP,
      36);
  assert_output_n_equals (1, 0xaf09);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_PC,
      36);
  assert_output_n_equals (2, 0xa109);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_SP,
      12);
  assert_output_n_equals (3, 0xa903);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      5);
  assert_output_n_equals (4, 0xbfe8);
  assert_output_n_equals (5, 0x1d79);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R5, ARM_REG_R7,
      5);
  assert_output_n_equals (6, 0xbfe8);
  assert_output_n_equals (7, 0x1d7d);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R3,
      5);
  assert_output_n_equals (8, 0xbfe8);
  assert_output_n_equals (9, 0x1d59);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      3);
  assert_output_n_equals (10, 0xbfe8);
  assert_output_n_equals (11, 0x1cf9);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      -3);
  assert_output_n_equals (12, 0xbfe8);
  assert_output_n_equals (13, 0x1ef9);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R0, ARM_REG_R0,
      255);
  assert_output_n_equals (14, 0xbfe8);
  assert_output_n_equals (15, 0x30ff);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_SP, ARM_REG_SP,
      4);
  assert_output_n_equals (16, 0xb001);

  g_assert_false (gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw,
      ARM_REG_R0, ARM_REG_R8, 4));

  g_assert_false (gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw,
      ARM_REG_R8, ARM_REG_R0, 4));
}

TESTCASE (sub_reg_imm)
{
  gum_thumb_writer_put_sub_reg_imm (&fixture->tw, ARM_REG_R0, 42);
  assert_output_n_equals (0, 0xbfe8);
  assert_output_n_equals (1, 0x382a);
}

TESTCASE (sub_reg_reg_reg)
{
  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2);
  /* it al */
  assert_output_n_equals (0, 0xbfe8);
  /* subs r0, r1, r2 */
  assert_output_n_equals (1, 0x1a88);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R7, ARM_REG_R1,
      ARM_REG_R2);
  assert_output_n_equals (2, 0xbfe8);
  assert_output_n_equals (3, 0x1a8f);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R7,
      ARM_REG_R2);
  assert_output_n_equals (4, 0xbfe8);
  assert_output_n_equals (5, 0x1ab8);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R7);
  assert_output_n_equals (6, 0xbfe8);
  assert_output_n_equals (7, 0x1bc8);
}

TESTCASE (sub_reg_reg_imm)
{
  gum_thumb_writer_put_sub_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      5);
  assert_output_n_equals (0, 0xbfe8);
  assert_output_n_equals (1, 0x1f79);
}

TESTCASE (and_reg_reg_imm)
{
  g_assert_false (gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw,
      ARM_REG_R0, ARM_REG_R0, -1));

  g_assert_false (gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw,
      ARM_REG_R0, ARM_REG_R0, 256));

  gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw, ARM_REG_R0, ARM_REG_R0,
      0);
  assert_output_n_equals (0, 0xf000);
  assert_output_n_equals (1, 0x0000);

  gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw, ARM_REG_R0, ARM_REG_R0,
      255);
  assert_output_n_equals (2, 0xf000);
  assert_output_n_equals (3, 0x00ff);

  gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw, ARM_REG_R0, ARM_REG_R7,
      0);
  assert_output_n_equals (4, 0xf007);
  assert_output_n_equals (5, 0x0000);

  gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw, ARM_REG_R7, ARM_REG_R0,
      0);
  assert_output_n_equals (6, 0xf000);
  assert_output_n_equals (7, 0x0700);

  gum_thumb_writer_put_and_reg_reg_imm (&fixture->tw, ARM_REG_R5, ARM_REG_R3,
      53);
  assert_output_n_equals (8, 0xf003);
  assert_output_n_equals (9, 0x0535);
}

TESTCASE (lsls_reg_reg_imm)
{
  gum_thumb_writer_put_lsls_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R3,
      7);
  assert_output_n_equals (0, 0x01d9);
}

TESTCASE (lsrs_reg_reg_imm)
{
  gum_thumb_writer_put_lsrs_reg_reg_imm (&fixture->tw, ARM_REG_R3, ARM_REG_R7,
      9);
  assert_output_n_equals (0, 0x0a7b);
}

TESTCASE (mrs_reg_reg)
{
  gum_thumb_writer_put_mrs_reg_reg (&fixture->tw, ARM_REG_R1,
      ARM_SYSREG_APSR_NZCVQ);
  assert_output_n_equals (0, 0xf3ef);
  assert_output_n_equals (1, 0x8100);

  gum_thumb_writer_put_mrs_reg_reg (&fixture->tw, ARM_REG_R7,
      ARM_SYSREG_APSR_NZCVQ);
  assert_output_n_equals (2, 0xf3ef);
  assert_output_n_equals (3, 0x8700);
}

TESTCASE (msr_reg_reg)
{
  gum_thumb_writer_put_msr_reg_reg (&fixture->tw, ARM_SYSREG_APSR_NZCVQ,
      ARM_REG_R1);
  assert_output_n_equals (0, 0xf381);
  assert_output_n_equals (1, 0x8800);

  gum_thumb_writer_put_msr_reg_reg (&fixture->tw, ARM_SYSREG_APSR_NZCVQ,
      ARM_REG_R7);
  assert_output_n_equals (2, 0xf387);
  assert_output_n_equals (3, 0x8800);
}

TESTCASE (nop)
{
  gum_thumb_writer_put_nop (&fixture->tw);
  assert_output_equals (0xbf00);
}
```