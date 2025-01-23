Response:
Let's break down the thought process to analyze this C code for Frida's ARM64 relocator.

1. **Understand the Goal:** The file `arm64relocator.c` within Frida's `frida-gum` project and specifically the `tests/core/arch-arm64` directory strongly suggests this code is about *relocating* ARM64 instructions. Relocation is essential when moving code in memory, which is a core aspect of dynamic instrumentation.

2. **Identify Key Structures and Functions:**  The code is structured as a series of test cases. The `TESTLIST_BEGIN`, `TESTENTRY`, `TESTCASE`, and `TESTLIST_END` macros indicate a testing framework (likely a custom one or based on a lightweight library). The presence of `SETUP_RELOCATOR_WITH` suggests a setup function for each test. The core functionality will likely reside in functions prefixed with `gum_arm64_relocator_`.

3. **Analyze Individual Test Cases:** Each `TESTCASE` focuses on a specific scenario. Let's look at a few in detail:

    * **`one_to_one`:** This seems like a basic test. It reads and writes instructions and compares the output. The names `read_one` and `write_one` are strong indicators of the relocator's fundamental operations. The `memcmp` confirms a direct copy, indicating no relocation is needed for these instructions.

    * **`ldr_x_should_be_rewritten`:** The "should be rewritten" part is a crucial clue. The input instruction `ldr x16, [pc, #8]` is a PC-relative load. The `expected_output_instructions` show the original `ldr`, followed by `ldr x16, [x16]` and two placeholder words. This pattern strongly suggests the relocator is transforming PC-relative loads into absolute loads by first loading the address into a register.

    * **`adr_should_be_rewritten` and `adrp_should_be_rewritten`:** Similar to `ldr`, these test cases deal with address generation instructions (`adr` and `adrp`). The expected output pattern is the same: load the calculated address into a register using a PC-relative `ldr`.

    * **`cbz_should_be_rewritten`, `tbnz_should_be_rewritten`, `b_cond_should_be_rewritten`:** These tests focus on conditional branch instructions. The expected output involves a short jump, a PC-relative load, and an indirect branch (`br`). This is a common technique to relocate conditional branches that have short offsets.

    * **`b_should_be_rewritten` and `bl_should_be_rewritten`:** These cover unconditional branches (`b`) and branch-with-link (`bl`). The rewriting pattern involves loading the target address into a register and then using an indirect branch (`br` or `blr`).

    * **`cannot_relocate_with_early_br`:** This is a negative test, checking that the relocator refuses to operate on code that already contains an indirect branch. This is a safety measure to avoid unexpected behavior.

    * **`eob_and_eoi_on_br` and `eob_and_eoi_on_ret`:** These test the "end of block" (EOB) and "end of input" (EOI) flags. Branch and return instructions often mark the end of a basic block.

4. **Connect to Reverse Engineering Concepts:**

    * **Code Patching/Modification:** Relocation is essential for modifying existing code. Frida injects code, and that injected code needs to interact with the original code. If the original code has PC-relative addressing, simply copying it won't work in the new location. The relocator fixes these references.
    * **Dynamic Instrumentation:** Frida's core purpose is dynamic instrumentation. Relocation is a fundamental building block for inserting instrumentation code without breaking the original program's logic.
    * **Code Caves:** When injecting code, you might need to move existing code out of the way. Relocation ensures the moved code still functions correctly.

5. **Connect to Binary/OS/Kernel Concepts:**

    * **ARM64 Architecture:** The code directly manipulates ARM64 instructions. Understanding the encoding of instructions like `ldr`, `adr`, `b`, etc., is crucial.
    * **PC-Relative Addressing:** The relocator's main job is handling PC-relative addressing modes, a common feature of ARM64.
    * **Memory Management:** Relocation is necessary because the location of code in memory can change, especially in dynamic environments.
    * **Instruction Set Architecture (ISA):** The code is deeply tied to the specifics of the ARM64 ISA. The test cases target different instruction types and their encoding.

6. **Identify Logical Reasoning and Assumptions:**

    * **Assumption:** The input code is valid ARM64.
    * **Assumption:** The relocator has enough space in the output buffer to rewrite instructions (which the tests seem to guarantee).
    * **Logic:** The rewriting strategy generally involves replacing potentially problematic instructions (like PC-relative loads and branches) with sequences of instructions that achieve the same effect regardless of the code's position. This often involves loading the target address into a register.

7. **Consider User Errors:**

    * **Incorrect Input:** Providing non-ARM64 code would likely lead to errors during disassembly or relocation.
    * **Insufficient Output Buffer:**  If the output buffer is too small, the relocation process might fail or corrupt memory.
    * **Relocating Code with Dependencies:**  While this file focuses on instruction-level relocation, real-world scenarios might involve data dependencies. Users need to be aware that simply relocating code might not be enough if it relies on global data or other position-dependent resources.

8. **Trace User Operations (Debugging Context):**

    * A developer using Frida might write a script to intercept a function.
    * Frida injects a "trampoline" or detour.
    * To create the detour, Frida needs to copy some of the original function's instructions.
    * The `arm64relocator` is used to process those copied instructions, fixing up any PC-relative addressing so the copied code works correctly in its new location within the trampoline.
    * During debugging, if the intercepted code crashes or behaves unexpectedly, the developer might look at the relocated code. Examining the output of the `arm64relocator` (as these tests do) can reveal if the relocation logic is correct.

By following these steps, we can systematically analyze the provided C code and extract the requested information. The key is to understand the context (Frida, dynamic instrumentation), dissect the code's structure (test cases), and relate the observed behavior to fundamental concepts in computer architecture and reverse engineering.
这个C文件 `arm64relocator.c` 是 Frida 动态插桩工具中用于 ARM64 架构的代码重定位器（relocator）的测试代码。它的主要功能是通过一系列测试用例来验证 `gum_arm64_relocator` 组件的正确性。

**主要功能：**

1. **测试指令重定位:**  该文件包含多个测试用例，每个用例针对不同的 ARM64 指令，验证 `gum_arm64_relocator` 能否正确地重定位这些指令。重定位是指当一段代码被移动到内存中的新位置时，需要修改代码中某些指令的操作数，以确保指令仍然指向正确的地址。

2. **模拟代码移动场景:** 每个测试用例都定义了一段原始的 ARM64 指令序列（`input`）以及期望的重定位后的指令序列（`expected_output`）。测试代码会使用 `gum_arm64_relocator` 对 `input` 进行处理，然后将处理结果与 `expected_output` 进行比较，以验证重定位的正确性。

3. **覆盖多种指令类型:**  测试用例涵盖了 ARM64 架构中需要进行重定位的多种指令类型，例如：
    * **加载指令 (LDR):**  测试了 `ldr xN, [pc, #offset]` 这种 PC 相对寻址的加载指令的重定位。
    * **地址计算指令 (ADR, ADRP):** 测试了 `adr` 和 `adrp` 这两种地址计算指令的重定位。
    * **条件分支指令 (CBZ, TBNZ, B.cond):** 测试了条件分支指令的重定位，当分支目标超出短距离范围时，需要进行改写。
    * **无条件分支指令 (B, BL):** 测试了无条件分支指令的重定位，同样需要处理目标地址超出范围的情况。

4. **边界情况测试:**  文件中还包含了一些边界情况的测试，例如 `cannot_relocate_with_early_br` 测试了当输入代码中已经存在间接跳转指令时，重定位器是否会拒绝处理。`eob_and_eoi_on_br` 和 `eob_and_eoi_on_ret` 测试了当遇到分支或返回指令时，重定位器是否能正确标记代码块的结束。

**与逆向方法的关系及举例说明：**

代码重定位是动态逆向工程中的一个核心概念。当 Frida 或其他动态插桩工具需要在目标进程中插入自己的代码（例如 hook 函数的入口）时，就需要将目标进程中原有的指令进行备份和重定位，以确保在插桩后，原有的代码仍然能够正确执行。

**举例说明 `ldr_x_should_be_rewritten` 测试用例：**

* **原始指令:** `ldr x16, [pc, #8]`  (从当前 PC 地址 + 8 的位置加载数据到寄存器 x16)
* **逆向中的意义:**  在逆向分析时，如果遇到这种 PC 相对寻址的加载指令，我们知道它通常用于加载代码段中的常量数据或者跳转目标地址。
* **重定位需求:**  当这段代码被移动到新的内存地址时，`pc` 的值会发生变化。为了使 `ldr` 指令仍然加载到原来的数据，需要将这条指令改写。
* **重定位后的指令:**
    ```assembly
    ldr x16, [pc, #8]  // 先加载目标数据的地址到 x16
    ldr x16, [x16]     // 再从 x16 指向的地址加载数据到 x16
    <calculated PC>     // 原始目标数据的绝对地址
    ```
    Frida 的重定位器会将原始的 PC 相对加载指令保留，然后在后面插入一条间接加载指令，并将原始的目标地址计算出来并存储在紧随其后的内存位置。这样，无论代码被移动到哪里，这段代码都能正确加载到目标数据。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

1. **二进制底层知识：**
   * **ARM64 指令集架构:**  代码直接操作 ARM64 指令的二进制表示，例如 `GUINT32_TO_LE(0x58000050)` 代表 `ldr x16, [pc, #8]` 的小端字节序表示。理解 ARM64 指令的编码格式是进行重定位的基础。
   * **PC 相对寻址:**  很多 ARM64 指令使用 PC 相对寻址，其目标地址是相对于当前程序计数器 (PC) 的偏移量。重定位的核心就是处理这类指令。
   * **指令长度:** ARM64 指令通常是 4 字节的。重定位器需要正确读取和写入这些指令。

2. **Linux/Android 内核及框架知识：**
   * **进程内存布局:** 动态插桩涉及到在目标进程的内存空间中插入代码。理解进程的内存布局（代码段、数据段、堆栈等）对于确定代码移动的位置和需要重定位的指令至关重要。
   * **动态链接:**  在 Linux/Android 中，共享库的加载地址在运行时可能是不确定的。代码重定位技术也用于处理共享库中需要进行地址调整的指令，这通常由动态链接器完成，而 Frida 的重定位器在动态插桩场景下扮演类似的角色。
   * **代码注入:** Frida 的工作原理是将自己的代码注入到目标进程中。重定位是确保注入的代码和被 hook 的代码能够无缝衔接的关键技术。

**逻辑推理、假设输入与输出举例：**

**测试用例 `adr_should_be_rewritten`：**

* **假设输入:**  一段包含 `adr x1, 0x14e6` 指令的二进制代码，假设该指令位于内存地址 `0x1000`。
* **指令含义:** `adr x1, 0x14e6` 指令将当前 PC 加上一个偏移量计算出的地址加载到寄存器 `x1` 中。 假设原始 PC 是 `0x1000`，那么目标地址是 `0x1000 + 0x14e6 = 0x24e6`。
* **重定位逻辑:**  当这段代码被移动到新的地址，例如 `0x3000` 时，直接执行 `adr x1, 0x14e6` 会计算出错误的地址 `0x3000 + 0x14e6 = 0x44e6`。为了保持 `x1` 仍然指向 `0x24e6`，需要进行重定位。
* **假设输出 (重定位后的指令):**
    ```assembly
    ldr x1, [pc, #4]  // 加载紧随其后的 64 位地址到 x1
    0x00000000000024e6 // 存储原始的目标地址
    ```
    重定位器会将 `adr` 指令替换为一条 `ldr` 指令，该 `ldr` 指令从紧随其后的内存位置加载一个 64 位的绝对地址，这个地址就是原始 `adr` 指令计算出的目标地址 `0x24e6`。

**用户或编程常见的使用错误及举例说明：**

1. **假设目标代码不可写:**  Frida 需要将重定位后的指令写入到内存中。如果用户尝试 hook 的内存区域是只读的，重定位过程将会失败。

2. **重定位范围不足:**  如果用户需要 hook 的代码片段非常大，导致重定位后的指令序列超过了可用的空间，可能会导致覆盖其他内存区域，引发崩溃。

3. **错误地假设指令长度:**  ARM 指令集有不同长度的指令（虽然 ARM64 大部分是 4 字节）。如果用户或工具错误地估计了指令长度，可能会导致重定位器读取到错误的指令边界，从而产生错误的重定位结果。

**用户操作如何一步步到达这里作为调试线索：**

假设一个开发者在使用 Frida hook 一个 Android 应用的 native 函数：

1. **编写 Frida 脚本:** 开发者编写一个 JavaScript 脚本，使用 Frida 的 `Interceptor.attach` API 来 hook 目标函数。

2. **指定目标函数地址或符号:** 脚本中需要指定要 hook 的目标函数的地址或者符号名称。

3. **Frida 注入:** 当 Frida 运行时，它会将 Frida agent 注入到目标应用进程中。

4. **执行到目标函数:** 当应用执行到被 hook 的目标函数时，Frida 会拦截执行流程。

5. **代码备份和重定位:**  为了执行用户的 hook 代码，Frida 需要在目标函数入口处插入跳转指令。这通常需要备份目标函数开头的几条指令，并将这些指令重定位到新的位置，以便在执行完 hook 代码后能够继续执行原始指令。 **这个 `arm64relocator.c` 中测试的代码就是在验证这个重定位步骤的正确性。**

6. **执行 Hook 代码:**  Frida 执行用户定义的 JavaScript hook 代码。

7. **返回原始执行流:**  在 hook 代码执行完毕后，Frida 会跳转回重定位后的原始指令继续执行。

如果在调试过程中发现被 hook 的函数执行出现异常，例如崩溃或者行为不符合预期，一个可能的调试线索就是怀疑代码重定位过程出现了问题。开发者可能会检查 Frida 的日志输出，查看是否有重定位相关的错误信息。更深入的调试可能需要查看 Frida 生成的重定位后的代码，对比原始指令，看是否重定位逻辑有误。`arm64relocator.c` 中的测试用例就是帮助 Frida 的开发者确保在各种情况下都能正确地进行代码重定位，从而避免这类问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm64/arm64relocator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2014-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64relocator-fixture.c"

TESTLIST_BEGIN (arm64relocator)
  TESTENTRY (one_to_one)
  TESTENTRY (ldr_x_should_be_rewritten)
  TESTENTRY (ldr_w_should_be_rewritten)
  TESTENTRY (ldr_d_should_be_rewritten)
  TESTENTRY (ldrsw_x_should_be_rewritten)
  TESTENTRY (adr_should_be_rewritten)
  TESTENTRY (adrp_should_be_rewritten)
  TESTENTRY (cbz_should_be_rewritten)
  TESTENTRY (tbnz_should_be_rewritten)
  TESTENTRY (b_cond_should_be_rewritten)
  TESTENTRY (b_should_be_rewritten)
  TESTENTRY (bl_should_be_rewritten)
  TESTENTRY (cannot_relocate_with_early_br)
  TESTENTRY (eob_and_eoi_on_br)
  TESTENTRY (eob_and_eoi_on_ret)
TESTLIST_END ()

TESTCASE (one_to_one)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xa9be4ff4), /* stp x20, x19, [sp, #-32]! */
    GUINT32_TO_LE (0x92800210), /* movn x16, #0x10           */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 8);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 4, input + 1, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (8);

  g_assert_false (gum_arm64_relocator_write_one (&fixture->rl));
}

TESTCASE (ldr_x_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x58000050)  /* ldr x16, [pc, #8]  */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000050), /* ldr x16, [pc, #8]  */
    GUINT32_TO_LE (0xf9400210), /* ldr x16, [x16]     */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[4 * sizeof (guint32)];
  guint64 calculated_pc;
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 8;
  *((guint64 *) (expected_output + 8)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_LDR);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (ldr_w_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x18000042)  /* ldr w2, [pc, #8]   */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000042), /* ldr x2, [pc, #8]   */
    GUINT32_TO_LE (0xb9400042), /* ldr w2, [x2]       */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[4 * sizeof (guint32)];
  guint64 calculated_pc;
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 8;
  *((guint64 *) (expected_output + 8)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_LDR);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (ldr_d_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x5c000041)  /* ldr d1, [pc, #8]   */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0xa9bf07e0), /* push {x0, x1}      */
    GUINT32_TO_LE (0x58000060), /* ldr x0, [pc, #16]  */
    GUINT32_TO_LE (0xfd400001), /* ldr d1, [x0]       */
    GUINT32_TO_LE (0xa8c107e0), /* pop {x0, x1}       */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[6 * sizeof (guint32)];
  guint64 calculated_pc;
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 8;
  *((guint64 *) (expected_output + 16)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_LDR);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (ldrsw_x_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x98000048)  /* ldrsw x8, [pc, #8] */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000048), /* ldr x8, [pc, #8]   */
    GUINT32_TO_LE (0xb9800108), /* ldrsw x8, [x8]     */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[4 * sizeof (guint32)];
  guint64 calculated_pc;
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 8;
  *((guint64 *) (expected_output + 8)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_LDRSW);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (adr_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x5000a721)  /* adr x1, 0x14e6     */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000021), /* ldr x1, [pc, #4]   */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[3 * sizeof (guint32)];
  guint64 calculated_pc;
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 0x14e6;
  *((guint64 *) (expected_output + 4)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_ADR);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (adrp_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xd000a723)  /* adrp x3, 0x14e6000 */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000023), /* ldr x3, [pc, #4]   */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[3 * sizeof (guint32)];
  guint64 calculated_pc;
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc =
      (fixture->rl.input_pc & ~G_GUINT64_CONSTANT (4096 - 1)) + 0x14e6000;
  *((guint64 *) (expected_output + 4)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_ADRP);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (cbz_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xb40000c0)  /* cbz x0, #+6       */
  };
  const guint32 expected_output[] = {
    GUINT32_TO_LE (0xb4000040), /* cbz x0, #+2       */
    GUINT32_TO_LE (0x14000003), /* b +3              */
    GUINT32_TO_LE (0x58000050), /* ldr x16, [pc, #8] */
    GUINT32_TO_LE (0xd61f0200)  /* br x16            */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_CBZ);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (tbnz_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x37480061)  /* tbnz w1, #9, #+3 */
  };
  const guint32 expected_output[] = {
    GUINT32_TO_LE (0x37480041), /* tbnz w1, #9, #+2  */
    GUINT32_TO_LE (0x14000003), /* b +3              */
    GUINT32_TO_LE (0x58000050), /* ldr x16, [pc, #8] */
    GUINT32_TO_LE (0xd61f0200)  /* br x16            */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_TBNZ);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (b_cond_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x540000c3)  /* b.lo #+6          */
  };
  const guint32 expected_output[] = {
    GUINT32_TO_LE (0x54000043), /* b.lo #+2          */
    GUINT32_TO_LE (0x14000003), /* b +3              */
    GUINT32_TO_LE (0x58000050), /* ldr x16, [pc, #8] */
    GUINT32_TO_LE (0xd61f0200)  /* br x16            */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM64_INS_B);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  guint instruction_id;
  guint32 input[1];
  gsize input_length;
  guint32 expected_output[4];
  gsize expected_output_length;
  gsize pc_offset;
  gssize expected_pc_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestArm64RelocatorFixture * fixture);

TESTCASE (b_should_be_rewritten)
{
  BranchScenario bs = {
    ARM64_INS_B,
    { 0x17ffff5a }, 1,  /* b #-664            */
    {
      0x58000050,       /* ldr x16, [pc, #8]  */
      0xd61f0200,       /* br x16             */
      0xffffffff,       /* <calculated PC     */
      0xffffffff        /*  goes here>        */
    }, 4,
    2, -664
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (bl_should_be_rewritten)
{
  BranchScenario bs = {
    ARM64_INS_BL,
    { 0x97ffff5a }, 1,  /* bl #-664           */
    {
      0x5800005e,       /* ldr lr, [pc, #8]   */
      0xd63f03c0,       /* blr lr             */
      0xffffffff,       /* <calculated PC     */
      0xffffffff        /*  goes here>        */
    }, 4,
    2, -664
  };
  branch_scenario_execute (&bs, fixture);
}

static void
branch_scenario_execute (BranchScenario * bs,
                         TestArm64RelocatorFixture * fixture)
{
  gsize i;
  guint64 calculated_pc;
  const cs_insn * insn;

  for (i = 0; i != bs->input_length; i++)
    bs->input[i] = GUINT32_TO_LE (bs->input[i]);
  for (i = 0; i != bs->expected_output_length; i++)
    bs->expected_output[i] = GUINT32_TO_LE (bs->expected_output[i]);

  SETUP_RELOCATOR_WITH (bs->input);

  calculated_pc = fixture->rl.input_pc + bs->expected_pc_distance;
  bs->expected_output[bs->pc_offset + 0] =
      GUINT32_TO_LE ((calculated_pc >> 0) & 0xffffffff);
  bs->expected_output[bs->pc_offset + 1] =
      GUINT32_TO_LE ((calculated_pc >> 32) & 0xffffffff);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, bs->instruction_id);
  g_assert_true (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, bs->expected_output,
      bs->expected_output_length * sizeof (guint32)), ==, 0);
}

TESTCASE (cannot_relocate_with_early_br)
{
  guint32 input[] = {
    GUINT32_TO_LE (0x58000050), /* ldr x16, [pc, #8] */
    GUINT32_TO_LE (0xd61f0200)  /* br x16            */
  };

  g_assert_false (gum_arm64_relocator_can_relocate (input, 16,
      GUM_SCENARIO_OFFLINE, NULL, NULL));
}

TESTCASE (eob_and_eoi_on_br)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xd61f0200)  /* br x16 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert_true (gum_arm64_relocator_eob (&fixture->rl));
  g_assert_true (gum_arm64_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

TESTCASE (eob_and_eoi_on_ret)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xd65f03c0)  /* ret */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert_true (gum_arm64_relocator_eob (&fixture->rl));
  g_assert_true (gum_arm64_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, NULL), ==, 0);
}
```