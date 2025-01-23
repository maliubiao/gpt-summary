Response:
The user wants a summary of the functionality of the C code provided, which is a test file for a Thumb instruction relocator within the Frida dynamic instrumentation framework.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file `thumbrelocator.c` contains test cases for `gum_thumb_relocator`. This indicates the code being tested is responsible for modifying Thumb instructions at runtime. Relocation often means adjusting instruction addresses or operands.

2. **Examine the test cases:** The names of the `TESTENTRY` macros are highly informative. They describe specific scenarios the relocator is designed to handle. Group these scenarios by their intent. For example, tests with "ldrpc", "adr", and "addh" relate to PC-relative addressing. Tests with "b", "bl", "blx", "cbz", "cbnz", and "b_cond" deal with branching instructions. "it_block" tests cover conditional execution blocks.

3. **Look for common patterns in the test cases:**  Most test cases follow a similar structure:
    - Define `input`: The original Thumb instructions.
    - Define `expected_output`: The modified instructions after relocation.
    - Use `SETUP_RELOCATOR_WITH`: Initializes the relocator with the input.
    - Use `gum_thumb_relocator_read_one`: Simulates reading an instruction.
    - Use `gum_thumb_relocator_write_one` or `gum_thumb_relocator_write_all`: Simulates writing the relocated instruction(s).
    - Use `check_output`: Verifies that the output matches the expected output.

4. **Connect to reverse engineering:**  Instruction relocation is a crucial technique in dynamic instrumentation and reverse engineering. When inserting code (like Frida's instrumentation stubs), branch targets and PC-relative loads might need to be adjusted to point to the correct locations in the modified code.

5. **Connect to low-level concepts:**  The code directly manipulates binary instructions (represented by `guint16`). It deals with concepts like PC (Program Counter), instruction encoding, and addressing modes (PC-relative). The ARM architecture and its Thumb instruction set are central.

6. **Infer logic and assumptions:** The tests with "should_be_rewritten" imply that the original instruction cannot be directly executed at the new location and needs modification. The "expected_output" shows how the relocator transforms the instructions. For instance, PC-relative loads are often rewritten into a sequence that loads the address into a register and then performs the actual load. Branches are rewritten to accommodate larger offsets or to jump to injected code.

7. **Consider potential errors:** If the relocator doesn't correctly handle an instruction, the program could crash or behave unexpectedly. Errors could arise from incorrect calculation of new addresses, improper instruction encoding, or failing to handle specific instruction types.

8. **Trace the user's path:**  A user would typically use Frida to attach to a running process and inject JavaScript code. Frida, in turn, uses its Gum engine. The Thumb relocator would be invoked by Gum when modifying Thumb code within the target process.

9. **Summarize the core functionality:** Based on the above points, synthesize a concise description of the file's purpose.

**Self-Correction/Refinement during thought process:**

- Initially, I might focus too much on individual test cases. It's important to step back and identify the higher-level goal: testing the Thumb instruction relocation logic.
-  I need to ensure I connect the testing to the practical use case in Frida – dynamic instrumentation.
-  The examples need to be concrete and related to the specific instruction types being tested (e.g., `ldrpc`, `bl`).
-  When explaining the low-level aspects, I need to mention relevant terms like "binary instructions," "PC," "Thumb," and "addressing modes."
-  The user's path needs to be described in a way that makes sense within the context of Frida's workflow.
这个C源代码文件 `thumbrelocator.c` 是 Frida Dynamic Instrumentation 工具中 `frida-gum` 组件的一部分，它专注于 **ARM 架构下 Thumb 指令的重定位 (relocation) 功能的单元测试**。

以下是其功能的详细归纳：

**核心功能：测试 Thumb 指令重定位**

这个文件的主要目的是验证 `gum_thumb_relocator` 组件在各种 Thumb 指令场景下的正确性。重定位是指在代码被移动到内存中的新位置后，修改指令中的地址或偏移量，以确保它们仍然指向正确的目标。

**具体测试的指令类型和场景：**

该文件包含多个 `TESTCASE`，每个 `TESTCASE` 针对不同的 Thumb 指令或指令序列进行测试，主要覆盖以下方面：

1. **一对一指令重定位 (one_to_one):**
   - 测试简单的指令，验证读取和写入单个指令的功能，并确保输出与输入一致。

2. **处理扩展指令 (handle_extended_instructions):**
   - 测试处理占用多个字 (word) 的 Thumb-2 扩展指令的情况。

3. **PC 相对加载指令重写 (ldrpc_t1_should_be_rewritten, ldrpc_t2_should_be_rewritten, vldrpc_t1_should_be_rewritten, vldrpc_t2_should_be_rewritten):**
   - 测试 `ldr reg, [pc, #offset]` 类型的指令，这类指令从程序计数器 (PC) 相对的地址加载数据。
   - 功能是将这类指令重写为先将目标地址加载到一个寄存器，再通过寄存器加载数据，以适应代码移动后的 PC 值变化。

4. **地址加载指令重写 (adr_should_be_rewritten, adr_unaligned_should_be_rewritten):**
   - 测试 `adr reg, #offset` 类型的指令，用于计算并加载基于 PC 的地址到寄存器。
   - 功能是将这类指令重写为先计算出正确的绝对地址，再加载到寄存器。

5. **加法高位寄存器指令重写 (addh_should_be_rewritten_if_pc_relative):**
   - 测试使用 PC 作为源操作数的 `add` 指令，需要确保在重定位后仍然计算出正确的地址。

6. **分支链接指令序列重写 (bl_sequence_should_be_rewritten):**
   - 测试 `bl` (Branch with Link) 和 `blx` (Branch with Link and Exchange) 指令序列，这类指令用于调用子程序。
   - 功能是将这类指令重写为先将目标地址加载到 `lr` (Link Register)，然后使用 `blx lr` 进行跳转，以支持更大的跳转范围和代码移动。

7. **无条件分支指令重写 (b_imm_t2_positive_should_be_rewritten, b_imm_t2_negative_should_be_rewritten, b_imm_t4_positive_should_be_rewritten, b_imm_t4_negative_should_be_rewritten):**
   - 测试 `b` (Branch) 指令的不同编码格式和正负偏移量。
   - 功能是将这类指令重写为跳转到目标地址，需要考虑代码移动后的目标地址变化。

8. **分支链接指令重写 (bl_imm_t1_positive_should_be_rewritten, bl_imm_t1_negative_should_be_rewritten, blx_imm_t2_positive_should_be_rewritten, blx_imm_t2_negative_should_be_rewritten):**
   - 测试 `bl` 和 `blx` 指令的不同编码格式和正负偏移量。
   - 功能类似于 `bl_sequence_should_be_rewritten`，但针对的是单条 `bl/blx` 指令。

9. **条件分支指令重写 (cbz_should_be_rewritten, cbnz_should_be_rewritten, b_cond_should_be_rewritten):**
   - 测试 `cbz` (Compare and Branch if Zero), `cbnz` (Compare and Branch if Non-Zero) 以及带条件的 `b` 指令。
   - 功能是将这类指令重写为在条件不满足时跳过原目标地址的代码，并在条件满足时跳转到目标地址。

10. **IT 块指令重写 (it_block_with_pc_relative_load_should_be_rewritten, it_block_with_b_should_be_rewritten, it_block_should_be_rewritten_as_a_whole, it_block_with_eoi_insn_should_be_rewritten):**
    - 测试 `IT` (If-Then) 块指令，这是一组条件执行的指令。
    - 功能是将 `IT` 块中的 PC 相对加载或分支指令进行重写，确保在条件执行的情况下目标地址的正确性。

11. **处理返回指令附近的 EOB 和 EOI 指令 (eob_and_eoi_on_ret):**
    - 测试在函数返回指令附近可能出现的 `EOB` (End of Branch) 和 `EOI` (End of Instruction) 指令的处理。

**与逆向方法的关系：**

这个文件直接关系到动态逆向分析的方法。Frida 作为一个动态插桩工具，其核心功能之一就是在运行时修改目标进程的代码。为了实现这一点，当 Frida 在目标进程中插入自己的代码 (例如，JavaScript 代码对应的 native 代码) 时，就需要对原始代码中的指令进行重定位，以确保程序流程的正确性。

**举例说明：**

假设原始代码中有一条指令 `ldr r0, [pc, #4]`，它从 PC + 4 的地址加载数据到 `r0` 寄存器。

- **逆向分析时：**  逆向工程师可能会遇到这条指令，并需要理解它加载的数据是什么。如果代码被移动到新的内存地址，`pc + 4` 的值将不再指向原始的目标数据。
- **Frida 的作用：**  `gum_thumb_relocator` 会识别出这条指令是 PC 相对加载。
- **重定位过程：**  它会将这条指令重写为类似下面的指令序列：
   ```assembly
   ldr r1, [pc, #new_offset]  ; 加载原始目标数据的绝对地址到 r1
   ldr r0, [r1]               ; 从 r1 指向的地址加载数据到 r0
   ; new_offset 的值会被计算出来，使得 [pc + new_offset] 指向原始的目标数据地址。
   ```
   这样，即使代码被移动，`r0` 仍然能加载到正确的数据。

**涉及的二进制底层、Linux、Android 内核及框架知识：**

1. **二进制底层知识：**
   - **ARM 架构和 Thumb 指令集：**  该文件针对 ARM 架构的 Thumb 和 Thumb-2 指令进行测试，需要理解不同 Thumb 指令的编码格式、操作码、寻址方式等。例如，需要知道 PC 相对寻址的工作原理，以及分支指令中偏移量的计算方式。
   - **指令长度和对齐：**  需要知道 Thumb 指令是 16 位或 32 位 (Thumb-2)，以及指令的内存对齐要求。
   - **程序计数器 (PC)：**  理解 PC 在指令执行过程中的作用，以及 PC 相对寻址中 PC 的值是如何计算的。
   - **寄存器约定：**  例如，Link Register (LR) 用于存储返回地址。

2. **Linux/Android 内核知识：**
   - **内存管理：**  理解进程的内存空间布局，代码段、数据段等。重定位发生在代码被加载到内存的不同位置时。
   - **动态链接和加载：**  虽然这个测试文件本身不直接涉及动态链接，但重定位的概念在动态链接中也很重要。
   - **进程上下文：**  Frida 需要在目标进程的上下文中进行代码修改和执行。

3. **Android 框架知识：**
   - **ART/Dalvik 虚拟机：**  在 Android 环境下，Frida 经常需要操作运行在虚拟机上的代码。虽然这个测试针对的是 native 代码，但理解虚拟机的工作原理有助于理解 Frida 的应用场景。

**逻辑推理、假设输入与输出：**

大多数 `TESTCASE` 都包含了假设的输入指令和预期的输出指令。以 `ldrpc_t1_should_be_rewritten` 为例：

**假设输入：**

```assembly
GUINT16_TO_LE (0x4a03), /* ldr r2, [pc, #12] */
```
这条指令的含义是：将 PC + 12 指向的内存地址处的值加载到寄存器 `r2`。

**假设输入环境：** 假设这条指令位于内存地址 `fixture->rl.input_pc`。

**逻辑推理：**

- 原始指令是 PC 相对加载，如果代码被移动，`pc + 12` 不再指向正确的数据。
- 需要将这条指令重写为先加载目标地址，再加载数据。
- 重写后的指令序列会使用一个临时的 PC 相对加载来获取原始目标数据的绝对地址。

**预期输出：**

```assembly
GUINT16_TO_LE (0x4a00), /* ldr r2, [pc, #0] */
GUINT16_TO_LE (0x6812), /* ldr r2, r2       */
GUINT16_TO_LE (0xffff), /* <calculated PC   */
GUINT16_TO_LE (0xffff), /*  goes here>      */
```
- 第一条指令 `ldr r2, [pc, #0]` 加载紧随其后的 4 字节数据到 `r2`。
- 第二条指令 `ldr r2, r2` 实际上是以 `r2` 寄存器中的地址为目标地址进行加载，实现了从原始目标地址加载数据的目的。
- 后面的两个 `0xffff` 被实际计算出的原始目标数据地址替换。

**用户或编程常见的使用错误：**

这个文件主要测试 Frida 内部的组件，用户直接与这个文件交互的可能性很小。但是，如果 `gum_thumb_relocator` 组件存在 bug，可能会导致以下问题：

1. **代码执行错误：** 重定位不正确可能导致程序跳转到错误的地址，或者加载错误的数据，最终导致程序崩溃或行为异常。
2. **安全漏洞：** 在某些情况下，错误的重定位可能被恶意利用来执行非预期的代码。
3. **Frida 功能失效：**  如果重定位功能出现问题，Frida 注入代码的能力会受到影响。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户使用 Frida 连接到目标进程：**  例如，使用 `frida -p <pid>` 或通过 Python 脚本连接。
2. **用户编写 JavaScript 代码并注入到目标进程：**  JavaScript 代码可能包含 hook 函数、替换函数等操作，这些操作最终需要在 native 代码层面实现。
3. **Frida 的 Gum 引擎处理 JavaScript 请求：**  Gum 引擎负责将 JavaScript 代码转化为 native 指令，并在目标进程中执行。
4. **Gum 引擎需要修改目标进程的 Thumb 代码：**  例如，在 hook 函数入口处插入跳转指令，或者替换原有的函数实现。
5. **`gum_thumb_relocator` 被调用：** 当需要修改 Thumb 代码时，Gum 引擎会使用 `gum_thumb_relocator` 来重定位被覆盖或移动的指令，确保原始代码的功能不受影响。
6. **如果 `gum_thumb_relocator` 存在 bug，用户可能会观察到目标进程崩溃或行为异常，而调试线索可能指向 Frida 内部的重定位逻辑。**  开发者可能会查看 Frida 的日志或进行更深入的调试，最终可能涉及到 `thumbrelocator.c` 中的测试用例来理解和修复问题。

**功能归纳 (针对第 1 部分):**

这个 `thumbrelocator.c` 文件的第 1 部分主要定义了 **针对 ARM 架构下 Thumb 指令重定位功能的各种单元测试用例**。这些测试用例覆盖了多种 Thumb 指令类型，包括 PC 相对加载、地址加载、分支指令、条件分支指令以及 IT 块指令。其目的是验证 `gum_thumb_relocator` 组件能够正确地识别需要重定位的指令，并将其重写为在代码移动后仍然能够正确执行的指令序列。这些测试是确保 Frida 动态插桩功能在 ARM Thumb 代码上正确运行的关键组成部分。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/thumbrelocator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2010-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "thumbrelocator-fixture.c"

TESTLIST_BEGIN (thumbrelocator)
  TESTENTRY (one_to_one)
  TESTENTRY (handle_extended_instructions)

  TESTENTRY (ldrpc_t1_should_be_rewritten)
  TESTENTRY (ldrpc_t2_should_be_rewritten)
  TESTENTRY (vldrpc_t1_should_be_rewritten)
  TESTENTRY (vldrpc_t2_should_be_rewritten)
  TESTENTRY (adr_should_be_rewritten)
  TESTENTRY (adr_unaligned_should_be_rewritten)
  TESTENTRY (addh_should_be_rewritten_if_pc_relative)
  TESTENTRY (bl_sequence_should_be_rewritten)
  TESTENTRY (b_imm_t2_positive_should_be_rewritten)
  TESTENTRY (b_imm_t2_negative_should_be_rewritten)
  TESTENTRY (b_imm_t4_positive_should_be_rewritten)
  TESTENTRY (b_imm_t4_negative_should_be_rewritten)
  TESTENTRY (bl_imm_t1_positive_should_be_rewritten)
  TESTENTRY (bl_imm_t1_negative_should_be_rewritten)
  TESTENTRY (blx_imm_t2_positive_should_be_rewritten)
  TESTENTRY (blx_imm_t2_negative_should_be_rewritten)
  TESTENTRY (cbz_should_be_rewritten)
  TESTENTRY (cbnz_should_be_rewritten)
  TESTENTRY (b_cond_should_be_rewritten)
  TESTENTRY (it_block_with_pc_relative_load_should_be_rewritten)
  TESTENTRY (it_block_with_b_should_be_rewritten)
  TESTENTRY (it_block_should_be_rewritten_as_a_whole)
  TESTENTRY (it_block_with_eoi_insn_should_be_rewritten)
  TESTENTRY (eob_and_eoi_on_ret)
TESTLIST_END ()

TESTCASE (one_to_one)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb580), /* push {r7, lr}  */
    GUINT16_TO_LE (0xaf00), /* add r7, sp, #0 */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_ADD);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 2), ==, 0);
  assert_outbuf_still_zeroed_from_offset (2);

  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (((guint8 *) fixture->output) + 2, input + 1, 2),
      ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert_false (gum_thumb_relocator_write_one (&fixture->rl));
}

TESTCASE (handle_extended_instructions)
{
  const guint16 input[] = {
    /* stmdb sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr} */
    GUINT16_TO_LE (0xe92d), GUINT16_TO_LE (0x4ff0),
    GUINT16_TO_LE (0xb580), /* push {r7, lr}  */
    GUINT16_TO_LE (0xf241), GUINT16_TO_LE (0x3037), /* movw r0, #4919 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 6);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 10);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_false (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input)), ==, 0);
}

TESTCASE (ldrpc_t1_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x4a03), /* ldr r2, [pc, #12] */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0x4a00), /* ldr r2, [pc, #0] */
    GUINT16_TO_LE (0x6812), /* ldr r2, r2       */
    GUINT16_TO_LE (0xffff), /* <calculated PC   */
    GUINT16_TO_LE (0xffff), /*  goes here>      */
  };
  gchar expected_output[4 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = (fixture->rl.input_pc + 4 + 12) & ~(4 - 1);
  *((guint32 *) (expected_output + 4)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_LDR);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (ldrpc_t2_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xf8df), GUINT16_TO_LE (0x2768) /* ldr.w r2, [pc, #1896] */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0x4a00), /* ldr r2, [pc, #0] */
    GUINT16_TO_LE (0x6812), /* ldr r2, r2       */
    GUINT16_TO_LE (0xffff), /* <calculated PC   */
    GUINT16_TO_LE (0xffff), /*  goes here>      */
  };
  gchar expected_output[4 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = (fixture->rl.input_pc + 4 + 1896) & ~(4 - 1);
  *((guint32 *) (expected_output + 4)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_LDR);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (vldrpc_t1_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xeddf),
    GUINT16_TO_LE (0x0a00), /* vldr  s1, [pc, #0] */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb401), /* push {r0}          */
    GUINT16_TO_LE (0x4802), /* ldr  r0, [pc, #8]  */
    GUINT16_TO_LE (0xedd0), /* ...                */
    GUINT16_TO_LE (0x0a00), /* vldr s1, [r0]      */
    GUINT16_TO_LE (0xbc01), /* pop  {r0}          */
    GUINT16_TO_LE (0xbf00), /* nop                */
    GUINT16_TO_LE (0xffff), /* <calculated PC     */
    GUINT16_TO_LE (0xffff), /*  goes here>        */
  };
  gchar expected_output[8 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));

  calculated_pc = (fixture->rl.input_pc + 4) & ~(4 - 1);
  *((guint32 *) (expected_output + 12)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_VLDR);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);

  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (vldrpc_t2_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xed9f),
    GUINT16_TO_LE (0x1b00), /* vldr  d1, [pc, #0] */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb401), /* push {r0}          */
    GUINT16_TO_LE (0x4802), /* ldr  r0, [pc, #8]  */
    GUINT16_TO_LE (0xed90), /* ...                */
    GUINT16_TO_LE (0x1b00), /* vldr d1, [r0]      */
    GUINT16_TO_LE (0xbc01), /* pop  {r0}          */
    GUINT16_TO_LE (0xbf00), /* nop                */
    GUINT16_TO_LE (0xffff), /* <calculated PC     */
    GUINT16_TO_LE (0xffff), /*  goes here>        */
  };
  gchar expected_output[8 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));

  calculated_pc = (fixture->rl.input_pc + 4) & ~(4 - 1);
  *((guint32 *) (expected_output + 12)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_VLDR);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);

  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (adr_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xa107),   /* adr r1, #0x1c    */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb401),   /* push {r0}        */
    GUINT16_TO_LE (0x4902),   /* ldr r1, [pc, #8] */
    GUINT16_TO_LE (0x4802),   /* ldr r0, [pc, #8] */
    GUINT16_TO_LE (0x4401),   /* add r1, r0       */
    GUINT16_TO_LE (0xbc01),   /* pop {r0}         */
    GUINT16_TO_LE (0xbf00),   /* nop              */
    GUINT16_TO_LE (0xffff),   /* <calculated PC   */
    GUINT16_TO_LE (0xffff),   /*  goes here>      */
    GUINT16_TO_LE (0x001c),   /* <immediate       */
    GUINT16_TO_LE (0x0000),   /*  goes here>      */
  };
  gchar expected_output[10 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 4;
  *((guint32 *) (expected_output + 12)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_ADR);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (adr_unaligned_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x4600),   /* mov r0, r0       */
    GUINT16_TO_LE (0xa107),   /* adr r1, #0x1c    */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0x4600),   /* mov r0, r0       */
    GUINT16_TO_LE (0xb401),   /* push {r0}        */
    GUINT16_TO_LE (0x4901),   /* ldr r1, [pc, #4] */
    GUINT16_TO_LE (0x4802),   /* ldr r0, [pc, #8] */
    GUINT16_TO_LE (0x4401),   /* add r1, r0       */
    GUINT16_TO_LE (0xbc01),   /* pop {r0}         */
    GUINT16_TO_LE (0xffff),   /* <calculated PC   */
    GUINT16_TO_LE (0xffff),   /*  goes here>      */
    GUINT16_TO_LE (0x001c),   /* <immediate       */
    GUINT16_TO_LE (0x0000),   /*  goes here>      */
  };
  gchar expected_output[10 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 4;
  *((guint32 *) (expected_output + 12)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_MOV);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_ADR);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));

  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (addh_should_be_rewritten_if_pc_relative)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x447a),   /* add r2, pc       */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb401),   /* push {r0}        */
    GUINT16_TO_LE (0x4801),   /* ldr r0, [pc, #4] */
    GUINT16_TO_LE (0x4402),   /* add r2, r0       */
    GUINT16_TO_LE (0xbc01),   /* pop {r0}         */
    GUINT16_TO_LE (0xffff),   /* <calculated PC   */
    GUINT16_TO_LE (0xffff),   /*  goes here>      */
  };
  gchar expected_output[6 * sizeof (guint16)];

  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 4;
  *((guint32 *) (expected_output + 8)) = calculated_pc;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_ADD);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (bl_sequence_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb573),      /* push {r0, r1, r4, r5, r6, lr} */
    GUINT16_TO_LE (0xf001), GUINT16_TO_LE (0xfbc9), /* bl 0x1543c */
    GUINT16_TO_LE (0xf7fb), GUINT16_TO_LE (0xeca0), /* blx 0xf5ec */
  };
  const guint16 expected_output_instructions[16] = {
    GUINT16_TO_LE (0xb573),      /* push {r0, r1, r4, r5, r6, lr} */
    GUINT16_TO_LE (0xb401),                  /* push {r0}         */
    GUINT16_TO_LE (0x4804),                  /* ldr r0, [pc, #16] */
    GUINT16_TO_LE (0x4686),                  /* mov lr, r0        */
    GUINT16_TO_LE (0xbc01),                  /* pop {r0}          */
    GUINT16_TO_LE (0x47f0),                  /* blx lr            */
    GUINT16_TO_LE (0xb401),                  /* push {r0}         */
    GUINT16_TO_LE (0x4803),                  /* ldr r0, [pc, #12] */
    GUINT16_TO_LE (0x4686),                  /* mov lr, r0        */
    GUINT16_TO_LE (0xbc01),                  /* pop {r0}          */
    GUINT16_TO_LE (0x47f0),                  /* blx lr            */
    GUINT16_TO_LE (0xbf00),                  /* <padding nop>     */
    GUINT16_TO_LE (0xffff),                  /* <calculated PC1   */
    GUINT16_TO_LE (0xffff),                  /*  goes here>       */
    GUINT16_TO_LE (0xffff),                  /* <calculated PC2   */
    GUINT16_TO_LE (0xffff),                  /*  goes here>       */
  };
  gchar expected_output[16 * sizeof (guint16)];

  const cs_insn * insn = NULL;

  fixture->tw.pc = 0x200000;
  SETUP_RELOCATOR_WITH (input);
  fixture->rl.input_pc = 0x13ca4;

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  *((guint32 *) (expected_output + 24)) = 0x1543c | 1;
  *((guint32 *) (expected_output + 28)) = 0xf5ec;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_PUSH);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 6);
  g_assert_cmpint (insn->id, ==, ARM_INS_BL);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 10);
  g_assert_cmpint (insn->id, ==, ARM_INS_BLX);
  gum_thumb_relocator_write_all (&fixture->rl);
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  guint instruction_id;
  guint16 input[2];
  gsize input_length;
  gsize instruction_length;
  guint16 expected_output[8];
  gsize expected_output_length;
  gsize pc_offset;
  gssize expected_pc_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestThumbRelocatorFixture * fixture);

TESTCASE (b_imm_t2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
    { 0xe004 }, 1, 2,           /* b pc + 8         */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 9
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (b_imm_t2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
    { 0xe7fc }, 1, 2,           /* b pc - 8         */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -7
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (b_imm_t4_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
    { 0xf001, 0xb91a }, 2, 4,   /* b pc + 0x1234    */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 0x1235
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (b_imm_t4_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
    { 0xf7fe, 0xbee6 }, 2, 4,   /* b pc - 0x1234    */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -0x1233
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (bl_imm_t1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BL,
    { 0xf001, 0xf91a }, 2, 4,   /* bl pc + 0x1234   */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 0x1235
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (bl_imm_t1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BL,
    { 0xf7fe, 0xfee6 }, 2, 4,   /* bl pc - 0x1234   */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -0x1233
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (blx_imm_t2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BLX,
    { 0xf001, 0xe91a }, 2, 4,   /* blx pc + 0x1234  */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 0x1234
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (blx_imm_t2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BLX,
    { 0xf7fe, 0xeee6 }, 2, 4,   /* blx pc - 0x1234  */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0xbf00,                   /* <padding nop>    */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -0x1234
  };
  branch_scenario_execute (&bs, fixture);
}

static void
branch_scenario_execute (BranchScenario * bs,
                         TestThumbRelocatorFixture * fixture)
{
  gsize i;
  guint32 calculated_pc;
  const cs_insn * insn = NULL;

  for (i = 0; i != bs->input_length; i++)
    bs->input[i] = GUINT16_TO_LE (bs->input[i]);
  for (i = 0; i != bs->expected_output_length; i++)
    bs->expected_output[i] = GUINT16_TO_LE (bs->expected_output[i]);

  SETUP_RELOCATOR_WITH (bs->input);

  calculated_pc = fixture->rl.input_pc + 4 + bs->expected_pc_distance;
  memcpy (bs->expected_output + bs->pc_offset, &calculated_pc,
      sizeof (calculated_pc));

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn),
      ==, bs->instruction_length);
  g_assert_cmpint (insn->id, ==, bs->instruction_id);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (bs->input, bs->input_length, fixture->output,
      bs->expected_output, bs->expected_output_length * sizeof (guint16));
}

TESTCASE (cbz_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb1e8),     /* cbz r0, #imm     */
    GUINT16_TO_LE (0xbd01)      /* pop {r0, pc}     */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb100),     /* cbz r0, #imm     */
    /* if_false: jump to next instruction           */
    GUINT16_TO_LE (0xe004),     /* b pc + 8         */
    /* if_true:                                     */
    GUINT16_TO_LE (0xb401),     /* push {r0}        */
    GUINT16_TO_LE (0xb401),     /* push {r0}        */
    GUINT16_TO_LE (0x4801),     /* ldr r0, [pc, #4] */
    GUINT16_TO_LE (0x9001),     /* str r0, [sp, #4] */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}     */
    /* next instruction                             */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}     */
    GUINT16_TO_LE (0xffff),
    GUINT16_TO_LE (0xffff)
  };
  guint32 calculated_target;
  gchar expected_output[10 * sizeof (guint16)];
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_target = (fixture->rl.input_pc + 4 + ((0xe8 >> 3) << 1)) | 1;
  *((guint32 *) (expected_output + 16)) = calculated_target;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_CBZ);
  gum_thumb_relocator_read_one (&fixture->rl, &insn);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (cbnz_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb912),     /* cbnz r2, #imm      */
    GUINT16_TO_LE (0xbd01)      /* pop {r0, pc}       */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb902),     /* cbnz r2, #imm      */
    /* if_false:                                      */
    GUINT16_TO_LE (0xe004),     /* b next_instruction */
    /* if_true:                                       */
    GUINT16_TO_LE (0xb401),     /* push {r0}          */
    GUINT16_TO_LE (0xb401),     /* push {r0}          */
    GUINT16_TO_LE (0x4801),     /* ldr r0, [pc, #4]   */
    GUINT16_TO_LE (0x9001),     /* str r0, [sp, #4]   */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}       */
    /* next_instruction:                              */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}       */
    GUINT16_TO_LE (0xffff),
    GUINT16_TO_LE (0xffff)
  };
  guint32 calculated_target;
  gchar expected_output[10 * sizeof (guint16)];
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_target = (fixture->rl.input_pc + 4 + ((0x12 >> 3) << 1)) | 1;
  *((guint32 *) (expected_output + 16)) = calculated_target;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_CBNZ);
  gum_thumb_relocator_read_one (&fixture->rl, &insn);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (b_cond_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xd01b),     /* beq #imm           */
    GUINT16_TO_LE (0xbd01)      /* pop {r0, pc}       */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xd000),     /* beq #imm           */
    /* if_false:                                      */
    GUINT16_TO_LE (0xe004),     /* b next_instruction */
    /* if_true:                                       */
    GUINT16_TO_LE (0xb401),     /* push {r0}          */
    GUINT16_TO_LE (0xb401),     /* push {r0}          */
    GUINT16_TO_LE (0x4801),     /* ldr r0, [pc, #4]   */
    GUINT16_TO_LE (0x9001),     /* str r0, [sp, #4]   */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}       */
    /* next_instruction:                              */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}       */
    GUINT16_TO_LE (0xffff),
    GUINT16_TO_LE (0xffff)
  };
  guint32 calculated_target;
  gchar expected_output[10 * sizeof (guint16)];
  const cs_insn * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_target = (fixture->rl.input_pc + 4 + (0x1b << 1)) | 1;

  *((guint32 *) (expected_output + 16)) = calculated_target;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_B);
  gum_thumb_relocator_read_one (&fixture->rl, &insn);
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  check_output (input, sizeof (input), fixture->output,
      (guint16 *) expected_output, sizeof (expected_output));
}

TESTCASE (it_block_with_pc_relative_load_should_be_rewritten)
{
 const guint16 input[] = {
   GUINT16_TO_LE (0x2800),      /* cmp r0, #0         */
   GUINT16_TO_LE (0xbf06),      /* itte eq            */
   GUINT16_TO_LE (0x4801),      /* ldreq r0, [pc, #4] */
   GUINT16_TO_LE (0x3001),      /* addeq r0, #1       */
   GUINT16_TO_LE (0x3001),      /* addne r0, #1       */
 };
 const guint16 expected_output[] = {
   GUINT16_TO_LE (0x2800),      /* cmp r0, #0         */
   GUINT16_TO_LE (0xd001),      /* beq if_true        */
   /* if_false:                                       */
   GUINT16_TO_LE (0x3001),      /* adds r0, #1        */
   GUINT16_TO_LE (0xe002),      /* b next_instruction */
   /* if_true:                                        */
   GUINT16_TO_LE (0x4800),      /* ldr r0, [pc, #0]   */
   GUINT16_TO_LE (0x6800),      /* ldr r0, [r0, #0]   */
   GUINT16_TO_LE (0x3001),      /* adds r0, #1        */
   /* next_instruction:                               */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);
  insn = NULL;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 10);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_false (gum_thumb_relocator_write_one (&fixture->rl));

  check_output (input, sizeof (input), fixture->output, expected_output,
      sizeof (expected_output));
}

TESTCASE (it_block_with_b_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb580),                         /* push {r7, lr}       */
    GUINT16_TO_LE (0x2801),                         /* cmp r0, #1          */
    GUINT16_TO_LE (0xbf0a),                         /* itet eq             */
    GUINT16_TO_LE (0xf101), GUINT16_TO_LE (0x37ff), /* addeq.w r7, r1, #-1 */
    GUINT16_TO_LE (0x1c4f),                         /* addne r7, r1, #1    */
    GUINT16_TO_LE (0xf7ff), GUINT16_TO_LE (0xef08), /* blxeq.w xxxx        */
  };
  const guint16 expected_output[] = {
    GUINT16_TO_LE (0xb580),                         /* push {r7, lr}       */
    GUINT16_TO_LE (0x2801),                         /* cmp r0, #1          */
    GUINT16_TO_LE (0xd001),                         /* beq if_true         */
    /* if_false:                                                           */
    GUINT16_TO_LE (0x1c4f),                         /* adds r7, r1, #1     */
    GUINT16_TO_LE (0xe006),                         /* b next_instruction  */
    /* if_true:                                                            */
    GUINT16_TO_LE (0xf101), GUINT16_TO_LE (0x37ff), /* add.w r7, r1, #-1   */
    GUINT16_TO_LE (0xb401),                         /* push {r0}           */
    GUINT16_TO_LE (0x4800),                         /* ldr r0, [pc, #0]    */
    GUINT16_TO_LE (0x4686),                         /* mov lr, r0          */
    GUINT16_TO_LE (0xbc01),                         /* pop {r0}            */
    GUINT16_TO_LE (0x47f0),                         /* blx lr              */
    /* next_instruction:                                                   */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);
  insn = NULL;

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 16);
  assert_outbuf_still_zeroed_from_offset (0);

  gum_thumb_relocator_write_all (&fixture->rl);

  check_output (input, sizeof (input), fixture->output, expected_output,
      sizeof (expected_output));
}

TESTCASE (it_block_should_be_rewritten_as_a_whole)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x2800), /* cmp r0, #0         */
    GUINT16_TO_LE (0xbf1c), /* itt ne             */
    GUINT16_TO_LE (0x6800), /* ldrne r0, [r0]     */
    GUINT16_TO_LE (0x2800)  /* cmpne r0, #0       */
  };
  const guint16 expected_output[] = {
    GUINT16_TO_LE (0x2800), /* cmp r0, #0         */
    GUINT16_TO_LE (0xd100), /* bne if_true        */
    /* if_false:                                  */
    GUINT16_TO_LE (0xe001), /* b next_instruction */
    /* if_true:                                   */
    GUINT16_TO_LE (0x6800), /* ldr r0, [r0, #0]   */
    GUINT16_TO_LE (0x2800), /* cmp r0, #0         */
    /* next_instruction:                          */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->id, ==, ARM_INS_CMP);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 8);
  g_assert_cmpint (insn->id, ==, ARM_INS_IT);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_true (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_false (gum_thumb_relocator_write_one (&fixture->rl));

  check_output (input, sizeof (input), fixture->output, expected_output,
      sizeof (expected_output));
}

TESTCASE (it_block_with_eoi_insn_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x2800),
```