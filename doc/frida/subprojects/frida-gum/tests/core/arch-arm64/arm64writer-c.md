Response:
Let's break down the thought process to analyze this C code for Frida.

1. **Understand the Goal:** The request is to analyze a C file (`arm64writer.c`) within the Frida project, focusing on its functionality, relevance to reverse engineering, low-level details, logic, potential errors, and how one might end up interacting with this code.

2. **Initial Code Scan - Structure:** The first step is to quickly scan the code to get a feel for its structure. I see:
    * Header: Copyright and license information.
    * `#include`: Including "arm64writer-fixture.c". This suggests a testing framework is being used, and `fixture` will likely contain setup data for the tests.
    * `TESTLIST_BEGIN` and `TESTLIST_END`:  These strongly indicate a unit testing framework. The entries within define individual test cases.
    * `TESTENTRY`:  Each line here likely corresponds to a function that tests a specific aspect of the `gum_arm64_writer_put_*` functions.
    * `TESTCASE`:  These are the individual test functions. They call functions like `gum_arm64_writer_put_cbz_reg_label`, `assert_output_n_equals`, etc.
    * `#ifdef HAVE_ARM64`:  Conditional compilation blocks, suggesting some functionality is ARM64-specific.
    * Static function definition: `gum_emit_ldr_in_large_block`.

3. **Identify Key Functionality:** Based on the `TESTENTRY` and `TESTCASE` names and the functions called within them (`gum_arm64_writer_put_*`), I can deduce the primary purpose of this file:

    * **Instruction Emission:** The code is about generating ARM64 assembly instructions programmatically. Functions like `put_cbz_reg_label`, `put_b_imm`, `put_ldr_reg_address`, etc., clearly indicate this.
    * **Testing:** The `TESTLIST_BEGIN`, `TESTENTRY`, `TESTCASE`, and `assert_output_n_equals` indicate a testing suite. It's verifying that the instruction emission functions produce the correct byte sequences.

4. **Relate to Reverse Engineering:**  Now, connect the functionality to reverse engineering:

    * **Dynamic Instrumentation:** Frida is a dynamic instrumentation tool. This means it modifies the behavior of running processes. Generating assembly instructions is a core part of this. Frida needs to inject code into the target process.
    * **Code Injection:** The `gum_arm64_writer_put_*` functions provide the building blocks for constructing this injected code. Reverse engineers use Frida to inject custom logic for hooking functions, modifying data, and tracing execution.
    * **Instruction Manipulation:**  Understanding how instructions are encoded is crucial for reverse engineering. This code demonstrates how to create specific ARM64 instructions.

5. **Identify Low-Level Concepts:**  What low-level details are apparent?

    * **ARM64 Architecture:**  The file name and function names (e.g., `ARM64_REG_X3`, `cbz`, `ldr`) directly refer to the ARM64 architecture and its instruction set.
    * **Registers:**  The use of `ARM64_REG_*` enumerations indicates manipulation of CPU registers.
    * **Instruction Encodings:** The `assert_output_n_equals` checks verify the exact byte representation of the generated instructions. This is directly related to the binary encoding of ARM64 instructions.
    * **Memory Addressing:**  Functions like `ldr_reg_address` and `ldr_reg_reg_offset` deal with loading data from and storing data to memory at specific addresses.
    * **Branching:** Instructions like `b`, `bl`, `br`, `blr`, and `ret` are fundamental for control flow in assembly code.
    * **Calling Conventions:**  The `call_reg` test case hints at how function calls are handled (moving arguments to registers before the call).
    * **Pages:** The `ldr_in_large_block` test touches upon memory management concepts like page allocation.

6. **Analyze Logic and Examples:** Look at specific test cases to understand the logic:

    * **`cbz_reg_label`:** This tests conditional branching based on a register's value being zero. It demonstrates how labels are used to represent jump targets and how the writer calculates the branch offset.
    * **`b_imm`:** This tests direct branching to an immediate address, highlighting the limitations on the branch offset.
    * **`ldr_x_address`:** This shows how to load a 64-bit value from a constant address into a register.
    * **`call_reg`:**  Illustrates setting up arguments in registers before calling a function pointer.

7. **Consider Potential Errors:** Think about common mistakes when using such an API:

    * **Incorrect Register Usage:** Using the wrong register for an operation.
    * **Invalid Immediate Values:** Providing immediate values that are out of the allowed range for an instruction.
    * **Branching Too Far:** Trying to branch to an address that is outside the reach of a direct branch instruction.
    * **Incorrect Instruction Sequencing:** Placing instructions in an order that doesn't achieve the desired outcome.
    * **Memory Alignment Issues:** Though not explicitly shown, misaligned memory access is a common issue in low-level programming.

8. **Trace User Interaction:** How does someone end up using this code?

    * **Frida Scripting (JavaScript/Python):**  A user writes a Frida script to instrument an application.
    * **Gum API:** The script uses Frida's Gum API, which is the underlying engine.
    * **`Interceptor` or `Stalker`:**  Commonly, users employ `Interceptor` to hook functions or `Stalker` to trace execution.
    * **Code Generation:**  When a hook is placed, Frida needs to generate code to be executed before, after, or instead of the original function. This is where `GumArm64Writer` comes in. The API calls from the scripting level translate into calls to the `gum_arm64_writer_put_*` functions.
    * **Internal Frida Mechanics:**  The user doesn't directly call these C functions, but their actions in the scripting language trigger Frida's internal mechanisms that utilize this code.

9. **Refine and Organize:** Finally, organize the information into clear categories as requested by the prompt (functionality, reverse engineering relevance, low-level details, logic, errors, user interaction). Use specific examples from the code to illustrate each point. This structured approach ensures all aspects of the prompt are addressed thoroughly.
这个C文件 `arm64writer.c` 是 Frida (一个动态 instrumentation 工具) 中用于生成 ARM64 汇编指令的核心组件的测试代码。它并不直接提供 Frida 的全部功能，而是专注于测试 `GumArm64Writer` 结构体的各种方法，这些方法用于将高级操作转化为实际的 ARM64 机器码。

以下是它的功能列表和相关说明：

**主要功能:**

1. **ARM64 指令生成 (Instruction Emission):**  这个文件中的测试用例主要验证了 `GumArm64Writer` 结构体提供的各种 `gum_arm64_writer_put_*` 函数的功能。这些函数对应于不同的 ARM64 汇编指令，例如：
    *   **条件分支:** `cbz` (Compare Branch if Zero), `tbnz` (Test bit and Branch if Non-Zero)
    *   **无条件分支:** `b` (Branch), `bl` (Branch with Link), `br` (Branch to Register), `blr` (Branch with Link to Register), `ret` (Return)
    *   **栈操作:** `push` (Push registers), `pop` (Pop registers)
    *   **加载/存储:** `ldr` (Load Register), `str` (Store Register), `ldrsw` (Load Register Signed Word)
    *   **数据移动:** `mov` (Move register), `uxtw` (Unsigned Extend Word)
    *   **算术运算:** `add` (Add), `sub` (Subtract)
    *   **逻辑运算:** `and` (AND), `eor` (Exclusive OR)
    *   **比较:** `tst` (Test bits), `cmp` (Compare)
    *   **函数调用:** `call_reg` (通过寄存器调用函数)
    *   **特殊指令:** `nop` (No Operation), `brk` (Breakpoint)

2. **测试框架 (Testing Framework):**  这个文件使用了自定义的测试框架 (`TESTLIST_BEGIN`, `TESTENTRY`, `TESTCASE`, `assert_output_n_equals`) 来验证指令生成函数的正确性。每个 `TESTCASE` 函数都针对一个或多个 `gum_arm64_writer_put_*` 函数进行测试，并断言生成的机器码是否符合预期。

**与逆向方法的关系及举例说明:**

这个文件与逆向工程的方法紧密相关，因为它提供了在运行时动态生成和修改目标进程指令的能力，这是动态 instrumentation 的核心。

*   **代码注入 (Code Injection):** Frida 经常需要将自定义的代码注入到目标进程中。`GumArm64Writer` 提供的功能正是用于构建这些注入代码的机器码。例如，在 hook 一个函数时，Frida 可以使用 `gum_arm64_writer_put_bl_imm` 或 `gum_arm64_writer_put_blr_reg` 生成跳转指令，将执行流程重定向到 Frida 的 hook 处理函数。
    *   **例子:**  如果你想在函数 `foo` 的开头插入一段代码，你可以使用 Frida 的 JavaScript API 来完成，而 Frida 内部会使用 `GumArm64Writer` 生成一个 `bl` 指令跳转到你的代码，然后再从你的代码跳回 `foo`。

*   **Hooking 函数 (Function Hooking):**  通过修改目标函数的入口指令，可以将程序执行流程导向 Frida 的 handler。`GumArm64Writer` 可以生成修改入口指令所需的跳转指令。
    *   **例子:**  `TESTCASE(bl_label)` 和 `TESTCASE(bl_imm)` 展示了如何生成 `bl` 指令，这在函数 hook 中至关重要。你可以用生成的 `bl` 指令覆盖目标函数的开头，使其跳转到你的 hook 函数。

*   **运行时代码修改 (Runtime Code Modification):**  在某些情况下，逆向工程师可能需要在运行时修改目标进程的现有指令。`GumArm64Writer` 提供了生成各种指令的能力，可以用于替换或修改目标代码。
    *   **例子:**  如果你想跳过某个条件判断，可以使用 `gum_arm64_writer_put_b_imm` 生成一个无条件跳转指令，直接跳过该判断。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明:**

这个文件直接操作 ARM64 汇编指令，因此涉及大量的底层知识。

*   **ARM64 指令集架构 (ISA):** 文件中的每一个 `gum_arm64_writer_put_*` 函数都对应着 ARM64 指令集中的一个或多个指令。理解 ARM64 指令的编码格式、操作数类型、寻址模式等是使用这个组件的基础。
    *   **例子:**  `TESTCASE(cbz_reg_label)` 测试了 `cbz` 指令，它需要一个寄存器和一个标签作为参数。理解 `cbz` 指令的编码格式，如何将标签转化为相对于当前指令的偏移量是关键。

*   **寄存器 (Registers):** 代码中大量使用了 `ARM64_REG_*` 枚举，代表 ARM64 架构中的各种通用寄存器（X0-X30, SP, PC, etc.）和浮点寄存器（S/D/Q 寄存器）。了解不同寄存器的用途和调用约定是必要的。
    *   **例子:** `TESTCASE(call_reg)` 展示了如何在调用函数前将参数放入指定的寄存器（如 X0, X1 等），这符合 ARM64 的函数调用约定 (AAPCS64)。

*   **内存寻址模式 (Memory Addressing Modes):**  `ldr` 和 `str` 指令支持多种寻址模式。例如，基于寄存器偏移、预/后索引等。`GumArm64Writer` 提供了相应的函数来生成这些指令。
    *   **例子:** `TESTCASE(ldr_integer_reg_reg_imm_mode)` 测试了带有不同索引模式的 `ldr` 指令，例如 `GUM_INDEX_POST_ADJUST` 和 `GUM_INDEX_PRE_ADJUST`。

*   **二进制编码 (Binary Encoding):**  `assert_output_n_equals` 函数断言生成的字节序列与预期的机器码完全一致。这要求对 ARM64 指令的二进制编码有深入的理解。
    *   **例子:** `assert_output_n_equals (0, 0x34000105);` 验证了 `cbz w5, beach` 指令被正确编码为 `0x34000105`。

*   **Linux/Android 用户空间和内核交互 (间接):**  虽然这个文件本身是在用户空间运行的 Frida 组件的一部分，但它生成的代码最终会在目标进程的上下文中执行，可能涉及到系统调用、内存管理等与内核交互的操作。
    *   **例子:** 当 Frida 注入代码并执行时，如果注入的代码尝试访问内存或执行其他特权操作，最终会触发系统调用，与 Linux 或 Android 内核进行交互。

*   **进程内存管理 (Process Memory Management):**  `TESTCASE(ldr_in_large_block)` 涉及到分配和管理大块内存 (`gum_alloc_n_pages`, `gum_free_pages`)，这与操作系统提供的内存管理机制有关。

**逻辑推理、假设输入与输出:**

每个 `TESTCASE` 都包含了逻辑推理，即给定一组 `gum_arm64_writer_put_*` 函数的调用，预期会生成特定的机器码。

*   **假设输入:** `gum_arm64_writer_put_cbz_reg_label (&fixture->aw, ARM64_REG_W5, beach_lbl);`
*   **逻辑推理:**  当寄存器 `W5` 的值为零时，程序应该跳转到标签 `beach_lbl` 所在的位置。生成的机器码需要包含正确的条件码和跳转偏移量。
*   **预期输出:** `assert_output_n_equals (0, 0x34000105);`  (具体的机器码会根据标签 `beach_lbl` 的相对位置而变化)

*   **假设输入:** `gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_X3, ARM64_REG_X5, 7);`
*   **逻辑推理:**  将寄存器 `X5` 的值加上立即数 `7`，结果存入寄存器 `X3`。需要生成对应的 `add` 指令。
*   **预期输出:** `assert_output_n_equals (0, 0x91001ca3);`

**用户或编程常见的使用错误及举例说明:**

虽然这个文件是 Frida 内部的测试代码，普通用户不会直接编写这样的 C 代码，但理解这些测试可以帮助理解 Frida API 的使用限制和潜在错误。

*   **分支超出范围:**  ARM64 的条件分支指令 (`cbz`, `tbnz`) 和短跳转指令 (`b`) 有一定的跳转范围限制。如果目标地址距离当前指令太远，直接使用这些指令会出错。`TESTCASE(b_imm)` 验证了 `gum_arm64_writer_can_branch_directly_between` 函数，该函数用于检查分支是否在有效范围内。
    *   **错误示例 (假设 Frida API 直接暴露了这些底层函数):**  用户尝试使用 `gum_arm64_writer_put_b_imm` 跳转到一个非常远的地址，但该地址超出了 `b` 指令的 +/- 128MB 范围。Frida 内部会处理这种情况，可能会使用更长的跳转序列，但如果用户直接使用底层 API，可能会生成无效的指令。

*   **寄存器类型不匹配:**  某些指令只能操作特定大小的寄存器（如 `w` 表示 32 位，`x` 表示 64 位）。如果使用了错误的寄存器类型，生成的指令可能无效或行为不符合预期。
    *   **错误示例 (假设 Frida API 直接暴露了这些底层函数):**  用户尝试使用 `gum_arm64_writer_put_add_reg_reg_imm` 将一个 64 位寄存器和一个 32 位寄存器相加，这在某些情况下是不允许的或者需要显式转换。

*   **立即数超出范围:**  不同的 ARM64 指令对立即数的大小有不同的限制。如果提供的立即数超出了指令所能编码的范围，会导致指令编码失败。
    *   **错误示例 (假设 Frida API 直接暴露了这些底层函数):**  用户尝试使用 `gum_arm64_writer_put_add_reg_reg_imm` 时提供了一个过大的立即数，超过了该指令允许的最大值。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为普通 Frida 用户，你通常不会直接接触到这个 C 文件。你与 Frida 的交互通常是通过 JavaScript 或 Python API 进行的。但是，当你使用这些高级 API 时，Frida 内部会调用底层的 C 代码，包括这个 `arm64writer.c` 文件中定义的功能。以下是一个可能的流程：

1. **编写 Frida 脚本:**  用户编写一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来 hook 目标进程中的某个函数。例如：

    ```javascript
    Interceptor.attach(Module.findExportByName("libTarget.so", "targetFunction"), {
      onEnter: function(args) {
        console.log("Entered targetFunction");
      }
    });
    ```

2. **Frida 处理脚本:**  Frida 的 JavaScript 引擎或 Python 绑定会解析这个脚本。

3. **调用 Gum API:**  `Interceptor.attach` 方法最终会调用 Frida 的 Gum 引擎提供的 C API。

4. **分配内存:**  Gum 引擎会在目标进程中分配一块可执行的内存区域，用于存放 hook 代码。

5. **生成 hook 代码:**  Gum 引擎会根据用户的 hook 设置，使用 `GumArm64Writer` 提供的函数来生成 ARM64 汇编指令。例如，要实现 `onEnter` hook，Frida 需要生成以下指令：
    *   保存现场 (push 寄存器)
    *   调用用户提供的 JavaScript `onEnter` 函数的逻辑 (可能涉及函数调用，参数传递等)
    *   恢复现场 (pop 寄存器)
    *   跳转回原始目标函数

6. **写入目标进程:**  生成的机器码会被写入到目标进程分配的内存中，并修改目标函数的入口指令，使其跳转到 Frida 的 hook 代码。  `GumArm64Writer` 生成的指令最终会通过内存写入操作应用到目标进程。

7. **执行 hook 代码:**  当目标进程执行到被 hook 的函数时，会先执行 Frida 注入的 hook 代码。

**作为调试线索:**

如果在使用 Frida 时遇到问题，例如 hook 没有生效，或者程序崩溃，理解 `arm64writer.c` 的功能可以帮助你进行更深入的调试：

*   **检查生成的指令:**  Frida 提供了一些方法来查看它生成的机器码。如果你怀疑生成的指令有问题，可以查看 Frida 的日志或使用调试工具来检查实际写入到目标进程的指令，并与 `arm64writer.c` 中的测试用例进行对比，看是否符合预期。

*   **理解指令的限制:**  如果你尝试进行一些复杂的 hook 操作，例如在非常远的地址之间跳转，了解 `arm64writer.c` 中关于分支范围的测试可以帮助你理解 Frida 可能的限制，并思考是否有其他方法实现你的目标。

*   **排查底层错误:**  如果 Frida 报告了一些底层的错误，例如内存写入失败，或者执行了无效指令，理解 `arm64writer.c` 中涉及的内存操作和指令生成过程可以帮助你缩小问题范围，例如检查目标进程的内存保护设置，或者检查生成的指令是否真的无效。

总而言之，`arm64writer.c` 虽然是 Frida 的内部测试代码，但它展示了 Frida 如何在底层生成 ARM64 机器码来实现动态 instrumentation 的功能。理解它的功能可以帮助逆向工程师更好地理解 Frida 的工作原理，并更有效地使用 Frida 进行调试和分析。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm64/arm64writer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2014-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64writer-fixture.c"

TESTLIST_BEGIN (arm64writer)
  TESTENTRY (cbz_reg_label)
  TESTENTRY (tbnz_reg_imm_imm)

  TESTENTRY (b_imm)
  TESTENTRY (b_label)
  TESTENTRY (bl_imm)
  TESTENTRY (bl_label)
  TESTENTRY (br_reg)
  TESTENTRY (blr_reg)
  TESTENTRY (ret)

  TESTENTRY (push_reg_reg)
  TESTENTRY (pop_reg_reg)
  TESTENTRY (ldr_x_address)
  TESTENTRY (ldr_d_address)
#ifdef HAVE_ARM64
  TESTENTRY (ldr_in_large_block)
#endif
  TESTENTRY (ldr_integer_reg_reg_imm)
  TESTENTRY (ldr_integer_reg_reg_imm_mode)
  TESTENTRY (ldr_fp_reg_reg_imm)
  TESTENTRY (ldrsw_reg_reg_imm)
  TESTENTRY (str_integer_reg_reg_imm)
  TESTENTRY (str_integer_reg_reg_imm_mode)
  TESTENTRY (str_fp_reg_reg_imm)
  TESTENTRY (mov_reg_reg)
  TESTENTRY (uxtw_reg_reg)
  TESTENTRY (add_reg_reg_imm)
  TESTENTRY (sub_reg_reg_imm)
  TESTENTRY (sub_reg_reg_reg)
  TESTENTRY (and_reg_reg_imm)
  TESTENTRY (and_reg_reg_neg_imm)
  TESTENTRY (eor_reg_reg_reg)
  TESTENTRY (tst_reg_imm)
  TESTENTRY (cmp_reg_reg)

  TESTENTRY (call_reg)
TESTLIST_END ()

#ifdef HAVE_ARM64
static void gum_emit_ldr_in_large_block (gpointer mem, gpointer user_data);
#endif

TESTCASE (call_reg)
{
  gum_arm64_writer_put_call_reg_with_arguments (&fixture->aw, ARM64_REG_X3,
      2,
      GUM_ARG_REGISTER, ARM64_REG_X5,
      GUM_ARG_REGISTER, ARM64_REG_W7);
  assert_output_n_equals (0, 0xd3407ce1); /* uxtw x1, w7 */
  assert_output_n_equals (1, 0xaa0503e0); /* mov x0, x5 */
  assert_output_n_equals (2, 0xd63f0060); /* blr x3 */
}

TESTCASE (cbz_reg_label)
{
  const gchar * beach_lbl = "beach";

  gum_arm64_writer_put_cbz_reg_label (&fixture->aw, ARM64_REG_W5, beach_lbl);
  gum_arm64_writer_put_cbz_reg_label (&fixture->aw, ARM64_REG_X7, beach_lbl);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 1);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 2);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 3);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 4);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 5);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 6);

  gum_arm64_writer_put_label (&fixture->aw, beach_lbl);
  gum_arm64_writer_put_nop (&fixture->aw);

  gum_arm64_writer_flush (&fixture->aw);

  assert_output_n_equals (0, 0x34000105); /* cbz w5, beach */
  assert_output_n_equals (1, 0xb40000e7); /* cbz x7, beach */
  assert_output_n_equals (2, 0xd4200020); /* brk #1 */
  assert_output_n_equals (3, 0xd4200040); /* brk #2 */
  assert_output_n_equals (4, 0xd4200060); /* brk #3 */
  assert_output_n_equals (5, 0xd4200080); /* brk #4 */
  assert_output_n_equals (6, 0xd42000a0); /* brk #5 */
  assert_output_n_equals (7, 0xd42000c0); /* brk #6 */
  /* beach: */
  assert_output_n_equals (8, 0xd503201f); /* nop */
}

TESTCASE (tbnz_reg_imm_imm)
{
  GumAddress target = GUM_ADDRESS (fixture->aw.pc + 8);

  gum_arm64_writer_put_tbnz_reg_imm_imm (&fixture->aw, ARM64_REG_X17, 0,
      target);
  assert_output_n_equals (0, 0x37000051);

  gum_arm64_writer_put_tbnz_reg_imm_imm (&fixture->aw, ARM64_REG_X17, 33,
      target);
  assert_output_n_equals (1, 0xb7080031);
}

TESTCASE (b_imm)
{
  GumArm64Writer * aw = &fixture->aw;

  GumAddress from = 1024;
  g_assert_true (gum_arm64_writer_can_branch_directly_between (aw, from,
      1024 + 134217727));
  g_assert_false (gum_arm64_writer_can_branch_directly_between (aw, from,
      1024 + 134217728));

  from = 1024 + 134217728;
  g_assert_true (gum_arm64_writer_can_branch_directly_between (aw, from,
      1024));
  g_assert_false (gum_arm64_writer_can_branch_directly_between (aw, from,
      1023));

  aw->pc = 1024;
  gum_arm64_writer_put_b_imm (aw, 2048);
  assert_output_n_equals (0, 0x14000100);
}

TESTCASE (b_label)
{
  const gchar * next_lbl = "next";

  gum_arm64_writer_put_b_label (&fixture->aw, next_lbl);
  gum_arm64_writer_put_nop (&fixture->aw);
  gum_arm64_writer_put_label (&fixture->aw, next_lbl);
  gum_arm64_writer_put_nop (&fixture->aw);

  gum_arm64_writer_flush (&fixture->aw);

  assert_output_n_equals (0, 0x14000002); /* b next */
  assert_output_n_equals (1, 0xd503201f); /* nop */
  /* next: */
  assert_output_n_equals (2, 0xd503201f); /* nop */
}

TESTCASE (bl_imm)
{
  fixture->aw.pc = 1024;
  gum_arm64_writer_put_bl_imm (&fixture->aw, 1028);
  assert_output_n_equals (0, 0x94000001);
}

TESTCASE (bl_label)
{
  const gchar * next_lbl = "next";

  gum_arm64_writer_put_bl_label (&fixture->aw, next_lbl);
  gum_arm64_writer_put_nop (&fixture->aw);
  gum_arm64_writer_put_label (&fixture->aw, next_lbl);
  gum_arm64_writer_put_nop (&fixture->aw);

  gum_arm64_writer_flush (&fixture->aw);

  assert_output_n_equals (0, 0x94000002); /* bl next */
  assert_output_n_equals (1, 0xd503201f); /* nop */
  /* next: */
  assert_output_n_equals (2, 0xd503201f); /* nop */
}

TESTCASE (br_reg)
{
  gum_arm64_writer_put_br_reg (&fixture->aw, ARM64_REG_X3);
  assert_output_n_equals (0, 0xd61f0060);
}

TESTCASE (blr_reg)
{
  gum_arm64_writer_put_blr_reg (&fixture->aw, ARM64_REG_X5);
  assert_output_n_equals (0, 0xd63f00a0);
}

TESTCASE (ret)
{
  gum_arm64_writer_put_ret (&fixture->aw);
  assert_output_n_equals (0, 0xd65f03c0);
}

TESTCASE (push_reg_reg)
{
  gum_arm64_writer_put_push_reg_reg (&fixture->aw, ARM64_REG_X3, ARM64_REG_X5);
  assert_output_n_equals (0, 0xa9bf17e3);

  gum_arm64_writer_put_push_reg_reg (&fixture->aw, ARM64_REG_W3, ARM64_REG_W5);
  assert_output_n_equals (1, 0x29bf17e3);

  gum_arm64_writer_put_push_reg_reg (&fixture->aw, ARM64_REG_Q6, ARM64_REG_Q7);
  assert_output_n_equals (2, 0xadbf1fe6);
}

TESTCASE (pop_reg_reg)
{
  gum_arm64_writer_put_pop_reg_reg (&fixture->aw, ARM64_REG_X7, ARM64_REG_X12);
  assert_output_n_equals (0, 0xa8c133e7);

  gum_arm64_writer_put_pop_reg_reg (&fixture->aw, ARM64_REG_W7, ARM64_REG_W12);
  assert_output_n_equals (1, 0x28c133e7);

  gum_arm64_writer_put_pop_reg_reg (&fixture->aw, ARM64_REG_Q6, ARM64_REG_Q7);
  assert_output_n_equals (2, 0xacc11fe6);
}

TESTCASE (ldr_x_address)
{
  gum_arm64_writer_put_ldr_reg_address (&fixture->aw, ARM64_REG_X7,
      0x123456789abcdef0);
  gum_arm64_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0x58000027);
  g_assert_cmphex (
      GUINT64_FROM_LE (*((guint64 *) (((guint8 *) fixture->output) + 4))),
      ==, 0x123456789abcdef0);
}

TESTCASE (ldr_d_address)
{
  gum_arm64_writer_put_ldr_reg_address (&fixture->aw, ARM64_REG_D1,
      0x123456789abcdef0);
  gum_arm64_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0x5c000021);
  g_assert_cmphex (
      GUINT64_FROM_LE (*((guint64 *) (((guint8 *) fixture->output) + 4))),
      ==, 0x123456789abcdef0);
}

#ifdef HAVE_ARM64

TESTCASE (ldr_in_large_block)
{
  const gsize code_size_in_pages = 512;
  gsize code_size;
  gpointer code;
  gint (* impl) (void);

  code_size = code_size_in_pages * gum_query_page_size ();
  code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  gum_memory_patch_code (code, code_size, gum_emit_ldr_in_large_block, code);

  impl = gum_sign_code_pointer (code);
  g_assert_cmpint (impl (), ==, 0x1337);

  gum_free_pages (code);
}

static void
gum_emit_ldr_in_large_block (gpointer mem,
                             gpointer user_data)
{
  gpointer code = user_data;
  GumArm64Writer aw;
  guint i;

  gum_arm64_writer_init (&aw, mem);
  aw.pc = GUM_ADDRESS (code);

  gum_arm64_writer_put_ldr_reg_address (&aw, ARM64_REG_X0, 0x1337);
  for (i = 0; i != 262142; i++)
    gum_arm64_writer_put_nop (&aw);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_clear (&aw);
}

#endif

TESTCASE (ldr_integer_reg_reg_imm)
{
  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (0, 0xf94008a3);

  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (1, 0xb94010a3);
}

TESTCASE (ldr_integer_reg_reg_imm_mode)
{
  gum_arm64_writer_put_ldr_reg_reg_offset_mode (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16, GUM_INDEX_POST_ADJUST);
  assert_output_n_equals (0, 0xf84104a3);

  gum_arm64_writer_put_ldr_reg_reg_offset_mode (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_X5, -16, GUM_INDEX_PRE_ADJUST);
  assert_output_n_equals (1, 0xb85f0ca3);
}

TESTCASE (ldr_fp_reg_reg_imm)
{
  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_S3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (0, 0xbd4010e3);

  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_D3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (1, 0xfd4008e3);

  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_Q3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (2, 0x3dc004e3);
}

TESTCASE (ldrsw_reg_reg_imm)
{
  gum_arm64_writer_put_ldrsw_reg_reg_offset (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (0, 0xb98010a3);
}

TESTCASE (str_integer_reg_reg_imm)
{
  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (0, 0xf90008a3);

  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (1, 0xb90010a3);
}

TESTCASE (str_integer_reg_reg_imm_mode)
{
  gum_arm64_writer_put_str_reg_reg_offset_mode (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16, GUM_INDEX_POST_ADJUST);
  assert_output_n_equals (0, 0xf80104a3);

  gum_arm64_writer_put_str_reg_reg_offset_mode (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_X5, -16, GUM_INDEX_PRE_ADJUST);
  assert_output_n_equals (1, 0xb81f0ca3);
}

TESTCASE (str_fp_reg_reg_imm)
{
  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_S3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (0, 0xbd0010e3);

  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_D3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (1, 0xfd0008e3);

  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_Q3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (2, 0x3d8004e3);
}

TESTCASE (mov_reg_reg)
{
  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_X3, ARM64_REG_X5);
  assert_output_n_equals (0, 0xaa0503e3);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_W3, ARM64_REG_W5);
  assert_output_n_equals (1, 0x2a0503e3);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_X7, ARM64_REG_SP);
  assert_output_n_equals (2, 0x910003e7);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_SP, ARM64_REG_X12);
  assert_output_n_equals (3, 0x9100019f);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_X7, ARM64_REG_XZR);
  assert_output_n_equals (4, 0xaa1f03e7);
}

TESTCASE (uxtw_reg_reg)
{
  gum_arm64_writer_put_uxtw_reg_reg (&fixture->aw, ARM64_REG_X3, ARM64_REG_W5);
  assert_output_n_equals (0, 0xd3407ca3);

  gum_arm64_writer_put_uxtw_reg_reg (&fixture->aw, ARM64_REG_X7, ARM64_REG_W12);
  assert_output_n_equals (1, 0xd3407d87);
}

TESTCASE (add_reg_reg_imm)
{
  gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 7);
  assert_output_n_equals (0, 0x91001ca3);

  gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_X7,
      ARM64_REG_X12, 16);
  assert_output_n_equals (1, 0x91004187);

  gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_W7,
      ARM64_REG_W12, 16);
  assert_output_n_equals (2, 0x11004187);
}

TESTCASE (sub_reg_reg_imm)
{
  gum_arm64_writer_put_sub_reg_reg_imm (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 7);
  assert_output_n_equals (0, 0xd1001ca3);

  gum_arm64_writer_put_sub_reg_reg_imm (&fixture->aw, ARM64_REG_X7,
      ARM64_REG_X12, 16);
  assert_output_n_equals (1, 0xd1004187);

  gum_arm64_writer_put_sub_reg_reg_imm (&fixture->aw, ARM64_REG_W7,
      ARM64_REG_W12, 16);
  assert_output_n_equals (2, 0x51004187);
}

TESTCASE (sub_reg_reg_reg)
{
  gum_arm64_writer_put_sub_reg_reg_reg (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, ARM64_REG_X7);
  assert_output_n_equals (0, 0xcb0700a3);
}

TESTCASE (and_reg_reg_imm)
{
  gum_arm64_writer_put_and_reg_reg_imm (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 63);
  assert_output_n_equals (0, 0x924014a3);
}

TESTCASE (and_reg_reg_neg_imm)
{
  gum_arm64_writer_put_and_reg_reg_imm (&fixture->aw, ARM64_REG_X0,
      ARM64_REG_X0, (guint64) -0x10);
  assert_output_n_equals (0, 0x927cec00);
}

TESTCASE (eor_reg_reg_reg)
{
  gum_arm64_writer_put_eor_reg_reg_reg (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, ARM64_REG_X7);
  assert_output_n_equals (0, 0xca0700a3);

  gum_arm64_writer_put_eor_reg_reg_reg (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_W5, ARM64_REG_W7);
  assert_output_n_equals (1, 0x4a0700a3);
}

TESTCASE (tst_reg_imm)
{
  gum_arm64_writer_put_tst_reg_imm (&fixture->aw, ARM64_REG_X3, 16383);
  assert_output_n_equals (0, 0xf240347f);

  gum_arm64_writer_put_tst_reg_imm (&fixture->aw, ARM64_REG_W7, 31);
  assert_output_n_equals (1, 0x720010ff);
}

TESTCASE (cmp_reg_reg)
{
  gum_arm64_writer_put_cmp_reg_reg (&fixture->aw, ARM64_REG_X3, ARM64_REG_X5);
  assert_output_n_equals (0, 0xeb05007f);
}
```