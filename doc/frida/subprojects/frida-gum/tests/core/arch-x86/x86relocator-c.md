Response:
Let's break down the thought process for analyzing this C code for the `x86relocator.c` file.

**1. Initial Understanding - The Big Picture:**

The filename `x86relocator.c` immediately suggests this code deals with the relocation of x86 instructions. The inclusion of `frida` in the path points to a dynamic instrumentation context. So, the core idea is likely about modifying x86 code at runtime. The presence of `TESTLIST_BEGIN` and `TESTCASE` strongly indicates this is a test suite.

**2. Dissecting the Test Structure:**

The `TESTLIST_BEGIN` and `TESTENTRY` macros define a series of test cases. Each `TESTENTRY` maps to a `TESTCASE` function. This is a common pattern for unit testing. By looking at the `TESTENTRY` names (e.g., `one_to_one`, `call_near_relative`, `jmp_short_outside_block`), we can infer the specific x86 instruction types or scenarios being tested. This gives us a high-level understanding of the functionalities being verified.

**3. Analyzing Individual Test Cases (Iterative Process):**

For each `TESTCASE`, the process involves:

* **Input Definition:**  Look for `guint8 input[] = { ... };`. This defines the raw byte sequence representing the x86 instructions to be relocated.

* **Setup:**  The `SETUP_RELOCATOR_WITH(input)` macro is key. It likely initializes the `gum_x86_relocator` with the input bytecode. We don't have the macro definition here, but its name suggests its purpose.

* **Reading Instructions:**  Functions like `gum_x86_relocator_read_one(&fixture->rl, &insn)` are used to parse and decode the input instructions. The `&insn` part suggests it's storing the decoded instruction information.

* **Writing Instructions:**  Functions like `gum_x86_relocator_write_one(&fixture->rl)` and `gum_x86_relocator_write_all(&fixture->rl)` are responsible for writing the potentially relocated instructions to an output buffer.

* **Assertions:**  `g_assert_cmp...` functions are used to verify the correctness of the relocation. This includes checking:
    * The number of bytes read (`gum_x86_relocator_read_one` return value).
    * The decoded instruction type (`insn->id`).
    * The content of the output buffer using `memcmp`.
    * The offset in the output buffer (`gum_x86_writer_offset`).
    * The relocated jump/call distances.

* **Expected Output (Sometimes):** Some test cases have `guint8 expected_output[] = { ... };`. This explicitly defines the expected byte sequence after relocation, allowing for direct comparison.

**4. Identifying Key Functionalities and Concepts:**

By examining the test cases, we can list the core functionalities of the `x86relocator`:

* **Basic Instruction Relocation:**  `one_to_one` shows the simplest case of copying instructions.
* **Relocating Near Calls:** `call_near_relative` and `call_near_relative_to_next_instruction` demonstrate how relative call offsets are adjusted when the code is moved.
* **Handling PC-Relative Addressing (GOT):** `call_near_gnu_get_pc_thunk` and `call_near_android_get_pc_thunk` (on 32-bit) show how calls to get the program counter (often used with Global Offset Tables) are handled.
* **Indirect Calls/Jumps:** `call_near_indirect`, `jmp_indirect`, and `jmp_register` illustrate how control flow instructions that depend on register or memory values are treated (usually copied verbatim as their target is dynamic).
* **Short and Near Jumps:** `jmp_short_outside_block` and `jmp_near_outside_block` show the relocation of jump instructions with short and near relative offsets, especially when jumping outside the current code block.
* **Conditional Jumps:** `jcc_short_within_block`, `jcc_short_outside_block`, and `jcc_near_outside_block` demonstrate the relocation of conditional jumps, again considering cases within and outside the current block.
* **`jcxz` Relocation:**  `jcxz_short_within_block` and `jcxz_short_outside_block` focus on the relocation of the `jcxz` (jump if cx/ecx is zero) instruction.
* **RIP-Relative Addressing (64-bit):**  The tests starting with `rip_relative_` (only for 64-bit) are crucial for handling addressing relative to the instruction pointer, a common feature in 64-bit code. These tests cover moves, pushes, `cmpxchg`, and calls using RIP-relative addressing.
* **Edge Cases:** Tests like `eob_and_eoi_on_jmp`, `eob_but_not_eoi_on_call`, etc., are essential for verifying the correct handling of "end of block" and "end of input" conditions.
* **Peeking and Skipping Instructions:** `peek_next_write` and `skip_instruction` show functionalities for inspecting the next instruction to be written and for skipping instructions during relocation.

**5. Connecting to Reverse Engineering and Low-Level Concepts:**

As the analysis progresses, connections to reverse engineering and low-level concepts become clear:

* **Code Injection/Modification:** The core purpose of a relocator aligns directly with code injection and dynamic modification, fundamental techniques in reverse engineering, malware analysis, and dynamic instrumentation.
* **Instruction Set Architecture (ISA):**  Understanding x86 instruction formats, addressing modes (relative, register-based, immediate), and opcode encodings is essential for writing a relocator.
* **Control Flow Analysis:**  Relocating jump and call instructions requires careful analysis of control flow to update target addresses correctly.
* **Position Independent Code (PIC):**  The tests involving `gnu_get_pc_thunk` and `android_get_pc_thunk` touch upon concepts related to PIC, where code needs to work correctly regardless of its load address.
* **Memory Management:**  The relocator needs to manage the input and output buffers effectively.
* **Operating System and Kernel Concepts:**  While not explicitly testing kernel code, the relocator's ability to modify code can be used to hook system calls or modify kernel behavior. On Android, modifying framework code is a common use case for tools like Frida.
* **Binary Formats (ELF, Mach-O, PE):**  Understanding how code is laid out in executable files is helpful in understanding the context of relocation.

**6. Inferring Usage and Potential Errors:**

By considering how this relocator might be used, we can infer potential user errors:

* **Incorrect Input:** Providing malformed or incomplete x86 bytecode as input.
* **Insufficient Output Buffer:**  Not allocating enough space for the relocated code (which might be larger due to added instructions).
* **Relocating Across Architectures:** Attempting to relocate code for a different CPU architecture.
* **Assumptions about Code Layout:** Making incorrect assumptions about the relative positions of code blocks.

**7. Debugging Perspective:**

Thinking about debugging involves understanding how a developer might reach this code:

* **Developing Frida Gadgets/Scripts:** A user might be writing a Frida script that injects or modifies code. If the injected code contains relative jumps or calls, the relocator would be involved.
* **Developing Frida Itself:**  A Frida developer might be working on the core instrumentation engine, encountering issues with code relocation.
* **Analyzing Crashes:**  If an injected snippet crashes, examining the relocated code and the relocator's behavior could be part of the debugging process.

By following these steps – understanding the purpose, dissecting the code structure, analyzing individual tests, identifying key concepts, and considering usage and debugging – we can effectively analyze the functionality and implications of the `x86relocator.c` file.
这个文件 `x86relocator.c` 是 Frida dynamic instrumentation 工具中，用于 x86 架构代码重定位功能的测试代码。它并不直接实现代码重定位的逻辑，而是通过一系列的单元测试来验证 `gum_x86_relocator` 模块的功能是否正确。

下面我们根据你的要求，来详细列举其功能和涉及的知识点：

**1. 功能列举:**

这个文件的主要功能是：

* **测试 x86 指令的逐条读取 (`gum_x86_relocator_read_one`)：**  测试能否正确识别和读取不同长度和类型的 x86 指令。
* **测试 x86 指令的逐条写入 (`gum_x86_relocator_write_one`)：** 测试能否将读取的指令原样或修改后写入到目标缓冲区。
* **测试 x86 指令的批量写入 (`gum_x86_relocator_write_all`)：** 测试能否一次性写入多个指令。
* **测试近调用重定位 (`call_near_relative`, `call_near_relative_to_next_instruction`)：**  测试当包含 `call` 指令的代码被移动时，能否正确调整相对偏移量，使其仍然指向目标地址。包括针对 `call` 指向下一条指令的特殊情况。
* **测试获取程序计数器（PC）相关的调用 (`call_near_gnu_get_pc_thunk`, `call_near_android_get_pc_thunk`)：**  在 32 位环境下，测试对用于获取当前指令地址的特殊 `call` 模式的处理，例如 GNU 和 Android 编译器的常见模式。
* **测试间接调用 (`call_near_indirect`)：** 测试对通过内存地址进行调用的指令的处理。
* **测试短跳转和近跳转的重定位 (`jmp_short_outside_block`, `jmp_near_outside_block`)：** 测试当包含短跳转或近跳转指令的代码被移动时，能否正确调整跳转目标的相对偏移量。
* **测试寄存器跳转和间接跳转 (`jmp_register`, `jmp_indirect`)：** 测试对通过寄存器或内存地址进行跳转的指令的处理。
* **测试条件跳转的重定位 (`jcc_short_within_block`, `jcc_short_outside_block`, `jcc_near_outside_block`)：** 测试当包含条件跳转指令的代码被移动时，能否正确调整跳转目标的相对偏移量。包括跳转目标在代码块内部和外部的情况。
* **测试 `jcxz` 指令的重定位 (`jcxz_short_within_block`, `jcxz_short_outside_block`)：** 测试对 `jcxz` 指令（根据 CX/ECX 寄存器为零跳转）的重定位。
* **测试窥视下一个可写入的指令 (`peek_next_write`)：** 测试在不实际写入的情况下，能否预览下一个待写入的指令。
* **测试跳过指令 (`skip_instruction`)：** 测试能否在重定位过程中跳过某些指令。
* **测试指令边界 (`eob_and_eoi_on_jmp`, `eob_but_not_eoi_on_call`, `eob_and_eoi_on_ret`, `eob_but_not_eoi_on_jcc`, `eob_but_not_eoi_on_jcxz`)：** 测试能否正确识别指令块的结束 (`eob`) 和输入的结束 (`eoi`)，对于不同类型的控制流指令（跳转、调用、返回）。
* **测试 RIP 相对寻址的重定位 (仅限 64 位) (`rip_relative_move_different_target`, `rip_relative_move_same_target`, `rip_relative_push`, `rip_relative_push_red_zone`, `rip_relative_cmpxchg`, `rip_relative_call`, `rip_relative_adjust_offset`)：** 测试在 64 位架构下，对使用 RIP 相对寻址的指令的重定位，包括 `mov`、`push`、`cmpxchg` 和 `call` 等指令，以及在不同目标地址和红区情况下的处理。

**2. 与逆向方法的关系举例说明:**

这个文件直接测试了 Frida 代码重定位的核心功能，而代码重定位是动态 instrumentation 和逆向工程中非常重要的技术。

**举例说明:**

* **代码注入 (Code Injection):**  逆向工程师常常需要将自己的代码注入到目标进程中。注入的代码可能包含相对跳转或调用指令。Frida 使用 `x86relocator` 确保注入的代码在新的内存地址上仍然可以正确执行，即调整这些相对偏移量。例如，如果注入的代码包含 `call $+5` (调用当前指令后 5 字节的位置)，在新的地址上，这个偏移量需要相应调整。 `call_near_relative` 等测试用例就模拟了这种情况。
* **Hooking 函数 (Function Hooking):** Frida 可以拦截目标进程的函数调用。Hooking 的实现常常需要在目标函数的开头插入跳转指令，跳转到 Hook 函数。`jmp_short_outside_block` 和 `jmp_near_outside_block` 的测试保证了这种跳转在目标函数被加载到不同地址时仍然有效。
* **代码修改 (Code Modification):** 逆向工程师可能需要修改目标进程的现有代码，例如修改条件跳转指令的跳转方向。在修改后，可能需要移动修改后的代码块，这时就需要重定位来保证代码的正确性。
* **动态分析 (Dynamic Analysis):** Frida 用于动态分析程序的行为。在分析过程中，可能需要在运行时修改代码以插入探针或改变程序流程。`x86relocator` 保证了这些动态修改后的代码能够正常运行。

**3. 涉及的二进制底层、Linux、Android 内核及框架的知识举例说明:**

* **二进制底层知识:**
    * **x86 指令集架构 (ISA):**  理解 x86 指令的格式、操作码、操作数、寻址模式（例如立即数寻址、寄存器寻址、内存寻址、RIP 相对寻址）是重定位的基础。每个测试用例都针对特定的 x86 指令及其编码方式。
    * **相对偏移量 (Relative Offset):**  像 `call` 和跳转指令通常使用相对于当前指令地址的偏移量来确定目标地址。重定位的核心就是正确计算和更新这些偏移量。
    * **指令长度 (Instruction Length):**  需要准确判断每条指令的长度才能正确读取和写入连续的指令序列。`gum_x86_relocator_read_one` 的返回值就是指令长度。
    * **RIP 相对寻址:**  64 位架构中常用的寻址方式，指令中包含相对于 RIP 寄存器（指令指针）的偏移量。`rip_relative_*` 系列的测试用例专门针对这种寻址方式。
* **Linux/Android 内核及框架知识:**
    * **进程内存布局:**  了解进程的内存空间组织方式，代码段、数据段、堆、栈等，有助于理解代码重定位的上下文。
    * **动态链接和加载:**  理解动态链接库的加载和重定位过程，虽然 `x86relocator` 处理的是更细粒度的代码块重定位，但概念上有相似之处。
    * **Android Framework (在 `call_near_android_get_pc_thunk` 中体现):**  Android 平台在某些情况下会使用特定的模式来获取程序计数器，这个测试用例就是针对 Android 平台的特定优化或约定。
    * **GNU C 库 (在 `call_near_gnu_get_pc_thunk` 中体现):**  类似于 Android，GNU C 库也有其特定的获取程序计数器的方式。
    * **调用约定 (Calling Convention):**  虽然这个文件没有直接测试调用约定，但重定位涉及的 `call` 指令与调用约定密切相关。
    * **红区 (Red Zone，在 `rip_relative_push_red_zone` 中体现):**  在 x64 的 Unix-like 系统上，栈顶下方存在一个 128 字节的红区，函数可以使用这个区域存储临时数据而无需调整栈指针。这个测试用例测试了在涉及 RIP 相对寻址的 `push` 指令时，如何处理红区。

**4. 逻辑推理的假设输入与输出举例:**

**测试用例:** `call_near_relative`

**假设输入 (字节码):**

```
0x55,                         // push ebp
0x8b, 0xec,                   // mov ebp, esp
0xe8, 0x04, 0x00, 0x00, 0x00, // call dummy (相对偏移 +4)
0x8b, 0xe5,                   // mov esp, ebp
0x5d,                         // pop ebp
0xc3,                         // retn
// ... 后面跟着 dummy 函数的字节码
0xc3                          // retn (dummy 函数)
```

**假设输入的起始地址:** `0x1000`

**输出 (重定位后的字节码):**

假设这段代码被移动到了 `0x2000` 的位置。`call dummy` 指令需要被重定位。

* 原始 `call dummy` 指令在 `0x1003` 处，目标地址是 `0x1003 + 5 = 0x1008` (dummy 函数的起始地址)。
* 重定位后，`call dummy` 指令位于 `0x2003` 处。
* `dummy` 函数的起始地址也需要被计算出来，它位于原始代码结束后的某个位置，例如 `0x100C`。移动后，`dummy` 函数的起始地址变为 `0x200C` (假设代码块整体平移)。
* 因此，重定位后的 `call dummy` 指令的相对偏移量需要是 `0x200C - (0x2003 + 5) = 4`。

**预期输出 (部分):**

```
// ... 前面的指令保持不变
0xe8, 0x04, 0x00, 0x00, 0x00, // call dummy (相对偏移已更新为 +4)
// ... 后面的指令也可能需要根据整体移动进行调整，但在这个测试用例中可能主要关注 call 指令
```

**5. 用户或编程常见的使用错误举例说明:**

* **错误地计算目标地址:**  如果用户在手动进行代码重定位时，错误地计算了跳转或调用指令的目标地址，会导致程序执行流程错误。例如，在 `call_near_relative` 测试中，如果计算的 `expected_distance` 不正确，说明重定位逻辑有误。
* **没有考虑指令长度的变化:** 某些重定位操作可能会导致指令长度发生变化（例如，短跳转变为长跳转）。如果用户没有考虑到这一点，可能会覆盖后续的指令。`jmp_short_outside_block` 测试就体现了这种情况。短跳转在需要跳跃较远距离时会被替换为长跳转。
* **在不应该重定位的地方进行重定位:**  例如，对数据区域的代码进行重定位是无意义且可能导致错误的。
* **没有正确处理 RIP 相对寻址 (64 位):**  在 64 位环境下，如果用户编写的 instrumentation 代码没有正确处理 RIP 相对寻址，可能会导致访问错误的内存地址。`rip_relative_*` 系列的测试用例就是为了避免这种情况。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

作为一个 Frida 的开发者或者使用者，可能会因为以下原因需要查看或调试 `x86relocator.c` 文件：

1. **开发新的 Frida 功能:**  如果正在开发涉及代码注入或修改的新功能，并且涉及到 x86 架构，那么可能会需要了解 `x86relocator` 的工作原理，甚至需要修改或扩展其功能。
2. **调试 Frida 自身的问题:**  如果在使用 Frida 进行 instrumentation 时遇到目标程序崩溃或行为异常，怀疑是代码重定位环节出现了问题，那么可能会查看这个文件来分析问题原因。
3. **为 Frida 提交 bug 报告:**  如果发现 Frida 在处理某些特定的 x86 指令时重定位不正确，可能会通过阅读源代码来定位问题，并提供更详细的 bug 报告。
4. **学习 Frida 的实现原理:**  对于对 Frida 内部实现感兴趣的开发者，阅读 `x86relocator.c` 可以深入了解其代码重定位的具体实现方式。

**调试线索 (假设用户报告了某个 x86 程序使用 Frida Hooking 后崩溃):**

1. **确定崩溃的指令地址和指令类型:** 使用调试器（例如 GDB）附加到目标进程，查看崩溃时的指令地址，并反汇编该地址的指令。
2. **分析是否是由于重定位错误导致:**  如果崩溃的指令是一个跳转或调用指令，并且目标地址看起来不合理，那么很有可能是重定位出现了问题。
3. **查看 Frida 的日志或输出:**  Frida 可能会提供一些关于代码重定位的日志信息，可以帮助定位问题。
4. **根据崩溃指令查找相关的测试用例:**  在 `x86relocator.c` 中查找与崩溃指令类型相似的测试用例，例如 `call_near_relative` 或 `jmp_short_outside_block`。
5. **运行相关的测试用例:**  尝试运行这些测试用例，看是否能够复现问题，或者加深对重定位逻辑的理解。
6. **单步调试 `gum_x86_relocator` 的代码:**  如果怀疑是 `gum_x86_relocator` 的具体实现有问题，可以使用调试器单步跟踪其代码执行流程，查看在处理特定的指令时，偏移量的计算和写入过程是否正确。
7. **修改测试用例进行验证:**  可以修改现有的测试用例，使其更接近崩溃时的场景，例如使用相同的指令序列或内存布局，然后运行测试来验证修复方案。

总而言之，`x86relocator.c` 虽然是测试代码，但它揭示了 Frida 在处理 x86 代码重定位时的各种细节和考虑，对于理解 Frida 的工作原理和调试相关问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-x86/x86relocator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2009-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "x86relocator-fixture.c"

TESTLIST_BEGIN (x86relocator)
  TESTENTRY (one_to_one)
  TESTENTRY (call_near_relative)
  TESTENTRY (call_near_relative_to_next_instruction)
#if GLIB_SIZEOF_VOID_P == 4
  TESTENTRY (call_near_gnu_get_pc_thunk)
  TESTENTRY (call_near_android_get_pc_thunk)
  TESTENTRY (call_near_indirect)
#endif
  TESTENTRY (jmp_short_outside_block)
  TESTENTRY (jmp_near_outside_block)
  TESTENTRY (jmp_register)
  TESTENTRY (jmp_indirect)
  TESTENTRY (jcc_short_within_block)
  TESTENTRY (jcc_short_outside_block)
  TESTENTRY (jcc_near_outside_block)
  TESTENTRY (jcxz_short_within_block)
  TESTENTRY (jcxz_short_outside_block)
  TESTENTRY (peek_next_write)
  TESTENTRY (skip_instruction)
  TESTENTRY (eob_and_eoi_on_jmp)
  TESTENTRY (eob_but_not_eoi_on_call)
  TESTENTRY (eob_and_eoi_on_ret)
  TESTENTRY (eob_but_not_eoi_on_jcc)
  TESTENTRY (eob_but_not_eoi_on_jcxz)

#if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (rip_relative_move_different_target)
  TESTENTRY (rip_relative_move_same_target)
  TESTENTRY (rip_relative_push)
  TESTENTRY (rip_relative_push_red_zone)
  TESTENTRY (rip_relative_cmpxchg)
  TESTENTRY (rip_relative_call)
  TESTENTRY (rip_relative_adjust_offset)
#endif
TESTLIST_END ()

TESTCASE (one_to_one)
{
  guint8 input[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, &insn), ==, 1);
  g_assert_cmpint (insn->id, ==, X86_INS_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, &insn), ==, 3);
  g_assert_cmpint (insn->id, ==, X86_INS_MOV);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_x86_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 1), ==, 0);
  assert_outbuf_still_zeroed_from_offset (1);

  g_assert_true (gum_x86_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 1, input + 1, 2), ==, 0);
  assert_outbuf_still_zeroed_from_offset (3);

  g_assert_false (gum_x86_relocator_write_one (&fixture->rl));
}

TESTCASE (call_near_relative)
{
  guint8 input[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
    0xe8, 0x04, 0x00, 0x00, 0x00, /* call dummy   */
    0x8b, 0xe5,                   /* mov esp, ebp */
    0x5d,                         /* pop ebp      */
    0xc3,                         /* retn         */

/* dummy:                                         */
    0xc3                          /* retn         */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 8);

  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpint (memcmp (fixture->output + 3, input + 3, 5), !=, 0);
  reloc_distance = *((gint32 *) (fixture->output + 4));
  expected_distance =
      ((gssize) (input + 12)) - ((gssize) (fixture->output + 8));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

TESTCASE (call_near_relative_to_next_instruction)
{
  guint8 input[] = {
    0xe8, 0x00, 0x00, 0x00, 0x00, /* call +0         */
    0x59                          /* pop xcx         */
  };
#if GLIB_SIZEOF_VOID_P == 8
  guint8 expected_output[] = {
    0x50,                         /* push rax        */
    0x48, 0xb8,                   /* mov rax, <imm>  */
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
    0x48, 0x87, 0x04, 0x24        /* xchg rax, [rsp] */
  };

  *((gpointer *) (expected_output + 3)) = input + 5;
#else
  guint8 expected_output[] = {
    0x68, 0x00, 0x00, 0x00, 0x00  /* push <imm> */
  };

  *((gpointer *) (expected_output + 1)) = input + 5;
#endif

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert_false (gum_x86_relocator_eob (&fixture->rl));
  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (expected_output));
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

#if GLIB_SIZEOF_VOID_P == 4

TESTCASE (call_near_gnu_get_pc_thunk)
{
  const guint8 input[] = {
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call +1         */

    0xcc,                         /* int 3          */
    0x8b, 0x0c, 0x24,             /* mov ecx, [esp] */
    0xc3                          /* ret            */
  };
  guint8 expected_output[] = {
    0xb9, 0x00, 0x00, 0x00, 0x00  /* mov ecx, <imm> */
  };

  *((guint32 *) (expected_output + 1)) = GPOINTER_TO_SIZE (input + 5);

  gum_x86_writer_set_target_cpu (&fixture->cw, GUM_CPU_IA32);
  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert_false (gum_x86_relocator_eob (&fixture->rl));
  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (expected_output));
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (call_near_android_get_pc_thunk)
{
  const guint8 input[] = {
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call +1         */

    0xcc,                         /* int 3          */
    0x8b, 0x1c, 0x24,             /* mov ebx, [esp] */
    0xc3                          /* ret            */
  };
  guint8 expected_output[] = {
    0xbb, 0x00, 0x00, 0x00, 0x00  /* mov ebx, <imm> */
  };

  *((guint32 *) (expected_output + 1)) = GPOINTER_TO_SIZE (input + 5);

  gum_x86_writer_set_target_cpu (&fixture->cw, GUM_CPU_IA32);
  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert_false (gum_x86_relocator_eob (&fixture->rl));
  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (expected_output));
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

#endif

TESTCASE (call_near_indirect)
{
  guint8 input[] = {
    0xff, 0x15, 0x78, 0x56, 0x34, 0x12 /* call ds:012345678h */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 6);
  gum_x86_relocator_write_one (&fixture->rl);
  g_assert_cmpint (memcmp (fixture->output, input, 6), ==, 0);
}

TESTCASE (jmp_short_outside_block)
{
  guint8 input[] = {
    0xeb, 0x01  /* jmp +1 */
  };
  const gssize input_end = GPOINTER_TO_SIZE (input) + G_N_ELEMENTS (input);
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, 5);

  g_assert_cmphex (fixture->output[0], !=, input[0]);
  g_assert_cmphex (fixture->output[0], ==, 0xe9);

  reloc_distance = *((gint32 *) (fixture->output + 1));
  expected_distance = (input_end + 1) - ((gssize) (fixture->output + 5));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

TESTCASE (jmp_near_outside_block)
{
  guint8 input[] = {
    0xe9, 0x01, 0x00, 0x00, 0x00, /* jmp +1 */
  };
  const gssize input_end = GPOINTER_TO_SIZE (input) + G_N_ELEMENTS (input);
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, sizeof (input));

  g_assert_cmphex (fixture->output[0], ==, input[0]);

  reloc_distance = *((gint32 *) (fixture->output + 1));
  expected_distance = (input_end + 1) - ((gssize) (fixture->output + 5));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

TESTCASE (jmp_register)
{
  guint8 input[] = {
    0xff, 0xe0 /* jmp eax */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, sizeof (input));
  g_assert_cmpint (memcmp (fixture->output, input, 2), ==, 0);
}

TESTCASE (jmp_indirect)
{
  guint8 input[] = {
#if GLIB_SIZEOF_VOID_P == 8
    0x48,
#endif
    0xff, 0x60, 0x08
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), == , sizeof (input));
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input)), == , 0);
}

TESTCASE (jcc_short_within_block)
{
  guint8 input[] = {
    0x31, 0xc0,                         /* xor eax,eax */
    0x81, 0xfb, 0x2a, 0x00, 0x00, 0x00, /* cmp ebx, 42 */
    0x75, 0x02,                         /* jnz beach   */
    0xff, 0xc0,                         /* inc eax     */

/* beach:                                              */
    0xc3                                /* retn        */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 10);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==,
      sizeof (input));

  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_writer_put_inc_reg (&fixture->cw, GUM_X86_EAX);
  gum_x86_relocator_write_one (&fixture->rl);

  gum_x86_writer_flush (&fixture->cw);

  /* output should have one extra instruction of 2 bytes */
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (input) + 2);

  /* the first 9 bytes should be the same */
  g_assert_cmpint (memcmp (fixture->output, input, 9), ==, 0);

  /* the jnz offset should be adjusted to account for the extra instruction */
  g_assert_cmpint ((gint8) fixture->output[9], ==, ((gint8) input[9]) + 2);

  /* the rest should be the same */
  g_assert_cmpint (memcmp (fixture->output + 10 + 2, input + 10, 3), ==, 0);
}

TESTCASE (jcc_short_outside_block)
{
  guint8 input[] = {
    0x75, 0xfd, /* jnz -3 */
    0xc3        /* retn   */
  };
  const gssize input_start = GPOINTER_TO_SIZE (input);

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, 6 + 1);
  g_assert_cmphex (fixture->output[0], ==, 0x0f);
  g_assert_cmphex (fixture->output[1], ==, 0x85);
  g_assert_cmpint (*((gint32 *) (fixture->output + 2)), ==,
      (input_start - 1) - (gssize) (fixture->output + 6));
  g_assert_cmphex (fixture->output[6], ==, input[2]);
}

TESTCASE (jcc_near_outside_block)
{
  guint8 input[] = {
    0x0f, 0x84, 0xda, 0x00, 0x00, 0x00, /* jz +218 */
    0xc3                                /* retn    */
  };
  const gssize retn_start = GPOINTER_TO_SIZE (input) + 6;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, 6 + 1);
  g_assert_cmphex (fixture->output[0], ==, 0x0f);
  g_assert_cmphex (fixture->output[1], ==, 0x84);
  g_assert_cmpint (*((gint32 *) (fixture->output + 2)), ==,
      (retn_start + 218) - (gssize) (fixture->output + 6));
  g_assert_cmphex (fixture->output[6], ==, input[6]);
}

TESTCASE (jcxz_short_within_block)
{
  guint8 input[] = {
    0xe3, 0x02,                         /* jecxz/jrcxz beach */
    0xff, 0xc0,                         /* inc eax           */

/* beach:                                                    */
    0xc3                                /* retn              */
  };
  const guint8 expected_output[] = {
    0xe3, 0x04,                         /* jecxz/jrcxz beach */
    0xff, 0xc0,                         /* inc eax           */
    0xff, 0xc0,                         /* inc eax           */

/* beach:                                                    */
    0xc3                                /* retn              */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);

  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_writer_put_inc_reg (&fixture->cw, GUM_X86_EAX);
  gum_x86_relocator_write_one (&fixture->rl);

  gum_x86_writer_flush (&fixture->cw);

  assert_output_equals (expected_output);
}

TESTCASE (jcxz_short_outside_block)
{
  guint8 input[] = {
    0xe3, 0xfd, /* jecxz/jrcxz -3      */
    0xc3        /* retn                */
  };
  const gssize retn_start = GPOINTER_TO_SIZE (input) + 2;
  guint8 expected_output[] = {
    0xe3, 0x02, /* jecxz/jrcxz is_true */
    0xeb, 0x05, /* jmp is_false        */

/* is_true:                            */
    0xe9, 0xaa, 0xaa, 0xaa, 0xaa,

/* is_false:                           */
    0xc3        /* retn                */
  };

  *((gint32 *) (expected_output + 5)) =
      (retn_start - 3) - ((gssize) (fixture->output + 9));

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);

  gum_x86_writer_flush (&fixture->cw);

  assert_output_equals (expected_output);
}

TESTCASE (peek_next_write)
{
  guint8 input[] = {
    0x31, 0xc0, /* xor eax,eax */
    0xff, 0xc0  /* inc eax     */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);

  g_assert_cmpint (gum_x86_relocator_peek_next_write_insn (&fixture->rl)->id,
      ==, X86_INS_XOR);
  gum_x86_relocator_write_one (&fixture->rl);
  g_assert_cmpint (gum_x86_relocator_peek_next_write_insn (&fixture->rl)->id,
      ==, X86_INS_INC);
  g_assert_cmpint (gum_x86_relocator_peek_next_write_insn (&fixture->rl)->id,
      ==, X86_INS_INC);
  g_assert_true (gum_x86_relocator_peek_next_write_source (&fixture->rl)
      == input + 2);
  g_assert_true (gum_x86_relocator_write_one (&fixture->rl));
  g_assert_null (gum_x86_relocator_peek_next_write_insn (&fixture->rl));
  g_assert_null (gum_x86_relocator_peek_next_write_source (&fixture->rl));
  g_assert_false (gum_x86_relocator_write_one (&fixture->rl));
}

TESTCASE (skip_instruction)
{
  guint8 input[] = {
    0x31, 0xc0,                         /* xor eax,eax */
    0x81, 0xfb, 0x2a, 0x00, 0x00, 0x00, /* cmp ebx, 42 */
    0x75, 0x02,                         /* jnz beach   */
    0xff, 0xc0,                         /* inc eax     */

/* beach:                                              */
    0xc3                                /* retn        */
  };

  SETUP_RELOCATOR_WITH (input);

  while (!gum_x86_relocator_eoi (&fixture->rl))
    gum_x86_relocator_read_one (&fixture->rl, NULL);

  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_skip_one (&fixture->rl); /* skip retn */
  gum_x86_writer_put_inc_reg (&fixture->cw, GUM_X86_EAX); /* put "inc eax"
                                                           * there instead */

  gum_x86_writer_flush (&fixture->cw);

  /* output should be of almost the same size */
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (input) + 1);

  /* the first n - 1 bytes should be the same */
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input) - 1), ==, 0);
}

TESTCASE (eob_and_eoi_on_jmp)
{
  guint8 input[] = {
    0xeb, 0x01  /* jmp +1 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert_true (gum_x86_relocator_eob (&fixture->rl));
  g_assert_true (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

TESTCASE (eob_but_not_eoi_on_call)
{
  guint8 input[] = {
    0xe8, 0x42, 0x00, 0x00, 0x00  /* call +0x42 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert_true (gum_x86_relocator_eob (&fixture->rl));
  g_assert_false (gum_x86_relocator_eoi (&fixture->rl));
}

TESTCASE (eob_and_eoi_on_ret)
{
  guint8 input[] = {
    0xc2, 0x04, 0x00  /* retn 4 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert_true (gum_x86_relocator_eob (&fixture->rl));
  g_assert_true (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

TESTCASE (eob_but_not_eoi_on_jcc)
{
  guint8 input[] = {
    0x74, 0x01, /* jz +1  */
    0xc3        /* ret    */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert_true (gum_x86_relocator_eob (&fixture->rl));
  g_assert_false (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert_true (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

TESTCASE (eob_but_not_eoi_on_jcxz)
{
  guint8 input[] = {
    0xe3, 0x01, /* jecxz/jrcxz +1 */
    0xc3        /* ret            */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert_true (gum_x86_relocator_eob (&fixture->rl));
  g_assert_false (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert_true (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

#if GLIB_SIZEOF_VOID_P == 8

TESTCASE (rip_relative_move_different_target)
{
  static guint8 input[] = {
    0x8b, 0x15, 0x01, 0x00, 0x00, 0x00, /* mov edx, [rip + 1] */
    0xc3,                               /* ret                */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x50,                               /* push rax           */
    0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, /* mov rax, <rip>     */
                0xff, 0xff, 0xff, 0xff,
    0x8b, 0x90, 0x01, 0x00, 0x00, 0x00, /* mov edx, [rax + 1] */
    0x58                                /* pop rax            */
  };

  /*
   * Since our test fixture writes our output to a stack buffer, we mark our
   * input buffer as static so that it is part of the .data section and thus
   * more than 2GB from the stack. This means we can test the cases when the
   * offset to the RIP relative instruction can't simply be modified.
   */
  g_assert (((input - expected_output) < G_MININT32) ||
      ((input - expected_output) > G_MAXINT32));

  *((gpointer *) (expected_output + 3)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

TESTCASE (rip_relative_move_same_target)
{
  static guint8 input[] = {
    0x8b, 0x05, 0x01, 0x00, 0x00, 0x00, /* mov eax, [rip + 1] */
    0xc3,                               /* ret                */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x51,                               /* push rcx           */
    0x48, 0xb9, 0xff, 0xff, 0xff, 0xff, /* mov rcx, <rip>     */
                0xff, 0xff, 0xff, 0xff,
    0x8b, 0x81, 0x01, 0x00, 0x00, 0x00, /* mov eax, [rcx + 1] */
    0x59                                /* pop rcx            */
  };

  /*
   * Since our test fixture writes our output to a stack buffer, we mark our
   * input buffer as static so that it is part of the .data section and thus
   * more than 2GB from the stack. This means we can test the cases when the
   * offset to the RIP relative instruction can't simply be modified.
   */
  g_assert (((input - expected_output) < G_MININT32) ||
      ((input - expected_output) > G_MAXINT32));

  *((gpointer *) (expected_output + 3)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

TESTCASE (rip_relative_push)
{
  static const guint8 input[] = {
    0xff, 0x35,                         /* push [rip + imm32]   */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x50,                               /* push rax  */
    0x50,                               /* push rax  */

    0x48, 0xb8,                         /* mov rax, <rip> */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x48, 0x8b, 0x80,                   /* mov rax, [rax + <imm32>] */
    0x01, 0x02, 0x03, 0x04,

    0x48, 0x89, 0x44, 0x24, 0x08,       /* mov [rsp + 8], rax */
    0x58                                /* pop rax */
  };

  /*
   * Since our test fixture writes our output to a stack buffer, we mark our
   * input buffer as static so that it is part of the .data section and thus
   * more than 2GB from the stack. This means we can test the cases when the
   * offset to the RIP relative instruction can't simply be modified.
   */
  g_assert (((input - expected_output) < G_MININT32) ||
      ((input - expected_output) > G_MAXINT32));

  *((gpointer *) (expected_output + 4)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

TESTCASE (rip_relative_push_red_zone)
{
  static const guint8 input[] = {
    0xff, 0x35,                         /* push [rip + imm32]   */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x50,                               /* push rax  */
    0x48, 0x8d, 0xa4, 0x24,             /* lea rsp, [rsp - 128] */
          0x80, 0xff, 0xff, 0xff,
    0x50,                               /* push rax  */

    0x48, 0xb8,                         /* mov rax, <rip> */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x48, 0x8b, 0x80,                   /* mov rax, [rax + <imm32>] */
    0x01, 0x02, 0x03, 0x04,

    0x48, 0x89, 0x84, 0x24,             /* mov [rsp + 8 + 128], rax */
          0x88, 0x00, 0x00, 0x00,
    0x58,                               /* pop rax */
    0x48, 0x8d, 0xa4, 0x24,             /* lea rsp, [rsp + 128] */
          0x80, 0x00, 0x00, 0x00
  };

  /*
   * Since our test fixture writes our output to a stack buffer, we mark our
   * input buffer as static so that it is part of the .data section and thus
   * more than 2GB from the stack. This means we can test the cases when the
   * offset to the RIP relative instruction can't simply be modified.
   */
  g_assert (((input - expected_output) < G_MININT32) ||
      ((input - expected_output) > G_MAXINT32));

  *((gpointer *) (expected_output + 12)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_UNIX);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

TESTCASE (rip_relative_cmpxchg)
{
  static const guint8 input[] = {
    0xf0, 0x48, 0x0f, 0xb1, 0x0d,       /* lock cmpxchg [rip + 1], rcx */
          0x01, 0x00, 0x00, 0x00
  };
  guint8 expected_output[] = {
    0x52,                               /* push rdx           */
    0x48, 0xba, 0xff, 0xff, 0xff, 0xff, /* mov rdx, <rip>     */
                0xff, 0xff, 0xff, 0xff,
    0xf0, 0x48, 0x0f, 0xb1, 0x8a,       /* lock cmpxchg [rdx + 1], rcx */
                0x01, 0x00, 0x00, 0x00,
    0x5a                                /* pop rdx            */
  };

  /*
   * Since our test fixture writes our output to a stack buffer, we mark our
   * input buffer as static so that it is part of the .data section and thus
   * more than 2GB from the stack. This means we can test the cases when the
   * offset to the RIP relative instruction can't simply be modified.
   */
  g_assert (((input - expected_output) < G_MININT32) ||
      ((input - expected_output) > G_MAXINT32));

  *((gpointer *) (expected_output + 3)) = (gpointer) (input + 9);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

TESTCASE (rip_relative_call)
{
  const guint8 input_template[] = {
    0xff, 0x15,                   /* call [rip + 0x1234] */
          0x34, 0x12, 0x00, 0x00
  };
  static guint8 input[sizeof (input_template) + 0x1234];
  guint8 expected_output[] = {
    0x50,                         /* push rax */
    0x48, 0xb8,                   /* movabs rax, <return_address> */
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
    0x48, 0x87, 0x04, 0x24,       /* xchg qword [rsp], rax */

    0x50,                         /* push rax */
    0x48, 0xb8,                   /* movabs rax, <target_address> */
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x40, 0x00,       /* mov rax, qword [rax] */
    0x48, 0x87, 0x04, 0x24,       /* xchg qword [rsp], rax */
    0xc3,                         /* ret */
    /* return_address: */
  };

  /*
   * Our input buffer must be at least 0x1234 + 6 bytes long to avoid GCC
   * warning about static array bounds checking. Since our test fixture writes
   * our output to a stack buffer, we want to mark our input buffer as static so
   * that it is part of the image and thus more than 2GB from the stack. This
   * means we can test the cases when the offset to the RIP relative
   * instruction can't simply be modified. To avoid bloating the image though,
   * we instead copy in a template so that our input buffer can be uninitialized
   * and actually reside in the .bss section.
   */
  memcpy (input, input_template, sizeof (input_template));
  g_assert (((input - expected_output) < G_MININT32) ||
      ((input - expected_output) > G_MAXINT32));

  *((gpointer *) (expected_output + 3)) =
      fixture->output + sizeof (expected_output);
  *((gpointer *) (expected_output + 18)) =
      (gpointer) (input + 6 + 0x1234);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_UNIX);
  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 6);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

TESTCASE (rip_relative_adjust_offset)
{
  guint8 input[] = {
    0x48, 0x8b, 0x05,             /* mov rax, qword ptr [rip + 0x140bc6a] */
          0x6a, 0xbc, 0x40, 0x01,
  };
  guint8 expected_output[] = {
    0x48, 0x8b, 0x05,             /* mov rax, qword ptr [rip - 0x1d98dcc] */
           0x34, 0x72, 0x26, 0xfe,
  };

  SETUP_RELOCATOR_WITH (input);
  fixture->rl.input_pc = G_GUINT64_CONSTANT (0x10007043f);
  fixture->rl.output->pc = G_GUINT64_CONSTANT (0x103214e75);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

#endif
```