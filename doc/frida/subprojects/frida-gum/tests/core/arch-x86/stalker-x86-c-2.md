Response:
The user wants to understand the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. This specific file seems to focus on testing the Stalker component on x86 architecture, specifically concerning different types of function calls and jumps.

Here's a breakdown of the thinking process to answer the user's request:

1. **Identify the core purpose:** The file name `stalker-x86.c` and the presence of `TESTCASE` macros strongly suggest this is a test suite for Frida's Stalker functionality on x86. Stalker is about tracing and instrumenting code execution.

2. **Analyze the `TESTCASE` structure:** Each `TESTCASE` represents a specific scenario being tested. The names of the test cases (`direct_call_with_immediate`, `indirect_call_with_register`, `indirect_jump_with_immediate`, etc.) are highly descriptive and provide clues about the functionality being tested.

3. **Focus on the code within each `TESTCASE`:**  Each test case sets up a small code snippet (`code` array), defines a `CallTemplate` or `JumpTemplate` structure to configure the test, and then uses the `invoke_call_from_template` or `invoke_jump` function.

4. **Understand `CallTemplate` and `JumpTemplate`:** These structs contain information about the code being tested:
    * `code_template`: The raw bytes of the x86 instruction sequence.
    * `code_size`: The size of the instruction sequence.
    * `call_site_offset` / `offset_of_target_pointer`: Where the call/jump instruction is located.
    * `target_mov_offset`, `target_address_offset`:  For indirect calls/jumps, where the target address is being loaded.
    * `target_func_offset` / `offset_of_target`: Where the actual target function/code block begins within the `code` array.
    * `target_func_immediate_fixup` / `target_immediate_fixup`:  Adjustments needed for relative addressing.
    * `instruction_count`: The expected number of instructions executed in the test.
    * `ia32_padding_instruction_count`:  Padding needed for 32-bit systems.

5. **Trace the execution flow (mentally):**  Imagine how Frida's Stalker would interact with the given code snippets. For example, in `direct_call_with_immediate`, the Stalker should detect the `call` instruction and potentially log the target address. In indirect calls, Stalker needs to resolve the target address based on register values or memory lookups.

6. **Connect to reverse engineering concepts:** The code directly deals with x86 assembly instructions, which is fundamental to reverse engineering. Understanding different call and jump types is crucial for analyzing program control flow. Dynamic analysis, which Frida facilitates, is a core reverse engineering technique.

7. **Relate to binary, Linux/Android:**
    * **Binary:** The code operates on raw byte sequences, representing machine code.
    * **Linux/Android:** The tests likely run on these platforms, and the concepts of memory protection (`gum_mprotect`), code marking (`gum_memory_mark_code`), and system calls (in other parts of Frida) are relevant. The `GLIB_SIZEOF_VOID_P` checks indicate platform-specific behavior (32-bit vs. 64-bit).

8. **Identify logic and assumptions:** The tests assume that Frida's Stalker correctly identifies and handles different call and jump instructions. The `invoke_call_from_template` and `invoke_jump` functions likely set up the Stalker and verify the expected behavior (e.g., the number of executed instructions).

9. **Look for potential errors:**  The tests themselves are designed to catch errors in Stalker's implementation. Common errors in dynamic instrumentation could involve incorrect address resolution, missing call/jump instructions, or issues with handling different operand types.

10. **Consider user interaction:**  While this specific file is a test suite, it indirectly reflects how a user would interact with Frida. A user might use Frida scripts to intercept function calls or trace code execution, and the underlying Stalker component needs to correctly handle these scenarios. A user error might be providing an incorrect address or pattern to Frida.

11. **Address the "part 3" request:** The user explicitly asked for a summary of the functionality. Based on the analysis, the main function is to test various scenarios of function calls and jumps within the Frida Stalker on the x86 architecture.

12. **Structure the answer:** Organize the findings into categories requested by the user: functionality, relation to reverse engineering, low-level details, logic, potential errors, user interaction, and a summary. Provide concrete examples from the code.
这是 `frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c` 文件的第三部分，它主要包含了一系列针对 x86 架构下 Frida Stalker 组件进行测试的用例（`TESTCASE`）。这些测试用例旨在验证 Stalker 在跟踪和分析代码执行流程时，对于不同类型的函数调用（`call`）和跳转（`jmp`）指令的处理是否正确。

**功能归纳（基于第三部分内容）：**

* **测试间接调用指令 (Indirect Calls):**  该部分着重测试各种形式的间接调用指令，包括：
    * **使用寄存器和立即数偏移的间接调用:** 测试了使用寄存器（如 `xbp`, `xax`）加上正或负的字节或双字立即数偏移来计算目标地址的 `call` 指令。
    * **使用扩展寄存器的间接调用 (64位):**  针对 64 位架构，测试了使用扩展寄存器（如 `r11`, `r10`) 和复杂偏移计算（寄存器乘以比例因子加上立即数）的间接调用。
    * **使用栈指针 (ESP) 的间接调用:** 测试了通过栈指针 `xsp` 加上立即数偏移来获取目标地址的间接调用，这通常用于调用栈上的函数指针。
* **测试直接调用指令 (Direct Calls with Register):**  测试了目标地址直接存储在寄存器中的 `call` 指令。
* **测试 `popcnt` 指令:**  测试了 `popcnt` 指令（计算二进制数中置位比特的数量）的跟踪。
* **测试间接跳转指令 (Indirect Jumps):**
    * **使用立即数地址的间接跳转:** 测试了通过内存地址存储的目标地址进行跳转的 `jmp` 指令。
    * **使用寄存器和缩放索引的间接跳转:** 测试了使用寄存器加上另一个寄存器乘以比例因子再加上立即数偏移来计算目标地址的 `jmp` 指令。
* **测试 Stalker 的行为，防止寄存器被意外修改 (No Register Clobber - 部分代码，主要在下一部分):**  虽然这部分代码主要在下一部分，但可以看到测试用例尝试在 Stalker 跟踪的代码中设置特定的寄存器值，并验证这些值在 Stalker 跟踪后是否保持不变，以此来确保 Stalker 不会意外修改寄存器的状态。
* **测试 Stalker 是否会错误地操作 "红区" (No Red Zone Clobber):**  在 64 位架构中，函数调用后栈指针下方有一小块 "红区"，Stalker 需要避免访问或修改这部分内存。这个测试用例验证了 Stalker 是否遵守这一规则。
* **测试处理大代码块的能力 (Big Block):**  测试 Stalker 处理包含大量指令的代码块的能力。

**与逆向方法的关联：**

* **动态分析:** 这些测试用例直接关联到动态分析技术。Frida Stalker 本身就是一个动态分析工具，它通过在程序运行时跟踪指令执行来帮助逆向工程师理解程序的行为。
* **指令分析:** 理解不同类型的 `call` 和 `jmp` 指令是逆向工程的基础。这些测试用例覆盖了常见的指令模式，确保 Stalker 能够准确地识别和处理它们。
* **控制流分析:** Stalker 的核心功能之一是跟踪程序的控制流。这些测试用例验证了 Stalker 在遇到各种跳转和调用指令时，能否正确地追踪程序的执行路径。
* **代码插桩:** Frida 的工作原理是在目标进程中插入代码。这些测试用例验证了 Stalker 在进行插桩后，是否仍然能够正确地跟踪原始代码的执行，并且插桩本身不会引入错误。

**举例说明:**

* **间接调用测试 (`indirect_call_with_register_and_negative_byte_immediate`):**  逆向工程师在分析一个二进制文件时，可能会遇到类似 `call [ebp-0x1c]` 的指令。理解这种间接调用的工作方式（目标地址是 `ebp` 寄存器的值减去 `0x1c`）对于理解程序如何调用函数至关重要。Frida Stalker 需要正确解析并跟踪这种调用。
* **间接跳转测试 (`indirect_jump_with_immediate_and_scaled_register`):**  在优化的代码或虚拟机中，可能会出现像 `jmp [esi + eax * 4 - 7]` 这样的复杂跳转。逆向工程师需要理解这种寻址模式来确定跳转目标。Stalker 的测试用例确保它可以处理这种复杂的寻址方式。

**涉及的二进制底层、Linux、Android 内核及框架知识：**

* **x86/x64 汇编指令集:**  所有测试用例都基于 x86/x64 汇编指令，需要理解不同 `call` 和 `jmp` 指令的编码格式和操作数。
* **寄存器:**  测试用例中使用了各种通用寄存器（如 `eax`, `ebp`, `esi`）和扩展寄存器（如 `r9`, `r11`），需要理解它们在 x86 架构中的作用。
* **内存寻址模式:**  测试用例涵盖了直接寻址、寄存器寻址、立即数寻址、基址加偏移寻址、比例变址寻址等多种 x86 的内存寻址模式。
* **栈 (Stack):**  `indirect_call_with_esp_and_byte_immediate` 等测试用例涉及栈指针 `esp/rsp`，需要理解栈的工作原理以及函数调用时栈帧的结构。
* **代码段 (Code Segment):**  Stalker 需要跟踪代码段的执行。
* **内存保护 (Memory Protection):**  `gum_mprotect` 用于修改内存页的保护属性，这涉及到操作系统底层的内存管理。
* **Linux/Android 进程内存布局:** 理解进程的内存空间如何组织，例如代码段、数据段、栈等。
* **系统调用:** 虽然这段代码本身没有直接涉及系统调用，但 Frida 作为动态分析工具，在底层会使用系统调用来实现代码注入、内存操作等功能。
* **64 位架构的特性:**  测试用例中使用了 `GLIB_SIZEOF_VOID_P == 8` 来区分 64 位架构，并测试了 64 位特有的寄存器和指令。

**逻辑推理、假设输入与输出：**

每个 `TESTCASE` 都是一个独立的逻辑单元。

**假设输入:**

* **代码 (`code` 数组):** 一段精心构造的 x86 汇编指令序列。
* **`CallTemplate` 或 `JumpTemplate` 结构:**  定义了代码的关键信息，如调用/跳转指令的位置、目标地址的偏移等。

**预期输出:**

* **Stalker 的跟踪结果:**  `test_stalker_fixture_follow_and_invoke` 函数会执行代码并使用 Stalker 进行跟踪。预期 Stalker 能够正确识别和记录执行的指令，特别是 `call` 和 `jmp` 指令的目标地址。
* **断言 (`g_assert_cmpint`, `g_assert_cmpuint`):**  测试用例会使用断言来验证 Stalker 的行为是否符合预期，例如验证函数调用的返回值、跟踪到的指令数量等。

**例如，对于 `indirect_call_with_register_and_negative_byte_immediate` 测试用例:**

* **假设输入:**
    * `code`: 包含 `mov xbp, X`, `call [xbp - 0x1c]`, `ret` 等指令的字节数组。
    * `call_template.call_site_offset = 10;` 指示 `call` 指令位于代码偏移 10 的位置。
    * `call_template.target_mov_offset = 1;` 指示设置目标地址的 `mov` 指令位于偏移 1。
    * `call_template.target_address_offset = 2;` 指示目标地址值在 `mov` 指令后的偏移 2 的位置。
    * `call_template.target_func_offset = 14;` 指示被调用函数的起始位置在代码偏移 14。
    * `call_template.target_func_immediate_fixup = 0x1c;` 指示需要修正的偏移量。
    * `call_template.instruction_count = 5;`  预期执行 5 条指令。
    * `call_template.ia32_padding_instruction_count = 5;`  32位系统需要 5 个 padding 指令。
* **预期输出:**
    * Stalker 能够识别出 `call [xbp - 0x1c]` 是一条间接调用指令。
    * Stalker 能够计算出正确的目标地址，即 `xbp` 寄存器的值减去 `0x1c`。
    * Stalker 能够跟踪到被调用函数的执行。
    * 断言会验证跟踪到的指令数量是否为预期的值。

**涉及用户或者编程常见的使用错误：**

虽然这段代码是测试代码，但可以推断出一些用户在使用 Frida Stalker 时可能遇到的错误：

* **错误的地址或偏移量:** 如果用户在使用 Frida 的 API 时，提供的内存地址或偏移量不正确，Stalker 可能无法正确跟踪代码执行。例如，如果用户尝试 hook 一个不存在的函数地址。
* **不理解间接调用/跳转:** 用户可能不清楚某些 `call` 或 `jmp` 指令的目标地址是如何计算的（例如，复杂的寻址模式），导致在使用 Frida 进行插桩或分析时出现错误。
* **假设代码是静态的:** 动态生成的代码或经过混淆的代码可能在运行时改变其结构，用户如果假设代码是静态的，可能会导致跟踪失败。
* **与 ASLR (Address Space Layout Randomization) 冲突:**  操作系统为了安全，通常会启用 ASLR，导致每次程序运行时代码的加载地址都不同。用户如果使用硬编码的地址，可能会失效。Frida 通常会处理 ASLR，但用户需要理解其影响。
* **在不安全的时间点进行操作:**  如果在 Stalker 正在跟踪的时候，用户尝试修改正在执行的代码，可能会导致不可预测的结果。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要使用 Frida 的 Stalker 功能来动态分析一个 x86 架构的程序。**
2. **用户可能会编写一个 Frida 脚本，使用 `Stalker.follow()` 方法来启动 Stalker，并配置需要跟踪的线程或进程。**
3. **在目标程序执行过程中，Stalker 会拦截代码的执行，并生成事件，例如 `call`、`ret`、`exec` 等。**
4. **如果 Stalker 在处理特定的 `call` 或 `jmp` 指令时出现问题，开发者可能会查看 Stalker 的源代码，特别是针对 x86 架构的处理逻辑。**
5. **`frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c` 文件就是 Frida 开发者用来测试 Stalker 在 x86 架构下各种场景的测试用例。**
6. **如果用户报告了与特定类型的调用或跳转相关的 bug，开发者可能会查看或添加相关的 `TESTCASE` 来重现和修复问题。**
7. **开发者可能会通过运行这些测试用例，例如 `gtester frida-gum-tests`，来验证 Stalker 的行为是否符合预期。**
8. **当调试与间接调用相关的问题时，开发者可能会特别关注 `indirect_call_with_*` 相关的测试用例，以确定 Stalker 是否正确处理了各种间接调用的情况。**

总而言之，这部分代码是 Frida Stalker 组件在 x86 架构下的一个详细的测试套件，用于确保其能够正确地跟踪和分析各种类型的函数调用和跳转指令，这对于 Frida 作为动态分析工具的可靠性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
_fixup = -0x54;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_negative_byte_immediate)
{
  const guint8 code[] = {
    0x90, 0xbd, 0x00, 0x00, 0x00, 0x00, /* mov xbp, X           */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0x55, 0xe4,                   /* call [xbp - 0x1c]    */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 14;
  call_template.target_func_immediate_fixup = 0x1c;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_positive_dword_immediate)
{
  const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0x90, 0x54, 0x00, 0x00, 0x00, /* call [xax + 0x54]    */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 17;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_negative_dword_immediate)
{
  const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0x90, 0xbe, 0xab, 0xff, 0xff, /* call [xax - 0x5442]  */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 17;
  call_template.target_func_immediate_fixup = 0x5442;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

#if GLIB_SIZEOF_VOID_P == 8

TESTCASE (indirect_call_with_extended_registers_and_immediate)
{
  const guint8 code[] = {
    0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, /* mov r11, X                   */
                0x00, 0x00, 0x00, 0x00,
    0x49, 0xba, 0x39, 0x05, 0x00, 0x00, /* mov r10, 1337                */
                0x00, 0x00, 0x00, 0x00,
    0x43, 0xff, 0x94, 0xd3,             /* call [r11 + r10*8 + 0x270e0] */
                0xe0, 0x70, 0x02, 0x00,
    0xc3,                               /* ret                          */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337                */
    0xc3,                               /* ret                          */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 20;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 29;
  call_template.target_func_immediate_fixup = -((1337 * 8) + 0x270e0);
  call_template.instruction_count = 6;

  invoke_call_from_template (fixture, &call_template);
}

#endif

TESTCASE (indirect_call_with_esp_and_byte_immediate)
{
const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X          */
                0x90, 0x90, 0x90, 0x90,
    0x50,                               /* push xax            */
    0x56,                               /* push xsi            */
    0x57,                               /* push xdi            */
    0xff, 0x54, 0x24,                   /* call [xsp + Y]      */
          2 * sizeof (gpointer),
    0x5F,                               /* pop xdi             */
    0x5E,                               /* pop xsi             */
    0x59,                               /* pop xcx             */
    0xc3,                               /* ret                 */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337       */
    0xc3,                               /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 13;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 21;
  call_template.instruction_count = 11;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_esp_and_dword_immediate)
{
  const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00,         /* mov xax, X          */
                0x90, 0x90, 0x90, 0x90,
    0x50,                                       /* push xax            */
    0x56,                                       /* push xsi            */
    0x57,                                       /* push xdi            */
    0xff, 0x94, 0x24,                           /* call [xsp + Y]      */
          2 * sizeof (gpointer), 0x00, 0x00, 0x00,
    0x5F,                                       /* pop xdi             */
    0x5E,                                       /* pop xsi             */
    0x59,                                       /* pop xcx             */
    0xc3,                                       /* ret                 */

    0xb8, 0x39, 0x05, 0x00, 0x00,               /* mov eax, 1337       */
    0xc3,                                       /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 13;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 24;
  call_template.instruction_count = 11;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (direct_call_with_register)
{
  const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X          */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0xd0,                         /* call xax             */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3                                /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 13;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

#if GLIB_SIZEOF_VOID_P == 8

TESTCASE (direct_call_with_extended_register)
{
  const guint8 code[] = {
    0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, /* mov r9, X            */
                0x00, 0x00, 0x00, 0x00,
    0x41, 0xff, 0xd1,                   /* call r9              */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 0;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 14;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 0;

  invoke_call_from_template (fixture, &call_template);
}

#endif

TESTCASE (popcnt)
{
  const guint8 code[] =
  {
    0xf3, 0x0f, 0xb8, 0xcb, /* popcnt ecx, ebx */
    0xc3,                   /* ret             */
    0xcc,                   /* int3            */
  };
  StalkerTestFunc func;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_NOTHING;
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
}

typedef struct _JumpTemplate JumpTemplate;

struct _JumpTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint offset_of_target_pointer;
  gboolean offset_of_target_pointer_points_directly;
  guint offset_of_target;
  gint target_immediate_fixup;
  guint instruction_count;
  guint ia32_padding_instruction_count;
};

static StalkerTestFunc
invoke_jump (TestStalkerFixture * fixture,
             JumpTemplate * jump_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer target_address;
  gsize target_actual_address;
  guint expected_insn_count;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture, jump_template->code_template,
      jump_template->code_size);
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  gum_mprotect (code, jump_template->code_size, GUM_PAGE_RW);

  target_address = code + jump_template->offset_of_target;
  if (jump_template->offset_of_target_pointer_points_directly)
    target_actual_address = GPOINTER_TO_SIZE (target_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_address);
  *((gsize *) (code + jump_template->offset_of_target_pointer)) =
      target_actual_address + jump_template->target_immediate_fixup;

  gum_memory_mark_code (code, jump_template->code_size);

  expected_insn_count = INVOKER_INSN_COUNT + jump_template->instruction_count;
#if GLIB_SIZEOF_VOID_P == 4
  expected_insn_count += jump_template->ia32_padding_instruction_count;
#endif

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, expected_insn_count);

  return func;
}

TESTCASE (indirect_jump_with_immediate)
{
  const guint8 code[] = {
    0xeb, 0x08,                         /* jmp +8          */

    0x00, 0x00, 0x00, 0x00,             /* address padding */
    0x00, 0x00, 0x00, 0x00,

    0xff, 0x25, 0xf2, 0xff, 0xff, 0xff, /* jmp             */
    0xcc,                               /* int3            */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
    0xc3,                               /* ret             */
  };
  JumpTemplate jump_template = { 0, };

  jump_template.code_template = code;
  jump_template.code_size = sizeof (code);
  jump_template.offset_of_target_pointer = 12;
  jump_template.offset_of_target = 17;
  jump_template.instruction_count = 4;

#if GLIB_SIZEOF_VOID_P == 8
  jump_template.offset_of_target_pointer -= 10;
  jump_template.offset_of_target_pointer_points_directly = TRUE;
#endif

  invoke_jump (fixture, &jump_template);
}

TESTCASE (indirect_jump_with_immediate_and_scaled_register)
{
  guint8 code[] = {
    0x90, 0xbe, 0x00, 0x00, 0x00, 0x00, /* mov xsi, addr           */
                0x90, 0x90, 0x90, 0x90,
    0x90, 0xb8, 0x03, 0x00, 0x00, 0x00, /* mov xax, 3              */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0x64, 0x86, 0xf9,             /* jmp [xsi + xax * 4 - 7] */
    0xcc,                               /* int3                    */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337           */
    0xc3,                               /* ret                     */
  };
  JumpTemplate jump_template = { 0, };

  jump_template.code_template = code;
  jump_template.code_size = sizeof (code);
  jump_template.offset_of_target_pointer = 2;
  jump_template.offset_of_target = 25;
  jump_template.target_immediate_fixup = -5;
  jump_template.instruction_count = 5;
  jump_template.ia32_padding_instruction_count = 10;

#if GLIB_SIZEOF_VOID_P == 8
  code[0] = 0x48;

  code[10] = 0x48;
  memset (code + 10 + 6, 0, 4);

  jump_template.ia32_padding_instruction_count = 5;
#endif

  invoke_jump (fixture, &jump_template);
}

#if GLIB_SIZEOF_VOID_P == 4

typedef void (* ClobberFunc) (GumCpuContext * ctx);

TESTCASE (no_register_clobber)
{
  guint8 * code;
  GumX86Writer cw;
  const gchar * my_func_lbl = "my_func";
  const gchar * my_beach_lbl = "my_beach";
  ClobberFunc func;
  GumCpuContext ctx;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_pushax (&cw);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->sink);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->transformer);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->stalker);
  gum_x86_writer_put_call_address (&cw, GUM_ADDRESS (gum_stalker_follow_me));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_ESP, 3 * sizeof (gpointer));
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_EAX, 0xcafebabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_ECX, 0xbeefbabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_EDX, 0xb00bbabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_EBX, 0xf001babe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_EBP, 0xababe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_ESI, 0x1337);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_X86_EDI, 0x1227);

  gum_x86_writer_put_call_near_label (&cw, my_func_lbl);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_ESP, 2 * sizeof (gpointer));
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->stalker);
  gum_x86_writer_put_call_address (&cw, GUM_ADDRESS (gum_stalker_unfollow_me));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_ESP, 3 * sizeof (gpointer));
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_push_reg (&cw, GUM_X86_ECX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_ECX,
      GUM_X86_ESP, sizeof (gpointer) + (8 * sizeof (gpointer))
      + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, eax), GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, edx), GUM_X86_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx), GUM_X86_EBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp), GUM_X86_EBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, esi), GUM_X86_ESI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, edi), GUM_X86_EDI);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_X86_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx), GUM_X86_EAX);

  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, my_func_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_jmp_short_label (&cw, my_beach_lbl);
  gum_x86_writer_put_breakpoint (&cw);

  gum_x86_writer_put_label (&cw, my_beach_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_x86_writer_offset (&cw));
  gum_x86_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (ClobberFunc, code);
  func (&ctx);

  g_assert_cmphex (ctx.eax, ==, 0xcafebabe);
  g_assert_cmphex (ctx.ecx, ==, 0xbeefbabe);
  g_assert_cmphex (ctx.edx, ==, 0xb00bbabe);
  g_assert_cmphex (ctx.ebx, ==, 0xf001babe);
  g_assert_cmphex (ctx.ebp, ==, 0xababe);
  g_assert_cmphex (ctx.esi, ==, 0x1337);
  g_assert_cmphex (ctx.edi, ==, 0x1227);

  gum_free_pages (code);
}

#endif

TESTCASE (no_red_zone_clobber)
{
  guint8 code_template[] =
  {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, <addr>    */
                0x90, 0x90, 0x90, 0x90,
    0x90, 0x89, 0x44, 0x24, 0xf8,       /* mov [rsp - 8], xax */
    0x90, 0x8b, 0x44, 0x24, 0xf8,       /* mov xax, [rsp - 8] */
    0xff, 0xe0,                         /* jmp rax            */
    0xcc,                               /* int3               */
    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov rax, 1337      */
    0xc3                                /* ret                */
  };
  guint8 * code;
  StalkerTestFunc func;
  gint ret;

#if GLIB_SIZEOF_VOID_P == 8
  code_template[0] = 0x48;
  code_template[10] = 0x48;
  code_template[15] = 0x48;
#endif

  code = test_stalker_fixture_dup_code (fixture, code_template,
      sizeof (code_template));
  gum_mprotect (code, sizeof (code_template), GUM_PAGE_RW);
  *((gpointer *) (code + 2)) = code + 23;
  gum_memory_mark_code (code, sizeof (code_template));

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  ret = func (42);
  g_assert_cmpint (ret, ==, 1337);

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
#if GLIB_SIZEOF_VOID_P == 8
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);
#else
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 13);
#endif
  g_assert_cmpint (ret, ==, 1337);
}

TESTCASE (big_block)
{
  const guint nop_instruction_count = 1000000;
  guint8 * code;
  GumX86Writer cw;
  guint i;
  StalkerTestFunc func;

  code = gum_alloc_n_pages (
      (nop_instruction_count / gum_query_page_size ()) + 1,
      GUM_PAGE_RW);
  gum_x86_writer_init (&cw, code);

  for (i = 0; i != nop_instruction_count; i++)
    gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_x86_writer_offset (&cw));

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code,
          gum_x86_writer_offset (&cw)));

  gum_x86_writer_clear (&cw);
  gum_free_pages (code);

  test_stalker_fixture_follow_and_invoke (fixture, func, -1);
}

#ifdef HAVE_WINDOWS

typedef struct _TestWindow TestWindow;

typedef void (* TestWindowMessageHandler) (TestWindow * window,
    gpointer user_data);

struct _TestWindow
{
  LPTSTR klass;
  HWND handle;
  GumStalker * stalker;

  TestWindowMessageHandler handler;
  gpointer user_data;
};

static void do_follow (TestWindow * window, gpointer user_data);
static void do_unfollow (TestWindow * window, gpointer user_data);

static TestWindow * create_test_window (GumStalker * stalker);
static void destroy_test_window (TestWindow * window);
static void send_message_and_pump_messages_briefly (TestWindow * window,
    TestWindowMessageHandler handler, gpointer user_data);

static LRESULT CALLBACK test_window_proc (HWND hwnd, UINT msg,
    WPARAM wparam, LPARAM lparam);

#if GLIB_SIZEOF_VOID_P == 4

static StalkerTestFunc
invoke_indirect_call_seg (TestStalkerFixture * fixture,
                          GumEventType mask)
{
  const guint8 code_template[] = {
    0x64, 0xff, 0x35,                   /* push dword [dword fs:0x700] */
        0x00, 0x07, 0x00, 0x00,
    0x64, 0xc7, 0x05,                   /* mov dword [dword fs:0x700], */
        0x00, 0x07, 0x00, 0x00,         /*     <addr>                  */
        0xaa, 0xbb, 0xcc, 0xdd,

    0x64, 0xff, 0x15,                   /* call fs:700h                */
        0x00, 0x07, 0x00, 0x00,

    0x50,                               /* push eax                    */
    0x8b, 0x44, 0x24, 0x04,             /* mov eax, [esp+0x4]          */
    0x64, 0xa3, 0x00, 0x07, 0x00, 0x00, /* mov [fs:0x700],eax          */
    0x58,                               /* pop eax                     */
    0x81, 0xc4, 0x04, 0x00, 0x00, 0x00, /* add esp, 0x4                */

    0xc3,                               /* ret                         */

    0xb8, 0xbe, 0xba, 0xfe, 0xca,       /* mov eax, 0xcafebabe         */
    0xc3,                               /* ret                         */
  };
  guint8 * code;
  StalkerTestFunc func;
  guint ret;

  code = test_stalker_fixture_dup_code (fixture, code_template,
      sizeof (code_template));
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  gum_mprotect (code, sizeof (code_template), GUM_PAGE_RW);
  *((gpointer *) (code + 14)) = code + sizeof (code_template) - 1 - 5;
  gum_memory_mark_code (code, sizeof (code_template));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmphex (ret, ==, 0xcafebabe);

  return func;
}

TESTCASE (win32_indirect_call_seg)
{
  invoke_indirect_call_seg (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 11);
}

#endif

TESTCASE (win32_messagebeep_api)
{
  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  MessageBeep (MB_ICONINFORMATION);
  gum_stalker_unfollow_me (fixture->stalker);
}

TESTCASE (win32_follow_user_to_kernel_to_callback)
{
  TestWindow * window;

  window = create_test_window (fixture->stalker);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  send_message_and_pump_messages_briefly (window, do_unfollow,
      fixture->stalker);
  g_assert_false (gum_stalker_is_following_me (fixture->stalker));

  destroy_test_window (window);
}

TESTCASE (win32_follow_callback_to_kernel_to_user)
{
  TestWindow * window;

  window = create_test_window (fixture->stalker);

  send_message_and_pump_messages_briefly (window, do_follow, fixture->sink);
  g_assert_true (gum_stalker_is_following_me (fixture->stalker));
  gum_stalker_unfollow_me (fixture->stalker);

  destroy_test_window (window);
}

static void
do_follow (TestWindow * window, gpointer user_data)
{
  gum_stalker_follow_me (window->stalker, NULL, GUM_EVENT_SINK (user_data));
}

static void
do_unfollow (TestWindow * window, gpointer user_data)
{
  gum_stalker_unfollow_me (window->stalker);
}

static TestWindow *
create_test_window (GumStalker * stalker)
{
  TestWindow * window;
  WNDCLASS wc = { 0, };

  window = g_slice_new (TestWindow);

  window->stalker = stalker;

  wc.lpfnWndProc = test_window_proc;
  wc.hInstance = GetModuleHandle (NULL);
  wc.lpszClassName = _T ("GumTestWindowClass");
  window->klass = (LPTSTR) GSIZE_TO_POINTER (RegisterClass (&wc));
  g_assert_nonnull (window->klass);

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4306)
#endif
  window->handle = CreateWindow (window->klass, _T ("GumTestWindow"),
      WS_CAPTION, 10, 10, 320, 240, HWND_MESSAGE, NULL,
      GetModuleHandle (NULL), NULL);
#ifdef _MSC_VER
# pragma warning (pop)
#endif
  g_assert_nonnull (window->handle);

  SetWindowLongPtr (window->handle, GWLP_USERDATA, (LONG_PTR) window);
  ShowWindow (window->handle, SW_SHOWNORMAL);

  return window;
}

static void
destroy_test_window (TestWindow * window)
{
  g_assert_true (UnregisterClass (window->klass, GetModuleHandle (NULL)));

  g_slice_free (TestWindow, window);
}

static void
send_message_and_pump_messages_briefly (TestWindow * window,
                                        TestWindowMessageHandler handler,
                                        gpointer user_data)
{
  MSG msg;

  window->handler = handler;
  window->user_data = user_data;

  SendMessage (window->handle, WM_USER, 0, 0);

  while (GetMessage (&msg, NULL, 0, 0))
  {
    TranslateMessage (&msg);
    DispatchMessage (&msg);
  }
}

static LRESULT CALLBACK
test_window_proc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  if (msg == WM_USER)
  {
    TestWindow * window;

    window = (TestWindow *) GetWindowLongPtr (hwnd, GWLP_USERDATA);
    window->handler (window, window->user_data);

    SetTimer (hwnd, 1, USER_TIMER_MINIMUM, NULL);

    return 0;
  }
  else if (msg == WM_TIMER)
  {
    KillTimer (hwnd, 1);
    DestroyWindow (hwnd);
  }
  else if (msg == WM_DESTROY)
  {
    PostQuitMessage (0);
    return 0;
  }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}

#endif

#ifdef HAVE_LINUX

TESTCASE (prefetch)
{
  GumMemoryRange runner_range;
  gint trust;
  int compile_pipes[2] = { -1, -1 };
  int execute_pipes[2] = { -1, -1 };
  GumEventSink * sink;
  GHashTable * compiled_run1;
  GHashTable * executed_run1;
  guint compiled_size_run1;
  guint executed_size_run1;
  GHashTableIter iter;
  gpointer iter_key, iter_value;
  GHashTable * compiled_run2;
  GHashTable * executed_run2;
  guint compiled_size_run2;
  guint executed_size_run2;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  /* Initialize workload parameters */
  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_cmpuint (runner_range.base_address, !=, 0);
  g_assert_cmpuint (runner_range.size, !=, 0);

  /* Initialize Stalker */
  gum_stalker_set_trust_threshold (fixture->stalker, 3);
  trust = gum_stalker_get_trust_threshold (fixture->stalker);

  /*
   * Create IPC.
   *
   * The pipes by default are 64 KB in size. At 8-bytes per-block, (the block
   * address) we thus have capacity to communicate up to 8192 blocks back to the
   * parent before the child's write() call blocks and we deadlock in waitpid().
   *
   * We can increase the size of these pipes using fcntl(F_SETPIPE_SZ), but we
   * need to be careful so we don't exceed the limit set in
   * /proc/sys/fs/pipe-max-size.
   *
   * Since our test has approx 1300 blocks, we don't need to worry about this.
   * However, production implementations may need to handle this error.
   */
  g_assert_cmpint (pipe (compile_pipes), ==, 0);
  g_assert_cmpint (pipe (execute_pipes), ==, 0);
  g_assert_true (g_unix_set_fd_nonblocking (compile_pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (compile_pipes[1], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (execute_pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (execute_pipes[1], TRUE, NULL));

  /* Configure Stalker */
  sink = gum_event_sink_make_from_callback (GUM_COMPILE | GUM_BLOCK,
      prefetch_on_event, NULL, NULL);
  gum_stalker_follow_me (fixture->stalker, NULL, sink);
  gum_stalker_deactivate (fixture->stalker);

  /* Run the child */
  prefetch_run_child (fixture->stalker, &runner_range,
      compile_pipes[STDOUT_FILENO], execute_pipes[STDOUT_FILENO]);

  /* Read the results */
  compiled_run1 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (compile_pipes[STDIN_FILENO], compiled_run1);
  executed_run1 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (execute_pipes[STDIN_FILENO], executed_run1);

  compiled_size_run1 = g_hash_table_size (compiled_run1);
  executed_size_run1 = g_hash_table_size (executed_run1);

  if (g_test_verbose ())
  {
    g_print ("\tcompiled: %d\n", compiled_size_run1);
    g_print ("\texecuted: %d\n", executed_size_run1);
  }

  g_assert_cmpuint (compiled_size_run1, >, 0);

  /* Prefetch the blocks */
  g_hash_table_iter_init (&iter, compiled_run1);
  while (g_hash_table_iter_next (&iter, &iter_key, &iter_value))
  {
    gum_stalker_prefetch (fixture->stalker, iter_key, trust);
  }

  /* Run the child again */
  prefetch_run_child (fixture->stalker, &runner_range,
      compile_pipes[STDOUT_FILENO], execute_pipes[STDOUT_FILENO]);

  /* Read the results */
  compiled_run2 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (compile_pipes[STDIN_FILENO], compiled_run2);
  executed_run2 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (execute_pipes[STDIN_FILENO], executed_run2);

  compiled_size_run2 = g_hash_table_size (compiled_run2);
  executed_size_run2 = g_hash_table_size (executed_run2);

  if (g_test_verbose ())
  {
    g_print ("\tcompiled2: %d\n", compiled_size_run2);
    g_print ("\texecuted2: %d\n", executed_size_run2);
  }

  g_assert_cmpuint (compiled_size_run2, ==, 0);

  /* Free resources */
  g_hash_table_unref (compiled_run2);
  g_hash_table_unref (executed_run2);
  g_hash_table_unref (compiled_run1);
  g_hash_table_unref (executed_run1);

  close (execute_pipes[STDIN_FILENO]);
  close (execute_pipes[STDOUT_FILENO]);
  close (compile_pipes[STDIN_FILENO]);
  close (compile_pipes[STDOUT_FILENO]);

  gum_stalker_unfollow_me (fixture->stalker);
  g_object_unref (sink);
}

static void
prefetch_on_event (const GumEvent * event,
                   GumCpuContext * cpu_context,
                   gpointer user_data)
{
  switch (event->type)
  {
    case GUM_COMPILE:
    {
      const GumCompileEvent * compile = &event->compile;

      if (prefetch_compiled != NULL)
        g_hash_table_add (prefetch_compiled, compile->start);

      break;
    }
    case GUM_BLOCK:
    {
      const GumBlockEvent * block = &event->block;

      if (prefetch_executed != NULL)
        g_hash_table_add (prefetch_executed, block->start);

      break;
    }
    default:
      break;
  }
}

static void
prefetch_run_child (GumStalker * stalker,
                    GumMemoryRange * runner_range,
                    int compile_fd,
                    int execute_fd)
{
  pid_t pid;
  int res;
  int status;

  pid = fork ();
  g_assert_cmpint (pid, >=, 0);

  if (pid == 0)
  {
    /* Child */

    prefetch_compiled = g_hash_table_new (NULL, NULL);
    prefetch_executed = g_hash_table_new (NULL, NULL);

    gum_stalker_activate (stalker, prefetch_activation_target);
    prefetch_activation_target ();
    pretend_workload (runner_range);
    gum_stalker_unfollow_me (stalker);

    prefetch_write_blocks (compile_fd, prefetch_compiled);
    prefetch_write_blocks (execute_fd, prefetch_executed);

    exit (0);
  }

  /* Wait for the child */
  res = waitpid (pid, &status, 0);
  g_assert_cmpint (res, ==, pid);
  g_assert_cmpint (WIFEXITED (status), !=, 0);
  g_assert_cmpint (WEXITSTATUS (status), ==, 0);
}

GUM_NOINLINE static void
prefetch_activation_target (void)
{
  /* Avoid calls being optimized out */
  asm ("");
}

static void
prefetch_write_blocks (int fd,
                       GHashTable * table)
{
  GHashTableIter iter;
  gpointer iter_key, iter_value;

  g_hash_table_iter_init (&iter, table);
  while (g_hash_table_iter_next (&iter, &iter_key, &iter_value))
  {
    int res = write (fd, &iter_key, sizeof (gpointer));
    g_assert_cmpint (res, ==, sizeof (gpointer));
  }
}

static void
prefetch_read_blocks (int fd,
                      GHashTable * table)
{
  gpointer block_address;

  while (read (fd, &block_address, sizeof (gpointer)) == sizeof (gpointer))
  {
    g_hash_table_add (table, block_address);
  }
}

TESTCASE (prefetch_backpatch)
{
  gsize pipe_size;
  void * fork_addr;
  GumInterceptor * interceptor;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  bp_ctx.stalker = fixture->stalker;

  g_assert_cmpint (pipe (bp_ctx.pipes), ==, 0);
  g_assert_true (g_unix_set_fd_nonblocking (bp_ctx.pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (bp_ctx.pipes[1], TRUE, NULL));

  pipe_size = get_max_pipe_size ();

  g_assert_cmpint (fcntl (bp_ctx.pipes[0], F_SETPIPE_SZ, pipe_size), ==,
      pipe_size);
  g_assert_cmpint (fcntl (bp_ctx.pipes[1], F_SETPIPE_SZ, pipe_size), ==,
      pipe_size);

  bp_ctx.observer = g_object_new (GUM_TYPE_TEST_STALKER_OBSERVER, NULL);

  gum_process_enumerate_modules (store_range_of_test_runner,
      &bp_ctx.runner_range);
  g_assert_cmpuint (bp_ctx.runner_range.base_address, !=, 0);
  g_assert_cmpuint (bp_ctx.runner_range.size, !=, 0);

  bp_ctx.transformer = gum_stalker_transformer_make_from_callback (
```