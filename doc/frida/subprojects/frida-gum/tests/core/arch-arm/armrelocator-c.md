Response:
Let's break down the thought process for analyzing this C code and answering the prompt's questions.

**1. Initial Understanding: What is the Code Doing?**

The first step is to recognize the code's purpose. The file name "armrelocator.c" and the `#include "armrelocator-fixture.c"` strongly suggest this is a unit test file for a component named "armrelocator". The `TESTLIST_BEGIN` and `TESTENTRY` macros confirm this. The names of the test cases (e.g., `pc_relative_ldr_positive_should_be_rewritten`) give a good hint about the functionality being tested. The core idea revolves around rewriting ARM instructions, particularly those involving PC-relative addressing.

**2. Identifying Core Functionality: Relocation**

The name "relocator" immediately brings the concept of code relocation to mind. In dynamic instrumentation, when you insert or move code, you need to adjust addresses within the instructions so they still point to the correct locations. PC-relative addressing is common in ARM, where instructions reference data or code relative to the current program counter (PC). If the code is moved, these offsets need adjustment.

**3. Analyzing Test Cases:  Specific Scenarios**

The individual test cases are crucial for understanding the *specifics* of the relocation process. Looking at the names:

* `one_to_one`:  Likely a basic test to ensure instructions are copied without modification when no relocation is needed.
* `pc_relative_ldr_*`:  Focuses on the `ldr` instruction using PC-relative addressing. The positive/negative suffixes indicate tests for forward and backward offsets. The `_reg` and `_reg_shift` suffixes point to different addressing modes.
* `pc_relative_mov_*`, `pc_relative_add_*`, `pc_relative_sub_*`:  Covers other instructions using PC-relative addressing, including moves, additions, and subtractions. The suffixes detail various operand combinations.
* `b_imm_*`, `bl_imm_*`, `blx_imm_*`:  Deals with branch instructions (`b`, `bl`, `blx`) and how their immediate offsets are handled.

**4. Deeper Dive into Test Structure: `BranchScenario`**

The `BranchScenario` struct and the `branch_scenario_execute` function reveal a pattern for testing relocation. Key elements are:

* `input`: The original ARM instruction(s).
* `expected_output`: The desired ARM instruction(s) *after* relocation.
* `pc_offset`, `expected_pc_distance`:  Indicate how PC-relative offsets are expected to change.
* `lr_offset`, `expected_lr_distance`:  Similar for the Link Register (LR), relevant for branch instructions.

The `branch_scenario_execute` function sets up the relocator, performs the read and write operations (simulating the relocation process), and then compares the generated output with the expected output. The `show_disassembly` function is a debugging aid to visualize the instructions.

**5. Connecting to Reverse Engineering:**

The core function of this code – modifying instructions – is fundamental to dynamic instrumentation and reverse engineering. Tools like Frida intercept and alter program execution by rewriting instructions on the fly. This code provides the low-level mechanism for that.

**6. Identifying Binary and Kernel/Framework Aspects:**

* **Binary Level:** The code directly manipulates raw instruction bytes (`guint32`). It deals with ARM instruction encoding and addressing modes.
* **Linux/Android Kernel/Framework:** While this specific code isn't *in* the kernel, Frida itself operates by injecting code into processes. The relocation process is essential for ensuring this injected code (or modified existing code) functions correctly within the target process's address space. PC-relative addressing is a common feature of compiled code on these platforms.

**7. Logic and Assumptions:**

The tests implicitly assume that the `gum_arm_relocator_read_one` function correctly parses ARM instructions and that `gum_arm_relocator_write_one` performs the relocation logic. The `BranchScenario` tests have explicit assumptions about how specific instructions should be rewritten based on the change in the code's base address.

**8. Common Usage Errors (From a Frida User Perspective):**

While this is a test file, we can infer potential user errors in Frida by thinking about what this code *prevents*:

* Incorrectly calculating offsets when manually rewriting instructions. The relocator automates this.
* Breaking PC-relative addressing by simply overwriting instructions without adjusting offsets.
* Not accounting for different ARM instruction encodings and addressing modes.

**9. Tracing User Operations:**

To reach this code, a Frida user would:

1. **Write a Frida script:** This script would use Frida's API to interact with a target process.
2. **Identify a location to modify:** The script would specify an address or a function to hook.
3. **Use Frida's instrumentation API:**  Functions like `Interceptor.replace`, `Interceptor.attach`, or `Memory.patchCode` would be used. These functions internally rely on components like the `armrelocator` to handle instruction rewriting.
4. **Frida executes the script:**  Frida injects its agent into the target process.
5. **The `armrelocator` is invoked:** When Frida needs to modify code containing PC-relative instructions, the `armrelocator` is used to generate the correct replacement instructions.

By following these steps, we can provide a comprehensive answer to the prompt, covering the code's functionality, its relevance to reverse engineering, its connection to lower-level concepts, and potential user interactions.
这个文件 `armrelocator.c` 是 Frida 工具中用于 ARM 架构代码重定位功能的单元测试文件。它的主要功能是通过一系列测试用例来验证 `gum_arm_relocator` 组件在处理不同 ARM 指令时，能否正确地进行重定位。

下面是对其功能的详细列举，以及与逆向、二进制底层、Linux/Android 内核/框架的关系，逻辑推理和用户使用错误的说明：

**功能列举：**

1. **测试指令的读取和写入：**  `one_to_one` 测试用例验证了 `gum_arm_relocator_read_one` 和 `gum_arm_relocator_write_one` 函数的基本功能，即能够正确地读取和写回 ARM 指令，且在不需要重定位的情况下保持指令不变。
2. **测试 PC 相对加载指令的重定位：**  例如 `pc_relative_ldr_positive_should_be_rewritten` 和 `pc_relative_ldr_negative_should_be_rewritten` 等测试用例，验证了对于 `ldr` 指令使用 PC 相对寻址时，重定位器能够将其转换为一系列不依赖于原始 PC 地址的指令。
3. **测试 PC 相对 `mov`, `add`, `sub` 指令的重定位：**  例如 `pc_relative_mov_should_be_rewritten`，`pc_relative_add_with_pc_on_lhs_should_be_rewritten` 等测试用例，验证了对于使用 PC 作为操作数的 `mov`, `add`, `sub` 指令，重定位器能够正确处理。
4. **测试分支指令的重定位：**  例如 `b_imm_a1_positive_should_be_rewritten` 和 `bl_imm_a1_negative_should_be_rewritten` 等测试用例，验证了对于无条件分支指令 `b` 和带链接分支指令 `bl`，重定位器能够修改其跳转目标地址，使其在新位置仍然有效。
5. **覆盖多种 PC 相对寻址模式：**  测试用例覆盖了 `ldr` 指令的多种 PC 相对寻址模式，包括立即数偏移、寄存器偏移和带移位的寄存器偏移。
6. **测试将值加载到 PC 寄存器的指令重定位：** 例如 `pc_relative_ldr_into_pc_should_be_rewritten`，验证了当目标寄存器是 PC 时，重定位器需要更复杂的操作来保证控制流的正确转移。
7. **使用 `BranchScenario` 结构体进行参数化测试：**  `BranchScenario` 结构体允许定义不同的输入指令、期望的输出指令、PC 偏移量等，方便地进行多种场景的测试。

**与逆向方法的关系：**

* **代码注入和 hook：** Frida 的核心功能之一是在运行时修改目标进程的代码。当 Frida 需要将一段新的代码注入到目标进程，或者 hook 某个函数并插入自己的代码时，就可能需要进行代码重定位。因为注入的代码或者 hook 代码的地址与原始代码的地址不同，其中使用 PC 相对寻址的指令需要被修改，以确保它们仍然指向正确的目标。
    * **举例：** 假设你要 hook 一个函数，并在函数入口处插入一段代码来打印函数的参数。你的 hook 代码可能会包含加载全局变量地址或者调用其他函数的指令。如果这些指令使用了 PC 相对寻址，那么在你将这段 hook 代码注入到目标进程的内存中时，`armrelocator.c` 中测试的重定位逻辑就会被用来调整这些指令，确保它们指向你注入代码内部的正确位置，而不是原始代码中的错误位置。
* **动态分析和代码修改：**  逆向工程师经常需要动态地修改程序的行为来进行分析。Frida 提供的代码修改能力依赖于像 `armrelocator` 这样的组件来确保修改后的代码仍然能够正确执行。
    * **举例：**  你可能需要修改一个条件跳转指令，使其总是跳转到某个特定的分支。如果这个跳转指令是 PC 相对的，你需要计算出新的跳转偏移量，`armrelocator` 提供的功能可以帮助完成这个任务，或者在更底层，Frida 内部会使用类似的逻辑。

**涉及二进制底层、Linux/Android 内核及框架的知识：**

* **ARM 指令集架构：**  该文件直接处理 ARM 指令的二进制编码，例如 `GUINT32_TO_LE(0xe59f3028)` 表示一个 ARM 指令。理解 ARM 指令的格式、寻址模式（尤其是 PC 相对寻址）是理解这段代码的基础。
* **代码重定位的概念：**  在动态链接和代码注入等场景中，代码需要在内存中的不同位置执行，这就需要调整代码中的地址引用。`armrelocator` 就是实现这一功能的组件。
* **内存布局和地址空间：**  理解进程的内存布局对于理解代码重定位的必要性至关重要。注入的代码需要在目标进程的地址空间中分配内存，并确保指令中的地址引用在新位置仍然有效。
* **Linux/Android 用户空间：** Frida 通常在用户空间运行，并注入到其他用户空间进程。`armrelocator` 处理的是用户空间进程中的代码。
* **动态链接器 (ld-linux.so)：** 虽然 `armrelocator` 不是动态链接器的一部分，但它解决的是类似的问题：确保代码在不同的加载地址下都能正常工作。动态链接器在程序启动时会进行类似的重定位操作。

**逻辑推理的例子：**

在 `pc_relative_ldr_positive_should_be_rewritten` 测试用例中：

* **假设输入：**  指令 `ldr r3, [pc, #0x28]`，其含义是将 PC 寄存器当前值加上 0x28 偏移量所指向的内存地址中的值加载到 r3 寄存器。
* **逻辑推理：** 由于代码将被移动，直接使用这条指令会导致读取错误的内存地址。为了解决这个问题，重定位器会将其转换为以下指令序列：
    1. `ldr r3, [pc, #0]`：先将当前（新的）PC 值加载到一个寄存器（这里仍然使用了 PC 相对寻址，但偏移量为 0，目的是获取当前指令的地址）。
    2. `ldr r3, [r3]`:  将 r3 中的地址（即新 PC 的值）作为基址，加载该地址处的值到 r3。
    3. `0xffffffff`:  紧随其后的数据，其值是原始 PC + 8 + 0x28 计算出的绝对地址。

* **预期输出：** 上述指令序列，其中 `0xffffffff` 的值会被计算出来。

**用户或编程常见的使用错误举例：**

虽然用户一般不直接操作 `armrelocator.c` 中的代码，但理解其原理可以帮助避免在使用 Frida 时犯错：

* **错误地手动修改 PC 相对指令：**  如果用户尝试手动修改使用了 PC 相对寻址的指令，例如直接修改偏移量而不考虑代码移动后的影响，会导致程序崩溃或行为异常。`armrelocator` 的作用就是自动且正确地处理这种情况。
* **不理解代码注入的地址影响：**  在进行代码注入时，如果不理解被注入代码的地址与原始代码地址的不同，可能会导致使用了硬编码地址的指令失效。虽然 `armrelocator` 主要处理 PC 相对寻址，但理解地址空间的概念对于编写可靠的 Frida 脚本至关重要。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 Frida 脚本：** 用户使用 Python 或 JavaScript 编写 Frida 脚本，目标是 hook 某个 ARM 架构的应用程序的函数。
2. **Frida 注入目标进程：**  用户运行 Frida 脚本，Frida 将其 agent 注入到目标进程中。
3. **hook 生效，代码修改发生：**  Frida agent 根据脚本的指示，在目标函数的入口处设置 hook。为了执行 hook 代码，Frida 可能会修改原始指令，或者插入跳转指令到用户提供的 hook 代码。
4. **遇到 PC 相对指令：**  如果被 hook 的函数或 Frida 插入的 hook 代码中包含使用了 PC 相对寻址的指令。
5. **调用 `gum_arm_relocator`：** Frida 内部的机制会调用 `gum_arm_relocator` 组件来处理这些需要重定位的指令。
6. **`armrelocator.c` 中的测试用例作为调试线索：** 如果在 Frida 的开发过程中，重定位功能出现 bug，开发者可能会参考 `armrelocator.c` 中的测试用例来复现问题，分析是哪种类型的 PC 相对指令的重定位出现了错误。例如，如果某个用户报告了一个与 `bl` 指令相关的 hook 错误，开发者可能会重点检查 `bl_imm_a1_positive_should_be_rewritten` 等测试用例，看是否覆盖了相关的场景。

总而言之，`armrelocator.c` 是 Frida 中保证代码动态修改正确性的关键组成部分的测试代码，它验证了在 ARM 架构下处理 PC 相对寻址指令时的重定位逻辑，这对于 Frida 的 hook 和代码注入功能至关重要。理解这段代码可以帮助开发者调试 Frida 的相关问题，并帮助用户更好地理解 Frida 的工作原理以及避免一些常见的错误。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/armrelocator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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

#include "armrelocator-fixture.c"

TESTLIST_BEGIN (armrelocator)
  TESTENTRY (one_to_one)
  TESTENTRY (pc_relative_ldr_positive_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_negative_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_reg_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_reg_shift_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_into_pc_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_into_pc_with_shift_should_be_rewritten)
  TESTENTRY (pc_relative_mov_should_be_rewritten)
  TESTENTRY (pc_relative_add_with_pc_on_lhs_should_be_rewritten)
  TESTENTRY (pc_relative_add_with_pc_on_rhs_should_be_rewritten)
  TESTENTRY (pc_relative_add_lsl_should_be_rewritten)
  TESTENTRY (pc_relative_add_imm_should_be_rewritten)
  TESTENTRY (pc_relative_add_imm_ror_should_be_rewritten)
  TESTENTRY (pc_relative_add_with_two_registers_should_be_rewritten)
  TESTENTRY (pc_relative_sub_with_pc_on_lhs_should_be_rewritten)
  TESTENTRY (pc_relative_sub_with_pc_on_rhs_should_be_rewritten)
  TESTENTRY (pc_relative_sub_imm_should_be_rewritten)
  TESTENTRY (pc_relative_sub_pc_pc_should_be_rewritten)
  TESTENTRY (pc_relative_sub_with_pc_on_lhs_and_dest_should_be_rewritten)
  TESTENTRY (pc_relative_sub_with_pc_on_rhs_and_dest_should_be_rewritten)
  TESTENTRY (pc_relative_sub_pc_pc_imm_should_be_rewritten)
  TESTENTRY (pc_relative_sub_rd_pc_rm_should_be_rewritten)
  TESTENTRY (pc_relative_sub_rd_rn_pc_should_be_rewritten)
  TESTENTRY (pc_relative_sub_pc_shift_imm_should_be_rewritten)
  TESTENTRY (pc_relative_sub_shift_imm_should_be_rewritten)
  TESTENTRY (pc_relative_sub_pc_shift_reg_should_be_rewritten)
  TESTENTRY (pc_relative_sub_shift_reg_should_be_rewritten)
  TESTENTRY (b_imm_a1_positive_should_be_rewritten)
  TESTENTRY (b_imm_a1_negative_should_be_rewritten)
  TESTENTRY (bl_imm_a1_positive_should_be_rewritten)
  TESTENTRY (bl_imm_a1_negative_should_be_rewritten)
  TESTENTRY (blx_imm_a2_positive_should_be_rewritten)
  TESTENTRY (blx_imm_a2_negative_should_be_rewritten)
TESTLIST_END ()

TESTCASE (one_to_one)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xe1a0c00d), /* mov ip, sp    */
    GUINT32_TO_LE (0xe92d0030), /* push {r4, r5} */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_MOV);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 8);
  g_assert_cmpint (insn->id, ==, ARM_INS_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_arm_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert_true (gum_arm_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 4, input + 1, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (8);

  g_assert_false (gum_arm_relocator_write_one (&fixture->rl));
}

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  guint instruction_id;
  guint32 input[1];
  gsize input_length;
  guint32 expected_output[10];
  gsize expected_output_length;
  gssize pc_offset;
  gssize expected_pc_distance;
  gssize lr_offset;
  gssize expected_lr_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestArmRelocatorFixture * fixture);
static void show_disassembly (const guint32 * input, gsize length);

TESTCASE (pc_relative_ldr_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe59f3028 }, 1,          /* ldr r3, [pc, #0x28] */
    {
      0xe59f3000,               /* ldr r3, [pc, #0]  */
      0xe5933000,               /* ldr r3, [r3]      */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 3,
    2, 0x28,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe51f3028 }, 1,          /* ldr r3, [pc, -#0x28] */
    {
      0xe59f3000,               /* ldr r3, [pc, #0]  */
      0xe5933000,               /* ldr r3, [r3]      */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 3,
    2, -0x28,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_reg_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe79f3003 }, 1,          /* ldr r3, [pc, r3] */
    {
      0xe2833c08,               /* add r3, r3, <0x08 >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, #8               */
      0xe5933000,               /* ldr r3, [r3]                 */
    }, 3,
    -1, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_reg_shift_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe79f3103 }, 1,          /* ldr r3, [pc, r3, lsl #2] */
    {
      0xe1a03103,               /* lsl r3, r3, #2               */
      0xe2833c08,               /* add r3, r3, <0x08 >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, #8               */
      0xe5933000,               /* ldr r3, [r3]                 */
    }, 4,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_into_pc_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe59ff004 }, 1,          /* ldr pc, [pc, #4] */
    {
      0xe92d8001,               /* push {r0, pc}      */
      0xe59f0008,               /* ldr r0, [pc, #0x8] */
      0xe5900000,               /* ldr r0, [r0]       */
      0xe58d0004,               /* str r0, [sp, #4]   */
      0xe8bd8001,               /* pop {r0, pc}       */
      0xffffffff                /* <calculated PC     */
                                /*  goes here>        */
    }, 6,
    5, 4,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_into_pc_with_shift_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe79ff103 }, 1,          /* ldr pc, [pc, r3, lsl #2] */
    {
      0xe92d8008,               /* push {r3, pc}       */
      0xe1a03103,               /* lsl r3, r3, #2      */
      0xe2833c08,               /* add r3, r3, #8, #24 */
      0xe2833008,               /* add r3, r3, #8      */
      0xe5933000,               /* ldr r3, [r3]        */
      0xe58d3004,               /* str r3, [sp, #4]    */
      0xe8bd8008,               /* pop {r3, pc}        */
    }, 7,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_mov_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_MOV,
    { 0xe1a0e00f }, 1,          /* mov lr, pc        */
    {
      0xe51fe004,               /* ldr lr, [pc, #-4] */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    1, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_with_pc_on_lhs_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe08f3003 }, 1,          /* add r3, pc, r3   */
    {
      0xe2833c08,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, 0xXX             */
    }, 2,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_with_pc_on_rhs_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe08cc00f }, 1,          /* add ip, ip, pc               */
    {
      0xe28ccc08,               /* add ip, ip, <0xXX >>> 0xc*2> */
      0xe28cc008,               /* add ip, ip, 0xXX             */
    }, 2,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_lsl_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe08ff101 }, 1,          /* add pc, pc, r1 lsl #2  */
    {
      0xe92d8002,               /* push {r1, pc}                */
      0xe1a01101,               /* mov r1, r1, lsl #2           */
      0xe2811c08,               /* add r1, r1, <0xXX >>> 0xc*2> */
      0xe2811008,               /* add r1, r1, 0xXX             */
      0xe58d1004,               /* str r1, [sp, #4]             */
      0xe8bd8002,               /* pop {r1, pc}                 */
    }, 6,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_imm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe28f3008 }, 1,          /* add r3, pc, #8   */
    {
      0xe59f3000,               /* ldr r3, [pc]     */
      0xe2833008,               /* add r3, r3, 0xXX */
      0xffffffff                /* <calculated PC   */
                                /*  goes here>      */
    }, 3,
    2, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_imm_ror_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe28fc604 }, 1,          /* add ip, pc, #4, #12          */
    {
      0xe59fc008,               /* ldr ip, [pc, #8]             */
      0xe1a0c66c,               /* ror ip, ip, #0xc             */
      0xe28ccc08,               /* add ip, ip, <0xXX >>> 0xc*2> */
      0xe28cc008,               /* add ip, ip, 0xXX             */
      0x00000004,               /* #4                           */
    }, 5,
    -1, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_with_two_registers_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe08f9004 }, 1,          /* add sb, pc, r4 */
    {
      0xe59f9000,               /* ldr sb, [pc]   */
      0xe0899004,               /* add sb, sb, r4 */
      0xffffffff                /* <calculated PC */
                                /*  goes here>    */
    }, 3,
    2, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_with_pc_on_lhs_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04f3003 }, 1,          /* sub r3, pc, r3               */
    {
      0xe2633000,               /* rsb r3, r3, #0               */
      0xe2833c08,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, 0xXX             */
    }, 2,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_with_pc_on_rhs_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04cc00f }, 1,          /* sub ip, ip, pc               */
    {
      0xe24ccc08,               /* sub ip, ip, <0xXX >>> 0xc*2> */
      0xe24cc008,               /* sub ip, ip, 0xXX             */
    }, 8,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_imm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe24f3008 }, 1,          /* sub r3, pc, #8   */
    {
      0xe59f3000,               /* ldr r3, [pc]     */
      0xe2433008,               /* sub r3, r3, 0xXX */
      0xffffffff                /* <calculated PC   */
                                /*  goes here>      */
    }, 3,
    2, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_pc_pc_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04ff00f }, 1,          /* sub pc, pc, pc   */
    {
      0xe92d8001,               /* push {r0, pc}    */
      0xe0400000,               /* sub r0, r0, r0   */
      0xe58d0004,               /* str r0, [sp, #4] */
      0xe8bd8001,               /* pop {r0, pc}     */
    }, 4,
    -1, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_with_pc_on_lhs_and_dest_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04ff003 }, 1,          /* sub pc, pc, r3               */
    {
      0xe92d8008,               /* push {r3, pc}                */
      0xe2633000,               /* rsb r3, r3, #0               */
      0xe2833c08,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, 0xXX             */
      0xe58d3004,               /* str r3, [sp, #4]             */
      0xe8bd8008,               /* pop {r3, pc}                 */
    }, 6,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_with_pc_on_rhs_and_dest_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04cf00f }, 1,          /* sub pc, ip, pc               */
    {
      0xe92d8001,               /* push {r0, pc}                */
      0xe28c0000,               /* add r0, ip, #0               */
      0xe2400c08,               /* sub r0, r0, <0xXX >>> 0xc*2> */
      0xe2400008,               /* sub r0, r0, 0xXX             */
      0xe58d0004,               /* str r0, [sp, #4]             */
      0xe8bd8001,               /* pop {r0, pc}                 */
    }, 6,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_pc_pc_imm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe24ff00c }, 1,          /* sub pc, pc, #12  */
    {
      0xe92d8001,               /* push {r0, pc}    */
      0xe59f0008,               /* ldr r0, [pc, #8] */
      0xe240000c,               /* sub r0, r0, #0xc */
      0xe58d0004,               /* str r0, [sp, #4] */
      0xe8bd8001,               /* pop {r0, pc}     */
      0xffffffff                /* <calculated PC   */
                                /*  goes here>      */
    }, 6,
    5, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_rd_pc_rm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04f300c }, 1,          /* sub r3, pc, ip */
    {
      0xe59f3000,               /* ldr r3, [pc]   */
      0xe24c3000,               /* sub r3, ip, #0 */
      0xffffffff                /* <calculated PC */
                                /*  goes here>    */
    }, 3,
    2, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_rd_rn_pc_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04c300f }, 1,          /* sub r3, ip, pc   */
    {
      0xe59f3004,               /* ldr r3, [pc, #4] */
      0xe2633000,               /* rsb r3, r3, #0   */
      0xe28c3000,               /* add r3, ip, #0   */
      0xffffffff                /* <calculated PC   */
                                /*  goes here>      */
    }, 4,
    3, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_pc_shift_imm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe24ff27f }, 1,          /* sub pc, pc, #127, #4 */
    {
      0xe92d8001,               /* push {r0, pc}        */
      0xe59f000c,               /* ldr r0, [pc, #0xc]   */
      0xe24004f0,               /* sub r0, r0, #240, #8 */
      0xe2400007,               /* sub r0, r0, #7       */
      0xe58d0004,               /* str r0, [sp, #4]     */
      0xe8bd8001,               /* pop {r0, pc}         */
      0xffffffff                /* <calculated PC       */
                                /*  goes here>          */
    }, 7,
    6, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_shift_imm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe24f327f }, 1,          /* sub r3, pc, #127, #4 */
    {
      0xe59f3004,               /* ldr r3, [pc, #4]     */
      0xe24334f0,               /* sub r3, r3, #240, #8 */
      0xe2433007,               /* sub r3, r3, #7       */
      0xffffffff                /* <calculated PC       */
                                /*  goes here>          */
    }, 4,
    3, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_pc_shift_reg_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04ff101 }, 1,          /* sub pc, pc, r1, lsl #2       */
    {
      0xe92d8002,               /* push {r1, pc}                */
      0xe1a01101,               /* lsl r1, r1, #2               */
      0xe2611000,               /* rsb r1, r1, #0               */
      0xe2811c08,               /* add r1, r1, <0xXX >>> 0xc*2> */
      0xe2811008,               /* add r1, r1, 0xXX             */
      0xe58d1004,               /* str r1, [sp, #4]             */
      0xe8bd8002,               /* pop {r1, pc}                 */
    }, 7,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_sub_shift_reg_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_SUB,
    { 0xe04f3101 }, 1,          /* sub r3, pc, r1, lsl #2       */
    {
      0xe2813000,               /* add r3, r1, #0               */
      0xe1a03103,               /* lsl r3, r3, #2               */
      0xe2633000,               /* rsb r3, r3, #0               */
      0xe2833c08,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, 0xXX             */
    }, 5,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (b_imm_a1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
    { 0xea000001 }, 1,          /* b pc + 4          */
    {
      0xe51ff004,               /* ldr pc, [pc, #-4] */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    1, 4,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (b_imm_a1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
    { 0xeaffffff }, 1,          /* b pc - 4          */
    {
      0xe51ff004,               /* ldr pc, [pc, #-4] */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    1, -4,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (bl_imm_a1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BL,
    { 0xeb000001 }, 1,          /* bl pc + 4         */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, 4,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (bl_imm_a1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BL,
    { 0xebffffff }, 1,          /* bl pc - 4         */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, -4,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (blx_imm_a2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BLX,
    { 0xfb000001 }, 1,          /* blx pc + 6        */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, 7,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (blx_imm_a2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BLX,
    { 0xfaffffff }, 1,          /* blx pc - 4        */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, -3,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

static void
branch_scenario_execute (BranchScenario * bs,
                         TestArmRelocatorFixture * fixture)
{
  gsize i;
  const cs_insn * insn = NULL;
  gboolean same_content;
  gchar * diff;

  for (i = 0; i != bs->input_length; i++)
    bs->input[i] = GUINT32_TO_LE (bs->input[i]);
  for (i = 0; i != bs->expected_output_length; i++)
    bs->expected_output[i] = GUINT32_TO_LE (bs->expected_output[i]);

  SETUP_RELOCATOR_WITH (bs->input);

  if (bs->pc_offset != -1)
  {
    guint32 calculated_pc;

    calculated_pc = fixture->rl.input_pc + 8 + bs->expected_pc_distance;
    *((guint32 *) (bs->expected_output + bs->pc_offset)) = calculated_pc;
  }

  if (bs->lr_offset != -1)
  {
    guint32 calculated_lr;

    calculated_lr = (guint32) (fixture->aw.pc +
        (bs->expected_lr_distance * sizeof (guint32)));
    *((guint32 *) (bs->expected_output + bs->lr_offset)) = calculated_lr;
  }

  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, bs->instruction_id);
  g_assert_true (gum_arm_relocator_write_one (&fixture->rl));
  gum_arm_writer_flush (&fixture->aw);

  same_content = memcmp (fixture->output, bs->expected_output,
      bs->expected_output_length * sizeof (guint32)) == 0;

  diff = test_util_diff_binary (
      (guint8 *) bs->expected_output,
      bs->expected_output_length * sizeof (guint32),
      fixture->output,
      bs->expected_output_length * sizeof (guint32));

  if (!same_content)
  {
    g_print ("\n\nGenerated code is not equal to expected code:\n\n%s\n", diff);

    g_print ("\n\nInput:\n\n");
    g_print ("0x%" G_GINT64_MODIFIER "x: %s %s\n",
        insn->address, insn->mnemonic, insn->op_str);

    g_print ("\n\nExpected:\n\n");
    show_disassembly (bs->expected_output, bs->expected_output_length);

    g_print ("\n\nWrong:\n\n");
    show_disassembly ((guint32 *) fixture->output, bs->expected_output_length);
  }

  g_assert_true (same_content);
}

static void
show_disassembly (const guint32 * input,
                  gsize length)
{
  csh capstone;
  cs_insn * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  cs_open (CS_ARCH_ARM, CS_MODE_ARM, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  insn = cs_malloc (capstone);

  code = (const uint8_t *) input;
  size = length * sizeof (guint32);
  address = GPOINTER_TO_SIZE (input);

  while (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    guint32 raw_insn;

    memcpy (&raw_insn, insn->bytes, sizeof (raw_insn));

    g_print ("0x%" G_GINT64_MODIFIER "x\t0x%08x,               /* %s %s */\n",
        insn->address, raw_insn, insn->mnemonic, insn->op_str);
  }

  cs_free (insn, 1);
  cs_close (&capstone);
}
```