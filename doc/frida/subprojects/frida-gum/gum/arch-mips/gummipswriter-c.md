Response:
Let's break down the thought process for analyzing this C code and fulfilling the request.

**1. Understanding the Goal:**

The core request is to analyze the C code (`gummipswriter.c`) for a dynamic instrumentation tool (Frida) targeting MIPS architecture. The analysis should cover its functionality, relationship to reverse engineering, interaction with low-level concepts, logical reasoning, common user errors, and debugging context.

**2. Initial Code Scan and High-Level Overview:**

First, I'd quickly scan the code, looking for keywords and structural elements to get a general idea of its purpose. I'd notice:

* **`GumMipsWriter` struct:** This likely represents the core data structure for generating MIPS instructions.
* **`gum_mips_writer_new`, `gum_mips_writer_init`, `gum_mips_writer_unref`:** Standard object lifecycle management functions.
* **`gum_mips_writer_put_*` functions:**  These are the most important, as they seem to be responsible for writing specific MIPS instructions. The naming convention (`put_call_address_with_arguments`, `put_j_address`, `put_lui_reg_imm`, etc.) is very informative.
* **Label handling (`label_defs`, `label_refs`):**  Indicates support for forward references and patching.
* **Argument handling (`gum_mips_writer_put_argument_list_*`):**  Suggests support for calling functions.
* **Register definitions (`GUM_MREG_*`):**  Clearly related to MIPS registers.
* **Conditional compilation (`#if GLIB_SIZEOF_VOID_P == 8`):** Shows support for both 32-bit and 64-bit MIPS.

From this initial scan, I can infer that this code is responsible for dynamically generating MIPS assembly code.

**3. Detailed Function Analysis (Focusing on Key Areas):**

Next, I'd dive into the details of specific functions, categorizing them based on their apparent purpose.

* **Instruction Emission:** The `gum_mips_writer_put_*` functions are central. I'd examine a few examples:
    * `gum_mips_writer_put_j_address`:  Note the handling of PC-relative addressing and potential range limitations.
    * `gum_mips_writer_put_lui_reg_imm` and `gum_mips_writer_put_ori_reg_reg_imm`: Recognize these as standard techniques for loading full 32-bit or 64-bit immediate values into registers.
    * `gum_mips_writer_put_call_address_with_arguments`: Understand the process of setting up arguments in registers and on the stack before a function call.
* **Label Management:** The functions related to labels (`gum_mips_writer_put_label`, `gum_mips_writer_add_label_reference_here`, `gum_mips_writer_flush`) are important for patching and control flow. I'd pay attention to how forward references are handled (storing references and resolving them later).
* **Argument Handling:**  The `gum_mips_writer_put_argument_list_*` functions are crucial for understanding how function calls are prepared. The distinction between passing arguments in registers and on the stack, based on the number of arguments, is key.
* **Trampolines:** The `gum_mips_writer_put_prologue_trampoline` function is interesting. I'd analyze why it's needed and how it works (placing the target address in the instruction stream).

**4. Connecting to the Request's Themes:**

Now, I'd systematically address each part of the request, using the understanding gained from the code analysis:

* **Functionality:** Summarize the core purpose and capabilities based on the analyzed functions (generating MIPS code, handling labels, function calls, etc.).
* **Relationship to Reverse Engineering:** Consider how this tool could be used in reverse engineering. Hooking functions, modifying behavior, logging arguments – these are common use cases. Provide concrete examples.
* **Binary/Kernel/Framework:**  Identify interactions with low-level concepts. Register manipulation, instruction encoding, stack management, function calling conventions – these all relate to the binary level. Mention the impact of operating systems (Linux/Android) and how Frida operates in user space to interact with these lower layers.
* **Logical Reasoning:**  Look for functions with conditional logic or calculations. The label patching in `gum_mips_writer_flush` is a prime example. Formulate hypothetical scenarios to illustrate input and output.
* **User Errors:** Think about common mistakes a programmer might make when using this API. Incorrect argument types, stack imbalances, and incorrect label usage are good examples.
* **Debugging:** Trace the steps a user might take that lead to this code being executed. Hooking a function is the most obvious path. Explain the role of this code in that process.

**5. Structuring the Response:**

Finally, organize the information clearly, following the structure of the original request. Use headings and bullet points to make it easy to read and understand. Provide code snippets where relevant to illustrate points. Ensure the language is clear and concise.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just writes MIPS instructions."
* **Correction:**  "It does more than just write instructions. It also handles labels and function call setup, which are crucial for more complex instrumentation."
* **Initial thought:** "The user errors are obvious."
* **Refinement:** "Think about *why* those errors occur in the context of dynamic instrumentation. What specific steps or misunderstandings lead to them?"
* **Initial thought:** "Just list the functions."
* **Refinement:** "Group the functions by functionality to provide a better overview and demonstrate understanding."

By following this systematic approach, combining code analysis with an understanding of the request's themes, I can generate a comprehensive and accurate response. The key is to go beyond just describing the code and to explain its significance and implications in the context of Frida and reverse engineering.
好的，我们来分析一下 `frida/subprojects/frida-gum/gum/arch-mips/gummipswriter.c` 这个文件的功能。

**文件功能概览:**

`gummipswriter.c` 文件是 Frida Gum 框架中用于在 MIPS 架构上动态生成和写入机器码的关键组件。它提供了一组 API，允许开发者以更高级的方式构建 MIPS 指令序列，而无需手动处理原始字节码。可以将其看作是一个 MIPS 汇编代码的生成器，但它是以 C 语言 API 的形式提供的。

**具体功能列举:**

1. **初始化和管理代码缓冲区:**
   - `gum_mips_writer_new`: 创建一个新的 `GumMipsWriter` 实例，它会分配用于存储生成代码的内存。
   - `gum_mips_writer_init`: 初始化 `GumMipsWriter` 结构体，设置代码写入的起始地址。
   - `gum_mips_writer_ref` 和 `gum_mips_writer_unref`: 管理 `GumMipsWriter` 实例的引用计数，用于内存管理。
   - `gum_mips_writer_clear`: 清理 `GumMipsWriter` 占用的资源，可以选择是否将生成的代码刷新到内存。
   - `gum_mips_writer_reset`: 重置代码写入器的状态，可以重新开始在指定的地址写入代码。
   - `gum_mips_writer_cur`: 获取当前代码写入的位置。
   - `gum_mips_writer_offset`: 获取当前写入的字节数偏移量。
   - `gum_mips_writer_skip`: 跳过指定数量的字节，用于在代码中预留空间。
   - `gum_mips_writer_flush`: 将所有延迟的标签引用解析并填充到生成的代码中。

2. **生成 MIPS 指令:**
   该文件提供了大量的函数，用于生成各种 MIPS 指令，例如：
   - **跳转和分支指令:** `gum_mips_writer_put_j_address`, `gum_mips_writer_put_jr_reg`, `gum_mips_writer_put_jal_address`, `gum_mips_writer_put_jalr_reg`, `gum_mips_writer_put_b_offset`, `gum_mips_writer_put_beq_reg_reg_label`, `gum_mips_writer_put_ret`.
   - **加载和存储指令:** `gum_mips_writer_put_la_reg_address`, `gum_mips_writer_put_lui_reg_imm`, `gum_mips_writer_put_ld_reg_reg_offset`, `gum_mips_writer_put_lw_reg_reg_offset`, `gum_mips_writer_put_sw_reg_reg_offset`.
   - **算术和逻辑运算指令:** `gum_mips_writer_put_move_reg_reg`, `gum_mips_writer_put_addu_reg_reg_reg`, `gum_mips_writer_put_addi_reg_reg_imm`, `gum_mips_writer_put_sub_reg_reg_imm`, `gum_mips_writer_put_ori_reg_reg_imm`, `gum_mips_writer_put_dsll_reg_reg`.
   - **栈操作指令:** `gum_mips_writer_put_push_reg`, `gum_mips_writer_put_pop_reg`.
   - **乘除法辅助寄存器操作指令:** `gum_mips_writer_put_mfhi_reg`, `gum_mips_writer_put_mflo_reg`, `gum_mips_writer_put_mthi_reg`, `gum_mips_writer_put_mtlo_reg`.
   - **其他指令:** `gum_mips_writer_put_nop` (空操作), `gum_mips_writer_put_break` (断点指令), `gum_mips_writer_put_instruction` (直接写入 32 位指令).

3. **处理标签 (Labels) 和代码重定位:**
   - `gum_mips_writer_put_label`: 在当前代码位置定义一个标签，方便后续跳转或引用。
   - `gum_mips_writer_add_label_reference_here`:  添加一个对标签的引用，当标签定义后，Frida 会自动计算跳转距离并填充。
   - `gum_mips_writer_has_label_defs`, `gum_mips_writer_has_label_refs`: 检查是否存在定义的标签或标签引用。
   - 这种机制允许在生成代码时使用向前引用，即在标签定义之前就引用它。

4. **处理函数调用:**
   - `gum_mips_writer_put_call_address_with_arguments`:  生成调用指定地址的函数的代码，并设置函数参数（通过寄存器或栈）。
   - `gum_mips_writer_put_call_address_with_arguments_array`:  与上类似，但参数以数组形式传递。
   - `gum_mips_writer_put_call_reg_with_arguments`: 生成通过寄存器间接调用的函数的代码，并设置参数。
   - `gum_mips_writer_put_call_reg_with_arguments_array`:  与上类似，但参数以数组形式传递。
   - `gum_mips_writer_put_argument_list_setup`, `gum_mips_writer_put_argument_list_setup_va`, `gum_mips_writer_put_argument_list_teardown`: 辅助函数，用于设置函数调用的参数（放入寄存器或压入栈），并在调用后清理栈。

5. **生成 Trampoline (跳板代码):**
   - `gum_mips_writer_put_prologue_trampoline`:  生成一个小型的跳板代码，用于将执行流重定向到指定的地址。这在 Frida 的 hook 机制中非常常见，用于在目标函数入口处插入自定义代码。

6. **直接写入字节:**
   - `gum_mips_writer_put_bytes`:  允许直接写入原始字节数据到代码缓冲区。

7. **辅助函数:**
   - `gum_mips_writer_can_branch_directly_between`: 检查两个地址之间是否可以直接跳转（在 MIPS 的分支指令的寻址范围内）。
   - `gum_mips_writer_describe_reg`:  获取 MIPS 寄存器的元信息，如索引和宽度。

**与逆向方法的关系及举例说明:**

`gummipswriter.c` 是 Frida 动态插桩的核心组成部分，它直接服务于逆向工程的各种需求：

* **代码注入 (Code Injection):**  逆向工程师可以使用 Frida 将自定义的恶意代码或分析代码注入到目标进程中。`GumMipsWriter` 提供的 API 可以方便地生成这些注入代码的 MIPS 指令。
   * **举例:**  你想在目标程序的某个函数执行前打印其参数。你可以使用 Frida 的 JavaScript API，结合 Gum API，生成一段 MIPS 代码，该代码会保存目标函数的参数到指定位置，然后调用原始函数，最后恢复现场。`gum_mips_writer_put_push_reg`, `gum_mips_writer_put_lw_reg_reg_offset`, `gum_mips_writer_put_call_address_with_arguments` 等函数会被用到。

* **Hooking (函数劫持):**  Frida 最常用的功能之一是 hook。`GumMipsWriter` 用于生成 hook 函数入口处的跳板代码，将执行流导向 Frida 的处理函数。
   * **举例:**  你想监控目标程序中 `open` 系统调用的行为。你可以使用 Frida hook `open` 函数，并在 hook 函数中使用 `gum_mips_writer_put_prologue_trampoline` 生成一个跳转到你的自定义处理函数的跳板，在你的处理函数中记录 `open` 的参数，然后再跳转回原始 `open` 函数。

* **运行时代码修改:**  逆向工程师可以使用 Frida 在运行时修改程序的行为，例如修改函数返回值、跳过某些逻辑分支等。`GumMipsWriter` 可以生成用于修改指令的机器码。
   * **举例:**  你想绕过目标程序中的一个 license 校验。你可以使用 Frida hook 校验函数，并使用 `gum_mips_writer_put_move_reg_reg` 或 `gum_mips_writer_put_addi_reg_imm` 等函数生成代码，将校验函数的返回值直接设置为成功的值。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明:**

* **MIPS 架构指令集:**  `gummipswriter.c` 中的函数名和参数直接对应于 MIPS 指令的助记符和操作数类型 (例如 `lui`, `ori`, `jalr`, 寄存器如 `MIPS_REG_SP`, `MIPS_REG_RA`)。理解 MIPS 指令格式、寻址方式、寄存器约定是使用这个文件的基础。
   * **举例:**  `gum_mips_writer_put_lw_reg_reg_offset(self, dst_reg, src_reg, src_offset)` 函数对应于 MIPS 的 load word 指令，它从 `src_reg + src_offset` 的内存地址加载一个 32 位字到 `dst_reg` 寄存器。

* **MIPS 调用约定 (Calling Convention):**  `gum_mips_writer_put_argument_list_setup` 和相关函数处理函数调用时的参数传递。MIPS 的调用约定规定了参数如何通过寄存器 ($a0-$a3) 和栈来传递，以及返回值的存放位置 ($v0-$v1)。
   * **举例:**  在 32 位 MIPS 中，前 4 个参数通常通过 `$a0` 到 `$a3` 寄存器传递。如果函数有更多参数，则会压入栈中。`gum_mips_writer_put_argument_list_setup` 会根据参数数量将参数放入相应的寄存器或压入栈。

* **内存布局和地址空间:**  `GumAddress` 类型代表内存地址。Frida 需要知道目标进程的内存布局，以便在正确的地址注入代码或 hook 函数。
   * **举例:**  当使用 `gum_mips_writer_put_call_address_with_arguments` 调用一个函数时，需要提供目标函数的入口地址。这个地址需要是目标进程地址空间中的有效地址。

* **Linux/Android 系统调用接口 (System Call Interface):**  虽然 `gummipswriter.c` 本身不直接处理系统调用，但 Frida 经常用于 hook 系统调用。理解 MIPS 的系统调用约定（例如使用 `syscall` 指令，系统调用号放在 `$v0` 寄存器，参数放在 `$a0` 等寄存器）有助于理解 Frida 如何拦截和修改系统调用行为。

* **进程内存管理:**  Frida 需要操作目标进程的内存，包括分配可执行内存、写入代码、修改内存保护属性等。这涉及到操作系统提供的内存管理机制。

**逻辑推理及假设输入与输出:**

假设我们要生成一个简单的 MIPS 代码片段，将寄存器 `$t0` 的值加 1，并将结果存回 `$t0`。

* **假设输入:**
    - `GumMipsWriter` 实例 `writer` 已经创建并初始化。
    - 我们想操作 MIPS 寄存器 `$t0`，其对应的 `mips_reg` 枚举值为 `MIPS_REG_T0`。
* **代码调用序列:**
    ```c
    gum_mips_writer_put_addi_reg_imm(writer, MIPS_REG_T0, 1);
    ```
* **逻辑推理:**
    - `gum_mips_writer_put_addi_reg_imm` 函数会根据传入的寄存器和立即数生成 `addi` 指令的机器码。
    - MIPS `addi` 指令的格式是 `addi $t, $s, immediate`，其中 `$t` 是目标寄存器，`$s` 是源寄存器，`immediate` 是立即数。
    - 在本例中，目标寄存器和源寄存器都是 `$t0`。
    - 函数会查找 `$t0` 对应的寄存器索引。
    - 函数会将操作码、寄存器索引和立即数编码到 32 位指令中。
* **预期输出 (假设在 32 位 MIPS 上):**
    - 生成的机器码将是 `0x21080001`。
    - 这个 32 位值对应于 `addi $t0, $t0, 1` 指令。
    - 代码写入器的当前位置会前进 4 个字节。

**用户或编程常见的使用错误及举例说明:**

1. **错误的寄存器编号或类型:**  使用了不存在的寄存器或者在需要通用寄存器的地方使用了特殊用途寄存器。
   * **举例:**  `gum_mips_writer_put_push_reg(writer, MIPS_REG_PC);`  `PC` (程序计数器) 通常不能直接作为 `push` 指令的操作数。

2. **立即数超出范围:**  MIPS 指令的立即数字段有位数限制。如果提供的立即数超出了该范围，会导致编码错误。
   * **举例:**  `gum_mips_writer_put_addi_reg_imm(writer, MIPS_REG_T0, 0xFFFFFFFF);` 在某些 `addi` 指令中，立即数是符号扩展的 16 位值，`0xFFFFFFFF` 超出了这个范围。

3. **标签未定义或重复定义:**  引用了一个尚未定义的标签，或者定义了多个同名的标签。
   * **举例:**  先调用 `gum_mips_writer_add_label_reference_here(writer, "my_label");`，但之后没有调用 `gum_mips_writer_put_label(writer, "my_label");`。

4. **跳转目标超出范围:**  使用直接跳转指令时，目标地址与当前地址的偏移量超出指令的寻址范围。
   * **举例:**  尝试使用 `gum_mips_writer_put_j_address` 跳转到一个距离当前位置非常远的地址，超出了 26 位偏移的范围。

5. **栈不平衡:**  在函数调用前后，没有正确地平衡栈指针，导致栈溢出或数据错误。
   * **举例:**  在 `gum_mips_writer_put_call_address_with_arguments` 后，如果参数是通过栈传递的，但没有调用相应的清理栈的指令，就会导致栈不平衡。

6. **在错误的时机调用 `flush`:**  在所有标签引用都被定义之前调用 `gum_mips_writer_flush` 可能导致部分跳转指令无法正确解析。

**用户操作如何一步步到达这里作为调试线索:**

作为 Frida 的用户或开发者，你可能会通过以下步骤间接或直接地使用到 `gummipswriter.c` 中的功能：

1. **编写 Frida 脚本 (JavaScript):** 你编写 JavaScript 代码，使用 Frida 提供的 API 来 hook 函数、读取内存、调用函数等。例如：
   ```javascript
   Interceptor.attach(Module.findExportByName(null, "open"), {
     onEnter: function(args) {
       console.log("Opening file:", args[0].readUtf8String());
     }
   });
   ```

2. **Frida Core 处理脚本:** Frida 的核心组件接收你的 JavaScript 脚本，并将其转换为内部表示。当遇到 `Interceptor.attach` 这样的 API 调用时，Frida 需要在目标进程中插入代码来实现 hook。

3. **Gum 框架介入:** Frida 使用 Gum 框架来处理底层的代码生成和操作。对于 MIPS 架构，Gum 会选择 `gummipswriter.c` 来生成 hook 的跳板代码。

4. **调用 `GumMipsWriter` API:**  Gum 框架内部会调用 `gummipswriter.c` 中提供的 API，例如 `gum_mips_writer_new` 创建代码写入器，`gum_mips_writer_put_prologue_trampoline` 生成跳板代码，`gum_mips_writer_put_instruction` 写入指令等。

5. **代码注入:**  生成的 MIPS 代码会被注入到目标进程的内存中，通常是在目标函数的入口处。

6. **执行流程跳转:**  当目标函数被调用时，CPU 会先执行注入的跳板代码，然后跳转到 Frida 的处理函数。

**作为调试线索:**

当你在使用 Frida 进行逆向分析时遇到问题，例如程序崩溃、行为异常、hook 不生效等，`gummipswriter.c` 可以作为调试的线索：

* **检查生成的机器码:**  你可以通过 Frida 的日志或内存查看工具，查看 `gummipswriter.c` 生成的 MIPS 指令是否正确。错误的指令会导致程序崩溃或行为异常。
* **分析跳板代码:**  如果 hook 不生效，可能是生成的跳板代码有误，例如跳转地址错误、寄存器保存不正确等。
* **理解函数调用约定:**  如果函数参数传递或返回值处理出现问题，可能是因为 `gum_mips_writer_put_argument_list_setup` 等函数生成的代码不符合 MIPS 的调用约定。
* **检查标签引用:**  如果涉及跳转的逻辑出现问题，可以检查标签的定义和引用是否正确，`gum_mips_writer_flush` 是否成功解析了所有引用。

总而言之，`gummipswriter.c` 是 Frida 在 MIPS 架构上进行动态插桩的关键基础设施，理解它的功能对于深入理解 Frida 的工作原理以及调试 Frida 脚本至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/arch-mips/gummipswriter.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2014-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummipswriter.h"

#include "gumlibc.h"
#include "gummemory.h"

#if GLIB_SIZEOF_VOID_P == 8
# define GUM_MIPS_MAX_ARGS_IN_REGISTERS 8
#else
# define GUM_MIPS_MAX_ARGS_IN_REGISTERS 4
#endif

typedef struct _GumMipsLabelRef GumMipsLabelRef;
typedef guint GumMipsMemPairOperandSize;
typedef guint GumMipsMetaReg;
typedef struct _GumMipsRegInfo GumMipsRegInfo;

struct _GumMipsLabelRef
{
  gconstpointer id;
  guint32 * insn;
};

enum _GumMipsMetaReg
{
  GUM_MREG_R0,
  GUM_MREG_R1,
  GUM_MREG_R2,
  GUM_MREG_R3,
  GUM_MREG_R4,
  GUM_MREG_R5,
  GUM_MREG_R6,
  GUM_MREG_R7,
  GUM_MREG_R8,
  GUM_MREG_R9,
  GUM_MREG_R10,
  GUM_MREG_R11,
  GUM_MREG_R12,
  GUM_MREG_R13,
  GUM_MREG_R14,
  GUM_MREG_R15,
  GUM_MREG_R16,
  GUM_MREG_R17,
  GUM_MREG_R18,
  GUM_MREG_R19,
  GUM_MREG_R20,
  GUM_MREG_R21,
  GUM_MREG_R22,
  GUM_MREG_R23,
  GUM_MREG_R24,
  GUM_MREG_R25,
  GUM_MREG_R26,
  GUM_MREG_R27,
  GUM_MREG_R28,
  GUM_MREG_R29,
  GUM_MREG_R30,
  GUM_MREG_R31,

  GUM_MREG_HI,
  GUM_MREG_LO,

  GUM_MREG_ZERO = GUM_MREG_R0,
  GUM_MREG_AT = GUM_MREG_R1,
  GUM_MREG_V0 = GUM_MREG_R2,
  GUM_MREG_V1 = GUM_MREG_R3,
  GUM_MREG_A0 = GUM_MREG_R4,
  GUM_MREG_A1 = GUM_MREG_R5,
  GUM_MREG_A2 = GUM_MREG_R6,
  GUM_MREG_A3 = GUM_MREG_R7,
  GUM_MREG_T0 = GUM_MREG_R8,
  GUM_MREG_T1 = GUM_MREG_R9,
  GUM_MREG_T2 = GUM_MREG_R10,
  GUM_MREG_T3 = GUM_MREG_R11,
  GUM_MREG_T4 = GUM_MREG_R12,
  GUM_MREG_T5 = GUM_MREG_R13,
  GUM_MREG_T6 = GUM_MREG_R14,
  GUM_MREG_T7 = GUM_MREG_R15,
  GUM_MREG_S0 = GUM_MREG_R16,
  GUM_MREG_S1 = GUM_MREG_R17,
  GUM_MREG_S2 = GUM_MREG_R18,
  GUM_MREG_S3 = GUM_MREG_R19,
  GUM_MREG_S4 = GUM_MREG_R20,
  GUM_MREG_S5 = GUM_MREG_R21,
  GUM_MREG_S6 = GUM_MREG_R22,
  GUM_MREG_S7 = GUM_MREG_R23,
  GUM_MREG_T8 = GUM_MREG_R24,
  GUM_MREG_T9 = GUM_MREG_R25,
  GUM_MREG_K0 = GUM_MREG_R26,
  GUM_MREG_K1 = GUM_MREG_R27,
  GUM_MREG_GP = GUM_MREG_R28,
  GUM_MREG_SP = GUM_MREG_R29,
  GUM_MREG_FP = GUM_MREG_R30,
  GUM_MREG_S8 = GUM_MREG_R30,
  GUM_MREG_RA = GUM_MREG_R31,
};

struct _GumMipsRegInfo
{
  GumMipsMetaReg meta;
  guint width;
  guint index;
};

static void gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
    guint n_args, const GumArgument * args);
static void gum_mips_writer_put_argument_list_setup_va (GumMipsWriter * self,
    guint n_args, va_list args);
static void gum_mips_writer_put_argument_list_teardown (GumMipsWriter * self,
    guint n_args);

static void gum_mips_writer_describe_reg (GumMipsWriter * self, mips_reg reg,
    GumMipsRegInfo * ri);

GumMipsWriter *
gum_mips_writer_new (gpointer code_address)
{
  GumMipsWriter * writer;

  writer = g_slice_new (GumMipsWriter);

  gum_mips_writer_init (writer, code_address);

  return writer;
}

GumMipsWriter *
gum_mips_writer_ref (GumMipsWriter * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_mips_writer_unref (GumMipsWriter * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_mips_writer_clear (writer);

    g_slice_free (GumMipsWriter, writer);
  }
}

void
gum_mips_writer_init (GumMipsWriter * writer,
                      gpointer code_address)
{
  writer->ref_count = 1;
  writer->flush_on_destroy = TRUE;

  writer->label_defs = NULL;
  writer->label_refs.data = NULL;

  gum_mips_writer_reset (writer, code_address);
}

static gboolean
gum_mips_writer_has_label_defs (GumMipsWriter * self)
{
  return self->label_defs != NULL;
}

static gboolean
gum_mips_writer_has_label_refs (GumMipsWriter * self)
{
  return self->label_refs.data != NULL;
}

void
gum_mips_writer_clear (GumMipsWriter * writer)
{
  if (writer->flush_on_destroy)
    gum_mips_writer_flush (writer);

  if (gum_mips_writer_has_label_defs (writer))
    gum_metal_hash_table_unref (writer->label_defs);

  if (gum_mips_writer_has_label_refs (writer))
    gum_metal_array_free (&writer->label_refs);
}

void
gum_mips_writer_reset (GumMipsWriter * writer,
                       gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  if (gum_mips_writer_has_label_defs (writer))
    gum_metal_hash_table_remove_all (writer->label_defs);

  if (gum_mips_writer_has_label_refs (writer))
    gum_metal_array_remove_all (&writer->label_refs);
}

gpointer
gum_mips_writer_cur (GumMipsWriter * self)
{
  return self->code;
}

guint
gum_mips_writer_offset (GumMipsWriter * self)
{
  return (guint) (self->code - self->base) * sizeof (guint32);
}

void
gum_mips_writer_skip (GumMipsWriter * self,
                      guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

gboolean
gum_mips_writer_flush (GumMipsWriter * self)
{
  guint num_refs, ref_index;

  if (!gum_mips_writer_has_label_refs (self))
    return TRUE;

  if (!gum_mips_writer_has_label_defs (self))
    return FALSE;

  num_refs = self->label_refs.length;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumMipsLabelRef * r;
    const guint32 * target_insn;
    gssize distance;
    guint32 insn;

    r = gum_metal_array_element_at (&self->label_refs, ref_index);

    target_insn = gum_metal_hash_table_lookup (self->label_defs, r->id);
    if (target_insn == NULL)
      goto error;

    distance = target_insn - r->insn;

    insn = *r->insn;
    /* j <int16> */
    if (insn == 0x08000000)
    {
      if (!GUM_IS_WITHIN_INT18_RANGE (distance << 2))
        goto error;
      insn |= distance & GUM_INT16_MASK;
    }
    /* beq <int16> */
    else if ((insn & 0xfc000000) == 0x10000000)
    {
      if (!GUM_IS_WITHIN_INT18_RANGE (distance << 2))
        goto error;
      insn |= distance & GUM_INT16_MASK;
    }
    /* TODO: conditional branches */
    else if ((insn & 0x7e000000) == 0x36000000)
    {
      if (!GUM_IS_WITHIN_INT14_RANGE (distance))
        goto error;
      insn |= (distance & GUM_INT14_MASK) << 5;
    }
    else
    {
      if (!GUM_IS_WITHIN_INT19_RANGE (distance))
        goto error;
      insn |= (distance & GUM_INT19_MASK) << 5;
    }

    *r->insn = insn;
  }

  gum_metal_array_remove_all (&self->label_refs);

  return TRUE;

error:
  {
    gum_metal_array_remove_all (&self->label_refs);

    return FALSE;
  }
}

gboolean
gum_mips_writer_put_label (GumMipsWriter * self,
                           gconstpointer id)
{
  if (!gum_mips_writer_has_label_defs (self))
    self->label_defs = gum_metal_hash_table_new (NULL, NULL);

  if (gum_metal_hash_table_lookup (self->label_defs, id) != NULL)
    return FALSE;

  gum_metal_hash_table_insert (self->label_defs, (gpointer) id, self->code);

  return TRUE;
}

static void
gum_mips_writer_add_label_reference_here (GumMipsWriter * self,
                                          gconstpointer id)
{
  GumMipsLabelRef * r;

  if (!gum_mips_writer_has_label_refs (self))
    gum_metal_array_init (&self->label_refs, sizeof (GumMipsLabelRef));

  r = gum_metal_array_append (&self->label_refs);
  r->id = id;
  r->insn = self->code;
}

void
gum_mips_writer_put_call_address_with_arguments (GumMipsWriter * self,
                                                 GumAddress func,
                                                 guint n_args,
                                                 ...)
{
  va_list args;

  va_start (args, n_args);
  gum_mips_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  mips_reg target = MIPS_REG_T9;
  gum_mips_writer_put_la_reg_address (self, target, func);
  gum_mips_writer_put_jalr_reg (self, target);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

void
gum_mips_writer_put_call_address_with_arguments_array (
    GumMipsWriter * self,
    GumAddress func,
    guint n_args,
    const GumArgument * args)
{
  gum_mips_writer_put_argument_list_setup (self, n_args, args);

  mips_reg target = MIPS_REG_T9;
  gum_mips_writer_put_la_reg_address (self, target, func);
  gum_mips_writer_put_jalr_reg (self, target);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

void
gum_mips_writer_put_call_reg_with_arguments (GumMipsWriter * self,
                                             mips_reg reg,
                                             guint n_args,
                                             ...)
{
  va_list args;

  va_start (args, n_args);
  gum_mips_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  gum_mips_writer_put_jalr_reg (self, reg);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

void
gum_mips_writer_put_call_reg_with_arguments_array (GumMipsWriter * self,
                                                   mips_reg reg,
                                                   guint n_args,
                                                   const GumArgument * args)
{
  gum_mips_writer_put_argument_list_setup (self, n_args, args);

  gum_mips_writer_put_jalr_reg (self, reg);

  gum_mips_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_mips_writer_put_argument_list_setup (GumMipsWriter * self,
                                         guint n_args,
                                         const GumArgument * args)
{
  gint arg_index;

  for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
  {
    const GumArgument * arg = &args[arg_index];
    mips_reg r = MIPS_REG_A0 + arg_index;

    if (arg_index < GUM_MIPS_MAX_ARGS_IN_REGISTERS)
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_mips_writer_put_la_reg_address (self, r, arg->value.address);
      }
      else
      {
        if (arg->value.reg != r)
          gum_mips_writer_put_move_reg_reg (self, r, arg->value.reg);
      }
    }
    else
    {
      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_mips_writer_put_la_reg_address (self, MIPS_REG_A0,
            arg->value.address);
        gum_mips_writer_put_push_reg (self, MIPS_REG_A0);
      }
      else
      {
        gum_mips_writer_put_push_reg (self, arg->value.reg);
      }
    }
  }
}

static void
gum_mips_writer_put_argument_list_setup_va (GumMipsWriter * self,
                                            guint n_args,
                                            va_list args)
{
  GumArgument * arg_values;
  guint arg_index;

  arg_values = g_newa (GumArgument, n_args);

  for (arg_index = 0; arg_index != n_args; arg_index++)
  {
    GumArgument * arg = &arg_values[arg_index];

    arg->type = va_arg (args, GumArgType);
    if (arg->type == GUM_ARG_ADDRESS)
      arg->value.address = va_arg (args, GumAddress);
    else if (arg->type == GUM_ARG_REGISTER)
      arg->value.reg = va_arg (args, mips_reg);
    else
      g_assert_not_reached ();
  }

  gum_mips_writer_put_argument_list_setup (self, n_args, arg_values);
}

static void
gum_mips_writer_put_argument_list_teardown (GumMipsWriter * self,
                                            guint n_args)
{
  if (n_args > GUM_MIPS_MAX_ARGS_IN_REGISTERS)
  {
    gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP,
        (n_args - GUM_MIPS_MAX_ARGS_IN_REGISTERS) * GLIB_SIZEOF_VOID_P);
  }
}

gboolean
gum_mips_writer_can_branch_directly_between (GumAddress from,
                                             GumAddress to)
{
#if GLIB_SIZEOF_VOID_P == 8
  const gint64 lower_limit = (from & G_GUINT64_CONSTANT (0xfffffffff0000000));
  const gint64 upper_limit = (from & G_GUINT64_CONSTANT (0xfffffffff0000000)) +
      GUM_INT28_MASK;
#else
  const gint64 lower_limit = (from & 0xf0000000);
  const gint64 upper_limit = (from & 0xf0000000) + GUM_INT28_MASK;
#endif

  return lower_limit < to && to < upper_limit;
}

gboolean
gum_mips_writer_put_j_address (GumMipsWriter * self,
                               GumAddress address)
{
  if (!gum_mips_writer_put_j_address_without_nop (self, address))
    return FALSE;

  gum_mips_writer_put_nop (self);

  return TRUE;
}

gboolean
gum_mips_writer_put_j_address_without_nop (GumMipsWriter * self,
                                           GumAddress address)
{
  if ((address & G_GUINT64_CONSTANT (0xfffffffff0000000)) !=
      (self->pc & G_GUINT64_CONSTANT (0xfffffffff0000000)) ||
      address % 4 != 0)
  {
    return FALSE;
  }

  gum_mips_writer_put_instruction (self,
      0x08000000 | ((address & GUM_INT28_MASK) / 4));

  return TRUE;
}

void
gum_mips_writer_put_j_label (GumMipsWriter * self,
                             gconstpointer label_id)
{
  gum_mips_writer_add_label_reference_here (self, label_id);
  gum_mips_writer_put_instruction (self, 0x08000000);
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jr_reg (GumMipsWriter * self,
                            mips_reg reg)
{
  GumMipsRegInfo ri;

  gum_mips_writer_describe_reg (self, reg, &ri);

  gum_mips_writer_put_instruction (self, 0x00000008 | (ri.index << 21));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jal_address (GumMipsWriter * self,
                                 guint32 address)
{
  gum_mips_writer_put_instruction (self, 0x0c000000 |
      ((address & GUM_INT28_MASK) >> 2));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_jalr_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo ri;

  gum_mips_writer_describe_reg (self, reg, &ri);

  gum_mips_writer_put_instruction (self, 0x00000009 | (ri.index << 21) |
      (GUM_MREG_RA << 11));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_b_offset (GumMipsWriter * self,
                              gint32 offset)
{
  gum_mips_writer_put_instruction (self, 0x10000000 | ((offset >> 2) & 0xffff));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_beq_reg_reg_label (GumMipsWriter * self,
                                       mips_reg right_reg,
                                       mips_reg left_reg,
                                       gconstpointer label_id)
{
  GumMipsRegInfo rs, rt;

  gum_mips_writer_describe_reg (self, right_reg, &rs);
  gum_mips_writer_describe_reg (self, left_reg, &rt);

  gum_mips_writer_add_label_reference_here (self, label_id);
  gum_mips_writer_put_instruction (self, 0x01000000 | (rs.index << 21) |
      (rt.index << 16));
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_ret (GumMipsWriter * self)
{
  gum_mips_writer_put_jr_reg (self, MIPS_REG_RA);
  gum_mips_writer_put_nop (self);
}

void
gum_mips_writer_put_la_reg_address (GumMipsWriter * self,
                                    mips_reg reg,
                                    GumAddress address)
{
#if GLIB_SIZEOF_VOID_P == 8
  gum_mips_writer_put_lui_reg_imm (self, reg, (address >> 48));
  gum_mips_writer_put_ori_reg_reg_imm (self, reg, reg,
      (address >> 32) & 0xffff);

  gum_mips_writer_put_dsll_reg_reg (self, reg, reg, 16);
  gum_mips_writer_put_ori_reg_reg_imm (self, reg, reg,
      (address >> 16) & 0xffff);

  gum_mips_writer_put_dsll_reg_reg (self, reg, reg, 16);
  gum_mips_writer_put_ori_reg_reg_imm (self, reg, reg, address & 0xffff);
#else
  gum_mips_writer_put_lui_reg_imm (self, reg, address >> 16);
  gum_mips_writer_put_ori_reg_reg_imm (self, reg, reg, address & 0xffff);
#endif
}

void
gum_mips_writer_put_lui_reg_imm (GumMipsWriter * self,
                                 mips_reg reg,
                                 guint imm)
{
  GumMipsRegInfo ri;

  gum_mips_writer_describe_reg (self, reg, &ri);

  gum_mips_writer_put_instruction (self, 0x3c000000 | (ri.index << 16) |
      (imm & 0xffff));
}

void
gum_mips_writer_put_dsll_reg_reg (GumMipsWriter * self,
                                  mips_reg dst_reg,
                                  mips_reg src_reg,
                                  guint amount)
{
  GumMipsRegInfo rd, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, src_reg, &rs);
  g_assert ((amount & 0x1f) == amount);

  gum_mips_writer_put_instruction (self, (rs.index << 16) | (rd.index << 11) |
      (amount << 6) | 0x38);
}

void
gum_mips_writer_put_ori_reg_reg_imm (GumMipsWriter * self,
                                     mips_reg dst_reg,
                                     mips_reg src_reg,
                                     guint imm)
{
  GumMipsRegInfo rd, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, src_reg, &rs);

  gum_mips_writer_put_instruction (self, 0x34000000 | (rd.index << 16) |
      (rs.index << 21) | (imm & 0xffff));
}

void
gum_mips_writer_put_ld_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg dst_reg,
                                       mips_reg src_reg,
                                       gsize src_offset)
{
  GumMipsRegInfo rd, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, src_reg, &rs);

  gum_mips_writer_put_instruction (self, 0x68000000 | (rs.index << 21) |
      (rd.index << 16) | src_offset);
}

void
gum_mips_writer_put_lw_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg dst_reg,
                                       mips_reg src_reg,
                                       gsize src_offset)
{
  GumMipsRegInfo rd, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, src_reg, &rs);

  /*
   * A number of the other MIPS instructions being written here need to
   * be modified. MIPS64 retained backward compatibility with MIPS32 and
   * introduced new instructions for 64 bit data manipulation. MIPS
   * refers to these as doublewords. The mnemonic for the instruction
   * is different to the original.
   */
  gum_mips_writer_put_instruction (self,
#if GLIB_SIZEOF_VOID_P == 8
      0xdc000000
#else
      0x8c000000
#endif
      | (rs.index << 21) | (rd.index << 16) | (src_offset & 0xffff));
}

void
gum_mips_writer_put_sw_reg_reg_offset (GumMipsWriter * self,
                                       mips_reg src_reg,
                                       mips_reg dst_reg,
                                       gsize dst_offset)
{
  GumMipsRegInfo rs, rd;

  gum_mips_writer_describe_reg (self, src_reg, &rs);
  gum_mips_writer_describe_reg (self, dst_reg, &rd);

  gum_mips_writer_put_instruction (self,
      /* See MIPS64 comment in put_lw_reg_reg_offset(). */
#if GLIB_SIZEOF_VOID_P == 8
      0xfc000000
#else
      0xac000000
#endif
      | (rd.index << 21) | (rs.index << 16) | (dst_offset & 0xffff));
}

void
gum_mips_writer_put_move_reg_reg (GumMipsWriter * self,
                                  mips_reg dst_reg,
                                  mips_reg src_reg)
{
  gum_mips_writer_put_addu_reg_reg_reg (self, dst_reg, src_reg, MIPS_REG_ZERO);
}

void
gum_mips_writer_put_addu_reg_reg_reg (GumMipsWriter * self,
                                      mips_reg dst_reg,
                                      mips_reg left_reg,
                                      mips_reg right_reg)
{
  GumMipsRegInfo rs, rt, rd;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, left_reg, &rs);
  gum_mips_writer_describe_reg (self, right_reg, &rt);

  gum_mips_writer_put_instruction (self,
      /* See MIPS64 comment in put_lw_reg_reg_offset(). */
#if GLIB_SIZEOF_VOID_P == 8
      0x000000a5
#else
      0x00000021
#endif
      | (rs.index << 21) | (rt.index << 16) | (rd.index << 11));
}

void
gum_mips_writer_put_addi_reg_reg_imm (GumMipsWriter * self,
                                      mips_reg dst_reg,
                                      mips_reg left_reg,
                                      gint32 imm)
{
  GumMipsRegInfo rd, rs;

  gum_mips_writer_describe_reg (self, dst_reg, &rd);
  gum_mips_writer_describe_reg (self, left_reg, &rs);

  g_assert (GUM_IS_WITHIN_INT16_RANGE (imm));

  gum_mips_writer_put_instruction (self,
      /* See MIPS64 comment in put_lw_reg_reg_offset(). */
#if GLIB_SIZEOF_VOID_P == 8
      0x64000000
#else
      0x20000000
#endif
      | (rs.index << 21) | (rd.index << 16) | (imm & 0xffff));
}

void
gum_mips_writer_put_addi_reg_imm (GumMipsWriter * self,
                                  mips_reg dst_reg,
                                  gint32 imm)
{
  gum_mips_writer_put_addi_reg_reg_imm (self, dst_reg, dst_reg, imm);
}

void
gum_mips_writer_put_sub_reg_reg_imm (GumMipsWriter * self,
                                     mips_reg dst_reg,
                                     mips_reg left_reg,
                                     gint32 imm)
{
  gum_mips_writer_put_addi_reg_reg_imm (self, dst_reg, left_reg, -imm);
}

void
gum_mips_writer_put_push_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_mips_writer_put_sw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
}

void
gum_mips_writer_put_pop_reg (GumMipsWriter * self,
                             mips_reg reg)
{
  gum_mips_writer_put_lw_reg_reg_offset (self, reg, MIPS_REG_SP, 0);
  gum_mips_writer_put_addi_reg_imm (self, MIPS_REG_SP, sizeof (gsize));
}

void
gum_mips_writer_put_mfhi_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rd;

  gum_mips_writer_describe_reg (self, reg, &rd);

  gum_mips_writer_put_instruction (self, 0x00000010 | (rd.index << 11));
}

void
gum_mips_writer_put_mflo_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rd;

  gum_mips_writer_describe_reg (self, reg, &rd);

  gum_mips_writer_put_instruction (self, 0x00000012 | (rd.index << 11));
}

void
gum_mips_writer_put_mthi_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rs;

  gum_mips_writer_describe_reg (self, reg, &rs);

  gum_mips_writer_put_instruction (self, 0x00000011 | (rs.index << 21));
}

void
gum_mips_writer_put_mtlo_reg (GumMipsWriter * self,
                              mips_reg reg)
{
  GumMipsRegInfo rs;

  gum_mips_writer_describe_reg (self, reg, &rs);

  gum_mips_writer_put_instruction (self, 0x00000013 | (rs.index << 21));
}

void
gum_mips_writer_put_nop (GumMipsWriter * self)
{
  gum_mips_writer_put_instruction (self, 0x00000000);
}

void
gum_mips_writer_put_break (GumMipsWriter * self)
{
  gum_mips_writer_put_instruction (self, 0x0000000d);
}

void
gum_mips_writer_put_prologue_trampoline (GumMipsWriter * self,
                                         mips_reg reg,
                                         GumAddress address)
{
  /*
   * This builds our minimal sized trampoline. We place our address raw into the
   * instruction stream and jump over it. We use R9 (which points to the start
   * of the function) to reference the immediate in the instruction stream. Note
   * that this load is executed from the branch delay slot. Finally, MIPS64 only
   * supports aligned 64 bit loads and hence we must align the address in the
   * instruction stream accordingly. We can see therefore that the trampoline is
   * one instruction larger if the function is not 64 bit aligned (the
   * instruction stream need only be 32 bit aligned).
   */
  if (self->pc % 8 == 0)
  {
    gum_mips_writer_put_j_address_without_nop (self, self->pc + 0x10);
    gum_mips_writer_put_ld_reg_reg_offset (self, reg, MIPS_REG_T9, 0x8);
  }
  else
  {
    gum_mips_writer_put_j_address_without_nop (self, self->pc + 0x14);
    gum_mips_writer_put_ld_reg_reg_offset (self, reg, MIPS_REG_T9, 0xc);
    gum_mips_writer_put_nop (self);
  }
  g_assert (self->pc % 8 == 0);

  gum_mips_writer_put_instruction (self, address >> 32);
  gum_mips_writer_put_instruction (self, address & 0xffffffff);
  gum_mips_writer_put_jr_reg (self, reg);
}

void
gum_mips_writer_put_instruction (GumMipsWriter * self,
                                 guint32 insn)
{
  *self->code++ = insn;
  self->pc += 4;
}

gboolean
gum_mips_writer_put_bytes (GumMipsWriter * self,
                           const guint8 * data,
                           guint n)
{
  if (n % 4 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;

  return TRUE;
}

static void
gum_mips_writer_describe_reg (GumMipsWriter * self,
                              mips_reg reg,
                              GumMipsRegInfo * ri)
{
  if (reg >= MIPS_REG_0 && reg <= MIPS_REG_31)
  {
    ri->meta = GUM_MREG_R0 + (reg - MIPS_REG_0);
    ri->width = GLIB_SIZEOF_VOID_P * 8;
    ri->index = ri->meta - GUM_MREG_R0;
  }
  else if (reg == MIPS_REG_HI)
  {
    ri->meta = GUM_MREG_HI;
    ri->width = GLIB_SIZEOF_VOID_P * 8;
    ri->index = -1;
  }
  else if (reg == MIPS_REG_LO)
  {
    ri->meta = GUM_MREG_LO;
    ri->width = GLIB_SIZEOF_VOID_P * 8;
    ri->index = -1;
  }
  else
  {
    g_assert_not_reached ();
  }
}
```