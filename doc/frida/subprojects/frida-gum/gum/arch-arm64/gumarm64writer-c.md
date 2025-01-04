Response:
Let's break down the thought process for analyzing this C code snippet.

1. **Understand the Goal:** The primary goal is to analyze the provided C code for the `gumarm64writer.c` file, which is part of Frida, a dynamic instrumentation toolkit. The request asks for the file's functionality, its relation to reverse engineering, low-level concepts, logical reasoning, potential user errors, and debugging.

2. **Initial Scan and Keywords:**  Start by quickly scanning the code for important keywords and structures. This immediately reveals:
    * `#include`:  Standard C includes, suggesting dependencies on other Frida components (`gumlibc.h`, `gummemory.h`, `gumprocess.h`).
    * `typedef`:  Custom type definitions, indicating abstractions over basic types. Look for structures like `GumArm64LabelRef`, `GumArm64LiteralRef`, etc. These suggest the code deals with labels, literals, and other code-related concepts.
    * `enum`:  Enumerated types define sets of named constants. These are crucial for understanding the different types of operations and operands the writer handles (e.g., `GUM_ARM64_B`, `GUM_MEM_OPERATION_STORE`).
    * `struct`: Structures define data layouts. Pay attention to members like `insn` (instruction), `id` (label identifier), `val` (value), `type`, and register information.
    * Function declarations (look for function names followed by parentheses). Notice prefixes like `gum_arm64_writer_` and actions like `put_`, `get_`, `reset_`, `flush_`, `describe_`. This strongly suggests a "writer" pattern for generating ARM64 assembly instructions.
    * `static`: Indicates functions or variables with internal linkage (scoped to this file).
    * `gboolean`, `guint`, `gint`, `GumAddress`: These are likely GLib/GObject types, suggesting a dependency on that library.

3. **Identify Core Functionality:** Based on the initial scan, the core functionality seems to revolve around:
    * **Writing ARM64 Instructions:** The `put_` prefix in many function names strongly suggests this. Look for patterns like `put_b_imm`, `put_ldr_reg_address`, etc. These likely correspond to specific ARM64 instructions.
    * **Managing Labels and Literals:** The `GumArm64LabelRef` and `GumArm64LiteralRef` structures, along with functions like `gum_arm64_writer_put_label`, `gum_arm64_writer_add_label_reference_here`, and `gum_arm64_writer_add_literal_reference_here`, point to this.
    * **Handling Function Calls and Branches:** Functions like `gum_arm64_writer_put_call_address_with_arguments`, `gum_arm64_writer_put_branch_address`, and `gum_arm64_writer_put_b_imm` confirm this.
    * **Register Management:** The `GumArm64RegInfo` structure and functions like `gum_arm64_writer_describe_reg` indicate the writer keeps track of registers.
    * **Memory Operations:**  `GUM_MEM_OPERATION_STORE`, `GUM_MEM_OPERATION_LOAD`, and functions like `gum_arm64_writer_put_load_store_pair` clearly deal with memory access.

4. **Relate to Reverse Engineering:** Think about how the identified functionalities relate to reverse engineering:
    * **Dynamic Code Generation:** The ability to write ARM64 instructions is fundamental for dynamic instrumentation. Frida intercepts execution and inserts new code at runtime. This writer is a key component for building that injected code.
    * **Instruction Manipulation:**  Reverse engineers need to understand and potentially modify instructions. This writer provides the low-level building blocks for doing so programmatically.
    * **Function Hooking:**  Injecting calls to custom functions is a common reverse engineering technique. The writer's call-related functions facilitate this.
    * **Code Analysis:**  Understanding how the writer constructs instructions can aid in analyzing existing code.

5. **Connect to Low-Level Concepts:**  Consider the underlying computer architecture and operating system concepts involved:
    * **ARM64 Architecture:** The entire file is specific to ARM64. Knowledge of ARM64 instruction sets, registers, addressing modes, and calling conventions is essential.
    * **Binary Encoding:**  The writer ultimately generates binary machine code. The code deals with bitwise operations and understanding the encoding of ARM64 instructions.
    * **Memory Management:**  The writer operates on memory where code is executed. Concepts like code sections, memory protection, and address spaces are relevant.
    * **Operating System (Linux/Android Kernel):**  The generated code will run within the context of the OS kernel or user-space processes. Understanding system calls, process memory layouts, and potentially kernel internals is helpful.
    * **Function Calling Conventions (AAPCS64):** The way arguments are passed in registers (X0-X7) aligns with the ARM64 calling convention.

6. **Identify Logical Reasoning:** Look for conditional logic and calculations:
    * **Branch Range Checks:** The `gum_arm64_writer_can_branch_directly_between` function and the checks within `gum_arm64_writer_put_b_imm` demonstrate logical reasoning about branch distances.
    * **Label Resolution:** The process of storing label references and then resolving them later involves logical steps.
    * **Literal Pool Management:**  The logic for managing literal values and placing them in memory.

7. **Consider User Errors:**  Think about how a developer using this writer might make mistakes:
    * **Incorrect Register Usage:**  Using the wrong register type or width for an operation.
    * **Out-of-Range Branches:**  Trying to branch to an address too far away for a direct branch instruction.
    * **Mismatched Push/Pop:**  Unbalanced stack operations.
    * **Incorrect Argument Passing:**  Not setting up arguments correctly before a function call.

8. **Trace User Operations (Debugging):** Imagine how a user might interact with Frida and end up using this code:
    * **Frida Script:** A user writes a JavaScript or Python script using the Frida API.
    * **Interception:** The script intercepts a function or code location.
    * **Code Modification:** The script uses Frida's `Stalker` or similar to modify the code.
    * **`GumArm64Writer` Usage:** Frida internally uses the `GumArm64Writer` to generate the new ARM64 instructions to be injected.

9. **Synthesize and Organize:** Finally, organize the findings into the requested categories. Start with the main functionality and then elaborate on each of the other points with specific examples from the code. Focus on being clear and concise. Use code snippets to illustrate your points whenever possible. For the "assumptions" part, explicitly create scenarios and describe the expected input and output of specific functions.

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too much on individual functions.**  It's important to step back and understand the *overall* purpose of the file.
* **I might overlook the connections to higher-level Frida concepts.**  It's crucial to relate the low-level C code to how it's used in the broader context of dynamic instrumentation.
* **I might not provide concrete examples.**  Abstract descriptions are less helpful than illustrating points with specific function calls or code snippets. For instance, instead of saying "handles branches," show an example like `gum_arm64_writer_put_b_imm`.
* **I need to ensure I address *all* parts of the prompt.** Double-check that I've covered reverse engineering, low-level details, logic, errors, and debugging.好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/arch-arm64/gumarm64writer.c` 这个文件的功能。

**文件功能归纳（第 1 部分）:**

`gumarm64writer.c` 文件是 Frida 工具中用于在 ARM64 架构上动态生成机器码的关键组件。它提供了一组 API，允许开发者以编程方式构建和写入 ARM64 汇编指令到内存中。  可以将其视为一个汇编代码生成器，但它是以 C 语言实现的，并且专门为了在运行时修改目标进程的指令而设计。

**更具体的功能点包括：**

1. **指令写入:** 提供各种函数 (以 `gum_arm64_writer_put_` 开头) 用于写入不同的 ARM64 指令，例如：
    * **跳转指令:** `b`, `bl`, `br`, `blr`, `cbz`, `cbnz`, `tbz`, `tbnz` 等。
    * **数据加载/存储指令:** `ldr`, `str`, `push`, `pop` 等。
    * **算术/逻辑指令:** (虽然此部分代码未展示，但推测在其他部分会有)。
    * **移动指令:** `mov` 等。
    * **返回指令:** `ret`。
2. **标签管理:** 允许定义标签 (`gum_arm64_writer_put_label`) 并在后续指令中引用这些标签，方便生成跳转目标不确定的代码。
3. **立即数处理:**  能够将立即数加载到寄存器 (`gum_arm64_writer_put_ldr_reg_u32`, `gum_arm64_writer_put_ldr_reg_u64`)。
4. **函数调用:** 提供方便的函数 (`gum_arm64_writer_put_call_address_with_arguments`, `gum_arm64_writer_put_call_reg_with_arguments`) 来生成函数调用代码，并处理参数传递。
5. **代码回填 (Code Relocation/Patching):**  虽然代码中没有直接体现“回填”这个词，但其核心功能就是修改内存中的代码，这与代码回填的概念紧密相关。通过生成新的指令序列，可以替换或插入到目标进程的现有代码中。
6. **引用管理:**  维护着标签引用 (`GumArm64LabelRef`) 和字面量引用 (`GumArm64LiteralRef`)，以便在后续处理中解析这些引用，确定跳转目标或加载字面量的地址。
7. **状态管理:**  维护着写入器的状态，例如当前代码写入的位置 (`writer->code`)，基地址 (`writer->base`) 和程序计数器 (`writer->pc`)。
8. **刷新机制:**  `gum_arm64_writer_flush` 函数用于提交所有待处理的标签和字面量引用，确保生成的代码的完整性。

---

**与逆向方法的关联及举例说明:**

`gumarm64writer.c` 是 Frida 动态插桩的核心，而动态插桩是逆向工程中一种强大的技术。

**举例说明:**

假设我们需要 hook 一个函数 `target_function`，并在其执行前后打印一些信息。

1. **找到目标函数地址:**  逆向工程师首先需要通过静态分析或动态调试等手段，找到 `target_function` 在内存中的地址。
2. **分配内存:** Frida 需要在目标进程中分配一块新的可执行内存，用于存放我们注入的 hook 代码。
3. **使用 `gumarm64writer` 生成 hook 代码:**  我们可以使用 `gumarm64writer` 来生成以下 ARM64 指令序列：
    * **保存现场:**  `gum_arm64_writer_put_push_all_x_registers` (保存所有通用寄存器)。
    * **调用自定义的 pre-hook 函数:**
        * `gum_arm64_writer_put_ldr_reg_address(writer, ARM64_REG_X0, pre_hook_function_address);` (将 `pre_hook_function` 的地址加载到 X0 寄存器)
        * `gum_arm64_writer_put_blr_reg(writer, ARM64_REG_X0);` (调用 `pre_hook_function`)
    * **跳转回原始函数:**
        * 如果我们想在原始函数执行后继续执行 hook 代码，则需要保存原始函数的指令，并在 pre-hook 执行后跳转回原始函数。这可能涉及到复制原始指令，或者直接跳转到原始函数。
        * 如果我们想替换原始函数，则直接跳转到原始函数后面我们定义的 post-hook 代码。
    * **恢复现场 (如果需要):** `gum_arm64_writer_put_pop_all_x_registers`。
    * **调用自定义的 post-hook 函数:**  类似于 pre-hook。
    * **跳转回原始函数的返回地址:**  通常需要保存原始函数的返回地址（在 LR 寄存器中），然后在 post-hook 执行后跳转回去。`gum_arm64_writer_put_ret(writer);`

在这个过程中，`gumarm64writer` 负责将这些高级的 "保存现场"、"调用函数"、"跳转" 等操作翻译成实际的 ARM64 机器码。

---

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

`gumarm64writer.c` 的工作直接与底层的二进制指令相关，并且在 Frida 的使用场景中，经常会涉及到操作系统内核和框架。

**举例说明:**

1. **ARM64 指令集:**  `gumarm64writer` 需要开发者理解 ARM64 指令的编码格式、操作码、寻址方式等。例如，`gum_arm64_writer_put_b_imm` 函数中，需要根据目标地址计算出相对偏移量，并将其编码到 `b` 指令的特定位域中。 这直接涉及到 ARM64 架构的指令格式知识。
2. **寄存器约定:** 函数调用时，参数通常通过特定的寄存器传递（例如，前几个参数通过 X0-X7 传递）。 `gum_arm64_writer_put_call_address_with_arguments` 函数就需要根据参数数量和类型，将参数加载到正确的寄存器中，这需要了解 ARM64 的调用约定 (Application Binary Interface, ABI)。
3. **内存布局:**  在进行 hook 操作时，需要知道代码段、数据段、堆栈等内存区域的分布，以便将注入的代码放置在合适的位置。`gumarm64writer` 生成的代码会被写入到目标进程的可执行内存区域。
4. **内存保护机制:**  操作系统为了安全，通常会对内存区域进行保护，例如代码段通常是只读的。 Frida 需要通过一些技术手段（例如，修改内存页的权限）来使得 `gumarm64writer` 能够写入指令。
5. **动态链接:**  在 hook 共享库中的函数时，需要考虑动态链接的过程。目标函数的实际地址可能在运行时才确定。 `gumarm64writer` 生成的代码可能需要间接跳转或者使用 GOT (Global Offset Table) 表来访问这些地址。
6. **Android Framework:** 在 Android 环境下，hook 系统服务或者应用层代码时，会涉及到 ART (Android Runtime) 虚拟机和 Android Framework 的知识。例如，需要了解 ART 的对象模型、方法调用机制等，才能正确地 hook Java 代码或者 Native 代码。
7. **内核交互 (可能间接涉及):** 虽然 `gumarm64writer` 本身运行在用户空间，但 Frida 的底层机制可能涉及到内核模块或者系统调用，以便进行内存分配、权限修改等操作。

---

**逻辑推理、假设输入与输出:**

`gumarm64writer` 中存在很多逻辑推理，尤其是在处理跳转指令和标签时。

**举例说明:**

假设我们使用以下代码：

```c
GumArm64Writer* writer = gum_arm64_writer_new(code_buffer);
GumAddress label_address;

gum_arm64_writer_put_label(writer, "my_label");
label_address = gum_arm64_writer_cur(writer); // 假设标签定义在当前位置

gum_arm64_writer_put_mov_imm(writer, ARM64_REG_W0, 10);
gum_arm64_writer_put_b_label(writer, "my_label"); // 回跳到标签位置
gum_arm64_writer_put_mov_imm(writer, ARM64_REG_W0, 20);

gum_arm64_writer_flush(writer);
```

**假设输入:**

* `code_buffer`: 指向一块可写的内存区域。
* "my_label" 字符串作为标签 ID。

**逻辑推理:**

1. 当调用 `gum_arm64_writer_put_label(writer, "my_label")` 时，writer 会将标签 "my_label" 与当前的写入地址关联起来。
2. `gum_arm64_writer_put_b_label(writer, "my_label")` 被调用时，writer 会创建一个对 "my_label" 的引用，并生成一个占位的 `b` 指令。由于此时标签的实际地址已知，`gum_arm64_writer_flush` 会计算出从当前 `b` 指令到标签定义地址的相对偏移，并更新该 `b` 指令的机器码，使其跳转到正确的地址。

**预期输出 (大致的汇编指令序列):**

```assembly
my_label:
  mov w0, #0xa  // 移动立即数 10 到 w0
  b <相对偏移到 my_label> // 无条件跳转回到 my_label
  mov w0, #0x14 // 移动立即数 20 到 w0 (这行代码不会被执行，因为上面发生了跳转)
```

**更底层的二进制输出 (示例):**

假设 `my_label` 的地址是 `0x1000`，`b` 指令的地址是 `0x1004`，则相对偏移是 `-4`。 `b` 指令的编码格式会包含这个偏移量。

---

**用户或编程常见的使用错误及举例说明:**

使用 `gumarm64writer` 时，常见的错误包括对 ARM64 指令集的不熟悉，以及对 API 使用不当。

**举例说明:**

1. **尝试写入超出范围的立即数:**

```c
gum_arm64_writer_put_mov_imm(writer, ARM64_REG_W0, 0xFFFFFFFF0); // 错误：32 位寄存器无法直接加载 64 位立即数
```

解决方法是使用 `gum_arm64_writer_put_ldr_reg_u64` 将 64 位立即数从内存加载到寄存器。

2. **跳转目标超出范围:**

```c
GumAddress target_address = some_very_far_address;
gum_arm64_writer_put_b_imm(writer, target_address); // 错误：如果 target_address 距离当前位置太远，`b` 指令无法直接跳转
```

解决方法是使用间接跳转：先将目标地址加载到寄存器，然后使用 `br` 指令跳转。

3. **忘记 `flush` 操作:**

```c
GumArm64Writer* writer = gum_arm64_writer_new(code_buffer);
gum_arm64_writer_put_b_label(writer, "my_label");
// 忘记调用 gum_arm64_writer_flush(writer);
```

如果没有调用 `flush`，标签引用将不会被解析，生成的代码可能无法正确跳转。

4. **寄存器类型不匹配:**

```c
gum_arm64_writer_put_str_reg_reg_offset(writer, ARM64_REG_W0, ARM64_REG_X1, 0); // 错误：尝试将 32 位寄存器的值存储到 X1 指向的内存，但 str 指令需要指定存储的大小
```

需要根据操作数的大小选择正确的指令变体（例如 `strw` 用于存储 32 位值）。

---

**用户操作如何一步步到达这里作为调试线索:**

当用户在使用 Frida 进行动态插桩时，如果遇到了与 ARM64 代码生成相关的问题，调试线索可能会引导他们查看 `gumarm64writer.c`。

**调试步骤示例:**

1. **Frida 脚本报错:** 用户编写了一个 Frida 脚本，尝试 hook 某个 ARM64 函数，但脚本运行时报错，提示生成的代码无效或导致程序崩溃。
2. **查看 Frida 的日志或错误信息:**  Frida 可能会输出一些底层的错误信息，例如 "Invalid instruction encoding" 或者崩溃时的指令地址。
3. **定位到代码生成阶段:**  通过分析错误信息，用户可能会发现问题出在 Frida 尝试生成 ARM64 指令的阶段。
4. **检查 Frida 的源码 (可选):**  如果用户对 Frida 的内部实现比较熟悉，或者想深入了解问题，可能会查看 Frida 的 C 源码。
5. **关注 `GumArm64Writer`:**  由于错误与 ARM64 指令生成有关，用户会自然而然地关注 `gumarm64writer.c` 这个文件，因为它负责生成 ARM64 机器码。
6. **检查 `put_` 函数的调用:** 用户可能会检查 Frida 的其他模块是如何调用 `gumarm64writer` 的 `put_` 系列函数，以及传递的参数是否正确。
7. **分析生成的指令:**  用户可以使用反汇编工具查看 Frida 实际生成的机器码，并与预期的指令进行对比，从而找出编码错误或者逻辑错误。
8. **单步调试 Frida (更高级):**  在更复杂的情况下，用户甚至可以编译带有调试符号的 Frida，并使用 GDB 等调试器单步执行 Frida 的代码，追踪 `gumarm64writer` 的执行过程，查看每条指令是如何生成的。

总之，`gumarm64writer.c` 是 Frida 动态插桩的核心组件，理解其功能对于深入理解 Frida 的工作原理以及解决 ARM64 平台的插桩问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/arch-arm64/gumarm64writer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2014-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2019 Jon Wilson <jonwilson@zepler.net>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2023 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64writer.h"

#include "gumlibc.h"
#include "gummemory.h"
#include "gumprocess.h"

#ifdef _MSC_VER
# include <intrin.h>
#endif

typedef guint GumArm64LabelRefType;
typedef struct _GumArm64LabelRef GumArm64LabelRef;
typedef struct _GumArm64LiteralRef GumArm64LiteralRef;
typedef guint GumArm64LiteralWidth;
typedef guint GumArm64MemOperationType;
typedef guint GumArm64MemOperandType;
typedef guint GumArm64MetaReg;
typedef struct _GumArm64RegInfo GumArm64RegInfo;

enum _GumArm64LabelRefType
{
  GUM_ARM64_B,
  GUM_ARM64_B_COND,
  GUM_ARM64_BL,
  GUM_ARM64_CBZ,
  GUM_ARM64_CBNZ,
  GUM_ARM64_TBZ,
  GUM_ARM64_TBNZ,
};

struct _GumArm64LabelRef
{
  gconstpointer id;
  GumArm64LabelRefType type;
  guint32 * insn;
};

struct _GumArm64LiteralRef
{
  guint32 * insn;
  gint64 val;
  GumArm64LiteralWidth width;
};

enum _GumArm64LiteralWidth
{
  GUM_LITERAL_32BIT,
  GUM_LITERAL_64BIT
};

enum _GumArm64MemOperationType
{
  GUM_MEM_OPERATION_STORE = 0,
  GUM_MEM_OPERATION_LOAD = 1
};

enum _GumArm64MemOperandType
{
  GUM_MEM_OPERAND_I32,
  GUM_MEM_OPERAND_I64,
  GUM_MEM_OPERAND_S32,
  GUM_MEM_OPERAND_D64,
  GUM_MEM_OPERAND_Q128
};

enum _GumArm64MetaReg
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

  GUM_MREG_FP = GUM_MREG_R29,
  GUM_MREG_LR = GUM_MREG_R30,
  GUM_MREG_SP = GUM_MREG_R31,
  GUM_MREG_ZR = GUM_MREG_R31
};

struct _GumArm64RegInfo
{
  GumArm64MetaReg meta;
  gboolean is_integer;
  guint width;
  guint index;
  guint32 sf;
  GumArm64MemOperandType operand_type;
};

static void gum_arm64_writer_reset_refs (GumArm64Writer * self);

static void gum_arm64_writer_put_argument_list_setup (GumArm64Writer * self,
    guint n_args, const GumArgument * args);
static void gum_arm64_writer_put_argument_list_setup_va (GumArm64Writer * self,
    guint n_args, va_list args);
static void gum_arm64_writer_put_argument_list_teardown (GumArm64Writer * self,
    guint n_args);
static gboolean gum_arm64_writer_put_br_reg_with_extra (GumArm64Writer * self,
    arm64_reg reg, guint32 extra);
static gboolean gum_arm64_writer_put_blr_reg_with_extra (GumArm64Writer * self,
    arm64_reg reg, guint32 extra);
static gboolean gum_arm64_writer_put_cbx_op_reg_imm (GumArm64Writer * self,
    guint8 op, arm64_reg reg, GumAddress target);
static gboolean gum_arm64_writer_put_tbx_op_reg_imm_imm (GumArm64Writer * self,
    guint8 op, arm64_reg reg, guint bit, GumAddress target);
static gboolean gum_arm64_writer_put_ldr_reg_pcrel (GumArm64Writer * self,
    const GumArm64RegInfo * ri, GumAddress src_address);
static void gum_arm64_writer_put_load_store_pair (GumArm64Writer * self,
    GumArm64MemOperationType operation_type,
    GumArm64MemOperandType operand_type, guint rt, guint rt2, guint rn,
    gssize rn_offset, GumArm64IndexMode mode);

static GumAddress gum_arm64_writer_strip (GumArm64Writer * self,
    GumAddress value);

static gboolean gum_arm64_writer_try_commit_label_refs (GumArm64Writer * self);
static void gum_arm64_writer_maybe_commit_literals (GumArm64Writer * self);
static void gum_arm64_writer_commit_literals (GumArm64Writer * self);

static void gum_arm64_writer_describe_reg (GumArm64Writer * self,
    arm64_reg reg, GumArm64RegInfo * ri);

static GumArm64MemOperandType gum_arm64_mem_operand_type_from_reg_info (
    const GumArm64RegInfo * ri);

static gboolean gum_arm64_try_encode_logical_immediate (guint64 imm_value,
    guint reg_width, guint * imm_enc);
static guint gum_arm64_determine_logical_element_size (guint64 imm_value,
    guint reg_width);
static gboolean gum_arm64_try_determine_logical_rotation (guint64 imm_value,
    guint element_size, guint * num_rotations, guint * num_trailing_ones);

static gboolean gum_is_shifted_mask_64 (guint64 value);
static gboolean gum_is_mask_64 (guint64 value);

static guint gum_count_leading_zeros (guint64 value);
static guint gum_count_trailing_zeros (guint64 value);
static guint gum_count_leading_ones (guint64 value);
static guint gum_count_trailing_ones (guint64 value);

GumArm64Writer *
gum_arm64_writer_new (gpointer code_address)
{
  GumArm64Writer * writer;

  writer = g_slice_new (GumArm64Writer);

  gum_arm64_writer_init (writer, code_address);

  return writer;
}

GumArm64Writer *
gum_arm64_writer_ref (GumArm64Writer * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_arm64_writer_unref (GumArm64Writer * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_arm64_writer_clear (writer);

    g_slice_free (GumArm64Writer, writer);
  }
}

void
gum_arm64_writer_init (GumArm64Writer * writer,
                       gpointer code_address)
{
  writer->ref_count = 1;
  writer->flush_on_destroy = TRUE;

  writer->target_os = gum_process_get_native_os ();
  writer->ptrauth_support = gum_query_ptrauth_support ();
  writer->sign = gum_sign_code_address;

  writer->label_defs = NULL;
  writer->label_refs.data = NULL;
  writer->literal_refs.data = NULL;

  gum_arm64_writer_reset (writer, code_address);
}

static gboolean
gum_arm64_writer_has_label_defs (GumArm64Writer * self)
{
  return self->label_defs != NULL;
}

static gboolean
gum_arm64_writer_has_label_refs (GumArm64Writer * self)
{
  return self->label_refs.data != NULL;
}

static gboolean
gum_arm64_writer_has_literal_refs (GumArm64Writer * self)
{
  return self->literal_refs.data != NULL;
}

void
gum_arm64_writer_clear (GumArm64Writer * writer)
{
  if (writer->flush_on_destroy)
    gum_arm64_writer_flush (writer);

  if (gum_arm64_writer_has_label_defs (writer))
    gum_metal_hash_table_unref (writer->label_defs);

  if (gum_arm64_writer_has_label_refs (writer))
    gum_metal_array_free (&writer->label_refs);

  if (gum_arm64_writer_has_literal_refs (writer))
    gum_metal_array_free (&writer->literal_refs);
}

void
gum_arm64_writer_reset (GumArm64Writer * writer,
                        gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  if (gum_arm64_writer_has_label_defs (writer))
    gum_metal_hash_table_remove_all (writer->label_defs);

  gum_arm64_writer_reset_refs (writer);
}

static void
gum_arm64_writer_reset_refs (GumArm64Writer * self)
{
  if (gum_arm64_writer_has_label_refs (self))
    gum_metal_array_remove_all (&self->label_refs);

  if (gum_arm64_writer_has_literal_refs (self))
    gum_metal_array_remove_all (&self->literal_refs);

  self->earliest_literal_insn = NULL;
}

gpointer
gum_arm64_writer_cur (GumArm64Writer * self)
{
  return self->code;
}

guint
gum_arm64_writer_offset (GumArm64Writer * self)
{
  return (guint) (self->code - self->base) * sizeof (guint32);
}

void
gum_arm64_writer_skip (GumArm64Writer * self,
                       guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

gboolean
gum_arm64_writer_flush (GumArm64Writer * self)
{
  if (!gum_arm64_writer_try_commit_label_refs (self))
    goto error;

  gum_arm64_writer_commit_literals (self);

  return TRUE;

error:
  {
    gum_arm64_writer_reset_refs (self);

    return FALSE;
  }
}

gboolean
gum_arm64_writer_put_label (GumArm64Writer * self,
                            gconstpointer id)
{
  if (!gum_arm64_writer_has_label_defs (self))
    self->label_defs = gum_metal_hash_table_new (NULL, NULL);

  if (gum_metal_hash_table_lookup (self->label_defs, id) != NULL)
    return FALSE;

  gum_metal_hash_table_insert (self->label_defs, (gpointer) id, self->code);

  return TRUE;
}

static void
gum_arm64_writer_add_label_reference_here (GumArm64Writer * self,
                                           gconstpointer id,
                                           GumArm64LabelRefType type)
{
  GumArm64LabelRef * r;

  if (!gum_arm64_writer_has_label_refs (self))
    gum_metal_array_init (&self->label_refs, sizeof (GumArm64LabelRef));

  r = gum_metal_array_append (&self->label_refs);
  r->id = id;
  r->type = type;
  r->insn = self->code;
}

static void
gum_arm64_writer_add_literal_reference_here (GumArm64Writer * self,
                                             guint64 val,
                                             GumArm64LiteralWidth width)
{
  GumArm64LiteralRef * r;

  if (!gum_arm64_writer_has_literal_refs (self))
    gum_metal_array_init (&self->literal_refs, sizeof (GumArm64LiteralRef));

  r = gum_metal_array_append (&self->literal_refs);
  r->insn = self->code;
  r->val = val;
  r->width = width;

  if (self->earliest_literal_insn == NULL)
    self->earliest_literal_insn = r->insn;
}

void
gum_arm64_writer_put_call_address_with_arguments (GumArm64Writer * self,
                                                  GumAddress func,
                                                  guint n_args,
                                                  ...)
{
  va_list args;

  va_start (args, n_args);
  gum_arm64_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  if (gum_arm64_writer_can_branch_directly_between (self, self->pc, func))
  {
    gum_arm64_writer_put_bl_imm (self, func);
  }
  else
  {
    const arm64_reg target = ARM64_REG_X0 + n_args;
    gum_arm64_writer_put_ldr_reg_address (self, target, func);
    gum_arm64_writer_put_blr_reg (self, target);
  }

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

void
gum_arm64_writer_put_call_address_with_arguments_array (
    GumArm64Writer * self,
    GumAddress func,
    guint n_args,
    const GumArgument * args)
{
  gum_arm64_writer_put_argument_list_setup (self, n_args, args);

  if (gum_arm64_writer_can_branch_directly_between (self, self->pc, func))
  {
    gum_arm64_writer_put_bl_imm (self, func);
  }
  else
  {
    const arm64_reg target = ARM64_REG_X0 + n_args;
    gum_arm64_writer_put_ldr_reg_address (self, target, func);
    gum_arm64_writer_put_blr_reg (self, target);
  }

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

void
gum_arm64_writer_put_call_reg_with_arguments (GumArm64Writer * self,
                                              arm64_reg reg,
                                              guint n_args,
                                              ...)
{
  va_list args;

  va_start (args, n_args);
  gum_arm64_writer_put_argument_list_setup_va (self, n_args, args);
  va_end (args);

  gum_arm64_writer_put_blr_reg (self, reg);

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

void
gum_arm64_writer_put_call_reg_with_arguments_array (GumArm64Writer * self,
                                                    arm64_reg reg,
                                                    guint n_args,
                                                    const GumArgument * args)
{
  gum_arm64_writer_put_argument_list_setup (self, n_args, args);

  gum_arm64_writer_put_blr_reg (self, reg);

  gum_arm64_writer_put_argument_list_teardown (self, n_args);
}

static void
gum_arm64_writer_put_argument_list_setup (GumArm64Writer * self,
                                          guint n_args,
                                          const GumArgument * args)
{
  gint arg_index;

  for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
  {
    const GumArgument * arg = &args[arg_index];
    arm64_reg dst_reg = ARM64_REG_X0 + arg_index;

    if (arg->type == GUM_ARG_ADDRESS)
    {
      gum_arm64_writer_put_ldr_reg_address (self, dst_reg, arg->value.address);
    }
    else
    {
      arm64_reg src_reg = arg->value.reg;
      GumArm64RegInfo rs;

      gum_arm64_writer_describe_reg (self, src_reg, &rs);

      if (rs.width == 64)
      {
        if (src_reg != dst_reg)
          gum_arm64_writer_put_mov_reg_reg (self, dst_reg, arg->value.reg);
      }
      else
      {
        gum_arm64_writer_put_uxtw_reg_reg (self, dst_reg, src_reg);
      }
    }
  }
}

static void
gum_arm64_writer_put_argument_list_setup_va (GumArm64Writer * self,
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
      arg->value.reg = va_arg (args, arm64_reg);
    else
      g_assert_not_reached ();
  }

  gum_arm64_writer_put_argument_list_setup (self, n_args, arg_values);
}

static void
gum_arm64_writer_put_argument_list_teardown (GumArm64Writer * self,
                                             guint n_args)
{
}

void
gum_arm64_writer_put_branch_address (GumArm64Writer * self,
                                     GumAddress address)
{
  if (!gum_arm64_writer_can_branch_directly_between (self, self->pc, address))
  {
    const arm64_reg target = ARM64_REG_X16;

    gum_arm64_writer_put_ldr_reg_address (self, target, address);
    gum_arm64_writer_put_br_reg (self, target);

    return;
  }

  gum_arm64_writer_put_b_imm (self, address);
}

gboolean
gum_arm64_writer_can_branch_directly_between (GumArm64Writer * self,
                                              GumAddress from,
                                              GumAddress to)
{
  gint64 distance = (gint64) gum_arm64_writer_strip (self, to) -
      (gint64) gum_arm64_writer_strip (self, from);

  return GUM_IS_WITHIN_INT28_RANGE (distance);
}

gboolean
gum_arm64_writer_put_b_imm (GumArm64Writer * self,
                            GumAddress address)
{
  gint64 distance =
      (gint64) gum_arm64_writer_strip (self, address) - (gint64) self->pc;

  if (!GUM_IS_WITHIN_INT28_RANGE (distance) || distance % 4 != 0)
    return FALSE;

  gum_arm64_writer_put_instruction (self,
      0x14000000 | ((distance / 4) & GUM_INT26_MASK));

  return TRUE;
}

void
gum_arm64_writer_put_b_label (GumArm64Writer * self,
                              gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_B);
  gum_arm64_writer_put_instruction (self, 0x14000000);
}

void
gum_arm64_writer_put_b_cond_label (GumArm64Writer * self,
                                   arm64_cc cc,
                                   gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_B_COND);
  gum_arm64_writer_put_instruction (self, 0x54000000 | (cc - 1));
}

gboolean
gum_arm64_writer_put_bl_imm (GumArm64Writer * self,
                             GumAddress address)
{
  gint64 distance =
      (gint64) gum_arm64_writer_strip (self, address) - (gint64) self->pc;

  if (!GUM_IS_WITHIN_INT28_RANGE (distance) || distance % 4 != 0)
    return FALSE;

  gum_arm64_writer_put_instruction (self,
      0x94000000 | ((distance / 4) & GUM_INT26_MASK));

  return TRUE;
}

void
gum_arm64_writer_put_bl_label (GumArm64Writer * self,
                               gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_BL);
  gum_arm64_writer_put_instruction (self, 0x94000000);
}

gboolean
gum_arm64_writer_put_br_reg (GumArm64Writer * self,
                             arm64_reg reg)
{
  return gum_arm64_writer_put_br_reg_with_extra (self, reg,
      (self->ptrauth_support == GUM_PTRAUTH_SUPPORTED) ? 0x81f : 0);
}

gboolean
gum_arm64_writer_put_br_reg_no_auth (GumArm64Writer * self,
                                     arm64_reg reg)
{
  return gum_arm64_writer_put_br_reg_with_extra (self, reg, 0);
}

static gboolean
gum_arm64_writer_put_br_reg_with_extra (GumArm64Writer * self,
                                        arm64_reg reg,
                                        guint32 extra)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0xd61f0000 | (ri.index << 5) | extra);

  return TRUE;
}

gboolean
gum_arm64_writer_put_blr_reg (GumArm64Writer * self,
                              arm64_reg reg)
{
  return gum_arm64_writer_put_blr_reg_with_extra (self, reg,
      (self->ptrauth_support == GUM_PTRAUTH_SUPPORTED) ? 0x81f : 0);
}

gboolean
gum_arm64_writer_put_blr_reg_no_auth (GumArm64Writer * self,
                                      arm64_reg reg)
{
  return gum_arm64_writer_put_blr_reg_with_extra (self, reg, 0);
}

static gboolean
gum_arm64_writer_put_blr_reg_with_extra (GumArm64Writer * self,
                                         arm64_reg reg,
                                         guint32 extra)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0xd63f0000 | (ri.index << 5) | extra);

  return TRUE;
}

void
gum_arm64_writer_put_ret (GumArm64Writer * self)
{
  gum_arm64_writer_put_instruction (self, 0xd65f0000 | (GUM_MREG_LR << 5));
}

gboolean
gum_arm64_writer_put_ret_reg (GumArm64Writer * self,
                              arm64_reg reg)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  gum_arm64_writer_put_instruction (self, 0xd65f0000 | (ri.index << 5));

  return TRUE;
}

gboolean
gum_arm64_writer_put_cbz_reg_imm (GumArm64Writer * self,
                                  arm64_reg reg,
                                  GumAddress target)
{
  return gum_arm64_writer_put_cbx_op_reg_imm (self, 0, reg, target);
}

gboolean
gum_arm64_writer_put_cbnz_reg_imm (GumArm64Writer * self,
                                   arm64_reg reg,
                                   GumAddress target)
{
  return gum_arm64_writer_put_cbx_op_reg_imm (self, 1, reg, target);
}

void
gum_arm64_writer_put_cbz_reg_label (GumArm64Writer * self,
                                    arm64_reg reg,
                                    gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_CBZ);
  gum_arm64_writer_put_cbx_op_reg_imm (self, 0, reg, 0);
}

void
gum_arm64_writer_put_cbnz_reg_label (GumArm64Writer * self,
                                     arm64_reg reg,
                                     gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_CBNZ);
  gum_arm64_writer_put_cbx_op_reg_imm (self, 1, reg, 0);
}

static gboolean
gum_arm64_writer_put_cbx_op_reg_imm (GumArm64Writer * self,
                                     guint8 op,
                                     arm64_reg reg,
                                     GumAddress target)
{
  GumArm64RegInfo ri;
  gint64 imm19;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (target != 0)
  {
    const gint64 distance = (gint64) target - (gint64) self->pc;
    imm19 = distance / 4;
    if (distance % 4 != 0 || !GUM_IS_WITHIN_INT19_RANGE (imm19))
      return FALSE;
  }
  else
  {
    imm19 = 0;
  }

  gum_arm64_writer_put_instruction (self,
      ri.sf |
      0x34000000 |
      (guint32) op << 24 |
      (imm19 & GUM_INT19_MASK) << 5 |
      ri.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_tbz_reg_imm_imm (GumArm64Writer * self,
                                      arm64_reg reg,
                                      guint bit,
                                      GumAddress target)
{
  return gum_arm64_writer_put_tbx_op_reg_imm_imm (self, 0, reg, bit, target);
}

gboolean
gum_arm64_writer_put_tbnz_reg_imm_imm (GumArm64Writer * self,
                                       arm64_reg reg,
                                       guint bit,
                                       GumAddress target)
{
  return gum_arm64_writer_put_tbx_op_reg_imm_imm (self, 1, reg, bit, target);
}

void
gum_arm64_writer_put_tbz_reg_imm_label (GumArm64Writer * self,
                                        arm64_reg reg,
                                        guint bit,
                                        gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_TBZ);
  gum_arm64_writer_put_tbx_op_reg_imm_imm (self, 0, reg, bit, 0);
}

void
gum_arm64_writer_put_tbnz_reg_imm_label (GumArm64Writer * self,
                                         arm64_reg reg,
                                         guint bit,
                                         gconstpointer label_id)
{
  gum_arm64_writer_add_label_reference_here (self, label_id, GUM_ARM64_TBNZ);
  gum_arm64_writer_put_tbx_op_reg_imm_imm (self, 1, reg, bit, 0);
}

static gboolean
gum_arm64_writer_put_tbx_op_reg_imm_imm (GumArm64Writer * self,
                                         guint8 op,
                                         arm64_reg reg,
                                         guint bit,
                                         GumAddress target)
{
  GumArm64RegInfo ri;
  gint64 imm14;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (bit >= ri.width)
    return FALSE;

  if (target != 0)
  {
    const gint64 distance = (gint64) target - (gint64) self->pc;
    imm14 = distance / 4;
    if (distance % 4 != 0 || !GUM_IS_WITHIN_INT14_RANGE (imm14))
      return FALSE;
  }
  else
  {
    imm14 = 0;
  }

  gum_arm64_writer_put_instruction (self,
      ((bit >> 5) << 31) |
      0x36000000 |
      (guint32) op << 24 |
      ((bit & GUM_INT5_MASK) << 19) |
      (imm14 & GUM_INT14_MASK) << 5 |
      ri.index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_push_reg_reg (GumArm64Writer * self,
                                   arm64_reg reg_a,
                                   arm64_reg reg_b)
{
  GumArm64RegInfo ra, rb, sp;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);
  gum_arm64_writer_describe_reg (self, ARM64_REG_SP, &sp);

  if (ra.width != rb.width)
    return FALSE;

  gum_arm64_writer_put_load_store_pair (self, GUM_MEM_OPERATION_STORE,
      gum_arm64_mem_operand_type_from_reg_info (&ra), ra.index, rb.index,
      sp.index, -(2 * ((gint) ra.width / 8)), GUM_INDEX_PRE_ADJUST);

  return TRUE;
}

gboolean
gum_arm64_writer_put_pop_reg_reg (GumArm64Writer * self,
                                  arm64_reg reg_a,
                                  arm64_reg reg_b)
{
  GumArm64RegInfo ra, rb, sp;

  gum_arm64_writer_describe_reg (self, reg_a, &ra);
  gum_arm64_writer_describe_reg (self, reg_b, &rb);
  gum_arm64_writer_describe_reg (self, ARM64_REG_SP, &sp);

  if (ra.width != rb.width)
    return FALSE;

  gum_arm64_writer_put_load_store_pair (self, GUM_MEM_OPERATION_LOAD,
      gum_arm64_mem_operand_type_from_reg_info (&ra), ra.index, rb.index,
      sp.index, 2 * (ra.width / 8), GUM_INDEX_POST_ADJUST);

  return TRUE;
}

void
gum_arm64_writer_put_push_all_x_registers (GumArm64Writer * self)
{
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X2, ARM64_REG_X3);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X4, ARM64_REG_X5);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X6, ARM64_REG_X7);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X8, ARM64_REG_X9);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X10, ARM64_REG_X11);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X12, ARM64_REG_X13);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X14, ARM64_REG_X15);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X18, ARM64_REG_X19);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X20, ARM64_REG_X21);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X22, ARM64_REG_X23);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X24, ARM64_REG_X25);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X26, ARM64_REG_X27);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X28, ARM64_REG_X29);
  gum_arm64_writer_put_mov_reg_nzcv (self, ARM64_REG_X15);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_X30, ARM64_REG_X15);
}

void
gum_arm64_writer_put_pop_all_x_registers (GumArm64Writer * self)
{
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X30, ARM64_REG_X15);
  gum_arm64_writer_put_mov_nzcv_reg (self, ARM64_REG_X15);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X28, ARM64_REG_X29);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X26, ARM64_REG_X27);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X24, ARM64_REG_X25);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X22, ARM64_REG_X23);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X20, ARM64_REG_X21);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X18, ARM64_REG_X19);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X14, ARM64_REG_X15);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X12, ARM64_REG_X13);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X10, ARM64_REG_X11);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X8, ARM64_REG_X9);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X6, ARM64_REG_X7);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X4, ARM64_REG_X5);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X2, ARM64_REG_X3);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_X0, ARM64_REG_X1);
}

void
gum_arm64_writer_put_push_all_q_registers (GumArm64Writer * self)
{
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q0, ARM64_REG_Q1);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q2, ARM64_REG_Q3);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q4, ARM64_REG_Q5);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q6, ARM64_REG_Q7);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q8, ARM64_REG_Q9);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q10, ARM64_REG_Q11);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q12, ARM64_REG_Q13);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q14, ARM64_REG_Q15);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q16, ARM64_REG_Q17);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q18, ARM64_REG_Q19);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q20, ARM64_REG_Q21);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q22, ARM64_REG_Q23);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q24, ARM64_REG_Q25);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q26, ARM64_REG_Q27);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q28, ARM64_REG_Q29);
  gum_arm64_writer_put_push_reg_reg (self, ARM64_REG_Q30, ARM64_REG_Q31);
}

void
gum_arm64_writer_put_pop_all_q_registers (GumArm64Writer * self)
{
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q30, ARM64_REG_Q31);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q28, ARM64_REG_Q29);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q26, ARM64_REG_Q27);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q24, ARM64_REG_Q25);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q22, ARM64_REG_Q23);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q20, ARM64_REG_Q21);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q18, ARM64_REG_Q19);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q16, ARM64_REG_Q17);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q14, ARM64_REG_Q15);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q12, ARM64_REG_Q13);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q10, ARM64_REG_Q11);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q8, ARM64_REG_Q9);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q6, ARM64_REG_Q7);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q4, ARM64_REG_Q5);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q2, ARM64_REG_Q3);
  gum_arm64_writer_put_pop_reg_reg (self, ARM64_REG_Q0, ARM64_REG_Q1);
}

gboolean
gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self,
                                      arm64_reg reg,
                                      GumAddress address)
{
  return gum_arm64_writer_put_ldr_reg_u64 (self, reg, (guint64) address);
}

gboolean
gum_arm64_writer_put_ldr_reg_u32 (GumArm64Writer * self,
                                  arm64_reg reg,
                                  guint32 val)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.is_integer && val == 0)
    return gum_arm64_writer_put_mov_reg_reg (self, reg, ARM64_REG_WZR);

  if (ri.width != 32)
    return FALSE;

  gum_arm64_writer_add_literal_reference_here (self, val, GUM_LITERAL_32BIT);
  gum_arm64_writer_put_ldr_reg_pcrel (self, &ri, 0);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self,
                                  arm64_reg reg,
                                  guint64 val)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.is_integer && val == 0)
    return gum_arm64_writer_put_mov_reg_reg (self, reg, ARM64_REG_XZR);

  if (ri.width != 64)
    return FALSE;

  gum_arm64_writer_add_literal_reference_here (self, val, GUM_LITERAL_64BIT);
  gum_arm64_writer_put_ldr_reg_pcrel (self, &ri, 0);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ldr_reg_u32_ptr (GumArm64Writer * self,
                                      arm64_reg reg,
                                      GumAddress src_address)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 32)
    return FALSE;

  return gum_arm64_writer_put_ldr_reg_pcrel (self, &ri, src_address);
}

gboolean
gum_arm64_writer_put_ldr_reg_u64_ptr (GumArm64Writer * self,
                                      arm64_reg reg,
                                      GumAddress src_address)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  return gum_arm64_writer_put_ldr_reg_pcrel (self, &ri, src_address);
}

guint
gum_arm64_writer_put_ldr_reg_ref (GumArm64Writer * self,
                                  arm64_reg reg)
{
  GumArm64RegInfo ri;
  guint ref;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  ref = gum_arm64_writer_offset (self);

  gum_arm64_writer_put_ldr_reg_pcrel (self, &ri, 0);

  return ref;
}

void
gum_arm64_writer_put_ldr_reg_value (GumArm64Writer * self,
                                    guint ref,
                                    GumAddress value)
{
  guint distance;
  guint32 * insn;

  distance = gum_arm64_writer_offset (self) - ref;

  insn = self->base + (ref / 4);
  *insn = GUINT32_TO_LE (GUINT32_FROM_LE (*insn) |
      (((distance / 4) & GUM_INT19_MASK) << 5));

  *((guint64 *) self->code) = GUINT64_TO_LE (value);
  self->code += 2;
  self->pc += 8;
}

static gboolean
gum_arm64_writer_put_ldr_reg_pcrel (GumArm64Writer * self,
                                    const GumArm64RegInfo * ri,
                                    GumAddress src_address)
{
  gint64 imm19;

  if (src_address != 0)
  {
    const gint64 distance = (gint64) src_address - (gint64) self->pc;
    imm19 = distance / 4;
    if (distance % 4 != 0 || !GUM_IS_WITHIN_INT19_RANGE (imm19))
      return FALSE;
  }
  else
  {
    imm19 = 0;
  }

  gum_arm64_writer_put_instruction (self,
      (ri->width == 64 ? 0x50000000 : 0x10000000) |
      (ri->is_integer  ? 0x08000000 : 0x0c000000) |
      (imm19 & GUM_INT19_MASK) << 5 |
      ri->index);

  return TRUE;
}

gboolean
gum_arm64_writer_put_ldr_reg_reg (GumArm64Writer * self,
                                  arm64_reg dst_reg,
                                  arm64_reg src_reg)
{
  return gum_arm64_writer_put_ldr_reg_reg_offset (self, dst_reg, src_reg, 0);
}

gboolean
gum_arm64_writer_put_ldr_reg_reg_offset (GumArm64Writer * self,
                                         arm64_reg dst_reg,
                                         arm64_reg src_reg,
                                         gsize src_offset)
{
  GumArm64RegInfo rd, rs;
  guint32 size, v, opc;

  gum_arm64_writer_describe_reg (self, dst_reg, &rd);
  gum_arm64
"""


```