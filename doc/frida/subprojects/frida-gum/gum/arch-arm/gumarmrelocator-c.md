Response:
Let's break down the thought process for analyzing this C code and answering the prompt.

**1. Understanding the Goal:**

The core request is to analyze the `gumarmrelocator.c` file and explain its functionality, especially in the context of reverse engineering, low-level details, and potential user errors. The prompt also emphasizes connecting user actions to the code.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code to identify key data structures, functions, and concepts. Keywords like "relocator," "writer," "capstone," "instruction," "address," "rewrite," "ldr," "mov," "add," "sub," "b," "bl," and "PC" immediately stand out. These suggest the file is about modifying or relocating ARM instructions.

**3. Deeper Dive into Core Components:**

* **`GumArmRelocator`:**  This is the central data structure. It holds information about the input and output code, the Capstone disassembler instance, and the current processing positions. The functions `gum_arm_relocator_new`, `_init`, `_ref`, `_unref`, `_clear`, and `_reset` manage its lifecycle.
* **`GumArmWriter`:** This seems responsible for writing the modified instructions. The code interacts with it via functions like `gum_arm_writer_put_bytes`, `gum_arm_writer_put_ldr_reg_address`, etc. This points towards the process of generating new machine code.
* **Capstone (`cs_insn`, `cs_open`, `cs_disasm_iter`, `cs_free`):**  This is a well-known disassembly library. Its presence confirms that the code needs to understand the structure of ARM instructions. The functions used highlight the steps of initializing the disassembler, disassembling instructions iteratively, and freeing allocated memory.
* **Instruction Rewriting Functions (`gum_arm_relocator_rewrite_...`):** These functions (e.g., `_rewrite_ldr`, `_rewrite_mov`) are the heart of the modification logic. They handle specific ARM instructions and implement the relocation/rewriting process.

**4. Identifying Key Functionality:**

Based on the keywords and component analysis, the core functionalities emerge:

* **Reading Instructions:**  `gum_arm_relocator_read_one` uses Capstone to disassemble instructions from the input code.
* **Peeking at Instructions:** `gum_arm_relocator_peek_next_write_insn` and `_peek_next_write_source` allow inspection of the next instruction to be processed.
* **Skipping Instructions:** `gum_arm_relocator_skip_one` allows ignoring an instruction.
* **Writing (Rewriting) Instructions:** `gum_arm_relocator_write_one` is the main function for either rewriting an instruction (if needed) or simply copying it to the output.
* **Relocation:** The `gum_arm_relocator_relocate` function orchestrates the entire process of reading, potentially rewriting, and writing instructions to a new memory location.
* **Checking Relocatability:** `gum_arm_relocator_can_relocate` determines if a given code region can be relocated without issues.

**5. Connecting to Reverse Engineering:**

The core concept of *relocation* is directly related to reverse engineering. When you want to intercept and modify the behavior of a program, you often need to move code snippets to a different location in memory. This code provides the mechanism to do that while ensuring that instruction addressing (especially PC-relative addressing) remains correct. The examples for `LDR`, `MOV`, `ADD`, and `SUB` involving the PC register are direct demonstrations of how PC-relative loads and arithmetic need special handling during relocation.

**6. Identifying Low-Level Details:**

The code is deeply intertwined with binary instruction formats and CPU architecture:

* **ARM Instruction Set:** The code heavily uses ARM-specific constants like `ARM_INS_LDR`, `ARM_REG_PC`, `ARM_OP_MEM`, etc.
* **Instruction Modes (ARM/Thumb):** The code considers both ARM and Thumb instruction sets (`CS_MODE_ARM`, `CS_MODE_THUMB`).
* **PC-Relative Addressing:**  The rewriting logic specifically addresses instructions that load data or perform arithmetic relative to the Program Counter (PC).
* **Register Manipulation:** The code directly manipulates ARM registers (e.g., pushing and popping registers, moving data between them).

**7. Considering Kernel/Android:**

While the code itself doesn't *directly* interact with the Linux or Android kernel APIs, its purpose is crucial for dynamic instrumentation, which *does* have kernel implications:

* **Dynamic Instrumentation:** Tools like Frida, for which this code is a part, operate by injecting code into running processes. This often involves manipulating memory mappings and potentially interacting with kernel debugging interfaces.
* **Address Space Layout Randomization (ASLR):** Relocation is essential to handle ASLR, where code is loaded at different addresses each time a program runs. This code allows instrumentation to work correctly regardless of the loaded address.

**8. Logic and Assumptions:**

The rewriting functions demonstrate logical reasoning:

* **Identifying Problematic Instructions:** The code identifies instructions that rely on the current code location (e.g., `LDR PC, [PC, #offset]`).
* **Transforming Instructions:** It replaces these instructions with equivalent sequences that are position-independent. The assumption is that a scratch register is available for temporary calculations.
* **Handling Different Cases:**  The `switch` statements and `if/else` blocks within the rewriting functions demonstrate handling various operand types and instruction formats.

**9. User/Programming Errors:**

The example about passing `NULL` as `input_code` illustrates a potential error. Other potential errors could arise from:

* **Insufficient Output Buffer:**  If the `GumArmWriter`'s buffer is too small, the rewritten code might overflow.
* **Incorrect Instruction Boundaries:** If the input `input_code` doesn't point to the beginning of a valid instruction, the disassembly might fail or produce incorrect results.
* **Assumptions about Register Availability:**  The rewriting logic assumes certain registers are available as scratch registers. In highly optimized code, these registers might be in use, leading to incorrect behavior if not handled carefully.

**10. Debugging and User Steps:**

The debugging scenario illustrates how a user might reach this code:

1. **User wants to instrument an ARM application.**
2. **Frida is used to attach to the process.**
3. **The user sets an intercept on a function.**
4. **When the function is called, Frida needs to prepare the trampoline (the injected code).**
5. **Part of the trampoline creation involves relocating the original instructions.**
6. **This leads to the execution of functions in `gumarmrelocator.c` to analyze and rewrite the instructions.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on the code structure.
* **Correction:**  Realize the importance of connecting the code to its purpose (dynamic instrumentation) and related concepts (reverse engineering, ASLR).
* **Initial thought:**  Simply list the functions.
* **Correction:**  Explain the *purpose* of each function and how they contribute to the overall functionality.
* **Initial thought:**  Provide very technical explanations.
* **Correction:** Balance technical details with clear explanations and examples that are understandable to a broader audience.

By following this systematic approach, we can effectively analyze the code and address all aspects of the prompt.
这个`gumarmrelocator.c` 文件是 Frida 工具链中 `frida-gum` 组件的一部分，专注于在 ARM 架构上动态地重新定位（relocate）指令。重新定位指令是动态插桩的一个核心需求，它允许 Frida 将原始代码片段移动到新的内存位置，同时确保代码仍然能够正确执行。

以下是该文件的主要功能：

**1. 指令读取和解析 (Instruction Reading and Parsing):**

* **`gum_arm_relocator_read_one`:** 使用 Capstone 反汇编引擎 (通过 `cs_disasm_iter`) 从给定的内存地址读取并解析一条 ARM 指令。
* 它将解析后的指令存储在内部缓冲区 `relocator->input_insns` 中。
* 它会分析指令的类型，例如分支指令 (`B`, `BX`, `BL`, `BLX`) 和可能修改程序计数器 (PC) 的指令 (`LDR`, `MOV`, `ADD`, `SUB`, `POP`, `LDM`)，并设置 `relocator->eob` (End of Block) 和 `relocator->eoi` (End of Instruction) 标志。这两个标志用于指示当前代码块的结束以及指令是否会导致控制流的改变。

**2. 指令重写 (Instruction Rewriting):**

* **`gum_arm_relocator_write_one`:** 这是核心的重写逻辑。它检查当前要写入的指令是否需要修改。
* **`gum_arm_relocator_rewrite_ldr`, `gum_arm_relocator_rewrite_mov`, `gum_arm_relocator_rewrite_add`, `gum_arm_relocator_rewrite_sub`, `gum_arm_relocator_rewrite_b`, `gum_arm_relocator_rewrite_bl`:** 这些函数针对特定的 ARM 指令类型实现了重写逻辑。
* **目的：** 当原始指令包含与当前代码位置相关的操作时（例如，加载 PC 相对地址），需要将其改写成与位置无关的代码。这通常涉及到将立即数加载到寄存器，然后使用该寄存器进行操作。
* **示例：** 如果原始指令是 `LDR Rx, [PC, #offset]`，它会将相对于当前 PC 的地址加载到 `Rx`。在重新定位后，原始 PC 的值会改变，因此需要将其改写为类似 `LDR Ry, =original_pc_value + offset; LDR Rx, [Ry]` 的形式。

**3. 指令写入 (Instruction Writing):**

* **`gum_arm_writer_put_bytes` (通过 `GumArmWriter`):** 如果指令不需要重写，或者重写已经完成，则将指令的原始字节写入到输出缓冲区。
* `GumArmWriter` 是 Frida 提供的用于生成 ARM 机器码的工具。

**4. 整体重新定位流程 (Overall Relocation Process):**

* **`gum_arm_relocator_relocate`:**  这是执行重新定位的主函数。
    * 它初始化 `GumArmRelocator` 和 `GumArmWriter`。
    * 它循环调用 `gum_arm_relocator_read_one` 读取指令。
    * 它循环调用 `gum_arm_relocator_write_one` 写入（可能重写过的）指令到新的内存位置。
* **`gum_arm_relocator_can_relocate`:** 检查给定地址和最小字节数的代码是否可以被安全地重新定位。

**5. 控制流分析 (Control Flow Analysis):**

* **`gum_arm_branch_is_unconditional`:** 判断一个分支指令是否是无条件分支。这对于确定代码块的边界很重要。
* 通过分析指令类型和操作数，`gum_arm_relocator` 试图理解代码的控制流，以便正确地处理分支目标。

**与逆向方法的关联及举例说明:**

* **代码注入和Hooking:** 在逆向工程中，我们经常需要将自己的代码注入到目标进程中，或者拦截（hook）目标函数的执行。重新定位器是实现这些操作的关键组件。当我们插入代码时，我们可能需要将目标函数的一部分代码移动到我们控制的区域，并确保跳转指令仍然指向正确的位置。
    * **例子：** 假设我们要 hook 函数 `foo` 的开头。Frida 可能会将 `foo` 开头的几条指令复制到一个新的内存位置，并在 `foo` 的开头放置一个跳转指令跳到我们的 hook 函数。`gumarmrelocator.c` 就负责将 `foo` 开头的指令复制到新位置，并确保其中任何 PC 相关的指令在新的位置仍然正确工作。
* **动态代码分析:**  理解程序在运行时的行为。通过动态地修改代码，我们可以插入探针来收集信息，例如函数调用参数、返回值等。重新定位器确保插入的代码不会破坏原始程序的执行流程。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **ARM 架构:** 代码中大量使用了 ARM 指令集的特定标识符 (例如 `ARM_INS_LDR`, `ARM_REG_PC`, `ARM_CC_AL`)，以及 ARM 的寻址模式和指令格式。
* **程序计数器 (PC):**  代码特别关注与 PC 寄存器相关的指令，因为这些指令在代码重新定位后可能失效。例如，`LDR Rx, [PC, #offset]`  这条指令依赖于当前 PC 的值来计算加载地址。
* **内存管理:**  重新定位器需要在目标进程的内存空间中分配新的内存区域来存放被移动的代码。这涉及到对进程内存布局的理解。
* **Capstone 反汇编引擎:**  使用了 Capstone 库来进行指令的解码和分析。Capstone 是一个跨平台的反汇编框架，支持多种 CPU 架构。
* **Linux/Android 进程内存模型:**  理解代码段、数据段、堆栈等概念，以及进程地址空间的布局，对于安全地进行代码注入和重新定位至关重要。
* **调用约定 (Calling Conventions):**  在 hook 函数时，需要理解 ARM 的调用约定，以便正确地保存和恢复寄存器状态。

**逻辑推理及假设输入与输出:**

* **假设输入:**
    * `input_code`: 指向要重新定位的 ARM 指令序列的内存地址。
    * `min_bytes`:  要重新定位的最小字节数。
    * `to`:  目标内存地址，用于存放重新定位后的指令。
* **逻辑推理:**
    1. 逐条读取 `input_code` 指向的指令。
    2. 对于每一条指令，判断是否需要重写（例如，是否包含 PC 相关的操作）。
    3. 如果需要重写，则生成新的指令序列，实现相同的功能，但不依赖于原始代码的位置。
    4. 将原始指令（如果不需要重写）或新的指令序列写入到 `to` 指向的内存地址。
* **输出:**
    * `gum_arm_relocator_relocate` 返回实际重新定位的字节数。
    * `to` 指向的内存区域包含重新定位后的 ARM 指令序列。

**涉及用户或编程常见的使用错误及举例说明:**

* **提供的输入代码地址不正确:** 如果 `input_code` 指向的不是有效的 ARM 指令序列的开始，Capstone 可能无法正确反汇编，导致程序崩溃或产生不可预测的结果。
    * **例子：** 用户可能误将数据段的地址传递给了 `gum_arm_relocator_relocate`。
* **输出缓冲区太小:**  如果 `to` 指向的内存区域没有足够的空间来存放重新定位后的指令，可能会发生缓冲区溢出。一些指令在重写后可能会比原始指令更长。
    * **例子：** 用户可能分配了一个与 `min_bytes` 大小相同的缓冲区，但某些指令在重写后需要更多空间。
* **尝试重新定位不完整的指令:**  如果 `min_bytes` 参数指定的大小不足以包含一条完整的指令，可能会导致反汇编失败。
* **在不安全的时间进行重新定位:**  如果在多线程环境下，在代码正在执行时进行重新定位，可能会导致竞争条件和程序崩溃。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要使用 Frida 对 Android 或 Linux 上的 ARM 应用程序进行动态分析或修改。**
2. **用户编写 Frida 脚本，使用 `Interceptor` API 来拦截目标函数。** 例如：
   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'target_function'), {
     onEnter: function(args) {
       console.log('Entered target_function');
     },
     onLeave: function(retval) {
       console.log('Left target_function');
     }
   });
   ```
3. **Frida 进程将脚本发送到目标应用程序。**
4. **当目标应用程序执行到 `target_function` 时，Frida 的 Gum 引擎会被触发。**
5. **为了执行 `Interceptor.attach`，Frida 需要在 `target_function` 的开头注入一段代码（通常是一个跳转指令），以便在函数入口和出口执行用户提供的 JavaScript 代码。**
6. **为了安全地注入代码，Frida 需要将 `target_function` 开头的一些原始指令移动到一个新的位置，并用跳转指令替换它们。**
7. **`gumarmrelocator.c` 中的代码会被调用，负责读取 `target_function` 开头的指令，并将其重新定位到 Frida 分配的内存区域。**  这个过程会调用 `gum_arm_relocator_read_one` 来解析指令，并根据需要调用 `gum_arm_relocator_rewrite_...` 函数来重写包含 PC 相对引用的指令。最后，使用 `GumArmWriter` 将原始或重写后的指令写入到新的内存位置。
8. **调试线索：** 如果在 Frida 脚本执行过程中出现与代码执行或内存访问相关的错误，可以怀疑是指令重定位过程出现了问题。例如，如果程序崩溃在被 hook 的函数附近，并且错误信息指示访问了错误的内存地址，那么可能是 `gumarmrelocator.c` 没有正确处理某些类型的指令，导致重定位后的代码无法正确执行。可以通过查看 Frida 的日志输出，或者使用更底层的调试工具来跟踪指令的执行流程，从而定位到 `gumarmrelocator.c` 中的具体问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/arch-arm/gumarmrelocator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarmrelocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const cs_insn * insn;
  cs_arm * detail;
  GumAddress pc;

  GumArmWriter * output;
};

static gboolean gum_arm_branch_is_unconditional (const cs_insn * insn);
static gboolean gum_reg_dest_is_pc (const cs_insn * insn);
static gboolean gum_reg_list_contains_pc (const cs_insn * insn,
    guint8 start_index);

static gboolean gum_arm_relocator_rewrite_ldr (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_mov (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_add (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_sub (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_b (GumArmRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_bl (GumArmRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);

GumArmRelocator *
gum_arm_relocator_new (gconstpointer input_code,
                       GumArmWriter * output)
{
  GumArmRelocator * relocator;

  relocator = g_slice_new (GumArmRelocator);

  gum_arm_relocator_init (relocator, input_code, output);

  return relocator;
}

GumArmRelocator *
gum_arm_relocator_ref (GumArmRelocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_arm_relocator_unref (GumArmRelocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_arm_relocator_clear (relocator);

    g_slice_free (GumArmRelocator, relocator);
  }
}

void
gum_arm_relocator_init (GumArmRelocator * relocator,
                        gconstpointer input_code,
                        GumArmWriter * output)
{
  relocator->ref_count = 1;

  cs_arch_register_arm ();
  cs_open (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8, &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_arm_relocator_reset (relocator, input_code, output);
}

void
gum_arm_relocator_clear (GumArmRelocator * relocator)
{
  guint i;

  gum_arm_relocator_reset (relocator, NULL, NULL);

  for (i = 0; i != GUM_MAX_INPUT_INSN_COUNT; i++)
  {
    cs_insn * insn = relocator->input_insns[i];
    if (insn != NULL)
    {
      cs_free (insn, 1);
      relocator->input_insns[i] = NULL;
    }
  }
  g_free (relocator->input_insns);

  cs_close (&relocator->capstone);
}

void
gum_arm_relocator_reset (GumArmRelocator * relocator,
                         gconstpointer input_code,
                         GumArmWriter * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);

  if (output != NULL)
    gum_arm_writer_ref (output);
  if (relocator->output != NULL)
    gum_arm_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

static guint
gum_arm_relocator_inpos (GumArmRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_arm_relocator_outpos (GumArmRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_arm_relocator_increment_inpos (GumArmRelocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_arm_relocator_increment_outpos (GumArmRelocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_arm_relocator_read_one (GumArmRelocator * self,
                            const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_arm_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = 4;
  address = self->input_pc;
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

  switch (insn->id)
  {
    case ARM_INS_B:
    case ARM_INS_BX:
      self->eob = TRUE;
      self->eoi = gum_arm_branch_is_unconditional (insn);
      break;
    case ARM_INS_BL:
    case ARM_INS_BLX:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
    case ARM_INS_LDR:
    case ARM_INS_MOV:
    case ARM_INS_ADD:
    case ARM_INS_SUB:
      self->eob = self->eoi = gum_reg_dest_is_pc (insn);
      break;
    case ARM_INS_POP:
      self->eob = self->eoi = gum_reg_list_contains_pc (insn, 0);
      break;
    case ARM_INS_LDM:
      self->eob = self->eoi = gum_reg_list_contains_pc (insn, 1);
      break;
    default:
      self->eob = FALSE;
      break;
  }

  gum_arm_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur = code;
  self->input_pc = address;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_arm_relocator_peek_next_write_insn (GumArmRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_arm_relocator_outpos (self)];
}

gpointer
gum_arm_relocator_peek_next_write_source (GumArmRelocator * self)
{
  cs_insn * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_arm_relocator_skip_one (GumArmRelocator * self)
{
  gum_arm_relocator_increment_outpos (self);
}

gboolean
gum_arm_relocator_write_one (GumArmRelocator * self)
{
  const cs_insn * insn;
  GumCodeGenCtx ctx;
  gboolean rewritten;

  if ((insn = gum_arm_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm_relocator_increment_outpos (self);
  ctx.insn = insn;
  ctx.detail = &ctx.insn->detail->arm;
  ctx.pc = insn->address + 8;
  ctx.output = self->output;

  switch (insn->id)
  {
    case ARM_INS_LDR:
      rewritten = gum_arm_relocator_rewrite_ldr (self, &ctx);
      break;
    case ARM_INS_MOV:
      rewritten = gum_arm_relocator_rewrite_mov (self, &ctx);
      break;
    case ARM_INS_ADD:
      rewritten = gum_arm_relocator_rewrite_add (self, &ctx);
      break;
    case ARM_INS_SUB:
      rewritten = gum_arm_relocator_rewrite_sub (self, &ctx);
      break;
    case ARM_INS_B:
      rewritten = gum_arm_relocator_rewrite_b (self, CS_MODE_ARM, &ctx);
      break;
    case ARM_INS_BX:
      rewritten = gum_arm_relocator_rewrite_b (self, CS_MODE_THUMB, &ctx);
      break;
    case ARM_INS_BL:
      rewritten = gum_arm_relocator_rewrite_bl (self, CS_MODE_ARM, &ctx);
      break;
    case ARM_INS_BLX:
      rewritten = gum_arm_relocator_rewrite_bl (self, CS_MODE_THUMB, &ctx);
      break;
    default:
      rewritten = FALSE;
      break;
  }

  if (!rewritten)
    gum_arm_writer_put_bytes (ctx.output, insn->bytes, insn->size);

  return TRUE;
}

void
gum_arm_relocator_write_all (GumArmRelocator * self)
{
  G_GNUC_UNUSED guint count = 0;

  while (gum_arm_relocator_write_one (self))
    count++;

  g_assert (count > 0);
}

gboolean
gum_arm_relocator_eob (GumArmRelocator * self)
{
  return self->eob;
}

gboolean
gum_arm_relocator_eoi (GumArmRelocator * self)
{
  return self->eoi;
}

gboolean
gum_arm_relocator_can_relocate (gpointer address,
                                guint min_bytes,
                                guint * maximum)
{
  guint n = 0;
  guint8 * buf;
  GumArmWriter cw;
  GumArmRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_arm_writer_init (&cw, buf);
  cw.cpu_features = gum_query_cpu_features ();

  gum_arm_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_clear (&rl);

  gum_arm_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

guint
gum_arm_relocator_relocate (gpointer from,
                            guint min_bytes,
                            gpointer to)
{
  GumArmWriter cw;
  GumArmRelocator rl;
  guint reloc_bytes;

  gum_arm_writer_init (&cw, to);
  cw.cpu_features = gum_query_cpu_features ();

  gum_arm_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (&rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_write_all (&rl);

  gum_arm_relocator_clear (&rl);
  gum_arm_writer_clear (&cw);

  return reloc_bytes;
}

static gboolean
gum_arm_branch_is_unconditional (const cs_insn * insn)
{
  switch (insn->detail->arm.cc)
  {
    case ARM_CC_INVALID:
    case ARM_CC_AL:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_reg_dest_is_pc (const cs_insn * insn)
{
  return insn->detail->arm.operands[0].reg == ARM_REG_PC;
}

static gboolean
gum_reg_list_contains_pc (const cs_insn * insn,
                          guint8 start_index)
{
  guint8 i;

  for (i = start_index; i < insn->detail->arm.op_count; i++)
  {
    if (insn->detail->arm.operands[i].reg == ARM_REG_PC)
      return TRUE;
  }

  return FALSE;
}

static gboolean
gum_arm_relocator_rewrite_ldr (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];
  arm_reg target;

  if (src->type != ARM_OP_MEM || src->mem.base != ARM_REG_PC)
    return FALSE;

  if (ctx->detail->writeback)
  {
    /* FIXME: LDR with writeback not yet supported. */
    g_assert_not_reached ();
    return FALSE;
  }

  if (dst->reg == ARM_REG_PC)
  {
    /*
     * When choosing a scratch register, we favor Rm since it is often this
     * value we wish to use to start our calculation and this avoids a register
     * move.
     *
     * If however Rm is an immediate, we choose an arbitrary register.
     */
    target = (src->mem.index != ARM_REG_INVALID) ? src->mem.index : ARM_REG_R0;

    gum_arm_writer_put_push_regs (ctx->output, 2, target, ARM_REG_PC);
  }
  else
  {
    target = dst->reg;
  }

  /* Handle 'LDR Rt, [Rn, #x]' or 'LDR Rt, [Rn, #-x]' */
  if (src->mem.index == ARM_REG_INVALID)
  {
    gum_arm_writer_put_ldr_reg_address (ctx->output, target,
        ctx->pc + src->mem.disp);
  }
  else
  {
    if (src->subtracted)
    {
      /* FIXME: 'LDR Rt, [Rn, -Rm, #x]' not yet supported. */
      gum_arm_writer_put_breakpoint (ctx->output);
      return TRUE;
    }

    /* Handle 'LDR Rt, [Rn, Rm, lsl #x]' */
    gum_arm_writer_put_mov_reg_reg_shift (ctx->output, target, src->mem.index,
        src->shift.type, src->shift.value);

    gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
  }

  gum_arm_writer_put_ldr_reg_reg_offset (ctx->output, target, target, 0);

  if (dst->reg == ARM_REG_PC)
  {
    gum_arm_writer_put_str_reg_reg_offset (ctx->output, target, ARM_REG_SP, 4);
    gum_arm_writer_put_pop_regs (ctx->output, 2, target, ARM_REG_PC);
  }

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_mov (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];

  if (src->type != ARM_OP_REG || src->reg != ARM_REG_PC)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);
  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_add (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * operands = ctx->detail->operands;
  const cs_arm_op * dst = &operands[0];
  const cs_arm_op * left = &operands[1];
  const cs_arm_op * right = &operands[2];
  arm_reg target;

  if (right->type == ARM_OP_REG && right->reg == ARM_REG_PC)
  {
    const cs_arm_op * l = left;
    left = right;
    right = l;
  }

  if (left->reg != ARM_REG_PC)
    return FALSE;

  if (dst->reg == ARM_REG_PC)
  {
    /*
     * When choosing a scratch register, we favor Rm since it is often this
     * value we wish to use to start our calculation and this avoids a register
     * move.
     *
     * If however Rm is an immediate, we choose an arbitrary register.
     */
    target = (right->type == ARM_OP_REG) ? right->reg : ARM_REG_R0;

    gum_arm_writer_put_push_regs (ctx->output, 2, target, ARM_REG_PC);
  }
  else
  {
    target = dst->reg;
  }

  if (right->shift.value == 0 && ctx->detail->op_count < 4)
  {
    /*
     * We have no shift to apply, so we start our calculation with the value of
     * PC since we can store this as a literal in the code stream and reduce the
     * number of instructions we need to generate.
     */
    if (right->type == ARM_OP_IMM)
    {
      /* Handle 'ADD Rd, Rn, #x' */
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_add_reg_u32 (ctx->output, target, right->imm);
    }
    else if (right->reg == dst->reg)
    {
      /*
       * Handle 'ADD Rd, Rn, Rd'. This is a special case since we cannot load PC
       * from a literal into Rd since in doing so, we lose the value of Rm which
       * we want to add on. This calculation can be simplified to just adding
       * the PC to Rd.
       */
      gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
    }
    else
    {
      /* Handle 'ADD Rd, Rn, Rm' */
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_add_reg_reg_reg (ctx->output, target, target,
          right->reg);
    }
  }
  else
  {
    /*
     * As we have a shift operation to apply, we must start by calculating this
     * value and adding on PC, as we would otherwise need a second scratch
     * register to calculate this. Note that in this case, we don't have to
     * worry if Rd == Rm since although we may be using Rd to hold the
     * intermediate result, we perform all necessary calculations on Rm before
     * we update Rd.
     */

    if (right->type == ARM_OP_IMM)
    {
      /* Handle 'ADD Rd, Rn, #x, lsl #n' */
      gum_arm_writer_put_ldr_reg_u32 (ctx->output, target, right->imm);
    }
    else
    {
      /* Handle 'ADD Rd, Rn, Rm, lsl #n' */
      gum_arm_writer_put_mov_reg_reg (ctx->output, target, right->reg);
    }

    if (ctx->detail->op_count < 4)
    {
      gum_arm_writer_put_mov_reg_reg_shift (ctx->output, target, target,
          right->shift.type, right->shift.value);
    }
    else
    {
      gum_arm_writer_put_mov_reg_reg_shift (ctx->output, target, target,
          ARM_SFT_ROR, operands[3].imm);
    }

    /*
     * Now the shifted second operand has been calculated, we can simply add the
     * PC value.
     */
    gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
  }

  if (dst->reg == ARM_REG_PC)
  {
    gum_arm_writer_put_str_reg_reg_offset (ctx->output, target, ARM_REG_SP, 4);
    gum_arm_writer_put_pop_regs (ctx->output, 2, target, ARM_REG_PC);
  }

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_sub (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * operands = ctx->detail->operands;
  const cs_arm_op * dst = &operands[0];
  const cs_arm_op * left = &operands[1];
  const cs_arm_op * right = &operands[2];
  gboolean pc_is_involved;
  arm_reg target;

  pc_is_involved = (left->type == ARM_OP_REG && left->reg == ARM_REG_PC) ||
      (right->type == ARM_OP_REG && right->reg == ARM_REG_PC);
  if (!pc_is_involved)
    return FALSE;

  if (dst->reg == ARM_REG_PC)
  {
    /*
     * When choosing a scratch register, we favor Rm since it is often this
     * value we wish to use to start our calculation and this avoids a register
     * move.
     *
     * If however Rm is an immediate, we choose an arbitrary register.
     */
    target = (right->type == ARM_OP_REG && right->reg != ARM_REG_PC)
        ? right->reg
        : ARM_REG_R0;

    gum_arm_writer_put_push_regs (ctx->output, 2, target, ARM_REG_PC);
  }
  else
  {
    target = dst->reg;
  }

  if (right->shift.value == 0)
  {
    /*
     * We have no shift to apply, so we start our calculation with the value of
     * PC since we can store this as a literal in the code stream and reduce the
     * number of instructions we need to generate.
     */
    if (right->type == ARM_OP_IMM)
    {
      /* Handle 'SUB Rd, PC, #x'. */
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_sub_reg_u32 (ctx->output, target, right->imm);
    }
    else if (dst->reg == left->reg && left->reg == right->reg)
    {
      /* Handle 'SUB, PC, PC, PC'. */
      gum_arm_writer_put_sub_reg_reg_reg (ctx->output, target, target, target);
    }
    else if (left->reg == dst->reg)
    {
      if (left->reg == ARM_REG_PC)
      {
        /* Handle 'SUB PC, PC, Rm'. */
        gum_arm_writer_put_rsb_reg_reg_imm (ctx->output, target, target, 0);
        gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
      }
      else
      {
        /* Handle 'SUB Rd, Rd, PC'. */
        gum_arm_writer_put_sub_reg_u32 (ctx->output, target, ctx->pc);
      }
    }
    else if (right->reg == dst->reg)
    {
      if (right->reg == ARM_REG_PC)
      {
        /* Handle 'SUB PC, Rn, PC'. */
        gum_arm_writer_put_mov_reg_reg (ctx->output, target, left->reg);
        gum_arm_writer_put_sub_reg_u32 (ctx->output, target, ctx->pc);
      }
      else
      {
        /* Handle 'SUB Rd, PC, Rd'. */
        gum_arm_writer_put_rsb_reg_reg_imm (ctx->output, target, target, 0);
        gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
      }
    }
    else if (left->reg == ARM_REG_PC)
    {
      /* Handle 'SUB Rd, PC, Rm'. */
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_sub_reg_reg_imm (ctx->output, target, right->reg, 0);
    }
    else if (right->reg == ARM_REG_PC)
    {
      /* Handle 'SUB Rd, Rn, PC'. */
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_rsb_reg_reg_imm (ctx->output, target, target, 0);
      gum_arm_writer_put_add_reg_reg_imm (ctx->output, target, left->reg, 0);
    }
  }
  else
  {
    /*
     * As we have a shift operation to apply, we must start by calculating this
     * value and subtracting from PC, as we would otherwise need a second
     * scratch register to calculate this. Note that in this case, we don't have
     * to worry if Rd == Rm since although we may be using Rd to hold the
     * intermediate result, we perform all necessary calculations on Rm before
     * we update Rd.
     */
    if (right->type == ARM_OP_IMM)
    {
      /* Handle 'SUB Rd, PC, #x, lsl #n'. */
      gum_arm_writer_put_ldr_reg_u32 (ctx->output, target, right->imm);
    }
    else
    {
      /*
      * Whilst technically possible, it seems quite unlikely that anyone would
      * want to perform any shifting operations on the PC itself.
      */
      g_assert (right->reg != ARM_REG_PC);

      /* Handle 'SUB Rd, PC, Rm, lsl #n'. */
      gum_arm_writer_put_mov_reg_reg (ctx->output, target, right->reg);
    }

    gum_arm_writer_put_mov_reg_reg_shift (ctx->output, target, target,
        right->shift.type, right->shift.value);

    /*
     * Now the shifted second operand has been calculated, we can negate it and
     * add the PC value.
     */
    gum_arm_writer_put_rsb_reg_reg_imm (ctx->output, target, target, 0);
    gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
  }

  if (dst->reg == ARM_REG_PC)
  {
    gum_arm_writer_put_str_reg_reg_offset (ctx->output, target, ARM_REG_SP, 4);
    gum_arm_writer_put_pop_regs (ctx->output, 2, target, ARM_REG_PC);
  }

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_b (GumArmRelocator * self,
                             cs_mode target_mode,
                             GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, ARM_REG_PC,
      (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_bl (GumArmRelocator * self,
                              cs_mode target_mode,
                              GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, ARM_REG_LR,
      ctx->output->pc + (2 * 4));
  gum_arm_writer_put_ldr_reg_address (ctx->output, ARM_REG_PC,
      (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
  return TRUE;
}
```