Response:
The user wants a functional summary of the provided C code for `gumx86writer.c`, a part of the Frida dynamic instrumentation toolkit. I need to extract the core functionalities, especially those related to reverse engineering, low-level operations (binary, Linux/Android kernel/framework), logical inferences, potential user errors, and debugging contexts. Since this is part 1 of 3, I should focus on summarizing the functions defined in this specific chunk of code.

Here’s a breakdown of the steps:

1. **Identify Core Functionalities:** Go through each function and understand its primary purpose. Look for keywords related to code generation, instruction manipulation, and memory management.

2. **Reverse Engineering Relevance:**  Note functions that directly deal with x86 instructions (like `put_call_address`, `put_jmp_reg`), register manipulation, and control flow modification, as these are central to reverse engineering tasks like hooking and code injection.

3. **Low-Level Details:** Look for functions interacting with memory addresses, CPU registers, and instruction encoding (like prefix handling). Pay attention to the distinction between 32-bit and 64-bit architectures and different calling conventions.

4. **Logical Inferences:**  Analyze functions that make decisions based on input (e.g., choosing between short and near jumps based on distance). Identify any assumptions made and the resulting output.

5. **User Errors:**  Consider common mistakes a user might make when using these functions (e.g., providing an out-of-range address for a short jump).

6. **Debugging Context:**  Think about how a user would arrive at this code. This involves understanding the higher-level Frida API and how it uses `GumX86Writer` internally.

7. **Part 1 Summary:**  Condense the identified functionalities into a concise summary, as requested for this part.

**Mental Sandbox:**

* **Instruction Emission:** The code seems to be building x86 instructions byte by byte. Functions like `gum_x86_writer_put_u8`, `gum_x86_writer_put_s8`, and committing bytes (`gum_x86_writer_commit`) confirm this.
* **Label Management:**  The presence of `label_defs` and `label_refs` suggests a mechanism for handling relative jumps and calls within the generated code. This is crucial for patching and injecting code.
* **Calling Convention Support:** Functions related to argument setup (`gum_x86_writer_put_argument_list_setup`) indicate support for different calling conventions, which is vital for interacting with existing functions in a target process.
* **Architecture-Specifics:** The code distinguishes between IA32 and AMD64 architectures, demonstrating awareness of different instruction sets and register usage.
* **Error Handling:**  Some functions return `gboolean` indicating success or failure, suggesting basic error handling.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果它与逆向的方法有关系，请做出对应的举例说明: Yes
3. 如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明: Yes
4. 如果做了逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
6. 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
7. 这是第1部分，共3部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I am confident I can address all the requirements.

Strategizing complete. I will now proceed with generating the response based on the identified functionalities and considerations.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/arch-x86/gumx86writer.c` 文件的功能。

**功能归纳（针对第1部分代码）：**

这个C文件定义了一个名为 `GumX86Writer` 的结构体，并提供了一系列函数来动态生成 x86 和 x86-64 架构的机器码。 它的主要功能是提供一个抽象层，允许开发者以编程方式构建 x86 指令序列，而无需手动处理原始的字节码。 这对于 Frida 这样的动态插桩工具至关重要，因为它需要在运行时修改目标进程的代码。

更具体地说，到目前为止的代码实现了以下功能：

1. **代码生成基础设施:**
   - **`gum_x86_writer_new` 和 `gum_x86_writer_init`:**  创建和初始化 `GumX86Writer` 实例，分配内存来存储生成的代码。
   - **`gum_x86_writer_ref` 和 `gum_x86_writer_unref`:**  提供引用计数机制，用于管理 `GumX86Writer` 实例的生命周期。
   - **`gum_x86_writer_clear`:** 清理 `GumX86Writer` 实例，包括刷新（写入）生成的代码和释放资源。
   - **`gum_x86_writer_reset`:** 重置 `GumX86Writer` 的状态，使其可以用于生成新的代码块。
   - **`gum_x86_writer_set_target_cpu` 和 `gum_x86_writer_set_target_abi`:** 设置目标 CPU 架构（IA32 或 AMD64）和 ABI（应用程序二进制接口，例如 Unix 或 Windows）。这会影响指令的生成方式。
   - **`gum_x86_writer_cur` 和 `gum_x86_writer_offset`:** 获取当前代码生成的位置和相对于起始地址的偏移量。
   - **`gum_x86_writer_commit`:**  提交指定数量的字节到代码缓冲区，更新内部指针。
   - **`gum_x86_writer_flush`:**  处理和解析代码中引用的标签，计算跳转距离，并将最终的地址填入相应的指令中。这是将逻辑标签转换为实际机器码地址的关键步骤。

2. **标签（Label）管理:**
   - **`gum_x86_writer_put_label`:** 在当前代码位置定义一个标签，用于后续的跳转或调用。
   - **`gum_x86_writer_add_label_reference_here`:**  记录一个对特定标签的引用，包括引用位置和跳转类型（短跳转、近跳转、绝对跳转）。

3. **控制流指令生成:**
   - **`gum_x86_writer_can_branch_directly_between`:**  检查两个地址之间是否可以使用直接跳转指令（即，跳转距离是否在允许的范围内）。
   - **`gum_x86_writer_put_call_address_with_arguments` 等一系列 `put_call_*` 函数:** 生成 `call` 指令来调用指定地址的函数，并负责处理函数参数的传递，包括寄存器传参和栈传参，并区分不同的调用约定 (calling convention)。
   - **`gum_x86_writer_put_call_reg_with_arguments` 等一系列 `put_call_*` 函数:** 生成 `call` 指令来调用寄存器中存储的地址所指向的函数，同样处理参数传递。
   - **`gum_x86_writer_put_call_address`:** 生成直接调用指定地址的 `call` 指令。
   - **`gum_x86_writer_put_call_reg`:** 生成调用指定寄存器中地址的 `call` 指令。
   - **`gum_x86_writer_put_call_reg_offset_ptr`:** 生成通过寄存器加偏移量寻址并调用的 `call` 指令。
   - **`gum_x86_writer_put_call_indirect` 和 `gum_x86_writer_put_call_indirect_label`:** 生成间接调用指令，通过内存地址或标签来确定调用目标。
   - **`gum_x86_writer_put_call_near_label`:** 生成调用近距离标签的 `call` 指令。
   - **`gum_x86_writer_put_leave`:** 生成 `leave` 指令，用于清理栈帧。
   - **`gum_x86_writer_put_ret` 和 `gum_x86_writer_put_ret_imm`:** 生成 `ret` 指令，用于从函数返回。
   - **`gum_x86_writer_put_jmp_address`:** 生成跳转到指定地址的 `jmp` 指令。
   - **`gum_x86_writer_put_jmp_short_label` 和 `gum_x86_writer_put_jmp_near_label`:** 生成跳转到标签的 `jmp` 指令。
   - **`gum_x86_writer_put_jmp_reg` 和 `gum_x86_writer_put_jmp_reg_ptr` 和 `gum_x86_writer_put_jmp_reg_offset_ptr`:** 生成跳转到寄存器或内存地址的 `jmp` 指令。
   - **`gum_x86_writer_put_jmp_near_ptr`:** 生成跳转到内存地址的 `jmp` 指令。

4. **参数处理:**
   - **`gum_x86_writer_get_cpu_register_for_nth_argument`:**  根据目标 CPU 和 ABI，获取用于传递第 n 个参数的寄存器。
   - **`gum_x86_writer_put_argument_list_setup` 和 `gum_x86_writer_put_argument_list_setup_va`:**  根据调用约定和参数列表，生成将参数放置到正确位置（寄存器或栈）的代码。
   - **`gum_x86_writer_put_argument_list_teardown`:**  在函数调用后，生成清理栈上参数的代码（如果需要）。
   - **`gum_x86_writer_put_aligned_argument_list_setup` 和相关函数:**  处理需要栈对齐的函数调用。
   - **`gum_x86_writer_get_needed_alignment_correction`:** 计算进行栈对齐所需的调整量。

**与逆向方法的关联和举例说明:**

`GumX86Writer` 是 Frida 进行动态插桩的核心组件，与逆向方法紧密相关。以下是一些例子：

* **代码注入 (Code Injection):**  逆向工程师可以使用 `GumX86Writer` 来构建恶意代码或 hook 代码，然后将其注入到目标进程中。例如，可以使用 `gum_x86_writer_put_call_address` 来调用自定义的恶意函数，或者使用 `gum_x86_writer_put_jmp_address` 来修改程序的执行流程。
    * **例子:**  假设需要在函数 `target_function` 的入口处插入一段代码，记录函数的调用次数。可以使用 `gum_x86_writer_put_call_address` 来调用一个计数器函数，然后使用 `gum_x86_writer_put_jmp_address` 跳回 `target_function` 的原始代码。
* **Hooking:**  `GumX86Writer` 可以用来生成 hook 代码，拦截对特定函数的调用。
    * **例子:** 可以使用 `gum_x86_writer_put_jmp_address` 将目标函数的入口点重定向到自定义的 hook 函数。Hook 函数可以使用 `gum_x86_writer_put_call_address` 调用原始函数，并在调用前后执行额外的逻辑（例如，记录参数或修改返回值）。
* **动态修改代码:**  在运行时修改目标进程的代码，例如，修复 bug、添加功能或绕过安全检查。
    * **例子:** 可以使用 `GumX86Writer` 生成新的指令序列来替换目标进程中现有的指令。

**涉及二进制底层、Linux/Android 内核及框架的知识和举例说明:**

* **二进制指令编码:**  `GumX86Writer` 需要理解 x86 和 x86-64 指令的二进制编码格式，才能正确地生成机器码。例如，不同的指令有不同的操作码、ModR/M 字节、SIB 字节和立即数编码方式。
* **寄存器:**  代码中大量使用了 `GumX86Reg` 枚举，表示不同的 x86 寄存器（如 EAX, ESP, RDI 等）。理解这些寄存器的用途和调用约定是至关重要的。
* **调用约定 (Calling Conventions):**  不同的操作系统和编译器使用不同的调用约定来传递函数参数和管理栈。`GumX86Writer` 必须了解这些约定（例如，CDECL, STDCALL, fastcall 等），才能生成正确的参数传递代码。
    * **例子:** 在 Linux x86-64 系统中，前 6 个整型或指针类型的参数通常通过寄存器 RDI, RSI, RDX, RCX, R8, R9 传递。`gum_x86_writer_get_cpu_register_for_nth_argument` 函数会根据目标 ABI 返回相应的寄存器。
* **栈操作:**  函数调用和返回涉及到栈的操作（push, pop）。`GumX86Writer` 生成的代码会操作栈来传递参数、保存返回地址和局部变量。
* **内存地址:**  `GumAddress` 类型表示内存地址。在进行代码注入和 hook 时，需要准确地获取目标进程的内存地址。
* **内核和框架知识 (间接体现):**  虽然代码本身没有直接操作内核或框架，但 Frida 作为用户态工具，经常用于分析和修改运行在内核或框架层的代码。`GumX86Writer` 生成的代码可能会与内核或框架的 API 进行交互。

**逻辑推理、假设输入与输出:**

* **`gum_x86_writer_can_branch_directly_between(from, to)`:**
    * **假设输入:** `from = 0x1000`, `to = 0x100A`
    * **逻辑推理:** 计算距离 `distance = to - (from + 5) = 0x100A - 0x1005 = 5`。检查 5 是否在 `G_MININT32` 和 `G_MAXINT32` 的范围内。由于跳转指令通常是 5 个字节 (操作码 + 4 字节偏移)，所以要减去 5。
    * **输出:** `TRUE` (因为距离很小，可以使用直接跳转)
    * **假设输入:** `from = 0x1000`, `to = 0x100000000` (一个很远的地址)
    * **逻辑推理:** 计算出的距离会超出 `G_MAXINT32` 的范围。
    * **输出:** `FALSE` (需要使用间接跳转或其他方式)

* **`gum_x86_writer_flush`:**
    * **假设输入:** 代码中有一个对标签 `my_label` 的近跳转 (`GUM_LREF_NEAR`)，标签 `my_label` 定义在地址 `0x2000`，跳转指令位于地址 `0x1500`。
    * **逻辑推理:** `gum_x86_writer_flush` 会计算跳转距离 `0x2000 - (0x1500 + 5) = 0xAFB`。然后，将这个距离的小端表示写入跳转指令的偏移部分。
    * **输出:**  跳转指令的 1-4 字节将被修改为 `FB 0A 00 00` (假设小端序)。

**涉及用户或编程常见的使用错误:**

* **目标地址超出短跳转范围:** 用户尝试使用 `gum_x86_writer_put_jmp_short_label` 跳转到一个距离当前位置超过 +/- 127 字节的标签。这会导致 `gum_x86_writer_flush` 失败或生成错误的跳转。
* **调用约定不匹配:**  用户在调用外部函数时，使用了错误的调用约定设置。例如，在 Windows x64 系统上调用一个使用 CDECL 约定的函数时，没有清理栈上的参数，可能导致程序崩溃或行为异常。
* **内存分配不足:**  用户尝试生成的代码量超过了 `GumX86Writer` 内部缓冲区的容量。这可能导致内存溢出或其他不可预测的行为。
* **忘记 `flush`:** 用户生成了包含标签引用的代码，但忘记调用 `gum_x86_writer_flush` 来解析这些引用，导致生成的代码包含未解析的占位符。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为调试线索，了解用户如何使用 Frida 最终调用到 `gumx86writer.c` 中的函数非常重要。通常的步骤如下：

1. **编写 Frida 脚本:** 用户编写 JavaScript 或 Python 脚本，使用 Frida 的 API 来进行插桩。
2. **选择目标进程和函数:**  用户通过 Frida 的 API (例如 `Interceptor.attach`) 选择要 hook 的目标进程和函数。
3. **定义 hook 代码:** 用户提供一个 JavaScript 或 Python 的回调函数，Frida 会在这个回调函数中执行用户自定义的逻辑。
4. **Frida 内部操作:**
   - Frida 的 JavaScript 或 Python 绑定会调用 GumJS 或 GumPy 的代码。
   - GumJS/GumPy 会使用 `Gum` 核心库的功能。
   - 当需要生成机器码来替换或插入代码时，`Gum` 会根据目标架构选择合适的 Writer，这里就是 `GumX86Writer`。
   - 用户在回调函数中执行的某些操作，例如调用 `Memory.allocCode` 分配可执行内存，或者使用 `Instruction.build` 构建指令，最终会调用到 `GumX86Writer` 的相关函数来生成底层的机器码。
   - 例如，如果用户想在 hook 函数中调用原始函数，Frida 内部会使用 `GumX86Writer` 生成一段代码，将参数传递给原始函数，调用原始函数，并处理返回值。

因此，当在 `gumx86writer.c` 中设置断点进行调试时，调用堆栈通常会回溯到用户的 Frida 脚本和 Frida 的内部实现。

希望这个详细的分析对您有所帮助！

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/arch-x86/gumx86writer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2009-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 * Copyright (C) 2024 Yannis Juglaret <yjuglaret@mozilla.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumx86writer.h"

#include "gumlibc.h"
#include "gummemory.h"

typedef guint GumX86MetaReg;
typedef struct _GumX86RegInfo GumX86RegInfo;
typedef guint GumX86LabelRefSize;
typedef struct _GumX86LabelRef GumX86LabelRef;

enum _GumX86MetaReg
{
  GUM_X86_META_XAX = 0,
  GUM_X86_META_XCX,
  GUM_X86_META_XDX,
  GUM_X86_META_XBX,
  GUM_X86_META_XSP,
  GUM_X86_META_XBP,
  GUM_X86_META_XSI,
  GUM_X86_META_XDI,
  GUM_X86_META_R8,
  GUM_X86_META_R9,
  GUM_X86_META_R10,
  GUM_X86_META_R11,
  GUM_X86_META_R12,
  GUM_X86_META_R13,
  GUM_X86_META_R14,
  GUM_X86_META_R15
};

struct _GumX86RegInfo
{
  GumX86MetaReg meta;
  guint width;
  guint index;
  gboolean index_is_extended;
};

enum _GumX86LabelRefSize
{
  GUM_LREF_SHORT,
  GUM_LREF_NEAR,
  GUM_LREF_ABS
};

struct _GumX86LabelRef
{
  gconstpointer id;
  guint8 * address;
  GumX86LabelRefSize size;
};

static void gum_x86_writer_put_argument_list_setup (GumX86Writer * self,
    GumCallingConvention conv, guint n_args, const GumArgument * args);
static void gum_x86_writer_put_argument_list_setup_va (GumX86Writer * self,
    GumCallingConvention conv, guint n_args, va_list args);
static void gum_x86_writer_put_argument_list_teardown (GumX86Writer * self,
    GumCallingConvention conv, guint n_args);
static void gum_x86_writer_put_aligned_argument_list_setup (GumX86Writer * self,
    GumCallingConvention conv, guint n_args, const GumArgument * args);
static void gum_x86_writer_put_aligned_argument_list_setup_va (
    GumX86Writer * self, GumCallingConvention conv, guint n_args, va_list args);
static void gum_x86_writer_put_aligned_argument_list_teardown (
    GumX86Writer * self, GumCallingConvention conv, guint n_args);
static guint gum_x86_writer_get_needed_alignment_correction (
    GumX86Writer * self, guint n_args);
static gboolean gum_x86_writer_put_short_jmp (GumX86Writer * self,
    gconstpointer target);
static gboolean gum_x86_writer_put_near_jmp (GumX86Writer * self,
    gconstpointer target);
static void gum_x86_writer_put_ud2 (GumX86Writer * self);
static gboolean gum_x86_writer_put_fx_save_or_restore_reg_ptr (
    GumX86Writer * self, guint8 operation, GumX86Reg reg);
static void gum_x86_writer_describe_cpu_reg (GumX86Writer * self,
    GumX86Reg reg, GumX86RegInfo * ri);

static GumX86MetaReg gum_meta_reg_from_cpu_reg (GumX86Reg reg);

static gboolean gum_x86_writer_put_prefix_for_reg_info (GumX86Writer * self,
    const GumX86RegInfo * ri, guint operand_index);
static gboolean gum_x86_writer_put_prefix_for_registers (GumX86Writer * self,
    const GumX86RegInfo * width_reg, guint default_width, ...);

static guint8 gum_get_jcc_opcode (x86_insn instruction_id);

GumX86Writer *
gum_x86_writer_new (gpointer code_address)
{
  GumX86Writer * writer;

  writer = g_slice_new (GumX86Writer);

  gum_x86_writer_init (writer, code_address);

  return writer;
}

GumX86Writer *
gum_x86_writer_ref (GumX86Writer * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_x86_writer_unref (GumX86Writer * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_x86_writer_clear (writer);

    g_slice_free (GumX86Writer, writer);
  }
}

void
gum_x86_writer_init (GumX86Writer * writer,
                     gpointer code_address)
{
  writer->ref_count = 1;
  writer->flush_on_destroy = TRUE;

  writer->label_defs = NULL;
  writer->label_refs.data = NULL;

  gum_x86_writer_reset (writer, code_address);
}

static gboolean
gum_x86_writer_has_label_defs (GumX86Writer * self)
{
  return self->label_defs != NULL;
}

static gboolean
gum_x86_writer_has_label_refs (GumX86Writer * self)
{
  return self->label_refs.data != NULL;
}

void
gum_x86_writer_clear (GumX86Writer * writer)
{
  if (writer->flush_on_destroy)
    gum_x86_writer_flush (writer);

  if (gum_x86_writer_has_label_defs (writer))
    gum_metal_hash_table_unref (writer->label_defs);

  if (gum_x86_writer_has_label_refs (writer))
    gum_metal_array_free (&writer->label_refs);
}

void
gum_x86_writer_reset (GumX86Writer * writer,
                      gpointer code_address)
{
#if GLIB_SIZEOF_VOID_P == 4
  writer->target_cpu = GUM_CPU_IA32;
#else
  writer->target_cpu = GUM_CPU_AMD64;
#endif
  writer->target_abi = GUM_NATIVE_ABI;
  writer->cpu_features = gum_query_cpu_features ();

  writer->base = (guint8 *) code_address;
  writer->code = (guint8 *) code_address;
  writer->pc = GUM_ADDRESS (code_address);

  if (gum_x86_writer_has_label_defs (writer))
    gum_metal_hash_table_remove_all (writer->label_defs);

  if (gum_x86_writer_has_label_refs (writer))
    gum_metal_array_remove_all (&writer->label_refs);
}

void
gum_x86_writer_set_target_cpu (GumX86Writer * self,
                               GumCpuType cpu_type)
{
  self->target_cpu = cpu_type;
}

void
gum_x86_writer_set_target_abi (GumX86Writer * self,
                               GumAbiType abi_type)
{
  self->target_abi = abi_type;
}

gpointer
gum_x86_writer_cur (GumX86Writer * self)
{
  return self->code;
}

guint
gum_x86_writer_offset (GumX86Writer * self)
{
  return self->code - self->base;
}

static void
gum_x86_writer_commit (GumX86Writer * self,
                       guint n)
{
  self->code += n;
  self->pc += n;
}

gboolean
gum_x86_writer_flush (GumX86Writer * self)
{
  guint num_refs, ref_index;

  if (!gum_x86_writer_has_label_refs (self))
    return TRUE;

  if (!gum_x86_writer_has_label_defs (self))
    return FALSE;

  num_refs = self->label_refs.length;

  for (ref_index = 0; ref_index != num_refs; ref_index++)
  {
    GumX86LabelRef * r;
    gpointer target_address;
    gint32 distance;

    r = gum_metal_array_element_at (&self->label_refs, ref_index);

    target_address = gum_metal_hash_table_lookup (self->label_defs, r->id);
    if (target_address == NULL)
      goto error;

    distance = (gssize) target_address - (gssize) r->address;

    switch (r->size)
    {
      case GUM_LREF_SHORT:
        if (!GUM_IS_WITHIN_INT8_RANGE (distance))
          goto error;
        *((gint8 *) (r->address - 1)) = distance;
        break;
      case GUM_LREF_NEAR:
        *((gint32 *) (r->address - 4)) = GINT32_TO_LE (distance);
        break;
      case GUM_LREF_ABS:
      {
        goffset target_offset;
        GumAddress base_pc, target_pc;

        target_offset = (guint8 *) target_address - self->base;

        base_pc = self->pc - gum_x86_writer_offset (self);
        target_pc = base_pc + target_offset;

        if (self->target_cpu == GUM_CPU_AMD64)
          *((guint64 *) (r->address - 8)) = GUINT64_TO_LE (target_pc);
        else
          *((guint32 *) (r->address - 4)) = GUINT32_TO_LE (target_pc);

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  gum_metal_array_remove_all (&self->label_refs);

  return TRUE;

error:
  {
    gum_metal_array_remove_all (&self->label_refs);

    return FALSE;
  }
}

GumX86Reg
gum_x86_writer_get_cpu_register_for_nth_argument (GumX86Writer * self,
                                                  guint n)
{
  if (self->target_cpu == GUM_CPU_AMD64)
  {
    if (self->target_abi == GUM_ABI_UNIX)
    {
      static const GumX86Reg amd64_unix_reg_by_index[] = {
        GUM_X86_RDI,
        GUM_X86_RSI,
        GUM_X86_RDX,
        GUM_X86_RCX,
        GUM_X86_R8,
        GUM_X86_R9
      };

      if (n < G_N_ELEMENTS (amd64_unix_reg_by_index))
        return amd64_unix_reg_by_index[n];
    }
    else if (self->target_abi == GUM_ABI_WINDOWS)
    {
      static const GumX86Reg amd64_windows_reg_by_index[] = {
        GUM_X86_RCX,
        GUM_X86_RDX,
        GUM_X86_R8,
        GUM_X86_R9
      };

      if (n < G_N_ELEMENTS (amd64_windows_reg_by_index))
        return amd64_windows_reg_by_index[n];
    }
  }
  else if (self->target_cpu == GUM_CPU_IA32)
  {
    static const GumX86Reg fastcall_reg_by_index[] = {
      GUM_X86_ECX,
      GUM_X86_EDX,
    };

    if (n < G_N_ELEMENTS (fastcall_reg_by_index))
      return fastcall_reg_by_index[n];
  }

  return GUM_X86_NONE;
}

gboolean
gum_x86_writer_put_label (GumX86Writer * self,
                          gconstpointer id)
{
  if (!gum_x86_writer_has_label_defs (self))
    self->label_defs = gum_metal_hash_table_new (NULL, NULL);

  if (gum_metal_hash_table_lookup (self->label_defs, id) != NULL)
    return FALSE;

  gum_metal_hash_table_insert (self->label_defs, (gpointer) id, self->code);

  return TRUE;
}

static void
gum_x86_writer_add_label_reference_here (GumX86Writer * self,
                                         gconstpointer id,
                                         GumX86LabelRefSize size)
{
  GumX86LabelRef * r;

  if (!gum_x86_writer_has_label_refs (self))
    gum_metal_array_init (&self->label_refs, sizeof (GumX86LabelRef));

  r = gum_metal_array_append (&self->label_refs);
  r->id = id;
  r->address = self->code;
  r->size = size;
}

gboolean
gum_x86_writer_can_branch_directly_between (GumAddress from,
                                            GumAddress to)
{
  gint64 distance;
  gboolean distance_fits_in_i32;

  distance = (gssize) to - (gssize) (from + 5);

  distance_fits_in_i32 = (distance >= G_MININT32 && distance <= G_MAXINT32);

  return distance_fits_in_i32;
}

gboolean
gum_x86_writer_put_call_address_with_arguments (GumX86Writer * self,
                                                GumCallingConvention conv,
                                                GumAddress func,
                                                guint n_args,
                                                ...)
{
  va_list args;

  va_start (args, n_args);
  gum_x86_writer_put_argument_list_setup_va (self, conv, n_args, args);
  va_end (args);

  if (!gum_x86_writer_put_call_address (self, func))
    return FALSE;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_address_with_arguments_array (GumX86Writer * self,
                                                      GumCallingConvention conv,
                                                      GumAddress func,
                                                      guint n_args,
                                                      const GumArgument * args)
{
  gum_x86_writer_put_argument_list_setup (self, conv, n_args, args);

  if (!gum_x86_writer_put_call_address (self, func))
    return FALSE;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_address_with_aligned_arguments (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumAddress func,
    guint n_args,
    ...)
{
  va_list args;

  va_start (args, n_args);
  gum_x86_writer_put_aligned_argument_list_setup_va (self, conv, n_args, args);
  va_end (args);

  if (!gum_x86_writer_put_call_address (self, func))
    return FALSE;

  gum_x86_writer_put_aligned_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_address_with_aligned_arguments_array (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumAddress func,
    guint n_args,
    const GumArgument * args)
{
  gum_x86_writer_put_aligned_argument_list_setup (self, conv, n_args, args);

  if (!gum_x86_writer_put_call_address (self, func))
    return FALSE;

  gum_x86_writer_put_aligned_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_with_arguments (GumX86Writer * self,
                                            GumCallingConvention conv,
                                            GumX86Reg reg,
                                            guint n_args,
                                            ...)
{
  va_list args;

  va_start (args, n_args);
  gum_x86_writer_put_argument_list_setup_va (self, conv, n_args, args);
  va_end (args);

  if (!gum_x86_writer_put_call_reg (self, reg))
    return FALSE;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_with_arguments_array (GumX86Writer * self,
                                                  GumCallingConvention conv,
                                                  GumX86Reg reg,
                                                  guint n_args,
                                                  const GumArgument * args)
{
  gum_x86_writer_put_argument_list_setup (self, conv, n_args, args);

  if (!gum_x86_writer_put_call_reg (self, reg))
    return FALSE;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_with_aligned_arguments (GumX86Writer * self,
                                                    GumCallingConvention conv,
                                                    GumX86Reg reg,
                                                    guint n_args,
                                                    ...)
{
  va_list args;

  va_start (args, n_args);
  gum_x86_writer_put_aligned_argument_list_setup_va (self, conv, n_args, args);
  va_end (args);

  if (!gum_x86_writer_put_call_reg (self, reg))
    return FALSE;

  gum_x86_writer_put_aligned_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_with_aligned_arguments_array (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumX86Reg reg,
    guint n_args,
    const GumArgument * args)
{
  gum_x86_writer_put_aligned_argument_list_setup (self, conv, n_args, args);

  if (!gum_x86_writer_put_call_reg (self, reg))
    return FALSE;

  gum_x86_writer_put_aligned_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

static void
gum_x86_writer_put_argument_list_setup (GumX86Writer * self,
                                        GumCallingConvention conv,
                                        guint n_args,
                                        const GumArgument * args)
{
  gint arg_index;

  if (self->target_cpu == GUM_CPU_IA32)
  {
    for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
    {
      const GumArgument * arg = &args[arg_index];

      if (arg->type == GUM_ARG_ADDRESS)
      {
        gum_x86_writer_put_push_u32 (self, arg->value.address);
      }
      else
      {
        gum_x86_writer_put_push_reg (self, arg->value.reg);
      }
    }
  }
  else
  {
    static const GumX86Reg reg_for_arg_unix_64[6] = {
      GUM_X86_RDI,
      GUM_X86_RSI,
      GUM_X86_RDX,
      GUM_X86_RCX,
      GUM_X86_R8,
      GUM_X86_R9
    };
    static const GumX86Reg reg_for_arg_unix_32[6] = {
      GUM_X86_EDI,
      GUM_X86_ESI,
      GUM_X86_EDX,
      GUM_X86_ECX,
      GUM_X86_R8D,
      GUM_X86_R9D
    };
    static const GumX86Reg reg_for_arg_windows_64[4] = {
      GUM_X86_RCX,
      GUM_X86_RDX,
      GUM_X86_R8,
      GUM_X86_R9
    };
    static const GumX86Reg reg_for_arg_windows_32[4] = {
      GUM_X86_ECX,
      GUM_X86_EDX,
      GUM_X86_R8D,
      GUM_X86_R9D
    };
    const GumX86Reg * reg_for_arg_64, * reg_for_arg_32;
    gint reg_for_arg_count;

    if (self->target_abi == GUM_ABI_UNIX)
    {
      reg_for_arg_64 = reg_for_arg_unix_64;
      reg_for_arg_32 = reg_for_arg_unix_32;
      reg_for_arg_count = G_N_ELEMENTS (reg_for_arg_unix_64);
    }
    else
    {
      reg_for_arg_64 = reg_for_arg_windows_64;
      reg_for_arg_32 = reg_for_arg_windows_32;
      reg_for_arg_count = G_N_ELEMENTS (reg_for_arg_windows_64);
    }

    for (arg_index = (gint) n_args - 1; arg_index >= 0; arg_index--)
    {
      const GumArgument * arg = &args[arg_index];

      if (arg_index < reg_for_arg_count)
      {
        if (arg->type == GUM_ARG_ADDRESS)
        {
          gum_x86_writer_put_mov_reg_u64 (self, reg_for_arg_64[arg_index],
              arg->value.address);
        }
        else if (gum_meta_reg_from_cpu_reg (arg->value.reg) !=
            gum_meta_reg_from_cpu_reg (reg_for_arg_64[arg_index]))
        {
          if (arg->value.reg >= GUM_X86_EAX && arg->value.reg <= GUM_X86_EIP)
          {
            gum_x86_writer_put_mov_reg_reg (self, reg_for_arg_32[arg_index],
                arg->value.reg);
          }
          else
          {
            gum_x86_writer_put_mov_reg_reg (self, reg_for_arg_64[arg_index],
                arg->value.reg);
          }
        }
      }
      else
      {
        if (arg->type == GUM_ARG_ADDRESS)
        {
          gum_x86_writer_put_push_reg (self, GUM_X86_XAX);
          gum_x86_writer_put_mov_reg_address (self, GUM_X86_RAX,
              arg->value.address);
          gum_x86_writer_put_xchg_reg_reg_ptr (self, GUM_X86_RAX, GUM_X86_RSP);
        }
        else
        {
          gum_x86_writer_put_push_reg (self, arg->value.reg);
        }
      }
    }

    if (self->target_abi == GUM_ABI_WINDOWS)
      gum_x86_writer_put_sub_reg_imm (self, GUM_X86_RSP, 4 * 8);
  }
}

static void
gum_x86_writer_put_argument_list_setup_va (GumX86Writer * self,
                                           GumCallingConvention conv,
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
      arg->value.reg = va_arg (args, GumX86Reg);
    else
      g_assert_not_reached ();
  }

  gum_x86_writer_put_argument_list_setup (self, conv, n_args, arg_values);
}

static void
gum_x86_writer_put_argument_list_teardown (GumX86Writer * self,
                                           GumCallingConvention conv,
                                           guint n_args)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (conv == GUM_CALL_CAPI && n_args != 0)
    {
      gum_x86_writer_put_add_reg_imm (self, GUM_X86_ESP,
          n_args * sizeof (guint32));
    }
  }
  else
  {
    if (self->target_abi == GUM_ABI_WINDOWS)
      gum_x86_writer_put_add_reg_imm (self, GUM_X86_RSP, MAX (n_args, 4) * 8);
    else if (n_args > 6)
      gum_x86_writer_put_add_reg_imm (self, GUM_X86_RSP, (n_args - 6) * 8);
  }
}

static void
gum_x86_writer_put_aligned_argument_list_setup (GumX86Writer * self,
                                                GumCallingConvention conv,
                                                guint n_args,
                                                const GumArgument * args)
{
  guint align_correction;

  align_correction =
      gum_x86_writer_get_needed_alignment_correction (self, n_args);
  if (align_correction != 0)
  {
    gum_x86_writer_put_sub_reg_imm (self, GUM_X86_XSP, align_correction);
  }

  gum_x86_writer_put_argument_list_setup (self, conv, n_args, args);
}

static void
gum_x86_writer_put_aligned_argument_list_setup_va (GumX86Writer * self,
                                                   GumCallingConvention conv,
                                                   guint n_args,
                                                   va_list args)
{
  guint align_correction;

  align_correction =
      gum_x86_writer_get_needed_alignment_correction (self, n_args);
  if (align_correction != 0)
  {
    gum_x86_writer_put_sub_reg_imm (self, GUM_X86_XSP, align_correction);
  }

  gum_x86_writer_put_argument_list_setup_va (self, conv, n_args, args);
}

static void
gum_x86_writer_put_aligned_argument_list_teardown (GumX86Writer * self,
                                                   GumCallingConvention conv,
                                                   guint n_args)
{
  guint align_correction;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  align_correction =
      gum_x86_writer_get_needed_alignment_correction (self, n_args);
  if (align_correction != 0)
  {
    gum_x86_writer_put_add_reg_imm (self, GUM_X86_XSP, align_correction);
  }
}

static guint
gum_x86_writer_get_needed_alignment_correction (GumX86Writer * self,
                                                guint n_args)
{
  guint n_stack_args, pointer_size, stack_args_size, remainder;

  if (self->target_cpu == GUM_CPU_IA32)
  {
    n_stack_args = n_args;

    pointer_size = 4;
  }
  else
  {
    if (self->target_abi == GUM_ABI_UNIX)
      n_stack_args = (n_args > 6) ? n_args - 6 : 0;
    else
      n_stack_args = (n_args > 4) ? n_args - 4 : 0;

    pointer_size = 8;
  }

  stack_args_size = n_stack_args * pointer_size;

  remainder = stack_args_size % 16;

  return (remainder != 0) ? 16 - remainder : 0;
}

gboolean
gum_x86_writer_put_call_reg_offset_ptr_with_arguments (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumX86Reg reg,
    gssize offset,
    guint n_args,
    ...)
{
  va_list args;

  va_start (args, n_args);
  gum_x86_writer_put_argument_list_setup_va (self, conv, n_args, args);
  va_end (args);

  if (!gum_x86_writer_put_call_reg_offset_ptr (self, reg, offset))
    return FALSE;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_offset_ptr_with_arguments_array (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumX86Reg reg,
    gssize offset,
    guint n_args,
    const GumArgument * args)
{
  gum_x86_writer_put_argument_list_setup (self, conv, n_args, args);

  if (!gum_x86_writer_put_call_reg_offset_ptr (self, reg, offset))
    return FALSE;

  gum_x86_writer_put_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumX86Reg reg,
    gssize offset,
    guint n_args,
    ...)
{
  va_list args;

  va_start (args, n_args);
  gum_x86_writer_put_aligned_argument_list_setup_va (self, conv, n_args, args);
  va_end (args);

  if (!gum_x86_writer_put_call_reg_offset_ptr (self, reg, offset))
    return FALSE;

  gum_x86_writer_put_aligned_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments_array (
    GumX86Writer * self,
    GumCallingConvention conv,
    GumX86Reg reg,
    gssize offset,
    guint n_args,
    const GumArgument * args)
{
  gum_x86_writer_put_aligned_argument_list_setup (self, conv, n_args, args);

  if (!gum_x86_writer_put_call_reg_offset_ptr (self, reg, offset))
    return FALSE;

  gum_x86_writer_put_aligned_argument_list_teardown (self, conv, n_args);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_address (GumX86Writer * self,
                                 GumAddress address)
{
  gint64 distance;
  gboolean distance_fits_in_i32;

  distance = (gssize) address - (gssize) (self->pc + 5);
  distance_fits_in_i32 = (distance >= G_MININT32 && distance <= G_MAXINT32);

  if (distance_fits_in_i32)
  {
    self->code[0] = 0xe8;
    *((gint32 *) (self->code + 1)) = GINT32_TO_LE (distance);
    gum_x86_writer_commit (self, 5);
  }
  else
  {
    gconstpointer call_target_storage = self->code + 1;
    gconstpointer carry_on = self->code + 2;

    if (self->target_cpu != GUM_CPU_AMD64)
      return FALSE;

    gum_x86_writer_put_call_indirect_label (self, call_target_storage);
    gum_x86_writer_put_jmp_short_label (self, carry_on);

    gum_x86_writer_put_label (self, call_target_storage);
    *((guint64 *) (self->code)) = GUINT64_TO_LE (address);
    gum_x86_writer_commit (self, 8);

    gum_x86_writer_put_label (self, carry_on);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg (GumX86Writer * self,
                             GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32 || ri.index_is_extended)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (ri.index_is_extended)
    gum_x86_writer_put_u8 (self, 0x41);
  self->code[0] = 0xff;
  self->code[1] = 0xd0 | ri.index;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_reg_offset_ptr (GumX86Writer * self,
                                        GumX86Reg reg,
                                        gssize offset)
{
  GumX86RegInfo ri;
  gboolean offset_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (offset);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32 || ri.index_is_extended)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  self->code[0] = 0xff;
  self->code[1] = (offset_fits_in_i8 ? 0x50 : 0x90) | ri.index;
  gum_x86_writer_commit (self, 2);

  if (ri.index == 4)
    gum_x86_writer_put_u8 (self, 0x24);

  if (offset_fits_in_i8)
  {
    gum_x86_writer_put_s8 (self, offset);
  }
  else
  {
    *((gint32 *) self->code) = GINT32_TO_LE (offset);
    gum_x86_writer_commit (self, 4);
  }

  return TRUE;
}

gboolean
gum_x86_writer_put_call_indirect (GumX86Writer * self,
                                  GumAddress address)
{
  if (self->target_cpu == GUM_CPU_AMD64)
  {
    gint64 distance = (gint64) address - (gint64) (self->pc + 6);

    if (!GUM_IS_WITHIN_INT32_RANGE (distance))
      return FALSE;

    self->code[0] = 0xff;
    self->code[1] = 0x15;
    *((guint32 *) (self->code + 2)) = GINT32_TO_LE ((gint32) distance);
  }
  else
  {
    self->code[0] = 0xff;
    self->code[1] = 0x15;
    *((guint32 *) (self->code + 2)) = GUINT32_TO_LE (address);
  }

  gum_x86_writer_commit (self, 6);

  return TRUE;
}

gboolean
gum_x86_writer_put_call_indirect_label (GumX86Writer * self,
                                        gconstpointer label_id)
{
  if (!gum_x86_writer_put_call_indirect (self, self->pc))
    return FALSE;

  gum_x86_writer_add_label_reference_here (self, label_id,
      (self->target_cpu == GUM_CPU_AMD64)
          ? GUM_LREF_NEAR
          : GUM_LREF_ABS);
  return TRUE;
}

void
gum_x86_writer_put_call_near_label (GumX86Writer * self,
                                    gconstpointer label_id)
{
  gum_x86_writer_put_call_address (self, self->pc);
  gum_x86_writer_add_label_reference_here (self, label_id, GUM_LREF_NEAR);
}

void
gum_x86_writer_put_leave (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xc9);
}

void
gum_x86_writer_put_ret (GumX86Writer * self)
{
  gum_x86_writer_put_u8 (self, 0xc3);
}

void
gum_x86_writer_put_ret_imm (GumX86Writer * self,
                            guint16 imm_value)
{
  self->code[0] = 0xc2;
  *((guint16 *) (self->code + 1)) = GUINT16_TO_LE (imm_value);
  gum_x86_writer_commit (self, 3);
}

gboolean
gum_x86_writer_put_jmp_address (GumX86Writer * self,
                                GumAddress address)
{
  gint64 distance;

  distance = (gssize) address - (gssize) (self->pc + 2);

  if (GUM_IS_WITHIN_INT8_RANGE (distance))
  {
    self->code[0] = 0xeb;
    *((gint8 *) (self->code + 1)) = distance;
    gum_x86_writer_commit (self, 2);
  }
  else
  {
    distance = (gssize) address - (gssize) (self->pc + 5);

    if (GUM_IS_WITHIN_INT32_RANGE (distance))
    {
      self->code[0] = 0xe9;
      *((gint32 *) (self->code + 1)) = GINT32_TO_LE ((gint32) distance);
      gum_x86_writer_commit (self, 5);
    }
    else
    {
      if (self->target_cpu != GUM_CPU_AMD64)
        return FALSE;

      self->code[0] = 0xff;
      self->code[1] = 0x25;
      *((gint32 *) (self->code + 2)) = GINT32_TO_LE (2); /* RIP + 2 */
      self->code[6] = 0x0f;
      self->code[7] = 0x0b;
      *((guint64 *) (self->code + 8)) = GUINT64_TO_LE (address);
      gum_x86_writer_commit (self, 16);
    }
  }

  return TRUE;
}

static gboolean
gum_x86_writer_put_short_jmp (GumX86Writer * self,
                              gconstpointer target)
{
  gint64 distance;

  distance = (gssize) target - (gssize) (self->pc + 2);
  if (!GUM_IS_WITHIN_INT8_RANGE (distance))
    return FALSE;

  self->code[0] = 0xeb;
  *((gint8 *) (self->code + 1)) = distance;
  gum_x86_writer_commit (self, 2);

  return TRUE;
}

static gboolean
gum_x86_writer_put_near_jmp (GumX86Writer * self,
                             gconstpointer target)
{
  gint64 distance;

  distance = (gssize) target - (gssize) (self->pc + 5);

  if (GUM_IS_WITHIN_INT32_RANGE (distance))
  {
    self->code[0] = 0xe9;
    *((gint32 *) (self->code + 1)) = GINT32_TO_LE (distance);
    gum_x86_writer_commit (self, 5);
  }
  else
  {
    if (self->target_cpu != GUM_CPU_AMD64)
      return FALSE;

    self->code[0] = 0xff;                               /* JMP [RIP + 2] */
    self->code[1] = 0x25;
    *((gint32 *) (self->code + 2)) = GINT32_TO_LE (2);  /* RIP + 2 */

    self->code[6] = 0x0f;                               /* UD2 */
    self->code[7] = 0x0b;

    *((guint64 *) (self->code + 8)) = GUINT64_TO_LE (GPOINTER_TO_SIZE (target));
    gum_x86_writer_commit (self, 16);
  }

  return TRUE;
}

void
gum_x86_writer_put_jmp_short_label (GumX86Writer * self,
                                    gconstpointer label_id)
{
  gum_x86_writer_put_short_jmp (self, GSIZE_TO_POINTER (self->pc));
  gum_x86_writer_add_label_reference_here (self, label_id, GUM_LREF_SHORT);
}

void
gum_x86_writer_put_jmp_near_label (GumX86Writer * self,
                                   gconstpointer label_id)
{
  gum_x86_writer_put_near_jmp (self, GSIZE_TO_POINTER (self->pc));
  gum_x86_writer_add_label_reference_here (self, label_id, GUM_LREF_NEAR);
}

gboolean
gum_x86_writer_put_jmp_reg (GumX86Writer * self,
                            GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32 || ri.index_is_extended)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  self->code[0] = 0xff;
  self->code[1] = 0xe0 | ri.index;
  gum_x86_writer_commit (self, 2);

  gum_x86_writer_put_ud2 (self);

  return TRUE;
}

gboolean
gum_x86_writer_put_jmp_reg_ptr (GumX86Writer * self,
                                GumX86Reg reg)
{
  GumX86RegInfo ri;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32 || ri.index_is_extended)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  self->code[0] = 0xff;
  self->code[1] = 0x20 | ri.index;
  gum_x86_writer_commit (self, 2);

  if (ri.meta == GUM_X86_META_XSP)
    gum_x86_writer_put_u8 (self, 0x24);

  gum_x86_writer_put_ud2 (self);

  return TRUE;
}

gboolean
gum_x86_writer_put_jmp_reg_offset_ptr (GumX86Writer * self,
                                       GumX86Reg reg,
                                       gssize offset)
{
  GumX86RegInfo ri;
  gboolean offset_fits_in_i8;

  gum_x86_writer_describe_cpu_reg (self, reg, &ri);

  offset_fits_in_i8 = GUM_IS_WITHIN_INT8_RANGE (offset);

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (ri.width != 32 || ri.index_is_extended)
      return FALSE;
  }
  else
  {
    if (ri.width != 64)
      return FALSE;
  }

  if (!gum_x86_writer_put_prefix_for_registers (self, &ri, 64, &ri, NULL))
    return FALSE;

  self->code[0] = 0xff;
  self->code[1] = (offset_fits_in_i8 ? 0x60 : 0xa0) | ri.index;
  gum_x86_writer_commit (self, 2);

  if (ri.index == 4)
    gum_x86_writer_put_u8 (self, 0x24);

  if (offset_fits_in_i8)
  {
    gum_x86_writer_put_s8 (self, offset);
  }
  else
  {
    *((gint32 *) self->code) = GINT32_TO_LE (offset);
    gum_x86_writer_commit (self, 4);
  }

  gum_x86_writer_put_ud2 (self);

  return TRUE;
}

gboolean
gum_x86_writer_put_jmp_near_ptr (GumX86Writer * self,
                                 GumAddress address)
{
  self->code[0] = 0xff;
  self->code[1] = 0x25;

  if (self->target_cpu == GUM_CPU_IA32)
  {
    if (address > G_MAXUINT32)
      return FALSE;
    *((guint32 *) (self->code + 2)) = GUINT32_TO_LE ((guint32) address);
  }
  else
  {
    gint64 distance = (gint64) address - (gint64) (self->pc + 6);
    if (distance < G_MININT32 || distance > G_MAXINT32)
      return FALSE;
    *((gint32 *) (self->code + 2)) = GINT32_TO_LE ((gint32) distance);
  }

  gum_x86_writer_commit (self, 6);

  gum_x86_writer_put_ud
```