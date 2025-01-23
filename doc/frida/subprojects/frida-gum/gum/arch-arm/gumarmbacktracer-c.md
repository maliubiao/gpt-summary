Response:
Let's break down the thought process for analyzing this C code snippet and generating the comprehensive explanation.

**1. Initial Reading and Identification of Core Functionality:**

* The first step is to read through the code and identify the main purpose. The filename "gumarmbacktracer.c" and the presence of functions like `gum_arm_backtracer_generate` strongly suggest it's about tracing the call stack on ARM architectures.
* Keywords like "backtracer", "cpu_context", "return_addresses", and "stack" confirm this.

**2. Deconstructing the Code Structure:**

* **Data Structures:**  Identify the key data structures: `GumArmBacktracer`, `GumMemoryMap`, `GumCpuContext`, `GumReturnAddressArray`, and `GumInvocationStack`. Understand their relationships. For example, `GumArmBacktracer` *has-a* `GumMemoryMap`, and the `generate` function takes `GumCpuContext` and outputs to `GumReturnAddressArray`.
* **Functions:** Analyze each function's purpose:
    * `gum_arm_backtracer_iface_init`, `gum_arm_backtracer_dispose`, `gum_arm_backtracer_class_init`, `gum_arm_backtracer_init`: These are standard GObject lifecycle functions.
    * `gum_arm_backtracer_new`:  Object creation.
    * `gum_arm_backtracer_generate`: The core logic for backtracing.
* **Preprocessor Directives:** Note `#ifndef GUM_DIET`. This indicates conditional compilation, suggesting this code might be omitted in "diet" builds.
* **GObject Framework:** Recognize the use of GObject macros (`G_DEFINE_TYPE_EXTENDED`, `G_IMPLEMENT_INTERFACE`). This signifies the code is part of the GLib/GObject ecosystem.

**3. Analyzing the Backtracing Logic (`gum_arm_backtracer_generate`):**

* **Input:** Understand the inputs: `backtracer` (the object itself), `cpu_context` (register state), `return_addresses` (the output array), and `limit` (maximum depth).
* **Stack Handling:** Notice the attempt to get the current stack pointer (`sp`) and link register (`lr`) from the `cpu_context` or via inline assembly if `cpu_context` is null (meaning tracing from the current execution point). The code also attempts to determine stack boundaries.
* **Return Address Identification:** The core loop iterates through potential return addresses on the stack. The logic to identify valid return addresses is complex and involves:
    * Checking if a value looks like an address within executable memory (`gum_memory_map_contains(self->code, &vr)`).
    * Handling potential address translation via `gum_invocation_stack_translate`.
    * Identifying specific ARM instruction patterns (BL, BLX) that indicate function calls. This is the core of the architecture-specific part.
* **Skips Pending:**  The `skips_pending` variable suggests a mechanism to skip the initial return address when tracing from the current execution point.
* **Output:** The identified return addresses are stored in the `return_addresses` array.

**4. Connecting to Reverse Engineering Concepts:**

* **Call Stack Visualization:**  Directly relates to how debuggers show the call stack.
* **Identifying Function Calls:** The ARM instruction pattern matching is a fundamental technique used in static and dynamic analysis to understand code flow.
* **Stack Analysis:**  Understanding stack layout and frame pointers (though not explicitly used here in the traditional frame pointer sense) is crucial for manual reverse engineering.

**5. Identifying Links to Low-Level/Kernel Concepts:**

* **ARM Architecture:** The code is explicitly for ARM, referencing registers (`sp`, `lr`) and instruction encodings.
* **Memory Management:**  `GumMemoryMap` suggests interaction with memory regions and permissions (executable, writable). This relates to OS-level memory management.
* **Threads:** `gum_thread_try_get_ranges` hints at awareness of threads and their stack regions.
* **Dynamic Instrumentation:** The context of Frida is crucial. This is *dynamic* analysis, meaning the code is being analyzed during runtime.

**6. Considering Logic and Examples:**

* **Assumptions:**  Assume the user has set up Frida and is injecting code into a running process.
* **Input/Output:** Think about a simple function call scenario. The input would be the CPU context at the time of the call, and the output would be the address of the calling function.

**7. Thinking About User Errors:**

* **Incorrect Context:**  Providing an invalid `GumCpuContext` could lead to incorrect backtraces.
* **Limitations:**  The backtracer might fail if stack frames are corrupted or if non-standard calling conventions are used.

**8. Tracing User Actions:**

* Start with the user attaching Frida to a process.
* The user then sets up an interception point (using `Interceptor.attach()` in Frida's JavaScript API).
* When the intercepted function is called, Frida can capture the CPU context and use the `GumArmBacktracer` to generate the call stack.

**9. Structuring the Explanation:**

* Use clear headings to organize the information.
* Provide specific code snippets to illustrate points.
* Explain technical terms.
* Offer concrete examples.
* Emphasize the "why" behind the code's logic.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the GObject specifics. Realizing the core is the backtracing algorithm, I'd shift focus there.
* I'd revisit the ARM instruction patterns to ensure I correctly understood their purpose.
* I'd consider edge cases and limitations of the backtracer.
* I'd ensure the examples are relevant and easy to understand.

By following this structured approach, combining code analysis with conceptual understanding and considering the broader context of Frida and reverse engineering, it's possible to generate a comprehensive and accurate explanation like the example provided in the initial prompt.
这个C源代码文件 `gumarmbacktracer.c` 是 Frida 动态 instrumentation 工具中用于 ARM 架构的栈回溯（backtracing）功能的实现。它的主要功能是**在程序运行时，根据当前的 CPU 状态，生成函数调用栈的快照**，即找出当前执行点的函数是由哪些函数一级一级调用上来的。

下面我们详细列举其功能，并结合逆向、二进制底层、Linux/Android 内核及框架知识、逻辑推理、用户错误以及调试线索进行说明：

**功能列表:**

1. **栈回溯核心功能:**
   - **生成调用栈:**  `gum_arm_backtracer_generate` 函数是核心，它接收当前的 CPU 上下文 (`GumCpuContext`) 和一个用于存储返回地址的数组 (`GumReturnAddressArray`)，然后尝试填充这个数组，记录调用栈上的返回地址。
   - **支持从 CPU 上下文回溯:** 如果提供了 `GumCpuContext` (例如在 hook 函数内部)，它可以从寄存器（特别是栈指针 `sp` 和链接寄存器 `lr`）开始回溯。
   - **支持从当前位置回溯:** 如果没有提供 `GumCpuContext`，它会尝试从当前程序的栈指针开始回溯。
   - **限制回溯深度:** `limit` 参数可以限制回溯的层数，防止无限回溯。

2. **内存管理感知:**
   - **代码段和可写段:** 使用 `GumMemoryMap` 来维护代码段 (`code`) 和可写段 (`writable`) 的信息。这有助于判断栈上的值是否可能是有效的返回地址。只有指向代码段的地址才会被认为是潜在的返回地址。
   - **栈内存范围判断:** 尝试获取当前线程的栈内存范围 (`gum_thread_try_get_ranges`)，并限制回溯的范围在这个栈内，避免访问无效内存。

3. **指令模式识别 (ARM 特性):**
   - **识别 BL/BLX 指令:**  代码会检查栈上的值的前后指令，判断是否是 ARM 的 `BL` (Branch with Link) 或 `BLX` (Branch with Link and Exchange) 指令。这些指令是函数调用的关键，它们的下一条指令地址通常会被保存到链接寄存器 (`lr`)，然后压入栈中作为返回地址。
   - **Thumb 模式支持:**  代码也考虑了 Thumb 指令集的情况，Thumb 指令的长度可能是 16 位或 32 位，并且函数地址的最低位通常会置 1。

4. **地址转换:**
   - **`gum_invocation_stack_translate`:** 这个函数用于处理 Frida 的插桩代码可能导致的地址偏移。当 Frida 在函数入口或出口插入代码时，实际的返回地址可能会被修改。`gum_invocation_stack_translate` 可以将插桩后的地址转换回原始的被调用函数的地址。

**与逆向方法的关联及举例说明:**

* **动态分析:**  `gumarmbacktracer.c` 是 Frida 动态插桩工具的一部分，天然与动态逆向分析方法紧密相关。通过在程序运行时获取调用栈，逆向工程师可以：
    * **理解程序执行流程:** 跟踪函数调用关系，了解代码是如何一步步执行到当前位置的。
    * **定位关键函数:**  在程序崩溃或发生特定行为时，回溯调用栈可以快速定位到导致问题的函数。
    * **分析函数参数:**  结合栈回溯，可以进一步检查栈上保存的函数参数。
    * **破解反调试机制:**  一些反调试技术会检查调用栈，Frida 可以通过回溯来分析这些检查。

* **举例说明:**
    假设我们想知道 Android 系统中 `SurfaceFlinger` 服务的 `handleMessage` 函数是被哪些函数调用的。我们可以使用 Frida 脚本在 `handleMessage` 函数入口处 hook，并使用 `DebugSymbol.fromAddress(addr).name` 将栈上的地址转换为函数名：

    ```javascript
    // Frida 脚本
    Interceptor.attach(Module.findExportByName("libsurfaceflinger.so", "_ZN7android14SurfaceFlinger13handleMessageERKNS_10MessageBaseE"), {
        onEnter: function(args) {
            console.log("handleMessage called!");
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n");
            console.log(backtrace);
        }
    });
    ```

    当 `SurfaceFlinger` 处理消息时，Frida 会打印 `handleMessage called!`，然后会打印出调用 `handleMessage` 的函数调用栈，例如：

    ```
    handleMessage called!
    _ZN7android14SurfaceFlinger13handleMessageERKNS_10MessageBaseE
    _ZN7android14Looper9pollInnerEi
    _ZN7android14Looper10pollOnceEiPiS1_PPv
    _ZN7android8ALooper10pollOnceEiPiS1_PPv
    android:: দাও(void*)
    ...
    ```

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明:**

* **ARM 架构:** 代码中直接操作了 ARM 架构的寄存器 (`sp`, `lr`)，并根据 ARM 指令的编码格式 (`BL`, `BLX`) 来判断返回地址。
* **调用约定:**  栈回溯依赖于 ARM 的标准调用约定，即函数调用时链接寄存器保存返回地址，并压入栈中。
* **栈帧结构:**  虽然代码没有显式地解析栈帧，但其原理是基于栈帧的结构，返回地址通常位于栈帧的特定位置。
* **内存保护 (NX 位):**  `GumMemoryMap` 的使用与操作系统的内存保护机制相关。只有标记为可执行的内存区域中的地址才被认为是有效的返回地址。
* **Linux 线程模型:** `gum_thread_try_get_ranges` 函数表明代码知道 Linux 的线程模型，每个线程有独立的栈空间。
* **Android 框架:**  在 Frida 的上下文中，回溯经常用于分析 Android 系统服务 (如 `SurfaceFlinger`) 或应用程序的内部工作原理。

* **举例说明:**
    当代码检查 `BL` 指令时 (`(insn & 0xf000000) == 0xb000000`)，它是在检查指令的特定位模式。在 ARM 32 位指令集中，`BL` 指令的最高 4 位为 `1011` (二进制)，对应的十六进制就是 `0xb`。通过位与操作 `& 0xf000000` 并与 `0xb000000` 比较，可以判断是否为 `BL` 指令。这涉及到对 ARM 指令编码的深入理解。

**逻辑推理、假设输入与输出:**

* **假设输入:**
    - `cpu_context`:  指向一个 `GumCpuContext` 结构的指针，该结构包含了当前 CPU 的寄存器状态，假设 `cpu_context->sp` (栈指针) 指向 `0xbef00000`，`cpu_context->lr` (链接寄存器) 指向 `0xabcdef10`。
    - `return_addresses`: 一个 `GumReturnAddressArray` 结构，初始时 `len` 为 0，`items` 数组未填充。
    - `limit`:  回溯深度限制，假设为 10。
    - 假设在栈地址 `0xbef00004` 处存储着值 `0x12345678`，并且地址 `0x12345674` 位于代码段，并且该地址处的指令是 `BL` 指令，调用了地址 `0x12345678` 的函数。

* **逻辑推理:**
    1. 代码首先检查 `cpu_context` 是否为空，由于我们提供了，所以进入 `if` 分支。
    2. `start_address` 被设置为 `cpu_context->sp`，即 `0xbef00000`。
    3. `return_addresses->items[0]` 被设置为 `cpu_context->lr`，经过可能的 `gum_invocation_stack_translate` 转换后（假设没有转换），为 `0xabcdef10`。
    4. `start_index` 被设置为 1，`skips_pending` 为 0。
    5. 代码开始从 `start_address` 向上遍历栈内存。
    6. 当遍历到地址 `0xbef00004` 时，读取到值 `0x12345678`。
    7. 代码检查地址 `0x12345678 - 4 = 0x12345674` 是否在代码段，并且该地址处的指令是否是 `BL` 指令。根据假设，条件成立。
    8. 由于 `skips_pending` 为 0，将 `0x12345678` 存储到 `return_addresses->items[1]`。
    9. 继续向上遍历栈，查找更多的返回地址，直到达到 `limit` 或栈顶。

* **预期输出:**
    `return_addresses->len` 将大于 0，并且 `return_addresses->items` 数组的前几个元素将包含回溯到的返回地址，例如：
    ```
    return_addresses->len = 2;
    return_addresses->items[0] = 0xabcdef10;
    return_addresses->items[1] = 0x12345678;
    // ... 可能还有更多
    ```

**涉及用户或者编程常见的使用错误及举例说明:**

* **错误的 CPU 上下文:**  如果用户提供的 `GumCpuContext` 结构不正确或过时，回溯的结果将不可靠。例如，如果在 hook 函数的 `onEnter` 或 `onLeave` 中不正确地访问或修改了 `this.context`，传递给 `gum_arm_backtracer_generate` 的上下文就可能是错误的。
* **栈被破坏:** 如果程序的栈被意外覆盖或损坏，回溯可能会提前终止或产生错误的返回地址。这在多线程编程中尤其需要注意，例如栈溢出。
* **回溯深度过大:**  如果 `limit` 设置得过大，可能会导致遍历大量的栈内存，影响性能。
* **没有正确初始化 Frida 环境:** 如果 Frida 没有正确注入到目标进程，`gum_interceptor_get_current_stack()` 可能返回错误的值。

* **举例说明:**
    用户在编写 Frida 脚本时，可能会错误地使用 `setTimeout` 或异步操作，导致在回调函数中访问 `this.context` 时，上下文已经不是 hook 时的上下文了。将这个错误的上下文传递给回溯函数，就会得到错误的调用栈。

    ```javascript
    Interceptor.attach(someFunction, {
        onEnter: function(args) {
            var currentContext = this.context;
            setTimeout(function() {
                // 此时 currentContext 可能已经失效
                var backtrace = Thread.backtrace(currentContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n");
                console.log(backtrace);
            }, 100);
        }
    });
    ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida 或一个使用 Frida 的工具:**  用户首先需要启动 Frida 命令行工具（如 `frida`, `frida-ps`, `frida-trace`）或者一个基于 Frida 开发的应用。
2. **用户选择目标进程:**  用户需要指定要进行动态插桩的目标进程。这可以通过进程 ID、进程名称或者 USB 设备上的应用程序包名来完成。
3. **用户编写或加载 Frida 脚本:**  用户编写 JavaScript 代码，使用 Frida 提供的 API 来定义插桩逻辑，例如 hook 函数、替换函数、读取内存等。
4. **用户在脚本中使用 `Thread.backtrace()`:**  在 Frida 脚本中，用户可能会调用 `Thread.backtrace(context, Backtracer.ACCURATE)` 函数来获取当前或指定上下文的调用栈。
5. **`Thread.backtrace()` 内部调用 `GumBacktracer` 接口:**  `Thread.backtrace()` 函数在底层会调用与当前 CPU 架构对应的 `GumBacktracer` 接口的 `generate` 方法，对于 ARM 架构，就是 `gum_arm_backtracer_generate`。
6. **Frida 引擎准备调用参数:** Frida 的引擎会根据调用 `Thread.backtrace()` 时提供的 `context` 参数（如果没有提供，则使用当前线程的上下文）以及其他参数（如回溯深度）准备好调用 `gum_arm_backtracer_generate` 所需的 `GumCpuContext`、`GumReturnAddressArray` 和 `limit`。
7. **调用 `gum_arm_backtracer_generate`:** Frida 引擎最终调用 `gumarmbacktracer.c` 文件中的 `gum_arm_backtracer_generate` 函数，执行栈回溯的逻辑。

**作为调试线索：**

如果用户在使用 Frida 时遇到了栈回溯相关的问题（例如，回溯不完整、返回地址错误、Frida 崩溃等），那么 `gumarmbacktracer.c` 的代码就是重要的调试线索：

* **检查 Frida 版本:**  不同版本的 Frida 在栈回溯的实现上可能有所不同，确认使用的 Frida 版本有助于查找已知问题。
* **查看错误日志:**  Frida 可能会输出与栈回溯相关的错误或警告信息。
* **分析目标进程的架构和状态:**  确认目标进程是 ARM 架构，并且在回溯时其栈没有严重损坏。
* **检查 Frida 脚本逻辑:**  确认传递给 `Thread.backtrace()` 的 `context` 是否正确。
* **阅读 `gumarmbacktracer.c` 源码:**  仔细阅读 `gum_arm_backtracer_generate` 函数的实现，理解其回溯的原理和可能出错的地方，例如内存访问错误、指令模式识别错误等。
* **使用 GDB 或 LLDB 调试 Frida Agent:**  可以尝试使用调试器连接到 Frida Agent 进程，在 `gum_arm_backtracer_generate` 函数中设置断点，单步执行，查看变量的值，帮助定位问题。

总而言之，`gumarmbacktracer.c` 是 Frida 在 ARM 架构上实现动态栈回溯的关键组成部分，它结合了对 ARM 架构、调用约定、内存管理以及动态插桩技术的理解，为逆向工程师提供了强大的运行时代码分析能力。理解其工作原理有助于用户更有效地使用 Frida，并在遇到问题时进行调试。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/arch-arm/gumarmbacktracer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2013-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumarmbacktracer.h"

#include "guminterceptor.h"
#include "gummemorymap.h"

struct _GumArmBacktracer
{
  GObject parent;

  GumMemoryMap * code;
  GumMemoryMap * writable;
};

static void gum_arm_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_arm_backtracer_dispose (GObject * object);
static void gum_arm_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context, GumReturnAddressArray * return_addresses,
    guint limit);

G_DEFINE_TYPE_EXTENDED (GumArmBacktracer,
                        gum_arm_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_arm_backtracer_iface_init))

static void
gum_arm_backtracer_class_init (GumArmBacktracerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_arm_backtracer_dispose;
}

static void
gum_arm_backtracer_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumBacktracerInterface * iface = g_iface;

  iface->generate = gum_arm_backtracer_generate;
}

static void
gum_arm_backtracer_init (GumArmBacktracer * self)
{
  self->code = gum_memory_map_new (GUM_PAGE_EXECUTE);
  self->writable = gum_memory_map_new (GUM_PAGE_WRITE);
}

static void
gum_arm_backtracer_dispose (GObject * object)
{
  GumArmBacktracer * self = GUM_ARM_BACKTRACER (object);

  g_clear_object (&self->code);
  g_clear_object (&self->writable);

  G_OBJECT_CLASS (gum_arm_backtracer_parent_class)->dispose (object);
}

GumBacktracer *
gum_arm_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_ARM_BACKTRACER, NULL);
}

static void
gum_arm_backtracer_generate (GumBacktracer * backtracer,
                             const GumCpuContext * cpu_context,
                             GumReturnAddressArray * return_addresses,
                             guint limit)
{
  GumArmBacktracer * self;
  GumInvocationStack * invocation_stack;
  const gsize * start_address, * end_address;
  guint start_index, skips_pending, depth, n, i;
  GumMemoryRange stack_ranges[2];
  const gsize * p;

  self = GUM_ARM_BACKTRACER (backtracer);
  invocation_stack = gum_interceptor_get_current_stack ();

  if (cpu_context != NULL)
  {
    start_address = GSIZE_TO_POINTER (cpu_context->sp);
    return_addresses->items[0] = gum_invocation_stack_translate (
        invocation_stack, GSIZE_TO_POINTER (cpu_context->lr));
    start_index = 1;
    skips_pending = 0;
  }
  else
  {
    asm ("\tmov %0, sp" : "=r" (start_address));
    start_index = 0;
    skips_pending = 1;
  }

  end_address = start_address + 2048;

  n = gum_thread_try_get_ranges (stack_ranges, G_N_ELEMENTS (stack_ranges));
  for (i = 0; i != n; i++)
  {
    const GumMemoryRange * r = &stack_ranges[i];

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (start_address)))
    {
      end_address = GSIZE_TO_POINTER (r->base_address + r->size);
      break;
    }
  }

  depth = MIN (limit, G_N_ELEMENTS (return_addresses->items));

  for (i = start_index, p = start_address; p < end_address; p++)
  {
    gboolean valid = FALSE;
    gsize value;
    GumMemoryRange vr;

    if ((GPOINTER_TO_SIZE (p) & (4096 - 1)) == 0)
    {
      GumMemoryRange next_range;
      next_range.base_address = GUM_ADDRESS (p);
      next_range.size = 4096;
      if (!gum_memory_map_contains (self->writable, &next_range))
        break;
    }

    value = *p;
    vr.base_address = value - 4;
    vr.size = 4;

    if (value > 4096 + 4 && gum_memory_map_contains (self->code, &vr))
    {
      gsize translated_value;

      translated_value = GPOINTER_TO_SIZE (gum_invocation_stack_translate (
          invocation_stack, GSIZE_TO_POINTER (value)));
      if (translated_value != value)
      {
        value = translated_value;
        valid = TRUE;
      }
      else
      {
        if (value % 4 == 0)
        {
          const guint32 insn = GUINT32_FROM_LE (
              *((guint32 *) GSIZE_TO_POINTER (value - 4)));
          if ((insn & 0xf000000) == 0xb000000)
          {
            /* BL <imm24> */
            valid = TRUE;
          }
          else if ((insn & 0xfe000000) == 0xfa000000)
          {
            /* BLX <imm24> */
            valid = TRUE;
          }
          else if ((insn & 0xff000f0) == 0x1200030)
          {
            /* BLX Rx */
            valid = TRUE;
          }
        }
        else if ((value & 1) != 0)
        {
          const guint16 * insns_before = GSIZE_TO_POINTER (value - 1 - 2 - 2);
          if ((GUINT16_FROM_LE (insns_before[0]) & 0xf800) == 0xf000 &&
              (GUINT16_FROM_LE (insns_before[1]) & 0xe800) == 0xe800)
          {
            /* BL/BLX <imm11> */
            value--;
            valid = TRUE;
          }
          else if ((GUINT16_FROM_LE (insns_before[1]) & 0xff80) == 0x4780)
          {
            /* BLX Rx */
            value--;
            valid = TRUE;
          }
        }
      }
    }

    if (valid)
    {
      if (skips_pending == 0)
      {
        return_addresses->items[i++] = GSIZE_TO_POINTER (value);
        if (i == depth)
          break;
      }
      else
      {
        skips_pending--;
      }
    }
  }

  return_addresses->len = i;
}

#endif
```