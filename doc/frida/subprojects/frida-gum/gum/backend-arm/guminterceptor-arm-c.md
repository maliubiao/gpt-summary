Response:
Let's break down the thought process for analyzing this C code and answering the request.

**1. Understanding the Goal:**

The request asks for the functionality of the `guminterceptor-arm.c` file within the Frida dynamic instrumentation tool, specifically focusing on its relationship to reverse engineering, low-level concepts, logical reasoning, potential user errors, and how a user reaches this code.

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for keywords and patterns that hint at its purpose. Keywords like "interceptor," "trampoline," "redirect," "relocator," "writer," "reader," "ARM," "Thumb," "context," "thunk," and function names like `emit_arm_`, `emit_thumb_`, `push_cpu_context`, `prolog`, and `epilog` are strong indicators. The copyright notice also confirms it's part of Frida.

**3. Deconstructing the Functionality (Top-Down Approach):**

* **Core Purpose:** The filename and keywords strongly suggest this file handles intercepting function calls on ARM architectures (both ARM and Thumb instruction sets). The "interceptor" aspect means it modifies the execution flow of a program.

* **Trampolines:**  The frequent mention of "trampoline" is crucial. I know from reverse engineering concepts that trampolines are small snippets of code inserted at the beginning of a function to redirect execution. This confirms the core interception mechanism.

* **Redirection:** The "redirect" keywords and related sizes (`FULL_REDIRECT_SIZE`, `TINY_REDIRECT_SIZE`, etc.) point to how the interception is implemented. Different redirection sizes likely offer trade-offs between code size and functionality.

* **ARM and Thumb Handling:** The separation of code into `gum_emit_arm_*` and `gum_emit_thumb_*` functions clearly shows support for both ARM and Thumb instruction sets, which are common on ARM architectures.

* **Context Management:** The `GumFunctionContext` and `GumArmFunctionContextData` structures suggest the code manages the state of the intercepted function. This includes storing the original function address, the replacement function (if any), and backend-specific data.

* **Code Allocation:**  `GumCodeAllocator` indicates that the interceptor dynamically allocates memory to store the trampoline code.

* **Relocation:** The "relocator" components (`GumArmRelocator`, `GumThumbRelocator`) are critical for handling position-independent code. When inserting trampolines, addresses might need adjustments.

* **Writers and Readers:** The "writer" and "reader" components (`GumArmWriter`, `GumThumbWriter`, `GumArmReader`, `GumThumbReader`) handle the generation and analysis of ARM and Thumb instructions.

* **Thunks:** "Thunks" are small pieces of code that bridge different calling conventions or environments. In this context, the "enter" and "leave" thunks likely handle the transition into and out of the interception logic.

* **CPU Context:**  The code related to pushing and popping the CPU context (`gum_emit_*_push_cpu_context_high_part`) is essential for preserving the state of the registers when intercepting a function.

* **Prolog and Epilog:**  The `gum_emit_*_prolog` and `gum_emit_*_epilog` functions deal with setting up and tearing down the stack frame for the interceptor's code.

**4. Connecting to Reverse Engineering:**

* **Code Injection:** The entire process of creating and activating trampolines is a form of code injection, a fundamental technique in reverse engineering for modifying program behavior.
* **Hooking:**  The interception mechanism is a classic example of function hooking.
* **Dynamic Analysis:** Frida is a dynamic analysis tool, and this code is at the heart of its dynamic instrumentation capabilities.

**5. Connecting to Low-Level Concepts:**

* **ARM Architecture:**  The code heavily relies on understanding the ARM and Thumb instruction sets, registers, and calling conventions.
* **Memory Management:** Dynamic memory allocation and code patching are core low-level concepts.
* **Stack Frames:** The prolog and epilog code manipulates the stack frame.
* **CPU Registers:**  Saving and restoring CPU registers is crucial for maintaining program integrity.
* **Instruction Relocation:**  The relocator components handle the complexities of position-independent code.

**6. Logical Reasoning and Hypothetical Input/Output:**

* **Trampoline Selection:** The logic in `gum_interceptor_backend_prepare_trampoline` determines the appropriate trampoline size based on the available space and instruction set. *Hypothetical Input:*  A function at address `0x1000` with Thumb instructions. *Hypothetical Output:*  `data->redirect_code_size` set to `GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE` or a smaller size if relocation isn't fully possible.

* **Deflector Allocation:** The code allocates "deflectors" for more complex redirection scenarios. *Hypothetical Input:* An attempt to hook a function where the initial prologue is larger than the smallest redirect size. *Hypothetical Output:* Allocation of a `GumCodeDeflector`.

**7. User/Programming Errors:**

* **Memory Allocation Failures:**  If the `GumCodeAllocator` fails to allocate memory, the trampoline creation will fail. The code checks for `NULL` returns in some places, indicating awareness of this potential error.
* **Incorrect Function Address:** Providing an invalid function address to be intercepted would lead to crashes or unexpected behavior.

**8. User Operations Leading to This Code:**

This requires understanding how Frida is used:

1. **Target Selection:** The user selects a target process or application to instrument.
2. **Script Writing:** The user writes a Frida script (usually in JavaScript) to specify which functions to intercept and what actions to perform.
3. **Function Interception:** The script uses Frida's API (e.g., `Interceptor.attach`) to register the functions to be hooked.
4. **Backend Selection:** Frida's core logic determines the appropriate backend for the target architecture (in this case, ARM).
5. **Trampoline Creation:** When a function is intercepted, Frida's backend (this `guminterceptor-arm.c` code) kicks in to create and install the trampoline.
6. **Execution Redirection:** When the target function is called, the trampoline redirects execution to Frida's handler.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just intercepts function calls."  *Correction:* It's more than just a simple jump; it involves careful code generation, relocation, and context management.
* **Realization:** The code explicitly handles both ARM and Thumb modes. It's important to highlight the differences in instruction sizes and redirection mechanisms between them.
* **Consideration of edge cases:**  The code handles scenarios where the initial bytes of the function are too small for a full redirect, necessitating the use of deflectors. This is a crucial detail.
* **Understanding the "thunk" purpose:**  Initially, I might have glossed over thunks. Realizing their role in bridging calling conventions added a deeper understanding.

By following this structured approach, combining code analysis with conceptual knowledge of reverse engineering and low-level programming, I can generate a comprehensive and accurate answer to the request.
好的，让我们来详细分析一下 `guminterceptor-arm.c` 这个文件。

**功能列举:**

这个文件是 Frida 工具中负责在 ARM 架构上实现函数拦截 (function interception) 功能的核心组件。它的主要功能可以概括为：

1. **创建和管理 Trampoline (跳板代码):**
   - 当用户希望拦截一个 ARM 或 Thumb 函数时，这个文件负责在目标函数的起始位置注入一段小的代码片段，称为 Trampoline。
   - Trampoline 的作用是将程序执行流重定向到 Frida 的处理逻辑，以便在目标函数执行前后执行用户自定义的代码。
   - 文件中定义了不同大小的 Trampoline (`GUM_INTERCEPTOR_ARM_FULL_REDIRECT_SIZE`, `GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE`, `GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE` 等)，以适应不同的拦截场景和目标函数的前导指令长度。

2. **生成 ARM 和 Thumb 指令:**
   - 文件中使用了 `GumArmWriter` 和 `GumThumbWriter` 来动态生成 ARM 和 Thumb 指令。
   - 这些指令用于构建 Trampoline、进入和离开 Frida 的处理逻辑 (enter/leave thunks)、以及保存和恢复 CPU 上下文。

3. **处理代码重定位 (Relocation):**
   - 使用 `GumArmRelocator` 和 `GumThumbRelocator` 来分析目标函数的原始指令，并将它们复制到 Trampoline 中。
   - 在复制过程中，需要处理指令中的地址引用，确保 Trampoline 中的指令能够正确执行，即使它们被移动了位置。这对于包含相对跳转或地址加载指令的函数至关重要。

4. **管理函数上下文 (Function Context):**
   - 通过 `GumFunctionContext` 结构体来维护关于被拦截函数的信息，例如函数地址、原始指令、Trampoline 的地址等。
   - `GumArmFunctionContextData` 存储了 ARM 架构特定的上下文数据，例如重定向代码的大小。

5. **实现 Enter 和 Leave Thunks:**
   - 定义了 `enter_thunk_arm`, `enter_thunk_thumb`, `leave_thunk_arm`, `leave_thunk_thumb` 这些 thunk 函数的入口地址。
   - 这些 thunk 是在 Trampoline 被触发后，程序执行流进入 Frida 框架的入口点。
   - `enter_thunk` 负责在目标函数执行前调用用户提供的 "onEnter" 回调。
   - `leave_thunk` 负责在目标函数执行后调用用户提供的 "onLeave" 回调。

6. **保存和恢复 CPU 上下文:**
   - 在进入 Frida 的处理逻辑时，需要保存当前 CPU 的寄存器状态，以便在目标函数执行完毕后能够恢复。
   - `gum_emit_arm_push_cpu_context_high_part` 和 `gum_emit_thumb_push_cpu_context_high_part` 函数负责生成保存 CPU 上下文的指令。
   - 相应的，在离开 Frida 的处理逻辑时，需要恢复这些寄存器。

7. **处理 Fast Interception:**
   - 支持一种更快速的拦截方式 (`GUM_INTERCEPTOR_TYPE_FAST`)，在这种模式下，Trampoline 直接跳转到用户提供的替换函数，减少了 Frida 框架的介入。

**与逆向方法的关系及举例说明:**

这个文件直接体现了动态 instrumentation 这种逆向方法的核心。它允许在程序运行时动态地修改程序的行为，而无需修改程序的二进制文件。

**举例说明:**

假设我们想要拦截 `malloc` 函数，以便在每次分配内存时打印分配的大小：

1. **Frida 脚本:** 用户会编写一个 Frida 脚本，指定要拦截的函数和要执行的操作。例如：

   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'malloc'), {
     onEnter: function (args) {
       console.log('malloc called with size:', args[0]);
     },
     onLeave: function (retval) {
       console.log('malloc returned address:', retval);
     }
   });
   ```

2. **`guminterceptor-arm.c` 的作用:** 当 Frida 尝试执行 `Interceptor.attach` 时，对于 ARM 架构的目标进程，`guminterceptor-arm.c` 中的代码会被调用。

3. **Trampoline 创建:**
   -  `_gum_interceptor_backend_create_trampoline` 函数会被调用，为 `malloc` 函数创建 Trampoline。
   -  根据 `malloc` 函数的起始指令是 ARM 还是 Thumb，以及前导指令的长度，选择合适的 Trampoline 大小。
   -  `gum_interceptor_backend_emit_arm_trampolines` 或 `gum_interceptor_backend_emit_thumb_trampolines` 会生成相应的指令。例如，对于一个 ARM 函数，可能会生成类似以下的指令序列：

     ```assembly
     ; Original malloc prologue instructions (relocated)
     PUSH {r0-r7, lr}
     ; ... more original instructions ...

     ; Frida redirection
     LDR  r6, [pc, #offset_to_GumFunctionContext] ; 加载函数上下文指针
     LDR  pc, [pc, #offset_to_enter_thunk_arm]     ; 跳转到 enter thunk
     ```

4. **执行流程:** 当目标程序调用 `malloc` 时，会首先执行 Trampoline 中的代码，跳转到 `enter_thunk_arm`。

5. **Enter Thunk:** `gum_emit_arm_enter_thunk` 中生成的代码会被执行，它会：
   - 保存 CPU 上下文。
   - 将参数传递给 Frida 框架。
   - 调用 JavaScript 中定义的 `onEnter` 函数，打印分配大小。

6. **恢复执行:**  `onEnter` 执行完毕后，Frida 会恢复目标函数的原始执行流程（通过 Trampoline 中保存的原始指令）。

7. **Leave Thunk:** 当 `malloc` 函数执行完毕返回时，会再次经过 Trampoline，跳转到 `leave_thunk_arm`。

8. **Leave Thunk 执行:** `gum_emit_arm_leave_thunk` 中生成的代码会被执行，它会：
   - 保存 CPU 上下文。
   - 将返回值传递给 Frida 框架。
   - 调用 JavaScript 中定义的 `onLeave` 函数，打印返回值。
   - 恢复 CPU 上下文并返回到调用 `malloc` 的地方。

**涉及到的二进制底层、Linux/Android 内核及框架的知识及举例说明:**

1. **ARM/Thumb 指令集:** 代码中大量使用了 ARM 和 Thumb 指令，例如 `PUSH`, `LDR`, `STR`, `MOV`, `BL`, `B` 等。理解这些指令的含义和编码方式是理解代码功能的基础。

2. **ARM 架构寄存器:** 代码中操作了各种 ARM 寄存器，例如 `r0`-`r12`, `sp` (堆栈指针), `lr` (链接寄存器), `pc` (程序计数器), `cpsr` (当前程序状态寄存器) 等。理解这些寄存器的作用对于理解 CPU 上下文保存和恢复至关重要。

3. **函数调用约定 (Calling Convention):** 代码假设了标准的 ARM 函数调用约定，例如参数通过寄存器传递，返回值通过 `r0` 传递。

4. **内存管理:** 代码中使用了 `GumCodeAllocator` 来动态分配内存，这涉及到操作系统的内存管理机制。

5. **代码段可写权限:**  Frida 需要在目标进程的代码段注入 Trampoline，这通常需要代码段具有可写权限。在某些受保护的环境中，可能需要特殊的处理才能实现。

6. **CPU 缓存一致性:** 在修改代码段后，需要确保 CPU 缓存的一致性，以避免执行到旧的指令。虽然代码中没有显式体现，但 Frida 框架底层会处理这个问题。

7. **位置无关代码 (Position Independent Code - PIC):**  `GumArmRelocator` 和 `GumThumbRelocator` 的存在表明需要处理位置无关代码的情况，即代码可以在内存中的任意位置加载和执行。

8. **Linux/Android 进程内存布局:**  Frida 需要了解目标进程的内存布局，才能找到函数的地址并注入 Trampoline。

**逻辑推理及假设输入与输出:**

在 `gum_interceptor_backend_prepare_trampoline` 函数中，可以看到一些逻辑推理：

**假设输入:**

- `ctx->function_address`:  目标函数的地址 (例如 `0x70001000`).
- 目标函数是 Thumb 代码 (`FUNCTION_CONTEXT_ADDRESS_IS_THUMB(ctx)` 为真).

**逻辑推理:**

- **判断 Full Redirect Size:**  首先尝试使用完整的重定向大小 `GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE` (8 字节)。如果函数地址不是 4 字节对齐的，则增加 2 字节。
- **判断是否可以完整重定位:** 调用 `gum_thumb_relocator_can_relocate` 检查从 `function_address` 开始的 `data->full_redirect_size` 字节是否可以被安全地重定位。
- **如果不能完整重定位:**
    - 尝试使用链接重定向大小 `GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE` (6 字节)。
    - 如果还不行，尝试使用更小的微型重定向大小 `GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE` (4 字节)。
    - 如果所有尝试都失败，则 `gum_interceptor_backend_prepare_trampoline` 返回 `FALSE`，表示无法拦截。

**假设输出:**

- 如果 `gum_thumb_relocator_can_relocate` 返回真，则 `data->redirect_code_size` 等于 `data->full_redirect_size` (可能是 8 或 10 字节)。
- 否则，`data->redirect_code_size` 可能等于 `GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE` 或 `GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE`，取决于 `redirect_limit` 的值。

**涉及用户或编程常见的使用错误及举例说明:**

1. **尝试拦截不存在的函数:** 如果用户提供的函数名或地址是错误的，Frida 可能无法找到目标函数，导致拦截失败。虽然这个文件本身不直接处理用户输入，但错误的输入会导致上层逻辑无法正确调用此文件中的函数。

2. **在不安全的时间点拦截函数:**  如果在不恰当的时间点（例如，在函数执行的关键临界区）进行拦截，可能会导致程序崩溃或产生意外行为。这通常是用户在编写 Frida 脚本时需要注意的问题，但 `guminterceptor-arm.c` 中的代码需要在各种状态下都能稳定工作。

3. **拦截内联函数或短小函数:** 对于非常短小的函数，可能无法容纳任何类型的 Trampoline，导致拦截失败。`guminterceptor-arm.c` 中的逻辑会尝试使用最小的重定向方式来应对这种情况。

4. **内存分配失败:** 虽然不太常见，但如果 `GumCodeAllocator` 无法分配足够的内存来创建 Trampoline，拦截也会失败。这可能是由于系统内存不足或其他限制导致。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida:** 用户通过命令行工具 (例如 `frida`) 或编程方式启动 Frida，并指定要附加的目标进程。

2. **用户编写 Frida 脚本:** 用户编写 JavaScript 代码，使用 Frida 的 API 来定义要执行的拦截操作，例如：

   ```javascript
   // attach.js
   if (Process.arch === 'arm') {
     Interceptor.attach(Module.findExportByName(null, 'open'), {
       onEnter: function (args) {
         console.log('Opening file:', args[0].readUtf8String());
       }
     });
   }
   ```

3. **用户加载脚本:** 用户使用 Frida 命令行工具或 API 将脚本加载到目标进程中：

   ```bash
   frida -p <pid> -l attach.js
   ```

4. **Frida Core 处理:** Frida 的核心逻辑接收到用户的拦截请求。

5. **确定架构:** Frida 确定目标进程的架构是 ARM。

6. **调用 Backend:** Frida 会选择相应的 backend 来处理 ARM 架构的拦截，即 `guminterceptor-arm.c` 所在的组件。

7. **查找函数地址:** `Module.findExportByName(null, 'open')` 会在目标进程的模块中查找 `open` 函数的地址。

8. **创建拦截上下文:** Frida 创建一个 `GumFunctionContext` 结构体来存储关于这次拦截的信息。

9. **调用 `_gum_interceptor_backend_create_trampoline`:** `guminterceptor-arm.c` 中的这个函数会被调用，开始创建 Trampoline 的过程。

10. **Trampoline 代码生成:**  根据 `open` 函数的属性（ARM/Thumb，前导指令），调用 `gum_interceptor_backend_emit_arm_trampolines` 或 `gum_interceptor_backend_emit_thumb_trampolines` 来生成具体的指令。

11. **激活 Trampoline:**  生成的 Trampoline 代码会被写入到目标进程的内存中，覆盖 `open` 函数的起始部分。

12. **目标函数执行:** 当目标进程执行到 `open` 函数时，会先执行注入的 Trampoline 代码，从而将控制权转移到 Frida 的处理逻辑。

**调试线索:**

如果用户在使用 Frida 时遇到拦截问题，可以从以下方面进行调试，这些都与 `guminterceptor-arm.c` 的功能相关：

- **确认目标函数地址是否正确:**  使用 Frida 的 API (例如 `Module.findExportByName`) 确认获取到的函数地址是否正确。
- **检查架构是否匹配:** 确保 Frida 脚本中的架构判断 (`Process.arch === 'arm'`) 与目标进程的架构一致。
- **查看 Frida 的日志输出:** Frida 通常会输出一些调试信息，可以帮助了解拦截过程是否成功。
- **使用 Frida 的调试工具:** Frida 提供了一些调试 API，可以用来查看内存内容、寄存器状态等，帮助分析 Trampoline 的生成和执行过程。
- **分析目标函数的汇编代码:**  了解目标函数的起始指令，可以帮助判断 Trampoline 的大小选择是否合适。

总而言之，`guminterceptor-arm.c` 是 Frida 在 ARM 架构上实现动态 instrumentation 的关键组成部分，它负责生成和管理 Trampoline，处理代码重定位，以及实现进入和离开 Frida 处理逻辑的机制。理解这个文件的功能对于深入理解 Frida 的工作原理和解决相关的调试问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/guminterceptor-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarmreader.h"
#include "gumarmrelocator.h"
#include "gumarmwriter.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumthumbreader.h"
#include "gumthumbrelocator.h"
#include "gumthumbwriter.h"

#include <string.h>
#include <unistd.h>

#define GUM_INTERCEPTOR_ARM_FULL_REDIRECT_SIZE   (4 + 4)
#define GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE   (4)
#define GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE (8)
#define GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE (6)
#define GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE (4)

#define FUNCTION_CONTEXT_ADDRESS_IS_THUMB(ctx) ( \
    (GPOINTER_TO_SIZE (ctx->function_address) & 0x1) == 0x1)

#define GUM_FRAME_OFFSET_NEXT_HOP 0
#define GUM_FRAME_OFFSET_CPU_CONTEXT \
    (GUM_FRAME_OFFSET_NEXT_HOP + (2 * sizeof (gpointer)))

#define GUM_FCDATA(context) \
    ((GumArmFunctionContextData *) (context)->backend_data.storage)

typedef struct _GumArmFunctionContextData GumArmFunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumArmWriter arm_writer;
  GumArmRelocator arm_relocator;

  GumThumbWriter thumb_writer;
  GumThumbRelocator thumb_relocator;

  GumCodeSlice * arm_thunks;
  GumCodeSlice * thumb_thunks;

  gpointer enter_thunk_arm;
  gpointer enter_thunk_thumb;
  gpointer leave_thunk_arm;
  gpointer leave_thunk_thumb;
};

struct _GumArmFunctionContextData
{
  guint full_redirect_size;
  guint redirect_code_size;
};

G_STATIC_ASSERT (sizeof (GumArmFunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static gboolean gum_interceptor_backend_emit_arm_trampolines (
    GumInterceptorBackend * self, GumFunctionContext * ctx,
    gpointer function_address);
static gboolean gum_interceptor_backend_emit_thumb_trampolines (
    GumInterceptorBackend * self, GumFunctionContext * ctx,
    gpointer function_address);

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_arm_enter_thunk (GumArmWriter * aw);
static void gum_emit_thumb_enter_thunk (GumThumbWriter * tw);
static void gum_emit_arm_leave_thunk (GumArmWriter * aw);
static void gum_emit_thumb_leave_thunk (GumThumbWriter * tw);

static void gum_emit_arm_push_cpu_context_high_part (GumArmWriter * aw);
static void gum_emit_thumb_push_cpu_context_high_part (GumThumbWriter * tw);
static void gum_emit_arm_prolog (GumArmWriter * aw);
static void gum_emit_thumb_prolog (GumThumbWriter * tw);
static void gum_emit_arm_epilog (GumArmWriter * aw);
static void gum_emit_thumb_epilog (GumThumbWriter * tw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_arm_writer_init (&backend->arm_writer, NULL);
  backend->arm_writer.cpu_features = gum_query_cpu_features ();
  gum_arm_relocator_init (&backend->arm_relocator, NULL, &backend->arm_writer);

  gum_thumb_writer_init (&backend->thumb_writer, NULL);
  gum_thumb_relocator_init (&backend->thumb_relocator, NULL,
      &backend->thumb_writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_thumb_relocator_clear (&backend->thumb_relocator);
  gum_thumb_writer_clear (&backend->thumb_writer);

  gum_arm_relocator_clear (&backend->arm_relocator);
  gum_arm_writer_clear (&backend->arm_writer);

  g_slice_free (GumInterceptorBackend, backend);
}

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumArmFunctionContextData * data = GUM_FCDATA (ctx);
  gpointer function_address;
  gboolean is_thumb;
  guint redirect_limit;

  function_address = _gum_interceptor_backend_get_function_address (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  if (is_thumb)
  {
    data->full_redirect_size = GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE;
    if ((GPOINTER_TO_SIZE (function_address) & 3) != 0)
      data->full_redirect_size += 2;

    if (gum_thumb_relocator_can_relocate (function_address,
        data->full_redirect_size, GUM_SCENARIO_ONLINE, &redirect_limit))
    {
      data->redirect_code_size = data->full_redirect_size;
    }
    else
    {
      if (redirect_limit >= GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE)
        data->redirect_code_size = GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE;
      else if (redirect_limit >= GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE)
        data->redirect_code_size = GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE;
      else
        return FALSE;
    }
  }
  else
  {
    data->full_redirect_size = GUM_INTERCEPTOR_ARM_FULL_REDIRECT_SIZE;

    if (gum_arm_relocator_can_relocate (function_address,
        data->full_redirect_size, &redirect_limit))
    {
      data->redirect_code_size = data->full_redirect_size;
    }
    else
    {
      if (redirect_limit >= GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE)
        data->redirect_code_size = GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE;
      else
        return FALSE;
    }
  }

  ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  gpointer func;
  gboolean success;

  func = _gum_interceptor_backend_get_function_address (ctx);

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  if (FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx))
    success = gum_interceptor_backend_emit_thumb_trampolines (self, ctx, func);
  else
    success = gum_interceptor_backend_emit_arm_trampolines (self, ctx, func);
  if (!success)
    return FALSE;

  gum_memcpy (ctx->overwritten_prologue, func, ctx->overwritten_prologue_len);

  return TRUE;
}

static gboolean
gum_interceptor_backend_emit_arm_trampolines (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer function_address)
{
  GumArmFunctionContextData * data = GUM_FCDATA (ctx);
  GumArmWriter * aw = &self->arm_writer;
  GumArmRelocator * ar = &self->arm_relocator;
  gpointer deflector_target;
  guint reloc_bytes;

  gum_arm_writer_reset (aw, ctx->trampoline_slice->data);

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
  {
    deflector_target = ctx->replacement_function;
  }
  else
  {
    ctx->on_enter_trampoline = gum_arm_writer_cur (aw);
    deflector_target = ctx->on_enter_trampoline;
  }

  if (data->redirect_code_size != data->full_redirect_size)
  {
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address = function_address + data->redirect_code_size + 4;
    caller.max_distance = GUM_ARM_B_MAX_DISTANCE;

    return_address = function_address + data->redirect_code_size;

    dedicated = TRUE;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, deflector_target, dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_unref (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }
  }

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    gum_emit_arm_push_cpu_context_high_part (aw);
    gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_R6, GUM_ADDRESS (ctx));
    gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
        GUM_ADDRESS (self->enter_thunk_arm));

    ctx->on_leave_trampoline = gum_arm_writer_cur (aw);

    gum_emit_arm_push_cpu_context_high_part (aw);
    gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_R6, GUM_ADDRESS (ctx));
    gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
        GUM_ADDRESS (self->leave_thunk_arm));

    gum_arm_writer_flush (aw);
    g_assert (gum_arm_writer_offset (aw) <= ctx->trampoline_slice->size);
  }

  ctx->on_invoke_trampoline = gum_arm_writer_cur (aw);

  gum_arm_writer_reset (aw, ctx->on_invoke_trampoline);
  gum_arm_relocator_reset (ar, function_address, aw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (ar, NULL);
    if (reloc_bytes == 0)
      reloc_bytes = data->redirect_code_size;
  }
  while (reloc_bytes < data->redirect_code_size);

  gum_arm_relocator_write_all (ar);

  if (!gum_arm_relocator_eoi (ar))
  {
    gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
        GUM_ADDRESS (function_address + reloc_bytes));
  }

  gum_arm_writer_flush (aw);
  g_assert (gum_arm_writer_offset (aw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;

  return TRUE;
}

static gboolean
gum_interceptor_backend_emit_thumb_trampolines (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer function_address)
{
  GumArmFunctionContextData * data = GUM_FCDATA (ctx);
  GumThumbWriter * tw = &self->thumb_writer;
  GumThumbRelocator * tr = &self->thumb_relocator;
  gpointer deflector_target;
  GString * signature;
  const cs_insn * insn, * trailing_bl;
  guint reloc_bytes;
  gboolean is_branch_back_needed;
  gboolean is_eligible_for_lr_rewriting;

  gum_thumb_writer_reset (tw, ctx->trampoline_slice->data);

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
  {
    deflector_target = ctx->replacement_function;
  }
  else
  {
    ctx->on_enter_trampoline = gum_thumb_writer_cur (tw) + 1;
    deflector_target = ctx->on_enter_trampoline;
  }

  if (data->redirect_code_size != data->full_redirect_size)
  {
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address = function_address + data->redirect_code_size;
    caller.max_distance = GUM_THUMB_B_MAX_DISTANCE;

    return_address = function_address + data->redirect_code_size + 1;

    dedicated =
        data->redirect_code_size == GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, deflector_target, dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_unref (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }
  }

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    if (data->redirect_code_size != GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE)
    {
      gum_emit_thumb_push_cpu_context_high_part (tw);
    }

    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R6, GUM_ADDRESS (ctx));
    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
        GUM_ADDRESS (self->enter_thunk_thumb));

    ctx->on_leave_trampoline = gum_thumb_writer_cur (tw) + 1;

    gum_emit_thumb_push_cpu_context_high_part (tw);
    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R6, GUM_ADDRESS (ctx));
    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
        GUM_ADDRESS (self->leave_thunk_thumb));

    gum_thumb_writer_flush (tw);
    g_assert (gum_thumb_writer_offset (tw) <= ctx->trampoline_slice->size);
  }

  ctx->on_invoke_trampoline = gum_thumb_writer_cur (tw) + 1;

  gum_thumb_relocator_reset (tr, function_address, tw);

  signature = g_string_sized_new (16);

  insn = NULL;
  do
  {
    reloc_bytes = gum_thumb_relocator_read_one (tr, &insn);

    if (reloc_bytes != 0)
    {
      if (signature->len != 0)
        g_string_append_c (signature, ';');
      g_string_append (signature, insn->mnemonic);
    }
    else
    {
      reloc_bytes = data->redirect_code_size;
    }
  }
  while (reloc_bytes < data->redirect_code_size);

  /*
   * When we are hooking a function already hooked by another copy of
   * Gum, we need to be very careful when relocating BL instructions.
   * This is because the deflector trampoline looks at LR to determine
   * which hook is invoking it. So when the last of the overwritten
   * instructions is a BL, we might as well just transform it so it
   * looks just as if it had executed at its original memory location.
   */
  trailing_bl = (insn != NULL && insn->id == ARM_INS_BL &&
      insn->detail->arm.operands[0].type == ARM_OP_IMM) ? insn : NULL;

  is_branch_back_needed = !gum_thumb_relocator_eoi (tr);

  /*
   * Try to deal with minimal thunks that determine their caller and pass
   * it along to some inner function. This is important to support hooking
   * dlopen() on Android, where the dynamic linker uses the caller address
   * to decide on namespace and whether to allow the particular library to
   * be used by a particular caller.
   *
   * Because we potentially replace LR in order to trap the return, we end
   * up breaking dlopen() in such cases. We work around this by detecting
   * LR being read, and replace that instruction with a load of the actual
   * caller.
   *
   * This is however a bit risky done blindly, so we try to limit the
   * scope to the bare minimum. A potentially better longer term solution
   * is to analyze the function and patch each point of return, so we don't
   * have to replace LR on entry. That is however a bit complex, so we
   * opt for this simpler solution for now.
   */
  is_eligible_for_lr_rewriting = strcmp (signature->str, "mov;b") == 0 ||
      strcmp (signature->str, "mov;bx") == 0 ||
      g_str_has_prefix (signature->str, "push;mov;bl");

  g_string_free (signature, TRUE);

  if (is_eligible_for_lr_rewriting)
  {
    const cs_insn * insn;

    while ((insn = gum_thumb_relocator_peek_next_write_insn (tr)) != NULL)
    {
      if (insn->id == ARM_INS_MOV &&
          insn->detail->arm.operands[1].reg == ARM_REG_LR)
      {
        arm_reg dst_reg = insn->detail->arm.operands[0].reg;
        const arm_reg clobbered_regs[] = {
          ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
          ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
          ARM_REG_R9, ARM_REG_R12, ARM_REG_LR,
        };
        GArray * saved_regs;
        guint i;
        arm_reg nzcvq_reg;

        saved_regs = g_array_sized_new (FALSE, FALSE, sizeof (arm_reg),
            G_N_ELEMENTS (clobbered_regs));
        for (i = 0; i != G_N_ELEMENTS (clobbered_regs); i++)
        {
          arm_reg reg = clobbered_regs[i];
          if (reg != dst_reg)
            g_array_append_val (saved_regs, reg);
        }

        nzcvq_reg = ARM_REG_R4;
        if (nzcvq_reg == dst_reg)
          nzcvq_reg = ARM_REG_R5;

        gum_thumb_writer_put_push_regs_array (tw, saved_regs->len,
            (const arm_reg *) saved_regs->data);
        gum_thumb_writer_put_mrs_reg_reg (tw, nzcvq_reg,
            ARM_SYSREG_APSR_NZCVQ);

        gum_thumb_writer_put_call_address_with_arguments (tw,
            GUM_ADDRESS (_gum_interceptor_translate_top_return_address), 1,
            GUM_ARG_REGISTER, ARM_REG_LR);
        gum_thumb_writer_put_mov_reg_reg (tw, dst_reg, ARM_REG_R0);

        gum_thumb_writer_put_msr_reg_reg (tw, ARM_SYSREG_APSR_NZCVQ,
            nzcvq_reg);
        gum_thumb_writer_put_pop_regs_array (tw, saved_regs->len,
            (const arm_reg *) saved_regs->data);

        g_array_free (saved_regs, TRUE);

        gum_thumb_relocator_skip_one (tr);
      }
      else
      {
        gum_thumb_relocator_write_one (tr);
      }
    }
  }
  else if (trailing_bl != NULL)
  {
    const cs_arm_op * target = &trailing_bl->detail->arm.operands[0];

    while (gum_thumb_relocator_peek_next_write_insn (tr) != trailing_bl)
      gum_thumb_relocator_write_one (tr);
    gum_thumb_relocator_skip_one (tr);

    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_LR,
        trailing_bl->address + trailing_bl->size + 1);
    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
        target->imm | 1);

    is_branch_back_needed = FALSE;
  }
  else
  {
    gum_thumb_relocator_write_all (tr);
  }

  if (is_branch_back_needed)
  {
    gum_thumb_writer_put_push_regs (tw, 2, ARM_REG_R0, ARM_REG_R1);
    gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
        GUM_ADDRESS (function_address + reloc_bytes + 1));
    gum_thumb_writer_put_str_reg_reg_offset (tw, ARM_REG_R0,
        ARM_REG_SP, 4);
    gum_thumb_writer_put_pop_regs (tw, 2, ARM_REG_R0, ARM_REG_PC);
  }

  gum_thumb_writer_flush (tw);
  g_assert (gum_thumb_writer_offset (tw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumAddress function_address;
  GumArmFunctionContextData * data = GUM_FCDATA (ctx);

  function_address = GUM_ADDRESS (
      _gum_interceptor_backend_get_function_address (ctx));

  if (FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx))
  {
    GumThumbWriter * tw = &self->thumb_writer;

    gum_thumb_writer_reset (tw, prologue);
    tw->pc = function_address;

    if (ctx->trampoline_deflector != NULL)
    {
      if (data->redirect_code_size == GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE)
      {
        gum_emit_thumb_push_cpu_context_high_part (tw);
        gum_thumb_writer_put_bl_imm (tw,
            GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
      }
      else
      {
        g_assert (data->redirect_code_size ==
            GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE);
        gum_thumb_writer_put_b_imm (tw,
            GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
      }
    }
    else if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
    {
      gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
          GUM_ADDRESS (ctx->replacement_function));
    }
    else
    {
      gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
          GUM_ADDRESS (ctx->on_enter_trampoline));
    }

    gum_thumb_writer_flush (tw);
    g_assert (gum_thumb_writer_offset (tw) <= data->redirect_code_size);
  }
  else
  {
    GumArmWriter * aw = &self->arm_writer;

    gum_arm_writer_reset (aw, prologue);
    aw->pc = function_address;

    if (ctx->trampoline_deflector != NULL)
    {
      g_assert (data->redirect_code_size ==
          GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE);
      gum_arm_writer_put_b_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
    {
      gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
          GUM_ADDRESS (ctx->replacement_function));
    }
    else
    {
      gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
          GUM_ADDRESS (ctx->on_enter_trampoline));
    }

    gum_arm_writer_flush (aw);
    g_assert (gum_arm_writer_offset (aw) == data->redirect_code_size);
  }
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (ctx->function_address) & ~((gsize) 1));
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  gpointer target;

  if ((GPOINTER_TO_SIZE (address) & 1) == 1)
  {
    target = gum_thumb_reader_try_get_relative_jump_target (address);
  }
  else
  {
    target = gum_arm_reader_try_get_relative_jump_target (address);
    if (target == NULL)
      target = gum_arm_reader_try_get_indirect_jump_target (address);
  }

  return target;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumArmWriter * aw = &self->arm_writer;
  GumThumbWriter * tw = &self->thumb_writer;

  self->arm_thunks = gum_code_allocator_alloc_slice (self->allocator);
  gum_arm_writer_reset (aw, self->arm_thunks->data);

  self->enter_thunk_arm = gum_arm_writer_cur (aw);
  gum_emit_arm_enter_thunk (aw);

  self->leave_thunk_arm = gum_arm_writer_cur (aw);
  gum_emit_arm_leave_thunk (aw);

  gum_arm_writer_flush (aw);
  g_assert (gum_arm_writer_offset (aw) <= self->arm_thunks->size);

  self->thumb_thunks = gum_code_allocator_alloc_slice (self->allocator);
  gum_thumb_writer_reset (tw, self->thumb_thunks->data);

  self->enter_thunk_thumb = gum_thumb_writer_cur (tw) + 1;
  gum_emit_thumb_enter_thunk (tw);

  self->leave_thunk_thumb = gum_thumb_writer_cur (tw) + 1;
  gum_emit_thumb_leave_thunk (tw);

  gum_thumb_writer_flush (tw);
  g_assert (gum_thumb_writer_offset (tw) <= self->thumb_thunks->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->thumb_thunks);
  gum_code_slice_unref (self->arm_thunks);
}

static void
gum_emit_arm_enter_thunk (GumArmWriter * aw)
{
  gum_emit_arm_prolog (aw);

  gum_arm_writer_put_add_reg_reg_imm (aw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm_writer_put_sub_reg_reg_imm (aw, ARM_REG_R2, ARM_REG_R4, 4);
  gum_arm_writer_put_add_reg_reg_imm (aw, ARM_REG_R3, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, ARM_REG_R6,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R3);

  gum_emit_arm_epilog (aw);
}

static void
gum_emit_thumb_enter_thunk (GumThumbWriter * tw)
{
  gum_emit_thumb_prolog (tw);

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R2, ARM_REG_R4, 4);
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R3, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_thumb_writer_put_call_address_with_arguments (tw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, ARM_REG_R6,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R3);

  gum_emit_thumb_epilog (tw);
}

static void
gum_emit_arm_leave_thunk (GumArmWriter * aw)
{
  gum_emit_arm_prolog (aw);

  gum_arm_writer_put_add_reg_reg_imm (aw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm_writer_put_add_reg_reg_imm (aw, ARM_REG_R2, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, ARM_REG_R6,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2);

  gum_emit_arm_epilog (aw);
}

static void
gum_emit_thumb_leave_thunk (GumThumbWriter * tw)
{
  gum_emit_thumb_prolog (tw);

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R2, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_thumb_writer_put_call_address_with_arguments (tw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, ARM_REG_R6,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2);

  gum_emit_thumb_epilog (tw);
}

static void
gum_emit_arm_push_cpu_context_high_part (GumArmWriter * aw)
{
  gum_arm_writer_put_push_regs (aw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
}

static void
gum_emit_thumb_push_cpu_context_high_part (GumThumbWriter * tw)
{
  gum_thumb_writer_put_push_regs (tw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
}

static void
gum_emit_arm_prolog (GumArmWriter * aw)
{
  GumCpuFeatures cpu_features;

  /*
   * Set up our stack frame:
   *
   * [cpu_context] <-- high part already pushed
   * [padding]
   * [next_hop]
   */

  gum_arm_writer_put_mov_reg_cpsr (aw, ARM_REG_R5);
  gum_arm_writer_put_add_reg_reg_imm (aw, ARM_REG_R4, ARM_REG_SP, 9 * 4);

  /* Store vector registers + padding */
  cpu_features = gum_query_cpu_features ();

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_arm_writer_put_sub_reg_u16 (aw, ARM_REG_SP, 4);
      gum_arm_writer_put_vpush_range (aw, ARM_REG_Q8, ARM_REG_Q15);
    }
    else
    {
      gum_arm_writer_put_sub_reg_u16 (aw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }

    gum_arm_writer_put_vpush_range (aw, ARM_REG_Q0, ARM_REG_Q7);
  }
  else
  {
    gum_arm_writer_put_sub_reg_u16 (aw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  /* Store SP, CPSR, followed by R8-R12 */
  gum_arm_writer_put_push_regs (aw, 7,
      ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  /* Reserve space for next_hop, padding, and the PC placeholder */
  gum_arm_writer_put_sub_reg_u16 (aw, ARM_REG_SP, 3 * 4);
}

static void
gum_emit_thumb_prolog (GumThumbWriter * tw)
{
  GumCpuFeatures cpu_features;

  gum_thumb_writer_put_mov_reg_cpsr (tw, ARM_REG_R5);
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R4, ARM_REG_SP, 9 * 4);

  cpu_features = gum_query_cpu_features ();

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_thumb_writer_put_sub_reg_imm (tw, ARM_REG_SP, 4);
      gum_thumb_writer_put_vpush_range (tw, ARM_REG_Q8, ARM_REG_Q15);
    }
    else
    {
      gum_thumb_writer_put_sub_reg_imm (tw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }

    gum_thumb_writer_put_vpush_range (tw, ARM_REG_Q0, ARM_REG_Q7);
  }
  else
  {
    gum_thumb_writer_put_sub_reg_imm (tw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  gum_thumb_writer_put_push_regs (tw, 7,
      ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  gum_thumb_writer_put_sub_reg_imm (tw, ARM_REG_SP, 3 * 4);
}

static void
gum_emit_arm_epilog (GumArmWriter * aw)
{
  GumCpuFeatures cpu_features;

  /* Restore LR */
  gum_arm_writer_put_sub_reg_reg_imm (aw, ARM_REG_R0, ARM_REG_R4, 4);
  gum_arm_writer_put_ldr_reg_reg (aw, ARM_REG_LR, ARM_REG_R0);

  /* Replace LR with next_hop so we can pop it straight into PC */
  gum_arm_writer_put_ldr_reg_reg_offset (aw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);
  gum_arm_writer_put_str_reg_reg (aw, ARM_REG_R1, ARM_REG_R0);

  gum_arm_writer_put_ldr_reg_reg_offset (aw, ARM_REG_R5, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, cpsr));

  /* Skip [next_hop, padding] and [PC, SP, and CPSR] */
  gum_arm_writer_put_add_reg_u16 (aw, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + (3 * 4));

  gum_arm_writer_put_pop_regs (aw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  cpu_features = gum_query_cpu_features ();

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    gum_arm_writer_put_vpop_range (aw, ARM_REG_Q0, ARM_REG_Q7);

    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_arm_writer_put_vpop_range (aw, ARM_REG_Q8, ARM_REG_Q15);
      gum_arm_writer_put_add_reg_u16 (aw, ARM_REG_SP, 4);
    }
    else
    {
      gum_arm_writer_put_add_reg_u16 (aw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }
  }
  else
  {
    gum_arm_writer_put_add_reg_u16 (aw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  gum_arm_writer_put_mov_cpsr_reg (aw, ARM_REG_R5);

  gum_arm_writer_put_pop_regs (aw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);
}

static void
gum_emit_thumb_epilog (GumThumbWriter * tw)
{
  GumCpuFeatures cpu_features;

  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R0, ARM_REG_R4, 4);
  gum_thumb_writer_put_ldr_reg_reg (tw, ARM_REG_R1, ARM_REG_R0);
  gum_thumb_writer_put_mov_reg_reg (tw, ARM_REG_LR, ARM_REG_R1);

  gum_thumb_writer_put_ldr_reg_reg_offset (tw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);
  gum_thumb_writer_put_str_reg_reg (tw, ARM_REG_R1, ARM_REG_R0);

  gum_thumb_writer_put_ldr_reg_reg_offset (tw, ARM_REG_R5, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, cpsr));

  gum_thumb_writer_put_add_reg_imm (tw, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + (3 * 4));

  gum_thumb_writer_put_pop_regs (tw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  cpu_features = gum_query_cpu_features ();

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    gum_thumb_writer_put_vpop_range (tw, ARM_REG_Q0, ARM_REG_Q7);

    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_thumb_writer_put_vpop_range (tw, ARM_REG_Q8, ARM_REG_Q15);
      gum_thumb_writer_put_add_reg_imm (tw, ARM_REG_SP, 4);
    }
    else
    {
      gum_thumb_writer_put_add_reg_imm (tw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }
  }
  else
  {
    gum_thumb_writer_put_add_reg_imm (tw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  gum_thumb_writer_put_mov_cpsr_reg (tw, ARM_REG_R5);

  gum_thumb_writer_put_pop_regs (tw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);
}

"""

```