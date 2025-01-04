Response:
Let's break down the thought process for analyzing the provided C code.

**1. Understanding the Goal:**

The request is to analyze a specific C source file from Frida, `guminvocationlistener.c`, and describe its functionality, its relation to reverse engineering, its involvement with low-level details, any logical inferences it performs, potential user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and High-Level Understanding:**

My first step is to quickly read through the code to get a general idea of what it does. I notice:

* **Includes:**  `guminvocationlistener.h` suggests this file defines or implements something related to "invocation listeners."
* **Conditional Compilation:** The `#ifndef GUM_DIET` block hints at different build configurations (likely a "full" and a "slimmed-down" version). This is important to keep in mind as the functionality might vary.
* **Structures:** `_GumCallListener` and `_GumProbeListener` are defined, each containing function pointers (`on_enter`, `on_leave`, `on_hit`), a data pointer, and a data destruction function. This strongly suggests these structures represent different kinds of listeners.
* **Functions:**  Functions like `gum_make_call_listener`, `gum_make_probe_listener`, `gum_invocation_listener_on_enter`, and `gum_invocation_listener_on_leave` clearly indicate the creation and triggering of these listeners.
* **GObject:** The use of `G_DEFINE_INTERFACE`, `G_DEFINE_TYPE_EXTENDED`, and mentions of `GObject` suggest this code is part of a larger system (likely GLib/GObject) and uses object-oriented principles.

**3. Deeper Dive and Functional Analysis (Focusing on `#ifndef GUM_DIET` first):**

I start analyzing the code block that's active when `GUM_DIET` is not defined. This seems to be the more feature-rich version.

* **Key Concept: Call Listener:** This listener has callbacks for entering and leaving a function (`on_enter`, `on_leave`). This immediately connects to function hooking and tracing, a core reverse engineering technique.
* **Key Concept: Probe Listener:** This listener has a callback that's triggered when a specific point in the code is hit (`on_hit`). This also relates to hooking but at a more granular level (e.g., a specific instruction address).
* **Interface:**  `GumInvocationListener` is defined as an interface. This allows for polymorphism – both `GumCallListener` and `GumProbeListener` can be treated as `GumInvocationListener` objects.
* **Object Management:** The code uses `g_object_new` for allocation and has `finalize` methods for cleanup, suggesting proper resource management.
* **Callback Mechanism:** The `GumInvocationCallback` type and the `on_enter` and `on_leave` functions show a clear pattern for executing user-defined code at specific points during program execution.

**4. Analyzing the `#else` Block (When `GUM_DIET` is defined):**

I then examine the alternative implementation when `GUM_DIET` is defined.

* **Simplified:**  The structure is simpler, directly containing the callback function pointers. There's no separate `GumCallListener` and `GumProbeListener` types.
* **Efficiency Focus:**  This version appears to be optimized for size or performance, potentially in environments with resource constraints.

**5. Connecting to Reverse Engineering:**

At this point, the connection to reverse engineering becomes clear. The listeners provide the fundamental mechanism for:

* **Function Hooking:** Intercepting function calls to examine arguments, return values, or even modify behavior.
* **Code Tracing:** Monitoring the execution flow of a program by setting probes at specific locations.
* **Dynamic Analysis:**  Observing a program's behavior as it runs.

I then formulate concrete examples of how these listeners would be used in reverse engineering scenarios.

**6. Identifying Low-Level Aspects:**

I consider the underlying technologies and concepts involved:

* **Binary Code:**  The listeners operate on the executable code itself, dealing with function addresses and instruction points.
* **Operating System Interaction:** Frida needs to interact with the OS to inject code and intercept function calls. This involves concepts like process memory, code injection, and potentially kernel-level interactions (though this specific file might not directly touch the kernel).
* **Android:** Given the context of Frida and the example usage, the connection to Android and its framework (like ART) is important.

**7. Logical Inferences and Assumptions:**

I think about how the code is likely used:

* **Input:**  The user (through Frida's scripting API) provides the target function or code address and the callback functions they want to execute.
* **Output:** When the targeted code is executed, the registered callbacks are invoked with context information.

I create a simple hypothetical scenario to illustrate this.

**8. User Errors:**

I consider common mistakes users might make:

* **Incorrect Callback Signatures:**  Mismatched function pointer types are a classic C error.
* **Memory Management Issues:** If the user-provided `data_destroy` function is incorrect, it could lead to memory leaks or crashes.
* **Race Conditions:** In multithreaded environments, careful synchronization is needed, and users might make mistakes here.

**9. Tracing User Interaction (Debugging Clues):**

I think about the steps a user would take to reach this code:

* **Frida Scripting:** Users primarily interact with Frida through its JavaScript API.
* **`Interceptor` API:** The `Interceptor` object is the core mechanism for setting up hooks and probes.
* **Mapping to C Code:**  The JavaScript API calls down into Frida's C++ core, which eventually uses the `Gum` library and these listener components.

**10. Structuring the Answer:**

Finally, I organize my findings into the requested sections (Functionality, Reverse Engineering, Low-Level Details, Logic, User Errors, Debugging Clues) and present the information clearly and concisely. I make sure to explain the concepts in a way that someone familiar with reverse engineering but perhaps not the specifics of Frida's internals can understand. I also explicitly address each point of the original request.
这个 `guminvocationlistener.c` 文件是 Frida 动态 instrumentation 工具中 `Gum` 库的一个核心组件，它定义了用于监听函数调用和代码执行的功能。 让我们详细分解其功能以及它与逆向工程、底层知识和用户交互的关系。

**文件功能:**

该文件主要定义了以下两种类型的调用监听器：

1. **`GumCallListener` (调用监听器):**
   - 允许用户在目标进程中 **函数调用前后** 插入自定义的代码执行。
   - 提供了两个回调函数指针：`on_enter` 和 `on_leave`。
   - `on_enter` 在目标函数即将执行时被调用。
   - `on_leave` 在目标函数执行完毕即将返回时被调用。
   - 可以关联用户自定义的数据 (`data`)，这些数据会在回调函数中传递。

2. **`GumProbeListener` (探针监听器):**
   - 允许用户在目标进程中的 **特定代码地址** 插入自定义的代码执行。
   - 提供了单个回调函数指针：`on_hit`。
   - `on_hit` 在执行流到达指定代码地址时被调用。
   - 同样可以关联用户自定义的数据 (`data`)。

**核心功能总结:**

- **提供接口:** 定义了 `GumInvocationListener` 接口，作为 `GumCallListener` 和 `GumProbeListener` 的抽象基类。
- **创建监听器:** 提供了 `gum_make_call_listener` 和 `gum_make_probe_listener` 函数，用于创建不同类型的监听器实例。
- **触发回调:** 实现了 `gum_invocation_listener_on_enter` 和 `gum_invocation_listener_on_leave` 函数，用于在合适的时机调用用户定义的回调函数。
- **管理用户数据:** 允许用户关联自定义数据，并在监听器销毁时提供清理机制 (`data_destroy`)。

**与逆向方法的关系及举例说明:**

`guminvocationlistener.c` 中定义的监听器是 Frida 进行动态逆向的核心机制之一。逆向工程师可以利用这些监听器来：

**1. 函数 Hook (Function Hooking):**

   - **概念:**  拦截对目标函数的调用，并在其执行前后执行自定义代码。
   - **实现:** 通过 `GumCallListener` 实现。
   - **举例:** 假设要逆向分析一个名为 `calculate_sum` 的函数，查看其参数和返回值：

     ```c
     #include <frida-gum.h>
     #include <stdio.h>

     void on_calculate_sum_enter(GumInvocationContext *context, gpointer user_data) {
         int arg1 = gum_invocation_context_get_nth_argument(context, 0);
         int arg2 = gum_invocation_context_get_nth_argument(context, 1);
         printf("Entering calculate_sum with arguments: %d, %d\n", arg1, arg2);
     }

     void on_calculate_sum_leave(GumInvocationContext *context, gpointer user_data) {
         int return_value = gum_invocation_context_get_return_value(context);
         printf("Leaving calculate_sum with return value: %d\n", return_value);
     }

     int main() {
         GumInterceptor *interceptor = gum_interceptor_obtain();
         void *target_address = // 获取 calculate_sum 函数的地址 (例如通过符号查找)

         GumInvocationListener *listener = gum_make_call_listener(
             on_calculate_sum_enter,
             on_calculate_sum_leave,
             NULL, // 用户数据
             NULL  // 数据销毁回调
         );

         gum_interceptor_begin_transaction();
         gum_interceptor_attach(interceptor, target_address, listener);
         gum_interceptor_end_transaction();

         // ... (连接到目标进程并执行相关代码) ...

         return 0;
     }
     ```

   - **解释:**  当目标进程调用 `calculate_sum` 时，`on_calculate_sum_enter` 会先被调用，打印出参数。函数执行完毕后，`on_calculate_sum_leave` 被调用，打印出返回值。

**2. 代码跟踪 (Code Tracing):**

   - **概念:**  在程序执行的特定指令地址上插入代码，观察执行流程。
   - **实现:** 通过 `GumProbeListener` 实现。
   - **举例:**  假设要观察地址 `0x12345678` 处的指令执行情况：

     ```c
     #include <frida-gum.h>
     #include <stdio.h>

     void on_probe_hit(GumInvocationContext *context, gpointer user_data) {
         guint64 address = gum_invocation_context_get_instruction_address(context);
         printf("Probe hit at address: 0x%" G_GINT64_MODIFIER "x\n", address);
         // 还可以获取寄存器状态等信息
     }

     int main() {
         GumInterceptor *interceptor = gum_interceptor_obtain();
         void *target_address = (void *)0x12345678;

         GumInvocationListener *listener = gum_make_probe_listener(
             on_probe_hit,
             NULL,
             NULL
         );

         gum_interceptor_begin_transaction();
         gum_interceptor_attach(interceptor, target_address, listener);
         gum_interceptor_end_transaction();

         // ... (连接到目标进程并使其执行到该地址) ...

         return 0;
     }
     ```

   - **解释:**  当目标进程执行到地址 `0x12345678` 时，`on_probe_hit` 会被调用，打印出当前指令地址。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

此文件虽然本身是 C 代码，但其背后的运作机制涉及到许多底层概念：

**1. 二进制底层知识:**

   - **函数地址:**  逆向时需要知道目标函数的内存地址才能进行 hook。这涉及到对目标程序的内存布局的理解，例如代码段的起始地址。
   - **指令地址:**  `GumProbeListener` 直接操作指令地址，需要理解机器码和汇编指令才能选择合适的探针位置。
   - **调用约定:**  Hook 函数时需要理解目标平台的调用约定（例如 x86-64 的 System V ABI 或 Windows x64 calling convention），才能正确地获取和修改函数参数和返回值。`GumInvocationContext` 提供了抽象层来处理这些细节。

**2. Linux/Android 内核知识:**

   - **进程间通信 (IPC):** Frida 需要通过某种 IPC 机制与目标进程进行通信，以便注入代码和控制执行。在 Linux/Android 上，这可能涉及到 `ptrace` 系统调用或其他更高级的机制。
   - **内存管理:** Frida 需要在目标进程的内存空间中分配和管理内存，用于存储 hook 代码和用户数据。
   - **代码注入:** 将自定义代码注入到目标进程的地址空间是核心功能。这需要绕过操作系统的安全机制，例如地址空间布局随机化 (ASLR)。
   - **Android 框架 (ART/Dalvik):** 在 Android 平台上，hook 通常发生在 Android Runtime (ART 或 Dalvik) 的层面。理解 ART 的内部结构，例如方法表的布局，对于精确 hook Java 或 Native 方法至关重要。

**3. 举例说明:**

   - 在 Android 上 hook 一个 Java 方法，Frida 需要与 ART 虚拟机交互，找到对应的方法对象，并修改其入口地址，使其指向 Frida 注入的 hook 代码。`GumInvocationListener` 机制会被用来处理 hook 代码的执行。
   - 使用 `GumProbeListener` 跟踪 Linux 内核的某个系统调用入口点，需要知道内核代码的地址空间和相关的内核数据结构。

**逻辑推理及假设输入与输出:**

虽然这个文件主要定义了数据结构和接口，但其使用方式涉及到逻辑推理：

**假设输入:**

- 用户指定要 hook 的函数名或地址。
- 用户提供了 `on_enter` 和/或 `on_leave` 回调函数（对于 `GumCallListener`）或 `on_hit` 回调函数（对于 `GumProbeListener`）。
- 用户可能提供了自定义的数据指针和销毁函数。

**逻辑推理:**

1. **查找目标:** Frida 内部需要根据用户提供的函数名或地址，在目标进程的内存空间中定位到实际的函数入口点或指令地址。
2. **注入 Hook 代码:** Frida 需要生成或找到合适的 hook 代码（通常是跳转指令），将其注入到目标进程，并修改目标函数的入口地址或在目标指令前插入跳转。
3. **上下文传递:** 当 hook 代码被执行时，需要创建 `GumInvocationContext` 对象，包含当前的执行上下文信息，例如寄存器状态、函数参数等。
4. **回调执行:**  根据监听器的类型，在函数入口或出口，或者探针命中时，调用用户提供的回调函数，并将 `GumInvocationContext` 和用户数据传递给回调函数。

**输出:**

- 回调函数执行产生的副作用，例如打印日志、修改参数或返回值等。

**用户或编程常见的使用错误及举例说明:**

1. **回调函数签名错误:**  用户定义的回调函数 `on_enter`、`on_leave` 或 `on_hit` 的参数类型与 `GumInvocationCallback` 定义不符，可能导致编译错误或运行时崩溃。

   ```c
   // 错误的 on_enter 回调函数签名
   void my_on_enter(GumInvocationContext *context) { // 缺少 gpointer user_data
       // ...
   }

   // 在创建监听器时使用错误的签名
   GumInvocationListener *listener = gum_make_call_listener(
       my_on_enter, // 编译时可能不会报错，但运行时会出问题
       NULL,
       NULL,
       NULL
   );
   ```

2. **内存管理错误:** 用户提供的 `data_destroy` 函数不正确，可能导致内存泄漏或 double free。

   ```c
   void *my_data = malloc(1024);

   void my_data_destroy(gpointer data) {
       // 错误的销毁逻辑，可能多次 free 或者不 free
       free(data);
   }

   GumInvocationListener *listener = gum_make_call_listener(
       NULL,
       NULL,
       my_data,
       my_data_destroy
   );

   // ... 当 listener 被销毁时，my_data_destroy 会被调用
   ```

3. **在回调函数中进行不安全的操作:**  在回调函数中执行耗时或可能阻塞的操作，可能会影响目标进程的性能和稳定性。

4. **并发问题:**  如果在多线程环境下使用监听器，需要考虑线程安全问题，避免竞态条件。

**用户操作是如何一步步的到达这里，作为调试线索:**

用户通常不会直接操作 `guminvocationlistener.c` 中的代码。他们通过 Frida 的更高级别的 API 进行交互，例如 Python 或 JavaScript API。 让我们以 Python API 为例：

1. **编写 Frida 脚本:** 用户编写一个 Python 脚本，使用 Frida 的 `frida` 模块来连接到目标进程，并使用 `Interceptor` 对象来 attach 函数或设置探针。

   ```python
   import frida

   def on_message(message, data):
       print(message)

   session = frida.attach("target_process") # 连接到目标进程

   script = session.create_script("""
       Interceptor.attach(ptr("0x12345678"), { // 设置探针
           onEnter: function(args) {
               console.log("Entering function at 0x12345678");
           }
       });
   """)
   script.on('message', on_message)
   script.load()
   input() # 防止脚本立即退出
   ```

2. **Frida 内部处理:** 当 `Interceptor.attach()` 被调用时，Frida 的 JavaScript 桥接会将这个请求传递到 Frida 的 C++ 核心代码。

3. **Gum 库介入:**  C++ 核心代码会使用 `GumInterceptor` 对象来处理 attach 请求。这最终会涉及到 `gum_make_probe_listener` (或 `gum_make_call_listener`) 来创建相应的监听器实例。

4. **`guminvocationlistener.c` 的作用:**  `gum_make_probe_listener` 的实现就在 `guminvocationlistener.c` 中。它会分配 `GumProbeListener` 结构体，并将用户提供的回调函数 (在 JavaScript 中定义，通过桥接传递过来) 存储在 `on_hit` 字段中。

5. **代码注入和执行:** Frida 会将必要的 hook 代码注入到目标进程，并在目标地址设置断点或修改指令。当目标进程执行到被 hook 的位置时，注入的 hook 代码会触发，并调用 `gum_invocation_listener_on_enter` (或 `gum_invocation_listener_on_leave` 对于 `GumCallListener`)。

6. **回调执行:** `gum_invocation_listener_on_enter` 最终会调用用户提供的 JavaScript 回调函数 (通过 Frida 的桥接机制)。

**调试线索:**

如果在 Frida 使用过程中遇到问题，例如回调函数没有被触发，或者出现崩溃，可以按照以下线索进行调试：

- **检查目标地址是否正确:**  确保要 hook 的函数或代码地址是正确的。
- **检查 Frida 是否成功 attach 到目标进程:**  确认 Frida 是否成功连接到目标进程，并且没有被安全策略阻止。
- **检查回调函数是否正确定义:**  确保回调函数的参数类型和返回值与 Frida 的期望一致。
- **查看 Frida 的日志输出:**  Frida 通常会输出一些调试信息，可以帮助定位问题。
- **使用 Frida 的调试功能:** Frida 提供了一些调试功能，例如查看注入的代码和断点信息。
- **如果问题涉及到 `Gum` 库的层面，可以考虑查看 `guminvocationlistener.c` 相关的代码逻辑，理解监听器是如何创建和触发的。**

总而言之，`guminvocationlistener.c` 是 Frida 动态 instrumentation 机制的基础，它提供了在目标进程中拦截代码执行的能力，是实现各种逆向分析任务的关键组件。 用户虽然不直接操作这个文件，但他们通过 Frida 的高级 API 使用了这里定义的功能。理解这个文件的作用有助于深入理解 Frida 的工作原理，并在遇到问题时提供调试思路。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/guminvocationlistener.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminvocationlistener.h"

#ifndef GUM_DIET

#define GUM_TYPE_CALL_LISTENER (gum_call_listener_get_type ())
GUM_DECLARE_FINAL_TYPE (GumCallListener, gum_call_listener, GUM, CALL_LISTENER,
                        GObject)

#define GUM_TYPE_PROBE_LISTENER (gum_probe_listener_get_type ())
GUM_DECLARE_FINAL_TYPE (GumProbeListener, gum_probe_listener, GUM,
                        PROBE_LISTENER, GObject)

struct _GumCallListener
{
  GObject parent;

  GumInvocationCallback on_enter;
  GumInvocationCallback on_leave;

  gpointer data;
  GDestroyNotify data_destroy;
};

struct _GumProbeListener
{
  GObject parent;

  GumInvocationCallback on_hit;

  gpointer data;
  GDestroyNotify data_destroy;
};

G_DEFINE_INTERFACE (GumInvocationListener, gum_invocation_listener,
                    G_TYPE_OBJECT)

static void gum_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_call_listener_finalize (GObject * object);
static void gum_call_listener_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_call_listener_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);
G_DEFINE_TYPE_EXTENDED (GumCallListener,
                        gum_call_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_call_listener_iface_init))

static void gum_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_probe_listener_finalize (GObject * object);
static void gum_probe_listener_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
G_DEFINE_TYPE_EXTENDED (GumProbeListener,
                        gum_probe_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_probe_listener_iface_init))

static void
gum_invocation_listener_default_init (GumInvocationListenerInterface * iface)
{
}

GumInvocationListener *
gum_make_call_listener (GumInvocationCallback on_enter,
                        GumInvocationCallback on_leave,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
  GumCallListener * listener;

  listener = g_object_new (GUM_TYPE_CALL_LISTENER, NULL);
  listener->on_enter = on_enter;
  listener->on_leave = on_leave;
  listener->data = data;
  listener->data_destroy = data_destroy;

  return GUM_INVOCATION_LISTENER (listener);
}

GumInvocationListener *
gum_make_probe_listener (GumInvocationCallback on_hit,
                         gpointer data,
                         GDestroyNotify data_destroy)
{
  GumProbeListener * listener;

  listener = g_object_new (GUM_TYPE_PROBE_LISTENER, NULL);
  listener->on_hit = on_hit;
  listener->data = data;
  listener->data_destroy = data_destroy;

  return GUM_INVOCATION_LISTENER (listener);
}

void
gum_invocation_listener_on_enter (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  GumInvocationListenerInterface * iface =
      GUM_INVOCATION_LISTENER_GET_IFACE (self);

  if (iface->on_enter != NULL)
    iface->on_enter (self, context);
}

void
gum_invocation_listener_on_leave (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  GumInvocationListenerInterface * iface =
      GUM_INVOCATION_LISTENER_GET_IFACE (self);

  if (iface->on_leave != NULL)
    iface->on_leave (self, context);
}

static void
gum_call_listener_class_init (GumCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_call_listener_finalize;
}

static void
gum_call_listener_iface_init (gpointer g_iface,
                              gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_call_listener_on_enter;
  iface->on_leave = gum_call_listener_on_leave;
}

static void
gum_call_listener_init (GumCallListener * self)
{
}

static void
gum_call_listener_finalize (GObject * object)
{
  GumCallListener * self = GUM_CALL_LISTENER (object);

  if (self->data_destroy != NULL)
    self->data_destroy (self->data);

  G_OBJECT_CLASS (gum_call_listener_parent_class)->finalize (object);
}

static void
gum_call_listener_on_enter (GumInvocationListener * listener,
                            GumInvocationContext * context)
{
  GumCallListener * self = GUM_CALL_LISTENER (listener);

  if (self->on_enter != NULL)
    self->on_enter (context, self->data);
}

static void
gum_call_listener_on_leave (GumInvocationListener * listener,
                            GumInvocationContext * context)
{
  GumCallListener * self = GUM_CALL_LISTENER (listener);

  if (self->on_leave != NULL)
    self->on_leave (context, self->data);
}

static void
gum_probe_listener_class_init (GumProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_probe_listener_finalize;
}

static void
gum_probe_listener_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_probe_listener_on_enter;
}

static void
gum_probe_listener_init (GumProbeListener * self)
{
}

static void
gum_probe_listener_finalize (GObject * object)
{
  GumProbeListener * self = GUM_PROBE_LISTENER (object);

  if (self->data_destroy != NULL)
    self->data_destroy (self->data);

  G_OBJECT_CLASS (gum_probe_listener_parent_class)->finalize (object);
}

static void
gum_probe_listener_on_enter (GumInvocationListener * listener,
                             GumInvocationContext * context)
{
  GumProbeListener * self = GUM_PROBE_LISTENER (listener);

  self->on_hit (context, self->data);
}

#else

static GumInvocationListener * gum_make_invocation_listener (
    GumInvocationCallback on_enter, GumInvocationCallback on_leave,
    gpointer data, GDestroyNotify data_destroy);
static void gum_invocation_listener_finalize (GumObject * object);
static void gum_invocation_listener_dummy_callback (
    GumInvocationContext * context, gpointer user_data);

GumInvocationListener *
gum_make_call_listener (GumInvocationCallback on_enter,
                        GumInvocationCallback on_leave,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
  return gum_make_invocation_listener (on_enter,
      (on_leave != NULL) ? on_leave : gum_invocation_listener_dummy_callback,
      data, data_destroy);
}

GumInvocationListener *
gum_make_probe_listener (GumInvocationCallback on_hit,
                         gpointer data,
                         GDestroyNotify data_destroy)
{
  return gum_make_invocation_listener (on_hit, NULL, data, data_destroy);
}

void
gum_invocation_listener_on_enter (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  if (self->on_enter != NULL)
    self->on_enter (context, self->data);
}

void
gum_invocation_listener_on_leave (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  if (self->on_leave != NULL)
    self->on_leave (context, self->data);
}

static GumInvocationListener *
gum_make_invocation_listener (GumInvocationCallback on_enter,
                              GumInvocationCallback on_leave,
                              gpointer data,
                              GDestroyNotify data_destroy)
{
  GumInvocationListener * listener;

  listener = g_new (GumInvocationListener, 1);
  listener->parent.ref_count = 1;
  listener->parent.finalize = gum_invocation_listener_finalize;
  listener->on_enter = on_enter;
  listener->on_leave = on_leave;
  listener->data = data;
  listener->data_destroy = data_destroy;

  return listener;
}

static void
gum_invocation_listener_finalize (GumObject * object)
{
  GumInvocationListener * self = GUM_INVOCATION_LISTENER (object);

  if (self->data_destroy != NULL)
    self->data_destroy (self->data);
}

static void
gum_invocation_listener_dummy_callback (GumInvocationContext * context,
                                        gpointer user_data)
{
}

#endif

"""

```