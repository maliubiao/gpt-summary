Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request is to analyze `gumv8eventsink.cpp`, focusing on its functionality, relation to reverse engineering, interaction with low-level concepts, logical inferences, potential user errors, and how users reach this code.

2. **High-Level Overview:**  First, skim the code to get a general idea. Notice the inclusion of headers like `gumv8scope.h`, `gumv8value.h`, `glib.h`, and `gumspinlock.h`. This suggests interaction with V8 (JavaScript engine), GLib (a general-purpose utility library), and Frida's own components. The presence of `GumEvent` and `GumCpuContext` indicates this file is involved in event handling within Frida.

3. **Identify the Core Structures:**  Pay close attention to the defined structs: `_GumV8JSEventSink` and `_GumV8NativeEventSink`. These are the primary data structures this file manipulates. Note their members:
    * `_GumV8JSEventSink`:  Manages a queue of events, interacts with the V8 engine, uses a spinlock for thread safety, and handles callbacks to JavaScript.
    * `_GumV8NativeEventSink`: A simpler structure for handling events via a native C callback.

4. **Analyze Function by Function (Initial Pass):** Go through each function and understand its purpose. Focus on the key actions:
    * `gum_v8_event_sink_new`: Creates either a JS or native event sink based on the `options`. This is a crucial entry point.
    * `gum_v8_js_event_sink_iface_init` and `gum_v8_native_event_sink_iface_init`: Implement the `GumEventSink` interface, defining how these sinks behave.
    * `gum_v8_js_event_sink_process`: Adds events to the queue.
    * `gum_v8_native_event_sink_process`:  Directly calls the native callback.
    * `gum_v8_js_event_sink_drain`: Processes the event queue and invokes JavaScript callbacks.
    * `gum_v8_js_event_sink_start`/`stop`: Manage the event processing loop.
    * `gum_v8_js_event_sink_flush`: Forces immediate processing of the queue.
    * `gum_v8_js_event_sink_query_mask`: Returns the event mask.

5. **Connect to Frida Concepts:**  Start linking the functions and data structures to Frida's overall architecture. Think about:
    * **Instrumentation:** How does this code facilitate instrumenting target processes? The event sinks are where the *results* of instrumentation (events) are delivered.
    * **JavaScript Bridge:** The "JS" event sink clearly involves communication between the Frida agent (JavaScript) and the Gum core (C++).
    * **Native Callbacks:** The "native" event sink provides an alternative for C/C++-based agents.
    * **Event Types:**  Recognize that `GumEvent` likely represents different types of instrumentation events (e.g., function calls, memory access).
    * **Thread Safety:** The spinlock highlights the need for thread-safe event handling.

6. **Address Specific Questions (Second Pass - More Detailed):** Now, go back through the code with the specific questions from the prompt in mind:

    * **Functionality:**  Summarize the core responsibilities of each sink type.
    * **Reverse Engineering:** Consider *how* this code is used in reverse engineering. The events being captured are the raw data used for analysis. Think about hooking functions and tracing execution.
    * **Low-Level Details:** Look for interactions with the OS and hardware:
        * **Binary Level:**  The `GumEvent` structure itself likely contains raw memory addresses and data. The `on_call_summary` processing demonstrates aggregation of call targets.
        * **Linux/Android Kernel/Framework:**  Frida operates within the address space of the target process, so understanding process memory, function calls, and potentially even system calls is relevant.
    * **Logical Inference:** Analyze the `gum_v8_js_event_sink_drain` function. Trace the data flow: events are queued, then processed in batches, and finally passed to JavaScript callbacks. Consider the conditions under which `frequencies` are calculated.
    * **User Errors:** Think about common mistakes developers might make when using Frida:
        * Incorrect event mask.
        * Issues with the JavaScript callback function.
        * Queue overflow (though this code tries to prevent it).
    * **User Journey (Debugging):** Imagine a user setting a breakpoint or hook. How does that trigger events, and how do those events end up in this code?  Start from the JavaScript API and trace down through Frida's internals.

7. **Structure the Explanation:** Organize the findings into logical sections based on the prompt's questions. Use clear headings and bullet points for readability. Provide code snippets where necessary to illustrate points.

8. **Refine and Elaborate:** Review the explanation for clarity and completeness. Add details and examples where needed. For instance, when discussing reverse engineering, give concrete examples of what kind of information the events might contain.

9. **Self-Correction/Improvements:**  During the process, you might realize you missed something or made an incorrect assumption. For example, you might initially think the queue *never* overflows, but then notice the check `self->queue->len != self->queue_capacity` and understand that events are dropped if the queue is full. Refine your explanation accordingly. Similarly, ensure you clearly distinguish between the JS and native event sink paths.

By following these steps, you can systematically analyze the code and generate a comprehensive and accurate explanation that addresses all aspects of the request. The key is to move from a high-level understanding to a detailed analysis, constantly connecting the code to the broader context of Frida and reverse engineering.
好的，让我们来详细分析一下 `gumv8eventsink.cpp` 文件的功能和相关知识点。

**文件功能概述**

`gumv8eventsink.cpp` 文件的核心功能是 **定义了 Frida-gum 中用于接收和处理来自 instrumentation 代码产生的事件的“接收器”（Sink）**。  它提供了两种主要的事件接收机制：

1. **JavaScript 事件接收器 (`GumV8JSEventSink`)**:  将事件数据传递给在 Frida agent (JavaScript) 中定义的 JavaScript 回调函数。
2. **原生 C++ 事件接收器 (`GumV8NativeEventSink`)**: 将事件数据传递给原生 C++ 函数。

简单来说，当 Frida instrument 目标进程时，例如 hook 了一个函数，当被 hook 的函数被调用时，Frida 会生成一个事件（例如 `GumCallEvent`）。 `gumv8eventsink.cpp` 中定义的类负责接收这些事件，并将它们传递到用户预先设定的处理逻辑中。

**与逆向方法的关系及举例说明**

这个文件直接服务于动态逆向分析的核心需求：**观察和控制目标程序的运行时行为**。

* **Hook 函数并捕获调用信息：** 通过 Frida 提供的 API，用户可以 hook 目标进程中的函数。当这些被 hook 的函数被调用时，Frida-gum 会生成 `GUM_CALL` 类型的事件。`GumV8JSEventSink` 或 `GumV8NativeEventSink` 会接收到这些事件，其中包含了被调用函数的地址、参数、返回值等信息。逆向工程师可以利用这些信息来理解函数的用途、参数意义以及程序执行流程。

    **举例：**  假设你想知道 `malloc` 函数在目标程序中的调用情况。你可以编写 Frida 脚本 hook `malloc` 函数，并在 JavaScript 回调函数中打印出 `malloc` 被调用的次数、每次分配的大小以及返回的内存地址。`GumV8JSEventSink` 负责将 `GUM_CALL` 事件（包含 `malloc` 的调用信息）传递到你的 JavaScript 回调函数。

* **跟踪内存访问：** Frida 还可以用于监控特定内存区域的读写操作。当发生内存访问时，会生成相应的事件（例如 `GUM_MEM_ACCESS`）。事件接收器可以将这些信息传递给用户，帮助逆向工程师理解数据在内存中的流转和修改情况。

    **举例：**  你想监控一个全局变量的值何时被修改以及修改后的值。你可以使用 Frida 的内存监控功能，当该变量被写入时，`GumV8JSEventSink` 会将包含内存地址、写入值等信息的事件发送到你的 JavaScript 回调函数。

**涉及的二进制底层、Linux/Android 内核及框架知识**

这个文件虽然是用 C++ 编写，并且操作的是 Frida-gum 框架，但其背后的运作涉及不少底层知识：

* **二进制底层:**
    * **内存地址:** 事件中包含大量的内存地址，例如函数地址、数据地址等。理解这些地址的意义，需要对目标程序的内存布局有一定的了解。
    * **函数调用约定 (Calling Convention):** 当 hook 函数时，Frida 需要理解目标平台的函数调用约定，以便正确地获取函数参数和返回值。`GumCpuContext` 结构体就包含了 CPU 的寄存器状态，这与调用约定密切相关。
    * **指令集架构 (ISA):**  虽然代码本身没有直接操作机器码，但 Frida-gum 的实现需要考虑目标平台的指令集架构，以便进行代码注入和 hook 操作。

* **Linux/Android 内核及框架:**
    * **进程和线程:** Frida 运行在目标进程的上下文中，需要理解进程和线程的概念，以及它们之间的关系。事件的产生和处理都发生在特定的进程和线程中。
    * **共享库 (Shared Libraries):**  目标程序通常会加载多个共享库。Hook 这些库中的函数需要理解共享库的加载和链接机制。
    * **系统调用 (System Calls):** 目标程序会通过系统调用与操作系统内核交互。Frida 可以 hook 系统调用，从而监控程序的底层行为。
    * **Android 特有的知识:** 在 Android 平台上，Frida 需要与 ART (Android Runtime) 或 Dalvik 虚拟机交互，才能 hook Java 代码。这涉及到对 ART/Dalvik 内部机制的理解。

**逻辑推理及假设输入与输出**

让我们关注 `gum_v8_js_event_sink_drain` 函数，这个函数负责将累积的事件发送到 JavaScript 回调函数。

**假设输入：**

1. `self->queue` 中积累了一批 `GumEvent` 结构体，包含不同类型的事件，例如 `GUM_CALL` 事件和可能的其他事件。
2. `self->on_receive` 指向一个 JavaScript 函数的 `Global` 句柄，该函数期望接收一个 `ArrayBuffer` 作为参数。
3. `self->on_call_summary` 指向一个 JavaScript 函数的 `Global` 句柄，该函数期望接收一个包含函数调用频率信息的 JavaScript 对象作为参数。
4. `options->queue_drain_interval` 被设置为一个非零值，导致定时调用 `gum_v8_js_event_sink_drain`。

**逻辑推理：**

1. 函数首先检查 `self->core` 是否为空，如果为空则直接返回。
2. 获取 `self->queue` 中的事件数量 `len` 和总大小 `size`。
3. 如果 `len` 大于 0，则复制 `self->queue` 中的事件数据到 `buffer` 中。
4. 使用自旋锁保护，清空 `self->queue`。
5. 如果 `self->on_call_summary` 不为空，则遍历 `buffer` 中的事件，统计 `GUM_CALL` 事件中 `target` (被调用函数地址) 的频率，并将结果存储在 `frequencies` 哈希表中。
6. 创建一个 JavaScript 对象 `summary`，并将 `frequencies` 中的函数地址和调用次数添加到 `summary` 对象中。
7. 调用 `self->on_call_summary` 指向的 JavaScript 函数，将 `summary` 对象作为参数传递。
8. 如果 `self->on_receive` 不为空，则创建一个包含 `buffer` 内容的 `ArrayBuffer`。
9. 调用 `self->on_receive` 指向的 JavaScript 函数，将 `ArrayBuffer` 作为参数传递。
10. 释放 `buffer` 的内存。

**假设输出：**

1. 如果 `self->on_call_summary` 存在，JavaScript 端会收到一个类似 `{ "0x12345678": 10, "0x9abcdef0": 5 }` 的对象，表示地址 `0x12345678` 的函数被调用了 10 次，地址 `0x9abcdef0` 的函数被调用了 5 次。
2. 如果 `self->on_receive` 存在，JavaScript 端会收到一个 `ArrayBuffer`，其内容是所有捕获到的事件数据的二进制表示。JavaScript 代码需要解析这个 `ArrayBuffer` 来获取具体的事件信息。

**涉及用户或编程常见的使用错误及举例说明**

* **JavaScript 回调函数错误:**
    * **未定义或抛出异常:** 如果用户在 JavaScript 中提供的 `on_receive` 或 `on_call_summary` 函数中发生错误（例如，未定义变量、类型错误），Frida-gum 会捕获这些异常，但可能导致事件处理中断或数据丢失。
        **举例：**  用户定义的 `on_receive` 函数尝试访问一个不存在的对象的属性，导致 JavaScript 抛出异常。Frida 会记录这个异常，但后续的事件可能无法正常处理。
    * **参数类型不匹配:**  如果 JavaScript 回调函数期望接收的参数类型与 Frida-gum 传递的类型不符，可能会导致错误。
        **举例：**  用户定义的 `on_receive` 函数期望接收一个 JSON 对象，但 Frida-gum 传递的是一个 `ArrayBuffer`。JavaScript 代码可能无法正确解析。

* **事件掩码配置错误:**
    * **设置了错误的 `event_mask`:** 用户在创建 `GumV8EventSink` 时需要指定 `event_mask` 来过滤感兴趣的事件类型。如果配置错误，可能导致用户接收不到期望的事件，或者接收到过多的无关事件。
        **举例：**  用户只想监听函数调用事件 (`GUM_EVENT_CALL`)，但 `event_mask` 设置为了监听所有事件 (`GUM_EVENT_MASK_ALL`)，导致 JavaScript 回调函数接收到大量的内存访问事件，影响性能。

* **队列容量配置不当:**
    * **`queue_capacity` 过小:** 如果事件产生速度过快，而事件队列的容量太小，可能会导致事件被丢弃。
        **举例：**  目标程序在一个循环中频繁调用某个被 hook 的函数，导致事件产生速度超过了队列的处理速度和容量，部分函数调用事件可能会丢失。

* **资源泄漏:**
    * **在原生回调中未正确管理 `user_data`:** 如果使用原生 C++ 事件接收器，用户需要在 `options->user_data` 中传递自定义数据。如果在使用完毕后没有正确释放这部分内存，可能会导致资源泄漏。

**用户操作是如何一步步的到达这里，作为调试线索**

以下是一个用户操作的典型流程，最终会涉及到 `gumv8eventsink.cpp`：

1. **编写 Frida 脚本 (JavaScript):** 用户使用 Frida 的 JavaScript API 来定义 instrumentation 逻辑。例如，使用 `Interceptor.attach` 来 hook 目标函数，并提供一个回调函数来处理 hook 事件。
   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'malloc'), {
     onEnter: function (args) {
       console.log('malloc called with size: ' + args[0]);
     },
     onLeave: function (retval) {
       console.log('malloc returned: ' + retval);
     }
   });
   ```

2. **运行 Frida 脚本:** 用户使用 Frida 命令行工具或 API 将脚本注入到目标进程中。
   ```bash
   frida -p <process_id> -l your_script.js
   ```

3. **Frida-gum 的介入:** 当目标进程执行到被 hook 的 `malloc` 函数时，Frida-gum 的 Interceptor 组件会捕获到这次调用。

4. **事件生成:** Frida-gum 根据 hook 的配置和执行情况，生成一个 `GumCallEvent` 类型的事件，其中包含了 `malloc` 的参数和当时的 CPU 上下文等信息。

5. **事件路由:**  Frida-gum 需要将生成的事件发送到用户提供的处理逻辑。这涉及到选择合适的事件接收器。如果用户在 JavaScript 中使用了 `Interceptor.attach`，Frida-gum 会创建一个 `GumV8JSEventSink` 实例。

6. **`gum_v8_js_event_sink_process`:**  生成的 `GumCallEvent` 会被传递到 `gum_v8_js_event_sink_process` 函数。该函数会将事件添加到 `GumV8JSEventSink` 的内部队列 `queue` 中。

7. **事件刷新 (可选):**
   * **定时刷新:** 如果创建 `GumV8JSEventSink` 时设置了 `queue_drain_interval`，则会定时调用 `gum_v8_js_event_sink_drain` 函数。
   * **手动刷新:** 用户也可以通过 Frida API 手动刷新事件队列。

8. **`gum_v8_js_event_sink_drain`:**  当事件队列需要被处理时，`gum_v8_js_event_sink_drain` 函数会被调用。它会将队列中的事件数据转换为 `ArrayBuffer`，并调用用户在 JavaScript 中提供的 `onEnter` 和 `onLeave` 回调函数。

9. **JavaScript 回调执行:**  JavaScript 引擎 (V8) 执行用户提供的回调函数，并将事件数据作为参数传递进去。在上面的例子中，`console.log` 会将调用信息输出到 Frida 的控制台。

**调试线索:**

当遇到 Frida 脚本无法正常工作或没有接收到预期事件时，可以从以下几个方面着手调试，并可能涉及到 `gumv8eventsink.cpp` 中的逻辑：

* **检查 `event_mask`:** 确保设置的事件掩码包含了你想要监听的事件类型。
* **检查 JavaScript 回调函数:** 确保回调函数没有错误，并且能够正确处理接收到的事件数据。可以使用 `try-catch` 块来捕获 JavaScript 异常。
* **查看 Frida 的错误日志:** Frida 通常会输出一些错误信息，可以帮助定位问题。
* **分析事件队列行为:**  如果怀疑事件丢失，可以尝试增加 `queue_capacity` 或减小 `queue_drain_interval`，或者手动调用刷新方法。
* **使用原生回调排查:** 如果 JavaScript 端出现问题，可以尝试使用原生 C++ 事件接收器来验证事件是否被正确生成和传递。

总而言之，`gumv8eventsink.cpp` 是 Frida-gum 中至关重要的一个组件，它负责将 instrumentation 的结果（事件）传递给用户定义的处理逻辑，是连接 Frida 核心功能和用户接口的关键桥梁。理解其工作原理有助于更深入地理解 Frida 的运作机制，并能更好地进行动态逆向分析和调试。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8eventsink.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 Alex Soler <asoler@nowsecure.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8eventsink.h"

#include "gumv8scope.h"
#include "gumv8value.h"

#include <glib/gprintf.h>
#include <gum/gumspinlock.h>
#include <string.h>

using namespace v8;

struct _GumV8JSEventSink
{
  GObject parent;

  GumSpinlock lock;
  GArray * queue;
  guint queue_capacity;
  guint queue_drain_interval;

  GumV8Core * core;
  GMainContext * main_context;
  GumEventType event_mask;
  Global<Function> * on_receive;
  Global<Function> * on_call_summary;
  GSource * source;
};

struct _GumV8NativeEventSink
{
  GObject parent;

  GumEventType event_mask;
  GumV8OnEvent on_event;
  gpointer user_data;
};

static void gum_v8_js_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_js_event_sink_dispose (GObject * obj);
static void gum_v8_js_event_sink_finalize (GObject * obj);
static GumEventType gum_v8_js_event_sink_query_mask (GumEventSink * sink);
static void gum_v8_js_event_sink_start (GumEventSink * sink);
static void gum_v8_js_event_sink_process (GumEventSink * sink,
    const GumEvent * event, GumCpuContext * cpu_context);
static void gum_v8_js_event_sink_flush (GumEventSink * sink);
static void gum_v8_js_event_sink_stop (GumEventSink * sink);
static gboolean gum_v8_js_event_sink_stop_when_idle (GumV8JSEventSink * self);
static gboolean gum_v8_js_event_sink_drain (GumV8JSEventSink * self);

static void gum_v8_native_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumEventType gum_v8_native_event_sink_query_mask (GumEventSink * sink);
static void gum_v8_native_event_sink_process (GumEventSink * sink,
    const GumEvent * event, GumCpuContext * cpu_context);

G_DEFINE_TYPE_EXTENDED (GumV8JSEventSink,
                        gum_v8_js_event_sink,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_EVENT_SINK,
                            gum_v8_js_event_sink_iface_init))

G_DEFINE_TYPE_EXTENDED (GumV8NativeEventSink,
                        gum_v8_native_event_sink,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_EVENT_SINK,
                            gum_v8_native_event_sink_iface_init))

GumEventSink *
gum_v8_event_sink_new (const GumV8EventSinkOptions * options)
{
  if (options->on_event != NULL)
  {
    auto sink = GUM_V8_NATIVE_EVENT_SINK (
        g_object_new (GUM_V8_TYPE_NATIVE_EVENT_SINK, NULL));

    sink->event_mask = options->event_mask;
    sink->on_event = options->on_event;
    sink->user_data = options->user_data;

    return GUM_EVENT_SINK (sink);
  }
  else
  {
    auto isolate = options->core->isolate;

    auto sink = GUM_V8_JS_EVENT_SINK (
        g_object_new (GUM_V8_TYPE_JS_EVENT_SINK, NULL));

    sink->queue = g_array_sized_new (FALSE, FALSE, sizeof (GumEvent),
        options->queue_capacity);
    sink->queue_capacity = options->queue_capacity;
    sink->queue_drain_interval = options->queue_drain_interval;

    g_object_ref (options->core->script);
    sink->core = options->core;
    sink->main_context = options->main_context;
    sink->event_mask = options->event_mask;
    if (!options->on_receive.IsEmpty ())
    {
      sink->on_receive =
          new Global<Function> (isolate, options->on_receive);
    }
    if (!options->on_call_summary.IsEmpty ())
    {
      sink->on_call_summary =
          new Global<Function> (isolate, options->on_call_summary);
    }

    return GUM_EVENT_SINK (sink);
  }
}

static void
gum_v8_js_event_sink_class_init (GumV8JSEventSinkClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_js_event_sink_dispose;
  object_class->finalize = gum_v8_js_event_sink_finalize;
}

static void
gum_v8_js_event_sink_iface_init (gpointer g_iface,
                                 gpointer iface_data)
{
  auto iface = (GumEventSinkInterface *) g_iface;

  iface->query_mask = gum_v8_js_event_sink_query_mask;
  iface->start = gum_v8_js_event_sink_start;
  iface->process = gum_v8_js_event_sink_process;
  iface->flush = gum_v8_js_event_sink_flush;
  iface->stop = gum_v8_js_event_sink_stop;
}

static void
gum_v8_js_event_sink_init (GumV8JSEventSink * self)
{
  gum_spinlock_init (&self->lock);
}

static void
gum_v8_js_event_sink_release_core (GumV8JSEventSink * self)
{
  GumV8Core * core = (GumV8Core *) g_steal_pointer (&self->core);
  if (core == NULL)
    return;

  auto script = core->script;

  {
    ScriptScope scope (script);

    delete self->on_receive;
    self->on_receive = nullptr;

    delete self->on_call_summary;
    self->on_call_summary = nullptr;
  }

  g_object_unref (script);
}

static void
gum_v8_js_event_sink_dispose (GObject * obj)
{
  gum_v8_js_event_sink_release_core (GUM_V8_JS_EVENT_SINK (obj));

  G_OBJECT_CLASS (gum_v8_js_event_sink_parent_class)->dispose (obj);
}

static void
gum_v8_js_event_sink_finalize (GObject * obj)
{
  auto self = GUM_V8_JS_EVENT_SINK (obj);

  g_assert (self->source == NULL);

  g_array_free (self->queue, TRUE);

  G_OBJECT_CLASS (gum_v8_js_event_sink_parent_class)->finalize (obj);
}

static GumEventType
gum_v8_js_event_sink_query_mask (GumEventSink * sink)
{
  return GUM_V8_JS_EVENT_SINK (sink)->event_mask;
}

static void
gum_v8_js_event_sink_start (GumEventSink * sink)
{
  auto self = GUM_V8_JS_EVENT_SINK (sink);

  if (self->queue_drain_interval != 0)
  {
    self->source = g_timeout_source_new (self->queue_drain_interval);
    g_source_set_callback (self->source,
        (GSourceFunc) gum_v8_js_event_sink_drain, g_object_ref (self),
        g_object_unref);
    g_source_attach (self->source, self->main_context);
  }
}

static void
gum_v8_js_event_sink_process (GumEventSink * sink,
                              const GumEvent * event,
                              GumCpuContext * cpu_context)
{
  auto self = GUM_V8_JS_EVENT_SINK_CAST (sink);

  gum_spinlock_acquire (&self->lock);
  if (self->queue->len != self->queue_capacity)
    g_array_append_val (self->queue, *event);
  gum_spinlock_release (&self->lock);
}

static void
gum_v8_js_event_sink_flush (GumEventSink * sink)
{
  auto self = GUM_V8_JS_EVENT_SINK (sink);

  if (self->core == NULL)
    return;

  gum_v8_js_event_sink_drain (self);
}

static void
gum_v8_js_event_sink_stop (GumEventSink * sink)
{
  auto self = GUM_V8_JS_EVENT_SINK (sink);

  if (g_main_context_is_owner (self->main_context))
  {
    gum_v8_js_event_sink_stop_when_idle (self);
  }
  else
  {
    auto source = g_idle_source_new ();
    g_source_set_callback (source,
        (GSourceFunc) gum_v8_js_event_sink_stop_when_idle, g_object_ref (self),
        g_object_unref);
    g_source_attach (source, self->main_context);
    g_source_unref (source);
  }
}

static gboolean
gum_v8_js_event_sink_stop_when_idle (GumV8JSEventSink * self)
{
  gum_v8_js_event_sink_drain (self);

  g_object_ref (self);

  if (self->source != NULL)
  {
    g_source_destroy (self->source);
    g_source_unref (self->source);
    self->source = NULL;
  }

  gum_v8_js_event_sink_release_core (self);

  g_object_unref (self);

  return FALSE;
}

static gboolean
gum_v8_js_event_sink_drain (GumV8JSEventSink * self)
{
  gpointer buffer = NULL;
  guint len, size;

  auto core = self->core;
  if (core == NULL)
    return FALSE;

  len = self->queue->len;
  size = len * sizeof (GumEvent);
  if (len != 0)
  {
    buffer = g_memdup2 (self->queue->data, size);

    gum_spinlock_acquire (&self->lock);
    g_array_remove_range (self->queue, 0, len);
    gum_spinlock_release (&self->lock);
  }

  if (buffer != NULL)
  {
    GHashTable * frequencies = NULL;

    if (self->on_call_summary != nullptr)
    {
      frequencies = g_hash_table_new (NULL, NULL);

      auto ev = (GumCallEvent *) buffer;
      for (guint i = 0; i != len; i++)
      {
        if (ev->type == GUM_CALL)
        {
          auto count = GPOINTER_TO_SIZE (
              g_hash_table_lookup (frequencies, ev->target));
          count++;
          g_hash_table_insert (frequencies, ev->target,
              GSIZE_TO_POINTER (count));
        }

        ev++;
      }
    }

    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();
    auto recv = Undefined (isolate);

    if (frequencies != NULL)
    {
      auto summary = Object::New (isolate);

      GHashTableIter iter;
      g_hash_table_iter_init (&iter, frequencies);
      gpointer target, count;
      gchar target_str[32];
      while (g_hash_table_iter_next (&iter, &target, &count))
      {
        g_sprintf (target_str, "0x%" G_GSIZE_MODIFIER "x",
            GPOINTER_TO_SIZE (target));
        _gum_v8_object_set (summary, target_str,
            Number::New (isolate, GPOINTER_TO_SIZE (count)), core);
      }

      g_hash_table_unref (frequencies);

      Local<Value> argv[] = { summary };
      auto on_call_summary =
          Local<Function>::New (isolate, *self->on_call_summary);
      auto result =
          on_call_summary->Call (context, recv, G_N_ELEMENTS (argv), argv);
      if (result.IsEmpty ())
        scope.ProcessAnyPendingException ();
    }

    if (self->on_receive != nullptr)
    {
      auto on_receive = Local<Function>::New (isolate, *self->on_receive);
      Local<Value> argv[] = {
        _gum_v8_array_buffer_new_take (isolate, g_steal_pointer (&buffer),
            size),
      };
      auto result = on_receive->Call (context, recv, G_N_ELEMENTS (argv), argv);
      if (result.IsEmpty ())
        scope.ProcessAnyPendingException ();
    }

    g_free (buffer);
  }

  return TRUE;
}

static void
gum_v8_native_event_sink_class_init (GumV8NativeEventSinkClass * klass)
{
}

static void
gum_v8_native_event_sink_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  auto iface = (GumEventSinkInterface *) g_iface;

  iface->query_mask = gum_v8_native_event_sink_query_mask;
  iface->process = gum_v8_native_event_sink_process;
}

static void
gum_v8_native_event_sink_init (GumV8NativeEventSink * self)
{
}

static GumEventType
gum_v8_native_event_sink_query_mask (GumEventSink * sink)
{
  return GUM_V8_NATIVE_EVENT_SINK (sink)->event_mask;
}

static void
gum_v8_native_event_sink_process (GumEventSink * sink,
                                  const GumEvent * event,
                                  GumCpuContext * cpu_context)
{
  auto self = GUM_V8_NATIVE_EVENT_SINK_CAST (sink);

  self->on_event (event, cpu_context, self->user_data);
}
```