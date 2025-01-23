Response:
The user wants a summary of the functionalities of the C code provided for `gumquickstalker.c`. I need to analyze the code to identify its core features and how they relate to dynamic instrumentation, reverse engineering, and low-level system interactions.

Here's a breakdown of how to approach this:

1. **Identify Core Structures:** Look for `struct` definitions as they represent the fundamental data organization.
2. **Analyze Functions:** Examine the declared and defined functions to understand the actions the code performs. Pay close attention to functions prefixed with `gumjs_` as these are likely JavaScript bindings.
3. **Look for Interactions with Frida Core:** Identify usage of types and functions from the `gum` library (e.g., `GumStalker`, `GumEvent`, `GumCpuContext`).
4. **Connect to Reverse Engineering Concepts:**  See if functionalities relate to tracing execution, inspecting memory, or manipulating program flow.
5. **Identify System-Level Interactions:** Look for mentions of threads, memory ranges, and potentially OS-specific APIs (though less evident in this snippet).
6. **Infer Logic and Potential Issues:** Based on the function names and parameters, try to deduce the intended logic and potential user errors.
7. **Trace User Flow (Hypothetically):**  Imagine how a user interacting with the Frida API might trigger actions that eventually lead to this C code being executed.

**Mental Checklist & Confidence Score:**

* List functionalities? Yes.
* Relationship to reverse engineering? Yes.
* Examples for reverse engineering? Yes.
* Binary/OS/Kernel/Framework involvement? Yes.
* Examples for binary/OS/Kernel/Framework? Yes.
* Logical reasoning? Yes.
* Hypothesis for input/output? Yes.
* Common usage errors? Yes.
* Example for common usage errors? Yes.
* User operation to reach here? Yes.
* As debugging clue? Yes.
* Summarize functionalities? Yes.

Confidence Score: 5/5 -  The code structure and naming conventions are quite informative, making it possible to infer most of the intended functionalities.
这是 `frida/subprojects/frida-gum/bindings/gumjs/gumquickstalker.c` 文件的第 1 部分，该文件是 Frida 动态instrumentation 工具的一部分。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：程序执行追踪与拦截 (Stalking)**

这个文件的主要目的是实现 Frida 的 "Stalker" 功能，它允许用户追踪目标进程的执行流程，包括执行的代码块、函数调用和返回等事件。 `gumquickstalker.c` 提供了将底层的 Stalker 功能暴露给 JavaScript 环境的桥梁。

**具体功能点：**

1. **Stalker 实例管理:**
   - 维护一个 `GumStalker` 实例 (`self->stalker`)，这是 Frida 底层执行追踪的核心对象。
   - 提供了获取和创建 `GumStalker` 实例的方法 (`_gum_quick_stalker_get`).

2. **执行追踪控制:**
   - `follow(thread_id, transformer_callback, ...)`:  允许开始追踪指定线程的执行。
   - `unfollow(thread_id)`: 停止追踪指定线程的执行。
   - `flush()`: 强制刷新 Stalker 的内部缓冲区，确保所有追踪到的事件都被处理。
   - `garbageCollect()`: 触发 Stalker 的垃圾回收机制，释放不再使用的资源。
   - `exclude(base, size)`:  排除指定内存范围的代码执行追踪。
   - `invalidate(address)` 或 `invalidate(thread_id, address)`:  使缓存中与指定地址相关的追踪信息失效。

3. **执行事件处理 (通过 Transformer 和 Sink):**
   - **Transformer (`GumQuickTransformer`):**
     - 允许用户自定义 JavaScript 回调函数 (`callback`)，在追踪到的代码块执行前被调用。
     - 提供了一种机制，可以将底层的执行信息转换为 JavaScript 可以理解的数据结构。
   - **Sink (`GumQuickEventSink`):**
     -  负责接收 Stalker 产生的执行事件。
     -  将这些事件传递到 JavaScript 环境进行处理 (虽然这部分的代码不在本段，但可以推断其存在)。

4. **函数调用探测 (Call Probes):**
   - `addCallProbe(target_address, callback)`:  允许在指定的函数入口地址设置探测点，当程序执行到该地址时，会触发 JavaScript 回调函数。
   - `removeCallProbe(id)`:  移除之前设置的调用探测点。

5. **迭代器 (Iterators):**
   - 提供了两种迭代器 (`GumQuickDefaultIterator` 和 `GumQuickSpecialIterator`) 用于遍历追踪到的指令。
   - 这些迭代器允许 JavaScript 代码逐条检查执行的指令，并进行相应的操作，例如插入额外的代码 (Callout) 或修改执行流程 (Chaining Return)。

6. **配置选项:**
   - `trustThreshold`: 设置 Stalker 信任代码的阈值 (可能用于优化追踪性能)。
   - `queueCapacity`:  设置 Stalker 内部事件队列的容量。
   - `queueDrainInterval`: 设置 Stalker 刷新事件队列的间隔。

7. **事件解析 (`parse`):**
   - 提供了一个 `parse` 函数，可以将 Stalker 产生的原始事件数据 (以二进制 ArrayBuffer 的形式) 解析成 JavaScript 对象数组，方便用户分析。

**与逆向方法的关系及举例说明：**

* **动态代码追踪:**  Stalker 的核心功能就是动态代码追踪。逆向工程师可以使用 `follow` 函数来监控目标进程的执行流程，了解程序的运行路径。
    * **举例:**  逆向一个恶意软件时，可以使用 Stalker 追踪其执行的函数调用序列，从而找到恶意行为发生的关键位置。
* **函数调用拦截与分析:**  `addCallProbe` 允许在特定函数入口处设置断点，并执行自定义的 JavaScript 代码。这可以用于分析函数的参数、返回值，甚至修改函数的行为。
    * **举例:**  逆向一个加密算法时，可以在加密函数的入口处设置 Call Probe，记录传递给该函数的明文数据，从而分析加密过程。
* **代码块执行分析:** 通过 Transformer 和迭代器，可以分析程序执行的每个代码块，甚至是每条指令。
    * **举例:**  在分析一个漏洞利用时，可以追踪程序执行到特定内存地址范围内的代码，观察程序状态的变化，定位漏洞触发点。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **二进制代码:** Stalker 追踪的是实际执行的二进制代码，因此需要理解目标架构 (例如 ARM, x86) 的指令集。
    * **举例:**  `gum_stalker_iterator_next` 函数会返回下一条执行的指令，这需要理解二进制指令的格式和长度。
* **内存地址:**  Stalker 操作的核心是内存地址，例如追踪的起始地址、排除的地址范围、函数调用的目标地址等。
    * **举例:** `exclude(base, size)` 函数需要指定内存范围的起始地址 (`base`) 和大小 (`size`)。
* **线程 ID (`GumThreadId`):**  Stalker 可以针对特定的线程进行追踪，这需要理解操作系统中线程的概念和标识。
    * **举例:** `follow(thread_id, ...)` 函数需要指定要追踪的线程 ID。
* **函数调用约定:**  `addCallProbe` 需要知道目标函数的入口地址，并理解目标平台的函数调用约定 (例如参数如何传递、返回值如何处理)。
    * **举例:**  设置 Call Probe 后，回调函数的触发时机与目标函数的调用约定密切相关。
* **事件结构 (`GumEvent`):**  `parse` 函数处理的 `GumEvent` 结构体包含了底层的执行事件信息，这需要理解 Frida 底层是如何表示这些事件的。

**逻辑推理、假设输入与输出：**

假设用户执行以下 JavaScript 代码：

```javascript
Stalker.follow({
  onCall: function (context) {
    console.log("Function call at:", context.target);
  }
});
```

* **假设输入:**  目标进程正在执行代码，并且触发了一个函数调用。
* **逻辑推理:**
    1. `Stalker.follow` 函数被调用，设置了一个 Transformer 回调。
    2. Frida 底层的 Stalker 捕捉到了一个函数调用事件。
    3. `gumquickstalker.c` 中的相关逻辑会将这个事件传递到 JavaScript 环境。
    4. 定义的 `onCall` 回调函数被执行。
* **预期输出:**  控制台上会打印出 "Function call at:" 以及被调用函数的地址。

**涉及用户或者编程常见的使用错误及举例说明：**

* **追踪过多线程:**  如果用户追踪过多的线程，可能会导致性能问题，因为 Stalker 需要处理大量的执行事件。
    * **举例:**  在多线程程序中，不加选择地追踪所有线程可能会导致 CPU 占用率过高。
* **Transformer 回调中执行耗时操作:**  Transformer 回调是在目标进程执行路径上被调用的，如果在回调中执行过于耗时的操作，会影响目标进程的性能甚至导致死锁。
    * **举例:**  在 Transformer 回调中进行大量的字符串操作或网络请求。
* **未正确释放资源:**  虽然代码中使用了 `g_object_unref` 和 `JS_FreeValue` 等函数来管理资源，但用户如果自定义了回调函数，需要注意避免内存泄漏。
* **错误的内存地址或大小:** 在使用 `exclude` 函数时，如果提供的内存地址或大小不正确，可能会导致意外的追踪行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:** 用户首先编写 JavaScript 代码，使用 `Stalker` 对象及其方法，例如 `Stalker.follow()`, `Stalker.addCallProbe()` 等。
2. **Frida 将 JavaScript 转换为 Gum 代码:** Frida 框架会将用户编写的 JavaScript 代码转换成 Gum (Frida 的底层引擎) 可以理解的指令。
3. **调用 `gumjs_stalker_follow` 等函数:**  JavaScript 中对 `Stalker.follow()` 的调用会最终映射到 `gumquickstalker.c` 文件中的 `gumjs_stalker_follow` 函数。
4. **`gumjs_stalker_follow` 调用底层 Gum API:**  `gumjs_stalker_follow` 函数会调用 Frida 底层的 Gum API，例如 `gum_stalker_follow()`, `gum_stalker_transformer_make_from_callback()`, `gum_quick_event_sink_new()` 等。
5. **Stalker 开始工作:** 底层的 Stalker 模块开始监控目标进程的执行，并将事件传递给配置的 Transformer 和 Sink。
6. **Transformer 回调执行:** 当 Stalker 追踪到符合条件的事件时，例如代码块执行或函数调用，与该 Stalker 关联的 Transformer 回调函数 (在 JavaScript 中定义) 会被执行。
7. **调试线索:** 如果用户在 Frida 脚本中设置了断点或者输出了日志，那么当程序执行到 `gumquickstalker.c` 中的代码时，这些断点或日志信息可以帮助用户理解 Frida 的内部工作流程以及脚本的执行情况。例如，可以在 `gumjs_stalker_follow` 函数入口处设置断点，查看传递的参数，验证 JavaScript 代码的调用是否正确。

**归纳其功能 (第 1 部分):**

总而言之，`gumquickstalker.c` (第 1 部分) 的主要功能是 **为 Frida 的 JavaScript API 提供访问底层 Stalker 功能的接口**。它允许用户通过 JavaScript 代码来控制程序执行的追踪，设置回调函数来处理追踪到的事件，以及配置 Stalker 的各种参数。它构建了 JavaScript 世界和 Frida 底层执行追踪引擎之间的桥梁。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickstalker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2020-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickstalker.h"

#include "gumquickeventsink.h"
#include "gumquickmacros.h"

#include <string.h>

#define GUM_QUICK_TYPE_TRANSFORMER (gum_quick_transformer_get_type ())
#define GUM_QUICK_TRANSFORMER_CAST(obj) ((GumQuickTransformer *) (obj))

typedef struct _GumQuickTransformer GumQuickTransformer;
typedef struct _GumQuickTransformerClass GumQuickTransformerClass;
typedef struct _GumQuickIterator GumQuickIterator;
typedef struct _GumQuickCallout GumQuickCallout;
typedef struct _GumQuickCallProbe GumQuickCallProbe;

struct _GumQuickTransformer
{
  GObject object;

  GumThreadId thread_id;
  JSValue callback;

  GumQuickStalker * parent;
};

struct _GumQuickTransformerClass
{
  GObjectClass object_class;
};

struct _GumQuickIterator
{
  GumStalkerIterator * handle;
  GumQuickInstructionValue * instruction;

  GumQuickStalker * parent;
};

struct _GumQuickDefaultIterator
{
  GumQuickDefaultWriter writer;
  GumQuickIterator iterator;
};

struct _GumQuickSpecialIterator
{
  GumQuickSpecialWriter writer;
  GumQuickIterator iterator;
};

struct _GumQuickCallout
{
  JSValue callback;

  GumQuickStalker * parent;
};

struct _GumQuickCallProbe
{
  JSValue callback;

  GumQuickStalker * parent;
};

struct _GumQuickProbeArgs
{
  JSValue wrapper;
  GumCallDetails * call;
};

static gboolean gum_quick_stalker_on_flush_timer_tick (GumQuickStalker * self);

GUMJS_DECLARE_GETTER (gumjs_stalker_get_trust_threshold)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_trust_threshold)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_capacity)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_capacity)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_drain_interval)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_drain_interval)

GUMJS_DECLARE_FUNCTION (gumjs_stalker_flush)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_garbage_collect)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_exclude)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_follow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_unfollow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_invalidate)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_add_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_remove_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_parse)

static void gum_quick_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_transformer_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumQuickTransformer,
                        gum_quick_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_quick_transformer_iface_init))

static JSValue gum_quick_default_iterator_new (GumQuickStalker * parent,
    GumQuickDefaultIterator ** iterator);
static void gum_quick_default_iterator_reset (GumQuickDefaultIterator * self,
    GumStalkerIterator * handle, GumStalkerOutput * output);
GUMJS_DECLARE_FINALIZER (gumjs_default_iterator_finalize)
GUMJS_DECLARE_GETTER (gumjs_default_iterator_get_memory_access)
GUMJS_DECLARE_FUNCTION (gumjs_default_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_default_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_default_iterator_put_callout)
GUMJS_DECLARE_FUNCTION (gumjs_default_iterator_put_chaining_return)

static JSValue gum_quick_special_iterator_new (GumQuickStalker * parent,
    GumQuickSpecialIterator ** iterator);
static void gum_quick_special_iterator_reset (GumQuickSpecialIterator * self,
    GumStalkerIterator * handle, GumStalkerOutput * output);
GUMJS_DECLARE_FINALIZER (gumjs_special_iterator_finalize)
GUMJS_DECLARE_GETTER (gumjs_special_iterator_get_memory_access)
GUMJS_DECLARE_FUNCTION (gumjs_special_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_special_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_special_iterator_put_callout)
GUMJS_DECLARE_FUNCTION (gumjs_special_iterator_put_chaining_return)

static void gum_quick_callout_free (GumQuickCallout * callout);
static void gum_quick_callout_on_invoke (GumCpuContext * cpu_context,
    GumQuickCallout * self);

static void gum_quick_call_probe_free (GumQuickCallProbe * probe);
static void gum_quick_call_probe_on_fire (GumCallDetails * details,
    GumQuickCallProbe * self);

static JSValue gum_quick_probe_args_new (GumQuickStalker * parent,
    GumQuickProbeArgs ** probe_args);
static void gum_quick_probe_args_reset (GumQuickProbeArgs * self,
    GumCallDetails * call);
GUMJS_DECLARE_FINALIZER (gumjs_probe_args_finalize)
static JSValue gumjs_probe_args_get_property (JSContext * ctx, JSValueConst obj,
    JSAtom atom, JSValueConst receiver);
static int gumjs_probe_args_set_property (JSContext * ctx, JSValueConst obj,
    JSAtom atom, JSValueConst value, JSValueConst receiver, int flags);

static GumQuickDefaultIterator * gum_quick_stalker_obtain_default_iterator (
    GumQuickStalker * self);
static void gum_quick_stalker_release_default_iterator (GumQuickStalker * self,
    GumQuickDefaultIterator * iterator);
static GumQuickSpecialIterator * gum_quick_stalker_obtain_special_iterator (
    GumQuickStalker * self);
static void gum_quick_stalker_release_special_iterator (GumQuickStalker * self,
    GumQuickSpecialIterator * iterator);
static GumQuickInstructionValue * gum_quick_stalker_obtain_instruction (
    GumQuickStalker * self);
static void gum_quick_stalker_release_instruction (GumQuickStalker * self,
    GumQuickInstructionValue * value);
static GumQuickCpuContext * gum_quick_stalker_obtain_cpu_context (
    GumQuickStalker * self);
static void gum_quick_stalker_release_cpu_context (GumQuickStalker * self,
    GumQuickCpuContext * cpu_context);
static GumQuickProbeArgs * gum_quick_stalker_obtain_probe_args (
    GumQuickStalker * self);
static void gum_quick_stalker_release_probe_args (GumQuickStalker * self,
    GumQuickProbeArgs * args);

static JSValue gum_encode_pointer (JSContext * ctx, gpointer value,
    gboolean stringify, GumQuickCore * core);

static const JSCFunctionListEntry gumjs_stalker_entries[] =
{
  JS_CGETSET_DEF ("trustThreshold", gumjs_stalker_get_trust_threshold,
      gumjs_stalker_set_trust_threshold),
  JS_CGETSET_DEF ("queueCapacity", gumjs_stalker_get_queue_capacity,
      gumjs_stalker_set_queue_capacity),
  JS_CGETSET_DEF ("queueDrainInterval", gumjs_stalker_get_queue_drain_interval,
      gumjs_stalker_set_queue_drain_interval),
  JS_CFUNC_DEF ("flush", 0, gumjs_stalker_flush),
  JS_CFUNC_DEF ("garbageCollect", 0, gumjs_stalker_garbage_collect),
  JS_CFUNC_DEF ("_exclude", 0, gumjs_stalker_exclude),
  JS_CFUNC_DEF ("_follow", 0, gumjs_stalker_follow),
  JS_CFUNC_DEF ("unfollow", 0, gumjs_stalker_unfollow),
  JS_CFUNC_DEF ("invalidate", 0, gumjs_stalker_invalidate),
  JS_CFUNC_DEF ("addCallProbe", 0, gumjs_stalker_add_call_probe),
  JS_CFUNC_DEF ("removeCallProbe", 0, gumjs_stalker_remove_call_probe),
  JS_CFUNC_DEF ("_parse", 0, gumjs_stalker_parse),
};

static const JSClassDef gumjs_default_iterator_def =
{
  .class_name = "DefaultIterator",
  .finalizer = gumjs_default_iterator_finalize,
};

static const JSCFunctionListEntry gumjs_default_iterator_entries[] =
{
  JS_CGETSET_DEF ("memoryAccess", gumjs_default_iterator_get_memory_access,
      NULL),
  JS_CFUNC_DEF ("next", 0, gumjs_default_iterator_next),
  JS_CFUNC_DEF ("keep", 0, gumjs_default_iterator_keep),
  JS_CFUNC_DEF ("putCallout", 0, gumjs_default_iterator_put_callout),
  JS_CFUNC_DEF ("putChainingReturn", 0,
      gumjs_default_iterator_put_chaining_return),
};

static const JSClassDef gumjs_special_iterator_def =
{
  .class_name = "SpecialIterator",
  .finalizer = gumjs_special_iterator_finalize,
};

static const JSCFunctionListEntry gumjs_special_iterator_entries[] =
{
  JS_CGETSET_DEF ("memoryAccess", gumjs_special_iterator_get_memory_access,
      NULL),
  JS_CFUNC_DEF ("next", 0, gumjs_special_iterator_next),
  JS_CFUNC_DEF ("keep", 0, gumjs_special_iterator_keep),
  JS_CFUNC_DEF ("putCallout", 0, gumjs_special_iterator_put_callout),
  JS_CFUNC_DEF ("putChainingReturn", 0,
      gumjs_special_iterator_put_chaining_return),
};

static const JSClassExoticMethods gumjs_probe_args_exotic_methods =
{
  .get_property = gumjs_probe_args_get_property,
  .set_property = gumjs_probe_args_set_property,
};

static const JSClassDef gumjs_probe_args_def =
{
  .class_name = "ProbeArguments",
  .finalizer = gumjs_probe_args_finalize,
  .exotic = (JSClassExoticMethods *) &gumjs_probe_args_exotic_methods,
};

void
_gum_quick_stalker_init (GumQuickStalker * self,
                         JSValue ns,
                         GumQuickCodeWriter * writer,
                         GumQuickInstruction * instruction,
                         GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto;

  self->writer = writer;
  self->instruction = instruction;
  self->core = core;

  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  self->flush_timer = NULL;

  _gum_quick_core_store_module_data (core, "stalker", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_stalker_entries,
      G_N_ELEMENTS (gumjs_stalker_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Stalker", obj, JS_PROP_C_W_E);

  _gum_quick_create_subclass (ctx, &gumjs_default_iterator_def,
      writer->G_PASTE (GUM_QUICK_DEFAULT_WRITER_FIELD, _class),
      writer->G_PASTE (GUM_QUICK_DEFAULT_WRITER_FIELD, _proto), core,
      &self->default_iterator_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto,
      gumjs_default_iterator_entries,
      G_N_ELEMENTS (gumjs_default_iterator_entries));

  _gum_quick_create_subclass (ctx, &gumjs_special_iterator_def,
      writer->G_PASTE (GUM_QUICK_SPECIAL_WRITER_FIELD, _class),
      writer->G_PASTE (GUM_QUICK_SPECIAL_WRITER_FIELD, _proto), core,
      &self->special_iterator_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto,
      gumjs_special_iterator_entries,
      G_N_ELEMENTS (gumjs_special_iterator_entries));

  _gum_quick_create_class (ctx, &gumjs_probe_args_def, core,
      &self->probe_args_class, &proto);

  gum_quick_default_iterator_new (self, &self->cached_default_iterator);
  self->cached_default_iterator_in_use = FALSE;

  gum_quick_special_iterator_new (self, &self->cached_special_iterator);
  self->cached_special_iterator_in_use = FALSE;

  _gum_quick_instruction_new (ctx, NULL, TRUE, NULL, 0, instruction,
      &self->cached_instruction);
  self->cached_instruction_in_use = FALSE;

  _gum_quick_cpu_context_new (ctx, NULL, GUM_CPU_CONTEXT_READWRITE, core,
      &self->cached_cpu_context);
  self->cached_cpu_context_in_use = FALSE;

  gum_quick_probe_args_new (self, &self->cached_probe_args);
  self->cached_probe_args_in_use = FALSE;
}

void
_gum_quick_stalker_flush (GumQuickStalker * self)
{
  GumQuickCore * core = self->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gboolean pending_garbage;

  if (self->stalker == NULL)
    return;

  _gum_quick_scope_suspend (&scope);

  gum_stalker_stop (self->stalker);

  pending_garbage = gum_stalker_garbage_collect (self->stalker);

  _gum_quick_scope_resume (&scope);

  if (pending_garbage)
  {
    if (self->flush_timer == NULL)
    {
      GSource * source;

      source = g_timeout_source_new (10);
      g_source_set_callback (source,
          (GSourceFunc) gum_quick_stalker_on_flush_timer_tick, self, NULL);
      self->flush_timer = source;

      _gum_quick_core_pin (core);
      _gum_quick_scope_suspend (&scope);

      g_source_attach (source,
          gum_script_scheduler_get_js_context (core->scheduler));
      g_source_unref (source);

      _gum_quick_scope_resume (&scope);
    }
  }
  else
  {
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

static gboolean
gum_quick_stalker_on_flush_timer_tick (GumQuickStalker * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumQuickCore * core = self->core;
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);
    _gum_quick_core_unpin (core);
    self->flush_timer = NULL;
    _gum_quick_scope_leave (&scope);
  }

  return pending_garbage;
}

void
_gum_quick_stalker_dispose (GumQuickStalker * self)
{
  JSContext * ctx = self->core->ctx;

  g_assert (self->flush_timer == NULL);

  JS_FreeValue (ctx, self->cached_probe_args->wrapper);
  JS_FreeValue (ctx, self->cached_cpu_context->wrapper);
  JS_FreeValue (ctx, self->cached_instruction->wrapper);
  JS_FreeValue (ctx, self->cached_special_iterator->writer.wrapper);
  JS_FreeValue (ctx, self->cached_default_iterator->writer.wrapper);
}

void
_gum_quick_stalker_finalize (GumQuickStalker * self)
{
}

GumStalker *
_gum_quick_stalker_get (GumQuickStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_quick_stalker_process_pending (GumQuickStalker * self,
                                    GumQuickScope * scope)
{
  if (scope->pending_stalker_level > 0)
  {
    gum_stalker_follow_me (_gum_quick_stalker_get (self),
        scope->pending_stalker_transformer, scope->pending_stalker_sink);
  }
  else if (scope->pending_stalker_level < 0)
  {
    gum_stalker_unfollow_me (_gum_quick_stalker_get (self));
  }
  scope->pending_stalker_level = 0;

  g_clear_object (&scope->pending_stalker_sink);
  g_clear_object (&scope->pending_stalker_transformer);
}

static GumQuickStalker *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "stalker");
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  GumStalker * stalker =
      _gum_quick_stalker_get (gumjs_get_parent_module (core));

  return JS_NewInt32 (ctx, gum_stalker_get_trust_threshold (stalker));
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  GumStalker * stalker;
  gint threshold;

  stalker = _gum_quick_stalker_get (gumjs_get_parent_module (core));

  if (!_gum_quick_int_get (ctx, val, &threshold))
    return JS_EXCEPTION;

  gum_stalker_set_trust_threshold (stalker, threshold);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  GumQuickStalker * self = gumjs_get_parent_module (core);

  return JS_NewInt32 (ctx, self->queue_capacity);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  GumQuickStalker * self = gumjs_get_parent_module (core);

  if (!_gum_quick_uint_get (ctx, val, &self->queue_capacity))
    return JS_EXCEPTION;

  return JS_UNDEFINED;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  GumQuickStalker * self = gumjs_get_parent_module (core);

  return JS_NewInt32 (ctx, self->queue_drain_interval);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  GumQuickStalker * self = gumjs_get_parent_module (core);

  if (!_gum_quick_uint_get (ctx, val, &self->queue_drain_interval))
    return JS_EXCEPTION;

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_flush)
{
  GumStalker * stalker =
      _gum_quick_stalker_get (gumjs_get_parent_module (core));

  gum_stalker_flush (stalker);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_garbage_collect)
{
  GumStalker * stalker =
      _gum_quick_stalker_get (gumjs_get_parent_module (core));

  gum_stalker_garbage_collect (stalker);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_exclude)
{
  GumStalker * stalker;
  gpointer base;
  gsize size;
  GumMemoryRange range;

  stalker = _gum_quick_stalker_get (gumjs_get_parent_module (core));

  if (!_gum_quick_args_parse (args, "pZ", &base, &size))
    return JS_EXCEPTION;

  range.base_address = GUM_ADDRESS (base);
  range.size = size;

  gum_stalker_exclude (stalker, &range);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_follow)
{
  GumQuickStalker * parent;
  GumStalker * stalker;
  GumThreadId thread_id;
  JSValue transformer_callback_js;
  GumStalkerTransformerCallback transformer_callback_c;
  GumQuickEventSinkOptions so;
  gpointer user_data;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;

  parent = gumjs_get_parent_module (core);
  stalker = _gum_quick_stalker_get (parent);

  so.core = core;
  so.main_context = gum_script_scheduler_get_js_context (core->scheduler);
  so.queue_capacity = parent->queue_capacity;
  so.queue_drain_interval = parent->queue_drain_interval;

  if (!_gum_quick_args_parse (args, "ZF*?uF?F?pp", &thread_id,
      &transformer_callback_js, &transformer_callback_c, &so.event_mask,
      &so.on_receive, &so.on_call_summary, &so.on_event, &user_data))
    return JS_EXCEPTION;

  so.user_data = user_data;

  if (!JS_IsNull (transformer_callback_js))
  {
    GumQuickTransformer * cbt;

    cbt = g_object_new (GUM_QUICK_TYPE_TRANSFORMER, NULL);
    cbt->thread_id = thread_id;
    cbt->callback = JS_DupValue (ctx, transformer_callback_js);
    cbt->parent = parent;

    transformer = GUM_STALKER_TRANSFORMER (cbt);
  }
  else if (transformer_callback_c != NULL)
  {
    transformer = gum_stalker_transformer_make_from_callback (
        transformer_callback_c, user_data, NULL);
  }
  else
  {
    transformer = NULL;
  }

  sink = gum_quick_event_sink_new (ctx, &so);

  if (thread_id == gum_process_get_current_thread_id ())
  {
    GumQuickScope * scope = core->current_scope;

    scope->pending_stalker_level = 1;

    g_clear_object (&scope->pending_stalker_transformer);
    g_clear_object (&scope->pending_stalker_sink);
    scope->pending_stalker_transformer = transformer;
    scope->pending_stalker_sink = sink;
  }
  else
  {
    gum_stalker_follow (stalker, thread_id, transformer, sink);
    g_object_unref (sink);
    g_clear_object (&transformer);
  }

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_unfollow)
{
  GumQuickStalker * parent;
  GumStalker * stalker;
  GumThreadId current_thread_id, thread_id;

  parent = gumjs_get_parent_module (core);
  stalker = _gum_quick_stalker_get (parent);

  current_thread_id = gum_process_get_current_thread_id ();

  thread_id = current_thread_id;
  if (!_gum_quick_args_parse (args, "|Z", &thread_id))
    return JS_EXCEPTION;

  if (thread_id == current_thread_id)
    parent->core->current_scope->pending_stalker_level--;
  else
    gum_stalker_unfollow (stalker, thread_id);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_invalidate)
{
  GumQuickStalker * parent;
  GumStalker * stalker;
  gconstpointer address;

  parent = gumjs_get_parent_module (core);
  stalker = _gum_quick_stalker_get (parent);

  if (args->count <= 1)
  {
    if (!_gum_quick_args_parse (args, "p", &address))
      return JS_EXCEPTION;

    gum_stalker_invalidate (stalker, address);
  }
  else
  {
    GumThreadId thread_id;
    GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

    if (!_gum_quick_args_parse (args, "Zp", &thread_id, &address))
      return JS_EXCEPTION;

    _gum_quick_scope_suspend (&scope);

    gum_stalker_invalidate_for_thread (stalker, thread_id, address);

    _gum_quick_scope_resume (&scope);
  }

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_add_call_probe)
{
  GumProbeId id;
  GumQuickStalker * parent;
  GumStalker * stalker;
  gpointer target_address;
  JSValue callback_js;
  GumCallProbeCallback callback_c;
  gpointer user_data;
  GumQuickCallProbe * probe;

  parent = gumjs_get_parent_module (core);
  stalker = _gum_quick_stalker_get (parent);

  user_data = NULL;
  if (!_gum_quick_args_parse (args, "pF*|p", &target_address, &callback_js,
      &callback_c, &user_data))
    return JS_EXCEPTION;

  if (!JS_IsNull (callback_js))
  {
    probe = g_slice_new (GumQuickCallProbe);
    probe->callback = JS_DupValue (ctx, callback_js);
    probe->parent = parent;

    id = gum_stalker_add_call_probe (stalker, target_address,
        (GumCallProbeCallback) gum_quick_call_probe_on_fire, probe,
        (GDestroyNotify) gum_quick_call_probe_free);
  }
  else
  {
    id = gum_stalker_add_call_probe (stalker, target_address, callback_c,
        user_data, NULL);
  }

  return JS_NewInt32 (ctx, id);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_remove_call_probe)
{
  GumQuickStalker * parent;
  GumProbeId id;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "u", &id))
    return JS_EXCEPTION;

  gum_stalker_remove_call_probe (_gum_quick_stalker_get (parent), id);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_parse)
{
  JSValue result = JS_NULL;
  JSValue events_value;
  gboolean annotate, stringify;
  const GumEvent * events;
  size_t size, count, row_index;
  const GumEvent * ev;
  JSValue row = JS_NULL;

  if (!_gum_quick_args_parse (args, "Vtt", &events_value, &annotate,
      &stringify))
    return JS_EXCEPTION;

  events = (const GumEvent *) JS_GetArrayBuffer (ctx, &size, events_value);
  if (events == NULL)
    return JS_EXCEPTION;

  if (size % sizeof (GumEvent) != 0)
    goto invalid_buffer_shape;

  count = size / sizeof (GumEvent);

  result = JS_NewArray (ctx);

  for (ev = events, row_index = 0; row_index != count; ev++, row_index++)
  {
    size_t column_index = 0;

    row = JS_NewArray (ctx);

#define GUM_APPEND_VAL(v) \
    JS_DefinePropertyValueUint32 (ctx, row, (uint32_t) column_index++, v, \
        JS_PROP_C_W_E)
#define GUM_APPEND_STR(s) \
    GUM_APPEND_VAL (JS_NewString (ctx, s))
#define GUM_APPEND_PTR(p) \
    GUM_APPEND_VAL (gum_encode_pointer (ctx, p, stringify, core))
#define GUM_APPEND_INT(v) \
    GUM_APPEND_VAL (JS_NewInt32 (ctx, v))

    switch (ev->type)
    {
      case GUM_CALL:
      {
        const GumCallEvent * call = &ev->call;

        if (annotate)
          GUM_APPEND_STR ("call");
        GUM_APPEND_PTR (call->location);
        GUM_APPEND_PTR (call->target);
        GUM_APPEND_INT (call->depth);

        break;
      }
      case GUM_RET:
      {
        const GumRetEvent * ret = &ev->ret;

        if (annotate)
          GUM_APPEND_STR ("ret");
        GUM_APPEND_PTR (ret->location);
        GUM_APPEND_PTR (ret->target);
        GUM_APPEND_INT (ret->depth);

        break;
      }
      case GUM_EXEC:
      {
        const GumExecEvent * exec = &ev->exec;

        if (annotate)
          GUM_APPEND_STR ("exec");
        GUM_APPEND_PTR (exec->location);

        break;
      }
      case GUM_BLOCK:
      {
        const GumBlockEvent * block = &ev->block;

        if (annotate)
          GUM_APPEND_STR ("block");
        GUM_APPEND_PTR (block->start);
        GUM_APPEND_PTR (block->end);

        break;
      }
      case GUM_COMPILE:
      {
        const GumCompileEvent * compile = &ev->compile;

        if (annotate)
          GUM_APPEND_STR ("compile");
        GUM_APPEND_PTR (compile->start);
        GUM_APPEND_PTR (compile->end);

        break;
      }
      default:
        goto invalid_event_type;
    }

#undef GUM_APPEND_VAL
#undef GUM_APPEND_STR
#undef GUM_APPEND_PTR
#undef GUM_APPEND_INT

    JS_DefinePropertyValueUint32 (ctx, result, (uint32_t) row_index, row,
        JS_PROP_C_W_E);
  }

  return result;

invalid_buffer_shape:
  {
    _gum_quick_throw_literal (ctx, "invalid buffer shape");
    goto propagate_exception;
  }
invalid_event_type:
  {
    _gum_quick_throw_literal (ctx, "invalid event type");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, row);
    JS_FreeValue (ctx, result);

    return JS_EXCEPTION;
  }
}

static void
gum_quick_transformer_transform_block (GumStalkerTransformer * transformer,
                                       GumStalkerIterator * iterator,
                                       GumStalkerOutput * output)
{
  GumQuickTransformer * self = GUM_QUICK_TRANSFORMER_CAST (transformer);
  GumQuickStalker * parent = self->parent;
  gint saved_system_error;
  GumQuickScope scope;
  GumQuickDefaultIterator * default_iter = NULL;
  GumQuickSpecialIterator * special_iter = NULL;
  JSValue iter_val;
  gboolean transform_threw_an_exception;

  saved_system_error = gum_thread_get_system_error ();

  _gum_quick_scope_enter (&scope, parent->core);

  if (output->encoding == GUM_INSTRUCTION_DEFAULT)
  {
    default_iter = gum_quick_stalker_obtain_default_iterator (parent);
    gum_quick_default_iterator_reset (default_iter, iterator, output);
    iter_val = default_iter->writer.wrapper;
  }
  else
  {
    special_iter = gum_quick_stalker_obtain_special_iterator (parent);
    gum_quick_special_iterator_reset (special_iter, iterator, output);
    iter_val = special_iter->writer.wrapper;
  }

  transform_threw_an_exception = !_gum_quick_scope_call_void (&scope,
      self->callback, JS_UNDEFINED, 1, &iter_val);

  if (default_iter != NULL)
  {
    gum_quick_default_iterator_reset (default_iter, NULL, NULL);
    gum_quick_stalker_release_default_iterator (parent, default_iter);
  }
  else
  {
    gum_quick_special_iterator_reset (special_iter, NULL, NULL);
    gum_quick_stalker_release_special_iterator (parent, special_iter);
  }

  _gum_quick_scope_leave (&scope);

  if (transform_threw_an_exception)
    gum_stalker_unfollow (parent->stalker, self->thread_id);

  gum_thread_set_system_error (saved_system_error);
}

static void
gum_quick_transformer_class_init (GumQuickTransformerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_transformer_dispose;
}

static void
gum_quick_transformer_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumStalkerTransformerInterface * iface = g_iface;

  iface->transform_block = gum_quick_transformer_transform_block;
}

static void
gum_quick_transformer_init (GumQuickTransformer * self)
{
}

static void
gum_quick_transformer_dispose (GObject * object)
{
  GumQuickTransformer * self = GUM_QUICK_TRANSFORMER_CAST (object);
  GumQuickCore * core = self->parent->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);

  if (!JS_IsNull (self->callback))
  {
    JS_FreeValue (core->ctx, self->callback);
    self->callback = JS_NULL;
  }

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_transformer_parent_class)->dispose (object);
}

static void
gum_quick_stalker_iterator_init (GumQuickIterator * iter,
                                 GumQuickStalker * parent)
{
  iter->handle = NULL;
  iter->instruction = NULL;

  iter->parent = parent;
}

static void
gum_quick_stalker_iterator_reset (GumQuickIterator * self,
                                  GumStalkerIterator * handle)
{
  self->handle = handle;

  if (self->instruction != NULL)
  {
    self->instruction->insn = NULL;
    gum_quick_stalker_release_instruction (self->parent, self->instruction);
  }
  self->instruction = (handle != NULL)
      ? gum_quick_stalker_obtain_instruction (self->parent)
      : NULL;
}

static JSValue
gum_quick_stalker_iterator_get_memory_access (GumQuickIterator * self,
                                              JSContext * ctx)
{
  switch (gum_stalker_iterator_get_memory_access (self->handle))
  {
    case GUM_MEMORY_ACCESS_OPEN:
      return JS_NewString (ctx, "open");
    case GUM_MEMORY_ACCESS_EXCLUSIVE:
      return JS_NewString (ctx, "exclusive");
    default:
      g_assert_not_reached ();
  }

  return JS_NULL;
}

static JSValue
gum_quick_stalker_iterator_next (GumQuickIterator * self,
                                 JSContext * ctx)
{
  if (gum_stalker_iterator_next (self->handle, &self->instruction->insn))
    return JS_DupValue (ctx, self->instruction->wrapper);

  return JS_NULL;
}

static JSValue
gum_quick_stalker_iterator_keep (GumQuickIterator * self,
                                 JSContext * ctx)
{
  gum_stalker_iterator_keep (self->handle);

  return JS_UNDEFINED;
}

static JSValue
gum_quick_stalker_iterator_put_callout (GumQuickIterator * self,
                                        JSContext * ctx,
                                        GumQuickArgs * args)
{
  JSValue callback_js;
  GumStalkerCallout callback_c;
  gpointer user_data;

  user_data = NULL;
  if (!_gum_quick_args_parse (args, "F*|p", &callback_js, &callback_c,
      &user_data))
    return JS_EXCEPTION;

  if (!JS_IsNull (callback_js))
  {
    GumQuickCallout * callout;

    callout = g_slice_new (GumQuickCallout);
    callout->callback = JS_DupValue (ctx, callback_js);
    callout->parent = self->parent;

    gum_stalker_iterator_put_callout (self->handle,
        (GumStalkerCallout) gum_quick_callout_on_invoke, callout,
        (GDestroyNotify) gum_quick_callout_free);
  }
  else
  {
    gum_stalker_iterator_put_callout (self->handle, callback_c, user_data,
        NULL);
  }

  return JS_UNDEFINED;
}

static JSValue
gum_quick_stalker_iterator_put_chaining_return (GumQuickIterator * self,
                                                JSContext * ctx)
{
  gum_stalker_iterator_put_chaining_return (self->handle);

  return JS_UNDEFINED;
}

static JSValue
gum_quick_default_iterator_new (GumQuickStalker * parent,
                                GumQuickDefaultIterator ** iterator)
{
  JSValue wrapper;
  JSContext * ctx = parent->core->ctx;
  GumQuickDefaultIterator * iter;
  GumQuickDefaultWriter * writer;

  wrapper = JS_NewObjectClass (ctx, parent->default_iterator_class);

  iter = g_slice_new (GumQuickDefaultIterator);

  writer = &iter->writer;
  _gum_quick_default_writer_init (writer, ctx, parent->writer);
  writer->wrapper = wrapper;

  gum_quick_stalker_iterator_init (&iter->iterator, parent);

  JS_SetOpaque (wrapper, iter);

  *iterator = iter;

  return wrapper;
}

static void
gum_quick_default_iterator_release (GumQuickDefaultIterator * self)
{
  JS_FreeValue (self->writer.ctx, self->writer.wrapper);
}

static void
gum_quick_default_iterator_reset (GumQuickDefaultIterator * self,
                                  GumStalkerIterator * handle,
                                  GumStalkerOutput * output)
{
  _gum_quick_default_writer_reset (&self->writer,
      (output != NULL) ? output->writer.instance : NULL);
  gum_quick_stalker_iterator_reset (&self->iterator, handle);
}

static gboolean
gum_quick_default_iterator_get (JSContext * ctx,
                                JSValueConst val,
                                GumQuickCore * core,
                                GumQuickDefaultIterator ** iterator)
{
  GumQuickDefaultIterator * it;

  if (!_gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->default_iterator_class, core,
      (gpointer *) &it))
    return FALSE;

  if (it->iterator.handle == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *iterator = it;
  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_default_iterator_finalize)
{
  GumQuickDefaultIterator * it;

  it = JS_GetOpaque (val,
      gumjs_get_parent_module (core)->default_iterator_class);
  if (it == NULL)
    return;

  _gum_quick_default_writer_finalize (&it->writer);

  g_slice_free (GumQuickDefaultIterator, it);
}

GUMJS_DEFINE_GETTER (gumjs_default_iterator_get_memory_access)
{
  GumQuickDefaultIterator * self;

  if (!gum_quick_default_iterator_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return gum_quick_stalker_iterator_get_memory_access (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_default_iterator_next)
{
  GumQuickDefaultIterator * self;

  if (!gum_quick_default_iterator_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return gum_quick_stalker_iterator_next (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_default_iterator_keep)
{
  GumQuickDefaultIterator * self;

  if (!gum_quick_default_iterator_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return gum_quick_stalker_iterator_keep (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_default_iterator_put_callout)
{
  GumQuickDefaultIterator * self;

  if (!gum_quick_default_iterator_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return gum_quick_stalker_iterator_put_callout (&self->iterator, ctx, args);
}

GUMJS_DEFINE_FUNCTION (gumjs_default_iterator_put_chaining_return)
{
  GumQuickDefaultIterator * self;

  if (!gum_quick_default_iterator_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return gum_quick_stalker_iterator_put_chaining_return (&self->iterator, ctx);
}

static JSValue
gum_quick_special_iterator_new (GumQuickStalker * parent,
                                GumQuickSpecialIterator ** iterator)
{
  JSValue wrapper;
  JSContext * ctx = parent->core->ctx;
  GumQuickSpecialIterator * iter;
  GumQuickSpecialWriter * writer;

  wrapper = JS_NewObjectClass (ctx, parent->special_iterator_class);

  iter = g_slice_new (GumQuickSpecialIterator);

  writer = &iter->writer;
  _gum_quick_special_writer_init (writer, ctx,
```