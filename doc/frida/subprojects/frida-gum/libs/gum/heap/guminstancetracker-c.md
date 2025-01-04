Response:
Let's break down the thought process for analyzing this C code and generating the response.

**1. Understanding the Core Purpose:**

The very first step is to read the initial comments and the `typedef` and `struct` definitions. These immediately reveal the core purpose: tracking instances of objects within a process, specifically looking at creation and destruction. The name "GumInstanceTracker" is a strong indicator. The presence of `GHashTable` suggests storing information about these instances.

**2. Identifying Key Components and Data Structures:**

Next, I'd look at the key data structures and their members:

*   `GumInstanceTracker`: The main structure, containing:
    *   `mutex`:  Indicates thread-safety is a concern.
    *   `counter_ht`: Likely stores counts of instances for each type.
    *   `instances_ht`: Likely stores actual instance pointers.
    *   `interceptor`:  Crucial for dynamic instrumentation - hooking into function calls.
    *   `vtable`:  Stores function pointers for creating, freeing, and getting the name of object types. This suggests a focus on GObject-like structures (or at least a generic interface).
    *   `type_filter_func`:  A mechanism to selectively track instances.

*   `FunctionId`: An enum for distinguishing between creation and destruction functions.

*   `GumInstanceVTable`: Holds function pointers related to instance lifecycle.

**3. Analyzing Key Functions:**

I'd then go through the functions, paying close attention to their purpose and how they interact with the data structures:

*   `gum_instance_tracker_new`:  Standard object creation.
*   `gum_instance_tracker_begin`: This is where the instrumentation magic happens. It uses the `GumInterceptor` to hook `create_instance` and `free_instance`. This is a HUGE clue for its dynamic instrumentation role. The logic to find the vtable (either provided or by searching modules) is important.
*   `gum_instance_tracker_end`:  Reverses the `begin` operation by detaching the hooks.
*   `gum_instance_tracker_peek_total_count`: Retrieves the number of instances, either for a specific type or overall.
*   `gum_instance_tracker_peek_instances`:  Gets a list of all tracked instances.
*   `gum_instance_tracker_walk_instances`:  Provides a way to iterate through tracked instances and access their details.
*   `gum_instance_tracker_add_instance` and `gum_instance_tracker_remove_instance`:  These are called by the hooks to update the tracking data. The filtering logic is important here.
*   `gum_instance_tracker_on_enter` and `gum_instance_tracker_on_leave`: These are the callbacks invoked by the `GumInterceptor` when the hooked functions are called. They are responsible for calling `add_instance` and `remove_instance`.

**4. Connecting to Concepts (as requested in the prompt):**

As I analyze the functions, I'd actively look for connections to the prompt's requirements:

*   **Reverse Engineering:** The core functionality of intercepting function calls (`gum_interceptor`) is a fundamental technique in dynamic analysis and reverse engineering. Tracking object lifecycles helps understand program behavior.
*   **Binary Level:** The interaction with modules and function pointers points to a binary-level understanding of the target process. The code needs to locate and hook functions in memory.
*   **Linux/Android Kernel & Framework:**  While not explicitly using kernel APIs here, the concept of dynamic instrumentation is heavily used in these environments. The example of tracking GObject instances directly relates to the GObject framework common in Linux/GNOME and used in Android's UI layer.
*   **Logical Inference:** The `if` conditions, especially in `on_enter` and `on_leave`, involve simple logical reasoning based on the `FunctionId`. The interaction between `begin`, `end`, `add_instance`, and `remove_instance` also implies a clear logical flow.
*   **User Errors:**  Thinking about how a user would *misuse* the API is important. Forgetting to call `begin`/`end`, providing incorrect vtables, or filtering incorrectly are potential issues.
*   **Debugging:**  The functions for peeking and walking instances are clearly designed for debugging and inspecting the state of the application.

**5. Structuring the Response:**

Finally, I'd structure the response according to the prompt's requirements, using clear headings and examples.

*   **Functionality List:** A straightforward enumeration of the key capabilities.
*   **Relationship to Reverse Engineering:** Explain the dynamic analysis aspect and provide a concrete example.
*   **Binary/Kernel/Framework Connections:**  Highlight the binary instrumentation and the GObject example.
*   **Logical Inference Example:** Choose a simple scenario (like creating an instance) and trace the function calls and data updates.
*   **User Errors:** Provide practical examples of common mistakes.
*   **Debugging Clues:** Explain how the functions help in debugging.

**Self-Correction/Refinement during the Process:**

*   **Initial thought:**  Is this just about counting objects?  **Correction:**  No, the `interceptor` indicates a more active role in modifying execution.
*   **Initial thought:**  Does it only work with GObjects? **Correction:** While heavily focused on GObjects, the ability to provide a custom `vtable` suggests it can be adapted for other object models (though the provided example is GObject-centric).
*   **Making assumptions explicit:** When explaining the logical inference, explicitly state the assumed input and expected output.
*   **Adding context:** When explaining the user's path to this code, consider the broader Frida workflow (scripting, attaching, etc.).

By following this structured approach, focusing on the key elements of the code and relating them to the prompt's specific questions, I can generate a comprehensive and accurate explanation of the `guminstancetracker.c` file.
这个 `guminstancetracker.c` 文件是 Frida 动态插桩工具中的一个核心组件，它的主要功能是**跟踪程序运行时创建和销毁的对象实例**。它通过 hook (拦截) 关键的内存分配和释放函数来实现这一目标，从而为开发者提供程序运行时对象生命周期的洞察。

以下是该文件的具体功能列表以及与逆向、底层知识、逻辑推理、用户错误和调试线索的关联：

**功能列表:**

1. **实例创建跟踪 (Instance Creation Tracking):**
    *   拦截指定类型的实例创建函数（默认为 `g_type_create_instance`，可以通过 `gum_instance_tracker_begin` 自定义）。
    *   当创建一个新的实例时，记录该实例的地址和类型。
    *   维护一个哈希表 (`instances_ht`) 来存储当前存活的所有被跟踪的实例。
    *   维护一个哈希表 (`counter_ht`) 来记录每种类型实例的创建数量。

2. **实例销毁跟踪 (Instance Destruction Tracking):**
    *   拦截指定类型的实例销毁函数（默认为 `g_type_free_instance`，可以通过 `gum_instance_tracker_begin` 自定义）。
    *   当一个实例被销毁时，将其从 `instances_ht` 中移除。
    *   更新 `counter_ht` 中对应类型实例的计数。

3. **实例类型过滤 (Instance Type Filtering):**
    *   允许用户设置一个过滤函数 (`type_filter_func`)，以便只跟踪特定类型的实例。这可以通过 `gum_instance_tracker_set_type_filter_function` 实现。

4. **获取实例信息 (Getting Instance Information):**
    *   `gum_instance_tracker_peek_total_count`:  获取指定类型或所有被跟踪实例的总数。
    *   `gum_instance_tracker_peek_instances`:  获取当前所有被跟踪实例的地址列表。
    *   `gum_instance_tracker_walk_instances`:  遍历所有被跟踪的实例，并对每个实例调用用户提供的回调函数，传递实例的地址、引用计数（如果适用）和类型名称。

5. **动态调整跟踪 (Dynamic Tracking Adjustment):**
    *   `gum_instance_tracker_begin`:  开始跟踪实例的创建和销毁。需要提供一个 `GumInstanceVTable` 结构，其中包含了创建和销毁实例的函数指针。如果未提供，则默认使用 GObject 的相关函数。
    *   `gum_instance_tracker_end`:  停止跟踪实例。

**与逆向方法的关系及举例说明:**

*   **动态分析 (Dynamic Analysis):** `guminstancetracker.c` 是一个典型的动态分析工具组件。逆向工程师可以通过它来观察程序运行时对象的创建和销毁，理解程序的内部状态和行为。
    *   **举例:** 逆向一个使用了大量对象的 C++ 程序时，可以使用 Frida 脚本加载 `guminstancetracker`，并设置跟踪特定类的实例。通过观察这些实例的创建和销毁时机，可以推断出对象之间的关系、资源的生命周期管理方式等。

*   **内存布局分析 (Memory Layout Analysis):**  通过跟踪实例的地址，可以帮助逆向工程师理解内存的布局方式，例如对象是否在堆上分配，以及相同类型的对象是否分配在连续的内存区域。
    *   **举例:** 逆向一个恶意软件时，可以使用 `guminstancetracker` 跟踪特定数据结构实例的分配，观察其地址变化，判断是否存在堆喷射等内存攻击行为。

*   **理解对象生命周期 (Understanding Object Lifecycles):**  清晰地了解对象的创建和销毁时机对于理解程序的逻辑至关重要。例如，可以帮助识别内存泄漏问题，或者理解某个操作是否会导致不期望的对象被释放。
    *   **举例:** 逆向一个使用了 GObject 框架的应用程序时，可以使用 `guminstancetracker` 跟踪特定 GObject 类型的实例，观察其 `ref_count` 的变化和最终的销毁，从而理解对象的引用计数管理机制。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明:**

*   **二进制代码 Hook (Binary Code Hooking):** `guminstancetracker` 的核心机制是使用 Frida 的 `GumInterceptor` 来 hook 函数。这涉及到在运行时修改目标进程的二进制代码，将目标函数的入口地址替换为 Frida 的 hook 函数地址。
    *   **举例:**  当 `gum_instance_tracker_begin` 被调用时，如果目标是 `g_type_create_instance`，Frida 会在目标进程中找到 `g_type_create_instance` 的地址，并修改该地址处的指令，跳转到 `gum_instance_tracker_on_leave` 函数。

*   **函数调用约定 (Calling Conventions):** Frida 需要理解目标平台的函数调用约定（例如 x86-64 的 System V ABI，ARM64 的 AAPCS），才能正确地获取被 hook 函数的参数和返回值。`gum_invocation_context_get_nth_argument` 和 `gum_invocation_context_get_return_value` 的实现依赖于这些知识。
    *   **举例:** 在 `gum_instance_tracker_on_enter` 中，`gum_invocation_context_get_nth_argument(context, 0)` 假设实例指针是创建或销毁函数的第一个参数，这符合常见的 C/C++ 函数调用约定。

*   **GObject 框架 (GObject Framework):** 代码中大量使用了 GObject 相关的类型和函数 (如 `GType`, `GObject`, `g_type_create_instance`, `g_type_free_instance`, `g_type_name`)。这表明 `guminstancetracker` 默认针对的是使用了 GObject 框架的程序，例如 GNOME 桌面环境下的应用程序或者部分 Android 框架。
    *   **举例:**  代码会尝试通过模块名查找 "gobject-2.0" 来动态获取 GObject 的函数指针。`gum_instance_tracker_fill_vtable_if_module_is_gobject` 函数就体现了这一点。

*   **进程内存管理 (Process Memory Management):**  跟踪实例需要理解进程的内存布局，特别是堆的分配和释放机制。`gum_hash_table` 的使用依赖于底层的内存分配器。
    *   **举例:**  `instances_ht` 哈希表存储了指向堆上分配的对象实例的指针。

**逻辑推理的假设输入与输出:**

假设用户使用 Frida 脚本，并进行以下操作：

1. 创建一个 `GumInstanceTracker` 对象。
2. 调用 `gum_instance_tracker_begin`，但不提供自定义的 `vtable`，因此默认会 hook `g_type_create_instance` 和 `g_type_free_instance`。
3. 目标程序中创建了一个 `GObject` 类型的实例，例如 `GtkWidget`。
4. 目标程序中销毁了这个 `GtkWidget` 实例。

**假设输入:**

*   Frida 脚本中 `gum_instance_tracker_begin` 被成功调用。
*   目标进程中 `g_type_create_instance` 被调用，参数指向 `GtkWidget` 的类型信息。
*   目标进程中 `g_type_free_instance` 被调用，参数指向之前创建的 `GtkWidget` 实例的地址。

**假设输出:**

*   在 `g_type_create_instance` 被 hook 到之后，`gum_instance_tracker_on_leave` 会被调用。
*   `gum_instance_tracker_add_instance` 会被调用，将 `GtkWidget` 实例的地址和类型添加到 `instances_ht` 和 `counter_ht` 中。`counter_ht` 中 `GtkWidget` 类型的计数会增加 1。
*   在 `g_type_free_instance` 被 hook 到之后，`gum_instance_tracker_on_enter` 会被调用。
*   `gum_instance_tracker_remove_instance` 会被调用，将该 `GtkWidget` 实例从 `instances_ht` 中移除，并更新 `counter_ht`，使 `GtkWidget` 类型的计数减少 1。
*   如果之后调用 `gum_instance_tracker_peek_total_count` 查询 `GtkWidget` 类型的实例数量，在创建后会返回 1，在销毁后会返回 0。

**涉及用户或编程常见的使用错误及举例说明:**

1. **忘记调用 `gum_instance_tracker_begin` 或 `gum_instance_tracker_end`:** 如果用户忘记调用 `gum_instance_tracker_begin`，则不会进行任何 hook，也无法跟踪实例。如果忘记调用 `gum_instance_tracker_end`，则 hook 会一直存在，可能会影响目标程序的性能或稳定性。
    *   **例子:** 用户编写 Frida 脚本，创建了 `GumInstanceTracker` 对象，但直接调用了 `gum_instance_tracker_peek_instances`，期望看到实例列表，但实际上列表为空，因为跟踪还未开始。

2. **提供错误的 `GumInstanceVTable`:** 如果用户想要跟踪的不是 GObject 类型的实例，就需要提供自定义的 `GumInstanceVTable`，其中包含正确的创建和销毁函数指针。如果提供的函数指针错误，会导致 hook 失败或跟踪错误的对象。
    *   **例子:** 用户尝试跟踪一个自定义 C++ 类的实例，但提供的 `create_instance` 函数指针指向了错误的函数，导致 `guminstancetracker` 无法正确捕获实例的创建。

3. **类型过滤函数 (`type_filter_func`) 实现错误:** 如果用户设置了类型过滤函数，但该函数实现有误，可能会导致漏掉需要跟踪的实例，或者跟踪了不应该跟踪的实例。
    *   **例子:** 用户编写了一个类型过滤函数，只允许跟踪名称包含 "MyObject" 的类型，但是由于字符串匹配的错误，导致部分名称为 "MyObjectDerived" 的子类实例没有被跟踪到。

4. **在不安全的时间访问跟踪数据:** 由于 `guminstancetracker` 使用了互斥锁 (`GMutex`) 来保护内部数据结构，用户在多线程环境下直接访问 `counter_ht` 或 `instances_ht` 可能会导致竞争条件。应该使用提供的 API 函数（如 `gum_instance_tracker_peek_total_count` 和 `gum_instance_tracker_walk_instances`）来安全地访问数据。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本，目标是分析某个应用程序的运行时对象。
2. **引入 `GumInstanceTracker`:**  在脚本中，用户会创建一个 `GumInstanceTracker` 的实例，以便开始跟踪对象的生命周期。这通常通过 `Java.use` 或 `Module.load` 等 Frida API 来加载和使用 `guminstancetracker` 相关的模块。
3. **调用 `gum_instance_tracker_begin`:** 用户会调用 `gum_instance_tracker_begin` 函数来启动跟踪。在这个步骤，Frida 内部会调用 `guminstancetracker.c` 中的 `gum_instance_tracker_begin` 函数。如果用户没有提供自定义的 `vtable`，则会尝试自动检测 GObject 相关的函数。
4. **目标程序执行对象创建/销毁操作:** 当目标程序执行代码，调用到被 hook 的函数（例如 `g_type_create_instance` 或 `g_type_free_instance`）时，Frida 的拦截机制会生效，并将执行流导向 `guminstancetracker.c` 中定义的 hook 回调函数 (`gum_instance_tracker_on_enter` 或 `gum_instance_tracker_on_leave`)。
5. **回调函数执行:** 在回调函数中，`guminstancetracker.c` 会记录实例的创建或销毁信息，更新内部的数据结构 (`instances_ht`, `counter_ht`)。
6. **用户查询跟踪结果:** 用户可能会在脚本中调用 `gum_instance_tracker_peek_total_count` 或 `gum_instance_tracker_walk_instances` 等函数来查看当前跟踪到的实例信息。这些调用会读取 `guminstancetracker.c` 中维护的数据。

**作为调试线索:**

*   如果在调试 Frida 脚本时，发现对象跟踪功能没有按预期工作，可以检查以下几个方面：
    *   **是否正确调用了 `gum_instance_tracker_begin`？**
    *   **对于非 GObject 程序，是否提供了正确的 `GumInstanceVTable`？**
    *   **类型过滤函数是否正确实现了预期的过滤逻辑？**
    *   **目标程序是否真的调用了被 hook 的函数？** 可以通过 Frida 的 `Interceptor.attach` 功能来验证目标函数是否被调用。
    *   **是否存在多线程竞争导致数据不一致？**  需要确保对跟踪数据的访问是线程安全的。

通过理解 `guminstancetracker.c` 的功能和实现原理，可以更有效地使用 Frida 进行动态分析和逆向工程，并能更好地定位和解决相关的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/guminstancetracker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminstancetracker.h"

#include "guminterceptor.h"
#include "gumprocess.h"

typedef enum _FunctionId FunctionId;

struct _GumInstanceTracker
{
  GObject parent;

  gboolean disposed;

  GMutex mutex;
  GHashTable * counter_ht;
  GHashTable * instances_ht;
  GumInterceptor * interceptor;

  gboolean is_active;
  GumInstanceVTable vtable;

  GumFilterInstanceTypeFunc type_filter_func;
  gpointer type_filter_func_user_data;
};

enum _FunctionId
{
  FUNCTION_ID_CREATE_INSTANCE,
  FUNCTION_ID_FREE_INSTANCE
};

#define GUM_INSTANCE_TRACKER_LOCK() g_mutex_lock (&self->mutex)
#define GUM_INSTANCE_TRACKER_UNLOCK() g_mutex_unlock (&self->mutex)

#define COUNTER_TABLE_GET(gtype) GPOINTER_TO_UINT (g_hash_table_lookup (\
    self->counter_ht, GUINT_TO_POINTER (gtype)))
#define COUNTER_TABLE_SET(gtype, count) g_hash_table_insert (\
    self->counter_ht, GUINT_TO_POINTER (gtype), GUINT_TO_POINTER (count))

static void gum_instance_tracker_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_instance_tracker_dispose (GObject * object);
static void gum_instance_tracker_finalize (GObject * object);

static void gum_instance_tracker_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_instance_tracker_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

G_DEFINE_TYPE_EXTENDED (GumInstanceTracker,
                        gum_instance_tracker,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_instance_tracker_listener_iface_init))

static void
gum_instance_tracker_class_init (GumInstanceTrackerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose = gum_instance_tracker_dispose;
  gobject_class->finalize = gum_instance_tracker_finalize;
}

static void
gum_instance_tracker_listener_iface_init (gpointer g_iface,
                                          gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_instance_tracker_on_enter;
  iface->on_leave = gum_instance_tracker_on_leave;
}

static void
gum_instance_tracker_init (GumInstanceTracker * self)
{
  g_mutex_init (&self->mutex);

  self->counter_ht = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, NULL);
  g_assert (self->counter_ht != NULL);

  self->instances_ht = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, NULL);

  self->interceptor = gum_interceptor_obtain ();
}

static void
gum_instance_tracker_dispose (GObject * object)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    if (self->is_active)
      gum_instance_tracker_end (self);

    g_object_unref (self->interceptor);

    g_hash_table_unref (self->counter_ht);
    self->counter_ht = NULL;

    g_hash_table_unref (self->instances_ht);
    self->instances_ht = NULL;
  }

  G_OBJECT_CLASS (gum_instance_tracker_parent_class)->dispose (object);
}

static void
gum_instance_tracker_finalize (GObject * object)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER (object);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_instance_tracker_parent_class)->finalize (object);
}

GumInstanceTracker *
gum_instance_tracker_new (void)
{
  return g_object_new (GUM_TYPE_INSTANCE_TRACKER, NULL);
}

static gboolean
gum_instance_tracker_fill_vtable_if_module_is_gobject (
    const GumModuleDetails * details,
    gpointer user_data)
{
  GumInstanceTracker * self;
  GumInstanceVTable * vtable;
  gchar * name_lowercase;

  self = GUM_INSTANCE_TRACKER (user_data);
  vtable = &self->vtable;

  name_lowercase = g_ascii_strdown (details->name, -1);

  if (g_strstr_len (name_lowercase, -1, "gobject-2.0") != NULL)
  {
#define GUM_ASSIGN(type, field, name) \
    vtable->field = GUM_POINTER_TO_FUNCPTR (type, \
        gum_module_find_export_by_name (details->path, G_STRINGIFY (name)))

    GUM_ASSIGN (GumCreateInstanceFunc, create_instance, g_type_create_instance);
    GUM_ASSIGN (GumFreeInstanceFunc, free_instance, g_type_free_instance);
    GUM_ASSIGN (GumTypeIdToNameFunc, type_id_to_name, g_type_name);

#undef GUM_ASSIGN
  }

  g_free (name_lowercase);

  return TRUE;
}

void
gum_instance_tracker_begin (GumInstanceTracker * self,
                            GumInstanceVTable * vtable)
{
  g_assert (!self->is_active);

  if (vtable != NULL)
  {
    self->vtable = *vtable;
  }
  else
  {
    gum_process_enumerate_modules (
        gum_instance_tracker_fill_vtable_if_module_is_gobject, self);

    if (self->vtable.create_instance == NULL)
    {
      self->vtable.create_instance = g_type_create_instance;
      self->vtable.free_instance = g_type_free_instance;
      self->vtable.type_id_to_name = g_type_name;
    }
  }

  gum_interceptor_begin_transaction (self->interceptor);

  gum_interceptor_attach (self->interceptor,
      GUM_FUNCPTR_TO_POINTER (self->vtable.create_instance),
      GUM_INVOCATION_LISTENER (self),
      GUINT_TO_POINTER (FUNCTION_ID_CREATE_INSTANCE));

  gum_interceptor_attach (self->interceptor,
      GUM_FUNCPTR_TO_POINTER (self->vtable.free_instance),
      GUM_INVOCATION_LISTENER (self),
      GUINT_TO_POINTER (FUNCTION_ID_FREE_INSTANCE));

  gum_interceptor_end_transaction (self->interceptor);

  self->is_active = TRUE;
}

void
gum_instance_tracker_end (GumInstanceTracker * self)
{
  g_assert (self->is_active);

  gum_interceptor_detach (self->interceptor, GUM_INVOCATION_LISTENER (self));

  self->is_active = FALSE;
}

const GumInstanceVTable *
gum_instance_tracker_get_current_vtable (GumInstanceTracker * self)
{
  return &self->vtable;
}

void
gum_instance_tracker_set_type_filter_function (GumInstanceTracker * self,
                                               GumFilterInstanceTypeFunc filter,
                                               gpointer user_data)
{
  self->type_filter_func = filter;
  self->type_filter_func_user_data = user_data;
}

guint
gum_instance_tracker_peek_total_count (GumInstanceTracker * self,
                                       const gchar * type_name)
{
  guint result = 0;

  if (type_name != NULL)
  {
    GType gtype = g_type_from_name (type_name);

    if (gtype != 0)
    {
      GUM_INSTANCE_TRACKER_LOCK ();
      result = COUNTER_TABLE_GET (gtype);
      GUM_INSTANCE_TRACKER_UNLOCK ();
    }
  }
  else
  {
    GUM_INSTANCE_TRACKER_LOCK ();
    result = g_hash_table_size (self->instances_ht);
    GUM_INSTANCE_TRACKER_UNLOCK ();
  }

  return result;
}

GList *
gum_instance_tracker_peek_instances (GumInstanceTracker * self)
{
  GList * result;

  GUM_INSTANCE_TRACKER_LOCK ();
  result = g_hash_table_get_keys (self->instances_ht);
  GUM_INSTANCE_TRACKER_UNLOCK ();

  return result;
}

void
gum_instance_tracker_walk_instances (GumInstanceTracker * self,
                                     GumWalkInstanceFunc func,
                                     gpointer user_data)
{
  GHashTableIter iter;
  gpointer key, value;
  GType gobject_type;

  gobject_type = G_TYPE_OBJECT;

  GUM_INSTANCE_TRACKER_LOCK ();

  g_hash_table_iter_init (&iter, self->instances_ht);
  while (g_hash_table_iter_next (&iter, &key, &value))
  {
    const GTypeInstance * instance = (const GTypeInstance *) key;
    GType type;
    GumInstanceDetails details;

    type = G_TYPE_FROM_INSTANCE (instance);

    details.address = instance;
    if (g_type_is_a (type, gobject_type))
      details.ref_count = ((const GObject *) instance)->ref_count;
    else
      details.ref_count = 1;
    details.type_name = self->vtable.type_id_to_name (type);

    func (&details, user_data);
  }

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

void
gum_instance_tracker_add_instance (GumInstanceTracker * self,
                                   gpointer instance,
                                   GType instance_type)
{
  guint count;

  if (instance_type == G_TYPE_FROM_INSTANCE (self))
    return;

  if (self->type_filter_func != NULL)
  {
    if (!self->type_filter_func (self, instance_type,
        self->type_filter_func_user_data))
    {
      return;
    }
  }

  GUM_INSTANCE_TRACKER_LOCK ();

  g_assert (g_hash_table_lookup (self->instances_ht, instance) == NULL);
  g_hash_table_add (self->instances_ht, instance);

  count = COUNTER_TABLE_GET (instance_type);
  COUNTER_TABLE_SET (instance_type, count + 1);

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

void
gum_instance_tracker_remove_instance (GumInstanceTracker * self,
                                      gpointer instance,
                                      GType instance_type)
{
  guint count;

  GUM_INSTANCE_TRACKER_LOCK ();

  if (g_hash_table_remove (self->instances_ht, instance))
  {
    count = COUNTER_TABLE_GET (instance_type);
    if (count > 0)
      COUNTER_TABLE_SET (instance_type, count - 1);
  }

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

static void
gum_instance_tracker_on_enter (GumInvocationListener * listener,
                               GumInvocationContext * context)
{
  GumInstanceTracker * self;
  FunctionId function_id;

  self = GUM_INSTANCE_TRACKER (listener);
  function_id = GPOINTER_TO_INT (
      gum_invocation_context_get_listener_function_data (context));

  if (function_id == FUNCTION_ID_FREE_INSTANCE)
  {
    GTypeInstance * instance;
    GType gtype;

    instance = (GTypeInstance *)
        gum_invocation_context_get_nth_argument (context, 0);
    gtype = G_TYPE_FROM_INSTANCE (instance);

    gum_instance_tracker_remove_instance (self, instance, gtype);
  }
}

static void
gum_instance_tracker_on_leave (GumInvocationListener * listener,
                               GumInvocationContext * context)
{
  GumInstanceTracker * self;
  FunctionId function_id;

  self = GUM_INSTANCE_TRACKER (listener);
  function_id = GPOINTER_TO_INT (
      gum_invocation_context_get_listener_function_data (context));

  if (function_id == FUNCTION_ID_CREATE_INSTANCE)
  {
    GTypeInstance * instance;
    GType gtype;

    instance = (GTypeInstance *)
        gum_invocation_context_get_return_value (context);
    gtype = G_TYPE_FROM_INSTANCE (instance);

    gum_instance_tracker_add_instance (self, instance, gtype);
  }
}

"""

```