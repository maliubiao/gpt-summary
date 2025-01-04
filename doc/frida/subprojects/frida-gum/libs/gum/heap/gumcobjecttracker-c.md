Response:
Let's break down the thought process for analyzing this C code for Frida's `gumcobjecttracker.c`.

**1. Initial Understanding of the Goal:**

The request asks for a breakdown of the file's functionality, its relation to reverse engineering, its interaction with lower-level concepts (binary, Linux, Android), logical reasoning, common user errors, and how a user reaches this code during debugging. Essentially, "explain what this code *does* and *how it fits* into the bigger picture of Frida."

**2. High-Level Code Scan and Identification of Key Structures:**

The first step is a quick scan to identify the major data structures and functions. I see:

* `GumCObjectTracker`: The central structure, likely managing the tracking.
* `ObjectType`:  Represents a type of tracked object.
* `CObjectFunctionContext`: Information about hooking specific functions.
* `CObjectThreadContext`: Thread-local data for tracking.
* `GumInterceptor`: A crucial Frida component for function hooking.
* `GumBacktracer`:  For capturing call stacks.
* `GHashTable`: Used for storing types and tracked objects.
* `GMutex`: For thread safety.
* `*_enter_handler` and `*_leave_handler`: Callback functions for when tracked functions are entered or exited.

This immediately gives a strong hint: This code is about *tracking the lifecycle of C objects*.

**3. Deconstructing the Functionality - What does it *do*?**

Now, I examine the key functions and their interactions:

* **`gum_cobject_tracker_new` and `gum_cobject_tracker_new_with_backtracer`:** These are constructors, creating instances of the tracker. The latter allows attaching a `GumBacktracer`.
* **`gum_cobject_tracker_track`:**  This is the core function for telling the tracker *what* to track. It takes a `type_name` and `type_constructor` function pointer. This suggests that it hooks the constructor of a specific C object type.
* **`gum_cobject_tracker_attach_to_function`:**  A lower-level function that's used by `gum_cobject_tracker_track` and directly for `free` and `g_slice_free1`. This clearly establishes the function hooking mechanism.
* **`gum_cobject_tracker_on_enter` and `gum_cobject_tracker_on_leave`:** These are the *callbacks* invoked when a tracked function is entered or exited. They retrieve the `CObjectFunctionContext` and call the specific handlers.
* **`on_constructor_enter_handler` and `on_constructor_leave_handler`:**  These are specific handlers for object construction. The `enter` handler creates a `GumCObject` instance, potentially capturing the backtrace. The `leave` handler gets the allocated address and adds it to the `objects_ht`.
* **`on_free_enter_handler` and `on_g_slice_free1_enter_handler`:** Handlers for memory deallocation. They remove the object from `objects_ht`.
* **`gum_cobject_tracker_peek_total_count` and `gum_cobject_tracker_peek_object_list`:** These provide ways to inspect the tracked objects and their counts. They use locking to ensure thread safety.
* **`gum_cobject_tracker_begin` and `gum_cobject_tracker_end`:** Currently empty, but likely intended for future use, perhaps for batch operations or marking a tracking scope.
* **`gum_cobject_tracker_dispose` and `gum_cobject_tracker_finalize`:**  Cleanup functions to release resources.

**4. Connecting to Reverse Engineering:**

With the functionality understood, I consider how it's relevant to reverse engineering:

* **Dynamic Analysis:** The core idea of tracking object creation and destruction is central to dynamic analysis. Knowing when and where objects are allocated and freed can reveal memory management patterns, identify leaks, and understand object lifecycles.
* **Understanding Object Interactions:** By hooking constructors and destructors, you can infer relationships between objects.
* **Identifying Vulnerabilities:** Tracking memory allocation/deallocation can help pinpoint potential double-frees, use-after-frees, or other memory corruption issues.
* **Tracing Program Flow:**  Knowing which objects are being created and destroyed during specific operations helps in understanding program flow.

I then create concrete examples, like tracing the lifecycle of a `NSString` in Objective-C (even though this is C code, the *concept* is transferable) or a custom C++ object.

**5. Linking to Binary/Kernel Concepts:**

Now, I think about the lower-level aspects:

* **Binary Instrumentation:** Frida's core mechanism is binary instrumentation, and this code leverages it via `GumInterceptor`. Mentioning the need to inject code into a running process is important.
* **Function Hooking:**  The `gum_interceptor_attach` function directly relates to how Frida intercepts function calls at the binary level.
* **Memory Management (Linux/Android):** Functions like `free` and `g_slice_free1` are fundamental memory management functions in C and commonly used in Linux/Android environments. The tracker's interaction with these functions is a direct tie-in.
* **Call Stacks (Backtracer):** The `GumBacktracer` usage connects to the ability to inspect the call stack, a crucial debugging and reverse engineering technique. This involves understanding how the CPU stores return addresses.

**6. Logical Reasoning - Assumptions and Outputs:**

For logical reasoning, I consider a simple scenario: tracking a hypothetical `MyObject`. I trace the execution flow from calling `gum_cobject_tracker_track` to the handlers being invoked during construction and destruction. I then illustrate the output of `gum_cobject_tracker_peek_total_count` and `gum_cobject_tracker_peek_object_list`.

**7. Common User Errors:**

Thinking about how a *user* would interact with this code (through Frida's API, of course), I identify potential errors:

* **Incorrect Type Name:**  A typo would result in no objects being tracked.
* **Incorrect Constructor:**  Hooking the wrong function wouldn't capture object creation.
* **Forgetting to Track:**  Simply not calling `gum_cobject_tracker_track` is a basic oversight.
* **Assuming Immediate Tracking:** Users need to understand that tracking happens *during* the execution after the hook is set.

**8. Tracing User Interaction (Debugging Clues):**

Finally, I consider how a developer using Frida might end up looking at this specific source file. The scenario involves a user wanting to track object allocations, leading them to the Frida documentation for `CObjectTracker`. If they encounter issues (like not seeing the objects they expect), they might delve into the source code to understand the implementation details, examining `gumcobjecttracker.c` to see how the tracking works. This includes setting breakpoints within this code to understand the data flow.

**Self-Correction/Refinement During the Process:**

* **Initial Focus Might Be Too Narrow:**  I might initially focus too much on individual functions. I then realize the importance of describing the overall *goal* and *how the pieces fit together*.
* **Clarity of Examples:** I need to ensure the examples are clear and concrete, illustrating the concepts effectively. Generic examples are less helpful than showing the flow with a specific (even if hypothetical) object type.
* **Balancing Detail:** I need to provide enough detail to be informative but avoid getting bogged down in extremely low-level implementation details of Frida's internals (unless specifically asked). The focus should remain on the functionality and its relevance.
* **Addressing All Aspects of the Prompt:**  I double-check the prompt to ensure I've addressed all the requested points (functionality, reverse engineering, binary/kernel, logic, errors, debugging).

By following this structured approach, combining code analysis with an understanding of the broader context of Frida and reverse engineering, I can produce a comprehensive and informative explanation of the `gumcobjecttracker.c` file.
This C source file, `gumcobjecttracker.c`, which is part of the Frida dynamic instrumentation toolkit, implements a mechanism for **tracking the lifecycle of C objects**. It allows Frida to monitor the creation and destruction of specific types of C objects within a target process.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Object Type Tracking:**
   - It maintains a registry of object types to track, storing the type name and a count of currently alive objects of that type (`types_ht`).
   - The `gum_cobject_tracker_track` function is the primary way to register a new object type for tracking. It takes the type name and the address of the type's constructor function.

2. **Object Instance Tracking:**
   - It keeps track of individual instances of the registered object types that are currently alive (`objects_ht`). The key in this hash table is the memory address of the object.
   - When a tracked constructor function is entered and exited, the tracker adds the newly created object's address to this table.
   - When a tracked destructor function (like `free` or `g_slice_free1`) is entered, the tracker removes the object's address from this table.

3. **Function Interception:**
   - It uses Frida's `GumInterceptor` to hook the constructor and destructor functions of the tracked object types.
   - The `gum_cobject_tracker_attach_to_function` function handles the attaching of these hooks.
   - It defines `enter` and `leave` handlers for these hooked functions to perform actions before and after the original function call.

4. **Constructor/Destructor Handling:**
   - **Constructor (`on_constructor_enter_handler`, `on_constructor_leave_handler`):**
     - When a tracked constructor is entered, it creates a `GumCObject` structure to represent the object being created and stores the object's type information.
     - If a `GumBacktracer` is configured, it captures the call stack at the point of construction.
     - When the constructor exits, it retrieves the allocated memory address (the return value of the constructor) and adds the `GumCObject` to the `objects_ht`.
   - **Destructor (`on_free_enter_handler`, `on_g_slice_free1_enter_handler`):**
     - When a tracked destructor (`free` or `g_slice_free1`) is entered, it retrieves the memory address being freed and removes the corresponding object from the `objects_ht`.

5. **Information Retrieval:**
   - `gum_cobject_tracker_peek_total_count`: Allows querying the number of live objects for a specific tracked type or the total number of tracked objects.
   - `gum_cobject_tracker_peek_object_list`: Provides a list of all currently tracked `GumCObject` instances, including their addresses and types.

6. **Thread Safety:**
   - It uses a `GMutex` (`mutex`) to protect access to the shared data structures (`types_ht` and `objects_ht`), ensuring thread safety when multiple threads in the target process are creating or destroying objects.

7. **Backtracing (Optional):**
   - It can optionally integrate with Frida's `GumBacktracer` to capture the call stack when objects are created. This can be invaluable for understanding where objects are being allocated and for debugging memory leaks.

**Relationship to Reverse Engineering:**

This code is directly related to dynamic reverse engineering techniques. By tracking object lifecycles, reverse engineers can gain insights into:

* **Object Creation Patterns:** Identify when and where specific types of objects are being created. This can help in understanding the program's logic and data structures.
* **Memory Management:** Observe how memory is being allocated and deallocated for specific object types. This is crucial for identifying potential memory leaks, double-frees, or use-after-free vulnerabilities.
* **Object Relationships:** By tracking the creation and destruction of related objects, one can infer relationships and dependencies between different parts of the program.
* **Identifying Key Data Structures:**  Tracking objects can reveal the underlying data structures used by the application. For example, tracking allocation and deallocation of a custom object might reveal the structure of a linked list or a tree.

**Example:**

Imagine you are reverse engineering a C application that uses a custom data structure called `MyData`. You want to know when instances of `MyData` are being created and destroyed.

1. **Identify the Constructor:** You find the function responsible for allocating and initializing `MyData`, let's say it's called `create_my_data`.
2. **Identify the Destructor:** You find the function responsible for freeing `MyData`, which is likely `free`.
3. **Use Frida to Track:** You would use Frida's scripting API to interact with `GumCObjectTracker`:

   ```python
   import frida

   session = frida.attach("target_process")
   script = session.create_script("""
       const tracker = new Frida.CObjectTracker();

       const createMyDataPtr = Module.findExportByName(null, 'create_my_data');
       tracker.track('MyData', createMyDataPtr);

       Interceptor.attach(Module.findExportByName(null, 'free'), {
           onEnter: function (args) {
               tracker.remove(args[0]); // Manually removing, though tracker hooks free already
           }
       });
   """)
   script.load()

   # ... run the application ...

   console.log(tracker.liveObjects());
   """)
   ```

   This script would:
   - Create a `CObjectTracker` instance.
   - Track objects of type "MyData" by hooking the `create_my_data` function.
   - (Optionally) Manually hook `free` to remove tracked objects (though the `gumcobjecttracker` already handles this for standard `free`).
   - After the application runs, you can inspect `tracker.liveObjects()` to see the currently allocated `MyData` objects.

**Binary/Kernel/Android Knowledge:**

* **Binary Instrumentation:** The entire concept relies on Frida's ability to perform binary instrumentation, which involves modifying the executable code of a running process in memory. This requires understanding of executable formats (like ELF on Linux, Mach-O on macOS, PE on Windows, and their Android counterparts like DEX/ART).
* **Function Pointers and Calling Conventions:**  The code manipulates function pointers (`type_constructor`, `free`, `g_slice_free1`) and relies on understanding the calling conventions of the target architecture (e.g., x86, ARM) to correctly intercept function calls and access arguments.
* **Memory Management (Linux/Android):** It directly interacts with standard C memory management functions like `free` and `g_slice_free1` (a GLib function). Understanding how these allocators work at a lower level (e.g., using `malloc` internally, managing memory heaps) can be helpful for deeper analysis.
* **Kernel Interaction (Indirect):** While this code doesn't directly interact with the kernel, Frida itself relies on kernel-level mechanisms (like ptrace on Linux or debugging APIs on other platforms) to perform instrumentation and inject code.
* **Android Framework (Indirect):**  On Android, the principles are the same, but the specific libraries and allocation patterns might differ (e.g., using `new`/`delete` for C++, or Java object allocation). While this specific C code focuses on C-style allocations, the concept extends to other languages and frameworks.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

1. Frida is attached to a process.
2. The `gum_cobject_tracker_track` function is called with `type_name = "MyWidget"` and `type_constructor` pointing to the address of the `create_my_widget` function.
3. The `create_my_widget` function is called three times within the target process.
4. The `free` function is called once with the address of one of the created `MyWidget` instances.

**Hypothetical Output:**

- `gum_cobject_tracker_peek_total_count("MyWidget")` would return `2`.
- `gum_cobject_tracker_peek_total_count(NULL)` would return `2` (assuming only `MyWidget` is tracked).
- `gum_cobject_tracker_peek_object_list()` would return a list containing two `GumCObject` instances, both with `type_name = "MyWidget"` and their respective memory addresses. The `return_addresses` in each `GumCObject` would contain the captured call stack at the point of their creation.

**User/Programming Errors:**

1. **Incorrect Type Name:** If the user provides an incorrect `type_name` to `gum_cobject_tracker_track`, the tracker will not be able to find and update the count for that type. For example, if the actual type is "MyWidget" but the user enters "MyWidjet", no objects will be tracked under that name.

2. **Incorrect Constructor Address:** Providing the wrong address for the `type_constructor` will prevent the tracker from intercepting the object creation. This will result in no objects being added to the `objects_ht`.

3. **Forgetting to Track Destructors (or Incorrect Destructor Hooking):** If the user only tracks the constructor but not the destructor (or hooks the wrong destructor function), the `objects_ht` will grow indefinitely, leading to an inaccurate count of live objects and potentially a memory leak within the tracking mechanism itself.

4. **Assuming Immediate Tracking:** Users might mistakenly assume that once `gum_cobject_tracker_track` is called, all past instances of the object are tracked. The tracker only starts monitoring objects created *after* the hook is established.

**User Operations to Reach This Code (Debugging Clues):**

A user would typically encounter this code while:

1. **Developing a Frida script for dynamic analysis.** They might be using Frida's JavaScript API and interacting with `Frida.CObjectTracker`.
2. **Debugging issues with their Frida script related to object tracking.** If the script isn't tracking objects correctly, or if the counts are inaccurate, they might delve into the Frida source code to understand how `CObjectTracker` works internally.
3. **Contributing to Frida.** Developers working on Frida itself would be directly interacting with and modifying this code.
4. **Using a higher-level Frida module that internally uses `CObjectTracker`.**  They might not be directly aware of this code, but if they encounter issues with that module's object tracking functionality, they might need to investigate the underlying implementation.

**Steps to Reach Here as a Debugger:**

1. **Set Breakpoints:** A developer might set breakpoints in their Frida script where they interact with `Frida.CObjectTracker` methods (e.g., `track`, `liveObjects`).
2. **Step Through Frida's JavaScript Bindings:** They would step through the JavaScript code to see how it calls into the native Frida code.
3. **Trace Native Function Calls:** Using a debugger like GDB (for native code), they would trace the execution from the JavaScript bindings into the C++ code of Frida, eventually reaching the relevant functions in `gumcobjecttracker.c`.
4. **Examine Data Structures:** They would inspect the values of the data structures (`types_ht`, `objects_ht`) to understand the current state of the tracked objects.
5. **Analyze Call Stacks:** When a constructor or destructor is hit, they might examine the call stack to understand how the execution reached that point and verify that the hooks are working correctly.

In summary, `gumcobjecttracker.c` is a crucial component of Frida that enables powerful dynamic analysis by providing a robust and flexible mechanism for tracking the lifecycle of C objects within a target process. It leverages Frida's instrumentation capabilities to intercept function calls and maintain a real-time view of object creation and destruction.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/gumcobjecttracker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcobjecttracker.h"

#include "gumcobject.h"
#include "guminterceptor.h"

#include <stdlib.h>
#include <string.h>

#define GUM_COBJECT_TRACKER_CAST(o) ((GumCObjectTracker *) (o))

typedef struct _ObjectType             ObjectType;
typedef struct _CObjectFunctionContext CObjectFunctionContext;
typedef struct _CObjectThreadContext   CObjectThreadContext;
typedef struct _CObjectHandlers        CObjectHandlers;

typedef void (* CObjectEnterHandler) (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
typedef void (* CObjectLeaveHandler) (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);

struct _GumCObjectTracker
{
  GObject parent;

  gboolean disposed;

  GMutex mutex;
  GHashTable * types_ht;
  GHashTable * objects_ht;
  GumInterceptor * interceptor;
  GPtrArray * function_contexts;

  GumBacktracerInterface * backtracer_iface;
  GumBacktracer * backtracer_instance;
};

enum
{
  PROP_0,
  PROP_BACKTRACER,
};

struct _ObjectType
{
  gchar * name;
  guint count;
};

struct _CObjectHandlers
{
  CObjectEnterHandler enter_handler;
  CObjectLeaveHandler leave_handler;
};

struct _CObjectThreadContext
{
  gpointer data;
};

struct _CObjectFunctionContext
{
  CObjectHandlers handlers;
  gpointer context;
};

#define GUM_COBJECT_TRACKER_LOCK() g_mutex_lock (&self->mutex)
#define GUM_COBJECT_TRACKER_UNLOCK() g_mutex_unlock (&self->mutex)

static void gum_cobject_tracker_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_cobject_tracker_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_cobject_tracker_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_cobject_tracker_dispose (GObject * object);
static void gum_cobject_tracker_finalize (GObject * object);

static ObjectType * object_type_new (const gchar * name);
static void object_type_free (ObjectType * t);

static void gum_cobject_tracker_add_object (GumCObjectTracker * self,
    GumCObject * cobject);
static void gum_cobject_tracker_maybe_remove_object (GumCObjectTracker * self,
    gpointer address);

static void gum_cobject_tracker_attach_to_function (GumCObjectTracker * self,
    gpointer function_address, const CObjectHandlers * handlers,
    gpointer context);

static void gum_cobject_tracker_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_cobject_tracker_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static void on_constructor_enter_handler (GumCObjectTracker * self,
    ObjectType * object_type, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
static void on_constructor_leave_handler (GumCObjectTracker * self,
    ObjectType * object_type, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
static void on_free_enter_handler (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
static void on_g_slice_free1_enter_handler (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);

G_DEFINE_TYPE_EXTENDED (GumCObjectTracker,
                        gum_cobject_tracker,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_cobject_tracker_listener_iface_init))

static void
gum_cobject_tracker_class_init (GumCObjectTrackerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);
  GParamSpec * pspec;

  gobject_class->set_property = gum_cobject_tracker_set_property;
  gobject_class->get_property = gum_cobject_tracker_get_property;
  gobject_class->dispose = gum_cobject_tracker_dispose;
  gobject_class->finalize = gum_cobject_tracker_finalize;

  pspec = g_param_spec_object ("backtracer", "Backtracer",
      "Backtracer Implementation", GUM_TYPE_BACKTRACER,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS |
      G_PARAM_CONSTRUCT_ONLY));
  g_object_class_install_property (gobject_class, PROP_BACKTRACER, pspec);
}

static void
gum_cobject_tracker_listener_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_cobject_tracker_on_enter;
  iface->on_leave = gum_cobject_tracker_on_leave;
}

static const CObjectHandlers free_cobject_handlers =
{
  on_free_enter_handler, NULL
};

static const CObjectHandlers g_slice_free1_cobject_handlers =
{
  on_g_slice_free1_enter_handler, NULL
};

static void
gum_cobject_tracker_init (GumCObjectTracker * self)
{
  g_mutex_init (&self->mutex);

  self->types_ht = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) object_type_free);

  self->objects_ht = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, (GDestroyNotify) gum_cobject_free);

  self->interceptor = gum_interceptor_obtain ();

  self->function_contexts = g_ptr_array_new ();

  gum_interceptor_begin_transaction (self->interceptor);

  gum_cobject_tracker_attach_to_function (self,
      GUM_FUNCPTR_TO_POINTER (free),
      &free_cobject_handlers, NULL);
  gum_cobject_tracker_attach_to_function (self,
      GUM_FUNCPTR_TO_POINTER (g_slice_free1),
      &g_slice_free1_cobject_handlers, NULL);

  gum_interceptor_end_transaction (self->interceptor);
}

static void
gum_cobject_tracker_set_property (GObject * object,
                                  guint property_id,
                                  const GValue * value,
                                  GParamSpec * pspec)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      if (self->backtracer_instance != NULL)
        g_object_unref (self->backtracer_instance);
      self->backtracer_instance = g_value_dup_object (value);

      if (self->backtracer_instance != NULL)
      {
        self->backtracer_iface =
            GUM_BACKTRACER_GET_IFACE (self->backtracer_instance);
      }
      else
      {
        self->backtracer_iface = NULL;
      }

      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_cobject_tracker_get_property (GObject * object,
                                  guint property_id,
                                  GValue * value,
                                  GParamSpec * pspec)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      g_value_set_object (value, self->backtracer_instance);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_cobject_tracker_dispose (GObject * object)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_interceptor_detach (self->interceptor, GUM_INVOCATION_LISTENER (self));
    g_object_unref (self->interceptor);
    self->interceptor = NULL;

    g_clear_object (&self->backtracer_instance);
    self->backtracer_iface = NULL;

    g_hash_table_unref (self->objects_ht);
    self->objects_ht = NULL;

    g_hash_table_unref (self->types_ht);
    self->types_ht = NULL;
  }

  G_OBJECT_CLASS (gum_cobject_tracker_parent_class)->dispose (object);
}

static void
gum_cobject_tracker_finalize (GObject * object)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);

  g_ptr_array_foreach (self->function_contexts, (GFunc) g_free, NULL);
  g_ptr_array_free (self->function_contexts, TRUE);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_cobject_tracker_parent_class)->finalize (object);
}

GumCObjectTracker *
gum_cobject_tracker_new (void)
{
  return g_object_new (GUM_TYPE_COBJECT_TRACKER, NULL);
}

GumCObjectTracker *
gum_cobject_tracker_new_with_backtracer (GumBacktracer * backtracer)
{
  return g_object_new (GUM_TYPE_COBJECT_TRACKER,
      "backtracer", backtracer,
      NULL);
}

static const CObjectHandlers object_type_cobject_handlers =
{
  (CObjectEnterHandler) on_constructor_enter_handler,
  (CObjectLeaveHandler) on_constructor_leave_handler
};

void
gum_cobject_tracker_track (GumCObjectTracker * self,
                           const gchar * type_name,
                           gpointer type_constructor)
{
  ObjectType * t;

  g_assert (strlen (type_name) <= GUM_MAX_TYPE_NAME);

  t = object_type_new (type_name);
  g_hash_table_insert (self->types_ht, g_strdup (type_name), t);

  gum_cobject_tracker_attach_to_function (self, type_constructor,
      &object_type_cobject_handlers, t);
}

void
gum_cobject_tracker_begin (GumCObjectTracker * self)
{
}

void
gum_cobject_tracker_end (GumCObjectTracker * self)
{
}

guint
gum_cobject_tracker_peek_total_count (GumCObjectTracker * self,
                                      const gchar * type_name)
{
  guint result;

  GUM_COBJECT_TRACKER_LOCK ();
  gum_interceptor_ignore_current_thread (self->interceptor);

  if (type_name != NULL)
  {
    ObjectType * object_type;

    object_type = g_hash_table_lookup (self->types_ht, type_name);
    g_assert (object_type != NULL);

    result = object_type->count;
  }
  else
  {
    result = g_hash_table_size (self->objects_ht);
  }

  gum_interceptor_unignore_current_thread (self->interceptor);
  GUM_COBJECT_TRACKER_UNLOCK ();

  return result;
}

GList *
gum_cobject_tracker_peek_object_list (GumCObjectTracker * self)
{
  GList * result = NULL, * cur;

  GUM_COBJECT_TRACKER_LOCK ();
  gum_interceptor_ignore_current_thread (self->interceptor);

  result = g_hash_table_get_values (self->objects_ht);
  for (cur = result; cur != NULL; cur = cur->next)
  {
    cur->data = gum_cobject_copy ((GumCObject *) cur->data);
  }

  gum_interceptor_unignore_current_thread (self->interceptor);
  GUM_COBJECT_TRACKER_UNLOCK ();

  return result;
}

static ObjectType *
object_type_new (const gchar * name)
{
  ObjectType * t;

  t = g_new0 (ObjectType, 1);
  t->name = g_strdup (name);

  return t;
}

static void
object_type_free (ObjectType * t)
{
  g_free (t->name);
  g_free (t);
}

static void
gum_cobject_tracker_add_object (GumCObjectTracker * self,
                                GumCObject * cobject)
{
  ObjectType * object_type = cobject->data;

  GUM_COBJECT_TRACKER_LOCK ();

  g_hash_table_insert (self->objects_ht, cobject->address, cobject);
  object_type->count++;

  GUM_COBJECT_TRACKER_UNLOCK ();
}

static void
gum_cobject_tracker_maybe_remove_object (GumCObjectTracker * self,
                                         gpointer address)
{
  GumCObject * cobject;

  GUM_COBJECT_TRACKER_LOCK ();

  cobject = g_hash_table_lookup (self->objects_ht, address);
  if (cobject != NULL)
  {
    ObjectType * object_type = cobject->data;
    object_type->count--;
    g_hash_table_remove (self->objects_ht, address);
  }

  GUM_COBJECT_TRACKER_UNLOCK ();
}

static void
gum_cobject_tracker_attach_to_function (GumCObjectTracker * self,
                                        gpointer function_address,
                                        const CObjectHandlers * handlers,
                                        gpointer context)
{
  CObjectFunctionContext * function_ctx;

  function_ctx = g_new (CObjectFunctionContext, 1);
  function_ctx->handlers = *handlers;
  function_ctx->context = context;
  g_ptr_array_add (self->function_contexts, function_ctx);

  gum_interceptor_attach (self->interceptor, function_address,
      GUM_INVOCATION_LISTENER (self), function_ctx);
}

static void
gum_cobject_tracker_on_enter (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumCObjectTracker * self;
  CObjectFunctionContext * function_ctx;

  self = GUM_COBJECT_TRACKER_CAST (listener);
  function_ctx = GUM_IC_GET_FUNC_DATA (context, CObjectFunctionContext *);

  if (function_ctx->handlers.enter_handler != NULL)
  {
    function_ctx->handlers.enter_handler (self, function_ctx->context,
        GUM_IC_GET_INVOCATION_DATA (context, CObjectThreadContext), context);
  }
}

static void
gum_cobject_tracker_on_leave (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumCObjectTracker * self;
  CObjectFunctionContext * function_ctx;

  self = GUM_COBJECT_TRACKER_CAST (listener);
  function_ctx = GUM_IC_GET_FUNC_DATA (context, CObjectFunctionContext *);

  if (function_ctx->handlers.leave_handler != NULL)
  {
    function_ctx->handlers.leave_handler (self, function_ctx->context,
        GUM_IC_GET_INVOCATION_DATA (context, CObjectThreadContext), context);
  }
}

static void
on_constructor_enter_handler (GumCObjectTracker * self,
                              ObjectType * object_type,
                              CObjectThreadContext * thread_context,
                              GumInvocationContext * invocation_context)
{
  GumCObject * cobject;

  cobject = gum_cobject_new (NULL, object_type->name);
  cobject->data = object_type;

  if (self->backtracer_instance != NULL)
  {
    self->backtracer_iface->generate (self->backtracer_instance,
        invocation_context->cpu_context, &cobject->return_addresses,
        GUM_MAX_BACKTRACE_DEPTH);
  }

  thread_context->data = cobject;
}

static void
on_constructor_leave_handler (GumCObjectTracker * self,
                              ObjectType * object_type,
                              CObjectThreadContext * thread_context,
                              GumInvocationContext * invocation_context)
{
  GumCObject * cobject = (GumCObject *) thread_context->data;

  cobject->address =
      gum_invocation_context_get_return_value (invocation_context);
  gum_cobject_tracker_add_object (self, cobject);
}

static void
on_free_enter_handler (GumCObjectTracker * self,
                       gpointer handler_context,
                       CObjectThreadContext * thread_context,
                       GumInvocationContext * invocation_context)
{
  gpointer address;

  address = gum_invocation_context_get_nth_argument (invocation_context, 0);

  gum_cobject_tracker_maybe_remove_object (self, address);
}

static void
on_g_slice_free1_enter_handler (GumCObjectTracker * self,
                                gpointer handler_context,
                                CObjectThreadContext * thread_context,
                                GumInvocationContext * invocation_context)
{
  gpointer mem_block;

  mem_block = gum_invocation_context_get_nth_argument (invocation_context, 1);

  gum_cobject_tracker_maybe_remove_object (self, mem_block);
}

"""

```