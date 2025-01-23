Response:
Let's break down the thought process to analyze this C code for Frida's Gum Profiler.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this C file (`gumprofiler.c`) within the context of Frida, focusing on its relevance to reverse engineering, low-level details, logic, potential errors, and how a user might trigger its execution.

**2. Initial Scan and Keyword Spotting:**

A quick read-through reveals important terms and structures:

* **`Profiler`**:  The central entity, suggesting performance measurement.
* **`Invocation`**, **`Interceptor`**, **`Listener`**: Hints at Frida's dynamic instrumentation mechanism. Frida *intercepts* function calls.
* **`Sample`**, **`Duration`**, **`Worst Case`**:  Performance metrics.
* **`Thread`**:  Multi-threading awareness.
* **`FunctionContext`**: Information related to a specific function being profiled.
* **`SymbolUtil`**:  Resolving function names from addresses.
* **`g_mutex`**: Thread safety.
* **`GHashTable`**: Data storage, likely for function information.
* **`GArray`**, **`GSList`**: Dynamic data structures.
* **`instrument_function`**, **`instrument_functions_matching`**:  Methods to activate profiling.
* **`generate_report`**:  Outputting the collected data.

**3. Deeper Dive into Functionality (Top-Down Approach):**

Starting with the main structure `GumProfiler`, we can trace its lifecycle and core operations:

* **Initialization (`gum_profiler_init`)**:  Sets up mutex, obtains the interceptor, and creates a hash table to store function context information.
* **Instrumentation (`gum_profiler_instrument_function`, `gum_profiler_instrument_functions_matching`)**:  The crucial part where Frida's interceptor is used to hook into function calls. It associates a `GumFunctionContext` with each instrumented function. This involves:
    * Using `gum_interceptor_attach`.
    * Creating a `GumFunctionContext` to store function-specific data (sampler, inspector).
    * Storing the `GumFunctionContext` in the `function_by_address` hash table.
* **Call Interception (`gum_profiler_on_enter`, `gum_profiler_on_leave`)**:  These are the callback functions triggered by Frida when an instrumented function is entered and exited.
    * **`on_enter`**: Records the start time using a `GumSampler`, tracks recursion, and stores the current thread's context in a stack.
    * **`on_leave`**: Calculates the duration, updates statistics (total calls, duration, worst case), and manages the call stack to understand the call hierarchy.
* **Report Generation (`gum_profiler_generate_report`)**:  Processes the collected data to produce a `GumProfileReport`, which likely includes function call counts, durations, and worst-case scenarios. It iterates through the `function_by_address` hash table.
* **Cleanup (`gum_profiler_dispose`, `gum_profiler_finalize`)**: Releases resources (interceptor, hash table, mutex).

**4. Connecting to Reverse Engineering:**

The core functionality – *measuring the execution time and call counts of functions* – is directly relevant to reverse engineering:

* **Performance Bottlenecks**: Identifying slow functions can pinpoint areas of interest or potential vulnerabilities.
* **Control Flow Analysis**: The call stack information in the report reveals the sequence of function calls, aiding in understanding the program's logic.
* **Identifying Key Functions**: Functions with high call counts or long durations are often central to the program's operation.
* **Understanding Algorithm Complexity**: By profiling different inputs, one can infer the time complexity of algorithms.
* **Dynamic Analysis**:  Observing runtime behavior to understand how the software operates.

**5. Identifying Low-Level, Kernel, and Framework Aspects:**

* **Binary Level**:  The code directly interacts with function addresses (`gpointer function_address`). Instrumentation works at the binary level by modifying the execution flow.
* **Linux/Android Kernel**:  The concept of threads (`guint thread_id`) and the use of mutexes (`g_mutex`) are operating system primitives. The `gum_invocation_context_get_thread_id` function interacts with the OS's thread management. On Android, this would involve interacting with the Android runtime (ART) or Dalvik.
* **Framework Awareness**: While the code itself isn't Android framework specific, it's designed to profile *within* those frameworks. The functions being profiled could be part of the Android framework.

**6. Logic and Assumptions (Hypothetical Input/Output):**

Consider a simple scenario:

* **Input:** Instrumenting a function `calculate_sum(int a, int b)` and then calling it twice from the main thread. The first call takes 10ms, the second takes 15ms.
* **Assumptions:**
    * The `GumSampler` provides time in milliseconds.
    * No other threads are involved.
* **Output (in the generated report):**
    * `calculate_sum`:
        * `total_calls`: 2
        * `total_duration`: 25ms
        * `worst_case_duration`: 15ms
        * (Worst-case info might be empty or populated based on the inspector)

**7. Common Usage Errors:**

* **Instrumenting too many functions**: Can lead to performance overhead and a massive report, making analysis difficult.
* **Not detaching the profiler**: Leaving hooks in place can cause unexpected behavior after profiling is complete.
* **Incorrect sampler**: Choosing a sampler with insufficient precision or incorrect units can lead to inaccurate measurements.
* **Misinterpreting the report**:  Understanding the difference between total duration and worst-case duration is important.
* **Forgetting to call `generate_report`**: The profiling data is collected, but not presented without this step.

**8. User Steps and Debugging Clues:**

A typical user workflow:

1. **Create a `GumProfiler` instance:** `GumProfiler *profiler = gum_profiler_new();`
2. **Choose functions to instrument:**
   * By name: `gum_profiler_instrument_functions_matching(profiler, "my_function_*", ...)`
   * By address: `gum_profiler_instrument_function(profiler, (gpointer)0x..., ...)`
3. **Run the target application or execute the code being profiled.**
4. **Generate the report:** `GumProfileReport *report = gum_profiler_generate_report(profiler);`
5. **Process and analyze the report.**

**Debugging Clues if Something Goes Wrong:**

* **No data in the report:**  Perhaps the target functions weren't called, the instrumentation failed (check return values of `instrument_*` functions), or the sampler isn't working.
* **Unexpectedly long durations:**  Could indicate issues with the sampler or interference from other Frida scripts.
* **Crashes:**  Could be due to errors in the inspector function (if used) or conflicts with other Frida scripts.

By following these steps, we can systematically analyze the C code and address all aspects of the prompt. The key is to understand the purpose of each code section and how they contribute to the overall profiling functionality.
This C source file, `gumprofiler.c`, is part of Frida's Gum library and implements a **code profiler**. Its main function is to **measure the execution time and call counts of specified functions** within a running process, providing insights into performance characteristics.

Here's a breakdown of its functionalities and connections to various concepts:

**1. Core Functionality: Code Profiling**

* **Instrumentation:**  The profiler instruments target functions by inserting probes at their entry and exit points. This is achieved using Frida's `GumInterceptor`.
* **Time Measurement:** It uses `GumSampler` to capture timestamps when entering and leaving instrumented functions, allowing calculation of execution duration.
* **Call Counting:** It tracks the number of times each instrumented function is called.
* **Worst-Case Analysis:** It can identify the invocation with the longest execution time for each function and optionally store additional information about that specific invocation using a `GumWorstCaseInspectorFunc`.
* **Thread Awareness:** The profiler is aware of multi-threading and tracks statistics for each thread individually.
* **Call Stack Tracking:** It maintains a call stack for each thread to understand the call hierarchy and identify root nodes (functions called directly without a profiled parent).
* **Report Generation:** It generates a `GumProfileReport` containing the collected profiling data, including function names, call counts, total execution time, worst-case execution time, and potentially worst-case information.

**2. Relationship with Reverse Engineering**

This profiler is a powerful tool for **dynamic analysis**, a crucial aspect of reverse engineering:

* **Identifying Performance Bottlenecks:** By measuring execution times, reverse engineers can pinpoint slow functions that might be targets for optimization or analysis of their algorithms.
    * **Example:** Observing that a specific encryption function takes a disproportionately long time to execute might direct attention to its implementation details.
* **Understanding Control Flow:** The call stack information reveals the sequence of function calls, helping to understand how different parts of the code interact.
    * **Example:** Seeing a chain of calls leading to a specific security check function can help understand how that check is triggered.
* **Identifying Frequently Called Functions:** High call counts might indicate important or core functions in the application's logic.
    * **Example:** A function responsible for network communication being called repeatedly could be a key area to investigate for protocol analysis.
* **Analyzing Algorithm Complexity:** By profiling function execution with different inputs, one can gain insights into the time complexity of underlying algorithms.
* **Dynamic Instrumentation:** The very act of using Frida and this profiler exemplifies dynamic instrumentation, where code is modified and analyzed at runtime without needing the original source code.

**3. Binary, Linux, Android Kernel, and Framework Knowledge**

* **Binary Level:**
    * **Function Addresses:** The profiler works directly with function addresses (`gpointer function_address`). It needs to identify the starting points of functions in the binary.
    * **Code Injection:**  Frida's `GumInterceptor` internally manipulates the binary code (or its in-memory representation) to insert hooks. This involves understanding the target architecture's instruction set.
* **Linux/Android Kernel:**
    * **Threads:** The profiler uses thread IDs (`guint thread_id`) and mutexes (`GMutex`) which are fundamental concepts in operating system kernels. It needs to interact with the OS to get the current thread ID.
    * **System Calls (Indirectly):** While this code doesn't directly make system calls, the `GumSampler` implementation might rely on system calls to get high-resolution timestamps (e.g., `clock_gettime` on Linux).
* **Android Framework (Potentially):**
    * The functions being profiled could be part of the Android framework (e.g., Java methods in ART or native libraries). The profiler works across these boundaries.
    * When profiling on Android, the thread IDs will correspond to Android's thread management.

**4. Logical Reasoning and Assumptions**

* **Assumption: Accurate Timestamps:** The profiler assumes that the `GumSampler` provides sufficiently accurate and reliable timestamps for measuring function durations.
* **Assumption: Minimal Overhead:**  While dynamic instrumentation introduces overhead, the profiler aims to minimize it. However, measuring very short function calls might be affected by the instrumentation overhead itself.
* **Input:**  The user specifies which functions to instrument, either by name (using a matching string) or by providing their memory addresses.
* **Output:** A `GumProfileReport` which is a data structure containing:
    * For each profiled function (and potentially per thread):
        * Function name (resolved using `gum_symbol_name_from_address`).
        * Total number of calls (`total_calls`).
        * Total execution time (`total_duration`).
        * Duration of the longest execution (`worst_case_duration`).
        * Optional information about the worst-case invocation (`worst_case_info`).
        * A hierarchical representation of function calls (`child`).

**5. User and Programming Errors**

* **Incorrect Function Matching String:** If the `match_str` in `gum_profiler_instrument_functions_matching` doesn't match any functions, no instrumentation will occur, and the report will be empty or incomplete.
    * **Example:** User intends to profile `my_function`, but types `my_functon` in the matching string.
* **Instrumenting Too Many Functions:** Instrumenting a large number of frequently called functions can introduce significant overhead, potentially skewing the profiling results and slowing down the target process.
* **Forgetting to Generate the Report:** If the user instruments functions but doesn't call `gum_profiler_generate_report`, the collected data will not be accessible.
* **Not Handling Errors from Instrumentation:**  `gum_profiler_instrument_function` returns a `GumInstrumentReturn` value. Ignoring potential errors like `GUM_INSTRUMENT_WRONG_SIGNATURE` or `GUM_INSTRUMENT_WAS_INSTRUMENTED` might lead to unexpected behavior.
* **Using an Inappropriate Sampler:** Choosing a `GumSampler` with low resolution might lead to inaccurate timing measurements, especially for short-duration functions.
* **Race Conditions (Less Likely in Basic Usage):** While the code uses mutexes for thread safety, complex interactions with other Frida scripts or manual manipulation of the profiler's state could potentially introduce race conditions.

**6. User Operation and Debugging Clues**

A typical user interaction to reach this code would involve:

1. **Writing a Frida script (JavaScript or Python).**
2. **Importing the `frida` module.**
3. **Attaching to a running process or spawning a new process.**
4. **Creating a `GumProfiler` instance using the Gum API.**
5. **Calling `instrument_function` or `instrument_functions_matching` on the `GumProfiler` instance to specify the functions to be profiled.**
6. **Executing the code within the target process that calls the instrumented functions.**
7. **Calling `generate_report` on the `GumProfiler` instance to retrieve the profiling data.**
8. **Processing and analyzing the generated report.**

**Debugging Clues if Something Goes Wrong:**

* **No output in the report:** This could indicate that the specified functions were not called, the instrumentation failed, or the matching string was incorrect. Check the return values of the instrumentation functions.
* **Unexpectedly high overhead:** If the target process slows down significantly after enabling the profiler, it might indicate that too many functions are being instrumented or that the chosen sampler is inefficient.
* **Incorrect function names in the report:** This could be due to issues with symbol resolution.
* **Inconsistent timings:**  Could point to issues with the sampler or interference from other parts of the system.
* **Crashes:**  Less likely in the profiler itself but could occur if the inspector function (`GumWorstCaseInspectorFunc`) has errors or if there are conflicts with other Frida scripts.

In summary, `gumprofiler.c` implements a dynamic code profiler within Frida's Gum library. It leverages instrumentation techniques to measure function execution times and call counts, providing valuable insights for reverse engineering, performance analysis, and understanding program behavior at a low level, often involving interactions with operating system and potentially framework-specific concepts.

### 提示词
```
这是目录为frida/subprojects/frida-gum/libs/gum/prof/gumprofiler.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprofiler.h"

#include "guminterceptor.h"
#include "gumsymbolutil.h"

#include <string.h>

#define GUM_PROFILER_LOCK()   (g_mutex_lock (&self->mutex))
#define GUM_PROFILER_UNLOCK() (g_mutex_unlock (&self->mutex))

typedef struct _GumProfilerInvocation GumProfilerInvocation;
typedef struct _GumProfilerContext GumProfilerContext;
typedef struct _GumFunctionContext GumFunctionContext;
typedef struct _GumWorstCaseInfo GumWorstCaseInfo;
typedef struct _GumWorstCase GumWorstCase;
typedef struct _GumFunctionThreadContext GumFunctionThreadContext;

struct _GumProfiler
{
  GObject parent;

  gboolean disposed;

  GMutex mutex;

  GumInterceptor * interceptor;
  GHashTable * function_by_address;
  GSList * stacks;
};

struct _GumProfilerInvocation
{
  GumProfilerContext * profiler;
  GumFunctionContext * function;
  GumFunctionThreadContext * thread;

  GumSample start_time;
};

struct _GumProfilerContext
{
  GArray * stack;
};

struct _GumWorstCaseInfo
{
  gchar buf[GUM_MAX_WORST_CASE_INFO_SIZE];
};

struct _GumWorstCase
{
  GumSample duration;
  GumWorstCaseInfo info;
};

struct _GumFunctionThreadContext
{
  GumFunctionContext * function_ctx;
  guint thread_id;

  /* statistics */
  guint64 total_calls;
  GumSample total_duration;
  GumWorstCase worst_case;

  /* state */
  gboolean is_root_node;
  gint recurse_count;
  GumWorstCaseInfo potential_info;

  GumFunctionThreadContext * child_ctx;
};

struct _GumFunctionContext
{
  gpointer function_address;

  GumSamplerInterface * sampler_interface;
  GumSampler * sampler_instance;
  GumWorstCaseInspectorFunc inspector_func;
  gpointer inspector_user_data;

  GumFunctionThreadContext thread_contexts[GUM_MAX_THREADS];
  volatile gint thread_context_count;
};

static void gum_profiler_invocation_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_profiler_dispose (GObject * object);
static void gum_profiler_finalize (GObject * object);

static void gum_profiler_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_profiler_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static void unstrument_and_free_function (gpointer key, gpointer value,
    gpointer user_data);

static void add_to_report_if_root_node (gpointer key, gpointer value,
    gpointer user_data);
static GumProfileReportNode * make_node_from_thread_context (
    GumFunctionThreadContext * thread_ctx, GHashTable ** processed_nodes);
static GumProfileReportNode * make_node (gchar * name, guint64 total_calls,
    GumSample total_duration, GumSample worst_case_duration,
    gchar * worst_case_info, GumProfileReportNode * child);
static void thread_context_register_child_timing (
    GumFunctionThreadContext * parent_ctx,
    GumFunctionThreadContext * child_ctx);

static void get_number_of_threads_foreach (gpointer key, gpointer value,
    gpointer user_data);

static GumFunctionThreadContext * gum_function_context_get_current_thread (
    GumFunctionContext * function_ctx, GumInvocationContext * context);

G_DEFINE_TYPE_EXTENDED (GumProfiler,
                        gum_profiler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_profiler_invocation_listener_iface_init))

static void
gum_profiler_class_init (GumProfilerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_profiler_dispose;
  object_class->finalize = gum_profiler_finalize;
}

static void
gum_profiler_invocation_listener_iface_init (gpointer g_iface,
                                             gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_profiler_on_enter;
  iface->on_leave = gum_profiler_on_leave;
}

static void
gum_profiler_init (GumProfiler * self)
{
  g_mutex_init (&self->mutex);

  self->interceptor = gum_interceptor_obtain ();
  self->function_by_address = g_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, NULL);
}

static void
gum_profiler_dispose (GObject * object)
{
  GumProfiler * self = GUM_PROFILER (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_interceptor_detach (self->interceptor, GUM_INVOCATION_LISTENER (self));

    g_hash_table_foreach (self->function_by_address,
        unstrument_and_free_function, self);
    g_hash_table_remove_all (self->function_by_address);

    g_object_unref (self->interceptor);
    self->interceptor = NULL;
  }

  G_OBJECT_CLASS (gum_profiler_parent_class)->dispose (object);
}

static void
gum_profiler_finalize (GObject * object)
{
  GumProfiler * self = GUM_PROFILER (object);

  while (self->stacks != NULL)
  {
    GArray * stack = (GArray *) self->stacks->data;
    g_array_free (stack, TRUE);
    self->stacks = g_slist_delete_link (self->stacks, self->stacks);
  }

  g_hash_table_unref (self->function_by_address);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_profiler_parent_class)->finalize (object);
}

static void
gum_profiler_on_enter (GumInvocationListener * listener,
                       GumInvocationContext * context)
{
  GumProfilerInvocation * inv;
  GumFunctionContext * fctx;
  GumFunctionThreadContext * tctx;

  inv = GUM_IC_GET_INVOCATION_DATA (context, GumProfilerInvocation);

  inv->profiler = GUM_IC_GET_THREAD_DATA (context, GumProfilerContext);
  if (inv->profiler->stack == NULL)
  {
    GumProfiler * self = GUM_PROFILER (listener);

    inv->profiler->stack = g_array_sized_new (FALSE, FALSE,
        sizeof (GumFunctionThreadContext *), GUM_MAX_CALL_DEPTH);

    GUM_PROFILER_LOCK ();
    self->stacks = g_slist_prepend (self->stacks, inv->profiler->stack);
    GUM_PROFILER_UNLOCK ();
  }

  inv->function = GUM_IC_GET_FUNC_DATA (context, GumFunctionContext *);
  inv->thread = gum_function_context_get_current_thread (inv->function,
      context);

  fctx = inv->function;
  tctx = inv->thread;

  g_array_append_val (inv->profiler->stack, tctx);

  tctx->total_calls++;

  if (tctx->recurse_count == 0)
  {
    GumWorstCaseInspectorFunc inspector_func;

    if ((inspector_func = fctx->inspector_func) != NULL)
    {
      inspector_func (context, tctx->potential_info.buf,
          sizeof (tctx->potential_info.buf), fctx->inspector_user_data);
    }

    inv->start_time = fctx->sampler_interface->sample (fctx->sampler_instance);
  }

  tctx->recurse_count++;
}

static void
gum_profiler_on_leave (GumInvocationListener * listener,
                       GumInvocationContext * context)
{
  GumProfilerInvocation * inv;
  GumFunctionContext * fctx;
  GumFunctionThreadContext * tctx;
  GArray * stack;

  inv = GUM_IC_GET_INVOCATION_DATA (context, GumProfilerInvocation);

  fctx = inv->function;
  tctx = inv->thread;
  stack = inv->profiler->stack;

  if (tctx->recurse_count == 1)
  {
    GumSample now, duration;
    GumFunctionThreadContext * parent;
    guint i;

    now = fctx->sampler_interface->sample (fctx->sampler_instance);
    duration = now - inv->start_time;

    tctx->total_duration += duration;

    if (duration > tctx->worst_case.duration)
    {
      tctx->worst_case.duration = duration;
      memcpy (&tctx->worst_case.info, &tctx->potential_info,
          sizeof (tctx->potential_info));
    }

    parent = NULL;
    for (i = 0; i != stack->len; i++)
    {
      GumFunctionThreadContext * cur;

      cur = g_array_index (stack, GumFunctionThreadContext *, i);
      if (cur != tctx)
        parent = cur;
      else
        break;
    }

    if (parent == NULL)
      tctx->is_root_node = TRUE;
    else
      thread_context_register_child_timing (parent, tctx);
  }

  tctx->recurse_count--;

  g_array_set_size (stack, stack->len - 1);
}

GumProfiler *
gum_profiler_new (void)
{
  return g_object_new (GUM_TYPE_PROFILER, NULL);
}

void
gum_profiler_instrument_functions_matching (GumProfiler * self,
                                            const gchar * match_str,
                                            GumSampler * sampler,
                                            GumFunctionMatchFilterFunc filter,
                                            gpointer user_data)
{
  GumInterceptor * interceptor = self->interceptor;
  GArray * matches;
  guint i;

  matches = gum_find_functions_matching (match_str);

  gum_interceptor_begin_transaction (interceptor);

  for (i = 0; i < matches->len; i++)
  {
    gpointer address = g_array_index (matches, gpointer, i);
    gboolean approved = TRUE;

    if (filter != NULL)
    {
      gchar * func_name;

      func_name = gum_symbol_name_from_address (address);
      approved = filter (func_name, user_data);
      g_free (func_name);
    }

    if (approved)
      gum_profiler_instrument_function (self, address, sampler);
  }

  gum_interceptor_end_transaction (interceptor);

  g_array_free (matches, TRUE);
}

GumInstrumentReturn
gum_profiler_instrument_function (GumProfiler * self,
                                  gpointer function_address,
                                  GumSampler * sampler)
{
  return gum_profiler_instrument_function_with_inspector (self,
      function_address, sampler, NULL, NULL);
}

GumInstrumentReturn
gum_profiler_instrument_function_with_inspector (
    GumProfiler * self,
    gpointer function_address,
    GumSampler * sampler,
    GumWorstCaseInspectorFunc inspector_func,
    gpointer user_data)
{
  GumInstrumentReturn result = GUM_INSTRUMENT_OK;
  GumFunctionContext * ctx;
  GumAttachReturn attach_ret;

  ctx = g_new0 (GumFunctionContext, 1);

  attach_ret = gum_interceptor_attach (self->interceptor, function_address,
      GUM_INVOCATION_LISTENER (self), ctx);
  if (attach_ret != GUM_ATTACH_OK)
    goto error;

  ctx->function_address = function_address;
  ctx->sampler_interface = GUM_SAMPLER_GET_IFACE (sampler);
  ctx->sampler_instance = g_object_ref (sampler);
  ctx->inspector_func = inspector_func;
  ctx->inspector_user_data = user_data;

  GUM_PROFILER_LOCK ();
  g_hash_table_insert (self->function_by_address, function_address, ctx);
  GUM_PROFILER_UNLOCK ();

  return result;

error:
  g_free (ctx);

  if (attach_ret == GUM_ATTACH_WRONG_SIGNATURE)
    result = GUM_INSTRUMENT_WRONG_SIGNATURE;
  else if (attach_ret == GUM_ATTACH_ALREADY_ATTACHED)
    result = GUM_INSTRUMENT_WAS_INSTRUMENTED;
  else
    g_assert_not_reached ();

  return result;
}

static void
unstrument_and_free_function (gpointer key,
                              gpointer value,
                              gpointer user_data)
{
  GumFunctionContext * function_ctx = (GumFunctionContext *) value;

  g_object_unref (function_ctx->sampler_instance);
  g_free (function_ctx);
}

GumProfileReport *
gum_profiler_generate_report (GumProfiler * self)
{
  GumProfileReport * report;

  report = gum_profile_report_new ();
  g_hash_table_foreach (self->function_by_address, add_to_report_if_root_node,
      report);
  _gum_profile_report_sort (report);

  return report;
}

static void
add_to_report_if_root_node (gpointer key,
                            gpointer value,
                            gpointer user_data)
{
  GumProfileReport * report = GUM_PROFILE_REPORT (user_data);
  GumFunctionContext * function_ctx = (GumFunctionContext *) value;

  if (function_ctx->thread_context_count > 0)
  {
    gint i;

    for (i = 0; i != function_ctx->thread_context_count; i++)
    {
      GumFunctionThreadContext * thread_ctx =
          &function_ctx->thread_contexts[i];

      if (thread_ctx->is_root_node)
      {
        GHashTable * processed_nodes = NULL;
        GumProfileReportNode * root_node;

        root_node = make_node_from_thread_context (thread_ctx,
            &processed_nodes);
        _gum_profile_report_append_thread_root_node (report,
            thread_ctx->thread_id, root_node);
      }
    }
  }
}

static GumProfileReportNode *
make_node_from_thread_context (GumFunctionThreadContext * thread_ctx,
                               GHashTable ** processed_nodes)
{
  gpointer parent_function_address;
  gchar * parent_node_name;
  GumProfileReportNode * parent_node;
  GumFunctionThreadContext * child_ctx;
  GumProfileReportNode * child_node = NULL;

  if (*processed_nodes != NULL)
    g_hash_table_ref (*processed_nodes);

  parent_function_address = thread_ctx->function_ctx->function_address;
  parent_node_name = gum_symbol_name_from_address (parent_function_address);

  child_ctx = thread_ctx->child_ctx;
  if (child_ctx != NULL)
  {
    if (*processed_nodes == NULL)
      *processed_nodes = g_hash_table_new (g_direct_hash, g_direct_equal);

    if (g_hash_table_lookup (*processed_nodes, child_ctx) == NULL)
    {
      g_hash_table_insert (*processed_nodes, thread_ctx, GSIZE_TO_POINTER (1));

      child_node = make_node_from_thread_context (child_ctx, processed_nodes);
    }
  }

  parent_node = make_node (parent_node_name, thread_ctx->total_calls,
      thread_ctx->total_duration, thread_ctx->worst_case.duration,
      g_strdup (thread_ctx->worst_case.info.buf),
      child_node);

  if (*processed_nodes != NULL)
    g_hash_table_unref (*processed_nodes);

  return parent_node;
}

static GumProfileReportNode *
make_node (gchar * name,
           guint64 total_calls,
           GumSample total_duration,
           GumSample worst_case_duration,
           gchar * worst_case_info,
           GumProfileReportNode * child)
{
  GumProfileReportNode * node;

  node = g_new (GumProfileReportNode, 1);
  node->name = name;
  node->total_calls = total_calls;
  node->total_duration = total_duration;
  node->worst_case_duration = worst_case_duration;
  node->worst_case_info = worst_case_info;
  node->child = child;

  return node;
}

guint
gum_profiler_get_number_of_threads (GumProfiler * self)
{
  guint result;
  GHashTable * unique_thread_id_set;

  unique_thread_id_set = g_hash_table_new (g_direct_hash, g_direct_equal);
  GUM_PROFILER_LOCK ();
  g_hash_table_foreach (self->function_by_address,
      get_number_of_threads_foreach, unique_thread_id_set);
  GUM_PROFILER_UNLOCK ();
  result = g_hash_table_size (unique_thread_id_set);
  g_hash_table_unref (unique_thread_id_set);

  return result;
}

GumSample
gum_profiler_get_total_duration_of (GumProfiler * self,
                                    guint thread_index,
                                    gpointer function_address)
{
  GumFunctionContext * function_ctx;

  GUM_PROFILER_LOCK ();
  function_ctx = (GumFunctionContext *)
      g_hash_table_lookup (self->function_by_address, function_address);
  GUM_PROFILER_UNLOCK ();

  if (function_ctx != NULL
      && (gint) thread_index < function_ctx->thread_context_count)
    return function_ctx->thread_contexts[thread_index].total_duration;
  else
    return 0;
}

GumSample
gum_profiler_get_worst_case_duration_of (GumProfiler * self,
                                         guint thread_index,
                                         gpointer function_address)
{
  GumFunctionContext * function_ctx;

  GUM_PROFILER_LOCK ();
  function_ctx = (GumFunctionContext *)
      g_hash_table_lookup (self->function_by_address, function_address);
  GUM_PROFILER_UNLOCK ();

  if (function_ctx != NULL
      && (gint) thread_index < function_ctx->thread_context_count)
    return function_ctx->thread_contexts[thread_index].worst_case.duration;
  else
    return 0;
}

const gchar *
gum_profiler_get_worst_case_info_of (GumProfiler * self,
                                     guint thread_index,
                                     gpointer function_address)
{
  GumFunctionContext * function_ctx;

  GUM_PROFILER_LOCK ();
  function_ctx = (GumFunctionContext *)
      g_hash_table_lookup (self->function_by_address, function_address);
  GUM_PROFILER_UNLOCK ();

  if (function_ctx != NULL
      && (gint) thread_index < function_ctx->thread_context_count)
    return function_ctx->thread_contexts[thread_index].worst_case.info.buf;
  else
    return "";
}

static void
thread_context_register_child_timing (GumFunctionThreadContext * parent_ctx,
                                      GumFunctionThreadContext * child_ctx)
{
  GumFunctionThreadContext * cur_child = parent_ctx->child_ctx;

  if (cur_child != NULL)
  {
    if (child_ctx->total_duration > cur_child->total_duration)
      parent_ctx->child_ctx = child_ctx;
  }
  else
  {
    parent_ctx->child_ctx = child_ctx;
  }
}

static void
get_number_of_threads_foreach (gpointer key,
                               gpointer value,
                               gpointer user_data)
{
  GumFunctionContext * function_ctx = value;
  GHashTable * unique_thread_id_set = user_data;
  guint thread_count = function_ctx->thread_context_count;
  guint i;

  for (i = 0; i < thread_count; i++)
  {
    g_hash_table_insert (unique_thread_id_set,
        GUINT_TO_POINTER (function_ctx->thread_contexts[i].thread_id), NULL);
  }
}

GumFunctionThreadContext *
gum_function_context_get_current_thread (GumFunctionContext * function_ctx,
                                         GumInvocationContext * context)
{
  guint32 current_thread_id;
  guint thread_count;
  guint i;
  GumFunctionThreadContext * thread_ctx;

  current_thread_id = gum_invocation_context_get_thread_id (context);

  thread_count = g_atomic_int_get (&function_ctx->thread_context_count);
  for (i = 0; i != thread_count; i++)
  {
    thread_ctx = &function_ctx->thread_contexts[i];

    if (thread_ctx->thread_id == current_thread_id)
      return thread_ctx;
  }

  i = g_atomic_int_add (&function_ctx->thread_context_count, 1);
  g_assert (i < G_N_ELEMENTS (function_ctx->thread_contexts));
  thread_ctx = &function_ctx->thread_contexts[i];
  thread_ctx->function_ctx = function_ctx;
  thread_ctx->thread_id = current_thread_id;

  return thread_ctx;
}
```