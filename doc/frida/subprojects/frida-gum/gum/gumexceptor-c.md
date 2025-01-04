Response:
Let's break down the thought process for analyzing this C code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The core request is to analyze the `gumexceptor.c` file, part of Frida's Gum library, and explain its functionalities, its relevance to reverse engineering, its low-level aspects, its logical flow, potential user errors, and how a user might end up triggering its execution.

**2. Initial Scan and Identification of Key Components:**

A quick skim reveals these important elements:

* **Headers:** Inclusion of `<string.h>` and a custom header `gumexceptor.h` and `gumexceptorbackend.h`. This suggests it's dealing with strings and has a backend component. The `#ifndef GUM_DIET` indicates conditional compilation, likely for a reduced "diet" version of Frida.
* **Data Structures:**  `GumExceptor`, `GumExceptionHandlerEntry`, and `GumExceptorScope`. These are the core data structures managing exception handling.
* **Functions with `gum_exceptor_` prefix:**  This strongly suggests the main functionalities of this module. Functions like `gum_exceptor_add`, `gum_exceptor_remove`, `gum_exceptor_handle_exception`, `gum_exceptor_obtain`, etc., are key indicators.
* **Locking Mechanisms:** `GMutex` and `G_LOCK_DEFINE_STATIC`. This hints at thread safety and managing concurrent access.
* **Exception Handling Logic:** The presence of `GumExceptionDetails`, `gum_exceptor_handle_exception`, `_gum_exceptor_prepare_try`, `gum_exceptor_catch`, and `gum_exceptor_scope_perform_longjmp` clearly points to exception handling.
* **Platform-Specific Code:**  `#ifdef HAVE_ANDROID`, `#if defined (HAVE_I386)`, etc., indicates platform-dependent implementation details.
* **`longjmp`:** The presence of `GUM_NATIVE_LONGJMP` and related setup in `gum_exceptor_scope_perform_longjmp` is a significant clue regarding the non-local transfer of control during exception handling.

**3. Deeper Analysis and Function Grouping:**

Now, let's analyze the functions in logical groups based on their purpose:

* **Initialization and Management:**  `gum_exceptor_class_init`, `gum_exceptor_init`, `gum_exceptor_dispose`, `gum_exceptor_finalize`, `gum_exceptor_obtain`, `the_exceptor_weak_notify`, `gum_exceptor_disable`, `gum_exceptor_reset`. These deal with creating, destroying, and managing the global `GumExceptor` instance.
* **Adding/Removing Handlers:** `gum_exceptor_add`, `gum_exceptor_remove`. These manage the list of functions to be called when an exception occurs.
* **Exception Handling Core:** `gum_exceptor_handle_exception`, `gum_exceptor_handle_scope_exception`. These are the central functions that process exceptions and invoke the registered handlers.
* **Try/Catch Mechanism:** `_gum_exceptor_prepare_try`, `gum_exceptor_catch`. These implement a try-catch block mechanism for handling exceptions within specific scopes.
* **Scope Management:** `gum_exceptor_has_scope`. Checks if a specific thread has an active exception handling scope.
* **Exception Details:** `gum_exception_details_to_string`. Formats exception information into a human-readable string.
* **Context Manipulation for `longjmp`:** `gum_exceptor_scope_perform_longjmp`. This function is crucial for setting up the CPU state before a `longjmp`.

**4. Connecting to Key Concepts:**

As I analyze the functions, I start connecting them to broader concepts:

* **Reverse Engineering:** The ability to intercept and analyze exceptions is invaluable for understanding program behavior, identifying vulnerabilities, and debugging.
* **Binary Underpinnings:**  The manipulation of CPU context (registers like IP/PC, SP, LR) and the use of `longjmp` directly relate to how programs execute at the binary level.
* **Operating System Concepts:**  Thread IDs, signal masks (`sigprocmask`), and the concept of exceptions are all OS-level features.
* **Concurrency:** The use of mutexes highlights the importance of thread safety in a dynamic instrumentation framework like Frida.
* **Try-Catch:**  This is a standard programming construct for error handling, and Frida implements its own version for intercepted code.

**5. Logical Flow and Hypothetical Scenarios:**

I start to trace the execution flow:

1. A user script interacts with Frida.
2. Frida injects code into the target process.
3. The injected code might trigger an exception (e.g., accessing invalid memory).
4. The OS signals the exception.
5. Frida's backend (related to `gumexceptorbackend.h`) intercepts this signal.
6. `gum_exceptor_handle_exception` is called.
7. Registered handlers are invoked.
8. If a `try`/`catch` block is active, `gum_exceptor_handle_scope_exception` might be called.
9. `gum_exceptor_scope_perform_longjmp` is used to jump back to the `catch` block.

**6. Identifying Potential User Errors:**

Based on the code, I can identify potential issues:

* **Incorrect Handler Logic:**  A poorly written exception handler could cause more problems.
* **Missing `catch`:**  If an exception occurs within a `try` block but there's no corresponding `catch`, the program might terminate unexpectedly.
* **Resource Leaks:**  If handlers don't properly clean up resources.

**7. Tracing User Actions:**

I think about how a user might reach this code:

1. **Basic Hooking:** A user hooks a function that crashes.
2. **Manual Exception Triggering:** A user deliberately triggers a fault in their injected code to test exception handling.
3. **Using Frida's `Process.setExceptionHandler`:** This API directly relates to the functionality of this module.
4. **Internal Frida Operations:**  Even Frida's internal workings might trigger exceptions that are handled by this module.

**8. Structuring the Explanation:**

Finally, I organize my findings into the requested categories: Functionality, Relationship to Reverse Engineering, Binary/Kernel/Framework aspects, Logical Reasoning, User Errors, and User Journey. I use clear language and provide concrete examples.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on individual functions. I need to step back and see the bigger picture of how they work together.
* I need to ensure my explanations are accessible to someone with some programming knowledge but maybe not deep expertise in OS internals or Frida.
* I should double-check my assumptions about how Frida works internally and refer back to the code to confirm. For instance, the role of `gumexceptorbackend.h` needs to be acknowledged even if its implementation isn't directly in this file.

By following this systematic approach, I can dissect the code effectively and generate a comprehensive and informative explanation.
好的，让我们详细分析一下 `frida/subprojects/frida-gum/gum/gumexceptor.c` 这个文件，它是 Frida 中负责异常处理的核心组件。

**功能列举:**

1. **全局单例异常管理器:** 该文件实现了一个全局单例的异常管理器 `GumExceptor`。通过 `gum_exceptor_obtain()` 获取该单例实例。这确保了整个 Frida 进程中只有一个统一的异常处理中心。

2. **注册和管理异常处理器:**  允许注册多个异常处理函数 (`GumExceptionHandler`)。
   - `gum_exceptor_add()`: 用于向异常管理器注册一个新的异常处理函数。每个处理器可以关联用户自定义的数据。
   - `gum_exceptor_remove()`: 用于移除已注册的异常处理函数。

3. **处理异常:** 当目标进程发生异常时，`gum_exceptor_handle_exception()` 函数会被调用。它会遍历所有已注册的异常处理函数，并依次调用，直到某个处理函数返回 `TRUE` (表示已处理)。

4. **实现 Try-Catch 机制:**  提供了类似 try-catch 的作用域机制，允许在特定的代码块内捕获和处理异常。
   - `_gum_exceptor_prepare_try()`:  在 try 块开始时调用，用于设置异常处理上下文 `GumExceptorScope`。
   - `gum_exceptor_catch()`: 在 catch 块中调用，检查是否发生了异常。
   - `gum_exceptor_has_scope()`: 检查指定线程是否有活动的异常处理作用域。

5. **异常信息封装:** 使用 `GumExceptionDetails` 结构体封装了异常的详细信息，包括异常类型、发生地址、线程 ID 以及 CPU 上下文等。

6. **异常信息格式化:** `gum_exception_details_to_string()` 函数可以将 `GumExceptionDetails` 结构体转换为人类可读的字符串，方便调试和日志记录。

7. **禁用异常处理:** `gum_exceptor_disable()` 可以禁用全局异常处理，这通常用于测试或其他特殊场景。

8. **重置异常管理器:** `gum_exceptor_reset()` 用于重置异常管理器，通常会重新创建底层的异常处理后端。

**与逆向方法的关系及举例说明:**

`gumexceptor.c` 是 Frida 动态插桩技术的核心组成部分，它使得在运行时拦截和处理目标进程的异常成为可能，这对于逆向工程至关重要。

**举例说明:**

* **捕获访问违规 (Segmentation Fault):**  在逆向分析一个程序时，你可能会遇到程序崩溃的情况。通过 Frida 注册一个异常处理器，你可以捕获 `GUM_EXCEPTION_ACCESS_VIOLATION` 类型的异常，并获取发生错误的内存地址 (`details->memory.address`) 以及当时的 CPU 寄存器状态 (`details->context`)。这可以帮助你定位导致崩溃的代码位置和原因。

  ```javascript
  // JavaScript Frida 代码
  Process.setExceptionHandler(function(details) {
    if (details.type === 'access-violation') {
      console.log("访问违规发生！");
      console.log("错误地址: " + details.memory.address);
      console.log("寄存器状态: " + JSON.stringify(details.context));
      return true; // 表示已处理，阻止程序崩溃
    }
    return false;
  });
  ```

* **拦截断点异常:**  调试器通常会使用断点指令来暂停程序执行。Frida 可以拦截 `GUM_EXCEPTION_BREAKPOINT` 类型的异常，允许你在断点处执行自定义的操作，例如打印变量值或修改程序行为。

* **分析反调试技术:** 某些程序会使用异常来检测调试器的存在。通过 Frida 的异常处理机制，你可以拦截这些异常，分析其触发条件和处理方式，从而绕过反调试机制。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

1. **二进制底层:**
   - **CPU 上下文 (CPU Context):** `GumExceptionDetails` 结构体包含了 `GumCpuContext`，它保存了发生异常时的 CPU 寄存器状态 (如指令指针、栈指针、通用寄存器等)。这些信息直接反映了程序执行的底层状态。
   - **指令指针 (IP/PC):**  异常发生时的指令指针指向导致异常的指令地址。
   - **栈指针 (SP):**  异常发生时的栈指针指向当前的栈顶位置。
   - **`longjmp` 和 `sigprocmask`:**  `gum_exceptor_scope_perform_longjmp()` 使用 `GUM_NATIVE_LONGJMP` (通常是 `longjmp`) 来实现非本地跳转，从异常发生点跳回到 `catch` 块。在 Android 上，还使用 `sigprocmask` 来恢复信号掩码，这与信号处理机制有关。

   **举例:**  在 `gum_exceptor_handle_scope_exception()` 中，可以看到如何修改 CPU 上下文来模拟从 `try` 块跳转到 `catch` 块：

   ```c
   #if defined (HAVE_I386)
     GUM_CPU_CONTEXT_XIP (context) = GPOINTER_TO_SIZE (
         GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));
     // ... 修改栈指针和参数
   #elif defined (HAVE_ARM)
     context->pc = GPOINTER_TO_SIZE (
         GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));
     // ... 修改栈指针和参数
   #endif
   ```
   这段代码根据不同的 CPU 架构，修改指令指针（IP 或 PC）指向 `gum_exceptor_scope_perform_longjmp` 函数，并设置栈指针和参数，以便在 `longjmp` 后能够正确执行 `catch` 块的代码。

2. **Linux 和 Android 内核:**
   - **异常和信号:**  操作系统通过信号机制通知进程发生了异常（例如，SIGSEGV 表示访问违规，SIGILL 表示非法指令）。Frida 的异常处理机制建立在操作系统的信号处理之上。
   - **线程 ID:** `details->thread_id` 记录了发生异常的线程 ID，这对于多线程程序的调试至关重要。
   - **进程和线程管理:** Frida 需要与目标进程交互，获取线程信息，并修改其内存和执行流程。

   **举例:** `#ifdef HAVE_ANDROID` 中的 `sigprocmask` 调用是为了处理 Android 系统中与信号掩码相关的特定问题。信号掩码控制着哪些信号会被阻塞。

3. **Android 框架:**
   - **Bionic 库:** 代码中提到了 "Workaround for Bionic bug up to and including Android L"，说明该代码需要处理 Android 底层库 (Bionic) 的特定行为或 bug。

**逻辑推理、假设输入与输出:**

**假设输入:** 目标进程在某个线程中执行了会导致除零错误的指令。

**逻辑推理过程:**

1. 操作系统内核检测到除零错误，并生成一个相应的信号（例如，SIGFPE）。
2. Frida 的底层机制拦截了这个信号。
3. Frida 将信号转化为 `GumExceptionDetails` 结构体，其中 `details->type` 为 `GUM_EXCEPTION_ARITHMETIC`，并填充其他相关信息，如错误地址、线程 ID 和 CPU 上下文。
4. `gum_exceptor_handle_exception()` 被调用，传入 `details` 结构体和 `GumExceptor` 实例。
5. 异常管理器遍历已注册的异常处理函数。
6. 如果某个处理函数满足处理条件（例如，检查 `details->type` 是否为 `GUM_EXCEPTION_ARITHMETIC`），则该处理函数被调用。
7. 处理函数可以检查 `details` 中的信息，例如记录错误日志、修改程序状态或指示 Frida 继续执行或停止目标进程。
8. 如果处理函数返回 `TRUE`，则异常被认为已处理，后续的处理函数不会被调用。如果所有处理函数都返回 `FALSE`，Frida 可能会采取默认的异常处理行为（例如，让程序崩溃）。
9. 如果异常发生在 `try` 块内，并且有相应的 `catch` 块，`gum_exceptor_handle_scope_exception()` 会被调用。它会修改 CPU 上下文，使得程序跳转到 `catch` 块继续执行。

**假设输出:**

* 如果注册的异常处理函数打印了错误信息并返回 `true`，则控制台会输出相应的错误信息，并且目标进程可能继续执行（取决于处理函数的具体逻辑）。
* 如果没有注册处理函数或所有处理函数都返回 `false`，目标进程可能会因为未处理的异常而崩溃。
* 如果异常发生在 `try-catch` 块中，程序流程会跳转到 `catch` 块继续执行。

**涉及用户或编程常见的使用错误及举例说明:**

1. **忘记在 `try` 块中调用 `_gum_exceptor_prepare_try()` 或在 `catch` 块中调用 `gum_exceptor_catch()`:** 这会导致 `try-catch` 机制失效，异常不会被捕获。

   ```c
   // 错误示例：忘记调用 _gum_exceptor_prepare_try()
   GumExceptorScope scope;
   // _gum_exceptor_prepare_try(exceptor, &scope); // 忘记调用

   // 可能抛出异常的代码
   *(int*)0 = 123;

   if (gum_exceptor_catch(exceptor, &scope)) {
       // 这里的代码可能不会被执行
       // ...
   }
   ```

2. **在异常处理函数中引入新的错误:**  如果在异常处理函数本身的代码中出现错误，可能会导致程序进入无限循环或崩溃。

3. **注册了错误的异常处理函数或用户数据:** `gum_exceptor_remove()` 使用函数指针和用户数据来匹配要移除的处理函数。如果提供的参数不匹配，则无法正确移除。

4. **不理解 `try-catch` 的作用域:** 可能会错误地认为在 `try` 块之外发生的异常也会被该 `catch` 块捕获。

5. **在多线程环境下没有进行适当的同步:** 虽然 `GumExceptor` 使用互斥锁来保护其内部状态，但如果用户在异常处理函数中访问共享资源而没有进行适当的同步，仍然可能导致竞态条件。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本，使用 `Process.setExceptionHandler()` 注册全局异常处理函数:** 这是最直接的方式。用户明确告知 Frida 当进程发生异常时执行指定的 JavaScript 函数。

   ```javascript
   // JavaScript Frida 代码
   Process.setExceptionHandler(function(details) {
       console.log("捕获到异常：" + details.type);
       return true;
   });
   ```

2. **用户编写 Frida 脚本，使用 `Interceptor.replace()` 或 `Interceptor.attach()` Hook 了某个函数，并且在 Hook 的实现中引入了可能导致异常的代码:**  例如，尝试访问空指针或执行非法操作。

   ```javascript
   // JavaScript Frida 代码
   Interceptor.attach(Module.findExportByName(null, "some_function"), {
       onEnter: function(args) {
           // 错误地访问一个指针
           var ptr = null;
           console.log(ptr.readInt()); // 这会抛出异常
       }
   });
   ```

3. **Frida 内部操作触发了异常:**  Frida 在进行代码注入、内存操作或其他内部操作时，自身也可能遇到异常。虽然这些异常通常会被 Frida 内部处理，但在某些情况下，用户注册的全局异常处理函数也可能被调用。

4. **用户使用 Frida 提供的 API (如 `Memory.read*()`, `Memory.write*()`) 尝试访问无效的内存地址:** 这些操作可能会触发访问违规异常。

5. **目标进程本身的代码执行过程中发生了异常:**  即使没有用户编写的 Frida 脚本，目标进程自身也可能存在 bug 或错误，导致异常发生。Frida 的异常处理机制会捕获这些异常，前提是有注册相应的处理函数。

**作为调试线索:**

当用户报告 Frida 脚本行为异常或目标进程出现问题时，了解 `gumexceptor.c` 的工作原理可以提供以下调试线索：

* **检查是否注册了异常处理函数:**  确认用户是否通过 `Process.setExceptionHandler()` 注册了全局异常处理函数。
* **分析异常类型和发生地址:** 如果捕获到了异常，`details->type` 和 `details->memory.address` 可以帮助定位问题发生的类型和位置。
* **查看 CPU 上下文:** `details->context` 包含了异常发生时的 CPU 寄存器状态，这对于理解程序当时的执行状态至关重要。
* **检查是否使用了 `try-catch` 机制:**  如果用户尝试使用 Frida 的 `try-catch` 机制，需要检查 `_gum_exceptor_prepare_try()` 和 `gum_exceptor_catch()` 的使用是否正确。
* **分析异常处理函数的逻辑:**  如果注册了异常处理函数，需要检查该函数的实现是否存在错误，或者是否正确地处理了预期的异常类型。
* **考虑多线程并发问题:**  如果目标进程是多线程的，需要考虑异常是否发生在特定的线程，以及是否存在并发访问共享资源的问题。

总而言之，`gumexceptor.c` 是 Frida 中一个关键的低层组件，它赋予了 Frida 强大的异常处理能力，这对于动态分析、逆向工程和调试目标进程至关重要。理解其工作原理有助于我们更好地利用 Frida，并能更有效地排查使用过程中遇到的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumexceptor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumexceptor.h"

#include "gumexceptorbackend.h"

#include <string.h>

typedef struct _GumExceptionHandlerEntry GumExceptionHandlerEntry;

#define GUM_EXCEPTOR_LOCK()   (g_mutex_lock (&self->mutex))
#define GUM_EXCEPTOR_UNLOCK() (g_mutex_unlock (&self->mutex))

struct _GumExceptor
{
  GObject parent;

  GMutex mutex;

  GSList * handlers;
  GHashTable * scopes;

  GumExceptorBackend * backend;
};

struct _GumExceptionHandlerEntry
{
  GumExceptionHandler func;
  gpointer user_data;
};

static void gum_exceptor_dispose (GObject * object);
static void gum_exceptor_finalize (GObject * object);
static void the_exceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);

static gboolean gum_exceptor_handle_exception (GumExceptionDetails * details,
    GumExceptor * self);
static gboolean gum_exceptor_handle_scope_exception (
    GumExceptionDetails * details, gpointer user_data);

static void gum_exceptor_scope_perform_longjmp (GumExceptorScope * scope);

G_DEFINE_TYPE (GumExceptor, gum_exceptor, G_TYPE_OBJECT)

G_LOCK_DEFINE_STATIC (the_exceptor);
static GumExceptor * the_exceptor = NULL;
static gboolean gum_exceptor_is_available = TRUE;

static void
gum_exceptor_class_init (GumExceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_exceptor_dispose;
  object_class->finalize = gum_exceptor_finalize;
}

static void
gum_exceptor_init (GumExceptor * self)
{
  g_mutex_init (&self->mutex);

  self->scopes = g_hash_table_new (NULL, NULL);

  gum_exceptor_add (self, gum_exceptor_handle_scope_exception, self);

  gum_exceptor_reset (self);
}

static void
gum_exceptor_dispose (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);

  g_clear_object (&self->backend);

  G_OBJECT_CLASS (gum_exceptor_parent_class)->dispose (object);
}

static void
gum_exceptor_finalize (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);

  gum_exceptor_remove (self, gum_exceptor_handle_scope_exception, self);

  g_hash_table_unref (self->scopes);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_exceptor_parent_class)->finalize (object);
}

void
gum_exceptor_disable (void)
{
  g_assert (the_exceptor == NULL);

  gum_exceptor_is_available = FALSE;
}

GumExceptor *
gum_exceptor_obtain (void)
{
  GumExceptor * exceptor;

  G_LOCK (the_exceptor);

  if (the_exceptor != NULL)
  {
    exceptor = g_object_ref (the_exceptor);
  }
  else
  {
    the_exceptor = g_object_new (GUM_TYPE_EXCEPTOR, NULL);
    g_object_weak_ref (G_OBJECT (the_exceptor), the_exceptor_weak_notify, NULL);

    exceptor = the_exceptor;
  }

  G_UNLOCK (the_exceptor);

  return exceptor;
}

static void
the_exceptor_weak_notify (gpointer data,
                          GObject * where_the_object_was)
{
  G_LOCK (the_exceptor);

  g_assert (the_exceptor == (GumExceptor *) where_the_object_was);
  the_exceptor = NULL;

  G_UNLOCK (the_exceptor);
}

void
gum_exceptor_reset (GumExceptor * self)
{
  g_clear_object (&self->backend);

  if (gum_exceptor_is_available)
  {
    self->backend = gum_exceptor_backend_new (
        (GumExceptionHandler) gum_exceptor_handle_exception, self);
  }
}

void
gum_exceptor_add (GumExceptor * self,
                  GumExceptionHandler func,
                  gpointer user_data)
{
  GumExceptionHandlerEntry * entry;

  entry = g_slice_new (GumExceptionHandlerEntry);
  entry->func = func;
  entry->user_data = user_data;

  GUM_EXCEPTOR_LOCK ();
  self->handlers = g_slist_append (self->handlers, entry);
  GUM_EXCEPTOR_UNLOCK ();
}

void
gum_exceptor_remove (GumExceptor * self,
                     GumExceptionHandler func,
                     gpointer user_data)
{
  GumExceptionHandlerEntry * matching_entry;
  GSList * cur;

  GUM_EXCEPTOR_LOCK ();

  for (matching_entry = NULL, cur = self->handlers;
      matching_entry == NULL && cur != NULL;
      cur = cur->next)
  {
    GumExceptionHandlerEntry * entry = (GumExceptionHandlerEntry *) cur->data;

    if (entry->func == func && entry->user_data == user_data)
      matching_entry = entry;
  }

  g_assert (matching_entry != NULL);

  self->handlers = g_slist_remove (self->handlers, matching_entry);

  GUM_EXCEPTOR_UNLOCK ();

  g_slice_free (GumExceptionHandlerEntry, matching_entry);
}

static gboolean
gum_exceptor_handle_exception (GumExceptionDetails * details,
                               GumExceptor * self)
{
  gboolean handled = FALSE;
  GSList * invoked = NULL;
  GumExceptionHandlerEntry e;

  do
  {
    GSList * cur;

    e.func = NULL;
    e.user_data = NULL;

    GUM_EXCEPTOR_LOCK ();
    for (cur = self->handlers; e.func == NULL && cur != NULL; cur = cur->next)
    {
      GumExceptionHandlerEntry * entry = (GumExceptionHandlerEntry *) cur->data;

      if (g_slist_find (invoked, entry) == NULL)
      {
        invoked = g_slist_prepend (invoked, entry);
        e = *entry;
      }
    }
    GUM_EXCEPTOR_UNLOCK ();

    if (e.func != NULL)
      handled = e.func (details, e.user_data);
  }
  while (!handled && e.func != NULL);

  g_slist_free (invoked);

  return handled;
}

void
_gum_exceptor_prepare_try (GumExceptor * self,
                           GumExceptorScope * scope)
{
  gpointer thread_id_key;

  thread_id_key = GSIZE_TO_POINTER (gum_process_get_current_thread_id ());

  scope->exception_occurred = FALSE;
#ifdef HAVE_ANDROID
  /* Workaround for Bionic bug up to and including Android L */
  sigprocmask (SIG_SETMASK, NULL, &scope->mask);
#endif

  GUM_EXCEPTOR_LOCK ();
  scope->next = g_hash_table_lookup (self->scopes, thread_id_key);
  g_hash_table_insert (self->scopes, thread_id_key, scope);
  GUM_EXCEPTOR_UNLOCK ();
}

gboolean
gum_exceptor_catch (GumExceptor * self,
                    GumExceptorScope * scope)
{
  gpointer thread_id_key;

  thread_id_key = GSIZE_TO_POINTER (gum_process_get_current_thread_id ());

  GUM_EXCEPTOR_LOCK ();
  g_hash_table_insert (self->scopes, thread_id_key, scope->next);
  GUM_EXCEPTOR_UNLOCK ();

  return scope->exception_occurred;
}

gboolean
gum_exceptor_has_scope (GumExceptor * self, GumThreadId thread_id)
{
  GumExceptorScope * scope;

  GUM_EXCEPTOR_LOCK ();
  scope = g_hash_table_lookup (self->scopes, GSIZE_TO_POINTER (thread_id));
  GUM_EXCEPTOR_UNLOCK ();

  return scope != NULL;
}

gchar *
gum_exception_details_to_string (const GumExceptionDetails * details)
{
  GString * message;

  message = g_string_new ("");

  switch (details->type)
  {
    case GUM_EXCEPTION_ABORT:
      g_string_append (message, "abort was called");
      break;
    case GUM_EXCEPTION_ACCESS_VIOLATION:
      g_string_append (message, "access violation");
      break;
    case GUM_EXCEPTION_GUARD_PAGE:
      g_string_append (message, "guard page was hit");
      break;
    case GUM_EXCEPTION_ILLEGAL_INSTRUCTION:
      g_string_append (message, "illegal instruction");
      break;
    case GUM_EXCEPTION_STACK_OVERFLOW:
      g_string_append (message, "stack overflow");
      break;
    case GUM_EXCEPTION_ARITHMETIC:
      g_string_append (message, "arithmetic error");
      break;
    case GUM_EXCEPTION_BREAKPOINT:
      g_string_append (message, "breakpoint triggered");
      break;
    case GUM_EXCEPTION_SINGLE_STEP:
      g_string_append (message, "single-step triggered");
      break;
    case GUM_EXCEPTION_SYSTEM:
      g_string_append (message, "system error");
      break;
    default:
      break;
  }

  if (details->memory.operation != GUM_MEMOP_INVALID)
  {
    g_string_append_printf (message, " accessing 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (details->memory.address));
  }

  return g_string_free (message, FALSE);
}

static gboolean
gum_exceptor_handle_scope_exception (GumExceptionDetails * details,
                                     gpointer user_data)
{
  GumExceptor * self = GUM_EXCEPTOR (user_data);
  GumExceptorScope * scope;
  GumCpuContext * context = &details->context;

  GUM_EXCEPTOR_LOCK ();
  scope = g_hash_table_lookup (self->scopes,
      GSIZE_TO_POINTER (details->thread_id));
  GUM_EXCEPTOR_UNLOCK ();
  if (scope == NULL)
    return FALSE;

  if (scope->exception_occurred)
    return FALSE;

  scope->exception_occurred = TRUE;
  memcpy (&scope->exception, details, sizeof (GumExceptionDetails));
  scope->exception.native_context = NULL;

  /*
   * Place IP at the start of the function as if the call already happened,
   * and set up stack and registers accordingly.
   */
#if defined (HAVE_I386)
  GUM_CPU_CONTEXT_XIP (context) = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));

  /* Align to 16 byte boundary (macOS ABI) */
  GUM_CPU_CONTEXT_XSP (context) &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  GUM_CPU_CONTEXT_XSP (context) -= GUM_RED_ZONE_SIZE;
  /* Reserve spill space for first four arguments (Win64 ABI) */
  GUM_CPU_CONTEXT_XSP (context) -= 4 * 8;

# if GLIB_SIZEOF_VOID_P == 4
  /* 32-bit: First argument goes on the stack (cdecl) */
  *((GumExceptorScope **) context->esp) = scope;
# else
  /* 64-bit: First argument goes in a register */
#  if GUM_NATIVE_ABI_IS_WINDOWS
  context->rcx = GPOINTER_TO_SIZE (scope);
#  else
  context->rdi = GPOINTER_TO_SIZE (scope);
#  endif
# endif

  /* Dummy return address (we won't return) */
  GUM_CPU_CONTEXT_XSP (context) -= sizeof (gpointer);
  *((gsize *) GUM_CPU_CONTEXT_XSP (context)) = 1337;
#elif defined (HAVE_ARM)
  context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));
  if ((context->pc & 1) != 0)
    context->cpsr |= GUM_PSR_T_BIT;
  else
    context->cpsr &= ~GUM_PSR_T_BIT;
  context->pc &= ~1;

  /* Align to 16 byte boundary */
  context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  context->sp -= GUM_RED_ZONE_SIZE;

  context->r[0] = GPOINTER_TO_SIZE (scope);

  /* Dummy return address (we won't return) */
  context->lr = 1337;
#elif defined (HAVE_ARM64)
  {
    gsize pc, sp, lr;

    pc = GPOINTER_TO_SIZE (
        GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));
    sp = context->sp;

# ifdef HAVE_PTRAUTH
    pc = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (pc),
        ptrauth_key_process_independent_code));
    sp = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (sp),
        ptrauth_key_process_independent_data));
# endif

    /* Align to 16 byte boundary */
    sp &= ~(gsize) (16 - 1);
    /* Avoid the red zone (when applicable) */
    sp -= GUM_RED_ZONE_SIZE;

    /* Dummy return address (we won't return) */
    lr = 1337;

# ifdef HAVE_PTRAUTH
    pc = GPOINTER_TO_SIZE (
        ptrauth_sign_unauthenticated (GSIZE_TO_POINTER (pc),
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator ("pc")));
    sp = GPOINTER_TO_SIZE (
        ptrauth_sign_unauthenticated (GSIZE_TO_POINTER (sp),
        ptrauth_key_process_independent_data,
        ptrauth_string_discriminator ("sp")));
    lr = GPOINTER_TO_SIZE (
        ptrauth_sign_unauthenticated (GSIZE_TO_POINTER (lr),
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator ("lr")));
# endif

    context->pc = pc;
    context->sp = sp;
    context->lr = lr;

    context->x[0] = GPOINTER_TO_SIZE (scope);
  }
#elif defined (HAVE_MIPS)
  context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));

  /*
   * Set t9 to gum_exceptor_scope_perform_longjmp, as it is PIC and needs
   * t9 for the gp calculation.
   */
  context->t9 = context->pc;

  /* Align to 16 byte boundary */
  context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  context->sp -= GUM_RED_ZONE_SIZE;

  context->a0 = GPOINTER_TO_SIZE (scope);

  /* Dummy return address (we won't return) */
  context->ra = 1337;
#else
# error Unsupported architecture
#endif

  return TRUE;
}

static void
gum_exceptor_scope_perform_longjmp (GumExceptorScope * self)
{
#ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &self->mask, NULL);
#endif
  GUM_NATIVE_LONGJMP (self->env, 1);
}

#endif

"""

```