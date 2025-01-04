Response:
Let's break down the thought process for analyzing this C code snippet and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `gumtls-windows.c` file within the context of Frida. The prompt specifically asks about its features, relationship to reverse engineering, interactions with the binary level and kernel, logic, potential errors, and how a user might reach this code during debugging.

**2. Initial Code Scan and Keyword Recognition:**

A quick scan of the code reveals several key elements:

* **`#include` directives:** `gumtls.h`, `gumprocess.h`, `gumspinlock.h`, `<windows.h>`. This immediately tells us the code interacts with Windows APIs and likely relies on other Frida-specific components for process and threading management, as well as synchronization.
* **`GumTlsKey`:**  This custom type and related functions (`gum_tls_key_new`, `gum_tls_key_free`, `gum_tls_key_get_value`, `gum_tls_key_set_value`) strongly suggest the code is about managing Thread Local Storage (TLS).
* **`TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`:** These are standard Windows API functions for TLS management.
* **`#if defined (HAVE_I386)`:** This indicates architecture-specific code, likely targeting 32-bit systems. The presence of `__readfsdword` and `__writefsdword` further confirms this, as these are intrinsics for accessing the FS segment register on x86. The `__readgsqword` and `__writegsqword` appearing later point to 64-bit support.
* **`GumSpinlock`:**  This highlights the importance of thread safety and synchronization when accessing TLS data, especially the temporary storage mechanism.
* **`gum_process_get_current_thread_id()`:** This links the TLS management to specific threads.
* **`MAX_TMP_TLS_KEY`:**  This constant suggests a temporary, limited-size storage mechanism for TLS values.
* **`memset`:** Used for initializing the temporary TLS storage.
* **`g_assert`:** Indicates assertions for debugging and ensuring program correctness.

**3. Deconstructing the Functionality (Feature Identification):**

Based on the keywords and code structure, the core functionality is clearly about providing a cross-platform abstraction for thread-local storage within Frida on Windows. Specifically:

* **TLS Key Allocation and Deallocation:**  The `gum_tls_key_new` and `gum_tls_key_free` functions wrap the Windows API to manage TLS indices.
* **TLS Value Get and Set:** The `gum_tls_key_get_value` and `gum_tls_key_set_value` functions are responsible for retrieving and storing values associated with a TLS key.
* **Architecture-Specific Handling (x86):** The `#if defined (HAVE_I386)` block shows a special mechanism for managing TLS on 32-bit Windows. This involves directly accessing memory locations via segment registers and a temporary storage array (`gum_tls_tmp_keys`). This is likely an optimization or workaround for limitations on how TLS is accessed in certain scenarios. The temporary storage with a spinlock suggests handling cases where the standard Windows TLS mechanism might not be immediately available or efficient.
* **Thread-Local Scope:** The code explicitly uses thread IDs to ensure that TLS values are specific to the current thread.

**4. Linking to Reverse Engineering:**

With the understanding of TLS management, the connection to reverse engineering becomes apparent:

* **Hooking and Instrumentation:** Frida is a dynamic instrumentation tool. When Frida injects code into a target process, that injected code might need thread-local storage to maintain its own state without interfering with the target process's TLS. This file likely provides the mechanism for Frida's injected code to have its own TLS.
* **Observing Thread State:**  Reverse engineers often need to understand the state of individual threads in a running process. Frida, by using its own TLS, can track information specific to its hooks and scripts running within different threads.

**5. Identifying Binary/Kernel/Framework Interactions:**

* **Windows API:** The direct usage of `TlsAlloc`, `TlsFree`, `TlsGetValue`, and `TlsSetValue` signifies direct interaction with the Windows operating system's API for thread local storage.
* **Segment Registers (x86):** The use of `__readfsdword` and `__readgsqword` directly interacts with the processor's architecture and how TLS is implemented at a low level on x86 Windows. The FS segment register points to the Thread Environment Block (TEB), which contains thread-local data.
* **No Direct Linux/Android Kernel Interaction (in this file):**  This specific file is for Windows. Frida has separate implementations for other platforms.

**6. Logical Reasoning and Assumptions:**

* **Assumption (Temporary Storage):** The `gum_tls_tmp_keys` array suggests a fallback mechanism. A reasonable assumption is that Windows might have limitations or performance issues with dynamically allocated TLS slots in certain scenarios, especially early in thread creation or in special contexts. The temporary array provides a pre-allocated, fast storage option.
* **Input/Output (Conceptual):**  While there's no explicit user input here, conceptually:
    * **Input:** A Frida script or Gum code requests to allocate a TLS key (`gum_tls_key_new`) and set a value for a specific thread (`gum_tls_key_set_value`).
    * **Output:** `gum_tls_key_new` returns a `GumTlsKey` (a DWORD index). `gum_tls_key_set_value` stores the provided `gpointer` associated with the key and the current thread. `gum_tls_key_get_value` would later retrieve this `gpointer` for the same thread and key.

**7. User/Programming Errors:**

* **Resource Exhaustion:**  The `MAX_TMP_TLS_KEY` constant introduces a potential error. If too many temporary TLS keys are used simultaneously, the assertion `g_assert (i < MAX_TMP_TLS_KEY)` will fail, likely crashing the Frida agent.
* **Incorrect Key Usage:**  Using a `GumTlsKey` that has been freed (`gum_tls_key_free`) would lead to undefined behavior and potential crashes. The Windows API might reuse the index.
* **Race Conditions (Potential):** Although the spinlock protects the `gum_tls_tmp_keys` array, incorrect usage patterns in other parts of Frida that rely on this TLS mechanism could introduce race conditions if not properly synchronized.

**8. Debugging Scenario and User Steps:**

To arrive at this code during debugging:

1. **User Writes a Frida Script:** A user interacts with Frida by writing a JavaScript or Python script.
2. **Script Uses Frida APIs:** The script might use Frida's API to hook functions, modify memory, or track thread-specific data.
3. **Frida Internals Use TLS:**  Internally, Frida's Gum library (which this file belongs to) might need to store thread-local information for its instrumentation logic (e.g., data related to active hooks within a specific thread).
4. **Execution on Windows:** The target application is running on Windows.
5. **Potential 32-bit Target:** If the target is a 32-bit application, the architecture-specific code within this file will be executed.
6. **Debugging Frida:** If the user encounters issues related to thread-local storage within their Frida script or observes crashes within the Frida agent, they might delve into Frida's source code to understand how TLS is managed. Setting breakpoints within `gum_tls_key_get_value` or `gum_tls_key_set_value` would lead them to this file. They might also look at stack traces that point to these functions.

**Self-Correction/Refinement:**

Initially, I might have focused solely on the Windows API aspects. However, recognizing the `#if defined (HAVE_I386)` block and the custom temporary storage mechanism is crucial for a complete understanding. Also, explicitly considering potential error scenarios and how a user would interact with Frida to trigger this code strengthens the analysis. Connecting the functionality directly back to Frida's core purpose of dynamic instrumentation is also essential.
This C source file, `gumtls-windows.c`, is part of the Frida dynamic instrumentation toolkit and specifically deals with **Thread Local Storage (TLS)** on the Windows platform. Let's break down its functionalities:

**Core Functionality: Managing Thread Local Storage (TLS)**

The primary purpose of this file is to provide an abstraction layer for managing thread-specific data within Frida's Gum library on Windows. TLS allows each thread in a process to have its own independent copy of certain variables or data structures. This is crucial in multi-threaded environments to avoid race conditions and maintain data integrity.

**Key Functions and Their Roles:**

* **`gum_tls_key_new()`:**
    * **Function:** Allocates a new TLS slot (index) for use within the process.
    * **Mechanism:**  It directly calls the Windows API function `TlsAlloc()`. `TlsAlloc()` returns a DWORD (a number) that serves as the index for accessing thread-local storage.
    * **Error Handling:** It asserts that `TlsAlloc()` does not return `TLS_OUT_OF_INDEXES`, which indicates that the system has run out of available TLS slots.

* **`gum_tls_key_free(GumTlsKey key)`:**
    * **Function:** Releases a previously allocated TLS slot, making it available for reuse.
    * **Mechanism:** It calls the Windows API function `TlsFree(key)` to deallocate the TLS index.

* **`gum_tls_key_get_value(GumTlsKey key)`:**
    * **Function:** Retrieves the value associated with a specific TLS key for the current thread.
    * **Mechanism (Architecture Dependent):**
        * **x86 (32-bit):**  It attempts to read the value directly from the Thread Environment Block (TEB) using assembly instructions like `__readfsdword`. It checks if the key is within a certain range (0-63 and 64-1087). For keys outside the directly accessible range, it uses a temporary storage mechanism (`gum_tls_tmp_keys`).
        * **x64 (64-bit):** Similar to x86, but uses `__readgsqword` to access the TEB and different offsets.
        * **Other Architectures:** It uses the standard Windows API function `TlsGetValue(key)`.
    * **Temporary Storage (x86):**  The temporary storage is used as a fallback, possibly for optimization or handling cases where direct TEB access isn't immediately available or efficient. It uses a spinlock (`gum_tls_tmp_keys_lock`) for thread safety.

* **`gum_tls_key_set_value(GumTlsKey key, gpointer value)`:**
    * **Function:** Sets the value associated with a specific TLS key for the current thread.
    * **Mechanism (Architecture Dependent):**
        * **x86 (32-bit):**  Writes the value directly to the TEB using `__writefsdword`. For keys outside the directly accessible range, it uses the temporary storage or calls `TlsSetValue` as a fallback.
        * **x64 (64-bit):** Similar to x86, but uses `__writegsqword`.
        * **Other Architectures:** It uses the standard Windows API function `TlsSetValue(key, value)`.
    * **Temporary Storage (x86):** When using temporary storage, it sets the value in the `gum_tls_tmp_keys` array, and potentially also calls `TlsSetValue` to ensure broader compatibility or eventual consistency.

* **`_gum_tls_init()`, `_gum_tls_realize()`, `_gum_tls_deinit()`:**
    * **Function:** These functions are part of the initialization and cleanup lifecycle of the TLS module.
    * **Mechanism:**
        * `_gum_tls_init()`: Initializes the temporary TLS key array by setting all entries to zero.
        * `_gum_tls_realize()`: Currently empty, potentially reserved for future initialization steps that might be needed after the module is loaded.
        * `_gum_tls_deinit()`: Currently empty, potentially reserved for future cleanup tasks when the module is unloaded.

**Temporary TLS Key Management (x86 Specific):**

The code for x86 includes a temporary mechanism for storing TLS values. This involves:

* **`gum_tls_tmp_keys`:** An array of `GumTmpTlsKey` structures. Each structure holds the thread ID (`tid`), the TLS key (`key`), and the associated value.
* **`gum_tls_tmp_keys_lock`:** A spinlock to protect access to the `gum_tls_tmp_keys` array, ensuring thread safety when multiple threads are trying to access or modify it.
* **`gum_tls_key_get_tmp_value()`, `gum_tls_key_set_tmp_value()`, `gum_tls_key_del_tmp_value()`:** These helper functions manage the temporary storage, searching for existing entries or adding/removing them based on the thread ID and TLS key.

**Relationship to Reverse Engineering:**

This file is directly relevant to reverse engineering, especially when using Frida for dynamic analysis:

* **Hooking and Instrumentation:** Frida allows reverse engineers to inject code into running processes. This injected code often needs to store its own thread-specific state. `gumtls-windows.c` provides the mechanism for Frida's injected code (within the Gum library) to have its own TLS, separate from the target process's TLS. This prevents interference and ensures that Frida's hooks and instrumentation logic work correctly across different threads.
* **Observing Thread Context:** Reverse engineers might use Frida to track the execution flow and data within specific threads. By understanding how Frida manages its own TLS, they can better interpret the data and context associated with their hooks and probes.
* **Circumventing Anti-Debugging Techniques:** Some anti-debugging techniques rely on manipulating or checking TLS values. Frida's independent TLS management helps ensure that Frida's functionality is not disrupted by such techniques.

**Example:** Imagine you are using Frida to hook a function that is called from multiple threads. You want to track how many times this function is called from each thread. You could use Frida's API (which internally uses `gumtls`) to create a TLS key and then increment a counter associated with that key each time the hooked function is called within a particular thread.

**Involvement of Binary Bottom, Linux, Android Kernel/Framework:**

* **Binary Bottom (Windows):** This file directly interacts with the Windows operating system at a low level through the Windows API functions for TLS management (`TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`). On x86 architectures, it even goes further by directly manipulating memory locations within the Thread Environment Block (TEB) using assembly instructions (`__readfsdword`, `__writefsdword`, `__readgsqword`, `__writegsqword`). This demonstrates a deep understanding of the underlying binary structure of threads on Windows.
* **Linux and Android Kernel/Framework:**  This specific file is **exclusively for Windows**. Frida has separate implementations for TLS management on Linux and Android. These implementations would interact with the respective kernel APIs (e.g., `pthread_key_create`, `pthread_getspecific`, `pthread_setspecific` on Linux) or framework components for thread-local storage on Android.

**Logic and Assumptions:**

* **Assumption:** The code assumes that the `TlsAlloc()` function will succeed in allocating a TLS slot. The `g_assert()` verifies this assumption in debug builds.
* **Logic (x86 Temporary Storage):** The logic for the temporary TLS storage on x86 involves:
    * Getting the current thread ID.
    * Acquiring a spinlock for thread safety.
    * Iterating through the `gum_tls_tmp_keys` array to find an existing entry for the current thread and key (for getting) or an empty slot (for setting).
    * Storing or retrieving the value.
    * Releasing the spinlock.
    * **Assumption:** The `MAX_TMP_TLS_KEY` constant defines the maximum number of temporary TLS keys that can be used concurrently. If this limit is reached, the `gum_tls_key_set_tmp_value()` function will trigger an assertion failure, indicating an error.
    * **Reasoning for Temporary Storage:** The temporary storage likely exists as an optimization or workaround for certain scenarios on x86 Windows where direct access to the TEB might have performance implications or limitations. It provides a fast, local cache for TLS values.

**Example of Assumption, Input, and Output (Temporary Storage on x86):**

**Hypothetical Input:**

1. Thread A calls `gum_tls_key_set_value(key1, value_a)`.
2. Thread B calls `gum_tls_key_set_value(key1, value_b)`.
3. Thread A calls `gum_tls_key_get_value(key1)`.

**Process and Output:**

1. **Thread A (Set):**
   - `gum_tls_key_set_value()` is called.
   - If `key1` is within the temporary range and no entry exists for Thread A and `key1`, an empty slot in `gum_tls_tmp_keys` is found.
   - `gum_tls_tmp_keys[i].tid` is set to Thread A's ID.
   - `gum_tls_tmp_keys[i].key` is set to `key1`.
   - `gum_tls_tmp_keys[i].value` is set to `value_a`.

2. **Thread B (Set):**
   - `gum_tls_key_set_value()` is called.
   - An empty slot in `gum_tls_tmp_keys` is found.
   - `gum_tls_tmp_keys[j].tid` is set to Thread B's ID.
   - `gum_tls_tmp_keys[j].key` is set to `key1`.
   - `gum_tls_tmp_keys[j].value` is set to `value_b`.

3. **Thread A (Get):**
   - `gum_tls_key_get_value()` is called.
   - The code searches `gum_tls_tmp_keys` for an entry where `tid` matches Thread A's ID and `key` matches `key1`.
   - The entry set in step 1 is found.
   - **Output:** `value_a` is returned.

**User or Programming Common Usage Errors:**

* **Forgetting to Free TLS Keys:** If a `GumTlsKey` is allocated with `gum_tls_key_new()` but not freed with `gum_tls_key_free()`, it can lead to resource leaks over time, potentially exhausting available TLS slots.
* **Accessing Invalid Keys:** Trying to get or set the value for a TLS key that has not been allocated or has already been freed will result in undefined behavior and potential crashes.
* **Race Conditions (if not using Gum's API correctly):** While `gumtls-windows.c` implements internal locking, if the higher-level Gum API that utilizes this is not used correctly, race conditions might still occur in user code trying to access thread-local data without proper synchronization.
* **Exceeding `MAX_TMP_TLS_KEY` (on x86):**  If a Frida script or Gum internals attempt to allocate more temporary TLS keys than `MAX_TMP_TLS_KEY`, the assertion in `gum_tls_key_set_tmp_value()` will fail, halting execution. This could happen if a large number of threads are simultaneously using a feature relying on this temporary storage.

**User Operation Steps to Reach Here (Debugging Scenario):**

1. **User Writes a Frida Script:** A user writes a Frida script (in JavaScript or Python) that instruments a Windows application.
2. **Script Uses Frida APIs:** The script uses Frida's API to hook functions, read/write memory, or track data specific to threads. For instance, the script might use `Thread.getCurrentId()` and attempt to store thread-specific information.
3. **Frida Internals Utilize Gum's TLS:** When the Frida script is executed, the underlying Gum library might internally use the functions in `gumtls-windows.c` to manage thread-local storage for its own purposes (e.g., storing context for active hooks within a thread).
4. **Encountering an Issue:** The user might encounter a bug or unexpected behavior related to thread-specific data within their Frida script or even within Frida itself.
5. **Debugging Frida:** The user decides to debug the Frida agent or their script more deeply. They might use a debugger (like WinDbg or a GDB-like debugger attached to the Frida agent process).
6. **Setting Breakpoints:** The user might set breakpoints in Frida's code related to thread management or data access, suspecting an issue with how thread-local data is handled. They might set a breakpoint in `gum_tls_key_get_value` or `gum_tls_key_set_value`.
7. **Stepping Through Code:** When the breakpoint is hit, the user will see the execution flow entering the `gumtls-windows.c` file. They can then step through the code to understand how TLS is being managed, inspect the values of TLS keys, and identify potential problems.
8. **Analyzing Crash Dumps:** If Frida crashes, the user might analyze a crash dump. The call stack in the dump might point to functions within `gumtls-windows.c`, providing a clue about the source of the crash (e.g., an assertion failure in the temporary TLS management).

By understanding the functions and mechanisms within `gumtls-windows.c`, a reverse engineer or Frida user can gain valuable insight into how Frida manages thread-local data on Windows, which can be crucial for debugging, understanding Frida's internals, and developing more robust and reliable instrumentation scripts.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-windows/gumtls-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
* Copyright (C) 2015-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
* Copyright (C) 2015 Eloi Vanderbeken <eloi.vanderbeken@synacktiv.com>
*
* Licence: wxWindows Library Licence, Version 3.1
*/

#include "gumtls.h"

#include "gumprocess.h"
#include "gumspinlock.h"

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#if defined (HAVE_I386)

# define MAX_TMP_TLS_KEY 200

typedef struct _GumTmpTlsKey GumTmpTlsKey;

struct _GumTmpTlsKey
{
  GumThreadId tid;
  GumTlsKey key;
  gpointer value;
};

static gpointer gum_tls_key_get_tmp_value (GumTlsKey key);
static void gum_tls_key_set_tmp_value (GumTlsKey key, gpointer value);
static void gum_tls_key_del_tmp_value (GumTlsKey key);

static GumTmpTlsKey gum_tls_tmp_keys[MAX_TMP_TLS_KEY];
static GumSpinlock gum_tls_tmp_keys_lock = GUM_SPINLOCK_INIT;

#endif

GumTlsKey
gum_tls_key_new (void)
{
  DWORD res;

  res = TlsAlloc ();
  g_assert (res != TLS_OUT_OF_INDEXES);

  return res;
}

void
gum_tls_key_free (GumTlsKey key)
{
  TlsFree (key);
}

void
_gum_tls_init (void)
{
#if defined (HAVE_I386)
  memset (gum_tls_tmp_keys, 0, sizeof (gum_tls_tmp_keys));
#endif
}

void
_gum_tls_realize (void)
{
}

void
_gum_tls_deinit (void)
{
}

#if defined (HAVE_I386)

static gpointer
gum_tls_key_get_tmp_value (GumTlsKey key)
{
  GumThreadId tid;
  gpointer value;
  guint i;

  tid = gum_process_get_current_thread_id ();
  value = NULL;

  gum_spinlock_acquire (&gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEY; i++)
  {
    if (gum_tls_tmp_keys[i].tid == tid && gum_tls_tmp_keys[i].key == key)
    {
      value = gum_tls_tmp_keys[i].value;
      break;
    }
  }

  gum_spinlock_release (&gum_tls_tmp_keys_lock);

  return value;
}

static void
gum_tls_key_set_tmp_value (GumTlsKey key,
                           gpointer value)
{
  GumThreadId tid;
  guint i;

  tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEY; i++)
  {
    if (gum_tls_tmp_keys[i].tid == 0)
    {
      gum_tls_tmp_keys[i].tid = tid;
      gum_tls_tmp_keys[i].key = key;
      gum_tls_tmp_keys[i].value = value;
      break;
    }
  }
  g_assert (i < MAX_TMP_TLS_KEY);

  gum_spinlock_release (&gum_tls_tmp_keys_lock);
}

static void
gum_tls_key_del_tmp_value (GumTlsKey key)
{
  GumThreadId tid;
  guint i;

  tid = gum_process_get_current_thread_id ();

  gum_spinlock_acquire (&gum_tls_tmp_keys_lock);

  for (i = 0; i != MAX_TMP_TLS_KEY; i++)
  {
    if (gum_tls_tmp_keys[i].tid == tid && gum_tls_tmp_keys[i].key == key)
    {
      memset (&gum_tls_tmp_keys[i], 0, sizeof (gum_tls_tmp_keys[i]));
      break;
    }
  }
  g_assert (i < MAX_TMP_TLS_KEY);

  gum_spinlock_release (&gum_tls_tmp_keys_lock);
}

# ifndef _MSC_VER
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Warray-bounds"
# endif

# if GLIB_SIZEOF_VOID_P == 4

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  if (key < 64)
  {
    return (gpointer) __readfsdword (3600 + key * sizeof (gpointer));
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer *) __readfsdword (3988);
    if (tls_expansion_slots != NULL)
      return tls_expansion_slots[key - 64];

    return gum_tls_key_get_tmp_value (key);
  }

  return NULL;
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  if (key < 64)
  {
    __writefsdword (3600 + key * sizeof (gpointer), (DWORD) value);
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer *) __readfsdword (3988);
    if (tls_expansion_slots != NULL)
    {
      tls_expansion_slots[key - 64] = value;
    }
    else
    {
      gum_tls_key_set_tmp_value (key, value);
      TlsSetValue (key, value);
      gum_tls_key_del_tmp_value (key);
    }
  }
}

# elif GLIB_SIZEOF_VOID_P == 8

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  if (key < 64)
  {
    return (gpointer) __readgsqword (0x1480 + key * sizeof (gpointer));
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer) __readgsqword (0x1780);
    if (tls_expansion_slots != NULL)
      return tls_expansion_slots[key - 64];

    return gum_tls_key_get_tmp_value (key);
  }
  return NULL;
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  if (key < 64)
  {
    __writegsqword (0x1480 + key * sizeof (gpointer), (guint64) value);
  }
  else if (key < 1088)
  {
    gpointer * tls_expansion_slots;

    tls_expansion_slots = (gpointer) __readgsqword (0x1780);
    if (tls_expansion_slots != NULL)
    {
      tls_expansion_slots[key - 64] = value;
    }
    else
    {
      gum_tls_key_set_tmp_value (key, value);
      TlsSetValue (key, value);
      gum_tls_key_del_tmp_value (key);
    }
  }
}

# else
#  error Unknown architecture
# endif

# ifndef _MSC_VER
#  pragma GCC diagnostic pop
# endif

#else

gpointer
gum_tls_key_get_value (GumTlsKey key)
{
  return TlsGetValue (key);
}

void
gum_tls_key_set_value (GumTlsKey key,
                       gpointer value)
{
  TlsSetValue (key, value);
}

#endif

"""

```