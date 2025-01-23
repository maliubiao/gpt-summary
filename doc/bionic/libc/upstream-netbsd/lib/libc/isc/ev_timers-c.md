Response:
Let's break down the thought process for analyzing this C source code. The goal is to extract its functionality, understand its relation to Android, explain its implementation details, and address various related concerns.

**1. Initial Understanding and Core Functionality Identification:**

* **Keywords and Context:** The prompt explicitly states this is `ev_timers.c` from NetBSD, used within Android's Bionic libc. The filename itself strongly suggests it deals with timers. The ISC copyright notice reinforces its origin in a networking-focused context.
* **Includes:** Examining the `#include` directives gives clues:
    * `<sys/cdefs.h>`, `fd_setsize.h`:  System-level definitions, likely related to POSIX.
    * `<errno.h>`:  Standard error reporting.
    * `<isc/assertions.h>`, `<isc/eventlib.h>`, `"eventlib_p.h"`:  ISC's event library. This is the central component. The `_p.h` likely indicates private internal definitions.
    * `"port_before.h"`, `"port_after.h"`: Suggests platform adaptation or wrapper layers.
* **Data Structures:**  The definitions of `struct timespec` and potentially `evTimer` (though its internal structure isn't fully visible here, only through pointers) are critical. The `idle_timer` struct is also important for understanding idle timer functionality.
* **Function Names (Public):**  Functions like `evConsTime`, `evAddTime`, `evSubTime`, `evCmpTime`, `evNowTime`, `evSetTimer`, `evClearTimer`, etc., clearly indicate operations related to time manipulation and timer management.
* **Function Names (Private):** Functions prefixed with `due_sooner`, `set_index`, `free_timer`, `print_timer`, `idle_timeout` suggest internal helper functions for managing the timer data structure.

**2. Detailed Analysis of Public Functions:**

* **Time Manipulation:**  Focus on `evConsTime`, `evAddTime`, `evSubTime`, `evCmpTime`, `evNowTime`, `evUTCTime`, `evTimeSpec`, `evTimeVal`. Understand how they convert, compare, and manipulate `struct timespec` and `struct timeval`. Note the use of `CLOCK_REALTIME` and `CLOCK_MONOTONIC`.
* **Timer Management:** Analyze `evSetTimer`, `evClearTimer`, `evResetTimer`, `evConfigTimer`. Key aspects include:
    * Function pointers (`evTimerFunc`).
    * User data pointers (`void *uap`).
    * Due times and intervals (`struct timespec`).
    * The role of `evTimerID`.
    * The interaction with the internal timer data structure (likely a heap based on the `heap_insert`, `heap_delete`, `heap_increased`, `heap_decreased` calls).
* **Idle Timers:** Understand `evSetIdleTimer`, `evClearIdleTimer`, `evResetIdleTimer`, `evTouchIdleTimer`. Note how they build upon the basic timer functionality and introduce the concept of tracking "last touched" time.

**3. Identifying Android Relevance:**

* **Bionic Context:**  The prompt explicitly states this is part of Android's Bionic. This means these functions are fundamental building blocks for higher-level Android functionalities.
* **System Services:**  Consider which Android system services might rely on timers. Things like `AlarmManager`, `PowerManager` (for idle timeouts), and network daemons come to mind.
* **NDK Usage:** Think about how native developers using the NDK might directly or indirectly use timer functionalities. For instance, scheduling tasks or implementing timeouts in network operations.

**4. Implementation Details:**

* **Heap Data Structure:** The calls to `heap_new`, `heap_insert`, `heap_delete`, `heap_increased`, `heap_decreased`, `heap_for_each` strongly indicate a min-heap is used to efficiently manage timers, ordered by their due time. This is a crucial implementation detail for efficient timer management.
* **`due_sooner` function:** This function defines the comparison logic for the heap, confirming it's a min-heap based on the `due` time.
* **`set_index` function:** This function is used by the heap to maintain the index of each timer element within the heap array.
* **`idle_timeout` function:** This is a callback function specifically for idle timers. Understand its logic for checking if the idle timeout has expired and rescheduling the timer if not.

**5. Dynamic Linking Considerations:**

* **`_LIBC` Macro:** The `#ifndef _LIBC` sections are critical. They indicate code that's *not* part of the standard C library build but is used within the event library itself. This suggests the event library might be a separate internal component within Bionic.
* **SO Layout (Conceptual):**  Imagine `libc.so` containing the standard C library functions and potentially this `ev_timers.c` code (though the `#ifndef _LIBC` sections suggest it might be in a separate internal library). Other Android system services would link against `libc.so`.

**6. Error Handling and Common Mistakes:**

* **`EV_ERR` Macro:**  Identify where this macro is used and what kind of errors it handles (e.g., `EINVAL`, `ENOENT`).
* **Invalid Time Values:**  The checks for negative time values and nanoseconds exceeding `BILLION` are important for preventing errors.
* **Misunderstanding Idle Timers:** Explain the difference between regular timers and idle timers and how improper usage of `evTouchIdleTimer` could lead to unexpected behavior.

**7. Tracing and Debugging (Frida Hooking):**

* **Identify Key Functions:** Focus on hooking the public `evSetTimer`, `evClearTimer`, and potentially the `idle_timeout` function.
* **Parameter and Return Value Logging:** Show how to log the input parameters and return values of these functions.
* **Context:**  Emphasize the importance of understanding the execution context when analyzing the output.

**8. Structuring the Response:**

* **Organize by Topic:**  Group the information into logical sections: Functionality, Android Relevance, Implementation Details, Dynamic Linking, Error Handling, Tracing, etc.
* **Use Clear Language:** Explain technical concepts in a way that's understandable.
* **Provide Examples:**  Illustrate concepts with concrete examples, especially for error handling and usage.
* **Address All Parts of the Prompt:** Make sure to answer each question explicitly.

**Self-Correction/Refinement during the Process:**

* **Initial Assumption:**  Initially, I might have assumed `ev_timers.c` was directly part of `libc.so`. However, the `#ifndef _LIBC` sections suggest it's likely in a separate internal library within Bionic that `libc.so` might link against or use. This requires adjusting the dynamic linking explanation.
* **Heap Implementation:**  Recognizing the pattern of heap-related function calls is crucial for understanding the core timer management strategy.
* **Frida Specifics:** Ensure the Frida hook examples are syntactically correct and clearly demonstrate how to intercept the relevant functions.

By following this systematic approach, we can thoroughly analyze the provided C source code and generate a comprehensive and informative response that addresses all aspects of the prompt.
## bionic/libc/upstream-netbsd/lib/libc/isc/ev_timers.c 功能解析

这个文件 `ev_timers.c` 是 Android Bionic C 库中，从 NetBSD 上游同步过来的 `libisc` 库的一部分，专门用于实现事件库 (eventlib) 的定时器功能。它的主要职责是管理和触发基于时间的事件。

**主要功能:**

1. **时间操作:**
   - 提供了一系列用于操作 `struct timespec` 结构体的函数，用于表示和计算时间。
   - 包括：
     - `evConsTime`:  根据秒和纳秒创建一个 `struct timespec` 结构体。
     - `evAddTime`:  将两个 `struct timespec` 结构体的时间相加。
     - `evSubTime`:  将两个 `struct timespec` 结构体的时间相减。
     - `evCmpTime`:  比较两个 `struct timespec` 结构体的时间大小。
     - `evNowTime`:  获取当前时间（可以选择使用 `CLOCK_REALTIME` 或 `CLOCK_MONOTONIC`，后者在 Android 中更常用）。
     - `evUTCTime`:  获取当前 UTC 时间（始终使用 `CLOCK_REALTIME`）。
     - `evTimeSpec`:  将 `struct timeval` 转换为 `struct timespec`。
     - `evTimeVal`:  将 `struct timespec` 转换为 `struct timeval`。

2. **定时器管理:**
   - 提供了创建、启动、清除、重置和配置定时器的功能。
   - 包括：
     - `evSetTimer`:  设置一个新的定时器，指定回调函数、用户数据、到期时间和间隔时间。
     - `evClearTimer`:  清除一个已设置的定时器。
     - `evResetTimer`:  重置一个已设置的定时器的属性（回调函数、用户数据、到期时间和间隔时间）。
     - `evConfigTimer`:  配置定时器的行为，例如设置为速率模式（`rate`) 或间隔模式 (`interval`)。

3. **空闲定时器管理:**
   - 提供了特殊的“空闲定时器”，当在指定时间内没有发生任何事件时触发。
   - 包括：
     - `evSetIdleTimer`:  设置一个新的空闲定时器，指定回调函数、用户数据和最大空闲时间。
     - `evClearIdleTimer`:  清除一个已设置的空闲定时器。
     - `evResetIdleTimer`:  重置一个已设置的空闲定时器的属性。
     - `evTouchIdleTimer`:  重置空闲定时器的计时，表示最近有事件发生。

4. **内部定时器数据结构管理:**
   - `evCreateTimers`:  创建一个用于存储定时器的内部数据结构（这里使用了一个堆）。
   - `evDestroyTimers`:  销毁定时器数据结构并释放相关资源。

**与 Android 功能的关系及举例:**

此文件中的定时器功能是 Android 系统中许多高层功能的基础。Android 的事件循环、异步操作、超时机制等都可能依赖于类似的定时器机制。

**举例：**

* **`AlarmManager` 服务:** Android 的 `AlarmManager` 允许应用程序在未来的特定时间执行操作。虽然 `AlarmManager` 不会直接调用这个文件中的函数，但其底层实现很可能使用了类似的基于内核定时器或用户空间定时器的机制，而 `ev_timers.c` 提供的功能可以作为用户空间定时器的一种实现参考。
* **网络连接超时:** 当应用程序尝试建立网络连接时，通常会设置一个超时时间。如果连接在超时时间内没有建立成功，则会取消连接尝试。`evSetTimer` 可以用于实现这样的超时机制。
* **屏幕超时 (Screen Timeout):** Android 设备在一段时间不活动后会自动关闭屏幕以节省电量。`evSetIdleTimer` 的概念与此类似，可以用于监控用户活动并在空闲一段时间后执行操作（例如关闭屏幕）。
* **`Handler` 和 `Looper` 机制:** Android 的 `Handler` 和 `Looper` 机制允许在特定线程上延迟执行任务。虽然它们主要依赖消息队列，但也可以结合定时器来实现延迟功能。

**libc 函数功能实现详解:**

由于代码中大量使用了宏和内部结构（例如 `evContext_p`, `evTimer` 的具体定义在头文件中），我们只能根据代码逻辑推断其实现方式。

1. **时间操作函数 (`evConsTime`, `evAddTime`, `evSubTime`, `evCmpTime`):**
   - 这些函数直接操作 `struct timespec` 的 `tv_sec` (秒) 和 `tv_nsec` (纳秒) 成员。
   - `evAddTime` 和 `evSubTime` 需要处理纳秒溢出/借位的情况（当纳秒超过 10 亿时进位/借位到秒）。
   - `evCmpTime` 先比较秒，如果秒相等则比较纳秒。

2. **`evNowTime` 和 `evUTCTime`:**
   - 这两个函数尝试使用 `clock_gettime()` 系统调用来获取时间。
   - `evNowTime` 优先使用 `CLOCK_MONOTONIC` (如果定义了 `CLOCK_MONOTONIC` 并且 `__evOptMonoTime` 为真)，否则使用 `CLOCK_REALTIME`。`CLOCK_MONOTONIC` 提供一个稳定的、不随系统时间调整而变化的时间源，适合用于计算时间间隔。`CLOCK_REALTIME` 代表系统当前的实际时间。
   - `evUTCTime` 始终使用 `CLOCK_REALTIME` 获取 UTC 时间。
   - 如果 `clock_gettime()` 失败，则回退到使用 `gettimeofday()`。

3. **`evSetTimer`:**
   - 分配一个 `evTimer` 结构体，存储回调函数 `func`、用户数据 `uap`、到期时间 `due` 和间隔时间 `inter`。
   - 如果 `due` 为 `{0, 0}`，则将其设置为当前时间。
   - 将新的 `evTimer` 插入到定时器堆 `ctx->timers` 中。
   - 定时器堆很可能是一个最小堆，按照 `due` 时间排序，以便快速找到最先到期的定时器。`heap_insert` 函数负责将元素插入堆并维护堆的性质。
   - 如果提供了 `opaqueID`，则将新创建的 `evTimer` 指针赋值给它，作为定时器的唯一标识。

4. **`evClearTimer`:**
   - 根据 `opaqueID` 获取要清除的 `evTimer` 结构体。
   - 如果要清除的定时器当前正在执行（`ctx->cur != NULL && ctx->cur->type == Timer && ctx->cur->u.timer.this == del`），则延迟删除，将间隔时间设置为 0，在 `evDrop()` 中清理。
   - 否则，使用 `heap_delete` 从定时器堆中删除该定时器，并释放 `evTimer` 结构体的内存。

5. **`evResetTimer`:**
   - 根据 `opaqueID` 获取要重置的 `evTimer` 结构体。
   - 更新定时器的 `func`, `uap`, `due`, `inter` 属性。
   - 根据新的 `due` 时间与旧的 `due` 时间的比较结果，调用 `heap_increased` 或 `heap_decreased` 来调整定时器在堆中的位置，以维护堆的排序性质。

6. **`evSetIdleTimer`:**
   - 分配一个 `idle_timer` 结构体，存储回调函数、用户数据、最后一次触摸时间和最大空闲时间。
   - 调用 `evSetTimer` 设置一个普通的定时器，其到期时间为 `lastTouched` 加上 `max_idle`，回调函数为 `idle_timeout`，并将 `idle_timer` 结构体作为用户数据传递给 `idle_timeout`。
   - 将新创建的普通定时器的 ID 存储在 `idle_timer` 的 `timer` 字段中。

7. **`idle_timeout`:**
   - 这是空闲定时器的回调函数。
   - 计算从上次事件发生到现在的空闲时间。
   - 如果空闲时间超过了最大空闲时间，则调用用户提供的回调函数，并将定时器的间隔设置为 0，以便在 `evDrop()` 中清理。
   - 否则，计算剩余的空闲时间，并将普通定时器的间隔设置为这个值，以便在下次事件循环中重新调度。

8. **`evCreateTimers` 和 `evDestroyTimers`:**
   - `evCreateTimers` 调用 `heap_new` 创建一个新的堆结构，用于存储定时器。`due_sooner` 函数定义了堆的排序方式（根据到期时间升序），`set_index` 函数用于在堆调整时更新元素的索引。
   - `evDestroyTimers` 遍历堆中的所有定时器，调用 `free_timer` 释放 `evTimer` 结构体的内存，然后调用 `heap_free` 释放堆结构本身的内存。

**涉及 dynamic linker 的功能:**

这个代码文件本身不直接涉及 dynamic linker 的功能。它属于 `libc` 库的一部分，在程序启动时由 dynamic linker 加载到进程的地址空间。

**SO 布局样本：**

假设 `libc.so` 是主要的 C 库文件，`libisc.so` 是 `libc` 内部使用的库 (实际情况可能更复杂，组件可能更细分)。

```
Memory Map:

0x...7000  - 0x...8fff  [load address of libc.so]
    ...
    [`.text` section - 存放代码]
        ... [evConsTime, evSetTimer 等函数的代码] ...
    [`.data` section - 存放已初始化的全局变量]
    [`.bss` section - 存放未初始化的全局变量]
    ...

0x...9000 - 0x...9fff [load address of libisc.so (如果独立存在)]
    ...
    [`.text` section]
        ... [evCreateTimers, due_sooner 等函数的代码] ...
    ...
```

**链接的处理过程：**

1. **编译时：** 编译器将 `ev_timers.c` 编译成目标文件 (`.o`)。
2. **链接时：** 链接器将 `ev_timers.o` 与其他 `libc` 的目标文件链接在一起，生成最终的共享库 `libc.so`。如果 `libisc` 是一个独立的共享库，那么 `ev_timers.o` 将会被链接到 `libisc.so` 中。
3. **运行时：** 当一个 Android 应用程序启动时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析：** dynamic linker 会解析应用程序和 `libc.so` 之间的符号引用。例如，如果应用程序调用了 `gettimeofday`，dynamic linker 会找到 `libc.so` 中 `gettimeofday` 函数的地址，并将调用跳转到该地址。

**逻辑推理，假设输入与输出:**

**假设输入:**

1. 调用 `evSetTimer(context, my_callback, user_data, {5, 0}, {0, 0}, &timer_id)`  设置一个 5 秒后执行一次的回调函数。
2. 5 秒后，事件循环检查到定时器到期。

**输出:**

1. `my_callback(context, user_data, due_time, interval)` 被调用，其中 `due_time` 接近设置定时器时的当前时间 + 5 秒，`interval` 为 `{0, 0}`。

**假设输入:**

1. 调用 `evSetIdleTimer(context, idle_callback, idle_data, {10, 0}, &idle_timer_id)` 设置一个 10 秒空闲定时器。
2. 在 8 秒后，调用 `evTouchIdleTimer(context, idle_timer_id)`。
3. 在之后的 10 秒内没有其他 `evTouchIdleTimer` 调用。

**输出:**

1. 在第一次 `evTouchIdleTimer` 调用时，空闲定时器被重置。
2. 在第一次 `evTouchIdleTimer` 调用后的 10 秒，`idle_callback(context, idle_data, due_time, max_idle_time)` 被调用，其中 `max_idle_time` 为 `{10, 0}`。

**用户或编程常见的使用错误:**

1. **忘记清除不再需要的定时器:**  这会导致回调函数在不应该执行的时候被调用，并可能造成资源泄漏。
   ```c
   evTimerID timer_id;
   evSetTimer(context, my_func, NULL, evConsTime(1, 0), evConsTime(0, 0), &timer_id);
   // ... 某些情况下不再需要这个定时器了，但忘记调用 evClearTimer(context, timer_id);
   ```

2. **在定时器回调函数中执行耗时操作:**  这会阻塞事件循环，影响程序的响应性。应该将耗时操作放到单独的线程中执行。

3. **错误地使用空闲定时器:**  例如，在应该调用 `evTouchIdleTimer` 的时候忘记调用，导致空闲定时器过早触发。

4. **时间单位混淆:**  虽然 `struct timespec` 使用秒和纳秒，但有时开发者可能会误以为是毫秒或微秒，导致定时器设置错误。

5. **不处理 `evSetTimer` 的返回值:** `evSetTimer` 可能会返回错误，例如由于内存分配失败。忽略返回值可能导致程序行为异常。

**Android framework 或 NDK 如何一步步到达这里，以及 Frida hook 示例调试:**

**路径示例 (Framework):**

1. **`AlarmManager` 服务:**  Android Framework 的 `AlarmManager` 服务负责管理应用程序的闹钟和定时任务。
2. **`AlarmThread` 或 `DeliveryRunner`:**  `AlarmManager` 内部可能有线程负责检查到期的闹钟。
3. **Native 代码 (可能):**  `AlarmManager` 的某些底层实现可能涉及 Native 代码，例如使用 `epoll` 或 `select` 等系统调用来监听定时器事件。
4. **Bionic `libc`:**  最终，这些 Native 代码可能会使用 Bionic `libc` 提供的定时器相关函数，或者使用内核提供的 timerfd 等机制。虽然 `AlarmManager` 不会直接调用 `ev_timers.c` 中的函数（因为它有自己的实现），但其概念和原理是相似的。

**路径示例 (NDK):**

1. **NDK 应用程序:**  一个使用 NDK 开发的应用程序需要实现一个定时器功能。
2. **`pthread_cond_timedwait`:** 一种常见的方式是使用 `pthread_cond_timedwait`，它允许线程等待一个条件变量，并在超时后返回。
3. **`clock_gettime` (Bionic `libc`):** `pthread_cond_timedwait` 的实现内部会使用 `clock_gettime` 等 Bionic `libc` 的时间函数来计算超时时间。
4. **间接使用:**  虽然 NDK 应用不太可能直接调用 `ev_timers.c` 中的 `evSetTimer` 等函数（因为这些是 ISC eventlib 的一部分，不属于标准的 POSIX 或 Android NDK API），但理解 `ev_timers.c` 的实现有助于理解底层定时器的工作原理。

**Frida Hook 示例:**

假设我们想 hook `evSetTimer` 函数来观察定时器的设置情况。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "evSetTimer"), {
    onEnter: function(args) {
        const context = args[0];
        const func = args[1];
        const uap = args[2];
        const due_sec = ptr(args[3]).readU64();
        const due_nsec = ptr(args[3]).add(8).readU64();
        const inter_sec = ptr(args[4]).readU64();
        const inter_nsec = ptr(args[4]).add(8).readU64();
        const opaqueID = args[5];

        console.log("[evSetTimer] Called");
        console.log("  Context:", context);
        console.log("  Function:", func);
        console.log("  User Data:", uap);
        console.log("  Due Time:", due_sec.toString() + "." + due_nsec.toString().padStart(9, '0'));
        console.log("  Interval:", inter_sec.toString() + "." + inter_nsec.toString().padStart(9, '0'));
        console.log("  Opaque ID:", opaqueID);
    },
    onLeave: function(retval) {
        console.log("[evSetTimer] Return Value:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 解释:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到通过 USB 连接的 Android 设备上的目标应用程序进程。
2. **`Module.findExportByName("libc.so", "evSetTimer")`:**  在 `libc.so` 库中查找 `evSetTimer` 函数的导出地址。
3. **`Interceptor.attach(...)`:**  拦截 `evSetTimer` 函数的调用。
4. **`onEnter`:**  在 `evSetTimer` 函数被调用之前执行。
   - `args` 数组包含了传递给 `evSetTimer` 函数的参数。
   - 通过 `ptr(args[i]).readU64()` 读取 `struct timespec` 结构体的秒和纳秒成员。
   - 打印出函数的参数信息。
5. **`onLeave`:** 在 `evSetTimer` 函数执行完毕后执行。
   - `retval` 是函数的返回值。
   - 打印出返回值。

通过运行这个 Frida 脚本，你可以在目标应用程序调用 `evSetTimer` 时，在控制台上看到相关的调用信息，从而帮助你调试和理解定时器的使用情况。你可以类似地 hook 其他定时器相关的函数，例如 `evClearTimer` 或 `evResetTimer`。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/isc/ev_timers.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*	$NetBSD: ev_timers.c,v 1.11 2012/03/21 00:34:54 christos Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1995-1999 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* ev_timers.c - implement timers for the eventlib
 * vix 09sep95 [initial]
 */

#include <sys/cdefs.h>
#if !defined(LINT) && !defined(CODECENTER) && !defined(lint)
#ifdef notdef
static const char rcsid[] = "Id: ev_timers.c,v 1.6 2005/04/27 04:56:36 sra Exp";
#else
__RCSID("$NetBSD: ev_timers.c,v 1.11 2012/03/21 00:34:54 christos Exp $");
#endif
#endif

/* Import. */

#include "port_before.h"
#include "fd_setsize.h"

#include <errno.h>

#include <isc/assertions.h>
#include <isc/eventlib.h>
#include "eventlib_p.h"

#include "port_after.h"

/* Constants. */

#define	MILLION 1000000
#define BILLION 1000000000

/* Forward. */

#ifndef _LIBC
static int due_sooner(void *, void *);
static void set_index(void *, int);
static void free_timer(void *, void *);
static void print_timer(void *, void *);
static void idle_timeout(evContext, void *, struct timespec, struct timespec);

/* Private type. */

typedef struct {
	evTimerFunc	func;
	void *		uap;
	struct timespec	lastTouched;
	struct timespec	max_idle;
	evTimer *	timer;
} idle_timer;
#endif

/* Public. */

struct timespec
evConsTime(time_t sec, long nsec) {
	struct timespec x;

	x.tv_sec = sec;
	x.tv_nsec = nsec;
	return (x);
}

struct timespec
evAddTime(struct timespec addend1, struct timespec addend2) {
	struct timespec x;

	x.tv_sec = addend1.tv_sec + addend2.tv_sec;
	x.tv_nsec = addend1.tv_nsec + addend2.tv_nsec;
	if (x.tv_nsec >= BILLION) {
		x.tv_sec++;
		x.tv_nsec -= BILLION;
	}
	return (x);
}

struct timespec
evSubTime(struct timespec minuend, struct timespec subtrahend) {
	struct timespec x;

	x.tv_sec = minuend.tv_sec - subtrahend.tv_sec;
	if (minuend.tv_nsec >= subtrahend.tv_nsec)
		x.tv_nsec = minuend.tv_nsec - subtrahend.tv_nsec;
	else {
		x.tv_nsec = BILLION - subtrahend.tv_nsec + minuend.tv_nsec;
		x.tv_sec--;
	}
	return (x);
}

int
evCmpTime(struct timespec a, struct timespec b) {
#define SGN(x) ((x) < 0 ? (-1) : (x) > 0 ? (1) : (0));
	time_t s = a.tv_sec - b.tv_sec;
	long n;

	if (s != 0)
		return SGN(s);

	n = a.tv_nsec - b.tv_nsec;
	return SGN(n);
}

struct timespec
evNowTime(void)
{
	struct timeval now;
#ifdef CLOCK_REALTIME
	struct timespec tsnow;
	int m = CLOCK_REALTIME;

#ifdef CLOCK_MONOTONIC
#ifndef _LIBC
	if (__evOptMonoTime)
		m = CLOCK_MONOTONIC;
#endif
#endif
	if (clock_gettime(m, &tsnow) == 0)
		return (tsnow);
#endif
	if (gettimeofday(&now, NULL) < 0)
		return (evConsTime((time_t)0, 0L));
	return (evTimeSpec(now));
}

struct timespec
evUTCTime(void) {
	struct timeval now;
#ifdef CLOCK_REALTIME
	struct timespec tsnow;
	if (clock_gettime(CLOCK_REALTIME, &tsnow) == 0)
		return (tsnow);
#endif
	if (gettimeofday(&now, NULL) < 0)
		return (evConsTime((time_t)0, 0L));
	return (evTimeSpec(now));
}

#ifndef _LIBC
struct timespec
evLastEventTime(evContext opaqueCtx) {
	evContext_p *ctx = opaqueCtx.opaque;

	return (ctx->lastEventTime);
}
#endif

struct timespec
evTimeSpec(struct timeval tv) {
	struct timespec ts;

	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
	return (ts);
}

struct timeval
evTimeVal(struct timespec ts) {
	struct timeval tv;

	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = (suseconds_t)(ts.tv_nsec / 1000);
	return (tv);
}

#ifndef _LIBC
int
evSetTimer(evContext opaqueCtx,
	   evTimerFunc func,
	   void *uap,
	   struct timespec due,
	   struct timespec inter,
	   evTimerID *opaqueID
) {
	evContext_p *ctx = opaqueCtx.opaque;
	evTimer *id;

	evPrintf(ctx, 1,
"evSetTimer(ctx %p, func %p, uap %p, due %ld.%09ld, inter %ld.%09ld)\n",
		 ctx, func, uap,
		 (long)due.tv_sec, due.tv_nsec,
		 (long)inter.tv_sec, inter.tv_nsec);

#ifdef __hpux
	/*
	 * tv_sec and tv_nsec are unsigned.
	 */
	if (due.tv_nsec >= BILLION)
		EV_ERR(EINVAL);

	if (inter.tv_nsec >= BILLION)
		EV_ERR(EINVAL);
#else
	if (due.tv_sec < 0 || due.tv_nsec < 0 || due.tv_nsec >= BILLION)
		EV_ERR(EINVAL);

	if (inter.tv_sec < 0 || inter.tv_nsec < 0 || inter.tv_nsec >= BILLION)
		EV_ERR(EINVAL);
#endif

	/* due={0,0} is a magic cookie meaning "now." */
	if (due.tv_sec == (time_t)0 && due.tv_nsec == 0L)
		due = evNowTime();

	/* Allocate and fill. */
	OKNEW(id);
	id->func = func;
	id->uap = uap;
	id->due = due;
	id->inter = inter;

	if (heap_insert(ctx->timers, id) < 0)
		return (-1);

	/* Remember the ID if the caller provided us a place for it. */
	if (opaqueID)
		opaqueID->opaque = id;

	if (ctx->debug > 7) {
		evPrintf(ctx, 7, "timers after evSetTimer:\n");
		(void) heap_for_each(ctx->timers, print_timer, (void *)ctx);
	}

	return (0);
}

int
evClearTimer(evContext opaqueCtx, evTimerID id) {
	evContext_p *ctx = opaqueCtx.opaque;
	evTimer *del = id.opaque;

	if (ctx->cur != NULL &&
	    ctx->cur->type == Timer &&
	    ctx->cur->u.timer.this == del) {
		evPrintf(ctx, 8, "deferring delete of timer (executing)\n");
		/*
		 * Setting the interval to zero ensures that evDrop() will
		 * clean up the timer.
		 */
		del->inter = evConsTime(0, 0);
		return (0);
	}

	if (heap_element(ctx->timers, del->index) != del)
		EV_ERR(ENOENT);

	if (heap_delete(ctx->timers, del->index) < 0)
		return (-1);
	FREE(del);

	if (ctx->debug > 7) {
		evPrintf(ctx, 7, "timers after evClearTimer:\n");
		(void) heap_for_each(ctx->timers, print_timer, (void *)ctx);
	}

	return (0);
}

int
evConfigTimer(evContext opaqueCtx,
	     evTimerID id,
	     const char *param,
	     int value
) {
	evContext_p *ctx = opaqueCtx.opaque;
	evTimer *timer = id.opaque;
	int result=0;

	UNUSED(value);

	if (heap_element(ctx->timers, timer->index) != timer)
		EV_ERR(ENOENT);

	if (strcmp(param, "rate") == 0)
		timer->mode |= EV_TMR_RATE;
	else if (strcmp(param, "interval") == 0)
		timer->mode &= ~EV_TMR_RATE;
	else
		EV_ERR(EINVAL);

	return (result);
}

int
evResetTimer(evContext opaqueCtx,
	     evTimerID id,
	     evTimerFunc func,
	     void *uap,
	     struct timespec due,
	     struct timespec inter
) {
	evContext_p *ctx = opaqueCtx.opaque;
	evTimer *timer = id.opaque;
	struct timespec old_due;
	int result=0;

	if (heap_element(ctx->timers, timer->index) != timer)
		EV_ERR(ENOENT);

#ifdef __hpux
	/*
	 * tv_sec and tv_nsec are unsigned.
	 */
	if (due.tv_nsec >= BILLION)
		EV_ERR(EINVAL);

	if (inter.tv_nsec >= BILLION)
		EV_ERR(EINVAL);
#else
	if (due.tv_sec < 0 || due.tv_nsec < 0 || due.tv_nsec >= BILLION)
		EV_ERR(EINVAL);

	if (inter.tv_sec < 0 || inter.tv_nsec < 0 || inter.tv_nsec >= BILLION)
		EV_ERR(EINVAL);
#endif

	old_due = timer->due;

	timer->func = func;
	timer->uap = uap;
	timer->due = due;
	timer->inter = inter;

	switch (evCmpTime(due, old_due)) {
	case -1:
		result = heap_increased(ctx->timers, timer->index);
		break;
	case 0:
		result = 0;
		break;
	case 1:
		result = heap_decreased(ctx->timers, timer->index);
		break;
	}

	if (ctx->debug > 7) {
		evPrintf(ctx, 7, "timers after evResetTimer:\n");
		(void) heap_for_each(ctx->timers, print_timer, (void *)ctx);
	}

	return (result);
}

int
evSetIdleTimer(evContext opaqueCtx,
		evTimerFunc func,
		void *uap,
		struct timespec max_idle,
		evTimerID *opaqueID
) {
	evContext_p *ctx = opaqueCtx.opaque;
	idle_timer *tt;

	/* Allocate and fill. */
	OKNEW(tt);
	tt->func = func;
	tt->uap = uap;
	tt->lastTouched = ctx->lastEventTime;
	tt->max_idle = max_idle;

	if (evSetTimer(opaqueCtx, idle_timeout, tt,
		       evAddTime(ctx->lastEventTime, max_idle),
		       max_idle, opaqueID) < 0) {
		FREE(tt);
		return (-1);
	}

	tt->timer = opaqueID->opaque;

	return (0);
}

int
evClearIdleTimer(evContext opaqueCtx, evTimerID id) {
	evTimer *del = id.opaque;
	idle_timer *tt = del->uap;

	FREE(tt);
	return (evClearTimer(opaqueCtx, id));
}

int
evResetIdleTimer(evContext opaqueCtx,
		 evTimerID opaqueID,
		 evTimerFunc func,
		 void *uap,
		 struct timespec max_idle
) {
	evContext_p *ctx = opaqueCtx.opaque;
	evTimer *timer = opaqueID.opaque;
	idle_timer *tt = timer->uap;

	tt->func = func;
	tt->uap = uap;
	tt->lastTouched = ctx->lastEventTime;
	tt->max_idle = max_idle;

	return (evResetTimer(opaqueCtx, opaqueID, idle_timeout, tt,
			     evAddTime(ctx->lastEventTime, max_idle),
			     max_idle));
}

int
evTouchIdleTimer(evContext opaqueCtx, evTimerID id) {
	evContext_p *ctx = opaqueCtx.opaque;
	evTimer *t = id.opaque;
	idle_timer *tt = t->uap;

	tt->lastTouched = ctx->lastEventTime;

	return (0);
}

/* Public to the rest of eventlib. */

heap_context
evCreateTimers(const evContext_p *ctx) {

	UNUSED(ctx);

	return (heap_new(due_sooner, set_index, 2048));
}

void
evDestroyTimers(const evContext_p *ctx) {
	(void) heap_for_each(ctx->timers, free_timer, NULL);
	(void) heap_free(ctx->timers);
}

/* Private. */

static int
due_sooner(void *a, void *b) {
	evTimer *a_timer, *b_timer;

	a_timer = a;
	b_timer = b;
	return (evCmpTime(a_timer->due, b_timer->due) < 0);
}

static void
set_index(void *what, int idx) {
	evTimer *timer;

	timer = what;
	timer->index = idx;
}

static void
free_timer(void *what, void *uap) {
	evTimer *t = what;

	UNUSED(uap);

	FREE(t);
}

static void
print_timer(void *what, void *uap) {
	evTimer *cur = what;
	evContext_p *ctx = uap;

	cur = what;
	evPrintf(ctx, 7,
	    "  func %p, uap %p, due %ld.%09ld, inter %ld.%09ld\n",
		 cur->func, cur->uap,
		 (long)cur->due.tv_sec, cur->due.tv_nsec,
		 (long)cur->inter.tv_sec, cur->inter.tv_nsec);
}

static void
idle_timeout(evContext opaqueCtx,
	     void *uap,
	     struct timespec due,
	     struct timespec inter
) {
	evContext_p *ctx = opaqueCtx.opaque;
	idle_timer *this = uap;
	struct timespec idle;

	UNUSED(due);
	UNUSED(inter);
	
	idle = evSubTime(ctx->lastEventTime, this->lastTouched);
	if (evCmpTime(idle, this->max_idle) >= 0) {
		(this->func)(opaqueCtx, this->uap, this->timer->due,
			     this->max_idle);
		/*
		 * Setting the interval to zero will cause the timer to
		 * be cleaned up in evDrop().
		 */
		this->timer->inter = evConsTime(0L, 0L);
		FREE(this);
	} else {
		/* evDrop() will reschedule the timer. */
		this->timer->inter = evSubTime(this->max_idle, idle);
	}
}
#endif

/*! \file */
```