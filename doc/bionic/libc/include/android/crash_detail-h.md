Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Understanding and Purpose:**

The first step is to read the file's header comment and the brief description provided in the prompt. The key takeaway is that this file (`android/crash_detail.h`) deals with attaching extra information to Android crashes. This immediately suggests a debugging or diagnostic purpose.

**2. Identifying Key Components:**

Next, I scan the code for the core elements:

* **`crash_detail_t`**:  This is clearly a key data structure. The `typedef struct crash_detail_t crash_detail_t;` declaration indicates it's a forward declaration, meaning the actual definition is likely in the corresponding `.c` file. It acts as a handle to manage the crash detail information.

* **Functions:** The header file primarily defines functions. I identify the four main functions:
    * `android_crash_detail_register`: For registering new crash detail information.
    * `android_crash_detail_unregister`: For removing registered information.
    * `android_crash_detail_replace_data`: For updating the data part of the information.
    * `android_crash_detail_replace_name`: For updating the name part of the information.

* **Macros and Directives:**  I notice `#pragma once`, include directives (`<sys/cdefs.h>`, `<stddef.h>`), and the `__BEGIN_DECLS` and `__END_DECLS` macros (standard C++ practice for controlling symbol visibility, though less critical for initial understanding). Importantly, I spot the `#if __BIONIC_AVAILABILITY_GUARD(35)` block and the `__INTRODUCED_IN(35)` attribute. This signals that these functions are only available from Android API level 35 onwards.

**3. Analyzing Function Functionality (Decomposition):**

For each function, I carefully read its documentation comment. I try to answer the "What does it do?" question for each one:

* **`android_crash_detail_register`**: Registers a buffer (name and data) to be included in crash reports (tombstones). The documentation explicitly mentions the `tombstone.proto` and `ApplicationExitInfo`, providing context within the Android ecosystem. The crucial point about the lifetime of `name` and `data` is noted.

* **`android_crash_detail_unregister`**:  Releases the resources associated with a registered crash detail. This is important for preventing memory leaks.

* **`android_crash_detail_replace_data`**:  Allows efficient updating of the data associated with an existing crash detail registration. This avoids the overhead of unregistering and re-registering.

* **`android_crash_detail_replace_name`**: Similar to `replace_data`, but for the name.

**4. Connecting to Android Functionality:**

The documentation heavily hints at the connection to Android's crash reporting mechanism. I focus on the following keywords and phrases:

* "tombstones"
* "tombstone proto"
* "crash_detail field"
* `android.app.ApplicationExitInfo`
* `REASON_CRASH_NATIVE`

These clearly link the functionality of this header file to how Android captures and reports native crashes. The example usage further reinforces this understanding.

**5. Considering Implementation Details (Though the Header Doesn't Show It):**

Even though the header doesn't reveal the implementation, I start to think about *how* these functions might work:

* **`register`**:  Likely involves allocating memory to store the name and data and linking it to some internal data structure.
* **`unregister`**: Would involve freeing the allocated memory and removing the entry from the internal structure.
* **`replace`**:  Would involve updating the pointers and sizes associated with an existing entry.

This internal mechanism is crucial for understanding the potential for errors.

**6. Identifying Potential Usage Errors:**

Based on the function descriptions, especially the lifetime requirement in `android_crash_detail_register`, I can anticipate common mistakes:

* **Dangling Pointers:** Passing a pointer to data that is deallocated before a crash occurs.
* **Incorrect Sizes:**  Providing the wrong `name_size` or `data_size`.
* **API Level Issues:**  Trying to use these functions on Android versions prior to API 35.
* **Forgetting to Unregister:**  Leading to potential resource leaks if crash details are registered repeatedly without being unregistered.

**7. Thinking About the Dynamic Linker (Limited Information in Header):**

The header itself doesn't directly involve dynamic linking. However, because it's part of `bionic`, the C library, I know that the *implementation* of these functions will be linked into processes. I anticipate that the actual implementation will reside in a shared library (likely `libc.so`). I start considering a basic `so` layout and how the linker would resolve these symbols.

**8. Considering the Call Chain (How Android Gets Here):**

I think about how a crash scenario would involve these functions. Likely, a native crash handler in Android's runtime (like `debuggerd`) would need to access this information. Applications, through the NDK, would use these functions to provide context before a potential crash.

**9. Planning the Frida Hook Example:**

To demonstrate usage, a Frida hook needs to target these functions. I think about which function to hook (likely `android_crash_detail_register` to observe the registration process) and what information to log (arguments like name, name size, data, data size).

**10. Structuring the Response:**

Finally, I organize the information into the requested categories: Functionality, Relationship to Android, Libc Function Details (even if inferred), Dynamic Linker aspects, Logic Reasoning (simple cases), Usage Errors, and the Android Framework/NDK path with a Frida example. I ensure the language is Chinese as requested.

This detailed thought process allows for a comprehensive analysis of even a relatively small header file, extracting its core purpose, connecting it to the broader Android ecosystem, and anticipating potential issues and usage patterns.
这是一个定义在 `bionic/libc/include/android/crash_detail.h` 头文件中的 C 语言接口，它属于 Android 的 Bionic C 库。这个接口的主要功能是允许开发者在应用程序发生崩溃时，向崩溃报告（tombstone）中添加额外的自定义信息。

**功能列举:**

1. **注册崩溃详情 (Register Crash Detail):** 提供了一种机制，允许应用程序在可能发生崩溃的代码段之前，注册一些额外的名称和数据。
2. **包含到崩溃报告 (Include in Crash Report):** 注册的信息会被包含到崩溃报告中，以帮助开发者更好地理解崩溃发生时的上下文。这些信息会出现在 tombstone 文件的文本格式和 protobuf 格式中。
3. **管理崩溃详情生命周期 (Manage Crash Detail Lifecycle):** 提供了注册 (`android_crash_detail_register`) 和注销 (`android_crash_detail_unregister`) 崩溃详情的函数，以及更新崩溃详情数据 (`android_crash_detail_replace_data`) 和名称 (`android_crash_detail_replace_name`) 的函数。
4. **API 级别限制 (API Level Restriction):** 这些函数是在 API level 35 中引入的，这意味着只能在 Android 15 及更高版本的系统上使用。

**与 Android 功能的关系及举例说明:**

这个接口直接关系到 Android 的崩溃报告机制。当应用程序发生 Native Crash (C/C++ 代码崩溃) 时，Android 系统会生成一个 tombstone 文件，其中包含了崩溃时的线程信息、寄存器状态、堆栈跟踪等重要信息。`android_crash_detail.h` 提供的功能允许开发者在 tombstone 文件中添加自定义的额外信息，这对于调试和分析崩溃原因非常有帮助。

**举例说明:**

假设你的应用程序中有一个负责网络请求的模块，你希望在发生网络相关的崩溃时，能够知道当时正在请求的 URL。你可以使用 `android_crash_detail_register` 函数在发起请求前注册 URL 信息：

```c
#include <android/crash_detail.h>
#include <string.h>
#include <stdlib.h>

void make_network_request(const char* url) {
    const char* detail_name = "network_url";
    crash_detail_t* cd = android_crash_detail_register(detail_name, strlen(detail_name), url, strlen(url));

    // 执行网络请求，如果这里发生崩溃
    // ...

    android_crash_detail_unregister(cd); // 请求完成后注销
}
```

如果在执行网络请求的过程中发生崩溃，tombstone 文件中将会包含类似这样的信息：

```
Extra crash detail: network_url: 'https://example.com/api/data'
```

这能帮助开发者快速定位崩溃是否与特定的网络请求有关。

**详细解释每个 libc 函数的功能是如何实现的:**

由于你提供的只是头文件，我们无法直接看到这些函数的具体实现。这些函数的实现在 Bionic 的 C 库源文件中，通常位于 `bionic/libc/bionic/` 或类似的目录下。

一般来说，这些函数的实现会涉及以下步骤：

1. **`android_crash_detail_register`:**
   - **分配内存:** 为 `crash_detail_t` 结构以及存储 `name` 和 `data` 的缓冲区分配内存。
   - **复制数据:** 将传入的 `name` 和 `data` 复制到新分配的缓冲区中。
   - **存储信息:** 将 `name`、`name_size`、`data`、`data_size` 等信息存储到 `crash_detail_t` 结构中。
   - **管理列表:**  将新创建的 `crash_detail_t` 结构添加到一个全局的链表或其他数据结构中，以便在崩溃发生时能够遍历这些已注册的详情。可能需要使用锁来保证线程安全。
   - **返回句柄:** 返回指向新创建的 `crash_detail_t` 结构的指针作为句柄。

2. **`android_crash_detail_unregister`:**
   - **查找条目:** 根据传入的 `crash_detail_t` 指针，在全局的列表中找到对应的条目。
   - **释放内存:** 释放与该条目关联的 `name`、`data` 缓冲区以及 `crash_detail_t` 结构本身的内存。
   - **从列表中移除:** 将该条目从全局列表中移除。

3. **`android_crash_detail_replace_data`:**
   - **查找条目:** 根据传入的 `crash_detail_t` 指针，在全局的列表中找到对应的条目。
   - **释放旧数据:** 如果之前注册了数据，则释放旧的 `data` 缓冲区。
   - **分配新内存 (如果需要):** 如果 `data` 不为 `NULL`，则分配新的内存来存储新的数据。
   - **复制新数据:** 将新的 `data` 复制到新分配的缓冲区中。
   - **更新信息:** 更新 `crash_detail_t` 结构中的 `data` 指针和 `data_size`。

4. **`android_crash_detail_replace_name`:**
   - **查找条目:** 根据传入的 `crash_detail_t` 指针，在全局的列表中找到对应的条目。
   - **释放旧名称:** 释放旧的 `name` 缓冲区。
   - **分配新内存:** 分配新的内存来存储新的名称。
   - **复制新名称:** 将新的 `name` 复制到新分配的缓冲区中。
   - **更新信息:** 更新 `crash_detail_t` 结构中的 `name` 指针和 `name_size`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件定义的功能本身并不直接涉及 dynamic linker 的操作。这些函数是 libc 的一部分，它们会在应用程序启动时被 dynamic linker 加载到应用程序的进程空间中。

**so 布局样本:**

```
# 假设 libc.so 的布局
libc.so:
    .text:  # 代码段
        android_crash_detail_register: ... (实现代码)
        android_crash_detail_unregister: ... (实现代码)
        android_crash_detail_replace_data: ... (实现代码)
        android_crash_detail_replace_name: ... (实现代码)
        ... 其他 libc 函数 ...
    .rodata: # 只读数据段
        ...
    .data:   # 可读写数据段 (可能包含用于存储已注册 crash detail 的全局列表)
        g_crash_detail_list: ...
    .bss:    # 未初始化数据段
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当你编译包含 `android/crash_detail.h` 的 C/C++ 代码时，编译器会识别出对 `android_crash_detail_register` 等函数的调用。链接器会记录下这些未解析的符号。
2. **运行时链接:** 当 Android 启动你的应用程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，包括 `libc.so`。
3. **符号解析:** dynamic linker 会遍历应用程序的依赖关系，找到 `libc.so`，并将其加载到进程的地址空间。然后，它会解析之前编译器记录的未解析符号，将应用程序中对 `android_crash_detail_register` 等函数的调用地址，链接到 `libc.so` 中对应的函数实现地址。
4. **动态链接完成:** 一旦所有必要的符号都被解析，应用程序就可以正常执行，并调用 `libc.so` 中提供的 `android_crash_detail_*` 函数。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们调用 `android_crash_detail_register` 函数：

**假设输入:**

```c
const char* name = "my_data";
size_t name_size = strlen(name);
const char* data = "important_value";
size_t data_size = strlen(data);

crash_detail_t* cd = android_crash_detail_register(name, name_size, data, data_size);
```

**逻辑推理:**

- 函数会分配内存来存储 "my_data" 和 "important_value"。
- 函数会创建一个 `crash_detail_t` 结构，其中包含指向 "my_data" 和 "important_value" 内存的指针，以及它们的长度。
- 函数会将这个 `crash_detail_t` 结构添加到内部的全局列表中。
- 函数会返回指向新创建的 `crash_detail_t` 结构的指针 `cd`。

**假设输出:**

- `cd` 是一个非 `NULL` 的指针，指向一块有效的内存区域。
- 在系统内部，存在一个数据结构（例如链表），其中包含了指向 "my_data" 和 "important_value" 的信息。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **生命周期管理错误:**

   ```c
   void some_function() {
       char name_buffer[64] = "stage";
       char data_buffer[128] = "processing";
       crash_detail_t* cd = android_crash_detail_register(name_buffer, strlen(name_buffer), data_buffer, strlen(data_buffer));
       // ... 可能会崩溃的代码 ...
       // 忘记调用 android_crash_detail_unregister(cd);
   } // name_buffer 和 data_buffer 在函数结束时被销毁，但 crash detail 仍然指向这些内存
   ```

   **错误说明:** 在函数结束时，局部变量 `name_buffer` 和 `data_buffer` 会被销毁，但 `android_crash_detail_register` 内部可能只是存储了指向这些内存的指针。如果在崩溃发生时尝试访问这些指针，会导致未定义的行为或程序崩溃。正确的做法是在不再需要 crash detail 时调用 `android_crash_detail_unregister`。

2. **传递无效的指针或大小:**

   ```c
   crash_detail_t* cd = android_crash_detail_register("error_code", 10, "INVALID", -1); // data_size 错误
   ```

   **错误说明:** 传递负数的 `data_size` 是不合法的，会导致未定义的行为。同样，传递 `NULL` 指针而没有将相应的 size 设置为 0 也是错误的。

3. **API 级别不兼容:**

   ```c
   // 在 API level 小于 35 的设备上调用
   crash_detail_t* cd = android_crash_detail_register("debug", 5, "info", 4); // 会导致链接错误或运行时崩溃
   ```

   **错误说明:** 这些函数只能在 API level 35 及以上版本的 Android 系统上使用。在旧版本上调用会导致链接错误（如果静态链接）或运行时崩溃（如果动态链接但系统库中不存在这些符号）。

4. **重复注册而不注销:**

   ```c
   void loop() {
       const char* info = "looping";
       crash_detail_t* cd = android_crash_detail_register("status", strlen("status"), info, strlen(info));
       // ... 一些操作 ...
       // 忘记在每次循环后注销
   }
   ```

   **错误说明:** 如果在一个循环中多次注册 crash detail 而不注销，可能会导致内存泄漏，因为每次注册都会分配新的内存。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 调用:**  C/C++ 代码通常通过 NDK (Native Development Kit) 与 Android 系统交互。开发者在 NDK 代码中直接调用 `android_crash_detail_register` 等函数。

2. **Libc 的链接:** 当应用程序被加载时，dynamic linker 会将应用程序链接到 `libc.so` (Bionic C 库)，其中包含了 `android_crash_detail_*` 函数的实现。

3. **崩溃发生:** 当应用程序发生 Native Crash 时，例如访问了无效的内存地址，操作系统会发送一个信号 (例如 `SIGSEGV`) 给应用程序进程。

4. **`debuggerd` 介入:** Android 系统中的 `debuggerd` 守护进程会捕获这个信号。

5. **收集崩溃信息:** `debuggerd` 会收集崩溃时的各种信息，包括线程信息、寄存器状态、内存映射等。

6. **访问已注册的崩溃详情:** `debuggerd` 会遍历在 `libc.so` 中维护的已注册的 `crash_detail_t` 列表，并将这些额外的信息添加到 tombstone 文件中。

7. **生成 Tombstone:**  `debuggerd` 将收集到的所有信息格式化并写入 tombstone 文件。

8. **ApplicationExitInfo (Java Framework):**  对于应用程序崩溃，Java 框架层也会记录相关信息，并可以通过 `ApplicationExitInfo` API 获取，其中包括 Native Crash 的原因 (`REASON_CRASH_NATIVE`) 以及可能包含的崩溃详情输入流 (`getTraceInputStream()`)。

**Frida Hook 示例:**

可以使用 Frida 来 hook `android_crash_detail_register` 函数，观察其调用参数。

```javascript
// save as crash_detail_hook.js
if (Process.platform === 'android') {
  const android_crash_detail_register = Module.findExportByName("libc.so", "android_crash_detail_register");
  if (android_crash_detail_register) {
    Interceptor.attach(android_crash_detail_register, {
      onEnter: function (args) {
        const namePtr = args[0];
        const nameSize = args[1].toInt();
        const dataPtr = args[2];
        const dataSize = args[3].toInt();

        const name = namePtr.readUtf8String(nameSize);
        let data = null;
        if (!dataPtr.isNull()) {
          data = dataPtr.readUtf8String(dataSize);
        }

        console.log("android_crash_detail_register called:");
        console.log("  Name:", name);
        console.log("  Name Size:", nameSize);
        console.log("  Data:", data);
        console.log("  Data Size:", dataSize);
      }
    });
  } else {
    console.log("android_crash_detail_register not found in libc.so");
  }
} else {
  console.log("This script is for Android only.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `crash_detail_hook.js`。
2. 使用 Frida 连接到目标 Android 应用程序进程：

   ```bash
   frida -U -f <your_app_package_name> -l crash_detail_hook.js --no-pause
   ```

   或者，如果应用程序已经在运行：

   ```bash
   frida -U <your_app_package_name> -l crash_detail_hook.js
   ```

当目标应用程序调用 `android_crash_detail_register` 函数时，Frida 会拦截调用并打印出传递给函数的参数，包括 `name` 和 `data` 的内容。这可以帮助你了解哪些信息被注册为崩溃详情。

要 hook 其他的 `android_crash_detail_*` 函数，只需修改 `Module.findExportByName` 中的函数名即可。例如，hook `android_crash_detail_unregister`：

```javascript
const android_crash_detail_unregister = Module.findExportByName("libc.so", "android_crash_detail_unregister");
if (android_crash_detail_unregister) {
  Interceptor.attach(android_crash_detail_unregister, {
    onEnter: function (args) {
      const crash_detail_ptr = args[0];
      console.log("android_crash_detail_unregister called with crash_detail:", crash_detail_ptr);
    }
  });
}
```

通过 Frida hook，你可以动态地观察这些函数的行为，验证你的代码是否正确地使用了这些接口，以及在崩溃发生前注册了哪些信息。

Prompt: 
```
这是目录为bionic/libc/include/android/crash_detail.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2024 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

/**
 * @file android/crash_detail.h
 * @brief Attach extra information to android crashes.
 */

#include <sys/cdefs.h>

#include <stddef.h>

__BEGIN_DECLS

typedef struct crash_detail_t crash_detail_t;

/**
 * Register a new buffer to get logged into tombstones for crashes.
 *
 * It will be added to both the tombstone proto in the crash_detail field, and
 * in the tombstone text format.
 *
 * Tombstone proto definition:
 *   https://cs.android.com/android/platform/superproject/main/+/main:system/core/debuggerd/proto/tombstone.proto
 *
 * An app can get hold of these for any `REASON_CRASH_NATIVE` instance of
 * `android.app.ApplicationExitInfo`.
 *
 * https://developer.android.com/reference/android/app/ApplicationExitInfo#getTraceInputStream()

 * The lifetime of name and data has to be valid until the program crashes, or until
 * android_crash_detail_unregister is called.
 *
 * Example usage:
 *   const char* stageName = "garbage_collection";
 *   crash_detail_t* cd = android_crash_detail_register("stage", stageName, strlen(stageName));
 *   do_garbage_collection();
 *   android_crash_detail_unregister(cd);
 *
 * If this example crashes in do_garbage_collection, a line will show up in the textual representation of the tombstone:
 *   Extra crash detail: stage: 'garbage_collection'
 *
 * Introduced in API 35.
 *
 * \param name identifying name for this extra data.
 *             this should generally be a human-readable UTF-8 string, but we are treating
 *             it as arbitrary bytes because it could be corrupted by the crash.
 * \param name_size number of bytes of the buffer pointed to by name
 * \param data a buffer containing the extra detail bytes, if null the crash detail
 *             is disabled until android_crash_detail_replace_data replaces it with
 *             a non-null pointer.
 * \param data_size number of bytes of the buffer pointed to by data
 *
 * \return a handle to the extra crash detail.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
crash_detail_t* _Nullable android_crash_detail_register(
    const void* _Nonnull name, size_t name_size, const void* _Nullable data, size_t data_size) __INTRODUCED_IN(35);

/**
 * Unregister crash detail from being logged into tombstones.
 *
 * After this function returns, the lifetime of the objects crash_detail was
 * constructed from no longer needs to be valid.
 *
 * Introduced in API 35.
 *
 * \param crash_detail the crash_detail that should be removed.
 */
void android_crash_detail_unregister(crash_detail_t* _Nonnull crash_detail) __INTRODUCED_IN(35);

/**
 * Replace data of crash detail.
 *
 * This is more efficient than using android_crash_detail_unregister followed by
 * android_crash_detail_register. If you very frequently need to swap out the data,
 * you can hold onto the crash_detail.
 *
 * Introduced in API 35.
 *
 * \param data the new buffer containing the extra detail bytes, or null to disable until
 *             android_crash_detail_replace_data is called again with non-null data.
 * \param data_size the number of bytes of the buffer pointed to by data.
 */
void android_crash_detail_replace_data(crash_detail_t* _Nonnull crash_detail, const void* _Nullable data, size_t data_size) __INTRODUCED_IN(35);

/**
 * Replace name of crash detail.
 *
 * This is more efficient than using android_crash_detail_unregister followed by
 * android_crash_detail_register. If you very frequently need to swap out the name,
 * you can hold onto the crash_detail.
 *
 * Introduced in API 35.
 *
 * \param name identifying name for this extra data.
 * \param name_size number of bytes of the buffer pointed to by name
 */
void android_crash_detail_replace_name(crash_detail_t* _Nonnull crash_detail, const void* _Nonnull name, size_t name_size) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


__END_DECLS

"""

```