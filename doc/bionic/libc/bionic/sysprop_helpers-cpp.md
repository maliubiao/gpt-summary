Response:
Let's break down the thought process for analyzing this C++ source code snippet.

**1. Understanding the Request:**

The request is to analyze a specific C++ file (`sysprop_helpers.cpp`) within the Android Bionic library. The goal is to understand its functionality, its relationship to Android, explain the implementation details of the libc functions used, discuss dynamic linking aspects (if any), identify potential errors, and illustrate how to reach this code from higher levels of Android (framework/NDK) using Frida.

**2. Initial Code Scan and Purpose Identification:**

First, read through the code. Key observations:

* **Includes:**  `<assert.h>`, `<stdint.h>`, `<stdlib.h>`, `<string.h>`, and importantly `"sys/system_properties.h"`. The last one is the strongest indicator of the file's purpose.
* **Function `get_property_value`:** This function interacts with system properties. The function signature and the use of `__system_property_find` and `__system_property_read_callback` confirm this.
* **Function `get_config_from_env_or_sysprops`:** This function checks environment variables *and* system properties, suggesting it's a utility for retrieving configuration.

Therefore, the core functionality revolves around accessing and retrieving system properties and environment variables. The filename `sysprop_helpers.cpp` is a clear indicator.

**3. Detailed Function Analysis:**

Now, analyze each function step-by-step:

* **`get_property_value`:**
    * **Input:** `property_name` (the name of the system property), `dest` (a buffer to store the value), `dest_size` (the size of the buffer).
    * **`assert`:**  Basic sanity check.
    * **`__system_property_find`:** This is the key Bionic API for finding a system property. The documentation (or prior knowledge) tells you it returns a pointer to a `prop_info` structure if found, otherwise `nullptr`. *Crucially, this is where the interaction with the Android system property service happens at a lower level.*
    * **`PropCbCookie`:**  A local struct to pass data to the callback. This is a common C-style pattern for passing context to callbacks.
    * **`__system_property_read_callback`:**  This function reads the value of the property. It takes a callback function as an argument. The callback receives the property name, value, and a serial number.
    * **Callback Lambda:** The lambda captures the `PropCbCookie` and copies the property `value` into the provided `dest` buffer, ensuring null termination.
    * **Return Value:** `true` if a property is found and its value is copied, `false` otherwise. The check `*dest != '\0'` confirms something was written.

* **`get_config_from_env_or_sysprops`:**
    * **Input:** `env_var_name` (the name of the environment variable), `sys_prop_names` (an array of system property names), `sys_prop_names_size` (the size of the array), `options` (the destination buffer), `options_size` (the size of the buffer).
    * **`getenv`:**  Standard C library function to retrieve the value of an environment variable.
    * **Environment Variable Check:**  If the environment variable is set and not empty, its value is copied to `options`.
    * **System Property Iteration:**  If the environment variable is not set, the code iterates through the provided array of system property names.
    * **`get_property_value` Call:** For each system property name, `get_property_value` is called. If it succeeds, the function returns `true`.
    * **Return Value:** `true` if either an environment variable or a system property is successfully read, `false` otherwise.

**4. Connecting to Android Functionality:**

The use of `sys/system_properties.h` and the `__system_property_find` and `__system_property_read_callback` functions directly link this code to Android's system property mechanism. This mechanism is fundamental for configuration and inter-process communication in Android. Give concrete examples like retrieving the Android SDK version or device manufacturer.

**5. libc Function Explanation:**

Explain the core libc functions used:

* **`assert`:**  Debugging aid.
* **`getenv`:**  Retrieve environment variables.
* **`strncpy`:**  Safe string copying with size limits. Emphasize the importance of null termination.
* **`strlen`:** Calculate string length (implicitly used by `strncpy`).
* **`reinterpret_cast`:**  Type casting pointers (use with caution).

**6. Dynamic Linker Aspects:**

The key here is realizing that while this code *uses* Bionic functions related to system properties, it doesn't inherently *implement* dynamic linking itself. The dynamic linker is responsible for resolving the symbols like `__system_property_find` and `__system_property_read_callback` at runtime. Provide a simple SO layout and explain the linking process – symbol lookup in dependencies, PLT/GOT.

**7. Logical Reasoning and Examples:**

Create scenarios to illustrate the function behavior. For example:

* **Input:**  `env_var_name` set, `sys_prop_names` not set. Expected output: environment variable value.
* **Input:** `env_var_name` not set, one `sys_prop_names` is valid. Expected output: system property value.
* **Input:** Neither set. Expected output: empty string (or some default depending on the caller).

**8. Common Usage Errors:**

Think about how a developer might misuse these functions:

* **Buffer overflows:**  Passing an undersized buffer to `get_config_from_env_or_sysprops`.
* **Incorrect property names:**  Typos in the system property name.
* **Null pointers:** Passing `nullptr` where it's not allowed.

**9. Android Framework/NDK Path and Frida Hook:**

* **Framework:**  Start from a high-level framework service (e.g., `SystemProperties`). Explain how that service might eventually call down into native code that uses these helpers. Mention JNI.
* **NDK:**  Show a simple NDK example where a C++ application uses the AOSP APIs that wrap these Bionic functions.
* **Frida Hook:** Provide concrete Frida JavaScript code to hook `get_config_from_env_or_sysprops`. Show how to log arguments and return values.

**10. Structuring the Response:**

Organize the information logically with clear headings and bullet points. This makes it easier to read and understand. Use code formatting for code snippets.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This file directly implements system property access."
* **Correction:** "No, it *helps* access system properties by providing utility functions. The actual low-level implementation is elsewhere in Bionic."
* **Initial thought (for dynamic linking):**  "This code is heavily involved in dynamic linking."
* **Correction:** "While it resides in Bionic (which includes the dynamic linker), this specific file *uses* dynamically linked functions, but doesn't directly perform dynamic linking operations itself. The linker resolves the `__system_property_*` symbols."

By following this systematic approach, considering edge cases, and providing concrete examples, you can generate a comprehensive and accurate analysis of the given C++ code.
好的，让我们来详细分析一下 `bionic/libc/bionic/sysprop_helpers.cpp` 文件的功能。

**文件功能概述**

`sysprop_helpers.cpp` 文件在 Android Bionic 库中，主要提供了一些辅助函数，用于方便地获取系统属性 (system properties) 和环境变量的值。它提供了以下核心功能：

1. **从系统属性中获取值:**  `get_property_value` 函数允许你通过系统属性的名称来获取其对应的值。
2. **从环境变量或系统属性中获取配置:** `get_config_from_env_or_sysprops` 函数提供了一种优先从环境变量获取配置，如果环境变量不存在则尝试从一组系统属性中获取的机制。

**与 Android 功能的关系及举例说明**

系统属性是 Android 系统中一种全局的键值对存储机制，用于存储各种系统配置信息。 应用程序和系统服务可以通过系统属性来获取设备的各种状态和配置信息。环境变量是进程启动时可以传递给进程的一些配置信息。

这个文件提供的功能是 Android 系统底层基础设施的一部分，被很多上层组件所使用。

**举例说明:**

* **获取 Android 版本:**  Android 系统使用 `ro.build.version.release` 系统属性来存储 Android 的版本号。应用程序可以通过调用 `get_property_value("ro.build.version.release", buffer, sizeof(buffer))` 来获取该值。
* **获取设备制造商:**  `ro.product.manufacturer` 系统属性存储了设备的制造商信息。
* **配置调试选项:** 一些调试相关的选项可能通过系统属性进行配置，例如是否启用某种特定的日志输出。
* **动态库加载路径:** 环境变量 `LD_LIBRARY_PATH` 可以指定动态链接器搜索动态库的路径。

**libc 函数的功能及实现**

1. **`assert(property_name && dest && dest_size != 0);`:**
   - **功能:** `assert` 是一个宏，用于在运行时检查条件是否为真。如果条件为假，程序会中止并打印错误信息。
   - **实现:**  在 debug 构建中，`assert` 通常会调用一个类似 `abort()` 的函数来终止程序。在 release 构建中，`assert` 宏通常会被禁用，不会产生任何代码。
   - **本例用途:**  检查传入 `get_property_value` 函数的参数是否有效，防止空指针或零大小的缓冲区。

2. **`getenv(env_var_name)`:**
   - **功能:** `getenv` 是一个标准 C 库函数，用于获取指定名称的环境变量的值。
   - **实现:**  在 Linux 和 Android 上，环境变量通常存储在进程的内存空间中。`getenv` 函数会遍历进程的环境变量列表，查找匹配的名称，并返回对应的值的指针。如果找不到，则返回 `NULL`。
   - **本例用途:**  在 `get_config_from_env_or_sysprops` 中，用于尝试获取指定环境变量的值。

3. **`strncpy(options, env, options_size);`:**
   - **功能:** `strncpy` 是一个标准 C 库函数，用于将一个字符串的一部分复制到另一个缓冲区中。它会复制最多 `options_size` 个字符，如果源字符串的长度小于 `options_size`，则会在目标缓冲区的剩余部分填充空字符 `\0`。 **注意：与 `strcpy` 不同，`strncpy` 不保证目标字符串以空字符结尾，因此需要手动添加。**
   - **实现:**  `strncpy` 函数通常通过循环逐个字符地复制源字符串到目标缓冲区。
   - **本例用途:**  在 `get_config_from_env_or_sysprops` 中，用于将环境变量的值复制到 `options` 缓冲区中。

4. **`strlen(value)` (隐式使用):**
   - **功能:** `strlen` 是一个标准 C 库函数，用于计算字符串的长度，不包括结尾的空字符 `\0`。
   - **实现:**  `strlen` 函数会从字符串的起始位置开始遍历，直到遇到空字符 `\0` 为止，并返回遍历的字符数。
   - **本例用途:** `strncpy` 内部会使用 `strlen` 来确定源字符串的长度，以便知道需要复制多少个字符。

5. **`reinterpret_cast<PropCbCookie*>(cookie)`:**
   - **功能:** `reinterpret_cast` 是 C++ 中的一种强制类型转换运算符。它允许将一个指针或引用转换为另一种类型的指针或引用，**但不会进行任何类型检查或数据转换。**  这是一种非常底层的转换，需要谨慎使用。
   - **实现:**  `reinterpret_cast` 实际上只是告诉编译器将一个内存地址视为另一种类型。
   - **本例用途:**  在 `__system_property_read_callback` 的回调函数中，`cookie` 是一个 `void*` 类型的指针，需要将其转换为 `PropCbCookie*` 类型，才能访问 `PropCbCookie` 结构体的成员。

**涉及 dynamic linker 的功能**

这个文件本身并不直接实现 dynamic linker 的功能，但它使用了与动态链接相关的 Bionic 库函数：

* **`__system_property_find(property_name)`:**
    - **功能:**  这个函数是 Bionic 库提供的用于查找指定名称的系统属性的函数。它通常由动态链接器加载到进程空间。
    - **实现:**  `__system_property_find` 内部会与 `system_properties` 服务进行交互，该服务维护着系统属性的数据库。它会查找与 `property_name` 匹配的属性，如果找到则返回一个指向 `prop_info` 结构体的指针，否则返回 `NULL`。
    - **链接处理过程:** 当一个程序调用 `__system_property_find` 时，动态链接器会查找定义该符号的共享库 (通常是 `libc.so`)，并将该函数的地址链接到调用处。

* **`__system_property_read_callback(prop, ...)`:**
    - **功能:** 这个函数用于读取指定 `prop_info` 结构体对应的系统属性的值。它使用回调函数的方式来处理读取到的值。
    - **实现:**  `__system_property_read_callback` 内部会读取 `prop_info` 结构体中存储的属性值，并调用提供的回调函数，将属性的名称、值和序列号作为参数传递给回调函数。
    - **链接处理过程:**  类似于 `__system_property_find`，动态链接器会将对 `__system_property_read_callback` 的调用链接到 `libc.so` 中对应的实现。

**so 布局样本:**

```
libc.so:
    ...
    __system_property_find:  (代码地址)
    __system_property_read_callback: (代码地址)
    ...

你的应用程序/共享库:
    ...
    调用 __system_property_find  (链接到 libc.so 中的地址)
    调用 __system_property_read_callback (链接到 libc.so 中的地址)
    ...
```

**链接的处理过程:**

1. **编译时:** 编译器遇到对 `__system_property_find` 和 `__system_property_read_callback` 的调用时，会生成一个符号引用。
2. **链接时:** 静态链接器会将这些符号引用标记为需要动态链接。
3. **运行时:** 当应用程序或共享库被加载时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   - 加载所有依赖的共享库 (例如 `libc.so`) 到内存中。
   - 遍历应用程序或共享库的重定位表，找到需要动态链接的符号。
   - 在已加载的共享库中查找这些符号的定义 (例如在 `libc.so` 的符号表中查找 `__system_property_find` 和 `__system_property_read_callback`)。
   - 将找到的符号地址写入到应用程序或共享库的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table) 中。
   - 当程序执行到调用这些函数的地方时，会通过 GOT 或 PLT 跳转到 `libc.so` 中对应的函数地址执行。

**假设输入与输出 (逻辑推理)**

**`get_property_value` 函数:**

* **假设输入:**
    - `property_name`: "ro.build.version.sdk"
    - `dest`: 一个大小为 10 的 char 数组
    - `dest_size`: 10
* **假设输出:**
    - 如果系统属性 "ro.build.version.sdk" 存在且值为 "33"，则 `dest` 数组将包含 "33\0"，函数返回 `true`。
    - 如果系统属性不存在，则 `dest` 数组的第一个字符仍然是 `\0`，函数返回 `false`。

**`get_config_from_env_or_sysprops` 函数:**

* **假设输入:**
    - `env_var_name`: "MY_CONFIG"
    - `sys_prop_names`: {"my.config.prop1", "my.config.prop2", nullptr}
    - `sys_prop_names_size`: 3
    - `options`: 一个大小为 20 的 char 数组
    - `options_size`: 20
* **假设输出:**
    - **场景 1: 环境变量存在:** 如果环境变量 `MY_CONFIG` 的值为 "env_value"，则 `options` 数组将包含 "env_value\0"，函数返回 `true`。
    - **场景 2: 环境变量不存在，第一个系统属性存在:** 如果环境变量 `MY_CONFIG` 不存在，且系统属性 "my.config.prop1" 的值为 "prop1_value"，则 `options` 数组将包含 "prop1_value\0"，函数返回 `true`。
    - **场景 3: 环境变量不存在，第一个系统属性不存在，第二个系统属性存在:** 如果环境变量 `MY_CONFIG` 和系统属性 "my.config.prop1" 都不存在，但系统属性 "my.config.prop2" 的值为 "prop2_value"，则 `options` 数组将包含 "prop2_value\0"，函数返回 `true`。
    - **场景 4: 环境变量和所有系统属性都不存在:** 则 `options` 数组的第一个字符仍然是 `\0`，函数返回 `false`。

**用户或编程常见的使用错误**

1. **缓冲区溢出:**  传递给 `get_property_value` 或 `get_config_from_env_or_sysprops` 的 `dest` 或 `options` 缓冲区太小，无法容纳实际的属性值或环境变量值，导致内存写入越界。
   ```c++
   char buffer[5];
   get_property_value("ro.product.model", buffer, sizeof(buffer)); // 如果 model 的长度超过 4，则会溢出
   ```

2. **未检查返回值:**  忘记检查 `get_property_value` 或 `get_config_from_env_or_sysprops` 的返回值，导致在属性或环境变量不存在的情况下，使用了未初始化的缓冲区。
   ```c++
   char buffer[64];
   get_property_value("non.existent.property", buffer, sizeof(buffer));
   // 此时 buffer 可能为空，但程序可能仍然尝试使用 buffer 中的内容
   ```

3. **错误的系统属性名称:**  拼写错误的系统属性名称会导致 `__system_property_find` 返回 `NULL`，从而无法获取到期望的值。

4. **空指针传递:**  将 `nullptr` 传递给 `get_property_value` 的 `property_name` 或 `dest` 参数，会导致程序崩溃。虽然代码中有 `assert` 检查，但在 release 版本中 `assert` 会被禁用。

5. **忘记 null 终止:** 虽然 `strncpy` 会在空间足够的情况下填充空字符，但在 `get_config_from_env_or_sysprops` 中，从环境变量复制后需要手动确保 null 终止。

**Android Framework 或 NDK 如何到达这里**

**Android Framework:**

1. **Framework Service 调用:**  Android Framework 中的一个 Java 服务 (例如 `android.os.SystemProperties`) 可能需要获取一些系统配置信息。
2. **JNI 调用:**  `android.os.SystemProperties` 类会通过 JNI (Java Native Interface) 调用到 `frameworks/base/core/jni/android_os_SystemProperties.cpp` 中的 native 代码。
3. **Native 代码调用 Bionic 函数:** `android_os_SystemProperties.cpp` 中的 native 代码会调用 Bionic 库提供的 `__system_property_get` 等函数来获取系统属性。
4. **Bionic 函数内部调用:**  `__system_property_get` 的实现可能会间接或直接使用 `sysprop_helpers.cpp` 中提供的 `get_property_value` 等辅助函数。

**Android NDK:**

1. **NDK API 使用:**  NDK 开发者可以使用 Android 的 C/C++ API，例如 `<sys/system_properties.h>` 中声明的函数，来访问系统属性。
   ```c++
   #include <sys/system_properties.h>
   #include <android/log.h>

   void get_sdk_version() {
       char sdk_version[32];
       int len = __system_property_get("ro.build.version.sdk", sdk_version);
       if (len > 0) {
           __android_log_print(ANDROID_LOG_INFO, "MyApp", "SDK Version: %s", sdk_version);
       }
   }
   ```
2. **Bionic 库链接:**  当 NDK 应用编译链接时，会链接到 Bionic 库 (`libc.so`)。
3. **间接使用 `sysprop_helpers`:**  NDK 应用调用的 `__system_property_get` 等函数最终可能会调用到 `sysprop_helpers.cpp` 中的辅助函数。

**Frida Hook 示例**

以下是一个使用 Frida Hook `get_config_from_env_or_sysprops` 函数的示例：

```javascript
if (Process.platform === 'android') {
  const moduleName = 'libc.so';
  const functionName = '_Z31get_config_from_env_or_syspropsPKPKcS0_mPcS1_'; // Mangled name, might need adjustment

  const targetFunction = Module.findExportByName(moduleName, functionName);

  if (targetFunction) {
    Interceptor.attach(targetFunction, {
      onEnter: function (args) {
        console.log(`[+] Hooking ${functionName}`);
        console.log(`[+] env_var_name: ${args[0].readCString()}`);
        const sys_prop_names = ptr(args[1]);
        const sys_prop_names_size = args[2].toInt();
        console.log(`[+] sys_prop_names_size: ${sys_prop_names_size}`);
        for (let i = 0; i < sys_prop_names_size; i++) {
          const propNamePtr = sys_prop_names.add(i * Process.pointerSize).readPointer();
          if (!propNamePtr.isNull()) {
            console.log(`[+]   sys_prop_names[${i}]: ${propNamePtr.readCString()}`);
          } else {
            console.log(`[+]   sys_prop_names[${i}]: null`);
          }
        }
        console.log(`[+] options_size: ${args[4].toInt()}`);
      },
      onLeave: function (retval) {
        console.log(`[+] Return value: ${retval}`);
        if (retval.toInt() !== 0) {
          console.log(`[+] options: ${this.context.r3.readCString()}`); // Assuming ARM64, adjust register if needed
        }
        console.log(`[+] Leaving ${functionName}`);
      },
    });
  } else {
    console.log(`[-] Function ${functionName} not found in ${moduleName}`);
  }
} else {
  console.log('[!] This script is for Android only.');
}
```

**说明:**

1. **`Process.platform === 'android'`:** 检查是否在 Android 环境中运行。
2. **`moduleName` 和 `functionName`:**  指定要 Hook 的模块和函数名。你需要使用 `adb shell cat /proc/PID/maps` 或者其他工具找到 `libc.so` 的加载地址，并使用 `frida-ls-exports -a -n libc.so` 来找到函数的 mangled name (或者使用一些反编译工具)。 **注意：mangled name 可能会因 Android 版本和架构而异。**
3. **`Module.findExportByName`:**  查找指定模块中导出的函数。
4. **`Interceptor.attach`:**  拦截目标函数的调用。
5. **`onEnter`:**  在函数调用前执行，可以访问函数的参数。
6. **`onLeave`:**  在函数调用后执行，可以访问函数的返回值。
7. **参数访问:**  `args[0]`, `args[1]` 等用于访问函数的参数。需要根据函数的签名和调用约定来理解参数的含义。
8. **返回值访问:** `retval` 变量包含函数的返回值。
9. **`this.context.r3.readCString()`:**  在 `onLeave` 中，尝试读取 `options` 缓冲区的内容。 **这里假设是在 ARM64 架构下，`options` 缓冲区的指针可能存储在 `r3` 寄存器中。你需要根据实际情况调整寄存器名称。**

这个 Frida 脚本可以帮助你动态地观察 `get_config_from_env_or_sysprops` 函数的调用，了解它接收到的参数和返回的值，从而更好地理解其行为。

希望这个详细的分析能够帮助你理解 `bionic/libc/bionic/sysprop_helpers.cpp` 文件的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/sysprop_helpers.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "sysprop_helpers.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sys/system_properties.h"

static bool get_property_value(const char* property_name, char* dest, size_t dest_size) {
  assert(property_name && dest && dest_size != 0);
  const prop_info* prop = __system_property_find(property_name);
  if (!prop) return false;

  struct PropCbCookie {
    char* dest;
    size_t size;
  };
  *dest = '\0';
  PropCbCookie cb_cookie = {dest, dest_size};

  __system_property_read_callback(
      prop,
      [](void* cookie, const char* /* name */, const char* value, uint32_t /* serial */) {
        auto* cb_cookie = reinterpret_cast<PropCbCookie*>(cookie);
        strncpy(cb_cookie->dest, value, cb_cookie->size);
      },
      &cb_cookie);
  return *dest != '\0';
}

bool get_config_from_env_or_sysprops(const char* env_var_name, const char* const* sys_prop_names,
                                     size_t sys_prop_names_size, char* options,
                                     size_t options_size) {
  const char* env = getenv(env_var_name);
  if (env && *env != '\0') {
    strncpy(options, env, options_size);
    options[options_size - 1] = '\0';  // Ensure null-termination.
    return true;
  }

  for (size_t i = 0; i < sys_prop_names_size; ++i) {
    if (sys_prop_names[i] == nullptr) continue;
    if (get_property_value(sys_prop_names[i], options, options_size)) return true;
  }
  return false;
}
```