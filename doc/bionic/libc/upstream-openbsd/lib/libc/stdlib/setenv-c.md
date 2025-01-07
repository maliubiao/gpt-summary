Response:
Let's break down the thought process for answering the request about `setenv.c`.

**1. Understanding the Core Request:**

The fundamental goal is to analyze the provided `setenv.c` source code, explaining its functionality, its relation to Android, its implementation details, its interaction with the dynamic linker (if any), potential usage errors, and how it's reached from Android frameworks/NDK, including debugging.

**2. Initial Code Scan and Function Identification:**

The first step is to quickly scan the code to identify the main functions. We can easily spot `putenv`, `setenv`, and `unsetenv`. We also see a `static char **lastenv;` which hints at internal memory management. The copyright notice tells us it's based on OpenBSD.

**3. Function-by-Function Analysis (Mental Walkthrough):**

For each function, the thought process would be:

* **`putenv(char *str)`:**
    * **Purpose:**  Adds a `name=value` string directly to the environment.
    * **Key Steps:**
        * Find the `=` separator. Error if missing or at the start.
        * Use `__findenv` to see if the variable already exists.
        * If it exists, replace the existing entry. Crucially, it handles *multiple* occurrences of the same variable.
        * If it doesn't exist, allocate more space for the `environ` array using `reallocarray`.
        * Copy the existing environment (if any) to the new space.
        * Add the new string to the `environ` array.
    * **Android Relevance:**  Directly manipulates the process's environment variables. Useful for setting configuration or passing information to child processes.

* **`setenv(const char *name, const char *value, int rewrite)`:**
    * **Purpose:** Sets the value of an environment variable. More controlled than `putenv`.
    * **Key Steps:**
        * Validate the `name` (no empty name or `=`).
        * Use `__findenv` to check for existence.
        * **`rewrite` logic:**
            * If `rewrite` is 0 and the variable exists, do nothing.
            * If the variable exists and `rewrite` is non-zero, potentially reallocate memory (the `#if 0` section is interesting - it shows an optimization that's *not* currently active, likely due to potential writability issues of the existing string).
        * If the variable doesn't exist, allocate new space in `environ`.
        * Allocate memory for the `name=value` string using `malloc`.
        * Construct the `name=value` string in the allocated memory.
    * **Android Relevance:**  The preferred way to set environment variables in Android due to the `rewrite` control. Frameworks and apps use this.

* **`unsetenv(const char *name)`:**
    * **Purpose:** Removes an environment variable.
    * **Key Steps:**
        * Validate `name`.
        * Use `__findenv` to locate occurrences of the variable.
        * Shift the subsequent entries in the `environ` array to overwrite the removed entry.
    * **Android Relevance:**  Important for cleaning up the environment or removing unwanted variables.

* **`__findenv(const char *name, int namelen, int *offset)`:** (Although not directly in this file, its use is critical).
    * **Purpose (deduced from usage):**  Finds an environment variable by name.
    * **Key Information:**  The `offset` parameter is key – it returns the *index* in the `environ` array.
    * **Android Relevance:** An internal helper function essential for the other three.

**4. Identifying Android Specifics and Connections:**

* **`bionic` Context:** The request explicitly states this is *bionic*, Android's C library. This immediately highlights the importance of these functions in the Android ecosystem.
* **NDK and Framework:** Consider how environment variables are used in Android development:
    * **NDK:** Native code interacts directly with these functions. Developers might use them for custom configurations or passing data.
    * **Framework:** Android framework services and apps use environment variables for configuration and communication. The `init` process sets up many initial environment variables.

**5. Dynamic Linker Considerations:**

While `setenv.c` itself doesn't *directly* perform dynamic linking, environment variables can *influence* the dynamic linker. Think of `LD_LIBRARY_PATH`.

* **SO Layout:** Describe a typical Android SO layout.
* **Linking Process:** Explain how `LD_LIBRARY_PATH` affects the search for shared libraries.

**6. Common Errors and Assumptions:**

Think about how developers might misuse these functions.

* **`putenv` Modification:** Modifying the string passed to `putenv` directly is dangerous.
* **Memory Leaks with `setenv`:**  Not freeing memory if `setenv` fails.
* **Incorrect `name` format:** Using `=` in the name.

**7. Frida Hooking:**

Think about how to observe these functions in action. Frida is ideal for this.

* **Targeting Functions:**  Hook `putenv`, `setenv`, and `unsetenv`.
* **Logging Parameters:**  Log the `name`, `value`, and `rewrite` parameters.
* **Observing `environ`:**  Print the `environ` array before and after the function call to see the changes.

**8. Structuring the Answer:**

Organize the information logically:

* **Functionality Overview:**  Start with a high-level summary.
* **Detailed Function Explanations:**  Go through each function, explaining its purpose and implementation.
* **Android Relevance with Examples:** Provide concrete Android use cases.
* **Dynamic Linker Aspects:**  Explain the indirect relationship.
* **Common Errors:**  Highlight potential pitfalls.
* **Android Framework/NDK Path:** Describe how these functions are reached.
* **Frida Hooking:** Give practical examples.
* **Assumptions and Input/Output (where applicable):**  Provide illustrative scenarios.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe focus too much on the memory allocation details of `reallocarray`. **Correction:**  Shift focus to the core logic of environment variable manipulation.
* **Thinking about Dynamic Linker:** Realize `setenv.c` isn't *doing* the linking, but *influences* it through environment variables. **Correction:** Explain the indirect relationship through examples like `LD_LIBRARY_PATH`.
* **Frida Examples:**  Start with basic hooking and then think about adding more detail (like printing `environ`).

By following this structured thought process, including function-by-function analysis, considering the Android context, and anticipating potential problems, we can arrive at a comprehensive and informative answer like the example provided.
## bionic 中 setenv.c 的功能详解

你提供的 `setenv.c` 文件是 Android Bionic C 库中用于操作环境变量的源代码文件。它来源于 OpenBSD 的 `libc` 库，并在 Bionic 中被使用。这个文件主要实现了以下三个核心功能：

1. **`putenv(char *str)`:**  将一个形如 "name=value" 的字符串直接添加到环境变量中。如果同名的环境变量已存在，则替换其值。

2. **`setenv(const char *name, const char *value, int rewrite)`:** 设置名为 `name` 的环境变量的值为 `value`。`rewrite` 参数控制是否覆盖已存在的同名环境变量。如果 `rewrite` 为非零值，则覆盖；如果为零，且环境变量已存在，则不进行任何操作。

3. **`unsetenv(const char *name)`:** 删除名为 `name` 的环境变量。

**与 Android 功能的关系及举例说明：**

环境变量在 Android 系统中扮演着重要的角色，它们可以影响进程的行为和配置。`setenv.c` 中提供的函数是 Android 系统中程序管理环境变量的基础工具。

* **系统属性的读取和设置：** Android 系统中许多系统属性可以通过环境变量来传递和影响。例如，`ANDROID_ROOT` 环境变量通常指向 Android 系统根目录。虽然 Android 更倾向于使用 `property_get` 和 `property_set` 来管理系统属性，但在某些情况下，环境变量仍然会被用来传递信息。
    * **例子：** 某些 Android Native 服务可能通过读取特定的环境变量来确定其配置路径或行为模式。例如，一个守护进程可能会读取 `MY_CONFIG_DIR` 环境变量来找到其配置文件。
* **进程间通信：** 环境变量可以作为一种简单的进程间通信方式。父进程可以设置环境变量，然后子进程可以读取这些变量来获取信息。
    * **例子：** 当 Android Framework 启动一个应用进程时，它可能会设置一些环境变量，例如 `CLASSPATH`（用于指定 Java 类的路径）或 `LD_LIBRARY_PATH`（用于指定 Native 库的路径），供应用进程使用。
* **NDK 开发：** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的 Native 代码。在 Native 代码中，开发者可以使用 `setenv`、`putenv` 和 `unsetenv` 来操作环境变量。
    * **例子：** 一个使用 NDK 开发的游戏引擎可能需要设置一些自定义的环境变量来控制其渲染管线或其他内部设置。
* **动态链接器的行为：**  `LD_LIBRARY_PATH` 环境变量是动态链接器关注的重要变量。它指示了动态链接器在哪些路径下搜索共享库。
    * **例子：** 在 Android 中，为了加载 Native 库，系统会设置 `LD_LIBRARY_PATH` 环境变量，其中包含了系统库和应用私有库的路径。

**每一个 libc 函数的功能实现详解：**

**1. `putenv(char *str)`:**

* **功能：** 直接将 `str` (形如 "name=value") 添加到 `environ` 数组中。
* **实现步骤：**
    1. **验证输入：** 检查 `str` 是否包含 `=` 并且 `=` 不在字符串的开头。如果校验失败，则设置 `errno` 为 `EINVAL` 并返回 -1。
    2. **查找已存在的环境变量：** 调用内部函数 `__findenv` 查找是否已经存在与 `str` 中 `name` 部分相同的环境变量。`__findenv` 会返回匹配的 `environ` 数组的索引（通过 `offset` 返回）。
    3. **替换已存在的环境变量：** 如果找到了同名环境变量，则直接将 `environ` 数组中对应的指针指向 `str`。如果存在多个同名环境变量（理论上不应该发生，但代码考虑了这种情况），则会删除后续重复的条目。
    4. **创建新的环境变量：** 如果没有找到同名环境变量：
        * 计算当前 `environ` 数组的大小。
        * 使用 `reallocarray` 重新分配 `environ` 数组，增加两个 `char *` 的空间（一个用于新的环境变量，一个用于 NULL 结尾符）。
        * 如果重新分配失败，返回 -1。
        * 如果 `environ` 指针发生了变化（即进行了重新分配），则将旧的 `environ` 内容拷贝到新的内存区域。
        * 将新的环境变量字符串 `str` 赋值给 `environ` 数组的最后一个有效位置。
        * 将 `environ` 数组的倒数第二个位置设置为 `str`，最后一个位置设置为 `NULL`，以保持 `environ` 数组的 NULL 结尾特性。
* **关键数据结构：**
    * `environ`:  全局变量，是一个 `char **` 类型的数组，存储着所有的环境变量字符串。
    * `lastenv`:  一个静态全局变量，用于记录 `environ` 的最后值，主要用于在 `reallocarray` 之后更新 `environ` 指针。
* **注意事项：** `putenv` 直接使用传入的 `char *str`，这意味着如果外部修改了 `str` 指向的内存，环境变量的值也会被修改。

**2. `setenv(const char *name, const char *value, int rewrite)`:**

* **功能：** 设置名为 `name` 的环境变量的值为 `value`，并根据 `rewrite` 参数决定是否覆盖已存在的同名变量。
* **实现步骤：**
    1. **验证输入：** 检查 `name` 是否为空或包含 `=`。如果校验失败，则设置 `errno` 为 `EINVAL` 并返回 -1。
    2. **查找已存在的环境变量：** 调用内部函数 `__findenv` 查找是否已经存在名为 `name` 的环境变量。
    3. **处理已存在的环境变量：**
        * 如果找到了同名环境变量并且 `rewrite` 为 0，则直接返回 0，不做任何修改。
        * 如果找到了同名环境变量并且 `rewrite` 为非零值，则：
            * 删除所有已存在的同名环境变量条目。
    4. **创建或更新环境变量：**
        * 计算当前 `environ` 数组的大小。
        * 使用 `reallocarray` 重新分配 `environ` 数组，增加两个 `char *` 的空间。
        * 如果重新分配失败，返回 -1。
        * 如果 `environ` 指针发生了变化，则拷贝旧的 `environ` 内容。
        * 使用 `malloc` 分配足够的内存来存储新的环境变量字符串（`name` + "=" + `value` + '\0'）。
        * 如果 `malloc` 失败，返回 -1。
        * 将 `name`、`=` 和 `value` 复制到新分配的内存中，构建环境变量字符串。
        * 将新分配的字符串的指针赋值给 `environ` 数组的最后一个有效位置。
        * 设置 `environ` 数组的 NULL 结尾符。
* **关键数据结构：**
    * `environ`: 全局变量，存储环境变量。
    * `lastenv`: 静态全局变量，用于记录 `environ` 的最后值。
* **注意事项：** `setenv` 会为新的环境变量字符串分配内存，这意味着当环境变量不再需要时，相关的内存需要被释放（虽然通常环境变量的生命周期与进程相同）。

**3. `unsetenv(const char *name)`:**

* **功能：** 删除名为 `name` 的环境变量。
* **实现步骤：**
    1. **验证输入：** 检查 `name` 是否为空或包含 `=`。如果校验失败，则设置 `errno` 为 `EINVAL` 并返回 -1。
    2. **查找要删除的环境变量：** 调用内部函数 `__findenv` 查找名为 `name` 的环境变量。
    3. **删除环境变量：** 如果找到了要删除的环境变量：
        * 将 `environ` 数组中该环境变量的指针以及后续所有同名环境变量的指针都指向数组中的下一个元素，有效地将这些条目从 `environ` 数组中移除。
        * 持续查找和删除同名环境变量，直到找不到为止。
* **关键数据结构：**
    * `environ`: 全局变量，存储环境变量。
* **注意事项：** `unsetenv` 只会从 `environ` 数组中移除指向环境变量字符串的指针，但不会释放环境变量字符串本身占用的内存。这通常不是问题，因为这些内存是在 `setenv` 或 `putenv` 中分配的，并与进程的生命周期相关联。

**涉及 dynamic linker 的功能：**

`setenv.c` 本身不直接包含 dynamic linker 的代码，但它提供的函数可以影响 dynamic linker 的行为。最典型的例子就是 `LD_LIBRARY_PATH` 环境变量。

**假设 `setenv` 被用来设置 `LD_LIBRARY_PATH`：**

**SO 布局样本：**

假设我们有以下目录结构：

```
/data/app/com.example.myapp/lib/arm64/my_custom_lib.so
/system/lib64/libc.so
/vendor/lib64/some_vendor_lib.so
```

**链接的处理过程：**

1. 当 Android 系统启动一个使用了 Native 库的应用时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载和链接这些库。
2. 动态链接器首先会查找可执行文件依赖的共享库列表。
3. 对于每一个依赖的共享库，动态链接器会按照一定的顺序搜索库文件，这个搜索路径受到 `LD_LIBRARY_PATH` 环境变量的影响。
4. 如果 `setenv("LD_LIBRARY_PATH", "/data/app/com.example.myapp/lib/arm64:/system/lib64", 1)` 被调用，则动态链接器在搜索共享库时，会先查找 `/data/app/com.example.myapp/lib/arm64` 目录，然后再查找 `/system/lib64` 目录。
5. 如果应用依赖 `my_custom_lib.so`，动态链接器会在 `/data/app/com.example.myapp/lib/arm64` 目录下找到并加载它。
6. 如果应用依赖 `libc.so`，动态链接器会在 `/system/lib64` 目录下找到并加载它。

**假设输入与输出（针对 `setenv`）：**

**假设输入：**

```c
const char *name = "MY_VAR";
const char *value = "my_value";
int rewrite = 1;
```

**预期输出：**

* 如果环境变量 "MY_VAR" 之前不存在，则调用 `setenv` 后，环境变量中会新增 "MY_VAR=my_value"。
* 如果环境变量 "MY_VAR" 之前存在且值为 "old_value"，由于 `rewrite` 为 1，调用 `setenv` 后，"MY_VAR" 的值会被更新为 "my_value"。
* 函数 `setenv` 返回 0 表示成功。

**假设输入与输出（针对 `unsetenv`）：**

**假设输入：**

```c
const char *name = "MY_VAR";
```

**预期输出：**

* 如果环境变量 "MY_VAR" 存在，调用 `unsetenv` 后，该环境变量会被删除。
* 如果环境变量 "MY_VAR" 不存在，调用 `unsetenv` 后，环境变量不会发生变化。
* 函数 `unsetenv` 返回 0 表示成功。

**用户或编程常见的使用错误：**

1. **`putenv` 的内存管理问题：**  如果传递给 `putenv` 的字符串是栈上分配的或者之后被释放了，那么环境变量可能会指向无效的内存，导致程序崩溃或未定义行为。
   ```c
   void foo() {
       char buffer[100];
       snprintf(buffer, sizeof(buffer), "MY_VAR=some_value");
       putenv(buffer); // 错误：buffer 在 foo 函数返回后失效
   }
   ```

2. **`setenv` 的内存泄漏：**  在某些不常见的场景下，如果 `setenv` 失败，可能会导致内存泄漏，尽管现代的 `setenv` 实现会尽量避免这种情况。

3. **尝试设置无效的环境变量名：**  环境变量名不应包含 `=` 或以数字开头。尝试设置这样的环境变量会导致 `errno` 被设置为 `EINVAL`。
   ```c
   setenv("MY=VAR", "value", 1); // 错误：环境变量名包含 '='
   setenv("123VAR", "value", 1); // 错误：环境变量名以数字开头（虽然这可能在某些系统上允许，但不是标准的）
   ```

4. **在多线程环境中使用 `putenv`：** `putenv` 可能会修改全局的 `environ` 指针，这在多线程环境下不是线程安全的。推荐在多线程环境中使用 `setenv` 和 `unsetenv`。

5. **修改 `putenv` 的参数：**  由于 `putenv` 直接使用传入的 `char *` 指针，修改这个字符串会直接影响到环境变量的值，这可能会导致意想不到的结果。

**Android framework 或 ndk 是如何一步步的到达这里：**

1. **Android Framework (Java 层):**
   * Android 的 Java Framework 层面通常不会直接调用 `setenv` 等 C 库函数。
   * 相反，它更多地使用 `System.setProperty()` 来设置系统属性，这些属性可以通过 `property_get` 在 Native 层读取。
   * 但在某些情况下，Framework 可能会通过执行 shell 命令或启动新的 Native 进程来间接影响环境变量。例如，`Runtime.exec()` 可以执行带有自定义环境变量的命令。

2. **Android NDK (Native 层):**
   * NDK 开发的 C/C++ 代码可以直接调用 `setenv`、`putenv` 和 `unsetenv`。
   * 例如，一个 Native 库可能需要在初始化时设置某些环境变量。

3. **系统服务和守护进程:**
   * Android 的系统服务和守护进程（通常用 C/C++ 编写）会广泛使用这些函数来配置自身或传递信息给子进程。
   * `init` 进程是 Android 系统启动的第一个进程，它会读取配置文件 (`init.rc`) 并使用 `setenv` 设置许多初始的环境变量。

**Frida hook 示例调试这些步骤：**

以下是一个使用 Frida hook `setenv` 函数的示例：

```javascript
Java.perform(function() {
    var setenv = Module.findExportByName("libc.so", "setenv");
    if (setenv) {
        Interceptor.attach(setenv, {
            onEnter: function(args) {
                var name = Memory.readUtf8String(args[0]);
                var value = Memory.readUtf8String(args[1]);
                var rewrite = args[2].toInt();
                console.log("setenv called with name: " + name + ", value: " + value + ", rewrite: " + rewrite);
            },
            onLeave: function(retval) {
                console.log("setenv returned: " + retval);
            }
        });
        console.log("Hooked setenv");
    } else {
        console.log("setenv not found in libc.so");
    }

    var putenv = Module.findExportByName("libc.so", "putenv");
    if (putenv) {
        Interceptor.attach(putenv, {
            onEnter: function(args) {
                var str = Memory.readUtf8String(args[0]);
                console.log("putenv called with str: " + str);
            },
            onLeave: function(retval) {
                console.log("putenv returned: " + retval);
            }
        });
        console.log("Hooked putenv");
    } else {
        console.log("putenv not found in libc.so");
    }

    var unsetenv = Module.findExportByName("libc.so", "unsetenv");
    if (unsetenv) {
        Interceptor.attach(unsetenv, {
            onEnter: function(args) {
                var name = Memory.readUtf8String(args[0]);
                console.log("unsetenv called with name: " + name);
            },
            onLeave: function(retval) {
                console.log("unsetenv returned: " + retval);
            }
        });
        console.log("Hooked unsetenv");
    } else {
        console.log("unsetenv not found in libc.so");
    }
});
```

**使用方法：**

1. 将以上 JavaScript 代码保存为 `hook_env.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_env.js --no-pause
   ```
   将 `<package_name>` 替换为你要监控的应用程序的包名。
3. 当目标应用程序调用 `setenv`、`putenv` 或 `unsetenv` 时，Frida 将会在控制台上打印出相应的调用信息，包括函数名、参数和返回值。

通过 Frida hook，你可以动态地观察 Android 系统或特定应用程序是如何使用这些环境变量操作函数的，从而更好地理解系统的行为和调试问题。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdlib/setenv.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: setenv.c,v 1.20 2022/08/08 22:40:03 millert Exp $ */
/*
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static char **lastenv;				/* last value of environ */

/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
int
putenv(char *str)
{
	char **P, *cp;
	size_t cnt = 0;
	int offset = 0;

	for (cp = str; *cp && *cp != '='; ++cp)
		;
	if (cp == str || *cp != '=') {
		/* '=' is the first character of string or is missing. */
		errno = EINVAL;
		return (-1);
	}

	if (__findenv(str, (int)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		while (__findenv(str, (int)(cp - str), &offset)) {
			for (P = &environ[offset];; ++P)
				if (!(*P = *(P + 1)))
					break;
		}
		return (0);
	}

	/* create new slot for string */
	if (environ != NULL) {
		for (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
	}
	P = reallocarray(lastenv, cnt + 2, sizeof(char *));
	if (!P)
		return (-1);
	if (lastenv != environ && environ != NULL)
		memcpy(P, environ, cnt * sizeof(char *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	return (0);
}
DEF_WEAK(putenv);

/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
int
setenv(const char *name, const char *value, int rewrite)
{
	char *C, **P;
	const char *np;
	int l_value, offset = 0;

	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}
	for (np = name; *np && *np != '='; ++np)
		;
	if (*np) {
		errno = EINVAL;
		return (-1);			/* has `=' in name */
	}

	l_value = strlen(value);
	if ((C = __findenv(name, (int)(np - name), &offset)) != NULL) {
		int tmpoff = offset + 1;
		if (!rewrite)
			return (0);
#if 0 /* XXX - existing entry may not be writable */
		if (strlen(C) >= l_value) {	/* old larger; copy over */
			while ((*C++ = *value++))
				;
			return (0);
		}
#endif
		/* could be set multiple times */
		while (__findenv(name, (int)(np - name), &tmpoff)) {
			for (P = &environ[tmpoff];; ++P)
				if (!(*P = *(P + 1)))
					break;
		}
	} else {					/* create new slot */
		size_t cnt = 0;

		if (environ != NULL) {
			for (P = environ; *P != NULL; P++)
				;
			cnt = P - environ;
		}
		P = reallocarray(lastenv, cnt + 2, sizeof(char *));
		if (!P)
			return (-1);
		if (lastenv != environ && environ != NULL)
			memcpy(P, environ, cnt * sizeof(char *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	if (!(environ[offset] =			/* name + `=' + value */
	    malloc((int)(np - name) + l_value + 2)))
		return (-1);
	for (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	for (*C++ = '='; (*C++ = *value++); )
		;
	return (0);
}
DEF_WEAK(setenv);

/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
int
unsetenv(const char *name)
{
	char **P;
	const char *np;
	int offset = 0;

	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}
	for (np = name; *np && *np != '='; ++np)
		;
	if (*np) {
		errno = EINVAL;
		return (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	while (__findenv(name, (int)(np - name), &offset)) {
		for (P = &environ[offset];; ++P)
			if (!(*P = *(P + 1)))
				break;
	}
	return (0);
}
DEF_WEAK(unsetenv);

"""

```