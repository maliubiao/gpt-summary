Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a comprehensive analysis of the provided `syslog.handroid` header file, specifically within the context of Android's Bionic libc. The key is to identify its functionality, its relationship to Android, implementation details (especially libc and dynamic linker interactions), common usage errors, and how it's reached by higher-level Android components.

2. **Initial Scan and Keyword Identification:** I quickly scanned the file, looking for keywords like `define`, function declarations (`void closelog(...)`), comments mentioning Android, and terms related to logging. This gives a high-level understanding of the file's purpose. I noticed the extensive use of `#define` for log levels and facilities, and the mentions of `logcat`.

3. **Categorize Functionality:** I started grouping the information I found into logical categories. The most obvious categories are:
    * **Log Priorities:** `LOG_EMERG`, `LOG_DEBUG`, etc.
    * **Log Facilities:** `LOG_KERN`, `LOG_USER`, `LOG_LOCAL0`, etc. (and the comment that most are ignored on Android).
    * **Macros:** `LOG_PRIMASK`, `LOG_PRI`, `LOG_MAKEPRI`, `LOG_MASK`, `LOG_UPTO`.
    * **Functions:** `closelog`, `openlog`, `setlogmask`, `syslog`, `vsyslog`.
    * **Data Structures (Conditional):** `CODE` struct, `facilitynames`, `prioritynames` (under `SYSLOG_NAMES`).
    * **Openlog Options:** `LOG_PID`, `LOG_CONS`, etc. (and comments about them being ignored).

4. **Analyze Each Category in Detail:**

    * **Log Priorities:** I noted the mapping to Android log priorities (ERROR, WARN, INFO, DEBUG). This is a crucial connection to Android.
    * **Log Facilities:** I emphasized that most facilities are *ignored* on Android, highlighting the difference from standard `syslog`. This is a key Android-specific behavior.
    * **Macros:** I explained the purpose of each macro (extracting priority, combining facility and priority, creating masks).
    * **Functions:**  This is where the bulk of the explanation is needed.
        * **`closelog`:**  Simple: does nothing on Android.
        * **`openlog`:** Focus on the `__prefix` argument and its use as the log tag. Mention the ignored arguments.
        * **`setlogmask`:** Explain its role in filtering log messages based on priority.
        * **`syslog` and `vsyslog`:**  Crucially, these are the functions that actually send logs to `logcat`. Explain the formatting and priority aspects. The `__printflike` attribute is also worth mentioning.
    * **Data Structures:** Explained the purpose of the `CODE` struct and the name-to-value mappings, while noting the conditional compilation (`SYSLOG_NAMES`).
    * **Openlog Options:** Explained what each option *would* do in a standard syslog implementation but is *ignored* on Android, except for `LOG_PERROR`.

5. **Address Android-Specific Aspects:**

    * **Relationship to Android:**  Emphasize the connection between the defined log levels and Android's `Log` class (e.g., `Log.e`, `Log.d`). The destination of the logs being `logcat` is paramount.
    * **No Dynamic Linker Involvement (for *this* header):** Carefully analyze the *header file*. It contains *declarations* and *macros*, not function *implementations*. The actual implementation of `syslog` (which *does* interact with the dynamic linker to find the `__android_log_write` function) is in a separate `.c` file. Therefore, *for this specific header file*, there's no direct dynamic linker involvement to explain. I need to acknowledge this nuance.

6. **Consider Common Usage Errors:**

    * **Incorrect Priority Levels:**  Using numerical values directly instead of the defined macros.
    * **Assuming Standard Syslog Behavior:**  Expecting `openlog` options (other than `LOG_PERROR` since API 34) or facility specifications to have an effect.
    * **Forgetting `setlogmask`:**  Being surprised that logs aren't appearing when the mask is set too high.

7. **Explain the Path from Framework/NDK to `syslog`:**

    * **Android Framework:** Start with a high-level example (e.g., `Log.e()`) and trace it down through the JNI bridge to native code.
    * **NDK:** Show a direct usage example from C/C++ code using the `syslog` function.

8. **Provide Frida Hook Examples:**  Craft specific Frida scripts to intercept `syslog`, `openlog`, and `setlogmask`, demonstrating how to inspect arguments and potentially modify behavior.

9. **Structure and Language:**

    * Use clear headings and bullet points for readability.
    * Explain technical terms concisely.
    * Use code blocks for code snippets.
    * Maintain a formal but understandable tone.
    * Explicitly state assumptions and limitations (e.g., about dynamic linker involvement *in this header file*).

10. **Review and Refine:**  After drafting the answer, I reread the request and my response to ensure I addressed all points and that the explanations are accurate and complete. I specifically double-checked the dynamic linker part to ensure I was being precise about the context of the header file vs. the implementation.

By following these steps, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to break down the problem into smaller, manageable parts and then synthesize the information into a coherent whole.
好的，让我们详细分析一下 `bionic/libc/include/syslog.handroid` 这个头文件。

**功能列举:**

这个头文件定义了与系统日志记录相关的常量、宏和函数声明。其主要功能是：

1. **定义日志优先级 (Log Priorities):**  定义了一系列表示日志重要程度的宏，例如 `LOG_EMERG`（最高优先级，紧急情况）、`LOG_ALERT`、`LOG_CRIT`、`LOG_ERR`、`LOG_WARNING`、`LOG_NOTICE`、`LOG_INFO` 和 `LOG_DEBUG`（最低优先级，调试信息）。这些优先级与 Android 的日志级别直接对应。

2. **定义日志设施 (Log Facilities):**  定义了一些表示日志来源的宏，例如 `LOG_KERN`（内核）、`LOG_USER`（用户级别）、`LOG_DAEMON`（守护进程）等。**但在 Android 中，这些设施标志基本上被忽略，不起实际作用。**  `LOG_LOCAL0` 到 `LOG_LOCAL7` 也被定义，但在 Android 中同样被忽略。

3. **提供日志操作相关的宏:**
    * `LOG_PRIMASK`: 用于提取优先级。
    * `LOG_PRI(x)`: 从优先级和设施组合的值中提取优先级。
    * `LOG_MAKEPRI(fac, pri)`: 将设施和优先级组合成一个值。
    * `LOG_MASK(pri)`: 生成一个用于 `setlogmask` 的位掩码，用于启用特定优先级的日志。
    * `LOG_UPTO(pri)`: 生成一个用于 `setlogmask` 的位掩码，用于启用指定优先级及其以上所有优先级的日志。

4. **声明日志操作相关的函数:**
    * `closelog()`:  关闭日志描述符。在 Android 中，此函数实际上不执行任何操作。
    * `openlog()`: 打开日志连接。在 Android 中，它主要用于设置日志的标签（tag）。
    * `setlogmask()`: 设置日志掩码，用于控制哪些优先级的日志会被记录。
    * `syslog()`:  生成格式化的日志消息。这是最主要的日志记录函数。
    * `vsyslog()`:  与 `syslog` 类似，但使用 `va_list` 接收可变参数。

5. **可选的日志名称映射 (条件编译):**  在定义了 `SYSLOG_NAMES` 的情况下，会定义 `CODE` 结构体以及 `facilitynames` 和 `prioritynames` 数组，用于将设施和优先级的名称映射到其对应的数值。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 系统日志机制的核心接口。Android 使用 `logcat` 作为其主要的系统日志记录工具，而 `syslog` 函数是应用程序向 `logcat` 发送日志消息的关键途径。

**举例说明:**

在 Android 的 Java 代码中，我们通常使用 `android.util.Log` 类来记录日志。例如：

```java
import android.util.Log;

public class MyClass {
    public void someMethod() {
        Log.d("MyTag", "This is a debug message.");
        Log.e("MyTag", "An error occurred!");
    }
}
```

在底层，`android.util.Log` 的实现会通过 JNI 调用到 Native 代码，最终会调用到 Bionic libc 提供的 `__android_log_write` 函数，而 `syslog` 函数的实现会调用这个 `__android_log_write` 函数将日志写入到 `logcat` 中。

这个头文件中定义的 `LOG_DEBUG`、`LOG_ERROR` 等宏，就对应了 `android.util.Log.d` 和 `android.util.Log.e` 等方法中隐含的日志优先级。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于你提供的只是头文件，我们只能看到函数的声明。函数的具体实现位于 Bionic libc 的源代码文件中（通常是 `.c` 文件）。我们可以推测其实现原理：

* **`closelog()`:**  在标准的 `syslog` 实现中，`closelog` 会关闭与日志守护进程的连接。但在 Android 中，日志记录由 `logd` 守护进程处理，并且通常不需要显式打开和关闭连接，因此 Bionic 的 `closelog` 实现很可能是一个空函数或者只包含一些清理操作。

* **`openlog(const char* __prefix, int __option, int __facility)`:**
    * `__prefix`:  这个参数会被用来设置日志的标签 (tag)。Android 的 `logcat` 使用标签来过滤和识别日志消息的来源。Bionic 的 `openlog` 可能会将这个 `__prefix` 存储在一个全局变量中，供后续的 `syslog` 调用使用。
    * `__option` 和 `__facility`:  在 Android 中，这两个参数大部分情况下会被忽略。以前的版本完全忽略，在较新的版本中，`LOG_PERROR` 选项（API 级别 34 引入）如果设置了，可能会导致日志同时输出到标准错误输出。

* **`setlogmask(int __mask)`:**
    * 这个函数用于设置一个全局的日志掩码。掩码中的每一位对应一个日志优先级。如果设置了某个优先级对应的位，则该优先级的日志会被记录；否则，会被忽略。Bionic 的 `setlogmask` 会更新这个全局掩码。

* **`syslog(int __priority, const char* __fmt, ...)`:**
    1. **检查日志掩码:**  首先，它会检查当前的日志优先级 `__priority` 是否被 `setlogmask` 设置的掩码允许记录。
    2. **格式化消息:**  使用 `printf` 类似的机制，根据 `__fmt` 和后续的可变参数格式化生成最终的日志消息字符串。
    3. **获取标签:**  如果之前调用过 `openlog`，则使用设置的标签；否则，使用默认的标签（通常是进程名）。
    4. **调用底层 Android 日志写入函数:**  最终，`syslog` 会调用 Bionic libc 提供的 `__android_log_write(priority, tag, message)` 函数，将日志消息发送给 `logd` 守护进程。`logd` 负责将日志写入到不同的日志缓冲区（如 main, system, crash 等），并最终可以通过 `logcat` 工具查看。

* **`vsyslog(int __priority, const char* __fmt, va_list __args)`:**  与 `syslog` 类似，只是使用 `va_list` 来处理可变参数，内部实现逻辑与 `syslog` 大致相同。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**在这个 `syslog.handroid` 头文件中，并没有直接涉及 dynamic linker 的功能。**  这个头文件主要定义了 API 接口，而具体的函数实现是在 Bionic libc 的共享库 (`.so` 文件) 中。

当一个应用程序调用 `syslog` 函数时，这个调用会链接到 Bionic libc 的共享库。dynamic linker (在 Android 中是 `linker` 或 `linker64`) 负责在程序启动时加载必要的共享库，并解析符号引用，将 `syslog` 函数的调用指向 Bionic libc 中 `syslog` 函数的实际地址。

**`liblog.so` 的布局样本 (Simplified):**

虽然 `syslog` 的实现位于 `libc.so`，但 Android 实际的日志写入操作是由 `liblog.so` 提供的。我们可以看下 `liblog.so` 的一个简化布局：

```
liblog.so:
  .text:
    __android_log_write  (实际实现将日志写入到 logd)
    ... 其他日志相关的函数 ...
  .data:
    ... 全局变量 ...
  .dynamic:
    ... 动态链接信息 ...
  .symtab:
    __android_log_write (符号表项)
    ... 其他符号 ...
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序被编译时，编译器会记录下对 `syslog` 函数的外部引用。链接器会将这些引用指向 Bionic libc 共享库中的 `syslog` 符号。

2. **运行时链接:**
   * 当应用程序启动时，Android 的 dynamic linker (`linker`/`linker64`) 会被操作系统调用。
   * Dynamic linker 会加载应用程序依赖的共享库，包括 `libc.so` 和可能间接依赖的 `liblog.so`。
   * Dynamic linker 会解析应用程序中对 `syslog` 的未定义符号引用。它会在 `libc.so` 的符号表中查找 `syslog` 的地址。
   * Bionic libc 的 `syslog` 实现内部会调用 `liblog.so` 提供的 `__android_log_write` 函数。因此，dynamic linker 还需要确保 `libc.so` 能够找到 `__android_log_write` 的地址。这通常通过 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table) 机制实现。

**假设输入与输出 (针对 `syslog` 函数):**

**假设输入:**

```c
#include <syslog.h>

int main() {
  openlog("MyApp", 0, LOG_USER);
  syslog(LOG_INFO, "User activity: user logged in");
  closelog();
  return 0;
}
```

**预期输出 (通过 `logcat` 查看):**

```
I MyApp   : User activity: user logged in
```

* `I`: 表示日志级别为 INFO。
* `MyApp`: 是通过 `openlog` 设置的标签。
* `User activity: user logged in`: 是 `syslog` 函数格式化的消息。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用了错误的日志优先级:**  例如，将重要的错误信息用 `LOG_DEBUG` 记录，导致在生产环境中被过滤掉。

   ```c
   syslog(LOG_DEBUG, "An important error occurred!"); // 错误：应该使用 LOG_ERR 或更高优先级
   ```

2. **忘记调用 `openlog` 设置标签:**  如果不调用 `openlog`，默认会使用进程名作为标签，可能不够清晰。

3. **过度使用日志:**  在性能敏感的代码路径中记录过多的日志，会影响应用程序的性能。

4. **在循环中不恰当地使用 `openlog`:**  `openlog` 一般只需要调用一次，如果在循环中多次调用可能会导致不必要的开销。

5. **错误地假设 `openlog` 的 `option` 和 `facility` 参数在 Android 中有效:**  如前所述，大部分 `option` 和 `facility` 参数在 Android 中被忽略，开发者不应该依赖这些参数的行为。

6. **混淆了日志优先级的值:**  直接使用数字而不是使用预定义的宏（如 `LOG_INFO`），容易出错。

   ```c
   syslog(6, "This is an info message"); // 虽然也能工作，但不推荐，应该使用 LOG_INFO
   ```

7. **假设 `closelog` 会释放资源:** 在 Android 中，`closelog` 几乎不做任何事情，因此依赖它来释放资源是错误的。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `syslog` 的路径:**

1. **Android Framework (Java):**  应用程序通常使用 `android.util.Log` 类的方法来记录日志，例如 `Log.d()`, `Log.i()`, `Log.e()` 等。

2. **JNI 调用:** `android.util.Log` 的底层实现会通过 Java Native Interface (JNI) 调用到 Native 代码中的函数。具体来说，会调用到 `android_util_Log_println_native` 函数，这个函数位于 `libandroid_runtime.so` 中。

3. **`libandroid_runtime.so`:**  `android_util_Log_println_native` 函数会进一步调用到 `__android_log_write` 函数，这个函数位于 `liblog.so` 中。

4. **`liblog.so`:**  `__android_log_write` 函数负责将日志消息写入到 `logd` 守护进程。

**NDK 到 `syslog` 的路径:**

1. **NDK (C/C++):**  使用 NDK 开发的应用程序可以直接调用 Bionic libc 提供的 `syslog` 函数。

   ```c++
   #include <android/log.h> // 也可以使用 android 的 log 宏
   #include <syslog.h>

   void myNativeFunction() {
     syslog(LOG_INFO, "Native log message from NDK");
     __android_log_print(ANDROID_LOG_INFO, "MyTag", "Another native log message");
   }
   ```

2. **Bionic libc (`libc.so`):**  `syslog` 函数的实现位于 Bionic libc 中。

3. **`liblog.so` (间接):**  Bionic libc 的 `syslog` 实现内部会调用 `liblog.so` 提供的 `__android_log_write` 函数来完成实际的日志写入操作。

**Frida Hook 示例:**

以下是一些使用 Frida hook 这些步骤的示例：

**Hook `syslog` 函数:**

```javascript
if (Process.platform === 'android') {
  const syslog = Module.findExportByName("libc.so", "syslog");
  if (syslog) {
    Interceptor.attach(syslog, {
      onEnter: function (args) {
        const priority = args[0].toInt32();
        const format = Memory.readUtf8String(args[1]);
        console.log(`[syslog] Priority: ${priority}, Format: ${format}`);
        if (arguments.length > 2) {
          // 可以尝试解析可变参数，但这比较复杂
          console.log("[syslog] Has additional arguments");
        }
      },
      onLeave: function (retval) {
        // syslog 通常返回 void
      }
    });
  } else {
    console.log("Failed to find syslog");
  }
}
```

**Hook `openlog` 函数:**

```javascript
if (Process.platform === 'android') {
  const openlog = Module.findExportByName("libc.so", "openlog");
  if (openlog) {
    Interceptor.attach(openlog, {
      onEnter: function (args) {
        const prefix = args[0] ? Memory.readUtf8String(args[0]) : null;
        const option = args[1].toInt32();
        const facility = args[2].toInt32();
        console.log(`[openlog] Prefix: ${prefix}, Option: ${option}, Facility: ${facility}`);
      },
      onLeave: function (retval) {
        // openlog 返回 void
      }
    });
  } else {
    console.log("Failed to find openlog");
  }
}
```

**Hook `__android_log_write` 函数 (位于 `liblog.so`):**

```javascript
if (Process.platform === 'android') {
  const android_log_write = Module.findExportByName("liblog.so", "__android_log_write");
  if (android_log_write) {
    Interceptor.attach(android_log_write, {
      onEnter: function (args) {
        const prio = args[0].toInt32();
        const tag = Memory.readUtf8String(args[1]);
        const msg = Memory.readUtf8String(args[2]);
        console.log(`[__android_log_write] Priority: ${prio}, Tag: ${tag}, Message: ${msg}`);
      },
      onLeave: function (retval) {
        // __android_log_write 返回 int
        console.log(`[__android_log_write] Return value: ${retval}`);
      }
    });
  } else {
    console.log("Failed to find __android_log_write");
  }
}
```

**Hook `android_util_Log_println_native` 函数 (位于 `libandroid_runtime.so`):**

```javascript
if (Process.platform === 'android') {
  const println_native = Module.findExportByName("libandroid_runtime.so", "android_util_Log_println_native");
  if (println_native) {
    Interceptor.attach(println_native, {
      onEnter: function (args) {
        const priority = args[0].toInt32();
        const tag = Memory.readUtf8String(args[1]);
        const msg = Memory.readUtf8String(args[2]);
        console.log(`[android_util_Log_println_native] Priority: ${priority}, Tag: ${tag}, Message: ${msg}`);
      },
      onLeave: function (retval) {
        // println_native 返回 void
      }
    });
  } else {
    console.log("Failed to find android_util_Log_println_native");
  }
}
```

**使用 Frida 调试步骤:**

1. **编写 Frida 脚本:** 将上述 Hook 代码保存到一个 `.js` 文件中。
2. **连接到 Android 设备/模拟器:** 使用 `frida -U -f <package_name>` 或 `frida -H <host>:<port> <process_name>` 连接到目标应用程序。
3. **加载脚本:** 使用 `frida> .load your_script.js` 命令加载你的 Frida 脚本。
4. **触发日志记录:** 在应用程序中执行会产生日志的操作。
5. **查看 Frida 输出:** Frida 会在控制台输出 Hook 到的函数调用信息，包括参数值，从而帮助你追踪日志记录的流程。

通过这些 Frida Hook 示例，你可以深入了解 Android Framework 和 NDK 是如何一步步调用到 `syslog` 以及底层的日志写入函数的，从而更好地理解 Android 的日志机制。

### 提示词
```
这是目录为bionic/libc/include/syslog.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2008 The Android Open Source Project
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
/*
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#pragma once

#include <sys/cdefs.h>

#include <stdio.h>
#include <stdarg.h>

__BEGIN_DECLS

/** Corresponds to the Android ERROR log priority. */
#define LOG_EMERG 0
/** Corresponds to the Android ERROR log priority. */
#define LOG_ALERT 1
/** Corresponds to the Android ERROR log priority. */
#define LOG_CRIT 2
/** Corresponds to the Android ERROR log priority. */
#define LOG_ERR 3
/** Corresponds to the Android WARN log priority. */
#define LOG_WARNING 4
/** Corresponds to the Android INFO log priority. */
#define LOG_NOTICE 5
/** Corresponds to the Android INFO log priority. */
#define LOG_INFO 6
/** Corresponds to the Android DEBUG log priority. */
#define LOG_DEBUG 7

#define LOG_PRIMASK 7
#define LOG_PRI(x) ((x) & LOG_PRIMASK)
#define LOG_MAKEPRI(fac, pri) ((fac) | (pri))

/** Currently ignored on Android. */
#define LOG_KERN     (0<<3)
/** Currently ignored on Android. */
#define LOG_USER     (1<<3)
/** Currently ignored on Android. */
#define LOG_MAIL     (2<<3)
/** Currently ignored on Android. */
#define LOG_DAEMON   (3<<3)
/** Currently ignored on Android. */
#define LOG_AUTH     (4<<3)
/** Currently ignored on Android. */
#define LOG_SYSLOG   (5<<3)
/** Currently ignored on Android. */
#define LOG_LPR      (6<<3)
/** Currently ignored on Android. */
#define LOG_NEWS     (7<<3)
/** Currently ignored on Android. */
#define LOG_UUCP     (8<<3)
/** Currently ignored on Android. */
#define LOG_CRON     (9<<3)
/** Currently ignored on Android. */
#define LOG_AUTHPRIV (10<<3)
/** Currently ignored on Android. */
#define LOG_FTP      (11<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL0   (16<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL1   (17<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL2   (18<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL3   (19<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL4   (20<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL5   (21<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL6   (22<<3)
/** Currently ignored on Android. */
#define LOG_LOCAL7   (23<<3)

#define LOG_NFACILITIES 24
#define LOG_FACMASK 0x3f8
#define LOG_FAC(x) (((x) >> 3) & (LOG_FACMASK >> 3))

/**
 * Converts a log priority into a mask enabling that single priority,
 * for use with setlogmask().
 */
#define LOG_MASK(pri) (1 << (pri))

/**
 * Converts a log priority into a mask enabling that priority and all lower
 * priorities, for use with setlogmask().
 */
#define LOG_UPTO(pri) ((1 << ((pri)+1)) - 1)

/** openlog() option ignored on Android. */
#define LOG_PID    0x01
/** openlog() option ignored on Android. */
#define LOG_CONS   0x02
/** openlog() option ignored on Android. */
#define LOG_ODELAY 0x04
/** openlog() option ignored on Android. */
#define LOG_NDELAY 0x08
/** openlog() option ignored on Android. */
#define LOG_NOWAIT 0x10
/**
 * openlog() option to log to stderr as well as the system log.
 *
 * Available since API level 34 (ignored before then).
 */
#define LOG_PERROR 0x20

#if defined(SYSLOG_NAMES)
/** A mapping from name to value, used by `facilitynames` and `prioritynames`. */
typedef struct _code {
  char* c_name;
  int c_val;
} CODE;
/* A bogus facility value for "mark". */
#define INTERNAL_MARK LOG_MAKEPRI((LOG_NFACILITIES<<3), 0)
/** A table mapping facility names to values. */
static const CODE facilitynames[] = {
  { "auth", LOG_AUTH, },
  { "authpriv", LOG_AUTHPRIV, },
  { "cron", LOG_CRON, },
  { "daemon", LOG_DAEMON, },
  { "ftp", LOG_FTP, },
  { "kern", LOG_KERN, },
  { "lpr", LOG_LPR, },
  { "mail", LOG_MAIL, },
  { "mark", INTERNAL_MARK, },
  { "news", LOG_NEWS, },
  { "security", LOG_AUTH, },
  { "syslog", LOG_SYSLOG, },
  { "user", LOG_USER, },
  { "uucp", LOG_UUCP, },
  { "local0", LOG_LOCAL0, },
  { "local1", LOG_LOCAL1, },
  { "local2", LOG_LOCAL2, },
  { "local3", LOG_LOCAL3, },
  { "local4", LOG_LOCAL4, },
  { "local5", LOG_LOCAL5, },
  { "local6", LOG_LOCAL6, },
  { "local7", LOG_LOCAL7, },
  { NULL, -1, },
};
/* A bogus priority value for "none". */
#define INTERNAL_NOPRI 8
/** A table mapping priority names to values. */
static const CODE prioritynames[] = {
  { "alert", LOG_ALERT, },
  { "crit", LOG_CRIT, },
  { "debug", LOG_DEBUG, },
  { "emerg", LOG_EMERG, },
  { "err", LOG_ERR, },
  { "error", LOG_ERR, },
  { "info", LOG_INFO, },
  { "none", INTERNAL_NOPRI, },
  { "notice", LOG_NOTICE, },
  { "panic", LOG_EMERG, },
  { "warn", LOG_WARNING, },
  { "warning", LOG_WARNING, },
  { NULL, -1, },
};
#endif

/**
 * [closelog(3)](https://man7.org/linux/man-pages/man3/closelog.3.html) does
 * nothing on Android.
 */
void closelog(void);

/**
 * [openlog(3)](https://man7.org/linux/man-pages/man3/openlog.3.html) sets
 * the log tag to `__prefix`, which can be NULL to return to the default of
 * getprogname(). On Android, the other two arguments are ignored.
 */
void openlog(const char* _Nullable __prefix, int __option, int __facility);

/**
 * [setlogmask(3)](https://man7.org/linux/man-pages/man3/setlogmask.3.html)
 * sets which log priorities will actually be logged. See `LOG_MASK` and
 * `LOG_UPTO`.
 */
int setlogmask(int __mask);

/**
 * [syslog(3)](https://man7.org/linux/man-pages/man3/syslog.3.html) formats
 * the printf()-like message and logs it with the given priority, unless
 * suppressed by setlogmask(). On Android, the output goes to logcat.
 */
void syslog(int __priority, const char* _Nonnull __fmt, ...) __printflike(2, 3);

/**
 * [vsyslog(3)](https://man7.org/linux/man-pages/man3/vsyslog.3.html) formats
 * the vprintf()-like message and logs it with the given priority, unless
 * suppressed by setlogmask(). On Android, the output goes to logcat.
 */
void vsyslog(int __priority, const char* _Nonnull __fmt, va_list __args) __printflike(2, 0);

__END_DECLS
```