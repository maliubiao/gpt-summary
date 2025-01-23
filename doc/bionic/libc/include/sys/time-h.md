Response:
Let's break down the thought process for analyzing this `time.h` header file.

**1. Initial Understanding & Context:**

The first step is to grasp the fundamental nature of the file. The prompt clearly states it's `bionic/libc/include/sys/time.h`, part of Android's C library. The copyright notice confirms this. This immediately tells us it deals with time-related functionalities within the Android system.

**2. Identifying Core Functionalities (High-Level):**

Scan the header file for function declarations. The readily apparent functions are:

* `gettimeofday`:  Likely retrieves the current time.
* `settimeofday`:  Likely sets the system time.
* `getitimer`: Likely deals with interval timers.
* `setitimer`: Likely sets interval timers.
* `utimes`: Likely modifies file access and modification times.
* `futimes`, `lutimes`, `futimesat`:  Variations of `utimes`, potentially dealing with file descriptors and symbolic links.

**3. Analyzing Individual Functions (Detailed):**

For each function, consider:

* **Purpose:** Based on the name and parameters, infer the function's core task.
* **Parameters:**  What inputs does it take? What are their types?  Note the `_Nullable` and `_Nonnull` annotations, as they indicate nullability constraints.
* **Return Value:**  Usually an `int`, often indicating success (0) or failure (-1). The comment mentioning setting `errno` reinforces this.
* **Availability:** Pay attention to preprocessor directives like `#if defined(__USE_BSD)` and `#if defined(__USE_GNU)` and the `__INTRODUCED_IN(26)` macro. This highlights platform-specific features and API level dependencies.
* **Underlying System Calls:**  While not explicitly in the header, think about what system calls these functions likely wrap. `gettimeofday` and `settimeofday` likely map directly to syscalls with similar names. The `*times` functions probably use `utimensat` or related syscalls.

**4. Analyzing Macros:**

The header also defines several macros. Analyze their purpose:

* `timerclear`, `timerisset`, `timercmp`, `timeradd`, `timersub`: These clearly operate on `timeval` structures, providing convenient ways to manipulate time values.
* `TIMEVAL_TO_TIMESPEC`, `TIMESPEC_TO_TIMEVAL`: These perform conversions between `timeval` and `timespec` structures, highlighting the existence of both representations.

**5. Relating to Android Functionality:**

Now, connect these low-level functions to higher-level Android concepts:

* **System Time:**  `gettimeofday` and `settimeofday` are fundamental for Android's timekeeping. Mention how apps and the system use this. Note the security implications of `settimeofday`.
* **File Timestamps:**  The `*times` functions are crucial for file system operations, impacting caching, build processes, and file synchronization. Give examples.
* **Timers:** `getitimer` and `setitimer` are less commonly used directly in application code but are important for certain system-level tasks and potentially for older Android code.

**6. Dynamic Linker Aspects:**

Since the prompt mentions the dynamic linker, consider how this header is relevant:

* **Shared Libraries:** This header is part of `libc.so`, a core shared library. Explain that applications link against this library to access these functions.
* **Symbol Resolution:** The dynamic linker resolves the symbols (function names) declared in this header to their implementations in `libc.so`.
* **SO Layout:**  Provide a basic mental model of how `libc.so` is structured, including the `.text` (code) and `.data`/`.bss` (data) sections.

**7. Logic, Assumptions, and Error Handling:**

* **Assumptions:** When explaining function behavior, sometimes you need to make logical assumptions (e.g., `settimeofday` requires root privileges).
* **Error Handling:**  Mention that these functions can fail, and they typically set `errno`. Give examples of common errors (e.g., invalid pointers, permission issues).

**8. Usage in Android Framework/NDK:**

Trace the path from the Android framework down to these C library functions:

* **Framework:** High-level Java APIs (e.g., `System.currentTimeMillis()`, `File.setLastModified()`) are entry points.
* **JNI:** These Java APIs often call native methods via the Java Native Interface (JNI).
* **NDK:** NDK developers can directly use the functions declared in this header.
* **System Calls:** Ultimately, these C library functions make system calls to the Linux kernel.

**9. Frida Hooking Example:**

Provide a practical Frida script to demonstrate how to intercept calls to one of these functions (e.g., `gettimeofday`). This makes the explanation more concrete.

**10. Structure and Language:**

Organize the information logically with clear headings and subheadings. Use clear and concise Chinese. Explain technical terms where necessary. Address all parts of the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the historical context of BSD/GNU extensions.
* **Correction:**  While mentioning BSD/GNU is important, prioritize explaining the core functionality and its relevance to Android.
* **Initial thought:**  Go into extreme detail about the `timeval` and `timespec` structures.
* **Correction:**  Provide enough detail for understanding but avoid getting bogged down in low-level struct member descriptions unless directly relevant to a function's explanation.
* **Initial thought:**  Focus only on successful execution.
* **Correction:**  Remember to discuss error conditions and common mistakes.

By following these steps and continuously refining the approach, we can produce a comprehensive and accurate explanation of the `time.h` header file's functionalities within the Android ecosystem.
这个文件 `bionic/libc/include/sys/time.h` 是 Android Bionic C 库中定义时间相关功能的头文件。它声明了一些用于获取和设置系统时间、以及操作定时器的函数和宏。

**主要功能列表:**

1. **获取和设置系统时间:**
   - `gettimeofday()`: 获取当前时间和时区信息。
   - `settimeofday()`: 设置系统时间和时区信息（需要特权）。

2. **操作间隔定时器 (Interval Timers):**
   - `getitimer()`: 获取当前间隔定时器的设置。
   - `setitimer()`: 设置或修改间隔定时器。

3. **修改文件时间戳:**
   - `utimes()`: 修改指定路径文件的访问和修改时间。
   - `futimes()` (BSD 扩展): 修改指定文件描述符所指文件的访问和修改时间。
   - `lutimes()` (BSD 扩展): 修改指定符号链接自身的时间戳，而不是它指向的文件。
   - `futimesat()` (GNU 扩展): 类似于 `futimes`，但允许指定相对目录的文件描述符。

4. **时间结构体和宏:**
   - 定义了 `struct timeval` 和 `struct timezone` 结构体，用于表示时间和时区。
   - 定义了一些操作 `timeval` 结构体的宏，如 `timerclear`、`timerisset`、`timercmp`、`timeradd`、`timersub`，方便进行时间比较和运算。
   - 定义了 `TIMEVAL_TO_TIMESPEC` 和 `TIMESPEC_TO_TIMEVAL` 宏，用于在 `timeval` 和 `timespec` 结构体之间进行转换。

**与 Android 功能的关系及举例说明:**

这个头文件中声明的函数是 Android 系统底层时间管理的核心组成部分，被 Android Framework 和 NDK 中的许多组件使用。

* **系统时间:**
    - Android Framework 中的 `System.currentTimeMillis()` 方法最终会通过 JNI 调用到 `gettimeofday()` 来获取当前时间戳。
    - 系统服务（例如 `SystemServer`）可能会使用 `settimeofday()` 来同步系统时间（需要 `android.permission.SET_TIME` 权限）。
    - 例如，一个应用程序想要记录某个事件发生的时间，可以使用 `System.currentTimeMillis()`，这将最终调用到 `gettimeofday()`。

* **文件时间戳:**
    - 当在 Android 设备上创建、修改或访问文件时，系统会更新文件的访问时间、修改时间和状态改变时间。`utimes` 等函数就是用来操作这些时间戳的底层接口。
    - 例如，文件管理器应用显示文件的最后修改时间，其底层可能就用到了 `utimes` 或其变体。
    - 编译系统（如 `make` 或 Gradle 构建）会依赖文件时间戳来判断哪些文件需要重新编译。

* **定时器:**
    - Android 系统内部的某些组件可能会使用间隔定时器来周期性地执行任务。例如，`AlarmManager` 的某些底层实现可能使用了 `setitimer`。
    - 尽管在应用层开发中直接使用 `getitimer`/`setitimer` 较少见，但一些底层的系统服务或库可能会利用它们来实现定时功能。

**libc 函数的功能和实现:**

这些函数是 Bionic libc 提供的标准 C 库函数，它们的实现通常会涉及到系统调用。

1. **`gettimeofday(struct timeval* _Nullable __tv, struct timezone* _Nullable __tz)`:**
   - **功能:** 获取当前时间和时区信息。
   - **实现:**  这个函数会发起一个 `gettimeofday` 系统调用，由 Linux 内核返回当前的时间（自 Epoch 以来的秒数和微秒数）和时区信息。
   - **假设输入与输出:**
     - 假设调用时系统时间是 2023-10-27 10:00:00.123456 UTC，时区是 UTC+8。
     - 输入：`tv` 指向一个未初始化的 `struct timeval`，`tz` 指向一个未初始化的 `struct timezone`。
     - 输出：`tv->tv_sec` 将被设置为从 Epoch (1970-01-01 00:00:00 UTC) 到当前时间的秒数，`tv->tv_usec` 将被设置为微秒数（123456）。`tz->tz_minuteswest` 将被设置为 -480 (8 * 60)，`tz->tz_dsttime` 通常为 0。

2. **`settimeofday(const struct timeval* _Nullable __tv, const struct timezone* _Nullable __tz)`:**
   - **功能:** 设置系统时间和时区信息。
   - **实现:**  这个函数会发起一个 `settimeofday` 系统调用，通知内核更新系统时间。这是一个特权操作，需要 `CAP_SYS_TIME` 能力。
   - **假设输入与输出:**
     - 假设调用时 `tv->tv_sec` 和 `tv->tv_usec` 表示 2023-10-28 12:00:00.000000 UTC，`tz->tz_minuteswest` 为 -480。
     - 输入：`tv` 指向包含新时间的 `struct timeval`，`tz` 指向包含新时区的 `struct timezone`。
     - 输出：如果调用成功，系统时间将被设置为指定的时间和时区，返回 0。如果失败（例如，没有权限），返回 -1 并设置 `errno`。

3. **`getitimer(int __which, struct itimerval* _Nonnull __current_value)`:**
   - **功能:** 获取指定类型的间隔定时器的当前值。
   - **实现:** 这个函数会发起一个 `getitimer` 系统调用，获取指定定时器的当前值（包括间隔和到期时间）。
   - **参数 `__which`:**  可以是 `ITIMER_REAL` (实际流逝的时间), `ITIMER_VIRTUAL` (进程执行用户代码的时间), `ITIMER_PROF` (进程执行用户和内核代码的时间)。

4. **`setitimer(int __which, const struct itimerval* _Nonnull __new_value, struct itimerval* _Nullable __old_value)`:**
   - **功能:** 设置指定类型的间隔定时器。
   - **实现:** 这个函数会发起一个 `setitimer` 系统调用，设置或修改指定定时器的间隔和初始到期时间。当定时器到期时，会向进程发送一个信号。
   - **参数 `__which`:**  与 `getitimer` 相同。

5. **`utimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2])`:**
   - **功能:** 修改指定路径文件的访问和修改时间。
   - **实现:** 这个函数会发起一个 `utimes` 或 `utimensat` 系统调用。
     - 如果 `__times` 为 `NULL`，则将访问和修改时间设置为当前时间。
     - 如果 `__times` 指向一个包含两个 `struct timeval` 的数组，则第一个元素设置访问时间，第二个元素设置修改时间。
   - **假设输入与输出:**
     - 假设要修改文件 `/sdcard/test.txt` 的时间戳。
     - 输入：`__path` 指向字符串 "/sdcard/test.txt"，`__times` 指向一个数组 `[{1698400000, 0}, {1698400000, 0}]`（表示 2023-10-27）。
     - 输出：如果调用成功，文件 `/sdcard/test.txt` 的访问时间和修改时间将被设置为指定的时间戳，返回 0。如果失败（例如，文件不存在或没有权限），返回 -1 并设置 `errno`。

6. **`futimes(int __fd, const struct timeval __times[_Nullable 2])`:**
   - **功能:** 修改文件描述符所指文件的访问和修改时间。
   - **实现:** 类似于 `utimes`，但操作的是已打开的文件描述符，避免了路径查找的开销。会发起 `futimesat` 系统调用。

7. **`lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2])`:**
   - **功能:** 修改符号链接自身的时间戳。
   - **实现:**  与 `utimes` 类似，但会发起 `utimensat` 系统调用并带上 `AT_SYMLINK_NOFOLLOW` 标志，确保操作的是符号链接本身，而不是它指向的文件。

8. **`futimesat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, const struct timeval __times[_Nullable 2])`:**
   - **功能:** 相对于目录文件描述符修改文件时间戳。
   - **实现:**  会发起 `utimensat` 系统调用。`__dir_fd` 可以是一个目录的文件描述符，`__path` 是相对于该目录的路径。如果 `__path` 为 `NULL`，则 `__dir_fd` 必须是目录的文件描述符，并修改该目录的时间戳。

**涉及 dynamic linker 的功能：**

虽然 `sys/time.h` 本身是一个头文件，不包含可执行代码，但其中声明的函数（如 `gettimeofday`）的实现位于 Bionic libc (`libc.so`) 中，这涉及到动态链接。

**so 布局样本 (libc.so 的简化示意):**

```
libc.so:
    .text:  // 包含可执行代码
        gettimeofday: ... // gettimeofday 函数的实现代码
        settimeofday: ...
        utimes: ...
        ...

    .data:  // 包含已初始化的全局变量

    .bss:   // 包含未初始化的全局变量

    .dynsym: // 动态符号表，列出库中导出的符号
        gettimeofday
        settimeofday
        utimes
        ...

    .dynstr: // 动态字符串表，包含符号表中符号的名字

    .plt:   // 程序链接表，用于延迟绑定

    .got:   // 全局偏移表，存储外部符号的地址
```

**链接的处理过程:**

1. **编译时:** 当一个应用程序的代码中使用了 `gettimeofday` 等函数时，编译器会生成对这些函数的外部引用。
2. **链接时:** 链接器（在 Android 上通常是 `lld`）会将应用程序的目标文件与所需的共享库（如 `libc.so`) 链接在一起。链接器会记录应用程序对 `libc.so` 中符号的依赖。
3. **运行时:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载应用程序依赖的共享库。
4. **符号解析:** 动态链接器会解析应用程序中对 `gettimeofday` 等符号的引用，将其与 `libc.so` 中对应的函数地址关联起来。这通常通过查看 `libc.so` 的 `.dynsym` 和 `.dynstr` 表来完成。
5. **重定位:** 动态链接器会修改应用程序的 `.got` 表，使其指向 `libc.so` 中 `gettimeofday` 等函数的实际地址。
6. **延迟绑定 (Lazy Binding):** 默认情况下，为了提高启动速度，Android 使用延迟绑定。这意味着只有在第一次调用 `gettimeofday` 时，动态链接器才会真正解析和重定位这个符号。这通过 `.plt` 表来实现：
   - 第一次调用 `gettimeofday` 时，会跳转到 `.plt` 表中对应的条目。
   - `.plt` 条目会跳转到动态链接器的某个函数。
   - 动态链接器解析 `gettimeofday` 的地址，并更新 `.got` 表中对应的条目。
   - 随后对 `gettimeofday` 的调用将直接通过 `.got` 表跳转到函数的实际地址。

**逻辑推理的假设输入与输出 (以 `timeradd` 宏为例):**

`#define timeradd(a, b, res)`

* **假设输入:**
    - `a` 指向的 `timeval` 结构体包含 `tv_sec = 1`, `tv_usec = 500000`。
    - `b` 指向的 `timeval` 结构体包含 `tv_sec = 2`, `tv_usec = 750000`。
    - `res` 指向一个未初始化的 `timeval` 结构体。

* **输出:**
    - 执行 `timeradd(a, b, res)` 后，`res` 指向的 `timeval` 结构体将被设置为：
        - `res->tv_sec = 1 + 2 + 1 = 4` (因为微秒部分溢出)
        - `res->tv_usec = 500000 + 750000 - 1000000 = 250000`

**用户或编程常见的使用错误:**

1. **`settimeofday` 权限不足:**  普通应用程序调用 `settimeofday` 会失败，因为需要 `CAP_SYS_TIME` 能力。这通常发生在尝试在非 root 权限下设置系统时间。
   ```c
   #include <sys/time.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       struct timeval tv;
       tv.tv_sec = 1700000000; // 假设的新时间
       tv.tv_usec = 0;
       if (settimeofday(&tv, NULL) == -1) {
           perror("settimeofday failed"); // 输出类似 "settimeofday failed: Operation not permitted"
       }
       return 0;
   }
   ```

2. **`timeval` 结构体未初始化:**  在使用 `gettimeofday` 之前，确保 `struct timeval` 指针指向有效的内存。
   ```c
   #include <sys/time.h>
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       struct timeval *tv; // 未分配内存
       if (gettimeofday(tv, NULL) == 0) { // 错误：访问无效内存
           printf("Seconds: %ld, Microseconds: %ld\n", tv->tv_sec, tv->tv_usec);
       } else {
           perror("gettimeofday failed");
       }
       return 0;
   }
   ```
   **正确做法:**
   ```c
   #include <sys/time.h>
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       struct timeval tv; // 在栈上分配内存
       if (gettimeofday(&tv, NULL) == 0) {
           printf("Seconds: %ld, Microseconds: %ld\n", tv.tv_sec, tv.tv_usec);
       } else {
           perror("gettimeofday failed");
       }
       return 0;
   }
   ```

3. **错误地使用时间比较宏:**  例如，混淆大于和小于的比较。
   ```c
   #include <sys/time.h>
   #include <stdio.h>

   int main() {
       struct timeval t1 = {1, 0};
       struct timeval t2 = {0, 999999};
       if (timercmp(&t1, &t2, <)) { // 错误：t1 比 t2 大
           printf("t1 is earlier than t2\n");
       } else {
           printf("t1 is later than or equal to t2\n");
       }
       return 0;
   }
   ```

**Android Framework 或 NDK 如何一步步到达这里:**

以获取当前时间为例：

1. **Android Framework (Java):**  应用程序调用 `System.currentTimeMillis()` 或 `java.util.Date` 等 API。
2. **Java Native Interface (JNI):**  `System.currentTimeMillis()` 的实现最终会调用到 native 方法，通常在 `java.lang.System` 或相关类的 native 方法中。
3. **NDK (C/C++):**  Native 方法的实现代码使用 NDK 提供的接口，这些接口实际上是对 Bionic libc 函数的封装。例如，可能会直接调用 `gettimeofday()`。
   ```c++
   // Example in a native method implementation
   #include <jni.h>
   #include <sys/time.h>
   #include <android/log.h>

   extern "C" JNIEXPORT jlong JNICALL
   Java_com_example_myapp_MainActivity_getCurrentTimeMillis(JNIEnv *env, jobject /* this */) {
       struct timeval tv;
       if (gettimeofday(&tv, nullptr) == 0) {
           jlong millis = (jlong)tv.tv_sec * 1000 + (jlong)tv.tv_usec / 1000;
           return millis;
       } else {
           __android_log_print(ANDROID_LOG_ERROR, "MyApp", "gettimeofday failed");
           return -1; // 或抛出异常
       }
   }
   ```
4. **Bionic libc (`libc.so`):**  `gettimeofday()` 函数的实现位于 `libc.so` 中。
5. **Linux Kernel (System Call):**  `libc.so` 中的 `gettimeofday()` 函数会发起一个 `gettimeofday` 系统调用，请求内核提供当前时间。
6. **Kernel Response:** Linux 内核获取当前时间并将其返回给 `libc.so`。
7. **Return to NDK/JNI:**  `libc.so` 将时间返回给 native 方法。
8. **Return to Framework:**  Native 方法将时间转换成 Java 的 `long` 类型并返回给 Java Framework。

**Frida Hook 示例调试步骤:**

假设我们要 hook `gettimeofday` 函数，查看其被调用时的参数和返回值。

```javascript
// Frida 脚本

if (Process.platform === 'android') {
  const libc = Process.getModuleByName('libc.so');
  const gettimeofdayPtr = libc.getExportByName('gettimeofday');

  if (gettimeofdayPtr) {
    Interceptor.attach(gettimeofdayPtr, {
      onEnter: function (args) {
        console.log('[+] gettimeofday called');
        this.tv = args[0];
        this.tz = args[1];
        console.log('    tv: ' + this.tv);
        console.log('    tz: ' + this.tz);
      },
      onLeave: function (retval) {
        console.log('[+] gettimeofday returned: ' + retval);
        if (this.tv.isNull() === false) {
          const tv_sec = this.tv.readU64();
          const tv_usec = this.tv.add(8).readU64(); // 假设 timeval 结构体是 8 字节对齐
          console.log('    tv_sec: ' + tv_sec);
          console.log('    tv_usec: ' + tv_usec);
        }
        // 可以修改返回值或参数
      },
    });
    console.log('[+] Interceptor attached to gettimeofday');
  } else {
    console.log('[-] gettimeofday not found');
  }
} else {
  console.log('[!] This script is for Android.');
}
```

**调试步骤:**

1. **准备环境:** 确保已安装 Frida 和 adb，并且 Android 设备已 root 并开启 USB 调试。
2. **启动目标应用:** 运行你想要观察其时间调用的 Android 应用程序。
3. **运行 Frida 脚本:** 使用 Frida 连接到目标应用程序的进程，并加载上述 JavaScript 脚本。
   ```bash
   frida -U -f <包名> -l script.js --no-pause
   # 或者，如果应用已在运行
   frida -U <包名> -l script.js
   ```
4. **观察输出:** 当应用程序执行到调用 `gettimeofday` 的代码时，Frida 脚本会在控制台输出相关信息，包括进入函数时的参数（`timeval` 和 `timezone` 结构体的地址）和离开函数时的返回值。通过读取 `timeval` 结构体的内存，可以查看返回的时间值。

通过这个 Frida 示例，你可以实时监控 `gettimeofday` 的调用情况，验证应用程序如何使用这个底层的 Bionic libc 函数。你可以类似地 hook 其他时间相关的函数，例如 `settimeofday` 或 `utimes`，来调试和理解 Android 系统的时间管理机制。

### 提示词
```
这是目录为bionic/libc/include/sys/time.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _SYS_TIME_H_
#define _SYS_TIME_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <linux/time.h>

/* POSIX says <sys/time.h> gets you most of <sys/select.h> and may get you all of it. */
#include <sys/select.h>

__BEGIN_DECLS

int gettimeofday(struct timeval* _Nullable __tv, struct timezone* _Nullable __tz);
int settimeofday(const struct timeval* _Nullable __tv, const struct timezone* _Nullable __tz);

int getitimer(int __which, struct itimerval* _Nonnull __current_value);
int setitimer(int __which, const struct itimerval* _Nonnull __new_value, struct itimerval* _Nullable __old_value);

int utimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]);

#if defined(__USE_BSD)

#if __BIONIC_AVAILABILITY_GUARD(26)
int futimes(int __fd, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
int lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

#endif

#if defined(__USE_GNU)
/**
 * [futimesat(2)](https://man7.org/linux/man-pages/man2/futimesat.2.html) sets
 * file timestamps.
 *
 * Note: Linux supports `__path` being NULL (in which case `__dir_fd` need not
 * be a directory), allowing futimensat() to be implemented with utimensat().
 * Most callers should just use utimensat() directly, especially on Android
 * where utimensat() has been available for longer than futimesat().
 *
 * Returns 0 on success and -1 and sets `errno` on failure.
 *
 * Available since API level 26.
 */

#if __BIONIC_AVAILABILITY_GUARD(26)
int futimesat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

#endif

#define timerclear(a)   \
        ((a)->tv_sec = (a)->tv_usec = 0)

#define timerisset(a)    \
        ((a)->tv_sec != 0 || (a)->tv_usec != 0)

#define timercmp(a, b, op)               \
        ((a)->tv_sec == (b)->tv_sec      \
        ? (a)->tv_usec op (b)->tv_usec   \
        : (a)->tv_sec op (b)->tv_sec)

#define timeradd(a, b, res)                           \
    do {                                              \
        (res)->tv_sec  = (a)->tv_sec  + (b)->tv_sec;  \
        (res)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
        if ((res)->tv_usec >= 1000000) {              \
            (res)->tv_usec -= 1000000;                \
            (res)->tv_sec  += 1;                      \
        }                                             \
    } while (0)

#define timersub(a, b, res)                           \
    do {                                              \
        (res)->tv_sec  = (a)->tv_sec  - (b)->tv_sec;  \
        (res)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
        if ((res)->tv_usec < 0) {                     \
            (res)->tv_usec += 1000000;                \
            (res)->tv_sec  -= 1;                      \
        }                                             \
    } while (0)

#define TIMEVAL_TO_TIMESPEC(tv, ts) {     \
    (ts)->tv_sec = (tv)->tv_sec;          \
    (ts)->tv_nsec = (tv)->tv_usec * 1000; \
}
#define TIMESPEC_TO_TIMEVAL(tv, ts) {     \
    (tv)->tv_sec = (ts)->tv_sec;          \
    (tv)->tv_usec = (ts)->tv_nsec / 1000; \
}

__END_DECLS

#endif
```