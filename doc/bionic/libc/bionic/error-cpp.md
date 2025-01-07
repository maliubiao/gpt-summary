Response:
Let's break down the thought process to answer the user's request about `bionic/libc/bionic/error.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `error.cpp`, its relation to Android, implementation details of included libc functions, dynamic linker aspects (if any), common errors, and how Android frameworks reach this code, concluding with a Frida hook example.

**2. Initial Analysis of the Code:**

The first step is to read through the code provided. Key observations:

* **Primary Functions:** The file defines `error()` and `error_at_line()`. These seem to be the main entry points for error reporting.
* **Helper Functions:**  `__error_head()` and `__error_tail()` are internal helpers for common tasks.
* **Global Variables:**  `error_message_count`, `error_print_progname`, and `error_one_per_line` control error reporting behavior.
* **Dependencies:** Includes like `<error.h>`, `<errno.h>`, `<stdio.h>`, `<stdlib.h>`, and `<string.h>` indicate usage of standard C library functions related to error handling, I/O, and strings.

**3. Deconstructing the User's Questions (and planning the answer structure):**

It's helpful to directly address each point in the user's request:

* **Functionality:**  What does this code *do*?  The primary goal is to provide standardized error reporting with options for program name, file/line number, and conditional suppression of duplicate errors.
* **Android Relevance:** How is this used within the Android ecosystem?  This involves thinking about where errors are likely to occur in system libraries and applications.
* **libc Function Implementations:**  The code uses `fprintf`, `vfprintf`, `fflush`, `getprogname`, `strerror`, `putc`, `exit`, `va_start`, and `va_end`. The request specifically asks for *how* these are implemented. This will require referencing knowledge about standard C libraries (or looking up documentation if unsure).
* **Dynamic Linker:** Does this file directly involve the dynamic linker?  A careful scan shows no direct interaction with dynamic linking mechanisms like `dlopen`, `dlsym`, etc. The linking happens *before* this code is executed. The connection is that *other* bionic components that use dynamic linking might call these error functions when things go wrong during the linking process.
* **Logic and Assumptions:**  While the code itself isn't complex with elaborate logic, the `error_one_per_line` mechanism has a simple conditional. We can illustrate this with input/output examples.
* **Common Errors:** What mistakes do developers make when using these kinds of error reporting functions (even indirectly)?
* **Android Framework/NDK Path:**  How does a call from an app or framework eventually reach this code? This requires tracing the layers of abstraction in Android.
* **Frida Hook:** How can we use Frida to observe the execution of these functions?  This involves understanding Frida's basic hooking syntax.

**4. Answering Each Point (with self-correction and refinement):**

* **Functionality:**  Start with a concise summary, then elaborate on each global variable and function's role.
* **Android Relevance:** Think of examples. System calls failing, libraries encountering unexpected conditions, etc.
* **libc Function Implementations:**  For each function:
    * **`fprintf`:** Explain buffered output to a file stream.
    * **`vfprintf`:** Explain variable arguments and delegation to `fprintf`.
    * **`fflush`:** Explain forcing output.
    * **`getprogname`:** Explain retrieving the program name (implementation is OS-specific, note this).
    * **`strerror`:** Explain mapping error numbers to strings (implementation is OS-specific).
    * **`putc`:** Explain single character output.
    * **`exit`:** Explain process termination.
    * **`va_start` / `va_end`:** Explain variable argument handling.
* **Dynamic Linker:** Explicitly state that this file doesn't *directly* handle dynamic linking. Explain the indirect connection – linker errors might use these functions. Provide a simplified SO layout and explain the *linking* process conceptually (not the execution of these error functions themselves during linking).
* **Logic and Assumptions:**  Focus on `error_one_per_line`. Provide clear "before" and "after" scenarios to illustrate its behavior.
* **Common Errors:** Think about common mistakes: forgetting to check return values, not providing enough context in error messages, relying solely on error codes without good messages.
* **Android Framework/NDK Path:** Start high-level (App -> Framework) and gradually move towards the native layer. Mention JNI as the bridge. Give concrete examples of where these errors might originate (system services, native libraries).
* **Frida Hook:** Provide a basic example using `Interceptor.attach`. Focus on hooking the key functions (`error`, `error_at_line`) and logging arguments.

**5. Structuring the Answer and Adding Detail:**

Organize the answer logically, following the user's questions. Use headings and bullet points for clarity. Provide specific details and examples. Explain technical terms.

**6. Review and Refine:**

Read through the entire answer. Check for accuracy, clarity, and completeness. Ensure the language is accessible and addresses all parts of the user's request. For example, initially, I might have just said "strerror gets the error string," but a better explanation includes *how* it does that (mapping error numbers).

**Self-Correction Example During the Process:**

Initially, I might have thought about explaining the *dynamic linking process in detail*. However, realizing the `error.cpp` file itself doesn't *perform* dynamic linking, I shifted the focus to how errors *during* dynamic linking might *lead to* these error functions being called. This avoids going into unnecessary depth about the linker internals within the context of *this specific file*. The SO layout and linking explanation are provided to illustrate the context in which such errors might arise, not the inner workings of the error functions themselves.
好的，让我们详细分析 `bionic/libc/bionic/error.cpp` 这个文件。

**功能列举:**

`error.cpp` 文件定义了用于在 bionic C 库中报告错误的函数。它的主要功能包括：

1. **格式化错误消息:**  允许使用类似于 `printf` 的格式化字符串来创建错误消息。
2. **输出错误信息到标准错误流:** 将生成的错误消息输出到 `stderr`。
3. **包含错误代码信息:** 可以将 `errno` 值包含在错误消息中，提供更具体的错误原因。
4. **报告错误发生的文件和行号:** `error_at_line` 函数可以报告错误发生的代码位置，便于调试。
5. **控制程序退出:**  `error` 和 `error_at_line` 函数可以选择在报告错误后终止程序。
6. **控制是否打印程序名:**  可以通过 `error_print_progname` 回调函数控制是否在错误消息前打印程序名。
7. **控制是否每行只报告一次错误:**  `error_one_per_line` 变量可以用于抑制在同一文件和行号上重复报告相同的错误。
8. **统计错误消息数量:** 使用 `error_message_count` 记录已报告的错误消息数量。

**与 Android 功能的关系及举例说明:**

`error.cpp` 是 Android Bionic C 库的一部分，Bionic 是 Android 系统最底层的库之一，几乎所有的 Android 组件，包括 Framework 和 NDK 开发的应用，都会直接或间接地使用到它。因此，`error.cpp` 中定义的错误报告机制在整个 Android 系统中被广泛使用。

**举例说明:**

* **系统调用失败:** 当 Android 系统中的代码执行一个系统调用（例如 `open`, `read`, `write`）失败时，通常会设置全局变量 `errno` 来指示错误类型。然后，Bionic 库中的其他函数可能会调用 `error` 或 `error_at_line` 来报告这个错误。例如，`open()` 系统调用失败时，`libc` 中封装 `open()` 的函数可能会这样使用 `error`:
  ```c
  #include <fcntl.h>
  #include <stdio.h>
  #include <errno.h>
  #include <string.h>
  #include <bionic/error.h> // 假设需要直接使用 error.h

  int my_open(const char *pathname, int flags) {
    int fd = open(pathname, flags);
    if (fd == -1) {
      error(1, errno, "Failed to open file: %s", pathname); // 报告错误并退出
    }
    return fd;
  }
  ```
  在这个例子中，如果 `open()` 调用失败，`error(1, errno, ...)` 将会被调用，它会打印包含程序名、错误消息以及 `errno` 对应的错误描述到 `stderr`，并且因为 `status` 为 1，程序会退出。

* **NDK 应用错误报告:**  NDK 开发的应用可以直接使用 Bionic 提供的这些错误报告函数。当 NDK 应用中的 C/C++ 代码发生错误时，可以使用 `error` 或 `error_at_line` 将错误信息输出到 logcat 中（因为 `stderr` 通常会被重定向到 logcat）。

* **Framework 中的错误处理:** Android Framework (使用 Java 和 C++ 编写) 的底层很多部分也是基于 Native 代码实现的。当 Framework 中的 Native 代码遇到错误时，也会使用类似的错误报告机制。虽然 Framework 通常会捕获并处理这些错误，但在开发和调试阶段，这些错误信息会很有用。

**libc 函数的功能实现:**

让我们详细解释一下 `error.cpp` 中使用的 libc 函数：

* **`fprintf(stderr, fmt, ...)` 和 `vfprintf(stderr, fmt, va_list ap)`:**
    * **功能:** 这两个函数都用于格式化输出数据到指定的文件流。`fprintf` 接受可变数量的参数，而 `vfprintf` 接受一个 `va_list` 类型的参数，通常用于在可变参数函数内部调用。
    * **实现:**  这两个函数是 C 标准库中用于格式化输出的核心函数。它们的实现涉及解析格式化字符串 (`fmt`)，然后根据格式说明符（如 `%d`, `%s`, `%x` 等）从后续的参数列表中提取数据，并将其转换为字符串形式写入到 `stderr` 文件流。这通常涉及到缓冲区管理、类型转换和字符串操作等底层实现。
* **`fflush(stderr)`:**
    * **功能:** 将缓冲区中未写入的数据强制刷新到文件流。对于 `stderr` 来说，通常是非缓冲的，但调用 `fflush` 可以确保任何缓冲的数据立即被写入。
    * **实现:** 对于缓冲的文件流，`fflush` 会调用底层的操作系统 API（如 `write` 系统调用）将缓冲区中的数据写入到文件描述符对应的文件或设备。对于非缓冲的流，`fflush` 可能不做任何操作或者只更新内部状态。
* **`getprogname()`:**
    * **功能:** 返回当前程序的名称。
    * **实现:**  Bionic 中 `getprogname()` 的实现通常会读取存储程序名称的全局变量。这个全局变量可能在程序启动时由动态链接器或启动代码设置。不同的操作系统和 C 库可能有不同的实现方式来获取程序名称。
* **`strerror(error)`:**
    * **功能:**  将给定的错误码 (`error`) 转换为对应的错误描述字符串。
    * **实现:**  `strerror` 通常使用一个静态的错误码到错误消息的映射表。当传入一个错误码时，它会在这个表中查找对应的错误消息字符串并返回。这个映射表的内容是平台相关的，定义了各种可能的错误及其描述。
* **`putc('\n', stderr)`:**
    * **功能:** 将一个字符（这里是换行符 `\n`）写入到指定的文件流 (`stderr`)。
    * **实现:** `putc` 通常是 `fputc` 的宏定义或内联函数。它会将字符放入 `stderr` 的输出缓冲区（如果存在），或者直接调用底层的操作系统 API 将字符写入到文件描述符。
* **`exit(status)`:**
    * **功能:** 终止当前程序的执行，并将状态码 `status` 返回给操作系统。
    * **实现:** `exit` 函数会执行一系列清理操作，包括调用通过 `atexit` 注册的函数、刷新所有打开的输出流的缓冲区，然后调用底层的操作系统 API（如 `_exit` 系统调用）来终止进程。
* **`va_start(ap, fmt)` 和 `va_end(ap)`:**
    * **功能:** 用于在可变参数函数中访问和处理可变数量的参数。 `va_start` 初始化一个 `va_list` 类型的变量 `ap`，使其指向 `fmt` 参数之后的第一个可变参数。 `va_end` 用于清理 `va_list` 变量。
    * **实现:** 这涉及到平台相关的汇编代码操作来获取参数在栈上的地址。`va_start` 通常会根据 `fmt` 参数的位置计算出第一个可变参数的地址。 `va_end` 主要用于标记 `va_list` 的使用结束，可能在某些架构上需要进行一些清理工作。

**涉及 dynamic linker 的功能:**

`error.cpp` 本身并不直接处理 dynamic linker 的功能。它的主要作用是报告错误，而 dynamic linker (在 Android 中是 `linker64` 或 `linker`) 是负责加载和链接共享库的组件。

然而，`error.cpp` 中定义的函数可能会被 dynamic linker 在链接过程中遇到错误时调用。例如，当 dynamic linker 无法找到所需的共享库、符号未定义、或者发生其他链接错误时，它可能会使用类似 `error` 的机制来报告这些错误。

**so 布局样本及链接的处理过程 (以 dynamic linker 可能报告的错误为例):**

假设我们有两个共享库 `libA.so` 和 `libB.so`，`libB.so` 依赖于 `libA.so`，并且 `libB.so` 中使用了 `libA.so` 中定义的函数 `foo`。

**`libA.so` 布局样本:**

```
libA.so:
    .text         # 代码段
        foo:     # 函数 foo 的代码
            ...
    .rodata       # 只读数据段
    .data         # 可读写数据段
    .dynamic      # 动态链接信息
        SONAME: libA.so
        NEEDED:
        SYMTAB:  # 符号表
            foo (global, function)
            ...
```

**`libB.so` 布局样本:**

```
libB.so:
    .text         # 代码段
        bar:     # 函数 bar 的代码，调用了 foo
            ...
            call foo
            ...
    .rodata       # 只读数据段
    .data         # 可读写数据段
    .dynamic      # 动态链接信息
        SONAME: libB.so
        NEEDED: libA.so  # 依赖于 libA.so
        SYMTAB:  # 符号表
            bar (global, function)
            ...
```

**链接的处理过程 (可能导致 `error` 调用的情况):**

1. **加载 `libB.so`:** 当程序需要使用 `libB.so` 时，dynamic linker 会首先加载 `libB.so` 到内存中。
2. **解析依赖关系:** dynamic linker 会读取 `libB.so` 的 `.dynamic` 段，找到 `NEEDED` 条目，发现 `libB.so` 依赖于 `libA.so`。
3. **加载 `libA.so`:** dynamic linker 尝试加载 `libA.so`。如果 `libA.so` 在系统库路径中找不到，dynamic linker 可能会调用一个错误报告函数（类似于 `error`）来报告 "cannot find library libA.so"。
4. **符号解析:** 如果 `libA.so` 成功加载，dynamic linker 会解析 `libB.so` 中对 `libA.so` 中符号的引用。例如，在 `libB.so` 的 `bar` 函数中调用了 `foo`。dynamic linker 会在 `libA.so` 的符号表 (`SYMTAB`) 中查找 `foo` 的地址。
5. **链接错误:** 如果 `libA.so` 中没有定义名为 `foo` 的全局符号，或者符号类型不匹配，dynamic linker 可能会调用一个错误报告函数来报告 "undefined symbol foo in libB.so"。

**假设输入与输出 (针对 `error_one_per_line`):**

假设我们多次调用 `error_at_line`，且 `error_one_per_line` 设置为非零值 (例如 1)：

**假设输入:**

```c
error_one_per_line = 1;

error_at_line(0, 0, "myfile.c", 10, "Error message 1");
error_at_line(0, 0, "myfile.c", 10, "Error message 1"); // 相同的 文件和行号
error_at_line(0, 0, "myfile.c", 11, "Error message 2"); // 不同的行号
error_at_line(0, 0, "anotherfile.c", 10, "Error message 3"); // 不同的文件
```

**预期输出 (到 stderr):**

```
myfile.c:10: Error message 1
myfile.c:11: Error message 2
anotherfile.c:10: Error message 3
```

可以看到，在相同的文件和行号上的重复错误消息被抑制了。

**用户或编程常见的使用错误:**

1. **忘记检查返回值并报告错误:**  很多函数调用可能会失败，但开发者可能忘记检查返回值（例如，系统调用返回 -1）并使用 `errno` 来报告错误。
   ```c
   FILE *fp = fopen("nonexistent.txt", "r");
   if (fp == NULL) {
       // 应该报告错误
       perror("Failed to open file"); // 或者使用 error 函数
   }
   ```

2. **提供不准确或不清晰的错误消息:**  错误消息应该足够清晰，能够帮助开发者快速定位问题。像 "Something went wrong" 这样的消息就过于笼统。

3. **在不应该退出的情况下调用 `error` 并设置非零状态码:**  `error` 函数的 `status` 参数如果非零，会导致程序退出。开发者应该根据错误的严重程度来决定是否终止程序。

4. **过度依赖错误码，而忽略了提供上下文信息:**  虽然错误码很有用，但仅仅提供错误码可能不足以诊断问题。错误消息应该包含与错误相关的上下文信息，例如文件名、操作类型等。

5. **在多线程环境中使用全局的 `errno` 而不加保护:**  `errno` 是线程局部存储的，但在某些情况下，如果跨线程传递错误码，可能会出现问题。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 应用调用 libc 函数:**  NDK 应用中的 C/C++ 代码可以直接调用 Bionic 提供的 libc 函数，这些函数在遇到错误时可能会调用 `error` 或 `error_at_line`。例如，调用 `open()` 失败会间接走到这里。

2. **Framework Native 代码:** Android Framework 的很多核心功能是由 C++ 实现的，这些 Native 代码在遇到错误时也会使用 Bionic 提供的错误报告机制。例如，在 SurfaceFlinger 或 MediaCodec 等组件的实现中。

3. **JNI 调用:** Java 代码通过 JNI (Java Native Interface) 调用 Native 代码时，如果 Native 代码执行出错，可能会通过 `error` 等函数报告错误。这些错误通常会被记录到 logcat 中。

**一步步的路径示例 (从 Framework 到 `error.cpp`):**

假设一个 Java 应用尝试打开一个不存在的文件，最终触发了 `error.cpp` 中的代码：

1. **Java 代码:**
   ```java
   try {
       FileInputStream fis = new FileInputStream("/sdcard/nonexistent.txt");
   } catch (FileNotFoundException e) {
       Log.e("MyApp", "File not found", e);
   }
   ```

2. **Framework `FileInputStream`:** `FileInputStream` 的底层实现会调用 Native 代码来执行文件操作。

3. **Native 代码 (libjavacrypto.so 或类似的库):**  这个 Native 代码会调用 Bionic 的 `open()` 函数。

4. **Bionic `open()` 实现:** `open()` 系统调用失败，设置 `errno` 为 `ENOENT` (No such file or directory)。

5. **Bionic 封装的 `open()` 函数 (例如在 `bionic/libc/bionic/syscalls.c` 或其他相关文件中):**  这个封装函数会检查 `open()` 的返回值，如果失败，可能会调用 `error` 或类似的函数来报告错误。

6. **`error.cpp`:**  `error` 或 `error_at_line` 函数被调用，将错误信息输出到 `stderr` (最终会出现在 logcat 中)。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `error` 函数的示例：

```javascript
if (Java.available) {
    Java.perform(function() {
        var error = Module.findExportByName("libc.so", "error");
        if (error) {
            Interceptor.attach(error, {
                onEnter: function(args) {
                    var status = args[0].toInt32();
                    var err = args[1].toInt32();
                    var fmt = Memory.readCString(args[2]);
                    var formatted_string = fmt;
                    if (arguments.length > 3) {
                        try {
                            formatted_string = vsprintf(fmt, args.slice(3));
                        } catch (e) {
                            formatted_string = "Error formatting string: " + fmt;
                        }
                    }

                    console.log("--- error() called ---");
                    console.log("Status: " + status);
                    console.log("Errno: " + err + " (" + getErrnoString(err) + ")");
                    console.log("Format: " + fmt);
                    console.log("Message: " + formatted_string);
                    // 可以选择修改参数或阻止执行
                    // args[0] = ptr(0); // 例如，阻止程序退出
                },
                onLeave: function(retval) {
                    // 可选：在函数返回后执行
                }
            });
        } else {
            console.log("Could not find error function in libc.so");
        }

        function getErrnoString(err) {
            var strerror = Module.findExportByName("libc.so", "strerror");
            if (strerror) {
                return Memory.readCString(Module.invokeStdcall(strerror, [err]));
            }
            return "Unknown error";
        }

        // 模拟 vsprintf (简化的实现)
        function vsprintf(fmt, args) {
            var formatted = fmt;
            for (var i = 0; i < args.length; i++) {
                var arg = args[i];
                var replacement = "";
                if (fmt.includes("%d") || fmt.includes("%i")) {
                    replacement = arg.toInt32();
                    formatted = formatted.replace(/%d|%i/, replacement);
                } else if (fmt.includes("%s")) {
                    replacement = Memory.readCString(arg);
                    formatted = formatted.replace("%s", replacement);
                } else if (fmt.includes("%x")) {
                    replacement = arg.toInt32().toString(16);
                    formatted = formatted.replace("%x", replacement);
                }
                // ... 其他格式说明符
            }
            return formatted;
        }
    });
} else {
    console.log("Java is not available.");
}
```

**代码解释:**

1. **`Java.available` 和 `Java.perform`:**  Frida 的 Java API，用于在 Android 进程中执行代码。
2. **`Module.findExportByName("libc.so", "error")`:**  在 `libc.so` 中查找 `error` 函数的地址。
3. **`Interceptor.attach(error, ...)`:**  Hook `error` 函数。
4. **`onEnter`:**  在 `error` 函数执行之前被调用。
5. **`args`:**  包含了传递给 `error` 函数的参数。
6. **读取参数:**  从 `args` 中读取 `status`, `error` 代码, 和格式化字符串。
7. **格式化字符串:**  尝试使用一个简化的 `vsprintf` 函数来格式化错误消息。
8. **输出信息:**  将捕获到的信息输出到 Frida 的控制台。
9. **`getErrnoString`:**  使用 `strerror` 获取错误码对应的字符串描述。
10. **`vsprintf` (简化):**  一个简单的 `vsprintf` 实现，用于格式化错误消息。实际的 `vsprintf` 实现更复杂。

这个 Frida 脚本可以在目标 Android 应用运行时注入，并拦截对 `error` 函数的调用，打印出详细的错误信息，有助于调试和理解错误发生的上下文。对于 `error_at_line` 函数，可以使用类似的方法进行 Hook。

希望这个详尽的解答能够帮助你理解 `bionic/libc/bionic/error.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/error.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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

#include <error.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int error_message_count = 0;
void (*error_print_progname)(void) = nullptr;
int error_one_per_line = 0;

static void __error_head() {
  ++error_message_count;

  if (error_print_progname != nullptr) {
    error_print_progname();
  } else {
    fflush(stdout);
    fprintf(stderr, "%s:", getprogname());
  }
}

static void __error_tail(int status, int error) {
  if (error != 0) {
    fprintf(stderr, ": %s", strerror(error));
  }

  putc('\n', stderr);
  fflush(stderr);

  if (status != 0) {
    exit(status);
  }
}

void error(int status, int error, const char* fmt, ...) {
  __error_head();
  putc(' ', stderr);

  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  __error_tail(status, error);
}

void error_at_line(int status, int error, const char* file, unsigned int line, const char* fmt, ...) {
  if (error_one_per_line) {
    static const char* last_file;
    static unsigned int last_line;
    if (last_line == line && last_file != nullptr && strcmp(last_file, file) == 0) {
      return;
    }
    last_file = file;
    last_line = line;
  }

  __error_head();
  fprintf(stderr, "%s:%d: ", file, line);

  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  __error_tail(status, error);
}

"""

```