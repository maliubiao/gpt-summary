Response:
Let's break down the thought process to generate the comprehensive answer.

1. **Understanding the Core Question:** The fundamental task is to analyze the provided C header file (`bionic_errdefs.handroid`) and explain its purpose, relationships to Android, implementation details (even though it's just definitions), dynamic linking aspects (despite the file not directly being involved), common errors, and how to debug its usage.

2. **Initial Analysis of the File:**  The first thing that jumps out is the repeating pattern `__BIONIC_ERRDEF(error_code, "error message")`. This strongly suggests that the file defines error codes and their corresponding textual descriptions. The `#ifndef __BIONIC_ERRDEF` and `#error __BIONIC_ERRDEF not defined` block indicate that this file is meant to be included after another file defines the `__BIONIC_ERRDEF` macro. This is a crucial point for understanding its function.

3. **Identifying Key Concepts:**  From the initial analysis, the key concepts are:
    * **Error Codes:** Numerical representations of different error conditions.
    * **Error Messages:** Human-readable descriptions of those error conditions.
    * **`errno`:**  The standard C library variable that stores the last error code.
    * **System Calls:** The primary source of these error codes.
    * **Android Bionic:** The C library this file belongs to.
    * **Dynamic Linking (Indirectly):**  While this file doesn't *perform* dynamic linking, the errors it defines can arise from dynamic linking failures.

4. **Structuring the Answer:**  A logical flow for the answer would be:
    * **Overall Function:** What does this file *do*?
    * **Relationship to Android:** How does this relate to the bigger picture?
    * **Implementation (of the definitions):** How are these errors used?
    * **Dynamic Linking Aspects:** Address the dynamic linker connection (even if it's indirect).
    * **Logic Inference (Minimal):**  While this file isn't heavy on logic, it's important to consider the *flow* of error reporting.
    * **Common Errors:** How might a programmer misuse or encounter these errors?
    * **Android Framework/NDK Integration:** How do you end up interacting with these errors?
    * **Frida Hooking:** How to debug this.

5. **Elaborating on Each Section:**

    * **Function:** Clearly state that it defines error codes and their names. Emphasize its role in the broader error handling mechanism.

    * **Android Relationship:** Explain that Bionic is Android's libc. Give *concrete examples* of how these errors manifest in Android (file I/O, network, memory allocation). Mention `errno`.

    * **Implementation:** Since it's macro-based, the "implementation" is about how these definitions are *used*. Explain that another file defines `__BIONIC_ERRDEF` to create either `#define` constants or entries in an error table. Mention the standard C library functions like `perror` and `strerror` that utilize these definitions.

    * **Dynamic Linking:** This requires careful phrasing. This file *doesn't do dynamic linking*, but dynamic linking *can result in some of these errors*. Provide specific examples like `ELIBACC`, `ELIBBAD`, etc. Create a simple `so` layout example and outline the linking process (finding symbols, resolving addresses).

    * **Logic Inference:** Focus on the *path* of an error. A system call fails, sets `errno`, and user-space code checks `errno`. Give a simple example using `open()`.

    * **Common Errors:** Provide practical coding mistakes that lead to these errors (e.g., trying to open a non-existent file, not checking return values, permission issues).

    * **Android Framework/NDK:** Trace the path from Java (framework) or C/C++ (NDK) down to the underlying system calls where these errors originate. Give examples of framework APIs (like `FileInputStream`) and NDK functions (`open()`).

    * **Frida Hooking:**  Provide a clear and functional Frida example. Hook a system call like `open()` and demonstrate how to print the `errno` value. Explain the different ways to hook (address, symbol).

6. **Refinement and Language:**  Use clear and concise language. Avoid overly technical jargon where possible. Provide code examples to illustrate concepts. Use formatting (bolding, bullet points) to improve readability. Ensure the answer directly addresses all parts of the prompt.

7. **Self-Correction/Improvements during the process:**

    * **Initial thought:** Maybe I should explain how the kernel sets these errors. **Correction:** The prompt focuses on the user-space perspective and Bionic. Keep the kernel explanation brief and focus on its role in setting `errno`.
    * **Initial thought:** Go deep into the dynamic linker implementation. **Correction:** The file itself isn't about *implementing* the dynamic linker. Focus on *how errors from dynamic linking are represented* by these codes.
    * **Initial thought:**  Just list the error codes. **Correction:** The prompt asks for explanations, examples, and context. Elaborate on the *meaning* and *use* of each part.
    * **Ensure all parts of the prompt are answered:** Double-check if all questions about functions, dynamic linking, errors, and debugging are covered.

By following these steps, incorporating self-correction, and focusing on providing clear, practical explanations, we arrive at the comprehensive answer provided previously.
## 对 `bionic/libc/private/bionic_errdefs.handroid` 源代码文件的分析

这个文件 `bionic/libc/private/bionic_errdefs.handroid` 是 Android Bionic C 库的一部分，主要功能是 **定义标准 POSIX 错误码及其对应的文本描述**。它本身不包含任何可执行代码或复杂的逻辑，而是一个头文件，用于在 Bionic 的其他部分以及最终编译的 Android 系统中使用。

**功能列表:**

1. **定义错误码常量:**  它使用宏 `__BIONIC_ERRDEF` 来定义一系列代表不同错误情况的常量，例如 `EPERM`、`ENOENT`、`EINVAL` 等。这些常量通常是整数值。
2. **提供错误码的文本描述:**  `__BIONIC_ERRDEF` 宏同时也关联了每个错误码的文本描述，例如 "Operation not permitted"、"No such file or directory" 等。这些描述用于向用户或开发者提供更清晰的错误信息。
3. **作为标准错误码的来源:**  这个文件是 Android Bionic 中定义和管理标准 POSIX 错误码的主要来源。其他 Bionic 组件和上层应用会引用这些定义。
4. **提高代码可读性和维护性:**  使用符号常量（如 `EPERM`）而不是直接使用数字（如 `1`）来表示错误码，可以使代码更易于理解和维护。

**与 Android 功能的关系及举例说明:**

这个文件直接影响着 Android 系统中各种功能的错误报告机制。当系统调用或其他底层操作失败时，它们会返回一个负数，并将相应的错误码设置到全局变量 `errno` 中。  这个文件定义的常量就是 `errno` 可能取的值。

**举例说明:**

* **文件操作:** 当应用尝试打开一个不存在的文件时，`open()` 系统调用会失败，并将 `errno` 设置为 `ENOENT` (No such file or directory)。Bionic 库中的相关函数（如 `fopen`）会捕获这个错误，并可能向上层 Java Framework 抛出一个 `FileNotFoundException` 异常，其中包含了 "No such file or directory" 这样的描述信息。
* **网络操作:** 当网络连接失败时，socket 相关的系统调用可能会将 `errno` 设置为 `ECONNREFUSED` (Connection refused) 或 `ETIMEDOUT` (Connection timed out)。Android Framework 中的网络库（如 `java.net` 包）会根据这些错误码生成相应的异常信息。
* **权限管理:** 如果应用尝试执行一个没有权限的操作，系统调用会返回失败，并将 `errno` 设置为 `EACCES` (Permission denied)。Android 的权限管理机制会利用这些错误码来判断是否允许应用执行特定的操作。

**详细解释 libc 函数的功能是如何实现的:**

这个文件本身 **不包含任何 libc 函数的实现**。它仅仅定义了错误码常量和描述。libc 函数的实现通常位于其他的 `.c` 或 `.S` 文件中。

然而，这个文件中定义的错误码被 libc 函数广泛使用。例如，`open()` 函数的实现可能会如下所示（简化版）：

```c
// 假设的 open() 函数实现片段
int open(const char *pathname, int flags, ...) {
  // ... 一些参数检查和处理 ...
  int fd = syscall(__NR_openat, AT_FDCWD, pathname, flags, mode); // 调用内核系统调用
  if (fd < 0) {
    // 系统调用失败，内核已经设置了 errno
    return -1;
  }
  return fd;
}
```

当 `syscall(__NR_openat, ...)` 返回负数时，意味着内核操作失败，并且内核已经根据失败的原因设置了 `errno` 的值（例如 `ENOENT`）。上层的 libc 函数会将这个错误传递给调用者。

libc 中的 `perror()` 和 `strerror()` 函数会使用这些定义的错误码来生成错误消息：

* **`perror(const char *s)`:**  打印由 `s` 指向的字符串，后跟一个冒号，一个空格，以及当前 `errno` 值的文本描述（从这个文件中获取）。
* **`strerror(int errnum)`:** 返回指向与错误码 `errnum` 对应的错误描述字符串的指针。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个文件本身 **不直接涉及 dynamic linker 的具体功能**。但是，在动态链接过程中可能会出现一些与权限、文件访问等相关的错误，这些错误会体现在这里定义的错误码中，例如：

* **`ELIBACC` (Can not access a needed shared library):**  动态链接器无法访问需要的共享库文件。
* **`ELIBBAD` (Accessing a corrupted shared library):** 动态链接器发现共享库文件已损坏。
* **`ENOENT` (No such file or directory):** 动态链接器找不到指定的共享库文件。

**so 布局样本:**

假设我们有一个应用程序 `app` 链接了两个共享库 `liba.so` 和 `libb.so`。

```
/system/bin/app
/system/lib64/liba.so
/vendor/lib64/libb.so
```

**链接的处理过程 (简化描述):**

1. **加载可执行文件:** 当系统启动 `app` 时，内核会将 `app` 的代码和数据加载到内存中。
2. **查找依赖的共享库:**  `app` 的 ELF 头中包含了它依赖的共享库列表（`liba.so` 和 `libb.so`）。动态链接器（`linker64` 或 `linker`）会根据预定义的路径（如 `/system/lib64`, `/vendor/lib64` 等）查找这些共享库。
3. **加载共享库:**  如果找到共享库，动态链接器会将其加载到内存中。
4. **符号解析 (Symbol Resolution):** `app` 和其依赖的共享库之间可能存在函数调用和数据访问。动态链接器会解析这些符号引用，将 `app` 中调用的 `liba.so` 中的函数地址，以及 `app` 中使用的 `libb.so` 中的全局变量地址确定下来。
5. **重定位 (Relocation):**  由于共享库加载到内存中的地址可能每次都不同，动态链接器需要修改 `app` 和共享库中的某些指令和数据，使其指向正确的内存地址。

**在这个过程中，如果发生错误，可能会设置相关的错误码:**

* **找不到共享库:** 如果动态链接器在指定的路径中找不到 `liba.so` 或 `libb.so`，`errno` 可能会被设置为 `ENOENT`，导致应用启动失败。
* **权限问题:** 如果动态链接器没有读取 `liba.so` 或 `libb.so` 的权限，`errno` 可能会被设置为 `EACCES`。
* **共享库损坏:** 如果动态链接器检测到 `liba.so` 或 `libb.so` 文件格式错误或损坏，`errno` 可能会被设置为 `ELIBBAD`.

**如果做了逻辑推理，请给出假设输入与输出:**

这个文件本身不涉及逻辑推理。它的作用是提供预定义的常量和字符串。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记检查系统调用的返回值:**  程序员调用 `open()`、`read()`、`write()` 等系统调用后，如果没有检查返回值是否为 -1，就无法知道操作是否成功，也就无法根据 `errno` 来判断错误原因。

   ```c
   int fd = open("nonexistent_file.txt", O_RDONLY);
   // 错误的做法：没有检查 fd 的值
   read(fd, buffer, size); // 可能导致崩溃或未定义行为

   // 正确的做法：检查返回值并处理错误
   if (fd == -1) {
       perror("Error opening file"); // 会打印类似 "Error opening file: No such file or directory" 的信息
       // 或者使用 strerror(errno) 获取错误描述
   } else {
       read(fd, buffer, size);
       close(fd);
   }
   ```

2. **假设错误码固定不变:** 错误码的值虽然在 POSIX 标准中定义，但在不同的系统或 Bionic 版本中，具体的数值可能略有不同。应该使用宏定义（如 `ENOENT`）而不是硬编码的数字。

3. **不理解错误码的含义:**  遇到错误时，如果不理解 `errno` 的具体含义，就很难找到问题的根源。参考这个文件中的描述可以帮助理解错误的原因。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `bionic_errdefs.handroid` 的步骤:**

1. **Java Framework API 调用:** Android 应用通常通过 Java Framework 提供的 API 进行操作，例如 `java.io.FileInputStream` 用于读取文件。
2. **Framework Native 方法调用:**  Java Framework 的某些操作最终会调用 Native 方法（通过 JNI）。例如，`FileInputStream.open()` 可能会调用一个 Native 方法。
3. **NDK 函数调用:**  Native 方法内部会使用 NDK 提供的 C/C++ 接口，例如 `<fcntl.h>` 中的 `open()` 函数。
4. **Bionic libc 函数调用:** NDK 的函数实际上是 Bionic libc 提供的实现。`open()` 函数是 Bionic libc 的一部分。
5. **系统调用:** Bionic libc 中的 `open()` 函数会最终调用内核的 `openat` 系统调用。
6. **内核设置 `errno`:** 如果系统调用失败，内核会根据错误原因设置全局变量 `errno` 的值。
7. **Bionic libc 返回错误:** Bionic libc 的 `open()` 函数会检查系统调用的返回值，如果失败（返回 -1），则会将 `errno` 的值传递给调用者。
8. **NDK Native 方法处理错误:** Native 方法会检查 `open()` 的返回值，并可能抛出 Java 异常。异常信息中可能会包含与 `errno` 对应的错误描述。
9. **Framework 处理异常:** Java Framework 会捕获 Native 方法抛出的异常，并将其转化为更高级别的 Java 异常，提供给应用开发者。

**Frida Hook 示例调试:**

我们可以使用 Frida Hook Bionic libc 的 `open()` 函数，并在其执行后打印 `errno` 的值，来观察在特定场景下会产生哪个错误码。

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        console.log("[*] open() called");
        console.log("    pathname: " + Memory.readUtf8String(args[0]));
        console.log("    flags: " + args[1]);
    },
    onLeave: function(retval) {
        if (retval.toInt32() === -1) {
            const errno_ptr = Module.findExportByName(null, "__errno_location");
            const errno_val = Memory.readS32(Memory.readPointer(errno_ptr));
            const strerror_ptr = Module.findExportByName(null, "strerror");
            const strerror_func = new NativeFunction(strerror_ptr, 'pointer', ['int']);
            const error_message = Memory.readUtf8String(strerror_func(errno_val));
            send({ "type": "error", "errno": errno_val, "message": error_message });
            console.log("[*] open() failed with errno: " + errno_val + " (" + error_message + ")");
        } else {
            console.log("[*] open() succeeded, fd: " + retval);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
input("[*] Press Enter to detach from process...\n")
session.detach()
```

**使用方法:**

1. 将 `your.app.package` 替换为你想要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试启用。
3. 运行这个 Python 脚本。
4. 在你的 Android 应用中执行会调用 `open()` 函数的操作（例如，打开一个文件）。
5. Frida 会拦截 `open()` 函数的调用，并在控制台中打印相关信息，包括 `errno` 的值和对应的错误描述。

**示例输出:**

```
[*] open() called
    pathname: /data/data/your.app.package/files/test.txt
    flags: 0
[*] open() failed with errno: 2 (No such file or directory)
[*] {"type": "error", "errno": 2, "message": "No such file or directory"}
```

这个 Frida 脚本演示了如何 Hook Bionic libc 的函数，并在其执行过程中获取错误信息，帮助开发者理解 Android 系统底层的错误处理机制，并定位应用中出现问题的根源。通过观察 `errno` 的值和对应的错误描述，我们可以更好地理解为什么某个操作失败了。

### 提示词
```
这是目录为bionic/libc/private/bionic_errdefs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2023 The Android Open Source Project
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
 * This header is used to define error constants and names;
 * it might be included several times.
 */

#ifndef __BIONIC_ERRDEF
#error __BIONIC_ERRDEF not defined
#endif

__BIONIC_ERRDEF(0, "Success")
__BIONIC_ERRDEF(EPERM, "Operation not permitted")
__BIONIC_ERRDEF(ENOENT, "No such file or directory")
__BIONIC_ERRDEF(ESRCH, "No such process")
__BIONIC_ERRDEF(EINTR, "Interrupted system call")
__BIONIC_ERRDEF(EIO, "I/O error")
__BIONIC_ERRDEF(ENXIO, "No such device or address")
__BIONIC_ERRDEF(E2BIG, "Argument list too long")
__BIONIC_ERRDEF(ENOEXEC, "Exec format error")
__BIONIC_ERRDEF(EBADF, "Bad file descriptor")
__BIONIC_ERRDEF(ECHILD, "No child processes")
__BIONIC_ERRDEF(EAGAIN, "Try again")
__BIONIC_ERRDEF(ENOMEM, "Out of memory")
__BIONIC_ERRDEF(EACCES, "Permission denied")
__BIONIC_ERRDEF(EFAULT, "Bad address")
__BIONIC_ERRDEF(ENOTBLK, "Block device required")
__BIONIC_ERRDEF(EBUSY, "Device or resource busy")
__BIONIC_ERRDEF(EEXIST, "File exists")
__BIONIC_ERRDEF(EXDEV, "Cross-device link")
__BIONIC_ERRDEF(ENODEV, "No such device")
__BIONIC_ERRDEF(ENOTDIR, "Not a directory")
__BIONIC_ERRDEF(EISDIR, "Is a directory")
__BIONIC_ERRDEF(EINVAL, "Invalid argument")
__BIONIC_ERRDEF(ENFILE, "File table overflow")
__BIONIC_ERRDEF(EMFILE, "Too many open files")
__BIONIC_ERRDEF(ENOTTY, "Inappropriate ioctl for device")
__BIONIC_ERRDEF(ETXTBSY, "Text file busy")
__BIONIC_ERRDEF(EFBIG, "File too large")
__BIONIC_ERRDEF(ENOSPC, "No space left on device")
__BIONIC_ERRDEF(ESPIPE, "Illegal seek")
__BIONIC_ERRDEF(EROFS, "Read-only file system")
__BIONIC_ERRDEF(EMLINK, "Too many links")
__BIONIC_ERRDEF(EPIPE, "Broken pipe")
__BIONIC_ERRDEF(EDOM, "Math argument out of domain of func")
__BIONIC_ERRDEF(ERANGE, "Math result not representable")
__BIONIC_ERRDEF(EDEADLK, "Resource deadlock would occur")
__BIONIC_ERRDEF(ENAMETOOLONG, "File name too long")
__BIONIC_ERRDEF(ENOLCK, "No record locks available")
__BIONIC_ERRDEF(ENOSYS, "Function not implemented")
__BIONIC_ERRDEF(ENOTEMPTY, "Directory not empty")
__BIONIC_ERRDEF(ELOOP, "Too many symbolic links encountered")
__BIONIC_ERRDEF(ENOMSG, "No message of desired type")
__BIONIC_ERRDEF(EIDRM, "Identifier removed")
__BIONIC_ERRDEF(ECHRNG, "Channel number out of range")
__BIONIC_ERRDEF(EL2NSYNC, "Level 2 not synchronized")
__BIONIC_ERRDEF(EL3HLT, "Level 3 halted")
__BIONIC_ERRDEF(EL3RST, "Level 3 reset")
__BIONIC_ERRDEF(ELNRNG, "Link number out of range")
__BIONIC_ERRDEF(EUNATCH, "Protocol driver not attached")
__BIONIC_ERRDEF(ENOCSI, "No CSI structure available")
__BIONIC_ERRDEF(EL2HLT, "Level 2 halted")
__BIONIC_ERRDEF(EBADE, "Invalid exchange")
__BIONIC_ERRDEF(EBADR, "Invalid request descriptor")
__BIONIC_ERRDEF(EXFULL, "Exchange full")
__BIONIC_ERRDEF(ENOANO, "No anode")
__BIONIC_ERRDEF(EBADRQC, "Invalid request code")
__BIONIC_ERRDEF(EBADSLT, "Invalid slot")
__BIONIC_ERRDEF(EBFONT, "Bad font file format")
__BIONIC_ERRDEF(ENOSTR, "Device not a stream")
__BIONIC_ERRDEF(ENODATA, "No data available")
__BIONIC_ERRDEF(ETIME, "Timer expired")
__BIONIC_ERRDEF(ENOSR, "Out of streams resources")
__BIONIC_ERRDEF(ENONET, "Machine is not on the network")
__BIONIC_ERRDEF(ENOPKG, "Package not installed")
__BIONIC_ERRDEF(EREMOTE, "Object is remote")
__BIONIC_ERRDEF(ENOLINK, "Link has been severed")
__BIONIC_ERRDEF(EADV, "Advertise error")
__BIONIC_ERRDEF(ESRMNT, "Srmount error")
__BIONIC_ERRDEF(ECOMM, "Communication error on send")
__BIONIC_ERRDEF(EPROTO, "Protocol error")
__BIONIC_ERRDEF(EMULTIHOP, "Multihop attempted")
__BIONIC_ERRDEF(EDOTDOT, "RFS specific error")
__BIONIC_ERRDEF(EBADMSG, "Not a data message")
__BIONIC_ERRDEF(EOVERFLOW, "Value too large for defined data type")
__BIONIC_ERRDEF(ENOTUNIQ, "Name not unique on network")
__BIONIC_ERRDEF(EBADFD, "File descriptor in bad state")
__BIONIC_ERRDEF(EREMCHG, "Remote address changed")
__BIONIC_ERRDEF(ELIBACC, "Can not access a needed shared library")
__BIONIC_ERRDEF(ELIBBAD, "Accessing a corrupted shared library")
__BIONIC_ERRDEF(ELIBSCN, ".lib section in a.out corrupted")
__BIONIC_ERRDEF(ELIBMAX, "Attempting to link in too many shared libraries")
__BIONIC_ERRDEF(ELIBEXEC, "Cannot exec a shared library directly")
__BIONIC_ERRDEF(EILSEQ, "Illegal byte sequence")
__BIONIC_ERRDEF(ERESTART, "Interrupted system call should be restarted")
__BIONIC_ERRDEF(ESTRPIPE, "Streams pipe error")
__BIONIC_ERRDEF(EUSERS, "Too many users")
__BIONIC_ERRDEF(ENOTSOCK, "Socket operation on non-socket")
__BIONIC_ERRDEF(EDESTADDRREQ, "Destination address required")
__BIONIC_ERRDEF(EMSGSIZE, "Message too long")
__BIONIC_ERRDEF(EPROTOTYPE, "Protocol wrong type for socket")
__BIONIC_ERRDEF(ENOPROTOOPT, "Protocol not available")
__BIONIC_ERRDEF(EPROTONOSUPPORT, "Protocol not supported")
__BIONIC_ERRDEF(ESOCKTNOSUPPORT, "Socket type not supported")
__BIONIC_ERRDEF(EOPNOTSUPP, "Operation not supported on transport endpoint")
__BIONIC_ERRDEF(EPFNOSUPPORT, "Protocol family not supported")
__BIONIC_ERRDEF(EAFNOSUPPORT, "Address family not supported by protocol")
__BIONIC_ERRDEF(EADDRINUSE, "Address already in use")
__BIONIC_ERRDEF(EADDRNOTAVAIL, "Cannot assign requested address")
__BIONIC_ERRDEF(ENETDOWN, "Network is down")
__BIONIC_ERRDEF(ENETUNREACH, "Network is unreachable")
__BIONIC_ERRDEF(ENETRESET, "Network dropped connection because of reset")
__BIONIC_ERRDEF(ECONNABORTED, "Software caused connection abort")
__BIONIC_ERRDEF(ECONNRESET, "Connection reset by peer")
__BIONIC_ERRDEF(ENOBUFS, "No buffer space available")
__BIONIC_ERRDEF(EISCONN, "Transport endpoint is already connected")
__BIONIC_ERRDEF(ENOTCONN, "Transport endpoint is not connected")
__BIONIC_ERRDEF(ESHUTDOWN, "Cannot send after transport endpoint shutdown")
__BIONIC_ERRDEF(ETOOMANYREFS, "Too many references: cannot splice")
__BIONIC_ERRDEF(ETIMEDOUT, "Connection timed out")
__BIONIC_ERRDEF(ECONNREFUSED, "Connection refused")
__BIONIC_ERRDEF(EHOSTDOWN, "Host is down")
__BIONIC_ERRDEF(EHOSTUNREACH, "No route to host")
__BIONIC_ERRDEF(EALREADY, "Operation already in progress")
__BIONIC_ERRDEF(EINPROGRESS, "Operation now in progress")
__BIONIC_ERRDEF(ESTALE, "Stale NFS file handle")
__BIONIC_ERRDEF(EUCLEAN, "Structure needs cleaning")
__BIONIC_ERRDEF(ENOTNAM, "Not a XENIX named type file")
__BIONIC_ERRDEF(ENAVAIL, "No XENIX semaphores available")
__BIONIC_ERRDEF(EISNAM, "Is a named type file")
__BIONIC_ERRDEF(EREMOTEIO, "Remote I/O error")
__BIONIC_ERRDEF(EDQUOT, "Quota exceeded")
__BIONIC_ERRDEF(ENOMEDIUM, "No medium found")
__BIONIC_ERRDEF(EMEDIUMTYPE, "Wrong medium type")
__BIONIC_ERRDEF(ECANCELED, "Operation Canceled")
__BIONIC_ERRDEF(ENOKEY, "Required key not available")
__BIONIC_ERRDEF(EKEYEXPIRED, "Key has expired")
__BIONIC_ERRDEF(EKEYREVOKED, "Key has been revoked")
__BIONIC_ERRDEF(EKEYREJECTED, "Key was rejected by service")
__BIONIC_ERRDEF(EOWNERDEAD, "Owner died")
__BIONIC_ERRDEF(ENOTRECOVERABLE, "State not recoverable")
__BIONIC_ERRDEF(ERFKILL, "Operation not possible due to RF-kill")
__BIONIC_ERRDEF(EHWPOISON, "Memory page has hardware error")

#undef __BIONIC_ERRDEF
```