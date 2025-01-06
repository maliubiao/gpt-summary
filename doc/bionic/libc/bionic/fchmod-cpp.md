Response:
Let's break down the thought process for generating the comprehensive answer to the `fchmod.cpp` analysis request.

**1. Understanding the Core Request:**

The initial request asks for an analysis of `bionic/libc/bionic/fchmod.cpp`. Key elements to address include: functionality, relation to Android, implementation details, dynamic linker involvement, error scenarios, usage in Android, and Frida hooking.

**2. Initial Code Analysis (Static Analysis):**

* **Identify the Primary Function:** The core function is `fchmod(int fd, mode_t mode)`.
* **Identify System Calls:**  The code directly calls `__fchmod(fd, mode)` and `chmod(path, mode)`. It also uses `fcntl(fd, F_GETFL)`.
* **Identify Error Handling:** The code checks the return values of syscalls and manipulates `errno`. It also has a specific handling case for `EBADF` and `ELOOP`.
* **Identify Included Headers:**  The includes (`fcntl.h`, `sys/stat.h`, etc.) provide clues about the function's purpose.
* **Identify Private Headers:** The inclusion of `"private/FdPath.h"` suggests internal Bionic implementation details.
* **High-Level Functionality:**  The function modifies file permissions based on a file descriptor. The presence of the `O_PATH` handling suggests a special case.

**3. Deconstructing the `fchmod` Implementation:**

* **Direct Syscall (`__fchmod`):**  The code first tries the direct system call via `__fchmod`. This is the most efficient path.
* **`EBADF` Handling:** The code specifically checks for `EBADF` after the `__fchmod` call. This triggers the special handling for `O_PATH` file descriptors.
* **`O_PATH` Detection:** The code uses `fcntl(fd, F_GETFL)` to check if the file descriptor was opened with `O_PATH`.
* **Emulation via `/proc/self/fd`:**  If it's an `O_PATH` descriptor, the code constructs a path using `FdPath(fd).c_str()` and calls `chmod`. The `FdPath` class likely constructs a path like `/proc/self/fd/<fd>`.
* **`ELOOP` Handling:**  If the `chmod` call returns `ELOOP`, the code changes `errno` to `ENOTSUP`. This is related to the POSIX requirement for `fchmodat(AT_SYMLINK_NOFOLLOW)` on symlinks.

**4. Relating to Android Functionality:**

* **Core System Functionality:** `fchmod` is a fundamental POSIX function, essential for managing file permissions in Android.
* **Security:** It's crucial for enforcing security policies by controlling access to files and directories.
* **Package Management:** Android's package manager likely uses `fchmod` to set permissions for installed applications.
* **File System Operations:** Any Android component that interacts with the file system (e.g., file explorers, download managers) might indirectly use `fchmod`.

**5. Dynamic Linker Considerations:**

* **`__fchmod` and Linking:** The `__fchmod` function name with double underscores strongly suggests it's the underlying system call implementation provided by the kernel. The dynamic linker is responsible for resolving the call to `__fchmod` to the actual kernel entry point.
* **SO Layout:**  Consider the typical layout of an Android executable and shared libraries. The executable will link against libc.so (which contains `fchmod`). When `fchmod` is called, the dynamic linker will resolve `__fchmod` based on the symbol tables.

**6. Error Scenarios and Common Mistakes:**

* **Invalid File Descriptor:** Passing an invalid `fd` is a common error, resulting in `EBADF`.
* **Incorrect Permissions:**  Setting inappropriate permissions can lead to security vulnerabilities or application malfunction.
* **Trying to Change Permissions of a Symlink:**  Directly trying to change permissions of a symlink with `fchmod` (without `AT_SYMLINK_NOFOLLOW`) is a POSIX limitation, leading to potential confusion.

**7. Android Framework and NDK Usage:**

* **Framework Path:**  Trace how a high-level Android API call (e.g., `java.io.File.setExecutable()`) might eventually lead to the `fchmod` call in Bionic. This involves traversing through Java Native Interface (JNI) calls and potentially framework services.
* **NDK Path:**  Demonstrate how an NDK application can directly use the `fchmod` function declared in `<unistd.h>`.

**8. Frida Hooking:**

* **Identify the Hook Target:** The primary function to hook is `fchmod`.
* **Basic Hook:** Show a simple Frida script to intercept `fchmod`, log arguments, and potentially modify the behavior.
* **Hooking `__fchmod`:** Illustrate hooking the underlying system call to observe the direct interaction with the kernel.

**9. Structuring the Answer:**

* **Start with a Summary:** Briefly state the function's purpose.
* **Detail Functionality:** Explain each part of the `fchmod` implementation.
* **Android Relevance:** Provide concrete examples of how `fchmod` is used in Android.
* **Libc Implementation:** Describe the internal workings, including the `O_PATH` handling.
* **Dynamic Linker:** Explain the role of the dynamic linker and provide an example SO layout.
* **Error Scenarios:** List common mistakes and their consequences.
* **Android Integration:** Explain how the Android framework and NDK use `fchmod`.
* **Frida Hooking:** Provide practical Frida examples.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focusing solely on the direct `__fchmod` call.
* **Correction:**  Realizing the importance of the `O_PATH` handling and the emulation using `/proc/self/fd`. This is a crucial aspect of the Android-specific implementation.
* **Initial thought:**  Listing general file system operations as examples.
* **Refinement:**  Providing more specific Android examples like package management and framework APIs.
* **Initial thought:** A simple Frida hook for `fchmod`.
* **Refinement:**  Adding a hook for `__fchmod` to demonstrate the deeper system interaction.

By following this structured approach, breaking down the problem into smaller parts, and iteratively refining the analysis, it's possible to generate a comprehensive and accurate answer to the initial request. The key is to understand the code at a low level, connect it to the broader Android ecosystem, and anticipate common questions or areas of interest.
好的，让我们来详细分析一下 `bionic/libc/bionic/fchmod.cpp` 这个文件。

**功能概述**

`fchmod.cpp` 文件实现了 `fchmod` 这个 POSIX 标准 C 库函数。其主要功能是：

* **修改已打开文件的访问权限（mode）**：  `fchmod` 允许你通过文件描述符（file descriptor，`fd`）来更改文件的权限。这与 `chmod` 函数通过文件路径名来修改权限不同。

**与 Android 功能的关系及举例**

`fchmod` 是一个底层的系统调用接口，在 Android 系统中被广泛使用，因为它涉及到文件系统的安全和权限管理。以下是一些例子：

* **Package 安装和管理:** 当 Android 安装或更新一个应用时，系统需要设置应用相关文件和目录的权限，以确保应用能够正常运行并且不会被恶意篡改。`fchmod` 可能被用来设置已创建文件的权限。
* **文件共享和访问控制:** 在多用户或者应用之间共享文件时，系统需要精确控制不同用户或应用对文件的读、写、执行权限。`fchmod` 可以被用来调整这些权限。
* **临时文件和目录:**  Android 系统和应用在运行时经常创建临时文件和目录。`fchmod` 可以用于限制这些临时文件的访问权限，防止未授权的访问。
* **服务进程管理:** Android 的各种系统服务通常以特定的用户和权限运行。`fchmod` 可以用于设置服务进程相关文件的权限。

**libc 函数 `fchmod` 的实现细节**

让我们逐行分析 `fchmod` 函数的实现：

```c++
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "private/FdPath.h"

extern "C" int __fchmod(int, mode_t);

int fchmod(int fd, mode_t mode) {
  int saved_errno = errno;
  int result = __fchmod(fd, mode);
  if (result == 0 || errno != EBADF) {
    return result;
  }

  // fd could be an O_PATH file descriptor, and the kernel
  // may not directly support fchmod() on such a file descriptor.
  // Use /proc/self/fd instead to emulate this support.
  // https://sourceware.org/bugzilla/show_bug.cgi?id=14578
  //
  // As of February 2015, there are no kernels which support fchmod
  // on an O_PATH file descriptor, and "man open" documents fchmod
  // on O_PATH file descriptors as returning EBADF.
  int fd_flag = fcntl(fd, F_GETFL);
  if (fd_flag == -1 || (fd_flag & O_PATH) == 0) {
    errno = EBADF;
    return -1;
  }

  errno = saved_errno;
  result = chmod(FdPath(fd).c_str(), mode);
  if (result == -1 && errno == ELOOP) {
    // Linux does not support changing the mode of a symlink.
    // For fchmodat(AT_SYMLINK_NOFOLLOW), POSIX requires a return
    // value of ENOTSUP. Assume that's true here too.
    errno = ENOTSUP;
  }

  return result;
}
```

1. **头文件包含:**
   - `<fcntl.h>`: 包含了文件控制相关的定义，例如 `F_GETFL` 和 `O_PATH`。
   - `<sys/stat.h>`: 包含了文件状态相关的定义，例如 `mode_t`。
   - `<sys/types.h>`: 包含了基本的数据类型定义。
   - `<errno.h>`:  用于处理错误码。
   - `<unistd.h>`: 包含了 POSIX 操作系统 API 的声明，包括 `fcntl` 和 `chmod`。
   - `<stdio.h>`:  虽然在这个特定的代码中没有直接使用，但通常会包含在 C/C++ 文件中。
   - `"private/FdPath.h"`:  这是一个 Bionic 内部的头文件，它可能定义了 `FdPath` 类，用于根据文件描述符创建对应的路径字符串。

2. **外部声明 `__fchmod`:**
   ```c++
   extern "C" int __fchmod(int, mode_t);
   ```
   - `extern "C"`:  告诉编译器使用 C 的命名约定，这通常用于声明系统调用或者与 C 代码链接的函数。
   - `__fchmod`:  这是一个内部函数，通常是直接与内核交互的系统调用的包装器。Bionic 会提供这个函数的实现，它最终会调用 Linux 内核的 `fchmod` 系统调用。

3. **`fchmod` 函数实现:**
   ```c++
   int fchmod(int fd, mode_t mode) {
     int saved_errno = errno;
     int result = __fchmod(fd, mode);
     if (result == 0 || errno != EBADF) {
       return result;
     }
   ```
   - 首先保存当前的 `errno` 值。
   - 尝试直接调用底层的 `__fchmod` 函数。
   - 如果 `__fchmod` 调用成功（返回 0）或者失败但不是因为无效的文件描述符 (`EBADF`)，则直接返回结果。

4. **处理 `O_PATH` 文件描述符:**
   ```c++
   // fd could be an O_PATH file descriptor, and the kernel
   // may not directly support fchmod() on such a file descriptor.
   // Use /proc/self/fd instead to emulate this support.
   // ... (注释)
   int fd_flag = fcntl(fd, F_GETFL);
   if (fd_flag == -1 || (fd_flag & O_PATH) == 0) {
     errno = EBADF;
     return -1;
   }
   ```
   - 注释解释了这里处理的特殊情况：`O_PATH` 文件描述符。当使用 `open` 函数打开文件时，可以指定 `O_PATH` 标志。这种文件描述符只用于路径操作，本身不提供读写权限。早期的 Linux 内核可能不支持直接对 `O_PATH` 文件描述符使用 `fchmod`。
   - 使用 `fcntl(fd, F_GETFL)` 获取文件描述符的标志。
   - 如果 `fcntl` 调用失败或者文件描述符没有设置 `O_PATH` 标志，则将 `errno` 设置为 `EBADF` 并返回 -1，表明这是一个无效的文件描述符操作。

5. **使用 `/proc/self/fd` 模拟 `fchmod`:**
   ```c++
   errno = saved_errno;
   result = chmod(FdPath(fd).c_str(), mode);
   if (result == -1 && errno == ELOOP) {
     // Linux does not support changing the mode of a symlink.
     // For fchmodat(AT_SYMLINK_NOFOLLOW), POSIX requires a return
     // value of ENOTSUP. Assume that's true here too.
     errno = ENOTSUP;
   }
   ```
   - 如果文件描述符是 `O_PATH` 类型，则恢复之前保存的 `errno` 值。
   - 调用 `chmod` 函数，但是使用 `FdPath(fd).c_str()` 构建的文件路径。`FdPath(fd).c_str()` 会生成类似 `/proc/self/fd/<fd>` 的路径，其中 `<fd>` 是文件描述符的数值。`/proc/self/fd/` 目录下的条目是指向当前进程打开的文件的符号链接，通过操作这个链接，可以间接地修改对应文件的权限。
   - 处理符号链接的情况：如果 `chmod` 调用失败，并且错误码是 `ELOOP`，这通常意味着尝试修改一个符号链接自身的权限。POSIX 标准中，对于 `fchmodat(AT_SYMLINK_NOFOLLOW)` 操作，如果尝试修改符号链接的权限，应该返回 `ENOTSUP` (Operation not supported)。这里假设直接使用 `chmod` 修改符号链接也会有类似的行为，并将 `errno` 设置为 `ENOTSUP`。

6. **返回结果:**
   ```c++
   return result;
   ```
   - 返回 `chmod` 函数的调用结果。

**涉及 dynamic linker 的功能**

在这个 `fchmod.cpp` 文件中，与 dynamic linker 直接相关的部分是 `__fchmod` 的声明和使用。

* **`__fchmod` 的链接:** 当一个程序调用 `fchmod` 时，链接器需要找到 `__fchmod` 的实现。在 Android 中，libc.so 包含了 `fchmod` 的实现，而 `__fchmod` 通常是链接到内核提供的系统调用入口点。Dynamic linker (如 `linker64` 或 `linker`) 负责在程序运行时解析这些符号，并将 `fchmod` 中的 `__fchmod` 调用指向正确的内核地址。

**SO 布局样本和链接处理过程**

假设我们有一个简单的可执行文件 `my_app`，它调用了 `fchmod`。

**SO 布局样本:**

```
/system/bin/my_app  (可执行文件)
/system/lib64/libc.so (Android 的 C 库)
/system/lib64/ld-android.so (Dynamic linker)
```

**链接处理过程:**

1. **编译时链接:** 当 `my_app` 被编译和链接时，链接器会记录下 `fchmod` 函数的符号引用，并标记它需要在运行时被解析。它还会记录下 `__fchmod` 的符号引用，虽然这个符号通常由 libc.so 提供。

2. **运行时加载:** 当 `my_app` 启动时，Android 的 `zygote` 进程会 `fork` 出新的进程，并加载 `my_app`。Dynamic linker (`ld-android.so`) 会被首先加载。

3. **依赖项加载:** Dynamic linker 会检查 `my_app` 的依赖项，发现它依赖于 `libc.so`，于是加载 `libc.so` 到进程的地址空间。

4. **符号解析 (Symbol Resolution):**
   - Dynamic linker 遍历 `my_app` 的重定位表，找到需要解析的符号，例如 `fchmod`。
   - 它在已加载的共享库 (`libc.so`) 的符号表中查找 `fchmod` 的定义，找到后更新 `my_app` 中 `fchmod` 函数调用的地址，使其指向 `libc.so` 中 `fchmod` 的实现。
   - 类似地，当 `libc.so` 中的 `fchmod` 函数被执行时，它会调用 `__fchmod`。Dynamic linker 已经预先处理了 `libc.so` 内部的符号引用。对于 `__fchmod`，它通常通过某种机制（例如，vDSO 或直接的系统调用表）来找到内核提供的系统调用入口点。

5. **执行:** 当 `my_app` 调用 `fchmod` 时，实际上执行的是 `libc.so` 中实现的 `fchmod` 函数。当 `fchmod` 内部调用 `__fchmod` 时，最终会触发内核的 `fchmod` 系统调用。

**逻辑推理的假设输入与输出**

**假设输入 1:**

* `fd`: 一个已打开的文件的有效文件描述符，例如 3。
* `mode`: 新的文件权限，例如 `S_IRUSR | S_IWUSR` (所有者读写)。

**预期输出 1:**

* 如果操作成功，`fchmod` 返回 0。
* 文件的权限被更改为所有者读写。

**假设输入 2:**

* `fd`: 一个无效的文件描述符，例如 -1。
* `mode`: 任意权限值。

**预期输出 2:**

* `fchmod` 返回 -1。
* `errno` 被设置为 `EBADF` (Bad file descriptor)。

**假设输入 3:**

* `fd`: 一个通过 `open` 函数使用 `O_PATH` 标志打开的文件描述符。
* `mode`: 新的文件权限。

**预期输出 3:**

* `fchmod` 会尝试通过操作 `/proc/self/fd/<fd>` 来更改文件权限。
* 如果操作成功，返回 0。
* 如果因为其他原因失败（例如，没有权限修改 `/proc/self/fd/<fd>` 指向的文件），返回 -1，并设置相应的 `errno`。

**用户或编程常见的使用错误**

1. **使用无效的文件描述符:**  传递一个未打开或已关闭的文件描述符会导致 `EBADF` 错误。
   ```c++
   int fd = open("myfile.txt", O_RDONLY);
   close(fd);
   if (fchmod(fd, S_IRUSR) == -1) {
       perror("fchmod failed"); // 可能输出: fchmod failed: Bad file descriptor
   }
   ```

2. **设置不正确的权限 `mode`:** 传递错误的 `mode` 值可能导致无法达到预期的权限设置。需要查阅 `<sys/stat.h>` 中定义的权限宏。
   ```c++
   int fd = open("myfile.txt", O_RDWR | O_CREAT, 0666);
   if (fchmod(fd, 0) == -1) { // 错误地将权限设置为 0
       perror("fchmod failed");
   }
   close(fd);
   ```

3. **尝试修改没有权限的文件:**  如果进程没有足够的权限来修改文件的权限，`fchmod` 会失败并返回 `EPERM` (Operation not permitted)。
   ```c++
   // 假设当前用户对 some_protected_file 没有修改权限
   int fd = open("some_protected_file", O_RDONLY);
   if (fd != -1) {
       if (fchmod(fd, S_IRWXU) == -1) {
           perror("fchmod failed"); // 可能输出: fchmod failed: Operation not permitted
       }
       close(fd);
   }
   ```

4. **混淆 `fchmod` 和 `chmod` 的使用场景:** 错误地在应该使用文件路径名的地方使用了文件描述符，或者反之。

**Android Framework 或 NDK 如何到达这里**

**Android Framework 路径 (Java 层到 Native 层):**

1. **Java 代码调用:** 在 Android Framework 的 Java 层，可能会有类似 `java.io.File.setExecutable(boolean)` 或涉及到文件权限修改的操作。

2. **JNI 调用:** 这些 Java 方法通常会通过 Java Native Interface (JNI) 调用到 Android 系统的 Native 代码。

3. **Framework Native 代码:** 在 Framework 的 Native 代码中（例如，在 `libjavacrypto.so` 或其他系统库中），可能会调用到 Bionic 提供的 C 库函数，例如 `chmod` 或 `fchmod`。

   例如，`java.io.File.setExecutable()` 最终可能会调用到 `fcntl` 或 `fchmod` 来设置文件的执行权限。

**NDK 路径 (C/C++ 代码直接调用):**

1. **NDK 应用代码:** 使用 NDK 开发的 Android 应用可以直接调用 POSIX 标准的 C 库函数，包括 `fchmod`。

   ```c++
   #include <unistd.h>
   #include <sys/stat.h>
   #include <fcntl.h>
   #include <errno.h>
   #include <stdio.h>

   int main() {
       int fd = open("/sdcard/my_file.txt", O_RDWR);
       if (fd != -1) {
           if (fchmod(fd, S_IRUSR | S_IWUSR) == -1) {
               perror("fchmod failed");
           }
           close(fd);
       } else {
           perror("open failed");
       }
       return 0;
   }
   ```

2. **编译和链接:** NDK 编译器会将这段代码编译成机器码，并链接到 Android 系统的 C 库 `libc.so`。

3. **运行时调用:** 当应用运行时，对 `fchmod` 的调用会直接执行 `bionic/libc/bionic/fchmod.cpp` 中实现的函数。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 调试 `fchmod` 的示例：

**Frida 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const fchmodPtr = libc.getExportByName("fchmod");

  if (fchmodPtr) {
    Interceptor.attach(fchmodPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const mode = args[1].toInt32();
        console.log("[fchmod] Called with fd:", fd, ", mode:", mode.toString(8)); // 以八进制打印 mode
        // 你可以在这里修改参数，例如：
        // args[1] = ptr(parseInt("0777", 8)); // 将 mode 修改为 0777
      },
      onLeave: function (retval) {
        console.log("[fchmod] Returned:", retval.toInt32());
      }
    });
    console.log("[fchmod] Hooked!");
  } else {
    console.error("[fchmod] Not found in libc.so");
  }

  const __fchmodPtr = libc.getExportByName("__fchmod");
  if (__fchmodPtr) {
    Interceptor.attach(__fchmodPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const mode = args[1].toInt32();
        console.log("[__fchmod] Called with fd:", fd, ", mode:", mode.toString(8));
      },
      onLeave: function (retval) {
        console.log("[__fchmod] Returned:", retval.toInt32());
      }
    });
    console.log("[__fchmod] Hooked!");
  } else {
    console.error("[__fchmod] Not found in libc.so");
  }
} else {
  console.log("This script is designed for Android.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 Frida Server。

2. **启动目标应用:** 运行你想要监控其 `fchmod` 调用的 Android 应用。

3. **运行 Frida 脚本:** 使用 Frida 命令将脚本附加到目标应用进程：
   ```bash
   frida -U -f <your_app_package_name> -l your_frida_script.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l your_frida_script.js
   ```

4. **观察输出:** 当目标应用执行到 `fchmod` 或 `__fchmod` 函数时，Frida 脚本会在终端输出相关的日志信息，包括文件描述符和要设置的权限值。

**示例输出:**

```
[Pixel 6::com.example.myapp ]-> [fchmod] Hooked!
[Pixel 6::com.example.myapp ]-> [__fchmod] Hooked!
[Pixel 6::com.example.myapp ]-> [fchmod] Called with fd: 3, mode: 600
[Pixel 6::com.example.myapp ]-> [__fchmod] Called with fd: 3, mode: 600
[Pixel 6::com.example.myapp ]-> [__fchmod] Returned: 0
[Pixel 6::com.example.myapp ]-> [fchmod] Returned: 0
```

这个输出表明 `fchmod` 函数被调用，文件描述符为 3，权限模式为八进制的 600。同时，我们也 hook 了底层的 `__fchmod` 函数，可以看到它也被调用，并且返回值为 0 (成功)。

通过这种方式，你可以监控 Android 应用中 `fchmod` 的调用情况，了解哪些文件被修改了权限，以及修改成了什么样的权限。这对于安全分析、逆向工程和调试都非常有帮助。

Prompt: 
```
这是目录为bionic/libc/bionic/fchmod.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "private/FdPath.h"

extern "C" int __fchmod(int, mode_t);

int fchmod(int fd, mode_t mode) {
  int saved_errno = errno;
  int result = __fchmod(fd, mode);
  if (result == 0 || errno != EBADF) {
    return result;
  }

  // fd could be an O_PATH file descriptor, and the kernel
  // may not directly support fchmod() on such a file descriptor.
  // Use /proc/self/fd instead to emulate this support.
  // https://sourceware.org/bugzilla/show_bug.cgi?id=14578
  //
  // As of February 2015, there are no kernels which support fchmod
  // on an O_PATH file descriptor, and "man open" documents fchmod
  // on O_PATH file descriptors as returning EBADF.
  int fd_flag = fcntl(fd, F_GETFL);
  if (fd_flag == -1 || (fd_flag & O_PATH) == 0) {
    errno = EBADF;
    return -1;
  }

  errno = saved_errno;
  result = chmod(FdPath(fd).c_str(), mode);
  if (result == -1 && errno == ELOOP) {
    // Linux does not support changing the mode of a symlink.
    // For fchmodat(AT_SYMLINK_NOFOLLOW), POSIX requires a return
    // value of ENOTSUP. Assume that's true here too.
    errno = ENOTSUP;
  }

  return result;
}

"""

```