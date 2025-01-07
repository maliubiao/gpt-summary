Response:
Let's break down the thought process for analyzing the `sys_prctl_test.cpp` file.

**1. Understanding the Goal:**

The initial request asks for a comprehensive analysis of the provided C++ test file. Key areas of focus include: functionality, relation to Android, libc function implementations, dynamic linker involvement, logical reasoning (with inputs/outputs), common errors, and tracing the code's execution from the Android framework/NDK.

**2. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of what it's doing. Keywords like `TEST`, `ASSERT_`, `EXPECT_`, `prctl`, `mmap`, `munmap`, `mprotect`, `/proc/self/maps`, `uname`, `CAP_SYS_ADMIN` stand out. This suggests the file is testing the `prctl` system call, specifically focusing on memory management and capabilities.

**3. Deconstructing Each Test Case:**

The file contains two distinct test cases: `bug_20017123` and `pr_cap_ambient`. It's crucial to analyze each separately.

* **`bug_20017123`:**
    * **Hypothesis:** The test seems to be checking for memory map overlaps after setting an anonymous VMA name using `prctl`.
    * **Key Functions:** `mmap`, `mprotect`, `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)`, `munmap`, file I/O to `/proc/self/maps`.
    * **Logic:** Allocate memory, make a portion read-only, set an anonymous name, read the memory map, and verify no overlaps.
    * **Android Relevance:** Memory management and process introspection are core Android functionalities. The `/proc` filesystem is fundamental to Linux and Android.

* **`pr_cap_ambient`:**
    * **Hypothesis:** This test focuses on the `PR_CAP_AMBIENT` operations of `prctl`, related to ambient capabilities.
    * **Key Functions:** `prctl(PR_CAP_AMBIENT, ...)`, `uname`.
    * **Logic:** Check for the existence of ambient capability features in the kernel, and verify the behavior of raising, lowering, and checking ambient capabilities, particularly `CAP_SYS_ADMIN`.
    * **Android Relevance:**  Capabilities are crucial for Android's security model, allowing fine-grained control over process privileges.

**4. Analyzing Individual libc Functions:**

For each libc function used, the goal is to explain its purpose and how it achieves it (at a high level, without going into kernel implementation details unless necessary for clarity).

* **`sysconf(_SC_PAGESIZE)`:**  Get system configuration information, specifically the page size. This involves a system call that queries the kernel.
* **`mmap()`:** Map memory. This involves the kernel setting up virtual memory mappings for the process. Key aspects: address, size, protection, flags, file descriptor (if mapping a file), offset.
* **`mprotect()`:** Change the access protection of a memory region. This interacts with the kernel's memory management unit (MMU).
* **`prctl()`:** Perform control operations on a process. The functionality varies greatly depending on the first argument. It's a direct system call interface.
* **`munmap()`:** Unmap a previously mapped memory region, releasing resources. Another system call.
* **`open()`, `read()`, `close()` (implicitly through `android::base::ReadFileToString`):** Standard file I/O operations. These involve system calls to interact with the filesystem.
* **`sscanf()`:** Parse formatted input from a string. This is a standard C library function for string manipulation.
* **`uname()`:** Get information about the operating system. This involves a system call.

**5. Dynamic Linker Analysis:**

The provided test file *doesn't directly* interact with the dynamic linker. The focus is on process control and memory management. Therefore, the "dynamic linker" section of the answer explains *why* it's not directly involved and provides a general overview of how the dynamic linker works in Android for context.

**6. Logical Reasoning and Examples:**

For each test case, consider the expected behavior. For `bug_20017123`, the expectation is that memory maps don't overlap. For `pr_cap_ambient`, the expectations are tied to the semantics of ambient capabilities. The examples provided illustrate potential failure scenarios and what the output would look like.

**7. Common Usage Errors:**

Think about how developers might misuse the functions being tested. Examples include incorrect `prctl` arguments, forgetting to `munmap`, or misunderstanding capability semantics.

**8. Tracing Execution (Android Framework/NDK to the Test):**

This requires understanding the layers involved in executing native code on Android.

* **Application Code (Java/Kotlin):**  A user interacts with an Android app.
* **NDK:** The app uses JNI to call native code.
* **Bionic:** The native code uses Bionic libc functions like `prctl`.
* **Kernel:** Bionic functions make system calls to the Linux kernel.

The Frida hook example demonstrates how to intercept the `prctl` system call, which is the core function being tested.

**9. Structuring the Answer:**

Organize the information clearly using headings and bullet points to make it easy to read and understand. Address each part of the original request systematically.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe the `bug_20017123` test is directly related to a specific linker bug.
* **Correction:**  Closer reading reveals it's about memory map overlaps after using `prctl` to name an anonymous VMA, not a dynamic linking issue directly. The "bug number" is just a reference.
* **Initial thought:**  Go deep into the kernel implementation of `prctl`.
* **Correction:**  For this analysis, a high-level explanation of what the system call does is sufficient. Focus on the user-space perspective.
* **Initial thought:** Provide very technical details about ambient capabilities.
* **Correction:**  Explain the core concepts and how the test validates the expected behavior (raising, lowering, checking).

By following these steps, breaking down the problem into smaller pieces, and constantly checking back against the original request, a comprehensive and accurate analysis can be generated.
好的，让我们详细分析一下 `bionic/tests/sys_prctl_test.cpp` 这个文件。

**文件功能概述**

这个 C++ 文件是 Android Bionic 库中的一个测试文件，专门用于测试 `prctl` 系统调用的各种功能。`prctl` (process control) 是一个功能强大的系统调用，允许进程执行多种控制操作，例如获取和设置进程属性、进程间信号处理、内存管理等方面。

该测试文件主要包含两个测试用例：

1. **`TEST(sys_prctl, bug_20017123)`:**  这个测试用例旨在复现和验证一个特定的 bug (b/20017123)，该 bug 与使用 `prctl` 设置匿名内存区域名称后可能出现的内存映射重叠有关。

2. **`TEST(sys_prctl, pr_cap_ambient)`:** 这个测试用例主要测试 `prctl` 提供的与 ambient capabilities (环境能力) 相关的操作，例如清除、提升、检查和降低 ambient capabilities。

**与 Android 功能的关系及举例**

`prctl` 系统调用在 Android 系统中扮演着重要的角色，它允许系统和服务进行各种精细的进程控制。以下是一些与 Android 功能相关的例子：

* **安全性与权限管理：**
    * **Ambient Capabilities:**  Android 使用 capabilities 来管理进程的权限。Ambient capabilities 允许进程在 `execve` 后保留一部分权限。`prctl` 提供了操作这些 ambient capabilities 的接口，例如提升或降低权限。这对于安全地启动具有特定权限的进程至关重要。
    * **`PR_SET_NO_NEW_PRIVS`:** 可以使用 `prctl` 设置此标志，防止进程获取新的权限，增强安全性。Android 系统服务可能会使用此功能。

* **内存管理：**
    * **`PR_SET_VMA` 和 `PR_SET_VMA_ANON_NAME`:**  `bug_20017123` 测试的重点。Android 系统或应用在分配匿名内存后，可以使用 `prctl` 为这些内存区域设置一个名称。这在调试和分析时很有用，可以通过 `/proc/pid/maps` 文件查看。例如，ART (Android Runtime) 虚拟机可能会使用此功能来标记其内部的内存区域。

* **进程间通信与信号处理：**
    * `prctl` 还可以用于设置子进程的死亡信号 (`PR_SET_PDEATHSIG`)，这对于确保父进程能够及时知道子进程的终止状态很有用。Android 的 `init` 进程和各种系统服务可能会使用此功能来管理其子进程。

**libc 函数的实现解释**

让我们详细解释一下测试文件中使用的 libc 函数：

1. **`sysconf(_SC_PAGESIZE)`:**
   * **功能:** 获取系统的页面大小。页面大小是操作系统内存管理的基本单位。
   * **实现:**  `sysconf` 是一个 POSIX 标准函数，它通过 `syscall` 发起一个 `sysconf` 系统调用。内核根据传入的参数 `_SC_PAGESIZE` 返回系统的页面大小。这个值通常在启动时由内核确定，并在运行时保持不变。

2. **`mmap(NULL, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)`:**
   * **功能:** 创建一个匿名内存映射。
   * **实现:** `mmap` 函数通过 `syscall` 发起 `mmap` 系统调用。
     * `NULL`:  表示让内核选择映射的起始地址。
     * `page_size * 3`:  指定映射的内存大小为三个页面。
     * `PROT_READ | PROT_WRITE`:  指定映射的内存具有读写权限。
     * `MAP_PRIVATE | MAP_ANONYMOUS`:
         * `MAP_PRIVATE`:  表示这是一个私有映射，对该映射的修改不会反映到原始文件（因为是匿名映射，所以没有原始文件）。
         * `MAP_ANONYMOUS`: 表示这是一个匿名映射，不与任何文件关联。
     * `-1`:  对于匿名映射，文件描述符设置为 -1。
     * `0`:  对于匿名映射，偏移量设置为 0。
   * **内核处理:** 内核会在进程的虚拟地址空间中找到一块合适的空闲区域，分配相应大小的物理页面，并建立页表项，将虚拟地址映射到物理地址。

3. **`mprotect(p, page_size, PROT_NONE)`:**
   * **功能:** 修改内存映射的保护属性。
   * **实现:** `mprotect` 函数通过 `syscall` 发起 `mprotect` 系统调用。
     * `p`:  指向要修改保护属性的内存区域的起始地址。
     * `page_size`:  指定要修改保护属性的内存区域的大小，这里是一个页面。
     * `PROT_NONE`:  指定新的保护属性为无访问权限。
   * **内核处理:** 内核会修改对应页表项中的权限位，使得对该内存区域的访问（读、写、执行）会触发异常。

4. **`prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p, page_size * 3, "anonymous map space")`:**
   * **功能:**  使用 `prctl` 系统调用设置一个匿名内存区域的名称。
   * **实现:** `prctl` 是一个通用的进程控制系统调用。
     * `PR_SET_VMA`: 指定要执行的操作是设置 VMA (Virtual Memory Area) 的属性。
     * `PR_SET_VMA_ANON_NAME`:  `PR_SET_VMA` 的子操作，表示要设置匿名 VMA 的名称。
     * `p`:  指向要命名的内存区域的起始地址。
     * `page_size * 3`:  指定内存区域的大小。
     * `"anonymous map space"`:  要设置的名称。
   * **内核处理:** 内核会遍历进程的 VMA 列表，找到与 `p` 和 `page_size * 3` 匹配的匿名 VMA，并将指定的名称存储在该 VMA 的数据结构中。这个名称可以通过读取 `/proc/self/maps` 文件查看。

5. **`munmap(p, page_size * 3)`:**
   * **功能:**  取消内存映射。
   * **实现:** `munmap` 函数通过 `syscall` 发起 `munmap` 系统调用。
     * `p`:  要取消映射的内存区域的起始地址。
     * `page_size * 3`:  要取消映射的内存区域的大小。
   * **内核处理:** 内核会释放与该内存区域关联的物理页面，并更新进程的页表，使其不再指向这些物理页面。

6. **`open("/proc/self/maps", O_RDONLY)`、`read()`、`close()` (通过 `android::base::ReadFileToString` 使用):**
   * **功能:** 读取 `/proc/self/maps` 文件。
   * **实现:**  这些是标准的 Unix 文件操作函数，通过 `syscall` 发起对应的系统调用 (`open`, `read`, `close`)。`/proc/self/maps` 是一个虚拟文件，由内核动态生成，包含了当前进程的内存映射信息。

7. **`sscanf(lines[i].c_str(), "%" SCNxPTR "-%" SCNxPTR " ", &start, &end)`:**
   * **功能:**  从字符串中解析十六进制的起始和结束地址。
   * **实现:** `sscanf` 是一个标准 C 库函数，用于格式化输入。它在用户空间进行字符串解析，不涉及系统调用。

8. **`uname(&u)`:**
   * **功能:** 获取当前系统的内核信息。
   * **实现:** `uname` 函数通过 `syscall` 发起 `uname` 系统调用。内核会将系统的名称、版本、发布号等信息填充到 `utsname` 结构体中。

**涉及 Dynamic Linker 的功能**

在这个测试文件中，**并没有直接涉及到 Dynamic Linker 的功能。**  测试的重点在于 `prctl` 系统调用，这是一个内核提供的功能，不直接与动态链接过程相关。

然而，理解 Dynamic Linker 在 Android 中的作用对于理解整个系统的运行至关重要。

**Dynamic Linker 的作用:**

* **加载共享库 (.so 文件):**  当一个程序需要使用共享库时，Dynamic Linker 负责将这些库加载到进程的地址空间。
* **符号解析:**  当程序调用共享库中的函数或访问其全局变量时，Dynamic Linker 负责在运行时解析这些符号，找到它们在共享库中的地址。
* **重定位:**  共享库在编译时通常不知道其最终加载地址，Dynamic Linker 需要在加载时调整代码和数据中的地址引用。

**so 布局样本和链接的处理过程 (理论说明):**

假设我们有一个简单的应用程序 `app` 和一个共享库 `libfoo.so`。

**`libfoo.so` 布局样本 (简化):**

```
.text        # 代码段
  function_a:
    ...
  function_b:
    ...

.data        # 数据段
  global_var: ...

.dynamic     # 动态链接信息
  SONAME: libfoo.so
  NEEDED: libc.so
  SYMTAB: ... # 符号表
  STRTAB: ... # 字符串表
  RELA: ...    # 重定位表
```

**链接的处理过程:**

1. **程序启动:** 当系统启动 `app` 进程时，内核会加载 `app` 的可执行文件。
2. **Dynamic Linker 启动:**  内核会注意到 `app` 依赖于动态链接器 (通常是 `/system/bin/linker64` 或 `/system/bin/linker`)，并首先加载和执行动态链接器。
3. **加载依赖库:** 动态链接器会读取 `app` 的 ELF 头，找到其依赖的共享库 (例如 `libfoo.so`)。
4. **查找共享库:** 动态链接器会在预定义的路径 (例如 `/system/lib64`, `/vendor/lib64`) 中搜索 `libfoo.so`。
5. **加载共享库:** 找到 `libfoo.so` 后，动态链接器会将其加载到 `app` 进程的地址空间中。
6. **符号解析和重定位:**
   * 动态链接器会解析 `app` 中对 `libfoo.so` 中符号的引用。
   * 它会读取 `libfoo.so` 的 `.dynamic` 段中的符号表 (`SYMTAB`) 和字符串表 (`STRTAB`) 来查找符号的地址。
   * 它会读取重定位表 (`RELA`)，根据加载地址调整 `libfoo.so` 和 `app` 中的地址引用。例如，如果 `app` 调用了 `libfoo.so` 中的 `function_a`，动态链接器会将调用指令的目标地址修改为 `function_a` 在加载后的实际地址。
7. **控制权转移:**  完成所有必要的链接操作后，动态链接器会将控制权转移给 `app` 的入口点。

**假设输入与输出 (针对测试用例):**

**`TEST(sys_prctl, bug_20017123)`:**

* **假设输入:**
    * 系统页面大小为 4096 字节。
    * 进程有足够的连续虚拟地址空间来分配 3 个页面。
* **预期输出:**
    * `mmap` 成功，返回一个有效的内存地址 `p`。
    * `mprotect` 成功，不会返回错误。
    * `prctl` 成功，返回 0。
    * 读取 `/proc/self/maps` 文件后，解析出的内存映射区域之间没有重叠，即每个内存区域的起始地址都大于等于前一个区域的结束地址。
    * `munmap` 成功，返回 0。

**`TEST(sys_prctl, pr_cap_ambient)`:**

* **假设输入:**
    * 运行测试的内核支持 ambient capabilities (通常是较新的 Linux 内核版本)。
    * 运行测试的进程没有 `CAP_SYS_ADMIN` 权限。
* **预期输出:**
    * `uname` 成功，返回 0。
    * `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, ...)` 成功，返回 0。
    * `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, ...)` 失败，返回 -1，`errno` 设置为 `EPERM` (Operation not permitted)。
    * `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_SYS_ADMIN, ...)` 返回 0，表示当前没有设置 ambient `CAP_SYS_ADMIN`。
    * `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, ...)` 成功，返回 0 (即使没有设置，降低也是允许的)。
    * 尝试操作无效的 capability (如 `ULONG_MAX`) 会失败，返回 -1，`errno` 设置为 `EINVAL` (Invalid argument)。

**用户或编程常见的使用错误**

1. **`mmap` 后忘记 `munmap`:**  这会导致内存泄漏。如果分配了大量的内存而没有释放，最终可能导致系统资源耗尽。
   ```c++
   void* p = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   // ... 使用 p ...
   // 忘记 munmap(p, 1024);
   ```

2. **`prctl` 使用错误的参数:** `prctl` 的第一个参数指定了要执行的操作，后续参数的含义取决于第一个参数。使用错误的参数会导致 `prctl` 调用失败并返回 -1，`errno` 会指示错误类型 (`EINVAL` 通常表示参数无效)。
   ```c++
   // 错误的 prctl 调用，参数数量或类型不匹配
   int result = prctl(PR_SET_PDEATHSIG, 15); // 需要更多的参数
   if (result == -1) {
       perror("prctl failed"); // 可能会输出 "prctl failed: Invalid argument"
   }
   ```

3. **在不合适的上下文中操作 capabilities:**  提升 ambient capabilities 通常需要进程拥有相应的 effective capabilities。尝试在没有足够权限的情况下提升 ambient capabilities 会失败。
   ```c++
   // 假设进程没有 CAP_SYS_ADMIN 权限
   if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0) == -1) {
       perror("Failed to raise ambient capability"); // 输出 "Failed to raise ambient capability: Operation not permitted"
   }
   ```

4. **误解内存保护标志:**  错误地设置 `mprotect` 的保护标志可能导致程序崩溃或安全漏洞。例如，尝试写入一个只读的内存区域会导致 SIGSEGV 信号。

**Android Framework 或 NDK 如何到达这里**

让我们以 `bug_20017123` 测试中涉及的 `PR_SET_VMA_ANON_NAME` 为例，说明 Android Framework 或 NDK 如何最终调用到 `prctl`：

1. **Android Framework/NDK 代码:**  Android Framework 或 NDK 中的某些组件可能需要为匿名内存区域设置一个名称以便于调试或监控。例如，ART 虚拟机可能会在分配堆内存时这样做。

2. **调用 Bionic Libc 函数:**  这些组件会调用 Bionic Libc 提供的 `syscall` 函数来直接进行系统调用。或者，它们可能会使用 Bionic Libc 中封装好的函数（如果存在，但 `prctl` 通常直接使用 `syscall`）。

3. **`syscall` 函数:** Bionic Libc 的 `syscall` 函数是一个汇编语言实现的函数，它负责将系统调用号和参数放入寄存器中，然后执行 `syscall` 指令，陷入内核。

4. **内核处理 `prctl` 系统调用:**
   * 内核接收到 `prctl` 系统调用后，会根据第一个参数 (例如 `PR_SET_VMA`) 分发到相应的处理函数。
   * 对于 `PR_SET_VMA` 和 `PR_SET_VMA_ANON_NAME`，内核会查找进程的内存映射，找到匹配的匿名 VMA，并将指定的名称存储起来。

**Frida Hook 示例调试步骤**

可以使用 Frida Hook 来拦截和观察 `prctl` 系统调用的执行过程。以下是一个使用 Python 和 Frida 的示例，用于 Hook `prctl` 系统调用，特别是当 `option` 参数为 `PR_SET_VMA_ANON_NAME` 时：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    package_name = "目标应用的包名" # 替换为你要调试的应用的包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"未找到进程：{package_name}")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "syscall"), {
        onEnter: function(args) {
            const syscall_number = args[0].toInt32();
            const PR_SET_VMA = 0x36; // Linux 中 PR_SET_VMA 的值，可能需要根据架构调整
            const PR_SET_VMA_ANON_NAME = 2; // PR_SET_VMA 的子选项

            if (syscall_number === 157) { // 157 是 prctl 的系统调用号，可能需要根据架构调整
                const option = args[1].toInt32();
                if (option === PR_SET_VMA) {
                    const suboption = args[2].toInt32();
                    if (suboption === PR_SET_VMA_ANON_NAME) {
                        const addr = args[3];
                        const len = args[4].toInt32();
                        const namePtr = args[5];
                        const name = Memory.readUtf8String(namePtr);
                        send({
                            type: "prctl",
                            option: "PR_SET_VMA_ANON_NAME",
                            address: addr.toString(),
                            length: len,
                            name: name
                        });
                    }
                }
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] 脚本已加载，正在监听 prctl 系统调用...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida-Tools (`pip install frida-tools`).
2. **连接 Android 设备:** 确保你的 Android 设备通过 USB 连接到电脑，并且 adb 可用。设备需要 root 权限并运行 frida-server。
3. **替换包名:** 将 `目标应用的包名` 替换为你要监控的 Android 应用的实际包名。
4. **运行脚本:** 运行 Python 脚本。
5. **操作应用:**  在 Android 设备上操作目标应用，如果应用中使用了 `prctl` 并设置了匿名 VMA 的名称，Frida 脚本会捕获到相关信息并输出到控制台。

这个 Frida 脚本会拦截 `syscall`，检查系统调用号是否为 `prctl` (通常是 157，但可能因架构而异)，然后检查 `option` 参数是否为 `PR_SET_VMA`，以及 `suboption` 是否为 `PR_SET_VMA_ANON_NAME`。如果是，它会读取内存中的地址、长度和名称，并通过 Frida 的 `send` 函数发送到 Python 脚本，从而实现监控。

希望这个详细的解释能够帮助你理解 `bionic/tests/sys_prctl_test.cpp` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/sys_prctl_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "android-base/file.h"
#include "android-base/strings.h"

#include "utils.h"

// http://b/20017123.
TEST(sys_prctl, bug_20017123) {
  size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void* p = mmap(NULL, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, p);
  ASSERT_EQ(0, mprotect(p, page_size, PROT_NONE));
  ASSERT_NE(-1, prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p, page_size * 3, "anonymous map space"));
  // Now read the maps and verify that there are no overlapped maps.
  std::string file_data;
  ASSERT_TRUE(android::base::ReadFileToString("/proc/self/maps", &file_data));

  uintptr_t last_end = 0;
  std::vector<std::string> lines = android::base::Split(file_data, "\n");
  for (size_t i = 0; i < lines.size(); i++) {
    if (lines[i].empty()) {
      continue;
    }
    uintptr_t start;
    uintptr_t end;
    ASSERT_EQ(2, sscanf(lines[i].c_str(), "%" SCNxPTR "-%" SCNxPTR " ", &start, &end))
        << "Failed to parse line: " << lines[i];
    // This will never fail on the first line, so no need to do any special checking.
    ASSERT_GE(start, last_end)
        << "Overlapping map detected:\n" << lines[i -1] << '\n' << lines[i] << '\n';
    last_end = end;
  }

  ASSERT_EQ(0, munmap(p, page_size * 3));
}

TEST(sys_prctl, pr_cap_ambient) {
  const std::string caps_sha =
      "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/"
      "?id=58319057b7847667f0c9585b9de0e8932b0fdb08";
  const std::string caps_typo_sha =
      "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/"
      "?id=b7f76ea2ef6739ee484a165ffbac98deb855d3d3";

  utsname u = {};
  ASSERT_EQ(0, uname(&u));

  errno = 0;
  auto err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
  EXPECT_EQ(0, err);
  // EINVAL -> unrecognized prctl option
  ASSERT_NE(EINVAL, errno) << "kernel (" << u.release << ") missing required commits:\n"
                           << caps_sha << "\n"
                           << caps_typo_sha << "\n";

  // Unprivileged processes shouldn't be able to raise CAP_SYS_ADMIN,
  // but they can check or lower it
  err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0);
  EXPECT_EQ(-1, err);
  EXPECT_ERRNO(EPERM);

  err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_SYS_ADMIN, 0, 0);
  EXPECT_EQ(0, err);

  err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0);
  EXPECT_EQ(0, err);

  // ULONG_MAX isn't a legal cap
  err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, ULONG_MAX, 0, 0);
  EXPECT_EQ(-1, err);
  EXPECT_ERRNO(EINVAL);

  err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, ULONG_MAX, 0, 0);
  EXPECT_EQ(-1, err);
  EXPECT_ERRNO(EINVAL);

  err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, ULONG_MAX, 0, 0);
  EXPECT_EQ(-1, err);
  EXPECT_ERRNO(EINVAL);
}

"""

```