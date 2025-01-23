Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understanding the Context:** The first and most crucial step is to understand the purpose of the file and its location. The prompt clearly states it's `bionic/tests/memtag_stack_test.cpp` within the `bionic` project of Android. `bionic` is identified as Android's C library, math library, and dynamic linker. This immediately tells us the tests are related to core system functionalities. The `memtag_stack_test` part strongly suggests it's testing memory tagging, specifically related to the stack.

2. **High-Level Overview of the Code:**  A quick scan reveals the use of Google Test (`gtest`). There's a parameterized test fixture `MemtagStackTest`. The core logic is within the `TEST_P` macro. Conditional compilation using `#if defined(__BIONIC__) && defined(__aarch64__)` indicates it's specific to Android on ARM64 architecture. The code executes an external helper program.

3. **Dissecting the `TEST_P` Function:**

   * **Architecture Check:** The `if (!mte_supported()) { GTEST_SKIP() << "MTE unsupported"; }` line is a crucial check. `mte_supported()` hints at Memory Tagging Extension (MTE), a hardware feature for memory safety. The test skips if MTE isn't supported.
   * **Parameterization:** `std::get<1>(GetParam())` suggests the test is parameterized. The boolean value likely controls something, and the code confirms this by using it to choose between "stack_tagging_static_helper" and "stack_tagging_helper". This implies testing both statically and dynamically linked helper executables.
   * **Helper Execution:**  The core action is executing an external helper program. `ExecTestHelper` is a custom utility (we infer this because it's not standard C++). It sets up arguments (`SetArgs`) and then uses `execve` (or potentially `execl` within the helper) to run the helper.
   * **Arguments to Helper:** The helper receives an argument determined by `std::get<0>(GetParam())`. Looking at `INSTANTIATE_TEST_SUITE_P`, we see the possible values: "vfork_execve", "vfork_execl", "vfork_exit", "longjmp", "longjmp_sigaltstack", "android_mallopt", "exception_cleanup". These strings strongly suggest the *types* of stack operations or scenarios being tested.

4. **Understanding the Test Scenarios (from `INSTANTIATE_TEST_SUITE_P`):**

   * **`vfork_execve`, `vfork_execl`:** These relate to creating a new process but sharing the address space initially. They are crucial for testing how MTE handles memory sharing and potential tag inheritance or isolation during `execve`.
   * **`vfork_exit`:** Tests how MTE behaves when a `vfork`ed child process exits.
   * **`longjmp`, `longjmp_sigaltstack`:**  These test non-local jumps, potentially across different stack frames. `sigaltstack` involves a separate stack for signal handlers. Testing MTE with these is vital because stack pointers and tag associations might need careful handling.
   * **`android_mallopt`:**  This directly interacts with the memory allocator (`malloc`). It's testing if MTE interacts correctly with memory allocation flags or options.
   * **`exception_cleanup`:**  This tests how MTE works with C++ exceptions and stack unwinding. Memory tagged on the stack during exception handling needs to be managed correctly.

5. **Inferring the Helper Program's Role:**  The helper program, given the arguments, likely performs specific actions related to the scenarios mentioned above. For instance, the "longjmp" helper probably sets up a stack frame, sets a jump buffer, and then performs a `longjmp`. The MTE mechanism should detect if the stack is accessed incorrectly after the jump.

6. **Dynamic Linker Implications:** The test uses both static and dynamic linking for the helper. This directly involves the dynamic linker. The linker is responsible for loading shared libraries and resolving symbols. The test likely ensures MTE works correctly in both scenarios. The dynamic linker needs to be aware of MTE and handle any necessary tag propagation or initialization when loading libraries.

7. **Connecting to Android Framework/NDK:** This test is part of the core `bionic` library. The Android Framework and NDK ultimately rely on `bionic`. If memory tagging on the stack has issues at this level, it would affect everything built upon it. The framework might use these low-level functionalities implicitly. For example, when an app makes a system call, the framework might involve stack operations that this test covers.

8. **Frida Hooking (Hypothetical):**  To debug, one could use Frida to hook functions within the helper program or even within `bionic` itself. Points of interest would be:
    * `execve`: To see the arguments and environment.
    * `vfork`, `fork`: To inspect process creation.
    * `longjmp`, `siglongjmp`: To understand stack manipulation.
    * `malloc`, `free`, `android_mallopt`: To observe memory allocation with MTE.
    * Functions related to MTE itself (if they were public/hookable).

9. **Anticipating Common Errors:** Based on the scenarios, potential errors include:
    * Accessing memory after a `longjmp` without proper tag restoration.
    * Incorrect tag propagation during `vfork`/`execve`.
    * Memory corruption due to incorrect tagging in exception handling.
    * Issues with static vs. dynamic linking and MTE initialization.

10. **Structuring the Answer:**  Finally, organize the findings into clear sections as requested by the prompt: Functionality, Relationship to Android, Libc Functions, Dynamic Linker, Logical Reasoning, Common Errors, and Android Framework/NDK with Frida. Use clear and concise language, providing examples where necessary.

This systematic approach of understanding the context, dissecting the code, inferring the purpose, and connecting it to the broader system allows for a comprehensive analysis of the provided test file.
这个C++源代码文件 `bionic/tests/memtag_stack_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试内存标签（Memory Tagging，MTE）功能在堆栈上的行为。 内存标签是一种硬件辅助的内存安全特性，用于检测内存访问错误，例如越界访问或使用已释放的内存。

下面详细列举其功能和相关说明：

**1. 功能概述:**

* **测试 MTE 在堆栈上的功能:** 该测试的主要目的是验证当启用内存标签功能时，各种堆栈操作（如函数调用、返回、异常处理、非本地跳转等）是否能正确地与内存标签机制协同工作。
* **测试静态链接和动态链接场景:** 通过参数化测试，该测试可以分别针对静态链接和动态链接的辅助程序进行测试，以确保 MTE 在不同链接方式下都能正常工作。
* **测试多种堆栈操作场景:**  测试覆盖了多种可能涉及堆栈操作的场景，例如 `vfork` 后执行新程序、非本地跳转 (`longjmp`)、使用信号处理栈 (`sigaltstack`)、以及与内存分配器 (`android_mallopt`) 的交互和异常处理。

**2. 与 Android 功能的关系及举例说明:**

该测试直接关系到 Android 系统的内存安全和稳定性。MTE 是一项重要的安全特性，它可以帮助开发者尽早发现和修复内存错误，从而提高应用程序和系统的安全性。

* **提高系统安全性:**  MTE 能够检测到可能导致崩溃或安全漏洞的内存访问错误。例如，如果一个函数错误地访问了超出其栈帧的内存，MTE 可以捕获到这种行为，防止潜在的攻击。
* **辅助应用开发:** 开发者可以使用支持 MTE 的设备来更有效地调试应用程序中的内存问题。当出现内存访问错误时，MTE 可以提供更精确的错误报告，帮助开发者快速定位问题。
* **支持 NDK 开发:** 对于使用 NDK 进行 Native 开发的应用程序，MTE 同样有效。该测试确保了 Bionic 库的 MTE 功能能够正确地支持 Native 代码的堆栈操作。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

该测试文件本身并没有直接实现 libc 函数，而是通过 `execve` 等系统调用来执行外部的辅助程序。这些辅助程序会调用各种 libc 函数来模拟不同的堆栈操作。以下是一些相关 libc 函数的解释，以及在这个测试场景下的作用：

* **`execve(const char *pathname, char *const argv[], char *const envp[])`:**  这是一个 POSIX 标准的系统调用，用于执行一个新的程序。
    * **功能实现:** `execve` 会停止当前进程的执行，加载并运行由 `pathname` 指定的新程序。`argv` 数组包含了传递给新程序的命令行参数，`envp` 数组包含了新程序的环境变量。
    * **测试中的作用:** `execve` 用于启动辅助测试程序 (`stack_tagging_helper` 或 `stack_tagging_static_helper`)，并将不同的参数传递给它，以指示辅助程序执行特定的堆栈操作。
* **`vfork()`:**  这是一个系统调用，用于创建一个新的进程。与 `fork()` 不同的是，`vfork()` 创建的子进程会共享父进程的内存空间和调用栈，直到子进程调用 `execve` 或 `_exit`。
    * **功能实现:**  `vfork()` 的实现通常比 `fork()` 更轻量级，因为它避免了复制父进程的地址空间。
    * **测试中的作用:**  测试用例 "vfork_execve" 和 "vfork_execl" 使用 `vfork` 创建子进程，然后在子进程中执行新的程序。这可以测试 MTE 在 `vfork` 后的 `execve` 操作中，堆栈标签是否能正确处理。
* **`execl(const char *pathname, const char *arg, ...)`:** 类似于 `execve`，但参数传递方式不同，参数是逐个列出的。
    * **功能实现:** 最终会调用到 `execve`。
    * **测试中的作用:**  测试用例 "vfork_execl" 使用 `execl` 在 `vfork` 创建的子进程中执行新的程序。
* **`exit(int status)`:**  用于终止当前进程的执行。
    * **功能实现:**  `exit` 会进行一些清理工作（例如刷新缓冲区，关闭文件描述符），然后将控制权返回给操作系统。
    * **测试中的作用:** 测试用例 "vfork_exit" 使用 `exit` 在 `vfork` 创建的子进程中退出，测试 MTE 在这种场景下的行为。
* **`longjmp(jmp_buf env, int val)` 和 `setjmp(jmp_buf env)`:**  用于实现非本地跳转。`setjmp` 保存当前的执行环境到 `env` 中，`longjmp` 从 `env` 中恢复执行环境，使得程序跳转到之前 `setjmp` 调用的位置。
    * **功能实现:** `setjmp` 将当前的栈指针、程序计数器、以及其他重要的寄存器值保存到 `jmp_buf` 结构体中。`longjmp` 恢复这些值，从而实现跳转。
    * **测试中的作用:** 测试用例 "longjmp" 和 "longjmp_sigaltstack" 用于测试 MTE 在非本地跳转场景下的行为，例如跳转后栈帧的标签是否仍然有效。
* **`android_mallopt(int option, int value)`:**  这是一个 Android 特有的函数，用于控制 Bionic 内存分配器的行为。
    * **功能实现:** 它允许调整内存分配器的各种参数，例如 trim threshold, arena size 等。
    * **测试中的作用:** 测试用例 "android_mallopt" 可能用于测试当内存分配器的行为被修改时，MTE 在堆栈上的行为是否仍然正确。
* **异常处理 (try-catch 等):** C++ 的异常处理机制涉及堆栈的展开 (stack unwinding)。当抛出异常时，运行时系统会逐帧回溯堆栈，调用析构函数清理资源，直到找到匹配的 `catch` 块。
    * **功能实现:**  编译器会生成代码来维护堆栈展开所需的信息。运行时系统会利用这些信息来执行堆栈展开。
    * **测试中的作用:** 测试用例 "exception_cleanup" 用于测试 MTE 在异常处理的堆栈展开过程中是否能正确地工作，例如确保被释放的栈帧上的内存不再被访问。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

当测试涉及到动态链接时（即 `is_static` 为 `false` 的情况），会加载 `stack_tagging_helper` 动态链接库 (SO)。

**SO 布局样本 (`stack_tagging_helper.so`)：**

```
ELF Header:
  Magic:   7f 45 4c 46 64 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x... (通常不需要，动态库不作为程序入口)
  Start of program headers:          64 (bytes into file)
  Start of section headers:          ...
  Flags:                             0x...
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         ...
  Size of section headers:           64 (bytes)
  Number of section headers:         ...
  String table index:                ...

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags  Align
  PHDR           0x0000000000000040 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x0000000000000240 0x0000000000000240 R      0x8
  INTERP         0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x000000000000001c 0x000000000000001c R      0x1
      [Requesting program interpreter: /system/bin/linker64]
  LOAD           0x0000000000000000 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx R E    0x1000
  LOAD           0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx RW     0x1000
  DYNAMIC        0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000xxxxxxxxx 0x00000000000001e8 0x00000000000001e8 RW     0x8

Section Headers:
  [Nr] Name              Type             Address           Offset             Size              EntSize          Flags  Link  Info  Align
  ...
  [ .text ]           PROGBITS         xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx 00               AX       0     0     16
  [ .data ]           PROGBITS         xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx 00               WA       0     0     8
  [ .bss ]            NOBITS           xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx 00               WA       0     0     8
  [ .dynamic ]        DYNAMIC          xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx 16               WA       6     0     8
  [ .dynsym ]         DYNSYM           xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx 24               5     1     8
  [ .dynstr ]         STRTAB           xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx 00               0     0     1
  ...
```

**链接处理过程:**

1. **加载器 (Loader):** 当父进程（即运行测试的进程）调用 `execve` 并指定执行 `stack_tagging_helper` 时，如果 `stack_tagging_helper` 是一个动态链接的可执行文件或者依赖于动态库，内核会将控制权交给动态链接器 (`/system/bin/linker64`)。
2. **解析 ELF Header 和 Program Headers:** 动态链接器首先解析 `stack_tagging_helper` 的 ELF 头和程序头，以了解其依赖关系和内存布局。
3. **加载依赖库:**  动态链接器会根据 `DYNAMIC` 段中的信息，找到 `stack_tagging_helper` 所依赖的其他动态库（例如 Bionic 库自身）。
4. **地址空间分配:**  动态链接器会在进程的地址空间中为 `stack_tagging_helper` 及其依赖的库分配内存区域。为了避免地址冲突，Android 使用地址空间布局随机化 (ASLR)。
5. **重定位 (Relocation):** 由于动态库在不同的进程中加载的地址可能不同，动态链接器需要修改代码和数据段中对外部符号的引用，使其指向正确的内存地址。这通过处理 ELF 文件的重定位段完成。
6. **符号解析 (Symbol Resolution):**  动态链接器会解析 `stack_tagging_helper` 及其依赖库中的符号表，将函数调用和全局变量引用绑定到实际的地址。
7. **执行初始化代码:**  每个动态库可以有 `.init` 和 `.fini` 段，包含初始化和清理代码。动态链接器会在完成链接后执行所有已加载库的初始化代码。

**在这个测试中，动态链接的处理过程确保了 `stack_tagging_helper` 能够正确地调用 Bionic 库中的函数，并且 MTE 功能在动态链接的场景下也能正常工作。**  例如，如果 `stack_tagging_helper` 调用了 `malloc`，动态链接器会确保调用的是 Bionic 库中的 `malloc` 实现。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

这个测试文件本身是一个测试框架，它并没有直接的 "输入" 和 "输出" 的概念。它的输入是通过 `INSTANTIATE_TEST_SUITE_P` 定义的参数组合，输出是 Google Test 框架生成的测试结果（通过/失败）。

**假设的辅助程序 (`stack_tagging_helper`) 的行为和预期输出：**

假设 "longjmp" 测试用例被执行，且辅助程序 `stack_tagging_helper` 的 "longjmp" 模式代码如下：

```c++
#include <iostream>
#include <csetjmp>
#include <stdexcept>

jmp_buf buf;

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: helper <mode>" << std::endl;
    return 1;
  }

  if (std::string(argv[1]) == "longjmp") {
    int val = setjmp(buf);
    if (val == 0) {
      // 首次执行，保存环境并跳转
      int stack_var = 42;
      longjmp(buf, 1);
      // 这里的代码不应该被执行
      std::cout << "Error: Should not reach here!" << std::endl;
      return 1;
    } else {
      // 从 longjmp 返回
      std::cout << "longjmped back, val = " << val << std::endl;
      return 0;
    }
  }
  // ... 其他模式的处理
  return 0;
}
```

**假设输入:**

* 测试进程执行 `execve`，启动 `stack_tagging_helper`。
* 传递给 `stack_tagging_helper` 的参数是 `"longjmp"`。
* 假设 MTE 功能已启用。

**预期输出:**

如果 MTE 功能正常工作，`longjmp` 操作应该能够正确地恢复堆栈状态，并且程序能够正常输出 "longjmped back, val = 1"。  Google Test 框架会报告该测试用例通过。

**如果 MTE 检测到错误（例如，`longjmp` 后访问了错误的堆栈内存），MTE 机制应该会触发错误信号（例如 SIGSEGV），导致程序崩溃。**  在这种情况下，Google Test 框架会报告该测试用例失败。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **在启用了 MTE 的情况下，访问越界堆栈内存:**  这是 MTE 最主要检测的错误类型。例如，一个缓冲区溢出漏洞，程序尝试写入超过分配给局部变量的内存空间。MTE 会检测到标签不匹配，并触发错误。
* **在 `longjmp` 后，访问在跳转前已经失效的局部变量:**  例如，在 `setjmp` 之前声明的局部变量在 `longjmp` 返回后仍然可以访问，但在 `setjmp` 之后声明的局部变量在 `longjmp` 返回后其值是不确定的，访问这些变量可能导致未定义的行为，MTE 可以帮助检测这种潜在的问题。
* **在 `vfork` 后，父子进程同时修改共享的堆栈内存:** 虽然 `vfork` 后子进程会立即执行 `execve` 或 `exit`，但在某些情况下，如果父子进程都尝试修改共享的堆栈内存，可能会导致不可预测的行为。MTE 可以在这种情况下检测到潜在的冲突。
* **在异常处理过程中，访问已经被析构的对象:**  如果在 `catch` 块中错误地访问了在 `try` 块中抛出异常时已经被析构的对象的成员，MTE 可能会检测到对已释放内存的访问。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

虽然这个测试是在 Bionic 库的测试中，但理解 Android Framework 或 NDK 如何最终涉及到 Bionic 库的内存管理是重要的。

1. **应用程序 (Java/Kotlin 或 Native):** 无论是 Java/Kotlin 编写的 Android 应用，还是通过 NDK 编写的 Native 应用，最终都会调用到 Android 系统的各种 API。
2. **Android Framework (Java 层):** 对于 Java/Kotlin 应用，当它们执行某些操作（例如分配内存、创建线程、进行网络请求等）时，Android Framework 会将这些请求转换为底层的 Native 调用。
3. **System Services (Native 层):** Android Framework 的许多核心功能是由 Native 层的系统服务实现的，例如 `SurfaceFlinger`、`AudioFlinger`、`Zygote` 等。这些服务通常使用 C++ 编写，并直接与 Bionic 库交互。
4. **NDK (Native Development Kit):**  使用 NDK 开发的应用程序可以直接调用 Bionic 库提供的 C/C++ 标准库函数以及 Android 特定的 API。
5. **Bionic 库:**  无论是 Framework 的系统服务还是 NDK 应用，最终的内存分配、线程管理、系统调用等操作都会通过 Bionic 库来实现。例如，当一个 Native 代码分配内存时，会调用 `malloc`，这个 `malloc` 的实现就在 Bionic 库中。 当涉及到堆栈操作时，例如函数调用、异常处理等，也都是 Bionic 库的运行时环境在管理。

**Frida Hook 示例：**

假设我们想观察当一个 NDK 应用调用 `malloc` 时，是否会涉及到 MTE 相关的操作。可以使用 Frida Hook `malloc` 函数：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
  onEnter: function(args) {
    var size = args[0].toInt();
    console.log("[+] malloc called, size: " + size);
    // 这里可以添加更多逻辑来检查 MTE 状态或相关信息
  },
  onLeave: function(retval) {
    console.log("[+] malloc returned, address: " + retval);
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

* **`frida.attach(package_name)`:**  连接到目标 Android 应用程序的进程。
* **`Module.findExportByName("libc.so", "malloc")`:**  在 `libc.so` 库中查找 `malloc` 函数的地址。
* **`Interceptor.attach(...)`:**  拦截 `malloc` 函数的调用。
* **`onEnter`:**  在 `malloc` 函数被调用之前执行，可以获取传递给 `malloc` 的参数（例如要分配的内存大小）。
* **`onLeave`:**  在 `malloc` 函数返回之后执行，可以获取 `malloc` 的返回值（分配的内存地址）。
* **`console.log(...)`:**  在 Frida 的控制台中打印信息。

通过这个 Frida Hook 示例，你可以观察到 NDK 应用中 `malloc` 的调用，并且可以在 `onEnter` 和 `onLeave` 中添加更多的 Hook 逻辑来检查 MTE 的状态，例如读取相关的系统属性或调用与 MTE 相关的 Bionic 内部函数（如果可知）。

**要调试 `memtag_stack_test.cpp` 中的步骤，你可以使用类似的 Frida 技术来 Hook `execve` 系统调用，观察测试程序和辅助程序的执行流程和参数。**  你还可以尝试 Hook `longjmp`、`setjmp` 等函数来深入理解非本地跳转场景下 MTE 的行为。

请注意，直接 Hook Bionic 内部的 MTE 相关函数可能比较复杂，因为这些函数可能没有公开的符号，并且其实现细节可能会因 Android 版本而异。但通过 Hook 标准的 libc 函数和系统调用，仍然可以有效地理解 MTE 在更高层次上的行为。

### 提示词
```
这是目录为bionic/tests/memtag_stack_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2022 The Android Open Source Project
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

#include <tuple>

#include <gtest/gtest.h>

#if defined(__BIONIC__)
#include "gtest_globals.h"
#include "platform/bionic/mte.h"
#include "utils.h"
#endif

class MemtagStackTest : public testing::TestWithParam<std::tuple<const char*, bool>> {};

TEST_P(MemtagStackTest, test) {
#if defined(__BIONIC__) && defined(__aarch64__)
  if (!mte_supported()) {
    GTEST_SKIP() << "MTE unsupported";
  }
  bool is_static = std::get<1>(GetParam());
  std::string helper =
      GetTestLibRoot() + (is_static ? "/stack_tagging_static_helper" : "/stack_tagging_helper");
  const char* arg = std::get<0>(GetParam());
  ExecTestHelper eth;
  eth.SetArgs({helper.c_str(), arg, nullptr});
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, "");
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}

INSTANTIATE_TEST_SUITE_P(
    , MemtagStackTest,
    testing::Combine(testing::Values("vfork_execve", "vfork_execl", "vfork_exit", "longjmp",
                                     "longjmp_sigaltstack", "android_mallopt", "exception_cleanup"),
                     testing::Bool()),
    [](const ::testing::TestParamInfo<MemtagStackTest::ParamType>& info) {
      std::string s = std::get<0>(info.param);
      if (std::get<1>(info.param)) s += "_static";
      return s;
    });
```