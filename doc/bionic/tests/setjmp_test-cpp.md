Response:
Let's break down the thought process for analyzing the `setjmp_test.cpp` file and generating the comprehensive Chinese response.

**1. Understanding the Core Goal:**

The request is to analyze a C++ test file for `setjmp` and related functions within the Android Bionic library. The key is to understand what the tests do, how they relate to Android, and delve into the implementation details of the involved libc functions.

**2. Initial Scan and Identification of Key Functions:**

The first step is to quickly scan the code and identify the core functions being tested. This immediately reveals:

* `setjmp` and `longjmp`
* `_setjmp` and `_longjmp`
* `sigsetjmp` and `siglongjmp`

The presence of `gtest/gtest.h` confirms this is a unit test file using the Google Test framework.

**3. Analyzing Individual Tests:**

The next step is to examine each `TEST` block individually to understand its purpose:

* **`setjmp_smoke`:** A basic test to see if `setjmp` and `longjmp` work. It checks if `longjmp` jumps back and returns the correct value.
* **`_setjmp_smoke`:**  Similar to `setjmp_smoke`, but for `_setjmp` and `_longjmp`.
* **`sigsetjmp_0_smoke` and `sigsetjmp_1_smoke`:** Test `sigsetjmp` with the `savesigs` argument set to 0 and 1, respectively. This hints at the signal mask saving behavior.
* **`_setjmp_signal_mask`:** Specifically tests if `_setjmp` and `_longjmp` save/restore the signal mask. The code explicitly sets and checks the mask.
* **`setjmp_signal_mask`:** Tests signal mask saving/restoring for `setjmp`/`longjmp`. The `#ifdef __BIONIC__` is crucial for understanding the Bionic-specific behavior.
* **`sigsetjmp_0_signal_mask` and `sigsetjmp_1_signal_mask`:** Test signal mask handling for `sigsetjmp` with `savesigs` 0 and 1.
* **`setjmp_fp_registers`:**  Focuses on whether floating-point registers are correctly saved and restored by `setjmp`/`longjmp` on specific architectures (ARM, AArch64, RISC-V). The `#ifdef` blocks are essential.
* **`setjmp_cookie` and `setjmp_cookie_checksum`:** These "Death Tests" check for stack corruption detection mechanisms (cookies) when using `longjmp`. They specifically manipulate the `jmp_buf` structure to trigger failures.
* **`setjmp_stack`:** A basic test to ensure `longjmp` can jump across function calls.
* **`bug_152210274`:**  A more complex test involving multiple threads and signals to verify the robustness of `setjmp`/`longjmp` under concurrency and signal handling. The `#ifdef __BIONIC__` indicates it's a Bionic-specific test.

**4. Identifying Relationships to Android:**

Throughout the analysis, connections to Android's functionality need to be made. This involves:

* **Bionic as the C library:** Recognize that these tests are *for* Bionic, meaning they directly test core Android functionality.
* **Signal Handling:**  Android relies heavily on signals for various purposes (process management, inter-process communication). The tests involving signal masks are directly relevant.
* **NDK Usage:**  Developers using the NDK directly interact with the C library, including `setjmp`/`longjmp`, for error handling, implementing state machines, etc.

**5. Delving into `libc` Function Implementations:**

This is the most technical part. For each function (`setjmp`, `longjmp`, etc.), the thought process involves:

* **General Functionality:**  What is the purpose of the function?
* **Mechanism:** How does it achieve its purpose?  This often involves describing how the stack frame, registers (including special registers like the stack pointer and instruction pointer), and potentially signal masks are manipulated. Assembly language knowledge is helpful here (though not strictly required for a high-level explanation).
* **Differences:**  Highlight the differences between related functions (e.g., `setjmp` vs. `_setjmp`, or the `savesigs` argument of `sigsetjmp`).
* **Platform Dependencies:** Emphasize how the implementation might vary across architectures (like the floating-point register saving in the tests).

**6. Addressing Dynamic Linking:**

The prompt specifically asks about the dynamic linker. Here, the connection is somewhat indirect:

* **`libc.so`:**  The `setjmp` family of functions resides within `libc.so`, which is a dynamically linked library.
* **General Linking Process:** Explain the basics of how the dynamic linker resolves symbols at runtime.
* **SO Layout (Conceptual):**  Provide a simplified representation of `libc.so`'s structure, highlighting the `.text` (code), `.data` (global variables), and `.bss` (uninitialized data) sections. Mention the GOT and PLT for function calls.

**7. Crafting Examples (Usage Errors, Frida Hook):**

* **Common Errors:** Think about typical mistakes developers might make when using `setjmp`/`longjmp`, like incorrect usage across threads or after stack frames have been unwound.
* **Frida Hook:**  Devise a simple Frida script to intercept calls to `setjmp` and `longjmp`, logging arguments and return values. This demonstrates how to observe the functions in action.

**8. Structuring the Response:**

Organize the information logically using headings and subheadings to make it easy to read and understand. Follow the structure requested in the prompt.

**9. Language and Tone:**

Use clear and concise Chinese. Explain technical concepts in a way that is understandable without being overly simplistic. Maintain a helpful and informative tone.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on the code.
* **Correction:** Realize the prompt requires connecting the code to Android's broader context.
* **Initial thought:**  Only describe the *what* of each function.
* **Correction:** Include the *how* – the underlying mechanisms.
* **Initial thought:** Treat all `setjmp` variants the same.
* **Correction:**  Highlight the crucial differences, especially concerning signal masks.
* **Initial thought:** Skip the dynamic linking aspect since it's not directly tested in the code.
* **Correction:**  Recognize the implicit connection and provide a general explanation.

By following this systematic approach, breaking down the problem into smaller pieces, and continuously refining the understanding and explanation, a comprehensive and accurate response can be generated.
这个文件 `bionic/tests/setjmp_test.cpp` 是 Android Bionic 库中用于测试 `setjmp` 和相关函数的功能的源代码文件。它的主要功能是验证这些关键的 C 标准库函数在 Bionic 库中的实现是否正确和可靠。

**该文件的功能列表:**

1. **测试 `setjmp` 和 `longjmp` 的基本功能:** 验证 `setjmp` 能保存当前程序的执行上下文，而 `longjmp` 能恢复到之前 `setjmp` 保存的上下文。
2. **测试 `_setjmp` 和 `_longjmp` 的基本功能:**  与 `setjmp`/`longjmp` 类似，但行为上有一些细微差别，尤其是在信号掩码的处理上。
3. **测试 `sigsetjmp` 和 `siglongjmp` 的基本功能:** 验证在处理信号时的上下文保存和恢复，特别是关于信号掩码的处理。
4. **测试信号掩码的保存和恢复:**  重点测试 `setjmp`、`_setjmp` 和 `sigsetjmp` 在保存程序上下文时，对当前线程的信号掩码的处理方式。
5. **测试浮点寄存器的保存和恢复 (在特定架构上):** 验证在 ARM、AArch64 和 RISC-V 等架构上，`setjmp`/`longjmp` 是否正确地保存和恢复了浮点寄存器的状态。
6. **测试 `setjmp` 的 "cookie" 机制:**  验证 Bionic 库中为了防止 `longjmp` 跳转到无效的 `jmp_buf` 而引入的 cookie 机制。
7. **测试 `setjmp` 的栈完整性:**  通过跨函数调用 `longjmp` 来确保栈指针在跳转后保持正确。
8. **进行并发和信号处理的压力测试 (Bionic 特有):**  通过创建多个线程并发调用 `setjmp`/`longjmp`，并使用信号中断线程执行，来测试在复杂的并发场景下 `setjmp`/`longjmp` 的可靠性。

**与 Android 功能的关系及举例说明:**

`setjmp` 和 `longjmp` (以及它们的信号处理版本) 是 C 语言中用于实现非本地跳转的重要机制。它们在 Android 中扮演着以下角色：

* **错误处理和异常处理的替代方案:**  在某些情况下，尤其是在 C 代码中，`setjmp`/`longjmp` 可以作为一种简单的错误处理机制，允许程序在遇到严重错误时跳转到一个预先设定的安全点。例如，在解析复杂的数据结构时，如果遇到格式错误，可以 `longjmp` 到一个错误处理例程。
* **实现协作式多任务:** 在某些嵌入式或资源受限的环境中，`setjmp`/`longjmp` 可以用于实现简单的协作式多任务处理，手动切换不同任务的执行上下文。虽然 Android 主要使用线程进行并发，但在某些底层或特定的场景下可能仍然会用到。
* **在某些库或框架的内部实现中使用:**  一些底层的 C 库或框架可能会使用 `setjmp`/`longjmp` 来管理控制流，例如某些协程库或者状态机实现。

**举例说明:**

假设一个 Android 原生代码库需要解析一个复杂的配置文件。如果解析过程中遇到错误，它可以使用 `setjmp` 设置一个返回点，并在遇到错误时使用 `longjmp` 跳回该点，从而避免程序崩溃。

```c
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

jmp_buf error_handler;

void parse_config(const char* config_file) {
  if (setjmp(error_handler) == 0) {
    // 正常解析逻辑
    printf("开始解析配置文件: %s\n", config_file);
    // ... (解析配置文件的代码) ...
    if (/* 遇到错误 */) {
      fprintf(stderr, "解析错误，跳转到错误处理\n");
      longjmp(error_handler, 1); // 跳转并传递错误代码
    }
    printf("配置文件解析成功\n");
  } else {
    // 错误处理逻辑
    fprintf(stderr, "配置文件解析失败\n");
    // 进行清理或记录日志等操作
  }
}

int main() {
  parse_config("my_config.conf");
  return 0;
}
```

**详细解释每一个 libc 函数的功能是如何实现的:**

* **`setjmp(jmp_buf env)`:**
    * **功能:**  保存当前的程序执行上下文到 `jmp_buf` 结构体 `env` 中。这个上下文包括：
        * **程序计数器 (PC/IP):**  下一条要执行的指令的地址。
        * **栈指针 (SP):**  当前栈顶的地址。
        * **通用寄存器:**  CPU 中用于存储数据的寄存器的值。
        * **浮点寄存器 (在支持的架构上):**  存储浮点数的寄存器的值。
        * **信号掩码 (对于 `sigsetjmp` 且 `savesigs` 非零):**  当前线程阻塞的信号集合。
    * **实现:**  `setjmp` 的实现通常是平台相关的，并需要使用汇编语言。它会将当前 CPU 的关键寄存器的值（包括 PC、SP 和通用寄存器）保存到 `jmp_buf` 结构体中。`jmp_buf` 通常是一个数组，其大小和结构依赖于具体的架构和操作系统。`setjmp` 自身会返回 0。

* **`longjmp(jmp_buf env, int val)`:**
    * **功能:**  恢复之前通过 `setjmp` 保存的程序执行上下文。执行 `longjmp` 后，程序会跳转回调用 `setjmp` 的地方，并且 `setjmp` 的返回值会变成 `val`（如果 `val` 为 0，则返回 1）。
    * **实现:**  `longjmp` 的实现也高度依赖于平台。它会将 `jmp_buf` 结构体中保存的寄存器值恢复到 CPU 中，包括：
        * 将 `jmp_buf` 中保存的 PC 值加载到程序计数器，从而实现跳转。
        * 将 `jmp_buf` 中保存的 SP 值加载到栈指针，恢复栈的状态。
        * 将 `jmp_buf` 中保存的通用寄存器值加载到相应的寄存器。
        * 将 `jmp_buf` 中保存的浮点寄存器值加载到浮点寄存器 (如果保存了)。
        * 恢复信号掩码 (对于 `siglongjmp` 且相应的 `sigsetjmp` `savesigs` 非零)。
    * **关键点:** `longjmp` 不会像函数返回那样清理栈帧，而是直接修改程序计数器和栈指针，使得程序的执行流发生突变。

* **`_setjmp(jmp_buf env)` 和 `_longjmp(jmp_buf env, int val)`:**
    * **功能:**  类似于 `setjmp` 和 `longjmp`，但它们**不保存和恢复信号掩码**。这是它们与标准 `setjmp`/`longjmp` 的主要区别。
    * **实现:**  其实现与 `setjmp` 和 `longjmp` 类似，但省略了保存和恢复信号掩码的操作。由于不涉及信号掩码的处理，`_setjmp` 和 `_longjmp` 在某些平台上可能比 `setjmp` 和 `longjmp` 效率更高。

* **`sigsetjmp(sigjmp_buf env, int savesigs)`:**
    * **功能:**  是 `setjmp` 的一个变体，专门用于处理信号。它除了保存基本的执行上下文外，还可以根据 `savesigs` 参数决定是否保存当前的信号掩码。
        * 如果 `savesigs` 为非零值，则保存信号掩码。
        * 如果 `savesigs` 为零，则不保存信号掩码。
    * **实现:**  与 `setjmp` 类似，但如果 `savesigs` 非零，还会将当前线程的信号掩码保存到 `sigjmp_buf` 结构体中。

* **`siglongjmp(sigjmp_buf env, int val)`:**
    * **功能:**  是 `longjmp` 的一个变体，用于恢复由 `sigsetjmp` 保存的上下文。如果 `sigsetjmp` 在保存上下文时也保存了信号掩码（即 `savesigs` 非零），那么 `siglongjmp` 还会恢复该信号掩码。
    * **实现:**  与 `longjmp` 类似，但如果对应的 `sigsetjmp` 保存了信号掩码，`siglongjmp` 还会将 `sigjmp_buf` 中保存的信号掩码恢复到当前线程。

**涉及 dynamic linker 的功能 (间接涉及):**

`setjmp` 和相关的函数是 `libc.so` (Bionic C 库) 的一部分。当程序调用这些函数时，动态链接器负责在运行时将程序与 `libc.so` 链接起来，解析函数地址。

**SO 布局样本 (简化):**

```
libc.so:
    .text:  // 包含可执行代码
        setjmp:  // setjmp 函数的代码
        longjmp: // longjmp 函数的代码
        _setjmp: // _setjmp 函数的代码
        _longjmp: // _longjmp 函数的代码
        sigsetjmp: // sigsetjmp 函数的代码
        siglongjmp: // siglongjmp 函数的代码
        ... 其他 libc 函数 ...
    .data:  // 包含已初始化的全局变量
        ...
    .bss:   // 包含未初始化的全局变量
        ...
    .plt:   // Procedure Linkage Table，用于延迟绑定
        ...
    .got:   // Global Offset Table，存储全局变量和函数地址
        ...
```

**链接的处理过程 (简化):**

1. **编译时:** 编译器在编译程序时，遇到 `setjmp` 等函数调用，会在目标文件中生成对这些符号的未解析引用。
2. **链接时:** 静态链接器将目标文件链接成可执行文件或共享库。对于动态链接的库 (如 `libc.so`)，静态链接器不会将 `setjmp` 等函数的代码直接复制到最终的可执行文件中，而是在可执行文件中生成一些辅助信息，例如 PLT 和 GOT 条目。
3. **运行时:** 当程序启动时，动态链接器 (例如 Android 的 `linker64` 或 `linker`) 会负责加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** 当程序第一次调用 `setjmp` 时，如果该符号尚未解析，动态链接器会查找 `libc.so` 中 `setjmp` 函数的地址，并将该地址填充到 GOT 表中。后续对 `setjmp` 的调用将直接从 GOT 表中获取地址，而无需再次解析。

**假设输入与输出 (逻辑推理):**

由于这是一个测试文件，我们关注的是测试用例的输入和预期输出。

**示例： `TEST(setjmp, setjmp_smoke)`**

* **假设输入:** 程序执行到 `setjmp(jb)`。
* **预期输出:**
    * `setjmp` 首次调用返回 0。
    * 执行 `longjmp(jb, 123)` 后，程序跳转回 `setjmp(jb)` 的位置。
    * 此时 `setjmp` 的返回值变为 123。
    * `ASSERT_EQ(123, value)` 断言成功。

**示例： `TEST(setjmp, setjmp_signal_mask)` (在 Bionic 上)**

* **假设输入:**
    * 使用 `sigprocmask64` 设置信号掩码为 `ss.one`。
    * 调用 `setjmp(jb)`。
    * 使用 `sigprocmask64` 设置信号掩码为 `ss.two`。
    * 调用 `longjmp(jb, 1)`。
* **预期输出:**
    * 在 Bionic 上，`setjmp` 保存了信号掩码。
    * `longjmp` 恢复了 `setjmp` 时的信号掩码，即 `ss.one`。
    * `AssertSigmaskEquals(ss.one)` 断言成功。

**用户或编程常见的使用错误举例说明:**

1. **在 `setjmp` 调用返回之前使用 `longjmp`:**  `longjmp` 只能跳转回已经调用过 `setjmp` 的地方。如果在 `setjmp` 被调用之前就调用 `longjmp`，会导致程序行为未定义，通常会崩溃。

   ```c
   #include <setjmp.h>
   #include <stdio.h>
   #include <stdlib.h>

   jmp_buf buf;

   void jump_back() {
       longjmp(buf, 1); // 错误：在 setjmp 之前调用 longjmp
   }

   int main() {
       jump_back();
       if (setjmp(buf) == 0) {
           printf("Should not reach here\n");
       } else {
           printf("Reached after longjmp\n");
       }
       return 0;
   }
   ```

2. **`setjmp`/`longjmp` 跨越栈帧:**  在 `setjmp` 调用的函数返回后，再使用该 `jmp_buf` 进行 `longjmp` 是危险的。因为栈帧已经释放，恢复的上下文可能指向无效的内存。

   ```c
   #include <setjmp.h>
   #include <stdio.h>
   #include <stdlib.h>

   jmp_buf buf;

   void set_jump_point() {
       setjmp(buf);
       printf("setjmp called\n");
   }

   int main() {
       set_jump_point(); // setjmp 被调用，函数返回
       longjmp(buf, 1); // 错误：尝试跳转回已释放的栈帧
       printf("Should not reach here\n");
       return 0;
   }
   ```

3. **在信号处理函数中使用不当:**  在信号处理函数中调用 `longjmp` 需要特别小心。确保 `longjmp` 跳转回的上下文是安全的，并且信号处理函数是可重入的。通常建议使用 `siglongjmp` 来处理信号相关的跳转。

4. **忽略 `setjmp` 的返回值:**  `setjmp` 第一次调用返回 0，后续通过 `longjmp` 返回时返回 `longjmp` 的第二个参数。忽略返回值可能导致逻辑错误。

**说明 Android framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

`setjmp` 和相关函数是 Bionic C 库的基础组成部分，几乎所有的 Android 用户空间进程都会间接地或直接地使用它们。

**Android Framework 到 Bionic 的调用路径 (示例):**

1. **Java 代码 (Android Framework):**  例如，一个 Java 服务在处理 Binder 调用时，可能会调用到 Native 代码。
2. **JNI 调用:** Java 代码通过 Java Native Interface (JNI) 调用到 C/C++ 代码 (NDK 开发的库)。
3. **NDK 库:** NDK 库中的 C/C++ 代码可能会直接或间接地调用 `setjmp` 或 `longjmp`。例如，某些 C++ 异常处理机制的底层实现可能会用到类似的概念。
4. **Bionic `libc.so`:**  NDK 库链接到 Bionic C 库 `libc.so`，当 NDK 代码调用 `setjmp` 或 `longjmp` 时，最终会执行 `libc.so` 中对应的实现。

**Frida Hook 示例:**

可以使用 Frida 来 hook `setjmp` 和 `longjmp` 函数，观察它们的调用情况。

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const setjmpPtr = Module.findExportByName("libc.so", "setjmp");
  const longjmpPtr = Module.findExportByName("libc.so", "longjmp");

  if (setjmpPtr) {
    Interceptor.attach(setjmpPtr, {
      onEnter: function (args) {
        console.log("[setjmp] Called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\\n"));
        // 可以检查 args[0] (jmp_buf 的地址)
      },
      onLeave: function (retval) {
        console.log("[setjmp] Return value: " + retval);
      }
    });
  }

  if (longjmpPtr) {
    Interceptor.attach(longjmpPtr, {
      onEnter: function (args) {
        console.log("[longjmp] Called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\\n"));
        console.log("[longjmp] jmp_buf address: " + args[0]);
        console.log("[longjmp] val: " + args[1]);
      }
    });
  }
} else {
  console.log("Frida hook example is for ARM/ARM64 architectures.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_setjmp.js`)。
2. 使用 Frida 连接到 Android 设备上的目标进程：
   ```bash
   frida -U -f <package_name> -l hook_setjmp.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_setjmp.js
   ```
3. 当目标进程执行到 `setjmp` 或 `longjmp` 时，Frida 会打印出相应的日志信息，包括调用栈和参数。

通过 Frida hook，可以动态地观察 `setjmp` 和 `longjmp` 在 Android 系统中的实际使用情况，以及调用它们的上下文，从而更深入地理解其工作原理和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/setjmp_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <setjmp.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <android-base/silent_death_test.h>
#include <android-base/test_utils.h>

#include "SignalUtils.h"

using setjmp_DeathTest = SilentDeathTest;

TEST(setjmp, setjmp_smoke) {
  int value;
  jmp_buf jb;
  if ((value = setjmp(jb)) == 0) {
    longjmp(jb, 123);
    FAIL(); // Unreachable.
  } else {
    ASSERT_EQ(123, value);
  }
}

TEST(setjmp, _setjmp_smoke) {
  int value;
  jmp_buf jb;
  if ((value = _setjmp(jb)) == 0) {
    _longjmp(jb, 456);
    FAIL(); // Unreachable.
  } else {
    ASSERT_EQ(456, value);
  }
}

TEST(setjmp, sigsetjmp_0_smoke) {
  int value;
  sigjmp_buf jb;
  if ((value = sigsetjmp(jb, 0)) == 0) {
    siglongjmp(jb, 789);
    FAIL(); // Unreachable.
  } else {
    ASSERT_EQ(789, value);
  }
}

TEST(setjmp, sigsetjmp_1_smoke) {
  int value;
  sigjmp_buf jb;
  if ((value = sigsetjmp(jb, 0)) == 0) {
    siglongjmp(jb, 0xabc);
    FAIL(); // Unreachable.
  } else {
    ASSERT_EQ(0xabc, value);
  }
}

// Two distinct signal sets.
struct SigSets {
  SigSets() : one(MakeSigSet(0)), two(MakeSigSet(1)) {
  }

  static sigset64_t MakeSigSet(int offset) {
    sigset64_t ss;
    sigemptyset64(&ss);
    sigaddset64(&ss, SIGUSR1 + offset);
#if defined(__BIONIC__)
    // TIMER_SIGNAL.
    sigaddset64(&ss, __SIGRTMIN);
#endif
    sigaddset64(&ss, SIGRTMIN + offset);
    return ss;
  }

  sigset64_t one;
  sigset64_t two;
};

void AssertSigmaskEquals(const sigset64_t& expected) {
  sigset64_t actual;
  sigprocmask64(SIG_SETMASK, nullptr, &actual);
  size_t end = sizeof(expected) * 8;
  for (size_t i = 1; i <= end; ++i) {
    EXPECT_EQ(sigismember64(&expected, i), sigismember64(&actual, i)) << i;
  }
}

TEST(setjmp, _setjmp_signal_mask) {
  SignalMaskRestorer smr;

  // _setjmp/_longjmp do not save/restore the signal mask.
  SigSets ss;
  sigprocmask64(SIG_SETMASK, &ss.one, nullptr);
  jmp_buf jb;
  if (_setjmp(jb) == 0) {
    sigprocmask64(SIG_SETMASK, &ss.two, nullptr);
    _longjmp(jb, 1);
    FAIL(); // Unreachable.
  } else {
    AssertSigmaskEquals(ss.two);
  }
}

TEST(setjmp, setjmp_signal_mask) {
  SignalMaskRestorer smr;

  // setjmp/longjmp do save/restore the signal mask on bionic, but not on glibc.
  // This is a BSD versus System V historical accident. POSIX leaves the
  // behavior unspecified, so any code that cares needs to use sigsetjmp.
  SigSets ss;
  sigprocmask64(SIG_SETMASK, &ss.one, nullptr);
  jmp_buf jb;
  if (setjmp(jb) == 0) {
    sigprocmask64(SIG_SETMASK, &ss.two, nullptr);
    longjmp(jb, 1);
    FAIL(); // Unreachable.
  } else {
#if defined(__BIONIC__)
    // bionic behaves like BSD and does save/restore the signal mask.
    AssertSigmaskEquals(ss.one);
#else
    // glibc behaves like System V and doesn't save/restore the signal mask.
    AssertSigmaskEquals(ss.two);
#endif
  }
}

TEST(setjmp, sigsetjmp_0_signal_mask) {
  SignalMaskRestorer smr;

  // sigsetjmp(0)/siglongjmp do not save/restore the signal mask.
  SigSets ss;
  sigprocmask64(SIG_SETMASK, &ss.one, nullptr);
  sigjmp_buf sjb;
  if (sigsetjmp(sjb, 0) == 0) {
    sigprocmask64(SIG_SETMASK, &ss.two, nullptr);
    siglongjmp(sjb, 1);
    FAIL(); // Unreachable.
  } else {
    AssertSigmaskEquals(ss.two);
  }
}

TEST(setjmp, sigsetjmp_1_signal_mask) {
  SignalMaskRestorer smr;

  // sigsetjmp(1)/siglongjmp does save/restore the signal mask.
  SigSets ss;
  sigprocmask64(SIG_SETMASK, &ss.one, nullptr);
  sigjmp_buf sjb;
  if (sigsetjmp(sjb, 1) == 0) {
    sigprocmask64(SIG_SETMASK, &ss.two, nullptr);
    siglongjmp(sjb, 1);
    FAIL(); // Unreachable.
  } else {
    AssertSigmaskEquals(ss.one);
  }
}

#if defined(__arm__) || defined(__aarch64__)
// arm and arm64 have the same callee save fp registers (8-15),
// but use different instructions for accessing them.
#if defined(__arm__)
#define SET_FREG(n, v) asm volatile("vmov.f64 d"#n ", #"#v : : : "d"#n)
#define GET_FREG(n) ({ double _r; asm volatile("fcpyd %P0, d"#n : "=w"(_r) : :); _r;})
#define CLEAR_FREG(n) asm volatile("vmov.i64 d"#n ", #0x0" : : : "d"#n)
#elif defined(__aarch64__)
#define SET_FREG(n, v) asm volatile("fmov d"#n ", "#v : : : "d"#n)
#define GET_FREG(n) ({ double _r; asm volatile("fmov %0, d"#n : "=r"(_r) : :); _r; })
#define CLEAR_FREG(n) asm volatile("fmov d"#n ", xzr" : : : "d"#n)
#endif
#define SET_FREGS \
  SET_FREG(8, 8.0); SET_FREG(9, 9.0); SET_FREG(10, 10.0); SET_FREG(11, 11.0); \
  SET_FREG(12, 12.0); SET_FREG(13, 13.0); SET_FREG(14, 14.0); SET_FREG(15, 15.0)
#define CLEAR_FREGS \
  CLEAR_FREG(8); CLEAR_FREG(9); CLEAR_FREG(10); CLEAR_FREG(11); \
  CLEAR_FREG(12); CLEAR_FREG(13); CLEAR_FREG(14); CLEAR_FREG(15)
#define CHECK_FREGS \
  EXPECT_EQ(8.0, GET_FREG(8)); EXPECT_EQ(9.0, GET_FREG(9)); \
  EXPECT_EQ(10.0, GET_FREG(10)); EXPECT_EQ(11.0, GET_FREG(11)); \
  EXPECT_EQ(12.0, GET_FREG(12)); EXPECT_EQ(13.0, GET_FREG(13)); \
  EXPECT_EQ(14.0, GET_FREG(14)); EXPECT_EQ(15.0, GET_FREG(15))

#elif defined(__riscv)
// riscv64 has callee save registers fs0-fs11.
// TODO: use Zfa to get 1.0 rather than the one_p trick.
#define SET_FREGS \
  double one = 1, *one_p = &one; \
  asm volatile("fmv.d.x fs0, zero ; fld fs1, (%0) ; \
                fadd.d fs2, fs1, fs1 ; fadd.d fs3, fs2, fs1 ; \
                fadd.d fs4, fs3, fs1 ; fadd.d fs5, fs4, fs1 ; \
                fadd.d fs6, fs5, fs1 ; fadd.d fs7, fs6, fs1 ; \
                fadd.d fs8, fs7, fs1 ; fadd.d fs9, fs8, fs1 ; \
                fadd.d fs10, fs9, fs1 ; fadd.d fs11, fs10, fs1" \
               : \
               : "r"(one_p) \
               : "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", \
                  "fs6", "fs7", "fs8", "fs9", "fs10", "fs11")
#define CLEAR_FREGS \
  asm volatile("fmv.d.x fs0, zero ; fmv.d.x fs1, zero ; \
                fmv.d.x fs2, zero ; fmv.d.x fs3, zero ; \
                fmv.d.x fs4, zero ; fmv.d.x fs5, zero ; \
                fmv.d.x fs6, zero ; fmv.d.x fs7, zero ; \
                fmv.d.x fs8, zero ; fmv.d.x fs9, zero ; \
                fmv.d.x fs10, zero ; fmv.d.x fs11, zero" \
               : : : "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", \
                     "fs6", "fs7", "fs8", "fs9", "fs10", "fs11")
#define GET_FREG(n) ({ double _r; asm volatile("fmv.d %0, fs"#n : "=f"(_r) : :); _r; })
#define CHECK_FREGS \
  EXPECT_EQ(0.0, GET_FREG(0)); EXPECT_EQ(1.0, GET_FREG(1)); \
  EXPECT_EQ(2.0, GET_FREG(2)); EXPECT_EQ(3.0, GET_FREG(3)); \
  EXPECT_EQ(4.0, GET_FREG(4)); EXPECT_EQ(5.0, GET_FREG(5)); \
  EXPECT_EQ(6.0, GET_FREG(6)); EXPECT_EQ(7.0, GET_FREG(7)); \
  EXPECT_EQ(8.0, GET_FREG(8)); EXPECT_EQ(9.0, GET_FREG(9)); \
  EXPECT_EQ(10.0, GET_FREG(10)); EXPECT_EQ(11.0, GET_FREG(11))

#else
// x86 and x86-64 don't save/restore fp registers.
#define SET_FREGS
#define CLEAR_FREGS
#define CHECK_FREGS
#endif

TEST(setjmp, setjmp_fp_registers) {
  int value;
  jmp_buf jb;
  SET_FREGS;
  if ((value = setjmp(jb)) == 0) {
    CLEAR_FREGS;
    longjmp(jb, 123);
    FAIL(); // Unreachable.
  } else {
    ASSERT_EQ(123, value);
    CHECK_FREGS;
  }
}

#if defined(__arm__)
#define JB_SIGFLAG_OFFSET 0
#elif defined(__aarch64__)
#define JB_SIGFLAG_OFFSET 0
#elif defined(__i386__)
#define JB_SIGFLAG_OFFSET 8
#elif defined(__riscv)
#define JB_SIGFLAG_OFFSET 0
#elif defined(__x86_64)
#define JB_SIGFLAG_OFFSET 8
#endif

TEST_F(setjmp_DeathTest, setjmp_cookie) {
  jmp_buf jb;
  int value = setjmp(jb);
  ASSERT_EQ(0, value);

  long* sigflag = reinterpret_cast<long*>(jb) + JB_SIGFLAG_OFFSET;

  // Make sure there's actually a cookie.
  EXPECT_NE(0, *sigflag & ~1);

  // Wipe it out
  *sigflag &= 1;
  EXPECT_DEATH(longjmp(jb, 0), "");
}

TEST_F(setjmp_DeathTest, setjmp_cookie_checksum) {
  jmp_buf jb;
  int value = setjmp(jb);

  if (value == 0) {
    // Flip a bit.
    reinterpret_cast<long*>(jb)[1] ^= 1;

    EXPECT_DEATH(longjmp(jb, 1), "checksum mismatch");
  } else {
    fprintf(stderr, "setjmp_cookie_checksum: longjmp succeeded?");
  }
}

__attribute__((noinline)) void call_longjmp(jmp_buf buf) {
  longjmp(buf, 123);
}

TEST(setjmp, setjmp_stack) {
  jmp_buf buf;
  int value = setjmp(buf);
  if (value == 0) call_longjmp(buf);
  EXPECT_EQ(123, value);
}

TEST(setjmp, bug_152210274) {
  // Ensure that we never have a mangled value in the stack pointer.
#if defined(__BIONIC__)
  struct sigaction sa = {.sa_flags = SA_SIGINFO, .sa_sigaction = [](int, siginfo_t*, void*) {}};
  ASSERT_EQ(0, sigaction(SIGPROF, &sa, 0));

  constexpr size_t kNumThreads = 20;

  // Start a bunch of threads calling setjmp/longjmp.
  auto jumper = [](void* arg) -> void* {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPROF);
    pthread_sigmask(SIG_UNBLOCK, &set, nullptr);

    jmp_buf buf;
    for (size_t count = 0; count < 100000; ++count) {
      if (setjmp(buf) != 0) {
        perror("setjmp");
        abort();
      }
      // This will never be true, but the compiler doesn't know that, so the
      // setjmp won't be removed by DCE. With HWASan/MTE this also acts as a
      // kind of enforcement that the threads are done before leaving the test.
      if (*static_cast<size_t*>(arg) != 123) longjmp(buf, 1);
    }
    return nullptr;
  };
  pthread_t threads[kNumThreads];
  pid_t tids[kNumThreads] = {};
  size_t var = 123;
  for (size_t i = 0; i < kNumThreads; ++i) {
    ASSERT_EQ(0, pthread_create(&threads[i], nullptr, jumper, &var));
    tids[i] = pthread_gettid_np(threads[i]);
  }

  // Start the interrupter thread.
  auto interrupter = [](void* arg) -> void* {
    pid_t* tids = static_cast<pid_t*>(arg);
    for (size_t count = 0; count < 1000; ++count) {
      for (size_t i = 0; i < kNumThreads; i++) {
        if (tgkill(getpid(), tids[i], SIGPROF) == -1 && errno != ESRCH) {
          perror("tgkill failed");
          abort();
        }
      }
      usleep(100);
    }
    return nullptr;
  };
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, interrupter, tids));
  pthread_join(t, nullptr);
  for (size_t i = 0; i < kNumThreads; i++) {
    pthread_join(threads[i], nullptr);
  }
#else
  GTEST_SKIP() << "tests uses functions not in glibc";
#endif
}

"""

```