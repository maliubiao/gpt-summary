Response:
Let's break down the thought process for answering the request about `setjmp.handroid`.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the `setjmp.handroid` header file within the context of Android's Bionic library. The request also asks for specific details like Android relevance, implementation details, dynamic linker interactions, error scenarios, and how Android frameworks/NDK reach this file. The request emphasizes the need for examples (including Frida hooks).

**2. Initial Analysis of the Source Code:**

* **Header File Nature:** The `.h` extension immediately tells us this is a header file. Header files primarily declare types, macros, and function prototypes. They don't contain the actual function implementations.
* **Copyright and Licensing:**  The copyright notices indicate this file originates from OpenBSD and NetBSD. This is a common pattern for Bionic, which often reuses code from other BSD-based systems.
* **`#pragma once` and `#include <sys/cdefs.h>`:** Standard header file practices to prevent multiple inclusions and provide compiler definitions.
* **Architecture-Specific Definitions (`__aarch64__`, `__arm__`, etc.):**  The `#if defined(...)` blocks are crucial. They define the `_JBLEN` macro differently based on the target architecture. This hints that `setjmp`/`longjmp`'s implementation details are architecture-dependent. The comments within these blocks are very informative, explaining the purpose of `_JBLEN` (size of `jmp_buf`) and even mentioning comparisons with OpenBSD and glibc.
* **Type Definitions (`typedef long sigjmp_buf[...]`, `typedef long jmp_buf[...]`):** These define the data structures used to store the jump context. The difference between `sigjmp_buf` and `jmp_buf` (the extra element) is noteworthy and likely related to signal mask saving.
* **Function Prototypes:** The `__BEGIN_DECLS` and `__END_DECLS` blocks contain the declarations for functions like `_setjmp`, `_longjmp`, `setjmp`, `longjmp`, `sigsetjmp`, and `siglongjmp`. The `__returns_twice` and `__noreturn` attributes provide important information about function behavior. The redefinition of `setjmp` as a macro that calls the function `setjmp` is also significant.
* **Documentation Comments:** The `/** ... */` comments provide high-level explanations of the functions, often referencing man pages.

**3. Categorizing and Addressing the Requirements:**

Now, I'll go through each part of the request and think about how to address it based on the header file's content:

* **功能 (Functionality):**  The core functionality is providing non-local jumps. This needs to be explained clearly.
* **与 Android 功能的关系 (Relationship to Android):**  Because this is part of Bionic, it's fundamental to Android's C library. Examples should involve common Android use cases, like error handling or implementing coroutines.
* **libc 函数的实现 (Implementation of libc functions):** This is where the header file is *limited*. It only *declares* the functions. The actual implementation resides in assembly or C source files within Bionic. I need to emphasize this and provide a *general* understanding of how `setjmp` and `longjmp` work (saving and restoring registers, stack pointer, etc.) without delving into Bionic's specific assembly.
* **dynamic linker 的功能 (Dynamic linker functionality):** The header file itself doesn't directly involve the dynamic linker. However, `setjmp`/`longjmp` are essential for managing control flow within and potentially across shared libraries. I need to discuss how the dynamic linker ensures that the jump buffers are correctly handled in shared library scenarios and provide a simplified SO layout example.
* **逻辑推理 (Logical reasoning):**  Hypothetical input and output for `setjmp` and `longjmp` can illustrate their behavior.
* **用户或编程常见的使用错误 (Common user/programming errors):**  This is important for practical guidance. Common pitfalls include jumping out of scope, modifying jump buffers directly, and signal handling issues.
* **Android framework or ndk 如何到达这里 (How Android framework/NDK reaches here):**  Trace the path from high-level Android (Java/Kotlin) through the NDK and finally to Bionic's libc. System calls are a key intermediary.
* **Frida hook 示例 (Frida hook examples):**  Provide concrete examples of how to use Frida to intercept calls to `setjmp` and `longjmp`.

**4. Structuring the Answer:**

Organize the answer logically according to the request's points. Use clear headings and subheadings. Provide code examples where appropriate.

**5. Addressing Limitations and Making Assumptions:**

* **Implementation Details:**  Since the header file doesn't contain implementations, I need to provide general explanations and acknowledge that the actual Bionic implementation might vary.
* **Dynamic Linker Complexity:** The dynamic linker is a complex beast. I need to provide a simplified explanation relevant to `setjmp`/`longjmp`.
* **Frida Hooking:** Frida examples will be basic but illustrative. More complex scenarios could involve architecture-specific registers or signal handling.

**Pre-computation/Pre-analysis (Internal):**

Before writing the answer, I'd mentally (or actually, if it's a very complex topic) run through the typical flow of `setjmp`/`longjmp`:

1. `setjmp` is called: It saves the current processor state (registers, stack pointer, program counter) into the provided `jmp_buf`. It returns 0.
2. Code executes.
3. Some condition occurs, and `longjmp` is called: It restores the processor state from the `jmp_buf` previously set by `setjmp`. Execution jumps back to the point after the `setjmp` call, but this time `setjmp` returns the value passed to `longjmp`.

For signal handling (`sigsetjmp`/`siglongjmp`), the signal mask is also saved and restored.

**Self-Correction/Refinement During Generation:**

* **Clarity:**  Ensure explanations are clear and avoid jargon where possible.
* **Accuracy:** Double-check the information, especially regarding architecture-specific details and the behavior of `setjmp`'s return value.
* **Completeness:**  Ensure all aspects of the request are addressed.
* **Examples:**  Verify that examples are correct and easy to understand.

By following this systematic approach, I can generate a comprehensive and accurate answer that addresses all the points in the request, while acknowledging the limitations of analyzing a header file in isolation.
这是一个关于 Android Bionic 库中 `setjmp.handroid` 头文件的分析。让我们逐步分解其功能和相关细节。

**1. `setjmp.handroid` 的功能**

`setjmp.handroid` 头文件定义了实现非本地跳转（non-local jumps）的函数和数据结构。非本地跳转允许程序跳过正常的函数调用和返回机制，直接跳转到之前程序执行过的某个点。这主要由 `setjmp` 和 `longjmp` (以及其信号处理版本 `sigsetjmp` 和 `siglongjmp`) 这四个函数（或宏）提供。

* **`setjmp` (或 `_setjmp`)**:  这个函数保存当前程序的执行上下文（包括程序计数器、栈指针、寄存器等）到一个 `jmp_buf` 类型的缓冲区中。它的主要作用是标记一个可以稍后通过 `longjmp` 跳回来的位置。  `setjmp` 首次被调用时返回 0。如果通过 `longjmp` 跳转回来，则返回 `longjmp` 提供的非零值。
* **`longjmp` (或 `_longjmp`)**: 这个函数恢复之前通过 `setjmp` 保存的执行上下文。它接受一个 `jmp_buf` 缓冲区作为参数，并将程序的控制流跳转回 `setjmp` 被调用的位置，并使 `setjmp` 返回 `longjmp` 的第二个参数（如果该参数为 0，则 `setjmp` 返回 1）。 `longjmp` 函数不会返回。
* **`sigsetjmp`**: 与 `setjmp` 类似，但它还可以选择保存当前的信号屏蔽字（signal mask）。它的第二个参数 `__save_signal_mask` 决定是否保存信号屏蔽字。如果为非零值，则保存；否则不保存。
* **`siglongjmp`**: 与 `longjmp` 类似，但它在跳转回 `sigsetjmp` 的位置时，可以选择恢复之前保存的信号屏蔽字。

**2. 与 Android 功能的关系及举例**

`setjmp`/`longjmp` 在 Android 系统中主要用于以下场景：

* **错误处理和异常恢复:** 在 C 代码中，当遇到无法直接通过函数返回值处理的严重错误时，可以使用 `setjmp` 标记一个恢复点，然后在错误处理代码中使用 `longjmp` 跳转回该点。例如，在解析配置文件或处理网络连接时，如果遇到致命错误，可以跳回到主循环。
* **用户态线程的上下文切换 (通常不直接使用):**  虽然 Android 主要使用内核线程，但在某些特定的用户态线程库或协程实现中，`setjmp`/`longjmp` 可以作为一种底层的上下文切换机制。不过，现代的协程库通常会采用更高级的机制。
* **某些库的内部实现:** 一些底层的 C 库可能会使用 `setjmp`/`longjmp` 来实现特定的控制流逻辑。

**举例说明 (伪代码):**

```c
#include <stdio.h>
#include <setjmp.h>

jmp_buf env;

void handle_error() {
    printf("发生错误，正在恢复...\n");
    longjmp(env, 1); // 跳转回 setjmp 的位置，并让 setjmp 返回 1
}

int main() {
    int val = setjmp(env); // 保存当前上下文

    if (val == 0) {
        printf("程序开始执行...\n");
        // 模拟可能发生错误的情况
        int error_occurred = 1;
        if (error_occurred) {
            handle_error();
            // 这里不会执行到，因为 longjmp 已经跳转走了
        }
        printf("程序正常结束。\n");
    } else if (val == 1) {
        printf("从错误恢复后继续执行。\n");
    }

    return 0;
}
```

在这个例子中，`setjmp(env)` 保存了当前的执行状态。如果 `error_occurred` 为真，`handle_error` 函数会调用 `longjmp(env, 1)`，这会导致程序跳转回 `setjmp(env)` 的位置，并且 `setjmp` 会返回 1。

**3. Libc 函数的实现**

`setjmp` 和 `longjmp` 的实现高度依赖于目标平台的体系结构，因为它们需要直接操作 CPU 的寄存器和栈指针。

**`setjmp` 的实现原理：**

1. **保存寄存器:** `setjmp` 的核心任务是将当前 CPU 的关键寄存器的值保存到 `jmp_buf` 结构中。这些寄存器通常包括：
   * **程序计数器 (PC/IP):**  指示下一条要执行的指令的地址。
   * **栈指针 (SP):** 指向当前栈顶的地址。
   * **基址指针 (BP/FP):** 指向当前栈帧的底部，用于追踪函数调用关系。
   * **调用者保存的寄存器 (callee-saved registers):**  这些寄存器的值需要在函数调用前后保持不变，因此 `setjmp` 需要保存它们。在不同的架构上，具体需要保存的寄存器有所不同。
2. **保存信号屏蔽字 (对于 `sigsetjmp`):** 如果 `sigsetjmp` 的第二个参数为非零，还需要保存当前的信号屏蔽字。
3. **返回 0:**  `setjmp` 首次被调用时，总是返回 0。

**`longjmp` 的实现原理：**

1. **恢复寄存器:** `longjmp` 从传入的 `jmp_buf` 结构中恢复之前保存的 CPU 寄存器的值。这会将程序计数器、栈指针等恢复到 `setjmp` 被调用时的状态。
2. **设置 `setjmp` 的返回值:** `longjmp` 会设置 `setjmp` 的返回值。如果传递给 `longjmp` 的第二个参数 `__value` 为 0，则 `setjmp` 返回 1；否则，`setjmp` 返回 `__value`。
3. **跳转:**  通过恢复程序计数器，程序执行流跳转回 `setjmp` 被调用的位置。

**架构特定的 `_JBLEN` 定义:**

头文件中定义的 `_JBLEN` 宏指定了 `jmp_buf` 和 `sigjmp_buf` 数组的大小（以 `long` 类型元素的个数计）。这个值根据不同的 CPU 架构而变化，这是因为不同架构需要保存的寄存器数量和类型不同。

**4. 涉及 Dynamic Linker 的功能**

`setjmp`/`longjmp` 本身并不直接与 dynamic linker 交互。然而，当它们被用于跨越共享库边界时，dynamic linker 的一些机制会发挥作用：

* **地址空间布局:**  Dynamic linker 负责加载共享库到进程的地址空间，并进行符号解析和重定位。`setjmp` 保存的程序计数器等信息会指向正确的代码段和数据段地址，即使这些代码位于不同的共享库中。
* **栈管理:** 每个共享库在进程的地址空间中都有自己的栈区域。当 `longjmp` 跳转时，恢复的栈指针需要指向正确的栈区域。Dynamic linker 和操作系统共同维护这些栈结构。

**SO 布局样本 (简化):**

假设一个简单的场景，`app` 可执行文件链接了共享库 `libmylib.so`。

```
地址空间 (进程内存):

[可执行文件 app]
  - 代码段 (包含 main 函数，调用 setjmp 的代码)
  - 数据段
  - ...

[共享库 libmylib.so]
  - 代码段 (包含调用 longjmp 的函数)
  - 数据段
  - .got.plt (全局偏移量表和过程链接表)
  - ...

[栈]
  - 用于 app 的栈帧
  - 用于 libmylib.so 中函数的栈帧
```

**链接的处理过程:**

1. **`setjmp` 调用:**  当 `app` 中的代码调用 `setjmp` 时，它保存的是当前 `app` 代码段的执行上下文，包括栈指针、程序计数器等，这些指针指向 `app` 自己的栈和代码。
2. **跨库调用:**  假设 `app` 调用了 `libmylib.so` 中的一个函数，该函数内部会触发需要 `longjmp` 的错误。
3. **`longjmp` 调用:** `libmylib.so` 中的函数调用 `longjmp`，使用之前在 `app` 中 `setjmp` 保存的 `jmp_buf`。
4. **跳转回 `app`:** `longjmp` 根据 `jmp_buf` 中保存的程序计数器、栈指针等信息，将执行流跳转回 `app` 中 `setjmp` 调用的位置。由于地址空间布局是由 dynamic linker 管理的，确保了 `jmp_buf` 中保存的地址在跳转时仍然有效。

**注意:**  跨越共享库边界使用 `setjmp`/`longjmp` 需要谨慎，因为它可能会破坏栈帧结构，导致未定义的行为，尤其是在涉及异常处理、C++ 对象析构等方面。

**5. 假设输入与输出 (逻辑推理)**

**假设输入:**

```c
#include <stdio.h>
#include <setjmp.h>

jmp_buf env;

int main() {
    int val = setjmp(env);

    if (val == 0) {
        printf("第一次执行 setjmp，返回 %d\n", val);
        longjmp(env, 5);
        printf("这里不会被执行\n");
    } else {
        printf("通过 longjmp 返回，返回 %d\n", val);
    }

    return 0;
}
```

**输出:**

```
第一次执行 setjmp，返回 0
通过 longjmp 返回，返回 5
```

**解释:**

1. 第一次执行 `setjmp(env)` 时，它保存了当前状态并返回 0。
2. `longjmp(env, 5)` 被调用，它恢复了之前保存的状态，并将 `setjmp` 的返回值设置为 5。
3. 程序跳转回 `setjmp` 的位置，这次 `setjmp` 返回 5。

**6. 用户或编程常见的使用错误**

* **在 `setjmp` 调用之前使用 `longjmp`:** 这是最常见的错误，会导致程序崩溃或未定义的行为，因为 `longjmp` 需要一个有效的 `jmp_buf`，而这个缓冲区需要先通过 `setjmp` 初始化。
   ```c
   #include <stdio.h>
   #include <setjmp.h>

   jmp_buf env;

   int main() {
       longjmp(env, 1); // 错误：在 setjmp 之前调用 longjmp
       setjmp(env);
       return 0;
   }
   ```

* **跳转出函数的 `setjmp` 调用栈帧:**  如果 `setjmp` 在一个函数中调用，而 `longjmp` 从另一个函数中跳转回来，那么在 `setjmp` 调用栈帧上的局部变量可能已经失效。这会导致访问无效内存。
   ```c
   #include <stdio.h>
   #include <setjmp.h>

   jmp_buf env;

   void func() {
       longjmp(env, 1);
   }

   int main() {
       if (setjmp(env) == 0) {
           func();
       } else {
           printf("返回到 main 函数\n");
       }
       return 0;
   }
   ```
   在这个例子中，如果 `func` 被调用并执行 `longjmp`，它会跳回到 `main` 函数中 `setjmp` 的位置。这是允许的。但如果在 `func` 中 `setjmp`，然后在 `main` 中 `longjmp` 回去，就会有问题。

* **修改 `jmp_buf` 的内容:**  `jmp_buf` 的内容是内部实现细节，用户不应该直接修改它。这样做可能会导致 `longjmp` 无法正确恢复状态。

* **信号处理不当 (使用 `setjmp`/`longjmp`):**  如果涉及到信号处理，应该优先使用 `sigsetjmp`/`siglongjmp`，因为它们可以保存和恢复信号屏蔽字，避免出现竞态条件或不可预测的行为。

**7. Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例**

**Android Framework 到 Bionic 的路径:**

1. **Java/Kotlin 代码 (Android Framework):**  Android Framework 的上层是用 Java 或 Kotlin 编写的。
2. **JNI (Java Native Interface):** 当 Framework 需要调用底层的 C/C++ 代码时，会使用 JNI。
3. **NDK (Native Development Kit):** NDK 提供了编译和链接 C/C++ 代码的工具和库，这些代码可以被 Framework 通过 JNI 调用。
4. **Bionic Libc:** NDK 编译的代码最终链接到 Bionic 库，包括 `libc.so`。`setjmp.h` 中声明的函数 (`setjmp`, `longjmp`, `sigsetjmp`, `siglongjmp`) 的实现位于 Bionic 的源代码中。
5. **系统调用:**  `setjmp` 和 `longjmp` 的底层实现通常会涉及到一些与操作系统内核交互的操作，例如保存和恢复寄存器状态。但这部分是 Bionic 库内部处理的，NDK 开发者通常不需要直接关心系统调用。

**Frida Hook 示例:**

可以使用 Frida Hook `setjmp` 和 `longjmp` 来观察它们的调用：

```javascript
// Hook setjmp
Interceptor.attach(Module.findExportByName("libc.so", "setjmp"), {
  onEnter: function (args) {
    console.log("setjmp called");
    console.log("  jmp_buf address:", args[0]);
    // 可以读取 jmp_buf 的内容 (谨慎操作)
    // let env = ptr(args[0]);
    // console.log("  env[0]:", Memory.readLong(env));
  },
  onLeave: function (retval) {
    console.log("setjmp returned:", retval);
  },
});

// Hook longjmp
Interceptor.attach(Module.findExportByName("libc.so", "longjmp"), {
  onEnter: function (args) {
    console.log("longjmp called");
    console.log("  jmp_buf address:", args[0]);
    console.log("  value:", args[1].toInt32());
  },
  onLeave: function (retval) {
    // longjmp 不会返回
  },
});

// Hook sigsetjmp
Interceptor.attach(Module.findExportByName("libc.so", "sigsetjmp"), {
    onEnter: function (args) {
        console.log("sigsetjmp called");
        console.log("  sigjmp_buf address:", args[0]);
        console.log("  save_signal_mask:", args[1].toInt32());
    },
    onLeave: function (retval) {
        console.log("sigsetjmp returned:", retval);
    }
});

// Hook siglongjmp
Interceptor.attach(Module.findExportByName("libc.so", "siglongjmp"), {
    onEnter: function (args) {
        console.log("siglongjmp called");
        console.log("  sigjmp_buf address:", args[0]);
        console.log("  value:", args[1].toInt32());
    }
});
```

**使用方法:**

1. 将以上 JavaScript 代码保存为 `.js` 文件 (例如 `hook_setjmp.js`).
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_setjmp.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_setjmp.js
   ```
3. 当目标应用执行到 `setjmp` 或 `longjmp` 时，Frida 会拦截这些调用，并在控制台输出相关信息，例如 `jmp_buf` 的地址和返回值。

**总结**

`setjmp.handroid` 定义了 C 语言中实现非本地跳转的关键机制。它在 Android 系统中用于错误处理、某些库的内部实现，并在理解程序控制流方面发挥着重要作用。虽然直接使用 `setjmp`/`longjmp` 容易出错，但理解其原理对于分析底层代码和调试问题非常有帮助。 通过 Frida 可以方便地观察和分析这些函数的行为。

Prompt: 
```
这是目录为bionic/libc/include/setjmp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: setjmp.h,v 1.5 2005/12/13 00:35:22 millert Exp $	*/
/*	$NetBSD: setjmp.h,v 1.11 1994/12/20 10:35:44 cgd Exp $	*/

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *
 *	@(#)setjmp.h	8.2 (Berkeley) 1/21/94
 */

#pragma once

/**
 * @file setjmp.h
 * @brief Non-local jumps.
 */

#include <sys/cdefs.h>

#if defined(__aarch64__)
/**
 * The size in words of an arm64 jmp_buf. Room for callee-saved registers,
 * including floating point, stack pointer and program counter, various
 * internal implementation details, and leaving some free space.
 *
 * Coincidentally matches OpenBSD, though they also save/restore the
 * floating point status register too.
 */
#define _JBLEN 32
#elif defined(__arm__)
/** The size in words of an arm32 jmp_buf. Inherited from OpenBSD. */
#define _JBLEN 64
#elif defined(__i386__)
/** The size in words of an x86 jmp_buf. Inherited from OpenBSD. */
#define _JBLEN 10
#elif defined(__riscv)
/**
 * The size in words of a riscv64 jmp_buf. Room for callee-saved registers,
 * including floating point, stack pointer and program counter, various
 * internal implementation details, and leaving lots of free space.
 *
 * Deliberately very large given the uncertainty around the final form of
 * hardware shadow stack, and the fact that x86-64 glibc needed to steal
 * space from their enormous sigset_t (which we don't have) to be able to
 * implement the CET shadow stack.
 */
#define _JBLEN 64
#elif defined(__x86_64__)
/** The size in words of an x86-64 jmp_buf. Inherited from OpenBSD. */
#define _JBLEN 11
#endif

/** The type of the buffer used by sigsetjmp()/siglongjmp(). */
typedef long sigjmp_buf[_JBLEN + 1];

/** The type of the buffer used by setjmp()/longjmp(). */
typedef long jmp_buf[_JBLEN];

#undef _JBLEN

__BEGIN_DECLS

/**
 * Equivalent to sigsetjmp() with the second argument 0, so that the signal
 * mask is not saved.
 */
int _setjmp(jmp_buf __env) __returns_twice;

/** Equivalent to siglongjmp(). */
__noreturn void _longjmp(jmp_buf __env, int __value);

/**
 * Equivalent to sigsetjmp() with the second argument 1, so that the signal
 * mask is saved.
 */
int setjmp(jmp_buf __env) __returns_twice;

/** C11 says setjmp() must be a macro, but Android already had a function. */
#define setjmp(__env) setjmp(__env)

/** Equivalent to siglongjmp(). */
__noreturn void longjmp(jmp_buf __env, int __value);

/**
 * [sigsetjmp(3)](https://man7.org/linux/man-pages/man3/sigsetjmp.3.html)
 * sets the target of a future siglongjmp() call, saving or not saving the
 * current signal mask based on the second argument.
 *
 * Returns 0 when first called, and returns the value passed to siglongjmp()
 * when returning here as a result of a siglongjmp() call.
 */
int sigsetjmp(sigjmp_buf __env, int __save_signal_mask) __returns_twice;

/**
 * [siglongjmp(3)](https://man7.org/linux/man-pages/man3/siglongjmp.3.html)
 * transfers control back to the site of the sigsetjmp() call that initialized
 * the given jump buffer, returning the given value.
 *
 * Does not return.
 */
__noreturn void siglongjmp(sigjmp_buf __env, int __value);

__END_DECLS

"""

```