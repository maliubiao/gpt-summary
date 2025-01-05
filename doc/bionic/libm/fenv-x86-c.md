Response:
Let's break down the thought process for answering the request about `bionic/libm/fenv-x86.c`.

**1. Understanding the Core Purpose:**

The first step is to grasp the fundamental goal of this file. The name `fenv-x86.c` and the initial comments strongly suggest it's related to *floating-point environment control* specifically for the *x86 architecture*. This immediately brings to mind concepts like:

* **Floating-point exceptions:**  Overflow, underflow, division by zero, etc.
* **Rounding modes:**  Round to nearest, up, down, towards zero.
* **Precision:**  The level of accuracy in floating-point calculations.
* **Control and status registers:**  Hardware registers that govern these aspects.

The inclusion of `<fenv.h>` reinforces this.

**2. Identifying Key Components and Functions:**

Next, I scanned the code for crucial elements:

* **Includes:**  `<sys/cdefs.h>`, `<sys/types.h>`, `fenv.h`. These point to system-level definitions and the standard floating-point environment header.
* **Macros:**  `ROUND_MASK`, `__INITIAL_NPXCW__`, `__INITIAL_MXCSR__`, `_SSE_ROUND_SHIFT`, `_SSE_EMASK_SHIFT`. These define constants related to floating-point control words and SSE.
* **`__fe_dfl_env`:**  This looks like the default floating-point environment.
* **Assembly macros:**  `__fldcw`, `__fldenv`, `__fnstcw`, `__fnstsw`, etc. These directly interact with the x87 FPU and SSE registers. Recognizing these as assembly instructions is key.
* **`__HAS_SSE()` and `__test_sse()`:** This indicates handling for SSE (Streaming SIMD Extensions), a modern x86 instruction set for floating-point.
* **The public `fenv.h` functions:** `fesetexceptflag`, `feraiseexcept`, `fegetenv`, `feholdexcept`, `feupdateenv`, `feenableexcept`, `fedisableexcept`, `feclearexcept`, `fegetexceptflag`, `fetestexcept`, `fegetround`, `fesetround`, `fesetenv`, `fegetexcept`. These are the main functionalities exposed by this file.

**3. Analyzing Function Implementations:**

For each public function, I considered:

* **What it does:** Based on the function name (e.g., `fesetround` sets the rounding mode).
* **How it does it:** By examining the assembly instructions used. For instance, `fesetround` uses `__fnstcw` to get the current control word, modifies it using bitwise operations, and then uses `__fldcw` to set the new control word. The SSE handling adds another layer of complexity.
* **The role of `fenv_t`:**  This structure clearly holds the state of the floating-point environment.

**4. Connecting to Android:**

The prompt asks about the relation to Android. The fact that this is in `bionic`, Android's C library, means these functions are part of the standard C library implementation available to Android applications (both native and those using the NDK). Examples of Android components using floating-point math (graphics, audio, physics engines) help illustrate the relevance.

**5. Addressing Dynamic Linking:**

The request about the dynamic linker requires a different perspective. This file *itself* doesn't directly implement dynamic linking. However, functions within it (like any other library code) are subject to the dynamic linking process. Therefore, I focused on:

* **SO layout:** Describing the basic structure of a shared object (`.so`) file (code, data, GOT, PLT).
* **Symbol resolution:** Explaining how symbols are resolved at runtime using the GOT and PLT. Different types of symbols (global data, function calls) need different treatment.
* **Relocation:** Briefly mentioning the process of adjusting addresses.

**6. Considering User Errors and Debugging:**

For common errors, I thought about typical mistakes when dealing with floating-point:

* Not checking for exceptions.
* Assuming a specific rounding mode.
* Incorrectly manipulating the FPU control word directly (though this file provides safer abstractions).

For debugging, the path from the Android Framework/NDK down to these functions involves:

* **NDK:**  Native code directly calls these functions.
* **Framework:** Java code might trigger native calls that eventually lead to floating-point operations. The JNI boundary is a key point. Tracing system calls (`strace`) and using debugging tools (like GDB) are standard techniques.

**7. Structuring the Answer:**

Finally, I organized the information logically, addressing each part of the prompt:

* **Functionality:**  A high-level overview.
* **Relationship to Android:** Providing concrete examples.
* **Libc Function Implementation:** Detailed explanations of the key functions.
* **Dynamic Linker:**  A separate section addressing this.
* **Logic and Examples:**  Illustrating behavior with hypothetical inputs and outputs.
* **User Errors:**  Providing practical scenarios.
* **Debugging:** Tracing the execution path.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps focus too much on the assembly instructions. **Correction:**  Balance the technical details with a higher-level explanation of the purpose of each function.
* **Initial thought:**  The dynamic linking part is about *this file's* loading. **Correction:** It's about how functions *within* this file are linked when the library is loaded.
* **Initial thought:**  Just list the functions. **Correction:**  Group them by related concepts (exception handling, rounding, environment management) for better clarity.

By following these steps,  analyzing the code structure, understanding the underlying concepts of floating-point arithmetic and dynamic linking, and considering the Android context, a comprehensive answer can be constructed.
好的，让我们深入分析一下 `bionic/libm/fenv-x86.c` 这个文件。

**文件功能概览:**

`fenv-x86.c` 实现了 C 标准库 `<fenv.h>` 头文件中定义的浮点环境控制功能，专门针对 x86 架构的处理器。它允许程序控制和查询浮点运算的各种方面，例如：

* **浮点异常处理:**  允许程序捕获和处理各种浮点异常，例如除零、溢出、下溢、不精确结果和无效操作。
* **舍入模式控制:** 允许程序设置浮点运算的舍入方式，例如舍入到最近、向上舍入、向下舍入、向零舍入。
* **浮点环境的保存和恢复:** 允许程序保存当前的浮点环境设置，并在之后恢复。
* **访问和修改浮点状态标志:**  允许程序读取和修改浮点状态寄存器中的标志位，这些标志位指示了最近发生的浮点异常。

**与 Android 功能的关系及举例:**

由于 `bionic` 是 Android 的 C 库，因此 `fenv-x86.c` 提供的功能是 Android 应用程序可以直接使用的。这对于需要精确控制浮点运算行为的应用程序非常重要，例如：

* **高性能计算:** 科学计算、工程模拟等领域需要精确的浮点控制来保证结果的准确性。例如，一个物理模拟程序可能需要设置特定的舍入模式来保证能量守恒。
* **图形渲染:** 图形处理单元（GPU）虽然有自己的浮点单元，但在 CPU 端进行一些预处理或后处理时，也可能需要控制浮点环境。例如，在进行颜色空间转换时，可能需要特定的舍入模式。
* **音频处理:** 音频处理算法中涉及到大量的浮点运算，控制浮点异常可以帮助开发者更好地处理异常情况，避免程序崩溃或产生错误结果。例如，在音频解码过程中遇到除零错误时，可以优雅地处理并避免程序崩溃。
* **金融计算:** 金融领域的计算对精度要求非常高，控制舍入模式可以避免累积误差。

**Libc 函数的实现细节:**

该文件中的大多数函数都直接操作 x86 处理器的浮点控制寄存器（Control Word）和状态寄存器（Status Word），以及 SSE（Streaming SIMD Extensions）单元的 MXCSR 寄存器。这些操作通常通过内联汇编实现。

以下是一些关键函数的实现解释：

* **`fesetexceptflag(const fexcept_t *flagp, int excepts)`:**
    * **功能:** 设置指定的浮点异常标志。
    * **实现:**
        1. 获取当前的浮点环境状态 (`__fnstenv`).
        2. 清除状态字中与 `excepts` 相关的位 (`env.__status &= ~excepts`).
        3. 根据 `flagp` 中的值设置状态字中与 `excepts` 相关的位 (`env.__status |= *flagp & excepts`).
        4. 清除浮点异常标志 (`__fnclex`).
        5. 恢复修改后的浮点环境 (`__fldenv`).
        6. 如果支持 SSE，则同步修改 MXCSR 寄存器中相应的异常标志位。
    * **关键点:** 直接操作状态寄存器的位来设置异常标志。

* **`feraiseexcept(int excepts)`:**
    * **功能:** 触发指定的浮点异常。
    * **实现:** 实际上是通过调用 `fesetexceptflag` 来设置异常标志，然后执行一个 `__fwait()` 指令，该指令会等待所有之前的浮点操作完成，并检查是否发生了未屏蔽的异常。如果发生了，就会触发相应的信号（通常是 SIGFPE）。
    * **关键点:** 利用设置异常标志和 `fwait` 指令来触发异常。

* **`fegetenv(fenv_t *envp)`:**
    * **功能:** 获取当前的浮点环境。
    * **实现:**
        1. 使用 `__fnstenv` 指令将当前的浮点环境（包括控制字、状态字等）保存到 `envp` 指向的结构体中。
        2. 由于 `fnstenv` 会屏蔽所有异常，所以需要使用 `__fldcw` 恢复之前的控制字，避免产生副作用。
        3. 如果支持 SSE，则使用 `__stmxcsr` 获取 MXCSR 寄存器的值并保存到 `envp` 中。
    * **关键点:** 使用 `fnstenv` 指令获取环境，并处理 `fnstenv` 的副作用。

* **`feholdexcept(fenv_t *envp)`:**
    * **功能:** 保存当前的浮点环境，并清除所有异常标志，屏蔽所有异常。
    * **实现:**
        1. 获取当前的浮点环境并保存到 `envp` (`__fnstenv`).
        2. 清除当前环境的状态字中的所有异常标志 (`env.__status &= ~FE_ALL_EXCEPT`).
        3. 屏蔽当前环境的控制字中的所有异常 (`env.__control |= FE_ALL_EXCEPT`).
        4. 清除浮点异常标志 (`__fnclex`).
        5. 加载修改后的浮点环境 (`__fldenv`).
        6. 如果支持 SSE，则同步修改 MXCSR 寄存器，屏蔽所有异常。
    * **关键点:** 用于在执行可能产生浮点异常的代码块之前，保存环境并屏蔽异常，之后可以使用 `feupdateenv` 恢复并处理异常。

* **`feupdateenv(const fenv_t *envp)`:**
    * **功能:** 恢复指定的浮点环境，并触发在保存环境期间发生的任何浮点异常。
    * **实现:**
        1. 获取当前的状态字 (`__fnstsw`).
        2. 如果支持 SSE，则获取当前的 MXCSR (`__stmxcsr`).
        3. 使用 `fesetenv` 恢复之前保存的浮点环境。
        4. 使用 `feraiseexcept` 触发在保存环境期间发生的任何浮点异常，这些异常是通过比较当前状态字和 MXCSR 与保存的环境中的状态来确定的。
    * **关键点:** 用于配合 `feholdexcept`，在执行可能产生异常的代码后恢复环境并处理异常。

* **`feenableexcept(int mask)`:**
    * **功能:** 启用指定的浮点异常。
    * **实现:**
        1. 获取当前的控制字 (`__fnstcw`).
        2. 如果支持 SSE，则获取当前的 MXCSR (`__stmxcsr`).
        3. 计算当前已禁用的异常 (`omask`).
        4. 清除控制字中与 `mask` 相关的位（0 表示启用异常），使用 `__fldcw` 更新控制字。
        5. 如果支持 SSE，则清除 MXCSR 中与 `mask` 相关的位，使用 `__ldmxcsr` 更新 MXCSR。
    * **关键点:** 通过修改控制字和 MXCSR 的掩码位来启用异常。

* **`fedisableexcept(int mask)`:**
    * **功能:** 禁用指定的浮点异常。
    * **实现:** 类似于 `feenableexcept`，但它是设置控制字和 MXCSR 中与 `mask` 相关的位（1 表示禁用异常）。

* **`feclearexcept(int excepts)`:**
    * **功能:** 清除指定的浮点异常标志。
    * **实现:** 与 `fesetexceptflag` 类似，但它总是将状态字中与 `excepts` 相关的位设置为 0。

* **`fegetexceptflag(fexcept_t *flagp, int excepts)`:**
    * **功能:** 获取指定的浮点异常标志的状态。
    * **实现:** 读取状态字和 MXCSR 寄存器，并将与 `excepts` 相关的位提取出来，存储到 `flagp` 指向的变量中。

* **`fetestexcept(int excepts)`:**
    * **功能:** 测试指定的浮点异常是否被设置。
    * **实现:** 读取状态字和 MXCSR 寄存器，并返回与 `excepts` 相关的位的逻辑或结果。

* **`fegetround(void)`:**
    * **功能:** 获取当前的舍入模式。
    * **实现:** 读取浮点控制字，并提取出舍入模式相关的位 (`ROUND_MASK`)。优先读取 x87 的控制字，因为它通常比读取 SSE 的 MXCSR 更快。

* **`fesetround(int round)`:**
    * **功能:** 设置当前的舍入模式。
    * **实现:**
        1. 检查 `round` 参数是否是有效的舍入模式。
        2. 读取当前的控制字。
        3. 清除控制字中原有的舍入模式位。
        4. 设置新的舍入模式位。
        5. 使用 `__fldcw` 更新控制字。
        6. 如果支持 SSE，则同步修改 MXCSR 寄存器中的舍入模式位。

* **`fesetenv(const fenv_t *envp)`:**
    * **功能:** 设置当前的浮点环境为 `envp` 指向的值。
    * **实现:**
        1. 将 `envp` 中的 MXCSR 值组合成一个完整的 32 位值。
        2. 使用 `__fldenvx` 指令加载 `envp` 中的浮点环境。`__fldenvx` 相比 `__fldenv`，会告知编译器此操作会影响 i387 寄存器栈，因为恢复的环境可能包含不同的标记字。
        3. 如果支持 SSE，则使用 `__ldmxcsr` 加载 MXCSR 寄存器的值。

* **`fegetexcept(void)`:**
    * **功能:** 获取当前启用的浮点异常。
    * **实现:** 读取浮点控制字，并取反，然后与 `FE_ALL_EXCEPT` 进行与运算，得到当前未被屏蔽的异常。

**Dynamic Linker 的功能:**

虽然 `fenv-x86.c` 本身不是动态链接器的一部分，但它编译生成的代码会被链接到共享库中，并由动态链接器加载和处理。

**SO 布局样本:**

一个典型的共享库 (`.so`) 文件（例如 `libm.so`，其中包含了 `fenv-x86.c` 编译的代码）的布局可能如下：

```
.so 文件
├── .text        (代码段)
├── .rodata      (只读数据段，例如 __fe_dfl_env)
├── .data        (可读写数据段)
├── .bss         (未初始化数据段)
├── .plt         (过程链接表，Procedure Linkage Table)
├── .got         (全局偏移表，Global Offset Table)
├── .symtab      (符号表)
├── .strtab      (字符串表)
├── .rel.dyn     (动态重定位表)
├── .rel.plt     (PLT 重定位表)
└── 其他段
```

**每种符号的处理过程:**

1. **全局函数符号 (例如 `fesetround`):**
   - **定义:** 在 `fenv-x86.c` 中定义。
   - **引用:** 可能在其他的 C 库文件中引用，也可能被应用程序直接引用。
   - **处理:**
     - **编译时:** 编译器会将对外部全局函数的调用生成一个 PLT 条目。
     - **链接时:** 静态链接器会解析内部引用，但对于外部库的引用，会生成重定位信息。
     - **动态链接时:** 动态链接器在加载共享库时，会解析 PLT 条目，将 PLT 条目指向 GOT 中相应的地址。第一次调用该函数时，GOT 条目会指向一个 resolver 函数，resolver 函数会查找函数的实际地址并更新 GOT 条目，后续调用将直接跳转到实际地址。

2. **全局数据符号 (例如 `__fe_dfl_env`):**
   - **定义:** 在 `fenv-x86.c` 中定义。
   - **引用:** 可能在同一个文件或其他 C 库文件中引用。
   - **处理:**
     - **编译时:** 编译器会生成对该全局数据的访问指令，使用 GOT 条目来间接访问。
     - **链接时:** 静态链接器会处理内部引用，对于外部库的引用，会生成重定位信息。
     - **动态链接时:** 动态链接器在加载共享库时，会更新 GOT 条目，使其指向全局数据的实际内存地址。

3. **静态函数符号 (在 `fenv-x86.c` 中使用 `static` 声明的函数，例如 `__test_sse`):**
   - **定义:** 在 `fenv-x86.c` 中定义，作用域限定在当前文件。
   - **引用:** 只能在 `fenv-x86.c` 内部引用。
   - **处理:**
     - **编译时:** 编译器会直接生成函数调用的代码。
     - **链接时:** 静态链接器会将静态函数的代码直接链接到使用它的地方，不需要动态链接器的参与。这些符号通常不会出现在动态符号表中。

**假设输入与输出 (逻辑推理):**

假设我们有以下代码片段：

```c
#include <fenv.h>
#include <stdio.h>

int main() {
    fenv_t env;
    fegetenv(&env); // 获取当前环境

    // 设置舍入到向上舍入
    fesetround(FE_UPWARD);

    printf("2.3 rounded upward: %.0f\n", 2.3);

    fesetenv(&env); // 恢复之前的环境
    printf("2.3 rounded with original setting: %.0f\n", 2.3);

    return 0;
}
```

**假设输入:**  程序启动时，浮点舍入模式为默认的 `FE_TONEAREST`。

**预期输出:**

```
2.3 rounded upward: 3
2.3 rounded with original setting: 2
```

**解释:**

1. `fegetenv(&env)` 保存了初始的浮点环境。
2. `fesetround(FE_UPWARD)` 将舍入模式设置为向上舍入。
3. `printf("2.3 rounded upward: %.0f\n", 2.3)` 会将 2.3 向上舍入到 3。
4. `fesetenv(&env)` 恢复了之前保存的浮点环境（舍入模式恢复为 `FE_TONEAREST`）。
5. `printf("2.3 rounded with original setting: %.0f\n", 2.3)` 会按照默认的舍入到最近的规则，将 2.3 舍入到 2。

**用户或编程常见的使用错误:**

1. **未检查 `fesetround` 的返回值:** `fesetround` 在设置无效的舍入模式时会返回 -1，但程序员可能忽略了返回值检查，导致程序行为不符合预期。

   ```c
   if (fesetround(invalid_round_mode) == -1) {
       fprintf(stderr, "Error setting rounding mode!\n");
       // ... 处理错误 ...
   }
   ```

2. **错误地假设浮点环境的初始状态:**  不同的平台或编译器可能对浮点环境有不同的默认设置，程序员不应假设一个特定的初始状态，而应该显式地设置需要的环境。

3. **在多线程环境下不正确地使用浮点环境控制:** 浮点环境是线程本地的，在一个线程中修改浮点环境不会影响其他线程。但如果多个线程共享某些浮点计算的代码，需要仔细考虑如何管理浮点环境，避免互相干扰。可以使用线程局部存储（TLS）来管理每个线程的浮点环境。

4. **忘记恢复浮点环境:** 在修改了浮点环境之后，应该在不再需要自定义环境时将其恢复到之前的状态，避免影响程序的其他部分。

5. **不理解浮点异常的含义和处理方式:** 盲目地屏蔽所有浮点异常可能会掩盖程序中的潜在错误。应该根据具体情况选择需要捕获和处理的异常。

**Android Framework 或 NDK 如何到达这里 (调试线索):**

1. **NDK (Native Development Kit):**  如果 Android 应用使用了 NDK 进行本地开发，那么本地 C/C++ 代码可以直接调用 `<fenv.h>` 中定义的函数。例如，一个使用 OpenGL ES 进行图形渲染的应用，其本地代码可能会调用 `fesetround` 来控制浮点运算的精度。

   * **调试线索:** 在本地代码中使用 GDB 或 LLDB 进行调试，设置断点在 `fesetround` 等函数入口，可以跟踪调用堆栈，查看是哪个本地模块发起的调用。

2. **Android Framework (Java 代码间接调用):** 虽然 Java 代码本身不直接操作浮点环境，但某些 Framework 层的操作可能会最终调用到本地代码，而这些本地代码可能会使用 `<fenv.h>` 中的函数。例如，涉及到数学计算、图形处理、音频处理等底层服务，可能会使用到这些功能。

   * **调试线索:**
     * **Tracing:** 使用 `adb logcat` 查看系统日志，可能会有与浮点异常相关的输出（如果异常没有被屏蔽）。
     * **System Calls:** 使用 `strace` 命令跟踪进程的系统调用，可以观察到与浮点环境相关的系统调用（虽然 `<fenv.h>` 的函数通常不直接对应系统调用，但它们会操作 FPU 状态）。
     * **Framework 源码分析:** 分析 Android Framework 的源码，特别是与数学、图形、音频相关的模块，查看是否有本地方法的调用，并追踪到本地代码中是否使用了 `<fenv.h>` 的函数。
     * **Perfetto/Systrace:** 使用性能分析工具 Perfetto 或 Systrace 可以捕获更底层的系统事件和函数调用，帮助追踪执行路径。
     * **JNI 桥接:** 重点关注 Java 代码通过 JNI (Java Native Interface) 调用本地代码的过程，检查本地方法中是否使用了浮点环境控制功能。

**示例 NDK 调用链:**

1. **Java 代码:**
   ```java
   public class MyRenderer {
       static {
           System.loadLibrary("my_native_lib");
       }
       public native void nativeRender();
   }
   ```

2. **Native 代码 (my_native_lib.c):**
   ```c
   #include <fenv.h>
   #include <jni.h>
   #include <android/log.h>

   JNIEXPORT void JNICALL Java_com_example_myapp_MyRenderer_nativeRender(JNIEnv *env, jobject thiz) {
       fenv_t current_env;
       fegetenv(&current_env);
       __android_log_print(ANDROID_LOG_INFO, "MyTag", "Current rounding mode: %d", fegetround());

       fesetround(FE_TOWARDZERO);
       // ... 进行一些需要特定舍入模式的渲染操作 ...

       fesetenv(&current_env); // 恢复之前的环境
   }
   ```

在这个例子中，Java 代码调用了本地方法 `nativeRender`，而 `nativeRender` 中使用了 `fegetenv`, `fesetround`, 和 `fesetenv` 来控制浮点环境。调试时，可以在 `nativeRender` 函数中设置断点，查看浮点环境的变化。

希望以上详细的分析能够帮助你理解 `bionic/libm/fenv-x86.c` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libm/fenv-x86.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * Copyright (c) 2004-2005 David Schultz <das@FreeBSD.ORG>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/lib/msun/i387/fenv.c,v 1.2 2005/03/17 22:21:46 das Exp $
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include "fenv.h"

#define ROUND_MASK   (FE_TONEAREST | FE_DOWNWARD | FE_UPWARD | FE_TOWARDZERO)

/*
 * The hardware default control word for i387's and later coprocessors is
 * 0x37F, giving:
 *
 *	round to nearest
 *	64-bit precision
 *	all exceptions masked.
 *
 * We modify the affine mode bit and precision bits in this to give:
 *
 *	affine mode for 287's (if they work at all) (1 in bitfield 1<<12)
 *	53-bit precision (2 in bitfield 3<<8)
 *
 * 64-bit precision often gives bad results with high level languages
 * because it makes the results of calculations depend on whether
 * intermediate values are stored in memory or in FPU registers.
 */
#define	__INITIAL_NPXCW__	0x127F
#define	__INITIAL_MXCSR__	0x1F80

/*
 * As compared to the x87 control word, the SSE unit's control word
 * has the rounding control bits offset by 3 and the exception mask
 * bits offset by 7.
 */
#define _SSE_ROUND_SHIFT 3
#define _SSE_EMASK_SHIFT 7

const fenv_t __fe_dfl_env = {
  __INITIAL_NPXCW__, /*__control*/
  0x0000,            /*__mxcsr_hi*/
  0x0000,            /*__status*/
  0x1f80,            /*__mxcsr_lo*/
  0xffffffff,        /*__tag*/
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff } /*__other*/
};

#define __fldcw(__cw)           __asm volatile("fldcw %0" : : "m" (__cw))
#define __fldenv(__env)         __asm volatile("fldenv %0" : : "m" (__env))
#define __fldenvx(__env)        __asm volatile("fldenv %0" : : "m" (__env)  \
                                : "st", "st(1)", "st(2)", "st(3)", "st(4)",   \
                                "st(5)", "st(6)", "st(7)")
#define __fnclex()              __asm volatile("fnclex")
#define __fnstenv(__env)        __asm volatile("fnstenv %0" : "=m" (*(__env)))
#define __fnstcw(__cw)          __asm volatile("fnstcw %0" : "=m" (*(__cw)))
#define __fnstsw(__sw)          __asm volatile("fnstsw %0" : "=am" (*(__sw)))
#define __fwait()               __asm volatile("fwait")
#define __ldmxcsr(__csr)        __asm volatile("ldmxcsr %0" : : "m" (__csr))
#define __stmxcsr(__csr)        __asm volatile("stmxcsr %0" : "=m" (*(__csr)))

/* After testing for SSE support once, we cache the result in __has_sse. */
enum __sse_support { __SSE_YES, __SSE_NO, __SSE_UNK };
#ifdef __SSE__
#define __HAS_SSE()     1
#else
#define __HAS_SSE()     (__has_sse == __SSE_YES ||                      \
                        (__has_sse == __SSE_UNK && __test_sse()))
#endif

enum __sse_support __has_sse =
#ifdef __SSE__
  __SSE_YES;
#else
  __SSE_UNK;
#endif

#ifndef __SSE__
#define getfl(x)    __asm volatile("pushfl\n\tpopl %0" : "=mr" (*(x)))
#define setfl(x)    __asm volatile("pushl %0\n\tpopfl" : : "g" (x))
#define cpuid_dx(x) __asm volatile("pushl %%ebx\n\tmovl $1, %%eax\n\t"  \
                    "cpuid\n\tpopl %%ebx"          \
                    : "=d" (*(x)) : : "eax", "ecx")

/*
 * Test for SSE support on this processor.  We need to do this because
 * we need to use ldmxcsr/stmxcsr to get correct results if any part
 * of the program was compiled to use SSE floating-point, but we can't
 * use SSE on older processors.
 */
int
__test_sse(void)
{
  int flag, nflag;
  int dx_features;

  /* Am I a 486? */
  getfl(&flag);
  nflag = flag ^ 0x200000;
  setfl(nflag);
  getfl(&nflag);
  if (flag != nflag) {
    /* Not a 486, so CPUID should work. */
    cpuid_dx(&dx_features);
    if (dx_features & 0x2000000) {
      __has_sse = __SSE_YES;
      return (1);
    }
  }
  __has_sse = __SSE_NO;
  return (0);
}
#endif /* __SSE__ */

int
fesetexceptflag(const fexcept_t *flagp, int excepts)
{
  fenv_t env;
  __uint32_t mxcsr;

  excepts &= FE_ALL_EXCEPT;
  if (excepts) { /* Do nothing if excepts is 0 */
    __fnstenv(&env);
    env.__status &= ~excepts;
    env.__status |= *flagp & excepts;
    __fnclex();
    __fldenv(env);
    if (__HAS_SSE()) {
      __stmxcsr(&mxcsr);
      mxcsr &= ~excepts;
      mxcsr |= *flagp & excepts;
      __ldmxcsr(mxcsr);
    }
  }

  return (0);
}

int
feraiseexcept(int excepts)
{
  fexcept_t ex = excepts;

  fesetexceptflag(&ex, excepts);
  __fwait();
  return (0);
}

int
fegetenv(fenv_t *envp)
{
  __uint32_t mxcsr;

  __fnstenv(envp);
  /*
   * fnstenv masks all exceptions, so we need to restore
   * the old control word to avoid this side effect.
   */
  __fldcw(envp->__control);
  if (__HAS_SSE()) {
    __stmxcsr(&mxcsr);
    envp->__mxcsr_hi = mxcsr >> 16;
    envp->__mxcsr_lo = mxcsr & 0xffff;
  }
  return (0);
}

int
feholdexcept(fenv_t *envp)
{
  __uint32_t mxcsr;
  fenv_t env;

  __fnstenv(&env);
  *envp = env;
  env.__status &= ~FE_ALL_EXCEPT;
  env.__control |= FE_ALL_EXCEPT;
  __fnclex();
  __fldenv(env);
  if (__HAS_SSE()) {
    __stmxcsr(&mxcsr);
    envp->__mxcsr_hi = mxcsr >> 16;
    envp->__mxcsr_lo = mxcsr & 0xffff;
    mxcsr &= ~FE_ALL_EXCEPT;
    mxcsr |= FE_ALL_EXCEPT << _SSE_EMASK_SHIFT;
    __ldmxcsr(mxcsr);
  }
  return (0);
}

int
feupdateenv(const fenv_t *envp)
{
  __uint32_t mxcsr;
  __uint16_t status;

  __fnstsw(&status);
  if (__HAS_SSE()) {
    __stmxcsr(&mxcsr);
  } else {
    mxcsr = 0;
  }
  fesetenv(envp);
  feraiseexcept((mxcsr | status) & FE_ALL_EXCEPT);
  return (0);
}

int
feenableexcept(int mask)
{
  __uint32_t mxcsr;
  __uint16_t control, omask;

  mask &= FE_ALL_EXCEPT;
  __fnstcw(&control);
  if (__HAS_SSE()) {
    __stmxcsr(&mxcsr);
  } else {
    mxcsr = 0;
  }
  omask = ~(control | mxcsr >> _SSE_EMASK_SHIFT) & FE_ALL_EXCEPT;
  if (mask) {
    control &= ~mask;
    __fldcw(control);
    if (__HAS_SSE()) {
      mxcsr &= ~(mask << _SSE_EMASK_SHIFT);
      __ldmxcsr(mxcsr);
    }
  }
  return (omask);
}

int
fedisableexcept(int mask)
{
  __uint32_t mxcsr;
  __uint16_t control, omask;

  mask &= FE_ALL_EXCEPT;
  __fnstcw(&control);
  if (__HAS_SSE()) {
    __stmxcsr(&mxcsr);
  } else {
    mxcsr = 0;
  }
  omask = ~(control | mxcsr >> _SSE_EMASK_SHIFT) & FE_ALL_EXCEPT;
  if (mask) {
    control |= mask;
    __fldcw(control);
    if (__HAS_SSE()) {
      mxcsr |= mask << _SSE_EMASK_SHIFT;
      __ldmxcsr(mxcsr);
    }
  }
  return (omask);
}

int
feclearexcept(int excepts)
{
  fenv_t env;
  __uint32_t mxcsr;

  excepts &= FE_ALL_EXCEPT;
  if (excepts) { /* Do nothing if excepts is 0 */
    __fnstenv(&env);
    env.__status &= ~excepts;
    __fnclex();
    __fldenv(env);
    if (__HAS_SSE()) {
      __stmxcsr(&mxcsr);
      mxcsr &= ~excepts;
      __ldmxcsr(mxcsr);
    }
  }
  return (0);
}

int
fegetexceptflag(fexcept_t *flagp, int excepts)
{
  __uint32_t mxcsr;
  __uint16_t status;

  excepts &= FE_ALL_EXCEPT;
  __fnstsw(&status);
  if (__HAS_SSE()) {
    __stmxcsr(&mxcsr);
  } else {
    mxcsr = 0;
  }
  *flagp = (status | mxcsr) & excepts;
  return (0);
}

int
fetestexcept(int excepts)
{
  __uint32_t mxcsr;
  __uint16_t status;

  excepts &= FE_ALL_EXCEPT;
  if (excepts) { /* Do nothing if excepts is 0 */
    __fnstsw(&status);
    if (__HAS_SSE()) {
      __stmxcsr(&mxcsr);
    } else {
      mxcsr = 0;
    }
    return ((status | mxcsr) & excepts);
  }
  return (0);
}

int
fegetround(void)
{
  __uint16_t control;

  /*
   * We assume that the x87 and the SSE unit agree on the
   * rounding mode.  Reading the control word on the x87 turns
   * out to be about 5 times faster than reading it on the SSE
   * unit on an Opteron 244.
   */
  __fnstcw(&control);
  return (control & ROUND_MASK);
}

int
fesetround(int round)
{
  __uint32_t mxcsr;
  __uint16_t control;

  if (round & ~ROUND_MASK) {
    return (-1);
  } else {
    __fnstcw(&control);
    control &= ~ROUND_MASK;
    control |= round;
    __fldcw(control);
    if (__HAS_SSE()) {
      __stmxcsr(&mxcsr);
      mxcsr &= ~(ROUND_MASK << _SSE_ROUND_SHIFT);
      mxcsr |= round << _SSE_ROUND_SHIFT;
      __ldmxcsr(mxcsr);
    }
    return (0);
  }
}

int
fesetenv(const fenv_t *envp)
{
  fenv_t env = *envp;
  __uint32_t mxcsr;

  mxcsr = (env.__mxcsr_hi << 16) | (env.__mxcsr_lo);
  env.__mxcsr_hi = 0xffff;
  env.__mxcsr_lo = 0xffff;
  /*
   * XXX Using fldenvx() instead of fldenv() tells the compiler that this
   * instruction clobbers the i387 register stack.  This happens because
   * we restore the tag word from the saved environment.  Normally, this
   * would happen anyway and we wouldn't care, because the ABI allows
   * function calls to clobber the i387 regs.  However, fesetenv() is
   * inlined, so we need to be more careful.
   */
  __fldenvx(env);
  if (__HAS_SSE()) {
    __ldmxcsr(mxcsr);
  }
  return (0);
}

int
fegetexcept(void)
{
  __uint16_t control;

  /*
   * We assume that the masks for the x87 and the SSE unit are
   * the same.
   */
  __fnstcw(&control);
  return (~control & FE_ALL_EXCEPT);
}

"""

```