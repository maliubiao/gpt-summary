Response:
Let's break down the thought process to answer the user's request about `bionic/libm/fenv-arm64.c`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided C code snippet, specifically focusing on its purpose within Android's Bionic library, its relationship to floating-point exception handling, and related concepts like the dynamic linker. They also want debugging guidance.

**2. Initial Analysis of the Code:**

* **Headers:** The code includes `stdint.h` and `fenv.h`. This immediately signals that it deals with floating-point environment control as defined by the standard `fenv.h`.
* **Copyright Notice:**  The copyright indicates it's derived from FreeBSD, hinting at its role as a standard part of a C library.
* **Global Variable:** `__fe_dfl_env` suggests a default floating-point environment.
* **Typedefs:** `fpu_control_t` and `fpu_status_t` strongly suggest interaction with ARM64 processor registers (FPCR and FPSR).
* **Macros `__get` and `__set`:** These are crucial. They use inline assembly to directly read from and write to processor registers. This confirms the code's low-level nature and direct interaction with hardware.
* **Function Definitions:** The functions like `fegetenv`, `fesetenv`, `feclearexcept`, etc., are all standard functions defined in `fenv.h`. This reinforces the code's purpose as implementing the floating-point environment functionality.

**3. Deconstructing the User's Questions:**

* **Functionality:**  The core functionality is clearly manipulating the floating-point environment: getting, setting, clearing, testing, raising, and controlling rounding modes for floating-point exceptions.
* **Relationship to Android:**  Bionic is Android's C library, so this file is a *core* part of how Android handles floating-point operations. Examples would involve any app doing floating-point math, especially those that need precise control over exceptions.
* **libc Function Implementation:**  The implementation uses direct register access (`mrs` and `msr` instructions). The logic for each function involves reading the relevant registers, modifying them based on the input parameters, and writing the modified values back.
* **Dynamic Linker:** This is a separate but related topic. The user wants to know how the dynamic linker handles symbols from this library. This requires explaining the structure of shared libraries (.so files), symbol tables (global, local, undefined), and the linking process.
* **Logic Reasoning:**  For functions like `fesetround`, there's a clear transformation of input (rounding mode) to output (modified FPCR value). Hypothetical inputs and outputs can illustrate this.
* **User Errors:** Common errors involve incorrect usage of the `fenv.h` functions, leading to unexpected floating-point behavior or silent errors.
* **Debugging Path:**  The user wants to know how a call from an Android app eventually reaches this code. This involves tracing the call stack from the application level through the NDK (if used), the Android Framework, and finally into Bionic.

**4. Structuring the Answer:**

Based on the analysis, a structured approach is needed:

* **Overview:** Start with a high-level summary of the file's purpose.
* **Function-by-Function Explanation:**  Detail the functionality and implementation of each exported function.
* **Android Relevance:** Provide concrete examples of how this code is used in Android.
* **Dynamic Linker Details:**  Address the .so layout and symbol resolution process.
* **Logic Reasoning:** Give examples of how specific functions work with hypothetical inputs.
* **Common Errors:** Explain potential pitfalls for developers.
* **Debugging Path:** Outline the steps from an Android app to this code.

**5. Fleshing out the Details:**

* **For each `fenv.h` function:** Describe its standard purpose and then detail how the ARM64-specific implementation achieves it (primarily through register manipulation).
* **Android Examples:** Think of scenarios where floating-point control is important: high-precision calculations, scientific applications, graphics rendering (though less direct here).
* **Dynamic Linker Explanation:** Use a simplified .so layout, focusing on the symbol table entries (STT_FUNC, STT_OBJECT). Describe how `dlopen`, `dlsym`, and lazy/eager linking work.
* **Logic Reasoning Examples:** For `fesetround`, show how different `round` values map to the FPCR bit manipulation.
* **Common Errors:**  Focus on misunderstanding exception flags, incorrect rounding mode settings, and not checking return values.
* **Debugging Path:**  Emphasize the role of the NDK, the Android Framework (e.g., through the `java.lang.Math` class using native methods), and system calls. Explain how to use tools like debuggers and `adb logcat`.

**6. Refinement and Language:**

* **Clarity:** Use clear and concise language, avoiding overly technical jargon where possible.
* **Accuracy:** Ensure the technical details (register names, instruction names) are correct.
* **Completeness:**  Address all aspects of the user's request.
* **Organization:**  Use headings and bullet points to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus solely on the C code.
* **Correction:**  Realize the user explicitly asked about Android context and dynamic linking, so expand the scope.
* **Initial thought:**  Go into extreme detail about ARM64 architecture.
* **Correction:**  Provide enough detail to be informative but avoid overwhelming the user with unnecessary low-level specifics. Focus on the *relevant* aspects for understanding the code's function.
* **Initial thought:**  Assume the user is an expert in floating-point arithmetic.
* **Correction:** Explain concepts like rounding modes and exception flags briefly to ensure broader understanding.

By following these steps, combining code analysis with understanding the user's needs, and refining the approach along the way, a comprehensive and helpful answer can be constructed.
好的，让我们详细分析一下 `bionic/libm/fenv-arm64.c` 这个文件。

**文件功能概述**

`bionic/libm/fenv-arm64.c` 实现了 C 标准库 `<fenv.h>` 中定义的用于控制和查询浮点环境的功能。它针对 ARM64 架构进行了特定的实现，直接操作 ARM64 处理器的浮点控制寄存器 (FPCR) 和浮点状态寄存器 (FPSR)。

**具体功能列举**

该文件主要提供了以下功能：

1. **获取和设置浮点环境：**
   - `fegetenv(fenv_t* envp)`: 获取当前的浮点环境并存储到 `envp` 指向的结构体中。
   - `fesetenv(const fenv_t* envp)`: 将浮点环境设置为 `envp` 指向的结构体中存储的值。

2. **清除浮点异常标志：**
   - `feclearexcept(int excepts)`: 清除指定的浮点异常标志（例如，除零、溢出等）。

3. **获取和设置浮点异常标志：**
   - `fegetexceptflag(fexcept_t* flagp, int excepts)`: 获取指定浮点异常标志的当前状态。
   - `fesetexceptflag(const fexcept_t* flagp, int excepts)`: 设置指定的浮点异常标志的状态。

4. **引发浮点异常：**
   - `feraiseexcept(int excepts)`: 尝试引发指定的浮点异常。

5. **测试浮点异常标志：**
   - `fetestexcept(int excepts)`: 检查是否设置了指定的浮点异常标志。

6. **获取和设置舍入模式：**
   - `fegetround(void)`: 获取当前的浮点舍入模式（例如，舍入到最接近的值、朝零舍入等）。
   - `fesetround(int round)`: 设置浮点舍入模式。

7. **保存和恢复浮点环境，并清除异常：**
   - `feholdexcept(fenv_t* envp)`: 获取当前的浮点环境并清除所有的浮点异常标志。
   - `feupdateenv(const fenv_t* envp)`: 设置浮点环境为 `envp` 指向的值，并重新引发之前被 `feholdexcept` 保存的异常。

8. **启用和禁用浮点异常陷阱（trap）：**
   - `feenableexcept(int mask)`:  在 ARM64 上，此函数总是返回 -1，表示无法启用浮点异常陷阱。
   - `fedisableexcept(int mask)`:  在 ARM64 上，此函数总是返回 0，表示禁用浮点异常陷阱。

9. **获取所有支持的异常标志：**
   - `fegetexcept(void)`: 在 ARM64 上，总是返回 0。

**与 Android 功能的关系及举例说明**

这个文件是 Android 底层 C 库 (Bionic) 的一部分，因此直接影响着所有使用浮点运算的 Android 应用程序和系统组件。

* **Java `java.lang.Math` 类:**  Java 的 `Math` 类中的许多方法（例如 `sin`, `cos`, `sqrt` 等）最终会调用到 Bionic 的数学库实现，而 Bionic 的数学库可能会受到浮点环境设置的影响。例如，你可以通过 JNI 调用 Bionic 的函数来修改浮点舍入模式，这会影响 `java.lang.Math.round()` 等方法的行为。

* **NDK 开发:** 使用 NDK 进行原生开发的应用程序，其 C/C++ 代码中的浮点运算直接依赖于 Bionic 提供的浮点环境管理。开发者可以使用 `<fenv.h>` 中的函数来控制浮点异常的处理和舍入模式。例如，一个进行科学计算的 NDK 应用可能需要捕获浮点除零异常并进行特殊处理。

* **图形渲染 (OpenGL ES, Vulkan):** 图形渲染大量使用浮点运算。虽然这些库通常有自己的错误处理机制，但底层的浮点环境设置仍然可能产生影响，尤其是在处理精度和异常方面。

**libc 函数的实现细节**

这些 libc 函数的实现核心在于直接操作 ARM64 的浮点控制寄存器 (FPCR) 和浮点状态寄存器 (FPSR)。

* **`fegetenv(fenv_t* envp)`:**
    - 使用内联汇编指令 `mrs` (move register to system register) 从 FPCR 和 FPSR 读取值。
    - 将读取到的 FPCR 值存储到 `envp->__control`，将 FPSR 值存储到 `envp->__status`。

* **`fesetenv(const fenv_t* envp)`:**
    - 使用内联汇编指令 `msr` (move system register to register) 将 `envp->__control` 的值写入 FPCR。
    - 将 `envp->__status` 的值写入 FPSR。
    - **注意:**  为了避免不必要的寄存器写入，会先读取当前的 FPCR 值，只有当 `envp->__control` 与当前 FPCR 不同时才进行写入。

* **`feclearexcept(int excepts)`:**
    - 读取当前的 FPSR 值。
    - 使用位运算 `& ~` 清除 FPSR 中与 `excepts` 中指定的异常标志位相对应的位。
    - 将修改后的 FPSR 值写回寄存器。

* **`fegetexceptflag(fexcept_t* flagp, int excepts)`:**
    - 读取当前的 FPSR 值。
    - 使用位运算 `&` 提取 FPSR 中与 `excepts` 中指定的异常标志位相对应的位。
    - 将提取到的值存储到 `*flagp`。

* **`fesetexceptflag(const fexcept_t* flagp, int excepts)`:**
    - 读取当前的 FPSR 值。
    - 使用位运算 `& ~` 清除 FPSR 中与 `excepts` 中指定的异常标志位相对应的位。
    - 使用位运算 `| &` 将 `*flagp` 中对应的位设置到 FPSR。
    - 将修改后的 FPSR 值写回寄存器。

* **`feraiseexcept(int excepts)`:**
    - 创建一个 `fexcept_t` 变量 `ex` 并赋值为 `excepts`。
    - 调用 `fesetexceptflag(&ex, excepts)` 来设置异常标志，这可能会导致程序行为的改变，但实际是否会产生硬件异常取决于系统的配置。

* **`fetestexcept(int excepts)`:**
    - 读取当前的 FPSR 值。
    - 使用位运算 `&` 检查 FPSR 中是否设置了 `excepts` 中指定的任何异常标志。

* **`fegetround(void)`:**
    - 读取当前的 FPCR 值。
    - 使用位移 `>>` 和位掩码 `& FE_TOWARDZERO`（注意这里的 `FE_TOWARDZERO` 实际上代表了舍入模式的掩码）提取舍入模式位。

* **`fesetround(int round)`:**
    - 检查 `round` 参数是否是有效的舍入模式。
    - 读取当前的 FPCR 值。
    - 使用位运算 `& ~` 清除 FPCR 中现有的舍入模式位。
    - 使用位运算 `| <<` 将新的舍入模式设置到 FPCR 中。
    - 同样，为了避免不必要的写入，会检查新的 FPCR 值是否与旧值不同。

* **`feholdexcept(fenv_t* envp)`:**
    - 调用 `fegetenv(envp)` 保存当前的浮点环境。
    - 调用 `feclearexcept(FE_ALL_EXCEPT)` 清除所有浮点异常标志。

* **`feupdateenv(const fenv_t* envp)`:**
    - 调用 `fetestexcept(FE_ALL_EXCEPT)` 获取当前设置的异常标志。
    - 调用 `fesetenv(envp)` 恢复之前保存的浮点环境。
    - 调用 `feraiseexcept(excepts)` 重新引发在调用 `feholdexcept` 之前发生的异常。

* **`feenableexcept(int mask)` 和 `fedisableexcept(int mask)`:**
    - 在 ARM64 上，浮点异常陷阱的控制通常由操作系统或其他机制处理，而不是直接通过修改 FPCR/FPSR。因此，这两个函数的实现比较简单。`feenableexcept` 总是返回 -1，表示无法启用，而 `fedisableexcept` 总是返回 0。

* **`fegetexcept(void)`:**
    -  此函数本应返回所有支持的异常标志的位掩码，但在当前的实现中直接返回 0。这可能意味着在 ARM64 Bionic 中，并没有直接提供查询所有支持异常的能力，或者这个功能没有被实现。

**Dynamic Linker 功能**

当一个应用程序或共享库（.so 文件）使用到 `libm.so` (Bionic 的数学库，包含 `fenv-arm64.o` 编译后的代码) 中的 `fenv.h` 函数时，Android 的动态链接器 `linker64` 负责将这些函数调用链接到 `libm.so` 中对应的实现。

**SO 布局样本**

假设 `libm.so` 包含 `fenv-arm64.o` 编译后的代码，一个简化的 `libm.so` 布局可能如下：

```
ELF Header
Program Headers (描述内存段，例如 .text, .data, .rodata)
Section Headers (描述各个 section 的信息)

.text section (代码段):
    - fegetenv 函数的代码
    - fesetenv 函数的代码
    - ... 其他 fenv.h 函数的代码
    - ... 其他数学函数代码

.rodata section (只读数据段):
    - __fe_dfl_env 变量的数据

.data section (可读写数据段):
    - (可能有一些内部使用的全局变量)

.symtab section (符号表):
    - 符号信息列表，包括函数名、变量名、地址等
    - 示例条目:
        - st_name: 指向字符串表中 "fegetenv" 的索引
        - st_value: fegetenv 函数在内存中的地址
        - st_size: fegetenv 函数的大小
        - st_info: 符号类型 (例如 STT_FUNC 表示函数)
        - st_other: 符号可见性
        - st_shndx: 符号所在 section 的索引

.strtab section (字符串表):
    - 存储符号名称的字符串，例如 "fegetenv", "__fe_dfl_env" 等

.rel.dyn section (动态重定位表):
    - 记录需要在加载时进行地址修正的信息 (对于 PIC 代码)

.rela.plt section (Procedure Linkage Table 重定位表):
    - 记录 PLT 表项的重定位信息，用于延迟绑定

... 其他 section
```

**符号处理过程**

1. **编译和链接:** 当应用程序或共享库的代码中调用了 `fegetenv` 等函数时，编译器会生成对这些符号的引用。链接器在链接时会查找这些符号的定义。对于动态链接的库，链接器通常不会解析所有符号的地址，而是生成需要在运行时解析的重定位信息。

2. **加载时:** 当 Android 系统加载应用程序或共享库时，动态链接器 `linker64` 会被调用。

3. **查找共享库:** 动态链接器会根据依赖关系查找所需的共享库 (`libm.so` 在这里)。

4. **加载共享库:** 将 `libm.so` 加载到内存中的某个地址空间。

5. **符号解析:**
   - **全局符号:** `fegetenv` 等在 `libm.so` 中定义的函数是全局符号。动态链接器会在 `libm.so` 的符号表 (`.symtab`) 中查找这些符号的地址。
   - **本地符号:**  `fenv-arm64.c` 中定义的 `__get`, `__set` 等宏并不是外部可见的符号，它们通常不会出现在共享库的全局符号表中。
   - **未定义符号:** 如果应用程序或共享库引用了在任何已加载的共享库中都找不到的符号，链接器会报告一个未定义符号的错误。

6. **重定位:**
   - **数据引用:** 如果应用程序或共享库中使用了 `__fe_dfl_env` 这样的全局变量，动态链接器需要将对这个变量的引用修正为它在 `libm.so` 中的实际地址。这通过处理 `.rel.dyn` section 中的重定位条目完成。
   - **函数调用:** 对于函数调用，通常使用 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 机制实现延迟绑定。
     - 第一次调用 `fegetenv` 时，会跳转到 PLT 中对应的条目。
     - PLT 条目会调用动态链接器的代码。
     - 动态链接器在 GOT 中查找 `fegetenv` 的地址，如果地址尚未解析，则在 `libm.so` 的符号表中查找并更新 GOT。
     - 然后，PLT 条目会将控制权转移到 `fegetenv` 的实际地址。
     - 后续对 `fegetenv` 的调用会直接跳转到 GOT 中已解析的地址，避免了重复的符号查找。

**假设输入与输出（逻辑推理）**

以 `fesetround` 函数为例：

**假设输入:** `round = FE_TOWARDZERO`

**逻辑推理:**

1. `FE_TOWARDZERO` 的值通常是 `0x0001` (二进制 `0001`)。
2. `FPCR_RMODE_SHIFT` 被定义为 `22`。
3. 当前 `fpcr` 的值假设为 `0x00800000` (二进制 `0000 0000 1000 0000 0000 0000 0000 0000`)，其中舍入模式位可能是 `00` (例如，舍入到最接近的值)。
4. `fpcr & ~(FE_TOWARDZERO << FPCR_RMODE_SHIFT)`:
   - `FE_TOWARDZERO << FPCR_RMODE_SHIFT` 变为 `0x00000400` (二进制 `0000 0000 0000 0000 0000 0100 0000 0000`)。
   - `0x00800000 & ~0x00400000` 结果是 `0x00800000` (假设原舍入模式不是 towardZero)。
5. `new_fpcr |= (round << FPCR_RMODE_SHIFT)`:
   - `round << FPCR_RMODE_SHIFT` 得到 `0x00000400`。
   - `0x00800000 | 0x00000400` 结果是 `0x00800400`。
6. `__set_fpcr(new_fpcr)` 将 `0x00800400` 写入 FPCR 寄存器，从而将舍入模式设置为朝零舍入。

**输出:** FPCR 寄存器的值被修改，舍入模式变为朝零舍入。

**用户或编程常见的使用错误**

1. **不理解浮点异常标志的含义:** 错误地假设某个操作会引发特定类型的异常，或者不正确地处理异常标志。
   ```c
   #include <fenv.h>
   #include <stdio.h>

   int main() {
       feclearexcept(FE_ALL_EXCEPT);
       double result = 1.0 / 0.0; // 除零操作
       if (fetestexcept(FE_DIVBYZERO)) {
           printf("Division by zero occurred.\n");
       } else {
           printf("Division by zero did not occur (incorrectly).\n");
       }
       return 0;
   }
   ```

2. **错误地设置舍入模式:**  在需要特定精度的计算中，设置了不正确的舍入模式可能导致计算结果的偏差超出预期。
   ```c
   #include <fenv.h>
   #include <math.h>
   #include <stdio.h>

   int main() {
       fesetround(FE_UPWARD); // 设置为向上舍入
       double x = 3.1;
       int rounded_x = rint(x); // 使用当前的舍入模式
       printf("Rounded value of %f is %d\n", x, rounded_x); // 可能会输出 4 而不是 3
       return 0;
   }
   ```

3. **假设所有平台行为一致:**  虽然 `<fenv.h>` 是标准，但不同架构和操作系统的实现细节可能有所不同。例如，浮点异常陷阱的行为可能不一致。

4. **忘记清除异常标志:** 在检查异常标志之前没有清除它们，可能导致检查到之前的操作产生的异常。

5. **滥用或误解 `feholdexcept` 和 `feupdateenv`:**  如果没有正确理解这两个函数的使用场景，可能会导致异常信息丢失或不正确的异常处理。

**Android Framework 或 NDK 如何到达这里（调试线索）**

1. **Java 代码调用 `java.lang.Math`:**
   - 例如，`java.lang.Math.sqrt(double a)` 方法。
   - 这些 `java.lang.Math` 方法通常是 native 方法。

2. **NDK 调用 (如果使用):**
   - 如果你的 Android 应用使用了 NDK，你的 C/C++ 代码可以直接包含 `<fenv.h>` 并调用其中的函数。
   - 例如：
     ```c++
     #include <fenv.h>
     #include <jni.h>

     extern "C" JNIEXPORT void JNICALL
     Java_com_example_myapp_MainActivity_setRoundingMode(JNIEnv *env, jobject /* this */, jint mode) {
         fesetround(mode);
     }
     ```

3. **Bionic 数学库 (`libm.so`):**
   - `java.lang.Math` 的 native 方法最终会调用到 Bionic 的数学库实现。
   - 例如，`java.lang.Math.sqrt()` 可能会调用 `bionic/libm/upstream-freebsd/lib/msun/src/s_sqrt.c` 中的实现。
   - 在这些数学函数的实现中，可能会间接地依赖于浮点环境的设置。

4. **系统调用 (间接):**
   - 虽然 `fenv.h` 函数不直接涉及系统调用，但底层的浮点运算是由 CPU 执行的，操作系统负责管理进程的上下文，包括浮点寄存器的状态。

**调试线索:**

* **使用 Android Studio 的调试器:**  可以设置断点在 NDK 代码中 `<fenv.h>` 的函数调用处，查看寄存器的值。
* **使用 `adb shell` 和 `gdbserver`:**  可以远程调试 Android 设备上的原生代码。
* **查看 `logcat` 输出:**  虽然 `<fenv.h>` 函数本身不产生日志，但与浮点运算相关的错误或异常可能在日志中有所体现。
* **使用 `perf` 等性能分析工具:**  可以分析应用程序的性能，包括浮点运算的开销。
* **查看 Bionic 源代码:**  深入理解 Bionic 的实现是理解浮点环境管理的最佳方式。

总而言之，`bionic/libm/fenv-arm64.c` 是 Android 底层浮点环境管理的关键组成部分，它直接与 ARM64 处理器的硬件特性交互，并为 Android 应用程序和框架提供了标准的浮点控制接口。理解其功能和实现细节对于开发高性能、精确的数值计算应用至关重要。

### 提示词
```
这是目录为bionic/libm/fenv-arm64.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*-
 * Copyright (c) 2004 David Schultz <das@FreeBSD.ORG>
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
 * $FreeBSD: libm/aarch64/fenv.c $
 */

#include <stdint.h>
#include <fenv.h>

#define FPCR_RMODE_SHIFT 22

const fenv_t __fe_dfl_env = { 0 /* control */, 0 /* status */};

typedef __uint32_t fpu_control_t;   // FPCR, Floating-point Control Register.
typedef __uint32_t fpu_status_t;    // FPSR, Floating-point Status Register.

#define __get(REGISTER, __value) { \
  uint64_t __value64; \
  __asm__ __volatile__("mrs %0," REGISTER : "=r" (__value64)); \
  __value = (__uint32_t) __value64; \
}
#define __get_fpcr(__fpcr) __get("fpcr", __fpcr)
#define __get_fpsr(__fpsr) __get("fpsr", __fpsr)

#define __set(REGISTER, __value) { \
  uint64_t __value64 = __value; \
  __asm__ __volatile__("msr " REGISTER ",%0" : : "ri" (__value64)); \
}
#define __set_fpcr(__fpcr) __set("fpcr", __fpcr)
#define __set_fpsr(__fpsr) __set("fpsr", __fpsr)

int fegetenv(fenv_t* envp) {
  __get_fpcr(envp->__control);
  __get_fpsr(envp->__status);
  return 0;
}

int fesetenv(const fenv_t* envp) {
  fpu_control_t fpcr;
  __get_fpcr(fpcr);
  if (envp->__control != fpcr) {
    __set_fpcr(envp->__control);
  }
  __set_fpsr(envp->__status);
  return 0;
}

int feclearexcept(int excepts) {
  fpu_status_t fpsr;
  __get_fpsr(fpsr);
  fpsr &= ~(excepts & FE_ALL_EXCEPT);
  __set_fpsr(fpsr);
  return 0;
}

int fegetexceptflag(fexcept_t* flagp, int excepts) {
  fpu_status_t fpsr;
  __get_fpsr(fpsr);
  *flagp = fpsr & (excepts & FE_ALL_EXCEPT);
  return 0;
}

int fesetexceptflag(const fexcept_t* flagp, int excepts) {
  excepts &= FE_ALL_EXCEPT;
  fpu_status_t fpsr;
  __get_fpsr(fpsr);
  fpsr &= ~excepts;
  fpsr |= *flagp & excepts;
  __set_fpsr(fpsr);
  return 0;
}

int feraiseexcept(int excepts) {
  fexcept_t ex = excepts;
  fesetexceptflag(&ex, excepts);
  return 0;
}

int fetestexcept(int excepts) {
  fpu_status_t fpsr;
  __get_fpsr(fpsr);
  return (fpsr & (excepts & FE_ALL_EXCEPT));
}

int fegetround(void) {
  fpu_control_t fpcr;
  __get_fpcr(fpcr);
  return ((fpcr >> FPCR_RMODE_SHIFT) & FE_TOWARDZERO);
}

int fesetround(int round) {
  if (round < FE_TONEAREST || round > FE_TOWARDZERO) return -1;
  fpu_control_t fpcr;
  __get_fpcr(fpcr);
  fpu_control_t new_fpcr = fpcr & ~(FE_TOWARDZERO << FPCR_RMODE_SHIFT);
  new_fpcr |= (round << FPCR_RMODE_SHIFT);
  if (new_fpcr != fpcr) {
    __set_fpcr(new_fpcr);
  }
  return 0;
}

int feholdexcept(fenv_t* envp) {
  fegetenv(envp);
  feclearexcept(FE_ALL_EXCEPT);
  return 0;
}

int feupdateenv(const fenv_t* envp) {
  int excepts = fetestexcept(FE_ALL_EXCEPT);
  fesetenv(envp);
  feraiseexcept(excepts);
  return 0;
}

int feenableexcept(int mask __unused) {
  return -1;
}

int fedisableexcept(int mask __unused) {
  return 0;
}

int fegetexcept(void) {
  return 0;
}
```