Response:
Let's break down the thought process for answering this request. The core task is to analyze a C header file related to floating-point environment control on ARM Android and explain its purpose and connections to the Android ecosystem.

**1. Understanding the Core Subject Matter:**

The first step is to recognize that `bionic/libc/include/bits/fenv_arm.handroid` deals with the floating-point environment (FPE) on ARM architectures within Android's libc (Bionic). Keywords here are "floating-point," "environment," "ARM," and "Android." This immediately suggests that the file defines structures and constants related to controlling how floating-point operations behave (rounding, exception handling).

**2. Analyzing the Code:**

Next, a detailed examination of the code is crucial. I'd look for:

* **Copyright Notice:** Note the origin (FreeBSD) and licensing (BSD). This hints at the portability and open-source nature of the underlying implementation.
* **`#pragma once`:** This standard C++ directive prevents multiple inclusions of the header file.
* **`#include <sys/types.h>`:**  This inclusion indicates the use of basic system types like `__uint32_t`.
* **`__BEGIN_DECLS` and `__END_DECLS`:** These are Bionic-specific macros likely used for C++ linkage control when included in C++ code. It's important to mention this aspect of Bionic's internal conventions.
* **`fenv_t` structure/typedef:** This is the central data structure representing the floating-point environment. The conditional definition based on `__LP64__` (for 64-bit architectures) is a significant point. It shows that the FPE is represented differently on 32-bit and 64-bit ARM. Specifically, on 64-bit, it holds the `FPCR` (control) and `FPSR` (status) registers directly, whereas on 32-bit, it's just a single `__uint32_t`, likely representing the `FPSCR`. Mentioning the ARM architecture documentation links is very helpful for deeper understanding.
* **`fexcept_t` typedef:** This represents the type for floating-point exception flags.
* **`FE_...` Macros (Exception Flags):** These define the possible floating-point exceptions (invalid operation, division by zero, overflow, underflow, inexact, denormal). It's important to explain what each represents.
* **`FE_ALL_EXCEPT` Macro:** This is a convenience macro to represent all possible exceptions.
* **`FE_...` Macros (Rounding Modes):** These define the different rounding modes for floating-point operations (to nearest, upward, downward, toward zero). Explaining each mode is essential.

**3. Connecting to Android Functionality:**

Once the code is understood, the next step is to connect it to Android.

* **Bionic's Role:** Emphasize that this file is part of Bionic, Android's core C library. This means any native Android process using standard C/C++ math functions will interact with these definitions.
* **NDK and Framework:** Explain how the NDK allows developers to write native code (C/C++) that utilizes these definitions. Mention how the Android Framework (written in Java/Kotlin) ultimately relies on native libraries, which in turn use Bionic.
* **Examples:** Provide concrete examples of how these flags and modes are relevant. For instance, catching `FE_DIVBYZERO` or setting the rounding mode to `FE_UPWARD` for specific calculations.

**4. Explaining Libc Function Implementation (Conceptual):**

Since the *source code* of the actual libc functions isn't provided, the explanation needs to be conceptual. Focus on *how* these definitions are used by functions like `fesetround`, `fegetround`, `feraiseexcept`, etc. Explain that these functions manipulate the underlying ARM processor registers (FPCR/FPSR/FPSCR) based on the values defined in this header file. Mention system calls or direct register manipulation as potential implementation methods.

**5. Dynamic Linker Aspects:**

While this *specific* header file doesn't directly involve dynamic linking, it's important to address the prompt. Explain the general role of the dynamic linker in loading shared libraries (.so files). Provide a sample .so layout (ELF structure components) and a simplified description of the linking process (symbol resolution, relocation). Acknowledge that this header file defines *data* used by code that *might* be in a shared library, but the header itself doesn't contain dynamic linking logic.

**6. Logic Reasoning (Hypothetical Input/Output):**

Create simple scenarios to illustrate how the flags and rounding modes work. For example:

* **Input:**  Division by zero. **Output:** `FE_DIVBYZERO` flag set.
* **Input:** Setting rounding mode to `FE_UPWARD`. **Output:** Subsequent calculations round towards positive infinity.

**7. Common Usage Errors:**

Think about common pitfalls developers might encounter when dealing with floating-point operations and the FPE:

* **Ignoring Exceptions:** Not checking the status flags after potential errors.
* **Incorrectly Setting Rounding Modes:**  Using a rounding mode that's not appropriate for the calculation.
* **Assumptions about Floating-Point Behavior:**  Not understanding the nuances of floating-point representation and arithmetic.

**8. Frida Hooking Example:**

Provide a practical Frida script to demonstrate how to intercept and inspect or modify the values defined in this header. Focus on hooking functions that interact with the FPE, like `fesetround` or `fegetenv`.

**9. Structuring the Answer:**

Organize the answer logically with clear headings and subheadings. Use bullet points and code blocks to make the information easy to read and understand.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe I should explain the precise assembly instructions used to manipulate the FPU registers. **Correction:** That's too low-level for this request. Focus on the higher-level concepts and the purpose of the header file.
* **Initial thought:** I should provide the exact source code of `fesetround`. **Correction:** The prompt only gives the header file. Explain the *concept* of how it works without needing the implementation details.
* **Initial thought:**  The dynamic linker section should be very detailed. **Correction:** The connection is indirect. Focus on the general principles of dynamic linking and how .so files are structured, rather than trying to force a direct link to this specific header.

By following these steps, iterating, and refining, a comprehensive and accurate answer to the request can be constructed.
这个目录 `bionic/libc/include/bits/fenv_arm.handroid` 下的源代码文件 `fenv_arm.h` 定义了与 ARM 架构上浮点环境相关的结构体、类型和宏定义。它为 C 标准库中与浮点异常处理和舍入模式控制相关的函数提供了底层支持。由于它是 Bionic 的一部分，因此与 Android 的功能紧密相关。

**功能列举:**

1. **定义浮点环境类型 `fenv_t`:**
   - 该类型用于存储浮点控制和状态信息。在 64 位 ARM 架构 (`__LP64__`) 上，它是一个结构体，包含两个 32 位无符号整数：`__control` (对应 FPCR，浮点控制寄存器) 和 `__status` (对应 FPSR，浮点状态寄存器)。
   - 在 32 位 ARM 架构上，它只是一个 32 位无符号整数，可能对应 FPSCR (浮点状态和控制寄存器)。

2. **定义浮点异常标志类型 `fexcept_t`:**
   - 该类型通常是一个整数类型，用于表示一组浮点异常标志。

3. **定义浮点异常标志宏:**
   - `FE_INVALID`:  无效操作异常 (例如，对负数取平方根)。
   - `FE_DIVBYZERO`: 除零异常。
   - `FE_OVERFLOW`: 上溢异常 (结果太大，无法表示)。
   - `FE_UNDERFLOW`: 下溢异常 (结果太小，无法表示为标准化的非零数)。
   - `FE_INEXACT`:  不精确结果异常 (结果需要舍入)。
   - `FE_DENORMAL`:  非规格化操作数异常 (操作数是非常接近零的数)。
   - `FE_ALL_EXCEPT`:  一个包含所有浮点异常的位掩码。

4. **定义浮点舍入模式宏:**
   - `FE_TONEAREST`:  舍入到最近的值，相等时舍入到偶数。
   - `FE_UPWARD`:  朝正无穷大方向舍入。
   - `FE_DOWNWARD`: 朝负无穷大方向舍入。
   - `FE_TOWARDZERO`: 朝零方向舍入。

**与 Android 功能的关系和举例说明:**

这个文件是 Android 系统底层库的一部分，它直接影响到任何在 Android 上运行的 native 代码中执行的浮点运算。

* **NDK 开发:** 当 Android 开发者使用 NDK (Native Development Kit) 编写 C/C++ 代码时，这些代码可能会涉及到浮点运算。开发者可以使用 `<fenv.h>` 头文件（它会包含这个 `fenv_arm.h` 文件）中定义的函数来控制浮点环境，例如：
    * **捕获浮点异常:**  开发者可以使用 `fetestexcept()` 函数检查是否发生了特定的浮点异常，并采取相应的处理措施。例如，一个图形渲染引擎可能会在遇到除零错误时输出警告信息，而不是崩溃。
    * **控制舍入模式:** 开发者可以使用 `fesetround()` 函数设置浮点运算的舍入模式。例如，在进行金融计算时，可能需要使用特定的舍入模式以满足精度要求。

* **Android Framework:** 尽管 Android Framework 主要使用 Java/Kotlin 编写，但其底层仍然依赖于 native 代码来实现一些核心功能，包括数学计算。例如，Android 的 Skia 图形库 (一个 native 库) 在进行图形渲染时会大量使用浮点运算，它会受到这里定义的浮点环境设置的影响。

**libc 函数的功能和实现 (概念性解释):**

这个头文件本身不包含 libc 函数的实现代码，它只是定义了数据结构和宏。实际的 libc 函数（例如 `fesetround`, `fegetround`, `feraiseexcept`, `fetestexcept`, `feclearexcept`, `fegetenv`, `feholdexcept`, `fesetenv`, `feupdateenv`）的实现位于 Bionic 的其他源文件中。

这些函数的功能和实现原理大致如下：

1. **`fesetround(int round)`:** 设置当前的浮点舍入模式。
   - **实现:**  该函数会根据传入的 `round` 参数（例如 `FE_TONEAREST`），修改 ARM 处理器的浮点控制寄存器 (FPCR 或 FPSCR) 中相应的位域。这通常涉及到内联汇编指令或特定的系统调用来直接操作硬件寄存器。

2. **`fegetround()`:** 获取当前的浮点舍入模式。
   - **实现:**  该函数会读取 ARM 处理器的浮点控制寄存器 (FPCR 或 FPSCR) 中表示舍入模式的位域，并将其转换为对应的宏定义值 (例如 `FE_TONEAREST`) 返回。

3. **`feraiseexcept(int excepts)`:** 触发指定的浮点异常。
   - **实现:**  该函数会修改 ARM 处理器的浮点状态寄存器 (FPSR 或 FPSCR) 中与指定异常对应的标志位。这会导致后续的浮点运算可能会抛出相应的信号或触发陷阱（如果已配置）。

4. **`fetestexcept(int excepts)`:** 检查是否发生了指定的浮点异常。
   - **实现:**  该函数会读取 ARM 处理器的浮点状态寄存器 (FPSR 或 FPSCR) 中与指定异常对应的标志位，并返回一个表示是否发生了这些异常的位掩码。

5. **`feclearexcept(int excepts)`:** 清除指定的浮点异常标志。
   - **实现:**  该函数会修改 ARM 处理器的浮点状态寄存器 (FPSR 或 FPSCR) 中与指定异常对应的标志位，将其设置为未发生状态。

6. **`fegetenv(fenv_t *envp)`:** 获取当前的浮点环境并存储到 `envp` 指向的结构体中。
   - **实现:**  根据架构 (32 位或 64 位)，该函数会读取相应的浮点控制和状态寄存器 (FPCR/FPSR 或 FPSCR)，并将它们的值存储到 `fenv_t` 结构体的相应成员中。

7. **`feholdexcept(fenv_t *envp)`:** 获取当前的浮点环境，清除所有浮点异常标志，并将获取的环境存储到 `envp` 指向的结构体中。
   - **实现:**  该函数先调用类似 `fegetenv` 的操作来保存当前环境，然后调用类似 `feclearexcept(FE_ALL_EXCEPT)` 的操作来清除所有异常标志。

8. **`fesetenv(const fenv_t *envp)`:** 将浮点环境设置为 `envp` 指向的结构体中存储的值。
   - **实现:**  根据架构，该函数会将 `envp` 指向的 `fenv_t` 结构体中的值写入到相应的浮点控制和状态寄存器 (FPCR/FPSR 或 FPSCR)。

9. **`feupdateenv(const fenv_t *envp)`:** 将 `envp` 指向的浮点环境应用到当前环境，但不清除已发生的异常。
   - **实现:**  该函数首先会获取当前的浮点异常状态，然后将 `envp` 中的控制信息 (例如舍入模式) 设置到浮点控制寄存器，最后恢复之前获取的异常状态。

**涉及 dynamic linker 的功能 (间接关系):**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号引用。

然而，这个头文件中定义的类型和宏会被编译到 libc.so 中，并可能被其他依赖于 libc 的共享库使用。当一个应用程序启动时，dynamic linker 会加载 libc.so，以及应用程序依赖的其他共享库。

**so 布局样本:**

一个典型的 `.so` 文件（例如 `libc.so`) 的布局大致如下：

```
ELF Header:
  ...
Program Headers:  (描述内存段的信息，如代码段、数据段等)
  ...
Section Headers:  (描述各个节的信息，如 .text, .data, .bss, .symtab, .strtab 等)
  ...

.text:  (代码段，包含函数指令)
  ... (fesetround 的实现代码等)

.rodata: (只读数据段，包含常量字符串等)
  ...

.data:   (已初始化的数据段，包含全局变量等)
  ...

.bss:    (未初始化的数据段，包含未初始化的全局变量)
  ...

.symtab: (符号表，包含导出的和导入的符号信息)
  ... (包含 fesetround 等函数的符号)

.strtab: (字符串表，用于存储符号名等字符串)
  ...

.dynsym: (动态符号表，用于动态链接)
  ... (包含 fesetround 等需要动态链接的符号)

.dynstr: (动态字符串表)
  ...

.rel.dyn: (动态重定位表，描述需要在加载时修改的地址)
  ...

.rel.plt: (PLT (Procedure Linkage Table) 重定位表)
  ...
```

**链接的处理过程:**

1. **编译时:** 当编译一个依赖 libc 的 native 代码时，编译器会遇到对 `fesetround` 等函数的调用。由于这些函数的声明在 `<fenv.h>` 中，编译器知道这些函数的存在和参数类型。编译器会生成对这些函数的未解析符号引用。

2. **链接时 (静态链接/动态链接):**
   - **静态链接 (通常不用于共享库):** 链接器会将应用程序代码与 libc.a (静态库) 链接在一起，将 `fesetround` 的代码直接复制到应用程序的可执行文件中。
   - **动态链接 (Android 常用):** 链接器会在应用程序的可执行文件中创建一个指向 `fesetround` 的动态符号引用。这个引用会指向一个在 PLT 中的条目。

3. **运行时 (dynamic linker 的工作):**
   - 当应用程序启动时，dynamic linker 会加载应用程序依赖的共享库，包括 `libc.so`。
   - Dynamic linker 会解析应用程序中对 `fesetround` 的动态符号引用。它会在 `libc.so` 的 `.dynsym` 中查找 `fesetround` 的符号。
   - 找到符号后，dynamic linker 会更新 PLT 中对应 `fesetround` 的条目，使其指向 `libc.so` 中 `fesetround` 函数的实际地址。
   - 当应用程序调用 `fesetround` 时，程序会跳转到 PLT 中的条目，然后通过 dynamic linker 更新后的地址跳转到 `libc.so` 中 `fesetround` 的实际代码执行。

**逻辑推理 (假设输入与输出):**

假设一个程序执行以下操作：

```c
#include <fenv.h>
#include <stdio.h>

int main() {
  // 获取当前的舍入模式
  int current_round = fegetround();
  printf("Current rounding mode: %d\n", current_round);

  // 设置为向上舍入
  fesetround(FE_UPWARD);
  printf("Rounding mode set to upward\n");

  // 执行一个浮点运算
  float a = 3.1;
  float b = 2.0;
  float result = a / b;
  printf("3.1 / 2.0 = %f\n", result);

  // 恢复原来的舍入模式
  fesetround(current_round);
  printf("Rounding mode restored\n");

  return 0;
}
```

**假设输入:** 无

**预期输出:**

```
Current rounding mode: 0  // 假设默认是 FE_TONEAREST
Rounding mode set to upward
3.1 / 2.0 = 1.550000  // 在向上舍入模式下，1.55 向上舍入为 1.6
Rounding mode restored
```

**用户或编程常见的使用错误:**

1. **忘记包含头文件:** 如果没有包含 `<fenv.h>`，就无法使用 `fesetround` 等函数和相关的宏定义。会导致编译错误。

2. **错误地假设默认舍入模式:**  开发者可能没有显式设置舍入模式，就假设使用的是某种特定的舍入模式，导致计算结果不符合预期。应该显式设置需要的舍入模式。

3. **忽略浮点异常:**  浮点运算可能产生异常（例如除零）。开发者可能没有检查和处理这些异常，导致程序行为不可预测或崩溃。应该使用 `fetestexcept` 等函数检查异常状态。

4. **在多线程环境中使用但未进行适当的同步:** 浮点环境是线程局部的，但如果多个线程共享浮点环境设置，可能会导致竞争条件和意外的行为。

5. **不理解不同舍入模式的影响:**  不同的舍入模式会导致不同的计算结果。开发者需要理解各种舍入模式的含义，并根据需求选择合适的模式。例如，在金融计算中，舍入误差可能会累积，选择正确的舍入模式至关重要。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 开发:**
   - 开发者使用 NDK 编写 C/C++ 代码。
   - 代码中包含了 `<fenv.h>` 头文件。
   - 编译器在编译时会找到 `bionic/libc/include/fenv.h`，该头文件会包含 `bionic/libc/include/bits/fenv_arm.handroid`。
   - 开发者调用的 `fesetround` 等函数在编译时会生成对 libc.so 中相应符号的引用。
   - 在运行时，dynamic linker 加载 libc.so，并解析这些符号引用。
   - 当 native 代码执行到 `fesetround` 时，会调用 libc.so 中实现的该函数，该函数会操作底层的 ARM 浮点寄存器，这些寄存器的定义就在 `fenv_arm.h` 中。

2. **Android Framework:**
   - Android Framework 的某些底层组件是用 C/C++ 编写的，例如 Skia 图形库。
   - 这些组件在进行浮点运算时，会隐式地使用 Bionic 提供的浮点环境设置。
   - 虽然 Framework 开发者通常不直接调用 `fesetround` 等函数，但 Bionic 默认的浮点环境设置会影响到这些底层库的浮点运算行为.
   - 如果 Framework 的某些部分需要特定的浮点行为，可能会通过 JNI 调用 native 代码，然后在 native 代码中使用 `<fenv.h>` 中的函数来控制浮点环境。

**Frida Hook 示例调试步骤:**

假设我们要 hook `fesetround` 函数来观察其调用和参数。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.arch === "arm" || Process.arch === "arm64") {
  const fesetround = Module.findExportByName("libc.so", "fesetround");
  if (fesetround) {
    Interceptor.attach(fesetround, {
      onEnter: function (args) {
        const roundMode = args[0].toInt();
        console.log("fesetround called with round mode:", roundMode);
        switch (roundMode) {
          case 0: console.log("  FE_TONEAREST"); break;
          case 1: console.log("  FE_UPWARD"); break;
          case 2: console.log("  FE_DOWNWARD"); break;
          case 3: console.log("  FE_TOWARDZERO"); break;
          default: console.log("  Unknown round mode"); break;
        }
      },
      onLeave: function (retval) {
        console.log("fesetround returned:", retval);
      },
    });
  } else {
    console.log("fesetround not found in libc.so");
  }
} else {
  console.log("Skipping fenv hook on non-ARM architecture");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. **运行目标应用:** 启动你想要调试的 Android 应用。
3. **运行 Frida 脚本:** 使用 Frida 命令行工具将脚本注入到目标应用进程中。例如：
   ```bash
   frida -U -f <包名> -l hook_fenv.js --no-pause
   ```
   将 `<包名>` 替换为目标应用的包名，`hook_fenv.js` 是上面保存的 Frida 脚本文件名。
4. **观察输出:**  当目标应用中调用 `fesetround` 函数时，Frida 会拦截该调用，并打印出传入的舍入模式参数。你可以观察哪些代码设置了浮点舍入模式以及设置的值。

**更复杂的 Frida Hook 场景:**

* **修改舍入模式:**  在 `onEnter` 中修改 `args[0]` 的值，可以改变程序实际设置的舍入模式。
* **追踪浮点异常:** 可以 hook 相关的函数如 `feraiseexcept` 或检查浮点状态寄存器的值。
* **定位调用来源:** 使用 `Thread.backtrace()` 可以查看 `fesetround` 的调用栈，从而确定是哪个函数或库调用了它。

这个 `fenv_arm.handroid` 文件虽然小，但它是 Android 系统中处理浮点运算的基础，理解它的作用对于进行底层 native 开发和调试至关重要。

### 提示词
```
这是目录为bionic/libc/include/bits/fenv_arm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * $FreeBSD: src/lib/msun/arm/fenv.h,v 1.5 2005/03/16 19:03:45 das Exp $
 */

#pragma once

#include <sys/types.h>

__BEGIN_DECLS

/*
 * The ARM Cortex-A75 registers are described here:
 *
 * AArch64:
 *  FPCR: http://infocenter.arm.com/help/topic/com.arm.doc.100403_0200_00_en/lau1442502503726.html
 *  FPSR: http://infocenter.arm.com/help/topic/com.arm.doc.100403_0200_00_en/lau1442502526288.html
 * AArch32:
 *  FPSCR: http://infocenter.arm.com/help/topic/com.arm.doc.100403_0200_00_en/lau1442504290459.html
 */

#if defined(__LP64__)
typedef struct {
  /* FPCR, Floating-point Control Register. */
  __uint32_t __control;
  /* FPSR, Floating-point Status Register. */
  __uint32_t __status;
} fenv_t;

#else
typedef __uint32_t fenv_t;
#endif

typedef __uint32_t fexcept_t;

/* Exception flags. */
#define FE_INVALID    0x01
#define FE_DIVBYZERO  0x02
#define FE_OVERFLOW   0x04
#define FE_UNDERFLOW  0x08
#define FE_INEXACT    0x10
#define FE_DENORMAL   0x80
#define FE_ALL_EXCEPT (FE_DIVBYZERO | FE_INEXACT | FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW | FE_DENORMAL)

/* Rounding modes. */
#define FE_TONEAREST  0x0
#define FE_UPWARD     0x1
#define FE_DOWNWARD   0x2
#define FE_TOWARDZERO 0x3

__END_DECLS
```