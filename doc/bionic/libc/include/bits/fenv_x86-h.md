Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The core request is to analyze the provided C header file (`fenv_x86.handroid`) within the context of Android's Bionic library and explain its functionality, connections to Android, implementation details, dynamic linking aspects, potential errors, and how it's used in the Android framework and NDK. The response needs to be in Chinese.

**2. Initial Analysis of the Header File:**

* **Copyright and Origin:**  Notice the FreeBSD copyright. This immediately suggests that Bionic is borrowing or has been inspired by FreeBSD's implementation for floating-point environment control.
* **Header Guard:** `#pragma once` indicates it's a header file designed to be included only once per compilation unit.
* **Includes:** `<sys/types.h>` is a standard system header likely providing basic type definitions.
* **`__BEGIN_DECLS` and `__END_DECLS`:** These are common Bionic (and glibc) macros for ensuring proper C linkage in mixed C/C++ code.
* **`fenv_t` Structure:** This is the central data structure. The comments about binary compatibility with FreeBSD 5.3 and packing the `mxcsr` are crucial clues. The structure clearly stores information related to the floating-point environment: control, status, and the `mxcsr` register (Media eXtension Control and Status Register), which is specific to x86.
* **`fexcept_t` Typedef:** This is a type alias for representing floating-point exceptions.
* **`FE_*` Macros (Exception Flags):** These define constants representing different floating-point exception conditions (invalid operation, denormalized operand, division by zero, overflow, underflow, inexact result). `FE_ALL_EXCEPT` combines them.
* **`FE_*` Macros (Rounding Modes):** These define constants for different floating-point rounding modes (round to nearest, round down, round up, round towards zero).

**3. Connecting to Key Concepts:**

* **Floating-Point Environment (FPU):** The header directly deals with controlling the behavior of the floating-point unit in the processor. Keywords like "control," "status," "exceptions," and "rounding" are strong indicators.
* **IEEE 754:**  The exception flags and rounding modes directly correspond to the standards defined by IEEE 754 for floating-point arithmetic.
* **x86 Architecture:** The presence of `mxcsr` explicitly ties this to x86 processors.
* **Bionic and libc:**  As stated in the prompt, this file is part of Bionic's C library, so it provides standard C library functions related to floating-point environment control.
* **Dynamic Linking:** Since it's part of `libc`, it will be dynamically linked. This necessitates considering shared object layout and linking processes.

**4. Structuring the Answer:**

Based on the prompt's requests, the answer should cover these points:

* **Functionality:** A concise summary of what the header defines.
* **Relationship to Android:** Concrete examples of how floating-point operations are used in Android.
* **libc Function Implementation:**  Explain how the functions that *use* these definitions would work (even though the header itself doesn't contain function implementations). Focus on the interaction with processor registers.
* **Dynamic Linker:**  Describe a typical `libc.so` layout and the linking process involving symbols related to floating-point environment control.
* **Logical Reasoning (Hypothetical Input/Output):**  Provide a simple scenario demonstrating how setting a rounding mode or enabling an exception flag might affect the result of a calculation or trigger a signal.
* **Common Usage Errors:**  Illustrate potential pitfalls developers might encounter when working with the floating-point environment.
* **Android Framework/NDK Usage and Frida Hooking:** Explain how the framework or NDK might indirectly utilize these definitions and how to use Frida to inspect the values.

**5. Detailed Content Generation (Iterative Process):**

* **Functionality:** Start with the basics – defining data structures and constants for controlling floating-point behavior.
* **Android Relevance:** Brainstorm common Android use cases: graphics (OpenGL/Vulkan), multimedia, sensor data processing, scientific apps.
* **libc Function Implementation:**  This requires some inference. Think about the standard C functions like `fesetround`, `fegetround`, `feraiseexcept`, etc. Explain how they likely interact with the FPU's control and status registers using inline assembly or compiler intrinsics.
* **Dynamic Linker:** Imagine a simplified `libc.so`. Include sections like `.text`, `.data`, `.bss`, `.symtab`, `.dynsym`. Illustrate how symbols related to floating-point functions would be present and resolved during linking.
* **Logical Reasoning:** Choose a simple example. Setting rounding mode to `FE_UPWARD` and adding 0.3 + 0.3. Demonstrate the expected output compared to the default rounding mode.
* **Common Errors:**  Focus on forgetting to clear exception flags or not checking for exceptions. Provide code examples.
* **Android Framework/NDK & Frida:**  Trace the path from high-level framework components down to native code. Give an example of hooking `fesetround` using Frida and inspecting the arguments.

**6. Refinement and Language:**

* **Accuracy:** Ensure technical correctness in the explanations.
* **Clarity:** Use clear and concise language. Avoid jargon where possible, or explain it.
* **Completeness:** Address all aspects of the prompt.
* **Chinese Translation:**  Translate the technical terms accurately and ensure the overall flow is natural in Chinese. This often involves choosing the right terminology and phrasing. For example, "floating-point environment" translates to "浮点环境," "dynamic linker" to "动态链接器," etc.
* **Code Examples:**  Provide clear and simple code snippets to illustrate concepts.

**Self-Correction/Improvements During the Process:**

* **Initial thought:** Maybe focus on the specifics of `fenv_t`. **Correction:** Broaden the scope to include the standard C library functions that *use* these definitions.
* **Initial thought:** Just list Android components. **Correction:**  Explain *how* these components might use floating-point operations.
* **Initial thought:**  Overly complex dynamic linking example. **Correction:** Simplify the `libc.so` layout and focus on the core linking concept.
* **Initial thought:**  Generic Frida example. **Correction:** Make it specific to one of the floating-point functions (e.g., `fesetround`).

By following these steps, including the iterative refinement, a comprehensive and accurate answer addressing all aspects of the prompt can be constructed. The key is to understand the purpose of the header file, its place within the Android ecosystem, and how the concepts it defines are used in practice.
这是一个定义了 x86 架构下浮点环境相关的数据结构和宏定义的头文件，属于 Android Bionic C 库的一部分。它定义了如何表示和操作浮点运算的环境，例如异常处理和舍入模式。

**它的功能：**

1. **定义了 `fenv_t` 结构体:**  这个结构体用于存储浮点环境的状态。在 x86 架构下，它主要包含控制字（control word）、状态字（status word）以及 MXCSR 寄存器的值。MXCSR 寄存器控制着 SSE/SSE2 等指令集的浮点运算行为。为了与 FreeBSD 5.3 保持二进制兼容，`mxcsr` 被分成了高低两个 16 位字段存储。
2. **定义了 `fexcept_t` 类型:**  这是一个 `__uint16_t` 的别名，用于表示浮点异常标志。
3. **定义了浮点异常标志宏:**  例如 `FE_INVALID` (无效操作), `FE_DENORMAL` (非正常化), `FE_DIVBYZERO` (除零), `FE_OVERFLOW` (溢出), `FE_UNDERFLOW` (下溢), `FE_INEXACT` (不精确结果)。`FE_ALL_EXCEPT` 是所有这些异常的按位或。
4. **定义了舍入模式宏:** 例如 `FE_TONEAREST` (舍入到最近), `FE_DOWNWARD` (向下舍入), `FE_UPWARD` (向上舍入), `FE_TOWARDZERO` (向零舍入)。

**它与 Android 功能的关系及举例说明：**

Android 系统和应用程序广泛使用浮点运算，例如：

* **图形处理 (OpenGL/Vulkan):**  在渲染 3D 图形时，需要进行大量的浮点数计算，例如顶点变换、光照计算等。`fenv_x86.handroid` 定义的浮点环境影响着这些计算的精度和异常处理。例如，如果发生浮点溢出，可以通过设置相应的异常标志来捕获并处理。
* **多媒体处理 (音频/视频编解码):** 音频和视频数据的处理通常涉及到浮点数运算，例如滤波、变换等。
* **传感器数据处理:** 从加速度计、陀螺仪等传感器获取的数据通常是浮点数，需要进行滤波、融合等处理。
* **科学计算类应用:** 运行在 Android 上的科学计算应用程序会大量使用浮点运算。
* **Java Math 类库的底层实现:**  Java 的 `Math` 类和相关的浮点数运算在底层会调用 Bionic 提供的浮点数操作，最终会受到这里定义的浮点环境的影响。

**libc 函数的功能实现 (涉及 `fenv.h` 中定义的类型和宏)：**

虽然 `fenv_x86.handroid` 本身只是一个头文件，定义了数据结构和宏，但它被其他 Bionic 的 C 库函数使用，这些函数用于操作浮点环境。常见的相关函数有（这些函数的具体实现在 `bionic/libc/arch-x86/src/fenv.c` 等文件中）：

* **`feclearexcept(int excepts)`:** 清除指定的浮点异常标志。实现上，它会读取浮点状态字或 MXCSR 寄存器，清除对应的位，然后写回寄存器。例如，`feclearexcept(FE_OVERFLOW)` 会清除溢出异常标志。
* **`feraiseexcept(int excepts)`:** 触发指定的浮点异常。实现上，它会向浮点状态字或 MXCSR 寄存器中设置对应的异常标志位，这可能会导致程序产生一个浮点异常信号。
* **`fetestexcept(int excepts)`:** 测试指定的浮点异常标志是否被设置。实现上，它会读取浮点状态字或 MXCSR 寄存器，并与传入的 `excepts` 进行按位与操作，返回结果。
* **`fegetround()`:** 获取当前的浮点舍入模式。实现上，它会读取浮点控制字或 MXCSR 寄存器的舍入控制位，并根据其值返回对应的宏（例如 `FE_TONEAREST`）。
* **`fesetround(int mode)`:** 设置浮点舍入模式。实现上，它会读取浮点控制字或 MXCSR 寄存器，修改其中的舍入控制位为传入的 `mode` 对应的值，然后写回寄存器。
* **`fegetenv(fenv_t *envp)`:** 获取当前的浮点环境并存储到 `envp` 指向的结构体中。实现上，它会读取浮点控制字、状态字和 MXCSR 寄存器的值，并将它们存储到 `envp->control`, `envp->status`, `envp->__mxcsr_lo` 和 `envp->__mxcsr_hi` 中。
* **`fesetenv(const fenv_t *envp)`:** 将浮点环境设置为 `envp` 指向的值。实现上，它会将 `envp` 中存储的控制字、状态字和 MXCSR 寄存器的值写回到对应的硬件寄存器中。
* **`feholdexcept(fenv_t *envp)`:** 保存当前的浮点环境，并清除所有的浮点异常标志。相当于先调用 `fegetenv(envp)`，然后调用 `feclearexcept(FE_ALL_EXCEPT)`。
* **`feupdateenv(const fenv_t *envp)`:** 设置浮点环境为 `envp` 指向的值，但不会清除已发生的异常。它会先获取当前的异常标志，然后设置环境，最后再重新触发之前发生的异常。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`fenv_x86.handroid` 中定义的类型和宏本身不会直接涉及动态链接器，因为它们只是数据结构的定义。然而，使用这些定义的相关函数（如上面列出的 `feclearexcept` 等）会被编译到 `libc.so` 中，并通过动态链接器被应用程序加载和使用。

**`libc.so` 布局样本 (简化版):**

```
libc.so:
  .text         # 包含可执行代码，例如 feclearexcept, fesetround 等函数的实现
  .rodata       # 包含只读数据
  .data         # 包含已初始化的可变数据
  .bss          # 包含未初始化的可变数据
  .dynsym       # 动态符号表，包含导出的符号（函数名、变量名等）
  .dynstr       # 动态字符串表，包含符号名字符串
  .rel.dyn      # 重定位表，用于在加载时调整地址
  ...
```

**链接的处理过程：**

1. **编译时:** 当应用程序或 NDK 库使用例如 `fesetround` 函数时，编译器会生成对该函数的未解析引用。
2. **链接时:** 链接器 (通常是 `lld` 或 `gold`) 在链接应用程序或共享库时，会查找需要的符号。如果应用程序链接了 `libc.so`，链接器会在 `libc.so` 的 `.dynsym` (动态符号表) 中查找 `fesetround` 的符号。
3. **运行时 (动态链接):** 当 Android 系统加载应用程序时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，例如 `libc.so`。
4. **符号解析:** 动态链接器会遍历应用程序的重定位表 (`.rel.dyn`)，找到所有未解析的符号引用（例如对 `fesetround` 的引用）。
5. **查找符号地址:** 动态链接器会在已加载的共享库 (`libc.so`) 的动态符号表中查找这些符号的地址。`fesetround` 的地址会在 `libc.so` 的 `.text` 段中找到。
6. **重定位:** 动态链接器会将查找到的地址填入应用程序中对 `fesetround` 函数的调用位置，从而完成符号的解析和绑定。

**假设输入与输出 (逻辑推理)：**

假设有以下代码片段：

```c
#include <fenv.h>
#include <stdio.h>

int main() {
  // 获取当前的舍入模式
  int current_round = fegetround();
  printf("Current rounding mode: %d\n", current_round); // 假设输出 0 (FE_TONEAREST)

  // 设置为向上舍入
  fesetround(FE_UPWARD);

  // 进行浮点数运算
  float a = 1.1f;
  float b = 2.2f;
  float sum = a + b;
  printf("1.1 + 2.2 = %.1f\n", sum); // 输出可能是 3.4 (因为向上舍入)

  // 恢复原来的舍入模式
  fesetround(current_round);

  return 0;
}
```

**假设输入：** 默认的浮点舍入模式是舍入到最近 (`FE_TONEAREST`)。

**输出：**

```
Current rounding mode: 0
1.1 + 2.2 = 3.4
```

**解释：**

* `fegetround()` 获取到当前的舍入模式，假设是 0，对应 `FE_TONEAREST`。
* `fesetround(FE_UPWARD)` 将舍入模式设置为向上舍入。
* 计算 `1.1 + 2.2`，理论结果是 `3.3`。由于设置了向上舍入，所以结果被舍入到 `3.4`。
* 最后，舍入模式被恢复到原来的值。

**用户或编程常见的使用错误：**

1. **忘记清除异常标志:**  浮点异常标志一旦被设置，会一直保持设置状态，直到被显式清除。如果在处理完一个浮点异常后，忘记使用 `feclearexcept()` 清除相应的标志，后续的 `fetestexcept()` 可能会得到错误的结果。

   ```c
   #include <fenv.h>
   #include <stdio.h>
   #include <math.h>

   int main() {
       double result = 1.0 / 0.0; // 触发 FE_DIVBYZERO

       if (fetestexcept(FE_DIVBYZERO)) {
           printf("Division by zero occurred.\n");
           // 忘记清除异常标志
       }

       if (fetestexcept(FE_DIVBYZERO)) {
           printf("Division by zero still reported.\n"); // 错误地认为又发生了一次除零
       }

       feclearexcept(FE_DIVBYZERO); // 正确的做法
       if (!fetestexcept(FE_DIVBYZERO)) {
           printf("Division by zero flag cleared.\n");
       }

       return 0;
   }
   ```

2. **不正确地假设默认的浮点环境:**  虽然通常默认的舍入模式是舍入到最近，但最好显式地设置需要的舍入模式，以避免依赖于平台或编译器的默认行为。

3. **没有检查浮点异常:**  浮点运算可能会产生异常，例如除零、溢出等。如果不检查这些异常，可能会导致程序行为不符合预期甚至崩溃。

   ```c
   #include <fenv.h>
   #include <stdio.h>

   int main() {
       // 没有检查除零异常
       double result = 1.0 / 0.0;
       printf("Result: %f\n", result); // 可能会输出 inf 或导致程序崩溃
       return 0;
   }
   ```

4. **在多线程环境下不正确地操作浮点环境:**  浮点环境通常是线程局部的，但在某些情况下，不正确的操作可能会导致多个线程之间的干扰。应该谨慎地在多线程程序中修改浮点环境，或者使用线程安全的机制。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

从 Android Framework 或 NDK 到达 `fenv_x86.handroid` 中定义的类型和宏，通常经过以下步骤：

1. **Android Framework (Java 代码):**  Android Framework 的某些部分可能需要进行浮点运算。例如，图形相关的 API (如 `android.graphics.Matrix`) 或数学相关的工具类。虽然 Java 代码本身不直接操作底层的浮点环境，但 Java 的 `Math` 类中的某些方法在 Native 层会有对应的实现。

2. **JNI 调用:** 当 Java 代码调用涉及到浮点运算的 Native 方法时，会通过 JNI (Java Native Interface) 机制调用到 Native 代码。

3. **NDK 代码 (C/C++ 代码):**  NDK 开发人员可以使用 C/C++ 编写 Native 代码。这些代码可以直接使用 Bionic 提供的浮点数相关的函数，例如 `fesetround`, `fegetround` 等。这些函数的头文件会包含 `fenv.h` 或其平台特定的变体 (`fenv_x86.handroid`)。

4. **Bionic libc:**  NDK 代码中调用的浮点数函数最终会链接到 Bionic 的 `libc.so` 中。`libc.so` 包含了这些函数的实现，而这些实现会使用 `fenv_x86.handroid` 中定义的结构体和宏来操作底层的浮点环境。

**Frida Hook 示例：**

假设我们想 hook `fesetround` 函数，查看应用程序设置的舍入模式。

```javascript
// Frida 脚本
if (Process.arch === 'x86' || Process.arch === 'x64') {
  const fesetroundPtr = Module.findExportByName("libc.so", "fesetround");
  if (fesetroundPtr) {
    Interceptor.attach(fesetroundPtr, {
      onEnter: function (args) {
        const mode = args[0].toInt();
        let modeString = "";
        switch (mode) {
          case 0x0000:
            modeString = "FE_TONEAREST";
            break;
          case 0x0400:
            modeString = "FE_DOWNWARD";
            break;
          case 0x0800:
            modeString = "FE_UPWARD";
            break;
          case 0x0c00:
            modeString = "FE_TOWARDZERO";
            break;
          default:
            modeString = "Unknown";
            break;
        }
        console.log(`[fesetround] Setting rounding mode to: ${mode} (${modeString})`);
      },
      onLeave: function (retval) {
        // console.log("[fesetround] Return value:", retval);
      }
    });
  } else {
    console.log("Could not find fesetround in libc.so");
  }
} else {
  console.log("Not an x86 or x64 process.");
}
```

**步骤说明：**

1. **检查架构:** 首先检查进程的架构是否为 x86 或 x64，因为 `fesetround` 是 x86 特定的。
2. **查找函数地址:** 使用 `Module.findExportByName` 在 `libc.so` 中查找 `fesetround` 函数的地址。
3. **Hook 函数:** 使用 `Interceptor.attach` 拦截 `fesetround` 函数的调用。
4. **`onEnter` 回调:** 在 `onEnter` 回调函数中，可以访问函数的参数。`fesetround` 的第一个参数是要设置的舍入模式。
5. **解析舍入模式:** 将传入的整数参数转换为对应的宏名称，方便理解。
6. **打印日志:** 打印日志信息，显示正在设置的舍入模式。

**如何调试这些步骤 (Frida 示例场景):**

1. **编写一个 Android NDK 应用:** 创建一个简单的 Android 应用，其中包含一个 Native 方法，该方法调用 `fesetround` 设置浮点舍入模式。

   ```c
   // native-lib.cpp
   #include <jni.h>
   #include <fenv.h>
   #include <android/log.h>

   #define TAG "FENV_TEST"

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_fenvtest_MainActivity_setRoundingMode(JNIEnv* env, jobject /* this */, jint mode) {
       __android_log_print(ANDROID_LOG_DEBUG, TAG, "Setting rounding mode to: %d", mode);
       fesetround(mode);
   }
   ```

2. **在 Java 代码中调用 Native 方法:** 在 MainActivity 中调用 `setRoundingMode` 方法，并传入不同的舍入模式值。

   ```java
   // MainActivity.java
   package com.example.fenvtest;

   import androidx.appcompat.app.AppCompatActivity;
   import android.os.Bundle;
   import android.widget.TextView;

   public class MainActivity extends AppCompatActivity {

       static {
           System.loadLibrary("fenvtest");
       }

       private native void setRoundingMode(int mode);

       @Override
       protected void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           setContentView(R.layout.activity_main);

           setRoundingMode(FE_UPWARD); // 设置为向上舍入
       }
   }
   ```

3. **运行 Frida 脚本:** 使用 Frida 连接到正在运行的 Android 应用，并执行上面编写的 Frida 脚本。

   ```bash
   frida -U -f com.example.fenvtest -l hook_fenv.js --no-pause
   ```

4. **观察 Frida 输出:** Frida 的输出会显示 `fesetround` 被调用以及传入的舍入模式值。

   ```
   [#] Attaching...
   [#] Attached
   Spawned `com.example.fenvtest`. Use %resume to let the main process start.
   [Android Emulator::com.example.fenvtest]-> [#] [fesetround] Setting rounding mode to: 2048 (FE_UPWARD)
   ```

通过这种方式，你可以使用 Frida 动态地监控和调试 Android 应用中与浮点环境相关的操作，理解 Framework 或 NDK 代码是如何一步步地调用到底层的 Bionic C 库函数的。

Prompt: 
```
这是目录为bionic/libc/include/bits/fenv_x86.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

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
 * $FreeBSD: src/lib/msun/i387/fenv.h,v 1.4 2005/03/17 22:21:46 das Exp $
 */

#pragma once

#include <sys/types.h>

__BEGIN_DECLS

/*
 * To preserve binary compatibility with FreeBSD 5.3, we pack the
 * mxcsr into some reserved fields, rather than changing sizeof(fenv_t).
 */
typedef struct {
  __uint16_t __control;
  __uint16_t __mxcsr_hi;
  __uint16_t __status;
  __uint16_t __mxcsr_lo;
  __uint32_t __tag;
  char       __other[16];
} fenv_t;

typedef __uint16_t fexcept_t;

/* Exception flags */
#define FE_INVALID    0x01
#define FE_DENORMAL   0x02
#define FE_DIVBYZERO  0x04
#define FE_OVERFLOW   0x08
#define FE_UNDERFLOW  0x10
#define FE_INEXACT    0x20
#define FE_ALL_EXCEPT (FE_DIVBYZERO | FE_DENORMAL | FE_INEXACT | \
                       FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW)

/* Rounding modes */
#define FE_TONEAREST  0x0000
#define FE_DOWNWARD   0x0400
#define FE_UPWARD     0x0800
#define FE_TOWARDZERO 0x0c00

__END_DECLS

"""

```