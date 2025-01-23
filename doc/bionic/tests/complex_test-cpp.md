Response:
Let's break down the thought process for answering the user's request. The request is quite comprehensive, asking for analysis of a specific C++ test file within the Android Bionic library.

**1. Initial Understanding and Goal Setting:**

The core task is to understand the purpose of `complex_test.cpp` and explain its functionality within the broader context of Android's Bionic library. This involves identifying what the code tests, how it interacts with Bionic components, and potential pitfalls for users.

**2. Deconstructing the Request:**

The request is structured with specific points to address:

* **Functionality:** What does the test file do?
* **Android Relationship:** How does it relate to Android functionality?
* **libc Function Implementation:** How are the libc functions implemented? (This is a deep dive request)
* **Dynamic Linker:**  How does it interact with the dynamic linker? (Another deep dive)
* **Logic and Examples:** Provide assumptions, inputs, and outputs for tested functions.
* **Common Errors:** What are common user errors?
* **Android Integration:** How does the execution reach this test file from the Android framework/NDK?
* **Frida Hooking:** Provide Frida examples for debugging.

This breakdown provides a roadmap for the analysis.

**3. Analyzing the Code (Iterative Process):**

* **High-Level Overview:**  The first thing to notice is the `#include "../libc/include/complex.h"` and the numerous `TEST(complex_h, ...)` blocks. This immediately suggests that the file is a unit test suite specifically for the `<complex.h>` header file, which provides complex number functionality in C.

* **Individual Test Cases:** Examine each `TEST` block. They all follow a similar pattern: calling a complex number function (like `cabs`, `cacos`, `cexp`, etc.) with a specific input and using `ASSERT_EQ` to verify the output. This confirms the purpose of the file: testing the correctness of Bionic's complex number implementations.

* **Identifying Tested Functions:** List all the tested functions. This forms the basis of the "Functionality" section of the answer.

* **Relationship to Android:**  Realize that `<complex.h>` is part of the standard C library (libc), which is a fundamental component of Android. Applications using complex numbers will rely on these Bionic implementations. Examples are scientific apps, signal processing, and game development.

* **libc Implementation Details (The Deep Dive):**  This requires knowledge of how libc functions are typically implemented. It's crucial to understand that these are usually *thin wrappers* around the underlying system calls or direct hardware instructions for basic math operations. For more complex functions, they involve algorithms. However, the *exact* implementation is often hidden within the Bionic source code (which isn't fully provided in the prompt). The answer should focus on the general approach: basic operations use hardware, more complex ones use algorithms, and Bionic might have optimizations. *Crucially, acknowledge the limitations of not having the full source code*.

* **Dynamic Linker (Another Deep Dive):**  Consider how the complex number functions are linked into an Android application. They reside in `libc.so`. When an app uses a complex number function, the dynamic linker resolves the symbol and links it to the appropriate implementation in `libc.so`. A simple `libc.so` layout example is sufficient to illustrate the concept. Explain the symbol resolution process.

* **Logic and Examples:** For each tested function, provide a simple example of its mathematical behavior. For instance, `cabs` calculates the magnitude.

* **Common Errors:** Think about typical mistakes developers make when working with complex numbers: misunderstanding the imaginary unit, incorrect function usage, precision issues, and linking problems.

* **Android Framework/NDK Integration:**  Trace the path from an Android app using a complex number function. It starts with the app code, goes through the NDK (if used), involves the compilation process, and finally, at runtime, the dynamic linker loads `libc.so`. Frida can be used to intercept these calls at various stages.

* **Frida Hooking:**  Provide basic Frida snippets demonstrating how to hook functions like `cabs` and `creal`. Emphasize the importance of finding the correct library and function name.

**4. Structuring the Answer:**

Organize the information logically, following the structure of the original request:

* Start with the overall functionality.
* Discuss the relationship with Android.
* Explain libc function implementation (general principles).
* Address the dynamic linker (layout and linking).
* Provide input/output examples.
* Discuss common user errors.
* Explain the Android framework/NDK path.
* Give Frida hooking examples.

**5. Refining and Reviewing:**

* **Clarity and Conciseness:** Ensure the language is clear and avoids jargon where possible.
* **Accuracy:** Double-check the technical details.
* **Completeness:**  Address all parts of the request.
* **Caveats:** Acknowledge any limitations, such as not having the full Bionic source code. For example, the exact implementation of `ctanh` is not shown in the provided code, so avoid making definitive statements about its internal workings.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the specific mathematical formulas for each complex function. However, the prompt emphasizes understanding the *Bionic context*. Therefore, I'd shift the focus to how these functions are *tested* within Bionic, their link to `libc.so`, and how Android applications use them. The exact mathematical implementation is less important than the testing and linking aspects in this context. Also, realizing I don't have the full Bionic source code means I need to generalize the libc implementation explanation.

By following these steps, the detailed and comprehensive answer provided earlier can be constructed. The key is to break down the complex request into manageable parts and address each point systematically.
好的，让我们来详细分析一下 `bionic/tests/complex_test.cpp` 这个文件。

**文件功能概述:**

这个 `complex_test.cpp` 文件是一个单元测试文件，用于测试 Android Bionic C 库 (`libc`) 中 `<complex.h>` 头文件中定义的复数运算相关函数的正确性。  它使用了 Google Test 框架 (`gtest`) 来组织和执行这些测试。

**与 Android 功能的关系及举例说明:**

Bionic 是 Android 的基础 C 库，它提供了应用程序运行所需的各种基本功能，包括数学运算、字符串处理、文件 I/O 等。 `<complex.h>` 中定义的复数运算函数是 C 标准库的一部分，Bionic 必须提供这些函数的实现，以确保在 Android 上运行的 C/C++ 程序能够正常进行复数运算。

**举例说明:**

* **科学计算应用:**  许多科学计算或者工程应用会用到复数，例如信号处理、电路分析、量子力学模拟等。这些应用依赖 Bionic 提供的复数运算功能。
* **游戏开发:**  在一些 3D 游戏中，可能会使用复数或者与复数相关的数学概念（例如四元数可以用复数对表示）进行旋转、变换等计算。
* **NDK 开发:**  使用 Android NDK 进行原生代码开发的开发者，可以直接使用 `<complex.h>` 中定义的函数进行复数运算。

**libc 函数的功能及其实现:**

这个测试文件涵盖了 `<complex.h>` 中定义的大部分复数运算函数。对于每个函数，测试都通过断言（`ASSERT_EQ`）来验证在特定输入下，函数的输出是否符合预期。

**详细解释 libc 函数的功能（根据测试文件推断）:**

* **`cabs(z)` / `cabsf(z)` / `cabsl(z)`:** 计算复数 `z` 的绝对值（模）。实现通常会利用 `sqrt(real*real + imag*imag)`。
* **`cacos(z)` / `cacosf(z)` / `cacosl(z)`:** 计算复数 `z` 的反余弦。实现通常会利用实数的反余弦函数和对数函数，涉及复杂的数学公式。
* **`cacosh(z)` / `cacoshf(z)` / `cacoshl(z)`:** 计算复数 `z` 的反双曲余弦。实现类似 `cacos`，涉及双曲函数和对数函数。
* **`carg(z)` / `cargf(z)` / `cargl(z)`:** 计算复数 `z` 的辐角（argument，即复数在复平面上与正实轴的夹角）。实现通常使用 `atan2(cimag(z), creal(z))`。
* **`casin(z)` / `casinf(z)` / `casinl(z)`:** 计算复数 `z` 的反正弦。实现类似 `cacos`，涉及反正弦和对数函数。
* **`casinh(z)` / `casinhf(z)` / `casinhl(z)`:** 计算复数 `z` 的反双曲正弦。实现类似 `cacosh`，涉及反双曲正弦和对数函数。
* **`catan(z)` / `catanf(z)` / `catanl(z)`:** 计算复数 `z` 的反正切。实现类似 `cacos`，涉及反正切和对数函数。
* **`catanh(z)` / `catanhf(z)` / `catanhl(z)`:** 计算复数 `z` 的反双曲正切。实现类似 `cacosh`，涉及反双曲正切和对数函数。
* **`ccos(z)` / `ccosf(z)` / `ccosl(z)`:** 计算复数 `z` 的余弦。实现通常使用三角恒等式和指数函数，例如 `cos(x+iy) = cos(x)cosh(y) - isin(x)sinh(y)`。
* **`ccosh(z)` / `ccoshf(z)` / `ccoshl(z)`:** 计算复数 `z` 的双曲余弦。实现类似 `ccos`，使用双曲恒等式和指数函数。
* **`cexp(z)` / `cexpf(z)` / `cexpl(z)`:** 计算复数 `z` 的指数。实现通常使用欧拉公式：`exp(x+iy) = exp(x)(cos(y) + isin(y))`。
* **`cimag(z)` / `cimagf(z)` / `cimagl(z)`:** 获取复数 `z` 的虚部。实现非常简单，直接访问复数结构体的虚部成员。
* **`clog(z)` / `clogf(z)` / `clogl(z)`:** 计算复数 `z` 的自然对数。实现通常使用复数的极坐标表示：`log(r*e^(i*theta)) = log(r) + i*theta`，其中 `r` 是模，`theta` 是辐角。
* **`conj(z)` / `conjf(z)` / `conjl(z)`:** 计算复数 `z` 的共轭复数。实现非常简单，将虚部取反。
* **`cpow(base, exponent)` / `cpowf(base, exponent)` / `cpowl(base, exponent)`:** 计算复数 `base` 的 `exponent` 次幂。实现通常利用对数和指数运算：`base^exponent = exp(exponent * log(base))`。
* **`cproj(z)` / `cprojf(z)` / `cprojl(z)`:** 计算复数 `z` 在 Riemann 球面上的投影。 这通常用于处理无穷大的情况，例如将无穷大的复数映射到特定的无穷远点。
* **`creal(z)` / `crealf(z)` / `creall(z)`:** 获取复数 `z` 的实部。实现非常简单，直接访问复数结构体的实部成员。
* **`csin(z)` / `csinf(z)` / `csinl(z)`:** 计算复数 `z` 的正弦。实现通常使用三角恒等式和指数函数，例如 `sin(x+iy) = sin(x)cosh(y) + icos(x)sinh(y)`。
* **`csinh(z)` / `csinhf(z)` / `csinhl(z)`:** 计算复数 `z` 的双曲正弦。实现类似 `csin`，使用双曲恒等式和指数函数。
* **`csqrt(z)` / `csqrtf(z)` / `csqrtl(z)`:** 计算复数 `z` 的平方根。实现通常利用复数的极坐标表示。
* **`ctan(z)` / `ctanf(z)` / `ctanl(z)`:** 计算复数 `z` 的正切。实现通常使用正弦和余弦函数：`tan(z) = sin(z) / cos(z)`。
* **`ctanh(z)` / `ctanhf(z)` / `ctanhl(z)`:** 计算复数 `z` 的双曲正切。实现通常使用双曲正弦和双曲余弦函数：`tanh(z) = sinh(z) / cosh(z)`。

**注意:**  以上是基于常见实现方式的推断。Bionic 的具体实现可能包含针对 Android 平台的优化。

**涉及 dynamic linker 的功能:**

虽然这个测试文件本身不直接涉及 dynamic linker 的代码，但它测试的函数最终会被动态链接到使用它们的应用程序中。

**so 布局样本 (以 `libc.so` 为例):**

```
libc.so:
    ...
    .text:  # 代码段
        ...
        cabs:          # cabs 函数的代码
            ...
        cacos:         # cacos 函数的代码
            ...
        # 其他复数运算函数的代码
        ...
    .data:  # 数据段
        ...
    .dynsym: # 动态符号表
        ...
        cabs        R_ARM_JUMP_SLOT   # cabs 函数的符号信息
        cacos       R_ARM_JUMP_SLOT   # cacos 函数的符号信息
        ...
    .dynstr: # 动态字符串表
        cabs
        cacos
        ...
    ...
```

**链接的处理过程:**

1. **编译时:** 当应用程序代码中使用了 `<complex.h>` 中的函数时，编译器会生成对这些函数的外部引用。
2. **链接时:** 链接器（在 Android 上通常是 `lld`）会将应用程序的目标文件与所需的共享库（例如 `libc.so`) 链接起来。链接器会读取 `libc.so` 的动态符号表 (`.dynsym`)，找到应用程序引用的复数运算函数的地址，并将这些地址信息写入到应用程序的可执行文件中。
3. **运行时:** 当应用程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所需的共享库（`libc.so`) 到内存中。然后，dynamic linker 会根据应用程序可执行文件中的信息，解析外部符号引用，将应用程序中对复数运算函数的调用指向 `libc.so` 中实际的函数地址。这个过程通常涉及到延迟绑定 (lazy binding)，即在函数第一次被调用时才进行地址解析。

**逻辑推理、假设输入与输出:**

以下是一些测试用例的逻辑推理和假设输入输出：

* **`TEST(complex_h, cabs)`:**
    * **假设输入:** `0` (相当于复数 `0 + 0i`)
    * **逻辑推理:** 复数 `0 + 0i` 的模为 `sqrt(0^2 + 0^2) = 0`。
    * **预期输出:** `0.0`
* **`TEST(complex_h, cacos)`:**
    * **假设输入:** `0.0` (相当于复数 `0.0 + 0.0i`)
    * **逻辑推理:**  `cacos(0)` 的实部是 `arccos(0)`，即 `π/2`。
    * **预期输出:** `M_PI_2` (宏定义，表示 π/2)
* **`TEST(complex_h, cpow)`:**
    * **假设输入:** `2.0` (底数，相当于复数 `2.0 + 0.0i`)，`3.0` (指数，相当于复数 `3.0 + 0.0i`)
    * **逻辑推理:** 实数的幂运算，`2.0^3.0 = 8.0`。
    * **预期输出:** `8.0`
* **`TEST(complex_h, ctanh)` (涉及 NaN 的测试):**
    * **假设输入:** `nan("") + 0i` (一个 NaN 实部和 0 虚部的复数)
    * **逻辑推理:** 根据 IEEE 754 标准，对 NaN 进行某些运算的结果仍然是 NaN。`ctanh` 函数在遇到 NaN 时应该返回 NaN 或者包含 NaN 的结果。
    * **预期输出:** 实部为 NaN，虚部为 0。
    * **假设输入:** `nan("") + 2.0i` (一个 NaN 实部和非零虚部的复数)
    * **预期输出:** 实部为 NaN，虚部为 NaN。
    * **假设输入:** `nan("") + nan("") * I` (实部和虚部都是 NaN 的复数)
    * **预期输出:** 实部为 NaN，虚部为 NaN。

**用户或编程常见的使用错误:**

* **未包含头文件:** 忘记包含 `<complex.h>` 导致编译错误。
* **类型不匹配:** 将实数传递给需要复数的函数，或者反之。可以使用 `_Complex_I` 宏来表示虚数单位 `i`。 例如：`double complex z = 2.0 + 3.0 * _Complex_I;`
* **精度问题:** 浮点数的比较需要考虑精度误差，不能直接使用 `==`。在测试代码中，通常会使用允许一定误差范围的比较方式（虽然这个测试文件中直接使用了 `ASSERT_EQ`，但在实际应用中需要注意）。
* **对辐角的理解:**  对 `carg` 函数返回的角度范围理解错误（通常是 `[-π, π]`）。
* **复数运算的顺序:**  在复杂的复数表达式中，运算顺序可能会影响结果，需要注意括号的使用。
* **链接错误:** 在某些构建系统中，可能需要显式链接 `m` 库（数学库，虽然 `complex.h` 的实现通常在 `libc` 中）。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework / 应用层 (Java/Kotlin):**
   - 如果 Android Framework 或应用层需要进行复数运算，它们通常会通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。
2. **NDK 开发 (C/C++):**
   - 使用 NDK 进行开发的应用程序，可以直接包含 `<complex.h>` 头文件，并使用其中定义的复数运算函数。
   - 例如，一个音频处理模块可能需要进行傅里叶变换，这涉及到复数运算。
   ```c++
   #include <complex.h>
   #include <jni.h>

   extern "C" JNIEXPORT jdouble JNICALL
   Java_com_example_myapp_MyClass_calculateComplexMagnitude(JNIEnv *env, jobject /* this */, jdouble real, jdouble imag) {
       double complex z = real + imag * _Complex_I;
       return cabs(z);
   }
   ```
3. **编译和链接:**
   - 当 NDK 代码被编译时，编译器会处理 `<complex.h>` 的包含，并将对复数运算函数的调用生成符号引用。
   - 链接器会将这些符号引用链接到 Bionic 的 `libc.so` 中。
4. **运行时:**
   - 当应用程序运行到调用复数运算函数的地方时，dynamic linker 会确保 `libc.so` 已经被加载，并且函数调用会被正确地路由到 `libc.so` 中的实现。
5. **单元测试:**
   -  `bionic/tests/complex_test.cpp`  是在 Android 系统构建过程中被编译和执行的单元测试。这些测试确保了 Bionic 提供的复数运算功能的正确性。

**Frida Hook 示例调试步骤:**

假设你想 hook `cabs` 函数来观察其输入和输出：

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在你的开发机器上安装了 Frida 客户端 (`pip install frida-tools`).

2. **编写 Frida Hook 脚本 (JavaScript):**

   ```javascript
   function hook_cabs() {
       const libc = Process.getModuleByName("libc.so");
       const cabs_ptr = libc.getExportByName("cabs");

       if (cabs_ptr) {
           Interceptor.attach(cabs_ptr, {
               onEnter: function(args) {
                   const real_part = args[0].readDouble(); // 读取实部
                   const imag_part = args[0].add(8).readDouble(); // 读取虚部 (假设 double 占 8 字节)
                   console.log("[cabs] Input: (" + real_part + ", " + imag_part + "i)");
               },
               onLeave: function(retval) {
                   console.log("[cabs] Output: " + retval.readDouble());
               }
           });
           console.log("Hooked cabs at:", cabs_ptr);
       } else {
           console.error("Failed to find cabs in libc.so");
       }
   }

   rpc.exports = {
       hook_cabs: hook_cabs
   };
   ```

3. **运行 Frida 脚本:**

   ```bash
   frida -U -f <your_app_package_name> -l your_hook_script.js --no-pause
   ```

   或者，如果你的应用已经在运行：

   ```bash
   frida -U <your_app_package_name> -l your_hook_script.js
   ```

4. **在应用中触发复数运算:**  运行你的 Android 应用，并执行会调用 `cabs` 函数的操作。

5. **观察 Frida 输出:**  Frida 会在控制台上打印出 `cabs` 函数的输入（复数的实部和虚部）和输出（模）。

**Frida Hook 示例调试其他步骤:**

你可以使用类似的 `Interceptor.attach` 方法 hook 其他的复数运算函数，例如 `creal`，`cimag` 等。你需要找到对应函数在 `libc.so` 中的导出符号。

例如，hook `creal`:

```javascript
function hook_creal() {
    const libc = Process.getModuleByName("libc.so");
    const creal_ptr = libc.getExportByName("creal");

    if (creal_ptr) {
        Interceptor.attach(creal_ptr, {
            onEnter: function(args) {
                const real_part = args[0].readDouble();
                const imag_part = args[0].add(8).readDouble();
                console.log("[creal] Input: (" + real_part + ", " + imag_part + "i)");
            },
            onLeave: function(retval) {
                console.log("[creal] Output: " + retval.readDouble());
            }
        });
        console.log("Hooked creal at:", creal_ptr);
    } else {
        console.error("Failed to find creal in libc.so");
    }
}

rpc.exports = {
    hook_creal: hook_creal
};
```

**总结:**

`bionic/tests/complex_test.cpp` 是一个关键的测试文件，用于验证 Android Bionic C 库中复数运算函数的正确性。理解这个文件有助于理解 Android 系统中复数运算的实现方式，以及如何进行相关的开发和调试。 通过 Frida 这样的动态分析工具，开发者可以更深入地了解这些函数在运行时 behavior。

### 提示词
```
这是目录为bionic/tests/complex_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

// This file is compiled against both glibc and bionic, and our complex.h
// depends on bionic-specific macros, so hack around that.
#include <sys/cdefs.h>
#if !defined(__INTRODUCED_IN)
#define __INTRODUCED_IN(x)
#endif
#if !defined(__BIONIC_AVAILABILITY_GUARD)
#define __BIONIC_AVAILABILITY_GUARD(x) 1
#endif

// libc++ actively gets in the way of including <complex.h> from C++, so we
// have to be naughty.
#include "../libc/include/complex.h"

// (libc++ also seems to have really bad implementations of its own that ignore
// the intricacies of floating point math.)
// http://llvm.org/bugs/show_bug.cgi?id=21504

#include <math.h> // For M_PI_2/M_PI_2l.

// Prettify gtest Complex printing.
// Macro 'complex' defined in complex.h conflicts with iostream.
#pragma push_macro("complex")
#undef complex
#include <iostream>
#pragma pop_macro("complex")
namespace testing {
namespace internal {
inline void PrintTo(const double _Complex& c, std::ostream* os) {
  *os << "(" << creal(c) << "," << cimag(c) << "i)";
}
inline void PrintTo(const float _Complex& c, std::ostream* os) {
  *os << "(" << crealf(c) << "," << cimagf(c) << "i)";
}
inline void PrintTo(const long double _Complex& c, std::ostream* os) {
  *os << "(" << creall(c) << "," << cimagl(c) << "i)";
}
}
}

// Macro 'I' defined in complex.h conflicts with gtest.h.
#pragma push_macro("I")
#undef I
#include <gtest/gtest.h>
#pragma pop_macro("I")

TEST(complex_h, cabs) {
  ASSERT_EQ(0.0, cabs(0));
}

TEST(complex_h, cabsf) {
  ASSERT_EQ(0.0, cabsf(0));
}

TEST(complex_h, cabsl) {
  ASSERT_EQ(0.0, cabsl(0));
}

TEST(complex_h, cacos) {
  ASSERT_EQ(M_PI_2, cacos(0.0));
}

TEST(complex_h, cacosf) {
  ASSERT_EQ(static_cast<float>(M_PI_2), cacosf(0.0));
}

TEST(complex_h, cacosl) {
  ASSERT_EQ(M_PI_2l, cacosl(0.0));
}

TEST(complex_h, cacosh) {
  ASSERT_EQ(0.0, cacosh(1.0));
}

TEST(complex_h, cacoshl) {
  ASSERT_EQ(0.0, cacoshl(1.0));
}

TEST(complex_h, cacoshf) {
  ASSERT_EQ(0.0, cacoshf(1.0));
}

TEST(complex_h, carg) {
  ASSERT_EQ(0.0, carg(0));
}

TEST(complex_h, cargf) {
  ASSERT_EQ(0.0, cargf(0));
}

TEST(complex_h, cargl) {
  ASSERT_EQ(0.0, cargl(0));
}

TEST(complex_h, casin) {
  ASSERT_EQ(0.0, casin(0));
}

TEST(complex_h, casinf) {
  ASSERT_EQ(0.0, casinf(0));
}

TEST(complex_h, casinl) {
  ASSERT_EQ(0.0, casinl(0));
}

TEST(complex_h, casinh) {
  ASSERT_EQ(0.0, casinh(0));
}

TEST(complex_h, casinhf) {
  ASSERT_EQ(0.0, casinhf(0));
}

TEST(complex_h, casinhl) {
  ASSERT_EQ(0.0, casinhl(0));
}

TEST(complex_h, catan) {
  ASSERT_EQ(0.0, catan(0));
}

TEST(complex_h, catanf) {
  ASSERT_EQ(0.0, catanf(0));
}

TEST(complex_h, catanl) {
  ASSERT_EQ(0.0, catanl(0));
}

TEST(complex_h, catanh) {
  ASSERT_EQ(0.0, catanh(0));
}

TEST(complex_h, catanhf) {
  ASSERT_EQ(0.0, catanhf(0));
}

TEST(complex_h, catanhl) {
  ASSERT_EQ(0.0, catanhl(0));
}

TEST(complex_h, ccos) {
  ASSERT_EQ(1.0, ccos(0));
}

TEST(complex_h, ccosf) {
  ASSERT_EQ(1.0, ccosf(0));
}

TEST(complex_h, ccosl) {
  ASSERT_EQ(1.0, ccosl(0));
}

TEST(complex_h, ccosh) {
  ASSERT_EQ(1.0, ccosh(0));
}

TEST(complex_h, ccoshf) {
  ASSERT_EQ(1.0, ccoshf(0));
}

TEST(complex_h, ccoshl) {
  ASSERT_EQ(1.0, ccoshl(0));
}

TEST(complex_h, cexp) {
  ASSERT_EQ(1.0, cexp(0));
}

TEST(complex_h, cexpf) {
  ASSERT_EQ(1.0, cexpf(0));
}

TEST(complex_h, cexpl) {
  ASSERT_EQ(1.0, cexpl(0));
}

TEST(complex_h, cimag) {
  ASSERT_EQ(0.0, cimag(0));
}

TEST(complex_h, cimagf) {
  ASSERT_EQ(0.0f, cimagf(0));
}

TEST(complex_h, cimagl) {
  ASSERT_EQ(0.0, cimagl(0));
}

TEST(complex_h, clog) {
  ASSERT_EQ(0.0, clog(1.0));
}

TEST(complex_h, clogf) {
  ASSERT_EQ(0.0f, clogf(1.0f));
}

TEST(complex_h, clogl) {
  ASSERT_EQ(0.0L, clogl(1.0L));
}

TEST(complex_h, conj) {
  ASSERT_EQ(0.0, conj(0));
}

TEST(complex_h, conjf) {
  ASSERT_EQ(0.0f, conjf(0));
}

TEST(complex_h, conjl) {
  ASSERT_EQ(0.0, conjl(0));
}

TEST(complex_h, cpow) {
  ASSERT_EQ(8.0, cpow(2.0, 3.0));
}

TEST(complex_h, cpowf) {
  ASSERT_EQ(8.0f, cpowf(2.0f, 3.0f));
}

TEST(complex_h, cpowl) {
  ASSERT_EQ(8.0L, cpowl(2.0L, 3.0L));
}

TEST(complex_h, cproj) {
  ASSERT_EQ(0.0, cproj(0));
}

TEST(complex_h, cprojf) {
  ASSERT_EQ(0.0f, cprojf(0));
}

TEST(complex_h, cprojl) {
  ASSERT_EQ(0.0, cprojl(0));
}

TEST(complex_h, creal) {
  ASSERT_EQ(2.0, creal(2.0 + 3.0I));
}

TEST(complex_h, crealf) {
  ASSERT_EQ(2.0f, crealf(2.0f + 3.0fI));
}

TEST(complex_h, creall) {
  ASSERT_EQ(2.0, creall(2.0L + 3.0LI));
}

TEST(complex_h, csin) {
  ASSERT_EQ(0.0, csin(0));
}

TEST(complex_h, csinf) {
  ASSERT_EQ(0.0, csinf(0));
}

TEST(complex_h, csinl) {
  ASSERT_EQ(0.0, csinl(0));
}

TEST(complex_h, csinh) {
  ASSERT_EQ(0.0, csinh(0));
}

TEST(complex_h, csinhf) {
  ASSERT_EQ(0.0, csinhf(0));
}

TEST(complex_h, csinhl) {
  ASSERT_EQ(0.0, csinhl(0));
}

TEST(complex_h, csqrt) {
  ASSERT_EQ(0.0, csqrt(0));
}

TEST(complex_h, csqrtf) {
  ASSERT_EQ(0.0f, csqrtf(0));
}

TEST(complex_h, csqrtl) {
  ASSERT_EQ(0.0, csqrtl(0));
}

TEST(complex_h, ctan) {
  ASSERT_EQ(0.0, ctan(0));
}

TEST(complex_h, ctanf) {
  ASSERT_EQ(0.0, ctanf(0));
}

TEST(complex_h, ctanl) {
  ASSERT_EQ(0.0, ctanl(0));
}

TEST(complex_h, ctanh) {
  ASSERT_EQ(0.0, ctanh(0));

  double complex z;

  // If z is NaN+0i, the result is NaN+0i.
  z = ctanh(nan("") + 0i);
  ASSERT_TRUE(isnan(creal(z)));
  ASSERT_EQ(0.0, cimag(z));

  // If z is NaN+yi, the result is NaN+NaNi.
  z = ctanh(nan("") + 2.0i);
  ASSERT_TRUE(isnan(creal(z)));
  ASSERT_TRUE(isnan(cimag(z)));

  // If z is NaN+NaNi, the result is NaN+NaNi.
  z = ctanh(nan("") + nan("") * I);
  ASSERT_TRUE(isnan(creal(z)));
  ASSERT_TRUE(isnan(cimag(z)));
}

TEST(complex_h, ctanhf) {
  ASSERT_EQ(0.0f, ctanhf(0.0f));

  float complex z;

  // If z is NaN+0i, the result is NaN+0i.
  z = ctanhf(nanf("") + 0.0fi);
  ASSERT_TRUE(isnan(crealf(z)));
  ASSERT_EQ(0.0f, cimagf(z));

  // If z is NaN+yi, the result is NaN+NaNi.
  z = ctanhf(nanf("") + 2.0fi);
  ASSERT_TRUE(isnan(crealf(z)));
  ASSERT_TRUE(isnan(cimagf(z)));

  // If z is NaN+NaNi, the result is NaN+NaNi.
  z = ctanhf(nanf("") + nanf("") * I);
  ASSERT_TRUE(isnan(crealf(z)));
  ASSERT_TRUE(isnan(cimagf(z)));
}

TEST(complex_h, ctanhl) {
  ASSERT_EQ(0.0L, ctanhl(0.0L));

  long double complex z;

  // If z is NaN+0i, the result is NaN+0i.
  z = ctanhl(nanl("") + 0.0Li);
  ASSERT_TRUE(isnan(creall(z)));
  // TODO: this case is currently broken in the netbsd ctanhl.
  // ASSERT_EQ(0.0L, cimagl(z));

  // If z is NaN+yi, the result is NaN+NaNi.
  z = ctanhl(nanl("") + 2.0Li);
  ASSERT_TRUE(isnan(creall(z)));
  ASSERT_TRUE(isnan(cimagl(z)));

  // If z is NaN+NaNi, the result is NaN+NaNi.
  z = ctanhl(nanl("") + nanl("") * I);
  ASSERT_TRUE(isnan(creall(z)));
  ASSERT_TRUE(isnan(cimagl(z)));
}
```