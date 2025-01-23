Response:
Let's break down the thought process for analyzing the `s_exp2l.c` code.

1. **Understand the Goal:** The primary goal is to analyze a specific C source file (`s_exp2l.c`) from Android's `bionic` library, specifically the math library component. The analysis should cover its function, relationship to Android, implementation details, dynamic linking aspects, potential errors, and how Android code reaches this point.

2. **Initial Code Scan (High-Level):**
   - **Headers:**  `float.h`, `stdint.h`, `fpmath.h`, `math.h`. This immediately signals it's a math function dealing with floating-point numbers, specifically `long double`.
   - **Copyright and License:**  BSD-2-Clause license, indicating it's derived from FreeBSD. This is a crucial piece of information about its origin.
   - **Macros:** `TBLBITS`, `TBLSIZE`, `BIAS`, `EXPMASK`. These define constants, likely related to the internal workings of the exponential calculation. The names suggest a table-based approach.
   - **Static Variables:** `huge`, `twom10000`, and several constants `P1` through `P10`. `huge` and `twom10000` are likely used for handling overflow/underflow. The `P` constants strongly suggest polynomial approximation.
   - **Arrays:** `tbl` and `eps`. The names and sizes (`TBLSIZE`) confirm the table-based approach. `tbl` likely stores precomputed exponential values, and `eps` probably holds error correction terms.
   - **Function Signature:** `long double exp2l(long double x)`. This confirms it calculates 2 to the power of `x` for `long double` precision.

3. **Functionality Identification:** Based on the function name `exp2l` and the comments, the core functionality is calculating 2 raised to the power of a `long double` number.

4. **Android Relevance:**  Realize that `bionic` is *the* standard C library for Android. Any math function within it is fundamental to Android's operation. Examples are easy to come up with: any app doing scientific calculations, graphics processing, or even seemingly simple operations that rely on system libraries.

5. **Implementation Deep Dive:**
   - **Reduction Steps:** The comments mention reducing `x` to `y` and then `y` to `z`. This is a common technique in numerical computation to bring the input into a range where approximations are easier to manage.
   - **Table Lookup:**  The `tbl` array and the comment about `exp2t[i0]` clearly indicate a table lookup to get an initial approximation.
   - **Polynomial Approximation:** The constants `P1` through `P10` are used in a polynomial expression, which refines the table lookup result.
   - **Error Correction:** The `eps` array and its subtraction from `z` suggest an error correction mechanism to improve accuracy.
   - **Exponent Handling:**  The code extracts `k` (the integer part of the exponent) and uses it to scale the result, handling potential overflow and underflow.
   - **Bit Manipulation:**  The use of `union IEEEl2bits` and direct bit manipulation (`u.xbits.expsign`, `u.bits.manl`) shows low-level manipulation of the floating-point representation.

6. **Dynamic Linking (Hypothetical Scenario):** Since the request mentions the dynamic linker, imagine a hypothetical scenario.
   - **SO Layout:**  Visualize the structure of a shared object (`.so`) file. Think about sections like `.text` (code), `.rodata` (read-only data like the tables and constants), `.data` (initialized data), and symbol tables.
   - **Symbol Resolution:** Consider how the dynamic linker resolves symbols. `exp2l` would be an exported symbol. Internal symbols like the `static` variables and the constants would likely not be exported. Think about the linking process and how symbols are found and addresses are patched.

7. **Logic and Assumptions:**
   - **Input/Output:** Consider simple cases like `exp2l(0)` (should be 1), `exp2l(1)` (should be 2), and edge cases like very large or very small numbers.
   - **Assumptions:**  The code assumes IEEE 754 representation for `long double`. The table size and polynomial degree are chosen for a specific accuracy target.

8. **Common Errors:** Think about how a programmer might misuse this function:
   - Passing NaN or infinity.
   - Overflow/underflow without proper checking (although the function itself attempts to handle this).

9. **Android Framework/NDK Path:** Trace the execution flow from a high level:
   - **NDK:** A developer uses a math function like `powl` (long double version of `pow`).
   - **libc:** `powl` likely calls `exp2l` internally (since `pow(x, y)` can be computed as `exp2(y * log2(x))`).
   - **Dynamic Linking:** The call to `exp2l` goes through the dynamic linker to find the actual implementation in `libm.so`.

10. **Structure and Refine:** Organize the findings into the requested sections (Functionality, Android Relationship, Implementation, Dynamic Linker, Logic, Errors, Debugging). Refine the explanations, adding more detail and clarity. Use code snippets and examples where appropriate. Ensure the language is precise and avoids jargon where possible.

**Self-Correction/Refinement during the process:**

- **Initial thought:**  Maybe the tables are for direct lookup of all possible values. **Correction:**  Realize the input range is infinite, so tables must be used for reduction and interpolation/approximation.
- **Focus too much on low-level bit details:** **Correction:**  Balance the low-level details with a higher-level explanation of the algorithm.
- **Dynamic linker explanation too generic:** **Correction:**  Provide a concrete example of how symbols related to `exp2l` would be handled.
- **Missing concrete examples for errors:** **Correction:** Add specific code snippets showing potential misuse.

By following this structured thought process, and incorporating self-correction, a comprehensive analysis of the `s_exp2l.c` file can be achieved.
这是一个关于计算 `long double` 类型变量的以 2 为底的指数函数 `exp2l(x)` 的 C 源代码文件，属于 Android 系统库 `bionic` 的数学库部分。

**它的功能:**

`s_exp2l.c` 文件的主要功能是实现 `exp2l(long double x)` 函数，该函数计算并返回 2 的 `x` 次方，即 2<sup>x</sup>。  由于它位于 `libm` (math library) 中，它为需要进行以 2 为底指数运算的程序提供了基础的数学功能。

**与 Android 功能的关系及举例:**

`exp2l` 函数是 Android 系统底层数学库的一部分，许多 Android 的功能都间接地依赖于它。以下是一些例子：

* **图形渲染 (Graphics Rendering):**  在 OpenGL 或 Vulkan 等图形 API 中，计算光照、纹理坐标、变换矩阵等可能涉及到指数运算。虽然不一定直接调用 `exp2l`，但底层的实现可能会用到类似的技术。
* **音频处理 (Audio Processing):** 音频编解码、音频效果处理等可能需要进行指数运算来调整音量、频率等。
* **科学计算和工程应用 (Scientific Computing and Engineering Applications):**  如果 Android 设备运行科学计算或工程相关的应用，这些应用很可能直接或间接地使用 `exp2l` 或其他相关的指数函数。
* **机器学习和人工智能 (Machine Learning and Artificial Intelligence):**  许多机器学习模型，特别是神经网络，会使用到指数函数（例如，在激活函数如 sigmoid 或 softmax 中）。虽然这些框架通常有自己的优化实现，但底层的库可能会用到 `exp2l` 这样的函数。
* **游戏开发 (Game Development):** 游戏中的物理模拟、动画、特效等都可能涉及到指数运算。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件中只有一个主要的 libc 函数：`exp2l(long double x)`。其实现方法如下：

1. **输入处理和特殊情况处理:**
   - 将输入的 `long double` 类型的 `x` 存储到联合体 `union IEEEl2bits u` 中，允许以位模式访问。
   - 检查 `x` 的特殊情况，例如 NaN (非数字)、正负无穷大。对于这些情况，按照 IEEE 754 标准返回相应的结果。
   - 处理溢出和下溢的情况。如果 `x` 非常大，结果会溢出；如果 `x` 非常小，结果会下溢。
   - 对于接近 0 的 `x`，使用泰勒展开的线性近似 `1.0 + x` 来提高效率。

2. **范围缩减 (Range Reduction):**
   - 将 `x` 分解为整数部分 `k` 和小数部分 `y`，使得 `x = k + y`，其中 `|y| <= 0.5`。这样 `2^x = 2^k * 2^y`。
   - 进一步缩减 `y` 的范围，使用一个预先计算的表格 `tbl` 和一个小的误差校正数组 `eps`。  目标是将 `y` 转换到一个非常小的范围内，以便使用多项式逼近。
   - 公式如下：`y = i / TBLSIZE + z - eps[i]`，其中 `i` 是接近 `y * TBLSIZE` 的整数。

3. **表格查找 (Table Lookup):**
   - 使用计算得到的索引 `i0` (由 `i` 加上偏移量得到) 在表格 `tbl` 中查找预先计算好的值。`tbl[i0]` 约等于 `exp2(i / TBLSIZE + eps[i])`。

4. **多项式逼近 (Polynomial Approximation):**
   - 使用一个 10 阶的 minimax 多项式来计算 `exp2(z - eps[i])`。多项式的系数是 `P1` 到 `P10`。由于 `z - eps[i]` 非常小，多项式逼近可以提供很高的精度。
   - 计算 `r = tbl[i0] * (1 + z * (P1 + z * (P2 + ...)))`，其中多项式部分逼近 `exp2(z - eps[i])`。

5. **结果缩放 (Scaling):**
   - 将多项式逼近的结果 `r` 乘以 `2^k` 来得到最终的 `2^x`。
   - 如果 `k` 很大，直接计算 `2^k` 可能会溢出，因此使用位操作来构造 `2^k` 的 `long double` 表示。
   - 如果 `k` 很小，结果可能需要乘以一个非常小的数，可能导致下溢，也需要特殊处理。

**对于 dynamic linker 的功能，请给 so 布局样本，以及每种符号如何的处理过程:**

由于 `s_exp2l.c` 是 `libm.so` 的一部分，我们来看一下 `libm.so` 的布局以及符号处理：

**`libm.so` 布局样本 (简化):**

```
ELF Header
Program Headers
Section Headers:
  .text         PROGBITS, ALLOC, EXECUTE   ; 函数代码 (例如 exp2l)
  .rodata       PROGBITS, ALLOC, LOAD      ; 只读数据 (例如 tbl, eps, P1-P10)
  .data         PROGBITS, ALLOC, WRITE     ; 已初始化的可写数据 (可能没有)
  .bss          NOBITS,   ALLOC, WRITE     ; 未初始化的可写数据 (可能没有)
  .symtab       SYMTAB                     ; 符号表
  .strtab       STRTAB                     ; 字符串表
  .dynsym       DYNSYM                     ; 动态符号表
  .dynstr       DYNSTR                     ; 动态字符串表
  .rel.dyn      REL/RELA                   ; 动态重定位表
  .rel.plt      REL/RELA                   ; PLT 重定位表
  ... 其他段 ...
```

**符号处理过程:**

1. **导出符号 (Exported Symbols):**
   - `exp2l`:  这是一个需要被其他共享库或可执行文件调用的函数。它会出现在 `.dynsym` (动态符号表) 中，类型通常是 `FUNC`，绑定属性可能是 `GLOBAL` 或 `WEAK`。
   - **处理过程:** 当其他模块（例如，一个使用 `exp2l` 的应用）需要调用 `exp2l` 时，动态链接器会在 `libm.so` 的 `.dynsym` 中找到 `exp2l` 的地址，并将其填入调用模块的 PLT (Procedure Linkage Table)。

2. **本地静态符号 (Local Static Symbols):**
   - `huge`, `twom10000`, `P1` - `P10`, `tbl`, `eps`: 这些变量和数组被声明为 `static const` 或 `static volatile`，意味着它们只在 `s_exp2l.c` 文件内部可见。它们通常不会出现在 `.dynsym` 中，而是作为本地符号存储在 `.symtab` 中（如果没有被 strip 掉调试信息）。
   - **处理过程:** 编译器在编译 `s_exp2l.c` 时，会直接将这些符号的地址编码到 `exp2l` 函数的代码中。动态链接器不需要处理这些符号。

3. **外部符号 (External Symbols):**
   - 虽然在这个文件中没有明显的外部符号（除了标准库头文件中声明的类型和宏），但在更复杂的库中，可能会引用其他共享库中的函数或变量。
   - **处理过程:** 如果 `exp2l` 函数内部调用了其他共享库的函数，这些被调用的函数会作为未定义的符号出现在 `libm.so` 的动态符号表中。动态链接器需要在加载时找到这些符号的定义，通常在其他依赖的共享库中。

**假设输入与输出 (逻辑推理):**

* **假设输入:** `x = 0.0`
   * **输出:** `exp2l(0.0)` 应该返回 `1.0` (因为 2<sup>0</sup> = 1)。
* **假设输入:** `x = 1.0`
   * **输出:** `exp2l(1.0)` 应该返回 `2.0` (因为 2<sup>1</sup> = 2)。
* **假设输入:** `x = -1.0`
   * **输出:** `exp2l(-1.0)` 应该返回 `0.5` (因为 2<sup>-1</sup> = 1/2)。
* **假设输入:** `x` 是一个很大的正数 (例如 1000)
   * **输出:** `exp2l(1000)` 应该返回一个非常大的数，可能接近 `LDBL_MAX` 或导致溢出 (取决于具体的实现和平台)。
* **假设输入:** `x` 是一个很小的负数 (例如 -1000)
   * **输出:** `exp2l(-1000)` 应该返回一个非常接近 0 的数，可能导致下溢。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **溢出 (Overflow):**  当输入 `x` 过大时，`exp2l(x)` 的结果会超出 `long double` 能表示的最大值。这通常不会导致程序崩溃，但会返回一个表示无穷大的值 (`Inf`)，这可能不是用户期望的结果。

   ```c
   #include <stdio.h>
   #include <math.h>
   #include <float.h>

   int main() {
       long double x = 2000.0L; // 一个可能导致溢出的值
       long double result = exp2l(x);
       printf("exp2l(%Lf) = %Lf\n", x, result); // 可能输出 Inf
       return 0;
   }
   ```

2. **下溢 (Underflow):** 当输入 `x` 非常小（负数且绝对值很大）时，`exp2l(x)` 的结果会非常接近 0，可能会低于 `long double` 能表示的最小正数。这通常会返回 0.0 或一个非常小的数。

   ```c
   #include <stdio.h>
   #include <math.h>
   #include <float.h>

   int main() {
       long double x = -2000.0L; // 一个可能导致下溢的值
       long double result = exp2l(x);
       printf("exp2l(%Lf) = %Lf\n", x, result); // 可能输出 0.0
       return 0;
   }
   ```

3. **将 NaN 作为输入:** 如果传递 NaN (非数字) 给 `exp2l`，函数会按照 IEEE 754 标准返回 NaN。虽然这符合规范，但如果用户没有正确处理 NaN，可能会导致程序中出现意外的结果。

   ```c
   #include <stdio.h>
   #include <math.h>
   #include <float.h>

   int main() {
       long double nan_val = nanl("");
       long double result = exp2l(nan_val);
       printf("exp2l(NaN) = %Lf\n", result); // 输出 NaN
       return 0;
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，作为调试线索:**

1. **NDK 开发:**  Android Native Development Kit (NDK) 允许开发者使用 C 和 C++ 编写 Android 应用的一部分。如果 NDK 代码中使用了 `powl` (以 `long double` 为参数的幂函数) 或其他内部会调用 `exp2l` 的函数，那么就会涉及到 `libm.so` 中的 `exp2l`。

2. **C/C++ 标准库调用:** 在 NDK 代码中，如果直接调用了 `exp2l` 函数 (包含 `<math.h>`)，编译器会将这个函数调用链接到 Android 系统提供的 `libm.so` 库。

3. **动态链接:** 当 Android 系统加载包含 NDK 代码的应用时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会解析应用的依赖关系，找到需要加载的共享库，包括 `libm.so`。

4. **符号解析:** 动态链接器会解析应用中对 `exp2l` 的引用，并在 `libm.so` 的动态符号表中查找 `exp2l` 的地址。

5. **PLT (Procedure Linkage Table) 和 GOT (Global Offset Table):**  动态链接器会更新应用的 GOT，使其包含 `exp2l` 函数在内存中的实际地址。对 `exp2l` 的首次调用可能会通过 PLT 进行延迟绑定。

**调试线索:**

* **使用 `adb logcat`:**  在 Android 设备上运行应用，并使用 `adb logcat` 查看系统日志。如果应用中涉及到数学运算，可能会有相关的日志输出。
* **使用 NDK Debugger (lldb):**  通过 Android Studio 或命令行使用 lldb 连接到正在运行的 Android 应用的 native 进程。
    - **设置断点:** 在 `s_exp2l.c` 文件的 `exp2l` 函数入口处设置断点。
    - **单步执行:**  观察 `exp2l` 函数的执行过程，查看输入参数 `x` 的值，以及中间变量的变化。
    - **查看调用栈:**  查看 `exp2l` 是被哪个函数调用的，从而追踪调用链，了解 Android framework 或 NDK 代码是如何一步步到达这里的。
* **查看 `maps` 文件:**  在 Android 设备上，可以查看进程的 `/proc/<pid>/maps` 文件，了解 `libm.so` 被加载到哪个内存地址范围，以及 `exp2l` 函数的地址。
* **使用 `objdump` 或 `readelf`:**  可以使用 `objdump -T /system/lib64/libm.so` 或 `readelf -s /system/lib64/libm.so` 查看 `libm.so` 的符号表，确认 `exp2l` 是否被导出。
* **静态分析:** 分析 NDK 代码，查找对 `powl` 或其他可能调用 `exp2l` 的数学函数的调用。

通过以上分析，我们可以理解 `s_exp2l.c` 在 Android 系统中的作用，以及如何从上层应用逐步追踪到这个底层的数学函数实现。这对于理解 Android 系统的底层机制以及调试相关的数学问题非常有帮助。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/s_exp2l.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005-2008 David Schultz <das@FreeBSD.ORG>
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
 */

#include <float.h>
#include <stdint.h>

#include "fpmath.h"
#include "math.h"

#define	TBLBITS	7
#define	TBLSIZE	(1 << TBLBITS)

#define	BIAS	(LDBL_MAX_EXP - 1)
#define	EXPMASK	(BIAS + LDBL_MAX_EXP)

static volatile long double
    huge      = 0x1p10000L,
    twom10000 = 0x1p-10000L;

static const long double
    P1        = 0x1.62e42fefa39ef35793c7673007e6p-1L,
    P2	      = 0x1.ebfbdff82c58ea86f16b06ec9736p-3L,
    P3        = 0x1.c6b08d704a0bf8b33a762bad3459p-5L,
    P4        = 0x1.3b2ab6fba4e7729ccbbe0b4f3fc2p-7L,
    P5        = 0x1.5d87fe78a67311071dee13fd11d9p-10L,
    P6        = 0x1.430912f86c7876f4b663b23c5fe5p-13L;

static const double
    P7        = 0x1.ffcbfc588b041p-17,
    P8        = 0x1.62c0223a5c7c7p-20,
    P9        = 0x1.b52541ff59713p-24,
    P10       = 0x1.e4cf56a391e22p-28,
    redux     = 0x1.8p112 / TBLSIZE;

static const long double tbl[TBLSIZE] = {
	0x1.6a09e667f3bcc908b2fb1366dfeap-1L,
	0x1.6c012750bdabeed76a99800f4edep-1L,
	0x1.6dfb23c651a2ef220e2cbe1bc0d4p-1L,
	0x1.6ff7df9519483cf87e1b4f3e1e98p-1L,
	0x1.71f75e8ec5f73dd2370f2ef0b148p-1L,
	0x1.73f9a48a58173bd5c9a4e68ab074p-1L,
	0x1.75feb564267c8bf6e9aa33a489a8p-1L,
	0x1.780694fde5d3f619ae02808592a4p-1L,
	0x1.7a11473eb0186d7d51023f6ccb1ap-1L,
	0x1.7c1ed0130c1327c49334459378dep-1L,
	0x1.7e2f336cf4e62105d02ba1579756p-1L,
	0x1.80427543e1a11b60de67649a3842p-1L,
	0x1.82589994cce128acf88afab34928p-1L,
	0x1.8471a4623c7acce52f6b97c6444cp-1L,
	0x1.868d99b4492ec80e41d90ac2556ap-1L,
	0x1.88ac7d98a669966530bcdf2d4cc0p-1L,
	0x1.8ace5422aa0db5ba7c55a192c648p-1L,
	0x1.8cf3216b5448bef2aa1cd161c57ap-1L,
	0x1.8f1ae991577362b982745c72eddap-1L,
	0x1.9145b0b91ffc588a61b469f6b6a0p-1L,
	0x1.93737b0cdc5e4f4501c3f2540ae8p-1L,
	0x1.95a44cbc8520ee9b483695a0e7fep-1L,
	0x1.97d829fde4e4f8b9e920f91e8eb6p-1L,
	0x1.9a0f170ca07b9ba3109b8c467844p-1L,
	0x1.9c49182a3f0901c7c46b071f28dep-1L,
	0x1.9e86319e323231824ca78e64c462p-1L,
	0x1.a0c667b5de564b29ada8b8cabbacp-1L,
	0x1.a309bec4a2d3358c171f770db1f4p-1L,
	0x1.a5503b23e255c8b424491caf88ccp-1L,
	0x1.a799e1330b3586f2dfb2b158f31ep-1L,
	0x1.a9e6b5579fdbf43eb243bdff53a2p-1L,
	0x1.ac36bbfd3f379c0db966a3126988p-1L,
	0x1.ae89f995ad3ad5e8734d17731c80p-1L,
	0x1.b0e07298db66590842acdfc6fb4ep-1L,
	0x1.b33a2b84f15faf6bfd0e7bd941b0p-1L,
	0x1.b59728de559398e3881111648738p-1L,
	0x1.b7f76f2fb5e46eaa7b081ab53ff6p-1L,
	0x1.ba5b030a10649840cb3c6af5b74cp-1L,
	0x1.bcc1e904bc1d2247ba0f45b3d06cp-1L,
	0x1.bf2c25bd71e088408d7025190cd0p-1L,
	0x1.c199bdd85529c2220cb12a0916bap-1L,
	0x1.c40ab5fffd07a6d14df820f17deap-1L,
	0x1.c67f12e57d14b4a2137fd20f2a26p-1L,
	0x1.c8f6d9406e7b511acbc48805c3f6p-1L,
	0x1.cb720dcef90691503cbd1e949d0ap-1L,
	0x1.cdf0b555dc3f9c44f8958fac4f12p-1L,
	0x1.d072d4a07897b8d0f22f21a13792p-1L,
	0x1.d2f87080d89f18ade123989ea50ep-1L,
	0x1.d5818dcfba48725da05aeb66dff8p-1L,
	0x1.d80e316c98397bb84f9d048807a0p-1L,
	0x1.da9e603db3285708c01a5b6d480cp-1L,
	0x1.dd321f301b4604b695de3c0630c0p-1L,
	0x1.dfc97337b9b5eb968cac39ed284cp-1L,
	0x1.e264614f5a128a12761fa17adc74p-1L,
	0x1.e502ee78b3ff6273d130153992d0p-1L,
	0x1.e7a51fbc74c834b548b2832378a4p-1L,
	0x1.ea4afa2a490d9858f73a18f5dab4p-1L,
	0x1.ecf482d8e67f08db0312fb949d50p-1L,
	0x1.efa1bee615a27771fd21a92dabb6p-1L,
	0x1.f252b376bba974e8696fc3638f24p-1L,
	0x1.f50765b6e4540674f84b762861a6p-1L,
	0x1.f7bfdad9cbe138913b4bfe72bd78p-1L,
	0x1.fa7c1819e90d82e90a7e74b26360p-1L,
	0x1.fd3c22b8f71f10975ba4b32bd006p-1L,
	0x1.0000000000000000000000000000p+0L,
	0x1.0163da9fb33356d84a66ae336e98p+0L,
	0x1.02c9a3e778060ee6f7caca4f7a18p+0L,
	0x1.04315e86e7f84bd738f9a20da442p+0L,
	0x1.059b0d31585743ae7c548eb68c6ap+0L,
	0x1.0706b29ddf6ddc6dc403a9d87b1ep+0L,
	0x1.0874518759bc808c35f25d942856p+0L,
	0x1.09e3ecac6f3834521e060c584d5cp+0L,
	0x1.0b5586cf9890f6298b92b7184200p+0L,
	0x1.0cc922b7247f7407b705b893dbdep+0L,
	0x1.0e3ec32d3d1a2020742e4f8af794p+0L,
	0x1.0fb66affed31af232091dd8a169ep+0L,
	0x1.11301d0125b50a4ebbf1aed9321cp+0L,
	0x1.12abdc06c31cbfb92bad324d6f84p+0L,
	0x1.1429aaea92ddfb34101943b2588ep+0L,
	0x1.15a98c8a58e512480d573dd562aep+0L,
	0x1.172b83c7d517adcdf7c8c50eb162p+0L,
	0x1.18af9388c8de9bbbf70b9a3c269cp+0L,
	0x1.1a35beb6fcb753cb698f692d2038p+0L,
	0x1.1bbe084045cd39ab1e72b442810ep+0L,
	0x1.1d4873168b9aa7805b8028990be8p+0L,
	0x1.1ed5022fcd91cb8819ff61121fbep+0L,
	0x1.2063b88628cd63b8eeb0295093f6p+0L,
	0x1.21f49917ddc962552fd29294bc20p+0L,
	0x1.2387a6e75623866c1fadb1c159c0p+0L,
	0x1.251ce4fb2a63f3582ab7de9e9562p+0L,
	0x1.26b4565e27cdd257a673281d3068p+0L,
	0x1.284dfe1f5638096cf15cf03c9fa0p+0L,
	0x1.29e9df51fdee12c25d15f5a25022p+0L,
	0x1.2b87fd0dad98ffddea46538fca24p+0L,
	0x1.2d285a6e4030b40091d536d0733ep+0L,
	0x1.2ecafa93e2f5611ca0f45d5239a4p+0L,
	0x1.306fe0a31b7152de8d5a463063bep+0L,
	0x1.32170fc4cd8313539cf1c3009330p+0L,
	0x1.33c08b26416ff4c9c8610d96680ep+0L,
	0x1.356c55f929ff0c94623476373be4p+0L,
	0x1.371a7373aa9caa7145502f45452ap+0L,
	0x1.38cae6d05d86585a9cb0d9bed530p+0L,
	0x1.3a7db34e59ff6ea1bc9299e0a1fep+0L,
	0x1.3c32dc313a8e484001f228b58cf0p+0L,
	0x1.3dea64c12342235b41223e13d7eep+0L,
	0x1.3fa4504ac801ba0bf701aa417b9cp+0L,
	0x1.4160a21f72e29f84325b8f3dbacap+0L,
	0x1.431f5d950a896dc704439410b628p+0L,
	0x1.44e086061892d03136f409df0724p+0L,
	0x1.46a41ed1d005772512f459229f0ap+0L,
	0x1.486a2b5c13cd013c1a3b69062f26p+0L,
	0x1.4a32af0d7d3de672d8bcf46f99b4p+0L,
	0x1.4bfdad5362a271d4397afec42e36p+0L,
	0x1.4dcb299fddd0d63b36ef1a9e19dep+0L,
	0x1.4f9b2769d2ca6ad33d8b69aa0b8cp+0L,
	0x1.516daa2cf6641c112f52c84d6066p+0L,
	0x1.5342b569d4f81df0a83c49d86bf4p+0L,
	0x1.551a4ca5d920ec52ec620243540cp+0L,
	0x1.56f4736b527da66ecb004764e61ep+0L,
	0x1.58d12d497c7fd252bc2b7343d554p+0L,
	0x1.5ab07dd48542958c93015191e9a8p+0L,
	0x1.5c9268a5946b701c4b1b81697ed4p+0L,
	0x1.5e76f15ad21486e9be4c20399d12p+0L,
	0x1.605e1b976dc08b076f592a487066p+0L,
	0x1.6247eb03a5584b1f0fa06fd2d9eap+0L,
	0x1.6434634ccc31fc76f8714c4ee122p+0L,
	0x1.66238825522249127d9e29b92ea2p+0L,
	0x1.68155d44ca973081c57227b9f69ep+0L,
};

static const float eps[TBLSIZE] = {
	-0x1.5c50p-101,
	-0x1.5d00p-106,
	 0x1.8e90p-102,
	-0x1.5340p-103,
	 0x1.1bd0p-102,
	-0x1.4600p-105,
	-0x1.7a40p-104,
	 0x1.d590p-102,
	-0x1.d590p-101,
	 0x1.b100p-103,
	-0x1.0d80p-105,
	 0x1.6b00p-103,
	-0x1.9f00p-105,
	 0x1.c400p-103,
	 0x1.e120p-103,
	-0x1.c100p-104,
	-0x1.9d20p-103,
	 0x1.a800p-108,
	 0x1.4c00p-106,
	-0x1.9500p-106,
	 0x1.6900p-105,
	-0x1.29d0p-100,
	 0x1.4c60p-103,
	 0x1.13a0p-102,
	-0x1.5b60p-103,
	-0x1.1c40p-103,
	 0x1.db80p-102,
	 0x1.91a0p-102,
	 0x1.dc00p-105,
	 0x1.44c0p-104,
	 0x1.9710p-102,
	 0x1.8760p-103,
	-0x1.a720p-103,
	 0x1.ed20p-103,
	-0x1.49c0p-102,
	-0x1.e000p-111,
	 0x1.86a0p-103,
	 0x1.2b40p-103,
	-0x1.b400p-108,
	 0x1.1280p-99,
	-0x1.02d8p-102,
	-0x1.e3d0p-103,
	-0x1.b080p-105,
	-0x1.f100p-107,
	-0x1.16c0p-105,
	-0x1.1190p-103,
	-0x1.a7d2p-100,
	 0x1.3450p-103,
	-0x1.67c0p-105,
	 0x1.4b80p-104,
	-0x1.c4e0p-103,
	 0x1.6000p-108,
	-0x1.3f60p-105,
	 0x1.93f0p-104,
	 0x1.5fe0p-105,
	 0x1.6f80p-107,
	-0x1.7600p-106,
	 0x1.21e0p-106,
	-0x1.3a40p-106,
	-0x1.40c0p-104,
	-0x1.9860p-105,
	-0x1.5d40p-108,
	-0x1.1d70p-106,
	 0x1.2760p-105,
	 0x0.0000p+0,
	 0x1.21e2p-104,
	-0x1.9520p-108,
	-0x1.5720p-106,
	-0x1.4810p-106,
	-0x1.be00p-109,
	 0x1.0080p-105,
	-0x1.5780p-108,
	-0x1.d460p-105,
	-0x1.6140p-105,
	 0x1.4630p-104,
	 0x1.ad50p-103,
	 0x1.82e0p-105,
	 0x1.1d3cp-101,
	 0x1.6100p-107,
	 0x1.ec30p-104,
	 0x1.f200p-108,
	 0x1.0b40p-103,
	 0x1.3660p-102,
	 0x1.d9d0p-103,
	-0x1.02d0p-102,
	 0x1.b070p-103,
	 0x1.b9c0p-104,
	-0x1.01c0p-103,
	-0x1.dfe0p-103,
	 0x1.1b60p-104,
	-0x1.ae94p-101,
	-0x1.3340p-104,
	 0x1.b3d8p-102,
	-0x1.6e40p-105,
	-0x1.3670p-103,
	 0x1.c140p-104,
	 0x1.1840p-101,
	 0x1.1ab0p-102,
	-0x1.a400p-104,
	 0x1.1f00p-104,
	-0x1.7180p-103,
	 0x1.4ce0p-102,
	 0x1.9200p-107,
	-0x1.54c0p-103,
	 0x1.1b80p-105,
	-0x1.1828p-101,
	 0x1.5720p-102,
	-0x1.a060p-100,
	 0x1.9160p-102,
	 0x1.a280p-104,
	 0x1.3400p-107,
	 0x1.2b20p-102,
	 0x1.7800p-108,
	 0x1.cfd0p-101,
	 0x1.2ef0p-102,
	-0x1.2760p-99,
	 0x1.b380p-104,
	 0x1.0048p-101,
	-0x1.60b0p-102,
	 0x1.a1ccp-100,
	-0x1.a640p-104,
	-0x1.08a0p-101,
	 0x1.7e60p-102,
	 0x1.22c0p-103,
	-0x1.7200p-106,
	 0x1.f0f0p-102,
	 0x1.eb4ep-99,
	 0x1.c6e0p-103,
};

/*
 * exp2l(x): compute the base 2 exponential of x
 *
 * Accuracy: Peak error < 0.502 ulp.
 *
 * Method: (accurate tables)
 *
 *   Reduce x:
 *     x = 2**k + y, for integer k and |y| <= 1/2.
 *     Thus we have exp2(x) = 2**k * exp2(y).
 *
 *   Reduce y:
 *     y = i/TBLSIZE + z - eps[i] for integer i near y * TBLSIZE.
 *     Thus we have exp2(y) = exp2(i/TBLSIZE) * exp2(z - eps[i]),
 *     with |z - eps[i]| <= 2**-8 + 2**-98 for the table used.
 *
 *   We compute exp2(i/TBLSIZE) via table lookup and exp2(z - eps[i]) via
 *   a degree-10 minimax polynomial with maximum error under 2**-120.
 *   The values in exp2t[] and eps[] are chosen such that
 *   exp2t[i] = exp2(i/TBLSIZE + eps[i]), and eps[i] is a small offset such
 *   that exp2t[i] is accurate to 2**-122.
 *
 *   Note that the range of i is +-TBLSIZE/2, so we actually index the tables
 *   by i0 = i + TBLSIZE/2.
 *
 *   This method is due to Gal, with many details due to Gal and Bachelis:
 *
 *	Gal, S. and Bachelis, B.  An Accurate Elementary Mathematical Library
 *	for the IEEE Floating Point Standard.  TOMS 17(1), 26-46 (1991).
 */
long double
exp2l(long double x)
{
	union IEEEl2bits u, v;
	long double r, t, twopk, twopkp10000, z;
	uint32_t hx, ix, i0;
	int k;

	u.e = x;

	/* Filter out exceptional cases. */
	hx = u.xbits.expsign;
	ix = hx & EXPMASK;
	if (ix >= BIAS + 14) {		/* |x| >= 16384 */
		if (ix == BIAS + LDBL_MAX_EXP) {
			if (u.xbits.manh != 0
			    || u.xbits.manl != 0
			    || (hx & 0x8000) == 0)
				return (x + x);	/* x is NaN or +Inf */
			else 
				return (0.0);	/* x is -Inf */
		}
		if (x >= 16384)
			return (huge * huge); /* overflow */
		if (x <= -16495)
			return (twom10000 * twom10000); /* underflow */
	} else if (ix <= BIAS - 115) {		/* |x| < 0x1p-115 */
		return (1.0 + x);
	}

	/*
	 * Reduce x, computing z, i0, and k. The low bits of x + redux
	 * contain the 16-bit integer part of the exponent (k) followed by
	 * TBLBITS fractional bits (i0). We use bit tricks to extract these
	 * as integers, then set z to the remainder.
	 *
	 * Example: Suppose x is 0xabc.123456p0 and TBLBITS is 8.
	 * Then the low-order word of x + redux is 0x000abc12,
	 * We split this into k = 0xabc and i0 = 0x12 (adjusted to
	 * index into the table), then we compute z = 0x0.003456p0.
	 *
	 * XXX If the exponent is negative, the computation of k depends on
	 *     '>>' doing sign extension.
	 */
	u.e = x + redux;
	i0 = (u.bits.manl & 0xffffffff) + TBLSIZE / 2;
	k = (int)i0 >> TBLBITS;
	i0 = i0 & (TBLSIZE - 1);
	u.e -= redux;
	z = x - u.e;
	v.xbits.manh = 0;
	v.xbits.manl = 0;
	if (k >= LDBL_MIN_EXP) {
		v.xbits.expsign = LDBL_MAX_EXP - 1 + k;
		twopk = v.e;
	} else {
		v.xbits.expsign = LDBL_MAX_EXP - 1 + k + 10000;
		twopkp10000 = v.e;
	}

	/* Compute r = exp2(y) = exp2t[i0] * p(z - eps[i]). */
	t = tbl[i0];		/* exp2t[i0] */
	z -= eps[i0];		/* eps[i0]   */
	r = t + t * z * (P1 + z * (P2 + z * (P3 + z * (P4 + z * (P5 + z * (P6
	    + z * (P7 + z * (P8 + z * (P9 + z * P10)))))))));

	/* Scale by 2**k. */
	if(k >= LDBL_MIN_EXP) {
		if (k == LDBL_MAX_EXP)
			return (r * 2.0 * 0x1p16383L);
		return (r * twopk);
	} else {
		return (r * twopkp10000 * twom10000);
	}
}
```