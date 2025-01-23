Response:
Let's break down the thought process for analyzing the `e_jn.c` file. The goal is to answer the user's complex, multi-faceted request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this specific C file within the Android Bionic library. They're asking for:

* **Functionality:** What does the code *do*?
* **Android Relevance:** How does it relate to Android?
* **Implementation Details:** How are the `libc` functions implemented within?
* **Dynamic Linking:**  How does it interact with the dynamic linker (if at all)?
* **Logical Reasoning:**  What are example inputs and outputs?
* **Common Mistakes:** What are typical errors when using these functions?
* **Android Integration:** How does Android framework/NDK lead to this code?
* **Debugging:**  How can we use Frida to debug this?

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to:

* **Comments:** The initial copyright notice and the comments explaining the `jn` and `yn` functions are very helpful.
* **Function Names:** `jn(int n, double x)` and `yn(int n, double x)` clearly suggest Bessel functions.
* **Include Headers:** `math.h` and `math_private.h` indicate math-related operations.
* **Constants:** The defined constants like `invsqrtpi`, `two`, `one`, `zero` are clues about the mathematical nature of the code.
* **Special Cases:** The comments about special cases (y0(0), yn(n,0), etc.) provide insights into edge cases.
* **Control Flow:** The `if/else` statements reveal different execution paths based on the input values of `n` and `x`.
* **Helper Functions:** The calls to `j0(x)`, `j1(x)`, and `sincos(x, &s, &c)` suggest dependencies on other math functions.
* **Macros:** The use of `EXTRACT_WORDS` and `GET_HIGH_WORD` hints at low-level bit manipulation, likely for handling floating-point representations.

**3. Deciphering the Functionality (jn and yn):**

Based on the comments and function names, it's clear that this code implements Bessel functions of the first kind (`jn`) and second kind (`yn`). The comments also explain the core algorithms used:

* **Forward Recursion:** For `jn` when `n < x`.
* **Continued Fraction and Backward Recursion:** For `jn` when `n > x`.
* **Forward Recursion:** For `yn` for `n > 1`.

**4. Connecting to Android:**

The file path `bionic/libm/upstream-freebsd/lib/msun/src/e_jn.c` immediately tells us this is part of Android's math library (`libm`) in Bionic. This means:

* **Core System Library:** These functions are fundamental for mathematical operations within Android.
* **NDK Usage:**  Developers using the NDK can directly call these functions.
* **Framework Dependence:**  Higher-level Android frameworks might rely on these functions indirectly for various calculations (graphics, physics, etc.).

**5. Explaining `libc` Functions:**

The main "libc functions" *implemented* in this file are `jn` and `yn`. The explanation should cover:

* **Purpose:** Calculating Bessel functions.
* **Parameters:** Order `n` and value `x`.
* **Return Value:** The calculated Bessel function value.
* **Implementation Details:**  Summarize the different algorithms used (forward/backward recursion, continued fractions) based on the comments.
* **Special Case Handling:** Briefly mention how special cases like NaN, infinity, and zero are handled.

**6. Addressing Dynamic Linking:**

Careful examination of the code reveals **no direct interaction with the dynamic linker**. There are no calls to functions like `dlopen`, `dlsym`, etc. The linking happens at a higher level when `libm.so` is built and loaded. Therefore, the explanation should emphasize this point and provide a general overview of how shared libraries work in Android, along with a typical `libm.so` layout.

**7. Providing Logical Reasoning (Examples):**

This involves creating simple test cases with expected outputs. Think about:

* **Basic Cases:** `jn(0, 1.0)`, `yn(1, 0.5)`.
* **Edge Cases:** `jn(5, 0.1)` (where `n > x`), `yn(0, 0.0)` (a special case).
* **Negative Inputs:** `jn(-2, 1.0)`.

**8. Identifying Common Usage Errors:**

Think about common mistakes developers might make when using Bessel functions:

* **Incorrect Order:**  Using a non-integer order (though the function takes an `int`).
* **Domain Errors:**  Providing negative values to `yn` (as noted in the comments).
* **Performance Considerations:**  Not being aware of the computational cost for large `n`.
* **Numerical Stability:**  Potential issues with precision for very large or very small values.

**9. Tracing Android Framework/NDK Calls:**

This requires a conceptual understanding of how Android works:

* **NDK:** The most direct path. Native code can call `jn` and `yn` directly from `<math.h>`.
* **Framework:**  Framework components (e.g., graphics, physics) might use these functions internally. It's difficult to pinpoint exact call chains without specific framework code. The explanation should focus on *possible* indirect usage.

**10. Creating Frida Hooks:**

The Frida examples should demonstrate how to intercept calls to `jn` and `yn` at the native level. This involves:

* **Attaching to a Process:**  Targeting an app that uses these functions (directly or indirectly).
* **Intercepting Functions:** Using `Interceptor.attach` to hook the `jn` and `yn` symbols in `libm.so`.
* **Logging Arguments and Return Values:**  Showing how to access and print the input arguments (`n`, `x`) and the returned value.

**11. Structuring the Response:**

Finally, organize the information logically with clear headings and explanations for each part of the user's request. Use code blocks for examples and Frida snippets. Maintain a clear and concise writing style.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus heavily on the low-level floating-point manipulation. **Correction:**  While important, prioritize the higher-level functionality and algorithms first, then touch on the bit manipulation.
* **Initial thought:** Try to find concrete examples of framework calls. **Correction:**  Acknowledge the difficulty and focus on the conceptual possibilities.
* **Initial thought:** Provide overly complex Frida examples. **Correction:** Keep the Frida examples simple and focused on the core task of interception.

By following this structured thought process, breaking down the complex request into smaller, manageable parts, and iterating on the explanations, a comprehensive and accurate answer can be generated.
好的，我们来详细分析 `bionic/libm/upstream-freebsd/lib/msun/src/e_jn.c` 这个文件。

**文件功能概览**

该文件实现了计算第一类贝塞尔函数 `jn(n, x)` 和第二类贝塞尔函数 `yn(n, x)` 的浮点数版本。 贝塞尔函数是在物理学和工程学中经常遇到的特殊函数，特别是在处理具有圆柱对称性的问题时，例如波的传播、热传导等。

**与 Android 功能的关系**

这个文件是 Android 系统库 `libm` 的一部分。`libm` 提供了标准的 C 语言数学函数，供 Android 系统以及应用程序使用。

* **Android Framework:** Android Framework 的某些组件，例如处理图形渲染、音频处理、传感器数据等，在底层可能会依赖数学计算，间接地使用到 `libm` 中的贝塞尔函数。例如，在音频处理中，可能需要使用贝塞尔函数来分析或合成声音。
* **Android NDK:** 使用 Android NDK（Native Development Kit）开发的应用程序可以直接调用 `libm` 提供的数学函数，包括 `jn` 和 `yn`。例如，一个游戏引擎或者物理模拟程序可能会使用贝塞尔函数进行更精确的计算。

**libc 函数的功能实现**

该文件实现了两个主要的 libc 函数：

1. **`double jn(int n, double x)`：计算第一类贝塞尔函数 J<sub>n</sub>(x)。**

   * **特殊情况处理：**
     * 如果 `x` 是 NaN（非数字），则返回 NaN。
     * 如果 `n` 是负数，利用 J<sub>-n</sub>(x) = (-1)<sup>n</sup> * J<sub>n</sub>(x) 的性质进行转换。
     * 如果 `n` 是 0 或 1，则直接调用 `j0(x)` 或 `j1(x)`，这两个函数通常在其他文件中实现，分别计算 J<sub>0</sub>(x) 和 J<sub>1</sub>(x)。
     * 如果 `x` 是 0 或无穷大，则 `jn` 的值为 0。

   * **计算方法：**
     * **当 |n| ≤ x 时（小阶数或大自变量）：** 使用前向递归公式：J<sub>n+1</sub>(x) = (2n/x) * J<sub>n</sub>(x) - J<sub>n-1</sub>(x)。 从 J<sub>0</sub>(x) 和 J<sub>1</sub>(x) 的值开始递推计算。对于非常大的 `x`，使用渐近展开式  J<sub>n</sub>(x) ≈ cos(x - (2n+1)π/4) * √(2/(πx)) 来近似计算，提高效率。
     * **当 |n| > x 时（大阶数或小自变量）：** 使用连分式逼近和后向递归。
       * 首先，评估 J<sub>n</sub>(x)/J<sub>n-1</sub>(x) 的连分式近似值。
       * 然后，假设一个 J<sub>n</sub>(x) 的值，并使用后向递归公式计算 J<sub>0</sub>(x) 或 J<sub>1</sub>(x)。
       * 将计算得到的 J<sub>0</sub>(x) 或 J<sub>1</sub>(x) 与实际值进行比较，以校正假设的 J<sub>n</sub>(x) 值。
       * 对于非常小的 `x`，使用泰勒展开式的首项 J<sub>n</sub>(x) ≈ (x/2)<sup>n</sup> / n! 来近似计算。

2. **`double yn(int n, double x)`：计算第二类贝塞尔函数 Y<sub>n</sub>(x)。**

   * **特殊情况处理：**
     * 如果 `x` 是 NaN，则返回 NaN。
     * 如果 `x` 是 +0，则返回 -Infinity 并触发除零异常。
     * 如果 `x` 是负数，则返回 NaN 并触发无效操作异常。
     * 如果 `n` 是负数，利用 Y<sub>-n</sub>(x) = (-1)<sup>n</sup> * Y<sub>n</sub>(x) 的性质进行转换。
     * 如果 `n` 是 0 或 1，则直接调用 `y0(x)` 或 `y1(x)`，这两个函数通常在其他文件中实现，分别计算 Y<sub>0</sub>(x) 和 Y<sub>1</sub>(x)。
     * 如果 `x` 是无穷大，则 `yn` 的值为 0。

   * **计算方法：**
     * **当 n ≥ 1 时：** 使用前向递归公式：Y<sub>n+1</sub>(x) = (2n/x) * Y<sub>n</sub>(x) - Y<sub>n-1</sub>(x)。 从 Y<sub>0</sub>(x) 和 Y<sub>1</sub>(x) 的值开始递推计算。
     * **对于非常大的 `x`：** 使用渐近展开式 Y<sub>n</sub>(x) ≈ sin(x - (2n+1)π/4) * √(2/(πx)) 来近似计算。

**动态链接功能**

这个 `e_jn.c` 文件本身并不直接涉及动态链接的功能。动态链接是由 Android 的动态链接器 `linker` 负责的。当应用程序启动或者需要使用共享库时，`linker` 会将所需的共享库加载到进程的地址空间，并解析符号引用，将函数调用指向正确的内存地址。

**`libm.so` 布局样本：**

```
libm.so:
    ...
    .text:  // 代码段
        ...
        jn:     // jn 函数的机器码
            ...
        yn:     // yn 函数的机器码
            ...
        j0:     // j0 函数的机器码 (可能在其他文件中实现)
            ...
        y0:     // y0 函数的机器码 (可能在其他文件中实现)
            ...
    .data:  // 数据段 (例如，全局变量和常量)
        invsqrtpi: 0x3FE20DD750429B6D
        two:       0x4000000000000000
        ...
    .symtab: // 符号表 (包含函数名和地址等信息)
        ...
        jn
        yn
        j0
        y0
        ...
    .dynsym: // 动态符号表
        ...
        jn
        yn
        ...
```

**链接的处理过程：**

1. **加载共享库：** 当应用程序需要使用 `libm.so` 中的函数时，动态链接器会将 `libm.so` 加载到进程的地址空间。
2. **符号查找：** 当应用程序调用 `jn` 或 `yn` 函数时，链接器会根据符号表（`.symtab` 或 `.dynsym`）查找这些符号对应的内存地址。
3. **重定位：** 如果代码中使用了全局变量或调用了其他共享库的函数，链接器会进行重定位，将这些引用指向正确的地址。
4. **绑定：** 最终，函数调用指令会被绑定到 `jn` 或 `yn` 函数在内存中的实际地址。

**逻辑推理：假设输入与输出**

* **假设输入：`jn(2, 1.0)`**
   * 根据贝塞尔函数的计算方法，`jn(2, 1.0)` 的值应该接近 `0.11490348199565608`。
* **假设输入：`yn(0, 0.5)`**
   * 由于 `yn(0, x)` 对应 Y<sub>0</sub>(x)，对于 `x = 0.5`，其值应该接近 `(2/π) * (γ + ln(0.5/2))`，其中 γ 是欧拉-马斯刻罗尼常数。计算结果约为 `0.08825696421567773`。
* **假设输入：`jn(-1, 2.0)`**
   * 根据 J<sub>-n</sub>(x) = (-1)<sup>n</sup> * J<sub>n</sub>(x)，`jn(-1, 2.0)` = (-1)<sup>-1</sup> * `jn(1, 2.0)` = -`jn(1, 2.0)`，其值应该接近 `-0.5767248077558533`。
* **假设输入：`yn(1, -1.0)`**
   * 根据特殊情况处理，`yn` 的第二个参数为负数时会返回 NaN。

**用户或编程常见的使用错误**

1. **参数类型错误：** 虽然函数签名指定了 `int n` 和 `double x`，但如果传递了错误的类型，编译器可能会进行隐式转换，导致意外的结果或精度损失。
2. **`yn` 的自变量为负数或零：**  如前所述，`yn(n, x)` 当 `x <= 0` 时是未定义的，会导致 NaN 或 -Infinity 的结果，并且可能触发异常。
3. **阶数 `n` 的选择不当：**  对于某些应用，可能需要计算高阶的贝塞尔函数。选择不合适的 `n` 值可能导致计算量过大或结果不准确。
4. **忽略特殊情况：** 没有正确处理 `x` 为 0 或无穷大的情况，可能会导致程序崩溃或得到错误的结果。
5. **精度问题：** 浮点数计算 inherently 有精度限制。对于某些极端情况，例如非常大的 `x` 或 `n`，可能需要考虑数值稳定性问题。

**Android Framework 或 NDK 如何一步步到达这里**

**Android NDK 场景：**

1. **NDK 代码调用：** C/C++ 代码使用 NDK 开发，包含了 `<math.h>` 头文件，并调用了 `jn(n, x)` 或 `yn(n, x)` 函数。
   ```c++
   #include <cmath>
   #include <iostream>

   int main() {
       int n = 2;
       double x = 1.5;
       double j_result = std::jn(n, x);
       double y_result = std::yn(n, x);
       std::cout << "jn(" << n << ", " << x << ") = " << j_result << std::endl;
       std::cout << "yn(" << n << ", " << x << ") = " << y_result << std::endl;
       return 0;
   }
   ```
2. **编译链接：** NDK 工具链中的编译器（例如，`clang++`）会将 C/C++ 代码编译成机器码，链接器会将对 `jn` 和 `yn` 的调用链接到 `libm.so` 中对应的符号。
3. **运行时加载：** 当 Android 应用程序运行时，动态链接器会加载 `libm.so`。
4. **函数调用：** 当执行到调用 `jn` 或 `yn` 的代码时，程序会跳转到 `libm.so` 中 `e_jn.c` 文件编译生成的对应函数地址执行。

**Android Framework 场景（较为间接）：**

1. **Framework 组件调用：** Android Framework 的某个组件（例如，负责音频处理的 AudioFlinger 服务）在实现其功能时，可能需要进行一些数学计算。
2. **调用 Framework 提供的 API：** 该组件可能会调用 Android Framework 提供的更高级的 API，而这些 API 的底层实现可能间接使用了 `libm` 中的数学函数。
3. **Framework 内部调用：** Framework 的代码最终会调用到 Bionic 库中的数学函数，包括 `jn` 或 `yn`。例如，某个图形渲染算法可能需要计算贝塞尔函数来模拟某种光线效果。

**Frida Hook 示例调试步骤**

假设我们有一个 Android 应用程序（包名为 `com.example.app`），它在 Native 代码中调用了 `jn` 函数。我们可以使用 Frida 来 Hook 这个函数调用。

1. **准备 Frida 环境：**
   * 确保你的电脑上安装了 Frida 和 Python。
   * 确保你的 Android 设备已 Root，并且安装了 `frida-server`。

2. **编写 Frida Hook 脚本（例如 `hook_jn.js`）：**
   ```javascript
   if (Java.available) {
       Java.perform(function () {
           const libm = Process.getModuleByName("libm.so");
           const jnPtr = libm.getExportByName("jn");

           if (jnPtr) {
               Interceptor.attach(jnPtr, {
                   onEnter: function (args) {
                       const n = args[0].toInt32();
                       const x = args[1].toDouble();
                       console.log("Called jn with n =", n, "and x =", x);
                   },
                   onLeave: function (retval) {
                       const result = retval.toDouble();
                       console.log("jn returned:", result);
                   }
               });
               console.log("Successfully hooked jn in libm.so");
           } else {
               console.log("Failed to find jn in libm.so");
           }
       });
   } else {
       console.log("Java is not available.");
   }
   ```

3. **运行 Frida 脚本：**
   打开终端，使用以下命令运行 Frida 脚本：
   ```bash
   frida -U -f com.example.app -l hook_jn.js --no-pause
   ```
   * `-U`: 连接 USB 设备。
   * `-f com.example.app`: 启动并附加到 `com.example.app` 进程。
   * `-l hook_jn.js`: 加载并执行 `hook_jn.js` 脚本。
   * `--no-pause`: 立即执行，不暂停程序启动。

4. **查看输出：**
   当目标应用程序调用 `jn` 函数时，Frida 会拦截该调用，并打印出传递给 `jn` 的参数 `n` 和 `x`，以及 `jn` 函数的返回值。

**Hook `yn` 函数的脚本类似：**

```javascript
if (Java.available) {
    Java.perform(function () {
        const libm = Process.getModuleByName("libm.so");
        const ynPtr = libm.getExportByName("yn");

        if (ynPtr) {
            Interceptor.attach(ynPtr, {
                onEnter: function (args) {
                    const n = args[0].toInt32();
                    const x = args[1].toDouble();
                    console.log("Called yn with n =", n, "and x =", x);
                },
                onLeave: function (retval) {
                    const result = retval.toDouble();
                    console.log("yn returned:", result);
                }
            });
            console.log("Successfully hooked yn in libm.so");
        } else {
            console.log("Failed to find yn in libm.so");
        }
    });
} else {
    console.log("Java is not available.");
}
```

通过这种方式，你可以动态地观察 `jn` 和 `yn` 函数的调用情况，这对于理解 Android 系统或应用程序如何使用这些数学函数非常有帮助。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_jn.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * jn(n, x), yn(n, x)
 * floating point Bessel's function of the 1st and 2nd kind
 * of order n
 *
 * Special cases:
 *	y0(0)=y1(0)=yn(n,0) = -inf with division by zero signal;
 *	y0(-ve)=y1(-ve)=yn(n,-ve) are NaN with invalid signal.
 * Note 2. About jn(n,x), yn(n,x)
 *	For n=0, j0(x) is called.
 *	For n=1, j1(x) is called.
 *	For n<x, forward recursion is used starting
 *	from values of j0(x) and j1(x).
 *	For n>x, a continued fraction approximation to
 *	j(n,x)/j(n-1,x) is evaluated and then backward
 *	recursion is used starting from a supposed value
 *	for j(n,x). The resulting values of j(0,x) or j(1,x) are
 *	compared with the actual values to correct the
 *	supposed value of j(n,x).
 *
 *	yn(n,x) is similar in all respects, except
 *	that forward recursion is used for all
 *	values of n>1.
 */

#include "math.h"
#include "math_private.h"

static const volatile double vone = 1, vzero = 0;

static const double
invsqrtpi=  5.64189583547756279280e-01, /* 0x3FE20DD7, 0x50429B6D */
two   =  2.00000000000000000000e+00, /* 0x40000000, 0x00000000 */
one   =  1.00000000000000000000e+00; /* 0x3FF00000, 0x00000000 */

static const double zero  =  0.00000000000000000000e+00;

double
jn(int n, double x)
{
	int32_t i,hx,ix,lx, sgn;
	double a, b, c, s, temp, di;
	double z, w;

    /* J(-n,x) = (-1)^n * J(n, x), J(n, -x) = (-1)^n * J(n, x)
     * Thus, J(-n,x) = J(n,-x)
     */
	EXTRACT_WORDS(hx,lx,x);
	ix = 0x7fffffff&hx;
    /* if J(n,NaN) is NaN */
	if((ix|((u_int32_t)(lx|-lx))>>31)>0x7ff00000) return x+x;
	if(n<0){
		n = -n;
		x = -x;
		hx ^= 0x80000000;
	}
	if(n==0) return(j0(x));
	if(n==1) return(j1(x));
	sgn = (n&1)&(hx>>31);	/* even n -- 0, odd n -- sign(x) */
	x = fabs(x);
	if((ix|lx)==0||ix>=0x7ff00000) 	/* if x is 0 or inf */
	    b = zero;
	else if((double)n<=x) {
		/* Safe to use J(n+1,x)=2n/x *J(n,x)-J(n-1,x) */
	    if(ix>=0x52D00000) { /* x > 2**302 */
    /* (x >> n**2)
     *	    Jn(x) = cos(x-(2n+1)*pi/4)*sqrt(2/x*pi)
     *	    Yn(x) = sin(x-(2n+1)*pi/4)*sqrt(2/x*pi)
     *	    Let s=sin(x), c=cos(x),
     *		xn=x-(2n+1)*pi/4, sqt2 = sqrt(2), then
     *
     *		   n	sin(xn)*sqt2	cos(xn)*sqt2
     *		----------------------------------
     *		   0	 s-c		 c+s
     *		   1	-s-c 		-c+s
     *		   2	-s+c		-c-s
     *		   3	 s+c		 c-s
     */
		sincos(x, &s, &c);
		switch(n&3) {
		    case 0: temp =  c+s; break;
		    case 1: temp = -c+s; break;
		    case 2: temp = -c-s; break;
		    case 3: temp =  c-s; break;
		}
		b = invsqrtpi*temp/sqrt(x);
	    } else {
	        a = j0(x);
	        b = j1(x);
	        for(i=1;i<n;i++){
		    temp = b;
		    b = b*((double)(i+i)/x) - a; /* avoid underflow */
		    a = temp;
	        }
	    }
	} else {
	    if(ix<0x3e100000) {	/* x < 2**-29 */
    /* x is tiny, return the first Taylor expansion of J(n,x)
     * J(n,x) = 1/n!*(x/2)^n  - ...
     */
		if(n>33)	/* underflow */
		    b = zero;
		else {
		    temp = x*0.5; b = temp;
		    for (a=one,i=2;i<=n;i++) {
			a *= (double)i;		/* a = n! */
			b *= temp;		/* b = (x/2)^n */
		    }
		    b = b/a;
		}
	    } else {
		/* use backward recurrence */
		/* 			x      x^2      x^2
		 *  J(n,x)/J(n-1,x) =  ----   ------   ------   .....
		 *			2n  - 2(n+1) - 2(n+2)
		 *
		 * 			1      1        1
		 *  (for large x)   =  ----  ------   ------   .....
		 *			2n   2(n+1)   2(n+2)
		 *			-- - ------ - ------ -
		 *			 x     x         x
		 *
		 * Let w = 2n/x and h=2/x, then the above quotient
		 * is equal to the continued fraction:
		 *		    1
		 *	= -----------------------
		 *		       1
		 *	   w - -----------------
		 *			  1
		 * 	        w+h - ---------
		 *		       w+2h - ...
		 *
		 * To determine how many terms needed, let
		 * Q(0) = w, Q(1) = w(w+h) - 1,
		 * Q(k) = (w+k*h)*Q(k-1) - Q(k-2),
		 * When Q(k) > 1e4	good for single
		 * When Q(k) > 1e9	good for double
		 * When Q(k) > 1e17	good for quadruple
		 */
	    /* determine k */
		double t,v;
		double q0,q1,h,tmp; int32_t k,m;
		w  = (n+n)/(double)x; h = 2.0/(double)x;
		q0 = w;  z = w+h; q1 = w*z - 1.0; k=1;
		while(q1<1.0e9) {
			k += 1; z += h;
			tmp = z*q1 - q0;
			q0 = q1;
			q1 = tmp;
		}
		m = n+n;
		for(t=zero, i = 2*(n+k); i>=m; i -= 2) t = one/(i/x-t);
		a = t;
		b = one;
		/*  estimate log((2/x)^n*n!) = n*log(2/x)+n*ln(n)
		 *  Hence, if n*(log(2n/x)) > ...
		 *  single 8.8722839355e+01
		 *  double 7.09782712893383973096e+02
		 *  long double 1.1356523406294143949491931077970765006170e+04
		 *  then recurrent value may overflow and the result is
		 *  likely underflow to zero
		 */
		tmp = n;
		v = two/x;
		tmp = tmp*log(fabs(v*tmp));
		if(tmp<7.09782712893383973096e+02) {
	    	    for(i=n-1,di=(double)(i+i);i>0;i--){
		        temp = b;
			b *= di;
			b  = b/x - a;
		        a = temp;
			di -= two;
	     	    }
		} else {
	    	    for(i=n-1,di=(double)(i+i);i>0;i--){
		        temp = b;
			b *= di;
			b  = b/x - a;
		        a = temp;
			di -= two;
		    /* scale b to avoid spurious overflow */
			if(b>1e100) {
			    a /= b;
			    t /= b;
			    b  = one;
			}
	     	    }
		}
		z = j0(x);
		w = j1(x);
		if (fabs(z) >= fabs(w))
		    b = (t*z/b);
		else
		    b = (t*w/a);
	    }
	}
	if(sgn==1) return -b; else return b;
}

double
yn(int n, double x)
{
	int32_t i,hx,ix,lx;
	int32_t sign;
	double a, b, c, s, temp;

	EXTRACT_WORDS(hx,lx,x);
	ix = 0x7fffffff&hx;
	/* yn(n,NaN) = NaN */
	if((ix|((u_int32_t)(lx|-lx))>>31)>0x7ff00000) return x+x;
	/* yn(n,+-0) = -inf and raise divide-by-zero exception. */
	if((ix|lx)==0) return -one/vzero;
	/* yn(n,x<0) = NaN and raise invalid exception. */
	if(hx<0) return vzero/vzero;
	sign = 1;
	if(n<0){
		n = -n;
		sign = 1 - ((n&1)<<1);
	}
	if(n==0) return(y0(x));
	if(n==1) return(sign*y1(x));
	if(ix==0x7ff00000) return zero;
	if(ix>=0x52D00000) { /* x > 2**302 */
    /* (x >> n**2)
     *	    Jn(x) = cos(x-(2n+1)*pi/4)*sqrt(2/x*pi)
     *	    Yn(x) = sin(x-(2n+1)*pi/4)*sqrt(2/x*pi)
     *	    Let s=sin(x), c=cos(x),
     *		xn=x-(2n+1)*pi/4, sqt2 = sqrt(2), then
     *
     *		   n	sin(xn)*sqt2	cos(xn)*sqt2
     *		----------------------------------
     *		   0	 s-c		 c+s
     *		   1	-s-c 		-c+s
     *		   2	-s+c		-c-s
     *		   3	 s+c		 c-s
     */
		sincos(x, &s, &c);
		switch(n&3) {
		    case 0: temp =  s-c; break;
		    case 1: temp = -s-c; break;
		    case 2: temp = -s+c; break;
		    case 3: temp =  s+c; break;
		}
		b = invsqrtpi*temp/sqrt(x);
	} else {
	    u_int32_t high;
	    a = y0(x);
	    b = y1(x);
	/* quit if b is -inf */
	    GET_HIGH_WORD(high,b);
	    for(i=1;i<n&&high!=0xfff00000;i++){
		temp = b;
		b = ((double)(i+i)/x)*b - a;
		GET_HIGH_WORD(high,b);
		a = temp;
	    }
	}
	if(sign>0) return b; else return -b;
}
```