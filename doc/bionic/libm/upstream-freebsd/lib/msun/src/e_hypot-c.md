Response:
Let's break down the thought process for analyzing this `e_hypot.c` file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the `hypot` function in Android's Bionic library. This includes:

* **Functionality:** What does `hypot(x, y)` do?
* **Android Relevance:** How does this relate to the Android ecosystem?
* **Implementation Details:** How is the function implemented within `e_hypot.c`?
* **Dynamic Linker (Indirectly):** How does the dynamic linker play a role in making this function available?
* **Logic & Assumptions:** What are the underlying assumptions and how does the code handle different inputs?
* **Common Errors:** How might developers misuse this function?
* **Tracing:** How does a call to `hypot` in an Android app reach this specific code?

**2. Initial Code Scan and High-Level Understanding:**

First, I'd read the comments at the beginning of the file. These are crucial for understanding the author's intent and the mathematical principles behind the implementation. Key takeaways from the comments:

* **Purpose:** Calculates the hypotenuse (`sqrt(x^2 + y^2)`).
* **Accuracy:** Aims for less than 1 ulp error.
* **Method:** Uses different calculation methods based on the relative magnitudes of `x` and `y` to maintain accuracy and avoid overflow/underflow. The specific formulas are mentioned.
* **Special Cases:** Handles infinities and NaNs.
* **Scaling:** Mentions the need for scaling to deal with very large or very small numbers.

**3. Deeper Dive into the Code:**

Now, I'd go through the code section by section:

* **Includes:**  `float.h`, `math.h`, `math_private.h`. These provide necessary definitions and declarations.
* **Function Signature:** `double hypot(double x, double y)`. Takes two doubles and returns a double.
* **Magnitude Comparison:** The code starts by comparing the magnitudes of `x` and `y` and swapping them if necessary to ensure `a >= b`. This simplifies the subsequent logic.
* **Absolute Values:** Takes the absolute values of `a` and `b`. The hypotenuse is always non-negative.
* **Large Magnitude Optimization:** `if((ha-hb)>0x3c00000) {return a+b;}`. This checks if one number is significantly larger than the other. In such cases, the smaller number's contribution to the hypotenuse is negligible, so it returns `a + b` (approximately `a`). This avoids unnecessary computations and potential overflow.
* **Scaling for Large Numbers:** The `if(ha > 0x5f300000)` block handles very large numbers. It scales them down to prevent overflow during the intermediate `x*x` and `y*y` calculations. It also handles the special cases of infinity and NaN. The `fabsl(x+0.0L)-fabs(y+0)` trick is a way to check for NaN while quieting potential signaling NaNs.
* **Scaling for Small Numbers:** The `if(hb < 0x20b00000)` block handles very small numbers. It scales them up to prevent underflow and loss of precision.
* **Core Calculation Logic:** The `if (w>b)` and `else` blocks implement the specific formulas mentioned in the comments, chosen based on the relative magnitudes of `a` and `b`. The bit manipulation using `SET_HIGH_WORD` is used to isolate parts of the floating-point representation for accurate calculations.
* **Scaling Back:** The `if(k!=0)` block applies the reverse scaling to get the final result in the correct magnitude.
* **Weak Reference:** `#if LDBL_MANT_DIG == 53 ... __weak_reference(hypot, hypotl);` creates a weak alias for the `long double` version if `long double` has the same precision as `double`.

**4. Connecting to Android:**

At this stage, I would start thinking about how this low-level function relates to the Android framework and NDK.

* **NDK:**  C/C++ developers using the NDK can directly call `hypot` from `math.h`.
* **Android Framework:** Higher-level Java code in the Android framework might indirectly use `hypot`. For example, calculations involving distances, vector magnitudes, or graphics transformations might eventually call down to this native implementation.

**5. Dynamic Linker Considerations:**

The dynamic linker part requires understanding how shared libraries are loaded and symbols are resolved.

* **Shared Object (SO) Layout:** I would visualize a typical SO layout with sections like `.text`, `.data`, `.bss`, `.dynsym`, `.dynstr`, `.plt`, `.got`.
* **Symbol Resolution:** Explain the difference between global and local symbols, how the dynamic linker finds symbols using symbol tables (`.dynsym`, `.dynstr`), and the role of the PLT and GOT in lazy symbol resolution.

**6. Identifying Assumptions and Edge Cases:**

This involves thinking about what could go wrong or what assumptions the code makes.

* **Floating-Point Representation:** The code relies on the IEEE 754 standard for floating-point numbers.
* **Rounding Mode:** The initial comment mentions "round-to-nearest." While the code tries to be accurate regardless, certain optimizations might assume this default rounding mode.
* **Input Ranges:**  Consider what happens with very large, very small, and special values (infinity, NaN). The code explicitly handles these, which is important to note.

**7. Tracing the Execution Path:**

To illustrate how a call reaches `e_hypot.c`, I would outline the steps from an Android app to the native library.

* **Java Call:**  Start with a Java method call (e.g., in `android.graphics.PointF`).
* **JNI Transition:** Explain how the Java Native Interface (JNI) is used to call native code.
* **NDK Library:** The native code calls `hypot` from `<cmath>` or `math.h`.
* **Dynamic Linking:** The dynamic linker resolves the `hypot` symbol to the implementation in `libm.so`.

**8. Refining and Structuring the Answer:**

Finally, I would organize the information logically, using headings, bullet points, code snippets, and examples to make the explanation clear and comprehensive. I'd review the answer to ensure it addresses all aspects of the original request. For example, explicitly mentioning the assumptions about IEEE 754 and the "round-to-nearest" mode is important for completeness. Similarly, providing concrete examples for common errors and the SO layout makes the explanation more practical.
好的，让我们详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_hypot.c` 这个文件。

**1. 功能列举**

`e_hypot.c` 文件实现了 `hypot(x, y)` 函数。这个函数的功能是计算直角三角形的斜边长度，给定两条直角边的长度 `x` 和 `y`。数学公式表示为：

```
hypot(x, y) = sqrt(x² + y²)
```

简而言之，它的功能是：**计算两个数的平方和的平方根。**

**2. 与 Android 功能的关系及举例**

`hypot` 函数是标准 C 库（libc）的一部分，而 Bionic 是 Android 系统的 libc 实现。因此，`hypot` 函数在 Android 系统中被广泛使用。以下是一些与 Android 功能相关的例子：

* **图形和动画:** 在 Android 的图形渲染（如 Canvas API、OpenGL ES）和动画系统中，经常需要计算两点之间的距离。这可以使用 `hypot` 函数来实现。例如，计算一个触摸事件距离某个 UI 元素的距离。

   ```c++
   // NDK 代码示例
   #include <cmath>
   #include <android/log.h>

   void onTouch(float touchX, float touchY, float elementX, float elementY) {
       float distance = hypot(touchX - elementX, touchY - elementY);
       __android_log_print(ANDROID_LOG_INFO, "MyApp", "Distance: %f", distance);
   }
   ```

* **传感器数据处理:** 处理加速度计、陀螺仪等传感器数据时，可能需要计算向量的模长，这本质上也是计算平方和的平方根。

   ```c++
   // NDK 代码示例
   #include <cmath>

   struct Vector3 {
       float x, y, z;
   };

   float vectorMagnitude(Vector3 v) {
       return hypot(hypot(v.x, v.y), v.z); // 或者更高效的实现
   }
   ```

* **地理位置计算:** 在地图应用或定位服务中，计算两个地理坐标之间的欧氏距离（在小范围内近似）可以使用 `hypot` 函数。

* **物理引擎:** 游戏开发或模拟应用中，物理引擎经常需要计算距离、速度的模等，`hypot` 函数可以用于这些计算。

**3. libc 函数 `hypot` 的实现细节**

`e_hypot.c` 中的代码采取了一些技巧来提高精度和处理特殊情况，避免溢出或下溢。以下是对代码逻辑的详细解释：

* **头文件包含:**
    * `<float.h>`: 定义了浮点数类型的特性，如最大值、最小值等。
    * `"math.h"`: 声明了标准数学函数，包括 `hypot` 的声明。
    * `"math_private.h"`: 定义了 Bionic 内部使用的数学相关的宏和结构。

* **函数签名:**
    ```c
    double hypot(double x, double y)
    ```
    接收两个 `double` 类型的参数 `x` 和 `y`，返回一个 `double` 类型的结果。

* **处理参数顺序和绝对值:**
    ```c
    GET_HIGH_WORD(ha,x);
    ha &= 0x7fffffff;
    GET_HIGH_WORD(hb,y);
    hb &= 0x7fffffff;
    if(hb > ha) {a=y;b=x;j=ha; ha=hb;hb=j;} else {a=x;b=y;}
    a = fabs(a);
    b = fabs(b);
    ```
    这段代码首先获取 `x` 和 `y` 的高位字（用于比较大小），然后取绝对值。并确保 `a` 是绝对值较大的那个数，`b` 是绝对值较小的那个数，这有助于后续的计算优化。

* **快速处理极端情况:**
    ```c
    if((ha-hb)>0x3c00000) {return a+b;} /* x/y > 2**60 */
    ```
    如果 `a` 比 `b` 大很多（大约 2 的 60 次方倍），那么 `b²` 相对于 `a²` 可以忽略不计，直接返回 `a + b` 是一个很好的近似，并且避免了不必要的平方运算。

* **处理大数值溢出:**
    ```c
    k=0;
    if(ha > 0x5f300000) {	/* a>2**500 */
       if(ha >= 0x7ff00000) {	/* Inf or NaN */
           // ... 处理无穷大和 NaN
       }
       /* scale a and b by 2**-600 */
       ha -= 0x25800000; hb -= 0x25800000;	k += 600;
       SET_HIGH_WORD(a,ha);
       SET_HIGH_WORD(b,hb);
    }
    ```
    如果 `a` 非常大（大于 2 的 500 次方），直接计算 `a²` 和 `b²` 可能会导致溢出。这里的处理方法是将 `a` 和 `b` 都缩小一个因子（2 的 600 次方），记录下缩小的倍数 `k`，然后在最后将结果放大回来。对于无穷大和 NaN，会进行特殊处理。

* **处理小数值下溢:**
    ```c
    if(hb < 0x20b00000) {	/* b < 2**-500 */
        if(hb <= 0x000fffff) {	/* subnormal b or 0 */
            // ... 处理次正规数和 0
        } else {		/* scale a and b by 2^600 */
            // ... 将 a 和 b 放大
        }
    }
    ```
    如果 `b` 非常小（小于 2 的 -500 次方），直接计算 `b²` 可能会导致下溢，损失精度。这里的处理方法是将 `a` 和 `b` 都放大一个因子，记录下放大的倍数 `k`，然后在最后将结果缩小回来。对于次正规数和 0 会进行特殊处理。

* **核心计算逻辑:**
    ```c
    /* medium size a and b */
    w = a-b;
    if (w>b) {
        t1 = 0;
        SET_HIGH_WORD(t1,ha);
        t2 = a-t1;
        w  = sqrt(t1*t1-(b*(-b)-t2*(a+t1)));
    } else {
        a  = a+a;
        y1 = 0;
        SET_HIGH_WORD(y1,hb);
        y2 = b - y1;
        t1 = 0;
        SET_HIGH_WORD(t1,ha+0x00100000);
        t2 = a - t1;
        w  = sqrt(t1*y1-(w*(-w)-(t1*y2+t2*b)));
    }
    ```
    对于中等大小的 `a` 和 `b`，代码使用了两种不同的计算公式，旨在减少舍入误差，保持精度。这些公式是通过巧妙的代数变换得到的，目的是避免直接计算 `a² + b²` 可能带来的精度问题。代码中使用了 `SET_HIGH_WORD` 宏来操作浮点数的位表示，这是一种低级别的优化手段。

* **反向缩放:**
    ```c
    if(k!=0) {
        t1 = 0.0;
        SET_HIGH_WORD(t1,(1023+k)<<20);
        return t1*w;
    } else return w;
    ```
    如果之前进行了缩放，这里将计算结果乘以相应的因子，恢复到原始的数量级。

* **弱引用:**
    ```c
    #if LDBL_MANT_DIG == 53
    __weak_reference(hypot, hypotl);
    #endif
    ```
    这部分代码是针对 `long double` 类型的。如果 `long double` 的有效位数（`LDBL_MANT_DIG`）是 53（与 `double` 相同），则创建一个 `hypotl` 的弱引用，指向 `hypot` 函数。这意味着在没有提供 `hypotl` 的特定实现时，会使用 `hypot` 的实现。

**4. Dynamic Linker 的功能和符号处理**

Dynamic Linker（在 Android 中主要是 `linker` 或 `ld-android.so`）负责在程序运行时加载共享库（`.so` 文件）并将程序代码中使用的符号（如函数名）链接到共享库中对应的实现。

**SO 布局样本:**

一个典型的 Android `.so` 文件（如 `libm.so`）的布局可能包含以下主要部分：

```
ELF Header:
  ...
Program Headers:
  LOAD segment (可执行代码和只读数据)
  LOAD segment (可读写数据)
  DYNAMIC segment (动态链接信息)
Section Headers:
  .text (代码段)
  .rodata (只读数据)
  .data (已初始化的可读写数据)
  .bss (未初始化的可读写数据)
  .symtab (符号表)
  .strtab (字符串表)
  .dynsym (动态符号表)
  .dynstr (动态字符串表)
  .plt (过程链接表)
  .got (全局偏移表)
  ...
```

**符号处理过程:**

1. **编译和链接:** 当一个使用 `hypot` 函数的程序（例如，一个 NDK 应用）被编译和链接时，编译器会在其目标文件中记录下对 `hypot` 函数的外部引用。链接器会将这些引用标记为需要动态链接。

2. **加载时:** 当 Android 系统启动程序时，dynamic linker 会被加载并开始工作。

3. **加载共享库:** 当程序执行到需要调用 `hypot` 函数的代码时，如果 `libm.so` 尚未加载，dynamic linker 会找到并加载 `libm.so` 到内存中。

4. **符号查找:** dynamic linker 会查看 `libm.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，以找到 `hypot` 符号的地址。

5. **重定位:**
   * **PLT (Procedure Linkage Table):**  对于函数调用，通常会使用 PLT 和 GOT (Global Offset Table) 进行延迟绑定。程序最初调用 `hypot` 时，会跳转到 PLT 中的一个桩（stub）函数。
   * **GOT (Global Offset Table):** PLT 桩函数会检查 GOT 中 `hypot` 对应的条目是否已经被解析。如果未解析，PLT 桩函数会调用 dynamic linker 的解析函数。
   * **解析:** dynamic linker 根据符号名在已加载的共享库中查找 `hypot` 的实际地址，并将该地址写入 GOT 中对应的条目。
   * **后续调用:**  之后对 `hypot` 的调用会直接通过 GOT 跳转到 `hypot` 的实际地址，避免了重复解析。

6. **执行:** 一旦 `hypot` 的地址被解析，程序就可以跳转到 `libm.so` 中 `e_hypot.c` 实现的 `hypot` 函数执行。

**示例:**

假设你的 NDK 代码中调用了 `hypot(3.0, 4.0)`。

* **编译时:** 编译器生成对 `hypot` 的外部引用。
* **加载时:** `linker` 加载你的应用的 `.apk` 中的 native library (`.so` 文件) 和依赖的 `libm.so`。
* **符号查找和重定位:** 当首次执行到 `hypot(3.0, 4.0)` 的调用时，`linker` 会找到 `libm.so` 中的 `hypot` 函数地址，并更新 GOT。
* **执行:** 程序跳转到 `libm.so` 中 `hypot` 函数的代码执行，计算结果 5.0。

**5. 逻辑推理、假设输入与输出**

假设输入：`x = 3.0`, `y = 4.0`

* `a = 4.0`, `b = 3.0`
* `ha` 和 `hb` 的值会根据浮点数表示确定，但在此例中不会触发大数值或小数值的特殊处理。
* `w = a - b = 4.0 - 3.0 = 1.0`
* `w > b` 为假 (1.0 不大于 3.0)，进入 `else` 分支。
* `a = a + a = 8.0`
* `y1` 的高位被设置为 `hb`，`y2 = b - y1` 会提取 `b` 的低位部分。
* `t1` 的高位被设置为 `ha + 0x00100000`，相当于将 `a` 向上取整到下一个整数。
* `t2 = a - t1` 计算 `a` 的小数部分。
* `w` 的计算涉及到平方根和一些乘法、加法操作，最终结果应接近 `sqrt(4.0² + 3.0²) = sqrt(16 + 9) = sqrt(25) = 5.0`。

输出：接近 `5.0` 的 `double` 类型数值。

假设输入：`x = 1e300`, `y = 1e300`

* `a = 1e300`, `b = 1e300`
* `ha` 会非常大，触发大数值处理的 `if(ha > 0x5f300000)` 分支。
* `a` 和 `b` 会被缩小，`k` 会增加。
* 中间的计算会在缩小的数值上进行，避免溢出。
* 最后，结果会乘以缩放因子，得到接近 `sqrt((1e300)² + (1e300)²) = sqrt(2 * 1e600) = sqrt(2) * 1e300` 的值。

输出：接近 `1.41421356... * 1e300` 的 `double` 类型数值。

**6. 用户或编程常见的使用错误**

* **参数类型错误:**  传递非 `double` 类型的参数，虽然可能隐式转换，但可能导致精度损失或意外行为。
* **溢出/下溢的假设:**  程序员可能假设 `hypot` 函数总能返回一个有效的结果，而忽略了输入值过大或过小可能导致的结果（如无穷大）。
* **性能考虑不周:** 在循环中频繁调用 `hypot`，尤其是在性能敏感的应用中，可能成为瓶颈。可以考虑是否有优化的方法，例如在某些特定情况下可以避免平方根的计算。
* **误解精度:**  `hypot` 旨在提供高精度的结果，但浮点运算本身存在精度限制。程序员不应期望绝对精确的结果。

**示例错误:**

```c++
// 错误示例：假设结果总是有限的
#include <cmath>
#include <iostream>

int main() {
    double x = 1e308;
    double y = 1e308;
    double h = hypot(x, y);
    if (h < 1e300) { // 错误的假设
        std::cout << "Result is small" << std::endl;
    } else {
        std::cout << "Result is large: " << h << std::endl; // 实际输出为 inf
    }
    return 0;
}
```

**7. Android Framework 或 NDK 如何到达这里**

作为调试线索，以下是从 Android Framework 或 NDK 到达 `e_hypot.c` 的步骤：

1. **Android Framework (Java 代码):**
   * 例如，`android.graphics.PointF` 类有 `distance(PointF other)` 方法，内部会计算两点之间的距离，可能使用 `Math.hypot()`。
   * `android.opengl.Matrix` 或其他图形相关的类在进行矩阵运算或向量计算时可能间接使用到 `hypot`。

2. **调用 `Math.hypot()` (Java):**
   * `java.lang.Math.hypot(double a, double b)` 是一个 native 方法。

3. **JNI 调用:**
   * 当 Java 代码调用 `Math.hypot()` 时，会通过 Java Native Interface (JNI) 跳转到相应的 native 实现。

4. **`libjavacrypto.so` 或其他 Framework Native 库:**
   * `Math.hypot()` 的 native 实现可能在 `libjavacrypto.so` 或其他 Framework 提供的 native 库中。

5. **`libm.so` 的符号引用:**
   * Framework 的 native 代码最终会调用标准的 C 库函数 `hypot`。

6. **Dynamic Linker 解析:**
   * 当程序执行到调用 `hypot` 的代码时，dynamic linker 会将 `hypot` 符号解析到 `libm.so` 中 `e_hypot.c` 编译生成的代码。

7. **NDK (C/C++ 代码):**
   * NDK 应用可以直接包含 `<cmath>` 或 `math.h` 并调用 `hypot` 函数。

8. **编译链接:**
   * NDK 代码编译时，链接器会将对 `hypot` 的引用指向 `libm.so`。

9. **运行时链接:**
   * 在 Android 设备上运行 NDK 应用时，dynamic linker 会加载 `libm.so`，并将 NDK 应用中对 `hypot` 的调用链接到 `libm.so` 中 `e_hypot.c` 的实现。

**调试线索:**

* **Java 代码:** 可以通过 IDE 的断点调试或日志输出，追踪 `Math.hypot()` 的调用。
* **JNI 调用:** 使用 `adb logcat` 查找与 JNI 相关的日志，或者使用 Systrace 等工具分析系统调用。
* **Native 代码 (NDK):** 使用 GDB 或 LLDB 连接到 Android 设备上的进程进行调试，在 `hypot` 函数入口处设置断点。
* **查看 `libm.so`:** 可以使用 `adb pull` 将设备上的 `libm.so` 下载到本地，使用 `readelf` 等工具查看其符号表。

总而言之，`e_hypot.c` 是 Android 系统中一个基础但至关重要的数学函数实现，它被广泛应用于各种需要计算距离或模的应用场景中。其实现考虑了精度、性能以及各种特殊情况，体现了底层库开发的严谨性。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_hypot.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

/* hypot(x,y)
 *
 * Method :                  
 *	If (assume round-to-nearest) z=x*x+y*y 
 *	has error less than sqrt(2)/2 ulp, than 
 *	sqrt(z) has error less than 1 ulp (exercise).
 *
 *	So, compute sqrt(x*x+y*y) with some care as 
 *	follows to get the error below 1 ulp:
 *
 *	Assume x>y>0;
 *	(if possible, set rounding to round-to-nearest)
 *	1. if x > 2y  use
 *		x1*x1+(y*y+(x2*(x+x1))) for x*x+y*y
 *	where x1 = x with lower 32 bits cleared, x2 = x-x1; else
 *	2. if x <= 2y use
 *		t1*y1+((x-y)*(x-y)+(t1*y2+t2*y))
 *	where t1 = 2x with lower 32 bits cleared, t2 = 2x-t1, 
 *	y1= y with lower 32 bits chopped, y2 = y-y1.
 *		
 *	NOTE: scaling may be necessary if some argument is too 
 *	      large or too tiny
 *
 * Special cases:
 *	hypot(x,y) is INF if x or y is +INF or -INF; else
 *	hypot(x,y) is NAN if x or y is NAN.
 *
 * Accuracy:
 * 	hypot(x,y) returns sqrt(x^2+y^2) with error less 
 * 	than 1 ulps (units in the last place) 
 */

#include <float.h>

#include "math.h"
#include "math_private.h"

double
hypot(double x, double y)
{
	double a,b,t1,t2,y1,y2,w;
	int32_t j,k,ha,hb;

	GET_HIGH_WORD(ha,x);
	ha &= 0x7fffffff;
	GET_HIGH_WORD(hb,y);
	hb &= 0x7fffffff;
	if(hb > ha) {a=y;b=x;j=ha; ha=hb;hb=j;} else {a=x;b=y;}
	a = fabs(a);
	b = fabs(b);
	if((ha-hb)>0x3c00000) {return a+b;} /* x/y > 2**60 */
	k=0;
	if(ha > 0x5f300000) {	/* a>2**500 */
	   if(ha >= 0x7ff00000) {	/* Inf or NaN */
	       u_int32_t low;
	       /* Use original arg order iff result is NaN; quieten sNaNs. */
	       w = fabsl(x+0.0L)-fabs(y+0);
	       GET_LOW_WORD(low,a);
	       if(((ha&0xfffff)|low)==0) w = a;
	       GET_LOW_WORD(low,b);
	       if(((hb^0x7ff00000)|low)==0) w = b;
	       return w;
	   }
	   /* scale a and b by 2**-600 */
	   ha -= 0x25800000; hb -= 0x25800000;	k += 600;
	   SET_HIGH_WORD(a,ha);
	   SET_HIGH_WORD(b,hb);
	}
	if(hb < 0x20b00000) {	/* b < 2**-500 */
	    if(hb <= 0x000fffff) {	/* subnormal b or 0 */
	        u_int32_t low;
		GET_LOW_WORD(low,b);
		if((hb|low)==0) return a;
		t1=0;
		SET_HIGH_WORD(t1,0x7fd00000);	/* t1=2^1022 */
		b *= t1;
		a *= t1;
		k -= 1022;
	    } else {		/* scale a and b by 2^600 */
	        ha += 0x25800000; 	/* a *= 2^600 */
		hb += 0x25800000;	/* b *= 2^600 */
		k -= 600;
		SET_HIGH_WORD(a,ha);
		SET_HIGH_WORD(b,hb);
	    }
	}
    /* medium size a and b */
	w = a-b;
	if (w>b) {
	    t1 = 0;
	    SET_HIGH_WORD(t1,ha);
	    t2 = a-t1;
	    w  = sqrt(t1*t1-(b*(-b)-t2*(a+t1)));
	} else {
	    a  = a+a;
	    y1 = 0;
	    SET_HIGH_WORD(y1,hb);
	    y2 = b - y1;
	    t1 = 0;
	    SET_HIGH_WORD(t1,ha+0x00100000);
	    t2 = a - t1;
	    w  = sqrt(t1*y1-(w*(-w)-(t1*y2+t2*b)));
	}
	if(k!=0) {
	    t1 = 0.0;
	    SET_HIGH_WORD(t1,(1023+k)<<20);
	    return t1*w;
	} else return w;
}

#if LDBL_MANT_DIG == 53
__weak_reference(hypot, hypotl);
#endif
```