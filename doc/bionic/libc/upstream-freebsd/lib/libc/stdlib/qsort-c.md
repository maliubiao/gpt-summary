Response:
Let's break down the thought process for generating the detailed explanation of `qsort.c`.

**1. Understanding the Core Request:**

The fundamental request is to analyze the provided C source code for `qsort.c` from Android's Bionic library. The analysis should cover functionality, Android-specific relevance, implementation details, dynamic linking aspects, logical reasoning examples, common usage errors, and how the code is reached from higher levels (Android Framework/NDK). The response should be in Chinese and include Frida hook examples.

**2. Initial Code Scan and Function Identification:**

The first step is to read through the code to get a high-level understanding. Keywords like `qsort`, `swapfunc`, `med3`, `CMP`, and the various `#define` directives related to different `qsort` variants (`_r`, `_s`) immediately stand out. The presence of copyright information and BSD license is noted but less critical for functional analysis.

**3. Core Functionality Identification: Sorting**

The name `qsort` and the inclusion of "Bentley & McIlroy's 'Engineering a Sort Function'" clearly indicate that the primary function is **sorting**. The parameters `void *a`, `size_t n`, `size_t es`, and `cmp_t *cmp` confirm this: array pointer, number of elements, element size, and comparison function.

**4. Dissecting the Implementation Details (Top-Down):**

* **`qsort` Entry Points:**  The code has multiple entry points: `qsort`, `qsort_r`, `__qsort_r_compat`, and `qsort_s`. Understanding the differences is crucial. The `_r` variants take an extra `void *thunk` for passing context to the comparison function. The `_s` variant includes runtime size checks for security. It's important to distinguish between the public API functions and the internal `local_qsort` function.
* **`local_qsort`:** This is the core implementation. The code implements a **Quicksort algorithm**, but with optimizations.
* **Optimization Strategies:**  Identify the key optimizations:
    * **Insertion Sort for Small Arrays:** The `if (n < 7)` block switches to insertion sort for small subarrays, as it's more efficient in such cases.
    * **Median-of-Three Pivot Selection:**  The `med3` function helps choose a better pivot to avoid worst-case scenarios for Quicksort (already sorted or reverse-sorted data). The code even uses a more sophisticated median-of-three for larger arrays.
    * **Partitioning Logic:**  The `while (pb <= pc ...)` loop implements the partitioning process, moving elements smaller than the pivot to the left and larger elements to the right.
    * **Handling Equal Elements:** The `if (cmp_result == 0)` blocks efficiently handle elements equal to the pivot, grouping them in the middle.
    * **Iterative Approach for Larger Partitions:**  The code avoids deep recursion by using a `goto loop` to process the larger partition iteratively, saving stack space.
* **`swapfunc` and `vecswap`:** These are helper functions for efficient element swapping. `swapfunc` handles single element swaps, while `vecswap` handles swapping contiguous blocks.
* **`med3`:**  Analyze its logic for selecting the median of three elements using comparisons.
* **`CMP` Macro:**  Understand how the `CMP` macro adapts to the different `qsort` variants by incorporating or omitting the `thunk` argument.

**5. Android-Specific Relevance and Examples:**

Think about where sorting might be used in Android. Common scenarios include:

* **Sorting lists of applications:** In settings or app drawers.
* **Sorting contacts:** By name, phone number, etc.
* **Sorting files:** In file explorers.
* **Sorting network connections:**  By signal strength or other criteria.
* **Sorting data within applications:** Any app that needs to present ordered data.

For each scenario, connect it back to the usage of `qsort`. Imagine an Android component having an array of objects that needs to be sorted. The comparison function would need to extract the relevant field for comparison.

**6. Dynamic Linking:**

* **SO Layout:** Describe the typical structure of a shared object (`.so`) file in Android, including sections like `.text`, `.data`, `.bss`, `.dynsym`, `.dynstr`, `.plt`, `.got`.
* **Linking Process:** Explain how the dynamic linker (`linker64` or `linker`) resolves symbols at runtime, focusing on how `qsort` in `libc.so` becomes available to other processes. Mention the role of the Global Offset Table (GOT) and Procedure Linkage Table (PLT).

**7. Logical Reasoning Examples (Hypothetical Input/Output):**

Create simple examples to illustrate the sorting process. Use a small array of integers and a basic comparison function. Show the input and the expected sorted output.

**8. Common Usage Errors:**

Think about the pitfalls of using `qsort`:

* **Incorrect Comparison Function:** The comparison function *must* adhere to the specified contract (negative, zero, positive return values). Errors here are very common.
* **Incorrect Element Size:** Providing the wrong size to `es` can lead to memory corruption or incorrect sorting.
* **Modifying Elements During Comparison:** The comparison function should *not* modify the elements being compared.
* **Passing Null Pointers:**  The `qsort_s` variant helps mitigate this with runtime checks.

Provide code examples that demonstrate these errors.

**9. Android Framework/NDK Path and Frida Hooking:**

Trace the execution path from a high-level Android component down to `qsort`.

* **Android Framework:**  Start with a Java API call that implies sorting (e.g., `Collections.sort`). Explain how this can potentially lead to native code execution via JNI.
* **NDK:**  Show a simple NDK example where C/C++ code directly calls `qsort`.
* **Frida Hooking:**  Provide concrete Frida code snippets to hook the `qsort` function. Show how to log arguments and potentially modify behavior for debugging or analysis.

**10. Structure and Language (Chinese):**

Organize the information logically with clear headings and subheadings. Use precise and understandable Chinese. Translate technical terms accurately.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the Quicksort algorithm's intricacies.** I need to balance that with the other requirements of the prompt, especially the Android-specific aspects and the dynamic linking explanation.
* **I need to ensure the examples are clear and concise.**  Avoid overly complex scenarios that might obscure the point.
* **The Frida hook example needs to be practical and demonstrate key hooking concepts.**  Simply hooking the function might not be enough; logging arguments is crucial for understanding its use.
* **Double-check the Chinese translations of technical terms.** Ensure consistency and accuracy.

By following this structured thought process, addressing each part of the prompt systematically, and iteratively refining the explanation, a comprehensive and accurate answer can be generated.
好的，让我们详细分析一下 `bionic/libc/upstream-freebsd/lib/libc/stdlib/qsort.c` 这个文件。

**1. 功能概述**

这个 `qsort.c` 文件实现了标准 C 库中的 `qsort` 函数，用于对数组进行原地快速排序。它的主要功能是：

* **通用排序:** 能够对任意数据类型的数组进行排序。
* **自定义比较:** 允许用户提供一个比较函数，定义元素之间的顺序关系。
* **原地排序:**  排序过程直接在原数组上进行，不需要额外的存储空间（除了递归调用栈）。

**2. 与 Android 功能的关系及举例**

`qsort` 是一个基础的 C 库函数，在 Android 系统中被广泛使用。它在各种需要对数据进行排序的场景中发挥作用，例如：

* **系统服务:** Android 的某些系统服务可能需要对数据进行排序，例如，`ActivityManagerService` 可能需要对最近使用的应用进行排序。
* **应用程序框架:** Android 应用程序框架的某些组件可能会使用 `qsort` 对内部数据结构进行排序。例如，在处理联系人列表、文件列表或网络连接列表时。
* **NDK 开发:** 使用 Android NDK 进行原生开发的应用程序可以直接调用 `qsort` 函数来排序数据。

**举例说明 (NDK):**

假设你正在开发一个 Android NDK 应用，需要对一个整数数组进行排序：

```c
#include <stdlib.h>
#include <jni.h>

// 比较函数，用于比较两个整数
int compare_integers(const void *a, const void *b) {
  return (*(int *)a - *(int *)b);
}

jintArray Java_com_example_myapp_MainActivity_sortArray(JNIEnv *env, jobject thiz, jintArray input_array) {
  jsize length = (*env)->GetArrayLength(env, input_array);
  jint *elements = (*env)->GetIntArrayElements(env, input_array, NULL);

  // 使用 qsort 对数组进行排序
  qsort(elements, length, sizeof(jint), compare_integers);

  // 创建一个新的 jintArray 并返回
  jintArray result_array = (*env)->NewIntArray(env, length);
  (*env)->SetIntArrayRegion(env, result_array, 0, length, elements);

  (*env)->ReleaseIntArrayElements(env, input_array, elements, 0); // 释放资源

  return result_array;
}
```

在这个例子中，`qsort` 函数被用来排序从 Java 层传递下来的整型数组。`compare_integers` 函数定义了排序的规则（升序）。

**3. libc 函数的实现细节**

让我们详细解释 `qsort.c` 中关键函数的实现：

* **`qsort(void *a, size_t n, size_t es, cmp_t *cmp)` (或其变体 `qsort_r`, `qsort_s`)**

   这是 `qsort` 函数的入口点。它接收以下参数：
    * `a`: 指向要排序的数组的首地址。
    * `n`: 数组中元素的数量。
    * `es`: 每个元素的大小（以字节为单位）。
    * `cmp`: 指向比较函数的指针。比较函数接收两个指向元素的 `const void *` 指针，并返回：
        * 负值：如果第一个元素应排在第二个元素之前。
        * 零：如果两个元素相等。
        * 正值：如果第一个元素应排在第二个元素之后。
    * `thunk` (仅在 `qsort_r` 和 `qsort_s` 中)：一个用户提供的指针，可以传递给比较函数，用于传递额外的上下文信息。

   `qsort` 的实现采用的是**快速排序 (Quicksort)** 算法，这是一种分治算法：
    1. **选择枢轴 (Pivot):**  在数组中选择一个元素作为枢轴。这里使用了更复杂的选择策略，包括对小数组使用插入排序，以及对大数组使用 "median-of-three" 方法来选择更好的枢轴，以避免最坏情况的发生。
    2. **分区 (Partitioning):**  重新排列数组，使得所有小于枢轴的元素都放在枢轴的左边，所有大于枢轴的元素都放在枢轴的右边。相等的元素会被集中在枢轴附近。
    3. **递归排序:** 递归地对枢轴左边的子数组和右边的子数组进行排序。

   为了提高效率和避免无限递归，代码中做了以下优化：
    * **小数组使用插入排序:** 对于小于 7 个元素的数组，直接使用插入排序，因为它在小规模数据上更有效。
    * **尾递归优化 (通过迭代实现):**  在递归调用时，如果递归调用是函数的最后一个操作，可以通过循环迭代的方式来避免栈溢出。代码中通过 `goto loop` 实现了对较大分区的迭代处理。

* **`local_qsort(void *a, size_t n, size_t es, cmp_t *cmp, void *thunk)`**

   这是 `qsort` 的实际实现函数。为了避免在递归时发生抢占调用，它被声明为 `static`。不同的 `qsort` 变体通过宏定义 `local_qsort` 指向不同的内部实现，例如 `local_qsort_r`，`local_qsort_s`。

* **`swapfunc(char *a, char *b, size_t es)`**

   这是一个内联函数，用于交换两个指定大小的内存块（即数组中的两个元素）。它通过逐字节交换来实现。

* **`vecswap(char *a, char *b, n)`**

   这是一个宏定义，用于交换两个连续的内存块。它在 `n > 0` 的情况下调用 `swapfunc`。

* **`med3(char *a, char *b, char *c, cmp_t *cmp, void *thunk __unused)`**

   这是一个内联函数，用于从三个元素中选择中间值（中位数）。它用于改进快速排序的枢轴选择策略，以减少最坏情况发生的概率。`__unused` 宏表示 `thunk` 参数在这里可能不会被使用（对于非 `_r` 和 `_s` 版本）。

* **`CMP(t, x, y)` 宏**

   这是一个宏，用于调用比较函数。它根据 `qsort` 的不同变体（`_r`, `_s`）来传递正确的参数给比较函数。

**4. 涉及 dynamic linker 的功能**

`qsort` 函数本身并不直接涉及动态链接器的功能。它是一个普通的 C 库函数，编译后会包含在 `libc.so` 这个共享库中。当其他程序需要使用 `qsort` 时，动态链接器负责在运行时将程序与 `libc.so` 链接起来，使得程序能够找到并调用 `qsort` 函数。

**so 布局样本:**

`libc.so` 是一个共享对象文件，它包含各种 C 标准库函数。其内部布局大致如下：

```
libc.so:
    .text          # 包含可执行的代码，包括 qsort 的机器码
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .rodata        # 包含只读数据，例如字符串常量
    .dynsym        # 动态符号表，列出导出的符号（例如 qsort）和导入的符号
    .dynstr        # 动态字符串表，包含符号名称的字符串
    .plt           # Procedure Linkage Table，过程链接表，用于延迟绑定
    .got           # Global Offset Table，全局偏移表，用于存储全局变量和函数地址
    ... 其他段 ...
```

**链接的处理过程:**

1. **编译时:** 当程序编译时，编译器遇到 `qsort` 函数调用，会生成一个对 `qsort` 的外部符号引用。
2. **链接时:**  链接器将程序的目标文件与所需的共享库（例如 `libc.so`）链接在一起。链接器会记录程序对 `qsort` 的依赖。
3. **运行时:** 当程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载程序所需的共享库。
4. **符号解析:** 动态链接器会查找 `libc.so` 中的符号表 (`.dynsym`)，找到 `qsort` 的地址。
5. **GOT/PLT 更新:**  如果使用延迟绑定，第一次调用 `qsort` 时，会通过 PLT 跳转到动态链接器的解析代码。动态链接器找到 `qsort` 的实际地址后，会更新 GOT 中对应的条目，后续的 `qsort` 调用将直接通过 GOT 跳转到 `qsort` 的实现。

**5. 逻辑推理 (假设输入与输出)**

假设我们有一个包含以下整数的数组：`{5, 2, 9, 1, 5}`，我们想使用 `qsort` 对其进行升序排序。

**假设输入:**

* `a`: 指向数组 `{5, 2, 9, 1, 5}` 的指针。
* `n`: 数组长度，为 5。
* `es`: 每个元素的大小，为 `sizeof(int)`（假设为 4 字节）。
* `cmp`: 指向 `compare_integers` 函数的指针（见上面的 NDK 示例）。

**比较函数 `compare_integers` 的逻辑:**

* `compare_integers(5, 2)` 返回正数 (5 > 2)。
* `compare_integers(2, 9)` 返回负数 (2 < 9)。
* `compare_integers(5, 5)` 返回零 (5 == 5)。

**输出:**

经过 `qsort` 排序后，数组 `a` 中的元素顺序将变为：`{1, 2, 5, 5, 9}`。

**排序过程 (简化示意):**

快速排序的实际过程会进行多次分区和递归调用，以下是一个简化的步骤：

1. 选择一个枢轴（例如第一个元素 5）。
2. 将数组分区，小于 5 的放在左边，大于 5 的放在右边，等于 5 的放在中间。
3. 递归地对左右两个子数组进行排序。

**6. 用户或编程常见的使用错误**

* **错误的比较函数:** 这是最常见的错误。比较函数必须严格遵守其约定，即返回负数、零或正数。如果比较逻辑错误，会导致排序结果不正确或程序崩溃。
   ```c
   // 错误的比较函数，总是返回 1
   int bad_compare(const void *a, const void *b) {
       return 1;
   }

   int arr[] = {3, 1, 4, 1, 5, 9};
   qsort(arr, sizeof(arr) / sizeof(arr[0]), sizeof(int), bad_compare);
   // 结果是未定义的，可能不会排序，甚至可能崩溃。
   ```

* **错误的元素大小:** 如果传递给 `qsort` 的 `es` 参数不等于数组元素的实际大小，会导致内存访问错误或排序逻辑混乱。
   ```c
   int arr[] = {3, 1, 4, 1, 5, 9};
   qsort(arr, sizeof(arr) / sizeof(arr[0]), 1, compare_integers); // 错误：元素大小应该是 sizeof(int)
   // 可能会导致程序崩溃或得到错误的排序结果。
   ```

* **修改比较函数中的元素:** 比较函数应该只比较元素，而不应该修改它们。修改元素可能会导致排序逻辑出错。
   ```c
   int modify_compare(const void *a, const void *b) {
       *(int *)a = 0; // 错误：修改了元素
       return (*(int *)a - *(int *)b);
   }
   ```

* **传递 NULL 指针:**  如果传递给 `qsort` 的数组指针或比较函数指针是 `NULL`，会导致程序崩溃。`qsort_s` 提供了一些安全检查来避免这种情况。
   ```c
   int *arr = NULL;
   qsort(arr, 10, sizeof(int), compare_integers); // 错误：数组指针为 NULL
   ```

**7. Android Framework 或 NDK 如何到达这里，Frida Hook 示例**

**Android Framework 到 `qsort` 的路径 (示例，非常简化):**

1. **Java Framework:**  Android Framework 中的某个 Java 类（例如 `ArrayList`）调用了 `Collections.sort()` 方法。
2. **`Collections.sort()`:**  `Collections.sort()` 最终会调用实现了 `Comparator` 接口的对象的 `compare()` 方法。
3. **JNI 调用 (如果涉及原生排序):**  在某些情况下，为了性能或特定需求，Java 的排序操作可能会委托给 Native 代码实现。这会涉及 JNI (Java Native Interface) 调用。
4. **NDK 代码:**  Native 代码可能会使用标准 C 库函数，包括 `qsort`，来进行排序。

**NDK 到 `qsort` 的路径:**

NDK 代码可以直接调用 `qsort` 函数，就像上面 NDK 示例中所示。

**Frida Hook 示例:**

可以使用 Frida 来 hook `qsort` 函数，以便在运行时观察其参数和行为。以下是一个简单的 Frida 脚本示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const qsortPtr = Module.findExportByName(null, 'qsort');
    if (qsortPtr) {
        Interceptor.attach(qsortPtr, {
            onEnter: function (args) {
                const a = args[0];
                const n = args[1].toInt();
                const es = args[2].toInt();
                const cmp = args[3];

                console.log("qsort called!");
                console.log("  Array address:", a);
                console.log("  Number of elements:", n);
                console.log("  Element size:", es);
                console.log("  Compare function address:", cmp);

                // 可以尝试读取数组的内容 (小心越界)
                if (n > 0 && es > 0) {
                    console.log("  First few elements:");
                    for (let i = 0; i < Math.min(n, 5); i++) {
                        if (es === 4) { // 假设是 int 数组
                            console.log("    Element " + i + ": " + ptr(a).add(i * es).readInt());
                        } else if (es === 8) { // 假设是 long long 数组
                            console.log("    Element " + i + ": " + ptr(a).add(i * es).readLong());
                        }
                        // ... 可以根据 es 的值添加更多类型的处理
                    }
                }
            },
            onLeave: function (retval) {
                console.log("qsort finished.");
            }
        });
    } else {
        console.log("qsort not found!");
    }
} else {
    console.log("Frida hook for qsort is only tested on arm64 and x64.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `qsort_hook.js`。
2. 运行 Frida，将其附加到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l qsort_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l qsort_hook.js
   ```
3. 当目标应用程序调用 `qsort` 时，Frida 会拦截调用并打印相关信息到控制台。

**更复杂的 Hooking:**

* 可以 hook 比较函数，查看比较的元素。
* 可以尝试修改数组元素或比较函数的返回值，以观察对排序结果的影响（需要谨慎操作）。

希望这个详细的分析能够帮助你理解 `qsort.c` 的功能、实现以及在 Android 系统中的应用。

### 提示词
```
这是目录为bionic/libc/upstream-freebsd/lib/libc/stdlib/qsort.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)qsort.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libc_private.h"

#if defined(I_AM_QSORT_R)
typedef int		 cmp_t(const void *, const void *, void *);
#elif defined(I_AM_QSORT_R_COMPAT)
typedef int		 cmp_t(void *, const void *, const void *);
#elif defined(I_AM_QSORT_S)
typedef int		 cmp_t(const void *, const void *, void *);
#else
typedef int		 cmp_t(const void *, const void *);
#endif
static inline char	*med3(char *, char *, char *, cmp_t *, void *);

#define	MIN(a, b)	((a) < (b) ? a : b)

/*
 * Qsort routine from Bentley & McIlroy's "Engineering a Sort Function".
 */

static inline void
swapfunc(char *a, char *b, size_t es)
{
	char t;

	do {
		t = *a;
		*a++ = *b;
		*b++ = t;
	} while (--es > 0);
}

#define	vecswap(a, b, n)				\
	if ((n) > 0) swapfunc(a, b, n)

#if defined(I_AM_QSORT_R)
#define	CMP(t, x, y) (cmp((x), (y), (t)))
#elif defined(I_AM_QSORT_R_COMPAT)
#define	CMP(t, x, y) (cmp((t), (x), (y)))
#elif defined(I_AM_QSORT_S)
#define	CMP(t, x, y) (cmp((x), (y), (t)))
#else
#define	CMP(t, x, y) (cmp((x), (y)))
#endif

static inline char *
med3(char *a, char *b, char *c, cmp_t *cmp, void *thunk
#if !defined(I_AM_QSORT_R) && !defined(I_AM_QSORT_R_COMPAT) && !defined(I_AM_QSORT_S)
__unused
#endif
)
{
	return CMP(thunk, a, b) < 0 ?
	       (CMP(thunk, b, c) < 0 ? b : (CMP(thunk, a, c) < 0 ? c : a ))
	      :(CMP(thunk, b, c) > 0 ? b : (CMP(thunk, a, c) < 0 ? a : c ));
}

/*
 * The actual qsort() implementation is static to avoid preemptible calls when
 * recursing. Also give them different names for improved debugging.
 */
#if defined(I_AM_QSORT_R)
#define local_qsort local_qsort_r
#elif defined(I_AM_QSORT_R_COMPAT)
#define local_qsort local_qsort_r_compat
#elif defined(I_AM_QSORT_S)
#define local_qsort local_qsort_s
#endif
static void
local_qsort(void *a, size_t n, size_t es, cmp_t *cmp, void *thunk)
{
	char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
	size_t d1, d2;
	int cmp_result;
	int swap_cnt;

	/* if there are less than 2 elements, then sorting is not needed */
	if (__predict_false(n < 2))
		return;
loop:
	swap_cnt = 0;
	if (n < 7) {
		for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
			for (pl = pm; 
			     pl > (char *)a && CMP(thunk, pl - es, pl) > 0;
			     pl -= es)
				swapfunc(pl, pl - es, es);
		return;
	}
	pm = (char *)a + (n / 2) * es;
	if (n > 7) {
		pl = a;
		pn = (char *)a + (n - 1) * es;
		if (n > 40) {
			size_t d = (n / 8) * es;

			pl = med3(pl, pl + d, pl + 2 * d, cmp, thunk);
			pm = med3(pm - d, pm, pm + d, cmp, thunk);
			pn = med3(pn - 2 * d, pn - d, pn, cmp, thunk);
		}
		pm = med3(pl, pm, pn, cmp, thunk);
	}
	swapfunc(a, pm, es);
	pa = pb = (char *)a + es;

	pc = pd = (char *)a + (n - 1) * es;
	for (;;) {
		while (pb <= pc && (cmp_result = CMP(thunk, pb, a)) <= 0) {
			if (cmp_result == 0) {
				swap_cnt = 1;
				swapfunc(pa, pb, es);
				pa += es;
			}
			pb += es;
		}
		while (pb <= pc && (cmp_result = CMP(thunk, pc, a)) >= 0) {
			if (cmp_result == 0) {
				swap_cnt = 1;
				swapfunc(pc, pd, es);
				pd -= es;
			}
			pc -= es;
		}
		if (pb > pc)
			break;
		swapfunc(pb, pc, es);
		swap_cnt = 1;
		pb += es;
		pc -= es;
	}
	if (swap_cnt == 0) {  /* Switch to insertion sort */
		for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
			for (pl = pm; 
			     pl > (char *)a && CMP(thunk, pl - es, pl) > 0;
			     pl -= es)
				swapfunc(pl, pl - es, es);
		return;
	}

	pn = (char *)a + n * es;
	d1 = MIN(pa - (char *)a, pb - pa);
	vecswap(a, pb - d1, d1);
	/*
	 * Cast es to preserve signedness of right-hand side of MIN()
	 * expression, to avoid sign ambiguity in the implied comparison.  es
	 * is safely within [0, SSIZE_MAX].
	 */
	d1 = MIN(pd - pc, pn - pd - (ssize_t)es);
	vecswap(pb, pn - d1, d1);

	d1 = pb - pa;
	d2 = pd - pc;
	if (d1 <= d2) {
		/* Recurse on left partition, then iterate on right partition */
		if (d1 > es) {
			local_qsort(a, d1 / es, es, cmp, thunk);
		}
		if (d2 > es) {
			/* Iterate rather than recurse to save stack space */
			/* qsort(pn - d2, d2 / es, es, cmp); */
			a = pn - d2;
			n = d2 / es;
			goto loop;
		}
	} else {
		/* Recurse on right partition, then iterate on left partition */
		if (d2 > es) {
			local_qsort(pn - d2, d2 / es, es, cmp, thunk);
		}
		if (d1 > es) {
			/* Iterate rather than recurse to save stack space */
			/* qsort(a, d1 / es, es, cmp); */
			n = d1 / es;
			goto loop;
		}
	}
}

#if defined(I_AM_QSORT_R)
void
(qsort_r)(void *a, size_t n, size_t es, cmp_t *cmp, void *thunk)
{
	local_qsort_r(a, n, es, cmp, thunk);
}
#elif defined(I_AM_QSORT_R_COMPAT)
void
__qsort_r_compat(void *a, size_t n, size_t es, void *thunk, cmp_t *cmp)
{
	local_qsort_r_compat(a, n, es, cmp, thunk);
}
#elif defined(I_AM_QSORT_S)
errno_t
qsort_s(void *a, rsize_t n, rsize_t es, cmp_t *cmp, void *thunk)
{
	if (n > RSIZE_MAX) {
		__throw_constraint_handler_s("qsort_s : n > RSIZE_MAX", EINVAL);
		return (EINVAL);
	} else if (es > RSIZE_MAX) {
		__throw_constraint_handler_s("qsort_s : es > RSIZE_MAX",
		    EINVAL);
		return (EINVAL);
	} else if (n != 0) {
		if (a == NULL) {
			__throw_constraint_handler_s("qsort_s : a == NULL",
			    EINVAL);
			return (EINVAL);
		} else if (cmp == NULL) {
			__throw_constraint_handler_s("qsort_s : cmp == NULL",
			    EINVAL);
			return (EINVAL);
		} else if (es <= 0) {
			__throw_constraint_handler_s("qsort_s : es <= 0",
			    EINVAL);
			return (EINVAL);
		}
	}

	local_qsort_s(a, n, es, cmp, thunk);
	return (0);
}
#else
void
qsort(void *a, size_t n, size_t es, cmp_t *cmp)
{
	local_qsort(a, n, es, cmp, NULL);
}
#endif
```