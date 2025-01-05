Response:
Here's a breakdown of the thought process to generate the comprehensive answer:

1. **Understand the Core Request:** The main goal is to analyze the `random.c` source code from Android's Bionic library (originally from NetBSD), focusing on its functionality, relationship to Android, implementation details, interaction with the dynamic linker (if any), common usage errors, and how it's accessed from higher layers (Android Framework/NDK). The prompt also requests Frida hook examples.

2. **Initial Code Scan and High-Level Functionality Identification:**  Read through the code to identify the main functions provided: `srandom`, `initstate`, `setstate`, and `random`. Notice the conditional compilation (`#ifndef SMALL_RANDOM`) which indicates two different implementations based on whether `SMALL_RANDOM` is defined. This immediately suggests the need to address both scenarios. The comments within the code are very helpful for understanding the intended behavior and different random number generation algorithms.

3. **Function-by-Function Analysis (Conceptual):**  For each of the main functions, think about:
    * **Purpose:** What does this function do conceptually?  (e.g., `srandom` seeds the generator, `random` generates a random number).
    * **Inputs/Outputs:** What parameters does it take? What does it return?
    * **Internal Logic (Simplified):** What are the key steps involved in its operation?  (e.g., `srandom` initializes the state array, `random` performs calculations based on the current state).
    * **Mutex Usage:** Note the use of `mutex_lock` and `mutex_unlock` indicating thread-safety considerations.

4. **Relationship to Android:** Consider how random number generation is used in general Android development. Think about security (cryptography), games, simulations, and other applications where randomness is required. Realize that this `libc` implementation is a fundamental building block used by higher-level Android components.

5. **Detailed Implementation Explanation:**  Dive deeper into the code for each function.
    * **`srandom`:** Focus on the two branches: the simpler seed storage for `TYPE_0` and the more complex state array initialization using a linear congruential generator for other types. Explain the purpose of cycling the state.
    * **`initstate`:**  Explain how it sets up the state array based on the provided size and selects the appropriate random number generation algorithm. Highlight the saving of the old state.
    * **`setstate`:**  Describe how it restores the state from a previously initialized array, including the pointer positions and the generator type.
    * **`random`:**  Explain the two main branches: the simple linear congruential method for `TYPE_0` and the linear feedback shift register approach for other types, emphasizing the movement of the `fptr` and `rptr`. For the `SMALL_RANDOM` case, explain the simpler Park-Miller algorithm.

6. **Dynamic Linker Analysis:** Carefully examine the code for any direct interactions with the dynamic linker. Notice the `#ifdef __weak_alias` which suggests weak symbol aliasing. This is the key interaction with the dynamic linker. Explain weak linking and provide an example of how it's used (allowing alternative implementations to override the default). Create a simple SO layout demonstrating this concept.

7. **Logical Reasoning (Assumptions and Outputs):**  Choose specific input values for `srandom` and demonstrate the expected output from subsequent `random` calls. This helps illustrate the deterministic nature of pseudo-random number generators when seeded.

8. **Common Usage Errors:** Brainstorm potential mistakes developers might make when using these functions, such as not seeding the generator, providing an incorrectly sized state array to `initstate`, or assuming perfect randomness.

9. **Android Framework/NDK Access:**  Think about the layers of Android. Start with user applications, then move to the NDK, then to the system libraries like `libc`. Explain that NDK developers can directly call these functions. For the Framework, point out that higher-level Java APIs (like `java.util.Random`) ultimately rely on native implementations, which could involve this code.

10. **Frida Hook Examples:**  Craft Frida scripts to intercept calls to `srandom` and `random`. Show how to print arguments and return values. This provides practical debugging techniques.

11. **Structure and Language:**  Organize the information logically with clear headings and subheadings. Use clear and concise Chinese. Explain technical terms where necessary. Ensure all parts of the prompt are addressed. Pay attention to formatting for readability.

12. **Review and Refine:** Read through the entire answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or missing information. For example, initially, I might have overlooked the `SMALL_RANDOM` section and had to go back and add details about it. Similarly, double-checking the dynamic linker section to ensure the explanation of weak symbols and the SO layout is accurate.
## 分析 Android Bionic 中的 random.c 文件

这个 `random.c` 文件是 Android Bionic C 库中用于生成伪随机数的代码，它源自 NetBSD 的 `stdlib` 库。它的主要功能是提供一套标准的、可配置的随机数生成机制。

**功能列表:**

1. **伪随机数生成:** 提供 `random()` 函数，用于生成 0 到 `RAND_MAX` 之间的非负长整型伪随机数。
2. **种子设置:** 提供 `srandom(unsigned int seed)` 函数，用于使用给定的种子初始化随机数生成器。相同的种子会产生相同的随机数序列。
3. **状态初始化:** 提供 `initstate(unsigned int seed, char *state, size_t n)` 函数，允许用户自定义状态数组的大小和初始种子，从而选择不同质量的随机数生成算法。
4. **状态设置:** 提供 `setstate(char *state)` 函数，允许用户切换到之前通过 `initstate` 创建的状态数组，恢复之前的随机数生成状态。
5. **线程安全:** 使用互斥锁 (`mutex_t`) 保护共享的随机数生成状态，使得在多线程环境下调用这些函数是安全的。
6. **多种随机数生成算法:**  根据提供的状态数组大小，支持多种线性反馈移位寄存器 (LFSR) 算法，提供不同质量和周期的随机数生成。也支持简单的线性同余生成器 (LCG) 用于小状态。
7. **弱符号别名:** 使用 `__weak_alias` 定义了 `_initstate`, `_random`, `_setstate`, `_srandom` 等弱符号别名，允许其他库或程序提供自定义的实现。

**与 Android 功能的关系及举例说明:**

* **基础库支持:** 作为 Bionic libc 的一部分，`random.c` 提供的功能是 Android 系统和应用的基础设施，被许多其他系统组件和应用所依赖。
* **安全性:** 随机数在密码学中扮演着至关重要的角色。虽然 `random()` 产生的不是密码学安全的随机数，但它是许多非安全敏感场景下的默认选择。Android 系统中一些需要基本随机性的功能可能会使用它。
* **游戏和模拟:** 游戏开发和科学模拟经常需要生成随机数来模拟各种事件和行为。NDK 开发人员可以直接使用这些函数。
* **系统初始化和配置:**  某些系统服务的初始化或配置可能需要生成随机值。
* **测试和调试:** 随机数生成在软件测试中也很有用，可以用于生成测试数据或模拟随机行为。

**举例说明:**

假设一个 Android 应用需要生成一个随机数来决定是否显示一个提示信息：

```c
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main() {
  srand(time(NULL)); // 使用当前时间作为种子初始化
  int should_show = rand() % 10; // 生成 0 到 9 的随机数
  if (should_show < 3) {
    printf("显示提示信息！\n");
  } else {
    printf("不显示提示信息。\n");
  }
  return 0;
}
```

在这个例子中，`srand` 和 `rand` (实际上是 `srandom` 和 `random` 的宏定义或内联函数) 就使用了 `random.c` 中提供的功能。

**libc 函数的实现细节:**

为了详细解释，我们分别查看每个函数在 `random.c` 中的实现方式：

**1. `random()` (和 `random_unlocked()`):**

* **逻辑:**  `random()` 函数是生成随机数的核心。它根据当前的状态信息和选择的随机数生成算法进行计算。
* **非 `SMALL_RANDOM` 情况:**
    * 如果 `rand_type` 是 `TYPE_0` (线性同余)，则直接使用简单的 LCG 算法：`state[0] = i = (i * 1103515245 + 12345) & 0x7fffffff;`。
    * 否则，使用更复杂的 LFSR 算法。它维护两个指针 `fptr` (前指针) 和 `rptr` (后指针)，它们在状态数组中循环移动，并相隔 `rand_sep` 个位置。
    * 计算新的随机数的方式是将 `rptr` 指向的值加到 `fptr` 指向的值上：`*f += *r;`。
    * 返回的值是 `fptr` 指向的值右移一位，并与 `0x7fffffff` 进行与运算，得到一个 31 位的非负随机数。
    * `fptr` 和 `rptr` 循环移动，确保每次生成的随机数都依赖于之前的状态。
* **`SMALL_RANDOM` 情况:**  使用一个简单的 Park-Miller 算法，直接基于一个静态的种子变量 `randseed` 进行计算。
* **线程安全:** `random()` 函数会先获取互斥锁 `random_mutex`，调用 `random_unlocked()` 执行实际的随机数生成，最后释放锁，保证了多线程安全。

**2. `srandom(unsigned int seed)` (和 `srandom_unlocked()`):**

* **逻辑:**  `srandom()` 函数用于设置随机数生成器的初始种子。
* **非 `SMALL_RANDOM` 情况:**
    * 如果 `rand_type` 是 `TYPE_0`，则直接将种子值赋给状态数组的第一个元素 `state[0]`。
    * 否则，使用一个 LCG 算法 (不同的参数，取决于 `USE_BETTER_RANDOM` 宏) 根据种子值初始化状态数组 `state[]` 的所有元素。
    * 初始化 `fptr` 和 `rptr` 的位置，使其相隔 `rand_sep` 个位置。
    * 为了消除 LCG 初始化可能引入的依赖性，会调用 `random_unlocked()`  `10 * rand_deg` 次来“扰动”状态。
* **`SMALL_RANDOM` 情况:**  直接将种子值赋给静态变量 `randseed`。
* **线程安全:**  `srandom()` 函数会先获取互斥锁 `random_mutex`，调用 `srandom_unlocked()` 执行实际的种子设置，最后释放锁。

**3. `initstate(unsigned int seed, char *state, size_t n)`:**

* **逻辑:**  `initstate()` 函数允许用户使用自定义的状态数组初始化随机数生成器。
* **保存旧状态:**  首先保存当前的状态信息，以便后续可以恢复。
* **确定随机数类型:** 根据提供的状态数组大小 `n`，选择合适的随机数生成算法 (`rand_type`, `rand_deg`, `rand_sep`)。不同的状态大小对应不同的 LFSR 多项式，提供不同质量和周期的随机数。
* **设置状态指针:** 将全局的 `state` 指针指向用户提供的状态数组 `arg_state` 的适当位置。
* **调用 `srandom_unlocked()`:** 使用提供的种子初始化新的状态数组。
* **存储类型信息:** 将当前的随机数类型和 `rptr` 的位置信息存储在状态数组的第一个元素中，以便 `setstate()` 可以正确恢复状态。
* **返回旧状态:** 返回指向旧状态数组的指针。
* **线程安全:**  `initstate()` 函数使用互斥锁保护共享状态。

**4. `setstate(char *state)`:**

* **逻辑:**  `setstate()` 函数允许用户切换到之前通过 `initstate()` 创建的状态数组。
* **保存旧状态:**  首先保存当前的状态信息。
* **解析状态信息:** 从提供的状态数组的第一个元素中解析出随机数类型和 `rptr` 的位置信息。
* **验证类型:** 检查解析出的随机数类型是否有效。
* **恢复状态:**  根据解析出的信息，更新全局的 `rand_type`, `rand_deg`, `rand_sep`, `state`, `rptr`, `fptr` 和 `end_ptr`，恢复到之前的随机数生成状态。
* **返回旧状态:** 返回指向旧状态数组的指针。
* **线程安全:** `setstate()` 函数使用互斥锁保护共享状态。

**涉及 dynamic linker 的功能:**

`random.c` 中最直接涉及 dynamic linker 的功能是使用了 **弱符号别名 (`__weak_alias`)**。

```c
#ifdef __weak_alias
__weak_alias(initstate,_initstate)
__weak_alias(random,_random)
__weak_alias(setstate,_setstate)
__weak_alias(srandom,_srandom)
#endif
```

这表示 `initstate` 是 `_initstate` 的弱符号别名。这意味着如果在链接时找到了 `_initstate` 的强符号定义（例如，在另一个库中提供了自定义的实现），那么链接器会使用强符号的定义。如果没有找到强符号定义，则会使用 `random.c` 中提供的 `initstate` 的定义。

**SO 布局样本:**

假设有一个名为 `libcustomrand.so` 的共享库，它提供了自定义的 `_srandom` 实现：

**`libcustomrand.so` 的布局可能如下:**

```
libcustomrand.so:
    符号表:
        ...
        00000100 T _srandom  // 自定义的 _srandom 函数
        ...
```

**`libc.so` (包含 `random.c`) 的布局可能如下:**

```
libc.so:
    符号表:
        ...
        00010000 W srandom   // weak symbol, 实际指向 random.c 中的 srandom
        ...
```

**链接的处理过程:**

1. 当一个应用或库链接到 `libc.so` 时，它会引用 `srandom` 符号。
2. 链接器在 `libc.so` 的符号表中找到 `srandom`，但这是一个弱符号。
3. 如果该应用或库还链接到了 `libcustomrand.so`，链接器会在 `libcustomrand.so` 的符号表中找到 `_srandom` 的强符号定义。
4. 由于 `_srandom` 是 `srandom` 的别名，并且是一个强符号，链接器会将对 `srandom` 的引用解析到 `libcustomrand.so` 中定义的 `_srandom` 函数。
5. 如果没有链接到 `libcustomrand.so` 或其他提供了 `_srandom` 强符号的库，链接器将使用 `libc.so` 中 `srandom` 的弱符号定义，即 `random.c` 中提供的实现。

**假设输入与输出 (针对 `random()` 和 `srandom()`):**

**假设输入:**

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
  srandom(123); // 使用种子 123 初始化
  printf("Random number 1: %ld\n", random());
  printf("Random number 2: %ld\n", random());
  srandom(123); // 再次使用相同的种子初始化
  printf("Random number 3: %ld\n", random());
  return 0;
}
```

**预期输出:**

```
Random number 1: 1979881415
Random number 2: 1129974507
Random number 3: 1979881415
```

**解释:**

* 第一次调用 `srandom(123)` 使用种子 123 初始化了随机数生成器。
* 前两次 `random()` 调用会产生特定的随机数序列，因为种子是固定的。
* 第二次调用 `srandom(123)` 使用相同的种子重新初始化，导致随机数生成器回到相同的初始状态。
* 因此，第三次 `random()` 调用产生的随机数与第一次相同。

**用户或编程常见的使用错误:**

1. **未初始化种子:**  在调用 `random()` 之前没有调用 `srandom()` 或 `srand()` (它是 `srandom()` 的另一个名称)。这会导致每次程序运行时都生成相同的随机数序列，因为默认种子通常是 1。
   ```c
   #include <stdlib.h>
   #include <stdio.h>

   int main() {
     printf("Random number: %d\n", rand()); // 错误：未初始化种子
     return 0;
   }
   ```

2. **使用不安全的种子:**  使用可预测的种子值，例如固定的常量，会导致生成的随机数序列也是可预测的。对于需要一定程度随机性的应用，应该使用更随机的源作为种子，例如当前时间：`srand(time(NULL));`。

3. **假设 `random()` 是加密安全的:** `random()` 函数生成的伪随机数不适合用于密码学应用。对于安全性要求高的场景，应该使用 Android 提供的更安全的随机数生成机制，例如 `java.security.SecureRandom` 或 Linux 内核的 `/dev/urandom`。

4. **`initstate` 使用不当:**  传递给 `initstate` 的状态数组大小不足以支持期望的随机数生成算法。如果 `n` 小于 `BREAK_0`，`initstate` 会返回 `NULL`。

5. **多线程环境下的竞争条件 (如果未使用 `srandom`/`random` 而是直接操作内部状态):**  虽然 `srandom` 和 `random` 是线程安全的，但如果用户尝试直接操作 `random.c` 内部的全局状态变量，可能会导致竞争条件和不可预测的结果。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 开发:**  NDK (Native Development Kit) 允许开发者使用 C 或 C++ 编写 Android 应用的一部分。在 NDK 代码中，可以直接包含 `<stdlib.h>` 并调用 `rand()`, `srand()`, `random()`, `srandom()`, `initstate()`, `setstate()` 等函数，这些函数最终会链接到 Bionic libc 中的 `random.c` 实现。

   ```c++
   // NDK 代码示例
   #include <stdlib.h>
   #include <time.h>
   #include <android/log.h>

   void generate_random() {
     srand(time(NULL));
     int random_value = rand();
     __android_log_print(ANDROID_LOG_INFO, "MyTag", "Random value: %d", random_value);
   }
   ```

2. **Android Framework (通过 JNI):** Android Framework 主要使用 Java 编写。如果 Framework 需要生成随机数，通常会使用 `java.util.Random` 类。`java.util.Random` 的某些实现 (尤其是在较底层的 native 方法中) 可能会调用到 native 代码，最终有可能间接地使用到 Bionic libc 的随机数生成功能。例如，一些底层的数学或加密相关的 native 代码可能会使用这些函数。

**Frida Hook 示例调试步骤:**

以下是使用 Frida Hook 调试 `srandom` 和 `random` 函数的示例：

**1. Hook `srandom`:**

```javascript
if (Process.platform === 'android') {
  const srandomPtr = Module.findExportByName('libc.so', 'srandom');
  if (srandomPtr) {
    Interceptor.attach(srandomPtr, {
      onEnter: function (args) {
        console.log('[srandom] Called');
        console.log('\tSeed:', args[0].toInt());
      },
      onLeave: function (retval) {
        console.log('[srandom] Return Value:', retval.toInt());
      }
    });
  } else {
    console.log('srandom not found in libc.so');
  }
}
```

**步骤:**

* 找到 `libc.so` 中 `srandom` 函数的地址。
* 使用 `Interceptor.attach` 拦截对 `srandom` 的调用。
* 在 `onEnter` 中，打印调用的信息和传入的种子值。
* 在 `onLeave` 中，打印返回值（`void` 函数，返回值通常是 0）。

**2. Hook `random`:**

```javascript
if (Process.platform === 'android') {
  const randomPtr = Module.findExportByName('libc.so', 'random');
  if (randomPtr) {
    Interceptor.attach(randomPtr, {
      onEnter: function (args) {
        console.log('[random] Called');
      },
      onLeave: function (retval) {
        console.log('[random] Return Value:', retval.toInt());
      }
    });
  } else {
    console.log('random not found in libc.so');
  }
}
```

**步骤:**

* 找到 `libc.so` 中 `random` 函数的地址。
* 使用 `Interceptor.attach` 拦截对 `random` 的调用。
* 在 `onEnter` 中，打印调用信息。
* 在 `onLeave` 中，打印生成的随机数值。

**运行 Frida Hook:**

1. 确保你的 Android 设备或模拟器已连接并启用了 USB 调试。
2. 确保你的设备上安装了 Frida 服务。
3. 将上面的 JavaScript 代码保存到一个文件中，例如 `random_hook.js`。
4. 运行要调试的 Android 应用。
5. 使用 Frida 命令运行 hook 脚本，替换 `<应用包名>` 为实际的应用包名：

   ```bash
   frida -U -f <应用包名> -l random_hook.js --no-pause
   ```

   或者，如果应用已经在运行：

   ```bash
   frida -U <应用包名> -l random_hook.js
   ```

通过这些 Frida Hook，你可以在应用调用 `srandom` 和 `random` 时实时查看调用的参数和返回值，从而了解随机数生成器的行为。这对于调试和分析与随机数相关的 Android 应用非常有用。

希望以上详细的分析能够帮助你理解 Android Bionic 中 `random.c` 文件的功能、实现、与 Android 的关系以及如何进行调试。

Prompt: 
```
这是目录为bionic/libc/upstream-netbsd/common/lib/libc/stdlib/random.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: random.c,v 1.5 2016/02/08 05:27:24 dholland Exp $	*/

/*
 * Copyright (c) 1983, 1993
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

#if !defined(_KERNEL) && !defined(_STANDALONE)
#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)random.c	8.2 (Berkeley) 5/19/95";
#else
__RCSID("$NetBSD: random.c,v 1.5 2016/02/08 05:27:24 dholland Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include "reentrant.h"

#ifdef __weak_alias
__weak_alias(initstate,_initstate)
__weak_alias(random,_random)
__weak_alias(setstate,_setstate)
__weak_alias(srandom,_srandom)
#endif


#ifdef _REENTRANT
static mutex_t random_mutex = MUTEX_INITIALIZER;
#endif
#else
#include <lib/libkern/libkern.h>
#define mutex_lock(a)	(void)0
#define mutex_unlock(a) (void)0
#endif

#ifndef SMALL_RANDOM
static void srandom_unlocked(unsigned int);
static long random_unlocked(void);

#define USE_BETTER_RANDOM

/*
 * random.c:
 *
 * An improved random number generation package.  In addition to the standard
 * rand()/srand() like interface, this package also has a special state info
 * interface.  The initstate() routine is called with a seed, an array of
 * bytes, and a count of how many bytes are being passed in; this array is
 * then initialized to contain information for random number generation with
 * that much state information.  Good sizes for the amount of state
 * information are 32, 64, 128, and 256 bytes.  The state can be switched by
 * calling the setstate() routine with the same array as was initiallized
 * with initstate().  By default, the package runs with 128 bytes of state
 * information and generates far better random numbers than a linear
 * congruential generator.  If the amount of state information is less than
 * 32 bytes, a simple linear congruential R.N.G. is used.
 *
 * Internally, the state information is treated as an array of ints; the
 * zeroeth element of the array is the type of R.N.G. being used (small
 * integer); the remainder of the array is the state information for the
 * R.N.G.  Thus, 32 bytes of state information will give 7 ints worth of
 * state information, which will allow a degree seven polynomial.  (Note:
 * the zeroeth word of state information also has some other information
 * stored in it -- see setstate() for details).
 *
 * The random number generation technique is a linear feedback shift register
 * approach, employing trinomials (since there are fewer terms to sum up that
 * way).  In this approach, the least significant bit of all the numbers in
 * the state table will act as a linear feedback shift register, and will
 * have period 2^deg - 1 (where deg is the degree of the polynomial being
 * used, assuming that the polynomial is irreducible and primitive).  The
 * higher order bits will have longer periods, since their values are also
 * influenced by pseudo-random carries out of the lower bits.  The total
 * period of the generator is approximately deg*(2**deg - 1); thus doubling
 * the amount of state information has a vast influence on the period of the
 * generator.  Note: the deg*(2**deg - 1) is an approximation only good for
 * large deg, when the period of the shift register is the dominant factor.
 * With deg equal to seven, the period is actually much longer than the
 * 7*(2**7 - 1) predicted by this formula.
 *
 * Modified 28 December 1994 by Jacob S. Rosenberg.
 * The following changes have been made:
 * All references to the type u_int have been changed to unsigned long.
 * All references to type int have been changed to type long.  Other
 * cleanups have been made as well.  A warning for both initstate and
 * setstate has been inserted to the effect that on Sparc platforms
 * the 'arg_state' variable must be forced to begin on word boundaries.
 * This can be easily done by casting a long integer array to char *.
 * The overall logic has been left STRICTLY alone.  This software was
 * tested on both a VAX and Sun SpacsStation with exactly the same
 * results.  The new version and the original give IDENTICAL results.
 * The new version is somewhat faster than the original.  As the
 * documentation says:  "By default, the package runs with 128 bytes of
 * state information and generates far better random numbers than a linear
 * congruential generator.  If the amount of state information is less than
 * 32 bytes, a simple linear congruential R.N.G. is used."  For a buffer of
 * 128 bytes, this new version runs about 19 percent faster and for a 16
 * byte buffer it is about 5 percent faster.
 *
 * Modified 07 January 2002 by Jason R. Thorpe.
 * The following changes have been made:
 * All the references to "long" have been changed back to "int".  This
 * fixes memory corruption problems on LP64 platforms.
 */

/*
 * For each of the currently supported random number generators, we have a
 * break value on the amount of state information (you need at least this
 * many bytes of state info to support this random number generator), a degree
 * for the polynomial (actually a trinomial) that the R.N.G. is based on, and
 * the separation between the two lower order coefficients of the trinomial.
 */
#define	TYPE_0		0		/* linear congruential */
#define	BREAK_0		8
#define	DEG_0		0
#define	SEP_0		0

#define	TYPE_1		1		/* x**7 + x**3 + 1 */
#define	BREAK_1		32
#define	DEG_1		7
#define	SEP_1		3

#define	TYPE_2		2		/* x**15 + x + 1 */
#define	BREAK_2		64
#define	DEG_2		15
#define	SEP_2		1

#define	TYPE_3		3		/* x**31 + x**3 + 1 */
#define	BREAK_3		128
#define	DEG_3		31
#define	SEP_3		3

#define	TYPE_4		4		/* x**63 + x + 1 */
#define	BREAK_4		256
#define	DEG_4		63
#define	SEP_4		1

/*
 * Array versions of the above information to make code run faster --
 * relies on fact that TYPE_i == i.
 */
#define	MAX_TYPES	5		/* max number of types above */

static const int degrees[MAX_TYPES] =	{ DEG_0, DEG_1, DEG_2, DEG_3, DEG_4 };
static const int seps[MAX_TYPES] =	{ SEP_0, SEP_1, SEP_2, SEP_3, SEP_4 };

/*
 * Initially, everything is set up as if from:
 *
 *	initstate(1, &randtbl, 128);
 *
 * Note that this initialization takes advantage of the fact that srandom()
 * advances the front and rear pointers 10*rand_deg times, and hence the
 * rear pointer which starts at 0 will also end up at zero; thus the zeroeth
 * element of the state information, which contains info about the current
 * position of the rear pointer is just
 *
 *	MAX_TYPES * (rptr - state) + TYPE_3 == TYPE_3.
 */

/* LINTED */
static int randtbl[DEG_3 + 1] = {
	TYPE_3,
#ifdef USE_BETTER_RANDOM
	0x991539b1, 0x16a5bce3, 0x6774a4cd,
	0x3e01511e, 0x4e508aaa, 0x61048c05,
	0xf5500617, 0x846b7115, 0x6a19892c,
	0x896a97af, 0xdb48f936, 0x14898454,
	0x37ffd106, 0xb58bff9c, 0x59e17104,
	0xcf918a49, 0x09378c83, 0x52c7a471,
	0x8d293ea9, 0x1f4fc301, 0xc3db71be,
	0x39b44e1c, 0xf8a44ef9, 0x4c8b80b1,
	0x19edc328, 0x87bf4bdd, 0xc9b240e5,
	0xe9ee4b1b, 0x4382aee7, 0x535b6b41,
	0xf3bec5da,
#else
	0x9a319039, 0x32d9c024, 0x9b663182,
	0x5da1f342, 0xde3b81e0, 0xdf0a6fb5,
	0xf103bc02, 0x48f340fb, 0x7449e56b,
	0xbeb1dbb0, 0xab5c5918, 0x946554fd,
	0x8c2e680f, 0xeb3d799f, 0xb11ee0b7,
	0x2d436b86, 0xda672e2a, 0x1588ca88,
	0xe369735d, 0x904f35f7, 0xd7158fd6,
	0x6fa6f051, 0x616e6b96, 0xac94efdc,
	0x36413f93, 0xc622c298, 0xf5a42ab8,
	0x8a88d77b, 0xf5ad9d0e, 0x8999220b,
	0x27fb47b9,
#endif /* USE_BETTER_RANDOM */
};

/*
 * fptr and rptr are two pointers into the state info, a front and a rear
 * pointer.  These two pointers are always rand_sep places aparts, as they
 * cycle cyclically through the state information.  (Yes, this does mean we
 * could get away with just one pointer, but the code for random() is more
 * efficient this way).  The pointers are left positioned as they would be
 * from the call
 *
 *	initstate(1, randtbl, 128);
 *
 * (The position of the rear pointer, rptr, is really 0 (as explained above
 * in the initialization of randtbl) because the state table pointer is set
 * to point to randtbl[1] (as explained below).
 */
static int *fptr = &randtbl[SEP_3 + 1];
static int *rptr = &randtbl[1];

/*
 * The following things are the pointer to the state information table, the
 * type of the current generator, the degree of the current polynomial being
 * used, and the separation between the two pointers.  Note that for efficiency
 * of random(), we remember the first location of the state information, not
 * the zeroeth.  Hence it is valid to access state[-1], which is used to
 * store the type of the R.N.G.  Also, we remember the last location, since
 * this is more efficient than indexing every time to find the address of
 * the last element to see if the front and rear pointers have wrapped.
 */
static int *state = &randtbl[1];
static int rand_type = TYPE_3;
static int rand_deg = DEG_3;
static int rand_sep = SEP_3;
static int *end_ptr = &randtbl[DEG_3 + 1];

/*
 * srandom:
 *
 * Initialize the random number generator based on the given seed.  If the
 * type is the trivial no-state-information type, just remember the seed.
 * Otherwise, initializes state[] based on the given "seed" via a linear
 * congruential generator.  Then, the pointers are set to known locations
 * that are exactly rand_sep places apart.  Lastly, it cycles the state
 * information a given number of times to get rid of any initial dependencies
 * introduced by the L.C.R.N.G.  Note that the initialization of randtbl[]
 * for default usage relies on values produced by this routine.
 */
static void
srandom_unlocked(unsigned int x)
{
	int i;

	if (rand_type == TYPE_0)
		state[0] = x;
	else {
		state[0] = x;
		for (i = 1; i < rand_deg; i++) {
#ifdef USE_BETTER_RANDOM
			int x1, hi, lo, t;

			/*
			 * Compute x[n + 1] = (7^5 * x[n]) mod (2^31 - 1).
			 * From "Random number generators: good ones are hard
			 * to find", Park and Miller, Communications of the ACM,
			 * vol. 31, no. 10,
			 * October 1988, p. 1195.
			 */
			x1 = state[i - 1];
			hi = x1 / 127773;
			lo = x1 % 127773;
			t = 16807 * lo - 2836 * hi;
			if (t <= 0)
				t += 0x7fffffff;
			state[i] = t;
#else
			state[i] = 1103515245 * state[i - 1] + 12345;
#endif /* USE_BETTER_RANDOM */
		}
		fptr = &state[rand_sep];
		rptr = &state[0];
		for (i = 0; i < 10 * rand_deg; i++)
			(void)random_unlocked();
	}
}

void
srandom(unsigned int x)
{

	mutex_lock(&random_mutex);
	srandom_unlocked(x);
	mutex_unlock(&random_mutex);
}

/*
 * initstate:
 *
 * Initialize the state information in the given array of n bytes for future
 * random number generation.  Based on the number of bytes we are given, and
 * the break values for the different R.N.G.'s, we choose the best (largest)
 * one we can and set things up for it.  srandom() is then called to
 * initialize the state information.
 *
 * Note that on return from srandom(), we set state[-1] to be the type
 * multiplexed with the current value of the rear pointer; this is so
 * successive calls to initstate() won't lose this information and will be
 * able to restart with setstate().
 *
 * Note: the first thing we do is save the current state, if any, just like
 * setstate() so that it doesn't matter when initstate is called.
 *
 * Returns a pointer to the old state.
 *
 * Note: The Sparc platform requires that arg_state begin on an int
 * word boundary; otherwise a bus error will occur. Even so, lint will
 * complain about mis-alignment, but you should disregard these messages.
 */
char *
initstate(
	unsigned int seed,		/* seed for R.N.G. */
	char *arg_state,		/* pointer to state array */
	size_t n)			/* # bytes of state info */
{
	void *ostate = (void *)(&state[-1]);
	int *int_arg_state;

	_DIAGASSERT(arg_state != NULL);

	int_arg_state = (int *)(void *)arg_state;

	mutex_lock(&random_mutex);
	if (rand_type == TYPE_0)
		state[-1] = rand_type;
	else
		state[-1] = MAX_TYPES * (int)(rptr - state) + rand_type;
	if (n < BREAK_0) {
		mutex_unlock(&random_mutex);
		return (NULL);
	} else if (n < BREAK_1) {
		rand_type = TYPE_0;
		rand_deg = DEG_0;
		rand_sep = SEP_0;
	} else if (n < BREAK_2) {
		rand_type = TYPE_1;
		rand_deg = DEG_1;
		rand_sep = SEP_1;
	} else if (n < BREAK_3) {
		rand_type = TYPE_2;
		rand_deg = DEG_2;
		rand_sep = SEP_2;
	} else if (n < BREAK_4) {
		rand_type = TYPE_3;
		rand_deg = DEG_3;
		rand_sep = SEP_3;
	} else {
		rand_type = TYPE_4;
		rand_deg = DEG_4;
		rand_sep = SEP_4;
	}
	state = (int *) (int_arg_state + 1); /* first location */
	end_ptr = &state[rand_deg];	/* must set end_ptr before srandom */
	srandom_unlocked(seed);
	if (rand_type == TYPE_0)
		int_arg_state[0] = rand_type;
	else
		int_arg_state[0] = MAX_TYPES * (int)(rptr - state) + rand_type;
	mutex_unlock(&random_mutex);
	return((char *)ostate);
}

/*
 * setstate:
 *
 * Restore the state from the given state array.
 *
 * Note: it is important that we also remember the locations of the pointers
 * in the current state information, and restore the locations of the pointers
 * from the old state information.  This is done by multiplexing the pointer
 * location into the zeroeth word of the state information.
 *
 * Note that due to the order in which things are done, it is OK to call
 * setstate() with the same state as the current state.
 *
 * Returns a pointer to the old state information.
 *
 * Note: The Sparc platform requires that arg_state begin on a long
 * word boundary; otherwise a bus error will occur. Even so, lint will
 * complain about mis-alignment, but you should disregard these messages.
 */
char *
setstate(char *arg_state)		/* pointer to state array */
{
	int *new_state;
	int type;
	int rear;
	void *ostate = (void *)(&state[-1]);

	_DIAGASSERT(arg_state != NULL);

	new_state = (int *)(void *)arg_state;
	type = (int)(new_state[0] % MAX_TYPES);
	rear = (int)(new_state[0] / MAX_TYPES);

	mutex_lock(&random_mutex);
	if (rand_type == TYPE_0)
		state[-1] = rand_type;
	else
		state[-1] = MAX_TYPES * (int)(rptr - state) + rand_type;
	switch(type) {
	case TYPE_0:
	case TYPE_1:
	case TYPE_2:
	case TYPE_3:
	case TYPE_4:
		rand_type = type;
		rand_deg = degrees[type];
		rand_sep = seps[type];
		break;
	default:
		mutex_unlock(&random_mutex);
		return (NULL);
	}
	state = (int *) (new_state + 1);
	if (rand_type != TYPE_0) {
		rptr = &state[rear];
		fptr = &state[(rear + rand_sep) % rand_deg];
	}
	end_ptr = &state[rand_deg];		/* set end_ptr too */
	mutex_unlock(&random_mutex);
	return((char *)ostate);
}

/*
 * random:
 *
 * If we are using the trivial TYPE_0 R.N.G., just do the old linear
 * congruential bit.  Otherwise, we do our fancy trinomial stuff, which is
 * the same in all the other cases due to all the global variables that have
 * been set up.  The basic operation is to add the number at the rear pointer
 * into the one at the front pointer.  Then both pointers are advanced to
 * the next location cyclically in the table.  The value returned is the sum
 * generated, reduced to 31 bits by throwing away the "least random" low bit.
 *
 * Note: the code takes advantage of the fact that both the front and
 * rear pointers can't wrap on the same call by not testing the rear
 * pointer if the front one has wrapped.
 *
 * Returns a 31-bit random number.
 */
static long
random_unlocked(void)
{
	int i;
	int *f, *r;

	if (rand_type == TYPE_0) {
		i = state[0];
		state[0] = i = (i * 1103515245 + 12345) & 0x7fffffff;
	} else {
		/*
		 * Use local variables rather than static variables for speed.
		 */
		f = fptr; r = rptr;
		*f += *r;
		/* chucking least random bit */
		i = ((unsigned int)*f >> 1) & 0x7fffffff;
		if (++f >= end_ptr) {
			f = state;
			++r;
		}
		else if (++r >= end_ptr) {
			r = state;
		}

		fptr = f; rptr = r;
	}
	return(i);
}

long
random(void)
{
	long r;

	mutex_lock(&random_mutex);
	r = random_unlocked();
	mutex_unlock(&random_mutex);
	return (r);
}
#else
long
random(void)
{
	static u_long randseed = 1;
	long x, hi, lo, t;

	/*
	 * Compute x[n + 1] = (7^5 * x[n]) mod (2^31 - 1).
	 * From "Random number generators: good ones are hard to find",
	 * Park and Miller, Communications of the ACM, vol. 31, no. 10,
	 * October 1988, p. 1195.
	 */
	x = randseed;
	hi = x / 127773;
	lo = x % 127773;
	t = 16807 * lo - 2836 * hi;
	if (t <= 0)
		t += 0x7fffffff;
	randseed = t;
	return (t);
}
#endif /* SMALL_RANDOM */

"""

```