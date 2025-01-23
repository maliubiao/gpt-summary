Response:
Let's break down the thought process to generate the comprehensive answer about `reallocarr.c`.

**1. Understanding the Request:**

The request asks for a deep dive into the `reallocarr.c` source code, focusing on its functionality, relationship with Android, implementation details, dynamic linking aspects, usage errors, and how it's reached from the Android framework/NDK, along with a Frida hook example. The key is to address each point systematically.

**2. Initial Code Analysis:**

* **Purpose:** The code defines a function `reallocarr`. The name suggests it's a variant of `realloc` that deals with allocating arrays of elements.
* **Licensing:**  The copyright and licensing information indicate it originates from NetBSD. This is important for context (it's an upstream component).
* **Includes:**  Standard C library headers (`errno.h`, `limits.h`, `stdint.h`, `stdlib.h`, `string.h`) and some conditional includes (`nbtool_config.h`, `namespace.h`). These give clues about the function's dependencies and environment.
* **Weak Alias:** The `__weak_alias` macro suggests a way to provide a default implementation if a stronger symbol isn't present.
* **`SQRT_SIZE_MAX`:** This constant hints at an overflow check during multiplication.
* **`HAVE_REALLOCARR`:** The `#if !HAVE_REALLOCARR` preprocessor directive indicates this code provides an implementation of `reallocarr` only if it's not already present. This is crucial for understanding its role in a larger system.

**3. Deconstructing `reallocarr`'s Logic:**

* **Input:** The function takes a pointer to a pointer (`void *ptr`), a number of elements (`size_t number`), and the size of each element (`size_t size`).
* **Error Handling:** It saves and restores `errno`.
* **Zero Size/Number:** If either `number` or `size` is zero, it frees the original memory (if any) and sets the input pointer to `NULL`.
* **Overflow Check:** The code includes a clever check for potential integer overflow when calculating the total allocation size (`number * size`). It uses `SQRT_SIZE_MAX` to avoid a direct multiplication that might overflow before the check. The `__predict_false` suggests this is an optimization for the common case where overflow doesn't occur.
* **Actual Allocation:** It calls the standard `realloc` function to resize the memory block.
* **Updating the Pointer:** If `realloc` is successful, it updates the pointer pointed to by the input `ptr` with the new address.
* **Return Value:** It returns 0 on success or an error code (specifically `EOVERFLOW` for multiplication overflow).

**4. Connecting to Android:**

* **Bionic:** The problem statement explicitly mentions Bionic. Knowing that this code is part of Bionic's libc is the crucial link.
* **Upstream NetBSD:** Recognizing the NetBSD origin is important. It means Bionic likely adopted this implementation from NetBSD.
* **Android's Memory Management:** `reallocarr` fits into Android's memory management strategy. It provides a safer way to reallocate memory for arrays.

**5. Dynamic Linking (Less Relevant Here):**

The code itself doesn't directly interact with the dynamic linker in a complex way. The `__weak_alias` is a linker feature, but its usage is straightforward. No explicit calls to dynamic linker APIs are present. Therefore, the focus on dynamic linking should be on how `reallocarr` *itself* is linked into executables.

**6. Usage Errors and Examples:**

Think about common pitfalls when using memory allocation functions:

* **Forgetting to check for `NULL`:** This is a classic error with `malloc` and `realloc`.
* **Integer overflow:**  This is precisely what `reallocarr` tries to prevent.
* **Dangling pointers:** Freeing memory and then trying to access it.

**7. Android Framework/NDK Path and Frida Hook:**

* **Framework/NDK Call Stack:** Trace back how an allocation might occur in Android. Consider scenarios:
    * Java code allocating arrays (leading to JNI calls).
    * Native code in the NDK using `new` or `malloc`/`realloc`.
    * System services written in C/C++.
* **Frida Hooking:** The key is to target the `reallocarr` function within the `libc.so` library. Frida needs the function name and the library where it resides.

**8. Structuring the Answer:**

Organize the information logically, addressing each part of the request:

* **Functionality:** Start with a clear, concise summary of what `reallocarr` does.
* **Android Relationship:** Explain its role in Bionic and why it's important.
* **Implementation Details:**  Go through the code section by section, explaining the purpose of each part.
* **Dynamic Linking:**  Describe how `reallocarr` is linked and mention the weak alias. Provide a simple SO layout example.
* **Logic Reasoning (Overflow):**  Explain the overflow prevention mechanism with an example.
* **Usage Errors:** Illustrate common mistakes with code snippets.
* **Android Path & Frida:** Detail how the function is reached and provide a functional Frida hook example.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `reallocarr` directly uses system calls for memory management. **Correction:** It calls the standard `realloc`, simplifying its role.
* **Initial thought:**  The dynamic linking section needs to be very detailed. **Correction:** The interaction with the dynamic linker is relatively simple in this case; focus on the linking of the function itself.
* **Frida hook:**  Ensure the Frida code is correct and targets the right function and library. Test the hook mentally to see if it would work.

By following these steps, the detailed and accurate answer provided in the initial example can be constructed. The process involves understanding the code, connecting it to the broader Android context, explaining technical details clearly, and anticipating potential questions and areas of interest.
好的，我们来详细分析一下 `bionic/libc/upstream-netbsd/lib/libc/stdlib/reallocarr.c` 这个文件。

**1. 功能列举**

`reallocarr` 函数的主要功能是：

* **安全地重新分配内存块**：它类似于 `realloc`，但专门用于重新分配数组内存。它接收一个指向已分配内存的指针、数组元素的数量以及每个元素的大小作为参数。
* **防止整数溢出**：`reallocarr` 的核心特点是在计算总的内存分配大小时（`number * size`）会进行整数溢出检查。如果 `number * size` 的结果超过了 `size_t` 的最大值，它将返回错误（`EOVERFLOW`），而不是导致未定义的行为。
* **处理零大小/数量的情况**：如果 `number` 或 `size` 为 0，它会释放 `ptr` 指向的内存（如果 `ptr` 不为空），并将传入的 `ptr` 指向的指针设置为 `NULL`。
* **封装 `realloc`**：在通过溢出检查后，`reallocarr` 最终会调用标准的 `realloc` 函数来实际执行内存的重新分配。

**2. 与 Android 功能的关系及举例说明**

`reallocarr` 是 Android Bionic C 库的一部分，因此直接影响到 Android 系统和应用程序的内存管理。

**举例说明：**

假设一个 Android 应用需要动态调整一个存储用户信息的数组的大小。

```c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

typedef struct {
    char name[32];
    int age;
} UserInfo;

int main() {
    UserInfo *users = NULL;
    size_t num_users = 0;
    size_t new_num_users = 10;

    // 初始分配
    users = (UserInfo *)malloc(new_num_users * sizeof(UserInfo));
    if (users == NULL) {
        perror("malloc failed");
        return 1;
    }
    num_users = new_num_users;

    // 假设需要增加数组大小
    new_num_users = 20;
    int result = reallocarr(&users, new_num_users, sizeof(UserInfo));
    if (result != 0) {
        fprintf(stderr, "reallocarr failed with error: %d\n", result);
        free(users); // 记得释放之前分配的内存
        return 1;
    }

    printf("Memory reallocated successfully.\n");

    // ... 使用 users 数组 ...

    free(users);
    return 0;
}
```

在这个例子中，如果使用普通的 `realloc`，当 `new_num_users` 非常大时，`new_num_users * sizeof(UserInfo)` 可能会发生整数溢出，导致 `realloc` 分配一个非常小的内存块，甚至导致程序崩溃。而使用 `reallocarr`，它会在计算大小之前进行溢出检查，如果发生溢出，会返回 `EOVERFLOW` 错误，从而避免了潜在的风险。

**3. libc 函数的实现详解**

下面详细解释 `reallocarr` 函数的实现：

```c
int
reallocarr(void *ptr, size_t number, size_t size)
{
	int saved_errno, result;
	void *optr;
	void *nptr;

	saved_errno = errno; // 保存当前的 errno 值，因为后续操作可能会修改它
	memcpy(&optr, ptr, sizeof(ptr)); // 从 ptr 指向的地址读取指针值到 optr。这里 ptr 是一个指向指针的指针。
	if (number == 0 || size == 0) {
		free(optr); // 如果元素数量或大小为 0，则释放原有的内存
		nptr = NULL;
		memcpy(ptr, &nptr, sizeof(ptr)); // 将 ptr 指向的指针设置为 NULL
		errno = saved_errno; // 恢复之前的 errno 值
		return 0; // 返回成功
	}

	/*
	 * Try to avoid division here.
	 *
	 * It isn't possible to overflow during multiplication if neither
	 * operand uses any of the most significant half of the bits.
	 */
	if (__predict_false((number|size) >= SQRT_SIZE_MAX &&
	                    number > SIZE_MAX / size)) {
		errno = saved_errno; // 恢复之前的 errno 值
		return EOVERFLOW; // 返回溢出错误
	}

	nptr = realloc(optr, number * size); // 调用标准的 realloc 进行内存重新分配
	if (__predict_false(nptr == NULL)) {
		result = errno; // 如果 realloc 失败，记录 errno
	} else {
		result = 0; // realloc 成功
		memcpy(ptr, &nptr, sizeof(ptr)); // 将新的内存地址写回 ptr 指向的指针
	}
	errno = saved_errno; // 恢复之前的 errno 值
	return result; // 返回结果
}
```

* **`saved_errno = errno;` 和 `errno = saved_errno;`**:  这是为了保证函数调用不会意外地修改全局的 `errno` 值。在函数开始时保存 `errno`，在结束时恢复，是一种良好的实践。
* **`memcpy(&optr, ptr, sizeof(ptr));`**:  由于 `ptr` 是一个 `void **`，即指向指针的指针，我们需要先取出它所指向的实际指针值。这里使用 `memcpy` 将 `ptr` 指向的内存内容（即原始指针的地址）复制到 `optr` 变量中。
* **`if (number == 0 || size == 0)`**: 如果请求分配的大小为 0，则相当于要求释放内存。`free(optr)` 释放之前的内存，并将调用者提供的指针（通过 `ptr` 传递）设置为 `NULL`。
* **溢出检查**:
    * `SQRT_SIZE_MAX` 被定义为 `(((size_t)1) << (sizeof(size_t) * CHAR_BIT / 2))`，它大约是 `size_t` 最大值的平方根。
    * `(number|size) >= SQRT_SIZE_MAX`:  如果 `number` 或 `size` 足够大，以至于它们各自占用了一半或更多的 `size_t` 的位，那么乘法运算很可能溢出。
    * `number > SIZE_MAX / size`:  这是另一种溢出检查方式，通过除法来避免直接乘法。如果 `number` 大于 `SIZE_MAX / size`，则 `number * size` 必然会溢出。
    * `__predict_false`:  这是一个编译器提示，表明括号内的条件很可能为假。这是一种性能优化，允许编译器进行相应的指令重排。
* **`nptr = realloc(optr, number * size);`**:  如果通过了溢出检查，则调用标准的 `realloc` 函数来尝试重新分配内存。`realloc` 尝试在原地扩展内存块，如果无法扩展，则会分配新的内存块，将旧数据复制过去，并释放旧的内存块。
* **`memcpy(ptr, &nptr, sizeof(ptr));`**:  如果 `realloc` 成功，`nptr` 指向新的内存块。我们需要更新调用者提供的指针，使其指向新的内存。同样使用 `memcpy` 将新指针的地址写回 `ptr` 指向的内存位置。
* **返回值**: 成功时返回 0，失败时返回一个非零的错误码（通常是 `EOVERFLOW`）。

**4. 涉及 dynamic linker 的功能**

在这个 `reallocarr.c` 文件中，并没有直接涉及动态链接器的复杂功能。`__weak_alias` 宏是与链接器相关的，但它的作用相对简单。

* **`__weak_alias(reallocarr, _reallocarr)`**:  这是一个 GNU 扩展，用于声明一个弱符号别名。它的意思是，如果在链接时找到了名为 `reallocarr` 的强符号定义，则使用该定义；否则，使用当前文件中 `_reallocarr` 的定义作为 `reallocarr` 的实现。这通常用于提供默认实现，允许其他库或应用程序提供更优化的版本。

**so 布局样本和链接处理过程：**

假设 `reallocarr.c` 被编译到 `libc.so` 中。

**`libc.so` 布局样本 (简化)：**

```
.text  # 存放代码段
    ...
    reallocarr:  # reallocarr 函数的入口地址
        <reallocarr 的机器码>
    _reallocarr: # _reallocarr 函数的入口地址 (与 reallocarr 相同，因为是弱别名)
        <reallocarr 的机器码>
    ...
.data  # 存放已初始化的全局变量和静态变量
    ...
.bss   # 存放未初始化的全局变量和静态变量
    ...
.dynsym # 动态符号表
    ...
    reallocarr  # 符号名
    _reallocarr # 符号名
    ...
.dynstr # 动态字符串表 (存放符号名)
    ...
    reallocarr
    _reallocarr
    ...
```

**链接处理过程：**

1. **编译**: `reallocarr.c` 被编译成目标文件 `reallocarr.o`。
2. **链接**:  `reallocarr.o` 与其他 libc 的目标文件被链接器（如 `ld`）链接成共享库 `libc.so`。
3. **符号解析**: 当其他程序或库（例如 `libutils.so`）调用 `reallocarr` 时，动态链接器会负责解析这个符号。
4. **弱符号处理**:
   * 如果在链接时，其他目标文件中定义了 `reallocarr` 的强符号（例如，某个自定义的内存分配器），那么动态链接器会优先使用那个强符号的定义。
   * 如果没有找到强符号 `reallocarr`，动态链接器会使用 `libc.so` 中 `_reallocarr` 的定义（由于 `__weak_alias`，它实际上就是 `reallocarr` 的实现）。

**5. 逻辑推理：假设输入与输出**

**假设输入 1：**

* `ptr`: 指向一块已分配了 10 个 `int` 的内存的指针的地址（假设该内存地址为 0x1000）
* `number`: 20
* `size`: `sizeof(int)`

**预期输出：**

* 函数成功执行，返回 0。
* `ptr` 指向的地址会更新为新的内存块的地址（可能与 0x1000 相同，也可能不同）。
* 新的内存块大小为 `20 * sizeof(int)` 字节。

**假设输入 2（溢出）：**

* `ptr`: 指向一块已分配内存的指针的地址
* `number`: `SIZE_MAX`
* `size`: 2

**预期输出：**

* 函数返回 `EOVERFLOW`。
* `ptr` 指向的地址不会改变。
* `errno` 被设置为 `EOVERFLOW`。

**假设输入 3（释放内存）：**

* `ptr`: 指向一块已分配内存的指针的地址（假设该内存地址为 0x2000）
* `number`: 0
* `size`: 10

**预期输出：**

* 函数成功执行，返回 0。
* 地址 0x2000 的内存被释放。
* `ptr` 指向的地址被设置为 `NULL`。

**6. 用户或编程常见的使用错误**

* **忘记检查返回值**:  `reallocarr` 可能会返回错误（`EOVERFLOW`），程序员必须检查返回值以确保内存分配成功。如果不检查，可能会导致程序使用未分配的内存。
    ```c
    int result = reallocarr(&ptr, new_size, sizeof(int));
    // 缺少对 result 的检查
    // ... 尝试使用 ptr ... // 如果 reallocarr 失败，ptr 可能还是旧的，或者为 NULL
    ```
* **假设原地重新分配总是成功**: `reallocarr` 内部的 `realloc` 不保证在原地扩展内存。如果分配了新的内存块，旧的内存块会被释放。因此，不能依赖旧的指针仍然有效。
* **多次 `free`**:  如果 `reallocarr` 内部的 `realloc` 失败并返回错误，原始的内存块并没有被释放。如果在这种情况下又尝试 `free` 原始指针，会导致 double free 错误。
    ```c
    int result = reallocarr(&ptr, new_size, sizeof(int));
    if (result != 0) {
        free(original_ptr); // 如果 reallocarr 失败，ptr 和 original_ptr 指向同一块内存
    }
    ```
* **整数溢出风险 (如果使用不当)**: 即使使用了 `reallocarr`，程序员仍然需要注意传入的 `number` 和 `size` 的值，避免在调用 `reallocarr` 之前就发生了溢出。例如，如果 `number * size` 的计算结果溢出，然后将溢出的结果传递给 `reallocarr`，那么溢出检查就失去了意义。

**7. Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例**

**Android Framework 或 NDK 到达 `reallocarr` 的路径：**

1. **Java Framework 层**: Android Framework 的 Java 代码经常需要操作大量的数组或缓冲区。当需要调整这些数据结构的大小时，Framework 可能会调用 Native 代码（通常通过 JNI）。
2. **JNI 调用**: Java 代码通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。
3. **NDK 代码**:  Android NDK 提供的库（如 `libandroid.so`, 自定义的 Native 库）以及 Framework 的 Native 组件中，会使用标准的 C 库函数进行内存管理，包括 `malloc`, `calloc`, `realloc` 和 `free`。
4. **`realloc` 的间接调用**: 虽然代码中可能直接调用 `realloc`，但在某些情况下，为了安全性和额外的检查，可能会使用类似 `reallocarr` 这样的包装函数。Framework 或 NDK 中的某些组件可能选择使用 `reallocarr` 来重新分配数组内存。
5. **Bionic libc**:  最终，`reallocarr` 的实现位于 Bionic 的 `libc.so` 中。当 Native 代码调用 `reallocarr` 时，会链接到 `libc.so` 中的对应函数。

**Frida Hook 示例：**

以下是一个使用 Frida hook `reallocarr` 函数的示例：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const reallocarrPtr = libc.getExportByName("reallocarr");

  if (reallocarrPtr) {
    Interceptor.attach(reallocarrPtr, {
      onEnter: function (args) {
        const ptr = args[0];
        const number = args[1].toInt();
        const size = args[2].toInt();

        console.log("[reallocarr] Called");
        console.log("  ptr:", ptr);
        console.log("  number:", number);
        console.log("  size:", size);

        if (ptr.isNull()) {
          console.log("  Reallocating new memory.");
        } else {
          console.log("  Reallocating existing memory.");
        }
      },
      onLeave: function (retval) {
        console.log("[reallocarr] Return value:", retval);
        if (retval.toInt() === 0) {
          const newPtr = this.context.eax; // 或其他架构的寄存器
          console.log("  New memory address:", newPtr);
        } else if (retval.toInt() === 12 /* EOVERFLOW */) {
          console.log("  Error: Integer overflow detected.");
        }
      }
    });

    console.log("Frida hook attached to reallocarr");
  } else {
    console.error("reallocarr function not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**代码解释：**

1. **检查平台**: 确保脚本在 Android 平台上运行。
2. **获取 `libc.so` 模块**: 使用 `Process.getModuleByName` 获取 `libc.so` 的模块对象。
3. **获取 `reallocarr` 函数地址**: 使用 `libc.getExportByName` 获取 `reallocarr` 函数的地址。
4. **附加 Interceptor**: 使用 `Interceptor.attach` 拦截对 `reallocarr` 函数的调用。
   * **`onEnter`**: 在函数执行前调用。打印传入的参数，包括指向指针的指针的地址、元素数量和元素大小。
   * **`onLeave`**: 在函数执行后调用。打印返回值，如果成功，还尝试获取新的内存地址（注意，获取寄存器的值可能因架构而异）。如果返回值为 `EOVERFLOW`，则打印相应的错误信息。

**运行 Frida Hook：**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `reallocarr_hook.js`）。
2. 使用 Frida 连接到 Android 设备或模拟器上的目标进程：
   ```bash
   frida -U -f <package_name> -l reallocarr_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l reallocarr_hook.js
   ```
   将 `<package_name>` 替换为目标应用的包名。

当目标应用调用 `reallocarr` 时，Frida 会拦截调用并执行 `onEnter` 和 `onLeave` 中定义的代码，将相关信息输出到控制台。这可以帮助你理解 `reallocarr` 何时被调用，传入了哪些参数，以及返回了什么结果。

希望这个详细的分析能够帮助你理解 `bionic/libc/upstream-netbsd/lib/libc/stdlib/reallocarr.c` 文件的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/stdlib/reallocarr.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/* $NetBSD: reallocarr.c,v 1.5 2015/08/20 22:27:49 kamil Exp $ */

/*-
 * Copyright (c) 2015 Joerg Sonnenberger <joerg@NetBSD.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if HAVE_NBTOOL_CONFIG_H
#include "nbtool_config.h"
#endif

#include <sys/cdefs.h>
__RCSID("$NetBSD: reallocarr.c,v 1.5 2015/08/20 22:27:49 kamil Exp $");

#include "namespace.h"
#include <errno.h>
/* Old POSIX has SIZE_MAX in limits.h */
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _LIBC
#ifdef __weak_alias
__weak_alias(reallocarr, _reallocarr)
#endif
#endif

#define SQRT_SIZE_MAX (((size_t)1) << (sizeof(size_t) * CHAR_BIT / 2))

#if !HAVE_REALLOCARR
int
reallocarr(void *ptr, size_t number, size_t size)
{
	int saved_errno, result;
	void *optr;
	void *nptr;

	saved_errno = errno;
	memcpy(&optr, ptr, sizeof(ptr));
	if (number == 0 || size == 0) {
		free(optr);
		nptr = NULL;
		memcpy(ptr, &nptr, sizeof(ptr));
		errno = saved_errno;
		return 0;
	}

	/*
	 * Try to avoid division here.
	 *
	 * It isn't possible to overflow during multiplication if neither
	 * operand uses any of the most significant half of the bits.
	 */
	if (__predict_false((number|size) >= SQRT_SIZE_MAX &&
	                    number > SIZE_MAX / size)) {
		errno = saved_errno;
		return EOVERFLOW;
	}

	nptr = realloc(optr, number * size);
	if (__predict_false(nptr == NULL)) {
		result = errno;
	} else {
		result = 0;
		memcpy(ptr, &nptr, sizeof(ptr));
	}
	errno = saved_errno;
	return result;
}
#endif
```