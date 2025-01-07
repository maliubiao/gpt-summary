Response:
Let's break down the thought process for answering this complex question about `strlen_generic.c`.

**1. Understanding the Core Request:**

The fundamental request is to analyze the given `strlen_generic.c` source code. This involves understanding its functionality, its relationship to Android, how it's implemented, its interaction with the dynamic linker (if any), potential issues, and how it's used within the Android ecosystem.

**2. Initial Code Examination and Function Identification:**

The first step is to read through the code. Key elements immediately stand out:

*   **`strlen_generic` function:** This is the main function under scrutiny. Its name suggests a generic implementation of `strlen`.
*   **Header includes:**  `<string.h>` and `<stdint.h>` indicate standard string operations and fixed-width integer types are used.
*   **Copyright notice:**  Confirms it's part of the Android Open Source Project.
*   **`__builtin_prefetch`:** Hints at performance optimizations by pre-loading data into the cache.
*   **`union`:**  Used for type punning to access the string as bytes or words (32-bit).
*   **Assembly code block (`asm(...)`):** This is the performance-critical part and will require careful analysis.
*   **Looping structure:**  Both a `while` loop for initial alignment and the `asm` block represent the core logic.
*   **Bitwise operations:**  Within the assembly, operations like `lsr`, `and`, `bics`, and `tst` are used to check for null bytes efficiently.

**3. Deconstructing Functionality:**

Based on the code, the function's purpose is clearly to calculate the length of a null-terminated string. The implementation employs several optimizations:

*   **Prefetching:**  Anticipates data access to improve cache hit rates.
*   **Word-aligned access:** Processes data in 32-bit chunks for efficiency.
*   **Assembly optimization:**  Uses low-level instructions for fast null byte detection.

**4. Android Relevance:**

Since the file path (`bionic/libc/...`) explicitly indicates it's part of Bionic, Android's C library, the connection to Android is direct. Every Android process that uses standard C library functions like `strlen` potentially uses this implementation.

**5. Detailed Implementation Explanation:**

This requires a step-by-step breakdown of the code:

*   **Prefetching:** Explain the purpose of `__builtin_prefetch`.
*   **Union and Alignment:**  Describe how the union is used for type casting and the initial `while` loop aligns the pointer.
*   **Assembly Block:** This is the most complex part. Each assembly instruction needs to be deciphered:
    *   `ldr`: Load word.
    *   `sub`: Subtract.
    *   `pld`: Prefetch data.
    *   `lsr`: Logical shift right.
    *   `and`: Bitwise AND.
    *   `bics`: Bitwise AND NOT, setting flags.
    *   `bne`: Branch if not equal.
    *   `tst`: Test bits.
    *   `beq`: Branch if equal.
    *   Explain the masking technique (`0x80808080UL`) to detect null bytes within a word.
    *   Explain the loop unrolling (multiple `ldr` blocks) for performance.
*   **Post-Assembly Check:** Explain how the code after the assembly block handles the case where a null byte is found within a word.

**6. Dynamic Linker and SO Layout:**

The `strlen` function itself *doesn't directly involve* the dynamic linker. It's a standard C library function. However, it *is part of* `libc.so`, which *is* loaded by the dynamic linker.

*   **SO Layout:** Describe the general structure of a shared object (.so) file (e.g., .text, .data, .bss, .plt, .got).
*   **Linking Process:** Explain how the dynamic linker resolves symbols like `strlen` when an application uses it. This involves the PLT (Procedure Linkage Table) and GOT (Global Offset Table).

**7. Logic, Assumptions, and Input/Output:**

Provide simple examples to illustrate `strlen`'s behavior:

*   Empty string: `""` -> output `0`
*   Short string: `"abc"` -> output `3`
*   String with null in the middle (important to note it stops at the first null): `"abc\0def"` -> output `3`

**8. Common Usage Errors:**

Focus on the most frequent mistake:

*   **Not null-terminating strings:** Explain the consequences of passing a character array without a null terminator to `strlen`. This leads to reading beyond the intended memory, causing crashes or unexpected behavior.

**9. Android Framework/NDK and Frida Hooking:**

*   **Framework/NDK Path:** Illustrate how a call to `strlen` might originate from Java code in the Android Framework, be passed down through JNI to native code, and eventually reach the Bionic `strlen` implementation. Give a simple example.
*   **Frida Hooking:** Provide a concrete Frida script example to intercept calls to `strlen`. This demonstrates how to observe the function's arguments and return value at runtime.

**10. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use formatting (bolding, code blocks) to improve readability.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:**  Maybe `strlen` has some complex interaction with the dynamic linker itself. **Correction:** Realized it's more about `strlen` *being part of* a shared object loaded by the linker. Focus shifted to the PLT/GOT mechanism.
*   **Overly technical assembly explanation:**  Realized the need to balance technical detail with clarity for a broader audience. Added explanations of the high-level logic behind the assembly optimizations.
*   **Missing practical examples:**  Added input/output examples and the Frida hook to make the explanation more tangible.
*   **Lack of clear connection to Android:** Explicitly outlined the path from Android Framework/NDK to `strlen` to strengthen the connection.

By following this detailed thought process, incorporating corrections and refinements, a comprehensive and accurate answer can be constructed to address all aspects of the original prompt.
好的，让我们详细分析一下 `bionic/libc/arch-arm/generic/bionic/strlen.c` 这个文件。

**功能列举:**

这个文件定义了一个名为 `strlen_generic` 的函数，其主要功能是：

1. **计算以 null 结尾的字符串的长度。**  它接收一个指向字符数组（字符串）的指针 `s` 作为输入，并返回字符串中字符的个数，不包括结尾的 null 字符 `\0`。

**与 Android 功能的关系及举例说明:**

`strlen` 是一个标准的 C 库函数，在所有 C 程序中都非常常用。由于 bionic 是 Android 的 C 库，因此 `strlen_generic` 是 Android 系统中用于计算字符串长度的基础函数之一。

**举例说明:**

*   **Android Framework (Java 代码):**  许多 Android Framework 的 Java 代码在处理字符串时，最终会通过 JNI (Java Native Interface) 调用到 Native 代码。在 Native 代码中，如果需要获取字符串的长度，很可能会调用 `strlen`。例如，在处理文件路径、用户输入、网络数据等场景中，都可能用到 `strlen`。
*   **NDK 开发:** 使用 Android NDK 进行 Native 开发的开发者，可以直接调用 `strlen` 函数。例如，在实现一个处理字符串的 Native 库时，就需要使用 `strlen` 来获取字符串长度。
*   **系统服务:** Android 的许多系统服务是用 C++ 或 C 实现的，它们在内部处理字符串时也会用到 `strlen`。

**libc 函数 `strlen_generic` 的实现解释:**

`strlen_generic` 的实现采用了一些优化技巧来提高性能，尤其是在 ARM 架构上。以下是代码的详细解释：

1. **预取 (Prefetching):**
    ```c
    __builtin_prefetch(s);
    __builtin_prefetch(s+32);
    ```
    这两行代码使用了 GCC 的内建函数 `__builtin_prefetch`。其目的是提前将字符串 `s` 指向的内存及其后 32 字节的数据加载到 CPU 的缓存中。这可以减少实际访问内存时的延迟，提高程序的执行效率，特别是当处理较长的字符串时。

2. **联合体 (Union) `u`:**
    ```c
    union {
        const char      *b;
        const uint32_t  *w;
        uintptr_t       i;
    } u;
    ```
    定义了一个联合体 `u`，它可以以不同的方式查看同一块内存：
    *   `u.b`: 将内存视为指向字符的指针。
    *   `u.w`: 将内存视为指向 32 位无符号整数的指针。
    *   `u.i`: 将内存视为一个无符号整数指针，用于进行地址对齐判断。

3. **变量初始化:**
    ```c
    uint32_t v, t;
    size_t l = 0;
    ```
    *   `v` 和 `t` 是用于汇编代码中的临时变量。
    *   `l` 初始化为 0，用于存储字符串的长度。

4. **地址对齐:**
    ```c
    u.b = s;
    while (u.i & 0x3)  {
        if (__builtin_expect(*u.b++ == 0, 0)) {
            goto done;
        }
        l++;
    }
    ```
    这段代码的目的是将指针 `u.b` (即原始字符串指针 `s`) 对齐到 4 字节边界。这是因为在 ARM 架构上，对齐的内存访问通常更高效。
    *   `u.i & 0x3` 检查指针的低两位是否为 0，如果不是 0，则说明未对齐。
    *   循环每次检查一个字节，如果遇到 null 字符，则跳转到 `done` 标签。
    *   否则，长度 `l` 加 1，指针 `u.b` 移动到下一个字节。
    *   `__builtin_expect(*u.b++ == 0, 0)` 是一个编译器的提示，告诉编译器通常情况下 `*u.b++ == 0` 的结果是 `false` (即字符串没有立即结束)，这有助于编译器进行优化。

5. **汇编代码优化:**
    ```assembly
    asm(
        "ldr     %[v], [%[s]], #4           \n" // 加载一个字（4字节）到 v，s 指向下一个字
        "sub     %[l], %[l], %[s]           \n" // 计算当前已处理的字节数
        "0:                                 \n" // 循环标签
        "pld     [%[s], #64]                \n" // 预取 s 指针后 64 字节的数据
        "sub     %[t], %[v], %[mask], lsr #7\n" // 将每个字节的最高位移到最低位
        "and     %[t], %[t], %[mask]        \n" // 保留每个字节的最高位
        "bics    %[t], %[t], %[v]           \n" // 如果字节为 0，则最高位为 0，结果为 0
        "bne     1f                         \n" // 如果 t 不为 0，说明当前字中存在 null 字节，跳转到 1f
        "ldr     %[v], [%[s]], #4           \n" // 加载下一个字

        // ... (重复多次加载和检查，实现循环展开) ...

        "b       0b                         \n" // 无条件跳转到循环开始

        "1:                                 \n" // 找到 null 字节
        "add     %[l], %[l], %[s]           \n" // 将已处理的字数加到长度上
        "tst     %[v], #0xFF                \n" // 检查最低字节是否为 null
        "beq     2f                         \n" // 如果是，跳转到 2f
        "add     %[l], %[l], #1             \n" // 否则，长度加 1
        "tst     %[v], #0xFF00              \n" // 检查下一个字节
        "beq     2f                         \n"
        "add     %[l], %[l], #1             \n"
        "tst     %[v], #0xFF0000            \n"
        "beq     2f                         \n"
        "add     %[l], %[l], #1             \n"
        "2:                                 \n" // 完成
        : [l]"=&r"(l), [v]"=&r"(v), [t]"=&r"(t), [s]"=&r"(u.b) // 输出操作数
        : "%[l]"(l), "%[s]"(u.b), [mask]"r"(0x80808080UL)    // 输入操作数
        : "cc"                                             // clobbered 列表
    );
    ```
    这段汇编代码是性能优化的核心部分。它一次处理 4 个字节（一个字）。
    *   **`ldr %[v], [%[s]], #4`**:  加载 `u.b` 指向的 4 字节数据到寄存器 `v` 中，并将 `u.b` 指针向前移动 4 个字节。
    *   **`sub %[l], %[l], %[s]`**: 由于 `l` 初始为 0，且每次循环 `s` 都增加 4，这里巧妙地计算了已经处理了多少个完整的 4 字节块。
    *   **`pld [%[s], #64]`**: 预取 `u.b` 指针后 64 字节的数据。
    *   **`sub %[t], %[v], %[mask], lsr #7` 和 `and %[t], %[t], %[mask]`**:  这两步操作使用了一个巧妙的技巧来检查一个字中是否包含 null 字节。`mask` 的值为 `0x80808080UL`。通过右移 7 位并与 `mask` 进行与操作，可以将每个字节的最高位提取出来。如果一个字节是 0，那么它的最高位也是 0。
    *   **`bics %[t], %[t], %[v]`**:  `bics` 指令执行按位与非操作，并将结果写回第一个操作数。如果 `v` 中包含 null 字节，那么对应的字节最高位为 0，`t` 中相应的位也是 0。如果 `t` 最终为 0，说明当前字中没有 null 字节。
    *   **`bne 1f`**: 如果 `t` 不为 0，说明当前字中存在 null 字节，跳转到标签 `1f`。
    *   **循环展开:** 代码中多次重复加载和检查的操作是为了实现循环展开，减少循环跳转的开销，提高性能。
    *   **标签 `1f` 后的代码:** 当找到 null 字节后，需要精确定位 null 字节的位置。通过逐字节检查 `v` 中的内容来确定 null 字节在哪个位置，并更新长度 `l`。

6. **处理剩余的字节:**
    ```c
    done:
    return l;
    ```
    如果字符串长度不是 4 的倍数，或者在对齐过程中找到了 null 字符，程序会跳转到 `done` 标签，返回计算出的长度 `l`。

**涉及 dynamic linker 的功能 (无直接涉及):**

`strlen` 函数本身是标准 C 库的一部分，其链接是由动态链接器完成的。在这个 `strlen.c` 文件中，**没有直接涉及动态链接器的代码**。

**SO 布局样本及链接的处理过程:**

`strlen_generic` 函数会被编译到 `libc.so` (或类似的共享库) 中。当一个应用程序需要使用 `strlen` 函数时，动态链接器会负责将 `libc.so` 加载到进程的地址空间，并解析 `strlen` 的符号地址。

**SO 布局样本 (简化):**

```
libc.so:
  .text:  // 存放代码段
    ...
    [strlen_generic 函数的代码]
    ...
  .data:  // 存放已初始化的全局变量和静态变量
    ...
  .bss:   // 存放未初始化的全局变量和静态变量
    ...
  .dynsym: // 动态符号表 (包含 strlen 等导出符号)
    ...
    strlen  (地址指向 .text 段中的 strlen_generic 代码)
    ...
  .dynstr: // 动态字符串表 (存储符号名称)
    ...
    strlen
    ...
  .plt:   // Procedure Linkage Table (过程链接表，用于延迟绑定)
    ...
  .got:   // Global Offset Table (全局偏移表，用于存储全局变量地址)
    ...
```

**链接的处理过程 (简化):**

1. **编译时:** 应用程序的代码在编译时，如果调用了 `strlen`，编译器会在生成的目标文件中记录一个对 `strlen` 的未解析符号引用。
2. **链接时:** 静态链接器会将应用程序的目标文件与必要的库文件链接在一起。对于动态链接的库 (如 `libc.so`)，静态链接器只会记录对这些库的依赖关系，而不会将库的代码直接嵌入到应用程序中。
3. **运行时:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载应用程序依赖的共享库 (`libc.so` 等)。
4. **符号解析:** 动态链接器会遍历加载的共享库的动态符号表 (`.dynsym`)，查找应用程序中未解析的符号 (如 `strlen`)。一旦找到匹配的符号，动态链接器会将该符号在共享库中的地址填入应用程序的全局偏移表 (`.got`) 或通过过程链接表 (`.plt`) 进行延迟绑定。
5. **函数调用:** 当应用程序执行到调用 `strlen` 的代码时，实际会跳转到 `libc.so` 中 `strlen_generic` 函数的地址执行。

**逻辑推理、假设输入与输出:**

假设输入一个字符串指针 `s` 指向 "Hello"，内存布局如下：

```
地址:     0x1000  0x1001  0x1002  0x1003  0x1004  0x1005
内容:     'H'     'e'     'l'     'l'     'o'     '\0'
```

**执行 `strlen_generic("Hello")` 的过程：**

1. **预取:**  预取 `0x1000` 和 `0x1020` 附近的数据到缓存。
2. **地址对齐:** 指针 `s` 已经对齐，跳过对齐循环。
3. **汇编代码循环:**
    *   加载 `0x1000` - `0x1003` 的内容 (H, e, l, l 的 ASCII 码) 到寄存器 `v`。
    *   检查 `v` 中是否包含 null 字节，结果为否。
    *   加载 `0x1004` - `0x1007` 的内容 (o, \0, ..., ...) 到寄存器 `v`。
    *   检查 `v` 中是否包含 null 字节，结果为是 (在第二个字节)。
    *   跳转到标签 `1f`。
4. **精确定位:** 检查 `v` 中的字节，发现第二个字节是 null。
5. **计算长度:** 长度 `l` 被更新为 5。
6. **返回:** 函数返回 5。

**假设输入与输出:**

*   **输入:** `s` 指向 "World"
    *   **输出:** 5
*   **输入:** `s` 指向 "" (空字符串)
    *   **输出:** 0
*   **输入:** `s` 指向 "A\0BC"
    *   **输出:** 1 (遇到第一个 null 字符停止)

**用户或编程常见的使用错误:**

1. **传递未以 null 结尾的字符数组:**
    ```c
    char buffer[5] = {'H', 'e', 'l', 'l', 'o'};
    size_t len = strlen(buffer); // 错误！buffer 没有 null 结尾
    ```
    在这种情况下，`strlen` 会继续读取内存，直到找到一个 null 字符，这可能会导致读取越界，产生不可预测的结果甚至程序崩溃。

2. **对空指针调用 `strlen`:**
    ```c
    char *str = NULL;
    size_t len = strlen(str); // 错误！对空指针解引用
    ```
    这将导致程序崩溃，因为 `strlen` 试图访问空指针指向的内存。

3. **缓冲区溢出:**  虽然 `strlen` 本身不会导致缓冲区溢出，但它返回的长度值经常被用于后续的字符串操作，如果使用不当，可能会导致缓冲区溢出。例如：
    ```c
    char src[] = "This is a long string";
    char dest[5];
    size_t len = strlen(src);
    if (len < sizeof(dest)) {
        strcpy(dest, src); // 如果 len >= sizeof(dest)，则会导致缓冲区溢出
    }
    ```

**Android Framework 或 NDK 如何一步步到达这里:**

**示例：从 Android Framework 的 Java 代码调用到 `strlen`**

1. **Android Framework (Java):** 假设有一个 Java 代码需要获取一个字符串的长度：
    ```java
    String text = "Hello from Java";
    int length = text.length(); // 获取 Java String 的长度
    ```
    这个 `length()` 方法是 Java String 类的内置方法。

2. **JNI 调用 (Native 代码):**  如果 Android Framework 需要将这个 Java 字符串传递给 Native 代码处理，可能会使用 JNI。例如：
    ```c++
    // C++ Native 代码
    #include <jni.h>
    #include <string.h>

    extern "C" JNIEXPORT void JNICALL
    Java_com_example_myapp_MainActivity_processString(JNIEnv *env, jobject thiz, jstring javaString) {
        const char *nativeString = env->GetStringUTFChars(javaString, 0);
        if (nativeString != nullptr) {
            size_t length = strlen(nativeString); // 调用 strlen
            // ... 使用 length 进行后续操作 ...
            env->ReleaseStringUTFChars(javaString, nativeString);
        }
    }
    ```
    在这个 Native 函数中，`env->GetStringUTFChars` 将 Java String 转换为 Native 的 `const char*` 字符串。然后，就可以调用 `strlen` 来获取其长度。

3. **Bionic `libc.so`:**  当 Native 代码调用 `strlen` 时，由于 `strlen` 是 `libc.so` 提供的函数，实际执行的代码就是 `bionic/libc/arch-arm/generic/bionic/strlen.c` 中定义的 `strlen_generic` 函数。

**Frida Hook 示例调试步骤:**

可以使用 Frida 来 Hook `strlen` 函数，观察其调用过程和参数。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.arch === 'arm') {
  const strlenPtr = Module.findExportByName("libc.so", "strlen");

  if (strlenPtr) {
    Interceptor.attach(strlenPtr, {
      onEnter: function (args) {
        const strPtr = args[0];
        const str = strPtr ? Memory.readUtf8String(strPtr) : 'NULL';
        console.log(`strlen called with arg: '${str}'`);
      },
      onLeave: function (retval) {
        console.log(`strlen returned: ${retval}`);
      }
    });
    console.log("strlen hooked!");
  } else {
    console.log("strlen not found in libc.so");
  }
} else {
  console.log("This script is for ARM architecture.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备或模拟器上安装了 Frida 服务，并且你的开发机器上安装了 Frida 客户端。

2. **运行目标应用:** 运行你想要调试的 Android 应用程序。

3. **执行 Frida Hook 脚本:** 使用 Frida 客户端连接到目标应用程序，并执行上面的 JavaScript 脚本：
    ```bash
    frida -U -f <your_application_package_name> -l strlen_hook.js --no-pause
    ```
    将 `<your_application_package_name>` 替换为你的应用程序的包名，`strlen_hook.js` 是你保存的 Frida 脚本文件名。

4. **观察输出:** 当应用程序中任何代码调用 `strlen` 函数时，Frida 会拦截该调用，并打印出传递给 `strlen` 的字符串参数以及 `strlen` 的返回值。

**示例 Frida 输出:**

```
strlen hooked!
strlen called with arg: 'Hello from Java'
strlen returned: 15
strlen called with arg: '/data/user/0/com.example.myapp/cache'
strlen returned: 34
...
```

通过 Frida Hook，你可以清楚地看到哪些代码路径调用了 `strlen`，以及传递的字符串内容，从而更好地理解 Android Framework 或 NDK 如何使用这个底层的 C 库函数。

希望这个详细的解释能够帮助你理解 `bionic/libc/arch-arm/generic/bionic/strlen.c` 文件的功能、实现以及在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/arch-arm/generic/bionic/strlen.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>
#include <stdint.h>

size_t strlen_generic(const char *s)
{
    __builtin_prefetch(s);
    __builtin_prefetch(s+32);

    union {
        const char      *b;
        const uint32_t  *w;
        uintptr_t       i;
    } u;

    // these are some scratch variables for the asm code below
    uint32_t v, t;

    // initialize the string length to zero
    size_t l = 0;

    // align the pointer to a 32-bit word boundary
    u.b = s;
    while (u.i & 0x3)  {
        if (__builtin_expect(*u.b++ == 0, 0)) {
            goto done;
        }
        l++;
    }

    // loop for each word, testing if it contains a zero byte
    // if so, exit the loop and update the length.
    // We need to process 32 bytes per loop to schedule PLD properly
    // and achieve the maximum bus speed.
    asm(
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[l], %[l], %[s]           \n"
        "0:                                 \n"
        "pld     [%[s], #64]                \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
#if !defined(__OPTIMIZE_SIZE__)
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
        "sub     %[t], %[v], %[mask], lsr #7\n"
        "and     %[t], %[t], %[mask]        \n"
        "bics    %[t], %[t], %[v]           \n"
        "bne     1f                         \n"
        "ldr     %[v], [%[s]], #4           \n"
#endif
        "b       0b                         \n"
        "1:                                 \n"
        "add     %[l], %[l], %[s]           \n"
        "tst     %[v], #0xFF                \n"
        "beq     2f                         \n"
        "add     %[l], %[l], #1             \n"
        "tst     %[v], #0xFF00              \n"
        "beq     2f                         \n"
        "add     %[l], %[l], #1             \n"
        "tst     %[v], #0xFF0000            \n"
        "beq     2f                         \n"
        "add     %[l], %[l], #1             \n"
        "2:                                 \n"
        : [l]"=&r"(l), [v]"=&r"(v), [t]"=&r"(t), [s]"=&r"(u.b)
        : "%[l]"(l), "%[s]"(u.b), [mask]"r"(0x80808080UL)
        : "cc"
    );

done:
    return l;
}

"""

```