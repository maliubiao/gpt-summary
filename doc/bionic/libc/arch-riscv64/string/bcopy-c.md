Response:
Let's break down the thought process for answering the user's request about `bcopy.c`.

**1. Understanding the Core Request:**

The user has provided a specific C source file (`bionic/libc/arch-riscv64/string/bcopy.c`) from Android Bionic and wants to understand its functionality, its relationship to Android, implementation details, interactions with the dynamic linker, potential errors, and how it's used in the Android framework and NDK. They also requested a Frida hook example.

**2. Initial Analysis of the Code:**

The first step is to read the code and understand its fundamental purpose. Key observations:

* **License Header:** The BSD-3-Clause license indicates this is standard, open-source code.
* **Copyright:** Mentions the University of California, hinting at its historical origins.
* **`typedef intptr_t word;`:** Defines `word` as a machine word-sized integer. This suggests optimization for word-aligned memory access.
* **`#define wsize sizeof(word)` and `#define wmask (wsize - 1)`:**  These are standard bit manipulation techniques for aligning memory addresses to word boundaries.
* **`#include <string.h>`:** This is a crucial inclusion, indicating this code relates to string/memory manipulation functions.
* **Function Definition:**  The code defines a function named either `memcpy_gc` (if `MEMCOPY` is defined) or `memmove_gc` (otherwise). The presence of `gc` is interesting, but the context suggests it's likely just a variant name and not related to garbage collection in the usual sense. The core functionality is a memory copy/move.
* **Overlapping Memory Handling:**  The core logic contains two main branches: one for copying forward (`dst < src`) and one for copying backward (`dst >= src`). This strongly suggests the function is designed to handle overlapping source and destination memory regions safely, which is the hallmark of `memmove`.
* **Word-Wise Copying:**  The code attempts to copy data in `word`-sized chunks for performance, using type casting (`*(word *)(void *)dst`).
* **Byte-Wise Copying:**  It also handles the cases where addresses are not aligned or the remaining length is less than a word size, resorting to byte-by-byte copying.
* **`TLOOP` Macros:** These macros are used to optimize the loops for copying multiple words or bytes.
* **Return Value:** The function returns `dst0` (the original destination pointer) if `MEMCOPY` or `MEMMOVE` are defined, otherwise it returns nothing (void).

**3. Identifying the Core Functionality:**

Based on the code and the naming convention (`memmove_gc`), the primary function is clearly to copy a block of memory from a source to a destination, handling potential overlap between the source and destination regions. This is the definition of `memmove`. The `#ifdef MEMCOPY` indicates that it can also act like `memcpy` if that macro is defined (though the provided code snippet doesn't define it).

**4. Relating to Android:**

This function is part of Bionic, Android's C library. This means it's a fundamental building block for many Android system components and applications. Examples include:

* Copying data between buffers in system services.
* Implementing higher-level string manipulation functions.
* Passing data between processes (using shared memory).
* File I/O operations.

**5. Explaining the Implementation Details:**

A detailed explanation of each part of the code is necessary. This involves describing the alignment logic, the forward and backward copying strategies, and the purpose of the `TLOOP` macros.

**6. Dynamic Linker Aspects:**

While this specific file doesn't directly interact with the dynamic linker, it *is* part of the C library that the dynamic linker loads. To address this, a sample SO layout and the general linking process should be described. The key is to explain how the dynamic linker finds and loads the shared library containing `memmove`.

**7. Logical Reasoning (Assumptions and Outputs):**

Simple examples demonstrating forward and backward copying, including overlapping cases, can help illustrate the function's behavior.

**8. Common Usage Errors:**

Pointing out common mistakes like incorrect size arguments or forgetting about potential overlaps is crucial.

**9. Tracing Usage in Android:**

Explaining how a call from the Android framework or NDK eventually reaches `memmove` requires outlining a typical call stack. Starting with a high-level Android API call and tracing it down through the layers to the NDK and finally to the C library provides context.

**10. Frida Hook Example:**

A practical Frida hook example demonstrates how to intercept calls to `memmove` and inspect its arguments, which is very helpful for debugging and understanding runtime behavior.

**11. Structuring the Answer:**

The answer needs to be well-organized and easy to understand. Using clear headings and bullet points is essential. The flow should follow the user's request, starting with the basic functionality and progressively delving into more technical details.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Is this `memcpy` or `memmove`? The code structure clearly points to `memmove` due to the overlapping handling. The `#ifdef` suggests it can also behave as `memcpy`.
* **Clarification:** The "gc" suffix is likely a historical artifact or internal naming convention and doesn't signify garbage collection in the standard sense. Avoid making that assumption.
* **Dynamic Linker Focus:** The question explicitly asks about the dynamic linker. Even though this file doesn't *directly* call linker functions, its role as part of a dynamically linked library is important.
* **Frida Hook Specificity:**  The Frida hook should be concrete and demonstrate how to intercept arguments (source, destination, size).

By following these steps,  addressing each part of the user's request methodically, and providing clear explanations and examples, a comprehensive and informative answer can be constructed.
好的，让我们详细分析一下 `bionic/libc/arch-riscv64/string/bcopy.c` 这个文件。

**功能列举:**

这个文件定义了一个内存复制函数，实际上是 `memmove` 函数的一个实现。根据代码中的 `#ifdef MEMCOPY` 和 `#else memmove_gc` 可以看出，当 `MEMCOPY` 宏定义存在时，它会被编译成 `memcpy_gc`，否则编译成 `memmove_gc`。  虽然名字可能不同，但核心功能都是将一块内存区域的数据复制到另一块内存区域。

核心功能是：

1. **内存块复制:** 将从 `src` 地址开始的 `length` 个字节的数据复制到从 `dst` 地址开始的内存区域。
2. **处理内存重叠:**  这是 `memmove` 和 `memcpy` 的关键区别。`memmove` 能够正确处理源内存区域和目标内存区域发生重叠的情况。
3. **字节级和字级复制优化:**  为了提高效率，代码尝试以机器字 (word) 的大小进行复制，同时处理非字对齐的情况，使用字节级的复制。

**与 Android 功能的关系及举例:**

`memmove` (或 `memcpy`) 是 C 标准库中非常基础和重要的函数，在 Android 系统中被广泛使用，因为它涉及到任何需要移动或复制内存数据的操作。

* **Android Framework:**
    * **Binder IPC:**  在进程间通信 (IPC) 过程中，当传递大量数据时，例如图片、音频、视频等，系统需要将数据从一个进程的内存复制到另一个进程的内存。`memmove` 可能在 Binder 驱动或相关库中被使用。
    * **SurfaceFlinger:**  Android 的图形合成服务 SurfaceFlinger 在管理图形缓冲区时，需要复制像素数据。
    * **Zygote 进程孵化:**  Zygote 进程在 fork 新的应用进程时，需要复制父进程的部分内存空间。

* **Android NDK:**
    * **JNI 开发:**  当 Java 代码需要与 native 代码交互并传递字节数组或其他内存数据时，NDK 中提供的 JNI 函数（例如 `GetByteArrayElements`, `GetDirectBufferAddress` 等）底层的内存操作可能会用到 `memmove` 或 `memcpy`。
    * **Native 代码开发:**  开发者在编写 C/C++ native 代码时，进行数据缓冲、内存管理等操作，会直接或间接地调用 `memmove` 或 `memcpy`。例如，处理文件读写、网络数据传输、图像处理等。

**举例说明:**

假设一个 Android 应用需要从网络下载一张图片并显示出来。

1. **Network Stack:**  网络库接收到图片数据后，会将数据写入到一块内存缓冲区中。
2. **Bitmap Decoding:**  当需要将网络数据解码成 Bitmap 对象时，解码库可能需要将缓冲区中的数据复制到另一块用于存储 Bitmap 像素数据的内存区域。这里就可能使用 `memmove` 或 `memcpy`。
3. **SurfaceFlinger:**  最终，Bitmap 的像素数据会被传递给 SurfaceFlinger 进行渲染，SurfaceFlinger 在管理 GraphicBuffer 时可能也会用到内存复制操作。

**libc 函数 `memmove` 的实现详解:**

`memmove_gc` 函数的核心思想是根据源地址和目标地址的相对位置，选择向前复制还是向后复制，以避免数据覆盖问题。

1. **头文件包含和类型定义:**
   ```c
   #include <sys/types.h>
   typedef	intptr_t word;
   #define	wsize	sizeof(word)
   #define	wmask	(wsize - 1)
   #include <string.h>
   ```
   - `<sys/types.h>`: 包含了一些基本的数据类型定义。
   - `typedef intptr_t word;`: 定义 `word` 为一个指针大小的整数类型，通常是 64 位。这是为了进行字级别的快速复制。
   - `wsize`: 定义 `word` 的大小（字节数）。
   - `wmask`: 定义字对齐的掩码，用于判断地址是否字对齐。
   - `<string.h>`: 虽然这个文件本身实现了类似 `memmove` 的功能，但它可能依赖于 `<string.h>` 中的其他定义或宏。

2. **函数签名:**
   ```c
   void *
   #ifdef MEMCOPY
   memcpy_gc
   #else
   memmove_gc
   #endif
   (void *dst0, const void *src0, size_t length)
   ```
   - `void *dst0`: 目标内存区域的起始地址。
   - `const void *src0`: 源内存区域的起始地址。
   - `size_t length`: 要复制的字节数。
   - 返回值 `void *`: 返回目标内存区域的起始地址 `dst0`。

3. **初始化:**
   ```c
   char *dst = dst0;
   const char *src = src0;
   size_t t;

   if (length == 0 || dst == src)		/* nothing to do */
       goto done;
   ```
   - 将 `void *` 类型的指针转换为 `char *` 和 `const char *`，方便进行字节级别的操作。
   - 如果复制长度为 0 或者源地址和目标地址相同，则无需复制，直接跳转到 `done` 标签。

4. **宏定义:**
   ```c
   #define	TLOOP(s) if (t) TLOOP1(s)
   #define	TLOOP1(s) do { s; } while (--t)
   ```
   - `TLOOP` 和 `TLOOP1` 是用于循环复制的宏，通过判断 `t` 的值来决定是否执行循环。

5. **处理向前复制的情况 (`(unsigned long)dst < (unsigned long)src`)：**
   ```c
   if ((unsigned long)dst < (unsigned long)src) {
       // ...
   }
   ```
   - 当目标地址低于源地址时，直接从前往后复制不会导致数据覆盖。
   - **对齐处理:**
     ```c
     t = (uintptr_t)src;
     if ((t | (uintptr_t)dst) & wmask) {
         if ((t ^ (uintptr_t)dst) & wmask || length < wsize)
             t = length;
         else
             t = wsize - (t & wmask);
         length -= t;
         TLOOP1(*dst++ = *src++);
     }
     ```
     - 这段代码尝试将源地址和目标地址都对齐到字边界。
     - `(t | (uintptr_t)dst) & wmask`: 判断源地址或目标地址是否未对齐。
     - `(t ^ (uintptr_t)dst) & wmask`: 判断源地址和目标地址的低位是否相同。如果不同，则无法通过字复制进行对齐。
     - 如果可以对齐，则复制 `wsize - (t & wmask)` 个字节，将地址对齐。否则，直接字节复制。
   - **字级别复制:**
     ```c
     t = length / wsize;
     TLOOP(*(word *)(void *)dst = *(const word *)(const void *)src;
         src += wsize; dst += wsize);
     ```
     - 计算可以进行字级别复制的次数 `t`。
     - 使用 `TLOOP` 宏进行循环，每次复制一个字。
   - **剩余字节复制:**
     ```c
     t = length & wmask;
     TLOOP(*dst++ = *src++);
     ```
     - 处理剩余不足一个字的字节，进行字节级别的复制。

6. **处理向后复制的情况 (`else`)：**
   ```c
   else {
       // ...
   }
   ```
   - 当目标地址高于或等于源地址时，为了避免覆盖源数据，需要从后往前复制。
   - **初始化指针到末尾:**
     ```c
     src += length;
     dst += length;
     ```
     - 将源指针和目标指针移动到各自内存块的末尾。
   - **对齐处理:**
     ```c
     t = (uintptr_t)src;
     if ((t | (uintptr_t)dst) & wmask) {
         if ((t ^ (uintptr_t)dst) & wmask || length <= wsize)
             t = length;
         else
             t &= wmask;
         length -= t;
         TLOOP1(*--dst = *--src);
     }
     ```
     - 逻辑与向前复制类似，但计算对齐的字节数略有不同。
   - **字级别复制 (向后):**
     ```c
     t = length / wsize;
     TLOOP(src -= wsize; dst -= wsize;
         *(word *)(void *)dst = *(const word *)(const void *)src);
     ```
     - 循环向后复制一个字。
   - **剩余字节复制 (向后):**
     ```c
     t = length & wmask;
     TLOOP(*--dst = *--src);
     ```
     - 处理剩余字节，向后复制。

7. **返回:**
   ```c
   done:
   #if defined(MEMCOPY) || defined(MEMMOVE)
       return (dst0);
   #else
       return;
   #endif
   ```
   - 返回目标内存区域的起始地址。

**涉及 dynamic linker 的功能:**

虽然 `bcopy.c` 本身的代码不直接涉及动态链接器的操作，但作为 `libc` 的一部分，它会被动态链接器加载到进程的地址空间。

**so 布局样本:**

```
[地址范围起始]-[地址范围结束] 权限  偏移量 设备   inode   pathname
...
7xxxxxxxxx000-7xxxxxxxxxfff r--p  00000000 08:06  12345   /system/lib64/libc.so
7xxxxxxxxx000-7xxxxxxxyyyfff r-xp  00001000 08:06  12345   /system/lib64/libc.so
7xxxxxxxyyy000-7xxxxxxxyzzfff r--p  00xyz000 08:06  12345   /system/lib64/libc.so
7xxxxxxxyzz000-7xxxxxxxxwwoff rw-p  00abc000 08:06  12345   /system/lib64/libc.so
...
```

- `libc.so` 是一个共享库，包含了 `memmove` 的实现。
- **r--p:**  只读权限。包含了只读的数据，例如字符串常量。
- **r-xp:**  只读且可执行权限。包含了代码段，`memmove_gc` 的机器码就在这里。
- **r--p:**  只读权限。包含了全局变量等数据。
- **rw-p:**  读写权限。包含了可读写的数据，例如未初始化的全局变量。

**链接的处理过程:**

1. **编译链接时:** 当编译链接一个使用了 `memmove` 的程序时，链接器会在程序的可执行文件中记录下对 `memmove` 函数的符号引用。同时，会记录下程序依赖于 `libc.so` 这个共享库。
2. **程序加载时:** 当 Android 系统加载这个程序时，动态链接器 (linker，通常是 `/system/bin/linker64`) 会被首先启动。
3. **加载依赖库:** 动态链接器会解析程序头部的信息，找到程序依赖的共享库列表，并加载这些库到内存中，例如 `libc.so`。
4. **符号解析 (Symbol Resolution):** 动态链接器会遍历加载的共享库的符号表，找到 `memmove` 函数的定义。
5. **重定位 (Relocation):** 动态链接器会将程序中对 `memmove` 函数的符号引用替换为 `memmove` 函数在 `libc.so` 中的实际内存地址。这样，程序在运行时调用 `memmove` 时，就能跳转到正确的代码位置。

**假设输入与输出 (逻辑推理):**

**假设输入 1 (向前复制，无重叠):**
- `dst0`: 0x1000
- `src0`: 0x2000
- `length`: 16

**输出:**  地址 0x1000 到 0x100F 的内存区域的内容与地址 0x2000 到 0x200F 的内容相同。函数返回 0x1000。

**假设输入 2 (向后复制，有重叠):**
- `dst0`: 0x2000
- `src0`: 0x1FFF
- `length`: 16

**输出:** 地址 0x2000 到 0x200F 的内存区域的内容与原始地址 0x1FFF 到 0x200E 的内容相同（从后往前复制）。函数返回 0x2000。

**假设输入 3 (长度为 0):**
- `dst0`: 0x1000
- `src0`: 0x2000
- `length`: 0

**输出:** 不进行任何内存复制。函数返回 0x1000。

**用户或编程常见的使用错误:**

1. **`memcpy` 和 `memmove` 的混淆:**  在源地址和目标地址重叠时使用 `memcpy`，可能导致数据损坏，因为 `memcpy` 不保证处理重叠。应该在这种情况下使用 `memmove`。
2. **`length` 参数错误:**  传递了错误的 `length` 值，可能导致复制过多或过少的数据，造成缓冲区溢出或数据不完整。
3. **空指针:**  传递了空指针作为 `dst0` 或 `src0`，会导致程序崩溃。
4. **内存区域无效:**  `dst0` 或 `src0` 指向的内存区域是无效的（例如，未分配的内存），会导致段错误。

**举例说明错误:**

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char src[10] = "012345678";
    char dest[10];

    // 错误示例 1: 使用 memcpy 处理重叠 (可能导致未定义行为)
    memmove(dest + 2, dest, 5); // 正确应该使用 memmove
    printf("dest after potential overlap with memcpy: %s\n", dest);

    // 错误示例 2: length 参数错误 (缓冲区溢出)
    char dest2[5];
    memcpy(dest2, src, 10); // 缓冲区溢出
    printf("dest2 after overflow: %s\n", dest2);

    // 错误示例 3: 空指针
    char *ptr = NULL;
    // memcpy(ptr, src, 5); // 导致程序崩溃

    return 0;
}
```

**Android framework 或 ndk 如何一步步的到达这里:**

以一个 NDK 开发的图片处理功能为例：

1. **Java 代码调用 NDK 方法:**  Android Framework 中的 Java 代码（例如一个 Activity）调用了 NDK 中实现的 native 方法，该方法负责处理图片。
   ```java
   // Java 代码
   public class ImageProcessor {
       public native void processImage(Bitmap bitmap);
       // ...
   }
   ```
2. **JNI 调用:**  Java 虚拟机 (Dalvik/ART) 通过 Java Native Interface (JNI) 调用到 native 代码。
3. **获取 Bitmap 数据:**  Native 方法需要获取 Bitmap 的像素数据。这通常涉及调用 Android NDK 提供的 Bitmap 相关函数，例如 `AndroidBitmap_lockPixels` 获取像素数据的指针。
   ```c++
   // Native (C++) 代码
   #include <jni.h>
   #include <android/bitmap.h>

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_myapp_ImageProcessor_processImage(JNIEnv *env, jobject thiz, jobject bitmap) {
       AndroidBitmapInfo info;
       void *pixels;
       AndroidBitmap_getInfo(env, bitmap, &info);
       AndroidBitmap_lockPixels(env, bitmap, &pixels);

       // ... 对像素数据进行处理，可能涉及内存复制 ...

       AndroidBitmap_unlockPixels(env, bitmap);
   }
   ```
4. **内存操作:** 在 native 代码中，对像素数据进行处理时，可能需要将像素数据复制到临时的缓冲区进行操作，或者将处理后的数据写回 Bitmap 的内存。这时就会用到 `memcpy` 或 `memmove`。
   ```c++
   // 假设需要将一部分像素数据复制到另一个缓冲区
   char *temp_buffer = (char *)malloc(info.stride * info.height);
   if (temp_buffer != nullptr) {
       memmove(temp_buffer, pixels, info.stride * info.height); // 调用到 libc 的 memmove
       // ... 对 temp_buffer 进行操作 ...
       free(temp_buffer);
   }
   ```
5. **libc 调用:**  最终，`memmove` 函数的调用会链接到 `bionic/libc/arch-riscv64/string/bcopy.c` 中实现的 `memmove_gc` 函数。

**Frida hook 示例调试步骤:**

可以使用 Frida hook `memmove` 函数来观察其调用情况和参数。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.arch === 'riscv64') {
    const memmovePtr = Module.findExportByName("libc.so", "memmove");

    if (memmovePtr) {
        Interceptor.attach(memmovePtr, {
            onEnter: function (args) {
                console.log("[memmove] Called from:", Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\\n'));
                console.log("[memmove] Destination:", args[0]);
                console.log("[memmove] Source:", args[1]);
                console.log("[memmove] Length:", args[2].toInt());
            },
            onLeave: function (retval) {
                console.log("[memmove] Returned:", retval);
            }
        });
        console.log("[Frida] memmove hook installed on riscv64");
    } else {
        console.log("[Frida] memmove not found in libc.so");
    }
} else {
    console.log("[Frida] Skipping memmove hook, not riscv64 architecture");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备或模拟器已 root，并且安装了 Frida 服务。
2. **运行目标应用:** 启动你想要监控的应用。
3. **运行 Frida 脚本:** 使用 Frida 命令将上述脚本注入到目标应用进程中。
   ```bash
   frida -U -f <your_package_name> -l your_script.js --no-pause
   ```
   将 `<your_package_name>` 替换为你的应用包名，`your_script.js` 替换为保存的 Frida 脚本文件名。
4. **触发 `memmove` 调用:** 在应用中执行会导致 `memmove` 被调用的操作，例如加载图片、处理数据等。
5. **查看 Frida 输出:** Frida 会在控制台中打印出 `memmove` 函数被调用时的堆栈信息、参数值和返回值，帮助你理解 `memmove` 在应用中的使用情况。

通过以上分析和示例，你应该对 `bionic/libc/arch-riscv64/string/bcopy.c` 文件的功能、与 Android 的关系、实现细节以及如何调试有了一个更深入的了解。

Prompt: 
```
这是目录为bionic/libc/arch-riscv64/string/bcopy.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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

#include <sys/types.h>

typedef	intptr_t word;		/* "word" used for optimal copy speed */

#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

/*
 * Copy a block of memory, handling overlap.
 */
#include <string.h>

void *
#ifdef MEMCOPY
memcpy_gc
#else
memmove_gc
#endif
(void *dst0, const void *src0, size_t length)
{
	char *dst = dst0;
	const char *src = src0;
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
		goto done;

	/*
	 * Macros: loop-t-times; and loop-t-times, t>0
	 */
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	if ((unsigned long)dst < (unsigned long)src) {
		/*
		 * Copy forward.
		 */
		t = (uintptr_t)src;	/* only need low bits */
		if ((t | (uintptr_t)dst) & wmask) {
			/*
			 * Try to align operands.  This cannot be done
			 * unless the low bits match.
			 */
			if ((t ^ (uintptr_t)dst) & wmask || length < wsize)
				t = length;
			else
				t = wsize - (t & wmask);
			length -= t;
			TLOOP1(*dst++ = *src++);
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = length / wsize;
		TLOOP(*(word *)(void *)dst = *(const word *)(const void *)src;
		    src += wsize; dst += wsize);
		t = length & wmask;
		TLOOP(*dst++ = *src++);
	} else {
		/*
		 * Copy backwards.  Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += length;
		dst += length;
		t = (uintptr_t)src;
		if ((t | (uintptr_t)dst) & wmask) {
			if ((t ^ (uintptr_t)dst) & wmask || length <= wsize)
				t = length;
			else
				t &= wmask;
			length -= t;
			TLOOP1(*--dst = *--src);
		}
		t = length / wsize;
		TLOOP(src -= wsize; dst -= wsize;
		    *(word *)(void *)dst = *(const word *)(const void *)src);
		t = length & wmask;
		TLOOP(*--dst = *--src);
	}
done:
#if defined(MEMCOPY) || defined(MEMMOVE)
	return (dst0);
#else
	return;
#endif
}

"""

```