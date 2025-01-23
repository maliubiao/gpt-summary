Response:
Let's break down the thought process for answering the user's request about the `strings.handroid` file.

**1. Understanding the Core Request:**

The user wants a detailed explanation of the provided C code snippet, specifically focusing on its function, its relation to Android, implementation details, dynamic linking aspects (though the snippet doesn't directly show this), potential errors, how it's reached, and debugging methods. The keyword "fortify" in the filename is a major clue.

**2. Initial Analysis of the Code:**

The first thing to notice is the `#if defined(__BIONIC_FORTIFY)` block. This immediately tells us that the code is related to a security hardening or runtime checking mechanism within Bionic. The `__BIONIC_FORTIFY_INLINE` suggests these are inlined functions for performance.

The functions themselves (`__bionic_bcopy` and `__bionic_bzero`) are clearly fortified versions of the standard C library functions `bcopy` and `bzero`. The `__pass_object_size0` and `__bos_unevaluated_lt` are key indicators of buffer overflow protection.

**3. Deconstructing Each Function:**

* **`__bionic_bcopy`:**
    * **Purpose:** A safer version of `bcopy`.
    * **Mechanism:** Uses `__bos0(dst)` to get the size of the destination buffer. It uses `__bos_unevaluated_lt` (a compile-time check) to flag errors if the copy size `len` is larger than the destination buffer size. At runtime, if `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` is defined, it uses `__builtin___memmove_chk` for runtime bounds checking; otherwise, it falls back to the standard `__builtin_memmove`. The `__overloadable` keyword hints at potential function overloading (though not explicitly shown in the snippet).
    * **Key Concepts:** Buffer overflow prevention, compile-time vs. runtime checks.

* **`__bionic_bzero`:**
    * **Purpose:** A safer version of `bzero`.
    * **Mechanism:** Very similar to `__bionic_bcopy`, using `__bos0(b)`, `__bos_unevaluated_lt`, `__builtin___memset_chk`, and `__builtin_memset`.

**4. Connecting to Android:**

The file path `bionic/libc/include/bits/fortify/strings.handroid` clearly places this code within Android's standard C library (Bionic). The "fortify" directory signifies its purpose in security. The provided explanation focuses on how Android uses these fortified versions to prevent common memory corruption vulnerabilities.

**5. Addressing Dynamic Linking (Crucially, the code *doesn't* directly show this):**

The code snippet itself *doesn't* directly involve dynamic linking. However, the request specifically asks about it. The explanation acknowledges this and provides a general overview of how dynamic linking works in Android with SO files, the dynamic linker (`linker64` or `linker`), relocation, and the PLT/GOT. It emphasizes that while the current code isn't a direct example, it's part of Bionic, which *is* dynamically linked. A sample SO layout and the linking process are described at a high level.

**6. Providing Examples of Usage and Errors:**

Simple examples are provided for using `bcopy` and `bzero` and how the fortified versions would catch potential buffer overflows. This makes the concept concrete for the user.

**7. Explaining the Path from Android Framework/NDK:**

This part requires understanding the Android build process. The explanation traces the path from a developer using NDK to compile native code, linking against Bionic, and how the compiler selects the fortified versions of the functions. It highlights the role of build flags and system properties in enabling/disabling these checks.

**8. Providing a Frida Hook Example:**

A practical Frida hook example is crucial for demonstrating how to inspect the behavior of these functions at runtime. The example targets `__bionic_bcopy` and logs the arguments and buffer sizes, which is a valuable debugging technique.

**9. Structuring the Answer:**

The answer is organized logically based on the user's request, addressing each point systematically:

* File Functionality
* Relationship to Android
* Function Implementation Details
* Dynamic Linking (acknowledged as not directly present but explained contextually)
* Logical Inference (with input/output examples)
* Common Usage Errors
* Path from Framework/NDK
* Frida Hook Example

**10. Language and Tone:**

The answer is in Chinese, as requested, and uses clear and concise language. Technical terms are explained where necessary.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:**  Focus only on the direct code.
* **Correction:** The prompt asks about dynamic linking, even if the code doesn't show it. Provide context about Bionic and dynamic linking in Android.
* **Initial thought:** Provide very technical, low-level implementation details.
* **Correction:**  Balance technical details with clear explanations and examples that are easy to understand for a broader audience. Focus on the *benefits* of fortification, not just the mechanics.
* **Initial thought:**  A single Frida hook example might suffice.
* **Correction:**  Make sure the Frida example is practical and directly relevant to observing the behavior of the fortified functions, logging arguments and sizes.

By following this detailed thought process, the answer effectively addresses all aspects of the user's request, providing a comprehensive explanation of the `strings.handroid` file and its role in Android's security mechanisms.
这是一个定义了 `__bionic_bcopy` 和 `__bionic_bzero` 这两个函数的内联函数的头文件，它们是 Bionic C 库中 `bcopy` 和 `bzero` 的 fortified (强化) 版本。 fortified 版本旨在提供额外的安全检查，以防止缓冲区溢出等常见的安全漏洞。

**文件功能：**

这个文件的主要功能是定义了两个用于内存操作的强化函数：

1. **`__bionic_bcopy(const void * src, void* dst, size_t len)`:**  强化版本的内存复制函数，用于将 `src` 指向的内存块复制到 `dst` 指向的内存块，复制的字节数为 `len`。
2. **`__bionic_bzero(void* b, size_t len)`:** 强化版本的内存清零函数，用于将 `b` 指向的内存块的 `len` 个字节设置为零。

**与 Android 功能的关系及举例说明：**

这两个函数是 Bionic C 库的一部分，而 Bionic 是 Android 操作系统的基础 C 库。几乎所有在 Android 上运行的 native 代码（通过 NDK 开发的应用或系统服务）都会间接地使用到 Bionic 提供的函数。

* **安全性提升:**  `__bionic_bcopy` 和 `__bionic_bzero` 的主要目的是提高安全性。它们通过在编译时和运行时进行额外的检查，来防止由于错误的内存操作导致的缓冲区溢出。例如，当开发者尝试复制或清零超出目标缓冲区大小的数据时，fortified 版本可以发出警告或终止程序，从而避免潜在的安全漏洞。

* **系统服务:** Android 的系统服务，例如 SurfaceFlinger（负责屏幕合成）或 MediaServer（负责媒体处理），通常使用 C++ 或 C 编写，并会使用到这些底层的内存操作函数。如果这些服务中存在缓冲区溢出漏洞，可能会导致系统崩溃甚至被恶意利用。使用 fortified 版本可以降低这种风险。

* **NDK 开发的应用:** 使用 Android NDK 开发的原生应用，其代码最终会链接到 Bionic 库。当应用代码调用 `bcopy` 或 `bzero` 时，如果启用了 fortify 功能，实际上会调用到 `__bionic_bcopy` 或 `__bionic_bzero`。

**libc 函数的功能实现：**

让我们详细解释 `__bionic_bcopy` 和 `__bionic_bzero` 的实现：

**`__bionic_bcopy` 的实现：**

```c
__BIONIC_FORTIFY_INLINE
void __bionic_bcopy(const void * _Nonnull src, void* _Nonnull const dst __pass_object_size0, size_t len)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos0(dst), len),
                         "'bcopy' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(dst);
    if (!__bos_trivially_ge(bos, len)) {
        __builtin___memmove_chk(dst, src, len, bos);
        return;
    }
#endif
    __builtin_memmove(dst, src, len);
}
```

1. **`__BIONIC_FORTIFY_INLINE`:**  这是一个 Bionic 特定的宏，表示该函数应该被内联，以减少函数调用的开销。

2. **`const void * _Nonnull src` 和 `void* _Nonnull const dst __pass_object_size0`:**
   - `_Nonnull`:  Clang 的属性，表示指针不能为空。
   - `__pass_object_size0`:  这是一个 Bionic 特定的属性，告诉编译器 `dst` 指向的缓冲区的大小信息。这个信息会被 `__bos0(dst)` 宏使用。

3. **`size_t len`:**  要复制的字节数。

4. **`__overloadable`:**  表示该函数可以被重载（虽然在这个代码片段中没有看到重载的例子）。

5. **`__clang_error_if(__bos_unevaluated_lt(__bos0(dst), len), "'bcopy' called with size bigger than buffer")`:**
   - `__bos0(dst)`:  这是一个宏，用于获取 `dst` 指向的缓冲区的大小。编译器会根据 `__pass_object_size0` 提供的信息计算出这个大小。
   - `__bos_unevaluated_lt(size1, size2)`: 这是一个编译时检查宏，如果 `size1` 小于 `size2`，则会产生一个编译错误。
   - 这一行代码的作用是在编译时检查，如果编译器能够确定要复制的长度 `len` 大于目标缓冲区的大小，则会产生一个编译错误，提示开发者 `bcopy` 调用时使用了过大的尺寸。

6. **`#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` ... `#endif`:**  这是一个条件编译块，只有在定义了 `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` 宏时才会编译其中的代码。这个宏通常在 debug 或测试构建中被启用。

7. **`size_t bos = __bos0(dst);`:**  在运行时获取目标缓冲区的大小。

8. **`if (!__bos_trivially_ge(bos, len))`:**
   - `__bos_trivially_ge(size1, size2)`: 这是一个运行时检查宏，如果 `size1` 大于或等于 `size2`，则返回真。
   - 这一行代码在运行时检查要复制的长度 `len` 是否超过了目标缓冲区的大小 `bos`。

9. **`__builtin___memmove_chk(dst, src, len, bos);`:**  如果运行时检查发现缓冲区溢出风险，则调用 `__builtin___memmove_chk`。这是一个编译器内置的带有边界检查的 `memmove` 版本。如果发生溢出，这个函数可能会触发错误处理机制（例如，终止程序）。

10. **`__builtin_memmove(dst, src, len);`:**  如果在编译时检查没有发现问题，并且运行时检查也没有发现问题（或者禁用了运行时检查），则最终调用标准的 `memmove` 函数来执行内存复制。`memmove` 能够正确处理源和目标缓冲区重叠的情况。

**`__bionic_bzero` 的实现：**

```c
__BIONIC_FORTIFY_INLINE
void __bionic_bzero(void* _Nonnull const b __pass_object_size0, size_t len)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos0(b), len),
                         "'bzero' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(b);
    if (!__bos_trivially_ge(bos, len)) {
        __builtin___memset_chk(b, 0, len, bos);
        return;
    }
#endif
    __builtin_memset(b, 0, len);
}
```

`__bionic_bzero` 的实现与 `__bionic_bcopy` 非常相似，只是它执行的是内存清零操作：

1. **`__clang_error_if(__bos_unevaluated_lt(__bos0(b), len), "'bzero' called with size bigger than buffer")`:** 编译时检查，确保清零的长度不超过缓冲区大小。

2. **`__builtin___memset_chk(b, 0, len, bos);`:** 运行时检查到溢出风险时，调用带有边界检查的 `memset` 版本。

3. **`__builtin_memset(b, 0, len);`:**  正常情况下，调用标准的 `memset` 函数进行内存清零。

**涉及 dynamic linker 的功能：**

这个代码文件本身并不直接涉及 dynamic linker 的功能。它定义的是 C 库中的函数，这些函数在程序运行时被调用。Dynamic linker 的作用是在程序启动时加载必要的共享库（如 libc.so），并将程序中对共享库函数的调用链接到库中实际的函数地址。

尽管如此，这些 fortified 函数最终会被链接到 `libc.so` 中，并通过 dynamic linker 加载到进程的地址空间。

**so 布局样本和链接的处理过程：**

假设有一个简单的 native 代码程序 `my_app`，它调用了 `bcopy`：

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char src[] = "Hello";
    char *dest = malloc(10);
    if (dest == NULL) {
        return 1;
    }
    bcopy(src, dest, sizeof(src));
    printf("Copied string: %s\n", dest);
    free(dest);
    return 0;
}
```

编译链接这个程序时，`bcopy` 的调用最终会链接到 `libc.so` 中的 `__bionic_bcopy` 函数（如果启用了 fortify）。

**SO 布局样本 (`libc.so`)：**

```
Address Range      Permissions     Mapping
-----------------  ------------  ---------------------------
...
[text segment]     r-x          /system/lib64/libc.so
    ...
    [Symbol Table]
        ...
        __bionic_bcopy: 0xXXXXXXXXXXXX  // __bionic_bcopy 函数的地址
        ...
    [Relocation Table]
        ...
        RELOCATION_GLOBAL_DATA offset=YYYYYYYYYYYY type=R_AARCH64_GLOB_DAT symbol=__stack_chk_guard
        ...
...
[data segment]     rw-           /system/lib64/libc.so
    ...
    [Global Offset Table (GOT)]
        ...
        GOT entry for __bionic_bcopy: 0xZZZZZZZZZZZZ  // 运行时解析后的 __bionic_bcopy 地址
        ...
...
```

**链接的处理过程：**

1. **编译时链接:**  编译器在编译 `my_app.c` 时，遇到 `bcopy` 函数调用，会在其目标文件 (`my_app.o`) 中生成一个对 `bcopy` 的未解析引用。

2. **链接时链接:**  链接器 (`ld`) 将 `my_app.o` 和必要的库（包括 `libc.so`）链接在一起。链接器会查看 `libc.so` 的符号表，找到 `__bionic_bcopy` 的符号，并将 `my_app.o` 中对 `bcopy` 的引用解析为 `__bionic_bcopy` 在 `libc.so` 中的地址。此时，链接器可能会在 `my_app` 的 GOT (Global Offset Table) 中创建一个条目，用于存储 `__bionic_bcopy` 的运行时地址。

3. **运行时链接:** 当 `my_app` 被启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载所有需要的共享库（如 `libc.so`）到进程的地址空间。

4. **重定位:**  Dynamic linker 会遍历程序和共享库的重定位表。对于 `my_app` 中对 `__bionic_bcopy` 的调用，dynamic linker 会将 `__bionic_bcopy` 在 `libc.so` 中的实际加载地址填入 `my_app` 的 GOT 表中对应的条目。

5. **函数调用:**  当程序执行到 `bcopy` 的调用时，它会通过 GOT 表中存储的运行时地址，跳转到 `libc.so` 中 `__bionic_bcopy` 的实际代码执行。

**逻辑推理、假设输入与输出：**

**假设输入：**

```c
char src[] = "TooLongString";
char dest[5];
__bionic_bcopy(src, dest, sizeof(src)); // 复制长度超过 dest 的大小
```

**输出（取决于编译和运行时的 fortify 设置）：**

* **编译时错误（如果启用了相应的编译时检查）：**
  ```
  error: 'bcopy' called with size bigger than buffer
  ```

* **运行时错误（如果启用了运行时检查）：**
  程序可能会因为 `__builtin___memmove_chk` 检测到缓冲区溢出而终止，并可能输出类似以下的错误信息（具体取决于 Android 系统的错误处理机制）：
  ```
  *** buffer overflow detected ***: terminated
  ```

* **未启用 fortify：**
  `dest` 缓冲区会发生溢出，导致相邻的内存被覆盖，可能导致程序崩溃或其他不可预测的行为。

**用户或编程常见的使用错误：**

1. **复制或清零的长度超过目标缓冲区的大小:** 这是最常见的错误，也是 fortify 版本主要防御的目标。
   ```c
   char buffer[10];
   __bionic_bzero(buffer, 100); // 错误：尝试清零 100 字节，超出 buffer 的大小
   ```

2. **目标缓冲区未正确分配或初始化:**
   ```c
   char *dest; // 未分配内存
   char src[] = "Test";
   __bionic_bcopy(src, dest, sizeof(src)); // 错误：dest 指向无效内存
   ```

3. **源和目标缓冲区重叠但使用了错误的函数:** 虽然 `__bionic_bcopy` 基于 `memmove` 实现，可以处理重叠，但如果误用了 `memcpy` 的 fortified 版本（如果存在），且源和目标缓冲区重叠，则可能导致未定义的行为。

**Android Framework 或 NDK 如何到达这里：**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码。

   ```c++
   // my_native_lib.cpp
   #include <string.h>

   extern "C" int myNativeFunction(char* input) {
       char buffer[64];
       strcpy(buffer, input); // 这里可能会间接调用到 bcopy 或 memcpy 的 fortified 版本
       return 0;
   }
   ```

2. **编译 NDK 代码:** NDK 工具链（例如 `clang`）在编译 `my_native_lib.cpp` 时，会将其编译成机器码，其中 `strcpy` 等函数的调用会被解析为对 Bionic C 库中对应函数的引用。如果启用了 fortify，`strcpy` 可能会被替换成其 fortified 版本（例如 `__strcpy_chk`，但这不在当前文件中）。即使使用 `bcopy` 或 `bzero`，也会调用到这里定义的函数。

3. **链接:** 链接器将编译后的目标文件和 Bionic C 库 (`libc.so`) 链接在一起。链接过程会将 `myNativeFunction` 中对 `strcpy` 或 `bcopy` 等函数的调用地址指向 `libc.so` 中对应的 fortified 函数。

4. **Android Framework 调用:** Android Framework (用 Java 编写) 通过 JNI (Java Native Interface) 调用 native 代码。

   ```java
   // MainActivity.java
   public class MainActivity extends AppCompatActivity {
       static {
           System.loadLibrary("my_native_lib");
       }

       private native int myNativeFunction(String input);

       @Override
       protected void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           setContentView(R.layout.activity_main);
           myNativeFunction("Some input string");
       }
   }
   ```

5. **运行时加载:** 当 `MainActivity` 的 `onCreate` 方法被调用时，`System.loadLibrary("my_native_lib")` 会加载 `libmy_native_lib.so`。dynamic linker 会加载 `libmy_native_lib.so` 依赖的 `libc.so`，并解析其中的符号。

6. **JNI 调用:**  当 `myNativeFunction` 被调用时，程序会跳转到 `libmy_native_lib.so` 中 `myNativeFunction` 的代码。如果在 `myNativeFunction` 中调用了 `strcpy` 或 `bcopy`，并且启用了 fortify，则会执行 `libc.so` 中的 `__strcpy_chk` 或 `__bionic_bcopy` 代码。

**Frida hook 示例调试步骤：**

以下是一个使用 Frida hook `__bionic_bcopy` 函数的示例：

```javascript
// frida script
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const bionic_bcopy = Module.findExportByName("libc.so", "__bionic_bcopy");
    if (bionic_bcopy) {
        Interceptor.attach(bionic_bcopy, {
            onEnter: function (args) {
                const src = args[0];
                const dst = args[1];
                const len = args[2].toInt();
                const bos = Memory.readUSize(dst); // 尝试读取目标缓冲区大小 (可能不可靠，取决于编译器优化)

                console.log("[__bionic_bcopy] Called");
                console.log("  Source: " + src);
                console.log("  Destination: " + dst);
                console.log("  Length: " + len);
                if (bos) {
                    console.log("  Destination Buffer Size (approx): " + bos);
                }
                console.log("  Source Content: " + (src ? Memory.readUtf8String(src, Math.min(len, 32)) : "null")); // 读取部分源内容
            },
            onLeave: function (retval) {
                console.log("[__bionic_bcopy] Returning");
            }
        });
    } else {
        console.log("[Warning] __bionic_bcopy not found in libc.so");
    }
} else {
    console.log("[Warning] Frida script designed for arm64/x64");
}
```

**调试步骤：**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。

2. **找到目标进程:** 确定你要调试的进程的名称或 PID。

3. **运行 Frida 命令:** 使用 Frida 命令行工具将脚本注入到目标进程。例如：
   ```bash
   frida -U -f <package_name> -l your_script.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <process_name> -l your_script.js
   ```

4. **触发目标代码:** 运行或操作你的 Android 应用，使其执行到会调用 `bcopy` 的代码路径。

5. **查看 Frida 输出:** Frida 会在终端输出 `__bionic_bcopy` 被调用时的相关信息，包括源地址、目标地址、复制长度以及（尝试获取的）目标缓冲区大小。你可以根据这些信息来分析内存操作是否安全。

**注意:**

*  直接读取目标缓冲区大小 (`Memory.readUSize(dst)`) 可能不可靠，因为编译器可能会进行优化，使得缓冲区大小信息不容易在运行时获取。`__bos0` 宏主要是在编译时起作用。
*  实际的 fortified 函数调用可能会因为编译器的优化而有所不同（例如，`strcpy` 可能会被替换为 `__strcpy_chk`）。这个例子主要关注 `bcopy` 的 fortified 版本。
*  你需要根据具体的 Android 版本和架构来调整 Frida 脚本。

这个详细的解释涵盖了 `bionic/libc/include/bits/fortify/strings.handroid` 文件的功能、与 Android 的关系、实现细节、与 dynamic linker 的联系、潜在的错误以及如何使用 Frida 进行调试。希望这些信息对您有所帮助！

### 提示词
```
这是目录为bionic/libc/include/bits/fortify/strings.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#if defined(__BIONIC_FORTIFY)

__BIONIC_FORTIFY_INLINE
void __bionic_bcopy(const void * _Nonnull src, void* _Nonnull const dst __pass_object_size0, size_t len)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos0(dst), len),
                         "'bcopy' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(dst);
    if (!__bos_trivially_ge(bos, len)) {
        __builtin___memmove_chk(dst, src, len, bos);
        return;
    }
#endif
    __builtin_memmove(dst, src, len);
}

__BIONIC_FORTIFY_INLINE
void __bionic_bzero(void* _Nonnull const b __pass_object_size0, size_t len)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos0(b), len),
                         "'bzero' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(b);
    if (!__bos_trivially_ge(bos, len)) {
        __builtin___memset_chk(b, 0, len, bos);
        return;
    }
#endif
    __builtin_memset(b, 0, len);
}

#endif /* defined(__BIONIC_FORTIFY) */
```