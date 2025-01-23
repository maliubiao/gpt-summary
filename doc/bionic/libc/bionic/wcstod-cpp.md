Response:
Let's break down the thought process to generate the comprehensive answer about `wcstod.cpp`.

**1. Understanding the Core Request:**

The request asks for a detailed explanation of the `wcstod.cpp` file, specifically focusing on its functionality, relationship to Android, implementation details, dynamic linking aspects, usage errors, and how it's reached within the Android ecosystem. The key is to be comprehensive and provide concrete examples.

**2. Initial Analysis of the Code:**

* **Purpose:** The code clearly defines a template function `wcstod` and then uses it to implement `wcstof`, `wcstod`, and `wcstold`. These functions convert wide-character strings to floating-point numbers (float, double, and long double, respectively).
* **Key Technique:**  The central strategy is converting the wide-character string (which might contain non-ASCII characters) into an ASCII string. This is crucial because the underlying `strtod`, `strtof`, and `strtold` functions (standard C library functions) operate on narrow (ASCII) character strings.
* **Supporting Functions:** The code uses functions like `iswspace`, `wcsspn`, and calls `parsefloat`. It also manipulates `FILE` structures.
* **Templates:** The use of a template allows for code reuse across different floating-point types.
* **`__strong_alias`:**  This macro indicates the existence of locale-aware versions of these functions (`wcstof_l`, `wcstod_l`, `wcstold_l`).

**3. Structuring the Answer:**

A logical structure is crucial for a comprehensive answer. The request itself provides a good outline:

* Functionality
* Relationship to Android
* Implementation Details
* Dynamic Linking
* Logic Inference (Input/Output)
* Common Usage Errors
* Android Framework/NDK Path and Frida Hook

**4. Detailing Each Section:**

* **Functionality:**  Start with a high-level overview, then list the specific functions and their purpose (converting wide-character strings to different floating-point types). Emphasize the role of the template.

* **Relationship to Android:**  Explain that this is part of Bionic, Android's C library. Give concrete examples of where this functionality is needed, such as parsing user input in apps or handling data from configuration files.

* **Implementation Details:** This is the core of the explanation. Go step-by-step through the `wcstod` template function:
    * Skip leading whitespace.
    * Determine the longest potential numeric part.
    * Create an ASCII copy. Explain *why* this is done (compatibility with `strtod`).
    * The `FILE` manipulation is complex. Explain the reasoning: they're trying to reuse the `parsefloat` logic, which expects a `FILE*`. Explain the limitations of not having `fwmemopen`.
    * Explain the call to `parsefloat` and its role in more carefully analyzing the ASCII string.
    * Explain the final call to `strtod_fn`.
    * Explain the handling of the `end` pointer and potential errors.
    * Mention memory management (`delete[] ascii_str`).

* **Dynamic Linking:**
    * **Identify the Key Point:**  The crucial aspect is how the `wcstod` implementation in `libc.so` links to other functions like `strtod` (also likely in `libc.so`).
    * **SO Layout Sample:**  Provide a simplified but representative layout showing `wcstod`, `strtod`, and potentially other related functions within `libc.so`.
    * **Linking Process:** Explain the dynamic linker's role in resolving symbols at runtime. Mention symbol tables and relocation. Explain that in this case, the linking is likely internal within `libc.so`.

* **Logic Inference (Input/Output):** Provide concrete examples of how the function behaves with different inputs, including valid numbers, numbers with whitespace, invalid inputs, and special cases like NaN and infinity. This helps solidify understanding.

* **Common Usage Errors:**  Focus on errors programmers might make when using functions like `wcstod`:
    * Forgetting to check the `end` pointer.
    * Passing null pointers.
    * Overflow/underflow (though the code itself doesn't explicitly handle this beyond what `strtod` does).
    * Locale issues (important since there are `_l` versions).

* **Android Framework/NDK Path and Frida Hook:** This requires understanding the Android ecosystem.
    * **NDK:** Explain how NDK developers directly call `wcstod`. Give a simple C++ example.
    * **Framework:** Explain that while the Framework itself might not directly call `wcstod`, it could happen indirectly through JNI calls or native libraries. Focus on scenarios like handling user input in text fields or processing data.
    * **Frida Hook:** Provide a concrete Frida example to intercept calls to `wcstod`. Explain how to set up Frida, find the function address, and implement the hook to log arguments and results.

**5. Refinement and Language:**

* **Clarity:** Use clear and concise language. Avoid overly technical jargon where possible, or explain it if necessary.
* **Accuracy:** Ensure the technical details are correct.
* **Completeness:** Address all aspects of the request.
* **Structure and Formatting:** Use headings, bullet points, and code formatting to make the answer easy to read and understand.
* **Chinese:**  Since the request was in Chinese, ensure the entire response is in fluent Chinese.

**Self-Correction/Improvements During the Process:**

* **Initial thought:**  Might have initially focused too much on the low-level details of `parsefloat`. Realized that a higher-level explanation of its role is sufficient.
* **Dynamic Linking:**  Initially considered going into more detail about GOT/PLT, but simplified it to focus on the core concept of symbol resolution within `libc.so`.
* **Frida Hook:**  Made sure the Frida example was practical and easy to adapt. Initially considered more complex hooking scenarios, but simplified it for clarity.
* **Error Handling:**  Initially overlooked some common usage errors. Added more detail based on potential programmer mistakes.

By following this structured approach, combined with a good understanding of the code and the Android environment, a comprehensive and accurate answer can be generated. The key is to break down the problem into smaller, manageable parts and then synthesize the information into a coherent whole.
好的，让我们来详细分析一下 `bionic/libc/bionic/wcstod.cpp` 这个文件。

**文件功能概述**

`wcstod.cpp` 文件在 Android 的 Bionic C 库中实现了将宽字符字符串转换为双精度浮点数（`double`）、单精度浮点数（`float`）和长双精度浮点数（`long double`）的功能。它提供了三个主要的函数：

* **`wcstof(const wchar_t* s, wchar_t** end)`:** 将宽字符字符串 `s` 转换为 `float` 类型的浮点数。
* **`wcstod(const wchar_t* s, wchar_t** end)`:** 将宽字符字符串 `s` 转换为 `double` 类型的浮点数。
* **`wcstold(const wchar_t* s, wchar_t** end)`:** 将宽字符字符串 `s` 转换为 `long double` 类型的浮点数。

这三个函数都使用了同一个模板函数 `wcstod<float_type>` 来实现核心转换逻辑，只是模板参数 `float_type` 和内部调用的 ASCII 转换函数 (`strtof`, `strtod`, `strtold`) 不同。

**与 Android 功能的关系及举例**

这些函数是标准 C 库的一部分，在各种需要处理浮点数输入的场景中都会被用到。在 Android 中，它们也扮演着重要的角色：

* **解析用户输入:**  当 Android 应用需要从用户那里获取浮点数输入时，例如一个计算器应用，如果用户输入的是宽字符（可能包含非 ASCII 字符，虽然数字本身通常是 ASCII），就需要使用 `wcstod` 系列函数进行转换。
* **解析配置文件或数据:**  某些配置文件或数据格式可能使用宽字符编码来表示浮点数。Android 系统或应用在读取这些数据时，可能需要使用这些函数将其转换为数值类型。
* **JNI 调用:**  在 Java 代码中，如果需要将宽字符表示的数字传递给 Native 代码（通过 JNI），Native 代码可能会使用 `wcstod` 系列函数进行转换。
* **Webview 等组件:**  处理网页内容时，可能会遇到宽字符表示的数字，需要进行转换。

**举例说明:**

假设一个 Android 应用需要解析包含宽字符数字的字符串：

```c++
#include <iostream>
#include <wchar.h>
#include <locale.h>

int main() {
    setlocale(LC_ALL, "zh_CN.UTF-8"); // 设置本地化，支持宽字符
    const wchar_t* wide_str = L"  +3.14159 你好";
    wchar_t* end_ptr;
    double value = wcstod(wide_str, &end_ptr);

    std::wcout << L"原始字符串: " << wide_str << std::endl;
    std::wcout << L"转换后的值: " << value << std::endl;
    std::wcout << L"未转换部分: " << end_ptr << std::endl;

    return 0;
}
```

在这个例子中，`wcstod` 函数会忽略前导空格，并将 `L"+3.14159"` 转换为 `double` 类型的 `3.14159`。`end_ptr` 会指向字符串中未能成功转换的部分 `L" 你好"`。

**`libc` 函数的实现细节**

让我们详细分析一下 `wcstod` 模板函数的实现：

1. **去除前导空白:**
   ```c++
   while (iswspace(*str)) {
     str++;
   }
   ```
   这段代码使用 `iswspace` 函数检查当前字符是否是空白字符（例如空格、制表符等），如果是则跳过。

2. **确定可能构成浮点数的最长跨度:**
   ```c++
   size_t max_len = wcsspn(str, L"-+0123456789.xXeEpP()nNaAiIfFtTyY");
   ```
   `wcsspn` 函数计算从 `str` 开始，连续包含在第二个参数指定字符集中的字符的个数。这里指定的字符集包含了浮点数可能包含的所有合法字符（正负号、数字、小数点、指数符号、NaN 和 Infinity 的表示等）。

3. **将宽字符转换为 ASCII 字符:**
   ```c++
   char* ascii_str = new char[max_len + 1];
   if (!ascii_str) return float_type();
   for (size_t i = 0; i < max_len; ++i) {
     ascii_str[i] = str[i] & 0xff;
   }
   ascii_str[max_len] = 0;
   ```
   由于底层的浮点数转换函数（如 `strtod`）通常只处理 ASCII 字符，因此需要将宽字符字符串中可能构成数字的部分转换为 ASCII 字符串。这里通过简单的位运算 `& 0xff` 来截取宽字符的低 8 位，假设有效的数字部分都是 ASCII 字符。**这是一个重要的假设，如果宽字符表示的数字使用了非 ASCII 字符，则转换可能会出错。**

4. **设置伪造的 `FILE` 结构:**
   ```c++
   FILE f;
   __sfileext fext;
   _FILEEXT_SETUP(&f, &fext);
   f._flags = __SRD;
   f._bf._base = f._p = reinterpret_cast<unsigned char*>(ascii_str);
   f._bf._size = f._r = max_len;
   f._read = [](void*, char*, int) { return 0; }; // aka `eofread`
   f._lb._base = nullptr;
   ```
   这段代码是为了调用 `parsefloat` 函数。`parsefloat` 函数原本是设计用来从 `FILE` 流中解析浮点数的。由于没有直接从内存中的宽字符数组创建 `FILE` 流的便捷方法（类似于 `fmemopen` 的宽字符版本），Bionic 这里创建了一个假的 `FILE` 结构，将它的缓冲区指针指向了前面创建的 ASCII 字符串。`f._read` 被设置为一个总是返回 0 的函数，模拟文件结束。

5. **调用 `parsefloat` 进行更精确的分析:**
   ```c++
   size_t actual_len = parsefloat(&f, ascii_str, ascii_str + max_len);
   ```
   `parsefloat` 函数会更仔细地分析 ASCII 字符串，确定实际构成有效浮点数部分的长度。这个函数可以处理更复杂的浮点数格式，包括 NaN 和 Infinity 等。

6. **调用底层的 ASCII 转换函数:**
   ```c++
   char* ascii_end;
   float_type result = strtod_fn(ascii_str, &ascii_end);
   if (ascii_end != ascii_str + actual_len) abort();
   ```
   最终，调用标准的 ASCII 字符串到浮点数转换函数 (`strtof`, `strtod`, 或 `strtold`) 来完成实际的转换。这里会检查 `ascii_end` 指针是否指向了 `parsefloat` 确定的有效数字部分的末尾，如果不一致则说明内部逻辑错误，会调用 `abort()` 终止程序。

7. **处理 `end` 指针:**
   ```c++
   if (end) {
     if (actual_len == 0) {
       *end = const_cast<wchar_t*>(original_str);
     } else {
       *end = const_cast<wchar_t*>(str) + actual_len;
     }
   }
   ```
   如果调用者提供了 `end` 指针，则根据转换结果更新该指针。如果转换失败（`actual_len` 为 0），则 `end` 指针指向原始字符串的开始；否则，指向成功转换部分的末尾。

8. **释放内存:**
   ```c++
   delete[] ascii_str;
   ```
   释放之前分配的 ASCII 字符串的内存。

**涉及 dynamic linker 的功能**

`wcstod.cpp` 本身并没有直接涉及 dynamic linker 的操作。它是一个被编译成 `libc.so` 库的代码。Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 的作用是在程序启动时，将程序依赖的动态链接库加载到内存中，并解析库之间的符号引用。

**SO 布局样本:**

`libc.so` 是一个非常庞大的动态链接库，包含了各种 C 标准库的实现。一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text:  // 代码段
        wcstof:  <-- wcstof 函数的代码
        wcstod:  <-- wcstod 函数的代码
        wcstold: <-- wcstold 函数的代码
        strtof:  <-- strtof 函数的代码
        strtod:  <-- strtod 函数的代码
        strtold: <-- strtold 函数的代码
        iswspace:
        wcsspn:
        parsefloat:
        ... 其他 C 标准库函数 ...
    .data:  // 数据段
        ... 全局变量 ...
    .rodata: // 只读数据段
        ... 常量字符串 ...
    .dynamic: // 动态链接信息
        ... 依赖的库 ...
        ... 符号表 ...
        ... 重定位表 ...
```

**链接的处理过程:**

1. **编译时:** 当编译链接一个使用了 `wcstod` 等函数的程序或库时，编译器会将对这些函数的调用记录下来，生成相应的符号引用。
2. **加载时:** 当 Android 系统加载程序时，dynamic linker 会读取程序头部的动态链接信息，找到程序依赖的库（例如 `libc.so`）。
3. **加载库:** Dynamic linker 将 `libc.so` 加载到内存中的某个地址。
4. **符号解析:** Dynamic linker 扫描 `libc.so` 的符号表，找到程序中引用的 `wcstod`、`strtod` 等函数的地址。
5. **重定位:** Dynamic linker 更新程序代码中的符号引用，将它们指向 `libc.so` 中对应函数的实际内存地址。

在这个过程中，`wcstod` 函数本身可能会调用 `libc.so` 中其他的函数，例如 `iswspace`、`wcsspn`、`parsefloat` 以及底层的 ASCII 转换函数 `strtod` 等。这些函数之间的调用是库内部的，在 `libc.so` 加载时由 dynamic linker 完成地址解析。

**假设输入与输出**

* **假设输入:** `L"  -123.45e+2"`
* **输出:** `-12345.0`

* **假设输入:** `L"  +0.001 "`
* **输出:** `0.001`

* **假设输入:** `L"Infinity"` (假设系统支持宽字符的 Infinity 表示)
* **输出:** 正无穷大

* **假设输入:** `L"NaN"` (假设系统支持宽字符的 NaN 表示)
* **输出:** NaN (Not a Number)

* **假设输入:** `L"invalid"`
* **输出:** `0.0` (`end` 指针会指向 `L"invalid"`)

* **假设输入:** `L"  1.23abc"`
* **输出:** `1.23` (`end` 指针会指向 `L"abc"`)

**用户或编程常见的使用错误**

1. **未检查 `end` 指针:** 调用 `wcstod` 后，应该检查 `end` 指针指向的位置，以判断整个字符串是否都被成功转换。如果 `*end` 不指向字符串的结尾，则说明字符串中包含无法转换为数字的部分。

   ```c++
   wchar_t* end_ptr;
   double value = wcstod(L"123.45abc", &end_ptr);
   if (*end_ptr != L'\0') {
       // 字符串包含无效字符
       std::wcerr << L"转换失败，剩余部分: " << end_ptr << std::endl;
   }
   ```

2. **假设输入始终有效:**  不应该假设 `wcstod` 的输入总是有效的数字字符串。必须处理转换失败的情况。

3. **忽略本地化设置:** 浮点数的表示（例如小数点是 `.` 还是 `,`）可能受到本地化设置的影响。如果程序需要处理特定格式的浮点数，需要确保本地化设置正确。虽然 `wcstod` 本身不直接处理本地化，但它调用的底层函数可能受到影响。Bionic 提供了 `wcstod_l` 等带 `_l` 后缀的版本，允许指定 `locale`。

4. **内存泄漏 (在早期版本或错误使用中):**  在当前的实现中，`ascii_str` 使用 `new` 分配，并使用 `delete[]` 释放，一般不会有内存泄漏。但在早期的实现或不正确的代码修改中，可能出现忘记释放内存的情况。

5. **缓冲区溢出 (理论上):**  在将宽字符转换为 ASCII 字符时，如果 `max_len` 计算错误，可能会导致 `ascii_str` 缓冲区溢出。但当前的实现中，`max_len` 的计算基于输入字符串，并且分配了足够的空间，因此不容易出现这个问题。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 直接调用:**  使用 Android NDK 开发 Native 代码时，可以直接调用 `wcstod` 等标准 C 库函数。例如：

   ```c++
   #include <jni.h>
   #include <wchar.h>
   #include <stdlib.h>

   extern "C" JNIEXPORT jdouble JNICALL
   Java_com_example_myapp_MainActivity_stringToDouble(JNIEnv *env, jobject /* this */, jstring jstr) {
       const wchar_t* wstr = env->GetStringChars(jstr, nullptr);
       wchar_t* end_ptr;
       double result = wcstod(wstr, &end_ptr);
       env->ReleaseStringChars(jstr, wstr);
       return result;
   }
   ```
   在这个例子中，Java 代码调用 `stringToDouble` 方法，将 Java 字符串传递给 Native 代码，Native 代码使用 `wcstod` 将其转换为 `double`。

2. **Android Framework 间接调用:**  Android Framework 本身是用 Java 编写的，通常不会直接调用 `wcstod`。但是，Framework 底层的某些组件或服务可能是用 C/C++ 编写的，并且会使用 Bionic 库。例如：
   * **System Server:**  System Server 进程包含许多用 C++ 编写的系统服务，它们可能会在处理配置文件或系统属性时使用 `wcstod`。
   * **Native Libraries:**  Framework 依赖的某些 Native 库（例如 Skia 图形库，Media Framework 的某些部分）可能会使用 `wcstod`。
   * **Webview (Chromium):**  Webview 组件底层是 Chromium，其 C++ 代码中可能会使用到浮点数转换函数。

**Frida Hook 示例调试步骤**

假设我们想 hook `wcstod` 函数，查看其参数和返回值。

**1. 准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在你的开发机器上安装了 Frida 客户端 (`pip install frida-tools`).

**2. 编写 Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const libc = Module.findBaseAddress("libc.so");
    const wcstodPtr = Module.getExportByName("libc.so", "wcstod");

    if (wcstodPtr) {
        Interceptor.attach(wcstodPtr, {
            onEnter: function (args) {
                const str = Memory.readUtf16String(args[0]);
                console.log("[wcstod] Entering, string:", str);
            },
            onLeave: function (retval) {
                console.log("[wcstod] Leaving, return value:", retval);
            }
        });
        console.log("[wcstod] Hooked!");
    } else {
        console.error("[wcstod] Not found!");
    }
} else {
    console.log("Skipping hook on non-ARM architecture.");
}
```

**3. 运行 Frida 脚本:**

* 找到目标 Android 应用的进程 ID 或包名。例如，使用 `adb shell ps | grep <app_name>`。
* 使用 Frida 客户端连接到目标进程并运行脚本：

```bash
frida -U -f <package_name> -l wcstod_hook.js --no-pause
# 或者如果进程已经在运行
frida -U <process_id> -l wcstod_hook.js
```

**调试步骤说明:**

* **`Process.arch`:**  检查进程架构，因为 `wcstod` 可能只存在于 `libc.so` 中。
* **`Module.findBaseAddress("libc.so")`:** 获取 `libc.so` 库的基地址。
* **`Module.getExportByName("libc.so", "wcstod")`:** 获取 `wcstod` 函数的地址。
* **`Interceptor.attach(wcstodPtr, ...)`:** 拦截对 `wcstod` 函数的调用。
* **`onEnter`:** 在 `wcstod` 函数执行之前调用。`args[0]` 包含了指向宽字符字符串的指针。我们使用 `Memory.readUtf16String` 读取字符串内容。
* **`onLeave`:** 在 `wcstod` 函数执行之后调用。`retval` 包含了函数的返回值（转换后的浮点数）。

**示例输出:**

当目标应用调用 `wcstod` 时，Frida 会在控制台上输出类似以下信息：

```
[#] Frida: Listening on 127.0.0.1:27042
[#] ^C
[wcstod] Hooked!
[wcstod] Entering, string:   3.14
[wcstod] Leaving, return value: 3.14
[wcstod] Entering, string: 1.23e-2
[wcstod] Leaving, return value: 0.0123
```

通过这种方式，你可以观察 `wcstod` 函数的调用情况，包括传入的参数和返回的值，从而进行调试和分析。

希望这个详尽的解答能够帮助你理解 `bionic/libc/bionic/wcstod.cpp` 文件的功能和实现细节，以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/wcstod.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <wchar.h>

#include <stdlib.h>
#include <string.h>

#include "local.h"

/// Performs wide-character string to floating point conversion.
template <typename float_type>
float_type wcstod(const wchar_t* str, wchar_t** end, float_type strtod_fn(const char*, char**)) {
  const wchar_t* original_str = str;
  while (iswspace(*str)) {
    str++;
  }

  // What's the longest span of the input that might be part of the float?
  size_t max_len = wcsspn(str, L"-+0123456789.xXeEpP()nNaAiIfFtTyY");

  // We know the only valid characters are ASCII, so convert them by brute force.
  char* ascii_str = new char[max_len + 1];
  if (!ascii_str) return float_type();
  for (size_t i = 0; i < max_len; ++i) {
    ascii_str[i] = str[i] & 0xff;
  }
  ascii_str[max_len] = 0;

  // Set up a fake FILE that points to those ASCII characters, for `parsefloat`.
  FILE f;
  __sfileext fext;
  _FILEEXT_SETUP(&f, &fext);
  f._flags = __SRD;
  f._bf._base = f._p = reinterpret_cast<unsigned char*>(ascii_str);
  f._bf._size = f._r = max_len;
  f._read = [](void*, char*, int) { return 0; }; // aka `eofread`, aka "no more data".
  f._lb._base = nullptr;

  // Ask `parsefloat` to look at the same data more carefully.

  // We can't just do this straight away because we can't construct a suitable FILE*
  // in the absence of any `fwmemopen` analogous to `fmemopen`. And we don't want to
  // duplicate the `parsefloat` logic. We also don't want to actually have to have wchar_t
  // implementations of the ASCII `strtod` logic (though if you were designing a libc
  // from scratch, you'd probably want to just make that more generic and lose all the
  // cruft on top).
  size_t actual_len = parsefloat(&f, ascii_str, ascii_str + max_len);

  // Finally let the ASCII conversion function do the work.
  char* ascii_end;
  float_type result = strtod_fn(ascii_str, &ascii_end);
  if (ascii_end != ascii_str + actual_len) abort();

  if (end) {
    if (actual_len == 0) {
      // There was an error. We need to set the end pointer back to the original string, not the
      // one we advanced past the leading whitespace.
      *end = const_cast<wchar_t*>(original_str);
    } else {
      *end = const_cast<wchar_t*>(str) + actual_len;
    }
  }

  delete[] ascii_str;
  return result;
}

float wcstof(const wchar_t* s, wchar_t** end) {
  return wcstod<float>(s, end, strtof);
}
__strong_alias(wcstof_l, wcstof);

double wcstod(const wchar_t* s, wchar_t** end) {
  return wcstod<double>(s, end, strtod);
}
__strong_alias(wcstod_l, wcstod);

long double wcstold(const wchar_t* s, wchar_t** end) {
  return wcstod<long double>(s, end, strtold);
}
__strong_alias(wcstold_l, wcstold);
```