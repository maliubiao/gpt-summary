Response:
Here's a breakdown of the thought process used to generate the detailed answer:

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code (`locale.cpp`) and explain its functionality, its relation to Android, and how it interacts with the Android system, including dynamic linking and usage patterns. The answer needs to be in Chinese and should include examples and a Frida hook demonstration.

2. **Initial Code Scan and High-Level Functionality:** The first step is to read through the code and identify the core purpose. The file name (`locale.cpp`) and the included headers (`locale.h`, `wchar.h`, etc.) immediately suggest that this code deals with locale management. The comments at the beginning confirm this and explicitly state the supported locales: "C" and "C.UTF-8". The code also includes functions like `setlocale`, `uselocale`, `localeconv`, `newlocale`, `duplocale`, and `freelocale`, which are standard C library functions for locale manipulation.

3. **Break Down Each Function:**  The next step is to analyze each function individually:

    * **`__bionic_current_locale_is_utf8`:** Identify this as a global variable indicating the current locale's UTF-8 status.
    * **`__locale_t`:**  Recognize this as a simple structure to hold locale-specific data, currently only `mb_cur_max`.
    * **`__alloc_locale`:** Understand its role in allocating memory for `__locale_t`. The comment about avoiding `new/delete` is important to note.
    * **`get_locale_mb_cur_max`:**  Determine how it retrieves the maximum number of bytes per multibyte character, handling the global locale case.
    * **`__ctype_get_mb_cur_max`:** Connect this to character type functions and how they determine the multibyte character width.
    * **`g_locale_once` and `g_locale`:** Identify the mechanism for initializing the `lconv` structure once.
    * **`__locale_init`:**  Analyze the initialization of the `lconv` structure with default (mostly empty) values. Emphasize that Android's bionic provides minimal locale support.
    * **`__is_supported_locale`:**  List the supported locale names.
    * **`__is_utf8_locale`:** Determine how UTF-8 locales are identified.
    * **`localeconv`:** Explain its role in returning the `lconv` structure and the single initialization.
    * **`duplocale`:** Explain how it duplicates a locale object.
    * **`freelocale`:** Explain how it frees a locale object.
    * **`newlocale`:** Explain its function in creating a new locale object, including validation and the limitation of supported locales.
    * **`setlocale`:** Explain its function in setting the global locale and the limitations on supported locales.
    * **`get_current_locale_ptr`:**  Explain how it accesses the thread-local storage for the current locale. This is a key detail for understanding thread-safety.
    * **`uselocale`:** Explain how it sets and retrieves the thread-specific locale. Emphasize the initial `LC_GLOBAL_LOCALE` and how it's managed.

4. **Relate to Android Functionality:**  Think about how locale settings impact Android applications:

    * **Text display:**  UTF-8 handling is crucial for supporting various languages.
    * **Number and date formatting:**  While `lconv` is mostly empty, the framework builds upon this.
    * **Internationalization:**  The limited support in bionic influences how apps handle localization.
    * **NDK usage:**  Highlight how NDK developers interact with these functions.

5. **Explain Libc Function Implementation:** For each function, provide a detailed explanation of *how* it works, referring back to the code. Focus on the key logic, such as the use of thread-local storage, the limited supported locales, and the initialization of `lconv`.

6. **Address Dynamic Linking:**

    * **SO Layout:**  Create a simplified example of how `libc.so` would be structured, including the `.text`, `.data`, `.bss`, and `.plt.got` sections.
    * **Linking Process:**  Explain the role of the dynamic linker (`/linker64` or `/linker`) in resolving symbols, using `uselocale` as an example. Describe the steps involved: symbol lookup in the `.dynsym` table, GOT and PLT entries, and the dynamic linker's role.

7. **Provide Logic Inference (Assumptions and Outputs):**  Create simple scenarios to illustrate how the functions behave with different inputs. For example, calling `setlocale` with different locale names and observing the return value and the state of `__bionic_current_locale_is_utf8`.

8. **Illustrate Common User/Programming Errors:**  Think about typical mistakes developers might make when working with locales:

    * Assuming full locale support.
    * Incorrectly interpreting return values.
    * Threading issues (though bionic's implementation is relatively simple in this regard).

9. **Explain Android Framework and NDK Interaction:**  Trace how locale settings propagate from the Android framework down to the NDK and bionic:

    * **Framework:**  Settings app, system locale settings.
    * **System Services:** How these settings are communicated to apps.
    * **App Process:**  How the app's process inherits or sets locale information.
    * **NDK:**  How NDK code calls `setlocale`, `uselocale`, etc.

10. **Demonstrate with Frida Hook:**  Create a practical Frida script to intercept calls to `setlocale` and `uselocale`. This provides a concrete way to observe the function calls and arguments at runtime. Explain the purpose of the script and how to use it.

11. **Structure and Language:** Organize the answer logically with clear headings and subheadings. Use precise and accurate Chinese terminology. Ensure that the explanation is easy to understand, even for someone who might not be deeply familiar with the bionic library.

12. **Review and Refine:**  Read through the entire answer to check for clarity, accuracy, and completeness. Make any necessary corrections or improvements. For instance, ensure consistent terminology and that all parts of the prompt have been addressed. For example, initially, I might have focused too much on individual function details and not enough on the broader Android context. Reviewing would highlight this and prompt me to add more information about the framework and NDK interaction.
好的，让我们详细分析一下 `bionic/libc/bionic/locale.cpp` 文件的功能和实现。

**文件功能总览**

`locale.cpp` 文件是 Android Bionic C 库中负责处理本地化 (locale) 相关的设置和功能的源代码文件。其主要功能是：

1. **管理当前线程和全局的 locale 设置:**  允许程序查询和设置当前线程或全局的 locale 设置。
2. **支持有限的 locale:** Bionic 仅支持 "C" (或 "POSIX") 和 "C.UTF-8" (或 "en_US.UTF-8") 两种 locale。这意味着在 Android 上，应用程序的 locale 支持是相对有限的。
3. **提供 locale 相关的 C 标准库函数:** 实现了 `setlocale`, `uselocale`, `localeconv`, `newlocale`, `duplocale`, 和 `freelocale` 等标准 C 库函数。
4. **提供获取多字节字符最大长度的函数:**  `__ctype_get_mb_cur_max` 用于获取当前 locale 下多字节字符的最大字节数。

**与 Android 功能的关系及举例说明**

虽然 Bionic 的 locale 支持有限，但它仍然是 Android 系统中处理国际化和本地化的基础。

* **字符编码处理:**  "C.UTF-8" locale 的支持使得 Android 能够正确处理 UTF-8 编码的文本，这是显示各种语言文字的基础。例如，当一个应用需要显示中文、日文或韩文时，依赖于底层的 locale 设置为 UTF-8。
* **C 库函数的行为:** 某些 C 库函数的行为会受到 locale 设置的影响，例如 `printf` 格式化数字时的小数点分隔符。虽然 Bionic 的 `localeconv` 返回的结构体大部分字段为空，但 `decimal_point` 字段被设置为 "."，这影响了浮点数的默认输出格式。
* **NDK 开发:** NDK 开发人员可以使用 `setlocale` 等函数来尝试设置 locale。尽管 Bionic 只支持两种，但理解其行为对于处理国际化相关的 NDK 代码仍然很重要。

**详细解释 libc 函数的功能和实现**

让我们逐个分析 `locale.cpp` 中实现的 libc 函数：

1. **`__bionic_current_locale_is_utf8` (静态全局变量):**
   - **功能:**  指示当前全局 locale 是否为 UTF-8。
   - **实现:**  当调用 `setlocale` 设置全局 locale 时，此变量会被更新。

2. **`struct __locale_t`:**
   - **功能:**  一个简单的结构体，用于存储 locale 相关的信息。目前只包含 `mb_cur_max` (多字节字符的最大字节数)。
   - **实现:**  用于 `newlocale` 和 `duplocale` 创建 locale 对象。

3. **`__alloc_locale(size_t mb_cur_max)` (静态内联函数):**
   - **功能:**  分配 `__locale_t` 结构体的内存，并设置 `mb_cur_max`。
   - **实现:**  使用 `malloc` 分配内存。避免使用 `new/delete` 是为了防止用户重载了这些运算符导致意外行为。

4. **`get_locale_mb_cur_max(locale_t l)` (静态内联函数):**
   - **功能:**  获取给定 locale 的 `mb_cur_max` 值。
   - **实现:**  如果 `l` 是 `LC_GLOBAL_LOCALE`，则根据全局的 `__bionic_current_locale_is_utf8` 返回 4 (UTF-8) 或 1 (非 UTF-8)。否则，返回 `l->mb_cur_max`。

5. **`__ctype_get_mb_cur_max()`:**
   - **功能:**  获取当前 locale 下多字节字符的最大字节数。这个函数通常被 `<ctype.h>` 中的字符分类函数使用。
   - **实现:**  调用 `uselocale(nullptr)` 获取当前线程的 locale，然后调用 `get_locale_mb_cur_max` 获取其 `mb_cur_max`。

6. **`g_locale_once` 和 `g_locale` (静态全局变量):**
   - **功能:**  `g_locale_once` 用于确保 `__locale_init` 函数只被调用一次（线程安全），`g_locale` 存储 locale 的数字格式信息 (struct `lconv`)。
   - **实现:**  `pthread_once` 机制保证初始化只执行一次。

7. **`__locale_init()` (静态函数):**
   - **功能:**  初始化 `g_locale` 结构体。
   - **实现:**  Bionic 的实现非常简单，只设置了 `decimal_point` 为 "."，其他数字格式相关的字段都设置为空字符串或 `CHAR_MAX`，表明 Android 提供的 locale 信息非常有限。

8. **`__is_supported_locale(const char* locale_name)` (静态函数):**
   - **功能:**  检查给定的 locale 名称是否是 Bionic 支持的 locale。
   - **实现:**  通过字符串比较判断是否为 "", "C", "C.UTF-8", "en_US.UTF-8", 或 "POSIX"。

9. **`__is_utf8_locale(const char* locale_name)` (静态函数):**
   - **功能:**  判断给定的 locale 名称是否是 UTF-8 locale。
   - **实现:**  如果 locale 名称为空字符串或包含 "UTF-8" 子串，则认为是 UTF-8 locale。

10. **`localeconv()`:**
    - **功能:**  返回当前 locale 的数字格式信息 (指向 `lconv` 结构体的指针)。
    - **实现:**  使用 `pthread_once` 调用 `__locale_init` 进行初始化，然后返回指向静态变量 `g_locale` 的指针。由于 `g_locale` 的内容几乎为空，实际上能提供的格式信息很少。

11. **`duplocale(locale_t l)`:**
    - **功能:**  复制一个 locale 对象。
    - **实现:**  调用 `__alloc_locale` 分配新的 `__locale_t` 结构体，并复制原始 locale 的 `mb_cur_max`。

12. **`freelocale(locale_t l)`:**
    - **功能:**  释放由 `newlocale` 或 `duplocale` 创建的 locale 对象。
    - **实现:**  调用 `free` 释放内存。

13. **`newlocale(int category_mask, const char* locale_name, locale_t /*base*/)`:**
    - **功能:**  创建一个新的 locale 对象。`category_mask` 指定了影响哪些 locale 类别 (例如 `LC_CTYPE`, `LC_NUMERIC`)，但 Bionic 的实现并没有真正区分这些类别。
    - **实现:**
        - 检查 `category_mask` 和 `locale_name` 的有效性。
        - 调用 `__is_supported_locale` 检查 `locale_name` 是否被支持。
        - 调用 `__alloc_locale` 创建新的 locale 对象，并根据 `locale_name` 是否是 UTF-8 设置 `mb_cur_max` 为 4 或 1。

14. **`setlocale(int category, const char* locale_name)`:**
    - **功能:**  设置或查询全局的 locale。
    - **实现:**
        - 检查 `category` 的有效性。Bionic 的实现忽略了 `category`，总是设置所有类别。
        - 如果 `locale_name` 不为 `nullptr` (表示要设置 locale):
            - 调用 `__is_supported_locale` 检查 locale 是否被支持。
            - 更新全局变量 `__bionic_current_locale_is_utf8`。
        - 返回当前的全局 locale 名称 ("C.UTF-8" 或 "C")。

15. **`get_current_locale_ptr()` (静态函数):**
    - **功能:**  获取指向当前线程的 locale 变量的指针。
    - **实现:**  使用 Bionic 的线程本地存储机制 `__get_bionic_tls().locale` 来存储每个线程的 locale 信息。

16. **`uselocale(locale_t new_locale)`:**
    - **功能:**  设置或查询当前线程的 locale。
    - **实现:**
        - 获取当前线程的 locale (从 TLS 中获取)。如果这是线程第一次调用 `uselocale`，则返回 `LC_GLOBAL_LOCALE`。
        - 如果 `new_locale` 不为 `nullptr`，则将当前线程的 locale 设置为 `new_locale`。
        - 返回之前的线程 locale。

**涉及 dynamic linker 的功能**

`locale.cpp` 中并没有直接涉及动态链接器的具体功能，因为它本身是 `libc.so` 的一部分。但是，理解动态链接对于理解 `uselocale` 的工作方式至关重要，因为它使用了线程本地存储 (TLS)。

**SO 布局样本 (libc.so 的简化示例)**

```
libc.so:
    .text          # 存放代码段，包括 uselocale 等函数的指令
    .rodata        # 存放只读数据，例如字符串常量
    .data          # 存放已初始化的全局变量，例如 g_locale
    .bss           # 存放未初始化的全局变量
    .tbss          # 存放线程本地存储 (TLS) 的未初始化变量
    .tdata         # 存放线程本地存储 (TLS) 的已初始化变量
    .plt           # Procedure Linkage Table，用于延迟绑定
    .got           # Global Offset Table，用于存储全局变量的地址
    .dynsym        # 动态符号表，包含导出的和导入的符号
    .dynstr        # 动态字符串表，存储符号名称
    .hash          # 符号哈希表，加速符号查找
    ...
```

**链接的处理过程 (以 `uselocale` 为例)**

1. **符号查找:** 当应用程序调用 `uselocale` 时，如果该符号在应用程序自身中未定义，则动态链接器会负责找到 `libc.so` 中 `uselocale` 的定义。
2. **GOT 和 PLT:**
   - 首次调用 `uselocale` 时，会通过 PLT 跳转到动态链接器。
   - 动态链接器在 `.dynsym` 中查找 `uselocale` 的地址。
   - 动态链接器将 `uselocale` 的实际地址写入 GOT 表中对应的条目。
   - 后续对 `uselocale` 的调用将直接通过 GOT 表跳转到其实现。
3. **线程本地存储 (TLS):** `uselocale` 的实现依赖于 TLS 来存储每个线程的 locale 信息。
   - 动态链接器在加载 `libc.so` 时会处理 TLS 的分配和初始化。
   - `__get_bionic_tls()` 函数会返回指向当前线程 TLS 块的指针。
   - 每个线程都有自己独立的 `locale` 变量存储在 TLS 中，因此 `uselocale` 可以安全地在多线程环境中使用。

**逻辑推理 (假设输入与输出)**

**假设输入:**

```c++
#include <locale.h>
#include <stdio.h>

int main() {
  printf("Initial locale: %s\n", setlocale(LC_ALL, nullptr));

  locale_t new_loc = newlocale(LC_ALL_MASK, "C.UTF-8", nullptr);
  uselocale(new_loc);
  printf("Current thread locale: %s\n", setlocale(LC_ALL, nullptr));

  setlocale(LC_ALL, "C");
  printf("Global locale after setting: %s\n", setlocale(LC_ALL, nullptr));

  uselocale(LC_GLOBAL_LOCALE);
  printf("Current thread locale after resetting to global: %s\n", setlocale(LC_ALL, nullptr));

  freelocale(new_loc);
  return 0;
}
```

**预期输出:**

```
Initial locale: C.UTF-8  // 假设初始全局 locale 是 UTF-8
Current thread locale: C.UTF-8
Global locale after setting: C
Current thread locale after resetting to global: C
```

**解释:**

- 初始全局 locale 可能是 "C.UTF-8" (Android 的默认行为)。
- `newlocale` 创建了一个 "C.UTF-8" 的 locale 对象。
- `uselocale` 将当前线程的 locale 设置为新创建的 locale。
- `setlocale(LC_ALL, "C")` 修改了全局 locale 为 "C"。
- `uselocale(LC_GLOBAL_LOCALE)` 将当前线程的 locale 重置为全局 locale。

**用户或编程常见的使用错误**

1. **假设支持所有 locale:**  新手开发者可能会尝试使用 `setlocale` 设置除 "C" 和 "C.UTF-8" 之外的 locale，导致失败 (`setlocale` 返回 `nullptr` 且 `errno` 设置为 `ENOENT`).
   ```c++
   setlocale(LC_ALL, "fr_FR.UTF-8"); // 在 Android 上会失败
   if (setlocale(LC_ALL, "fr_FR.UTF-8") == nullptr) {
       perror("setlocale failed"); // 输出 "setlocale failed: No such file or directory"
   }
   ```

2. **混淆全局和线程 locale:**  不理解 `setlocale` 修改全局 locale，而 `uselocale` 修改线程 locale，可能导致在多线程程序中出现意外的 locale 行为。

3. **不检查 `setlocale` 的返回值:**  如果 `setlocale` 调用失败，应该检查返回值并处理错误。

4. **过度依赖 `localeconv`:**  由于 Bionic 的 `localeconv` 返回的信息非常有限，过度依赖其返回值可能会导致程序在 Android 上的行为与在其他系统上不同。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 层):**
   - 当用户在 Android 系统的设置中更改语言和地区时，Framework 会接收到这些事件。
   - Framework 会更新系统属性，例如 `persist.sys.locale`。
   - 一些系统服务（例如 `SystemServer`）会读取这些属性。
   - 当启动新的应用进程时，`zygote` 进程会根据系统属性设置初始的进程 locale。这通常涉及到调用 `setlocale`。

2. **NDK (C/C++ 层):**
   - NDK 应用可以直接调用 `setlocale` 和 `uselocale` 等函数。
   - 当 NDK 应用启动时，它会继承 `zygote` 设置的初始 locale。
   - NDK 应用可以根据需要修改其线程或全局的 locale。

**Frida Hook 示例调试**

以下是一个使用 Frida Hook 拦截 `setlocale` 和 `uselocale` 函数调用的示例：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");

  if (libc) {
    const setlocalePtr = libc.getExportByName("setlocale");
    if (setlocalePtr) {
      Interceptor.attach(setlocalePtr, {
        onEnter: function (args) {
          const category = args[0].toInt32();
          const locale = args[1];
          const localeStr = locale ? Memory.readCString(locale) : null;
          console.log(`[setlocale] category: ${category}, locale: ${localeStr}`);
        },
        onLeave: function (retval) {
          const result = retval ? Memory.readCString(retval) : null;
          console.log(`[setlocale] returned: ${result}`);
        }
      });
    } else {
      console.log("[-] setlocale not found");
    }

    const uselocalePtr = libc.getExportByName("uselocale");
    if (uselocalePtr) {
      Interceptor.attach(uselocalePtr, {
        onEnter: function (args) {
          const locale = args[0];
          // 由于 locale_t 是一个指针，我们不能直接读取字符串
          console.log(`[uselocale] new_locale: ${locale}`);
        },
        onLeave: function (retval) {
          console.log(`[uselocale] returned: ${retval}`);
        }
      });
    } else {
      console.log("[-] uselocale not found");
    }
  } else {
    console.log("[-] libc.so not found");
  }
} else {
  console.log("[-] This script is for Android only");
}
```

**使用方法:**

1. 将以上 JavaScript 代码保存为 `locale_hook.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l locale_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l locale_hook.js
   ```
3. 当目标应用调用 `setlocale` 或 `uselocale` 时，Frida 会拦截这些调用并在控制台输出相关信息，例如传入的参数和返回值。

**调试步骤:**

1. 运行包含 `setlocale` 或 `uselocale` 调用的 Android 应用。
2. 查看 Frida 控制台的输出，可以观察到 `setlocale` 和 `uselocale` 的调用时机、设置的 locale 值等信息。
3. 可以根据 Hook 的输出，分析应用的 locale 设置行为，例如是否正确设置了需要的 locale，或者是否存在 locale 设置上的错误。

这个 Frida Hook 示例可以帮助开发者深入了解 Android 应用中 locale 的使用情况，并排查相关问题。

希望以上详细的分析能够帮助你理解 `bionic/libc/bionic/locale.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/locale.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <wchar.h>

#include "bionic/pthread_internal.h"
#include "platform/bionic/macros.h"

// We only support two locales, the "C" locale (also known as "POSIX"),
// and the "C.UTF-8" locale (also known as "en_US.UTF-8").

static bool __bionic_current_locale_is_utf8 = true;

struct __locale_t {
  size_t mb_cur_max;
};

// Avoid using new/delete in this file, because a user may have overridden
// new/delete, and we want to avoid making extraneous calls to them. This isn't
// an issue for libc.so in the platform, but this file is also compiled into the
// NDK's libandroid_support.a, and there are libc++ tests that count the number
// of calls to new/delete.
#pragma clang poison new delete

static inline locale_t __alloc_locale(size_t mb_cur_max) {
  auto result = static_cast<__locale_t*>(malloc(sizeof(__locale_t)));
  if (result == nullptr) return nullptr;
  result->mb_cur_max = mb_cur_max;
  return result;
}

static inline size_t get_locale_mb_cur_max(locale_t l) {
  if (l == LC_GLOBAL_LOCALE) {
    return __bionic_current_locale_is_utf8 ? 4 : 1;
  } else {
    return l->mb_cur_max;
  }
}

size_t __ctype_get_mb_cur_max() {
  return get_locale_mb_cur_max(uselocale(nullptr));
}

static pthread_once_t g_locale_once = PTHREAD_ONCE_INIT;
static lconv g_locale;

static void __locale_init() {
  g_locale.decimal_point = const_cast<char*>(".");

  char* not_available = const_cast<char*>("");
  g_locale.thousands_sep = not_available;
  g_locale.grouping = not_available;
  g_locale.int_curr_symbol = not_available;
  g_locale.currency_symbol = not_available;
  g_locale.mon_decimal_point = not_available;
  g_locale.mon_thousands_sep = not_available;
  g_locale.mon_grouping = not_available;
  g_locale.positive_sign = not_available;
  g_locale.negative_sign = not_available;

  g_locale.int_frac_digits = CHAR_MAX;
  g_locale.frac_digits = CHAR_MAX;
  g_locale.p_cs_precedes = CHAR_MAX;
  g_locale.p_sep_by_space = CHAR_MAX;
  g_locale.n_cs_precedes = CHAR_MAX;
  g_locale.n_sep_by_space = CHAR_MAX;
  g_locale.p_sign_posn = CHAR_MAX;
  g_locale.n_sign_posn = CHAR_MAX;
  g_locale.int_p_cs_precedes = CHAR_MAX;
  g_locale.int_p_sep_by_space = CHAR_MAX;
  g_locale.int_n_cs_precedes = CHAR_MAX;
  g_locale.int_n_sep_by_space = CHAR_MAX;
  g_locale.int_p_sign_posn = CHAR_MAX;
  g_locale.int_n_sign_posn = CHAR_MAX;
}

static bool __is_supported_locale(const char* locale_name) {
  return (strcmp(locale_name, "") == 0 ||
          strcmp(locale_name, "C") == 0 ||
          strcmp(locale_name, "C.UTF-8") == 0 ||
          strcmp(locale_name, "en_US.UTF-8") == 0 ||
          strcmp(locale_name, "POSIX") == 0);
}

static bool __is_utf8_locale(const char* locale_name) {
  return (*locale_name == '\0' || strstr(locale_name, "UTF-8"));
}

lconv* localeconv() {
  pthread_once(&g_locale_once, __locale_init);
  return &g_locale;
}

locale_t duplocale(locale_t l) {
  return __alloc_locale(get_locale_mb_cur_max(l));
}

void freelocale(locale_t l) {
  free(l);
}

locale_t newlocale(int category_mask, const char* locale_name, locale_t /*base*/) {
  // Are 'category_mask' and 'locale_name' valid?
  if ((category_mask & ~LC_ALL_MASK) != 0 || locale_name == nullptr) {
    errno = EINVAL;
    return nullptr;
  }

  if (!__is_supported_locale(locale_name)) {
    errno = ENOENT;
    return nullptr;
  }

  return __alloc_locale(__is_utf8_locale(locale_name) ? 4 : 1);
}

char* setlocale(int category, const char* locale_name) {
  // Is 'category' valid?
  if (category < LC_CTYPE || category > LC_IDENTIFICATION) {
    errno = EINVAL;
    return nullptr;
  }

  // Caller wants to set the locale rather than just query?
  if (locale_name != nullptr) {
    if (!__is_supported_locale(locale_name)) {
      // We don't support this locale.
      errno = ENOENT;
      return nullptr;
    }
    __bionic_current_locale_is_utf8 = __is_utf8_locale(locale_name);
  }

  return const_cast<char*>(__bionic_current_locale_is_utf8 ? "C.UTF-8" : "C");
}

static locale_t* get_current_locale_ptr() {
  return &__get_bionic_tls().locale;
}

locale_t uselocale(locale_t new_locale) {
  locale_t old_locale = *get_current_locale_ptr();

  // If this is the first call to uselocale(3) on this thread, we return LC_GLOBAL_LOCALE.
  if (old_locale == nullptr) {
    old_locale = LC_GLOBAL_LOCALE;
  }

  if (new_locale != nullptr) {
    *get_current_locale_ptr() = new_locale;
  }

  return old_locale;
}

"""

```