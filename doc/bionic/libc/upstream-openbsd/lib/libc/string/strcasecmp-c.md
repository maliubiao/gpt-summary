Response:
Let's break down the thought process for answering the request about `strcasecmp.c`.

**1. Understanding the Core Request:**

The request is to analyze the provided C code for `strcasecmp.c` (and implicitly `strncasecmp.c`), explain its functionality, its relevance to Android, its implementation details, how it fits into the Android ecosystem (including dynamic linking), common usage errors, and how to debug it. The key is to provide a comprehensive and detailed explanation.

**2. Initial Code Analysis (Skimming and Identifying Key Elements):**

* **Copyright and License:** Note the origin (OpenBSD) and the BSD license. This is important context.
* **Includes:**  `<string.h>` is the standard header for string functions in C.
* **`typedef unsigned char u_char;`:** This defines a common unsigned character type.
* **`static const u_char charmap[]`:** This is the core of the case-insensitive comparison logic. It maps characters to their lowercase equivalents (or themselves if already lowercase or non-alphabetic).
* **`strcasecmp(const char *s1, const char *s2)`:** The main function for case-insensitive string comparison.
* **`strncasecmp(const char *s1, const char *s2, size_t n)`:**  A version that compares at most `n` characters.
* **`DEF_WEAK(strcasecmp);` and `DEF_WEAK(strncasecmp);`:**  This is specific to Bionic/Android and indicates these functions are weak symbols, allowing for potential overrides.

**3. Detailed Functional Analysis:**

* **`strcasecmp`:**
    * **Purpose:** Compares two strings case-insensitively.
    * **Mechanism:** Iterates through the strings, comparing the lowercase (or mapped) versions of corresponding characters. Stops when a difference is found or the end of a string is reached.
    * **Return Value:**  Similar to `strcmp`: negative if `s1` is less than `s2`, positive if `s1` is greater than `s2`, and zero if they are equal (case-insensitively).
* **`strncasecmp`:**
    * **Purpose:** Compares at most `n` characters of two strings case-insensitively.
    * **Mechanism:** Similar to `strcasecmp`, but with a limit on the number of characters to compare.
    * **Return Value:** Same as `strcasecmp`.
    * **Edge Case:** Handles `n == 0` by immediately returning 0.

**4. Android Relevance:**

* **Core Library:**  `libc` is fundamental. These functions are used throughout the Android system and applications.
* **Case-Insensitive Operations:** Essential for things like:
    * **File system paths:**  While Linux is case-sensitive, Android often tries to be more user-friendly.
    * **Network protocols:** Many protocols are case-insensitive.
    * **Configuration files:**  Keywords might be case-insensitive.
    * **User input:**  Comparing user-entered strings without being strictly case-sensitive.

**5. Implementation Details:**

* **`charmap` Array:** Explain how this array works as a lookup table to convert characters to their lowercase equivalents. Highlight the ASCII assumption.
* **Looping Logic:** Describe how the `while` and `do-while` loops iterate and compare characters.
* **Early Exit:** Explain how the functions handle null terminators and early returns.

**6. Dynamic Linking:**

* **`DEF_WEAK` Macro:** Explain what a weak symbol is and why it's used in Android (allowing for overrides, often for optimization or customization).
* **SO Layout:**  Provide a basic example of how `libc.so` might be structured, showing where these functions would reside.
* **Linking Process:**  Explain at a high level how the dynamic linker resolves symbols, especially in the context of weak symbols. Mention the search order.

**7. Logical Reasoning (Assumptions and Outputs):**

Create clear examples demonstrating the behavior of `strcasecmp` and `strncasecmp` with various inputs, including:

* Identical strings (different cases).
* Strings that differ at the beginning.
* Strings that differ later on.
* Strings where one is a prefix of the other.
* Empty strings.
* `strncasecmp` with different values of `n`.

**8. Common Usage Errors:**

* **Incorrect Case Handling:**  Assuming case-sensitive comparison when `strcasecmp` is needed, or vice-versa.
* **Buffer Overflows (Less Likely Here):** While these specific functions don't directly write to memory, it's worth mentioning potential issues if the input pointers are invalid.
* **Ignoring Return Value:** Not properly checking the return value to determine the relationship between the strings.
* **Misunderstanding `strncasecmp`:** Not providing the correct `n` value.

**9. Android Framework/NDK and Frida Hooking:**

* **Framework:**  Trace a possible call path, starting from a high-level Android API (like `Intent` extras or file access) down to native code where these functions might be used.
* **NDK:** Explain how native code directly uses these functions via `<string.h>`.
* **Frida Hooking:** Provide a practical JavaScript example to intercept calls to `strcasecmp`, log arguments, and potentially modify behavior. Focus on the target function name and the need to attach to the correct process.

**10. Structure and Language:**

* **Organize:** Use clear headings and subheadings.
* **Clarity:** Explain technical terms simply.
* **Code Examples:**  Use code snippets to illustrate points.
* **Accuracy:** Ensure technical correctness.
* **Completeness:** Address all aspects of the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe I should go deep into assembly-level implementation. **Correction:** The prompt asks for functional explanation, so high-level C is sufficient. Assembly can be mentioned as a lower-level implementation detail but isn't the focus.
* **Initial thought:** Just list Android APIs that *might* use this. **Correction:** Provide a more concrete, albeit simplified, example of how it *could* be used within the Android framework.
* **Initial thought:**  Just provide the Frida hook syntax. **Correction:** Explain *why* each part of the Frida code is necessary (e.g., `NativePointer`, `readUtf8String`).

By following these steps and continuously refining the approach, we can construct a comprehensive and accurate answer that addresses all parts of the user's request.
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/string/strcasecmp.c` 这个文件。

**功能列举:**

这个文件定义了两个主要的 C 标准库函数，用于进行**不区分大小写**的字符串比较：

1. **`strcasecmp(const char *s1, const char *s2)`:**  比较字符串 `s1` 和 `s2`，忽略字母的大小写。
2. **`strncasecmp(const char *s1, const char *s2, size_t n)`:**  比较字符串 `s1` 和 `s2` 的前 `n` 个字符，忽略字母的大小写。

**与 Android 功能的关系及举例说明:**

这两个函数在 Android 系统和应用程序中被广泛使用，因为在很多场景下需要进行不区分大小写的字符串比较。以下是一些例子：

* **文件系统操作:**  尽管 Linux 文件系统本身是大小写敏感的，但在某些高层抽象或用户界面中，可能需要进行不区分大小写的路径或文件名比较。例如，在 `PackageManager` 中查找应用时，可能会使用 `strcasecmp` 来进行包名或应用名的匹配。
* **网络协议处理:** 许多网络协议（如 HTTP 头部）是大小写不敏感的。在 Android 的网络库（如 `libcurl` 或 Java 的 `HttpURLConnection`）中，可能会使用 `strcasecmp` 或 `strncasecmp` 来比较协议关键字。
* **配置文件的解析:** Android 系统和应用会读取各种配置文件。在解析这些文件时，可能需要不区分大小写地比较配置项的键值。
* **用户输入处理:** 在用户界面中，有时需要比较用户输入的字符串，例如用户名、密码等，可能需要在某些环节进行不区分大小写的比较。
* **Binder 通信:** 虽然 Binder 通信通常基于精确的字符串匹配，但在某些上层抽象中，为了提供更灵活的接口，可能会使用不区分大小写的比较。

**详细解释 libc 函数的功能是如何实现的:**

**1. `strcasecmp(const char *s1, const char *s2)`:**

* **核心思想:** 逐个比较两个字符串的字符，但在比较之前，将字符转换为统一的大小写形式（这里是转换为小写）。
* **实现步骤:**
    1. 获取一个指向预定义的字符映射表 `charmap` 的指针 `cm`。这个表的核心作用是将大写字母映射到对应的小写字母，而其他字符则映射到自身。
    2. 将输入的 `const char *` 类型的字符串指针 `s1` 和 `s2` 转换为 `const u_char *` 类型的指针 `us1` 和 `us2`，方便进行无符号字符的操作。
    3. 进入一个 `while` 循环，条件是 `cm[*us1] == cm[*us2++]`。这意味着：
        * `*us1` 和 `*us2` 分别获取当前 `s1` 和 `s2` 指向的字符。
        * `cm[*us1]` 和 `cm[*us2]` 通过 `charmap` 表将这两个字符转换为统一的大小写形式（实际上，`charmap` 设计为将大写字母转换为小写字母）。
        * 比较转换后的字符是否相等。
        * `us2++` 在比较后，将 `us2` 指针向后移动一位。
    4. 在循环内部，如果当前 `s1` 指向的字符是空字符 `\0`，则说明两个字符串在忽略大小写的情况下是相等的，函数返回 `0`。
    5. 如果循环因为遇到不同的字符而退出，则比较 `cm[*us1]` 和 `cm[*--us2]` 的值。注意，这里 `us2` 先自减，因为在 `while` 循环的条件判断中，`us2` 已经自增过了。
    6. 返回两个转换后字符的差值。如果 `cm[*us1]` 小于 `cm[*--us2]`，则返回负数；如果大于，则返回正数。

* **`charmap` 数组:** 这个数组是实现不区分大小写比较的关键。它是一个包含 256 个 `unsigned char` 的静态常量数组。对于 ASCII 字符集来说，它的设计如下：
    * 对于小写字母 'a' 到 'z'，`charmap['a']` 到 `charmap['z']` 的值就是它们自身。
    * 对于大写字母 'A' 到 'Z'，`charmap['A']` 到 `charmap['Z']` 的值被映射到对应的小写字母。例如，`charmap['A']` 的值是 'a'。
    * 对于其他字符（数字、符号等），`charmap` 的值就是字符本身。

**2. `strncasecmp(const char *s1, const char *s2, size_t n)`:**

* **核心思想:** 与 `strcasecmp` 类似，但不比较整个字符串，而是最多比较前 `n` 个字符（忽略大小写）。
* **实现步骤:**
    1. 首先检查 `n` 是否为 `0`。如果是，则表示不比较任何字符，直接返回 `0`（表示相等）。
    2. 获取指向 `charmap` 的指针 `cm`，并将 `s1` 和 `s2` 转换为 `const u_char *` 类型的指针 `us1` 和 `us2`。
    3. 进入一个 `do-while` 循环。
    4. 在循环内部，首先比较 `cm[*us1]` 和 `cm[*us2++]` 的值，与 `strcasecmp` 类似，进行不区分大小写的字符比较。如果不同，则立即返回差值。
    5. 如果当前 `s1` 指向的字符是空字符 `\0`，则说明在比较的前 `n` 个字符内，两个字符串是相等的，跳出循环。
    6. 递减计数器 `n`。
    7. `do-while` 循环的条件是 `n != 0`，即只要还有字符需要比较，就继续循环。
    8. 如果循环正常结束（即比较了 `n` 个字符或者遇到了空字符），则返回 `0`。

**涉及 dynamic linker 的功能 (弱符号):**

代码中出现了 `DEF_WEAK(strcasecmp);` 和 `DEF_WEAK(strncasecmp);`。 `DEF_WEAK` 是一个宏，在 Bionic 中用于声明**弱符号**。

* **弱符号的意义:**  弱符号允许在链接时，如果存在同名的强符号，则优先使用强符号。如果只存在弱符号，则使用弱符号的定义。这提供了一种机制，允许开发者或系统提供自定义的 `strcasecmp` 和 `strncasecmp` 实现，而无需修改 Bionic 提供的默认实现。

* **SO 布局样本 (libc.so):**

```
// 假设的 libc.so 布局

.text:
    ...
    strcasecmp:   // 弱符号的默认实现
        <strcasecmp 的机器码>
    ...
    strncasecmp:  // 弱符号的默认实现
        <strncasecmp 的机器码>
    ...

.data:
    charmap:
        <charmap 数组的数据>
    ...

// 如果有其他库或可执行文件定义了同名的强符号，
// 动态链接器会优先使用那些定义。
```

* **链接的处理过程:**

1. **编译时:** 编译器遇到 `DEF_WEAK(strcasecmp)` 时，会将 `strcasecmp` 标记为弱符号。
2. **链接时:** 当动态链接器加载一个依赖于 `libc.so` 的可执行文件或共享库时，如果该可执行文件或共享库也定义了一个名为 `strcasecmp` 的函数（并且该函数不是弱符号，即是强符号），则动态链接器会解析并绑定到该强符号的地址。
3. **如果没有找到强符号:** 如果没有找到同名的强符号，动态链接器会使用 `libc.so` 中提供的弱符号 `strcasecmp` 的定义。

**逻辑推理 (假设输入与输出):**

**`strcasecmp` 示例:**

| 输入 s1     | 输入 s2     | 输出 | 说明                                     |
|-------------|-------------|------|------------------------------------------|
| "hello"     | "HELLO"     | 0    | 忽略大小写，两个字符串相等                 |
| "apple"     | "Banana"    | 负数 | "apple" (小写) 小于 "banana" (小写)       |
| "zebra"     | "ant"       | 正数 | "zebra" (小写) 大于 "ant" (小写)          |
| "Test1"     | "test2"     | 负数 | '1' 的 ASCII 值小于 '2' 的 ASCII 值       |
| "abc"       | "abcd"      | 负数 | "abc" 是 "abcd" 的前缀                   |
| ""          | ""          | 0    | 两个空字符串相等                         |

**`strncasecmp` 示例:**

| 输入 s1     | 输入 s2     | 输入 n | 输出 | 说明                                           |
|-------------|-------------|--------|------|------------------------------------------------|
| "hello"     | "heLLO"     | 3      | 0    | 前 3 个字符 "hel" 和 "heL" (忽略大小写) 相等      |
| "apple"     | "Banana"    | 1      | 负数 | 第一个字符 'a' 小于 'b'                       |
| "TEST"      | "test"      | 10     | 0    | `n` 大于字符串长度，比较整个字符串，忽略大小写 |
| "abc"       | "abd"       | 2      | 0    | 前 2 个字符相等                                |
| "abc"       | "abd"       | 3      | 负数 | 第 3 个字符 'c' 小于 'd'                       |

**用户或编程常见的使用错误:**

1. **误用 `strcmp` 进行大小写不敏感的比较:** 有些开发者可能错误地使用 `strcmp` 来比较字符串，期望得到不区分大小写的结果，这会导致逻辑错误。
   ```c
   char str1[] = "Hello";
   char str2[] = "hello";
   if (strcmp(str1, str2) == 0) {
       // 这里的代码不会执行，因为 strcmp 区分大小写
   }
   if (strcasecmp(str1, str2) == 0) {
       // 这里的代码会执行
   }
   ```

2. **混淆 `strcasecmp` 和 `strncmp` 的使用场景:** 开发者可能在需要比较指定长度的字符串时，错误地使用了 `strcasecmp`，或者反之。

3. **忽略返回值:** 没有正确检查 `strcasecmp` 或 `strncasecmp` 的返回值，导致逻辑判断错误。返回值是判断字符串大小关系的依据，`0` 表示相等，负数表示第一个字符串小于第二个，正数表示第一个字符串大于第二个。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `strcasecmp` 的路径 (示例):**

1. **Java Framework 层:** 比如，在处理 Intent 的 Action 时，可能会进行字符串比较。例如，`Intent.ACTION_VIEW` 是一个常量字符串。

   ```java
   // Android Framework 代码示例 (简化)
   Intent intent = getIntent();
   if (Intent.ACTION_VIEW.equalsIgnoreCase(intent.getAction())) {
       // 处理 ACTION_VIEW intent
   }
   ```

   `equalsIgnoreCase` 方法在底层最终会调用到 native 代码进行不区分大小写的比较。

2. **Native 代码 (Framework 或 Libraries):**  `equalsIgnoreCase` 的 native 实现可能会使用 JNI 调用到 C/C++ 代码。在 C/C++ 代码中，可能会直接或间接地调用 `strcasecmp`。例如，Android 的 `libutils` 库中可能存在这样的调用。

3. **Bionic libc:** 最终，这些调用会链接到 Bionic 的 `libc.so` 中实现的 `strcasecmp` 函数。

**NDK 到 `strcasecmp` 的路径:**

1. **NDK 开发:**  开发者使用 NDK 编写 C/C++ 代码。
2. **直接调用:** 在 NDK 代码中，开发者可以直接包含 `<string.h>` 并调用 `strcasecmp` 或 `strncasecmp`。

   ```c++
   // NDK 代码示例
   #include <string.h>
   #include <jni.h>

   extern "C" JNIEXPORT jboolean JNICALL
   Java_com_example_myapp_MyClass_compareStrings(JNIEnv *env, jobject /* this */, jstring s1, jstring s2) {
       const char *str1 = env->GetStringUTFChars(s1, 0);
       const char *str2 = env->GetStringUTFChars(s2, 0);
       jboolean result = (strcasecmp(str1, str2) == 0);
       env->ReleaseStringUTFChars(s1, str1);
       env->ReleaseStringUTFChars(s2, str2);
       return result;
   }
   ```

3. **链接到 libc:**  当 NDK 代码被编译和链接时，`strcasecmp` 函数的符号会被解析到 Bionic 的 `libc.so` 中的实现。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `strcasecmp` 函数调用的示例：

```javascript
// frida hook 脚本
if (Process.platform === 'android') {
  const libc = Module.findExportByName("libc.so", "strcasecmp");

  if (libc) {
    Interceptor.attach(libc, {
      onEnter: function (args) {
        const s1 = Memory.readUtf8String(args[0]);
        const s2 = Memory.readUtf8String(args[1]);
        console.log(`[strcasecmp] s1: "${s1}", s2: "${s2}"`);
      },
      onLeave: function (retval) {
        console.log(`[strcasecmp] 返回值: ${retval}`);
      }
    });
    console.log("Hooked strcasecmp in libc.so");
  } else {
    console.log("strcasecmp not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**Frida Hook 代码解释:**

1. **检查平台:** `Process.platform === 'android'` 确保脚本只在 Android 平台上运行。
2. **查找 `strcasecmp`:** `Module.findExportByName("libc.so", "strcasecmp")` 尝试在 `libc.so` 中找到 `strcasecmp` 函数的地址。
3. **附加拦截器:** `Interceptor.attach(libc, ...)` 将一个拦截器附加到 `strcasecmp` 函数的入口和出口。
4. **`onEnter`:** 当 `strcasecmp` 被调用时，`onEnter` 函数会被执行。
   - `Memory.readUtf8String(args[0])` 和 `Memory.readUtf8String(args[1])` 读取 `strcasecmp` 的两个字符串参数。
   - `console.log` 打印出函数调用时的参数。
5. **`onLeave`:** 当 `strcasecmp` 函数执行完毕即将返回时，`onLeave` 函数会被执行。
   - `retval` 包含了 `strcasecmp` 的返回值。
   - `console.log` 打印出函数的返回值.

**使用 Frida 调试步骤:**

1. **安装 Frida:** 确保你的 Android 设备上安装了 Frida 服务，并且你的电脑上安装了 Frida 客户端。
2. **找到目标进程:** 确定你想监控的 Android 应用程序的进程 ID 或包名。
3. **运行 Frida 脚本:** 使用 Frida 客户端连接到目标进程，并运行上述 JavaScript 脚本。例如：
   ```bash
   frida -U -f com.example.myapp -l your_script.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U com.example.myapp -l your_script.js
   ```
4. **触发 `strcasecmp` 调用:** 在目标应用程序中执行一些操作，这些操作可能会导致 `strcasecmp` 函数被调用。
5. **查看 Frida 输出:**  Frida 会在终端中打印出 `strcasecmp` 函数被调用时的参数和返回值，帮助你理解函数的行为和调用上下文。

通过 Frida Hook，你可以动态地观察 `strcasecmp` 函数在 Android 系统或应用程序中的行为，这对于调试和逆向工程非常有用。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/string/strcasecmp.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: strcasecmp.c,v 1.7 2015/08/31 02:53:57 guenther Exp $	*/

/*
 * Copyright (c) 1987, 1993
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

#include <string.h>

typedef unsigned char u_char;

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
static const u_char charmap[] = {
	'\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
	'\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
	'\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
	'\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
	'\040', '\041', '\042', '\043', '\044', '\045', '\046', '\047',
	'\050', '\051', '\052', '\053', '\054', '\055', '\056', '\057',
	'\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
	'\070', '\071', '\072', '\073', '\074', '\075', '\076', '\077',
	'\100', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\133', '\134', '\135', '\136', '\137',
	'\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
	'\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
	'\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
	'\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
	'\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
	'\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
	'\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
	'\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
	'\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
	'\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
	'\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
	'\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
	'\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
	'\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
	'\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377',
};

int
strcasecmp(const char *s1, const char *s2)
{
	const u_char *cm = charmap;
	const u_char *us1 = (const u_char *)s1;
	const u_char *us2 = (const u_char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*--us2]);
}
DEF_WEAK(strcasecmp);

int
strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (n != 0) {
		const u_char *cm = charmap;
		const u_char *us1 = (const u_char *)s1;
		const u_char *us2 = (const u_char *)s2;

		do {
			if (cm[*us1] != cm[*us2++])
				return (cm[*us1] - cm[*--us2]);
			if (*us1++ == '\0')
				break;
		} while (--n != 0);
	}
	return (0);
}
DEF_WEAK(strncasecmp);
```