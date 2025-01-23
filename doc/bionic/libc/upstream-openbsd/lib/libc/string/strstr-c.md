Response:
Let's break down the thought process for analyzing the `strstr.c` file.

**1. Understanding the Goal:**

The primary goal is to thoroughly analyze the provided C code for `strstr`, specifically within the context of Android's Bionic libc. This involves:

* **Functionality:**  What does the code *do*?
* **Android Relevance:** How does this function relate to the Android ecosystem?
* **Implementation Details:**  A deep dive into *how* the code works.
* **Dynamic Linking:**  If applicable, how does it interact with the dynamic linker?
* **Logic and Examples:**  Illustrative input/output scenarios.
* **Common Errors:**  Pitfalls developers might encounter.
* **Android Integration:** Tracing the path from the Android framework to this specific function.
* **Debugging:**  Providing a Frida hook example.

**2. Initial Code Scan and High-Level Understanding:**

* **Copyright and License:** Recognize the OpenBSD origin and the permissive license. This immediately tells us it's not solely Google's code.
* **Includes:** Note the standard includes `<string.h>` and `<stdint.h>`. This indicates basic string manipulation and integer types are involved.
* **Helper Functions:**  Spot the `twobyte_strstr`, `threebyte_strstr`, and `fourbyte_strstr` functions. Hypothesize they are optimized for short needles.
* **`twoway_strstr`:** Notice this function is more complex. The comment mentions "Two-way string-matching" and cites a research paper. This suggests a more sophisticated algorithm for longer needles.
* **`strstr` Function:** This is the main entry point. Observe the logic: it handles empty needles and then dispatches to the short-needle optimizations or the `twoway_strstr` function.
* **`DEF_STRONG(strstr)`:** This macro is Bionic-specific. It's likely related to defining a strong symbol for linking.

**3. Deep Dive into Individual Functions:**

* **Short-Needle Functions (`twobyte_strstr`, etc.):**
    * **Mechanism:** They use bitwise operations (`<<`, `|`) to efficiently compare substrings. The loop incrementally compares chunks of the haystack with the needle.
    * **Optimization:**  The benefit is likely reduced overhead compared to character-by-character comparison for very short needles.

* **`twoway_strstr` Function:**  This requires more attention.
    * **Comment:** The comment points to the "Two-way string-matching" algorithm by Crochemore and Perrin. This provides a valuable research starting point if deeper understanding is needed.
    * **`byteset` and `shift`:**  These arrays suggest a pre-processing step to optimize the search. `byteset` likely tracks characters present in the needle, and `shift` calculates how far to shift the haystack pointer.
    * **Maximal Suffix Calculation:** The code computes the "maximal suffix," a crucial part of the Two-Way algorithm. This helps in efficiently skipping mismatches.
    * **Periodic Needle Check:** The code checks if the needle has a repeating pattern. This is another optimization technique.
    * **Search Loop:** The main loop implements the core logic of the Two-Way algorithm, utilizing the precomputed information to efficiently search.

* **`strstr` Function (Main Logic):**
    * **Early Returns:**  Handling the empty needle and using `strchr` for single-character needles are important optimizations.
    * **Dispatching:** The clear logic of calling the specialized functions based on needle length is evident.

**4. Connecting to Android and Dynamic Linking:**

* **Bionic Context:**  Remember the file path: `bionic/libc/`. This immediately establishes the context. `strstr` is a fundamental C library function, so its presence in Bionic is expected.
* **`DEF_STRONG` Macro:** Research or prior knowledge about Bionic would reveal that this macro is used to define a strongly linked symbol. This is relevant for the dynamic linker.

**5. Examples, Errors, and Framework Integration:**

* **Input/Output Examples:**  Think of simple test cases to illustrate how `strstr` works (finding, not finding, empty strings).
* **Common Errors:**  Consider typical mistakes when using `strstr` (null pointers, assuming the returned pointer points to a modifiable string).
* **Android Framework/NDK:**  Trace how a higher-level Android component (e.g., a Java string operation, NDK code using `std::string::find`) might eventually call `strstr`. This requires understanding the layers of abstraction.

**6. Frida Hooking:**

* **Target Function:** Identify `strstr` as the function to hook.
* **Arguments and Return Value:**  Determine the types of the input arguments (`const char*`, `const char*`) and the return value (`char*`).
* **Frida Syntax:** Construct the Frida script using `Interceptor.attach`, access arguments using `args[]`, and the return value using `retval`.

**7. Structuring the Output:**

Organize the information logically based on the prompt's requirements:

* Functionality
* Android Relevance
* Implementation Details (for each function)
* Dynamic Linking
* Logic and Examples
* Common Errors
* Android Framework/NDK Path
* Frida Hook Example

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `twoway_strstr` is some complex Bionic-specific optimization.
* **Correction:** The comment clearly points to a well-known string searching algorithm. Researching this algorithm provides a much deeper understanding.
* **Initial thought:** Focus only on the code within the file.
* **Correction:** Recognize the importance of the surrounding context – Bionic, the role of `libc`, and the dynamic linker. The `DEF_STRONG` macro is a key example of this.
* **Ensuring Clarity:**  Use clear and concise language. Explain technical terms when necessary. Provide code snippets to illustrate points.

By following these steps, combining code analysis with contextual knowledge and research, we can generate a comprehensive and accurate explanation of the `strstr.c` file within the Android Bionic environment.
好的，让我们来详细分析一下 Android Bionic 中 `bionic/libc/upstream-openbsd/lib/libc/string/strstr.c` 这个文件的源代码。

**文件功能：**

该文件实现了 `strstr` 函数，其功能是在一个字符串（`haystack`，被搜索的字符串）中查找第一次出现另一个字符串（`needle`，要查找的字符串）的位置。如果找到，则返回指向 `haystack` 中第一次出现 `needle` 子字符串的指针；如果未找到，则返回 `NULL`。

**与 Android 功能的关系及举例说明：**

`strstr` 是一个标准的 C 库函数，在 Android 系统中被广泛使用。任何需要在一个字符串中查找子字符串的地方都可能用到它。

**举例：**

* **Android Framework:**
    * 在解析 URI 或者 URL 的时候，可能会使用 `strstr` 来查找特定的分隔符或者关键词。例如，在解析 "https://www.example.com/path?query=value" 这个 URL 时，可能用 `strstr` 查找 "?" 来分割路径和查询参数。
    * 在处理文件路径时，可能需要查找特定的目录名或者文件名。
    * 在日志系统中，可能会使用 `strstr` 来过滤或者查找包含特定关键词的日志信息。

* **NDK 开发:**
    * 使用 C/C++ 进行 Android 原生开发（NDK）时，可以直接调用 `strstr` 函数。例如，一个网络应用可能需要检查接收到的数据包是否包含特定的协议头。
    * 在进行文本处理、数据解析等操作时，`strstr` 都是一个常用的工具。

**libc 函数功能实现详解：**

该文件中的 `strstr` 函数实现采取了一些优化策略，特别是针对短的 `needle` 字符串。

1. **空 `needle` 处理:**
   ```c
   if (!n[0]) return (char *)h;
   ```
   如果 `needle` 是空字符串，则根据 C 标准，`strstr` 应该返回指向 `haystack` 开头的指针。

2. **短 `needle` 优化:**
   为了提高效率，对于长度较小的 `needle`，代码使用了专门优化的函数：
   * **长度为 1:** 使用 `strchr(h, *n)`。`strchr` 函数专门用于查找单个字符，通常比通用的 `strstr` 更快。
   * **长度为 2, 3, 4:** 使用 `twobyte_strstr`, `threebyte_strstr`, `fourbyte_strstr`。这些函数通过一次比较多个字节来加速查找过程。例如，`twobyte_strstr` 将 `needle` 和 `haystack` 中连续的两个字节组合成 16 位整数进行比较。

   ```c
   h = strchr(h, *n);
   if (!h || !n[1]) return (char *)h;
   if (!h[1]) return 0;
   if (!n[2]) return twobyte_strstr((void *)h, (void *)n);
   if (!h[2]) return 0;
   if (!n[3]) return threebyte_strstr((void *)h, (void *)n);
   if (!h[3]) return 0;
   if (!n[4]) return fourbyte_strstr((void *)h, (void *)n);
   ```

   让我们详细看一个短 `needle` 优化的例子 `twobyte_strstr`:

   ```c
   static char *
   twobyte_strstr(const unsigned char *h, const unsigned char *n)
   {
       uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
       for (h++; *h && hw != nw; hw = hw<<8 | *++h);
       return *h ? (char *)h-1 : 0;
   }
   ```
   - `uint16_t nw = n[0]<<8 | n[1];`: 将 `needle` 的前两个字符组合成一个 16 位整数 `nw`。
   - `uint16_t hw = h[0]<<8 | h[1];`: 将 `haystack` 的前两个字符组合成一个 16 位整数 `hw`。
   - `for (h++; *h && hw != nw; hw = hw<<8 | *++h);`: 循环遍历 `haystack`。
     - `h++`:  `haystack` 指针向前移动一个位置。
     - `*h`: 检查当前 `haystack` 指针是否指向字符串的结尾。
     - `hw != nw`: 比较 `haystack` 当前位置的两个字符与 `needle` 的两个字符是否相等。
     - `hw = hw<<8 | *++h;`: 如果不相等，则更新 `hw`，将之前的第二个字符移到高 8 位，并将 `haystack` 的下一个字符放入低 8 位，相当于滑动窗口。
   - `return *h ? (char *)h-1 : 0;`: 如果找到匹配，则返回指向 `haystack` 中匹配子字符串起始位置的指针（`h-1` 是因为循环开始时 `h` 就已经自增了）；否则返回 `NULL`。

3. **长 `needle` 处理:**
   对于长度较长的 `needle`，代码使用了 **Two-Way 字符串匹配算法** (由 Maxime Crochemore 和 Dominique Perrin 提出)。这种算法通常比简单的暴力匹配更有效。

   ```c
   return twoway_strstr((void *)h, (void *)n);
   ```

   `twoway_strstr` 函数的实现比较复杂，涉及到以下几个步骤：

   - **预处理 `needle`：**
     - 计算 `needle` 的长度。
     - 构建 `byteset` 表：记录 `needle` 中出现的所有字符，用于快速判断 `haystack` 的当前字符是否可能匹配。
     - 构建 `shift` 表：用于在不匹配时快速移动 `haystack` 指针。
     - 计算 `needle` 的最大后缀 (maximal suffix)，这在 Two-Way 算法中至关重要，用于确定比较的方向和跳跃的距离。

   - **搜索过程：**
     - 使用两个指针（隐式地通过索引操作）在 `haystack` 中滑动窗口。
     - 首先比较窗口的最后一个字符，如果与 `needle` 的最后一个字符不匹配，则根据 `shift` 表移动窗口。
     - 如果最后一个字符匹配，则向左和向右比较剩余的字符，以确认整个 `needle` 是否匹配。

   Two-Way 算法的核心思想是通过预处理 `needle` 来避免在 `haystack` 中进行不必要的比较，从而提高搜索效率。

**涉及 dynamic linker 的功能：**

在这个 `strstr.c` 文件中，并没有直接涉及 dynamic linker 的功能。`strstr` 是一个标准的 C 库函数，它的链接是由 dynamic linker 在程序启动时处理的。

**so 布局样本以及链接的处理过程：**

当一个 Android 应用或者 native 库链接到 `libc.so` 时，`strstr` 函数的符号会被解析。

**so 布局样本 (简化)：**

```
libc.so:
    ...
    .text:
        ...
        strstr:  # strstr 函数的代码
        ...
    .data:
        ...
    .bss:
        ...
    .symtab:
        ...
        strstr  (address of strstr function)
        ...
```

**链接处理过程：**

1. **编译时：** 编译器在编译使用了 `strstr` 的代码时，会生成对 `strstr` 函数的未解析引用。

2. **链接时：** 链接器（在 Android 上通常是 `lld`）会将所有的目标文件和库文件链接在一起。当链接器遇到对 `strstr` 的未解析引用时，它会在链接的库文件（通常是 `libc.so`）的符号表（`.symtab`）中查找 `strstr` 的符号。

3. **运行时：** 当应用启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库（如 `libc.so`）。
   - dynamic linker 会解析应用或库中对外部符号的引用，包括 `strstr`。
   - 它会查找 `libc.so` 的符号表，找到 `strstr` 函数的实际地址。
   - 它会将应用或库中对 `strstr` 的调用重定向到 `libc.so` 中 `strstr` 函数的地址。

**逻辑推理、假设输入与输出：**

**假设输入 1:**
`haystack = "This is a test string"`
`needle = "test"`
**输出:** 指向 `haystack` 中 "test" 子字符串起始位置的指针。

**假设输入 2:**
`haystack = "This is a test string"`
`needle = "not found"`
**输出:** `NULL`

**假设输入 3:**
`haystack = "This is a test string"`
`needle = ""`
**输出:** 指向 `haystack` 开头的指针。

**假设输入 4:**
`haystack = "aaaaa"`
`needle = "aaa"`
**输出:** 指向 `haystack` 第一个 "aaa" 的起始位置的指针。

**用户或者编程常见的使用错误：**

1. **空指针检查不足:**  `strstr` 返回 `NULL` 表示未找到子字符串。如果代码没有正确检查返回值，就可能导致空指针解引用错误。

   ```c
   char *result = strstr(haystack, needle);
   // 错误：如果 result 为 NULL，访问 result[0] 会导致崩溃
   if (result[0] == 't') {
       // ...
   }

   // 正确的做法：
   if (result != NULL) {
       if (*result == 't') {
           // ...
       }
   }
   ```

2. **修改返回的字符串:** `strstr` 返回的是指向 `haystack` 内部的指针。修改这个指针指向的内容会修改原始的 `haystack` 字符串，这可能不是期望的行为，并且在 `haystack` 是字符串字面量时会导致未定义行为。

   ```c
   char haystack[] = "hello world";
   char *result = strstr(haystack, "world");
   if (result != NULL) {
       result[0] = 'W'; // 正确，修改了 haystack
   }

   const char *haystack2 = "hello world";
   char *result2 = strstr(haystack2, "world");
   if (result2 != NULL) {
       // 错误：修改字符串字面量会导致未定义行为
       // result2[0] = 'W';
   }
   ```

3. **混淆 `haystack` 和 `needle` 的顺序:**  `strstr` 的第一个参数是 `haystack` (被搜索的字符串)，第二个参数是 `needle` (要查找的字符串)。顺序错误会导致查找失败。

**说明 Android Framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `strstr` 的路径 (示例):**

假设一个 Java 应用需要在用户输入的字符串中查找特定的关键词。

1. **Java 代码:**
   ```java
   String input = "User entered: example keyword";
   String keyword = "keyword";
   if (input.contains(keyword)) {
       Log.d("MyApp", "Keyword found!");
   }
   ```

2. **`String.contains()` 的实现:** `String.contains()` 方法最终会调用 `String.indexOf()`。

3. **`String.indexOf()` 的实现 (OpenJDK):**  在 OpenJDK 的 `String` 类中，`indexOf()` 有多种实现，最终可能会使用优化的 native 方法。

4. **Native 方法调用:**  如果 `indexOf()` 使用 native 方法，它会通过 JNI (Java Native Interface) 调用到 Android 运行时库 (ART)。

5. **ART 和 Bionic:** ART 内部的字符串处理函数可能会直接或间接地调用 Bionic 提供的字符串函数，包括 `strstr`。例如，ART 可能有自己的 `String` 实现，但对于底层的字符串查找操作，可能会委托给 `strstr`。

**NDK 到 `strstr` 的路径:**

如果开发者使用 NDK 进行原生开发，可以直接调用 `strstr`。

1. **NDK C/C++ 代码:**
   ```c++
   #include <string.h>
   #include <jni.h>

   extern "C" JNIEXPORT jboolean JNICALL
   Java_com_example_myapp_MainActivity_findKeyword(JNIEnv *env, jobject /* this */, jstring text, jstring keyword) {
       const char *nativeText = env->GetStringUTFChars(text, 0);
       const char *nativeKeyword = env->GetStringUTFChars(keyword, 0);

       char *result = strstr(nativeText, nativeKeyword);

       env->ReleaseStringUTFChars(text, nativeText);
       env->ReleaseStringUTFChars(keyword, nativeKeyword);

       return result != nullptr;
   }
   ```

**Frida Hook 示例调试步骤:**

假设我们要 hook NDK 代码中对 `strstr` 的调用。

1. **准备 Frida 环境:** 确保你的设备已 root，安装了 Frida 和 Frida Server。

2. **编写 Frida 脚本:**

   ```javascript
   Java.perform(function() {
       var nativeFunc = Module.findExportByName("libc.so", "strstr");
       if (nativeFunc) {
           Interceptor.attach(nativeFunc, {
               onEnter: function(args) {
                   var haystack = Memory.readUtf8String(args[0]);
                   var needle = Memory.readUtf8String(args[1]);
                   console.log("[strstr] Haystack: " + haystack);
                   console.log("[strstr] Needle: " + needle);
               },
               onLeave: function(retval) {
                   if (retval.isNull()) {
                       console.log("[strstr] Result: NULL");
                   } else {
                       console.log("[strstr] Result: " + retval);
                   }
               }
           });
           console.log("Hooked strstr in libc.so");
       } else {
           console.log("Failed to find strstr in libc.so");
       }
   });
   ```

3. **运行 Frida 脚本:** 使用 Frida 命令行工具将脚本附加到目标应用进程。

   ```bash
   frida -U -f com.example.myapp -l your_frida_script.js --no-pause
   ```

   将 `com.example.myapp` 替换为你的应用包名，`your_frida_script.js` 替换为你的 Frida 脚本文件名。

4. **操作应用:** 运行你的 Android 应用，触发调用 `strstr` 的代码路径（例如，在输入框中输入包含关键词的文本）。

5. **查看 Frida 输出:** Frida 会打印出 `strstr` 函数的调用信息，包括 `haystack`、`needle` 和返回结果。

**Frida Hook 示例说明:**

* `Java.perform(function() { ... });`: 确保 Frida 代码在 Java VM 上下文中运行。
* `Module.findExportByName("libc.so", "strstr");`: 查找 `libc.so` 中导出的 `strstr` 函数的地址。
* `Interceptor.attach(nativeFunc, { ... });`: 拦截对 `strstr` 函数的调用。
* `onEnter: function(args) { ... }`: 在 `strstr` 函数执行之前调用。`args[0]` 和 `args[1]` 分别是 `haystack` 和 `needle` 的指针。`Memory.readUtf8String()` 用于读取指针指向的字符串。
* `onLeave: function(retval) { ... }`: 在 `strstr` 函数执行之后调用。`retval` 是函数的返回值。
* `console.log(...)`: 将信息打印到 Frida 控制台。

通过这个 Frida 脚本，你可以动态地观察 `strstr` 函数的调用情况，帮助你理解 Android Framework 或 NDK 是如何一步步地调用到这个 libc 函数的。

希望以上分析能够帮助你理解 Android Bionic 中 `strstr.c` 文件的功能、实现以及在 Android 系统中的应用。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/string/strstr.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: strstr.c,v 1.9 2020/04/16 12:37:52 claudio Exp $ */

/*
 * Copyright (c) 2005-2018 Rich Felker
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include <stdint.h>

static char *
twobyte_strstr(const unsigned char *h, const unsigned char *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	for (h++; *h && hw != nw; hw = hw<<8 | *++h);
	return *h ? (char *)h-1 : 0;
}

static char *
threebyte_strstr(const unsigned char *h, const unsigned char *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	for (h+=2; *h && hw != nw; hw = (hw|*++h)<<8);
	return *h ? (char *)h-2 : 0;
}

static char *
fourbyte_strstr(const unsigned char *h, const unsigned char *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	for (h+=3; *h && hw != nw; hw = hw<<8 | *++h);
	return *h ? (char *)h-3 : 0;
}

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*sizeof *(a))] op (size_t)1<<((size_t)(b)%(8*sizeof *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
static char *
twoway_strstr(const unsigned char *h, const unsigned char *n)
{
	const unsigned char *z;
	size_t l, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / sizeof(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	for (l=0; n[l] && h[l]; l++)
		BITOP(byteset, n[l], |=), shift[n[l]] = l+1;
	if (n[l]) return 0; /* hit the end of h */

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	while (jp+k<l) {
		if (n[ip+k] == n[jp+k]) {
			if (k == p) {
				jp += p;
				k = 1;
			} else k++;
		} else if (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} else {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	while (jp+k<l) {
		if (n[ip+k] == n[jp+k]) {
			if (k == p) {
				jp += p;
				k = 1;
			} else k++;
		} else if (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} else {
			ip = jp++;
			k = p = 1;
		}
	}
	if (ip+1 > ms+1) ms = ip;
	else p = p0;

	/* Periodic needle? */
	if (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} else mem0 = l-p;
	mem = 0;

	/* Initialize incremental end-of-haystack pointer */
	z = h;

	/* Search loop */
	for (;;) {
		/* Update incremental end-of-haystack pointer */
		if (z-h < l) {
			/* Fast estimate for MIN(l,63) */
			size_t grow = l | 63;
			const unsigned char *z2 = memchr(z, 0, grow);
			if (z2) {
				z = z2;
				if (z-h < l) return 0;
			} else z += grow;
		}

		/* Check last byte first; advance by shift on mismatch */
		if (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			if (k) {
				if (k < mem) k = mem;
				h += k;
				mem = 0;
				continue;
			}
		} else {
			h += l;
			mem = 0;
			continue;
		}

		/* Compare right half */
		for (k=MAX(ms+1,mem); n[k] && n[k] == h[k]; k++);
		if (n[k]) {
			h += k-ms;
			mem = 0;
			continue;
		}
		/* Compare left half */
		for (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		if (k <= mem) return (char *)h;
		h += p;
		mem = mem0;
	}
}

char *
strstr(const char *h, const char *n)
{
	/* Return immediately on empty needle */
	if (!n[0]) return (char *)h;

	/* Use faster algorithms for short needles */
	h = strchr(h, *n);
	if (!h || !n[1]) return (char *)h;
	if (!h[1]) return 0;
	if (!n[2]) return twobyte_strstr((void *)h, (void *)n);
	if (!h[2]) return 0;
	if (!n[3]) return threebyte_strstr((void *)h, (void *)n);
	if (!h[3]) return 0;
	if (!n[4]) return fourbyte_strstr((void *)h, (void *)n);

	return twoway_strstr((void *)h, (void *)n);
}
DEF_STRONG(strstr);
```