Response:
Let's break down the thought process to generate the comprehensive answer about `bionic/libc/include/bits/wctype.handroid`.

**1. Understanding the Request:**

The request asks for a detailed analysis of the provided C header file, `wctype.handroid`, within the context of Android's Bionic library. Key points of the request include:

* **Functionality:** What does this file *do*? What functions does it declare?
* **Android Relevance:** How are these functions used within Android? Examples are needed.
* **Implementation:**  How are these functions *actually* implemented?  This will involve speculation since only the header is provided.
* **Dynamic Linking:**  If dynamic linking is involved, explain the process and provide an example.
* **Logical Reasoning:**  If there are assumptions about input/output, illustrate them.
* **Common Errors:**  Point out typical mistakes programmers might make.
* **Android Framework/NDK Integration:** How does the code get invoked from higher levels?  Provide a Frida hook example.
* **Language:**  The answer must be in Chinese.

**2. Initial Analysis of the Header File:**

* **Copyright Notice:** This confirms it's part of the Android Open Source Project (AOSP).
* **Header Guard (`#ifndef _BITS_WCTYPE_H_`):**  Standard practice to prevent multiple inclusions.
* **Includes:**  It includes `sys/cdefs.h`, suggesting it deals with compiler definitions and potentially platform-specific aspects.
* **`__BEGIN_DECLS` and `__END_DECLS`:** These are likely macros to ensure proper C++ compatibility.
* **Type Definitions:**
    * `wint_t`:  Represents a wide character (integer type).
    * `wctype_t`:  Represents a character classification.
    * `wctrans_t`:  Represents a character transformation.
* **Macro Definition:** `WEOF`: Defines the wide character equivalent of EOF.
* **Function Declarations:** A series of `isw*` functions for character classification (alphanumeric, alphabetic, blank, etc.) and `tow*` functions for case conversion. Also, functions for handling character types and transformations (`wctype`, `iswctype`, `wctrans`, `towctrans`).
* **Availability Guard (`__BIONIC_AVAILABILITY_GUARD(26)`):** Indicates that `towctrans` and `wctrans` are only available from Android API level 26 onwards.

**3. Deconstructing the Request and Planning the Answer:**

Based on the initial analysis, I can structure the answer to address each part of the request:

* **功能 (Functionality):** Focus on the purpose of wide character handling and character classification/transformation.
* **Android 关系 (Android Relevance):** Think about where wide characters are commonly used in Android – internationalization (i18n), handling user input, file names, etc. Provide concrete examples like handling different language characters.
* **libc 函数实现 (libc Function Implementation):** Since only the header is available, I need to make educated guesses about the implementation. Likely involves lookup tables or range checks based on Unicode character properties. Emphasize that the actual implementation is in the `.c` files.
* **Dynamic Linker 功能 (Dynamic Linker Functionality):**  These functions are part of `libc.so`, which is dynamically linked. I need to describe the standard dynamic linking process: loading, symbol resolution, relocation. Create a simple `so` layout and illustrate the linking of a function call.
* **逻辑推理 (Logical Reasoning):**  For the `isw*` and `tow*` functions, provide simple examples of input wide characters and their expected output (true/false for `isw*`, transformed character for `tow*`).
* **常见错误 (Common Errors):**  Focus on typical mistakes when working with wide characters, such as incorrect character encoding, mixing narrow and wide characters, and forgetting to check return values.
* **Android Framework/NDK 到达 (Android Framework/NDK Arrival):**  Trace the path from higher levels of Android to these libc functions. Start with an app, then through the framework (e.g., TextView), then down to the NDK and finally to libc. The Frida hook example will be crucial here.
* **Frida Hook 示例 (Frida Hook Example):**  Write a practical Frida script to intercept one of the `isw*` functions, log arguments and return values, demonstrating how to debug these functions at runtime.

**4. Generating the Content (Iterative Process):**

* **Start with the basics:** Define the core purpose of the header file.
* **Elaborate on each function:** Briefly explain what each declared function does.
* **Connect to Android:** Think of specific scenarios where these functions would be used in an Android context.
* **Speculate on Implementation:**  Use general knowledge of C library implementations. Avoid definitive statements since the source isn't provided.
* **Dynamic Linking Explanation:** Describe the standard process. The `so` layout should be simple but illustrative.
* **Examples are key:** For logical reasoning and common errors, concrete examples make the explanation much clearer.
* **Framework/NDK Path:** Visualize the call stack. The Frida hook will help solidify this.
* **Frida Code:** Ensure the Frida script is functional and targets a relevant function.
* **Review and Refine:** Check for clarity, accuracy, and completeness. Make sure the Chinese is natural and easy to understand. Pay attention to the specific constraints of the prompt (e.g., "详细解释每一个libc函数的功能是如何实现的" - while I can't provide the *exact* implementation, I can describe the likely mechanisms).

**Self-Correction/Refinement during the process:**

* **Initial thought:** Directly copy the function descriptions from man pages.
* **Correction:** Rephrase them in the context of Android and the header file, focusing on the *declarations* and their general purpose.
* **Initial thought:** Provide a very complex dynamic linking scenario.
* **Correction:** Simplify the `so` layout and linking example to make it easier to grasp.
* **Initial thought:**  Only mention general Android usage.
* **Correction:** Provide more specific examples, like handling internationalized text input in UI elements.
* **Initial thought:**  Write a very basic Frida hook that just prints a message.
* **Correction:** Make the Frida hook more informative by logging arguments and the return value.

By following these steps and continuously refining the answer, I can generate a comprehensive and accurate response that addresses all aspects of the original request. The iterative process of analysis, planning, generation, and refinement is crucial for producing a high-quality answer.
这是一个定义了处理宽字符（wide character）的函数和类型的头文件 `wctype.handroid`，它是 Android Bionic C 库的一部分。它主要提供了用于字符分类和转换的工具，这些工具能够处理多字节字符，对于支持国际化和本地化非常重要。

以下是它的功能以及与 Android 的关系、实现细节、动态链接、逻辑推理、常见错误、以及 Android 框架和 NDK 如何到达这里的详细说明：

**1. 功能列表:**

该头文件定义了以下主要功能：

* **字符分类函数 (返回非零值表示真，零表示假):**
    * `iswalnum(wint_t __wc)`:  检查宽字符 `__wc` 是否是字母数字字符（字母或数字）。
    * `iswalpha(wint_t __wc)`:  检查宽字符 `__wc` 是否是字母字符。
    * `iswblank(wint_t __wc)`:  检查宽字符 `__wc` 是否是空白字符（空格或制表符）。
    * `iswcntrl(wint_t __wc)`:  检查宽字符 `__wc` 是否是控制字符。
    * `iswdigit(wint_t __wc)`:  检查宽字符 `__wc` 是否是数字字符。
    * `iswgraph(wint_t __wc)`:  检查宽字符 `__wc` 是否是图形字符（除空格外的可打印字符）。
    * `iswlower(wint_t __wc)`:  检查宽字符 `__wc` 是否是小写字母。
    * `iswprint(wint_t __wc)`:  检查宽字符 `__wc` 是否是可打印字符（包括空格）。
    * `iswpunct(wint_t __wc)`:  检查宽字符 `__wc` 是否是标点符号字符。
    * `iswspace(wint_t __wc)`:  检查宽字符 `__wc` 是否是空白字符（包括空格、换行符、制表符等）。
    * `iswupper(wint_t __wc)`:  检查宽字符 `__wc` 是否是大写字母。
    * `iswxdigit(wint_t __wc)`: 检查宽字符 `__wc` 是否是十六进制数字字符。

* **字符转换函数:**
    * `towlower(wint_t __wc)`: 将宽字符 `__wc` 转换为小写。
    * `towupper(wint_t __wc)`: 将宽字符 `__wc` 转换为大写。

* **宽字符类型和转换函数 (API level 26+):**
    * `wctype_t wctype(const char* _Nonnull __name)`:  根据给定的字符串 `__name` 返回一个表示字符分类的 `wctype_t` 对象。例如，`wctype("digit")` 返回表示数字分类的对象。
    * `int iswctype(wint_t __wc, wctype_t __type)`: 检查宽字符 `__wc` 是否属于 `__type` 指定的字符分类。
    * `wctrans_t _Nullable wctrans(const char* _Nonnull __name)`:  根据给定的字符串 `__name` 返回一个表示字符转换的 `wctrans_t` 对象。例如，`wctrans("tolower")` 返回表示转换为小写的对象。
    * `wint_t towctrans(wint_t __wc, wctrans_t _Nonnull __transform)`: 使用 `__transform` 指定的转换规则转换宽字符 `__wc`。

* **类型定义:**
    * `wint_t`:  通常是足够大的整数类型，可以表示任何扩展字符集中的字符。
    * `wctype_t`:  表示字符分类的类型。
    * `wctrans_t`: 表示字符转换的类型。

* **宏定义:**
    * `WEOF`:  宽字符版本的 EOF (文件结束符)，通常定义为 -1。

**2. 与 Android 功能的关系及举例说明:**

这些函数在 Android 中对于处理文本和字符数据至关重要，特别是在涉及国际化（i18n）和本地化（l10n）的场景下。Android 需要支持多种语言，这些语言的字符集可能超出 ASCII 的范围。

**举例说明:**

* **输入法 (IME):** 当用户使用输入法输入字符时，系统需要正确识别和处理各种语言的字符。`iswalpha` 可以用来判断用户输入的是否为字母字符，而 `towlower` 可以用来将输入的字符转换为小写进行统一处理。
* **文本显示:** Android 的 TextView 等 UI 组件需要正确渲染不同语言的文本。这些组件内部可能会使用 `iswprint` 来判断字符是否可打印，从而决定如何显示。
* **文件系统:**  虽然 Android 的文件路径通常使用 UTF-8 编码，但理解宽字符处理有助于理解底层如何处理文件名中的特殊字符。
* **国际化 API:** Android Framework 提供了 `java.lang.Character` 类和相关的国际化 API，这些 API 的底层实现可能依赖于 Bionic C 库提供的宽字符处理函数。例如，`Character.isLetter()` 在底层可能会调用 `iswalpha` 的实现。
* **NDK 开发:** 通过 NDK 进行 C/C++ 开发的开发者可以使用这些函数来处理字符串和字符数据，确保他们的应用能够正确处理多语言文本。

**3. libc 函数的功能实现:**

这些 libc 函数的具体实现通常在与头文件对应的 `.c` 源文件中。由于你只提供了头文件，我们只能推测其实现方式。一般来说，这些函数的实现可能基于以下几种策略：

* **查表法 (Lookup Table):** 对于字符分类，可能会使用大型的查找表，其中索引是字符的编码值，而表中的值指示该字符所属的类别。例如，一个表格可以存储每个 Unicode 代码点是否为字母、数字、空格等信息。
* **范围检查:** 对于某些字符类别（如数字、大小写字母），可以通过检查字符的编码值是否在特定的范围内来判断。例如，ASCII 编码中，大写字母 'A' 到 'Z' 的编码是连续的。
* **Unicode 属性数据库:** 更复杂的实现可能会依赖于 Unicode 标准提供的字符属性数据库 (Unicode Character Database, UCD)，该数据库包含了每个 Unicode 代码点的详细属性信息。Bionic 可能在内部使用了经过优化的 UCD 数据结构。
* **本地化信息:** 某些字符分类和转换可能受到当前语言环境 (locale) 的影响。例如，某些语言中可能存在特殊的排序规则或大小写转换规则。因此，实现可能需要考虑当前的 locale 设置。

**示例解释 `iswalpha` 的可能实现:**

```c
// (这只是一个简化的概念性示例，实际实现可能更复杂)
int iswalpha(wint_t wc) {
  // 假设我们使用一个查找表，或者直接检查 Unicode 属性
  if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z')) {
    return 1; // 是基本的拉丁字母
  }
  // 还需要检查其他语言的字母，这可能需要查表或者更复杂的逻辑
  // 例如，检查是否属于 Unicode 定义的 "Letter" 类别
  // ...
  return 0;
}
```

**4. 涉及 dynamic linker 的功能:**

这个头文件本身**不直接**涉及 dynamic linker 的功能。它定义的是 C 库中的函数接口。然而，这些函数的**实现代码**位于 Bionic 的共享库 `libc.so` 中。当程序调用这些函数时，dynamic linker 负责将这些函数链接到程序的地址空间。

**so 布局样本:**

假设 `libc.so` 的部分布局如下（简化表示）：

```
libc.so:
  .text:
    _start:  // 程序入口点（不是这里定义的函数）
    iswalnum: // iswalnum 函数的机器码
    iswalpha: // iswalpha 函数的机器码
    towlower: // towlower 函数的机器码
    // ... 其他 libc 函数的机器码
  .rodata:
    // 常量数据，例如字符分类表
  .data:
    // 全局变量
  .dynsym:
    iswalnum  (地址)
    iswalpha  (地址)
    towlower  (地址)
    // ... 其他导出符号
  .dynstr:
    "iswalnum"
    "iswalpha"
    "towlower"
    // ... 其他导出符号的字符串表示
```

**链接的处理过程:**

1. **编译时:** 当你编译使用这些函数的代码时，编译器会生成对这些函数的**外部符号引用**。例如，如果你调用了 `iswalpha`，编译器会生成一条指令，指示需要调用名为 `iswalpha` 的函数。
2. **链接时:** 静态链接器（通常是 `ld`）在链接你的程序时，如果发现对 `libc.so` 中定义的符号的引用，它会在生成的可执行文件中记录这些依赖关系。
3. **运行时:** 当你的 Android 应用启动时，系统的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
    * 加载可执行文件到内存。
    * 解析可执行文件的头部信息，找到依赖的共享库列表（例如 `libc.so`）。
    * 加载 `libc.so` 到内存的某个地址空间。
    * **符号解析 (Symbol Resolution):**  遍历可执行文件中对外部符号的引用，然后在 `libc.so` 的 `.dynsym` 段中查找对应的符号（例如 `iswalpha`）。找到后，dynamic linker 会获取该符号在 `libc.so` 中的地址。
    * **重定位 (Relocation):**  更新可执行文件中的指令，将对 `iswalpha` 等函数的引用替换为它们在 `libc.so` 中的实际内存地址。这样，当程序执行到调用 `iswalpha` 的指令时，就能跳转到 `libc.so` 中 `iswalpha` 的代码执行。

**5. 逻辑推理 (假设输入与输出):**

* **假设输入:** `wint_t wc = L'A';` (宽字符 'A')
    * `iswalnum(wc)` 输出: 非零值 (真)，因为 'A' 是字母数字字符。
    * `iswalpha(wc)` 输出: 非零值 (真)，因为 'A' 是字母字符。
    * `iswlower(wc)` 输出: 零 (假)，因为 'A' 不是小写字母。
    * `towlower(wc)` 输出: `L'a'`，因为 'A' 的小写形式是 'a'。

* **假设输入:** `wint_t wc = L'9';` (宽字符 '9')
    * `iswalnum(wc)` 输出: 非零值 (真)，因为 '9' 是字母数字字符。
    * `iswdigit(wc)` 输出: 非零值 (真)，因为 '9' 是数字字符。
    * `iswalpha(wc)` 输出: 零 (假)，因为 '9' 不是字母字符。

* **假设输入:** `wint_t wc = L' ';` (宽字符 空格)
    * `iswspace(wc)` 输出: 非零值 (真)，因为空格是空白字符。
    * `iswprint(wc)` 输出: 非零值 (真)，因为空格是可打印字符。
    * `iswgraph(wc)` 输出: 零 (假)，因为空格不是图形字符。

**6. 涉及用户或者编程常见的使用错误:**

* **混淆窄字符和宽字符:**  新手容易混淆 `char` 和 `wchar_t` (或 `wint_t`) 类型，错误地将窄字符传递给需要宽字符的函数，或者反之。这会导致未定义的行为或编译错误。
    ```c
    char c = 'A';
    iswalpha(c); // 错误：应该传递 wint_t
    ```
* **不正确的字符编码:**  如果程序处理的字符编码与当前 locale 设置不一致，宽字符函数可能会返回错误的结果。例如，如果字符串是用 UTF-8 编码的，而 locale 设置为 ISO-8859-1，则某些非 ASCII 字符可能无法正确分类。
* **忘记设置 locale:** 某些宽字符函数的行为可能依赖于当前的 locale 设置。如果程序没有正确设置 locale，可能会得到与预期不同的结果。可以使用 `setlocale(LC_ALL, "zh_CN.UTF-8");` 等函数设置 locale。
* **错误地使用返回值:** 某些函数（如字符转换函数）会返回转换后的字符，而某些函数（如字符分类函数）会返回 0 或非零值表示真假。容易混淆这些返回值。
* **API level 限制:**  `towctrans` 和 `wctrans` 函数在 Android API level 26 及更高版本才可用。如果在较低版本的 Android 系统上使用这些函数，会导致运行时错误。

**7. 说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `wctype.h` 的路径 (示例，以 TextView 显示文本为例):**

1. **Android 应用 (Java 代码):** 你创建一个 `TextView` 并设置文本内容，例如包含中文的字符串。
   ```java
   TextView textView = findViewById(R.id.myTextView);
   textView.setText("你好");
   ```

2. **Android Framework (Java 代码):** `TextView` 的 `setText()` 方法最终会调用到 Native 层，进行文本渲染。这个过程可能涉及：
   * `android.widget.TextView` 类的方法调用。
   * 调用到 `android.graphics.Canvas` 或其他图形相关的 Native 方法。
   * 这些 Native 方法通常位于 Android Framework 的 C++ 代码中 (例如 Skia 图形库)。

3. **NDK (C/C++ 代码 in Android Framework):**  在 Framework 的 Native 代码中，当需要处理文本时，可能会使用到 C 标准库提供的函数。例如，当需要判断一个字符是否是可打印字符以便进行绘制时，可能会间接地调用到 `iswprint`。

4. **Bionic C 库 (`libc.so`):**  Framework 的 Native 代码链接到 Bionic C 库。当调用 `iswprint` 等函数时，实际执行的是 `libc.so` 中对应的实现代码。`wctype.h` 头文件定义了这些函数的接口，并在编译时被包含进来。

**NDK 应用直接到达 `wctype.h`:**

1. **NDK 应用 (C/C++ 代码):**  你的 NDK 应用直接调用了 `wctype.h` 中声明的函数。
   ```c++
   #include <wchar.h>
   #include <wctype.h>

   void process_char(wchar_t wc) {
       if (iswalpha(wc)) {
           // ...
       }
   }
   ```

2. **编译链接:** NDK 编译器会将你的代码与 Bionic C 库链接。

3. **运行时:** 当你的 NDK 应用执行到调用 `iswalpha` 的代码时，会跳转到 `libc.so` 中 `iswalpha` 的实现。

**Frida Hook 示例:**

以下是一个使用 Frida hook `iswalpha` 函数的示例，用于观察其行为：

```python
import frida
import sys

package_name = "your.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
except frida.TimedOutError:
    print("[-] Device not found or busy.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "iswalpha"), {
    onEnter: function(args) {
        var wc = ptr(args[0]).readU32();
        console.log("[iswalpha] Input wide char:", wc, String.fromCharCode(wc));
    },
    onLeave: function(retval) {
        console.log("[iswalpha] Return value:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
device.resume(pid)

print("[*] Script loaded. Press Ctrl+C to detach.")
sys.stdin.read()
session.detach()
```

**使用方法:**

1. 确保你的 Android 设备已连接并通过 ADB 授权。
2. 安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 将 `your.package.name` 替换为你要调试的 Android 应用的包名。
4. 运行这个 Python 脚本。
5. 在你的 Android 应用中执行一些会涉及到字符处理的操作（例如，在 `TextView` 中显示包含字母的文本）。

**输出示例:**

你可能会在 Frida 的输出中看到类似以下的信息：

```
[*] [iswalpha] Input wide char: 65 A
[*] [iswalpha] Return value: 1
[*] [iswalpha] Input wide char: 97 a
[*] [iswalpha] Return value: 1
[*] [iswalpha] Input wide char: 20320 你
[*] [iswalpha] Return value: 0
```

这个输出表明 Frida 成功 hook 了 `iswalpha` 函数，并记录了每次调用时的输入宽字符的值（以十进制和字符形式显示）以及返回值。你可以观察到，对于英文字母 'A' 和 'a'，`iswalpha` 返回 1 (真)，而对于汉字 "你"，返回 0 (假)。

这个 Frida 示例可以帮助你理解在 Android 应用的运行时，何时以及如何调用 Bionic C 库中的宽字符处理函数。你可以根据需要修改脚本来 hook 其他函数并观察它们的行为。

### 提示词
```
这是目录为bionic/libc/include/bits/wctype.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _BITS_WCTYPE_H_
#define _BITS_WCTYPE_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

typedef __WINT_TYPE__ wint_t;

#define WEOF __BIONIC_CAST(static_cast, wint_t, -1)

int iswalnum(wint_t __wc);
int iswalpha(wint_t __wc);
int iswblank(wint_t __wc);
int iswcntrl(wint_t __wc);
int iswdigit(wint_t __wc);
int iswgraph(wint_t __wc);
int iswlower(wint_t __wc);
int iswprint(wint_t __wc);
int iswpunct(wint_t __wc);
int iswspace(wint_t __wc);
int iswupper(wint_t __wc);
int iswxdigit(wint_t __wc);

wint_t towlower(wint_t __wc);
wint_t towupper(wint_t __wc);

typedef long wctype_t;
wctype_t wctype(const char* _Nonnull __name);
int iswctype(wint_t __wc, wctype_t __type);

typedef const void* wctrans_t;

#if __BIONIC_AVAILABILITY_GUARD(26)
wint_t towctrans(wint_t __wc, wctrans_t _Nonnull __transform) __INTRODUCED_IN(26);
wctrans_t _Nullable wctrans(const char* _Nonnull __name) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


__END_DECLS

#endif
```