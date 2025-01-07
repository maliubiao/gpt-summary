Response:
Let's break down the thought process for answering the user's request. The request is quite comprehensive, asking for a detailed analysis of a C++ test file. Here's a possible internal monologue and steps:

1. **Understand the Core Request:** The user wants to know *everything* about this `wctype_test.cpp` file within the context of Android's Bionic library. This means looking at functionality, relation to Android, implementation details, dynamic linking, potential errors, and how Android apps reach this code.

2. **Initial Scan and Functionality Identification:** The first step is to read through the code and identify the main purpose. It's clearly a test file for functions related to wide character classification and transformation (`wctype.h`). The tests are using Google Test (`gtest`). Key function groups being tested are:
    * `isw*` functions (e.g., `iswalnum`, `iswalpha`) - checking character properties.
    * `towlower`, `towupper` - case conversion.
    * `wctype`, `iswctype` - character classification using named categories.
    * `wctrans`, `towctrans` - character transformation using named transformations.
    * Locale-aware versions of these functions (ending with `_l`).

3. **Relate to Android:**  The file is part of Bionic, which *is* Android's C library. So the connection is direct. The tests ensure the correctness of the wide character handling within Android's core libraries. An example would be an app that needs to process text in different languages, relying on these functions to correctly identify letters, numbers, or perform case conversions according to the locale.

4. **Implementation Details of libc Functions:**  This requires knowledge of how these standard C library functions are typically implemented. The core idea is often lookup tables or conditional checks based on character ranges (ASCII). For Unicode, things get more complex, often involving external data or libraries like ICU. The code itself provides clues: the `have_dl()` check suggests that for Unicode characters, some functionality might be dynamically loaded (likely ICU). This is a crucial observation.

5. **Dynamic Linker Aspects:** The `dlfcn.h` include and the `have_dl()` function strongly indicate the use of dynamic linking. The code conditionally skips some Unicode tests if dynamic linking isn't available. This implies that for full Unicode support, an external shared library (like ICU) is loaded.

6. **SO Layout and Linking:**  Imagine an Android app. It links against Bionic's `libc.so`. When the app calls a `wctype` function involving Unicode, and `have_dl()` is true, `libc.so` would dynamically load another SO (likely containing ICU or Bionic's own Unicode implementation if ICU isn't used directly for these specific functions). The linking process involves resolving the symbols at runtime. A sample layout would include the app's APK, `libc.so`, and the dynamically loaded Unicode support library.

7. **Logic Inference and Assumptions:** The tests themselves provide examples of input and expected output. For instance, `iswalnum(L'a')` should be true, `iswalnum(L' ')` should be false. The tests explicitly cover both ASCII and some non-ASCII characters.

8. **Common Usage Errors:**  A common mistake is forgetting about locale settings. The `_l` versions of the functions exist precisely for this. Another error could be assuming ASCII-only behavior when dealing with potentially multi-lingual text.

9. **Android Framework/NDK to Test:**  Start with an Android app (Java/Kotlin). If it uses JNI (NDK), it calls C/C++ code. This C/C++ code uses standard C library functions like those in `wctype.h`. The framework itself (e.g., handling text input, displaying text) internally relies on these low-level functions.

10. **Frida Hooking:** To debug, one could hook the relevant `isw*`, `tow*`, `wctype`, or `wctrans` functions in `libc.so`. A basic Frida script would involve attaching to the process, finding the function address, and replacing its implementation or logging its arguments and return value. Crucially, remember that the locale-aware versions (`_l`) take a `locale_t` argument, which is also useful to inspect.

11. **Structure and Language:**  Organize the answer logically, addressing each part of the user's request. Use clear and concise Chinese. Use bullet points or numbered lists where appropriate. Provide specific code examples where possible.

12. **Review and Refine:**  Read through the answer to ensure accuracy and completeness. Double-check the explanations, especially regarding dynamic linking and the role of ICU (or similar). Make sure the Frida example is functional and demonstrates the core concept.

This step-by-step approach, combining code analysis, understanding of Android internals, and knowledge of standard C library functions and dynamic linking, leads to the comprehensive answer provided. The key was to dissect the request, address each point systematically, and leverage the information present in the test code itself.
这个文件 `bionic/tests/wctype_test.cpp` 是 Android Bionic 库中用于测试宽字符分类和转换相关函数（定义在 `<wctype.h>` 头文件中）的单元测试文件。  Bionic 是 Android 系统的 C 库，它提供了与标准 C 库类似的接口，并针对嵌入式环境进行了优化。

**它的功能：**

这个测试文件的主要功能是验证 `<wctype.h>` 中声明的宽字符处理函数的正确性。 具体来说，它测试了以下功能：

1. **字符分类函数 (Character Classification):**
   - `iswalnum()`: 检查一个宽字符是否是字母或数字。
   - `iswalpha()`: 检查一个宽字符是否是字母。
   - `iswblank()`: 检查一个宽字符是否是空白字符（空格或制表符）。
   - `iswcntrl()`: 检查一个宽字符是否是控制字符。
   - `iswdigit()`: 检查一个宽字符是否是数字。
   - `iswgraph()`: 检查一个宽字符是否是图形字符（除空格外的可打印字符）。
   - `iswlower()`: 检查一个宽字符是否是小写字母。
   - `iswprint()`: 检查一个宽字符是否是可打印字符。
   - `iswpunct()`: 检查一个宽字符是否是标点符号。
   - `iswspace()`: 检查一个宽字符是否是空白字符。
   - `iswupper()`: 检查一个宽字符是否是大写字母。
   - `iswxdigit()`: 检查一个宽字符是否是十六进制数字。
   - `iswctype()`: 使用 `wctype()` 返回的分类描述符来检查宽字符的类型。

2. **字符大小写转换函数 (Case Conversion):**
   - `towlower()`: 将宽字符转换为小写。
   - `towupper()`: 将宽字符转换为大写。
   - `towctrans()`: 使用 `wctrans()` 返回的转换描述符来转换宽字符。

3. **字符分类和转换描述符函数:**
   - `wctype()`: 获取指定名称的字符分类的描述符。
   - `wctrans()`: 获取指定名称的字符转换的描述符。

4. **本地化版本 (Locale-aware versions):**
   对于上述大部分函数，都提供了带 `_l` 后缀的版本（例如 `iswalnum_l`），这些版本允许指定一个 `locale_t` 对象，以便根据特定的区域设置进行字符处理。

**与 Android 功能的关系及举例说明：**

这些函数是 Android 系统处理文本的基础。 它们在各种场景下被使用，例如：

* **输入法 (Input Method Editors, IME):**  当用户输入文本时，系统需要判断输入的字符类型（字母、数字、标点符号等），并可能需要进行大小写转换。 例如，输入法可能使用 `iswalpha()` 来判断一个字符是否是字母，以便进行联想输入。
* **文本渲染 (Text Rendering):**  在显示文本时，系统可能需要根据字符的类型来应用不同的样式或进行分词处理。例如，`iswspace()` 可以用来识别单词之间的分隔符。
* **国际化 (Internationalization, i18n) 和本地化 (Localization, l10n):**  Android 支持多种语言和地区。  宽字符处理函数能够正确处理不同语言中的字符，例如重音字符、特殊符号等。带 `_l` 后缀的函数允许根据用户的语言设置进行正确的字符分类和转换。 例如，土耳其语中的 'i' 和 'İ' 的大小写转换与英语不同，使用本地化版本的函数可以确保转换的正确性。
* **正则表达式 (Regular Expressions):**  Android 的正则表达式库可能使用这些函数来匹配特定类型的字符。
* **文件系统和路径处理:**  在处理文件名或路径时，可能需要判断字符的合法性或进行大小写转换。

**libc 函数的实现原理：**

这些函数的具体实现细节在 Bionic 库的源代码中。 通常，它们的实现会涉及到以下几个方面：

1. **ASCII 字符集的直接判断:** 对于 ASCII 范围内的字符 (0-127)，可以直接通过简单的数值比较或位运算来判断其类型。 例如，大写字母的 ASCII 码范围是 65-90。
2. **扩展 ASCII 和 Unicode 字符集的处理:** 对于超出 ASCII 范围的字符，处理会更复杂。  Bionic 通常会依赖于字符属性表或者算法来进行判断。
3. **本地化支持:** 对于带 `_l` 后缀的函数，Bionic 会使用 `locale_t` 参数中指定的区域设置信息。 这通常涉及到查询与该区域设置相关的字符分类和转换规则的数据结构。
4. **动态加载 (Dynamic Linking):**  为了支持完整的 Unicode 功能，Bionic 可能会动态加载包含更全面的字符属性信息的库，例如 ICU (International Components for Unicode)。  你可以在代码中看到 `have_dl()` 的检查，这表明在某些情况下，对于 Unicode 字符的处理可能依赖于动态加载的库。

**示例说明 `iswalnum()` 的可能实现方式 (简化版):**

```c
int iswalnum(wint_t wc) {
  // 首先检查是否是 ASCII 字母或数字
  if ((wc >= '0' && wc <= '9') || (wc >= 'a' && wc <= 'z') || (wc >= 'A' && wc <= 'Z')) {
    return 1;
  }
  // 对于非 ASCII 字符，可能需要查表或者使用更复杂的算法
  // 例如，如果启用了 ICU，则调用 ICU 提供的函数
  // 否则，可能有一些预定义的 Unicode 属性范围进行判断
  // ... 具体实现会比较复杂 ...
  return 0;
}
```

**涉及 dynamic linker 的功能：**

在提供的代码中，`#include <dlfcn.h>` 和 `have_dl()` 函数的使用表明了对动态链接的支持。

* **`dlfcn.h`:**  这个头文件定义了用于动态加载和管理共享库的函数，如 `dlopen()`, `dlsym()`, `dlclose()`, `dlerror()`。
* **`have_dl()`:**  这个函数 (在 `utils.h` 中定义，但代码未提供) 很可能用于检查当前系统是否支持动态链接。

当 `have_dl()` 返回真时，表示系统支持动态链接，Bionic 可能会利用动态链接来加载包含更全面的 Unicode 支持的共享库 (很可能是 ICU)。 这允许 Bionic 在不增加基本 libc 大小的情况下，提供强大的国际化功能。

**so 布局样本和链接处理过程：**

假设 Android 系统中存在以下 SO 文件：

* `/system/lib64/libc.so`: Bionic 的 C 库。
* `/system/lib64/libicuuc.so`: ICU 的字符处理库。

**链接处理过程：**

1. **应用程序启动:** 当一个 Android 应用程序启动时，`linker64` (或 `linker`) 负责加载应用程序所需的共享库。
2. **静态链接:** 应用程序的可执行文件会静态链接到 `libc.so`。  当应用程序调用 `iswalnum()` 等函数时，最初会调用 `libc.so` 中提供的版本。
3. **动态加载 (可选):** 如果 `iswalnum()` 检测到需要更强大的 Unicode 支持 (例如，处理非 BMP 平面的字符)，并且 `have_dl()` 返回真，那么 `libc.so` 可能会在运行时调用 `dlopen("libicuuc.so", RTLD_LAZY)` 来动态加载 `libicuuc.so`。
4. **符号查找:** 加载 `libicuuc.so` 后，`libc.so` 可能会使用 `dlsym()` 来查找 `libicuuc.so` 中提供的 Unicode 字符处理函数的地址。
5. **调用:**  找到函数地址后，`libc.so` 会将调用转发到 `libicuuc.so` 中的函数。

**Frida Hook 示例调试步骤 (假设 `iswalnum` 可能动态调用 ICU)：**

```python
import frida
import sys

package_name = "你的应用包名" # 替换为你的应用包名

session = frida.attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "iswalnum"), {
  onEnter: function(args) {
    console.log("iswalnum called with:", ptr(args[0]));
    var charCode = args[0].toInt();
    console.log("Character code:", charCode);
  },
  onLeave: function(retval) {
    console.log("iswalnum returned:", retval);
  }
});

// 假设 iswalnum 内部可能会调用 ICU 的 u_isalnum 函数
var icuuc_module = Process.getModuleByName("libicuuc.so");
if (icuuc_module) {
  var u_isalnum_addr = icuuc_module.findExportByName("u_isalnum");
  if (u_isalnum_addr) {
    Interceptor.attach(u_isalnum_addr, {
      onEnter: function(args) {
        console.log("ICU u_isalnum called with:", ptr(args[0]));
        var charCode = args[0].toInt();
        console.log("ICU Character code:", charCode);
      },
      onLeave: function(retval) {
        console.log("ICU u_isalnum returned:", retval);
      }
    });
    console.log("Hooked ICU u_isalnum");
  } else {
    console.log("ICU u_isalnum not found");
  }
} else {
  console.log("libicuuc.so not loaded");
}
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**假设输入与输出 (针对 `iswalnum`)：**

* **假设输入:** 宽字符 `'A'` (ASCII 码 65)
* **预期输出:** `iswalnum('A')` 返回真 (非零值)。  Frida Hook 会打印 `iswalnum called with: 0x...41`, `Character code: 65`, `iswalnum returned: 0x...1`.

* **假设输入:** 宽字符 `' '` (空格，ASCII 码 32)
* **预期输出:** `iswalnum(' ')` 返回假 (0)。 Frida Hook 会打印 `iswalnum called with: 0x...20`, `Character code: 32`, `iswalnum returned: 0x...0`.

* **假设输入:** 宽字符 `'Ç'` (带有 Cedilla 的大写 C，Unicode 码 U+00C7)
* **预期输出:** 如果使用了 ICU，`iswalnum('Ç')` 应该返回真。 Frida Hook 可能会打印 `iswalnum called with: 0x...c7`, `Character code: 199`, 以及如果调用了 ICU 的 `u_isalnum`，也会有相应的 ICU Hook 输出。

**用户或编程常见的使用错误：**

1. **假定单字节字符:** 许多早期的 C 代码可能假设字符都是单字节的，没有正确处理宽字符。这会导致在处理包含非 ASCII 字符的文本时出现错误。
2. **混淆字符和宽字符:**  直接将 `char` 类型的值传递给接受 `wint_t` 或 `wchar_t` 的函数，或者反之。
3. **忽略本地化:**  没有使用带 `_l` 后缀的函数，或者使用了错误的 `locale_t` 对象，导致程序在不同的地区设置下行为不一致。
   ```c
   #include <stdio.h>
   #include <wctype.h>
   #include <locale.h>

   int main() {
       wchar_t ch = L'é'; // 带重音符号的小写 e

       // 错误：没有考虑本地化
       if (iswupper(ch)) {
           printf("Character is uppercase\n");
       } else {
           printf("Character is not uppercase\n"); // 在某些 locale 下可能错误
       }

       // 正确：使用本地化版本
       locale_t loc = newlocale(LC_ALL, "fr_FR.UTF-8", NULL);
       if (iswupper_l(ch, loc)) {
           printf("Character is uppercase in fr_FR\n");
       } else {
           printf("Character is not uppercase in fr_FR\n"); // 正确输出
       }
       freelocale(loc);
       return 0;
   }
   ```
4. **内存管理错误:**  在使用宽字符串时，没有正确分配足够的内存来存储宽字符，因为一个宽字符可能占用多个字节。
5. **不正确的类型转换:** 在 `char` 和 `wchar_t` 之间进行不正确的类型转换可能导致数据丢失或错误解释。

**Android Framework 或 NDK 如何到达这里：**

1. **Java/Kotlin 代码调用 Framework API:**  Android 应用程序通常使用 Java 或 Kotlin 编写。 当应用程序需要处理文本时，它会调用 Android Framework 提供的 API，例如 `String` 类的方法，或者 `TextView` 等 UI 组件。
2. **Framework 层调用 Native 代码:**  Android Framework 的某些部分是用 C++ 编写的，并通过 JNI (Java Native Interface) 与 Java/Kotlin 代码交互。  例如，文本渲染、国际化支持等功能的实现可能位于 Native 层。
3. **Native 代码调用 Bionic libc:** Framework 的 Native 代码会调用 Bionic 库提供的标准 C 函数，包括 `<wctype.h>` 中定义的宽字符处理函数。
4. **NDK 开发:**  使用 NDK 进行开发的应用程序可以直接调用 Bionic 库的函数。 例如，一个使用 C++ 编写的游戏引擎，如果需要处理用户输入的文本，可能会直接调用 `iswalnum()` 等函数。

**逐步到达 `wctype_test.cpp` 中测试的函数的流程：**

假设一个 Android 应用需要判断用户输入的字符是否是字母：

1. **用户在 EditText 中输入字符 'A'。**
2. **EditText 的监听器捕获到输入事件。**
3. **Framework 的文本处理代码 (Java/Kotlin) 获取输入的字符。**
4. **如果需要进行更底层的字符处理 (例如，在 Native 代码中进行复杂的文本分析或渲染)，Framework 可能会将字符传递给 Native 代码。**
5. **Native 代码 (C++) 可能会调用 `iswalpha()` 函数来判断字符是否是字母。**  这个 `iswalpha()` 函数的实现就位于 Bionic 的 `libc.so` 中，而 `wctype_test.cpp` 正是为了测试这个实现的正确性而存在的。

总而言之，`bionic/tests/wctype_test.cpp` 是 Android 系统中一个至关重要的测试文件，它确保了 Bionic 库提供的宽字符处理功能的正确性，这些功能是 Android 系统处理多语言文本的基础。 通过各种单元测试用例，它验证了字符分类和转换函数的行为是否符合预期，从而保障了 Android 系统的稳定性和国际化支持。

Prompt: 
```
这是目录为bionic/tests/wctype_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <wctype.h>

#include <dlfcn.h>

#include <gtest/gtest.h>

#include "utils.h"

class UtfLocale {
 public:
  UtfLocale() : l(newlocale(LC_ALL, "C.UTF-8", nullptr)) {}
  ~UtfLocale() { freelocale(l); }
  locale_t l;
};

static void TestIsWideFn(int fn(wint_t),
                         int fn_l(wint_t, locale_t),
                         const wchar_t* trues,
                         const wchar_t* falses) {
  UtfLocale l;
  for (const wchar_t* p = trues; *p; ++p) {
    const wchar_t val_ch = *p;
    const int val_int = static_cast<int>(val_ch);
    if (!have_dl() && val_ch > 0x7f) {
      GTEST_LOG_(INFO) << "skipping unicode test " << val_int;
      continue;
    }
    EXPECT_TRUE(fn(val_ch)) << val_int;
    EXPECT_TRUE(fn_l(val_ch, l.l)) << val_int;
  }
  for (const wchar_t* p = falses; *p; ++p) {
    const wchar_t val_ch = *p;
    const int val_int = static_cast<int>(val_ch);
    if (!have_dl() && val_ch > 0x7f) {
      GTEST_LOG_(INFO) << "skipping unicode test " << val_int;
      continue;
    }
    EXPECT_FALSE(fn(val_ch)) << val_int;
    EXPECT_FALSE(fn_l(val_ch, l.l)) << val_int;
  }
}

TEST(wctype, iswalnum) {
  TestIsWideFn(iswalnum, iswalnum_l, L"1aAÇçΔδ", L"! \b");
}

TEST(wctype, iswalpha) {
  TestIsWideFn(iswalpha, iswalpha_l, L"aAÇçΔδ", L"1! \b");
}

TEST(wctype, iswblank) {
  TestIsWideFn(iswblank, iswblank_l, L" \t", L"1aA!\bÇçΔδ");
}

TEST(wctype, iswcntrl) {
  TestIsWideFn(iswcntrl, iswcntrl_l, L"\b\u009f", L"1aA! ÇçΔδ");
}

TEST(wctype, iswdigit) {
  TestIsWideFn(iswdigit, iswdigit_l, L"1", L"aA! \bÇçΔδ");
}

TEST(wctype, iswgraph) {
  TestIsWideFn(iswgraph, iswgraph_l, L"1aA!ÇçΔδ", L" \b");
}

TEST(wctype, iswlower) {
  TestIsWideFn(iswlower, iswlower_l, L"açδ", L"1A! \bÇΔ");
}

TEST(wctype, iswprint) {
  TestIsWideFn(iswprint, iswprint_l, L"1aA! ÇçΔδ", L"\b");
}

TEST(wctype, iswpunct) {
  TestIsWideFn(iswpunct, iswpunct_l, L"!", L"1aA \bÇçΔδ");
}

TEST(wctype, iswspace) {
  TestIsWideFn(iswspace, iswspace_l, L" \f\t", L"1aA!\bÇçΔδ");
}

TEST(wctype, iswupper) {
  TestIsWideFn(iswupper, iswupper_l, L"AÇΔ", L"1a! \bçδ");
}

TEST(wctype, iswxdigit) {
  TestIsWideFn(iswxdigit, iswxdigit_l, L"01aA", L"xg! \b");
}

TEST(wctype, towlower) {
  EXPECT_EQ(WEOF, towlower(WEOF));
  EXPECT_EQ(wint_t('!'), towlower(L'!'));
  EXPECT_EQ(wint_t('a'), towlower(L'a'));
  EXPECT_EQ(wint_t('a'), towlower(L'A'));
  EXPECT_EQ(wint_t('z'), towlower(L'z'));
  EXPECT_EQ(wint_t('z'), towlower(L'Z'));
  if (have_dl()) {
    EXPECT_EQ(wint_t(L'ç'), towlower(L'ç'));
    EXPECT_EQ(wint_t(L'ç'), towlower(L'Ç'));
    EXPECT_EQ(wint_t(L'δ'), towlower(L'δ'));
    EXPECT_EQ(wint_t(L'δ'), towlower(L'Δ'));
  } else {
    GTEST_SKIP() << "icu not available";
  }
}

TEST(wctype, towlower_l) {
  UtfLocale l;
  EXPECT_EQ(WEOF, towlower(WEOF));
  EXPECT_EQ(wint_t('!'), towlower_l(L'!', l.l));
  EXPECT_EQ(wint_t('a'), towlower_l(L'a', l.l));
  EXPECT_EQ(wint_t('a'), towlower_l(L'A', l.l));
  EXPECT_EQ(wint_t('z'), towlower_l(L'z', l.l));
  EXPECT_EQ(wint_t('z'), towlower_l(L'Z', l.l));
  if (have_dl()) {
    EXPECT_EQ(wint_t(L'ç'), towlower_l(L'ç', l.l));
    EXPECT_EQ(wint_t(L'ç'), towlower_l(L'Ç', l.l));
    EXPECT_EQ(wint_t(L'δ'), towlower_l(L'δ', l.l));
    EXPECT_EQ(wint_t(L'δ'), towlower_l(L'Δ', l.l));
  } else {
    GTEST_SKIP() << "icu not available";
  }
}

TEST(wctype, towupper) {
  EXPECT_EQ(WEOF, towupper(WEOF));
  EXPECT_EQ(wint_t('!'), towupper(L'!'));
  EXPECT_EQ(wint_t('A'), towupper(L'a'));
  EXPECT_EQ(wint_t('A'), towupper(L'A'));
  EXPECT_EQ(wint_t('Z'), towupper(L'z'));
  EXPECT_EQ(wint_t('Z'), towupper(L'Z'));
  if (have_dl()) {
    EXPECT_EQ(wint_t(L'Ç'), towupper(L'ç'));
    EXPECT_EQ(wint_t(L'Ç'), towupper(L'Ç'));
    EXPECT_EQ(wint_t(L'Δ'), towupper(L'δ'));
    EXPECT_EQ(wint_t(L'Δ'), towupper(L'Δ'));
  } else {
    GTEST_SKIP() << "icu not available";
  }
}

TEST(wctype, towupper_l) {
  UtfLocale l;
  EXPECT_EQ(WEOF, towupper_l(WEOF, l.l));
  EXPECT_EQ(wint_t('!'), towupper_l(L'!', l.l));
  EXPECT_EQ(wint_t('A'), towupper_l(L'a', l.l));
  EXPECT_EQ(wint_t('A'), towupper_l(L'A', l.l));
  EXPECT_EQ(wint_t('Z'), towupper_l(L'z', l.l));
  EXPECT_EQ(wint_t('Z'), towupper_l(L'Z', l.l));
  if (have_dl()) {
    EXPECT_EQ(wint_t(L'Ç'), towupper_l(L'ç', l.l));
    EXPECT_EQ(wint_t(L'Ç'), towupper_l(L'Ç', l.l));
    EXPECT_EQ(wint_t(L'Δ'), towupper_l(L'δ', l.l));
    EXPECT_EQ(wint_t(L'Δ'), towupper_l(L'Δ', l.l));
  } else {
    GTEST_SKIP() << "icu not available";
  }
}

TEST(wctype, wctype) {
  EXPECT_TRUE(wctype("alnum") != 0);
  EXPECT_TRUE(wctype("alpha") != 0);
  EXPECT_TRUE(wctype("blank") != 0);
  EXPECT_TRUE(wctype("cntrl") != 0);
  EXPECT_TRUE(wctype("digit") != 0);
  EXPECT_TRUE(wctype("graph") != 0);
  EXPECT_TRUE(wctype("lower") != 0);
  EXPECT_TRUE(wctype("print") != 0);
  EXPECT_TRUE(wctype("punct") != 0);
  EXPECT_TRUE(wctype("space") != 0);
  EXPECT_TRUE(wctype("upper") != 0);
  EXPECT_TRUE(wctype("xdigit") != 0);

  EXPECT_TRUE(wctype("monkeys") == 0);
}

TEST(wctype, wctype_l) {
  UtfLocale l;
  EXPECT_TRUE(wctype_l("alnum", l.l) != 0);
  EXPECT_TRUE(wctype_l("alpha", l.l) != 0);
  EXPECT_TRUE(wctype_l("blank", l.l) != 0);
  EXPECT_TRUE(wctype_l("cntrl", l.l) != 0);
  EXPECT_TRUE(wctype_l("digit", l.l) != 0);
  EXPECT_TRUE(wctype_l("graph", l.l) != 0);
  EXPECT_TRUE(wctype_l("lower", l.l) != 0);
  EXPECT_TRUE(wctype_l("print", l.l) != 0);
  EXPECT_TRUE(wctype_l("punct", l.l) != 0);
  EXPECT_TRUE(wctype_l("space", l.l) != 0);
  EXPECT_TRUE(wctype_l("upper", l.l) != 0);
  EXPECT_TRUE(wctype_l("xdigit", l.l) != 0);

  EXPECT_TRUE(wctype_l("monkeys", l.l) == 0);
}

TEST(wctype, iswctype) {
  EXPECT_TRUE(iswctype(L'a', wctype("alnum")));
  EXPECT_TRUE(iswctype(L'1', wctype("alnum")));
  EXPECT_FALSE(iswctype(L' ', wctype("alnum")));

  EXPECT_EQ(0, iswctype(WEOF, wctype("alnum")));
}

TEST(wctype, iswctype_l) {
  UtfLocale l;
  EXPECT_TRUE(iswctype_l(L'a', wctype_l("alnum", l.l), l.l));
  EXPECT_TRUE(iswctype_l(L'1', wctype_l("alnum", l.l), l.l));
  EXPECT_FALSE(iswctype_l(L' ', wctype_l("alnum", l.l), l.l));

  EXPECT_EQ(0, iswctype_l(WEOF, wctype_l("alnum", l.l), l.l));
}

TEST(wctype, wctrans) {
  EXPECT_TRUE(wctrans("tolower") != nullptr);
  EXPECT_TRUE(wctrans("toupper") != nullptr);

  errno = 0;
  EXPECT_TRUE(wctrans("monkeys") == nullptr);
  #if defined(__BIONIC__)
  // Android/FreeBSD/iOS set errno, but musl/glibc don't.
  EXPECT_ERRNO(EINVAL);
  #endif
}

TEST(wctype, wctrans_l) {
  UtfLocale l;
  EXPECT_TRUE(wctrans_l("tolower", l.l) != nullptr);
  EXPECT_TRUE(wctrans_l("toupper", l.l) != nullptr);

  errno = 0;
  EXPECT_TRUE(wctrans_l("monkeys", l.l) == nullptr);
  #if defined(__BIONIC__)
  // Android/FreeBSD/iOS set errno, but musl/glibc don't.
  EXPECT_ERRNO(EINVAL);
  #endif
}

TEST(wctype, towctrans) {
  wctrans_t lower = wctrans("tolower");
  EXPECT_EQ(wint_t('a'), towctrans(L'A', lower));
  EXPECT_EQ(WEOF, towctrans(WEOF, lower));

  wctrans_t upper = wctrans("toupper");
  EXPECT_EQ(wint_t('A'), towctrans(L'a', upper));
  EXPECT_EQ(WEOF, towctrans(WEOF, upper));

  wctrans_t invalid = wctrans("monkeys");
  errno = 0;
  EXPECT_EQ(wint_t('a'), towctrans(L'a', invalid));
  #if defined(__BIONIC__)
  // Android/FreeBSD/iOS set errno, but musl/glibc don't.
  EXPECT_ERRNO(EINVAL);
  #endif
}

TEST(wctype, towctrans_l) {
  UtfLocale l;
  wctrans_t lower = wctrans_l("tolower", l.l);
  EXPECT_EQ(wint_t('a'), towctrans_l(L'A', lower, l.l));
  EXPECT_EQ(WEOF, towctrans_l(WEOF, lower, l.l));

  wctrans_t upper = wctrans_l("toupper", l.l);
  EXPECT_EQ(wint_t('A'), towctrans_l(L'a', upper, l.l));
  EXPECT_EQ(WEOF, towctrans_l(WEOF, upper, l.l));

  wctrans_t invalid = wctrans_l("monkeys", l.l);
  errno = 0;
  EXPECT_EQ(wint_t('a'), towctrans_l(L'a', invalid, l.l));
  #if defined(__BIONIC__)
  // Android/FreeBSD/iOS set errno, but musl/glibc don't.
  EXPECT_ERRNO(EINVAL);
  #endif
}

"""

```