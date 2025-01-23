Response:
The user wants me to analyze a C source code file for Frida, specifically `frida/subprojects/frida-gum/tests/gumjs/script.c`.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:**  The filename and the test structure (`TESTCASE`) strongly suggest this file contains unit tests for the JavaScript API provided by Frida-gum related to scripting. Keywords like "string," "memory," "CModule," "Interceptor," and "Stalker" are hints.

2. **Categorize Test Cases:** Group the test cases by the functionality they are testing. This will help in summarizing the file's purpose. Look for patterns in the test case names and the code within them.

3. **Explain Functionality with Examples:** For each category of functionality, provide a concise description and illustrate it with examples from the code.

4. **Relate to Reverse Engineering:** Think about how each tested feature is relevant to dynamic instrumentation and reverse engineering. For instance, reading/writing memory, hooking functions, and tracing execution are key aspects.

5. **Connect to Low-Level Concepts:** Identify tests that touch upon operating system specifics (like Windows code pages), memory management, kernel concepts (through implication of system calls being hooked), and processor architecture (through Stalker's assembly manipulation).

6. **Analyze Logic and Assumptions:**  For tests involving conditional logic or specific input/output, try to infer the assumptions and expected behavior. Give examples of inputs and the expected outcomes.

7. **Spot Potential User Errors:** Think about how a user might misuse the API based on the test cases. For example, incorrect pointer usage or trying to access invalid memory.

8. **Trace User Actions:** Imagine the steps a user would take to trigger the execution of these test cases. It starts with writing a Frida script and then running it with the Frida runtime.

9. **Summarize Overall Function:**  Based on the analysis of individual test cases, provide a high-level summary of the file's role.

**Mental Walkthrough of the Provided Code Snippet:**

* **String Handling:** The snippet focuses on reading, writing, and allocating UTF-16 and ANSI strings. This immediately connects to the need to work with text data in different encodings, common in software.
* **Platform Specificity:** The `#ifdef HAVE_WINDOWS` blocks highlight the handling of ANSI strings, which is more relevant on Windows due to its legacy. The different code page tests (936 and 1252) are specific to Windows locale settings.
* **Memory Operations:**  `Memory.readUtf16String`, `Memory.writeUtf16String`, `Memory.allocUtf16String`, `Memory.readAnsiString`, `Memory.writeAnsiString`, `Memory.allocAnsiString` directly relate to manipulating memory contents, a fundamental aspect of dynamic instrumentation.
* **Error Handling:** The "invalid_read_results_in_exception" and "invalid_write_results_in_exception" tests verify that Frida gracefully handles attempts to access invalid memory, which is crucial for stability.
* **`COMPILE_AND_LOAD_SCRIPT` and `EXPECT_SEND_MESSAGE_WITH`:** These macros are the testing infrastructure. They show how JavaScript code snippets are executed within the Frida environment and how the results are checked.

By going through these steps and focusing on the meaning of the code, I can generate a comprehensive answer.
这是 `frida/subprojects/frida-gum/tests/gumjs/script.c` 文件的第 9 部分，该文件是 Frida 动态 instrumentation 工具的源代码文件，专门用于测试 Frida 的 GumJS 引擎中 JavaScript 脚本的功能。 从提供的代码片段来看，这部分主要集中在测试 **字符串处理** 和 **C模块 (CModule)** 的相关功能。

以下是代码片段功能的详细列举和说明：

**1. 字符串处理功能测试:**

* **`utf16_string_can_be_read`**: 测试从内存中读取 UTF-16 编码的字符串。
    * **功能:**  分配一块内存，写入一个 UTF-16 字符串，然后使用 Frida 的 JavaScript API (`ptr('0').readUtf16String()`) 从该内存地址读取字符串。
    * **与逆向的关系:** 在逆向分析中，经常需要读取进程内存中的字符串，例如读取 UI 元素的文本、网络协议中的数据、配置文件等。此功能模拟了读取内存中 UTF-16 字符串的场景。
    * **二进制底层知识:**  涉及到了内存地址的概念 (ptr('0')) 和 UTF-16 编码的理解。 UTF-16 是一种以 16 位为单位编码 Unicode 字符的方式。
    * **假设输入与输出:** 假设内存地址 0 处存储了 UTF-16 编码的 "Hello"，则输出应为 `"Hello"`。
    * **用户使用错误:** 用户可能提供错误的内存地址，导致读取失败或读取到错误的数据。 例如，如果地址指向非 UTF-16 编码的数据，`readUtf16String()` 可能会产生乱码或崩溃。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `ptr(address).readUtf16String()` 尝试读取指定内存地址的 UTF-16 字符串。

* **`utf16_string_can_be_written`**: 测试向内存中写入 UTF-16 编码的字符串。
    * **功能:** 分配一块内存，其中包含一个 UTF-16 字符串，然后使用 Frida 的 JavaScript API (`GUM_PTR_CONST ".writeUtf16String('Bye');"`) 将新的 UTF-16 字符串写入该内存地址。
    * **与逆向的关系:** 在逆向分析中，可能需要修改内存中的字符串，例如修改游戏中的文本显示、修改网络请求的数据等。
    * **二进制底层知识:** 涉及内存写入操作和 UTF-16 编码。 写入时需要确保写入的长度不超过分配的内存大小，避免缓冲区溢出。
    * **假设输入与输出:** 假设 `str` 指向的内存包含 "Hello"，执行脚本后，该内存的前几个字节会被 "Bye\0" 的 UTF-16 编码覆盖。
    * **用户使用错误:** 用户可能写入过长的字符串导致缓冲区溢出，或者写入非法的 UTF-16 数据。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `ptr(address).writeUtf16String(string)` 尝试将指定的 UTF-16 字符串写入到内存地址。

* **`utf16_string_can_be_allocated`**: 测试在内存中分配并写入 UTF-16 编码的字符串。
    * **功能:** 使用 Frida 的 JavaScript API (`Memory.allocUtf16String('Bjørheimsbygd')`) 分配内存并写入指定的 UTF-16 字符串，然后读取并发送该字符串。
    * **与逆向的关系:** 有时需要在目标进程中动态分配内存来存储数据，例如存储要注入的代码或数据。
    * **二进制底层知识:** 涉及内存分配和 UTF-16 编码。
    * **假设输入与输出:**  脚本执行后，输出应为 `"Bjørheimsbygd"`。
    * **用户使用错误:**  理论上用户不会直接操作这里的 C 代码，但在 JavaScript 层，如果分配的内存没有被及时释放，可能会导致内存泄漏。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `Memory.allocUtf16String(string)` 来分配并初始化 UTF-16 字符串。

* **`ansi_string_can_be_read_in_code_page_936` 和 `ansi_string_can_be_read_in_code_page_1252`**: 测试在特定 ANSI 代码页下读取字符串。
    * **功能:** 在 Windows 系统上，根据当前线程的 ANSI 代码页（936 代表中文简体，1252 代表西欧语言），从内存中读取 ANSI 编码的字符串。
    * **与逆向的关系:** 应用程序可能使用 ANSI 编码来存储字符串，特别是在 Windows 平台上。 理解代码页对于正确解析这些字符串至关重要。
    * **二进制底层知识:**  涉及内存地址、ANSI 编码和 Windows 的代码页概念。 ANSI 编码是与特定代码页相关的单字节或多字节字符编码。
    * **假设输入与输出:** 例如，在代码页 936 下，如果内存中存储了 "test测试." 的 ANSI 编码，则 `Memory.readAnsiString()` 应该返回 `"test测试."`。
    * **用户使用错误:** 在非 Windows 系统上运行这些测试会跳过。用户可能错误地假设 ANSI 字符串总是以 UTF-8 或其他编码存储。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `Memory.readAnsiString(address, length)` 尝试读取指定内存地址和长度的 ANSI 字符串。

* **`ansi_string_can_be_written_in_code_page_936` 和 `ansi_string_can_be_written_in_code_page_1252`**: 测试在特定 ANSI 代码页下写入字符串。
    * **功能:** 在 Windows 系统上，根据当前线程的 ANSI 代码页，将指定的字符串写入到内存中。
    * **与逆向的关系:**  类似于修改 UTF-16 字符串，但针对的是 ANSI 编码。
    * **二进制底层知识:** 涉及内存写入和 ANSI 编码。
    * **假设输入与输出:**  例如，在代码页 936 下，将 "test测试." 写入内存后，该内存会包含对应的 ANSI 编码。
    * **用户使用错误:** 写入过长的字符串可能导致缓冲区溢出，或者写入的字符无法在当前代码页中表示，导致数据丢失或损坏。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `ptr(address).writeAnsiString(string)` 尝试将 ANSI 字符串写入到内存地址。

* **`ansi_string_can_be_allocated_in_code_page_936` 和 `ansi_string_can_be_allocated_in_code_page_1252`**: 测试在特定 ANSI 代码页下分配并写入字符串。
    * **功能:** 在 Windows 系统上，根据当前线程的 ANSI 代码页，分配内存并写入指定的 ANSI 字符串。
    * **与逆向的关系:**  动态分配存储 ANSI 编码字符串的内存。
    * **二进制底层知识:** 涉及内存分配和 ANSI 编码。
    * **假设输入与输出:**  例如，在代码页 936 下，分配并写入 "test测试." 后，读取该内存应得到 `"test测试."`。
    * **用户使用错误:**  与 UTF-16 的分配类似，内存泄漏是潜在问题。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `Memory.allocAnsiString(string)` 来分配并初始化 ANSI 字符串。

* **`invalid_read_results_in_exception`**: 测试读取无效内存地址时是否会抛出异常。
    * **功能:**  尝试读取一个很可能无效的内存地址 (`ptr('1328')`) 的各种数据类型。
    * **与逆向的关系:**  在逆向分析中，尝试访问无效内存是很常见的错误，需要确保工具能够安全地处理这些情况。
    * **操作系统/内核知识:**  涉及到操作系统对内存访问权限的管理。尝试访问未分配或没有权限访问的内存会触发异常。
    * **假设输入与输出:**  尝试读取 `ptr('1328')` 的任何数据类型都应该导致一个访问违规的错误消息。
    * **用户使用错误:**  用户在 Frida 脚本中使用了错误的内存地址。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `ptr(invalid_address).readType()` 尝试读取数据。

* **`invalid_write_results_in_exception`**: 测试写入无效内存地址时是否会抛出异常。
    * **功能:** 尝试向一个很可能无效的内存地址 (`ptr('1328')`) 写入各种数据类型。
    * **与逆向的关系:**  类似于无效读取，确保工具能够安全地处理无效的内存写入尝试。
    * **操作系统/内核知识:**  操作系统内存访问权限管理。
    * **假设输入与输出:**  尝试写入 `ptr('1328')` 的任何数据类型都应该导致一个访问违规的错误消息。
    * **用户使用错误:** 用户在 Frida 脚本中使用了错误的内存地址。
    * **用户操作到达这里:** 用户在 Frida 脚本中使用 `ptr(invalid_address).writeType(value)` 尝试写入数据。

* **`invalid_read_write_execute_results_in_exception`**: 测试对无读/写/执行权限的内存进行操作是否会抛出异常。
    * **功能:** 尝试读取、写入一个很可能无效的内存地址，以及尝试执行一块新分配但未设置执行权限的内存。
    * **与逆向的关系:**  理解内存保护机制对于安全地进行动态分析至关重要。
    * **操作系统/内核知识:**  
### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readUtf16String());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str);
}

TESTCASE (utf16_string_can_be_written)
{
  gunichar2 * str = g_utf8_to_utf16 ("Hello", -1, NULL, NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUtf16String('Bye');", str);
  g_assert_cmphex (str[0], ==, 'B');
  g_assert_cmphex (str[1], ==, 'y');
  g_assert_cmphex (str[2], ==, 'e');
  g_assert_cmphex (str[3], ==, '\0');
  g_assert_cmphex (str[4], ==, 'o');
  g_assert_cmphex (str[5], ==, '\0');

  g_free (str);
}

TESTCASE (utf16_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocUtf16String('Bjørheimsbygd').readUtf16String()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#ifdef HAVE_WINDOWS

TESTCASE (ansi_string_can_be_read_in_code_page_936)
{
  CPINFOEX cpi;
  const gchar * str_utf8;
  WCHAR * str_utf16;
  gchar str[13 + 1];

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 936)
  {
    g_print ("<skipping, only available on systems with ANSI code page 936> ");
    return;
  }

  str_utf8 = "test测试.";
  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1, str, sizeof (str),
      NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 5));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test?\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 6));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", int64(-1)));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(ptr(\"0\")));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str_utf16);

  str_utf8 = "Bjørheimsbygd";
  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1, str, sizeof (str),
      NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bj?rheimsbygd\"");

  g_free (str_utf16);
}

TESTCASE (ansi_string_can_be_read_in_code_page_1252)
{
  CPINFOEX cpi;
  const gchar * str_utf8;
  WCHAR * str_utf16;
  gchar str[13 + 1];

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 1252)
  {
    g_print ("<skipping, only available on systems with ANSI code page 1252> ");
    return;
  }

  str_utf8 = "Bjørheimsbygd";
  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1, str, sizeof (str),
      NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(-1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(int64(-1)));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readAnsiString());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str_utf16);
}

TESTCASE (ansi_string_can_be_written_in_code_page_936)
{
  CPINFOEX cpi;
  gchar str_ansi[13 + 1];
  gunichar2 str_utf16[13 + 1];
  gchar * str_utf8;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 936)
  {
    g_print ("<skipping, only available on systems with ANSI code page 936> ");
    return;
  }

  strcpy (str_ansi, "truncate-plz");
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeAnsiString('test测试.');",
      str_ansi);
  MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, -1,
      str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, ==, "test测试.");
  g_free (str_utf8);
  g_assert_cmphex (str_ansi[9], ==, '\0');
  g_assert_cmphex (str_ansi[10], ==, 'l');
  g_assert_cmphex (str_ansi[11], ==, 'z');
  g_assert_cmphex (str_ansi[12], ==, '\0');

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeAnsiString('Bjørheimsbygd');",
      str_ansi);
  MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, -1,
      str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, ==, "Bj?rheimsbygd");
  g_free (str_utf8);
}

TESTCASE (ansi_string_can_be_written_in_code_page_1252)
{
  CPINFOEX cpi;
  gchar str_ansi[16 + 1];
  gunichar2 str_utf16[16 + 1];
  gchar * str_utf8;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 1252)
  {
    g_print ("<skipping, only available on systems with ANSI code page 1252> ");
    return;
  }

  strcpy (str_ansi, "Kjempeforhaustar");
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeAnsiString('Bjørheimsbygd');",
      str_ansi);
  MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, -1,
      str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, ==, "Bjørheimsbygd");
  g_free (str_utf8);
  g_assert_cmphex (str_ansi[13], ==, '\0');
  g_assert_cmphex (str_ansi[14], ==, 'a');
  g_assert_cmphex (str_ansi[15], ==, 'r');
  g_assert_cmphex (str_ansi[16], ==, '\0');
}

TESTCASE (ansi_string_can_be_allocated_in_code_page_936)
{
  CPINFOEX cpi;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 936)
  {
    g_print ("<skipping, only available on systems with ANSI code page 936> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocAnsiString('test测试.').readAnsiString()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");
}

TESTCASE (ansi_string_can_be_allocated_in_code_page_1252)
{
  CPINFOEX cpi;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 1252)
  {
    g_print ("<skipping, only available on systems with ANSI code page 1252> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocAnsiString('Bjørheimsbygd').readAnsiString()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#endif

TESTCASE (invalid_read_results_in_exception)
{
  const gchar * type_name[] = {
      "Pointer",
      "S8",
      "U8",
      "S16",
      "U16",
      "S32",
      "U32",
      "Float",
      "Double",
      "S64",
      "U64",
      "Utf8String",
      "Utf16String",
#ifdef HAVE_WINDOWS
      "AnsiString"
#endif
  };
  guint i;

  if (!check_exception_handling_testable ())
    return;

  for (i = 0; i != G_N_ELEMENTS (type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("ptr('1328').read", type_name[i], "();", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);

#if GLIB_SIZEOF_VOID_P == 8
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x530");
#else
    /*
     * On 32-bit platforms, when reading 64-bit values we must read 32-bits at a
     * time. The compiler is at liberty to read either the high or low part
     * first, and hence we may not fault on the first part of the value, but
     * rather on the second. The ordering is likely dependent on endianness.
     */
    EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x53(0|4)");
#endif

    g_free (source);
  }
}

TESTCASE (invalid_write_results_in_exception)
{
  const gchar * primitive_type_name[] = {
      "S8",
      "U8",
      "S16",
      "U16",
      "S32",
      "U32",
      "Float",
      "Double",
      "S64",
      "U64"
  };
  const gchar * string_type_name[] = {
      "Utf8String",
      "Utf16String"
  };
  guint i;

  if (!check_exception_handling_testable ())
    return;

  for (i = 0; i != G_N_ELEMENTS (primitive_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("ptr('1328').write", primitive_type_name[i], "(13);",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);

#if GLIB_SIZEOF_VOID_P == 8
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x530");
#else
    /* See note in previous test. */
    EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x53(0|4)");
#endif

    g_free (source);
  }

  for (i = 0; i != G_N_ELEMENTS (string_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("ptr('1328').write", string_type_name[i], "('Hey');",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);

#if GLIB_SIZEOF_VOID_P == 8
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x530");
#else
    /* See note in previous test. */
    EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x53(0|4)");
#endif

    g_free (source);
  }
}

TESTCASE (invalid_read_write_execute_results_in_exception)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT ("ptr('1328').readU8();");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x530");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT ("ptr('1328').writeU8(42);");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x530");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT ("const data = Memory.alloc(Process.pageSize);"
      "const f = new NativeFunction(data.sign(), 'void', []);"
      "try {"
      "  f();"
      "} catch (e) {"
      "  send(e.toString().startsWith('Error: access violation accessing 0x'));"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

#ifdef HAVE_TINYCC

TESTCASE (cmodule_can_be_defined)
{
  int (* add_impl) (int a, int b);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      ""
      "int\\n"
      "add (int a,\\n"
      "     int b)\\n"
      "{\\n"
      "  return a + b;\\n"
      "}"
      "');"
      "send(m.add);");

  add_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (add_impl);
  g_assert_cmpint (add_impl (3, 4), ==, 7);
}

TESTCASE (cmodule_can_be_defined_with_toolchain)
{
  const gchar * code =
      "int\\n"
      "answer (void)\\n"
      "{\\n"
      "  return 42;\\n"
      "}";
  int (* answer_impl) (void);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('%s', null, { toolchain: 'any' });"
      "send(m.answer);",
      code);
  answer_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_cmpint (answer_impl (), ==, 42);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('%s', null, { toolchain: 'internal' });"
      "send(m.answer);",
      code);
  answer_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_cmpint (answer_impl (), ==, 42);

#ifndef HAVE_MACOS
  if (g_test_slow ())
#endif
  {
    COMPILE_AND_LOAD_SCRIPT (
        "const m = new CModule('%s', null, { toolchain: 'external' });"
        "send(m.answer);",
        code);
    answer_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
    g_assert_cmpint (answer_impl (), ==, 42);
  }

  COMPILE_AND_LOAD_SCRIPT (
      "new CModule('%s', null, { toolchain: 'nope' });",
      code);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid toolchain value");
}

TESTCASE (cmodule_can_be_created_from_prebuilt_binary)
{
#ifdef HAVE_DARWIN
  gchar * data_dir, * module_path;
  gpointer module_contents;
  gsize module_size;
  GBytes * module_bytes;
  int (* answer_impl) (void);

  data_dir = test_util_get_data_dir ();
  module_path = g_build_filename (data_dir, "prebuiltcmodule.dylib", NULL);
  g_assert_true (g_file_get_contents (module_path, (gchar **) &module_contents,
      &module_size, NULL));
  module_bytes =
      g_bytes_new_take (g_steal_pointer (&module_contents), module_size);

  COMPILE_AND_LOAD_SCRIPT (
      "let m = null;"
      "const notify = new NativeCallback(n => { send(n); }, 'void', ['int']);"
      "recv((message, data) => {"
      "  m = new CModule(data, { notify });"
      "  send(m.answer);"
      "});");
  EXPECT_NO_MESSAGES ();

  gum_script_post (fixture->script, "{}", module_bytes);
  answer_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_cmpint (answer_impl (), ==, 42);
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_NO_MESSAGES ();

  g_bytes_unref (module_bytes);
  g_free (module_path);
  g_free (data_dir);
#else
  g_test_skip ("Missing implementation or test on this OS");
#endif
}

TESTCASE (cmodule_symbols_can_be_provided)
{
  int a = 42;
  int b = 1337;
  int (* get_magic_impl) (void);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      ""
      "extern int a;\\n"
      "extern int b;\\n"
      "\\n"
      "int\\n"
      "get_magic (void)\\n"
      "{\\n"
      "  return a + b;\\n"
      "}"
      "', { a: " GUM_PTR_CONST ", b: " GUM_PTR_CONST " });"
      "send(m.get_magic);",
      &a, &b);

  get_magic_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (get_magic_impl);
  g_assert_cmpint (get_magic_impl (), ==, 1379);
}

TESTCASE (cmodule_should_report_parsing_errors)
{
  COMPILE_AND_LOAD_SCRIPT ("new CModule('void foo (int a');");
  EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
      "Error: compilation failed.+");
}

TESTCASE (cmodule_should_report_linking_errors)
{
  const gchar * expected_message =
      "(Error: linking failed: tcc: error: undefined symbol '"
#ifdef HAVE_DARWIN
      "_"
#endif
      "v'|undefined reference to `v')";

  COMPILE_AND_LOAD_SCRIPT ("new CModule('"
      "extern int v; int f (void) { return v; }');");
  EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER, expected_message);
}

TESTCASE (cmodule_should_provide_lifecycle_hooks)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      ""
      "extern void notify (int n);\\n"
      "\\n"
      "void\\n"
      "init (void)\\n"
      "{\\n"
      "  notify (1);\\n"
      "}\\n"
      "\\n"
      "void\\n"
      "finalize (void)\\n"
      "{\\n"
      "  notify (2);\\n"
      "}\\n"
      "', {"
      "  notify: new NativeCallback(n => { send(n); }, 'void', ['int'])"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_NO_MESSAGES ();

  UNLOAD_SCRIPT ();
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_can_be_used_with_interceptor_attach)
{
  int seen_argval = -1;
  int seen_retval = -1;
  gpointer seen_return_address = NULL;
  guint seen_thread_id = 0;
  guint seen_depth = G_MAXUINT;
  int seen_function_data = -1;
  int seen_thread_state_calls = -1;
  int seen_invocation_state_arg = -1;

  COMPILE_AND_LOAD_SCRIPT (
      "const cm = new CModule('"
      "  #include <gum/guminterceptor.h>\\n"
      "\\n"
      "  typedef struct _ThreadState ThreadState;\\n"
      "  typedef struct _InvState InvState;\\n"
      "\\n"
      "  struct _ThreadState\\n"
      "  {\\n"
      "    int calls;\\n"
      "  };\\n"
      "\\n"
      "  struct _InvState\\n"
      "  {\\n"
      "    int arg;\\n"
      "  };\\n"
      "\\n"
      "  extern int seenArgval;\\n"
      "  extern int seenRetval;\\n"
      "  extern gpointer seenReturnAddress;\\n"
      "  extern guint seenThreadId;\\n"
      "  extern guint seenDepth;\\n"
      "  extern int seenFunctionData;\\n"
      "  extern int seenThreadStateCalls;\\n"
      "  extern int seenInvocationStateArg;\\n"
      "\\n"
      "  void\\n"
      "  onEnter (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    int arg = GPOINTER_TO_INT (\\n"
      "        gum_invocation_context_get_nth_argument (ic, 0));\\n"
      "\\n"
      "    seenArgval = arg;\\n"
      "    gum_invocation_context_replace_nth_argument (ic, 0,\\n"
      "        GINT_TO_POINTER (arg + 1));\\n"
      "\\n"
      "    seenReturnAddress =\\n"
      "        gum_invocation_context_get_return_address (ic);\\n"
      "    seenThreadId = gum_invocation_context_get_thread_id (ic);\\n"
      "    seenDepth = gum_invocation_context_get_depth (ic);\\n"
      "\\n"
      "    seenFunctionData = GUM_IC_GET_FUNC_DATA (ic, gsize);\\n"
      "\\n"
      "    ThreadState * ts = GUM_IC_GET_THREAD_DATA (ic, ThreadState);\\n"
      "    ts->calls++;\\n"
      "\\n"
      "    InvState * is = GUM_IC_GET_INVOCATION_DATA (ic, InvState);\\n"
      "    is->arg = seenArgval;\\n"
      "  }\\n"
      "\\n"
      "  void\\n"
      "  onLeave (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    seenRetval = GPOINTER_TO_INT (\\n"
      "        gum_invocation_context_get_return_value (ic));\\n"
      "    gum_invocation_context_replace_return_value (ic,\\n"
      "        GINT_TO_POINTER (42));\\n"
      "\\n"
      "    ThreadState * ts = GUM_IC_GET_THREAD_DATA (ic, ThreadState);\\n"
      "    seenThreadStateCalls = ts->calls;\\n"
      "\\n"
      "    InvState * is = GUM_IC_GET_INVOCATION_DATA (ic, InvState);\\n"
      "    seenInvocationStateArg = is->arg;\\n"
      "  }\\n"
      "', {"
      "  seenArgval: " GUM_PTR_CONST ","
      "  seenRetval: " GUM_PTR_CONST ","
      "  seenReturnAddress: " GUM_PTR_CONST ","
      "  seenThreadId: " GUM_PTR_CONST ","
      "  seenDepth: " GUM_PTR_CONST ","
      "  seenFunctionData: " GUM_PTR_CONST ","
      "  seenThreadStateCalls: " GUM_PTR_CONST ","
      "  seenInvocationStateArg: " GUM_PTR_CONST
      "});"
      "Interceptor.attach(" GUM_PTR_CONST ", cm, ptr(1911));",
      &seen_argval,
      &seen_retval,
      &seen_return_address,
      &seen_thread_id,
      &seen_depth,
      &seen_function_data,
      &seen_thread_state_calls,
      &seen_invocation_state_arg,
      target_function_int);

  EXPECT_NO_MESSAGES ();

  g_assert_cmpint (target_function_int (1), ==, 42);
  g_assert_cmpint (seen_argval, ==, 1);
  g_assert_cmpint (seen_retval, ==, 90);
  g_assert_nonnull (seen_return_address);
  g_assert_cmpuint (seen_thread_id, ==, gum_process_get_current_thread_id ());
  g_assert_cmpuint (seen_depth, ==, 0);
  g_assert_cmpint (seen_function_data, ==, 1911);
  g_assert_cmpint (seen_thread_state_calls, ==, 1);
  g_assert_cmpint (seen_invocation_state_arg, ==, 1);

  target_function_int (12);
  g_assert_cmpint (seen_thread_state_calls, ==, 2);
  g_assert_cmpint (seen_invocation_state_arg, ==, 12);
}

TESTCASE (cmodule_can_be_used_with_interceptor_replace)
{
  int seen_replacement_data = -1;

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <gum/guminterceptor.h>\\n"
      "\\n"
      "extern int seenReplacementData;\\n"
      "\\n"
      "int\\n"
      "dummy (int arg)\\n"
      "{\\n"
      "  GumInvocationContext * ic =\\n"
      "      gum_interceptor_get_current_invocation ();\\n"
      "  seenReplacementData = GUM_IC_GET_REPLACEMENT_DATA (ic, gsize);\\n"
      "\\n"
      "  return 1337;\\n"
      "}\\n"
      "', { seenReplacementData: " GUM_PTR_CONST " });"
      "Interceptor.replace(" GUM_PTR_CONST ", m.dummy, ptr(1911));",
      &seen_replacement_data, target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  g_assert_cmpint (seen_replacement_data, ==, 1911);

  gum_script_unload_sync (fixture->script, NULL);
  g_assert_cmpint (target_function_int (7), ==, 315);
}

TESTCASE (cmodule_can_be_used_with_stalker_events)
{
  GumThreadId test_thread_id;
  guint num_events = 0;
  gsize seen_user_data = 0;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumspinlock.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "extern GumSpinlock lock;\\n"
      "extern guint numEvents;\\n"
      "extern gpointer seenUserData;\\n"
      "\\n"
      "void\\n"
      "process (const GumEvent * event,\\n"
      "         GumCpuContext * cpu_context,\\n"
      "         gpointer user_data)\\n"
      "{\\n"
      "  switch (event->type)\\n"
      "  {\\n"
      "    case GUM_CALL:\\n"
      "      printf (\"[*] CALL\\\\n\");\\n"
      "      break;\\n"
      "    case GUM_RET:\\n"
      "      printf (\"[*] RET\\\\n\");\\n"
      "      break;\\n"
      "    case GUM_EXEC:\\n"
      "      printf (\"[*] EXEC\\\\n\");\\n"
      "      break;\\n"
      "    case GUM_BLOCK:\\n"
      "      printf (\"[*] BLOCK\\\\n\");\\n"
      "      break;\\n"
      "    case GUM_COMPILE:\\n"
      "      printf (\"[*] COMPILE\\\\n\");\\n"
      "      break;\\n"
      "    default:\\n"
      "      printf (\"[*] UNKNOWN\\\\n\");\\n"
      "      break;\\n"
      "  }\\n"
      "\\n"
      "  gum_spinlock_acquire (&lock);\\n"
      "  numEvents++;\\n"
      "  seenUserData = user_data;\\n"
      "  gum_spinlock_release (&lock);\\n"
      "}\\n"
      "', {"
      "  lock: Memory.alloc(Process.pointerSize),"
      "  numEvents: " GUM_PTR_CONST ","
      "  seenUserData: " GUM_PTR_CONST
      "});"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  events: { compile: true, call: true, ret: true },"
      "  onEvent: m.process,"
      "  data: ptr(42)"
      "});"
      "recv('stop', message => {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send('done');"
      "});",
      &num_events,
      &seen_user_data,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();
  g_assert_true (num_events > 0);
  g_assert_cmphex (seen_user_data, ==, 42);
}

TESTCASE (cmodule_can_be_used_with_stalker_transform)
{
  GumThreadId test_thread_id;
  guint num_transforms = 0;
  gsize seen_user_data = 0;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "static void on_ret (GumCpuContext * cpu_context, gpointer user_data);\\n"
      "\\n"
      "extern guint numTransforms;\\n"
      "extern gpointer seenUserData;\\n"
      "\\n"
      "void\\n"
      "transform (GumStalkerIterator * iterator,\\n"
      "           GumStalkerOutput * output,\\n"
      "           gpointer user_data)\\n"
      "{\\n"
      "  GumMemoryAccess access =\\n"
      "      gum_stalker_iterator_get_memory_access (iterator);\\n"
      "  printf (\"\\\\ntransform()\\\\n\");\\n"
      "  const cs_insn * insn = NULL;\\n"
      "  while (gum_stalker_iterator_next (iterator, &insn))\\n"
      "  {\\n"
      "    printf (\"\\\\t%%s %%s\\\\n\", insn->mnemonic, insn->op_str);\\n"
      "#if defined (HAVE_I386)\\n"
      "    if (insn->id == X86_INS_RET)\\n"
      "    {\\n"
      "      gum_x86_writer_put_nop (output->writer.x86);\\n"
      "      gum_stalker_iterator_put_callout (iterator, on_ret, NULL,\\n"
      "          NULL);\\n"
      "    }\\n"
      "#elif defined (HAVE_ARM)\\n"
      "    if (insn->id == ARM_INS_POP)\\n"
      "    {\\n"
      "      if (output->encoding == GUM_INSTRUCTION_DEFAULT)\\n"
      "        gum_arm_writer_put_nop (output->writer.arm);\\n"
      "      else\\n"
      "        gum_thumb_writer_put_nop (output->writer.thumb);\\n"
      "      if (access == GUM_MEMORY_ACCESS_OPEN)\\n"
      "      {\\n"
      "        gum_stalker_iterator_put_callout (iterator, on_ret, NULL,\\n"
      "            NULL);\\n"
      "      }\\n"
      "    }\\n"
      "#elif defined (HAVE_ARM64)\\n"
      "    if (insn->id == ARM64_INS_RET)\\n"
      "    {\\n"
      "      gum_arm64_writer_put_nop (output->writer.arm64);\\n"
      "      if (access == GUM_MEMORY_ACCESS_OPEN)\\n"
      "      {\\n"
      "        gum_stalker_iterator_put_callout (iterator, on_ret, NULL,\\n"
      "            NULL);\\n"
      "      }\\n"
      "    }\\n"
      "#endif\\n"
      "    gum_stalker_iterator_keep (iterator);\\n"
      "  }\\n"
      "  numTransforms++;\\n"
      "  seenUserData = user_data;\\n"
      "}\\n"
      "\\n"
      "static void\\n"
      "on_ret (GumCpuContext * cpu_context,"
      "        gpointer user_data)\\n"
      "{\\n"
      "  // printf (\"\\\\non_ret() cpu_context=%%p\\\\n\", cpu_context);\\n"
      "}\\n"
      "', {"
      "  numTransforms: " GUM_PTR_CONST ","
      "  seenUserData: " GUM_PTR_CONST
      "});"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform: m.transform,"
      "  data: ptr(3)"
      "});"
      "recv('stop', message => {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send('done');"
      "});",
      &num_transforms,
      &seen_user_data,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();
  g_assert_true (num_transforms > 0);
  g_assert_cmphex (seen_user_data, ==, 3);
}

TESTCASE (cmodule_can_be_used_with_stalker_callout)
{
  GumThreadId test_thread_id;
  guint num_callouts = 0;
  gsize seen_user_data = 0;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "extern guint numCallouts;\\n"
      "extern gpointer seenUserData;\\n"
      "\\n"
      "void\\n"
      "onBeforeFirstInstruction (GumCpuContext * cpu_context,"
      "                          gpointer user_data)\\n"
      "{\\n"
      "  printf (\"cpu_context=%%p\\\\n\", cpu_context);\\n"
      "  numCallouts++;\\n"
      "  seenUserData = user_data;\\n"
      "}\\n"
      "', {"
      "  numCallouts: " GUM_PTR_CONST ","
      "  seenUserData: " GUM_PTR_CONST
      "});"
      "let instructionsSeen = 0;"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform(iterator) {"
      "    let instruction;"

      "    while ((instruction = iterator.next()) !== null) {"
      "      if (instructionsSeen === 0) {"
      "        iterator.putCallout(m.onBeforeFirstInstruction, ptr(7));"
      "      }"

      "      iterator.keep();"

      "      instructionsSeen++;"
      "    }"
      "  }"
      "});"
      "recv('stop', message => {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send(instructionsSeen > 0);"
      "});",
      &num_callouts,
      &seen_user_data,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
  g_assert_true (num_callouts > 0);
  g_assert_cmphex (seen_user_data, ==, 7);
}

TESTCASE (cmodule_can_be_used_with_stalker_call_probe)
{
  GumThreadId test_thread_id;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "extern void send (gpointer v);\\n"
      ""
      "void\\n"
      "onCall (GumCallSite * site,"
      "        gpointer user_data)\\n"
      "{\\n"
      "  printf (\"block_address=%%p\\\\n\", site->block_address);\\n"
      "  send (user_data);\\n"
      "}\\n"
      "', {"
      "  send: new NativeCallback(v => { send(v.toUInt32()); }, 'void', "
          "['pointer'])"
      "});"
      "Stalker.addCallProbe(" GUM_PTR_CONST ", m.onCall, ptr(12));"
      "Stalker.follow(%" G_GSIZE_FORMAT ");"
      "recv('stop', message => {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "});"
      "send('ready');",
      target_function_int,
      test_thread_id,
      test_thread_id);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");
  target_function_int (1337);
  EXPECT_SEND_MESSAGE_WITH ("12");
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_can_be_used_with_module_map)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const modules = new ModuleMap();"
      ""
      "const cm = new CModule('"
      "#include <gum/gummodulemap.h>\\n"
      "\\n"
      "const gchar *\\n"
      "find (GumModuleMap * map,\\n"
      "      gconstpointer address)\\n"
      "{\\n"
      "  const GumModuleDetails * m;\\n"
      "\\n"
      "  m = gum_module_map_find (map, GUM_ADDRESS (address));\\n"
      "  if (m == NULL)\\n"
      "    return NULL;\\n"
      "\\n"
      "  return m->name;\\n"
      "}');"
      ""
      "const find = new NativeFunction(cm.find, 'pointer', "
          "['pointer', 'pointer']);"
      "send(find(modules, modules.values()[0].base).isNull());"
      "send(find(modules, NULL).isNull());");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_provide_some_builtin_string_functions)
{
  guint8 buf[2] = { 0, 0 };
  int (* score_impl) (const char * str);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <glib.h>\\n"
      "#include <string.h>\\n"
      "\\n"
      "extern guint8 buf[2];"
      ""
      "int\\n"
      "score (const char * str)\\n"
      "{\\n"
      "  if (strlen (str) == 1)\\n"
      "    return 1;\\n"
      "  if (strcmp (str, \"1234\") == 0)\\n"
      "    return 2;\\n"
      "  if (strstr (str, \"badger\") == str + 4)\\n"
      "    return 3;\\n"
      "  if (strchr (str, \\'!\\') == str + 3)\\n"
      "    return 4;\\n"
      "  if (strrchr (str, \\'/\\') == str + 8)\\n"
      "    return 5;\\n"
      "  if (strlen (str) == 2)\\n"
      "  {\\n"
      "    memcpy (buf, str, 2);\\n"
      "    return 6;\\n"
      "  }\\n"
      "  if (strlen (str) == 3)\\n"
      "  {\\n"
      "    memmove (buf, str + 1, 2);\\n"
      "    return 7;\\n"
      "  }\\n"
      "  if (strlen (str) == 4)\\n"
      "  {\\n"
      "    memset (buf, 88, 2);\\n"
      "    return 8;\\n"
      "  }\\n"
      "  if (strncmp (str, \"w00t\", 4) == 0)\\n"
      "    return 9;\\n"
      "  return -1;\\n"
      "}"
      "', { buf: " GUM_PTR_CONST " });"
      "send(m.score);",
      buf);

  score_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (score_impl);

  g_assert_cmpint (score_impl ("x"), ==, 1);
  g_assert_cmpint (score_impl ("1234"), ==, 2);
  g_assert_cmpint (score_impl ("Goodbadger"), ==, 3);
  g_assert_cmpint (score_impl ("Yay!"), ==, 4);
  g_assert_cmpint (score_impl ("/path/to/file"), ==, 5);

  g_assert_cmphex (buf[0], ==, 0);
  g_assert_cmphex (buf[1], ==, 0);
  g_assert_cmpint (score_impl ("xy"), ==, 6);
  g_assert_cmphex (buf[0], ==, 'x');
  g_assert_cmphex (buf[1], ==, 'y');

  memset (buf, 0, sizeof (buf));
  g_assert_cmpint (score_impl ("xyz"), ==, 7);
  g_assert_cmphex (buf[0], ==, 'y');
  g_assert_cmphex (buf[1], ==, 'z');

  memset (buf, 0, sizeof (buf));
  g_assert_cmpint (score_impl ("xyzx"), ==, 8);
  g_assert_cmphex (buf[0], ==, 'X');
  g_assert_cmphex (buf[1], ==, 'X');

  g_assert_cmpint (score_impl ("w00tage"), ==, 9);
}

TESTCASE (cmodule_should_provide_memory_access_apis)
{
  gboolean (* scan) (const guint8 * p, guint8 ** match);
  guint8 * match;
  const guint8 haystack[] = { 0x11, 0x22, 0x33, 0x13, 0x37, 0x44, 0x42, 0x55 };

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule(`"
      "#include <gum/gummemory.h>\\n"
      "\\n"
      "static gboolean store_match (GumAddress address, gsize size,\\n"
      "    gpointer user_data);\\n"
      "\\n"
      "gboolean\\n"
      "scan (const guint8 * p,\\n"
      "      guint8 ** match)\\n"
      "{\\n"
      "  guint8 * data;\\n"
      "  gsize n_bytes_read;\\n"
      "  GumMemoryRange range;\\n"
      "  GumMatchPattern * pattern;\\n"
      "\\n"
      "  *match = NULL;\\n"
      "\\n"
      "  data = gum_memory_read (p, 8, &n_bytes_read);\\n"
      "  if (data == NULL || n_bytes_read != 8)\\n"
      "    return FALSE;\\n"
      "\\n"
      "  range.base_address = GUM_ADDRESS (data);\\n"
      "  range.size = 8;\\n"
      "  pattern = gum_match_pattern_new_from_string (\"13 37 ?? 42\");\\n"
      "  gum_memory_scan (&range, pattern, store_match, match);\\n"
      "\\n"
      "  gum_match_pattern_unref (pattern);\\n"
      "  g_free (data);\\n"
      "\\n"
      "  return TRUE;\\n"
      "}\\n"
      "\\n"
      "static gboolean\\n"
      "
```