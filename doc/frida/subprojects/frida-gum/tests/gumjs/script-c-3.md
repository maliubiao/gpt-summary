Response:
The user wants to understand the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. The code seems to be testing various JavaScript APIs exposed by Frida's GumJS engine.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The code consists of a series of `TESTCASE` blocks. This immediately suggests that the primary function of this file is to test the functionality of Frida's JavaScript bindings (`gumjs`).

2. **Analyze Individual Test Cases:**  Go through each `TESTCASE` block and understand what it's testing. Look for:
    * The JavaScript code being executed using `COMPILE_AND_LOAD_SCRIPT`.
    * The expected output using `EXPECT_SEND_MESSAGE_WITH`, `EXPECT_ERROR_MESSAGE_WITH`, and `EXPECT_NO_MESSAGES`.
    * Any C code functions being called (e.g., `gum_toupper`).
    * Any data structures being passed between C and JavaScript.

3. **Group Functionalities:**  Based on the individual test cases, categorize the functionalities being tested. Some initial categories might be:
    * `ArrayBuffer` manipulation
    * Integer types (`uint64`, `int64`)
    * Calling native functions (`NativeFunction`)
    * File system operations (`File`)
    * Cryptographic hashing (`Checksum`)
    * SQLite database access (`SqliteDatabase`)
    * Socket communication (`Socket`)
    * Memory manipulation (`ArrayBuffer.wrap`)
    * Pattern matching (`MatchPattern`)

4. **Address Specific Questions:**

    * **Relation to Reversing:** Consider how each tested functionality can be used in reverse engineering. For example:
        * `ArrayBuffer` and memory manipulation are crucial for reading and modifying memory in the target process.
        * Calling native functions allows interaction with the target process's libraries.
        * File system operations are useful for reading configuration files or dumping data.
        * Socket communication can be used to interact with network services or custom communication protocols within the target.
        * Cryptographic hashing can help in identifying algorithms or verifying data integrity.
        * SQLite access is relevant if the target application uses a local database.

    * **Binary/Kernel/Framework Knowledge:**  Think about the underlying concepts each test touches:
        * Memory representation (pointers, data types)
        * Operating system APIs (file I/O, sockets)
        * Android-specific concerns (file paths)

    * **Logical Reasoning:**  Identify test cases that demonstrate a clear input-output relationship. For instance, the `uint64` arithmetic tests show the results of basic operations.

    * **User/Programming Errors:**  Look for tests that explicitly check for errors or demonstrate potential pitfalls, such as incorrect file paths or invalid checksum types.

    * **User Operation to Reach Here:**  Trace back the steps a user would take to end up running these tests. This involves:
        * Installing Frida.
        * Writing a Frida script in JavaScript.
        * Using the Frida CLI or API to inject the script into a target process.
        * The `script.c` file being part of Frida's internal testing framework, so users wouldn't directly interact with it.

5. **Synthesize and Summarize:**  Combine the findings into a concise summary of the file's functionality. Emphasize the testing aspect and the range of JavaScript APIs covered.

6. **Structure the Output:** Organize the information logically, using headings and bullet points for clarity. Address each part of the user's request systematically.

**Self-Correction/Refinement during thought process:**

* Initially, I might have focused too much on the individual lines of C code. It's more important to understand the *purpose* of each test case in terms of the JavaScript API it's exercising.
* I need to explicitly connect the tested functionalities to common reverse engineering tasks. It's not enough to just say "it tests `ArrayBuffer`"; I need to explain *why* `ArrayBuffer` is relevant to reversing.
* I should ensure that the examples for user errors and debugging steps are realistic and helpful.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the user's query.
这是 `frida/subprojects/frida-gum/tests/gumjs/script.c` 文件的第 4 部分，主要功能是测试 Frida 的 GumJS 引擎中与 **内存操作、文件系统操作、加密哈希、SQLite 数据库访问以及网络 Socket 通信** 相关的 JavaScript API 的功能。

**以下是具体功能的列举和说明：**

**1. 内存操作 (ArrayBuffer):**

* **功能:** 测试 `ArrayBuffer` 对象及其与本地内存的交互。包括：
    * 使用 `ArrayBuffer.wrap()` 将 JavaScript 的 `ArrayBuffer` 对象与 C 层的内存关联。
    * 测试读取和修改通过 `ArrayBuffer.wrap()` 关联的本地内存中的数据。
    * 测试 `ArrayBuffer.wrap()` 在不同大小和空指针情况下的行为。
    * 测试使用 `buf.unwrap()` 将 `ArrayBuffer` 对象与底层的内存指针分离。

* **与逆向的关系及举例:**
    * **内存读取/修改:**  在逆向过程中，经常需要读取目标进程的内存来分析数据结构、函数参数、返回值等。`ArrayBuffer.wrap()` 可以将目标进程中的内存地址包装成 JavaScript 的 `ArrayBuffer` 对象，方便在 JavaScript 中进行读取和修改。
        * **例子:** 假设你已知目标进程中某个关键变量的地址为 `0x12345678`，可以使用以下 Frida 代码读取其值：
          ```javascript
          const address = ptr("0x12345678");
          const buffer = new Uint32Array(ArrayBuffer.wrap(address, 4));
          send(buffer[0]); // 发送该地址处的 32 位整数值
          ```
    * **Hook 函数参数/返回值:** 可以利用 `ArrayBuffer.wrap()` 来访问和修改被 hook 函数的指针参数指向的内存区域，从而影响函数的行为。

* **二进制底层知识:** 涉及对内存地址、数据类型（如 `Uint8Array`）、指针的理解。`ArrayBuffer.wrap()` 的第一个参数是内存地址，第二个参数是大小，这直接对应了二进制内存的布局。

* **逻辑推理 (假设输入与输出):**
    * **输入:**  `GUM_PTR_CONST` 指向一块 C 层的内存，值为 `0x0d 0x25` (十进制 13 和 37)。
    * **JavaScript 代码:**  `const val = new Uint8Array(ArrayBuffer.wrap(" GUM_PTR_CONST ", 2)); send(val[0]); send(val[1]);`
    * **输出:**  发送消息 `"13"` 和 `"37"`。

**2. 基本数据类型 (uint64, int64):**

* **功能:** 测试 JavaScript 中 `uint64` 和 `int64` 类型的算术运算能力，包括加、减、与、或、异或、右移、左移、非等操作，以及与 `Number` 类型的转换。

* **与逆向的关系及举例:**
    * **处理大整数:** 在逆向分析中，经常会遇到 64 位整数，例如时间戳、内存地址等。Frida 提供的 `uint64` 和 `int64` 类型可以方便地处理这些大整数，避免 JavaScript 中 `Number` 类型精度丢失的问题。
        * **例子:**  目标进程返回一个 64 位的时间戳，可以使用 Frida 获取并进行运算：
          ```javascript
          const timestamp = recv('timestamp').timestamp; // 假设通过 send 接收到
          const ts = uint64(timestamp);
          send(ts.toString()); // 将 64 位整数转换为字符串发送
          ```

* **二进制底层知识:** 涉及到 64 位整数的二进制表示和运算规则。

* **逻辑推理 (假设输入与输出):**
    * **JavaScript 代码:** `send(uint64(3).add(4).toNumber());`
    * **输出:** 发送消息 `"7"`。

**3. 调用原生函数 (NativeFunction):**

* **功能:** 测试使用 `NativeFunction` API 从 JavaScript 调用 C 层的函数。包括：
    * 定义 `NativeFunction` 对象，指定函数指针、返回值类型和参数类型。
    * 传递不同类型的参数，如指针、整数。
    * 处理返回值。

* **与逆向的关系及举例:**
    * **调用目标进程函数:** 这是 Frida 最核心的功能之一。通过 `NativeFunction`，可以在 JavaScript 中调用目标进程中的任何导出函数或已知地址处的函数。
        * **例子:** 调用 libc 中的 `toupper` 函数将字符串转换为大写：
          ```javascript
          const toupper = new NativeFunction(Module.getExportByName(null, 'toupper'), 'int', ['int']);
          const charCode = 'a'.charCodeAt(0);
          const upperCharCode = toupper(charCode);
          send(String.fromCharCode(upperCharCode)); // 发送 "A"
          ```

* **Linux/Android 内核及框架知识:**  需要了解目标进程的内存布局，以及如何找到目标函数的地址（例如通过模块导出表）。在 Android 上，可能需要了解 Bionic 库。

* **用户/编程常见的使用错误:**
    * **错误的函数指针:** 如果 `GUM_PTR_CONST` 指向的地址不是一个有效的函数，会导致程序崩溃。
    * **错误的参数或返回值类型定义:** 如果 `NativeFunction` 定义的参数或返回值类型与实际函数不符，会导致数据解析错误或崩溃。

**4. 文件系统操作 (File):**

* **功能:** 测试 Frida 提供的 `File` API，用于在目标进程中进行文件读写操作。包括：
    * 读取整个文件 (`File.readAllBytes`, `File.readAllText`).
    * 写入整个文件 (`File.writeAllBytes`, `File.writeAllText`).
    * 分块读取文件 (`file.readBytes`, `file.readText`).
    * 逐行读取文件 (`file.readLine`).
    * 获取和设置文件指针 (`file.tell`, `file.seek`).
    * 写入文件 (`file.write`).

* **与逆向的关系及举例:**
    * **读取配置文件:** 可以读取目标进程的配置文件，了解其运行参数和配置信息。
    * **Dump 内存数据到文件:**  可以将从目标进程内存中读取的数据保存到文件中进行进一步分析。
    * **修改文件内容:** 在某些情况下，可能需要修改目标进程的文件，例如修改配置、破解验证等。

* **Linux/Android 内核及框架知识:** 涉及到操作系统提供的文件 I/O 系统调用，如 `open`, `read`, `write`, `close`, `lseek` 等。在 Android 上，文件路径可能与 Linux 系统有所不同。

* **用户操作是如何一步步的到达这里，作为调试线索:**
    1. 用户编写了一个 Frida 脚本，使用了 `File` 相关的 API，例如尝试读取某个文件。
    2. 用户使用 Frida CLI 或 API 将该脚本注入到目标进程中。
    3. Frida 的 GumJS 引擎执行脚本中的 `File` 相关操作。
    4. 如果操作出现问题，例如文件不存在或权限不足，Frida 会抛出异常，这可以在脚本中捕获或在 Frida 的控制台看到。这里的测试用例就是为了覆盖这些可能出现的情况，确保 `File` API 的各种功能正常工作，并能正确处理错误。

**5. 加密哈希 (Checksum):**

* **功能:** 测试 Frida 提供的 `Checksum` API，用于计算数据的哈希值。支持 MD5, SHA-1, SHA-256, SHA-384, SHA-512 等算法。包括：
    * 流式更新数据并计算哈希值。
    * 一次性计算字符串或字节数组的哈希值。
    * 获取哈希值的字符串表示和二进制表示。

* **与逆向的关系及举例:**
    * **识别加密算法:** 通过计算目标进程中使用的密钥或敏感数据的哈希值，可以帮助识别其使用的加密算法。
    * **校验文件完整性:** 可以计算目标进程加载的库文件或数据的哈希值，与已知的哈希值进行比较，判断文件是否被篡改。

* **二进制底层知识:** 涉及到各种哈希算法的原理和实现。

* **用户/编程常见的使用错误:**
    * **请求未知的校验和类型:**  测试用例中演示了请求 'bogus' 校验和类型时会抛出错误。

**6. SQLite 数据库访问 (SqliteDatabase):**

* **功能:** 测试 Frida 提供的 `SqliteDatabase` API，用于访问目标进程中使用的 SQLite 数据库。包括：
    * 打开内存数据库和外部数据库。
    * 执行 SQL 查询和更新语句。
    * 绑定参数到预编译的 SQL 语句。
    * 获取查询结果。
    * 关闭数据库连接。

* **与逆向的关系及举例:**
    * **分析应用数据存储:** 许多应用使用 SQLite 数据库存储用户数据、配置信息等。通过 Frida 可以访问这些数据库，提取关键信息。
        * **例子:**  查看某个应用存储用户信息的 `users` 表中的数据：
          ```javascript
          const db = SqliteDatabase.open('/data/data/com.example.app/databases/user_info.db');
          const stmt = db.prepare('SELECT username, email FROM users');
          while (stmt.step()) {
            send({ username: stmt.get(0), email: stmt.get(1) });
          }
          stmt.dispose();
          db.close();
          ```

* **Linux/Android 内核及框架知识:**  需要了解 SQLite 数据库的基本概念和 SQL 语法。在 Android 上，数据库文件通常位于应用的私有目录下。

**7. 网络 Socket 通信 (Socket):**

* **功能:** 测试 Frida 提供的 `Socket` API，用于进行网络通信。包括：
    * 创建和监听 TCP 和 Unix Domain Socket。
    * 建立连接。
    * 发送和接收数据。
    * 关闭连接。
    * 支持 TLS 加密连接。
    * 查询 Socket 类型。

* **与逆向的关系及举例:**
    * **监控网络通信:** 可以 hook 目标进程的网络相关函数，但 Frida 提供的 `Socket` API 也可以用于模拟网络请求或与目标进程建立自定义的通信通道。
    * **分析网络协议:** 通过捕获和分析目标进程发送和接收的网络数据，可以了解其使用的网络协议。

* **Linux/Android 内核及框架知识:**  涉及到网络编程的基础知识，如 TCP/IP 协议、Socket 编程 API（`socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `close` 等）。

**8. 匹配模式 (MatchPattern):**

* **功能:** 测试 `MatchPattern` 对象，用于创建匹配字节序列的模式，可以包含通配符。

* **与逆向的关系及举例:**
    * **查找特征码:** 在逆向分析中，经常需要查找特定的字节序列（特征码）来定位代码或数据。`MatchPattern` 可以方便地创建包含通配符的特征码进行搜索。

**归纳一下它的功能 (作为第 4 部分):**

这部分代码专注于测试 Frida 的 GumJS 引擎提供的与**底层系统交互**相关的核心功能，包括**直接操作内存、读写文件、进行加密计算、访问 SQLite 数据库以及建立网络连接**。这些功能对于动态分析和逆向工程至关重要，因为它允许 JavaScript 脚本深入到目标进程的内部，并与操作系统进行交互。通过这些测试用例，可以确保 Frida 的这些核心 API 的稳定性和正确性。

**用户操作是如何一步步的到达这里，作为调试线索:**

虽然用户通常不会直接运行 `script.c` 中的测试用例，但这些测试覆盖了用户在编写 Frida 脚本时可能使用的各种 API。当用户编写的 Frida 脚本使用了这些 API 并遇到问题时，可以参考这些测试用例来理解 API 的预期行为，对比自己的使用方式，从而找到问题所在。例如：

1. **用户脚本使用了 `File.readAllText()` 读取文件失败:**  可以查看 `TESTCASE (whole_file_can_be_read_as_text)` 及其相关的错误处理测试，了解可能的错误原因（例如文件不存在、权限问题、编码问题）。
2. **用户脚本使用 `NativeFunction` 调用函数崩溃:** 可以查看 `TESTCASE` 中 `NativeFunction` 的使用方式，检查函数指针是否正确，参数和返回值类型是否匹配。
3. **用户脚本操作 SQLite 数据库出错:** 可以参考 `TESTCASE` 中 `SqliteDatabase` 的用法，检查 SQL 语句是否正确，参数绑定是否正确。

因此，这些测试用例虽然是 Frida 内部的测试代码，但它们也为用户提供了理解 Frida API 工作原理和进行调试的重要参考。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
IPT (
      "const val = new Uint8Array(ArrayBuffer.wrap(" GUM_PTR_CONST ", 2));"
      "send(val.length);"
      "send(val[0]);"
      "send(val[1]);"
      "val[0] = 42;"
      "val[1] = 24;",
      val);
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("13");
  EXPECT_SEND_MESSAGE_WITH ("37");
  g_assert_cmpint (val[0], ==, 42);
  g_assert_cmpint (val[1], ==, 24);

  COMPILE_AND_LOAD_SCRIPT (
      "const val = new Uint8Array(ArrayBuffer.wrap(" GUM_PTR_CONST ", 0));"
      "send(val.length);"
      "send(typeof val[0]);",
      val);
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const val = new Uint8Array(ArrayBuffer.wrap(NULL, 0));"
      "send(val.length);"
      "send(typeof val[0]);");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
}

TESTCASE (array_buffer_can_be_unwrapped)
{
  gchar str[5 + 1];

  COMPILE_AND_LOAD_SCRIPT (
      "const toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "const buf = new ArrayBuffer(2 + 1);"
      "const bytes = new Uint8Array(buf);"
      "bytes[0] = 'h'.charCodeAt(0);"
      "bytes[1] = 'i'.charCodeAt(0);"
      "send(toupper(buf.unwrap(), -1));"
      "send(bytes[0]);"
      "send(bytes[1]);",
      gum_toupper, str);
  EXPECT_SEND_MESSAGE_WITH ("-2");
  EXPECT_SEND_MESSAGE_WITH ("72");
  EXPECT_SEND_MESSAGE_WITH ("73");
  EXPECT_NO_MESSAGES ();

  strcpy (str, "snake");
  COMPILE_AND_LOAD_SCRIPT (
      "const toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "const buf = ArrayBuffer.wrap(" GUM_PTR_CONST ", 5 + 1);"
      "send(toupper(buf.unwrap(), -1));",
      gum_toupper, str);
  EXPECT_SEND_MESSAGE_WITH ("-5");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (str, ==, "SNAKE");
}

TESTCASE (uint64_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(uint64(3).add(4).toNumber());"
      "send(uint64(7).sub(4).toNumber());"
      "send(uint64(6).and(3).toNumber());"
      "send(uint64(6).or(3).toNumber());"
      "send(uint64(6).xor(3).toNumber());"
      "send(uint64(63).shr(4).toNumber());"
      "send(uint64(1).shl(3).toNumber());"
      "send(uint64(0).not().toString());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("\"18446744073709551615\"");
}

TESTCASE (uint64_can_be_constructed_from_a_large_number)
{
  COMPILE_AND_LOAD_SCRIPT ("send(uint64(Math.pow(2, 63)).toString(16));");
  EXPECT_SEND_MESSAGE_WITH ("\"8000000000000000\"");
}

TESTCASE (uint64_can_be_converted_to_a_large_number)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const a = Math.pow(2, 63);"
      "const b = uint64(a).toNumber();"
      "send(b === a);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (int64_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(int64(3).add(4).toNumber());"
      "send(int64(7).sub(4).toNumber());"
      "send(int64(6).and(3).toNumber());"
      "send(int64(6).or(3).toNumber());"
      "send(int64(6).xor(3).toNumber());"
      "send(int64(63).shr(4).toNumber());"
      "send(int64(1).shl(3).toNumber());"
      "send(int64(0).not().toNumber());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("-1");
}

static gint
gum_get_answer_to_life_universe_and_everything (void)
{
  return 42;
}

static gint
gum_toupper (gchar * str,
             gint limit)
{
  gint count = 0;
  gchar * c;

  for (c = str; *c != '\0' && (count < limit || limit == -1); c++, count++)
  {
    *c = g_ascii_toupper (*c);
  }

  return (limit == -1) ? -count : count;
}

static gint64
gum_classify_timestamp (gint64 timestamp)
{
  if (timestamp < 0)
    return -1;
  else if (timestamp > 0)
    return 1;
  else
    return 0;
}

static guint64
gum_square (guint64 value)
{
  return value * value;
}

static gint
gum_sum (gint count,
         ...)
{
  gint total = 0;
  va_list args;
  gint i;

  va_start (args, count);
  for (i = 0; i != count; i++)
    total += va_arg (args, gint);
  va_end (args);

  return total;
}

static gint
gum_add_pointers_and_float_fixed (gpointer a,
                                  gpointer b,
                                  float c)
{
  return GPOINTER_TO_SIZE (a) + GPOINTER_TO_SIZE (b) + (int) c;
}

static gint
gum_add_pointers_and_float_variadic (gpointer a,
                                     ...)
{
  gint total = GPOINTER_TO_SIZE (a);
  va_list args;
  gpointer p;

  va_start (args, a);
  while ((p = va_arg (args, gpointer)) != NULL)
  {
    total += GPOINTER_TO_SIZE (p);
    total += (int) va_arg (args, double); /* float is promoted to double */
  }
  va_end (args);

  return total;
}

TESTCASE (whole_file_can_be_read_as_bytes)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "send(Array.from(new Uint8Array(File.readAllBytes('%s'))));",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("[97,98,99]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (whole_file_can_be_read_as_text)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT ("send(File.readAllText('%s'));", ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("\"abc\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (whole_file_can_be_read_as_text_with_validation)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("ab\xc3\x28" "c");
  COMPILE_AND_LOAD_SCRIPT ("send(File.readAllText('%s'));", ESCAPE_PATH (path));
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: can't decode byte 0xc3 in position 2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (whole_file_can_be_written_from_bytes)
{
  const gchar * path;
  gchar * contents;

  path = MAKE_TEMPFILE_CONTAINING ("abc");

  COMPILE_AND_LOAD_SCRIPT (
      "File.writeAllBytes('%s', new Uint8Array([100,101,102]));",
      ESCAPE_PATH (path));
  EXPECT_NO_MESSAGES ();

  g_file_get_contents (path, &contents, NULL, NULL);
  g_assert_cmpstr (contents, ==, "def");
  g_free (contents);
}

TESTCASE (whole_file_can_be_written_from_text)
{
  const gchar * path;
  gchar * contents;

  path = MAKE_TEMPFILE_CONTAINING ("abc");

  COMPILE_AND_LOAD_SCRIPT ("File.writeAllText('%s', 'def');",
      ESCAPE_PATH (path));
  EXPECT_NO_MESSAGES ();

  g_file_get_contents (path, &contents, NULL, NULL);
  g_assert_cmpstr (contents, ==, "def");
  g_free (contents);
}

TESTCASE (file_can_be_read_as_bytes_in_one_go)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "const buf = file.readBytes();"
      "send(buf instanceof ArrayBuffer);"
      "send(Array.from(new Uint8Array(buf)));",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("[97,98,99]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_read_as_bytes_in_chunks)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "send(Array.from(new Uint8Array(file.readBytes(2))));"
      "send(Array.from(new Uint8Array(file.readBytes())));"
      "send(Array.from(new Uint8Array(file.readBytes(1))));",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("[97,98]");
  EXPECT_SEND_MESSAGE_WITH ("[99]");
  EXPECT_SEND_MESSAGE_WITH ("[]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_read_as_text_in_one_go)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "send(file.readText());",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("\"abc\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_read_as_text_in_chunks)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "send(file.readText(2));"
      "send(file.readText());"
      "send(file.readText(1));",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("\"ab\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c\"");
  EXPECT_SEND_MESSAGE_WITH ("\"\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_read_as_text_with_validation)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("\xc3\x28yay");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "try {"
      "  send(file.readText(2));"
      "} catch (e) {"
      "  send(e.message);"
      "}"
      "send(file.tell());"
      "file.seek(2, File.SEEK_CUR);"
      "send(file.readText());",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("\"can't decode byte 0xc3 in position 0\"");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"yay\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_read_line_by_line)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("first\nsecond");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');\n"
      "send(file.readLine());\n"
      "send(file.readLine());\n"
      "send(file.readLine());\n",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("\"first\\n\"");
  EXPECT_SEND_MESSAGE_WITH ("\"second\"");
  EXPECT_SEND_MESSAGE_WITH ("\"\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_read_line_by_line_with_validation)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("first\noops\xc3\x28\nlast");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');\n"
      "send(file.readLine());\n"
      "try {"
      "  send(file.readLine());"
      "} catch (e) {"
      "  send(e.message);"
      "}"
      "file.seek(7, File.SEEK_CUR);"
      "send(file.readLine());\n",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("\"first\\n\"");
  EXPECT_SEND_MESSAGE_WITH ("\"can't decode byte 0xc3 in position 4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"last\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_position_can_be_queried)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "send(file.tell());"
      "file.readBytes(2);"
      "send(file.tell());",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_position_can_be_updated_to_absolute_position_implicitly)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "file.seek(2);"
      "send(file.tell());"
      "send(Array.from(new Uint8Array(file.readBytes())));"
      "send(file.tell());",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("[99]");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_position_can_be_updated_to_absolute_position_explicitly)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "file.seek(2, File.SEEK_SET);"
      "send(file.tell());"
      "send(Array.from(new Uint8Array(file.readBytes())));"
      "send(file.tell());",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("[99]");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_position_can_be_updated_to_relative_position_from_current)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "send(Array.from(new Uint8Array(file.readBytes(2))));"
      "file.seek(-1, File.SEEK_CUR);"
      "send(Array.from(new Uint8Array(file.readBytes())));",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("[97,98]");
  EXPECT_SEND_MESSAGE_WITH ("[98,99]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_position_can_be_updated_to_relative_position_from_end)
{
  const gchar * path = MAKE_TEMPFILE_CONTAINING ("abc");
  COMPILE_AND_LOAD_SCRIPT (
      "const file = new File('%s', 'rb');"
      "file.seek(-2, File.SEEK_END);"
      "send(Array.from(new Uint8Array(file.readBytes())));",
      ESCAPE_PATH (path));
  EXPECT_SEND_MESSAGE_WITH ("[98,99]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (file_can_be_written_to)
{
  const gchar * path;
  const gchar d00d[4] = { 0x64, 0x30, 0x30, 0x64 };
  gchar * contents;

  path = MAKE_TEMPFILE_CONTAINING ("abc");

  COMPILE_AND_LOAD_SCRIPT (
      "const log = new File('%s', 'wb');"
      "log.write(\"Hello \");"
      "log.write(" GUM_PTR_CONST ".readByteArray(4));"
      "log.write(\"!\\n\");"
      "log.close();",
      ESCAPE_PATH (path), d00d);
  EXPECT_NO_MESSAGES ();

  g_file_get_contents (path, &contents, NULL, NULL);
  g_assert_cmpstr (contents, ==, "Hello d00d!\n");
  g_free (contents);
}

#ifndef HAVE_QNX

TESTCASE (file_apis_can_not_trigger_interceptor)
{
  const gchar * path;
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  path = MAKE_TEMPFILE_CONTAINING ("abc");

  COMPILE_AND_LOAD_SCRIPT (
      "const referencePath = '%s';"
      "setTimeout(() => {"
      "  Interceptor.attach(Module.getExportByName(null, 'fopen'), {"
      "    onEnter(args) {"
      "      const path = args[0].readUtf8String();"
      "      if (path === referencePath) {"
      "        send('intercepted');"
      "      }"
      "    }"
      "  });"
      "  Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback((arg) => {"
      "    const log = new File(referencePath, 'wb');"
      "    log.write('Hello!\\n');"
      "    log.close();"
      "    send('File written');"
      "    return arg;"
      "  }, 'int', ['int']));"
      "  send('Test scheduled');"
      "}, 0);",
      ESCAPE_PATH (path),
      target_function_int);

  EXPECT_SEND_MESSAGE_WITH ("\"Test scheduled\"");
  ctx.script = fixture->script;
  ctx.repeat_duration = 0;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_SEND_MESSAGE_WITH ("\"File written\"");
  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_NO_MESSAGES ();
}

#endif

TESTCASE (md5_can_be_computed_for_stream)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const checksum = new Checksum('md5');"
      "checksum.update('ab').update('c');"

      "send(checksum.getString());"

      "const view = new DataView(checksum.getDigest());"
      "send(["
      "  view.getUint32(0).toString(16),"
      "  view.getUint32(4).toString(16),"
      "  view.getUint32(8).toString(16),"
      "  view.getUint32(12).toString(16)"
      "]);"

      "checksum.update('d');");

  EXPECT_SEND_MESSAGE_WITH ("\"900150983cd24fb0d6963f7d28e17f72\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"90015098\",\"3cd24fb0\",\"d6963f7d\","
      "\"28e17f72\"]");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: checksum is closed");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (md5_can_be_computed_for_string)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Checksum.compute('md5', 'abc'));");
  EXPECT_SEND_MESSAGE_WITH ("\"900150983cd24fb0d6963f7d28e17f72\"");
}

TESTCASE (md5_can_be_computed_for_bytes)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const data = new Uint8Array([ 1, 2, 3 ]);"
      "send(Checksum.compute('md5', data.buffer));");
  EXPECT_SEND_MESSAGE_WITH ("\"5289df737df57326fcdd22597afb1fac\"");
}

TESTCASE (sha1_can_be_computed_for_string)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Checksum.compute('sha1', 'abc'));");
  EXPECT_SEND_MESSAGE_WITH ("\"a9993e364706816aba3e25717850c26c9cd0d89d\"");
}

TESTCASE (sha256_can_be_computed_for_string)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Checksum.compute('sha256', 'abc'));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      "\"");
}

TESTCASE (sha384_can_be_computed_for_string)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Checksum.compute('sha384', 'abc'));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
      "8086072ba1e7cc2358baeca134c825a7"
      "\"");
}

TESTCASE (sha512_can_be_computed_for_string)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Checksum.compute('sha512', 'abc'));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
      "\"");
}

TESTCASE (requesting_unknown_checksum_for_string_should_throw)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Checksum.compute('bogus', 'abc'));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: unsupported checksum type");
}

#ifdef HAVE_SQLITE

TESTCASE (inline_sqlite_database_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const db = SqliteDatabase.openInline('"
          "H4sIAMMIT1kAA+3ZsU7DMBAG4HMC7VChROpQut0IqGJhYCWJDAq4LbhGoqNRDYqgpIo"
          "CO8y8JM/AC+CKFNhgLfo/+U7n0/kBTp5cqKJ2fFNWc1vzAcUkBB0xE1HYxIrwsdHUYX"
          "P/TUj7m+nWcjhy5A8AAAAAAADA//W8Ldq9fl+8dGp7fe8WrlyscphpmRjJJkmV5M8e7"
          "xQzzkdGnkjN5zofJnrKZ3LKySQb8IOdOzbyyvBo7ONSqQHbW/f14Lt7Z/1S7+uh1Hn2"
          "c/rJ1rbiVI3T3b8s8QAAAAAAAACw3pZ/80H0RtG7TwAAAAAAAACwnuKgRT0RxMdVMbN"
          "teu0edkSLukLQaen2Hj8AoNOJGgAwAAA="
      "');\n"

      /* 1: bindInteger() */
      "let s = db.prepare('SELECT name, age FROM people WHERE age = ?');\n"
      "s.bindInteger(1, 42);\n"
      "send(s.step());\n"
      "send(s.step());\n"
      "s.reset();\n"
      "s.bindInteger(1, 7);\n"
      "send(s.step());\n"

      /* 2: bindFloat() */
      "s = db.prepare('SELECT name FROM people WHERE karma <= ?');\n"
      "s.bindFloat(1, 117.5);\n"
      "send(s.step());\n"
      "send(s.step());\n"

      /* 3: bindText() */
      "s = db.prepare('SELECT age FROM people WHERE name = ?');\n"
      "s.bindText(1, 'Joe');\n"
      "send(s.step());\n"

      /* 4: bindBlob() */
      "s = db.prepare('SELECT name FROM people WHERE avatar = ?');\n"
      "s.bindBlob(1, [0x13, 0x37]);\n"
      "send(s.step());\n"
      "send(s.step());\n"

      /* 5: bindNull() */
      "s = db.prepare('INSERT INTO people VALUES (?, ?, ?, ?, ?)');\n"
      "s.bindInteger(1, 3);\n"
      "s.bindText(2, 'Alice');\n"
      "s.bindInteger(3, 40);\n"
      "s.bindInteger(4, 150);\n"
      "s.bindNull(5);\n"
      "send(s.step());\n"
      "s = db.prepare('SELECT * FROM people WHERE name = \"Alice\"');\n"
      "send(s.step());\n"
      "send(s.step());\n"

      /* 6: blob column */
      "s = db.prepare('SELECT avatar FROM people WHERE name = ?');\n"
      "s.bindText(1, 'Frida');\n"
      "send('avatar', s.step()[0]);\n"
      "send(s.step());\n"
      "s.reset();\n"
      "s.bindText(1, 'Joe');\n"
      "send(s.step());\n"
      "send(s.step());\n");

  /* 1: bindInteger() */
  EXPECT_SEND_MESSAGE_WITH ("[\"Joe\",42]");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("[\"Frida\",7]");

  /* 2: bindFloat() */
  EXPECT_SEND_MESSAGE_WITH ("[\"Joe\"]");
  EXPECT_SEND_MESSAGE_WITH ("null");

  /* 3: bindText() */
  EXPECT_SEND_MESSAGE_WITH ("[42]");

  /* 4: bindBlob() */
  EXPECT_SEND_MESSAGE_WITH ("[\"Frida\"]");
  EXPECT_SEND_MESSAGE_WITH ("null");

  /* 5: bindNull() */
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("[3,\"Alice\",40,150,null]");
  EXPECT_SEND_MESSAGE_WITH ("null");

  /* 6: blob column */
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"avatar\"", "13 37");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("[null]");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (external_sqlite_database_can_be_queried)
{
  TestScriptMessageItem * item;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "const db = SqliteDatabase.open('/tmp/gum-test.db');\n"
      "db.exec(\""
          "PRAGMA foreign_keys=OFF;"
          "BEGIN TRANSACTION;"
          "CREATE TABLE people ("
              "id INTEGER PRIMARY KEY ASC,"
              "name TEXT NOT NULL,"
              "age INTEGER NOT NULL,"
              "karma NUMERIC NOT NULL,"
              "avatar BLOB"
          ");"
          "INSERT INTO people VALUES (1, 'Joe', 42, 117, NULL);"
          "INSERT INTO people VALUES (2, 'Frida', 7, 140, X'1337');"
          "COMMIT;"
      "\");\n"
      "send(db.dump());\n"
      "db.close();\n");

  item = test_script_fixture_pop_message (fixture);
  g_print ("%s\n", item->message);
  test_script_message_item_free (item);
}

TESTCASE (external_sqlite_database_can_be_opened_with_flags)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "let db = null;\n"

      "try {\n"
          "db = SqliteDatabase.open('/tmp/gum-test-dont-create.db',"
            "{ flags: ['readwrite'] });\n"
          "send('fail');\n"
          "db.close();\n"
      "} catch (e) {\n"
          "send('not exists');\n"
      "}\n"

      "try {\n"
          "db = SqliteDatabase.open('/tmp/gum-test-dont-create2.db',"
            "{ flags: ['readonly'] });\n"
          "send('fail');\n"
          "db.close();\n"
      "} catch (e) {\n"
          "send('not exists again');\n"
      "}\n"

      "try {\n"
          "db = SqliteDatabase.open('/tmp/gum-test-dont-write.db',"
            "{ flags: ['readonly', 'create'] });\n"
          "send('fail');\n"
          "db.close();\n"
      "} catch (e) {\n"
          "send('invalid flags');\n"
      "}\n"

      "db = SqliteDatabase.open('/tmp/gum-test-can-write.db',"
        "{ flags: ['readwrite', 'create'] });\n"
      "try {\n"
          "db.exec(\""
              "PRAGMA foreign_keys=OFF;"
              "BEGIN TRANSACTION;"
              "CREATE TABLE people ("
                  "id INTEGER PRIMARY KEY ASC,"
                  "name TEXT NOT NULL,"
                  "age INTEGER NOT NULL,"
                  "karma NUMERIC NOT NULL,"
                  "avatar BLOB"
              ");"
              "INSERT INTO people VALUES (1, 'Joe', 42, 117, NULL);"
              "INSERT INTO people VALUES (2, 'Frida', 7, 140, X'1337');"
              "COMMIT;"
          "\");\n"
          "send('can write');\n"
      "} catch (e) {\n"
          "send('fail');\n"
      "}\n"
      "db.close();\n");

  EXPECT_SEND_MESSAGE_WITH ("\"not exists\"");
  EXPECT_SEND_MESSAGE_WITH ("\"not exists again\"");
  EXPECT_SEND_MESSAGE_WITH ("\"invalid flags\"");
  EXPECT_SEND_MESSAGE_WITH ("\"can write\"");
  EXPECT_NO_MESSAGES ();
}

# if !defined (HAVE_WINDOWS) && !defined (HAVE_QNX)

TESTCASE (sqlite_apis_can_not_trigger_interceptor)
{
  gchar * path;
  gint fd;
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  fd = g_file_open_tmp ("gum-tests.XXXXXX", &path, NULL);
  g_assert_cmpint (fd, !=, -1);
  close (fd);
  g_queue_push_tail (&fixture->tempfiles, path);

  COMPILE_AND_LOAD_SCRIPT (
      "const referencePath = '%s';"
      "let stat = Module.findExportByName(null, 'stat');"
      "if (stat === null) {"
      "  stat = Module.findExportByName(null, '__xstat64');"
      "}"
      "if (stat === null) {"
      "  stat = Module.findExportByName(null, '__xstat');"
      "}"
      "Interceptor.attach(stat, {"
      "  onEnter(args) {"
      "    const path = args[0].readUtf8String();"
      "    if (path.includes(referencePath)) {"
      "      send('intercepted stat');"
      "    }"
      "  }"
      "});"
      "Interceptor.attach(Module.getExportByName(null, 'open'), {"
      "  onEnter(args) {"
      "    const path = args[0].readUtf8String();"
      "    if (path.includes(referencePath)) {"
      "      send('intercepted open');"
      "    }"
      "  }"
      "});"
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback((arg) => {"
      "  const db = SqliteDatabase.open(referencePath);"
      "  send('Database created');"
      "  db.exec(`"
      "  CREATE TABLE IF NOT EXISTS test ("
      "     id TEXT PRIMARY KEY,"
      "     stuff TEXT"
      "  );`);"
      "  send('Table created');"
      "  const statement = db"
      "    .prepare('INSERT INTO test (id, stuff) VALUES (?, ?);');"
      "  send('Statement prepared');"
      "  statement.bindText(1, 'i am primary ' + Date.now());"
      "  statement.bindText(2, 'i am stuff');"
      "  statement.step();"
      "  statement.reset();"
      "  send('Query done');"
      "  db.close();"
      "  send('Database closed');"
      "  return arg;"
      "}, 'int', ['int']));",
      ESCAPE_PATH (path),
      target_function_int);

  ctx.script = fixture->script;
  ctx.repeat_duration = 0;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_SEND_MESSAGE_WITH ("\"Database created\"");
  EXPECT_SEND_MESSAGE_WITH ("\"Table created\"");
  EXPECT_SEND_MESSAGE_WITH ("\"Statement prepared\"");
  EXPECT_SEND_MESSAGE_WITH ("\"Query done\"");
  EXPECT_SEND_MESSAGE_WITH ("\"Database closed\"");
  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_NO_MESSAGES ();
}

# endif

#endif

TESTCASE (match_pattern_can_be_constructed_from_string)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const p = new MatchPattern('13 37 ?? ff');"
      "send(JSON.stringify(p));"
  );
  EXPECT_SEND_MESSAGE_WITH ("\"{}\"");

  COMPILE_AND_LOAD_SCRIPT ("new MatchPattern('Some bad pattern');");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid match pattern");
}

TESTCASE (socket_connection_can_be_established)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  PUSH_TIMEOUT (10000);

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const listener = await Socket.listen({ backlog: 1 });"
      "    launchClient({"
      "      family: 'ipv4',"
      "      host: 'localhost',"
      "      port: listener.port,"
      "    });"
      "    const client = await listener.accept();"
      "    const data = await client.input.readAll(5);"
      "    send('server read', data);"
      "    await client.close();"
      "    await listener.close();"
      "  } catch (e) {"
      "    send(`[server] ${e.stack}`);"
      "  }"
      "}"
      "async function launchClient(options) {"
      "  try {"
      "    const connection = await Socket.connect(options);"
      "    await connection.setNoDelay(true);"
      "    await connection.output.writeAll([0x31, 0x33, 0x33, 0x37, 0x0a]);"
      "    await connection.close();"
      "  } catch (e) {"
      "    send(`[client] ${e.stack}`);"
      "  }"
      "}"
      "run();");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"server read\"",
      "31 33 33 37 0a");

#ifdef G_OS_UNIX
  {
    const gchar * tmp_dir;

#ifdef HAVE_ANDROID
    tmp_dir = "/data/local/tmp";
#else
    tmp_dir = g_get_tmp_dir ();
#endif

    COMPILE_AND_LOAD_SCRIPT (
        "const unlink = new NativeFunction("
        "    Module.getExportByName(null, 'unlink'), 'int', ['pointer']);"
        "async function run() {"
        "  try {"
        "    const listener = await Socket.listen({"
        "      type: 'path',"
        "      path: '%s/frida-gum-test-listener-' + Process.id,"
        "      backlog: 1,"
        "    });"
        "    launchClient({"
        "      type: 'path',"
        "      path: listener.path,"
        "    });"
        "    const client = await listener.accept();"
        "    const data = await client.input.readAll(5);"
        "    send('server read', data);"
        "    await client.close();"
        "    await listener.close();"
        "  } catch (e) {"
        "    send(`[server] ${e.stack}`);"
        "  }"
        "}"
        "async function launchClient(options) {"
        "  try {"
        "    const connection = await Socket.connect(options);"
        "    unlink(Memory.allocUtf8String(options.path));"
        "    await connection.output.writeAll([0x31, 0x33, 0x33, 0x37, 0x0a]);"
        "    await connection.close();"
        "  } catch (e) {"
        "    send(`[client] ${e.stack}`);"
        "  }"
        "}"
        "run();",
      tmp_dir);
    EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"server read\"",
        "31 33 33 37 0a");
  }
#endif
}

TESTCASE (socket_connection_can_be_established_with_tls)
{
  gboolean done;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  PUSH_TIMEOUT (10000);

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const connection = await Socket.connect({"
      "      family: 'ipv4',"
      "      host: 'www.google.com',"
      "      port: 443,"
      "      tls: true,"
      "    });"
      ""
      "    await connection.setNoDelay(true);"
      ""
      "    const request = ["
      "      'GET / HTTP/1.1',"
      "      'Connection: close',"
      "      'Host: www.google.com',"
      "      'Accept: text/html',"
      "      'User-Agent: Frida/" FRIDA_VERSION "',"
      "      '',"
      "      '',"
      "    ].join('\\r\\n');"
      "    const rawRequest = [];"
      "    for (let i = 0; i !== request.length; i++)"
      "      rawRequest.push(request.charCodeAt(i));"
      "    send('request', rawRequest);"
      "    await connection.output.writeAll(rawRequest);"
      ""
      "    const response = await connection.input.read(128 * 1024);"
      "    send('response', response);"
      "  } catch (e) {"
      "    send(`oops: ${e.stack}`);"
      "  }"
      "}"
      "run();");

  g_printerr ("\n\n");

  done = FALSE;
  while (!done)
  {
    TestScriptMessageItem * item;

    item = test_script_fixture_pop_message (fixture);

    if (item->raw_data != NULL)
    {
      gboolean is_request;
      const guint8 * raw_chunk;
      gsize size;
      gchar * chunk;

      is_request = strstr (item->message, "\"request\"") != NULL;

      raw_chunk = g_bytes_get_data (item->raw_data, &size);
      chunk = g_strndup ((const gchar *) raw_chunk, size);

      g_printerr ("*** %s %" G_GSIZE_MODIFIER "u bytes\n%s",
          is_request ? "Sent" : "Received",
          size,
          chunk);

      g_free (chunk);

      done = !is_request;
    }
    else
    {
      g_printerr ("Got: %s\n", item->message);
    }

    test_script_message_item_free (item);
  }
}

TESTCASE (socket_connection_should_not_leak_on_error)
{
  if (!g_test_slow ())
  {
    g_print("<skipping, run in slow mode> ");
    return;
  }

  PUSH_TIMEOUT (5000);
  COMPILE_AND_LOAD_SCRIPT (
      "let tries = 0;"
      "let port = 28300;"
      "let firstErrorMessage = null;"
      ""
      "tryNext();"
      ""
      "function tryNext() {"
      "  tries++;"
      "  if (tries === 200) {"
      "    send('done');"
      "    return;"
      "  }"
      ""
      "  Socket.connect({"
      "    family: 'ipv4',"
      "    host: 'localhost',"
      "    port: port,"
      "  })"
      "  .then(connection => {"
      "    console.log('success');"
      "    tries--;"
      "    port++;"
      "    tryNext();"
      "  })"
      "  .catch(error => {"
      "    if (firstErrorMessage === null) {"
      "      firstErrorMessage = error.message;"
      "    } else if (error.message !== firstErrorMessage) {"
      "      send('Expected \"' + firstErrorMessage + '\" but got \"' +"
      "          error.message + '\"');"
      "      return;"
      "    }"
      "    console.log('tries=' + tries + ' error=\"' + error.message + '\"');"
      "    tryNext();"
      "  });"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
}

TESTCASE (socket_type_can_be_inspected)
{
  int fd;
  struct sockaddr_in addr = { 0, };
  const guint port = 39876;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"tcp\"");
  addr.sin_family = AF_INET;
  addr.sin_port = GUINT16_TO_BE (port);
  addr.sin_addr.s_addr = INADDR_ANY;
  bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"tcp\"");
  GUM_CLOSE_SOCKET (fd);

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"udp\"");
  GUM_CLOSE_SOCKET (fd);

  fd = socket (AF_INET6, SOCK_STREAM, 0);
  if (fd != -1)
  {
    COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
    EXPECT_SEND_M
```