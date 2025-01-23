Response:
Let's break down the thought process for analyzing this C code.

1. **Understand the Purpose:** The first step is to recognize what this code is for. The filename `memory.c` and the inclusion of `gummemory-priv.h` strongly suggest this is testing the memory manipulation functionalities of the Frida Gum library. The `#include "testutil.h"` further reinforces that it's a test suite.

2. **Identify Key Functionalities:** Scan through the `TESTCASE` definitions. Each `TESTCASE` name hints at a specific memory-related operation being tested. List them out:

    * Reading from valid/invalid/unaligned addresses
    * Reading across page boundaries
    * Writing to valid/invalid addresses
    * Matching memory patterns (exact, wildcard, masked, regex)
    * Checking memory readability
    * Allocating aligned memory (near and not near)
    * Handling alignment during allocation
    * Handling page boundaries with `mprotect`

3. **Relate to Reverse Engineering:**  Consider how these functionalities are relevant to reverse engineering. Frida is a dynamic instrumentation toolkit, so its core purpose is to interact with running processes. Memory manipulation is fundamental to this. Think about common RE tasks:

    * **Reading process memory:**  Essential for inspecting data, code, and structures. The `read_from_...` tests directly relate.
    * **Writing to process memory:**  Used for patching, modifying behavior, injecting code. The `write_to_...` tests are relevant.
    * **Searching for patterns:** Crucial for locating specific instructions, data sequences, or signatures within a process's memory. The `scan_range_finds...` tests are directly related to this.
    * **Understanding memory protection:**  Knowing if memory is readable, writable, or executable is vital for understanding how a program operates and for successful instrumentation. The `is_memory_readable...` and `mprotect_handles...` tests are pertinent.
    * **Memory allocation:** Frida might need to allocate memory within the target process for its own purposes (e.g., storing hooks or injected code). The `alloc_n_pages...` and `allocate_handles...` tests demonstrate these capabilities.

4. **Examine Code Snippets for Specific Examples:** Dive into individual `TESTCASE` functions to understand *how* the tests are performed. Look for key Frida Gum functions like `gum_memory_read`, `gum_memory_write`, `gum_memory_scan`, `gum_alloc_n_pages`, `gum_mprotect`, etc.

    * **Reading:** The `read_from_valid_address_should_succeed` test shows how to read a small block of memory using `gum_memory_read`. The test verifies the read data.
    * **Writing:** `write_to_valid_address_should_succeed` demonstrates writing to a memory location.
    * **Scanning:**  The `scan_range_finds...` tests use `gum_memory_scan` along with `gum_match_pattern_new_from_string` to locate byte sequences within a memory region. The callback function `match_found_cb` processes each match.
    * **Memory Protection:** `is_memory_readable_handles_mixed_page_protections` and `mprotect_handles_page_boundaries` illustrate how Frida interacts with and manipulates memory permissions.

5. **Identify Low-Level/Kernel Connections:** Look for clues suggesting interaction with the operating system's memory management:

    * **Page size:** The frequent use of `gum_query_page_size()` indicates awareness of the OS's memory page concept.
    * **Memory protection:** `gum_mprotect` directly corresponds to the `mprotect` system call on Linux (and similar functions on other OSes), which modifies page permissions.
    * **Memory allocation:** `gum_alloc_n_pages` likely relies on system calls like `mmap` or similar mechanisms for allocating memory. The "near" allocation likely interacts with OS features for hint-based allocation.
    * **Address alignment:** The tests for alignment highlight the importance of memory alignment at the hardware level.

6. **Infer Logical Reasoning and Assumptions:** Observe how the tests are structured. They often set up a specific memory state (e.g., writing known values), perform an operation, and then assert that the outcome is as expected. This demonstrates logical reasoning. For example, in the scanning tests, the expected addresses of the matches are pre-calculated.

7. **Anticipate User Errors:** Think about common mistakes developers might make when working with memory:

    * **Invalid addresses:** Trying to read or write to addresses that are not mapped or accessible. The `read_from_invalid_address_should_fail` and `write_to_invalid_address_should_fail` tests catch this.
    * **Incorrect sizes:** Specifying the wrong number of bytes to read or write. While not explicitly tested for *incorrect* size leading to crashes, the tests ensure correct size handling for valid operations.
    * **Alignment issues:**  While Frida seems to handle alignment for allocation, manually managing memory might lead to alignment errors.

8. **Trace User Actions to Reach the Code:** Consider how a user would interact with Frida to trigger the execution of these memory functions:

    * **Scripting:**  The most common way is through Frida's scripting API (JavaScript, Python). A user might write a script that uses functions like `Memory.readByteArray()`, `Memory.writeByteArray()`, `Memory.scanSync()`, or `Memory.alloc()`.
    * **CLI tools:** Frida's command-line tools might also internally use these memory functions. For instance, inspecting memory with `frida-ps -m`.
    * **Developer usage:** Developers contributing to Frida itself would be directly working with this C code and its API.

9. **Structure the Explanation:** Organize the findings into logical categories as requested by the prompt: functionalities, relationship to reverse engineering, low-level details, logical reasoning, user errors, and how to reach the code. Provide concrete examples from the code for each point.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This is just about memory reading and writing."
* **Correction:**  "No, it also includes memory scanning, allocation, and protection manipulation."
* **Initial thought:** "The regex scanning is just a string search."
* **Refinement:** "It's searching for byte patterns represented by a regex, which is more powerful than simple string matching in binary data."
* **Initial thought:** "User errors are hard to pinpoint in this low-level code."
* **Refinement:** "Focus on the types of errors the *tests* are designed to prevent or demonstrate, like accessing invalid memory."

By following these steps and continuously refining the understanding of the code, a comprehensive analysis can be produced.
这个C源代码文件是 Frida 动态 instrumentation 工具中 `frida-gum` 子项目的一部分，专门用于测试 Frida 的核心内存操作功能。它通过一系列单元测试来验证 `gummemory-priv.h` 中声明的内存管理 API 的正确性和健壮性。

以下是该文件列举的功能以及与逆向、底层知识、逻辑推理和用户错误相关的说明：

**功能列表:**

1. **读取内存:**
   - 从有效的内存地址读取数据并验证读取结果的正确性。
   - 尝试从无效的内存地址读取数据，并验证操作是否失败。
   - 从非对齐的内存地址读取数据，并验证读取结果的正确性。
   - 读取跨越两个内存页的数据，并验证读取结果的完整性。
   - 读取超出内存页边界的数据，并验证是否只返回部分数据。

2. **写入内存:**
   - 向有效的内存地址写入数据，并验证写入操作是否成功。
   - 尝试向无效的内存地址写入数据，并验证操作是否失败。

3. **内存模式匹配 (扫描):**
   - 使用字符串形式的精确模式匹配，在指定内存范围内查找匹配项。
   - 使用包含通配符的模式匹配，在指定内存范围内查找匹配项。
   - 使用带掩码的模式匹配，在指定内存范围内查找匹配项。
   - 使用正则表达式模式匹配，在指定内存范围内查找匹配项。

4. **检查内存可读性:**
   - 检查指定内存地址范围是否可读，并能正确处理具有不同保护属性的内存页。

5. **内存分配:**
   - 分配指定数量的内存页，并验证分配的地址是对齐的，且具有读写权限。
   - 在指定地址附近分配指定数量的内存页，并验证分配的地址在指定范围内且对齐，并具有读写权限。
   - 分配内存时处理对齐要求。
   - 在指定地址附近分配内存时处理对齐要求。

6. **修改内存保护属性 (mprotect):**
   - 修改内存页的保护属性，并能正确处理跨越内存页边界的情况。

**与逆向方法的关联及举例说明:**

* **读取内存:** 在逆向分析中，需要读取目标进程的内存来检查变量的值、函数的指令、数据结构等。例如，可以使用 Frida 脚本读取某个关键变量的值，以了解程序的状态：
  ```javascript
  // 假设 targetAddress 是目标变量的地址
  let value = Memory.readU32(ptr(targetAddress));
  console.log("Target variable value:", value);
  ```
  这个测试用例 `test_memory_read_from_valid_address_should_succeed` 验证了 Frida 的 `gum_memory_read` 函数可以正确读取内存，这正是逆向分析的基础操作。

* **写入内存:** 逆向工程师常常需要修改目标进程的内存，例如修改函数返回值、跳过某些指令、注入代码等。例如，可以修改一个函数的返回值来绕过某个安全检查：
  ```javascript
  // 假设 targetFunctionAddress 是目标函数的地址
  Interceptor.attach(ptr(targetFunctionAddress), {
    onLeave: function(retval) {
      retval.replace(1); // 将返回值替换为 1
    }
  });
  ```
  `test_memory_write_to_valid_address_should_succeed` 验证了 Frida 的 `gum_memory_write` 函数可以正确写入内存，这是动态修改程序行为的关键。

* **内存模式匹配 (扫描):**  在逆向工程中，常常需要在进程的内存中搜索特定的字节序列（例如，特定的指令序列、常量字符串、特征码）。例如，可以使用 Frida 脚本查找特定指令的位置：
  ```javascript
  Memory.scan(Process.memory[0].base, Process.memory[0].size, "E8 ?? ?? ?? ??", { // 查找 call 指令
    onMatch: function(address, size) {
      console.log("Found call instruction at:", address);
    },
    onComplete: function() {}
  });
  ```
  `test_memory_scan_range_finds_three_exact_matches` 等测试用例验证了 Frida 的内存扫描功能，这对于查找代码或数据非常有用。

* **检查内存可读性:** 在进行内存操作前，需要确认目标内存区域是否可读，避免程序崩溃。例如，在尝试读取某个指针指向的内存之前，可以先检查该地址是否有效且可读。`test_memory_is_memory_readable_handles_mixed_page_protections` 验证了 Frida 可以正确判断内存区域的可读性。

* **内存分配:** 当需要注入自定义代码或数据时，需要在目标进程中分配内存。Frida 提供了内存分配的功能。`test_memory_alloc_n_pages_returns_aligned_rw_address` 等测试用例验证了内存分配功能的正确性。

* **修改内存保护属性 (mprotect):**  为了执行注入的代码或修改只读内存，可能需要修改内存页的保护属性。例如，将代码段设置为可写以便进行 patch。`test_memory_mprotect_handles_page_boundaries` 验证了 Frida 修改内存保护属性的功能。

**涉及的二进制底层、Linux、Android内核及框架的知识及举例说明:**

* **内存页 (Page):** 测试用例中多次提到 "page" 和 `gum_query_page_size()`。这是操作系统内存管理的基本单位。Linux 和 Android 内核都使用分页机制管理内存。测试用例关注跨页读取、内存页边界的保护修改，体现了对操作系统内存管理机制的理解。

* **内存保护属性 (Memory Protection):**  `GUM_PAGE_RW`, `GUM_PAGE_NO_ACCESS` 等常量代表了内存页的保护属性，如可读、可写、可执行等。这些是操作系统提供的机制，用于控制对内存区域的访问权限。`gum_mprotect` 函数类似于 Linux 的 `mprotect` 系统调用，Android 也有类似的机制。`test_memory_is_memory_readable_handles_mixed_page_protections` 演示了 Frida 如何处理不同保护属性的内存页。

* **地址对齐 (Alignment):** 测试用例 `test_memory_alloc_n_pages_returns_aligned_rw_address` 和 `test_memory_allocate_handles_alignment` 强调了内存分配的地址对齐。在二进制层面，特定的数据类型或指令可能要求地址是特定值的倍数才能正确访问。

* **无效内存地址:** `test_memory_read_from_invalid_address_should_fail` 和 `test_memory_write_to_invalid_address_should_fail` 涉及操作系统如何处理访问无效内存地址的情况，这通常会导致 segmentation fault (SIGSEGV) 信号。

* **系统调用:** 虽然代码中没有直接调用系统调用，但像 `gum_alloc_n_pages` 和 `gum_mprotect` 这样的 Frida 函数底层很可能会调用操作系统提供的内存管理相关的系统调用，例如 Linux 的 `mmap`, `munmap`, `mprotect` 等。在 Android 上，可能涉及到 `mmap`, `munmap`, `mprotect` 或相关的 Binder 接口调用。

**逻辑推理及假设输入与输出:**

例如，对于 `test_memory_read_from_valid_address_should_succeed`:

* **假设输入:** 一个有效的内存地址 `magic` 指向包含字节 `0x13` 和 `0x37` 的内存区域，读取大小为 2 字节。
* **逻辑推理:**  Frida 的 `gum_memory_read` 函数应该能够成功读取这 2 个字节。
* **预期输出:**  返回一个包含 `0x13` 和 `0x37` 的内存缓冲区，并且读取的字节数 `n_bytes_read` 等于 2。

对于 `test_memory_scan_range_finds_three_exact_matches`:

* **假设输入:** 一个包含特定字节序列的缓冲区 `buf`，和一个要搜索的模式 "13 37"。
* **逻辑推理:** `gum_memory_scan` 函数应该在 `buf` 中找到三个匹配项。
* **预期输出:** `match_found_cb` 回调函数会被调用三次，每次调用的 `address` 参数分别对应 `buf` 中 "13 37" 出现的起始地址，`size` 参数为 2。

**涉及用户或者编程常见的使用错误及举例说明:**

* **读取或写入越界:** 用户可能错误地指定了要读取或写入的字节数，超出了实际分配的内存大小。虽然测试用例主要关注 Frida 内部的正确性，但用户使用 Frida API 时可能会犯这种错误。例如：
  ```javascript
  let buffer = Memory.alloc(10);
  Memory.writeByteArray(buffer, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  let data = Memory.readByteArray(buffer, 20); // 错误：尝试读取 20 字节，但只分配了 10 字节
  ```
  虽然 Frida 会尽力处理这些错误，但可能会导致程序崩溃或读取到不期望的数据。

* **使用无效的内存地址:** 用户可能使用了未映射或无权访问的内存地址。例如，尝试读取一个空指针或已释放的内存。测试用例 `test_memory_read_from_invalid_address_should_fail` 旨在验证 Frida 能够正确处理这种情况，但用户在编写 Frida 脚本时需要注意避免此类错误。

* **不正确的模式匹配字符串:** 在使用内存扫描功能时，用户可能提供了格式错误的模式匹配字符串，导致扫描失败或得到意外的结果。`test_memory_match_pattern_from_string_does_proper_validation` 验证了 Frida 对模式匹配字符串的校验，可以帮助用户尽早发现错误。

* **忘记释放分配的内存:** 如果用户使用 Frida 的内存分配功能，需要记得在不再使用时释放内存，否则可能导致内存泄漏。虽然这个测试文件没有直接测试内存泄漏，但内存管理是编程中常见的错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 开发者使用 Frida 的 JavaScript 或 Python API 来与目标进程交互。例如，他们可能编写了一个脚本来读取某个内存地址的值，或者搜索特定的内存模式。

2. **Frida 脚本执行:** 用户通过 Frida 的 CLI 工具（如 `frida`, `frida-ps`）或通过编程方式（使用 Frida 的 Python 绑定）执行他们编写的脚本。

3. **Frida-core 处理请求:** Frida 的核心组件 `frida-core` 接收到脚本的请求，例如读取内存的请求。

4. **frida-gum 介入:** `frida-core` 会调用 `frida-gum` 提供的内存管理 API 来执行实际的内存操作。例如，如果脚本请求读取内存，`frida-gum` 中的 `gum_memory_read` 函数会被调用。

5. **执行到 `memory.c` 中的代码:** 当 `gum_memory_read` 函数被调用时，如果出现了问题（例如，读取失败），或者开发者想要验证 `frida-gum` 的行为，他们可能会查看 `frida/subprojects/frida-gum/tests/core/memory.c` 这个测试文件，看看是否已经有相关的测试用例覆盖了这种情况，或者需要添加新的测试用例来重现和修复 bug。

6. **调试线索:** 测试用例可以作为调试线索，帮助开发者理解 Frida 内部的内存管理机制是如何工作的，以及在特定情况下会发生什么。例如，如果用户报告了无法从某个地址读取内存的问题，开发者可以查看 `test_memory_read_from_invalid_address_should_fail` 或相关的测试用例，来确认 Frida 是否按照预期处理了无效地址的情况。如果测试用例通过，那么问题可能出在用户提供的地址上；如果测试用例失败，那么说明 Frida 的内存读取功能存在 bug。

总而言之，`frida/subprojects/frida-gum/tests/core/memory.c` 是 Frida 内存管理功能的核心测试文件，它通过一系列细致的单元测试确保了 Frida 能够安全可靠地进行各种内存操作，这对于 Frida 作为动态 instrumentation 工具至关重要，并且与逆向工程实践紧密相关。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/memory.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2010-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "gummemory-priv.h"

#define TESTCASE(NAME) \
    void test_memory_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Memory", test_memory, NAME)

TESTLIST_BEGIN (memory)
  TESTENTRY (read_from_valid_address_should_succeed)
  TESTENTRY (read_from_invalid_address_should_fail)
  TESTENTRY (read_from_unaligned_address_should_succeed)
  TESTENTRY (read_across_two_pages_should_return_correct_data)
  TESTENTRY (read_beyond_page_should_return_partial_data)
  TESTENTRY (write_to_valid_address_should_succeed)
  TESTENTRY (write_to_invalid_address_should_fail)
  TESTENTRY (match_pattern_from_string_does_proper_validation)
  TESTENTRY (scan_range_finds_three_exact_matches)
  TESTENTRY (scan_range_finds_three_wildcarded_matches)
  TESTENTRY (scan_range_finds_three_masked_matches)
  TESTENTRY (scan_range_finds_three_regex_matches)
  TESTENTRY (is_memory_readable_handles_mixed_page_protections)
  TESTENTRY (alloc_n_pages_returns_aligned_rw_address)
  TESTENTRY (alloc_n_pages_near_returns_aligned_rw_address_within_range)
  TESTENTRY (allocate_handles_alignment)
  TESTENTRY (allocate_near_handles_alignment)
  TESTENTRY (mprotect_handles_page_boundaries)
TESTLIST_END ()

typedef struct _TestForEachContext {
  gboolean value_to_return;
  guint number_of_calls;

  gpointer expected_address[3];
  guint expected_size;
} TestForEachContext;

static gboolean match_found_cb (GumAddress address, gsize size,
    gpointer user_data);

TESTCASE (read_from_valid_address_should_succeed)
{
  guint8 magic[2] = { 0x13, 0x37 };
  gsize n_bytes_read;
  guint8 * result;

  result = gum_memory_read (magic, sizeof (magic), &n_bytes_read);
  g_assert_nonnull (result);

  g_assert_cmpuint (n_bytes_read, ==, sizeof (magic));

  g_assert_cmphex (result[0], ==, magic[0]);
  g_assert_cmphex (result[1], ==, magic[1]);

  g_free (result);
}

TESTCASE (read_from_invalid_address_should_fail)
{
  guint8 * invalid_address = GSIZE_TO_POINTER (0x42);
  g_assert_null (gum_memory_read (invalid_address, 1, NULL));
}

TESTCASE (read_from_unaligned_address_should_succeed)
{
  gpointer page;
  guint page_size;
  guint8 * last_byte;
  gsize n_bytes_read;
  guint8 * data;

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);
  page_size = gum_query_page_size ();

  last_byte = ((guint8 *) page) + page_size - 1;
  *last_byte = 42;
  data = gum_memory_read (last_byte, 1, &n_bytes_read);
  g_assert_nonnull (data);
  g_assert_cmpuint (n_bytes_read, ==, 1);
  g_assert_cmpuint (*data, ==, 42);
  g_free (data);

  gum_free_pages (page);
}

TESTCASE (read_across_two_pages_should_return_correct_data)
{
  GRand * rand;
  guint8 * pages;
  guint size, i, start_offset;
  gchar * expected_checksum, * actual_checksum;
  guint8 * data;
  gsize n_bytes_read;

  rand = g_rand_new_with_seed (42);
  pages = gum_alloc_n_pages (2, GUM_PAGE_RW);
  size = 2 * gum_query_page_size ();
  start_offset = (size / 2) - 1;
  for (i = start_offset; i != size; i++)
  {
    pages[i] = (guint8) g_rand_int_range (rand, 0, 255);
  }
  expected_checksum = g_compute_checksum_for_data (G_CHECKSUM_SHA1,
      pages + start_offset, size - start_offset);

  data = gum_memory_read (pages + start_offset, size - start_offset,
      &n_bytes_read);
  g_assert_nonnull (data);
  g_assert_cmpuint (n_bytes_read, ==, size - start_offset);
  actual_checksum =
      g_compute_checksum_for_data (G_CHECKSUM_SHA1, data, n_bytes_read);
  g_assert_cmpstr (actual_checksum, ==, expected_checksum);
  g_free (actual_checksum);
  g_free (data);

  g_free (expected_checksum);
  gum_free_pages (pages);
  g_rand_free (rand);
}

TESTCASE (read_beyond_page_should_return_partial_data)
{
  guint8 * page;
  guint page_size;
  gsize n_bytes_read;
  guint8 * data;

  page = gum_alloc_n_pages (2, GUM_PAGE_RW);
  page_size = gum_query_page_size ();
  gum_mprotect (page + page_size, page_size, GUM_PAGE_NO_ACCESS);

  data = gum_memory_read (page, 2 * page_size, &n_bytes_read);
  g_assert_nonnull (data);
  g_assert_cmpuint (n_bytes_read, ==, page_size);
  g_free (data);

  data = gum_memory_read (page + page_size - 1, 1 + page_size, &n_bytes_read);
  g_assert_nonnull (data);
  g_assert_cmpuint (n_bytes_read, ==, 1);
  g_free (data);

  gum_free_pages (page);
}

TESTCASE (write_to_valid_address_should_succeed)
{
  guint8 bytes[3] = { 0x00, 0x00, 0x12 };
  guint8 magic[2] = { 0x13, 0x37 };

  g_assert_true (gum_memory_write (bytes, magic, sizeof (magic)));

  g_assert_cmphex (bytes[0], ==, 0x13);
  g_assert_cmphex (bytes[1], ==, 0x37);
  g_assert_cmphex (bytes[2], ==, 0x12);
}

TESTCASE (write_to_invalid_address_should_fail)
{
  guint8 bytes[3] = { 0x00, 0x00, 0x12 };
  guint8 * invalid_address = GSIZE_TO_POINTER (0x42);
  g_assert_false (gum_memory_write (invalid_address, bytes, sizeof (bytes)));
}

#define GUM_PATTERN_NTH_TOKEN(p, n) \
    ((GumMatchToken *) g_ptr_array_index (gum_match_pattern_get_tokens (p), n))
#define GUM_PATTERN_NTH_TOKEN_NTH_BYTE(p, n, b) \
    (g_array_index (((GumMatchToken *) g_ptr_array_index ( \
        gum_match_pattern_get_tokens (p), n))->bytes, guint8, b))
#define GUM_PATTERN_NTH_TOKEN_NTH_MASK(p, n, b) \
    (g_array_index (((GumMatchToken *) g_ptr_array_index ( \
        gum_match_pattern_get_tokens (p), n))->masks, guint8, b))

TESTCASE (match_pattern_from_string_does_proper_validation)
{
  GumMatchPattern * pattern;

  pattern = gum_match_pattern_new_from_string ("1337");
  g_assert_nonnull (pattern);
  g_assert_cmpuint (gum_match_pattern_get_size (pattern), ==, 2);
  g_assert_cmpuint (gum_match_pattern_get_tokens (pattern)->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 2);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 1), ==, 0x37);
  gum_match_pattern_unref (pattern);

  pattern = gum_match_pattern_new_from_string ("13 37");
  g_assert_nonnull (pattern);
  g_assert_cmpuint (gum_match_pattern_get_size (pattern), ==, 2);
  g_assert_cmpuint (gum_match_pattern_get_tokens (pattern)->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 2);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 1), ==, 0x37);
  gum_match_pattern_unref (pattern);

  pattern = gum_match_pattern_new_from_string ("1 37");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("13 3");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("13+37");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("13 ?? 37");
  g_assert_nonnull (pattern);
  g_assert_cmpuint (gum_match_pattern_get_size (pattern), ==, 3);
  g_assert_cmpuint (gum_match_pattern_get_tokens (pattern)->len, ==, 3);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 1)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 1, 0), ==, 0x42);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 2)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 2, 0), ==, 0x37);
  gum_match_pattern_unref (pattern);

  pattern = gum_match_pattern_new_from_string ("13 ? 37");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("??");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("?? 13");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("13 ??");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string (" ");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("");
  g_assert_null (pattern);

  pattern = gum_match_pattern_new_from_string ("1337:ff0f");
  g_assert_nonnull (pattern);
  g_assert_cmpuint (gum_match_pattern_get_size (pattern), ==, 2);
  g_assert_cmpuint (gum_match_pattern_get_tokens (pattern)->len, ==, 2);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 1)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 1, 0), ==, 0x37);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_MASK (pattern, 1, 0), ==, 0x0f);
  gum_match_pattern_unref (pattern);

  pattern = gum_match_pattern_new_from_string ("13 37 : ff 0f");
  g_assert_nonnull (pattern);
  g_assert_cmpuint (gum_match_pattern_get_size (pattern), ==, 2);
  g_assert_cmpuint (gum_match_pattern_get_tokens (pattern)->len, ==, 2);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 1)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 1, 0), ==, 0x37);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_MASK (pattern, 1, 0), ==, 0x0f);
  gum_match_pattern_unref (pattern);

  pattern = gum_match_pattern_new_from_string ("13 ?7");
  g_assert_nonnull (pattern);
  g_assert_cmpuint (gum_match_pattern_get_size (pattern), ==, 2);
  g_assert_cmpuint (gum_match_pattern_get_tokens (pattern)->len, ==, 2);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 1)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 1, 0), ==, 0x47);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_MASK (pattern, 1, 0), ==, 0x0f);
  gum_match_pattern_unref (pattern);

  pattern = gum_match_pattern_new_from_string ("13 37 : ff");
  g_assert_null (pattern);
}

TESTCASE (scan_range_finds_three_exact_matches)
{
  guint8 buf[] = {
    0x13, 0x37,
    0x12,
    0x13, 0x37,
    0x13, 0x37
  };
  GumMemoryRange range;
  GumMatchPattern * pattern;
  TestForEachContext ctx;

  range.base_address = GUM_ADDRESS (buf);
  range.size = sizeof (buf);

  pattern = gum_match_pattern_new_from_string ("13 37");
  g_assert_nonnull (pattern);

  ctx.expected_address[0] = buf + 0;
  ctx.expected_address[1] = buf + 2 + 1;
  ctx.expected_address[2] = buf + 2 + 1 + 2;
  ctx.expected_size = 2;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_memory_scan (&range, pattern, match_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 3);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_memory_scan (&range, pattern, match_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  gum_match_pattern_unref (pattern);
}

TESTCASE (scan_range_finds_three_wildcarded_matches)
{
  guint8 buf[] = {
    0x12, 0x11, 0x13, 0x37,
    0x12, 0x00,
    0x12, 0xc0, 0x13, 0x37,
    0x12, 0x44, 0x13, 0x37
  };
  GumMemoryRange range;
  GumMatchPattern * pattern;
  TestForEachContext ctx;

  range.base_address = GUM_ADDRESS (buf);
  range.size = sizeof (buf);

  pattern = gum_match_pattern_new_from_string ("12 ?? 13 37");
  g_assert_nonnull (pattern);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;

  ctx.expected_address[0] = buf + 0;
  ctx.expected_address[1] = buf + 4 + 2;
  ctx.expected_address[2] = buf + 4 + 2 + 4;
  ctx.expected_size = 4;

  gum_memory_scan (&range, pattern, match_found_cb, &ctx);

  g_assert_cmpuint (ctx.number_of_calls, ==, 3);

  gum_match_pattern_unref (pattern);
}

TESTCASE (scan_range_finds_three_masked_matches)
{
  guint8 buf[] = {
    0x12, 0x11, 0x13, 0x35,
    0x12, 0x00,
    0x72, 0xc0, 0x13, 0x37,
    0xb2, 0x44, 0x13, 0x33
  };
  GumMemoryRange range;
  GumMatchPattern * pattern;
  TestForEachContext ctx;

  range.base_address = GUM_ADDRESS (buf);
  range.size = sizeof (buf);

  pattern = gum_match_pattern_new_from_string ("12 ?? 13 37 : 1f ff ff f1");
  g_assert_nonnull (pattern);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;

  ctx.expected_address[0] = buf + 0;
  ctx.expected_address[1] = buf + 4 + 2;
  ctx.expected_address[2] = buf + 4 + 2 + 4;
  ctx.expected_size = 4;

  gum_memory_scan (&range, pattern, match_found_cb, &ctx);

  g_assert_cmpuint (ctx.number_of_calls, ==, 3);

  gum_match_pattern_unref (pattern);
}

TESTCASE (scan_range_finds_three_regex_matches)
{
  gchar buf[] = "Brainfuck_OR_brainsuckANDbrainluck\nbrainmuck";
  GumMemoryRange range;
  GumMatchPattern * pattern;
  TestForEachContext ctx;

  range.base_address = GUM_ADDRESS (buf);
  range.size = sizeof (buf);

  pattern = gum_match_pattern_new_from_string ("/[Bb]rain[fsm]..k/");
  g_assert_nonnull (pattern);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;

  ctx.expected_address[0] = buf + 0;
  ctx.expected_address[1] = buf + sizeof ("Brainfuck_OR_") - 1;
  ctx.expected_address[2] = buf +
      sizeof ("Brainfuck_OR_brainsuckANDbrainluck\n") - 1;
  ctx.expected_size = 9;

  gum_memory_scan (&range, pattern, match_found_cb, &ctx);

  g_assert_cmpuint (ctx.number_of_calls, ==, 3);

  gum_match_pattern_unref (pattern);
}

TESTCASE (is_memory_readable_handles_mixed_page_protections)
{
  guint8 * pages;
  guint page_size;
  guint8 * left_guard, * first_page, * second_page, * right_guard;

  pages = gum_alloc_n_pages (4, GUM_PAGE_RW);

  page_size = gum_query_page_size ();

  left_guard = pages;
  first_page = left_guard + page_size;
  second_page = first_page + page_size;
  right_guard = second_page + page_size;

  gum_mprotect (left_guard, page_size, GUM_PAGE_NO_ACCESS);
  gum_mprotect (right_guard, page_size, GUM_PAGE_NO_ACCESS);

  g_assert_true (gum_memory_is_readable (first_page, 1));
  g_assert_true (gum_memory_is_readable (first_page + page_size - 1, 1));
  g_assert_true (gum_memory_is_readable (first_page, page_size));

  g_assert_true (gum_memory_is_readable (second_page, 1));
  g_assert_true (gum_memory_is_readable (second_page + page_size - 1, 1));
  g_assert_true (gum_memory_is_readable (second_page, page_size));

  g_assert_true (gum_memory_is_readable (first_page + page_size - 1, 2));
  g_assert_true (gum_memory_is_readable (first_page, 2 * page_size));

  g_assert_false (gum_memory_is_readable (second_page + page_size, 1));
  g_assert_false (gum_memory_is_readable (second_page + page_size - 1, 2));

  gum_free_pages (pages);
}

TESTCASE (alloc_n_pages_returns_aligned_rw_address)
{
  gpointer page;
  guint page_size;

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);

  page_size = gum_query_page_size ();

  g_assert_cmpuint (GPOINTER_TO_SIZE (page) % page_size, ==, 0);

  g_assert_true (gum_memory_is_readable (page, page_size));

  g_assert_cmpuint (*((gsize *) page), ==, 0);
  *((gsize *) page) = 42;
  g_assert_cmpuint (*((gsize *) page), ==, 42);

  gum_free_pages (page);
}

TESTCASE (alloc_n_pages_near_returns_aligned_rw_address_within_range)
{
  GumAddressSpec as;
  guint variable_on_stack;
  gpointer page;
  guint page_size;
  gsize actual_distance;

  as.near_address = &variable_on_stack;
  as.max_distance = G_MAXINT32;

  page = gum_try_alloc_n_pages_near (1, GUM_PAGE_RW, &as);
  if (page == NULL)
  {
    g_print ("<skipping, not supported on this system> ");
    return;
  }

  page_size = gum_query_page_size ();

  g_assert_cmpuint (GPOINTER_TO_SIZE (page) % page_size, ==, 0);

  g_assert_true (gum_memory_is_readable (page, page_size));

  g_assert_cmpuint (*((gsize *) page), ==, 0);
  *((gsize *) page) = 42;
  g_assert_cmpuint (*((gsize *) page), ==, 42);

  actual_distance = ABS ((guint8 *) page - (guint8 *) as.near_address);
  g_assert_cmpuint (actual_distance, <=, as.max_distance);

  gum_free_pages (page);
}

TESTCASE (allocate_handles_alignment)
{
  gsize size, alignment;
  gpointer page;

  size = gum_query_page_size ();
  alignment = 1024 * 1024;

  page = gum_memory_allocate (NULL, size, alignment, GUM_PAGE_RW);
  g_assert_nonnull (page);
  g_assert_cmpuint (GPOINTER_TO_SIZE (page) % alignment, ==, 0);

  gum_memory_free (page, size);
}

TESTCASE (allocate_near_handles_alignment)
{
  GumAddressSpec as;
  guint variable_on_stack;
  gsize size, alignment;
  gpointer page;

#if defined (HAVE_FREEBSD) && defined (HAVE_ARM64)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  as.near_address = &variable_on_stack;
  as.max_distance = G_MAXINT32;

  size = gum_query_page_size ();
  alignment = 1024 * 1024;

  page = gum_memory_allocate_near (&as, size, alignment, GUM_PAGE_RW);
  g_assert_nonnull (page);
  g_assert_cmpuint (GPOINTER_TO_SIZE (page) % alignment, ==, 0);

  gum_memory_free (page, size);
}

TESTCASE (mprotect_handles_page_boundaries)
{
  guint8 * pages;
  guint page_size;

  pages = gum_alloc_n_pages (2, GUM_PAGE_NO_ACCESS);
  page_size = gum_query_page_size ();

  gum_mprotect (pages + page_size - 1, 2, GUM_PAGE_RW);
  pages[page_size - 1] = 0x13;
  pages[page_size] = 0x37;

  gum_free_pages (pages);
}

static gboolean
match_found_cb (GumAddress address,
                gsize size,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  g_assert_cmpuint (ctx->number_of_calls, <, 3);

  g_assert_cmpuint (address, ==,
      GUM_ADDRESS (ctx->expected_address[ctx->number_of_calls]));
  g_assert_cmpuint (size, ==, ctx->expected_size);

  ctx->number_of_calls++;

  return ctx->value_to_return;
}
```