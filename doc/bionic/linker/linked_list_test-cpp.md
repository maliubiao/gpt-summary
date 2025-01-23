Response:
Let's break down the thought process for answering this complex request.

1. **Understanding the Core Request:** The central task is to analyze the `linked_list_test.cpp` file from Android's Bionic library and explain its functionality, its relation to Android, the implementation details of relevant libc and dynamic linker components, potential issues, and how to debug it.

2. **Initial Scan and Identification of Key Components:**  A quick read of the code reveals:
    * **Includes:** `<stdlib.h>`, `<string>`, `<sstream>`, `<gtest/gtest.h>`, `"linked_list.h"`. This immediately tells us it's a C++ unit test using Google Test, testing a custom linked list implementation.
    * **Namespace:** `namespace { ... }`. This indicates helper functions and classes specific to this test file, not part of the public API.
    * **`LinkedListTestAllocator`:** This custom allocator is crucial. It uses `malloc` and `free` but adds flags (`alloc_called`, `free_called`) for tracking allocation and deallocation within the tests. This suggests the tests are specifically designed to verify memory management.
    * **`test_list_t`:** A type alias for the linked list, parameterizing it with `const char*` and the custom allocator.
    * **`test_list_to_string`:** A helper function to convert the linked list to a string for easy assertion.
    * **`TEST(linked_list, ...)` blocks:**  These are the actual Google Test test cases covering various linked list operations.

3. **Deconstructing the Request into Sub-tasks:** To address all parts of the request systematically, I broke it down:

    * **Functionality:** Describe what the test file *does*.
    * **Relationship to Android:** How does this test file fit into the bigger picture of Android?
    * **libc Function Explanation:**  Focus on the libc functions used *within this test file* (`malloc`, `free`, `memset`, `strcmp`).
    * **Dynamic Linker:**  Since the file is under `bionic/linker`, the connection to the dynamic linker needs exploration, even if this specific *test file* doesn't directly interact with it. Think about *why* linked lists are important in the linker.
    * **Logic and Assumptions:**  Analyze the test cases themselves, considering the inputs and expected outputs.
    * **Common Usage Errors:**  Think about how a programmer might misuse a linked list.
    * **Android Framework/NDK Connection:** Explain how code like this eventually gets used by higher layers of Android.
    * **Frida Hooking:** Provide a practical example of how to inspect the behavior at runtime.

4. **Addressing Each Sub-task:**

    * **Functionality:**  Focus on the test cases: `simple`, `push_pop`, `remove_if_then_pop`, `remove_if_last_then_push_back`, `copy_to_array`, `test_visit`. Describe what each test case aims to verify (e.g., adding/removing elements, iterating, copying).

    * **Relationship to Android:** Emphasize that while this specific file *tests* the linked list, the linked list itself is a fundamental data structure used throughout Bionic, including the dynamic linker. This is a key connection.

    * **libc Functions:**  Explain the purpose of `malloc`, `free`, `memset`, and `strcmp` (or `ASSERT_STREQ` which internally uses string comparison). Crucially, explain *how* they might be implemented at a high level (e.g., `malloc` using system calls like `brk` or `mmap`).

    * **Dynamic Linker:**  Although the test file doesn't directly call linker functions, explain *why* the linker might use linked lists (managing loaded libraries, symbols, etc.). Provide a simplified SO layout example and briefly describe the linking process. *Acknowledge the test file's indirect connection.*

    * **Logic and Assumptions:**  Go through some of the test cases and explain the setup (input) and the `ASSERT_*` statements (expected output). For example, in the `simple` test, the input is a series of `push_front` and `remove_if` operations, and the output is verified using `ASSERT_EQ`.

    * **Common Usage Errors:** Consider typical linked list mistakes: memory leaks (forgetting to free), dangling pointers (accessing freed memory), null pointer dereferences (if `pop_front` returns `nullptr`).

    * **Android Framework/NDK Connection:**  Trace the path: NDK uses Bionic, Framework uses native libraries built with the NDK (or directly using Bionic). Give concrete examples like loading native libraries (`System.loadLibrary`).

    * **Frida Hooking:** Provide a simple Frida script that hooks `malloc` and `free` to track calls and potentially examine the allocated memory. Focus on practical debugging.

5. **Structuring the Answer:** Organize the information logically, using clear headings and bullet points for readability. Start with a high-level overview and then delve into the specifics.

6. **Refinement and Language:** Ensure the language is clear, concise, and accurate. Use appropriate technical terms but explain them if necessary. Since the request is in Chinese, ensure the translation is accurate and natural.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the dynamic linker because the file path contains "linker."
* **Correction:** Realize that this is *just a test file* for a generic linked list. While the linked list *is used* by the linker, this test file itself doesn't directly test linker functionality. Shift focus to the core linked list operations and how the custom allocator helps test memory management.
* **Initial thought:**  Deep dive into the intricate details of `malloc`'s implementation.
* **Correction:** Provide a high-level explanation of `malloc`'s function without getting bogged down in low-level details of different allocators. The focus should be on understanding *what* it does.
* **Ensuring Chinese Language Accuracy:**  Pay attention to translating technical terms correctly and ensuring the flow of the text is natural in Chinese.

By following this structured thought process, addressing each part of the request systematically, and making necessary refinements, a comprehensive and accurate answer can be generated.
好的，让我们来详细分析一下 `bionic/linker/linked_list_test.cpp` 这个文件。

**功能概述**

这个文件是一个 C++ 单元测试文件，用于测试 `bionic` 库中的 `linked_list.h` 头文件中定义的链表数据结构。它的主要功能是：

1. **验证链表基本操作的正确性:**  测试链表的插入（`push_front`, `push_back`）、删除（`remove_if`, `pop_front`, `clear`）、遍历（`for_each`, `visit`）、复制到数组（`copy_to_array`）等操作是否按预期工作。
2. **测试自定义内存分配器:**  这个测试使用了自定义的内存分配器 `LinkedListTestAllocator`，用于跟踪链表节点的分配和释放情况，确保内存管理的正确性。

**与 Android 功能的关系及举例**

虽然这个测试文件本身不是 Android 运行时直接使用的代码，但它测试的 `linked_list` 数据结构在 Android 的底层系统组件中被广泛使用，尤其是在动态链接器 `linker` 中。

**举例说明：动态链接器中的链表应用**

在 Android 的动态链接器中，链表被用于管理：

* **已加载的共享库（Shared Objects, SOs）:** 动态链接器需要跟踪已经加载到进程地址空间的共享库。可以使用链表来存储这些 SO 的信息，例如 SO 的路径、加载地址、依赖关系等。
* **全局符号表:**  动态链接器需要维护全局符号表，以便在不同的共享库之间解析符号引用。链表可以用来存储符号信息。
* **延迟加载的 SO:**  某些 SO 可能设置为延迟加载，只有在首次被使用时才加载。链表可以用来管理这些需要延迟加载的 SO。

**详细解释 libc 函数的功能实现**

这个测试文件中用到了以下 libc 函数：

1. **`malloc(size_t size)`:**
   * **功能:** 从堆上分配 `size` 字节大小的内存块。返回指向分配内存的指针。如果分配失败，返回 `NULL`。
   * **实现原理 (简化):**
     * `malloc` 通常会维护一个或多个空闲内存块的列表。
     * 当请求分配内存时，`malloc` 会在空闲列表中查找足够大的块。
     * 如果找到合适的块，它会将其分割成两部分：一部分分配给用户，另一部分（如果剩余空间足够大）仍然作为空闲块保留。
     * 如果找不到足够大的块，`malloc` 可能会调用系统调用（如 `brk` 或 `mmap`）来扩展堆空间。
     * 为了提高效率，`malloc` 可能会使用一些优化策略，例如合并相邻的空闲块。
   * **测试文件中的使用:** `LinkedListTestAllocator::alloc()` 中调用 `::malloc(sizeof(entry_t))` 来为链表节点分配内存。

2. **`free(void* ptr)`:**
   * **功能:** 释放之前通过 `malloc`、`calloc` 或 `realloc` 分配的内存块。`ptr` 必须是指向已分配内存块的指针，否则行为未定义。
   * **实现原理 (简化):**
     * `free` 接收指向要释放的内存块的指针。
     * 它会将该内存块标记为空闲，并将其添加回空闲内存块的列表。
     * `free` 可能会检查要释放的内存块是否与相邻的空闲块相邻，如果是，则将它们合并成一个更大的空闲块。
   * **测试文件中的使用:** `LinkedListTestAllocator::free(entry_t* p)` 中调用 `::free(p)` 来释放链表节点占用的内存。

3. **`memset(void* ptr, int value, size_t num)`:**
   * **功能:** 将 `ptr` 指向的内存块的前 `num` 个字节设置为 `value`（被转换为 `unsigned char`）。
   * **实现原理 (通常通过汇编优化):**
     * `memset` 通常会以字（word）或更大的单位进行批量填充，以提高效率。
     * 具体的实现会根据不同的架构进行优化，例如使用 SIMD 指令。
   * **测试文件中的使用:** `TEST(linked_list, copy_to_array)` 中使用 `memset(buf, 0, sizeof(buf))` 将数组 `buf` 初始化为 0。

4. **`strcmp(const char* str1, const char* str2)`:** (虽然代码中没有直接调用，但 `ASSERT_STREQ` 内部使用了字符串比较)
   * **功能:** 比较字符串 `str1` 和 `str2`。
   * **返回值:**
     * 如果 `str1` 等于 `str2`，则返回 0。
     * 如果 `str1` 小于 `str2`，则返回负值。
     * 如果 `str1` 大于 `str2`，则返回正值。
   * **实现原理:**
     * `strcmp` 从字符串的第一个字符开始逐个比较，直到遇到不同的字符或字符串的结尾。
     * 字符的比较是基于它们的 ASCII 值或其他字符编码。
   * **测试文件中的使用:** `ASSERT_STREQ("a", list.pop_front())` 等断言内部会使用字符串比较来验证弹出的元素是否符合预期。

**涉及 dynamic linker 的功能、SO 布局样本和链接处理过程**

虽然这个测试文件测试的是通用的链表数据结构，但由于它位于 `bionic/linker` 目录下，我们可以推断这个链表可能会在动态链接器的实现中使用。

**SO 布局样本**

假设我们有一个简单的共享库 `libtest.so`，它可能具有以下布局：

```
libtest.so:
  .text         # 代码段
  .rodata       # 只读数据段
  .data         # 可读写数据段
  .bss          # 未初始化数据段
  .symtab       # 符号表
  .strtab       # 字符串表
  .dynsym       # 动态符号表
  .dynstr       # 动态字符串表
  .plt          # 程序链接表 (Procedure Linkage Table)
  .got          # 全局偏移表 (Global Offset Table)
  ...
```

**链接的处理过程 (简化)**

1. **加载 SO:** 当程序需要使用 `libtest.so` 中的符号时，动态链接器会将 `libtest.so` 加载到进程的地址空间。
2. **符号解析:**
   * 当程序调用 `libtest.so` 中的函数时，编译器会生成对该函数的符号引用。
   * 动态链接器会查找 `libtest.so` 的 `.dynsym` 段（动态符号表）来找到该符号的地址。
   * 如果该符号在 `libtest.so` 中定义，则解析成功。
   * 如果该符号未在 `libtest.so` 中定义，动态链接器会继续在其他已加载的共享库中查找。
3. **重定位:**
   * 共享库在编译时并不知道最终的加载地址。
   * 动态链接器会根据实际的加载地址修改代码和数据段中的地址引用，这个过程称为重定位。
   * `.plt` 和 `.got` 段在延迟绑定中起着关键作用。首次调用外部函数时，会跳转到 `.plt` 中的一段代码，该代码会调用动态链接器来解析符号并更新 `.got` 表中的地址。后续调用将直接通过 `.got` 表跳转到目标地址。

**链表在动态链接器中的应用举例:**

动态链接器可以使用链表来管理已加载的共享库：

* 每个链表节点可能存储一个 `dl_phdr_info` 结构，包含共享库的加载地址、大小、程序头等信息。
* 当加载新的 SO 时，会创建一个新的链表节点并添加到链表中。
* 当卸载 SO 时，会从链表中移除对应的节点。
* 在符号解析过程中，动态链接器可能需要遍历这个链表来查找包含目标符号的 SO。

**逻辑推理、假设输入与输出**

让我们看一个 `linked_list_test.cpp` 中的测试用例：

```c++
TEST(linked_list, simple) {
  alloc_called = free_called = false;
  test_list_t list;
  ASSERT_EQ("", test_list_to_string(list)); // 假设输入：空链表
  ASSERT_TRUE(!alloc_called);
  ASSERT_TRUE(!free_called);
  list.push_front("a"); // 假设输入：添加元素 "a"
  ASSERT_TRUE(alloc_called); // 预期输出：alloc_called 为 true
  ASSERT_TRUE(!free_called); // 预期输出：free_called 为 false
  ASSERT_EQ("a", test_list_to_string(list)); // 预期输出：链表内容为 "a"
  // ... 更多操作
}
```

在这个 `simple` 测试用例中：

* **假设输入:**  首先创建一个空的链表。然后依次向链表头部添加字符串 "a", "b", "c", "d"。之后，尝试移除字符串 "c"。
* **逻辑推理:**
    * 创建空链表时，不应该调用内存分配函数。
    * 每次向链表添加元素时，应该调用内存分配函数为新的节点分配内存。
    * 移除元素时，如果找到匹配的元素，应该调用内存释放函数释放对应的节点内存。
    * `test_list_to_string` 函数会将链表中的元素连接成一个字符串，以便进行比较。
* **预期输出:**  在每一步操作后，通过 `ASSERT_*` 断言来验证程序的行为是否符合预期，例如：
    * `ASSERT_EQ("", test_list_to_string(list))`：初始时链表为空字符串。
    * `ASSERT_TRUE(alloc_called)`：在 `push_front("a")` 后，内存分配器被调用。
    * `ASSERT_EQ("dcba", test_list_to_string(list))`：在多次 `push_front` 后，链表内容为 "dcba"。
    * `ASSERT_TRUE(free_called)`：在 `remove_if` 移除 "c" 后，内存释放器被调用。
    * `ASSERT_EQ("dba", test_list_to_string(list))`：移除 "c" 后，链表内容为 "dba"。

**用户或编程常见的使用错误**

1. **内存泄漏:**  如果在使用链表后没有正确地释放节点占用的内存，会导致内存泄漏。例如，忘记调用 `clear()` 或者手动遍历并释放每个节点。
2. **悬挂指针:**  在释放链表节点后，仍然尝试访问该节点的数据，会导致悬挂指针错误，程序可能会崩溃或产生不可预测的行为。
3. **空指针解引用:**  在链表为空时，尝试访问 `pop_front()` 返回的 `nullptr`，会导致空指针解引用错误。
4. **迭代器失效:**  在遍历链表的过程中修改链表的结构（例如插入或删除节点），可能会导致迭代器失效，从而引发错误。
5. **忘记处理空链表的情况:**  在编写操作链表的代码时，需要考虑链表为空的情况，避免出现错误。

**Android Framework or NDK 如何一步步到达这里**

1. **NDK (Native Development Kit):**  Android NDK 允许开发者使用 C 和 C++ 等原生语言编写代码。
2. **Bionic 库:**  NDK 提供的 C/C++ 标准库实现就是 Bionic。当你使用 NDK 编译原生代码时，你的代码会链接到 Bionic 提供的库，包括 `libc` (C 标准库) 和 `libm` (数学库)，以及动态链接器。
3. **动态链接器 (`linker` 或 `linker64`):**  当 Android 系统启动一个使用 NDK 开发的应用程序时，操作系统会加载应用程序的可执行文件。在加载过程中，动态链接器负责加载应用程序依赖的共享库 (SOs)，包括 Bionic 提供的库和其他第三方库。
4. **链表的使用:**  动态链接器内部使用链表来管理已加载的共享库、符号表等数据结构。

**具体的路径示例:**

假设你的 NDK 应用加载了一个名为 `mylibrary.so` 的共享库，并且 `mylibrary.so` 依赖于 Bionic 提供的某些库。

1. **应用启动:** 当你的应用启动时，Zygote 进程会 fork 出一个新的进程来运行你的应用。
2. **加载器调用:**  新进程的加载器（通常是 `linker` 或 `linker64`）会被调用。
3. **解析依赖:**  加载器会解析 `mylibrary.so` 的依赖关系，发现它依赖于 Bionic 的库。
4. **加载 Bionic 库:**  加载器会加载 Bionic 提供的共享库，例如 `libc.so`、`libm.so` 等。在这个过程中，动态链接器内部可能会使用链表来管理这些已加载的库。
5. **符号解析和重定位:**  加载器会解析 `mylibrary.so` 中对 Bionic 库中符号的引用，并进行重定位。

**Frida Hook 示例调试**

你可以使用 Frida 来 hook `linked_list_test.cpp` 中使用的 `malloc` 和 `free` 函数，以观察内存分配和释放的情况。

```python
import frida

# 目标进程，假设编译后运行的测试程序名为 linked_list_test
process_name = "linked_list_test"

session = frida.attach(process_name)

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "malloc"), {
  onEnter: function(args) {
    var size = args[0].toInt3d();
    console.log("[malloc] Size: " + size);
  },
  onLeave: function(retval) {
    console.log("[malloc] Returned: " + retval);
  }
});

Interceptor.attach(Module.findExportByName(null, "free"), {
  onEnter: function(args) {
    var ptr = args[0];
    console.log("[free] Pointer: " + ptr);
  }
});
""")

script.load()
input() # Keep the script running
```

**使用方法:**

1. **编译 `linked_list_test.cpp`:** 你需要先将 `linked_list_test.cpp` 编译成可执行文件。这通常涉及到使用 Android 的构建系统 (如 `AOSP build system` 或 `CMake`)。
2. **运行测试程序:**  将编译后的可执行文件 push 到 Android 设备上，并通过 adb shell 运行它。
3. **运行 Frida 脚本:** 在你的电脑上运行上面的 Python Frida 脚本。确保你的设备上已经安装了 Frida server。
4. **观察输出:** 当测试程序运行时，Frida 脚本会拦截对 `malloc` 和 `free` 的调用，并在控制台上打印相关的参数和返回值，你可以观察内存分配和释放的具体情况。

这个 Frida 示例可以帮助你理解在运行链表测试时，内存是如何被分配和释放的。你可以进一步扩展这个脚本，例如记录分配的内存地址，并在 `free` 时进行匹配，以更详细地跟踪内存管理。

希望这个详细的解答能够帮助你理解 `bionic/linker/linked_list_test.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/linker/linked_list_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdlib.h>
#include <string>
#include <sstream>

#include <gtest/gtest.h>

#include "linked_list.h"

namespace {

bool alloc_called = false;
bool free_called = false;

class LinkedListTestAllocator {
 public:
  typedef LinkedListEntry<const char> entry_t;

  static entry_t* alloc() {
    alloc_called = true;
    return reinterpret_cast<entry_t*>(::malloc(sizeof(entry_t)));
  }

  static void free(entry_t* p) {
    free_called = true;
    ::free(p);
  }
 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(LinkedListTestAllocator);
};

typedef LinkedList<const char, LinkedListTestAllocator> test_list_t;

std::string test_list_to_string(test_list_t& list) {
  std::stringstream ss;
  list.for_each([&] (const char* c) {
    ss << c;
  });

  return ss.str();
}

};

TEST(linked_list, simple) {
  alloc_called = free_called = false;
  test_list_t list;
  ASSERT_EQ("", test_list_to_string(list));
  ASSERT_TRUE(!alloc_called);
  ASSERT_TRUE(!free_called);
  list.push_front("a");
  ASSERT_TRUE(alloc_called);
  ASSERT_TRUE(!free_called);
  ASSERT_EQ("a", test_list_to_string(list));
  list.push_front("b");
  ASSERT_EQ("ba", test_list_to_string(list));
  list.push_front("c");
  list.push_front("d");
  ASSERT_EQ("dcba", test_list_to_string(list));
  ASSERT_TRUE(alloc_called);
  ASSERT_TRUE(!free_called);
  alloc_called = free_called = false;
  list.remove_if([] (const char* c) {
    return *c == 'c';
  });

  ASSERT_TRUE(!alloc_called);
  ASSERT_TRUE(free_called);

  ASSERT_EQ("dba", test_list_to_string(list));
  alloc_called = free_called = false;
  list.remove_if([] (const char* c) {
    return *c == '2';
  });
  ASSERT_TRUE(!alloc_called);
  ASSERT_TRUE(!free_called);
  ASSERT_EQ("dba", test_list_to_string(list));
  list.clear();
  ASSERT_TRUE(!alloc_called);
  ASSERT_TRUE(free_called);
  ASSERT_EQ("", test_list_to_string(list));
}

TEST(linked_list, push_pop) {
  test_list_t list;
  list.push_front("b");
  list.push_front("a");
  ASSERT_EQ("ab", test_list_to_string(list));
  list.push_back("c");
  ASSERT_EQ("abc", test_list_to_string(list));
  ASSERT_STREQ("a", list.pop_front());
  ASSERT_EQ("bc", test_list_to_string(list));
  ASSERT_STREQ("b", list.pop_front());
  ASSERT_EQ("c", test_list_to_string(list));
  ASSERT_STREQ("c", list.pop_front());
  ASSERT_EQ("", test_list_to_string(list));
  ASSERT_TRUE(list.pop_front() == nullptr);
  list.push_back("r");
  ASSERT_EQ("r", test_list_to_string(list));
  ASSERT_STREQ("r", list.pop_front());
  ASSERT_TRUE(list.pop_front() == nullptr);
}

TEST(linked_list, remove_if_then_pop) {
  test_list_t list;
  list.push_back("a");
  list.push_back("b");
  list.push_back("c");
  list.push_back("d");
  list.remove_if([](const char* c) {
    return *c == 'b' || *c == 'c';
  });

  ASSERT_EQ("ad", test_list_to_string(list));
  ASSERT_STREQ("a", list.pop_front());
  ASSERT_EQ("d", test_list_to_string(list));
  ASSERT_STREQ("d", list.pop_front());
  ASSERT_TRUE(list.pop_front() == nullptr);
}

TEST(linked_list, remove_if_last_then_push_back) {
  test_list_t list;

  list.push_back("a");
  list.push_back("b");
  list.push_back("c");
  list.push_back("d");

  list.remove_if([](const char* c) {
    return *c == 'c' || *c == 'd';
  });

  ASSERT_EQ("ab", test_list_to_string(list));
  list.push_back("d");
  ASSERT_EQ("abd", test_list_to_string(list));
}

TEST(linked_list, copy_to_array) {
  test_list_t list;
  const size_t max_size = 128;
  const char* buf[max_size];
  memset(buf, 0, sizeof(buf));

  ASSERT_EQ(0U, list.copy_to_array(buf, max_size));
  ASSERT_EQ(nullptr, buf[0]);

  list.push_back("a");
  list.push_back("b");
  list.push_back("c");
  list.push_back("d");

  memset(buf, 0, sizeof(buf));
  ASSERT_EQ(2U, list.copy_to_array(buf, 2));
  ASSERT_STREQ("a", buf[0]);
  ASSERT_STREQ("b", buf[1]);
  ASSERT_EQ(nullptr, buf[2]);

  ASSERT_EQ(4U, list.copy_to_array(buf, max_size));
  ASSERT_STREQ("a", buf[0]);
  ASSERT_STREQ("b", buf[1]);
  ASSERT_STREQ("c", buf[2]);
  ASSERT_STREQ("d", buf[3]);
  ASSERT_EQ(nullptr, buf[4]);

  memset(buf, 0, sizeof(buf));
  list.remove_if([](const char* c) {
    return *c != 'c';
  });
  ASSERT_EQ(1U, list.copy_to_array(buf, max_size));
  ASSERT_STREQ("c", buf[0]);
  ASSERT_EQ(nullptr, buf[1]);

  memset(buf, 0, sizeof(buf));

  list.remove_if([](const char* c) {
    return *c == 'c';
  });

  ASSERT_EQ(0U, list.copy_to_array(buf, max_size));
  ASSERT_EQ(nullptr, buf[0]);
}

TEST(linked_list, test_visit) {
  test_list_t list;
  list.push_back("a");
  list.push_back("b");
  list.push_back("c");
  list.push_back("d");

  int visits = 0;
  std::stringstream ss;
  bool result = list.visit([&](const char* c) {
    ++visits;
    ss << c;
    return true;
  });

  ASSERT_TRUE(result);
  ASSERT_EQ(4, visits);
  ASSERT_EQ("abcd", ss.str());

  visits = 0;
  ss.str(std::string());

  result = list.visit([&](const char* c) {
    if (++visits == 3) {
      return false;
    }

    ss << c;
    return true;
  });

  ASSERT_TRUE(!result);
  ASSERT_EQ(3, visits);
  ASSERT_EQ("ab", ss.str());
}
```