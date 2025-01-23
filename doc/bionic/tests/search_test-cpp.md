Response:
The user wants a detailed explanation of the C++ source code file `bionic/tests/search_test.cpp` within the Android Bionic library. They are asking for a breakdown of its functionality, its relation to Android, in-depth explanations of the libc functions tested, details about dynamic linking if applicable, logical reasoning with input/output examples, common usage errors, and how the Android framework/NDK reaches this code, including a Frida hook example.

Here's a plan to address each of these points:

1. **Functionality of the test file:** Summarize what the tests in the file are doing. It's testing various search and data structure functions provided by the C standard library.

2. **Relationship to Android:** Explain that Bionic is Android's standard C library. The tests ensure these core functionalities work correctly on Android.

3. **Detailed explanation of libc functions:** For each tested function (`lfind`, `lsearch`, `tfind`, `tsearch`, `twalk`, `tdestroy`, `tdelete`, `insque`, `remque`, `hcreate`, `hsearch`, `hdestroy`, `hcreate_r`, `hsearch_r`, `hdestroy_r`), provide a description of what it does, its parameters, and return values.

4. **Dynamic linker aspects:** The provided code doesn't directly test dynamic linking functionality. Mention this.

5. **Logical reasoning with input/output:** For each test case, explain the sequence of operations and the expected outcomes (assertions). This serves as the input/output example.

6. **Common usage errors:**  Provide examples of how developers might misuse the tested functions, leading to errors or unexpected behavior.

7. **Android framework/NDK path:** Describe the general flow of how an Android application using these libc functions would eventually trigger this code (during testing). It involves the NDK providing access to these standard C library functions, which are implemented by Bionic. Mention that these specific tests are run as part of the Bionic library's development and verification process, not directly by user applications.

8. **Frida hook example:**  Show how to use Frida to hook one of the functions being tested, demonstrating how to intercept calls and examine parameters.

**Mental Sandbox Simulation:**

* **`lfind_lsearch` test:**  This is straightforward. Simulate adding an element with `lsearch` and then finding it with `lfind`. Test the case where the element isn't present.
* **`tfind_tsearch_twalk_tdestroy` test:** Simulate building a binary search tree, traversing it, and then destroying it.
* **`tdestroy_null` test:**  A simple test for handling null input.
* **`tdelete` test:** Simulate adding and deleting a node from a tree. Highlight the potential memory leak.
* **`insque_remque` test:**  Simulate adding and removing elements from a doubly-linked list, both linearly and circularly.
* **`hcreate_hsearch_hdestroy` test:** Simulate creating a hash table, adding, finding, and updating entries.
* **`hcreate_r_hsearch_r_hdestroy_r` test:** Similar to the previous hash table test but using the reentrant versions.
* **`hsearch_resizing` test:**  Tests the hash table's resizing behavior.

**Self-Correction/Refinement:**

* The initial request asks about dynamic linking. The code doesn't directly test dynamic linking. Clarify that these are standard C library functions and not directly related to the dynamic linker's operation *in this test*. However, Bionic itself *is* the dynamic linker, so it's crucial to mention Bionic's role.
* For the Frida hook, choose a simple function like `lfind` or `lsearch` for ease of demonstration.
* Ensure the language is clear and technically accurate.

By following this plan and incorporating the self-corrections, I can generate a comprehensive and accurate response to the user's request.
这个文件 `bionic/tests/search_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试 C 标准库中与搜索和数据结构相关的函数。由于 Bionic 是 Android 的基础 C 库，这些测试确保了这些核心功能在 Android 平台上的正确性和稳定性。

**它的功能：**

该文件的主要功能是针对以下 C 标准库函数编写单元测试：

* **线性搜索函数:**
    * `lfind()`: 在线性搜索中查找与给定键匹配的元素。
    * `lsearch()`: 在线性搜索中查找元素，如果找不到则将其添加到数组末尾。
* **二叉搜索树函数:**
    * `tfind()`: 在二叉搜索树中查找节点。
    * `tsearch()`: 在二叉搜索树中插入节点。
    * `twalk()`: 遍历二叉搜索树，并对每个节点执行指定的操作。
    * `tdestroy()`: 删除二叉搜索树，并对每个节点执行指定的操作（通常用于释放节点内存）。
    * `tdelete()`: 从二叉搜索树中删除节点。
* **队列操作函数:**
    * `insque()`: 在双向链表中插入节点。
    * `remque()`: 从双向链表中移除节点。
* **哈希表函数:**
    * `hcreate()`: 创建哈希表。
    * `hsearch()`: 在哈希表中查找或插入条目。
    * `hdestroy()`: 销毁哈希表。
    * `hcreate_r()`: 创建线程安全的哈希表。
    * `hsearch_r()`: 在线程安全的哈希表中查找或插入条目。
    * `hdestroy_r()`: 销毁线程安全的哈希表。

**与 Android 功能的关系及举例说明：**

Bionic 提供的这些函数是 Android 系统和应用程序的基础构建块。许多 Android 的核心功能都依赖于这些数据结构和搜索操作。

* **系统服务:** Android 的各种系统服务（例如，PackageManagerService, ActivityManagerService）可能使用哈希表来高效地存储和查找组件信息（例如，已安装的应用程序、正在运行的进程）。 `hcreate`/`hsearch` 等函数就用于实现这些哈希表。
* **NDK 开发:** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的一部分。NDK 应用可以直接调用这些 Bionic 提供的标准 C 库函数。例如，一个游戏可能使用二叉搜索树 (`tsearch`/`tfind`) 来管理游戏对象或 AI 决策。
* **底层库:** Android 的其他底层库和框架也可能使用这些函数。例如，一个音频解码器可能使用某种查找表来实现高效的音频采样率转换。
* **文件系统:** 某些文件系统的实现或相关工具可能会用到搜索功能来查找文件或目录。

**详细解释每一个 libc 函数的功能是如何实现的：**

由于您要求详细解释 *如何实现*，这通常涉及到查看 Bionic 的源代码。这里提供概念性的解释，不涉及具体的 Bionic 源码实现细节：

* **`lfind(key, base, nmemb, size, compar)` 和 `lsearch(key, base, nmemb, size, compar)`:**
    * **功能:** 这两个函数都在由 `base` 指向的数组中进行线性搜索，查找与 `key` 指向的元素匹配的元素。 `nmemb` 是数组中元素的数量，`size` 是每个元素的大小，`compar` 是比较函数。`lsearch` 如果找不到匹配项，会将 `key` 的副本添加到数组末尾，并更新 `nmemb` 指向的值。
    * **实现:**  它们通常通过遍历数组中的每个元素，并使用提供的比较函数 `compar` 将当前元素与 `key` 进行比较来实现。如果比较函数返回 0，则表示找到匹配项。`lsearch` 的额外步骤是在未找到时分配内存（如果需要）并将 `key` 复制到数组末尾。

* **`tfind(key, rootp, compar)` 和 `tsearch(key, rootp, compar)`:**
    * **功能:** 这两个函数操作二叉搜索树。 `rootp` 是指向树根节点指针的指针，`key` 是要查找或插入的元素的指针，`compar` 是比较函数。 `tfind` 查找与 `key` 匹配的节点，如果找到则返回指向该节点的指针，否则返回 `NULL`。 `tsearch` 尝试插入 `key`，如果树中已存在匹配的节点，则返回指向该现有节点的指针；否则，它会创建一个新节点并将 `key` 复制到其中，然后将新节点插入到树中，并返回指向新节点的指针。
    * **实现:**  `tfind` 从根节点开始，根据 `compar` 函数的返回值，决定是向左子树还是右子树搜索。`tsearch` 的实现类似，但在找不到匹配项时，会分配新节点，将数据复制进去，并根据比较结果将新节点连接到树的相应位置。可能涉及到树的旋转等操作以维持树的平衡（虽然标准 `tsearch` 不保证平衡，但实际实现可能会有优化）。

* **`twalk(root, action)`:**
    * **功能:**  对二叉搜索树进行遍历，并对每个节点调用 `action` 指向的函数。遍历的顺序由 `action` 函数的第二个参数 `order` 指示（前序、中序、后序或叶节点）。
    * **实现:**  通常使用递归或栈来实现树的遍历。 `action` 函数会在遍历到每个节点时被调用，并接收节点指针、遍历顺序和节点深度作为参数。

* **`tdestroy(root, freefcn)`:**
    * **功能:** 删除以 `root` 为根的二叉搜索树，并对每个节点调用 `freefcn` 指向的函数，通常用于释放节点占用的内存。
    * **实现:**  通常使用后序遍历来删除节点，以确保先删除子节点再删除父节点。对于每个访问到的节点，调用 `freefcn` 来释放节点的内存。

* **`tdelete(key, rootp, compar)`:**
    * **功能:** 从以 `*rootp` 为根的二叉搜索树中删除与 `key` 匹配的节点。
    * **实现:**  需要先找到要删除的节点。然后根据该节点是否有子节点以及子节点的数量，执行不同的删除操作。可能需要找到待删除节点的后继节点或前驱节点来替换被删除的节点，并调整树的结构以保持二叉搜索树的性质。

* **`insque(elem, prev)` 和 `remque(elem)`:**
    * **功能:** 这两个函数用于操作双向链表。 `insque` 将 `elem` 指向的元素插入到 `prev` 指向的元素之后。如果 `prev` 为 `NULL`，则将 `elem` 插入到链表的头部。 `remque` 从链表中移除 `elem` 指向的元素。
    * **实现:** `insque` 需要更新 `elem` 的 `next` 和 `prev` 指针，以及 `prev` 节点的 `next` 指针和 `prev` 的下一个节点的 `prev` 指针。 `remque` 需要更新被移除节点的前一个节点的 `next` 指针和后一个节点的 `prev` 指针，从而将该节点从链表中解链。

* **`hcreate(nel)` 和 `hdestroy()`:**
    * **功能:** `hcreate` 创建一个可以容纳至少 `nel` 个条目的哈希表。 `hdestroy` 销毁之前通过 `hcreate` 创建的哈希表并释放其占用的内存。
    * **实现:** `hcreate` 通常会分配一个数组作为哈希表的桶（buckets），并进行必要的初始化。哈希表的大小可能基于 `nel` 进行调整。 `hdestroy` 会遍历哈希表的桶，释放每个条目的键和值（如果需要），然后释放桶数组本身。

* **`hsearch(item, action)`:**
    * **功能:** 在哈希表中查找或插入条目。 `item` 是一个 `ENTRY` 结构，包含要查找或插入的键和数据。 `action` 可以是 `FIND` 或 `ENTER`。如果 `action` 是 `FIND`，则在哈希表中查找与 `item.key` 匹配的条目。如果 `action` 是 `ENTER`，则将 `item` 插入到哈希表中。如果键已存在，`ENTER` 会返回现有条目的指针。
    * **实现:** `hsearch` 首先使用一个哈希函数计算 `item.key` 的哈希值，然后使用该哈希值确定条目应该放在哪个桶中。
        * 对于 `FIND`，它会在相应的桶中线性搜索匹配的键。
        * 对于 `ENTER`，如果键不存在，它会在桶中创建一个新的 `ENTRY` 并将 `item` 的内容复制进去。如果键已存在，则返回现有条目的指针。  处理哈希冲突的方式有很多种，例如链地址法（每个桶维护一个链表）或开放寻址法。

* **`hcreate_r(nel, ht)` 和 `hdestroy_r(ht)`:**
    * **功能:**  与 `hcreate` 和 `hdestroy` 类似，但这些是线程安全（reentrant）的版本，使用用户提供的 `hsearch_data` 结构 `ht` 来存储哈希表的状态。这允许多个线程安全地操作不同的哈希表。
    * **实现:**  与非线程安全版本类似，但所有与哈希表状态相关的数据都存储在 `ht` 指向的结构中，避免了使用全局变量，从而实现线程安全。

* **`hsearch_r(item, action, retval, ht)`:**
    * **功能:**  线程安全的哈希表查找和插入操作。 `retval` 是一个指向 `ENTRY` 指针的指针，用于返回找到的条目或新插入的条目。 `ht` 是指向 `hsearch_data` 结构的指针。
    * **实现:**  与 `hsearch` 类似，但使用 `ht` 指向的哈希表数据结构。由于是线程安全的，其内部实现可能需要使用互斥锁或其他同步机制来保护哈希表的数据结构，防止并发访问导致的数据竞争。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个测试文件中的函数是 C 标准库函数，它们通常由 `libc.so` 提供，而不是动态链接器本身的功能。动态链接器（在 Android 上是 `linker` 或 `linker64`）负责加载共享库 (`.so` 文件) 并解析符号引用。

**so 布局样本 (以 `libc.so` 为例):**

```
libc.so:
    .interp        # 指向动态链接器的路径
    .note.android.ident
    .plt            # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
    .got.plt        # 全局偏移表 (Global Offset Table)，用于存储全局符号的地址
    .text           # 代码段，包含函数实现
        lfind: ...
        lsearch: ...
        tfind: ...
        ...
    .rodata         # 只读数据段，包含字符串常量等
    .data           # 可读写数据段，包含全局变量
    .bss            # 未初始化数据段
    .dynamic        # 动态链接信息
        NEEDED libc++.so  # 依赖的其他共享库
        SONAME libc.so
        ...
    .symtab         # 符号表，包含导出的和导入的符号信息
        lfind
        lsearch
        tfind
        ...
    .strtab         # 字符串表，存储符号名称等字符串
    .hash           # 哈希表，用于快速查找符号
    ...
```

**链接的处理过程：**

1. **加载：** 当一个应用程序或共享库需要使用 `libc.so` 中的函数时，动态链接器会在启动时或运行时加载 `libc.so` 到进程的地址空间。
2. **符号查找：** 当代码中调用 `lfind` 等函数时，编译器和链接器会在生成可执行文件或共享库时生成对这些符号的引用。
3. **重定位：** 动态链接器会根据 `libc.so` 在内存中的实际加载地址，更新 `.got.plt` 中的条目。
4. **延迟绑定 (对于 PLT/GOT 机制):**
   - 第一次调用 `lfind` 时，会跳转到 `.plt` 中的一个桩代码。
   - 这个桩代码会将控制权交给动态链接器。
   - 动态链接器在 `libc.so` 的符号表中查找 `lfind` 的实际地址。
   - 动态链接器将 `lfind` 的地址写入 `.got.plt` 中对应的条目。
   - 然后，动态链接器将控制权转移到 `lfind` 的实际地址。
   - 后续对 `lfind` 的调用会直接通过 `.got.plt` 跳转到 `lfind` 的地址，避免了每次都调用动态链接器，提高了性能。

**逻辑推理，假设输入与输出：**

以 `lsearch` 为例：

**假设输入：**

* `key`: 指向整数值 5 的指针。
* `base`: 指向一个已包含整数 `[1, 3, 7]` 的数组的指针。
* `nmemb`: 指向值为 3 的 `size_t` 变量的指针。
* `size`: 整数类型的大小 (例如，4 字节)。
* `compar`: 一个比较函数，如果第一个参数小于第二个参数返回负数，相等返回 0，大于返回正数。

**输出：**

* `lsearch` 返回指向数组中新插入元素 (值为 5) 的指针。
* `nmemb` 指向的值变为 4。
* `base` 指向的数组变为 `[1, 3, 7, 5]` (顺序取决于比较函数的实现)。

**常见的使用错误：**

* **`lfind` 和 `lsearch`:**
    * **未初始化 `nmemb`:**  `lsearch` 需要 `nmemb` 指示当前数组的大小。如果未正确初始化，`lsearch` 可能会写入非法内存。
    * **比较函数错误:**  比较函数必须严格遵循其规范，否则搜索结果可能不正确。
    * **`base` 指针为空:**  会导致段错误。
    * **`lsearch` 假设数组有足够的空间:** 如果数组已满，`lsearch` 可能会写入超出数组边界的内存。
* **二叉搜索树函数:**
    * **比较函数不一致:**  在树的整个生命周期内，比较函数必须保持一致。
    * **忘记释放内存:** 使用 `tsearch` 插入的节点通常需要手动释放或使用 `tdestroy` 释放。`tdelete` 只删除节点，不负责释放节点本身占用的内存（示例代码中的 `tdelete` 测试就展示了这一点）。
    * **对 `twalk` 的 `action` 函数处理不当:** `action` 函数不应修改树的结构，否则可能导致未定义的行为。
* **哈希表函数:**
    * **忘记调用 `hcreate`:**  在调用 `hsearch` 之前必须先调用 `hcreate` 初始化哈希表。
    * **哈希表大小估计不足:** 如果插入的元素数量超过 `hcreate` 中指定的初始大小，哈希表的性能可能会下降。
    * **内存泄漏:**  使用 `hsearch` (ENTER) 插入的 `key` 和 `data` 的内存由用户管理，需要适时释放。`hdestroy` 只释放哈希表本身的结构，不释放条目的 `key` 和 `data`。
    * **非线程安全地使用 `hcreate`/`hsearch`/`hdestroy`:** 在多线程环境中使用这些函数可能导致数据竞争。应该使用 `hcreate_r`/`hsearch_r`/`hdestroy_r`。

**Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码，并在代码中调用例如 `lsearch`。
2. **编译和链接:** NDK 的工具链（例如，clang, ld）会将 C/C++ 代码编译成机器码，并将对 `lsearch` 的调用链接到 Bionic 提供的 `libc.so`。
3. **应用程序安装:**  包含原生代码的 APK 安装到 Android 设备上。
4. **应用程序启动:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会加载应用程序所需的共享库，包括 `libc.so`。
5. **符号解析和重定位:** 动态链接器解析应用程序中对 `lsearch` 的符号引用，并将其重定位到 `libc.so` 中 `lsearch` 函数的实际地址。
6. **函数调用:** 当应用程序执行到调用 `lsearch` 的代码时，程序会跳转到 Bionic 的 `lsearch` 实现。

**Frida hook 示例：**

假设我们要 hook `lsearch` 函数，以查看其参数和返回值。

```python
import frida
import sys

package_name = "your.application.package.name"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "lsearch"), {
    onEnter: function(args) {
        console.log("[*] lsearch called");
        console.log("    key:", args[0]);
        console.log("    base:", args[1]);
        console.log("    nmemb:", args[2].readU32());
        console.log("    size:", args[3].readU32());
        // 假设 compar 函数是简单的整数比较
        // console.log("    compar return:", Memory.readS32(ptr(args[4]).readPointer()));
    },
    onLeave: function(retval) {
        console.log("[*] lsearch returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释：**

1. **导入 Frida 库。**
2. **指定要 hook 的应用程序的包名。**
3. **`on_message` 函数用于处理 Frida 发送的消息。**
4. **连接到 USB 设备上的目标应用程序进程。**
5. **Frida 脚本代码：**
   - `Interceptor.attach`:  用于拦截函数调用。
   - `Module.findExportByName("libc.so", "lsearch")`: 找到 `libc.so` 中导出的 `lsearch` 函数。
   - `onEnter`:  在 `lsearch` 函数入口处执行。
     - `args`:  包含了传递给 `lsearch` 的参数。
     - `args[0]` 到 `args[3]` 分别对应 `key`, `base`, `nmemb`, `size`。
     - `args[2].readU32()` 和 `args[3].readU32()` 用于读取指针指向的内存中的值。
   - `onLeave`: 在 `lsearch` 函数返回时执行。
     - `retval`: 包含了 `lsearch` 函数的返回值。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到用户输入。**

运行此 Frida 脚本，当目标应用程序调用 `lsearch` 函数时，你将在控制台上看到 `lsearch` 的参数值和返回值，从而帮助你调试和理解代码的执行流程。

请注意，hook 涉及与目标进程的交互，可能需要 root 权限或在调试模式下运行的应用程序。

### 提示词
```
这是目录为bionic/tests/search_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <search.h>

#include "utils.h"

static int int_cmp(const void* lhs, const void* rhs) {
  return *reinterpret_cast<const int*>(rhs) - *reinterpret_cast<const int*>(lhs);
}

TEST(search, lfind_lsearch) {
  int xs[10];
  memset(xs, 0, sizeof(xs));
  size_t x_size = 0;

  int needle;

  // lfind(3) can't find '2' in the empty table.
  needle = 2;
  ASSERT_EQ(nullptr, lfind(&needle, xs, &x_size, sizeof(xs[0]), int_cmp));
  ASSERT_EQ(0U, x_size);

  // lsearch(3) will add it.
  ASSERT_EQ(&xs[0], lsearch(&needle, xs, &x_size, sizeof(xs[0]), int_cmp));
  ASSERT_EQ(2, xs[0]);
  ASSERT_EQ(1U, x_size);

  // And then lfind(3) can find it.
  ASSERT_EQ(&xs[0], lfind(&needle, xs, &x_size, sizeof(xs[0]), int_cmp));
  ASSERT_EQ(1U, x_size);

  // Inserting a duplicate does nothing (but returns the existing element).
  ASSERT_EQ(&xs[0], lsearch(&needle, xs, &x_size, sizeof(xs[0]), int_cmp));
  ASSERT_EQ(1U, x_size);
}

struct node {
  explicit node(const char* s) : s(strdup(s)) {}

  char* s;
};

static int node_cmp(const void* lhs, const void* rhs) {
  return strcmp(reinterpret_cast<const node*>(lhs)->s, reinterpret_cast<const node*>(rhs)->s);
}

static std::vector<std::string> g_nodes;

static void node_walk(const void* p, VISIT order, int) {
  const node* n = *reinterpret_cast<const node* const*>(p);
  if (order == postorder || order == leaf)  {
    g_nodes.push_back(n->s);
  }
}

static size_t g_free_calls;

static void node_free(void* p) {
  node* n = reinterpret_cast<node*>(p);
  free(n->s);
  ++g_free_calls;
}

TEST(search, tfind_tsearch_twalk_tdestroy) {
  void* root = nullptr;

  node n1("z");
  node n2("a");
  node n3("m");

  // tfind(3) can't find anything in the empty tree.
  ASSERT_EQ(nullptr, tfind(&n1, &root, node_cmp));
  ASSERT_EQ(nullptr, tfind(&n2, &root, node_cmp));
  ASSERT_EQ(nullptr, tfind(&n3, &root, node_cmp));

  // tsearch(3) inserts and returns a pointer to a new node.
  void* i1 = tsearch(&n1, &root, node_cmp);
  ASSERT_NE(nullptr, i1);

  // ...which tfind(3) will then return.
  ASSERT_EQ(i1, tfind(&n1, &root, node_cmp));
  ASSERT_EQ(nullptr, tfind(&n2, &root, node_cmp));
  ASSERT_EQ(nullptr, tfind(&n3, &root, node_cmp));

  // Add the other nodes.
  ASSERT_NE(nullptr, tsearch(&n2, &root, node_cmp));
  ASSERT_NE(nullptr, tsearch(&n3, &root, node_cmp));

  // Use twalk(3) to iterate over the nodes.
  g_nodes.clear();
  twalk(root, node_walk);
  ASSERT_EQ(3U, g_nodes.size());
  ASSERT_EQ("a", g_nodes[0]);
  ASSERT_EQ("m", g_nodes[1]);
  ASSERT_EQ("z", g_nodes[2]);

  // tdestroy(3) removes nodes under a node, calling our callback to destroy each one.
  g_free_calls = 0;
  tdestroy(root, node_free);
  ASSERT_EQ(3U, g_free_calls);
}

TEST(search, tdestroy_null) {
  // It's okay to pass a null node, and your callback will not be called.
  tdestroy(nullptr, nullptr);
}

struct pod_node {
  explicit pod_node(int i) : i(i) {}
  int i;
};

static int pod_node_cmp(const void* lhs, const void* rhs) {
  return reinterpret_cast<const pod_node*>(rhs)->i - reinterpret_cast<const pod_node*>(lhs)->i;
}

TEST(search, tdelete) {
  void* root = nullptr;

  pod_node n1(123);
  ASSERT_NE(nullptr, tsearch(&n1, &root, pod_node_cmp));

  // tdelete(3) leaks n1.
  pod_node not_there(456);
  ASSERT_EQ(nullptr, tdelete(&not_there, &root, pod_node_cmp));
  ASSERT_NE(nullptr, tdelete(&n1, &root, pod_node_cmp));
}

struct q_node {
  explicit q_node(int i) : i(i) {}

  q_node* next;
  q_node* prev;

  int i;
};

TEST(search, insque_remque) {
  q_node zero(0);
  q_node one(1);
  q_node two(2);

  // Linear (not circular).

  insque(&zero, nullptr);
  insque(&one, &zero);
  insque(&two, &one);

  int expected = 0;
  for (q_node* q = &zero; q != nullptr; q = q->next) {
    ASSERT_EQ(expected, q->i);
    ++expected;
  }
  ASSERT_EQ(3, expected);

  for (q_node* q = &two; q != nullptr; q = q->prev) {
    --expected;
    ASSERT_EQ(expected, q->i);
  }
  ASSERT_EQ(0, expected);

  q_node* head = &zero;

  remque(&one);
  ASSERT_EQ(0, head->i);
  ASSERT_EQ(2, head->next->i);
  ASSERT_EQ(nullptr, head->next->next);

  remque(&two);
  ASSERT_EQ(0, head->i);
  ASSERT_EQ(nullptr, head->next);

  remque(&zero);

  // Circular.

  zero.next = &zero;
  zero.prev = &zero;

  insque(&one, &zero);
  insque(&two, &one);

  ASSERT_EQ(0, head->i);
  ASSERT_EQ(1, head->next->i);
  ASSERT_EQ(2, head->next->next->i);
  ASSERT_EQ(0, head->next->next->next->i);
  ASSERT_EQ(1, head->next->next->next->next->i);
  ASSERT_EQ(2, head->next->next->next->next->next->i);

  remque(&one);
  ASSERT_EQ(0, head->i);
  ASSERT_EQ(2, head->next->i);
  ASSERT_EQ(0, head->next->next->i);
  ASSERT_EQ(2, head->next->next->next->i);

  remque(&two);
  ASSERT_EQ(0, head->i);
  ASSERT_EQ(0, head->next->i);

  remque(&zero);
}

static void AssertEntry(ENTRY* e, const char* expected_key, const char* expected_data) {
  ASSERT_TRUE(e != nullptr);
  ASSERT_STREQ(expected_key, reinterpret_cast<char*>(e->key));
  ASSERT_STREQ(expected_data, reinterpret_cast<char*>(e->data));
}

TEST(search, hcreate_hsearch_hdestroy) {
  ASSERT_NE(0, hcreate(13));

  // Add some initial entries.
  ENTRY* e;
  e = hsearch(ENTRY{.key = const_cast<char*>("a"), .data = const_cast<char*>("A")}, ENTER);
  AssertEntry(e, "a", "A");
  e = hsearch(ENTRY{.key = const_cast<char*>("aa"), .data = const_cast<char*>("B")}, ENTER);
  AssertEntry(e, "aa", "B");
  e = hsearch(ENTRY{.key = const_cast<char*>("aaa"), .data = const_cast<char*>("C")}, ENTER);
  AssertEntry(e, "aaa", "C");

  // Check missing.
  e = hsearch(ENTRY{.key = const_cast<char*>("aaaa"), .data = nullptr}, FIND);
  ASSERT_FALSE(e != nullptr);

  // Check present.
  e = hsearch(ENTRY{.key = const_cast<char*>("aa"), .data = nullptr}, FIND);
  AssertEntry(e, "aa", "B");

  // ENTER with an existing key just returns the existing ENTRY.
  e = hsearch(ENTRY{.key = const_cast<char*>("aa"), .data = const_cast<char*>("X")}, ENTER);
  AssertEntry(e, "aa", "B");
  e->data = const_cast<char*>("X");

  // Check present and updated.
  e = hsearch(ENTRY{.key = const_cast<char*>("aa"), .data = nullptr}, FIND);
  AssertEntry(e, "aa", "X");
  // But other entries stayed the same.
  e = hsearch(ENTRY{.key = const_cast<char*>("a"), .data = nullptr}, FIND);
  AssertEntry(e, "a", "A");
  e = hsearch(ENTRY{.key = const_cast<char*>("aaa"), .data = nullptr}, FIND);
  AssertEntry(e, "aaa", "C");

  hdestroy();
}

TEST(search, hcreate_r_hsearch_r_hdestroy_r) {
  hsearch_data h1 = {};
  ASSERT_EQ(1, hcreate_r(13, &h1));

  hsearch_data h2 = {};
  ASSERT_EQ(1, hcreate_r(128, &h2));

  // Add some initial entries.
  ENTRY* e;
  ASSERT_EQ(1, hsearch_r(ENTRY{.key = const_cast<char*>("a"), .data = const_cast<char*>("A")},
                         ENTER, &e, &h1));
  AssertEntry(e, "a", "A");
  ASSERT_EQ(1, hsearch_r(ENTRY{.key = const_cast<char*>("a"), .data = const_cast<char*>("B")},
                         ENTER, &e, &h2));
  AssertEntry(e, "a", "B");

  // Check missing.
  errno = 0;
  ASSERT_EQ(0, hsearch_r(ENTRY{.key = const_cast<char*>("b"), .data = nullptr}, FIND, &e, &h1));
  ASSERT_ERRNO(ESRCH);

  // Check present.
  ASSERT_EQ(1, hsearch_r(ENTRY{.key = const_cast<char*>("a"), .data = nullptr}, FIND, &e, &h1));
  AssertEntry(e, "a", "A");
  ASSERT_EQ(1, hsearch_r(ENTRY{.key = const_cast<char*>("a"), .data = nullptr}, FIND, &e, &h2));
  AssertEntry(e, "a", "B");

  // Destroying one doesn't affect the other.
  hdestroy_r(&h1);
  ASSERT_EQ(1, hsearch_r(ENTRY{.key = const_cast<char*>("a"), .data = nullptr}, FIND, &e, &h2));
  AssertEntry(e, "a", "B");
  hdestroy_r(&h2);
}

TEST(search, hsearch_resizing) {
  ASSERT_NE(0, hcreate(1));

  std::vector<char*> entries;
  // Add enough entries to ensure that we've had to resize.
  for (char ch = ' '; ch <= '~'; ++ch) {
    char* p;
    asprintf(&p, "%c", ch);
    ENTRY e;
    e.data = e.key = p;
    ASSERT_TRUE(hsearch(e, ENTER) != nullptr);
    entries.push_back(p);
  }

  // Check they're all there.
  for (auto& p : entries) {
    ENTRY* e = hsearch(ENTRY{.key = p, .data = nullptr}, FIND);
    AssertEntry(e, p, p);
  }

  for (auto& p : entries) free(p);
}
```