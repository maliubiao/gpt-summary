Response:
Let's break down the thought process for analyzing this `search.h` header file.

**1. Initial Understanding & Keyword Extraction:**

* **Purpose:** The header file is `search.h` and located in `bionic/libc/include/`. This immediately signals that it's part of Android's C library and deals with searching and data structures. The brief description confirms this: "Queues, hash tables, trees, and linear array searches."
* **Key Data Structures/Algorithms:**  The comments and function names clearly point to:
    * Queues (doubly-linked lists): `insque`, `remque`
    * Hash Tables: `hcreate`, `hdestroy`, `hsearch`, and their reentrant versions (`_r`)
    * Trees: `tdelete`, `tdestroy`, `tfind`, `tsearch`, `twalk`
    * Linear Array Search: `lfind`, `lsearch`
* **Key Concepts:**  The presence of `ACTION` (FIND/ENTER) and `VISIT` (preorder, inorder, endorder, leaf) enums, along with `ENTRY` struct, further clarifies the context of hash table and tree operations.
* **Android Context:** The mention of "bionic" and the availability guards (`__BIONIC_AVAILABILITY_GUARD`) and `__INTRODUCED_IN` indicate that the functions have specific Android API level dependencies.

**2. Categorization of Functionality:**

It's helpful to group the functions by the data structure they operate on:

* **Queue Operations:** `insque`, `remque`
* **Hash Table Operations:** `hcreate`, `hdestroy`, `hsearch`, `hcreate_r`, `hdestroy_r`, `hsearch_r`
* **Tree Operations:** `tdelete`, `tdestroy`, `tfind`, `tsearch`, `twalk`
* **Linear Array Search:** `lfind`, `lsearch`

**3. Detailed Analysis of Each Function Group:**

For each group, the process involves:

* **Understanding the Core Function:** Reading the descriptive comments (especially the `[function_name(3)]` links, which point to man pages).
* **Identifying Key Parameters:** Understanding what each parameter represents (e.g., `__key`, `__array`, `__comparator`).
* **Noting Return Values:**  Understanding what a successful or failed return indicates.
* **Considering Reentrancy:**  Recognizing the `_r` versions of hash table functions and their significance for multi-threading.
* **Linking to Android:** Thinking about how these generic data structures and algorithms are used within the Android framework and by NDK developers.
* **Identifying Potential Errors:**  Considering common mistakes developers might make when using these functions.

**4. Addressing Specific Prompts in the Request:**

* **Functionality Listing:** This is a straightforward summary of the identified function groups.
* **Android Relevance & Examples:** This requires some domain knowledge about Android development. Thinking about system services, resource management, and native code interactions helps in generating relevant examples.
* **Detailed Implementation Explanation:** This is where the request becomes challenging *without the source code*. The strategy here is to describe the *general* implementation principles of each data structure/algorithm. For example, explaining how a hash table uses a hash function and collision resolution, or how a binary search tree is structured and searched. *Acknowledge the lack of actual source for precise details.*
* **Dynamic Linker Aspects:**  This requires understanding how shared libraries (`.so` files) are loaded and linked in Android. The key is to explain the role of the dynamic linker in resolving symbols and the general structure of an `.so` file. A sample layout helps illustrate this.
* **Logical Reasoning (Assumptions and Outputs):**  For each function, think of a simple scenario and predict the outcome. This helps demonstrate understanding of the function's behavior.
* **Common Usage Errors:** Based on experience or by thinking about the potential pitfalls of each function (e.g., memory management, incorrect comparators).
* **Android Framework/NDK Usage & Frida Hooking:** This involves tracing the execution path from the Android application level down to the native libraries. The key is to illustrate how framework components or NDK code might eventually call these C library functions. Providing a Frida hook example makes the debugging process concrete.

**5. Structuring the Output:**

Organize the information logically, using clear headings and bullet points. This makes the response easier to read and understand. Start with a general overview and then delve into the specifics of each function or concept.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus solely on the function descriptions.
* **Correction:** Realize the importance of linking the functions to Android context and providing concrete examples.
* **Initial thought:**  Try to guess the exact implementation details of each function.
* **Correction:** Acknowledge the limitation of not having the source code and focus on general principles and common implementations.
* **Initial thought:**  Provide overly technical details about dynamic linking.
* **Correction:**  Keep the explanation at a level understandable to a broader audience, focusing on the key concepts of symbol resolution and shared library structure.

By following this structured approach, even without the underlying C code, a comprehensive and informative analysis of the header file can be generated. The key is to leverage the provided comments, understand the standard C library functions, and connect them to the Android ecosystem.
## 对 bionic/libc/include/search.handroid 中 `search.h` 文件的功能分析

`bionic/libc/include/search.handroid/search.h` 是 Android Bionic C 库中的一个头文件，它定义了一些用于实现常见搜索和数据结构操作的函数。这些功能包括队列操作、哈希表操作、二叉树操作以及线性搜索。

**功能列表:**

该文件定义了以下功能，可以大致分为几类：

1. **队列操作 (Intrusive Doubly-Linked Lists):**
   - `insque(void* __element, void* __previous)`: 将一个元素插入到队列中。
   - `remque(void* __element)`: 从队列中移除一个元素。

2. **哈希表操作:**
   - `hcreate(size_t __n)`: 初始化全局哈希表，预留至少 `__n` 个元素的空间 (API level 28 及以上)。
   - `hdestroy(void)`: 销毁全局哈希表 (API level 28 及以上)。
   - `hsearch(ENTRY __entry, ACTION __action)`: 在全局哈希表中查找或插入条目 (API level 28 及以上)。
   - `hcreate_r(size_t __n, struct hsearch_data* __table)`: 初始化一个哈希表 `__table`，预留至少 `__n` 个元素的空间 (API level 28 及以上)。
   - `hdestroy_r(struct hsearch_data* __table)`: 销毁哈希表 `__table` (API level 28 及以上)。
   - `hsearch_r(ENTRY __entry, ACTION __action, ENTRY* * __result, struct hsearch_data* __table)`: 在哈希表 `__table` 中查找或插入条目 (API level 28 及以上)。

3. **二叉树操作:**
   - `tdelete(const void* __key, void* * __root_ptr, int (* __comparator)(const void*, const void*))`: 在二叉树 `*__root_ptr` 中查找并删除一个元素。
   - `tdestroy(void* __root, void (* __free_fn)(void*))`: 销毁二叉树 `__root`，并对每个节点调用 `__free_fn` 进行清理。
   - `tfind(const void* __key, void* const* __root_ptr, int (* __comparator)(const void*, const void*))`: 在二叉树 `*__root_ptr` 中查找一个元素。
   - `tsearch(const void* __key, void* * __root_ptr, int (* __comparator)(const void*, const void*))`: 在二叉树 `*__root_ptr` 中查找一个元素，如果找不到则插入。
   - `twalk(const void* __root, void (* __visitor)(const void*, VISIT, int))`: 遍历二叉树 `__root` 的每个节点，并调用 `__visitor` 函数。

4. **线性搜索:**
   - `lfind(const void* __key, const void* __array, size_t* __count, size_t __size, int (* __comparator)(const void*, const void*))`: 在未排序数组 `__array` 中查找 `__key`。
   - `lsearch(const void* __key, void* __array, size_t* __count, size_t __size, int (* __comparator)(const void*, const void*))`: 在未排序数组 `__array` 中查找 `__key`，如果找不到则将其插入到数组末尾。

**与 Android 功能的关系及举例说明:**

这些函数虽然是底层的 C 库函数，但它们在 Android 框架和 NDK 开发中被广泛使用，用于实现各种数据管理和查找功能。

* **队列操作 (`insque`, `remque`):**
    - **Android Framework:**  例如，Android 的事件循环机制中，消息队列可能会使用类似的链表结构来管理待处理的消息。虽然 Bionic 可能不直接使用 `insque` 和 `remque`，但这些函数体现了链表操作的基本思想，而链表是构建消息队列的常用数据结构。
    - **NDK:**  开发者在编写 Native 代码时，如果需要维护一个任务队列或者事件队列，可以使用这些函数或者基于这些思想实现自己的队列。

* **哈希表操作 (`hcreate`, `hdestroy`, `hsearch`, `hcreate_r`, `hdestroy_r`, `hsearch_r`):**
    - **Android Framework:**  哈希表在 Android 中被大量使用，例如用于存储系统服务 (Service Manager 使用哈希表来映射服务名称和服务 Binder 对象)，资源查找 (资源 ID 到实际资源的映射)，以及各种缓存实现。
        - **例子:** Service Manager 维护着一个全局的哈希表，键是服务的名称字符串，值是对应的 Binder 接口。当应用程序需要获取一个系统服务时，它会通过 Service Manager 的接口，Service Manager 内部会使用类似 `hsearch` 的函数来查找对应的服务。
    - **NDK:**  NDK 开发者可以使用这些函数来高效地实现键值对的存储和查找。例如，在游戏开发中，可以使用哈希表来存储游戏对象的属性，以便快速访问。

* **二叉树操作 (`tdelete`, `tdestroy`, `tfind`, `tsearch`, `twalk`):**
    - **Android Framework:**  二叉树（特别是平衡二叉树，例如红黑树）常用于需要高效查找和排序的场景。例如，Linux 内核中的文件系统索引 (如 inode 树) 就使用了类似的结构。虽然 Bionic 提供的接口是普通的二叉树，但其思想在 Android 底层仍然有应用。
    - **NDK:**  开发者在需要维护有序数据集合并进行高效查找时，可以使用这些函数。例如，在一个图形引擎中，可以使用二叉树来管理场景中的对象，根据它们的深度进行排序，以便进行正确的渲染。

* **线性搜索 (`lfind`, `lsearch`):**
    - **Android Framework:**  当数据量较小或者数据无需排序时，线性搜索是一种简单的选择。例如，在某些配置信息的查找中，如果配置项的数量不多，可能会使用线性搜索。
    - **NDK:**  NDK 开发者在处理小型数组或列表时，可以使用这些函数进行查找。例如，在一个简单的配置解析器中，可以使用 `lfind` 来查找特定的配置项。

**libc 函数的实现解释:**

* **`insque(void* __element, void* __previous)` 和 `remque(void* __element)`:**
    - **`insque`:**  假设每个要加入队列的元素都包含指向前一个和后一个元素的指针。`insque` 函数会将 `__element` 的“next”指针指向 `__previous` 的下一个元素，并将 `__previous` 的下一个元素的“prev”指针指向 `__element`。然后，将 `__element` 的“prev”指针指向 `__previous`，并将 `__previous` 的“next”指针指向 `__element`。 这就完成了在 `__previous` 之后插入 `__element` 的操作。
    - **`remque`:**  `remque` 函数通过修改被移除元素的前一个和后一个元素的指针来完成移除操作。它会将 `__element` 的前一个元素的“next”指针指向 `__element` 的后一个元素，并将 `__element` 的后一个元素的“prev”指针指向 `__element` 的前一个元素。

* **`hcreate(size_t __n)` 和 `hcreate_r(size_t __n, struct hsearch_data* __table)`:**
    - 这些函数负责分配和初始化哈希表。它们会根据 `__n` 估算需要分配的桶（bucket）的数量，并分配相应的内存。  初始化过程可能包括将所有桶置为空。`_r` 版本是线程安全的，因为它操作的是用户提供的 `hsearch_data` 结构，避免了全局状态的竞争。
    - **实现细节:** 通常使用数组来实现哈希表，每个数组元素是一个桶，可以存储一个或多个条目（通过链表或其他方式解决冲突）。哈希函数将键映射到桶的索引。

* **`hdestroy(void)` 和 `hdestroy_r(struct hsearch_data* __table)`:**
    - 这些函数负责释放哈希表占用的内存。它们会遍历所有桶，释放每个桶中存储的条目的内存（通常包括键和数据），最后释放哈希表本身的内存。`_r` 版本只释放指定的哈希表。

* **`hsearch(ENTRY __entry, ACTION __action)` 和 `hsearch_r(ENTRY __entry, ACTION __action, ENTRY* * __result, struct hsearch_data* __table)`:**
    - 这些函数根据提供的 `__action` (FIND 或 ENTER) 在哈希表中查找或插入条目。
    - **查找 (FIND):**  首先使用哈希函数计算 `__entry.key` 的哈希值，确定其对应的桶。然后在该桶中查找具有相同键的条目（通常需要使用字符串比较函数）。如果找到，则返回该条目的指针；否则返回 NULL。
    - **插入 (ENTER):**  同样计算哈希值并定位到对应的桶。如果桶中已存在相同键的条目，行为取决于具体的实现（可能替换数据，也可能返回已存在的条目）。如果不存在，则创建一个新的 `ENTRY` 结构，将 `__entry` 的键和数据复制到新的结构中，并将新结构添加到该桶中（例如，添加到链表的头部）。`_r` 版本将找到的条目指针存储在 `__result` 中，并返回一个表示成功或失败的整数。

* **`tdelete(const void* __key, void* * __root_ptr, int (* __comparator)(const void*, const void*))`:**
    - 在以 `*__root_ptr` 为根的二叉树中查找键为 `__key` 的节点。查找过程类似于二叉搜索，使用 `__comparator` 函数比较节点键和目标键。
    - 找到节点后，需要处理不同的删除情况：
        - **叶子节点:** 直接将父节点指向该节点的指针设置为 NULL。
        - **只有一个子节点的节点:** 将父节点指向该节点的指针指向其子节点。
        - **有两个子节点的节点:** 通常找到该节点的中序后继节点（右子树的最小节点），将后继节点的值复制到待删除节点，然后在右子树中删除后继节点（后继节点必然是叶子节点或只有一个右子节点的节点，处理起来比较简单）。

* **`tdestroy(void* __root, void (* __free_fn)(void*))`:**
    - 递归地遍历二叉树的每个节点。对于每个节点，先递归地销毁其左右子树，然后调用 `__free_fn` 函数释放该节点占用的内存。

* **`tfind(const void* __key, void* const* __root_ptr, int (* __comparator)(const void*, const void*))`:**
    - 从根节点开始，使用 `__comparator` 函数将目标键 `__key` 与当前节点的键进行比较。
    - 如果目标键小于当前节点的键，则在左子树中继续查找。
    - 如果目标键大于当前节点的键，则在右子树中继续查找。
    - 如果相等，则找到目标节点，返回其指针。
    - 如果遍历到叶子节点的子节点（NULL）仍未找到，则返回 NULL。

* **`tsearch(const void* __key, void* * __root_ptr, int (* __comparator)(const void*, const void*))`:**
    - 与 `tfind` 类似地进行查找。
    - 如果找到目标节点，则返回该节点的指针。
    - 如果未找到，则创建一个新的节点，并将 `__key` 存储在新节点中。然后，根据比较结果，将新节点插入到树中的合适位置，并更新父节点的指针。返回新插入节点的指针。

* **`twalk(const void* __root, void (* __visitor)(const void*, VISIT, int))`:**
    - 用于遍历二叉树的所有节点，并对每个节点调用用户提供的 `__visitor` 函数。
    - `VISIT` 枚举类型指示访问节点的时间：
        - `preorder`:  第一次访问一个非叶子节点（在访问其子节点之前）。
        - `postorder`: 第二次访问一个非叶子节点（在访问完其左子节点之后，访问右子节点之前）。
        - `endorder`:  第三次访问一个非叶子节点（在访问完其所有子节点之后）。
        - `leaf`: 访问叶子节点。
    - `twalk` 通常使用递归实现。

* **`lfind(const void* __key, const void* __array, size_t* __count, size_t __size, int (* __comparator)(const void*, const void*))`:**
    - 从数组的第一个元素开始，逐个与目标键 `__key` 进行比较，直到找到匹配的元素或遍历完整个数组。
    - 使用提供的比较函数 `__comparator` 进行比较。
    - 如果找到匹配的元素，则返回该元素的指针。
    - 如果遍历完整个数组都没有找到匹配的元素，则返回 NULL。

* **`lsearch(const void* __key, void* __array, size_t* __count, size_t __size, int (* __comparator)(const void*, const void*))`:**
    - 与 `lfind` 类似地进行线性搜索。
    - 如果找到匹配的元素，则返回该元素的指针。
    - 如果未找到，则将 `__key` 复制到数组的末尾（索引为 `*__count * __size`），并将 `*__count` 的值增加 1。返回指向新添加元素的指针。

**Dynamic Linker 功能及 so 布局样本和链接处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。它定义的是 C 库提供的搜索和数据结构操作函数。Dynamic linker (如 Android 的 `linker64` 或 `linker`) 负责加载共享库 (`.so` 文件) 并解析符号引用。

当程序调用 `search.h` 中定义的函数时，这些函数的实现代码通常位于 C 库的共享库中 (例如 `libc.so`)。Dynamic linker 的作用是确保在程序运行时，这些函数能够被正确地找到和调用。

**so 布局样本 (简化):**

```
libc.so:
    .text:  // 代码段
        insque: ...
        remque: ...
        hcreate: ...
        // ... 其他 search.h 中函数的实现 ...
        printf: ...
        malloc: ...
    .data:  // 数据段 (全局变量等)
        __global_hash_table: ...
    .dynsym: // 动态符号表 (导出的符号)
        insque
        remque
        hcreate
        // ...
        printf
        malloc
    .dynstr: // 动态字符串表 (符号名称等)
        insque
        remque
        hcreate
        // ...
        printf
        malloc
```

**链接的处理过程:**

1. **编译时:** 当程序代码调用 `search.h` 中声明的函数时，编译器会生成对这些函数的未解析引用。
2. **链接时 (静态链接器):**  在传统的静态链接中，链接器会将程序的目标文件和所需的库文件（例如 `libc.a`）合并成一个可执行文件。所有符号引用都会在此时被解析。
3. **运行时 (动态链接器):** 在 Android 等现代系统中，通常使用动态链接。当程序启动时，操作系统会加载程序本身，并启动 dynamic linker。
4. **加载共享库:** Dynamic linker 会根据程序头的指示加载程序依赖的共享库 (例如 `libc.so`) 到内存中。
5. **符号解析:** Dynamic linker 会遍历程序和已加载共享库的动态符号表 (`.dynsym`)，解析程序中对共享库函数的引用。例如，当程序调用 `hcreate` 时，dynamic linker 会在 `libc.so` 的符号表中找到 `hcreate` 的地址，并将程序的调用指向该地址。
6. **重定位:**  由于共享库加载到内存的地址可能不固定，dynamic linker 还需要进行重定位，调整代码中涉及绝对地址的指令。

**假设输入与输出 (逻辑推理):**

* **`hsearch` 示例:**
    * **假设输入:**  哈希表已创建，包含键值对 `{"apple", "red"}`。现在调用 `hsearch({"banana", NULL}, FIND)`。
    * **输出:** 返回 NULL，因为键 "banana" 不存在于哈希表中。

* **`tfind` 示例:**
    * **假设输入:** 一个二叉搜索树，根节点值为 10，左子节点为 5，右子节点为 15。调用 `tfind(7, &root, compare_int)`，其中 `compare_int` 是一个比较整数的函数。
    * **输出:** 返回 NULL，因为值 7 不在树中。

* **`lsearch` 示例:**
    * **假设输入:** 一个包含 `{"cat", "dog"}` 的字符串数组，`count` 为 2。调用 `lsearch("bird", array, &count, sizeof(char*), compare_string)`。
    * **输出:**  返回指向新添加的 "bird" 的指针，`count` 的值变为 3，数组变为 `{"cat", "dog", "bird"}`。

**用户或编程常见的使用错误:**

1. **哈希表相关:**
   - **忘记调用 `hcreate` 或 `hcreate_r`:**  在使用哈希表之前必须先初始化，否则会导致段错误或未定义行为。
   - **内存泄漏:** 如果使用 `hsearch` 的 `ENTER` 操作插入了数据，并且这些数据是动态分配的，需要在不再使用时手动释放，否则会导致内存泄漏。
   - **使用错误的比较函数:** 在 `hsearch` 中，键的比较通常是字符串比较。使用错误的比较函数会导致查找失败或插入错误。
   - **在多线程环境中使用非线程安全的哈希表函数 (如 `hcreate`, `hsearch`):**  这会导致数据竞争和未定义行为。应该使用 `_r` 版本的函数。

2. **二叉树相关:**
   - **传递错误的比较函数:**  比较函数必须与树中存储的数据类型一致，并且能够正确定义元素的顺序。错误的比较函数会导致查找、插入和删除操作失败，甚至破坏树的结构。
   - **内存管理错误:**  如果树节点中存储的数据是动态分配的，需要在删除节点时手动释放，否则会导致内存泄漏。`tdestroy` 函数可以帮助清理整个树。
   - **修改树结构的同时进行遍历:**  在 `twalk` 遍历树的过程中修改树的结构可能会导致未定义行为。

3. **线性搜索相关:**
   - **传递错误的元素大小 (`__size`):**  如果 `__size` 参数不正确，会导致访问错误的内存位置。
   - **使用 `lsearch` 时未正确管理数组大小:**  `lsearch` 会在找不到元素时插入新元素，调用者需要确保数组有足够的空间容纳新元素，并更新 `count` 变量。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例:**

1. **Android Framework:**
   - Android Framework 的 Java 代码通常会调用 JNI (Java Native Interface) 来与 Native 代码交互。
   - Framework 的 Native 代码 (C/C++) 可能会使用 Bionic 提供的这些搜索和数据结构函数。
   - **例子:**  `android.os.ServiceManager` 的 Java 代码通过 JNI 调用 Native 层的 Service Manager，而 Native 层的 Service Manager 内部可能使用了哈希表（通过 `hcreate_r` 和 `hsearch_r`）来管理系统服务。

2. **NDK:**
   - NDK 开发者可以直接在 C/C++ 代码中使用 `search.h` 中定义的函数。
   - 当 NDK 代码被编译并链接到应用程序时，这些函数的符号引用会被链接到 Bionic 的共享库 `libc.so`。

**Frida Hook 示例:**

假设我们想监控 `hsearch_r` 函数的调用，可以编写如下 Frida 脚本：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const hsearch_r = Module.findExportByName("libc.so", "hsearch_r");
  if (hsearch_r) {
    Interceptor.attach(hsearch_r, {
      onEnter: function (args) {
        const entryPtr = args[0]; // ENTRY 结构体的指针
        const action = args[1].toInt(); // ACTION 枚举值
        const tablePtr = args[3]; // struct hsearch_data* 指针

        const keyPtr = Memory.readPointer(entryPtr);
        const dataPtr = Memory.readPointer(entryPtr.add(Process.pointerSize));
        const key = keyPtr.readCString();

        console.log("hsearch_r called:");
        console.log("  Key:", key);
        console.log("  Action:", action === 0 ? "FIND" : "ENTER");
        console.log("  Table:", tablePtr);
      },
      onLeave: function (retval) {
        console.log("hsearch_r returned:", retval);
      }
    });
  } else {
    console.log("hsearch_r not found in libc.so");
  }
} else {
  console.log("Frida hook example only for ARM/ARM64");
}
```

**解释:**

* 该脚本首先检查进程架构是否为 ARM 或 ARM64。
* 使用 `Module.findExportByName` 查找 `libc.so` 中 `hsearch_r` 函数的地址。
* 如果找到，则使用 `Interceptor.attach` 拦截该函数的调用。
* `onEnter` 函数在 `hsearch_r` 函数被调用时执行，它可以访问函数的参数。我们读取了 `ENTRY` 结构体中的键，以及 `ACTION` 和哈希表指针。
* `onLeave` 函数在 `hsearch_r` 函数返回时执行，可以查看返回值。

通过 Frida 这样的工具，开发者可以动态地观察 Android 系统或 NDK 应用中对这些底层 C 库函数的调用，从而进行调试和性能分析。

### 提示词
```
这是目录为bionic/libc/include/search.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*-
 * Written by J.T. Conklin <jtc@netbsd.org>
 * Public domain.
 *
 *	$NetBSD: search.h,v 1.12 1999/02/22 10:34:28 christos Exp $
 * $FreeBSD: release/9.0.0/include/search.h 105250 2002-10-16 14:29:23Z robert $
 */

#pragma once

/**
 * @file search.h
 * @brief Queues, hash tables, trees, and linear array searches.
 */

#include <sys/cdefs.h>
#include <sys/types.h>

/** See hsearch()/hsearch_r(). */
typedef enum {
  FIND,
  ENTER
} ACTION;

/** See hsearch()/hsearch_r(). */
typedef struct entry {
  /** The string key. */
  char* _Nullable key;
  /** The associated data. */
  void* _Nullable data;
} ENTRY;

/**
 * Constants given to the twalk() visitor.
 * Note that the constant names are misleading.
 */
typedef enum {
  /**
   * If this is the first visit to a non-leaf node.
   * Use this for *preorder* traversal.
   */
  preorder,
  /**
   * If this is the second visit to a non-leaf node.
   * Use this for *inorder* traversal.
   */
  postorder,
  /**
   * If this is the third visit to a non-leaf node.
   * Use this for *postorder* traversal.
   */
  endorder,
  /** If this is the first and only visit to a leaf node. */
  leaf
} VISIT;

#if defined(__USE_BSD) || defined(__USE_GNU)
/** The hash table type for hcreate_r()/hdestroy_r()/hsearch_r(). */
struct hsearch_data {
  struct __hsearch* _Nullable __hsearch;
};
#endif

__BEGIN_DECLS

/**
 * [insque(3)](https://man7.org/linux/man-pages/man3/insque.3.html) inserts
 * an item in a queue (an intrusive doubly-linked list).
 */
void insque(void* _Nonnull __element, void* _Nullable __previous);

/**
 * [remque(3)](https://man7.org/linux/man-pages/man3/remque.3.html) removes
 * an item from a queue (an intrusive doubly-linked list).
 */
void remque(void* _Nonnull __element);

/**
 * [hcreate(3)](https://man7.org/linux/man-pages/man3/hcreate.3.html)
 * initializes the global hash table, with space for at least `__n` elements.
 *
 * See hcreate_r() if you need more than one hash table.
 *
 * Returns *non-zero* on success and returns 0 and sets `errno` on failure.
 *
 * Available since API level 28.
 */

#if __BIONIC_AVAILABILITY_GUARD(28)
int hcreate(size_t __n) __INTRODUCED_IN(28);

/**
 * [hdestroy(3)](https://man7.org/linux/man-pages/man3/hdestroy.3.html) destroys
 * the global hash table.
 *
 * See hdestroy_r() if you need more than one hash table.
 *
 * Available since API level 28.
 */
void hdestroy(void) __INTRODUCED_IN(28);

/**
 * [hsearch(3)](https://man7.org/linux/man-pages/man3/hsearch.3.html) finds or
 * inserts `__entry` in the global hash table, based on `__action`.
 *
 * See hsearch_r() if you need more than one hash table.
 *
 * Returns a pointer to the entry on success, and returns NULL and sets
 * `errno` on failure.
 *
 * Available since API level 28.
 */
ENTRY* _Nullable hsearch(ENTRY __entry, ACTION __action) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


#if defined(__USE_BSD) || defined(__USE_GNU)

/**
 * [hcreate_r(3)](https://man7.org/linux/man-pages/man3/hcreate_r.3.html)
 * initializes a hash table `__table` with space for at least `__n` elements.
 *
 * Returns *non-zero* on success and returns 0 and sets `errno` on failure.
 *
 * Available since API level 28.
 */

#if __BIONIC_AVAILABILITY_GUARD(28)
int hcreate_r(size_t __n, struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);

/**
 * [hdestroy_r(3)](https://man7.org/linux/man-pages/man3/hdestroy_r.3.html) destroys
 * the hash table `__table`.
 *
 * Available since API level 28.
 */
void hdestroy_r(struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);

/**
 * [hsearch_r(3)](https://man7.org/linux/man-pages/man3/hsearch_r.3.html) finds or
 * inserts `__entry` in the hash table `__table`, based on `__action`.
 *
 * Returns *non-zero* on success and returns 0 and sets `errno` on failure.
 * A pointer to the entry is returned in `*__result`.
 *
 * Available since API level 28.
 */
int hsearch_r(ENTRY __entry, ACTION __action, ENTRY* _Nullable * _Nonnull __result, struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


#endif

/**
 * [lfind(3)](https://man7.org/linux/man-pages/man3/lfind.3.html) brute-force
 * searches the unsorted array `__array` (of `__count` items each of size `__size`)
 * for `__key`, using `__comparator`.
 *
 * See bsearch() if you have a sorted array.
 *
 * Returns a pointer to the matching element on success, or NULL on failure.
 */
void* _Nullable lfind(const void* _Nonnull __key, const void* _Nonnull __array, size_t* _Nonnull __count, size_t __size, int (* _Nonnull __comparator)(const void* _Nonnull, const void* _Nonnull));

/**
 * [lsearch(3)](https://man7.org/linux/man-pages/man3/lsearch.3.html) brute-force
 * searches the unsorted array `__array` (of `__count` items each of size `__size`)
 * for `__key`, using `__comparator`.
 *
 * Unlike lfind(), on failure lsearch() will *insert* `__key` at the end of
 * `__array` and increment `*__count`.
 *
 * Returns a pointer to the matching element on success, or to the newly-added
 * element on failure.
 */
void* _Nonnull lsearch(const void* _Nonnull __key, void* _Nonnull __array, size_t* _Nonnull __count, size_t __size, int (* _Nonnull __comparator)(const void* _Nonnull, const void* _Nonnull));

/**
 * [tdelete(3)](https://man7.org/linux/man-pages/man3/tdelete.3.html) searches
 * for and removes an element in the tree `*__root_ptr`. The search is performed
 * using `__comparator`.
 *
 * Returns a pointer to the parent of the deleted node, or NULL on failure.
 */
void* _Nullable tdelete(const void* _Nonnull __key, void* _Nullable * _Nullable __root_ptr, int (* _Nonnull __comparator)(const void* _Nonnull, const void* _Nonnull));

/**
 * [tdestroy(3)](https://man7.org/linux/man-pages/man3/tdestroy.3.html) destroys
 * the hash table `__root` using `__free_fn` on each node.
 */
void tdestroy(void* _Nullable __root, void (* _Nullable __free_fn)(void* _Nullable));

/**
 * [tfind(3)](https://man7.org/linux/man-pages/man3/tfind.3.html) searches
 * for an element in the tree `*__root_ptr`. The search is performed using
 * `__comparator`.
 *
 * Returns a pointer to the matching node, or NULL on failure.
 */
void* _Nullable tfind(const void* _Nonnull __key, void* _Nullable const* _Nullable __root_ptr, int (* _Nonnull __comparator)(const void* _Nonnull, const void* _Nonnull));

/**
 * [tsearch(3)](https://man7.org/linux/man-pages/man3/tsearch.3.html) searches
 * for an element in the tree `*__root_ptr`. The search is performed using
 * `__comparator`.
 *
 * Unlike tfind(), on failure tsearch() will *insert* `__key` into the tree.
 *
 * Returns a pointer to the matching node, or to the newly-added node.
 */
void* _Nullable tsearch(const void* _Nonnull __key, void* _Nullable * _Nullable __root_ptr, int (* _Nonnull __comparator)(const void* _Nonnull, const void* _Nonnull));

/**
 * [twalk(3)](https://man7.org/linux/man-pages/man3/twalk.3.html) calls
 * `__visitor` on every node in the tree.
 */
void twalk(const void* _Nullable __root, void (* _Nullable __visitor)(const void* _Nullable, VISIT, int));

__END_DECLS
```