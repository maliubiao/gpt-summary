Response:
Let's break down the thought process for generating the detailed response about `tsearch.c`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided `tsearch.c` source code within the context of Android's Bionic libc. Key aspects to cover include functionality, Android relevance, implementation details, dynamic linking, logic, error handling, and debugging.

**2. Initial Code Scan and Function Identification:**

The first step is to quickly scan the code and identify the primary functions: `tsearch`, `tdelete`, `twalk`, and the internal helper `trecurse`. The `typedef struct node_t` defines the structure used for the binary search tree nodes.

**3. Function-by-Function Analysis (Mental Walkthrough):**

* **`tsearch`:**  Recognize this as the core search and insertion function for a binary search tree. The logic involves traversing the tree based on the comparison result and inserting a new node if the key is not found. Think about the edge case of an empty tree (`rootp == 0`).

* **`tdelete`:** This function handles the removal of a node from the tree. This is the most complex function here. Mentally walk through the different cases for deleting a node:
    * Node with no children.
    * Node with one child.
    * Node with two children (requiring finding the inorder successor or predecessor). The code uses the inorder successor approach.

* **`twalk`:**  This function performs a traversal of the tree. Note the use of the `VISIT` enum (preorder, inorder, postorder, leaf) which is not defined in the provided code snippet but is part of `search.h`.

* **`trecurse`:**  This is the recursive helper function for `twalk`. Understand how the recursion works to implement the different traversal orders.

**4. Connecting to Android and Bionic:**

At this stage, consider the context. The code originates from OpenBSD and is part of Bionic. Think about:

* **Why is this needed in a C library?**  Binary search trees are fundamental data structures for efficient searching, insertion, and deletion.
* **Where might Android use this?**  Consider scenarios where efficient key-based lookups are required. Examples include resource management, internal data structures in system services, etc. (Though concrete examples are hard to pinpoint without broader Android source knowledge). Emphasize the potential use cases due to the general nature of the utility.
* **Dynamic Linking Relevance:** Recognize that `tsearch.c` is part of `libc.so` in Android. This immediately triggers the need to discuss dynamic linking concepts.

**5. Deep Dive into Implementation Details (`tsearch`, `tdelete`):**

* **Pointer Manipulation:** Pay close attention to the double pointers (`void **vrootp`, `node **rootp`). Explain why they are necessary to modify the root of the tree.
* **Comparison Function:** Highlight the role of the `compar` function and its importance for defining the ordering of elements in the tree.
* **Memory Allocation (`malloc`, `free`):** Note the use of `malloc` in `tsearch` and `free` in `tdelete`. Discuss memory management considerations.
* **Edge Cases and Error Handling:**  Mention the checks for null pointers and the return values indicating success or failure.

**6. Addressing Dynamic Linking:**

* **SO Layout:** Sketch a simplified layout of `libc.so`, including sections like `.text`, `.data`, `.bss`, and the GOT/PLT.
* **Linking Process:**  Explain the role of the dynamic linker (`linker64` or `linker`) in resolving symbols, particularly how `tsearch` (and potentially the comparison function) would be resolved during runtime. Emphasize the lazy binding behavior and the GOT/PLT interaction.

**7. Logical Reasoning and Examples:**

* **`tsearch` Example:** Create a simple scenario with integer keys and a comparison function. Illustrate how the tree would be built with specific insertions.
* **`tdelete` Example:**  Take the tree from the `tsearch` example and show how deleting different nodes (leaf, one child, two children) would modify the tree structure.

**8. Common Usage Errors:**

Think about typical mistakes developers might make when using these functions:

* **Incorrect Comparison Function:**  This is a critical error that can lead to incorrect tree structure and search results.
* **Memory Management Issues:** Forgetting to free the memory associated with the keys (if dynamically allocated).
* **Passing Incorrect Root Pointer:**  This can lead to operating on the wrong tree or causing crashes.

**9. Android Framework/NDK Integration and Debugging:**

* **Framework/NDK Path:** Explain the general path from Android framework calls (e.g., using a data structure that internally uses a tree) or NDK usage of standard C library functions. Since `tsearch` isn't a directly exposed Android API, the connection is more about its use as a low-level building block.
* **Frida Hooking:** Provide concrete Frida examples for hooking `tsearch`, `tdelete`, and the comparison function. Explain how to inspect arguments and return values. Highlight the usefulness of Frida for understanding the runtime behavior.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use code blocks for code snippets and format the output for readability. Maintain a consistent and clear writing style.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus too much on specific Android API usage. **Correction:** Shift the focus to the general utility of `tsearch` and how it could be used internally.
* **Initial thought:**  Overcomplicate the dynamic linking explanation. **Correction:**  Simplify the explanation to focus on the core concepts of GOT/PLT and symbol resolution.
* **Initial thought:**  Assume the user has deep knowledge of binary search trees. **Correction:** Briefly explain the basic concepts to ensure clarity for a wider audience.
* **Initial thought:**  Not provide enough concrete examples. **Correction:**  Add specific examples for `tsearch` and `tdelete` with sample input and output.

By following these steps, the goal is to create a comprehensive, accurate, and easy-to-understand explanation of the provided `tsearch.c` code within the specified context.
好的，让我们详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdlib/tsearch.c` 这个文件。

**功能概述**

`tsearch.c` 文件实现了二叉搜索树（Binary Search Tree）的通用查找、插入和删除功能。它提供了以下三个主要的公开函数：

1. **`tsearch()`**:  在二叉搜索树中查找指定的键值。如果找到，则返回指向匹配节点的指针；如果没找到，则将新的键值插入到树中，并返回指向新插入节点的指针。
2. **`tdelete()`**: 从二叉搜索树中删除指定的键值对应的节点。如果找到并成功删除，则返回被删除节点的父节点（注意：原始 OpenBSD 的实现返回的是被删除的节点，这里 Bionic 的实现可能略有不同，但根据代码分析，它返回的是被删除节点的父节点）；如果没找到，则返回 `NULL`。
3. **`twalk()`**:  遍历二叉搜索树中的所有节点，并对每个节点执行指定的操作。

此外，还有一个内部使用的静态函数：

4. **`trecurse()`**:  `twalk()` 函数的递归实现。

**与 Android 功能的关系及举例**

尽管 `tsearch`、`tdelete` 和 `twalk` 不是 Android Framework 或 NDK 中直接暴露的公共 API，但它们作为 C 标准库的一部分，可以被 Android 系统的各种组件和服务在内部使用。由于二叉搜索树是一种高效的数据结构，用于存储和检索有序数据，因此在以下场景中可能被间接使用：

*   **内部数据管理:**  Android 系统的某些底层服务或组件可能使用二叉搜索树来维护和查找内部状态信息或配置数据。例如，某个服务可能用它来管理一组已注册的事件监听器，按照某种优先级或 ID 排序。
*   **资源管理:**  虽然不太常见，但在一些需要快速查找和管理特定类型资源的场景下，二叉搜索树也可能被考虑使用。
*   **某些算法的实现:**  一些更复杂的算法内部可能会用到二叉搜索树作为辅助数据结构。

**举例说明:**

假设 Android 的一个内部服务需要管理一组插件，每个插件都有一个唯一的名称。该服务可以使用 `tsearch` 来快速查找是否已经存在某个名称的插件，如果不存在，则将其添加到一个二叉搜索树中。

```c
// 假设插件结构体
typedef struct {
    char *name;
    // 其他插件相关数据
} Plugin;

// 用于比较插件名称的比较函数
int compare_plugins(const void *key1, const void *key2) {
    const char *name1 = ((const Plugin *)key1)->name;
    const char *name2 = ((const Plugin *)key2)->name;
    return strcmp(name1, name2);
}

// 插件管理服务的内部数据结构
void *plugin_tree_root = NULL;

// 添加一个插件
Plugin *add_plugin(char *plugin_name) {
    Plugin *new_plugin = malloc(sizeof(Plugin));
    if (new_plugin == NULL) {
        return NULL;
    }
    new_plugin->name = strdup(plugin_name); // 复制插件名称
    if (new_plugin->name == NULL) {
        free(new_plugin);
        return NULL;
    }

    Plugin *found_plugin = tsearch(new_plugin, &plugin_tree_root, compare_plugins);
    if (found_plugin == new_plugin) {
        // 新插件成功添加到树中
        return new_plugin;
    } else {
        // 插件已存在，释放新分配的内存
        free(new_plugin->name);
        free(new_plugin);
        return found_plugin; // 返回已存在的插件
    }
}

// 查找一个插件
Plugin *find_plugin(char *plugin_name) {
    Plugin key = {.name = plugin_name};
    return tsearch(&key, &plugin_tree_root, compare_plugins);
}
```

**libc 函数实现详解**

1. **`tsearch(const void *vkey, void **vrootp, int (*compar)(const void *, const void *))`**

    *   **功能:**  在以 `*vrootp` 为根节点的二叉搜索树中查找键值 `vkey`。如果找到，返回指向匹配节点的指针；否则，插入新节点并返回指向新节点的指针。
    *   **实现:**
        *   将 `vkey` 和 `vrootp` 转换为正确的类型 (`char *` 和 `node **`)。
        *   如果根指针 `rootp` 为 `NULL`，表示树为空，直接返回 `NULL`。
        *   进入一个 `while` 循环，遍历树直到找到匹配的节点或到达叶子节点：
            *   使用提供的比较函数 `compar` 比较 `key` 和当前节点的键值。
            *   如果比较结果为 0，表示找到匹配的节点，返回当前节点的地址。
            *   如果比较结果小于 0，表示 `key` 小于当前节点的键值，沿着左子树继续查找。
            *   如果比较结果大于 0，表示 `key` 大于当前节点的键值，沿着右子树继续查找。
        *   如果循环结束时仍未找到，说明 `key` 不在树中。
        *   分配一个新的 `node` 结构体。
        *   如果分配成功，将新节点的 `key` 指向 `key`，并将新节点链接到父节点的相应位置 (`*rootp = q`)。新节点的左右子节点指针初始化为 `NULL`。
        *   返回指向新节点的指针。

2. **`tdelete(const void *vkey, void **vrootp, int (*compar)(const void *, const void *))`**

    *   **功能:**  从以 `*vrootp` 为根节点的二叉搜索树中删除键值为 `vkey` 的节点。
    *   **实现:**
        *   将 `vkey` 和 `vrootp` 转换为正确的类型。
        *   如果根指针 `rootp` 为 `NULL` 或者树为空，直接返回 `NULL`。
        *   使用一个 `while` 循环查找要删除的节点：
            *   使用比较函数 `compar` 比较 `key` 和当前节点的键值。
            *   如果找到匹配的节点，跳出循环。
            *   如果 `key` 小于当前节点的键值，沿着左子树继续查找。
            *   如果 `key` 大于当前节点的键值，沿着右子树继续查找。
            *   如果在遍历过程中遇到 `NULL` 子节点，表示未找到要删除的节点，返回 `NULL`。
        *   **删除节点的逻辑 (Knuth 的算法 T 的变体):**
            *   `r` 指向要删除节点的右子树。
            *   `q` 指向要删除节点的左子树。
            *   **情况 1: 要删除的节点没有左子树 (`q == NULL`)**
                *   将父节点的相应指针指向要删除节点的右子树 (`q = r`)。
            *   **情况 2: 要删除的节点有左子树，但没有右子树 (`r == NULL`)**
                *   实际上这种情况在前面的 `if` 中已经处理了，因为如果右子树为空，`q` 就会被赋值为 `r` (也就是 NULL)。
            *   **情况 3: 要删除的节点既有左子树又有右子树 (`r != NULL`)**
                *   **子情况 3.1: 右子树的左子树为空 (`r->left == NULL`)**
                    *   将右子树的左子树指向要删除节点的左子树 (`r->left = q`)。
                    *   将 `q` 指向右子树，作为新的子树根。
                *   **子情况 3.2: 右子树的左子树不为空 (`r->left != NULL`)**
                    *   在右子树中找到 inorder successor（即右子树中最小的节点）。这通过循环 `for (q = r->left; q->left != NULL; q = r->left)` 实现，其中 `r` 会指向 `q` 的父节点。
                    *   将 successor 的父节点的左子树指向 successor 的右子树 (`r->left = q->right`)，相当于将 successor 从原来的位置移除。
                    *   将 successor 的左子树指向要删除节点的左子树 (`q->left = (*rootp)->left`)。
                    *   将 successor 的右子树指向要删除节点的右子树 (`q->right = (*rootp)->right`)。
            *   释放要删除节点的内存 (`free((struct node_t *) *rootp)`)。
            *   将父节点的相应指针指向新的子树根 `q` (`*rootp = q`)。
        *   返回被删除节点的父节点 `p`。

3. **`twalk(const void *vroot, void (*action)(const void *, VISIT, int))`**

    *   **功能:**  对以 `vroot` 为根节点的二叉搜索树进行遍历，并对每个节点执行由 `action` 指针指定的函数。
    *   **实现:**
        *   将 `vroot` 转换为 `node *` 类型。
        *   如果根节点为空或者 `action` 函数指针为空，则直接返回。
        *   调用内部递归函数 `trecurse` 来执行遍历。

4. **`trecurse(node *root, void (*action)(const void *, VISIT, int), int level)`**

    *   **功能:**  `twalk` 的递归实现，执行实际的树遍历操作。
    *   **实现:**
        *   如果当前节点是叶子节点（左右子节点都为空），则调用 `action` 函数，传入当前节点、`leaf` 枚举值和当前节点的深度 `level`。
        *   否则，按照以下顺序调用 `action` 函数：
            *   `preorder`:  在访问子节点之前调用。
            *   递归访问左子树。
            *   `postorder`: 在访问左子树之后，访问右子树之前调用。
            *   递归访问右子树。
            *   `endorder`: 在访问右子树之后调用。
        *   `VISIT` 是一个枚举类型，定义了遍历过程中访问节点的不同时机，通常包括 `preorder`（前序）、`inorder`（中序）、`postorder`（后序）和 `leaf`（叶子节点）。注意：这个枚举类型在提供的代码片段中没有定义，通常在 `<search.h>` 中。

**涉及 dynamic linker 的功能**

`tsearch.c` 本身的代码并不直接涉及 dynamic linker 的具体操作。然而，作为 `libc.so` 的一部分，当 Android 应用或系统服务调用 `tsearch`、`tdelete` 或 `twalk` 时，dynamic linker 会参与到符号的查找和链接过程中。

**so 布局样本 (简化)**

```
libc.so:
    .text:
        [...其他函数...]
        tsearch:  <tsearch 函数的代码>
        tdelete:  <tdelete 函数的代码>
        twalk:    <twalk 函数的代码>
        trecurse: <trecurse 函数的代码>
        [...其他函数...]
    .data:
        [...全局变量...]
    .bss:
        [...未初始化的全局变量...]
    .rodata:
        [...只读数据...]
    .dynamic:
        [...动态链接信息...]
    .got:      <全局偏移量表>
    .plt:      <过程链接表>
```

**链接的处理过程**

1. **编译时:** 当包含 `<search.h>` 并调用 `tsearch` 等函数的代码被编译时，编译器会生成对这些函数的未解析引用。
2. **链接时:** 静态链接器（在构建 `libc.so` 时）会将 `tsearch.o` 等目标文件链接到 `libc.so` 中，确定这些函数的实际地址。
3. **运行时 (dynamic linker 介入):**
    *   当一个 Android 应用或服务启动时，操作系统会加载其可执行文件以及依赖的共享库（如 `libc.so`）。
    *   dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 负责解析可执行文件和共享库之间的符号引用。
    *   当应用首次调用 `tsearch` 时，如果采用了延迟绑定（通常是默认行为），会首先跳转到 `libc.so` 的 `.plt` 段中的一个桩代码（stub）。
    *   这个桩代码会调用 dynamic linker，dynamic linker 会在 `libc.so` 的符号表（在 `.dynsym` 段）中查找 `tsearch` 的地址。
    *   找到地址后，dynamic linker 会更新 `.got` 段中 `tsearch` 对应的条目，将其指向 `tsearch` 函数在内存中的实际地址。
    *   后续对 `tsearch` 的调用将直接通过 `.got` 表跳转到 `tsearch` 的实际代码，避免了重复的符号查找。

**逻辑推理：假设输入与输出**

假设我们有以下代码片段：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>

int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

void print_node(const void *nodeptr, VISIT order, int level) {
    if (order == leaf || order == postorder) {
        printf("Level %d: %s\n", level, *(const char **)nodeptr);
    }
}

int main() {
    void *root = NULL;
    char *str1 = "banana";
    char *str2 = "apple";
    char *str3 = "cherry";

    // 插入
    tsearch(&str1, &root, compare_strings);
    tsearch(&str2, &root, compare_strings);
    tsearch(&str3, &root, compare_strings);

    // 遍历
    printf("Tree traversal:\n");
    twalk(root, print_node);

    // 查找
    char *search_key = "apple";
    char **found = tsearch(&search_key, &root, compare_strings);
    if (found && *found) {
        printf("Found: %s\n", *found);
    } else {
        printf("Not found\n");
    }

    // 删除
    char *delete_key = "banana";
    tdelete(&delete_key, &root, compare_strings);

    printf("Tree traversal after deletion:\n");
    twalk(root, print_node);

    return 0;
}
```

**预期输出:**

```
Tree traversal:
Level 1: apple
Level 0: banana
Level 1: cherry
Found: apple
Tree traversal after deletion:
Level 0: apple
Level 1: cherry
```

**用户或编程常见的使用错误**

1. **未提供正确的比较函数:**  `compar` 函数必须正确地比较两个键值，并返回负数、零或正数。错误的比较函数会导致二叉搜索树的结构错误，从而影响查找、插入和删除操作的正确性。

    ```c
    // 错误的比较函数，可能导致排序错误
    int bad_compare(const void *a, const void *b) {
        return 1; // 总是返回正数
    }
    ```

2. **比较函数不一致:**  在整个生命周期中，对同一棵树的 `tsearch`、`tdelete` 和 `twalk` 操作必须使用相同的比较函数。使用不同的比较函数会导致逻辑错误。

3. **内存管理错误:**  `tsearch` 内部不会复制 `vkey` 指向的数据，只是存储了指针。如果 `vkey` 指向的内存被释放或修改，会导致树中的数据损坏。用户需要确保在树的生命周期内，键值数据的有效性。

    ```c
    char *key = malloc(10);
    strcpy(key, "test");
    tsearch(&key, &root, compare_strings);
    free(key); // 错误：键值内存被释放
    ```

4. **对空指针解引用:**  在使用 `tsearch` 或 `tdelete` 之前，没有正确初始化根指针 `root`，可能导致空指针解引用。

    ```c
    void *root; // 未初始化
    char *key = "test";
    tsearch(&key, &root, compare_strings); // 错误：可能解引用未初始化的 root
    ```

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例**

由于 `tsearch` 等函数是 C 标准库的一部分，Android Framework 或 NDK 中使用标准 C 函数的组件或库可能会间接地调用到这些函数。

**Framework 路径 (较为间接):**

1. Android Framework 的某些组件（通常是用 Java 编写）可能会通过 JNI 调用 NDK 中的本地代码。
2. NDK 中的 C/C++ 代码可能会使用标准 C 库函数，例如，如果某个 NDK 模块需要维护一个有序的数据集合，可能会使用基于 `tsearch` 手动实现的二叉搜索树（尽管更常见的是使用标准库提供的容器如 `std::set` 或 `std::map`）。

**NDK 路径 (更直接):**

1. NDK 开发者可以直接在其 C/C++ 代码中使用 `<search.h>` 中声明的 `tsearch` 等函数。

**Frida Hook 示例**

可以使用 Frida Hook 来观察 `tsearch` 函数的调用情况。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

package_name = "your.android.app.package"  # 替换为你的应用包名

try:
    device = frida.get_usb_device(timeout=10)
    session = device.attach(package_name)
except frida.WaitForDebuggerTimeoutError:
    print(f"[-] 设备未连接或应用 '{package_name}' 未运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "tsearch"), {
    onEnter: function(args) {
        console.log("[+] tsearch called");
        console.log("    Key: " + ptr(args[0]));
        console.log("    Root pointer address: " + ptr(args[1]));
        console.log("    Comparison function: " + ptr(args[2]));

        // 尝试读取键值（假设键是指向字符串的指针）
        try {
            var keyPtr = ptr(args[0]).readPointer();
            console.log("    Key value: " + keyPtr.readCString());
        } catch (e) {
            console.log("    Could not read key value.");
        }
    },
    onLeave: function(retval) {
        console.log("[+] tsearch returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "tdelete"), {
    onEnter: function(args) {
        console.log("[+] tdelete called");
        console.log("    Key: " + ptr(args[0]));
        console.log("    Root pointer address: " + ptr(args[1]));
        console.log("    Comparison function: " + ptr(args[2]));
        // ... (类似地读取键值)
    },
    onLeave: function(retval) {
        console.log("[+] tdelete returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "twalk"), {
    onEnter: function(args) {
        console.log("[+] twalk called");
        console.log("    Root: " + ptr(args[0]));
        console.log("    Action function: " + ptr(args[1]));
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook `libc.so` 中的 `tsearch`, `tdelete`, 和 `twalk` 函数，并在它们被调用时打印相关信息，包括参数的值。你需要将 `your.android.app.package` 替换为你想要监控的 Android 应用的包名。运行这个脚本后，当目标应用执行到 `tsearch` 等函数时，你将在 Frida 的输出中看到相应的日志信息，从而可以调试这些步骤。

希望这个详细的分析能够帮助你理解 `tsearch.c` 的功能和在 Android 系统中的潜在应用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdlib/tsearch.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: tsearch.c,v 1.10 2015/09/26 16:03:48 guenther Exp $	*/

/*
 * Tree search generalized from Knuth (6.2.2) Algorithm T just like
 * the AT&T man page says.
 *
 * The node_t structure is for internal use only
 *
 * Written by reading the System V Interface Definition, not the code.
 *
 * Totally public domain.
 */

#include <search.h>
#include <stdlib.h>

typedef struct node_t {
    char	  *key;
    struct node_t *left, *right;
} node;

/* find or insert datum into search tree */
void *
tsearch(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *))
{
    node *q;
    char *key = (char *)vkey;
    node **rootp = (node **)vrootp;

    if (rootp == (struct node_t **)0)
	return ((void *)0);
    while (*rootp != (struct node_t *)0) {	/* Knuth's T1: */
	int r;

	if ((r = (*compar)(key, (*rootp)->key)) == 0)	/* T2: */
	    return ((void *)*rootp);		/* we found it! */
	rootp = (r < 0) ?
	    &(*rootp)->left :		/* T3: follow left branch */
	    &(*rootp)->right;		/* T4: follow right branch */
    }
    q = malloc(sizeof(node));	/* T5: key not found */
    if (q != (struct node_t *)0) {	/* make new node */
	*rootp = q;			/* link new node to old */
	q->key = key;			/* initialize new node */
	q->left = q->right = (struct node_t *)0;
    }
    return ((void *)q);
}

/* delete node with given key */
void *
tdelete(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *))
{
    node **rootp = (node **)vrootp;
    char *key = (char *)vkey;
    node *p = (node *)1;
    node *q;
    node *r;
    int cmp;

    if (rootp == (struct node_t **)0 || *rootp == (struct node_t *)0)
	return ((struct node_t *)0);
    while ((cmp = (*compar)(key, (*rootp)->key)) != 0) {
	p = *rootp;
	rootp = (cmp < 0) ?
	    &(*rootp)->left :		/* follow left branch */
	    &(*rootp)->right;		/* follow right branch */
	if (*rootp == (struct node_t *)0)
	    return ((void *)0);		/* key not found */
    }
    r = (*rootp)->right;			/* D1: */
    if ((q = (*rootp)->left) == (struct node_t *)0)	/* Left (struct node_t *)0? */
	q = r;
    else if (r != (struct node_t *)0) {		/* Right link is null? */
	if (r->left == (struct node_t *)0) {	/* D2: Find successor */
	    r->left = q;
	    q = r;
	} else {			/* D3: Find (struct node_t *)0 link */
	    for (q = r->left; q->left != (struct node_t *)0; q = r->left)
		r = q;
	    r->left = q->right;
	    q->left = (*rootp)->left;
	    q->right = (*rootp)->right;
	}
    }
    free((struct node_t *) *rootp);	/* D4: Free node */
    *rootp = q;				/* link parent to new node */
    return(p);
}

/* Walk the nodes of a tree */
static void
trecurse(node *root, void (*action)(const void *, VISIT, int), int level)
{
    if (root->left == (struct node_t *)0 && root->right == (struct node_t *)0)
	(*action)(root, leaf, level);
    else {
	(*action)(root, preorder, level);
	if (root->left != (struct node_t *)0)
	    trecurse(root->left, action, level + 1);
	(*action)(root, postorder, level);
	if (root->right != (struct node_t *)0)
	    trecurse(root->right, action, level + 1);
	(*action)(root, endorder, level);
    }
}

/* Walk the nodes of a tree */
void
twalk(const void *vroot, void (*action)(const void *, VISIT, int))
{
    node *root = (node *)vroot;

    if (root != (node *)0 && action != (void (*)(const void *, VISIT, int))0)
	trecurse(root, action, 0);
}

"""

```