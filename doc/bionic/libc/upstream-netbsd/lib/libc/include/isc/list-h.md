Response:
Let's break down the thought process for analyzing this `list.h` file.

1. **Understanding the Context:** The prompt clearly states this is a header file for a linked list implementation from NetBSD, used within Android's Bionic libc. This immediately tells us the purpose: providing a basic linked list data structure for use within the C library.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for keywords and common C preprocessor directives. We see:
    * `#ifndef`, `#define`, `#endif`: Header guard to prevent multiple inclusions.
    * `#include`: Inclusion of `isc/assertions.h`, suggesting the presence of internal assertions for debugging.
    * `struct`:  Indicates the definition of data structures.
    * `#define` with arguments:  Likely macros that simplify common operations.
    * Function-like macro names (e.g., `INIT_LIST`, `PREPEND`, `APPEND`):  These strongly suggest the core functionalities of the linked list.

3. **Deconstructing the Core Data Structures:** Focus on the `struct` definitions:
    * `LIST(type)`: This is a macro that expands to a structure containing `head` and `tail` pointers of a given `type`. This represents the overall linked list. The use of a macro makes it generic.
    * `LINK(type)`: This macro expands to a structure containing `prev` and `next` pointers, also of a given `type`. This structure is meant to be embedded *within* the elements that will be stored in the list. This is a crucial detail for understanding how the linking works.

4. **Analyzing the Macros (The Core Functionality):** Go through each macro, understanding its purpose and how it manipulates the pointers:
    * `INIT_LIST`:  Initializes an empty list by setting `head` and `tail` to `NULL`.
    * `INIT_LINK_TYPE` and `INIT_LINK`: Initialize the `prev` and `next` pointers of a list element to a sentinel value (`(type *)(-1)`). This likely marks an element as not currently being part of any list.
    * `LINKED`: Checks if an element is currently linked in a list by verifying that its `prev` and `next` pointers are not the sentinel value.
    * `HEAD`, `TAIL`, `EMPTY`: Simple accessors for the list's head, tail, and emptiness status.
    * `PREPEND`:  Adds an element to the beginning of the list. Carefully trace the pointer manipulations: updating the new element's `next`, updating the old head's `prev`, and updating the list's `head`. Handle the case of an empty list.
    * `APPEND`:  Adds an element to the end of the list. Similar logic to `PREPEND`, but working with the `tail`.
    * `UNLINK_TYPE` and `UNLINK`: Removes an element from the list. This is more complex. Consider the cases where the element is the head, the tail, or in the middle of the list. Crucially, after unlinking, the element's link pointers are re-initialized.
    * `PREV`, `NEXT`: Accessors for an element's previous and next pointers.
    * `INSERT_BEFORE`, `INSERT_AFTER`: Insert an element at a specific location in the list. Handle the edge cases of inserting at the beginning or end.
    * `ENQUEUE`, `DEQUEUE`:  These are simply aliases for `APPEND` and `UNLINK`, suggesting this list implementation can be used as a queue.

5. **Relating to Android:**  Consider how a basic linked list could be useful in Android's core libraries. Think about scenarios where you need to maintain an ordered collection of items where efficient insertion and removal at arbitrary points are important. Examples include:
    * Managing a list of network connections.
    * Maintaining a queue of pending tasks.
    * Keeping track of allocated memory blocks (though more complex structures are often used).

6. **Dynamic Linker Considerations (and Absence Thereof):**  The code itself *doesn't* directly interact with the dynamic linker. It's a basic data structure. However, understand *how* it might be used by code that *does* involve the dynamic linker. For instance, the dynamic linker might use a linked list internally to track loaded libraries or symbols. Recognize that the provided code is too low-level to directly demonstrate dynamic linking. Provide a *conceptual* example and explain the linking process generally.

7. **Common Usage Errors:**  Think about the pitfalls of working with linked lists in C:
    * Memory management issues (leaks, dangling pointers).
    * Incorrectly handling edge cases (empty lists, single-element lists).
    * Not initializing the link structure.
    * Double linking/unlinking.

8. **Tracing the Path from Framework/NDK:**  Consider how this basic building block fits into the larger Android ecosystem. Higher-level frameworks might use data structures built upon this, even indirectly. Provide a hypothetical chain of calls to illustrate this.

9. **Frida Hooking:**  Demonstrate how to use Frida to inspect the state of the linked list and its elements at runtime. Focus on hooking the insertion or deletion operations to observe the pointer manipulations.

10. **Structure and Language:** Organize the information logically, using clear headings and explanations. Use precise technical language but also explain concepts in a way that is easy to understand. Since the request is in Chinese, ensure the entire response is in accurate and natural-sounding Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just a simple linked list."  **Correction:** While conceptually simple, it's important to explain *how* the macros achieve the linking, especially the embedded `LINK` structure.
* **Initial thought:** "This code must be directly used by the dynamic linker." **Correction:**  While *used within* the C library, it's not directly manipulating dynamic linking structures in *this specific file*. Focus on how it *could* be used in related contexts.
* **Clarity:**  Ensure the explanations of the macros are step-by-step and easy to follow. Use terms like "points to" and "is pointed to by" to clarify pointer relationships.
* **Examples:**  Provide concrete examples of how the linked list might be used in Android to make the explanation more tangible.

By following these steps, and iteratively refining the understanding, a comprehensive and accurate answer like the example provided can be constructed.
这个头文件 `list.h` 定义了一个通用的双向链表数据结构和相关的操作宏。它源自 NetBSD，并被 Android 的 Bionic C 库所使用。

**功能列表:**

1. **定义链表结构 (`LIST(type)`)**: 提供了一个创建链表头部的结构体模板。你可以用它来定义一个存储特定类型元素的链表。
2. **初始化链表 (`INIT_LIST(list)`)**:  将链表的头部和尾部指针都设置为 `NULL`，表示一个空链表。
3. **定义链表节点链接 (`LINK(type)`)**: 提供了一个嵌入到链表节点结构体中的链接结构体模板，包含指向前一个和后一个节点的指针。
4. **初始化链表节点链接 (`INIT_LINK_TYPE`, `INIT_LINK`)**: 将链表节点的 `prev` 和 `next` 指针初始化为一个特定的无效值 `(type *)(-1)`，表示该节点当前没有链接到任何链表中。
5. **检查节点是否已链接 (`LINKED(elt, link)`)**: 检查一个节点的 `prev` 和 `next` 指针是否为无效值，以此判断该节点是否已插入到某个链表中。
6. **获取链表头部和尾部 (`HEAD(list)`, `TAIL(list)`)**:  分别返回链表的头节点和尾节点。
7. **检查链表是否为空 (`EMPTY(list)`)**: 检查链表的头节点是否为 `NULL`。
8. **在链表头部添加节点 (`PREPEND(list, elt, link)`)**: 将一个节点添加到链表的头部。
9. **在链表尾部添加节点 (`APPEND(list, elt, link)`)**: 将一个节点添加到链表的尾部。
10. **从链表中移除节点 (`UNLINK_TYPE`, `UNLINK`)**: 将一个节点从链表中移除。
11. **获取节点的前一个和后一个节点 (`PREV(elt, link)`, `NEXT(elt, link)`)**:  分别返回一个节点的前一个和后一个节点。
12. **在指定节点前插入节点 (`INSERT_BEFORE(list, before, elt, link)`)**: 在链表中的某个节点之前插入一个新的节点。
13. **在指定节点后插入节点 (`INSERT_AFTER(list, after, elt, link)`)**: 在链表中的某个节点之后插入一个新的节点。
14. **入队和出队操作 (`ENQUEUE(list, elt, link)`, `DEQUEUE(list, elt, link)`)**:  将链表用作队列时的入队（添加到尾部）和出队（从头部移除）操作的别名。

**与 Android 功能的关系及举例说明:**

虽然这是一个底层的链表实现，但它是 Bionic libc 的一部分，因此被 Android 系统和应用程序广泛使用，尽管通常是通过更高层次的抽象来实现的。以下是一些可能的应用场景：

* **网络连接管理:**  Android 的网络栈可能会使用链表来管理活动的网络连接。例如，一个 `tcp_connection` 结构体可能包含一个 `LINK(tcp_connection)` 类型的成员，用于将连接对象加入到全局的连接列表中。
* **线程管理:**  操作系统内核或用户空间的线程库可能会使用链表来管理线程队列，例如就绪队列或等待队列。
* **内存管理:** 虽然 Bionic 的内存分配器 (jemalloc) 使用更复杂的数据结构，但在某些内部管理结构中，链表可能被用来跟踪小的内存块或其他资源。
* **Binder 机制:**  Binder 是 Android 中进程间通信 (IPC) 的核心机制。在 Binder 驱动或库的内部实现中，可能使用链表来管理等待的事务、已连接的进程等。
* **文件系统:**  文件系统的 inode 缓存或目录项缓存可能使用链表来提高查找效率。

**详细解释 libc 函数的实现:**

这里的 "libc 函数" 实际上指的是这个头文件中定义的宏。这些宏在编译时会被展开为实际的 C 代码。

* **`LIST(type)`:** 这是一个简单的宏，用于定义一个包含 `head` 和 `tail` 指针的匿名结构体。例如，`LIST(int)` 会展开成 `struct { int *head, *tail; }`。

* **`INIT_LIST(list)`:**  将传入的链表结构体的 `head` 和 `tail` 成员设置为 `NULL`。这是一个内联操作，直接赋值。

* **`LINK(type)`:**  类似于 `LIST(type)`，定义了一个包含 `prev` 和 `next` 指针的匿名结构体，用于构建链表节点之间的链接。

* **`INIT_LINK_TYPE(elt, link, type)` 和 `INIT_LINK(elt, link)`:** 将指定元素的链接结构体的 `prev` 和 `next` 指针设置为 `(type *)(-1)`。这是一个特殊的地址值，用作标记，表示该节点当前未链接到任何链表。`INIT_LINK` 是一个简化版本，假设类型为 `void*`。

* **`LINKED(elt, link)`:** 检查指定元素的链接结构体的 `prev` 和 `next` 指针是否不等于 `(void *)(-1)`。如果都不等于，则认为该节点已链接。

* **`HEAD(list)` 和 `TAIL(list)`:**  直接返回链表结构体的 `head` 和 `tail` 成员。

* **`EMPTY(list)`:** 检查链表结构体的 `head` 成员是否为 `NULL`。

* **`PREPEND(list, elt, link)`:**
    1. `INSIST(!LINKED(elt, link));`: 断言要添加的节点当前没有链接到任何链表。
    2. 如果链表非空 (`(list).head != NULL`)，则将当前头节点的 `prev` 指针设置为要添加的节点 `elt`。
    3. 否则 (链表为空)，将链表的尾指针 `(list).tail` 设置为要添加的节点 `elt`。
    4. 将要添加的节点 `elt` 的 `prev` 指针设置为 `NULL` (因为它将成为新的头节点)。
    5. 将要添加的节点 `elt` 的 `next` 指针设置为当前的头节点 `(list).head`。
    6. 将链表的头指针 `(list).head` 更新为要添加的节点 `elt`。

* **`APPEND(list, elt, link)`:**  逻辑与 `PREPEND` 类似，但操作的是链表的尾部。

* **`UNLINK_TYPE(list, elt, link, type)` 和 `UNLINK(list, elt, link)`:**
    1. `INSIST(LINKED(elt, link));`: 断言要移除的节点当前已链接到某个链表。
    2. 如果要移除的节点有后继节点 (`(elt)->link.next != NULL`)，则将后继节点的 `prev` 指针设置为要移除节点的 `prev` 指针。
    3. 否则 (要移除的节点是尾节点)，将链表的尾指针 `(list).tail` 设置为要移除节点的 `prev` 指针。
    4. 如果要移除的节点有前驱节点 (`(elt)->link.prev != NULL`)，则将前驱节点的 `next` 指针设置为要移除节点的 `next` 指针。
    5. 否则 (要移除的节点是头节点)，将链表的头指针 `(list).head` 设置为要移除节点的 `next` 指针。
    6. 使用 `INIT_LINK_TYPE` 或 `INIT_LINK` 重新初始化被移除节点的链接指针，表示它不再链接到任何链表。

* **`PREV(elt, link)` 和 `NEXT(elt, link)`:** 直接返回指定元素的链接结构体的 `prev` 和 `next` 成员。

* **`INSERT_BEFORE(list, before, elt, link)`:**
    1. `INSIST(!LINKED(elt, link));`: 断言要插入的节点当前没有链接到任何链表。
    2. 如果 `before` 节点是头节点 (`(before)->link.prev == NULL`)，则直接调用 `PREPEND` 将 `elt` 添加到链表头部。
    3. 否则，将 `elt` 的 `prev` 指针设置为 `before` 节点的前一个节点。
    4. 将 `before` 节点的前一个节点的 `next` 指针设置为 `elt`。
    5. 将 `before` 节点的 `prev` 指针设置为 `elt`。
    6. 将 `elt` 的 `next` 指针设置为 `before` 节点。

* **`INSERT_AFTER(list, after, elt, link)`:** 逻辑与 `INSERT_BEFORE` 类似，但操作的是在指定节点之后插入。

* **`ENQUEUE(list, elt, link)` 和 `DEQUEUE(list, elt, link)`:** 分别是 `APPEND` 和 `UNLINK` 的别名，用于表示将链表用作队列。

**涉及 dynamic linker 的功能:**

这个头文件本身并没有直接涉及 dynamic linker 的功能。它只是一个通用的链表实现。然而，dynamic linker 内部可能会使用类似的数据结构来管理已加载的共享库、符号表等。

**假设的 so 布局样本和链接处理过程 (Dynamic Linker 使用链表的例子):**

假设 dynamic linker 使用一个链表来管理已加载的共享库 (SO)。每个 SO 可以用一个结构体表示，其中包含 SO 的名称、加载地址、符号表等信息，并且嵌入了一个 `LINK(so_info)` 类型的成员用于链表操作。

```c
// 假设的 so_info 结构体
struct so_info {
    char *name;
    void *load_address;
    // ... 其他信息
    LINK(so_info) link;
};

// 假设的全局 SO 链表
LIST(so_info) loaded_libraries;

// 初始化链表 (在 dynamic linker 初始化时)
INIT_LIST(loaded_libraries);

// 加载 SO 时：
struct so_info *new_so = malloc(sizeof(struct so_info));
// ... 初始化 new_so 的其他成员 ...
APPEND(loaded_libraries, new_so, link);

// 查找符号时：
struct so_info *current_so;
for (current_so = HEAD(loaded_libraries); current_so != NULL; current_so = NEXT(current_so, link)) {
    // 在 current_so 的符号表中查找符号
    // ...
}

// 卸载 SO 时：
// ... 找到要卸载的 so_info ...
UNLINK(loaded_libraries, so_to_unload, link);
free(so_to_unload);
```

**链接处理过程:** 当程序需要使用共享库中的函数时，dynamic linker 会遍历 `loaded_libraries` 链表，查找包含该符号的 SO。

**逻辑推理的假设输入与输出:**

假设我们有一个存储整数的链表：

```c
LIST(int) my_list;
INIT_LIST(my_list);

struct node {
    int data;
    LINK(node) link;
};

// 假设的节点创建函数
struct node* create_node(int value) {
    struct node* n = malloc(sizeof(struct node));
    n->data = value;
    INIT_LINK(n, link);
    return n;
}

struct node *node1 = create_node(10);
struct node *node2 = create_node(20);
struct node *node3 = create_node(30);
```

* **输入:**
    * 空链表 `my_list`
    * 节点 `node1` (data: 10)
    * 节点 `node2` (data: 20)
    * 节点 `node3` (data: 30)

* **操作和输出:**
    * `PREPEND(my_list, node1, link);`  -> `my_list.head` 指向 `node1`, `my_list.tail` 指向 `node1`
    * `APPEND(my_list, node2, link);`   -> `my_list.head` 指向 `node1`, `my_list.tail` 指向 `node2`, `node1->link.next` 指向 `node2`, `node2->link.prev` 指向 `node1`
    * `PREPEND(my_list, node3, link);`  -> `my_list.head` 指向 `node3`, `my_list.tail` 指向 `node2`, `node3->link.next` 指向 `node1`, `node1->link.prev` 指向 `node3`
    * `UNLINK(my_list, node1, link);`   -> `my_list.head` 指向 `node3`, `my_list.tail` 指向 `node2`, `node3->link.next` 指向 `node2`, `node2->link.prev` 指向 `node3`

**用户或编程常见的使用错误:**

1. **内存泄漏:**  在从链表中移除节点后，没有 `free` 掉节点所占用的内存。
   ```c
   UNLINK(my_list, node1, link);
   // 忘记 free(node1);
   ```

2. **访问空链表的头部或尾部:**  在链表为空时尝试访问 `HEAD(list)` 或 `TAIL(list)` 会导致空指针解引用。
   ```c
   LIST(int) empty_list;
   INIT_LIST(empty_list);
   struct node *head = HEAD(empty_list); // head 将为 NULL
   if (head != NULL) {
       // ...
   }
   ```

3. **操作未初始化的链接:**  在将节点添加到链表之前，没有调用 `INIT_LINK` 初始化节点的链接成员。这会导致 `LINKED` 宏判断错误，甚至可能导致程序崩溃。
   ```c
   struct node *bad_node = malloc(sizeof(struct node));
   bad_node->data = 40;
   // 忘记 INIT_LINK(bad_node, link);
   PREPEND(my_list, bad_node, link); // 可能导致 INSIST 失败或更严重的问题
   ```

4. **双重释放:**  多次 `free` 同一个节点。

5. **野指针:**  在节点被 `free` 之后，仍然尝试访问该节点的成员。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤。**

由于这是一个非常底层的库，直接从 Android Framework 或 NDK 代码中直接调用这些宏的情况可能比较少见。更常见的是，Framework 或 NDK 使用 Bionic libc 提供的更高级别的抽象，而这些抽象在内部使用了这些链表宏。

例如，Android 的 `libbinder` (用于 Binder IPC) 可能会在内部使用链表来管理事务。Framework 层通过 Binder 与系统服务进行通信，最终可能会触发 `libbinder` 中链表操作相关的代码。

**Frida Hook 示例:**

假设我们想 hook `APPEND` 宏，看看什么时候有节点被添加到链表中。由于 `APPEND` 是一个宏，我们无法直接 hook。我们需要找到实际调用 `APPEND` 的 C 代码。假设我们找到了一个名为 `add_connection` 的函数，它内部使用了 `APPEND` 将连接添加到全局连接列表中。

```python
import frida

# 要 hook 的进程名称
process_name = "com.android.system_server"

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "add_connection"), {
    onEnter: function(args) {
        console.log("add_connection called!");
        // 假设第一个参数是要添加的节点，可以打印其信息
        // console.log("Node data:", Memory.readU32(args[0]));
    },
    onLeave: function(retval) {
        console.log("add_connection returned:", retval);
    }
});

// 如果你想 hook APPEND 宏展开后的代码，需要更精细的分析和汇编级别的 hook
// 这通常更复杂，需要找到 APPEND 宏展开后的指令地址
"""

def on_message(message, data):
    print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([process_name])
    session = device.attach(pid)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input()  # Keep the script running
except frida.ServerNotStartedError:
    print("Frida server is not running on the device.")
except frida.TimedOutError:
    print("Timeout connecting to the device.")
except frida.ProcessNotFoundError:
    print(f"Process '{process_name}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")
```

**解释:**

1. **`Interceptor.attach`:**  Frida 的核心功能，用于拦截函数调用。
2. **`Module.findExportByName("libc.so", "add_connection")`:**  找到 `libc.so` 中名为 `add_connection` 的导出函数的地址。你需要根据实际情况替换函数名。
3. **`onEnter` 和 `onLeave`:**  在目标函数调用前后执行的回调函数。
4. **`args`:**  `onEnter` 回调函数的参数，包含了目标函数的参数。你需要根据目标函数的签名来解析这些参数。
5. **`Memory.readU32(args[0])`:**  一个示例，假设要添加的节点的结构体的第一个成员是一个 32 位整数，用于读取该值。

**Hook `APPEND` 宏的更深入方法:**

直接 hook 宏是很困难的，因为宏在编译时就被展开了。要 hook `APPEND` 的效果，你需要：

1. **找到 `APPEND` 宏在特定上下文中的展开代码:** 使用反汇编工具 (如 `ida`, `ghidra`) 或 `objdump` 分析使用了 `APPEND` 的 Bionic libc 代码，找到 `APPEND` 宏展开后的汇编指令序列。
2. **Hook 展开后的指令序列的起始地址:** 使用 Frida 的 `Interceptor.attach` 功能，但需要提供具体的内存地址，而不是函数名。这需要更深入的底层知识。

这种方法更加复杂，需要对汇编语言和目标代码的内存布局有深入的理解。通常，hook 更高层次的函数是更可行的调试方法。

总而言之，`list.h` 提供了一个基础且高效的双向链表实现，虽然它本身不涉及动态链接，但作为 Bionic libc 的一部分，被 Android 系统和应用程序的各种组件广泛使用，为构建更复杂的数据结构和算法提供了基础。理解其功能和使用方式对于理解 Android 底层机制至关重要。

Prompt: 
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/include/isc/list.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: list.h,v 1.6 2022/04/19 20:32:15 rillig Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1997,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef LIST_H
#define LIST_H 1
#include <isc/assertions.h>

#define LIST(type) struct { type *head, *tail; }
#define INIT_LIST(list) \
	do { (list).head = NULL; (list).tail = NULL; } while (0)

#define LINK(type) struct { type *prev, *next; }
#define INIT_LINK_TYPE(elt, link, type) \
	do { \
		(elt)->link.prev = (type *)(-1); \
		(elt)->link.next = (type *)(-1); \
	} while (0)
#define INIT_LINK(elt, link) \
	INIT_LINK_TYPE(elt, link, void)
#define LINKED(elt, link) ((void *)((elt)->link.prev) != (void *)(-1) && \
			   (void *)((elt)->link.next) != (void *)(-1))

#define HEAD(list) ((list).head)
#define TAIL(list) ((list).tail)
#define EMPTY(list) ((list).head == NULL)

#define PREPEND(list, elt, link) \
	do { \
		INSIST(!LINKED(elt, link));\
		if ((list).head != NULL) \
			(list).head->link.prev = (elt); \
		else \
			(list).tail = (elt); \
		(elt)->link.prev = NULL; \
		(elt)->link.next = (list).head; \
		(list).head = (elt); \
	} while (0)

#define APPEND(list, elt, link) \
	do { \
		INSIST(!LINKED(elt, link));\
		if ((list).tail != NULL) \
			(list).tail->link.next = (elt); \
		else \
			(list).head = (elt); \
		(elt)->link.prev = (list).tail; \
		(elt)->link.next = NULL; \
		(list).tail = (elt); \
	} while (0)

#define UNLINK_TYPE(list, elt, link, type) \
	do { \
		INSIST(LINKED(elt, link));\
		if ((elt)->link.next != NULL) \
			(elt)->link.next->link.prev = (elt)->link.prev; \
		else { \
			INSIST((list).tail == (elt)); \
			(list).tail = (elt)->link.prev; \
		} \
		if ((elt)->link.prev != NULL) \
			(elt)->link.prev->link.next = (elt)->link.next; \
		else { \
			INSIST((list).head == (elt)); \
			(list).head = (elt)->link.next; \
		} \
		INIT_LINK_TYPE(elt, link, type); \
	} while (0)
#define UNLINK(list, elt, link) \
	UNLINK_TYPE(list, elt, link, void)

#define PREV(elt, link) ((elt)->link.prev)
#define NEXT(elt, link) ((elt)->link.next)

#define INSERT_BEFORE(list, before, elt, link) \
	do { \
		INSIST(!LINKED(elt, link));\
		if ((before)->link.prev == NULL) \
			PREPEND(list, elt, link); \
		else { \
			(elt)->link.prev = (before)->link.prev; \
			(before)->link.prev = (elt); \
			(elt)->link.prev->link.next = (elt); \
			(elt)->link.next = (before); \
		} \
	} while (0)

#define INSERT_AFTER(list, after, elt, link) \
	do { \
		INSIST(!LINKED(elt, link));\
		if ((after)->link.next == NULL) \
			APPEND(list, elt, link); \
		else { \
			(elt)->link.next = (after)->link.next; \
			(after)->link.next = (elt); \
			(elt)->link.next->link.prev = (elt); \
			(elt)->link.prev = (after); \
		} \
	} while (0)

#define ENQUEUE(list, elt, link) APPEND(list, elt, link)
#define DEQUEUE(list, elt, link) UNLINK(list, elt, link)

#endif /* LIST_H */
/*! \file */

"""

```