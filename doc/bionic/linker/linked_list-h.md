Response:
Let's break down the thought process for analyzing the provided C++ code snippet of a linked list implementation.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `LinkedList` implementation, covering its functionality, relationship to Android, libc function explanations, dynamic linker aspects, usage examples, common errors, tracing via Frida, and a detailed explanation in Chinese.

**2. Initial Code Scan & High-Level Understanding:**

* **`LinkedListEntry`:**  The fundamental building block of the linked list. It holds a pointer to the next entry and a pointer to the actual data (`element`).
* **`LinkedListIterator`:**  Provides a way to traverse the linked list. It implements the basic iterator operations (`++, *, ==, !=`).
* **`LinkedList`:**  The main class that manages the list. It contains the `head` and `tail` pointers, and methods for adding, removing, and accessing elements.
* **Templates:**  The use of templates (`typename T`, `typename Allocator`) makes the list generic, usable with different data types and memory allocation strategies.
* **`Allocator`:**  This is a crucial design choice. It decouples the linked list logic from the specific way memory is managed. This allows for custom allocators, which is relevant in environments like Android where memory management can be specialized.
* **Core Operations:**  The code clearly implements standard linked list operations like `push_front`, `push_back`, `pop_front`, `front`, `clear`, `remove`, `find`, etc.

**3. Analyzing Functionality (Instruction 1):**

At this stage, the thought process is to systematically go through each method of the `LinkedList` class and describe its purpose. Keywords like "add to the beginning," "add to the end," "remove from the beginning," "traverse," "search," etc., are used to create concise descriptions.

**4. Connecting to Android (Instruction 2):**

The prompt explicitly mentions `bionic/linker`. This immediately triggers the thought: "How is a linked list used in a dynamic linker?"

* **Dynamic Linker Context:**  The dynamic linker (`linker` or `ld.so`) is responsible for loading shared libraries (`.so` files) and resolving symbols. It needs to keep track of loaded libraries, their dependencies, and exported symbols.
* **Potential Use Cases:**  Linked lists are a suitable data structure for maintaining collections of things where insertions and deletions are frequent and the order matters (or doesn't matter much, but sequential access is needed). Possible candidates in the linker include:
    * Loaded shared objects (`soinfo` structures in the actual linker code).
    * Global variables that need initialization.
    * Symbol tables.
    * Dependency graphs.
* **Example:**  The example provided in the answer—managing `soinfo` structures—is a very relevant and likely use case. The comment in the code itself about saving memory in the Zygote by separating the header supports this idea.

**5. Explaining Libc Functions (Instruction 3):**

The code *doesn't* directly use standard `libc` functions for memory allocation (`malloc`, `free`). Instead, it uses a template parameter `Allocator`. This is a deliberate design choice.

* **Key Insight:** The `Allocator` abstraction is the important point here. It allows the linked list to be used with different memory management strategies, potentially including custom allocators within the linker itself for performance or specific memory regions.
* **Explaining the Abstraction:** Focus on the purpose of `Allocator` and how it provides `alloc()` and `free()`. Acknowledge that the *specific* implementation of `Allocator` might use `malloc`/`free` or other mechanisms.

**6. Dynamic Linker Details (Instruction 4):**

* **`soinfo` Structure:** Introduce the concept of `soinfo` (or a similar structure) that the linker uses to represent a loaded shared object.
* **Sample Layout:**  Create a simplified representation of how `soinfo` objects might be linked together in memory. Show the `head` and `tail` pointers of the `LinkedList` pointing to `soinfo` entries.
* **Linking Process:** Describe the high-level steps involved when the linker needs to load a new shared library and add its `soinfo` to the list. This involves:
    1. Opening the `.so` file.
    2. Parsing the ELF headers.
    3. Creating an `soinfo` structure.
    4. Adding the `soinfo` to the linked list using `push_back` or `push_front`.
* **Assumptions:** Be explicit about any assumptions made (e.g., the existence of an `soinfo` structure).

**7. Logical Reasoning and I/O Examples (Instruction 5):**

* **Simple Operations:** Focus on demonstrating the behavior of basic operations like adding and removing elements.
* **Illustrative Scenarios:** Choose scenarios that clearly show how the list's structure changes.
* **Input/Output Format:** Define clear inputs (method calls and data) and outputs (state of the list).

**8. Common Usage Errors (Instruction 6):**

Think about typical mistakes developers make when working with linked lists:

* **Null Pointer Dereferences:** Accessing `next` or `element` on a null entry.
* **Memory Leaks:** Forgetting to `free` allocated nodes.
* **Dangling Pointers:**  Referencing memory that has already been freed.
* **Iterator Invalidation:** Modifying the list structure while iterating.

**9. Android Framework/NDK Path (Instruction 7):**

This requires tracing the execution flow from a high-level Android component down to the linker's linked list.

* **NDK Scenario:**  A native library is loaded. This is the most direct path.
* **Framework Scenario:** An Android app uses a shared library provided by the system or another app.
* **Key Players:**  Mention the `System.loadLibrary()` call (or similar), the `dlopen()` function in the NDK, and how these eventually trigger the dynamic linker.
* **Simplified Explanation:**  Don't need to go into extreme low-level detail, but highlight the key stages.

**10. Frida Hooking (Instruction 8):**

* **Targeting Key Functions:**  Identify important functions in the `LinkedList` class, such as `push_back`, `pop_front`, `remove`, or even the constructor/destructor.
* **Frida Basics:** Show the basic syntax for hooking functions using `Interceptor.attach`.
* **Logging Information:** Demonstrate how to log arguments and return values to observe the list's behavior.

**11. Language and Formatting (Implicit):**

The request specifies Chinese output. Ensure accurate translation of technical terms. Use clear and organized formatting (headings, bullet points, code blocks) to make the explanation easy to read.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `Allocator` *is* directly `malloc`/`free`.
* **Correction:**  The code uses a template, indicating abstraction. Focus on the abstraction.
* **Initial thought:** Explain every detail of the linking process.
* **Correction:**  Keep the linker explanation at a high level, focusing on how the linked list is used.
* **Initial thought:**  Provide very complex Frida scripts.
* **Correction:**  Keep the Frida examples simple and focused on demonstrating the hooking concept.

By following these steps and constantly refining the analysis, you can generate a comprehensive and accurate answer that addresses all aspects of the request. The key is to break the problem down, understand the code's purpose and context, and then systematically address each point in the prompt.
好的，我们来详细分析一下 `bionic/linker/linked_list.handroid` 这个源代码文件。

**功能列举**

这个文件定义了一个通用的**链表 (Linked List)** 数据结构的模板类 `LinkedList`。它的主要功能包括：

1. **存储元素:** 可以存储任意类型的元素 `T`，通过 `T* element` 指针持有元素。
2. **动态增删:**  提供了在链表头部和尾部添加 (`push_front`, `push_back`) 和删除 (`pop_front`, `remove`, `remove_if`) 元素的功能。
3. **访问元素:**  可以访问链表的头部元素 (`front`)。
4. **遍历:** 提供了迭代器 (`LinkedListIterator`) 和 `for_each`, `visit` 方法来遍历链表中的所有元素。
5. **查找:**  提供了 `find`, `find_if` 方法来查找特定的元素。
6. **清空:**  提供了 `clear` 方法来移除链表中的所有元素。
7. **判空:**  提供了 `empty` 方法来检查链表是否为空。
8. **大小:** 提供了 `size` 方法来获取链表中元素的数量。
9. **包含:** 提供了 `contains` 方法来检查链表是否包含特定元素。
10. **复制到数组:** 提供了 `copy_to_array` 方法将链表中的元素复制到数组中。

**与 Android 功能的关系及举例说明**

这个链表实现是 Android Bionic 库的一部分，尤其是位于 `bionic/linker` 目录下，这表明它主要服务于 **动态链接器 (dynamic linker)**。动态链接器负责在程序运行时加载共享库 (`.so` 文件) 并解析符号。

**举例说明:**

* **管理已加载的共享库 (Shared Objects):** 动态链接器需要维护一个已加载的共享库列表。`LinkedList` 可以用来存储这些共享库的信息，例如 `soinfo` 结构体。`soinfo` 结构体包含了共享库的路径、加载地址、依赖关系等信息。
    * 当一个新的共享库被加载时，动态链接器会创建一个 `soinfo` 对象，并使用 `push_back` 将其添加到链表中。
    * 当需要查找某个共享库时，可以使用 `find_if` 遍历链表，根据共享库的名字或其他属性进行查找。
    * 当一个共享库被卸载时，可以使用 `remove` 将其从链表中移除。

* **管理全局变量初始化器:** 动态链接器需要在所有共享库加载完成后，按照一定的顺序调用它们的全局变量初始化器。`LinkedList` 可以用来存储这些初始化器函数指针，然后按顺序调用。

* **管理依赖关系:**  共享库之间可能存在依赖关系。可以使用 `LinkedList` 来存储某个共享库的依赖项列表。

**详细解释 libc 函数的功能是如何实现的**

**注意：** 这个 `linked_list.handroid` 文件本身并没有直接调用任何标准的 C 库 (`libc`) 函数，例如 `malloc` 或 `free`。  它使用了模板参数 `Allocator` 来抽象内存分配和释放的操作。

* **`Allocator` 模板参数:**  这个设计允许 `LinkedList` 类使用不同的内存分配策略。在 `bionic/linker` 中，可能会使用自定义的分配器，以便更好地管理内存，例如使用匿名映射 (`mmap`) 或从预先分配的内存池中分配。

* **如果 `Allocator` 最终使用了 `malloc` 和 `free`:**
    * **`malloc(size_t size)`:**  `malloc` 函数用于在堆上分配指定大小的内存块。它会返回一个指向新分配内存的指针，如果分配失败则返回 `NULL`。
    * **`free(void* ptr)`:** `free` 函数用于释放之前由 `malloc`, `calloc`, 或 `realloc` 分配的内存。传递给 `free` 的指针必须是之前由这些函数返回的有效指针。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

**so 布局样本 (简化版):**

假设我们有两个共享库 `liba.so` 和 `libb.so`，`libb.so` 依赖于 `liba.so`。

```
// liba.so 内存布局 (简化)
-------------------------------------
| ELF Header                        |
-------------------------------------
| .text (代码段)                     |
|   - function_a1 ...               |
-------------------------------------
| .rodata (只读数据段)              |
|   - global_ro_var_a ...          |
-------------------------------------
| .data (已初始化数据段)            |
|   - global_var_a ...             |
-------------------------------------
| .bss (未初始化数据段)            |
|   - uninitialized_var_a ...      |
-------------------------------------
| .dynamic (动态链接信息)           |
|   - DT_NEEDED: libb.so           | // 指示依赖于 libb.so
|   - ...                           |
-------------------------------------
| Symbol Table                      |
|   - function_a1 symbol info     |
|   - global_ro_var_a symbol info |
|   - global_var_a symbol info    |
|   - ...                           |
-------------------------------------

// libb.so 内存布局 (简化)
-------------------------------------
| ELF Header                        |
-------------------------------------
| .text (代码段)                     |
|   - function_b1 ...               |
-------------------------------------
| .rodata (只读数据段)              |
|   - global_ro_var_b ...          |
-------------------------------------
| .data (已初始化数据段)            |
|   - global_var_b ...             |
-------------------------------------
| .bss (未初始化数据段)            |
|   - uninitialized_var_b ...      |
-------------------------------------
| .dynamic (动态链接信息)           |
|   - DT_NEEDED: liba.so           | // 指示依赖于 liba.so
|   - ...                           |
-------------------------------------
| Symbol Table                      |
|   - function_b1 symbol info     |
|   - global_ro_var_b symbol info |
|   - global_var_b symbol info    |
|   - ...                           |
-------------------------------------
```

**链接的处理过程 (简化):**

1. **加载可执行文件:** 当操作系统启动一个程序时，会加载可执行文件到内存。
2. **加载依赖库:** 可执行文件的 `.dynamic` 段会包含它所依赖的共享库的信息。动态链接器会首先加载这些直接依赖的库，例如 `liba.so`。
3. **递归加载依赖:**  `liba.so` 的 `.dynamic` 段可能又会依赖其他的库。动态链接器会递归地加载所有依赖的库。
4. **`soinfo` 创建和管理:** 对于每个加载的共享库，动态链接器会创建一个 `soinfo` 结构体来记录其信息。这个 `soinfo` 对象会被添加到一个 `LinkedList` 中进行管理。
5. **符号解析 (Symbol Resolution):**
   - 当程序或某个共享库需要调用其他共享库中的函数或访问其全局变量时，就需要进行符号解析。
   - 动态链接器会查找被调用函数或变量的符号。
   - 它会遍历已加载共享库的 `LinkedList`，并在每个 `soinfo` 中查找符号表。
   - 一旦找到匹配的符号，动态链接器会将调用地址或变量地址更新为实际的地址。这通常涉及修改程序的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table)。
6. **重定位 (Relocation):** 加载共享库时，其代码和数据可能需要在内存中进行重定位，因为加载地址可能不是编译时的地址。动态链接器会根据重定位信息修改代码和数据中的地址。

**在 `LinkedList` 上的操作:**

* 当加载 `liba.so` 时，会创建一个 `soinfo` 对象，并使用 `push_back` 添加到 `LinkedList` 中。
* 当加载 `libb.so` 时，也会创建一个 `soinfo` 对象，并添加到 `LinkedList` 中。
* 当解析 `libb.so` 中对 `liba.so` 中 `function_a1` 的调用时，动态链接器会遍历 `soinfo` 链表，找到 `liba.so` 的 `soinfo`，然后在 `liba.so` 的符号表中查找 `function_a1` 的地址。

**逻辑推理，给出假设输入与输出**

假设我们有一个 `LinkedList<int, SomeAllocator>` 类型的链表 `my_list`。

**场景 1: `push_back` 和 `front`**

* **假设输入:**
    ```c++
    my_list.push_back(10);
    my_list.push_back(20);
    int* first_element = my_list.front();
    ```
* **预期输出:** `first_element` 指向的值为 `10`。链表内部结构： `head` 指向包含 `10` 的节点，该节点的 `next` 指向包含 `20` 的节点，包含 `20` 的节点的 `next` 为 `nullptr`，`tail` 指向包含 `20` 的节点。

**场景 2: `push_front` 和 `pop_front`**

* **假设输入:**
    ```c++
    my_list.push_front(5);
    my_list.push_front(3);
    int* removed_element = my_list.pop_front();
    ```
* **预期输出:** `removed_element` 指向的值为 `3`。链表内部结构： `head` 指向包含 `5` 的节点，该节点的 `next` 为 `nullptr`，`tail` 指向包含 `5` 的节点。

**场景 3: `remove`**

* **假设输入:**
    ```c++
    my_list.push_back(1);
    my_list.push_back(2);
    my_list.push_back(3);
    int value_to_remove = 2;
    my_list.remove(&value_to_remove);
    ```
* **预期输出:** 链表中包含 `1` 和 `3`。链表内部结构： `head` 指向包含 `1` 的节点，该节点的 `next` 指向包含 `3` 的节点，包含 `3` 的节点的 `next` 为 `nullptr`，`tail` 指向包含 `3` 的节点。

**涉及用户或者编程常见的使用错误，请举例说明**

1. **空指针解引用:** 在链表为空时调用 `front()` 或 `pop_front()`，或者在迭代器指向 `nullptr` 时尝试解引用。
   ```c++
   LinkedList<int, SomeAllocator> empty_list;
   int* value = empty_list.front(); // value 将为 nullptr
   if (value != nullptr) {
       // ... 使用 value，如果没检查空指针就会出错
   }

   for (auto it = empty_list.begin(); it != empty_list.end(); ++it) {
       int val = *it; // 当 empty_list 为空时，begin() == end()，循环体不会执行，没问题
   }
   ```

2. **内存泄漏:**  如果 `Allocator::free()` 没有正确释放分配的内存，或者在使用 `remove` 或 `clear` 时没有正确释放链表节点的内存。
   ```c++
   // 假设 Allocator 的实现不正确，没有真正释放内存
   LinkedList<int, SomeAllocator> leaky_list;
   for (int i = 0; i < 1000; ++i) {
       leaky_list.push_back(new int(i));
   }
   leaky_list.clear(); // 如果 Allocator::free 没有释放 new int(i) 分配的内存，就会发生泄漏
   ```

3. **迭代器失效:** 在遍历链表的过程中修改链表的结构（例如，插入或删除元素），可能导致迭代器失效。
   ```c++
   LinkedList<int, SomeAllocator> list;
   list.push_back(1);
   list.push_back(2);
   list.push_back(3);

   for (auto it = list.begin(); it != list.end(); ++it) {
       if (*it == 2) {
           list.remove(&*it); // 错误：在遍历时删除当前迭代器指向的元素，可能导致迭代器失效
       }
   }
   ```
   **正确的做法是使用 `remove_if` 或在删除后重新调整迭代器。**

4. **删除不存在的元素:** `remove` 函数会遍历链表查找元素，如果元素不存在，则不会执行任何操作，但不会报错。用户需要确保要删除的元素确实在链表中。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤**

**Android Framework 到达 `LinkedList` 的路径 (举例说明，可能因 Android 版本和具体场景而异):**

1. **Framework 请求加载 Native Library:**  Android Framework 中的 Java 代码（例如，Activity 中的 `System.loadLibrary("mylib")`）请求加载一个 Native Library (`mylib.so`)。

2. **`Runtime.loadLibrary0` (Java):**  `System.loadLibrary` 调用最终会到达 `java.lang.Runtime` 的 `loadLibrary0` 方法。

3. **`nativeLoad` (Native, libdl.so):**  `loadLibrary0` 会调用一个 Native 方法 `nativeLoad`，这个方法位于 `libdl.so` (Android 的动态链接器包装库) 中。

4. **`do_dlopen` 或 `android_dlopen_ext` (Native, linker):** `libdl.so` 中的代码最终会调用 Bionic 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 的 `do_dlopen` 或 `android_dlopen_ext` 函数。

5. **动态链接器加载流程:** 在动态链接器的 `do_dlopen` 等函数中，会进行一系列操作，包括：
   - 查找共享库文件。
   - 解析 ELF 文件头和段。
   - 创建 `soinfo` 结构体来表示加载的共享库。
   - **将新创建的 `soinfo` 对象添加到某个 `LinkedList` 中进行管理。**  这就是我们分析的 `bionic/linker/linked_list.handroid` 可能被使用的地方。

**NDK 到达 `LinkedList` 的路径:**

1. **NDK 代码调用 `dlopen`:**  使用 NDK 开发的 Native 代码可以直接调用 `dlopen("anotherlib.so", ...)` 来加载其他的共享库。

2. **`dlopen` (Native, libdl.so):**  NDK 中的 `dlopen` 函数实际上是调用了 `libdl.so` 中的 `dlopen` 实现。

3. **后续步骤与 Framework 类似:**  `libdl.so` 的 `dlopen` 最终也会调用 Bionic 动态链接器的加载函数，并可能使用 `LinkedList` 来管理加载的共享库。

**Frida Hook 示例:**

假设我们想观察动态链接器在加载共享库时如何使用 `LinkedList` 的 `push_back` 方法。我们可以 hook `LinkedList::push_back` 函数。

```python
import frida
import sys

# 替换为你的设备/模拟器上的进程名或 PID
process_name = "com.example.myapp"

try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {process_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("linker64", "_ZN8LinkedListI6soinfo11MallocatorE9push_backEP6soinfo"), { // 替换为实际的符号名，可能需要根据linker版本调整
    onEnter: function(args) {
        console.log("LinkedList::push_back called!");
        var soinfoPtr = args[1];
        if (soinfoPtr) {
            // 读取 soinfo 结构体的信息，例如 dso 文件名
            var dsoNamePtr = ptr(soinfoPtr).readPointer(); // 假设 soinfo 第一个成员是指向 dso name 的指针
            if (dsoNamePtr) {
                console.log("  soinfo->dso_name: " + dsoNamePtr.readCString());
            }
        }
    },
    onLeave: function(retval) {
        console.log("LinkedList::push_back returned.");
    }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **`frida.attach(process_name)`:** 连接到目标 Android 进程。
2. **`Module.findExportByName("linker64", "_ZN8LinkedListI6soinfo11MallocatorE9push_backEP6soinfo")`:**  找到 `linker64` 模块中 `LinkedList<soinfo, Mallocator>::push_back(soinfo*)` 函数的地址。**注意：** 这个符号名是 mangled 后的 C++ 函数名，需要根据具体的编译器和链接器版本进行调整。可以使用 `adb shell "grep push_back /proc/<pid>/maps"` 或类似的命令来辅助查找。
3. **`Interceptor.attach(...)`:**  拦截 `push_back` 函数的调用。
4. **`onEnter`:**  在 `push_back` 函数被调用前执行的代码。
   - `args[0]` 是 `this` 指针。
   - `args[1]` 是传递给 `push_back` 的 `soinfo*` 指针。
   - 代码尝试读取 `soinfo` 结构体中的 `dso_name` 成员，以了解正在加载的共享库的名称。  **这需要对 `soinfo` 的结构有一定的了解。**
5. **`onLeave`:** 在 `push_back` 函数返回后执行的代码。

**使用 Frida Hook 进行调试的步骤:**

1. **准备环境:** 确保你的 Android 设备或模拟器已 root，并且安装了 Frida Server。
2. **运行目标应用:** 启动你想要分析的 Android 应用。
3. **运行 Frida 脚本:** 在你的电脑上运行上面的 Python Frida 脚本，将 `process_name` 替换为你的应用的进程名。
4. **观察输出:** 当应用加载新的共享库时，Frida 脚本会输出 `LinkedList::push_back called!` 和相关 `soinfo` 的信息，从而帮助你理解动态链接器如何使用链表管理共享库。

**总结**

`bionic/linker/linked_list.handroid` 提供了一个通用的链表数据结构，主要被 Android Bionic 的动态链接器用于管理加载的共享库等信息。理解其功能和使用场景，并结合 Frida 等工具进行动态调试，可以帮助我们深入了解 Android 系统底层的运作机制。

### 提示词
```
这是目录为bionic/linker/linked_list.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#pragma once

#include <android-base/macros.h>

template<typename T>
struct LinkedListEntry {
  LinkedListEntry<T>* next;
  T* element;
};

// ForwardInputIterator
template<typename T>
class LinkedListIterator {
 public:
  LinkedListIterator() : entry_(nullptr) {}
  LinkedListIterator(const LinkedListIterator<T>& that) : entry_(that.entry_) {}
  explicit LinkedListIterator(LinkedListEntry<T>* entry) : entry_(entry) {}

  LinkedListIterator<T>& operator=(const LinkedListIterator<T>& that) {
    entry_ = that.entry_;
    return *this;
  }

  LinkedListIterator<T>& operator++() {
    entry_ = entry_->next;
    return *this;
  }

  T* const operator*() {
    return entry_->element;
  }

  bool operator==(const LinkedListIterator<T>& that) const {
    return entry_ == that.entry_;
  }

  bool operator!=(const LinkedListIterator<T>& that) const {
    return entry_ != that.entry_;
  }

 private:
  LinkedListEntry<T> *entry_;
};

/*
 * Represents linked list of objects of type T
 */
template<typename T, typename Allocator>
class LinkedList {
 public:
  typedef LinkedListIterator<T> iterator;
  typedef T* value_type;

  // Allocating the head/tail fields separately from the LinkedList struct saves memory in the
  // Zygote (e.g. because adding an soinfo to a namespace doesn't dirty the page containing the
  // soinfo).
  struct LinkedListHeader {
    LinkedListEntry<T>* head;
    LinkedListEntry<T>* tail;
  };

  // The allocator returns a LinkedListEntry<T>* but we want to treat it as a LinkedListHeader
  // struct instead.
  static_assert(sizeof(LinkedListHeader) == sizeof(LinkedListEntry<T>));
  static_assert(alignof(LinkedListHeader) == alignof(LinkedListEntry<T>));

  constexpr LinkedList() : header_(nullptr) {}
  ~LinkedList() {
    clear();
    if (header_ != nullptr) {
      Allocator::free(reinterpret_cast<LinkedListEntry<T>*>(header_));
    }
  }

  LinkedList(LinkedList&& that) noexcept {
    this->header_ = that.header_;
    that.header_ = nullptr;
  }

  bool empty() const {
    return header_ == nullptr || header_->head == nullptr;
  }

  void push_front(T* const element) {
    alloc_header();
    LinkedListEntry<T>* new_entry = Allocator::alloc();
    new_entry->next = header_->head;
    new_entry->element = element;
    header_->head = new_entry;
    if (header_->tail == nullptr) {
      header_->tail = new_entry;
    }
  }

  void push_back(T* const element) {
    alloc_header();
    LinkedListEntry<T>* new_entry = Allocator::alloc();
    new_entry->next = nullptr;
    new_entry->element = element;
    if (header_->tail == nullptr) {
      header_->tail = header_->head = new_entry;
    } else {
      header_->tail->next = new_entry;
      header_->tail = new_entry;
    }
  }

  T* pop_front() {
    if (empty()) return nullptr;

    LinkedListEntry<T>* entry = header_->head;
    T* element = entry->element;
    header_->head = entry->next;
    Allocator::free(entry);

    if (header_->head == nullptr) {
      header_->tail = nullptr;
    }

    return element;
  }

  T* front() const {
    return empty() ? nullptr : header_->head->element;
  }

  void clear() {
    if (empty()) return;

    while (header_->head != nullptr) {
      LinkedListEntry<T>* p = header_->head;
      header_->head = header_->head->next;
      Allocator::free(p);
    }

    header_->tail = nullptr;
  }

  template<typename F>
  void for_each(F action) const {
    visit([&] (T* si) {
      action(si);
      return true;
    });
  }

  template<typename F>
  bool visit(F action) const {
    for (LinkedListEntry<T>* e = head(); e != nullptr; e = e->next) {
      if (!action(e->element)) {
        return false;
      }
    }
    return true;
  }

  template<typename F>
  void remove_if(F predicate) {
    if (empty()) return;
    for (LinkedListEntry<T>* e = header_->head, *p = nullptr; e != nullptr;) {
      if (predicate(e->element)) {
        LinkedListEntry<T>* next = e->next;
        if (p == nullptr) {
          header_->head = next;
        } else {
          p->next = next;
        }

        if (header_->tail == e) {
          header_->tail = p;
        }

        Allocator::free(e);

        e = next;
      } else {
        p = e;
        e = e->next;
      }
    }
  }

  void remove(T* element) {
    remove_if([&](T* e) {
      return e == element;
    });
  }

  template<typename F>
  T* find_if(F predicate) const {
    for (LinkedListEntry<T>* e = head(); e != nullptr; e = e->next) {
      if (predicate(e->element)) {
        return e->element;
      }
    }

    return nullptr;
  }

  iterator begin() const {
    return iterator(head());
  }

  iterator end() const {
    return iterator(nullptr);
  }

  iterator find(T* value) const {
    for (LinkedListEntry<T>* e = head(); e != nullptr; e = e->next) {
      if (e->element == value) {
        return iterator(e);
      }
    }

    return end();
  }

  size_t copy_to_array(T* array[], size_t array_length) const {
    size_t sz = 0;
    for (LinkedListEntry<T>* e = head(); sz < array_length && e != nullptr; e = e->next) {
      array[sz++] = e->element;
    }

    return sz;
  }

  bool contains(const T* el) const {
    for (LinkedListEntry<T>* e = head(); e != nullptr; e = e->next) {
      if (e->element == el) {
        return true;
      }
    }
    return false;
  }

  static LinkedList make_list(T* const element) {
    LinkedList<T, Allocator> one_element_list;
    one_element_list.push_back(element);
    return one_element_list;
  }

  size_t size() const {
    size_t result = 0;
    for_each([&](T*) { ++result; });
    return result;
  }

 private:
  void alloc_header() {
    if (header_ == nullptr) {
      header_ = reinterpret_cast<LinkedListHeader*>(Allocator::alloc());
      header_->head = header_->tail = nullptr;
    }
  }

  LinkedListEntry<T>* head() const {
    return header_ != nullptr ? header_->head : nullptr;
  }

  LinkedListHeader* header_;
  DISALLOW_COPY_AND_ASSIGN(LinkedList);
};
```