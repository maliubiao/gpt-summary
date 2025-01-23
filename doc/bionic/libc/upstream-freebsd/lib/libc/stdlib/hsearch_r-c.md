Response:
Let's break down the thought process for analyzing the `hsearch_r.c` code. The goal is to provide a comprehensive explanation as requested by the user.

**1. Initial Understanding and Goal Setting:**

The first step is to recognize the core function of the code: implementing a reentrant hash table search and insertion function. The filename and comments clearly point to `hsearch_r`. The "reentrant" part is crucial, meaning it's thread-safe due to the explicit `htab` parameter. The request asks for:

* Functionality explanation.
* Android relevance and examples.
* Detailed implementation explanation of libc functions.
* Dynamic linker relationship (if any).
* Logical reasoning with input/output examples.
* Common usage errors.
* How Android framework/NDK reaches this code.
* Frida hook examples.

This provides a clear roadmap for the analysis.

**2. High-Level Functionality Extraction:**

Read the code and identify the main purpose of `hsearch_r`. It searches for an entry in a hash table. If the entry isn't found and the action is `ENTER`, it inserts the entry. Key behaviors are:

* **Hashing:** Uses FNV-1a for key hashing.
* **Collision Handling:** Employs quadratic probing.
* **Dynamic Resizing:**  Doubles the hash table size when it's more than 50% full.
* **Reentrancy:**  Operates on a provided `hsearch_data` structure.

**3. Detailed Code Analysis - Breakdown by Function:**

Go through each function and understand its role:

* **`hsearch_lookup_free`:** Finds an empty slot in the hash table using quadratic probing. This is an internal helper function.
* **`hsearch_hash`:** Calculates the hash value of a key. Note the platform-dependent prime numbers for 32-bit and 64-bit architectures.
* **`hsearch_r`:** The main function. It orchestrates the search, insertion, and resizing logic. Pay attention to the control flow, especially the `FIND` and `ENTER` actions.

**4. Identifying Android Relevance:**

Since this code is part of Android's libc (bionic), its relevance is inherent. Consider *where* hash tables are commonly used in operating systems and libraries. Examples include:

* Symbol tables in dynamic linking.
* Caching mechanisms.
* Data structures for efficient lookups.

Specifically for Android, think about how the system might use hash tables for managing loaded libraries, function lookups, or property storage.

**5. Explaining libc Function Implementations:**

Focus on the standard C library functions used within `hsearch_r`:

* **`strcmp`:** String comparison. Explain its basic operation.
* **`calloc`:**  Memory allocation and zeroing. Highlight the importance of zeroing for hash table initialization.
* **`free`:** Memory deallocation.
* **`errno`:**  Setting error codes. Explain its role in signaling failures.

**6. Addressing Dynamic Linker Aspects:**

While `hsearch_r` itself isn't *directly* a dynamic linker function, hash tables are fundamental to dynamic linking. Explain how the dynamic linker uses hash tables to:

* Store symbols (function names, variable names).
* Quickly look up symbols during linking and runtime.

Create a simplified example of an SO layout showing a `.dynsym` (dynamic symbol table) section, which is typically implemented as a hash table. Describe the linking process where the dynamic linker uses this hash table to resolve symbols.

**7. Crafting Logical Reasoning Examples:**

Devise simple scenarios to illustrate `hsearch_r`'s behavior:

* **Successful Search:** Provide an input where the key exists.
* **Successful Insertion:**  Demonstrate adding a new key.
* **Resizing:**  Illustrate how adding enough elements triggers table resizing.
* **Failed Search:** Show a case where the key is not present.

For each example, specify the input (`item`, `action`, initial table state) and the expected output (`retval`, return value, modified table state).

**8. Identifying Common Usage Errors:**

Think about typical mistakes programmers might make when using hash tables:

* **Incorrect Initialization:** Forgetting to initialize the `hsearch_data` structure.
* **`FIND` without `ENTER`:**  Trying to find an element that hasn't been inserted.
* **Memory Management Issues:**  Not freeing the `hsearch_data` structure.
* **Thread Safety Issues (if not using `hsearch_r` correctly):** Although `hsearch_r` is reentrant, using the non-reentrant `hsearch` in a multithreaded environment is a problem.

**9. Tracing the Android Framework/NDK Path:**

Work backward from `hsearch_r`. Consider how an Android application might eventually call this function:

* **NDK:**  A C/C++ application using standard library functions like `hcreate_r`, `hsearch_r`, etc.
* **Android Framework:**  Internal framework components (written in C/C++) might use hash tables for various purposes. Give examples like service management or resource tracking.

Explain the layers involved: Application -> NDK/Framework C/C++ code -> bionic libc -> `hsearch_r`.

**10. Creating Frida Hook Examples:**

Design Frida scripts to intercept calls to `hsearch_r` and related functions:

* **Hooking `hsearch_r`:**  Log input parameters (`item`, `action`, `htab`) and the return value.
* **Hooking `strcmp` within `hsearch_r`:** Show how to hook a function called internally by `hsearch_r` to observe its behavior.
* **Hooking `calloc` during resizing:**  Demonstrate intercepting memory allocation to understand when resizing occurs.

**11. Structuring the Response:**

Organize the information logically using headings and subheadings. Use clear and concise language. Provide code snippets and examples where appropriate. Ensure all parts of the original request are addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the dynamic linker directly calls `hsearch_r`.
* **Correction:**  While the dynamic linker *uses* hash tables, it likely has its own specialized hash table implementations optimized for its specific needs. `hsearch_r` is a general-purpose function. Focus on how the *concept* of hash tables is relevant to the dynamic linker.
* **Initial thought:**  Just explain the code.
* **Correction:**  The request asks for Android context. Actively look for connections to Android system behavior and provide specific examples.
* **Initial thought:** A simple example of `hsearch_r` usage is enough.
* **Correction:**  Provide multiple examples showcasing different scenarios (search, insert, resize, failure) for better understanding.

By following this structured approach and continually refining the analysis, a comprehensive and accurate answer can be constructed.
这个文件 `bionic/libc/upstream-freebsd/lib/libc/stdlib/hsearch_r.c` 是 Android Bionic C 库中 `stdlib` 模块下关于可重入哈希表查找和插入功能的实现。它来源于 FreeBSD 的代码，并被 Android 采用。

**功能列举:**

1. **哈希表查找 (hsearch_r):**  给定一个键值对 (entry)，在指定的哈希表中查找是否存在具有相同键的条目。
2. **哈希表插入 (hsearch_r with ACTION == ENTER):** 如果在哈希表中没有找到具有相同键的条目，并且指定的操作是插入 (`ENTER`)，则将给定的键值对插入到哈希表中。
3. **可重入性:**  函数是可重入的，这意味着它可以在多线程环境下安全地使用，因为它使用用户提供的 `htab` 结构来存储哈希表的状态，而不是使用全局变量。
4. **动态扩容:** 当哈希表的使用率超过 50% 时，会自动扩容，以保持查找效率。
5. **FNV-1a 哈希算法:** 使用 FNV-1a 哈希算法来计算键的哈希值。
6. **二次探测法:** 使用二次探测法来解决哈希冲突。

**与 Android 功能的关系及举例:**

哈希表在 Android 系统中被广泛使用，用于高效地存储和检索数据。`hsearch_r` 提供的可重入哈希表功能在以下场景中可能被使用：

* **动态链接器 (linker):**  虽然这个文件本身不是动态链接器的核心代码，但动态链接器在管理已加载的共享库和符号表时，经常会使用哈希表来快速查找符号（函数名、变量名等）。  例如，当一个应用调用一个共享库中的函数时，动态链接器需要快速找到该函数的地址，哈希表可以提供高效的查找。
* **系统服务管理 (servicemanager):** Android 的 `servicemanager` 使用哈希表来维护系统服务的名称和 Binder 代理之间的映射关系，以便快速查找和访问系统服务。
* **属性服务 (property service):**  Android 的属性系统使用哈希表来存储系统属性的键值对，方便快速读取和设置系统属性。
* **Native 代码中的数据结构:**  使用 NDK 开发的 Native 代码中，如果需要高效的键值对存储和查找，开发者可能会使用 `hcreate_r` 和 `hsearch_r` 来实现自己的哈希表。

**libc 函数的实现细节:**

1. **`hsearch_lookup_free(struct __hsearch *hsearch, size_t hash)`:**
   - **功能:**  在给定的哈希表中查找一个空闲的条目，以便插入新的元素。
   - **实现:**
     - 接收哈希表结构 `hsearch` 和键的哈希值 `hash` 作为输入。
     - 使用二次探测法来查找空闲条目。它从 `hash` 值对应的索引开始，如果该位置已被占用，则按照 `index += ++i` 的方式计算下一个探测的索引，其中 `i` 从 0 开始递增。
     - `index & hsearch->index_mask` 用于将索引限制在哈希表的大小范围内。
     - 循环直到找到一个 `entry->key == NULL` 的空闲条目并返回其指针。
   - **假设输入与输出:**
     - **输入:**  `hsearch` 指向一个已初始化的哈希表，`hash` 是一个计算出的哈希值。假设哈希表中索引为 `hash`, `hash + 1`, `hash + 4` 的位置被占用，那么这个函数会返回索引为 `hash + 9` (因为 i 会依次是 0, 1, 2, 3，对应的偏移是 0, 1, 4, 9) 的空闲条目的指针（假设这个位置是空闲的，并且哈希表大小足够大）。

2. **`hsearch_hash(size_t offset_basis, const char *str)`:**
   - **功能:** 计算给定字符串 `str` 的 FNV-1a 哈希值。
   - **实现:**
     - 接收一个偏移基数 `offset_basis` 和要哈希的字符串 `str`。
     - 初始化哈希值 `hash` 为 `offset_basis`。
     - 遍历字符串 `str` 的每个字符：
       - 将当前字符的 ASCII 值与 `hash` 进行异或操作 (`hash ^= (uint8_t)*str++`)。
       - 根据指针大小（32位或64位），将 `hash` 乘以相应的 FNV 质数 (32 位: 16777619, 64 位: 1099511628211)。
     - 返回计算出的哈希值。
   - **假设输入与输出:**
     - **输入:** `offset_basis = 0`, `str = "test"`
     - **输出:**  一个基于 FNV-1a 算法计算出的哈希值，例如 `2147483647` (实际值取决于架构)。

3. **`hsearch_r(ENTRY item, ACTION action, ENTRY **retval, struct hsearch_data *htab)`:**
   - **功能:**  在哈希表中查找或插入条目。
   - **实现:**
     - 接收要查找/插入的条目 `item`，操作类型 `action` (`FIND` 或 `ENTER`)，用于返回找到的条目指针的 `retval`，以及哈希表数据结构 `htab`。
     - 从 `htab` 中获取底层的哈希表结构 `hsearch`。
     - 使用 `hsearch_hash` 计算 `item.key` 的哈希值。
     - **查找过程:**
       - 使用二次探测法遍历哈希表。
       - 如果找到一个 `entry->key` 为 `NULL` 的空闲位置，则说明没有找到该键，跳出循环。
       - 如果找到一个 `strcmp(entry->key, item.key) == 0` 的条目，则将该条目的指针赋值给 `*retval` 并返回 1 (成功)。
     - **插入过程 (如果 `action == ENTER`):**
       - 如果在查找过程中遇到空闲位置，并且 `action` 为 `ENTER`，则进行插入操作。
       - **动态扩容:**
         - 如果当前哈希表的使用率超过 50% (`hsearch->entries_used * 2 >= hsearch->index_mask`)，则进行扩容：
           - 保存旧的哈希表信息。
           - 分配一个大小是原来两倍的新哈希表。
           - 将旧哈希表中的所有条目重新插入到新哈希表中。注意，由于哈希表大小改变，每个条目的新哈希位置可能不同。
           - 释放旧的哈希表。
           - 重新查找新哈希表中的空闲位置。
       - 将新的 `item` 插入到找到的空闲位置。
       - 更新 `hsearch->entries_used` 计数器。
       - 将新插入的条目的指针赋值给 `*retval` 并返回 1 (成功)。
     - **查找失败:**
       - 如果 `action` 为 `FIND` 且未找到条目，则设置 `errno` 为 `ESRCH` 并返回 0 (失败)。
   - **假设输入与输出:**
     - **假设输入 (查找):** `item.key = "existing_key"`, `action = FIND`, `htab` 指向一个包含键为 "existing_key" 的条目的哈希表。
     - **假设输出 (查找):** `*retval` 指向哈希表中键为 "existing_key" 的 `ENTRY` 结构，函数返回 1。
     - **假设输入 (插入):** `item.key = "new_key"`, `item.data = some_data`, `action = ENTER`, `htab` 指向一个不包含键为 "new_key" 的哈希表。
     - **假设输出 (插入):** `*retval` 指向新插入的 `ENTRY` 结构，该结构的 `key` 为 "new_key"，`data` 为 `some_data`，函数返回 1。如果触发了扩容，则 `htab` 指向的哈希表的大小会增加。

**涉及 dynamic linker 的功能和处理过程:**

虽然 `hsearch_r.c` 本身不是动态链接器的代码，但动态链接器在内部会使用类似哈希表的数据结构来管理符号表 (`.dynsym` 和 `.hash` 节)。

**SO 布局样本:**

```
ELF Header
...
Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  ...
  [ 1] .dynsym           DYNSYM           0x...             0x...
       00000100          00000018         WA       6     1     4
  [ 2] .syrtab.dyn       GNU_HASH         0x...             0x...
       00000020          00000004         WA       5     1     4
  ...
String Table (.dynstr):
  Offset: 0x...
  Contents:
    printf\0
    malloc\0
    ...
Dynamic Section:
  TAG        TYPE              VALUE
  ...
  DT_SYMTAB  (Symbol Table)    0x... // 指向 .dynsym
  DT_STRTAB  (String Table)    0x... // 指向 .dynstr
  DT_HASH    (Symbol Hash Table) 0x... // 指向 .syrtab.dyn
  ...
```

**链接的处理过程:**

1. **加载共享库:** 当动态链接器加载一个共享库 (`.so` 文件) 时，它会解析 SO 文件的头部和节区。
2. **解析符号表:** 动态链接器会读取 `.dynsym` (动态符号表) 节，该节包含了共享库导出的和导入的符号信息（函数名、变量名等）。
3. **构建哈希表:**  `.syrtab.dyn` (或旧式的 `.hash`) 节包含了一个哈希表，用于加速符号查找。动态链接器会使用这个哈希表来快速定位符号在 `.dynsym` 中的位置。
4. **符号查找:** 当程序需要调用一个共享库中的函数时，动态链接器会使用函数名在符号哈希表中查找对应的符号信息。
5. **重定位:**  一旦找到符号，动态链接器会更新程序中的地址，使其指向共享库中函数的实际地址。

**链接过程中的哈希表作用:**  在链接过程中，动态链接器需要解析符号依赖关系，找到需要的符号定义。符号哈希表允许动态链接器以接近常数时间复杂度查找符号，这对于启动速度和运行时性能至关重要。

**用户或编程常见的使用错误:**

1. **未初始化 `hsearch_data` 结构:** 在调用 `hcreate_r` 或手动初始化 `__hsearch` 之前，直接使用 `hsearch_r` 会导致未定义行为。
2. **`action` 参数使用错误:**
   - 在没有调用 `hcreate_r` 或哈希表为空的情况下使用 `action = ENTER` 可能会导致错误。
   - 在只想查找元素时错误地使用 `action = ENTER` 会意外地插入新元素。
3. **键的内存管理问题:** 哈希表存储的是指向键的指针。如果键的内存被释放，哈希表中的指针会变成悬挂指针，导致程序崩溃或数据损坏。用户需要确保键的生命周期长于哈希表中对应条目的生命周期，或者在不再需要哈希表时销毁它。
4. **线程安全问题 (针对非 `_r` 版本):** 如果使用非可重入的 `hsearch`，在多线程环境下进行并发操作会导致数据竞争和未定义的行为。这就是为什么 Android Bionic 主要提供可重入的版本。
5. **假设哈希表总是能找到元素:** 在 `action = FIND` 时，如果没有检查 `hsearch_r` 的返回值，就直接使用 `*retval`，如果元素不存在，`*retval` 的值是未定义的。

**Frida Hook 示例调试步骤:**

假设我们想监控一个 Android 应用中使用 `hsearch_r` 的情况，例如查看插入了哪些键值对。

**假设场景:** 一个 Native 应用使用 `hsearch_r` 来存储配置信息。

**Frida Hook 脚本示例:**

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "hsearch_r"), {
    onEnter: function(args) {
        const itemPtr = ptr(args[0]);
        const action = args[1].toInt32();
        const keyPtr = Memory.readPointer(itemPtr);
        const dataPtr = Memory.readPointer(itemPtr.add(Process.pointerSize)); // 假设 ENTRY 结构是 { void *key; void *data; }
        const key = keyPtr.readUtf8String();
        const actionStr = action === 0 ? "FIND" : "ENTER";
        console.log(`[*] hsearch_r called: action=${actionStr}, key="${key}"`);
        this.key = key; // 保存 key 以便在 onLeave 中使用
    },
    onLeave: function(retval) {
        if (retval.toInt32() !== 0 && this.key) {
            console.log(`[*] hsearch_r ${retval.toInt32() === 1 ? "success" : "failure"} for key "${this.key}"`);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明:**

1. **导入 Frida 库:**  `import frida`
2. **指定目标应用包名:** 将 `your.target.package` 替换为你要监控的 Android 应用的包名。
3. **连接到目标应用:** 使用 `frida.get_usb_device().attach(package_name)` 连接到正在运行的目标应用进程。
4. **编写 Frida 脚本:**
   - `Module.findExportByName("libc.so", "hsearch_r")`: 找到 `libc.so` 中导出的 `hsearch_r` 函数的地址。
   - `Interceptor.attach(...)`: 拦截对 `hsearch_r` 函数的调用。
   - **`onEnter`:** 在函数调用前执行：
     - 读取 `item` 参数（`ENTRY` 结构）的指针。
     - 读取 `action` 参数的值。
     - 从 `item` 结构中读取 `key` 和 `data` 指针，并读取 `key` 指向的字符串。
     - 打印调用信息，包括操作类型和键。
     - 将 `key` 保存在 `this.key` 中，以便在 `onLeave` 中使用。
   - **`onLeave`:** 在函数调用后执行：
     - 读取返回值 `retval`。
     - 如果返回值不为 0 (表示成功或失败)，并且保存了 `key`，则打印操作结果。
5. **创建和加载脚本:** 使用 `session.create_script(script_code)` 创建脚本，并使用 `script.load()` 加载脚本到目标应用进程。
6. **监听消息:** 使用 `script.on('message', on_message)` 监听脚本发送的消息（这里主要是 `console.log` 输出）。
7. **保持脚本运行:** `sys.stdin.read()` 阻止脚本退出，直到手动中断。

**运行 Frida 脚本:**

1. 确保你的电脑上安装了 Frida 和 Frida CLI 工具。
2. 确保你的 Android 设备已连接到电脑，并且启用了 USB 调试。
3. 运行目标 Android 应用。
4. 在终端中运行该 Frida 脚本。

当你操作目标应用，触发调用 `hsearch_r` 的代码时，Frida 脚本会在终端中打印出相关的调用信息，包括操作类型和键值。

**说明 Android Framework 或 NDK 是如何一步步到达这里:**

1. **NDK 开发:**
   - 开发者使用 C/C++ 编写 Android Native 代码。
   - 在 Native 代码中，开发者可能会使用标准 C 库提供的哈希表功能，例如调用 `hcreate_r` 创建哈希表，然后使用 `hsearch_r` 进行查找和插入。
   - NDK 编译工具链会将这些 C/C++ 代码编译成包含对 `libc.so` 中 `hsearch_r` 函数调用的机器码。
   - 当应用运行在 Android 设备上时，系统会加载应用的 Native 库，其中包含对 `hsearch_r` 的调用，最终会链接到 Bionic 的 `libc.so` 中的 `hsearch_r` 实现。

2. **Android Framework (C/C++ 组件):**
   - Android Framework 的某些核心组件是用 C/C++ 编写的，例如 `servicemanager`、`SurfaceFlinger` 等。
   - 这些组件在内部可能需要使用哈希表来管理各种数据结构，例如服务名称到服务代理的映射。
   - 这些 Framework 组件的代码会直接调用 Bionic 提供的 `hcreate_r` 和 `hsearch_r`。
   - 例如，`servicemanager` 在注册和查找服务时，可能会使用哈希表来高效地管理服务信息。

**调用链示例 (NDK):**

```
Java 代码 (Activity/Service 等)
  -> 调用 JNI 方法
    -> Native C/C++ 代码
      -> 调用 hcreate_r 初始化哈希表
      -> 调用 hsearch_r 进行查找或插入
        -> Bionic libc (hsearch_r.c) 中的实现
```

**调用链示例 (Android Framework):**

```
Android Framework Java 代码 (例如 ServiceManager.java)
  -> 调用 Native 方法 (通过 JNI)
    -> Android Framework Native 代码 (例如 frameworks/base/cmds/servicemanager/service_manager.c)
      -> 调用 hcreate_r 初始化哈希表
      -> 调用 hsearch_r 进行查找或插入
        -> Bionic libc (hsearch_r.c) 中的实现
```

总而言之，`hsearch_r.c` 提供了 Android 系统中可重入的哈希表操作功能，无论是使用 NDK 开发的 Native 代码，还是 Android Framework 的 C/C++ 组件，都可以通过调用标准 C 库函数来使用这个功能。动态链接器本身也依赖哈希表的概念来实现高效的符号查找，虽然它可能使用自己的内部实现。

### 提示词
```
这是目录为bionic/libc/upstream-freebsd/lib/libc/stdlib/hsearch_r.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <limits.h>
#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hsearch.h"

/*
 * Look up an unused entry in the hash table for a given hash. For this
 * implementation we use quadratic probing. Quadratic probing has the
 * advantage of preventing primary clustering.
 */
static ENTRY *
hsearch_lookup_free(struct __hsearch *hsearch, size_t hash)
{
	size_t index, i;

	for (index = hash, i = 0;; index += ++i) {
		ENTRY *entry = &hsearch->entries[index & hsearch->index_mask];
		if (entry->key == NULL)
			return (entry);
	}
}

/*
 * Computes an FNV-1a hash of the key. Depending on the pointer size, this
 * either uses the 32- or 64-bit FNV prime.
 */
static size_t
hsearch_hash(size_t offset_basis, const char *str)
{
	size_t hash;

	hash = offset_basis;
	while (*str != '\0') {
		hash ^= (uint8_t)*str++;
		if (sizeof(size_t) * CHAR_BIT <= 32)
			hash *= UINT32_C(16777619);
		else
			hash *= UINT64_C(1099511628211);
	}
	return (hash);
}

int
hsearch_r(ENTRY item, ACTION action, ENTRY **retval, struct hsearch_data *htab)
{
	struct __hsearch *hsearch;
	ENTRY *entry, *old_entries, *new_entries;
	size_t hash, index, i, old_hash, old_count, new_count;

	hsearch = htab->__hsearch;
	hash = hsearch_hash(hsearch->offset_basis, item.key);

	/*
	 * Search the hash table for an existing entry for this key.
	 * Stop searching if we run into an unused hash table entry.
	 */
	for (index = hash, i = 0;; index += ++i) {
		entry = &hsearch->entries[index & hsearch->index_mask];
		if (entry->key == NULL)
			break;
		if (strcmp(entry->key, item.key) == 0) {
			*retval = entry;
			return (1);
		}
	}

	/* Only perform the insertion if action is set to ENTER. */
	if (action == FIND) {
		errno = ESRCH;
		return (0);
	}

	if (hsearch->entries_used * 2 >= hsearch->index_mask) {
		/* Preserve the old hash table entries. */
		old_count = hsearch->index_mask + 1;
		old_entries = hsearch->entries;

		/*
		 * Allocate and install a new table if insertion would
		 * yield a hash table that is more than 50% used. By
		 * using 50% as a threshold, a lookup will only take up
		 * to two steps on average.
		 */
		new_count = (hsearch->index_mask + 1) * 2;
		new_entries = calloc(new_count, sizeof(ENTRY));
		if (new_entries == NULL)
			return (0);
		hsearch->entries = new_entries;
		hsearch->index_mask = new_count - 1;

		/* Copy over the entries from the old table to the new table. */
		for (i = 0; i < old_count; ++i) {
			entry = &old_entries[i];
			if (entry->key != NULL) {
				old_hash = hsearch_hash(hsearch->offset_basis,
				    entry->key);
				*hsearch_lookup_free(hsearch, old_hash) =
				    *entry;
			}
		}

		/* Destroy the old hash table entries. */
		free(old_entries);

		/*
		 * Perform a new lookup for a free table entry, so that
		 * we insert the entry into the new hash table.
		 */
		hsearch = htab->__hsearch;
		entry = hsearch_lookup_free(hsearch, hash);
	}

	/* Insert the new entry into the hash table. */
	*entry = item;
	++hsearch->entries_used;
	*retval = entry;
	return (1);
}
```