Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request is to analyze the `contexts_split.cpp` file, which is part of Android's Bionic libc. The core goal is to understand its functionality, its relationship to Android, the implementation details of libc functions it uses, its interaction with the dynamic linker (if any), potential errors, and how Android Framework/NDK interacts with it, along with providing debugging examples.

2. **Initial Skim and Identify Key Data Structures:**  A quick scan reveals the core data structures: `ContextListNode` and `PrefixNode`. These immediately suggest a tree-like or linked-list structure used to store information about contexts and prefixes related to system properties. The `ContextsSplit` class itself appears to be the main manager of these structures.

3. **Identify Core Functionality (High Level):**  The function names provide clues: `InitializePropertiesFromFile`, `InitializeProperties`, `MapSerialPropertyArea`, `GetPropAreaForName`, `ForEach`, `ResetAccess`. This suggests the file is responsible for:
    * Loading property context information from files.
    * Mapping memory regions for storing properties.
    * Retrieving the appropriate memory region for a given property name.
    * Iterating over all properties.
    * Managing access to these properties.

4. **Analyze Key Functions in Detail:**  Now, delve deeper into the significant functions:

    * **`InitializePropertiesFromFile`:** This clearly parses a file to extract property prefixes and their associated security contexts. The `read_spec_entries` function within it is crucial for understanding the file format. The handling of `ctl.*` properties is a specific Android detail. The logic for associating prefixes with contexts and potentially creating new context nodes is important.

    * **`InitializeProperties`:** This function handles the discovery and loading of property context files from various locations (`/property_contexts`, `/system/etc/selinux/...`, `/vendor/...`). This highlights the importance of SELinux in property management.

    * **`MapSerialPropertyArea`:**  This function deals with memory mapping, likely for a shared memory region where properties are actually stored. The `prop_area` type suggests it's interacting with another part of the system property mechanism. The read/write access flag is significant.

    * **`GetPrefixNodeForName`:** This function performs a search to find the matching prefix for a given property name. The wildcard (`*`) prefix is interesting.

    * **`GetPropAreaForName`:** This builds upon `GetPrefixNodeForName` and retrieves the `prop_area` associated with the found prefix. The conditional `Open` call and the comment about SELinux audits are key details.

    * **`ForEach`:** This function iterates through the contexts and calls a provided function for each property. The access check (`CheckAccessAndOpen`) is important.

    * **`Initialize`:** This acts as the main entry point for initializing the `ContextsSplit` object. It calls the other initialization functions and handles memory mapping.

5. **Identify Interactions with Other Components:**

    * **SELinux:** The mentions of SELinux contexts (`u:object_r:properties_serial:s0`) and the logic in `InitializeProperties` point to a strong dependency on SELinux for security.
    * **`prop_area`:**  The frequent use of `prop_area` indicates a separate module responsible for the actual memory management and storage of properties.
    * **File System:**  The code interacts heavily with the file system to read configuration files and create/access property files.
    * **Dynamic Linker (Implicit):** While this specific file doesn't explicitly call dynamic linker functions, as part of `libc`, it's inherently linked by the dynamic linker. System properties are a foundational part of Android, so any process using them will involve the dynamic linker loading this library.

6. **Consider User/Programming Errors:**

    * **Incorrect Configuration:**  Malformed context files will likely cause parsing errors.
    * **Permissions:**  Incorrect file permissions on context files or the property directory will prevent proper loading and operation.
    * **Memory Leaks:** While the code has destructors, incorrect usage of the `ContextsSplit` object could lead to memory leaks if `FreeAndUnmap` isn't called.

7. **Trace the Path from Framework/NDK:**  Think about how a property gets set or retrieved. A high-level flow would involve:
    * **Java Framework:**  `SystemProperties.get()` or `SystemProperties.set()`.
    * **Native Bridge:** JNI calls into native code.
    * **Bionic Libc:**  Functions like `__system_property_get` and `__system_property_set` (not directly in this file, but part of the system property mechanism in `libc`). These functions would eventually use the structures managed by `ContextsSplit` to locate the property's storage.

8. **Develop Frida Hook Examples:** Focus on hooking the key functions to observe their behavior: `InitializePropertiesFromFile`, `GetPropAreaForName`, `ForEach`. The hooks should log arguments and potentially return values to understand the data flow.

9. **Structure the Output:** Organize the analysis into logical sections: Functionality, Android Relationship, Libc Functions, Dynamic Linker, Logic Inference, Common Errors, and Framework/NDK Interaction with Frida examples. Use clear headings and bullet points for readability.

10. **Refine and Elaborate:** Review the initial analysis and add more details. For example, explain *why* `ctl.*` properties are handled differently. Elaborate on the memory mapping process. Provide more concrete examples for user errors. Ensure the Frida examples are functional and explain what they do.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Might have initially focused too much on the individual `ListAdd` and `ListFind` template functions. Realized their purpose is simply list management and the core logic lies in how the lists are used with `ContextListNode` and `PrefixNode`.
* **Dynamic Linker:** Initially might have missed the implicit connection to the dynamic linker. Realized that as part of `libc`, this code is fundamental and must be linked. Considered adding a dedicated "Dynamic Linking" section even though the code doesn't directly call `dlopen` etc., because understanding library loading is crucial.
* **SELinux Importance:**  The frequent mentions of contexts and file paths related to SELinux became a clear indicator of its significance, prompting a stronger emphasis on this aspect.
* **Frida Examples:**  Started with simple hooks and then refined them to be more informative by logging arguments. Considered adding examples for both reading and setting properties, even though the provided code focuses more on the reading/initialization side.

By following this structured approach, combining code reading with domain knowledge (Android system properties, SELinux, dynamic linking), and iterative refinement, it's possible to generate a comprehensive analysis like the example provided in the prompt.
好的，让我们深入分析一下 `bionic/libc/system_properties/contexts_split.cpp` 这个文件。

**功能概览**

`contexts_split.cpp` 文件的核心功能是**管理和组织系统属性的上下文信息**。  在 Android 系统中，系统属性以键值对的形式存在，用于配置和传递系统状态信息。为了实现更细粒度的权限控制和管理，Android 将系统属性根据其前缀（prefix）分配到不同的上下文中。这个文件定义了如何加载、存储和查找这些上下文信息。

具体来说，它的功能包括：

1. **加载属性上下文配置文件:** 从指定的文件（通常是 `/property_contexts`, `/system/etc/selinux/plat_property_contexts`, `/vendor/etc/selinux/vendor_property_contexts` 等）读取属性前缀和对应的安全上下文。
2. **组织上下文信息:** 使用链表结构 (`ContextListNode` 和 `PrefixNode`) 来存储和管理这些信息。`PrefixNode` 关联一个属性前缀和一个 `ContextListNode`，而 `ContextListNode` 则包含一个上下文字符串和一个关联的文件名（用于存储该上下文下的属性）。
3. **查找属性的上下文:**  给定一个属性名称，根据其前缀找到对应的上下文信息。
4. **管理属性存储区域:**  每个上下文对应一个属性存储区域（`prop_area`），负责实际存储该上下文下的属性。`ContextsSplit` 负责按需打开和映射这些存储区域。
5. **提供属性迭代功能:**  允许遍历所有已加载的属性。
6. **管理串行属性区域:**  维护一个特殊的串行属性区域（`serial_prop_area_`），可能用于存储一些全局或需要特殊处理的属性。

**与 Android 功能的关系和举例**

`contexts_split.cpp` 是 Android 系统属性机制的关键组成部分，直接影响着系统的行为和安全性。

* **权限控制 (SELinux):**  每个属性都关联到一个安全上下文。当进程尝试访问或修改一个属性时，SELinux 会根据进程的上下文和属性的上下文来决定是否允许操作。 `contexts_split.cpp` 负责加载这些上下文信息，使得 SELinux 可以正确地进行决策。

   **举例:** 假设 `/system/etc/selinux/plat_property_contexts` 文件中包含一行：
   ```
   persist.sys.locale u:object_r:system_prop:s0
   ```
   这意味着所有以 `persist.sys.locale` 开头的属性都属于 `u:object_r:system_prop:s0` 这个安全上下文。当一个进程试图读取或设置 `persist.sys.locale` 属性时，SELinux 会检查该进程是否具有访问 `u:object_r:system_prop:s0` 上下文的权限。

* **系统配置:** 许多系统配置项都通过系统属性来管理。不同的上下文可以对应不同的配置文件，从而实现模块化的配置管理。

   **举例:**  可能存在一个上下文专门用于管理网络相关的属性，另一个上下文用于管理显示相关的属性。`contexts_split.cpp` 确保访问网络属性时会使用网络上下文的存储区域。

* **OTA (Over-The-Air) 更新:**  代码中注释提到了在 OTA 更新过程中 `/property_contexts` 的使用。这表明该文件也参与了系统更新过程中的属性管理。

**libc 函数的实现解释**

以下是 `contexts_split.cpp` 中使用的一些 libc 函数及其实现原理：

1. **`strdup(const char* s)`:**
   - **功能:** 分配一块新的内存，并将字符串 `s` 复制到这块新内存中。返回指向新分配内存的指针。
   - **实现:**  `strdup` 通常内部调用 `malloc` 分配 `strlen(s) + 1` 字节的内存（包括 null 终止符），然后调用 `strcpy` 将 `s` 复制到新分配的内存中。

2. **`free(void* ptr)`:**
   - **功能:** 释放之前由 `malloc`, `calloc`, 或 `realloc` 分配的内存块。
   - **实现:** `free` 将 `ptr` 指向的内存块标记为可用，以便后续的内存分配可以重用这块内存。具体的实现由底层的内存管理器负责，涉及维护空闲内存块的链表或树结构。

3. **`strlen(const char* s)`:**
   - **功能:** 计算字符串 `s` 的长度，不包括 null 终止符。
   - **实现:** `strlen` 从字符串的起始位置开始遍历，直到遇到 null 终止符 `\0` 为止，返回遍历的字符数。

4. **`strncmp(const char* s1, const char* s2, size_t n)`:**
   - **功能:** 比较字符串 `s1` 和 `s2` 的前 `n` 个字符。
   - **实现:** `strncmp` 从两个字符串的起始位置开始逐个比较字符，直到比较了 `n` 个字符或者遇到 null 终止符。返回 0 表示相等，负数表示 `s1` 小于 `s2`，正数表示 `s1` 大于 `s2`。

5. **`fopen(const char* pathname, const char* mode)`:**
   - **功能:** 打开由 `pathname` 指定的文件。 `mode` 参数指定了文件的访问模式（例如 "r" 表示只读，"re" 表示只读，如果文件不存在则返回错误）。
   - **实现:** `fopen` 会调用底层的系统调用（如 `open`）来打开文件。它会分配一个 `FILE` 结构体来维护文件的状态信息（如文件描述符、读写指针、缓冲区等）。

6. **`fclose(FILE* stream)`:**
   - **功能:** 关闭与文件流 `stream` 关联的文件。
   - **实现:** `fclose` 会刷新缓冲区中的数据到磁盘（如果适用），然后调用底层的系统调用（如 `close`）来关闭文件描述符，并释放 `FILE` 结构体。

7. **`getline(char** lineptr, size_t* n, FILE* stream)`:**
   - **功能:** 从文件流 `stream` 中读取一行，包括换行符（如果存在）。
   - **实现:** `getline` 会动态分配缓冲区来存储读取的行。如果提供的缓冲区 `*lineptr` 不够大，它会重新分配更大的缓冲区。它会持续读取字符直到遇到换行符或文件结束符。

8. **`access(const char* pathname, int mode)`:**
   - **功能:** 检查调用进程是否可以根据 `mode` 指定的方式访问 `pathname` 指向的文件。
   - **实现:** `access` 会调用底层的系统调用（如 `faccessat`）来检查文件的可访问性。它会考虑进程的 UID、GID 以及文件的权限位。

9. **`mkdir(const char* pathname, mode_t mode)`:**
   - **功能:** 创建一个由 `pathname` 指定的目录。
   - **实现:** `mkdir` 会调用底层的系统调用（如 `mkdirat`）来创建目录。 `mode` 参数指定了新目录的权限。

10. **`isspace(int c)`:**
    - **功能:** 检查字符 `c` 是否是空白字符（空格、制表符、换行符等）。
    - **实现:** `isspace` 通常通过查表的方式实现，根据字符的 ASCII 值判断是否属于空白字符的范围。

11. **`strndup(const char *s, size_t n)`:**
    - **功能:** 分配一块新的内存，并将字符串 `s` 的前 `n` 个字符复制到这块新内存中，并以 null 结尾。
    - **实现:** 类似于 `strdup`，但只复制最多 `n` 个字符，并确保结果以 null 结尾。

12. **`va_list`, `va_start`, `va_arg`, `va_end`:**
    - **功能:** 用于处理可变参数列表。
    - **实现:** 这些宏提供了访问传递给函数的额外参数的机制，即使在编译时不知道参数的数量和类型。它们通常依赖于平台相关的调用约定和栈布局。

**涉及 dynamic linker 的功能和处理过程**

虽然 `contexts_split.cpp` 本身没有直接调用 dynamic linker 的 API（如 `dlopen`, `dlsym`），但作为 `libc` 的一部分，它会被 dynamic linker 加载和链接到使用它的进程中。

**so 布局样本:**

假设一个简单的 Android 应用程序 `my_app` 链接了 `libc.so`。  `libc.so` 中包含了 `contexts_split.cpp` 编译生成的代码。

```
/system/bin/my_app
/system/lib64/libc.so  <-- 包含 contexts_split.cpp 的代码
/system/lib64/libdl.so
...
```

**链接的处理过程:**

1. **应用程序启动:** 当 `my_app` 启动时，Android 的 zygote 进程会 fork 出一个新的进程。
2. **加载器执行:** 内核会启动 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
3. **依赖项解析:** dynamic linker 读取 `my_app` 的 ELF 头，找到其依赖的共享库，包括 `libc.so`。
4. **加载共享库:** dynamic linker 将 `libc.so` 加载到进程的地址空间中。这包括将代码段、数据段等映射到内存。
5. **符号解析和重定位:** dynamic linker 解析 `my_app` 和 `libc.so` 中的符号引用。例如，如果 `my_app` 中调用了 `__system_property_get` 函数（该函数可能会间接使用 `contexts_split.cpp` 中的功能），dynamic linker 会将 `my_app` 中对 `__system_property_get` 的引用指向 `libc.so` 中 `__system_property_get` 函数的实际地址。这个过程称为重定位。
6. **初始化:**  加载完成后，dynamic linker 会调用共享库中的初始化函数（如果有的话）。

在这个过程中，`contexts_split.cpp` 编译生成的代码会被加载到 `libc.so` 的代码段中。当应用程序或其他 `libc` 内部组件需要访问或管理系统属性上下文信息时，就会调用 `contexts_split.cpp` 中定义的函数。

**逻辑推理、假设输入与输出**

考虑 `ContextsSplit::GetPropAreaForName(const char* name)` 函数。

**假设输入:**

* `prefixes_` 链表包含以下 `PrefixNode`:
    * `prefix`: "ro.build.", `context`: 指向一个包含上下文 "u:object_r:build_prop:s0" 的 `ContextListNode`
    * `prefix`: "sys.power.", `context`: 指向一个包含上下文 "u:object_r:power_prop:s0" 的 `ContextListNode`
    * `prefix`: "*", `context`: 指向一个包含上下文 "u:object_r:default_prop:s0" 的 `ContextListNode` (通配符)
* `name` (要查找的属性名) 为 "ro.build.version.sdk"

**逻辑推理:**

1. `GetPrefixNodeForName("ro.build.version.sdk")` 会遍历 `prefixes_` 链表。
2. 第一个 `PrefixNode` 的 `prefix` 是 "ro.build."，`strncmp("ro.build.version.sdk", "ro.build.", strlen("ro.build."))` 返回 0，匹配成功。
3. 返回指向该 `PrefixNode` 的指针。
4. `GetPropAreaForName` 获取到匹配的 `PrefixNode`。
5. 获取该 `PrefixNode` 关联的 `ContextListNode`，其上下文为 "u:object_r:build_prop:s0"。
6. 如果该 `ContextListNode` 的 `prop_area` 尚未打开，则打开它（这里假设已经打开）。
7. 返回该 `ContextListNode` 的 `prop_area` 指针。

**输出:**

返回指向 "u:object_r:build_prop:s0" 上下文对应的 `prop_area` 对象的指针。

**用户或编程常见的使用错误**

1. **配置文件格式错误:**  `InitializePropertiesFromFile` 依赖于特定格式的配置文件。如果文件格式不正确（例如，缺少空格分隔符，行尾没有换行符），会导致解析错误，部分或全部属性上下文无法加载。

   **举例:**  `/property_contexts` 文件中某一行缺少了上下文信息：
   ```
   ro.debuggable
   ```
   这会导致 `read_spec_entries` 返回错误，该行将被忽略。

2. **权限问题:**  如果进程没有读取属性上下文配置文件的权限，`InitializeProperties` 将无法打开文件，导致属性上下文初始化失败。

   **举例:** 如果 `/system/etc/selinux/plat_property_contexts` 的权限被错误地设置为只有 root 用户可读，非特权进程启动时将无法加载这些上下文信息。

3. **内存泄漏 (理论上):** 虽然代码本身有 `free` 操作，但在更高层次的使用中，如果 `ContextsSplit` 对象没有被正确销毁，可能会导致内存泄漏。不过，在 Android 系统属性的生命周期管理中，这种情况通常不太容易发生，因为 `ContextsSplit` 的实例通常是全局的或由系统服务管理。

**Android Framework 或 NDK 如何到达这里**

系统属性是 Android 系统中非常基础的服务，许多 Framework 组件和 Native 代码都会使用它。以下是一个简化的流程：

1. **Java Framework:**  Android Framework 中的 Java 代码通常通过 `android.os.SystemProperties` 类来访问系统属性。

   **举例:**  `android.os.Build` 类会读取各种 `ro.build.*` 属性来获取设备信息。

2. **Native Bridge (JNI):** `android.os.SystemProperties` 类的方法会通过 JNI 调用到 Native 代码中。

3. **Bionic Libc:** 在 Native 代码中，访问系统属性通常会调用 `libc.so` 中提供的函数，例如：
   - `__system_property_get(const char* name, char* value)`: 获取属性值。
   - `__system_property_set(const char* name, const char* value)`: 设置属性值。

4. **`system_properties.c` 和 `contexts_split.cpp`:**  `__system_property_get` 和 `__system_property_set` 的实现会使用 `contexts_split.cpp` 中提供的功能来查找属性对应的上下文和存储区域。

   例如，`__system_property_get` 可能会调用 `ContextsSplit::GetPropAreaForName` 来获取属性的存储区域，然后从该区域读取属性值。

**Frida Hook 示例**

以下是一些使用 Frida Hook 调试 `contexts_split.cpp` 中关键步骤的示例：

**1. Hook `ContextsSplit::InitializePropertiesFromFile`:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const InitializePropertiesFromFile = Module.findExportByName("libc.so", "_ZN13ContextsSplit26InitializePropertiesFromFileEPKc");
  if (InitializePropertiesFromFile) {
    Interceptor.attach(InitializePropertiesFromFile, {
      onEnter: function (args) {
        const filename = Memory.readUtf8String(args[1]);
        console.log(`[InitializePropertiesFromFile] filename: ${filename}`);
      },
      onLeave: function (retval) {
        console.log(`[InitializePropertiesFromFile] returned: ${retval}`);
      }
    });
  }
}
```

这个 hook 会在 `InitializePropertiesFromFile` 函数被调用时打印出正在加载的配置文件名以及返回值（是否成功）。

**2. Hook `ContextsSplit::GetPropAreaForName`:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const GetPropAreaForName = Module.findExportByName("libc.so", "_ZN13ContextsSplit18GetPropAreaForNameEPKc");
  if (GetPropAreaForName) {
    Interceptor.attach(GetPropAreaForName, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[1]);
        console.log(`[GetPropAreaForName] name: ${name}`);
      },
      onLeave: function (retval) {
        console.log(`[GetPropAreaForName] returned: ${retval}`);
        if (!retval.isNull()) {
          // 可以进一步检查返回的 prop_area 指针指向的内存
        }
      }
    });
  }
}
```

这个 hook 会在查找属性存储区域时打印出属性名以及返回的 `prop_area` 指针。

**3. Hook `ContextsSplit::ForEach`:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const ForEach = Module.findExportByName("libc.so", "_ZN13ContextsSplit7ForEachEPFvPK9prop_infoPvES1_");
  if (ForEach) {
    Interceptor.attach(ForEach, {
      onEnter: function (args) {
        console.log("[ForEach] called");
        this.propfn = args[1];
        this.cookie = args[2];
      },
      onLeave: function (retval) {
        console.log("[ForEach] finished");
      }
    });

    // Hook 传递给 ForEach 的回调函数 propfn
    Interceptor.attach(this.propfn, {
      onEnter: function (args) {
        const propInfoPtr = args[0];
        const namePtr = ptr(propInfoPtr).readPointer(); // 假设 prop_info 结构体第一个成员是指向属性名的指针
        const valuePtr = ptr(propInfoPtr).add(Process.pointerSize).readPointer(); // 假设 prop_info 结构体第二个成员是指向属性值的指针
        const name = namePtr.readCString();
        const value = valuePtr.readCString();
        console.log(`  [propfn] name: ${name}, value: ${value}`);
      }
    });
  }
}
```

这个 hook 可以用来观察属性的迭代过程，打印出每个属性的名称和值。需要注意的是，`prop_info` 结构体的布局可能需要根据实际情况调整。

**总结**

`bionic/libc/system_properties/contexts_split.cpp` 是 Android 系统属性机制中负责组织和管理属性上下文的关键组件。它通过加载配置文件、维护链表结构和管理属性存储区域，实现了属性的分类和安全访问控制。理解这个文件的功能对于深入理解 Android 系统属性的工作原理至关重要。 通过 Frida Hook，我们可以动态地观察和调试这个文件的行为，从而更好地理解其内部逻辑。

### 提示词
```
这是目录为bionic/libc/system_properties/contexts_split.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include "system_properties/contexts_split.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <async_safe/log.h>

#include "system_properties/context_node.h"
#include "system_properties/system_properties.h"

class ContextListNode : public ContextNode {
 public:
  ContextListNode(ContextListNode* next, const char* context, const char* filename)
      : ContextNode(strdup(context), filename), next(next) {
  }

  ~ContextListNode() {
    free(const_cast<char*>(context()));
  }

  ContextListNode* next;
};

struct PrefixNode {
  PrefixNode(struct PrefixNode* next, const char* prefix, ContextListNode* context)
      : prefix(strdup(prefix)), prefix_len(strlen(prefix)), context(context), next(next) {
  }
  ~PrefixNode() {
    free(prefix);
  }
  char* prefix;
  const size_t prefix_len;
  ContextListNode* context;
  PrefixNode* next;
};

template <typename List, typename... Args>
static inline void ListAdd(List** list, Args... args) {
  *list = new List(*list, args...);
}

static void ListAddAfterLen(PrefixNode** list, const char* prefix, ContextListNode* context) {
  size_t prefix_len = strlen(prefix);

  auto next_list = list;

  while (*next_list) {
    if ((*next_list)->prefix_len < prefix_len || (*next_list)->prefix[0] == '*') {
      ListAdd(next_list, prefix, context);
      return;
    }
    next_list = &(*next_list)->next;
  }
  ListAdd(next_list, prefix, context);
}

template <typename List, typename Func>
static void ListForEach(List* list, Func func) {
  while (list) {
    func(list);
    list = list->next;
  }
}

template <typename List, typename Func>
static List* ListFind(List* list, Func func) {
  while (list) {
    if (func(list)) {
      return list;
    }
    list = list->next;
  }
  return nullptr;
}

template <typename List>
static void ListFree(List** list) {
  while (*list) {
    auto old_list = *list;
    *list = old_list->next;
    delete old_list;
  }
}

// The below two functions are duplicated from label_support.c in libselinux.

// The read_spec_entries and read_spec_entry functions may be used to
// replace sscanf to read entries from spec files. The file and
// property services now use these.

// Read an entry from a spec file (e.g. file_contexts)
static inline int read_spec_entry(char** entry, char** ptr, int* len) {
  *entry = nullptr;
  char* tmp_buf = nullptr;

  while (isspace(**ptr) && **ptr != '\0') (*ptr)++;

  tmp_buf = *ptr;
  *len = 0;

  while (!isspace(**ptr) && **ptr != '\0') {
    (*ptr)++;
    (*len)++;
  }

  if (*len) {
    *entry = strndup(tmp_buf, *len);
    if (!*entry) return -1;
  }

  return 0;
}

// line_buf - Buffer containing the spec entries .
// num_args - The number of spec parameter entries to process.
// ...      - A 'char **spec_entry' for each parameter.
// returns  - The number of items processed.
//
// This function calls read_spec_entry() to do the actual string processing.
static int read_spec_entries(char* line_buf, int num_args, ...) {
  char **spec_entry, *buf_p;
  int len, rc, items, entry_len = 0;
  va_list ap;

  len = strlen(line_buf);
  if (line_buf[len - 1] == '\n')
    line_buf[len - 1] = '\0';
  else
    // Handle case if line not \n terminated by bumping
    // the len for the check below (as the line is NUL
    // terminated by getline(3))
    len++;

  buf_p = line_buf;
  while (isspace(*buf_p)) buf_p++;

  // Skip comment lines and empty lines.
  if (*buf_p == '#' || *buf_p == '\0') return 0;

  // Process the spec file entries
  va_start(ap, num_args);

  items = 0;
  while (items < num_args) {
    spec_entry = va_arg(ap, char**);

    if (len - 1 == buf_p - line_buf) {
      va_end(ap);
      return items;
    }

    rc = read_spec_entry(spec_entry, &buf_p, &entry_len);
    if (rc < 0) {
      va_end(ap);
      return rc;
    }
    if (entry_len) items++;
  }
  va_end(ap);
  return items;
}

bool ContextsSplit::MapSerialPropertyArea(bool access_rw, bool* fsetxattr_failed) {
  PropertiesFilename filename(filename_, "properties_serial");
  if (access_rw) {
    serial_prop_area_ = prop_area::map_prop_area_rw(
        filename.c_str(), "u:object_r:properties_serial:s0", fsetxattr_failed);
  } else {
    serial_prop_area_ = prop_area::map_prop_area(filename.c_str());
  }
  return serial_prop_area_;
}

bool ContextsSplit::InitializePropertiesFromFile(const char* filename) {
  FILE* file = fopen(filename, "re");
  if (!file) {
    return false;
  }

  char* buffer = nullptr;
  size_t line_len;
  char* prop_prefix = nullptr;
  char* context = nullptr;

  while (getline(&buffer, &line_len, file) > 0) {
    int items = read_spec_entries(buffer, 2, &prop_prefix, &context);
    if (items <= 0) {
      continue;
    }
    if (items == 1) {
      free(prop_prefix);
      continue;
    }

    // init uses ctl.* properties as an IPC mechanism and does not write them
    // to a property file, therefore we do not need to create property files
    // to store them.
    if (!strncmp(prop_prefix, "ctl.", 4)) {
      free(prop_prefix);
      free(context);
      continue;
    }

    auto old_context = ListFind(
        contexts_, [context](ContextListNode* l) { return !strcmp(l->context(), context); });
    if (old_context) {
      ListAddAfterLen(&prefixes_, prop_prefix, old_context);
    } else {
      ListAdd(&contexts_, context, filename_);
      ListAddAfterLen(&prefixes_, prop_prefix, contexts_);
    }
    free(prop_prefix);
    free(context);
  }

  free(buffer);
  fclose(file);

  return true;
}

bool ContextsSplit::InitializeProperties() {
  // If we do find /property_contexts, then this is being
  // run as part of the OTA updater on older release that had
  // /property_contexts - b/34370523
  if (InitializePropertiesFromFile("/property_contexts")) {
    return true;
  }

  // Use property_contexts from /system & /vendor, fall back to those from /
  if (access("/system/etc/selinux/plat_property_contexts", R_OK) != -1) {
    if (!InitializePropertiesFromFile("/system/etc/selinux/plat_property_contexts")) {
      return false;
    }
    // Don't check for failure here, since we don't always have all of these partitions.
    // E.g. In case of recovery, the vendor partition will not have mounted and we
    // still need the system / platform properties to function.
    if (access("/vendor/etc/selinux/vendor_property_contexts", R_OK) != -1) {
      InitializePropertiesFromFile("/vendor/etc/selinux/vendor_property_contexts");
    }
  } else {
    if (!InitializePropertiesFromFile("/plat_property_contexts")) {
      return false;
    }
    if (access("/vendor_property_contexts", R_OK) != -1) {
      InitializePropertiesFromFile("/vendor_property_contexts");
    }
  }

  return true;
}

bool ContextsSplit::Initialize(bool writable, const char* filename, bool* fsetxattr_failed, bool) {
  filename_ = filename;
  if (!InitializeProperties()) {
    return false;
  }

  if (writable) {
    mkdir(filename_, S_IRWXU | S_IXGRP | S_IXOTH);
    bool open_failed = false;
    if (fsetxattr_failed) {
      *fsetxattr_failed = false;
    }

    ListForEach(contexts_, [&fsetxattr_failed, &open_failed](ContextListNode* l) {
      if (!l->Open(true, fsetxattr_failed)) {
        open_failed = true;
      }
    });
    if (open_failed || !MapSerialPropertyArea(true, fsetxattr_failed)) {
      FreeAndUnmap();
      return false;
    }
  } else {
    if (!MapSerialPropertyArea(false, nullptr)) {
      FreeAndUnmap();
      return false;
    }
  }
  return true;
}

PrefixNode* ContextsSplit::GetPrefixNodeForName(const char* name) {
  auto entry = ListFind(prefixes_, [name](PrefixNode* l) {
    return l->prefix[0] == '*' || !strncmp(l->prefix, name, l->prefix_len);
  });

  return entry;
}

prop_area* ContextsSplit::GetPropAreaForName(const char* name) {
  auto entry = GetPrefixNodeForName(name);
  if (!entry) {
    return nullptr;
  }

  auto cnode = entry->context;
  if (!cnode->pa()) {
    // We explicitly do not check no_access_ in this case because unlike the
    // case of foreach(), we want to generate an selinux audit for each
    // non-permitted property access in this function.
    cnode->Open(false, nullptr);
  }
  return cnode->pa();
}

void ContextsSplit::ForEach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  ListForEach(contexts_, [propfn, cookie](ContextListNode* l) {
    if (l->CheckAccessAndOpen()) {
      l->pa()->foreach (propfn, cookie);
    }
  });
}

void ContextsSplit::ResetAccess() {
  ListForEach(contexts_, [](ContextListNode* l) { l->ResetAccess(); });
}

void ContextsSplit::FreeAndUnmap() {
  ListFree(&prefixes_);
  ListFree(&contexts_);
  prop_area::unmap_prop_area(&serial_prop_area_);
}
```