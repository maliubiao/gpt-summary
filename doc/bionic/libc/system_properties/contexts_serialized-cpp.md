Response:
Let's break down the thought process to generate the detailed analysis of `contexts_serialized.cpp`.

**1. Understanding the Core Functionality:**

The first step is to read through the code and identify the main purpose. Keywords like "system properties," "contexts," "serialized," and the file path itself (`bionic/libc/system_properties`) immediately suggest this file deals with the persistence and management of Android's system properties. The class `ContextsSerialized` seems central to this.

**2. Identifying Key Data Structures and Operations:**

Next, I look for important variables and methods. The following stand out:

*   `property_info_area_file_`:  This likely handles metadata about properties and their organization.
*   `context_nodes_`: An array of `ContextNode` objects, hinting at a contextual organization of properties.
*   `serial_prop_area_`:  Potentially a shared area for serialized properties.
*   `InitializeContextNodes()`, `MapSerialPropertyArea()`, `InitializeProperties()`, `Initialize()`: These are clearly initialization routines.
*   `GetPropAreaForName()`:  A function to retrieve the property area for a given property name.
*   `ForEach()`:  A function to iterate through properties.
*   `ResetAccess()`:  Something to do with access control.
*   `FreeAndUnmap()`:  Cleanup operations.

**3. Connecting to Android System Properties:**

Knowing the file's location and the "system properties" keywords, I can connect its functions to the broader Android system. System properties are key-value pairs used for configuration and communication across the system. This file likely manages how those properties are stored and accessed.

**4. Analyzing Individual Functions (and anticipating the request for libc explanations):**

Now, I go through each function and try to understand its details. This also involves recognizing the standard C library functions used and preparing to explain them.

*   **`InitializeContextNodes()`:**  Uses `mmap` and `prctl`. I need to explain these: `mmap` for memory mapping (anonymous in this case), and `prctl` for setting process attributes, specifically naming the mapped memory region. The loop with `new (&context_nodes_[i]) ContextNode(...)` indicates in-place construction of `ContextNode` objects.

*   **`MapSerialPropertyArea()`:**  Calls `prop_area::map_prop_area_rw` and `prop_area::map_prop_area`. This suggests the existence of a `prop_area` class or namespace responsible for mapping property areas. The `fsetxattr_failed` parameter hints at security attributes.

*   **`InitializeProperties()`:**  Loads metadata using `PropertyInfoAreaFile`.

*   **`Initialize()`:**  Combines the initialization steps, including creating directories (`mkdir`).

*   **`GetPropAreaForName()`:**  Retrieves the context index and then accesses the corresponding `ContextNode`. The check for `context_node->pa()` and the call to `Open()` indicate lazy loading of property areas. The `async_safe_format_log` shows error handling.

*   **`ForEach()`:** Iterates through `context_nodes_` and calls a function (`propfn`) for each property. The `CheckAccessAndOpen()` suggests access control during iteration.

*   **`ResetAccess()`:** Calls a `ResetAccess()` method on each `ContextNode`.

*   **`FreeAndUnmap()`:**  Releases resources using `munmap` and `prop_area::unmap_prop_area`.

**5. Addressing the Dynamic Linker Request:**

The prompt asks about dynamic linker involvement. While this specific file *doesn't directly interact* with the dynamic linker in terms of loading libraries, it's part of the Bionic libc, which *is* a dynamically linked library. Therefore, the connection lies in how this code is used by other dynamically linked components of Android. I need to explain the basic dynamic linking process and provide a simple SO layout example.

**6. Considering Potential Errors and User Mistakes:**

I think about common scenarios where things might go wrong. Permissions issues (`mkdir` failing, `fsetxattr` failing), memory mapping failures (`mmap`), and incorrect property names in `GetPropAreaForName()` are likely candidates.

**7. Tracing the Call Path (Android Framework/NDK):**

This requires knowledge of how system properties are used in Android. I consider scenarios like:

*   Boot process:  Init scripts setting properties.
*   Framework services:  Accessing properties for configuration.
*   NDK applications: Using `__system_property_get`/`__system_property_set`.

I then need to illustrate how a call from the NDK would eventually reach this code.

**8. Crafting Frida Hooks:**

To demonstrate debugging, I need to provide Frida hook examples for key functions like `Initialize` and `GetPropAreaForName`. This involves understanding basic Frida syntax for hooking C functions.

**9. Structuring the Response:**

Finally, I organize the information clearly, following the structure requested by the prompt:

*   Functionality overview.
*   Relationship to Android (with examples).
*   Detailed explanations of libc functions.
*   Dynamic linker aspects (SO layout, linking process).
*   Logical reasoning (hypothetical input/output).
*   Common errors.
*   Android Framework/NDK call path.
*   Frida hook examples.

**Self-Correction/Refinement during the process:**

*   Initially, I might focus too much on the low-level details of `prop_area` and `ContextNode`. I need to remember the prompt is about `contexts_serialized.cpp` itself. While mentioning those related structures is important, deep dives into their internals aren't necessary unless directly relevant to the file's functionality.
*   When explaining dynamic linking, I must avoid overcomplicating it. A high-level overview with a simple example is sufficient.
*   For Frida hooks, I need to provide concrete examples that are easy to understand and adapt. Simple logging of function entry and arguments is a good starting point.

By following these steps, systematically analyzing the code, and connecting it to the broader Android context, I can generate a comprehensive and accurate response that addresses all aspects of the user's request.
好的，让我们来详细分析一下 `bionic/libc/system_properties/contexts_serialized.cpp` 这个文件。

**功能概述:**

`contexts_serialized.cpp` 文件在 Android Bionic 库中，负责管理和加载系统属性的上下文信息。  系统属性是 Android 系统中用于存储配置信息的键值对。为了提高效率和安全性，系统属性被组织成不同的上下文，每个上下文拥有自己的属性集合和访问权限。

`ContextsSerialized` 类是这个文件的核心，它的主要功能包括：

1. **加载和管理属性上下文元数据:**  从磁盘上的文件中加载关于属性上下文的信息，例如上下文的数量、每个上下文的属性文件位置等。
2. **内存映射属性上下文数据:** 将属性上下文的数据（通常是序列化后的 `prop_area` 对象）映射到内存中，以便快速访问。
3. **提供按名称查找属性上下文的能力:**  根据属性的名称，找到其所属的上下文。
4. **支持遍历所有属性上下文:**  提供一种迭代所有已加载属性上下文的方式。
5. **处理属性的读写操作:**  虽然这个文件本身不直接进行属性的读写，但它提供了获取特定属性上下文的 `prop_area` 的方法，`prop_area` 才是实际管理属性读写的对象。
6. **管理序列化的属性区域:**  处理一个共享的、序列化的属性区域，用于存储一些公共的属性。

**与 Android 功能的关系及举例:**

`contexts_serialized.cpp` 是 Android 系统属性机制的关键组成部分，直接影响着系统的配置和行为。

*   **系统启动:**  在 Android 系统启动的早期阶段，`init` 进程会加载系统属性。`contexts_serialized.cpp` 中定义的 `ContextsSerialized` 类及其相关函数会被调用，以加载属性上下文信息，从而使得系统能够读取和使用各种配置属性。例如，读取 `ro.build.version.sdk` 来确定 Android SDK 版本。
*   **权限控制:**  属性上下文的概念允许 Android 对不同的属性设置不同的访问权限。例如，某些系统属性可能只允许系统进程修改，而普通应用只能读取。`contexts_serialized.cpp` 加载的上下文信息会影响到后续对属性的访问控制。
*   **动态配置:**  Android 运行时可以动态地读取和修改系统属性，以调整系统行为或传递信息。例如，Service Manager 使用系统属性来注册和查找服务。
*   **NDK 开发:**  通过 NDK 提供的 API，native 代码也可以访问系统属性。这些 API 的底层实现最终会涉及到 `contexts_serialized.cpp` 中提供的功能。

**libc 函数的功能实现:**

`contexts_serialized.cpp` 中使用了一些 libc 函数，下面是它们的详细解释：

1. **`fcntl.h`:**
    *   **`open()`:**  用于打开文件。在 `ContextNode::Open()` 中可能会被使用，以打开属性上下文对应的文件。
    *   **`close()`:** 用于关闭文件。在 `ContextNode::Unmap()` 中，可能会关闭之前打开的文件描述符。
    *   **`fcntl()`:**  提供各种文件控制操作。这个文件中没有直接使用，但在相关的 `prop_area` 实现中可能会用到，例如用于设置文件锁。

2. **`limits.h`:**
    *   定义了各种系统限制，例如 `PATH_MAX`（文件路径的最大长度）。虽然这个文件没有直接使用，但在其他与文件路径相关的代码中可能会用到。

3. **`sys/mman.h`:**
    *   **`mmap()`:**  将文件或匿名内存区域映射到进程的地址空间。在 `ContextsSerialized::InitializeContextNodes()` 中，用于匿名映射一块内存来存储 `ContextNode` 对象。在 `ContextsSerialized::MapSerialPropertyArea()` 和 `ContextNode::Open()` 中，用于将属性数据文件映射到内存，提高访问效率。
        *   **实现原理:** `mmap()` 系统调用会通知操作系统，将指定的文件或内存区域与进程的虚拟地址空间建立映射关系。当进程访问映射区域内的地址时，如果物理内存中没有对应的数据，操作系统会触发缺页异常，然后将数据从磁盘加载到物理内存中。
    *   **`munmap()`:**  取消 `mmap()` 创建的内存映射。在 `ContextsSerialized::FreeAndUnmap()` 和 `ContextNode::Unmap()` 中使用，释放之前映射的内存区域。
        *   **实现原理:** `munmap()` 系统调用会通知操作系统，解除指定内存区域的映射关系。之后，进程访问该区域将会导致错误。

4. **`sys/prctl.h`:**
    *   **`prctl()`:**  对进程或线程的行为进行控制。在 `ContextsSerialized::InitializeContextNodes()` 中，使用 `PR_SET_VMA` 操作和一个自定义的 `PR_SET_VMA_ANON_NAME` 来为匿名映射的内存区域设置一个名称，方便调试和诊断。
        *   **实现原理:** `prctl()` 是一个功能强大的系统调用，可以执行多种进程控制操作。对于 `PR_SET_VMA`，它允许修改进程虚拟内存区域的属性。

5. **`sys/stat.h`:**
    *   **`mkdir()`:**  创建目录。在 `ContextsSerialized::Initialize()` 中，当需要以可写模式初始化时，会尝试创建属性的目录。
        *   **实现原理:** `mkdir()` 系统调用会在文件系统中创建一个新的目录。它需要权限来创建目录，并且如果目录已存在则会失败。

6. **`sys/types.h`:**
    *   定义了各种基本数据类型，例如 `size_t`。

7. **`new`:**
    *   定位 new (placement new)。在 `ContextsSerialized::InitializeContextNodes()` 中，`new (&context_nodes_[i]) ContextNode(...)` 用于在已分配的内存上构造 `ContextNode` 对象，避免了额外的内存分配。
        *   **实现原理:** 定位 new 允许在已有的内存地址上构造对象。它不会分配新的内存，而是调用构造函数在指定的地址初始化对象。

8. **`async_safe/log.h`:**
    *   **`async_safe_format_log()`:**  一个线程安全的日志记录函数，用于在系统属性管理过程中记录错误或调试信息。
        *   **实现原理:**  `async_safe_format_log()` 通常使用原子操作和锁来保证在异步信号处理程序等场景下的线程安全性。它会将日志信息写入到系统的 logcat 中。

9. **`private/android_filesystem_config.h`:**
    *   包含 Android 文件系统配置相关的常量和宏。虽然这个文件没有直接使用，但相关的 `prop_area` 实现可能会用到，例如获取属性文件的默认路径或权限。

10. **`system_properties/system_properties.h`:**
    *   定义了与系统属性相关的结构体和函数，例如 `prop_info`。

**涉及 dynamic linker 的功能:**

`contexts_serialized.cpp` 本身并不直接处理动态链接，但它是 Bionic libc 的一部分，而 libc 本身就是一个动态链接库。当其他动态链接库或可执行文件需要访问系统属性时，会通过 libc 提供的接口（例如 `__system_property_get` 和 `__system_property_set`）来间接使用到这里的代码。

**SO 布局样本:**

假设有一个简单的 Android 应用程序 `my_app`，它链接了 libc.so。

```
/system/bin/my_app  // 可执行文件
/system/lib64/libc.so // Bionic libc
/system/lib64/libdl.so // Dynamic linker
/system/lib64/libm.so  // 数学库 (可能链接)
... 其他库 ...
```

**链接的处理过程:**

1. **加载:** 当 `my_app` 启动时，Android 的 `zygote` 进程（或其他启动器）会调用内核的 `execve` 系统调用。
2. **动态链接器介入:** 内核会识别出这是一个需要动态链接的可执行文件，并将控制权交给动态链接器 `libdl.so`。
3. **加载依赖:** 动态链接器会读取 `my_app` 的 ELF 头信息，找到其依赖的共享库（例如 `libc.so`）。
4. **查找共享库:** 动态链接器会在预定义的路径中查找这些共享库。
5. **映射共享库:**  找到的共享库会被映射到进程的地址空间中。
6. **符号解析和重定位:** 动态链接器会解析 `my_app` 中引用的来自 `libc.so` 的符号（例如 `__system_property_get`）。它会找到 `libc.so` 中这些符号的地址，并将 `my_app` 中的调用指令重定向到这些地址。这个过程称为符号解析和重定位。
7. **执行:**  链接完成后，动态链接器会将控制权交给 `my_app` 的入口点，程序开始执行。

当 `my_app` 调用 `__system_property_get` 时，实际上会调用 `libc.so` 中该函数的实现，而 `libc.so` 的实现最终会使用到 `contexts_serialized.cpp` 中的功能来查找和获取属性值。

**逻辑推理（假设输入与输出）:**

假设调用 `ContextsSerialized::GetPropAreaForName("ro.build.version.sdk")`：

*   **假设输入:**
    *   `name` 参数为 `"ro.build.version.sdk"`。
    *   `property_info_area_file_` 已经加载了属性信息，并且其中包含了 `"ro.build.version.sdk"` 对应的上下文索引。
    *   对应的上下文索引指向的 `context_nodes_` 元素尚未打开 (`pa()` 返回 nullptr)。

*   **逻辑推理:**
    1. `GetPropAreaForName` 会调用 `property_info_area_file_->GetPropertyInfoIndexes` 来获取 `"ro.build.version.sdk"` 对应的上下文索引。
    2. 假设获取到的索引是 `i`，且 `i` 小于 `num_context_nodes_`。
    3. `context_node` 指向 `context_nodes_[i]`。
    4. 由于 `context_node->pa()` 返回 nullptr，`Open(false, nullptr)` 会被调用，尝试打开对应的属性文件并映射到内存。
    5. 假设 `Open` 成功。

*   **预期输出:**  返回指向 `context_nodes_[i]` 的 `prop_area` 对象的指针。

**用户或编程常见的使用错误:**

1. **尝试直接操作 `contexts_serialized.cpp` 中的数据结构:**  用户或开发者不应该直接访问或修改 `ContextsSerialized` 类中的成员变量，因为这些是内部实现细节，可能会在未来版本中更改。应该使用 libc 提供的公共 API 来访问和修改系统属性。
2. **在不合适的时机访问属性:**  在系统启动的早期阶段，某些属性可能尚未被设置，尝试访问这些属性可能会得到空值或导致错误。
3. **权限问题:**  尝试修改没有权限修改的系统属性会导致操作失败。
4. **竞态条件:**  在多线程环境下，如果没有适当的同步机制，并发地访问或修改系统属性可能会导致数据不一致。

**示例:** 假设一个 NDK 应用尝试设置一个只允许系统进程修改的属性：

```c++
#include <sys/system_properties.h>
#include <android/log.h>

int main() {
  const char* name = "persist.my_system_setting";
  const char* value = "some_value";

  int result = __system_property_set(name, value);

  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, "MyApp", "Failed to set system property '%s'", name);
  } else {
    __android_log_print(ANDROID_LOG_INFO, "MyApp", "Successfully set system property '%s'", name);
  }

  return 0;
}
```

如果 `persist.my_system_setting` 属性被配置为只允许系统进程修改，那么 `__system_property_set` 将会失败并返回一个非零值。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 调用:**  一个 NDK 应用可能调用 `android_os_SystemProperties_get` 或 `android_os_SystemProperties_set` 等 JNI 方法。
2. **Framework 层:** 这些 JNI 方法会调用 Android Framework 层的 `android.os.SystemProperties` 类的方法。
3. **System Server:** Framework 层的调用通常会通过 Binder IPC 机制传递到 System Server 进程。
4. **系统属性服务:** System Server 中存在一个系统属性服务，负责管理系统属性。
5. **libc 接口:** 系统属性服务最终会调用 Bionic libc 提供的 `__system_property_get` 或 `__system_property_set` 函数。
6. **`properties_service.c` 或其他相关代码:**  在 Bionic libc 中，`__system_property_get` 和 `__system_property_set` 的实现会涉及到 `bionic/libc/system_properties/properties_service.c` 文件中的代码，该文件会与 `contexts_serialized.cpp` 交互。
7. **`ContextsSerialized` 类:**  `properties_service.c` 中的代码会使用 `ContextsSerialized` 类来查找属性所在的上下文，并获取对应的 `prop_area` 对象，从而读取或写入属性值。

**Frida Hook 示例:**

以下是一些使用 Frida hook `ContextsSerialized` 中函数的示例：

**Hook `ContextsSerialized::Initialize`:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const contextsSerializedInitialize = Module.findExportByName("libc.so", "_ZN19ContextsSerialized10InitializeEbPKcPbb");

  if (contextsSerializedInitialize) {
    Interceptor.attach(contextsSerializedInitialize, {
      onEnter: function (args) {
        console.log("[*] ContextsSerialized::Initialize called");
        console.log("    writable:", args[0]);
        console.log("    dirname:", args[1].readUtf8String());
        console.log("    fsetxattr_failed:", args[2]);
        console.log("    load_default_path:", args[3]);
      }
    });
  } else {
    console.log("[-] ContextsSerialized::Initialize not found");
  }
}
```

**Hook `ContextsSerialized::GetPropAreaForName`:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const contextsSerializedGetPropAreaForName = Module.findExportByName("libc.so", "_ZN19ContextsSerialized18GetPropAreaForNameEPKc");

  if (contextsSerializedGetPropAreaForName) {
    Interceptor.attach(contextsSerializedGetPropAreaForName, {
      onEnter: function (args) {
        const name = args[1].readUtf8String();
        console.log("[*] ContextsSerialized::GetPropAreaForName called");
        console.log("    name:", name);
        this.name = name;
      },
      onLeave: function (retval) {
        console.log("[*] ContextsSerialized::GetPropAreaForName returned");
        if (retval.isNull()) {
          console.log("    Return value: nullptr");
        } else {
          console.log("    Return value: 0x" + retval.toString());
        }
      }
    });
  } else {
    console.log("[-] ContextsSerialized::GetPropAreaForName not found");
  }
}
```

**说明:**

*   你需要根据目标设备的架构 (arm 或 arm64) 调整代码。
*   你需要找到 `ContextsSerialized::Initialize` 和 `ContextsSerialized::GetPropAreaForName` 函数的符号名称。可以使用 `adb shell "grep 'ContextsSerialized::Initialize' /proc/$(pidof system_server)/maps"` 命令在运行时查找符号地址，然后推断符号名称。
*   这些 hook 会在函数被调用时打印相关信息，帮助你理解系统属性的加载和访问过程。

希望以上详细的解释能够帮助你理解 `bionic/libc/system_properties/contexts_serialized.cpp` 文件的功能和作用。

Prompt: 
```
这是目录为bionic/libc/system_properties/contexts_serialized.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "system_properties/contexts_serialized.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <new>

#include <async_safe/log.h>
#include <private/android_filesystem_config.h>

#include "system_properties/system_properties.h"

bool ContextsSerialized::InitializeContextNodes() {
  auto num_context_nodes = property_info_area_file_->num_contexts();
  auto context_nodes_mmap_size = sizeof(ContextNode) * num_context_nodes;
  // We want to avoid malloc in system properties, so we take an anonymous map instead (b/31659220).
  void* const map_result = mmap(nullptr, context_nodes_mmap_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map_result == MAP_FAILED) {
    return false;
  }

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, map_result, context_nodes_mmap_size,
        "System property context nodes");

  context_nodes_ = reinterpret_cast<ContextNode*>(map_result);
  num_context_nodes_ = num_context_nodes;
  context_nodes_mmap_size_ = context_nodes_mmap_size;

  for (size_t i = 0; i < num_context_nodes; ++i) {
    new (&context_nodes_[i]) ContextNode(property_info_area_file_->context(i), dirname_);
  }

  return true;
}

bool ContextsSerialized::MapSerialPropertyArea(bool access_rw, bool* fsetxattr_failed) {
  if (access_rw) {
    serial_prop_area_ = prop_area::map_prop_area_rw(
        serial_filename_.c_str(), "u:object_r:properties_serial:s0", fsetxattr_failed);
  } else {
    serial_prop_area_ = prop_area::map_prop_area(serial_filename_.c_str());
  }
  return serial_prop_area_;
}

// Note: load_default_path is only used for testing, as it will cause properties to be loaded from
// one file (specified by PropertyInfoAreaFile.LoadDefaultPath), but be written to "filename".
bool ContextsSerialized::InitializeProperties(bool load_default_path) {
  if (load_default_path && !property_info_area_file_.LoadDefaultPath()) {
    return false;
  } else if (!load_default_path && !property_info_area_file_.LoadPath(tree_filename_.c_str())) {
    return false;
  }

  if (!InitializeContextNodes()) {
    FreeAndUnmap();
    return false;
  }

  return true;
}

// Note: load_default_path is only used for testing, as it will cause properties to be loaded from
// one file (specified by PropertyInfoAreaFile.LoadDefaultPath), but be written to "filename".
bool ContextsSerialized::Initialize(bool writable, const char* dirname, bool* fsetxattr_failed,
                                    bool load_default_path) {
  dirname_ = dirname;
  tree_filename_ = PropertiesFilename(dirname, "property_info");
  serial_filename_ = PropertiesFilename(dirname, "properties_serial");

  if (!InitializeProperties(load_default_path)) {
    return false;
  }

  if (writable) {
    mkdir(dirname_, S_IRWXU | S_IXGRP | S_IXOTH);
    bool open_failed = false;
    if (fsetxattr_failed) {
      *fsetxattr_failed = false;
    }

    for (size_t i = 0; i < num_context_nodes_; ++i) {
      if (!context_nodes_[i].Open(true, fsetxattr_failed)) {
        open_failed = true;
      }
    }
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

prop_area* ContextsSerialized::GetPropAreaForName(const char* name) {
  uint32_t index;
  property_info_area_file_->GetPropertyInfoIndexes(name, &index, nullptr);
  if (index == ~0u || index >= num_context_nodes_) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "Could not find context for property \"%s\"",
                          name);
    return nullptr;
  }
  auto* context_node = &context_nodes_[index];
  if (!context_node->pa()) {
    // We explicitly do not check no_access_ in this case because unlike the
    // case of foreach(), we want to generate an selinux audit for each
    // non-permitted property access in this function.
    context_node->Open(false, nullptr);
  }
  return context_node->pa();
}

void ContextsSerialized::ForEach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  for (size_t i = 0; i < num_context_nodes_; ++i) {
    if (context_nodes_[i].CheckAccessAndOpen()) {
      context_nodes_[i].pa()->foreach (propfn, cookie);
    }
  }
}

void ContextsSerialized::ResetAccess() {
  for (size_t i = 0; i < num_context_nodes_; ++i) {
    context_nodes_[i].ResetAccess();
  }
}

void ContextsSerialized::FreeAndUnmap() {
  property_info_area_file_.Reset();
  if (context_nodes_ != nullptr) {
    for (size_t i = 0; i < num_context_nodes_; ++i) {
      context_nodes_[i].Unmap();
    }
    munmap(context_nodes_, context_nodes_mmap_size_);
    context_nodes_ = nullptr;
  }
  prop_area::unmap_prop_area(&serial_prop_area_);
  serial_prop_area_ = nullptr;
}

"""

```