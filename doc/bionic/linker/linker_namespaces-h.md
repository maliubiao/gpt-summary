Response:
Let's break down the thought process for answering the request about `linker_namespaces.h`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C++ header file (`linker_namespaces.h`). The key elements to address are:

* **Functionality:** What does this code *do*?  What are its main purposes?
* **Android Relationship:** How does it fit into the broader Android ecosystem? Provide concrete examples.
* **`libc` Functions:**  Detailed explanation of how any `libc` functions are implemented (though this file doesn't directly *implement* `libc` functions, it uses standard C++ library components, which needs clarification).
* **Dynamic Linker Functionality:** How does it relate to the dynamic linker?  Include SO layout and linking process.
* **Logic and Assumptions:**  Provide hypothetical inputs and outputs if logical deduction is involved.
* **Common Errors:**  Illustrate potential user or programming mistakes.
* **Android Framework/NDK Path:** Explain how the code is reached from higher levels. Include Frida hook examples.

**2. Initial Code Scan and Interpretation:**

The first step is to read through the code and identify the main data structures and their members. Key observations:

* **`android_namespace_t` struct:**  This is the central structure. It represents a namespace for libraries. Its members like `name_`, `is_isolated_`, `ld_library_paths_`, etc., immediately suggest its purpose: managing library visibility and isolation.
* **`android_namespace_link_t` struct:** This struct clearly deals with linking namespaces together, controlling which libraries are shared between them. The `shared_lib_sonames_` member is a key indicator of selective sharing.
* **Standard C++:** The code uses `std::string`, `std::vector`, `std::unordered_set`, indicating modern C++ usage. This is important for distinguishing it from low-level `libc` implementations.
* **No Direct `libc` Implementation:**  A quick scan doesn't reveal any explicit implementation of `libc` functions within this file. This needs to be addressed by clarifying that it *uses* standard C++ library components which *are often built on top of* `libc`.

**3. Connecting to Android Concepts:**

The names of the structs (`android_namespace_t`) and the members (like `ld_library_paths`) strongly suggest a connection to Android's library loading mechanism. The concept of isolated namespaces is crucial for Android's security and stability. Consider:

* **App Isolation:** Different apps need to be isolated so they don't interfere with each other's libraries.
* **System Library Management:** The system needs control over which libraries are accessible to different processes.
* **NDK Usage:** NDK developers often need to manage their own libraries.

**4. Dynamic Linker Implications:**

This file is located within the `linker` directory, making its connection to the dynamic linker obvious. The `android_namespace_t` structure likely plays a crucial role in how the dynamic linker resolves library dependencies at runtime. Think about:

* **SO Layout:**  How are shared libraries organized in memory? How do namespaces affect this?
* **Linking Process:** How does the dynamic linker use namespace information to find and load libraries?

**5. Addressing Specific Request Points:**

* **`libc` Functions:** Since there are no direct implementations, focus on explaining that the code relies on standard C++ library elements, which themselves often have `libc` underpinnings. Mention examples like string manipulation and container management.
* **SO Layout and Linking:**  Provide a simple example of how different namespaces might have access to different sets of libraries. Illustrate the search process the linker might follow.
* **Logic and Assumptions:** Consider a scenario where a library is only accessible through a linked namespace. Describe how the `is_accessible` methods would behave.
* **Common Errors:**  Think about mistakes developers might make related to library dependencies, especially when dealing with namespaces. Missing dependencies, conflicting versions, and incorrect namespace configurations are good examples.
* **Android Framework/NDK Path:** Trace the execution flow from an app loading a shared library down to the linker's namespace management. This involves concepts like `System.loadLibrary`, the zygote process, and the dynamic linker.

**6. Frida Hooking:**

Identify key functions or methods within the code that would be interesting to monitor or modify. `is_accessible` is a prime candidate as it controls library visibility.

**7. Structuring the Response:**

Organize the information logically, following the structure of the original request:

* **Functionality Overview:** Start with a high-level description.
* **Android Relationship and Examples:**  Provide clear connections to Android.
* **`libc` Clarification:** Explain the usage of standard C++ libraries.
* **Dynamic Linker Details:**  Focus on SO layout and the linking process.
* **Logic and Assumptions:** Present a clear scenario.
* **Common Errors:** Give practical examples.
* **Android Framework/NDK Path:**  Describe the steps and provide Frida examples.

**Self-Correction/Refinement:**

* **Initial thought:**  Perhaps focus heavily on low-level memory management related to the linker.
* **Correction:** The provided file is more about the *logical organization* of libraries within the linker, not the low-level memory allocation. Shift the focus accordingly.
* **Initial thought:** Directly explain the implementation of standard C++ functions.
* **Correction:** It's more accurate to state that this code *uses* standard C++ and that those libraries *may* be built on `libc`. Avoid going into the implementation details of standard library functions themselves.
* **Ensure clarity:**  Use precise language and avoid jargon where possible. Provide clear examples to illustrate abstract concepts.

By following this thought process, combining code analysis with an understanding of Android's architecture, and iteratively refining the approach, we arrive at a comprehensive and accurate answer to the request.
这个头文件 `bionic/linker/linker_namespaces.h` 定义了 Android 动态链接器中用于管理**链接命名空间 (linker namespaces)** 的核心数据结构和辅助函数。链接命名空间是 Android 为了提高安全性和隔离性而引入的一个重要概念。

**功能列举:**

1. **定义 `android_namespace_t` 结构体:**  该结构体代表一个独立的链接命名空间，包含了该命名空间内的库搜索路径、允许加载的库、以及与其他命名空间的链接关系等信息。
2. **定义 `android_namespace_link_t` 结构体:** 该结构体描述了一个命名空间与其他命名空间之间的链接关系，包括被链接的命名空间对象、允许共享的库名列表，以及是否允许共享所有库的标志。
3. **提供 `fix_lib_paths` 函数:**  该函数用于规范化库路径，例如处理路径分隔符等，确保路径的一致性。
4. **提供访问和修改 `android_namespace_t` 成员的方法:**  例如 `get_name()`, `set_ld_library_paths()`, `add_linked_namespace()` 等，用于管理命名空间的属性和关系。
5. **提供判断库是否可访问的方法:**  例如 `is_accessible(const std::string& path)` 和 `is_accessible(soinfo* si)`，用于确定在一个命名空间内，特定的库文件或已加载的库对象是否可以被访问。
6. **提供获取命名空间内库对象列表的方法:** 例如 `soinfo_list()`，用于遍历或管理命名空间内已加载的共享库对象。
7. **提供获取全局组和共享组库对象列表的方法:** `get_global_group()` 和 `get_shared_group()`，用于实现特定类型的库共享策略。

**与 Android 功能的关系及举例:**

链接命名空间是 Android 安全架构的关键组成部分，它主要用于实现以下功能：

* **应用隔离:**  每个 Android 应用通常运行在自己的链接命名空间中。这确保了应用只能访问其所需的库，避免了不同应用之间库版本的冲突，增强了系统的稳定性。
    * **例子:** 假设应用 A 依赖 libfoo.so 的版本 1.0，而应用 B 依赖 libfoo.so 的版本 2.0。通过使用不同的命名空间，这两个应用可以各自加载其所需的版本，而不会发生冲突。
* **系统库管理:** Android 系统也使用链接命名空间来管理系统库。例如，`/system/lib64` 和 `/vendor/lib64` 等目录下的库可能属于不同的命名空间，并有不同的访问权限。
    * **例子:** 系统服务可能可以访问 `/system/lib64` 下的所有库，而一个普通的应用程序只能访问它自己的命名空间以及通过链接允许访问的系统库。
* **NDK 库加载:**  NDK 开发的应用也可以利用链接命名空间来管理其依赖的共享库，特别是当需要加载特定版本的第三方库时。
    * **例子:** 一个使用特定版本 OpenGL ES 库的 NDK 应用，可以在其命名空间中加载该版本，而不会影响系统默认的 OpenGL ES 库。

**libc 函数的功能实现:**

这个头文件本身并没有 *实现* 任何 `libc` 函数。它定义的是用于管理动态链接过程的数据结构。然而，在动态链接器的实现中，肯定会用到 `libc` 中的一些函数，例如：

* **内存管理:** `malloc`, `free`, `calloc`, `realloc` 等，用于分配和释放内存来存储命名空间对象和相关数据。
* **字符串操作:** `strcmp`, `strcpy`, `strlen` 等，用于比较和操作库名称、路径等字符串信息。
* **文件系统操作:** `open`, `close`, `read` 等，用于查找和加载共享库文件（虽然这部分逻辑更多在动态链接器的其他部分）。

**详细解释每一个 libc 函数的功能是如何实现的:**  由于这个头文件不直接实现 `libc` 函数，因此无法在这里详细解释。你需要查看 `libc` 的源代码才能了解其实现细节。

**涉及 dynamic linker 的功能，对应的 so 布局样本以及链接的处理过程:**

`android_namespace_t` 中存储了与动态链接息息相关的信息，它指导着动态链接器如何查找和加载共享库。

**SO 布局样本:**

假设我们有两个命名空间：`default` (默认命名空间) 和 `app_namespace` (应用命名空间)。

```
/system/lib64/libc.so
/system/lib64/libutils.so
/vendor/lib64/libvendor.so
/data/app/com.example.myapp/lib/arm64-v8a/libapp.so
/data/app/com.example.myapp/lib/arm64-v8a/libmylib.so
```

* **`default` 命名空间:**
    * `ld_library_paths`: [`/system/lib64`, `/vendor/lib64`]
    * `soinfo_list`: 包含 `libc.so`, `libutils.so`, `libvendor.so` 的 `soinfo` 对象。

* **`app_namespace` 命名空间 (属于 `com.example.myapp` 应用):**
    * `ld_library_paths`: [`/data/app/com.example.myapp/lib/arm64-v8a`]
    * `linked_namespaces`: 链接到 `default` 命名空间，允许访问 `libc.so` 和 `libutils.so`。
    * `soinfo_list`: 包含 `libapp.so`, `libmylib.so` 的 `soinfo` 对象。

**链接的处理过程:**

1. **应用启动:** 当 `com.example.myapp` 应用启动时，Android 系统会为其创建一个新的链接命名空间 `app_namespace`。
2. **加载主可执行文件:** 动态链接器首先加载应用的主可执行文件 `libapp.so` 到 `app_namespace` 中。
3. **解析依赖:** 动态链接器解析 `libapp.so` 的依赖项，例如它可能依赖 `libmylib.so`, `libc.so`, 和 `libutils.so`。
4. **在当前命名空间中查找:** 动态链接器首先在 `app_namespace` 的 `ld_library_paths` 中查找 `libmylib.so`。如果找到，则加载。
5. **在链接的命名空间中查找:** 对于 `libc.so` 和 `libutils.so`，由于 `app_namespace` 链接到了 `default` 命名空间，并且被允许访问这两个库，动态链接器会在 `default` 命名空间的 `ld_library_paths` 中查找并加载它们。
6. **创建 `soinfo` 对象:**  对于每个成功加载的共享库，动态链接器会创建一个 `soinfo` 对象来记录其加载信息，并将其添加到对应命名空间的 `soinfo_list` 中。
7. **符号解析和重定位:** 动态链接器解析库之间的符号引用，并进行重定位，使得库中的代码可以正确调用彼此的函数和访问彼此的数据。

**逻辑推理，假设输入与输出:**

假设我们有以下代码在一个 `app_namespace` 中尝试加载共享库：

```c++
// 假设 libcustom.so 不在 app_namespace 的 ld_library_paths 中，
// 但在 default 命名空间的 ld_library_paths 中。
// 并且 app_namespace 没有显式链接到 default 命名空间并允许访问 libcustom.so。

void load_library() {
  void* handle = dlopen("libcustom.so", RTLD_NOW);
  if (handle == nullptr) {
    // 加载失败
    const char* error = dlerror();
    // error 可能会指示 "library not found" 或者与命名空间相关的错误
  } else {
    // 加载成功
  }
}
```

**假设输入:**

* 当前命名空间为 `app_namespace`。
* `app_namespace` 的 `ld_library_paths` 不包含 `libcustom.so` 的路径。
* `default` 命名空间的 `ld_library_paths` 包含 `libcustom.so` 的路径。
* `app_namespace` 没有链接到 `default` 命名空间，或者链接了但没有允许访问 `libcustom.so`。

**预期输出:**

`dlopen("libcustom.so", RTLD_NOW)` 将返回 `nullptr`，并且 `dlerror()` 可能会返回一个类似于 "library "libcustom.so" not found" 或者更详细的命名空间相关的错误信息，指示无法在当前命名空间及其链接的命名空间中找到该库。

**用户或者编程常见的使用错误:**

1. **忘记设置正确的库搜索路径:** NDK 开发者可能会忘记将他们的共享库路径添加到 `android_namespace_t` 的 `ld_library_paths` 中，导致动态链接器找不到库。
2. **错误的命名空间链接配置:** 在创建和配置命名空间链接时，可能会错误地设置允许共享的库列表，导致某些库无法被访问。
3. **在隔离的命名空间中依赖未链接的库:** 如果一个应用运行在一个隔离的命名空间中，它只能访问自身命名空间内的库以及显式链接并允许访问的库。尝试加载未链接的库会导致加载失败。
    * **例子:** 一个隔离的应用尝试 `dlopen("libutils.so")`，但其命名空间没有链接到包含 `libutils.so` 的系统命名空间，就会失败。
4. **假设全局可访问:**  开发者可能会错误地假设某些系统库在所有命名空间中都是可访问的，但实际上由于命名空间的隔离，需要显式链接才能访问。

**Android Framework or NDK 是如何一步步的到达这里:**

1. **应用启动 (Framework):**  当 Android Framework 启动一个新的应用进程时 (通常由 Zygote 进程 fork 出来)，系统会为该应用创建一个新的链接命名空间。
2. **加载器请求 (Framework/NDK):**  当应用需要加载一个共享库时，可以通过以下方式触发：
    * **Java 代码:** `System.loadLibrary("mylib")` 会调用到 Native 代码。
    * **NDK 代码:**  `dlopen("mylib.so", RTLD_NOW)` 直接调用动态链接器的接口。
3. **`android_dlopen_ext` (linker):**  无论是通过 Java 的 `System.loadLibrary` 还是 NDK 的 `dlopen`，最终都会调用到动态链接器的 `android_dlopen_ext` 函数。
4. **命名空间查找 (linker):** 在 `android_dlopen_ext` 内部，动态链接器会首先确定当前线程所属的命名空间。
5. **库搜索 (linker):**  动态链接器根据当前命名空间的配置 (`ld_library_paths`, `linked_namespaces` 等) 开始搜索目标库。`android_namespace_t` 中存储的路径信息和链接关系指导着这个搜索过程。
6. **加载和链接 (linker):**  一旦找到库文件，动态链接器会加载它到内存，创建 `soinfo` 对象，并进行符号解析和重定位。

**Frida Hook 示例调试这些步骤:**

以下是一些使用 Frida Hook 来观察链接命名空间相关行为的示例：

```javascript
// Hook dlopen 函数，查看库加载时的命名空间信息
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function(args) {
    this.filename = args[0].readCString();
    console.log("[dlopen] Loading library:", this.filename);
    // 获取当前线程的 linker_namespace (需要一些技巧，可能需要解析 linker 的内部数据结构)
    // 这里简化处理，假设存在一个 get_current_namespace 函数
    let currentNamespace = get_current_namespace();
    if (currentNamespace) {
      console.log("[dlopen] Current namespace:", currentNamespace.name_.readCString());
    }
  },
  onLeave: function(retval) {
    if (retval.isNull()) {
      console.error("[dlopen] Failed to load library:", this.filename, ", error:", dlerror().readCString());
    } else {
      console.log("[dlopen] Library loaded successfully at:", retval);
    }
  }
});

// Hook android_namespace_t 的 is_accessible 方法，查看库的可访问性检查
let android_namespace_t_is_accessible = null;
// 需要找到 is_accessible 方法的地址，可以通过符号信息或者内存扫描
// 假设已经找到了地址
if (android_namespace_t_is_accessible) {
  Interceptor.attach(android_namespace_t_is_accessible, {
    onEnter: function(args) {
      let namespacePtr = args[0];
      let pathPtr = args[1];
      let path = pathPtr.readCString();
      // 读取 namespace 结构体的 name_ 成员
      let namespaceNamePtr = namespacePtr.add(offsetof_namespace_name_); // 假设已知 name_ 的偏移量
      let namespaceName = namespaceNamePtr.readCString();
      console.log("[is_accessible] Checking accessibility of:", path, "in namespace:", namespaceName);
    },
    onLeave: function(retval) {
      console.log("[is_accessible] Result:", retval);
    }
  });
}

// 辅助函数 (需要根据实际情况实现)
function dlerror() {
  return new NativePointer(Module.findExportByName(null, "dlerror")());
}

// 假设存在获取当前命名空间的函数 (实际实现会更复杂)
function get_current_namespace() {
  // ... 实现获取当前线程命名空间的逻辑 ...
  return null; // 占位符
}

// 假设已知 android_namespace_t 结构体中 name_ 成员的偏移量
const offsetof_namespace_name_ = 0; // 需要替换为实际偏移量
```

**请注意:**

* 上述 Frida Hook 示例代码是概念性的，实际使用中需要根据目标 Android 版本的动态链接器实现细节进行调整，例如查找 `is_accessible` 方法的地址、获取当前命名空间等。
* Hook 动态链接器的内部函数需要 root 权限。
* 理解动态链接器的内部结构和数据布局对于编写有效的 Hook 脚本至关重要。

希望以上详细的解释能够帮助你理解 `bionic/linker/linker_namespaces.h` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/linker/linker_namespaces.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include "linker_common_types.h"

#include <string>
#include <vector>
#include <unordered_set>

std::vector<std::string> fix_lib_paths(std::vector<std::string> paths);

struct android_namespace_t;

struct android_namespace_link_t {
 public:
  android_namespace_link_t(android_namespace_t* linked_namespace,
                           std::unordered_set<std::string> shared_lib_sonames,
                           bool allow_all_shared_libs)
      : linked_namespace_(linked_namespace),
        shared_lib_sonames_(std::move(shared_lib_sonames)),
        allow_all_shared_libs_(allow_all_shared_libs) {}

  android_namespace_t* linked_namespace() const {
    return linked_namespace_;
  }

  const std::unordered_set<std::string>& shared_lib_sonames() const {
    return shared_lib_sonames_;
  }

  bool is_accessible(const char* soname) const {
    return allow_all_shared_libs_ || shared_lib_sonames_.find(soname) != shared_lib_sonames_.end();
  }

  bool allow_all_shared_libs() const {
    return allow_all_shared_libs_;
  }

 private:
  android_namespace_t* const linked_namespace_;
  const std::unordered_set<std::string> shared_lib_sonames_;
  bool allow_all_shared_libs_;
};

struct android_namespace_t {
 public:
  android_namespace_t() :
    is_isolated_(false),
    is_exempt_list_enabled_(false),
    is_also_used_as_anonymous_(false) {}

  const char* get_name() const { return name_.c_str(); }
  void set_name(const char* name) { name_ = name; }

  bool is_isolated() const { return is_isolated_; }
  void set_isolated(bool isolated) { is_isolated_ = isolated; }

  bool is_exempt_list_enabled() const { return is_exempt_list_enabled_; }
  void set_exempt_list_enabled(bool enabled) { is_exempt_list_enabled_ = enabled; }

  bool is_also_used_as_anonymous() const { return is_also_used_as_anonymous_; }
  void set_also_used_as_anonymous(bool yes) { is_also_used_as_anonymous_ = yes; }

  const std::vector<std::string>& get_ld_library_paths() const {
    return ld_library_paths_;
  }
  void set_ld_library_paths(std::vector<std::string>&& library_paths) {
    ld_library_paths_ = std::move(library_paths);
  }

  const std::vector<std::string>& get_default_library_paths() const {
    return default_library_paths_;
  }
  void set_default_library_paths(std::vector<std::string>&& library_paths) {
    default_library_paths_ = fix_lib_paths(std::move(library_paths));
  }
  void set_default_library_paths(const std::vector<std::string>& library_paths) {
    default_library_paths_ = fix_lib_paths(library_paths);
  }

  const std::vector<std::string>& get_permitted_paths() const {
    return permitted_paths_;
  }
  void set_permitted_paths(std::vector<std::string>&& permitted_paths) {
    permitted_paths_ = std::move(permitted_paths);
  }
  void set_permitted_paths(const std::vector<std::string>& permitted_paths) {
    permitted_paths_ = permitted_paths;
  }

  const std::vector<std::string>& get_allowed_libs() const { return allowed_libs_; }
  void set_allowed_libs(std::vector<std::string>&& allowed_libs) {
    allowed_libs_ = std::move(allowed_libs);
  }
  void set_allowed_libs(const std::vector<std::string>& allowed_libs) {
    allowed_libs_ = allowed_libs;
  }

  const std::vector<android_namespace_link_t>& linked_namespaces() const {
    return linked_namespaces_;
  }
  void add_linked_namespace(android_namespace_t* linked_namespace,
                            std::unordered_set<std::string> shared_lib_sonames,
                            bool allow_all_shared_libs) {
    linked_namespaces_.emplace_back(linked_namespace, std::move(shared_lib_sonames),
                                    allow_all_shared_libs);
  }

  void add_soinfo(soinfo* si) {
    soinfo_list_.push_back(si);
  }

  void add_soinfos(const soinfo_list_t& soinfos) {
    for (auto si : soinfos) {
      add_soinfo(si);
    }
  }

  void remove_soinfo(soinfo* si) {
    soinfo_list_.remove_if([&](soinfo* candidate) {
      return si == candidate;
    });
  }

  const soinfo_list_t& soinfo_list() const { return soinfo_list_; }

  // For isolated namespaces - checks if the file is on the search path;
  // always returns true for not isolated namespace.
  bool is_accessible(const std::string& path);

  // Returns true if si is accessible from this namespace. A soinfo
  // is considered accessible when it belongs to this namespace
  // or one of it's parent soinfos belongs to this namespace.
  bool is_accessible(soinfo* si);

  soinfo_list_t get_global_group();
  soinfo_list_t get_shared_group();

 private:
  std::string name_;
  bool is_isolated_;
  bool is_exempt_list_enabled_;
  bool is_also_used_as_anonymous_;
  std::vector<std::string> ld_library_paths_;
  std::vector<std::string> default_library_paths_;
  std::vector<std::string> permitted_paths_;
  std::vector<std::string> allowed_libs_;
  // Loader looks into linked namespace if it was not able
  // to find a library in this namespace. Note that library
  // lookup in linked namespaces are limited by the list of
  // shared sonames.
  std::vector<android_namespace_link_t> linked_namespaces_;
  soinfo_list_t soinfo_list_;

  DISALLOW_COPY_AND_ASSIGN(android_namespace_t);
};
```