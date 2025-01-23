Response:
Let's break down the thought process for analyzing the provided C++ benchmark code.

**1. Understanding the Goal:**

The first step is to grasp the purpose of the code. The filename "context_lookup_benchmark.cpp" and the `#include <benchmark/benchmark.h>` strongly suggest this is a performance test. The code seems to be comparing different methods of looking up system properties based on context.

**2. Identifying Key Components:**

Next, I scanned the code for important elements:

* **Includes:**  These tell us what libraries and headers are used. Notice `<ctype.h>`, `<stdarg.h>`, `<stdlib.h>`, `<string.h>`, `<unistd.h>` (standard C), `<string>`, `<vector>` (C++ STL), and then Android-specific includes: `<android-base/...>`, `<property_info_parser/...>`, `<property_info_serializer/...>`, `<system_properties/...>`. This indicates the code interacts with Android's property system.
* **`BENCHMARK_MAIN()`:** This confirms it's a Google Benchmark.
* **`LegacyPropertyMapping` class:** This class takes a `property_contexts` string and seems to parse and initialize it using `InitializePropertiesFromFile`. This likely represents the older way of handling property contexts.
* **`PropertiesToLookup()` function:**  This function generates a set of property names to test with. It takes lines from `aosp_s_property_contexts`, extracts the base property name, and adds variations like "propertyName0" and "propertyNameA". This is crucial for understanding the benchmark's input.
* **`LegacyLookupOreo` and `LegacyLookupS` functions:** These benchmarks use the `LegacyPropertyMapping` class and measure the time it takes to look up properties using `GetPrefixNodeForName`. The "Oreo" and "S" likely refer to different Android versions and their respective `property_contexts` data.
* **`CreateSerializedTrie()` function:**  This function parses a `property_contexts` file, builds a trie data structure from it, and serializes the trie. This suggests a more optimized way to store and access property context information.
* **`TrieLookupOreo` and `TrieLookupS` functions:** These benchmarks use the serialized trie and measure lookup performance using `trie->GetPropertyInfo`.
* **Global string variables (`oreo_property_contexts`, `aosp_s_property_contexts`):** These contain the actual data used for the benchmarks. Although not shown in the provided snippet, these are likely defined in the included `context_lookup_benchmark_data.h` file.

**3. Deciphering the Functionality:**

Based on the components, I deduced the following:

* **Purpose:** The code benchmarks two methods of looking up system property contexts: a legacy method and a trie-based method.
* **Legacy Method:**  Presumably, this involves string-based searching or a less optimized data structure for storing property context rules.
* **Trie Method:** This leverages a trie, which is a tree-like data structure efficient for prefix-based searching. This is a common optimization for looking up strings with shared prefixes.
* **Comparison:** The benchmarks compare the performance of these two methods using different sets of property context data (`oreo_property_contexts` and `aosp_s_property_contexts`), likely representing data from older and newer Android releases.

**4. Connecting to Android Features:**

The term "system properties" is a strong indicator of the code's relevance to Android. I know that system properties are used extensively in Android for configuration and communication between different parts of the system. The context information is used for security and access control, determining which processes can access or modify specific properties.

**5. Explaining libc Functions:**

I went through each included libc function and explained its basic purpose. For functions like `memcpy`, I provided a high-level overview of how such a fundamental operation might be implemented (looping and byte copying). The goal here is not a deep dive into the assembly-level implementation but a functional understanding.

**6. Addressing Dynamic Linker Aspects:**

The code itself doesn't directly call dynamic linker functions like `dlopen` or `dlsym`. However, the use of shared libraries (`.so` files) is implicit in the Android environment. Therefore, I explained the general role of the dynamic linker in loading these libraries and resolving symbols. I provided a simplified `.so` layout and a basic linking scenario to illustrate the process.

**7. Considering Logic and Assumptions:**

The primary logic is within the benchmark setup and execution. The `PropertiesToLookup` function makes a specific assumption about how property names are constructed (adding "0" and "A"). This is an important detail to note. The assumption is that the `*_property_contexts` strings follow a specific format.

**8. Identifying Potential User Errors:**

I considered common mistakes developers might make when working with system properties, such as incorrect property names, permissions issues, and reliance on undocumented properties.

**9. Tracing the Path from Framework/NDK:**

This requires understanding how system properties are used in Android. I outlined the general flow, starting from an application or system service, going through the Android framework (SystemServer, init), and eventually reaching the native code in Bionic that manages these properties. The key is to show the layers involved.

**10. Providing Frida Hook Examples:**

To demonstrate debugging, I crafted Frida hook examples targeting the key functions being benchmarked (`GetPrefixNodeForName` and `GetPropertyInfo`). The hooks log input parameters, which is a standard debugging technique.

**11. Structuring the Response:**

Finally, I organized the information into logical sections with clear headings, as requested in the prompt, to make it easy to read and understand. Using bullet points, code blocks, and clear explanations helped to present the information effectively.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the exact data structures used in the legacy method.
* **Correction:** Realized a high-level understanding of the comparison is more important than low-level implementation details of the *legacy* method, as the focus is on the benchmark.
* **Initial thought:**  Provide assembly-level details for libc functions.
* **Correction:**  A high-level explanation of their functionality is sufficient for this context. The goal is understanding *what* they do, not necessarily *how* they are implemented at the lowest level.
* **Emphasis:**  Ensure the explanation clearly links the code back to core Android functionality (system properties, security contexts).

By following these steps and continually refining my understanding, I aimed to provide a comprehensive and accurate explanation of the provided code.
好的，让我们详细分析一下 `bionic/libc/system_properties/context_lookup_benchmark.cpp` 这个文件。

**文件功能总览**

这个 C++ 文件是一个基准测试程序（benchmark），用于评估在 Android 系统中查找属性上下文（property context）的性能。它比较了两种查找方法：

1. **传统方法 (Legacy):**  这种方法使用一个基于字符串的结构来存储和查找属性上下文信息。
2. **基于 Trie 树的方法:**  这种方法使用 Trie 树（也称为前缀树）来优化属性上下文的查找效率。

该基准测试模拟了在 Android 系统中根据属性名称查找其关联安全上下文的过程，并比较了两种方法的性能差异。

**与 Android 功能的关系及举例说明**

这个文件直接关系到 Android 系统属性（System Properties）的功能。

* **系统属性 (System Properties):**  Android 使用系统属性来存储和访问各种配置信息和状态。这些属性以键值对的形式存在，例如 `ro.build.version.sdk` 表示 SDK 版本，`wifi.interface` 表示 Wi-Fi 接口名称。
* **安全上下文 (Security Context):**  Android 使用 SELinux（Security-Enhanced Linux）进行安全管理。每个进程、文件、属性等都有一个安全上下文，用于定义其权限。
* **属性上下文 (Property Context):**  为了加强对系统属性的访问控制，Android 引入了属性上下文。属性上下文定义了哪些进程可以读取或写入哪些属性。例如，只有具有特定安全上下文的进程才能修改 `ro.debuggable` 属性。

**举例说明:**

假设我们想查找属性 `ro.debuggable` 的安全上下文。

* **传统方法:**  代码会遍历一个存储了属性上下文规则的列表，逐个比较属性名称的前缀，直到找到匹配的规则。
* **基于 Trie 树的方法:**  代码会沿着 Trie 树的路径，根据属性名称的字符逐个匹配节点，最终快速定位到属性的安全上下文信息。

`context_lookup_benchmark.cpp` 就是用来衡量这两种方法查找 `ro.debuggable` 或其他属性的上下文信息的速度。

**详细解释每个 libc 函数的功能实现**

文件中用到的 libc 函数包括：

* **`<ctype.h>`:**
    * **没有直接使用该头文件中的函数。**  虽然包含了，但代码中并没有调用 `isalpha`, `isdigit` 等字符处理函数。

* **`<stdarg.h>`:**
    * **没有直接使用该头文件中的函数。**  通常用于实现可变参数函数，如 `printf`，但此代码中未使用。

* **`<stdlib.h>`:**
    * **`atoi`，`atol`，`atoll`，`atof`，`strtol`，`strtoll`，`strtoul`，`strtoull`，`strtof`，`strtod`，`strtold`:** 这些是字符串转换成数字的函数，用于将字符表示的数字转换为相应的数值类型。**在此文件中未使用。**
    * **`malloc`，`calloc`，`realloc`，`free`:** 用于动态内存分配和释放。**在此文件中未使用。** 代码中使用了 C++ 的 `std::string` 和 `std::vector`，它们内部会自动管理内存。
    * **`exit`，`abort`:**  用于终止程序执行。  **在此文件中隐式使用。** `LOG(FATAL)` 宏内部可能会调用 `abort` 来终止程序。
    * **`getenv`，`system`:** 用于访问环境变量和执行 shell 命令。 **在此文件中未使用。**
    * **`rand`，`srand`:** 用于生成随机数。 **在此文件中未使用。**

* **`<string.h>`:**
    * **`strcpy`，`strncpy`:** 用于复制字符串。 **在此文件中未使用。**
    * **`strcat`，`strncat`:** 用于连接字符串。 **在此文件中未使用。**
    * **`strcmp`，`strncmp`:** 用于比较字符串。  **传统方法的 `ContextsSplit::GetPrefixNodeForName` 内部可能会用到 `strncmp` 来比较属性名称前缀。**
    * **`strlen`:** 用于获取字符串的长度。 **传统方法的 `ContextsSplit::GetPrefixNodeForName` 内部可能会用到 `strlen` 来确定字符串的长度。**
    * **`memcpy`，`memmove`:** 用于复制内存块。 **基于 Trie 树的方法中，序列化和反序列化 Trie 树结构时可能会用到 `memcpy`。**  `memcpy` 通常通过循环逐字节复制内存，而 `memmove` 可以处理源地址和目标地址重叠的情况。
    * **`memset`:** 用于将内存块设置为特定的值。 **可能在 `ContextsSplit` 的初始化过程中使用，用于初始化内部数据结构。**

* **`<unistd.h>`:**
    * **`close`:** 用于关闭文件描述符。 **在 `LegacyPropertyMapping` 构造函数中，使用 `TemporaryFile` 对象时，其析构函数会调用 `close` 关闭临时文件描述符。**
    * **`read`，`write`:** 用于读写文件。 **`WriteStringToFd` 函数内部会调用 `write` 将字符串写入文件描述符。`InitializePropertiesFromFile` 可能会调用 `read` 从文件中读取数据。**

**对于涉及 dynamic linker 的功能，给出对应的 so 布局样本以及链接的处理过程**

虽然这个 benchmark 代码本身没有直接调用动态链接器 (`dlopen`, `dlsym` 等) 的 API，但它作为 Android 系统的一部分，最终会被动态链接器加载和执行。

**so 布局样本 (简化)**

假设 `context_lookup_benchmark` 可执行文件链接了 `libc.so` 和其他必要的动态链接库，一个简化的 `libc.so` 布局可能如下：

```
libc.so:
    .text        # 存放代码段 (例如 strlen, memcpy 的实现)
    .data        # 存放已初始化的全局变量
    .bss         # 存放未初始化的全局变量
    .rodata      # 存放只读数据
    .symtab      # 符号表 (包含导出的函数和变量)
    .strtab      # 字符串表 (用于存储符号名称)
    .dynsym      # 动态符号表
    .dynstr      # 动态字符串表
    .rel.dyn     # 重定位表 (用于动态链接)
    .rel.plt     # PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程**

1. **编译时链接:** 当编译 `context_lookup_benchmark.cpp` 时，链接器会记录它依赖 `libc.so` 中的符号（例如 `strlen`, `memcpy` 等）。
2. **加载时链接:** 当 Android 系统执行 `context_lookup_benchmark` 时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责：
    * **加载依赖的 .so 文件:** 加载 `libc.so` 到内存中。
    * **符号查找和重定位:**  遍历 `context_lookup_benchmark` 的重定位表 (`.rel.dyn` 和 `.rel.plt`)，找到对 `libc.so` 中符号的引用。然后在 `libc.so` 的动态符号表 (`.dynsym`) 中查找这些符号的地址。
    * **地址修正:** 将 `context_lookup_benchmark` 中对 `libc.so` 函数的调用地址修正为 `libc.so` 中对应函数的实际内存地址。例如，如果代码中调用了 `strlen`，动态链接器会将其跳转地址指向 `libc.so` 中 `strlen` 函数的代码段。

**PLT (Procedure Linkage Table) 和 GOT (Global Offset Table):**  对于外部函数的调用，通常会使用 PLT 和 GOT 机制来实现延迟绑定（lazy binding）。第一次调用外部函数时，会跳转到 PLT 中的一段代码，这段代码会调用动态链接器来解析符号地址并更新 GOT 表项。后续的调用会直接跳转到 GOT 表中已解析的地址，从而提高效率。

**假设输入与输出 (逻辑推理)**

这个文件主要是做性能测试，所以更关注运行时间。

**假设输入:**

* **`oreo_property_contexts` 和 `aosp_s_property_contexts`:** 这两个字符串变量包含了不同 Android 版本（Oreo 和 S）的属性上下文规则。其内容格式通常是每行一个规则，包含属性名称前缀和对应的安全上下文信息。例如：
    ```
    # comment
    ro.build.version.sdk u:object_r:system_prop:s0
    wifi.            u:object_r:wifi_prop:s0
    ```
* **执行 benchmark 的次数和迭代次数:**  Google Benchmark 框架会控制 benchmark 的运行次数和每次运行的迭代次数，以获得更准确的性能数据。

**假设输出:**

Benchmark 的输出会显示不同查找方法的性能指标，通常是每次查找操作的平均时间（例如，纳秒/次）。例如：

```
BM_LegacyLookupOreo/iterations:10000        /real_time_per_iteration:123 ns
BM_LegacyLookupS/iterations:10000           /real_time_per_iteration:150 ns
BM_TrieLookupOreo/iterations:10000         /real_time_per_iteration:50 ns
BM_TrieLookupS/iterations:10000            /real_time_per_iteration:60 ns
```

从这个假设的输出可以看出：

* 基于 Trie 树的方法 (TrieLookup) 比传统方法 (LegacyLookup) 快得多。
* 在 Android S 上的查找速度比 Oreo 上略慢，可能是因为属性上下文规则更多更复杂。

**涉及用户或者编程常见的使用错误，举例说明**

虽然这个 benchmark 代码本身不是用户直接编写和使用的，但它测试的功能与 Android 开发密切相关。用户或开发者在使用系统属性时可能会遇到以下错误：

1. **使用错误的属性名称:**  拼写错误或使用了不存在的属性名称，导致无法获取到期望的值。
   ```java
   // 错误示例
   String sdkVersion = SystemProperties.get("ro.bluid.version.sdk"); // "bluid" 拼写错误
   ```

2. **尝试修改只读属性:**  有些系统属性是只读的，尝试修改会导致失败或没有效果。
   ```java
   // 错误示例 (在普通应用中无法修改)
   SystemProperties.set("ro.debuggable", "1");
   ```

3. **权限不足:**  尝试读取或写入需要特定权限的属性，例如安全相关的属性。
   ```java
   // 错误示例 (普通应用无法修改安全属性)
   SystemProperties.set("persist.sys.usb.config", "adb");
   ```

4. **依赖于非公开或隐藏的属性:**  某些属性可能没有文档记录，其行为或存在性在不同 Android 版本之间可能会发生变化，导致应用不稳定。

5. **过度使用系统属性:**  系统属性主要用于配置信息，不适合作为进程间通信或数据存储的主要方式。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤**

**Android Framework 到 Bionic 的路径 (简化)**

1. **Java 代码请求:** Android Framework 或应用通过 Java API（例如 `android.os.SystemProperties`）访问系统属性。

2. **System Server 处理:**  `SystemProperties` 的 Java 代码会通过 JNI (Java Native Interface) 调用到 Native 代码。这个 Native 代码通常位于 `/system/lib64/libutils.so` 或 `libcutils.so` 中。

3. **Native 函数调用:** `libutils.so` 或 `libcutils.so` 中的函数（例如 `property_get`, `property_set`) 会进一步调用 Bionic 中 `libc.so` 提供的系统属性相关函数。

4. **Bionic 处理:** `libc.so` 中的函数（例如 `__system_property_get`, `__system_property_set`) 负责实际的属性查找和设置操作，这其中就会涉及到属性上下文的查找，而 `context_lookup_benchmark.cpp` 测试的就是这个查找过程的性能。

**Frida Hook 示例**

我们可以使用 Frida Hook 来观察这个调用链。以下是一些可能的 Hook 点和示例代码：

**Hook Java Framework (观察 `SystemProperties.get`)**

```javascript
Java.perform(function() {
  var SystemProperties = Java.use("android.os.SystemProperties");
  SystemProperties.get.overload('java.lang.String').implementation = function(key) {
    console.log("[Frida] SystemProperties.get called with key: " + key);
    var result = this.get(key);
    console.log("[Frida] SystemProperties.get returned: " + result);
    return result;
  };
});
```

**Hook Native 代码 (`libutils.so` 或 `libcutils.so`)**

假设我们要 Hook `libcutils.so` 中的 `property_get` 函数：

```javascript
var libcutils = Process.getModuleByName("libcutils.so");
var property_get_ptr = libcutils.getExportByName("property_get");

if (property_get_ptr) {
  Interceptor.attach(property_get_ptr, {
    onEnter: function(args) {
      var name = Memory.readCString(args[0]);
      console.log("[Frida] property_get called with name: " + name);
    },
    onLeave: function(retval) {
      if (retval) {
        var value = Memory.readCString(retval);
        console.log("[Frida] property_get returned value: " + value);
      } else {
        console.log("[Frida] property_get returned NULL");
      }
    }
  });
} else {
  console.log("[Frida] Could not find property_get in libcutils.so");
}
```

**Hook Bionic (`libc.so`)**

假设我们要 Hook `libc.so` 中的 `__system_property_get` 函数:

```javascript
var libc = Process.getModuleByName("libc.so");
var system_property_get_ptr = libc.getExportByName("__system_property_get");

if (system_property_get_ptr) {
  Interceptor.attach(system_property_get_ptr, {
    onEnter: function(args) {
      var name = Memory.readCString(args[0]);
      console.log("[Frida] __system_property_get called with name: " + name);
    },
    onLeave: function(retval) {
      if (retval > 0) {
        var valueBuf = Memory.alloc(this.context.r1 * 1); // 假设返回值是写入缓冲区的长度，缓冲区地址在 r1
        Memory.copy(valueBuf, this.context.r1, retval.toInt());
        var value = Memory.readCString(valueBuf);
        console.log("[Frida] __system_property_get returned value: " + value);
      } else {
        console.log("[Frida] __system_property_get returned error");
      }
    }
  });
} else {
  console.log("[Frida] Could not find __system_property_get in libc.so");
}
```

**调试步骤:**

1. **启动 Frida Server:** 在 Android 设备或模拟器上运行 Frida Server。
2. **编写 Frida Hook 脚本:** 根据需要 Hook 的函数编写 JavaScript 脚本。
3. **运行目标应用或进程:** 启动你需要观察其系统属性访问行为的应用或进程（例如 `system_server`）。
4. **运行 Frida 脚本:** 使用 Frida 客户端工具 (例如 `frida -U -f <package_name> -l script.js`) 将 Hook 脚本注入到目标进程。
5. **观察输出:** 在 Frida 控制台中观察 Hook 到的日志信息，了解系统属性的访问过程和参数。

通过这些 Hook，你可以逐步跟踪 Android Framework 如何调用到 Bionic 的系统属性相关代码，并验证 `context_lookup_benchmark.cpp` 中测试的查找逻辑是否被使用。

希望以上分析对您有所帮助！

### 提示词
```
这是目录为bionic/libc/system_properties/context_lookup_benchmark.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <benchmark/benchmark.h>
#include <property_info_parser/property_info_parser.h>
#include <property_info_serializer/property_info_serializer.h>
#include <system_properties/contexts_split.h>

#include "context_lookup_benchmark_data.h"

using android::base::Split;
using android::base::WriteStringToFd;
using android::properties::BuildTrie;
using android::properties::ParsePropertyInfoFile;
using android::properties::PropertyInfoArea;
using android::properties::PropertyInfoEntry;

BENCHMARK_MAIN();

class LegacyPropertyMapping : public ContextsSplit {
 public:
  LegacyPropertyMapping(const char* property_contexts) {
    TemporaryFile file;
    if (!WriteStringToFd(property_contexts, file.fd)) {
      PLOG(FATAL) << "Could not write to temporary file";
    }

    if (!InitializePropertiesFromFile(file.path)) {
      LOG(FATAL) << "Could not initialize properties";
    }
  }
};

static std::vector<std::string> PropertiesToLookup() {
  std::vector<std::string> properties;
  auto property_lines = Split(aosp_s_property_contexts, "\n");
  for (const auto& line : property_lines) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto property = Split(line, " ")[0];
    properties.push_back(property);
    properties.push_back(property + "0");
    properties.push_back(property + "A");
  }
  return properties;
}

static void LegacyLookupOreo(benchmark::State& state) {
  LegacyPropertyMapping mapping(oreo_property_contexts);
  auto properties = PropertiesToLookup();
  for (auto _ : state) {
    for (const auto& property : properties) {
      benchmark::DoNotOptimize(mapping.GetPrefixNodeForName(property.c_str()));
    }
  }
}
BENCHMARK(LegacyLookupOreo);

static void LegacyLookupS(benchmark::State& state) {
  LegacyPropertyMapping mapping(aosp_s_property_contexts);
  auto properties = PropertiesToLookup();
  for (auto _ : state) {
    for (const auto& property : properties) {
      benchmark::DoNotOptimize(mapping.GetPrefixNodeForName(property.c_str()));
    }
  }
}
BENCHMARK(LegacyLookupS);

static std::string CreateSerializedTrie(const char* input_file) {
  std::vector<std::string> errors;
  std::vector<PropertyInfoEntry> property_infos;
  ParsePropertyInfoFile(input_file, false, &property_infos, &errors);

  std::string serialized_trie;
  std::string error;
  if (!BuildTrie(property_infos, "u:object_r:default_prop:s0", "string", &serialized_trie,
                 &error)) {
    LOG(FATAL) << "Could not build trie: " << error;
  }
  return serialized_trie;
}

static void TrieLookupOreo(benchmark::State& state) {
  std::string serialized_trie = CreateSerializedTrie(oreo_property_contexts);
  PropertyInfoArea* trie = reinterpret_cast<PropertyInfoArea*>(serialized_trie.data());
  auto properties = PropertiesToLookup();
  for (auto _ : state) {
    for (const auto& property : properties) {
      trie->GetPropertyInfo(property.c_str(), nullptr, nullptr);
    }
  }
}
BENCHMARK(TrieLookupOreo);

static void TrieLookupS(benchmark::State& state) {
  std::string serialized_trie = CreateSerializedTrie(aosp_s_property_contexts);
  PropertyInfoArea* trie = reinterpret_cast<PropertyInfoArea*>(serialized_trie.data());
  auto properties = PropertiesToLookup();
  for (auto _ : state) {
    for (const auto& property : properties) {
      trie->GetPropertyInfo(property.c_str(), nullptr, nullptr);
    }
  }
}
BENCHMARK(TrieLookupS);
```