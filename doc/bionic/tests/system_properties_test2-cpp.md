Response:
Let's break down the thought process to generate the detailed response for the `system_properties_test2.cpp` file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C++ source code for a system properties test in Android's Bionic library. The key elements to address are:

* **Functionality:** What does the code *do*?
* **Relationship to Android:** How does it connect to the broader Android system?
* **libc Function Implementation:** Details about the underlying C library functions used.
* **Dynamic Linker Involvement:**  Any interaction with the dynamic linker and related concepts.
* **Logical Reasoning and Examples:** Hypothetical inputs and outputs to illustrate the code's behavior.
* **Common User Errors:** Potential mistakes developers might make.
* **Android Framework/NDK Connection:**  How the test relates to higher-level Android development.
* **Frida Hooking:** Demonstrating debugging and observation.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to read through the code and identify its main purpose. Keywords like `TEST`, `ASSERT_EQ`, `__system_property_set`, `__system_property_get`, `__system_property_find`, and `__system_property_read_callback` immediately jump out. The `#if defined(__BIONIC__)` blocks clearly indicate that this test is specific to the Bionic C library environment.

This leads to the initial conclusion: This code tests the functionality of the system property APIs provided by Bionic. System properties are key-value pairs used for configuration and inter-process communication in Android.

**3. Analyzing Individual Test Cases:**

The code is organized into `TEST` blocks, making analysis easier. Let's consider each test case:

* **`properties.smoke`:** This test covers the core functionality of setting, getting, and finding system properties. It also checks edge cases like long property names and invalid property values. The use of `NanoTime()` and `getpid()` suggests an attempt to create unique property names to avoid conflicts between test runs.

* **`properties.no_fd_leaks`:**  This test focuses on resource management. It repeatedly sets and gets properties to ensure that no file descriptors are leaked during these operations. The `FdLeakChecker` (even though its implementation is not provided) hints at a mechanism to track open file descriptors.

* **`properties.empty_value`:** This test specifically checks how the system property mechanism handles empty string values.

**4. Addressing Specific Requirements (Iterative Refinement):**

Now, we systematically go through each part of the request, leveraging the understanding gained from the code analysis:

* **Functionality:**  Summarize the actions performed by each test case in clear, concise language. Focus on the verbs – set, get, find, read, check.

* **Relationship to Android:** Explain *why* system properties are important in Android. Mention their role in configuration, inter-process communication, and accessing system information. Give concrete examples, like build version, language settings, and debugging flags.

* **libc Function Implementation:**  This requires knowledge of the Bionic implementation of the system property APIs. Since the source code doesn't provide that *internal* implementation, the answer must focus on the *intended behavior* and general system call concepts. For example,  `__system_property_set` likely interacts with a system service (`/system/bin/init`) that manages properties. `__system_property_get` would involve querying this service. Acknowledge that the exact implementation details are not directly visible in this test file.

* **Dynamic Linker Involvement:**  System properties themselves aren't directly related to the dynamic linker. However, the dynamic linker *uses* system properties for configuration (e.g., `DEBUGGABLE`). So, the connection is indirect. Provide a basic `.so` layout and explain the dynamic linking process in general terms, highlighting how environment variables and potentially system properties can influence it.

* **Logical Reasoning and Examples:** Choose a simple scenario from the `smoke` test (setting and getting a property) and explicitly show the input (property name, value) and expected output.

* **Common User Errors:** Think about typical mistakes developers make when working with system properties. Examples include exceeding length limits, using incorrect names, and assuming immediate propagation of changes.

* **Android Framework/NDK Connection:** Trace the path from a high-level Android API (like `SystemProperties` in Java) down to the native layer and finally to the Bionic implementation. Mention the NDK as the bridge for native code access.

* **Frida Hooking:**  Demonstrate how Frida can be used to intercept calls to the `__system_property_set` and `__system_property_get` functions. Provide a basic JavaScript snippet showing how to log arguments and return values.

**5. Structuring the Response:**

Organize the information logically, following the order of the request. Use headings and bullet points to improve readability. Provide clear and concise explanations.

**6. Language and Tone:**

Maintain a professional and informative tone. Use clear and accurate Chinese terminology.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on the *exact* implementation of libc functions.
* **Correction:** Realize that the test code only *uses* these functions. The internal implementation is not directly visible. Shift focus to the expected behavior and the general concepts involved.

* **Initial thought:**  Overlook the indirect connection between system properties and the dynamic linker.
* **Correction:**  Recognize that the dynamic linker *reads* system properties for configuration, even if it doesn't directly manage them.

* **Initial thought:**  Provide overly complex Frida examples.
* **Correction:**  Simplify the Frida code to illustrate the basic hooking concept effectively.

By following this structured approach, iteratively refining the analysis, and addressing each part of the request methodically, a comprehensive and accurate response can be generated. The key is to move from a high-level understanding to more specific details, constantly relating the code back to the broader Android ecosystem.

好的，我们来详细分析一下 `bionic/tests/system_properties_test2.cpp` 这个文件。

**功能概述**

`system_properties_test2.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试 Bionic 提供的系统属性 (system properties) 相关 API 的功能和稳定性。系统属性是 Android 系统中一种全局的键值对存储机制，用于配置系统行为、传递进程间信息等。

这个测试文件主要关注以下几个方面：

* **基本读写功能:** 测试设置 (`__system_property_set`) 和获取 (`__system_property_get`) 系统属性的功能是否正常。
* **属性值长度限制:** 测试设置超出最大长度限制的属性值是否会失败，以及现有值是否会被保留。
* **属性名长度限制:** 测试设置长属性名的功能是否正常。
* **查找和读取回调:** 测试 `__system_property_find` 和 `__system_property_read_callback` 函数的功能，用于查找特定属性并进行回调处理。
* **读取功能:** 测试 `__system_property_read` 函数的功能，用于读取属性名和属性值。
* **资源泄漏:** 测试在频繁设置和获取属性时，是否存在文件描述符泄漏的情况。
* **空值处理:** 测试设置和获取空字符串作为属性值时的行为。

**与 Android 功能的关系及举例**

系统属性是 Android 系统中非常核心的机制，许多 Android 功能都依赖于它。

* **系统配置:**  Android 框架和系统服务使用系统属性来存储和读取各种配置信息。
    * **例子:**  `ro.build.version.sdk` 属性存储了 Android SDK 版本。
    * **例子:**  `persist.sys.language` 和 `persist.sys.country` 属性存储了当前的语言和国家设置。
    * **例子:**  `debug.adb.tcp.port` 属性用于设置 adb over TCP 的端口号。

* **进程间通信 (IPC):**  虽然不是主要的 IPC 机制，但系统属性可以作为简单的进程间通信方式。进程可以设置或监听属性的变化，从而传递一些简单的信号或数据。
    * **例子:**  一个进程可以设置一个特定的属性来通知另一个进程执行某些操作。

* **功能开关:**  系统属性可以作为某些功能的开关。
    * **例子:**  `debug.hwui.render_dirty_regions` 属性用于控制是否高亮显示需要重绘的区域，方便开发者调试 UI 性能问题。

* **系统状态监控:**  一些系统属性反映了系统的当前状态。
    * **例子:**  `sys.boot_completed` 属性指示系统启动是否完成。

**libc 函数功能详解**

该测试文件主要使用了以下 Bionic 提供的系统属性相关 libc 函数：

1. **`__system_property_set(const char *name, const char *value)`:**
   * **功能:**  设置一个系统属性。如果属性不存在，则创建它；如果属性已存在，则更新它的值。
   * **实现:**  这个函数通常会通过系统调用与 `init` 进程（Android 系统的第一个进程，负责属性服务的管理）进行通信。`init` 进程维护着系统属性的存储。
   * **内部过程 (简化描述):**
      * 测试代码调用 `__system_property_set`。
      * Bionic 库会将属性名和属性值打包成一个消息。
      * 这个消息通过某种 IPC 机制（例如，UNIX 域套接字）发送给 `init` 进程。
      * `init` 进程接收到消息后，会更新其内部的属性存储。
      * `__system_property_set` 返回操作结果（通常 0 表示成功，-1 表示失败）。
   * **假设输入与输出:**
      * **输入:** `name = "debug.test.my_property"`, `value = "test_value"`
      * **输出:** `0` (表示设置成功)

2. **`__system_property_get(const char *name, char *value)`:**
   * **功能:**  获取指定名称的系统属性的值。
   * **实现:**  类似于 `__system_property_set`，这个函数也会与 `init` 进程通信。
   * **内部过程 (简化描述):**
      * 测试代码调用 `__system_property_get`。
      * Bionic 库将属性名打包成消息发送给 `init` 进程。
      * `init` 进程查找该属性，并将属性值返回给调用进程。
      * `__system_property_get` 将返回的属性值复制到 `value` 指向的缓冲区，并返回属性值的长度。如果属性不存在，则返回 0。
   * **假设输入与输出:**
      * **假设已经通过 `__system_property_set` 设置了 `debug.test.my_property` 为 "test_value"`
      * **输入:** `name = "debug.test.my_property"`, `value` (一个足够大的字符数组)
      * **输出:** 返回 `10` (表示属性值长度)，`value` 的内容为 `"test_value"`。

3. **`__system_property_find(const char *name)`:**
   * **功能:**  查找指定名称的系统属性的 `prop_info` 结构体。`prop_info` 包含了属性的元数据。
   * **实现:**  这个函数通常会在 Bionic 库的内部缓存中查找属性信息，或者与 `init` 进程通信获取。
   * **内部过程 (简化描述):**
      * 测试代码调用 `__system_property_find`。
      * Bionic 库尝试在其内部维护的属性信息缓存中查找。
      * 如果找不到，可能会向 `init` 进程查询。
      * 返回指向 `prop_info` 结构的指针，如果找不到则返回 `nullptr`。
   * **假设输入与输出:**
      * **假设已经设置了 `debug.test.my_property`**
      * **输入:** `name = "debug.test.my_property"`
      * **输出:** 指向该属性 `prop_info` 结构的指针 (非 `nullptr`)

4. **`__system_property_read_callback(const prop_info *pi, void (*callback)(void *cookie, const char *name, const char *value, unsigned serial), void *cookie)`:**
   * **功能:**  使用回调函数读取指定 `prop_info` 结构体对应的属性信息。
   * **实现:**  这个函数接收一个 `prop_info` 指针，以及一个回调函数。它会调用回调函数，并将属性名和属性值作为参数传递给回调函数。
   * **内部过程 (简化描述):**
      * 测试代码调用 `__system_property_read_callback`，传入 `prop_info` 和回调函数。
      * Bionic 库从 `prop_info` 中获取属性名和属性值。
      * 调用提供的回调函数，将属性名、属性值以及用户提供的 `cookie` 传递给它。
   * **假设输入与输出:**
      * **假设 `pi` 是通过 `__system_property_find("debug.test.my_property")` 获取的，且属性值为 "test_value"`
      * **输入:** `pi`, `callback` (一个打印属性名和值的函数), `cookie` (例如，一个字符串 "context")
      * **输出:**  回调函数会被调用，输出类似于 "Property name: debug.test.my_property, value: test_value, cookie: context"。

5. **`__system_property_read(const prop_info *pi, char *name, char *value)`:**
   * **功能:**  读取指定 `prop_info` 结构体对应的属性名和属性值，并将它们复制到提供的缓冲区中。
   * **实现:**  类似于 `__system_property_read_callback`，但它直接将结果写入缓冲区而不是通过回调函数。
   * **内部过程 (简化描述):**
      * 测试代码调用 `__system_property_read`，传入 `prop_info` 和用于存储属性名和值的缓冲区。
      * Bionic 库从 `prop_info` 中获取属性名和属性值。
      * 将属性名复制到 `name` 指向的缓冲区，将属性值复制到 `value` 指向的缓冲区。
      * 返回属性值的长度。
   * **假设输入与输出:**
      * **假设 `pi` 是通过 `__system_property_find("debug.test.my_property")` 获取的，且属性值为 "test_value"`
      * **输入:** `pi`, `name` (一个足够大的字符数组), `value` (一个足够大的字符数组)
      * **输出:** 返回 `10`，`name` 的内容为 `"debug.test.my_property"` (可能会被截断到 `PROP_NAME_MAX - 1`)，`value` 的内容为 `"test_value"`。

**Dynamic Linker 的功能和处理过程**

系统属性本身不是动态链接器直接管理的功能。然而，动态链接器（`linker` 或 `ld-android.so`）在启动和加载共享库时，可能会读取一些系统属性来影响其行为。

* **SO 布局样本:**

```
/system/lib64/libc.so
/system/lib64/libm.so
/vendor/lib64/libMyLibrary.so
```

* **链接的处理过程 (与系统属性相关的部分):**

1. **进程启动:** 当一个进程启动时，操作系统会将可执行文件加载到内存，并启动动态链接器。
2. **读取环境变量和系统属性:** 动态链接器在初始化阶段，会读取一些环境变量和系统属性，这些信息可能会影响共享库的加载和链接过程。
    * **例子:** `android.debuggable` 属性如果为 1，可能会使链接器启用额外的调试功能。
    * **例子:**  某些属性可能指定额外的共享库搜索路径。
3. **加载依赖的共享库:**  动态链接器会解析可执行文件和已加载共享库的依赖关系，并按需加载其他共享库。
4. **符号解析和重定位:**  动态链接器会将共享库中的符号引用解析到正确的地址，并进行地址重定位。

**链接过程与系统属性的关联举例:**

假设有一个名为 `libMyLibrary.so` 的共享库，开发者希望只有在特定的调试模式下才加载它。可以通过以下步骤实现：

1. **设置系统属性:**  在 Android 系统中设置一个属性，例如 `debug.load_my_library=1`。
2. **修改应用程序代码:**  应用程序代码在加载 `libMyLibrary.so` 之前，先读取 `debug.load_my_library` 属性的值。
3. **动态加载:**  如果属性值为 "1"，则使用 `dlopen()` 函数动态加载 `libMyLibrary.so`。

虽然动态链接器本身不直接操作这些属性，但应用程序可以利用系统属性来控制动态库的加载行为。

**用户或编程常见的使用错误**

1. **缓冲区溢出:**  在使用 `__system_property_get` 或 `__system_property_read` 时，提供的缓冲区 `value` 或 `name` 可能太小，无法容纳实际的属性值或名称，导致缓冲区溢出。
   ```c
   char value[10]; // 缓冲区太小
   __system_property_get("ro.build.version.sdk", value); // 可能溢出
   ```

2. **属性名或值过长:**  系统属性的名称和值都有最大长度限制 (`PROP_NAME_MAX` 和 `PROP_VALUE_MAX`)。尝试设置超过此限制的属性将会失败。
   ```c
   char long_name[PROP_NAME_MAX + 1];
   memset(long_name, 'a', PROP_NAME_MAX);
   long_name[PROP_NAME_MAX] = '\0';
   __system_property_set(long_name, "value"); // 可能会失败
   ```

3. **假设属性一定存在:**  在获取属性值之前，没有检查属性是否存在，可能导致未定义的行为或程序崩溃。建议先使用 `__system_property_find` 检查属性是否存在。
   ```c
   char value[PROP_VALUE_MAX];
   __system_property_get("non.existent.property", value); // 如果属性不存在，value 的内容是未定义的
   ```

4. **权限问题:**  某些系统属性只能由特定的进程或用户设置。普通应用程序可能无法设置某些敏感的系统属性。

**Android Framework 或 NDK 如何到达这里**

1. **Java 代码:**  Android Framework 中，通常通过 `android.os.SystemProperties` 类来访问系统属性。
   ```java
   String sdkVersion = SystemProperties.get("ro.build.version.sdk");
   ```

2. **Framework Native 代码:**  `SystemProperties` 类的底层实现会调用 Framework 的 Native 代码 (C++ 代码)，通常位于 `frameworks/base/core/jni/android_os_SystemProperties.cpp`。在这个 Native 代码中，会使用 JNI (Java Native Interface) 调用 Bionic 提供的系统属性相关函数。
   ```c++
   // frameworks/base/core/jni/android_os_SystemProperties.cpp
   static jstring SystemProperties_native_get(JNIEnv* env, jobject clazz, jstring keyJni) {
       const char* key = env->GetStringUTFChars(keyJni, NULL);
       char buf[PROP_VALUE_MAX];
       int len = __system_property_get(key, buf);
       // ...
   }
   ```

3. **NDK:**  对于使用 NDK 开发的 Native 应用，可以直接包含 `<sys/system_properties.h>` 头文件，并调用 Bionic 提供的 `__system_property_set`、`__system_property_get` 等函数。

**Frida Hook 示例调试步骤**

可以使用 Frida 来 hook 这些 Bionic 函数，观察其行为。以下是一个简单的 Frida 脚本示例：

```javascript
if (Process.platform === 'android') {
  const SystemProperties = {
    set: Module.findExportByName(null, "__system_property_set"),
    get: Module.findExportByName(null, "__system_property_get"),
    find: Module.findExportByName(null, "__system_property_find"),
    read_callback: Module.findExportByName(null, "__system_property_read_callback"),
    read: Module.findExportByName(null, "__system_property_read")
  };

  if (SystemProperties.set) {
    Interceptor.attach(SystemProperties.set, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[0]);
        const value = Memory.readUtf8String(args[1]);
        console.log(`__system_property_set("${name}", "${value}")`);
      },
      onLeave: function (retval) {
        console.log(`__system_property_set returned: ${retval}`);
      }
    });
  }

  if (SystemProperties.get) {
    Interceptor.attach(SystemProperties.get, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[0]);
        console.log(`__system_property_get("${name}")`);
      },
      onLeave: function (retval) {
        const valuePtr = this.context.sp.add(Process.pointerSize * 2); // Adjust based on architecture
        const value = Memory.readUtf8String(Memory.readPointer(valuePtr));
        console.log(`__system_property_get returned length: ${retval}, value: "${value}"`);
      }
    });
  }

  // 可以类似地 hook 其他函数
} else {
  console.log("This script is designed for Android.");
}
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida-tools。
2. **启动目标应用或进程:** 运行你想要调试的 Android 应用或进程。
3. **运行 Frida 脚本:** 使用 `frida -U -f <包名或进程名> -l your_script.js` 命令运行上述 Frida 脚本。

当你运行目标应用并涉及到系统属性操作时，Frida 脚本会在控制台上打印出 `__system_property_set` 和 `__system_property_get` 等函数的调用信息，包括属性名、属性值和返回值，帮助你理解代码的执行流程。

希望以上详细的分析能够帮助你理解 `bionic/tests/system_properties_test2.cpp` 文件的功能和它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/system_properties_test2.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include "utils.h"

#if defined(__BIONIC__)
#include <sys/system_properties.h>
#endif

// Note that this test affects global state of the system
// this tests tries to mitigate this by using utime+pid
// prefix for the property name. It is still results in
// pollution of property service since properties cannot
// be removed.
//
// Note that there is also possibility to run into "out-of-memory"
// if this test if it is executed often enough without reboot.
TEST(properties, smoke) {
#if defined(__BIONIC__)
    char propvalue[PROP_VALUE_MAX];

    std::stringstream ss;
    ss << "debug.test." << getpid() << "." << NanoTime() << ".";
    const std::string property_prefix = ss.str();
    const std::string property_name = property_prefix + "property1";

    // Set brand new property
    ASSERT_EQ(0, __system_property_set(property_name.c_str(), "value1"));
    ASSERT_EQ(6, __system_property_get(property_name.c_str(), propvalue));
    ASSERT_STREQ("value1", propvalue);

    std::string long_value = "property-";
    for (size_t i = 0; i < PROP_VALUE_MAX; i++) {
      long_value += "y";
    }

    // Make sure that attempts to set invalid property value fails and preserves
    // previous value.
    propvalue[0] = '\0';
    ASSERT_EQ(-1, __system_property_set(property_name.c_str(), long_value.c_str()));
    ASSERT_EQ(6, __system_property_get(property_name.c_str(), propvalue));
    ASSERT_STREQ("value1", propvalue);

    // Update property
    ASSERT_EQ(0, __system_property_set(property_name.c_str(), "value1-1"));
    ASSERT_EQ(8, __system_property_get(property_name.c_str(), propvalue));
    ASSERT_STREQ("value1-1", propvalue);


    // check that there is no limit on property name length
    char suffix[1024];
    for (size_t i = 0; i < sizeof(suffix); i++) {
      suffix[i] = 'x';
    }

    suffix[sizeof(suffix)-1] = '\0';
    const std::string long_property_name = property_prefix + suffix;

    ASSERT_EQ(0, __system_property_set(long_property_name.c_str(), "value2"));
    ASSERT_EQ(6, __system_property_get(long_property_name.c_str(), propvalue));
    ASSERT_STREQ("value2", propvalue);

    // test find and read_callback
    const prop_info* pi = __system_property_find(property_name.c_str());
    ASSERT_TRUE(pi != nullptr);

    std::string expected_name = property_name;
    __system_property_read_callback(pi,
      [](void* cookie, const char* name, const char* value, unsigned /*serial*/) {
        const std::string* expected_name = static_cast<const std::string*>(cookie);
        ASSERT_EQ(*expected_name, name);
        ASSERT_STREQ("value1-1", value);
    }, &expected_name);

    pi = __system_property_find(long_property_name.c_str());
    ASSERT_TRUE(pi != nullptr);

    expected_name = long_property_name;
    __system_property_read_callback(pi,
      [](void* cookie, const char* name, const char* value, unsigned /*serial*/) {
        const std::string* expected_name = static_cast<const std::string*>(cookie);
        ASSERT_EQ(*expected_name, name);
        ASSERT_STREQ("value2", value);
    }, &expected_name);

    // Check that read() for long names still works but returns truncated version of the name
    pi = __system_property_find(property_name.c_str());
    ASSERT_TRUE(pi != nullptr);
    char legacy_name[PROP_NAME_MAX];
    expected_name = std::string(property_name.c_str(), PROP_NAME_MAX-1);
    ASSERT_EQ(8, __system_property_read(pi, &legacy_name[0], propvalue));
    ASSERT_EQ(expected_name, legacy_name);
    ASSERT_STREQ("value1-1", propvalue);

    const prop_info* pi_long = __system_property_find(long_property_name.c_str());
    ASSERT_TRUE(pi != nullptr);
    expected_name = std::string(long_property_name.c_str(), PROP_NAME_MAX-1);
    ASSERT_EQ(6, __system_property_read(pi_long, &legacy_name[0], propvalue));
    ASSERT_EQ(expected_name, legacy_name);
    ASSERT_STREQ("value2", propvalue);
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, no_fd_leaks) {
#if defined(__BIONIC__)
  FdLeakChecker leak_checker;
  std::stringstream ss;
  ss << "debug.test." << getpid() << "." << NanoTime() << ".";
  const std::string property_prefix = ss.str();
  const std::string property_name = property_prefix + "property1";

  for (size_t i = 0; i < 100; ++i) {
    char propvalue[PROP_VALUE_MAX];
    ASSERT_EQ(0, __system_property_set(property_name.c_str(), "value1"));
    ASSERT_EQ(6, __system_property_get(property_name.c_str(), propvalue));
    ASSERT_STREQ("value1", propvalue);

    ASSERT_EQ(0, __system_property_set(property_name.c_str(), "value2"));
    ASSERT_EQ(6, __system_property_get(property_name.c_str(), propvalue));
    ASSERT_STREQ("value2", propvalue);
  }
#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(properties, empty_value) {
#if defined(__BIONIC__)
    char propvalue[PROP_VALUE_MAX];

    std::stringstream ss;
    ss << "debug.test." << getpid() << "." << NanoTime() << "." << "property_empty";
    const std::string property_name = ss.str();

    for (size_t i = 0; i < 1000; ++i) {
      ASSERT_EQ(0, __system_property_set(property_name.c_str(), ""));
      ASSERT_EQ(0, __system_property_get(property_name.c_str(), propvalue));
      ASSERT_STREQ("", propvalue);
    }

#else  // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

"""

```