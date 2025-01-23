Response:
Let's break down the thought process to generate the detailed explanation of `system_properties.h`.

**1. Understanding the Core Purpose:**

The first step is to recognize that this header file defines the interface for accessing and manipulating system properties in Android. System properties are key-value pairs used for configuration and communication within the Android system. This immediately signals that the functionality will revolve around getting, setting, and observing these properties.

**2. Analyzing the Structure and Key Types:**

Next, carefully examine the types and macros defined in the header:

*   `prop_info`:  This opaque structure is a central element. The "opaque" nature suggests that its internal details are hidden, and it's accessed via pointers. It likely holds information about a specific property.
*   `PROP_VALUE_MAX`: This macro defines the maximum length of a property *value*. This is an important constraint to note.
*   Function declarations (starting with `__system_property_`): These are the main functional units. Each declaration needs to be understood individually.

**3. Deciphering Each Function's Purpose:**

Go through each function declaration and try to understand its role based on its name and parameters:

*   `__system_property_set`:  Clearly for setting or creating a property. The `const char*` parameters for name and value are standard.
*   `__system_property_find`:  For retrieving information about a property given its name. Returning a `prop_info*` aligns with the structure defined earlier. The note about caching is crucial for performance understanding.
*   `__system_property_read_callback`:  This looks like an asynchronous way to get the property's name, value, and a serial number. The callback structure suggests this. The API level availability is also important information.
*   `__system_property_foreach`:  Iterating through all properties. The callback structure confirms this. The warning about its limited usefulness is worth highlighting.
*   `__system_property_wait`:  Waiting for a property to change. The `prop_info`, `old_serial`, and timeout parameters make sense in this context.
*   Deprecated functions (`__system_property_find_nth`, `__system_property_read`, `__system_property_get`, `__system_property_wait_any`):  Acknowledge their existence and emphasize their deprecated status, pointing to the recommended replacements.
*   `__system_property_area_serial`:  A global serial number for the entire property area. The description provides valuable insights into its use for caching and detecting changes.
*   `__system_property_serial`:  A serial number for a specific property, useful for tracking changes.
*   `__system_properties_init`:  Initialization of the property system, likely internal to libc. The note about automatic calling is important.
*   `PROP_SERVICE_NAME`, `PROP_DIRNAME`, `PROP_MSG_*`, `PROP_ERROR_*`: These are constants and macros related to the underlying implementation and communication with the `init` process. They provide insights into the system's internal workings.
*   `__system_property_area_init`:  Initialization of the property area, specifically for the `init` process. Differentiating it from `__system_properties_init` is key.
*   `__system_property_add`: Adding a new property, restricted to processes with write access (like `init`).
*   `__system_property_update`: Updating an existing property, also restricted.
*   `__system_properties_zygote_reload`: Reloading properties from disk, specifically for the Zygote. The warning about pointer invalidation is crucial.
*   `__system_property_set_filename`: Deprecated function for testing.

**4. Identifying Key Concepts and Relationships:**

Connect the individual functions and types to the overall concept of system properties. Recognize the role of the `init` process in managing these properties. Understand the implications of read-only access for most processes and write access for `init`.

**5. Thinking About Android Integration:**

Consider how these functions are used within the Android ecosystem:

*   Framework using properties for configuration.
*   Apps reading properties for information.
*   `init` process setting properties during boot.
*   Zygote using properties.

**6. Addressing Specific Requirements of the Prompt:**

*   **Functionality Listing:**  Summarize the purpose of each function.
*   **Android Relationship and Examples:**  Provide concrete examples of how system properties are used in Android (e.g., build information, debugging flags, feature toggles).
*   **libc Function Implementation:**  Provide a high-level explanation of *how* these functions might be implemented (e.g., shared memory, file mapping, synchronization mechanisms). Since the source code isn't fully available, focus on the likely techniques.
*   **Dynamic Linker Integration:** Recognize the potential connection to how libraries are loaded and configured based on system properties. While the header doesn't directly deal with linking, the environment it creates can influence linker behavior. Construct a plausible example of an SO layout and the linking process.
*   **Logical Reasoning and Input/Output:** Create simple scenarios to illustrate the behavior of functions like `__system_property_set` and `__system_property_get`.
*   **Common Usage Errors:** Think about mistakes developers might make (e.g., exceeding limits, using deprecated functions, incorrect permissions).
*   **Android Framework/NDK Flow:** Trace the path from framework or NDK calls down to these low-level functions. The `SystemProperties` class in Java is the key intermediary.
*   **Frida Hooking:** Provide practical examples of how to use Frida to intercept calls to these functions for debugging and analysis.

**7. Structuring the Output:**

Organize the information logically with clear headings and subheadings. Start with a general overview and then delve into the details of each function. Use bullet points, code blocks, and explanations to enhance readability.

**8. Refining and Expanding:**

Review the generated explanation and add more details where necessary. For instance, explain the concept of serial numbers and their importance for change tracking. Elaborate on the synchronization challenges involved in managing shared system properties.

By following these steps, one can systematically analyze the header file and produce a comprehensive and informative explanation that addresses all the requirements of the prompt. The process involves understanding the code's purpose, dissecting its components, connecting it to the broader Android ecosystem, and then clearly and logically presenting the findings.
这个文件 `bionic/libc/include/sys/system_properties.h` 定义了 Android 系统属性（System Properties）的 C 接口。系统属性是 Android 系统中一种重要的键值对存储机制，用于配置系统行为、传递信息以及进行进程间的通信。它们在 Android 系统的启动、配置和运行过程中扮演着核心角色。

**功能列举:**

这个头文件定义了以下核心功能：

1. **设置系统属性 (`__system_property_set`)**: 允许设置或创建新的系统属性。
2. **查找系统属性信息 (`__system_property_find`)**:  根据属性名查找属性信息，返回一个指向 `prop_info` 结构的指针。
3. **读取系统属性的值 (带回调) (`__system_property_read_callback`)**:  通过回调函数安全地读取系统属性的名称、值和序列号。
4. **遍历所有系统属性 (`__system_property_foreach`)**:  允许遍历所有已存在的系统属性。
5. **等待系统属性更新 (`__system_property_wait`)**:  允许进程等待特定的系统属性更新。
6. **获取系统属性区域的全局序列号 (`__system_property_area_serial`)**: 获取系统属性区域的全局序列号，用于检测是否有任何属性发生变化。
7. **获取特定系统属性的序列号 (`__system_property_serial`)**: 获取特定属性的序列号，用于检查该属性是否已更改。
8. **初始化系统属性区域 (只读) (`__system_properties_init`)**: 初始化系统属性区域，供普通进程只读访问。
9. **初始化系统属性区域 (读写) (`__system_property_area_init`)**: 初始化系统属性区域，供拥有写权限的进程（通常是 `init` 进程）使用。
10. **添加新的系统属性 (`__system_property_add`)**:  添加新的系统属性，仅限拥有写权限的进程。
11. **更新系统属性的值 (`__system_property_update`)**: 更新已存在的系统属性的值，仅限拥有写权限的进程。
12. **从磁盘重新加载系统属性 (`__system_properties_zygote_reload`)**:  从磁盘重新加载系统属性，主要供 Zygote 进程使用。

**与 Android 功能的关系及举例说明:**

系统属性在 Android 系统中无处不在，几乎所有组件和服务都会使用到它。以下是一些例子：

*   **系统构建信息**:  例如 `ro.build.version.sdk` (SDK 版本), `ro.product.model` (设备型号) 等，这些属性在系统启动时被设置，供应用程序查询设备信息。
    *   **例子**:  一个应用可能通过读取 `ro.build.version.sdk` 来判断当前设备的 Android 版本，从而采取不同的兼容性处理。
*   **调试和开发选项**:  例如 `ro.debuggable` (是否可调试), `persist.sys.usb.config` (USB 配置) 等，这些属性可以控制系统的调试行为。
    *   **例子**:  开发者可以通过设置 `ro.debuggable=1` 来启用应用的调试功能。
*   **功能开关**:  例如 `persist.sys.wifi.disable_ipv6` (禁用 IPv6) 等，这些属性可以动态地启用或禁用某些系统特性。
    *   **例子**:  用户可以通过 adb 命令设置 `persist.sys.wifi.disable_ipv6=1` 来禁用 WiFi 的 IPv6 功能。
*   **进程间通信和配置**:  系统服务和应用程序可以通过监听特定的属性变化来协同工作。
    *   **例子**:  当网络状态发生变化时，网络管理服务可能会更新 `net.dns1` 和 `net.dns2` 等属性，其他需要知道 DNS 服务器地址的组件可以读取这些属性。

**libc 函数的功能实现:**

这些 `__system_property_*` 函数通常通过以下机制实现：

1. **共享内存区域**:  Android 系统通常会将系统属性存储在一个共享内存区域中，这样所有的进程都可以访问。`init` 进程负责创建和管理这块共享内存。
2. **文件映射 (mmap)**:  为了持久化系统属性，它们可能还会被存储在磁盘上的文件中，例如 `/system/build.prop` 或 `/vendor/default.prop`。系统启动时，`init` 进程会将这些文件映射到内存中。
3. **原子操作和锁**:  由于多个进程可能同时访问和修改系统属性，因此需要使用原子操作和锁机制来保证数据的一致性。`init` 进程在修改属性时会使用锁来防止竞态条件。
4. **ioctl 系统调用 (早期版本)**:  在较早的 Android 版本中，设置系统属性可能会涉及到通过 socket 连接到 `init` 进程并发送命令。`init` 进程会处理这些命令并更新属性。
5. **socket 通信**:  `__system_property_set` 通常会发送一个消息到 `property_service`（通常由 `init` 进程提供），后者负责验证权限并更新属性值。
6. **回调机制**:  `__system_property_read_callback` 提供了一种异步获取属性值的方式，避免了直接读取共享内存可能存在的并发问题。

**涉及 dynamic linker 的功能:**

虽然 `system_properties.h` 本身不直接涉及动态链接器的代码，但系统属性会影响动态链接器的行为。例如：

*   **`ro.debuggable`**:  这个属性可能会影响动态链接器加载库的方式，例如在调试模式下可能会加载额外的调试符号。
*   **`ro.dalvik.vm.isa.*.image`**: 这些属性指定了预加载的 Dalvik/ART 虚拟机镜像的路径，动态链接器在启动时会使用这些信息。
*   **`ro.ld.*` 开头的属性**:  一些以 `ro.ld.` 开头的系统属性可能直接影响动态链接器的行为，例如指定额外的库搜索路径。

**so 布局样本和链接的处理过程:**

假设我们有一个应用程序 `app`，它依赖于一个共享库 `libfoo.so`。系统属性 `ro.ld.library.path` 被设置为 `/vendor/lib:/system/lib`。

**SO 布局样本:**

```
/system/lib/libc.so
/system/lib/libm.so
/vendor/lib/libfoo.so
/data/app/com.example.app/lib/arm64-v8a/libnative.so (app 的 native 库)
```

**链接的处理过程:**

1. **应用程序启动**: 当应用程序 `app` 启动时，操作系统会加载 `app` 的主可执行文件。
2. **动态链接器启动**:  操作系统会找到并启动动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`)。
3. **加载依赖库**:  动态链接器会解析 `app` 的依赖关系，发现它依赖于 `libnative.so`。
4. **搜索库路径**:  动态链接器会在默认路径（例如 `/system/lib64`, `/vendor/lib64` 等）以及通过 `ro.ld.library.path` 指定的路径中搜索 `libnative.so`。
5. **加载 native 库**:  找到 `libnative.so` 后，动态链接器会将其加载到进程的内存空间。
6. **处理 native 库的依赖**:  `libnative.so` 可能本身也依赖于其他共享库，例如 `libfoo.so`。
7. **再次搜索库路径**:  动态链接器会重复步骤 4，在相同的路径中搜索 `libfoo.so`。由于 `ro.ld.library.path` 包含了 `/vendor/lib`，动态链接器会在那里找到 `libfoo.so`。
8. **加载依赖的共享库**:  动态链接器加载 `libfoo.so` 到进程的内存空间。
9. **符号解析和重定位**:  动态链接器会解析所有已加载库中的符号引用，并进行地址重定位，确保函数调用和数据访问指向正确的内存地址。

**假设输入与输出:**

**假设输入:**

*   调用 `__system_property_set("debug.myapp.trace", "1")`
*   调用 `__system_property_get("debug.myapp.trace", value_buffer)`

**输出:**

*   `__system_property_set` 返回 `0` (成功)。
*   `__system_property_get` 会将字符串 `"1"` 复制到 `value_buffer` 中，并返回正值 (读取到的字符串长度)。

**用户或编程常见的使用错误:**

1. **缓冲区溢出**: 使用 `__system_property_get` 时，提供的缓冲区 `value_buffer` 可能小于属性值的实际长度，导致缓冲区溢出。应该始终检查返回值，并确保缓冲区足够大（至少 `PROP_VALUE_MAX + 1` 字节）。
    ```c
    char value[PROP_VALUE_MAX]; // 错误：缺少一个字节用于 null 终止符
    if (__system_property_get("some.property", value) > 0) {
        // value 可能没有 null 终止
    }

    char value[PROP_VALUE_MAX + 1]; // 正确
    if (__system_property_get("some.property", value) > 0) {
        // value 是 null 终止的
    }
    ```
2. **使用已弃用的函数**: 开发者可能仍然使用 `__system_property_get` 等已弃用的函数，应该迁移到 `__system_property_find` 和 `__system_property_read_callback`。
3. **不必要的频繁调用**:  频繁调用 `__system_property_get` 进行轮询可能会影响性能。应该考虑使用 `__system_property_wait` 或 `__system_property_area_serial` / `__system_property_serial` 来更有效地检测属性变化。
4. **权限问题**: 普通应用程序无法使用 `__system_property_set` 设置所有属性，只有具有特定权限的进程（如 `init` 或具有相应 sepolicy 权限的进程）才能设置某些受保护的属性。尝试设置无权修改的属性会失败。
5. **假设属性一定存在**: 在使用 `__system_property_get` 之前，没有检查属性是否存在就直接使用返回的值可能导致问题。应该先使用 `__system_property_find` 检查属性是否存在。

**Android Framework 或 NDK 如何到达这里:**

**Android Framework:**

1. **Java 代码调用**: Android Framework 中的 Java 代码通常会使用 `android.os.SystemProperties` 类来访问系统属性。
    ```java
    String sdkVersion = SystemProperties.get("ro.build.version.sdk");
    ```
2. **JNI 调用**: `android.os.SystemProperties` 类的方法会通过 JNI (Java Native Interface) 调用到 Native 代码。
3. **Native 方法实现**:  在 Android 运行时 (ART) 或 Dalvik 的 Native 代码中，会调用 Bionic libc 提供的 `__system_property_get` 等函数。

**NDK:**

1. **C/C++ 代码直接调用**: NDK 开发的 Native 代码可以直接包含 `<sys/system_properties.h>` 头文件，并调用其中的函数。
    ```c++
    #include <sys/system_properties.h>
    #include <android/log.h>

    void getSdkVersion() {
        char sdk[PROP_VALUE_MAX + 1];
        __system_property_get("ro.build.version.sdk", sdk);
        __android_log_print(ANDROID_LOG_INFO, "MyApp", "SDK Version: %s", sdk);
    }
    ```

**Frida Hook 示例调试步骤:**

假设我们要 hook `__system_property_get` 函数来观察哪些应用程序正在读取哪些系统属性。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const SystemProperties = Module.findExportByName("libc.so", "__system_property_get");
  if (SystemProperties) {
    Interceptor.attach(SystemProperties, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[0]);
        this.valuePtr = args[1];
        console.log(`[__system_property_get] Name: ${name}`);
      },
      onLeave: function (retval) {
        if (retval > 0) {
          const value = Memory.readUtf8String(this.valuePtr);
          console.log(`[__system_property_get] Value: ${value}`);
        } else {
          console.log(`[__system_property_get] Property not found or error`);
        }
      }
    });
    console.log("[*] Hooked __system_property_get");
  } else {
    console.log("[!] __system_property_get not found in libc.so");
  }
} else {
  console.log("[!] This script is for Android only.");
}
```

**调试步骤:**

1. **准备环境**: 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **运行目标应用**: 启动你想要观察的 Android 应用程序。
3. **运行 Frida 脚本**: 使用 Frida 命令将脚本注入到目标应用程序的进程中。假设目标应用的进程 ID 是 `12345`，你可以使用以下命令：
    ```bash
    frida -U -p 12345 -l your_hook_script.js
    ```
4. **观察输出**: Frida 会输出 `__system_property_get` 函数被调用时的信息，包括属性名和属性值。

**更复杂的 Hook 示例 (Hook `__system_property_set` 并阻止特定属性被修改):**

```javascript
if (Process.platform === 'android') {
  const SystemPropertiesSet = Module.findExportByName("libc.so", "__system_property_set");
  if (SystemPropertiesSet) {
    Interceptor.attach(SystemPropertiesSet, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[0]);
        const value = Memory.readUtf8String(args[1]);
        console.log(`[__system_property_set] Attempting to set: ${name} = ${value}`);
        if (name === "persist.sys.dangerous_property") {
          console.log("[__system_property_set] Blocking modification of dangerous property!");
          // 可以修改参数来阻止设置
          // args[1] = Memory.allocUtf8String(""); // 设置为空字符串
          // Или полностью阻止函数执行
          // return -1;
          this.shouldBlock = true;
        } else {
          this.shouldBlock = false;
        }
      },
      onLeave: function (retval) {
        if (this.shouldBlock) {
          console.log("[__system_property_set] Blocked, returning error.");
          retval.replace(-1); // 强制返回错误
        }
      }
    });
    console.log("[*] Hooked __system_property_set");
  } else {
    console.log("[!] __system_property_set not found in libc.so");
  }
} else {
  console.log("[!] This script is for Android only.");
}
```

这个脚本会拦截对 `__system_property_set` 的调用，并阻止修改名为 `persist.sys.dangerous_property` 的系统属性。

通过这些 Frida hook 示例，你可以深入了解系统属性的访问和修改过程，并进行动态调试和分析。

### 提示词
```
这是目录为bionic/libc/include/sys/system_properties.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file system_properties.h
 * @brief System properties.
 */

#include <sys/cdefs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

__BEGIN_DECLS

/** An opaque structure representing a system property. */
typedef struct prop_info prop_info;

/**
 * The limit on the length of a property value.
 * (See PROP_NAME_MAX for property names.)
 */
#define PROP_VALUE_MAX  92

/**
 * Sets system property `name` to `value`, creating the system property if it doesn't already exist.
 *
 * Returns 0 on success, or -1 on failure.
 */
int __system_property_set(const char* _Nonnull __name, const char* _Nonnull __value);

/**
 * Returns a `prop_info` corresponding system property `name`, or nullptr if it doesn't exist.
 * Use __system_property_read_callback() to query the current value.
 *
 * Property lookup is expensive, so it can be useful to cache the result of this
 * function rather than using __system_property_get().
 */
const prop_info* _Nullable __system_property_find(const char* _Nonnull __name);

/**
 * Calls `callback` with a consistent trio of name, value, and serial number
 * for property `pi`.
 *
 * Available since API level 26.
 */

#if __BIONIC_AVAILABILITY_GUARD(26)
void __system_property_read_callback(const prop_info* _Nonnull __pi,
    void (* _Nonnull __callback)(void* _Nullable __cookie, const char* _Nonnull __name, const char* _Nonnull __value, uint32_t __serial),
    void* _Nullable __cookie) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


/**
 * Passes a `prop_info` for each system property to the provided
 * callback. Use __system_property_read_callback() to read the value of
 * any of the properties.
 *
 * This method is for inspecting and debugging the property system, and not generally useful.
 *
 * Returns 0 on success, or -1 on failure.
 */
int __system_property_foreach(void (* _Nonnull __callback)(const prop_info* _Nonnull __pi, void* _Nullable __cookie), void* _Nullable __cookie);

/**
 * Waits for the specific system property identified by `pi` to be updated
 * past `old_serial`. Waits no longer than `relative_timeout`, or forever
 * if `relative_timeout` is null.
 *
 * If `pi` is null, waits for the global serial number instead.
 *
 * If you don't know the current serial, use 0.
 *
 * Returns true and updates `*new_serial_ptr` on success, or false if the call
 * timed out.
 *
 * Available since API level 26.
 */
struct timespec;

#if __BIONIC_AVAILABILITY_GUARD(26)
bool __system_property_wait(const prop_info* _Nullable __pi, uint32_t __old_serial, uint32_t* _Nonnull __new_serial_ptr, const struct timespec* _Nullable __relative_timeout)
    __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


/**
 * Deprecated: there's no limit on the length of a property name since
 * API level 26, though the limit on property values (PROP_VALUE_MAX) remains.
 */
#define PROP_NAME_MAX   32

/** Deprecated. Use __system_property_foreach() instead. */
const prop_info* _Nullable __system_property_find_nth(unsigned __n);
/** Deprecated. Use __system_property_read_callback() instead. */
int __system_property_read(const prop_info* _Nonnull __pi, char* _Nullable __name, char* _Nonnull __value);
/** Deprecated. Use __system_property_read_callback() instead. */
int __system_property_get(const char* _Nonnull __name, char* _Nonnull __value);
/** Deprecated: use __system_property_wait() instead. */
uint32_t __system_property_wait_any(uint32_t __old_serial);

/**
 * Reads the global serial number of the system properties _area_.
 *
 * Called to predict if a series of cached __system_property_find()
 * objects will have seen __system_property_serial() values change.
 * Also aids the converse, as changes in the global serial can
 * also be used to predict if a failed __system_property_find()
 * could in turn now find a new object; thus preventing the
 * cycles of effort to poll __system_property_find().
 *
 * Typically called at beginning of a cache cycle to signal if _any_ possible
 * changes have occurred since last. If there is, one may check each individual
 * __system_property_serial() to confirm dirty, or __system_property_find()
 * to check if the property now exists. If a call to __system_property_add()
 * or __system_property_update() has completed between two calls to
 * __system_property_area_serial() then the second call will return a larger
 * value than the first call. Beware of race conditions as changes to the
 * properties are not atomic, the main value of this call is to determine
 * whether the expensive __system_property_find() is worth retrying to see if
 * a property now exists.
 *
 * Returns the serial number on success, -1 on error.
 */
uint32_t __system_property_area_serial(void);

/**
 * Reads the serial number of a specific system property previously returned by
 * __system_property_find(). This is a cheap way to check whether a system
 * property has changed or not.
 *
 * Returns the serial number on success, -1 on error.
 */
uint32_t __system_property_serial(const prop_info* _Nonnull __pi);

//
// libc implementation detail.
//

/**
 * Initializes the system properties area in read-only mode.
 *
 * This is called automatically during libc initialization,
 * so user code should never need to call this.
 *
 * Returns 0 on success, -1 otherwise.
 */
int __system_properties_init(void);

//
// init implementation details.
//

#define PROP_SERVICE_NAME "property_service"
#define PROP_SERVICE_FOR_SYSTEM_NAME "property_service_for_system"
#define PROP_DIRNAME "/dev/__properties__"

// Messages sent to init.
#define PROP_MSG_SETPROP 1
#define PROP_MSG_SETPROP2 0x00020001

// Status codes returned by init (but not passed from libc to the caller).
#define PROP_SUCCESS 0
#define PROP_ERROR_READ_CMD 0x0004
#define PROP_ERROR_READ_DATA 0x0008
#define PROP_ERROR_READ_ONLY_PROPERTY 0x000B
#define PROP_ERROR_INVALID_NAME 0x0010
#define PROP_ERROR_INVALID_VALUE 0x0014
#define PROP_ERROR_PERMISSION_DENIED 0x0018
#define PROP_ERROR_INVALID_CMD 0x001B
#define PROP_ERROR_HANDLE_CONTROL_MESSAGE 0x0020
#define PROP_ERROR_SET_FAILED 0x0024

/**
 * Initializes the area to be used to store properties.
 *
 * Can only be done by the process that has write access to the property area,
 * typically init.
 *
 * See __system_properties_init() for the equivalent for all other processes.
 */
int __system_property_area_init(void);

/**
 * Adds a new system property.
 * Can only be done by the process that has write access to the property area --
 * typically init -- which must handle sequencing to ensure that only one property is
 * updated at a time.
 *
 * Returns 0 on success, -1 if the property area is full.
 */
int __system_property_add(const char* _Nonnull __name, unsigned int __name_length, const char* _Nonnull __value, unsigned int __value_length);

/**
 * Updates the value of a system property returned by __system_property_find().
 * Can only be done by the process that has write access to the property area --
 * typically init -- which must handle sequencing to ensure that only one property is
 * updated at a time.
 *
 * Returns 0 on success, -1 if the parameters are incorrect.
 */
int __system_property_update(prop_info* _Nonnull __pi, const char* _Nonnull __value, unsigned int __value_length);

/**
 * Reloads the system properties from disk.
 * Not intended for use by any apps except the Zygote.
 * Should only be called from the main thread.
 *
 * Pointers received from functions such as __system_property_find()
 * may be invalidated by calls to this function.
 *
 * Returns 0 on success, -1 otherwise.
 *
 * Available since API level 35.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
int __system_properties_zygote_reload(void) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


/**
 * Deprecated: previously for testing, but now that SystemProperties is its own
 * testable class, there is never a reason to call this function and its
 * implementation simply returns -1.
 */
int __system_property_set_filename(const char* _Nullable __unused __filename);

__END_DECLS
```