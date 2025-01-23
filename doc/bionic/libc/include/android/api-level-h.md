Response:
Let's break down the thought process for answering the request about `android/api-level.h`.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the `android/api-level.h` header file in Android's Bionic library. The request also asks for its relationship to Android, implementation details (if any), dynamic linking aspects, usage errors, how it's reached from the framework/NDK, and debugging examples.

**2. Initial Analysis of the Code:**

The first step is to read through the provided source code. Key observations:

* **Copyright and License:** Standard open-source license information. Not directly relevant to the core functionality but good to note.
* **`#pragma once`:**  Ensures the header is included only once per compilation unit.
* **`@defgroup apilevels` and `@file android/api-level.h`:** Doxygen documentation indicating the purpose of the file: defining functions and constants for working with API levels.
* **`#include <sys/cdefs.h>`:** Likely includes macros for compiler directives and declarations.
* **`__BEGIN_DECLS` and `__END_DECLS`:** Standard C idiom for ensuring proper C linkage, especially when used in C++ code.
* **`__ANDROID_API_FUTURE__`:** A constant representing a future API level.
* **`#ifndef __ANDROID_API__` block:** This is the core logic. It defines `__ANDROID_API__` if it's not already defined. Crucially, it notes that for NDK/APEX builds, this macro is set by the compiler (Clang). For OS code, it defaults to `__ANDROID_API_FUTURE__`. The documentation also highlights its similarity to `minSdkVersion`.
* **`__ANDROID_API_G__`, `__ANDROID_API_I__`, ..., `__ANDROID_API_V__`:**  A series of `#define` statements associating symbolic names with integer API levels. This is a major part of the file's purpose.
* **`#if !defined(__ASSEMBLY__)` block:**  Code within this block is only for C/C++ compilation, not assembly.
* **`android_get_application_target_sdk_version()`:** A function to get the target SDK version of the app. It's guarded by `__BIONIC_AVAILABILITY_GUARD(24)` and `__INTRODUCED_IN(24)`, indicating it's available from API level 24.
* **`android_get_device_api_level()`:** A function to get the device's API level. The implementation differs depending on `__ANDROID_API__`. Before API level 29, it's an inline function (likely optimized for performance). From API level 29 onwards, it's a regular function.
* **`/** @} */`:** Closes the Doxygen group.

**3. Extracting Functionality:**

Based on the code analysis, the primary functionalities are:

* **Defining API Level Constants:** The numerous `#define` statements are the core functionality.
* **Providing Functions to Get API Levels:** `android_get_device_api_level()` and `android_get_application_target_sdk_version()`.

**4. Relating to Android Functionality:**

The API levels are central to Android's backward compatibility mechanism. The explanation should focus on how these constants and functions help developers and the system manage compatibility.

* **`__ANDROID_API__` vs. `minSdkVersion`:** Emphasize the build-time nature of `__ANDROID_API__` and its relation to `minSdkVersion`.
* **`targetSdkVersion`:** Explain how `android_get_application_target_sdk_version()` relates to the app's declared target.
* **Device API Level:** Explain how `android_get_device_api_level()` allows apps to check the capabilities of the running device.

**5. Addressing Specific Requests:**

* **Detailed Explanation of Libc Functions:** Focus on `android_get_device_api_level()` and `android_get_application_target_sdk_version()`. Describe their purpose, availability, and the difference in implementation for `android_get_device_api_level()` before and after API 29. *Crucially, note that these are *not* standard C library functions but Bionic-specific.*
* **Dynamic Linker:** While this header file itself doesn't *directly* implement dynamic linking, the concept of API levels is crucial for it. Explain how the linker uses API levels to ensure compatibility and potentially choose different library versions. Provide a simplified SO layout and illustrate the linking process conceptually.
* **Logic Reasoning:** For the API level comparisons, create simple examples demonstrating how `__ANDROID_API__` is used in conditional compilation.
* **User/Programming Errors:** Focus on the misuse of API levels, such as building with a low `__ANDROID_API__` and expecting to run on older devices without testing, or failing to check the device API level before using newer features.
* **Android Framework/NDK Path:** Describe the compilation process, starting from the Java/Kotlin code in the framework or C/C++ code in the NDK, going through the compiler (javac/clang), and how the `-target` flag influences the definition of `__ANDROID_API__`.
* **Frida Hook:** Provide concrete Frida examples for hooking the two key functions.

**6. Structuring the Response:**

Organize the information logically using the points from the request as headings. Use clear and concise language. Provide code examples where appropriate.

**7. Refinement and Review:**

After drafting the initial response, review it for accuracy, clarity, and completeness. Ensure all parts of the request have been addressed. For example, initially, I might have focused too much on the `#define` constants and less on the functions. A review would highlight the need to expand on the function descriptions and their significance. Also, ensure the dynamic linker explanation ties back to the concept of API levels effectively.

By following this structured thought process, breaking down the request, analyzing the code, and addressing each point systematically, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析一下 `bionic/libc/include/android/api-level.h` 这个头文件的功能和作用。

**功能概述:**

`android/api-level.h` 文件的主要功能是定义了一系列宏常量和函数，用于在 Android 系统中处理和比较不同的 API Level。API Level 是 Android 系统版本的一种数字标识，用于区分不同版本的 Android 系统所支持的功能和特性。

这个头文件提供了以下核心功能：

1. **定义 `__ANDROID_API__` 宏:**  这个宏代表了代码正在构建的目标 API Level。它是编译时的常量，由 Clang 编译器根据 `-target` 参数自动设置。例如，使用 `-target aarch64-linux-android24` 编译时，`__ANDROID_API__` 将被定义为 24。对于非 APEX OS 代码，如果未明确定义，则默认为 `__ANDROID_API_FUTURE__`。
2. **定义各个 Android 版本对应的 API Level 宏:**  例如 `__ANDROID_API_G__` (Gingerbread, API Level 9), `__ANDROID_API_I__` (Ice Cream Sandwich, API Level 14), 一直到 `__ANDROID_API_V__` (Android 15, API Level 35)。这些宏方便开发者进行版本比较。
3. **声明获取设备 API Level 的函数 `android_get_device_api_level()`:** 这个函数在运行时返回当前 Android 设备所运行的系统的 API Level。它对应于 Java 中的 `Build.VERSION.SDK_INT`。
4. **声明获取应用程序目标 SDK 版本的函数 `android_get_application_target_sdk_version()`:** 这个函数在运行时返回当前应用程序在 `AndroidManifest.xml` 中声明的 `targetSdkVersion`。

**与 Android 功能的关系及举例说明:**

`android/api-level.h` 是 Android 系统中处理兼容性问题的基础。它允许开发者根据不同的 Android 版本来选择性地使用 API 和功能。

**举例说明:**

* **条件编译:** 开发者可以使用 `__ANDROID_API__` 宏进行条件编译，以便在不同的 Android 版本上编译出不同的代码。例如，如果想使用 API Level 26 引入的某个新功能，可以这样写：

```c
#include <android/api-level.h>

#if __ANDROID_API__ >= __ANDROID_API_O__
// 使用 API Level 26 或更高版本提供的功能
#else
// 使用旧版本的兼容方案
#endif
```

* **运行时检查:** 开发者可以使用 `android_get_device_api_level()` 函数在运行时检查设备版本，并根据版本动态地加载或执行不同的代码。

```c
#include <android/api-level.h>
#include <stdio.h>

int main() {
  int device_api_level = android_get_device_api_level();
  printf("Device API Level: %d\n", device_api_level);

  if (device_api_level >= __ANDROID_API_T__) {
    printf("支持 Android 13 (Tiramisu) 及以上的功能。\n");
  } else {
    printf("不支持 Android 13 (Tiramisu) 的新功能。\n");
  }
  return 0;
}
```

* **了解应用程序的目标 SDK 版本:** `android_get_application_target_sdk_version()` 可以帮助库开发者了解宿主应用程序的目标 API Level，从而进行一些兼容性处理。

**详细解释 libc 函数的功能是如何实现的:**

这里提到的 `android_get_device_api_level()` 和 `android_get_application_target_sdk_version()` 并不是标准的 C 库函数，而是 Bionic C 库针对 Android 特性提供的函数。

* **`android_get_device_api_level()` 的实现:**
    * **API Level < 29:** 在 API Level 29 之前，`android_get_device_api_level()` 通常是一个 `static inline` 函数，其实现可能直接读取一个全局变量或者通过系统调用获取。具体的实现细节在 `bionic/libc/include/bits/get_device_api_level_inlines.h` 中。
    * **API Level >= 29:** 从 API Level 29 开始，`android_get_device_api_level()` 变成了一个普通的函数，它的实现通常会通过系统属性服务 (`/system/bin/getprop`) 获取 `ro.build.version.sdk_int` 属性的值。这个属性是由 Android 系统在启动时设置的，反映了设备的系统版本。

* **`android_get_application_target_sdk_version()` 的实现:**
    这个函数的实现需要访问当前进程的上下文信息，以获取应用程序的 `AndroidManifest.xml` 中声明的 `targetSdkVersion`。这通常涉及到与 Android 运行时环境 (如 ART) 的交互。Bionic 库可能会使用特定的系统调用或内部 API 来获取这个信息。

**涉及 dynamic linker 的功能:**

`android/api-level.h` 本身并不直接参与 dynamic linker 的核心实现，但它提供的 API Level 信息对 dynamic linker 的行为有重要的影响。

* **SO 布局样本:** 假设我们有两个共享库 `libfoo.so` 和 `libbar.so`。

```
/system/lib64/libfoo.so  (假设编译时 __ANDROID_API__ = 28)
/vendor/lib64/libbar.so  (假设编译时 __ANDROID_API__ = 30)
```

* **链接的处理过程:**
    1. **加载应用程序:** 当 Android 系统启动一个应用程序时，dynamic linker (通常是 `/system/bin/linker64`) 负责加载应用程序的可执行文件及其依赖的共享库。
    2. **解析依赖:** Linker 会解析应用程序的 ELF 文件头，找到其依赖的共享库列表。
    3. **查找共享库:** Linker 会在预定义的路径中搜索这些共享库，例如 `/system/lib64`, `/vendor/lib64` 等。
    4. **API Level 兼容性检查 (间接影响):**  虽然 linker 不会直接读取 `android/api-level.h`，但编译共享库时定义的 `__ANDROID_API__` 会影响库的构建方式。例如，如果 `libbar.so` 是用 `__ANDROID_API__ = 30` 编译的，它可能会使用一些 API Level 30 才引入的特性。
    5. **符号解析和重定位:** Linker 会解析共享库中的符号，并将应用程序中对这些符号的引用绑定到共享库中的实际地址。
    6. **加载到内存:** Linker 将共享库加载到进程的内存空间。

**API Level 的影响:**

* **最低支持版本 (`minSdkVersion`):** 应用程序的 `minSdkVersion` 声明了它能够运行的最低 Android 版本。如果设备的 API Level 低于 `minSdkVersion`，则应用程序将无法安装或启动。
* **目标版本 (`targetSdkVersion`):** 应用程序的 `targetSdkVersion` 表明了应用程序已经过测试并预期在哪个 Android 版本上运行。Android 系统可能会根据 `targetSdkVersion` 来调整某些行为，以提供更好的兼容性。
* **库的兼容性:**  如果一个共享库使用了高于应用程序 `minSdkVersion` 的 API，可能会导致运行时错误。Linker 不会阻止加载这样的库，但当应用程序尝试调用不存在的符号时，会发生错误。

**逻辑推理，假设输入与输出:**

假设我们在一个 API Level 为 25 的设备上运行一个应用程序，并且这个应用程序链接了一个使用以下代码的共享库：

```c
#include <android/api-level.h>
#include <stdio.h>

void check_api_level() {
  if (__ANDROID_API__ >= __ANDROID_API_O__) {
    printf("库是用 API Level %d 或更高版本编译的。\n", __ANDROID_API_O__);
  } else {
    printf("库是用低于 API Level %d 的版本编译的。\n", __ANDROID_API_O__);
  }

  int device_api = android_get_device_api_level();
  printf("设备 API Level: %d\n", device_api);

  if (device_api >= __ANDROID_API_O__) {
    printf("设备支持 API Level %d 的功能。\n", __ANDROID_API_O__);
  } else {
    printf("设备不支持 API Level %d 的功能。\n", __ANDROID_API_O__);
  }
}
```

**假设输入:**

* 设备 API Level: 25 (Nougat MR1)
* 共享库编译时的 `__ANDROID_API__`: 28 (Pie)

**预期输出:**

```
库是用 API Level 26 或更高版本编译的。
设备 API Level: 25
设备不支持 API Level 26 的功能。
```

**用户或编程常见的使用错误:**

1. **假设 `__ANDROID_API__` 等于设备 API Level:**  `__ANDROID_API__` 是编译时的常量，而设备 API Level 是运行时的属性。开发者不能假设它们相等。
2. **使用高于 `minSdkVersion` 的 API 但没有进行版本检查:** 如果应用程序的 `minSdkVersion` 低于某个 API 的引入版本，但代码中直接使用了该 API 而没有用 `__ANDROID_API__` 或 `android_get_device_api_level()` 进行检查，则在旧版本设备上会崩溃。
3. **库的编译目标 API Level 高于应用程序的 `minSdkVersion` 但使用了新 API:** 这会导致库在旧版本设备上加载，但在调用新 API 时崩溃。
4. **过度依赖条件编译，导致代码难以维护:**  过多的 `#if __ANDROID_API__` 可能会使代码变得复杂和难以理解。
5. **忘记在运行时检查设备 API Level 就使用新功能:** 即使应用程序的 `targetSdkVersion` 很高，也需要在运行时检查设备 API Level，因为用户可能运行在旧版本的 Android 系统上。

**举例说明用户或编程错误:**

```c
#include <stdio.h>
#include <android/api-level.h>
#include <sys/random.h> // getrandom introduced in API level 28

int main() {
  // 假设应用程序的 minSdkVersion 是 21，但这里直接使用了 API Level 28 的 getrandom
  unsigned char buf[16];
  ssize_t result = getrandom(buf, sizeof(buf), 0);
  if (result == sizeof(buf)) {
    printf("成功获取随机数\n");
  } else {
    perror("获取随机数失败");
  }
  return 0;
}
```

在这个例子中，如果应用程序运行在 API Level 低于 28 的设备上，`getrandom` 函数将不存在，导致程序崩溃。正确的做法是先检查设备 API Level。

**说明 Android framework 或 NDK 是如何一步步的到达这里:**

1. **Android Framework:**
   - 当 Android Framework 需要获取设备或应用程序的 API Level 信息时，它会通过 Java API (`android.os.Build.VERSION.SDK_INT`, `android.content.pm.ApplicationInfo.targetSdkVersion`) 来获取。
   - 这些 Java API 的底层实现会通过 JNI 调用到 Bionic 库中的相应函数。
   - 例如，`android.os.Build.VERSION.SDK_INT` 的实现最终会调用到 Bionic 库中的 `android_get_device_api_level()`。

2. **Android NDK:**
   - NDK 开发者在 C/C++ 代码中可以直接包含 `<android/api-level.h>` 头文件。
   - 在编译 NDK 代码时，Clang 编译器会根据 NDK 配置的 `android:minSdkVersion` 或 CMakeLists.txt 中的设置，使用 `-target` 参数来定义 `__ANDROID_API__` 宏。
   - NDK 代码可以直接调用 `android_get_device_api_level()` 和 `android_get_application_target_sdk_version()` 函数。

**Frida Hook 示例调试这些步骤:**

假设我们要 hook `android_get_device_api_level()` 函数来查看其返回值。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process name or pid>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "android_get_device_api_level"), {
        onEnter: function(args) {
            console.log("[*] Calling android_get_device_api_level()");
        },
        onLeave: function(retval) {
            console.log("[*] android_get_device_api_level returned: " + retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤:**

1. 将上述 Python 代码保存为 `hook_api_level.py`。
2. 找到你想要监控的进程的名称或 PID。例如，一个正在运行的应用程序的包名。
3. 运行 Frida 脚本：`frida -U -f <package_name> hook_api_level.py` 或者 `frida -U <pid> hook_api_level.py`。

**调试输出示例:**

当你运行被 hook 的应用程序并且它调用 `android_get_device_api_level()` 时，Frida 控制台会输出类似以下的信息：

```
[*] Script loaded. Press Ctrl+C to exit.
[*] Calling android_get_device_api_level()
[*] android_get_device_api_level returned: 29
```

这个输出表明 `android_get_device_api_level()` 函数被调用，并返回了设备的 API Level，例如 29。

你可以使用类似的方法 hook `android_get_application_target_sdk_version()` 函数：

```python
    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "android_get_application_target_sdk_version"), {
        onEnter: function(args) {
            console.log("[*] Calling android_get_application_target_sdk_version()");
        },
        onLeave: function(retval) {
            console.log("[*] android_get_application_target_sdk_version returned: " + retval);
        }
    });
    """
```

通过 Frida hook，你可以动态地观察这些 API Level 相关函数的调用和返回值，从而更好地理解 Android 系统如何处理 API Level 信息。

希望以上详细的解释能够帮助你理解 `android/api-level.h` 的作用和相关概念。

### 提示词
```
这是目录为bionic/libc/include/android/api-level.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * @defgroup apilevels API Levels
 *
 * Defines functions and constants for working with Android API levels.
 * @{
 */

/**
 * @file android/api-level.h
 * @brief Functions and constants for dealing with multiple API levels.
 *
 * See
 * https://android.googlesource.com/platform/bionic/+/main/docs/defines.md.
 */

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * Magic version number for an Android OS build which has not yet turned
 * into an official release, for comparison against `__ANDROID_API__`. See
 * https://android.googlesource.com/platform/bionic/+/main/docs/defines.md.
 */
#define __ANDROID_API_FUTURE__ 10000

/* This #ifndef should never be true except when doxygen is generating docs. */
#ifndef __ANDROID_API__
/**
 * `__ANDROID_API__` is the [API
 * level](https://developer.android.com/guide/topics/manifest/uses-sdk-element#ApiLevels)
 * this code is being built for. The resulting binaries are only guaranteed to
 * be compatible with devices which have an API level greater than or equal to
 * `__ANDROID_API__`.
 *
 * For NDK and APEX builds, this macro will always be defined. It is set
 * automatically by Clang using the version suffix that is a part of the target
 * name. For example, `__ANDROID_API__` will be 24 when Clang is given the
 * argument `-target aarch64-linux-android24`.
 *
 * For non-APEX OS code, this defaults to  __ANDROID_API_FUTURE__.
 *
 * The value of `__ANDROID_API__` can be compared to the named constants in
 * `<android/api-level.h>`.
 *
 * The interpretation of `__ANDROID_API__` is similar to the AndroidManifest.xml
 * `minSdkVersion`. In most cases `__ANDROID_API__` will be identical to
 * `minSdkVersion`, but as it is a build time constant it is possible for
 * library code to use a different value than the app it will be included in.
 * When libraries and applications build for different API levels, the
 * `minSdkVersion` of the application must be at least as high as the highest
 * API level used by any of its libraries which are loaded unconditionally.
 *
 * Note that in some cases the resulting binaries may load successfully on
 * devices with an older API level. That behavior should not be relied upon,
 * even if you are careful to avoid using new APIs, as the toolchain may make
 * use of new features by default. For example, additional FORTIFY features may
 * implicitly make use of new APIs, SysV hashes may be omitted in favor of GNU
 * hashes to improve library load times, or relocation packing may be enabled to
 * reduce binary size.
 *
 * See android_get_device_api_level(),
 * android_get_application_target_sdk_version() and
 * https://android.googlesource.com/platform/bionic/+/main/docs/defines.md.
 */
#define __ANDROID_API__ __ANDROID_API_FUTURE__
#endif

/** Names the Gingerbread API level (9), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_G__ 9

/** Names the Ice-Cream Sandwich API level (14), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_I__ 14

/** Names the Jellybean API level (16), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_J__ 16

/** Names the Jellybean MR1 API level (17), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_J_MR1__ 17

/** Names the Jellybean MR2 API level (18), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_J_MR2__ 18

/** Names the KitKat API level (19), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_K__ 19

/** Names the Lollipop API level (21), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_L__ 21

/** Names the Lollipop MR1 API level (22), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_L_MR1__ 22

/** Names the Marshmallow API level (23), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_M__ 23

/** Names the Nougat API level (24), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_N__ 24

/** Names the Nougat MR1 API level (25), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_N_MR1__ 25

/** Names the Oreo API level (26), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_O__ 26

/** Names the Oreo MR1 API level (27), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_O_MR1__ 27

/** Names the Pie API level (28), for comparison against `__ANDROID_API__`. */
#define __ANDROID_API_P__ 28

/**
 * Names the Android 10 (aka "Q" or "Quince Tart") API level (29), for
 * comparison against `__ANDROID_API__`.
 */
#define __ANDROID_API_Q__ 29

/**
 * Names the Android 11 (aka "R" or "Red Velvet Cake") API level (30), for
 * comparison against `__ANDROID_API__`.
 */
#define __ANDROID_API_R__ 30

/**
 * Names the Android 12 (aka "S" or "Snowcone") API level (31), for
 * comparison against `__ANDROID_API__`.
 */
#define __ANDROID_API_S__ 31

/**
 * Names the Android 13 (aka "T" or "Tiramisu") API level (33), for
 * comparison against `__ANDROID_API__`.
 */
#define __ANDROID_API_T__ 33

/**
 * Names the Android 14 (aka "U" or "UpsideDownCake") API level (34),
 * for comparison against `__ANDROID_API__`.
 */
#define __ANDROID_API_U__ 34

/**
 * Names the Android 15 (aka "V" or "VanillaIceCream") API level (35),
 * for comparison against `__ANDROID_API__`.
 */
#define __ANDROID_API_V__ 35

/* This file is included in <features.h>, and might be used from .S files. */
#if !defined(__ASSEMBLY__)

/**
 * Returns the `targetSdkVersion` of the caller, or `__ANDROID_API_FUTURE__` if
 * there is no known target SDK version (for code not running in the context of
 * an app).
 *
 * The returned values correspond to the named constants in `<android/api-level.h>`,
 * and is equivalent to the AndroidManifest.xml `targetSdkVersion`.
 *
 * See also android_get_device_api_level().
 *
 * Available since API level 24.
 */

#if __BIONIC_AVAILABILITY_GUARD(24)
int android_get_application_target_sdk_version() __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


#if __ANDROID_API__ < 29

/* android_get_device_api_level is a static inline before API level 29. */
#define __BIONIC_GET_DEVICE_API_LEVEL_INLINE static __inline
#include <bits/get_device_api_level_inlines.h>
#undef __BIONIC_GET_DEVICE_API_LEVEL_INLINE

#else

/**
 * Returns the API level of the device we're actually running on, or -1 on failure.
 * The returned values correspond to the named constants in `<android/api-level.h>`,
 * and is equivalent to the Java `Build.VERSION.SDK_INT` API.
 *
 * See also android_get_application_target_sdk_version().
 */
int android_get_device_api_level() __INTRODUCED_IN(29);

#endif

#endif /* defined(__ASSEMBLY__) */

__END_DECLS

/** @} */
```