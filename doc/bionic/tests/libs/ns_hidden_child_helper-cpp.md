Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed response.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `ns_hidden_child_helper.cpp` file within the context of Android's bionic library, focusing on its role in namespace isolation and dynamic linking. The prompt also asks for specific details about libc functions, dynamic linker interactions, error scenarios, and how Android frameworks reach this code.

**2. Initial Code Scan and High-Level Interpretation:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords like `android_create_namespace`, `android_link_namespaces`, `android_dlopen_ext`, and `dlsym` immediately stand out as related to dynamic linking and namespace management in Android. The `main` function taking a command-line argument suggests this is an executable test program.

**3. Identifying Key Functionality:**

Based on the initial scan, the core functionalities seem to be:

* **Namespace Creation:**  Creating an isolated Android namespace.
* **Namespace Linking:** Linking the newly created namespace with a set of public libraries.
* **Dynamic Loading:** Dynamically loading a library into the created namespace.
* **Symbol Resolution:**  Looking up a specific function within the loaded library.
* **Function Execution:** Calling the resolved function.

**4. Deconstructing Each Section of the Code:**

Now, we go through the code line by line, focusing on the purpose of each function call and code block.

* **Argument Parsing:** The `if (argc != 2)` block is standard command-line argument handling. It expects a single argument representing a path.
* **`global_function()` and `internal_function()`:** These are external functions declared but not defined in this file. The comment hints at testing that `-Wl,--needed` doesn't remove their `DT_NEEDED` entries. This points to a deeper concern with how the linker optimizes shared library dependencies. *Self-correction: Initially, I might have overlooked the significance of this, but the comment provides crucial context.*
* **Namespace Creation (`android_create_namespace`):**  This is a key bionic function. We need to identify its parameters and their significance: namespace name, visibility, library path, type, etc.
* **Namespace Linking (`android_link_namespaces`):**  This establishes the dependency relationship between the created namespace and other namespaces (in this case, the default namespace containing the "public" libraries). The string manipulation with `kCoreSharedLibs` and `"libns_hidden_child_public.so"` is important.
* **Dynamic Loading with Namespace (`android_dlopen_ext`):** This is where the target library is loaded *into* the previously created namespace. The `ANDROID_DLEXT_USE_NAMESPACE` flag is critical here.
* **Symbol Lookup (`dlsym`):** This is a standard libc function used to find the address of a symbol within a loaded library.
* **Function Call:**  The final step is executing the function obtained via `dlsym`.

**5. Connecting to Android Concepts:**

At this stage, we link the observed functionality to broader Android concepts:

* **Namespace Isolation:**  This is a security and stability feature in Android. This test explicitly demonstrates creating an isolated namespace.
* **Dynamic Linking:** The core mechanism for loading shared libraries in Android.
* **Bionic:**  Understanding that this code lives within bionic provides context about its low-level nature and its role in the Android system.
* **NDK:**  Consider how developers using the NDK might interact with these underlying mechanisms, even indirectly.

**6. Addressing Specific Prompt Requirements:**

Now, let's tackle the individual points in the prompt systematically:

* **Functionality Listing:** Summarize the key actions performed by the code (namespace creation, linking, loading, etc.).
* **Relationship to Android Features:** Explain how namespace isolation and dynamic linking are used in Android. Provide concrete examples, even if generalized (e.g., isolating app dependencies).
* **`libc` Function Explanation:** Focus on `dlfcn.h` functions like `dlerror`, `dlsym`. Explain their purpose and basic usage. *Self-correction:  The prompt asked for detailed implementation of *every* libc function. While fully reversing and explaining the internals of `dlsym` is beyond a quick analysis, I should explain its *purpose* and how it generally works (symbol table lookup). Acknowledging the complexity is important.*
* **Dynamic Linker Details:** This requires understanding how shared libraries are structured (ELF format, DT_NEEDED, symbol tables) and the linking process. The request for a sample SO layout is important. Illustrate the dependencies and how the linker resolves them. *Self-correction: I need to be careful not to oversimplify the dynamic linker's process. Focus on the key steps relevant to this code.*
* **Logic and Assumptions:**  Think about the expected inputs and outputs of the program. What happens if the namespace creation fails? What if the library doesn't exist?
* **Common Errors:** Consider common programming mistakes developers might make when working with dynamic linking or namespaces (e.g., incorrect paths, missing dependencies).
* **Framework/NDK Path:**  Trace how an Android application's request to load a shared library might eventually involve bionic functions like these. This requires understanding the Android OS architecture (Application Framework, Native Layer, Bionic).
* **Frida Hook Example:** Provide practical code snippets using Frida to intercept key function calls to observe their behavior. This requires knowledge of Frida's API.

**7. Structuring the Response:**

Organize the information logically, using clear headings and bullet points. This makes the response easier to read and understand. Start with a high-level overview and then delve into the specifics.

**8. Language and Tone:**

Use clear and concise Chinese. Maintain a helpful and informative tone.

**9. Review and Refinement:**

Before submitting the answer, review it for accuracy, completeness, and clarity. Ensure that all aspects of the prompt have been addressed adequately. Check for any inconsistencies or areas that could be explained better.

By following these steps, we can systematically analyze the code and generate a comprehensive and accurate response that addresses all the requirements of the prompt. The process involves not just reading the code but also understanding the underlying concepts and the broader context of Android's dynamic linking and namespace management.
这个 `bionic/tests/libs/ns_hidden_child_helper.cpp` 文件是一个用于测试 Android bionic 库中命名空间隔离和动态链接相关功能的程序。它旨在验证在一个新创建的、隔离的命名空间中加载共享库的行为。

以下是它的详细功能分解：

**1. 功能概述:**

* **创建隔离的命名空间:** 使用 `android_create_namespace` 创建一个新的 Android 命名空间。这个命名空间是隔离的，意味着它默认情况下无法访问其他命名空间中的共享库。
* **链接命名空间:** 使用 `android_link_namespaces` 将新创建的命名空间与包含公共共享库的默认命名空间以及一个名为 `libns_hidden_child_public.so` 的特定共享库链接起来。这使得新命名空间可以访问这些被链接的库。
* **在指定命名空间中加载共享库:** 使用 `android_dlopen_ext` 并指定 `ANDROID_DLEXT_USE_NAMESPACE` 标志以及新创建的命名空间，来加载 `libns_hidden_child_app.so` 共享库。这确保了该库被加载到正确的、隔离的命名空间中。
* **查找并执行共享库中的函数:** 使用 `dlsym` 在加载的 `libns_hidden_child_app.so` 中查找名为 `app_function` 的函数，并执行它。
* **测试 `-Wl,--needed` 的影响:**  通过调用 `global_function()` 和 `internal_function()` 来确保链接器选项 `-Wl,--needed` 不会错误地移除必要的 `DT_NEEDED` 条目，从而破坏测试。

**2. 与 Android 功能的关系及举例说明:**

这个测试文件直接关联到 Android 的**命名空间隔离 (Namespace Isolation)** 和**动态链接 (Dynamic Linking)** 功能。

* **命名空间隔离:** Android 使用命名空间来隔离应用和系统库，以及不同应用之间的依赖关系。这提高了安全性和稳定性，防止不同模块之间的符号冲突。这个测试正是模拟了创建一个隔离的命名空间，然后在其中加载应用程序的共享库。

    **举例:**  一个 Android 应用 `com.example.myapp` 可能会加载一个名为 `libmylib.so` 的本地库。为了避免与系统库或其他应用的库冲突，Android 会将 `libmylib.so` 加载到应用自身的命名空间中。这个测试模拟了这种创建和使用应用命名空间的过程。

* **动态链接:** Android 使用动态链接来加载和链接共享库。`android_dlopen_ext` 和 `dlsym` 是用于动态加载和符号查找的关键函数。这个测试验证了在特定命名空间中进行动态加载和符号查找是否正常工作。

    **举例:**  当一个应用需要使用 OpenGL ES 进行图形渲染时，它会动态加载 `libGLESv2.so` 库。`android_dlopen_ext` 会负责找到并加载这个库，而 `dlsym` 可以用来获取 OpenGL ES 函数的地址，例如 `glDrawArrays`。

**3. libc 函数的功能实现解释:**

这个测试文件中用到的 libc 函数主要是 `dlfcn.h` 头文件中定义的动态链接相关的函数：

* **`dlerror()`:**
    * **功能:** 返回最近一次 `dlopen`, `dlsym`, `dlclose` 等动态链接操作失败时产生的错误消息字符串。如果最近的操作成功，则返回 `NULL`.
    * **实现:**  libc 内部维护一个线程局部变量，用于存储最近一次动态链接操作的错误信息。当动态链接操作失败时，会将错误信息写入这个变量。`dlerror()` 函数只是简单地返回这个变量的值。
    * **本例使用:** 用于在 `android_create_namespace`, `android_link_namespaces`, `android_dlopen_ext`, `dlsym` 调用失败时打印错误信息。

* **`stdlib.h` 中的 `exit()`:**
    * **功能:** 终止当前进程，并将 `status` 作为退出状态返回给操作系统。
    * **实现:**  在 Linux 和 Android 上，`exit()` 通常会调用底层的 `_exit()` 系统调用。在此之前，它会执行一些清理工作，例如调用通过 `atexit()` 注册的函数，刷新所有打开的输出流等。
    * **本例使用:** 用于在参数不正确或动态链接操作失败时立即终止程序。

**4. 涉及 dynamic linker 的功能:**

* **`android_create_namespace(const char* name, const char* ld_library_path, const char* default_library_path, android_namespace_type_t type, const char* permitted_paths, const std::vector<std::string>* shared_libs)`:**
    * **功能:** 创建一个新的 Android 命名空间。
    * **dynamic linker 处理:**
        1. Dynamic linker 接收到创建命名空间的请求。
        2. 它会在内部创建一个新的数据结构来表示这个命名空间，包含名称、库搜索路径、类型等信息。
        3. 它会维护一个命名空间的列表或树状结构，以便进行管理和查找。
        4. 对于 `ANDROID_NAMESPACE_TYPE_ISOLATED` 类型的命名空间，dynamic linker 会确保它在加载共享库时只搜索指定的路径和链接的共享库。

* **`android_link_namespaces(android_namespace_t* ns, android_namespace_t* other_ns, const char* shared_libs)`:**
    * **功能:** 将一个命名空间 `ns` 与另一个命名空间（通常是默认命名空间或另一个自定义命名空间）链接起来，允许 `ns` 中的库访问 `other_ns` 中的指定的共享库。
    * **dynamic linker 处理:**
        1. Dynamic linker 接收到链接命名空间的请求，指定了源命名空间、目标命名空间和需要共享的库列表。
        2. 它会在源命名空间的数据结构中添加信息，表明它可以访问目标命名空间中的哪些库。
        3. 当在源命名空间中查找符号时，dynamic linker 会先在自身的命名空间中查找，如果没有找到，则会查找链接的目标命名空间中指定的共享库。

* **`android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)`:**
    * **功能:**  以扩展的方式加载共享库，允许指定命名空间等额外信息。
    * **dynamic linker 处理:**
        1. Dynamic linker 接收到加载共享库的请求，并根据 `extinfo` 中的 `ANDROID_DLEXT_USE_NAMESPACE` 标志和 `library_namespace` 指针，确定要在哪个命名空间中加载库。
        2. 它会在指定命名空间的库搜索路径中查找 `filename` 指定的共享库文件。
        3. 找到库文件后，dynamic linker 会解析 ELF 文件头，加载代码段和数据段到内存中。
        4. 它会处理库的依赖关系 (DT_NEEDED 条目)，递归地加载依赖的共享库（注意命名空间的影响）。
        5. 它会解析库的符号表，并将未定义的符号链接到已加载的库中的符号。

**对应的 so 布局样本以及链接的处理过程:**

假设有以下共享库：

* **`libns_hidden_child_public.so`:**  可能包含一些公共的辅助函数，供 `libns_hidden_child_app.so` 使用。
* **`libns_hidden_child_app.so`:** 应用程序特定的库，需要在隔离的命名空间中运行。

**`libns_hidden_child_public.so` 的布局 (简化):**

```
ELF Header
...
Program Headers
...
Section Headers
...
.dynsym (动态符号表):
    符号1: global_public_function (地址)
.strtab (字符串表):
    "global_public_function"
.dynamic (动态链接信息):
    DT_SONAME: libns_hidden_child_public.so
...
```

**`libns_hidden_child_app.so` 的布局 (简化):**

```
ELF Header
...
Program Headers
...
Section Headers
...
.dynsym (动态符号表):
    符号1: app_function (地址)
.strtab (字符串表):
    "app_function"
.dynamic (动态链接信息):
    DT_SONAME: libns_hidden_child_app.so
    DT_NEEDED: libns_hidden_child_public.so
...
```

**链接处理过程:**

1. **创建命名空间:** `android_create_namespace` 创建了一个名为 "app" 的隔离命名空间。
2. **链接命名空间:** `android_link_namespaces` 将 "app" 命名空间与默认命名空间链接，并允许访问 `libns_hidden_child_public.so`。
3. **加载 `libns_hidden_child_app.so`:** `android_dlopen_ext` 被调用，指定在 "app" 命名空间中加载 `libns_hidden_child_app.so`。
4. **处理 `DT_NEEDED`:** Dynamic linker 解析 `libns_hidden_child_app.so` 的 `DT_NEEDED` 条目，发现它依赖于 `libns_hidden_child_public.so`。
5. **查找依赖库:** 由于 "app" 命名空间已链接到包含 `libns_hidden_child_public.so` 的命名空间，dynamic linker 可以在该命名空间中找到并加载 `libns_hidden_child_public.so`。
6. **符号解析:** 当 `libns_hidden_child_app.so` 中调用了 `libns_hidden_child_public.so` 中定义的函数时，dynamic linker 会在加载的 `libns_hidden_child_public.so` 中查找对应的符号地址。
7. **查找 `app_function`:** `dlsym(app_lib, "app_function")` 被调用，dynamic linker 在 "app" 命名空间中加载的 `libns_hidden_child_app.so` 的符号表中查找 "app_function" 的地址。

**5. 逻辑推理、假设输入与输出:**

**假设输入:**

* 命令行参数 `argv[1]` 为指向包含 `libns_hidden_child_app.so` 和 `libns_hidden_child_public.so` 的目录的有效路径。

**逻辑推理:**

1. 程序首先检查命令行参数是否正确。
2. 然后创建一个名为 "app" 的隔离命名空间。
3. 接着将 "app" 命名空间链接到包含公共库和 `libns_hidden_child_public.so` 的命名空间。
4. 使用 `android_dlopen_ext` 在 "app" 命名空间中加载 `libns_hidden_child_app.so`。
5. 在加载的库中查找并执行 `app_function`。

**预期输出 (假设 `app_function` 的实现是打印一些信息):**

如果一切顺利，程序应该成功加载共享库并执行其中的函数，并可能在标准输出或标准错误输出中产生一些与 `app_function` 行为相关的输出。如果任何步骤失败（例如，无法创建命名空间、链接失败、加载失败、找不到符号），程序会打印错误消息并退出。

**6. 用户或编程常见的使用错误:**

* **错误的库路径:**  传递给程序或 `android_create_namespace` 的库路径不正确，导致 dynamic linker 无法找到共享库。
    * **例子:**  运行程序时，忘记传递库文件所在的目录作为参数。
* **忘记链接必要的库:** 在创建命名空间后，忘记使用 `android_link_namespaces` 链接需要的公共库，导致在加载应用程序库时无法找到依赖的库。
    * **例子:**  `libns_hidden_child_app.so` 依赖于标准 C 库或其他系统库，但创建的命名空间没有链接到包含这些库的默认命名空间。
* **在错误的命名空间中加载库:**  没有正确设置 `android_dlextinfo`，导致库被加载到错误的命名空间，可能导致符号查找失败或行为异常。
    * **例子:**  忘记设置 `ANDROID_DLEXT_USE_NAMESPACE` 标志或设置了错误的 `library_namespace`。
* **符号拼写错误:** 在 `dlsym` 中使用了错误的函数名，导致无法找到对应的函数。
    * **例子:**  将 `app_function` 拼写成 `appFunction`。
* **共享库依赖关系问题:** 共享库依赖于其他共享库，但这些依赖库没有被正确放置或链接，导致加载失败。
    * **例子:**  `libns_hidden_child_app.so` 依赖于另一个名为 `libhelper.so` 的库，但 `libhelper.so` 不在 "app" 命名空间的搜索路径中。

**7. Android Framework 或 NDK 如何到达这里:**

虽然开发者通常不会直接调用像 `android_create_namespace` 这样的 Bionic 接口，但 Android Framework 和 NDK 的许多功能都依赖于底层的动态链接机制。

**路径：**

1. **应用启动:** 当 Android 系统启动一个应用程序时，Zygote 进程会 fork 出一个新的进程来运行该应用。
2. **加载 APK:**  系统会加载 APK 文件，并解析其中的 `AndroidManifest.xml` 文件，获取应用所需的信息。
3. **加载本地库 (NDK):** 如果应用使用了 NDK 开发的本地库，系统会使用 `dlopen` 或类似机制来加载这些库。在较新的 Android 版本中，系统会确保这些库加载到应用自身的隔离命名空间中。
4. **`android_dlopen_ext` 的使用:** 虽然应用开发者通常使用 NDK 提供的 `dlopen` 函数，但 Android Framework 底层可能会使用 `android_dlopen_ext` 来加载系统库或进行更细粒度的控制，例如指定命名空间。
5. **Bionic 的作用:** Bionic 库作为 Android 的 C 库，实现了 `dlopen`, `dlsym`, `android_create_namespace` 等动态链接相关的函数。当 Android Framework 或应用进程需要进行动态链接操作时，最终会调用到 Bionic 库中的实现。

**Frida Hook 示例调试步骤:**

可以使用 Frida 来 hook 关键的 Bionic 函数，观察其参数和返回值，从而了解动态链接和命名空间创建的过程。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 找不到进程: {package_name}. 请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "android_create_namespace"), {
    onEnter: function(args) {
        console.log("[+] android_create_namespace called");
        console.log("    name: " + Memory.readUtf8String(args[0]));
        console.log("    ld_library_path: " + (args[1] ? Memory.readUtf8String(args[1]) : null));
        console.log("    default_library_path: " + Memory.readUtf8String(args[2]));
        console.log("    type: " + args[3]);
    },
    onLeave: function(retval) {
        console.log("[+] android_create_namespace returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "android_link_namespaces"), {
    onEnter: function(args) {
        console.log("[+] android_link_namespaces called");
        console.log("    ns: " + args[0]);
        console.log("    other_ns: " + args[1]);
        console.log("    shared_libs: " + Memory.readUtf8String(args[2]));
    },
    onLeave: function(retval) {
        console.log("[+] android_link_namespaces returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "android_dlopen_ext"), {
    onEnter: function(args) {
        console.log("[+] android_dlopen_ext called");
        console.log("    filename: " + Memory.readUtf8String(args[0]));
        console.log("    flag: " + args[1]);
        console.log("    extinfo: " + args[2]);
        if (args[2]) {
            var extinfo = ptr(args[2]);
            console.log("    extinfo->flags: " + extinfo.readU32());
            var library_namespace = extinfo.add(Process.pointerSize).readPointer();
            console.log("    extinfo->library_namespace: " + library_namespace);
        }
    },
    onLeave: function(retval) {
        console.log("[+] android_dlopen_ext returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "dlsym"), {
    onEnter: function(args) {
        console.log("[+] dlsym called");
        console.log("    handle: " + args[0]);
        console.log("    symbol: " + Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        console.log("[+] dlsym returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 Frida-tools。
2. **连接设备:** 将你的 Android 设备连接到电脑，并确保 adb 可用。
3. **运行目标应用:** 启动你想要分析的应用。
4. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `.py` 文件，并将 `package_name` 替换为你应用的包名，然后在终端运行该脚本。
5. **观察输出:**  Frida 会拦截对 `android_create_namespace`, `android_link_namespaces`, `android_dlopen_ext`, `dlsym` 的调用，并打印出相关的参数和返回值，帮助你理解动态链接的过程。

通过这些 Frida hook，你可以观察到 Android 系统或应用在加载本地库时如何创建和使用命名空间，以及动态链接的具体过程。

Prompt: 
```
这是目录为bionic/tests/libs/ns_hidden_child_helper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <android/dlext.h>
#include <dlfcn.h>
#include <stdlib.h>

#include <string>

#include "../core_shared_libs.h"
#include "../dlext_private_tests.h"

extern "C" void global_function();
extern "C" void internal_function();

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s NS_PATH\n", argv[0]);
    fprintf(stderr, "NS_PATH   path to the ns_hidden_child_app directory\n");
    exit(1);
  }

  // Ensure that -Wl,--needed doesn't break the test by removing DT_NEEDED entries.
  global_function();
  internal_function();

  const char* app_lib_dir = argv[1];
  android_namespace_t* app_ns =
      android_create_namespace("app", nullptr, app_lib_dir, ANDROID_NAMESPACE_TYPE_ISOLATED,
                               nullptr, nullptr);
  if (app_ns == nullptr) {
    fprintf(stderr, "android_create_namespace failed: %s\n", dlerror());
    exit(1);
  }

  std::string public_libs = std::string(kCoreSharedLibs) + ":libns_hidden_child_public.so";
  if (!android_link_namespaces(app_ns, nullptr, public_libs.c_str())) {
    fprintf(stderr, "android_link_namespaces failed: %s\n", dlerror());
    exit(1);
  }

  android_dlextinfo ext = {
    .flags = ANDROID_DLEXT_USE_NAMESPACE,
    .library_namespace = app_ns,
  };
  void* app_lib = android_dlopen_ext("libns_hidden_child_app.so", RTLD_NOW | RTLD_LOCAL, &ext);
  if (app_lib == nullptr) {
    fprintf(stderr, "android_dlopen_ext failed: %s\n", dlerror());
    exit(1);
  }

  auto app_function = reinterpret_cast<void(*)()>(dlsym(app_lib, "app_function"));
  if (app_function == nullptr) {
    fprintf(stderr, "dlsym failed to find app_function: %s\n", dlerror());
    exit(1);
  }

  app_function();
  return 0;
}

"""

```