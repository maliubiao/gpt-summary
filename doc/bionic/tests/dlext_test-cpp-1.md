Response:
My thinking process for summarizing the provided C++ code snippet went through these stages:

1. **Initial Scan and Keyword Recognition:** I quickly scanned the code, looking for recurring keywords and patterns. I immediately noticed the repeated use of `TEST(dlext, ...)`, `android_namespace_t`, `android_create_namespace`, `android_link_namespaces`, `android_dlopen_ext`, `dlsym`, `dlclose`, `dlerror`, `ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_STREQ`, `EXPECT_EQ`, and file-related operations (`open`, `O_TMPFILE`, `memfd_create`, `fstatfs`, `ReadFileToString`, `WriteStringToFd`). These keywords strongly suggested that the code is testing the dynamic linker (`dl`) extensions (`dlext`) and namespace functionality in Android's Bionic library.

2. **Identifying Core Functionality:**  Based on the keywords, I deduced that the primary focus of this code is testing various aspects of Android's namespace isolation for dynamically loaded libraries. The repeated pattern of creating namespaces, linking them, and then attempting to load libraries within those namespaces using `android_dlopen_ext` pointed towards testing the correctness of this isolation.

3. **Grouping Tests by Feature:**  I started grouping the individual `TEST` blocks based on what specific feature they seemed to be testing. For instance, multiple tests used `O_TMPFILE` or `memfd_create`, suggesting tests related to loading libraries from file descriptors. Other tests explicitly named namespaces like "public" and "private" and manipulated their linking, indicating tests about symbol visibility and namespace linking.

4. **Abstracting Test Logic:** For each group of tests, I tried to abstract the common goal or logic. For example, the tests involving `O_TMPFILE` and `memfd_create` were clearly about testing if `android_dlopen_ext` can load libraries from these file descriptors within specific namespaces. The tests involving linking namespaces were about verifying that libraries in different namespaces have the correct symbol visibility based on the linking configuration.

5. **Summarizing Each Feature:**  I then formulated concise summaries for each identified feature. I focused on the "what" and the "why" of each test group. For instance, instead of saying "This test calls `android_create_namespace`...", I'd say "Tests the ability to load libraries from memory file descriptors...".

6. **Identifying Key Concepts:**  As I summarized, I noted recurring concepts like "namespace isolation," "symbol visibility," "namespace linking," "exempt lists," and different namespace types (isolated, regular, shared). These became key elements in the overall summary.

7. **Structuring the Summary:** I organized the summary into a logical flow, starting with the core purpose and then detailing the specific features being tested. I used bullet points for clarity and conciseness.

8. **Refining the Language:**  I reviewed the summary to ensure it was clear, concise, and used appropriate terminology related to dynamic linking and namespaces. I avoided overly technical jargon where possible while still maintaining accuracy.

9. **Addressing the "Part 2" Instruction:** I explicitly addressed the prompt's request to summarize the functionality of this *specific* part of the file. This involved focusing solely on the tests included in the provided snippet.

Essentially, I treated the code like a specification document for the namespace functionality. My goal was to understand the requirements being tested and articulate those requirements in a human-readable summary. I moved from specific test cases to generalized features, and then organized those features into a coherent overview.
这段代码是 `bionic/tests/dlext_test.cpp` 文件的第二部分，它主要集中在测试 Android Bionic 动态链接器扩展 (`dlext`) 提供的命名空间 (namespace) 功能。

**这段代码的主要功能可以归纳为测试以下与动态链接器命名空间相关的特性：**

* **基本的命名空间隔离:**  验证在不同的命名空间中加载的库，即使拥有相同的符号名称，也能够独立存在，互不干扰。这包括对本地符号、私有外部符号和公共外部符号的隔离。
* **`dlopen_ext` 与命名空间:** 测试使用 `android_dlopen_ext` 函数，并通过 `android_dlextinfo` 结构体指定命名空间来加载库的行为。验证库被正确加载到指定的命名空间中。
* **使用文件描述符加载库:** 测试 `android_dlopen_ext` 是否能够从文件描述符 (例如通过 `O_TMPFILE` 或 `memfd_create` 创建的) 加载动态库，并将其加载到指定的命名空间中。
* **命名空间间的符号可见性:** 测试在不同的命名空间之间，符号的可见性是否符合预期。特别是：
    *  在一个命名空间内，依赖库的符号是否可以被访问。
    *  在不同的命名空间之间，未共享的库的符号是否不可见。
* **命名空间的卸载:** 测试卸载一个在特定命名空间中加载的库，是否会影响其他命名空间中同名的库。
* **命名空间卸载与缺失符号:** 测试在命名空间链接的情况下，卸载依赖的库是否会导致在其他命名空间中加载依赖它的库时出现找不到符号的错误。
* **命名空间豁免列表 (Exempt List):** 测试具有豁免列表特性的命名空间，是否允许加载特定的系统库 (例如 `libnativehelper.so`)，以及是否能正确避免重复加载 `libdl.so`。
* **默认禁用豁免列表:** 验证默认情况下，命名空间不启用豁免列表。
* **循环命名空间链接:** 测试循环依赖的命名空间链接 (例如 ns1 -> ns2 -> ns1) 是否会导致加载器崩溃或出现问题。
* **隔离命名空间:**  测试隔离命名空间的行为。隔离命名空间中的库无法访问其他命名空间（包括默认命名空间）的库，除非显式链接。同时也测试了通过绝对路径加载库在隔离命名空间中的限制和允许的情况 (取决于命名空间的 `isolation_path`)。
* **共享命名空间:** 测试共享命名空间的行为。共享命名空间允许子命名空间访问父命名空间中已经加载的库，从而避免重复加载。这部分测试了在共享和非共享的子命名空间中加载相同库时的差异，以及符号地址的异同。
* **共享命名空间的链接和路径:** 这部分测试了更复杂的共享命名空间场景，包括链接和搜索路径的配置。

**与 Android 功能的关系及举例说明：**

Android 使用命名空间来隔离不同的应用程序和系统组件，以提高安全性和稳定性。这段代码测试了这一核心机制的各种细节。

* **应用程序隔离:**  每个 Android 应用程序通常运行在自己的命名空间中。这段代码测试了如何创建和链接这样的命名空间，确保一个应用的库不会与另一个应用的库冲突。例如，如果两个应用都依赖了某个版本的 `libpng.so`，命名空间可以保证它们各自加载的是自己需要的版本，而不会互相干扰。
* **系统组件隔离:** Android 系统也使用命名空间来隔离不同的系统组件。例如，渲染相关的组件可能在一个命名空间中，而音频相关的组件在另一个命名空间中。这段代码测试了这种隔离机制的有效性。
* **NDK 开发:** NDK 开发者可以使用 `android_dlopen_ext` 和命名空间相关的 API 来更精细地控制动态库的加载和符号的可见性。这段代码的测试用例验证了这些 API 的正确性，确保 NDK 开发者可以安全可靠地使用它们。

**详细解释每一个 libc 函数的功能是如何实现的:**

这段代码主要测试的是动态链接器的功能，而不是 `libc` 的具体实现。其中使用了一些 POSIX 标准的 `libc` 函数，但重点不在于它们的内部实现，而在于它们与动态链接器扩展 API 的交互。

* **`open()`:**  用于打开文件或创建特殊文件。在这里，它被用来创建 `O_TMPFILE` 类型的临时文件，用于后续通过文件描述符加载库。`libc` 中的 `open()` 系统调用最终会传递给内核，由内核负责创建和管理文件描述符。
* **`dlopen()`:**  用于加载动态链接库。这里虽然没有直接测试 `dlopen`，但测试的是其扩展版本 `android_dlopen_ext`，它在内部会调用底层的动态链接器实现。 `libc` 中的 `dlopen()` 会调用系统的动态链接器（在 Android 上是 `linker` 或 `linker64`），由链接器负责查找、加载和链接动态库。
* **`dlsym()`:**  用于在已加载的动态链接库中查找符号的地址。`libc` 中的 `dlsym()` 会调用动态链接器的内部函数，遍历已加载库的符号表，找到匹配的符号并返回其地址。
* **`dlclose()`:**  用于卸载已加载的动态链接库。`libc` 中的 `dlclose()` 会通知动态链接器减少库的引用计数，当引用计数降为零时，链接器会执行卸载操作，包括解除内存映射和执行析构函数。
* **`dlerror()`:**  用于获取最近一次 `dlopen`、`dlsym` 或 `dlclose` 调用失败时的错误信息。 `libc` 中的 `dlerror()` 通常会维护一个线程局部变量来存储错误信息，并返回该变量的值。
* **`TEMP_FAILURE_RETRY()`:** 这是一个宏，用于在系统调用由于信号中断失败时重试该调用。它包装了可能被信号中断的系统调用，例如 `open` 和 `fstatfs`。
* **`memfd_create()`:** 用于创建一个匿名的、基于内存的文件描述符。这是一种在进程间共享内存的机制。在这里，它被用来创建一个内存文件，然后将动态库的内容写入该文件，并通过文件描述符加载。 `libc` 中的 `memfd_create()` 系统调用会与内核交互，创建一个与 tmpfs 文件系统关联的匿名文件。
* **`fstatfs()`:**  用于获取文件系统的状态信息。在这里，它被用来检查 `memfd_create` 创建的文件描述符是否确实是 `TMPFS_MAGIC`，以验证 `memfd_create` 的行为。`libc` 中的 `fstatfs()` 系统调用会传递给内核，由内核返回文件系统的统计信息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

为了更好地理解这些测试用例，让我们以 `TEST(dlext, ns_symbol_visibilty_one_namespace)` 为例，假设有以下 so 布局和链接过程：

**so 布局样本:**

假设有以下三个共享库：

* **`libnstest_root.so` (在 private_namespace_libs 目录下):**
    * 依赖于 `libnstest_internal.so`。
    * 导出函数 `ns_get_local_string()`，返回字符串 "This string is local to root library"。
    * 导入并使用 `ns_get_internal_extern_string()` 和 `internal_extern_string()`。

* **`libnstest_internal.so` (在 private_namespace_libs 目录下):**
    * 导出函数 `ns_get_internal_extern_string()`，返回字符串 "This string is from a library a shared library depends on"。
    * 依赖于 `libtest_internal_dep.so`。

* **`libtest_internal_dep.so` (在 private_namespace_libs 目录下):**
    * 导出函数 `internal_extern_string()`，返回字符串 "This string is from a library a shared library depends on"。

**链接的处理过程:**

1. **创建命名空间 "one":**  指定搜索路径为 `GetTestLibRoot() + "/public_namespace_libs:" + GetTestLibRoot() + "/private_namespace_libs"`。
2. **链接命名空间 "one" 与核心共享库:**  允许 "one" 命名空间访问核心的系统库 (如 `libc.so`, `libm.so`, `libdl.so`)。
3. **使用 `android_dlopen_ext` 加载 `libnstest_root.so` 到命名空间 "one":**
    * 动态链接器开始解析 `libnstest_root.so` 的依赖。
    * 动态链接器在命名空间 "one" 的搜索路径中查找 `libnstest_internal.so` 和 `libtest_internal_dep.so`。
    * 找到这两个依赖库后，动态链接器将它们加载到命名空间 "one" 中。
    * 动态链接器解析 `libnstest_root.so` 中的符号引用：
        * `ns_get_internal_extern_string()`:  链接到在 `libnstest_internal.so` 中导出的符号。
        * `internal_extern_string()`: 链接到在 `libtest_internal_dep.so` 中导出的符号。
4. **调用 `dlsym` 查找符号:**
    * `dlsym(handle, "ns_get_internal_extern_string")`:  在已加载的 `libnstest_root.so` 和其依赖库中查找 `ns_get_internal_extern_string`，成功找到并返回其地址。
    * `dlsym(handle, "internal_extern_string")`:  在已加载的 `libnstest_root.so` 和其依赖库中查找 `internal_extern_string`，成功找到并返回其地址。

**假设输入与输出 (针对 `TEST(dlext, ns_symbol_visibilty_one_namespace)`)**

**假设输入:**

* 存在 `libnstest_root.so`, `libnstest_internal.so`, `libtest_internal_dep.so` 这些共享库，并按照上述 so 布局组织。
* 命名空间 "one" 被成功创建并链接。

**预期输出:**

* `android_dlopen_ext(root_lib, RTLD_NOW, &extinfo)` 返回一个非空的句柄 `handle`。
* `dlsym(handle, "ns_get_internal_extern_string")` 返回一个非空的函数指针。
* `ns_get_internal_extern_string()` 调用返回字符串 "This string is from a library a shared library depends on"。
* `dlsym(handle, "internal_extern_string")` 返回一个非空的函数指针。
* `internal_extern_string_fn()` 调用返回字符串 "This string is from a library a shared library depends on"。

**用户或编程常见的使用错误举例说明:**

* **错误的命名空间配置:**  如果开发者创建命名空间时，搜索路径配置错误，或者没有正确链接依赖的命名空间，会导致 `dlopen_ext` 找不到库或者找不到符号。
    ```c++
    // 错误示例：命名空间搜索路径配置错误
    android_namespace_t* ns = android_create_namespace("my_ns", nullptr, "/wrong/path", ...);
    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
    extinfo.library_namespace = ns;
    void* handle = android_dlopen_ext("mylib.so", RTLD_NOW, &extinfo);
    ASSERT_TRUE(handle == nullptr); // 可能因为找不到 mylib.so 而失败
    ```

* **在错误的命名空间中查找符号:** 开发者可能会尝试在一个命名空间中加载的库中查找另一个命名空间中的符号，这会导致 `dlsym` 返回 `nullptr`。
    ```c++
    // 假设 libA.so 加载到 ns1，libB.so 加载到 ns2
    void* handle_a = android_dlopen_ext("libA.so", RTLD_NOW, &extinfo_ns1);
    void* handle_b = android_dlopen_ext("libB.so", RTLD_NOW, &extinfo_ns2);
    void* symbol_in_a = dlsym(handle_b, "symbol_from_lib_a");
    ASSERT_TRUE(symbol_in_a == nullptr); // 在 libB.so 的命名空间中找不到 libA.so 的符号
    ```

* **忘记链接命名空间:** 如果在创建子命名空间后，忘记将其链接到父命名空间或必要的共享库，会导致子命名空间中的库无法访问父命名空间中的符号。
    ```c++
    // 错误示例：忘记链接命名空间
    android_namespace_t* parent_ns = android_create_namespace("parent", ...);
    android_namespace_t* child_ns = android_create_namespace("child", ..., parent_ns);
    // 缺少 android_link_namespaces(child_ns, parent_ns, ...);
    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
    extinfo.library_namespace = child_ns;
    void* handle = android_dlopen_ext("lib_in_child.so", RTLD_NOW, &extinfo);
    // 如果 lib_in_child.so 依赖于 parent_ns 中的库，加载可能会失败
    ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用 `dlopen` 或 `dlopen_ext`:**  当 Android framework 或 NDK 中的代码需要加载一个动态库时，会调用 `dlopen` 或 `android_dlopen_ext` 函数。例如，当启动一个包含 native library 的 Activity 时，`System.loadLibrary()` 最终会调用到 native 层的 `dlopen` 或其变体。NDK 开发者也可以直接在 C/C++ 代码中使用这些函数。

2. **`libc` 层的 `dlopen` 或 `android_dlopen_ext`:** 这些函数是 `libc` 库提供的接口。`android_dlopen_ext` 是 Android 提供的扩展版本，允许指定额外的加载信息，例如命名空间。

3. **动态链接器 (`linker` 或 `linker64`):** `libc` 中的 `dlopen` 函数会调用底层的动态链接器。动态链接器负责查找、加载和链接共享库。当调用 `android_dlopen_ext` 并指定命名空间时，动态链接器会根据提供的命名空间信息来查找和加载库。

4. **命名空间管理:** 动态链接器内部维护着命名空间的信息。当需要加载库到特定命名空间时，链接器会检查该命名空间的配置（例如搜索路径、链接关系）来定位库文件和解析符号。

**Frida Hook 示例调试步骤:**

假设我们要 hook `android_dlopen_ext` 函数，查看加载库时使用的命名空间信息。

```python
import frida
import sys

package_name = "your.app.package" # 替换为你的应用包名

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

script_source = """
Interceptor.attach(Module.findExportByName("libdl.so", "android_dlopen_ext"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        var extinfo_ptr = args[2];

        var flags_extinfo = extinfo_ptr.readU32();
        var library_fd = extinfo_ptr.add(Process.pointerSize).readInt();
        var library_namespace = extinfo_ptr.add(2 * Process.pointerSize).readPointer();

        console.log("[+] android_dlopen_ext called");
        console.log("    Filename: " + filename);
        console.log("    Flags: " + flags);
        console.log("    extinfo Flags: " + flags_extinfo);
        console.log("    extinfo library_fd: " + library_fd);
        console.log("    extinfo library_namespace: " + library_namespace);

        if (library_namespace.isNull()) {
            console.log("    Loading into the default namespace.");
        } else {
            // 你可以尝试读取 namespace 结构体中的信息，但这取决于其内部布局
            console.log("    Loading into a specific namespace.");
        }
    },
    onLeave: function(retval) {
        console.log("[+] android_dlopen_ext returned: " + retval);
    }
});
"""

script = session.create_script(script_source)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook `android_dlopen_ext` 函数，并在函数调用时打印出传入的参数，包括文件名、标志位以及 `android_dlextinfo` 结构体中的信息，其中就包含了目标命名空间的指针。通过观察这些信息，你可以了解 Android framework 或 NDK 在加载特定库时是如何使用命名空间机制的。

总而言之，这段代码是 Android Bionic 中关于动态链接器命名空间功能的一组测试用例，它验证了命名空间隔离、符号可见性、库加载和卸载等核心特性，这些特性对于 Android 的安全性和稳定性至关重要。

### 提示词
```
这是目录为bionic/tests/dlext_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
lic namespace", ns_get_public_extern_string1());
  ASSERT_TRUE(ns_get_public_extern_string1() == ns_get_public_extern_string2());

  // and now check that dlopen() does the right thing in terms of preserving namespace
  fn_t ns_get_dlopened_string1 = reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_dlopened_string"));
  ASSERT_TRUE(ns_get_dlopened_string1 != nullptr) << dlerror();
  fn_t ns_get_dlopened_string2 = reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_dlopened_string"));
  ASSERT_TRUE(ns_get_dlopened_string2 != nullptr) << dlerror();

  EXPECT_STREQ("This string is from private namespace (dlopened library)", ns_get_dlopened_string1());
  EXPECT_STREQ("This string is from private namespace (dlopened library)", ns_get_dlopened_string2());

  ASSERT_TRUE(ns_get_dlopened_string1() != ns_get_dlopened_string2());

  // Check that symbols from non-shared libraries a shared library depends on are not visible
  // from original namespace.

  fn_t ns_get_internal_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_internal_extern_string"));
  ASSERT_TRUE(ns_get_internal_extern_string != nullptr) << dlerror();
  ASSERT_TRUE(ns_get_internal_extern_string() == nullptr) <<
      "ns_get_internal_extern_string() expected to return null but returns \"" <<
      ns_get_internal_extern_string() << "\"";

  dlclose(handle1);

  // Check if handle2 is still alive (and well)
  ASSERT_STREQ("This string is local to root library", ns_get_local_string2());
  ASSERT_STREQ("This string is from private namespace", ns_get_private_extern_string2());
  ASSERT_STREQ("This string is from public namespace", ns_get_public_extern_string2());
  ASSERT_STREQ("This string is from private namespace (dlopened library)", ns_get_dlopened_string2());

  dlclose(handle2);
}

TEST(dlext, dlopen_ext_use_o_tmpfile_fd) {
  const std::string lib_path = GetTestLibRoot() + "/libtest_simple.so";

  int tmpfd = TEMP_FAILURE_RETRY(
        open(GetTestLibRoot().c_str(), O_TMPFILE | O_CLOEXEC | O_RDWR | O_EXCL, 0));

  // Ignore kernels without O_TMPFILE flag support
  if (tmpfd == -1 && (errno == EISDIR || errno == EINVAL || errno == EOPNOTSUPP)) {
    return;
  }

  ASSERT_TRUE(tmpfd != -1) << strerror(errno);

  android_namespace_t* ns =
          android_create_namespace("testing-o_tmpfile",
                                   nullptr,
                                   GetTestLibRoot().c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_DL_NOTNULL(ns);

  ASSERT_TRUE(android_link_namespaces(ns, nullptr, g_core_shared_libs.c_str())) << dlerror();

  std::string content;
  ASSERT_TRUE(android::base::ReadFileToString(lib_path, &content)) << strerror(errno);
  ASSERT_TRUE(android::base::WriteStringToFd(content, tmpfd)) << strerror(errno);

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_fd = tmpfd;
  extinfo.library_namespace = ns;

  void* handle = android_dlopen_ext("foobar", RTLD_NOW, &extinfo);

  ASSERT_DL_NOTNULL(handle);

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  EXPECT_EQ(1729U, *taxicab_number);
  dlclose(handle);
}

TEST(dlext, dlopen_ext_use_memfd) {
  const std::string lib_path = GetTestLibRoot() + "/libtest_simple.so";

  // create memfd
  int memfd = memfd_create("foobar", MFD_CLOEXEC);
  if (memfd == -1 && errno == ENOSYS) GTEST_SKIP() << "no memfd_create() in this kernel";
  ASSERT_TRUE(memfd != -1) << strerror(errno);

  // Check st.f_type is TMPFS_MAGIC for memfd
  struct statfs st;
  ASSERT_TRUE(TEMP_FAILURE_RETRY(fstatfs(memfd, &st)) == 0) << strerror(errno);
  ASSERT_EQ(static_cast<decltype(st.f_type)>(TMPFS_MAGIC), st.f_type);

  android_namespace_t* ns =
          android_create_namespace("testing-memfd",
                                   nullptr,
                                   GetTestLibRoot().c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_DL_NOTNULL(ns);

  ASSERT_TRUE(android_link_namespaces(ns, nullptr, g_core_shared_libs.c_str())) << dlerror();

  // read file into memfd backed one.
  std::string content;
  ASSERT_TRUE(android::base::ReadFileToString(lib_path, &content)) << strerror(errno);
  ASSERT_TRUE(android::base::WriteStringToFd(content, memfd)) << strerror(errno);

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_fd = memfd;
  extinfo.library_namespace = ns;

  void* handle = android_dlopen_ext("foobar", RTLD_NOW, &extinfo);

  ASSERT_DL_NOTNULL(handle);

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  EXPECT_EQ(1729U, *taxicab_number);
  dlclose(handle);
}

TEST(dlext, ns_symbol_visibilty_one_namespace) {
  static const char* root_lib = "libnstest_root.so";
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string ns_search_path = GetTestLibRoot() + "/public_namespace_libs:" +
                                     GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns =
          android_create_namespace("one",
                                   nullptr,
                                   ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns;

  void* handle = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef const char* (*fn_t)();

  // Check that relocation worked correctly
  fn_t ns_get_internal_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle, "ns_get_internal_extern_string"));
  ASSERT_TRUE(ns_get_internal_extern_string != nullptr) << dlerror();
  ASSERT_STREQ("This string is from a library a shared library depends on", ns_get_internal_extern_string());

  fn_t internal_extern_string_fn =
          reinterpret_cast<fn_t>(dlsym(handle, "internal_extern_string"));
  ASSERT_TRUE(internal_extern_string_fn != nullptr) << dlerror();
  ASSERT_STREQ("This string is from a library a shared library depends on", internal_extern_string_fn());
}

TEST(dlext, ns_symbol_visibilty_between_namespaces) {
  static const char* root_lib = "libnstest_root.so";
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string public_ns_search_path =  GetTestLibRoot() + "/public_namespace_libs";
  const std::string private_ns_search_path = GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns_public =
          android_create_namespace("public",
                                   nullptr,
                                   public_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_public, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_private =
          android_create_namespace("private",
                                   nullptr,
                                   private_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_private, ns_public, g_public_lib)) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_private, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_private;

  void* handle = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef const char* (*fn_t)();

  // Check that relocation worked correctly
  fn_t ns_get_internal_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle, "ns_get_internal_extern_string"));
  ASSERT_TRUE(ns_get_internal_extern_string != nullptr) << dlerror();
  ASSERT_TRUE(ns_get_internal_extern_string() == nullptr) <<
      "ns_get_internal_extern_string() expected to return null but returns \"" <<
      ns_get_internal_extern_string() << "\"";

  fn_t internal_extern_string_fn =
          reinterpret_cast<fn_t>(dlsym(handle, "internal_extern_string"));
  ASSERT_TRUE(internal_extern_string_fn == nullptr);
  ASSERT_STREQ("undefined symbol: internal_extern_string", dlerror());
}

TEST(dlext, ns_unload_between_namespaces) {
  static const char* root_lib = "libnstest_root.so";
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string public_ns_search_path =  GetTestLibRoot() + "/public_namespace_libs";
  const std::string private_ns_search_path = GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns_public =
          android_create_namespace("public",
                                   nullptr,
                                   public_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_public, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_private =
          android_create_namespace("private",
                                   nullptr,
                                   private_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_private, ns_public, g_public_lib)) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_private, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_private;

  void* handle = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  dlclose(handle);
  // Check that root_lib was unloaded
  handle = android_dlopen_ext(root_lib, RTLD_NOW | RTLD_NOLOAD, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_EQ(std::string("dlopen failed: library \"") + root_lib +
            "\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());

  // Check that shared library was unloaded in public ns
  extinfo.library_namespace = ns_public;
  handle = android_dlopen_ext(g_public_lib, RTLD_NOW | RTLD_NOLOAD, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_EQ(std::string("dlopen failed: library \"") + g_public_lib +
            "\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
}

TEST(dlext, ns_unload_between_namespaces_missing_symbol_direct) {
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string public_ns_search_path =  GetTestLibRoot() + "/public_namespace_libs";
  const std::string private_ns_search_path = GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns_public =
          android_create_namespace("public",
                                   nullptr,
                                   public_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_public, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_private =
          android_create_namespace("private",
                                   nullptr,
                                   private_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_private, ns_public, "libtest_missing_symbol.so")) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_private, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_private;

  void* handle = android_dlopen_ext((public_ns_search_path + "/libtest_missing_symbol.so").c_str(),
                                    RTLD_NOW,
                                    &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_EQ(std::string("dlopen failed: cannot locate symbol \"dlopen_testlib_missing_symbol\" referenced by \"") +
            public_ns_search_path + "/libtest_missing_symbol.so\"...",
            dlerror());
}

TEST(dlext, ns_unload_between_namespaces_missing_symbol_indirect) {
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string public_ns_search_path =  GetTestLibRoot() + "/public_namespace_libs";
  const std::string private_ns_search_path = GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns_public =
          android_create_namespace("public",
                                   nullptr,
                                   public_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_public, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_private =
          android_create_namespace("private",
                                   nullptr,
                                   private_ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns_private,
                                      ns_public,
                                      "libnstest_public.so:libtest_missing_symbol_child_public.so")
              ) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_private, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_private;

  void* handle = android_dlopen_ext("libtest_missing_symbol_root.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_EQ(std::string("dlopen failed: cannot locate symbol \"dlopen_testlib_missing_symbol\" referenced by \"") +
            private_ns_search_path + "/libtest_missing_symbol_root.so\"...",
            dlerror());
}

TEST(dlext, ns_exempt_list_enabled) {
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string ns_search_path = GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns =
          android_create_namespace("namespace",
                                   nullptr,
                                   ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED | ANDROID_NAMESPACE_TYPE_EXEMPT_LIST_ENABLED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns;

  // An app targeting M can open libnativehelper.so because it's on the exempt-list.
  android_set_application_target_sdk_version(23);
  void* handle = android_dlopen_ext("libnativehelper.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  // Check that loader did not load another copy of libdl.so while loading exempted library.
  void* dlsym_ptr = dlsym(handle, "dlsym");
  ASSERT_TRUE(dlsym_ptr != nullptr) << dlerror();
  ASSERT_EQ(&dlsym, dlsym_ptr);

  dlclose(handle);

  // An app targeting N no longer has the exempt-list.
  android_set_application_target_sdk_version(24);
  handle = android_dlopen_ext("libnativehelper.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_STREQ("dlopen failed: library \"libnativehelper.so\" not found", dlerror());
}

TEST(dlext, ns_exempt_list_disabled_by_default) {
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string ns_search_path = GetTestLibRoot() + "/private_namespace_libs";

  android_namespace_t* ns =
          android_create_namespace("namespace",
                                   nullptr,
                                   ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns;

  android_set_application_target_sdk_version(23);
  void* handle = android_dlopen_ext("libnativehelper.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_STREQ("dlopen failed: library \"libnativehelper.so\" not found", dlerror());
}

TEST(dlext, ns_cyclic_namespaces) {
  // Test that ns1->ns2->ns1 link does not break the loader
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));
  std::string shared_libs = g_core_shared_libs + ":libthatdoesnotexist.so";

  const std::string ns_search_path =  GetTestLibRoot() + "/public_namespace_libs";

  android_namespace_t* ns1 =
          android_create_namespace("ns1",
                                   nullptr,
                                   ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns1, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns2 =
          android_create_namespace("ns1",
                                   nullptr,
                                   ns_search_path.c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(android_link_namespaces(ns2, nullptr, g_core_shared_libs.c_str())) << dlerror();

  ASSERT_TRUE(android_link_namespaces(ns2, ns1, shared_libs.c_str())) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns1, ns2, shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns1;

  void* handle = android_dlopen_ext("libthatdoesnotexist.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_STREQ("dlopen failed: library \"libthatdoesnotexist.so\" not found", dlerror());
}

TEST(dlext, ns_isolated) {
  static const char* root_lib = "libnstest_root_not_isolated.so";
  std::string shared_libs = g_core_shared_libs + ":" + g_public_lib;

  const std::string lib_public_path = GetTestLibRoot() + "/public_namespace_libs/" + g_public_lib;
  void* handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle_public != nullptr) << dlerror();

  android_set_application_target_sdk_version(42U); // something > 23

  ASSERT_TRUE(android_init_anonymous_namespace(shared_libs.c_str(), nullptr)) << dlerror();

  android_namespace_t* ns_not_isolated =
          android_create_namespace("private",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_REGULAR,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_not_isolated != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_not_isolated, nullptr, shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_isolated =
          android_create_namespace("private_isolated1",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_isolated != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_isolated, nullptr, shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_isolated2 =
          android_create_namespace("private_isolated2",
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   nullptr,
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   GetTestLibRoot().c_str(),
                                   nullptr);
  ASSERT_TRUE(ns_isolated2 != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_isolated2, nullptr, shared_libs.c_str())) << dlerror();

  ASSERT_TRUE(dlopen(root_lib, RTLD_NOW) == nullptr);
  ASSERT_STREQ("dlopen failed: library \"libnstest_root_not_isolated.so\" not found", dlerror());

  std::string lib_private_external_path =
      GetTestLibRoot() + "/private_namespace_libs_external/libnstest_private_external.so";

  // Load lib_private_external_path to default namespace
  // (it should remain invisible for the isolated namespaces after this)
  void* handle = dlopen(lib_private_external_path.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_not_isolated;

  void* handle1 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();

  extinfo.library_namespace = ns_isolated;

  void* handle2 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 == nullptr);
  const char* error = dlerror();
  ASSERT_MATCH(error,
               R"(dlopen failed: library "libnstest_private_external.so" not found: needed by )"
               R"(\S+libnstest_root_not_isolated.so in namespace private_isolated1)");

  // Check dlopen by absolute path
  handle2 = android_dlopen_ext(lib_private_external_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 == nullptr);
  ASSERT_EQ("dlopen failed: library \"" + lib_private_external_path + "\" needed"
            " or dlopened by \"" + android::base::GetExecutablePath() +  "\" is not accessible"
            " for the namespace \"private_isolated1\"", dlerror());

  extinfo.library_namespace = ns_isolated2;

  // this should work because isolation_path for private_isolated2 includes GetTestLibRoot()
  handle2 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 != nullptr) << dlerror();
  dlclose(handle2);

  // Check dlopen by absolute path
  handle2 = android_dlopen_ext(lib_private_external_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 != nullptr) << dlerror();
  dlclose(handle2);

  typedef const char* (*fn_t)();
  fn_t ns_get_local_string = reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_local_string"));
  ASSERT_TRUE(ns_get_local_string != nullptr) << dlerror();

  ASSERT_STREQ("This string is local to root library", ns_get_local_string());

  fn_t ns_get_private_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_private_extern_string"));
  ASSERT_TRUE(ns_get_private_extern_string != nullptr) << dlerror();

  ASSERT_STREQ("This string is from private namespace", ns_get_private_extern_string());

  fn_t ns_get_public_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_public_extern_string"));
  ASSERT_TRUE(ns_get_public_extern_string != nullptr) << dlerror();

  ASSERT_STREQ("This string is from public namespace", ns_get_public_extern_string());

  fn_t ns_get_dlopened_string = reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_dlopened_string"));
  ASSERT_TRUE(ns_get_dlopened_string != nullptr) << dlerror();

  ASSERT_STREQ("This string is from private namespace (dlopened library)", ns_get_dlopened_string());

  dlclose(handle1);
}

TEST(dlext, ns_shared) {
  static const char* root_lib = "libnstest_root_not_isolated.so";
  static const char* root_lib_isolated = "libnstest_root.so";

  std::string shared_libs = g_core_shared_libs + ":" + g_public_lib;

  // create a parent namespace to use instead of the default namespace. This is
  // to make this test be independent from the configuration of the default
  // namespace.
  android_namespace_t* ns_parent =
          android_create_namespace("parent",
                                   nullptr,
                                   nullptr,
                                   ANDROID_NAMESPACE_TYPE_REGULAR,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_parent != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_parent, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_parent;

  const std::string lib_public_path = GetTestLibRoot() + "/public_namespace_libs/" + g_public_lib;
  void* handle_public = android_dlopen_ext(lib_public_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_public != nullptr) << dlerror();

  android_set_application_target_sdk_version(42U); // something > 23

  ASSERT_TRUE(android_init_anonymous_namespace(shared_libs.c_str(), nullptr)) << dlerror();

  // preload this library to the parent namespace to check if it
  // is shared later on.
  void* handle_dlopened =
          android_dlopen_ext((GetTestLibRoot() + "/private_namespace_libs/libnstest_dlopened.so").c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_dlopened != nullptr) << dlerror();

  // create two child namespaces of 'ns_parent'. One with regular, the other
  // with isolated & shared.
  android_namespace_t* ns_not_isolated =
          android_create_namespace("private",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_REGULAR,
                                   nullptr,
                                   ns_parent);
  ASSERT_TRUE(ns_not_isolated != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_not_isolated, ns_parent, g_public_lib)) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_not_isolated, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_isolated_shared =
          android_create_namespace("private_isolated_shared",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED | ANDROID_NAMESPACE_TYPE_SHARED,
                                   nullptr,
                                   ns_parent);
  ASSERT_TRUE(ns_isolated_shared != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_isolated_shared, ns_parent, g_public_lib)) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_isolated_shared, nullptr, g_core_shared_libs.c_str())) << dlerror();

  ASSERT_TRUE(android_dlopen_ext(root_lib, RTLD_NOW, &extinfo) == nullptr);
  ASSERT_STREQ("dlopen failed: library \"libnstest_root_not_isolated.so\" not found", dlerror());

  std::string lib_private_external_path =
      GetTestLibRoot() + "/private_namespace_libs_external/libnstest_private_external.so";

  // Load lib_private_external_path to the parent namespace
  // (it should remain invisible for the isolated namespaces after this)
  void* handle = android_dlopen_ext(lib_private_external_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  extinfo.library_namespace = ns_not_isolated;

  void* handle1 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();

  extinfo.library_namespace = ns_isolated_shared;

  void* handle2 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 == nullptr);
  ASSERT_MATCH(dlerror(),
               R"(dlopen failed: library "libnstest_private_external.so" not found: needed by )"
               R"(\S+libnstest_root_not_isolated.so in namespace private_isolated_shared)");

  // Check dlopen by absolute path
  handle2 = android_dlopen_ext(lib_private_external_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 == nullptr);
  ASSERT_EQ("dlopen failed: library \"" + lib_private_external_path + "\" needed"
            " or dlopened by \"" + android::base::GetExecutablePath() + "\" is not accessible"
            " for the namespace \"private_isolated_shared\"", dlerror());

  // load libnstest_root.so to shared namespace in order to check that everything is different
  // except shared libnstest_dlopened.so

  handle2 = android_dlopen_ext(root_lib_isolated, RTLD_NOW, &extinfo);

  typedef const char* (*fn_t)();
  fn_t ns_get_local_string = reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_local_string"));
  ASSERT_TRUE(ns_get_local_string != nullptr) << dlerror();
  fn_t ns_get_local_string_shared = reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_local_string"));
  ASSERT_TRUE(ns_get_local_string_shared != nullptr) << dlerror();

  ASSERT_STREQ("This string is local to root library", ns_get_local_string());
  ASSERT_STREQ("This string is local to root library", ns_get_local_string_shared());
  ASSERT_TRUE(ns_get_local_string() != ns_get_local_string_shared());

  fn_t ns_get_private_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_private_extern_string"));
  ASSERT_TRUE(ns_get_private_extern_string != nullptr) << dlerror();
  fn_t ns_get_private_extern_string_shared =
          reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_private_extern_string"));
  ASSERT_TRUE(ns_get_private_extern_string_shared() != nullptr) << dlerror();

  ASSERT_STREQ("This string is from private namespace", ns_get_private_extern_string());
  ASSERT_STREQ("This string is from private namespace", ns_get_private_extern_string_shared());
  ASSERT_TRUE(ns_get_private_extern_string() != ns_get_private_extern_string_shared());

  fn_t ns_get_public_extern_string =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_public_extern_string"));
  ASSERT_TRUE(ns_get_public_extern_string != nullptr) << dlerror();
  fn_t ns_get_public_extern_string_shared =
          reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_public_extern_string"));
  ASSERT_TRUE(ns_get_public_extern_string_shared != nullptr) << dlerror();

  ASSERT_STREQ("This string is from public namespace", ns_get_public_extern_string());
  ASSERT_STREQ("This string is from public namespace", ns_get_public_extern_string_shared());
  ASSERT_TRUE(ns_get_public_extern_string() == ns_get_public_extern_string_shared());

  fn_t ns_get_dlopened_string = reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_dlopened_string"));
  ASSERT_TRUE(ns_get_dlopened_string != nullptr) << dlerror();
  fn_t ns_get_dlopened_string_shared = reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_dlopened_string"));
  ASSERT_TRUE(ns_get_dlopened_string_shared != nullptr) << dlerror();
  const char** ns_dlopened_string = static_cast<const char**>(dlsym(handle_dlopened, "g_private_dlopened_string"));
  ASSERT_TRUE(ns_dlopened_string != nullptr) << dlerror();

  ASSERT_STREQ("This string is from private namespace (dlopened library)", ns_get_dlopened_string());
  ASSERT_STREQ("This string is from private namespace (dlopened library)", *ns_dlopened_string);
  ASSERT_STREQ("This string is from private namespace (dlopened library)", ns_get_dlopened_string_shared());
  ASSERT_TRUE(ns_get_dlopened_string() != ns_get_dlopened_string_shared());
  ASSERT_TRUE(*ns_dlopened_string == ns_get_dlopened_string_shared());

  dlclose(handle1);
  dlclose(handle2);
}

TEST(dlext, ns_shared_links_and_paths) {
  // Create parent namespace (isolated, not shared)
  android_namespace_t* ns_isolated =
          android_create_namespace("private_isolated",
                                   nullptr,
```