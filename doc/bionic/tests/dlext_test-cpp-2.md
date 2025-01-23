Response:
The user wants a summary of the functionality of the C++ source code file `bionic/tests/dlext_test.cpp`. This file seems to contain unit tests related to `android_dlopen_ext` and namespace management in the Android Bionic library.

Here's a breakdown of the tasks:

1. **Summarize the file's functionality:**  Identify the main areas of testing, which seem to revolve around dynamic linking extensions (`dlext`) and namespace isolation.
2. **Relate to Android functionality with examples:** Connect the tests to real-world Android concepts, such as how apps are isolated and how shared libraries are managed.
3. **Explain libc function implementations:** This requires identifying libc functions used in the code (like `dlopen`, `dlsym`, `dlclose`, `dlerror`, `mmap`, `mprotect`, `stat`, `memcpy`, `execve`) and briefly describing their purpose and how they might be implemented. This will be high-level since the actual implementations are complex.
4. **Explain dynamic linker functionality with SO layout and linking process:** Focus on the namespace aspects, how different namespaces are created, linked, and how the dynamic linker resolves symbols within these namespaces. A simplified SO layout example would be helpful.
5. **Provide assumptions, inputs, and outputs for logical reasoning:** For specific test cases, describe what the test is trying to achieve, what setup is involved (the "input"), and what the expected outcome (the "output") is.
6. **Give examples of common user/programming errors:**  Think about common mistakes developers might make when working with `dlopen_ext` and namespaces.
7. **Explain how Android framework/NDK reaches this code, and provide Frida hook examples:**  Describe the high-level path from an app using shared libraries to the dynamic linker and how Frida can be used to intercept these calls.
8. **Conclude with a summary of the file's functionality (part 3).** This should reiterate the main purpose of the test file.

**Mental Sandbox:**

* **Scanning the code:** The test names (e.g., `ns_isolated`, `ns_shared_dlclose`, `ns_isolated_rtld_global`) clearly indicate a focus on namespace behavior. The use of `android_dlopen_ext`, `android_create_namespace`, and `android_link_namespaces` confirms this.
* **libc functions:**  Standard dynamic linking functions (`dlopen`, `dlsym`, `dlclose`) are heavily used. Memory management functions like `mmap` and `mprotect` appear in the `ns_anonymous` test. File system functions like `stat` are also present.
* **Dynamic linker aspects:** The tests demonstrate the creation of different namespace types (isolated, shared), linking namespaces, and controlling library visibility within namespaces.
* **User errors:**  Incorrectly specifying paths, forgetting to link namespaces, or misunderstanding namespace visibility are potential errors.
* **Android framework/NDK:**  NDK uses the Bionic library for dynamic linking. The framework also uses it extensively.
* **Frida:** Frida can hook `android_dlopen_ext` or other relevant functions to inspect arguments and behavior.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果它与android的功能有关系，请做出对应的举例说明: Yes
3. 详细解释每一个libc函数的功能是如何实现的: Yes (High-level explanation)
4. 对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程: Yes (Simplified example)
5. 如果做了逻辑推理，请给出假设输入与输出: Yes
6. 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
7. 说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤: Yes
8. 用中文回复: Yes
9. 这是第3部分，共3部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. I will now generate the response by addressing each of the user's requests systematically.
这是对 `bionic/tests/dlext_test.cpp` 文件功能的归纳总结。

总的来说，`bionic/tests/dlext_test.cpp` 文件包含了一系列单元测试，用于验证 Android Bionic 库中关于动态链接扩展（`dlext`），特别是 **命名空间（namespaces）** 功能的正确性和预期行为。这些测试覆盖了命名空间的创建、链接、库的加载和卸载，以及在不同命名空间中库的可见性和隔离性。

**该文件的主要功能可以归纳为以下几点：**

1. **验证命名空间的创建和属性：** 测试了 `android_create_namespace` 函数，用于创建不同类型的命名空间，例如隔离命名空间 (`ANDROID_NAMESPACE_TYPE_ISOLATED`) 和共享命名空间 (`ANDROID_NAMESPACE_TYPE_SHARED`)，并验证了命名空间的属性是否正确设置。
2. **验证命名空间的链接：** 测试了 `android_link_namespaces` 和 `__loader_android_link_namespaces_all_libs` 函数，用于将不同的命名空间连接起来，并控制在不同命名空间中共享库的可见性。
3. **验证使用命名空间加载库 (`android_dlopen_ext`)：**  测试了 `android_dlopen_ext` 函数，该函数允许在指定的命名空间中加载共享库。测试验证了库是否在正确的命名空间中加载，并且是否能够访问该命名空间允许访问的依赖库。
4. **验证命名空间的隔离性：**  测试了在隔离的命名空间中，库是否无法访问其他命名空间（包括默认命名空间）的库，除非显式链接。
5. **验证共享命名空间的继承特性：** 测试了共享命名空间是否能够继承父命名空间的搜索路径和链接到默认命名空间的能力。
6. **验证库的卸载 (`dlclose`) 在命名空间中的行为：** 测试了在某个命名空间中 `dlclose` 一个库后，该库是否在该命名空间中以及其他相关命名空间中被正确卸载。
7. **验证 `RTLD_GLOBAL` 标志在命名空间中的作用：** 测试了使用 `RTLD_GLOBAL` 标志加载的库在命名空间及其子命名空间中的可见性。
8. **验证错误消息的准确性：** 测试了当在命名空间中加载库失败时，`dlerror()` 返回的错误消息是否能够准确地指出问题，例如无法访问的库以及相关的命名空间名称。
9. **验证 `android_init_anonymous_namespace` 的功能：** 测试了创建匿名命名空间的功能，并验证了在匿名命名空间中加载的库的行为。
10. **验证 `dlopen` 返回的句柄值：**  测试了 `dlopen` 返回的句柄值在不同 Android 版本（根据目标 SDK 版本）上的特性。

**与 Android 功能的关系及举例说明：**

这些测试直接关系到 Android 系统中 **应用隔离** 和 **动态链接库管理** 的核心功能。

* **应用隔离:** Android 使用命名空间来实现应用之间的隔离。每个应用通常运行在自己的私有命名空间中，这可以防止应用之间互相干扰，提高系统的安全性。`dlext_test.cpp` 中的测试模拟了创建和链接不同命名空间的过程，验证了这种隔离机制的有效性。例如，`TEST(dlext, ns_isolated)` 测试创建了一个隔离的命名空间，并验证了在该命名空间中只能加载允许的库，其他库无法访问。这模拟了应用只能访问其自身的库以及系统允许访问的共享库。

* **动态链接库管理:** Android 系统和应用都依赖于大量的动态链接库 (`.so` 文件）。命名空间使得可以更精细地控制哪些库在哪些上下文中可见。`dlext_test.cpp` 中的测试验证了如何使用 `android_dlopen_ext` 在特定的命名空间中加载库，以及如何通过链接命名空间来共享库。例如，`TEST(dlext, ns_shared)` 测试创建了一个共享命名空间，验证了它可以继承父命名空间的搜索路径，并且可以链接到默认命名空间，这类似于应用可以访问系统提供的共享库。

**总结**

`bionic/tests/dlext_test.cpp` 通过一系列细致的单元测试，确保了 Android Bionic 库中关于动态链接扩展和命名空间管理功能的正确性和可靠性，这对于保障 Android 系统的安全性和稳定性至关重要。 这些测试覆盖了各种场景，包括不同类型的命名空间创建、命名空间之间的链接、库的加载和卸载，以及错误处理等，为 Android 平台的动态链接机制提供了强有力的保障。

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
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
(GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   (GetTestLibRoot() + "/public_namespace_libs").c_str(),
                                   nullptr);
  ASSERT_TRUE(ns_isolated != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_isolated, nullptr, g_core_shared_libs.c_str())) << dlerror();

  // Create shared namespace with ns_isolated parent
  android_namespace_t* ns_shared =
          android_create_namespace("private_shared",
                                   nullptr,
                                   nullptr,
                                   ANDROID_NAMESPACE_TYPE_SHARED | ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   ns_isolated);
  ASSERT_TRUE(ns_shared != nullptr) << dlerror();

  // 1. Load a library in ns_shared to check that it has inherited
  // search path and the link to the default namespace.
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_shared;

  {
    void* handle = android_dlopen_ext("libnstest_private.so", RTLD_NOW, &extinfo);
    ASSERT_TRUE(handle != nullptr) << dlerror();
    const char** ns_private_extern_string = static_cast<const char**>(dlsym(handle, "g_private_extern_string"));
    ASSERT_TRUE(ns_private_extern_string != nullptr) << dlerror();
    ASSERT_STREQ("This string is from private namespace", *ns_private_extern_string);

    dlclose(handle);
  }
  // 2. Load another test library by absolute path to check that
  // it has inherited permitted_when_isolated_path
  {
    void* handle = android_dlopen_ext(
            (GetTestLibRoot() + "/public_namespace_libs/libnstest_public.so").c_str(),
            RTLD_NOW,
            &extinfo);

    ASSERT_TRUE(handle != nullptr) << dlerror();
    const char** ns_public_extern_string = static_cast<const char**>(dlsym(handle, "g_public_extern_string"));
    ASSERT_TRUE(ns_public_extern_string != nullptr) << dlerror();
    ASSERT_STREQ("This string is from public namespace", *ns_public_extern_string);

    dlclose(handle);
  }

  // 3. Check that it is still isolated.
  {
    void* handle = android_dlopen_ext(
            (GetTestLibRoot() + "/libtest_empty.so").c_str(),
            RTLD_NOW,
            &extinfo);

    ASSERT_TRUE(handle == nullptr);
  }
}

TEST(dlext, ns_shared_dlclose) {
  android_set_application_target_sdk_version(42U); // something > 23

  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr)) << dlerror();

  // preload this library to the default namespace to check if it
  // is shared later on.
  void* handle_dlopened =
          dlopen((GetTestLibRoot() + "/private_namespace_libs/libnstest_dlopened.so").c_str(), RTLD_NOW);
  ASSERT_TRUE(handle_dlopened != nullptr) << dlerror();

  android_namespace_t* ns_isolated_shared =
          android_create_namespace("private_isolated_shared",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED | ANDROID_NAMESPACE_TYPE_SHARED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_isolated_shared != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_isolated_shared, nullptr, g_core_shared_libs.c_str())) << dlerror();

  // Check if "libnstest_dlopened.so" is loaded (and the same)
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_isolated_shared;

  void* handle = android_dlopen_ext("libnstest_dlopened.so", RTLD_NOW | RTLD_NOLOAD, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  ASSERT_TRUE(handle == handle_dlopened);
  dlclose(handle);
  dlclose(handle_dlopened);

  // And now check that the library cannot be found by soname (and is no longer loaded)
  handle = android_dlopen_ext("libnstest_dlopened.so", RTLD_NOW | RTLD_NOLOAD, &extinfo);
  ASSERT_TRUE(handle == nullptr)
      << "Error: libnstest_dlopened.so is still accessible in shared namespace";

  handle = android_dlopen_ext((GetTestLibRoot() + "/private_namespace_libs/libnstest_dlopened.so").c_str(),
                              RTLD_NOW | RTLD_NOLOAD, &extinfo);
  ASSERT_TRUE(handle == nullptr)
      << "Error: libnstest_dlopened.so is still accessible in shared namespace";

  handle = dlopen("libnstest_dlopened.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr)
      << "Error: libnstest_dlopened.so is still accessible in default namespace";

  handle = dlopen((GetTestLibRoot() + "/private_namespace_libs/libnstest_dlopened.so").c_str(),
                  RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr)
      << "Error: libnstest_dlopened.so is still accessible in default namespace";

  // Now lets see if the soinfo area gets reused in the wrong way:
  // load a library to default namespace.
  const std::string lib_public_path = GetTestLibRoot() + "/public_namespace_libs/" + g_public_lib;
  void* handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle_public != nullptr) << dlerror();

  // try to find it in shared namespace
  handle = android_dlopen_ext(g_public_lib, RTLD_NOW | RTLD_NOLOAD, &extinfo);
  ASSERT_TRUE(handle == nullptr)
      << "Error: " << g_public_lib << " is accessible in shared namespace";
}

TEST(dlext, ns_isolated_rtld_global) {
  static const char* root_lib = "libnstest_root.so";
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  const std::string lib_public_path = GetTestLibRoot() + "/public_namespace_libs";

  android_namespace_t* ns1 =
          android_create_namespace("isolated1",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   lib_public_path.c_str(),
                                   nullptr);
  ASSERT_TRUE(ns1 != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns1, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns2 =
          android_create_namespace("isolated2",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   lib_public_path.c_str(),
                                   nullptr);
  ASSERT_TRUE(ns2 != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns2, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns1;

  void* handle_global = android_dlopen_ext((lib_public_path + "/" + g_public_lib).c_str(),
                                           RTLD_GLOBAL,
                                           &extinfo);

  ASSERT_TRUE(handle_global != nullptr) << dlerror();

  android_namespace_t* ns1_child =
          android_create_namespace("isolated1_child",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   ns1);

  ASSERT_TRUE(ns1_child != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns1_child, nullptr, g_core_shared_libs.c_str())) << dlerror();

  // Now - only ns1 and ns1 child should be able to dlopen root_lib
  // attempt to use ns2 should result in dlerror()

  // Check ns1_child first.
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns1_child;

  void* handle1 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();

  // now ns1
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns1;

  handle1 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();

  // and ns2 should fail
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns2;

  handle1 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle1 == nullptr);
  ASSERT_MATCH(
      dlerror(),
      R"(dlopen failed: library "libnstest_public.so" not found: needed by \S+libnstest_root.so)"
      R"( in namespace isolated2)");
}

TEST(dlext, ns_inaccessible_error_message) {
  // We set up 2 namespaces (a and b) and link a->b with a shared library
  // libtestshared.so. Then try to dlopen different library with the same
  // name from in namespace a. Note that library should not be accessible
  // in either namespace but since it's soname is in the list of shared libs
  // the linker will attempt to find it in linked namespace.
  //
  // Check the error message and make sure it mentions correct namespace name.
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  android_namespace_t* ns_a =
          android_create_namespace("ns_a",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_a != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_a, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_b =
          android_create_namespace("ns_b",
                                   nullptr,
                                   GetTestLibRoot().c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_b != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_b, nullptr, g_core_shared_libs.c_str())) << dlerror();

  ASSERT_TRUE(android_link_namespaces(ns_a, ns_b, "libtestshared.so")) << dlerror();

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_a;

  std::string library_path = GetTestLibRoot() + "/inaccessible_libs/libtestshared.so";

  void* handle = android_dlopen_ext(library_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror =
      android::base::StringPrintf("dlopen failed: library \"%s\" needed or dlopened by \"%s\""
                                  " is not accessible for the namespace \"ns_a\"",
                                  library_path.c_str(),
                                  android::base::GetExecutablePath().c_str());
  ASSERT_EQ(expected_dlerror, dlerror());
}

extern "C" bool __loader_android_link_namespaces_all_libs(android_namespace_t* namespace_from,
                                                          android_namespace_t* namespace_to);

TEST(dlext, ns_link_namespaces_invalid_arguments) {
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  android_namespace_t* ns =
          android_create_namespace("private",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_REGULAR,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns != nullptr) << dlerror();

  // Test android_link_namespaces()
  ASSERT_FALSE(android_link_namespaces(nullptr, nullptr, "libc.so"));
  ASSERT_STREQ("android_link_namespaces failed: error linking namespaces: namespace_from is null.",
               dlerror());

  ASSERT_FALSE(android_link_namespaces(ns, nullptr, nullptr));
  ASSERT_STREQ("android_link_namespaces failed: "
               "error linking namespaces \"private\"->\"(default)\": "
               "the list of shared libraries is empty.", dlerror());

  ASSERT_FALSE(android_link_namespaces(ns, nullptr, ""));
  ASSERT_STREQ("android_link_namespaces failed: "
               "error linking namespaces \"private\"->\"(default)\": "
               "the list of shared libraries is empty.", dlerror());

  // Test __loader_android_link_namespaces_all_libs()
  ASSERT_FALSE(__loader_android_link_namespaces_all_libs(nullptr, nullptr));
  ASSERT_STREQ("android_link_namespaces_all_libs failed: "
               "error linking namespaces: namespace_from is null.", dlerror());

  ASSERT_FALSE(__loader_android_link_namespaces_all_libs(nullptr, ns));
  ASSERT_STREQ("android_link_namespaces_all_libs failed: "
               "error linking namespaces: namespace_from is null.", dlerror());

  ASSERT_FALSE(__loader_android_link_namespaces_all_libs(ns, nullptr));
  ASSERT_STREQ("android_link_namespaces_all_libs failed: "
               "error linking namespaces: namespace_to is null.", dlerror());
}

TEST(dlext, ns_allow_all_shared_libs) {
  ASSERT_TRUE(android_init_anonymous_namespace(g_core_shared_libs.c_str(), nullptr));

  android_namespace_t* ns_a =
          android_create_namespace("ns_a",
                                   nullptr,
                                   (GetTestLibRoot() + "/ns_a").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_a != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_a, nullptr, g_core_shared_libs.c_str())) << dlerror();

  android_namespace_t* ns_b =
          android_create_namespace("ns_b",
                                   nullptr,
                                   (GetTestLibRoot() + "/ns_b").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns_b != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns_b, nullptr, g_core_shared_libs.c_str())) << dlerror();

  ASSERT_TRUE(android_link_namespaces(ns_b, ns_a, "libnstest_ns_a_public1.so")) << dlerror();
  ASSERT_TRUE(__loader_android_link_namespaces_all_libs(ns_a, ns_b)) << dlerror();

  // Load libs with android_dlopen_ext() from namespace b
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns_b;

  void* ns_b_handle1 = android_dlopen_ext("libnstest_ns_a_public1.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_b_handle1 != nullptr) << dlerror();

  void* ns_b_handle1_internal =
      android_dlopen_ext("libnstest_ns_a_public1_internal.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_b_handle1_internal == nullptr);

  void* ns_b_handle2 = android_dlopen_ext("libnstest_ns_b_public2.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_b_handle2 != nullptr) << dlerror();

  void* ns_b_handle3 = android_dlopen_ext("libnstest_ns_b_public3.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_b_handle3 != nullptr) << dlerror();

  // Load libs with android_dlopen_ext() from namespace a
  extinfo.library_namespace = ns_a;

  void* ns_a_handle1 = android_dlopen_ext("libnstest_ns_a_public1.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_a_handle1 != nullptr) << dlerror();

  void* ns_a_handle1_internal =
      android_dlopen_ext("libnstest_ns_a_public1_internal.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_a_handle1_internal != nullptr) << dlerror();

  void* ns_a_handle2 = android_dlopen_ext("libnstest_ns_b_public2.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_a_handle2 != nullptr) << dlerror();

  void* ns_a_handle3 = android_dlopen_ext("libnstest_ns_b_public3.so", RTLD_NOW, &extinfo);
  ASSERT_TRUE(ns_a_handle3 != nullptr) << dlerror();

  // Compare the dlopen handle
  ASSERT_EQ(ns_b_handle1, ns_a_handle1);
  ASSERT_EQ(ns_b_handle2, ns_a_handle2);
  ASSERT_EQ(ns_b_handle3, ns_a_handle3);

  // Close libs
  dlclose(ns_b_handle1);
  dlclose(ns_b_handle2);
  dlclose(ns_b_handle3);

  dlclose(ns_a_handle1);
  dlclose(ns_a_handle1_internal);
  dlclose(ns_a_handle2);
  dlclose(ns_a_handle3);
}

static inline int MapPflagsToProtFlags(uint32_t flags) {
  int prot_flags = 0;
  if (PF_X & flags) prot_flags |= PROT_EXEC;
  if (PF_W & flags) prot_flags |= PROT_WRITE;
  if (PF_R & flags) prot_flags |= PROT_READ;
  return prot_flags;
}

TEST(dlext, ns_anonymous) {
  static const char* root_lib = "libnstest_root.so";
  std::string shared_libs = g_core_shared_libs + ":" + g_public_lib;

  const std::string lib_public_path = GetTestLibRoot() + "/public_namespace_libs/" + g_public_lib;
  void* handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);

  ASSERT_TRUE(handle_public != nullptr) << dlerror();

  ASSERT_TRUE(
          android_init_anonymous_namespace(shared_libs.c_str(),
                                           (GetTestLibRoot() + "/private_namespace_libs").c_str())
      ) << dlerror();

  android_namespace_t* ns =
          android_create_namespace("private",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_REGULAR,
                                   nullptr,
                                   nullptr);

  ASSERT_TRUE(ns != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns, nullptr, shared_libs.c_str())) << dlerror();

  std::string private_library_absolute_path = GetTestLibRoot() + "/private_namespace_libs/" + root_lib;

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns;

  // we are going to copy this library to anonymous mmap and call the copy of ns_get_dlopened_string
  void* handle = android_dlopen_ext(private_library_absolute_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  uintptr_t ns_get_dlopened_string_addr =
      reinterpret_cast<uintptr_t>(dlsym(handle, "ns_get_dlopened_string"));
  ASSERT_TRUE(ns_get_dlopened_string_addr != 0) << dlerror();
  typedef const char* (*fn_t)();
  fn_t ns_get_dlopened_string_private = reinterpret_cast<fn_t>(ns_get_dlopened_string_addr);

  Dl_info private_library_info;
  ASSERT_NE(dladdr(reinterpret_cast<void*>(ns_get_dlopened_string_addr), &private_library_info), 0)
      << dlerror();
  std::vector<map_record> maps_to_copy;
  bool has_executable_segment = false;
  uintptr_t addr_start = 0;
  uintptr_t addr_end = 0;
  std::tuple dl_iterate_arg = {&private_library_info, &maps_to_copy, &has_executable_segment,
                               &addr_start, &addr_end};
  ASSERT_EQ(
      1, dl_iterate_phdr(
             [](dl_phdr_info* info, size_t /*size*/, void* data) -> int {
               auto [private_library_info, maps_to_copy, has_executable_segment, addr_start,
                     addr_end] = *reinterpret_cast<decltype(dl_iterate_arg)*>(data);
               if (info->dlpi_addr != reinterpret_cast<ElfW(Addr)>(private_library_info->dli_fbase))
                 return 0;

               for (size_t i = 0; i < info->dlpi_phnum; ++i) {
                 const ElfW(Phdr)* phdr = info->dlpi_phdr + i;
                 if (phdr->p_type != PT_LOAD) continue;
                 *has_executable_segment |= phdr->p_flags & PF_X;
                 uintptr_t mapping_start = page_start(info->dlpi_addr + phdr->p_vaddr);
                 uintptr_t mapping_end = page_end(info->dlpi_addr + phdr->p_vaddr + phdr->p_memsz);
                 if (*addr_start == 0 || mapping_start < *addr_start) *addr_start = mapping_start;
                 if (*addr_end == 0 || mapping_end > *addr_end) *addr_end = mapping_end;
                 maps_to_copy->push_back({
                     .addr_start = mapping_start,
                     .addr_end = mapping_end,
                     .perms = MapPflagsToProtFlags(phdr->p_flags),
                 });
               }
               return 1;
             },
             &dl_iterate_arg));

  // Some validity checks.
  ASSERT_NE(maps_to_copy.size(), 0u);
  ASSERT_TRUE(addr_start > 0);
  ASSERT_TRUE(addr_end > 0);
  ASSERT_TRUE(ns_get_dlopened_string_addr > addr_start);
  ASSERT_TRUE(ns_get_dlopened_string_addr < addr_end);

  if (!has_executable_segment) {
    // For some natively bridged environments this code might be missing
    // the executable flag. This is because the guest code is not supposed
    // to be executed directly and making it non-executable is more secure.
    // In this case we assume the segment with the function is executable.
    for (auto& rec : maps_to_copy) {
      if (ns_get_dlopened_string_addr >= rec.addr_start &&
          ns_get_dlopened_string_addr < rec.addr_end) {
        ASSERT_TRUE((rec.perms & PROT_WRITE) == 0);
        rec.perms |= PROT_EXEC;
        break;
      }
    }
  }

  // copy
  uintptr_t reserved_addr = reinterpret_cast<uintptr_t>(mmap(nullptr, addr_end - addr_start,
                                                             PROT_NONE, MAP_ANON | MAP_PRIVATE,
                                                             -1, 0));
  ASSERT_TRUE(reinterpret_cast<void*>(reserved_addr) != MAP_FAILED);

  struct stat file_stat;
  int ret = TEMP_FAILURE_RETRY(stat(private_library_absolute_path.c_str(), &file_stat));
  ASSERT_EQ(ret, 0) << "Failed to stat library";
  size_t file_size = file_stat.st_size;

  {
    // Disable MTE while copying the PROT_MTE-protected global variables from
    // the existing mappings. We don't really care about turning on PROT_MTE for
    // the new copy of the mappings, as this isn't the behaviour under test and
    // tags will be ignored. This only applies for MTE-enabled devices.
    ScopedDisableMTE disable_mte_for_copying_global_variables;
    for (const auto& rec : maps_to_copy) {
      uintptr_t offset = rec.addr_start - addr_start;
      size_t size = rec.addr_end - rec.addr_start;
      void* addr = reinterpret_cast<void*>(reserved_addr + offset);
      void* map =
          mmap(addr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
      ASSERT_TRUE(map != MAP_FAILED);
      // Attempting the below memcpy from a portion of the map that is off the end of
      // the backing file will cause the kernel to throw a SIGBUS
      size_t _size =
          ::android::procinfo::MappedFileSize(rec.addr_start, rec.addr_end, rec.offset, file_size);
      memcpy(map, reinterpret_cast<void*>(rec.addr_start), _size);
      mprotect(map, size, rec.perms);
    }
  }

  // call the function copy
  uintptr_t ns_get_dlopened_string_offset  = ns_get_dlopened_string_addr - addr_start;
  fn_t ns_get_dlopened_string_anon = reinterpret_cast<fn_t>(reserved_addr + ns_get_dlopened_string_offset);
  ASSERT_STREQ("This string is from private namespace (dlopened library)",
               ns_get_dlopened_string_anon());

  // They should belong to different namespaces (private and anonymous)
  ASSERT_STREQ("This string is from private namespace (dlopened library)",
               ns_get_dlopened_string_private());

  ASSERT_TRUE(ns_get_dlopened_string_anon() != ns_get_dlopened_string_private());
}

TEST(dlext, ns_hidden_child) {
  ExecTestHelper eth;

  std::string helper = GetTestLibRoot() + "/ns_hidden_child_helper";
  std::string app_ns_dir = GetTestLibRoot() + "/ns_hidden_child_app";
  eth.SetArgs({ helper.c_str(), app_ns_dir.c_str(), nullptr });

  // Add the main libns_hidden_child_*.so libraries to the search path of the default namespace.
  std::string env = "LD_LIBRARY_PATH=" + GetTestLibRoot();
  eth.SetEnv({ env.c_str(), nullptr });

  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0,
          "public_function is non-null\n"
          "internal_function is null\n");
}

TEST(dlext, dlopen_handle_value_platform) {
  void* handle = dlopen("libtest_dlsym_from_this.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE((reinterpret_cast<uintptr_t>(handle) & 1) != 0)
          << "dlopen should return odd value for the handle";
  dlclose(handle);
}

TEST(dlext, dlopen_handle_value_app_compat) {
  android_set_application_target_sdk_version(23);
  void* handle = dlopen("libtest_dlsym_from_this.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(reinterpret_cast<uintptr_t>(handle) % sizeof(uintptr_t) == 0)
          << "dlopen should return valid pointer";
  dlclose(handle);
}
```