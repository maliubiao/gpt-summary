Response:
Let's break down the thought process for generating the comprehensive analysis of the `system_properties_test.cpp` file.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ test file and explain its functionality, its relationship to Android, the inner workings of relevant libc functions, dynamic linking aspects, potential errors, and how to debug it. The request specifically asks for a detailed explanation with examples and even a Frida hook demonstration.

**2. Initial Skim and High-Level Overview:**

First, I quickly scanned the code to get a general idea of what it does. Keywords like "SystemPropertiesTest," "__system_property_add," "__system_property_get," "mount," "umount," and the inclusion of `<system_properties/system_properties.h>` immediately suggest that this code tests the system property functionality in Android. The use of `gtest` confirms it's a unit test.

**3. Identifying Key Functionality:**

I then focused on the `TEST` macros to identify the specific test cases. Each test name gives a strong hint about its purpose:

* `__system_property_add`: Tests adding system properties.
* `__system_property_add_appcompat`: Tests adding properties related to app compatibility overrides.
* `__system_property_update`: Tests updating existing system properties.
* `fill`: Tests adding a large number of properties to check capacity.
* `__system_property_foreach`: Tests iterating through all system properties.
* `__system_property_find_nth`: Tests finding the nth system property.
* `fill_hierarchical`:  Likely tests adding properties with a structured naming convention.
* `errors`: Tests error handling scenarios.
* `__system_property_serial`: Tests the serial number associated with a property.
* `__system_property_wait_any`: Tests waiting for any property to change.
* `__system_property_wait`: Tests waiting for a specific property to change.
* `read_only`: Tests attempting to modify system properties in a read-only context.
* `__system_property_extra_long_read_only`: Tests reading properties with different lengths, including those exceeding the legacy read buffer size.
* `__system_property_extra_long_read_only_too_long`: Tests adding properties that are excessively long.
* `__system_property_reload_no_op`: Tests reloading system properties when no changes are made.
* `__system_property_reload_invalid`: Tests reloading with an invalid property info file.
* `__system_property_reload_valid`: Tests reloading system properties from a different directory.

**4. Analyzing Individual Test Cases and Connecting to Android:**

For each test case, I considered:

* **What it's testing:** The specific system property function or behavior.
* **How it relates to Android:**  System properties are fundamental to Android's configuration and runtime behavior. I provided examples like `ro.build.version.sdk` and `persist.sys.language`.
* **Relevant libc functions:** I identified the core functions being tested (`__system_property_add`, `__system_property_get`, `__system_property_update`, `__system_property_find`, `__system_property_foreach`, etc.) and explained their purpose within the context of the test. I also noted other standard C library functions used (e.g., `ASSERT_EQ`, `ASSERT_STREQ`, `snprintf`, `memset`, `strcmp`, `mount`, `umount2`, `getuid`, `usleep`).
* **Dynamic Linking (if applicable):**  For tests like `__system_property_reload_valid`, which involve mounting and potentially loading different property sets, I considered the dynamic linker's role in accessing these properties. While the test itself doesn't directly manipulate the linker, it tests scenarios that impact how the linker retrieves system properties. I provided a simplified SO layout example and explained the linking process conceptually.
* **Assumptions and Outputs:** For tests involving adding or updating properties, I implicitly assumed valid inputs and described the expected outcome (property being added/updated, return codes). For error cases, I highlighted the expected negative return values.
* **Common Errors:** I thought about typical mistakes developers might make when working with system properties, like exceeding the length limits or trying to modify read-only properties.
* **Android Framework/NDK Path:** I outlined the typical path from the Android framework (Java layer) or NDK (C/C++ layer) down to these bionic system property functions. This involved steps like `System.getProperty()`, JNI calls, and the eventual invocation of the bionic functions.
* **Frida Hooking:** I provided practical Frida examples demonstrating how to intercept calls to key system property functions and inspect their arguments and return values.

**5. Addressing the "libc function implementation" Request:**

This required explaining the *conceptual* implementation of the core system property functions. Since the actual implementation details are complex and involve kernel interaction, I focused on the high-level mechanisms:

* **Shared Memory:**  The central idea is a shared memory region accessible to all processes.
* **Data Structures:**  Explaining the likely internal structures (arrays or hash tables) to store properties.
* **Synchronization:**  Mentioning the need for locking mechanisms to handle concurrent access.
* **Persistence:**  Explaining how properties are loaded from files on disk during boot.

**6. Dynamic Linker Details:**

I explained that the dynamic linker (`linker64` or `linker`) is responsible for loading shared libraries and resolving symbols. I then connected this to system properties by explaining that libraries often use system properties for configuration and that the linker itself might need to access them. The SO layout was a simplified illustration of a typical dynamically linked executable and its dependencies.

**7. Structuring the Response:**

I organized the information logically, using clear headings and bullet points to make it easy to read and understand. I started with a general overview, then delved into specifics for each test case, addressed the libc and dynamic linker aspects, and finally covered error scenarios, the Android framework path, and Frida hooking.

**8. Language and Tone:**

I used clear and concise language, avoiding overly technical jargon where possible. The tone was informative and explanatory.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on the test cases. **Correction:** Realized the importance of explaining the underlying concepts (libc implementation, dynamic linking) and connecting the tests to the broader Android ecosystem.
* **Initial thought:**  Provide low-level implementation details of libc functions. **Correction:** Shifted to a higher-level, conceptual explanation due to the complexity and kernel involvement.
* **Initial Frida example:**  A very basic hook. **Refinement:**  Added more specific examples for different functions and included explanations of the code.
* **Dynamic linking explanation:** Initially too brief. **Refinement:** Expanded on the linker's role and provided a basic SO layout.

By following these steps and continually refining the analysis, I aimed to provide a comprehensive and helpful answer to the user's request.
这个文件 `bionic/tests/system_properties_test.cpp` 是 Android Bionic 库中的一个单元测试文件，专门用于测试系统属性（system properties）的相关功能。系统属性是 Android 系统中一种全局的键值对存储机制，用于配置和传递系统信息。

**文件功能列表：**

1. **测试系统属性的添加 (`__system_property_add`)**:
   - 验证是否能够成功添加新的系统属性。
   - 测试添加不同长度的属性名和属性值，包括接近和超过最大长度限制的情况。
   - 检查添加后能否正确读取到属性值。

2. **测试系统属性的添加 (兼容性覆盖) (`__system_property_add_appcompat`)**:
   - 测试在具有兼容性覆盖机制的情况下添加属性的行为。
   - 模拟通过挂载 (`mount`) 不同的属性目录来覆盖现有属性。
   - 验证在覆盖后，读取到的属性值是否来自覆盖的目录。

3. **测试系统属性的更新 (`__system_property_update`)**:
   - 验证是否能够成功更新已存在的系统属性的值。
   - 检查更新后，能否读取到新的属性值。

4. **测试系统属性的填充 (`fill`)**:
   - 测试能否添加大量的系统属性，以验证系统属性服务的容量和性能。
   - 添加后，验证是否能够正确读取所有添加的属性。

5. **测试系统属性的遍历 (`__system_property_foreach`)**:
   - 验证是否能够通过回调函数遍历所有已注册的系统属性。
   - 测试回调函数是否被正确调用，并能访问到每个属性的信息。

6. **测试查找指定索引的系统属性 (`__system_property_find_nth`)**:
   - 验证是否能够根据索引找到对应的系统属性。
   - 检查找到的属性的名称和值是否正确。

7. **测试分层填充系统属性 (`fill_hierarchical`)**:
   - 类似于 `fill` 测试，但使用具有分层命名结构的属性名（例如 `property_x.y.z`）。
   - 用于测试在更复杂的命名场景下，系统属性服务的处理能力。

8. **测试系统属性的错误处理 (`errors`)**:
   - 测试在尝试添加或更新属性时，如果提供无效的参数（例如，过长的值或空指针），系统是否能正确处理并返回错误。

9. **测试系统属性的序列号 (`__system_property_serial`)**:
   - 验证每次修改系统属性后，其关联的序列号是否会发生变化。
   - 序列号可用于跟踪属性的变更。

10. **测试等待任意系统属性变化 (`__system_property_wait_any`)**:
    - 验证当任何系统属性发生变化时，调用 `__system_property_wait_any` 的线程是否会被唤醒。

11. **测试等待特定系统属性变化 (`__system_property_wait`)**:
    - 验证当特定的系统属性发生变化时，调用 `__system_property_wait` 的线程是否会被唤醒。

12. **测试只读系统属性的写入保护 (`read_only`)**:
    - 尝试修改只读的系统属性，验证是否会导致程序崩溃（预期行为）。

13. **测试读取超长只读系统属性 (`__system_property_extra_long_read_only`)**:
    - 测试读取不同长度的只读属性，包括超过传统读取缓冲区大小的属性。
    - 验证使用 `__system_property_read_callback` 是否能正确读取超长属性。

14. **测试添加过长的只读系统属性 (`__system_property_extra_long_read_only_too_long`)**:
    - 尝试添加长度超过系统限制的只读属性，验证是否会失败。

15. **测试系统属性的重载 (无操作) (`__system_property_reload_no_op`)**:
    - 测试在没有实际修改底层属性文件的情况下，调用重载函数是否不会产生副作用。

16. **测试系统属性的重载 (无效状态) (`__system_property_reload_invalid`)**:
    - 测试在属性信息文件无效的情况下，调用重载函数是否能正确处理并返回错误。

17. **测试系统属性的重载 (有效状态) (`__system_property_reload_valid`)**:
    - 模拟修改底层的系统属性文件，然后调用重载函数，验证系统属性是否能够从新的文件中加载。

**与 Android 功能的关系及举例说明：**

系统属性在 Android 系统中扮演着至关重要的角色，用于配置和控制系统的行为。

* **版本信息:** 例如 `ro.build.version.sdk` 存储了 Android SDK 的版本号。
* **硬件信息:** 例如 `ro.product.model` 存储了设备型号。
* **系统配置:** 例如 `persist.sys.language` 存储了用户设置的语言。
* **功能开关:** 例如某些属性可以控制特定功能的启用或禁用。
* **进程间通信:** 系统属性可以作为不同进程之间传递信息的媒介。

**举例说明：**

* 当 Android 系统启动时，`init` 进程会读取 `/system/build.prop` 等文件，并将其中的属性加载到系统属性服务中。这些属性会被 framework 和 native 代码使用。
* Android framework 中的 `android.os.SystemProperties` 类允许 Java 代码访问系统属性。例如，应用可以通过 `SystemProperties.get("ro.build.version.sdk")` 获取 SDK 版本。
* Native 代码可以使用 `__system_property_get` 函数获取系统属性。例如，SurfaceFlinger 服务会读取一些系统属性来配置显示相关的参数。

**详细解释每一个 libc 函数的功能是如何实现的:**

以下是一些关键的 libc 函数及其简要的实现原理（由于 bionic 是闭源的，这里是基于推测和公开信息的理解）：

1. **`__system_property_add(const char *name, size_t namelen, const char *value, size_t valuelen)`**:
   - **功能:** 向系统属性服务添加一个新的属性。
   - **实现:**
     - 将属性名和属性值以及它们的长度信息传递给系统属性服务进程（通常是 `init` 进程）。
     - 系统属性服务进程接收到请求后，会进行权限检查，确保调用者有权限设置该属性。
     - 如果权限允许，系统属性服务会将属性名和值存储在一个共享内存区域中。
     - 为了保证并发安全，通常会使用锁机制来保护共享内存的访问。
     - 系统属性服务可能会将属性信息持久化到磁盘上的某个文件中，以便重启后恢复。

2. **`__system_property_get(const char *name, char *value)`**:
   - **功能:** 获取指定名称的系统属性的值。
   - **实现:**
     - 将要查询的属性名传递给系统属性服务进程。
     - 系统属性服务进程在共享内存区域中查找该属性。
     - 如果找到该属性，将其值复制到提供的 `value` 缓冲区中。
     - 如果未找到，`value` 缓冲区的内容可能保持不变或者被设置为一个默认值（通常是空字符串）。
     - 返回值通常是属性值的长度。

3. **`__system_property_update(const prop_info *pi, const char *value, size_t len)`**:
   - **功能:** 更新已存在的系统属性的值。`prop_info` 是指向属性元数据的指针。
   - **实现:**
     - 类似于 `__system_property_add`，但操作的是已存在的属性。
     - 系统属性服务进程接收到更新请求后，会找到对应的属性项，并更新其值。
     - 同样需要进行权限检查和并发控制。

4. **`__system_property_find(const char *name)`**:
   - **功能:** 查找指定名称的系统属性，返回一个指向 `prop_info` 结构的指针，如果未找到则返回 `nullptr`。
   - **实现:**
     - 系统属性服务进程在共享内存区域中搜索匹配的属性名。
     - 如果找到，返回指向该属性元数据的指针。这个元数据包含了属性的各种信息，例如值的偏移量、长度等。

5. **`__system_property_foreach(void (*propfn)(const prop_info *pi, void *cookie), void *cookie)`**:
   - **功能:** 遍历所有已注册的系统属性，并对每个属性调用指定的回调函数 `propfn`。
   - **实现:**
     - 系统属性服务进程会遍历其存储属性的内部数据结构（可能是一个数组或链表）。
     - 对于每个属性，调用 `propfn` 函数，并将指向该属性 `prop_info` 的指针和用户提供的 `cookie` 传递给它。

6. **`__system_property_read(const prop_info *pi, char *name, char *value)`**:
   - **功能:** 根据 `prop_info` 指针读取属性的名称和值。
   - **实现:**
     - 系统属性服务进程根据 `prop_info` 中存储的偏移量和长度信息，从共享内存中读取属性的名称和值，并将它们复制到提供的缓冲区中。

7. **`__system_property_serial(const prop_info *pi)`**:
   - **功能:** 获取指定属性的序列号。
   - **实现:**
     - 每个属性通常会关联一个序列号，用于跟踪属性的修改。每次属性被更新时，序列号会递增。
     - 系统属性服务进程从 `prop_info` 结构中读取并返回该序列号。

8. **`__system_property_wait_any(unsigned serial)`**:
   - **功能:** 等待任意系统属性的序列号发生变化（大于给定的 `serial`）。
   - **实现:**
     - 调用该函数的线程会进入休眠状态。
     - 系统属性服务进程在有属性被修改后，会检查是否有线程在等待 `wait_any`。
     - 如果有，并且新属性的序列号大于等待的序列号，则唤醒等待的线程。

9. **`__system_property_wait(const prop_info *pi, unsigned serial, unsigned *new_serial, unsigned *timed_out)`**:
   - **功能:** 等待特定属性的序列号发生变化。
   - **实现:**
     - 类似于 `__system_property_wait_any`，但只关注指定的属性。
     - 当指定属性的序列号发生变化时，唤醒等待的线程，并将新的序列号写入 `new_serial`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然这个测试文件主要关注系统属性服务本身，但某些操作，例如系统属性的重载 (`__system_properties_zygote_reload`)，可能会间接地影响到动态链接器。动态链接器在启动时或运行时可能会读取某些系统属性来配置其行为。

**SO 布局样本:**

```
# 假设一个简单的可执行文件 `app` 依赖于一个共享库 `libfoo.so`

app:
  - .text   (代码段)
  - .rodata (只读数据段，可能包含字符串常量等)
  - .data   (可读写数据段)
  - .bss    (未初始化数据段)
  - .dynamic (动态链接信息)
  - .dynsym  (动态符号表)
  - .dynstr  (动态字符串表)
  - NEEDED libfoo.so  (依赖的共享库)

libfoo.so:
  - .text
  - .rodata
  - .data
  - .bss
  - .dynamic
  - .dynsym
  - .dynstr
```

**链接的处理过程:**

1. **加载器 (Loader):** 当系统启动或 `fork` 一个新进程时，内核会调用加载器（对于 Android 而言，它是动态链接器本身，通常是 `/system/bin/linker64` 或 `/system/bin/linker`）。
2. **解析 ELF 头:** 动态链接器首先解析可执行文件（例如 `app`）的 ELF 头，获取程序的入口点、程序头表等信息。
3. **加载依赖库:** 动态链接器读取可执行文件的 `.dynamic` 段，找到 `NEEDED` 条目，列出了所有依赖的共享库（例如 `libfoo.so`）。
4. **查找共享库:** 动态链接器根据预设的路径（例如 `/system/lib64`, `/vendor/lib64` 等）查找这些共享库。
5. **加载共享库:** 找到共享库后，动态链接器将其加载到内存中。
6. **符号解析 (Symbol Resolution):** 动态链接器遍历可执行文件和所有已加载共享库的动态符号表 (`.dynsym`)，解析未定义的符号引用。例如，如果 `app` 中调用了 `libfoo.so` 中的函数 `foo()`, 动态链接器会将 `app` 中对 `foo()` 的引用绑定到 `libfoo.so` 中 `foo()` 的地址。
7. **重定位 (Relocation):** 由于共享库被加载到内存的哪个地址是不确定的（地址空间布局随机化 ASLR），动态链接器需要修改代码和数据段中与地址相关的部分，使其指向正确的内存位置。
8. **执行:** 所有依赖库加载和符号解析完成后，动态链接器会将控制权交给可执行文件的入口点，程序开始执行。

**系统属性与动态链接:**

动态链接器本身可能会读取一些系统属性来配置其行为，例如：

* **`ro.debuggable`**: 判断是否是可调试版本，影响链接器的某些调试行为。
* **`ro.dalvik.vm.isa.*.oat-file`**:  指示预编译的 oat 文件的路径，动态链接器需要加载这些文件来执行 Java 代码相关的 native 库。

当调用 `__system_properties_zygote_reload` 时，如果加载了新的系统属性配置，可能会影响到后续加载的共享库的行为，或者在某些情况下，如果链接器自身依赖的属性发生了变化，也可能会触发链接器的一些内部重载机制（虽然这种情况比较少见）。

**如果做了逻辑推理，请给出假设输入与输出:**

在测试 `__system_property_add` 的例子中：

**假设输入:**

```c++
const char* name = "my.test.property";
size_t namelen = strlen(name);
const char* value = "test_value";
size_t valuelen = strlen(value);
```

**预期输出:**

```c++
ASSERT_EQ(0, system_properties.Add(name, namelen, value, valuelen)); // 成功添加，返回 0
char propvalue[PROP_VALUE_MAX];
ASSERT_EQ(valuelen, system_properties.Get(name, propvalue)); // 获取属性值，返回值的长度
ASSERT_STREQ(propvalue, value); // 获取到的值与设置的值一致
```

在测试 `__system_property_get` 的例子中：

**假设输入:** 系统中已存在属性 `ro.build.version.sdk` 的值为 `33`。

**预期输出:**

```c++
char propvalue[PROP_VALUE_MAX];
int len = system_properties.Get("ro.build.version.sdk", propvalue);
ASSERT_GT(len, 0); // 返回值大于 0，表示成功获取
ASSERT_STREQ(propvalue, "33"); // 获取到的值是 "33"
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **属性名或属性值过长:**
   ```c++
   char long_name[PROP_NAME_MAX + 10]; // 超出最大长度
   memset(long_name, 'a', sizeof(long_name) - 1);
   long_name[sizeof(long_name) - 1] = '\0';
   system_properties.Add(long_name, strlen(long_name), "value", 5); // 可能返回错误
   ```

2. **尝试修改只读属性:**
   ```c++
   // 假设 ro.build.version.sdk 是只读属性
   system_properties.Add("ro.build.version.sdk", strlen("ro.build.version.sdk"), "new_value", strlen("new_value")); // 通常会失败
   ```

3. **读取不存在的属性:**
   ```c++
   char propvalue[PROP_VALUE_MAX];
   int len = system_properties.Get("non.existent.property", propvalue);
   ASSERT_EQ(0, len); // 返回 0，表示未找到
   ASSERT_STREQ(propvalue, ""); // 缓冲区内容可能为空字符串
   ```

4. **缓冲区溢出 (在旧版本或某些边缘情况下):**  虽然现代的 `__system_property_get` 通常会处理缓冲区大小，但在早期的实现或者错误的使用方式下，可能会导致缓冲区溢出。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Bionic 系统属性的路径：**

1. **Java 代码 (Android Framework):**
   - Android Framework 中的 Java 代码通常使用 `android.os.SystemProperties` 类来访问系统属性。例如：
     ```java
     String sdkVersion = SystemProperties.get("ro.build.version.sdk");
     ```

2. **JNI 调用:**
   - `SystemProperties.get()` 等方法最终会通过 JNI (Java Native Interface) 调用到 Native 代码。在 Android 源代码中，你可以找到类似 `android_os_SystemProperties_get` 这样的 JNI 函数。

3. **Native 代码 (libandroid_runtime.so 或其他 Framework Native 库):**
   - 这些 JNI 函数会调用 Bionic 库提供的系统属性 API，例如 `__system_property_get`.

4. **Bionic 库 (libc.so):**
   - `__system_property_get` 等函数是 Bionic libc 库的一部分。这些函数会与系统属性服务进程 (通常是 `init`) 进行进程间通信 (IPC)，以获取或设置属性值。

**NDK 到 Bionic 系统属性的路径：**

1. **C/C++ 代码 (NDK):**
   - NDK 开发人员可以直接使用 Bionic 库提供的系统属性 API，例如：
     ```c++
     #include <sys/system_properties.h>
     ...
     char value[PROP_VALUE_MAX];
     __system_property_get("ro.product.model", value);
     ```

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `__system_property_get` 函数的示例：

```javascript
// 连接到目标进程 (假设进程名为 "com.example.myapp")
const processName = "com.example.myapp";
const session = frida.attach(processName);

session.then(function(session) {
    const script = session.createScript(`
        Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
            onEnter: function(args) {
                const namePtr = args[0];
                const valuePtr = args[1];
                const name = Memory.readCString(namePtr);
                console.log("[__system_property_get] Called with name:", name);
                this.name = name; // 保存属性名，以便在 onLeave 中使用
            },
            onLeave: function(retval) {
                const valuePtr = this.context.args[1]; // 重新获取 value 指针
                const value = Memory.readCString(valuePtr);
                console.log("[__system_property_get] Returning value:", value);
            }
        });
    `);
    script.load();
}).catch(function(error) {
    console.error("Failed to attach:", error);
});
```

**Frida Hook 步骤说明：**

1. **连接到进程:** 使用 `frida.attach()` 连接到目标 Android 进程。
2. **创建 Script:** 使用 `session.createScript()` 创建一个 Frida 脚本。
3. **拦截函数:** 使用 `Interceptor.attach()` 拦截 `libc.so` 中的 `__system_property_get` 函数。
4. **`onEnter`:** 在函数调用前执行，可以访问函数参数 (`args`)。我们读取属性名并打印出来。
5. **`onLeave`:** 在函数返回后执行，可以访问返回值 (`retval`) 和修改后的参数。我们读取返回的属性值并打印出来。
6. **加载脚本:** 使用 `script.load()` 将脚本注入到目标进程。

通过运行这个 Frida 脚本，当目标应用调用 `__system_property_get` 时，你可以在 Frida 控制台中看到被访问的属性名和获取到的属性值，从而调试系统属性的访问过程。你可以类似地 Hook 其他的系统属性相关的函数，例如 `__system_property_add` 和 `__system_property_set`，以观察属性的添加和修改过程。

Prompt: 
```
这是目录为bionic/tests/system_properties_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/silent_death_test.h>
#include <android-base/stringprintf.h>

#include "utils.h"

using namespace std::literals;

#if defined(__BIONIC__)

#include <stdlib.h>
#include <sys/mount.h>
#include <sys/system_properties.h>

#include <system_properties/system_properties.h>

class SystemPropertiesTest : public SystemProperties {
 public:
  SystemPropertiesTest() : SystemProperties(false) {
    appcompat_path = android::base::StringPrintf("%s/appcompat_override", dir_.path);
    mount_path = android::base::StringPrintf("%s/__properties__", dir_.path);
    mkdir(appcompat_path.c_str(), S_IRWXU | S_IXGRP | S_IXOTH);
    valid_ = AreaInit(dir_.path, nullptr, true);
  }
  ~SystemPropertiesTest() {
    if (valid_) {
      contexts_->FreeAndUnmap();
    }
    umount2(dir_.path, MNT_DETACH);
    umount2(real_sysprop_dir.c_str(), MNT_DETACH);
  }

  bool valid() const {
    return valid_;
  }

  const char* get_path() const { return dir_.path; }

  const char* get_appcompat_path() const { return appcompat_path.c_str(); }

  const char* get_mount_path() const { return mount_path.c_str(); }

  const char* get_real_sysprop_dir() const { return real_sysprop_dir.c_str(); }

  std::string appcompat_path;
  std::string mount_path;
  std::string real_sysprop_dir = "/dev/__properties__";

 private:
  TemporaryDir dir_;
  bool valid_;
};

static void foreach_test_callback(const prop_info *pi, void* cookie) {
    size_t *count = static_cast<size_t *>(cookie);

    ASSERT_TRUE(pi != nullptr);
    (*count)++;
}

static void hierarchical_test_callback(const prop_info *pi, void *cookie) {
    bool (*ok)[8][8] = static_cast<bool (*)[8][8]>(cookie);

    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];

    __system_property_read(pi, name, value);

    int name_i, name_j, name_k;
    int value_i, value_j, value_k;
    ASSERT_EQ(3, sscanf(name, "property_%d.%d.%d", &name_i, &name_j, &name_k));
    ASSERT_EQ(3, sscanf(value, "value_%d.%d.%d", &value_i, &value_j, &value_k));
    ASSERT_EQ(name_i, value_i);
    ASSERT_GE(name_i, 0);
    ASSERT_LT(name_i, 8);
    ASSERT_EQ(name_j, value_j);
    ASSERT_GE(name_j, 0);
    ASSERT_LT(name_j, 8);
    ASSERT_EQ(name_k, value_k);
    ASSERT_GE(name_k, 0);
    ASSERT_LT(name_k, 8);

    ok[name_i][name_j][name_k] = true;
}

#endif // __BIONIC__

TEST(properties, __system_property_add) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));
    ASSERT_EQ(0, system_properties.Add("other_property", 14, "value2", 6));
    ASSERT_EQ(0, system_properties.Add("property_other", 14, "value3", 6));

    // check that there is no limit on property name length
    char name[PROP_NAME_MAX + 11];
    name[0] = 'p';
    for (size_t i = 1; i < sizeof(name); i++) {
      name[i] = 'x';
    }

    name[sizeof(name)-1] = '\0';
    ASSERT_EQ(0, system_properties.Add(name, strlen(name), "value", 5));

    char propvalue[PROP_VALUE_MAX];
    ASSERT_EQ(6, system_properties.Get("property", propvalue));
    ASSERT_STREQ(propvalue, "value1");

    ASSERT_EQ(6, system_properties.Get("other_property", propvalue));
    ASSERT_STREQ(propvalue, "value2");

    ASSERT_EQ(6, system_properties.Get("property_other", propvalue));
    ASSERT_STREQ(propvalue, "value3");

    ASSERT_EQ(5, system_properties.Get(name, propvalue));
    ASSERT_STREQ(propvalue, "value");
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_add_appcompat) {
#if defined(__BIONIC__)
    if (getuid() != 0) GTEST_SKIP() << "test requires root";
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    char name[] = "ro.property";
    char override_name[] = "ro.appcompat_override.ro.property";
    char name_not_written[] = "ro.property_other";
    char override_with_no_real[] = "ro.appcompat_override.ro.property_other";
    ASSERT_EQ(0, system_properties.Add(name, strlen(name), "value1", 6));
    ASSERT_EQ(0, system_properties.Add(override_name, strlen(override_name), "value2", 6));
    ASSERT_EQ(0, system_properties.Add(override_with_no_real, strlen(override_with_no_real),
                                       "value3", 6));

    char propvalue[PROP_VALUE_MAX];
    ASSERT_EQ(6, system_properties.Get(name, propvalue));
    ASSERT_STREQ(propvalue, "value1");

    ASSERT_EQ(6, system_properties.Get(override_name, propvalue));
    ASSERT_STREQ(propvalue, "value2");

    ASSERT_EQ(0, system_properties.Get(name_not_written, propvalue));
    ASSERT_STREQ(propvalue, "");

    ASSERT_EQ(6, system_properties.Get(override_with_no_real, propvalue));
    ASSERT_STREQ(propvalue, "value3");

    int ret = mount(system_properties.get_appcompat_path(), system_properties.get_path(), nullptr,
                    MS_BIND | MS_REC, nullptr);
    if (ret != 0) {
      ASSERT_ERRNO(0);
    }
    system_properties.Reload(true);

    ASSERT_EQ(6, system_properties.Get(name, propvalue));
    ASSERT_STREQ(propvalue, "value2");

    ASSERT_EQ(0, system_properties.Get(override_name, propvalue));
    ASSERT_STREQ(propvalue, "");

    ASSERT_EQ(6, system_properties.Get(name_not_written, propvalue));
    ASSERT_STREQ(propvalue, "value3");

    ASSERT_EQ(0, system_properties.Get(override_with_no_real, propvalue));
    ASSERT_STREQ(propvalue, "");

#else   // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(properties, __system_property_update) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "oldvalue1", 9));
    ASSERT_EQ(0, system_properties.Add("other_property", 14, "value2", 6));
    ASSERT_EQ(0, system_properties.Add("property_other", 14, "value3", 6));

    const prop_info* pi = system_properties.Find("property");
    ASSERT_TRUE(pi != nullptr);
    system_properties.Update(const_cast<prop_info*>(pi), "value4", 6);

    pi = system_properties.Find("other_property");
    ASSERT_TRUE(pi != nullptr);
    system_properties.Update(const_cast<prop_info*>(pi), "newvalue5", 9);

    pi = system_properties.Find("property_other");
    ASSERT_TRUE(pi != nullptr);
    system_properties.Update(const_cast<prop_info*>(pi), "value6", 6);

    char propvalue[PROP_VALUE_MAX];
    ASSERT_EQ(6, system_properties.Get("property", propvalue));
    ASSERT_STREQ(propvalue, "value4");

    ASSERT_EQ(9, system_properties.Get("other_property", propvalue));
    ASSERT_STREQ(propvalue, "newvalue5");

    ASSERT_EQ(6, system_properties.Get("property_other", propvalue));
    ASSERT_STREQ(propvalue, "value6");
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, fill) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    char prop_name[PROP_NAME_MAX];
    char prop_value[PROP_VALUE_MAX];
    char prop_value_ret[PROP_VALUE_MAX];
    int count = 0;
    int ret;

    while (true) {
        ret = snprintf(prop_name, PROP_NAME_MAX - 1, "property_%d", count);
        memset(prop_name + ret, 'a', PROP_NAME_MAX - 1 - ret);
        ret = snprintf(prop_value, PROP_VALUE_MAX - 1, "value_%d", count);
        memset(prop_value + ret, 'b', PROP_VALUE_MAX - 1 - ret);
        prop_name[PROP_NAME_MAX - 1] = 0;
        prop_value[PROP_VALUE_MAX - 1] = 0;

        ret = system_properties.Add(prop_name, PROP_NAME_MAX - 1, prop_value, PROP_VALUE_MAX - 1);
        if (ret < 0)
            break;

        count++;
    }

    // For historical reasons at least 247 properties must be supported
    ASSERT_GE(count, 247);

    for (int i = 0; i < count; i++) {
        ret = snprintf(prop_name, PROP_NAME_MAX - 1, "property_%d", i);
        memset(prop_name + ret, 'a', PROP_NAME_MAX - 1 - ret);
        ret = snprintf(prop_value, PROP_VALUE_MAX - 1, "value_%d", i);
        memset(prop_value + ret, 'b', PROP_VALUE_MAX - 1 - ret);
        prop_name[PROP_NAME_MAX - 1] = 0;
        prop_value[PROP_VALUE_MAX - 1] = 0;
        memset(prop_value_ret, '\0', PROP_VALUE_MAX);

        ASSERT_EQ(PROP_VALUE_MAX - 1, system_properties.Get(prop_name, prop_value_ret));
        ASSERT_EQ(0, memcmp(prop_value, prop_value_ret, PROP_VALUE_MAX));
    }
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_foreach) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));
    ASSERT_EQ(0, system_properties.Add("other_property", 14, "value2", 6));
    ASSERT_EQ(0, system_properties.Add("property_other", 14, "value3", 6));

    size_t count = 0;
    ASSERT_EQ(0, system_properties.Foreach(foreach_test_callback, &count));
    ASSERT_EQ(3U, count);
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_find_nth) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));
    ASSERT_EQ(0, system_properties.Add("other_property", 14, "value2", 6));
    ASSERT_EQ(0, system_properties.Add("property_other", 14, "value3", 6));

    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
    EXPECT_EQ(6, system_properties.Read(system_properties.FindNth(0), name, value));
    EXPECT_STREQ("property", name);
    EXPECT_STREQ("value1", value);
    EXPECT_EQ(6, system_properties.Read(system_properties.FindNth(1), name, value));
    EXPECT_STREQ("other_property", name);
    EXPECT_STREQ("value2", value);
    EXPECT_EQ(6, system_properties.Read(system_properties.FindNth(2), name, value));
    EXPECT_STREQ("property_other", name);
    EXPECT_STREQ("value3", value);

    for (unsigned i = 3; i < 1024; ++i) {
      ASSERT_TRUE(system_properties.FindNth(i) == nullptr);
    }
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, fill_hierarchical) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    char prop_name[PROP_NAME_MAX];
    char prop_value[PROP_VALUE_MAX];
    char prop_value_ret[PROP_VALUE_MAX];
    int ret;

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            for (int k = 0; k < 8; k++) {
                ret = snprintf(prop_name, PROP_NAME_MAX - 1, "property_%d.%d.%d", i, j, k);
                memset(prop_name + ret, 'a', PROP_NAME_MAX - 1 - ret);
                ret = snprintf(prop_value, PROP_VALUE_MAX - 1, "value_%d.%d.%d", i, j, k);
                memset(prop_value + ret, 'b', PROP_VALUE_MAX - 1 - ret);
                prop_name[PROP_NAME_MAX - 1] = 0;
                prop_value[PROP_VALUE_MAX - 1] = 0;

                ASSERT_EQ(0, system_properties.Add(
                    prop_name, PROP_NAME_MAX - 1, prop_value, PROP_VALUE_MAX - 1));
            }
        }
    }

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            for (int k = 0; k < 8; k++) {
                ret = snprintf(prop_name, PROP_NAME_MAX - 1, "property_%d.%d.%d", i, j, k);
                memset(prop_name + ret, 'a', PROP_NAME_MAX - 1 - ret);
                ret = snprintf(prop_value, PROP_VALUE_MAX - 1, "value_%d.%d.%d", i, j, k);
                memset(prop_value + ret, 'b', PROP_VALUE_MAX - 1 - ret);
                prop_name[PROP_NAME_MAX - 1] = 0;
                prop_value[PROP_VALUE_MAX - 1] = 0;
                memset(prop_value_ret, '\0', PROP_VALUE_MAX);

                ASSERT_EQ(PROP_VALUE_MAX - 1, system_properties.Get(prop_name, prop_value_ret));
                ASSERT_EQ(0, memcmp(prop_value, prop_value_ret, PROP_VALUE_MAX));
            }
        }
    }

    bool ok[8][8][8];
    memset(ok, 0, sizeof(ok));
    system_properties.Foreach(hierarchical_test_callback, ok);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            for (int k = 0; k < 8; k++) {
                ASSERT_TRUE(ok[i][j][k]);
            }
        }
    }
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, errors) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    char prop_value[PROP_NAME_MAX];

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));
    ASSERT_EQ(0, system_properties.Add("other_property", 14, "value2", 6));
    ASSERT_EQ(0, system_properties.Add("property_other", 14, "value3", 6));

    ASSERT_EQ(0, system_properties.Find("property1"));
    ASSERT_EQ(0, system_properties.Get("property1", prop_value));

    ASSERT_EQ(-1, system_properties.Add("name", 4, "value", PROP_VALUE_MAX));
    ASSERT_EQ(-1, system_properties.Update(NULL, "value", PROP_VALUE_MAX));
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_serial) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));
    const prop_info* pi = system_properties.Find("property");
    ASSERT_TRUE(pi != nullptr);
    unsigned serial = __system_property_serial(pi);
    ASSERT_EQ(0, system_properties.Update(const_cast<prop_info*>(pi), "value2", 6));
    ASSERT_NE(serial, __system_property_serial(pi));
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_wait_any) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));
    unsigned serial = system_properties.WaitAny(0);

    prop_info* pi = const_cast<prop_info*>(system_properties.Find("property"));
    ASSERT_TRUE(pi != nullptr);
    system_properties.Update(pi, "value2", 6);
    serial = system_properties.WaitAny(serial);

    int flag = 0;
    std::thread thread([&system_properties, &flag]() {
        prop_info* pi = const_cast<prop_info*>(system_properties.Find("property"));
        usleep(100000);

        flag = 1;
        system_properties.Update(pi, "value3", 6);
    });
    ASSERT_EQ(flag, 0);
    serial = system_properties.WaitAny(serial);
    ASSERT_EQ(flag, 1);

    thread.join();
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_wait) {
#if defined(__BIONIC__)
    SystemPropertiesTest system_properties;
    ASSERT_TRUE(system_properties.valid());

    ASSERT_EQ(0, system_properties.Add("property", 8, "value1", 6));

    prop_info* pi = const_cast<prop_info*>(system_properties.Find("property"));
    ASSERT_TRUE(pi != nullptr);

    unsigned serial = __system_property_serial(pi);

    std::thread thread([&system_properties]() {
        prop_info* pi = const_cast<prop_info*>(system_properties.Find("property"));
        ASSERT_TRUE(pi != nullptr);

        system_properties.Update(pi, "value2", 6);
    });

    uint32_t new_serial;
    system_properties.Wait(pi, serial, &new_serial, nullptr);
    ASSERT_GT(new_serial, serial);

    char value[PROP_VALUE_MAX];
    ASSERT_EQ(6, system_properties.Get("property", value));
    ASSERT_STREQ("value2", value);

    thread.join();
#else // __BIONIC__
    GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

class KilledByFault {
    public:
        explicit KilledByFault() {};
        bool operator()(int exit_status) const;
};

bool KilledByFault::operator()(int exit_status) const {
    return WIFSIGNALED(exit_status) &&
        (WTERMSIG(exit_status) == SIGSEGV ||
         WTERMSIG(exit_status) == SIGBUS ||
         WTERMSIG(exit_status) == SIGABRT);
}

using properties_DeathTest = SilentDeathTest;

TEST_F(properties_DeathTest, read_only) {
#if defined(__BIONIC__)

  // This test only makes sense if we're talking to the real system property service.
  struct stat sb;
  ASSERT_FALSE(stat(PROP_DIRNAME, &sb) == -1 && errno == ENOENT);

  ASSERT_EXIT(__system_property_add("property", 8, "value", 5), KilledByFault(), "");
#else // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif // __BIONIC__
}

TEST(properties, __system_property_extra_long_read_only) {
#if defined(__BIONIC__)
  SystemPropertiesTest system_properties;
  ASSERT_TRUE(system_properties.valid());

  std::vector<std::pair<std::string, std::string>> short_properties = {
    { "ro.0char", std::string() },
    { "ro.50char", std::string(50, 'x') },
    { "ro.91char", std::string(91, 'x') },
  };

  std::vector<std::pair<std::string, std::string>> long_properties = {
    { "ro.92char", std::string(92, 'x') },
    { "ro.93char", std::string(93, 'x') },
    { "ro.1000char", std::string(1000, 'x') },
  };

  for (const auto& property : short_properties) {
    const std::string& name = property.first;
    const std::string& value = property.second;
    ASSERT_EQ(0, system_properties.Add(name.c_str(), name.size(), value.c_str(), value.size()));
  }

  for (const auto& property : long_properties) {
    const std::string& name = property.first;
    const std::string& value = property.second;
    ASSERT_EQ(0, system_properties.Add(name.c_str(), name.size(), value.c_str(), value.size()));
  }

  auto check_with_legacy_read = [&system_properties](const std::string& name,
                                                     const std::string& expected_value) {
    char value[PROP_VALUE_MAX];
    EXPECT_EQ(static_cast<int>(expected_value.size()), system_properties.Get(name.c_str(), value))
        << name;
    EXPECT_EQ(expected_value, value) << name;
  };

  auto check_with_read_callback = [&system_properties](const std::string& name,
                                                       const std::string& expected_value) {
    const prop_info* pi = system_properties.Find(name.c_str());
    ASSERT_NE(nullptr, pi);
    std::string value;
    system_properties.ReadCallback(pi,
                                   [](void* cookie, const char*, const char* value, uint32_t) {
                                     auto* out_value = reinterpret_cast<std::string*>(cookie);
                                     *out_value = value;
                                   },
                                   &value);
    EXPECT_EQ(expected_value, value) << name;
  };

  for (const auto& property : short_properties) {
    const std::string& name = property.first;
    const std::string& value = property.second;
    check_with_legacy_read(name, value);
    check_with_read_callback(name, value);
  }

  static constexpr const char* kExtraLongLegacyError =
      "Must use __system_property_read_callback() to read";
  for (const auto& property : long_properties) {
    const std::string& name = property.first;
    const std::string& value = property.second;
    check_with_legacy_read(name, kExtraLongLegacyError);
    check_with_read_callback(name, value);
  }

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

// pa_size is 128 * 1024 currently, if a property is longer then we expect it to fail gracefully.
TEST(properties, __system_property_extra_long_read_only_too_long) {
#if defined(__BIONIC__)
  SystemPropertiesTest system_properties;
  ASSERT_TRUE(system_properties.valid());

  auto name = "ro.super_long_property"s;

#ifdef LARGE_SYSTEM_PROPERTY_NODE
  auto value = std::string(1024 * 1024 + 1, 'x');
#else
  auto value = std::string(128 * 1024 + 1, 'x');
#endif

  ASSERT_NE(0, system_properties.Add(name.c_str(), name.size(), value.c_str(), value.size()));

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

// Note that this test affects global state of the system
// this tests tries to mitigate this by using utime+pid
// prefix for the property name. It is still results in
// pollution of property service since properties cannot
// be removed.
//
// Note that there is also possibility to run into "out-of-memory"
// if this test if it is executed often enough without reboot.
TEST(properties, __system_property_reload_no_op) {
#if defined(__BIONIC__)
  std::string property_name =
      android::base::StringPrintf("debug.test.%d.%" PRId64 ".property", getpid(), NanoTime());
  ASSERT_EQ(0, __system_property_find(property_name.c_str()));
  ASSERT_EQ(0, __system_property_set(property_name.c_str(), "test value"));
  ASSERT_EQ(0, __system_properties_zygote_reload());
  const prop_info* readptr = __system_property_find(property_name.c_str());
  std::string expected_name = property_name;
  __system_property_read_callback(
      readptr,
      [](void*, const char*, const char* value, unsigned) { ASSERT_STREQ("test value", value); },
      &expected_name);
#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(properties, __system_property_reload_invalid) {
#if defined(__BIONIC__)
  if (getuid() != 0) GTEST_SKIP() << "test requires root";
  SystemPropertiesTest system_properties;

  // Create an invalid property_info file, so the system will attempt to initialize a
  // ContextSerialized
  std::string property_info_file =
      android::base::StringPrintf("%s/property_info", system_properties.get_path());
  fclose(fopen(property_info_file.c_str(), "w"));
  int ret = mount(system_properties.get_path(), system_properties.get_real_sysprop_dir(), nullptr,
                  MS_BIND | MS_REC, nullptr);
  if (ret != 0) {
    ASSERT_ERRNO(0);
  }

  ASSERT_EQ(-1, __system_properties_zygote_reload());
#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

// Note that this test affects global state of the system
// this tests tries to mitigate this by using utime+pid
// prefix for the property name. It is still results in
// pollution of property service since properties cannot
// be removed.
//
// Note that there is also possibility to run into "out-of-memory"
// if this test if it is executed often enough without reboot.
TEST(properties, __system_property_reload_valid) {
#if defined(__BIONIC__)
  if (getuid() != 0) GTEST_SKIP() << "test requires root";
  SystemPropertiesTest system_properties;

  // Copy the system properties files into the temp directory
  std::string shell_cmd = android::base::StringPrintf(
      "cp -r %s %s", system_properties.get_real_sysprop_dir(), system_properties.get_path());
  system(shell_cmd.c_str());

  // Write a system property to the current set of system properties
  std::string property_name =
      android::base::StringPrintf("debug.test.%d.%" PRId64 ".property", getpid(), NanoTime());
  ASSERT_EQ(0, __system_property_find(property_name.c_str()));
  ASSERT_EQ(0, __system_property_set(property_name.c_str(), "test value"));

  // Mount the temp directory (which doesn't have the property we just wrote) in place of the
  // real one
  int ret = mount(system_properties.get_mount_path(), system_properties.get_real_sysprop_dir(),
                  nullptr, MS_BIND | MS_REC, nullptr);
  if (ret != 0) {
    ASSERT_ERRNO(0);
  }

  // reload system properties in the new dir, and verify the property we wrote after we copied the
  // files isn't there
  ASSERT_EQ(0, __system_properties_zygote_reload());
  ASSERT_EQ(0, __system_property_find(property_name.c_str()));

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

"""

```