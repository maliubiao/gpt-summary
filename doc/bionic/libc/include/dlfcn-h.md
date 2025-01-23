Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a comprehensive explanation of the provided `dlfcn.handroid` header file from Android's Bionic library. This includes its functions, their purpose, their relationship to Android, implementation details (especially for libc functions), dynamic linker aspects, common errors, and how Android reaches this code.

2. **Break Down the Task:**  I identify the key areas to address:
    * **Functionality Overview:** What does this header *do*?
    * **Individual Function Details:**  For each function (`dlopen`, `dlclose`, etc.), explain its purpose, parameters, return values, and any Android-specific considerations.
    * **Android Integration:** How are these functions used within Android? Provide concrete examples.
    * **Implementation Details (libc functions):** While the header *declares* the functions, it doesn't *define* their implementation. I need to acknowledge this and explain conceptually how the dynamic linker handles these operations. I should focus on the dynamic linking process.
    * **Dynamic Linker Specifics:**  This is crucial. I need to cover `RTLD_DEFAULT`, `RTLD_NEXT`, `RTLD_LOCAL`, `RTLD_GLOBAL`, how shared libraries are loaded and linked, and provide a sample SO layout.
    * **Common Errors:**  Think about typical mistakes developers make when working with dynamic linking.
    * **Android Framework/NDK Integration:**  Trace the path from application code to these `dlfcn` calls.
    * **Frida Hooking:** Provide practical Frida examples for inspecting these functions.

3. **Initial Scan and Categorization:** I read through the header file, identifying the core elements:
    * Function declarations (`dlopen`, `dlclose`, etc.)
    * Data structures (`Dl_info`)
    * Macros (`RTLD_DEFAULT`, `RTLD_NOW`, etc.)
    * Copyright and licensing information.

4. **Address Each Function Individually:** For each function, I consider the following:
    * **Standard Purpose:** What does the corresponding POSIX function do? (The comments provide hints with `man` page references.)
    * **Android-Specific Notes:**  Are there any deviations from the standard? The comments often highlight these (e.g., `RTLD_LAZY` not supported).
    * **Implementation Insights:**  How does the dynamic linker *likely* implement this? (e.g., `dlopen` involves finding the library, mapping it into memory, resolving symbols). *Crucially, I need to avoid claiming to know the exact implementation details without access to the source code of the dynamic linker itself.*
    * **Usage Examples:** How would a developer use this function?

5. **Focus on Dynamic Linking Concepts:**  This is a key part of the request.
    * **SO Layout:**  I need to create a simplified example showing sections like `.text`, `.data`, `.bss`, `.dynsym`, `.plt`, `.got`, and how they relate to the loading process.
    * **Linking Process:** Explain the steps involved: locating the library, loading it, symbol resolution (including lazy and eager binding), and relocation.
    * **`RTLD_*` Flags:** Clearly explain the meaning and impact of each flag.

6. **Brainstorm Common Errors:** I draw upon my knowledge of common dynamic linking pitfalls:
    * Incorrect paths in `dlopen`.
    * Forgetting to check return values and use `dlerror`.
    * `dlclose` misuse and its dangers.
    * Versioning issues (although `dlvsym` is only briefly mentioned in the provided header).
    * Symbol name mismatches in `dlsym`.

7. **Trace the Android Path:**  I consider how a typical Android application might use these functions:
    * **NDK:** Direct use by native code.
    * **Android Framework:**  Potentially used internally for loading system libraries or plugins (though less direct for typical app development).
    * **Java Native Interface (JNI):**  How Java code might indirectly trigger dynamic linking.

8. **Craft Frida Examples:**  I think about practical ways to use Frida to observe these functions:
    * Hooking `dlopen` to see which libraries are being loaded.
    * Hooking `dlsym` to inspect symbol resolution.
    * Logging parameters and return values.

9. **Structure and Language:** I organize the information logically with clear headings and bullet points. I use precise language and avoid ambiguity. The request specifies Chinese, so I ensure all output is in Chinese.

10. **Review and Refine:**  I re-read my answer to ensure it addresses all aspects of the request, is technically accurate, and is easy to understand. I check for any inconsistencies or areas that could be clearer. For instance, initially, I might have focused too much on the libc *implementation*, but the header file is about the *interface*. I need to correct my focus to the dynamic linker's role. I also need to make sure the Frida examples are practical and easy to adapt.

By following these steps, I can construct a comprehensive and informative answer that addresses all the user's requirements. The key is to break down the complex request into manageable parts and address each part systematically.这是一个关于 Android Bionic 库中 `dlfcn.handroid` 文件的功能解释。这个文件定义了与动态链接相关的函数和数据结构。

**功能列举:**

这个头文件主要定义了以下与动态链接相关的功能：

* **加载共享库:**  允许程序在运行时加载共享库（也称为动态链接库，SO 文件）。
* **关闭共享库:**  允许程序在运行时卸载已加载的共享库。
* **查找错误信息:**  提供获取最近一次动态链接错误的机制。
* **查找符号地址:**  允许程序在已加载的共享库中查找特定符号（函数或变量）的地址。
* **按版本查找符号地址:** 允许程序在已加载的共享库中查找特定版本符号的地址（Android API 24 引入）。
* **获取地址信息:**  允许程序根据给定的地址，获取包含该地址的共享库信息和符号信息。

**与 Android 功能的关系及举例说明:**

动态链接是 Android 系统中至关重要的功能，它允许：

* **代码复用和模块化:** 不同的应用程序和系统组件可以共享相同的库，减少内存占用和代码冗余。例如，多个应用程序可能都使用 `libc.so` 提供的标准 C 库函数。
* **延迟加载:** 只有在需要时才加载共享库，可以加快应用程序启动速度并减少初始内存占用。
* **插件化和扩展性:**  应用程序可以通过动态加载插件或模块来扩展其功能。

**具体举例:**

1. **`dlopen()`:**  一个应用程序可能需要使用一个特定的第三方库来处理图像。它可以使用 `dlopen()` 函数在运行时加载这个库，例如：

   ```c
   void* handle = dlopen("/data/local/tmp/libimage.so", RTLD_LAZY);
   if (!handle) {
       fprintf(stderr, "dlopen failed: %s\n", dlerror());
       // 处理错误
   }
   ```
   这里，`dlopen()` 尝试加载 `/data/local/tmp/libimage.so` 共享库。`RTLD_LAZY` 表示采用延迟绑定，即只有在首次使用库中的符号时才进行解析。

2. **`dlsym()`:**  在成功加载 `libimage.so` 后，应用程序可以使用 `dlsym()` 函数查找库中定义的函数 `process_image` 的地址：

   ```c
   typedef void (*process_image_func)(const char* filename);
   process_image_func process = (process_image_func)dlsym(handle, "process_image");
   if (!process) {
       fprintf(stderr, "dlsym failed: %s\n", dlerror());
       dlclose(handle); // 记得关闭库
       // 处理错误
   } else {
       process("image.jpg"); // 调用查找到的函数
   }
   ```

3. **`dlclose()`:**  当应用程序不再需要 `libimage.so` 时，应该使用 `dlclose()` 函数卸载它：

   ```c
   dlclose(handle);
   ```

4. **`dlerror()`:** 如果 `dlopen()` 或 `dlsym()` 调用失败，可以调用 `dlerror()` 获取详细的错误信息：

   ```c
   void* handle = dlopen("non_existent_library.so", RTLD_NOW);
   if (!handle) {
       const char* error_msg = dlerror();
       fprintf(stderr, "Error loading library: %s\n", error_msg);
   }
   ```

5. **`dladdr()`:**  可以用来查找给定地址所属的库和符号信息。这在调试器或性能分析工具中很有用。

**libc 函数的实现解释:**

`dlfcn.handroid` 头文件本身 **只声明了这些函数的接口**，并没有包含具体的实现代码。这些函数的具体实现位于 Bionic 库的动态链接器部分 (`linker`)。

**以下是对每个 libc 函数的功能以及动态链接器如何实现它们的概念性解释：**

* **`dlopen(const char* __filename, int __flag)`:**
    * **功能:** 加载指定的共享库。
    * **实现:**
        1. **路径解析:** 根据 `__filename` 解析出共享库的完整路径。如果 `__filename` 为 NULL，则返回表示主程序命名空间的句柄。
        2. **查找已加载库:** 检查该库是否已经被加载到进程空间中。如果是，根据 `__flag` 的设置（例如 `RTLD_LOCAL` 或 `RTLD_GLOBAL`）增加其引用计数或直接返回已存在的句柄。
        3. **加载库:** 如果库未加载，动态链接器会：
            * 读取 ELF 文件头以获取加载信息。
            * 使用 `mmap()` 系统调用将库的代码段、数据段等映射到进程的地址空间。
            * 处理库的依赖关系 (DT_NEEDED)，递归加载依赖库。
            * 执行库的初始化代码（例如，全局对象的构造函数）。
            * 根据 `__flag` 的设置，将库的符号添加到全局符号表或保持局部。
        4. **返回句柄:** 返回一个表示已加载库的 opaque 句柄。

* **`dlclose(void* __handle)`:**
    * **功能:** 减少指定共享库的引用计数。当引用计数降至零时，可能会卸载库。
    * **实现:**
        1. **查找库:** 根据 `__handle` 找到对应的已加载共享库。
        2. **减少引用计数:** 将该库的引用计数减 1。
        3. **卸载库 (可能):** 如果引用计数变为 0，并且没有设置 `RTLD_NODELETE` 标志，动态链接器会：
            * 执行库的析构代码（例如，全局对象的析构函数）。
            * 从进程的地址空间中解除库的映射 (使用 `munmap()`)。
            * 从内部数据结构中移除该库的信息。
        4. **返回状态:** 成功返回 0，失败返回 -1。

* **`dlerror()`:**
    * **功能:** 返回最近一次 `dlfcn.h` 函数调用失败的错误消息。
    * **实现:** 动态链接器维护一个线程局部变量，用于存储最近的错误消息。`dlerror()` 只是简单地返回并清除这个变量的内容。

* **`dlsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char* _Nullable __symbol)`:**
    * **功能:** 在指定的共享库或全局符号表中查找指定名称的符号的地址。
    * **实现:**
        1. **确定搜索范围:**
            * 如果 `__handle` 是 `RTLD_DEFAULT`，则在全局符号表中搜索。
            * 如果 `__handle` 是 `RTLD_NEXT`，则从调用 `dlsym()` 的库之后加载的库开始搜索。
            * 如果 `__handle` 是一个有效的库句柄，则仅在该库中搜索。
        2. **符号查找:** 在指定的范围内，遍历符号表（通常是 `.dynsym` 段），查找与 `__symbol` 匹配的符号。
        3. **返回地址:** 如果找到符号，返回其在内存中的地址；否则返回 NULL。

* **`dlvsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char* _Nullable __symbol, const char* _Nullable __version)`:**
    * **功能:**  类似于 `dlsym()`，但允许指定符号的版本。
    * **实现:**  与 `dlsym()` 类似，但需要在符号表中同时匹配符号名称和版本信息。这通常涉及到查找 `.gnu.version_r` 段。

* **`dladdr(const void* _Nonnull __addr, Dl_info* _Nonnull __info)`:**
    * **功能:**  查找包含给定地址的共享库和符号信息。
    * **实现:**
        1. **遍历已加载库:** 遍历当前进程中所有已加载的共享库。
        2. **地址匹配:** 检查给定的地址 `__addr` 是否落在某个库的加载地址范围内。
        3. **符号查找 (可选):** 如果找到了包含该地址的库，可以在该库的符号表中查找最接近 `__addr` 的符号。
        4. **填充 `Dl_info`:** 将找到的库路径、加载基址、符号名称和符号地址填充到 `__info` 结构体中。

**涉及 dynamic linker 的功能：SO 布局样本和链接处理过程**

**SO 布局样本:**

一个典型的共享库（SO 文件）的布局如下：

```
ELF Header:  包含了标识 ELF 文件类型、架构等信息。

Program Headers:  描述了如何将文件的各个段加载到内存中。
  LOAD: 可执行代码段 (.text)
  LOAD: 只读数据段 (.rodata)
  LOAD: 可读写数据段 (.data, .bss)
  DYNAMIC: 动态链接信息段 (.dynamic)

Section Headers:  描述了文件的各个段。
  .text:     可执行机器指令
  .rodata:   只读数据 (例如字符串常量)
  .data:     已初始化的全局变量和静态变量
  .bss:      未初始化的全局变量和静态变量
  .symtab:   符号表 (用于链接和调试)
  .strtab:   字符串表 (存储符号名称等字符串)
  .dynsym:   动态符号表 (用于运行时链接)
  .dynstr:   动态字符串表 (存储动态符号名称)
  .rel.dyn:  动态重定位表 (用于在加载时调整数据段中的地址)
  .rel.plt:  PLT 重定位表 (用于延迟绑定)
  .plt:      过程链接表 (Procedure Linkage Table，用于外部函数调用)
  .got:      全局偏移量表 (Global Offset Table，存储全局变量的地址)
  .hash:     符号哈希表 (加速符号查找)
  .init:     初始化代码段 (在库加载时执行)
  .fini:     终止代码段 (在库卸载时执行)
  .gnu.version_r: 版本依赖信息 (用于版本化的符号)
  ... 其他段 ...
```

**链接的处理过程:**

1. **编译时链接 (Static Linking):**  链接器将程序的所有目标文件和静态库合并成一个可执行文件。所有符号引用都在编译时解析。

2. **运行时链接 (Dynamic Linking):** 动态链接器负责在程序运行时加载和链接共享库。这个过程包括：

   * **加载共享库:**  当程序启动或调用 `dlopen()` 时，动态链接器根据需要加载共享库到内存中。
   * **符号解析:**
      * **早期绑定 (Eager Binding, `RTLD_NOW`):**  在库加载时，动态链接器会解析所有未定义的符号。它会遍历库的 `.rel.dyn` 和 `.rel.plt` 段，找到需要重定位的条目，并在全局符号表或其他已加载库中查找对应的符号地址，然后更新 GOT 和 PLT 表。
      * **延迟绑定 (Lazy Binding, `RTLD_LAZY`):**  最初，PLT 中的每个条目都指向动态链接器中的一段代码。当程序首次调用一个外部函数时，控制权会转移到 PLT 中的这个桩代码。桩代码会调用动态链接器来解析该符号，并将解析后的地址写入 GOT 表。后续对该函数的调用将直接通过 GOT 表跳转到目标地址，避免了重复解析。
   * **重定位:**  由于共享库在不同的进程中可能被加载到不同的地址，动态链接器需要修改代码和数据段中的地址引用，使其指向正确的内存位置。GOT (全局偏移量表) 和 PLT (过程链接表) 是实现重定位的关键机制。
   * **初始化和终止:**  动态链接器会执行每个共享库的 `.init` 段中的初始化代码和 `.fini` 段中的终止代码。

**假设输入与输出 (逻辑推理)**

假设我们有以下简单的场景：

* `main_program` 可执行文件依赖于 `libA.so`。
* `libA.so` 依赖于 `libB.so`。

**启动 `main_program` 时的链接过程：**

**输入:** 执行 `main_program` 命令。

**输出:**

1. **动态链接器启动:**  操作系统加载 `main_program` 并启动动态链接器。
2. **加载 `libA.so`:** 动态链接器解析 `main_program` 的依赖关系，发现需要加载 `libA.so`，将其加载到内存。
3. **加载 `libB.so`:** 动态链接器解析 `libA.so` 的依赖关系，发现需要加载 `libB.so`，将其加载到内存。
4. **符号解析和重定位:**  动态链接器解析 `main_program`、`libA.so` 和 `libB.so` 之间的符号引用，并进行地址重定位。例如，如果 `main_program` 调用了 `libA.so` 中的函数 `foo`，动态链接器会找到 `foo` 的地址并更新 `main_program` 中的调用指令。
5. **执行 `main_program`:** 链接完成后，控制权转移到 `main_program` 的入口点。

**假设输入与输出 (`dlopen`/`dlsym`)**

假设一个应用程序通过 `dlopen` 加载了一个库并使用 `dlsym` 获取了函数指针：

**输入:**

```c
void* handle = dlopen("mylibrary.so", RTLD_LAZY);
void (*my_function)() = (void (*)())dlsym(handle, "my_function");
```

**输出:**

* **`dlopen` 的输出:**
    * **成功:** 返回一个非 NULL 的句柄，指向 `mylibrary.so` 的内部表示。
    * **失败:** 返回 NULL，并且可以通过 `dlerror()` 获取错误信息，例如 "mylibrary.so: cannot open shared object file: No such file or directory"。
* **`dlsym` 的输出:**
    * **成功:** 返回 `mylibrary.so` 中 `my_function` 函数的内存地址。
    * **失败:** 返回 NULL，并且可以通过 `dlerror()` 获取错误信息，例如 "undefined symbol my_function"。

**用户或编程常见的使用错误:**

1. **`dlopen` 时指定错误的路径:** 如果传递给 `dlopen` 的路径不正确，动态链接器将无法找到该库。

   ```c
   void* handle = dlopen("wrong_path/mylibrary.so", RTLD_LAZY); // 假设路径错误
   if (!handle) {
       fprintf(stderr, "Error: %s\n", dlerror()); // 可能会输出 "cannot open shared object file: No such file or directory"
   }
   ```

2. **忘记检查 `dlopen` 和 `dlsym` 的返回值:**  如果不检查返回值，就可能在空指针上进行操作，导致程序崩溃。

   ```c
   void* handle = dlopen("mylibrary.so", RTLD_LAZY);
   void (*my_function)() = (void (*)())dlsym(handle, "my_function");
   my_function(); // 如果 dlsym 失败，这里会导致崩溃
   ```

3. **`dlclose` 使用不当:**  过早地 `dlclose` 一个库可能导致程序尝试访问已卸载的内存。

   ```c
   void* handle = dlopen("mylibrary.so", RTLD_LAZY);
   void (*my_function)() = (void (*)())dlsym(handle, "my_function");
   dlclose(handle);
   my_function(); // 可能会崩溃，因为 mylibrary.so 已经被卸载
   ```

4. **`dlsym` 时使用了错误的符号名称:** 如果传递给 `dlsym` 的符号名称与库中实际的符号名称不匹配，`dlsym` 将返回 NULL。

   ```c
   void* handle = dlopen("mylibrary.so", RTLD_LAZY);
   void (*my_function)() = (void (*)())dlsym(handle, "wrong_function_name");
   if (!my_function) {
       fprintf(stderr, "Error: %s\n", dlerror()); // 可能会输出 "undefined symbol wrong_function_name"
   }
   ```

5. **与线程局部变量的交互问题:**  如文档所述，`dlclose` 与带有非平凡析构函数的线程局部变量交互不佳，可能导致资源泄漏或程序崩溃。

**Android framework or ndk 是如何一步步的到达这里:**

1. **NDK 开发:**
   * NDK 开发人员可以直接在 C/C++ 代码中使用 `<dlfcn.h>` 中声明的函数。
   * 例如，一个 NDK 应用可能使用 `dlopen` 加载一个动态库，该库提供了特定的功能。

2. **Android Framework (Java 层):**
   * Android Framework 本身在某些情况下也会使用动态链接，但通常是通过底层的 Native 代码来实现的。
   * Java 层可以通过 JNI (Java Native Interface) 调用 Native 代码，而 Native 代码可能会使用 `dlfcn.h` 中的函数。
   * 例如，Android 系统可能会动态加载一些 Native 模块来处理特定的任务。

**步骤示例 (从 Java 到 `dlopen`):**

1. **Java 代码尝试加载 Native 库:**

   ```java
   System.loadLibrary("my_native_lib");
   ```

2. **`System.loadLibrary` 的实现:**  `System.loadLibrary` 在内部会调用 Native 方法，最终会走到 Bionic 库中的加载逻辑。

3. **Native 方法调用 `dlopen` 或类似的函数:**  在 Bionic 库的实现中，会根据库的名称查找对应的 SO 文件，并调用底层的 `dlopen` 或 `android_dlopen_ext` 函数来加载库。`android_dlopen_ext` 是 Android 特有的扩展，提供了更多的控制选项。

**Frida hook 示例调试这些步骤:**

以下是一些使用 Frida hook 调试 `dlfcn.h` 中函数的示例：

```javascript
// Hook dlopen
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function(args) {
    console.log("dlopen called");
    console.log("  filename: " + args[0]);
    console.log("  flag: " + args[1]);
  },
  onLeave: function(retval) {
    console.log("dlopen returned: " + retval);
    if (retval.isNull()) {
      console.log("  Error: " + Module.findExportByName(null, "dlerror")());
    }
  }
});

// Hook dlsym
Interceptor.attach(Module.findExportByName(null, "dlsym"), {
  onEnter: function(args) {
    console.log("dlsym called");
    console.log("  handle: " + args[0]);
    console.log("  symbol: " + args[1]);
  },
  onLeave: function(retval) {
    console.log("dlsym returned: " + retval);
    if (retval.isNull()) {
      console.log("  Error: " + Module.findExportByName(null, "dlerror")());
    }
  }
});

// Hook dlclose
Interceptor.attach(Module.findExportByName(null, "dlclose"), {
  onEnter: function(args) {
    console.log("dlclose called");
    console.log("  handle: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("dlclose returned: " + retval);
    if (retval.toInt32() !== 0) {
      console.log("  Error: " + Module.findExportByName(null, "dlerror")());
    }
  }
});

// Hook dladdr
Interceptor.attach(Module.findExportByName(null, "dladdr"), {
  onEnter: function(args) {
    console.log("dladdr called");
    console.log("  addr: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("dladdr returned: " + retval);
    if (retval.toInt32() !== 0) {
      const Dl_info = new NativeStruct(ptr(arguments[1]), {
        dli_fname: 'pointer',
        dli_fbase: 'pointer',
        dli_sname: 'pointer',
        dli_saddr: 'pointer'
      });
      console.log("  dli_fname: " + Dl_info.dli_fname.readCString());
      console.log("  dli_fbase: " + Dl_info.dli_fbase);
      console.log("  dli_sname: " + Dl_info.dli_sname.readCString());
      console.log("  dli_saddr: " + Dl_info.dli_saddr);
    }
  }
});
```

这些 Frida 脚本可以帮助你：

* 观察何时调用了这些动态链接函数。
* 查看传递给函数的参数，例如要加载的库的名称、要查找的符号等。
* 查看函数的返回值，包括成功或失败以及可能的错误信息。
* 对于 `dladdr`，可以查看返回的库和符号信息。

通过使用 Frida hook，你可以深入了解 Android 系统或应用程序如何使用动态链接，并帮助你调试相关的问题。

### 提示词
```
这是目录为bionic/libc/include/dlfcn.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <sys/cdefs.h>

#include <stdint.h>

/**
 * @addtogroup libdl Dynamic Linker
 * @{
 */

/**
 * \file
 * Standard dynamic library support.
 * See also the Android-specific functionality in `<android/dlext.h>`.
 */

__BEGIN_DECLS

/**
 * dladdr() returns information using this structure.
 */
typedef struct {
  /** Pathname of the shared object that contains the given address. */
  const char* _Nullable dli_fname;
  /** Address at which the shared object is loaded. */
  void* _Nullable dli_fbase;
  /** Name of the nearest symbol with an address lower than the given address. */
  const char* _Nullable dli_sname;
  /** Exact address of the symbol named in `dli_sname`. */
  void* _Nullable dli_saddr;
} Dl_info;

/**
 * [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html)
 * loads the given shared library.
 *
 * See also android_dlopen_ext().
 *
 * Returns a pointer to an opaque handle for use with other <dlfcn.h> functions
 * on success, and returns NULL on failure, in which case dlerror() can be used
 * to retrieve the specific error.
 */
void* _Nullable dlopen(const char* _Nullable __filename, int __flag);

/**
 * [dlclose(3)](https://man7.org/linux/man-pages/man3/dlclose.3.html)
 * decrements the reference count for the given shared library (and
 * any libraries brought in by that library's DT_NEEDED entries).
 *
 * If a library's reference count hits zero, it may be unloaded.
 * Code that relies on this is not portable, and may not work on
 * future versions of Android.
 *
 * dlclose() is dangerous because function pointers may or may not
 * be rendered invalid, global data may or may not be rendered invalid,
 * and memory may or may not leak. Code with global constructors is
 * especially problematic. Instead of dlclose, prefer to leave the
 * library open or, if cleanup is necessary, dlopen() the library in
 * a child process which can later be killed by the parent or call
 * exit() itself.
 *
 * Note also that dlclose() interacts badly with thread local variables
 * with non-trivial destructors, with the
 * (exact behavior varying by API level)[https://android.googlesource.com/platform/bionic/+/main/android-changes-for-ndk-developers.md#dlclose-interacts-badly-with-thread-local-variables-with-non_trivial-destructors].
 *
 * Returns 0 on success, and returns -1 on failure, in which case
 * dlerror() can be used to retrieve the specific error.
 */
int dlclose(void* _Nonnull __handle);

/**
 * [dlerror(3)](https://man7.org/linux/man-pages/man3/dlerror.3.html)
 * returns a human-readable error message describing the most recent
 * failure from one of the <dlfcn.h> functions on the calling thread.
 *
 * This function also clears the error, so a second call (or a call
 * before any failure) will return NULL.
 *
 * Returns a pointer to an error on success, and returns NULL if no
 * error is pending.
 */
char* _Nullable dlerror(void);

/**
 * [dlsym(3)](https://man7.org/linux/man-pages/man3/dlsym.3.html)
 * returns a pointer to the symbol with the given name in the shared
 * library represented by the given handle. The handle may have been
 * returned from dlopen(), or can be RTLD_DEFAULT or RTLD_NEXT.
 *
 * Returns the address of the symbol on success, and returns NULL on failure,
 * in which case dlerror() can be used to retrieve the specific error.
 */
void* _Nullable dlsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char* _Nullable __symbol);

/**
 * [dlvsym(3)](https://man7.org/linux/man-pages/man3/dlvsym.3.html)
 * returns a pointer to the symbol with the given name and version in the shared
 * library represented by the given handle. The handle may have been
 * returned from dlopen(), or can be RTLD_DEFAULT or RTLD_NEXT.
 *
 * Returns the address of the symbol on success, and returns NULL on failure,
 * in which case dlerror() can be used to retrieve the specific error.
 */

#if __BIONIC_AVAILABILITY_GUARD(24)
void* _Nullable dlvsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char* _Nullable __symbol, const char* _Nullable __version) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


/**
 * [dladdr(3)](https://man7.org/linux/man-pages/man3/dladdr.3.html)
 * returns information about the symbol at the given address.
 *
 * Returns non-zero on success, and returns 0 on failure. Note that unlike
 * the other <dlfcn.h> functions, in this case dlerror() will _not_ have
 * more information.
 */
int dladdr(const void* _Nonnull __addr, Dl_info* _Nonnull __info);

/**
 * A dlsym()/dlvsym() handle that returns the first symbol found in any
 * shared library using the default search order.
 */
#define RTLD_DEFAULT  __BIONIC_CAST(reinterpret_cast, void*, 0)

/**
 * A dlsym()/dlvsym() handle that returns the first symbol found in any
 * shared library that appears _after_ the object containing the caller.
 */
#define RTLD_NEXT     __BIONIC_CAST(reinterpret_cast, void*, -1L)

/**
 * A dlopen() flag to not make symbols from this library available to later
 * libraries. See also RTLD_GLOBAL.
 */
#define RTLD_LOCAL    0

/**
 * Not supported on Android. Android always uses RTLD_NOW for security reasons.
 * Resolving all undefined symbols before dlopen() returns means that RELRO
 * protections can be applied to the PLT before dlopen() returns.
 */
#define RTLD_LAZY     0x00001

/** A dlopen() flag to resolve all undefined symbols before dlopen() returns. */
#define RTLD_NOW      0x00002

/**
 * A dlopen() flag to not actually load the given library;
 * used to test whether the library is already loaded.
 */
#define RTLD_NOLOAD   0x00004

/**
 * A dlopen() flag to make symbols from this library available to later
 * libraries. See also RTLD_LOCAL.
 */
#define RTLD_GLOBAL   0x00100

/**
 * A dlopen() flag to ignore later dlclose() calls on this library.
 */
#define RTLD_NODELETE 0x01000

/* LP32 has historical ABI breakage. */
#if !defined(__LP64__)
#undef RTLD_DEFAULT
#define RTLD_DEFAULT  __BIONIC_CAST(reinterpret_cast, void*, 0xffffffff)
#undef RTLD_NEXT
#define RTLD_NEXT     __BIONIC_CAST(reinterpret_cast, void*, 0xfffffffe)
#undef RTLD_NOW
#define RTLD_NOW      0x00000
#undef RTLD_GLOBAL
#define RTLD_GLOBAL   0x00002
#endif

__END_DECLS

/** @} */
```