Response:
Let's break down the thought process for analyzing this `atexit_test.cpp` file.

**1. Understanding the Goal:**

The first step is to understand the overall purpose of the code. The filename `atexit_test.cpp` and the inclusion of `<gtest/gtest.h>` immediately suggest this is a unit test file focused on the `atexit` functionality in Android's Bionic library. The comments within the code also explicitly mention testing `atexit` behavior.

**2. Deconstructing the Code:**

Next, I'll go through the code section by section, identifying key elements and their purpose.

* **Includes:**  Recognize standard C/C++ headers (`stdio.h`, `stdint.h`, `limits.h`) and Bionic-specific headers (`dlfcn.h`, `libgen.h`). Note that `dlfcn.h` is crucial, indicating dynamic linking is being tested. `gtest/gtest.h` confirms it's a Google Test file.

* **`TEST(atexit, sofile)`:** This is the first test case.
    * `dlopen("libtest_atexit.so", RTLD_NOW)`:  This immediately signals a test involving a dynamically linked library (`.so` file). The `RTLD_NOW` flag is also important, indicating eager symbol resolution.
    * `dlsym`:  This further confirms the interaction with dynamic linking, as `dlsym` is used to find symbols within the loaded library. The symbols being looked up (`get_cxx_ctor_called`, `get_attr_ctor_called`, `register_atexit`) provide hints about the functionality being tested within `libtest_atexit.so`.
    * `dlclose`: This is the counterpart to `dlopen` and is essential for proper cleanup in dynamic linking.
    * `ASSERT_EQ`: These assertions are the core of the test, verifying expected behavior. The checks on `atexit_call_sequence`, `valid_this_in_static_dtor`, and `attr_dtor_called` point to the specific aspects of `atexit` being validated (order of calls, context within destructors).

* **`class TestMainStaticDtorClass`:**  This class demonstrates the behavior of static object destructors. The constructor and destructor printing to `stderr` are key to understanding the order of execution. The `expected_this` pointer is a mechanism to verify the `this` pointer's validity during destructor execution.

* **Static Functions (`atexit_func1` to `atexit_func5`):** These are simple functions designed to be registered with `atexit`. The `fprintf` calls within them allow for tracking the execution order. Note the recursive call to `atexit` within `atexit_func3`.

* **`atexit_main`:**  This function orchestrates the `atexit` calls and creates the static object. The `exit(0)` call is crucial for triggering the `atexit` handlers.

* **`TEST(atexit, exit)`:** This is the second test case.
    * `ASSERT_EXIT`: This Google Test macro is specifically for testing the outcome of a program that calls `exit`. The expected output to `stderr` ("123456") directly relates to the order in which the `atexit` handlers and the static destructor are executed.

**3. Identifying Key Concepts:**

Based on the code analysis, the core concepts being tested are:

* **`atexit`:**  Its primary function is to register functions to be called when a program exits normally.
* **Static Destructors:** The order in which destructors of static objects are called.
* **Dynamic Linking (`dlopen`, `dlsym`, `dlclose`):**  How `atexit` behaves in the context of dynamically loaded libraries.
* **Order of Execution:** The precise sequence in which `atexit` handlers and static destructors are invoked.

**4. Answering the Prompt's Questions:**

Now, I can address each point in the prompt systematically:

* **Functionality:** Summarize the overall purpose of the test file – validating `atexit`.
* **Relationship to Android:** Explain how `atexit` is a standard C library function used in Android and provide examples of its relevance (e.g., resource cleanup).
* **`libc` Function Details:**
    * **`atexit`:** Explain its role in registering functions and the LIFO order.
    * **`dlopen`:** Describe its function in loading shared libraries.
    * **`dlsym`:** Explain how it retrieves function or variable addresses.
    * **`dlclose`:** Explain its role in unloading libraries.
    * **`exit`:** Describe its function in terminating the program and triggering `atexit` handlers.
* **Dynamic Linker Details:**
    * **SO Layout:** Create a simple example of `libtest_atexit.so`'s contents, highlighting the exported symbols.
    * **Linking Process:** Describe how `dlopen` loads the library and how `dlsym` resolves the symbols.
* **Logical Reasoning:**  Provide examples of how the tests work by outlining the expected sequence of calls and the resulting output.
* **Common Errors:** List potential pitfalls when using `atexit` (e.g., calling `exit` within an `atexit` handler, exceeding the limit).
* **Android Framework/NDK Path:** Explain how a typical Android application using the NDK would eventually lead to the execution of `atexit` within Bionic.
* **Frida Hook Example:** Provide a concrete Frida script to intercept the `atexit` calls and observe their behavior.

**5. Structuring the Response:**

Finally, I organize the information logically, using clear headings and bullet points to make it easy to read and understand. I ensure that all parts of the prompt are addressed comprehensively and accurately. I pay attention to providing concrete examples and detailed explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps focus too heavily on just the `atexit` function itself.
* **Correction:** Realize the test also covers static destructors and dynamic linking, so broaden the analysis.
* **Initial thought:** Briefly mention Frida.
* **Correction:** Provide a specific, working Frida example for better illustration.
* **Initial thought:**  Describe the linking process vaguely.
* **Correction:** Detail the steps involving the dynamic linker, symbol tables, and relocation.

By following this detailed breakdown and iterative refinement, I can generate a comprehensive and accurate answer to the prompt.
好的，让我们来详细分析一下 `bionic/tests/atexit_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/atexit_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试 `atexit` 函数及其相关机制在不同场景下的行为。 `atexit` 函数允许程序员注册一些函数，这些函数会在程序正常退出时被调用。 这个测试文件覆盖了以下几个方面：

1. **基本的 `atexit` 功能:**  验证 `atexit` 注册的函数能否在 `exit` 被调用时按正确的顺序执行。
2. **静态对象析构函数与 `atexit`:** 测试静态对象的析构函数与 `atexit` 注册的函数之间的调用顺序。
3. **动态链接库中的 `atexit`:**  测试在动态链接库中使用 `atexit` 的情况，包括库的构造函数、析构函数以及通过 `dlopen`/`dlsym`/`dlclose` 加载和卸载库时 `atexit` 的行为。
4. **`atexit` 处理程序中调用 `atexit`:**  测试在已经注册的 `atexit` 处理程序中再次调用 `atexit` 的行为。
5. **静态析构函数中 `this` 指针的有效性:** 验证在静态对象的析构函数中 `this` 指针是否有效。

**与 Android 功能的关系及举例**

`atexit` 是一个标准的 C 库函数，在 Android 中也被广泛使用。它的主要作用是在程序退出时执行一些清理工作，例如释放资源、关闭文件、记录日志等。

**举例说明：**

* **资源释放:** 在 Android 应用程序或 Native 代码中，你可能分配了一些内存或者打开了一些文件。使用 `atexit` 注册一个函数，确保在程序退出时这些资源被正确释放，避免内存泄漏或文件句柄泄露。
* **日志记录:**  在程序退出时，你可能希望记录一些最终的统计信息或错误信息。可以通过 `atexit` 注册一个日志记录函数来实现。
* **清理临时文件:**  如果程序在运行过程中创建了一些临时文件，可以使用 `atexit` 注册一个函数来删除这些临时文件。
* **关闭网络连接:**  如果程序打开了网络连接，可以使用 `atexit` 注册一个函数来关闭这些连接。

**`libc` 函数的功能及实现**

以下是对测试文件中涉及的 `libc` 函数的详细解释：

1. **`atexit(void (*function)(void))`:**
   * **功能:**  `atexit` 函数用于注册一个在程序正常终止时（通过调用 `exit` 或从 `main` 函数返回）被调用的函数。 可以多次调用 `atexit` 来注册多个函数。 这些函数将以注册的相反顺序（后进先出，LIFO）被调用。
   * **实现:** 在 Bionic 中，`atexit` 的实现通常维护一个函数指针数组或链表。 每次调用 `atexit` 时，新的函数指针会被添加到这个结构中。 当调用 `exit` 时，`exit` 函数会遍历这个结构，并依次调用其中的函数。 为了保证线程安全，`atexit` 的实现需要考虑多线程环境下的同步问题，可能使用互斥锁或其他同步机制来保护内部数据结构。

2. **`dlopen(const char *filename, int flags)`:**
   * **功能:**  `dlopen` 函数用于加载一个动态链接库（共享对象 `.so` 文件）。
   * **实现:**  `dlopen` 是动态链接器（linker）提供的接口。当调用 `dlopen` 时，动态链接器会执行以下步骤：
      * 查找指定的 `.so` 文件。
      * 将 `.so` 文件加载到进程的地址空间。
      * 解析 `.so` 文件中的符号表，并执行必要的重定位（将代码和数据中对外部符号的引用指向实际的地址）。
      * 执行 `.so` 文件中的初始化代码（例如，全局对象的构造函数，使用 `__attribute__((constructor))` 标记的函数）。
      * 返回一个指向加载的 `.so` 文件的句柄，如果加载失败则返回 `NULL`。
   * **`flags` 参数:**  `flags` 参数控制加载的行为，例如 `RTLD_NOW` 表示立即解析所有符号，如果解析失败则 `dlopen` 返回错误； `RTLD_LAZY` 表示延迟解析符号，只有在实际使用时才解析。

3. **`dlsym(void *handle, const char *symbol)`:**
   * **功能:**  `dlsym` 函数用于在一个已经通过 `dlopen` 加载的动态链接库中查找指定的符号（函数或全局变量）。
   * **实现:** `dlsym` 接收 `dlopen` 返回的库句柄和符号名称作为参数。它会在指定库的符号表中查找匹配的符号。 如果找到，它会返回该符号的地址；如果找不到，则返回 `NULL`。

4. **`dlclose(void *handle)`:**
   * **功能:** `dlclose` 函数用于卸载一个通过 `dlopen` 加载的动态链接库。
   * **实现:** 当调用 `dlclose` 时，动态链接器会执行以下步骤：
      * 检查是否有其他已加载的库依赖于要卸载的库。如果有，则卸载操作可能会失败。
      * 执行要卸载的库的清理代码（例如，全局对象的析构函数，使用 `__attribute__((destructor))` 标记的函数，以及通过 `atexit` 注册的函数）。
      * 将库从进程的地址空间中移除。
      * 减少库的引用计数。当引用计数降为零时，库才会被真正卸载。
      * 返回 0 表示成功，非零值表示失败。

5. **`exit(int status)`:**
   * **功能:** `exit` 函数用于使程序正常终止。
   * **实现:**  `exit` 函数执行以下操作：
      * 调用所有通过 `atexit` 注册的函数，按照注册的相反顺序。
      * 清理标准 I/O 缓冲区。
      * 调用所有已加载动态链接库的析构函数 (使用 `__attribute__((destructor))` 标记的函数)。
      * 终止进程，并将 `status` 作为退出状态返回给操作系统。

**涉及 Dynamic Linker 的功能**

在 `atexit_test.cpp` 中，`TEST(atexit, sofile)` 测试用例专门测试了与动态链接器相关的功能。

**SO 布局样本 (libtest_atexit.so 可能的结构):**

```c++
// libtest_atexit.cpp
#include <stdio.h>
#include <stdlib.h>
#include <string>

extern std::string atexit_call_sequence;
extern bool valid_this_in_static_dtor;
extern bool attr_dtor_called;

static int cxx_ctor_called = 0;
static int attr_ctor_called = 0;

__attribute__((constructor))
void my_so_constructor() {
  cxx_ctor_called = 1;
}

__attribute__((destructor))
void my_so_destructor() {
  attr_dtor_called = true;
}

class MyClass {
public:
  MyClass() {
    // Constructor
  }
  ~MyClass() {
    atexit_call_sequence += ", Goodbye from MyClass";
  }
};

static MyClass my_static_object;

extern "C" {

int get_cxx_ctor_called() {
  return cxx_ctor_called;
}

int get_attr_ctor_called() {
  return attr_ctor_called;
}

static void atexit_handler1() {
  atexit_call_sequence = "Humpty ";
}

static void atexit_handler2() {
  atexit_call_sequence += "Dumpty ";
}

static void atexit_handler3() {
  atexit_call_sequence += "sat on a wall";
}

void register_atexit(std::string* seq, bool* valid_this, bool* attr_called) {
  atexit_call_sequence = "";
  valid_this_in_static_dtor = (my_static_object.~MyClass(), true); // 模拟析构函数调用并检查 this 指针
  atexit(atexit_handler3);
  atexit(atexit_handler2);
  atexit(atexit_handler1);
}

} // extern "C"
```

**链接的处理过程:**

1. **`dlopen("libtest_atexit.so", RTLD_NOW)`:**
   - 动态链接器会查找 `libtest_atexit.so` 文件（通常在 `/system/lib`, `/vendor/lib` 或应用程序的 `libs` 目录下）。
   - 加载器将 `.so` 文件加载到内存，并解析其 ELF 头。
   - 由于使用了 `RTLD_NOW`，链接器会立即解析所有未定义的符号。
   - 执行 `libtest_atexit.so` 中的构造函数 (`my_so_constructor`)，这会将 `cxx_ctor_called` 设置为 1。
   - 动态链接器返回一个指向加载的 `.so` 的句柄。

2. **`dlsym(handle, "get_cxx_ctor_called")` 和 `dlsym(handle, "get_attr_ctor_called")`:**
   - 链接器在 `libtest_atexit.so` 的符号表中查找名为 `"get_cxx_ctor_called"` 和 `"get_attr_ctor_called"` 的导出函数。
   - 返回这些函数的地址。

3. **`ASSERT_EQ(1, get_cxx_ctor_called());` 和 `ASSERT_EQ(1, get_attr_ctor_called());`:**
   - 调用从 `dlsym` 获取的函数地址，验证构造函数是否被执行。

4. **`dlsym(handle, "register_atexit")`:**
   - 链接器查找 `"register_atexit"` 函数的地址。

5. **`reinterpret_cast<void (*)(std::string*, bool*, bool*)>(sym)(&atexit_call_sequence, &valid_this_in_static_dtor, &attr_dtor_called);`:**
   - 调用 `libtest_atexit.so` 中的 `register_atexit` 函数，该函数会注册几个 `atexit` 处理程序。

6. **`dlclose(handle)`:**
   - 动态链接器开始卸载 `libtest_atexit.so`。
   - 执行 `libtest_atexit.so` 中通过 `atexit` 注册的函数，按照注册的相反顺序执行，构建 `atexit_call_sequence` 字符串。
   - 执行 `libtest_atexit.so` 的析构函数 (`my_so_destructor`)，这会将 `attr_dtor_called` 设置为 `true`。
   - 卸载库。

7. **后续的 `ASSERT_EQ` 和 `ASSERT_TRUE` 验证了 `atexit` 调用顺序和析构函数的执行。**

**逻辑推理（假设输入与输出）**

**`TEST(atexit, sofile)`:**

* **假设输入:** 成功加载 `libtest_atexit.so`，并且 `libtest_atexit.so` 中正确实现了构造函数、析构函数以及 `register_atexit` 函数。
* **预期输出:**
    * `get_cxx_ctor_called()` 返回 1。
    * `get_attr_ctor_called()` 返回 1。
    * 在 `dlclose` 之后，`atexit_call_sequence` 的值是 "Humpty Dumpty sat on a wall"。
    * `valid_this_in_static_dtor` 的值为 `true`。
    * `attr_dtor_called` 的值为 `true`。

**`TEST(atexit, exit)`:**

* **假设输入:** `atexit_main` 函数被执行。
* **预期输出 (输出到 stderr):** "123456"
    * `atexit(atexit_func1)` 导致在退出时打印 "1"。
    * `atexit(atexit_func2)` 导致在退出时打印 "2"。
    * `atexit(atexit_func3)` 导致在退出时打印 "3"，并且注册 `atexit_func4`。
    * `atexit(atexit_func5)` 导致在退出时打印 "5"。
    * 静态对象 `static_obj` 的析构函数打印 "6"。
    * `atexit_func4` (由 `atexit_func3` 注册) 导致在退出时打印 "4"。
    * 由于 `atexit` 的 LIFO 特性，以及静态对象析构函数在 `atexit` 处理程序之后执行，所以输出顺序是 "123456"。

**用户或编程常见的使用错误**

1. **在 `atexit` 处理程序中调用 `exit`:**  这会导致无限循环或未定义的行为，因为 `exit` 会再次触发 `atexit` 处理程序。
   ```c++
   void cleanup() {
       // ... 一些清理工作 ...
       exit(1); // 错误的做法
   }

   int main() {
       atexit(cleanup);
       // ...
       return 0;
   }
   ```

2. **注册过多的 `atexit` 处理程序:**  不同的系统对可以注册的 `atexit` 处理程序的数量有限制。超出限制可能导致注册失败或未定义的行为。

3. **假设 `atexit` 处理程序的执行顺序:**  虽然 `atexit` 处理程序按照注册的相反顺序执行，但在动态链接库的情况下，库的卸载顺序可能会影响 `atexit` 处理程序的执行顺序。 依赖于跨多个库的 `atexit` 处理程序的特定执行顺序是不可靠的。

4. **在 `atexit` 处理程序中访问已释放的资源:**  需要确保 `atexit` 处理程序中访问的资源在程序退出时尚未被释放。例如，全局变量可能会在 `atexit` 处理程序执行之前被析构。

5. **线程安全问题:**  如果 `atexit` 处理程序访问共享资源，需要确保这些访问是线程安全的，因为 `atexit` 处理程序可能在多线程环境下被调用。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发:**  开发者使用 NDK 编写 Native 代码，这些代码会被编译成动态链接库 (`.so` 文件)。
2. **JNI 调用:**  Android Framework (Java 代码) 通过 JNI (Java Native Interface) 调用 Native 代码中的函数。
3. **Native 代码执行:**  在 Native 代码中，开发者可能会使用标准的 C/C++ 库函数，包括 `atexit`。
4. **`exit` 调用:**  当 Native 代码执行 `exit()` 函数时，或者当 Android 进程因某种原因正常终止时，Bionic 的 `exit` 实现会被调用。
5. **`atexit` 处理程序执行:**  Bionic 的 `exit` 实现会遍历并执行所有通过 `atexit` 注册的函数。

**Frida Hook 示例调试步骤**

假设我们要 Hook `atexit` 函数，查看注册了哪些函数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

session = frida.attach('com.example.myapp') # 替换为你的应用包名

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "atexit"), {
    onEnter: function(args) {
        var funcPtr = ptr(args[0]);
        console.log("[+] atexit called with function: " + funcPtr);
        // 可以尝试读取函数指针指向的代码，但需要小心
        // console.log(hexdump(funcPtr, { length: 64 }));
    },
    onLeave: function(retval) {
        console.log("[+] atexit returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "exit"), {
    onEnter: function(args) {
        console.log("[+] exit called with status: " + args[0]);
    }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明:**

1. **安装 Frida:** 确保你的设备或模拟器上安装了 Frida 服务，并且你的开发机上安装了 Frida Python 库。
2. **获取应用包名:** 替换 `'com.example.myapp'` 为你要调试的 Android 应用的包名。
3. **连接到应用:**  `frida.attach()` 连接到目标 Android 应用的进程。
4. **创建 Frida Script:**
   - 使用 `Interceptor.attach` 拦截 `atexit` 函数的调用。
   - `onEnter` 函数在 `atexit` 函数被调用时执行，打印注册的函数指针。
   - 使用 `Interceptor.attach` 拦截 `exit` 函数的调用，查看退出状态。
5. **加载脚本:** `script.load()` 将脚本注入到目标进程。
6. **执行应用并观察输出:** 运行你的 Android 应用，当应用调用 `atexit` 或 `exit` 时，Frida 会在控制台输出相应的日志信息。

**更进一步的调试:**

* **查看 `atexit` 注册的函数地址:**  可以通过 Frida 打印出 `atexit` 注册的函数的内存地址。
* **Hook `exit` 函数:**  可以 Hook `exit` 函数，在 `exit` 执行之前查看已经注册的 `atexit` 处理程序，但这需要更深入地了解 Bionic 的内部实现。
* **动态修改 `atexit` 的行为:**  虽然不推荐在生产环境这样做，但在调试时可以使用 Frida 动态修改 `atexit` 的行为，例如阻止某些处理程序的执行。

希望以上详细的解释能够帮助你理解 `bionic/tests/atexit_test.cpp` 文件的功能和相关知识。

### 提示词
```
这是目录为bionic/tests/atexit_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <dlfcn.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>

#include <string>

TEST(atexit, sofile) {
  std::string atexit_call_sequence;
  bool valid_this_in_static_dtor = false;
  bool attr_dtor_called = false;

  void* handle = dlopen("libtest_atexit.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr);

  typedef int (*int_fn)(void);
  int_fn get_cxx_ctor_called, get_attr_ctor_called;
  get_cxx_ctor_called = reinterpret_cast<int_fn>(dlsym(handle, "get_cxx_ctor_called"));
  get_attr_ctor_called = reinterpret_cast<int_fn>(dlsym(handle, "get_attr_ctor_called"));
  ASSERT_TRUE(get_cxx_ctor_called != nullptr);
  ASSERT_TRUE(get_attr_ctor_called != nullptr);

  ASSERT_EQ(1, get_cxx_ctor_called());
  ASSERT_EQ(1, get_attr_ctor_called());

  void* sym = dlsym(handle, "register_atexit");
  ASSERT_TRUE(sym != nullptr);
  reinterpret_cast<void (*)(std::string*, bool*, bool*)>(sym)(&atexit_call_sequence, &valid_this_in_static_dtor, &attr_dtor_called);

  ASSERT_EQ(0, dlclose(handle));
  // this test verifies atexit call from atexit handler. as well as the order of calls
  ASSERT_EQ("Humpty Dumpty sat on a wall", atexit_call_sequence);
  ASSERT_TRUE(valid_this_in_static_dtor);
  ASSERT_TRUE(attr_dtor_called);
}

class TestMainStaticDtorClass {
 public:
  TestMainStaticDtorClass() {
    expected_this = this;
  }

  ~TestMainStaticDtorClass() {
    if (this != expected_this) {
      fprintf(stderr, "\nerror: static d-tor called with incorrect this pointer: %p, expected: %p\n", this, expected_this);
    } else {
      fprintf(stderr, "6");
    }
  }
 private:
  static const TestMainStaticDtorClass* expected_this;
};

const TestMainStaticDtorClass* TestMainStaticDtorClass::expected_this = nullptr;

static void atexit_func5() {
  fprintf(stderr, "5");
}

static void atexit_func4() {
  fprintf(stderr, "4");
}

static void atexit_func3() {
  fprintf(stderr, "3");
  atexit(atexit_func4);
}

static void atexit_func2() {
  fprintf(stderr, "2");
}

static void atexit_func1() {
  fprintf(stderr, "1");
}

static void atexit_main() {
  // This should result in "123456" output to stderr
  static TestMainStaticDtorClass static_obj;
  atexit(atexit_func5);
  atexit(atexit_func3);
  atexit(atexit_func2);
  atexit(atexit_func1);
  exit(0);
}

TEST(atexit, exit) {
  ASSERT_EXIT(atexit_main(), testing::ExitedWithCode(0), "123456");
}
```