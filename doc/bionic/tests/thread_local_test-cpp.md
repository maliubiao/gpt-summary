Response:
Let's break down the thought process for analyzing the C++ test file and generating the comprehensive Chinese response.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ code (`thread_local_test.cpp`) and explain its functionality, its relation to Android, the underlying mechanisms of relevant C library and dynamic linker features, potential errors, and how to debug it using Frida. The output should be in Chinese.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key elements:

* **Includes:** `<gtest/gtest.h>`, `<stdint.h>`, `<string.h>` suggest this is a unit test file using Google Test framework and involves basic data types and string manipulation.
* **Global Variables:** `__thread int local_var`, `int shared_var`, `__thread Triangle local_triangle`, `Triangle shared_triangle`. The `__thread` keyword immediately signals thread-local storage. The distinction between `__thread` and regular globals is crucial.
* **Functions:** `reset_vars`, `inc_shared_var`, `inc_local_var`, `run_one_thread`, `reset_triangle`, `move_shared_triangle`, `move_local_triangle`. The naming clearly indicates their purpose (incrementing, moving, resetting shared/local variables). `run_one_thread` is a helper for creating and joining threads.
* **`TEST` Macros:**  These indicate Google Test test cases. The names (`thread_local_storage`, `shared`, `local`, `shared_triangle`, `local_triangle`, `type_size`, `init_value`) provide a high-level understanding of what's being tested.
* **`static_assert`:**  Used for compile-time assertions about data type sizes.
* **`extern "C" void* __emutls_get_address(__emutls_control*)`:** This is a key function related to emulated TLS, suggesting a fallback mechanism for systems without native TLS support.
* **Data Structures:** `Point`, `Triangle`, `gcc_emutls_object`, `__emutls_control`. Understanding these structures is vital for explaining the tests.

**3. Deconstructing the Test Cases:**

Now, analyze each `TEST` case individually:

* **`shared` and `local`:** These tests focus on the core difference between shared and thread-local variables. `shared` demonstrates that modifications in one thread are visible in others. `local` shows that each thread has its own copy of the `__thread` variable.
* **`shared_triangle` and `local_triangle`:** These tests expand on the previous ones but use a more complex data structure (an array of structs). The core principles remain the same.
* **`type_size`:** This test confirms the sizes of certain data types are consistent, which is important for interoperability.
* **`init_value`:** This is the most complex test, specifically dealing with `__emutls_get_address`. It tests the initialization and alignment of thread-local storage managed by this function.

**4. Identifying Android Relevance:**

The file is located within `bionic/tests`, and bionic is Android's C library. Therefore, the primary relevance is to the implementation of thread-local storage within Android's libc. The tests ensure the correctness and robustness of this crucial feature for multithreaded applications on Android.

**5. Explaining libc Functions:**

The code directly uses or interacts with:

* **`pthread_create`:**  Need to explain its role in creating new threads.
* **`pthread_join`:** Explain waiting for a thread to finish.
* **`memcpy`:**  Explain its purpose for copying memory.
* **`malloc` and `free`:** Explain dynamic memory allocation and deallocation.
* **`strlen`:** Explain how it calculates string length.

For each function, the explanation should cover its basic functionality and how it's used in the context of the test file. *Self-correction during this stage:* Initially, I might just describe what the function does in isolation. I need to remember to connect it back to *how it's being used in these specific tests* to make the explanation more relevant.

**6. Delving into Dynamic Linking:**

The presence of `__emutls_get_address` and the discussion of `gcc_emutls_object` and `__emutls_control` point to a dynamic linking aspect. The key here is to understand that `__thread` variables need to be handled correctly when shared libraries are involved.

* **SO Layout:**  A conceptual layout of an SO file showing the `.tbss` or similar section for TLS data is needed.
* **Linking Process:**  Explain how the dynamic linker resolves accesses to TLS variables. This involves the GOT (Global Offset Table) and potentially the TLS Initial Exec (TLS IE) or TLS Local Exec (TLS LE) models. *Self-correction:* Avoid going too deep into every detail of dynamic linking, but provide a good overview of the relevant concepts.

**7. Hypothetical Input/Output:**

For the core tests (`shared` and `local`), provide simple scenarios illustrating the behavior. This makes the concepts easier to grasp. Focus on the values of the shared and local variables before and after thread execution.

**8. Common Usage Errors:**

Think about common mistakes developers make when working with threads and TLS:

* Incorrectly assuming TLS variables are shared.
* Not initializing TLS variables properly.
* Race conditions when multiple threads access shared variables without synchronization.

**9. Android Framework/NDK Path and Frida Hooking:**

This requires understanding the higher-level Android architecture.

* **Framework/NDK to Bionic:** Trace the path from an Android application (Java or native) down to the bionic library. Mention JNI calls for native code.
* **Frida Hooking:**  Provide practical Frida examples to intercept the execution of `pthread_create` and potentially `__emutls_get_address`. Focus on how to inspect arguments and return values.

**10. Structuring the Response:**

Organize the information logically:

1. **功能 (Functionality):**  A high-level overview.
2. **与 Android 的关系 (Relationship with Android):**  Explain bionic's role.
3. **libc 函数详解 (Detailed Explanation of libc Functions):** Go through the relevant functions.
4. **动态链接器功能 (Dynamic Linker Functionality):** Explain TLS in the context of dynamic linking.
5. **逻辑推理 (Logical Deduction):**  Provide the input/output examples.
6. **常见错误 (Common Errors):**  List potential pitfalls.
7. **Android 框架/NDK 到达路径 (Path from Android Framework/NDK):** Explain the call stack.
8. **Frida Hook 示例 (Frida Hook Examples):**  Provide code snippets.

**11. Language and Tone:**

Maintain a clear, concise, and informative tone. Use accurate terminology and explain technical concepts in an accessible way. Ensure the entire response is in Chinese as requested.

**Self-Review and Refinement:**

After drafting the response, review it for clarity, accuracy, and completeness. Are the explanations easy to understand?  Are the examples clear?  Is all the requested information covered?  Are there any grammatical errors or typos in the Chinese text? This iterative refinement is crucial for producing a high-quality answer.
这个文件 `bionic/tests/thread_local_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试线程局部存储（Thread-Local Storage，TLS）的功能。Bionic 是 Android 的 C 库、数学库和动态链接器，因此这个测试文件涉及到 C 库的线程管理以及动态链接器对 TLS 的支持。

以下是该文件的功能详解：

**1. 功能列举：**

* **测试线程局部变量的特性：**  主要验证使用 `__thread` 关键字声明的变量在每个线程中都拥有独立的副本，修改一个线程的线程局部变量不会影响其他线程的同名变量。
* **测试共享变量的特性：**  验证不使用 `__thread` 声明的全局变量在所有线程之间共享，一个线程的修改会影响其他线程。
* **测试复杂数据类型的线程局部存储：**  验证线程局部存储可以用于复杂的数据结构，例如结构体数组。
* **测试 emutls 运行时数据结构和 `__emutls_get_address` 函数：**  这部分测试涉及到在没有原生 TLS 支持的架构上模拟 TLS 的机制，验证 `__emutls_get_address` 函数的正确性，包括初始化、对齐和数据访问。

**2. 与 Android 功能的关系及举例：**

这个测试文件直接关系到 Android 系统中多线程编程的基础能力。Android 应用和系统服务经常使用多线程来实现并发执行。线程局部存储对于以下场景至关重要：

* **每个线程需要维护自己的状态信息：** 例如，在网络请求处理中，每个线程可能需要保存自己的连接信息、请求参数等。使用 TLS 可以避免显式地传递这些信息，简化代码。
* **避免多线程竞争：**  对于某些全局资源，如果不希望使用锁进行同步，可以考虑使用 TLS，让每个线程拥有自己的副本，从而避免竞争条件。

**举例说明：**

* **Android Framework 的 Looper 和 Handler 机制：**  Android 的消息处理机制 Looper 和 Handler 依赖于线程局部存储来保存每个线程的消息队列。每个线程都有一个唯一的 Looper 对象，这个 Looper 对象通常会存储在线程局部变量中。这样，当一个 Handler 向其关联的 Looper 发送消息时，消息会被添加到当前线程的 Looper 的消息队列中。
* **NDK 开发中的线程特定数据：**  在 NDK 开发中，如果使用 Pthreads 进行多线程编程，可以使用 `__thread` 关键字来声明线程局部变量，方便管理每个线程的私有数据。例如，一个 OpenGL 渲染线程可能需要保存自己的渲染上下文。

**3. libc 函数的功能实现详解：**

* **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)`:**
    * **功能：** 创建一个新的线程。
    * **实现：**  `pthread_create` 是 POSIX 线程标准库中的函数。在 Bionic 中，它的实现会调用底层的系统调用（如 `clone` 或 `fork`），创建一个新的执行上下文（线程）。
    * **具体步骤：**
        1. 分配新的线程的栈空间。
        2. 复制调用线程的部分状态（例如信号屏蔽）。
        3. 设置新线程的入口点为 `start_routine` 函数。
        4. 将 `arg` 作为参数传递给 `start_routine`。
        5. 如果成功，将新线程的 ID 存储在 `thread` 指向的内存位置。
* **`pthread_join(pthread_t thread, void **retval)`:**
    * **功能：**  等待指定的线程终止。
    * **实现：** `pthread_join` 也是 POSIX 线程标准库中的函数。在 Bionic 中，它会调用底层的系统调用（如 `waitpid`），挂起调用线程的执行，直到目标线程退出。
    * **具体步骤：**
        1. 检查目标线程是否存在且可连接。
        2. 如果目标线程仍在运行，则调用线程进入等待状态。
        3. 当目标线程终止时，操作系统会唤醒等待的线程。
        4. 如果 `retval` 不为空，则将目标线程的返回值（通过 `pthread_exit` 设置）存储在 `retval` 指向的内存位置。
* **`memcpy(void *dest, const void *src, size_t n)`:**
    * **功能：** 将 `src` 指向的内存块的 `n` 个字节复制到 `dest` 指向的内存块。
    * **实现：**  `memcpy` 是 C 标准库中的函数。Bionic 的 `memcpy` 通常会进行一些优化，例如使用 SIMD 指令进行高速复制。
    * **具体步骤：**
        1. 检查 `dest` 和 `src` 是否有重叠（如果有，行为未定义，应使用 `memmove`）。
        2. 从 `src` 地址开始，逐字节或按字复制 `n` 个字节的数据到 `dest` 地址。
* **`strlen(const char *s)`:**
    * **功能：** 计算以空字符 `\0` 结尾的字符串 `s` 的长度（不包括空字符）。
    * **实现：** `strlen` 是 C 标准库中的函数。Bionic 的 `strlen` 实现通常会优化，例如一次读取多个字节进行检查。
    * **具体步骤：**
        1. 从字符串的起始地址开始遍历内存。
        2. 逐字节检查是否遇到了空字符 `\0`。
        3. 遇到空字符时，返回起始地址到空字符地址之间的字节数。
* **`malloc(size_t size)`:**
    * **功能：**  在堆上分配指定大小的内存块。
    * **实现：** `malloc` 是 C 标准库中的动态内存分配函数。Bionic 使用的内存分配器（例如 jemalloc 或 scudo）负责管理堆内存。
    * **具体步骤：**
        1. 接收需要分配的内存大小 `size`。
        2. 在堆上找到一个足够大的空闲内存块。
        3. 标记该内存块为已分配。
        4. 返回指向该内存块起始地址的指针。
* **`free(void *ptr)`:**
    * **功能：**  释放之前通过 `malloc`、`calloc` 或 `realloc` 分配的内存块。
    * **实现：**  `free` 是 C 标准库中的动态内存释放函数。
    * **具体步骤：**
        1. 接收指向需要释放的内存块的指针 `ptr`。
        2. 检查 `ptr` 是否有效（非空，且指向之前分配的内存块）。
        3. 将该内存块标记为空闲，并将其归还给内存分配器。
        4. 可能会与相邻的空闲内存块合并，以减少内存碎片。

**4. 涉及 dynamic linker 的功能，so 布局样本，链接的处理过程：**

这个测试文件涉及到 `__thread` 关键字，而线程局部存储的实现与动态链接器密切相关，特别是在加载共享库时。

**SO 布局样本 (简化)：**

假设有一个共享库 `libexample.so`，其中定义了一个线程局部变量：

```c++
// libexample.cpp
__thread int tls_variable = 42;
```

编译成共享库后，其布局可能包含以下部分（简化）：

```
.text          # 代码段
.rodata        # 只读数据段
.data          # 已初始化数据段
.bss           # 未初始化数据段
.tbss          # 线程局部存储未初始化数据段 (Thread BSS)
.tdata         # 线程局部存储已初始化数据段 (Thread Data)
.got           # 全局偏移量表
.plt           # 过程链接表
...
```

* **`.tbss` (Thread BSS)：**  用于存储未初始化的线程局部变量。
* **`.tdata` (Thread Data)：** 用于存储已初始化的线程局部变量，例如上面的 `tls_variable = 42;`。

**链接的处理过程：**

1. **加载时分配 TLS 空间：** 当动态链接器加载包含线程局部变量的共享库时，它需要为每个线程分配足够的空间来存储这些变量的副本。
2. **TLS 模板：**  共享库中会包含 TLS 模板，描述了 TLS 变量的大小和初始化值。动态链接器会根据这些模板为每个线程分配并初始化 TLS 块。
3. **访问 TLS 变量：**  当线程访问一个线程局部变量时，需要一种机制来找到该线程的 TLS 块中对应变量的地址。这通常通过以下方式实现：
    * **线程指针 (Thread Pointer, TP)：**  每个线程都有一个指向其 TLS 块的指针。
    * **偏移量：**  每个线程局部变量在 TLS 块中都有一个固定的偏移量。
    * **寻址方式：**  访问 TLS 变量的指令会利用线程指针和偏移量来计算出实际的内存地址。例如，在 ARM64 架构上，通常使用 `tpidr_el0` 寄存器作为线程指针。
4. **`__emutls_get_address` 的作用：**  在某些架构或旧版本的 Android 系统中，可能没有原生的 TLS 支持。这时，会使用模拟的 TLS (emulated TLS, emutls)。`__emutls_get_address` 函数就是用于获取模拟的线程局部变量的地址。它会维护一个数据结构来存储每个线程的 TLS 数据，并根据传入的控制信息找到对应的地址。

**示例：**

假设线程要访问 `libexample.so` 中的 `tls_variable`：

1. 编译器会将对 `tls_variable` 的访问转换为一种特殊的指令，该指令会利用线程指针和 `tls_variable` 在 `.tdata` 段中的偏移量。
2. 运行时，CPU 会读取当前线程的线程指针（例如 `tpidr_el0` 寄存器的值）。
3. 将线程指针加上 `tls_variable` 的偏移量，得到该线程的 `tls_variable` 副本的地址。
4. 从该地址读取或写入数据。

**5. 逻辑推理，假设输入与输出：**

**假设输入：**

考虑 `TEST(thread_local_storage, shared)` 的第一次断言：

* 调用 `reset_vars()`，设置 `local_var = 1000` 和 `shared_var = 2000`。

**输出：**

* `ASSERT_EQ(local_var, 1000)`：因为 `local_var` 是当前线程的局部变量，在 `reset_vars` 中被设置为 1000，所以断言成立。
* `ASSERT_EQ(shared_var, 2000)`：因为 `shared_var` 是共享变量，在 `reset_vars` 中被设置为 2000，所以断言成立。

再考虑 `TEST(thread_local_storage, shared)` 中调用 `run_one_thread(inc_shared_var)` 后的断言：

* 子线程执行 `inc_shared_var`，其中 `shared_var++` 将共享变量递增。

**输出：**

* `ASSERT_EQ(run_one_thread(inc_shared_var), 2001)`：`inc_shared_var` 返回递增后的 `shared_var` 的值，即 2001。
* `ASSERT_EQ(local_var, 1000)`：当前线程的 `local_var` 不受子线程的影响，仍然是 1000。
* `ASSERT_EQ(shared_var, 2001)`：`shared_var` 被子线程递增，变为 2001。

对于 `TEST(thread_local_storage, local)` 中调用 `run_one_thread(inc_local_var)` 后的断言：

* 子线程执行 `inc_local_var`，其中 `local_var++` 递增的是子线程的局部变量副本。

**输出：**

* `ASSERT_EQ(run_one_thread(inc_local_var), 101)`：子线程的 `local_var` 初始值为 100（在线程创建时初始化），递增后变为 101。
* `ASSERT_EQ(local_var, 1000)`：父线程的 `local_var` 不受子线程的影响，仍然是 1000。
* `ASSERT_EQ(shared_var, 2000)`：共享变量不受子线程操作线程局部变量的影响，仍然是 2000。

**6. 用户或编程常见的使用错误：**

* **误以为线程局部变量是全局共享的：** 这是最常见的错误。开发者可能会错误地认为在多个线程中访问同一个 `__thread` 变量会访问到相同的内存地址，导致逻辑错误。
    ```c++
    __thread int counter = 0;

    void* thread_func(void*) {
        counter++;
        printf("Thread ID: %ld, Counter: %d\n", pthread_self(), counter);
        return nullptr;
    }

    // 预期可能错误地认为所有线程会共享同一个 counter 并递增
    ```
    **正确理解：** 每个线程都有自己的 `counter` 副本，输出会显示每个线程的 `counter` 从 1 开始递增。
* **忘记初始化线程局部变量：** 如果线程局部变量没有显式初始化，其初始值取决于编译器和平台，可能会导致未定义的行为。
    ```c++
    __thread int tls_value; // 未初始化

    void* thread_func(void*) {
        printf("TLS Value: %d\n", tls_value); // tls_value 的值不确定
        return nullptr;
    }
    ```
    **推荐做法：** 始终显式地初始化线程局部变量。
* **在单线程程序中使用线程局部变量：**  虽然在语法上是允许的，但在单线程程序中使用线程局部变量没有实际意义，反而可能增加代码的复杂性。
* **与 `static` 关键字混淆：**  `static` 关键字在全局作用域中表示内部链接，在函数内部表示静态局部变量。与 `__thread` 的作用完全不同。
* **在不同的共享库之间共享 `__thread` 变量时可能遇到的问题：**  在某些情况下，如果不同的共享库中定义了同名的 `__thread` 变量，可能会导致意外的行为，因为动态链接器需要正确地管理这些变量的存储。

**7. 说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 Bionic 的路径（示例）：**

1. **Java 代码调用 NDK 方法：**  Android Framework 中的 Java 代码（例如 Activity、Service）通过 JNI (Java Native Interface) 调用 Native 代码。
   ```java
   // Java 代码
   public class MyClass {
       static {
           System.loadLibrary("my_native_lib");
       }
       public native void nativeMethod();
   }
   ```
2. **NDK 代码执行：**  NDK 中的 C/C++ 代码被执行。
   ```c++
   // my_native_lib.cpp
   #include <pthread.h>
   #include <stdio.h>

   __thread int thread_local_data = 123;

   void* thread_func(void*) {
       thread_local_data++;
       printf("Thread ID: %ld, TLS Data: %d\n", pthread_self(), thread_local_data);
       return nullptr;
   }

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_myapp_MyClass_nativeMethod(JNIEnv *env, jobject thiz) {
       pthread_t thread;
       pthread_create(&thread, nullptr, thread_func, nullptr);
       pthread_join(thread, nullptr);
       printf("Main thread TLS Data: %d\n", thread_local_data);
   }
   ```
3. **调用 Bionic 的 pthread 函数：**  NDK 代码中使用了 `pthread_create` 和 `pthread_join`，这些函数是 Bionic 提供的。
4. **Bionic 库的实现：**  Bionic 的 `pthread_create` 实现会调用底层的系统调用来创建线程，并管理线程局部存储。当创建新线程时，Bionic 会为该线程分配 TLS 块，并根据已加载的共享库的 TLS 模板进行初始化。

**Frida Hook 示例调试步骤：**

可以使用 Frida 来 hook `pthread_create` 函数，观察线程的创建过程。

```python
# frida hook 脚本

import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
        console.log("[+] pthread_create called");
        console.log("    Thread pointer:", args[0]);
        console.log("    Attributes:", args[1]);
        console.log("    Start routine:", args[2]);
        console.log("    Arg:", args[3]);
    },
    onLeave: function(retval) {
        console.log("[+] pthread_create returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 步骤解释：**

1. **导入 Frida 库。**
2. **指定要 hook 的应用包名。**
3. **连接到 USB 设备并附加到目标进程。**
4. **编写 Frida 脚本：**
   * 使用 `Interceptor.attach` 监听 `libc.so` 中的 `pthread_create` 函数。
   * 在 `onEnter` 中打印 `pthread_create` 的参数，包括线程指针、属性、启动函数和参数。
   * 在 `onLeave` 中打印返回值。
5. **加载并运行 Frida 脚本。**

**运行效果：** 当你的 Android 应用调用 `pthread_create` 创建新线程时，Frida 会拦截到这次调用，并打印出相关的参数信息，你可以从中观察到线程创建的细节。

如果需要更深入地调试 TLS 相关的功能，可以尝试 hook 与 TLS 管理相关的函数，例如 `__emutls_get_address` 或 Bionic 内部的 TLS 初始化函数（这需要更深入的 Bionic 源码知识）。

Prompt: 
```
这是目录为bionic/tests/thread_local_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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
#include <stdint.h>
#include <string.h>

__thread int local_var = 100;
int shared_var = 200;

static void reset_vars() {
  local_var = 1000;
  shared_var = 2000;
  // local_var should be reset by threads
}

typedef void* (*MyThread)(void*);

static void* inc_shared_var(void* p) {
  int *data = reinterpret_cast<int*>(p);
  shared_var++;
  *data = shared_var;
  return nullptr;
}

static void* inc_local_var(void* p) {
  int *data = reinterpret_cast<int*>(p);
  local_var++;
  *data = local_var;
  return nullptr;
}

static int run_one_thread(MyThread foo) {
  pthread_t t;
  int data;
  int error = pthread_create(&t, nullptr, foo, &data);
  if (!error)
      error = pthread_join(t, nullptr);
  return error ? error : data;
}

TEST(thread_local_storage, shared) {
  reset_vars();
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2000);

  // Update shared_var, local_var remains 1000.
  ASSERT_EQ(run_one_thread(inc_shared_var), 2001);
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2001);

  ASSERT_EQ(run_one_thread(inc_shared_var), 2002);
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2002);

  ASSERT_EQ(run_one_thread(inc_shared_var), 2003);
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2003);
}

TEST(thread_local_storage, local) {
  reset_vars();
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2000);

  // When a child thread updates its own TLS variable,
  // this thread's local_var and shared_var are not changed.
  // TLS local_var is initialized to 100 in a thread.
  ASSERT_EQ(run_one_thread(inc_local_var), 101);
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2000);

  ASSERT_EQ(run_one_thread(inc_local_var), 101);
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2000);

  ASSERT_EQ(run_one_thread(inc_local_var), 101);
  ASSERT_EQ(local_var, 1000);
  ASSERT_EQ(shared_var, 2000);
}

// Test TLS initialization of more complicated type, array of struct.
struct Point {
  int x, y;
};

typedef Point Triangle[3];

__thread Triangle local_triangle = {{10,10}, {20,20}, {30,30}};
Triangle shared_triangle = {{1,1}, {2,2}, {3,3}};

static void reset_triangle() {
  static const Triangle t1 = {{3,3}, {4,4}, {5,5}};
  static const Triangle t2 = {{2,2}, {3,3}, {4,4}};
  memcpy(local_triangle, t1, sizeof(local_triangle));
  memcpy(shared_triangle, t2, sizeof(shared_triangle));
}

static void* move_shared_triangle(void* p) {
  int *data = reinterpret_cast<int*>(p);
  shared_triangle[1].y++;
  *data = shared_triangle[1].y;
  return nullptr;
}

static void* move_local_triangle(void* p) {
  int *data = reinterpret_cast<int*>(p);
  local_triangle[1].y++;
  *data = local_triangle[1].y;
  return nullptr;
}

TEST(thread_local_storage, shared_triangle) {
  reset_triangle();
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 3);

  // Update shared_triangle, local_triangle remains 1000.
  ASSERT_EQ(run_one_thread(move_shared_triangle), 4);
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 4);

  ASSERT_EQ(run_one_thread(move_shared_triangle), 5);
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 5);

  ASSERT_EQ(run_one_thread(move_shared_triangle), 6);
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 6);
}

TEST(thread_local_storage, local_triangle) {
  reset_triangle();
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 3);

  // Update local_triangle, parent thread's
  // shared_triangle and local_triangle are unchanged.
  ASSERT_EQ(run_one_thread(move_local_triangle), 21);
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 3);

  ASSERT_EQ(run_one_thread(move_local_triangle), 21);
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 3);

  ASSERT_EQ(run_one_thread(move_local_triangle), 21);
  ASSERT_EQ(local_triangle[1].y, 4);
  ASSERT_EQ(shared_triangle[1].y, 3);
}

// Test emutls runtime data structures and __emutls_get_address function.
typedef unsigned int gcc_word __attribute__((mode(word)));
typedef unsigned int gcc_pointer __attribute__((mode(pointer)));
struct gcc_emutls_object {  // for libgcc
  gcc_word size;
  gcc_word align;
  union {
    gcc_pointer offset;
    void* ptr;
  } loc;
  void* templ;
};

typedef struct __emutls_control {  // for clang/llvm
  size_t size;
  size_t align;
  union {
    uintptr_t index;
    void* address;
  } object;
  void* value;
} __emutls_control;

TEST(thread_local_storage, type_size) {
  static_assert(sizeof(size_t) == sizeof(gcc_word),
                "size_t != gcc_word");
  static_assert(sizeof(uintptr_t) == sizeof(gcc_pointer),
                "uintptr_t != gcc_pointer");
  static_assert(sizeof(uintptr_t) == sizeof(void*),
                "sizoeof(uintptr_t) != sizeof(void*)");
  static_assert(sizeof(__emutls_control) == sizeof(struct gcc_emutls_object),
                "sizeof(__emutls_control) != sizeof(struct gcc_emutls_object)");
}

extern "C" void* __emutls_get_address(__emutls_control*);

TEST(thread_local_storage, init_value) {
  char tls_value1[] = "123456789";
  char tls_value2[] = "abcdefghi";
  constexpr size_t num_saved_values = 10;
  __emutls_control tls_var[num_saved_values];
  size_t prev_index = 0;
  void* saved_gap[num_saved_values];
  void* saved_p[num_saved_values];
  ASSERT_TRUE(strlen(tls_value2) <= strlen(tls_value1));
  __emutls_control c =
      {strlen(tls_value1) + 1, 1, {0}, tls_value1};
  for (size_t n = 0; n < num_saved_values; n++) {
    memcpy(&tls_var[n], &c, sizeof(c));
    tls_var[n].align = (1 << n);
  }
  for (size_t n = 0; n < num_saved_values; n++) {
    // Try to mess up malloc space so that the next malloc will not have the
    // required alignment, but __emutls_get_address should still return an
    // aligned address.
    saved_gap[n] = malloc(1);
    void* p = __emutls_get_address(&tls_var[n]);
    saved_p[n] = p;
    ASSERT_TRUE(p != nullptr);
    ASSERT_TRUE(tls_var[n].object.index != 0);
    // check if p is a new object.
    if (n > 0) {
      // In single-thread environment, object.address == p.
      // In multi-threads environment, object.index is increased.
      ASSERT_TRUE(prev_index + 1 == tls_var[n].object.index ||
                  p == tls_var[n].object.address);
      ASSERT_TRUE(p != saved_p[n - 1]);
    }
    prev_index = tls_var[n].object.index;
    // check if p is aligned
    uintptr_t align = (1 << n);
    uintptr_t address= reinterpret_cast<uintptr_t>(p);
    ASSERT_EQ((address & ~(align - 1)), address);
    // check if *p is initialized
    ASSERT_STREQ(tls_value1, static_cast<char*>(p));
    // change value in *p
    memcpy(p, tls_value2, strlen(tls_value2) + 1);
  }
  for (size_t n = 0; n < num_saved_values; n++) {
    free(saved_gap[n]);
  }
  for (size_t n = 0; n < num_saved_values; n++) {
    void* p = __emutls_get_address(&tls_var[n]);
    ASSERT_EQ(p, saved_p[n]);
    // check if *p has the new value
    ASSERT_STREQ(tls_value2, static_cast<char*>(p));
  }
}

"""

```