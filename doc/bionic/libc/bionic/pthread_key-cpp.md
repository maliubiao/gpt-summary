Response:
Let's break down the thought process for analyzing the provided `pthread_key.cpp` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `pthread_key.cpp` file within the context of Android's Bionic library. This means focusing on its function, relation to Android, implementation details, dynamic linking aspects, potential errors, and how it's used within the Android ecosystem.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to grasp its overall purpose. Keywords like `pthread_key`, `destructor`, `TLS` (implied by `__get_bionic_tls`), and atomic operations immediately suggest this file deals with thread-local storage keys and their management.

**3. Deconstructing the File Section by Section:**

A systematic approach is crucial. I'll go through the code, commenting mentally (and later, explicitly in the response) on each part:

* **Copyright and Includes:**  Standard boilerplate, not directly functional, but good to note the origin. The includes (`errno.h`, `pthread.h`, `stdatomic.h`, etc.) hint at the dependencies.
* **Typedefs and Defines:** `key_destructor_t` is straightforward. The `SEQ_KEY_IN_USE_BIT` and `SEQ_INCREMENT_STEP` are important for understanding the internal state management of keys.
* **`pthread_key_internal_t` struct:** This is a core data structure. The `seq` and `key_destructor` members are central to the key's lifecycle and cleanup. The comment about `seq` being a sequence number, not just a boolean, is key to understanding the logic for preventing stale data.
* **`key_map` array:** This is the global storage for the `pthread_key_internal_t` structures, limiting the number of available keys.
* **`SeqOfKeyInUse` inline function:** A simple helper to check the "in use" bit.
* **`KEY_VALID_FLAG` and `KeyInValidRange`:**  These define the valid range and encoding for `pthread_key_t` values. The comment explaining the bit manipulation is important.
* **`get_thread_key_data` inline function:** This clearly points to the usage of thread-local storage (`__get_bionic_tls`).
* **`pthread_key_clean_all` function:** This is the destructor invocation logic when a thread exits. The loop and the `rounds` variable (from `PTHREAD_DESTRUCTOR_ITERATIONS`) indicate a mechanism to handle potential cascading effects of destructors. The careful handling of atomic operations and sequence numbers is crucial here.
* **`pthread_key_create` function:** The logic for finding a free key slot and marking it as used. The atomic compare-and-exchange is the core of the thread-safe allocation.
* **`pthread_key_delete` function:**  How keys are marked as invalid. Crucially, it *doesn't* call destructors directly.
* **`pthread_getspecific` function:**  Retrieving thread-specific data associated with a key. The sequence number check is again important for correctness.
* **`pthread_setspecific` function:**  Setting the thread-specific data for a key.

**4. Answering the Specific Questions:**

With a good understanding of the code, I can now address each part of the request:

* **功能 (Functions):**  Summarize the purpose of each exposed function (`pthread_key_create`, `pthread_key_delete`, `pthread_getspecific`, `pthread_setspecific`) and the internal `pthread_key_clean_all`.
* **与 Android 的关系 (Relationship with Android):**  Explain that this is a fundamental part of Bionic, Android's C library. Give examples of how thread-local storage is used in Android (e.g., `errno`, per-thread data in libraries).
* **libc 函数实现 (libc Function Implementation):**  Go into detail on the implementation of each function, explaining the use of atomic operations, sequence numbers, and the `key_map`.
* **dynamic linker 功能 (Dynamic Linker Functionality):** The `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` macro is the key here. Explain its purpose in allowing overriding in native bridges. Provide a sample SO layout and explain the linking process, including symbol resolution.
* **逻辑推理 (Logical Reasoning):** For `pthread_key_create`, walk through a scenario of finding an available slot. For `pthread_getspecific`, illustrate the sequence number check and how it prevents stale data.
* **用户或编程常见错误 (Common User Errors):**  Highlight common mistakes like using uninitialized keys, forgetting to delete keys, and destructor issues (infinite loops, use-after-free).
* **Android Framework/NDK 到达路径 (Path from Android Framework/NDK):**  Trace the call stack from a high-level Android component (e.g., a Java thread calling native code) down to the `pthread` functions.
* **Frida Hook 示例 (Frida Hook Example):** Provide concrete Frida code snippets to intercept calls to the `pthread_key_*` functions and inspect their arguments and return values.

**5. Structuring the Response:**

Organize the information logically with clear headings and subheadings to make it easy to read and understand. Use code formatting and examples where appropriate. Maintain a consistent and professional tone. Translate technical terms accurately into Chinese.

**Self-Correction/Refinement during the Process:**

* **Initially, I might have overlooked the significance of the `SEQ_INCREMENT_STEP` value.**  Realizing it's not just `+1` but `1 << SEQ_KEY_IN_USE_BIT` prompts a deeper understanding of how the "in use" bit toggles.
* **The explanation of the sequence number's purpose needs to be clear and concise.**  Emphasize how it solves the stale data problem when keys are reused.
* **The dynamic linker section requires careful explanation of weak symbols and the role of the native bridge.**  A concrete SO layout example is essential for clarity.
* **The Frida hook examples should be practical and easy to adapt.**  Showing how to hook different functions and inspect arguments is key.

By following these steps, systematically analyzing the code, and carefully addressing each aspect of the request, I can generate a comprehensive and informative response like the example provided. The key is to go beyond simply describing the code and to explain *why* it's implemented in a particular way and how it fits into the larger Android ecosystem.
好的，让我们详细分析一下 `bionic/libc/bionic/pthread_key.cpp` 这个文件。

**功能概览**

该文件实现了 POSIX 标准中关于线程特定数据（Thread-Specific Data，TSD）的功能，主要涉及以下几个方面：

1. **创建线程特定数据键 (Key Creation):**  允许线程创建一个全局唯一的键，用于关联线程特定的数据。
2. **删除线程特定数据键 (Key Deletion):**  释放已创建的键，使其可以被重新使用。
3. **设置线程特定数据 (Setting TSD):**  将指定的数据与当前线程和指定的键关联起来。
4. **获取线程特定数据 (Getting TSD):**  检索当前线程与指定键关联的数据。
5. **线程退出时的清理 (Thread Exit Cleanup):**  在线程退出时，自动调用与键关联的析构函数（如果有），以释放线程特定的资源。

**与 Android 功能的关系及举例**

线程特定数据在 Android 系统中被广泛使用，用于管理与特定线程相关的状态和资源，而无需使用全局变量或显式传递参数。以下是一些例子：

* **`errno` 的实现:**  在多线程环境中，每个线程都有自己的 `errno` 变量。`pthread_key_create`、`pthread_getspecific` 和 `pthread_setspecific` 被用来实现这种线程局部存储，确保一个线程的错误不会影响其他线程的错误状态。
* **本地库中的线程局部变量:**  许多本地库（通过 NDK 使用）可能需要维护一些线程特定的状态。例如，一个网络库可能需要为每个处理请求的线程维护其连接信息。
* **`dlerror()` 的实现:**  `dlerror()` 函数用于获取动态链接错误信息。由于错误可能发生在不同的线程中，因此需要使用线程特定数据来存储每个线程的错误信息。
* **OpenGL ES 上下文管理:**  在某些 OpenGL ES 的实现中，每个线程可能需要维护自己的渲染上下文。

**libc 函数的实现细节**

1. **`pthread_key_create(pthread_key_t* key, void (*key_destructor)(void*))`**

   * **目标:** 创建一个新的线程特定数据键。
   * **实现:**
     * 遍历全局的 `key_map` 数组，查找一个未使用的槽位。`key_map` 是一个 `pthread_key_internal_t` 类型的数组，用于管理所有可用的键。
     * `pthread_key_internal_t` 结构体包含：
       * `seq`: 一个原子 `uintptr_t`，用于记录槽位的使用状态。最低位（`SEQ_KEY_IN_USE_BIT`）为 1 表示正在使用，0 表示未使用。每次创建或删除键时，`seq` 的值会增加 `SEQ_INCREMENT_STEP`，这会翻转最低位，并增加高位的值。使用序列号而不是简单的布尔值是为了防止在键被删除并重新使用时，`pthread_getspecific` 返回旧数据。
       * `key_destructor`: 一个原子 `uintptr_t`，存储与该键关联的析构函数的地址。
     * 使用原子操作 `atomic_compare_exchange_weak` 来尝试获取一个空闲槽位。如果成功获取，则将该槽位的 `seq` 标记为已使用，并存储提供的析构函数。
     * 将分配的槽位索引（加上 `KEY_VALID_FLAG`）赋值给 `*key`。`KEY_VALID_FLAG` 用于标记这是一个有效的键，并将其与普通的整数区分开来。
     * 如果没有空闲槽位，则返回 `EAGAIN`。

2. **`pthread_key_delete(pthread_key_t key)`**

   * **目标:** 删除一个已存在的线程特定数据键。
   * **实现:**
     * 首先检查 `key` 的有效性，确保其在有效范围内。
     * 通过位运算 `key &= ~KEY_VALID_FLAG` 获取实际的槽位索引。
     * 使用原子操作增加 `key_map` 中对应槽位的 `seq` 值。这会使所有线程中与该键关联的数据失效，因为线程本地存储中对应数据的 `seq` 将不再匹配。
     * 标准规定 `pthread_key_delete` 不会调用与键关联的析构函数。资源的释放是调用者的责任。

3. **`pthread_getspecific(pthread_key_t key)`**

   * **目标:** 获取当前线程与指定键关联的数据。
   * **实现:**
     * 首先检查 `key` 的有效性。
     * 通过位运算 `key &= ~KEY_VALID_FLAG` 获取实际的槽位索引。
     * 从全局 `key_map` 中加载对应键的当前 `seq` 值。
     * 调用 `get_thread_key_data()` 获取当前线程的线程特定数据存储区域。这个函数返回一个指向 `pthread_key_data_t` 数组的指针，该数组的大小与 `key_map` 相同。
     * `pthread_key_data_t` 结构体（定义在其他头文件中，例如 `pthread_internal.h`）通常包含一个 `void* data` 成员用于存储实际的数据，以及一个 `uintptr_t seq` 成员，用于存储创建该数据时对应键的 `seq` 值。
     * 检查全局 `key_map` 中键的 `seq` 是否与当前线程的线程特定数据存储中对应槽位的 `seq` 相匹配，并且键是否正在使用 (`SeqOfKeyInUse(seq)`)。如果匹配，则返回存储的数据。
     * 如果不匹配，说明当前线程持有的数据是之前已删除的键的，因此将当前线程存储的数据指针设置为 `nullptr`，并返回 `nullptr`。

4. **`pthread_setspecific(pthread_key_t key, const void* ptr)`**

   * **目标:** 将给定的指针与当前线程和指定的键关联起来。
   * **实现:**
     * 首先检查 `key` 的有效性。
     * 通过位运算 `key &= ~KEY_VALID_FLAG` 获取实际的槽位索引。
     * 从全局 `key_map` 中加载对应键的当前 `seq` 值。
     * 如果键正在使用，则调用 `get_thread_key_data()` 获取当前线程的线程特定数据存储区域，并将数据指针 `ptr` 和当前的 `seq` 值存储到对应的槽位中。

5. **`pthread_key_clean_all()`**

   * **目标:** 在线程退出时清理所有线程特定数据。
   * **实现:**
     * 这个函数在 `pthread_exit()` 中被调用。
     * 它会循环多次（最多 `PTHREAD_DESTRUCTOR_ITERATIONS` 次，通常为 4），因为析构函数可能会创建或删除其他的键。
     * 对于每个已使用的键，检查当前线程是否关联了数据，并且该键是否有析构函数。
     * 为了避免在其他线程正在创建/删除键时读取到错误的析构函数，它会先加载析构函数，然后再次检查全局 `key_map` 中的 `seq` 值是否与之前读取的一致。这确保了要么读取到正确的析构函数，要么检测到 `seq` 值已更改，从而避免使用新创建的键的析构函数。
     * 如果存在析构函数，则先将当前线程存储的数据指针设置为 `nullptr`（防止析构函数或后续析构函数看到旧值），然后调用析构函数。
     * 如果在一轮循环中没有调用任何析构函数，则退出循环。

**涉及 dynamic linker 的功能**

`__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 宏表明这些函数是弱符号，主要用于 Native Bridge 的场景。Native Bridge 允许在 Android 系统上运行非 Android 原生的代码，例如 ARM 架构的 Android 系统运行 x86 的程序。

**SO 布局样本和链接处理过程**

假设我们有两个 SO 文件：`libnative.so` (原生库) 和 `libnativebridge.so` (Native Bridge 库)。

**`libnative.so`:**

```
[地址范围]  节名   大小   对齐
----------------------------------
...
[数据段]
  [符号表]
    pthread_key_create (UND)  // 未定义的弱符号
    pthread_getspecific (UND)
    ...
[动态符号表]
    // 可能包含其他导出的符号
```

**`libnativebridge.so`:**

```
[地址范围]  节名   大小   对齐
----------------------------------
...
[文本段]
  [实现 pthread_key_create 等函数的替代版本]
    // ... 实现 ...
[数据段]
  [符号表]
    pthread_key_create (WEAK) // 定义了弱符号
    pthread_getspecific (WEAK)
    ...
[动态符号表]
    pthread_key_create
    pthread_getspecific
    ...
```

**链接处理过程:**

1. 当 `libnative.so` 被加载时，链接器会解析其未定义的符号。
2. 对于 `pthread_key_create` 等使用 `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 标记的符号，链接器会首先查找强符号定义。
3. 如果在 `libnativebridge.so` 中找到了同名的强符号（通常情况下 Native Bridge 会提供这些函数的替代实现），则 `libnative.so` 会链接到 `libnativebridge.so` 提供的实现。
4. 如果没有找到强符号，由于这些符号是弱符号，链接器不会报错，而是将这些符号的地址设置为 0 或者一个特殊的占位符。
5. 在 Native Bridge 的场景中，`libnativebridge.so` 会在运行时被加载，并且会提供这些弱符号的实现。由于链接器在处理弱符号时具有特殊性，即使 `libnative.so` 最初没有链接到具体的实现，当 `libnativebridge.so` 加载后，后续对这些弱符号的调用可能会被动态地绑定到 `libnativebridge.so` 提供的实现上。

**假设输入与输出（逻辑推理）**

**场景：`pthread_key_create`**

* **假设输入:** `pthread_key_t key; void (*destructor)(void*) = my_destructor;`，并且 `key_map` 中存在一个空闲槽位（例如，索引为 5 的槽位是空闲的）。
* **输出:**
    * `key` 的值将被设置为 `5 | KEY_VALID_FLAG` (假设 `KEY_VALID_FLAG` 的值为 `0x80000000`，则 `key` 的值为 `0x80000005`)。
    * `key_map[5].seq` 的最低位将被设置为 1，表示该槽位正在使用，并且其高位的值会增加。
    * `key_map[5].key_destructor` 将被设置为 `my_destructor` 的地址。
    * 函数返回 0。

**场景：`pthread_getspecific`**

* **假设输入:** `pthread_key_t key = 0x80000005;` (对应于上面创建的键)，当前线程已经使用 `pthread_setspecific` 将数据 `my_data` 与该键关联，并且全局 `key_map[5].seq` 的值与当前线程存储的 `seq` 值相同。
* **输出:** 函数将返回 `my_data` 的指针。

**用户或编程常见的使用错误**

1. **使用未初始化的键:** 在调用 `pthread_setspecific` 或 `pthread_getspecific` 之前没有调用 `pthread_key_create` 初始化键。这会导致访问无效的内存地址。
   ```c++
   pthread_key_t key;
   pthread_setspecific(key, my_data); // 错误：key 未初始化
   ```

2. **忘记删除键:**  创建的键如果没有被 `pthread_key_delete` 删除，虽然不会造成内存泄漏（因为线程退出时会清理），但会导致键资源无法被重用。

3. **析构函数中的错误:** 析构函数可能执行错误的操作，例如释放了错误的内存，或者引发异常。由于析构函数在线程退出时自动调用，这些错误可能难以追踪。

4. **竞争条件:**  在多线程环境下，多个线程可能同时尝试创建或删除相同的键，或者在析构函数执行期间修改全局状态，可能导致意想不到的结果。虽然代码中使用了原子操作，但业务逻辑上的并发问题仍然需要注意。

5. **过度依赖析构函数的执行顺序:**  由于析构函数的执行顺序是不确定的，并且会进行多次迭代，因此不应依赖于析构函数执行的特定顺序或次数。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 层):**
   - Java 代码中可以使用 `ThreadLocal` 类来创建线程局部变量。
   - 当 Native 代码需要访问这些 Java 层的线程局部变量时，会通过 JNI 调用到 Native 代码。

2. **NDK (Native 层):**
   - Native 代码可以直接调用 `pthread_key_create`、`pthread_setspecific`、`pthread_getspecific` 和 `pthread_key_delete` 这些 POSIX 标准的线程 API。
   - 许多 Android 系统库（例如 `libcutils`，`libbinder` 等）内部使用了这些 pthread 相关的 API。

**示例调用路径：**

假设一个 Java 线程调用了一个 Native 方法，该 Native 方法需要使用线程局部存储：

```
// Java 代码
public class MyClass {
    private static final ThreadLocal<String> myThreadLocal = new ThreadLocal<>();

    public native void myNativeMethod();

    public void someMethod() {
        myThreadLocal.set("Hello from Java");
        myNativeMethod();
        String value = myThreadLocal.get();
        // ...
    }
}
```

```c++
// Native 代码 (my_class.cpp)
#include <pthread.h>
#include <jni.h>
#include <android/log.h>

static pthread_key_t my_native_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void create_my_native_key() {
    pthread_key_create(&my_native_key, nullptr); // 创建一个简单的 key，没有析构函数
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MyClass_myNativeMethod(JNIEnv *env, jobject thiz) {
    pthread_once(&key_once, create_my_native_key);

    const char* data = "Hello from Native";
    pthread_setspecific(my_native_key, data);

    const char* retrieved_data = static_cast<const char*>(pthread_getspecific(my_native_key));
    __android_log_print(ANDROID_LOG_INFO, "MyTag", "Retrieved data: %s", retrieved_data);
}
```

在这个例子中，虽然 Java 层使用了 `ThreadLocal`，但 Native 代码也可以直接使用 `pthread_key_*` 函数来管理线程局部数据。当 `myNativeMethod` 被调用时，它会通过 `pthread_setspecific` 将数据与 `my_native_key` 关联起来，然后在同一个线程中通过 `pthread_getspecific` 获取该数据。

**Frida Hook 示例调试**

以下是使用 Frida Hook 拦截 `pthread_key_create` 和 `pthread_setspecific` 的示例：

```javascript
if (Process.platform === 'android') {
  const pthread_key_create = Module.findExportByName(null, "pthread_key_create");
  if (pthread_key_create) {
    Interceptor.attach(pthread_key_create, {
      onEnter: function (args) {
        console.log("[pthread_key_create] key:", args[0], "destructor:", args[1]);
      },
      onLeave: function (retval) {
        console.log("[pthread_key_create] returned:", retval);
      }
    });
  }

  const pthread_setspecific = Module.findExportByName(null, "pthread_setspecific");
  if (pthread_setspecific) {
    Interceptor.attach(pthread_setspecific, {
      onEnter: function (args) {
        console.log("[pthread_setspecific] key:", args[0], "ptr:", args[1]);
      },
      onLeave: function (retval) {
        console.log("[pthread_setspecific] returned:", retval);
      }
    });
  }
} else {
  console.log("This script is designed for Android.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `pthread_hook.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <包名> -l pthread_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <包名> -l pthread_hook.js
   ```

**预期输出:**

当目标进程调用 `pthread_key_create` 或 `pthread_setspecific` 时，Frida 控制台将打印出相应的日志信息，包括函数的参数和返回值，帮助你调试这些步骤。

希望这个详细的分析能够帮助你理解 `bionic/libc/bionic/pthread_key.cpp` 的功能和实现细节，以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/pthread_key.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

#include "private/bionic_defs.h"
#include "private/bionic_tls.h"
#include "pthread_internal.h"

typedef void (*key_destructor_t)(void*);

#define SEQ_KEY_IN_USE_BIT     0

#define SEQ_INCREMENT_STEP  (1 << SEQ_KEY_IN_USE_BIT)

// pthread_key_internal_t records the use of each pthread key slot:
//   seq records the state of the slot.
//      bit 0 is 1 when the key is in use, 0 when it is unused. Each time we create or delete the
//      pthread key in the slot, we increse the seq by 1 (which inverts bit 0). The reason to use
//      a sequence number instead of a boolean value here is that when the key slot is deleted and
//      reused for a new key, pthread_getspecific will not return stale data.
//   key_destructor records the destructor called at thread exit.
struct pthread_key_internal_t {
  atomic_uintptr_t seq;
  atomic_uintptr_t key_destructor;
};

static pthread_key_internal_t key_map[BIONIC_PTHREAD_KEY_COUNT];

static inline bool SeqOfKeyInUse(uintptr_t seq) {
  return seq & (1 << SEQ_KEY_IN_USE_BIT);
}

#define KEY_VALID_FLAG (1 << 31)

static_assert(sizeof(pthread_key_t) == sizeof(int) && static_cast<pthread_key_t>(-1) < 0,
              "pthread_key_t should be typedef to int");

static inline bool KeyInValidRange(pthread_key_t key) {
  // key < 0 means bit 31 is set.
  // Then key < (2^31 | BIONIC_PTHREAD_KEY_COUNT) means the index part of key < BIONIC_PTHREAD_KEY_COUNT.
  return (key < (KEY_VALID_FLAG | BIONIC_PTHREAD_KEY_COUNT));
}

static inline pthread_key_data_t* get_thread_key_data() {
  return __get_bionic_tls().key_data;
}

// Called from pthread_exit() to remove all pthread keys. This must call the destructor of
// all keys that have a non-NULL data value and a non-NULL destructor.
__LIBC_HIDDEN__ void pthread_key_clean_all() {
  // Because destructors can do funky things like deleting/creating other keys,
  // we need to implement this in a loop.
  pthread_key_data_t* key_data = get_thread_key_data();
  for (size_t rounds = PTHREAD_DESTRUCTOR_ITERATIONS; rounds > 0; --rounds) {
    size_t called_destructor_count = 0;
    for (size_t i = 0; i < BIONIC_PTHREAD_KEY_COUNT; ++i) {
      uintptr_t seq = atomic_load_explicit(&key_map[i].seq, memory_order_relaxed);
      if (SeqOfKeyInUse(seq) && seq == key_data[i].seq && key_data[i].data != nullptr) {
        // Other threads may be calling pthread_key_delete/pthread_key_create while current thread
        // is exiting. So we need to ensure we read the right key_destructor.
        // We can rely on a user-established happens-before relationship between the creation and
        // use of pthread key to ensure that we're not getting an earlier key_destructor.
        // To avoid using the key_destructor of the newly created key in the same slot, we need to
        // recheck the sequence number after reading key_destructor. As a result, we either see the
        // right key_destructor, or the sequence number must have changed when we reread it below.
        key_destructor_t key_destructor = reinterpret_cast<key_destructor_t>(
          atomic_load_explicit(&key_map[i].key_destructor, memory_order_relaxed));
        if (key_destructor == nullptr) {
          continue;
        }
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load_explicit(&key_map[i].seq, memory_order_relaxed) != seq) {
           continue;
        }

        // We need to clear the key data now, this will prevent the destructor (or a later one)
        // from seeing the old value if it calls pthread_getspecific().
        // We don't do this if 'key_destructor == NULL' just in case another destructor
        // function is responsible for manually releasing the corresponding data.
        void* data = key_data[i].data;
        key_data[i].data = nullptr;

        (*key_destructor)(data);
        ++called_destructor_count;
      }
    }

    // If we didn't call any destructors, there is no need to check the pthread keys again.
    if (called_destructor_count == 0) {
      break;
    }
  }
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int pthread_key_create(pthread_key_t* key, void (*key_destructor)(void*)) {
  for (size_t i = 0; i < BIONIC_PTHREAD_KEY_COUNT; ++i) {
    uintptr_t seq = atomic_load_explicit(&key_map[i].seq, memory_order_relaxed);
    while (!SeqOfKeyInUse(seq)) {
      if (atomic_compare_exchange_weak(&key_map[i].seq, &seq, seq + SEQ_INCREMENT_STEP)) {
        atomic_store(&key_map[i].key_destructor, reinterpret_cast<uintptr_t>(key_destructor));
        *key = i | KEY_VALID_FLAG;
        return 0;
      }
    }
  }
  return EAGAIN;
}

// Deletes a pthread_key_t. note that the standard mandates that this does
// not call the destructors for non-NULL key values. Instead, it is the
// responsibility of the caller to properly dispose of the corresponding data
// and resources, using any means it finds suitable.
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int pthread_key_delete(pthread_key_t key) {
  if (__predict_false(!KeyInValidRange(key))) {
    return EINVAL;
  }
  key &= ~KEY_VALID_FLAG;
  // Increase seq to invalidate values in all threads.
  uintptr_t seq = atomic_load_explicit(&key_map[key].seq, memory_order_relaxed);
  if (SeqOfKeyInUse(seq)) {
    if (atomic_compare_exchange_strong(&key_map[key].seq, &seq, seq + SEQ_INCREMENT_STEP)) {
      return 0;
    }
  }
  return EINVAL;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void* pthread_getspecific(pthread_key_t key) {
  if (__predict_false(!KeyInValidRange(key))) {
    return nullptr;
  }
  key &= ~KEY_VALID_FLAG;
  uintptr_t seq = atomic_load_explicit(&key_map[key].seq, memory_order_relaxed);
  pthread_key_data_t* data = &get_thread_key_data()[key];
  // It is user's responsibility to synchornize between the creation and use of pthread keys,
  // so we use memory_order_relaxed when checking the sequence number.
  if (__predict_true(SeqOfKeyInUse(seq) && data->seq == seq)) {
    return data->data;
  }
  // We arrive here when current thread holds the seq of an deleted pthread key. So the
  // data is for the deleted pthread key, and should be cleared.
  data->data = nullptr;
  return nullptr;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int pthread_setspecific(pthread_key_t key, const void* ptr) {
  if (__predict_false(!KeyInValidRange(key))) {
    return EINVAL;
  }
  key &= ~KEY_VALID_FLAG;
  uintptr_t seq = atomic_load_explicit(&key_map[key].seq, memory_order_relaxed);
  if (__predict_true(SeqOfKeyInUse(seq))) {
    pthread_key_data_t* data = &get_thread_key_data()[key];
    data->seq = seq;
    data->data = const_cast<void*>(ptr);
    return 0;
  }
  return EINVAL;
}

"""

```