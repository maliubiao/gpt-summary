Response:
Let's break down the thought process to answer the request about the `macros.handroid.h` file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided C header file (`macros.handroid.h`). Key aspects requested are:

* **Functionality:** What do the macros in the file do?
* **Android Relevance:** How do these macros relate to the Android operating system? Provide specific examples.
* **Libc Function Details:**  Explain how each libc function mentioned is implemented. (Initial thought: *Wait, there are no direct libc function implementations in this *header* file. The macros likely *use* libc functions.* This distinction is crucial).
* **Dynamic Linker Relevance:** Discuss macros related to the dynamic linker, including SO layout and linking processes.
* **Logic Inference:**  Provide examples of input and output for macros that perform calculations or transformations.
* **Common Usage Errors:** Highlight potential mistakes developers might make when using these macros.
* **Android Framework/NDK Journey:** Describe how the Android framework or NDK leads to the use of these macros, and provide a Frida hook example.

**2. Initial Scan and Categorization of Macros:**

The first step is to go through the file and identify the purpose of each macro. I'd group them based on their function:

* **Disabling Copying/Assignment:** `BIONIC_DISALLOW_COPY_AND_ASSIGN`, `BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS`
* **Rounding Up to Power of 2:** `BIONIC_ROUND_UP_POWER_OF_2`
* **Stopping Unwinding:** `BIONIC_STOP_UNWIND`
* **Calculating Array Size:** `arraysize`, `ArraySizeHelper`
* **Explicit Fallthrough:** `__BIONIC_FALLTHROUGH`
* **Untagging Addresses (for MTE):** `untag_address` (both versions)
* **Memory Tagging Global Annotation:** `BIONIC_USED_BEFORE_LINKER_RELOCATES`

**3. Analyzing Each Macro in Detail:**

For each macro, I would think through its implementation and purpose:

* **`BIONIC_DISALLOW_COPY_AND_ASSIGN` & `BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS`:** These are standard C++ idioms for preventing unintended object copying or creation. Relate this to resource management and preventing dangling pointers.
* **`BIONIC_ROUND_UP_POWER_OF_2`:**  This involves bit manipulation. I'd analyze the logic using `__builtin_clz` (count leading zeros) and bit shifting. Consider the differences for 32-bit and 64-bit values. Example input/output would be helpful here.
* **`BIONIC_STOP_UNWIND`:** This macro injects assembly instructions that mark the end of a stack unwinding sequence for exception handling or stack unwinding after a crash. The specific assembly varies by architecture.
* **`arraysize` & `ArraySizeHelper`:** This is a clever C++ template trick. Explain how `ArraySizeHelper`'s type deduction and `sizeof` work together to get the array size at compile time. Highlight the error when used with pointers.
* **`__BIONIC_FALLTHROUGH`:**  This is about code clarity and silencing compiler warnings for intentional fallthrough in `switch` statements.
* **`untag_address`:** This directly relates to Memory Tagging Extension (MTE). Explain the concept of address tagging and how this macro masks out the tag bits. Highlight the architecture-specific nature.
* **`BIONIC_USED_BEFORE_LINKER_RELOCATES`:** This is a very specific macro related to the dynamic linker and MTE. Explain the issue of accessing globals before relocation and how this attribute resolves it.

**4. Connecting to Android:**

Now, integrate the understanding of each macro with its relevance to Android:

* **General Utility:** Macros like disallowing copy/assignment and array size are good programming practices used throughout Android's codebase.
* **System-Level Aspects:**  `BIONIC_STOP_UNWIND` is crucial for exception handling and debugging on Android. `untag_address` is specific to Android's adoption of MTE.
* **Dynamic Linking:** `BIONIC_USED_BEFORE_LINKER_RELOCATES` is directly tied to the Android dynamic linker's behavior with MTE.

**5. Addressing Specific Points from the Request:**

* **Libc Function Implementation:**  Clarify that the *header* file doesn't implement libc functions but *uses* their functionality (e.g., `sizeof`). No need to explain the implementation of `sizeof`.
* **Dynamic Linker Details:** Focus on `BIONIC_USED_BEFORE_LINKER_RELOCATES`. Explain *why* this macro is needed in the context of the linker and MTE. Provide a simple SO layout example to illustrate the GOT and global variables. Describe the linking process conceptually.
* **Logic Inference:**  Focus on `BIONIC_ROUND_UP_POWER_OF_2` and show input/output.
* **Common Errors:**  Give examples for `arraysize` (using it with a pointer) and potentially misunderstanding the purpose of the "disallow" macros.
* **Android Framework/NDK Journey & Frida Hook:**  Trace a simplified path from an app using an NDK function that eventually relies on bionic. Provide a basic Frida hook example targeting a function where `arraysize` might be used, demonstrating how to inspect its value.

**6. Structuring the Answer:**

Organize the answer logically, addressing each part of the request systematically. Use clear headings and bullet points. Start with a general overview of the file's purpose and then delve into the details of each macro.

**7. Refinement and Language:**

Ensure the language is clear, concise, and accurate. Use technical terms correctly but provide explanations where necessary. Review and refine the answer for clarity and completeness. For instance, ensure the explanation of MTE is understandable without requiring deep prior knowledge.

**Self-Correction Example During the Process:**

Initially, I might have thought I needed to explain the implementation of `sizeof`. However, realizing that `sizeof` is an operator and not a function with a typical implementation within this header file, I'd correct my approach to focus on *how* the macros *use* `sizeof`. Similarly, with `__builtin_clz`,  I would describe its functionality rather than trying to provide its C code implementation, as it's a compiler intrinsic.
这是一个定义宏的 C 头文件，位于 Android Bionic 库中。Bionic 是 Android 的 C 库、数学库和动态链接器。这个文件名为 `macros.handroid`，很可能包含了一些 Android 特有的或者在 Bionic 中广泛使用的宏定义。

下面我们来详细列举它的功能，并结合 Android 的特性进行说明：

**1. 禁止拷贝和赋值 (`BIONIC_DISALLOW_COPY_AND_ASSIGN`)**

* **功能:**  这个宏用于禁止类的拷贝构造函数和拷贝赋值运算符。这意味着你无法通过拷贝的方式创建一个类的副本，或者将一个对象赋值给另一个对象。
* **实现:** 它通过将拷贝构造函数和拷贝赋值运算符声明为 `delete` 来实现。`delete` 是 C++11 引入的关键字，用于显式禁用函数的生成。
* **Android 关系:** 在 Android 系统编程中，某些类可能管理着重要的系统资源（例如文件描述符、内存等），或者具有唯一的身份标识。禁止拷贝和赋值可以防止资源被意外复制，导致资源泄露或状态不一致的问题。
* **举例说明:** 假设有一个类 `AudioFlingerClient` 代表与音频服务的连接。拷贝这个连接可能会导致多个客户端尝试控制同一个音频流，从而引发冲突。使用 `BIONIC_DISALLOW_COPY_AND_ASSIGN` 可以防止这种错误。
* **用户/编程常见错误:**  新手程序员可能会尝试直接拷贝或赋值这种类型的对象，导致编译错误。

**2. 禁止隐式构造 (`BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS`)**

* **功能:**  这个宏用于禁止类的默认构造函数以及拷贝构造函数和拷贝赋值运算符。这表示该类的对象必须通过特定的构造函数来创建，并且禁止拷贝和赋值。
* **实现:** 它首先将默认构造函数声明为 `delete`，然后调用 `BIONIC_DISALLOW_COPY_AND_ASSIGN` 来禁止拷贝和赋值。
* **Android 关系:** 类似于禁止拷贝和赋值，禁止隐式构造可以强制开发者使用更明确的初始化方式，确保对象的状态在创建时是正确的。这对于需要特定初始化流程的系统组件非常重要。
* **举例说明:** 考虑一个管理硬件资源的类 `HardwareBufferAllocator`。不希望通过默认方式创建它的实例，而是需要通过指定特定的参数（例如 buffer 的大小和格式）来初始化。
* **用户/编程常见错误:**  尝试不带参数直接创建该类的对象会导致编译错误。

**3. 向上取最近的 2 的幂 (`BIONIC_ROUND_UP_POWER_OF_2`)**

* **功能:**  给定一个值，该宏返回大于或等于该值的最小的 2 的幂。
* **实现:** 它使用了 GCC/Clang 的内建函数 `__builtin_clzl` (count leading zeros for long unsigned) 和 `__builtin_clz` (count leading zeros for unsigned)。
    * 对于 64 位值 (`sizeof(value) == 8`)，它计算 `value` 的前导零的个数，然后用 64 减去这个个数得到最高有效位的索引，最后将 1 左移相应的位数得到结果。
    * 对于 32 位值，逻辑类似。
* **Android 关系:** 在内存分配、数据结构优化等方面，将大小对齐到 2 的幂通常可以提高性能。例如，分配器可能会使用这种方法来管理内存块。
* **逻辑推理 (假设输入与输出):**
    * 输入: `value = 5` (32位)
    * `__builtin_clz(5)` 返回 29 (因为 `000...000101`)
    * `32 - 29 = 3`
    * `1UL << 3` 返回 `8`
    * 输出: `8`
    * 输入: `value = 16` (32位)
    * `__builtin_clz(16)` 返回 27
    * `32 - 27 = 5`
    * `1UL << 4` 返回 `16`
    * 输出: `16`
* **用户/编程常见错误:**  可能误解宏的目的，或者在不需要对齐到 2 的幂的场景下使用。

**4. 停止栈回溯 (`BIONIC_STOP_UNWIND`)**

* **功能:**  该宏用于在特定点显式地停止栈回溯 (stack unwinding) 过程。栈回溯通常发生在异常处理或程序崩溃时，用于清理资源和调用析构函数。
* **实现:** 它插入平台相关的汇编指令 `.cfi_undefined` 来标记寄存器为未定义。这会告知调试器和异常处理机制，栈帧信息在此处不可靠，从而阻止进一步的回溯。
* **Android 关系:** 在某些非常底层的系统代码中，可能需要在特定的点阻止栈回溯，例如在某些安全相关的场景或者在处理非常严重的错误时。
* **涉及 dynamic linker 的功能:**  动态链接器本身在启动和处理依赖库的过程中可能会用到这个宏，以确保在某些关键点不会触发不必要的栈回溯。
* **SO 布局样本和链接处理过程:**  由于这是底层的汇编指令，它不直接影响 SO 布局，而是影响运行时栈的行为。链接器在链接过程中不会直接处理这个宏，它会在编译时被替换为对应的汇编指令。
* **假设输入与输出:** 这个宏没有输入输出的概念，它的作用是修改程序的执行流程。
* **用户/编程常见错误:**  普通应用程序开发者很少需要直接使用这个宏。错误的使用可能会导致调试困难或程序行为异常。

**5. 计算数组大小 (`arraysize`, `ArraySizeHelper`)**

* **功能:**  `arraysize` 宏用于在编译时计算静态数组的元素个数。
* **实现:** 它使用了一个模板函数 `ArraySizeHelper`。
    * `ArraySizeHelper` 接受一个数组引用作为参数，并返回一个大小为 N 的 `char` 数组的引用，其中 N 是传入数组的元素个数。
    * `arraysize` 宏通过 `sizeof(ArraySizeHelper(array))` 来获取结果。由于 `ArraySizeHelper(array)` 返回的是一个 `char[N]` 的引用，`sizeof` 运算符作用于该引用会返回数组的大小，即 N。
* **Android 关系:** 在 Bionic 库和 Android 框架代码中，经常需要知道静态数组的大小，例如在遍历数组或分配与之相关的内存时。使用 `arraysize` 可以避免手动计算数组大小，提高代码的可维护性，并且能在编译时进行类型检查，防止将指针误传给 `arraysize`。
* **逻辑推理 (假设输入与输出):**
    * 假设有一个数组 `int myArray[10];`
    * `arraysize(myArray)` 将会被展开为 `sizeof(ArraySizeHelper(myArray))`
    * `ArraySizeHelper(myArray)` 的返回类型是 `char (&)[10]`
    * `sizeof(char (&)[10])` 返回 `10`
    * 输出: `10`
* **用户/编程常见错误:**
    * 将指针传递给 `arraysize` 会导致编译错误，因为模板参数 `N` 无法推导出来。
    * 对动态分配的数组（通过 `new` 创建）使用 `arraysize` 会得到指针的大小，而不是数组的元素个数。

**6. 显式标记 fallthrough (`__BIONIC_FALLTHROUGH`)**

* **功能:**  该宏用于显式地标记 `switch` 语句中的有意 fallthrough (执行完一个 `case` 后，不使用 `break` 语句而继续执行下一个 `case` 的代码)。
* **实现:**
    * 在 C++ 中，如果编译器支持 `-Wimplicit-fallthrough` 警告，该宏会被定义为 `[[clang::fallthrough]]`，这是一个 C++17 引入的属性，用于告知编译器这里是有意的 fallthrough。
    * 在 C 中，该宏为空，因为它没有对应的语法。
* **Android 关系:**  在 Android 代码中，为了提高代码可读性和避免编译器误报警告，可以使用这个宏来明确指示 fallthrough 是预期的行为。
* **用户/编程常见错误:**  忘记在需要 fallthrough 的地方使用这个宏，可能导致编译器产生警告。

**7. 去除地址标签 (`untag_address`)**

* **功能:**  该宏用于去除指针地址中的标签。这通常与内存标记扩展 (Memory Tagging Extension, MTE) 相关。MTE 是一种硬件特性，用于检测内存安全错误。在 MTE 中，指针地址的某些位被用作标签。
* **实现:**
    * 对于 ARM64 (`__aarch64__`) 架构，它使用位与运算 `p & ((1ULL << 56) - 1)` 来屏蔽掉高位标签。这里假设标签位于高 8 位。
    * 对于其他架构，它直接返回原始地址，不做任何操作。
* **Android 关系:** Android 系统开始采用 MTE 来增强内存安全。在某些情况下，需要在访问内存之前去除地址中的标签。例如，在比较地址或进行某些底层操作时。
* **涉及 dynamic linker 的功能:** 动态链接器在处理内存布局和加载共享库时，可能需要处理带有标签的地址。
* **SO 布局样本和链接处理过程:**  MTE 会影响内存分配和地址表示，但不会改变 SO 文件的基本布局。链接器在运行时加载 SO 文件时，可能需要使用 `untag_address` 来处理内存地址。
* **假设输入与输出:**
    * 假设在 ARM64 架构下，`p = 0xff00000012345678` (高 8 位是标签)
    * `untag_address(p)` 返回 `0x0000000012345678`
* **用户/编程常见错误:**  在不需要去除标签的情况下错误地使用此宏，可能会导致访问错误的内存地址（虽然这种情况在 MTE 环境下可能会被检测出来）。

**8. 在链接器重定位前使用的全局变量注解 (`BIONIC_USED_BEFORE_LINKER_RELOCATES`)**

* **功能:**  这是一个属性宏，用于标记全局变量。它指示编译器，这个全局变量在动态链接器完成重定位之前就被访问或获取地址。
* **实现:**
    * 如果编译器支持内存标签全局变量 (`__has_feature(memtag_globals)`)，该宏会被定义为 `__attribute__((no_sanitize("memtag")))`。这表示在内存标签检测中忽略对该全局变量的访问。
    * 否则，该宏为空。
* **Android 关系:**  在启用 MTE 的 Android 系统中，全局变量默认会被标记。然而，动态链接器在启动早期访问某些全局变量时，重定位可能还没有完成，此时访问带有标签的全局变量可能会导致问题。使用这个宏可以告诉编译器不要对这些特定的全局变量进行标记。
* **涉及 dynamic linker 的功能:**  这个宏直接与动态链接器的行为有关。它用于解决在 MTE 环境下，链接器早期访问全局变量的问题。
* **SO 布局样本和链接处理过程:**  这个宏本身不影响 SO 布局。在链接过程中，链接器会处理被标记的全局变量。在运行时，动态链接器加载 SO 文件并进行重定位。对于用此宏标记的全局变量，它们可能不会被加上 MTE 标签。
* **用户/编程常见错误:**  普通应用程序开发者不需要直接使用这个宏。这是 Bionic 库内部使用的机制。

**Android Framework or NDK 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码。
2. **使用 Bionic 库:**  NDK 代码会链接到 Bionic 库，可以使用 Bionic 提供的各种函数和宏，包括 `macros.handroid` 中定义的宏。例如，开发者可能会在一个类的定义中使用 `BIONIC_DISALLOW_COPY_AND_ASSIGN` 来防止拷贝。
3. **编译:** NDK 代码被编译成共享库 (`.so` 文件)。
4. **Android Framework 调用:**  Android Framework (Java 代码) 通过 JNI (Java Native Interface) 调用 NDK 编译生成的共享库中的函数。
5. **Bionic 库的加载和使用:** 当共享库被加载时，动态链接器会介入，加载所有依赖的库，包括 Bionic 库。在执行 NDK 代码时，可能会用到 `macros.handroid` 中定义的宏。

**Frida Hook 示例:**

假设我们想观察 `arraysize` 宏在某个 NDK 函数中的使用。我们可以 hook 这个函数，并在函数内部打印出 `arraysize` 计算出的数组大小。

假设 NDK 代码中有这样一个函数：

```c++
// my_native_lib.cpp
#include <jni.h>
#include <bionic/macros.handroid>
#include <android/log.h>

#define TAG "MyNativeLib"

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MainActivity_myNativeFunction(
        JNIEnv* env,
        jobject /* this */) {
    int myArray[] = {1, 2, 3, 4, 5};
    size_t size = arraysize(myArray);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Array size: %zu", size);
}
```

Frida Hook 脚本：

```python
import frida
import sys

package_name = "com.example.myapp"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
    console.log("Script loaded");

    Java.perform(function() {
        var MainActivity = Java.use('com.example.myapp.MainActivity');
        MainActivity.myNativeFunction.implementation = function() {
            console.log("myNativeFunction called");
            this.myNativeFunction(); // Call the original implementation
        };
    });

    // Hook the native function directly to see the log output
    var nativeFunctionAddress = Module.findExportByName("libmy_native_lib.so", "_ZN7example3app16MainActivity16myNativeFunctionEv");
    if (nativeFunctionAddress) {
        Interceptor.attach(nativeFunctionAddress, {
            onEnter: function(args) {
                console.log("Entered native myNativeFunction");
            },
            onLeave: function(retval) {
                console.log("Left native myNativeFunction");
            }
        });

        // Alternatively, hook the __android_log_print function
        var androidLogPrintAddress = Module.findExportByName("liblog.so", "__android_log_print");
        if (androidLogPrintAddress) {
            Interceptor.attach(androidLogPrintAddress, {
                onEnter: function(args) {
                    var priority = args[0];
                    var tagPtr = args[1];
                    var msgPtr = args[2];
                    var tag = Memory.readUtf8String(tagPtr);
                    var msg = Memory.readUtf8String(msgPtr);
                    console.log("[LOG] " + tag + ": " + msg);
                }
            });
        }
    } else {
        console.error("Could not find native function myNativeFunction");
    }
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 步骤:**

1. **连接到目标应用:**  使用 `frida.get_usb_device().attach(package_name)` 连接到正在运行的 Android 应用进程。
2. **Hook Java 函数 (可选):**  可以使用 `Java.perform` 来 hook Java 层的函数，作为入口点。
3. **查找 Native 函数地址:** 使用 `Module.findExportByName` 查找 NDK 库 (`libmy_native_lib.so`) 中 `myNativeFunction` 的地址。需要根据实际的符号名称进行调整，可以使用 `adb shell dumpsys package <package_name>` 查看应用的 nativeLibraryPath。
4. **Hook Native 函数:** 使用 `Interceptor.attach` hook 原生函数。
5. **Hook `__android_log_print`:** 为了观察 `arraysize` 的结果，我们 hook 了 `__android_log_print` 函数，以便捕获 NDK 代码中打印的日志。
6. **执行:** 运行 Frida 脚本，并触发应用中调用 `myNativeFunction` 的操作。你将在 Frida 的输出中看到 `arraysize` 计算出的数组大小。

这个例子展示了如何使用 Frida 来调试涉及到 Bionic 库宏的 NDK 代码。通过 hook 相关函数，我们可以观察宏展开后的行为和变量的值。

总结来说，`bionic/libc/platform/bionic/macros.handroid` 文件定义了一些在 Android Bionic 库中使用的通用宏，涵盖了代码规范、内存管理、异常处理、编译优化和内存安全等多个方面。理解这些宏的功能有助于深入理解 Android 系统底层的工作原理。

Prompt: 
```
这是目录为bionic/libc/platform/bionic/macros.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2010 The Android Open Source Project
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

#pragma once

#include <stddef.h>
#include <stdint.h>

#define BIONIC_DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete;             \
  void operator=(const TypeName&) = delete

#define BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName() = delete;                                  \
  BIONIC_DISALLOW_COPY_AND_ASSIGN(TypeName)

#define BIONIC_ROUND_UP_POWER_OF_2(value) \
  ((sizeof(value) == 8) \
    ? (1UL << (64 - __builtin_clzl(static_cast<unsigned long>(value)))) \
    : (1UL << (32 - __builtin_clz(static_cast<unsigned int>(value)))))

#if defined(__arm__)
#define BIONIC_STOP_UNWIND asm volatile(".cfi_undefined r14")
#elif defined(__aarch64__)
#define BIONIC_STOP_UNWIND asm volatile(".cfi_undefined x30")
#elif defined(__i386__)
#define BIONIC_STOP_UNWIND asm volatile(".cfi_undefined \%eip")
#elif defined(__riscv)
#define BIONIC_STOP_UNWIND asm volatile(".cfi_undefined ra")
#elif defined(__x86_64__)
#define BIONIC_STOP_UNWIND asm volatile(".cfi_undefined \%rip")
#endif

// The arraysize(arr) macro returns the # of elements in an array arr.
// The expression is a compile-time constant, and therefore can be
// used in defining new arrays, for example.  If you use arraysize on
// a pointer by mistake, you will get a compile-time error.
//
// One caveat is that arraysize() doesn't accept any array of an
// anonymous type or a type defined inside a function.
//
// This template function declaration is used in defining arraysize.
// Note that the function doesn't need an implementation, as we only
// use its type.
template <typename T, size_t N>
char (&ArraySizeHelper(T (&array)[N]))[N];  // NOLINT(readability/casting)

#define arraysize(array) (sizeof(ArraySizeHelper(array)))

// Used to inform clang's -Wimplicit-fallthrough that a fallthrough is intended. There's no way to
// silence (or enable, apparently) -Wimplicit-fallthrough in C yet.
#ifdef __cplusplus
#define __BIONIC_FALLTHROUGH [[clang::fallthrough]]
#else
#define __BIONIC_FALLTHROUGH
#endif

static inline uintptr_t untag_address(uintptr_t p) {
#if defined(__aarch64__)
  return p & ((1ULL << 56) - 1);
#else
  return p;
#endif
}

template <typename T>
static inline T* _Nonnull untag_address(T* _Nonnull p) {
  return reinterpret_cast<T*>(untag_address(reinterpret_cast<uintptr_t>(p)));
}

// MTE globals protects internal and external global variables. One of the main
// things that MTE globals does is force all global variable accesses to go
// through the GOT. In the linker though, some global variables are accessed (or
// address-taken) prior to relocations being processed. Because relocations
// haven't run yet, the GOT entry hasn't been populated, and this leads to
// crashes. Thus, any globals used by the linker prior to relocation should be
// annotated with this attribute, which suppresses tagging of this global
// variable, restoring the pc-relative address computation.
//
// A way to find global variables that need this attribute is to build the
// linker/libc with `SANITIZE_TARGET=memtag_globals`, push them onto a device
// (it doesn't have to be MTE capable), and then run an executable using
// LD_LIBRARY_PATH and using the linker in interpreter mode (e.g.
// `LD_LIBRARY_PATH=/data/tmp/ /data/tmp/linker64 /data/tmp/my_binary`). A
// good heuristic is that the global variable is in a file that should be
// compiled with `-ffreestanding` (but there are global variables there that
// don't need this attribute).
#if __has_feature(memtag_globals)
#define BIONIC_USED_BEFORE_LINKER_RELOCATES __attribute__((no_sanitize("memtag")))
#else  // __has_feature(memtag_globals)
#define BIONIC_USED_BEFORE_LINKER_RELOCATES
#endif  // __has_feature(memtag_globals)

"""

```