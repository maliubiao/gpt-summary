Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The core request is to understand the purpose and functionality of `fdtrack_test.cpp` within the Android Bionic library. This immediately tells us it's a testing file focused on a specific Bionic feature: `fdtrack`.

**2. Initial Code Scan and Identification of Key Elements:**

* **Includes:** The `#include` directives are crucial. They tell us what system calls, Bionic-specific headers, and testing frameworks are being used. We see `<gtest/gtest.h>` (Google Test), standard C/C++ headers like `<unistd.h>`, `<fcntl.h>`, and importantly,  `"platform/bionic/fdtrack.h"`. This confirms the file's purpose is to test the `fdtrack` functionality.
* **`#if defined(__BIONIC__)`:** This preprocessor directive appears frequently, indicating that the code within it is specific to the Bionic environment. This helps isolate the Bionic-specific parts.
* **`FdtrackRun` function:** This function looks central. It takes a function pointer (`void (*func)`) and seems to manage the `fdtrack` mechanism around the execution of that function. The logic involving `android_fdtrack_set_globally_enabled`, `android_fdtrack_compare_exchange_hook`, and storing events in a `std::vector<android_fdtrack_event>` suggests it's responsible for enabling, hooking, and capturing file descriptor related events.
* **`TEST(fdtrack, ...)` macros:** These are Google Test macros defining individual test cases. The names of the tests (e.g., `close`, `fork`, `open`) hint at the system calls being tested with `fdtrack`.
* **`FDTRACK_TEST` and `FDTRACK_TEST_NAME` macros:** These are custom macros that simplify the creation of `fdtrack` tests. They appear to execute a system call and then verify that the expected `fdtrack` events were generated.
* **Specific system calls being tested:**  The arguments to the `FDTRACK_TEST` macros reveal a range of file descriptor related system calls: `open`, `openat`, `socket`, `pidfd_open`, `pidfd_getfd`, `dup`, `dup2`, `dup3`, `fcntl`, `pipe`, `pipe2`, `socketpair`, `epoll_create`, `epoll_create1`, `eventfd`, `accept`, `accept4`, `recvmsg`, `vfork`.

**3. Deeper Analysis of `FdtrackRun`:**

* **Enabling/Disabling:** The function starts by enabling `fdtrack` globally (unless `reenable` is false). This suggests `fdtrack` can be enabled/disabled.
* **Hooking:** The core mechanism seems to be the `android_fdtrack_compare_exchange_hook` function. This likely sets a hook function that gets called whenever a relevant file descriptor operation occurs. The lambda expression `[](android_fdtrack_event* event) { events.push_back(*event); }` defines the hook's behavior: it captures the `android_fdtrack_event` and adds it to the `events` vector.
* **Filtering:** The loop that iterates through the `events` vector and erases elements looks like an attempt to filter out temporary file descriptors. The comment about `accept` creating a socket gives a clue as to why this is necessary.
* **Return Value:** The function returns a `std::vector<android_fdtrack_event>`, which confirms that it's designed to collect and report on file descriptor events.

**4. Analyzing Individual Tests:**

* **`close` test:**  Simple test of closing a file descriptor and verifying the corresponding `ANDROID_FDTRACK_EVENT_TYPE_CLOSE` event.
* **`fork` test:** Tests the behavior of `fdtrack` after a `fork`. It specifically checks that no events are recorded *in the parent process* after the fork.
* **`enable_disable` test:** Verifies that enabling and disabling `fdtrack` works as expected, with events only being recorded when enabled.
* **`FDTRACK_TEST` macro usage:** These tests generally follow a pattern: execute a system call, and then assert that a corresponding `ANDROID_FDTRACK_EVENT_TYPE_CREATE` event was recorded with the correct file descriptor and function name. The `expected_fds` vector helps track file descriptors created in calls like `pipe` and `socketpair`.

**5. Connecting to Android Functionality:**

* **System Call Tracing:** The core functionality is about tracing file descriptor operations. This is valuable for debugging, security auditing, and understanding the behavior of Android applications and system services.
* **Bionic's Role:**  As the C library, Bionic is the natural place for such a low-level tracing mechanism. It intercepts system calls or provides hooks around them.
* **Android Framework/NDK:** Applications using standard C/C++ file I/O functions (via the NDK) will trigger the `fdtrack` mechanism if it's enabled. The Android Framework itself, being built on top of the Linux kernel and using Bionic, will also be subject to `fdtrack`.

**6. Considering Dynamic Linking (More Speculation Initially):**

While the code itself doesn't explicitly *demonstrate* dynamic linking, the fact that it's part of Bionic and `fdtrack` is a system-level feature implies that the `fdtrack` implementation likely involves some interaction with the dynamic linker. The `android_fdtrack_*` functions would need to be resolved at runtime. This part requires understanding how Bionic's dynamic linker (linker64/linker) works. The provided code doesn't give direct evidence, but it's a logical inference based on the context.

**7. Addressing Potential User Errors:**

Thinking about how developers might misuse or encounter issues with file descriptors leads to examples like forgetting to close them (memory leaks) or using invalid file descriptors.

**8. Frida Hooking (Conceptual):**

The idea here is to intercept the `android_fdtrack_*` functions or the underlying system calls using Frida to observe their behavior in a running Android process.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `fdtrack` directly modifies the kernel. **Correction:**  More likely it uses Bionic-level interception to avoid kernel modifications.
* **Initial focus:** Just the test code. **Refinement:** Realize the importance of understanding the *purpose* of `fdtrack` within Android.
* **Dynamic linking:**  Initially, not explicitly visible in the test code. **Refinement:** Recognize that a Bionic-level feature like this likely interacts with the dynamic linker for implementation. The `android_fdtrack_*` functions themselves are symbols that need to be resolved.

By following these steps, combining code analysis with knowledge of Android system architecture and debugging tools, we can arrive at a comprehensive understanding of the `fdtrack_test.cpp` file and the `fdtrack` mechanism itself.
这是一个位于 Android Bionic 库中的测试文件，专门用于测试 Bionic 提供的 `fdtrack` 功能。`fdtrack` 是一个用于跟踪文件描述符（file descriptor）创建和关闭事件的机制。

**文件功能：**

`fdtrack_test.cpp` 的主要功能是验证 `fdtrack` 功能的正确性。它包含了一系列单元测试，每个测试用例都会执行特定的代码，并断言 `fdtrack` 是否记录了预期的文件描述符事件。

**与 Android 功能的关系及举例说明：**

`fdtrack` 是 Android Bionic 的一部分，因此与 Android 的底层功能紧密相关。其主要目的是为了：

1. **调试和诊断：** 帮助开发者追踪文件描述符的生命周期，找出文件描述符泄露、错误关闭等问题。例如，一个应用打开了一个文件但忘记关闭，`fdtrack` 可以记录下这个打开操作，并在程序退出时（如果启用了全局跟踪）或者在测试期间暴露出来。

2. **安全审计：** 监控关键文件描述符的操作，例如 socket 连接的创建和关闭，可以帮助检测潜在的安全漏洞或恶意行为。

3. **性能分析：** 了解文件描述符的使用模式，可以帮助优化 I/O 操作，提升应用性能。

**举例说明：**

* **文件泄露检测：** 假设一个 Android 应用在特定情况下打开了一个文件，但由于代码逻辑错误，没有在所有路径上都关闭它。通过启用 `fdtrack`，当应用执行到这个有缺陷的分支时，会记录下文件打开事件，但不会记录对应的关闭事件，从而暴露了文件泄露问题。`fdtrack_test.cpp` 中的 `enable_disable` 测试用例就演示了如何控制 `fdtrack` 的启用和禁用，从而只跟踪特定代码段的文件描述符操作。

* **Socket 连接跟踪：** 当一个 Android 应用发起网络连接时，会创建一个 socket 文件描述符。`fdtrack` 可以记录这个 socket 的创建事件。如果连接意外断开，但 socket 没有被正确关闭，`fdtrack` 可以帮助定位问题。`fdtrack_test.cpp` 中的 `socket` 和 `accept` 相关测试就模拟了 socket 的创建和接受连接的过程。

**libc 函数的实现解释：**

`fdtrack_test.cpp` 中使用了一些标准的 libc 函数，`fdtrack` 的实现原理通常是在这些 libc 函数的内部或周围添加 hook (钩子)，以便在文件描述符操作发生时进行记录。

* **`open()` 和 `openat()`：** 用于打开文件或目录。`fdtrack` 的 hook 会在 `open`/`openat` 成功返回时记录下新创建的文件描述符以及调用 `open`/`openat` 的函数名。
* **`close()`：** 用于关闭文件描述符。`fdtrack` 的 hook 会在 `close` 调用时记录下被关闭的文件描述符。
* **`socket()`：** 用于创建 socket。`fdtrack` 会记录新创建的 socket 文件描述符。
* **`dup()`, `dup2()`, `dup3()`：** 用于复制文件描述符。`fdtrack` 会记录新创建的文件描述符，并关联到原始的文件描述符。
* **`fcntl()`：** 提供多种文件控制操作，包括复制文件描述符 (`F_DUPFD`, `F_DUPFD_CLOEXEC`)。`fdtrack` 针对这些复制操作进行记录。
* **`pipe()` 和 `pipe2()`：** 用于创建管道，返回一对文件描述符。`fdtrack` 会记录这两个新创建的文件描述符。
* **`socketpair()`：** 创建一对连接的 socket 文件描述符。`fdtrack` 会记录这两个文件描述符。
* **`epoll_create()` 和 `epoll_create1()`：** 创建 epoll 实例的文件描述符。`fdtrack` 会记录这个文件描述符。
* **`eventfd()`：** 创建 eventfd 对象的文件描述符。`fdtrack` 会记录这个文件描述符。
* **`accept()` 和 `accept4()`：** 接受 socket 连接，返回新的连接的文件描述符。`fdtrack` 会记录这个新创建的文件描述符。
* **`vfork()`：** 创建一个子进程，与父进程共享内存空间。`fdtrack` 需要考虑在这种特殊的 fork 场景下的文件描述符跟踪。

**实现细节：**

Bionic 中 `fdtrack` 的具体实现细节可能涉及以下方面：

1. **Hook 机制：** Bionic 可能会使用诸如 LD_PRELOAD 或内部的符号替换机制来 hook libc 函数。当这些被 hook 的函数被调用时，会先执行 `fdtrack` 的记录逻辑，然后再调用原始的 libc 函数。
2. **全局状态管理：** 需要一个全局的状态来控制 `fdtrack` 是否启用。`android_fdtrack_set_globally_enabled()` 就是用来设置这个全局状态的。
3. **事件存储：** `fdtrack` 需要一个地方来存储记录下来的事件。在 `fdtrack_test.cpp` 中，这个存储是由 `std::vector<android_fdtrack_event> events` 来实现的。在实际的 Android 系统中，事件可能会被写入 logcat 或者其他持久化存储。
4. **线程安全：** 由于文件描述符操作可能发生在多个线程中，`fdtrack` 的实现需要是线程安全的，例如使用互斥锁来保护共享数据结构。

**涉及 dynamic linker 的功能：**

`fdtrack` 本身就涉及到 dynamic linker 的功能，因为它需要在运行时 hook 或替换 libc 函数。

**so 布局样本：**

假设 `fdtrack` 的实现位于一个共享库 `libfdtrack.so` 中，那么一个典型的进程的内存布局可能如下所示：

```
...
0x... 加载的共享库（例如 libdl.so, libc.so, libm.so, libfdtrack.so）
...
```

其中，`libfdtrack.so` 中会包含 `android_fdtrack_set_globally_enabled` 等函数的实现，以及 hook libc 函数的逻辑。

**链接的处理过程：**

1. **加载：** 当一个进程启动时，dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 `libc.so` 和可能的 `libfdtrack.so`。

2. **符号解析：** dynamic linker 会解析程序和各个共享库之间的符号引用。例如，如果 `fdtrack` 通过 hook `open` 函数实现，那么 `libfdtrack.so` 中会有一个 `open` 函数的实现，它会覆盖 `libc.so` 中的 `open` 函数。这通常通过 linker 的符号查找和重定位机制实现。

3. **PLT/GOT：** 对于延迟绑定的符号（默认情况），第一次调用被 hook 的函数时，会跳转到 Procedure Linkage Table (PLT) 中的一个条目，该条目会调用 linker 来解析符号，并将 Global Offset Table (GOT) 中的地址更新为 `libfdtrack.so` 中 `open` 函数的地址。后续的调用将直接跳转到 `libfdtrack.so` 的 `open` 函数。

**逻辑推理、假设输入与输出：**

`FdtrackRun` 函数模拟了启用 `fdtrack`、执行一段代码并收集 `fdtrack` 事件的过程。

**假设输入：**

```c++
auto events = FdtrackRun([]() {
  int fd = open("/dev/null", O_RDONLY);
  close(fd);
});
```

**预期输出：**

`events` 向量应该包含两个 `android_fdtrack_event` 结构体：

1. 第一个事件类型为 `ANDROID_FDTRACK_EVENT_TYPE_CREATE`，`fd` 字段为打开 `/dev/null` 返回的文件描述符，`data.create.function_name` 为 "open"。
2. 第二个事件类型为 `ANDROID_FDTRACK_EVENT_TYPE_CLOSE`，`fd` 字段与第一个事件的 `fd` 相同。

**用户或编程常见的使用错误：**

1. **忘记启用 `fdtrack`：** 如果开发者没有调用 `android_fdtrack_set_globally_enabled(true)` 或者在测试中使用 `FdtrackRun`，`fdtrack` 将不会记录任何事件。

2. **hook 函数冲突：** 如果有其他的机制也在尝试 hook 相同的 libc 函数，可能会导致冲突。`fdtrack_test.cpp` 中的 `android_fdtrack_compare_exchange_hook` 就展示了如何安全地设置 hook，避免覆盖已有的 hook。

3. **性能开销：** 频繁的文件描述符操作会导致大量的 `fdtrack` 事件，可能会带来一定的性能开销。在生产环境中，应该谨慎使用全局启用的 `fdtrack`。

4. **错误地假设事件顺序：** 虽然 `fdtrack` 通常会按照事件发生的顺序记录，但在多线程环境下，事件的顺序可能不是绝对确定的。

**Android Framework 或 NDK 如何到达这里，给出 frida hook 示例调试这些步骤：**

1. **NDK 调用 libc 函数：** 当一个使用 NDK 开发的 Android 应用调用例如 `open()` 函数时，实际上会调用到 Bionic 提供的 `libc.so` 中的 `open()` 实现。

2. **`fdtrack` 的 hook 介入：** 如果 `fdtrack` 处于启用状态，Bionic 中 `open()` 函数的实现（或者其周围的 hook）会记录下文件描述符创建事件。

3. **事件记录：** 记录的事件可能被存储在内存中，或者通过某种机制发送到系统服务进行处理。

**Frida Hook 示例：**

假设我们想 hook `open` 函数，查看 `fdtrack` 是否记录了事件。

```python
import frida
import sys

package_name = "your.app.package" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] Received: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
console.log("Script loaded");

var android_fdtrack_hook = null;

Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        console.log("[+] open called");
        this.pathname = Memory.readUtf8String(args[0]);
        this.flags = args[1].toInt();
        console.log("    pathname:", this.pathname);
        console.log("    flags:", this.flags);
    },
    onLeave: function(retval) {
        console.log("[+] open returned:", retval);
        if (retval.toInt() > 0 && android_fdtrack_hook) {
            // 尝试读取 fdtrack 的事件数据结构 (这只是一个示例，实际结构可能更复杂)
            // 需要根据 bionic 的源码来确定具体的数据结构布局
            console.log("    Potentially fdtrack event for fd:", retval.toInt());
        }
    }
});

// 如果知道 android_fdtrack_hook 的地址，可以尝试读取其内容
// 例如，在测试代码中，hook 被赋值给一个静态变量
// var android_fdtrack_compare_exchange_hook_ptr = Module.findExportByName("libc.so", "android_fdtrack_compare_exchange_hook");
// console.log("android_fdtrack_compare_exchange_hook address:", android_fdtrack_compare_exchange_hook_ptr);

"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)

try:
    input()
except KeyboardInterrupt:
    session.detach()
    sys.exit()
```

**解释 Frida Hook 代码：**

1. **附加到进程：**  首先使用 Frida 连接到目标 Android 应用的进程。
2. **Hook `open` 函数：** 使用 `Interceptor.attach` hook 了 `libc.so` 中的 `open` 函数。
3. **`onEnter`：** 在 `open` 函数被调用时，打印出传入的参数，例如文件路径和标志。
4. **`onLeave`：** 在 `open` 函数返回后，打印出返回值（文件描述符）。这里我们尝试性地检查如果返回值大于 0，并且 `android_fdtrack_hook` 存在，则可能存在 `fdtrack` 事件。**注意：直接访问 `fdtrack` 的内部数据结构可能需要更深入的逆向分析和对 Bionic 源码的理解。**
5. **加载和运行：** 加载并运行 Frida 脚本，然后恢复应用进程的执行。

**调试步骤：**

1. **准备环境：** 确保你的电脑上安装了 Frida 和 Python，并且手机已经 root 并安装了 `frida-server`。
2. **运行应用：** 运行你想要调试的 Android 应用。
3. **运行 Frida 脚本：** 执行上面的 Python 脚本，替换 `your.app.package` 为你的应用包名。
4. **观察输出：** 当应用调用 `open` 函数时，Frida 脚本会打印出相关信息。你需要分析这些信息来判断 `fdtrack` 是否记录了事件。更深入的调试可能需要 hook `android_fdtrack_compare_exchange_hook` 或分析 `fdtrack` 内部的数据结构。

通过这种方式，你可以观察 Android Framework 或 NDK 调用 libc 函数的过程，并利用 Frida 动态地分析 `fdtrack` 的行为。记住，hook 系统级别的函数需要 root 权限。

### 提示词
```
这是目录为bionic/tests/fdtrack_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__BIONIC__)
#include <sys/pidfd.h>

#include "platform/bionic/fdtrack.h"
#include "platform/bionic/reserved_signals.h"
#endif

#include <vector>

#include <android-base/cmsg.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "utils.h"

using android::base::ReceiveFileDescriptors;
using android::base::SendFileDescriptors;
using android::base::unique_fd;

#if defined(__BIONIC__)
void DumpEvent(std::vector<android_fdtrack_event>* events, size_t index) {
  auto& event = (*events)[index];
  if (event.type == ANDROID_FDTRACK_EVENT_TYPE_CREATE) {
    fprintf(stderr, "  event %zu: fd %d created by %s\n", index, event.fd,
            event.data.create.function_name);
  } else if (event.type == ANDROID_FDTRACK_EVENT_TYPE_CLOSE) {
    fprintf(stderr, "  event %zu: fd %d closed\n", index, event.fd);
  } else {
    errx(1, "unexpected fdtrack event type: %d", event.type);
  }
}

std::vector<android_fdtrack_event> FdtrackRun(void (*func)(), bool reenable = true) {
  // Each bionic test is run in separate process, so we can safely use a static here.
  // However, since they're all forked, we need to reenable fdtrack.
  if (reenable) {
    android_fdtrack_set_globally_enabled(true);
  }

  static std::vector<android_fdtrack_event> events;
  events.clear();

  android_fdtrack_hook_t previous = nullptr;
  android_fdtrack_hook_t hook = [](android_fdtrack_event* event) { events.push_back(*event); };

  if (!android_fdtrack_compare_exchange_hook(&previous, hook)) {
    errx(1, "failed to exchange hook: previous hook was %p", previous);
  }

  if (previous) {
    errx(1, "hook was already registered?");
    abort();
  }

  func();

  if (!android_fdtrack_compare_exchange_hook(&hook, nullptr)) {
    errx(1, "failed to reset hook");
  }

  // Filter out temporary fds created and closed as a result of the call.
  // (e.g. accept creating a socket to tell netd about the newly accepted socket)
  size_t i = 0;
  while (i + 1 < events.size()) {
    auto& event = events[i];
    if (event.type == ANDROID_FDTRACK_EVENT_TYPE_CREATE) {
      for (size_t j = i + 1; j < events.size(); ++j) {
        if (event.fd == events[j].fd) {
          if (events[j].type == ANDROID_FDTRACK_EVENT_TYPE_CREATE) {
            fprintf(stderr, "error: multiple create events for the same fd:\n");
            DumpEvent(&events, i);
            DumpEvent(&events, j);
            exit(1);
          }

          events.erase(events.begin() + j);
          events.erase(events.begin() + i);
          continue;
        }
      }
    }
    ++i;
  }

  return std::move(events);
}

const char* FdtrackEventTypeToName(android_fdtrack_event_type event_type) {
  switch (event_type) {
    case ANDROID_FDTRACK_EVENT_TYPE_CREATE:
      return "created";
    case ANDROID_FDTRACK_EVENT_TYPE_CLOSE:
      return "closed";
  }
}
#endif

TEST(fdtrack, close) {
#if defined(__BIONIC__)
  static int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);

  auto events = FdtrackRun([]() { close(fd); });
  ASSERT_EQ(1U, events.size());
  ASSERT_EQ(fd, events[0].fd);
  ASSERT_EQ(ANDROID_FDTRACK_EVENT_TYPE_CLOSE, events[0].type);
#endif
}

TEST(fdtrack, fork) {
#if defined(__BIONIC__)
  ASSERT_EXIT(
      []() {
        static int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        ASSERT_NE(-1, fd);

        auto events = FdtrackRun([]() { close(fd); }, false);
        ASSERT_EQ(0U, events.size());
        exit(0);
      }(),
      testing::ExitedWithCode(0), "");
#endif
}

TEST(fdtrack, enable_disable) {
#if defined(__BIONIC__)
  static int fd1 = -1;
  static int fd2 = -1;
  static int fd3 = -1;

  auto events = FdtrackRun([]() {
    if (!android_fdtrack_get_enabled()) {
      errx(1, "fdtrack is disabled");
    }
    fd1 = open("/dev/null", O_WRONLY | O_CLOEXEC);
    android_fdtrack_set_enabled(false);
    fd2 = open("/dev/null", O_WRONLY | O_CLOEXEC);
    android_fdtrack_set_enabled(true);
    fd3 = open("/dev/null", O_WRONLY | O_CLOEXEC);
  });

  if (fd1 == -1 || fd2 == -1 || fd3 == -1) {
    errx(1, "failed to open /dev/null");
  }

  ASSERT_EQ(2U, events.size());

  ASSERT_EQ(fd1, events[0].fd);
  ASSERT_EQ(ANDROID_FDTRACK_EVENT_TYPE_CREATE, events[0].type);
  ASSERT_STREQ("open", events[0].data.create.function_name);

  ASSERT_EQ(fd3, events[1].fd);
  ASSERT_EQ(ANDROID_FDTRACK_EVENT_TYPE_CREATE, events[1].type);
  ASSERT_STREQ("open", events[1].data.create.function_name);
#endif
}

struct require_semicolon;

#if defined(__BIONIC__)
void SetFdResult(std::vector<int>* output, int fd) {
  output->push_back(fd);
}

void SetFdResult(std::vector<int>* output, std::vector<int> fds) {
  *output = fds;
}

#define FDTRACK_TEST_NAME(test_name, fdtrack_name, expression)                                   \
  TEST(fdtrack, test_name) {                                                                     \
    static std::vector<int> expected_fds;                                                        \
    auto events = FdtrackRun([]() { SetFdResult(&expected_fds, expression); });                  \
    for (auto& fd : expected_fds) {                                                              \
      ASSERT_NE(-1, fd) << strerror(errno);                                                      \
    }                                                                                            \
    if (events.size() != expected_fds.size()) {                                                  \
      fprintf(stderr, "too many events received: expected %zu, got %zu:\n", expected_fds.size(), \
              events.size());                                                                    \
      for (size_t i = 0; i < events.size(); ++i) {                                               \
        DumpEvent(&events, i);                                                                   \
      }                                                                                          \
      FAIL();                                                                                    \
      return;                                                                                    \
    }                                                                                            \
    for (auto& event : events) {                                                                 \
      ASSERT_NE(expected_fds.end(),                                                              \
                std::find(expected_fds.begin(), expected_fds.end(), events[0].fd));              \
      ASSERT_EQ(ANDROID_FDTRACK_EVENT_TYPE_CREATE, event.type);                                  \
      ASSERT_STREQ(fdtrack_name, event.data.create.function_name);                               \
    }                                                                                            \
  }                                                                                              \
  struct require_semicolon
#else
#define FDTRACK_TEST_NAME(name, fdtrack_name, expression) \
  TEST(fdtrack, name) {}                                  \
  struct require_semicolon
#endif

#define FDTRACK_TEST(name, expression) FDTRACK_TEST_NAME(name, #name, expression)

// clang-format misformats statement expressions pretty badly here:
// clang-format off
FDTRACK_TEST(open, open("/dev/null", O_WRONLY | O_CLOEXEC));
FDTRACK_TEST(openat, openat(AT_EMPTY_PATH, "/dev/null", O_WRONLY | O_CLOEXEC));
FDTRACK_TEST(socket, socket(AF_UNIX, SOCK_STREAM, 0));

FDTRACK_TEST(pidfd_open, ({
  int rc = pidfd_open(getpid(), 0);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_open() in this kernel";
  ASSERT_NE(-1, rc) << strerror(errno);
  rc;
}));

FDTRACK_TEST(pidfd_getfd, ({
  android_fdtrack_set_enabled(false);
  int pidfd_self = pidfd_open(getpid(), 0);
  if (pidfd_self == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_open() in this kernel";
  ASSERT_NE(-1, pidfd_self) << strerror(errno);

  android_fdtrack_set_enabled(true);

  int rc = pidfd_getfd(pidfd_self, STDIN_FILENO, 0);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_getfd() in this kernel";
  ASSERT_NE(-1, rc) << strerror(errno);

  android_fdtrack_set_enabled(false);
  close(pidfd_self);
  android_fdtrack_set_enabled(true);

  rc;
}));

FDTRACK_TEST(dup, dup(STDOUT_FILENO));
FDTRACK_TEST(dup2, dup2(STDOUT_FILENO, STDERR_FILENO));
FDTRACK_TEST(dup3, dup3(STDOUT_FILENO, STDERR_FILENO, 0));
FDTRACK_TEST_NAME(fcntl_F_DUPFD, "F_DUPFD", fcntl(STDOUT_FILENO, F_DUPFD, 0));
FDTRACK_TEST_NAME(fcntl_F_DUPFD_CLOEXEC, "F_DUPFD_CLOEXEC", fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0));

FDTRACK_TEST(pipe, ({
  std::vector<int> fds = { -1, -1};
  if (pipe(fds.data()) != 0) {
    err(1, "pipe failed");
  }
  fds;
}));

FDTRACK_TEST(pipe2, ({
  std::vector<int> fds = { -1, -1};
  if (pipe2(fds.data(), O_CLOEXEC) != 0) {
    err(1, "pipe failed");
  }
  fds;
}));

FDTRACK_TEST(socketpair, ({
  std::vector<int> fds = { -1, -1};
  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds.data()) != 0) {
    err(1, "socketpair failed");
  }
  fds;
}));

FDTRACK_TEST(epoll_create, epoll_create(1));
FDTRACK_TEST(epoll_create1, epoll_create1(0));

FDTRACK_TEST(eventfd, eventfd(0, 0));

#if defined(__BIONIC__)
static int CreateListener() {
  android_fdtrack_set_enabled(false);
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  CHECK_NE(-1, listener);

  sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = 0,
      .sin_addr = {htonl(INADDR_LOOPBACK)},
  };
  socklen_t addrlen = sizeof(addr);

  CHECK_NE(-1, bind(listener, reinterpret_cast<sockaddr*>(&addr), addrlen)) << strerror(errno);
  CHECK_NE(-1, getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addrlen));
  CHECK_EQ(static_cast<size_t>(addrlen), sizeof(addr));
  CHECK_NE(-1, listen(listener, 1));

  int connector = socket(AF_INET, SOCK_STREAM, 0);
  CHECK_NE(-1, connector);
  CHECK_NE(-1, connect(connector, reinterpret_cast<sockaddr*>(&addr), addrlen));
  android_fdtrack_set_enabled(true);

  return listener;
}
#endif

FDTRACK_TEST_NAME(accept, "accept4", accept(CreateListener(), nullptr, nullptr));
FDTRACK_TEST(accept4, accept4(CreateListener(), nullptr, nullptr, 0));

FDTRACK_TEST(recvmsg, ({
  android_fdtrack_set_enabled(false);
  int sockets[2];
  ASSERT_NE(-1, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets));
  ASSERT_EQ(3, SendFileDescriptors(sockets[0], "foo", 3, STDIN_FILENO));
  android_fdtrack_set_enabled(true);

  char buf[4];
  unique_fd received_fd;
  ASSERT_EQ(3, ReceiveFileDescriptors(sockets[1], buf, sizeof(buf), &received_fd));
  received_fd.release();
}));

FDTRACK_TEST_NAME(vfork, "open", ({
  int fd = open("/dev/null", O_RDONLY);

  pid_t rc = vfork();
  ASSERT_NE(-1, rc);

  if (rc == 0) {
    close(fd);
    _exit(0);
  }

  int status;
  pid_t wait_result = waitpid(rc, &status, 0);
  ASSERT_EQ(wait_result, rc);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(0, WEXITSTATUS(status));

  fd;
}));
// clang-format on
```