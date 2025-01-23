Response:
我的目标是对给定的 C++ 头文件 `Config.handroid` 进行分析，并按照用户的要求给出详细的中文回复。文件位于 Android Bionic 库的内存分配调试模块中。

**1. 理解文件内容：**

首先，我仔细阅读了代码，识别出这是一个配置类 `Config`，用于控制内存分配调试的不同选项。这些选项通过宏定义（例如 `FRONT_GUARD`, `REAR_GUARD` 等）以及类成员变量进行管理。`Init` 方法用于解析配置字符串，而其他方法则用于获取或设置特定的配置值。

**2. 提取功能列表：**

根据代码中的宏定义和类成员变量，我列出了 `Config` 类提供的所有可配置功能，例如：

* 前后 guard 区域
* 调用栈追踪
* 内存填充
* 扩展分配
* 释放追踪
* 泄露追踪
* 记录分配
* 异常中止
* 详细日志
* 信号处理
* 特定大小调用栈追踪
* 记录分配器统计信息

**3. 分析与 Android 功能的关系：**

我意识到这些功能都直接关联到 Android 系统的内存管理和调试。为了说明这一点，我为每个功能都设想了一个使用场景，并解释了它如何帮助开发者在 Android 环境中调试内存问题。例如：

* **Guard 区域:**  防止缓冲区溢出。
* **调用栈追踪:** 确定内存分配/释放的位置。
* **内存填充:**  更容易检测未初始化或释放后使用的情况。
* **泄露追踪:** 找出未释放的内存。

**4. 解释 libc 函数实现（重点）：**

虽然这个 `Config.handroid` 文件本身**不包含任何 libc 函数的实现**，但它控制着内存分配的行为。关键在于，这个配置文件会影响 bionic 中 `malloc`, `free`, `calloc`, `realloc` 等内存管理函数的行为。 我需要在回答中明确指出这一点，并说明这些 libc 函数会读取 `Config` 的配置来决定是否启用特定的调试功能。

为了更具体地说明，我需要解释：

* **`malloc`:** 如何根据 `FRONT_GUARD`, `REAR_GUARD`, `FILL_ON_ALLOC` 等选项添加 guard 区域和填充内容。
* **`free`:** 如何根据 `REAR_GUARD`, `FILL_ON_FREE` 等选项检查 guard 区域，并可能填充释放的内存。
* **调用栈追踪:** 如何在 `malloc` 和 `free` 中使用 `backtrace` 或类似的机制来记录调用栈。

**5. dynamic linker 的功能（重点）：**

这个文件与 dynamic linker 的直接关系不大，但内存分配器是 dynamic linker 运行时所依赖的重要组件。  我可以创建一个简单的 so 布局样本，并解释 dynamic linker 在加载 so 时如何可能影响内存分配，例如，so 的加载地址可能会影响到某些内存区域的布局。

对于链接处理过程，我可以简要描述 dynamic linker 如何解析 ELF 文件，重定位符号，并将 so 映射到内存。

**6. 逻辑推理（假设输入与输出）：**

对于 `Init` 方法，我可以假设一个配置字符串作为输入，并预测哪些配置选项会被启用，哪些成员变量会被修改。

**7. 常见错误举例：**

我需要列举一些常见的内存管理错误，并说明这些 `Config` 选项如何帮助检测这些错误，例如：

* 缓冲区溢出（Guard 区域）
* 使用已释放的内存（填充）
* 内存泄漏（泄露追踪）

**8. Android Framework/NDK 到达这里的路径和 Frida Hook：**

为了说明到达 `Config.handroid` 的路径，我需要解释：

* Android Framework 或 NDK 中的代码会调用 `malloc` 等内存分配函数。
* 这些调用最终会进入 bionic 的内存分配实现。
* bionic 的内存分配实现会读取 `Config` 类的配置。
* 配置可以通过环境变量或其他方式设置。

关于 Frida Hook，我可以提供一个简单的 JavaScript 代码片段，用于 hook `Config::Init` 方法，以便在运行时查看或修改配置。

**9. 组织和润色答案：**

最后，我需要将所有的信息组织成结构清晰、易于理解的中文回复，并确保覆盖用户提出的所有问题。要详细解释每个配置项的作用，以及它在实际内存分配中的影响。

通过以上思考过程，我能够生成一个全面且准确的答案，满足用户的需求。特别是，我注意到了文件本身不包含 libc 函数实现，而是控制着内存分配的行为，并着重解释了这一点。同时，我也努力将抽象的概念与实际的 Android 开发场景联系起来。
这个文件 `bionic/libc/malloc_debug/Config.handroid` 是 Android Bionic 库中内存分配调试功能的一个配置文件。它定义了一些常量和配置类 `Config`，用于控制内存分配器在调试模式下的行为。

下面我将逐点解释其功能：

**1. 功能列举:**

该文件定义了以下用于内存分配调试的配置选项（以 `constexpr uint64_t` 定义的常量表示）：

* **`FRONT_GUARD`**: 在分配的内存块前面添加保护区域。
* **`REAR_GUARD`**: 在分配的内存块后面添加保护区域。
* **`BACKTRACE`**: 记录内存分配时的调用栈信息。
* **`FILL_ON_ALLOC`**: 在内存分配时用特定值填充分配的内存。
* **`FILL_ON_FREE`**: 在内存释放时用特定值填充释放的内存。
* **`EXPAND_ALLOC`**: 扩大分配的内存块大小，可能用于检测越界写入。
* **`FREE_TRACK`**: 跟踪已释放的内存块，可能用于检测 use-after-free 错误。
* **`TRACK_ALLOCS`**: 跟踪所有分配的内存块。
* **`LEAK_TRACK`**: 启用内存泄漏检测。
* **`RECORD_ALLOCS`**: 记录内存分配信息到文件。
* **`BACKTRACE_FULL`**: 记录完整的调用栈信息。
* **`ABORT_ON_ERROR`**: 在检测到内存错误时中止程序。
* **`VERBOSE`**: 启用更详细的日志输出。
* **`CHECK_UNREACHABLE_ON_SIGNAL`**: 在收到特定信号时检查不可达代码。
* **`BACKTRACE_SPECIFIC_SIZES`**: 仅为特定大小的分配记录调用栈。
* **`LOG_ALLOCATOR_STATS_ON_SIGNAL`**: 在收到特定信号时记录分配器统计信息。
* **`LOG_ALLOCATOR_STATS_ON_EXIT`**: 在程序退出时记录分配器统计信息。

此外，还定义了最小对齐字节数 `MINIMUM_ALIGNMENT_BYTES`，根据架构 (32-bit 或 64-bit) 不同而不同。

`HEADER_OPTIONS` 是一个常量，表示如果设置了 `FRONT_GUARD` 或 `REAR_GUARD` 中的任何一个，则需要一个特殊的头部来存储保护区域的信息。

`Config` 类提供了以下功能：

* **`Init(const char* options_str)`**:  初始化配置，解析来自字符串的配置选项。这个字符串通常是一个环境变量的值 (例如 `LIBC_DEBUG_MALLOC_OPTIONS`)。
* **`LogUsage()`**: 打印配置选项的用法说明。
* **各种 `get` 方法**:  用于获取当前的配置值，例如是否启用了 `BACKTRACE`，前后保护区域的大小等。

**2. 与 Android 功能的关系及举例说明:**

这些配置选项直接影响 Android 系统的内存管理，主要用于调试和检测内存相关的错误。以下是一些例子：

* **`FRONT_GUARD` 和 `REAR_GUARD`**:  用于检测缓冲区溢出。如果程序向已分配内存块的前面或后面写入超出范围的数据，这些保护区域会被破坏，内存分配器可以检测到并报告错误，甚至中止程序 (如果设置了 `ABORT_ON_ERROR`)。这对于在 Native 代码中调试潜在的缓冲区溢出漏洞非常重要。例如，一个 JNI 方法在拷贝 Java 层的字符串到 Native 缓冲区时，如果没有正确计算长度，就可能发生溢出。启用 guard 区域可以帮助快速定位问题。

* **`BACKTRACE`**:  当发生内存错误（例如，尝试释放未分配的内存）时，记录的调用栈可以帮助开发者快速定位到导致错误的具体代码位置。这在复杂的 Android 系统中非常有用，因为内存分配和释放可能发生在不同的组件和线程中。例如，一个 Service 在后台线程中分配了内存，但是忘记在退出时释放，启用 `BACKTRACE` 可以追溯到分配发生的地点。

* **`FILL_ON_ALLOC` 和 `FILL_ON_FREE`**:  有助于检测使用未初始化内存或 use-after-free 错误。用特定的值填充分配的内存可以使未初始化的访问更容易被识别（因为会读取到预设的值）。用特定的值填充释放的内存可以使 use-after-free 错误更容易触发和检测，因为尝试访问这些内存会得到预设的值，而不是之前的数据。例如，一个 Native 代码中的对象被释放后，如果仍然有指针指向该对象并尝试访问其成员，启用 `FILL_ON_FREE` 可以增加这种错误被立即发现的概率。

* **`LEAK_TRACK`**:  帮助开发者找出程序中未释放的内存块。在程序退出时，内存分配器可以报告哪些内存被分配了但没有被释放，以及这些内存分配时的调用栈信息。这对于防止 Android 应用因内存泄漏而导致性能下降或崩溃至关重要。

**3. libc 函数的功能实现:**

`Config.handroid` 文件本身**不包含任何 libc 函数的实现**。它只是一个配置文件，用于**指导** bionic 库中内存分配相关 libc 函数（例如 `malloc`, `free`, `calloc`, `realloc`）的**行为**。

这些 libc 函数的实现逻辑会读取 `Config` 类中的配置信息，并根据这些配置来执行额外的调试操作。例如：

* 当 `FRONT_GUARD` 被启用时，`malloc` 的实现会分配比请求大小更大的内存，并在返回给用户的内存块前面添加一个 guard 区域。
* 当 `BACKTRACE` 被启用时，`malloc` 和 `free` 的实现会调用相关的系统调用（例如 `backtrace`）来获取当前的调用栈信息，并存储在内存块的元数据中。
* 当检测到 guard 区域被破坏时，内存分配器会根据 `ABORT_ON_ERROR` 的设置来决定是否中止程序。

**关键在于，`Config` 类提供的是配置，而 libc 的 `malloc` 等函数的实现会根据这些配置来增加额外的调试逻辑。**

**4. 涉及 dynamic linker 的功能:**

这个文件本身与 dynamic linker 的功能没有直接的交互。dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析和绑定符号。

然而，内存分配器是 dynamic linker 运行时的重要组成部分。dynamic linker 需要使用内存分配器来加载和管理共享库的代码和数据段。

**SO 布局样本:**

假设一个简单的共享库 `libexample.so`：

```
LOAD           0x0000007000000000  0x0000007000000000 00000 00000 r-x 1000
LOAD           0x0000007000001000  0x0000007000001000 01000 00000 rw- 1000
DYNAMIC        0x0000007000001000  0x0000007000001000 01000 001a0 rw-
```

这是一个简化的示例，展示了 `libexample.so` 在内存中的布局。

* **`LOAD` 段**:  定义了需要加载到内存中的代码和数据段。
    * 第一个 `LOAD` 段通常是只读可执行的 (`r-x`)，包含代码。
    * 第二个 `LOAD` 段通常是可读写的 (`rw-`)，包含全局变量等数据。
* **`DYNAMIC` 段**:  包含了 dynamic linker 需要的信息，例如符号表、重定位表等。

**链接的处理过程:**

1. **加载**: 当 Android 系统需要加载 `libexample.so` 时，dynamic linker 会读取其 ELF 文件头，确定需要加载的段及其属性。
2. **映射**: Dynamic linker 使用 `mmap` 等系统调用将共享库的各个段映射到进程的地址空间。上面的例子展示了加载的基地址为 `0x0000007000000000`。
3. **重定位**: 共享库通常包含对其他共享库或自身内部符号的引用。这些引用需要在加载时根据共享库的实际加载地址进行调整，这个过程称为重定位。Dynamic linker 会读取 `DYNAMIC` 段中的重定位表，并修改相应的内存地址。
4. **符号绑定**: Dynamic linker 解析共享库的符号表，将未定义的符号与已加载的共享库中定义的符号进行绑定。这使得不同共享库之间的函数调用和数据访问成为可能。

**虽然 `Config.handroid` 不直接参与链接过程，但当 dynamic linker 加载共享库时，它会使用 `malloc` 等内存分配函数来为共享库分配内存。因此，`Config.handroid` 的配置会影响 dynamic linker 在加载共享库时使用的内存分配行为。例如，如果启用了 `FRONT_GUARD`，dynamic linker 在内部调用 `malloc` 时，分配的内存块也会带有保护区域。**

**5. 逻辑推理 (假设输入与输出):**

假设 `Config::Init` 函数接收到以下配置字符串：

```
"backtrace=16 front_guard=8 fill_on_alloc=255"
```

**假设输入:** `options_str` 为 `"backtrace=16 front_guard=8 fill_on_alloc=255"`

**逻辑推理:** `Init` 函数会解析这个字符串，并根据键值对设置相应的成员变量：

* `"backtrace=16"`: `backtrace_enabled_` 会被设置为 `true`，`backtrace_frames_` 会被设置为 `16`。
* `"front_guard=8"`: `options_` 会包含 `FRONT_GUARD` 标志，`front_guard_bytes_` 会被设置为 `8`.
* `"fill_on_alloc=255"`: `options_` 会包含 `FILL_ON_ALLOC` 标志，`fill_on_alloc_bytes_` 会被设置为非零值（实际使用中可能默认为分配的大小或一个预设值），`fill_alloc_value_` 会被设置为 `255`。

**假设输出 (部分):**

* `options_`: 包含 `FRONT_GUARD` 和 `BACKTRACE` 标志。
* `backtrace_enabled_`: `true`
* `backtrace_frames_`: `16`
* `front_guard_bytes_`: `8`
* `fill_on_alloc_bytes_`: (取决于实现，可能等于分配大小或预设值)
* `fill_alloc_value_`: `255`

**6. 用户或编程常见的使用错误举例:**

* **缓冲区溢出:**  在分配的内存块的边界之外进行读写操作。启用 `FRONT_GUARD` 和 `REAR_GUARD` 可以帮助检测这类错误。例如：

   ```c
   char *buffer = (char *)malloc(10);
   strcpy(buffer, "This string is longer than 10 bytes"); // 缓冲区溢出
   ```

* **使用已释放的内存 (Use-After-Free):** 访问已经被 `free` 释放的内存。启用 `FILL_ON_FREE` 可以让这类错误更容易被发现，因为访问被填充的内存会得到预设的值。启用 `FREE_TRACK` 也能记录释放信息，帮助定位错误。 例如：

   ```c
   char *ptr = (char *)malloc(10);
   free(ptr);
   *ptr = 'a'; // 使用已释放的内存
   ```

* **内存泄漏:** 分配了内存但忘记释放。启用 `LEAK_TRACK` 可以在程序退出时报告泄漏的内存块。例如：

   ```c
   void some_function() {
       char *buffer = (char *)malloc(1024);
       // ... 没有释放 buffer
   }
   ```

* **重复释放:**  对同一块内存执行多次 `free` 操作。内存分配器通常可以检测到这类错误，启用 `ABORT_ON_ERROR` 可以让程序在检测到错误时立即中止。

* **释放未分配的内存:**  尝试释放一个没有通过 `malloc` 等函数分配的内存地址。

**7. Android Framework or NDK 如何到达这里，给出 Frida Hook 示例:**

Android Framework 或 NDK 中的代码最终会调用 bionic 库提供的内存分配函数 (例如 `malloc`, `free`)。这些函数内部会读取 `Config` 类的配置来决定是否启用调试功能。

**步骤:**

1. **设置环境变量:**  可以通过设置环境变量 `LIBC_DEBUG_MALLOC_OPTIONS` 来配置内存分配调试选项。例如，在 adb shell 中运行：

   ```bash
   setprop libc.debug.malloc.options backtrace=16,front_guard=8
   stop
   start
   ```

   或者，在 AndroidManifest.xml 中为特定的进程设置：

   ```xml
   <application ...>
       <meta-data android:name="com.android.app.debuggable" android:value="true" />
       <meta-data android:name="android.sysprop.libc.debug.malloc.options" android:value="backtrace=16,front_guard=8" />
       ...
   </application>
   ```

2. **应用程序或系统服务调用 `malloc` 等函数:**  当应用程序或系统服务中的 Native 代码调用 `malloc`, `free` 等函数时，会进入 bionic 库的实现。

3. **读取配置:**  bionic 的 `malloc` 实现会读取 `Config` 类的配置信息，以决定是否执行额外的调试操作（例如添加 guard 区域，记录调用栈）。`Config` 类的实例通常在进程启动时被初始化。

**Frida Hook 示例:**

可以使用 Frida 来 hook `Config::Init` 方法，查看或修改配置信息。以下是一个 JavaScript Frida 脚本示例：

```javascript
if (Process.arch === 'arm64') {
  var configInitAddress = Module.findExportByName("libc.so", "_ZN6Config4InitEPKc"); // Android 7+ arm64
} else if (Process.arch === 'arm') {
  var configInitAddress = Module.findExportByName("libc.so", "_ZN6Config4InitEPKc"); // 可能需要调整
} else {
  console.log("Unsupported architecture.");
}

if (configInitAddress) {
  Interceptor.attach(configInitAddress, {
    onEnter: function(args) {
      var optionsStr = Memory.readCString(args[0]);
      console.log("Config::Init called with options:", optionsStr);
      // 可以修改 optionsStr 的值，例如：
      // Memory.writeUtf8String(args[0], "backtrace=32");
    },
    onLeave: function(retval) {
      console.log("Config::Init returned:", retval);
    }
  });
} else {
  console.log("Could not find Config::Init function.");
}
```

**解释:**

1. **查找函数地址:**  根据设备架构使用 `Module.findExportByName` 查找 `Config::Init` 函数的地址。注意函数签名可能会因 Android 版本和架构而异。
2. **附加 Interceptor:**  使用 `Interceptor.attach` 拦截对 `Config::Init` 函数的调用。
3. **`onEnter` 回调:**  在函数调用之前执行。`args[0]` 包含了传递给 `Init` 函数的配置字符串的指针。可以使用 `Memory.readCString` 读取字符串内容并打印出来。可以在这里修改配置字符串的值。
4. **`onLeave` 回调:**  在函数调用之后执行。`retval` 包含了函数的返回值。

通过这个 Frida 脚本，你可以在应用程序运行时动态地观察和修改内存分配调试的配置，从而更方便地进行调试。

总结来说，`Config.handroid` 定义了内存分配调试的配置选项，这些选项影响着 bionic 库中 `malloc` 等内存分配函数的行为，从而帮助开发者检测和修复内存相关的错误。虽然它不直接参与 dynamic linker 的功能，但内存分配器是 dynamic linker 运行时的重要组成部分。可以通过设置环境变量或 Frida Hook 等方式来配置和观察这些调试选项。

### 提示词
```
这是目录为bionic/libc/malloc_debug/Config.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdint.h>

#include <string>
#include <unordered_map>

constexpr uint64_t FRONT_GUARD = 0x1;
constexpr uint64_t REAR_GUARD = 0x2;
constexpr uint64_t BACKTRACE = 0x4;
constexpr uint64_t FILL_ON_ALLOC = 0x8;
constexpr uint64_t FILL_ON_FREE = 0x10;
constexpr uint64_t EXPAND_ALLOC = 0x20;
constexpr uint64_t FREE_TRACK = 0x40;
constexpr uint64_t TRACK_ALLOCS = 0x80;
constexpr uint64_t LEAK_TRACK = 0x100;
constexpr uint64_t RECORD_ALLOCS = 0x200;
constexpr uint64_t BACKTRACE_FULL = 0x400;
constexpr uint64_t ABORT_ON_ERROR = 0x800;
constexpr uint64_t VERBOSE = 0x1000;
constexpr uint64_t CHECK_UNREACHABLE_ON_SIGNAL = 0x2000;
constexpr uint64_t BACKTRACE_SPECIFIC_SIZES = 0x4000;
constexpr uint64_t LOG_ALLOCATOR_STATS_ON_SIGNAL = 0x8000;
constexpr uint64_t LOG_ALLOCATOR_STATS_ON_EXIT = 0x10000;

// In order to guarantee posix compliance, set the minimum alignment
// to 8 bytes for 32 bit systems and 16 bytes for 64 bit systems.
#if defined(__LP64__)
constexpr size_t MINIMUM_ALIGNMENT_BYTES = 16;
#else
constexpr size_t MINIMUM_ALIGNMENT_BYTES = 8;
#endif

// If one or more of these options is set, then a special header is needed.
constexpr uint64_t HEADER_OPTIONS = FRONT_GUARD | REAR_GUARD;

class Config {
 public:
  bool Init(const char* options_str);

  void LogUsage() const;

  uint64_t options() const { return options_; }

  int backtrace_signal() const { return backtrace_signal_; }
  int backtrace_dump_signal() const { return backtrace_dump_signal_; }
  size_t backtrace_frames() const { return backtrace_frames_; }
  size_t backtrace_enabled() const { return backtrace_enabled_; }
  size_t backtrace_enable_on_signal() const { return backtrace_enable_on_signal_; }
  bool backtrace_dump_on_exit() const { return backtrace_dump_on_exit_; }
  const std::string& backtrace_dump_prefix() const { return backtrace_dump_prefix_; }

  size_t front_guard_bytes() const { return front_guard_bytes_; }
  size_t rear_guard_bytes() const { return rear_guard_bytes_; }
  uint8_t front_guard_value() const { return front_guard_value_; }
  uint8_t rear_guard_value() const { return rear_guard_value_; }

  size_t expand_alloc_bytes() const { return expand_alloc_bytes_; }

  size_t free_track_allocations() const { return free_track_allocations_; }
  size_t free_track_backtrace_num_frames() const { return free_track_backtrace_num_frames_; }

  size_t fill_on_alloc_bytes() const { return fill_on_alloc_bytes_; }
  size_t fill_on_free_bytes() const { return fill_on_free_bytes_; }
  uint8_t fill_alloc_value() const { return fill_alloc_value_; }
  uint8_t fill_free_value() const { return fill_free_value_; }

  size_t backtrace_min_size_bytes() const { return backtrace_min_size_bytes_; }
  size_t backtrace_max_size_bytes() const { return backtrace_max_size_bytes_; }

  int record_allocs_signal() const { return record_allocs_signal_; }
  size_t record_allocs_num_entries() const { return record_allocs_num_entries_; }
  const std::string& record_allocs_file() const { return record_allocs_file_; }
  bool record_allocs_on_exit() const { return record_allocs_on_exit_; }

  int check_unreachable_signal() const { return check_unreachable_signal_; }

  int log_allocator_stats_signal() const { return log_allocator_stats_signal_; }

 private:
  struct OptionInfo {
    uint64_t option;
    bool (Config::*process_func)(const std::string&, const std::string&);
  };

  bool ParseValue(const std::string& option, const std::string& value, size_t default_value,
                  size_t min_value, size_t max_value, size_t* new_value) const;

  bool ParseValue(const std::string& option, const std::string& value, size_t min_value,
                  size_t max_value, size_t* parsed_value) const;

  bool SetGuard(const std::string& option, const std::string& value);
  bool SetFrontGuard(const std::string& option, const std::string& value);
  bool SetRearGuard(const std::string& option, const std::string& value);

  bool SetFill(const std::string& option, const std::string& value);
  bool SetFillOnAlloc(const std::string& option, const std::string& value);
  bool SetFillOnFree(const std::string& option, const std::string& value);

  bool SetBacktrace(const std::string& option, const std::string& value);
  bool SetBacktraceEnableOnSignal(const std::string& option, const std::string& value);
  bool SetBacktraceDumpOnExit(const std::string& option, const std::string& value);
  bool SetBacktraceDumpPrefix(const std::string& option, const std::string& value);

  bool SetBacktraceSize(const std::string& option, const std::string& value);
  bool SetBacktraceMinSize(const std::string& option, const std::string& value);
  bool SetBacktraceMaxSize(const std::string& option, const std::string& value);

  bool SetExpandAlloc(const std::string& option, const std::string& value);

  bool SetFreeTrack(const std::string& option, const std::string& value);
  bool SetFreeTrackBacktraceNumFrames(const std::string& option, const std::string& value);

  bool SetRecordAllocs(const std::string& option, const std::string& value);
  bool SetRecordAllocsFile(const std::string& option, const std::string& value);
  bool SetRecordAllocsOnExit(const std::string& option, const std::string& value);

  bool VerifyValueEmpty(const std::string& option, const std::string& value);

  static bool GetOption(const char** option_str, std::string* option, std::string* value);

  const static std::unordered_map<std::string, OptionInfo> kOptions;

  size_t front_guard_bytes_ = 0;
  size_t rear_guard_bytes_ = 0;

  bool backtrace_enable_on_signal_ = false;
  int backtrace_signal_ = 0;
  int backtrace_dump_signal_ = 0;
  bool backtrace_enabled_ = false;
  size_t backtrace_frames_ = 0;
  bool backtrace_dump_on_exit_ = false;
  std::string backtrace_dump_prefix_;
  size_t backtrace_min_size_bytes_ = 0;
  size_t backtrace_max_size_bytes_ = 0;

  size_t fill_on_alloc_bytes_ = 0;
  size_t fill_on_free_bytes_ = 0;

  size_t expand_alloc_bytes_ = 0;

  size_t free_track_allocations_ = 0;
  size_t free_track_backtrace_num_frames_ = 0;

  int record_allocs_signal_ = 0;
  size_t record_allocs_num_entries_ = 0;
  std::string record_allocs_file_;
  bool record_allocs_on_exit_ = false;

  uint64_t options_ = 0;
  uint8_t fill_alloc_value_;
  uint8_t fill_free_value_;
  uint8_t front_guard_value_;
  uint8_t rear_guard_value_;

  int check_unreachable_signal_ = 0;
  int log_allocator_stats_signal_ = 0;
};
```