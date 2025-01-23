Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The primary goal is to analyze the `gumv8stream.cpp` file from the Frida dynamic instrumentation tool and explain its functionalities in the context of reverse engineering, low-level operations, and common user errors, while also tracing the user interaction.

**2. Initial Skim and High-Level Overview:**

First, I'd quickly skim the code to get a general idea of what it's doing. I see includes for `<gio/*.h>`, suggesting it deals with input/output streams. The presence of `v8::` and `GumV8*` types indicates it's interacting with the V8 JavaScript engine within the Frida framework. Keywords like "read", "write", "close", and "stream" stand out. The `#ifdef HAVE_WINDOWS` block suggests platform-specific implementations.

**3. Identifying Core Functionalities:**

Next, I'd look for key structures, enums, and function declarations to pinpoint the main functionalities.

* **`GumV8ReadStrategy` and `GumV8WriteStrategy`:** These enums tell us there are different ways to read and write data (all or some).
* **`GumV8*Operation` structs:**  These structures (like `GumV8CloseIOStreamOperation`, `GumV8ReadOperation`, etc.) likely represent asynchronous operations, a common pattern for non-blocking I/O. The inheritance from `GumV8ObjectOperation` reinforces this.
* **`GUMJS_DECLARE_CONSTRUCTOR` and `GUMJS_DECLARE_FUNCTION` macros:**  These strongly suggest the creation of JavaScript-accessible classes and methods. The names following these macros (e.g., `gumjs_io_stream_construct`, `gumjs_input_stream_close`) provide clues about what each function does.
* **`_gum_v8_stream_init`:** This function seems responsible for initializing the JavaScript module, creating class templates for `IOStream`, `InputStream`, and `OutputStream`, as well as platform-specific native stream classes.
* **`gumjs_native_input_stream_construct` and `gumjs_native_output_stream_construct`:** These constructors handle the creation of streams from native file handles or descriptors.

**4. Relating to Reverse Engineering:**

Now, I'd start connecting these functionalities to reverse engineering concepts:

* **Interception and Modification:** Frida's core purpose is to intercept and modify program behavior. File I/O is a crucial aspect of program behavior. Being able to read and write to files or descriptors allows an attacker or reverse engineer to inspect data, inject code, or alter program state.
* **Dynamic Analysis:** This code is part of Frida, a *dynamic* instrumentation tool. This means it operates on a running process, allowing interaction with file I/O as it happens.

**5. Examining Low-Level and Kernel Interactions:**

The presence of platform-specific code is a strong indicator of low-level interaction.

* **Windows vs. Unix:** The `#ifdef HAVE_WINDOWS` block clearly shows the code handles different operating systems. It uses `gwin32inputstream`/`gwin32outputstream` for Windows and `gunixinputstream`/`gunixoutputstream` for Unix-like systems.
* **File Handles/Descriptors:** The `GumStreamHandle` type and the definitions of `GUM_NATIVE_KIND` ("Windows file handle" or "file descriptor") directly point to interaction with the operating system's core I/O mechanisms.
* **`gpointer` and `gint`:** These are GLib types, indicating the code uses GLib's cross-platform abstractions for I/O. GLib itself often wraps underlying system calls.

**6. Analyzing Logic and Control Flow:**

I would then examine the functions in more detail, paying attention to the flow of data and control.

* **Asynchronous Operations:** The `*_async` and `*_finish` functions (e.g., `g_io_stream_close_async`, `g_io_stream_close_finish`) indicate asynchronous operations. The `GumV8*Operation` structs are used to manage the state of these operations and handle callbacks.
* **Read/Write Strategies:** The `GUM_V8_READ_SOME`/`GUM_V8_READ_ALL` and `GUM_V8_WRITE_SOME`/`GUM_V8_WRITE_ALL` enums influence how data is read or written.
* **Error Handling:**  The code consistently checks for errors using `GError *error` and reports them back to the JavaScript side.

**7. Identifying Potential User Errors:**

Based on the code's structure and the types of operations, I'd consider common mistakes users might make:

* **Incorrect Arguments:**  The `_gum_v8_args_parse` function is used to validate arguments passed from JavaScript. Passing the wrong type or number of arguments is a common error.
* **Closing Streams Multiple Times:** Attempting to close a stream that's already closed could lead to errors. The code tries to handle this by canceling pending operations.
* **Reading/Writing Incorrect Sizes:**  Providing an incorrect size to `read` or `write` operations could result in truncated data or errors.
* **Not Handling Errors:** The JavaScript callbacks receive error information. If the user doesn't check for errors, they might not realize an operation failed.

**8. Tracing User Interaction (Debugging Clues):**

To understand how a user reaches this code, I'd consider the API exposed to the Frida user:

* **`frida.open_io_stream()` (Hypothetical):**  The user likely uses a Frida API to create or open streams, possibly based on file paths or file descriptors. This would lead to the `gumjs_io_stream_construct` or the native stream constructors.
* **`stream.input.read()` or `stream.output.write()`:**  These JavaScript methods would correspond to the `gumjs_input_stream_read` and `gumjs_output_stream_write` functions in the C++ code.
* **`stream.close()`:** The `gumjs_io_stream_close`, `gumjs_input_stream_close`, or `gumjs_output_stream_close` functions would be invoked.

**9. Structuring the Explanation:**

Finally, I'd organize the findings into a clear and structured explanation, covering the requested aspects: functionality, relationship to reverse engineering, low-level details, logic, user errors, and debugging clues. Using examples and clear language is crucial for making the explanation understandable. I'd iterate on the explanation, refining it as I uncover more details in the code.

This iterative process of skimming, identifying key elements, connecting to concepts, and analyzing details allows for a comprehensive understanding of the code and the generation of a detailed and accurate explanation.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumv8stream.cpp` 这个文件。

**文件功能概述**

这个 C++ 文件是 Frida 动态 instrumentation 工具中 `frida-gum` 组件的一部分，专门负责将底层的 I/O 流操作桥接到 V8 JavaScript 引擎。它的主要功能是：

1. **提供 JavaScript 中操作 I/O 流的接口:** 它定义了 JavaScript 中可用的 `IOStream`, `InputStream`, 和 `OutputStream` 类，以及它们的方法，比如 `close`, `read`, `readAll`, `write`, `writeAll`, `writeMemoryRegion`。
2. **封装底层的 GIOStream, GInputStream, GOutputStream:** 它使用了 GLib 库提供的跨平台 I/O 流抽象（`GIOStream`, `GInputStream`, `GOutputStream`），使得 Frida 可以在不同操作系统上以统一的方式处理 I/O 操作。
3. **处理异步 I/O 操作:**  使用了 GLib 的异步 API (`*_async` 和 `*_finish` 函数) 来执行 I/O 操作，避免阻塞 JavaScript 引擎的主线程。
4. **管理资源:** 负责创建和销毁底层的 GIOStream 对象，并将其与 JavaScript 对象关联起来。
5. **处理平台差异:**  通过预编译宏 (`#ifdef HAVE_WINDOWS`) 来处理 Windows 和 Unix-like 系统在创建本地流时的差异。

**与逆向方法的关系及举例说明**

这个文件直接关系到逆向工程中的数据流分析和交互。通过 Frida 提供的 JavaScript API，逆向工程师可以：

* **读取目标进程的文件内容:**  使用 `InputStream` 的 `read` 或 `readAll` 方法可以读取目标进程打开的文件，例如配置文件、数据文件等。
    * **例子:**  假设一个 Android 应用将其加密的数据库文件读取到内存中。逆向工程师可以使用 Frida 脚本打开该数据库文件，并使用 `InputStream` 读取其内容，从而在运行时获取加密后的数据。
* **修改目标进程的文件内容:** 使用 `OutputStream` 的 `write` 或 `writeAll` 方法可以修改目标进程正在写入的文件，例如修改日志文件、修改配置文件等。
    * **例子:**  一个恶意软件可能会在运行时下载 Payload 并写入到磁盘上的一个文件中。逆向工程师可以使用 Frida 脚本拦截该写入操作，并修改写入的内容，例如替换成无害的数据或者分析恶意 Payload 的结构。
* **与目标进程进行自定义的 I/O 交互:** 可以创建 `NativeInputStream` 和 `NativeOutputStream` 来操作目标进程已经打开的文件描述符或句柄，从而与目标进程进行更底层的交互。
    * **例子:**  一个网络服务程序可能使用 Socket 进行通信。逆向工程师可以使用 Frida 脚本获取该 Socket 的文件描述符，并使用 `NativeInputStream` 和 `NativeOutputStream` 来读取和发送原始的网络数据包，从而分析其通信协议。
* **注入数据到目标进程:** 使用 `OutputStream` 的 `writeMemoryRegion` 方法可以将数据写入到目标进程的任意内存地址，这可以用于代码注入或数据修改。
    * **例子:**  逆向工程师可以通过分析目标进程的内存布局，找到存储敏感数据（例如密钥）的位置，然后使用 `writeMemoryRegion` 方法修改该内存区域的值。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明**

* **二进制底层:**
    * **内存地址操作:** `gumjs_output_stream_write_memory_region` 函数直接操作内存地址，需要理解目标进程的内存布局，包括代码段、数据段、堆栈等。参数中的 `gconstpointer address` 代表目标进程的内存地址。
    * **数据块读写:**  `read` 和 `write` 操作涉及将二进制数据块从一个地方复制到另一个地方。需要理解字节序（Endianness）等概念，尤其是在跨平台或与网络协议交互时。
    * **文件描述符/句柄:**  `NativeInputStream` 和 `NativeOutputStream` 直接操作文件描述符 (Linux/Android) 或文件句柄 (Windows)，这些是操作系统内核用来标识打开的文件或其他 I/O 资源的整数或指针。
* **Linux/Android 内核:**
    * **文件系统:**  理解 Linux/Android 的虚拟文件系统 (VFS) 概念，以及如何通过文件路径访问文件。
    * **系统调用:** 底层的 I/O 操作最终会通过系统调用 (如 `read`, `write`, `close`) 进入内核。虽然 `gumv8stream.cpp` 使用的是 GLib 封装的 API，但理解这些系统调用有助于理解其背后的原理。
    * **进程间通信 (IPC):**  文件描述符也可以用于进程间通信，例如管道。Frida 可以利用这些机制来监控或修改不同进程之间的数据流动。
* **Android 框架:**
    * **Binder:** Android 的 Binder 机制也涉及到数据流的传递。虽然这个文件没有直接处理 Binder，但 Frida 可以在更高层次上拦截 Binder 调用，并可能涉及到读取或修改 Binder 传递的数据。
    * **Android 文件权限:**  在 Android 环境下，操作文件需要考虑 SELinux 和文件权限的限制。Frida 脚本的执行上下文可能影响其对文件的访问权限。

**逻辑推理及假设输入与输出**

以 `gumjs_input_stream_read` 函数为例：

**假设输入:**

* `self`: 一个指向 `GumV8InputStream` 对象的指针，代表一个已打开的输入流。
* `args`:  一个包含参数的 `GumV8Args` 对象，其中包含了：
    * 第一个参数: `size` (guint64 类型), 表示要读取的字节数，例如 `1024`。
    * 第二个参数: `callback` (Local<Function> 类型),  一个 JavaScript 回调函数，用于接收读取的结果。

**逻辑推理:**

1. `gumjs_input_stream_read` 函数被调用，并解析出要读取的大小 `size` 和回调函数 `callback`。
2. 创建一个 `GumV8ReadOperation` 对象，存储读取策略 (`GUM_V8_READ_SOME`)，分配一个大小为 `size` 的缓冲区 `buffer`。
3. 调用 `gum_v8_read_operation_start` 函数，启动异步读取操作。
4. `gum_v8_read_operation_start` 函数调用 GLib 的 `g_input_stream_read_async` 函数，从底层的输入流中读取最多 `size` 个字节到 `buffer` 中。
5. 当读取操作完成时，GLib 会调用 `gum_v8_read_operation_finish` 函数。
6. `gum_v8_read_operation_finish` 函数获取实际读取的字节数 `bytes_read` 和可能的错误信息。
7. 创建一个 JavaScript ArrayBuffer 对象，包含读取到的数据。
8. 调用 JavaScript 回调函数 `callback`，并传递两个参数：
    * 第一个参数：错误对象 (如果发生错误，否则为 `null`)。
    * 第二个参数：包含读取数据的 ArrayBuffer 对象 (如果发生错误，可能为 `null`)。

**可能的输出 (JavaScript 回调函数的参数):**

* **成功读取:** `[null, ArrayBuffer containing 1024 bytes of data]`
* **读取到末尾 (少于 1024 字节):** `[null, ArrayBuffer containing fewer than 1024 bytes of data]`
* **读取发生错误:** `[Error object, null]`

**用户或编程常见的使用错误及举例说明**

1. **未正确关闭流:**  如果用户在 JavaScript 中创建了 `IOStream`, `InputStream`, 或 `OutputStream` 对象后，忘记调用 `close()` 方法，会导致底层的 GIOStream 对象没有被释放，可能造成资源泄漏。
    * **例子:**

    ```javascript
    // JavaScript 代码
    const stream = new IOStream(...);
    const input = stream.input;
    input.read(1024, function(error, data) {
      // ... 处理数据
      // 忘记调用 stream.close() 或 input.close()
    });
    ```

2. **使用已关闭的流:**  如果在调用 `close()` 方法后，仍然尝试对流进行读取或写入操作，会导致错误。
    * **例子:**

    ```javascript
    const stream = new IOStream(...);
    stream.close(function(error, success) {
      stream.input.read(1024, function(error, data) { // 错误：流已关闭
        // ...
      });
    });
    ```

3. **读取或写入大小不匹配:**  `readAll` 方法期望读取指定大小的所有数据，如果实际可读数据少于指定大小，可能会抛出 "short read" 错误。类似地，`writeAll` 如果未能写入所有指定的数据，也可能抛出 "short write" 错误。
    * **例子:**

    ```javascript
    const input = new InputStream(...);
    input.readAll(999999, function(error, data) { // 如果实际可读数据不多
      if (error) {
        console.error(error); // 可能输出 "short read" 错误
      }
    });
    ```

4. **传递错误的参数类型:**  例如，`read` 方法的第一个参数应该是数字（表示要读取的字节数），如果传递了字符串或其他类型，会导致参数解析失败。
    * **例子:**

    ```javascript
    const input = new InputStream(...);
    input.read("not a number", function(error, data) { // 错误的参数类型
      // ...
    });
    ```

5. **忘记处理回调函数的错误:**  I/O 操作可能会失败，例如文件不存在、权限不足等。如果用户没有在回调函数中检查 `error` 参数，可能会忽略这些错误，导致程序行为异常。
    * **例子:**

    ```javascript
    const input = new InputStream("/path/to/nonexistent/file");
    input.readAll(1024, function(error, data) {
      // 没有检查 error，如果文件不存在，data 将为 null，但代码可能仍然尝试处理 data
      console.log("Read data:", data);
    });
    ```

**用户操作是如何一步步的到达这里，作为调试线索**

当用户在 Frida 脚本中执行与 I/O 流相关的操作时，代码执行流程会逐步到达 `gumv8stream.cpp` 中的相关函数：

1. **用户编写 Frida 脚本，使用 `IOStream`, `InputStream`, 或 `OutputStream` 类:**  例如：

   ```javascript
   // Frida 脚本
   function main() {
     const fd = /* 获取目标进程的文件描述符 */;
     const inputStream = new NativeInputStream(fd, { autoClose: false });
     inputStream.readAll(1024, function(error, data) {
       if (error) {
         console.error("Read error:", error);
       } else {
         console.log("Read data:", data);
       }
       inputStream.close(function(closeError, success) {
         if (closeError) {
           console.error("Close error:", closeError);
         }
       });
     });
   }

   setImmediate(main);
   ```

2. **Frida 引擎接收并解析该脚本:**  Frida 的 JavaScript 引擎 (V8) 会解析用户编写的 JavaScript 代码。

3. **执行 `new NativeInputStream(fd, ...)`:** 当执行到创建 `NativeInputStream` 对象的代码时，会调用 `gumjs_native_input_stream_construct` 函数。

4. **`gumjs_native_input_stream_construct` 解析参数:**  该函数会解析用户传递的文件描述符 `fd` 和选项对象。

5. **创建底层的 GUnixInputStream (Linux/Android) 或 GWin32InputStream (Windows):**  根据操作系统，调用相应的 GLib 函数 (`g_unix_input_stream_new` 或 `g_win32_input_stream_new`) 创建底层的输入流对象。

6. **创建 JavaScript 的 InputStream 对象:**  调用 `gumjs_input_stream_construct`，将底层的 GInputStream 对象包装成 JavaScript 可操作的 `InputStream` 对象。

7. **执行 `inputStream.readAll(1024, ...)`:**  当执行到 `readAll` 方法时，会调用 `gumjs_input_stream_read_all` 函数。

8. **`gumjs_input_stream_read_all` 启动异步读取:**  该函数会分配缓冲区，创建 `GumV8ReadOperation` 对象，并调用 `g_input_stream_read_all_async` 启动异步读取操作。

9. **底层 I/O 操作执行:**  操作系统执行实际的读取操作。

10. **读取完成，调用回调:** 当数据读取完成或发生错误时，GLib 会调用 `gum_v8_read_operation_finish` 函数。

11. **`gum_v8_read_operation_finish` 处理结果并调用 JavaScript 回调:**  该函数将读取到的数据或错误信息封装成 JavaScript 对象，并通过之前传递的回调函数返回给用户脚本。

12. **执行 `inputStream.close(...)`:**  当执行到 `close` 方法时，会调用 `gumjs_input_stream_close` 函数，该函数会调用底层的 `g_input_stream_close_async` 来关闭流。

**调试线索:**

* **查看 Frida 脚本的调用栈:** 如果在执行 Frida 脚本时出现错误，可以查看 V8 引擎的调用栈，了解代码执行到哪个 JavaScript 方法，以及是如何调用到 `gumv8stream.cpp` 中的函数的。
* **使用 Frida 的 `console.log` 输出调试信息:** 在 Frida 脚本中添加 `console.log` 语句，可以输出变量的值，帮助理解参数传递和代码执行流程。
* **GDB 调试 Frida-agent 或 frida-server:** 如果需要深入了解 C++ 层的执行情况，可以使用 GDB 连接到 `frida-agent` 或 `frida-server` 进程，并设置断点在 `gumv8stream.cpp` 中的关键函数上，例如 `gumjs_input_stream_read`, `gum_v8_read_operation_finish` 等，来查看底层的执行状态和变量值。
* **检查 GLib 的错误信息:**  GLib 的 I/O 函数会将错误信息存储在 `GError` 对象中。在 `gum_v8_read_operation_finish` 等函数中，可以查看 `error` 变量的值，了解底层的 I/O 操作是否发生了错误以及错误类型。

希望以上分析能够帮助你理解 `gumv8stream.cpp` 文件的功能和它在 Frida 中的作用。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8stream.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2016-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8stream.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

using namespace v8;

#ifdef HAVE_WINDOWS
# include <gio/gwin32inputstream.h>
# include <gio/gwin32outputstream.h>

# define GUM_NATIVE_INPUT_STREAM "Win32InputStream"
# define GUM_NATIVE_OUTPUT_STREAM "Win32OutputStream"
# define GUM_NATIVE_KIND "Windows file handle"
# define GUM_NATIVE_FORMAT "p"
typedef gpointer GumStreamHandle;
#else
# include <gio/gunixinputstream.h>
# include <gio/gunixoutputstream.h>

# define GUM_NATIVE_INPUT_STREAM "UnixInputStream"
# define GUM_NATIVE_OUTPUT_STREAM "UnixOutputStream"
# define GUM_NATIVE_KIND "file descriptor"
# define GUM_NATIVE_FORMAT "i"
typedef gint GumStreamHandle;
#endif

#define GUMJS_MODULE_NAME Stream

struct GumV8CloseIOStreamOperation
    : public GumV8ObjectOperation<GIOStream, GumV8Stream>
{
};

struct GumV8CloseInputOperation
    : public GumV8ObjectOperation<GInputStream, GumV8Stream>
{
};

enum GumV8ReadStrategy
{
  GUM_V8_READ_SOME,
  GUM_V8_READ_ALL
};

struct GumV8ReadOperation
    : public GumV8ObjectOperation<GInputStream, GumV8Stream>
{
  GumV8ReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
};

struct GumV8CloseOutputOperation
    : public GumV8ObjectOperation<GOutputStream, GumV8Stream>
{
};

enum GumV8WriteStrategy
{
  GUM_V8_WRITE_SOME,
  GUM_V8_WRITE_ALL
};

struct GumV8WriteOperation
    : public GumV8ObjectOperation<GOutputStream, GumV8Stream>
{
  GumV8WriteStrategy strategy;
  GBytes * bytes;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_io_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_io_stream_close)
static void gum_v8_close_io_stream_operation_start (
    GumV8CloseIOStreamOperation * self);
static void gum_v8_close_io_stream_operation_finish (GIOStream * stream,
    GAsyncResult * result, GumV8CloseIOStreamOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_input_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_close)
static void gum_v8_close_input_operation_start (
    GumV8CloseInputOperation * self);
static void gum_v8_close_input_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumV8CloseInputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read_all)
static void gumjs_input_stream_read_with_strategy (GumV8InputStream * self,
    const GumV8Args * args, GumV8ReadStrategy strategy);
static void gum_v8_read_operation_dispose (GumV8ReadOperation * self);
static void gum_v8_read_operation_start (GumV8ReadOperation * self);
static void gum_v8_read_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumV8ReadOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_output_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_close)
static void gum_v8_close_output_operation_start (
    GumV8CloseOutputOperation * self);
static void gum_v8_close_output_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumV8CloseOutputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_all)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_memory_region)
static void gumjs_output_stream_write_with_strategy (GumV8OutputStream * self,
    const GumV8Args * args, GumV8WriteStrategy strategy);
static void gum_v8_write_operation_dispose (GumV8WriteOperation * self);
static void gum_v8_write_operation_start (GumV8WriteOperation * self);
static void gum_v8_write_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumV8WriteOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_input_stream_construct)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_output_stream_construct)

static gboolean gum_v8_native_stream_ctor_args_parse (const GumV8Args * args,
    GumStreamHandle * handle, gboolean * auto_close, GumV8Core * core);

static const GumV8Function gumjs_io_stream_functions[] =
{
  { "_close", gumjs_io_stream_close },

  { NULL, NULL }
};

static const GumV8Function gumjs_input_stream_functions[] =
{
  { "_close", gumjs_input_stream_close },
  { "_read", gumjs_input_stream_read },
  { "_readAll", gumjs_input_stream_read_all },

  { NULL, NULL }
};

static const GumV8Function gumjs_output_stream_functions[] =
{
  { "_close", gumjs_output_stream_close },
  { "_write", gumjs_output_stream_write },
  { "_writeAll", gumjs_output_stream_write_all },
  { "_writeMemoryRegion", gumjs_output_stream_write_memory_region },

  { NULL, NULL }
};

void
_gum_v8_stream_init (GumV8Stream * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto io_stream = _gum_v8_create_class ("IOStream",
      gumjs_io_stream_construct, scope, module, isolate);
  _gum_v8_class_add (io_stream, gumjs_io_stream_functions, module, isolate);
  self->io_stream = new Global<FunctionTemplate> (isolate, io_stream);

  auto input_stream = _gum_v8_create_class ("InputStream",
      gumjs_input_stream_construct, scope, module, isolate);
  _gum_v8_class_add (input_stream, gumjs_input_stream_functions, module,
      isolate);
  self->input_stream = new Global<FunctionTemplate> (isolate, input_stream);

  auto output_stream = _gum_v8_create_class ("OutputStream",
      gumjs_output_stream_construct, scope, module, isolate);
  _gum_v8_class_add (output_stream, gumjs_output_stream_functions, module,
      isolate);
  self->output_stream = new Global<FunctionTemplate> (isolate, output_stream);

  auto native_input_stream = _gum_v8_create_class (GUM_NATIVE_INPUT_STREAM,
      gumjs_native_input_stream_construct, scope, module, isolate);
  native_input_stream->Inherit (input_stream);

  auto native_output_stream = _gum_v8_create_class (GUM_NATIVE_OUTPUT_STREAM,
      gumjs_native_output_stream_construct, scope, module, isolate);
  native_output_stream->Inherit (output_stream);
}

void
_gum_v8_stream_realize (GumV8Stream * self)
{
  gum_v8_object_manager_init (&self->objects);
}

void
_gum_v8_stream_flush (GumV8Stream * self)
{
  gum_v8_object_manager_flush (&self->objects);
}

void
_gum_v8_stream_dispose (GumV8Stream * self)
{
  gum_v8_object_manager_free (&self->objects);
}

void
_gum_v8_stream_finalize (GumV8Stream * self)
{
  delete self->io_stream;
  delete self->input_stream;
  delete self->output_stream;
  self->io_stream = nullptr;
  self->input_stream = nullptr;
  self->output_stream = nullptr;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_io_stream_construct)
{
  auto context = isolate->GetCurrentContext ();

  GIOStream * stream;
  if (!_gum_v8_args_parse (args, "X", &stream))
    return;

  gum_v8_object_manager_add (&module->objects, wrapper, stream, module);

  {
    auto ctor (Local<FunctionTemplate>::New (isolate, *module->input_stream));
    Local<Value> argv[] = {
      External::New (isolate, g_object_ref (
          g_io_stream_get_input_stream (stream)))
    };
    auto input = ctor->GetFunction (context).ToLocalChecked ()
        ->NewInstance (context, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
    _gum_v8_object_set (wrapper, "input", input, core);
  }

  {
    auto ctor (Local<FunctionTemplate>::New (isolate, *module->output_stream));
    Local<Value> argv[] = {
      External::New (isolate, g_object_ref (
          g_io_stream_get_output_stream (stream)))
    };
    auto output = ctor->GetFunction (context).ToLocalChecked ()
        ->NewInstance (context, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
    _gum_v8_object_set (wrapper, "output", output, core);
  }
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_io_stream_close, GumV8IOStream)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_close_io_stream_operation_start);

  auto dependencies = g_ptr_array_sized_new (2);

  auto objects = &module->objects;
  auto stream = self->handle;

  auto input =
      gum_v8_object_manager_lookup<GInputStream, GumV8Stream> (objects,
          g_io_stream_get_input_stream (stream));
  if (input != NULL)
  {
    g_cancellable_cancel (input->cancellable);
    g_ptr_array_add (dependencies, input);
  }

  auto output =
      gum_v8_object_manager_lookup<GOutputStream, GumV8Stream> (objects,
          g_io_stream_get_output_stream (stream));
  if (output != NULL)
  {
    g_cancellable_cancel (output->cancellable);
    g_ptr_array_add (dependencies, output);
  }

  g_cancellable_cancel (self->cancellable);

  gum_v8_object_operation_schedule_when_idle (op, dependencies);

  g_ptr_array_unref (dependencies);
}

static void
gum_v8_close_io_stream_operation_start (GumV8CloseIOStreamOperation * self)
{
  g_io_stream_close_async (self->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_v8_close_io_stream_operation_finish, self);
}

static void
gum_v8_close_io_stream_operation_finish (GIOStream * stream,
                                         GAsyncResult * result,
                                         GumV8CloseIOStreamOperation * self)
{
  GError * error = NULL;
  gboolean success;

  success = g_io_stream_close_finish (stream, result, &error);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto error_value = _gum_v8_error_new_take_error (isolate, &error);
    auto success_value = success ? True (isolate) : False (isolate);

    Local<Value> argv[] = { error_value, success_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_object_operation_finish (self);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_input_stream_construct)
{
  GInputStream * stream;
  if (!_gum_v8_args_parse (args, "X", &stream))
    return;

  gum_v8_object_manager_add (&module->objects, wrapper, stream, module);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_input_stream_close, GumV8InputStream)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  g_cancellable_cancel (self->cancellable);

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_close_input_operation_start);
  gum_v8_object_operation_schedule_when_idle (op);
}

static void
gum_v8_close_input_operation_start (GumV8CloseInputOperation * self)
{
  g_input_stream_close_async (self->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_v8_close_input_operation_finish, self);
}

static void
gum_v8_close_input_operation_finish (GInputStream * stream,
                                     GAsyncResult * result,
                                     GumV8CloseInputOperation * self)
{
  GError * error = NULL;
  gboolean success;

  success = g_input_stream_close_finish (stream, result, &error);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value = _gum_v8_error_new_take_error (isolate, &error);
    auto success_value = success ? True (isolate) : False (isolate);

    Local<Value> argv[] = { error_value, success_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_object_operation_finish (self);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_input_stream_read, GumV8InputStream)
{
  gumjs_input_stream_read_with_strategy (self, args, GUM_V8_READ_SOME);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_input_stream_read_all, GumV8InputStream)
{
  gumjs_input_stream_read_with_strategy (self, args, GUM_V8_READ_ALL);
}

static void
gumjs_input_stream_read_with_strategy (GumV8InputStream * self,
                                       const GumV8Args * args,
                                       GumV8ReadStrategy strategy)
{
  guint64 size;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "QF", &size, &callback))
    return;

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_read_operation_start, gum_v8_read_operation_dispose);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_read_operation_dispose (GumV8ReadOperation * self)
{
  g_free (self->buffer);
}

static void
gum_v8_read_operation_start (GumV8ReadOperation * self)
{
  auto stream = self->object;

  if (self->strategy == GUM_V8_READ_SOME)
  {
    g_input_stream_read_async (stream->handle, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_v8_read_operation_finish, self);
  }
  else
  {
    g_assert (self->strategy == GUM_V8_READ_ALL);

    g_input_stream_read_all_async (stream->handle, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_v8_read_operation_finish, self);
  }
}

static void
gum_v8_read_operation_finish (GInputStream * stream,
                              GAsyncResult * result,
                              GumV8ReadOperation * self)
{
  gsize bytes_read = 0;
  GError * error = NULL;

  if (self->strategy == GUM_V8_READ_SOME)
  {
    gsize n;

    n = g_input_stream_read_finish (stream, result, &error);
    if (n > 0)
      bytes_read = n;
  }
  else
  {
    g_assert (self->strategy == GUM_V8_READ_ALL);

    g_input_stream_read_all_finish (stream, result, &bytes_read, &error);
  }

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value, data_value;
    if (self->strategy == GUM_V8_READ_ALL && bytes_read != self->buffer_size)
    {
      if (error != NULL)
      {
        error_value = _gum_v8_error_new_take_error (isolate, &error);
      }
      else
      {
        error_value = Exception::Error (
            String::NewFromUtf8 (isolate, "short read").ToLocalChecked ());
      }
      data_value = _gum_v8_array_buffer_new_take (isolate,
          g_steal_pointer (&self->buffer), bytes_read);
    }
    else if (error == NULL)
    {
      error_value = Null (isolate);
      data_value = _gum_v8_array_buffer_new_take (isolate,
          g_steal_pointer (&self->buffer), bytes_read);
    }
    else
    {
      error_value = _gum_v8_error_new_take_error (isolate, &error);
      data_value = Null (isolate);
    }

    Local<Value> argv[] = { error_value, data_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_object_operation_finish (self);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_output_stream_construct)
{
  GOutputStream * stream;
  if (!_gum_v8_args_parse (args, "X", &stream))
    return;

  gum_v8_object_manager_add (&module->objects, wrapper, stream, module);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_output_stream_close, GumV8OutputStream)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  g_cancellable_cancel (self->cancellable);

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_close_output_operation_start);
  gum_v8_object_operation_schedule_when_idle (op);
}

static void
gum_v8_close_output_operation_start (GumV8CloseOutputOperation * self)
{
  g_output_stream_close_async (self->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_v8_close_output_operation_finish, self);
}

static void
gum_v8_close_output_operation_finish (GOutputStream * stream,
                                      GAsyncResult * result,
                                      GumV8CloseOutputOperation * self)
{
  GError * error = NULL;
  gboolean success;

  success = g_output_stream_close_finish (stream, result, &error);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto error_value = _gum_v8_error_new_take_error (isolate, &error);
    auto success_value = success ? True (isolate) : False (isolate);

    Local<Value> argv[] = { error_value, success_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_object_operation_finish (self);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_output_stream_write, GumV8OutputStream)
{
  gumjs_output_stream_write_with_strategy (self, args, GUM_V8_WRITE_SOME);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_output_stream_write_all, GumV8OutputStream)
{
  gumjs_output_stream_write_with_strategy (self, args, GUM_V8_WRITE_ALL);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_output_stream_write_memory_region,
    GumV8OutputStream)
{
  gconstpointer address;
  gsize length;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "pZF", &address, &length, &callback))
    return;

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_write_operation_start, gum_v8_write_operation_dispose);
  op->strategy = GUM_V8_WRITE_ALL;
  op->bytes = g_bytes_new_static (address, length);
  gum_v8_object_operation_schedule (op);
}

static void
gumjs_output_stream_write_with_strategy (GumV8OutputStream * self,
                                         const GumV8Args * args,
                                         GumV8WriteStrategy strategy)
{
  GBytes * bytes;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "BF", &bytes, &callback))
    return;

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_write_operation_start, gum_v8_write_operation_dispose);
  op->strategy = strategy;
  op->bytes = bytes;
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_write_operation_dispose (GumV8WriteOperation * self)
{
  g_bytes_unref (self->bytes);
}

static void
gum_v8_write_operation_start (GumV8WriteOperation * self)
{
  auto stream = self->object;

  if (self->strategy == GUM_V8_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (stream->handle, self->bytes,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_v8_write_operation_finish, self);
  }
  else
  {
    g_assert (self->strategy == GUM_V8_WRITE_ALL);

    gsize size;
    gconstpointer data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (stream->handle, data, size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_v8_write_operation_finish, self);
  }
}

static void
gum_v8_write_operation_finish (GOutputStream * stream,
                               GAsyncResult * result,
                               GumV8WriteOperation * self)
{
  gsize bytes_written = 0;
  GError * error = NULL;

  if (self->strategy == GUM_V8_WRITE_SOME)
  {
    gssize n;

    n = g_output_stream_write_bytes_finish (stream, result, &error);
    if (n > 0)
      bytes_written = n;
  }
  else
  {
    g_assert (self->strategy == GUM_V8_WRITE_ALL);

    g_output_stream_write_all_finish (stream, result, &bytes_written, &error);
  }

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value;
    auto size_value = Integer::NewFromUnsigned (isolate, bytes_written);
    if (self->strategy == GUM_V8_WRITE_ALL &&
        bytes_written != g_bytes_get_size (self->bytes))
    {
      if (error != NULL)
      {
        error_value = _gum_v8_error_new_take_error (isolate, &error);
      }
      else
      {
        error_value = Exception::Error (
            String::NewFromUtf8 (isolate, "short write").ToLocalChecked ());
      }
    }
    else
    {
      error_value = _gum_v8_error_new_take_error (isolate, &error);
    }

    Local<Value> argv[] = { error_value, size_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_object_operation_finish (self);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_input_stream_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new " GUM_NATIVE_INPUT_STREAM
        "()` to create a new instance");
    return;
  }

  GumStreamHandle handle;
  gboolean auto_close;
  if (!gum_v8_native_stream_ctor_args_parse (args, &handle, &auto_close, core))
    return;

#ifdef HAVE_WINDOWS
  auto stream = g_win32_input_stream_new (handle, auto_close);
#else
  auto stream = g_unix_input_stream_new (handle, auto_close);
#endif

  auto context = isolate->GetCurrentContext ();
  auto base_ctor (Local<FunctionTemplate>::New (isolate,
      *module->input_stream));
  Local<Value> argv[] = { External::New (isolate, stream) };
  base_ctor->GetFunction (context).ToLocalChecked ()
      ->Call (context, wrapper, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_output_stream_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new " GUM_NATIVE_OUTPUT_STREAM
        "()` to create a new instance");
    return;
  }

  GumStreamHandle handle;
  gboolean auto_close;
  if (!gum_v8_native_stream_ctor_args_parse (args, &handle, &auto_close, core))
    return;

#ifdef HAVE_WINDOWS
  auto stream = g_win32_output_stream_new (handle, auto_close);
#else
  auto stream = g_unix_output_stream_new (handle, auto_close);
#endif

  auto context = isolate->GetCurrentContext ();
  auto base_ctor (Local<FunctionTemplate>::New (isolate,
      *module->output_stream));
  Local<Value> argv[] = { External::New (isolate, stream) };
  base_ctor->GetFunction (context).ToLocalChecked ()
      ->Call (context, wrapper, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
}

static gboolean
gum_v8_native_stream_ctor_args_parse (const GumV8Args * args,
                                      GumStreamHandle * handle,
                                      gboolean * auto_close,
                                      GumV8Core * core)
{
  Local<Object> options;
  if (!_gum_v8_args_parse (args, GUM_NATIVE_FORMAT "|O", handle, &options))
    return FALSE;

  *auto_close = FALSE;
  if (!options.IsEmpty ())
  {
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto auto_close_key = _gum_v8_string_new_ascii (isolate, "autoClose");
    Local<Value> value;
    if (options->Get (context, auto_close_key).ToLocal (&value) &&
        value->IsBoolean ())
    {
      *auto_close = value.As<Boolean> ()->BooleanValue (isolate);
    }
  }

  return TRUE;
}
```