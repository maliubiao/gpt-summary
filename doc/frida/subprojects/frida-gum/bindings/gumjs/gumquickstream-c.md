Response:
Let's break down the thought process to analyze the `gumquickstream.c` file and address the prompt's requirements.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this C code file within the context of Frida, a dynamic instrumentation toolkit. We need to extract its capabilities, relate them to reverse engineering, identify low-level interactions, note any logic, pinpoint potential user errors, and understand how a user might trigger this code.

**2. Initial Code Scan (High-Level Overview):**

* **Includes:** The first thing to notice are the `#include` directives. This tells us about external dependencies. `gumquickstream.h` suggests a header file for this specific code. The `<gio/*.h>` includes are crucial. `gio` stands for GLib I/O, indicating this code deals with input and output streams, likely in an asynchronous manner. The `HAVE_WINDOWS` conditional reveals platform-specific handling.
* **Defines:**  Macros like `GUM_NATIVE_INPUT_STREAM` and `GUM_NATIVE_OUTPUT_STREAM` strongly suggest this code wraps native operating system stream handles. The `typedef` for `GumStreamHandle` confirms this.
* **Structs:**  The various `struct` definitions (`GumQuickCloseIOStreamOperation`, `GumQuickReadOperation`, etc.) indicate different asynchronous operations that can be performed on streams. The presence of `strategy` fields suggests variations in how read/write operations are handled (e.g., read some vs. read all).
* **Function Declarations:** The `GUMJS_DECLARE_*` macros point to JavaScript bindings. This confirms the file's role in exposing stream functionality to JavaScript within the Frida environment. The function names themselves are very descriptive (e.g., `gumjs_io_stream_close`, `gumjs_input_stream_read`).
* **Static Functions:** The presence of `static` functions like `gum_quick_close_io_stream_operation_start` and `gum_quick_read_operation_finish` strongly suggests an asynchronous operation management system. These likely handle the actual execution and completion of stream operations.
* **Class Definitions:** The `static const JSClassDef` structures define the JavaScript classes (e.g., "IOStream", "InputStream"). The `JSCFunctionListEntry` arrays map C functions to JavaScript methods.
* **`_gum_quick_stream_init`:** This function is a strong candidate for the initialization routine that sets up the JavaScript bindings.

**3. Deeper Dive and Functional Analysis:**

Now, we go through each section and function, understanding its purpose.

* **Platform Abstraction:** The `#ifdef HAVE_WINDOWS` block is key. It shows the code handles Windows and Unix-like systems differently, using `GWin32InputStream/OutputStream` on Windows and `GUnixInputStream/OutputStream` elsewhere.
* **Stream Types:** The code defines and manages different types of streams:
    * `IOStream`: A base class likely representing a stream that can be both read from and written to.
    * `InputStream`:  For reading data.
    * `OutputStream`: For writing data.
    * Native Streams (`Win32InputStream`, `UnixInputStream`, etc.):  Wrappers around operating system file handles or descriptors.
* **Asynchronous Operations:** The `GumQuick*Operation` structs and the `*_async` GIO functions (like `g_io_stream_close_async`, `g_input_stream_read_async`) clearly show asynchronous behavior. Callbacks are used to handle the completion of operations.
* **JavaScript Binding Logic:** The `GUMJS_DEFINE_*` macros implement the JavaScript-to-C++ bridge. For example, `gumjs_io_stream_close` is the C function called when the JavaScript `IOStream` object's `_close` method is invoked.
* **Object Management:** The `_gum_quick_object_manager_*` functions suggest a mechanism for managing the lifecycle of GIOStream objects and their corresponding JavaScript wrappers. This prevents memory leaks.
* **Read/Write Strategies:** The `GumQuickReadStrategy` and `GumQuickWriteStrategy` enums indicate that `read` and `write` operations can have different behaviors (e.g., reading a specific number of bytes or reading until the end of the stream).

**4. Connecting to Reverse Engineering:**

* **Interception of I/O:** The core function is to provide a way to interact with I/O streams. In reverse engineering, this is invaluable for observing how an application interacts with files, network sockets, or other data sources. By intercepting `read` and `write` calls, we can understand the data being exchanged.
* **Dynamic Analysis:** Frida's dynamic nature is crucial. This code enables the *live* inspection of an application's I/O operations, without needing to modify the application's binary beforehand.
* **Observing System Calls:**  While not directly visible in this C code, the underlying GIO library interacts with operating system APIs (like `read`, `write`, `close` on Linux/Android, or their Windows equivalents). By using this Frida module, a reverse engineer can indirectly observe the impact of these system calls.

**5. Identifying Low-Level and Kernel/Framework Connections:**

* **File Descriptors/Handles:** The `GumStreamHandle` type and the conditional logic for Windows and Unix clearly connect to the low-level concept of file descriptors (on Linux/Android) and file handles (on Windows). These are fundamental to operating system I/O.
* **GIO Library:** The reliance on the GLib I/O library is a significant point. GIO itself abstracts away many platform-specific details, but it ultimately interacts with the operating system kernel for I/O operations. On Android, this would involve interactions with the Linux kernel.
* **Asynchronous I/O:** Asynchronous operations are a common pattern in operating system programming to avoid blocking the main thread. This code reflects that by using `*_async` functions and callbacks.
* **Memory Regions:** The `gumjs_output_stream_write_memory_region` function directly deals with writing data from a specific memory address and length. This is very relevant in reverse engineering when analyzing in-memory data structures.

**6. Logic and Assumptions (Hypothetical Input/Output):**

Here, we analyze the functions and imagine their execution flow. For example, the `gumjs_input_stream_read_with_strategy` function takes a size and a callback. The assumption is that the underlying `g_input_stream_read_async` function will attempt to read up to that size. The output will be either the data read (as an ArrayBuffer) or an error object.

**7. Common User Errors:**

* **Incorrect Arguments:** Passing the wrong type or number of arguments to the JavaScript functions (e.g., providing a string instead of a number for the read size) is a common error.
* **Closing Streams Prematurely:** Closing a stream while an asynchronous operation is in progress could lead to errors or unexpected behavior.
* **Memory Management (Less Direct):** While GIO handles much of the underlying memory management, users might make mistakes if they try to interact with the buffer directly in JavaScript without understanding its lifecycle.

**8. Tracing User Actions:**

To understand how a user gets here, we consider the typical Frida workflow:

1. **Frida Script:** The user writes a JavaScript script using Frida's API.
2. **Accessing Stream Functionality:**  The script would likely access a module or object that provides access to stream manipulation functions (this C code likely implements the backend for such a module). For example, the script might call a function like `Frida.openInputStream(fileDescriptor)` or a similar API to create a stream object.
3. **Invoking Stream Methods:** The script then calls methods on the stream object, such as `read()`, `write()`, or `close()`.
4. **Reaching the C Code:** When these JavaScript methods are called, the Frida bridge invokes the corresponding C functions in `gumquickstream.c` (as defined by the `JS_CFUNC_DEF` entries).

**Self-Correction/Refinement during the thought process:**

* **Initial Focus on Single Functions:**  At first, one might be tempted to analyze each function in isolation. However, realizing the asynchronous nature and the interaction between different stream types requires a more holistic view.
* **Clarifying GIO's Role:** It's important to emphasize that `gumquickstream.c` is a *wrapper* around GIO. Understanding GIO's capabilities is crucial to understanding this file's potential.
* **Connecting JavaScript to C:**  The `GUMJS_DECLARE_*` and `JS_CFUNC_DEF` macros are the glue. It's essential to understand how these create the bridge between the JavaScript and C worlds.

By following this structured thought process, breaking down the code into manageable parts, and considering the context of Frida and reverse engineering, we can effectively analyze the `gumquickstream.c` file and address all aspects of the prompt.
这个C源代码文件 `gumquickstream.c` 是 Frida 工具中 `frida-gum` 库的一部分，专门负责处理快速的、非阻塞的 I/O 流操作。它为 JavaScript 环境提供了操作各种输入/输出流的能力，并且针对性能进行了优化。

以下是它的功能列表：

**核心功能：提供 JavaScript 中操作 I/O 流的能力**

1. **抽象 I/O 流:** 定义了 `IOStream`, `InputStream`, `OutputStream` 这几个 JavaScript 类，作为操作 I/O 流的抽象接口。
2. **原生流支持:**  提供了 `Win32InputStream`, `Win32OutputStream`, `UnixInputStream`, `UnixOutputStream` 等类，用于操作底层的操作系统文件句柄或文件描述符。这使得 JavaScript 可以直接与操作系统级别的 I/O 进行交互。
3. **异步操作:**  所有的 I/O 操作（读、写、关闭）都是异步的，这意味着它们不会阻塞 JavaScript 引擎的主线程。这对于性能敏感的动态 instrumentation 非常重要。
4. **读操作:**
    *   提供 `_read` 方法用于从输入流中读取指定大小的数据。
    *   提供 `_readAll` 方法用于读取输入流中的所有数据。
5. **写操作:**
    *   提供 `_write` 方法用于向输出流写入指定的数据。
    *   提供 `_writeAll` 方法用于写入所有给定的数据。
    *   提供 `_writeMemoryRegion` 方法，可以直接将内存中的一块区域的数据写入输出流。这对于在内存中捕获数据非常有用。
6. **关闭操作:** 提供 `_close` 方法用于关闭 I/O 流。
7. **对象管理:**  使用 `GumQuickObjectManager` 来管理创建的 I/O 流对象，确保资源的正确释放。
8. **跨平台支持:** 通过条件编译 (`#ifdef HAVE_WINDOWS`) 支持 Windows 和 Unix-like 系统。

**与逆向方法的关系及举例说明：**

这个文件提供的功能与逆向工程密切相关，因为它允许在运行时动态地拦截和修改目标进程的 I/O 操作。

*   **拦截文件读写:**
    *   **方法:**  通过 Frida 脚本，可以获取目标进程打开的文件描述符或句柄，然后使用 `NativeInputStream` 或 `NativeOutputStream` 创建对应的 JavaScript 流对象。
    *   **举例:** 假设一个恶意软件会读取一个加密的配置文件。逆向工程师可以使用 Frida 脚本，在恶意软件打开配置文件的文件描述符后，创建一个 `NativeInputStream` 对象，并使用 `readAll()` 方法读取文件的内容，从而获取加密的配置信息。

    ```javascript
    // 假设已经通过某种方式获取了目标进程中打开的配置文件的文件描述符 fd
    const fd = 10; // 示例文件描述符

    const NativeInputStream = Module.findExportByName(null, 'NativeInputStream');
    const stream = new NativeInputStream(fd);
    const data = stream.readAll();
    console.log("读取到的配置文件内容:", data.readUtf8String());
    stream.close();
    ```

*   **监控网络通信:**  虽然这个文件本身不直接处理网络套接字，但网络套接字在底层通常也表示为文件描述符（在 Unix-like 系统上）。因此，可以使用 `NativeInputStream` 和 `NativeOutputStream` 来监控和修改网络通信数据。
    *   **方法:** 找到目标进程用于网络通信的套接字的文件描述符，创建相应的流对象，并使用 `read` 和 `write` 方法来观察和修改发送/接收的数据。
    *   **举例:** 假设要分析一个应用程序发送到服务器的请求数据。可以找到该应用程序用于发送数据的套接字描述符，创建一个 `NativeOutputStream`，并 Hook 其 `write` 方法，记录或修改发送的数据。

*   **修改程序输出:**
    *   **方法:**  如果目标进程向标准输出或某个文件写入数据，可以找到对应的文件描述符，创建 `NativeOutputStream` 对象，并使用 `write` 方法写入自定义的数据，从而影响程序的行为或显示。
    *   **举例:**  一个程序在控制台输出 "Hello, world!"，可以使用 Frida 脚本拦截标准输出的文件描述符，并使用 `write` 方法写入 "Hello, Frida!"，从而修改程序的输出。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

这个文件直接与操作系统底层的 I/O 机制交互，因此涉及很多底层知识。

*   **文件描述符 (File Descriptor):** 在 Unix-like 系统（包括 Linux 和 Android）中，文件描述符是操作系统内核用来标识打开的文件或其他 I/O 资源的整数。`UnixInputStream` 和 `UnixOutputStream` 直接使用文件描述符进行操作。
    *   **举例:**  `g_unix_input_stream_new(handle, auto_close)` 中的 `handle` 参数就是一个文件描述符。当在 Frida 脚本中创建一个 `NativeInputStream` 并传入一个整数时，这个整数会被作为文件描述符传递给底层的 GIO 库，最终由内核处理。
*   **文件句柄 (File Handle):** 在 Windows 系统中，文件句柄是操作系统用来标识打开的文件或其他 I/O 资源的指针。`Win32InputStream` 和 `Win32OutputStream` 使用文件句柄。
    *   **举例:** `g_win32_input_stream_new(handle, auto_close)` 中的 `handle` 参数就是一个 Windows 文件句柄。
*   **GIO 库 (GLib I/O):** 这个文件大量使用了 GLib 库提供的 GIO 框架。GIO 提供了一套抽象的、跨平台的 I/O API，使得在不同操作系统上进行 I/O 操作更加方便。
    *   **举例:**  `g_input_stream_read_async` 和 `g_output_stream_write_bytes_async` 等函数都是 GIO 库提供的异步 I/O 函数。Frida 通过调用这些函数来实现非阻塞的 I/O 操作。
*   **异步 I/O:**  文件中的 `*_async` 函数（例如 `g_io_stream_close_async`）以及回调函数的机制，体现了异步 I/O 的概念。这种方式允许程序在等待 I/O 操作完成时继续执行其他任务，提高了效率。
*   **内存操作:** `gumjs_output_stream_write_memory_region` 函数直接操作内存地址和长度，这需要对进程的内存布局有深刻的理解。
    *   **举例:**  可以使用 Frida 的 `Process.readBuffer(address, size)` 获取目标进程内存中的数据，然后将这个数据的指针和大小传递给 `_writeMemoryRegion`，将其写入到某个输出流中。

**逻辑推理、假设输入与输出：**

*   **假设输入:**  在 JavaScript 中创建一个 `NativeInputStream` 对象，并传入一个有效的文件描述符 `fd = 5`，以及要读取的字节数 `size = 1024`。
*   **对应的 C 代码执行流程:**
    1. `gumjs_native_input_stream_construct` 被调用，使用 `fd` 创建一个 `GUnixInputStream` 对象。
    2. 在 JavaScript 中调用 `stream._read(1024, callback)`。
    3. `gumjs_input_stream_read_with_strategy` 被调用，创建一个 `GumQuickReadOperation` 结构体，包含读取策略、缓冲区等信息。
    4. `gum_quick_read_operation_start` 被调用，最终调用 `g_input_stream_read_async(stream->handle, self->buffer, self->buffer_size, ...)`，其中 `stream->handle` 就是文件描述符 `5`，`self->buffer_size` 是 `1024`。
*   **可能的输出:**
    *   **成功:** 如果文件描述符 `5` 指向的文件可以成功读取 1024 字节，那么 `gum_quick_read_operation_finish` 会被调用，回调函数会接收到包含读取数据的 `ArrayBuffer`。
    *   **失败:** 如果读取失败（例如文件不存在、权限不足），`gum_quick_read_operation_finish` 会接收到一个错误对象。如果读取到的字节数少于 1024，且策略是 `GUM_QUICK_READ_ALL`，也会产生一个 "short read" 的错误。

**涉及用户或编程常见的使用错误及举例说明：**

1. **传入无效的文件描述符/句柄:**
    *   **错误:**  用户在创建 `NativeInputStream` 或 `NativeOutputStream` 时，传入了一个目标进程中没有打开的或者无效的文件描述符/句柄。
    *   **举例:**  `const stream = new NativeInputStream(-1);` 或 `const stream = new NativeInputStream(99999);` (假设 99999 不是一个有效的文件描述符)。这会导致底层 GIO 库操作失败，并可能抛出异常或回调函数接收到错误。
2. **尝试在已关闭的流上进行操作:**
    *   **错误:**  用户调用了 `close()` 方法关闭了一个流之后，仍然尝试对其进行 `read()` 或 `write()` 操作。
    *   **举例:**
        ```javascript
        const stream = new NativeInputStream(10);
        stream.close();
        stream.readAll(); // 错误：尝试在已关闭的流上读取
        ```
        这会导致底层 GIO 库返回错误，Frida 会将错误传递给 JavaScript 回调函数。
3. **读取或写入大小超出限制:**
    *   **错误:**  尝试读取或写入非常大的数据块，可能导致内存不足或其他问题。
    *   **举例:** `stream._read(Number.MAX_SAFE_INTEGER, callback);` 尝试读取非常大的数据量，可能会失败。
4. **忘记关闭流:**
    *   **错误:**  创建了大量的流对象，但忘记调用 `close()` 方法释放底层资源，可能导致资源泄漏。
5. **异步操作中的回调处理不当:**
    *   **错误:**  没有正确处理异步操作完成后的回调函数，可能导致数据丢失或程序逻辑错误。例如，忘记检查回调函数中的错误参数。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本（通常是 JavaScript 代码），该脚本的目标是在目标进程中进行动态 instrumentation。
2. **获取目标进程信息:** 脚本可能需要获取目标进程的 ID 或名称，以便 Frida 可以附加到该进程。
3. **查找或创建 I/O 流:**
    *   **查找现有流:** 用户可能需要找到目标进程已经打开的某个文件的文件描述符或句柄。这可以通过 Hook 诸如 `open`, `fopen`, `CreateFile` 等系统调用来实现。
    *   **创建新的流:** 虽然 `gumquickstream.c` 自身不提供创建文件或套接字的功能，但用户可以通过 Frida 的其他 API 调用目标进程的函数来创建，并获取其文件描述符/句柄。
4. **创建 `NativeInputStream` 或 `NativeOutputStream` 对象:**  一旦获取了文件描述符或句柄，用户就会在 JavaScript 脚本中使用 `NativeInputStream` 或 `NativeOutputStream` 的构造函数来创建对应的流对象，并将文件描述符/句柄作为参数传入。
    *   **例如:** `const inputStream = new NativeInputStream(fileDescriptor);`
5. **调用流对象的方法:**  用户会调用流对象的 `_read`, `_write`, `_readAll`, `_writeAll`, `_writeMemoryRegion` 或 `_close` 等方法，执行相应的 I/O 操作。
    *   **例如:** `inputStream.readAll().then(data => console.log(data));`
6. **Frida 桥接:** 当 JavaScript 代码调用这些方法时，Frida 的内部机制会将这些调用桥接到 `gumquickstream.c` 中对应的 C 函数。
7. **执行 C 代码:** `gumquickstream.c` 中的 C 函数会调用底层的 GIO 库函数（如 `g_unix_input_stream_new`, `g_input_stream_read_async` 等）来执行实际的 I/O 操作。
8. **回调处理:**  对于异步操作，当 GIO 库完成 I/O 操作后，会调用预先设置的回调函数。`gumquickstream.c` 中的回调函数（例如 `gum_quick_read_operation_finish`）会处理结果，并将结果传递回 JavaScript 的回调函数。

**调试线索:**

*   如果在 Frida 脚本中创建 `NativeInputStream` 或 `NativeOutputStream` 时出现错误，可能是传入的文件描述符/句柄无效。可以使用 Frida Hook 相关系统调用来验证文件描述符/句柄的有效性。
*   如果在调用 `read` 或 `write` 方法时出现问题，可以使用 Frida 的日志功能 (`console.log`) 打印相关参数（例如读取的字节数、写入的数据等），以便分析问题原因。
*   可以使用 GDB 等调试工具附加到 Frida 进程，并在 `gumquickstream.c` 中设置断点，跟踪 C 代码的执行流程，查看变量的值，从而深入了解问题的根源。
*   检查 GIO 库的错误信息，这通常可以通过查看 Frida 传递给 JavaScript 的错误对象来完成。

总而言之，`gumquickstream.c` 是 Frida 中一个关键的组件，它将底层的操作系统 I/O 能力暴露给 JavaScript 环境，为动态 instrumentation 提供了强大的工具。理解其功能和实现机制对于进行高效的逆向工程和安全分析至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickstream.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickstream.h"

#include "gumquickmacros.h"

#ifdef HAVE_WINDOWS
# include <gio/gwin32inputstream.h>
# include <gio/gwin32outputstream.h>

# define GUM_NATIVE_INPUT_STREAM "Win32InputStream"
# define GUM_NATIVE_OUTPUT_STREAM "Win32OutputStream"
# define GUM_NATIVE_KIND "Windows file handle"
typedef gpointer GumStreamHandle;
#else
# include <gio/gunixinputstream.h>
# include <gio/gunixoutputstream.h>

# define GUM_NATIVE_INPUT_STREAM "UnixInputStream"
# define GUM_NATIVE_OUTPUT_STREAM "UnixOutputStream"
# define GUM_NATIVE_KIND "file descriptor"
typedef gint GumStreamHandle;
#endif

typedef struct _GumQuickCloseIOStreamOperation GumQuickCloseIOStreamOperation;

typedef struct _GumQuickCloseInputOperation GumQuickCloseInputOperation;
typedef struct _GumQuickReadOperation GumQuickReadOperation;
typedef guint GumQuickReadStrategy;

typedef struct _GumQuickCloseOutputOperation GumQuickCloseOutputOperation;
typedef struct _GumQuickWriteOperation GumQuickWriteOperation;
typedef guint GumQuickWriteStrategy;

struct _GumQuickCloseIOStreamOperation
{
  GumQuickObjectOperation operation;
};

struct _GumQuickCloseInputOperation
{
  GumQuickObjectOperation operation;
};

struct _GumQuickReadOperation
{
  GumQuickObjectOperation operation;
  GumQuickReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
};

enum _GumQuickReadStrategy
{
  GUM_QUICK_READ_SOME,
  GUM_QUICK_READ_ALL
};

struct _GumQuickCloseOutputOperation
{
  GumQuickObjectOperation operation;
};

struct _GumQuickWriteOperation
{
  GumQuickObjectOperation operation;
  GumQuickWriteStrategy strategy;
  GBytes * bytes;
};

enum _GumQuickWriteStrategy
{
  GUM_QUICK_WRITE_SOME,
  GUM_QUICK_WRITE_ALL
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_io_stream_construct)
GUMJS_DECLARE_GETTER (gumjs_io_stream_get_input)
GUMJS_DECLARE_GETTER (gumjs_io_stream_get_output)
GUMJS_DECLARE_FUNCTION (gumjs_io_stream_close)
static void gum_quick_close_io_stream_operation_start (
    GumQuickCloseIOStreamOperation * self);
static void gum_quick_close_io_stream_operation_finish (GIOStream * stream,
    GAsyncResult * result, GumQuickCloseIOStreamOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_input_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_close)
static void gum_quick_close_input_operation_start (
    GumQuickCloseInputOperation * self);
static void gum_quick_close_input_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumQuickCloseInputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read_all)
static JSValue gumjs_input_stream_read_with_strategy (JSContext * ctx,
    JSValueConst this_val, GumQuickArgs * args, GumQuickReadStrategy strategy,
    GumQuickCore * core);
static void gum_quick_read_operation_dispose (GumQuickReadOperation * self);
static void gum_quick_read_operation_start (GumQuickReadOperation * self);
static void gum_quick_read_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumQuickReadOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_output_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_close)
static void gum_quick_close_output_operation_start (
    GumQuickCloseOutputOperation * self);
static void gum_quick_close_output_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumQuickCloseOutputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_all)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_memory_region)
static JSValue gumjs_output_stream_write_with_strategy (JSContext * ctx,
    JSValueConst this_val, GumQuickArgs * args, GumQuickWriteStrategy strategy,
    GumQuickCore * core);
static void gum_quick_write_operation_dispose (GumQuickWriteOperation * self);
static void gum_quick_write_operation_start (GumQuickWriteOperation * self);
static void gum_quick_write_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumQuickWriteOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_input_stream_construct)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_output_stream_construct)

static gboolean gum_quick_native_stream_ctor_args_parse (GumQuickArgs * args,
    GumStreamHandle * handle, gboolean * auto_close);

static const JSClassDef gumjs_io_stream_def =
{
  .class_name = "IOStream",
};

static const JSCFunctionListEntry gumjs_io_stream_entries[] =
{
  JS_CGETSET_DEF ("input", gumjs_io_stream_get_input, NULL),
  JS_CGETSET_DEF ("output", gumjs_io_stream_get_output, NULL),
  JS_CFUNC_DEF ("_close", 0, gumjs_io_stream_close),
};

static const JSClassDef gumjs_input_stream_def =
{
  .class_name = "InputStream",
};

static const JSCFunctionListEntry gumjs_input_stream_entries[] =
{
  JS_CFUNC_DEF ("_close", 0, gumjs_input_stream_close),
  JS_CFUNC_DEF ("_read", 0, gumjs_input_stream_read),
  JS_CFUNC_DEF ("_readAll", 0, gumjs_input_stream_read_all),
};

static const JSClassDef gumjs_output_stream_def =
{
  .class_name = "OutputStream",
};

static const JSCFunctionListEntry gumjs_output_stream_entries[] =
{
  JS_CFUNC_DEF ("_close", 0, gumjs_output_stream_close),
  JS_CFUNC_DEF ("_write", 0, gumjs_output_stream_write),
  JS_CFUNC_DEF ("_writeAll", 0, gumjs_output_stream_write_all),
  JS_CFUNC_DEF ("_writeMemoryRegion", 0,
      gumjs_output_stream_write_memory_region),
};

static const JSClassDef gumjs_native_input_stream_def =
{
  .class_name = GUM_NATIVE_INPUT_STREAM,
};

static const JSClassDef gumjs_native_output_stream_def =
{
  .class_name = GUM_NATIVE_OUTPUT_STREAM,
};

void
_gum_quick_stream_init (GumQuickStream * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor, input_stream_proto, output_stream_proto;

  self->core = core;

  _gum_quick_core_store_module_data (core, "stream", self);

  _gum_quick_create_class (ctx, &gumjs_io_stream_def, core,
      &self->io_stream_class, &proto);
  self->io_stream_proto = JS_DupValue (ctx, proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_io_stream_construct,
      gumjs_io_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_io_stream_entries,
      G_N_ELEMENTS (gumjs_io_stream_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_io_stream_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_input_stream_def, core,
      &self->input_stream_class, &proto);
  input_stream_proto = proto;
  ctor = JS_NewCFunction2 (ctx, gumjs_input_stream_construct,
      gumjs_input_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_input_stream_entries,
      G_N_ELEMENTS (gumjs_input_stream_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_input_stream_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_output_stream_def, core,
      &self->output_stream_class, &proto);
  output_stream_proto = proto;
  ctor = JS_NewCFunction2 (ctx, gumjs_output_stream_construct,
      gumjs_output_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_output_stream_entries,
      G_N_ELEMENTS (gumjs_output_stream_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_output_stream_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_subclass (ctx, &gumjs_native_input_stream_def,
      self->input_stream_class, input_stream_proto, core,
      &self->native_input_stream_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_native_input_stream_construct,
      gumjs_native_input_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_native_input_stream_def.class_name,
      ctor, JS_PROP_C_W_E);

  _gum_quick_create_subclass (ctx, &gumjs_native_output_stream_def,
      self->output_stream_class, output_stream_proto, core,
      &self->native_output_stream_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_native_output_stream_construct,
      gumjs_native_output_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_native_output_stream_def.class_name,
      ctor, JS_PROP_C_W_E);

  _gum_quick_object_manager_init (&self->objects, self, core);
}

void
_gum_quick_stream_flush (GumQuickStream * self)
{
  _gum_quick_object_manager_flush (&self->objects);
}

void
_gum_quick_stream_dispose (GumQuickStream * self)
{
  JSContext * ctx = self->core->ctx;

  _gum_quick_object_manager_free (&self->objects);

  JS_FreeValue (ctx, self->io_stream_proto);
}

void
_gum_quick_stream_finalize (GumQuickStream * self)
{
}

static GumQuickStream *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "stream");
}

static gboolean
gum_quick_io_stream_get (JSContext * ctx,
                         JSValueConst val,
                         GumQuickCore * core,
                         GumQuickObject ** object)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->io_stream_class, core,
      (gpointer *) object);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_io_stream_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_GETTER (gumjs_io_stream_get_input)
{
  JSValue wrapper;
  GumQuickStream * parent;
  GumQuickObject * self;
  GInputStream * handle;
  GumQuickObject * input;

  wrapper = JS_GetProperty (ctx, this_val,
      GUM_QUICK_CORE_ATOM (core, cachedInput));
  if (!JS_IsUndefined (wrapper))
    return wrapper;

  parent = gumjs_get_parent_module (core);

  if (!gum_quick_io_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  handle = g_io_stream_get_input_stream (self->handle);

  input = _gum_quick_object_manager_lookup (&parent->objects, handle);
  if (input != NULL)
    return JS_DupValue (ctx, input->wrapper);

  wrapper = JS_NewObjectClass (ctx, parent->input_stream_class);

  _gum_quick_object_manager_add (&parent->objects, ctx, wrapper,
      g_object_ref (handle));

  JS_DefinePropertyValue (ctx, this_val,
      GUM_QUICK_CORE_ATOM (core, cachedInput),
      JS_DupValue (ctx, wrapper),
      0);

  return wrapper;
}

GUMJS_DEFINE_GETTER (gumjs_io_stream_get_output)
{
  GumQuickStream * parent;
  GumQuickObject * self;
  GOutputStream * handle;
  GumQuickObject * output;
  JSValue wrapper;

  wrapper = JS_GetProperty (ctx, this_val,
      GUM_QUICK_CORE_ATOM (core, cachedOutput));
  if (!JS_IsUndefined (wrapper))
    return wrapper;

  parent = gumjs_get_parent_module (core);

  if (!gum_quick_io_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  handle = g_io_stream_get_output_stream (self->handle);

  output = _gum_quick_object_manager_lookup (&parent->objects, handle);
  if (output != NULL)
    return JS_DupValue (ctx, output->wrapper);

  wrapper = JS_NewObjectClass (ctx, parent->output_stream_class);

  _gum_quick_object_manager_add (&parent->objects, ctx, wrapper,
      g_object_ref (handle));

  JS_DefinePropertyValue (ctx, this_val,
      GUM_QUICK_CORE_ATOM (core, cachedOutput),
      JS_DupValue (ctx, wrapper),
      0);

  return wrapper;
}

GUMJS_DEFINE_FUNCTION (gumjs_io_stream_close)
{
  GumQuickStream * parent;
  GumQuickObject * self;
  JSValue callback;
  GumQuickCloseIOStreamOperation * op;
  GPtrArray * dependencies;
  GumQuickObject * input, * output;

  parent = gumjs_get_parent_module (core);

  if (!gum_quick_io_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F", &callback))
    return JS_EXCEPTION;

  op = _gum_quick_object_operation_new (GumQuickCloseIOStreamOperation, self,
      callback, gum_quick_close_io_stream_operation_start, NULL);

  dependencies = g_ptr_array_sized_new (2);

  input = _gum_quick_object_manager_lookup (&parent->objects,
      g_io_stream_get_input_stream (self->handle));
  if (input != NULL)
  {
    g_cancellable_cancel (input->cancellable);
    g_ptr_array_add (dependencies, input);
  }

  output = _gum_quick_object_manager_lookup (&parent->objects,
      g_io_stream_get_output_stream (self->handle));
  if (output != NULL)
  {
    g_cancellable_cancel (output->cancellable);
    g_ptr_array_add (dependencies, output);
  }

  g_cancellable_cancel (self->cancellable);

  _gum_quick_object_operation_schedule_when_idle (op, dependencies);

  g_ptr_array_unref (dependencies);

  return JS_UNDEFINED;
}

static void
gum_quick_close_io_stream_operation_start (
    GumQuickCloseIOStreamOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);

  g_io_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_quick_close_io_stream_operation_finish, self);
}

static void
gum_quick_close_io_stream_operation_finish (
    GIOStream * stream,
    GAsyncResult * result,
    GumQuickCloseIOStreamOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSValue argv[2];

  success = g_io_stream_close_finish (stream, result, &error);

  _gum_quick_scope_enter (&scope, core);

  argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
  argv[1] = JS_NewBool (ctx, success);

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

static gboolean
gum_quick_input_stream_get (JSContext * ctx,
                            JSValueConst val,
                            GumQuickCore * core,
                            GumQuickObject ** object)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->input_stream_class, core,
      (gpointer *) object);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_input_stream_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_close)
{
  GumQuickObject * self;
  JSValue callback;
  GumQuickCloseInputOperation * op;

  if (!gum_quick_input_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F", &callback))
    return JS_EXCEPTION;

  g_cancellable_cancel (self->cancellable);

  op = _gum_quick_object_operation_new (GumQuickCloseInputOperation, self,
      callback, gum_quick_close_input_operation_start, NULL);
  _gum_quick_object_operation_schedule_when_idle (op, NULL);

  return JS_UNDEFINED;
}

static void
gum_quick_close_input_operation_start (GumQuickCloseInputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);

  g_input_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT,
      NULL, (GAsyncReadyCallback) gum_quick_close_input_operation_finish, self);
}

static void
gum_quick_close_input_operation_finish (GInputStream * stream,
                                        GAsyncResult * result,
                                        GumQuickCloseInputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSValue argv[2];

  success = g_input_stream_close_finish (stream, result, &error);

  _gum_quick_scope_enter (&scope, core);

  argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
  argv[1] = JS_NewBool (ctx, success);

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_read)
{
  return gumjs_input_stream_read_with_strategy (ctx, this_val, args,
      GUM_QUICK_READ_SOME, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_read_all)
{
  return gumjs_input_stream_read_with_strategy (ctx, this_val, args,
      GUM_QUICK_READ_ALL, core);
}

static JSValue
gumjs_input_stream_read_with_strategy (JSContext * ctx,
                                       JSValueConst this_val,
                                       GumQuickArgs * args,
                                       GumQuickReadStrategy strategy,
                                       GumQuickCore * core)
{
  GumQuickObject * self;
  guint64 size;
  JSValue callback;
  GumQuickReadOperation * op;

  if (!gum_quick_input_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "QF", &size, &callback))
    return JS_EXCEPTION;

  op = _gum_quick_object_operation_new (GumQuickReadOperation, self, callback,
      gum_quick_read_operation_start, gum_quick_read_operation_dispose);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  _gum_quick_object_operation_schedule (op);

  return JS_UNDEFINED;
}

static void
gum_quick_read_operation_dispose (GumQuickReadOperation * self)
{
  g_free (self->buffer);
}

static void
gum_quick_read_operation_start (GumQuickReadOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickObject * stream = op->object;

  if (self->strategy == GUM_QUICK_READ_SOME)
  {
    g_input_stream_read_async (stream->handle, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_read_operation_finish, self);
  }
  else
  {
    g_assert (self->strategy == GUM_QUICK_READ_ALL);

    g_input_stream_read_all_async (stream->handle, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_read_operation_finish, self);
  }
}

static void
gum_quick_read_operation_finish (GInputStream * stream,
                                 GAsyncResult * result,
                                 GumQuickReadOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  gsize bytes_read = 0;
  GError * error = NULL;
  GumQuickScope scope;
  JSValue argv[2];
  gboolean emit_data;

  if (self->strategy == GUM_QUICK_READ_SOME)
  {
    gsize n;

    n = g_input_stream_read_finish (stream, result, &error);
    if (n > 0)
      bytes_read = n;
  }
  else
  {
    g_assert (self->strategy == GUM_QUICK_READ_ALL);

    g_input_stream_read_all_finish (stream, result, &bytes_read, &error);
  }

  _gum_quick_scope_enter (&scope, op->core);

  if (self->strategy == GUM_QUICK_READ_ALL && bytes_read != self->buffer_size)
  {
    argv[0] = (error != NULL)
        ? _gum_quick_error_new_take_error (ctx, &error, core)
        : _gum_quick_error_new (ctx, "short read", core);
    emit_data = TRUE;
  }
  else if (error == NULL)
  {
    argv[0] = JS_NULL;
    emit_data = TRUE;
  }
  else
  {
    argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
    emit_data = FALSE;
  }

  if (emit_data)
    argv[1] = JS_NewArrayBufferCopy (ctx, self->buffer, bytes_read);
  else
    argv[1] = JS_NULL;

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);
  JS_FreeValue (ctx, argv[1]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

static gboolean
gum_quick_output_stream_get (JSContext * ctx,
                             JSValueConst val,
                             GumQuickCore * core,
                             GumQuickObject ** object)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->output_stream_class, core,
      (gpointer *) object);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_output_stream_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_close)
{
  GumQuickObject * self;
  JSValue callback;
  GumQuickCloseOutputOperation * op;

  if (!gum_quick_output_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F", &callback))
    return JS_EXCEPTION;

  g_cancellable_cancel (self->cancellable);

  op = _gum_quick_object_operation_new (GumQuickCloseOutputOperation, self,
      callback, gum_quick_close_output_operation_start, NULL);
  _gum_quick_object_operation_schedule_when_idle (op, NULL);

  return JS_UNDEFINED;
}

static void
gum_quick_close_output_operation_start (GumQuickCloseOutputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);

  g_output_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_quick_close_output_operation_finish, self);
}

static void
gum_quick_close_output_operation_finish (GOutputStream * stream,
                                         GAsyncResult * result,
                                         GumQuickCloseOutputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSValue argv[2];

  success = g_output_stream_close_finish (stream, result, &error);

  _gum_quick_scope_enter (&scope, op->core);

  argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
  argv[1] = JS_NewBool (ctx, success);

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write)
{
  return gumjs_output_stream_write_with_strategy (ctx, this_val, args,
      GUM_QUICK_WRITE_SOME, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write_all)
{
  return gumjs_output_stream_write_with_strategy (ctx, this_val, args,
      GUM_QUICK_WRITE_ALL, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write_memory_region)
{
  GumQuickObject * self;
  gconstpointer address;
  gsize length;
  JSValue callback;
  GumQuickWriteOperation * op;

  if (!gum_quick_output_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "pZF", &address, &length, &callback))
    return JS_EXCEPTION;

  op = _gum_quick_object_operation_new (GumQuickWriteOperation, self, callback,
      gum_quick_write_operation_start, gum_quick_write_operation_dispose);
  op->strategy = GUM_QUICK_WRITE_ALL;
  op->bytes = g_bytes_new_static (address, length);
  _gum_quick_object_operation_schedule (op);

  return JS_UNDEFINED;
}

static JSValue
gumjs_output_stream_write_with_strategy (JSContext * ctx,
                                         JSValueConst this_val,
                                         GumQuickArgs * args,
                                         GumQuickWriteStrategy strategy,
                                         GumQuickCore * core)
{
  GumQuickObject * self;
  GBytes * bytes;
  JSValue callback;
  GumQuickWriteOperation * op;

  if (!gum_quick_output_stream_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "BF", &bytes, &callback))
    return JS_EXCEPTION;

  op = _gum_quick_object_operation_new (GumQuickWriteOperation, self, callback,
      gum_quick_write_operation_start, gum_quick_write_operation_dispose);
  op->strategy = strategy;
  op->bytes = g_bytes_ref (bytes);
  _gum_quick_object_operation_schedule (op);

  return JS_UNDEFINED;
}

static void
gum_quick_write_operation_dispose (GumQuickWriteOperation * self)
{
  g_bytes_unref (self->bytes);
}

static void
gum_quick_write_operation_start (GumQuickWriteOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickObject * stream = op->object;

  if (self->strategy == GUM_QUICK_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (stream->handle, self->bytes,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_write_operation_finish, self);
  }
  else
  {
    gsize size;
    gconstpointer data;

    g_assert (self->strategy == GUM_QUICK_WRITE_ALL);

    data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (stream->handle, data, size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_write_operation_finish, self);
  }
}

static void
gum_quick_write_operation_finish (GOutputStream * stream,
                                  GAsyncResult * result,
                                  GumQuickWriteOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  gsize bytes_written = 0;
  GError * error = NULL;
  GumQuickScope scope;
  JSValue argv[2];

  if (self->strategy == GUM_QUICK_WRITE_SOME)
  {
    gssize n;

    n = g_output_stream_write_bytes_finish (stream, result, &error);
    if (n > 0)
      bytes_written = n;
  }
  else
  {
    g_assert (self->strategy == GUM_QUICK_WRITE_ALL);

    g_output_stream_write_all_finish (stream, result, &bytes_written, &error);
  }

  _gum_quick_scope_enter (&scope, op->core);

  if (self->strategy == GUM_QUICK_WRITE_ALL &&
      bytes_written != g_bytes_get_size (self->bytes))
  {
    argv[0] = (error != NULL)
        ? _gum_quick_error_new_take_error (ctx, &error, core)
        : _gum_quick_error_new (ctx, "short write", core);
  }
  else if (error == NULL)
  {
    argv[0] = JS_NULL;
  }
  else
  {
    argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
  }

  argv[1] = JS_NewInt64 (ctx, bytes_written);

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_input_stream_construct)
{
  GumQuickStream * parent;
  JSValue wrapper;
  GumStreamHandle handle;
  gboolean auto_close;
  JSValue proto;
  GInputStream * stream;

  parent = gumjs_get_parent_module (core);

  if (!gum_quick_native_stream_ctor_args_parse (args, &handle, &auto_close))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto,
      parent->native_input_stream_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

#ifdef HAVE_WINDOWS
  stream = g_win32_input_stream_new (handle, auto_close);
#else
  stream = g_unix_input_stream_new (handle, auto_close);
#endif

  _gum_quick_object_manager_add (&parent->objects, ctx, wrapper, stream);

  return wrapper;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_output_stream_construct)
{
  GumQuickStream * parent;
  JSValue wrapper;
  GumStreamHandle handle;
  gboolean auto_close;
  JSValue proto;
  GOutputStream * stream;

  parent = gumjs_get_parent_module (core);

  if (!gum_quick_native_stream_ctor_args_parse (args, &handle, &auto_close))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto,
      parent->native_output_stream_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

#ifdef HAVE_WINDOWS
  stream = g_win32_output_stream_new (handle, auto_close);
#else
  stream = g_unix_output_stream_new (handle, auto_close);
#endif

  _gum_quick_object_manager_add (&parent->objects, ctx, wrapper, stream);

  return wrapper;
}

static gboolean
gum_quick_native_stream_ctor_args_parse (GumQuickArgs * args,
                                         GumStreamHandle * handle,
                                         gboolean * auto_close)
{
  JSValue options = JS_NULL;

#ifdef HAVE_WINDOWS
  if (!_gum_quick_args_parse (args, "p|O", handle, &options))
#else
  if (!_gum_quick_args_parse (args, "i|O", handle, &options))
#endif
    return FALSE;

  *auto_close = FALSE;
  if (!JS_IsNull (options))
  {
    JSContext * ctx = args->ctx;
    GumQuickCore * core = args->core;
    JSValue val;
    gboolean valid;

    val = JS_GetProperty (ctx, options, GUM_QUICK_CORE_ATOM (core, autoClose));
    if (JS_IsException (val))
      return FALSE;
    valid = _gum_quick_boolean_get (ctx, val, auto_close);
    JS_FreeValue (ctx, val);

    if (!valid)
      return FALSE;
  }

  return TRUE;
}
```