Response:
Let's break down the thought process for analyzing this C++ code for Frida.

**1. Understanding the Goal:**

The core request is to understand the functionality of `gumv8file.cpp` within the context of Frida, specifically focusing on its relationship to reverse engineering, low-level operations, logical reasoning, potential user errors, and how a user might trigger this code.

**2. Initial Code Scan and High-Level Overview:**

The first step is to quickly scan the code and identify key components:

* **Includes:** `gumv8file.h`, `gumv8macros.h`, `gumv8scope.h`, `<errno.h>`, `<string.h>`. These suggest integration with V8 (JavaScript engine), macros for Frida, scope management, and standard C library functionalities for error handling and string manipulation.
* **`GUMJS_MODULE_NAME File`:** This clearly indicates this code defines a module named "File" exposed to the Frida/JavaScript environment.
* **`GumFile` struct:** This seems to be the internal representation of a file object within Frida's V8 context. It holds a V8 object wrapper, a standard `FILE*` handle, and a pointer to the `GumV8File` module.
* **Function Declarations:** A large number of functions are declared with the `GUMJS_DECLARE_FUNCTION` and `GUMJS_DECLARE_CONSTRUCTOR` macros. These hint at the available file operations (read, write, seek, tell, close, etc.) accessible from JavaScript.
* **`gumjs_file_module_functions` and `gumjs_file_functions` arrays:** These likely map the JavaScript function names (e.g., "readAllBytes") to their corresponding C++ implementation functions (e.g., `gumjs_file_read_all_bytes`).
* **`_gum_v8_file_init`, `_gum_v8_file_realize`, `_gum_v8_file_dispose`, `_gum_v8_file_finalize`:**  These look like lifecycle management functions for the `GumV8File` module.
* **Function Definitions (with `GUMJS_DEFINE_FUNCTION` and `GUMJS_DEFINE_CLASS_METHOD`):**  These are the actual implementations of the file operations. Notice the common pattern of argument parsing (`_gum_v8_args_parse`), error handling, and interacting with the underlying `FILE*` handle.

**3. Deeper Dive into Functionality and Relationships:**

Now, let's go through the functions and analyze their purpose and connections to the request:

* **`readAllBytes`, `readAllText`, `writeAllBytes`, `writeAllText`:** These are static methods on the `File` module, providing convenient ways to read or write entire files at once. They use standard C library functions like `g_file_get_contents` and custom helper `gum_file_set_contents`.
* **Constructor (`gumjs_file_construct`):** This is crucial. It explains how a `File` object is created in JavaScript. It takes a filename and mode ("r", "w", etc.), opens the file using `fopen`, and associates the `FILE*` with the JavaScript object. This is a direct bridge between the JavaScript world and the underlying OS file system.
* **Instance Methods (`tell`, `seek`, `readBytes`, `readText`, `readLine`, `write`, `flush`, `close`):**  These implement the standard file operations, manipulating the `FILE*` handle directly using functions like `ftell`, `fseek`, `fread`, `fwrite`, `fflush`, and `fclose`. The `readText` and `readLine` functions also include UTF-8 validation, which is important for handling text files correctly.
* **Helper Functions (`gum_file_new`, `gum_file_free`, `gum_file_check_open`, `gum_file_close`, `gum_file_query_num_bytes_available`, `gum_file_set_contents`, `gum_file_on_weak_notify`):** These are internal utility functions to manage the `GumFile` structure, handle memory, check file status, and implement platform-specific file writing (using `g_file_set_contents_full` on newer GLib versions).

**4. Connecting to the Request's Specific Points:**

* **Reverse Engineering:** The ability to read and write arbitrary files on the target process's file system is a powerful reverse engineering tool. This allows inspection of configuration files, libraries, and other data, as well as modification for testing and analysis.
* **Binary/Low-Level:** The code directly interacts with the underlying operating system's file system through C standard library functions. The `readBytes` and `writeAllBytes` functions deal with raw binary data. The `seek` function allows precise positioning within a file.
* **Linux/Android Kernel/Framework:** The use of standard C library functions like `fopen`, `fread`, `fwrite`, etc., directly interacts with the operating system kernel's file system interface. On Android, this interaction goes through the Android framework's file system abstractions. The file permissions (like `0666` in `gum_file_set_contents_full`) are directly related to Linux file system concepts.
* **Logical Reasoning:** The code implements a straightforward mapping of file operations. For instance, `readBytes` attempts to read a specified number of bytes and returns them. The `seek` function changes the file pointer, affecting subsequent read/write operations. The UTF-8 validation in `readText` and `readLine` adds a layer of logical processing.
* **User Errors:**  The code includes error handling using `errno` and `g_strerror`. Common user errors include trying to operate on a closed file, providing incorrect file paths, or using incorrect file modes.
* **User Operations and Debugging:** The code is reached when a Frida script in JavaScript uses the `File` object and its methods. Debugging would involve tracing the execution flow from the JavaScript call into the native C++ code.

**5. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each point of the request with specific examples from the code. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on individual functions without seeing the bigger picture of how they connect. *Correction:* Start with the overall structure and the `File` module concept.
* **Overlooking details:**  Missing the significance of the `GumFile` struct and its role in managing the file handle. *Correction:* Pay closer attention to data structures and how they are used.
* **Not explicitly linking to reverse engineering:**  Understanding the file operations is one thing, but explicitly stating their relevance to reverse engineering is crucial for the request. *Correction:*  Make those connections explicit in the "Reverse Engineering" section.
* **Not considering the user's perspective:** Initially focusing only on the code's functionality. *Correction:* Add sections on user errors and how the user reaches this code.

By following this structured thought process, combining code analysis with an understanding of the context (Frida and reverse engineering), we can generate a comprehensive and accurate answer to the given request.
这个文件 `gumv8file.cpp` 是 Frida 工具中用于在目标进程的 JavaScript 环境中提供文件操作功能的模块。它允许 Frida 脚本与目标进程的文件系统进行交互。

以下是它的功能列表以及与您提出的要求的对应说明：

**1. 提供文件操作的 JavaScript API:**

* **功能:**  该文件定义了一个名为 `File` 的 JavaScript 类，该类提供了对文件进行各种操作的方法。这些方法包括读取文件内容（以字节或文本形式）、写入文件内容（以字节或文本形式）、移动文件指针、刷新缓冲区和关闭文件等。
* **逆向方法关系:**
    * **读取文件内容:** 逆向工程师可以使用此功能读取目标进程的配置文件、日志文件、动态链接库（作为二进制数据分析）等。例如，可以读取一个应用的 preferences 文件来了解其配置信息。
    * **写入文件内容:** 逆向工程师可以使用此功能修改目标进程的配置文件（谨慎操作！），或者在目标进程中创建或修改文件以进行调试或注入。例如，可以写入一个特定的输入到目标进程正在监听的文件中，观察其行为。
* **二进制底层知识:**
    *  文件操作最终会调用操作系统提供的系统调用，例如 `open`, `read`, `write`, `lseek`, `close` 等。虽然这个 C++ 代码本身使用了标准 C 库的 `fopen`, `fread`, `fwrite` 等函数，但这些函数底层也会转化为系统调用与内核交互。
* **Linux, Android 内核及框架的知识:**
    *  在 Linux 和 Android 系统上，文件系统是内核的重要组成部分。这个模块通过 C 标准库函数与内核提供的文件系统接口进行交互。
    *  在 Android 上，文件访问权限、SELinux 等安全机制可能会影响这些操作的成功与否。Frida 需要在目标进程的上下文中运行才能执行这些操作，并受到目标进程权限的限制。
* **逻辑推理:**
    * **假设输入:**  在 JavaScript 中创建一个 `File` 对象，指定文件路径和打开模式 (例如 "r" 读取, "w" 写入, "rb" 二进制读取)。然后调用 `readAllText()` 方法。
    * **输出:**  如果文件存在且可读，则输出文件的文本内容。如果文件不存在或无法读取，则抛出一个 JavaScript 异常，异常信息会包含错误原因。
* **用户或编程常见的使用错误:**
    * **错误示例:**  在文件打开模式为 "r" (只读) 的情况下调用 `write()` 方法，会导致写入失败。
    * **错误示例:**  尝试打开一个不存在的文件且打开模式不包含创建选项 (例如 "r" 而不是 "r+")，会导致打开失败。
    * **错误示例:**  在操作完文件后忘记调用 `close()` 方法，可能导致文件句柄泄露。

**2. `readAllBytes(filename)` 和 `readAllText(filename)`:**

* **功能:**  静态方法，用于一次性读取整个文件的内容，分别返回 `ArrayBuffer` (字节) 或字符串 (文本)。
* **逆向方法关系:**
    * 快速获取整个文件的内容用于分析。例如，读取 DEX 文件或 ELF 文件的内容进行静态分析。
* **二进制底层知识:**
    * `readAllBytes` 直接读取文件的原始字节，与文件的二进制表示一一对应。
* **逻辑推理:**
    * **假设输入:** `File.readAllBytes("/data/local/tmp/my_binary_file")`
    * **输出:**  返回一个包含 `my_binary_file` 完整二进制数据的 `ArrayBuffer` 对象。
* **用户或编程常见的使用错误:**
    * 读取过大的文件可能导致内存消耗过高，甚至崩溃。

**3. `writeAllBytes(filename, bytes)` 和 `writeAllText(filename, text)`:**

* **功能:** 静态方法，用于一次性将字节数组或文本写入到文件中。如果文件不存在则创建，如果存在则覆盖。
* **逆向方法关系:**
    * 可以用于在目标进程中创建或修改文件。例如，修改应用的配置文件，或者注入特定的 payload 到文件中。
* **二进制底层知识:**
    * `writeAllBytes` 将提供的字节数组直接写入文件，不进行任何编码转换。
* **逻辑推理:**
    * **假设输入:** `File.writeAllText("/data/local/tmp/output.txt", "Hello from Frida!")`
    * **输出:**  在 `/data/local/tmp/` 目录下创建一个名为 `output.txt` 的文件，内容为 "Hello from Frida!"。如果文件已存在，其原有内容会被覆盖。
* **用户或编程常见的使用错误:**
    * 写入文件时没有足够的权限会导致写入失败。

**4. 实例方法 `tell()`, `seek(offset, whence)`, `readBytes(n)`, `readText(n)`, `readLine()`, `write(bytes)`, `flush()`, `close()`:**

* **功能:**  这些方法提供了更细粒度的文件操作。
    * `tell()`: 返回当前文件指针的位置。
    * `seek()`: 移动文件指针到指定位置。
    * `readBytes(n)`: 读取指定数量的字节。
    * `readText(n)`: 读取指定数量的文本，并尝试进行 UTF-8 解码。
    * `readLine()`: 读取一行文本。
    * `write(bytes)`: 写入字节数组。
    * `flush()`: 刷新文件缓冲区，确保数据写入到磁盘。
    * `close()`: 关闭文件。
* **逆向方法关系:**
    * 可以用于读取文件的特定部分，例如读取 ELF 文件的头部信息。
    * 可以用于在文件的特定位置写入数据，例如修改 PE 文件的导入表。
* **二进制底层知识:**
    * `seek` 操作直接操作文件描述符的偏移量。
    * `readBytes` 读取的是原始的二进制数据。
* **逻辑推理:**
    * **假设输入:** 创建一个 `File` 对象读取一个 ELF 文件，然后使用 `seek(0x18, File.SEEK_SET)` 将文件指针移动到 ELF header 的特定偏移，再调用 `readBytes(4)` 读取接下来的 4 个字节 (可能是魔数)。
    * **输出:**  返回一个包含从偏移 0x18 开始的 4 个字节的 `ArrayBuffer` 对象。
* **用户或编程常见的使用错误:**
    * `seek` 的 `whence` 参数使用错误 (例如使用了错误的常量值)。
    * 读取或写入操作超出了文件末尾。
    * 在文件关闭后尝试进行操作。

**5. 内部实现细节:**

* **`GumFile` 结构体:**  该结构体用于在 C++ 层面表示一个打开的文件，包含指向 V8 对象的包装器 (`wrapper`)、标准 C 文件指针 (`handle`) 和所属的模块 (`module`)。
* **内存管理:** 使用 `g_slice_new` 和 `g_slice_free` 进行内存分配和释放。
* **弱引用:**  使用 V8 的弱回调 (`gum_file_on_weak_notify`) 来管理 `GumFile` 对象的生命周期，当 JavaScript 端的 `File` 对象被垃圾回收时，C++ 端的资源也会被清理。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本 (JavaScript 代码)。
2. **使用 `File` 类:**  在脚本中，用户会使用 `File` 类的构造函数创建一个 `File` 对象，例如 `const f = new File("/path/to/file", "r");`。
3. **调用 `File` 对象的方法:**  用户会调用 `File` 对象的方法进行文件操作，例如 `f.readAllText()` 或 `f.write("some data");`.
4. **Frida 执行脚本:** Frida 将脚本注入到目标进程中执行。
5. **JavaScript 调用到 C++:** 当 JavaScript 代码调用 `File` 对象的方法时，Frida 的绑定机制会将这些调用路由到 `gumv8file.cpp` 中对应的 C++ 函数 (`gumjs_file_read_all_text`, `gumjs_file_write`, 等等)。
6. **C++ 函数执行:**  这些 C++ 函数会进行参数解析，调用标准 C 库函数 (例如 `fopen`, `fread`, `fwrite`) 与目标进程的文件系统进行交互。
7. **结果返回:**  C++ 函数执行的结果会转换回 JavaScript 对象，并返回给 Frida 脚本。

**总结:**

`gumv8file.cpp` 是 Frida 提供的文件操作功能的底层实现。它将标准 C 的文件操作接口暴露给 JavaScript 环境，使得逆向工程师可以在 Frida 脚本中方便地与目标进程的文件系统进行交互，进行文件读取、写入等操作，这对于分析目标进程的行为、提取信息或进行修改非常有用。理解这个文件的功能有助于理解 Frida 如何在底层实现这些 JavaScript API，以及如何利用这些 API 进行更深入的逆向分析。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8file.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2013-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8file.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <errno.h>
#include <string.h>

#define GUMJS_MODULE_NAME File

using namespace v8;

struct GumFile
{
  Global<Object> * wrapper;
  FILE * handle;
  GumV8File * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_file_read_all_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_all_text)
GUMJS_DECLARE_FUNCTION (gumjs_file_write_all_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_write_all_text)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FUNCTION (gumjs_file_tell)
GUMJS_DECLARE_FUNCTION (gumjs_file_seek)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_text)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_line)
GUMJS_DECLARE_FUNCTION (gumjs_file_write)
GUMJS_DECLARE_FUNCTION (gumjs_file_flush)
GUMJS_DECLARE_FUNCTION (gumjs_file_close)

static GumFile * gum_file_new (Local<Object> wrapper, FILE * handle,
    GumV8File * module);
static void gum_file_free (GumFile * file);
static gboolean gum_file_check_open (GumFile * self, Isolate * isolate);
static void gum_file_close (GumFile * self);
static gsize gum_file_query_num_bytes_available (GumFile * self);
static gboolean gum_file_set_contents (const gchar * filename,
    const gchar * contents, gssize length, GError ** error);
static void gum_file_on_weak_notify (const WeakCallbackInfo<GumFile> & info);

static const GumV8Function gumjs_file_module_functions[] =
{
  { "readAllBytes", gumjs_file_read_all_bytes },
  { "readAllText", gumjs_file_read_all_text },
  { "writeAllBytes", gumjs_file_write_all_bytes },
  { "writeAllText", gumjs_file_write_all_text },

  { NULL, NULL }
};

static const GumV8Function gumjs_file_functions[] =
{
  { "tell", gumjs_file_tell },
  { "seek", gumjs_file_seek },
  { "readBytes", gumjs_file_read_bytes },
  { "readText", gumjs_file_read_text },
  { "readLine", gumjs_file_read_line },
  { "write", gumjs_file_write },
  { "flush", gumjs_file_flush },
  { "close", gumjs_file_close },

  { NULL, NULL }
};

void
_gum_v8_file_init (GumV8File * self,
                   GumV8Core * core,
                   Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto file = _gum_v8_create_class ("File", gumjs_file_construct, scope,
      module, isolate);
  file->Set (_gum_v8_string_new_ascii (isolate, "SEEK_SET"),
      Integer::New (isolate, SEEK_SET), ReadOnly);
  file->Set (_gum_v8_string_new_ascii (isolate, "SEEK_CUR"),
      Integer::New (isolate, SEEK_CUR), ReadOnly);
  file->Set (_gum_v8_string_new_ascii (isolate, "SEEK_END"),
      Integer::New (isolate, SEEK_END), ReadOnly);
  _gum_v8_class_add_static (file, gumjs_file_module_functions, module, isolate);
  _gum_v8_class_add (file, gumjs_file_functions, module, isolate);
}

void
_gum_v8_file_realize (GumV8File * self)
{
  self->files = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_file_free);
}

void
_gum_v8_file_dispose (GumV8File * self)
{
  g_hash_table_unref (self->files);
  self->files = NULL;
}

void
_gum_v8_file_finalize (GumV8File * self)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_all_bytes)
{
  gchar * filename;
  if (!_gum_v8_args_parse (args, "s", &filename))
    return;

  gchar * contents;
  gsize length;
  GError * error = NULL;
  gboolean success = g_file_get_contents (filename, &contents, &length, &error);

  g_free (filename);

  if (!success)
  {
    _gum_v8_throw_literal (isolate, error->message);
    g_error_free (error);
    return;
  }

  auto result = ArrayBuffer::New (isolate, length);
  auto store = result.As<ArrayBuffer> ()->GetBackingStore ();
  memcpy (store->Data (), contents, length);
  info.GetReturnValue ().Set (result);

  g_free (contents);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_all_text)
{
  gchar * filename;
  if (!_gum_v8_args_parse (args, "s", &filename))
    return;

  gchar * contents;
  gsize length;
  GError * error = NULL;
  gboolean success = g_file_get_contents (filename, &contents, &length, &error);

  g_free (filename);

  if (!success)
  {
    _gum_v8_throw_literal (isolate, error->message);
    g_error_free (error);
    return;
  }

  const gchar * end;
  if (g_utf8_validate (contents, length, &end))
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (isolate, contents, NewStringType::kNormal, length)
        .ToLocalChecked ());
  }
  else
  {
    _gum_v8_throw (isolate, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - contents));
  }

  g_free (contents);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write_all_bytes)
{
  gchar * filename;
  GBytes * bytes;
  if (!_gum_v8_args_parse (args, "sB", &filename, &bytes))
    return;

  gsize size;
  gconstpointer data = g_bytes_get_data (bytes, &size);

  GError * error = NULL;
  gboolean success = gum_file_set_contents (filename, (const gchar *) data,
      size, &error);

  g_bytes_unref (bytes);
  g_free (filename);

  if (!success)
  {
    _gum_v8_throw_literal (isolate, error->message);
    g_error_free (error);
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write_all_text)
{
  gchar * filename, * text;
  if (!_gum_v8_args_parse (args, "ss", &filename, &text))
    return;

  GError * error = NULL;
  gboolean success = gum_file_set_contents (filename, text, -1, &error);

  g_free (text);
  g_free (filename);

  if (!success)
  {
    _gum_v8_throw_literal (isolate, error->message);
    g_error_free (error);
  }
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new File()` to create a new instance");
    return;
  }

  gchar * filename, * mode;
  if (!_gum_v8_args_parse (args, "ss", &filename, &mode))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  auto handle = fopen (filename, mode);

  g_free (filename);
  g_free (mode);

  if (handle == NULL)
  {
    _gum_v8_throw_literal (isolate, g_strerror (errno));
    return;
  }

  auto file = gum_file_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, file);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_tell, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  info.GetReturnValue ().Set ((double) ftell (self->handle));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_seek, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  gssize offset;
  gint whence = SEEK_SET;
  if (!_gum_v8_args_parse (args, "z|i", &offset, &whence))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  int result = fseek (self->handle, offset, whence);
  if (result == -1)
  {
    _gum_v8_throw_literal (isolate, g_strerror (errno));
    return;
  }

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_read_bytes, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  gsize n = G_MAXSIZE;
  if (!_gum_v8_args_parse (args, "|Z", &n))
    return;

  if (n == G_MAXSIZE)
    n = gum_file_query_num_bytes_available (self);

  if (n == 0)
  {
    info.GetReturnValue ().Set (ArrayBuffer::New (isolate, 0));
    return;
  }

  auto result = ArrayBuffer::New (isolate, n);
  auto store = result.As<ArrayBuffer> ()->GetBackingStore ();

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  size_t num_bytes_read = fread (store->Data (), 1, n, self->handle);
  if (num_bytes_read < n)
  {
    auto r = ArrayBuffer::New (isolate, num_bytes_read);
    auto s = r.As<ArrayBuffer> ()->GetBackingStore ();
    memcpy (s->Data (), store->Data (), num_bytes_read);
    result = r;
  }

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_read_text, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  gsize n = G_MAXSIZE;
  if (!_gum_v8_args_parse (args, "|Z", &n))
    return;

  if (n == G_MAXSIZE)
    n = gum_file_query_num_bytes_available (self);

  if (n == 0)
  {
    info.GetReturnValue ().Set (ArrayBuffer::New (isolate, 0));
    return;
  }

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  gchar * data = (gchar *) g_malloc (n);
  size_t num_bytes_read = fread (data, 1, n, self->handle);

  const gchar * end;
  if (g_utf8_validate (data, num_bytes_read, &end))
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (isolate, data, NewStringType::kNormal,
          (int) num_bytes_read).ToLocalChecked ());
  }
  else
  {
    _gum_v8_throw (isolate, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - data));

    fseek (self->handle, -((long) num_bytes_read), SEEK_CUR);
  }

  g_free (data);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_read_line, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  gsize offset = 0;
  gsize capacity = 256;
  GString * buffer = g_string_sized_new (capacity);
  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  while (TRUE)
  {
    g_string_set_size (buffer, capacity);

    if (fgets (buffer->str + offset, capacity - offset, self->handle) == NULL)
      break;

    gsize num_bytes_read = strlen (buffer->str + offset);
    offset += num_bytes_read;

    if (buffer->str[offset - 1] == '\n')
      break;

    if (offset == capacity - 1)
      capacity += 256;
    else
      break;
  }
  g_string_set_size (buffer, offset);

  const gchar * end;
  if (g_utf8_validate (buffer->str, buffer->len, &end))
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (isolate, buffer->str, NewStringType::kNormal,
          buffer->len).ToLocalChecked ());
  }
  else
  {
    _gum_v8_throw (isolate, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - buffer->str));

    fseek (self->handle, -((long) buffer->len), SEEK_CUR);
  }

  g_string_free (buffer, TRUE);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_write, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  GBytes * bytes;
  if (!_gum_v8_args_parse (args, "B~", &bytes))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  gsize size;
  auto data = g_bytes_get_data (bytes, &size);
  fwrite (data, size, 1, self->handle);

  g_bytes_unref (bytes);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_flush, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  fflush (self->handle);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_close, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  gum_file_close (self);
}

static GumFile *
gum_file_new (Local<Object> wrapper,
              FILE * handle,
              GumV8File * module)
{
  auto file = g_slice_new (GumFile);
  file->wrapper = new Global<Object> (module->core->isolate, wrapper);
  file->wrapper->SetWeak (file, gum_file_on_weak_notify,
      WeakCallbackType::kParameter);
  file->handle = handle;
  file->module = module;

  g_hash_table_add (module->files, file);

  return file;
}

static void
gum_file_free (GumFile * self)
{
  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  gum_file_close (self);

  delete self->wrapper;

  g_slice_free (GumFile, self);
}

static gboolean
gum_file_check_open (GumFile * self,
                     Isolate * isolate)
{
  if (self->handle == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "file is closed");
    return FALSE;
  }

  return TRUE;
}

static void
gum_file_close (GumFile * self)
{
  g_clear_pointer (&self->handle, fclose);
}

static gsize
gum_file_query_num_bytes_available (GumFile * self)
{
  FILE * handle = self->handle;
  GumV8InterceptorIgnoreScope interceptor_ignore_scope;

  long offset = ftell (handle);

  fseek (handle, 0, SEEK_END);
  long size = ftell (handle);

  fseek (handle, offset, SEEK_SET);

  return size - offset;
}

static gboolean
gum_file_set_contents (const gchar * filename,
                       const gchar * contents,
                       gssize length,
                       GError ** error)
{
#if GLIB_CHECK_VERSION (2, 66, 0)
  return g_file_set_contents_full (filename, contents, length,
      G_FILE_SET_CONTENTS_NONE, 0666, error);
#else
  return g_file_set_contents (filename, contents, length, error);
#endif
}

static void
gum_file_on_weak_notify (const WeakCallbackInfo<GumFile> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->files, self);
}
```