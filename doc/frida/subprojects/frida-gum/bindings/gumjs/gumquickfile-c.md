Response:
Let's break down the thought process for analyzing this C code for Frida.

**1. Initial Understanding - The Big Picture:**

The first thing to notice is the file path: `frida/subprojects/frida-gum/bindings/gumjs/gumquickfile.c`. This immediately tells us it's related to Frida's internal workings (`frida`), specifically its low-level instrumentation engine (`frida-gum`), and how it exposes functionality to JavaScript (`bindings/gumjs`). The filename `gumquickfile.c` strongly suggests it's about file system operations exposed through the Frida API.

**2. Identifying Core Functionality -  Declarations and Definitions:**

The next step is to scan the code for key function declarations and definitions. Look for patterns like `GUMJS_DECLARE_FUNCTION`, `GUMJS_DEFINE_FUNCTION`, `static`, and function signatures. This quickly reveals the main functionalities:

* **File Handling:**  `gumjs_file_construct`, `gumjs_file_finalize`, `gumjs_file_close`. These are the lifecycle management functions for a `File` object.
* **Reading:** `gumjs_file_read_all_bytes`, `gumjs_file_read_all_text`, `gumjs_file_read_bytes`, `gumjs_file_read_text`, `gumjs_file_read_line`.
* **Writing:** `gumjs_file_write_all_bytes`, `gumjs_file_write_all_text`, `gumjs_file_write`.
* **Navigation:** `gumjs_file_tell`, `gumjs_file_seek`.
* **Other:** `gumjs_file_flush`.

**3. Mapping to User-Level Concepts:**

Now, connect these function names to standard file system operations. `readAllBytes` and `readAllText` are for reading the entire file at once. `readBytes`, `readText`, and `readLine` offer more granular control. Similarly, the `write` functions correspond to writing data. `tell` and `seek` are standard file pointer manipulations.

**4. Identifying Key Data Structures:**

Notice the `GumFile` struct. This is the internal representation of a file within the Frida context. It holds a standard `FILE *` handle from the C library. This is a crucial link between Frida's JavaScript API and the underlying OS.

**5. Recognizing Glue Logic and Bindings:**

Pay attention to functions starting with `_gum_quick_`. These are likely internal Frida functions that bridge the gap between the C implementation and the JavaScript environment. For instance, `_gum_quick_args_parse` handles parsing arguments passed from JavaScript to the C functions. `_gum_quick_throw_literal` is used for error reporting back to JavaScript. The `GUMJS_DECLARE_*` and `GUMJS_DEFINE_*` macros are clearly part of Frida's binding mechanism.

**6. Connecting to Reverse Engineering:**

Think about *why* you'd want file system access in a reverse engineering context. Common scenarios include:

* **Reading configuration files:**  Many applications store settings in files.
* **Inspecting log files:** Useful for understanding application behavior.
* **Dumping data:**  Extracting data structures or memory contents to a file for later analysis.
* **Modifying files (carefully!):** Injecting code or altering program behavior (more advanced).

Relate these scenarios to the provided functions. `readAllBytes` is perfect for quickly grabbing an entire config file. `writeAllText` could be used to inject a modified configuration.

**7. Identifying System-Level Interactions:**

Look for standard C library functions related to file I/O: `fopen`, `fclose`, `fread`, `fwrite`, `fseek`, `ftell`, `fflush`. These functions directly interact with the operating system kernel. The inclusion of `<errno.h>` and `g_strerror` indicates error handling related to system calls. The use of `g_file_get_contents` and `g_file_set_contents_full` hints at reliance on GLib, a common library in Linux environments.

**8. Considering Assumptions and Edge Cases:**

Think about what could go wrong. What if the file doesn't exist? What if permissions are wrong? What if you try to read more bytes than are available? The code handles some of these with error checking and by using `g_file_query_num_bytes_available`.

**9. Tracing User Interaction:**

Imagine a Frida script. How would a user end up calling these functions?  They would typically use the `Frida.open()` method (or a similar API) in JavaScript to get a `File` object, and then call methods like `readAllBytes()`, `write()`, etc., on that object.

**10. Structuring the Explanation:**

Finally, organize the findings into a coherent explanation, addressing each part of the prompt systematically. Start with a high-level overview, then delve into specific functionalities, relate them to reverse engineering, discuss system-level aspects, provide examples, and address potential errors and user workflows. Use clear and concise language, and provide illustrative code snippets where appropriate.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This just reads and writes files."
* **Correction:** "It's not *just* that. It's exposing these operations within the Frida environment, making them available during dynamic instrumentation."
* **Initial thought:**  "Focus on individual functions."
* **Correction:** "It's important to also explain how these functions work together to provide a complete file I/O API."
* **Initial thought:** "Just list the system calls."
* **Correction:** "Explain *why* these system calls are relevant in the context of dynamic instrumentation and reverse engineering."

By following this structured approach, you can effectively analyze and understand the functionality of even moderately complex C code like this within the context of a larger framework like Frida.
这个C源代码文件 `gumquickfile.c` 是 Frida Dynamic Instrumentation 工具中 `frida-gum` 组件的一部分，专门为 JavaScript 绑定提供了文件操作的功能。它允许 Frida 用户在运行时通过 JavaScript 与目标进程的文件系统进行交互。

下面是该文件的功能列表以及与逆向、底层知识、逻辑推理和用户错误相关的说明：

**功能列表:**

1. **创建和管理 File 对象:**
   - `gumjs_file_construct`:  在 JavaScript 中创建一个 `File` 对象的构造函数，它会打开指定路径和模式的文件。
   - `gumjs_file_finalize`:  `File` 对象的析构函数，当 JavaScript 中的 `File` 对象被垃圾回收时调用，负责关闭底层的文件句柄。

2. **文件读取:**
   - `gumjs_file_read_all_bytes`: 读取文件的所有内容并以 `ArrayBuffer` 的形式返回。
   - `gumjs_file_read_all_text`: 读取文件的所有内容并尝试以 UTF-8 编码解析为字符串返回。
   - `gumjs_file_read_bytes`: 从当前文件指针位置读取指定数量的字节。
   - `gumjs_file_read_text`: 从当前文件指针位置读取指定数量的字节，并尝试以 UTF-8 编码解析为字符串返回。
   - `gumjs_file_read_line`: 从当前文件指针位置读取一行文本。

3. **文件写入:**
   - `gumjs_file_write_all_bytes`: 将 `ArrayBuffer` 中的所有字节写入到文件中。
   - `gumjs_file_write_all_text`: 将 JavaScript 字符串写入到文件中。
   - `gumjs_file_write`: 将 `ArrayBuffer` 中的数据写入到文件中。

4. **文件指针操作:**
   - `gumjs_file_tell`: 获取当前文件指针的位置。
   - `gumjs_file_seek`:  移动文件指针到指定的位置。

5. **其他操作:**
   - `gumjs_file_flush`: 刷新文件缓冲区，确保数据被写入到磁盘。
   - `gumjs_file_close`: 关闭文件。

**与逆向方法的关系及举例说明:**

这个文件提供的功能对于逆向工程非常有用，因为它允许在目标进程运行时检查和修改其访问的文件。

* **读取配置文件和数据文件:**  逆向工程师可以使用 `readAllText` 或 `readAllBytes` 来读取目标应用加载的配置文件，例如查看服务器地址、API 密钥或其他敏感信息。
    * **例子:** 假设一个 Android 应用将服务器地址存储在 `/data/data/com.example.app/shared_prefs/config.xml` 文件中。可以使用以下 Frida JavaScript 代码读取内容：
      ```javascript
      const File = Java.use('java.io.File');
      const FileInputStream = Java.use('java.io.FileInputStream');
      const BufferedReader = Java.use('java.io.BufferedReader');
      const InputStreamReader = Java.use('java.io.InputStreamReader');

      function readAllText(filePath) {
          const file = File.$new(filePath);
          const fis = FileInputStream.$new(file);
          const isr = InputStreamReader.$new(fis);
          const br = BufferedReader.$new(isr);
          let line;
          let allText = "";
          while ((line = br.readLine()) !== null) {
              allText += line + "\n";
          }
          br.close();
          isr.close();
          fis.close();
          return allText;
      }

      const configPath = "/data/data/com.example.app/shared_prefs/config.xml";
      const configFileContent = Module.load('file').readAllText(configPath);
      console.log("Config file content:\n" + configFileContent);
      ```
      **注意:**  在Frida的 GumJS 环境中，可以直接使用 `Module.load('file').readAllText(filepath)`，上面的 Java 代码示例是为了说明在没有直接 `gumquickfile.c` 封装的情况下，如何通过 Java API 实现类似功能。 `gumquickfile.c` 的目标就是提供更便捷的封装。

* **监控文件访问:** 可以通过 hook `fopen` 或相关的系统调用来监控目标进程打开了哪些文件，但这需要更底层的 Frida Gum 接口。 `gumquickfile.c` 提供了更高层次的抽象，可以直接操作已打开的文件。

* **修改文件内容 (谨慎使用):**  可以使用 `writeAllText` 或 `writeAllBytes` 来修改目标进程正在使用的文件。这可以用于动态地改变应用的配置或数据，用于测试或绕过某些安全机制。
    * **例子:** 假设你想临时修改一个应用的调试标志，该标志存储在一个简单的文本文件中。
      ```javascript
      Module.load('file').writeAllText("/path/to/debug_flag.txt", "true\n");
      console.log("Debug flag set to true.");
      ```
      **警告:**  随意修改文件内容可能导致目标应用崩溃或行为异常，务必谨慎操作。

* **读取日志文件:**  可以读取目标进程生成的日志文件，用于分析其行为和错误。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

* **二进制底层:**
    * `gumjs_file_read_bytes` 和 `gumjs_file_write` 处理的是原始字节流，这直接涉及到对二进制数据的操作。逆向工程中经常需要分析二进制文件格式。
    * `ArrayBuffer` 是 JavaScript 中表示原始二进制数据的对象，`gumquickfile.c` 将文件内容读取到 `ArrayBuffer` 中，或者从 `ArrayBuffer` 中写入文件，这体现了对二进制数据的处理能力。
* **Linux:**
    * 底层使用标准的 C 库文件操作函数，如 `fopen`, `fclose`, `fread`, `fwrite`, `fseek`, `ftell`, `fflush`，这些都是 Linux 系统提供的接口。
    * `SEEK_SET`, `SEEK_CUR`, `SEEK_END` 这些常量是 Linux 中用于 `lseek` 系统调用（或 C 库中的 `fseek`）的偏移量标志。
    * 文件权限 (在 `gum_file_set_contents` 中体现的 `0666`) 是 Linux 文件系统的重要概念。
* **Android:**
    * 虽然代码本身是通用的 C 代码，但它在 Frida 的 Android 环境中被使用。逆向 Android 应用时，经常需要访问应用的私有数据目录 (`/data/data/<package_name>/`) 或其他系统文件。
    * 这个模块可以用来读取 Android 应用的 Shared Preferences 文件、数据库文件、或应用自身的 APK 文件（虽然直接读取 APK 可能需要特殊权限）。
* **框架知识 (Frida Gum):**
    * `GUMJS_DECLARE_*` 和 `GUMJS_DEFINE_*` 宏是 Frida Gum 用于将 C 代码绑定到 JavaScript 的机制。
    * `GumFile` 结构体是 `frida-gum` 内部表示文件对象的结构。
    * 代码中使用了 GLib 库的一些功能，例如 `GError` 用于错误处理，`g_file_get_contents` 等函数用于文件操作。

**逻辑推理及假设输入与输出:**

假设 JavaScript 代码如下：

```javascript
const fileModule = Module.load('file');
const filePath = "/tmp/test.txt";

// 假设文件 /tmp/test.txt 不存在

// 写入文本
fileModule.writeAllText(filePath, "Hello Frida!\n");

// 读取所有文本
const content = fileModule.readAllText(filePath);
console.log("File content:", content);

// 读取所有字节
const bytes = fileModule.readAllBytes(filePath);
console.log("File bytes:", bytes);

// 打开文件进行更细粒度的操作
const fd = new fileModule.File(filePath, "r+");
fd.seek(6); // 移动到 "Frida" 的 'F'
const readBytes = fd.readBytes(5); // 读取 "Frida"
console.log("Read bytes:", readBytes);
fd.close();
```

**假设输入与输出:**

* **`fileModule.writeAllText(filePath, "Hello Frida!\n");`**:
    * **假设输入:** `filePath` 为 "/tmp/test.txt"，写入内容为 "Hello Frida!\n"。
    * **输出:**  在 `/tmp` 目录下创建一个名为 `test.txt` 的文件，内容为 "Hello Frida!\n"。

* **`const content = fileModule.readAllText(filePath);`**:
    * **假设输入:** `filePath` 为 "/tmp/test.txt"，文件内容为 "Hello Frida!\n"。
    * **输出:** JavaScript 变量 `content` 的值为字符串 "Hello Frida!\n"。

* **`const bytes = fileModule.readAllBytes(filePath);`**:
    * **假设输入:** `filePath` 为 "/tmp/test.txt"，文件内容为 "Hello Frida!\n"。
    * **输出:** JavaScript 变量 `bytes` 是一个 `ArrayBuffer`，其内容对应于 "Hello Frida!\n" 的 UTF-8 编码的字节。

* **`const fd = new fileModule.File(filePath, "r+");`**:
    * **假设输入:** `filePath` 为 "/tmp/test.txt"，以读写模式打开。
    * **输出:**  成功打开文件，返回一个 `File` 对象 `fd`。

* **`fd.seek(6);`**:
    * **假设输入:** 当前文件指针在文件开头，移动偏移量为 6。
    * **输出:** 文件指针移动到字符 'F' 的位置。

* **`const readBytes = fd.readBytes(5);`**:
    * **假设输入:** 当前文件指针在字符 'F' 的位置，读取 5 个字节。
    * **输出:** JavaScript 变量 `readBytes` 是一个 `ArrayBuffer`，其内容对应于 "Frida" 的 UTF-8 编码的字节。

* **`fd.close();`**:
    * **假设输入:**  `fd` 是一个已打开文件的 `File` 对象。
    * **输出:** 关闭与 `fd` 关联的文件句柄。

**用户或编程常见的使用错误及举例说明:**

1. **尝试操作未打开或已关闭的文件:**
   ```javascript
   const fileModule = Module.load('file');
   const filePath = "/tmp/test.txt";
   let fd;
   try {
       fd = new fileModule.File(filePath, "r");
       fd.close();
       fd.readAllText(); // 错误：尝试操作已关闭的文件
   } catch (e) {
       console.error("Error:", e); // 可能抛出 "file is closed" 异常
   }
   ```

2. **文件路径不存在或权限不足:**
   ```javascript
   const fileModule = Module.load('file');
   const filePath = "/nonexistent/file.txt";
   try {
       const content = fileModule.readAllText(filePath); // 错误：文件不存在
       console.log(content);
   } catch (e) {
       console.error("Error:", e); // 可能抛出包含 "No such file or directory" 的异常
   }
   ```

3. **以错误的模式打开文件进行操作:**
   ```javascript
   const fileModule = Module.load('file');
   const filePath = "/tmp/test.txt";
   try {
       const fd = new fileModule.File(filePath, "r"); // 以只读模式打开
       fd.write("Some text"); // 错误：尝试写入以只读模式打开的文件
       fd.close();
   } catch (e) {
       console.error("Error:", e); // 可能抛出与文件模式不匹配相关的异常
   }
   ```

4. **读取文本文件时假设错误的编码:** 如果文件不是 UTF-8 编码，`readAllText` 或 `readText` 可能会抛出异常或返回乱码。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户编写一个 JavaScript 脚本，该脚本使用 Frida 的 `Module.load('file')` 来加载 `gumquickfile` 模块。

2. **调用 File API:**  脚本中调用了 `fileModule` 提供的函数，例如 `readAllText`, `writeAllBytes`, 或者创建 `File` 对象并调用其方法。

3. **Frida 执行脚本:** 用户使用 Frida CLI 工具 (`frida`, `frida-ps`, `frida-trace` 等) 将脚本注入到目标进程中。

4. **GumJS 执行:**  Frida Gum 环境在目标进程中执行 JavaScript 代码。当调用 `fileModule` 的方法时，实际上会调用 `gumquickfile.c` 中对应的 C 函数。

5. **C 函数执行:**  `gumquickfile.c` 中的 C 函数会调用标准的 C 库函数（如 `fopen`, `fread`, `fwrite`）来执行实际的文件操作。

6. **系统调用:** C 库函数最终会转化为系统调用，由操作系统内核来完成文件读写等操作。

**调试线索:**

* **JavaScript 异常:** 如果用户操作不当，例如尝试读取不存在的文件，`gumquickfile.c` 中的 C 代码会返回错误，并由 Frida 的绑定机制将错误转换为 JavaScript 异常抛出。用户可以在 Frida 脚本中捕获这些异常来定位问题。
* **Frida 日志:** Frida 运行时可能会输出一些调试信息，可以帮助理解文件操作的执行情况。
* **目标进程行为:**  文件操作的结果会直接影响目标进程的行为。例如，如果修改了配置文件，目标进程下次读取配置时会加载新的内容。通过观察目标进程的行为变化，可以推断文件操作是否成功以及产生了什么影响。
* **系统调用跟踪 (strace):**  可以使用 `strace` 工具跟踪目标进程的系统调用，查看是否执行了预期的文件相关的系统调用，以及系统调用的返回值，从而更深入地了解文件操作的底层细节。

总而言之，`gumquickfile.c` 提供了一个方便的桥梁，使得 Frida 用户能够通过 JavaScript 灵活地与目标进程的文件系统进行交互，这在动态分析、逆向工程和安全研究等领域都有着重要的作用。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickfile.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2020-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickfile.h"

#include "gumquickinterceptor.h"
#include "gumquickmacros.h"

#include <errno.h>
#include <string.h>

typedef struct _GumFile GumFile;

struct _GumFile
{
  FILE * handle;
};

GUMJS_DECLARE_FUNCTION (gumjs_file_read_all_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_all_text)
GUMJS_DECLARE_FUNCTION (gumjs_file_write_all_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_write_all_text)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FINALIZER (gumjs_file_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_file_tell)
GUMJS_DECLARE_FUNCTION (gumjs_file_seek)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_text)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_line)
GUMJS_DECLARE_FUNCTION (gumjs_file_write)
GUMJS_DECLARE_FUNCTION (gumjs_file_flush)
GUMJS_DECLARE_FUNCTION (gumjs_file_close)

static GumFile * gum_file_new (FILE * handle);
static void gum_file_free (GumFile * self);
static void gum_file_close (GumFile * self);
static gsize gum_file_query_num_bytes_available (GumFile * self);
static gboolean gum_file_set_contents (const gchar * filename,
    const gchar * contents, gssize length, GError ** error);

static const JSClassDef gumjs_file_def =
{
  .class_name = "File",
  .finalizer = gumjs_file_finalize,
};

static const JSCFunctionListEntry gumjs_file_module_entries[] =
{
  JS_PROP_INT32_DEF ("SEEK_SET", SEEK_SET, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("SEEK_CUR", SEEK_CUR, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("SEEK_END", SEEK_END, JS_PROP_C_W_E),

  JS_CFUNC_DEF ("readAllBytes", 0, gumjs_file_read_all_bytes),
  JS_CFUNC_DEF ("readAllText", 0, gumjs_file_read_all_text),
  JS_CFUNC_DEF ("writeAllBytes", 0, gumjs_file_write_all_bytes),
  JS_CFUNC_DEF ("writeAllText", 0, gumjs_file_write_all_text),
};

static const JSCFunctionListEntry gumjs_file_entries[] =
{
  JS_CFUNC_DEF ("tell", 0, gumjs_file_tell),
  JS_CFUNC_DEF ("seek", 0, gumjs_file_seek),
  JS_CFUNC_DEF ("readBytes", 0, gumjs_file_read_bytes),
  JS_CFUNC_DEF ("readText", 0, gumjs_file_read_text),
  JS_CFUNC_DEF ("readLine", 0, gumjs_file_read_line),
  JS_CFUNC_DEF ("write", 0, gumjs_file_write),
  JS_CFUNC_DEF ("flush", 0, gumjs_file_flush),
  JS_CFUNC_DEF ("close", 0, gumjs_file_close),
};

void
_gum_quick_file_init (GumQuickFile * self,
                      JSValue ns,
                      GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "file", self);

  _gum_quick_create_class (ctx, &gumjs_file_def, core, &self->file_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_file_construct,
      gumjs_file_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_file_module_entries,
      G_N_ELEMENTS (gumjs_file_module_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_file_entries,
      G_N_ELEMENTS (gumjs_file_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_file_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_file_dispose (GumQuickFile * self)
{
}

void
_gum_quick_file_finalize (GumQuickFile * self)
{
}

static GumQuickFile *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "file");
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_all_bytes)
{
  const gchar * filename;
  gchar * contents;
  gsize length;
  GError * error;

  if (!_gum_quick_args_parse (args, "s", &filename))
    return JS_EXCEPTION;

  error = NULL;
  if (!g_file_get_contents (filename, &contents, &length, &error))
    goto propagate_error;

  return JS_NewArrayBuffer (ctx, (uint8_t *) contents, length,
      _gum_quick_array_buffer_free, contents, FALSE);

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_all_text)
{
  JSValue result;
  const gchar * filename;
  gchar * contents;
  gsize length;
  GError * error;
  const gchar * end;

  if (!_gum_quick_args_parse (args, "s", &filename))
    return JS_EXCEPTION;

  error = NULL;
  if (!g_file_get_contents (filename, &contents, &length, &error))
    goto propagate_error;

  if (g_utf8_validate (contents, length, &end))
  {
    result = JS_NewStringLen (ctx, contents, length);
  }
  else
  {
    result = _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - contents));
  }

  g_free (contents);

  return result;

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write_all_bytes)
{
  const gchar * filename;
  GBytes * bytes;
  gconstpointer data;
  gsize size;
  GError * error;

  if (!_gum_quick_args_parse (args, "sB", &filename, &bytes))
    return JS_EXCEPTION;

  data = g_bytes_get_data (bytes, &size);

  error = NULL;
  if (!gum_file_set_contents (filename, data, size, &error))
    goto propagate_error;

  return JS_UNDEFINED;

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write_all_text)
{
  const gchar * filename, * text;
  GError * error;

  if (!_gum_quick_args_parse (args, "ss", &filename, &text))
    return JS_EXCEPTION;

  error = NULL;
  if (!gum_file_set_contents (filename, text, -1, &error))
    goto propagate_error;

  return JS_UNDEFINED;

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

static gboolean
gum_file_get (JSContext * ctx,
              JSValueConst val,
              GumQuickCore * core,
              GumFile ** file)
{
  GumFile * f;

  if (!_gum_quick_unwrap (ctx, val, gumjs_get_parent_module (core)->file_class,
      core, (gpointer *) &f))
    return FALSE;

  if (f->handle == NULL)
  {
    _gum_quick_throw_literal (ctx, "file is closed");
    return FALSE;
  }

  *file = f;
  return TRUE;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  JSValue wrapper = JS_NULL;
  const gchar * filename, * mode;
  JSValue proto;
  FILE * handle;
  GumFile * file;

  if (!_gum_quick_args_parse (args, "ss", &filename, &mode))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto,
      gumjs_get_parent_module (core)->file_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  GUMJS_INTERCEPTOR_IGNORE ();

  handle = fopen (filename, mode);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (handle == NULL)
    goto fopen_failed;

  file = gum_file_new (handle);

  JS_SetOpaque (wrapper, file);

  return wrapper;

fopen_failed:
  {
    _gum_quick_throw_literal (ctx, g_strerror (errno));
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_file_finalize)
{
  GumFile * f;

  f = JS_GetOpaque (val, gumjs_get_parent_module (core)->file_class);
  if (f == NULL)
    return;

  gum_file_free (f);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_tell)
{
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt64 (ctx, ftell (self->handle));
}

GUMJS_DEFINE_FUNCTION (gumjs_file_seek)
{
  GumFile * self;
  gssize offset;
  gint whence;
  int result;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  whence = SEEK_SET;
  if (!_gum_quick_args_parse (args, "z|i", &offset, &whence))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  result = fseek (self->handle, offset, whence);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (result == -1)
    goto seek_failed;

  return JS_NewInt64 (ctx, result);

seek_failed:
  {
    return _gum_quick_throw_literal (ctx, g_strerror (errno));
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_bytes)
{
  JSValue result;
  GumFile * self;
  gsize n;
  gpointer data;
  size_t num_bytes_read;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  n = G_MAXSIZE;
  if (!_gum_quick_args_parse (args, "|Z", &n))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  if (n == G_MAXSIZE)
    n = gum_file_query_num_bytes_available (self);

  if (n == 0)
  {
    GUMJS_INTERCEPTOR_UNIGNORE ();
    return JS_NewArrayBufferCopy (ctx, NULL, 0);
  }

  data = g_malloc (n);
  result = JS_NewArrayBuffer (ctx, data, n, _gum_quick_array_buffer_free, data,
      FALSE);

  num_bytes_read = fread (data, 1, n, self->handle);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (num_bytes_read < n)
  {
    JSValue r;

    r = JS_NewArrayBufferCopy (ctx, data, num_bytes_read);
    JS_FreeValue (ctx, result);
    result = r;
  }

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_text)
{
  JSValue result;
  GumFile * self;
  gsize n;
  gchar * data;
  size_t num_bytes_read;
  const gchar * end;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  n = G_MAXSIZE;
  if (!_gum_quick_args_parse (args, "|Z", &n))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  if (n == G_MAXSIZE)
    n = gum_file_query_num_bytes_available (self);

  if (n == 0)
  {
    GUMJS_INTERCEPTOR_UNIGNORE ();
    return JS_NewString (ctx, "");
  }

  data = g_malloc (n);
  num_bytes_read = fread (data, 1, n, self->handle);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  if (g_utf8_validate (data, num_bytes_read, &end))
  {
    result = JS_NewStringLen (ctx, data, num_bytes_read);
  }
  else
  {
    result = _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - data));

    GUMJS_INTERCEPTOR_IGNORE ();

    fseek (self->handle, -((long) num_bytes_read), SEEK_CUR);

    GUMJS_INTERCEPTOR_UNIGNORE ();
  }

  g_free (data);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_line)
{
  JSValue result;
  GumFile * self;
  gsize offset, capacity;
  GString * buffer;
  const gchar * end;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  offset = 0;
  capacity = 256;
  buffer = g_string_sized_new (capacity);

  GUMJS_INTERCEPTOR_IGNORE ();

  while (TRUE)
  {
    gsize num_bytes_read;

    g_string_set_size (buffer, capacity);

    if (fgets (buffer->str + offset, capacity - offset, self->handle) == NULL)
      break;

    num_bytes_read = strlen (buffer->str + offset);
    offset += num_bytes_read;

    if (buffer->str[offset - 1] == '\n')
      break;

    if (offset == capacity - 1)
      capacity += 256;
    else
      break;
  }

  GUMJS_INTERCEPTOR_UNIGNORE ();

  g_string_set_size (buffer, offset);

  if (g_utf8_validate (buffer->str, buffer->len, &end))
  {
    result = JS_NewStringLen (ctx, buffer->str, buffer->len);
  }
  else
  {
    result = _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - buffer->str));

    GUMJS_INTERCEPTOR_IGNORE ();

    fseek (self->handle, -((long) buffer->len), SEEK_CUR);

    GUMJS_INTERCEPTOR_UNIGNORE ();
  }

  g_string_free (buffer, TRUE);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write)
{
  GumFile * self;
  GBytes * bytes;
  gconstpointer data;
  gsize size;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "B~", &bytes))
    return JS_EXCEPTION;

  data = g_bytes_get_data (bytes, &size);

  GUMJS_INTERCEPTOR_IGNORE ();

  fwrite (data, size, 1, self->handle);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_flush)
{
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  GUMJS_INTERCEPTOR_IGNORE ();

  fflush (self->handle);

  GUMJS_INTERCEPTOR_UNIGNORE ();

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_close)
{
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  gum_file_close (self);

  return JS_UNDEFINED;
}

static GumFile *
gum_file_new (FILE * handle)
{
  GumFile * file;

  file = g_slice_new (GumFile);
  file->handle = handle;

  return file;
}

static void
gum_file_free (GumFile * self)
{
  gum_file_close (self);

  g_slice_free (GumFile, self);
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
  long offset, size;

  offset = ftell (handle);

  fseek (handle, 0, SEEK_END);
  size = ftell (handle);

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
```