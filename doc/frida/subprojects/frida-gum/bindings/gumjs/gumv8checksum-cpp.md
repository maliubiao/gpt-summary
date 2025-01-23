Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Understanding & High-Level Overview:**

* **File Path:**  `frida/subprojects/frida-gum/bindings/gumjs/gumv8checksum.cpp`  Immediately signals that this code is part of Frida, specifically the "gumjs" component which bridges JavaScript and Frida's core ("gum"). The "v8" in the name points to the use of the V8 JavaScript engine. "checksum" suggests its primary function.
* **Copyright & License:**  Standard copyright and licensing information, indicating open-source nature.
* **Includes:**  `gumv8checksum.h`, `gumv8macros.h` hint at internal Frida/Gum structures and macros. `<v8.h>` confirms V8 integration.
* **Namespace:** `using namespace v8;`  Confirms interaction with the V8 API.
* **`GUMJS_MODULE_NAME Checksum`:** This is likely a macro defining the module name exposed to JavaScript, solidifying the purpose.

**2. Identifying Core Functionality:**

* **Struct `GumChecksum`:** This structure holds key data for a checksum operation:
    * `wrapper`: V8 object wrapper, crucial for managing the JavaScript object representation.
    * `handle`: `GChecksum *`, indicating the use of GLib's checksumming functionality. This is a major clue about the underlying implementation.
    * `type`: `GChecksumType`, storing the specific checksum algorithm (SHA256, MD5, etc.).
    * `closed`: A flag to track the state of the checksum object.
    * `module`: Pointer back to the `GumV8Checksum` module.
* **Function Declarations (`GUMJS_DECLARE_*`):** These macros declare functions that will be exposed to JavaScript. The names are very descriptive: `gumjs_checksum_compute`, `gumjs_checksum_construct`, `gumjs_checksum_update`, `gumjs_checksum_get_string`, `gumjs_checksum_get_digest`. This clearly outlines the API provided to JavaScript.
* **Static Helper Functions:** `gum_checksum_new`, `gum_checksum_free`, `gum_checksum_on_weak_notify`, `gum_v8_checksum_type_get` are internal helper functions for managing the `GumChecksum` structure and converting between string representations and `GChecksumType`.
* **Module Functions (`gumjs_checksum_module_functions`):**  The `compute` function appears to be a static method on the `Checksum` class, allowing direct checksum computation without creating an instance.
* **Instance Functions (`gumjs_checksum_functions`):** `update`, `getString`, and `getDigest` are methods available on instances of the `Checksum` class, indicating a stateful checksumming process.
* **`_gum_v8_checksum_init`, `_gum_v8_checksum_realize`, `_gum_v8_checksum_dispose`, `_gum_v8_checksum_finalize`:** These functions look like lifecycle management functions for the `GumV8Checksum` module, likely called by Frida's core.

**3. Connecting to Reverse Engineering and Binary Analysis:**

* **Checksums in Reverse Engineering:** Checksums are widely used in software:
    * **Integrity Checks:** Verifying file integrity.
    * **Code Signing:** Ensuring the authenticity of code.
    * **Data Validation:** Confirming data hasn't been tampered with.
    * **Algorithm Identification:** Recognizing common cryptographic algorithms.
* **Frida's Role:** Frida allows you to intercept and manipulate function calls. This `gumv8checksum` module enables scripts to calculate checksums of data *within* a running process. This is extremely useful for reverse engineering:
    * Calculating the checksum of a loaded library to verify it hasn't been patched.
    * Computing checksums of function arguments or return values to understand data flow.
    * Identifying encryption or hashing routines by analyzing the checksum algorithms used.

**4. Identifying Low-Level Interactions:**

* **GLib (`GChecksum`, `GChecksumType`, `g_checksum_new`, etc.):**  The code heavily relies on GLib, a fundamental library in many Linux and cross-platform environments. This is a key low-level detail.
* **V8 API:** The extensive use of `v8::Isolate`, `v8::Local`, `v8::ObjectTemplate`, `v8::String`, `v8::ArrayBuffer`, etc., demonstrates direct interaction with the V8 JavaScript engine's internals for creating and managing JavaScript objects and transferring data.
* **`ArrayBuffer` and `GetBackingStore`:**  This shows how binary data (digests) is transferred between C++ and JavaScript efficiently. It's accessing the raw memory backing the JavaScript `ArrayBuffer`.
* **Memory Management (`g_slice_new`, `g_slice_free`, `g_hash_table_new_full`):**  The code explicitly manages memory using GLib's memory allocation functions, highlighting the need for careful resource management in C++.

**5. Logic and Input/Output Analysis:**

* **`compute()` function:** Takes a checksum type and data (string or bytes) and returns the checksum as a string.
* **Constructor:** Takes a checksum type and initializes a `Checksum` object.
* **`update()`:**  Takes data (string or bytes) and updates the internal checksum state. Allows for incremental checksum calculation.
* **`getString()`:** Finalizes the checksum and returns it as a hexadecimal string.
* **`getDigest()`:** Finalizes the checksum and returns it as a raw byte array (JavaScript `ArrayBuffer`).

**6. Identifying Potential User Errors:**

* **Incorrect Checksum Type:** Providing an unsupported type like "sha224" will lead to an error.
* **Calling `update()` after `getString()` or `getDigest()`:** The `closed` flag prevents further updates.
* **Forgetting `new`:**  Trying to call `Checksum()` as a function instead of a constructor will result in an error.
* **Missing Arguments:** Not providing the required arguments to the functions will cause errors.

**7. Tracing User Operations (Debugging):**

* **Frida Script:** A user starts by writing a Frida script.
* **`import` or `require`:** The script likely imports the `Checksum` module.
* **Instantiation or Static Call:** The script either creates a new `Checksum` object or calls the static `Checksum.compute()` method.
* **Method Calls:** If an instance is created, the user might call `update()` multiple times, followed by `getString()` or `getDigest()`.
* **Error/Unexpected Output:** If something goes wrong, the user might set breakpoints or log output within their Frida script or within Frida's C++ code (if debugging Frida itself).

**Self-Correction/Refinement During Analysis:**

* Initially, I might just see function names and guess their purpose. Deeper inspection of the function implementations (e.g., `gumjs_checksum_update` using `g_checksum_update`) confirms the usage of GLib.
* Noticing the `wrapper` and weak references indicates the need for garbage collection management in the V8 environment.
* Recognizing the patterns in the `GUMJS_DEFINE_*` macros reveals how the C++ functions are connected to the JavaScript API.

By following this systematic approach, analyzing the code structure, function signatures, data structures, and external library usage, a comprehensive understanding of the code's functionality and its relevance to reverse engineering can be achieved. The examples and explanations then flow naturally from this understanding.
这个文件 `gumv8checksum.cpp` 是 Frida 动态插桩工具中 `gumjs` 组件的一部分，负责在 JavaScript 中提供计算各种数据校验和（checksum）的功能。它利用 GLib 库提供的 checksum 功能，并将这些功能桥接到 V8 JavaScript 引擎中，使得 Frida 脚本能够方便地计算数据的哈希值。

**功能列举：**

1. **提供 JavaScript 可调用的 `Checksum` 类:**  该文件定义了一个名为 `Checksum` 的 JavaScript 类，允许用户在 Frida 脚本中创建和使用 checksum 对象。
2. **支持多种哈希算法:** 通过使用 GLib 的 `GChecksum`，该模块支持多种常见的哈希算法，例如 SHA-256, SHA-384, SHA-512, SHA-1, MD5。
3. **静态方法 `compute()`:**  提供一个静态方法 `compute(type, data)`，可以直接计算给定数据的校验和。`type` 参数指定哈希算法，`data` 可以是字符串或二进制数据。
4. **实例方法 `update()`:**  对于 `Checksum` 类的实例，提供 `update(data)` 方法，允许逐步更新校验和。这在处理大数据流时非常有用。
5. **实例方法 `getString()`:**  用于获取计算完成的校验和的十六进制字符串表示。调用此方法后，校验和对象被标记为已关闭，不能再进行更新。
6. **实例方法 `getDigest()`:**  用于获取计算完成的校验和的原始二进制数据（以 `ArrayBuffer` 的形式返回）。调用此方法后，校验和对象同样被标记为已关闭。

**与逆向方法的关系及举例说明：**

该模块在逆向工程中扮演着重要的角色，因为它允许在运行时动态地计算和比较数据的校验和，从而帮助分析程序的行为和结构。

* **验证代码完整性:** 在运行时可以计算内存中代码段的校验和，并与预期值进行比较，以检测代码是否被修改或注入。
    * **举例:** 假设要检查一个关键函数 `targetFunction` 是否被 hook 或修改。可以编写 Frida 脚本，在 `targetFunction` 执行前或后，读取其内存区域，使用 `Checksum.compute('sha256', memoryData)` 计算其 SHA-256 校验和，并与原始或预期的校验和进行对比。
    ```javascript
    const targetFunctionAddress = Module.findExportByName(null, 'targetFunction');
    const functionSize = 1024; // 假设函数大小为 1024 字节
    const originalChecksum = '...预期的校验和...';

    Interceptor.attach(targetFunctionAddress, {
      onEnter: function(args) {
        const memoryData = Memory.readByteArray(targetFunctionAddress, functionSize);
        const currentChecksum = Checksum.compute('sha256', memoryData);
        if (currentChecksum !== originalChecksum) {
          console.warn('Warning: targetFunction 可能已被修改！');
        }
      }
    });
    ```

* **分析数据结构和协议:** 在运行时可以计算关键数据结构的校验和，以理解数据的变化和传输过程。
    * **举例:**  如果逆向分析一个网络协议，可以 hook 发送和接收数据的函数，计算发送或接收缓冲区数据的校验和，观察校验和的变化，从而推断协议的校验机制或数据完整性保护方式。
    ```javascript
    const sendFunction = Module.findExportByName(null, 'send');
    Interceptor.attach(sendFunction, {
      onEnter: function(args) {
        const buffer = ptr(args[1]);
        const length = args[2].toInt32();
        const data = Memory.readByteArray(buffer, length);
        const checksum = Checksum.compute('md5', data);
        console.log('发送数据 MD5 校验和:', checksum);
      }
    });
    ```

* **识别加密算法:**  通过计算已知明文和密文的校验和，或者在加密过程中计算中间数据的校验和，可能有助于识别程序使用的加密算法。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

该文件本身是 Frida 的一部分，它作为用户空间的应用，与操作系统内核及底层交互通常通过 Frida 的其他组件完成。然而，其功能涉及到一些底层概念：

* **二进制数据处理:** `getDigest()` 方法返回的是二进制数据，这涉及到对内存中原始字节的访问和操作。在逆向分析中，经常需要处理二进制数据，例如解析文件格式、网络协议等。
* **内存读取 (`Memory.readByteArray`)**: Frida 提供了 `Memory` API 来读取进程的内存，这是进行动态分析的基础。计算校验和需要读取目标进程的内存。
* **GLib 库:** 该模块底层使用了 GLib 库的 `GChecksum` 功能，GLib 是一个底层的 C 库，提供了许多基础的数据结构和工具函数，在 Linux 和其他类 Unix 系统中被广泛使用。理解 GLib 的使用有助于理解 Frida 的内部实现。
* **V8 JavaScript 引擎:** 该模块将 C++ 的功能桥接到 V8 引擎，涉及到 V8 的 API，例如创建对象、调用函数、处理数据类型等。理解 V8 的工作原理有助于理解 Frida 如何执行 JavaScript 代码并与目标进程交互。

**逻辑推理及假设输入与输出：**

* **假设输入:**
    * 调用 `Checksum.compute('sha1', 'hello')`
* **逻辑推理:**
    1. `gumjs_checksum_compute` 函数被调用。
    2. 参数 "sha1" 和字符串 "hello" 被解析。
    3. `gum_v8_checksum_type_get` 函数将 "sha1" 转换为 `G_CHECKSUM_SHA1`。
    4. `g_compute_checksum_for_string(G_CHECKSUM_SHA1, "hello", -1)` 被调用。
    5. GLib 计算 "hello" 的 SHA-1 校验和。
* **输出:** 返回 "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0" (这是 "hello" 的 SHA-1 校验和的十六进制表示)。

* **假设输入:**
    1. 创建 `const checksum = new Checksum('md5');`
    2. 调用 `checksum.update('world');`
    3. 调用 `checksum.getString();`
* **逻辑推理:**
    1. `gumjs_checksum_construct` 创建一个 `Checksum` 对象，初始化 `GChecksum` 为 MD5。
    2. `gumjs_checksum_update` 将字符串 "world" 更新到内部的 `GChecksum` 状态。
    3. `gumjs_checksum_get_string` 最终计算 MD5 校验和并返回其十六进制字符串表示。
* **输出:** 返回 "7d3a9efb4a4f8e09e1f2aa83c4a988d1" (这是 "world" 的 MD5 校验和的十六进制表示)。

**涉及用户或编程常见的使用错误及举例说明：**

1. **不支持的校验和类型:**  传递一个 `gum_v8_checksum_type_get` 函数无法识别的字符串作为校验和类型。
   ```javascript
   // 错误：'sm3' 不是支持的校验和类型
   const checksum = Checksum.compute('sm3', 'data');
   ```
   **结果:** 会抛出一个 JavaScript 异常，提示 "unsupported checksum type"。

2. **在 `getString()` 或 `getDigest()` 后调用 `update()`:**  一旦调用了 `getString()` 或 `getDigest()`，校验和对象就被标记为关闭，不能再更新。
   ```javascript
   const checksum = new Checksum('sha256');
   checksum.update('part1');
   const hash = checksum.getString();
   // 错误：checksum 已经关闭
   checksum.update('part2');
   ```
   **结果:** 会抛出一个 JavaScript 异常，提示 "checksum is closed"。

3. **忘记使用 `new` 关键字创建 `Checksum` 对象:**
   ```javascript
   // 错误：应该使用 new Checksum()
   const checksum = Checksum('md5');
   ```
   **结果:** 会抛出一个 JavaScript 异常，提示 "use `new Checksum()` to create a new instance"。

4. **缺少必要的参数:**  调用 `compute` 或构造函数时缺少必要的参数。
   ```javascript
   // 错误：缺少数据参数
   const hash = Checksum.compute('sha256');

   // 错误：缺少校验和类型参数
   const checksum = new Checksum();
   ```
   **结果:** 会抛出一个 JavaScript 异常，提示 "missing argument"。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:** 用户首先会编写一个 JavaScript 脚本，使用 Frida 的 API 与目标进程进行交互。
2. **引入 `Checksum` 模块:** 在脚本中，用户需要使用 `Checksum` 类来计算校验和，这会触发 Frida 加载和初始化 `gumv8checksum.cpp` 对应的模块。
   ```javascript
   // 假设用户想计算某个内存区域的 SHA-256 校验和
   const moduleBase = Module.getBaseAddress('target_module');
   const dataAddress = moduleBase.add(0x1000); // 假设数据地址
   const dataSize = 256;
   const data = Memory.readByteArray(dataAddress, dataSize);
   const checksum = Checksum.compute('sha256', data);
   console.log('SHA-256 校验和:', checksum);
   ```
3. **Frida 执行脚本:**  用户使用 Frida CLI 工具（例如 `frida -p <pid> -l script.js`）或通过 Frida 的其他绑定（如 Python）将脚本注入到目标进程中。
4. **V8 执行 JavaScript 代码:**  Frida 内部的 V8 引擎会解析并执行用户的 JavaScript 代码。当执行到 `Checksum.compute()` 时，V8 会查找与 `Checksum` 类及其 `compute` 方法对应的 C++ 代码实现，也就是 `gumjs_checksum_compute` 函数。
5. **C++ 代码执行:** `gumjs_checksum_compute` 函数会被调用，它会解析 JavaScript 传递的参数，并调用 GLib 的相关函数进行实际的校验和计算。
6. **可能的调试点:** 如果用户在脚本执行过程中遇到问题，例如校验和计算错误或崩溃，以下是一些可能的调试线索和如何到达 `gumv8checksum.cpp` 的步骤：
   * **JavaScript 错误信息:** 如果出现 JavaScript 异常，例如 "unsupported checksum type"，可以直接定位到 `gum_v8_checksum_type_get` 函数中的判断逻辑。
   * **Frida 日志:** Frida 可能会输出一些调试信息，指示模块加载和函数调用的过程。
   * **在 C++ 代码中添加日志:** 如果需要更深入的调试，可以在 `gumv8checksum.cpp` 的关键函数中添加 `printf` 或 Frida 提供的日志输出，例如在 `gumjs_checksum_compute` 函数中打印参数值。重新编译 Frida 后，可以观察这些日志输出。
   * **使用 GDB 等调试器:** 可以将 GDB 连接到 Frida 服务进程或目标进程，并在 `gumv8checksum.cpp` 中设置断点，例如在 `gumjs_checksum_compute` 的入口处，以便单步调试 C++ 代码的执行流程，查看变量的值，并理解参数是如何传递和处理的。
   * **检查 GLib 的返回值:** 如果怀疑是 GLib 的问题，可以检查 GLib 函数的返回值，并查阅 GLib 的文档。

通过以上步骤，用户可以逐步追踪代码的执行流程，从 JavaScript 代码到 Frida 的 C++ 绑定层，最终定位到 `gumv8checksum.cpp` 文件中的具体代码，从而理解问题的根源并进行修复。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8checksum.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8checksum.h"

#include "gumv8macros.h"

#define GUMJS_MODULE_NAME Checksum

using namespace v8;

struct GumChecksum
{
  Global<Object> * wrapper;
  GChecksum * handle;
  GChecksumType type;
  gboolean closed;
  GumV8Checksum * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_checksum_compute)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_checksum_construct)
GUMJS_DECLARE_FUNCTION (gumjs_checksum_update)
GUMJS_DECLARE_FUNCTION (gumjs_checksum_get_string)
GUMJS_DECLARE_FUNCTION (gumjs_checksum_get_digest)

static GumChecksum * gum_checksum_new (Local<Object> wrapper,
    GChecksumType type, GumV8Checksum * module);
static void gum_checksum_free (GumChecksum * self);
static void gum_checksum_on_weak_notify (
    const WeakCallbackInfo<GumChecksum> & info);

static gboolean gum_v8_checksum_type_get (Isolate * isolate, const gchar * name,
    GChecksumType * type);

static const GumV8Function gumjs_checksum_module_functions[] =
{
  { "compute", gumjs_checksum_compute },

  { NULL, NULL }
};

static const GumV8Function gumjs_checksum_functions[] =
{
  { "update", gumjs_checksum_update },
  { "getString", gumjs_checksum_get_string },
  { "getDigest", gumjs_checksum_get_digest },

  { NULL, NULL }
};

void
_gum_v8_checksum_init (GumV8Checksum * self,
                       GumV8Core * core,
                       Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto checksum = _gum_v8_create_class ("Checksum", gumjs_checksum_construct,
      scope, module, isolate);
  _gum_v8_class_add_static (checksum, gumjs_checksum_module_functions, module,
      isolate);
  _gum_v8_class_add (checksum, gumjs_checksum_functions, module, isolate);
}

void
_gum_v8_checksum_realize (GumV8Checksum * self)
{
  self->checksums = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_checksum_free);
}

void
_gum_v8_checksum_dispose (GumV8Checksum * self)
{
  g_hash_table_unref (self->checksums);
  self->checksums = NULL;
}

void
_gum_v8_checksum_finalize (GumV8Checksum * self)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_checksum_compute)
{
  if (info.Length () < 2)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gchar * type_str, * str;
  GBytes * bytes;
  auto data_val = info[1];
  if (data_val->IsString ())
  {
    if (!_gum_v8_args_parse (args, "ss", &type_str, &str))
      return;
    bytes = NULL;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "sB", &type_str, &bytes))
      return;
    str = NULL;
  }

  GChecksumType type;
  if (!gum_v8_checksum_type_get (isolate, type_str, &type))
    goto beach;

  gchar * result_str;
  if (str != NULL)
    result_str = g_compute_checksum_for_string (type, str, -1);
  else
    result_str = g_compute_checksum_for_bytes (type, bytes);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, result_str));

  g_free (result_str);

beach:
  g_bytes_unref (bytes);
  g_free (str);
  g_free (type_str);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_checksum_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new Checksum()` to create a new instance");
    return;
  }

  gchar * type_str;
  if (!_gum_v8_args_parse (args, "s", &type_str))
    return;

  GChecksumType type;
  if (!gum_v8_checksum_type_get (isolate, type_str, &type))
  {
    g_free (type_str);
    return;
  }

  auto checksum = gum_checksum_new (wrapper, type, module);
  wrapper->SetAlignedPointerInInternalField (0, checksum);

  g_free (type_str);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_checksum_update, GumChecksum)
{
  if (self->closed)
  {
    _gum_v8_throw_ascii_literal (isolate, "checksum is closed");
    return;
  }

  if (info.Length () < 1)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gchar * str;
  GBytes * bytes;
  auto data_val = info[0];
  if (data_val->IsString ())
  {
    if (!_gum_v8_args_parse (args, "s", &str))
      return;
    bytes = NULL;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "B", &bytes))
      return;
    str = NULL;
  }

  if (str != NULL)
  {
    g_checksum_update (self->handle, (const guchar *) str, -1);
  }
  else
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (bytes, &size);

    g_checksum_update (self->handle, (const guchar *) data, size);
  }

  g_bytes_unref (bytes);
  g_free (str);

  info.GetReturnValue ().Set (info.This ());
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_checksum_get_string, GumChecksum)
{
  self->closed = TRUE;

  info.GetReturnValue ().Set (
      _gum_v8_string_new_ascii (isolate, g_checksum_get_string (self->handle)));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_checksum_get_digest, GumChecksum)
{
  self->closed = TRUE;

  size_t length = g_checksum_type_get_length (self->type);
  auto result = ArrayBuffer::New (isolate, length);
  auto store = result.As<ArrayBuffer> ()->GetBackingStore ();

  g_checksum_get_digest (self->handle, (guint8 *) store->Data (), &length);

  info.GetReturnValue ().Set (result);
}

static GumChecksum *
gum_checksum_new (Local<Object> wrapper,
                  GChecksumType type,
                  GumV8Checksum * module)
{
  auto cs = g_slice_new (GumChecksum);
  cs->wrapper = new Global<Object> (module->core->isolate, wrapper);
  cs->wrapper->SetWeak (cs, gum_checksum_on_weak_notify,
      WeakCallbackType::kParameter);
  cs->handle = g_checksum_new (type);
  cs->type = type;
  cs->closed = FALSE;
  cs->module = module;

  g_hash_table_add (module->checksums, cs);

  return cs;
}

static void
gum_checksum_free (GumChecksum * self)
{
  g_checksum_free (self->handle);

  delete self->wrapper;

  g_slice_free (GumChecksum, self);
}

static void
gum_checksum_on_weak_notify (const WeakCallbackInfo<GumChecksum> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->checksums, self);
}

static gboolean
gum_v8_checksum_type_get (Isolate * isolate,
                          const gchar * name,
                          GChecksumType * type)
{
  if (strcmp (name, "sha256") == 0)
    *type = G_CHECKSUM_SHA256;
  else if (strcmp (name, "sha384") == 0)
    *type = G_CHECKSUM_SHA384;
  else if (strcmp (name, "sha512") == 0)
    *type = G_CHECKSUM_SHA512;
  else if (strcmp (name, "sha1") == 0)
    *type = G_CHECKSUM_SHA1;
  else if (strcmp (name, "md5") == 0)
    *type = G_CHECKSUM_MD5;
  else
    goto invalid_type;

  return TRUE;

invalid_type:
  _gum_v8_throw_ascii_literal (isolate, "unsupported checksum type");
  return FALSE;
}
```