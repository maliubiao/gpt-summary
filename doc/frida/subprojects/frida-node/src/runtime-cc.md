Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a functional breakdown of the `runtime.cc` file in Frida, specifically highlighting its relevance to reverse engineering, low-level concepts, logical reasoning (with examples), common user errors, and how a user might reach this code.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the code, looking for familiar keywords and patterns related to system interaction, data conversion, and Frida's architecture. Keywords like `UVContext`, `GLibContext`, `g_hash_table`, `JSON`, `GVariant`, `GSocketAddress`, `GTlsCertificate`, `node::Buffer`, and `Nan` stood out. These hinted at the core functionalities.

3. **Identify Major Functional Areas:**  Based on the keywords and function names, I started grouping functionalities:
    * **Initialization and Teardown:** The constructor and destructor handle resource allocation and deallocation (`uv_context_`, `glib_context_`, `data_`).
    * **Data Storage:** `GetDataPointer` and `SetDataPointer` suggest a mechanism for storing arbitrary data associated with identifiers.
    * **JSON Conversion:** `ValueToJson` and `ValueFromJson` handle serialization and deserialization between V8 values (JavaScript objects) and JSON strings.
    * **Date/Time Conversion:** `ValueFromDatetime` converts ISO 8601 strings to JavaScript `Date` objects.
    * **String Array Conversion:** `ValueToStrv` and `ValueFromStrv` handle conversion between JavaScript arrays of strings and C-style string arrays (`char**`).
    * **Environment Variable Conversion:** `ValueToEnvp` and `ValueFromEnvp` handle conversion between JavaScript objects representing environment variables and C-style environment arrays.
    * **Enum Conversion:** `ValueToEnum` and `ValueFromEnum` handle conversion between JavaScript strings and C enums.
    * **GVariant Conversion:**  A significant portion of the code deals with `ValueToVariant` and `ValueFromVariant`, enabling conversion between JavaScript values and GLib's `GVariant` type, which is crucial for inter-process communication in the GLib/GIO ecosystem.
    * **Socket Address Conversion:** `ValueFromSocketAddress` converts `GSocketAddress` to JavaScript objects, providing network information.
    * **Certificate Conversion:** `ValueToCertificate` converts JavaScript strings (representing PEM or file paths) to `GTlsCertificate` objects.
    * **Utility Functions:** `ClassNameFromC` and `ParameterNameFromC` handle string manipulation for naming conventions.

4. **Relate to Reverse Engineering:**  I considered how each functional area relates to reverse engineering tasks:
    * **Interception and Data Manipulation:**  The ability to convert data between JavaScript and native types is fundamental for intercepting function calls, inspecting arguments, modifying return values, and interacting with native libraries.
    * **Understanding System Calls:**  Accessing socket information (`ValueFromSocketAddress`) helps in understanding network activity.
    * **Working with Libraries:**  `GVariant` conversion is essential for interacting with GLib-based libraries, common on Linux and used by Android's framework.
    * **Security Analysis:** Handling certificates (`ValueToCertificate`) is relevant to intercepting and analyzing secure communication.

5. **Identify Low-Level Concepts:** I looked for code that directly interacts with operating system primitives or low-level libraries:
    * **Pointers:** Direct manipulation of pointers (`void*`, `gpointer`).
    * **Memory Management:** Use of `g_new0`, `g_strdup`, `g_free`, `g_memdup2`.
    * **Operating System Structures:** Interaction with `GSocketAddress`, which represents network socket information.
    * **GLib/GIO:** The heavy reliance on GLib's data structures and functions (like `GHashTable`, `GVariant`, `GDateTime`).

6. **Construct Logical Reasoning Examples:**  For areas involving data conversion, I devised simple input and output examples to illustrate the transformations. This helps demonstrate how data is marshalled between JavaScript and the native environment.

7. **Consider Common User Errors:** I thought about common mistakes developers might make when using Frida's API, particularly related to type mismatches or incorrect data formatting.

8. **Trace User Interaction (Debugging):** I outlined a typical Frida workflow that would lead to the execution of code within `runtime.cc`. This involves attaching to a process, injecting JavaScript, and the JavaScript interacting with Frida's bridge to call native functions.

9. **Structure the Answer:** I organized the information into logical sections based on the prompt's requirements: functions, reverse engineering relevance, low-level concepts, logical reasoning, user errors, and the debugging pathway. I used clear headings and bullet points for readability.

10. **Refine and Elaborate:** I reviewed my initial draft, adding more details and explanations where necessary. For instance, I elaborated on the significance of `GVariant` in the Android context and provided more specific examples of how reverse engineers might use the various functions. I also ensured that the examples were concrete and easy to understand.

By following this systematic approach, I could comprehensively address all aspects of the request and provide a well-structured and informative answer. The key was to break down the code into its core functionalities, understand its purpose within the Frida ecosystem, and then relate those functionalities to the specific areas highlighted in the prompt.
这是一个名为 `runtime.cc` 的 C++ 源代码文件，属于 Frida 这个动态 instrumentation 工具的 frida-node 子项目。它的主要职责是 **在 Frida 的 JavaScript 运行时环境和底层的 C++ 代码之间建立桥梁，负责数据类型的转换和上下文管理**。

以下是它的功能详细列表，并根据要求进行了分类说明：

**主要功能：**

1. **上下文管理:**
   - `Runtime(UVContext* uv_context, GLibContext* glib_context)`: 构造函数，接收 `UVContext` 和 `GLibContext` 指针。`UVContext` 通常用于处理异步 I/O 操作，而 `GLibContext` 用于处理 GLib 的主循环和相关功能。这表明该运行时环境依赖于 libuv 和 GLib 库。
   - `~Runtime()`: 析构函数，负责释放资源，包括 `json_module_`, `json_stringify_`, `json_parse_` 的资源，以及 `g_hash_table_unref(data_)`，并删除 `glib_context_` 和 `uv_context_`。
   - `GetUVContext() const`: 返回 `UVContext` 指针。
   - `GetGLibContext() const`: 返回 `GLibContext` 指针。

2. **数据存储:**
   - `GetDataPointer(const char* id)`: 根据 ID 获取存储的任意类型数据的指针。
   - `SetDataPointer(const char* id, void* value)`: 根据 ID 存储任意类型数据的指针。这提供了一种在 JavaScript 和 C++ 之间共享数据的机制。

3. **JSON 数据转换:**
   - `ValueToJson(Local<Value> value)`: 将 V8 (JavaScript) 的 `Value` 对象转换为 JSON 字符串。
   - `ValueFromJson(Local<String> json)`: 将 JSON 字符串转换为 V8 的 `Value` 对象。这使得 JavaScript 和 C++ 之间可以方便地传递结构化数据。

4. **日期时间转换:**
   - `ValueFromDatetime(const char* iso8601_text)`: 将 ISO 8601 格式的日期时间字符串转换为 JavaScript 的 `Date` 对象。

5. **字符串数组转换:**
   - `ValueToStrv(Local<Value> value, gchar*** strv, gint* length)`: 将 JavaScript 的字符串数组转换为 C 风格的字符串数组 (`gchar**`)。
   - `ValueFromStrv(gchar* const* strv, gint length)`: 将 C 风格的字符串数组转换为 JavaScript 的字符串数组。

6. **环境变量转换:**
   - `ValueToEnvp(Local<Value> value, gchar*** envp, gint* length)`: 将 JavaScript 的对象 (键值对) 转换为 C 风格的环境变量数组 (`gchar**`)。
   - `ValueFromEnvp(gchar* const* envp, gint length)`: 将 C 风格的环境变量数组转换为 JavaScript 的对象。

7. **枚举类型转换:**
   - `ValueToEnum(Local<Value> value, GType type, gpointer result)`: 将 JavaScript 的字符串转换为 GLib 的枚举类型。
   - `ValueFromEnum(gint value, GType type)`: 将 GLib 的枚举类型值转换为 JavaScript 的字符串。

8. **GVariant 数据转换:**
   - `ValueFromParametersDict(GHashTable* dict)`: 将 GLib 的哈希表 (`GHashTable`) 转换为 JavaScript 的对象。
   - `ValueToVariant(Local<Value> value)`: 将 JavaScript 的 `Value` 对象转换为 GLib 的 `GVariant`。`GVariant` 是一种通用的序列化类型，常用于进程间通信。
   - `ValueFromVariant(GVariant* v)`: 将 GLib 的 `GVariant` 转换为 JavaScript 的 `Value` 对象。
   - `ValueFromVariantByteArray(GVariant* v)`: 将 `GVariant` 中的字节数组转换为 JavaScript 的 `Buffer` 对象。
   - `ValueFromVariantDict(GVariant* v)`: 将 `GVariant` 字典转换为 JavaScript 的对象。
   - `ValueFromVariantArray(GVariant* v)`: 将 `GVariant` 数组转换为 JavaScript 的数组。

9. **Socket 地址转换:**
   - `ValueFromSocketAddress(GSocketAddress* address)`: 将 GLib 的 `GSocketAddress` 对象转换为 JavaScript 的对象，包含地址族、地址和端口等信息。

10. **TLS 证书转换:**
    - `ValueToCertificate(Local<Value> value, GTlsCertificate** certificate)`: 将 JavaScript 字符串 (PEM 格式或文件路径) 转换为 GLib 的 `GTlsCertificate` 对象。

11. **工具函数:**
    - `ClassNameFromC(const char* cname)`: 从 C++ 类名中提取更简洁的名称（去除 "Frida" 前缀）。
    - `ParameterNameFromC(const char* cname)`: 将 C 风格的参数名 (例如 "some-parameter") 转换为 JavaScript 风格的驼峰命名 (例如 "someParameter")。

**与逆向方法的关联及举例说明：**

这个文件在 Frida 的逆向工程中扮演着至关重要的角色，因为它负责了 JavaScript 脚本和目标进程内部 C/C++ 代码之间的数据交换。逆向工程师通常使用 Frida 的 JavaScript API 来 hook (拦截) 目标进程的函数调用，检查和修改参数，以及修改函数的返回值。`runtime.cc` 提供的类型转换功能使得这些操作成为可能。

**举例说明：**

假设你要 hook 一个 native 函数 `int calculateSum(int a, int b)`，并想在 JavaScript 中查看和修改它的参数。

1. **Hooking:** 你会使用 Frida 的 JavaScript API 来 hook 这个函数：
   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'calculateSum'), {
     onEnter: function(args) {
       console.log("calculateSum called with arguments:", args[0], args[1]);
       // 修改参数 a
       args[0] = ptr(10);
     },
     onLeave: function(retval) {
       console.log("calculateSum returned:", retval);
       // 修改返回值
       retval.replace(20);
     }
   });
   ```

2. **数据转换:** 当 `calculateSum` 被调用时，`runtime.cc` 中的 `ValueToVariant` 会将 JavaScript 中的数字 `10` 转换为 `GVariant`，以便传递给 native 代码。同样，当函数返回时，`ValueFromVariant` 会将 native 返回的整数转换为 JavaScript 的 `Number` 对象。

3. **更复杂的例子：Hook 接收结构体的函数**

   如果 native 函数接收一个结构体指针，例如 `void processData(Data* data)`，其中 `Data` 结构体包含多个字段。你可能需要在 JavaScript 中创建一个对应的对象，然后让 Frida 将其转换为 native 代码可以理解的内存布局。`ValueToVariant` 可以处理将 JavaScript 对象转换为 `GVariant`，如果结构体比较复杂，可能需要结合 Frida 的 `Memory` API 进行更精细的操作。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

这个文件直接或间接地涉及到这些底层知识：

1. **二进制底层:**
   - **内存管理:** 使用 `g_new0`, `g_strdup`, `g_free`, `g_memdup2` 等 GLib 提供的内存管理函数，这些函数最终会调用底层的 `malloc` 和 `free`。
   - **数据表示:**  处理 C 风格的字符串数组 (`gchar**`) 和指针 (`void*`)，这些都是与二进制内存布局直接相关的概念。
   - **Buffer 对象:**  与 Node.js 的 `Buffer` 对象交互，代表原始的二进制数据。

2. **Linux 操作系统:**
   - **环境变量:**  `ValueToEnvp` 和 `ValueFromEnvp` 涉及到 Linux 进程的环境变量概念。
   - **Socket 编程:** `ValueFromSocketAddress` 处理 `GSocketAddress`，这是 Linux 中网络编程的基础。它能够识别 IPv4、IPv6 和 Unix 域套接字地址。
   - **文件路径:**  `ValueToCertificate` 可以接受文件路径作为参数，这是 Linux 文件系统操作的一部分。

3. **Android 内核及框架:**
   - **GLib/GIO:** Android 的某些部分（尤其是系统服务和框架层）使用了 GLib 库。`GVariant` 是 GLib 中用于序列化数据的关键类型，广泛应用于 Binder IPC (进程间通信)。`runtime.cc` 中大量的 `GVariant` 转换代码表明 Frida 在 Android 上的应用非常广泛，需要与 Android 框架进行交互。
   - **Binder IPC:**  Frida 经常被用于 hook Android 系统服务，这些服务之间通常使用 Binder 进行通信，而 `GVariant` 是 Binder 传递数据的一种常见方式。

**逻辑推理的假设输入与输出举例：**

1. **`ValueToJson` 假设：**
   - **输入 (JavaScript):**  `{ name: "Frida", version: 16.0 }`
   - **输出 (JSON 字符串):**  `"{\"name\":\"Frida\",\"version\":16}"`

2. **`ValueFromDatetime` 假设：**
   - **输入 (ISO 8601 字符串):**  `"2023-10-27T10:00:00Z"`
   - **输出 (JavaScript Date 对象):**  一个表示 2023 年 10 月 27 日 10:00:00 UTC 的 `Date` 对象。

3. **`ValueToStrv` 假设：**
   - **输入 (JavaScript 数组):**  `["hello", "frida"]`
   - **输出 (C 风格字符串数组):**  一个包含两个字符串 "hello" 和 "frida" 的 `gchar**` 指针，以及长度 `2`。

4. **`ValueToEnum` 假设：**
   - **假设存在一个名为 `MyEnum` 的 GLib 枚举类型，包含 `VALUE1` 和 `VALUE2`。**
   - **输入 (JavaScript 字符串):**  `"value1"` (或 `"VALUE1"`)
   - **输出 (C 枚举值):**  `MyEnum` 中 `VALUE1` 对应的整数值。

**用户或编程常见的使用错误举例说明：**

1. **类型不匹配:**  在 JavaScript 中传递了错误类型的数据，导致 C++ 代码无法正确转换。
   - **错误示例:**  JavaScript 代码尝试将一个数字传递给一个期望字符串的 native 函数参数，但 `ValueToVariant` 或其他转换函数无法处理。
   - **Frida 错误提示:** 可能会抛出 `TypeError: Bad argument, expected a string` 或类似的错误。

2. **JSON 格式错误:**  在使用 `ValueFromJson` 时提供了格式错误的 JSON 字符串。
   - **错误示例:**  `Runtime.ValueFromJson("{name: 'Frida'}")` (缺少双引号)。
   - **Frida 错误提示:**  V8 的 JSON 解析器会抛出错误，例如 `SyntaxError: Unexpected token n in JSON at position 1`。

3. **枚举值错误:**  在使用 `ValueToEnum` 时提供了不存在的枚举字符串。
   - **错误示例:**  假设枚举类型只有 `RED` 和 `BLUE`，但 JavaScript 传递了 `"GREEN"`。
   - **Frida 错误提示:**  `TypeError: Enum type MyEnum does not have a value named 'GREEN', it only has: 'red', 'blue'`。

4. **忘记释放内存:**  如果用户在 C++ 侧通过 `GetDataPointer` 获取了指针，但忘记在 JavaScript 侧配合进行资源释放，可能导致内存泄漏。虽然 `runtime.cc` 本身负责内部资源的释放，但用户自定义的数据需要用户自己管理。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 Frida JavaScript 脚本:** 用户首先编写一个 JavaScript 脚本，使用 Frida 的 API 来与目标进程交互。这可能包括 `Interceptor.attach` 来 hook 函数，或者使用 `NativeFunction` 调用 native 函数。

2. **加载脚本并附加到进程:** 用户使用 Frida 的命令行工具 (`frida`, `frida-ps`, `frida -p <pid> -l script.js`) 或通过编程方式 (例如使用 Python 的 `frida` 库) 将脚本加载到目标进程中。

3. **JavaScript 代码执行:** 当目标进程执行到被 hook 的函数，或者 JavaScript 代码显式调用了 native 函数时，Frida 的 JavaScript 运行时环境开始工作。

4. **数据类型转换:**
   - **从 JavaScript 到 Native:** 当 JavaScript 代码需要将数据传递给 native 函数时，例如在 `onEnter` 回调中修改参数，或者通过 `NativeFunction` 传递参数，`runtime.cc` 中的 `ValueToXxx` 函数（例如 `ValueToVariant`, `ValueToStrv`）会被调用，将 JavaScript 的 `Value` 对象转换为 C++ 可以理解的数据类型。
   - **从 Native 到 JavaScript:** 当 native 函数返回结果，需要在 JavaScript 的 `onLeave` 回调中访问，或者 `NativeFunction` 调用返回结果时，`runtime.cc` 中的 `ValueFromXxx` 函数会被调用，将 C++ 的数据类型转换为 JavaScript 的 `Value` 对象。

5. **错误发生和调试:** 如果在数据转换过程中出现类型不匹配或其他错误，`runtime.cc` 中的代码会抛出异常 (通常是 `Nan::ThrowTypeError` 或 `Nan::ThrowError`)，这些异常会被传递回 Frida 的 JavaScript 运行时环境，最终可能导致 JavaScript 脚本执行失败并输出错误信息。

**调试线索：**

- **查看 Frida 的控制台输出:**  Frida 通常会将错误信息打印到控制台，这些信息可能包含 `TypeError` 或其他异常类型，以及相关的错误描述，这有助于定位问题。
- **使用 `console.log` 在 JavaScript 脚本中打印变量类型和值:**  在 JavaScript 代码中，可以使用 `console.log(typeof variable, variable)` 来检查变量的类型和值，确保传递给 native 代码的数据是符合预期的。
- **理解 `runtime.cc` 中的类型转换逻辑:**  当遇到类型转换相关的错误时，理解 `runtime.cc` 中各种 `ValueToXxx` 和 `ValueFromXxx` 函数的实现原理，可以帮助你分析为什么转换失败。例如，如果期望传递一个字节数组，你需要确保在 JavaScript 中传递的是一个 `Buffer` 对象。
- **检查 GLib 的类型系统:**  对于涉及到 `GVariant` 或枚举类型转换的错误，需要理解 GLib 的类型系统和 `GVariant` 的格式，确保 JavaScript 代码传递的数据能够正确映射到 `GVariant` 的类型。

总而言之，`runtime.cc` 是 Frida 实现动态 instrumentation 的关键组成部分，它通过高效的数据类型转换，使得 JavaScript 脚本能够无缝地与目标进程的 native 代码进行交互，为逆向工程师提供了强大的能力。理解其功能和工作原理对于有效地使用 Frida 进行逆向分析至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-node/src/runtime.cc的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "runtime.h"

#include <cstring>
#include <nan.h>
#ifdef G_OS_UNIX
# include <gio/gunixsocketaddress.h>
#endif

using std::strchr;
using v8::Array;
using v8::Boolean;
using v8::Date;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Symbol;
using v8::Value;

namespace frida {

Runtime::Runtime(UVContext* uv_context, GLibContext* glib_context)
  : uv_context_(uv_context),
    glib_context_(glib_context),
    data_(g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL)) {
  auto isolate = Isolate::GetCurrent();
  auto global = isolate->GetCurrentContext()->Global();
  auto json_module = Local<Object>::Cast(
      Nan::Get(global, Nan::New("JSON").ToLocalChecked()).ToLocalChecked());
  auto json_stringify = Local<Function>::Cast(
      Nan::Get(json_module,
        Nan::New("stringify").ToLocalChecked()).ToLocalChecked());
  auto json_parse = Local<Function>::Cast(
      Nan::Get(json_module,
        Nan::New("parse").ToLocalChecked()).ToLocalChecked());
  json_module_.Reset(isolate, json_module);
  json_stringify_.Reset(isolate, json_stringify);
  json_parse_.Reset(isolate, json_parse);
}

Runtime::~Runtime() {
  json_parse_.Reset();
  json_stringify_.Reset();
  json_module_.Reset();

  g_hash_table_unref(data_);

  delete glib_context_;
  delete uv_context_;
}

UVContext* Runtime::GetUVContext() const {
  return uv_context_;
}

GLibContext* Runtime::GetGLibContext() const {
  return glib_context_;
}

void* Runtime::GetDataPointer(const char* id) {
  return g_hash_table_lookup(data_, id);
}

void Runtime::SetDataPointer(const char* id, void* value) {
  g_hash_table_insert(data_, const_cast<char*>(id), value);
}

Local<String> Runtime::ValueToJson(Local<Value> value) {
  auto context = Isolate::GetCurrent()->GetCurrentContext();
  auto module = Nan::New<Object>(json_module_);
  auto stringify = Nan::New<Function>(json_stringify_);
  Local<Value> argv[] = { value };
  return Local<String>::Cast(
      stringify->Call(context, module, 1, argv).ToLocalChecked());
}

Local<Value> Runtime::ValueFromJson(Local<String> json) {
  auto context = Isolate::GetCurrent()->GetCurrentContext();
  auto module = Nan::New<Object>(json_module_);
  auto parse = Nan::New<Function>(json_parse_);
  Local<Value> argv[] = { json };
  return parse->Call(context, module, 1, argv).ToLocalChecked();
}

Local<Value> Runtime::ValueFromDatetime(const char* iso8601_text) {
  GDateTime* dt = g_date_time_new_from_iso8601(iso8601_text, NULL);
  if (dt == NULL)
    return Nan::Null();

  double unix_msec = static_cast<double>(g_date_time_to_unix(dt) * 1000) +
      (static_cast<double>(g_date_time_get_microsecond(dt)) / 1000.0);
  Local<Date> result = Nan::New<Date>(unix_msec).ToLocalChecked();

  g_date_time_unref(dt);

  return result;
}

bool Runtime::ValueToStrv(Local<Value> value, gchar*** strv, gint* length) {
  if (!value->IsArray()) {
    Nan::ThrowTypeError("Bad argument, expected an array of strings");
    return false;
  }
  auto array = Local<Array>::Cast(value);

  uint32_t n = array->Length();
  gchar** elements = g_new0(gchar*, n + 1);

  for (uint32_t i = 0; i != n; i++) {
    auto element_value = Nan::Get(array, i).ToLocalChecked();
    if (!element_value->IsString()) {
      g_strfreev(elements);
      Nan::ThrowTypeError("Bad argument, expected an array of strings only");
      return false;
    }

    Nan::Utf8String element(element_value);
    elements[i] = g_strdup(*element);
  }

  *strv = elements;
  *length = n;

  return true;
}

Local<Value> Runtime::ValueFromStrv(gchar* const* strv, gint length) {
  if (strv == NULL)
    return Nan::Null();

  auto result = Nan::New<Array>(length);
  for (gint i = 0; i != length; i++)
    Nan::Set(result, i, Nan::New(strv[i]).ToLocalChecked());
  return result;
}

bool Runtime::ValueToEnvp(Local<Value> value, gchar*** envp, gint* length) {
  auto isolate = Isolate::GetCurrent();
  auto context = isolate->GetCurrentContext();

  if (!value->IsObject()) {
    Nan::ThrowTypeError("Bad argument, expected an object");
    return false;
  }
  auto object = Local<Object>::Cast(value);

  Local<Array> names(object->GetOwnPropertyNames(context).ToLocalChecked());
  uint32_t n = names->Length();

  gchar** elements = g_new0(gchar*, n + 1);

  for (uint32_t i = 0; i != n; i++) {
    auto name = Nan::Get(names, i).ToLocalChecked();
    auto value = Nan::Get(object, name).ToLocalChecked();

    Nan::Utf8String name_str(name);
    Nan::Utf8String value_str(value);
    elements[i] = g_strconcat(*name_str, "=", *value_str, NULL);
  }

  *envp = elements;
  *length = n;

  return true;
}

Local<Value> Runtime::ValueFromEnvp(gchar* const* envp, gint length) {
  if (envp == NULL)
    return Nan::Null();

  auto result = Nan::New<Object>();
  for (gint i = 0; i != length; i++) {
    auto tokens = g_strsplit(envp[i], "=", 2);
    if (g_strv_length(tokens) == 2) {
      Nan::Set(result, Nan::New(tokens[0]).ToLocalChecked(),
          Nan::New(tokens[1]).ToLocalChecked());
    }
    g_strfreev(tokens);
  }
  return result;
}

bool Runtime::ValueToEnum(Local<Value> value, GType type, gpointer result) {
  if (!value->IsString()) {
    Nan::ThrowTypeError("Bad argument, expected a string");
    return false;
  }
  Nan::Utf8String str(value);

  bool success = false;

  auto enum_class = static_cast<GEnumClass*>(g_type_class_ref(type));

  auto enum_value = g_enum_get_value_by_nick(enum_class, *str);
  if (enum_value != NULL) {
    *((gint*) result) = enum_value->value;

    success = true;
  } else {
    auto message = g_string_sized_new(128);

    g_string_append_printf(message,
        "Enum type %s does not have a value named '%s', it only has: ",
        ClassNameFromC(g_type_name(type)), *str);

    for (guint i = 0; i != enum_class->n_values; i++) {
      if (i != 0)
        g_string_append(message, ", ");
      g_string_append_c(message, '\'');
      g_string_append(message, enum_class->values[i].value_nick);
      g_string_append_c(message, '\'');
    }

    Nan::ThrowTypeError(message->str);

    g_string_free(message, TRUE);
  }

  g_type_class_unref(enum_class);

  return success;
}

Local<String> Runtime::ValueFromEnum(gint value, GType type) {
  auto enum_class = static_cast<GEnumClass*>(g_type_class_ref(type));
  auto result = Nan::New(g_enum_get_value(enum_class, value)->value_nick)
      .ToLocalChecked();
  g_type_class_unref(enum_class);
  return result;
}

Local<Value> Runtime::ValueFromParametersDict(GHashTable* dict) {
  auto result = Nan::New<Object>();

  GHashTableIter iter;
  gpointer raw_key, raw_value;

  g_hash_table_iter_init(&iter, dict);

  while (g_hash_table_iter_next(&iter, &raw_key, &raw_value)) {
    char* canonicalized_key = ParameterNameFromC(static_cast<char*>(raw_key));

    Local<String> key = Nan::New(canonicalized_key).ToLocalChecked();
    Local<Value> value = ValueFromVariant(static_cast<GVariant*>(raw_value));
    Nan::Set(result, key, value);

    g_free(canonicalized_key);
  }

  return result;
}

GVariant* Runtime::ValueToVariant(Local<Value> value) {
  if (value->IsString()) {
    Nan::Utf8String str(value);
    return g_variant_new_string(*str);
  }

  if (value->IsNumber()) {
    return g_variant_new_int64(
        static_cast<gint64>(Local<Number>::Cast(value)->Value()));
  }

  if (value->IsBoolean()) {
    return g_variant_new_boolean(Local<Boolean>::Cast(value)->Value());
  }

  if (node::Buffer::HasInstance(value)) {
    auto size = node::Buffer::Length(value);
    auto copy = g_memdup2(node::Buffer::Data(value), size);
    return g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING, copy, size, TRUE,
        g_free, copy);
  }

  if (value->IsArray()) {
    auto array = Local<Array>::Cast(value);
    uint32_t n = array->Length();
    if (n == 2) {
      auto first = Nan::Get(array, 0).ToLocalChecked();
      if (first->IsSymbol()) {
        auto sym = first.As<Symbol>();
        auto desc = sym->Description(
#if V8_MAJOR_VERSION > 9 || (V8_MAJOR_VERSION == 9 && V8_MINOR_VERSION >= 5)
            Isolate::GetCurrent()
#endif
        );
        Nan::Utf8String type(desc);

        auto val = ValueToVariant(Nan::Get(array, 1).ToLocalChecked());
        if (val == NULL) {
          return NULL;
        }

        GVariant* t[2] = { g_variant_new_string(*type), val };
        return g_variant_new_tuple(t, G_N_ELEMENTS(t));
      }
    }

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE ("av"));

    for (uint32_t i = 0; i != n; i++) {
      auto v = ValueToVariant(Nan::Get(array, i).ToLocalChecked());
      if (v == NULL) {
        g_variant_builder_clear(&builder);
        return NULL;
      }
      g_variant_builder_add(&builder, "v", v);
    }

    return g_variant_builder_end(&builder);
  }

  if (value->IsObject()) {
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    auto isolate = Isolate::GetCurrent();
    auto context = isolate->GetCurrentContext();

    auto object = Local<Object>::Cast(value);

    Local<Array> names(object->GetOwnPropertyNames(context).ToLocalChecked());
    uint32_t n = names->Length();

    for (uint32_t i = 0; i != n; i++) {
      auto key = Nan::Get(names, i).ToLocalChecked();
      auto val = Nan::Get(object, key).ToLocalChecked();
      if (val->IsUndefined()) {
        continue;
      }

      Nan::Utf8String k(key);

      auto v = ValueToVariant(val);
      if (v == NULL) {
        g_variant_builder_clear(&builder);
        return NULL;
      }

      g_variant_builder_add(&builder, "{sv}", *k, v);
    }

    return g_variant_builder_end(&builder);
  }

  Nan::ThrowTypeError("Bad argument, expected value serializable to GVariant");
  return NULL;
}

Local<Value> Runtime::ValueFromVariant(GVariant* v) {
  switch (g_variant_classify(v)) {
    case G_VARIANT_CLASS_STRING:
      return Nan::New<String>(g_variant_get_string(v, NULL)).ToLocalChecked();
    case G_VARIANT_CLASS_INT64:
      return Nan::New<Number>(static_cast<double>(g_variant_get_int64(v)));
    case G_VARIANT_CLASS_UINT64:
      return Nan::New<Number>(static_cast<double>(g_variant_get_uint64(v)));
    case G_VARIANT_CLASS_DOUBLE:
      return Nan::New<Number>(static_cast<double>(g_variant_get_double(v)));
    case G_VARIANT_CLASS_BOOLEAN:
      return Nan::New<Boolean>(static_cast<bool>(g_variant_get_boolean(v)));
    case G_VARIANT_CLASS_ARRAY:
      if (g_variant_is_of_type(v, G_VARIANT_TYPE("ay"))) {
        return ValueFromVariantByteArray(v);
      }

      if (g_variant_is_of_type(v, G_VARIANT_TYPE_VARDICT)) {
        return ValueFromVariantDict(v);
      }

      if (g_variant_is_of_type(v, G_VARIANT_TYPE_ARRAY)) {
        return ValueFromVariantArray(v);
      }

      break;
    case G_VARIANT_CLASS_TUPLE:
      return Nan::Undefined();
    default:
      break;
  }

  return Nan::Null();
}

Local<Value> Runtime::ValueFromVariantByteArray(GVariant* v) {
  gsize size;
  gconstpointer data = g_variant_get_fixed_array(v, &size, sizeof(guint8));

  return Nan::CopyBuffer(static_cast<const char*>(data), size).ToLocalChecked();
}

Local<Value> Runtime::ValueFromVariantDict(GVariant* v) {
  auto dict = Nan::New<Object>();

  GVariantIter iter;
  gchar* raw_key;
  GVariant* raw_value;

  g_variant_iter_init(&iter, v);

  while (g_variant_iter_next(&iter, "{sv}", &raw_key, &raw_value)) {
    char* canonicalized_key = ParameterNameFromC(raw_key);

    Local<String> key = Nan::New(canonicalized_key).ToLocalChecked();
    Local<Value> value = ValueFromVariant(raw_value);
    Nan::Set(dict, key, value);

    g_free(canonicalized_key);
    g_variant_unref(raw_value);
    g_free(raw_key);
  }

  return dict;
}

Local<Value> Runtime::ValueFromVariantArray(GVariant* v) {
  GVariantIter iter;
  g_variant_iter_init(&iter, v);

  auto array = Nan::New<Array>(g_variant_iter_n_children(&iter));

  GVariant* child;
  for (int i = 0; (child = g_variant_iter_next_value(&iter)) != NULL; i++) {
    if (g_variant_is_of_type(child, G_VARIANT_TYPE_VARIANT)) {
      GVariant* inner = g_variant_get_variant(child);
      g_variant_unref(child);
      child = inner;
    }
    Nan::Set(array, i, ValueFromVariant(child));
    g_variant_unref(child);
  }

  return array;
}

Local<Object> Runtime::ValueFromSocketAddress(GSocketAddress* address) {
  auto result = Nan::New<Object>();

  if (G_IS_INET_SOCKET_ADDRESS(address)) {
    GSocketFamily family = g_socket_address_get_family(address);
    GInetSocketAddress* sa = G_INET_SOCKET_ADDRESS(address);

    Nan::Set(result,
        Nan::New("family").ToLocalChecked(),
        Nan::New((family == G_SOCKET_FAMILY_IPV6) ? "ipv6" : "ipv4")
        .ToLocalChecked());

    gchar* host = g_inet_address_to_string(
        g_inet_socket_address_get_address(sa));
    Nan::Set(result,
        Nan::New("address").ToLocalChecked(),
        Nan::New(host).ToLocalChecked());
    g_free(host);

    Nan::Set(result, Nan::New("port").ToLocalChecked(),
        Nan::New(static_cast<uint32_t>(g_inet_socket_address_get_port(sa))));

    if (family == G_SOCKET_FAMILY_IPV6) {
      Nan::Set(result,
          Nan::New("flowlabel").ToLocalChecked(),
          Nan::New(g_inet_socket_address_get_flowinfo(sa)));
      Nan::Set(result,
          Nan::New("scopeid").ToLocalChecked(),
          Nan::New(g_inet_socket_address_get_scope_id(sa)));
    }
  }

#ifdef G_OS_UNIX
  if (G_IS_UNIX_SOCKET_ADDRESS(address)) {
    GUnixSocketAddress* sa = G_UNIX_SOCKET_ADDRESS(address);

    switch (g_unix_socket_address_get_address_type(sa)) {
      case G_UNIX_SOCKET_ADDRESS_ANONYMOUS: {
        Nan::Set(result,
            Nan::New("family").ToLocalChecked(),
            Nan::New("unix:anonymous").ToLocalChecked());

        break;
      }
      case G_UNIX_SOCKET_ADDRESS_PATH: {
        Nan::Set(result,
            Nan::New("family").ToLocalChecked(),
            Nan::New("unix:path").ToLocalChecked());

        gchar* path = g_filename_to_utf8(g_unix_socket_address_get_path(sa), -1,
            NULL, NULL, NULL);
        Nan::Set(result,
            Nan::New("path").ToLocalChecked(),
            Nan::New(path).ToLocalChecked());
        g_free(path);

        break;
      }
      case G_UNIX_SOCKET_ADDRESS_ABSTRACT:
      case G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED: {
        Nan::Set(result,
            Nan::New("family").ToLocalChecked(),
            Nan::New("unix:abstract").ToLocalChecked());

        Nan::Set(result,
            Nan::New("path").ToLocalChecked(),
            Nan::CopyBuffer(
                g_unix_socket_address_get_path(sa),
                g_unix_socket_address_get_path_len(sa)).ToLocalChecked());

        break;
      }
      default:
        break;
    }
  }
#endif

  return result;
}

bool Runtime::ValueToCertificate(Local<Value> value,
    GTlsCertificate** certificate) {
  if (!value->IsString()) {
    Nan::ThrowTypeError("Bad argument, expected a string");
    return false;
  }
  Nan::Utf8String str(value);
  const char* cstr = *str;

  GError* error = NULL;
  if (strchr(cstr, '\n') != NULL)
    *certificate = g_tls_certificate_new_from_pem(cstr, -1, &error);
  else
    *certificate = g_tls_certificate_new_from_file(cstr, &error);

  if (error != NULL) {
    Nan::ThrowError(Nan::Error(error->message));
    g_error_free(error);
    return false;
  }

  return true;
}

const char* Runtime::ClassNameFromC(const char* cname) {
  if (g_str_has_prefix(cname, "Frida"))
    return cname + 5;

  return cname;
}

char* Runtime::ParameterNameFromC(const char* cname) {
  auto name = g_string_new("");

  bool need_uppercase = false;
  for (const char* cursor = cname; *cursor != '\0'; cursor++) {
    char ch = *cursor;
    if (ch == '-') {
      need_uppercase = true;
    } else {
      g_string_append_c(name, need_uppercase ? g_ascii_toupper(ch) : ch);
      need_uppercase = false;
    }
  }

  return g_string_free(name, FALSE);
}

}

"""

```