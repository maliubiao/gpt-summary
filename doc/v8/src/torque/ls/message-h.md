Response:
Let's break down the thought process for analyzing the provided `message.h` file.

1. **Initial Understanding of the File Path:** The path `v8/src/torque/ls/message.h` immediately tells us several things:
    * It's part of the V8 JavaScript engine source code.
    * It's within the `torque` directory, suggesting it's related to Torque, V8's internal language for writing built-in functions.
    * The `ls` subdirectory strongly hints at "Language Server" functionality.
    * The `.h` extension indicates it's a header file, likely defining classes and structures.

2. **Scanning the Header Guards:** The `#ifndef V8_TORQUE_LS_MESSAGE_H_` and `#define V8_TORQUE_LS_MESSAGE_H_` are standard header guards, preventing multiple inclusions and compilation errors. This is a basic but important observation.

3. **Identifying Key Includes:** The included headers provide crucial context:
    * `"src/base/logging.h"`:  Indicates the use of V8's logging facilities for debugging or information purposes.
    * `"src/torque/ls/json.h"`:  A strong indicator that this file deals with JSON (JavaScript Object Notation) for communication. This is a central point for understanding the file's purpose.
    * `"src/torque/ls/message-macros.h"`: Suggests the use of macros to simplify the definition of message structures and accessors. This is an implementation detail that explains the syntax we'll see later.
    * `"src/torque/source-positions.h"`: Indicates interaction with source code locations (line numbers, columns), which is typical for language server features like "Go to Definition."

4. **Namespace Analysis:** The nested namespaces `v8::internal::torque::ls` clearly delineate the scope of these classes within the V8 project. This helps in understanding the organizational structure.

5. **Analyzing `BaseJsonAccessor`:** This class stands out as a fundamental building block. Its purpose is to manage data backed by JSON. Key observations:
    * It can be backed by either a `JsonValue` or a `JsonObject`. This suggests flexibility in how the JSON data is held.
    * `GetObject`, `HasProperty`, `SetNull`, `IsNull` are basic JSON manipulation methods.
    * The protected virtual `object()` methods are crucial. They enforce that derived classes provide the underlying JSON object.
    * `GetObjectProperty` and `GetArrayProperty` handle lazy creation of nested objects and arrays within the JSON structure. This is a common pattern for working with potentially deep JSON structures.
    * `AddObjectElementToArrayProperty` is a convenience method for adding objects to arrays.

6. **Analyzing `Message`:**  This class inherits from `BaseJsonAccessor` and represents a complete, self-contained message.
    * It *owns* the `JsonValue` (`value_`), as opposed to just referencing it.
    * The constructor initializes the `jsonrpc` field to "2.0," indicating adherence to the JSON-RPC protocol.
    * The overridden `object()` methods return the root `JsonObject`.
    * `JSON_STRING_ACCESSORS(jsonrpc)` suggests a macro is used to generate getter/setter methods for the `jsonrpc` property.

7. **Analyzing `NestedJsonAccessor`:** This class represents parts of a larger message.
    * It *references* a `JsonObject` passed in the constructor, rather than owning it. This signifies it's a component within a larger JSON structure.

8. **Analyzing the Specific Message Classes (e.g., `ResponseError`, `InitializeParams`):** These classes follow a consistent pattern:
    * They inherit from `NestedJsonAccessor`.
    * They use macros like `JSON_INT_ACCESSORS`, `JSON_STRING_ACCESSORS`, `JSON_OBJECT_ACCESSORS`, and `JSON_ARRAY_OBJECT_ACCESSORS`. These macros are the key to understanding how they map JSON properties to class members. It's important to note what types of data each macro handles (integers, strings, nested objects, arrays of objects).
    * The names of the classes (e.g., `InitializeParams`, `ServerCapabilities`, `Location`) strongly suggest their purpose within a language server context. They represent parameters and data structures exchanged between the language server and the client (e.g., a code editor).

9. **Analyzing `Request` and `Response` Templates:** These templates are parameterized by a type `T`, indicating they are generic message structures.
    * They inherit from `Message`.
    * They include `id` and `method` fields, which are standard in JSON-RPC.
    * The `params` field in `Request` and `result` field in `Response` hold the specific data related to the request or response, using the type `T`.
    * The `Response` class also includes an `error` field for reporting errors.

10. **Connecting to Language Server Concepts:** At this point, the purpose becomes clear: this file defines the data structures used for communication in a language server implementation. The classes map directly to concepts in the Language Server Protocol (LSP):
    * **Requests:**  Actions initiated by the client (e.g., `InitializeRequest`, `GotoDefinitionRequest`, `DocumentSymbolRequest`).
    * **Responses:**  Replies from the server to requests (e.g., `InitializeResponse`, `GotoDefinitionResponse`, `DocumentSymbolResponse`).
    * **Notifications:** One-way messages from either the client or the server (e.g., `TorqueFileListNotification`, `DidChangeWatchedFilesNotification`, `PublishDiagnosticsNotification`).
    * **Parameters and Results:** The specific data exchanged within these messages (e.g., `InitializeParams`, `ServerCapabilities`, `Location`, `Diagnostic`).

11. **Considering the `.tq` Extension and JavaScript Relevance:**  The question about the `.tq` extension helps connect this to Torque. The file itself is `.h`, so it's C++, but the *purpose* of this language server is to support *Torque* code. The connection to JavaScript comes indirectly through Torque, which is used to implement JavaScript built-ins. The language server provides features for editing and understanding Torque code, which ultimately contributes to the functionality of the JavaScript engine.

12. **Generating Examples and Identifying Common Errors:**  Once the purpose is clear, it's possible to generate relevant JavaScript examples that illustrate the *kinds* of interactions these messages facilitate (even though the messages themselves are C++). Identifying common programming errors involves thinking about how these structures could be misused or misinterpreted, especially regarding JSON handling.

By following these steps, we can move from a basic understanding of the file path and includes to a comprehensive understanding of its role in the V8 project and its connection to language server principles and the Torque language. The key is to analyze the structure, the inheritance relationships, the use of macros, and the naming conventions to infer the purpose of each class and its place in the overall system.
这是一个V8源代码文件，定义了用于 Torque 语言服务器（Language Server）的消息结构。以下是它的功能分解：

**主要功能:**

* **定义 Torque 语言服务器的消息类型:**  该文件定义了用于在 Torque 语言服务器和客户端（通常是代码编辑器或 IDE）之间通信的各种消息类型。这些消息遵循类似 JSON-RPC 的协议。
* **结构化 JSON 数据:** 文件中的类和结构体主要用于表示和操作 JSON 数据。语言服务器之间的通信通常使用 JSON 格式。
* **提供类型安全的访问器:** 通过使用宏 (如 `JSON_STRING_ACCESSORS`, `JSON_INT_ACCESSORS`, `JSON_OBJECT_ACCESSORS`, `JSON_ARRAY_OBJECT_ACCESSORS`)，该文件为 JSON 属性提供了类型安全的 getter 和 setter 方法。这避免了手动解析和转换 JSON 数据的繁琐过程。
* **表示 LSP (Language Server Protocol) 的概念:**  许多类名和结构都与 LSP 中的概念相对应，例如 `InitializeParams`, `ServerCapabilities`, `Location`, `Diagnostic` 等。这表明 Torque 语言服务器很可能遵循 LSP 规范。

**功能细分:**

1. **`BaseJsonAccessor`:**
   - 作为所有基于 JSON 访问的类的基类。
   - 提供了访问和操作 JSON 对象的通用方法，例如获取对象属性、检查属性是否存在、设置 null 值等。
   - 使用模板方法 `GetObject` 来创建特定类型的嵌套对象。

2. **`Message`:**
   - 作为所有消息类型的基类（请求、响应、通知）。
   - 拥有顶层的 `JsonValue`，代表整个消息的 JSON 结构。
   - 包含 `jsonrpc` 字段，表明使用了 JSON-RPC 协议。

3. **`NestedJsonAccessor`:**
   - 作为消息中嵌套对象的基类。
   - 不拥有 `JsonValue`，而是引用父对象的 `JsonObject`。

4. **`ResponseError`:**
   - 表示响应消息中的错误信息，包含错误码 (`code`) 和错误消息 (`message`).

5. **`InitializeParams`:**
   - 表示 "初始化" 请求的参数，包含进程 ID (`processId`)、根路径 (`rootPath`, `rootUri`) 和追踪信息 (`trace`)。

6. **`FileListParams`:**
   - 表示 "文件列表" 通知的参数，用于传递文件列表信息（具体实现未完全展示）。

7. **`FileSystemWatcher` 和 `DidChangeWatchedFilesRegistrationOptions`:**
   - 用于注册监听文件系统变化的选项，例如监听特定模式的文件 (`globPattern`) 的创建、修改或删除 (`kind`)。

8. **`FileEvent` 和 `DidChangeWatchedFilesParams`:**
   - 表示文件系统变化的事件，包含变化的文件的 URI (`uri`) 和变化类型 (`type`)。

9. **`SaveOptions` 和 `TextDocumentSyncOptions`:**
   - 定义了文本文档同步的选项，例如是否在保存时包含文本 (`includeText`)，以及何时触发同步事件。

10. **`ServerCapabilities`:**
   - 表示语言服务器支持的功能，例如文本文档同步 (`textDocumentSync`)、定义跳转 (`definitionProvider`)、文档符号 (`documentSymbolProvider`) 等。

11. **`InitializeResult`:**
   - 表示 "初始化" 请求的响应结果，包含服务器的功能 (`capabilities`)。

12. **`Registration` 和 `RegistrationParams`:**
   - 用于动态注册语言服务器的功能。

13. **`JsonPosition` 和 `Range`:**
   - 表示代码中的位置和范围（由起始和结束位置组成）。

14. **`Location`:**
   - 表示代码的位置信息，包含文件 URI (`uri`) 和范围 (`range`)。
   - 提供了 `SetTo` 方法，用于从 `SourcePosition` 对象设置位置信息。

15. **`TextDocumentIdentifier` 和 `TextDocumentPositionParams`:**
   - 用于标识文本文档和文档中的特定位置。

16. **`Diagnostic`:**
   - 表示代码中的诊断信息（例如错误、警告），包含范围 (`range`)、严重程度 (`severity`)、来源 (`source`) 和消息 (`message`)。

17. **`PublishDiagnosticsParams`:**
   - 表示 "发布诊断" 通知的参数，用于发送指定文件的诊断信息。

18. **`SymbolKind` 和 `SymbolInformation`:**
   - 用于表示代码符号的类型（例如文件、类、方法）和信息（名称、类型、位置、容器名称）。

19. **`DocumentSymbolParams` 和 `DocumentSymbolResponse`:**
   - 用于请求文档符号信息。

20. **`Request<T>` 和 `Response<T>` 模板:**
    - 定义了通用的请求和响应消息结构，其中 `T` 是参数或结果的类型。
    - 例如，`InitializeRequest` 是 `Request<InitializeParams>` 的别名。

21. **`ResponseArrayResult<T>` 模板:**
    - 类似于 `Response<T>`，但结果是一个对象数组。

**关于 `.tq` 结尾：**

如果 `v8/src/torque/ls/message.h` 文件以 `.tq` 结尾，那么你的说法是正确的，它将是一个 **Torque 源代码文件**。 Torque 是 V8 内部使用的一种用于编写高性能内置函数的领域特定语言。

**与 JavaScript 的关系：**

虽然此文件本身是用 C++ 编写的，并且与 Torque 语言服务器相关，但它最终与 JavaScript 的功能息息相关，原因如下：

* **Torque 用于实现 JavaScript 内置函数:** V8 使用 Torque 来编写一些核心的 JavaScript 内置函数，例如数组方法、对象操作等。
* **语言服务器提供开发支持:** Torque 语言服务器的目的是为编写 Torque 代码提供诸如自动补全、错误检查、跳转到定义等功能。这使得 V8 开发者能够更高效地编写和维护用 Torque 编写的 JavaScript 内置函数。

**JavaScript 示例（说明 LSP 的交互概念）：**

虽然无法直接用 JavaScript 展示 `message.h` 中定义的 C++ 类，但我们可以用 JavaScript 模拟客户端与 Torque 语言服务器之间的交互，以理解这些消息的作用。

假设一个代码编辑器正在与 Torque 语言服务器通信：

```javascript
// 客户端发送 "初始化" 请求
const initializeRequest = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    processId: 1234,
    rootPath: "/path/to/torque/project",
    rootUri: "file:///path/to/torque/project",
    trace: "verbose"
  }
};

// 语言服务器返回 "初始化" 响应
const initializeResponse = {
  jsonrpc: "2.0",
  id: 1,
  result: {
    capabilities: {
      textDocumentSync: {
        openClose: true,
        change: 1 // TextDocumentSyncKind.Full
      },
      definitionProvider: true,
      documentSymbolProvider: true
    }
  }
};

// 客户端发送 "跳转到定义" 请求
const gotoDefinitionRequest = {
  jsonrpc: "2.0",
  id: 2,
  method: "textDocument/definition",
  params: {
    textDocument: {
      uri: "file:///path/to/torque/project/foo.tq"
    },
    position: {
      line: 10,
      character: 5
    }
  }
};

// 语言服务器返回 "跳转到定义" 响应
const gotoDefinitionResponse = {
  jsonrpc: "2.0",
  id: 2,
  result: {
    uri: "file:///path/to/torque/project/bar.tq",
    range: {
      start: { line: 20, character: 1 },
      end: { line: 20, character: 10 }
    }
  }
};

// 语言服务器发送 "发布诊断" 通知
const publishDiagnosticsNotification = {
  jsonrpc: "2.0",
  method: "textDocument/publishDiagnostics",
  params: {
    uri: "file:///path/to/torque/project/foo.tq",
    diagnostics: [
      {
        range: {
          start: { line: 5, character: 2 },
          end: { line: 5, character: 8 }
        },
        severity: 1, // DiagnosticSeverity.Error
        source: "Torque",
        message: "Syntax error: Unexpected token."
      }
    ]
  }
};
```

**代码逻辑推理（假设输入与输出）：**

假设有以下 Torque 代码片段：

```torque
// file.tq
type MyType extends Object;

const MyConstant: intptr = 10;

fun MyFunction(x: intptr): intptr {
  return x + MyConstant;
}
```

**场景：请求文档符号**

* **假设输入（来自客户端的 `DocumentSymbolRequest`）:**
  ```json
  {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "textDocument/documentSymbol",
    "params": {
      "textDocument": {
        "uri": "file:///path/to/torque/project/file.tq"
      }
    }
  }
  ```

* **可能的输出（来自服务器的 `DocumentSymbolResponse`）:**
  ```json
  {
    "jsonrpc": "2.0",
    "id": 3,
    "result": [
      {
        "name": "MyType",
        "kind": 5, // SymbolKind.Class
        "location": {
          "uri": "file:///path/to/torque/project/file.tq",
          "range": {
            "start": { "line": 1, "character": 5 },
            "end": { "line": 1, "character": 11 }
          }
        }
      },
      {
        "name": "MyConstant",
        "kind": 14, // SymbolKind.Constant
        "location": {
          "uri": "file:///path/to/torque/project/file.tq",
          "range": {
            "start": { "line": 3, "character": 6 },
            "end": { "line": 3, "character": 16 }
          }
        },
        "containerName": null
      },
      {
        "name": "MyFunction",
        "kind": 12, // SymbolKind.Function
        "location": {
          "uri": "file:///path/to/torque/project/file.tq",
          "range": {
            "start": { "line": 5, "character": 4 },
            "end": { "line": 7, "character": 1 }
          }
        }
      }
    ]
  }
  ```

**用户常见的编程错误举例说明：**

使用这些消息结构时，常见的编程错误可能包括：

1. **类型不匹配:** 尝试将错误的数据类型赋值给 JSON 属性。例如，将字符串赋值给 `JSON_INT_ACCESSORS` 定义的属性。
   ```c++
   InitializeParams params;
   // 错误：processId 应该是一个整数
   params.set_processId("not a number");
   ```

2. **忘记设置必需的属性:** 某些消息可能需要特定的属性才能正确处理。忘记设置这些属性可能导致语言服务器出现错误或行为异常。
   ```c++
   GotoDefinitionRequest request;
   // 错误：忘记设置 textDocument 和 position
   // ... 发送请求 ...
   ```

3. **JSON 结构不正确:**  手动创建 JSON 数据时，可能会出现结构错误，例如缺少必要的键或使用了错误的嵌套。使用提供的 C++ 类可以减少这种错误。
   ```c++
   // 手动创建 JSON (容易出错)
   JsonObject json = {{"jsonrpc", "2.0"}, {"id", "wrong_type"}, ...};

   // 使用提供的类更安全
   InitializeRequest request;
   request.set_id(1);
   request.params().set_processId(1234);
   ```

4. **混淆请求、响应和通知:**  错误地使用消息类型可能会导致通信失败。例如，将一个本应是响应的消息作为请求发送。

5. **忽略错误处理:**  在处理响应消息时，没有检查 `error` 字段，可能会导致程序在遇到错误时崩溃或产生不可预测的结果。
   ```c++
   InitializeResponse response = ...;
   if (response.has_error()) {
     // 处理错误
     LOG(ERROR) << "Initialization failed: " << response.error().message();
   } else {
     // 处理成功的结果
     ServerCapabilities capabilities = response.result();
     // ...
   }
   ```

总而言之，`v8/src/torque/ls/message.h` 定义了 Torque 语言服务器通信的基础结构，使得 V8 开发者能够更方便地为 Torque 语言提供强大的开发工具支持，最终帮助提升 JavaScript 引擎的开发效率和质量。

### 提示词
```
这是目录为v8/src/torque/ls/message.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/ls/message.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TORQUE_LS_MESSAGE_H_
#define V8_TORQUE_LS_MESSAGE_H_

#include "src/base/logging.h"
#include "src/torque/ls/json.h"
#include "src/torque/ls/message-macros.h"
#include "src/torque/source-positions.h"

namespace v8 {
namespace internal {
namespace torque {
namespace ls {

// Base class for Messages and Objects that are backed by either a
// JsonValue or a reference to a JsonObject.
// Helper methods are used by macros to implement typed accessors.
class BaseJsonAccessor {
 public:
  template <class T>
  T GetObject(const std::string& property) {
    return T(GetObjectProperty(property));
  }

  bool HasProperty(const std::string& property) const {
    return object().count(property) > 0;
  }

  void SetNull(const std::string& property) {
    object()[property] = JsonValue::JsonNull();
  }

  bool IsNull(const std::string& property) const {
    return HasProperty(property) &&
           object().at(property).tag == JsonValue::IS_NULL;
  }

 protected:
  virtual const JsonObject& object() const = 0;
  virtual JsonObject& object() = 0;

  JsonObject& GetObjectProperty(const std::string& property) {
    if (!object()[property].IsObject()) {
      object()[property] = JsonValue::From(JsonObject{});
    }
    return object()[property].ToObject();
  }

  JsonArray& GetArrayProperty(const std::string& property) {
    if (!object()[property].IsArray()) {
      object()[property] = JsonValue::From(JsonArray{});
    }
    return object()[property].ToArray();
  }

  JsonObject& AddObjectElementToArrayProperty(const std::string& property) {
    JsonArray& array = GetArrayProperty(property);
    array.push_back(JsonValue::From(JsonObject{}));

    return array.back().ToObject();
  }
};

// Base class for Requests, Responses and Notifications.
// In contrast to "BaseObject", a Message owns the backing JsonValue of the
// whole object tree; i.e. value_ serves as root.
class Message : public BaseJsonAccessor {
 public:
  Message() {
    value_ = JsonValue::From(JsonObject{});
    set_jsonrpc("2.0");
  }
  explicit Message(JsonValue value) : value_(std::move(value)) {
    CHECK(value_.tag == JsonValue::OBJECT);
  }

  JsonValue& GetJsonValue() { return value_; }

  JSON_STRING_ACCESSORS(jsonrpc)

 protected:
  const JsonObject& object() const override { return value_.ToObject(); }
  JsonObject& object() override { return value_.ToObject(); }

 private:
  JsonValue value_;
};

// Base class for complex type that might be part of a Message.
// Instead of creating theses directly, use the accessors on the
// root Message or a parent object.
class NestedJsonAccessor : public BaseJsonAccessor {
 public:
  explicit NestedJsonAccessor(JsonObject& object) : object_(object) {}

  const JsonObject& object() const override { return object_; }
  JsonObject& object() override { return object_; }

 private:
  JsonObject& object_;
};

class ResponseError : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_INT_ACCESSORS(code)
  JSON_STRING_ACCESSORS(message)
};

class InitializeParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_INT_ACCESSORS(processId)
  JSON_STRING_ACCESSORS(rootPath)
  JSON_STRING_ACCESSORS(rootUri)
  JSON_STRING_ACCESSORS(trace)
};

class FileListParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  // TODO(szuend): Implement read accessor for string
  //               arrays. "files" is managed directly.
};

class FileSystemWatcher : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(globPattern)
  JSON_INT_ACCESSORS(kind)

  enum WatchKind {
    kCreate = 1,
    kChange = 2,
    kDelete = 4,

    kAll = kCreate | kChange | kDelete,
  };
};

class DidChangeWatchedFilesRegistrationOptions : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_ARRAY_OBJECT_ACCESSORS(FileSystemWatcher, watchers)
};

class FileEvent : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(uri)
  JSON_INT_ACCESSORS(type)
};

class DidChangeWatchedFilesParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_ARRAY_OBJECT_ACCESSORS(FileEvent, changes)
};

class SaveOptions : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_BOOL_ACCESSORS(includeText)
};

class TextDocumentSyncOptions : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_BOOL_ACCESSORS(openClose)
  JSON_INT_ACCESSORS(change)
  JSON_BOOL_ACCESSORS(willSave)
  JSON_BOOL_ACCESSORS(willSaveWaitUntil)
  JSON_OBJECT_ACCESSORS(SaveOptions, save)
};

class ServerCapabilities : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_OBJECT_ACCESSORS(TextDocumentSyncOptions, textDocumentSync)
  JSON_BOOL_ACCESSORS(definitionProvider)
  JSON_BOOL_ACCESSORS(documentSymbolProvider)
};

class InitializeResult : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_OBJECT_ACCESSORS(ServerCapabilities, capabilities)
};

class Registration : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(id)
  JSON_STRING_ACCESSORS(method)
  JSON_DYNAMIC_OBJECT_ACCESSORS(registerOptions)
};

class RegistrationParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_ARRAY_OBJECT_ACCESSORS(Registration, registrations)
};

class JsonPosition : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_INT_ACCESSORS(line)
  JSON_INT_ACCESSORS(character)
};

class Range : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_OBJECT_ACCESSORS(JsonPosition, start)
  JSON_OBJECT_ACCESSORS(JsonPosition, end)
};

class Location : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(uri)
  JSON_OBJECT_ACCESSORS(Range, range)

  void SetTo(SourcePosition position) {
    set_uri(SourceFileMap::AbsolutePath(position.source));
    range().start().set_line(position.start.line);
    range().start().set_character(position.start.column);
    range().end().set_line(position.end.line);
    range().end().set_character(position.end.column);
  }
};

class TextDocumentIdentifier : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(uri)
};

class TextDocumentPositionParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_OBJECT_ACCESSORS(TextDocumentIdentifier, textDocument)
  JSON_OBJECT_ACCESSORS(JsonPosition, position)
};

class Diagnostic : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  enum DiagnosticSeverity {
    kError = 1,
    kWarning = 2,
    kInformation = 3,
    kHint = 4
  };

  JSON_OBJECT_ACCESSORS(Range, range)
  JSON_INT_ACCESSORS(severity)
  JSON_STRING_ACCESSORS(source)
  JSON_STRING_ACCESSORS(message)
};

class PublishDiagnosticsParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(uri)
  JSON_ARRAY_OBJECT_ACCESSORS(Diagnostic, diagnostics)
};

enum SymbolKind {
  kFile = 1,
  kNamespace = 3,
  kClass = 5,
  kMethod = 6,
  kProperty = 7,
  kField = 8,
  kConstructor = 9,
  kFunction = 12,
  kVariable = 13,
  kConstant = 14,
  kStruct = 23,
};

class DocumentSymbolParams : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_OBJECT_ACCESSORS(TextDocumentIdentifier, textDocument)
};

class SymbolInformation : public NestedJsonAccessor {
 public:
  using NestedJsonAccessor::NestedJsonAccessor;

  JSON_STRING_ACCESSORS(name)
  JSON_INT_ACCESSORS(kind)
  JSON_OBJECT_ACCESSORS(Location, location)
  JSON_STRING_ACCESSORS(containerName)
};

template <class T>
class Request : public Message {
 public:
  explicit Request(JsonValue value) : Message(std::move(value)) {}
  Request() : Message() {}

  JSON_INT_ACCESSORS(id)
  JSON_STRING_ACCESSORS(method)
  JSON_OBJECT_ACCESSORS(T, params)
};
using InitializeRequest = Request<InitializeParams>;
using RegistrationRequest = Request<RegistrationParams>;
using TorqueFileListNotification = Request<FileListParams>;
using GotoDefinitionRequest = Request<TextDocumentPositionParams>;
using DidChangeWatchedFilesNotification = Request<DidChangeWatchedFilesParams>;
using PublishDiagnosticsNotification = Request<PublishDiagnosticsParams>;
using DocumentSymbolRequest = Request<DocumentSymbolParams>;

template <class T>
class Response : public Message {
 public:
  explicit Response(JsonValue value) : Message(std::move(value)) {}
  Response() : Message() {}

  JSON_INT_ACCESSORS(id)
  JSON_OBJECT_ACCESSORS(ResponseError, error)
  JSON_OBJECT_ACCESSORS(T, result)
};
using InitializeResponse = Response<InitializeResult>;
using GotoDefinitionResponse = Response<Location>;

// Same as "Response" but the result is T[] instead of T.
template <class T>
class ResponseArrayResult : public Message {
 public:
  explicit ResponseArrayResult(JsonValue value) : Message(std::move(value)) {}
  ResponseArrayResult() : Message() {}

  JSON_INT_ACCESSORS(id)
  JSON_OBJECT_ACCESSORS(ResponseError, error)
  JSON_ARRAY_OBJECT_ACCESSORS(T, result)
};
using DocumentSymbolResponse = ResponseArrayResult<SymbolInformation>;

}  // namespace ls
}  // namespace torque
}  // namespace internal
}  // namespace v8

#endif  // V8_TORQUE_LS_MESSAGE_H_
```