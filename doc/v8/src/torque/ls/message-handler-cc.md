Response:
Let's break down the thought process for analyzing the `message-handler.cc` file.

1. **Understand the Context:** The file is located in `v8/src/torque/ls/`. The `ls` likely stands for Language Server. Torque is V8's custom language for generating TurboFan code. This immediately suggests the file is part of the tooling for developing and working with Torque code. A language server implies features like autocompletion, go-to-definition, and diagnostics.

2. **Identify Key Components and Their Roles:**

   * **`#include` directives:** These are the building blocks. They tell us about dependencies and functionalities used in the file. We see:
      * `algorithm`: Standard library for algorithms.
      * `message-handler.h`:  The header file for this source file, likely defining its interface.
      * `globals.h`, `json-parser.h`, `message-pipe.h`, `message.h`:  Hints at handling messages, likely in JSON format.
      * `server-data.h`:  Suggests storing and accessing information about the Torque codebase.
      * `source-positions.h`: Deals with tracking locations within source files.
      * `torque-compiler.h`: The core component for compiling Torque code.

   * **Namespaces:** `v8::internal::torque::ls` clearly defines the scope and purpose.

   * **Constants:** `kContentLength`, `kProtocolLineEnding`:  These look like protocol-related constants for reading messages. The content length suggests a way to frame the message data. The different line endings for Windows vs. other OSes are important for cross-platform compatibility.

   * **`ReadMessage()` and `WriteMessage()`:** These are fundamental for communication. They handle the low-level details of reading and writing messages, likely over a standard input/output stream, using the `Content-Length` mechanism.

   * **`ResetCompilationErrorDiagnostics()`:**  This suggests a process of clearing previous error messages, likely before a new compilation.

   * **`DiagnosticCollector`:** This class is crucial. Its purpose is to gather diagnostics (errors, warnings, hints) from the Torque compiler and format them into notifications suitable for a Language Server Protocol (LSP) client. The logic for suppressing lint messages after an error is interesting.

   * **`SendCompilationDiagnostics()`:** This function uses the `DiagnosticCollector` to send out the collected diagnostic messages.

   * **`CompilationFinished()`:** This function updates the internal state of the language server after a successful compilation, including the language server data and source file map.

   * **`RecompileTorque()` and `RecompileTorqueWithDiagnostics()`:** These trigger the Torque compiler and handle the resulting data. The "with diagnostics" version likely clears old errors first.

   * **`Handle...Request/Notification()` functions:**  These functions are the core of the language server logic. They handle specific LSP requests and notifications:
      * `HandleInitializeRequest`: Responds to the initial handshake from the LSP client.
      * `HandleInitializedNotification`: Handles the notification that the client is ready.
      * `HandleTorqueFileListNotification`: Receives the initial list of Torque files.
      * `HandleGotoDefinitionRequest`: Implements the "go to definition" feature.
      * `HandleChangeWatchedFilesNotification`: Handles notifications about changes to watched files (e.g., creation, deletion, modification).
      * `HandleDocumentSymbolRequest`:  Provides a list of symbols (functions, classes, etc.) in a document.

   * **`HandleMessage()`:** This is the central dispatch function. It reads the incoming message, determines its type (request or notification), and calls the appropriate handler function.

3. **Infer Functionality:** Based on the components, we can infer the main functionalities:

   * **Communication:** Reading and writing messages using a specific protocol (Content-Length).
   * **Compilation:** Triggering the Torque compiler.
   * **Diagnostics:** Collecting, formatting, and sending compiler errors and warnings to the client.
   * **Language Server Protocol (LSP) Support:** Implementing handlers for common LSP requests and notifications to provide features like go-to-definition and symbol listing.
   * **File Management:** Handling lists of Torque files and reacting to file changes.
   * **Data Management:** Storing and accessing information about the Torque codebase (`LanguageServerData`, `SourceFileMap`).

4. **Connect to JavaScript:** The connection is through the purpose of Torque. Torque generates C++ code that is eventually used in the V8 JavaScript engine. The language server helps developers work with Torque, which in turn affects the performance and features of JavaScript. The example provided in the prompt about a built-in function is a good illustration.

5. **Consider User Errors:** Common errors would involve incorrect Torque syntax, which the language server helps to catch and report. Another error might be misconfiguration of the LSP client or server.

6. **Hypothesize Inputs and Outputs:** For functions like `ReadMessage` and `WriteMessage`, the input/output is relatively straightforward (JSON data). For the handler functions, the input is a specific LSP request/notification, and the output is a corresponding response/notification.

7. **Address the `.tq` Extension:**  The code explicitly handles files with the `.tq` extension, confirming it's related to Torque source files.

8. **Structure the Answer:**  Organize the findings into clear sections: Functionality, Connection to JavaScript, Code Logic (with examples), and Common Errors. This makes the analysis easy to understand.

**Self-Correction/Refinement during the thought process:**

* Initially, I might just list the `#include` files. But then I'd realize that explaining *why* those includes are there adds more value.
* When looking at the `DiagnosticCollector`, I would initially focus on the collection aspect. But the logic for suppressing lint messages after an error is a key detail worth highlighting.
* For the handler functions, simply stating their names isn't enough. Briefly explaining what each one *does* within the context of an LSP is important.
* Connecting Torque to JavaScript requires more than just saying "Torque compiles to C++." Explaining that this C++ *powers* JavaScript features provides a stronger link.
* When considering user errors, I'd move beyond just "syntax errors" and think about errors related to the language server environment itself.

By following this structured approach, combining code analysis with domain knowledge (language servers, compiler concepts, V8 internals), and constantly refining the understanding, a comprehensive explanation of the `message-handler.cc` file can be developed.
好的，让我们来分析一下 `v8/src/torque/ls/message-handler.cc` 文件的功能。

**文件功能概述**

`v8/src/torque/ls/message-handler.cc` 文件是 V8 中 Torque 语言服务器 (Language Server) 的核心组件之一，负责处理客户端（例如代码编辑器）发送过来的各种消息。它的主要功能是：

1. **接收和解析来自客户端的消息:**  它监听标准输入 (`std::cin`)，读取客户端发送的符合 Language Server Protocol (LSP) 格式的消息，并使用 JSON 解析器将其解析为内部数据结构。消息通常包含请求（requests）或通知（notifications）。

2. **处理不同类型的消息:**  根据消息的 `method` 字段，它将消息分发给相应的处理函数。这些处理函数实现了 LSP 协议中定义的各种功能，例如：
   - 初始化语言服务器 (`initialize`)
   - 注册客户端能力 (`client/registerCapability`)
   - 接收 Torque 文件列表 (`torque/fileList`)
   - 处理 "跳转到定义" 请求 (`textDocument/definition`)
   - 处理 "监视文件变化" 通知 (`workspace/didChangeWatchedFiles`)
   - 处理 "文档符号" 请求（例如，列出文件中的函数和类） (`textDocument/documentSymbol`)

3. **调用 Torque 编译器:** 当接收到文件列表更新或文件内容变化的通知时，它会调用 Torque 编译器重新编译 Torque 代码。

4. **收集和发送编译诊断信息:**  在 Torque 编译完成后，它会收集编译器生成的错误、警告等诊断信息，并将这些信息格式化为 LSP 的 `publishDiagnostics` 通知发送回客户端，以便编辑器可以高亮显示错误和警告。

5. **管理语言服务器数据:** 它维护着 Torque 代码的符号信息、源文件映射等数据，用于响应客户端的请求，例如 "跳转到定义" 和 "文档符号"。

6. **向客户端发送响应和通知:**  对于客户端的请求，它会生成相应的响应并将其发送回客户端。它也会主动向客户端发送通知，例如编译诊断信息。消息的发送也遵循 LSP 格式，包括 `Content-Length` 头信息。

**`.tq` 文件与 JavaScript 的关系**

是的，如果 `v8/src/torque/ls/message-handler.cc` 与扩展名为 `.tq` 的文件交互，那么这些 `.tq` 文件就是 V8 Torque 的源代码。

Torque 是一种由 V8 团队开发的特定领域的语言，用于生成高效的 JavaScript 虚拟机 (VM) 的 C++ 代码，特别是用于实现内置函数和运行时库。

**JavaScript 示例说明**

例如，假设你有一个名为 `array.tq` 的 Torque 文件，其中定义了 JavaScript 中 `Array.prototype.push` 方法的实现。 当语言服务器接收到关于 `array.tq` 文件的消息（例如，文件被修改），它会触发 Torque 编译。如果 `array.tq` 中有语法错误，`message-handler.cc` 会收集这些错误并将其发送回代码编辑器，编辑器可能会显示如下的错误信息：

```
array.tq:10:5: error: Unexpected token, expected ';'
  let length: Number = this.length // 缺少分号
```

在 JavaScript 中使用这个内置函数：

```javascript
const arr = [1, 2, 3];
arr.push(4); // 这个 push 方法的实现可能就是用 Torque 编写的
console.log(arr); // 输出: [1, 2, 3, 4]
```

**代码逻辑推理 (假设输入与输出)**

假设语言服务器接收到一个 "跳转到定义" 的请求，请求查找在文件 `foo.tq` 的第 5 行第 10 列处的符号的定义。

**假设输入 (`GotoDefinitionRequest`):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "textDocument/definition",
  "params": {
    "textDocument": {
      "uri": "file:///path/to/foo.tq"
    },
    "position": {
      "line": 4,  // 行号从 0 开始，所以第 5 行是 4
      "character": 9 // 列号从 0 开始，所以第 10 列是 9
    }
  }
}
```

**可能的处理逻辑:**

1. `HandleGotoDefinitionRequest` 函数接收到请求。
2. 它从 `params.textDocument.uri` 中获取文件名 `foo.tq`，并查找其对应的 `SourceId`。
3. 它使用 `params.position` 中的行号和列号创建一个 `LineAndColumn` 对象。
4. 它调用 `LanguageServerData::FindDefinition`，传入 `SourceId` 和 `LineAndColumn`。
5. 如果在 `LanguageServerData` 中找到了该位置的符号定义，例如，该符号是一个在 `bar.tq` 文件第 2 行第 3 列定义的函数 `myFunction`。

**可能的输出 (`GotoDefinitionResponse`):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "uri": "file:///path/to/bar.tq",
    "range": {
      "start": {
        "line": 1,
        "character": 2
      },
      "end": {
        "line": 1,
        "character": 15 // 假设函数名长度为 12
      }
    }
  }
}
```

如果找不到定义，`result` 字段可能会是 `null`。

**用户常见的编程错误示例**

使用 Torque 编程时，常见的错误包括：

1. **语法错误:** 例如，忘记在语句末尾添加分号，类型拼写错误，使用了未定义的变量或宏。
   ```torque
   function MyFunction(x: Number) {
     let y : Nubmer = x; // 类型拼写错误 "Nubmer"
     return y
   } // 缺少分号
   ```
   语言服务器会在编译时检测到这些错误，并通过 `publishDiagnostics` 通知发送给编辑器，编辑器会高亮显示这些错误。

2. **类型错误:** 例如，将一个字符串赋值给一个期望数字的变量，或者将错误类型的参数传递给函数。
   ```torque
   function Add(a: Number, b: Number): Number {
     return a + b;
   }

   let result: Number = Add("hello", 5); // 类型错误，"hello" 不是 Number
   ```
   Torque 编译器会捕获这些类型错误。

3. **宏使用错误:**  如果宏的参数不正确，或者宏展开后产生无效的 Torque 代码，也会导致编译错误。
   ```torque
   macro Print(value: String) {
     std::out << value;
   }

   Print(123); // 宏期望 String 类型的参数，但传入了 Number
   ```

4. **循环或递归错误导致无限编译:** 虽然语言服务器本身不会直接捕获无限循环，但在复杂的 Torque 代码中，错误的使用循环或递归可能会导致编译器陷入死循环或消耗大量资源。

**总结**

`v8/src/torque/ls/message-handler.cc` 是 V8 中 Torque 语言服务器的关键组成部分，它负责处理客户端的请求和通知，驱动 Torque 编译，并向客户端报告编译结果和诊断信息，从而为 Torque 开发者提供实时的代码分析和辅助功能。它通过 Language Server Protocol 与代码编辑器进行通信，使得开发者能够在熟悉的编辑器环境中更高效地编写和调试 Torque 代码。

### 提示词
```
这是目录为v8/src/torque/ls/message-handler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/ls/message-handler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include "src/torque/ls/message-handler.h"

#include "src/torque/ls/globals.h"
#include "src/torque/ls/json-parser.h"
#include "src/torque/ls/message-pipe.h"
#include "src/torque/ls/message.h"
#include "src/torque/server-data.h"
#include "src/torque/source-positions.h"
#include "src/torque/torque-compiler.h"

EXPORT_CONTEXTUAL_VARIABLE(v8::internal::torque::DiagnosticsFiles)

namespace v8 {
namespace internal {
namespace torque {

namespace ls {

static const char kContentLength[] = "Content-Length: ";
static const size_t kContentLengthSize = sizeof(kContentLength) - 1;

#ifdef V8_OS_WIN
// On Windows, in text mode, \n is translated to \r\n.
constexpr const char* kProtocolLineEnding = "\n\n";
#else
constexpr const char* kProtocolLineEnding = "\r\n\r\n";
#endif

JsonValue ReadMessage() {
  std::string line;
  std::getline(std::cin, line);

  if (line.rfind(kContentLength) != 0) {
    // Invalid message, we just crash.
    Logger::Log("[fatal] Did not find Content-Length ...\n");
    v8::base::OS::Abort();
  }

  const int content_length = std::atoi(line.substr(kContentLengthSize).c_str());
  std::getline(std::cin, line);
  std::string content(content_length, ' ');
  std::cin.read(&content[0], content_length);

  Logger::Log("[incoming] ", content, "\n\n");

  return ParseJson(content).value;
}

void WriteMessage(JsonValue message) {
  std::string content = SerializeToString(message);

  Logger::Log("[outgoing] ", content, "\n\n");

  std::cout << kContentLength << content.size() << kProtocolLineEnding;
  std::cout << content << std::flush;
}

namespace {

void ResetCompilationErrorDiagnostics(MessageWriter writer) {
  for (const SourceId& source : DiagnosticsFiles::Get()) {
    PublishDiagnosticsNotification notification;
    notification.set_method("textDocument/publishDiagnostics");

    std::string error_file = SourceFileMap::AbsolutePath(source);
    notification.params().set_uri(error_file);
    // Trigger empty array creation.
    USE(notification.params().diagnostics_size());

    writer(std::move(notification.GetJsonValue()));
  }
  DiagnosticsFiles::Get() = {};
}

// Each notification must contain all diagnostics for a specific file,
// because sending multiple notifications per file resets previously sent
// diagnostics. Thus, two steps are needed:
//   1) collect all notifications in this class.
//   2) send one notification per entry (per file).
class DiagnosticCollector {
 public:
  void AddTorqueMessage(const TorqueMessage& message) {
    if (!ShouldAddMessageOfKind(message.kind)) return;

    SourceId id =
        message.position ? message.position->source : SourceId::Invalid();
    auto& notification = GetOrCreateNotificationForSource(id);

    Diagnostic diagnostic = notification.params().add_diagnostics();
    diagnostic.set_severity(ServerityFor(message.kind));
    diagnostic.set_message(message.message);
    diagnostic.set_source("Torque Compiler");

    if (message.position) {
      PopulateRangeFromSourcePosition(diagnostic.range(), *message.position);
    }
  }

  std::map<SourceId, PublishDiagnosticsNotification>& notifications() {
    return notifications_;
  }

 private:
  PublishDiagnosticsNotification& GetOrCreateNotificationForSource(
      SourceId id) {
    auto iter = notifications_.find(id);
    if (iter != notifications_.end()) return iter->second;

    PublishDiagnosticsNotification& notification = notifications_[id];
    notification.set_method("textDocument/publishDiagnostics");

    std::string file =
        id.IsValid() ? SourceFileMap::AbsolutePath(id) : "<unknown>";
    notification.params().set_uri(file);
    return notification;
  }

  bool ShouldAddMessageOfKind(TorqueMessage::Kind kind) {
    // An error can easily cause a lot of false positive lint messages, due to
    // unused variables, macros, etc. Thus we suppress subsequent lint messages
    // when there are errors.
    switch (kind) {
      case TorqueMessage::Kind::kError:
        suppress_lint_messages_ = true;
        return true;
      case TorqueMessage::Kind::kLint:
        if (suppress_lint_messages_) return false;
        return true;
    }
  }

  void PopulateRangeFromSourcePosition(Range range,
                                       const SourcePosition& position) {
    range.start().set_line(position.start.line);
    range.start().set_character(position.start.column);
    range.end().set_line(position.end.line);
    range.end().set_character(position.end.column);
  }

  Diagnostic::DiagnosticSeverity ServerityFor(TorqueMessage::Kind kind) {
    switch (kind) {
      case TorqueMessage::Kind::kError:
        return Diagnostic::kError;
      case TorqueMessage::Kind::kLint:
        return Diagnostic::kWarning;
    }
  }

  std::map<SourceId, PublishDiagnosticsNotification> notifications_;
  bool suppress_lint_messages_ = false;
};

void SendCompilationDiagnostics(const TorqueCompilerResult& result,
                                MessageWriter writer) {
  DiagnosticCollector collector;

  // TODO(szuend): Split up messages by SourceId and sort them by line number.
  for (const TorqueMessage& message : result.messages) {
    collector.AddTorqueMessage(message);
  }

  for (auto& pair : collector.notifications()) {
    PublishDiagnosticsNotification& notification = pair.second;
    writer(std::move(notification.GetJsonValue()));

    // Record all source files for which notifications are sent, so they
    // can be reset before the next compiler run.
    const SourceId& source = pair.first;
    if (source.IsValid()) DiagnosticsFiles::Get().push_back(source);
  }
}

}  // namespace

void CompilationFinished(TorqueCompilerResult result, MessageWriter writer) {
  LanguageServerData::Get() = std::move(result.language_server_data);
  SourceFileMap::Get() = *result.source_file_map;

  SendCompilationDiagnostics(result, writer);
}

namespace {

void RecompileTorque(MessageWriter writer) {
  Logger::Log("[info] Start compilation run ...\n");

  TorqueCompilerOptions options;
  options.output_directory = "";
  options.collect_language_server_data = true;
  options.force_assert_statements = true;

  TorqueCompilerResult result = CompileTorque(TorqueFileList::Get(), options);

  Logger::Log("[info] Finished compilation run ...\n");

  CompilationFinished(std::move(result), writer);
}

void RecompileTorqueWithDiagnostics(MessageWriter writer) {
  ResetCompilationErrorDiagnostics(writer);
  RecompileTorque(writer);
}

void HandleInitializeRequest(InitializeRequest request, MessageWriter writer) {
  InitializeResponse response;
  response.set_id(request.id());
  response.result().capabilities().textDocumentSync();
  response.result().capabilities().set_definitionProvider(true);
  response.result().capabilities().set_documentSymbolProvider(true);

  // TODO(szuend): Register for document synchronisation here,
  //               so we work with the content that the client
  //               provides, not directly read from files.
  // TODO(szuend): Check that the client actually supports dynamic
  //               "workspace/didChangeWatchedFiles" capability.
  // TODO(szuend): Check if client supports "LocationLink". This will
  //               influence the result of "goto definition".
  writer(std::move(response.GetJsonValue()));
}

void HandleInitializedNotification(MessageWriter writer) {
  RegistrationRequest request;
  // TODO(szuend): The language server needs a "global" request id counter.
  request.set_id(2000);
  request.set_method("client/registerCapability");

  Registration reg = request.params().add_registrations();
  auto options =
      reg.registerOptions<DidChangeWatchedFilesRegistrationOptions>();
  FileSystemWatcher watcher = options.add_watchers();
  watcher.set_globPattern("**/*.tq");
  watcher.set_kind(FileSystemWatcher::WatchKind::kAll);

  reg.set_id("did-change-id");
  reg.set_method("workspace/didChangeWatchedFiles");

  writer(std::move(request.GetJsonValue()));
}

void HandleTorqueFileListNotification(TorqueFileListNotification notification,
                                      MessageWriter writer) {
  CHECK_EQ(notification.params().object()["files"].tag, JsonValue::ARRAY);

  std::vector<std::string>& files = TorqueFileList::Get();
  Logger::Log("[info] Initial file list:\n");
  for (const auto& file_json :
       notification.params().object()["files"].ToArray()) {
    CHECK(file_json.IsString());

    // We only consider file URIs (there shouldn't be anything else).
    // Internally we store the URI instead of the path, eliminating the need
    // to encode it again.
    files.push_back(file_json.ToString());
    Logger::Log("    ", file_json.ToString(), "\n");
  }
  RecompileTorqueWithDiagnostics(writer);
}

void HandleGotoDefinitionRequest(GotoDefinitionRequest request,
                                 MessageWriter writer) {
  GotoDefinitionResponse response;
  response.set_id(request.id());

  SourceId id =
      SourceFileMap::GetSourceId(request.params().textDocument().uri());

  // Unknown source files cause an empty response which corresponds with
  // the definition not beeing found.
  if (!id.IsValid()) {
    response.SetNull("result");
    writer(std::move(response.GetJsonValue()));
    return;
  }

  auto pos =
      LineAndColumn::WithUnknownOffset(request.params().position().line(),
                                       request.params().position().character());

  if (auto maybe_definition = LanguageServerData::FindDefinition(id, pos)) {
    SourcePosition definition = *maybe_definition;
    response.result().SetTo(definition);
  } else {
    response.SetNull("result");
  }

  writer(std::move(response.GetJsonValue()));
}

void HandleChangeWatchedFilesNotification(
    DidChangeWatchedFilesNotification notification, MessageWriter writer) {
  // TODO(szuend): Implement updates to the TorqueFile list when create/delete
  //               notifications are received. Currently we simply re-compile.
  RecompileTorqueWithDiagnostics(writer);
}

void HandleDocumentSymbolRequest(DocumentSymbolRequest request,
                                 MessageWriter writer) {
  DocumentSymbolResponse response;
  response.set_id(request.id());

  SourceId id =
      SourceFileMap::GetSourceId(request.params().textDocument().uri());

  for (const auto& symbol : LanguageServerData::SymbolsForSourceId(id)) {
    DCHECK(symbol->IsUserDefined());
    if (symbol->IsMacro()) {
      Macro* macro = Macro::cast(symbol);
      SymbolInformation info = response.add_result();
      info.set_name(macro->ReadableName());
      info.set_kind(SymbolKind::kFunction);
      info.location().SetTo(macro->Position());
    } else if (symbol->IsBuiltin()) {
      Builtin* builtin = Builtin::cast(symbol);
      SymbolInformation info = response.add_result();
      info.set_name(builtin->ReadableName());
      info.set_kind(SymbolKind::kFunction);
      info.location().SetTo(builtin->Position());
    } else if (symbol->IsGenericCallable()) {
      GenericCallable* generic = GenericCallable::cast(symbol);
      SymbolInformation info = response.add_result();
      info.set_name(generic->name());
      info.set_kind(SymbolKind::kFunction);
      info.location().SetTo(generic->Position());
    } else if (symbol->IsTypeAlias()) {
      const Type* type = TypeAlias::cast(symbol)->type();
      SymbolKind kind =
          type->IsClassType() ? SymbolKind::kClass : SymbolKind::kStruct;

      SymbolInformation sym = response.add_result();
      sym.set_name(type->ToString());
      sym.set_kind(kind);
      sym.location().SetTo(symbol->Position());
    }
  }

  // Trigger empty array creation in case no symbols were found.
  USE(response.result_size());

  writer(std::move(response.GetJsonValue()));
}

}  // namespace

void HandleMessage(JsonValue raw_message, MessageWriter writer) {
  Request<bool> request(std::move(raw_message));

  // We ignore responses for now. They are matched to requests
  // by id and don't have a method set.
  // TODO(szuend): Implement proper response handling for requests
  //               that originate from the server.
  if (!request.has_method()) {
    Logger::Log("[info] Unhandled response with id ", request.id(), "\n\n");
    return;
  }

  const std::string method = request.method();
  if (method == "initialize") {
    HandleInitializeRequest(
        InitializeRequest(std::move(request.GetJsonValue())), writer);
  } else if (method == "initialized") {
    HandleInitializedNotification(writer);
  } else if (method == "torque/fileList") {
    HandleTorqueFileListNotification(
        TorqueFileListNotification(std::move(request.GetJsonValue())), writer);
  } else if (method == "textDocument/definition") {
    HandleGotoDefinitionRequest(
        GotoDefinitionRequest(std::move(request.GetJsonValue())), writer);
  } else if (method == "workspace/didChangeWatchedFiles") {
    HandleChangeWatchedFilesNotification(
        DidChangeWatchedFilesNotification(std::move(request.GetJsonValue())),
        writer);
  } else if (method == "textDocument/documentSymbol") {
    HandleDocumentSymbolRequest(
        DocumentSymbolRequest(std::move(request.GetJsonValue())), writer);
  } else {
    Logger::Log("[error] Message of type ", method, " is not handled!\n\n");
  }
}

}  // namespace ls
}  // namespace torque
}  // namespace internal
}  // namespace v8
```