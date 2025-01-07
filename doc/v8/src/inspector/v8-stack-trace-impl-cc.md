Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for a functional description of `v8-stack-trace-impl.cc`, along with explanations, examples, and common errors if applicable. It also mentions the `.tq` extension (Torque).

2. **Initial Skim and High-Level Purpose:** Read through the code quickly to get a general idea. Keywords like `StackTrace`, `StackFrame`, `Debugger`, `Inspector`, and functions like `capture`, `buildInspectorObject`, `toString` immediately suggest this file deals with capturing and representing stack traces for debugging purposes within V8's inspector. The namespace `v8_inspector` reinforces this.

3. **Identify Key Classes and Structures:**  Pay attention to class definitions: `V8StackTraceId`, `StackFrame`, `V8StackTraceImpl`, and `AsyncStackTrace`. These are the core building blocks. Note their member variables and methods.

4. **Analyze Each Class/Structure:**  Go through each class and structure in more detail.

   * **`V8StackTraceId`:**  Focus on its purpose: identifying stack traces. Notice the `id` and `debugger_id`. The `ToString` and constructor from JSON suggest it's used for serialization and deserialization, likely for communication with the debugger front-end. The `should_pause` flag hints at debugger control.

   * **`StackFrame`:** This clearly represents a single frame in the stack. Note the attributes: `functionName`, `scriptId`, `sourceURL`, `lineNumber`, `columnNumber`. The `buildInspectorObject` method is crucial, as it converts this internal representation to a format suitable for the inspector protocol. The `isEqual` method is used for comparison.

   * **`V8StackTraceImpl`:** This class seems to *manage* a collection of `StackFrame` objects. The `capture` method is likely the entry point for generating a stack trace. The `buildInspectorObjectImpl` methods convert the internal stack trace representation for the inspector. The `toString` method is for human-readable output. The `StackFrameIterator` is an internal helper for traversing the stack frames. The methods like `topSourceURL`, `topLineNumber`, etc., provide access to the topmost frame information.

   * **`AsyncStackTrace`:** This class appears to handle asynchronous call stacks. It has a `parent` which allows chaining asynchronous calls. The `capture` method for this class is similar to the one in `V8StackTraceImpl`, but specifically for asynchronous scenarios. The `store` method suggests a mechanism for tracking asynchronous stack traces.

5. **Trace Key Functionality:**  Focus on the important methods:

   * **`capture` (in both `V8StackTraceImpl` and `AsyncStackTrace`):** How is a stack trace captured? It uses `v8::StackTrace::CurrentStackTrace`. What options are used (`stackTraceOptions`)?  What is the purpose of `maxStackSize`?

   * **`buildInspectorObject` (in `StackFrame`, `V8StackTraceImpl`, and `AsyncStackTrace`):** How is the internal representation converted to the protocol format? Notice the use of `protocol::Runtime::CallFrame` and `protocol::Runtime::StackTrace`. Pay attention to the handling of asynchronous parents and external parents.

   * **`toString` (in `V8StackTraceImpl`):** How is the stack trace formatted for display?

6. **Connect to JavaScript (if applicable):**  Consider how the concepts in this C++ code relate to JavaScript. The stack trace concept is directly exposed in JavaScript through errors and debugger tools. Think about `console.trace()`, error stack properties, and how debuggers display call stacks. This leads to the JavaScript examples.

7. **Infer Code Logic and Potential Inputs/Outputs:** For methods like `isEqual` and `isEqualIgnoringTopFrame`, think about example inputs (two `V8StackTraceImpl` instances) and what the output (boolean) would represent.

8. **Identify Potential User Errors:**  Consider common mistakes JavaScript developers make that relate to stack traces. Not understanding asynchronous code flow and difficulty debugging asynchronous operations are prime examples.

9. **Address the `.tq` Question:** The request specifically asks about the `.tq` extension. Research or rely on prior knowledge about V8's build system to know that `.tq` files are for Torque. Since this file is `.cc`, it's standard C++.

10. **Structure the Answer:** Organize the findings logically. Start with a general summary of the file's purpose. Then, detail the functionality of each key class. Provide JavaScript examples where relevant. Explain code logic with input/output examples. Address potential user errors. Finally, answer the `.tq` question.

11. **Refine and Elaborate:** Review the generated explanation for clarity, accuracy, and completeness. Add more details or examples where needed. Ensure the language is easy to understand, even for someone who might not be deeply familiar with V8 internals. For example, explicitly stating what "inspector protocol" refers to adds clarity.

Self-Correction/Refinement Example during the process:

* **Initial thought:**  Maybe `V8StackTraceId` is just a simple ID.
* **Correction:**  Wait, it also has `debugger_id` and `should_pause`, and it's serialized to JSON. This suggests it's more than just a local ID and is used for communication and potentially controlling the debugger. This deeper understanding leads to a more accurate explanation.

By following these steps, iteratively analyzing the code, and connecting the C++ concepts to JavaScript and debugging practices, a comprehensive and informative explanation can be generated.
这个 `v8/src/inspector/v8-stack-trace-impl.cc` 文件是 V8 引擎中负责实现堆栈跟踪相关功能的 C++ 源代码。它的主要功能是**捕获、表示和操作 JavaScript 代码执行时的调用堆栈信息，并将其转换为可以被调试器和检查器使用的格式**。

以下是该文件更详细的功能列表：

**1. 堆栈帧 (Stack Frame) 的表示和创建:**

* **`StackFrame` 类:**  定义了堆栈中的一个帧，包含函数名、脚本 ID、源代码 URL、行号和列号等信息。
* **`toFramesVector` 函数:**  将 V8 引擎原生的 `v8::StackTrace` 对象转换为 `std::vector<std::shared_ptr<StackFrame>>`，这是 inspector 模块使用的堆栈帧表示形式。在这个过程中，它会调用 `debugger->symbolize` 来获取更详细的符号信息。

**2. 堆栈跟踪 (Stack Trace) 的表示和创建:**

* **`V8StackTraceImpl` 类:** 表示一个完整的堆栈跟踪。它包含一个 `StackFrame` 对象的向量，以及与异步调用相关的父堆栈跟踪信息。
* **`V8StackTraceImpl::capture` 静态方法:**  这是捕获当前 JavaScript 执行堆栈的关键方法。它会调用 `v8::StackTrace::CurrentStackTrace` 来获取 V8 引擎的原始堆栈信息，并使用 `toFramesVector` 将其转换为 inspector 使用的格式。
* **`V8StackTraceImpl::create` 静态方法:** 基于已有的 `v8::StackTrace` 对象创建 `V8StackTraceImpl` 实例。

**3. 异步堆栈跟踪 (Async Stack Trace) 的支持:**

* **`AsyncStackTrace` 类:**  用于表示异步操作的调用堆栈。它与 `V8StackTraceImpl` 类似，但可以链接到父异步堆栈跟踪，从而形成一个异步调用链。
* **`AsyncStackTrace::capture` 静态方法:** 捕获异步操作发生时的堆栈，并可以指定一个描述信息。
* **父堆栈跟踪链接:** `V8StackTraceImpl` 和 `AsyncStackTrace` 都维护了对父异步堆栈跟踪的引用 (`m_asyncParent`)，用于构建完整的异步调用链。

**4. 转换为 Inspector 协议格式:**

* **`StackFrame::buildInspectorObject` 方法:** 将 `StackFrame` 对象转换为 Chrome DevTools Protocol (CDP) 中定义的 `protocol::Runtime::CallFrame` 对象，以便调试器可以理解和展示这些信息。
* **`V8StackTraceImpl::buildInspectorObjectImpl` 和 `AsyncStackTrace::buildInspectorObject` 方法:** 将 `V8StackTraceImpl` 和 `AsyncStackTrace` 对象转换为 CDP 中定义的 `protocol::Runtime::StackTrace` 对象，包含一个调用帧数组和可能的父堆栈跟踪信息。

**5. 堆栈跟踪 ID 的管理:**

* **`V8StackTraceId` 类:**  用于唯一标识一个堆栈跟踪，特别是用于关联异步操作的堆栈。它包含一个 ID 和一个 debugger ID。
* **序列化和反序列化:** `V8StackTraceId` 提供了 `ToString` 方法将其序列化为 JSON 格式，并提供了从 JSON 字符串创建实例的构造函数。这允许在不同的组件之间传递堆栈跟踪 ID。

**6. 实用工具方法:**

* **`V8StackTraceImpl::toString`:**  将堆栈跟踪格式化为易于阅读的字符串。
* **`V8StackTraceImpl::isEqualIgnoringTopFrame`:**  比较两个堆栈跟踪，忽略顶部的调用帧。
* **`V8StackTraceImpl::StackFrameIterator`:**  一个用于遍历 `V8StackTraceImpl` 和其父异步堆栈跟踪中的所有帧的迭代器。

**关于 `.tq` 后缀：**

该文件名为 `v8-stack-trace-impl.cc`，以 `.cc` 结尾，**因此它不是一个 V8 Torque 源代码文件**。 Torque 文件通常以 `.tq` 结尾。 Torque 是一种用于 V8 内部实现的领域特定语言，用于生成高效的 C++ 代码。

**与 JavaScript 功能的关系及示例：**

这个文件直接支持了 JavaScript 中与错误和调试相关的核心功能，例如：

* **`Error.stack` 属性:**  当 JavaScript 代码抛出错误时，`Error` 对象会包含一个 `stack` 属性，其中包含了错误发生时的调用堆栈信息。`v8-stack-trace-impl.cc` 中的代码负责生成和格式化这个堆栈信息。
* **`console.trace()` 方法:**  调用 `console.trace()` 会在控制台中打印当前的调用堆栈。这个功能也依赖于 `v8-stack-trace-impl.cc` 中捕获堆栈的功能。
* **调试器 (Debugger) 的堆栈查看:**  当使用 Chrome DevTools 或 Node.js 调试器进行断点调试时，你看到的调用堆栈信息就是由这个文件中的代码生成的，并按照 Chrome DevTools Protocol 规定的格式传输给调试器。
* **异步操作的堆栈信息:**  对于 `Promise`、`async/await` 等异步操作，`v8-stack-trace-impl.cc` 提供了捕获和链接异步调用堆栈的能力，使得调试异步代码更加容易。

**JavaScript 示例：**

```javascript
function foo() {
  bar();
}

function bar() {
  console.trace("当前调用栈：");
  throw new Error("Something went wrong!");
}

try {
  foo();
} catch (e) {
  console.error("捕获到错误：", e);
  console.error("错误堆栈：", e.stack);
}

async function asyncOperation() {
  await delay(100);
  throw new Error("Async error!");
}

async function main() {
  try {
    await asyncOperation();
  } catch (e) {
    console.error("Async 错误堆栈：", e.stack);
  }
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

main();
```

在这个例子中：

* `console.trace()` 会触发 `v8-stack-trace-impl.cc` 中的堆栈捕获功能，并在控制台打印调用栈。
* `throw new Error()` 创建的错误对象的 `stack` 属性包含了调用 `bar` 和 `foo` 的堆栈信息，这由 `v8-stack-trace-impl.cc` 生成。
* `asyncOperation` 中抛出的异步错误，其 `stack` 属性也包含了异步调用的上下文信息（如果 V8 引擎支持异步堆栈跟踪）。

**代码逻辑推理示例：**

假设有以下 JavaScript 代码：

```javascript
function a() {
  b();
}

function b() {
  c();
}

function c() {
  // 捕获堆栈
  debugger;
}

a();
```

**假设输入：**  执行到 `debugger` 语句时，V8 引擎内部的状态。

**输出 (`V8StackTraceImpl::capture` 的可能输出):**  一个 `V8StackTraceImpl` 对象，其内部的 `m_frames` 向量可能包含三个 `StackFrame` 对象，分别对应函数 `c`、`b` 和 `a` 的调用。每个 `StackFrame` 对象会包含相应的函数名、脚本 ID、行号等信息。

例如，`m_frames` 可能如下所示 (简化表示)：

```
[
  StackFrame { functionName: "c", scriptId: 1, sourceURL: "your_script.js", lineNumber: 8, columnNumber: 1 },
  StackFrame { functionName: "b", scriptId: 1, sourceURL: "your_script.js", lineNumber: 4, columnNumber: 1 },
  StackFrame { functionName: "a", scriptId: 1, sourceURL: "your_script.js", lineNumber: 1, columnNumber: 1 }
]
```

**涉及用户常见的编程错误：**

* **不理解异步代码的堆栈信息：**  在处理 `Promise` 或 `async/await` 时，如果出现错误，开发者可能只看到 Promise 内部的堆栈，而无法追踪到异步操作发起的源头。`v8-stack-trace-impl.cc` 中异步堆栈跟踪的支持旨在解决这个问题，但开发者需要理解如何解读异步堆栈信息。
    ```javascript
    async function fetchData() {
      const response = await fetch('invalid_url');
      const data = await response.json(); // 可能在这里抛出错误
      return data;
    }

    async function processData() {
      try {
        await fetchData();
      } catch (error) {
        console.error("处理数据时出错：", error.stack);
      }
    }

    processData();
    ```
    早期的 JavaScript 引擎可能只显示 `response.json()` 内部的错误堆栈，而无法直接看到 `fetchData` 和 `processData` 的调用关系。现代 V8 引擎的异步堆栈跟踪可以提供更完整的调用链。

* **过度依赖 `console.log` 而不使用 `console.trace` 或调试器：**  当代码逻辑复杂时，仅仅使用 `console.log` 输出变量值可能难以定位问题。`console.trace()` 可以帮助开发者快速了解代码的执行路径。
    ```javascript
    function calculate(a, b) {
      console.log("a:", a, "b:", b);
      return a / b;
    }

    function process(x) {
      const result = calculate(x, 0); // 这里可能会导致错误
      console.log("result:", result);
      return result * 2;
    }

    process(10);
    ```
    在这个例子中，`calculate(x, 0)` 会导致除零错误。使用 `console.trace()` 或调试器可以更容易地定位到 `calculate` 函数的调用位置。

* **错误处理不当，导致堆栈信息丢失：**  如果 `try...catch` 块没有正确地记录或传播错误信息，原始的堆栈信息可能会丢失，使得问题排查更加困难。
    ```javascript
    function riskyOperation() {
      throw new Error("Something went wrong in riskyOperation");
    }

    function handleOperation() {
      try {
        riskyOperation();
      } catch (error) {
        console.error("发生错误，但未记录堆栈"); // 错误堆栈信息丢失
        throw "Error in handleOperation"; // 抛出一个新的字符串错误，没有堆栈信息
      }
    }

    try {
      handleOperation();
    } catch (e) {
      console.error("最终捕获的错误：", e); // 这里的 e 只是一个字符串，没有原始的堆栈信息
    }
    ```
    正确的做法是在 `catch` 块中记录原始错误的堆栈信息，或者重新抛出原始错误。

总而言之，`v8/src/inspector/v8-stack-trace-impl.cc` 是 V8 引擎中至关重要的组成部分，它为 JavaScript 的错误处理、调试和性能分析等功能提供了基础的堆栈跟踪能力。理解它的功能有助于开发者更好地理解 JavaScript 的执行机制和调试过程。

Prompt: 
```
这是目录为v8/src/inspector/v8-stack-trace-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-stack-trace-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if defined(V8_OS_STARBOARD)
#include "starboard/system.h"
#define __builtin_abort SbSystemBreakIntoDebugger
#endif

#include "src/inspector/v8-stack-trace-impl.h"

#include <algorithm>
#include <memory>
#include <vector>

#include "../../third_party/inspector_protocol/crdtp/json.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/tracing/trace-event.h"

using v8_crdtp::json::ConvertJSONToCBOR;

namespace v8_inspector {
namespace {

static const char kId[] = "id";
static const char kDebuggerId[] = "debuggerId";
static const char kShouldPause[] = "shouldPause";

static const v8::StackTrace::StackTraceOptions stackTraceOptions =
    static_cast<v8::StackTrace::StackTraceOptions>(
        v8::StackTrace::kDetailed |
        v8::StackTrace::kExposeFramesAcrossSecurityOrigins);

std::vector<std::shared_ptr<StackFrame>> toFramesVector(
    V8Debugger* debugger, v8::Local<v8::StackTrace> v8StackTrace,
    int maxStackSize) {
  DCHECK(debugger->isolate()->InContext());
  int frameCount = std::min(v8StackTrace->GetFrameCount(), maxStackSize);

  TRACE_EVENT1(
      TRACE_DISABLED_BY_DEFAULT("v8.inspector") "," TRACE_DISABLED_BY_DEFAULT(
          "v8.stack_trace"),
      "toFramesVector", "frameCount", frameCount);

  std::vector<std::shared_ptr<StackFrame>> frames(frameCount);
  for (int i = 0; i < frameCount; ++i) {
    frames[i] =
        debugger->symbolize(v8StackTrace->GetFrame(debugger->isolate(), i));
  }
  return frames;
}

std::unique_ptr<protocol::Runtime::StackTrace> buildInspectorObjectCommon(
    V8Debugger* debugger,
    const std::vector<std::shared_ptr<StackFrame>>& frames,
    const String16& description,
    const std::shared_ptr<AsyncStackTrace>& asyncParent,
    const V8StackTraceId& externalParent, int maxAsyncDepth) {
  if (asyncParent && frames.empty() &&
      description == asyncParent->description()) {
    return asyncParent->buildInspectorObject(debugger, maxAsyncDepth);
  }

  auto inspectorFrames =
      std::make_unique<protocol::Array<protocol::Runtime::CallFrame>>();
  for (const std::shared_ptr<StackFrame>& frame : frames) {
    V8InspectorClient* client = nullptr;
    if (debugger && debugger->inspector())
      client = debugger->inspector()->client();
    inspectorFrames->emplace_back(frame->buildInspectorObject(client));
  }
  std::unique_ptr<protocol::Runtime::StackTrace> stackTrace =
      protocol::Runtime::StackTrace::create()
          .setCallFrames(std::move(inspectorFrames))
          .build();
  if (!description.isEmpty()) stackTrace->setDescription(description);
  if (asyncParent) {
    if (maxAsyncDepth > 0) {
      stackTrace->setParent(
          asyncParent->buildInspectorObject(debugger, maxAsyncDepth - 1));
    } else if (debugger) {
      stackTrace->setParentId(
          protocol::Runtime::StackTraceId::create()
              .setId(stackTraceIdToString(
                  AsyncStackTrace::store(debugger, asyncParent)))
              .build());
    }
  }
  if (!externalParent.IsInvalid()) {
    stackTrace->setParentId(
        protocol::Runtime::StackTraceId::create()
            .setId(stackTraceIdToString(externalParent.id))
            .setDebuggerId(
                internal::V8DebuggerId(externalParent.debugger_id).toString())
            .build());
  }
  return stackTrace;
}

}  // namespace

V8StackTraceId::V8StackTraceId()
    : id(0), debugger_id(internal::V8DebuggerId().pair()) {}

V8StackTraceId::V8StackTraceId(uintptr_t id,
                               const std::pair<int64_t, int64_t> debugger_id)
    : id(id), debugger_id(debugger_id) {}

V8StackTraceId::V8StackTraceId(uintptr_t id,
                               const std::pair<int64_t, int64_t> debugger_id,
                               bool should_pause)
    : id(id), debugger_id(debugger_id), should_pause(should_pause) {}

V8StackTraceId::V8StackTraceId(StringView json)
    : id(0), debugger_id(internal::V8DebuggerId().pair()) {
  if (json.length() == 0) return;
  std::vector<uint8_t> cbor;
  if (json.is8Bit()) {
    ConvertJSONToCBOR(
        v8_crdtp::span<uint8_t>(json.characters8(), json.length()), &cbor);
  } else {
    ConvertJSONToCBOR(
        v8_crdtp::span<uint16_t>(json.characters16(), json.length()), &cbor);
  }
  auto dict = protocol::DictionaryValue::cast(
      protocol::Value::parseBinary(cbor.data(), cbor.size()));
  if (!dict) return;
  String16 s;
  if (!dict->getString(kId, &s)) return;
  bool isOk = false;
  int64_t parsedId = s.toInteger64(&isOk);
  if (!isOk || !parsedId) return;
  if (!dict->getString(kDebuggerId, &s)) return;
  internal::V8DebuggerId debuggerId(s);
  if (!debuggerId.isValid()) return;
  if (!dict->getBoolean(kShouldPause, &should_pause)) return;
  id = parsedId;
  debugger_id = debuggerId.pair();
}

bool V8StackTraceId::IsInvalid() const { return !id; }

std::unique_ptr<StringBuffer> V8StackTraceId::ToString() {
  if (IsInvalid()) return nullptr;
  auto dict = protocol::DictionaryValue::create();
  dict->setString(kId, String16::fromInteger64(id));
  dict->setString(kDebuggerId, internal::V8DebuggerId(debugger_id).toString());
  dict->setBoolean(kShouldPause, should_pause);
  std::vector<uint8_t> json;
  v8_crdtp::json::ConvertCBORToJSON(v8_crdtp::SpanFrom(dict->Serialize()),
                                    &json);
  return StringBufferFrom(std::move(json));
}

StackFrame::StackFrame(String16&& functionName, int scriptId,
                       String16&& sourceURL, int lineNumber, int columnNumber,
                       bool hasSourceURLComment)
    : m_functionName(std::move(functionName)),
      m_scriptId(scriptId),
      m_sourceURL(std::move(sourceURL)),
      m_lineNumber(lineNumber),
      m_columnNumber(columnNumber),
      m_hasSourceURLComment(hasSourceURLComment) {
  DCHECK_NE(v8::Message::kNoLineNumberInfo, m_lineNumber + 1);
  DCHECK_NE(v8::Message::kNoColumnInfo, m_columnNumber + 1);
}

const String16& StackFrame::functionName() const { return m_functionName; }

int StackFrame::scriptId() const { return m_scriptId; }

const String16& StackFrame::sourceURL() const { return m_sourceURL; }

int StackFrame::lineNumber() const { return m_lineNumber; }

int StackFrame::columnNumber() const { return m_columnNumber; }

std::unique_ptr<protocol::Runtime::CallFrame> StackFrame::buildInspectorObject(
    V8InspectorClient* client) const {
  String16 frameUrl;
  const char* dataURIPrefix = "data:";
  if (m_sourceURL.substring(0, strlen(dataURIPrefix)) != dataURIPrefix) {
    frameUrl = m_sourceURL;
  }

  if (client && !m_hasSourceURLComment && frameUrl.length() > 0) {
    std::unique_ptr<StringBuffer> url =
        client->resourceNameToUrl(toStringView(m_sourceURL));
    if (url) {
      frameUrl = toString16(url->string());
    }
  }
  return protocol::Runtime::CallFrame::create()
      .setFunctionName(m_functionName)
      .setScriptId(String16::fromInteger(m_scriptId))
      .setUrl(frameUrl)
      .setLineNumber(m_lineNumber)
      .setColumnNumber(m_columnNumber)
      .build();
}

bool StackFrame::isEqual(StackFrame* frame) const {
  return m_scriptId == frame->m_scriptId &&
         m_lineNumber == frame->m_lineNumber &&
         m_columnNumber == frame->m_columnNumber;
}

// static
std::unique_ptr<V8StackTraceImpl> V8StackTraceImpl::create(
    V8Debugger* debugger, v8::Local<v8::StackTrace> v8StackTrace,
    int maxStackSize) {
  DCHECK(debugger);

  v8::Isolate* isolate = debugger->isolate();
  v8::HandleScope scope(isolate);

  std::vector<std::shared_ptr<StackFrame>> frames;
  if (!v8StackTrace.IsEmpty() && v8StackTrace->GetFrameCount()) {
    frames = toFramesVector(debugger, v8StackTrace, maxStackSize);
  }

  int maxAsyncDepth = debugger->maxAsyncCallChainDepth();
  std::shared_ptr<AsyncStackTrace> asyncParent;
  V8StackTraceId externalParent;
  if (!v8StackTrace.IsEmpty()) {
    debugger->asyncParentFor(v8StackTrace->GetID(), &asyncParent,
                             &externalParent);
  }
  if (frames.empty() && !asyncParent && externalParent.IsInvalid()) return {};
  return std::unique_ptr<V8StackTraceImpl>(new V8StackTraceImpl(
      std::move(frames), maxAsyncDepth, asyncParent, externalParent));
}

// static
std::unique_ptr<V8StackTraceImpl> V8StackTraceImpl::capture(
    V8Debugger* debugger, int maxStackSize) {
  DCHECK(debugger);

  TRACE_EVENT1(
      TRACE_DISABLED_BY_DEFAULT("v8.inspector") "," TRACE_DISABLED_BY_DEFAULT(
          "v8.stack_trace"),
      "V8StackTraceImpl::capture", "maxFrameCount", maxStackSize);

  v8::Isolate* isolate = debugger->isolate();
  v8::HandleScope handleScope(isolate);
  v8::Local<v8::StackTrace> v8StackTrace;
  if (isolate->InContext()) {
    v8StackTrace = v8::StackTrace::CurrentStackTrace(isolate, maxStackSize,
                                                     stackTraceOptions);
  }
  return V8StackTraceImpl::create(debugger, v8StackTrace, maxStackSize);
}

V8StackTraceImpl::V8StackTraceImpl(
    std::vector<std::shared_ptr<StackFrame>> frames, int maxAsyncDepth,
    std::shared_ptr<AsyncStackTrace> asyncParent,
    const V8StackTraceId& externalParent)
    : m_frames(std::move(frames)),
      m_maxAsyncDepth(maxAsyncDepth),
      m_asyncParent(std::move(asyncParent)),
      m_externalParent(externalParent) {}

V8StackTraceImpl::~V8StackTraceImpl() = default;

std::unique_ptr<V8StackTrace> V8StackTraceImpl::clone() {
  return std::unique_ptr<V8StackTrace>(new V8StackTraceImpl(
      m_frames, 0, std::shared_ptr<AsyncStackTrace>(), V8StackTraceId()));
}

StringView V8StackTraceImpl::firstNonEmptySourceURL() const {
  StackFrameIterator current(this);
  while (!current.done()) {
    if (current.frame()->sourceURL().length()) {
      return toStringView(current.frame()->sourceURL());
    }
    current.next();
  }
  return StringView();
}

bool V8StackTraceImpl::isEmpty() const { return m_frames.empty(); }

StringView V8StackTraceImpl::topSourceURL() const {
  return toStringView(m_frames[0]->sourceURL());
}

int V8StackTraceImpl::topLineNumber() const {
  return m_frames[0]->lineNumber() + 1;
}

int V8StackTraceImpl::topColumnNumber() const {
  return m_frames[0]->columnNumber() + 1;
}

int V8StackTraceImpl::topScriptId() const { return m_frames[0]->scriptId(); }

StringView V8StackTraceImpl::topFunctionName() const {
  return toStringView(m_frames[0]->functionName());
}

std::vector<V8StackFrame> V8StackTraceImpl::frames() const {
  std::vector<V8StackFrame> ret;
  ret.reserve(m_frames.size());

  for (const auto& frame : m_frames) {
    if (frame) {
      ret.emplace_back(V8StackFrame{
          toStringView(frame->sourceURL()), toStringView(frame->functionName()),
          frame->lineNumber() + 1, frame->columnNumber() + 1});
    }
  }

  return ret;
}

std::unique_ptr<protocol::Runtime::StackTrace>
V8StackTraceImpl::buildInspectorObjectImpl(V8Debugger* debugger) const {
  return buildInspectorObjectImpl(debugger, m_maxAsyncDepth);
}

std::unique_ptr<protocol::Runtime::StackTrace>
V8StackTraceImpl::buildInspectorObjectImpl(V8Debugger* debugger,
                                           int maxAsyncDepth) const {
  return buildInspectorObjectCommon(debugger, m_frames, String16(),
                                    m_asyncParent.lock(), m_externalParent,
                                    maxAsyncDepth);
}

std::unique_ptr<protocol::Runtime::API::StackTrace>
V8StackTraceImpl::buildInspectorObject(int maxAsyncDepth) const {
  return buildInspectorObjectImpl(nullptr,
                                  std::min(maxAsyncDepth, m_maxAsyncDepth));
}

std::unique_ptr<StringBuffer> V8StackTraceImpl::toString() const {
  String16Builder stackTrace;
  for (size_t i = 0; i < m_frames.size(); ++i) {
    const StackFrame& frame = *m_frames[i];
    stackTrace.append("\n    at " + (frame.functionName().length()
                                         ? frame.functionName()
                                         : "(anonymous function)"));
    stackTrace.append(" (");
    stackTrace.append(frame.sourceURL());
    stackTrace.append(':');
    stackTrace.append(String16::fromInteger(frame.lineNumber() + 1));
    stackTrace.append(':');
    stackTrace.append(String16::fromInteger(frame.columnNumber() + 1));
    stackTrace.append(')');
  }
  return StringBufferFrom(stackTrace.toString());
}

bool V8StackTraceImpl::isEqualIgnoringTopFrame(
    V8StackTraceImpl* stackTrace) const {
  StackFrameIterator current(this);
  StackFrameIterator target(stackTrace);

  current.next();
  target.next();
  while (!current.done() && !target.done()) {
    if (!current.frame()->isEqual(target.frame())) {
      return false;
    }
    current.next();
    target.next();
  }
  return current.done() == target.done();
}

V8StackTraceImpl::StackFrameIterator::StackFrameIterator(
    const V8StackTraceImpl* stackTrace)
    : m_currentIt(stackTrace->m_frames.begin()),
      m_currentEnd(stackTrace->m_frames.end()),
      m_parent(stackTrace->m_asyncParent.lock().get()) {}

void V8StackTraceImpl::StackFrameIterator::next() {
  if (m_currentIt == m_currentEnd) return;
  ++m_currentIt;
  while (m_currentIt == m_currentEnd && m_parent) {
    const std::vector<std::shared_ptr<StackFrame>>& frames = m_parent->frames();
    m_currentIt = frames.begin();
    m_currentEnd = frames.end();
    m_parent = m_parent->parent().lock().get();
  }
}

bool V8StackTraceImpl::StackFrameIterator::done() {
  return m_currentIt == m_currentEnd;
}

StackFrame* V8StackTraceImpl::StackFrameIterator::frame() {
  return m_currentIt->get();
}

// static
std::shared_ptr<AsyncStackTrace> AsyncStackTrace::capture(
    V8Debugger* debugger, const String16& description, bool skipTopFrame) {
  DCHECK(debugger);

  int maxStackSize = debugger->maxCallStackSizeToCapture();
  TRACE_EVENT1(
      TRACE_DISABLED_BY_DEFAULT("v8.inspector") "," TRACE_DISABLED_BY_DEFAULT(
          "v8.stack_trace"),
      "AsyncStackTrace::capture", "maxFrameCount", maxStackSize);

  v8::Isolate* isolate = debugger->isolate();
  v8::HandleScope handleScope(isolate);

  std::vector<std::shared_ptr<StackFrame>> frames;
  std::shared_ptr<AsyncStackTrace> asyncParent;
  V8StackTraceId externalParent;
  if (isolate->InContext()) {
    v8::Local<v8::StackTrace> v8StackTrace = v8::StackTrace::CurrentStackTrace(
        isolate, maxStackSize, stackTraceOptions);
    frames = toFramesVector(debugger, v8StackTrace, maxStackSize);
    if (skipTopFrame && !frames.empty()) {
      frames.erase(frames.begin());
    }

    debugger->asyncParentFor(v8StackTrace->GetID(), &asyncParent,
                             &externalParent);
  }

  if (frames.empty() && !asyncParent && externalParent.IsInvalid())
    return nullptr;

  if (asyncParent && frames.empty() &&
      (asyncParent->m_description == description || description.isEmpty())) {
    return asyncParent;
  }

  return std::shared_ptr<AsyncStackTrace>(new AsyncStackTrace(
      description, std::move(frames), asyncParent, externalParent));
}

AsyncStackTrace::AsyncStackTrace(
    const String16& description,
    std::vector<std::shared_ptr<StackFrame>> frames,
    std::shared_ptr<AsyncStackTrace> asyncParent,
    const V8StackTraceId& externalParent)
    : m_id(0),
      m_description(description),
      m_frames(std::move(frames)),
      m_asyncParent(std::move(asyncParent)),
      m_externalParent(externalParent) {}

std::unique_ptr<protocol::Runtime::StackTrace>
AsyncStackTrace::buildInspectorObject(V8Debugger* debugger,
                                      int maxAsyncDepth) const {
  return buildInspectorObjectCommon(debugger, m_frames, m_description,
                                    m_asyncParent.lock(), m_externalParent,
                                    maxAsyncDepth);
}

uintptr_t AsyncStackTrace::store(V8Debugger* debugger,
                                 std::shared_ptr<AsyncStackTrace> stack) {
  if (stack->m_id) return stack->m_id;
  stack->m_id = debugger->storeStackTrace(stack);
  return stack->m_id;
}

const String16& AsyncStackTrace::description() const { return m_description; }

std::weak_ptr<AsyncStackTrace> AsyncStackTrace::parent() const {
  return m_asyncParent;
}

bool AsyncStackTrace::isEmpty() const { return m_frames.empty(); }

}  // namespace v8_inspector

"""

```