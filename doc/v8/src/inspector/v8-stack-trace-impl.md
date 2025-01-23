Response: The user wants to understand the functionality of the C++ source code file `v8-stack-trace-impl.cc` located in the `v8/src/inspector` directory. They also want to know how it relates to JavaScript and see an example.

Here's a breakdown of the thinking process to generate the answer:

1. **Understand the Core Purpose:** The file name itself, "v8-stack-trace-impl.cc," strongly suggests that it deals with the implementation of stack traces within the V8 engine's inspector. Inspectors are used for debugging and profiling JavaScript code.

2. **Analyze Key Classes and Structures:**
    * `V8StackTraceImpl`: This is likely the main class for representing stack traces within the inspector. It holds frames, potentially has an asynchronous parent, and handles serialization for the inspector protocol.
    * `StackFrame`: Represents a single frame in the stack trace, containing information like function name, script ID, URL, line number, and column number.
    * `AsyncStackTrace`: Deals with asynchronous call stacks, linking related stack traces.
    * `V8StackTraceId`: A unique identifier for stack traces, especially useful for asynchronous contexts and across different debugger instances.

3. **Identify Key Functionality by Examining Methods:**
    * `capture()`:  Likely responsible for capturing the current JavaScript call stack.
    * `create()`:  Potentially for creating `V8StackTraceImpl` instances from existing V8 stack trace objects.
    * `buildInspectorObject()`: Crucial for converting the internal stack trace representation into the format expected by the Chrome DevTools Protocol (CDP), which is used by debugging tools.
    * `toString()`:  Provides a human-readable string representation of the stack trace.
    * The iterator (`StackFrameIterator`) is for traversing the possibly chained asynchronous stack frames.
    * `AsyncStackTrace::capture()` and `AsyncStackTrace::store()` are related to capturing and managing asynchronous call stacks.
    * The presence of JSON/CBOR conversion functions suggests serialization and deserialization for communication with the inspector frontend.

4. **Trace the Data Flow:** Observe how V8's internal stack trace information (`v8::StackTrace`) is converted into the inspector's representation (`protocol::Runtime::StackTrace`). Note the involvement of `V8Debugger` and `V8InspectorImpl`.

5. **Identify the Relationship with JavaScript:**  The primary connection is that this C++ code *implements* the mechanism for collecting and presenting stack traces that developers see when debugging JavaScript code in their browsers or Node.js. When an error occurs or a breakpoint is hit, the inspector uses this code to get the call stack.

6. **Construct a JavaScript Example:** To illustrate the connection, create a simple JavaScript code snippet that would generate a stack trace. Focus on scenarios that demonstrate both synchronous and potentially asynchronous behavior. Error handling (`try...catch`) and asynchronous operations (`setTimeout`, Promises) are good candidates.

7. **Explain the Code's Functionality in Plain Language:** Summarize the purpose of the file, focusing on:
    * Representing JavaScript call stacks.
    * Handling synchronous and asynchronous stacks.
    * Converting V8 internal representation to the inspector protocol format.
    * Providing unique IDs for stack traces.

8. **Explain the JavaScript Connection:** Clearly articulate how this C++ code makes JavaScript debugging possible by providing the call stack information.

9. **Refine and Structure the Answer:** Organize the information logically, starting with a general summary, then detailing specific functionalities, and finally providing the JavaScript example and explanation. Use clear and concise language.

**(Self-Correction/Refinement during the process):**

* **Initial thought:**  Maybe it's just about formatting stack traces.
* **Correction:**  The asynchronous stack trace handling and the interaction with the debugger indicate a more complex role in capturing and managing call context across asynchronous operations.
* **Initial thought:**  The JavaScript example should just be a simple error.
* **Refinement:** Including asynchronous examples better demonstrates the importance of the `AsyncStackTrace` functionality.
* **Initial thought:** Focus heavily on the C++ details.
* **Refinement:**  Balance the C++ explanation with a clear explanation of its relevance to JavaScript developers.

By following these steps, one can arrive at a comprehensive and informative answer that addresses the user's request.
这个C++源代码文件 `v8-stack-trace-impl.cc` 的主要功能是**实现 V8 引擎中 JavaScript 堆栈跟踪的表示、捕获和序列化，以便在调试器 (Inspector) 中使用。**

更具体地说，它做了以下几件事：

1. **定义了表示堆栈帧的类 `StackFrame`:**  这个类存储了堆栈帧的关键信息，例如函数名、脚本 ID、源 URL、行号和列号。
2. **定义了表示完整堆栈跟踪的类 `V8StackTraceImpl`:** 这个类包含一个 `StackFrame` 对象的向量，并提供了捕获、克隆和格式化堆栈跟踪的方法。它还处理异步调用栈的情况。
3. **定义了表示异步堆栈跟踪的类 `AsyncStackTrace`:**  用于跟踪跨越异步操作的调用栈，例如 `setTimeout` 或 Promise。
4. **定义了用于标识堆栈跟踪的类 `V8StackTraceId`:**  为堆栈跟踪提供唯一的 ID，特别是在处理异步操作或跨多个调试器实例时。
5. **提供了从 V8 引擎的内部 `v8::StackTrace` 对象创建 `V8StackTraceImpl` 对象的方法 (`create`)。**
6. **提供了捕获当前 JavaScript 执行堆栈的方法 (`capture`)。**
7. **提供了将 `V8StackTraceImpl` 对象转换为调试器协议 (Chrome DevTools Protocol - CDP) 中 `Runtime.StackTrace` 对象的方法 (`buildInspectorObjectImpl`)。** 这使得调试器前端能够理解和显示堆栈跟踪信息。
8. **实现了将 `V8StackTraceId` 序列化和反序列化为字符串的方法，以便在调试器中传递和存储。**
9. **实现了用于遍历可能包含异步父级的堆栈帧的迭代器 `StackFrameIterator`。**

**它与 JavaScript 的功能有密切关系。**  当 JavaScript 代码执行出错，或者在调试过程中遇到断点时，V8 引擎会生成一个堆栈跟踪。  `v8-stack-trace-impl.cc` 中定义的类和方法就是用来捕获和格式化这个堆栈跟踪信息，并将其传递给调试器 (例如 Chrome DevTools)。 开发者在浏览器开发者工具的 "Sources" 或 "Console" 面板中看到的调用栈信息，很大程度上就是由这部分代码处理的。

**JavaScript 示例：**

```javascript
function functionA() {
  functionB();
}

function functionB() {
  functionC();
}

function functionC() {
  throw new Error("Something went wrong!");
}

try {
  functionA();
} catch (error) {
  console.log(error.stack); // 这会打印出 JavaScript 的堆栈跟踪
}

setTimeout(() => {
  asyncFunction();
}, 100);

async function asyncFunction() {
  await delay(50);
  throw new Error("Async error!");
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 在支持异步堆栈跟踪的调试器中，你可能会看到类似以下的异步调用栈信息：
// Error: Async error!
//     at asyncFunction (your_script.js:25)
//     at async Timeout._onTimeout (your_script.js:21)
// -- Async call --
//     at setTimeout (native)
//     at your_script.js:19
```

**解释：**

* 当 `functionC` 抛出错误时，JavaScript 引擎会创建一个堆栈跟踪，记录调用 `functionC`、`functionB` 和 `functionA` 的顺序。 `v8-stack-trace-impl.cc` 中的代码会捕获这些信息，并将其格式化为可以在调试器中显示的格式。
* `error.stack` 属性是 JavaScript 中访问堆栈跟踪的标准方式。 V8 引擎内部就是使用 `V8StackTraceImpl` 等类来构建这个字符串表示。
* 对于异步操作，例如 `setTimeout` 和 `async/await`，`AsyncStackTrace` 类用于跟踪跨越异步边界的调用关系。  现代调试器可以显示更详细的异步调用栈，这依赖于 V8 引擎提供的异步堆栈跟踪信息。

总而言之，`v8-stack-trace-impl.cc` 是 V8 引擎中负责处理 JavaScript 堆栈跟踪的关键组件，它使得开发者能够在调试过程中理解代码的执行流程，无论是同步的还是异步的。

### 提示词
```
这是目录为v8/src/inspector/v8-stack-trace-impl.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```