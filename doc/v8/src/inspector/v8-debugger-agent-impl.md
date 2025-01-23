Response: The user wants a summary of the C++ source code file `v8/src/inspector/v8-debugger-agent-impl.cc`.
The file seems to be responsible for the implementation of the debugger agent within the V8 engine's inspector.

Here's a plan to summarize the functionality:
1. **Identify the main purpose:** Based on the file name and includes, it's clearly about the debugger agent.
2. **Key Responsibilities:**  Look for the main classes and methods to understand what the agent does. Keywords like "enable", "disable", "breakpoint", "pause", "resume", "step", "evaluate", "scope" are good indicators.
3. **Relationship with Javascript:** Pay attention to how the agent interacts with the Javascript runtime, particularly around breakpoints, stepping, and evaluation.
4. **Illustrative Javascript examples:** For the Javascript interaction, create simple examples demonstrating the corresponding debugger actions.
这个C++源代码文件 `v8/src/inspector/v8-debugger-agent-impl.cc` 的主要功能是**实现了 V8 JavaScript 引擎的调试器代理 (Debugger Agent) 的核心逻辑**。  它负责处理来自调试客户端（例如 Chrome DevTools）的调试请求，并与 V8 引擎的调试接口进行交互，以实现断点设置、代码步进、变量查看、表达式求值等调试功能。

更具体地说，这个文件的功能包括：

1. **管理调试器的生命周期:**  实现 `enable` 和 `disable` 方法来启动和停止调试器代理。
2. **处理断点:**
    - 实现 `setBreakpointByUrl`, `setBreakpoint`, `setBreakpointOnFunctionCall`, `setInstrumentationBreakpoint` 等方法来设置不同类型的断点（基于 URL、行号列号、函数调用、特定事件等）。
    - 管理断点 ID，存储断点信息。
    - 与 V8 调试接口交互来激活和取消断点。
    - 实现 `removeBreakpoint` 方法来移除断点。
    - 实现 `getPossibleBreakpoints` 方法来获取指定位置可能的断点位置。
3. **控制代码执行:**
    - 实现 `continueToLocation` 方法来继续执行到指定位置。
    - 实现 `pause` 方法来暂停代码执行。
    - 实现 `resume` 方法来恢复代码执行。
    - 实现 `stepOver`, `stepInto`, `stepOut` 等方法来实现代码步进。
    - 实现 `setSkipAllPauses` 方法来设置是否跳过所有暂停。
4. **处理代码执行暂停状态:**
    - 跟踪调试器是否处于暂停状态。
    - 在代码暂停时，向调试客户端发送 `Paused` 事件。
5. **管理调用栈和作用域:**
    - 在代码暂停时，构建并提供当前的调用栈信息 (`getStackTrace`)。
    - 提供作用域信息，允许查看和修改变量的值 (`evaluateOnCallFrame`, `setVariableValue`)。
6. **代码修改和热重载:**
    - 实现 `setScriptSource` 方法来修改脚本源代码，支持热重载。
    - 实现 `restartFrame` 方法来重启当前调用帧。
7. **源代码检索:**
    - 实现 `getScriptSource` 方法来获取脚本源代码。
    - 实现 `searchInContent` 方法来在脚本内容中搜索。
8. **WebAssembly 支持 (如果启用):**
    - 实现 `disassembleWasmModule`, `nextWasmDisassemblyChunk`, `getWasmBytecode` 等方法来支持 WebAssembly 模块的调试，包括反汇编和获取字节码。
9. **异常处理:**
    - 实现 `setPauseOnExceptions` 方法来设置在抛出异常时暂停代码执行。
6. **黑盒 (Blackboxing) 功能:**
    - 实现 `isFunctionBlackboxed` 来判断函数是否被黑盒，从而在调试时跳过这些代码。
    - 实现 `setBlackboxPattern` 来设置黑盒的 URL 模式。
7. **性能优化:**
    - 缓存脚本信息 (`m_scripts`, `m_cachedScripts`) 以提高性能。

**它与 Javascript 的功能关系，并用 Javascript 举例说明:**

这个 C++ 文件实现了调试器的后端逻辑，而调试器最终是为了调试 Javascript 代码而存在的。  它通过 V8 引擎提供的调试接口来控制 Javascript 代码的执行和状态。

**Javascript 例子:**

假设我们在 Javascript 代码中设置了一个断点：

```javascript
function myFunction(a, b) {
  debugger; // 设置一个断点
  console.log(a + b);
  return a * b;
}

myFunction(5, 10);
```

当 Javascript 引擎执行到 `debugger;` 语句时，会触发一个暂停事件。 `v8-debugger-agent-impl.cc` 中的代码会捕获这个事件，并通知调试客户端（例如 Chrome DevTools），告诉它代码已经暂停。

在 Chrome DevTools 中，我们可以执行以下操作，这些操作会对应到 `v8-debugger-agent-impl.cc` 中的不同方法：

1. **设置断点:** 在 DevTools 的 Sources 面板中点击代码行号来设置断点。 这会触发一个请求，最终调用到 `v8-debugger-agent-impl.cc` 中的 `setBreakpointByUrl` 或 `setBreakpoint` 方法。

2. **继续执行:** 点击 DevTools 中的 "继续" 按钮。  这会调用到 `v8-debugger-agent-impl.cc` 中的 `resume` 方法，让 Javascript 引擎继续执行。

3. **单步跳过:** 点击 DevTools 中的 "单步跳过" 按钮。 这会调用到 `v8-debugger-agent-impl.cc` 中的 `stepOver` 方法，让 Javascript 引擎执行当前语句，然后暂停。

4. **单步进入:** 点击 DevTools 中的 "单步进入" 按钮。 这会调用到 `v8-debugger-agent-impl.cc` 中的 `stepInto` 方法，如果当前语句是函数调用，则会进入函数内部。

5. **单步跳出:** 点击 DevTools 中的 "单步跳出" 按钮。 这会调用到 `v8-debugger-agent-impl.cc` 中的 `stepOut` 方法，让 Javascript 引擎执行完当前函数，然后暂停。

6. **查看变量:** 在 DevTools 的 Scopes 面板中查看变量 `a` 和 `b` 的值。  当代码暂停时，DevTools 会请求作用域信息，这会涉及到 `v8-debugger-agent-impl.cc` 中对调用栈和作用域信息的处理。

7. **在控制台中求值表达式:** 在 DevTools 的 Console 面板中输入 `a + b` 并回车。  这会调用到 `v8-debugger-agent-impl.cc` 中的 `evaluateOnCallFrame` 方法，在当前调用栈帧中求值表达式。

总而言之，`v8-debugger-agent-impl.cc` 是 V8 调试器的核心，它充当了调试客户端和 V8 Javascript 引擎之间的桥梁，使得我们可以在开发工具中方便地调试 Javascript 代码。

### 提示词
```
这是目录为v8/src/inspector/v8-debugger-agent-impl.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-debugger-agent-impl.h"

#include <algorithm>
#include <memory>

#include "../../third_party/inspector_protocol/crdtp/json.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-inspector.h"
#include "include/v8-microtask-queue.h"
#include "src/base/safe_conversions.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/crc32.h"
#include "src/inspector/injected-script.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Debugger.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/remote-object-id.h"
#include "src/inspector/search-util.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-debugger-script.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-regex.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/v8-value-utils.h"

namespace v8_inspector {

using protocol::Array;
using protocol::Maybe;
using protocol::Debugger::BreakpointId;
using protocol::Debugger::CallFrame;
using protocol::Debugger::Scope;
using protocol::Runtime::ExceptionDetails;
using protocol::Runtime::RemoteObject;
using protocol::Runtime::ScriptId;

namespace InstrumentationEnum =
    protocol::Debugger::SetInstrumentationBreakpoint::InstrumentationEnum;

namespace DebuggerAgentState {
static const char pauseOnExceptionsState[] = "pauseOnExceptionsState";
static const char asyncCallStackDepth[] = "asyncCallStackDepth";
static const char blackboxPattern[] = "blackboxPattern";
static const char skipAnonymousScripts[] = "skipAnonymousScripts";
static const char debuggerEnabled[] = "debuggerEnabled";
static const char breakpointsActiveWhenEnabled[] = "breakpointsActive";
static const char skipAllPauses[] = "skipAllPauses";

static const char breakpointsByRegex[] = "breakpointsByRegex";
static const char breakpointsByUrl[] = "breakpointsByUrl";
static const char breakpointsByScriptHash[] = "breakpointsByScriptHash";
static const char breakpointHints[] = "breakpointHints";
static const char breakpointHintText[] = "text";
static const char breakpointHintPrefixHash[] = "prefixHash";
static const char breakpointHintPrefixLength[] = "prefixLen";
static const char instrumentationBreakpoints[] = "instrumentationBreakpoints";
static const char maxScriptCacheSize[] = "maxScriptCacheSize";

}  // namespace DebuggerAgentState

static const char kBacktraceObjectGroup[] = "backtrace";
static const char kDebuggerNotEnabled[] = "Debugger agent is not enabled";
static const char kDebuggerNotPaused[] =
    "Can only perform operation while paused.";

static const size_t kBreakpointHintMaxLength = 128;
static const intptr_t kBreakpointHintMaxSearchOffset = 80 * 10;
// Limit the number of breakpoints returned, as we otherwise may exceed
// the maximum length of a message in mojo (see https://crbug.com/1105172).
static const size_t kMaxNumBreakpoints = 1000;

#if V8_ENABLE_WEBASSEMBLY
// TODO(1099680): getScriptSource and getWasmBytecode return Wasm wire bytes
// as protocol::Binary, which is encoded as JSON string in the communication
// to the DevTools front-end and hence leads to either crashing the renderer
// that is being debugged or the renderer that's running the front-end if we
// allow arbitrarily big Wasm byte sequences here. Ideally we would find a
// different way to transfer the wire bytes (middle- to long-term), but as a
// short-term solution, we should at least not crash.
static constexpr size_t kWasmBytecodeMaxLength =
    (v8::String::kMaxLength / 4) * 3;
static constexpr const char kWasmBytecodeExceedsTransferLimit[] =
    "WebAssembly bytecode exceeds the transfer limit";
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

enum class BreakpointType {
  kByUrl = 1,
  kByUrlRegex,
  kByScriptHash,
  kByScriptId,
  kDebugCommand,
  kMonitorCommand,
  kBreakpointAtEntry,
  kInstrumentationBreakpoint
};

String16 generateBreakpointId(BreakpointType type,
                              const String16& scriptSelector, int lineNumber,
                              int columnNumber) {
  String16Builder builder;
  builder.appendNumber(static_cast<int>(type));
  builder.append(':');
  builder.appendNumber(lineNumber);
  builder.append(':');
  builder.appendNumber(columnNumber);
  builder.append(':');
  builder.append(scriptSelector);
  return builder.toString();
}

String16 generateBreakpointId(BreakpointType type,
                              v8::Local<v8::Function> function) {
  String16Builder builder;
  builder.appendNumber(static_cast<int>(type));
  builder.append(':');
  builder.appendNumber(v8::debug::GetDebuggingId(function));
  return builder.toString();
}

String16 generateInstrumentationBreakpointId(const String16& instrumentation) {
  String16Builder builder;
  builder.appendNumber(
      static_cast<int>(BreakpointType::kInstrumentationBreakpoint));
  builder.append(':');
  builder.append(instrumentation);
  return builder.toString();
}

bool parseBreakpointId(const String16& breakpointId, BreakpointType* type,
                       String16* scriptSelector = nullptr,
                       int* lineNumber = nullptr, int* columnNumber = nullptr) {
  size_t typeLineSeparator = breakpointId.find(':');
  if (typeLineSeparator == String16::kNotFound) return false;

  int rawType = breakpointId.substring(0, typeLineSeparator).toInteger();
  if (rawType < static_cast<int>(BreakpointType::kByUrl) ||
      rawType > static_cast<int>(BreakpointType::kInstrumentationBreakpoint)) {
    return false;
  }
  if (type) *type = static_cast<BreakpointType>(rawType);
  if (rawType == static_cast<int>(BreakpointType::kDebugCommand) ||
      rawType == static_cast<int>(BreakpointType::kMonitorCommand) ||
      rawType == static_cast<int>(BreakpointType::kBreakpointAtEntry) ||
      rawType == static_cast<int>(BreakpointType::kInstrumentationBreakpoint)) {
    // The script and source position are not encoded in this case.
    return true;
  }

  size_t lineColumnSeparator = breakpointId.find(':', typeLineSeparator + 1);
  if (lineColumnSeparator == String16::kNotFound) return false;
  size_t columnSelectorSeparator =
      breakpointId.find(':', lineColumnSeparator + 1);
  if (columnSelectorSeparator == String16::kNotFound) return false;
  if (scriptSelector) {
    *scriptSelector = breakpointId.substring(columnSelectorSeparator + 1);
  }
  if (lineNumber) {
    *lineNumber = breakpointId
                      .substring(typeLineSeparator + 1,
                                 lineColumnSeparator - typeLineSeparator - 1)
                      .toInteger();
  }
  if (columnNumber) {
    *columnNumber =
        breakpointId
            .substring(lineColumnSeparator + 1,
                       columnSelectorSeparator - lineColumnSeparator - 1)
            .toInteger();
  }
  return true;
}

bool positionComparator(const std::pair<int, int>& a,
                        const std::pair<int, int>& b) {
  if (a.first != b.first) return a.first < b.first;
  return a.second < b.second;
}

std::unique_ptr<protocol::DictionaryValue> breakpointHint(
    const V8DebuggerScript& script, int breakpointLineNumber,
    int breakpointColumnNumber, int actualLineNumber, int actualColumnNumber) {
  int actualOffset;
  int breakpointOffset;
  if (!script.offset(actualLineNumber, actualColumnNumber).To(&actualOffset) ||
      !script.offset(breakpointLineNumber, breakpointColumnNumber)
           .To(&breakpointOffset)) {
    return {};
  }

  auto hintObject = protocol::DictionaryValue::create();
  String16 rawHint = script.source(actualOffset, kBreakpointHintMaxLength);
  std::pair<size_t, size_t> offsetAndLength =
      rawHint.getTrimmedOffsetAndLength();
  String16 hint =
      rawHint.substring(offsetAndLength.first, offsetAndLength.second);
  for (size_t i = 0; i < hint.length(); ++i) {
    if (hint[i] == '\r' || hint[i] == '\n' || hint[i] == ';') {
      hint = hint.substring(0, i);
      break;
    }
  }
  hintObject->setString(DebuggerAgentState::breakpointHintText, hint);

  // Also store the hash of the text between the requested breakpoint location
  // and the actual breakpoint location. If we see the same prefix text next
  // time, we will keep the breakpoint at the same location (so that
  // breakpoints do not slide around on reloads without any edits).
  if (breakpointOffset <= actualOffset) {
    size_t length = actualOffset - breakpointOffset + offsetAndLength.first;
    String16 prefix = script.source(breakpointOffset, length);
    int crc32 = computeCrc32(prefix);
    hintObject->setInteger(DebuggerAgentState::breakpointHintPrefixHash, crc32);
    hintObject->setInteger(DebuggerAgentState::breakpointHintPrefixLength,
                           v8::base::checked_cast<int32_t>(length));
  }
  return hintObject;
}

void adjustBreakpointLocation(const V8DebuggerScript& script,
                              const protocol::DictionaryValue* hintObject,
                              int* lineNumber, int* columnNumber) {
  if (*lineNumber < script.startLine() || *lineNumber > script.endLine())
    return;
  if (*lineNumber == script.startLine() &&
      *columnNumber < script.startColumn()) {
    return;
  }
  if (*lineNumber == script.endLine() && script.endColumn() < *columnNumber) {
    return;
  }

  int sourceOffset;
  if (!script.offset(*lineNumber, *columnNumber).To(&sourceOffset)) return;

  int prefixLength = 0;
  hintObject->getInteger(DebuggerAgentState::breakpointHintPrefixLength,
                         &prefixLength);
  String16 hint;
  if (!hintObject->getString(DebuggerAgentState::breakpointHintText, &hint) ||
      hint.isEmpty())
    return;

  intptr_t searchRegionOffset = std::max(
      sourceOffset - kBreakpointHintMaxSearchOffset, static_cast<intptr_t>(0));
  size_t offset = sourceOffset - searchRegionOffset;
  size_t searchRegionSize =
      offset + std::max(kBreakpointHintMaxSearchOffset,
                        static_cast<intptr_t>(prefixLength + hint.length()));

  String16 searchArea = script.source(searchRegionOffset, searchRegionSize);

  // Let us see if the breakpoint hint text appears at the same location
  // as before, with the same prefix text in between. If yes, then we just use
  // that position.
  int prefixHash;
  if (hintObject->getInteger(DebuggerAgentState::breakpointHintPrefixHash,
                             &prefixHash) &&
      offset + prefixLength + hint.length() <= searchArea.length() &&
      searchArea.substring(offset + prefixLength, hint.length()) == hint &&
      computeCrc32(searchArea.substring(offset, prefixLength)) == prefixHash) {
    v8::debug::Location hintPosition = script.location(
        static_cast<int>(searchRegionOffset + offset + prefixLength));
    *lineNumber = hintPosition.GetLineNumber();
    *columnNumber = hintPosition.GetColumnNumber();
    return;
  }

  size_t nextMatch = searchArea.find(hint, offset);
  size_t prevMatch = searchArea.reverseFind(hint, offset);
  if (nextMatch == String16::kNotFound && prevMatch == String16::kNotFound) {
    return;
  }
  size_t bestMatch;
  if (nextMatch == String16::kNotFound ||
      nextMatch > offset + kBreakpointHintMaxSearchOffset) {
    bestMatch = prevMatch;
  } else if (prevMatch == String16::kNotFound) {
    bestMatch = nextMatch;
  } else {
    bestMatch = nextMatch - offset < offset - prevMatch ? nextMatch : prevMatch;
  }
  bestMatch += searchRegionOffset;
  v8::debug::Location hintPosition =
      script.location(static_cast<int>(bestMatch));
  if (hintPosition.IsEmpty()) return;
  *lineNumber = hintPosition.GetLineNumber();
  *columnNumber = hintPosition.GetColumnNumber();
}

String16 breakLocationType(v8::debug::BreakLocationType type) {
  switch (type) {
    case v8::debug::kCallBreakLocation:
      return protocol::Debugger::BreakLocation::TypeEnum::Call;
    case v8::debug::kReturnBreakLocation:
      return protocol::Debugger::BreakLocation::TypeEnum::Return;
    case v8::debug::kDebuggerStatementBreakLocation:
      return protocol::Debugger::BreakLocation::TypeEnum::DebuggerStatement;
    case v8::debug::kCommonBreakLocation:
      return String16();
  }
  return String16();
}

String16 scopeType(v8::debug::ScopeIterator::ScopeType type) {
  switch (type) {
    case v8::debug::ScopeIterator::ScopeTypeGlobal:
      return Scope::TypeEnum::Global;
    case v8::debug::ScopeIterator::ScopeTypeLocal:
      return Scope::TypeEnum::Local;
    case v8::debug::ScopeIterator::ScopeTypeWith:
      return Scope::TypeEnum::With;
    case v8::debug::ScopeIterator::ScopeTypeClosure:
      return Scope::TypeEnum::Closure;
    case v8::debug::ScopeIterator::ScopeTypeCatch:
      return Scope::TypeEnum::Catch;
    case v8::debug::ScopeIterator::ScopeTypeBlock:
      return Scope::TypeEnum::Block;
    case v8::debug::ScopeIterator::ScopeTypeScript:
      return Scope::TypeEnum::Script;
    case v8::debug::ScopeIterator::ScopeTypeEval:
      return Scope::TypeEnum::Eval;
    case v8::debug::ScopeIterator::ScopeTypeModule:
      return Scope::TypeEnum::Module;
    case v8::debug::ScopeIterator::ScopeTypeWasmExpressionStack:
      return Scope::TypeEnum::WasmExpressionStack;
  }
  UNREACHABLE();
}

Response buildScopes(v8::Isolate* isolate, v8::debug::ScopeIterator* iterator,
                     InjectedScript* injectedScript,
                     std::unique_ptr<Array<Scope>>* scopes) {
  *scopes = std::make_unique<Array<Scope>>();
  if (!injectedScript) return Response::Success();
  if (iterator->Done()) return Response::Success();

  String16 scriptId = String16::fromInteger(iterator->GetScriptId());

  for (; !iterator->Done(); iterator->Advance()) {
    std::unique_ptr<RemoteObject> object;
    Response result =
        injectedScript->wrapObject(iterator->GetObject(), kBacktraceObjectGroup,
                                   WrapOptions({WrapMode::kIdOnly}), &object);
    if (!result.IsSuccess()) return result;

    auto scope = Scope::create()
                     .setType(scopeType(iterator->GetType()))
                     .setObject(std::move(object))
                     .build();

    String16 name = toProtocolStringWithTypeCheck(
        isolate, iterator->GetFunctionDebugName());
    if (!name.isEmpty()) scope->setName(name);

    if (iterator->HasLocationInfo()) {
      v8::debug::Location start = iterator->GetStartLocation();
      scope->setStartLocation(protocol::Debugger::Location::create()
                                  .setScriptId(scriptId)
                                  .setLineNumber(start.GetLineNumber())
                                  .setColumnNumber(start.GetColumnNumber())
                                  .build());

      v8::debug::Location end = iterator->GetEndLocation();
      scope->setEndLocation(protocol::Debugger::Location::create()
                                .setScriptId(scriptId)
                                .setLineNumber(end.GetLineNumber())
                                .setColumnNumber(end.GetColumnNumber())
                                .build());
    }
    (*scopes)->emplace_back(std::move(scope));
  }
  return Response::Success();
}

protocol::DictionaryValue* getOrCreateObject(protocol::DictionaryValue* object,
                                             const String16& key) {
  protocol::DictionaryValue* value = object->getObject(key);
  if (value) return value;
  std::unique_ptr<protocol::DictionaryValue> newDictionary =
      protocol::DictionaryValue::create();
  value = newDictionary.get();
  object->setObject(key, std::move(newDictionary));
  return value;
}

Response isValidPosition(protocol::Debugger::ScriptPosition* position) {
  if (position->getLineNumber() < 0)
    return Response::ServerError("Position missing 'line' or 'line' < 0.");
  if (position->getColumnNumber() < 0)
    return Response::ServerError("Position missing 'column' or 'column' < 0.");
  return Response::Success();
}

Response isValidRangeOfPositions(std::vector<std::pair<int, int>>& positions) {
  for (size_t i = 1; i < positions.size(); ++i) {
    if (positions[i - 1].first < positions[i].first) continue;
    if (positions[i - 1].first == positions[i].first &&
        positions[i - 1].second < positions[i].second)
      continue;
    return Response::ServerError(
        "Input positions array is not sorted or contains duplicate values.");
  }
  return Response::Success();
}

bool hitBreakReasonEncodedAsOther(v8::debug::BreakReasons breakReasons) {
  // The listed break reasons are not explicitly encoded in CDP when
  // reporting the break. They are summarized as 'other'.
  v8::debug::BreakReasons otherBreakReasons(
      {v8::debug::BreakReason::kDebuggerStatement,
       v8::debug::BreakReason::kScheduled,
       v8::debug::BreakReason::kAlreadyPaused});
  return breakReasons.contains_any(otherBreakReasons);
}
}  // namespace

V8DebuggerAgentImpl::V8DebuggerAgentImpl(
    V8InspectorSessionImpl* session, protocol::FrontendChannel* frontendChannel,
    protocol::DictionaryValue* state)
    : m_inspector(session->inspector()),
      m_debugger(m_inspector->debugger()),
      m_session(session),
      m_enableState(kDisabled),
      m_state(state),
      m_frontend(frontendChannel),
      m_isolate(m_inspector->isolate()) {}

V8DebuggerAgentImpl::~V8DebuggerAgentImpl() = default;

void V8DebuggerAgentImpl::enableImpl() {
  m_enableState = kEnabled;
  m_state->setBoolean(DebuggerAgentState::debuggerEnabled, true);
  m_debugger->enable();

  std::vector<std::unique_ptr<V8DebuggerScript>> compiledScripts =
      m_debugger->getCompiledScripts(m_session->contextGroupId(), this);
  for (auto& script : compiledScripts) {
    didParseSource(std::move(script), true);
  }

  m_breakpointsActive = m_state->booleanProperty(
      DebuggerAgentState::breakpointsActiveWhenEnabled, true);
  if (m_breakpointsActive) {
    m_debugger->setBreakpointsActive(true);
  }
  if (isPaused()) {
    didPause(0, v8::Local<v8::Value>(), std::vector<v8::debug::BreakpointId>(),
             v8::debug::kException, false,
             v8::debug::BreakReasons({v8::debug::BreakReason::kAlreadyPaused}));
  }
}

Response V8DebuggerAgentImpl::enable(Maybe<double> maxScriptsCacheSize,
                                     String16* outDebuggerId) {
  if (m_enableState == kStopping)
    return Response::ServerError("Debugger is stopping");
  m_maxScriptCacheSize = v8::base::saturated_cast<size_t>(
      maxScriptsCacheSize.value_or(std::numeric_limits<double>::max()));
  m_state->setDouble(DebuggerAgentState::maxScriptCacheSize,
                     static_cast<double>(m_maxScriptCacheSize));
  *outDebuggerId =
      m_debugger->debuggerIdFor(m_session->contextGroupId()).toString();
  if (enabled()) return Response::Success();

  if (!m_inspector->client()->canExecuteScripts(m_session->contextGroupId()))
    return Response::ServerError("Script execution is prohibited");

  enableImpl();
  return Response::Success();
}

Response V8DebuggerAgentImpl::disable() {
  if (!enabled()) return Response::Success();

  m_state->remove(DebuggerAgentState::breakpointsByRegex);
  m_state->remove(DebuggerAgentState::breakpointsByUrl);
  m_state->remove(DebuggerAgentState::breakpointsByScriptHash);
  m_state->remove(DebuggerAgentState::breakpointHints);
  m_state->remove(DebuggerAgentState::instrumentationBreakpoints);

  m_state->setInteger(DebuggerAgentState::pauseOnExceptionsState,
                      v8::debug::NoBreakOnException);
  m_state->setInteger(DebuggerAgentState::asyncCallStackDepth, 0);

  if (m_breakpointsActive) {
    m_debugger->setBreakpointsActive(false);
    m_breakpointsActive = false;
  }
  m_blackboxedPositions.clear();
  m_blackboxPattern.reset();
  resetBlackboxedStateCache();
  m_skipList.clear();
  m_scripts.clear();
  m_cachedScripts.clear();
  m_cachedScriptSize = 0;
  m_maxScriptCacheSize = 0;
  m_state->setDouble(DebuggerAgentState::maxScriptCacheSize, 0);
  for (const auto& it : m_debuggerBreakpointIdToBreakpointId) {
    m_debugger->removeBreakpoint(it.first);
  }
  m_breakpointIdToDebuggerBreakpointIds.clear();
  m_debuggerBreakpointIdToBreakpointId.clear();
  m_wasmDisassemblies.clear();
  m_debugger->setAsyncCallStackDepth(this, 0);
  clearBreakDetails();
  m_skipAllPauses = false;
  m_state->setBoolean(DebuggerAgentState::skipAllPauses, false);
  m_state->remove(DebuggerAgentState::blackboxPattern);
  m_enableState = kDisabled;
  m_instrumentationFinished = true;
  m_state->setBoolean(DebuggerAgentState::debuggerEnabled, false);
  m_debugger->disable();
  return Response::Success();
}

void V8DebuggerAgentImpl::restore() {
  DCHECK(m_enableState == kDisabled);
  if (!m_state->booleanProperty(DebuggerAgentState::debuggerEnabled, false))
    return;
  if (!m_inspector->client()->canExecuteScripts(m_session->contextGroupId()))
    return;

  enableImpl();

  double maxScriptCacheSize = 0;
  m_state->getDouble(DebuggerAgentState::maxScriptCacheSize,
                     &maxScriptCacheSize);
  m_maxScriptCacheSize = v8::base::saturated_cast<size_t>(maxScriptCacheSize);

  int pauseState = v8::debug::NoBreakOnException;
  m_state->getInteger(DebuggerAgentState::pauseOnExceptionsState, &pauseState);
  setPauseOnExceptionsImpl(pauseState);

  m_skipAllPauses =
      m_state->booleanProperty(DebuggerAgentState::skipAllPauses, false);

  int asyncCallStackDepth = 0;
  m_state->getInteger(DebuggerAgentState::asyncCallStackDepth,
                      &asyncCallStackDepth);
  m_debugger->setAsyncCallStackDepth(this, asyncCallStackDepth);

  String16 blackboxPattern;
  if (m_state->getString(DebuggerAgentState::blackboxPattern,
                         &blackboxPattern)) {
    setBlackboxPattern(blackboxPattern);
  }
  m_skipAnonymousScripts =
      m_state->booleanProperty(DebuggerAgentState::skipAnonymousScripts, false);
}

Response V8DebuggerAgentImpl::setBreakpointsActive(bool active) {
  m_state->setBoolean(DebuggerAgentState::breakpointsActiveWhenEnabled, active);
  if (!enabled()) return Response::Success();
  if (m_breakpointsActive == active) return Response::Success();
  m_breakpointsActive = active;
  m_debugger->setBreakpointsActive(active);
  if (!active && !m_breakReason.empty()) {
    clearBreakDetails();
    m_debugger->setPauseOnNextCall(false, m_session->contextGroupId());
  }
  return Response::Success();
}

Response V8DebuggerAgentImpl::setSkipAllPauses(bool skip) {
  m_state->setBoolean(DebuggerAgentState::skipAllPauses, skip);
  m_skipAllPauses = skip;
  return Response::Success();
}

namespace {

class Matcher {
 public:
  Matcher(V8InspectorImpl* inspector, BreakpointType type,
          const String16& selector)
      : type_(type), selector_(selector) {
    if (type == BreakpointType::kByUrlRegex) {
      regex_ = std::make_unique<V8Regex>(inspector, selector, true);
    }
  }

  bool matches(const V8DebuggerScript& script) {
    switch (type_) {
      case BreakpointType::kByUrl:
        return script.sourceURL() == selector_;
      case BreakpointType::kByScriptHash:
        return script.hash() == selector_;
      case BreakpointType::kByUrlRegex: {
        return regex_->match(script.sourceURL()) != -1;
      }
      case BreakpointType::kByScriptId: {
        return script.scriptId() == selector_;
      }
      default:
        return false;
    }
  }

 private:
  std::unique_ptr<V8Regex> regex_;
  BreakpointType type_;
  const String16& selector_;
};

}  // namespace

Response V8DebuggerAgentImpl::setBreakpointByUrl(
    int lineNumber, Maybe<String16> optionalURL,
    Maybe<String16> optionalURLRegex, Maybe<String16> optionalScriptHash,
    Maybe<int> optionalColumnNumber, Maybe<String16> optionalCondition,
    String16* outBreakpointId,
    std::unique_ptr<protocol::Array<protocol::Debugger::Location>>* locations) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);

  *locations = std::make_unique<Array<protocol::Debugger::Location>>();

  int specified = (optionalURL.has_value() ? 1 : 0) +
                  (optionalURLRegex.has_value() ? 1 : 0) +
                  (optionalScriptHash.has_value() ? 1 : 0);
  if (specified != 1) {
    return Response::ServerError(
        "Either url or urlRegex or scriptHash must be specified.");
  }
  int columnNumber = 0;
  if (optionalColumnNumber.has_value()) {
    columnNumber = optionalColumnNumber.value();
    if (columnNumber < 0)
      return Response::ServerError("Incorrect column number");
  }

  BreakpointType type = BreakpointType::kByUrl;
  String16 selector;
  if (optionalURLRegex.has_value()) {
    selector = optionalURLRegex.value();
    type = BreakpointType::kByUrlRegex;
  } else if (optionalURL.has_value()) {
    selector = optionalURL.value();
    type = BreakpointType::kByUrl;
  } else if (optionalScriptHash.has_value()) {
    selector = optionalScriptHash.value();
    type = BreakpointType::kByScriptHash;
  }

  // Note: This constructor can call into JavaScript.
  Matcher matcher(m_inspector, type, selector);

  String16 condition = optionalCondition.value_or(String16());
  String16 breakpointId =
      generateBreakpointId(type, selector, lineNumber, columnNumber);
  protocol::DictionaryValue* breakpoints;
  switch (type) {
    case BreakpointType::kByUrlRegex:
      breakpoints =
          getOrCreateObject(m_state, DebuggerAgentState::breakpointsByRegex);
      break;
    case BreakpointType::kByUrl:
      breakpoints = getOrCreateObject(
          getOrCreateObject(m_state, DebuggerAgentState::breakpointsByUrl),
          selector);
      break;
    case BreakpointType::kByScriptHash:
      breakpoints = getOrCreateObject(
          getOrCreateObject(m_state,
                            DebuggerAgentState::breakpointsByScriptHash),
          selector);
      break;
    default:
      UNREACHABLE();
  }
  if (breakpoints->get(breakpointId)) {
    return Response::ServerError(
        "Breakpoint at specified location already exists.");
  }

  std::unique_ptr<protocol::DictionaryValue> hint;
  for (const auto& script : m_scripts) {
    if (!matcher.matches(*script.second)) continue;
    // Make sure the session was not disabled by some re-entrant call
    // in the script matcher.
    DCHECK(enabled());
    int adjustedLineNumber = lineNumber;
    int adjustedColumnNumber = columnNumber;
    if (hint) {
      adjustBreakpointLocation(*script.second, hint.get(), &adjustedLineNumber,
                               &adjustedColumnNumber);
    }
    std::unique_ptr<protocol::Debugger::Location> location =
        setBreakpointImpl(breakpointId, script.first, condition,
                          adjustedLineNumber, adjustedColumnNumber);
    if (location && type != BreakpointType::kByUrlRegex) {
      hint = breakpointHint(*script.second, lineNumber, columnNumber,
                            location->getLineNumber(),
                            location->getColumnNumber(adjustedColumnNumber));
    }
    if (location) (*locations)->emplace_back(std::move(location));
  }
  breakpoints->setString(breakpointId, condition);
  if (hint) {
    protocol::DictionaryValue* breakpointHints =
        getOrCreateObject(m_state, DebuggerAgentState::breakpointHints);
    breakpointHints->setObject(breakpointId, std::move(hint));
  }
  *outBreakpointId = breakpointId;
  return Response::Success();
}

Response V8DebuggerAgentImpl::setBreakpoint(
    std::unique_ptr<protocol::Debugger::Location> location,
    Maybe<String16> optionalCondition, String16* outBreakpointId,
    std::unique_ptr<protocol::Debugger::Location>* actualLocation) {
  String16 breakpointId = generateBreakpointId(
      BreakpointType::kByScriptId, location->getScriptId(),
      location->getLineNumber(), location->getColumnNumber(0));
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);

  if (m_breakpointIdToDebuggerBreakpointIds.find(breakpointId) !=
      m_breakpointIdToDebuggerBreakpointIds.end()) {
    return Response::ServerError(
        "Breakpoint at specified location already exists.");
  }
  *actualLocation = setBreakpointImpl(breakpointId, location->getScriptId(),
                                      optionalCondition.value_or(String16()),
                                      location->getLineNumber(),
                                      location->getColumnNumber(0));
  if (!*actualLocation)
    return Response::ServerError("Could not resolve breakpoint");
  *outBreakpointId = breakpointId;
  return Response::Success();
}

Response V8DebuggerAgentImpl::setBreakpointOnFunctionCall(
    const String16& functionObjectId, Maybe<String16> optionalCondition,
    String16* outBreakpointId) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);

  InjectedScript::ObjectScope scope(m_session, functionObjectId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  if (!scope.object()->IsFunction()) {
    return Response::ServerError("Could not find function with given id");
  }
  v8::Local<v8::Function> function =
      v8::Local<v8::Function>::Cast(scope.object());
  String16 breakpointId =
      generateBreakpointId(BreakpointType::kBreakpointAtEntry, function);
  if (m_breakpointIdToDebuggerBreakpointIds.find(breakpointId) !=
      m_breakpointIdToDebuggerBreakpointIds.end()) {
    return Response::ServerError(
        "Breakpoint at specified location already exists.");
  }
  v8::Local<v8::String> condition =
      toV8String(m_isolate, optionalCondition.value_or(String16()));
  setBreakpointImpl(breakpointId, function, condition);
  *outBreakpointId = breakpointId;
  return Response::Success();
}

Response V8DebuggerAgentImpl::setInstrumentationBreakpoint(
    const String16& instrumentation, String16* outBreakpointId) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  String16 breakpointId = generateInstrumentationBreakpointId(instrumentation);
  protocol::DictionaryValue* breakpoints = getOrCreateObject(
      m_state, DebuggerAgentState::instrumentationBreakpoints);
  if (breakpoints->get(breakpointId)) {
    return Response::ServerError(
        "Instrumentation breakpoint is already enabled.");
  }
  breakpoints->setBoolean(breakpointId, true);
  *outBreakpointId = breakpointId;
  return Response::Success();
}

Response V8DebuggerAgentImpl::removeBreakpoint(const String16& breakpointId) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  BreakpointType type;
  String16 selector;
  if (!parseBreakpointId(breakpointId, &type, &selector)) {
    return Response::Success();
  }
  Matcher matcher(m_inspector, type, selector);
  protocol::DictionaryValue* breakpoints = nullptr;
  switch (type) {
    case BreakpointType::kByUrl: {
      protocol::DictionaryValue* breakpointsByUrl =
          m_state->getObject(DebuggerAgentState::breakpointsByUrl);
      if (breakpointsByUrl) {
        breakpoints = breakpointsByUrl->getObject(selector);
      }
    } break;
    case BreakpointType::kByScriptHash: {
      protocol::DictionaryValue* breakpointsByScriptHash =
          m_state->getObject(DebuggerAgentState::breakpointsByScriptHash);
      if (breakpointsByScriptHash) {
        breakpoints = breakpointsByScriptHash->getObject(selector);
      }
    } break;
    case BreakpointType::kByUrlRegex:
      breakpoints = m_state->getObject(DebuggerAgentState::breakpointsByRegex);
      break;
    case BreakpointType::kInstrumentationBreakpoint:
      breakpoints =
          m_state->getObject(DebuggerAgentState::instrumentationBreakpoints);
      break;
    default:
      break;
  }
  if (breakpoints) breakpoints->remove(breakpointId);
  protocol::DictionaryValue* breakpointHints =
      m_state->getObject(DebuggerAgentState::breakpointHints);
  if (breakpointHints) breakpointHints->remove(breakpointId);

  // Get a list of scripts to remove breakpoints.
  // TODO(duongn): we can do better here if from breakpoint id we can tell it is
  // not Wasm breakpoint.
  std::vector<V8DebuggerScript*> scripts;
  for (const auto& scriptIter : m_scripts) {
    const bool scriptSelectorMatch = matcher.matches(*scriptIter.second);
    // Make sure the session was not disabled by some re-entrant call
    // in the script matcher.
    DCHECK(enabled());
    const bool isInstrumentation =
        type == BreakpointType::kInstrumentationBreakpoint;
    if (!scriptSelectorMatch && !isInstrumentation) continue;
    V8DebuggerScript* script = scriptIter.second.get();
    if (script->getLanguage() == V8DebuggerScript::Language::WebAssembly) {
      scripts.push_back(script);
    }
  }
  removeBreakpointImpl(breakpointId, scripts);

  return Response::Success();
}

void V8DebuggerAgentImpl::removeBreakpointImpl(
    const String16& breakpointId,
    const std::vector<V8DebuggerScript*>& scripts) {
  DCHECK(enabled());
  BreakpointIdToDebuggerBreakpointIdsMap::iterator
      debuggerBreakpointIdsIterator =
          m_breakpointIdToDebuggerBreakpointIds.find(breakpointId);
  if (debuggerBreakpointIdsIterator ==
      m_breakpointIdToDebuggerBreakpointIds.end()) {
    return;
  }
  for (const auto& id : debuggerBreakpointIdsIterator->second) {
#if V8_ENABLE_WEBASSEMBLY
    for (auto& script : scripts) {
      script->removeWasmBreakpoint(id);
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    m_debugger->removeBreakpoint(id);
    m_debuggerBreakpointIdToBreakpointId.erase(id);
  }
  m_breakpointIdToDebuggerBreakpointIds.erase(breakpointId);
}

Response V8DebuggerAgentImpl::getPossibleBreakpoints(
    std::unique_ptr<protocol::Debugger::Location> start,
    Maybe<protocol::Debugger::Location> end, Maybe<bool> restrictToFunction,
    std::unique_ptr<protocol::Array<protocol::Debugger::BreakLocation>>*
        locations) {
  String16 scriptId = start->getScriptId();

  if (start->getLineNumber() < 0 || start->getColumnNumber(0) < 0)
    return Response::ServerError(
        "start.lineNumber and start.columnNumber should be >= 0");

  v8::debug::Location v8Start(start->getLineNumber(),
                              start->getColumnNumber(0));
  v8::debug::Location v8End;
  if (end) {
    if (end->getScriptId() != scriptId)
      return Response::ServerError(
          "Locations should contain the same scriptId");
    int line = end->getLineNumber();
    int column = end->getColumnNumber(0);
    if (line < 0 || column < 0)
      return Response::ServerError(
          "end.lineNumber and end.columnNumber should be >= 0");
    v8End = v8::debug::Location(line, column);
  }
  auto it = m_scripts.find(scriptId);
  if (it == m_scripts.end()) return Response::ServerError("Script not found");
  std::vector<v8::debug::BreakLocation> v8Locations;
  {
    v8::HandleScope handleScope(m_isolate);
    int contextId = it->second->executionContextId();
    InspectedContext* inspected = m_inspector->getContext(contextId);
    if (!inspected) {
      return Response::ServerError("Cannot retrive script context");
    }
    v8::Context::Scope contextScope(inspected->context());
    v8::MicrotasksScope microtasks(inspected->context(),
                                   v8::MicrotasksScope::kDoNotRunMicrotasks);
    v8::TryCatch tryCatch(m_isolate);
    it->second->getPossibleBreakpoints(
        v8Start, v8End, restrictToFunction.value_or(false), &v8Locations);
  }

  *locations =
      std::make_unique<protocol::Array<protocol::Debugger::BreakLocation>>();

  // TODO(1106269): Return an error instead of capping the number of
  // breakpoints.
  const size_t numBreakpointsToSend =
      std::min(v8Locations.size(), kMaxNumBreakpoints);
  for (size_t i = 0; i < numBreakpointsToSend; ++i) {
    std::unique_ptr<protocol::Debugger::BreakLocation> breakLocation =
        protocol::Debugger::BreakLocation::create()
            .setScriptId(scriptId)
            .setLineNumber(v8Locations[i].GetLineNumber())
            .setColumnNumber(v8Locations[i].GetColumnNumber())
            .build();
    if (v8Locations[i].type() != v8::debug::kCommonBreakLocation) {
      breakLocation->setType(breakLocationType(v8Locations[i].type()));
    }
    (*locations)->emplace_back(std::move(breakLocation));
  }
  return Response::Success();
}

Response V8DebuggerAgentImpl::continueToLocation(
    std::unique_ptr<protocol::Debugger::Location> location,
    Maybe<String16> targetCallFrames) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  ScriptsMap::iterator it = m_scripts.find(location->getScriptId());
  if (it == m_scripts.end()) {
    return Response::ServerError("Cannot continue to specified location");
  }
  V8DebuggerScript* script = it->second.get();
  int contextId = script->executionContextId();
  InspectedContext* inspected = m_inspector->getContext(contextId);
  if (!inspected)
    return Response::ServerError("Cannot continue to specified location");
  v8::HandleScope handleScope(m_isolate);
  v8::Context::Scope contextScope(inspected->context());
  return m_debugger->continueToLocation(
      m_session->contextGroupId(), script, std::move(location),
      targetCallFrames.value_or(
          protocol::Debugger::ContinueToLocation::TargetCallFramesEnum::Any));
}

Response V8DebuggerAgentImpl::getStackTrace(
    std::unique_ptr<protocol::Runtime::StackTraceId> inStackTraceId,
    std::unique_ptr<protocol::Runtime::StackTrace>* outStackTrace) {
  bool isOk = false;
  int64_t id = inStackTraceId->getId().toInteger64(&isOk);
  if (!isOk) return Response::ServerError("Invalid stack trace id");

  internal::V8DebuggerId debuggerId;
  if (inStackTraceId->hasDebuggerId()) {
    debuggerId =
        internal::V8DebuggerId(inStackTraceId->getDebuggerId(String16()));
  } else {
    debuggerId = m_debugger->debuggerIdFor(m_session->contextGroupId());
  }
  if (!debuggerId.isValid())
    return Response::ServerError("Invalid stack trace id");

  V8StackTraceId v8StackTraceId(id, debuggerId.pair());
  if (v8StackTraceId.IsInvalid())
    return Response::ServerError("Invalid stack trace id");
  auto stack =
      m_debugger->stackTraceFor(m_session->contextGroupId(), v8StackTraceId);
  if (!stack) {
    return Response::ServerError("Stack trace with given id is not found");
  }
  *outStackTrace = stack->buildInspectorObject(
      m_debugger, m_debugger->maxAsyncCallChainDepth());
  return Response::Success();
}

bool V8DebuggerAgentImpl::isFunctionBlackboxed(const String16& scriptId,
                                               const v8::debug::Location& start,
                                               const v8::debug::Location& end) {
  ScriptsMap::iterator it = m_scripts.find(scriptId);
  if (it == m_scripts.end()) {
    // Unknown scripts are blackboxed.
    return true;
  }
  const String16& scriptSourceURL = it->second->sourceURL();
  if (m_blackboxPattern && !scriptSourceURL.isEmpty()
      && m_blackboxPattern->match(scriptSourceURL) != -1) {
    return true;
  }
  if (m_skipAnonymousScripts && scriptSourceURL.isEmpty()) {
    return true;
  }
  if (!m_blackboxedExecutionContexts.empty()) {
    int contextId = it->second->executionContextId();
    InspectedContext* inspected = m_inspector->getContext(contextId);
    if (inspected && m_blackboxedExecutionContexts.count(
                         inspected->uniqueId().toString()) > 0) {
      return true;
    }
  }
  auto itBlackboxedPositions = m_blackboxedPositions.find(scriptId);
  if (itBlackboxedPositions == m_blackboxedPositions.end()) return false;

  const std::vector<std::pair<int, int>>& ranges =
      itBlackboxedPositions->second;
  auto itStartRange = std::lower_bound(
      ranges.begin(), ranges.end(),
      std::make_pair(start.GetLineNumber(), start.GetColumnNumber()),
      positionComparator);
  auto itEndRange = std::lower_bound(
      itStartRange, ranges.end(),
      std::make_pair(end.GetLineNumber(), end.GetColumnNumber()),
      positionComparator);
  // Ranges array contains positions in script where blackbox state is changed.
  // [(0,0) ... ranges[0]) isn't blackboxed, [ranges[0] ... ranges[1]) is
  // blackboxed...
  return itStartRange == itEndRange &&
         std::distance(ranges.begin(), itStartRange) % 2;
}

bool V8DebuggerAgentImpl::shouldBeSkipped(const String16& scriptId, int line,
                                          int column) {
  if (m_skipList.empty()) return false;

  auto it = m_skipList.find(scriptId);
  if (it == m_skipList.end()) return false;

  const std::vector<std::pair<int, int>>& ranges = it->second;
  DCHECK(!ranges.empty());
  const std::pair<int, int> location = std::make_pair(line, column);
  auto itLowerBound = std::lower_bound(ranges.begin(), ranges.end(), location,
                                       positionComparator);

  bool shouldSkip = false;
  if (itLowerBound != ranges.end()) {
    // Skip lists are defined as pairs of locations that specify the
    // start and the end of ranges to skip: [ranges[0], ranges[1], ..], where
    // locations in [ranges[0], ranges[1]) should be skipped, i.e.
    // [(lineStart, columnStart), (lineEnd, columnEnd)).
    const bool isSameAsLowerBound = location == *itLowerBound;
    const bool isUnevenIndex = (itLowerBound - ranges.begin()) % 2;
    shouldSkip = isSameAsLowerBound ^ isUnevenIndex;
  }

  return shouldSkip;
}

bool V8DebuggerAgentImpl::acceptsPause(bool isOOMBreak) const {
  return enabled() && (isOOMBreak || !m_skipAllPauses);
}

std::unique_ptr<protocol::Debugger::Location>
V8DebuggerAgentImpl::setBreakpointImpl(const String16& breakpointId,
                                       const String16& scriptId,
                                       const String16& condition,
                                       int lineNumber, int columnNumber) {
  v8::HandleScope handles(m_isolate);
  DCHECK(enabled());

  ScriptsMap::iterator scriptIterator = m_scripts.find(scriptId);
  if (scriptIterator == m_scripts.end()) return nullptr;
  V8DebuggerScript* script = scriptIterator->second.get();

  v8::debug::BreakpointId debuggerBreakpointId;
  v8::debug::Location location(lineNumber, columnNumber);
  int contextId = script->executionContextId();
  InspectedContext* inspected = m_inspector->getContext(contextId);
  if (!inspected) return nullptr;

  {
    v8::Context::Scope contextScope(inspected->context());
    if (!script->setBreakpoint(condition, &location, &debuggerBreakpointId)) {
      return nullptr;
    }
  }

  m_debuggerBreakpointIdToBreakpointId[debuggerBreakpointId] = breakpointId;
  m_breakpointIdToDebuggerBreakpointIds[breakpointId].push_back(
      debuggerBreakpointId);

  return protocol::Debugger::Location::create()
      .setScriptId(scriptId)
      .setLineNumber(location.GetLineNumber())
      .setColumnNumber(location.GetColumnNumber())
      .build();
}

void V8DebuggerAgentImpl::setBreakpointImpl(const String16& breakpointId,
                                            v8::Local<v8::Function> function,
                                            v8::Local<v8::String> condition) {
  v8::debug::BreakpointId debuggerBreakpointId;
  if (!v8::debug::SetFunctionBreakpoint(function, condition,
                                        &debuggerBreakpointId)) {
    return;
  }
  m_debuggerBreakpointIdToBreakpointId[debuggerBreakpointId] = breakpointId;
  m_breakpointIdToDebuggerBreakpointIds[breakpointId].push_back(
      debuggerBreakpointId);
}

Response V8DebuggerAgentImpl::searchInContent(
    const String16& scriptId, const String16& query,
    Maybe<bool> optionalCaseSensitive, Maybe<bool> optionalIsRegex,
    std::unique_ptr<Array<protocol::Debugger::SearchMatch>>* results) {
  v8::HandleScope handles(m_isolate);
  ScriptsMap::iterator it = m_scripts.find(scriptId);
  if (it == m_scripts.end())
    return Response::ServerError("No script for id: " + scriptId.utf8());

  *results = std::make_unique<protocol::Array<protocol::Debugger::SearchMatch>>(
      searchInTextByLinesImpl(m_session, it->second->source(0), query,
                              optionalCaseSensitive.value_or(false),
                              optionalIsRegex.value_or(false)));
  return Response::Success();
}

namespace {
const char* buildStatus(v8::debug::LiveEditResult::Status status) {
  switch (status) {
    case v8::debug::LiveEditResult::OK:
      return protocol::Debugger::SetScriptSource::StatusEnum::Ok;
    case v8::debug::LiveEditResult::COMPILE_ERROR:
      return protocol::Debugger::SetScriptSource::StatusEnum::CompileError;
    case v8::debug::LiveEditResult::BLOCKED_BY_ACTIVE_FUNCTION:
      return protocol::Debugger::SetScriptSource::StatusEnum::
          BlockedByActiveFunction;
    case v8::debug::LiveEditResult::BLOCKED_BY_RUNNING_GENERATOR:
      return protocol::Debugger::SetScriptSource::StatusEnum::
          BlockedByActiveGenerator;
    case v8::debug::LiveEditResult::BLOCKED_BY_TOP_LEVEL_ES_MODULE_CHANGE:
      return protocol::Debugger::SetScriptSource::StatusEnum::
          BlockedByTopLevelEsModuleChange;
  }
}
}  // namespace

Response V8DebuggerAgentImpl::setScriptSource(
    const String16& scriptId, const String16& newContent, Maybe<bool> dryRun,
    Maybe<bool> allowTopFrameEditing,
    Maybe<protocol::Array<protocol::Debugger::CallFrame>>* newCallFrames,
    Maybe<bool>* stackChanged,
    Maybe<protocol::Runtime::StackTrace>* asyncStackTrace,
    Maybe<protocol::Runtime::StackTraceId>* asyncStackTraceId, String16* status,
    Maybe<protocol::Runtime::ExceptionDetails>* optOutCompileError) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);

  ScriptsMap::iterator it = m_scripts.find(scriptId);
  if (it == m_scripts.end()) {
    return Response::ServerError("No script with given id found");
  }
  int contextId = it->second->executionContextId();
  InspectedContext* inspected = m_inspector->getContext(contextId);
  if (!inspected) {
    return Response::InternalError();
  }
  v8::HandleScope handleScope(m_isolate);
  v8::Local<v8::Context> context = inspected->context();
  v8::Context::Scope contextScope(context);
  const bool allowTopFrameLiveEditing = allowTopFrameEditing.value_or(false);

  v8::debug::LiveEditResult result;
  it->second->setSource(newContent, dryRun.value_or(false),
                        allowTopFrameLiveEditing, &result);
  *status = buildStatus(result.status);
  if (result.status == v8::debug::LiveEditResult::COMPILE_ERROR) {
    *optOutCompileError =
        protocol::Runtime::ExceptionDetails::create()
            .setExceptionId(m_inspector->nextExceptionId())
            .setText(toProtocolString(m_isolate, result.message))
            .setLineNumber(result.line_number != -1 ? result.line_number - 1
                                                    : 0)
            .setColumnNumber(result.column_number != -1 ? result.column_number
                                                        : 0)
            .build();
    return Response::Success();
  }

  if (result.restart_top_frame_required) {
    CHECK(allowTopFrameLiveEditing);
    // Nothing could have happened to the JS stack since the live edit so
    // restarting the top frame is guaranteed to be successful.
    CHECK(m_debugger->restartFrame(m_session->contextGroupId(),
                                   /* callFrameOrdinal */ 0));
    m_session->releaseObjectGroup(kBacktraceObjectGroup);
  }

  return Response::Success();
}

Response V8DebuggerAgentImpl::restartFrame(
    const String16& callFrameId, Maybe<String16> mode,
    std::unique_ptr<Array<CallFrame>>* newCallFrames,
    Maybe<protocol::Runtime::StackTrace>* asyncStackTrace,
    Maybe<protocol::Runtime::StackTraceId>* asyncStackTraceId) {
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  if (!mode.has_value()) {
    return Response::ServerError(
        "Restarting frame without 'mode' not supported");
  }
  if (mode.value() != protocol::Debugger::RestartFrame::ModeEnum::StepInto) {
    return Response::InvalidParams("'StepInto' is the only valid mode");
  }

  InjectedScript::CallFrameScope scope(m_session, callFrameId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  int callFrameOrdinal = static_cast<int>(scope.frameOrdinal());

  if (!m_debugger->restartFrame(m_session->contextGroupId(),
                                callFrameOrdinal)) {
    return Response::ServerError("Restarting frame failed");
  }
  m_session->releaseObjectGroup(kBacktraceObjectGroup);
  *newCallFrames = std::make_unique<Array<CallFrame>>();
  return Response::Success();
}

Response V8DebuggerAgentImpl::getScriptSource(
    const String16& scriptId, String16* scriptSource,
    Maybe<protocol::Binary>* bytecode) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  ScriptsMap::iterator it = m_scripts.find(scriptId);
  if (it == m_scripts.end()) {
    auto cachedScriptIt =
        std::find_if(m_cachedScripts.begin(), m_cachedScripts.end(),
                     [&scriptId](const CachedScript& cachedScript) {
                       return cachedScript.scriptId == scriptId;
                     });
    if (cachedScriptIt != m_cachedScripts.end()) {
      *scriptSource = cachedScriptIt->source;
      *bytecode = protocol::Binary::fromSpan(v8::MemorySpan<const uint8_t>(
          cachedScriptIt->bytecode.begin(), cachedScriptIt->bytecode.size()));
      return Response::Success();
    }
    return Response::ServerError("No script for id: " + scriptId.utf8());
  }
  *scriptSource = it->second->source(0);
#if V8_ENABLE_WEBASSEMBLY
  v8::MemorySpan<const uint8_t> span;
  if (it->second->wasmBytecode().To(&span)) {
    if (span.size() > kWasmBytecodeMaxLength) {
      return Response::ServerError(kWasmBytecodeExceedsTransferLimit);
    }
    *bytecode = protocol::Binary::fromSpan(span);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return Response::Success();
}

struct DisassemblyChunk {
  DisassemblyChunk() = default;
  DisassemblyChunk(const DisassemblyChunk& other) = delete;
  DisassemblyChunk& operator=(const DisassemblyChunk& other) = delete;
  DisassemblyChunk(DisassemblyChunk&& other) V8_NOEXCEPT = default;
  DisassemblyChunk& operator=(DisassemblyChunk&& other) V8_NOEXCEPT = default;

  std::vector<String16> lines;
  std::vector<int> lineOffsets;

  void Reserve(size_t size) {
    lines.reserve(size);
    lineOffsets.reserve(size);
  }
};

class DisassemblyCollectorImpl final : public v8::debug::DisassemblyCollector {
 public:
  DisassemblyCollectorImpl() = default;

  void ReserveLineCount(size_t count) override {
    if (count == 0) return;
    size_t num_chunks = (count + kLinesPerChunk - 1) / kLinesPerChunk;
    chunks_.resize(num_chunks);
    for (size_t i = 0; i < num_chunks - 1; i++) {
      chunks_[i].Reserve(kLinesPerChunk);
    }
    size_t last = num_chunks - 1;
    size_t last_size = count % kLinesPerChunk;
    if (last_size == 0) last_size = kLinesPerChunk;
    chunks_[last].Reserve(last_size);
  }

  void AddLine(const char* src, size_t length,
               uint32_t bytecode_offset) override {
    chunks_[writing_chunk_index_].lines.emplace_back(src, length);
    chunks_[writing_chunk_index_].lineOffsets.push_back(
        static_cast<int>(bytecode_offset));
    if (chunks_[writing_chunk_index_].lines.size() == kLinesPerChunk) {
      writing_chunk_index_++;
    }
    total_number_of_lines_++;
  }

  size_t total_number_of_lines() { return total_number_of_lines_; }

  bool HasNextChunk() { return reading_chunk_index_ < chunks_.size(); }
  DisassemblyChunk NextChunk() {
    return std::move(chunks_[reading_chunk_index_++]);
  }

 private:
  // For a large Ritz module, the average is about 50 chars per line,
  // so (with 2-byte String16 chars) this should give approximately 20 MB
  // per chunk.
  static constexpr size_t kLinesPerChunk = 200'000;

  size_t writing_chunk_index_ = 0;
  size_t reading_chunk_index_ = 0;
  size_t total_number_of_lines_ = 0;
  std::vector<DisassemblyChunk> chunks_;
};

Response V8DebuggerAgentImpl::disassembleWasmModule(
    const String16& in_scriptId, Maybe<String16>* out_streamId,
    int* out_totalNumberOfLines,
    std::unique_ptr<protocol::Array<int>>* out_functionBodyOffsets,
    std::unique_ptr<protocol::Debugger::WasmDisassemblyChunk>* out_chunk) {
#if V8_ENABLE_WEBASSEMBLY
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  ScriptsMap::iterator it = m_scripts.find(in_scriptId);
  std::unique_ptr<DisassemblyCollectorImpl> collector =
      std::make_unique<DisassemblyCollectorImpl>();
  std::vector<int> functionBodyOffsets;
  if (it != m_scripts.end()) {
    V8DebuggerScript* script = it->second.get();
    if (script->getLanguage() != V8DebuggerScript::Language::WebAssembly) {
      return Response::InvalidParams("Script with id " + in_scriptId.utf8() +
                                     " is not WebAssembly");
    }
    script->Disassemble(collector.get(), &functionBodyOffsets);
  } else {
    auto cachedScriptIt =
        std::find_if(m_cachedScripts.begin(), m_cachedScripts.end(),
                     [&in_scriptId](const CachedScript& cachedScript) {
                       return cachedScript.scriptId == in_scriptId;
                     });
    if (cachedScriptIt == m_cachedScripts.end()) {
      return Response::InvalidParams("No script for id: " + in_scriptId.utf8());
    }
    v8::debug::Disassemble(v8::base::VectorOf(cachedScriptIt->bytecode),
                           collector.get(), &functionBodyOffsets);
  }
  *out_totalNumberOfLines =
      static_cast<int>(collector->total_number_of_lines());
  *out_functionBodyOffsets =
      std::make_unique<protocol::Array<int>>(std::move(functionBodyOffsets));
  // Even an empty module would disassemble to "(module)", never to zero lines.
  DCHECK(collector->HasNextChunk());
  DisassemblyChunk chunk(collector->NextChunk());
  *out_chunk = protocol::Debugger::WasmDisassemblyChunk::create()
                   .setBytecodeOffsets(std::make_unique<protocol::Array<int>>(
                       std::move(chunk.lineOffsets)))
                   .setLines(std::make_unique<protocol::Array<String16>>(
                       std::move(chunk.lines)))
                   .build();
  if (collector->HasNextChunk()) {
    String16 streamId = String16::fromInteger(m_nextWasmDisassemblyStreamId++);
    *out_streamId = streamId;
    m_wasmDisassemblies[streamId] = std::move(collector);
  }
  return Response::Success();
#else
  return Response::ServerError("WebAssembly is disabled");
#endif  // V8_ENABLE_WEBASSEMBLY
}

Response V8DebuggerAgentImpl::nextWasmDisassemblyChunk(
    const String16& in_streamId,
    std::unique_ptr<protocol::Debugger::WasmDisassemblyChunk>* out_chunk) {
#if V8_ENABLE_WEBASSEMBLY
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  auto it = m_wasmDisassemblies.find(in_streamId);
  if (it == m_wasmDisassemblies.end()) {
    return Response::InvalidParams("No chunks available for stream " +
                                   in_streamId.utf8());
  }
  if (it->second->HasNextChunk()) {
    DisassemblyChunk chunk(it->second->NextChunk());
    *out_chunk = protocol::Debugger::WasmDisassemblyChunk::create()
                     .setBytecodeOffsets(std::make_unique<protocol::Array<int>>(
                         std::move(chunk.lineOffsets)))
                     .setLines(std::make_unique<protocol::Array<String16>>(
                         std::move(chunk.lines)))
                     .build();
  } else {
    *out_chunk =
        protocol::Debugger::WasmDisassemblyChunk::create()
            .setBytecodeOffsets(std::make_unique<protocol::Array<int>>())
            .setLines(std::make_unique<protocol::Array<String16>>())
            .build();
    m_wasmDisassemblies.erase(it);
  }
  return Response::Success();
#else
  return Response::ServerError("WebAssembly is disabled");
#endif  // V8_ENABLE_WEBASSEMBLY
}

Response V8DebuggerAgentImpl::getWasmBytecode(const String16& scriptId,
                                              protocol::Binary* bytecode) {
#if V8_ENABLE_WEBASSEMBLY
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  ScriptsMap::iterator it = m_scripts.find(scriptId);
  if (it == m_scripts.end())
    return Response::ServerError("No script for id: " + scriptId.utf8());
  v8::MemorySpan<const uint8_t> span;
  if (!it->second->wasmBytecode().To(&span))
    return Response::ServerError("Script with id " + scriptId.utf8() +
                                 " is not WebAssembly");
  if (span.size() > kWasmBytecodeMaxLength) {
    return Response::ServerError(kWasmBytecodeExceedsTransferLimit);
  }
  *bytecode = protocol::Binary::fromSpan(span);
  return Response::Success();
#else
  return Response::ServerError("WebAssembly is disabled");
#endif  // V8_ENABLE_WEBASSEMBLY
}

void V8DebuggerAgentImpl::pushBreakDetails(
    const String16& breakReason,
    std::unique_ptr<protocol::DictionaryValue> breakAuxData) {
  m_breakReason.push_back(std::make_pair(breakReason, std::move(breakAuxData)));
}

void V8DebuggerAgentImpl::popBreakDetails() {
  if (m_breakReason.empty()) return;
  m_breakReason.pop_back();
}

void V8DebuggerAgentImpl::clearBreakDetails() {
  std::vector<BreakReason> emptyBreakReason;
  m_breakReason.swap(emptyBreakReason);
}

void V8DebuggerAgentImpl::schedulePauseOnNextStatement(
    const String16& breakReason,
    std::unique_ptr<protocol::DictionaryValue> data) {
  if (isPaused() || !acceptsPause(false) || !m_breakpointsActive) return;
  if (m_breakReason.empty()) {
    m_debugger->setPauseOnNextCall(true, m_session->contextGroupId());
  }
  pushBreakDetails(breakReason, std::move(data));
}

void V8DebuggerAgentImpl::cancelPauseOnNextStatement() {
  if (isPaused() || !acceptsPause(false) || !m_breakpointsActive) return;
  if (m_breakReason.size() == 1) {
    m_debugger->setPauseOnNextCall(false, m_session->contextGroupId());
  }
  popBreakDetails();
}

Response V8DebuggerAgentImpl::pause() {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);

  if (m_debugger->isInInstrumentationPause()) {
    // If we are inside an instrumentation pause, remember the pause request
    // so that we can enter the requested pause once we are done
    // with the instrumentation.
    m_debugger->requestPauseAfterInstrumentation();
  } else if (isPaused()) {
    // Ignore the pause request if we are already paused.
    return Response::Success();
  } else if (m_debugger->canBreakProgram()) {
    m_debugger->interruptAndBreak(m_session->contextGroupId());
  } else {
    pushBreakDetails(protocol::Debugger::Paused::ReasonEnum::Other, nullptr);
    m_debugger->setPauseOnNextCall(true, m_session->contextGroupId());
  }

  return Response::Success();
}

Response V8DebuggerAgentImpl::resume(Maybe<bool> terminateOnResume) {
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  m_session->releaseObjectGroup(kBacktraceObjectGroup);

  m_instrumentationFinished = true;
  m_debugger->continueProgram(m_session->contextGroupId(),
                              terminateOnResume.value_or(false));
  return Response::Success();
}

Response V8DebuggerAgentImpl::stepOver(
    Maybe<protocol::Array<protocol::Debugger::LocationRange>> inSkipList) {
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);

  if (inSkipList) {
    const Response res = processSkipList(*inSkipList);
    if (res.IsError()) return res;
  } else {
    m_skipList.clear();
  }

  m_session->releaseObjectGroup(kBacktraceObjectGroup);
  m_debugger->stepOverStatement(m_session->contextGroupId());
  return Response::Success();
}

Response V8DebuggerAgentImpl::stepInto(
    Maybe<bool> inBreakOnAsyncCall,
    Maybe<protocol::Array<protocol::Debugger::LocationRange>> inSkipList) {
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);

  if (inSkipList) {
    const Response res = processSkipList(*inSkipList);
    if (res.IsError()) return res;
  } else {
    m_skipList.clear();
  }

  m_session->releaseObjectGroup(kBacktraceObjectGroup);
  m_debugger->stepIntoStatement(m_session->contextGroupId(),
                                inBreakOnAsyncCall.value_or(false));
  return Response::Success();
}

Response V8DebuggerAgentImpl::stepOut() {
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  m_session->releaseObjectGroup(kBacktraceObjectGroup);
  m_debugger->stepOutOfFunction(m_session->contextGroupId());
  return Response::Success();
}

Response V8DebuggerAgentImpl::pauseOnAsyncCall(
    std::unique_ptr<protocol::Runtime::StackTraceId> inParentStackTraceId) {
  // Deprecated, just return OK.
  return Response::Success();
}

Response V8DebuggerAgentImpl::setPauseOnExceptions(
    const String16& stringPauseState) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  v8::debug::ExceptionBreakState pauseState;
  if (stringPauseState == "none") {
    pauseState = v8::debug::NoBreakOnException;
  } else if (stringPauseState == "all") {
    pauseState = v8::debug::BreakOnAnyException;
  } else if (stringPauseState == "caught") {
    pauseState = v8::debug::BreakOnCaughtException;
  } else if (stringPauseState == "uncaught") {
    pauseState = v8::debug::BreakOnUncaughtException;
  } else {
    return Response::ServerError("Unknown pause on exceptions mode: " +
                                 stringPauseState.utf8());
  }
  setPauseOnExceptionsImpl(pauseState);
  return Response::Success();
}

void V8DebuggerAgentImpl::setPauseOnExceptionsImpl(int pauseState) {
  // TODO(dgozman): this changes the global state and forces all context groups
  // to pause. We should make this flag be per-context-group.
  m_debugger->setPauseOnExceptionsState(
      static_cast<v8::debug::ExceptionBreakState>(pauseState));
  m_state->setInteger(DebuggerAgentState::pauseOnExceptionsState, pauseState);
}

Response V8DebuggerAgentImpl::evaluateOnCallFrame(
    const String16& callFrameId, const String16& expression,
    Maybe<String16> objectGroup, Maybe<bool> includeCommandLineAPI,
    Maybe<bool> silent, Maybe<bool> returnByValue, Maybe<bool> generatePreview,
    Maybe<bool> throwOnSideEffect, Maybe<double> timeout,
    std::unique_ptr<RemoteObject>* result,
    Maybe<protocol::Runtime::ExceptionDetails>* exceptionDetails) {
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  InjectedScript::CallFrameScope scope(m_session, callFrameId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  if (includeCommandLineAPI.value_or(false)) scope.installCommandLineAPI();
  if (silent.value_or(false)) scope.ignoreExceptionsAndMuteConsole();

  int frameOrdinal = static_cast<int>(scope.frameOrdinal());
  auto it = v8::debug::StackTraceIterator::Create(m_isolate, frameOrdinal);
  if (it->Done()) {
    return Response::ServerError("Could not find call frame with given id");
  }

  v8::MaybeLocal<v8::Value> maybeResultValue;
  {
    V8InspectorImpl::EvaluateScope evaluateScope(scope);
    if (timeout.has_value()) {
      response = evaluateScope.setTimeout(timeout.value() / 1000.0);
      if (!response.IsSuccess()) return response;
    }
    maybeResultValue = it->Evaluate(toV8String(m_isolate, expression),
                                    throwOnSideEffect.value_or(false));
  }
  // Re-initialize after running client's code, as it could have destroyed
  // context or session.
  response = scope.initialize();
  if (!response.IsSuccess()) return response;
  WrapOptions wrapOptions = generatePreview.value_or(false)
                                ? WrapOptions({WrapMode::kPreview})
                                : WrapOptions({WrapMode::kIdOnly});
  if (returnByValue.value_or(false))
    wrapOptions = WrapOptions({WrapMode::kJson});
  return scope.injectedScript()->wrapEvaluateResult(
      maybeResultValue, scope.tryCatch(), objectGroup.value_or(""), wrapOptions,
      throwOnSideEffect.value_or(false), result, exceptionDetails);
}

Response V8DebuggerAgentImpl::setVariableValue(
    int scopeNumber, const String16& variableName,
    std::unique_ptr<protocol::Runtime::CallArgument> newValueArgument,
    const String16& callFrameId) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  InjectedScript::CallFrameScope scope(m_session, callFrameId);
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  v8::Local<v8::Value> newValue;
  response = scope.injectedScript()->resolveCallArgument(newValueArgument.get(),
                                                         &newValue);
  if (!response.IsSuccess()) return response;

  int frameOrdinal = static_cast<int>(scope.frameOrdinal());
  auto it = v8::debug::StackTraceIterator::Create(m_isolate, frameOrdinal);
  if (it->Done()) {
    return Response::ServerError("Could not find call frame with given id");
  }
  auto scopeIterator = it->GetScopeIterator();
  while (!scopeIterator->Done() && scopeNumber > 0) {
    --scopeNumber;
    scopeIterator->Advance();
  }
  if (scopeNumber != 0) {
    return Response::ServerError("Could not find scope with given number");
  }

  if (!scopeIterator->SetVariableValue(toV8String(m_isolate, variableName),
                                       newValue) ||
      scope.tryCatch().HasC
```