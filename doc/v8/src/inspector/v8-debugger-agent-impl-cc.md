Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/inspector/v8-debugger-agent-impl.cc`. They also have some specific instructions and questions regarding the code.

Here's a breakdown of the thought process to address the request:

1. **Identify the core purpose of the file:** The filename `v8-debugger-agent-impl.cc` strongly suggests this file implements the debugger agent within the V8 inspector. This agent is responsible for handling debugger-related interactions.

2. **Scan for key functionalities:** Look for keywords and class names that hint at the features implemented.
    * Includes like `protocol/Debugger.h`, `v8-debugger.h`, `v8-inspector-session-impl.h` point towards debugger protocol handling and interaction with the core debugger.
    * Functions like `enable`, `disable`, `setBreakpoint`, `removeBreakpoint`, `pause`, `resume` are strong indicators of debugger control functionalities.
    * Data structures like `m_breakpointsActive`, `m_scripts`, `m_breakpointIdToDebuggerBreakpointIds` suggest the management of breakpoints and scripts.

3. **Categorize the functionalities:** Group related features together. This helps in structuring the explanation.
    * **Enabling/Disabling the debugger:** Functions like `enable` and `disable`.
    * **Breakpoint Management:** Functions like `setBreakpointByUrl`, `setBreakpoint`, `removeBreakpoint`, and the related data structures.
    * **Pausing and Resuming execution:** Though not explicitly present in this *snippet*, the presence of `isPaused()` and mentions of pause-related states indicate this functionality is handled by this class.
    * **Inspecting state:**  Mention of "scopes" and "call frames" hints at functionalities for examining the program's state during debugging.
    * **Blackboxing:** The presence of `blackboxPattern` and related functions suggests the ability to exclude certain scripts from debugging.
    * **Instrumentation breakpoints:** The specific mention of `setInstrumentationBreakpoint` indicates support for this type of breakpoint.

4. **Address specific instructions:**
    * **File extension:**  Check for `.tq` ending. The file ends in `.cc`, so it's not a Torque file.
    * **Relationship to JavaScript:** The file is part of the V8 engine, which executes JavaScript. The debugger directly interacts with the JavaScript runtime. Provide a JavaScript example demonstrating a common debugging scenario (setting a breakpoint).
    * **Code logic推理 (reasoning):** Focus on the `generateBreakpointId` and `parseBreakpointId` functions. Create a hypothetical breakpoint ID and show how it would be parsed.
    * **用户常见的编程错误 (common user errors):** Think about typical mistakes developers make when using debuggers. Setting breakpoints in the wrong place or not understanding conditional breakpoints are good examples.

5. **Synthesize a summary:** Based on the identified functionalities, write a concise summary of the file's purpose. Emphasize its role as the implementation of the debugger agent.

6. **Review and refine:** Ensure the explanation is clear, accurate, and addresses all parts of the user's request. Check for consistency and completeness. For instance, make sure the JavaScript example directly relates to the described functionality.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have focused too much on individual functions. Realizing the need for categorization helps present a clearer picture of the overall functionality.
* I noticed the absence of explicit `pause` and `resume` functions in the snippet. It's important to note their implicit existence based on the state variables and the overall context of a debugger.
* For the code logic reasoning, I initially considered explaining more complex scenarios. However, focusing on the basic breakpoint ID generation and parsing makes the example easier to understand.
* When considering user errors, I initially thought about V8-specific debugging issues. However, general debugging errors applicable to JavaScript development are more relevant in this context.
Based on the provided C++ code snippet for `v8/src/inspector/v8-debugger-agent-impl.cc`, here's a breakdown of its functionality:

**Core Functionality: Implementation of the V8 Debugger Agent**

This file implements the core logic for the V8 debugger agent, which is a component of the V8 Inspector. The debugger agent is responsible for enabling debugging capabilities within the V8 JavaScript engine, allowing developers to interact with the execution of their JavaScript code.

**Key Functions and Responsibilities:**

* **Enabling and Disabling the Debugger:**
    * `enableImpl()`:  Initializes and activates the debugger, attaching it to the V8 engine. It also handles restoring breakpoints from previous sessions.
    * `disable()`: Deactivates the debugger, removing breakpoints and resetting its state.
    * `restore()`:  Restores the debugger's state from a previous session, including breakpoints and settings.
* **Breakpoint Management:**
    * `setBreakpointByUrl()`: Sets breakpoints based on script URLs, URL regular expressions, or script hashes.
    * `setBreakpoint()`: Sets a breakpoint at a specific location (line and column) within a script identified by its ID.
    * `setBreakpointOnFunctionCall()`: Sets a breakpoint at the entry point of a specific JavaScript function.
    * `setInstrumentationBreakpoint()`: Sets breakpoints based on specific instrumentation points within the V8 engine.
    * `removeBreakpoint()`: Removes a previously set breakpoint.
    * Manages different types of breakpoints (by URL, regex, script hash, script ID, function call, instrumentation).
    * Stores and retrieves breakpoint information (conditions, locations) in the debugger's state.
* **Controlling Execution Flow:**
    * `setBreakpointsActive()`:  Activates or deactivates all currently set breakpoints.
    * `setSkipAllPauses()`:  Allows the debugger to skip all potential pause points.
* **Managing Paused States:**
    * Detects and handles debugger pauses.
    * Stores information about the current pause state (e.g., reason for pausing, call stack).
* **Inspecting Execution Context:**
    * Provides information about call frames and scopes during a pause.
    * `buildScopes()`:  Constructs a representation of the current scopes for inspection.
* **Blackboxing Scripts:**
    * `setBlackboxPattern()`:  Allows developers to specify regular expressions for scripts that should be "blackboxed" (ignored by the debugger during stepping).
* **Script Management:**
    * Caches parsed script information (`m_scripts`, `m_cachedScripts`).
    * Handles notifications when scripts are parsed (`didParseSource`).
* **Communication with the Frontend:**
    * Sends events to the debugger frontend (e.g., when a script is parsed, when the debugger pauses).

**If `v8/src/inspector/v8-debugger-agent-impl.cc` ended with `.tq`:**

Then it would be a **V8 Torque source code file**. Torque is a domain-specific language used within V8 for implementing built-in functions and runtime functionalities with better performance and type safety.

**Relationship to JavaScript and Example:**

The `v8-debugger-agent-impl.cc` directly enables debugging of JavaScript code executed by the V8 engine. When a developer sets a breakpoint in their browser's DevTools, the browser sends a message to the V8 Inspector, which is handled by this agent.

**JavaScript Example:**

```javascript
function myFunction() {
  let x = 10;
  debugger; // This will trigger a breakpoint if the debugger is attached and active.
  console.log(x * 2);
}

myFunction();
```

In this JavaScript example, the `debugger;` statement will cause the V8 engine to pause execution if the debugger is enabled. The `V8DebuggerAgentImpl` is responsible for handling this pause, informing the DevTools, and allowing the developer to inspect the state of the application (e.g., the value of `x`). The `setBreakpoint` function in the C++ code would be involved if the breakpoint was set programmatically via the DevTools interface rather than using the `debugger` statement.

**Code Logic Reasoning (Hypothetical):**

Let's consider the `generateBreakpointId` and `parseBreakpointId` functions.

**Hypothetical Input:**

Imagine a breakpoint is set on line 15, column 5 of a script with the URL "my-script.js".

**`generateBreakpointId` (Assumption: BreakpointType::kByUrl is 1):**

```c++
String16 breakpointId = generateBreakpointId(BreakpointType::kByUrl, "my-script.js", 15, 5);
```

**Output of `generateBreakpointId`:**  `"1:15:5:my-script.js"`

**`parseBreakpointId`:**

```c++
String16 breakpointIdToParse = "1:15:5:my-script.js";
BreakpointType type;
String16 scriptSelector;
int lineNumber;
int columnNumber;

bool success = parseBreakpointId(breakpointIdToParse, &type, &scriptSelector, &lineNumber, &columnNumber);
```

**Output of `parseBreakpointId`:**

* `success`: `true`
* `type`: `BreakpointType::kByUrl` (or its equivalent integer value, 1)
* `scriptSelector`: `"my-script.js"`
* `lineNumber`: `15`
* `columnNumber`: `5`

This demonstrates how the agent can create a unique identifier for a breakpoint and later parse it to retrieve the original breakpoint information.

**User-Common Programming Errors (Related to Debugging):**

This C++ code doesn't directly expose programming errors, but it's instrumental in helping developers find them. Common errors developers make that this code facilitates finding include:

* **Logic Errors:** Incorrect conditional statements, wrong calculations, flawed algorithms. Debugging helps step through the code to pinpoint where the logic deviates.
    ```javascript
    function calculateDiscount(price, hasCoupon) {
      if (hasCoupon = true) { // Intent was comparison (== or ===), assignment here!
        return price * 0.9;
      } else {
        return price;
      }
    }
    ```
    The debugger can show that `hasCoupon` is always `true` due to the assignment.
* **Type Errors:**  Operating on variables with unexpected data types.
    ```javascript
    function add(a, b) {
      return a + b;
    }

    let result = add("5", 3); // String concatenation instead of addition.
    ```
    Debugging would reveal that `a` is a string, leading to string concatenation.
* **Scope Issues:** Accessing variables outside their intended scope.
    ```javascript
    function myFunction() {
      let localVar = 10;
    }
    myFunction();
    console.log(localVar); // Error: localVar is not defined.
    ```
    The debugger can help understand the lifetime and scope of variables.
* **Asynchronous Issues:** Problems related to the timing and order of execution in asynchronous operations (Promises, `async/await`). The debugger's async call stack feature (mentioned in the code) is crucial here.

**Summary of Functionality (Part 1):**

The `v8/src/inspector/v8-debugger-agent-impl.cc` file implements the core logic of the V8 debugger agent. It provides the mechanisms for enabling and disabling debugging, setting and managing various types of breakpoints, controlling the execution flow of JavaScript code, inspecting the program's state during pauses, and communicating with the debugger frontend (like browser DevTools). It's a crucial component for enabling effective JavaScript debugging within the V8 engine.

### 提示词
```
这是目录为v8/src/inspector/v8-debugger-agent-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger-agent-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    if (script->getLanguage() == V8DebuggerScript::Lan
```