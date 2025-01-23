Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Initial Scan and Identification:**

   - The first thing I notice is the `#ifndef` and `#define` guards, indicating this is a header file. The name `v8-debugger-agent-impl.h` strongly suggests it's related to the V8 debugger implementation.
   - The inclusion of various standard library headers (`<deque>`, `<memory>`, etc.) and V8-specific headers (`"src/base/..."`, `"src/debug/..."`, `"src/inspector/protocol/..."`) confirms this.
   - The namespace `v8_inspector` and the class name `V8DebuggerAgentImpl` are key identifiers. The `Impl` suffix often indicates an implementation detail.

2. **High-Level Purpose Inference:**

   - The name `DebuggerAgent` strongly suggests this class acts as an intermediary or agent for interacting with the V8 debugger.
   - The inclusion of `protocol/Debugger.h` and `protocol::Debugger::Backend` suggests this class implements the "backend" part of the Chrome DevTools Protocol's Debugger domain. This means it handles the server-side logic for debugging.

3. **Protocol Methods (Key Functionality):**

   - The numerous public methods starting with `Response` and having names like `enable`, `disable`, `setBreakpointByUrl`, `continueToLocation`, `pause`, `resume`, `stepOver`, `evaluateOnCallFrame`, etc., directly correspond to the commands defined in the Chrome DevTools Protocol's Debugger domain.
   - *Deduction:*  The core functionality revolves around enabling/disabling the debugger, setting breakpoints, controlling execution flow (stepping, pausing, resuming), inspecting stack frames and variables, and managing script sources.

4. **Internal State and Data Structures:**

   - The private members provide insights into the internal workings:
     - `m_scripts`:  Likely stores information about loaded scripts, keyed by their ID.
     - `m_breakpointIdToDebuggerBreakpointIds`, `m_debuggerBreakpointIdToBreakpointId`: These suggest mappings between the debugger's internal breakpoint IDs and the IDs used by the inspector protocol.
     - `m_wasmDisassemblies`:  Indicates support for debugging WebAssembly.
     - `m_cachedScripts`: Suggests a mechanism for caching script content, likely for performance.
     - `m_breakReason`:  Stores information about why the debugger paused.
     - `m_blackboxPattern`, `m_blacklistedPositions`, `m_blacklistedExecutionContexts`:  Related to the "blackboxing" feature, allowing developers to ignore certain code during debugging.
   - *Deduction:* The class manages the state of the debugger session, including breakpoints, loaded scripts, and blackboxing rules.

5. **Callbacks and Event Handling:**

   - Methods like `didPause`, `didContinue`, `didParseSource`, and `didPauseOnInstrumentation` are clearly callbacks invoked by the core V8 debugger when certain events occur.
   - *Deduction:* The `V8DebuggerAgentImpl` reacts to debugger events and propagates them to the frontend (likely via the `m_frontend` member).

6. **Helper Methods:**

   - Private methods like `enableImpl`, `setBreakpointImpl`, `removeBreakpointImpl`, `processSkipList`, etc., encapsulate internal logic and contribute to the overall functionality.

7. **Torque Check:**

   - The prompt specifically asks about the `.tq` extension. Since the file ends in `.h`, it's a C++ header file, *not* a Torque file.

8. **JavaScript Relevance and Examples:**

   - Since this class *implements* the DevTools Debugger protocol, its functionality is directly exposed to JavaScript developers through the browser's debugging tools.
   - *Example Generation:* I would then think about common debugging actions and how they map to the methods in the header file. Setting a breakpoint in the browser's Sources panel uses the underlying `setBreakpointByUrl` or `setBreakpoint` methods. Stepping through code uses `stepOver`, `stepInto`, `stepOut`. Evaluating expressions uses `evaluateOnCallFrame`.

9. **Code Logic Inference and Examples:**

   - Consider a simple scenario like setting a breakpoint. The `setBreakpointByUrl` method takes a line number and potentially a URL.
   - *Hypothetical Input/Output:* If the input is a line number and URL, the output would ideally be a breakpoint ID and the actual location where the breakpoint was set (which might be slightly different if the exact line wasn't valid).
   - Think about the internal flow: The `V8DebuggerAgentImpl` likely communicates with the underlying `V8Debugger` to set the breakpoint in the V8 engine.

10. **Common Programming Errors:**

    - Relate the debugger functionality to common errors. Setting a breakpoint on the wrong line, forgetting a breakpoint, or not understanding asynchronous behavior are all common debugging scenarios. The methods in this class are the tools used to diagnose these issues.

11. **Refinement and Organization:**

    - Finally, structure the findings into logical categories: Purpose, Key Functions, Relationship to JavaScript, etc., to present a clear and comprehensive explanation.

This detailed thought process, moving from initial observation to detailed analysis and example generation, helps in understanding the role and functionality of the `V8DebuggerAgentImpl` class.
This C++ header file `v8-debugger-agent-impl.h` defines the implementation of the **Debugger Agent** for the V8 JavaScript engine's inspector. It acts as the backend for the debugging functionality exposed through the Chrome DevTools Protocol (CDP).

Here's a breakdown of its key functions:

**Core Responsibility:**

* **Bridging the Gap:** It acts as an intermediary between the V8 debugger API and the frontend (like Chrome DevTools). It translates high-level debugging commands from the frontend into low-level V8 debugger operations and vice versa.

**Key Functionalities and Methods:**

* **Enabling/Disabling Debugging:**
    * `enable()`: Activates the debugger.
    * `disable()`: Deactivates the debugger.
    * `setBreakpointsActive()`: Controls whether breakpoints are effective.
    * `setSkipAllPauses()`:  Allows skipping all debugger pauses.

* **Breakpoint Management:**
    * `setBreakpointByUrl()`: Sets a breakpoint based on URL, line number, and optional conditions.
    * `setBreakpoint()`: Sets a breakpoint at a specific location (script ID and position).
    * `setBreakpointOnFunctionCall()`: Sets a breakpoint when a specific function is called.
    * `setInstrumentationBreakpoint()`: Sets a breakpoint for specific instrumentation events.
    * `removeBreakpoint()`: Removes a breakpoint.

* **Controlling Execution Flow:**
    * `continueToLocation()`: Resumes execution until a specified location is reached.
    * `pause()`: Pauses script execution.
    * `resume()`: Resumes script execution.
    * `stepOver()`: Executes the current line and steps to the next line in the same scope.
    * `stepInto()`: Steps into a function call on the current line.
    * `stepOut()`: Steps out of the current function.
    * `pauseOnAsyncCall()`: Pauses execution when an asynchronous call is made.

* **Inspecting State:**
    * `getStackTrace()`: Retrieves the current call stack.
    * `evaluateOnCallFrame()`: Evaluates an expression in the context of a specific call frame.
    * `getScriptSource()`: Retrieves the source code of a script.
    * `disassembleWasmModule()`, `nextWasmDisassemblyChunk()`, `getWasmBytecode()`:  Functions for inspecting WebAssembly code.

* **Modifying State (with caution):**
    * `setScriptSource()`:  Modifies the source code of a script (can be risky).
    * `restartFrame()`: Restarts a specific stack frame.
    * `setVariableValue()`: Modifies the value of a variable in a specific scope.
    * `setReturnValue()`: Sets the return value of the current function.

* **Blackboxing (Ignoring Code):**
    * `setBlackboxPatterns()`: Sets regular expressions to identify scripts or functions to be ignored during debugging.
    * `setBlackboxExecutionContexts()`:  Blackboxes specific execution contexts.
    * `setBlackboxedRanges()`: Blackboxes specific ranges within a script.

* **Asynchronous Call Stack Handling:**
    * `setAsyncCallStackDepth()`: Controls the depth of the asynchronous call stack captured during debugging.

* **Internal Communication:**
    * Methods like `didPause()`, `didContinue()`, `didParseSource()` are called by the V8 debugger to notify the agent about events.

**Is it a Torque file?**

No, `v8/src/inspector/v8-debugger-agent-impl.h` ends with `.h`, which signifies a **C++ header file**. Torque source files typically end with `.tq`.

**Relationship to JavaScript and JavaScript Examples:**

This C++ code directly enables the debugging features you use in your browser's developer tools when working with JavaScript. Here are some examples of how the methods in this file relate to JavaScript debugging actions:

```javascript
// Setting a breakpoint by URL and line number:
// This action in DevTools would trigger a call to V8DebuggerAgentImpl::setBreakpointByUrl

// In the "Sources" panel, you click on line 10 of "my_script.js"

// Setting a conditional breakpoint:
// This would likely use the same method but with the 'optionalCondition' filled.

// In the "Sources" panel, you right-click on a line and select "Add conditional breakpoint...",
// then enter a condition like "x > 5".

// Stepping over a line:
// This corresponds to V8DebuggerAgentImpl::stepOver

function myFunction() {
  let a = 1; // Current execution point
  let b = 2; // After clicking "Step Over", execution moves here
  console.log(a + b);
}
myFunction();

// Stepping into a function call:
// This corresponds to V8DebuggerAgentImpl::stepInto

function add(x, y) {
  return x + y; // After clicking "Step Into", execution enters this function
}

function calculate() {
  let result = add(5, 3); // Current execution point
  console.log(result);
}
calculate();

// Evaluating an expression in the console during a breakpoint:
// This corresponds to V8DebuggerAgentImpl::evaluateOnCallFrame

// Breakpoint is hit in a function:
function debugMe(value) {
  debugger; // Execution pauses here
  console.log(value);
}
debugMe(10);

// In the "Console" panel, you type:  value * 2
// This triggers a call to evaluateOnCallFrame to evaluate "value * 2"
// in the current call frame.
```

**Code Logic Inference (Hypothetical Example: `setBreakpointByUrl`)**

**Assumptions:**

* **Input:** `lineNumber = 10`, `optionalURL = "my_script.js"`
* The script "my_script.js" has already been parsed and is known to the debugger agent.

**Likely Logic Flow:**

1. **Receive Request:** The `setBreakpointByUrl` method in `V8DebuggerAgentImpl` is called with the provided line number and URL.
2. **Find Script:** The agent searches its internal representation of scripts (`m_scripts`) to find the `V8DebuggerScript` object corresponding to "my_script.js".
3. **Translate to Location:** The provided line number is translated into an internal location (likely a script ID and a bytecode offset or source position) within the script.
4. **Call V8 Debugger:** The agent calls the underlying V8 debugger API (likely through `m_debugger`) to set a breakpoint at the determined location.
5. **Store Breakpoint Info:**  The agent stores information about the created breakpoint (e.g., a unique breakpoint ID) in its internal data structures (`m_breakpointIdToDebuggerBreakpointIds`).
6. **Send Response:** A response is sent back to the frontend, including the generated breakpoint ID and the actual location where the breakpoint was set (which might differ slightly if the requested line was not a valid breakpoint location).

**Output:** A `Response` object containing the breakpoint ID.

**User-Common Programming Errors and Debugger Agent's Role:**

The `V8DebuggerAgentImpl` helps developers identify and fix common programming errors. Here are a few examples:

* **Incorrect Logic/Unexpected Values:**
    * **Error:** A variable has an unexpected value, leading to incorrect program behavior.
    * **Debugger Agent's Role:** By setting breakpoints and using `evaluateOnCallFrame`, developers can inspect variable values at different points in the code to understand where the logic deviates.

    ```javascript
    function calculateArea(width, height) {
      let area = width + height; // Oops! Should be multiplication
      return area;
    }

    let result = calculateArea(5, 10); // Breakpoint here
    console.log(result);
    ```
    Debugging this, you'd see `area` is 15 instead of 50.

* **Incorrect Control Flow:**
    * **Error:** Code is not executing in the expected order, leading to missed steps or unexpected function calls.
    * **Debugger Agent's Role:**  Stepping through the code (`stepOver`, `stepInto`, `stepOut`) allows developers to follow the execution path and identify where the flow diverges from the intended sequence.

    ```javascript
    function processData(data) {
      if (data) {
        // ... some processing
      } // Missing 'else' block leads to unexpected behavior if data is falsy
      console.log("Data processing complete");
    }

    processData(null); // Breakpoint here and step through
    ```
    Stepping through would reveal that "Data processing complete" is always printed, even when `data` is null.

* **Asynchronous Issues:**
    * **Error:** Problems with asynchronous operations (e.g., incorrect timing, unhandled promises).
    * **Debugger Agent's Role:**  Features like `pauseOnAsyncCall` and viewing asynchronous call stacks help developers understand the timing and dependencies of asynchronous operations.

    ```javascript
    async function fetchData() {
      const response = await fetch('/api/data');
      const data = await response.json();
      console.log(data);
    }

    fetchData(); // Set a breakpoint inside fetchData and step through the 'await' calls.
    ```

* **Scope Issues:**
    * **Error:**  Variables are not accessible in the intended scope.
    * **Debugger Agent's Role:** Inspecting the call stack and evaluating expressions in different call frames helps developers understand variable scope and closure behavior.

    ```javascript
    function outer() {
      let outerVar = 10;
      function inner() {
        console.log(outerVar); // Breakpoint here
      }
      inner();
    }
    outer();
    ```
    Debugging would show that `outerVar` is accessible within `inner` due to closure.

In summary, `v8-debugger-agent-impl.h` defines the core logic that enables JavaScript debugging in V8. It acts as the crucial link between the developer's debugging actions and the V8 engine's internal state and execution.

### 提示词
```
这是目录为v8/src/inspector/v8-debugger-agent-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger-agent-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INSPECTOR_V8_DEBUGGER_AGENT_IMPL_H_
#define V8_INSPECTOR_V8_DEBUGGER_AGENT_IMPL_H_

#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

#include "src/base/enum-set.h"
#include "src/base/macros.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/protocol/Debugger.h"
#include "src/inspector/protocol/Forward.h"

namespace v8_inspector {

struct ScriptBreakpoint;
class DisassemblyCollectorImpl;
class V8Debugger;
class V8DebuggerScript;
class V8InspectorImpl;
class V8InspectorSessionImpl;
class V8Regex;

using protocol::Maybe;
using protocol::Response;

class V8DebuggerAgentImpl : public protocol::Debugger::Backend {
 public:
  enum BreakpointSource {
    UserBreakpointSource,
    DebugCommandBreakpointSource,
    MonitorCommandBreakpointSource
  };

  V8DebuggerAgentImpl(V8InspectorSessionImpl*, protocol::FrontendChannel*,
                      protocol::DictionaryValue* state);
  ~V8DebuggerAgentImpl() override;
  V8DebuggerAgentImpl(const V8DebuggerAgentImpl&) = delete;
  V8DebuggerAgentImpl& operator=(const V8DebuggerAgentImpl&) = delete;
  void restore();
  void stop();

  // Part of the protocol.
  Response enable(Maybe<double> maxScriptsCacheSize,
                  String16* outDebuggerId) override;
  Response disable() override;
  Response setBreakpointsActive(bool active) override;
  Response setSkipAllPauses(bool skip) override;
  Response setBreakpointByUrl(
      int lineNumber, Maybe<String16> optionalURL,
      Maybe<String16> optionalURLRegex, Maybe<String16> optionalScriptHash,
      Maybe<int> optionalColumnNumber, Maybe<String16> optionalCondition,
      String16*,
      std::unique_ptr<protocol::Array<protocol::Debugger::Location>>* locations)
      override;
  Response setBreakpoint(
      std::unique_ptr<protocol::Debugger::Location>,
      Maybe<String16> optionalCondition, String16*,
      std::unique_ptr<protocol::Debugger::Location>* actualLocation) override;
  Response setBreakpointOnFunctionCall(const String16& functionObjectId,
                                       Maybe<String16> optionalCondition,
                                       String16* outBreakpointId) override;
  Response setInstrumentationBreakpoint(const String16& instrumentation,
                                        String16* outBreakpointId) override;
  Response removeBreakpoint(const String16& breakpointId) override;
  Response continueToLocation(std::unique_ptr<protocol::Debugger::Location>,
                              Maybe<String16> targetCallFrames) override;
  Response getStackTrace(
      std::unique_ptr<protocol::Runtime::StackTraceId> inStackTraceId,
      std::unique_ptr<protocol::Runtime::StackTrace>* outStackTrace) override;
  Response searchInContent(
      const String16& scriptId, const String16& query,
      Maybe<bool> optionalCaseSensitive, Maybe<bool> optionalIsRegex,
      std::unique_ptr<protocol::Array<protocol::Debugger::SearchMatch>>*)
      override;
  Response getPossibleBreakpoints(
      std::unique_ptr<protocol::Debugger::Location> start,
      Maybe<protocol::Debugger::Location> end, Maybe<bool> restrictToFunction,
      std::unique_ptr<protocol::Array<protocol::Debugger::BreakLocation>>*
          locations) override;
  Response setScriptSource(
      const String16& inScriptId, const String16& inScriptSource,
      Maybe<bool> dryRun, Maybe<bool> allowTopFrameEditing,
      Maybe<protocol::Array<protocol::Debugger::CallFrame>>* optOutCallFrames,
      Maybe<bool>* optOutStackChanged,
      Maybe<protocol::Runtime::StackTrace>* optOutAsyncStackTrace,
      Maybe<protocol::Runtime::StackTraceId>* optOutAsyncStackTraceId,
      String16* outStatus,
      Maybe<protocol::Runtime::ExceptionDetails>* optOutCompileError) override;
  Response restartFrame(
      const String16& callFrameId, Maybe<String16> mode,
      std::unique_ptr<protocol::Array<protocol::Debugger::CallFrame>>*
          newCallFrames,
      Maybe<protocol::Runtime::StackTrace>* asyncStackTrace,
      Maybe<protocol::Runtime::StackTraceId>* asyncStackTraceId) override;
  Response getScriptSource(const String16& scriptId, String16* scriptSource,
                           Maybe<protocol::Binary>* bytecode) override;
  Response disassembleWasmModule(
      const String16& in_scriptId, Maybe<String16>* out_streamId,
      int* out_totalNumberOfLines,
      std::unique_ptr<protocol::Array<int>>* out_functionBodyOffsets,
      std::unique_ptr<protocol::Debugger::WasmDisassemblyChunk>* out_chunk)
      override;
  Response nextWasmDisassemblyChunk(
      const String16& in_streamId,
      std::unique_ptr<protocol::Debugger::WasmDisassemblyChunk>* out_chunk)
      override;
  Response getWasmBytecode(const String16& scriptId,
                           protocol::Binary* bytecode) override;
  Response pause() override;
  Response resume(Maybe<bool> terminateOnResume) override;
  Response stepOver(Maybe<protocol::Array<protocol::Debugger::LocationRange>>
                        inSkipList) override;
  Response stepInto(Maybe<bool> inBreakOnAsyncCall,
                    Maybe<protocol::Array<protocol::Debugger::LocationRange>>
                        inSkipList) override;
  Response stepOut() override;
  Response pauseOnAsyncCall(std::unique_ptr<protocol::Runtime::StackTraceId>
                                inParentStackTraceId) override;
  Response setPauseOnExceptions(const String16& pauseState) override;
  Response evaluateOnCallFrame(
      const String16& callFrameId, const String16& expression,
      Maybe<String16> objectGroup, Maybe<bool> includeCommandLineAPI,
      Maybe<bool> silent, Maybe<bool> returnByValue,
      Maybe<bool> generatePreview, Maybe<bool> throwOnSideEffect,
      Maybe<double> timeout,
      std::unique_ptr<protocol::Runtime::RemoteObject>* result,
      Maybe<protocol::Runtime::ExceptionDetails>*) override;
  Response setVariableValue(
      int scopeNumber, const String16& variableName,
      std::unique_ptr<protocol::Runtime::CallArgument> newValue,
      const String16& callFrame) override;
  Response setReturnValue(
      std::unique_ptr<protocol::Runtime::CallArgument> newValue) override;
  Response setAsyncCallStackDepth(int depth) override;
  Response setBlackboxPatterns(
      std::unique_ptr<protocol::Array<String16>> patterns,
      Maybe<bool> skipAnonymous) override;
  Response setBlackboxExecutionContexts(
      std::unique_ptr<protocol::Array<String16>> uniqueIds) override;
  Response setBlackboxedRanges(
      const String16& scriptId,
      std::unique_ptr<protocol::Array<protocol::Debugger::ScriptPosition>>
          positions) override;

  bool enabled() const { return m_enableState == kEnabled; }

  void setBreakpointFor(v8::Local<v8::Function> function,
                        v8::Local<v8::String> condition,
                        BreakpointSource source);
  void removeBreakpointFor(v8::Local<v8::Function> function,
                           BreakpointSource source);
  void schedulePauseOnNextStatement(
      const String16& breakReason,
      std::unique_ptr<protocol::DictionaryValue> data);
  void cancelPauseOnNextStatement();
  void breakProgram(const String16& breakReason,
                    std::unique_ptr<protocol::DictionaryValue> data);

  void reset();

  bool instrumentationFinished() { return m_instrumentationFinished; }
  // Interface for V8InspectorImpl
  void didPauseOnInstrumentation(v8::debug::BreakpointId instrumentationId);

  void didPause(int contextId, v8::Local<v8::Value> exception,
                const std::vector<v8::debug::BreakpointId>& hitBreakpoints,
                v8::debug::ExceptionType exceptionType, bool isUncaught,
                v8::debug::BreakReasons breakReasons);
  void didContinue();
  void didParseSource(std::unique_ptr<V8DebuggerScript>, bool success);

  bool isFunctionBlackboxed(const String16& scriptId,
                            const v8::debug::Location& start,
                            const v8::debug::Location& end);
  bool shouldBeSkipped(const String16& scriptId, int line, int column);

  bool acceptsPause(bool isOOMBreak) const;

  void ScriptCollected(const V8DebuggerScript* script);

  v8::Isolate* isolate() { return m_isolate; }

  void clearBreakDetails();

 private:
  void enableImpl();

  Response currentCallFrames(
      std::unique_ptr<protocol::Array<protocol::Debugger::CallFrame>>*);
  std::unique_ptr<protocol::Runtime::StackTrace> currentAsyncStackTrace();
  std::unique_ptr<protocol::Runtime::StackTraceId> currentExternalStackTrace();

  void setPauseOnExceptionsImpl(int);

  std::unique_ptr<protocol::Debugger::Location> setBreakpointImpl(
      const String16& breakpointId, const String16& scriptId,
      const String16& condition, int lineNumber, int columnNumber);
  void setBreakpointImpl(const String16& breakpointId,
                         v8::Local<v8::Function> function,
                         v8::Local<v8::String> condition);
  void removeBreakpointImpl(const String16& breakpointId,
                            const std::vector<V8DebuggerScript*>& scripts);

  void internalSetAsyncCallStackDepth(int);
  void increaseCachedSkipStackGeneration();

  Response setBlackboxPattern(const String16& pattern);
  void resetBlackboxedStateCache();

  bool isPaused() const;

  void setScriptInstrumentationBreakpointIfNeeded(V8DebuggerScript* script);

  Response processSkipList(
      protocol::Array<protocol::Debugger::LocationRange>& skipList);

  using ScriptsMap =
      std::unordered_map<String16, std::unique_ptr<V8DebuggerScript>>;
  using BreakpointIdToDebuggerBreakpointIdsMap =
      std::unordered_map<String16, std::vector<v8::debug::BreakpointId>>;
  using DebuggerBreakpointIdToBreakpointIdMap =
      std::unordered_map<v8::debug::BreakpointId, String16>;

  enum EnableState {
    kDisabled,
    kEnabled,
    kStopping,  // This is the same as 'disabled', but it cannot become enabled
                // again.
  };

  V8InspectorImpl* m_inspector;
  V8Debugger* m_debugger;
  V8InspectorSessionImpl* m_session;
  EnableState m_enableState;
  protocol::DictionaryValue* m_state;
  protocol::Debugger::Frontend m_frontend;
  v8::Isolate* m_isolate;
  ScriptsMap m_scripts;
  BreakpointIdToDebuggerBreakpointIdsMap m_breakpointIdToDebuggerBreakpointIds;
  DebuggerBreakpointIdToBreakpointIdMap m_debuggerBreakpointIdToBreakpointId;
  std::map<String16, std::unique_ptr<DisassemblyCollectorImpl>>
      m_wasmDisassemblies;
  size_t m_nextWasmDisassemblyStreamId = 0;

  size_t m_maxScriptCacheSize = 0;
  size_t m_cachedScriptSize = 0;
  struct CachedScript {
    String16 scriptId;
    String16 source;
    std::vector<uint8_t> bytecode;

    size_t size() const {
      return source.length() * sizeof(UChar) + bytecode.size();
    }
  };
  std::deque<CachedScript> m_cachedScripts;

  using BreakReason =
      std::pair<String16, std::unique_ptr<protocol::DictionaryValue>>;
  std::vector<BreakReason> m_breakReason;

  void pushBreakDetails(
      const String16& breakReason,
      std::unique_ptr<protocol::DictionaryValue> breakAuxData);
  void popBreakDetails();

  bool m_skipAllPauses = false;
  bool m_breakpointsActive = false;
  bool m_instrumentationFinished = true;
  bool m_skipAnonymousScripts = false;

  std::unique_ptr<V8Regex> m_blackboxPattern;
  std::unordered_map<String16, std::vector<std::pair<int, int>>>
      m_blackboxedPositions;
  std::unordered_map<String16, std::vector<std::pair<int, int>>> m_skipList;
  std::unordered_set<String16> m_blackboxedExecutionContexts;
};

}  // namespace v8_inspector

#endif  // V8_INSPECTOR_V8_DEBUGGER_AGENT_IMPL_H_
```