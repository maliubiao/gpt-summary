Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/inspector/v8-debugger-agent-impl.cc`.

Here's a breakdown of the code's functions and how to address the user's specific requests:

1. **Identify the main purpose:** The code snippet deals with debugger functionalities within V8, specifically related to breakpoints, stepping, stack traces, and live editing.

2. **List the functions and their actions:** Go through each function in the snippet and describe what it does.

3. **Check for Torque:**  The user asked about `.tq` files. This snippet is `.cc`, so it's not Torque.

4. **Relate to JavaScript:**  Since debugging directly impacts how developers interact with JavaScript, there's a strong connection. I'll provide JavaScript examples illustrating the debugger features controlled by this C++ code.

5. **Code logic and inference:**  Some functions involve logical steps, like finding breakpoints. I'll pick a function and create a simple "input/output" scenario.

6. **Common programming errors:** Debugging helps find errors. I'll think of common mistakes that the debugger helps uncover.

7. **Summarize functionality (part 2):** This requires synthesizing the individual function descriptions into a broader overview.

**Detailed thought process for each point:**

* **Main purpose:**  Keywords like "Breakpoint," "continueToLocation," "getStackTrace," "setScriptSource," clearly indicate debugger-related actions.

* **Function listing:**
    * `removeBreakpoint`:  Removes a breakpoint.
    * `removeBreakpointImpl`:  The internal implementation of removing breakpoints, handling both regular and WebAssembly breakpoints.
    * `getPossibleBreakpoints`:  Determines valid locations for setting breakpoints.
    * `continueToLocation`:  Resumes execution until a specific location.
    * `getStackTrace`: Retrieves the current call stack.
    * `isFunctionBlackboxed`: Checks if a function should be skipped during debugging.
    * `shouldBeSkipped`: Checks if a specific location should be skipped based on skip lists.
    * `acceptsPause`: Determines if the debugger should pause.
    * `setBreakpointImpl`:  Internal implementation to set a breakpoint at a line/column or function.
    * `searchInContent`: Searches for text within a script.
    * `setScriptSource`: Modifies the source code of a script (live edit).
    * `restartFrame`: Restarts the execution of a specific call frame.
    * `getScriptSource`: Retrieves the source code of a script.
    * `disassembleWasmModule`: Retrieves the disassembled code of a WebAssembly module.
    * `nextWasmDisassemblyChunk`: Retrieves the next chunk of disassembled WebAssembly code.
    * `getWasmBytecode`: Retrieves the bytecode of a WebAssembly module.
    * `pushBreakDetails`, `popBreakDetails`, `clearBreakDetails`: Manage information about the reason for pausing.
    * `schedulePauseOnNextStatement`, `cancelPauseOnNextStatement`:  Control pausing on the next line of code.
    * `pause`: Initiates a debugger pause.
    * `resume`: Resumes program execution.
    * `stepOver`, `stepInto`, `stepOut`: Stepping controls.
    * `pauseOnAsyncCall`: (Deprecated).
    * `setPauseOnExceptions`, `setPauseOnExceptionsImpl`: Configures pausing on exceptions.
    * `evaluateOnCallFrame`: Executes code within a specific call frame.
    * `setVariableValue`: Modifies the value of a variable in a call frame.

* **Torque:** A simple check of the file extension suffices.

* **JavaScript examples:**  Think of common debugging scenarios and map them to the C++ functions. Setting breakpoints, stepping, inspecting variables are good examples.

* **Code logic and inference (example with `getPossibleBreakpoints`):**
    * **Assumption:** A user wants to find all possible breakpoints in a specific function.
    * **Input:** `scriptId`, `start` location within the function (line/column).
    * **Output:** A list of valid `BreakLocation` objects.

* **Common programming errors:**  Think about what developers use debuggers for:
    * Incorrect variable values.
    * Unexpected control flow.
    * Errors during asynchronous operations.

* **Summarize functionality (part 2):**  Focus on the core themes: breakpoint management, stepping controls, code inspection, and live editing capabilities.

**(Self-correction during thought process):**

* Initially, I might have just listed function names. The prompt asks for *functionality*, so I need to describe *what each function does*.
* I need to ensure the JavaScript examples are clear and directly relate to the C++ code's purpose.
* For the logic inference, I should choose a function that demonstrates a clear input-to-output transformation.
* When thinking about common errors, it's important to link them back to the debugging actions provided by these functions.

By following these steps and considering potential pitfalls, I can generate a comprehensive and accurate response to the user's request.
这是对 V8 源代码文件 `v8/src/inspector/v8-debugger-agent-impl.cc` 的功能进行分析的第二部分。根据之前第一部分的分析，我们已经了解了该文件是 V8 调试器的核心实现部分，负责处理与调试会话相关的各种操作。

现在，我们来归纳一下这部分代码的功能：

**核心功能归纳：**

这部分代码主要负责以下调试功能的实现：

1. **移除断点 (Breakpoint Removal):**
   - `removeBreakpoint`:  接收前端发来的移除断点请求，并根据断点 ID 找到对应的内部调试器断点 ID，然后调用 `removeBreakpointImpl` 执行移除操作。
   - `removeBreakpointImpl`:  实际执行断点移除逻辑，包括移除 WebAssembly 断点 (如果启用) 和普通 JavaScript 断点，并更新内部的断点映射关系。

2. **获取可能的断点位置 (Possible Breakpoints):**
   - `getPossibleBreakpoints`:  根据给定的起始和可选的结束位置，查找脚本中可以设置断点的所有有效位置。它会调用 V8 内部的调试接口来获取这些位置，并将结果转换为调试协议定义的 `BreakLocation` 对象返回给前端。

3. **继续执行到指定位置 (Continue to Location):**
   - `continueToLocation`:  允许开发者指定一个脚本中的位置（行号和列号），让程序继续执行直到到达该位置。它会将请求转发给 V8 内部的调试器。

4. **获取调用栈信息 (Stack Trace):**
   - `getStackTrace`:  根据提供的调用栈 ID，从 V8 调试器中检索相应的调用栈信息，并将其转换为调试协议定义的 `StackTrace` 对象返回给前端。

5. **判断函数是否被黑盒 (Function Blackboxing):**
   - `isFunctionBlackboxed`:  判断给定的脚本和位置范围是否被设置为黑盒。黑盒功能允许开发者在调试过程中跳过某些代码，例如第三方库的代码。判断依据包括黑盒模式、是否跳过匿名脚本以及黑盒位置列表。

6. **判断是否应该跳过 (Should Be Skipped):**
   - `shouldBeSkipped`:  根据预定义的跳过列表，判断当前执行位置是否应该被调试器跳过。

7. **判断是否接受暂停 (Accepts Pause):**
   - `acceptsPause`:  判断调试器当前是否应该暂停，考虑了调试器是否启用以及是否设置了跳过所有暂停。

8. **设置断点 (Set Breakpoint - Implementation):**
   - `setBreakpointImpl` (两个重载版本):  实际执行断点的设置操作。一个版本接收脚本 ID、行号、列号和条件，另一个版本接收函数对象和条件。它会调用 V8 内部的调试接口来设置断点，并将内部调试器断点 ID 与外部断点 ID 关联起来。

9. **在内容中搜索 (Search in Content):**
   - `searchInContent`:  在指定的脚本内容中搜索匹配的文本，支持区分大小写和正则表达式。

10. **设置脚本源代码 (Set Script Source - Live Edit):**
    - `setScriptSource`:  允许在调试过程中修改脚本的源代码 (Live Edit)。它会将新的源代码传递给 V8，并根据 V8 的返回结果，告知前端修改状态，例如成功、编译错误、被激活函数阻止等。

11. **重启帧 (Restart Frame):**
    - `restartFrame`:  允许开发者重新执行当前调用栈中的某个帧。

12. **获取脚本源代码 (Get Script Source):**
    - `getScriptSource`:  根据脚本 ID 获取脚本的源代码，也可能包含字节码信息。

13. **反汇编 WebAssembly 模块 (Disassemble WASM Module):**
    - `disassembleWasmModule`:  将指定的 WebAssembly 模块反汇编成可读的汇编代码，并分块返回给前端。

14. **获取下一个 WebAssembly 反汇编块 (Next WASM Disassembly Chunk):**
    - `nextWasmDisassemblyChunk`:  在 WebAssembly 反汇编结果分块返回的情况下，获取下一个代码块。

15. **获取 WebAssembly 字节码 (Get WASM Bytecode):**
    - `getWasmBytecode`:  获取指定 WebAssembly 脚本的原始字节码。

16. **管理中断详情 (Break Details):**
    - `pushBreakDetails`, `popBreakDetails`, `clearBreakDetails`:  用于管理中断的原因和附加数据。

17. **计划在下一语句暂停 (Schedule Pause on Next Statement):**
    - `schedulePauseOnNextStatement`:  设置在执行到下一条语句时暂停，通常用于单步执行。

18. **取消在下一语句暂停 (Cancel Pause on Next Statement):**
    - `cancelPauseOnNextStatement`:  取消之前设置的在下一语句暂停的计划。

19. **暂停 (Pause):**
    - `pause`:  主动触发调试器暂停。

20. **恢复 (Resume):**
    - `resume`:  恢复程序的执行。

21. **单步跳过 (Step Over):**
    - `stepOver`:  执行当前语句，然后暂停在下一条语句。可以配合跳过列表使用。

22. **单步进入 (Step Into):**
    - `stepInto`:  进入当前语句调用的函数内部。可以设置是否在异步调用处中断，也可以配合跳过列表使用。

23. **单步跳出 (Step Out):**
    - `stepOut`:  执行完当前函数，然后暂停在调用该函数的语句之后。

24. **异步调用时暂停 (Pause on Async Call):**
    - `pauseOnAsyncCall`:  (已弃用) 曾经用于在异步操作调用时暂停。

25. **设置异常时的暂停行为 (Set Pause on Exceptions):**
    - `setPauseOnExceptions`, `setPauseOnExceptionsImpl`:  配置调试器在遇到异常时的暂停行为，例如不暂停、所有异常都暂停、仅捕获的异常暂停、仅未捕获的异常暂停。

26. **在调用帧上求值 (Evaluate on Call Frame):**
    - `evaluateOnCallFrame`:  在指定的调用帧上下文中执行一段 JavaScript 代码，并返回结果。

27. **设置变量值 (Set Variable Value):**
    - `setVariableValue`:  允许在调试过程中修改指定调用帧中变量的值。

**与 JavaScript 的关系及示例：**

这些 C++ 代码直接实现了我们在 JavaScript 调试器中使用的各种功能。以下是一些 JavaScript 代码示例，以及它们背后对应的 `v8-debugger-agent-impl.cc` 中的功能：

```javascript
// 设置断点
debugger; // 对应 pause() 或 setBreakpointImpl()

function myFunction() {
  let x = 10; // 可以在这里设置断点，对应 setBreakpointImpl()
  console.log(x);
}

// 单步执行
// 在调试器中点击 "Step Over" 按钮，对应 stepOver()
// 在调试器中点击 "Step Into" 按钮，对应 stepInto()
// 在调试器中点击 "Step Out" 按钮，对应 stepOut()

// 查看调用栈
// 调试器会显示当前的调用栈，对应 getStackTrace()

// 修改变量的值
// 在调试器中，可以修改变量 x 的值，对应 setVariableValue()

// 代码热更新 (Live Edit)
// 在 Chrome DevTools 中修改代码并保存，对应 setScriptSource()
```

**代码逻辑推理示例 (以 `getPossibleBreakpoints` 为例):**

**假设输入：**

- `start`:  `scriptId: "someScriptId"`, `lineNumber: 5`, `columnNumber: 0`
- `end`:  `scriptId: "someScriptId"`, `lineNumber: 10`, `columnNumber: 5`
- `restrictToFunction`: `false`

**输出 (可能的):**

一个 `protocol::Array<protocol::Debugger::BreakLocation>`，包含以下 `BreakLocation` 对象：

- `{ scriptId: "someScriptId", lineNumber: 6, columnNumber: 2 }`
- `{ scriptId: "someScriptId", lineNumber: 7, columnNumber: 0 }`
- `{ scriptId: "someScriptId", lineNumber: 9, columnNumber: 10 }`

**推理过程：**

`getPossibleBreakpoints` 函数会根据提供的脚本 ID，在内部查找对应的 V8 调试脚本对象。然后，它会调用该脚本对象的 `getPossibleBreakpoints` 方法，传入起始和结束位置。V8 内部的逻辑会分析脚本的语法结构，找出所有可以安全设置断点的语句或表达式的起始位置。这些位置会被封装成 `BreakLocation` 对象返回。

**涉及用户常见的编程错误 (调试器辅助发现):**

调试器可以帮助开发者发现各种常见的编程错误，例如：

- **变量未定义或赋值错误:** 通过设置断点和查看变量值，可以发现变量在某个时刻是否被正确赋值。
- **逻辑错误:** 通过单步执行，可以跟踪代码的执行流程，找到程序执行路径与预期不符的地方。
- **函数调用错误:** 可以查看调用栈，了解函数的调用顺序和参数传递情况。
- **异步操作中的问题:** 可以通过断点和查看异步操作的状态，理解异步代码的执行时序。
- **异常处理错误:** 可以设置在异常发生时暂停，查看异常的类型和发生的位置。

**总结：**

这部分 `V8DebuggerAgentImpl` 的代码集中实现了 V8 调试器的核心交互功能，涵盖了断点管理、代码执行控制（单步、恢复）、调用栈查看、代码检查（搜索、获取源码）、动态代码修改以及 WebAssembly 调试支持等关键方面。这些功能共同构成了开发者在 Chrome DevTools 或其他 V8 调试客户端中使用的调试体验的基础。

Prompt: 
```
这是目录为v8/src/inspector/v8-debugger-agent-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger-agent-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
guage::WebAssembly) {
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
"""


```