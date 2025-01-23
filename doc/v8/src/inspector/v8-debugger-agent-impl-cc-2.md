Response:
The user wants a summary of the functionality of the provided C++ code. The code is a part of the V8 JavaScript engine's debugger implementation.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `v8-debugger-agent-impl.cc` strongly suggests this code implements the debugger agent. This agent is responsible for handling communication and interactions related to debugging JavaScript code.

2. **Analyze the methods:** Go through the public methods of the `V8DebuggerAgentImpl` class. These methods usually correspond to specific debugger actions or functionalities.

3. **Categorize the functionalities:** Group related methods together to form higher-level functionalities. For example, methods dealing with breakpoints, stepping, call frames, etc.

4. **Look for connections to JavaScript:** Identify methods that directly interact with JavaScript concepts like scripts, functions, execution contexts, and values.

5. **Check for Torque involvement:** The prompt specifically asks about `.tq` files. Since the provided code is `.cc`, we can immediately say it's not Torque.

6. **Address the JavaScript example request:** For functionalities related to JavaScript, provide simple illustrative JavaScript code snippets.

7. **Handle code logic/inference and common errors:** Examine methods where the behavior depends on specific inputs or configurations. If there are common programming errors that this code helps to debug, mention them.

8. **Consider the multi-part context:**  Since this is part 3 of 3, assume that the previous parts have laid the groundwork. This part likely deals with more specific and complex aspects of the debugger agent.

9. **Synthesize the summary:** Combine the categorized functionalities and other observations into a concise summary.

**Detailed Method Analysis and Categorization (Mental Walkthrough):**

* **Enabling/Disabling:** `enable()`, `disable()`, `enabled()` - Core debugger state management.
* **Pausing/Resuming:** `pause()`, `resume()`, `setPauseOnExceptions()`, `setPauseOnCallFrames()` - Controls execution flow for debugging.
* **Stepping:** `stepOver()`, `stepInto()`, `stepOut()`, `stepWith горячей перезагрузкой()` - Stepping through the code.
* **Breakpoints:** `setBreakpointByUrl()`, `setBreakpoint()`, `removeBreakpoint()`, `getPossibleBreakpoints()`, `setBreakpointsActive()`, `setScriptInstrumentationBreakpointIfNeeded()` - Managing breakpoints.
* **Call Stack:** `getStackTrace()`, `getBacktraceFrames()`, `evaluateOnCallFrame()`, `setVariableValue()`, `setReturnValue()`, `currentCallFrames()` - Inspecting the call stack and modifying values.
* **Async/External Stacks:** `setAsyncCallStackDepth()`, `currentAsyncStackTrace()`, `currentExternalStackTrace()` - Handling asynchronous and external call stacks.
* **Blackboxing:** `setBlackboxPatterns()`, `setBlackboxExecutionContexts()`, `setBlackboxedRanges()` - Ignoring specific code during debugging.
* **Script Handling:** `didParseSource()`, `ScriptCollected()` - Receiving notifications about script loading and unloading.
* **Instrumentation:** `didPauseOnInstrumentation()` - Handling instrumentation breakpoints.
* **Pause Handling:** `didPause()`, `didContinue()`, `breakProgram()` - Reacting to pause events.
* **Internal Helpers:** `isValidPosition()`, `isValidRangeOfPositions()`, `buildScopes()`, `setBreakpointImpl()`, `removeBreakpointImpl()`, `generateBreakpointId()`, `parseBreakpointId()`, etc. - Internal utility functions.
* **Skip List:** `processSkipList()` -  Likely related to skipping certain code regions.
* **Resetting:** `reset()` - Resetting the debugger state.
* **Stopping:** `stop()` -  Stopping the debugger agent.

**JavaScript Connections:**  Many methods directly deal with JavaScript concepts: setting breakpoints in URLs or specific lines, evaluating expressions in the context of a call frame, setting variable values, handling exceptions, and stepping through code.

**Torque:**  The file extension is `.cc`, so it's C++, not Torque.

**Common Errors:**  The code implicitly helps debug common errors by allowing developers to step through code, inspect variables, and set breakpoints at potential error locations. Specific examples could be unhandled exceptions, incorrect variable assignments, or unexpected control flow.

**Synthesizing the Summary based on Part 3 context:** Given that it's the final part, it's likely focusing on more advanced features like modifying the execution state (`setReturnValue`, `setVariableValue`), managing asynchronous and external call stacks, and potentially blackboxing or skipping code.
这是 v8 源代码文件 `v8/src/inspector/v8-debugger-agent-impl.cc` 的第三部分，延续了之前定义的功能实现。 基于这部分的代码，我们可以归纳出以下功能：

**核心功能延续 (假设前两部分已定义基本调试功能):**

1. **修改函数返回值 (`setReturnValue`)**: 允许在断点暂停时修改当前函数即将返回的值。这对于在不重新运行代码的情况下测试不同的返回值效果非常有用。

2. **设置异步调用栈深度 (`setAsyncCallStackDepth`)**:  控制调试器记录的异步操作的调用栈深度。这有助于追踪由 `Promise`、`async/await` 或其他异步机制触发的代码执行流程。

3. **管理黑盒模式 (`setBlackboxPatterns`, `setBlackboxExecutionContexts`, `setBlackboxedRanges`)**:  允许将特定的脚本或代码区域标记为“黑盒”。当调试器单步执行时，会跳过这些黑盒代码，专注于用户关心的代码。这可以通过正则表达式、执行上下文 ID 或代码范围来定义。

4. **获取当前调用帧信息 (`currentCallFrames`)**:  在断点暂停时，获取当前的调用栈信息，包括函数名、位置、作用域链、`this` 对象和返回值（如果存在）。

5. **获取异步和外部调用栈信息 (`currentAsyncStackTrace`, `currentExternalStackTrace`)**:  获取导致当前执行暂停的异步操作的调用栈，以及外部（非 JavaScript）调用栈信息。

6. **处理脚本解析事件 (`didParseSource`)**: 当 V8 解析新的 JavaScript 脚本时，调试器代理会收到通知。它会记录脚本信息，并根据预设的断点规则设置断点。

7. **处理插桩断点 (`didPauseOnInstrumentation`)**:  处理由调试器自身插入的特殊断点，例如在脚本执行开始前。

8. **处理暂停事件 (`didPause`)**: 当代码执行因断点、异常或其他原因暂停时，调试器代理会收到通知，并生成包含调用栈、暂停原因等信息的事件发送给调试客户端。

9. **处理继续执行事件 (`didContinue`)**:  当调试器指示继续执行时，发送相应的事件。

10. **触发断点 (`breakProgram`)**:  允许通过代码或调试客户端强制程序进入断点状态。

11. **为特定函数设置断点 (`setBreakpointFor`)**:  允许为特定的 JavaScript 函数设置断点。

12. **移除特定函数的断点 (`removeBreakpointFor`)**:  移除为特定 JavaScript 函数设置的断点。

13. **重置调试器状态 (`reset`)**:  清除所有断点、黑盒设置等调试器状态。

14. **处理脚本回收事件 (`ScriptCollected`)**: 当脚本被垃圾回收时，调试器代理会收到通知，并可以将脚本信息缓存起来。

15. **处理跳过列表 (`processSkipList`)**:  允许设置在单步执行时需要跳过的代码范围。

16. **停止调试器代理 (`stop`)**:  停止调试器代理的功能。

**关于文件类型和 JavaScript 关系:**

*   代码以 `.cc` 结尾，**不是** v8 Torque 源代码。Torque 文件的后缀是 `.tq`。
*   此文件与 JavaScript 的功能有密切关系，因为它实现了 JavaScript 代码的调试功能。

**JavaScript 示例 (与 `setReturnValue` 功能相关):**

```javascript
function myFunction() {
  let result = 10;
  // ... 一些计算 ...
  return result; // 假设这里设置了断点
}

myFunction();
```

如果在 `return result;` 这一行设置了断点，并且程序暂停在那里，调试器代理的 `setReturnValue` 功能允许你修改 `result` 的值，例如修改为 `20`。 这样，函数最终会返回你修改后的值 `20`，而不需要重新运行程序。

**代码逻辑推理 (与 `setBlackboxPatterns` 功能相关):**

**假设输入:**

*   `patterns`: 一个包含字符串的数组，例如 `["/node_modules/.*", "/webpack/.*"]`。
*   `skipAnonymous`: 可选的布尔值，假设设置为 `true`。

**输出:**

*   `m_blackboxPattern`: 一个编译后的正则表达式对象，它匹配所有以 `/node_modules/` 或 `/webpack/` 开头的路径。
*   `m_skipAnonymousScripts`: 设置为 `true`。
*   调试器在单步执行时会跳过匹配这些模式的脚本。

**代码逻辑:** `setBlackboxPatterns` 方法会将输入的字符串数组组合成一个正则表达式，并将其存储起来。`skipAnonymous` 参数决定是否跳过匿名脚本。 当调试器遇到代码时，会检查其路径是否匹配黑盒模式，如果匹配则跳过。

**用户常见的编程错误 (与调试相关):**

*   **未处理的异常**: 调试器可以帮助开发者定位抛出异常但没有被 `try...catch` 捕获的代码位置。可以通过 `setPauseOnExceptions` 来在异常抛出时暂停。
*   **逻辑错误**: 通过单步执行、查看变量值和调用栈，开发者可以理解代码的执行流程，从而找到导致程序行为不符合预期的逻辑错误。
*   **异步操作中的错误**: 异步操作可能导致难以追踪的错误。调试器的异步调用栈功能可以帮助开发者理解异步操作之间的关系。
*   **作用域问题**: 调试器可以显示当前作用域内的变量值，帮助开发者理解变量的作用域和生命周期。

**归纳功能:**

总的来说，`v8/src/inspector/v8-debugger-agent-impl.cc` 的这部分代码主要负责实现 V8 调试器的**高级控制和信息获取功能**。它允许用户在调试过程中更深入地干预程序的执行，例如修改返回值、管理黑盒代码、查看异步调用栈等。这些功能极大地提升了 JavaScript 代码的调试效率和能力，帮助开发者更快速地定位和解决复杂的问题。它与前两部分一起，构成了 V8 调试器代理的核心实现。

### 提示词
```
这是目录为v8/src/inspector/v8-debugger-agent-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger-agent-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
aught()) {
    return Response::InternalError();
  }
  return Response::Success();
}

Response V8DebuggerAgentImpl::setReturnValue(
    std::unique_ptr<protocol::Runtime::CallArgument> protocolNewValue) {
  if (!enabled()) return Response::ServerError(kDebuggerNotEnabled);
  if (!isPaused()) return Response::ServerError(kDebuggerNotPaused);
  v8::HandleScope handleScope(m_isolate);
  auto iterator = v8::debug::StackTraceIterator::Create(m_isolate);
  if (iterator->Done()) {
    return Response::ServerError("Could not find top call frame");
  }
  if (iterator->GetReturnValue().IsEmpty()) {
    return Response::ServerError(
        "Could not update return value at non-return position");
  }
  InjectedScript::ContextScope scope(m_session, iterator->GetContextId());
  Response response = scope.initialize();
  if (!response.IsSuccess()) return response;
  v8::Local<v8::Value> newValue;
  response = scope.injectedScript()->resolveCallArgument(protocolNewValue.get(),
                                                         &newValue);
  if (!response.IsSuccess()) return response;
  v8::debug::SetReturnValue(m_isolate, newValue);
  return Response::Success();
}

Response V8DebuggerAgentImpl::setAsyncCallStackDepth(int depth) {
  if (!enabled() && !m_session->runtimeAgent()->enabled()) {
    return Response::ServerError(kDebuggerNotEnabled);
  }
  m_state->setInteger(DebuggerAgentState::asyncCallStackDepth, depth);
  m_debugger->setAsyncCallStackDepth(this, depth);
  return Response::Success();
}

Response V8DebuggerAgentImpl::setBlackboxPatterns(
    std::unique_ptr<protocol::Array<String16>> patterns,
    Maybe<bool> skipAnonymous) {
  m_skipAnonymousScripts = skipAnonymous.value_or(false);
  m_state->setBoolean(DebuggerAgentState::skipAnonymousScripts,
                      m_skipAnonymousScripts);
  if (patterns->empty()) {
    m_blackboxPattern = nullptr;
    resetBlackboxedStateCache();
    m_state->remove(DebuggerAgentState::blackboxPattern);
    return Response::Success();
  }

  String16Builder patternBuilder;
  patternBuilder.append('(');
  for (size_t i = 0; i < patterns->size() - 1; ++i) {
    patternBuilder.append((*patterns)[i]);
    patternBuilder.append("|");
  }
  patternBuilder.append(patterns->back());
  patternBuilder.append(')');
  String16 pattern = patternBuilder.toString();
  Response response = setBlackboxPattern(pattern);
  if (!response.IsSuccess()) return response;
  resetBlackboxedStateCache();
  m_state->setString(DebuggerAgentState::blackboxPattern, pattern);
  return Response::Success();
}

Response V8DebuggerAgentImpl::setBlackboxExecutionContexts(
    std::unique_ptr<protocol::Array<String16>> uniqueIds) {
  m_blackboxedExecutionContexts.clear();
  for (const String16& uniqueId : *uniqueIds) {
    m_blackboxedExecutionContexts.insert(uniqueId);
  }
  return Response::Success();
}

Response V8DebuggerAgentImpl::setBlackboxPattern(const String16& pattern) {
  std::unique_ptr<V8Regex> regex(new V8Regex(
      m_inspector, pattern, true /** caseSensitive */, false /** multiline */));
  if (!regex->isValid())
    return Response::ServerError("Pattern parser error: " +
                                 regex->errorMessage().utf8());
  m_blackboxPattern = std::move(regex);
  return Response::Success();
}

void V8DebuggerAgentImpl::resetBlackboxedStateCache() {
  for (const auto& it : m_scripts) {
    it.second->resetBlackboxedStateCache();
  }
}

Response V8DebuggerAgentImpl::setBlackboxedRanges(
    const String16& scriptId,
    std::unique_ptr<protocol::Array<protocol::Debugger::ScriptPosition>>
        inPositions) {
  auto it = m_scripts.find(scriptId);
  if (it == m_scripts.end())
    return Response::ServerError("No script with passed id.");

  if (inPositions->empty()) {
    m_blackboxedPositions.erase(scriptId);
    it->second->resetBlackboxedStateCache();
    return Response::Success();
  }

  std::vector<std::pair<int, int>> positions;
  positions.reserve(inPositions->size());
  for (const std::unique_ptr<protocol::Debugger::ScriptPosition>& position :
       *inPositions) {
    Response res = isValidPosition(position.get());
    if (res.IsError()) return res;

    positions.push_back(
        std::make_pair(position->getLineNumber(), position->getColumnNumber()));
  }
  Response res = isValidRangeOfPositions(positions);
  if (res.IsError()) return res;

  m_blackboxedPositions[scriptId] = positions;
  it->second->resetBlackboxedStateCache();
  return Response::Success();
}

Response V8DebuggerAgentImpl::currentCallFrames(
    std::unique_ptr<Array<CallFrame>>* result) {
  if (!isPaused()) {
    *result = std::make_unique<Array<CallFrame>>();
    return Response::Success();
  }
  v8::HandleScope handles(m_isolate);
  *result = std::make_unique<Array<CallFrame>>();
  auto iterator = v8::debug::StackTraceIterator::Create(m_isolate);
  int frameOrdinal = 0;
  for (; !iterator->Done(); iterator->Advance(), frameOrdinal++) {
    int contextId = iterator->GetContextId();
    InjectedScript* injectedScript = nullptr;
    if (contextId) m_session->findInjectedScript(contextId, injectedScript);
    String16 callFrameId = RemoteCallFrameId::serialize(
        m_inspector->isolateId(), contextId, frameOrdinal);

    v8::debug::Location loc = iterator->GetSourceLocation();

    std::unique_ptr<Array<Scope>> scopes;
    auto scopeIterator = iterator->GetScopeIterator();
    Response res =
        buildScopes(m_isolate, scopeIterator.get(), injectedScript, &scopes);
    if (!res.IsSuccess()) return res;

    std::unique_ptr<RemoteObject> protocolReceiver;
    if (injectedScript) {
      v8::Local<v8::Value> receiver;
      if (iterator->GetReceiver().ToLocal(&receiver)) {
        res = injectedScript->wrapObject(receiver, kBacktraceObjectGroup,
                                         WrapOptions({WrapMode::kIdOnly}),
                                         &protocolReceiver);
        if (!res.IsSuccess()) return res;
      }
    }
    if (!protocolReceiver) {
      protocolReceiver = RemoteObject::create()
                             .setType(RemoteObject::TypeEnum::Undefined)
                             .build();
    }

    v8::Local<v8::debug::Script> script = iterator->GetScript();
    DCHECK(!script.IsEmpty());
    std::unique_ptr<protocol::Debugger::Location> location =
        protocol::Debugger::Location::create()
            .setScriptId(String16::fromInteger(script->Id()))
            .setLineNumber(loc.GetLineNumber())
            .setColumnNumber(loc.GetColumnNumber())
            .build();

    auto frame = CallFrame::create()
                     .setCallFrameId(callFrameId)
                     .setFunctionName(toProtocolString(
                         m_isolate, iterator->GetFunctionDebugName()))
                     .setLocation(std::move(location))
                     .setUrl(String16())
                     .setScopeChain(std::move(scopes))
                     .setThis(std::move(protocolReceiver))
                     .setCanBeRestarted(iterator->CanBeRestarted())
                     .build();

    v8::debug::Location func_loc = iterator->GetFunctionLocation();
    if (!func_loc.IsEmpty()) {
      frame->setFunctionLocation(
          protocol::Debugger::Location::create()
              .setScriptId(String16::fromInteger(script->Id()))
              .setLineNumber(func_loc.GetLineNumber())
              .setColumnNumber(func_loc.GetColumnNumber())
              .build());
    }

    v8::Local<v8::Value> returnValue = iterator->GetReturnValue();
    if (!returnValue.IsEmpty() && injectedScript) {
      std::unique_ptr<RemoteObject> value;
      res =
          injectedScript->wrapObject(returnValue, kBacktraceObjectGroup,
                                     WrapOptions({WrapMode::kIdOnly}), &value);
      if (!res.IsSuccess()) return res;
      frame->setReturnValue(std::move(value));
    }
    (*result)->emplace_back(std::move(frame));
  }
  return Response::Success();
}

std::unique_ptr<protocol::Runtime::StackTrace>
V8DebuggerAgentImpl::currentAsyncStackTrace() {
  std::shared_ptr<AsyncStackTrace> asyncParent =
      m_debugger->currentAsyncParent();
  if (!asyncParent) return nullptr;
  return asyncParent->buildInspectorObject(
      m_debugger, m_debugger->maxAsyncCallChainDepth() - 1);
}

std::unique_ptr<protocol::Runtime::StackTraceId>
V8DebuggerAgentImpl::currentExternalStackTrace() {
  V8StackTraceId externalParent = m_debugger->currentExternalParent();
  if (externalParent.IsInvalid()) return nullptr;
  return protocol::Runtime::StackTraceId::create()
      .setId(stackTraceIdToString(externalParent.id))
      .setDebuggerId(
          internal::V8DebuggerId(externalParent.debugger_id).toString())
      .build();
}

bool V8DebuggerAgentImpl::isPaused() const {
  return m_debugger->isPausedInContextGroup(m_session->contextGroupId());
}

static String16 getScriptLanguage(const V8DebuggerScript& script) {
  switch (script.getLanguage()) {
    case V8DebuggerScript::Language::WebAssembly:
      return protocol::Debugger::ScriptLanguageEnum::WebAssembly;
    case V8DebuggerScript::Language::JavaScript:
      return protocol::Debugger::ScriptLanguageEnum::JavaScript;
  }
}

#if V8_ENABLE_WEBASSEMBLY
static const char* getDebugSymbolTypeName(
    v8::debug::WasmScript::DebugSymbols::Type type) {
  switch (type) {
    case v8::debug::WasmScript::DebugSymbols::Type::SourceMap:
      return v8_inspector::protocol::Debugger::DebugSymbols::TypeEnum::
          SourceMap;
    case v8::debug::WasmScript::DebugSymbols::Type::EmbeddedDWARF:
      return v8_inspector::protocol::Debugger::DebugSymbols::TypeEnum::
          EmbeddedDWARF;
    case v8::debug::WasmScript::DebugSymbols::Type::ExternalDWARF:
      return v8_inspector::protocol::Debugger::DebugSymbols::TypeEnum::
          ExternalDWARF;
  }
}

static void getDebugSymbols(
    const V8DebuggerScript& script,
    std::unique_ptr<Array<protocol::Debugger::DebugSymbols>>* debug_symbols) {
  std::vector<v8::debug::WasmScript::DebugSymbols> v8_script_debug_symbols =
      script.getDebugSymbols();

  *debug_symbols = std::make_unique<Array<protocol::Debugger::DebugSymbols>>();
  for (size_t i = 0; i < v8_script_debug_symbols.size(); ++i) {
    v8::debug::WasmScript::DebugSymbols& symbol = v8_script_debug_symbols[i];
    std::unique_ptr<protocol::Debugger::DebugSymbols> protocolDebugSymbol =
        v8_inspector::protocol::Debugger::DebugSymbols::create()
            .setType(getDebugSymbolTypeName(symbol.type))
            .build();
    if (symbol.external_url.size() > 0) {
      protocolDebugSymbol->setExternalURL(
          String16(symbol.external_url.data(), symbol.external_url.size()));
    }
    (*debug_symbols)->emplace_back(std::move(protocolDebugSymbol));
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void V8DebuggerAgentImpl::didParseSource(
    std::unique_ptr<V8DebuggerScript> script, bool success) {
  v8::HandleScope handles(m_isolate);
  if (!success) {
    String16 scriptSource = script->source(0);
    script->setSourceURL(findSourceURL(scriptSource, false));
    script->setSourceMappingURL(findSourceMapURL(scriptSource, false));
  }

  int contextId = script->executionContextId();
  int contextGroupId = m_inspector->contextGroupId(contextId);
  InspectedContext* inspected =
      m_inspector->getContext(contextGroupId, contextId);
  std::unique_ptr<protocol::DictionaryValue> executionContextAuxData;
  if (inspected) {
    // Script reused between different groups/sessions can have a stale
    // execution context id.
    const String16& aux = inspected->auxData();
    std::vector<uint8_t> cbor;
    v8_crdtp::json::ConvertJSONToCBOR(
        v8_crdtp::span<uint16_t>(aux.characters16(), aux.length()), &cbor);
    executionContextAuxData = protocol::DictionaryValue::cast(
        protocol::Value::parseBinary(cbor.data(), cbor.size()));
  }
  bool isLiveEdit = script->isLiveEdit();
  bool hasSourceURLComment = script->hasSourceURLComment();
  bool isModule = script->isModule();
  String16 scriptId = script->scriptId();
  String16 scriptURL = script->sourceURL();
  String16 embedderName = script->embedderName();
  String16 scriptLanguage = getScriptLanguage(*script);
  Maybe<int> codeOffset;
  std::unique_ptr<Array<protocol::Debugger::DebugSymbols>> debugSymbols;
#if V8_ENABLE_WEBASSEMBLY
  if (script->getLanguage() == V8DebuggerScript::Language::WebAssembly) {
    codeOffset = script->codeOffset();
    getDebugSymbols(*script, &debugSymbols);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  m_scripts[scriptId] = std::move(script);
  // Release the strong reference to get notified when debugger is the only
  // one that holds the script. Has to be done after script added to m_scripts.
  m_scripts[scriptId]->MakeWeak();

  ScriptsMap::iterator scriptIterator = m_scripts.find(scriptId);
  DCHECK(scriptIterator != m_scripts.end());
  V8DebuggerScript* scriptRef = scriptIterator->second.get();
  // V8 could create functions for parsed scripts before reporting and asks
  // inspector about blackboxed state, we should reset state each time when we
  // make any change that change isFunctionBlackboxed output - adding parsed
  // script is changing.
  scriptRef->resetBlackboxedStateCache();

  Maybe<String16> sourceMapURLParam = scriptRef->sourceMappingURL();
  Maybe<protocol::DictionaryValue> executionContextAuxDataParam(
      std::move(executionContextAuxData));
  const bool* isLiveEditParam = isLiveEdit ? &isLiveEdit : nullptr;
  const bool* hasSourceURLParam =
      hasSourceURLComment ? &hasSourceURLComment : nullptr;
  const bool* isModuleParam = isModule ? &isModule : nullptr;
  std::unique_ptr<V8StackTraceImpl> stack =
      V8StackTraceImpl::capture(m_inspector->debugger(), 1);
  std::unique_ptr<protocol::Runtime::StackTrace> stackTrace =
      stack && !stack->isEmpty()
          ? stack->buildInspectorObjectImpl(m_debugger, 0)
          : nullptr;

  if (!success) {
    m_frontend.scriptFailedToParse(
        scriptId, scriptURL, scriptRef->startLine(), scriptRef->startColumn(),
        scriptRef->endLine(), scriptRef->endColumn(), contextId,
        scriptRef->hash(), std::move(executionContextAuxDataParam),
        std::move(sourceMapURLParam), hasSourceURLParam, isModuleParam,
        scriptRef->length(), std::move(stackTrace), std::move(codeOffset),
        std::move(scriptLanguage), embedderName);
    return;
  }

  m_frontend.scriptParsed(
      scriptId, scriptURL, scriptRef->startLine(), scriptRef->startColumn(),
      scriptRef->endLine(), scriptRef->endColumn(), contextId,
      scriptRef->hash(), std::move(executionContextAuxDataParam),
      isLiveEditParam, std::move(sourceMapURLParam), hasSourceURLParam,
      isModuleParam, scriptRef->length(), std::move(stackTrace),
      std::move(codeOffset), std::move(scriptLanguage), std::move(debugSymbols),
      embedderName);

  std::vector<protocol::DictionaryValue*> potentialBreakpoints;
  if (!scriptURL.isEmpty()) {
    protocol::DictionaryValue* breakpointsByUrl =
        m_state->getObject(DebuggerAgentState::breakpointsByUrl);
    if (breakpointsByUrl) {
      potentialBreakpoints.push_back(breakpointsByUrl->getObject(scriptURL));
    }
    potentialBreakpoints.push_back(
        m_state->getObject(DebuggerAgentState::breakpointsByRegex));
  }
  protocol::DictionaryValue* breakpointsByScriptHash =
      m_state->getObject(DebuggerAgentState::breakpointsByScriptHash);
  if (breakpointsByScriptHash) {
    potentialBreakpoints.push_back(
        breakpointsByScriptHash->getObject(scriptRef->hash()));
  }
  protocol::DictionaryValue* breakpointHints =
      m_state->getObject(DebuggerAgentState::breakpointHints);
  for (auto breakpoints : potentialBreakpoints) {
    if (!breakpoints) continue;
    for (size_t i = 0; i < breakpoints->size(); ++i) {
      auto breakpointWithCondition = breakpoints->at(i);
      String16 breakpointId = breakpointWithCondition.first;

      BreakpointType type;
      String16 selector;
      int lineNumber = 0;
      int columnNumber = 0;
      parseBreakpointId(breakpointId, &type, &selector, &lineNumber,
                        &columnNumber);
      Matcher matcher(m_inspector, type, selector);

      if (!matcher.matches(*scriptRef)) continue;
      // Make sure the session was not disabled by some re-entrant call
      // in the script matcher.
      DCHECK(enabled());
      String16 condition;
      breakpointWithCondition.second->asString(&condition);
      protocol::DictionaryValue* hint =
          breakpointHints ? breakpointHints->getObject(breakpointId) : nullptr;
      if (hint) {
        adjustBreakpointLocation(*scriptRef, hint, &lineNumber, &columnNumber);
      }
      std::unique_ptr<protocol::Debugger::Location> location =
          setBreakpointImpl(breakpointId, scriptId, condition, lineNumber,
                            columnNumber);
      if (location)
        m_frontend.breakpointResolved(breakpointId, std::move(location));
    }
  }
  setScriptInstrumentationBreakpointIfNeeded(scriptRef);
}

void V8DebuggerAgentImpl::setScriptInstrumentationBreakpointIfNeeded(
    V8DebuggerScript* scriptRef) {
  protocol::DictionaryValue* breakpoints =
      m_state->getObject(DebuggerAgentState::instrumentationBreakpoints);
  if (!breakpoints) return;
  bool isBlackboxed = isFunctionBlackboxed(
      scriptRef->scriptId(), v8::debug::Location(0, 0),
      v8::debug::Location(scriptRef->endLine(), scriptRef->endColumn()));
  if (isBlackboxed) return;

  String16 sourceMapURL = scriptRef->sourceMappingURL();
  String16 breakpointId = generateInstrumentationBreakpointId(
      InstrumentationEnum::BeforeScriptExecution);
  if (!breakpoints->get(breakpointId)) {
    if (sourceMapURL.isEmpty()) return;
    breakpointId = generateInstrumentationBreakpointId(
        InstrumentationEnum::BeforeScriptWithSourceMapExecution);
    if (!breakpoints->get(breakpointId)) return;
  }
  v8::debug::BreakpointId debuggerBreakpointId;
  if (!scriptRef->setInstrumentationBreakpoint(&debuggerBreakpointId)) return;

  m_debuggerBreakpointIdToBreakpointId[debuggerBreakpointId] = breakpointId;
  m_breakpointIdToDebuggerBreakpointIds[breakpointId].push_back(
      debuggerBreakpointId);
}

void V8DebuggerAgentImpl::didPauseOnInstrumentation(
    v8::debug::BreakpointId instrumentationId) {
  String16 breakReason = protocol::Debugger::Paused::ReasonEnum::Other;
  std::unique_ptr<protocol::DictionaryValue> breakAuxData;

  std::unique_ptr<Array<CallFrame>> protocolCallFrames;
  Response response = currentCallFrames(&protocolCallFrames);
  if (!response.IsSuccess())
    protocolCallFrames = std::make_unique<Array<CallFrame>>();

  if (m_debuggerBreakpointIdToBreakpointId.find(instrumentationId) !=
      m_debuggerBreakpointIdToBreakpointId.end()) {
    DCHECK_GT(protocolCallFrames->size(), 0);
    if (!protocolCallFrames->empty()) {
      m_instrumentationFinished = false;
      breakReason = protocol::Debugger::Paused::ReasonEnum::Instrumentation;
      const String16 scriptId =
          protocolCallFrames->at(0)->getLocation()->getScriptId();
      DCHECK_NE(m_scripts.find(scriptId), m_scripts.end());
      const auto& script = m_scripts[scriptId];

      breakAuxData = protocol::DictionaryValue::create();
      breakAuxData->setString("scriptId", script->scriptId());
      breakAuxData->setString("url", script->sourceURL());
      if (!script->sourceMappingURL().isEmpty()) {
        breakAuxData->setString("sourceMapURL", (script->sourceMappingURL()));
      }
    }
  }

  m_frontend.paused(std::move(protocolCallFrames), breakReason,
                    std::move(breakAuxData),
                    std::make_unique<Array<String16>>(),
                    currentAsyncStackTrace(), currentExternalStackTrace());
}

void V8DebuggerAgentImpl::didPause(
    int contextId, v8::Local<v8::Value> exception,
    const std::vector<v8::debug::BreakpointId>& hitBreakpoints,
    v8::debug::ExceptionType exceptionType, bool isUncaught,
    v8::debug::BreakReasons breakReasons) {
  v8::HandleScope handles(m_isolate);

  std::vector<BreakReason> hitReasons;

  if (breakReasons.contains(v8::debug::BreakReason::kOOM)) {
    hitReasons.push_back(
        std::make_pair(protocol::Debugger::Paused::ReasonEnum::OOM, nullptr));
  } else if (breakReasons.contains(v8::debug::BreakReason::kAssert)) {
    hitReasons.push_back(std::make_pair(
        protocol::Debugger::Paused::ReasonEnum::Assert, nullptr));
  } else if (breakReasons.contains(v8::debug::BreakReason::kException)) {
    InjectedScript* injectedScript = nullptr;
    m_session->findInjectedScript(contextId, injectedScript);
    if (injectedScript) {
      String16 breakReason =
          exceptionType == v8::debug::kPromiseRejection
              ? protocol::Debugger::Paused::ReasonEnum::PromiseRejection
              : protocol::Debugger::Paused::ReasonEnum::Exception;
      std::unique_ptr<protocol::Runtime::RemoteObject> obj;
      injectedScript->wrapObject(exception, kBacktraceObjectGroup,
                                 WrapOptions({WrapMode::kIdOnly}), &obj);
      std::unique_ptr<protocol::DictionaryValue> breakAuxData;
      if (obj) {
        std::vector<uint8_t> serialized;
        obj->AppendSerialized(&serialized);
        breakAuxData = protocol::DictionaryValue::cast(
            protocol::Value::parseBinary(serialized.data(), serialized.size()));
        breakAuxData->setBoolean("uncaught", isUncaught);
      }
      hitReasons.push_back(
          std::make_pair(breakReason, std::move(breakAuxData)));
    }
  }

  if (breakReasons.contains(v8::debug::BreakReason::kStep) ||
      breakReasons.contains(v8::debug::BreakReason::kAsyncStep)) {
    hitReasons.push_back(
        std::make_pair(protocol::Debugger::Paused::ReasonEnum::Step, nullptr));
  }

  auto hitBreakpointIds = std::make_unique<Array<String16>>();
  bool hitRegularBreakpoint = false;
  for (const auto& id : hitBreakpoints) {
    auto breakpointIterator = m_debuggerBreakpointIdToBreakpointId.find(id);
    if (breakpointIterator == m_debuggerBreakpointIdToBreakpointId.end()) {
      continue;
    }
    const String16& breakpointId = breakpointIterator->second;
    hitBreakpointIds->emplace_back(breakpointId);
    BreakpointType type;
    parseBreakpointId(breakpointId, &type);
    if (type == BreakpointType::kDebugCommand) {
      hitReasons.push_back(std::make_pair(
          protocol::Debugger::Paused::ReasonEnum::DebugCommand, nullptr));
    } else {
      hitRegularBreakpoint = true;
    }
  }

  for (size_t i = 0; i < m_breakReason.size(); ++i) {
    hitReasons.push_back(std::move(m_breakReason[i]));
  }
  clearBreakDetails();

  // Make sure that we only include (other: nullptr) once.
  const BreakReason otherHitReason =
      std::make_pair(protocol::Debugger::Paused::ReasonEnum::Other, nullptr);
  const bool otherBreakReasons =
      hitRegularBreakpoint || hitBreakReasonEncodedAsOther(breakReasons);
  if (otherBreakReasons && std::find(hitReasons.begin(), hitReasons.end(),
                                     otherHitReason) == hitReasons.end()) {
    hitReasons.push_back(
        std::make_pair(protocol::Debugger::Paused::ReasonEnum::Other, nullptr));
  }

  // We should always know why we pause: either the pause relates to this agent
  // (`hitReason` is non empty), or it relates to another agent (hit a
  // breakpoint there, or a triggered pause was scheduled by other agent).
  DCHECK(hitReasons.size() > 0 || !hitBreakpoints.empty() ||
         breakReasons.contains(v8::debug::BreakReason::kAgent));
  String16 breakReason = protocol::Debugger::Paused::ReasonEnum::Other;
  std::unique_ptr<protocol::DictionaryValue> breakAuxData;
  if (hitReasons.size() == 1) {
    breakReason = hitReasons[0].first;
    breakAuxData = std::move(hitReasons[0].second);
  } else if (hitReasons.size() > 1) {
    breakReason = protocol::Debugger::Paused::ReasonEnum::Ambiguous;
    std::unique_ptr<protocol::ListValue> reasons =
        protocol::ListValue::create();
    for (size_t i = 0; i < hitReasons.size(); ++i) {
      std::unique_ptr<protocol::DictionaryValue> reason =
          protocol::DictionaryValue::create();
      reason->setString("reason", hitReasons[i].first);
      if (hitReasons[i].second)
        reason->setObject("auxData", std::move(hitReasons[i].second));
      reasons->pushValue(std::move(reason));
    }
    breakAuxData = protocol::DictionaryValue::create();
    breakAuxData->setArray("reasons", std::move(reasons));
  }

  std::unique_ptr<Array<CallFrame>> protocolCallFrames;
  Response response = currentCallFrames(&protocolCallFrames);
  if (!response.IsSuccess())
    protocolCallFrames = std::make_unique<Array<CallFrame>>();

  v8::debug::NotifyDebuggerPausedEventSent(m_debugger->isolate());
  m_frontend.paused(std::move(protocolCallFrames), breakReason,
                    std::move(breakAuxData), std::move(hitBreakpointIds),
                    currentAsyncStackTrace(), currentExternalStackTrace());
}

void V8DebuggerAgentImpl::didContinue() {
  m_frontend.resumed();
  m_frontend.flush();
}

void V8DebuggerAgentImpl::breakProgram(
    const String16& breakReason,
    std::unique_ptr<protocol::DictionaryValue> data) {
  if (!enabled() || m_skipAllPauses || !m_debugger->canBreakProgram()) return;
  std::vector<BreakReason> currentScheduledReason;
  currentScheduledReason.swap(m_breakReason);
  pushBreakDetails(breakReason, std::move(data));

  int contextGroupId = m_session->contextGroupId();
  int sessionId = m_session->sessionId();
  V8InspectorImpl* inspector = m_inspector;
  m_debugger->breakProgram(contextGroupId);
  // Check that session and |this| are still around.
  if (!inspector->sessionById(contextGroupId, sessionId)) return;
  if (!enabled()) return;

  popBreakDetails();
  m_breakReason.swap(currentScheduledReason);
  if (!m_breakReason.empty()) {
    m_debugger->setPauseOnNextCall(true, m_session->contextGroupId());
  }
}

void V8DebuggerAgentImpl::setBreakpointFor(v8::Local<v8::Function> function,
                                           v8::Local<v8::String> condition,
                                           BreakpointSource source) {
  String16 breakpointId = generateBreakpointId(
      source == DebugCommandBreakpointSource ? BreakpointType::kDebugCommand
                                             : BreakpointType::kMonitorCommand,
      function);
  if (m_breakpointIdToDebuggerBreakpointIds.find(breakpointId) !=
      m_breakpointIdToDebuggerBreakpointIds.end()) {
    return;
  }
  setBreakpointImpl(breakpointId, function, condition);
}

void V8DebuggerAgentImpl::removeBreakpointFor(v8::Local<v8::Function> function,
                                              BreakpointSource source) {
  String16 breakpointId = generateBreakpointId(
      source == DebugCommandBreakpointSource ? BreakpointType::kDebugCommand
                                             : BreakpointType::kMonitorCommand,
      function);
  std::vector<V8DebuggerScript*> scripts;
  removeBreakpointImpl(breakpointId, scripts);
}

void V8DebuggerAgentImpl::reset() {
  if (!enabled()) return;
  m_blackboxedPositions.clear();
  resetBlackboxedStateCache();
  m_skipList.clear();
  m_scripts.clear();
  m_cachedScripts.clear();
  m_cachedScriptSize = 0;
  m_debugger->allAsyncTasksCanceled();
  m_blackboxedExecutionContexts.clear();
}

void V8DebuggerAgentImpl::ScriptCollected(const V8DebuggerScript* script) {
  DCHECK_NE(m_scripts.find(script->scriptId()), m_scripts.end());
  std::vector<uint8_t> bytecode;
#if V8_ENABLE_WEBASSEMBLY
  v8::MemorySpan<const uint8_t> span;
  if (script->wasmBytecode().To(&span)) {
    bytecode.reserve(span.size());
    bytecode.insert(bytecode.begin(), span.data(), span.data() + span.size());
  }
#endif
  CachedScript cachedScript{script->scriptId(), script->source(0),
                            std::move(bytecode)};
  m_cachedScriptSize += cachedScript.size();
  m_cachedScripts.push_back(std::move(cachedScript));
  m_scripts.erase(script->scriptId());

  while (m_cachedScriptSize > m_maxScriptCacheSize) {
    const CachedScript& cachedScript = m_cachedScripts.front();
    DCHECK_GE(m_cachedScriptSize, cachedScript.size());
    m_cachedScriptSize -= cachedScript.size();
    m_cachedScripts.pop_front();
  }
}

Response V8DebuggerAgentImpl::processSkipList(
    protocol::Array<protocol::Debugger::LocationRange>& skipList) {
  std::unordered_map<String16, std::vector<std::pair<int, int>>> skipListInit;
  for (std::unique_ptr<protocol::Debugger::LocationRange>& range : skipList) {
    protocol::Debugger::ScriptPosition* start = range->getStart();
    protocol::Debugger::ScriptPosition* end = range->getEnd();
    String16 scriptId = range->getScriptId();

    auto it = m_scripts.find(scriptId);
    if (it == m_scripts.end())
      return Response::ServerError("No script with passed id.");

    Response res = isValidPosition(start);
    if (res.IsError()) return res;

    res = isValidPosition(end);
    if (res.IsError()) return res;

    skipListInit[scriptId].emplace_back(start->getLineNumber(),
                                        start->getColumnNumber());
    skipListInit[scriptId].emplace_back(end->getLineNumber(),
                                        end->getColumnNumber());
  }

  // Verify that the skipList is sorted, and that all ranges
  // are properly defined (start comes before end).
  for (auto skipListPair : skipListInit) {
    Response res = isValidRangeOfPositions(skipListPair.second);
    if (res.IsError()) return res;
  }

  m_skipList = std::move(skipListInit);
  return Response::Success();
}

void V8DebuggerAgentImpl::stop() {
  disable();
  m_enableState = kStopping;
}
}  // namespace v8_inspector
```