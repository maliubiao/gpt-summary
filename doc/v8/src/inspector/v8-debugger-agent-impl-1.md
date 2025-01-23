Response: The user wants a summary of the C++ source code file `v8-debugger-agent-impl.cc`.
This is the second part of the file. I need to analyze the provided code snippet and identify its main functionalities.

Based on the code, it seems to handle:
- Setting return values for paused functions.
- Managing asynchronous call stack depth.
- Implementing blackboxing of scripts and execution contexts.
- Retrieving the current call frames and asynchronous call stack.
- Handling script parsing events and notifications.
- Managing breakpoints, including instrumentation breakpoints.
- Handling pause events, including pauses due to instrumentation, exceptions, and breakpoints.
- Implementing the "continue" functionality.
- Implementing programmatic breakpoints (`breakProgram`).
- Setting and removing breakpoints for specific functions.
- Resetting the debugger agent state.
- Handling script garbage collection.
- Managing a skip list for debugging.
- Stopping the debugger agent.
这个C++源代码文件（`v8-debugger-agent-impl.cc` 的第 2 部分）延续了第 1 部分的功能，主要负责实现 Chrome DevTools 协议中与 JavaScript 调试相关的功能。以下是本部分的主要功能归纳：

**核心调试功能扩展与增强：**

* **设置函数返回值 (`setReturnValue`)**:  允许在调试暂停时修改函数的返回值。
* **设置异步调用栈深度 (`setAsyncCallStackDepth`)**: 控制调试器记录的异步操作调用栈的深度。
* **黑盒机制 (`setBlackboxPatterns`, `setBlackboxExecutionContexts`, `setBlackboxedRanges`)**:  实现了将某些脚本或执行上下文标记为“黑盒”的功能，调试时会跳过这些代码，从而专注于用户代码。
* **获取当前调用栈帧 (`currentCallFrames`)**:  在调试暂停时，获取当前的 JavaScript 调用栈信息，包括函数名、位置、作用域等。
* **获取当前异步调用栈 (`currentAsyncStackTrace`)**: 获取当前异步操作的调用栈信息。
* **获取当前外部调用栈 (`currentExternalStackTrace`)**:  获取外部（非 JavaScript）的调用栈信息。
* **脚本解析处理 (`didParseSource`)**:  当 V8 引擎解析 JavaScript 代码时，这个函数会被调用，负责向前端发送 `scriptParsed` 或 `scriptFailedToParse` 事件，并处理与断点相关的逻辑。
* **设置脚本插桩断点 (`setScriptInstrumentationBreakpointIfNeeded`)**:  在脚本的特定位置（例如脚本开始执行前）设置断点，用于收集脚本执行的元数据。
* **处理插桩暂停 (`didPauseOnInstrumentation`)**: 当命中插桩断点时，通知前端。
* **处理暂停事件 (`didPause`)**: 当 JavaScript 代码执行暂停时（例如遇到断点、异常），通知前端，并提供调用栈、暂停原因等信息。
* **处理继续执行事件 (`didContinue`)**: 当调试器继续执行 JavaScript 代码时，通知前端。
* **触发断点 (`breakProgram`)**:  允许通过代码主动触发断点。
* **为函数设置断点 (`setBreakpointFor`)**:  允许为特定的 JavaScript 函数设置断点。
* **移除函数断点 (`removeBreakpointFor`)**: 移除为特定 JavaScript 函数设置的断点。
* **重置调试器状态 (`reset`)**: 清除所有调试相关的状态信息。
* **处理脚本回收 (`ScriptCollected`)**: 当 JavaScript 脚本被垃圾回收时，缓存其信息，以便后续可能需要。
* **处理跳过列表 (`processSkipList`)**:  允许设置在调试时需要跳过的代码范围。
* **停止调试器 (`stop`)**: 停止调试器代理。

**与 JavaScript 的关系及示例:**

这些功能直接与 JavaScript 的调试体验相关。例如：

* **`setReturnValue`**:  当你在 Chrome DevTools 中暂停在某个函数内部，然后想修改函数的返回值，这个 C++ 函数会被调用。

  ```javascript
  function add(a, b) {
    debugger; // 程序会在这里暂停
    return a + b;
  }

  let result = add(5, 3);
  console.log(result);
  ```

  在 `debugger` 处暂停后，你可以在 DevTools 的 Console 中执行类似 `returnValue = 10;` 的命令，这将调用 `setReturnValue`，使得函数最终返回 10 而不是 8。

* **`setAsyncCallStackDepth`**: 当你在调试异步代码时，DevTools 可以显示异步操作的完整调用链。这个 C++ 函数控制了这个调用链的深度。

  ```javascript
  async function fetchData() {
    console.log("Fetching data...");
    await new Promise(resolve => setTimeout(resolve, 1000));
    console.log("Data fetched.");
    debugger;
    return "some data";
  }

  async function processData() {
    await fetchData();
  }

  processData();
  ```

  当程序在 `debugger` 处暂停时，DevTools 的 Call Stack 面板会显示 `processData` 和 `fetchData` 的调用关系，`setAsyncCallStackDepth` 影响了这个调用栈的完整性。

* **黑盒机制**:  如果你不想在调试时单步执行某些库的代码，你可以将其添加到黑盒列表中。

  ```javascript
  // 假设 'library.js' 是一个你不想单步执行的库文件
  import * as library from './library.js';

  function myCode() {
    library.someFunction();
    debugger; // 你只想在这里单步执行
  }

  myCode();
  ```

  在 DevTools 中，你可以将 `library.js` 添加到黑盒列表中，这样在单步执行时，调试器会自动跳过 `library.someFunction()` 的内部代码。`setBlackboxPatterns` 和相关的函数负责实现这个功能。

总之，这部分代码是 V8 调试器代理的核心组成部分，它将底层的 V8 引擎调试能力暴露给 Chrome DevTools 和其他调试客户端，从而实现了强大的 JavaScript 调试功能。

### 提示词
```
这是目录为v8/src/inspector/v8-debugger-agent-impl.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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