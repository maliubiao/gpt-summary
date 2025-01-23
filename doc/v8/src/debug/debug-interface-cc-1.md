Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/debug/debug-interface.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The file name suggests this code provides an interface for debugging V8. Many of the function names reinforce this.

2. **Categorize Functions:** Group the functions by their apparent functionality. Look for patterns in the names and the types they operate on. Common categories will likely emerge, such as:
    * Script manipulation (compiling, getting information)
    * Function manipulation (getting information, setting breakpoints)
    * WebAssembly specific functions
    * Debugger control (entering/leaving debugging, setting delegates)
    * Object inspection (getting size, type information)
    * Execution control (calling functions, evaluating code)
    * Coverage information
    * Ephemeron tables
    * Console interaction
    * Error/Exception handling
    * Generator object inspection
    * Property iteration

3. **Analyze Individual Functions:** For each function, understand its input and output, and what it does in between. Pay attention to:
    * V8 API types used (e.g., `Isolate`, `Script`, `Function`, `Context`, `Value`)
    * Internal V8 types (prefixed with `i::`)
    * Assertions and checks (`DCHECK`, `CHECK`) which provide clues about expected conditions.
    * Interactions with internal V8 components (e.g., `wasm::GetWasmEngine()`, `isolate->debug()`, `ScriptCompiler`)

4. **Address Specific Questions:**
    * **`.tq` extension:**  The code does *not* end with `.tq`, so it's not a Torque file.
    * **JavaScript relationship:**  Look for functions that bridge the gap between the C++ debugging interface and the JavaScript runtime (e.g., functions that operate on `Local<Value>`, `Local<Function>`, `Local<Context>`). Illustrate with JavaScript examples where applicable.
    * **Code logic推理:** For functions that perform more complex operations (like `GetContainingFunction` or `GetFunctionHash`), try to infer the logic and provide hypothetical inputs and outputs.
    * **Common programming errors:** Consider how the debugging features exposed by this interface might help developers identify common JavaScript errors (e.g., runtime exceptions, incorrect function calls).
    * **归纳功能:**  Summarize the categorized functionalities into a concise description of the overall purpose of the code.

5. **Structure the Output:** Organize the findings in a clear and readable manner, addressing each of the user's requests.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus on just listing the functions.
* **Correction:** Realized that simply listing isn't helpful. Need to group and explain their purpose.
* **Initial thought:** Try to deeply understand every single line of C++ code.
* **Correction:**  Focus on the high-level functionality and the interaction with V8's public API. Don't need to be an expert in V8 internals to understand the purpose of this interface. Leverage the function names and comments.
* **Initial thought:**  Assume all functions are directly related to user-level debugging.
* **Correction:** Some functions are more about internal V8 debugging or tooling support (like coverage).

By following these steps and refining the approach, a comprehensive and accurate summary of the code's functionality can be produced.
这是对 `v8/src/debug/debug-interface.cc` 文件代码片段的归纳总结，延续了之前对该文件的分析。

**主要功能归纳:**

这个代码片段延续了 `v8/src/debug/debug-interface.cc` 文件的核心功能：**为 V8 虚拟机提供 C++ 调试接口**。它封装了 V8 内部的调试机制，并将其暴露给外部使用，例如 Chrome 开发者工具的 JavaScript 调试器。

**具体功能点:**

* **WebAssembly 脚本支持 (如果启用了 V8_ENABLE_WEBASSEMBLY):**
    * `WasmScript::GetFunctionSourceRange`: 获取 WebAssembly 函数的源代码范围（偏移量）。
    * `WasmScript::GetContainingFunction`: 获取指定字节偏移量所在的 WebAssembly 函数索引。
    * `WasmScript::Disassemble`: 反汇编 WebAssembly 代码。
    * `Disassemble`: 反汇编原始字节码。
    * `WasmScript::GetFunctionHash`: 计算 WebAssembly 函数的哈希值。
    * `WasmScript::CodeOffset`: 获取 WebAssembly 模块代码的起始偏移量。
    * `EnterDebuggingForIsolate`:  允许为特定 Isolate 进入 WebAssembly 调试。
    * `LeaveDebuggingForIsolate`:  停止为特定 Isolate 进行 WebAssembly 调试。
    * `WasmValueObject::CheckCast`, `WasmValueObject::IsWasmValueObject`, `WasmValueObject::type`: 用于类型检查和获取 WebAssembly 值对象信息的辅助函数。

* **代码位置信息 (`Location`):**
    * `Location` 类用于表示代码中的行号和列号，用于调试信息。

* **脚本管理:**
    * `GetLoadedScripts`: 获取当前 Isolate 中加载的所有脚本（包括 JavaScript 和 WebAssembly）。
    * `CompileInspectorScript`: 编译用于检查器的脚本。

* **调试控制:**
    * `SetDebugDelegate`: 设置调试委托，用于接收调试事件。
    * `SetAsyncEventDelegate`: 设置异步事件委托。
    * `ResetBlackboxedStateCache`: 重置黑盒函数的状态缓存。

* **对象信息获取:**
    * `EstimatedValueSize`: 估计一个 V8 对象的大小。
    * `AccessorPair::CheckCast`, `AccessorPair::IsAccessorPair`, `AccessorPair::getter`, `AccessorPair::setter`:  用于类型检查和获取访问器对信息的辅助函数。

* **内置函数:**
    * `GetBuiltin`: 获取指定的内置函数 (示例中为 `String.prototype.toLocaleLowerCase`)。

* **Console 集成:**
    * `SetConsoleDelegate`: 设置控制台委托，用于处理 `console` API 的调用。
    * `ConsoleCallArguments`:  封装控制台调用的参数。

* **异常处理:**
    * `CreateMessageFromException`: 从异常创建一个消息对象。

* **生成器对象 (GeneratorObject):**
    * `GeneratorObject::Script`: 获取生成器对象所在脚本。
    * `GeneratorObject::Function`: 获取生成器对象关联的函数。
    * `GeneratorObject::SuspendedLocation`: 获取生成器对象暂停时的位置。
    * `GeneratorObject::IsSuspended`: 判断生成器对象是否已暂停。
    * `GeneratorObject::Cast`: 将一个 Value 转换为 GeneratorObject。

* **代码执行:**
    * `CallFunctionOn`: 在指定的上下文中使用给定的接收者和参数调用函数。
    * `EvaluateGlobal`: 在全局作用域中执行一段 JavaScript 代码。

* **作用域信息:**
    * `GlobalLexicalScopeNames`: 获取全局词法作用域中的变量名。

* **返回值控制:**
    * `SetReturnValue`: 设置调试器返回的值。

* **随机数生成:**
    * `GetNextRandomInt64`: 获取下一个 64 位随机整数。

* **函数断点:**
    * `GetDebuggingId`: 获取函数的调试 ID。
    * `SetFunctionBreakpoint`: 为函数设置断点。

* **作用域管理:**
    * `PostponeInterruptsScope`:  推迟中断。
    * `DisableBreakScope`: 禁用断点。

* **代码覆盖率 (Coverage):**
    * 提供用于收集和访问代码覆盖率信息的类和函数 (`Coverage`, `BlockData`, `FunctionData`, `ScriptData`)。

* **弱哈希表 (EphemeronTable):**
    * 提供用于操作弱哈希表的类 (`EphemeronTable`)，用于存储键值对，其中键是弱引用的。

* **Promise 调试:**
    * `GetMessageFromPromise`: 尝试从 Promise 中获取调试消息。

* **异步栈标记:**
    * `RecordAsyncStackTaggingCreateTaskCall`: 记录异步栈标记创建任务调用。

* **调试器事件通知:**
    * `NotifyDebuggerPausedEventSent`: 通知调试器暂停事件已发送。

* **属性迭代:**
    * `PropertyIterator::Create`: 创建一个属性迭代器，用于遍历对象的属性。
    * `DebugPropertyIterator::Advance`:  移动属性迭代器到下一个属性。

**与 JavaScript 的关系及示例:**

这些 C++ 函数通常没有直接的 JavaScript 对等物，因为它们是 V8 引擎内部的调试接口。然而，JavaScript 调试器（如 Chrome DevTools）会使用这些接口来实现其功能。

例如：

* **`GetLoadedScripts`**: 当你在 Chrome DevTools 的 "Sources" 面板中看到加载的脚本列表时，DevTools 可能会调用这个 C++ 函数来获取这些信息。
* **`SetFunctionBreakpoint`**: 当你在 DevTools 中设置函数断点时，DevTools 会调用这个 C++ 函数来通知 V8 引擎。
* **`EvaluateGlobal`**: 当你在 DevTools 的 "Console" 中执行代码时，DevTools 可能会使用这个函数来在 V8 中执行代码。
* **`Coverage::CollectPrecise`**:  当你使用 DevTools 的代码覆盖率功能时，它会调用相应的 C++ 函数来收集覆盖率数据。

**代码逻辑推理和假设输入/输出:**

以 `WasmScript::GetContainingFunction` 为例：

**假设输入:**

* `byte_offset`: 一个整数，表示 WebAssembly 模块中的一个字节偏移量。
* 一个已加载的 WebAssembly 脚本对象 (`this`).

**代码逻辑推理:**

该函数会在给定的字节偏移量处查找包含该偏移量的 WebAssembly 函数。它会遍历 WebAssembly 模块的函数列表，并检查每个函数的代码范围是否包含给定的 `byte_offset`。

**假设输出:**

* 如果在给定的 `byte_offset` 处找到一个 WebAssembly 函数，则返回该函数的索引（一个整数）。
* 如果没有找到，则可能返回一个特定的值表示未找到（具体值需要查看 V8 源码中 `i::wasm::GetContainingWasmFunction` 的实现）。

**用户常见的编程错误示例:**

V8 的调试接口可以帮助开发者调试各种 JavaScript 和 WebAssembly 编程错误。例如：

* **运行时错误:** 当 JavaScript 代码抛出异常时，调试器可以使用 `CreateMessageFromException` 来获取错误信息并显示给开发者。
* **逻辑错误:** 开发者可以使用断点 (`SetFunctionBreakpoint`) 来暂停代码执行，并检查变量的值，从而发现逻辑上的错误。
* **性能问题:** 代码覆盖率功能 (`Coverage::CollectPrecise`) 可以帮助开发者识别未执行的代码，这些代码可能是冗余的或者暗示着性能优化的机会。
* **WebAssembly 错误:** 调试器可以使用 `WasmScript::Disassemble` 来查看 WebAssembly 代码的底层指令，帮助理解和调试 WebAssembly 模块的问题。

**总结:**

这段代码是 V8 调试接口的重要组成部分，它提供了各种功能来检查和控制 V8 虚拟机的执行状态，特别是在调试 JavaScript 和 WebAssembly 代码时。它充当了 V8 内部机制和外部调试工具之间的桥梁。

### 提示词
```
这是目录为v8/src/debug/debug-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
;
  DCHECK_GE(i::kMaxInt, func.code.offset());
  DCHECK_GE(i::kMaxInt, func.code.end_offset());
  return std::make_pair(static_cast<int>(func.code.offset()),
                        static_cast<int>(func.code.end_offset()));
}

int WasmScript::GetContainingFunction(int byte_offset) const {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();
  DCHECK_LE(0, byte_offset);

  return i::wasm::GetContainingWasmFunction(module, byte_offset);
}

void WasmScript::Disassemble(DisassemblyCollector* collector,
                             std::vector<int>* function_body_offsets) {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();
  i::wasm::ModuleWireBytes wire_bytes(native_module->wire_bytes());
  i::wasm::Disassemble(module, wire_bytes, native_module->GetNamesProvider(),
                       collector, function_body_offsets);
}

void Disassemble(base::Vector<const uint8_t> wire_bytes,
                 DisassemblyCollector* collector,
                 std::vector<int>* function_body_offsets) {
  i::wasm::Disassemble(wire_bytes, collector, function_body_offsets);
}

uint32_t WasmScript::GetFunctionHash(int function_index) {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();
  DCHECK_LE(0, function_index);
  DCHECK_GT(module->functions.size(), function_index);
  const i::wasm::WasmFunction& func = module->functions[function_index];
  i::wasm::ModuleWireBytes wire_bytes(native_module->wire_bytes());
  base::Vector<const uint8_t> function_bytes =
      wire_bytes.GetFunctionBytes(&func);
  // TODO(herhut): Maybe also take module, name and signature into account.
  return i::StringHasher::HashSequentialString(function_bytes.begin(),
                                               function_bytes.length(), 0);
}

int WasmScript::CodeOffset() const {
  auto script = Utils::OpenDirectHandle(this);
  DCHECK_EQ(i::Script::Type::kWasm, script->type());
  i::wasm::NativeModule* native_module = script->wasm_native_module();
  const i::wasm::WasmModule* module = native_module->module();

  // If the module contains at least one function, the code offset must have
  // been initialized, and it cannot be zero.
  DCHECK_IMPLIES(module->num_declared_functions > 0,
                 module->code.offset() != 0);
  return module->code.offset();
}
#endif  // V8_ENABLE_WEBASSEMBLY

Location::Location(int line_number, int column_number)
    : line_number_(line_number),
      column_number_(column_number),
      is_empty_(false) {}

Location::Location()
    : line_number_(Function::kLineOffsetNotFound),
      column_number_(Function::kLineOffsetNotFound),
      is_empty_(true) {}

int Location::GetLineNumber() const {
  DCHECK(!IsEmpty());
  return line_number_;
}

int Location::GetColumnNumber() const {
  DCHECK(!IsEmpty());
  return column_number_;
}

bool Location::IsEmpty() const { return is_empty_; }

void GetLoadedScripts(Isolate* v8_isolate,
                      std::vector<v8::Global<Script>>& scripts) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  {
    i::DisallowGarbageCollection no_gc;
    i::Script::Iterator iterator(isolate);
    for (i::Tagged<i::Script> script = iterator.Next(); !script.is_null();
         script = iterator.Next()) {
#if V8_ENABLE_WEBASSEMBLY
      if (script->type() != i::Script::Type::kNormal &&
          script->type() != i::Script::Type::kWasm) {
        continue;
      }
#else
      if (script->type() != i::Script::Type::kNormal) continue;
#endif  // V8_ENABLE_WEBASSEMBLY
      if (!script->HasValidSource()) continue;
      i::HandleScope handle_scope(isolate);
      i::DirectHandle<i::Script> script_handle(script, isolate);
      scripts.emplace_back(v8_isolate, ToApiHandle<Script>(script_handle));
    }
  }
}

MaybeLocal<UnboundScript> CompileInspectorScript(Isolate* v8_isolate,
                                                 Local<String> source) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  v8::Local<v8::Context> context = Utils::ToLocal(isolate->native_context());
  PREPARE_FOR_DEBUG_INTERFACE_EXECUTION_WITH_ISOLATE(isolate, context,
                                                     UnboundScript);
  i::Handle<i::String> str = Utils::OpenHandle(*source);
  i::DirectHandle<i::SharedFunctionInfo> result;
  {
    i::AlignedCachedData* cached_data = nullptr;
    ScriptCompiler::CompilationDetails compilation_details;
    i::MaybeDirectHandle<i::SharedFunctionInfo> maybe_function_info =
        i::Compiler::GetSharedFunctionInfoForScriptWithCachedData(
            isolate, str, i::ScriptDetails(), cached_data,
            ScriptCompiler::kNoCompileOptions,
            ScriptCompiler::kNoCacheBecauseInspector,
            i::v8_flags.expose_inspector_scripts ? i::NOT_NATIVES_CODE
                                                 : i::INSPECTOR_CODE,
            &compilation_details);
    has_exception = !maybe_function_info.ToHandle(&result);
    RETURN_ON_FAILED_EXECUTION(UnboundScript);
  }
  RETURN_ESCAPED(ToApiHandle<UnboundScript>(result));
}

#if V8_ENABLE_WEBASSEMBLY
void EnterDebuggingForIsolate(Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::wasm::GetWasmEngine()->EnterDebuggingForIsolate(isolate);
}

void LeaveDebuggingForIsolate(Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::wasm::GetWasmEngine()->LeaveDebuggingForIsolate(isolate);
}
#endif  // V8_ENABLE_WEBASSEMBLY

void SetDebugDelegate(Isolate* v8_isolate, DebugDelegate* delegate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  isolate->debug()->SetDebugDelegate(delegate);
}

void SetAsyncEventDelegate(Isolate* v8_isolate, AsyncEventDelegate* delegate) {
  reinterpret_cast<i::Isolate*>(v8_isolate)->set_async_event_delegate(delegate);
}

void ResetBlackboxedStateCache(Isolate* v8_isolate, Local<Script> script) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  i::DisallowGarbageCollection no_gc;
  i::SharedFunctionInfo::ScriptIterator iter(isolate,
                                             *Utils::OpenDirectHandle(*script));
  for (i::Tagged<i::SharedFunctionInfo> info = iter.Next(); !info.is_null();
       info = iter.Next()) {
    if (auto debug_info = isolate->debug()->TryGetDebugInfo(info)) {
      debug_info.value()->set_computed_debug_is_blackboxed(false);
    }
  }
}

int EstimatedValueSize(Isolate* v8_isolate, Local<Value> value) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  auto object = Utils::OpenDirectHandle(*value);
  if (IsSmi(*object)) return i::kTaggedSize;
  CHECK(IsHeapObject(*object));
  return i::Cast<i::HeapObject>(object)->Size();
}

void AccessorPair::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsAccessorPair(*obj), "v8::debug::AccessorPair::Cast",
                  "Value is not a v8::debug::AccessorPair");
}

#if V8_ENABLE_WEBASSEMBLY
void WasmValueObject::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsWasmValueObject(*obj),
                  "v8::debug::WasmValueObject::Cast",
                  "Value is not a v8::debug::WasmValueObject");
}

bool WasmValueObject::IsWasmValueObject(Local<Value> that) {
  auto obj = Utils::OpenDirectHandle(*that);
  return i::IsWasmValueObject(*obj);
}

Local<String> WasmValueObject::type() const {
  auto object = i::Cast<i::WasmValueObject>(Utils::OpenDirectHandle(this));
  i::Isolate* isolate = object->GetIsolate();
  i::DirectHandle<i::String> type(object->type(), isolate);
  return Utils::ToLocal(type);
}
#endif  // V8_ENABLE_WEBASSEMBLY

Local<Function> GetBuiltin(Isolate* v8_isolate, Builtin requested_builtin) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  i::HandleScope handle_scope(isolate);

  CHECK_EQ(requested_builtin, kStringToLowerCase);
  i::Builtin builtin = i::Builtin::kStringPrototypeToLocaleLowerCase;

  i::Factory* factory = isolate->factory();
  i::Handle<i::String> name = isolate->factory()->empty_string();
  i::Handle<i::NativeContext> context(isolate->native_context());
  i::Handle<i::SharedFunctionInfo> info =
      factory->NewSharedFunctionInfoForBuiltin(name, builtin, 0, i::kAdapt);
  info->set_language_mode(i::LanguageMode::kStrict);
  i::Handle<i::JSFunction> fun =
      i::Factory::JSFunctionBuilder{isolate, info, context}
          .set_map(isolate->strict_function_without_prototype_map())
          .Build();

  return Utils::ToLocal(handle_scope.CloseAndEscape(fun));
}

void SetConsoleDelegate(Isolate* v8_isolate, ConsoleDelegate* delegate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(isolate);
  if (delegate == nullptr) {
    isolate->set_console_delegate(nullptr);
  } else {
    isolate->set_console_delegate(delegate);
  }
}

ConsoleCallArguments::ConsoleCallArguments(
    const v8::FunctionCallbackInfo<v8::Value>& info)
    : isolate_(info.GetIsolate()),
      values_(info.values_),
      length_(info.Length()) {}

ConsoleCallArguments::ConsoleCallArguments(
    internal::Isolate* isolate, const internal::BuiltinArguments& args)
    : isolate_(reinterpret_cast<v8::Isolate*>(isolate)),
      values_(args.length() > 1 ? args.address_of_first_argument() : nullptr),
      length_(args.length() - 1) {}

v8::Local<v8::Message> CreateMessageFromException(
    Isolate* v8_isolate, v8::Local<v8::Value> v8_error) {
  i::Handle<i::Object> obj = Utils::OpenHandle(*v8_error);
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  i::HandleScope scope(isolate);
  return Utils::MessageToLocal(
      scope.CloseAndEscape(isolate->CreateMessageFromException(obj)));
}

MaybeLocal<Script> GeneratorObject::Script() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Tagged<i::Object> maybe_script = obj->function()->shared()->script();
  if (!IsScript(maybe_script)) return {};
  i::Isolate* isolate = obj->GetIsolate();
  i::DirectHandle<i::Script> script(i::Cast<i::Script>(maybe_script), isolate);
  return ToApiHandle<v8::debug::Script>(script);
}

Local<Function> GeneratorObject::Function() {
  auto obj = Utils::OpenDirectHandle(this);
  return Utils::ToLocal(handle(obj->function(), obj->GetIsolate()));
}

Location GeneratorObject::SuspendedLocation() {
  auto obj = Utils::OpenDirectHandle(this);
  CHECK(obj->is_suspended());
  i::Tagged<i::Object> maybe_script = obj->function()->shared()->script();
  if (!IsScript(maybe_script)) return Location();
  i::Isolate* isolate = obj->GetIsolate();
  i::DirectHandle<i::Script> script(i::Cast<i::Script>(maybe_script), isolate);
  i::Script::PositionInfo info;
  i::SharedFunctionInfo::EnsureSourcePositionsAvailable(
      isolate, i::handle(obj->function()->shared(), isolate));
  i::Script::GetPositionInfo(script, obj->source_position(), &info);
  return Location(info.line, info.column);
}

bool GeneratorObject::IsSuspended() {
  return Utils::OpenDirectHandle(this)->is_suspended();
}

v8::Local<GeneratorObject> GeneratorObject::Cast(v8::Local<v8::Value> value) {
  CHECK(value->IsGeneratorObject());
  return ToApiHandle<GeneratorObject>(Utils::OpenHandle(*value));
}

MaybeLocal<Value> CallFunctionOn(Local<Context> context,
                                 Local<Function> function, Local<Value> recv,
                                 int argc, Global<Value> argv[],
                                 bool throw_on_side_effect) {
  auto isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  PREPARE_FOR_DEBUG_INTERFACE_EXECUTION_WITH_ISOLATE(isolate, context, Value);
  auto self = Utils::OpenHandle(*function);
  auto recv_obj = Utils::OpenHandle(*recv);
  static_assert(sizeof(v8::Global<v8::Value>) == sizeof(i::Handle<i::Object>));
  auto args = reinterpret_cast<i::Handle<i::Object>*>(argv);
  // Disable breaks in side-effect free mode.
  i::DisableBreak disable_break_scope(isolate->debug(), throw_on_side_effect);
  if (throw_on_side_effect) {
    isolate->debug()->StartSideEffectCheckMode();
  }
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::Call(isolate, self, recv_obj, argc, args), &result);
  if (throw_on_side_effect) {
    isolate->debug()->StopSideEffectCheckMode();
  }
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::Value> EvaluateGlobal(v8::Isolate* isolate,
                                     v8::Local<v8::String> source,
                                     EvaluateGlobalMode mode, bool repl) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::Local<v8::Context> context = Utils::ToLocal(i_isolate->native_context());
  PREPARE_FOR_DEBUG_INTERFACE_EXECUTION_WITH_ISOLATE(i_isolate, context, Value);
  i::REPLMode repl_mode = repl ? i::REPLMode::kYes : i::REPLMode::kNo;
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::DebugEvaluate::Global(i_isolate, Utils::OpenHandle(*source), mode,
                               repl_mode),
      &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

void GlobalLexicalScopeNames(v8::Local<v8::Context> v8_context,
                             std::vector<v8::Global<v8::String>>* names) {
  auto context = Utils::OpenDirectHandle(*v8_context);
  i::Isolate* isolate = context->GetIsolate();
  i::DirectHandle<i::ScriptContextTable> table(
      context->native_context()->script_context_table(), isolate);
  for (int i = 0; i < table->length(kAcquireLoad); i++) {
    i::DirectHandle<i::Context> script_context(table->get(i), isolate);
    DCHECK(script_context->IsScriptContext());
    i::Handle<i::ScopeInfo> scope_info(script_context->scope_info(), isolate);
    for (auto it : i::ScopeInfo::IterateLocalNames(scope_info)) {
      if (i::ScopeInfo::VariableIsSynthetic(it->name())) continue;
      names->emplace_back(reinterpret_cast<Isolate*>(isolate),
                          Utils::ToLocal(handle(it->name(), isolate)));
    }
  }
}

void SetReturnValue(v8::Isolate* v8_isolate, v8::Local<v8::Value> value) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  isolate->debug()->set_return_value(*Utils::OpenDirectHandle(*value));
}

int64_t GetNextRandomInt64(v8::Isolate* v8_isolate) {
  return reinterpret_cast<i::Isolate*>(v8_isolate)
      ->random_number_generator()
      ->NextInt64();
}

int GetDebuggingId(v8::Local<v8::Function> function) {
  auto callable = v8::Utils::OpenDirectHandle(*function);
  if (!IsJSFunction(*callable)) return i::DebugInfo::kNoDebuggingId;
  auto func = i::Cast<i::JSFunction>(callable);
  int id = func->GetIsolate()->debug()->GetFunctionDebuggingId(func);
  DCHECK_NE(i::DebugInfo::kNoDebuggingId, id);
  return id;
}

bool SetFunctionBreakpoint(v8::Local<v8::Function> function,
                           v8::Local<v8::String> condition, BreakpointId* id) {
  auto callable = Utils::OpenDirectHandle(*function);
  if (!IsJSFunction(*callable)) return false;
  auto jsfunction = i::Cast<i::JSFunction>(callable);
  i::Isolate* isolate = jsfunction->GetIsolate();
  i::DirectHandle<i::String> condition_string =
      condition.IsEmpty()
          ? i::DirectHandle<i::String>(isolate->factory()->empty_string())
          : Utils::OpenDirectHandle(*condition);
  return isolate->debug()->SetBreakpointForFunction(
      handle(jsfunction->shared(), isolate), condition_string, id);
}

PostponeInterruptsScope::PostponeInterruptsScope(v8::Isolate* isolate)
    : scope_(
          new i::PostponeInterruptsScope(reinterpret_cast<i::Isolate*>(isolate),
                                         i::StackGuard::API_INTERRUPT)) {}

PostponeInterruptsScope::~PostponeInterruptsScope() = default;

DisableBreakScope::DisableBreakScope(v8::Isolate* isolate)
    : scope_(std::make_unique<i::DisableBreak>(
          reinterpret_cast<i::Isolate*>(isolate)->debug())) {}

DisableBreakScope::~DisableBreakScope() = default;

int Coverage::BlockData::StartOffset() const { return block_->start; }

int Coverage::BlockData::EndOffset() const { return block_->end; }

uint32_t Coverage::BlockData::Count() const { return block_->count; }

int Coverage::FunctionData::StartOffset() const { return function_->start; }

int Coverage::FunctionData::EndOffset() const { return function_->end; }

uint32_t Coverage::FunctionData::Count() const { return function_->count; }

MaybeLocal<String> Coverage::FunctionData::Name() const {
  return ToApiHandle<String>(function_->name);
}

size_t Coverage::FunctionData::BlockCount() const {
  return function_->blocks.size();
}

bool Coverage::FunctionData::HasBlockCoverage() const {
  return function_->has_block_coverage;
}

Coverage::BlockData Coverage::FunctionData::GetBlockData(size_t i) const {
  return BlockData(&function_->blocks.at(i), coverage_);
}

Local<Script> Coverage::ScriptData::GetScript() const {
  return ToApiHandle<Script>(script_->script);
}

size_t Coverage::ScriptData::FunctionCount() const {
  return script_->functions.size();
}

Coverage::FunctionData Coverage::ScriptData::GetFunctionData(size_t i) const {
  return FunctionData(&script_->functions.at(i), coverage_);
}

Coverage::ScriptData::ScriptData(size_t index,
                                 std::shared_ptr<i::Coverage> coverage)
    : script_(&coverage->at(index)), coverage_(std::move(coverage)) {}

size_t Coverage::ScriptCount() const { return coverage_->size(); }

Coverage::ScriptData Coverage::GetScriptData(size_t i) const {
  return ScriptData(i, coverage_);
}

Coverage Coverage::CollectPrecise(Isolate* isolate) {
  return Coverage(
      i::Coverage::CollectPrecise(reinterpret_cast<i::Isolate*>(isolate)));
}

Coverage Coverage::CollectBestEffort(Isolate* isolate) {
  return Coverage(
      i::Coverage::CollectBestEffort(reinterpret_cast<i::Isolate*>(isolate)));
}

void Coverage::SelectMode(Isolate* isolate, CoverageMode mode) {
  i::Coverage::SelectMode(reinterpret_cast<i::Isolate*>(isolate), mode);
}

MaybeLocal<v8::Value> EphemeronTable::Get(v8::Isolate* isolate,
                                          v8::Local<v8::Value> key) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  auto self = i::Cast<i::EphemeronHashTable>(Utils::OpenDirectHandle(this));
  i::Handle<i::Object> internal_key = Utils::OpenHandle(*key);
  DCHECK(IsJSReceiver(*internal_key));

  i::DirectHandle<i::Object> value(self->Lookup(internal_key), i_isolate);

  if (IsTheHole(*value)) return {};
  return Utils::ToLocal(value);
}

Local<EphemeronTable> EphemeronTable::Set(v8::Isolate* isolate,
                                          v8::Local<v8::Value> key,
                                          v8::Local<v8::Value> value) {
  auto self = i::Cast<i::EphemeronHashTable>(Utils::OpenHandle(this));
  i::Handle<i::Object> internal_key = Utils::OpenHandle(*key);
  i::Handle<i::Object> internal_value = Utils::OpenHandle(*value);
  DCHECK(IsJSReceiver(*internal_key));

  i::DirectHandle<i::EphemeronHashTable> result(
      i::EphemeronHashTable::Put(self, internal_key, internal_value));

  return ToApiHandle<EphemeronTable>(result);
}

Local<EphemeronTable> EphemeronTable::New(v8::Isolate* isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::EphemeronHashTable> table =
      i::EphemeronHashTable::New(i_isolate, 0);
  return ToApiHandle<EphemeronTable>(table);
}

EphemeronTable* EphemeronTable::Cast(v8::Value* value) {
  return static_cast<EphemeronTable*>(value);
}

Local<Value> AccessorPair::getter() {
  auto accessors = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = accessors->GetIsolate();
  i::DirectHandle<i::Object> getter(accessors->getter(), isolate);
  return Utils::ToLocal(getter);
}

Local<Value> AccessorPair::setter() {
  auto accessors = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = accessors->GetIsolate();
  i::DirectHandle<i::Object> setter(accessors->setter(), isolate);
  return Utils::ToLocal(setter);
}

bool AccessorPair::IsAccessorPair(Local<Value> that) {
  return i::IsAccessorPair(*Utils::OpenDirectHandle(*that));
}

MaybeLocal<Message> GetMessageFromPromise(Local<Promise> p) {
  i::Handle<i::JSPromise> promise = Utils::OpenHandle(*p);
  i::Isolate* isolate = promise->GetIsolate();

  i::Handle<i::Symbol> key = isolate->factory()->promise_debug_message_symbol();
  i::Handle<i::Object> maybeMessage =
      i::JSReceiver::GetDataProperty(isolate, promise, key);

  if (!IsJSMessageObject(*maybeMessage, isolate)) return MaybeLocal<Message>();
  return ToApiHandle<Message>(i::Cast<i::JSMessageObject>(maybeMessage));
}

void RecordAsyncStackTaggingCreateTaskCall(v8::Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  isolate->CountUsage(v8::Isolate::kAsyncStackTaggingCreateTaskCall);
}

void NotifyDebuggerPausedEventSent(v8::Isolate* v8_isolate) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  isolate->debug()->NotifyDebuggerPausedEventSent();
}

std::unique_ptr<PropertyIterator> PropertyIterator::Create(
    Local<Context> context, Local<Object> object, bool skip_indices) {
  internal::Isolate* isolate =
      reinterpret_cast<i::Isolate*>(context->GetIsolate());
  if (isolate->is_execution_terminating()) {
    return nullptr;
  }
  CallDepthScope<false> call_depth_scope(isolate, context);

  return i::DebugPropertyIterator::Create(isolate, Utils::OpenHandle(*object),
                                          skip_indices);
}

}  // namespace debug

namespace internal {

Maybe<bool> DebugPropertyIterator::Advance() {
  if (isolate_->is_execution_terminating()) {
    return Nothing<bool>();
  }
  Local<v8::Context> context =
      Utils::ToLocal(handle(isolate_->context()->native_context(), isolate_));
  CallDepthScope<false> call_depth_scope(isolate_, context);

  if (!AdvanceInternal()) {
    DCHECK(isolate_->has_exception());
    return Nothing<bool>();
  }
  return Just(true);
}

}  // namespace internal
}  // namespace v8

#include "src/api/api-macros-undef.h"
```