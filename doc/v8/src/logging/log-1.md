Response: The user provided a C++ source code file for the V8 JavaScript engine's logging functionality. This is the second part of the file. The goal is to summarize the functionality of this part of the code and illustrate any connections to JavaScript using JavaScript examples.

**Breakdown of the Code:**

1. **Function Event Logging:** Logs function calls with details like reason, script ID, time delta, start/end positions, and function name. Two overloaded functions handle cases with `Tagged<String>` and `const char*` for function names.

2. **Compilation Cache Event Logging:** Logs events related to the compilation cache, including the action (e.g., "store", "load"), cache type, script ID, and start/end positions of the compiled function.

3. **Script Event Logging:** Logs various script-related events, such as reserving an ID, creation, deserialization, and different types of compilation (background, streaming).

4. **Script Details Logging:** Logs detailed information about a script, including its ID, name, line/column offset, and source mapping URL.

5. **Source Code Logging:**  Ensures that the source code of a script is logged. It avoids logging the same source code multiple times.

6. **Runtime Call Timer Event Logging:**  Logs events related to active runtime timers (enabled via `V8_RUNTIME_CALL_STATS`).

7. **Tick Event Logging (Profiling):** Logs tick events, which are used for CPU profiling. Includes information about the program counter, time, external callbacks (if any), stack state, and stack frames.

8. **IC (Inline Cache) Event Logging:** Logs events related to inline caches, providing details about the type of IC, whether it's keyed, the involved map and key, old and new states, modifiers, and reasons for slow stubs.

9. **Map Event Logging:** Logs events related to map (hidden class) transitions or creations, including the type of event, involved maps, the reason for the event, and potentially the name or SharedFunctionInfo associated with the map change.

10. **Map Create/Details/Move Event Logging:** Specific functions for logging map creation, detailed information about a map's structure, and map moves.

11. **Enumerating Compiled Functions:** A utility function to find and collect all compiled functions in the heap. This is used for logging existing compiled code.

12. **Enumerating Interpreted Functions (Windows ETW):**  A function specific to Windows ETW to enumerate functions that are currently being interpreted (have bytecode).

13. **Logging Interpreted Functions (Windows ETW):**  Logs interpreted functions for ETW tracing by installing interpreter trampolines.

14. **Logging Existing Code Objects:** Functions to log various existing code objects (stubs, builtins, compiled functions) when logging is enabled after some code has already been generated.

15. **Logging Builtins and Accessor Callbacks:** Functions to log built-in functions and getter/setter callbacks.

16. **Logging All Maps:** Logs all existing maps in the heap.

17. **Log File Setup:**  Sets up the log file, including handling placeholders in the filename (like process ID and timestamp). It also initializes platform-specific loggers (like the Linux perf logger).

18. **Late Setup:**  Performs setup steps that need to happen later in the initialization process, such as emitting code creation events for builtins and enabling Wasm code logging.

19. **ETW Code Event Handling (Windows):**  Functions to manage ETW (Event Tracing for Windows) code event handling, allowing the logging of code events for tools like Windows Performance Analyzer.

20. **Generic Code Event Handling:**  Functions to set up a generic code event handler, allowing external tools to receive notifications about code creation.

21. **Profiler Integration:** Integrates with the V8 profiler, starting and stopping it.

22. **Log File Teardown:**  Closes the log file and cleans up resources.

23. **Helper Functions:** Includes helper functions for updating the logging status, logging individual code objects, and converting internal code tags to more descriptive names.

**Connections to JavaScript:**

The logged events directly reflect actions and states within the JavaScript execution environment. Here are examples of how these logs relate to JavaScript code:

*   **Function Events:**  When a JavaScript function is called or returns, `FunctionEvent` would be triggered.
*   **Compilation Cache Events:** When V8 reuses previously compiled code for a function, `CompilationCacheEvent` would log whether it was a hit or miss.
*   **Script Events:** Loading a `<script>` tag or calling `eval()` would trigger `ScriptEvent` (create). Background compilation of a function would also be logged.
*   **IC Events:** When accessing properties of JavaScript objects, the inline cache mechanism is used. `ICEvent` logs the state transitions of these caches, indicating optimization efforts.
*   **Map Events:**  When the hidden class of a JavaScript object changes (e.g., by adding a new property), `MapEvent` would log this transition.
*   **Tick Events:**  During CPU profiling, every "tick" of the CPU timer would be logged with `TickEvent`, showing where the JavaScript code (or V8 internals) is spending time.

**JavaScript Examples:**

1. **Function Events:**

    ```javascript
    function myFunction() {
      console.log("Hello");
    }

    myFunction(); // This function call would likely trigger a FunctionEvent log.
    ```

2. **Compilation Cache Events:**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    add(1, 2); // First call might compile the function.
    add(3, 4); // Subsequent calls might hit the compilation cache.
    ```

3. **Script Events:**

    ```html
    <script>
      console.log("Script loaded"); // Loading this script would trigger a ScriptEvent.
    </script>

    <script>
      eval("console.log('Evaluated code')"); // Using eval would also log a ScriptEvent.
    </script>
    ```

4. **IC Events:**

    ```javascript
    const obj = { x: 1 };
    console.log(obj.x); // First access might be a "miss," subsequent accesses a "hit."
    obj.y = 2; // Adding a property might trigger an IC state change.
    console.log(obj.y);
    ```

5. **Map Events:**

    ```javascript
    const point = { x: 1, y: 2 }; // Object has a certain hidden class.
    point.z = 3; // Adding 'z' might cause a map transition, logged by MapEvent.
    ```

**Summary of Functionality:**

This part of `v8/src/logging/log.cc` defines the `V8FileLogger` class, which is responsible for logging various events occurring within the V8 JavaScript engine to a file. It captures information related to:

*   **Function execution:** Entry and exit points, execution times.
*   **Code compilation:** Compilation cache usage, script loading and compilation processes.
*   **Internal optimizations:** Inline cache state transitions, map (hidden class) changes.
*   **Profiling:** CPU tick samples, runtime call statistics.
*   **Existing code:** Logging compiled and interpreted functions when logging starts.

This detailed logging is crucial for debugging, performance analysis, and understanding the internal workings of the V8 engine during JavaScript execution. The integration with platform-specific tools like Linux perf and Windows ETW further enhances its capabilities for system-level analysis.
这是 `v8/src/logging/log.cc` 文件的第二部分，主要功能是实现 V8 引擎的详细日志记录，包括记录函数事件、编译缓存事件、脚本事件、IC (Inline Cache) 事件、Map (隐藏类) 事件以及用于性能分析的 Tick 事件。它还负责处理已编译代码对象的日志记录，以便在启动日志记录后也能捕获到之前编译的代码。

**主要功能归纳如下：**

1. **记录详细的运行时事件：**
    *   **函数事件 (`FunctionEvent`)：** 记录 JavaScript 函数的调用和返回事件，包括原因、脚本 ID、时间差、起始和结束位置以及函数名。
    *   **编译缓存事件 (`CompilationCacheEvent`)：** 记录编译缓存的命中和未命中事件，包括动作类型、缓存类型、脚本 ID 和函数位置。
    *   **脚本事件 (`ScriptEvent`)：** 记录脚本的各种生命周期事件，如 ID 预留、创建、反序列化以及不同类型的编译（后台编译、流式编译）。
    *   **脚本详情 (`ScriptDetails`)：** 记录脚本的详细信息，如脚本 ID、名称、行列偏移和 source map URL。
    *   **确保记录脚本源码 (`EnsureLogScriptSource`)：** 确保脚本的源代码被记录到日志文件中，避免重复记录。
    *   **运行时调用计时器事件 (`RuntimeCallTimerEvent`)：**  当启用运行时调用统计时，记录当前活跃的运行时计时器。
    *   **Tick 事件 (`TickEvent`)：**  记录 CPU 的 tick 事件，用于性能分析，包括程序计数器、时间戳、是否为外部回调以及堆栈信息。
    *   **IC 事件 (`ICEvent`)：** 记录内联缓存（Inline Cache）的状态变化，包括类型、是否为键控访问、Map 对象、键值、新旧状态、修饰符和慢速 stub 的原因。
    *   **Map 事件 (`MapEvent`)：** 记录 Map (隐藏类) 的创建、迁移和详细信息，包括类型、时间戳、涉及的 Map 对象、原因以及相关的函数或名称。
    *   **Map 创建/详情/移动事件 (`MapCreate`, `MapDetails`, `MapMoveEvent`)：**  分别记录 Map 对象的创建、详细信息和在内存中的移动。

2. **记录已编译的代码对象：**
    *   **枚举已编译的函数 (`EnumerateCompiledFunctions`)：** 遍历堆找出所有已编译的 JavaScript 函数，并记录其 `SharedFunctionInfo` 和 `AbstractCode`。
    *   **记录代码对象 (`LogCodeObjects`)：** 记录所有存在的代码对象（包括 Stub 和已编译的函数）。
    *   **记录内置函数 (`LogBuiltins`)：** 记录 V8 引擎的内置函数。
    *   **记录已编译的函数 (`LogCompiledFunctions`)：**  记录所有已编译的 JavaScript 函数，包括解释器代码、Baseline 代码和 TurboFan/Maglev 编译的代码。
    *   **记录已存在的函数 (`LogExistingFunction`)：** 记录单个 `SharedFunctionInfo` 及其对应的 `AbstractCode`，包括函数名、脚本信息和代码类型。

3. **日志文件的管理和配置：**
    *   **`SetUp`：** 初始化日志系统，包括打开日志文件，创建平台相关的日志记录器（如 Linux perf 日志记录器）。
    *   **`LateSetup`：** 执行一些需要在后期进行的设置，例如触发内置函数的代码创建事件。
    *   **`TearDownAndGetLogFile`：** 关闭日志文件并清理资源。
    *   **`UpdateIsLogging`：**  动态更新日志记录的开启状态。
    *   **文件名准备 (`PrepareLogFileName`)：**  根据配置生成日志文件名，支持一些占位符，如进程 ID 和时间戳。

4. **与外部工具的集成：**
    *   **ETW 代码事件处理 (`SetEtwCodeEventHandler`, `ResetEtwCodeEventHandler`) (Windows)：**  允许 V8 将代码事件发送到 Windows 的 Event Tracing for Windows (ETW) 系统，用于性能分析工具。
    *   **通用代码事件处理 (`SetCodeEventHandler`)：**  允许注册自定义的回调函数来接收代码创建事件，方便集成到其他工具中。

5. **性能分析支持：**
    *   **`TickEvent`：**  为基于采样的性能分析提供基础数据。
    *   **`Profiler`：**  集成 V8 的性能分析器。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这些日志记录功能直接反映了 V8 引擎在执行 JavaScript 代码时的内部状态和行为。以下是一些示例说明它们之间的关系：

1. **函数事件与 JavaScript 函数调用：**

    ```javascript
    function greet(name) {
      console.log("Hello, " + name);
    }

    greet("World"); // 这次函数调用会触发一个 FunctionEvent，记录函数名 "greet"。
    ```

2. **编译缓存事件与 JavaScript 函数的重复执行：**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    add(1, 2); // 第一次调用可能会触发编译。
    add(3, 4); // 第二次调用可能会命中编译缓存，触发 CompilationCacheEvent。
    ```

3. **脚本事件与 JavaScript 代码的加载和执行：**

    ```html
    <script>
      console.log("脚本已加载"); // 加载这个 <script> 标签会触发一个 ScriptEvent (create)。
    </script>

    <script>
      eval("console.log('动态执行的代码')"); // 使用 eval 执行代码也会触发一个 ScriptEvent。
    </script>
    ```

4. **IC 事件与 JavaScript 对象属性的访问：**

    ```javascript
    const obj = { x: 1 };
    console.log(obj.x); // 第一次访问 obj.x 可能会触发 IC 的状态转换，记录在 ICEvent 中。
    console.log(obj.x); // 后续访问可能会命中 IC。
    ```

5. **Map 事件与 JavaScript 对象的结构变化：**

    ```javascript
    const point = { x: 1, y: 2 }; // 创建对象时会创建一个 Map (隐藏类)。
    point.z = 3; // 添加新属性可能会导致 Map 的迁移，触发 MapEvent。
    ```

**总结:**

这部分 `v8/src/logging/log.cc` 代码是 V8 引擎日志记录的核心实现，它详细记录了引擎在执行 JavaScript 代码时的各种关键事件和状态变化。这些日志对于理解 V8 引擎的内部工作原理、进行性能分析和调试至关重要。通过记录已编译的代码对象，它还能在后期启动日志记录时捕获到之前生成的代码信息。与外部工具的集成则进一步扩展了其应用场景。

### 提示词
```
这是目录为v8/src/logging/log.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
amespace

void V8FileLogger::FunctionEvent(const char* reason, int script_id,
                                 double time_delta, int start_position,
                                 int end_position,
                                 Tagged<String> function_name) {
  if (!v8_flags.log_function_events) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  AppendFunctionMessage(msg, reason, script_id, time_delta, start_position,
                        end_position, Time());
  if (!function_name.is_null()) msg << function_name;
  msg.WriteToLogFile();
}

void V8FileLogger::FunctionEvent(const char* reason, int script_id,
                                 double time_delta, int start_position,
                                 int end_position, const char* function_name,
                                 size_t function_name_length,
                                 bool is_one_byte) {
  if (!v8_flags.log_function_events) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  AppendFunctionMessage(msg, reason, script_id, time_delta, start_position,
                        end_position, Time());
  if (function_name_length > 0) {
    msg.AppendString(function_name, function_name_length, is_one_byte);
  }
  msg.WriteToLogFile();
}

void V8FileLogger::CompilationCacheEvent(const char* action,
                                         const char* cache_type,
                                         Tagged<SharedFunctionInfo> sfi) {
  if (!v8_flags.log_function_events) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  int script_id = -1;
  if (IsScript(sfi->script())) {
    script_id = Cast<Script>(sfi->script())->id();
  }
  msg << "compilation-cache" << V8FileLogger::kNext << action
      << V8FileLogger::kNext << cache_type << V8FileLogger::kNext << script_id
      << V8FileLogger::kNext << sfi->StartPosition() << V8FileLogger::kNext
      << sfi->EndPosition() << V8FileLogger::kNext << Time();
  msg.WriteToLogFile();
}

void V8FileLogger::ScriptEvent(ScriptEventType type, int script_id) {
  if (!v8_flags.log_function_events) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "script" << V8FileLogger::kNext;
  switch (type) {
    case ScriptEventType::kReserveId:
      msg << "reserve-id";
      break;
    case ScriptEventType::kCreate:
      msg << "create";
      break;
    case ScriptEventType::kDeserialize:
      msg << "deserialize";
      break;
    case ScriptEventType::kBackgroundCompile:
      msg << "background-compile";
      break;
    case ScriptEventType::kStreamingCompileBackground:
      msg << "streaming-compile";
      break;
    case ScriptEventType::kStreamingCompileForeground:
      msg << "streaming-compile-foreground";
      break;
  }
  msg << V8FileLogger::kNext << script_id << V8FileLogger::kNext << Time();
  msg.WriteToLogFile();
}

void V8FileLogger::ScriptDetails(Tagged<Script> script) {
  if (!v8_flags.log_function_events) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  {
    MSG_BUILDER();
    msg << "script-details" << V8FileLogger::kNext << script->id()
        << V8FileLogger::kNext;
    if (IsString(script->name())) {
      msg << Cast<String>(script->name());
    }
    msg << V8FileLogger::kNext << script->line_offset() << V8FileLogger::kNext
        << script->column_offset() << V8FileLogger::kNext;
    if (IsString(script->source_mapping_url())) {
      msg << Cast<String>(script->source_mapping_url());
    }
    msg.WriteToLogFile();
  }
  EnsureLogScriptSource(script);
}

bool V8FileLogger::EnsureLogScriptSource(Tagged<Script> script) {
  if (!v8_flags.log_source_code) return true;
  VMStateIfMainThread<LOGGING> state(isolate_);
  // Make sure the script is written to the log file.
  int script_id = script->id();
  if (logged_source_code_.find(script_id) != logged_source_code_.end()) {
    return true;
  }
  // This script has not been logged yet.
  logged_source_code_.insert(script_id);
  Tagged<Object> source_object = script->source();
  if (!IsString(source_object)) return false;

  std::unique_ptr<LogFile::MessageBuilder> msg_ptr =
      log_file_->NewMessageBuilder();
  if (!msg_ptr) return false;
  LogFile::MessageBuilder& msg = *msg_ptr.get();

  Tagged<String> source_code = Cast<String>(source_object);
  msg << "script-source" << kNext << script_id << kNext;

  // Log the script name.
  if (IsString(script->name())) {
    msg << Cast<String>(script->name()) << kNext;
  } else {
    msg << "<unknown>" << kNext;
  }

  // Log the source code.
  msg << source_code;
  msg.WriteToLogFile();
  return true;
}

void V8FileLogger::RuntimeCallTimerEvent() {
#ifdef V8_RUNTIME_CALL_STATS
  VMStateIfMainThread<LOGGING> state(isolate_);
  RuntimeCallStats* stats = isolate_->counters()->runtime_call_stats();
  RuntimeCallCounter* counter = stats->current_counter();
  if (counter == nullptr) return;
  MSG_BUILDER();
  msg << "active-runtime-timer" << kNext << counter->name();
  msg.WriteToLogFile();
#endif  // V8_RUNTIME_CALL_STATS
}

void V8FileLogger::TickEvent(TickSample* sample, bool overflow) {
  if (!v8_flags.prof_cpp) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  if (V8_UNLIKELY(TracingFlags::runtime_stats.load(std::memory_order_relaxed) ==
                  v8::tracing::TracingCategoryObserver::ENABLED_BY_NATIVE)) {
    RuntimeCallTimerEvent();
  }
  MSG_BUILDER();
  msg << Event::kTick << kNext << reinterpret_cast<void*>(sample->pc) << kNext
      << Time();
  if (sample->has_external_callback) {
    msg << kNext << 1 << kNext
        << reinterpret_cast<void*>(sample->external_callback_entry);
  } else {
    msg << kNext << 0 << kNext << reinterpret_cast<void*>(sample->tos);
  }
  msg << kNext << static_cast<int>(sample->state);
  if (overflow) msg << kNext << "overflow";
  for (unsigned i = 0; i < sample->frames_count; ++i) {
    msg << kNext << reinterpret_cast<void*>(sample->stack[i]);
  }
  msg.WriteToLogFile();
}

void V8FileLogger::ICEvent(const char* type, bool keyed, Handle<Map> map,
                           DirectHandle<Object> key, char old_state,
                           char new_state, const char* modifier,
                           const char* slow_stub_reason) {
  if (!v8_flags.log_ic) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  int line;
  int column;
  // GetAbstractPC must come before MSG_BUILDER(), as it can GC, which might
  // attempt to get the log lock again and result in a deadlock.
  Address pc = isolate_->GetAbstractPC(&line, &column);
  MSG_BUILDER();
  if (keyed) msg << "Keyed";
  msg << type << kNext << reinterpret_cast<void*>(pc) << kNext << Time()
      << kNext << line << kNext << column << kNext << old_state << kNext
      << new_state << kNext
      << AsHex::Address(map.is_null() ? kNullAddress : map->ptr()) << kNext;
  if (IsSmi(*key)) {
    msg << Smi::ToInt(*key);
  } else if (IsNumber(*key)) {
    msg << Object::NumberValue(*key);
  } else if (IsName(*key)) {
    msg << Cast<Name>(*key);
  }
  msg << kNext << modifier << kNext;
  if (slow_stub_reason != nullptr) {
    msg << slow_stub_reason;
  }
  msg.WriteToLogFile();
}

void V8FileLogger::MapEvent(const char* type, Handle<Map> from, Handle<Map> to,
                            const char* reason,
                            Handle<HeapObject> name_or_sfi) {
  if (!v8_flags.log_maps) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  if (!to.is_null()) MapDetails(*to);
  int line = -1;
  int column = -1;
  Address pc = 0;

  if (!isolate_->bootstrapper()->IsActive()) {
    pc = isolate_->GetAbstractPC(&line, &column);
  }
  MSG_BUILDER();
  msg << "map" << kNext << type << kNext << Time() << kNext
      << AsHex::Address(from.is_null() ? kNullAddress : from->ptr()) << kNext
      << AsHex::Address(to.is_null() ? kNullAddress : to->ptr()) << kNext
      << AsHex::Address(pc) << kNext << line << kNext << column << kNext
      << reason << kNext;

  if (!name_or_sfi.is_null()) {
    if (IsName(*name_or_sfi)) {
      msg << Cast<Name>(*name_or_sfi);
    } else if (IsSharedFunctionInfo(*name_or_sfi)) {
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(*name_or_sfi);
      msg << sfi->DebugNameCStr().get();
      msg << " " << sfi->unique_id();
    }
  }
  msg.WriteToLogFile();
}

void V8FileLogger::MapCreate(Tagged<Map> map) {
  if (!v8_flags.log_maps) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  DisallowGarbageCollection no_gc;
  MSG_BUILDER();
  msg << "map-create" << kNext << Time() << kNext << AsHex::Address(map.ptr());
  msg.WriteToLogFile();
}

void V8FileLogger::MapDetails(Tagged<Map> map) {
  if (!v8_flags.log_maps) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  DisallowGarbageCollection no_gc;
  MSG_BUILDER();
  msg << "map-details" << kNext << Time() << kNext << AsHex::Address(map.ptr())
      << kNext;
  if (v8_flags.log_maps_details) {
    std::ostringstream buffer;
    map->PrintMapDetails(buffer);
    msg << buffer.str().c_str();
  }
  msg.WriteToLogFile();
}

void V8FileLogger::MapMoveEvent(Tagged<Map> from, Tagged<Map> to) {
  if (!v8_flags.log_maps) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  DisallowGarbageCollection no_gc;
  MSG_BUILDER();
  msg << "map-move" << kNext << Time() << kNext << AsHex::Address(from.ptr())
      << kNext << AsHex::Address(to.ptr());
  msg.WriteToLogFile();
}

static std::vector<std::pair<Handle<SharedFunctionInfo>, Handle<AbstractCode>>>
EnumerateCompiledFunctions(Heap* heap) {
  HeapObjectIterator iterator(heap);
  DisallowGarbageCollection no_gc;
  std::vector<std::pair<Handle<SharedFunctionInfo>, Handle<AbstractCode>>>
      compiled_funcs;
  Isolate* isolate = heap->isolate();
  auto hash =
      [](const std::pair<Tagged<SharedFunctionInfo>, Tagged<AbstractCode>>& p) {
        return base::hash_combine(p.first.address(), p.second.address());
      };
  std::unordered_set<
      std::pair<Tagged<SharedFunctionInfo>, Tagged<AbstractCode>>,
      decltype(hash)>
      seen(8, hash);

  auto record = [&](Tagged<SharedFunctionInfo> sfi, Tagged<AbstractCode> c) {
    if (auto [iter, inserted] = seen.emplace(sfi, c); inserted)
      compiled_funcs.emplace_back(handle(sfi, isolate), handle(c, isolate));
  };

  // Iterate the heap to find JSFunctions and record their optimized code.
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsSharedFunctionInfo(obj)) {
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
      if (sfi->is_compiled() && !sfi->HasBytecodeArray()) {
        record(sfi, Cast<AbstractCode>(sfi->abstract_code(isolate)));
      }
    } else if (IsJSFunction(obj)) {
      // Given that we no longer iterate over all optimized JSFunctions, we need
      // to take care of this here.
      Tagged<JSFunction> function = Cast<JSFunction>(obj);
      // TODO(jarin) This leaves out deoptimized code that might still be on the
      // stack. Also note that we will not log optimized code objects that are
      // only on a type feedback vector. We should make this more precise.
      if (function->HasAttachedOptimizedCode(isolate) &&
          Cast<Script>(function->shared()->script())->HasValidSource()) {
        record(function->shared(), Cast<AbstractCode>(function->code(isolate)));
      }
    }
  }

  Script::Iterator script_iterator(heap->isolate());
  for (Tagged<Script> script = script_iterator.Next(); !script.is_null();
       script = script_iterator.Next()) {
    if (!script->HasValidSource()) continue;

    SharedFunctionInfo::ScriptIterator sfi_iterator(heap->isolate(), script);
    for (Tagged<SharedFunctionInfo> sfi = sfi_iterator.Next(); !sfi.is_null();
         sfi = sfi_iterator.Next()) {
      if (sfi->is_compiled()) {
        record(sfi, Cast<AbstractCode>(sfi->abstract_code(isolate)));
      }
    }
  }

  return compiled_funcs;
}

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
static std::vector<Handle<SharedFunctionInfo>> EnumerateInterpretedFunctions(
    Heap* heap) {
  HeapObjectIterator iterator(heap);
  DisallowGarbageCollection no_gc;
  std::vector<Handle<SharedFunctionInfo>> interpreted_funcs;
  Isolate* isolate = heap->isolate();

  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsSharedFunctionInfo(obj)) {
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
      if (sfi->HasBytecodeArray()) {
        interpreted_funcs.push_back(handle(sfi, isolate));
      }
    }
  }

  return interpreted_funcs;
}

void V8FileLogger::LogInterpretedFunctions() {
  existing_code_logger_.LogInterpretedFunctions();
}

void ExistingCodeLogger::LogInterpretedFunctions() {
  DCHECK(isolate_->logger()->is_listening_to_code_events());
  Heap* heap = isolate_->heap();
  HandleScope scope(isolate_);
  std::vector<Handle<SharedFunctionInfo>> interpreted_funcs =
      EnumerateInterpretedFunctions(heap);
  for (Handle<SharedFunctionInfo> sfi : interpreted_funcs) {
    if (sfi->HasInterpreterData(isolate_) || !sfi->HasSourceCode() ||
        !sfi->HasBytecodeArray()) {
      continue;
    }
    LogEventListener::CodeTag log_tag =
        sfi->is_toplevel() ? LogEventListener::CodeTag::kScript
                           : LogEventListener::CodeTag::kFunction;
    Compiler::InstallInterpreterTrampolineCopy(isolate_, sfi, log_tag);
  }
}
#endif  // V8_OS_WIN && V8_ENABLE_ETW_STACK_WALKING

void V8FileLogger::LogCodeObjects() { existing_code_logger_.LogCodeObjects(); }

void V8FileLogger::LogExistingFunction(Handle<SharedFunctionInfo> shared,
                                       Handle<AbstractCode> code) {
  existing_code_logger_.LogExistingFunction(shared, code);
}

void V8FileLogger::LogCompiledFunctions(
    bool ensure_source_positions_available) {
  existing_code_logger_.LogCompiledFunctions(ensure_source_positions_available);
}

void V8FileLogger::LogBuiltins() { existing_code_logger_.LogBuiltins(); }

void V8FileLogger::LogAccessorCallbacks() {
  Heap* heap = isolate_->heap();
  HeapObjectIterator iterator(heap);
  DisallowGarbageCollection no_gc;
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (!IsAccessorInfo(obj)) continue;
    Tagged<AccessorInfo> ai = Cast<AccessorInfo>(obj);
    if (!IsName(ai->name())) continue;
    Address getter_entry = ai->getter(isolate_);
    HandleScope scope(isolate_);
    Handle<Name> name(Cast<Name>(ai->name()), isolate_);
    if (getter_entry != kNullAddress) {
#if USES_FUNCTION_DESCRIPTORS
      getter_entry = *FUNCTION_ENTRYPOINT_ADDRESS(getter_entry);
#endif
      PROFILE(isolate_, GetterCallbackEvent(name, getter_entry));
    }
    Address setter_entry = ai->setter(isolate_);
    if (setter_entry != kNullAddress) {
#if USES_FUNCTION_DESCRIPTORS
      setter_entry = *FUNCTION_ENTRYPOINT_ADDRESS(setter_entry);
#endif
      PROFILE(isolate_, SetterCallbackEvent(name, setter_entry));
    }
  }
}

void V8FileLogger::LogAllMaps() {
  Heap* heap = isolate_->heap();
  CombinedHeapObjectIterator iterator(heap);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (!IsMap(obj)) continue;
    Tagged<Map> map = Cast<Map>(obj);
    MapCreate(map);
    MapDetails(map);
  }
}

static void AddIsolateIdIfNeeded(std::ostream& os, Isolate* isolate) {
  if (!v8_flags.logfile_per_isolate) return;
  os << "isolate-" << isolate << "-" << base::OS::GetCurrentProcessId() << "-";
}

static void PrepareLogFileName(std::ostream& os, Isolate* isolate,
                               const char* file_name) {
  int dir_separator_count = 0;
  for (const char* p = file_name; *p; p++) {
    if (base::OS::isDirectorySeparator(*p)) dir_separator_count++;
  }

  for (const char* p = file_name; *p; p++) {
    if (dir_separator_count == 0) {
      AddIsolateIdIfNeeded(os, isolate);
      dir_separator_count--;
    }
    if (*p == '%') {
      p++;
      switch (*p) {
        case '\0':
          // If there's a % at the end of the string we back up
          // one character so we can escape the loop properly.
          p--;
          break;
        case 'p':
          os << base::OS::GetCurrentProcessId();
          break;
        case 't':
          // %t expands to the current time in milliseconds.
          os << V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds();
          break;
        case '%':
          // %% expands (contracts really) to %.
          os << '%';
          break;
        default:
          // All other %'s expand to themselves.
          os << '%' << *p;
          break;
      }
    } else {
      if (base::OS::isDirectorySeparator(*p)) dir_separator_count--;
      os << *p;
    }
  }
}

bool V8FileLogger::SetUp(Isolate* isolate) {
  // Tests and EnsureInitialize() can call this twice in a row. It's harmless.
  if (is_initialized_) return true;
  is_initialized_ = true;

  std::ostringstream log_file_name;
  PrepareLogFileName(log_file_name, isolate, v8_flags.logfile);
  log_file_ = std::make_unique<LogFile>(this, log_file_name.str());

#if V8_OS_LINUX
  if (v8_flags.perf_basic_prof) {
    perf_basic_logger_ = std::make_unique<LinuxPerfBasicLogger>(isolate);
    CHECK(logger()->AddListener(perf_basic_logger_.get()));
  }

  if (v8_flags.perf_prof) {
    perf_jit_logger_ = std::make_unique<LinuxPerfJitLogger>(isolate);
    CHECK(logger()->AddListener(perf_jit_logger_.get()));
  }
#else
  static_assert(
      !v8_flags.perf_prof.value(),
      "--perf-prof should be statically disabled on non-Linux platforms");
  static_assert(
      !v8_flags.perf_basic_prof.value(),
      "--perf-basic-prof should be statically disabled on non-Linux platforms");
#endif

#ifdef ENABLE_GDB_JIT_INTERFACE
  if (v8_flags.gdbjit) {
    gdb_jit_logger_ =
        std::make_unique<JitLogger>(isolate, i::GDBJITInterface::EventHandler);
    CHECK(logger()->AddListener(gdb_jit_logger_.get()));
    CHECK(isolate->logger()->is_listening_to_code_events());
  }
#endif  // ENABLE_GDB_JIT_INTERFACE

  if (v8_flags.ll_prof) {
    ll_logger_ =
        std::make_unique<LowLevelLogger>(isolate, log_file_name.str().c_str());
    CHECK(logger()->AddListener(ll_logger_.get()));
  }
  ticker_ = std::make_unique<Ticker>(isolate, v8_flags.prof_sampling_interval);
  if (v8_flags.log) UpdateIsLogging(true);
  timer_.Start();
  if (v8_flags.prof_cpp) {
    CHECK(v8_flags.log);
    CHECK(is_logging());
    profiler_ = std::make_unique<Profiler>(isolate);
    profiler_->Engage();
  }
  if (is_logging_) {
    CHECK(logger()->AddListener(this));
  }
  return true;
}

void V8FileLogger::LateSetup(Isolate* isolate) {
  if (!isolate->logger()->is_listening_to_code_events()) return;
  Builtins::EmitCodeCreateEvents(isolate);
#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->EnableCodeLogging(isolate);
#endif
}

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
void V8FileLogger::SetEtwCodeEventHandler(uint32_t options) {
  DCHECK(v8_flags.enable_etw_stack_walking);
  isolate_->UpdateLogObjectRelocation();
#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->EnableCodeLogging(isolate_);
#endif  // V8_ENABLE_WEBASSEMBLY

  if (!etw_jit_logger_) {
    etw_jit_logger_ = std::make_unique<ETWJitLogger>(isolate_);
    CHECK(logger()->AddListener(etw_jit_logger_.get()));
    CHECK(logger()->is_listening_to_code_events());
    // Generate builtins for new isolates always. Otherwise it will not
    // traverse the builtins.
    options |= kJitCodeEventEnumExisting;
  }

  if (options & kJitCodeEventEnumExisting) {
    // TODO(v8:11043) Here we log the existing code to all the listeners
    // registered to this Isolate logger, while we should only log to the newly
    // created ETWJitLogger. This should not generally be a problem because it
    // is quite unlikely to have both file logger and ETW tracing both enabled
    // by default.
    HandleScope scope(isolate_);
    LogBuiltins();
    LogCodeObjects();
    LogCompiledFunctions(false);
    if (v8_flags.interpreted_frames_native_stack) {
      LogInterpretedFunctions();
    }
  }
}

void V8FileLogger::ResetEtwCodeEventHandler() {
  DCHECK(v8_flags.enable_etw_stack_walking);
  if (etw_jit_logger_) {
    CHECK(logger()->RemoveListener(etw_jit_logger_.get()));
    etw_jit_logger_.reset();
  }
}
#endif

void V8FileLogger::SetCodeEventHandler(uint32_t options,
                                       JitCodeEventHandler event_handler) {
  if (jit_logger_) {
    CHECK(logger()->RemoveListener(jit_logger_.get()));
    jit_logger_.reset();
    isolate_->UpdateLogObjectRelocation();
  }

  if (event_handler) {
#if V8_ENABLE_WEBASSEMBLY
    wasm::GetWasmEngine()->EnableCodeLogging(isolate_);
#endif  // V8_ENABLE_WEBASSEMBLY
    jit_logger_ = std::make_unique<JitLogger>(isolate_, event_handler);
    isolate_->UpdateLogObjectRelocation();
    CHECK(logger()->AddListener(jit_logger_.get()));
    if (options & kJitCodeEventEnumExisting) {
      HandleScope scope(isolate_);
      LogBuiltins();
      LogCodeObjects();
      LogCompiledFunctions();
    }
  }
}

sampler::Sampler* V8FileLogger::sampler() { return ticker_.get(); }
std::string V8FileLogger::file_name() const {
  return log_file_.get()->file_name();
}

void V8FileLogger::StopProfilerThread() {
  if (profiler_ != nullptr) {
    profiler_->Disengage();
    profiler_.reset();
  }
}

FILE* V8FileLogger::TearDownAndGetLogFile() {
  if (!is_initialized_) return nullptr;
  is_initialized_ = false;
  UpdateIsLogging(false);

  // Stop the profiler thread before closing the file.
  StopProfilerThread();

  ticker_.reset();
  timer_.Stop();

#if V8_OS_LINUX
  if (perf_basic_logger_) {
    CHECK(logger()->RemoveListener(perf_basic_logger_.get()));
    perf_basic_logger_.reset();
  }

  if (perf_jit_logger_) {
    CHECK(logger()->RemoveListener(perf_jit_logger_.get()));
    perf_jit_logger_.reset();
  }
#endif

  if (ll_logger_) {
    CHECK(logger()->RemoveListener(ll_logger_.get()));
    ll_logger_.reset();
  }

  if (jit_logger_) {
    CHECK(logger()->RemoveListener(jit_logger_.get()));
    jit_logger_.reset();
    isolate_->UpdateLogObjectRelocation();
  }

  return log_file_->Close();
}

Logger* V8FileLogger::logger() const { return isolate_->logger(); }

void V8FileLogger::UpdateIsLogging(bool value) {
  if (value) {
    isolate_->CollectSourcePositionsForAllBytecodeArrays();
  }
  {
    base::MutexGuard guard(log_file_->mutex());
    // Relaxed atomic to avoid locking the mutex for the most common case: when
    // logging is disabled.
    is_logging_.store(value, std::memory_order_relaxed);
  }
  isolate_->UpdateLogObjectRelocation();
}

void ExistingCodeLogger::LogCodeObject(Tagged<AbstractCode> object) {
  HandleScope scope(isolate_);
  Handle<AbstractCode> abstract_code(object, isolate_);
  CodeTag tag = CodeTag::kStub;
  const char* description = "Unknown code from before profiling";
  PtrComprCageBase cage_base(isolate_);
  switch (abstract_code->kind(cage_base)) {
    case CodeKind::INTERPRETED_FUNCTION:
    case CodeKind::TURBOFAN_JS:
    case CodeKind::BASELINE:
    case CodeKind::MAGLEV:
      return;  // We log this later using LogCompiledFunctions.
    case CodeKind::FOR_TESTING:
      description = "STUB code";
      tag = CodeTag::kStub;
      break;
    case CodeKind::REGEXP:
      description = "Regular expression code";
      tag = CodeTag::kRegExp;
      break;
    case CodeKind::BYTECODE_HANDLER:
      description =
          isolate_->builtins()->name(abstract_code->builtin_id(cage_base));
      tag = CodeTag::kBytecodeHandler;
      break;
    case CodeKind::BUILTIN:
      if (abstract_code->has_instruction_stream(cage_base)) {
        DCHECK_EQ(abstract_code->builtin_id(cage_base),
                  Builtin::kInterpreterEntryTrampoline);
        // We treat interpreter trampoline builtin copies as
        // INTERPRETED_FUNCTION, which are logged using LogCompiledFunctions.
        return;
      }
      description = Builtins::name(abstract_code->builtin_id(cage_base));
      tag = CodeTag::kBuiltin;
      break;
    case CodeKind::WASM_FUNCTION:
      description = "A Wasm function";
      tag = CodeTag::kFunction;
      break;
    case CodeKind::JS_TO_WASM_FUNCTION:
      description = "A JavaScript to Wasm adapter";
      tag = CodeTag::kStub;
      break;
    case CodeKind::WASM_TO_CAPI_FUNCTION:
      description = "A Wasm to C-API adapter";
      tag = CodeTag::kStub;
      break;
    case CodeKind::WASM_TO_JS_FUNCTION:
      description = "A Wasm to JavaScript adapter";
      tag = CodeTag::kStub;
      break;
    case CodeKind::C_WASM_ENTRY:
      description = "A C to Wasm entry stub";
      tag = CodeTag::kStub;
      break;
  }
  CALL_CODE_EVENT_HANDLER(CodeCreateEvent(tag, abstract_code, description))
}

void ExistingCodeLogger::LogCodeObjects() {
  Heap* heap = isolate_->heap();
  CombinedHeapObjectIterator iterator(heap);
  DisallowGarbageCollection no_gc;
  PtrComprCageBase cage_base(isolate_);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    InstanceType instance_type = obj->map(cage_base)->instance_type();
    if (InstanceTypeChecker::IsCode(instance_type) ||
        InstanceTypeChecker::IsBytecodeArray(instance_type)) {
      LogCodeObject(Cast<AbstractCode>(obj));
    }
  }
}

void ExistingCodeLogger::LogBuiltins() {
  DCHECK(isolate_->builtins()->is_initialized());
  // The main "copy" of used builtins are logged by LogCodeObjects() while
  // iterating Code objects.
  // TODO(v8:11880): Log other copies of remapped builtins once we
  // decide to remap them multiple times into the code range (for example
  // for arm64).
}

void ExistingCodeLogger::LogCompiledFunctions(
    bool ensure_source_positions_available) {
  Heap* heap = isolate_->heap();
  HandleScope scope(isolate_);
  std::vector<std::pair<Handle<SharedFunctionInfo>, Handle<AbstractCode>>>
      compiled_funcs = EnumerateCompiledFunctions(heap);

  // During iteration, there can be heap allocation due to
  // GetScriptLineNumber call.
  for (auto& pair : compiled_funcs) {
    Handle<SharedFunctionInfo> shared = pair.first;

    // If the script is a Smi, then the SharedFunctionInfo is in
    // the process of being deserialized.
    Tagged<Object> script = shared->raw_script(kAcquireLoad);
    if (IsSmi(script)) {
      DCHECK_EQ(script, Smi::uninitialized_deserialization_value());
      continue;
    }

    if (ensure_source_positions_available) {
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate_, shared);
    }
    if (shared->HasInterpreterData(isolate_)) {
      LogExistingFunction(
          shared,
          Handle<AbstractCode>(
              Cast<AbstractCode>(shared->InterpreterTrampoline(isolate_)),
              isolate_));
    }
    if (shared->HasBaselineCode()) {
      LogExistingFunction(
          shared, Handle<AbstractCode>(
                      Cast<AbstractCode>(shared->baseline_code(kAcquireLoad)),
                      isolate_));
    }
    // TODO(saelo): remove the "!IsTrustedSpaceObject" once builtin Code
    // objects are also in trusted space. Currently this breaks because we must
    // not compare objects in trusted space with ones inside the sandbox.
    static_assert(!kAllCodeObjectsLiveInTrustedSpace);
    if (!HeapLayout::InTrustedSpace(*pair.second) &&
        pair.second.is_identical_to(BUILTIN_CODE(isolate_, CompileLazy))) {
      continue;
    }
    LogExistingFunction(pair.first, pair.second);
  }

#if V8_ENABLE_WEBASSEMBLY
  HeapObjectIterator iterator(heap);
  DisallowGarbageCollection no_gc;

  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (!IsWasmModuleObject(obj)) continue;
    auto module_object = Cast<WasmModuleObject>(obj);
    module_object->native_module()->LogWasmCodes(isolate_,
                                                 module_object->script());
  }
  wasm::GetWasmImportWrapperCache()->LogForIsolate(isolate_);
#endif  // V8_ENABLE_WEBASSEMBLY
}

void ExistingCodeLogger::LogExistingFunction(Handle<SharedFunctionInfo> shared,
                                             Handle<AbstractCode> code,
                                             CodeTag tag) {
  if (IsScript(shared->script())) {
    DirectHandle<Script> script(Cast<Script>(shared->script()), isolate_);
    Script::PositionInfo info;
    Script::GetPositionInfo(script, shared->StartPosition(), &info);
    int line_num = info.line + 1;
    int column_num = info.column + 1;
    if (IsString(script->name())) {
      Handle<String> script_name(Cast<String>(script->name()), isolate_);
      if (!shared->is_toplevel()) {
        CALL_CODE_EVENT_HANDLER(
            CodeCreateEvent(V8FileLogger::ToNativeByScript(tag, *script), code,
                            shared, script_name, line_num, column_num))
      } else {
        // Can't distinguish eval and script here, so always use Script.
        CALL_CODE_EVENT_HANDLER(CodeCreateEvent(
            V8FileLogger::ToNativeByScript(CodeTag::kScript, *script), code,
            shared, script_name))
      }
    } else {
      CALL_CODE_EVENT_HANDLER(CodeCreateEvent(
          V8FileLogger::ToNativeByScript(tag, *script), code, shared,
          ReadOnlyRoots(isolate_).empty_string_handle(), line_num, column_num))
    }
  } else if (shared->IsApiFunction()) {
    // API function.
    DirectHandle<FunctionTemplateInfo> fun_data(shared->api_func_data(),
                                                isolate_);
    if (fun_data->has_callback(isolate_)) {
      Address entry_point = fun_data->callback(isolate_);
#if USES_FUNCTION_DESCRIPTORS
      entry_point = *FUNCTION_ENTRYPOINT_ADDRESS(entry_point);
#endif
      Handle<String> fun_name = SharedFunctionInfo::DebugName(isolate_, shared);
      CALL_CODE_EVENT_HANDLER(CallbackEvent(fun_name, entry_point))

      // Fast API function.
      int c_functions_count = fun_data->GetCFunctionsCount();
      for (int i = 0; i < c_functions_count; i++) {
        CALL_CODE_EVENT_HANDLER(
            CallbackEvent(fun_name, fun_data->GetCFunction(isolate_, i)))
      }
    }
#if V8_ENABLE_WEBASSEMBLY
  } else if (shared->HasWasmJSFunctionData()) {
    CALL_CODE_EVENT_HANDLER(
        CodeCreateEvent(CodeTag::kFunction, code, "wasm-to-js"));
#endif  // V8_ENABLE_WEBASSEMBLY
  }
}

#undef CALL_CODE_EVENT_HANDLER
#undef MSG_BUILDER

}  // namespace internal
}  // namespace v8
```