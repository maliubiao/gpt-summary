Response: The user wants a summary of the C++ source code file `v8/src/codegen/compiler.cc`. This is the third part of a three-part summary request.

Based on the code provided, here's a breakdown of its functionality:

1. **Compilation from Strings (Eval):**  Deals with compiling JavaScript code provided as strings (like in `eval()` or `Function()` constructors). This includes:
    *   **Caching:**  Looking up and storing compiled code in a cache to avoid recompilation.
    *   **Source Validation:**  Checking with the embedder (the application using V8) if code generation from strings is allowed.
    *   **Error Handling:** Throwing `EvalError` if the source is not a string.

2. **Script Compilation Management:** Handles the overall process of compiling JavaScript scripts, including:
    *   **Caching Strategies:** Implementing different caching behaviors (e.g., isolate cache, code cache from embedder).
    *   **Background Compilation:**  Supporting compiling scripts on background threads to improve performance.
    *   **Streaming Compilation:**  Handling scripts that are being loaded in chunks (streaming).
    *   **Compilation Hints:**  Supporting hints to the compiler for optimization.

3. **SharedFunctionInfo Management:**  Deals with `SharedFunctionInfo`, an object that holds information shared between different instances of the same function. This includes:
    *   **Lookup:** Finding existing `SharedFunctionInfo` for a given function literal.
    *   **Creation:** Creating new `SharedFunctionInfo` objects.

4. **Optimized Compilation (OSR and Turbofan/Maglev):** Manages the process of optimizing functions, including:
    *   **On-Stack Replacement (OSR):**  Optimizing a function while it's already running.
    *   **Turbofan and Maglev Compilation Jobs:**  Managing the asynchronous compilation processes for these optimizers.
    *   **Finalization:**  Handling the completion of optimization jobs and updating the function with the optimized code.

5. **Post-Instantiation:**  Actions taken after a function object is created, such as:
    *   **Feedback Cell Initialization:** Setting up feedback mechanisms for optimization.
    *   **Debugger Integration:**  Notifying the debugger about compiled scripts.
    *   **Tracing:**  Emitting trace events related to script compilation.

6. **Script Streaming Data:**  A helper class for managing data related to streaming compilation.

**Relationship to JavaScript:**

This code is crucial for V8's ability to execute JavaScript. It directly translates JavaScript source code into executable code. The `eval()` and `Function()` examples demonstrate the explicit connection, but the script compilation mechanisms underpin the execution of all JavaScript code.
这是 `v8/src/codegen/compiler.cc` 源代码文件的第三部分，主要功能是**管理和执行 JavaScript 代码的编译过程，包括从字符串编译、脚本编译、以及优化编译等关键环节。** 它与 JavaScript 的功能有着直接且核心的联系，因为它负责将 JavaScript 代码转换为 V8 引擎可以执行的机器码或字节码。

以下是这部分代码功能的归纳，并用 JavaScript 例子说明其关联：

**主要功能归纳：**

1. **从字符串编译 (Eval 和 Function)**：
    *   **`GetFunctionFromEval`**:  处理 `eval()` 调用和 `Function()` 构造函数，将字符串形式的 JavaScript 代码编译成可执行的 `JSFunction` 对象。这部分涉及编译缓存，用于加速重复的 `eval` 调用。
    *   **`GetFunctionFromString` 和 `GetFunctionFromValidatedString`**:  用于从经过验证的字符串源代码创建函数，用于动态代码生成场景。
    *   **`ValidateDynamicCompilationSource`**:  与嵌入器（例如 Chrome 浏览器）交互，检查是否允许从字符串生成代码，并可能允许嵌入器修改源代码。

2. **脚本编译管理 (Script Compilation)**：
    *   **`GetSharedFunctionInfoForScript*` 系列函数**:  负责编译完整的 JavaScript 脚本文件或代码块。这些函数处理编译选项、缓存策略（如内存缓存、持久化缓存）、扩展脚本、以及后台编译等。
    *   **`ScriptCompileTimerScope`**:  用于测量脚本编译的各个阶段所花费的时间，并记录缓存行为。
    *   **后台编译 (`CompileScriptOnBothBackgroundAndMainThread`)**: 利用多线程并行编译，提高编译效率。
    *   **流式编译 (`GetSharedFunctionInfoForStreamedScript`)**:  处理边下载边编译的场景，优化加载体验。
    *   **编译缓存 (`CompilationCache`)**:  查找和存储编译结果，避免重复编译。

3. **优化编译管理 (Optimized Compilation)**：
    *   **`CompileOptimizedOSR`**:  处理 On-Stack Replacement (OSR)，即在函数执行过程中进行优化。
    *   **`DisposeTurbofanCompilationJob` 和 `FinalizeTurbofanCompilationJob`**:  管理 Turbofan 优化编译任务的生命周期，包括任务完成后的代码安装。
    *   **`DisposeMaglevCompilationJob` 和 `FinalizeMaglevCompilationJob`**:  管理 Maglev 优化编译任务的生命周期。

4. **`SharedFunctionInfo` 的获取和管理**：
    *   **`GetSharedFunctionInfo(FunctionLiteral*, ...)`**:  为函数字面量创建或获取 `SharedFunctionInfo` 对象，这是函数共享信息的关键载体。

5. **函数实例化后的处理 (`PostInstantiation`)**：
    *   在 `JSFunction` 对象创建后执行一些必要的初始化操作，例如初始化反馈槽 (feedback cell)，并可能触发即时编译 (always-turbofan)。

6. **代码生成权限控制**:
    *   **`ModifyCodeGenerationFromStrings`**: 允许嵌入器在代码生成前修改或阻止字符串形式的代码。

7. **调试和性能追踪**:
    *   集成调试器功能，在编译完成后通知调试器。
    *   使用 tracing 机制记录编译相关的事件，用于性能分析和监控。

**与 JavaScript 功能的关联及 JavaScript 例子：**

1. **`eval()` 和 `Function()`**:  `GetFunctionFromEval` 直接关联到 JavaScript 的动态代码执行能力。

    ```javascript
    let code = 'function add(a, b) { return a + b; }';
    let compiledFunction = eval(code);
    console.log(compiledFunction(2, 3)); // 输出 5

    let dynamicAdd = new Function('a', 'b', 'return a + b;');
    console.log(dynamicAdd(5, 2)); // 输出 7
    ```

2. **脚本加载和执行**: `GetSharedFunctionInfoForScript*` 系列函数在浏览器加载 `<script>` 标签或者在 Node.js 中 `require()` 模块时被调用。

    ```html
    <script src="my_script.js"></script>
    ```

    ```javascript
    // my_script.js
    function greet(name) {
      console.log('Hello, ' + name + '!');
    }
    greet('World');
    ```

3. **代码优化**: `CompileOptimizedOSR`, `FinalizeTurbofanCompilationJob`, 和 `FinalizeMaglevCompilationJob` 影响 JavaScript 代码的运行时性能。V8 会根据代码的执行情况，选择性地将热点代码优化为更高效的机器码。

    ```javascript
    function counter() {
      let count = 0;
      for (let i = 0; i < 10000; i++) {
        count++;
      }
      return count;
    }

    // 多次调用 counter() 函数后，V8 可能会对其进行优化。
    for (let j = 0; j < 5; j++) {
      console.log(counter());
    }
    ```

4. **模块加载**: 涉及 `GetSharedFunctionInfoForScript` 处理模块 (`<script type="module">` 或 ES 模块)。

    ```html
    <script type="module">
      import { myFunc } from './my_module.js';
      myFunc();
    </script>
    ```

    ```javascript
    // my_module.js
    export function myFunc() {
      console.log('Hello from module!');
    }
    ```

5. **嵌入式环境控制**: `ModifyCodeGenerationFromStrings` 允许宿主环境对动态代码生成进行干预，例如浏览器可以阻止执行来自某些来源的 `eval` 代码。

总而言之，这部分 `compiler.cc` 代码是 V8 引擎编译 JavaScript 代码的核心组成部分，它直接决定了 JavaScript 代码如何被解析、优化并最终执行。从最简单的 `eval` 到复杂的模块加载和运行时优化，都离不开这部分代码的处理。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
isolate, &is_compiled_scope);
}

// static
MaybeHandle<JSFunction> Compiler::GetFunctionFromEval(
    Handle<String> source, Handle<SharedFunctionInfo> outer_info,
    Handle<Context> context, LanguageMode language_mode,
    ParseRestriction restriction, int parameters_end_pos, int eval_position,
    ParsingWhileDebugging parsing_while_debugging) {
  Isolate* isolate = context->GetIsolate();

  // The cache lookup key needs to be aware of the separation between the
  // parameters and the body to prevent this valid invocation:
  //   Function("", "function anonymous(\n/**/) {\n}");
  // from adding an entry that falsely approves this invalid invocation:
  //   Function("\n/**/) {\nfunction anonymous(", "}");
  // The actual eval_position for indirect eval and CreateDynamicFunction
  // is unused (just 0), which means it's an available field to use to indicate
  // this separation. But to make sure we're not causing other false hits, we
  // negate the scope position.
  int eval_cache_position = eval_position;
  if (restriction == ONLY_SINGLE_FUNCTION_LITERAL &&
      parameters_end_pos != kNoSourcePosition) {
    // use the parameters_end_pos as the eval_position in the eval cache.
    DCHECK_EQ(eval_position, kNoSourcePosition);
    eval_cache_position = -parameters_end_pos;
  }
  CompilationCache* compilation_cache = isolate->compilation_cache();
  InfoCellPair eval_result = compilation_cache->LookupEval(
      source, outer_info, context, language_mode, eval_cache_position);
  Handle<FeedbackCell> feedback_cell;
  if (eval_result.has_feedback_cell()) {
    feedback_cell = handle(eval_result.feedback_cell(), isolate);
  }

  Handle<SharedFunctionInfo> shared_info;
  Handle<Script> script;
  IsCompiledScope is_compiled_scope;
  bool allow_eval_cache;
  if (eval_result.has_shared()) {
    shared_info = Handle<SharedFunctionInfo>(eval_result.shared(), isolate);
    script = Handle<Script>(Cast<Script>(shared_info->script()), isolate);
    is_compiled_scope = shared_info->is_compiled_scope(isolate);
    allow_eval_cache = true;
  } else {
    UnoptimizedCompileFlags flags = UnoptimizedCompileFlags::ForToplevelCompile(
        isolate, true, language_mode, REPLMode::kNo, ScriptType::kClassic,
        v8_flags.lazy_eval);
    flags.set_is_eval(true);
    flags.set_parsing_while_debugging(parsing_while_debugging);
    DCHECK(!flags.is_module());
    flags.set_parse_restriction(restriction);

    UnoptimizedCompileState compile_state;
    ReusableUnoptimizedCompileState reusable_state(isolate);
    ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);
    parse_info.set_parameters_end_pos(parameters_end_pos);

    MaybeHandle<ScopeInfo> maybe_outer_scope_info;
    if (!IsNativeContext(*context)) {
      maybe_outer_scope_info = handle(context->scope_info(), isolate);
    }
    script = parse_info.CreateScript(
        isolate, source, kNullMaybeHandle,
        OriginOptionsForEval(outer_info->script(), parsing_while_debugging));
    script->set_eval_from_shared(*outer_info);
    if (eval_position == kNoSourcePosition) {
      // If the position is missing, attempt to get the code offset by
      // walking the stack. Do not translate the code offset into source
      // position, but store it as negative value for lazy translation.
      DebuggableStackFrameIterator it(isolate);
      if (!it.done() && it.is_javascript()) {
        FrameSummary summary = it.GetTopValidFrame();
        script->set_eval_from_shared(
            summary.AsJavaScript().function()->shared());
        script->set_origin_options(
            OriginOptionsForEval(*summary.script(), parsing_while_debugging));
        eval_position = -summary.code_offset();
      } else {
        eval_position = 0;
      }
    }
    script->set_eval_from_position(eval_position);

    if (!v8::internal::CompileToplevel(&parse_info, script,
                                       maybe_outer_scope_info, isolate,
                                       &is_compiled_scope)
             .ToHandle(&shared_info)) {
      return MaybeHandle<JSFunction>();
    }
    allow_eval_cache = parse_info.allow_eval_cache();
  }

  // If caller is strict mode, the result must be in strict mode as well.
  DCHECK(is_sloppy(language_mode) || is_strict(shared_info->language_mode()));

  Handle<JSFunction> result;
  if (eval_result.has_shared()) {
    if (eval_result.has_feedback_cell()) {
      result = Factory::JSFunctionBuilder{isolate, shared_info, context}
                   .set_feedback_cell(feedback_cell)
                   .set_allocation_type(AllocationType::kYoung)
                   .Build();
    } else {
      result = Factory::JSFunctionBuilder{isolate, shared_info, context}
                   .set_allocation_type(AllocationType::kYoung)
                   .Build();
      // TODO(mythria): I don't think we need this here. PostInstantiation
      // already initializes feedback cell.
      JSFunction::InitializeFeedbackCell(result, &is_compiled_scope, true);
      if (allow_eval_cache) {
        // Make sure to cache this result.
        DirectHandle<FeedbackCell> new_feedback_cell(
            result->raw_feedback_cell(), isolate);
        compilation_cache->PutEval(source, outer_info, context, shared_info,
                                   new_feedback_cell, eval_cache_position);
      }
    }
  } else {
    result = Factory::JSFunctionBuilder{isolate, shared_info, context}
                 .set_allocation_type(AllocationType::kYoung)
                 .Build();
    // TODO(mythria): I don't think we need this here. PostInstantiation
    // already initializes feedback cell.
    JSFunction::InitializeFeedbackCell(result, &is_compiled_scope, true);
    if (allow_eval_cache) {
      // Add the SharedFunctionInfo and the LiteralsArray to the eval cache if
      // we didn't retrieve from there.
      DirectHandle<FeedbackCell> new_feedback_cell(result->raw_feedback_cell(),
                                                   isolate);
      compilation_cache->PutEval(source, outer_info, context, shared_info,
                                 new_feedback_cell, eval_cache_position);
    }
  }
  CHECK(is_compiled_scope.is_compiled());

  return result;
}

// Check whether embedder allows code generation in this context.
// (via v8::Isolate::SetModifyCodeGenerationFromStringsCallback)
bool ModifyCodeGenerationFromStrings(Isolate* isolate,
                                     Handle<NativeContext> context,
                                     Handle<i::Object>* source,
                                     bool is_code_like) {
  DCHECK(isolate->modify_code_gen_callback());
  DCHECK(source);

  // Callback set. Run it, and use the return value as source, or block
  // execution if it's not set.
  VMState<EXTERNAL> state(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCodeGenerationFromStringsCallbacks);
  ModifyCodeGenerationFromStringsResult result =
      isolate->modify_code_gen_callback()(v8::Utils::ToLocal(context),
                                          v8::Utils::ToLocal(*source),
                                          is_code_like);
  if (result.codegen_allowed && !result.modified_source.IsEmpty()) {
    // Use the new source (which might be the same as the old source).
    *source =
        Utils::OpenHandle(*result.modified_source.ToLocalChecked(), false);
  }
  return result.codegen_allowed;
}

// Run Embedder-mandated checks before generating code from a string.
//
// Returns a string to be used for compilation, or a flag that an object type
// was encountered that is neither a string, nor something the embedder knows
// how to handle.
//
// Returns: (assuming: std::tie(source, unknown_object))
// - !source.is_null(): compilation allowed, source contains the source string.
// - unknown_object is true: compilation allowed, but we don't know how to
//                           deal with source_object.
// - source.is_null() && !unknown_object: compilation should be blocked.
//
// - !source_is_null() and unknown_object can't be true at the same time.

// static
std::pair<MaybeHandle<String>, bool> Compiler::ValidateDynamicCompilationSource(
    Isolate* isolate, Handle<NativeContext> context,
    Handle<i::Object> original_source, bool is_code_like) {
  // Check if the context unconditionally allows code gen from strings.
  // allow_code_gen_from_strings can be many things, so we'll always check
  // against the 'false' literal, so that e.g. undefined and 'true' are treated
  // the same.
  if (!IsFalse(context->allow_code_gen_from_strings(), isolate) &&
      IsString(*original_source)) {
    return {Cast<String>(original_source), false};
  }

  // Check if the context wants to block or modify this source object.
  // Double-check that we really have a string now.
  // (Let modify_code_gen_callback decide, if it's been set.)
  if (isolate->modify_code_gen_callback()) {
    Handle<i::Object> modified_source = original_source;
    if (!ModifyCodeGenerationFromStrings(isolate, context, &modified_source,
                                         is_code_like)) {
      return {MaybeHandle<String>(), false};
    }
    if (!IsString(*modified_source)) {
      return {MaybeHandle<String>(), true};
    }
    return {Cast<String>(modified_source), false};
  }

  if (!IsFalse(context->allow_code_gen_from_strings(), isolate) &&
      Object::IsCodeLike(*original_source, isolate)) {
    // Codegen is unconditionally allowed, and we're been given a CodeLike
    // object. Stringify.
    MaybeHandle<String> stringified_source =
        Object::ToString(isolate, original_source);
    return {stringified_source, stringified_source.is_null()};
  }

  // If unconditional codegen was disabled, and no callback defined, we block
  // strings and allow all other objects.
  return {MaybeHandle<String>(), !IsString(*original_source)};
}

// static
MaybeHandle<JSFunction> Compiler::GetFunctionFromValidatedString(
    Handle<NativeContext> native_context, MaybeHandle<String> source,
    ParseRestriction restriction, int parameters_end_pos) {
  Isolate* const isolate = native_context->GetIsolate();

  // Raise an EvalError if we did not receive a string.
  if (source.is_null()) {
    Handle<Object> error_message =
        native_context->ErrorMessageForCodeGenerationFromStrings();
    THROW_NEW_ERROR(isolate, NewEvalError(MessageTemplate::kCodeGenFromStrings,
                                          error_message));
  }

  // Compile source string in the native context.
  int eval_position = kNoSourcePosition;
  Handle<SharedFunctionInfo> outer_info(
      native_context->empty_function()->shared(), isolate);
  return Compiler::GetFunctionFromEval(
      source.ToHandleChecked(), outer_info, native_context,
      LanguageMode::kSloppy, restriction, parameters_end_pos, eval_position);
}

// static
MaybeHandle<JSFunction> Compiler::GetFunctionFromString(
    Handle<NativeContext> context, Handle<Object> source,
    int parameters_end_pos, bool is_code_like) {
  Isolate* const isolate = context->GetIsolate();
  MaybeHandle<String> validated_source =
      ValidateDynamicCompilationSource(isolate, context, source, is_code_like)
          .first;
  return GetFunctionFromValidatedString(context, validated_source,
                                        ONLY_SINGLE_FUNCTION_LITERAL,
                                        parameters_end_pos);
}

namespace {

struct ScriptCompileTimerScope {
 public:
  // TODO(leszeks): There are too many blink-specific entries in this enum,
  // figure out a way to push produce/hit-isolate-cache/consume/consume-failed
  // back up the API and log them in blink instead.
  enum class CacheBehaviour {
    kProduceCodeCache,
    kHitIsolateCacheWhenNoCache,
    kConsumeCodeCache,
    kConsumeCodeCacheFailed,
    kNoCacheBecauseInlineScript,
    kNoCacheBecauseScriptTooSmall,
    kNoCacheBecauseCacheTooCold,
    kNoCacheNoReason,
    kNoCacheBecauseNoResource,
    kNoCacheBecauseInspector,
    kNoCacheBecauseCachingDisabled,
    kNoCacheBecauseModule,
    kNoCacheBecauseStreamingSource,
    kNoCacheBecauseV8Extension,
    kHitIsolateCacheWhenProduceCodeCache,
    kHitIsolateCacheWhenConsumeCodeCache,
    kNoCacheBecauseExtensionModule,
    kNoCacheBecausePacScript,
    kNoCacheBecauseInDocumentWrite,
    kNoCacheBecauseResourceWithNoCacheHandler,
    kHitIsolateCacheWhenStreamingSource,
    kCount
  };

  ScriptCompileTimerScope(
      Isolate* isolate, ScriptCompiler::NoCacheReason no_cache_reason,
      ScriptCompiler::CompilationDetails* compilation_details)
      : isolate_(isolate),
        histogram_scope_(&compilation_details->foreground_time_in_microseconds),
        all_scripts_histogram_scope_(isolate->counters()->compile_script()),
        no_cache_reason_(no_cache_reason),
        hit_isolate_cache_(false),
        consuming_code_cache_(false),
        consuming_code_cache_failed_(false) {}

  ~ScriptCompileTimerScope() {
    CacheBehaviour cache_behaviour = GetCacheBehaviour();

    Histogram* cache_behaviour_histogram =
        isolate_->counters()->compile_script_cache_behaviour();
    // Sanity check that the histogram has exactly one bin per enum entry.
    DCHECK_EQ(0, cache_behaviour_histogram->min());
    DCHECK_EQ(static_cast<int>(CacheBehaviour::kCount),
              cache_behaviour_histogram->max() + 1);
    DCHECK_EQ(static_cast<int>(CacheBehaviour::kCount),
              cache_behaviour_histogram->num_buckets());
    cache_behaviour_histogram->AddSample(static_cast<int>(cache_behaviour));

    histogram_scope_.set_histogram(
        GetCacheBehaviourTimedHistogram(cache_behaviour));
  }

  void set_hit_isolate_cache() { hit_isolate_cache_ = true; }

  void set_consuming_code_cache() { consuming_code_cache_ = true; }

  void set_consuming_code_cache_failed() {
    consuming_code_cache_failed_ = true;
  }

 private:
  Isolate* isolate_;
  LazyTimedHistogramScope histogram_scope_;
  // TODO(leszeks): This timer is the sum of the other times, consider removing
  // it to save space.
  NestedTimedHistogramScope all_scripts_histogram_scope_;
  ScriptCompiler::NoCacheReason no_cache_reason_;
  bool hit_isolate_cache_;
  bool consuming_code_cache_;
  bool consuming_code_cache_failed_;

  CacheBehaviour GetCacheBehaviour() {
    if (consuming_code_cache_) {
      if (hit_isolate_cache_) {
        return CacheBehaviour::kHitIsolateCacheWhenConsumeCodeCache;
      } else if (consuming_code_cache_failed_) {
        return CacheBehaviour::kConsumeCodeCacheFailed;
      }
      return CacheBehaviour::kConsumeCodeCache;
    }

    if (hit_isolate_cache_) {
      // A roundabout way of knowing the embedder is going to produce a code
      // cache (which is done by a separate API call later) is to check whether
      // no_cache_reason_ is
      // ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache.
      if (no_cache_reason_ ==
          ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache) {
        return CacheBehaviour::kHitIsolateCacheWhenProduceCodeCache;
      } else if (no_cache_reason_ ==
                 ScriptCompiler::kNoCacheBecauseStreamingSource) {
        return CacheBehaviour::kHitIsolateCacheWhenStreamingSource;
      }
      return CacheBehaviour::kHitIsolateCacheWhenNoCache;
    }

    switch (no_cache_reason_) {
      case ScriptCompiler::kNoCacheBecauseInlineScript:
        return CacheBehaviour::kNoCacheBecauseInlineScript;
      case ScriptCompiler::kNoCacheBecauseScriptTooSmall:
        return CacheBehaviour::kNoCacheBecauseScriptTooSmall;
      case ScriptCompiler::kNoCacheBecauseCacheTooCold:
        return CacheBehaviour::kNoCacheBecauseCacheTooCold;
      case ScriptCompiler::kNoCacheNoReason:
        return CacheBehaviour::kNoCacheNoReason;
      case ScriptCompiler::kNoCacheBecauseNoResource:
        return CacheBehaviour::kNoCacheBecauseNoResource;
      case ScriptCompiler::kNoCacheBecauseInspector:
        return CacheBehaviour::kNoCacheBecauseInspector;
      case ScriptCompiler::kNoCacheBecauseCachingDisabled:
        return CacheBehaviour::kNoCacheBecauseCachingDisabled;
      case ScriptCompiler::kNoCacheBecauseModule:
        return CacheBehaviour::kNoCacheBecauseModule;
      case ScriptCompiler::kNoCacheBecauseStreamingSource:
        return CacheBehaviour::kNoCacheBecauseStreamingSource;
      case ScriptCompiler::kNoCacheBecauseV8Extension:
        return CacheBehaviour::kNoCacheBecauseV8Extension;
      case ScriptCompiler::kNoCacheBecauseExtensionModule:
        return CacheBehaviour::kNoCacheBecauseExtensionModule;
      case ScriptCompiler::kNoCacheBecausePacScript:
        return CacheBehaviour::kNoCacheBecausePacScript;
      case ScriptCompiler::kNoCacheBecauseInDocumentWrite:
        return CacheBehaviour::kNoCacheBecauseInDocumentWrite;
      case ScriptCompiler::kNoCacheBecauseResourceWithNoCacheHandler:
        return CacheBehaviour::kNoCacheBecauseResourceWithNoCacheHandler;
      case ScriptCompiler::kNoCacheBecauseDeferredProduceCodeCache:
        return CacheBehaviour::kProduceCodeCache;
      }
    UNREACHABLE();
  }

  TimedHistogram* GetCacheBehaviourTimedHistogram(
      CacheBehaviour cache_behaviour) {
    switch (cache_behaviour) {
      case CacheBehaviour::kProduceCodeCache:
      // Even if we hit the isolate's compilation cache, we currently recompile
      // when we want to produce the code cache.
      case CacheBehaviour::kHitIsolateCacheWhenProduceCodeCache:
        return isolate_->counters()->compile_script_with_produce_cache();
      case CacheBehaviour::kHitIsolateCacheWhenNoCache:
      case CacheBehaviour::kHitIsolateCacheWhenConsumeCodeCache:
      case CacheBehaviour::kHitIsolateCacheWhenStreamingSource:
        return isolate_->counters()->compile_script_with_isolate_cache_hit();
      case CacheBehaviour::kConsumeCodeCacheFailed:
        return isolate_->counters()->compile_script_consume_failed();
      case CacheBehaviour::kConsumeCodeCache:
        return isolate_->counters()->compile_script_with_consume_cache();

      // Note that this only counts the finalization part of streaming, the
      // actual streaming compile is counted by BackgroundCompileTask into
      // "compile_script_on_background".
      case CacheBehaviour::kNoCacheBecauseStreamingSource:
        return isolate_->counters()->compile_script_streaming_finalization();

      case CacheBehaviour::kNoCacheBecauseInlineScript:
        return isolate_->counters()
            ->compile_script_no_cache_because_inline_script();
      case CacheBehaviour::kNoCacheBecauseScriptTooSmall:
        return isolate_->counters()
            ->compile_script_no_cache_because_script_too_small();
      case CacheBehaviour::kNoCacheBecauseCacheTooCold:
        return isolate_->counters()
            ->compile_script_no_cache_because_cache_too_cold();

      // Aggregate all the other "no cache" counters into a single histogram, to
      // save space.
      case CacheBehaviour::kNoCacheNoReason:
      case CacheBehaviour::kNoCacheBecauseNoResource:
      case CacheBehaviour::kNoCacheBecauseInspector:
      case CacheBehaviour::kNoCacheBecauseCachingDisabled:
      // TODO(leszeks): Consider counting separately once modules are more
      // common.
      case CacheBehaviour::kNoCacheBecauseModule:
      case CacheBehaviour::kNoCacheBecauseV8Extension:
      case CacheBehaviour::kNoCacheBecauseExtensionModule:
      case CacheBehaviour::kNoCacheBecausePacScript:
      case CacheBehaviour::kNoCacheBecauseInDocumentWrite:
      case CacheBehaviour::kNoCacheBecauseResourceWithNoCacheHandler:
        return isolate_->counters()->compile_script_no_cache_other();

      case CacheBehaviour::kCount:
        UNREACHABLE();
    }
    UNREACHABLE();
  }
};

Handle<Script> NewScript(Isolate* isolate, ParseInfo* parse_info,
                         Handle<String> source, ScriptDetails script_details,
                         NativesFlag natives) {
  // Create a script object describing the script to be compiled.
  Handle<Script> script = parse_info->CreateScript(
      isolate, source, script_details.wrapped_arguments,
      script_details.origin_options, natives);
  DisallowGarbageCollection no_gc;
  SetScriptFieldsFromDetails(isolate, *script, script_details, &no_gc);
  LOG(isolate, ScriptDetails(*script));
  return script;
}

MaybeHandle<SharedFunctionInfo> CompileScriptOnMainThread(
    const UnoptimizedCompileFlags flags, Handle<String> source,
    const ScriptDetails& script_details, NativesFlag natives,
    v8::Extension* extension, Isolate* isolate,
    MaybeHandle<Script> maybe_script, IsCompiledScope* is_compiled_scope,
    CompileHintCallback compile_hint_callback = nullptr,
    void* compile_hint_callback_data = nullptr) {
  UnoptimizedCompileState compile_state;
  ReusableUnoptimizedCompileState reusable_state(isolate);
  ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);
  parse_info.set_extension(extension);
  parse_info.SetCompileHintCallbackAndData(compile_hint_callback,
                                           compile_hint_callback_data);

  Handle<Script> script;
  if (!maybe_script.ToHandle(&script)) {
    script = NewScript(isolate, &parse_info, source, script_details, natives);
  }
  DCHECK_EQ(parse_info.flags().is_repl_mode(), script->is_repl_mode());

  return Compiler::CompileToplevel(&parse_info, script, isolate,
                                   is_compiled_scope);
}

class StressBackgroundCompileThread : public ParkingThread {
 public:
  StressBackgroundCompileThread(Isolate* isolate, Handle<String> source,
                                const ScriptDetails& script_details)
      : ParkingThread(
            base::Thread::Options("StressBackgroundCompileThread", 2 * i::MB)),
        source_(source),
        streamed_source_(std::make_unique<SourceStream>(source, isolate),
                         v8::ScriptCompiler::StreamedSource::TWO_BYTE) {
    ScriptType type = script_details.origin_options.IsModule()
                          ? ScriptType::kModule
                          : ScriptType::kClassic;
    data()->task = std::make_unique<i::BackgroundCompileTask>(
        data(), isolate, type,
        ScriptCompiler::CompileOptions::kNoCompileOptions,
        &streamed_source_.compilation_details());
  }

  void Run() override { data()->task->Run(); }

  ScriptStreamingData* data() { return streamed_source_.impl(); }

 private:
  // Dummy external source stream which returns the whole source in one go.
  // TODO(leszeks): Also test chunking the data.
  class SourceStream : public v8::ScriptCompiler::ExternalSourceStream {
   public:
    SourceStream(DirectHandle<String> source, Isolate* isolate) : done_(false) {
      source_length_ = source->length();
      source_buffer_ = std::make_unique<uint16_t[]>(source_length_);
      String::WriteToFlat(*source, source_buffer_.get(), 0, source_length_);
    }

    size_t GetMoreData(const uint8_t** src) override {
      if (done_) {
        return 0;
      }
      *src = reinterpret_cast<uint8_t*>(source_buffer_.release());
      done_ = true;

      return source_length_ * 2;
    }

   private:
    uint32_t source_length_;
    std::unique_ptr<uint16_t[]> source_buffer_;
    bool done_;
  };

  Handle<String> source_;
  v8::ScriptCompiler::StreamedSource streamed_source_;
};

bool CanBackgroundCompile(const ScriptDetails& script_details,
                          v8::Extension* extension,
                          ScriptCompiler::CompileOptions compile_options,
                          NativesFlag natives) {
  // TODO(leszeks): Remove the module check once background compilation of
  // modules is supported.
  return !script_details.origin_options.IsModule() && !extension &&
         script_details.repl_mode == REPLMode::kNo &&
         (compile_options == ScriptCompiler::kNoCompileOptions) &&
         natives == NOT_NATIVES_CODE;
}

bool CompilationExceptionIsRangeError(Isolate* isolate, Handle<Object> obj) {
  if (!IsJSError(*obj, isolate)) return false;
  Handle<JSReceiver> js_obj = Cast<JSReceiver>(obj);
  Handle<JSReceiver> constructor;
  if (!JSReceiver::GetConstructor(isolate, js_obj).ToHandle(&constructor)) {
    return false;
  }
  return *constructor == *isolate->range_error_function();
}

MaybeDirectHandle<SharedFunctionInfo>
CompileScriptOnBothBackgroundAndMainThread(Handle<String> source,
                                           const ScriptDetails& script_details,
                                           Isolate* isolate,
                                           IsCompiledScope* is_compiled_scope) {
  // Start a background thread compiling the script.
  StressBackgroundCompileThread background_compile_thread(isolate, source,
                                                          script_details);

  UnoptimizedCompileFlags flags_copy =
      background_compile_thread.data()->task->flags();

  CHECK(background_compile_thread.Start());
  MaybeHandle<SharedFunctionInfo> main_thread_maybe_result;
  bool main_thread_had_stack_overflow = false;
  // In parallel, compile on the main thread to flush out any data races.
  {
    IsCompiledScope inner_is_compiled_scope;
    // The background thread should also create any relevant exceptions, so we
    // can ignore the main-thread created ones.
    // TODO(leszeks): Maybe verify that any thrown (or unthrown) exceptions are
    // equivalent.
    TryCatch ignore_try_catch(reinterpret_cast<v8::Isolate*>(isolate));
    flags_copy.set_script_id(Script::kTemporaryScriptId);
    main_thread_maybe_result = CompileScriptOnMainThread(
        flags_copy, source, script_details, NOT_NATIVES_CODE, nullptr, isolate,
        MaybeHandle<Script>(), &inner_is_compiled_scope);
    if (main_thread_maybe_result.is_null()) {
      // Assume all range errors are stack overflows.
      main_thread_had_stack_overflow = CompilationExceptionIsRangeError(
          isolate, handle(isolate->exception(), isolate));
      isolate->clear_exception();
    }
  }

  // Join with background thread and finalize compilation.
  background_compile_thread.ParkedJoin(isolate->main_thread_local_isolate());

  ScriptCompiler::CompilationDetails compilation_details;
  MaybeDirectHandle<SharedFunctionInfo> maybe_result =
      Compiler::GetSharedFunctionInfoForStreamedScript(
          isolate, source, script_details, background_compile_thread.data(),
          &compilation_details);

  // Either both compiles should succeed, or both should fail. The one exception
  // to this is that the main-thread compilation might stack overflow while the
  // background compilation doesn't, so relax the check to include this case.
  // TODO(leszeks): Compare the contents of the results of the two compiles.
  if (main_thread_had_stack_overflow) {
    CHECK(main_thread_maybe_result.is_null());
  } else {
    CHECK_EQ(maybe_result.is_null(), main_thread_maybe_result.is_null());
  }

  DirectHandle<SharedFunctionInfo> result;
  if (maybe_result.ToHandle(&result)) {
    // The BackgroundCompileTask's IsCompiledScope will keep the result alive
    // until it dies at the end of this function, after which this new
    // IsCompiledScope can take over.
    *is_compiled_scope = result->is_compiled_scope(isolate);
  }

  return maybe_result;
}

namespace {
ScriptCompiler::InMemoryCacheResult CategorizeLookupResult(
    const CompilationCacheScript::LookupResult& lookup_result) {
  return !lookup_result.toplevel_sfi().is_null()
             ? ScriptCompiler::InMemoryCacheResult::kHit
         : !lookup_result.script().is_null()
             ? ScriptCompiler::InMemoryCacheResult::kPartial
             : ScriptCompiler::InMemoryCacheResult::kMiss;
}
}  // namespace

MaybeDirectHandle<SharedFunctionInfo> GetSharedFunctionInfoForScriptImpl(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, v8::Extension* extension,
    AlignedCachedData* cached_data, BackgroundDeserializeTask* deserialize_task,
    v8::CompileHintCallback compile_hint_callback,
    void* compile_hint_callback_data,
    ScriptCompiler::CompileOptions compile_options,
    ScriptCompiler::NoCacheReason no_cache_reason, NativesFlag natives,
    ScriptCompiler::CompilationDetails* compilation_details) {
  ScriptCompileTimerScope compile_timer(isolate, no_cache_reason,
                                        compilation_details);

  if (compile_options & ScriptCompiler::kConsumeCodeCache) {
    // Have to have exactly one of cached_data or deserialize_task.
    DCHECK(cached_data || deserialize_task);
    DCHECK(!(cached_data && deserialize_task));
    DCHECK_NULL(extension);
  } else {
    DCHECK_NULL(cached_data);
    DCHECK_NULL(deserialize_task);
  }

  if (compile_options & ScriptCompiler::kConsumeCompileHints) {
    DCHECK_NOT_NULL(compile_hint_callback);
    DCHECK_NOT_NULL(compile_hint_callback_data);
  } else {
    DCHECK_NULL(compile_hint_callback);
    DCHECK_NULL(compile_hint_callback_data);
  }

  compilation_details->background_time_in_microseconds =
      deserialize_task ? deserialize_task->background_time_in_microseconds()
                       : 0;

  LanguageMode language_mode = construct_language_mode(v8_flags.use_strict);
  CompilationCache* compilation_cache = isolate->compilation_cache();

  // For extensions or REPL mode scripts neither do a compilation cache lookup,
  // nor put the compilation result back into the cache.
  const bool use_compilation_cache =
      extension == nullptr && script_details.repl_mode == REPLMode::kNo;
  MaybeDirectHandle<SharedFunctionInfo> maybe_result;
  MaybeHandle<Script> maybe_script;
  IsCompiledScope is_compiled_scope;
  if (use_compilation_cache) {
    bool can_consume_code_cache =
        compile_options & ScriptCompiler::kConsumeCodeCache;
    if (can_consume_code_cache) {
      compile_timer.set_consuming_code_cache();
    }

    // First check per-isolate compilation cache.
    CompilationCacheScript::LookupResult lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    compilation_details->in_memory_cache_result =
        CategorizeLookupResult(lookup_result);
    maybe_script = lookup_result.script();
    maybe_result = lookup_result.toplevel_sfi();
    is_compiled_scope = lookup_result.is_compiled_scope();
    if (!maybe_result.is_null()) {
      compile_timer.set_hit_isolate_cache();
    } else if (can_consume_code_cache) {
      compile_timer.set_consuming_code_cache();
      // Then check cached code provided by embedder.
      NestedTimedHistogramScope timer(
          isolate->counters()->compile_deserialize());
      RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileDeserialize);
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                   "V8.CompileDeserialize");
      if (deserialize_task) {
        // If there's a cache consume task, finish it.
        maybe_result =
            deserialize_task->Finish(isolate, source, script_details);
        // It is possible at this point that there is a Script object for this
        // script in the compilation cache (held in the variable maybe_script),
        // which does not match maybe_result->script(). This could happen any of
        // three ways:
        // 1. The embedder didn't call MergeWithExistingScript.
        // 2. At the time the embedder called SourceTextAvailable, there was not
        //    yet a Script in the compilation cache, but it arrived sometime
        //    later.
        // 3. At the time the embedder called SourceTextAvailable, there was a
        //    Script available, and the new content has been merged into that
        //    Script. However, since then, the Script was replaced in the
        //    compilation cache, such as by another evaluation of the script
        //    hitting case 2, or DevTools clearing the cache.
        // This is okay; the new Script object will replace the current Script
        // held by the compilation cache. Both Scripts may remain in use
        // indefinitely, causing increased memory usage, but these cases are
        // sufficiently unlikely, and ensuring a correct merge in the third case
        // would be non-trivial.
      } else {
        maybe_result = CodeSerializer::Deserialize(
            isolate, cached_data, source, script_details, maybe_script);
      }

      bool consuming_code_cache_succeeded = false;
      DirectHandle<SharedFunctionInfo> result;
      if (maybe_result.ToHandle(&result)) {
        is_compiled_scope = result->is_compiled_scope(isolate);
        if (is_compiled_scope.is_compiled()) {
          consuming_code_cache_succeeded = true;
          // Promote to per-isolate compilation cache.
          compilation_cache->PutScript(source, language_mode, result);
        }
      }
      if (!consuming_code_cache_succeeded) {
        // Deserializer failed. Fall through to compile.
        compile_timer.set_consuming_code_cache_failed();
      }
    }
  }

  if (maybe_result.is_null()) {
    // No cache entry found compile the script.
    if (v8_flags.stress_background_compile &&
        CanBackgroundCompile(script_details, extension, compile_options,
                             natives)) {
      // If the --stress-background-compile flag is set, do the actual
      // compilation on a background thread, and wait for its result.
      maybe_result = CompileScriptOnBothBackgroundAndMainThread(
          source, script_details, isolate, &is_compiled_scope);
    } else {
      UnoptimizedCompileFlags flags =
          UnoptimizedCompileFlags::ForToplevelCompile(
              isolate, natives == NOT_NATIVES_CODE, language_mode,
              script_details.repl_mode,
              script_details.origin_options.IsModule() ? ScriptType::kModule
                                                       : ScriptType::kClassic,
              v8_flags.lazy);

      flags.set_is_eager(compile_options & ScriptCompiler::kEagerCompile);
      flags.set_compile_hints_magic_enabled(
          compile_options & ScriptCompiler::kFollowCompileHintsMagicComment);

      if (Handle<Script> script; maybe_script.ToHandle(&script)) {
        flags.set_script_id(script->id());
      }

      maybe_result = CompileScriptOnMainThread(
          flags, source, script_details, natives, extension, isolate,
          maybe_script, &is_compiled_scope, compile_hint_callback,
          compile_hint_callback_data);
    }

    // Add the result to the isolate cache.
    DirectHandle<SharedFunctionInfo> result;
    if (use_compilation_cache && maybe_result.ToHandle(&result)) {
      DCHECK(is_compiled_scope.is_compiled());
      compilation_cache->PutScript(source, language_mode, result);
    } else if (maybe_result.is_null() && natives != EXTENSION_CODE) {
      isolate->ReportPendingMessages();
    }
  }
  DirectHandle<SharedFunctionInfo> result;
  if (compile_options & ScriptCompiler::CompileOptions::kProduceCompileHints &&
      maybe_result.ToHandle(&result)) {
    Cast<Script>(result->script())->set_produce_compile_hints(true);
  }

  return maybe_result;
}

}  // namespace

MaybeDirectHandle<SharedFunctionInfo> Compiler::GetSharedFunctionInfoForScript(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details,
    ScriptCompiler::CompileOptions compile_options,
    ScriptCompiler::NoCacheReason no_cache_reason, NativesFlag natives,
    ScriptCompiler::CompilationDetails* compilation_details) {
  return GetSharedFunctionInfoForScriptImpl(
      isolate, source, script_details, nullptr, nullptr, nullptr, nullptr,
      nullptr, compile_options, no_cache_reason, natives, compilation_details);
}

MaybeDirectHandle<SharedFunctionInfo>
Compiler::GetSharedFunctionInfoForScriptWithExtension(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, v8::Extension* extension,
    ScriptCompiler::CompileOptions compile_options, NativesFlag natives,
    ScriptCompiler::CompilationDetails* compilation_details) {
  return GetSharedFunctionInfoForScriptImpl(
      isolate, source, script_details, extension, nullptr, nullptr, nullptr,
      nullptr, compile_options, ScriptCompiler::kNoCacheBecauseV8Extension,
      natives, compilation_details);
}

MaybeDirectHandle<SharedFunctionInfo>
Compiler::GetSharedFunctionInfoForScriptWithCachedData(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, AlignedCachedData* cached_data,
    ScriptCompiler::CompileOptions compile_options,
    ScriptCompiler::NoCacheReason no_cache_reason, NativesFlag natives,
    ScriptCompiler::CompilationDetails* compilation_details) {
  return GetSharedFunctionInfoForScriptImpl(
      isolate, source, script_details, nullptr, cached_data, nullptr, nullptr,
      nullptr, compile_options, no_cache_reason, natives, compilation_details);
}

MaybeDirectHandle<SharedFunctionInfo>
Compiler::GetSharedFunctionInfoForScriptWithDeserializeTask(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details,
    BackgroundDeserializeTask* deserialize_task,
    ScriptCompiler::CompileOptions compile_options,
    ScriptCompiler::NoCacheReason no_cache_reason, NativesFlag natives,
    ScriptCompiler::CompilationDetails* compilation_details) {
  return GetSharedFunctionInfoForScriptImpl(
      isolate, source, script_details, nullptr, nullptr, deserialize_task,
      nullptr, nullptr, compile_options, no_cache_reason, natives,
      compilation_details);
}

MaybeDirectHandle<SharedFunctionInfo>
Compiler::GetSharedFunctionInfoForScriptWithCompileHints(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details,
    v8::CompileHintCallback compile_hint_callback,
    void* compile_hint_callback_data,
    ScriptCompiler::CompileOptions compile_options,
    ScriptCompiler::NoCacheReason no_cache_reason, NativesFlag natives,
    ScriptCompiler::CompilationDetails* compilation_details) {
  return GetSharedFunctionInfoForScriptImpl(
      isolate, source, script_details, nullptr, nullptr, nullptr,
      compile_hint_callback, compile_hint_callback_data, compile_options,
      no_cache_reason, natives, compilation_details);
}

// static
MaybeHandle<JSFunction> Compiler::GetWrappedFunction(
    Handle<String> source, Handle<Context> context,
    const ScriptDetails& script_details, AlignedCachedData* cached_data,
    v8::ScriptCompiler::CompileOptions compile_options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason) {
  Isolate* isolate = context->GetIsolate();
  ScriptCompiler::CompilationDetails compilation_details;
  ScriptCompileTimerScope compile_timer(isolate, no_cache_reason,
                                        &compilation_details);

  if (compile_options & ScriptCompiler::kConsumeCodeCache) {
    DCHECK(cached_data);
    DCHECK_EQ(script_details.repl_mode, REPLMode::kNo);
  } else {
    DCHECK_NULL(cached_data);
  }

  LanguageMode language_mode = construct_language_mode(v8_flags.use_strict);
  DCHECK(!script_details.wrapped_arguments.is_null());
  MaybeDirectHandle<SharedFunctionInfo> maybe_result;
  DirectHandle<SharedFunctionInfo> result;
  Handle<Script> script;
  IsCompiledScope is_compiled_scope;
  bool can_consume_code_cache =
      compile_options & ScriptCompiler::kConsumeCodeCache;
  CompilationCache* compilation_cache = isolate->compilation_cache();
  // First check per-isolate compilation cache.
  CompilationCacheScript::LookupResult lookup_result =
      compilation_cache->LookupScript(source, script_details, language_mode);
  maybe_result = lookup_result.toplevel_sfi();
  if (maybe_result.ToHandle(&result)) {
    is_compiled_scope = result->is_compiled_scope(isolate);
    compile_timer.set_hit_isolate_cache();
  } else if (can_consume_code_cache) {
    compile_timer.set_consuming_code_cache();
    // Then check cached code provided by embedder.
    NestedTimedHistogramScope timer(isolate->counters()->compile_deserialize());
    RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileDeserialize);
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                 "V8.CompileDeserialize");
    maybe_result = CodeSerializer::Deserialize(isolate, cached_data, source,
                                               script_details);
    bool consuming_code_cache_succeeded = false;
    if (maybe_result.ToHandle(&result)) {
      is_compiled_scope = result->is_compiled_scope(isolate);
      if (is_compiled_scope.is_compiled()) {
        consuming_code_cache_succeeded = true;
        // Promote to per-isolate compilation cache.
        compilation_cache->PutScript(source, language_mode, result);
      }
    }
    if (!consuming_code_cache_succeeded) {
      // Deserializer failed. Fall through to compile.
      compile_timer.set_consuming_code_cache_failed();
    }
  }

  if (maybe_result.is_null()) {
    UnoptimizedCompileFlags flags = UnoptimizedCompileFlags::ForToplevelCompile(
        isolate, true, language_mode, script_details.repl_mode,
        ScriptType::kClassic, v8_flags.lazy);
    flags.set_is_eval(true);  // Use an eval scope as declaration scope.
    flags.set_function_syntax_kind(FunctionSyntaxKind::kWrapped);
    // TODO(delphick): Remove this and instead make the wrapped and wrapper
    // functions fully non-lazy instead thus preventing source positions from
    // being omitted.
    flags.set_collect_source_positions(true);
    flags.set_is_eager(compile_options & ScriptCompiler::kEagerCompile);

    UnoptimizedCompileState compile_state;
    ReusableUnoptimizedCompileState reusable_state(isolate);
    ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);

    MaybeHandle<ScopeInfo> maybe_outer_scope_info;
    if (!IsNativeContext(*context)) {
      maybe_outer_scope_info = handle(context->scope_info(), isolate);
    }
    script = NewScript(isolate, &parse_info, source, script_details,
                       NOT_NATIVES_CODE);

    DirectHandle<SharedFunctionInfo> top_level;
    maybe_result = v8::internal::CompileToplevel(&parse_info, script,
                                                 maybe_outer_scope_info,
                                                 isolate, &is_compiled_scope);
    if (maybe_result.is_null()) isolate->ReportPendingMessages();
    ASSIGN_RETURN_ON_EXCEPTION(isolate, top_level, maybe_result);

    SharedFunctionInfo::ScriptIterator infos(isolate, *script);
    for (Tagged<SharedFunctionInfo> info = infos.Next(); !info.is_null();
         info = infos.Next()) {
      if (info->is_wrapped()) {
        result = Handle<SharedFunctionInfo>(info, isolate);
        break;
      }
    }
    DCHECK(!result.is_null());

    is_compiled_scope = result->is_compiled_scope(isolate);
    script = Handle<Script>(Cast<Script>(result->script()), isolate);
    // Add the result to the isolate cache if there's no context extension.
    if (maybe_outer_scope_info.is_null()) {
      compilation_cache->PutScript(source, language_mode, result);
    }
  }

  DCHECK(is_compiled_scope.is_compiled());

  return Factory::JSFunctionBuilder{isolate, result, context}
      .set_allocation_type(AllocationType::kYoung)
      .Build();
}

// static
MaybeDirectHandle<SharedFunctionInfo>
Compiler::GetSharedFunctionInfoForStreamedScript(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, ScriptStreamingData* streaming_data,
    ScriptCompiler::CompilationDetails* compilation_details) {
  DCHECK(!script_details.origin_options.IsWasm());

  ScriptCompileTimerScope compile_timer(
      isolate, ScriptCompiler::kNoCacheBecauseStreamingSource,
      compilation_details);
  PostponeInterruptsScope postpone(isolate);

  BackgroundCompileTask* task = streaming_data->task.get();

  MaybeHandle<SharedFunctionInfo> maybe_result;
  MaybeHandle<Script> maybe_cached_script;
  // Check if compile cache already holds the SFI, if so no need to finalize
  // the code compiled on the background thread.
  CompilationCache* compilation_cache = isolate->compilation_cache();
  {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                 "V8.StreamingFinalization.CheckCache");
    CompilationCacheScript::LookupResult lookup_result =
        compilation_cache->LookupScript(source, script_details,
                                        task->flags().outer_language_mode());
    compilation_details->in_memory_cache_result =
        CategorizeLookupResult(lookup_result);

    if (!lookup_result.toplevel_sfi().is_null()) {
      maybe_result = lookup_result.toplevel_sfi();
    }

    if (!maybe_result.is_null()) {
      compile_timer.set_hit_isolate_cache();
    } else {
      maybe_cached_script = lookup_result.script();
    }
  }

  if (maybe_result.is_null()) {
    // No cache entry found, finalize compilation of the script and add it to
    // the isolate cache.
    RCS_SCOPE(isolate,
              RuntimeCallCounterId::kCompilePublishBackgroundFinalization);
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                 "V8.OffThreadFinalization.Publish");

    maybe_result = task->FinalizeScript(isolate, source, script_details,
                                        maybe_cached_script);

    Handle<SharedFunctionInfo> result;
    if (maybe_result.ToHandle(&result)) {
      if (task->flags().produce_compile_hints()) {
        Cast<Script>(result->script())->set_produce_compile_hints(true);
      }

      // Add compiled code to the isolate cache.
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                   "V8.StreamingFinalization.AddToCache");
      compilation_cache->PutScript(source, task->flags().outer_language_mode(),
                                   result);
    }
  }

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.StreamingFinalization.Release");
  streaming_data->Release();
  return maybe_result;
}  // namespace internal

// static
template <typename IsolateT>
DirectHandle<SharedFunctionInfo> Compiler::GetSharedFunctionInfo(
    FunctionLiteral* literal, Handle<Script> script, IsolateT* isolate) {
  // If we're parallel compiling functions, we might already have attached a SFI
  // to this literal.
  if (!literal->shared_function_info().is_null()) {
    return literal->shared_function_info();
  }
  // Precondition: code has been parsed and scopes have been analyzed.
  MaybeHandle<SharedFunctionInfo> maybe_existing;

  // Find any previously allocated shared function info for the given literal.
  maybe_existing = Script::FindSharedFunctionInfo(script, isolate, literal);

  // If we found an existing shared function info, return it.
  Handle<SharedFunctionInfo> existing;
  if (maybe_existing.ToHandle(&existing)) {
    // If the function has been uncompiled (bytecode flushed) it will have lost
    // any preparsed data. If we produced preparsed data during this compile for
    // this function, replace the uncompiled data with one that includes it.
    if (literal->produced_preparse_data() != nullptr &&
        existing->HasUncompiledDataWithoutPreparseData()) {
      DirectHandle<UncompiledData> existing_uncompiled_data(
          existing->uncompiled_data(isolate), isolate);
      DCHECK_EQ(literal->start_position(),
                existing_uncompiled_data->start_position());
      DCHECK_EQ(literal->end_position(),
                existing_uncompiled_data->end_position());
      // Use existing uncompiled data's inferred name as it may be more
      // accurate than the literal we preparsed.
      Handle<String> inferred_name =
          handle(existing_uncompiled_data->inferred_name(), isolate);
      Handle<PreparseData> preparse_data =
          literal->produced_preparse_data()->Serialize(isolate);
      DirectHandle<UncompiledData> new_uncompiled_data =
          isolate->factory()->NewUncompiledDataWithPreparseData(
              inferred_name, existing_uncompiled_data->start_position(),
              existing_uncompiled_data->end_position(), preparse_data);
      existing->set_uncompiled_data(*new_uncompiled_data);
    }
    return existing;
  }

  // Allocate a shared function info object which will be compiled lazily.
  Handle<SharedFunctionInfo> result =
      isolate->factory()->NewSharedFunctionInfoForLiteral(literal, script,
                                                          false);
  return result;
}

template DirectHandle<SharedFunctionInfo> Compiler::GetSharedFunctionInfo(
    FunctionLiteral* literal, Handle<Script> script, Isolate* isolate);
template DirectHandle<SharedFunctionInfo> Compiler::GetSharedFunctionInfo(
    FunctionLiteral* literal, Handle<Script> script, LocalIsolate* isolate);

// static
MaybeHandle<Code> Compiler::CompileOptimizedOSR(Isolate* isolate,
                                                Handle<JSFunction> function,
                                                BytecodeOffset osr_offset,
                                                ConcurrencyMode mode,
                                                CodeKind code_kind) {
  DCHECK(IsOSR(osr_offset));

  if (V8_UNLIKELY(isolate->serializer_enabled())) return {};
  if (V8_UNLIKELY(function->shared()->optimization_disabled())) return {};

  // TODO(chromium:1031479): Currently, OSR triggering mechanism is tied to the
  // bytecode array. So, it might be possible to mark closure in one native
  // context and optimize a closure from a different native context. So check if
  // there is a feedback vector before OSRing. We don't expect this to happen
  // often.
  if (V8_UNLIKELY(!function->has_feedback_vector())) return {};

  CompilerTracer::TraceOptimizeOSRStarted(isolate, function, osr_offset, mode);
  MaybeHandle<Code> result =
      GetOrCompileOptimized(isolate, function, mode, code_kind, osr_offset);

  if (result.is_null()) {
    CompilerTracer::TraceOptimizeOSRUnavailable(isolate, function, osr_offset,
                                                mode);
  } else {
    DCHECK_GE(result.ToHandleChecked()->kind(), CodeKind::MAGLEV);
    CompilerTracer::TraceOptimizeOSRAvailable(isolate, function, osr_offset,
                                              mode);
  }

  return result;
}

// static
void Compiler::DisposeTurbofanCompilationJob(Isolate* isolate,
                                             TurbofanCompilationJob* job) {
  DirectHandle<JSFunction> function = job->compilation_info()->closure();
  function->SetTieringInProgress(false, job->compilation_info()->osr_offset());
}

// static
void Compiler::FinalizeTurbofanCompilationJob(TurbofanCompilationJob* job,
                                              Isolate* isolate) {
  VMState<COMPILER> state(isolate);
  OptimizedCompilationInfo* compilation_info = job->compilation_info();

  TimerEventScope<TimerEventRecompileSynchronous> timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeConcurrentFinalize);
  TRACE_EVENT_WITH_FLOW0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                         "V8.OptimizeConcurrentFinalize", job->trace_id(),
                         TRACE_EVENT_FLAG_FLOW_IN);

  DirectHandle<JSFunction> function = compilation_info->closure();
  DirectHandle<SharedFunctionInfo> shared = compilation_info->shared_info();

  const bool use_result = !compilation_info->discard_result_for_testing();
  const BytecodeOffset osr_offset = compilation_info->osr_offset();

  DCHECK(!shared->HasBreakInfo(isolate));

  // 1) Optimization on the concurrent thread may have failed.
  // 2) The function may have already been optimized by OSR.  Simply continue.
  //    Except when OSR already disabled optimization for some reason.
  // 3) The code may have already been invalidated due to dependency change.
  // 4) InstructionStream generation may have failed.
  if (job->state() == CompilationJob::State::kReadyToFinalize) {
    if (shared->optimization_disabled()) {
      job->RetryOptimization(BailoutReason::kOptimizationDisabled);
    } else if (job->FinalizeJob(isolate) == CompilationJob::SUCCEEDED) {
      job->RecordCompilationStats(ConcurrencyMode::kConcurrent, isolate);
      job->RecordFunctionCompilation(LogEventListener::CodeTag::kFunction,
                                     isolate);
      if (V8_LIKELY(use_result)) {
        function->SetTieringInProgress(false,
                                       job->compilation_info()->osr_offset());
        if (!V8_ENABLE_LEAPTIERING_BOOL || IsOSR(osr_offset)) {
          OptimizedCodeCache::Insert(
              isolate, *compilation_info->closure(),
              compilation_info->osr_offset(), *compilation_info->code(),
              compilation_info->function_context_specializing());
        }
        CompilerTracer::TraceCompletedJob(isolate, compilation_info);
        if (IsOSR(osr_offset)) {
          CompilerTracer::TraceOptimizeOSRFinished(isolate, function,
                                                   osr_offset);
        } else {
          if (job->compilation_info()->function_context_specializing()) {
            function->UpdateContextSpecializedCode(isolate,
                                                   *compilation_info->code());
          } else {
            function->UpdateCode(*compilation_info->code());
          }
        }
      }
      return;
    }
  }

  DCHECK_EQ(job->state(), CompilationJob::State::kFailed);
  CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                  job->prepare_in_ms(), job->execute_in_ms(),
                                  job->finalize_in_ms());
  if (V8_LIKELY(use_result)) {
    function->SetTieringInProgress(false,
                                   job->compilation_info()->osr_offset());
    if (!IsOSR(osr_offset)) {
      function->UpdateCode(shared->GetCode(isolate));
    }
  }
}

// static
void Compiler::DisposeMaglevCompilationJob(maglev::MaglevCompilationJob* job,
                                           Isolate* isolate) {
#ifdef V8_ENABLE_MAGLEV
  DirectHandle<JSFunction> function = job->function();
  function->SetTieringInProgress(false, job->osr_offset());
#endif  // V8_ENABLE_MAGLEV
}

// static
void Compiler::FinalizeMaglevCompilationJob(maglev::MaglevCompilationJob* job,
                                            Isolate* isolate) {
#ifdef V8_ENABLE_MAGLEV
  VMState<COMPILER> state(isolate);

  DirectHandle<JSFunction> function = job->function();
  BytecodeOffset osr_offset = job->osr_offset();
  function->SetTieringInProgress(false, osr_offset);

  if (function->ActiveTierIsTurbofan(isolate) && !job->is_osr()) {
    CompilerTracer::TraceAbortedMaglevCompile(
        isolate, function, BailoutReason::kHigherTierAvailable);
    return;
  }

  const CompilationJob::Status status = job->FinalizeJob(isolate);

  // TODO(v8:7700): Use the result and check if job succeed
  // when all the bytecodes are implemented.
  USE(status);

  if (status == CompilationJob::SUCCEEDED) {
    DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);
    DCHECK(!shared->HasBreakInfo(isolate));

    // Note the finalized InstructionStream object has already been installed on
    // the function by MaglevCompilationJob::FinalizeJobImpl.

    Handle<Code> code = job->code().ToHandleChecked();
    if (!job->is_osr()) {
      if (job->specialize_to_function_context()) {
        job->function()->UpdateContextSpecializedCode(isolate, *code);
      } else {
        job->function()->UpdateCode(*code);
      }
    }

    DCHECK(code->is_maglevved());
    if (!V8_ENABLE_LEAPTIERING_BOOL || IsOSR(osr_offset)) {
      OptimizedCodeCache::Insert(isolate, *function, osr_offset, *code,
                                 job->specialize_to_function_context());
    }

    RecordMaglevFunctionCompilation(isolate, function,
                                    Cast<AbstractCode>(code));
    job->RecordCompilationStats(isolate);
    if (v8_flags.profile_guided_optimization &&
        shared->cached_tiering_decision() <=
            CachedTieringDecision::kEarlySparkplug) {
      shared->set_cached_tiering_decision(CachedTieringDecision::kEarlyMaglev);
    }
    CompilerTracer::TraceFinishMaglevCompile(
        isolate, function, job->is_osr(), job->prepare_in_ms(),
        job->execute_in_ms(), job->finalize_in_ms());
  }
#endif
}

// static
void Compiler::PostInstantiation(Isolate* isolate,
                                 DirectHandle<JSFunction> function,
                                 IsCompiledScope* is_compiled_scope) {
  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);

  // If code is compiled to bytecode (i.e., isn't asm.js), then allocate a
  // feedback and check for optimized code.
  if (is_compiled_scope->is_compiled() && shared->HasBytecodeArray()) {
    // Don't reset budget if there is a closure feedback cell array already. We
    // are just creating a new closure that shares the same feedback cell.
    JSFunction::InitializeFeedbackCell(function, is_compiled_scope, false);

#ifndef V8_ENABLE_LEAPTIERING
    if (function->has_feedback_vector()) {
      // Evict any deoptimized code on feedback vector. We need to do this after
      // creating the closure, since any heap allocations could trigger a GC and
      // deoptimized the code on the feedback vector. So check for any
      // deoptimized code just before installing it on the funciton.
      function->feedback_vector()->EvictOptimizedCodeMarkedForDeoptimization(
          isolate, *shared, "new function from shared function info");
      Tagged<Code> code = function->feedback_vector()->optimized_code(isolate);
      if (!code.is_null()) {
        // Caching of optimized code enabled and optimized code found.
        DCHECK(!code->marked_for_deoptimization());
        DCHECK(function->shared()->is_compiled());
        function->UpdateCode(code);
      }
    }
#endif  // !V8_ENABLE_LEAPTIERING

    if (v8_flags.always_turbofan && shared->allows_lazy_compilation() &&
        !shared->optimization_disabled() &&
        !function->HasAvailableOptimizedCode(isolate)) {
      CompilerTracer::TraceMarkForAlwaysOpt(isolate, function);
      JSFunction::EnsureFeedbackVector(isolate, function, is_compiled_scope);
      function->RequestOptimization(isolate, CodeKind::TURBOFAN_JS,
                                    ConcurrencyMode::kSynchronous);
    }
  }

  if (shared->is_toplevel() || shared->is_wrapped()) {
    // If it's a top-level script, report compilation to the debugger.
    DirectHandle<Script> script(Cast<Script>(shared->script()), isolate);
    isolate->debug()->OnAfterCompile(script);
    TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("devtools.v8-source-rundown"),
                 "ScriptCompiled", "data",
                 AddScriptCompiledTrace(isolate, shared));
    bool tracing_enabled;
    TRACE_EVENT_CATEGORY_GROUP_ENABLED(
        TRACE_DISABLED_BY_DEFAULT("devtools.v8-source-rundown-sources"),
        &tracing_enabled);
    if (tracing_enabled) {
      EmitScriptSourceTextTrace(isolate, shared);
    }
  }
}

std::unique_ptr<v8::tracing::TracedValue> Compiler::AddScriptCompiledTrace(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  DirectHandle<Script> script(Cast<Script>(shared->script()), isolate);
  i::Tagged<i::Object> context_value =
      isolate->native_context()->debug_context_id();
  int contextId = (IsSmi(context_value)) ? i::Smi::ToInt(context_value) : 0;
  Script::InitLineEnds(isolate, script);
  Script::PositionInfo endInfo;
  Script::GetPositionInfo(
      script, i::Cast<i::String>(script->source())->length(), &endInfo);
  Script::PositionInfo startInfo;
  Script::GetPositionInfo(script, shared->StartPosition(), &startInfo);
  auto value = v8::tracing::TracedValue::Create();
  value->SetString("isolate",
                   std::to_string(reinterpret_cast<size_t>(isolate)));
  value->SetInteger("executionContextId", contextId);
  value->SetInteger("scriptId", script->id());
  value->SetInteger("startLine", startInfo.line);
  value->SetInteger("startColumn", startInfo.column);
  value->SetInteger("endLine", endInfo.line);
  value->SetInteger("endColumn", endInfo.column);
  value->SetBoolean("isModule", script->origin_options().IsModule());
  value->SetBoolean("hasSourceUrl", script->HasValidSource());
  if (script->HasValidSource() && IsString(script->GetNameOrSourceURL())) {
    value->SetString(
        "sourceMapUrl",
        i::Cast<i::String>(script->GetNameOrSourceURL())->ToCString().get());
  }
  if (IsString(script->name())) {
    value->SetString("url",
                     i::Cast<i::String>(script->name())->ToCString().get());
  }
  value->SetString("hash",
                   i::Script::GetScriptHash(isolate, script,
                                            /* forceForInspector: */ false)
                       ->ToCString()
                       .get());
  return value;
}

void Compiler::EmitScriptSourceTextTrace(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  DirectHandle<Script> script(Cast<Script>(shared->script()), isolate);
  if (IsString(script->source())) {
    Tagged<String> source = i::Cast<i::String>(script->source());
    auto script_id = script->id();
    auto isolate_string = std::to_string(reinterpret_cast<size_t>(isolate));
    int32_t source_length = source->length();
    const int32_t kSplitMaxLength = 1000000;
    if (source_length <= kSplitMaxLength) {
      auto value = v8::tracing::TracedValue::Create();
      value->SetString("isolate", isolate_string);
      value->SetInteger("scriptId", script_id);
      value->SetInteger("length", source_length);
      value->SetString("sourceText", source->ToCString().get());
      TRACE_EVENT1(
          TRACE_DISABLED_BY_DEFAULT("devtools.v8-source-rundown-sources"),
          "ScriptCompiled", "data", std::move(value));
    } else {
      Handle<String> handle_source(source, isolate);
      int32_t split_count = source_length / kSplitMaxLength + 1;
      for (int32_t i = 0; i < split_count; i++) {
        int32_t begin = i * kSplitMaxLength;
        int32_t end = std::min(begin + kSplitMaxLength, source_length);
        DirectHandle<String> partial_source =
            isolate->factory()->NewSubString(handle_source, begin, end);
        auto split_trace_value = v8::tracing::TracedValue::Create();
        split_trace_value->SetInteger("splitIndex", i);
        split_trace_value->SetInteger("splitCount", split_count);
        split_trace_value->SetString("isolate", isolate_string);
        split_trace_value->SetInteger("scriptId", script_id);
        split_trace_value->SetString("sourceText",
                                     partial_source->ToCString().get());
        TRACE_EVENT1(
            TRACE_DISABLED_BY_DEFAULT("devtools.v8-source-rundown-sources"),
            "LargeScriptCompiledSplits", "data", std::move(split_trace_value));
      }
    }
  }
}

// ----------------------------------------------------------------------------
// Implementation of ScriptStreamingData

ScriptStreamingData::ScriptStreamingData(
    std::unique_ptr<ScriptCompiler::ExternalSourceStream> source_stream,
    ScriptCompiler::StreamedSource::Encoding encoding)
    : source_stream(std::move(source_stream)), encoding(encoding) {}

ScriptStreamingData::~ScriptStreamingData() = default;

void ScriptStreamingData::Release() { task.reset(); }

}  // namespace internal
}  // namespace v8
```