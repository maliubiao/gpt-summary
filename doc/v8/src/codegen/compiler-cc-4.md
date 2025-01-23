Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/compiler.cc`. They also have specific questions based on keywords in the code: `.tq`, JavaScript relevance, code logic, and common programming errors.

Here's a plan:

1. **Identify Core Functionality:** Read through the code and identify the main actions and goals. Keywords like `Compiler::GetFunctionFromEval`, `Compiler::ValidateDynamicCompilationSource`, `Compiler::GetFunctionFromString`, and sections related to script compilation and caching will be crucial.
2. **Address `.tq`:**  Check if the provided code contains `.tq` and answer the question accordingly.
3. **JavaScript Relevance:** Look for code that directly relates to JavaScript concepts like `eval`, `Function`, script compilation, and language modes. Provide a JavaScript example if applicable.
4. **Code Logic Reasoning:**  Focus on functions like `GetFunctionFromEval` and `ValidateDynamicCompilationSource`. Try to infer the logic flow and provide a hypothetical input and output.
5. **Common Programming Errors:** Consider scenarios where users might misuse `eval` or dynamically generated code, leading to errors.
6. **Summarize Overall Functionality:**  Combine the identified core functionalities into a concise summary for part 5 of 6.
```
v8/src/codegen/compiler.cc``` 文件是 V8 引擎中负责将 JavaScript 源代码编译成可执行机器码的关键组件。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能:**

1. **动态代码编译 (Eval 和 Function 构造器):**  该文件包含了 `Compiler::GetFunctionFromEval` 和 `Compiler::GetFunctionFromString` 等函数，专门处理通过 `eval()` 函数或者 `Function()` 构造器动态创建和编译 JavaScript 代码的场景。这包括：
    * **缓存查找:**  在编译前，会尝试在编译缓存中查找是否已经编译过相同的代码，以提高性能。缓存的键值包括源代码、外部信息、上下文和语言模式等。
    * **参数和主体分离:** 特别处理了 `Function()` 构造器中参数和函数体分开的情况，防止缓存污染。
    * **源代码解析:** 如果缓存未命中，则会解析提供的源代码。
    * **作用域处理:**  处理动态创建的函数的作用域，特别是与外部作用域的关系。
    * **错误处理:**  当提供的源代码不是字符串时，会抛出 `EvalError`。
    * **语言模式处理:** 考虑了严格模式 (`strict mode`) 和非严格模式 (`sloppy mode`) 的差异。
    * **生成可执行代码:**  最终将解析后的代码编译成可执行的 `JSFunction` 对象。

2. **代码生成权限验证:**  `Compiler::ValidateDynamicCompilationSource` 函数负责验证在当前上下文中是否允许通过字符串生成代码。这涉及到：
    * **上下文配置检查:**  检查上下文的 `allow_code_gen_from_strings` 属性。
    * **嵌入器回调:**  如果设置了嵌入器回调 (`v8::Isolate::SetModifyCodeGenerationFromStringsCallback`)，则会调用该回调来决定是否允许代码生成，并可能修改源代码。
    * **CodeLike 对象处理:**  允许编译类似代码的对象（例如，某些宿主环境提供的对象），并将其转换为字符串。

3. **脚本编译和缓存管理:**  代码中包含处理脚本编译和缓存的逻辑，虽然片段中没有完整的编译流程，但可以看到：
    * **编译计时:** 使用 `ScriptCompileTimerScope` 来衡量不同编译阶段的耗时，并记录缓存行为（命中、未命中等）。
    * **编译选项:**  支持不同的编译选项，例如是否使用缓存、是否提供编译提示等。
    * **后台编译:**  尝试在后台线程进行脚本编译，以提高性能。
    * **缓存查找和存储:**  与 `CompilationCache` 类交互，查找和存储编译结果。
    * **反序列化:**  处理从缓存中反序列化编译结果的逻辑。

**关于问题：**

* **`.tq` 结尾:**  代码片段是 `.cc` 文件，因此不是 v8 Torque 源代码。Torque 文件通常用于定义 V8 的内置函数和类型，并以 `.tq` 结尾。

* **与 JavaScript 的关系及举例:**  `v8/src/codegen/compiler.cc` 的主要功能就是编译 JavaScript 代码。以下 JavaScript 例子展示了该文件中代码所处理的场景：

   ```javascript
   // 使用 eval 动态执行代码
   let x = 10;
   eval("x = 20;");
   console.log(x); // 输出 20

   // 使用 Function 构造器动态创建函数
   const dynamicFunction = new Function('a', 'b', 'return a + b;');
   console.log(dynamicFunction(5, 3)); // 输出 8
   ```

* **代码逻辑推理:**

   **假设输入 (针对 `Compiler::GetFunctionFromEval`):**
   * `source`: 一个包含 JavaScript 函数定义的字符串，例如 `"function add(a, b) { return a + b; }"`。
   * `outer_info`:  外部函数的 `SharedFunctionInfo`，在顶级 `eval` 中可能为空。
   * `context`: 当前的 JavaScript 执行上下文。
   * `language_mode`: `LanguageMode::kSloppy` (非严格模式)。
   * `restriction`: `ONLY_SINGLE_FUNCTION_LITERAL`，表示期望编译单个函数字面量。
   * `parameters_end_pos`: `kNoSourcePosition`。
   * `eval_position`: `0`。
   * `parsing_while_debugging`:  一个枚举值，表示是否在调试时解析。

   **预期输出:**
   * 一个 `MaybeHandle<JSFunction>`，如果编译成功，则包含新创建的 `JSFunction` 对象；如果编译失败，则为空。编译成功的 `JSFunction` 对象会持有编译后的代码和相关的元数据。

* **用户常见的编程错误:**

   1. **滥用 `eval`:**  使用 `eval` 执行用户提供的字符串可能导致安全漏洞（代码注入）。
      ```javascript
      let userInput = prompt("请输入一些 JavaScript 代码：");
      // 潜在的安全风险！
      eval(userInput);
      ```

   2. **`Function` 构造器中的语法错误:**  传递给 `Function` 构造器的字符串包含语法错误会导致编译失败。
      ```javascript
      try {
          const badFunction = new Function('a', 'retun a;'); // "return" 拼写错误
      } catch (e) {
          console.error(e); // 输出 SyntaxError
      }
      ```

   3. **在不允许代码生成的上下文中使用 `eval` 或 `Function`:**  某些嵌入环境可能禁用动态代码生成。
      ```javascript
      // 假设在某个禁用动态代码生成的环境中
      try {
          eval("console.log('Hello');"); // 可能抛出 EvalError 或其他错误
      } catch (e) {
          console.error(e);
      }
      ```

**第 5 部分功能归纳:**

这部分代码主要负责 **V8 引擎中动态 JavaScript 代码的编译和执行**。它处理了 `eval()` 函数和 `Function()` 构造器创建的代码，包括缓存查找、源代码解析、作用域管理、错误处理以及代码生成权限的验证。此外，它还涉及脚本编译和缓存管理的一些基础机制，例如编译计时和后台编译的尝试。 这确保了 V8 能够安全高效地执行动态生成的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
          compilation_cache->PutScript(source, language
```