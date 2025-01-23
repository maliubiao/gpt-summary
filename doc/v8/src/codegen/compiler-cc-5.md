Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/compiler.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core function:** The central task of this code is to compile JavaScript source code into executable code (SharedFunctionInfo). The names of the functions like `GetSharedFunctionInfoForScript`, `CompileScriptOnMainThread`, `CompileScriptOnBothBackgroundAndMainThread`, `CompileToplevel`, and `GetWrappedFunction` strongly suggest this.

2. **Recognize the different compilation pathways:** Notice the various `GetSharedFunctionInfoForScript` overloads. These indicate different scenarios for compilation, such as:
    * Basic compilation from source.
    * Compilation with extensions.
    * Compilation using cached data.
    * Compilation using a background deserialization task.
    * Compilation with compile hints.
    * Compilation of "wrapped" code (likely eval or `Function()` constructor).

3. **Pinpoint key compilation steps:** The code mentions concepts like:
    * **Caching:**  `CompilationCache`, `LookupScript`, `PutScript`. This suggests the compiler tries to reuse previously compiled code.
    * **Background Compilation:** `CompileScriptOnBothBackgroundAndMainThread`, `BackgroundCompileTask`. This is for performance optimization.
    * **Deserialization:** `CodeSerializer::Deserialize`, used when consuming code cache.
    * **Flags:** `UnoptimizedCompileFlags`, used to configure the compilation process.
    * **Parsing:**  Mention of `ParseInfo` and `CompileToplevel`.
    * **Optimization:** Discussion of `CompileOptimizedOSR`, `TurbofanCompilationJob`, `MaglevCompilationJob`.
    * **Streaming:** `GetSharedFunctionInfoForStreamedScript`, `ScriptStreamingData`. This is another performance optimization for loading scripts.
    * **SharedFunctionInfo:** The core output of the compilation process.

4. **Look for conditional logic and flags:** Observe the `if` conditions that check for flags like `v8_flags.stress_background_compile`, `compile_options & ScriptCompiler::kConsumeCodeCache`, `v8_flags.always_turbofan`. These reveal different behaviors based on configuration.

5. **Understand the "wrapped" function scenario:** The `GetWrappedFunction` seems to handle the compilation of code passed to `eval()` or the `Function()` constructor. This requires creating a specific kind of scope.

6. **Connect to JavaScript concepts:** Consider how these C++ functions relate to JavaScript:
    * **Caching:**  Reduces compile times, similar to browser caching of resources.
    * **Background Compilation/Streaming:** Improves initial page load performance.
    * **Optimization:** Makes JavaScript code run faster.
    * **Eval/Function constructor:**  The `GetWrappedFunction` directly corresponds to these JavaScript features.

7. **Identify potential errors:**  The code mentions "Deserializer failed." This hints at potential issues with the code cache. More generally, invalid JavaScript syntax is a common error during compilation.

8. **Address the Torque aspect:** The prompt mentions `.tq` files. The code provided is `.cc`, so that part of the prompt can be addressed directly.

9. **Structure the response:** Organize the findings into logical sections:
    * Core Functionality
    * Detailed Functions and Features
    * Relationship to JavaScript
    * Code Logic Example (using a simplified scenario)
    * Common Programming Errors
    * Summary

10. **Refine and expand:**  Add details and explanations to each section to make the response more comprehensive and understandable. For instance, explain *why* caching is beneficial, or how background compilation works. For the code logic example, invent a simple JavaScript snippet and trace its theoretical compilation path.

11. **Self-Correction/Refinement during thought process:**
    * Initially, I might have focused too much on the individual functions without seeing the bigger picture. Realizing the core function is compilation helps to organize the information.
    * I might have overlooked some of the conditional logic at first glance. A closer reading helps to identify the different compilation paths.
    *  Ensuring the JavaScript examples are simple and illustrative is important. Avoid overly complex scenarios.
    *  Double-checking the prompt's constraints (like the `.tq` check) is essential.
这是目录为 `v8/src/codegen/compiler.cc` 的一个 V8 源代码文件。根据您提供的代码片段，我们可以归纳出它的主要功能是**负责将 JavaScript 源代码编译成 V8 虚拟机可以执行的代码（`SharedFunctionInfo`）**。

以下是更详细的功能列表：

1. **提供多种编译入口点:**  文件内定义了多个 `GetSharedFunctionInfoForScript` 的变体，这些函数作为编译的入口点，处理不同场景下的脚本编译：
    * `GetSharedFunctionInfoForScript`:  基本的脚本编译，不带扩展、缓存数据等。
    * `GetSharedFunctionInfoForScriptWithExtension`:  编译包含 V8 扩展的脚本。
    * `GetSharedFunctionInfoForScriptWithCachedData`:  使用预先缓存的代码数据进行编译，以加速启动。
    * `GetSharedFunctionInfoForScriptWithDeserializeTask`:  使用后台反序列化任务加载缓存的代码。
    * `GetSharedFunctionInfoForScriptWithCompileHints`:  使用编译提示进行编译。

2. **处理编译缓存:** 代码中使用了 `CompilationCache` 来存储和查找已编译的脚本。这可以避免重复编译相同的代码，提高性能。
    * 尝试从缓存中查找已编译的 `SharedFunctionInfo`。
    * 如果找到缓存，则直接使用，跳过编译过程。
    * 如果未找到，则进行编译，并将结果添加到缓存中。

3. **支持后台编译:**  通过 `CompileScriptOnBothBackgroundAndMainThread` 函数，文件支持在后台线程进行编译，以减少主线程的阻塞，提高响应速度。这通常在设置了 `--stress-background-compile` 标志时启用。

4. **执行主线程编译:**  `CompileScriptOnMainThread` 函数负责在主线程上执行实际的编译工作。它接收编译标志、源代码、脚本详情等信息，并调用底层的编译逻辑。

5. **处理不同类型的编译:** 文件可以处理不同类型的编译，例如：
    * **顶层编译 (Toplevel Compile):**  编译整个脚本。
    * **包裹编译 (Wrapped Compile):**  用于 `eval()` 或 `Function()` 构造函数创建的动态代码。`GetWrappedFunction` 负责处理这种情况。

6. **支持代码缓存的消费:**  如果提供了缓存数据 (`ScriptCompiler::kConsumeCodeCache`)，代码会尝试反序列化缓存的数据并使用它，跳过完整的编译过程。

7. **处理流式编译:** `GetSharedFunctionInfoForStreamedScript` 函数处理从流式源编译脚本的情况。这允许在整个脚本下载完成之前就开始编译，进一步提升性能。

8. **处理函数字面量编译:** `GetSharedFunctionInfo(FunctionLiteral...)`  函数用于获取函数字面量的 `SharedFunctionInfo`。它会尝试查找已有的 `SharedFunctionInfo`，如果不存在则创建一个。

9. **支持优化编译 (OSR):** `CompileOptimizedOSR` 函数处理 On-Stack Replacement (OSR) 编译，这是一种在函数执行过程中对其进行优化的技术。

10. **管理优化编译任务:**  代码中包含了管理 Turbofan 和 Maglev 优化编译任务的函数，例如 `DisposeTurbofanCompilationJob`, `FinalizeTurbofanCompilationJob`, `DisposeMaglevCompilationJob`, `FinalizeMaglevCompilationJob`。

11. **处理实例化后的操作:** `PostInstantiation` 函数在 `JSFunction` 实例化后执行一些操作，例如初始化反馈向量、触发优化、通知调试器等。

12. **提供调试信息:**  `AddScriptCompiledTrace` 和 `EmitScriptSourceTextTrace` 函数用于生成脚本编译相关的跟踪事件，供开发者工具使用。

**关于 .tq 文件：**

如果 `v8/src/codegen/compiler.cc` 以 `.tq` 结尾，那么它的确是 V8 Torque 源代码。Torque 是一种 V8 使用的领域特定语言，用于定义 V8 内部的运行时函数和内置函数。 然而，**您提供的代码片段的文件名是 `compiler.cc`，这是一个 C++ 文件**，因此它不是 Torque 源代码。Torque 代码通常用于生成一些底层的、性能关键的 V8 功能的 C++ 代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/codegen/compiler.cc` 的核心功能是将 JavaScript 代码转换为可执行代码，因此它与 JavaScript 的每一个执行过程都息息相关。以下是一些具体的 JavaScript 功能与 `compiler.cc` 中代码的关联示例：

**1. 脚本加载和执行：**

```javascript
// 当浏览器或 Node.js 加载并执行以下脚本时，
// v8/src/codegen/compiler.cc 中的代码会被调用来编译这段代码。
console.log("Hello, world!");

function add(a, b) {
  return a + b;
}

console.log(add(5, 3));
```

在这个例子中，`compiler.cc` 会解析这段 JavaScript 代码，构建抽象语法树 (AST)，进行作用域分析，然后生成字节码或机器码 (`SharedFunctionInfo`)，最终 V8 虚拟机才能执行 `console.log` 和 `add` 函数。

**2. `eval()` 函数：**

```javascript
let code = "console.log('Evaluated code!');";
eval(code);
```

当执行 `eval(code)` 时，V8 会再次调用 `compiler.cc` 中的相关代码（特别是 `GetWrappedFunction`）来编译 `code` 字符串中的 JavaScript 代码。

**3. `Function()` 构造函数：**

```javascript
let dynamicFunction = new Function('a', 'b', 'return a * b;');
console.log(dynamicFunction(4, 6));
```

类似于 `eval()`，当使用 `Function()` 构造函数创建函数时，`compiler.cc` 会负责编译作为字符串传递的函数体。

**4. 代码缓存：**

当 V8 编译一个脚本后，它可能会将编译结果缓存起来。下次加载相同的脚本时，`compiler.cc` 中的代码会尝试从缓存中恢复编译结果，从而加快加载速度。这对应于 `GetSharedFunctionInfoForScriptWithCachedData` 的使用。

**代码逻辑推理示例：**

**假设输入：**

* `source`: JavaScript 源代码字符串 `"function foo() { return 1; }"`
* `script_details`:  包含脚本元数据（例如，文件名、行号等）的对象。
* `compile_options`:  设置为默认编译选项。
* 未命中编译缓存。

**输出：**

1. `compiler.cc` 中的代码会创建一个 `ParseInfo` 对象来存储解析过程中的信息。
2. 调用解析器将 `source` 解析成抽象语法树 (AST)。
3. 进行作用域分析，确定变量的作用域。
4. 调用代码生成器生成 `foo` 函数的字节码或机器码。
5. 创建一个 `SharedFunctionInfo` 对象来封装编译后的代码和元数据。
6. 如果启用了编译缓存，则将 `source` 和 `SharedFunctionInfo` 的映射存储到 `CompilationCache` 中。
7. 返回 `SharedFunctionInfo` 对象。

**用户常见的编程错误示例：**

1. **语法错误：**

```javascript
// 缺少闭合括号
function bar() {
  console.log("Syntax error")
}
```

当 V8 尝试编译这段代码时，解析器会遇到语法错误，`compiler.cc` 中的代码会抛出异常，导致脚本执行失败。

2. **类型错误（在编译阶段可能无法完全检测到，但会影响优化）：**

```javascript
function multiply(a, b) {
  return a * b;
}

multiply("hello", 5); // 运行时类型错误，但在编译阶段可能不会报错
```

虽然这段代码在语法上是正确的，但在运行时，将字符串 `"hello"` 与数字 `5` 相乘会导致 `NaN`。V8 的编译器会在运行时根据类型反馈进行优化，如果类型不一致可能会导致 deoptimization。

3. **使用了未声明的变量：**

```javascript
function test() {
  console.log(undeclaredVariable);
}
```

在严格模式下，V8 的编译器会检测到使用了未声明的变量，并抛出 `ReferenceError`。

**总结其功能 (第 6 部分)：**

`v8/src/codegen/compiler.cc` 是 V8 JavaScript 引擎中至关重要的组成部分，**它负责将开发者编写的 JavaScript 源代码转化为 V8 虚拟机可以理解和执行的指令。**  它处理了各种编译场景，包括从源代码编译、使用缓存、后台编译、流式编译以及优化编译。其核心目标是高效且正确地将 JavaScript 代码转化为可执行的 `SharedFunctionInfo`，这是 V8 执行 JavaScript 代码的基础。该文件通过各种机制（如编译缓存、后台编译）来提升编译性能，从而提高整体的 JavaScript 执行效率。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
_mode, result);
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