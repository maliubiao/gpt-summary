Response:
Let's break down the thought process for analyzing this V8 C++ code snippet.

**1. Initial Scan and Identification of Key Elements:**

The first step is to quickly read through the code, looking for recognizable V8 concepts and patterns. Keywords like `CompilationJob`, `FunctionLiteral`, `SharedFunctionInfo`, `BytecodeArray`, `Code`, `Turbofan`, `Maglev`, `Isolate`, and `Script` immediately stand out. These are core components of V8's compilation pipeline. The presence of `#if V8_ENABLE_WEBASSEMBLY` hints at handling WebAssembly compilation as well.

**2. Function-by-Function Analysis:**

The code is organized into several distinct functions. Analyzing each function individually is a good strategy:

* **`ExecuteSingleUnoptimizedCompilationJob`:** The name suggests it handles the compilation of a single function without optimization. The presence of `interpreter::Interpreter::NewCompilationJob` confirms this. The check for `UseAsmWasm` indicates potential WebAssembly compilation.

* **`IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs`:** The "iteratively" suggests it processes multiple functions. The loop and the handling of `functions_to_compile` confirm this. The `FinalizeSingleUnoptimizedCompilationJob` call points to a separate finalization step. The handling of different `CompilationJob::Status` values (SUCCEEDED, FAILED, RETRY_ON_MAIN_THREAD) is important.

* **`FinalizeDeferredUnoptimizedCompilationJobs`:**  The "deferred" suggests handling compilations that were not finalized immediately. The loop iterating through `deferred_jobs` confirms this.

* **`OptimizedCodeCache::Get` and `OptimizedCodeCache::Insert`:** The name clearly indicates managing a cache for optimized code. The parameters like `JSFunction`, `BytecodeOffset`, and `CodeKind` are relevant to optimized code retrieval and storage. The OSR (On-Stack Replacement) logic is also apparent.

* **`PrepareJobWithHandleScope`:**  The name suggests setting up the environment for a compilation job, likely involving V8's handle management.

* **`CompileTurbofan_NotConcurrent` and `CompileTurbofan_Concurrent`:**  These clearly handle Turbofan (V8's optimizing compiler) compilation, with separate functions for synchronous and asynchronous (concurrent) execution.

* **`CompileTurbofan`:** This function seems to orchestrate the Turbofan compilation process, choosing between concurrent and non-concurrent execution.

* **`RecordMaglevFunctionCompilation` and `CompileMaglev`:** Similar to Turbofan, these handle Maglev (another of V8's optimizing compilers) compilation.

* **`GetOrCompileOptimized`:** This function appears to be a central point for getting or triggering optimized compilation. It checks for cached code and then calls either `CompileTurbofan` or `CompileMaglev`.

* **`SpawnDuplicateConcurrentJobForStressTesting`:**  The name is self-explanatory – used for testing concurrency.

* **`FailAndClearException`, `PrepareException`, `FailWithPreparedException`, `FailWithException`:** These are error handling utilities related to compilation failures.

* **`FinalizeUnoptimizedCompilation` and `FinalizeUnoptimizedScriptCompilation`:** These functions handle the finalization steps for unoptimized compilation, including logging and setting script states.

* **`CompileAllWithBaseline`:**  This seems to trigger baseline compilation (likely Ignition).

* **`CreateTopLevelSharedFunctionInfo` and `GetOrCreateTopLevelSharedFunctionInfo`:** These functions deal with creating and retrieving metadata for top-level functions.

* **`CompileToplevel`:**  This appears to be the main entry point for compiling top-level code (scripts or eval).

**3. Identifying Core Functionality:**

After analyzing the individual functions, we can start to synthesize the overall functionality:

* **Unoptimized Compilation:** The code handles the compilation of JavaScript code to bytecode using the interpreter (Ignition).
* **Optimized Compilation:**  It supports the compilation of code using optimizing compilers like Turbofan and Maglev.
* **Concurrency:**  It includes mechanisms for performing optimized compilation concurrently on background threads.
* **Code Caching:**  It manages a cache for optimized code to avoid redundant compilations.
* **On-Stack Replacement (OSR):**  It supports optimizing code while it's already running (OSR).
* **Error Handling:**  It provides mechanisms for handling compilation errors and exceptions.
* **WebAssembly Support:** It has conditional logic for handling WebAssembly modules.
* **Finalization:**  It includes steps to finalize both unoptimized and optimized compilation, including logging and updating metadata.

**4. Relating to JavaScript Concepts:**

The next step is to connect the V8 internals to familiar JavaScript concepts:

* **`FunctionLiteral`:** Represents a function definition in the JavaScript source code.
* **`SharedFunctionInfo`:** Metadata about a function that's shared across different instances of the same function.
* **`BytecodeArray`:** The compiled bytecode instructions for a function (from the interpreter).
* **`Code`:**  The machine code generated by the optimizing compilers.
* **Optimization:**  The process of making code run faster by applying various compiler techniques. This directly relates to Turbofan and Maglev.
* **OSR:**  Relevant when a function becomes "hot" while it's executing, and V8 decides to optimize it mid-execution.

**5. Hypothesizing Input/Output and Logic:**

Consider the flow of compilation:

* **Input:** JavaScript source code (represented by `ParseInfo`, `FunctionLiteral`, `Script`).
* **Unoptimized Compilation:**  Results in `BytecodeArray` associated with the `SharedFunctionInfo`.
* **Optimized Compilation:** Results in `Code` (machine code) stored in the `OptimizedCodeCache` and associated with the `JSFunction`.
* **Output:** Executable code (either bytecode or optimized machine code).

The logic involves checks for cached code, decisions about when and how to optimize, and mechanisms for managing concurrent compilation.

**6. Identifying Potential Programming Errors:**

Consider common JavaScript errors that might lead to compilation issues:

* **Syntax Errors:**  These would be caught during parsing (`parsing::ParseProgram`).
* **Stack Overflow:**  The code explicitly checks for and handles potential stack overflows during compilation.
* **Type Errors (at runtime, leading to deoptimization):** While not directly in *this* code, it's related to the concept of optimized code being invalidated.

**7. Addressing the `.tq` Question:**

The prompt specifically asks about the `.tq` extension. Since there's no mention of `.tq` in the provided snippet, the conclusion is that this particular file is not a Torque source file.

**8. Summarization (as Part 2 of 6):**

Given that this is part 2 of a larger set, the summarization should focus on the core compilation activities *within this specific snippet*. It should highlight the unoptimized and optimized compilation pathways, the handling of concurrency, and the code caching mechanism, setting the stage for the subsequent parts. It shouldn't try to encompass the entire V8 compilation process.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual compiler names (Turbofan, Maglev). It's important to step back and see the broader picture of unoptimized vs. optimized compilation.
*  The concurrency aspects are crucial. Realizing the distinction between synchronous and concurrent compilation flows is key.
* The role of `SharedFunctionInfo` as a central metadata structure needs to be emphasized.
*  Remembering the distinction between `JSFunction` (an instance of a function) and `SharedFunctionInfo` (the shared metadata) is important for understanding the optimized code cache.

By following this structured thought process, we can effectively analyze and understand complex code like this V8 compilation snippet.
好的，让我们来分析一下这段 `v8/src/codegen/compiler.cc` 的代码片段的功能。

**核心功能归纳:**

这段代码的核心功能是**执行和管理 JavaScript 函数的编译过程，包括未优化的（解释执行）编译和优化的（例如 Turbofan 或 Maglev）编译。**  它涉及以下几个关键方面：

1. **未优化编译（解释执行）：**
   - 创建和执行 `UnoptimizedCompilationJob`，这通常是使用解释器（Ignition）将 JavaScript 代码编译成字节码。
   - 迭代地编译函数，处理内部嵌套函数。
   - 管理未优化编译的完成和最终化，包括处理警告和错误。
   - 支持在后台线程上重试最终化。

2. **优化编译（Turbofan 和 Maglev）：**
   - 提供了获取或编译优化代码的入口 `GetOrCompileOptimized`。
   - 管理优化代码的缓存 (`OptimizedCodeCache`)，以避免重复编译。
   - 实现了 Turbofan 编译的同步和异步（并发）执行。
   - 实现了 Maglev 编译的同步和异步（并发）执行（如果启用了 Maglev）。
   - 决定是否应该对函数进行优化（基于配置和函数特性）。
   - 实现了在压力测试下生成重复的并发编译任务。

3. **编译任务管理:**
   - 使用 `CompilationJob` 基类及其派生类 (`UnoptimizedCompilationJob`, `TurbofanCompilationJob`, `MaglevCompilationJob`) 来抽象不同的编译阶段和类型。
   - 管理编译任务的准备 (`PrepareJob`)、执行 (`ExecuteJob`) 和最终化 (`FinalizeJob`) 阶段。

4. **错误处理:**
   - 提供了处理编译过程中出现的错误和异常的机制。
   - 跟踪和报告编译警告。

5. **共享函数信息管理:**
   - 创建和管理 `SharedFunctionInfo` 对象，该对象包含有关函数的元数据，并在不同的函数实例之间共享。

6. **脚本编译:**
   - 提供了编译顶级脚本代码的入口 `CompileToplevel`。

**关于 `.tq` 文件和 JavaScript 关系:**

根据您的描述，如果 `v8/src/codegen/compiler.cc` 以 `.tq` 结尾，那么它是一个 V8 Torque 源代码文件。 Torque 是一种 V8 使用的类型化的中间语言，用于生成高效的 C++ 代码。  然而，当前的 `compiler.cc` 文件是标准的 C++ 代码。

尽管此文件不是 Torque 代码，但它 *与* JavaScript 的功能有直接关系。它负责将 JavaScript 代码转换成可执行的形式（字节码或机器码）。

**JavaScript 举例说明:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 执行这段代码时，`compiler.cc` 中的代码（特别是 `CompileToplevel` 和相关的函数）会参与以下过程：

1. **解析 (Parsing):**  将 JavaScript 源代码解析成抽象语法树 (AST)。（虽然此代码片段中没有直接展示解析过程，但它依赖于解析结果）。
2. **未优化编译:**  `ExecuteSingleUnoptimizedCompilationJob` 和 `IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs` 会将 `add` 函数编译成字节码，以便解释器执行。
3. **优化编译 (可能):** 如果 `add` 函数被频繁调用，`GetOrCompileOptimized` 可能会被触发。根据 V8 的优化策略，它可能会选择使用 Turbofan 或 Maglev 将 `add` 函数编译成优化的机器码。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的函数字面量 `literal` 代表 `function add(a, b) { return a + b; }`，并且 `parse_info` 包含了该函数的解析信息。

**输入 (对于 `ExecuteSingleUnoptimizedCompilationJob`):**

- `parse_info`: 包含 `add` 函数解析信息的对象。
- `literal`: 指向 `add` 函数字面量的指针。
- `script`:  包含该脚本的 `Script` 对象。
- `allocator`: 用于内存分配的分配器。
- `eager_inner_literals`:  空的 vector，因为 `add` 函数没有内部的立即执行的函数。
- `local_isolate`: 当前 isolate 的本地表示。

**可能的输出 (对于 `ExecuteSingleUnoptimizedCompilationJob`):**

- 返回一个指向 `UnoptimizedCompilationJob` 对象的 `std::unique_ptr`，该对象包含了编译 `add` 函数的未优化任务的信息。  该任务成功执行后，会包含生成的字节码。如果编译失败（例如，语法错误），则可能返回一个空的 `std::unique_ptr`。

**用户常见的编程错误 (可能导致此代码中的编译失败):**

1. **语法错误:**  如果 JavaScript 代码包含语法错误（例如，`function add(a, b { return a + b; }` 缺少一个闭括号），解析阶段就会失败，导致编译过程提前终止。`FailWithException` 等函数会被调用来处理这些错误。

   ```javascript
   // 错误示例
   function subtract(x, y {
       return x - y;
   }
   ```

2. **超出堆栈大小:**  在非常深的递归调用或者定义了大量嵌套函数的情况下，可能会发生堆栈溢出。这段代码中，`IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs` 检查了 `shared_info.is_null()`，这可能是由于外部函数堆栈溢出导致的，并会跳过编译内部函数。

   ```javascript
   // 可能导致堆栈溢出的示例（虽然现代引擎通常会优化尾调用）
   function recursiveFunction(n) {
       if (n <= 0) {
           return 0;
       }
       return n + recursiveFunction(n - 1);
   }
   ```

**归纳功能 (作为第 2 部分):**

作为编译过程的第 2 部分，这段代码主要负责**执行和管理 JavaScript 函数的实际编译过程，从最初的未优化编译（生成字节码）开始，并为后续的优化编译（生成机器码）奠定基础。** 它处理了单个函数的编译、迭代地编译多个函数（包括内部函数），并提供了优化编译的入口点和缓存机制。 此外，它还涉及了基本的错误处理和编译任务管理。  这部分代码是 V8 将 JavaScript 源代码转化为可执行代码的关键环节。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ingleUnoptimizedCompilationJob(
    ParseInfo* parse_info, FunctionLiteral* literal, Handle<Script> script,
    AccountingAllocator* allocator,
    std::vector<FunctionLiteral*>* eager_inner_literals,
    LocalIsolate* local_isolate) {
#if V8_ENABLE_WEBASSEMBLY
  if (UseAsmWasm(literal, parse_info->flags().is_asm_wasm_broken())) {
    std::unique_ptr<UnoptimizedCompilationJob> asm_job(
        AsmJs::NewCompilationJob(parse_info, literal, allocator));
    if (asm_job->ExecuteJob() == CompilationJob::SUCCEEDED) {
      return asm_job;
    }
    // asm.js validation failed, fall through to standard unoptimized compile.
    // Note: we rely on the fact that AsmJs jobs have done all validation in the
    // PrepareJob and ExecuteJob phases and can't fail in FinalizeJob with
    // with a validation error or another error that could be solve by falling
    // through to standard unoptimized compile.
  }
#endif
  std::unique_ptr<UnoptimizedCompilationJob> job(
      interpreter::Interpreter::NewCompilationJob(
          parse_info, literal, script, allocator, eager_inner_literals,
          local_isolate));

  if (job->ExecuteJob() != CompilationJob::SUCCEEDED) {
    // Compilation failed, return null.
    return std::unique_ptr<UnoptimizedCompilationJob>();
  }

  return job;
}

template <typename IsolateT>
bool IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs(
    IsolateT* isolate, Handle<Script> script, ParseInfo* parse_info,
    AccountingAllocator* allocator, IsCompiledScope* is_compiled_scope,
    FinalizeUnoptimizedCompilationDataList*
        finalize_unoptimized_compilation_data_list,
    DeferredFinalizationJobDataList*
        jobs_to_retry_finalization_on_main_thread) {
  DeclarationScope::AllocateScopeInfos(parse_info, script, isolate);

  std::vector<FunctionLiteral*> functions_to_compile;
  functions_to_compile.push_back(parse_info->literal());

  bool compilation_succeeded = true;
  while (!functions_to_compile.empty()) {
    FunctionLiteral* literal = functions_to_compile.back();
    functions_to_compile.pop_back();
    Handle<SharedFunctionInfo> shared_info = literal->shared_function_info();
    // It's possible that compilation of an outer function overflowed the stack,
    // so a literal we'd like to compile won't have its SFI yet. Skip compiling
    // the inner function in that case.
    if (shared_info.is_null()) continue;
    if (shared_info->is_compiled()) continue;

    std::unique_ptr<UnoptimizedCompilationJob> job =
        ExecuteSingleUnoptimizedCompilationJob(parse_info, literal, script,
                                               allocator, &functions_to_compile,
                                               isolate->AsLocalIsolate());

    if (!job) {
      // Compilation failed presumably because of stack overflow, make sure
      // the shared function info contains uncompiled data for the next
      // compilation attempts.
      if (!shared_info->HasUncompiledData()) {
        SharedFunctionInfo::CreateAndSetUncompiledData(isolate, literal);
      }
      compilation_succeeded = false;
      // Proceed finalizing other functions in case they don't have uncompiled
      // data.
      continue;
    }

    UpdateSharedFunctionFlagsAfterCompilation(literal);

    auto finalization_status = FinalizeSingleUnoptimizedCompilationJob(
        job.get(), shared_info, isolate,
        finalize_unoptimized_compilation_data_list);

    switch (finalization_status) {
      case CompilationJob::SUCCEEDED:
        if (literal == parse_info->literal()) {
          // Ensure that the top level function is retained.
          *is_compiled_scope = shared_info->is_compiled_scope(isolate);
          DCHECK(is_compiled_scope->is_compiled());
        }
        break;

      case CompilationJob::FAILED:
        compilation_succeeded = false;
        // Proceed finalizing other functions in case they don't have uncompiled
        // data.
        continue;

      case CompilationJob::RETRY_ON_MAIN_THREAD:
        // This should not happen on the main thread.
        DCHECK((!std::is_same<IsolateT, Isolate>::value));
        DCHECK_NOT_NULL(jobs_to_retry_finalization_on_main_thread);

        // Clear the literal and ParseInfo to prevent further attempts to
        // access them.
        job->compilation_info()->ClearLiteral();
        job->ClearParseInfo();
        jobs_to_retry_finalization_on_main_thread->emplace_back(
            isolate, shared_info, std::move(job));
        break;
    }
  }

  // Report any warnings generated during compilation.
  if (parse_info->pending_error_handler()->has_pending_warnings()) {
    parse_info->pending_error_handler()->PrepareWarnings(isolate);
  }

  return compilation_succeeded;
}

bool FinalizeDeferredUnoptimizedCompilationJobs(
    Isolate* isolate, DirectHandle<Script> script,
    DeferredFinalizationJobDataList* deferred_jobs,
    PendingCompilationErrorHandler* pending_error_handler,
    FinalizeUnoptimizedCompilationDataList*
        finalize_unoptimized_compilation_data_list) {
  DCHECK(AllowCompilation::IsAllowed(isolate));

  if (deferred_jobs->empty()) return true;

  // TODO(rmcilroy): Clear native context in debug once AsmJS generates doesn't
  // rely on accessing native context during finalization.

  // Finalize the deferred compilation jobs.
  for (auto&& job : *deferred_jobs) {
    Handle<SharedFunctionInfo> shared_info = job.function_handle();
    if (FinalizeSingleUnoptimizedCompilationJob(
            job.job(), shared_info, isolate,
            finalize_unoptimized_compilation_data_list) !=
        CompilationJob::SUCCEEDED) {
      return false;
    }
  }

  // Report any warnings generated during deferred finalization.
  if (pending_error_handler->has_pending_warnings()) {
    pending_error_handler->PrepareWarnings(isolate);
  }

  return true;
}

// A wrapper to access the optimized code cache slots on the feedback vector.
class OptimizedCodeCache : public AllStatic {
 public:
  static V8_WARN_UNUSED_RESULT MaybeHandle<Code> Get(
      Isolate* isolate, DirectHandle<JSFunction> function,
      BytecodeOffset osr_offset, CodeKind code_kind) {
    DCHECK_IMPLIES(V8_ENABLE_LEAPTIERING_BOOL, IsOSR(osr_offset));
    if (!CodeKindIsStoredInOptimizedCodeCache(code_kind)) return {};
    if (!function->has_feedback_vector()) return {};

    DisallowGarbageCollection no_gc;
    Tagged<SharedFunctionInfo> shared = function->shared();
    RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileGetFromOptimizedCodeMap);

    Tagged<Code> code;
    Tagged<FeedbackVector> feedback_vector = function->feedback_vector();
    if (IsOSR(osr_offset)) {
      Handle<BytecodeArray> bytecode(shared->GetBytecodeArray(isolate),
                                     isolate);
      interpreter::BytecodeArrayIterator it(bytecode, osr_offset.ToInt());
      DCHECK_EQ(it.current_bytecode(), interpreter::Bytecode::kJumpLoop);
      std::optional<Tagged<Code>> maybe_code =
          feedback_vector->GetOptimizedOsrCode(isolate, it.GetSlotOperand(2));
      if (maybe_code.has_value()) code = maybe_code.value();
    } else {
#ifdef V8_ENABLE_LEAPTIERING
      UNREACHABLE();
#else
      feedback_vector->EvictOptimizedCodeMarkedForDeoptimization(
          isolate, shared, "OptimizedCodeCache::Get");
      code = feedback_vector->optimized_code(isolate);
#endif  // V8_ENABLE_LEAPTIERING
    }

    // Normal tierup should never request a code-kind we already have. In case
    // of OSR it can happen that we OSR from ignition to turbofan. This is
    // explicitly allowed here by re-using any larger-kinded than requested
    // code.
    DCHECK_IMPLIES(!code.is_null() && code->kind() > code_kind,
                   IsOSR(osr_offset));
    if (code.is_null() || code->kind() < code_kind) return {};

    DCHECK(!code->marked_for_deoptimization());
    DCHECK(shared->is_compiled());
    DCHECK(CodeKindIsStoredInOptimizedCodeCache(code->kind()));
    DCHECK_IMPLIES(IsOSR(osr_offset), CodeKindCanOSR(code->kind()));

    CompilerTracer::TraceOptimizedCodeCacheHit(isolate, function, osr_offset,
                                               code_kind);
    return handle(code, isolate);
  }

  static void Insert(Isolate* isolate, Tagged<JSFunction> function,
                     BytecodeOffset osr_offset, Tagged<Code> code,
                     bool is_function_context_specializing) {
    DCHECK_IMPLIES(V8_ENABLE_LEAPTIERING_BOOL, IsOSR(osr_offset));
    const CodeKind kind = code->kind();
    if (!CodeKindIsStoredInOptimizedCodeCache(kind)) return;

    Tagged<FeedbackVector> feedback_vector = function->feedback_vector();

    if (IsOSR(osr_offset)) {
      DCHECK(CodeKindCanOSR(kind));
      DCHECK(!is_function_context_specializing);
      Tagged<SharedFunctionInfo> shared = function->shared();
      Handle<BytecodeArray> bytecode(shared->GetBytecodeArray(isolate),
                                     isolate);
      // Bytecode may be different, so just make sure we see the expected
      // opcode. Otherwise fuzzers will complain.
      SBXCHECK_LT(osr_offset.ToInt(), bytecode->length());
      interpreter::BytecodeArrayIterator it(bytecode, osr_offset.ToInt());
      SBXCHECK_EQ(it.current_bytecode(), interpreter::Bytecode::kJumpLoop);
      feedback_vector->SetOptimizedOsrCode(isolate, it.GetSlotOperand(2), code);
      return;
    }

#ifdef V8_ENABLE_LEAPTIERING
    UNREACHABLE();
#else
    DCHECK(!IsOSR(osr_offset));

    if (is_function_context_specializing) {
      // Function context specialization folds-in the function context, so no
      // sharing can occur. Make sure the optimized code cache is cleared.
      // Only do so if the specialized code's kind matches the cached code kind.
      if (feedback_vector->has_optimized_code() &&
          feedback_vector->optimized_code(isolate)->kind() == code->kind()) {
        feedback_vector->ClearOptimizedCode();
      }
      return;
    }

    function->shared()->set_function_context_independent_compiled(true);
    feedback_vector->SetOptimizedCode(isolate, code);
#endif  // V8_ENABLE_LEAPTIERING
  }
};

// Runs PrepareJob in the proper compilation scopes. Handles will be allocated
// in a persistent handle scope that is detached and handed off to the
// {compilation_info} after PrepareJob.
bool PrepareJobWithHandleScope(OptimizedCompilationJob* job, Isolate* isolate,
                               OptimizedCompilationInfo* compilation_info,
                               ConcurrencyMode mode) {
  CompilationHandleScope compilation(isolate, compilation_info);
  CompilerTracer::TracePrepareJob(isolate, compilation_info, mode);
  compilation_info->ReopenAndCanonicalizeHandlesInNewScope(isolate);
  return job->PrepareJob(isolate) == CompilationJob::SUCCEEDED;
}

bool CompileTurbofan_NotConcurrent(Isolate* isolate,
                                   TurbofanCompilationJob* job) {
  OptimizedCompilationInfo* const compilation_info = job->compilation_info();
  DCHECK_EQ(compilation_info->code_kind(), CodeKind::TURBOFAN_JS);

  TimerEventScope<TimerEventRecompileSynchronous> timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeNonConcurrent);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.OptimizeNonConcurrent");

  if (!PrepareJobWithHandleScope(job, isolate, compilation_info,
                                 ConcurrencyMode::kSynchronous)) {
    CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                    job->prepare_in_ms(), job->execute_in_ms(),
                                    job->finalize_in_ms());
    return false;
  }

  if (job->ExecuteJob(isolate->counters()->runtime_call_stats(),
                      isolate->main_thread_local_isolate())) {
    CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                    job->prepare_in_ms(), job->execute_in_ms(),
                                    job->finalize_in_ms());
    return false;
  }

  if (job->FinalizeJob(isolate) != CompilationJob::SUCCEEDED) {
    CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                    job->prepare_in_ms(), job->execute_in_ms(),
                                    job->finalize_in_ms());
    return false;
  }

  // Success!
  job->RecordCompilationStats(ConcurrencyMode::kSynchronous, isolate);
  DCHECK(!isolate->has_exception());
  if (!V8_ENABLE_LEAPTIERING_BOOL || job->compilation_info()->is_osr()) {
    OptimizedCodeCache::Insert(
        isolate, *compilation_info->closure(), compilation_info->osr_offset(),
        *compilation_info->code(),
        compilation_info->function_context_specializing());
  }
  job->RecordFunctionCompilation(LogEventListener::CodeTag::kFunction, isolate);
  return true;
}

bool CompileTurbofan_Concurrent(Isolate* isolate,
                                std::unique_ptr<TurbofanCompilationJob> job) {
  OptimizedCompilationInfo* const compilation_info = job->compilation_info();
  DCHECK_EQ(compilation_info->code_kind(), CodeKind::TURBOFAN_JS);
  DirectHandle<JSFunction> function = compilation_info->closure();

  if (!isolate->optimizing_compile_dispatcher()->IsQueueAvailable()) {
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** Compilation queue full, will retry optimizing ");
      ShortPrint(*function);
      PrintF(" later.\n");
    }
    return false;
  }

  if (isolate->heap()->HighMemoryPressure()) {
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** High memory pressure, will retry optimizing ");
      ShortPrint(*function);
      PrintF(" later.\n");
    }
    return false;
  }

  TimerEventScope<TimerEventRecompileSynchronous> timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeConcurrentPrepare);
  TRACE_EVENT_WITH_FLOW0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                         "V8.OptimizeConcurrentPrepare", job->trace_id(),
                         TRACE_EVENT_FLAG_FLOW_OUT);

  if (!PrepareJobWithHandleScope(job.get(), isolate, compilation_info,
                                 ConcurrencyMode::kConcurrent)) {
    return false;
  }

  if (V8_LIKELY(!compilation_info->discard_result_for_testing())) {
    function->SetTieringInProgress(true, compilation_info->osr_offset());
  }

  // The background recompile will own this job.
  isolate->optimizing_compile_dispatcher()->QueueForOptimization(job.release());

  if (v8_flags.trace_concurrent_recompilation) {
    PrintF("  ** Queued ");
    ShortPrint(*function);
    PrintF(" for concurrent optimization.\n");
  }

  DCHECK(compilation_info->shared_info()->HasBytecodeArray());
  return true;
}

enum class CompileResultBehavior {
  // Default behavior, i.e. install the result, insert into caches, etc.
  kDefault,
  // Used only for stress testing. The compilation result should be discarded.
  kDiscardForTesting,
};

bool ShouldOptimize(CodeKind code_kind,
                    DirectHandle<SharedFunctionInfo> shared) {
  DCHECK(CodeKindIsOptimizedJSFunction(code_kind));
  switch (code_kind) {
    case CodeKind::TURBOFAN_JS:
      return v8_flags.turbofan && shared->PassesFilter(v8_flags.turbo_filter);
    case CodeKind::MAGLEV:
      return maglev::IsMaglevEnabled() &&
             shared->PassesFilter(v8_flags.maglev_filter);
    default:
      UNREACHABLE();
  }
}

MaybeHandle<Code> CompileTurbofan(Isolate* isolate, Handle<JSFunction> function,
                                  DirectHandle<SharedFunctionInfo> shared,
                                  ConcurrencyMode mode,
                                  BytecodeOffset osr_offset,
                                  CompileResultBehavior result_behavior) {
  VMState<COMPILER> state(isolate);
  TimerEventScope<TimerEventOptimizeCode> optimize_code_timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeCode);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.OptimizeCode");

  DCHECK(!isolate->has_exception());
  PostponeInterruptsScope postpone(isolate);
  const compiler::IsScriptAvailable has_script =
      IsScript(shared->script()) ? compiler::IsScriptAvailable::kYes
                                 : compiler::IsScriptAvailable::kNo;
  // BUG(5946): This DCHECK is necessary to make certain that we won't
  // tolerate the lack of a script without bytecode.
  DCHECK_IMPLIES(has_script == compiler::IsScriptAvailable::kNo,
                 shared->HasBytecodeArray());
  std::unique_ptr<TurbofanCompilationJob> job(
      compiler::NewCompilationJob(isolate, function, has_script, osr_offset));

  if (result_behavior == CompileResultBehavior::kDiscardForTesting) {
    job->compilation_info()->set_discard_result_for_testing();
  }

  if (IsOSR(osr_offset)) {
    isolate->CountUsage(v8::Isolate::kTurboFanOsrCompileStarted);
  }

  // Prepare the job and launch concurrent compilation, or compile now.
  if (IsConcurrent(mode)) {
    if (CompileTurbofan_Concurrent(isolate, std::move(job))) return {};
  } else {
    DCHECK(IsSynchronous(mode));
    if (CompileTurbofan_NotConcurrent(isolate, job.get())) {
      return job->compilation_info()->code();
    }
  }

  if (isolate->has_exception()) isolate->clear_exception();
  return {};
}

#ifdef V8_ENABLE_MAGLEV
// TODO(v8:7700): Record maglev compilations better.
void RecordMaglevFunctionCompilation(Isolate* isolate,
                                     DirectHandle<JSFunction> function,
                                     Handle<AbstractCode> code) {
  PtrComprCageBase cage_base(isolate);
  Handle<SharedFunctionInfo> shared(function->shared(cage_base), isolate);
  DirectHandle<Script> script(Cast<Script>(shared->script(cage_base)), isolate);
  Handle<FeedbackVector> feedback_vector(function->feedback_vector(cage_base),
                                         isolate);

  // Optimistic estimate.
  double time_taken_ms = 0;

  Compiler::LogFunctionCompilation(
      isolate, LogEventListener::CodeTag::kFunction, script, shared,
      feedback_vector, code, code->kind(cage_base), time_taken_ms);
}
#endif  // V8_ENABLE_MAGLEV

MaybeHandle<Code> CompileMaglev(Isolate* isolate, Handle<JSFunction> function,
                                ConcurrencyMode mode, BytecodeOffset osr_offset,
                                CompileResultBehavior result_behavior) {
#ifdef V8_ENABLE_MAGLEV
  DCHECK(maglev::IsMaglevEnabled());
  CHECK(result_behavior == CompileResultBehavior::kDefault);

  // TODO(v8:7700): Tracing, see CompileTurbofan.

  DCHECK(!isolate->has_exception());
  PostponeInterruptsScope postpone(isolate);

  // TODO(v8:7700): See everything in CompileTurbofan_Concurrent.
  // - Tracing,
  // - timers,
  // - aborts on memory pressure,
  // ...

  // Prepare the job.
  auto job = maglev::MaglevCompilationJob::New(isolate, function, osr_offset);

  if (IsConcurrent(mode) &&
      !isolate->maglev_concurrent_dispatcher()->is_enabled()) {
    mode = ConcurrencyMode::kSynchronous;
  }

  {
    TRACE_EVENT_WITH_FLOW0(
        TRACE_DISABLED_BY_DEFAULT("v8.compile"),
        IsSynchronous(mode) ? "V8.MaglevPrepare" : "V8.MaglevConcurrentPrepare",
        job->trace_id(), TRACE_EVENT_FLAG_FLOW_OUT);
    CompilerTracer::TraceStartMaglevCompile(isolate, function, job->is_osr(),
                                            mode);
    CompilationJob::Status status = job->PrepareJob(isolate);
    CHECK_EQ(status, CompilationJob::SUCCEEDED);  // TODO(v8:7700): Use status.
  }

  if (IsSynchronous(mode)) {
    CompilationJob::Status status =
        job->ExecuteJob(isolate->counters()->runtime_call_stats(),
                        isolate->main_thread_local_isolate());
    if (status == CompilationJob::FAILED) {
      return {};
    }
    CHECK_EQ(status, CompilationJob::SUCCEEDED);

    Compiler::FinalizeMaglevCompilationJob(job.get(), isolate);

    return job->code();
  }

  DCHECK(IsConcurrent(mode));

  // Enqueue it.
  isolate->maglev_concurrent_dispatcher()->EnqueueJob(std::move(job));

  // Remember that the function is currently being processed.
  function->SetTieringInProgress(true, osr_offset);
  function->SetInterruptBudget(isolate, CodeKind::MAGLEV);

  return {};
#else   // V8_ENABLE_MAGLEV
  UNREACHABLE();
#endif  // V8_ENABLE_MAGLEV
}

MaybeHandle<Code> GetOrCompileOptimized(
    Isolate* isolate, Handle<JSFunction> function, ConcurrencyMode mode,
    CodeKind code_kind, BytecodeOffset osr_offset = BytecodeOffset::None(),
    CompileResultBehavior result_behavior = CompileResultBehavior::kDefault) {
  DCHECK(CodeKindIsOptimizedJSFunction(code_kind));

  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);

  // Clear the optimization marker on the function so that we don't try to
  // re-optimize.
  if (!IsOSR(osr_offset)) {
#ifdef V8_ENABLE_LEAPTIERING
    DCHECK_IMPLIES(code_kind == CodeKind::MAGLEV,
                   !function->ActiveTierIsMaglev(isolate));
    DCHECK_IMPLIES(code_kind == CodeKind::TURBOFAN_JS,
                   !function->ActiveTierIsTurbofan(isolate));
#endif  // !V8_ENABLE_LEAPTIERING
    function->ResetTieringRequests(isolate);
    // Always reset the OSR urgency to ensure we reset it on function entry.
    function->feedback_vector()->reset_osr_urgency();
    int invocation_count =
        function->feedback_vector()->invocation_count(kRelaxedLoad);
    if (!(V8_UNLIKELY(v8_flags.testing_d8_test_runner ||
                      v8_flags.allow_natives_syntax) &&
          ManualOptimizationTable::IsMarkedForManualOptimization(isolate,
                                                                 *function)) &&
        invocation_count < v8_flags.minimum_invocations_before_optimization) {
      function->feedback_vector()->set_invocation_count(invocation_count + 1,
                                                        kRelaxedStore);
      return {};
    }
  }

  // TODO(v8:7700): Distinguish between Maglev and Turbofan.
  if (shared->optimization_disabled() &&
      shared->disabled_optimization_reason() == BailoutReason::kNeverOptimize) {
    return {};
  }

  // Do not optimize when debugger needs to hook into every call.
  if (isolate->debug()->needs_check_on_function_call()) {
    // Reset the OSR urgency to avoid triggering this compilation request on
    // every iteration and thereby skipping other interrupts.
    if (IsOSR(osr_offset)) {
      function->feedback_vector()->reset_osr_urgency();
    }
    return {};
  }

  // Do not optimize if we need to be able to set break points.
  if (shared->HasBreakInfo(isolate)) return {};

  // Do not optimize if optimization is disabled or function doesn't pass
  // turbo_filter.
  if (!ShouldOptimize(code_kind, shared)) return {};

  if (!V8_ENABLE_LEAPTIERING_BOOL || IsOSR(osr_offset)) {
    Handle<Code> cached_code;
    if (OptimizedCodeCache::Get(isolate, function, osr_offset, code_kind)
            .ToHandle(&cached_code)) {
      if (IsOSR(osr_offset)) {
        if (!function->osr_tiering_in_progress()) {
          function->feedback_vector()->reset_osr_urgency();
        }
      } else {
        DCHECK_LE(cached_code->kind(), code_kind);
      }
      return cached_code;
    }

    if (IsOSR(osr_offset)) {
      // One OSR job per function at a time.
      if (function->osr_tiering_in_progress()) {
        return {};
      }
      function->feedback_vector()->reset_osr_urgency();
    }
  }

  DCHECK(shared->is_compiled());

  if (code_kind == CodeKind::TURBOFAN_JS) {
    return CompileTurbofan(isolate, function, shared, mode, osr_offset,
                           result_behavior);
  } else {
    DCHECK_EQ(code_kind, CodeKind::MAGLEV);
    return CompileMaglev(isolate, function, mode, osr_offset, result_behavior);
  }
}

// When --stress-concurrent-inlining is enabled, spawn concurrent jobs in
// addition to non-concurrent compiles to increase coverage in mjsunit tests
// (where most interesting compiles are non-concurrent). The result of the
// compilation is thrown out.
void SpawnDuplicateConcurrentJobForStressTesting(Isolate* isolate,
                                                 Handle<JSFunction> function,
                                                 ConcurrencyMode mode,
                                                 CodeKind code_kind) {
  // TODO(v8:7700): Support Maglev.
  if (code_kind == CodeKind::MAGLEV) return;

  if (function->ActiveTierIsTurbofan(isolate)) return;

  DCHECK(v8_flags.stress_concurrent_inlining &&
         isolate->concurrent_recompilation_enabled() && IsSynchronous(mode) &&
         isolate->node_observer() == nullptr);
  CompileResultBehavior result_behavior =
      v8_flags.stress_concurrent_inlining_attach_code
          ? CompileResultBehavior::kDefault
          : CompileResultBehavior::kDiscardForTesting;
  USE(GetOrCompileOptimized(isolate, function, ConcurrencyMode::kConcurrent,
                            code_kind, BytecodeOffset::None(),
                            result_behavior));
}

bool FailAndClearException(Isolate* isolate) {
  isolate->clear_internal_exception();
  return false;
}

template <typename IsolateT>
bool PrepareException(IsolateT* isolate, ParseInfo* parse_info) {
  if (parse_info->pending_error_handler()->has_pending_error()) {
    parse_info->pending_error_handler()->PrepareErrors(
        isolate, parse_info->ast_value_factory());
  }
  return false;
}

bool FailWithPreparedException(
    Isolate* isolate, Handle<Script> script,
    const PendingCompilationErrorHandler* pending_error_handler,
    Compiler::ClearExceptionFlag flag = Compiler::KEEP_EXCEPTION) {
  if (flag == Compiler::CLEAR_EXCEPTION) {
    return FailAndClearException(isolate);
  }

  if (!isolate->has_exception()) {
    if (pending_error_handler->has_pending_error()) {
      pending_error_handler->ReportErrors(isolate, script);
    } else {
      isolate->StackOverflow();
    }
  }
  return false;
}

bool FailWithException(Isolate* isolate, Handle<Script> script,
                       ParseInfo* parse_info,
                       Compiler::ClearExceptionFlag flag) {
  PrepareException(isolate, parse_info);
  return FailWithPreparedException(isolate, script,
                                   parse_info->pending_error_handler(), flag);
}

void FinalizeUnoptimizedCompilation(
    Isolate* isolate, Handle<Script> script,
    const UnoptimizedCompileFlags& flags,
    const UnoptimizedCompileState* compile_state,
    const FinalizeUnoptimizedCompilationDataList&
        finalize_unoptimized_compilation_data_list) {
  if (compile_state->pending_error_handler()->has_pending_warnings()) {
    compile_state->pending_error_handler()->ReportWarnings(isolate, script);
  }

  bool need_source_positions =
      v8_flags.stress_lazy_source_positions ||
      (!flags.collect_source_positions() && isolate->NeedsSourcePositions());

  for (const auto& finalize_data : finalize_unoptimized_compilation_data_list) {
    Handle<SharedFunctionInfo> shared_info = finalize_data.function_handle();
    // It's unlikely, but possible, that the bytecode was flushed between being
    // allocated and now, so guard against that case, and against it being
    // flushed in the middle of this loop.
    IsCompiledScope is_compiled_scope(*shared_info, isolate);
    if (!is_compiled_scope.is_compiled()) continue;

    if (need_source_positions) {
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared_info);
    }
    LogEventListener::CodeTag log_tag;
    if (shared_info->is_toplevel()) {
      log_tag = flags.is_eval() ? LogEventListener::CodeTag::kEval
                                : LogEventListener::CodeTag::kScript;
    } else {
      log_tag = LogEventListener::CodeTag::kFunction;
    }
    log_tag = V8FileLogger::ToNativeByScript(log_tag, *script);
    if (v8_flags.interpreted_frames_native_stack &&
        isolate->logger()->is_listening_to_code_events()) {
      Compiler::InstallInterpreterTrampolineCopy(isolate, shared_info, log_tag);
    }
    Handle<CoverageInfo> coverage_info;
    if (finalize_data.coverage_info().ToHandle(&coverage_info)) {
      isolate->debug()->InstallCoverageInfo(shared_info, coverage_info);
    }

    LogUnoptimizedCompilation(isolate, shared_info, log_tag,
                              finalize_data.time_taken_to_execute(),
                              finalize_data.time_taken_to_finalize());
  }
}

void FinalizeUnoptimizedScriptCompilation(
    Isolate* isolate, Handle<Script> script,
    const UnoptimizedCompileFlags& flags,
    const UnoptimizedCompileState* compile_state,
    const FinalizeUnoptimizedCompilationDataList&
        finalize_unoptimized_compilation_data_list) {
  FinalizeUnoptimizedCompilation(isolate, script, flags, compile_state,
                                 finalize_unoptimized_compilation_data_list);

  script->set_compilation_state(Script::CompilationState::kCompiled);
  DCHECK_IMPLIES(isolate->NeedsSourcePositions(), script->has_line_ends());
}

void CompileAllWithBaseline(Isolate* isolate,
                            const FinalizeUnoptimizedCompilationDataList&
                                finalize_unoptimized_compilation_data_list) {
  for (const auto& finalize_data : finalize_unoptimized_compilation_data_list) {
    Handle<SharedFunctionInfo> shared_info = finalize_data.function_handle();
    IsCompiledScope is_compiled_scope(*shared_info, isolate);
    if (!is_compiled_scope.is_compiled()) continue;
    if (!CanCompileWithBaseline(isolate, *shared_info)) continue;
    Compiler::CompileSharedWithBaseline(
        isolate, shared_info, Compiler::CLEAR_EXCEPTION, &is_compiled_scope);
  }
}

// Create shared function info for top level and shared function infos array for
// inner functions.
template <typename IsolateT>
Handle<SharedFunctionInfo> CreateTopLevelSharedFunctionInfo(
    ParseInfo* parse_info, Handle<Script> script, IsolateT* isolate) {
  EnsureInfosArrayOnScript(script, parse_info, isolate);
  DCHECK_EQ(kNoSourcePosition,
            parse_info->literal()->function_token_position());
  return isolate->factory()->NewSharedFunctionInfoForLiteral(
      parse_info->literal(), script, true);
}

Handle<SharedFunctionInfo> GetOrCreateTopLevelSharedFunctionInfo(
    ParseInfo* parse_info, Handle<Script> script, Isolate* isolate,
    IsCompiledScope* is_compiled_scope) {
  EnsureInfosArrayOnScript(script, parse_info, isolate);
  MaybeHandle<SharedFunctionInfo> maybe_shared =
      Script::FindSharedFunctionInfo(script, isolate, parse_info->literal());
  if (Handle<SharedFunctionInfo> shared; maybe_shared.ToHandle(&shared)) {
    DCHECK_EQ(shared->function_literal_id(),
              parse_info->literal()->function_literal_id());
    *is_compiled_scope = shared->is_compiled_scope(isolate);
    return shared;
  }
  return CreateTopLevelSharedFunctionInfo(parse_info, script, isolate);
}

MaybeHandle<SharedFunctionInfo> CompileToplevel(
    ParseInfo* parse_info, Handle<Script> script,
    MaybeHandle<ScopeInfo> maybe_outer_scope_info, Isolate* isolate,
    IsCompiledScope* is_compiled_scope) {
  TimerEventScope<TimerEventCompileCode> top_level_timer(isolate);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.CompileCode");
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());

  PostponeInterruptsScope postpone(isolate);
  DCHECK(!isolate->native_context().is_null());
  RCS_SCOPE(isolate, parse_info->flags().is_eval()
                         ? RuntimeCallCounterId::kCompileEval
                         : RuntimeCallCounterId::kCompileScript);
  VMState<BYTECODE_COMPILER> state(isolate);
  if (parse_info->literal() == nullptr &&
      !parsing::ParseProgram(parse_info, script, maybe_outer_scope_info,
                             isolate, parsing::ReportStatisticsMode::kYes)) {
    FailWithException(isolate, script, parse_info,
                      Compiler::ClearExceptionFlag::KEEP_EXCEPTION);
    return MaybeHandle<SharedFunctionInfo>();
  }
  // Measure how long it takes to do the compilation; only take the
  // rest of the function into account to avoid overlap with the
  // parsing statistics.
  NestedTimedHistogram* rate = parse_info->flags().is_eval()
                                   ? isolate->counters()->compile_eval()
                                   : isolate->counters()->compile();
  NestedTimedHistogramScope timer(rate);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               parse_info->flags().is_eval() ? "V8.CompileEval" : "V8.Compile");

  // Create the SharedFunctionInfo and add it to the script's list.
  Handle<SharedFunctionInfo> shared_info =
      GetOrCreateTopLevelSharedFunctionInfo(parse_info, script, isolate,
                                            is_compiled_scope);

  FinalizeUnoptimizedCompilationDataList
      finalize_unoptimized_compilation_data_list;

  // Prepare and execute compilation of the outer
```