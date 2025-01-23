Response:
The user wants a summary of the provided C++ code snippet from `v8/src/codegen/compiler.cc`. I need to identify the functionalities within this excerpt, relate them to JavaScript concepts if applicable, and point out potential programming errors.

Here's a breakdown of the code's functionalities:

1. **Unoptimized Compilation Finalization:** The initial part of the snippet deals with finalizing the compilation of unoptimized code. This involves executing compilation jobs and potentially falling back to exception handling.

2. **Runtime Call Statistics:** The `RuntimeCallCounterIdForCompile` function determines the type of compilation (script, eval, or function) for runtime statistics tracking.

3. **Compilation Handle Scope:** The `CompilationHandleScope` manages persistent handles, which are necessary for transferring data between threads or across compilation phases.

4. **Deferred Finalization Data:** The `FinalizeUnoptimizedCompilationData` and `DeferredFinalizationJobData` structures hold information related to finalizing unoptimized compilation, especially when deferred to the main thread.

5. **Background Compilation Task:** The `BackgroundCompileTask` class is central to performing compilation on a background thread. It handles parsing, scope management, and generating the unoptimized code.

6. **Script Field Setting:** The `SetScriptFieldsFromDetails` function populates a `Script` object with metadata from `ScriptDetails`.

7. **Merge Assumption Checker:**  The `MergeAssumptionChecker` (under `ENABLE_SLOW_DCHECKS`) is a debugging tool that validates the structure of a newly compiled script during a background merge.

8. **Constant Pool Pointer Forwarder:** The `ConstantPoolPointerForwarder` class is used during background merging to update pointers within the constant pool of bytecode arrays to reference the correct objects from the cached script.

9. **Background Merge Task:** The `BackgroundMergeTask` class handles merging the results of background compilation with a previously cached script. This involves updating references and ensuring consistency.

Now, I need to weave these observations into a concise summary, address the user's specific requests about `.tq` files, JavaScript relations, code logic, and common errors.
这是v8源代码文件 `v8/src/codegen/compiler.cc` 的第三部分，主要关注 **背景编译任务** 和 **背景合并任务** 的实现细节。它处理了在后台线程执行代码编译，并将结果合并到主线程的过程。

**功能归纳:**

* **背景编译任务 (BackgroundCompileTask):**
    * **启动和运行在后台线程:**  `BackgroundCompileTask` 的主要职责是在后台线程执行脚本或函数的编译工作，从而避免阻塞主线程，提高性能。
    * **解析代码:**  它使用 `Parser` 类在后台解析源代码。
    * **管理编译状态:**  维护编译所需的各种信息，如编译标志 (`flags_`)、字符流 (`character_stream_`)、栈大小 (`stack_size_`) 等。
    * **处理顶级脚本和函数:** 可以处理完整的顶级脚本编译，也可以处理函数级别的编译。
    * **与主线程交互:** 通过持久句柄 (`persistent_handles_`) 将编译结果（如 `Script` 对象、`SharedFunctionInfo` 对象）传递回主线程。
    * **处理编译提示:** 支持编译提示 (Compile Hints)，允许开发者或工具指导编译过程。

* **背景合并任务 (BackgroundMergeTask):**
    * **将后台编译结果与缓存的脚本合并:** `BackgroundMergeTask` 负责将后台编译产生的新的 `Script` 对象与之前缓存的 `Script` 对象合并。这是为了利用已有的元数据和优化信息，提高编译效率。
    * **更新常量池指针:**  使用 `ConstantPoolPointerForwarder` 来更新新编译的 `BytecodeArray` 中常量池里的指针，使其指向旧的缓存脚本中的对象 (例如 `SharedFunctionInfo` 或 `ScopeInfo`)，从而保持引用的一致性。
    * **处理 ScopeInfo:** 特别关注 `ScopeInfo` 的管理和复用，确保在合并过程中 `ScopeInfo` 的一致性。
    * **优化编译流程:**  通过背景编译和合并，V8 可以在不阻塞用户界面的情况下完成耗时的编译工作。

**关于 `.tq` 文件:**

如果 `v8/src/codegen/compiler.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种 V8 内部使用的领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时函数。  **当前的 `compiler.cc` 文件是 C++ 代码，不是 Torque 代码。**

**与 JavaScript 的关系及示例:**

背景编译和合并对 JavaScript 开发者是透明的，但它是 V8 引擎优化 JavaScript 执行的关键部分。

**示例：**

```javascript
// 这是一个 JavaScript 脚本
function myFunction() {
  console.log("Hello from myFunction!");
}

myFunction();
```

当 V8 引擎加载和编译这个脚本时，`BackgroundCompileTask` 可能会在后台线程解析 `myFunction` 的代码，并生成其未优化的表示。随后，`BackgroundMergeTask` 可能会将这个结果与之前可能缓存的关于该脚本的信息合并。

**代码逻辑推理:**

假设输入：一个需要编译的 JavaScript 函数 `function add(a, b) { return a + b; }`。

1. **`BackgroundCompileTask::Run` 在后台线程被调用。**
2. **`Parser` 解析函数代码，创建抽象语法树 (AST)。**
3. **为 `add` 函数创建一个 `SharedFunctionInfo` 对象。**
4. **`IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs` 执行必要的编译步骤。**
5. **`BackgroundMergeTask` (在主线程) 被调用。**
6. **`ConstantPoolPointerForwarder` 可能会被用来更新 `add` 函数的 `BytecodeArray` 中的常量池指针，如果之前有相关的缓存信息。**

输出：一个完整的、可执行的 `SharedFunctionInfo` 对象，它包含了 `add` 函数的字节码和其他元数据。

**用户常见的编程错误 (与本部分代码关系较弱，但广义上与编译相关):**

* **过大的 JavaScript 文件:**  虽然背景编译可以缓解这个问题，但过大的文件仍然会增加编译时间，尤其是在首次加载时。
* **复杂的代码结构:**  过于复杂的函数或模块可能导致更长的编译时间。
* **依赖于未定义的变量或函数:** 这会导致解析错误，从而导致编译失败。V8 会抛出 `ReferenceError`。

**示例：**

```javascript
function buggyFunction() {
  console.log(undeclaredVariable); // 错误：使用了未声明的变量
}

buggyFunction(); // 这行代码会导致 ReferenceError
```

**总结本部分功能:**

这部分 `compiler.cc` 代码的核心功能是实现 V8 引擎的 **后台编译和合并机制**。它允许 V8 在后台线程异步地编译 JavaScript 代码，并将编译结果高效地整合到主线程，从而提高应用程序的启动速度和响应性。 `BackgroundCompileTask` 负责后台的解析和初步编译，而 `BackgroundMergeTask` 负责将后台编译的结果与主线程的缓存信息合并，并更新必要的指针和引用，以保证代码的正确执行。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
-most function.
  if (!IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs(
          isolate, script, parse_info, isolate->allocator(), is_compiled_scope,
          &finalize_unoptimized_compilation_data_list, nullptr)) {
    FailWithException(isolate, script, parse_info,
                      Compiler::ClearExceptionFlag::KEEP_EXCEPTION);
    return MaybeHandle<SharedFunctionInfo>();
  }

  // Character stream shouldn't be used again.
  parse_info->ResetCharacterStream();

  FinalizeUnoptimizedScriptCompilation(
      isolate, script, parse_info->flags(), parse_info->state(),
      finalize_unoptimized_compilation_data_list);

  if (v8_flags.always_sparkplug) {
    CompileAllWithBaseline(isolate, finalize_unoptimized_compilation_data_list);
  }

  return shared_info;
}

#ifdef V8_RUNTIME_CALL_STATS
RuntimeCallCounterId RuntimeCallCounterIdForCompile(ParseInfo* parse_info) {
  if (parse_info->flags().is_toplevel()) {
    if (parse_info->flags().is_eval()) {
      return RuntimeCallCounterId::kCompileEval;
    }
    return RuntimeCallCounterId::kCompileScript;
  }
  return RuntimeCallCounterId::kCompileFunction;
}
#endif  // V8_RUNTIME_CALL_STATS

}  // namespace

CompilationHandleScope::~CompilationHandleScope() {
  info_->set_persistent_handles(persistent_.Detach());
}

FinalizeUnoptimizedCompilationData::FinalizeUnoptimizedCompilationData(
    LocalIsolate* isolate, Handle<SharedFunctionInfo> function_handle,
    MaybeHandle<CoverageInfo> coverage_info,
    base::TimeDelta time_taken_to_execute,
    base::TimeDelta time_taken_to_finalize)
    : time_taken_to_execute_(time_taken_to_execute),
      time_taken_to_finalize_(time_taken_to_finalize),
      function_handle_(isolate->heap()->NewPersistentHandle(function_handle)),
      coverage_info_(isolate->heap()->NewPersistentMaybeHandle(coverage_info)) {
}

DeferredFinalizationJobData::DeferredFinalizationJobData(
    LocalIsolate* isolate, Handle<SharedFunctionInfo> function_handle,
    std::unique_ptr<UnoptimizedCompilationJob> job)
    : function_handle_(isolate->heap()->NewPersistentHandle(function_handle)),
      job_(std::move(job)) {}

BackgroundCompileTask::BackgroundCompileTask(
    ScriptStreamingData* streamed_data, Isolate* isolate, ScriptType type,
    ScriptCompiler::CompileOptions options,
    ScriptCompiler::CompilationDetails* compilation_details,
    CompileHintCallback compile_hint_callback, void* compile_hint_callback_data)
    : isolate_for_local_isolate_(isolate),
      flags_(UnoptimizedCompileFlags::ForToplevelCompile(
          isolate, true, construct_language_mode(v8_flags.use_strict),
          REPLMode::kNo, type,
          (options & ScriptCompiler::CompileOptions::kEagerCompile) == 0 &&
              v8_flags.lazy_streaming)),
      character_stream_(ScannerStream::For(streamed_data->source_stream.get(),
                                           streamed_data->encoding)),
      stack_size_(v8_flags.stack_size),
      worker_thread_runtime_call_stats_(
          isolate->counters()->worker_thread_runtime_call_stats()),
      timer_(isolate->counters()->compile_script_on_background()),
      compilation_details_(compilation_details),
      start_position_(0),
      end_position_(0),
      function_literal_id_(kFunctionLiteralIdTopLevel),
      compile_hint_callback_(compile_hint_callback),
      compile_hint_callback_data_(compile_hint_callback_data) {
  if (options & ScriptCompiler::CompileOptions::kProduceCompileHints) {
    flags_.set_produce_compile_hints(true);
  }
  DCHECK(is_streaming_compilation());
  if (options & ScriptCompiler::kConsumeCompileHints) {
    DCHECK_NOT_NULL(compile_hint_callback);
    DCHECK_NOT_NULL(compile_hint_callback_data);
  } else {
    DCHECK_NULL(compile_hint_callback);
    DCHECK_NULL(compile_hint_callback_data);
  }
  flags_.set_compile_hints_magic_enabled(
      options &
      ScriptCompiler::CompileOptions::kFollowCompileHintsMagicComment);
}

BackgroundCompileTask::BackgroundCompileTask(
    Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
    std::unique_ptr<Utf16CharacterStream> character_stream,
    WorkerThreadRuntimeCallStats* worker_thread_runtime_stats,
    TimedHistogram* timer, int max_stack_size)
    : isolate_for_local_isolate_(isolate),
      // TODO(leszeks): Create this from parent compile flags, to avoid
      // accessing the Isolate.
      flags_(
          UnoptimizedCompileFlags::ForFunctionCompile(isolate, *shared_info)),
      character_stream_(std::move(character_stream)),
      stack_size_(max_stack_size),
      worker_thread_runtime_call_stats_(worker_thread_runtime_stats),
      timer_(timer),
      compilation_details_(nullptr),
      start_position_(shared_info->StartPosition()),
      end_position_(shared_info->EndPosition()),
      function_literal_id_(shared_info->function_literal_id()) {
  DCHECK(!shared_info->is_toplevel());
  DCHECK(!is_streaming_compilation());

  character_stream_->Seek(start_position_);

  // Get the script out of the outer ParseInfo and turn it into a persistent
  // handle we can transfer to the background thread.
  persistent_handles_ = std::make_unique<PersistentHandles>(isolate);
  input_shared_info_ = persistent_handles_->NewHandle(shared_info);
}

BackgroundCompileTask::~BackgroundCompileTask() = default;

void SetScriptFieldsFromDetails(Isolate* isolate, Tagged<Script> script,
                                const ScriptDetails& script_details,
                                DisallowGarbageCollection* no_gc) {
  Handle<Object> script_name;
  if (script_details.name_obj.ToHandle(&script_name)) {
    script->set_name(*script_name);
    script->set_line_offset(script_details.line_offset);
    script->set_column_offset(script_details.column_offset);
  }
  // The API can provide a source map URL, but a source map URL could also have
  // been inferred by the parser from a magic comment. The API source map URL
  // takes precedence (as long as it is a non-empty string).
  Handle<Object> source_map_url;
  if (script_details.source_map_url.ToHandle(&source_map_url) &&
      IsString(*source_map_url) &&
      Cast<String>(*source_map_url)->length() > 0) {
    script->set_source_mapping_url(*source_map_url);
  }
  Handle<Object> host_defined_options;
  if (script_details.host_defined_options.ToHandle(&host_defined_options)) {
    // TODO(cbruni, chromium:1244145): Remove once migrated to the context.
    if (IsFixedArray(*host_defined_options)) {
      script->set_host_defined_options(Cast<FixedArray>(*host_defined_options));
    }
  }
}

namespace {

#ifdef ENABLE_SLOW_DCHECKS

// A class which traverses the object graph for a newly compiled Script and
// ensures that it contains pointers to Scripts, ScopeInfos and
// SharedFunctionInfos only at the expected locations. Any failure in this
// visitor indicates a case that is probably not handled correctly in
// BackgroundMergeTask.
class MergeAssumptionChecker final : public ObjectVisitor {
 public:
  explicit MergeAssumptionChecker(LocalIsolate* isolate)
      : isolate_(isolate), cage_base_(isolate->cage_base()) {}

  void IterateObjects(Tagged<HeapObject> start) {
    QueueVisit(start, kNormalObject);
    while (to_visit_.size() > 0) {
      std::pair<Tagged<HeapObject>, ObjectKind> pair = to_visit_.top();
      to_visit_.pop();
      Tagged<HeapObject> current = pair.first;
      // The Script's infos list and the constant pools for all
      // BytecodeArrays are expected to contain pointers to SharedFunctionInfos.
      // However, the type of those objects (FixedArray or WeakFixedArray)
      // doesn't have enough information to indicate their usage, so we enqueue
      // those objects here rather than during VisitPointers.
      if (IsScript(current)) {
        Tagged<Script> script = Cast<Script>(current);
        Tagged<HeapObject> infos = script->infos();
        QueueVisit(infos, kScriptInfosList);
        // Avoid visiting eval_from_shared_or_wrapped_arguments. This field
        // points to data outside the new Script, and doesn't need to be merged.
        Tagged<HeapObject> eval_from_shared_or_wrapped_arguments;
        if (script->eval_from_shared_or_wrapped_arguments()
                .GetHeapObjectIfStrong(
                    &eval_from_shared_or_wrapped_arguments)) {
          visited_.insert(eval_from_shared_or_wrapped_arguments);
        }
      } else if (IsBytecodeArray(current)) {
        Tagged<HeapObject> constants =
            Cast<BytecodeArray>(current)->constant_pool();
        QueueVisit(constants, kConstantPool);
      }
      current_object_kind_ = pair.second;
      i::VisitObjectBody(isolate_, current, this);
      QueueVisit(current->map(), kNormalObject);
    }
  }

  // ObjectVisitor implementation:
  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    MaybeObjectSlot maybe_start(start);
    MaybeObjectSlot maybe_end(end);
    VisitPointers(host, maybe_start, maybe_end);
  }
  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) override {
    for (MaybeObjectSlot current = start; current != end; ++current) {
      Tagged<MaybeObject> maybe_obj = current.load(cage_base_);
      Tagged<HeapObject> obj;
      bool is_weak = maybe_obj.IsWeak();
      if (maybe_obj.GetHeapObject(&obj)) {
        if (IsSharedFunctionInfo(obj)) {
          CHECK((current_object_kind_ == kConstantPool && !is_weak) ||
                (current_object_kind_ == kScriptInfosList && is_weak) ||
                (IsScript(host) &&
                 current.address() ==
                     host.address() +
                         Script::kEvalFromSharedOrWrappedArgumentsOffset));
        } else if (IsScopeInfo(obj)) {
          CHECK((current_object_kind_ == kConstantPool && !is_weak) ||
                (current_object_kind_ == kNormalObject && !is_weak) ||
                (current_object_kind_ == kScriptInfosList && is_weak));
        } else if (IsScript(obj)) {
          CHECK(IsSharedFunctionInfo(host) &&
                current == MaybeObjectSlot(host.address() +
                                           SharedFunctionInfo::kScriptOffset));
        } else if (IsFixedArray(obj) && current_object_kind_ == kConstantPool) {
          // Constant pools can contain nested fixed arrays, which in turn can
          // point to SFIs.
          QueueVisit(obj, kConstantPool);
        }

        QueueVisit(obj, kNormalObject);
      }
    }
  }

  // The object graph for a newly compiled Script shouldn't yet contain any
  // Code. If any of these functions are called, then that would indicate that
  // the graph was not disjoint from the rest of the heap as expected.
  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    UNREACHABLE();
  }
  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    UNREACHABLE();
  }
  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    UNREACHABLE();
  }

 private:
  enum ObjectKind {
    kNormalObject,
    kConstantPool,
    kScriptInfosList,
  };

  // If the object hasn't yet been added to the worklist, add it. Subsequent
  // calls with the same object have no effect, even if kind is different.
  void QueueVisit(Tagged<HeapObject> obj, ObjectKind kind) {
    if (visited_.insert(obj).second) {
      to_visit_.push(std::make_pair(obj, kind));
    }
  }

  DisallowGarbageCollection no_gc_;

  LocalIsolate* isolate_;
  PtrComprCageBase cage_base_;
  std::stack<std::pair<Tagged<HeapObject>, ObjectKind>> to_visit_;

  // Objects that are either in to_visit_ or done being visited. It is safe to
  // use HeapObject directly here because GC is disallowed while running this
  // visitor.
  std::unordered_set<Tagged<HeapObject>, Object::Hasher> visited_;

  ObjectKind current_object_kind_ = kNormalObject;
};

#endif  // ENABLE_SLOW_DCHECKS

}  // namespace

bool BackgroundCompileTask::is_streaming_compilation() const {
  return function_literal_id_ == kFunctionLiteralIdTopLevel;
}

void BackgroundCompileTask::Run() {
  DCHECK_NE(ThreadId::Current(), isolate_for_local_isolate_->thread_id());
  LocalIsolate isolate(isolate_for_local_isolate_, ThreadKind::kBackground);
  UnparkedScope unparked_scope(&isolate);
  LocalHandleScope handle_scope(&isolate);

  ReusableUnoptimizedCompileState reusable_state(&isolate);

  Run(&isolate, &reusable_state);
}

void BackgroundCompileTask::RunOnMainThread(Isolate* isolate) {
  LocalHandleScope handle_scope(isolate->main_thread_local_isolate());
  ReusableUnoptimizedCompileState reusable_state(isolate);
  Run(isolate->main_thread_local_isolate(), &reusable_state);
}

void BackgroundCompileTask::Run(
    LocalIsolate* isolate, ReusableUnoptimizedCompileState* reusable_state) {
  TimedHistogramScope timer(
      timer_, nullptr,
      compilation_details_
          ? &compilation_details_->background_time_in_microseconds
          : nullptr);

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "BackgroundCompileTask::Run");
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileCompileTask,
            RuntimeCallStats::CounterMode::kThreadSpecific);

  bool toplevel_script_compilation = flags_.is_toplevel();

  ParseInfo info(isolate, flags_, &compile_state_, reusable_state,
                 GetCurrentStackPosition() - stack_size_ * KB);
  info.set_character_stream(std::move(character_stream_));
  info.SetCompileHintCallbackAndData(compile_hint_callback_,
                                     compile_hint_callback_data_);
  if (is_streaming_compilation()) info.set_is_streaming_compilation();

  if (toplevel_script_compilation) {
    DCHECK_NULL(persistent_handles_);
    DCHECK(input_shared_info_.is_null());

    // We don't have the script source, origin, or details yet, so use default
    // values for them. These will be fixed up during the main-thread merge.
    Handle<Script> script = info.CreateScript(
        isolate, isolate->factory()->empty_string(), kNullMaybeHandle,
        ScriptOriginOptions(false, false, false, info.flags().is_module()));
    script_ = isolate->heap()->NewPersistentHandle(script);
  } else {
    DCHECK_NOT_NULL(persistent_handles_);
    isolate->heap()->AttachPersistentHandles(std::move(persistent_handles_));
    DirectHandle<SharedFunctionInfo> shared_info =
        input_shared_info_.ToHandleChecked();
    script_ = isolate->heap()->NewPersistentHandle(
        Cast<Script>(shared_info->script()));
    info.CheckFlagsForFunctionFromScript(*script_);

    {
      SharedStringAccessGuardIfNeeded access_guard(isolate);
      info.set_function_name(info.ast_value_factory()->GetString(
          shared_info->Name(), access_guard));
    }

    // Get preparsed scope data from the function literal.
    if (shared_info->HasUncompiledDataWithPreparseData()) {
      info.set_consumed_preparse_data(ConsumedPreparseData::For(
          isolate,
          handle(shared_info->uncompiled_data_with_preparse_data(isolate)
                     ->preparse_data(isolate),
                 isolate)));
    }
  }

  // Update the character stream's runtime call stats.
  info.character_stream()->set_runtime_call_stats(info.runtime_call_stats());

  Parser parser(isolate, &info);
  if (flags().is_toplevel()) {
    parser.InitializeEmptyScopeChain(&info);
  } else {
    // TODO(leszeks): Consider keeping Scope zones alive between compile tasks
    // and passing the Scope for the FunctionLiteral through here directly
    // without copying/deserializing.
    DirectHandle<SharedFunctionInfo> shared_info =
        input_shared_info_.ToHandleChecked();
    MaybeHandle<ScopeInfo> maybe_outer_scope_info;
    if (shared_info->HasOuterScopeInfo()) {
      maybe_outer_scope_info =
          handle(shared_info->GetOuterScopeInfo(), isolate);
    }
    parser.DeserializeScopeChain(
        isolate, &info, maybe_outer_scope_info,
        Scope::DeserializationMode::kIncludingVariables);
  }

  parser.ParseOnBackground(isolate, &info, script_, start_position_,
                           end_position_, function_literal_id_);
  parser.UpdateStatistics(script_, &use_counts_, &total_preparse_skipped_);

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.CompileCodeBackground");
  RCS_SCOPE(isolate, RuntimeCallCounterIdForCompile(&info),
            RuntimeCallStats::CounterMode::kThreadSpecific);

  MaybeHandle<SharedFunctionInfo> maybe_result;
  if (info.literal() != nullptr) {
    if (toplevel_script_compilation) {
      CreateTopLevelSharedFunctionInfo(&info, script_, isolate);
    } else {
      // Clone into a placeholder SFI for storing the results.
      info.literal()->set_shared_function_info(
          isolate->factory()->CloneSharedFunctionInfo(
              input_shared_info_.ToHandleChecked()));
    }

    if (IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs(
            isolate, script_, &info, reusable_state->allocator(),
            &is_compiled_scope_, &finalize_unoptimized_compilation_data_,
            &jobs_to_retry_finalization_on_main_thread_)) {
      maybe_result = info.literal()->shared_function_info();
    }
  }

  if (maybe_result.is_null()) {
    PrepareException(isolate, &info);
  } else if (v8_flags.enable_slow_asserts) {
#ifdef ENABLE_SLOW_DCHECKS
    MergeAssumptionChecker checker(isolate);
    checker.IterateObjects(*maybe_result.ToHandleChecked());
#endif
  }

  outer_function_sfi_ = isolate->heap()->NewPersistentMaybeHandle(maybe_result);
  DCHECK(isolate->heap()->ContainsPersistentHandle(script_.location()));
  persistent_handles_ = isolate->heap()->DetachPersistentHandles();
}

// A class which traverses the constant pools of newly compiled
// SharedFunctionInfos and updates any pointers which need updating.
class ConstantPoolPointerForwarder {
 public:
  explicit ConstantPoolPointerForwarder(PtrComprCageBase cage_base,
                                        LocalHeap* local_heap,
                                        DirectHandle<Script> old_script)
      : cage_base_(cage_base),
        local_heap_(local_heap),
        old_script_(old_script) {}

  void AddBytecodeArray(Tagged<BytecodeArray> bytecode_array) {
    CHECK(IsBytecodeArray(bytecode_array));
    bytecode_arrays_to_update_.emplace_back(bytecode_array, local_heap_);
  }

  void RecordScopeInfos(Tagged<MaybeObject> maybe_old_info) {
    RecordScopeInfos(maybe_old_info.GetHeapObjectAssumeWeak());
  }

  // Record all scope infos relevant for a shared function info or scope info
  // (recorded for eval).
  void RecordScopeInfos(Tagged<HeapObject> info) {
    if (!v8_flags.reuse_scope_infos) return;
    Tagged<ScopeInfo> scope_info;
    if (Is<SharedFunctionInfo>(info)) {
      Tagged<SharedFunctionInfo> old_sfi = Cast<SharedFunctionInfo>(info);
      // Also record context-having own scope infos for SFIs.
      if (!old_sfi->scope_info()->IsEmpty() &&
          old_sfi->scope_info()->HasContext()) {
        scope_info = old_sfi->scope_info();
      } else if (old_sfi->HasOuterScopeInfo()) {
        scope_info = old_sfi->GetOuterScopeInfo();
      } else {
        return;
      }
    } else {
      scope_info = Cast<ScopeInfo>(info);
    }

    while (true) {
      auto it = scope_infos_to_update_.find(scope_info->UniqueIdInScript());
      if (it != scope_infos_to_update_.end()) {
        // Once we find an already recorded scope info, it need to match the one
        // on the chain.
        if (V8_UNLIKELY(*it->second != scope_info)) {
          info->Print();
          (*it->second)->Print();
          scope_info->Print();
          UNREACHABLE();
        }
        return;
      }
      scope_infos_to_update_[scope_info->UniqueIdInScript()] =
          handle(scope_info, local_heap_);
      if (!scope_info->HasOuterScopeInfo()) break;
      scope_info = scope_info->OuterScopeInfo();
    }
  }

  // Runs the update after the setup functions above specified the work to do.
  void IterateAndForwardPointers() {
    DCHECK(HasAnythingToForward());
    for (DirectHandle<BytecodeArray> entry : bytecode_arrays_to_update_) {
      local_heap_->Safepoint();
      DisallowGarbageCollection no_gc;
      IterateConstantPool(entry->constant_pool());
    }
  }

  void set_has_shared_function_info_to_forward() {
    has_shared_function_info_to_forward_ = true;
  }

  bool HasAnythingToForward() const {
    return has_shared_function_info_to_forward_ ||
           !scope_infos_to_update_.empty();
  }

  // Find an own scope info for the sfi based on the UniqueIdInScript that the
  // own scope info would have. This works even if the SFI doesn't yet have a
  // scope info attached by computing UniqueIdInScript from the SFI position.
  //
  // This should only directly be used for SFIs that already existed on the
  // script. Their outer scope info will already be correct.
  bool InstallOwnScopeInfo(Tagged<SharedFunctionInfo> sfi) {
    if (!v8_flags.reuse_scope_infos) return false;
    auto it = scope_infos_to_update_.find(sfi->UniqueIdInScript());
    if (it == scope_infos_to_update_.end()) return false;
    sfi->SetScopeInfo(*it->second);
    return true;
  }

  // Either replace the own scope info of the sfi, or the first outer scope info
  // that was recorded.
  //
  // This has to be used for all newly created SFIs since their outer scope info
  // also may need to be reattached.
  void UpdateScopeInfo(Tagged<SharedFunctionInfo> sfi) {
    if (!v8_flags.reuse_scope_infos) return;
    if (InstallOwnScopeInfo(sfi)) return;
    if (!sfi->HasOuterScopeInfo()) return;

    Tagged<ScopeInfo> parent =
        sfi->scope_info()->IsEmpty() ? Tagged<ScopeInfo>() : sfi->scope_info();
    Tagged<ScopeInfo> outer_info = sfi->GetOuterScopeInfo();

    auto it = scope_infos_to_update_.find(outer_info->UniqueIdInScript());
    while (it == scope_infos_to_update_.end()) {
      if (!outer_info->HasOuterScopeInfo()) return;
      parent = outer_info;
      outer_info = outer_info->OuterScopeInfo();
      it = scope_infos_to_update_.find(outer_info->UniqueIdInScript());
    }
    if (outer_info == *it->second) return;

    VerifyScopeInfo(outer_info, *it->second);

    if (parent.is_null()) {
      sfi->set_raw_outer_scope_info_or_feedback_metadata(*it->second);
    } else {
      parent->set_outer_scope_info(*it->second);
    }
  }

 private:
  void VerifyScopeInfo(Tagged<ScopeInfo> scope_info,
                       Tagged<ScopeInfo> replacement) {
    CHECK_EQ(replacement->EndPosition(), scope_info->EndPosition());
    CHECK_EQ(replacement->scope_type(), scope_info->scope_type());
    CHECK_EQ(replacement->ContextLength(), scope_info->ContextLength());
  }
  template <typename TArray>
  void IterateConstantPoolEntry(Tagged<TArray> constant_pool, int i) {
    Tagged<Object> obj = constant_pool->get(i);
    if (IsSmi(obj)) return;
    Tagged<HeapObject> heap_obj = Cast<HeapObject>(obj);
    if (IsFixedArray(heap_obj, cage_base_)) {
      // Constant pools can have nested fixed arrays, but such relationships
      // are acyclic and never more than a few layers deep, so recursion is
      // fine here.
      IterateConstantPoolNestedArray(Cast<FixedArray>(heap_obj));
    } else if (has_shared_function_info_to_forward_ &&
               IsSharedFunctionInfo(heap_obj, cage_base_)) {
      VisitSharedFunctionInfo(constant_pool, i,
                              Cast<SharedFunctionInfo>(heap_obj));
    } else if (!scope_infos_to_update_.empty() &&
               IsScopeInfo(heap_obj, cage_base_)) {
      VisitScopeInfo(constant_pool, i, Cast<ScopeInfo>(heap_obj));
    }
  }

  template <typename TArray>
  void VisitSharedFunctionInfo(Tagged<TArray> constant_pool, int i,
                               Tagged<SharedFunctionInfo> sfi) {
    Tagged<MaybeObject> maybe_old_sfi =
        old_script_->infos()->get(sfi->function_literal_id());
    if (maybe_old_sfi.IsWeak()) {
      constant_pool->set(
          i, Cast<SharedFunctionInfo>(maybe_old_sfi.GetHeapObjectAssumeWeak()));
    }
  }

  template <typename TArray>
  void VisitScopeInfo(Tagged<TArray> constant_pool, int i,
                      Tagged<ScopeInfo> scope_info) {
    auto it = scope_infos_to_update_.find(scope_info->UniqueIdInScript());
    // Try to replace the scope info itself with an already existing version.
    if (it != scope_infos_to_update_.end()) {
      if (scope_info != *it->second) {
        VerifyScopeInfo(scope_info, *it->second);
        constant_pool->set(i, *it->second);
      }
    } else if (scope_info->HasOuterScopeInfo()) {
      // If we didn't find a match, but we have an outer scope info, try to
      // replace the outer scope info with an already existing outer scope
      // info. We only need to look at the direct outer scope info since we'll
      // process all scope infos that are created by this compilation task.
      Tagged<ScopeInfo> outer = scope_info->OuterScopeInfo();
      it = scope_infos_to_update_.find(outer->UniqueIdInScript());
      if (it != scope_infos_to_update_.end() && outer != *it->second) {
        VerifyScopeInfo(outer, *it->second);
        scope_info->set_outer_scope_info(*it->second);
      }
    }
  }

  void IterateConstantPool(Tagged<TrustedFixedArray> constant_pool) {
    for (int i = 0, length = constant_pool->length(); i < length; ++i) {
      IterateConstantPoolEntry(constant_pool, i);
    }
  }

  void IterateConstantPoolNestedArray(Tagged<FixedArray> nested_array) {
    for (int i = 0, length = nested_array->length(); i < length; ++i) {
      IterateConstantPoolEntry(nested_array, i);
    }
  }

  PtrComprCageBase cage_base_;
  LocalHeap* local_heap_;
  DirectHandle<Script> old_script_;
  std::vector<IndirectHandle<BytecodeArray>> bytecode_arrays_to_update_;

  // Indicates whether we have any shared function info to forward.
  bool has_shared_function_info_to_forward_ = false;
  std::unordered_map<int, IndirectHandle<ScopeInfo>> scope_infos_to_update_;
};

void BackgroundMergeTask::SetUpOnMainThread(Isolate* isolate,
                                            Handle<String> source_text,
                                            const ScriptDetails& script_details,
                                            LanguageMode language_mode) {
  DCHECK_EQ(state_, kNotStarted);

  HandleScope handle_scope(isolate);

  CompilationCacheScript::LookupResult lookup_result =
      isolate->compilation_cache()->LookupScript(source_text, script_details,
                                                 language_mode);
  Handle<Script> script;
  if (!lookup_result.script().ToHandle(&script)) {
    state_ = kDone;
    return;
  }

  if (lookup_result.is_compiled_scope().is_compiled()) {
    // There already exists a compiled top-level SFI, so the main thread will
    // discard the background serialization results and use the top-level SFI
    // from the cache, assuming the top-level SFI is still compiled by then.
    // Thus, there is no need to keep the Script pointer for background merging.
    // Do nothing in this case.
    state_ = kDone;
  } else {
    DCHECK(lookup_result.toplevel_sfi().is_null());
    // A background merge is required.
    SetUpOnMainThread(isolate, script);
  }
}

namespace {
void VerifyCodeMerge(Isolate* isolate, DirectHandle<Script> script) {
  // Check that:
  //   * There aren't any duplicate scope info. Every scope/context should
  //     correspond to at most one scope info.
  //   * All published SFIs refer to the old script (i.e. we chose new vs old
  //     correctly, and updated new SFIs where needed).
  //   * All constant pool SFI entries point to an SFI referring to the old
  //     script (i.e. references were updated correctly).
  std::unordered_map<int, Tagged<ScopeInfo>> scope_infos;
  for (int i = 0; i < script->infos()->length(); i++) {
    Tagged<ScopeInfo> scope_info;
    if (!script->infos()->get(i).IsWeak()) continue;
    Tagged<HeapObject> info = script->infos()->get(i).GetHeapObjectAssumeWeak();
    if (Is<SharedFunctionInfo>(info)) {
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(info);
      CHECK_EQ(sfi->script(), *script);

      if (sfi->HasBytecodeArray()) {
        Tagged<BytecodeArray> bytecode = sfi->GetBytecodeArray(isolate);
        Tagged<TrustedFixedArray> constant_pool = bytecode->constant_pool();
        for (int i = 0; i < constant_pool->length(); ++i) {
          Tagged<Object> entry = constant_pool->get(i);
          if (Is<SharedFunctionInfo>(entry)) {
            Tagged<SharedFunctionInfo> inner_sfi =
                Cast<SharedFunctionInfo>(entry);
            int id = inner_sfi->function_literal_id();
            CHECK_EQ(MakeWeak(inner_sfi), script->infos()->get(id));
            CHECK_EQ(inner_sfi->script(), *script);
          }
        }
      }

      if (!sfi->scope_info()->IsEmpty()) {
        scope_info = sfi->scope_info();
      } else if (sfi->HasOuterScopeInfo()) {
        scope_info = sfi->GetOuterScopeInfo();
      } else {
        continue;
      }
    } else {
      scope_info = Cast<ScopeInfo>(info);
    }
    while (true) {
      auto it = scope_infos.find(scope_info->UniqueIdInScript());
      if (it != scope_infos.end()) {
        if (*it->second != scope_info) {
          isolate->PushParamsAndDie(reinterpret_cast<void*>(it->second->ptr()),
                                    reinterpret_cast<void*>(scope_info.ptr()));
          UNREACHABLE();
        }
        break;
      }
      scope_infos[scope_info->UniqueIdInScript()] = scope_info;
      if (!scope_info->HasOuterScopeInfo()) break;
      scope_info = scope_info->OuterScopeInfo();
    }
  }
}
}  // namespace

void BackgroundMergeTask::SetUpOnMainThread(
    Isolate* isolate, DirectHandle<Script> cached_script) {
  // Any data sent to the background thread will need to be a persistent handle.
#ifdef DEBUG
  VerifyCodeMerge(isolate, cached_script);
#else
  if (v8_flags.verify_code_merge) {
    VerifyCodeMerge(isolate, cached_script);
  }
#endif

  persistent_handles_ = std::make_unique<PersistentHandles>(isolate);
  state_ = kPendingBackgroundWork;
  cached_script_ = persistent_handles_->NewHandle(*cached_script);
}

static bool force_gc_during_next_merge_for_testing_ = false;

void BackgroundMergeTask::ForceGCDuringNextMergeForTesting() {
  force_gc_during_next_merge_for_testing_ = true;
}

void BackgroundMergeTask::BeginMergeInBackground(
    LocalIsolate* isolate, DirectHandle<Script> new_script) {
  DCHECK_EQ(state_, kPendingBackgroundWork);

  LocalHeap* local_heap = isolate->heap();
  local_heap->AttachPersistentHandles(std::move(persistent_handles_));
  LocalHandleScope handle_scope(local_heap);
  DirectHandle<Script> old_script = cached_script_.ToHandleChecked();
  ConstantPoolPointerForwarder forwarder(isolate, local_heap, old_script);

  {
    DisallowGarbageCollection no_gc;
    Tagged<MaybeObject> maybe_old_toplevel_sfi =
        old_script->infos()->get(kFunctionLiteralIdTopLevel);
    if (maybe_old_toplevel_sfi.IsWeak()) {
      Tagged<SharedFunctionInfo> old_toplevel_sfi = Cast<SharedFunctionInfo>(
          maybe_old_toplevel_sfi.GetHeapObjectAssumeWeak());
      toplevel_sfi_from_cached_script_ =
          local_heap->NewPersistentHandle(old_toplevel_sfi);
    }
  }

  // Iterate the SFI lists on both Scripts to set up the forwarding table and
  // follow-up worklists for the main thread.
  CHECK_EQ(old_script->infos()->length(), new_script->infos()->length());
  for (int i = 0; i < old_script->infos()->length(); ++i) {
    DisallowGarbageCollection no_gc;
    Tagged<MaybeObject> maybe_new_sfi = new_script->infos()->get(i);
    Tagged<MaybeObject> maybe_old_info = old_script->infos()->get(i);
    // We might have scope infos in the table if it's deserialized from a code
    // cache.
    if (maybe_new_sfi.IsWeak() &&
        Is<SharedFunctionInfo>(maybe_new_sfi.GetHeapObjectAssumeWeak())) {
      Tagged<SharedFunctionInfo> new_sfi =
          Cast<SharedFunctionInfo>(maybe_new_sfi.GetHeapObjectAssumeWeak());
      if (maybe_old_info.IsWeak()) {
        forwarder.set_has_shared_function_info_to_forward();
        // The old script and the new script both have SharedFunctionInfos for
        // this function literal.
        Tagged<SharedFunctionInfo> old_sfi =
            Cast<SharedFunctionInfo>(maybe_old_info.GetHeapObjectAssumeWeak());
        // Make sure to allocate a persistent handle to the old sfi whether or
        // not it or the new sfi have bytecode -- this is necessary to keep the
        // old sfi reference in the old script list alive, so that pointers to
        // the new sfi are redirected to the old sfi.
```