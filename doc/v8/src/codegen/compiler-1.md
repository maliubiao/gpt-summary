Response: The user wants a summary of the C++ code in `v8/src/codegen/compiler.cc`.
This is part 2 of a 3-part request, implying there's context in the other parts.
The focus should be on the functions defined in this snippet and their roles, especially concerning their interaction with JavaScript functionalities.

Key elements in this snippet are:
- Background compilation tasks and their management.
- Merging background compilation results.
- Handling of `SharedFunctionInfo` and `Script` objects.
- Interaction with the compilation cache.
- Finalization of compilation jobs.

I need to describe the purpose of the classes and functions, and illustrate how this relates to the compilation of JavaScript code, providing a JavaScript example if applicable.
这是 `v8/src/codegen/compiler.cc` 文件的第二部分，主要关注于 **后台编译任务的管理和结果合并**。

**主要功能归纳:**

1. **`CompilationHandleScope`**:  这是一个作用域类，用于管理编译过程中创建的持久句柄。当 `CompilationHandleScope` 结束时，它会将持有的句柄关联到 `ParseInfo` 对象。

2. **`FinalizeUnoptimizedCompilationData`**:  存储未优化编译的最终数据，例如执行时间和最终确定时间，以及 `SharedFunctionInfo` 和 `CoverageInfo` 的持久句柄。

3. **`DeferredFinalizationJobData`**:  存储需要延迟最终确定的编译任务的数据，包括 `SharedFunctionInfo` 的持久句柄和一个 `UnoptimizedCompilationJob` 的智能指针。这通常用于那些不能在后台线程安全完成最终化的任务。

4. **`BackgroundCompileTask`**:  表示在后台线程执行的编译任务。
    - 它负责解析 JavaScript 代码（通过 `Parser`），生成未优化的字节码。
    - 它可以处理顶层脚本的编译以及函数的编译。
    - 对于顶层脚本，它会创建一个临时的 `Script` 对象，并在后台进行初步编译。
    - 对于函数，它会基于已有的 `SharedFunctionInfo` 进行编译。
    - 任务完成后，会将编译结果（例如 `SharedFunctionInfo`）存储起来。
    - 它涉及到与 `ParseInfo`、`UnoptimizedCompilationJob` 等组件的交互。

5. **`SetScriptFieldsFromDetails`**:  一个辅助函数，用于根据提供的 `ScriptDetails` 来设置 `Script` 对象的属性，例如名称、偏移量和 Source Map URL。

6. **`BackgroundMergeTask`**:  负责将后台编译任务的结果合并到主线程的 `Script` 对象中，特别是当存在缓存的脚本时。
    - 它尝试复用已有的 `SharedFunctionInfo` 和 `ScopeInfo`，以提高性能。
    - 它会比较新编译的 `Script` 和缓存的 `Script` 的 `SharedFunctionInfo` 列表。
    - 如果缓存中存在对应的 `SharedFunctionInfo`，则会尝试复用，并更新新 `SharedFunctionInfo` 中的引用。
    - 如果缓存中没有，则使用新编译的 `SharedFunctionInfo`。
    - 它使用 `ConstantPoolPointerForwarder` 来更新常量池中的指针，确保它们指向正确的 `SharedFunctionInfo` 和 `ScopeInfo`。

7. **`ConstantPoolPointerForwarder`**:  一个辅助类，用于遍历新编译的 `SharedFunctionInfo` 的常量池，并将指向旧 `Script` 中 `SharedFunctionInfo` 和 `ScopeInfo` 的指针更新为指向缓存的 `Script` 中的对应对象。这对于代码缓存的合并至关重要。

8. **`BackgroundDeserializeTask`**:  处理在后台线程反序列化代码缓存的任务。
    - 它从缓存的数据中恢复 `Script` 和相关的元数据。
    - 如果启用了合并功能，它会创建一个 `BackgroundMergeTask` 来将反序列化的结果与可能存在的编译缓存进行合并。

**与 JavaScript 功能的关系及示例:**

这些 C++ 代码直接参与了 V8 引擎编译 JavaScript 代码的过程。`BackgroundCompileTask` 和 `BackgroundMergeTask` 的存在使得 V8 能够在后台执行耗时的编译操作，从而提高主线程的响应速度，改善用户体验。

**JavaScript 示例:**

考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

console.log(add(5, 3));
```

当 V8 引擎第一次遇到 `add` 函数时，它可能不会立即进行完全优化编译。`BackgroundCompileTask` 可能会在后台线程解析 `add` 函数的源代码，并生成未优化的字节码。

如果启用了代码缓存，并且这个脚本之前被执行过，V8 可能会将编译结果缓存起来。当再次加载相同的脚本时，`BackgroundDeserializeTask` 可能会在后台线程反序列化这个缓存的数据。

`BackgroundMergeTask` 的作用体现在，如果 V8 找到了与当前脚本匹配的代码缓存，它会将缓存中的信息（例如已经编译的函数的优化代码）与当前正在后台编译的结果进行合并，避免重复编译，提高启动速度。

例如，假设 `add` 函数之前已经被编译过并缓存了，当 V8 再次执行包含 `add` 函数的脚本时，`BackgroundDeserializeTask` 会在后台加载缓存的数据。`BackgroundMergeTask` 会检查缓存中是否存在 `add` 函数的编译结果，如果存在，它会将这个结果（可能包含优化后的代码）合并到当前的执行环境中，而不需要重新进行完整的编译。

**总结:**

这部分 `compiler.cc` 代码的核心在于 **优化 JavaScript 代码的编译过程**，特别是通过利用后台线程来执行耗时的编译任务，并有效地合并编译结果，尤其是当涉及到代码缓存时。这直接影响了 JavaScript 代码的加载速度和执行效率。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
        Handle<SharedFunctionInfo> old_sfi_handle =
            local_heap->NewPersistentHandle(old_sfi);
        if (old_sfi->HasBytecodeArray()) {
          // Reset the old SFI's bytecode age so that it won't likely get
          // flushed right away. This operation might be racing against
          // concurrent modification by another thread, but such a race is not
          // catastrophic.
          old_sfi->set_age(0);
        } else if (new_sfi->HasBytecodeArray()) {
          // Also push the old_sfi to make sure it stays alive / isn't replaced.
          new_compiled_data_for_cached_sfis_.push_back(
              {old_sfi_handle, local_heap->NewPersistentHandle(new_sfi)});
          if (old_sfi->HasOuterScopeInfo()) {
            new_sfi->scope_info()->set_outer_scope_info(
                old_sfi->GetOuterScopeInfo());
          }
          forwarder.AddBytecodeArray(new_sfi->GetBytecodeArray(isolate));
        }
      } else {
        // The old script didn't have a SharedFunctionInfo for this function
        // literal, so it can use the new SharedFunctionInfo.
        new_sfi->set_script(*old_script, kReleaseStore);
        used_new_sfis_.push_back(local_heap->NewPersistentHandle(new_sfi));
        if (new_sfi->HasBytecodeArray()) {
          forwarder.AddBytecodeArray(new_sfi->GetBytecodeArray(isolate));
        }
      }
    }

    if (maybe_old_info.IsWeak()) {
      forwarder.RecordScopeInfos(maybe_old_info);
      // If the old script has a SFI, point to it from the new script to
      // indicate we've already seen it and we'll reuse it if necessary (if
      // newly compiled bytecode points to it).
      new_script->infos()->set(i, maybe_old_info);
    }
  }

  // Since we are walking the script infos weak list both when figuring out
  // which SFIs to merge above, and actually merging them below, make sure that
  // a GC here which clears any dead weak refs or flushes any bytecode doesn't
  // break anything.
  if (V8_UNLIKELY(force_gc_during_next_merge_for_testing_)) {
    // This GC is only synchronous on the main thread at the moment.
    DCHECK(isolate->is_main_thread());
    local_heap->AsHeap()->CollectAllAvailableGarbage(
        GarbageCollectionReason::kTesting);
  }

  if (forwarder.HasAnythingToForward()) {
    for (DirectHandle<SharedFunctionInfo> new_sfi : used_new_sfis_) {
      forwarder.UpdateScopeInfo(*new_sfi);
    }
    for (const auto& new_compiled_data : new_compiled_data_for_cached_sfis_) {
      // It's possible that new_compiled_data.cached_sfi had
      // scope_info()->IsEmpty() while an inner function has scope info if the
      // cached_sfi was recreated when an outer function was recompiled. If so,
      // new_compiled_data.new_sfi does not have a reused scope info yet, and
      // we'll have found it when we visited the inner function. Try to pick it
      // up here.
      forwarder.InstallOwnScopeInfo(*new_compiled_data.new_sfi);
    }
    forwarder.IterateAndForwardPointers();
  }
  persistent_handles_ = local_heap->DetachPersistentHandles();
  state_ = kPendingForegroundWork;
}

Handle<SharedFunctionInfo> BackgroundMergeTask::CompleteMergeInForeground(
    Isolate* isolate, DirectHandle<Script> new_script) {
  DCHECK_EQ(state_, kPendingForegroundWork);

  HandleScope handle_scope(isolate);
  DirectHandle<Script> old_script = cached_script_.ToHandleChecked();
  ConstantPoolPointerForwarder forwarder(
      isolate, isolate->main_thread_local_heap(), old_script);

  for (const auto& new_compiled_data : new_compiled_data_for_cached_sfis_) {
    Tagged<SharedFunctionInfo> sfi = *new_compiled_data.cached_sfi;
    if (!sfi->is_compiled() && new_compiled_data.new_sfi->is_compiled()) {
      // Updating existing DebugInfos is not supported, but we don't expect
      // uncompiled SharedFunctionInfos to contain DebugInfos.
      DCHECK(!new_compiled_data.cached_sfi->HasDebugInfo(isolate));
      // The goal here is to copy every field except script from
      // new_sfi to cached_sfi. The safest way to do so (including a DCHECK that
      // no fields were skipped) is to first copy the script from
      // cached_sfi to new_sfi, and then copy every field using CopyFrom.
      new_compiled_data.new_sfi->set_script(sfi->script(kAcquireLoad),
                                            kReleaseStore);
      sfi->CopyFrom(*new_compiled_data.new_sfi, isolate);
    }
  }

  for (int i = 0; i < old_script->infos()->length(); ++i) {
    Tagged<MaybeObject> maybe_old_info = old_script->infos()->get(i);
    Tagged<MaybeObject> maybe_new_info = new_script->infos()->get(i);
    if (maybe_new_info == maybe_old_info) continue;
    DisallowGarbageCollection no_gc;
    if (maybe_old_info.IsWeak()) {
      // The old script's SFI didn't exist during the background work, but does
      // now. This means a re-merge is necessary. Potential references to the
      // new script's SFI need to be updated to point to the cached script's SFI
      // instead. The cached script's SFI's outer scope infos need to be used by
      // the new script's outer SFIs.
      if (Is<SharedFunctionInfo>(maybe_old_info.GetHeapObjectAssumeWeak())) {
        forwarder.set_has_shared_function_info_to_forward();
      }
      forwarder.RecordScopeInfos(maybe_old_info);
    } else {
      old_script->infos()->set(i, maybe_new_info);
    }
  }

  // Most of the time, the background merge was sufficient. However, if there
  // are any new pointers that need forwarding, a new traversal of the constant
  // pools is required.
  if (forwarder.HasAnythingToForward()) {
    for (DirectHandle<SharedFunctionInfo> new_sfi : used_new_sfis_) {
      forwarder.UpdateScopeInfo(*new_sfi);
      if (new_sfi->HasBytecodeArray(isolate)) {
        forwarder.AddBytecodeArray(new_sfi->GetBytecodeArray(isolate));
      }
    }
    for (const auto& new_compiled_data : new_compiled_data_for_cached_sfis_) {
      // It's possible that cached_sfi wasn't compiled, but an inner function
      // existed that didn't exist when be background merged. In that case, pick
      // up the relevant scope infos.
      Tagged<SharedFunctionInfo> sfi = *new_compiled_data.cached_sfi;
      forwarder.InstallOwnScopeInfo(sfi);
      if (new_compiled_data.cached_sfi->HasBytecodeArray(isolate)) {
        forwarder.AddBytecodeArray(
            new_compiled_data.cached_sfi->GetBytecodeArray(isolate));
      }
    }
    forwarder.IterateAndForwardPointers();
  }

  Tagged<MaybeObject> maybe_toplevel_sfi =
      old_script->infos()->get(kFunctionLiteralIdTopLevel);
  CHECK(maybe_toplevel_sfi.IsWeak());
  Handle<SharedFunctionInfo> result = handle(
      Cast<SharedFunctionInfo>(maybe_toplevel_sfi.GetHeapObjectAssumeWeak()),
      isolate);

  state_ = kDone;

  if (isolate->NeedsSourcePositions()) {
    Script::InitLineEnds(isolate, new_script);
    SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, result);
  }

#ifdef DEBUG
  VerifyCodeMerge(isolate, old_script);
#else
  if (v8_flags.verify_code_merge) {
    VerifyCodeMerge(isolate, old_script);
  }
#endif

  return handle_scope.CloseAndEscape(result);
}

MaybeHandle<SharedFunctionInfo> BackgroundCompileTask::FinalizeScript(
    Isolate* isolate, DirectHandle<String> source,
    const ScriptDetails& script_details,
    MaybeHandle<Script> maybe_cached_script) {
  ScriptOriginOptions origin_options = script_details.origin_options;

  DCHECK(flags_.is_toplevel());
  DCHECK_EQ(flags_.is_module(), origin_options.IsModule());

  MaybeHandle<SharedFunctionInfo> maybe_result;
  Handle<Script> script = script_;

  // We might not have been able to finalize all jobs on the background
  // thread (e.g. asm.js jobs), so finalize those deferred jobs now.
  if (FinalizeDeferredUnoptimizedCompilationJobs(
          isolate, script, &jobs_to_retry_finalization_on_main_thread_,
          compile_state_.pending_error_handler(),
          &finalize_unoptimized_compilation_data_)) {
    maybe_result = outer_function_sfi_;
  }

  if (Handle<Script> cached_script;
      maybe_cached_script.ToHandle(&cached_script) && !maybe_result.is_null()) {
    BackgroundMergeTask merge;
    merge.SetUpOnMainThread(isolate, cached_script);
    CHECK(merge.HasPendingBackgroundWork());
    merge.BeginMergeInBackground(isolate->AsLocalIsolate(), script);
    CHECK(merge.HasPendingForegroundWork());
    Handle<SharedFunctionInfo> result =
        merge.CompleteMergeInForeground(isolate, script);
    maybe_result = result;
    script = handle(Cast<Script>(result->script()), isolate);
    DCHECK(Object::StrictEquals(script->source(), *source));
    DCHECK(isolate->factory()->script_list()->Contains(MakeWeak(*script)));
  } else {
    Script::SetSource(isolate, script, source);
    script->set_origin_options(origin_options);

    // The one post-hoc fix-up: Add the script to the script list.
    Handle<WeakArrayList> scripts = isolate->factory()->script_list();
    scripts = WeakArrayList::Append(isolate, scripts,
                                    MaybeObjectDirectHandle::Weak(script));
    isolate->heap()->SetRootScriptList(*scripts);

    // Set the script fields after finalization, to keep this path the same
    // between main-thread and off-thread finalization.
    {
      DisallowGarbageCollection no_gc;
      SetScriptFieldsFromDetails(isolate, *script, script_details, &no_gc);
      LOG(isolate, ScriptDetails(*script));
    }
  }

  ReportStatistics(isolate);

  Handle<SharedFunctionInfo> result;
  if (!maybe_result.ToHandle(&result)) {
    FailWithPreparedException(isolate, script,
                              compile_state_.pending_error_handler());
    return kNullMaybeHandle;
  }

  FinalizeUnoptimizedScriptCompilation(isolate, script, flags_, &compile_state_,
                                       finalize_unoptimized_compilation_data_);

  return handle(*result, isolate);
}

bool BackgroundCompileTask::FinalizeFunction(
    Isolate* isolate, Compiler::ClearExceptionFlag flag) {
  DCHECK(!flags_.is_toplevel());

  MaybeHandle<SharedFunctionInfo> maybe_result;
  DirectHandle<SharedFunctionInfo> input_shared_info =
      input_shared_info_.ToHandleChecked();

  // The UncompiledData on the input SharedFunctionInfo will have a pointer to
  // the LazyCompileDispatcher Job that launched this task, which will now be
  // considered complete, so clear that regardless of whether the finalize
  // succeeds or not.
  input_shared_info->ClearUncompiledDataJobPointer(isolate);

  // We might not have been able to finalize all jobs on the background
  // thread (e.g. asm.js jobs), so finalize those deferred jobs now.
  if (FinalizeDeferredUnoptimizedCompilationJobs(
          isolate, script_, &jobs_to_retry_finalization_on_main_thread_,
          compile_state_.pending_error_handler(),
          &finalize_unoptimized_compilation_data_)) {
    maybe_result = outer_function_sfi_;
  }

  ReportStatistics(isolate);

  Handle<SharedFunctionInfo> result;
  if (!maybe_result.ToHandle(&result)) {
    FailWithPreparedException(isolate, script_,
                              compile_state_.pending_error_handler(), flag);
    return false;
  }

  FinalizeUnoptimizedCompilation(isolate, script_, flags_, &compile_state_,
                                 finalize_unoptimized_compilation_data_);

  // Move the compiled data from the placeholder SFI back to the real SFI.
  input_shared_info->CopyFrom(*result, isolate);

  return true;
}

void BackgroundCompileTask::AbortFunction() {
  // The UncompiledData on the input SharedFunctionInfo will have a pointer to
  // the LazyCompileDispatcher Job that launched this task, which is about to be
  // deleted, so clear that to avoid the SharedFunctionInfo from pointing to
  // deallocated memory.
  input_shared_info_.ToHandleChecked()->ClearUncompiledDataJobPointer(
      isolate_for_local_isolate_);
}

void BackgroundCompileTask::ReportStatistics(Isolate* isolate) {
  // Update use-counts.
  for (auto feature : use_counts_) {
    isolate->CountUsage(feature);
  }
}

BackgroundDeserializeTask::BackgroundDeserializeTask(
    Isolate* isolate, std::unique_ptr<ScriptCompiler::CachedData> cached_data)
    : isolate_for_local_isolate_(isolate),
      cached_data_(cached_data->data, cached_data->length),
      timer_(isolate->counters()->deserialize_script_on_background()) {
  // If the passed in cached data has ownership of the buffer, move it to the
  // task.
  if (cached_data->buffer_policy == ScriptCompiler::CachedData::BufferOwned &&
      !cached_data_.HasDataOwnership()) {
    cached_data->buffer_policy = ScriptCompiler::CachedData::BufferNotOwned;
    cached_data_.AcquireDataOwnership();
  }
}

void BackgroundDeserializeTask::Run() {
  TimedHistogramScope timer(timer_, nullptr, &background_time_in_microseconds_);
  LocalIsolate isolate(isolate_for_local_isolate_, ThreadKind::kBackground);
  UnparkedScope unparked_scope(&isolate);
  LocalHandleScope handle_scope(&isolate);

  DirectHandle<SharedFunctionInfo> inner_result;
  off_thread_data_ =
      CodeSerializer::StartDeserializeOffThread(&isolate, &cached_data_);
  if (v8_flags.enable_slow_asserts && off_thread_data_.HasResult()) {
#ifdef ENABLE_SLOW_DCHECKS
    MergeAssumptionChecker checker(&isolate);
    checker.IterateObjects(*off_thread_data_.GetOnlyScript(isolate.heap()));
#endif
  }
}

void BackgroundDeserializeTask::SourceTextAvailable(
    Isolate* isolate, Handle<String> source_text,
    const ScriptDetails& script_details) {
  DCHECK_EQ(isolate, isolate_for_local_isolate_);
  LanguageMode language_mode = construct_language_mode(v8_flags.use_strict);
  background_merge_task_.SetUpOnMainThread(isolate, source_text, script_details,
                                           language_mode);
}

bool BackgroundDeserializeTask::ShouldMergeWithExistingScript() const {
  DCHECK(v8_flags.merge_background_deserialized_script_with_compilation_cache);
  return background_merge_task_.HasPendingBackgroundWork() &&
         off_thread_data_.HasResult();
}

void BackgroundDeserializeTask::MergeWithExistingScript() {
  DCHECK(ShouldMergeWithExistingScript());

  LocalIsolate isolate(isolate_for_local_isolate_, ThreadKind::kBackground);
  UnparkedScope unparked_scope(&isolate);
  LocalHandleScope handle_scope(isolate.heap());

  background_merge_task_.BeginMergeInBackground(
      &isolate, off_thread_data_.GetOnlyScript(isolate.heap()));
}

MaybeHandle<SharedFunctionInfo> BackgroundDeserializeTask::Finish(
    Isolate* isolate, DirectHandle<String> source,
    const ScriptDetails& script_details) {
  return CodeSerializer::FinishOffThreadDeserialize(
      isolate, std::move(off_thread_data_), &cached_data_, source,
      script_details, &background_merge_task_);
}

// ----------------------------------------------------------------------------
// Implementation of Compiler

// static
bool Compiler::CollectSourcePositions(Isolate* isolate,
                                      Handle<SharedFunctionInfo> shared_info) {
  DCHECK(shared_info->is_compiled());
  DCHECK(shared_info->HasBytecodeArray());
  DCHECK(!shared_info->GetBytecodeArray(isolate)->HasSourcePositionTable());

  // Source position collection should be context independent.
  NullContextScope null_context_scope(isolate);

  // Collecting source positions requires allocating a new source position
  // table.
  DCHECK(AllowHeapAllocation::IsAllowed());

  Handle<BytecodeArray> bytecode =
      handle(shared_info->GetBytecodeArray(isolate), isolate);

  // TODO(v8:8510): Push the CLEAR_EXCEPTION flag or something like it down into
  // the parser so it aborts without setting an exception, which then
  // gets thrown. This would avoid the situation where potentially we'd reparse
  // several times (running out of stack each time) before hitting this limit.
  if (GetCurrentStackPosition() < isolate->stack_guard()->real_climit()) {
    // Stack is already exhausted.
    bytecode->SetSourcePositionsFailedToCollect();
    return false;
  }

  // Unfinalized scripts don't yet have the proper source string attached and
  // thus can't be reparsed.
  if (Cast<Script>(shared_info->script())->IsMaybeUnfinalized(isolate)) {
    bytecode->SetSourcePositionsFailedToCollect();
    return false;
  }

  DCHECK(AllowCompilation::IsAllowed(isolate));
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());

  DCHECK(!isolate->has_exception());
  VMState<BYTECODE_COMPILER> state(isolate);
  PostponeInterruptsScope postpone(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileCollectSourcePositions);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.CollectSourcePositions");
  NestedTimedHistogramScope timer(
      isolate->counters()->collect_source_positions());

  // Set up parse info.
  UnoptimizedCompileFlags flags =
      UnoptimizedCompileFlags::ForFunctionCompile(isolate, *shared_info);
  flags.set_collect_source_positions(true);
  flags.set_is_reparse(true);
  // Prevent parallel tasks from being spawned by this job.
  flags.set_post_parallel_compile_tasks_for_eager_toplevel(false);
  flags.set_post_parallel_compile_tasks_for_lazy(false);

  UnoptimizedCompileState compile_state;
  ReusableUnoptimizedCompileState reusable_state(isolate);
  ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);

  // Parse and update ParseInfo with the results. Don't update parsing
  // statistics since we've already parsed the code before.
  if (!parsing::ParseAny(&parse_info, shared_info, isolate,
                         parsing::ReportStatisticsMode::kNo)) {
    // Parsing failed probably as a result of stack exhaustion.
    bytecode->SetSourcePositionsFailedToCollect();
    return FailAndClearException(isolate);
  }

  // Character stream shouldn't be used again.
  parse_info.ResetCharacterStream();

  // Generate the unoptimized bytecode.
  // TODO(v8:8510): Consider forcing preparsing of inner functions to avoid
  // wasting time fully parsing them when they won't ever be used.
  std::unique_ptr<UnoptimizedCompilationJob> job;
  {
    job = interpreter::Interpreter::NewSourcePositionCollectionJob(
        &parse_info, parse_info.literal(), bytecode, isolate->allocator(),
        isolate->main_thread_local_isolate());

    if (!job || job->ExecuteJob() != CompilationJob::SUCCEEDED ||
        job->FinalizeJob(shared_info, isolate) != CompilationJob::SUCCEEDED) {
      // Recompiling failed probably as a result of stack exhaustion.
      bytecode->SetSourcePositionsFailedToCollect();
      return FailAndClearException(isolate);
    }
  }

  DCHECK(job->compilation_info()->flags().collect_source_positions());

  // If debugging, make sure that instrumented bytecode has the source position
  // table set on it as well.
  if (std::optional<Tagged<DebugInfo>> debug_info =
          shared_info->TryGetDebugInfo(isolate)) {
    if (debug_info.value()->HasInstrumentedBytecodeArray()) {
      Tagged<TrustedByteArray> source_position_table =
          job->compilation_info()->bytecode_array()->SourcePositionTable();
      shared_info->GetActiveBytecodeArray(isolate)->set_source_position_table(
          source_position_table, kReleaseStore);
    }
  }

  DCHECK(!isolate->has_exception());
  DCHECK(shared_info->is_compiled_scope(isolate).is_compiled());
  return true;
}

// static
bool Compiler::Compile(Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
                       ClearExceptionFlag flag,
                       IsCompiledScope* is_compiled_scope,
                       CreateSourcePositions create_source_positions_flag) {
  // We should never reach here if the function is already compiled.
  DCHECK(!shared_info->is_compiled());
  DCHECK(!is_compiled_scope->is_compiled());
  DCHECK(AllowCompilation::IsAllowed(isolate));
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  DCHECK(!isolate->has_exception());
  DCHECK(!shared_info->HasBytecodeArray());

  VMState<BYTECODE_COMPILER> state(isolate);
  PostponeInterruptsScope postpone(isolate);
  TimerEventScope<TimerEventCompileCode> compile_timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileFunction);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.CompileCode");
  AggregatedHistogramTimerScope timer(isolate->counters()->compile_lazy());

  Handle<Script> script(Cast<Script>(shared_info->script()), isolate);

  // Set up parse info.
  UnoptimizedCompileFlags flags =
      UnoptimizedCompileFlags::ForFunctionCompile(isolate, *shared_info);
  if (create_source_positions_flag == CreateSourcePositions::kYes) {
    flags.set_collect_source_positions(true);
  }

  UnoptimizedCompileState compile_state;
  ReusableUnoptimizedCompileState reusable_state(isolate);
  ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);

  // Check if the compiler dispatcher has shared_info enqueued for compile.
  LazyCompileDispatcher* dispatcher = isolate->lazy_compile_dispatcher();
  if (dispatcher && dispatcher->IsEnqueued(shared_info)) {
    if (!dispatcher->FinishNow(shared_info)) {
      return FailWithException(isolate, script, &parse_info, flag);
    }
    *is_compiled_scope = shared_info->is_compiled_scope(isolate);
    DCHECK(is_compiled_scope->is_compiled());
    return true;
  }

  if (shared_info->HasUncompiledDataWithPreparseData()) {
    parse_info.set_consumed_preparse_data(ConsumedPreparseData::For(
        isolate, handle(shared_info->uncompiled_data_with_preparse_data(isolate)
                            ->preparse_data(),
                        isolate)));
  }

  // Parse and update ParseInfo with the results.
  if (!parsing::ParseAny(&parse_info, shared_info, isolate,
                         parsing::ReportStatisticsMode::kYes)) {
    return FailWithException(isolate, script, &parse_info, flag);
  }
  parse_info.literal()->set_shared_function_info(shared_info);

  // Generate the unoptimized bytecode or asm-js data.
  FinalizeUnoptimizedCompilationDataList
      finalize_unoptimized_compilation_data_list;

  if (!IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs(
          isolate, script, &parse_info, isolate->allocator(), is_compiled_scope,
          &finalize_unoptimized_compilation_data_list, nullptr)) {
    return FailWithException(isolate, script, &parse_info, flag);
  }

  FinalizeUnoptimizedCompilation(isolate, script, flags, &compile_state,
                                 finalize_unoptimized_compilation_data_list);

  if (v8_flags.always_sparkplug) {
    CompileAllWithBaseline(isolate, finalize_unoptimized_compilation_data_list);
  }

  if (script->produce_compile_hints()) {
    // Log lazy funtion compilation.
    Handle<ArrayList> list;
    if (IsUndefined(script->compiled_lazy_function_positions())) {
      constexpr int kInitialLazyFunctionPositionListSize = 100;
      list = ArrayList::New(isolate, kInitialLazyFunctionPositionListSize);
    } else {
      list = handle(Cast<ArrayList>(script->compiled_lazy_function_positions()),
                    isolate);
    }
    list = ArrayList::Add(isolate, list,
                          Smi::FromInt(shared_info->StartPosition()));
    script->set_compiled_lazy_function_positions(*list);
  }

  DCHECK(!isolate->has_exception());
  DCHECK(is_compiled_scope->is_compiled());
  return true;
}

// static
bool Compiler::Compile(Isolate* isolate, Handle<JSFunction> function,
                       ClearExceptionFlag flag,
                       IsCompiledScope* is_compiled_scope) {
  // We should never reach here if the function is already compiled or
  // optimized.
  DCHECK(!function->is_compiled(isolate));
  DCHECK_IMPLIES(function->has_feedback_vector() &&
                     function->IsTieringRequestedOrInProgress(isolate),
                 function->shared()->is_compiled());
  DCHECK_IMPLIES(function->HasAvailableOptimizedCode(isolate),
                 function->shared()->is_compiled());

  // Reset the JSFunction if we are recompiling due to the bytecode having been
  // flushed.
  function->ResetIfCodeFlushed(isolate);

  Handle<SharedFunctionInfo> shared_info(function->shared(), isolate);

  // Ensure shared function info is compiled.
  *is_compiled_scope = shared_info->is_compiled_scope(isolate);
  if (!is_compiled_scope->is_compiled() &&
      !Compile(isolate, shared_info, flag, is_compiled_scope)) {
    return false;
  }

  DCHECK(is_compiled_scope->is_compiled());
  DirectHandle<Code> code(shared_info->GetCode(isolate), isolate);

  // Initialize the feedback cell for this JSFunction and reset the interrupt
  // budget for feedback vector allocation even if there is a closure feedback
  // cell array. We are re-compiling when we have a closure feedback cell array
  // which means we are compiling after a bytecode flush.
  // TODO(verwaest/mythria): Investigate if allocating feedback vector
  // immediately after a flush would be better.
  JSFunction::InitializeFeedbackCell(function, is_compiled_scope, true);
  function->ResetTieringRequests(isolate);

  // Optimize now if --always-turbofan is enabled.
#if V8_ENABLE_WEBASSEMBLY
  if (v8_flags.always_turbofan && !function->shared()->HasAsmWasmData()) {
#else
  if (v8_flags.always_turbofan) {
#endif  // V8_ENABLE_WEBASSEMBLY
    CompilerTracer::TraceOptimizeForAlwaysOpt(isolate, function,
                                              CodeKindForTopTier());

    const CodeKind code_kind = CodeKindForTopTier();
    const ConcurrencyMode concurrency_mode = ConcurrencyMode::kSynchronous;

    if (v8_flags.stress_concurrent_inlining &&
        isolate->concurrent_recompilation_enabled() &&
        isolate->node_observer() == nullptr) {
      SpawnDuplicateConcurrentJobForStressTesting(isolate, function,
                                                  concurrency_mode, code_kind);
    }

    Handle<Code> maybe_code;
    if (GetOrCompileOptimized(isolate, function, concurrency_mode, code_kind)
            .ToHandle(&maybe_code)) {
      code = maybe_code;
    }

    function->UpdateMaybeContextSpecializedCode(isolate, *code);
  } else {
    function->UpdateCode(*code);
  }

  // Install a feedback vector if necessary.
  if (code->kind() == CodeKind::BASELINE) {
    JSFunction::EnsureFeedbackVector(isolate, function, is_compiled_scope);
  }

  // Check postconditions on success.
  DCHECK(!isolate->has_exception());
  DCHECK(function->shared()->is_compiled());
  DCHECK(function->is_compiled(isolate));
  return true;
}

// static
bool Compiler::CompileSharedWithBaseline(Isolate* isolate,
                                         Handle<SharedFunctionInfo> shared,
                                         Compiler::ClearExceptionFlag flag,
                                         IsCompiledScope* is_compiled_scope) {
  // We shouldn't be passing uncompiled functions into this function.
  DCHECK(is_compiled_scope->is_compiled());

  // Early return for already baseline-compiled functions.
  if (shared->HasBaselineCode()) return true;

  // Check if we actually can compile with baseline.
  if (!CanCompileWithBaseline(isolate, *shared)) return false;

  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed(kStackSpaceRequiredForCompilation * KB)) {
    if (flag == Compiler::KEEP_EXCEPTION) {
      isolate->StackOverflow();
    }
    return false;
  }

  CompilerTracer::TraceStartBaselineCompile(isolate, shared);
  Handle<Code> code;
  base::TimeDelta time_taken;
  {
    base::ScopedTimer timer(
        v8_flags.trace_baseline || v8_flags.log_function_events ? &time_taken
                                                                : nullptr);
    if (!GenerateBaselineCode(isolate, shared).ToHandle(&code)) {
      // TODO(leszeks): This can only fail because of an OOM. Do we want to
      // report these somehow, or silently ignore them?
      return false;
    }
    shared->set_baseline_code(*code, kReleaseStore);
    shared->set_age(0);
  }
  double time_taken_ms = time_taken.InMillisecondsF();

  CompilerTracer::TraceFinishBaselineCompile(isolate, shared, time_taken_ms);

  if (IsScript(shared->script())) {
    LogFunctionCompilation(isolate, LogEventListener::CodeTag::kFunction,
                           handle(Cast<Script>(shared->script()), isolate),
                           shared, Handle<FeedbackVector>(),
                           Cast<AbstractCode>(code), CodeKind::BASELINE,
                           time_taken_ms);
  }
  return true;
}

// static
bool Compiler::CompileBaseline(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               ClearExceptionFlag flag,
                               IsCompiledScope* is_compiled_scope) {
  Handle<SharedFunctionInfo> shared(function->shared(isolate), isolate);
  if (!CompileSharedWithBaseline(isolate, shared, flag, is_compiled_scope)) {
    return false;
  }

  // Baseline code needs a feedback vector.
  JSFunction::EnsureFeedbackVector(isolate, function, is_compiled_scope);

  Tagged<Code> baseline_code = shared->baseline_code(kAcquireLoad);
  DCHECK_EQ(baseline_code->kind(), CodeKind::BASELINE);
  function->UpdateCodeKeepTieringRequests(baseline_code);
  return true;
}

// static
MaybeHandle<SharedFunctionInfo> Compiler::CompileToplevel(
    ParseInfo* parse_info, Handle<Script> script, Isolate* isolate,
    IsCompiledScope* is_compiled_scope) {
  return v8::internal::CompileToplevel(parse_info, script, kNullMaybeHandle,
                                       isolate, is_compiled_scope);
}

// static
bool Compiler::FinalizeBackgroundCompileTask(BackgroundCompileTask* task,
                                             Isolate* isolate,
                                             ClearExceptionFlag flag) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.FinalizeBackgroundCompileTask");
  RCS_SCOPE(isolate,
            RuntimeCallCounterId::kCompileFinalizeBackgroundCompileTask);

  HandleScope scope(isolate);

  if (!task->FinalizeFunction(isolate, flag)) return false;

  DCHECK(!isolate->has_exception());
  return true;
}

// static
void Compiler::CompileOptimized(Isolate* isolate, Handle<JSFunction> function,
                                ConcurrencyMode mode, CodeKind code_kind) {
  DCHECK(CodeKindIsOptimizedJSFunction(code_kind));
  DCHECK(AllowCompilation::IsAllowed(isolate));

  if (v8_flags.stress_concurrent_inlining &&
      isolate->concurrent_recompilation_enabled() && IsSynchronous(mode) &&
      isolate->node_observer() == nullptr) {
    SpawnDuplicateConcurrentJobForStressTesting(isolate, function, mode,
                                                code_kind);
  }

#ifdef DEBUG
  if (V8_ENABLE_LEAPTIERING_BOOL && mode == ConcurrencyMode::kConcurrent) {
    DCHECK_IMPLIES(code_kind == CodeKind::MAGLEV,
                   !function->ActiveTierIsMaglev(isolate));
    DCHECK_IMPLIES(code_kind == CodeKind::TURBOFAN_JS,
                   !function->ActiveTierIsTurbofan(isolate));
  }
  bool tiering_was_in_progress = function->tiering_in_progress();
  DCHECK_IMPLIES(tiering_was_in_progress, mode != ConcurrencyMode::kConcurrent);
#endif  // DEBUG

  Handle<Code> code;
  if (GetOrCompileOptimized(isolate, function, mode, code_kind)
          .ToHandle(&code)) {
    function->UpdateMaybeContextSpecializedCode(isolate, *code);
    DCHECK_IMPLIES(v8_flags.log_function_events,
                   function->IsLoggingRequested(isolate));
  } else {
#ifdef V8_ENABLE_LEAPTIERING
    // We can get here from CompileLazy when we have requested optimized code
    // which isn't yet ready. Without Leaptiering, we'll already have set the
    // function's code to the bytecode/baseline code on the SFI. However, in the
    // leaptiering case, we potentially need to do this now.
    if (!function->is_compiled(isolate)) {
      function->UpdateCodeKeepTieringRequests(
          function->shared()->GetCode(isolate));
    }
#endif  // V8_ENABLE_LEAPTIERING
  }

#ifdef DEBUG
  DCHECK(!isolate->has_exception());
  DCHECK(function->is_compiled(isolate));
  DCHECK(function->shared()->HasBytecodeArray());

  DCHECK_IMPLIES(function->IsTieringRequestedOrInProgress(isolate) &&
                     !function->IsLoggingRequested(isolate),
                 function->tiering_in_progress());
  DCHECK_IMPLIES(!tiering_was_in_progress && function->tiering_in_progress(),
                 function->ChecksTieringState(isolate));
  DCHECK_IMPLIES(!tiering_was_in_progress && function->tiering_in_progress(),
                 IsConcurrent(mode));
#endif  // DEBUG
}

// static
MaybeHandle<SharedFunctionInfo> Compiler::CompileForLiveEdit(
    ParseInfo* parse_info, Handle<Script> script,
    MaybeHandle<ScopeInfo> outer_scope_info, Isolate* isolate) {
  IsCompiledScope is_compiled_scope;
  return v8::internal::CompileToplevel(parse_info, script, outer_scope_info,
```