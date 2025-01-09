Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `v8/src/debug/debug.cc`.

Here's a breakdown of the code's key functionalities:

1. **Breakpoints:**  The code heavily revolves around setting, managing, and triggering breakpoints in JavaScript and WebAssembly code.
2. **Stepping:**  It implements various stepping actions like Step Into, Step Over, and Step Out, controlling the execution flow during debugging.
3. **Exception Handling:** The code allows breaking on caught or uncaught exceptions.
4. **Muting Breakpoints:** It provides a mechanism to temporarily ignore breakpoints at specific locations.
5. **Instrumentation Breakpoints:**  It supports a special type of breakpoint for instrumentation purposes.
6. **Blackboxing:** It interacts with the concept of "blackboxing" functions, which are excluded from debugging.
7. **Debug Information Management:**  It handles the storage and retrieval of debug-related information for functions.
8. **Integration with WebAssembly Debugging:**  It includes specific logic for handling breakpoints and stepping in WebAssembly modules.

Based on this analysis, I will formulate a summary that covers these aspects and provides illustrative JavaScript examples where applicable.```cpp
// k location, we also do not trigger one for debugger statements, nor
// an exception event on exception at this location.
// This should have been computed at last break, and we should just
// check that we are not at that location.

if (IsSmi(thread_local_.muted_function_) ||
    *function != thread_local_.muted_function_) {
  return false;
}

for (const BreakLocation& location : locations) {
  if (location.position() == thread_local_.muted_position_) {
    return true;
  }
}

return false;
}

#if V8_ENABLE_WEBASSEMBLY
void Debug::SetMutedWasmLocation(DirectHandle<Script> script, int position) {
thread_local_.muted_function_ = *script;
thread_local_.muted_position_ = position;
}

bool Debug::IsMutedAtWasmLocation(Tagged<Script> script, int position) {
return script == thread_local_.muted_function_ &&
       position == thread_local_.muted_position_;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

// Convenience helper for easier std::optional translation.
bool ToHandle(Isolate* isolate, std::optional<Tagged<DebugInfo>> debug_info,
            Handle<DebugInfo>* out) {
if (!debug_info.has_value()) return false;
*out = handle(debug_info.value(), isolate);
return true;
}

}  // namespace

// Check whether a single break point object is triggered.
bool Debug::CheckBreakPoint(DirectHandle<BreakPoint> break_point,
                          bool is_break_at_entry) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
HandleScope scope(isolate_);

// Instrumentation breakpoints are handled separately.
if (break_point->id() == kInstrumentationId) {
  return false;
}

if (!break_point->condition()->length()) return true;
Handle<String> condition(break_point->condition(), isolate_);
MaybeHandle<Object> maybe_result;
Handle<Object> result;

if (is_break_at_entry) {
  maybe_result = DebugEvaluate::WithTopmostArguments(isolate_, condition);
} else {
  // Since we call CheckBreakpoint only for deoptimized frame on top of stack,
  // we can use 0 as index of inlined frame.
  const int inlined_jsframe_index = 0;
  const bool throw_on_side_effect = false;
  maybe_result =
      DebugEvaluate::Local(isolate_, break_frame_id(), inlined_jsframe_index,
                           condition, throw_on_side_effect);
}

Handle<Object> maybe_exception;
bool exception_thrown = true;
if (maybe_result.ToHandle(&result)) {
  exception_thrown = false;
} else if (isolate_->has_exception()) {
  maybe_exception = handle(isolate_->exception(), isolate_);
  isolate_->clear_exception();
}

CHECK(in_debug_scope());
DisableBreak no_recursive_break(this);

{
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
  debug_delegate_->BreakpointConditionEvaluated(
      v8::Utils::ToLocal(isolate_->native_context()), break_point->id(),
      exception_thrown, v8::Utils::ToLocal(maybe_exception));
}

return !result.is_null() ? Object::BooleanValue(*result, isolate_) : false;
}

bool Debug::SetBreakpoint(Handle<SharedFunctionInfo> shared,
                        DirectHandle<BreakPoint> break_point,
                        int* source_position) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
HandleScope scope(isolate_);

// Make sure the function is compiled and has set up the debug info.
if (!EnsureBreakInfo(shared)) return false;
PrepareFunctionForDebugExecution(shared);

Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
// Source positions starts with zero.
DCHECK_LE(0, *source_position);

// Find the break point and change it.
*source_position = FindBreakablePosition(debug_info, *source_position);
DebugInfo::SetBreakPoint(isolate_, debug_info, *source_position, break_point);
// At least one active break point now.
DCHECK_LT(0, debug_info->GetBreakPointCount(isolate_));

ClearBreakPoints(debug_info);
ApplyBreakPoints(debug_info);
return true;
}

bool Debug::SetBreakPointForScript(Handle<Script> script,
                                 DirectHandle<String> condition,
                                 int* source_position, int* id) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
*id = ++thread_local_.last_breakpoint_id_;
DirectHandle<BreakPoint> break_point =
    isolate_->factory()->NewBreakPoint(*id, condition);
#if V8_ENABLE_WEBASSEMBLY
if (script->type() == Script::Type::kWasm) {
  RecordWasmScriptWithBreakpoints(script);
  return WasmScript::SetBreakPoint(script, source_position, break_point);
}
#endif  //  V8_ENABLE_WEBASSEMBLY

HandleScope scope(isolate_);

// Obtain shared function info for the innermost function containing this
// position.
Handle<Object> result =
    FindInnermostContainingFunctionInfo(script, *source_position);
if (IsUndefined(*result, isolate_)) return false;

auto shared = Cast<SharedFunctionInfo>(result);
if (!EnsureBreakInfo(shared)) return false;
PrepareFunctionForDebugExecution(shared);

// Find the nested shared function info that is closest to the position within
// the containing function.
shared = FindClosestSharedFunctionInfoFromPosition(*source_position, script,
                                                   shared);

// Set the breakpoint in the function.
return SetBreakpoint(shared, break_point, source_position);
}

int Debug::FindBreakablePosition(Handle<DebugInfo> debug_info,
                               int source_position) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (debug_info->CanBreakAtEntry()) {
  return kBreakAtEntryPosition;
} else {
  DCHECK(debug_info->HasInstrumentedBytecodeArray());
  BreakIterator it(debug_info);
  it.SkipToPosition(source_position);
  return it.position();
}
}

void Debug::ApplyBreakPoints(Handle<DebugInfo> debug_info) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
DisallowGarbageCollection no_gc;
if (debug_info->CanBreakAtEntry()) {
  debug_info->SetBreakAtEntry();
} else {
  if (!debug_info->HasInstrumentedBytecodeArray()) return;
  Tagged<FixedArray> break_points = debug_info->break_points();
  for (int i = 0; i < break_points->length(); i++) {
    if (IsUndefined(break_points->get(i), isolate_)) continue;
    Tagged<BreakPointInfo> info = Cast<BreakPointInfo>(break_points->get(i));
    if (info->GetBreakPointCount(isolate_) == 0) continue;
    DCHECK(debug_info->HasInstrumentedBytecodeArray());
    BreakIterator it(debug_info);
    it.SkipToPosition(info->source_position());
    it.SetDebugBreak();
  }
}
debug_info->SetDebugExecutionMode(DebugInfo::kBreakpoints);
}

void Debug::ClearBreakPoints(Handle<DebugInfo> debug_info) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (debug_info->CanBreakAtEntry()) {
  debug_info->ClearBreakAtEntry();
} else {
  // If we attempt to clear breakpoints but none exist, simply return. This
  // can happen e.g. CoverageInfos exist but no breakpoints are set.
  if (!debug_info->HasInstrumentedBytecodeArray() ||
      !debug_info->HasBreakInfo()) {
    return;
  }

  DisallowGarbageCollection no_gc;
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    it.ClearDebugBreak();
  }
}
}

void Debug::ClearBreakPoint(DirectHandle<BreakPoint> break_point) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
HandleScope scope(isolate_);

DebugInfoCollection::Iterator it(&debug_infos_);
for (; it.HasNext(); it.Advance()) {
  Handle<DebugInfo> debug_info(it.Next(), isolate_);
  if (!debug_info->HasBreakInfo()) continue;

  DirectHandle<Object> result =
      DebugInfo::FindBreakPointInfo(isolate_, debug_info, break_point);
  if (IsUndefined(*result, isolate_)) continue;

  if (DebugInfo::ClearBreakPoint(isolate_, debug_info, break_point)) {
    ClearBreakPoints(debug_info);
    if (debug_info->GetBreakPointCount(isolate_) == 0) {
      debug_info->ClearBreakInfo(isolate_);
      if (debug_info->IsEmpty()) it.DeleteNext();
    } else {
      ApplyBreakPoints(debug_info);
    }
    return;
  }
}
}

int Debug::GetFunctionDebuggingId(DirectHandle<JSFunction> function) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate_);
DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);
int id = debug_info->debugging_id();
if (id == DebugInfo::kNoDebuggingId) {
  id = isolate_->heap()->NextDebuggingId();
  debug_info->set_debugging_id(id);
}
return id;
}

bool Debug::SetBreakpointForFunction(Handle<SharedFunctionInfo> shared,
                                   DirectHandle<String> condition, int* id,
                                   BreakPointKind kind) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (kind == kInstrumentation) {
  *id = kInstrumentationId;
} else {
  *id = ++thread_local_.last_breakpoint_id_;
}
DirectHandle<BreakPoint> breakpoint =
    isolate_->factory()->NewBreakPoint(*id, condition);
int source_position = 0;
#if V8_ENABLE_WEBASSEMBLY
if (shared->HasWasmExportedFunctionData()) {
  Tagged<WasmExportedFunctionData> function_data =
      shared->wasm_exported_function_data();
  int func_index = function_data->function_index();
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(function_data->instance_data()->has_instance_object());
  Tagged<WasmModuleObject> module_obj =
      function_data->instance_data()->instance_object()->module_object();
  DirectHandle<Script> script(module_obj->script(), isolate_);
  return WasmScript::SetBreakPointOnFirstBreakableForFunction(
      script, func_index, breakpoint);
}
#endif  // V8_ENABLE_WEBASSEMBLY
return SetBreakpoint(shared, breakpoint, &source_position);
}

void Debug::RemoveBreakpoint(int id) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
DirectHandle<BreakPoint> breakpoint = isolate_->factory()->NewBreakPoint(
    id, isolate_->factory()->empty_string());
ClearBreakPoint(breakpoint);
}

#if V8_ENABLE_WEBASSEMBLY
void Debug::SetInstrumentationBreakpointForWasmScript(Handle<Script> script,
                                                    int* id) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
DCHECK_EQ(Script::Type::kWasm, script->type());
*id = kInstrumentationId;

DirectHandle<BreakPoint> break_point = isolate_->factory()->NewBreakPoint(
    *id, isolate_->factory()->empty_string());
RecordWasmScriptWithBreakpoints(script);
WasmScript::SetInstrumentationBreakpoint(script, break_point);
}

void Debug::RemoveBreakpointForWasmScript(DirectHandle<Script> script, int id) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (script->type() == Script::Type::kWasm) {
  WasmScript::ClearBreakPointById(script, id);
}
}

void Debug::RecordWasmScriptWithBreakpoints(Handle<Script> script) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (wasm_scripts_with_break_points_.is_null()) {
  DirectHandle<WeakArrayList> new_list =
      isolate_->factory()->NewWeakArrayList(4);
  wasm_scripts_with_break_points_ =
      isolate_->global_handles()->Create(*new_list);
}
{
  DisallowGarbageCollection no_gc;
  for (int idx = wasm_scripts_with_break_points_->length() - 1; idx >= 0;
       --idx) {
    Tagged<HeapObject> wasm_script;
    if (wasm_scripts_with_break_points_->Get(idx).GetHeapObject(
            &wasm_script) &&
        wasm_script == *script) {
      return;
    }
  }
}
DirectHandle<WeakArrayList> new_list =
    WeakArrayList::Append(isolate_, wasm_scripts_with_break_points_,
                          MaybeObjectDirectHandle{script});
if (*new_list != *wasm_scripts_with_break_points_) {
  isolate_->global_handles()->Destroy(
      wasm_scripts_with_break_points_.location());
  wasm_scripts_with_break_points_ =
      isolate_->global_handles()->Create(*new_list);
}
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Clear out all the debug break code.
void Debug::ClearAllBreakPoints() {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
ClearAllDebugInfos([=, this](Handle<DebugInfo> info) {
  ClearBreakPoints(info);
  info->ClearBreakInfo(isolate_);
});
#if V8_ENABLE_WEBASSEMBLY
// Clear all wasm breakpoints.
if (!wasm_scripts_with_break_points_.is_null()) {
  DisallowGarbageCollection no_gc;
  for (int idx = wasm_scripts_with_break_points_->length() - 1; idx >= 0;
       --idx) {
    Tagged<HeapObject> raw_wasm_script;
    if (wasm_scripts_with_break_points_->Get(idx).GetHeapObject(
            &raw_wasm_script)) {
      Tagged<Script> wasm_script = Cast<Script>(raw_wasm_script);
      WasmScript::ClearAllBreakpoints(wasm_script);
      wasm_script->wasm_native_module()->GetDebugInfo()->RemoveIsolate(
          isolate_);
    }
  }
  wasm_scripts_with_break_points_ = Handle<WeakArrayList>{};
}
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Debug::FloodWithOneShot(Handle<SharedFunctionInfo> shared,
                           bool returns_only) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (IsBlackboxed(shared)) return;
// Make sure the function is compiled and has set up the debug info.
if (!EnsureBreakInfo(shared)) return;
PrepareFunctionForDebugExecution(shared);

Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
// Flood the function with break points.
DCHECK(debug_info->HasInstrumentedBytecodeArray());
for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
  if (returns_only && !it.GetBreakLocation().IsReturnOrSuspend()) continue;
  it.SetDebugBreak();
}
}

void Debug::ChangeBreakOnException(ExceptionBreakType type, bool enable) {
if (type == BreakUncaughtException) {
  break_on_uncaught_exception_ = enable;
} else {
  break_on_caught_exception_ = enable;
}
}

bool Debug::IsBreakOnException(ExceptionBreakType type) {
if (type == BreakUncaughtException) {
  return break_on_uncaught_exception_;
} else {
  return break_on_caught_exception_;
}
}

MaybeHandle<FixedArray> Debug::GetHitBreakPoints(
  DirectHandle<DebugInfo> debug_info, int position, bool* has_break_points) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
DirectHandle<Object> break_points =
    debug_info->GetBreakPoints(isolate_, position);
bool is_break_at_entry = debug_info->BreakAtEntry();
DCHECK(!IsUndefined(*break_points, isolate_));
if (!IsFixedArray(*break_points)) {
  const auto break_point = Cast<BreakPoint>(break_points);
  *has_break_points = break_point->id() != kInstrumentationId;
  if (!CheckBreakPoint(break_point, is_break_at_entry)) {
    return {};
  }
  Handle<FixedArray> break_points_hit = isolate_->factory()->NewFixedArray(1);
  break_points_hit->set(0, *break_points);
  return break_points_hit;
}

DirectHandle<FixedArray> array(Cast<FixedArray>(*break_points), isolate_);
int num_objects = array->length();
Handle<FixedArray> break_points_hit =
    isolate_->factory()->NewFixedArray(num_objects);
int break_points_hit_count = 0;
*has_break_points = false;
for (int i = 0; i < num_objects; ++i) {
  const auto break_point =
      Cast<BreakPoint>(direct_handle(array->get(i), isolate_));
  *has_break_points |= break_point->id() != kInstrumentationId;
  if (CheckBreakPoint(break_point, is_break_at_entry)) {
    break_points_hit->set(break_points_hit_count++, *break_point);
  }
}
if (break_points_hit_count == 0) return {};
break_points_hit->RightTrim(isolate_, break_points_hit_count);
return break_points_hit;
}

void Debug::SetBreakOnNextFunctionCall() {
// This method forces V8 to break on next function call regardless current
// last_step_action_. If any break happens between SetBreakOnNextFunctionCall
// and ClearBreakOnNextFunctionCall, we will clear this flag and stepping. If
// break does not happen, e.g. all called functions are blackboxed or no
// function is called, then we will clear this flag and let stepping continue
// its normal business.
thread_local_.break_on_next_function_call_ = true;
UpdateHookOnFunctionCall();
}

void Debug::ClearBreakOnNextFunctionCall() {
thread_local_.break_on_next_function_call_ = false;
UpdateHookOnFunctionCall();
}

void Debug::PrepareStepIn(DirectHandle<JSFunction> function) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
CHECK(last_step_action() >= StepInto || break_on_next_function_call() ||
      scheduled_break_on_function_call());
if (ignore_events()) return;
if (in_debug_scope()) return;
if (break_disabled()) return;
Handle<SharedFunctionInfo> shared(function->shared(), isolate_);
if (IsBlackboxed(shared)) return;
if (*function == thread_local_.ignore_step_into_function_) return;
thread_local_.ignore_step_into_function_ = Smi::zero();
FloodWithOneShot(shared);
}

void Debug::PrepareStepInSuspendedGenerator() {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
CHECK(has_suspended_generator());
if (ignore_events()) return;
if (in_debug_scope()) return;
if (break_disabled()) return;
thread_local_.last_step_action_ = StepInto;
UpdateHookOnFunctionCall();
DirectHandle<JSFunction> function(
    Cast<JSGeneratorObject>(thread_local_.suspended_generator_)->function(),
    isolate_);
FloodWithOneShot(handle(function->shared(), isolate_));
clear_suspended_generator();
}

void Debug::PrepareStepOnThrow() {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
if (last_step_action() == StepNone) return;
if (ignore_events()) return;
if (in_debug_scope()) return;
if (break_disabled()) return;

ClearOneShot();

int current_frame_count = CurrentFrameCount();

// Iterate through the JavaScript stack looking for handlers.
JavaScriptStackFrameIterator it(isolate_);
while (!it.done()) {
  JavaScriptFrame* frame = it.frame();
  if (frame->LookupExceptionHandlerInTable(nullptr, nullptr) > 0) break;
  std::vector<Tagged<SharedFunctionInfo>> infos;
  frame->GetFunctions(&infos);
  current_frame_count -= infos.size();
  it.Advance();
}

// No handler found. Nothing to instrument.
if (it.done()) return;

bool found_handler = false;
// Iterate frames, including inlined frames. First, find the handler frame.
// Then skip to the frame we want to break in, then instrument for stepping.
for (; !it.done(); it.Advance()) {
  JavaScriptFrame* frame = JavaScriptFrame::cast(it.frame());
  if (last_step_action() == StepInto) {
    // Deoptimize frame to ensure calls are checked for step-in.
    Deoptimizer::DeoptimizeFunction(frame->function());
  }
  std::vector<FrameSummary> summaries;
  frame->Summarize(&summaries);
  for (size_t i = summaries.size(); i != 0; i--, current_frame_count--) {
    const FrameSummary& summary = summaries[i - 1];
    if (!found_handler) {
      // We have yet to find the handler. If the frame inlines multiple
      // functions, we have to check each one for the handler.
      // If it only contains one function, we already found the handler.
      if (summaries.size() > 1) {
        DirectHandle<AbstractCode> code =
            summary.AsJavaScript().abstract_code();
        CHECK_EQ(CodeKind::INTERPRETED_FUNCTION, code->kind(isolate_));
        HandlerTable table(code->GetBytecodeArray());
        int code_offset = summary.code_offset();
        found_handler = table.LookupHandlerIndexForRange(code_offset) !=
                        HandlerTable::kNoHandlerFound;
      } else {
        found_handler = true;
      }
    }

    if (found_handler) {
      // We found the handler. If we are stepping next or out, we need to
      // iterate until we found the suitable target frame to break in.
      if ((last_step_action() == StepOver || last_step_action() == StepOut) &&
          current_frame_count > thread_local_.target_frame_count_) {
        continue;
      }
      Handle<SharedFunctionInfo> info(
          summary.AsJavaScript().function()->shared(), isolate_);
      if (IsBlackboxed(info)) continue;
      FloodWithOneShot(info);
      return;
    }
  }
}
}

void Debug::PrepareStep(StepAction step_action) {
RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
HandleScope scope(isolate_);

DCHECK(in_debug_scope());

// Get the frame where the execution has stopped and skip the debug frame if
// any. The debug frame will only be present if execution was stopped due to
// hitting a break point. In other situations (e.g. unhandled exception) the
// debug frame is not present.
StackFrameId frame_id = break_frame_id();
// If there is no JavaScript stack don't do anything.
if (frame_id == StackFrameId::NO_ID) return;

thread_local_.last_step_action_ = step_action;

DebuggableStackFrameIterator frames_it(isolate_, frame_id);
CommonFrame* frame = frames_it.frame();

BreakLocation location = BreakLocation::Invalid();
Handle<SharedFunctionInfo> shared;
int current_frame_count = CurrentFrameCount();

if (frame->is_javascript()) {
  JavaScriptFrame* js_frame = JavaScriptFrame::cast(frame);
  DCHECK(IsJSFunction(js_frame->function()));

  // Get the debug info (create it if it does not exist).
  auto summary = FrameSummary::GetTop(frame).AsJavaScript();
  DirectHandle<JSFunction> function(summary.function());
  shared = Handle<SharedFunctionInfo>(function->shared(), isolate_);
  if (!EnsureBreakInfo(shared)) return;
  PrepareFunctionForDebugExecution(shared);

  // PrepareFunctionForDebugExecution can invalidate Baseline frames
  js_frame = JavaScriptFrame::cast(frames_it.Reframe());

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
  location = BreakLocation::FromFrame(debug_info, js_frame);

  // Any step at a return is a step-out, and a step-out at a suspend behaves
  // like a return.
  if (location.IsReturn() ||
      (location.IsSuspend() && step_action == StepOut)) {
    // On StepOut we'll ignore our further calls to current function in
    // PrepareStepIn callback.
    if (last_step_action() == StepOut) {
      thread_local_.ignore_step_into_function_ = *function;
    }
    step_action = StepOut;
    thread_local_.last_step_action_ = StepInto;
  }

  // We need to schedule DebugOnFunction call callback
  UpdateHookOnFunctionCall();

  // A step-next in blackboxed function is a step-out.
  if (step_action == StepOver && IsBlackboxed(shared)) step_action = StepOut;

  thread_local_.last_statement_position_ = summary.SourceStatementPosition();
  thread_local_.last_bytecode_offset_ = summary.code_offset();
  thread_local_.last_frame_count_ = current_frame_count;
  // No longer perform the current async step.
  clear_suspended_generator();
#if V8_ENABLE_WEBASSEMBLY
} else if (frame->is_wasm() && step_action != StepOut) {
#if V8_ENABLE_DRUMBRAKE
  // TODO(paolosev@microsoft.com) - If we are running with the interpreter, we
  // cannot step.
  if (frame->is_wasm_interpreter_entry()) return;
#endif  // V8_ENABLE_DRUMBRAKE
  // Handle stepping in wasm.
  WasmFrame* wasm_frame = WasmFrame::cast(frame);
  auto* debug_info = wasm_frame->native_module()->GetDebugInfo();
  if (debug_info->PrepareStep(wasm_frame)) {
    UpdateHookOnFunctionCall();
    return;
  }
  // If the wasm code is not debuggable or will return after this step
  // (indicated by {PrepareStep} returning false), then step out of that frame
  // instead.
  step_action = StepOut;
  UpdateHookOnFunctionCall();
#endif  // V8_ENABLE_WEBASSEMBLY
}

switch (step_action) {
  case StepNone:
    UNREACHABLE();
  case StepOut: {
    // Clear last position info. For stepping out it does not matter.
    thread_local_.last_statement_position_ = kNoSourcePosition;
    thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
    thread_local_.last_frame_count_ = -1;
    if (!shared.is_null()) {
      if (!location.IsReturnOrSuspend() && !IsBlackboxed(shared)) {
        // At not return position we flood return positions with one shots and
        // will repeat StepOut automatically at next break.
        thread_local_.target_frame_count_ = current_frame_count;
        thread_local_.fast_forward_to_return_ = true;
        FloodWithOneShot(shared, true);
        return;
      }
      if (IsAsyncFunction(shared->kind())) {
        // Stepping out of an async function whose implicit promise is awaited
        // by some other async function, should resume the latter. The return
        // value here is either a JSPromise or a JSGeneratorObject (for the
        // initial yield of async generators).
        Handle<JSReceiver> return_value(
            Cast<JSReceiver>(thread_local_.return_value_), isolate_);
        DirectHandle<Object> awaited_by_holder = JSReceiver::GetDataProperty(
            isolate_, return_value,
            isolate_->factory()->promise_awaited_by_symbol());
        if (IsWeakFixedArray(*awaited_by_holder, isolate_)) {
          auto weak_fixed_array = Cast<WeakFixedArray>(awaited_by_holder);
          if (weak_fixed_array->length() == 1 &&
              weak_fixed_array->get(0).IsWeak()) {
            DirectHandle<HeapObject> awaited_by(
                weak_fixed_array->get(0).GetHeapObjectAssumeWeak(isolate_),
                isolate_);
            if (IsJSGeneratorObject(*awaited_by)) {
              DCHECK(!has_suspended_generator());
              thread_local_.suspended_generator_ = *awaited_by;
              ClearStepping();
              return;
            }
          }
        }
      }
    }
    // Skip the current frame, find the first frame we want to step out to
    // and deoptimize every frame along the way.
    bool in_current_frame = true;
    for (; !frames_it.done(); frames_it.Advance()) {
#if V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
      // TODO(paolosev@microsoft.com): Implement stepping out from JS to wasm
      // interpreter.
      if (frame->is_wasm_interpreter_entry()) continue;
#endif  // V8_ENABLE_DRUMBRAKE
      if (frames_it.frame()->is_wasm()) {
        if (in_current_frame) {
          in_current_frame = false;
          continue;
        }
        // Handle stepping out into Wasm.
        WasmFrame* wasm_frame = WasmFrame::cast(frames_it.frame());
        auto* debug_info = wasm_frame->native_module()->GetDebugInfo();
        if (debug_info->IsFrameBlackboxed(wasm_frame)) continue;
        debug_info->PrepareStepOutTo(wasm_frame);
        return;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      JavaScriptFrame* js_frame = JavaScriptFrame::cast(frames_it.frame());
      if (last_step_action() == StepInto) {
        // Deoptimize frame to ensure calls are checked for step-in.
        Deoptimizer::DeoptimizeFunction(js_frame->function());
      }
      HandleScope inner_scope(isolate_);
      std::vector<Handle<SharedFunctionInfo>> infos;
      js_frame->GetFunctions(&infos);
      for (; !infos.empty(); current_frame_count--) {
        Handle<SharedFunctionInfo> info = infos.back();
        infos.pop_back();
        if (in_current_frame) {
          // We want to step out, so skip the current frame.
          in_current_frame = false;
          continue;
        }
        if (IsBlackboxed(info)) continue;
        FloodWithOneShot(info);
        thread_local_.target_frame_count_ = current_frame_count;
        return;
      }
    }
    break;
  }
  case StepOver:
    thread_local_.target_frame_count_ = current_frame_count;
    [[fallthrough]];
  case StepInto:
    FloodWithOneShot(shared);
    break;
}
}

// Simple function for returning the source positions for active break points.
// static
Handle<Object> Debug::GetSourceBreakLocations(
  Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
RCS_SCOPE(isolate, RuntimeCallCounterId::kDebugger);
if (!shared->HasBreakInfo(isolate)) {
  return isolate->factory()->undefined_value();
}

DirectHandle<DebugInfo> debug_info(
    isolate->debug()->TryGetDebugInfo(*shared).value(), isolate);
if (debug_info->GetBreakPointCount(isolate) == 0) {
  return isolate->factory()->undefined_value();
}
Handle<FixedArray> locations = isolate->factory()->NewFixedArray(
    debug_info->GetBreakPointCount(isolate));
int count = 0;
for (int i = 0; i < debug_info->break_points()->length(); ++i) {
  if (!IsUndefined(debug_info->break_points()->get(i), isolate)) {
    Tagged<BreakPoint
Prompt: 
```
这是目录为v8/src/debug/debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
k location, we also do not trigger one for debugger statements, nor
  // an exception event on exception at this location.
  // This should have been computed at last break, and we should just
  // check that we are not at that location.

  if (IsSmi(thread_local_.muted_function_) ||
      *function != thread_local_.muted_function_) {
    return false;
  }

  for (const BreakLocation& location : locations) {
    if (location.position() == thread_local_.muted_position_) {
      return true;
    }
  }

  return false;
}

#if V8_ENABLE_WEBASSEMBLY
void Debug::SetMutedWasmLocation(DirectHandle<Script> script, int position) {
  thread_local_.muted_function_ = *script;
  thread_local_.muted_position_ = position;
}

bool Debug::IsMutedAtWasmLocation(Tagged<Script> script, int position) {
  return script == thread_local_.muted_function_ &&
         position == thread_local_.muted_position_;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

// Convenience helper for easier std::optional translation.
bool ToHandle(Isolate* isolate, std::optional<Tagged<DebugInfo>> debug_info,
              Handle<DebugInfo>* out) {
  if (!debug_info.has_value()) return false;
  *out = handle(debug_info.value(), isolate);
  return true;
}

}  // namespace

// Check whether a single break point object is triggered.
bool Debug::CheckBreakPoint(DirectHandle<BreakPoint> break_point,
                            bool is_break_at_entry) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  // Instrumentation breakpoints are handled separately.
  if (break_point->id() == kInstrumentationId) {
    return false;
  }

  if (!break_point->condition()->length()) return true;
  Handle<String> condition(break_point->condition(), isolate_);
  MaybeHandle<Object> maybe_result;
  Handle<Object> result;

  if (is_break_at_entry) {
    maybe_result = DebugEvaluate::WithTopmostArguments(isolate_, condition);
  } else {
    // Since we call CheckBreakpoint only for deoptimized frame on top of stack,
    // we can use 0 as index of inlined frame.
    const int inlined_jsframe_index = 0;
    const bool throw_on_side_effect = false;
    maybe_result =
        DebugEvaluate::Local(isolate_, break_frame_id(), inlined_jsframe_index,
                             condition, throw_on_side_effect);
  }

  Handle<Object> maybe_exception;
  bool exception_thrown = true;
  if (maybe_result.ToHandle(&result)) {
    exception_thrown = false;
  } else if (isolate_->has_exception()) {
    maybe_exception = handle(isolate_->exception(), isolate_);
    isolate_->clear_exception();
  }

  CHECK(in_debug_scope());
  DisableBreak no_recursive_break(this);

  {
    RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
    debug_delegate_->BreakpointConditionEvaluated(
        v8::Utils::ToLocal(isolate_->native_context()), break_point->id(),
        exception_thrown, v8::Utils::ToLocal(maybe_exception));
  }

  return !result.is_null() ? Object::BooleanValue(*result, isolate_) : false;
}

bool Debug::SetBreakpoint(Handle<SharedFunctionInfo> shared,
                          DirectHandle<BreakPoint> break_point,
                          int* source_position) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  // Make sure the function is compiled and has set up the debug info.
  if (!EnsureBreakInfo(shared)) return false;
  PrepareFunctionForDebugExecution(shared);

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
  // Source positions starts with zero.
  DCHECK_LE(0, *source_position);

  // Find the break point and change it.
  *source_position = FindBreakablePosition(debug_info, *source_position);
  DebugInfo::SetBreakPoint(isolate_, debug_info, *source_position, break_point);
  // At least one active break point now.
  DCHECK_LT(0, debug_info->GetBreakPointCount(isolate_));

  ClearBreakPoints(debug_info);
  ApplyBreakPoints(debug_info);
  return true;
}

bool Debug::SetBreakPointForScript(Handle<Script> script,
                                   DirectHandle<String> condition,
                                   int* source_position, int* id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  *id = ++thread_local_.last_breakpoint_id_;
  DirectHandle<BreakPoint> break_point =
      isolate_->factory()->NewBreakPoint(*id, condition);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == Script::Type::kWasm) {
    RecordWasmScriptWithBreakpoints(script);
    return WasmScript::SetBreakPoint(script, source_position, break_point);
  }
#endif  //  V8_ENABLE_WEBASSEMBLY

  HandleScope scope(isolate_);

  // Obtain shared function info for the innermost function containing this
  // position.
  Handle<Object> result =
      FindInnermostContainingFunctionInfo(script, *source_position);
  if (IsUndefined(*result, isolate_)) return false;

  auto shared = Cast<SharedFunctionInfo>(result);
  if (!EnsureBreakInfo(shared)) return false;
  PrepareFunctionForDebugExecution(shared);

  // Find the nested shared function info that is closest to the position within
  // the containing function.
  shared = FindClosestSharedFunctionInfoFromPosition(*source_position, script,
                                                     shared);

  // Set the breakpoint in the function.
  return SetBreakpoint(shared, break_point, source_position);
}

int Debug::FindBreakablePosition(Handle<DebugInfo> debug_info,
                                 int source_position) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (debug_info->CanBreakAtEntry()) {
    return kBreakAtEntryPosition;
  } else {
    DCHECK(debug_info->HasInstrumentedBytecodeArray());
    BreakIterator it(debug_info);
    it.SkipToPosition(source_position);
    return it.position();
  }
}

void Debug::ApplyBreakPoints(Handle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DisallowGarbageCollection no_gc;
  if (debug_info->CanBreakAtEntry()) {
    debug_info->SetBreakAtEntry();
  } else {
    if (!debug_info->HasInstrumentedBytecodeArray()) return;
    Tagged<FixedArray> break_points = debug_info->break_points();
    for (int i = 0; i < break_points->length(); i++) {
      if (IsUndefined(break_points->get(i), isolate_)) continue;
      Tagged<BreakPointInfo> info = Cast<BreakPointInfo>(break_points->get(i));
      if (info->GetBreakPointCount(isolate_) == 0) continue;
      DCHECK(debug_info->HasInstrumentedBytecodeArray());
      BreakIterator it(debug_info);
      it.SkipToPosition(info->source_position());
      it.SetDebugBreak();
    }
  }
  debug_info->SetDebugExecutionMode(DebugInfo::kBreakpoints);
}

void Debug::ClearBreakPoints(Handle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (debug_info->CanBreakAtEntry()) {
    debug_info->ClearBreakAtEntry();
  } else {
    // If we attempt to clear breakpoints but none exist, simply return. This
    // can happen e.g. CoverageInfos exist but no breakpoints are set.
    if (!debug_info->HasInstrumentedBytecodeArray() ||
        !debug_info->HasBreakInfo()) {
      return;
    }

    DisallowGarbageCollection no_gc;
    for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
      it.ClearDebugBreak();
    }
  }
}

void Debug::ClearBreakPoint(DirectHandle<BreakPoint> break_point) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Handle<DebugInfo> debug_info(it.Next(), isolate_);
    if (!debug_info->HasBreakInfo()) continue;

    DirectHandle<Object> result =
        DebugInfo::FindBreakPointInfo(isolate_, debug_info, break_point);
    if (IsUndefined(*result, isolate_)) continue;

    if (DebugInfo::ClearBreakPoint(isolate_, debug_info, break_point)) {
      ClearBreakPoints(debug_info);
      if (debug_info->GetBreakPointCount(isolate_) == 0) {
        debug_info->ClearBreakInfo(isolate_);
        if (debug_info->IsEmpty()) it.DeleteNext();
      } else {
        ApplyBreakPoints(debug_info);
      }
      return;
    }
  }
}

int Debug::GetFunctionDebuggingId(DirectHandle<JSFunction> function) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate_);
  DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);
  int id = debug_info->debugging_id();
  if (id == DebugInfo::kNoDebuggingId) {
    id = isolate_->heap()->NextDebuggingId();
    debug_info->set_debugging_id(id);
  }
  return id;
}

bool Debug::SetBreakpointForFunction(Handle<SharedFunctionInfo> shared,
                                     DirectHandle<String> condition, int* id,
                                     BreakPointKind kind) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (kind == kInstrumentation) {
    *id = kInstrumentationId;
  } else {
    *id = ++thread_local_.last_breakpoint_id_;
  }
  DirectHandle<BreakPoint> breakpoint =
      isolate_->factory()->NewBreakPoint(*id, condition);
  int source_position = 0;
#if V8_ENABLE_WEBASSEMBLY
  if (shared->HasWasmExportedFunctionData()) {
    Tagged<WasmExportedFunctionData> function_data =
        shared->wasm_exported_function_data();
    int func_index = function_data->function_index();
    // TODO(42204563): Avoid crashing if the instance object is not available.
    CHECK(function_data->instance_data()->has_instance_object());
    Tagged<WasmModuleObject> module_obj =
        function_data->instance_data()->instance_object()->module_object();
    DirectHandle<Script> script(module_obj->script(), isolate_);
    return WasmScript::SetBreakPointOnFirstBreakableForFunction(
        script, func_index, breakpoint);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return SetBreakpoint(shared, breakpoint, &source_position);
}

void Debug::RemoveBreakpoint(int id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DirectHandle<BreakPoint> breakpoint = isolate_->factory()->NewBreakPoint(
      id, isolate_->factory()->empty_string());
  ClearBreakPoint(breakpoint);
}

#if V8_ENABLE_WEBASSEMBLY
void Debug::SetInstrumentationBreakpointForWasmScript(Handle<Script> script,
                                                      int* id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(Script::Type::kWasm, script->type());
  *id = kInstrumentationId;

  DirectHandle<BreakPoint> break_point = isolate_->factory()->NewBreakPoint(
      *id, isolate_->factory()->empty_string());
  RecordWasmScriptWithBreakpoints(script);
  WasmScript::SetInstrumentationBreakpoint(script, break_point);
}

void Debug::RemoveBreakpointForWasmScript(DirectHandle<Script> script, int id) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (script->type() == Script::Type::kWasm) {
    WasmScript::ClearBreakPointById(script, id);
  }
}

void Debug::RecordWasmScriptWithBreakpoints(Handle<Script> script) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (wasm_scripts_with_break_points_.is_null()) {
    DirectHandle<WeakArrayList> new_list =
        isolate_->factory()->NewWeakArrayList(4);
    wasm_scripts_with_break_points_ =
        isolate_->global_handles()->Create(*new_list);
  }
  {
    DisallowGarbageCollection no_gc;
    for (int idx = wasm_scripts_with_break_points_->length() - 1; idx >= 0;
         --idx) {
      Tagged<HeapObject> wasm_script;
      if (wasm_scripts_with_break_points_->Get(idx).GetHeapObject(
              &wasm_script) &&
          wasm_script == *script) {
        return;
      }
    }
  }
  DirectHandle<WeakArrayList> new_list =
      WeakArrayList::Append(isolate_, wasm_scripts_with_break_points_,
                            MaybeObjectDirectHandle{script});
  if (*new_list != *wasm_scripts_with_break_points_) {
    isolate_->global_handles()->Destroy(
        wasm_scripts_with_break_points_.location());
    wasm_scripts_with_break_points_ =
        isolate_->global_handles()->Create(*new_list);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Clear out all the debug break code.
void Debug::ClearAllBreakPoints() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  ClearAllDebugInfos([=, this](Handle<DebugInfo> info) {
    ClearBreakPoints(info);
    info->ClearBreakInfo(isolate_);
  });
#if V8_ENABLE_WEBASSEMBLY
  // Clear all wasm breakpoints.
  if (!wasm_scripts_with_break_points_.is_null()) {
    DisallowGarbageCollection no_gc;
    for (int idx = wasm_scripts_with_break_points_->length() - 1; idx >= 0;
         --idx) {
      Tagged<HeapObject> raw_wasm_script;
      if (wasm_scripts_with_break_points_->Get(idx).GetHeapObject(
              &raw_wasm_script)) {
        Tagged<Script> wasm_script = Cast<Script>(raw_wasm_script);
        WasmScript::ClearAllBreakpoints(wasm_script);
        wasm_script->wasm_native_module()->GetDebugInfo()->RemoveIsolate(
            isolate_);
      }
    }
    wasm_scripts_with_break_points_ = Handle<WeakArrayList>{};
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Debug::FloodWithOneShot(Handle<SharedFunctionInfo> shared,
                             bool returns_only) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (IsBlackboxed(shared)) return;
  // Make sure the function is compiled and has set up the debug info.
  if (!EnsureBreakInfo(shared)) return;
  PrepareFunctionForDebugExecution(shared);

  Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
  // Flood the function with break points.
  DCHECK(debug_info->HasInstrumentedBytecodeArray());
  for (BreakIterator it(debug_info); !it.Done(); it.Next()) {
    if (returns_only && !it.GetBreakLocation().IsReturnOrSuspend()) continue;
    it.SetDebugBreak();
  }
}

void Debug::ChangeBreakOnException(ExceptionBreakType type, bool enable) {
  if (type == BreakUncaughtException) {
    break_on_uncaught_exception_ = enable;
  } else {
    break_on_caught_exception_ = enable;
  }
}

bool Debug::IsBreakOnException(ExceptionBreakType type) {
  if (type == BreakUncaughtException) {
    return break_on_uncaught_exception_;
  } else {
    return break_on_caught_exception_;
  }
}

MaybeHandle<FixedArray> Debug::GetHitBreakPoints(
    DirectHandle<DebugInfo> debug_info, int position, bool* has_break_points) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DirectHandle<Object> break_points =
      debug_info->GetBreakPoints(isolate_, position);
  bool is_break_at_entry = debug_info->BreakAtEntry();
  DCHECK(!IsUndefined(*break_points, isolate_));
  if (!IsFixedArray(*break_points)) {
    const auto break_point = Cast<BreakPoint>(break_points);
    *has_break_points = break_point->id() != kInstrumentationId;
    if (!CheckBreakPoint(break_point, is_break_at_entry)) {
      return {};
    }
    Handle<FixedArray> break_points_hit = isolate_->factory()->NewFixedArray(1);
    break_points_hit->set(0, *break_points);
    return break_points_hit;
  }

  DirectHandle<FixedArray> array(Cast<FixedArray>(*break_points), isolate_);
  int num_objects = array->length();
  Handle<FixedArray> break_points_hit =
      isolate_->factory()->NewFixedArray(num_objects);
  int break_points_hit_count = 0;
  *has_break_points = false;
  for (int i = 0; i < num_objects; ++i) {
    const auto break_point =
        Cast<BreakPoint>(direct_handle(array->get(i), isolate_));
    *has_break_points |= break_point->id() != kInstrumentationId;
    if (CheckBreakPoint(break_point, is_break_at_entry)) {
      break_points_hit->set(break_points_hit_count++, *break_point);
    }
  }
  if (break_points_hit_count == 0) return {};
  break_points_hit->RightTrim(isolate_, break_points_hit_count);
  return break_points_hit;
}

void Debug::SetBreakOnNextFunctionCall() {
  // This method forces V8 to break on next function call regardless current
  // last_step_action_. If any break happens between SetBreakOnNextFunctionCall
  // and ClearBreakOnNextFunctionCall, we will clear this flag and stepping. If
  // break does not happen, e.g. all called functions are blackboxed or no
  // function is called, then we will clear this flag and let stepping continue
  // its normal business.
  thread_local_.break_on_next_function_call_ = true;
  UpdateHookOnFunctionCall();
}

void Debug::ClearBreakOnNextFunctionCall() {
  thread_local_.break_on_next_function_call_ = false;
  UpdateHookOnFunctionCall();
}

void Debug::PrepareStepIn(DirectHandle<JSFunction> function) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  CHECK(last_step_action() >= StepInto || break_on_next_function_call() ||
        scheduled_break_on_function_call());
  if (ignore_events()) return;
  if (in_debug_scope()) return;
  if (break_disabled()) return;
  Handle<SharedFunctionInfo> shared(function->shared(), isolate_);
  if (IsBlackboxed(shared)) return;
  if (*function == thread_local_.ignore_step_into_function_) return;
  thread_local_.ignore_step_into_function_ = Smi::zero();
  FloodWithOneShot(shared);
}

void Debug::PrepareStepInSuspendedGenerator() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  CHECK(has_suspended_generator());
  if (ignore_events()) return;
  if (in_debug_scope()) return;
  if (break_disabled()) return;
  thread_local_.last_step_action_ = StepInto;
  UpdateHookOnFunctionCall();
  DirectHandle<JSFunction> function(
      Cast<JSGeneratorObject>(thread_local_.suspended_generator_)->function(),
      isolate_);
  FloodWithOneShot(handle(function->shared(), isolate_));
  clear_suspended_generator();
}

void Debug::PrepareStepOnThrow() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (last_step_action() == StepNone) return;
  if (ignore_events()) return;
  if (in_debug_scope()) return;
  if (break_disabled()) return;

  ClearOneShot();

  int current_frame_count = CurrentFrameCount();

  // Iterate through the JavaScript stack looking for handlers.
  JavaScriptStackFrameIterator it(isolate_);
  while (!it.done()) {
    JavaScriptFrame* frame = it.frame();
    if (frame->LookupExceptionHandlerInTable(nullptr, nullptr) > 0) break;
    std::vector<Tagged<SharedFunctionInfo>> infos;
    frame->GetFunctions(&infos);
    current_frame_count -= infos.size();
    it.Advance();
  }

  // No handler found. Nothing to instrument.
  if (it.done()) return;

  bool found_handler = false;
  // Iterate frames, including inlined frames. First, find the handler frame.
  // Then skip to the frame we want to break in, then instrument for stepping.
  for (; !it.done(); it.Advance()) {
    JavaScriptFrame* frame = JavaScriptFrame::cast(it.frame());
    if (last_step_action() == StepInto) {
      // Deoptimize frame to ensure calls are checked for step-in.
      Deoptimizer::DeoptimizeFunction(frame->function());
    }
    std::vector<FrameSummary> summaries;
    frame->Summarize(&summaries);
    for (size_t i = summaries.size(); i != 0; i--, current_frame_count--) {
      const FrameSummary& summary = summaries[i - 1];
      if (!found_handler) {
        // We have yet to find the handler. If the frame inlines multiple
        // functions, we have to check each one for the handler.
        // If it only contains one function, we already found the handler.
        if (summaries.size() > 1) {
          DirectHandle<AbstractCode> code =
              summary.AsJavaScript().abstract_code();
          CHECK_EQ(CodeKind::INTERPRETED_FUNCTION, code->kind(isolate_));
          HandlerTable table(code->GetBytecodeArray());
          int code_offset = summary.code_offset();
          found_handler = table.LookupHandlerIndexForRange(code_offset) !=
                          HandlerTable::kNoHandlerFound;
        } else {
          found_handler = true;
        }
      }

      if (found_handler) {
        // We found the handler. If we are stepping next or out, we need to
        // iterate until we found the suitable target frame to break in.
        if ((last_step_action() == StepOver || last_step_action() == StepOut) &&
            current_frame_count > thread_local_.target_frame_count_) {
          continue;
        }
        Handle<SharedFunctionInfo> info(
            summary.AsJavaScript().function()->shared(), isolate_);
        if (IsBlackboxed(info)) continue;
        FloodWithOneShot(info);
        return;
      }
    }
  }
}

void Debug::PrepareStep(StepAction step_action) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  DCHECK(in_debug_scope());

  // Get the frame where the execution has stopped and skip the debug frame if
  // any. The debug frame will only be present if execution was stopped due to
  // hitting a break point. In other situations (e.g. unhandled exception) the
  // debug frame is not present.
  StackFrameId frame_id = break_frame_id();
  // If there is no JavaScript stack don't do anything.
  if (frame_id == StackFrameId::NO_ID) return;

  thread_local_.last_step_action_ = step_action;

  DebuggableStackFrameIterator frames_it(isolate_, frame_id);
  CommonFrame* frame = frames_it.frame();

  BreakLocation location = BreakLocation::Invalid();
  Handle<SharedFunctionInfo> shared;
  int current_frame_count = CurrentFrameCount();

  if (frame->is_javascript()) {
    JavaScriptFrame* js_frame = JavaScriptFrame::cast(frame);
    DCHECK(IsJSFunction(js_frame->function()));

    // Get the debug info (create it if it does not exist).
    auto summary = FrameSummary::GetTop(frame).AsJavaScript();
    DirectHandle<JSFunction> function(summary.function());
    shared = Handle<SharedFunctionInfo>(function->shared(), isolate_);
    if (!EnsureBreakInfo(shared)) return;
    PrepareFunctionForDebugExecution(shared);

    // PrepareFunctionForDebugExecution can invalidate Baseline frames
    js_frame = JavaScriptFrame::cast(frames_it.Reframe());

    Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
    location = BreakLocation::FromFrame(debug_info, js_frame);

    // Any step at a return is a step-out, and a step-out at a suspend behaves
    // like a return.
    if (location.IsReturn() ||
        (location.IsSuspend() && step_action == StepOut)) {
      // On StepOut we'll ignore our further calls to current function in
      // PrepareStepIn callback.
      if (last_step_action() == StepOut) {
        thread_local_.ignore_step_into_function_ = *function;
      }
      step_action = StepOut;
      thread_local_.last_step_action_ = StepInto;
    }

    // We need to schedule DebugOnFunction call callback
    UpdateHookOnFunctionCall();

    // A step-next in blackboxed function is a step-out.
    if (step_action == StepOver && IsBlackboxed(shared)) step_action = StepOut;

    thread_local_.last_statement_position_ = summary.SourceStatementPosition();
    thread_local_.last_bytecode_offset_ = summary.code_offset();
    thread_local_.last_frame_count_ = current_frame_count;
    // No longer perform the current async step.
    clear_suspended_generator();
#if V8_ENABLE_WEBASSEMBLY
  } else if (frame->is_wasm() && step_action != StepOut) {
#if V8_ENABLE_DRUMBRAKE
    // TODO(paolosev@microsoft.com) - If we are running with the interpreter, we
    // cannot step.
    if (frame->is_wasm_interpreter_entry()) return;
#endif  // V8_ENABLE_DRUMBRAKE
    // Handle stepping in wasm.
    WasmFrame* wasm_frame = WasmFrame::cast(frame);
    auto* debug_info = wasm_frame->native_module()->GetDebugInfo();
    if (debug_info->PrepareStep(wasm_frame)) {
      UpdateHookOnFunctionCall();
      return;
    }
    // If the wasm code is not debuggable or will return after this step
    // (indicated by {PrepareStep} returning false), then step out of that frame
    // instead.
    step_action = StepOut;
    UpdateHookOnFunctionCall();
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  switch (step_action) {
    case StepNone:
      UNREACHABLE();
    case StepOut: {
      // Clear last position info. For stepping out it does not matter.
      thread_local_.last_statement_position_ = kNoSourcePosition;
      thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
      thread_local_.last_frame_count_ = -1;
      if (!shared.is_null()) {
        if (!location.IsReturnOrSuspend() && !IsBlackboxed(shared)) {
          // At not return position we flood return positions with one shots and
          // will repeat StepOut automatically at next break.
          thread_local_.target_frame_count_ = current_frame_count;
          thread_local_.fast_forward_to_return_ = true;
          FloodWithOneShot(shared, true);
          return;
        }
        if (IsAsyncFunction(shared->kind())) {
          // Stepping out of an async function whose implicit promise is awaited
          // by some other async function, should resume the latter. The return
          // value here is either a JSPromise or a JSGeneratorObject (for the
          // initial yield of async generators).
          Handle<JSReceiver> return_value(
              Cast<JSReceiver>(thread_local_.return_value_), isolate_);
          DirectHandle<Object> awaited_by_holder = JSReceiver::GetDataProperty(
              isolate_, return_value,
              isolate_->factory()->promise_awaited_by_symbol());
          if (IsWeakFixedArray(*awaited_by_holder, isolate_)) {
            auto weak_fixed_array = Cast<WeakFixedArray>(awaited_by_holder);
            if (weak_fixed_array->length() == 1 &&
                weak_fixed_array->get(0).IsWeak()) {
              DirectHandle<HeapObject> awaited_by(
                  weak_fixed_array->get(0).GetHeapObjectAssumeWeak(isolate_),
                  isolate_);
              if (IsJSGeneratorObject(*awaited_by)) {
                DCHECK(!has_suspended_generator());
                thread_local_.suspended_generator_ = *awaited_by;
                ClearStepping();
                return;
              }
            }
          }
        }
      }
      // Skip the current frame, find the first frame we want to step out to
      // and deoptimize every frame along the way.
      bool in_current_frame = true;
      for (; !frames_it.done(); frames_it.Advance()) {
#if V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
        // TODO(paolosev@microsoft.com): Implement stepping out from JS to wasm
        // interpreter.
        if (frame->is_wasm_interpreter_entry()) continue;
#endif  // V8_ENABLE_DRUMBRAKE
        if (frames_it.frame()->is_wasm()) {
          if (in_current_frame) {
            in_current_frame = false;
            continue;
          }
          // Handle stepping out into Wasm.
          WasmFrame* wasm_frame = WasmFrame::cast(frames_it.frame());
          auto* debug_info = wasm_frame->native_module()->GetDebugInfo();
          if (debug_info->IsFrameBlackboxed(wasm_frame)) continue;
          debug_info->PrepareStepOutTo(wasm_frame);
          return;
        }
#endif  // V8_ENABLE_WEBASSEMBLY
        JavaScriptFrame* js_frame = JavaScriptFrame::cast(frames_it.frame());
        if (last_step_action() == StepInto) {
          // Deoptimize frame to ensure calls are checked for step-in.
          Deoptimizer::DeoptimizeFunction(js_frame->function());
        }
        HandleScope inner_scope(isolate_);
        std::vector<Handle<SharedFunctionInfo>> infos;
        js_frame->GetFunctions(&infos);
        for (; !infos.empty(); current_frame_count--) {
          Handle<SharedFunctionInfo> info = infos.back();
          infos.pop_back();
          if (in_current_frame) {
            // We want to step out, so skip the current frame.
            in_current_frame = false;
            continue;
          }
          if (IsBlackboxed(info)) continue;
          FloodWithOneShot(info);
          thread_local_.target_frame_count_ = current_frame_count;
          return;
        }
      }
      break;
    }
    case StepOver:
      thread_local_.target_frame_count_ = current_frame_count;
      [[fallthrough]];
    case StepInto:
      FloodWithOneShot(shared);
      break;
  }
}

// Simple function for returning the source positions for active break points.
// static
Handle<Object> Debug::GetSourceBreakLocations(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kDebugger);
  if (!shared->HasBreakInfo(isolate)) {
    return isolate->factory()->undefined_value();
  }

  DirectHandle<DebugInfo> debug_info(
      isolate->debug()->TryGetDebugInfo(*shared).value(), isolate);
  if (debug_info->GetBreakPointCount(isolate) == 0) {
    return isolate->factory()->undefined_value();
  }
  Handle<FixedArray> locations = isolate->factory()->NewFixedArray(
      debug_info->GetBreakPointCount(isolate));
  int count = 0;
  for (int i = 0; i < debug_info->break_points()->length(); ++i) {
    if (!IsUndefined(debug_info->break_points()->get(i), isolate)) {
      Tagged<BreakPointInfo> break_point_info =
          Cast<BreakPointInfo>(debug_info->break_points()->get(i));
      int break_points = break_point_info->GetBreakPointCount(isolate);
      if (break_points == 0) continue;
      for (int j = 0; j < break_points; ++j) {
        locations->set(count++,
                       Smi::FromInt(break_point_info->source_position()));
      }
    }
  }
  return locations;
}

void Debug::ClearStepping() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Clear the various stepping setup.
  ClearOneShot();
  ClearMutedLocation();

  thread_local_.last_step_action_ = StepNone;
  thread_local_.last_statement_position_ = kNoSourcePosition;
  thread_local_.last_bytecode_offset_ = kFunctionEntryBytecodeOffset;
  thread_local_.ignore_step_into_function_ = Smi::zero();
  thread_local_.fast_forward_to_return_ = false;
  thread_local_.last_frame_count_ = -1;
  thread_local_.target_frame_count_ = -1;
  thread_local_.break_on_next_function_call_ = false;
  thread_local_.scheduled_break_on_next_function_call_ = false;
  clear_restart_frame();
  UpdateHookOnFunctionCall();
}

// Clears all the one-shot break points that are currently set. Normally this
// function is called each time a break point is hit as one shot break points
// are used to support stepping.
void Debug::ClearOneShot() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // The current implementation just runs through all the breakpoints. When the
  // last break point for a function is removed that function is automatically
  // removed from the list.
  HandleScope scope(isolate_);
  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Handle<DebugInfo> debug_info(it.Next(), isolate_);
    ClearBreakPoints(debug_info);
    ApplyBreakPoints(debug_info);
  }
}

void Debug::ClearMutedLocation() {
  thread_local_.muted_function_ = Smi::zero();
  thread_local_.muted_position_ = -1;
}

void Debug::SetMutedLocation(DirectHandle<SharedFunctionInfo> function,
                             const BreakLocation& location) {
  thread_local_.muted_function_ = *function;
  thread_local_.muted_position_ = location.position();
}

namespace {
class DiscardBaselineCodeVisitor : public ThreadVisitor {
 public:
  explicit DiscardBaselineCodeVisitor(Tagged<SharedFunctionInfo> shared)
      : shared_(shared) {}
  DiscardBaselineCodeVisitor() : shared_(SharedFunctionInfo()) {}

  void VisitThread(Isolate* isolate, ThreadLocalTop* top) override {
    DisallowGarbageCollection diallow_gc;
    bool deopt_all = shared_ == SharedFunctionInfo();
    for (JavaScriptStackFrameIterator it(isolate, top); !it.done();
         it.Advance()) {
      if (!deopt_all && it.frame()->function()->shared() != shared_) continue;
      if (it.frame()->type() == StackFrame::BASELINE) {
        BaselineFrame* frame = BaselineFrame::cast(it.frame());
        int bytecode_offset = frame->GetBytecodeOffset();
        Address* pc_addr = frame->pc_address();
        Address advance;
        if (bytecode_offset == kFunctionEntryBytecodeOffset) {
          advance = BUILTIN_CODE(isolate, BaselineOutOfLinePrologueDeopt)
                        ->instruction_start();
        } else {
          advance = BUILTIN_CODE(isolate, InterpreterEnterAtNextBytecode)
                        ->instruction_start();
        }
        PointerAuthentication::ReplacePC(pc_addr, advance, kSystemPointerSize);
        InterpretedFrame::cast(it.Reframe())
            ->PatchBytecodeOffset(bytecode_offset);
      } else if (it.frame()->type() == StackFrame::INTERPRETED) {
        // Check if the PC is a baseline entry trampoline. If it is, replace it
        // with the corresponding interpreter entry trampoline.
        // This is the case if a baseline function was inlined into a function
        // we deoptimized in the debugger and are stepping into it.
        JavaScriptFrame* frame = it.frame();
        Address pc = frame->pc();
        Builtin builtin =
"""


```