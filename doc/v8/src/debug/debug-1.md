Response: The user wants to understand the functionality of the C++ code in `v8/src/debug/debug.cc`. This is the second part of the file. I need to:

1. **Summarize the functions** within this code snippet.
2. **Identify connections to JavaScript functionality**.
3. **Provide JavaScript examples** if such connections exist.

Let's go through the code section by section:

- **`OffHeapInstructionStream::TryLookupCode` interaction**: This part seems to deal with handling specific built-in functions related to baseline/interpreter entry and potentially modifying the program counter (PC) during debugging.
- **`DiscardBaselineCodeVisitor`**: This visitor is used to traverse threads and the heap to discard baseline (optimized but less optimized than full optimization) code for a given function.
- **`Debug::DiscardBaselineCode`**: This function uses the visitor to discard baseline code for a specific `SharedFunctionInfo`. It also updates `JSFunction` objects using this `SharedFunctionInfo` to point to the interpreter entry trampoline.
- **`Debug::DiscardAllBaselineCode`**: Similar to the previous function, but it discards baseline code for all functions in the heap.
- **`Debug::DeoptimizeFunction`**:  Discards baseline code and deoptimizes all optimized code associated with a given `SharedFunctionInfo`.
- **`Debug::PrepareFunctionForDebugExecution`**: Prepares a function for debugging. This involves potentially discarding baseline code, installing debug bytecode, and installing a debug break trampoline.
- **`Debug::InstallDebugBreakTrampoline`**:  Installs a special trampoline (a small piece of code) that is executed when a breakpoint at the entry of a function is encountered. This involves iterating through functions and accessors to update their code pointers.
- **`Debug::GetPossibleBreakpoints`**: Determines valid locations for setting breakpoints within a script, potentially restricted to a specific function.
- **`SharedFunctionInfoFinder`**: A helper class to find the innermost `SharedFunctionInfo` at a given position.
- **`Debug::FindClosestSharedFunctionInfoFromPosition`**:  Finds the closest `SharedFunctionInfo` to a given position within a script.
- **`Debug::FindSharedFunctionInfosIntersectingRange`**: Finds `SharedFunctionInfo` objects whose source code intersects a given range within a script.
- **`Debug::GetTopLevelWithRecompile`**:  Retrieves the `SharedFunctionInfo` for the top-level code of a script, potentially recompiling it if necessary.
- **`Debug::FindInnermostContainingFunctionInfo`**:  Finds the `SharedFunctionInfo` of the function that most closely contains a given position in a script.
- **`Debug::EnsureBreakInfo`**: Ensures that debug information is available for a given `SharedFunctionInfo`.
- **`Debug::CreateBreakInfo`**: Creates and initializes debug information for a `SharedFunctionInfo`.
- **`Debug::GetOrCreateDebugInfo`**: Retrieves existing debug information or creates new information if it doesn't exist.
- **Coverage Information Functions (`InstallCoverageInfo`, `RemoveAllCoverageInfos`)**: Manage code coverage information for debugging.
- **Hint Clearing Functions (`ClearAllDebuggerHints`)**: Clears debugger hints stored in debug information.
- **Generic Debug Info Management (`ClearAllDebugInfos`, `RemoveBreakInfoAndMaybeFree`)**: Functions for clearing and removing debug information.
- **Breakpoint Related Functions (`IsBreakAtReturn`)**: Checks if a breakpoint is at a return statement.
- **Script Management (`GetLoadedScripts`)**: Retrieves a list of loaded scripts.
- **Debug Info Accessors (`TryGetDebugInfo`, `HasDebugInfo`, `HasCoverageInfo`, `HasBreakInfo`, `BreakAtEntry`)**: Functions to check for the presence of different types of debug information.
- **Exception Handling (`OnThrow`, `OnPromiseReject`, `OnException`)**: Handles JavaScript exceptions and promise rejections during debugging.
- **Blackboxing (`IsFrameBlackboxed`, `IsBlackboxed`, `ShouldBeSkipped`, `AllFramesOnStackAreBlackboxed`)**: Functions to manage the "blackboxing" of code, where the debugger skips over certain functions or frames.
- **Live Edit (`SetScriptSource`)**: Supports live editing of script source code during debugging.
- **Compilation Events (`OnCompileError`, `OnAfterCompile`, `ProcessCompileEvent`)**: Handles events related to script compilation.
- **Frame Counting (`CurrentFrameCount`)**:  Calculates the number of frames on the stack for debugging purposes.
- **Debug Delegate (`SetDebugDelegate`, `UpdateState`)**: Sets and updates a delegate for communication with the debugger.
- **Hook Management (`UpdateHookOnFunctionCall`)**: Manages function call hooks for debugging.
- **Debug Break Handling (`HandleDebugBreak`)**: Handles the logic when a debug break occurs.
- **Debug Location Printing (`PrintBreakLocation`)**: Prints information about the current break location (debug build only).
- **`DebugScope`**: A class to manage the scope of a debugging session.
- **`ReturnValueScope`**: A class to manage the return value during debugging.
- **Execution Mode Management (`UpdateDebugInfosForExecutionMode`)**: Updates debug information based on the current debugging execution mode.
- **Termination Control (`SetTerminateOnResume`)**: Allows requesting termination when the debugger resumes.
- **Side-Effect Checking (various `StartSideEffectCheckMode`, `StopSideEffectCheckMode`, `ApplySideEffectChecks`, `ClearSideEffectChecks`, `PerformSideEffectCheck*` functions)**:  A mechanism to check if code execution has side effects, used for safe evaluation during debugging.
- **Temporary Object Tracking (`SetTemporaryObjectTrackingDisabled`, `GetTemporaryObjectTrackingDisabled`)**: Controls the tracking of temporary objects during side-effect checks.
- **Frame Restart (`PrepareRestartFrame`)**:  Prepares the state to restart execution from a specific frame.
- **Debugger Paused Event Notification (`NotifyDebuggerPausedEventSent`)**:  Notifies when the debugger paused event has been sent.

**Connections to JavaScript and Examples:**

Many of these functions directly relate to JavaScript debugging features. Here are some examples:

- **Breakpoints:** Functions like `GetPossibleBreakpoints`, `EnsureBreakInfo`, `CreateBreakInfo`, and `HandleDebugBreak` are directly involved in setting and hitting breakpoints in JavaScript code.

  ```javascript
  // Setting a breakpoint (conceptual, the C++ code handles the low-level details)
  debugger; // This statement triggers a debug break
  ```

- **Stepping:** Functions related to stepping (`PrepareStep`, `ClearStepping`) are used when you step through JavaScript code in the debugger (step over, step into, step out).

  ```javascript
  function myFunction() {
    console.log("Line 1"); // Breakpoint here
    console.log("Line 2"); // Step over will execute this line and move to the next
  }
  myFunction();
  ```

- **Blackboxing:** The `IsBlackboxed` functions allow you to mark certain JavaScript code (like library code) to be skipped over during debugging.

  ```javascript
  // In the debugger settings, you might add a pattern to blacklist certain scripts.
  // This C++ code would then use that information to decide if a frame is blackboxed.
  ```

- **Live Edit:** `SetScriptSource` enables the "live edit" or "hot reload" feature where you can modify JavaScript code while debugging.

  ```javascript
  // While paused in the debugger, you might edit the source code of a function
  // and then resume execution, and the changes will be reflected.
  ```

- **Exceptions:** The `OnThrow`, `OnPromiseReject`, and `OnException` functions handle JavaScript exceptions and promise rejections, allowing the debugger to break on these events.

  ```javascript
  try {
    throw new Error("Something went wrong"); // This will trigger a debug break if "break on caught exceptions" is enabled.
  } catch (e) {
    console.error(e);
  }

  Promise.reject("Promise failed"); // This can trigger a debug break if "break on unhandled promise rejections" is enabled.
  ```

- **Side-Effect Checking:** The side-effect checking mechanism is used when you evaluate expressions in the debugger to ensure that the evaluation doesn't change the program's state unexpectedly.

  ```javascript
  // While paused in the debugger, you might type an expression in the console:
  // > myVariable = 10; // The debugger might prevent this if side-effect checks are enabled.
  ```

This section of `debug.cc` focuses heavily on the core mechanics of debugging JavaScript code within the V8 engine. It handles events, manages state, and interacts with the JavaScript execution environment to provide a robust debugging experience.
This part of the `v8/src/debug/debug.cc` file continues to implement the debugging functionality within the V8 JavaScript engine. It builds upon the concepts introduced in the first part and focuses on the following key areas:

**1. Discarding and Managing Baseline Code:**

- **`DiscardBaselineCodeVisitor`**: A visitor pattern implementation used to iterate through threads and the heap to find and discard baseline compiled code associated with a specific function. This is necessary when debugging to ensure that the debugger interacts with the intended bytecode or optimized code.
- **`DiscardBaselineCode(Tagged<SharedFunctionInfo> shared)`**:  This function takes a `SharedFunctionInfo` (which holds metadata about a JavaScript function) and discards its baseline compiled code. It iterates through threads and the heap, updating `JSFunction` objects that are currently using this baseline code to point back to the interpreter entry trampoline.
- **`DiscardAllBaselineCode()`**: Similar to the above, but discards baseline code for *all* functions in the heap.

**2. Deoptimization and Preparation for Debugging:**

- **`DeoptimizeFunction(DirectHandle<SharedFunctionInfo> shared)`**:  Deoptimizes a function by discarding its baseline code and then using the `Deoptimizer` to remove any fully optimized code. This forces the function to run in the interpreter or with baseline compilation, making it easier to debug.
- **`PrepareFunctionForDebugExecution(DirectHandle<SharedFunctionInfo> shared)`**:  This is a crucial function for setting up a function for debugging. It performs several steps:
    - It checks if the function is already prepared.
    - If the function can break at its entry point, it deoptimizes everything to avoid inlining issues.
    - It installs "debug bytecode" for the function, which includes extra information needed for debugging.
    - It installs a "debug break trampoline" if necessary, which is a small piece of code executed when a breakpoint is hit at the function's entry.
    - It redirects active function calls on the stack to use the debug bytecode.

**3. Installing and Managing Debug Break Trampolines:**

- **`InstallDebugBreakTrampoline()`**: This function is responsible for ensuring that when a breakpoint is set at the beginning of a function, the execution flow is correctly redirected to the debugger. It iterates through all functions and potentially accessors on the heap and updates their code pointers to the `DebugBreakTrampoline` if they have a breakpoint at their entry. It also handles cases where functions need to be compiled first.

**4. Determining Breakpoint Locations:**

- **`GetPossibleBreakpoints(Handle<Script> script, int start_position, int end_position, bool restrict_to_function, std::vector<BreakLocation>* locations)`**:  This function figures out all the valid locations within a given script (or a specific function within the script) where a breakpoint can be set. It uses `DebugInfo` to find breakable positions in the bytecode.

**5. Finding Function Information for Debugging:**

- **`SharedFunctionInfoFinder`**: A helper class to find the innermost `SharedFunctionInfo` at a specific source code position.
- **`FindClosestSharedFunctionInfoFromPosition(int position, Handle<Script> script, Handle<SharedFunctionInfo> outer_shared)`**: Finds the `SharedFunctionInfo` that is closest to a given position in the source code.
- **`FindSharedFunctionInfosIntersectingRange(Handle<Script> script, int start_position, int end_position, std::vector<Handle<SharedFunctionInfo>>* intersecting_shared)`**:  Locates all `SharedFunctionInfo` objects whose source code range overlaps with the provided start and end positions. It also handles the case where functions need to be compiled.
- **`GetTopLevelWithRecompile(Handle<Script> script, bool* did_compile)`**:  Retrieves the `SharedFunctionInfo` for the top-level code of a script, potentially recompiling it if it hasn't been compiled yet.
- **`FindInnermostContainingFunctionInfo(Handle<Script> script, int position)`**:  Finds the `SharedFunctionInfo` for the function that contains a given source code position. It handles cases where the function might not be compiled yet.

**6. Ensuring and Creating Debug Information:**

- **`EnsureBreakInfo(Handle<SharedFunctionInfo> shared)`**: Checks if debug information exists for a given `SharedFunctionInfo` and creates it if it doesn't. This includes compiling the function if necessary.
- **`CreateBreakInfo(Handle<SharedFunctionInfo> shared)`**: Creates the actual debug information (`DebugInfo`) object for a `SharedFunctionInfo`, including a list to store breakpoints.
- **`GetOrCreateDebugInfo(DirectHandle<SharedFunctionInfo> shared)`**: Retrieves the existing `DebugInfo` for a `SharedFunctionInfo` or creates a new one if it doesn't exist.

**7. Managing Coverage Information:**

- **`InstallCoverageInfo(DirectHandle<SharedFunctionInfo> shared, Handle<CoverageInfo> coverage_info)`**: Associates code coverage information with a function's `DebugInfo`.
- **`RemoveAllCoverageInfos()`**: Removes all code coverage information from all functions.

**8. Clearing Debugger Hints and Information:**

- **`ClearAllDebuggerHints()`**:  Clears any debugger hints stored in the `DebugInfo` objects.
- **`ClearAllDebugInfos(const DebugInfoClearFunction& clear_function)`**:  A generic function to apply a clearing function to all `DebugInfo` objects.
- **`RemoveBreakInfoAndMaybeFree(DirectHandle<DebugInfo> debug_info)`**: Removes breakpoint information from a `DebugInfo` and potentially frees the `DebugInfo` object if it's now empty.

**9. Determining Breakpoint State:**

- **`IsBreakAtReturn(JavaScriptFrame* frame)`**: Checks if the current breakpoint is located at a return statement in a JavaScript function.

**10. Accessing Loaded Scripts:**

- **`GetLoadedScripts()`**:  Returns a list of all loaded JavaScript scripts.

**11. Accessing Debug Information:**

- **`TryGetDebugInfo(Tagged<SharedFunctionInfo> sfi)`**: Attempts to retrieve the `DebugInfo` for a given `SharedFunctionInfo`.
- **`HasDebugInfo(Tagged<SharedFunctionInfo> sfi)`**: Checks if a `SharedFunctionInfo` has associated `DebugInfo`.
- **`HasCoverageInfo(Tagged<SharedFunctionInfo> sfi)`**: Checks if a `SharedFunctionInfo` has associated coverage information.
- **`HasBreakInfo(Tagged<SharedFunctionInfo> sfi)`**: Checks if a `SharedFunctionInfo` has breakpoint information.
- **`BreakAtEntry(Tagged<SharedFunctionInfo> sfi)`**: Checks if a breakpoint is set at the entry point of a function.

**Relation to JavaScript and Examples:**

This section of the code is deeply intertwined with JavaScript debugging features. Here are some examples demonstrating the connection:

- **Breakpoints:** When you set a breakpoint in JavaScript code using the `debugger;` statement or through browser developer tools, functions like `GetPossibleBreakpoints`, `EnsureBreakInfo`, `CreateBreakInfo`, and `HandleDebugBreak` are involved in figuring out where the breakpoint can be set, ensuring the function is ready for debugging, and then pausing execution when the breakpoint is hit.

  ```javascript
  function myFunction() {
    console.log("Before breakpoint");
    debugger; // Execution will pause here
    console.log("After breakpoint");
  }
  myFunction();
  ```

- **Stepping:** When you use the "Step Over", "Step Into", or "Step Out" debugging controls in the browser, functions like `PrepareStep` (not shown in this snippet, but closely related) and the logic for managing the program counter (PC) are used to advance the execution to the next line or function call. The `OffHeapInstructionStream::TryLookupCode` interaction might be involved in determining the next instruction to execute.

- **Blackboxing:** When you "blacklist" or "ignore" certain scripts or functions in the debugger settings, functions like `IsBlackboxed` are used to determine whether the debugger should step into that code or skip over it.

  ```javascript
  // Imagine a debugger setting to blacklist all code in 'library.js'
  // If execution reaches a function in 'library.js', `IsBlackboxed` would return true,
  // and the debugger would likely step over it.
  ```

- **Live Edit (Hot Reload):** When you modify JavaScript code while the debugger is active, functions like `SetScriptSource` are used to update the engine with the new code, allowing you to continue debugging with the changes.

  ```javascript
  // While paused in the debugger, you might change the body of a function and then
  // resume execution. The engine needs to update the function's code.
  ```

In essence, this section of `debug.cc` provides the core infrastructure for interacting with JavaScript code during debugging. It handles the low-level details of managing code execution, breakpoints, and the overall debugging state within the V8 engine.

Prompt: 
```
这是目录为v8/src/debug/debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 OffHeapInstructionStream::TryLookupCode(isolate, pc);
        if (builtin == Builtin::kBaselineOrInterpreterEnterAtBytecode ||
            builtin == Builtin::kBaselineOrInterpreterEnterAtNextBytecode) {
          Address* pc_addr = frame->pc_address();
          Builtin advance =
              builtin == Builtin::kBaselineOrInterpreterEnterAtBytecode
                  ? Builtin::kInterpreterEnterAtBytecode
                  : Builtin::kInterpreterEnterAtNextBytecode;
          Address advance_pc =
              isolate->builtins()->code(advance)->instruction_start();
          PointerAuthentication::ReplacePC(pc_addr, advance_pc,
                                           kSystemPointerSize);
        }
      }
    }
  }

 private:
  Tagged<SharedFunctionInfo> shared_;
};
}  // namespace

void Debug::DiscardBaselineCode(Tagged<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK(shared->HasBaselineCode());
  DiscardBaselineCodeVisitor visitor(shared);
  visitor.VisitThread(isolate_, isolate_->thread_local_top());
  isolate_->thread_manager()->IterateArchivedThreads(&visitor);
  // TODO(v8:11429): Avoid this heap walk somehow.
  HeapObjectIterator iterator(isolate_->heap());
  auto trampoline = BUILTIN_CODE(isolate_, InterpreterEntryTrampoline);
  shared->FlushBaselineCode();
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsJSFunction(obj)) {
      Tagged<JSFunction> fun = Cast<JSFunction>(obj);
      if (fun->shared() == shared && fun->ActiveTierIsBaseline(isolate_)) {
        fun->UpdateCode(*trampoline);
      }
    }
  }
}

void Debug::DiscardAllBaselineCode() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DiscardBaselineCodeVisitor visitor;
  visitor.VisitThread(isolate_, isolate_->thread_local_top());
  HeapObjectIterator iterator(isolate_->heap());
  auto trampoline = BUILTIN_CODE(isolate_, InterpreterEntryTrampoline);
  isolate_->thread_manager()->IterateArchivedThreads(&visitor);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsJSFunction(obj)) {
      Tagged<JSFunction> fun = Cast<JSFunction>(obj);
      if (fun->ActiveTierIsBaseline(isolate_)) {
        fun->UpdateCode(*trampoline);
      }
    } else if (IsSharedFunctionInfo(obj)) {
      Tagged<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(obj);
      if (shared->HasBaselineCode()) {
        shared->FlushBaselineCode();
      }
    }
  }
}

void Debug::DeoptimizeFunction(DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);

  if (shared->HasBaselineCode()) {
    DiscardBaselineCode(*shared);
  }
  Deoptimizer::DeoptimizeAllOptimizedCodeWithFunction(isolate_, shared);
}

void Debug::PrepareFunctionForDebugExecution(
    DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // To prepare bytecode for debugging, we already need to have the debug
  // info (containing the debug copy) upfront, but since we do not recompile,
  // preparing for break points cannot fail.
  DCHECK(shared->is_compiled());
  DirectHandle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(),
                                     isolate_);
  if (debug_info->flags(kRelaxedLoad) & DebugInfo::kPreparedForDebugExecution) {
    return;
  }

  // Have to discard baseline code before installing debug bytecode, since the
  // bytecode array field on the baseline code object is immutable.
  if (debug_info->CanBreakAtEntry()) {
    // Deopt everything in case the function is inlined anywhere.
    Deoptimizer::DeoptimizeAll(isolate_);
    DiscardAllBaselineCode();
  } else {
    DeoptimizeFunction(shared);
  }

  if (shared->HasBytecodeArray()) {
    DCHECK(!shared->HasBaselineCode());
    SharedFunctionInfo::InstallDebugBytecode(shared, isolate_);
  }

  if (debug_info->CanBreakAtEntry()) {
    InstallDebugBreakTrampoline();
  } else {
    // Update PCs on the stack to point to recompiled code.
    RedirectActiveFunctions redirect_visitor(
        isolate_, *shared, RedirectActiveFunctions::Mode::kUseDebugBytecode);
    redirect_visitor.VisitThread(isolate_, isolate_->thread_local_top());
    isolate_->thread_manager()->IterateArchivedThreads(&redirect_visitor);
  }

  debug_info->set_flags(
      debug_info->flags(kRelaxedLoad) | DebugInfo::kPreparedForDebugExecution,
      kRelaxedStore);
}

namespace {

bool IsJSFunctionAndNeedsTrampoline(Isolate* isolate,
                                    Tagged<Object> maybe_function) {
  if (!IsJSFunction(maybe_function)) return false;
  std::optional<Tagged<DebugInfo>> debug_info =
      isolate->debug()->TryGetDebugInfo(
          Cast<JSFunction>(maybe_function)->shared());
  return debug_info.has_value() && debug_info.value()->CanBreakAtEntry();
}

}  // namespace

void Debug::InstallDebugBreakTrampoline() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Check the list of debug infos whether the debug break trampoline needs to
  // be installed. If that's the case, iterate the heap for functions to rewire
  // to the trampoline.
  // If there is a breakpoint at function entry, we need to install trampoline.
  bool needs_to_use_trampoline = false;
  // If there we break at entry to an api callback, we need to clear ICs.
  bool needs_to_clear_ic = false;

  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Tagged<DebugInfo> debug_info = it.Next();
    if (debug_info->CanBreakAtEntry()) {
      needs_to_use_trampoline = true;
      if (debug_info->shared()->IsApiFunction()) {
        needs_to_clear_ic = true;
        break;
      }
    }
  }

  if (!needs_to_use_trampoline) return;

  HandleScope scope(isolate_);
  DirectHandle<Code> trampoline = BUILTIN_CODE(isolate_, DebugBreakTrampoline);
  std::vector<Handle<JSFunction>> needs_compile;
  using AccessorPairWithContext =
      std::pair<Handle<AccessorPair>, Handle<NativeContext>>;
  std::vector<AccessorPairWithContext> needs_instantiate;
  {
    // Deduplicate {needs_instantiate} by recording all collected AccessorPairs.
    std::set<Tagged<AccessorPair>> recorded;
    HeapObjectIterator iterator(isolate_->heap());
    DisallowGarbageCollection no_gc;
    for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
         obj = iterator.Next()) {
      if (needs_to_clear_ic && IsFeedbackVector(obj)) {
        Cast<FeedbackVector>(obj)->ClearSlots(isolate_);
        continue;
      } else if (IsJSFunctionAndNeedsTrampoline(isolate_, obj)) {
        Tagged<JSFunction> fun = Cast<JSFunction>(obj);
        if (!fun->is_compiled(isolate_)) {
          needs_compile.push_back(handle(fun, isolate_));
        } else {
          fun->UpdateCode(*trampoline);
        }
      } else if (IsJSObject(obj)) {
        Tagged<JSObject> object = Cast<JSObject>(obj);
        Tagged<DescriptorArray> descriptors =
            object->map()->instance_descriptors(kRelaxedLoad);

        for (InternalIndex i : object->map()->IterateOwnDescriptors()) {
          if (descriptors->GetDetails(i).kind() == PropertyKind::kAccessor) {
            Tagged<Object> value = descriptors->GetStrongValue(i);
            if (!IsAccessorPair(value)) continue;

            Tagged<AccessorPair> accessor_pair = Cast<AccessorPair>(value);
            if (!IsFunctionTemplateInfo(accessor_pair->getter()) &&
                !IsFunctionTemplateInfo(accessor_pair->setter())) {
              continue;
            }
            if (recorded.find(accessor_pair) != recorded.end()) continue;

            needs_instantiate.emplace_back(
                handle(accessor_pair, isolate_),
                handle(object->GetCreationContext().value(), isolate_));
            recorded.insert(accessor_pair);
          }
        }
      }
    }
  }

  // Forcibly instantiate all lazy accessor pairs to make sure that they
  // properly hit the debug break trampoline.
  for (AccessorPairWithContext tuple : needs_instantiate) {
    DirectHandle<AccessorPair> accessor_pair = tuple.first;
    Handle<NativeContext> native_context = tuple.second;
    Handle<Object> getter = AccessorPair::GetComponent(
        isolate_, native_context, accessor_pair, ACCESSOR_GETTER);
    if (IsJSFunctionAndNeedsTrampoline(isolate_, *getter)) {
      Cast<JSFunction>(getter)->UpdateCode(*trampoline);
    }

    DirectHandle<Object> setter = AccessorPair::GetComponent(
        isolate_, native_context, accessor_pair, ACCESSOR_SETTER);
    if (IsJSFunctionAndNeedsTrampoline(isolate_, *setter)) {
      Cast<JSFunction>(setter)->UpdateCode(*trampoline);
    }
  }

  // By overwriting the function code with DebugBreakTrampoline, which tailcalls
  // to shared code, we bypass CompileLazy. Perform CompileLazy here instead.
  for (Handle<JSFunction> fun : needs_compile) {
    IsCompiledScope is_compiled_scope;
    Compiler::Compile(isolate_, fun, Compiler::CLEAR_EXCEPTION,
                      &is_compiled_scope);
    DCHECK(is_compiled_scope.is_compiled());
    fun->UpdateCode(*trampoline);
  }
}

namespace {
void FindBreakablePositions(Handle<DebugInfo> debug_info, int start_position,
                            int end_position,
                            std::vector<BreakLocation>* locations) {
  DCHECK(debug_info->HasInstrumentedBytecodeArray());
  BreakIterator it(debug_info);
  while (!it.Done()) {
    if (it.GetDebugBreakType() != DEBUG_BREAK_SLOT_AT_SUSPEND &&
        it.position() >= start_position && it.position() < end_position) {
      locations->push_back(it.GetBreakLocation());
    }
    it.Next();
  }
}

bool CompileTopLevel(Isolate* isolate, Handle<Script> script,
                     MaybeHandle<SharedFunctionInfo>* result = nullptr) {
  if (script->compilation_type() == Script::CompilationType::kEval ||
      script->is_wrapped()) {
    return false;
  }
  UnoptimizedCompileState compile_state;
  ReusableUnoptimizedCompileState reusable_state(isolate);
  UnoptimizedCompileFlags flags =
      UnoptimizedCompileFlags::ForScriptCompile(isolate, *script);
  flags.set_is_reparse(true);
  ParseInfo parse_info(isolate, flags, &compile_state, &reusable_state);
  IsCompiledScope is_compiled_scope;
  const MaybeHandle<SharedFunctionInfo> maybe_result =
      Compiler::CompileToplevel(&parse_info, script, isolate,
                                &is_compiled_scope);
  if (maybe_result.is_null()) {
    if (isolate->has_exception()) {
      isolate->clear_exception();
    }
    return false;
  }
  if (result) *result = maybe_result;
  return true;
}
}  // namespace

bool Debug::GetPossibleBreakpoints(Handle<Script> script, int start_position,
                                   int end_position, bool restrict_to_function,
                                   std::vector<BreakLocation>* locations) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (restrict_to_function) {
    Handle<Object> result =
        FindInnermostContainingFunctionInfo(script, start_position);
    if (IsUndefined(*result, isolate_)) return false;

    // Make sure the function has set up the debug info.
    Handle<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(result);
    if (!EnsureBreakInfo(shared)) return false;
    PrepareFunctionForDebugExecution(shared);

    Handle<DebugInfo> debug_info(TryGetDebugInfo(*shared).value(), isolate_);
    FindBreakablePositions(debug_info, start_position, end_position, locations);
    return true;
  }

  HandleScope scope(isolate_);
  std::vector<Handle<SharedFunctionInfo>> candidates;
  if (!FindSharedFunctionInfosIntersectingRange(script, start_position,
                                                end_position, &candidates)) {
    return false;
  }
  for (const auto& candidate : candidates) {
    CHECK(candidate->HasBreakInfo(isolate_));
    Handle<DebugInfo> debug_info(TryGetDebugInfo(*candidate).value(), isolate_);
    FindBreakablePositions(debug_info, start_position, end_position, locations);
  }
  return true;
}

class SharedFunctionInfoFinder {
 public:
  explicit SharedFunctionInfoFinder(int target_position)
      : current_start_position_(kNoSourcePosition),
        target_position_(target_position) {}

  void NewCandidate(Tagged<SharedFunctionInfo> shared,
                    Tagged<JSFunction> closure = JSFunction()) {
    if (!shared->IsSubjectToDebugging()) return;
    int start_position = shared->function_token_position();
    if (start_position == kNoSourcePosition) {
      start_position = shared->StartPosition();
    }

    if (start_position > target_position_) return;
    if (target_position_ >= shared->EndPosition()) {
      // The SharedFunctionInfo::EndPosition() is generally exclusive, but there
      // are assumptions in various places in the debugger that for script level
      // (toplevel function) there's an end position that is technically outside
      // the script. It might be worth revisiting the overall design here at
      // some point in the future.
      if (!shared->is_toplevel() || target_position_ > shared->EndPosition()) {
        return;
      }
    }

    if (!current_candidate_.is_null()) {
      if (current_start_position_ == start_position &&
          shared->EndPosition() == current_candidate_->EndPosition()) {
        // If we already have a matching closure, do not throw it away.
        if (!current_candidate_closure_.is_null() && closure.is_null()) return;
        // If a top-level function contains only one function
        // declaration the source for the top-level and the function
        // is the same. In that case prefer the non top-level function.
        if (!current_candidate_->is_toplevel() && shared->is_toplevel()) return;
      } else if (start_position < current_start_position_ ||
                 current_candidate_->EndPosition() < shared->EndPosition()) {
        return;
      }
    }

    current_start_position_ = start_position;
    current_candidate_ = shared;
    current_candidate_closure_ = closure;
  }

  Tagged<SharedFunctionInfo> Result() { return current_candidate_; }

  Tagged<JSFunction> ResultClosure() { return current_candidate_closure_; }

 private:
  Tagged<SharedFunctionInfo> current_candidate_;
  Tagged<JSFunction> current_candidate_closure_;
  int current_start_position_;
  int target_position_;
  DISALLOW_GARBAGE_COLLECTION(no_gc_)
};

namespace {
Tagged<SharedFunctionInfo> FindSharedFunctionInfoCandidate(
    int position, DirectHandle<Script> script, Isolate* isolate) {
  SharedFunctionInfoFinder finder(position);
  SharedFunctionInfo::ScriptIterator iterator(isolate, *script);
  for (Tagged<SharedFunctionInfo> info = iterator.Next(); !info.is_null();
       info = iterator.Next()) {
    finder.NewCandidate(info);
  }
  return finder.Result();
}
}  // namespace

Handle<SharedFunctionInfo> Debug::FindClosestSharedFunctionInfoFromPosition(
    int position, Handle<Script> script,
    Handle<SharedFunctionInfo> outer_shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  Handle<DebugInfo> outer_debug_info(TryGetDebugInfo(*outer_shared).value(),
                                     isolate_);
  CHECK(outer_debug_info->HasBreakInfo());
  int closest_position = FindBreakablePosition(outer_debug_info, position);
  Handle<SharedFunctionInfo> closest_candidate = outer_shared;
  if (closest_position == position) return outer_shared;

  const int start_position = outer_shared->StartPosition();
  const int end_position = outer_shared->EndPosition();
  if (start_position == end_position) return outer_shared;

  if (closest_position == 0) closest_position = end_position;
  std::vector<Handle<SharedFunctionInfo>> candidates;
  // Find all shared function infos of functions that are intersecting from
  // the requested position until the end of the enclosing function.
  if (!FindSharedFunctionInfosIntersectingRange(
          script, position, closest_position, &candidates)) {
    return outer_shared;
  }

  for (auto candidate : candidates) {
    Handle<DebugInfo> debug_info(TryGetDebugInfo(*candidate).value(), isolate_);
    CHECK(debug_info->HasBreakInfo());
    const int candidate_position = FindBreakablePosition(debug_info, position);
    if (candidate_position >= position &&
        candidate_position < closest_position) {
      closest_position = candidate_position;
      closest_candidate = candidate;
    }
    if (closest_position == position) break;
  }
  return closest_candidate;
}

bool Debug::FindSharedFunctionInfosIntersectingRange(
    Handle<Script> script, int start_position, int end_position,
    std::vector<Handle<SharedFunctionInfo>>* intersecting_shared) {
  bool candidateSubsumesRange = false;
  bool triedTopLevelCompile = false;

  while (true) {
    std::vector<Handle<SharedFunctionInfo>> candidates;
    std::vector<IsCompiledScope> compiled_scopes;
    {
      DisallowGarbageCollection no_gc;
      SharedFunctionInfo::ScriptIterator iterator(isolate_, *script);
      for (Tagged<SharedFunctionInfo> info = iterator.Next(); !info.is_null();
           info = iterator.Next()) {
        if (info->EndPosition() < start_position ||
            info->StartPosition() >= end_position) {
          continue;
        }
        candidateSubsumesRange |= info->StartPosition() <= start_position &&
                                  info->EndPosition() >= end_position;
        if (!info->IsSubjectToDebugging()) continue;
        if (!info->is_compiled() && !info->allows_lazy_compilation()) continue;
        candidates.push_back(i::handle(info, isolate_));
      }
    }

    if (!triedTopLevelCompile && !candidateSubsumesRange &&
        script->infos()->length() > 0) {
      MaybeHandle<SharedFunctionInfo> shared =
          GetTopLevelWithRecompile(script, &triedTopLevelCompile);
      if (shared.is_null()) return false;
      if (triedTopLevelCompile) continue;
    }

    bool was_compiled = false;
    for (const auto& candidate : candidates) {
      IsCompiledScope is_compiled_scope(candidate->is_compiled_scope(isolate_));
      if (!is_compiled_scope.is_compiled()) {
        // InstructionStream that cannot be compiled lazily are internal and not
        // debuggable.
        DCHECK(candidate->allows_lazy_compilation());
        if (!Compiler::Compile(isolate_, candidate, Compiler::CLEAR_EXCEPTION,
                               &is_compiled_scope)) {
          return false;
        } else {
          was_compiled = true;
        }
      }
      DCHECK(is_compiled_scope.is_compiled());
      compiled_scopes.push_back(is_compiled_scope);
      if (!EnsureBreakInfo(candidate)) return false;
      PrepareFunctionForDebugExecution(candidate);
    }
    if (was_compiled) continue;
    *intersecting_shared = std::move(candidates);
    return true;
  }
  UNREACHABLE();
}

MaybeHandle<SharedFunctionInfo> Debug::GetTopLevelWithRecompile(
    Handle<Script> script, bool* did_compile) {
  DCHECK_LE(kFunctionLiteralIdTopLevel, script->infos()->length());
  Tagged<MaybeObject> maybeToplevel =
      script->infos()->get(kFunctionLiteralIdTopLevel);
  Tagged<HeapObject> heap_object;
  const bool topLevelInfoExists =
      maybeToplevel.GetHeapObject(&heap_object) && !IsUndefined(heap_object);
  if (topLevelInfoExists) {
    if (did_compile) *did_compile = false;
    return handle(Cast<SharedFunctionInfo>(heap_object), isolate_);
  }

  MaybeHandle<SharedFunctionInfo> shared;
  CompileTopLevel(isolate_, script, &shared);
  if (did_compile) *did_compile = true;
  return shared;
}

// We need to find a SFI for a literal that may not yet have been compiled yet,
// and there may not be a JSFunction referencing it. Find the SFI closest to
// the given position, compile it to reveal possible inner SFIs and repeat.
// While we are at this, also ensure code with debug break slots so that we do
// not have to compile a SFI without JSFunction, which is paifu for those that
// cannot be compiled without context (need to find outer compilable SFI etc.)
Handle<Object> Debug::FindInnermostContainingFunctionInfo(Handle<Script> script,
                                                          int position) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  for (int iteration = 0;; iteration++) {
    // Go through all shared function infos associated with this script to
    // find the innermost function containing this position.
    // If there is no shared function info for this script at all, there is
    // no point in looking for it by walking the heap.

    Tagged<SharedFunctionInfo> shared;
    IsCompiledScope is_compiled_scope;
    {
      shared = FindSharedFunctionInfoCandidate(position, script, isolate_);
      if (shared.is_null()) {
        if (iteration > 0) break;
        // It might be that the shared function info is not available as the
        // top level functions are removed due to the GC. Try to recompile
        // the top level functions.
        const bool success = CompileTopLevel(isolate_, script);
        if (!success) break;
        continue;
      }
      // We found it if it's already compiled.
      is_compiled_scope = shared->is_compiled_scope(isolate_);
      if (is_compiled_scope.is_compiled()) {
        Handle<SharedFunctionInfo> shared_handle(shared, isolate_);
        // If the iteration count is larger than 1, we had to compile the outer
        // function in order to create this shared function info. So there can
        // be no JSFunction referencing it. We can anticipate creating a debug
        // info while bypassing PrepareFunctionForDebugExecution.
        if (iteration > 1) {
          CreateBreakInfo(shared_handle);
        }
        return shared_handle;
      }
    }
    // If not, compile to reveal inner functions.
    HandleScope scope(isolate_);
    // InstructionStream that cannot be compiled lazily are internal and not
    // debuggable.
    DCHECK(shared->allows_lazy_compilation());
    if (!Compiler::Compile(isolate_, handle(shared, isolate_),
                           Compiler::CLEAR_EXCEPTION, &is_compiled_scope)) {
      break;
    }
  }
  return isolate_->factory()->undefined_value();
}

// Ensures the debug information is present for shared.
bool Debug::EnsureBreakInfo(Handle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Return if we already have the break info for shared.
  if (shared->HasBreakInfo(isolate_)) {
    DCHECK(shared->is_compiled());
    return true;
  }
  if (!shared->IsSubjectToDebugging() && !CanBreakAtEntry(shared)) {
    return false;
  }
  IsCompiledScope is_compiled_scope = shared->is_compiled_scope(isolate_);
  if (!is_compiled_scope.is_compiled() &&
      !Compiler::Compile(isolate_, shared, Compiler::CLEAR_EXCEPTION,
                         &is_compiled_scope, CreateSourcePositions::kYes)) {
    return false;
  }
  CreateBreakInfo(shared);
  return true;
}

void Debug::CreateBreakInfo(Handle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);
  DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);

  // Initialize with break information.

  DCHECK(!debug_info->HasBreakInfo());

  Factory* factory = isolate_->factory();
  DirectHandle<FixedArray> break_points(
      factory->NewFixedArray(DebugInfo::kEstimatedNofBreakPointsInFunction));

  int flags = debug_info->flags(kRelaxedLoad);
  flags |= DebugInfo::kHasBreakInfo;
  if (CanBreakAtEntry(shared)) flags |= DebugInfo::kCanBreakAtEntry;
  debug_info->set_flags(flags, kRelaxedStore);
  debug_info->set_break_points(*break_points);

  SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate_, shared);
}

Handle<DebugInfo> Debug::GetOrCreateDebugInfo(
    DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);

  if (std::optional<Tagged<DebugInfo>> di = debug_infos_.Find(*shared)) {
    return handle(di.value(), isolate_);
  }

  Handle<DebugInfo> debug_info = isolate_->factory()->NewDebugInfo(shared);
  debug_infos_.Insert(*shared, *debug_info);
  return debug_info;
}

void Debug::InstallCoverageInfo(DirectHandle<SharedFunctionInfo> shared,
                                Handle<CoverageInfo> coverage_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK(!coverage_info.is_null());

  DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);

  DCHECK(!debug_info->HasCoverageInfo());

  debug_info->set_flags(
      debug_info->flags(kRelaxedLoad) | DebugInfo::kHasCoverageInfo,
      kRelaxedStore);
  debug_info->set_coverage_info(*coverage_info);
}

void Debug::RemoveAllCoverageInfos() {
  ClearAllDebugInfos([=, this](DirectHandle<DebugInfo> info) {
    info->ClearCoverageInfo(isolate_);
  });
}

void Debug::ClearAllDebuggerHints() {
  ClearAllDebugInfos(
      [=](DirectHandle<DebugInfo> info) { info->set_debugger_hints(0); });
}

void Debug::ClearAllDebugInfos(const DebugInfoClearFunction& clear_function) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);

  HandleScope scope(isolate_);
  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Handle<DebugInfo> debug_info(it.Next(), isolate_);
    clear_function(debug_info);
    if (debug_info->IsEmpty()) it.DeleteNext();
  }
}

void Debug::RemoveBreakInfoAndMaybeFree(DirectHandle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  debug_info->ClearBreakInfo(isolate_);
  if (debug_info->IsEmpty()) {
    debug_infos_.DeleteSlow(debug_info->shared());
  }
}

bool Debug::IsBreakAtReturn(JavaScriptFrame* frame) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);

  // Get the executing function in which the debug break occurred.
  DirectHandle<SharedFunctionInfo> shared(frame->function()->shared(),
                                          isolate_);

  // With no debug info there are no break points, so we can't be at a return.
  Handle<DebugInfo> debug_info;
  if (!ToHandle(isolate_, TryGetDebugInfo(*shared), &debug_info) ||
      !debug_info->HasBreakInfo()) {
    return false;
  }

  DCHECK(!frame->is_optimized());
  BreakLocation location = BreakLocation::FromFrame(debug_info, frame);
  return location.IsReturn();
}

Handle<FixedArray> Debug::GetLoadedScripts() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  isolate_->heap()->CollectAllGarbage(GCFlag::kNoFlags,
                                      GarbageCollectionReason::kDebugger);
  Factory* factory = isolate_->factory();
  if (!IsWeakArrayList(*factory->script_list())) {
    return factory->empty_fixed_array();
  }
  auto array = Cast<WeakArrayList>(factory->script_list());
  Handle<FixedArray> results = factory->NewFixedArray(array->length());
  int length = 0;
  {
    Script::Iterator iterator(isolate_);
    for (Tagged<Script> script = iterator.Next(); !script.is_null();
         script = iterator.Next()) {
      if (script->HasValidSource()) results->set(length++, script);
    }
  }
  return FixedArray::RightTrimOrEmpty(isolate_, results, length);
}

std::optional<Tagged<DebugInfo>> Debug::TryGetDebugInfo(
    Tagged<SharedFunctionInfo> sfi) {
  return debug_infos_.Find(sfi);
}

bool Debug::HasDebugInfo(Tagged<SharedFunctionInfo> sfi) {
  return TryGetDebugInfo(sfi).has_value();
}

bool Debug::HasCoverageInfo(Tagged<SharedFunctionInfo> sfi) {
  if (std::optional<Tagged<DebugInfo>> debug_info = TryGetDebugInfo(sfi)) {
    return debug_info.value()->HasCoverageInfo();
  }
  return false;
}

bool Debug::HasBreakInfo(Tagged<SharedFunctionInfo> sfi) {
  if (std::optional<Tagged<DebugInfo>> debug_info = TryGetDebugInfo(sfi)) {
    return debug_info.value()->HasBreakInfo();
  }
  return false;
}

bool Debug::BreakAtEntry(Tagged<SharedFunctionInfo> sfi) {
  if (std::optional<Tagged<DebugInfo>> debug_info = TryGetDebugInfo(sfi)) {
    return debug_info.value()->BreakAtEntry();
  }
  return false;
}

std::optional<Tagged<Object>> Debug::OnThrow(Handle<Object> exception) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (in_debug_scope() || ignore_events()) return {};
  // Temporarily clear any exception to allow evaluating
  // JavaScript from the debug event handler.
  HandleScope scope(isolate_);
  {
    std::optional<Isolate::ExceptionScope> exception_scope;
    if (isolate_->has_exception()) exception_scope.emplace(isolate_);
    Isolate::CatchType catch_type = isolate_->PredictExceptionCatcher();
    OnException(exception, MaybeHandle<JSPromise>(),
                catch_type == Isolate::CAUGHT_BY_ASYNC_AWAIT ||
                        catch_type == Isolate::CAUGHT_BY_PROMISE
                    ? v8::debug::kPromiseRejection
                    : v8::debug::kException);
  }
  PrepareStepOnThrow();
  // If the OnException handler requested termination, then indicated this to
  // our caller Isolate::Throw so it can deal with it immediatelly instead of
  // throwing the original exception.
  if (isolate_->stack_guard()->CheckTerminateExecution()) {
    isolate_->stack_guard()->ClearTerminateExecution();
    return isolate_->TerminateExecution();
  }
  return {};
}

void Debug::OnPromiseReject(Handle<Object> promise, Handle<Object> value) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (in_debug_scope() || ignore_events()) return;
  MaybeHandle<JSPromise> maybe_promise;
  if (IsJSPromise(*promise)) {
    Handle<JSPromise> js_promise = Cast<JSPromise>(promise);
    if (js_promise->is_silent()) {
      return;
    }
    maybe_promise = js_promise;
  }
  OnException(value, maybe_promise, v8::debug::kPromiseRejection);
}

bool Debug::IsFrameBlackboxed(JavaScriptFrame* frame) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);
  std::vector<Handle<SharedFunctionInfo>> infos;
  frame->GetFunctions(&infos);
  for (const auto& info : infos) {
    if (!IsBlackboxed(info)) return false;
  }
  return true;
}

void Debug::OnException(Handle<Object> exception,
                        MaybeHandle<JSPromise> promise,
                        v8::debug::ExceptionType exception_type) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Do not trigger exception event on stack overflow. We cannot perform
  // anything useful for debugging in that situation.
  StackLimitCheck stack_limit_check(isolate_);
  if (stack_limit_check.JsHasOverflowed()) return;

  // Return if the event has nowhere to go.
  if (!debug_delegate_) return;

  // Return if we are not interested in exception events.
  if (!break_on_caught_exception_ && !break_on_uncaught_exception_) return;

  HandleScope scope(isolate_);

  bool all_frames_ignored = true;
  bool is_debuggable = false;
  bool uncaught = !isolate_->WalkCallStackAndPromiseTree(
      promise, [this, &all_frames_ignored,
                &is_debuggable](Isolate::PromiseHandler handler) {
        if (!handler.async) {
          is_debuggable = true;
        } else if (!is_debuggable) {
          // Don't bother checking ignore listing if there are no debuggable
          // frames on the callstack
          return;
        }
        all_frames_ignored =
            all_frames_ignored &&
            IsBlackboxed(handle(handler.function_info, isolate_));
      });

  if (all_frames_ignored || !is_debuggable) {
    return;
  }

  if (!uncaught) {
    if (!break_on_caught_exception_) {
      return;
    }
  } else {
    if (!break_on_uncaught_exception_) {
      return;
    }
  }

  {
    StackFrameIterator it(isolate_);
    for (; !it.done(); it.Advance()) {
      if (it.frame()->is_javascript()) {
        JavaScriptFrame* frame = JavaScriptFrame::cast(it.frame());
        FrameSummary summary = FrameSummary::GetTop(frame);
        DirectHandle<SharedFunctionInfo> shared{
            summary.AsJavaScript().function()->shared(), isolate_};
        if (shared->IsSubjectToDebugging()) {
          Handle<DebugInfo> debug_info;
          std::vector<BreakLocation> break_locations;
          if (ToHandle(isolate_, TryGetDebugInfo(*shared), &debug_info) &&
              debug_info->HasBreakInfo()) {
            // Enter the debugger.
            DebugScope debug_scope(this);
            BreakLocation::AllAtCurrentStatement(debug_info, frame,
                                                 &break_locations);
          }
          if (IsMutedAtAnyBreakLocation(shared, break_locations)) {
            return;
          }
          break;  // Stop at first debuggable function
        }
      }
#if V8_ENABLE_WEBASSEMBLY
      else if (it.frame()->is_wasm()) {
        const WasmFrame* frame = WasmFrame::cast(it.frame());
        if (IsMutedAtWasmLocation(frame->script(), frame->position())) {
          return;
        }
        // Wasm is always subject to debugging
        break;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    if (it.done()) return;  // Do not trigger an event with an empty stack.
  }

  DebugScope debug_scope(this);
  DisableBreak no_recursive_break(this);

  {
    Handle<Object> promise_object;
    if (!promise.ToHandle(&promise_object)) {
      promise_object = isolate_->factory()->undefined_value();
    }
    RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
    debug_delegate_->ExceptionThrown(
        v8::Utils::ToLocal(isolate_->native_context()),
        v8::Utils::ToLocal(exception), v8::Utils::ToLocal(promise_object),
        uncaught, exception_type);
  }
}

void Debug::OnDebugBreak(Handle<FixedArray> break_points_hit,
                         StepAction lastStepAction,
                         v8::debug::BreakReasons break_reasons) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK(!break_points_hit.is_null());
  // The caller provided for DebugScope.
  AssertDebugContext();
  // Bail out if there is no listener for this event
  if (ignore_events()) return;

#ifdef DEBUG
  PrintBreakLocation();
#endif  // DEBUG

  if (!debug_delegate_) return;
  DCHECK(in_debug_scope());
  HandleScope scope(isolate_);
  DisableBreak no_recursive_break(this);

  if ((lastStepAction == StepAction::StepOver ||
       lastStepAction == StepAction::StepInto) &&
      ShouldBeSkipped()) {
    PrepareStep(lastStepAction);
    return;
  }

  std::vector<int> inspector_break_points_hit;
  // This array contains breakpoints installed using JS debug API.
  for (int i = 0; i < break_points_hit->length(); ++i) {
    Tagged<BreakPoint> break_point = Cast<BreakPoint>(break_points_hit->get(i));
    inspector_break_points_hit.push_back(break_point->id());
  }
  {
    RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
    if (lastStepAction != StepAction::StepNone)
      break_reasons.Add(debug::BreakReason::kStep);
    debug_delegate_->BreakProgramRequested(
        v8::Utils::ToLocal(isolate_->native_context()),
        inspector_break_points_hit, break_reasons);
  }
}

namespace {
debug::Location GetDebugLocation(DirectHandle<Script> script,
                                 int source_position) {
  Script::PositionInfo info;
  Script::GetPositionInfo(script, source_position, &info);
  // V8 provides ScriptCompiler::CompileFunction method which takes
  // expression and compile it as anonymous function like (function() ..
  // expression ..). To produce correct locations for stmts inside of this
  // expression V8 compile this function with negative offset. Instead of stmt
  // position blackboxing use function start position which is negative in
  // described case.
  return debug::Location(std::max(info.line, 0), std::max(info.column, 0));
}
}  // namespace

bool Debug::IsFunctionBlackboxed(DirectHandle<Script> script, const int start,
                                 const int end) {
  debug::Location start_location = GetDebugLocation(script, start);
  debug::Location end_location = GetDebugLocation(script, end);
  return debug_delegate_->IsFunctionBlackboxed(
      ToApiHandle<debug::Script>(script), start_location, end_location);
}

bool Debug::IsBlackboxed(DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  if (!debug_delegate_) return !shared->IsSubjectToDebugging();
  DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);
  if (!debug_info->computed_debug_is_blackboxed()) {
    bool is_blackboxed =
        !shared->IsSubjectToDebugging() || !IsScript(shared->script());
    if (!is_blackboxed) {
      SuppressDebug while_processing(this);
      HandleScope handle_scope(isolate_);
      PostponeInterruptsScope no_interrupts(isolate_);
      DisableBreak no_recursive_break(this);
      DCHECK(IsScript(shared->script()));
      DirectHandle<Script> script(Cast<Script>(shared->script()), isolate_);
      DCHECK(script->IsUserJavaScript());
      {
        RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
        is_blackboxed = this->IsFunctionBlackboxed(
            script, shared->StartPosition(), shared->EndPosition());
      }
    }
    debug_info->set_debug_is_blackboxed(is_blackboxed);
    debug_info->set_computed_debug_is_blackboxed(true);
  }
  return debug_info->debug_is_blackboxed();
}

bool Debug::ShouldBeSkipped() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  SuppressDebug while_processing(this);
  PostponeInterruptsScope no_interrupts(isolate_);
  DisableBreak no_recursive_break(this);

  DebuggableStackFrameIterator iterator(isolate_);
  FrameSummary summary = iterator.GetTopValidFrame();
  Handle<Object> script_obj = summary.script();
  if (!IsScript(*script_obj)) return false;

  DirectHandle<Script> script = Cast<Script>(script_obj);
  summary.EnsureSourcePositionsAvailable();
  int source_position = summary.SourcePosition();
  Script::PositionInfo info;
  Script::GetPositionInfo(script, source_position, &info);
  {
    RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
    return debug_delegate_->ShouldBeSkipped(ToApiHandle<debug::Script>(script),
                                            info.line, info.column);
  }
}

bool Debug::AllFramesOnStackAreBlackboxed() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);

  HandleScope scope(isolate_);
  for (StackFrameIterator it(isolate_, isolate_->thread_local_top());
       !it.done(); it.Advance()) {
    StackFrame* frame = it.frame();
    if (frame->is_javascript() &&
        !IsFrameBlackboxed(JavaScriptFrame::cast(frame))) {
      return false;
    }
  }
  return true;
}

bool Debug::CanBreakAtEntry(DirectHandle<SharedFunctionInfo> shared) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Allow break at entry for builtin functions.
  if (shared->native() || shared->IsApiFunction()) {
    // Functions that are subject to debugging can have regular breakpoints.
    DCHECK(!shared->IsSubjectToDebugging());
    return true;
  }
  return false;
}

bool Debug::SetScriptSource(Handle<Script> script, Handle<String> source,
                            bool preview, bool allow_top_frame_live_editing,
                            debug::LiveEditResult* result) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DebugScope debug_scope(this);
  running_live_edit_ = true;
  LiveEdit::PatchScript(isolate_, script, source, preview,
                        allow_top_frame_live_editing, result);
  running_live_edit_ = false;
  return result->status == debug::LiveEditResult::OK;
}

void Debug::OnCompileError(DirectHandle<Script> script) {
  ProcessCompileEvent(true, script);
}

void Debug::OnAfterCompile(DirectHandle<Script> script) {
  ProcessCompileEvent(false, script);
}

void Debug::ProcessCompileEvent(bool has_compile_error,
                                DirectHandle<Script> script) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Ignore temporary scripts.
  if (script->id() == Script::kTemporaryScriptId) return;
  // TODO(kozyatinskiy): teach devtools to work with liveedit scripts better
  // first and then remove this fast return.
  if (running_live_edit_) return;
  // Attach the correct debug id to the script. The debug id is used by the
  // inspector to filter scripts by native context.
  script->set_context_data(isolate_->native_context()->debug_context_id());
  if (ignore_events()) return;
  if (!script->IsSubjectToDebugging()) return;
  if (!debug_delegate_) return;
  SuppressDebug while_processing(this);
  DebugScope debug_scope(this);
  HandleScope scope(isolate_);
  DisableBreak no_recursive_break(this);
  AllowJavascriptExecution allow_script(isolate_);
  {
    RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebuggerCallback);
    debug_delegate_->ScriptCompiled(ToApiHandle<debug::Script>(script),
                                    running_live_edit_, has_compile_error);
  }
}

int Debug::CurrentFrameCount() {
  DebuggableStackFrameIterator it(isolate_);
  if (break_frame_id() != StackFrameId::NO_ID) {
    // Skip to break frame.
    DCHECK(in_debug_scope());
    while (!it.done() && it.frame()->id() != break_frame_id()) it.Advance();
  }
  int counter = 0;
  for (; !it.done(); it.Advance()) {
    counter += it.FrameFunctionCount();
  }
  return counter;
}

void Debug::SetDebugDelegate(debug::DebugDelegate* delegate) {
  debug_delegate_ = delegate;
  UpdateState();
}

void Debug::UpdateState() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  bool is_active = debug_delegate_ != nullptr;
  if (is_active == is_active_) return;
  if (is_active) {
    // Note that the debug context could have already been loaded to
    // bootstrap test cases.
    isolate_->compilation_cache()->DisableScriptAndEval();
    isolate_->CollectSourcePositionsForAllBytecodeArrays();
    is_active = true;
  } else {
    isolate_->compilation_cache()->EnableScriptAndEval();
    Unload();
  }
  is_active_ = is_active;
  isolate_->PromiseHookStateUpdated();
}

void Debug::UpdateHookOnFunctionCall() {
  static_assert(LastStepAction == StepInto);
  hook_on_function_call_ =
      thread_local_.last_step_action_ == StepInto ||
      isolate_->debug_execution_mode() == DebugInfo::kSideEffects ||
      thread_local_.break_on_next_function_call_;
}

void Debug::HandleDebugBreak(IgnoreBreakMode ignore_break_mode,
                             v8::debug::BreakReasons break_reasons) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Ignore debug break during bootstrapping.
  if (isolate_->bootstrapper()->IsActive()) return;
  // Just continue if breaks are disabled.
  if (break_disabled()) return;
  // Ignore debug break if debugger is not active.
  if (!is_active()) return;

  StackLimitCheck check(isolate_);
  if (check.HasOverflowed()) return;

  HandleScope scope(isolate_);
  MaybeHandle<FixedArray> break_points;
  {
    DebuggableStackFrameIterator it(isolate_);
    DCHECK(!it.done());
    JavaScriptFrame* frame = it.frame()->is_javascript()
                                 ? JavaScriptFrame::cast(it.frame())
                                 : nullptr;
    if (frame && IsJSFunction(frame->function())) {
      DirectHandle<JSFunction> function(frame->function(), isolate_);
      DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate_);

      // kScheduled breaks are triggered by the stack check. While we could
      // pause here, the JSFunction didn't have time yet to create and push
      // it's context. Instead, we step into the function and pause at the
      // first official breakable position.
      // This behavior mirrors "BreakOnNextFunctionCall".
      if (break_reasons.contains(v8::debug::BreakReason::kScheduled) &&
          BreakLocation::IsPausedInJsFunctionEntry(frame)) {
        thread_local_.scheduled_break_on_next_function_call_ = true;
        PrepareStepIn(function);
        return;
      }

      // Don't stop in builtin and blackboxed functions.
      bool ignore_break = ignore_break_mode == kIgnoreIfTopFrameBlackboxed
                              ? IsBlackboxed(shared)
                              : AllFramesOnStackAreBlackboxed();
      if (ignore_break) return;
      Handle<DebugInfo> debug_info;
      if (ToHandle(isolate_, TryGetDebugInfo(*shared), &debug_info) &&
          debug_info->HasBreakInfo()) {
        // Enter the debugger.
        DebugScope debug_scope(this);

        std::vector<BreakLocation> break_locations;
        BreakLocation::AllAtCurrentStatement(debug_info, frame,
                                             &break_locations);

        if (IsMutedAtAnyBreakLocation(shared, break_locations)) {
          // If we get to this point, a break was triggered because e.g. of
          // a debugger statement, an assert, .. . However, we do not stop
          // if this position "is muted", which happens if a conditional
          // breakpoint at this point evaluated to false.
          return;
        }
      }
    }
  }

  StepAction lastStepAction = last_step_action();

  // Clear stepping to avoid duplicate breaks.
  ClearStepping();

  DebugScope debug_scope(this);
  OnDebugBreak(break_points.is_null() ? isolate_->factory()->empty_fixed_array()
                                      : break_points.ToHandleChecked(),
               lastStepAction, break_reasons);
}

#ifdef DEBUG
void Debug::PrintBreakLocation() {
  if (!v8_flags.print_break_location) return;
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  HandleScope scope(isolate_);
  DebuggableStackFrameIterator iterator(isolate_);
  if (iterator.done()) return;
  CommonFrame* frame = iterator.frame();
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  int inlined_frame_index = static_cast<int>(frames.size() - 1);
  FrameInspector inspector(frame, inlined_frame_index, isolate_);
  int source_position = inspector.GetSourcePosition();
  Handle<Object> script_obj = inspector.GetScript();
  PrintF("[debug] break in function '");
  inspector.GetFunctionName()->PrintOn(stdout);
  PrintF("'.\n");
  if (IsScript(*script_obj)) {
    DirectHandle<Script> script = Cast<Script>(script_obj);
    DirectHandle<String> source(Cast<String>(script->source()), isolate_);
    Script::InitLineEnds(isolate_, script);
    Script::PositionInfo info;
    Script::GetPositionInfo(script, source_position, &info,
                            Script::OffsetFlag::kNoOffset);
    int line = info.line;
    int column = info.column;
    DirectHandle<FixedArray> line_ends(Cast<FixedArray>(script->line_ends()),
                                       isolate_);
    int line_start = line == 0 ? 0 : Smi::ToInt(line_ends->get(line - 1)) + 1;
    int line_end = Smi::ToInt(line_ends->get(line));
    DisallowGarbageCollection no_gc;
    String::FlatContent content = source->GetFlatContent(no_gc);
    if (content.IsOneByte()) {
      PrintF("[debug] %.*s\n", line_end - line_start,
             content.ToOneByteVector().begin() + line_start);
      PrintF("[debug] ");
      for (int i = 0; i < column; i++) PrintF(" ");
      PrintF("^\n");
    } else {
      PrintF("[debug] at line %d column %d\n", line, column);
    }
  }
}
#endif  // DEBUG

DebugScope::DebugScope(Debug* debug)
    : debug_(debug),
      prev_(reinterpret_cast<DebugScope*>(
          base::Relaxed_Load(&debug->thread_local_.current_debug_scope_))),
      no_interrupts_(debug_->isolate_) {
  timer_.Start();
  // Link recursive debugger entry.
  base::Relaxed_Store(&debug_->thread_local_.current_debug_scope_,
                      reinterpret_cast<base::AtomicWord>(this));
  // Store the previous frame id and return value.
  break_frame_id_ = debug_->break_frame_id();

  // Create the new break info. If there is no proper frames there is no break
  // frame id.
  DebuggableStackFrameIterator it(isolate());
  bool has_frames = !it.done();
  debug_->thread_local_.break_frame_id_ =
      has_frames ? it.frame()->id() : StackFrameId::NO_ID;

  debug_->UpdateState();
}

void DebugScope::set_terminate_on_resume() { terminate_on_resume_ = true; }

base::TimeDelta DebugScope::ElapsedTimeSinceCreation() {
  return timer_.Elapsed();
}

DebugScope::~DebugScope() {
  // Terminate on resume must have been handled by retrieving it, if this is
  // the outer scope.
  if (terminate_on_resume_) {
    if (!prev_) {
      debug_->isolate_->stack_guard()->RequestTerminateExecution();
    } else {
      prev_->set_terminate_on_resume();
    }
  }
  // Leaving this debugger entry.
  base::Relaxed_Store(&debug_->thread_local_.current_debug_scope_,
                      reinterpret_cast<base::AtomicWord>(prev_));

  // Restore to the previous break state.
  debug_->thread_local_.break_frame_id_ = break_frame_id_;

  debug_->UpdateState();
}

ReturnValueScope::ReturnValueScope(Debug* debug) : debug_(debug) {
  return_value_ = debug_->return_value_handle();
}

ReturnValueScope::~ReturnValueScope() {
  debug_->set_return_value(*return_value_);
}

void Debug::UpdateDebugInfosForExecutionMode() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  // Walk all debug infos and update their execution mode if it is different
  // from the isolate execution mode.
  const DebugInfo::ExecutionMode current_debug_execution_mode =
      isolate_->debug_execution_mode();

  HandleScope scope(isolate_);
  DebugInfoCollection::Iterator it(&debug_infos_);
  for (; it.HasNext(); it.Advance()) {
    Handle<DebugInfo> debug_info(it.Next(), isolate_);
    if (debug_info->HasInstrumentedBytecodeArray() &&
        debug_info->DebugExecutionMode() != current_debug_execution_mode) {
      DCHECK(debug_info->shared()->HasBytecodeArray());
      if (current_debug_execution_mode == DebugInfo::kBreakpoints) {
        ClearSideEffectChecks(debug_info);
        ApplyBreakPoints(debug_info);
      } else {
        ClearBreakPoints(debug_info);
        ApplySideEffectChecks(debug_info);
      }
    }
  }
}

void Debug::SetTerminateOnResume() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DebugScope* scope = reinterpret_cast<DebugScope*>(
      base::Acquire_Load(&thread_local_.current_debug_scope_));
  CHECK_NOT_NULL(scope);
  scope->set_terminate_on_resume();
}

void Debug::StartSideEffectCheckMode() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kBreakpoints);
  isolate_->set_debug_execution_mode(DebugInfo::kSideEffects);
  UpdateHookOnFunctionCall();
  side_effect_check_failed_ = false;

  DCHECK(!temporary_objects_);
  temporary_objects_.reset(new TemporaryObjectsTracker());
  isolate_->heap()->AddHeapObjectAllocationTracker(temporary_objects_.get());

  DirectHandle<RegExpMatchInfo> current_match_info(
      isolate_->native_context()->regexp_last_match_info(), isolate_);
  int register_count = current_match_info->number_of_capture_registers();
  regexp_match_info_ = RegExpMatchInfo::New(
      isolate_, JSRegExp::CaptureCountForRegisters(register_count));
  DCHECK_EQ(regexp_match_info_->number_of_capture_registers(),
            current_match_info->number_of_capture_registers());
  regexp_match_info_->set_last_subject(current_match_info->last_subject());
  regexp_match_info_->set_last_input(current_match_info->last_input());
  RegExpMatchInfo::CopyElements(isolate_, *regexp_match_info_, 0,
                                *current_match_info, 0, register_count,
                                SKIP_WRITE_BARRIER);

  // Update debug infos to have correct execution mode.
  UpdateDebugInfosForExecutionMode();
}

void Debug::StopSideEffectCheckMode() {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);
  if (side_effect_check_failed_) {
    DCHECK(isolate_->has_exception());
    DCHECK_IMPLIES(v8_flags.strict_termination_checks,
                   isolate_->is_execution_terminating());
    // Convert the termination exception into a regular exception.
    isolate_->CancelTerminateExecution();
    isolate_->Throw(*isolate_->factory()->NewEvalError(
        MessageTemplate::kNoSideEffectDebugEvaluate));
  }
  isolate_->set_debug_execution_mode(DebugInfo::kBreakpoints);
  UpdateHookOnFunctionCall();
  side_effect_check_failed_ = false;

  DCHECK(temporary_objects_);
  isolate_->heap()->RemoveHeapObjectAllocationTracker(temporary_objects_.get());
  temporary_objects_.reset();
  isolate_->native_context()->set_regexp_last_match_info(*regexp_match_info_);
  regexp_match_info_ = Handle<RegExpMatchInfo>::null();

  // Update debug infos to have correct execution mode.
  UpdateDebugInfosForExecutionMode();
}

void Debug::ApplySideEffectChecks(DirectHandle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK(debug_info->HasInstrumentedBytecodeArray());
  Handle<BytecodeArray> debug_bytecode(debug_info->DebugBytecodeArray(isolate_),
                                       isolate_);
  DebugEvaluate::ApplySideEffectChecks(debug_bytecode);
  debug_info->SetDebugExecutionMode(DebugInfo::kSideEffects);
}

void Debug::ClearSideEffectChecks(DirectHandle<DebugInfo> debug_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK(debug_info->HasInstrumentedBytecodeArray());
  Handle<BytecodeArray> debug_bytecode(debug_info->DebugBytecodeArray(isolate_),
                                       isolate_);
  DirectHandle<BytecodeArray> original(
      debug_info->OriginalBytecodeArray(isolate_), isolate_);
  for (interpreter::BytecodeArrayIterator it(debug_bytecode); !it.done();
       it.Advance()) {
    // Restore from original. This may copy only the scaling prefix, which is
    // correct, since we patch scaling prefixes to debug breaks if exists.
    debug_bytecode->set(it.current_offset(),
                        original->get(it.current_offset()));
  }
}

bool Debug::PerformSideEffectCheck(Handle<JSFunction> function,
                                   Handle<Object> receiver) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);
  DisallowJavascriptExecution no_js(isolate_);
  IsCompiledScope is_compiled_scope(
      function->shared()->is_compiled_scope(isolate_));
  if (!function->is_compiled(isolate_) &&
      !Compiler::Compile(isolate_, function, Compiler::KEEP_EXCEPTION,
                         &is_compiled_scope)) {
    return false;
  }
  DCHECK(is_compiled_scope.is_compiled());
  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate_);
  DirectHandle<DebugInfo> debug_info = GetOrCreateDebugInfo(shared);
  DebugInfo::SideEffectState side_effect_state =
      debug_info->GetSideEffectState(isolate_);
  if (shared->HasBuiltinId()) {
    PrepareBuiltinForSideEffectCheck(isolate_, shared->builtin_id());
  }
  switch (side_effect_state) {
    case DebugInfo::kHasSideEffects:
      if (v8_flags.trace_side_effect_free_debug_evaluate) {
        PrintF("[debug-evaluate] Function %s failed side effect check.\n",
               function->shared()->DebugNameCStr().get());
      }
      side_effect_check_failed_ = true;
      // Throw an uncatchable termination exception.
      isolate_->TerminateExecution();
      return false;
    case DebugInfo::kRequiresRuntimeChecks: {
      if (!shared->HasBytecodeArray()) {
        return PerformSideEffectCheckForObject(receiver);
      }
      // If function has bytecode array then prepare function for debug
      // execution to perform runtime side effect checks.
      DCHECK(shared->is_compiled());
      PrepareFunctionForDebugExecution(shared);
      ApplySideEffectChecks(debug_info);
      return true;
    }
    case DebugInfo::kHasNoSideEffect:
      return true;
    case DebugInfo::kNotComputed:
    default:
      UNREACHABLE();
  }
}

Handle<Object> Debug::return_value_handle() {
  return handle(thread_local_.return_value_, isolate_);
}

void Debug::PrepareBuiltinForSideEffectCheck(Isolate* isolate, Builtin id) {
  switch (id) {
    case Builtin::kStringPrototypeMatch:
    case Builtin::kStringPrototypeSearch:
    case Builtin::kStringPrototypeSplit:
    case Builtin::kStringPrototypeMatchAll:
    case Builtin::kStringPrototypeReplace:
    case Builtin::kStringPrototypeReplaceAll:
      if (Protectors::IsRegExpSpeciesLookupChainIntact(isolate_)) {
        // Force RegExps to go slow path so that we have a chance to perform
        // side-effect checks for the functions for Symbol.match,
        // Symbol.matchAll, Symbol.search, Symbol.split and Symbol.replace.
        if (v8_flags.trace_side_effect_free_debug_evaluate) {
          PrintF("[debug-evaluate] invalidating protector cell for RegExps\n");
        }
        Protectors::InvalidateRegExpSpeciesLookupChain(isolate_);
      }
      return;
    default:
      return;
  }
}

bool Debug::PerformSideEffectCheckForAccessor(
    DirectHandle<AccessorInfo> accessor_info, Handle<Object> receiver,
    AccessorComponent component) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);

  // List of allowlisted internal accessors can be found in accessors.h.
  SideEffectType side_effect_type =
      component == AccessorComponent::ACCESSOR_SETTER
          ? accessor_info->setter_side_effect_type()
          : accessor_info->getter_side_effect_type();

  switch (side_effect_type) {
    case SideEffectType::kHasNoSideEffect:
      // We do not support setter accessors with no side effects, since
      // calling set accessors go through a store bytecode. Store bytecodes
      // are considered to cause side effects (to non-temporary objects).
      DCHECK_NE(AccessorComponent::ACCESSOR_SETTER, component);
      return true;

    case SideEffectType::kHasSideEffectToReceiver:
      DCHECK(!receiver.is_null());
      if (PerformSideEffectCheckForObject(receiver)) return true;
      return false;

    case SideEffectType::kHasSideEffect:
      break;
  }
  if (v8_flags.trace_side_effect_free_debug_evaluate) {
    PrintF("[debug-evaluate] API Callback '");
    ShortPrint(accessor_info->name());
    PrintF("' may cause side effect.\n");
  }

  side_effect_check_failed_ = true;
  // Throw an uncatchable termination exception.
  isolate_->TerminateExecution();
  return false;
}

void Debug::IgnoreSideEffectsOnNextCallTo(
    Handle<FunctionTemplateInfo> function) {
  DCHECK(function->has_side_effects());
  // There must be only one such call handler info.
  CHECK(ignore_side_effects_for_function_template_info_.is_null());
  ignore_side_effects_for_function_template_info_ = function;
}

bool Debug::PerformSideEffectCheckForCallback(
    Handle<FunctionTemplateInfo> function) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);

  // If an empty |function| handle is passed here then it means that
  // the callback IS side-effectful (see CallApiCallbackWithSideEffects
  // builtin).
  if (!function.is_null() && !function->has_side_effects()) {
    return true;
  }
  if (!ignore_side_effects_for_function_template_info_.is_null()) {
    // If the |ignore_side_effects_for_function_template_info_| is set then
    // the next API callback call must be made to this function.
    CHECK(ignore_side_effects_for_function_template_info_.is_identical_to(
        function));
    ignore_side_effects_for_function_template_info_ = {};
    return true;
  }

  if (v8_flags.trace_side_effect_free_debug_evaluate) {
    PrintF("[debug-evaluate] FunctionTemplateInfo may cause side effect.\n");
  }

  side_effect_check_failed_ = true;
  // Throw an uncatchable termination exception.
  isolate_->TerminateExecution();
  return false;
}

bool Debug::PerformSideEffectCheckForInterceptor(
    Handle<InterceptorInfo> interceptor_info) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);

  // Empty InterceptorInfo represents operations that do produce side effects.
  if (!interceptor_info.is_null()) {
    if (interceptor_info->has_no_side_effect()) return true;
  }
  if (v8_flags.trace_side_effect_free_debug_evaluate) {
    PrintF("[debug-evaluate] API Interceptor may cause side effect.\n");
  }

  side_effect_check_failed_ = true;
  // Throw an uncatchable termination exception.
  isolate_->TerminateExecution();
  return false;
}

bool Debug::PerformSideEffectCheckAtBytecode(InterpretedFrame* frame) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  using interpreter::Bytecode;

  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);
  Tagged<SharedFunctionInfo> shared = frame->function()->shared();
  Tagged<BytecodeArray> bytecode_array = shared->GetBytecodeArray(isolate_);
  int offset = frame->GetBytecodeOffset();
  interpreter::BytecodeArrayIterator bytecode_iterator(
      handle(bytecode_array, isolate_), offset);

  Bytecode bytecode = bytecode_iterator.current_bytecode();
  if (interpreter::Bytecodes::IsCallRuntime(bytecode)) {
    auto id = (bytecode == Bytecode::kInvokeIntrinsic)
                  ? bytecode_iterator.GetIntrinsicIdOperand(0)
                  : bytecode_iterator.GetRuntimeIdOperand(0);
    if (DebugEvaluate::IsSideEffectFreeIntrinsic(id)) {
      return true;
    }
    side_effect_check_failed_ = true;
    // Throw an uncatchable termination exception.
    isolate_->TerminateExecution();
    return false;
  }
  interpreter::Register reg;
  switch (bytecode) {
    case Bytecode::kStaCurrentContextSlot:
      reg = interpreter::Register::current_context();
      break;
    default:
      reg = bytecode_iterator.GetRegisterOperand(0);
      break;
  }
  Handle<Object> object =
      handle(frame->ReadInterpreterRegister(reg.index()), isolate_);
  return PerformSideEffectCheckForObject(object);
}

bool Debug::PerformSideEffectCheckForObject(Handle<Object> object) {
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kDebugger);
  DCHECK_EQ(isolate_->debug_execution_mode(), DebugInfo::kSideEffects);

  // We expect no side-effects for primitives.
  if (IsNumber(*object)) return true;
  if (IsName(*object)) return true;

  if (temporary_objects_->HasObject(Cast<HeapObject>(object))) {
    return true;
  }

  if (v8_flags.trace_side_effect_free_debug_evaluate) {
    PrintF("[debug-evaluate] failed runtime side effect check.\n");
  }
  side_effect_check_failed_ = true;
  // Throw an uncatchable termination exception.
  isolate_->TerminateExecution();
  return false;
}

void Debug::SetTemporaryObjectTrackingDisabled(bool disabled) {
  if (temporary_objects_) {
    temporary_objects_->disabled = disabled;
  }
}

bool Debug::GetTemporaryObjectTrackingDisabled() const {
  if (temporary_objects_) {
    return temporary_objects_->disabled;
  }
  return false;
}

void Debug::PrepareRestartFrame(JavaScriptFrame* frame,
                                int inlined_frame_index) {
  if (frame->is_optimized()) Deoptimizer::DeoptimizeFunction(frame->function());

  thread_local_.restart_frame_id_ = frame->id();
  thread_local_.restart_inline_frame_index_ = inlined_frame_index;

  // TODO(crbug.com/1303521): A full "StepInto" is probably not needed. Get the
  // necessary bits out of PrepareSTep into a separate method or fold them
  // into Debug::PrepareRestartFrame.
  PrepareStep(StepInto);
}

void Debug::NotifyDebuggerPausedEventSent() {
  DebugScope* scope = reinterpret_cast<DebugScope*>(
      base::Relaxed_Load(&thread_local_.current_debug_scope_));
  CHECK(scope);
  isolate_->counters()->debug_pause_to_paused_event()->AddTimedSample(
      scope->ElapsedTimeSinceCreation());
}

}  // namespace internal
}  // namespace v8

"""


```