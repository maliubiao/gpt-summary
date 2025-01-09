Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of V8's debugger implementation.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The code deals with debugging functionalities, specifically related to managing and manipulating baseline code, deoptimization, and breakpoints.

2. **Analyze the main functions:** Look for the `void Debug::...` functions. These are the primary entry points for the debugging features described in the snippet. The key functions are:
    * `DiscardBaselineCode`: Removes baseline code for a specific function.
    * `DiscardAllBaselineCode`: Removes baseline code for all functions.
    * `DeoptimizeFunction`: Deoptimizes a function, discarding baseline and optimized code.
    * `PrepareFunctionForDebugExecution`: Prepares a function for debugging, installing debug bytecode and potentially deoptimizing.
    * `InstallDebugBreakTrampoline`: Installs a special trampoline to handle breakpoints at function entry.
    * `GetPossibleBreakpoints`:  Determines valid locations for breakpoints.
    * `FindInnermostContainingFunctionInfo`: Locates the function containing a given position.
    * `FindClosestSharedFunctionInfoFromPosition`: Finds the closest function to a given position within another function.
    * `FindSharedFunctionInfosIntersectingRange`: Finds functions intersecting a given range in the source.
    * `GetTopLevelWithRecompile`: Retrieves the top-level function information, potentially recompiling it.
    * `EnsureBreakInfo`: Makes sure debug information exists for a function.
    * `CreateBreakInfo`: Creates the debug information for a function.
    * `GetOrCreateDebugInfo`: Retrieves or creates debug information.
    * `InstallCoverageInfo`:  Installs coverage information (mentioned but not extensively detailed in this snippet).
    * `RemoveAllCoverageInfos`, `ClearAllDebuggerHints`, `ClearAllDebugInfos`: Clean up debugging-related data.
    * `RemoveBreakInfoAndMaybeFree`: Removes break information.
    * `IsBreakAtReturn`: Checks if a breakpoint is at a return statement.
    * `GetLoadedScripts`: Retrieves the loaded scripts.
    * `TryGetDebugInfo`, `HasDebugInfo`, `HasCoverageInfo`, `HasBreakInfo`, `BreakAtEntry`:  Accessors for debug-related information.
    * `OnThrow`, `OnPromiseReject`: Handlers for exceptions and promise rejections during debugging.
    * `IsFrameBlackboxed`: Checks if a frame should be skipped during debugging.
    * `OnException`:  Handles exceptions during debugging.

3. **Identify key concepts and data structures:** Look for important classes and concepts being used:
    * `SharedFunctionInfo`: Represents a function's metadata.
    * `BaselineCode`:  A less optimized version of the function's code.
    * `DebugInfo`: Contains debugging-related information for a function.
    * `BytecodeArray`: The bytecode of a function.
    * `JSFunction`: Represents a JavaScript function object.
    * `Deoptimizer`:  The component responsible for deoptimizing code.
    * `DebugBreakTrampoline`:  A special code stub used for breakpoints.
    * `BreakLocation`: Represents a possible breakpoint location.
    * `Script`: Represents a JavaScript source code file.
    * `CoverageInfo`: Information about code coverage (briefly mentioned).

4. **Infer the relationships between functions:** Notice how some functions call others (e.g., `DeoptimizeFunction` calls `DiscardBaselineCode`). This highlights the workflow of certain debugging actions.

5. **Address the specific instructions in the prompt:**
    * **Functionality Listing:**  Create a bulleted list summarizing the purpose of the key functions.
    * **Torque Source:** The prompt explicitly asks if the file would be a Torque source if it ended in `.tq`. The provided snippet is C++, so the answer is no.
    * **JavaScript Relationship:**  Think about how these debugging features relate to JavaScript. Breakpoints, stepping through code, inspecting variables during exceptions – these are all actions a JavaScript developer uses. Provide a simple JavaScript example demonstrating breakpoints.
    * **Code Logic Reasoning:** Look for conditional logic and data manipulation. `DiscardBaselineCode` iterates through threads and the heap to update function code. Provide a scenario with input (a `SharedFunctionInfo`) and the expected output (baseline code is removed, related functions point to the interpreter).
    * **Common Programming Errors:** Consider how these debugging features help developers. A common error is unexpected exceptions. Explain how setting a breakpoint on exceptions can help.
    * **Overall Functionality (Part 3 Summary):** Combine the insights into a concise summary of the code's purpose within the larger debugging system.

6. **Structure the response:** Organize the information clearly using headings and bullet points for readability.

7. **Refine and review:** Read through the generated summary to ensure accuracy, clarity, and completeness, addressing all aspects of the prompt. For instance, initially, I might forget to explicitly mention the `.tq` check, so a review would catch that. Similarly, ensuring the JavaScript example is simple and relevant is important.
这是v8源代码文件 `v8/src/debug/debug.cc` 的一部分，它主要关注 **代码的去优化 (Deoptimization) 和为调试执行做准备**。

**功能归纳:**

这部分代码的核心功能是管理和操作已编译的 JavaScript 代码，以便在调试过程中能够正确地执行和检查。它主要负责以下几个方面：

* **清除 Baseline 代码:**  Baseline 代码是 V8 中一种轻量级的优化代码。为了进行精确的调试，需要将其清除，强制代码回到解释执行或更优化的版本（如果适用）。
* **去优化函数:** 将函数从优化的状态恢复到未优化状态，这通常是为了确保调试器能够单步执行所有代码，包括内联的代码。
* **准备函数以进行调试执行:**  这包括安装调试字节码，以便在断点处暂停执行。如果函数入口处设置了断点，可能需要安装一个特殊的 trampoline 代码。
* **管理调试断点 trampoline:**  当需要在函数入口处设置断点时，V8 会安装一个特殊的 trampoline 代码。这部分代码负责安装和管理这个 trampoline。
* **查找可能的断点位置:**  根据脚本和位置信息，查找可以设置断点的有效位置。
* **查找包含特定位置的函数信息:**  确定给定代码位置属于哪个函数。
* **查找与给定范围相交的函数信息:**  查找在给定代码范围内的所有函数。
* **管理和操作 `DebugInfo` 对象:** `DebugInfo` 存储了函数的调试相关信息，例如断点信息。这部分代码负责创建、查找和修改 `DebugInfo` 对象。
* **处理异常和 Promise 拒绝:**  在调试模式下，捕获和处理 JavaScript 异常和 Promise 拒绝事件。
* **处理代码覆盖率信息:** （虽然在这部分代码中不明显，但 `InstallCoverageInfo` 函数暗示了对代码覆盖率的支持）。

**关于源代码类型：**

如果 `v8/src/debug/debug.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。然而，根据你提供的文件名，它以 `.cc` 结尾，因此是 **C++ 源代码**。

**与 JavaScript 功能的关系及示例：**

这部分 C++ 代码直接影响着 JavaScript 代码的调试体验。以下是一些关联的 JavaScript 功能和示例：

* **设置断点：**  `GetPossibleBreakpoints` 和相关函数使得开发者能够在特定的代码行设置断点。当 JavaScript 执行到这些断点时，执行会暂停，允许开发者检查程序状态。

   ```javascript
   function myFunction(x) {
     debugger; // 在这里设置一个断点
     console.log("Value of x:", x);
     return x * 2;
   }

   myFunction(5);
   ```

* **单步执行：** 清除 baseline 代码和去优化函数确保调试器可以精确地单步执行 JavaScript 代码，即使是经过优化的代码。

   ```javascript
   function add(a, b) {
     let sum = a + b;
     return sum; // 可以单步执行到这里
   }

   add(2, 3);
   ```

* **在异常处中断：** `OnThrow` 函数允许调试器在抛出异常时暂停执行。

   ```javascript
   function divide(a, b) {
     if (b === 0) {
       throw new Error("Cannot divide by zero"); // 调试器可以在这里暂停
     }
     return a / b;
   }

   divide(10, 0);
   ```

* **在 Promise 拒绝时中断：** `OnPromiseReject` 函数允许调试器在 Promise 被拒绝时暂停执行。

   ```javascript
   function asyncOperation() {
     return new Promise((resolve, reject) => {
       setTimeout(() => {
         reject("Operation failed"); // 调试器可以在这里暂停
       }, 1000);
     });
   }

   asyncOperation().catch(error => {
     console.error(error);
   });
   ```

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `SharedFunctionInfo` 对象 `shared_info` 代表一个已经经过 Baseline 优化的 JavaScript 函数。

**假设输入：**

* `shared_info`: 指向已进行 Baseline 优化的 JavaScript 函数的 `SharedFunctionInfo` 对象。

**执行 `Debug::DiscardBaselineCode(shared_info)`：**

1. **遍历线程栈:**  `DiscardBaselineCodeVisitor` 会遍历当前线程和存档线程的栈帧。
2. **查找包含目标函数的栈帧:** 如果在栈帧中找到了正在执行 `shared_info` 代表的函数的代码，它会尝试修改程序计数器 (PC)。
3. **修改 PC (如果适用):** 如果 PC 指向 Baseline 代码入口，并且内置函数是 `kBaselineOrInterpreterEnterAtBytecode` 或 `kBaselineOrInterpreterEnterAtNextBytecode`，则会将其修改为指向解释器入口点 (`kInterpreterEnterAtBytecode` 或 `kInterpreterEnterAtNextBytecode`)。
4. **遍历堆:** 遍历堆中的所有对象。
5. **查找 `JSFunction` 对象:** 查找所有 `JSFunction` 对象。
6. **更新代码对象:** 对于 `shared` 属性与 `shared_info` 相同，且当前激活层为 Baseline 的 `JSFunction` 对象，将其代码对象更新为解释器入口 trampoline (`InterpreterEntryTrampoline`)。
7. **清除 `SharedFunctionInfo` 的 Baseline 代码标志:** 最后，清除 `shared_info` 上的 Baseline 代码标志。

**预期输出：**

* `shared_info` 对象不再具有 Baseline 代码。
* 所有正在执行 `shared_info` 代表的函数的栈帧（如果存在）的 PC 可能已被修改为指向解释器入口点。
* 所有引用 `shared_info` 且当前激活层为 Baseline 的 `JSFunction` 对象的代码已更新为解释器入口 trampoline。

**涉及用户常见的编程错误：**

这部分代码的功能主要用于支持调试，可以帮助开发者诊断各种编程错误，例如：

* **意外的优化行为：**  有时，V8 的优化可能会使调试变得困难，因为代码执行路径与源代码的直观理解不同。清除 Baseline 代码和去优化可以强制代码以更可预测的方式执行，更容易追踪问题。
* **断点未命中：** 如果代码被内联或优化，设置的断点可能不会被触发。`PrepareFunctionForDebugExecution` 可以确保在调试时断点能够被正确命中。
* **异常处理错误：**  在异常抛出时中断的功能可以帮助开发者理解未捕获的异常是如何产生的，以及捕获到的异常是否被正确处理。
* **异步操作错误：**  在 Promise 拒绝时中断的功能可以帮助开发者调试异步操作中的错误。

**示例：断点未命中的情况**

假设有以下 JavaScript 代码：

```javascript
function square(x) {
  return x * x;
}

function calculate(y) {
  let result = square(y + 1); // 假设这里被内联了
  console.log("Result:", result);
  return result;
}

calculate(2);
```

如果没有进行调试准备，`square` 函数可能被内联到 `calculate` 函数中。如果在 `square` 函数内部设置了断点，由于内联，该断点可能不会被触发。  `PrepareFunctionForDebugExecution` 可以强制不进行内联，确保断点能够被命中。

**总结 (第 3 部分的功能):**

这部分 `v8/src/debug/debug.cc` 的代码专注于 **为 JavaScript 代码的精确调试做准备**。它通过清除 Baseline 代码、去优化函数、安装调试字节码和管理断点 trampoline 等机制，确保开发者能够在调试过程中准确地单步执行代码、设置断点并检查程序状态，从而有效地诊断和修复各种编程错误。它还涉及处理异常和 Promise 拒绝等事件，以提供更全面的调试体验。

Prompt: 
```
这是目录为v8/src/debug/debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

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
        // Wasm is always
"""


```