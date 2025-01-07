Response:
The user wants a summary of the provided C++ code snippet from `v8/src/execution/isolate.cc`.

Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Function:** The central function in this snippet appears to be `CallsCatchMethod`. This function analyzes the bytecode of a JavaScript function to determine if it contains a `.catch()` call on a promise.

2. **Understand the Context:** The larger context is related to promise rejection handling in V8. The `WalkCallStackAndPromiseTree` function (partially visible) suggests this code is used to trace the execution flow when a promise is rejected to find appropriate handlers.

3. **Analyze `CallsCatchMethod`:**
    * It checks if the given `StackFrameSummaryIterator` points to a JavaScript frame.
    * If it's a bytecode array, it calls the inner `CallsCatchMethod` function.
    * The inner function iterates through the bytecode instructions.
    * It looks for a pattern:
        * Accessing a property of a value (assumed to be a promise).
        * The property being "catch" or "then" in a specific call context.
        * A subsequent `CallProperty` instruction invoking this method on the promise.

4. **Identify Supporting Functions:** The `GetPromiseMethod` function is used to identify if the accessed property is "then" or "catch". The `TouchesRegister` function is used to prevent scanning too far if other operations touch the relevant registers.

5. **Infer the Purpose:** The overall goal seems to be to statically analyze the bytecode to predict if a promise rejection will be handled within the current stack frame. This is likely an optimization or part of V8's error reporting/debugging mechanisms.

6. **Connect to JavaScript:**  The functionality directly relates to JavaScript promises and their `.catch()` and `.then()` methods.

7. **Construct a JavaScript Example:** Create a simple JavaScript example that demonstrates the scenario the code is trying to detect (a promise followed by a `.catch()` call).

8. **Consider Edge Cases/Limitations:** The code has comments indicating limitations, such as not handling arbitrary code between the promise creation and the `.catch()` call. This should be mentioned as a potential area for improvement or a simplification in the current implementation.

9. **Identify Potential Programming Errors:** A common mistake is forgetting to handle promise rejections. This code snippet helps V8 detect such situations.

10. **Address the ".tq" Question:** The prompt explicitly asks about the `.tq` extension. Since the code is `.cc`, it's standard C++, not Torque.

11. **Summarize:** Combine all the findings into a concise summary of the code's functionality.

12. **Structure the Answer:** Organize the information into logical sections as requested by the prompt (functionality, `.tq` check, JavaScript example, logic reasoning, common errors, and overall summary).

**Self-Correction/Refinement during the process:**

* Initially, one might focus solely on `CallsCatchMethod`. However, realizing its connection to `WalkCallStackAndPromiseTree` provides a broader understanding of its purpose in promise rejection handling.
* The comments in the code are crucial. The "TODO" comment about looping over non-matching instructions highlights a current limitation of the analysis.
* The logic for detecting `.then()` calls (checking `Bytecode::kCallProperty2`) needs to be explained clearly.
* Ensuring the JavaScript example accurately reflects the C++ code's focus on immediate `.catch()` calls is important.

By following these steps, a comprehensive and accurate answer can be generated, addressing all aspects of the user's request.
Based on the provided C++ code snippet from `v8/src/execution/isolate.cc`, here's a breakdown of its functionality:

**Functionality:**

The primary function of this code snippet is to determine if a specific stack frame in a JavaScript execution context contains a call to the `.catch()` method of a promise. It does this by analyzing the bytecode instructions within that stack frame.

Here's a breakdown of the logic within the `CallsCatchMethod` functions:

1. **`CallsCatchMethod(const StackFrameSummaryIterator& iterator)` (Outer Function):**
   - Checks if the current stack frame is a JavaScript frame.
   - If it is, and if it has a bytecode array associated with it, it calls the inner `CallsCatchMethod` function to perform the bytecode analysis.

2. **`CallsCatchMethod(Isolate* isolate, const BytecodeArray& bytecode_array, int bytecode_offset)` (Inner Function):**
   - This is the core logic for bytecode analysis.
   - It takes the `Isolate`, the `BytecodeArray` of the JavaScript function, and the starting `bytecode_offset` as input.
   - It iterates through the bytecode instructions starting from the given offset.
   - **Looking for a Promise and a `.catch()` or `.then()` call:**
     - It expects to find a sequence of bytecode instructions that indicate accessing a property (likely "catch" or "then") of a value that is assumed to be a promise.
     - It specifically looks for:
       - Instructions that get a named property (`Bytecode::kGetNamedProperty`).
       - The property name being "catch" or "then" (determined by `GetPromiseMethod`).
       - The result of getting the property being saved to a register (`Bytecodes::IsAnyStar`).
       - A subsequent call to this method using `Bytecode::kCallProperty1` or `Bytecode::kCallProperty2`.
   - **Handling Arguments:** It steps over the instructions that create arguments for the `.catch()` or `.then()` call.
   - **Checking for Control Flow and Register Touches:**
     - It stops scanning if it encounters control flow instructions like jumps or returns (`Bytecodes::IsJump`, `Bytecodes::IsSwitch`, `Bytecodes::Returns`, `Bytecodes::UnconditionallyThrows`).
     - It also stops scanning if an instruction unexpectedly modifies the registers holding the promise or the method being called (`TouchesRegister`).
   - **Identifying `.catch()` specifically:**
     - If it finds a call to a promise method, it checks if the method is indeed `kCatch` or if it's `kThen` with a `Bytecode::kCallProperty2` instruction (which might indicate a `.then(undefined, onRejected)` pattern effectively acting as a catch).

**If `v8/src/execution/isolate.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **Torque** source file. Torque is V8's domain-specific language for writing compiler intrinsics and runtime functions. Torque code compiles to highly optimized machine code. The current file is `.cc`, indicating it's standard C++ code.

**Relationship with JavaScript and JavaScript Example:**

This code is directly related to how V8 handles promises in JavaScript. It's trying to understand the structure of the JavaScript code at the bytecode level to make decisions about promise rejection handling.

Here's a JavaScript example that the code might be trying to identify:

```javascript
async function processData(data) {
  const promise = fetchData(data); // Assume fetchData returns a Promise
  console.log("Fetching data...");
  promise.catch(error => {
    console.error("Error fetching data:", error);
  });
}

async function processDataThen(data) {
  const promise = fetchData(data);
  console.log("Fetching data...");
  promise.then(undefined, error => { // .then with only a rejection handler
    console.error("Error fetching data:", error);
  });
}
```

The `CallsCatchMethod` function would likely return `true` when analyzing the bytecode of the `processData` and `processDataThen` functions (at the point of the `.catch()` or `.then(undefined, ...)` call).

**Code Logic Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:**

Imagine the bytecode for the `processData` function snippet above, specifically at the line `promise.catch(...)`. The `StackFrameSummaryIterator` would be positioned at or near the instructions corresponding to this line.

**Hypothetical Bytecode Sequence (Simplified):**

```
LdaGlobal               [Promise]
CallRuntime             [fetchData]  // Creates the promise
Star                    r0           // Save the promise in register r0
LdaSmi                  #0
Star                    r1
LdaContextSlot          [context]
PushContext             r1
Call                    r2, #0      // console.log
PopContext              r1
Ldar                    r0           // Load the promise from register r0
LdaStringImmediate      'catch'      // Load the string 'catch'
GetNamedProperty        r0           // Get the 'catch' property of the promise
Star                    r3           // Save the 'catch' method in register r3
LdaUndefined
Star                    r4
CallProperty1           r3, r0, r4  // Call the 'catch' method on the promise with one argument
```

**Hypothetical Output of `CallsCatchMethod`:**

Given this hypothetical bytecode, when the iterator is positioned around the `GetNamedProperty` or `CallProperty1` instructions related to `.catch()`, the `CallsCatchMethod` function would likely return `true`.

**User's Common Programming Errors:**

This code relates to a common programming error: **unhandled promise rejections**. If a promise is rejected and there is no `.catch()` handler (or `.then()` with a rejection handler) in the chain, the rejection can go unhandled, potentially leading to errors or unexpected behavior.

**Example of a Common Error:**

```javascript
async function fetchDataAsync() {
  // ... some code that might throw an error or return a rejected promise ...
  throw new Error("Something went wrong!");
}

async function processDataBad() {
  const dataPromise = fetchDataAsync();
  console.log("Fetching started...");
  // Oops! Forgot to add a .catch()
  // If fetchDataAsync rejects, this rejection will go unhandled.
}

processDataBad();
```

In this `processDataBad` example, if `fetchDataAsync` throws an error or returns a rejected promise, the rejection won't be caught, which is a common mistake. V8's mechanisms, potentially involving code like this snippet, help identify such situations.

**Summary of Functionality (Part 5 of 9):**

This specific part of `v8/src/execution/isolate.cc` focuses on **statically analyzing JavaScript bytecode within a stack frame to detect calls to the `.catch()` method of promises**. This analysis is likely part of V8's internal mechanisms for understanding promise handling, potentially for optimizing execution, improving error reporting for unhandled rejections, or debugging purposes. It allows V8 to introspect the code's structure and anticipate how promise rejections are being handled.

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能

"""
alse;
    }
    // The register it stores to will be assumed to be our promise
    int promise_register = iterator.GetStarTargetRegister().index();

    // TODO(crbug/40283993): Should we loop over non-matching instructions here
    // to allow code like
    // `const promise = foo(); console.log(...); promise.catch(...);`?

    iterator.Advance();
    // We should be on a GetNamedProperty instruction.
    if (iterator.done() ||
        iterator.current_bytecode() != Bytecode::kGetNamedProperty ||
        iterator.GetRegisterOperand(0).index() != promise_register) {
      return false;
    }
    PromiseMethod method = GetPromiseMethod(isolate, iterator);
    if (method == kInvalid) {
      return false;
    }

    iterator.Advance();
    // Next instruction should be a Star (save immediate to register)
    if (iterator.done() || !Bytecodes::IsAnyStar(iterator.current_bytecode())) {
      return false;
    }
    // This register contains the method we will eventually invoke
    int method_register = iterator.GetStarTargetRegister().index();
    if (method_register == promise_register) {
      return false;
    }

    // Now we step over multiple instructions creating the arguments for the
    // method.
    while (true) {
      iterator.Advance();
      if (iterator.done()) {
        return false;
      }
      Bytecode bytecode = iterator.current_bytecode();
      if (bytecode == Bytecode::kCallProperty1 ||
          bytecode == Bytecode::kCallProperty2) {
        // This is a call property call of the right size, but is it a call of
        // the method and on the promise?
        if (iterator.GetRegisterOperand(0).index() == method_register &&
            iterator.GetRegisterOperand(1).index() == promise_register) {
          // This is our method call, but does it catch?
          if (method == kCatch ||
              (method == kThen && bytecode == Bytecode::kCallProperty2)) {
            return true;
          }
          // Break out of the inner loop, continuing the outer loop. We
          // will use the same procedure to check for chained method calls.
          break;
        }
      }

      // Check for some instructions that should make us give up scanning.
      if (Bytecodes::IsJump(bytecode) || Bytecodes::IsSwitch(bytecode) ||
          Bytecodes::Returns(bytecode) ||
          Bytecodes::UnconditionallyThrows(bytecode)) {
        // Stop scanning at control flow instructions that aren't calls
        return false;
      }

      if (TouchesRegister(iterator, promise_register) ||
          TouchesRegister(iterator, method_register)) {
        // Stop scanning at instruction that unexpectedly interacts with one of
        // the registers we care about.
        return false;
      }
    }
  }
  return false;
}

bool CallsCatchMethod(const StackFrameSummaryIterator& iterator) {
  if (!iterator.frame()->is_javascript()) {
    return false;
  }
  if (iterator.frame_summary().IsJavaScript()) {
    auto& js_summary = iterator.frame_summary().AsJavaScript();
    if (IsBytecodeArray(*js_summary.abstract_code())) {
      if (CallsCatchMethod(iterator.isolate(),
                           Cast<BytecodeArray>(js_summary.abstract_code()),
                           js_summary.code_offset())) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

bool Isolate::WalkCallStackAndPromiseTree(
    MaybeHandle<JSPromise> rejected_promise,
    const std::function<void(PromiseHandler)>& callback) {
  bool is_promise_rejection = false;

  Handle<JSPromise> promise;
  if (rejected_promise.ToHandle(&promise)) {
    is_promise_rejection = true;
    // If the promise has reactions, follow them and assume we are done. If
    // it has no reactions, assume promise is returned up the call stack and
    // trace accordingly. If the promise is not pending, it has no reactions
    // and is probably the result of a call to Promise.reject().
    if (promise->status() != Promise::kPending) {
      // Ignore this promise; set to null
      rejected_promise = MaybeHandle<JSPromise>();
    } else if (IsSmi(promise->reactions())) {
      // Also check that there is no outer promise
      Handle<Symbol> key = factory()->promise_handled_by_symbol();
      if (!IsJSPromise(*JSObject::GetDataProperty(this, promise, key))) {
        // Ignore this promise; set to null
        rejected_promise = MaybeHandle<JSPromise>();
      }
    }
  }

  if (!is_promise_rejection && TopExceptionHandlerType(Tagged<Object>()) ==
                                   ExceptionHandlerType::kExternalTryCatch) {
    return true;  // caught by external
  }

  // Search for an exception handler by performing a full walk over the stack.
  for (StackFrameSummaryIterator iter(this); !iter.done(); iter.Advance()) {
    Isolate::CatchType prediction = PredictExceptionCatchAtFrame(iter);

    bool caught;
    if (rejected_promise.is_null()) {
      switch (prediction) {
        case NOT_CAUGHT:
          // Uncaught unless this is a promise rejection and the code will call
          // .catch()
          caught = is_promise_rejection && CallsCatchMethod(iter);
          break;
        case CAUGHT_BY_ASYNC_AWAIT:
          // Uncaught unless this is a promise rejection and the code will call
          // .catch()
          caught = is_promise_rejection && CallsCatchMethod(iter);
          // Exceptions turn into promise rejections here
          is_promise_rejection = true;
          break;
        case CAUGHT_BY_PROMISE:
          // Exceptions turn into promise rejections here
          // TODO(leese): Perhaps we can handle the case where the reject method
          // is called in the promise constructor and it is still on the stack
          // by ignoring all try/catches on the stack until we get to the right
          // CAUGHT_BY_PROMISE?
          is_promise_rejection = true;
          caught = false;
          break;
        case CAUGHT_BY_EXTERNAL:
          caught = !is_promise_rejection;
          break;
        case CAUGHT_BY_JAVASCRIPT:
          caught = true;
          // Unless this is a promise rejection and the function is not async...
          DCHECK(iter.has_frame_summary());
          const FrameSummary& summary = iter.frame_summary();
          if (is_promise_rejection && summary.IsJavaScript()) {
            // If the catch happens in an async function, assume it will
            // await this promise. Alternately, if the code will call .catch,
            // assume it is on this promise.
            caught = IsAsyncFunction(iter.frame_summary()
                                         .AsJavaScript()
                                         .function()
                                         ->shared()
                                         ->kind()) ||
                     CallsCatchMethod(iter);
          }
          break;
      }
    } else {
      // The frame that calls the reject handler will not catch that promise
      // regardless of what else it does. We will trace where this rejection
      // goes according to its reaction callbacks, but we first need to handle
      // the topmost debuggable frame just to ensure there is a debuggable
      // frame and to permit ignore listing there.
      caught = false;
    }

    if (iter.frame()->is_javascript()) {
      bool debuggable = false;
      DCHECK(iter.has_frame_summary());
      const FrameSummary& summary = iter.frame_summary();
      if (summary.IsJavaScript()) {
        const auto& info = summary.AsJavaScript().function()->shared();
        if (info->IsSubjectToDebugging()) {
          callback({*info, false});
          debuggable = true;
        }
      }

      // Ignore the rest of the call stack if this is a rejection and the
      // promise has handlers; we will trace where the rejection goes instead
      // of where it came from.
      if (debuggable && !rejected_promise.is_null()) {
        break;
      }
    }

    if (caught) {
      return true;
    }
  }

  if (rejected_promise.is_null()) {
    // Now follow promises if this is a promise reaction job.
    rejected_promise = TryGetCurrentTaskPromise(this);
  }

  if (rejected_promise.ToHandle(&promise)) {
    return WalkPromiseTreeInternal(this, promise, callback);
  }
  // Nothing caught.
  return false;
}

void Isolate::SetCaptureStackTraceForUncaughtExceptions(
    bool capture, int frame_limit, StackTrace::StackTraceOptions options) {
  capture_stack_trace_for_uncaught_exceptions_ = capture;
  stack_trace_for_uncaught_exceptions_frame_limit_ = frame_limit;
  stack_trace_for_uncaught_exceptions_options_ = options;
}

bool Isolate::get_capture_stack_trace_for_uncaught_exceptions() const {
  return capture_stack_trace_for_uncaught_exceptions_;
}

void Isolate::SetAbortOnUncaughtExceptionCallback(
    v8::Isolate::AbortOnUncaughtExceptionCallback callback) {
  abort_on_uncaught_exception_callback_ = callback;
}

void Isolate::InstallConditionalFeatures(Handle<NativeContext> context) {
  Handle<JSGlobalObject> global = handle(context->global_object(), this);
  // If some fuzzer decided to make the global object non-extensible, then
  // we can't install any features (and would CHECK-fail if we tried).
  if (!global->map()->is_extensible()) return;
  Handle<String> sab_name = factory()->SharedArrayBuffer_string();
  if (IsSharedArrayBufferConstructorEnabled(context)) {
    if (!JSObject::HasRealNamedProperty(this, global, sab_name)
             .FromMaybe(true)) {
      JSObject::AddProperty(this, global, factory()->SharedArrayBuffer_string(),
                            shared_array_buffer_fun(), DONT_ENUM);
    }
  }
}

bool Isolate::IsSharedArrayBufferConstructorEnabled(
    Handle<NativeContext> context) {
  if (!v8_flags.enable_sharedarraybuffer_per_context) return true;

  if (sharedarraybuffer_constructor_enabled_callback()) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    return sharedarraybuffer_constructor_enabled_callback()(api_context);
  }
  return false;
}

bool Isolate::IsWasmStringRefEnabled(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  // If Wasm imported strings are explicitly enabled via a callback, also enable
  // stringref.
  v8::WasmImportedStringsEnabledCallback callback_imported_strings =
      wasm_imported_strings_enabled_callback();
  if (callback_imported_strings) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    if (callback_imported_strings(api_context)) return true;
  }
  // Otherwise use the runtime flag.
  return v8_flags.experimental_wasm_stringref;
#else
  return false;
#endif
}

bool Isolate::IsWasmJSPIRequested(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  v8::WasmJSPIEnabledCallback jspi_callback = wasm_jspi_enabled_callback();
  if (jspi_callback) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    if (jspi_callback(api_context)) return true;
  }

  // Otherwise use the runtime flag.
  return v8_flags.experimental_wasm_jspi;
#else
  return false;
#endif
}

bool Isolate::IsWasmJSPIEnabled(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  return IsWasmJSPIRequested(context) &&
         context->is_wasm_jspi_installed() != Smi::zero();
#else
  return false;
#endif
}

bool Isolate::IsWasmImportedStringsEnabled(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  v8::WasmImportedStringsEnabledCallback callback =
      wasm_imported_strings_enabled_callback();
  if (callback) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    if (callback(api_context)) return true;
  }
  return v8_flags.experimental_wasm_imported_strings;
#else
  return false;
#endif
}

Handle<NativeContext> Isolate::GetIncumbentContextSlow() {
  JavaScriptStackFrameIterator it(this);

  // 1st candidate: most-recently-entered author function's context
  // if it's newer than the last Context::BackupIncumbentScope entry.
  //
  // NOTE: This code assumes that the stack grows downward.
  Address top_backup_incumbent =
      top_backup_incumbent_scope()
          ? top_backup_incumbent_scope()->JSStackComparableAddressPrivate()
          : 0;
  if (!it.done() &&
      (!top_backup_incumbent || it.frame()->sp() < top_backup_incumbent)) {
    Tagged<Context> context = Cast<Context>(it.frame()->context());
    // If the topmost_script_having_context is set then it must be correct.
    if (DEBUG_BOOL && !topmost_script_having_context().is_null()) {
      DCHECK_EQ(topmost_script_having_context()->native_context(),
                context->native_context());
    }
    return Handle<NativeContext>(context->native_context(), this);
  }
  DCHECK(topmost_script_having_context().is_null());

  // 2nd candidate: the last Context::Scope's incumbent context if any.
  if (top_backup_incumbent_scope()) {
    v8::Local<v8::Context> incumbent_context =
        top_backup_incumbent_scope()->backup_incumbent_context_;
    return Utils::OpenHandle(*incumbent_context);
  }

  // Last candidate: the entered context or microtask context.
  // Given that there is no other author function is running, there must be
  // no cross-context function running, then the incumbent realm must match
  // the entry realm.
  v8::Local<v8::Context> entered_context =
      reinterpret_cast<v8::Isolate*>(this)->GetEnteredOrMicrotaskContext();
  return Utils::OpenHandle(*entered_context);
}

char* Isolate::ArchiveThread(char* to) {
  MemCopy(to, reinterpret_cast<char*>(thread_local_top()),
          sizeof(ThreadLocalTop));
  return to + sizeof(ThreadLocalTop);
}

char* Isolate::RestoreThread(char* from) {
  MemCopy(reinterpret_cast<char*>(thread_local_top()), from,
          sizeof(ThreadLocalTop));
  DCHECK(context().is_null() || IsContext(context()));
  return from + sizeof(ThreadLocalTop);
}

void Isolate::ReleaseSharedPtrs() {
  base::MutexGuard lock(&managed_ptr_destructors_mutex_);
  while (managed_ptr_destructors_head_) {
    ManagedPtrDestructor* l = managed_ptr_destructors_head_;
    ManagedPtrDestructor* n = nullptr;
    managed_ptr_destructors_head_ = nullptr;
    for (; l != nullptr; l = n) {
      l->external_memory_accounter_.Decrease(this, l->estimated_size_);
      l->destructor_(l->shared_ptr_ptr_);
      n = l->next_;
      delete l;
    }
  }
}

bool Isolate::IsBuiltinTableHandleLocation(Address* handle_location) {
  FullObjectSlot location(handle_location);
  FullObjectSlot first_root(builtin_table());
  FullObjectSlot last_root(first_root + Builtins::kBuiltinCount);
  if (location >= last_root) return false;
  if (location < first_root) return false;
  return true;
}

void Isolate::RegisterManagedPtrDestructor(ManagedPtrDestructor* destructor) {
  base::MutexGuard lock(&managed_ptr_destructors_mutex_);
  DCHECK_NULL(destructor->prev_);
  DCHECK_NULL(destructor->next_);
  if (managed_ptr_destructors_head_) {
    managed_ptr_destructors_head_->prev_ = destructor;
  }
  destructor->next_ = managed_ptr_destructors_head_;
  managed_ptr_destructors_head_ = destructor;
}

void Isolate::UnregisterManagedPtrDestructor(ManagedPtrDestructor* destructor) {
  base::MutexGuard lock(&managed_ptr_destructors_mutex_);
  if (destructor->prev_) {
    destructor->prev_->next_ = destructor->next_;
  } else {
    DCHECK_EQ(destructor, managed_ptr_destructors_head_);
    managed_ptr_destructors_head_ = destructor->next_;
  }
  if (destructor->next_) destructor->next_->prev_ = destructor->prev_;
  destructor->prev_ = nullptr;
  destructor->next_ = nullptr;
}

#if V8_ENABLE_WEBASSEMBLY
bool Isolate::IsOnCentralStack(Address addr) {
  auto stack = SimulatorStack::GetCentralStackView(this);
  Address stack_top = reinterpret_cast<Address>(stack.begin());
  Address stack_base = reinterpret_cast<Address>(stack.end());
  return stack_top < addr && addr <= stack_base;
}

bool Isolate::IsOnCentralStack() {
#if USE_SIMULATOR
  return IsOnCentralStack(Simulator::current(this)->get_sp());
#else
  return IsOnCentralStack(GetCurrentStackPosition());
#endif
}

void Isolate::AddSharedWasmMemory(Handle<WasmMemoryObject> memory_object) {
  Handle<WeakArrayList> shared_wasm_memories =
      factory()->shared_wasm_memories();
  shared_wasm_memories = WeakArrayList::Append(
      this, shared_wasm_memories, MaybeObjectDirectHandle::Weak(memory_object));
  heap()->set_shared_wasm_memories(*shared_wasm_memories);
}

void Isolate::SyncStackLimit() {
  // Synchronize the stack limit with the active continuation for
  // stack-switching. This can be done before or after changing the stack
  // pointer itself, as long as we update both before the next stack check.
  // {StackGuard::SetStackLimitForStackSwitching} doesn't update the value of
  // the jslimit if it contains a sentinel value, and it is also thread-safe. So
  // if an interrupt is requested before, during or after this call, it will be
  // preserved and handled at the next stack check.

  DisallowGarbageCollection no_gc;
  auto continuation =
      Cast<WasmContinuationObject>(root(RootIndex::kActiveContinuation));
  wasm::StackMemory* stack =
      reinterpret_cast<wasm::StackMemory*>(continuation->stack());
  if (v8_flags.trace_wasm_stack_switching) {
    PrintF("Switch to stack #%d\n", stack->id());
  }
  uintptr_t limit = reinterpret_cast<uintptr_t>(stack->jmpbuf()->stack_limit);
  stack_guard()->SetStackLimitForStackSwitching(limit);
  UpdateCentralStackInfo();
}

void Isolate::UpdateCentralStackInfo() {
  Tagged<Object> current = root(RootIndex::kActiveContinuation);
  DCHECK(!IsUndefined(current));
  wasm::StackMemory* wasm_stack = reinterpret_cast<wasm::StackMemory*>(
      Cast<WasmContinuationObject>(current)->stack());
  current = Cast<WasmContinuationObject>(current)->parent();
  thread_local_top()->is_on_central_stack_flag_ =
      IsOnCentralStack(wasm_stack->jmpbuf()->sp);
  // Update the central stack info on switch. Only consider the innermost stack
  bool updated_central_stack = false;
  // We don't need to add all inactive stacks. Only the ones in the active chain
  // may contain cpp heap pointers.
  while (!IsUndefined(current)) {
    auto cont = Cast<WasmContinuationObject>(current);
    auto* wasm_stack = reinterpret_cast<wasm::StackMemory*>(cont->stack());
    // On x64 and arm64 we don't need to record the stack segments for
    // conservative stack scanning. We switch to the central stack for foreign
    // calls, so secondary stacks only contain wasm frames which use the precise
    // GC.
    current = cont->parent();
    if (!updated_central_stack && IsOnCentralStack(wasm_stack->jmpbuf()->sp)) {
      // This is the most recent use of the central stack in the call chain.
      // Switch to this SP if we need to switch to the central stack in the
      // future.
      thread_local_top()->central_stack_sp_ = wasm_stack->jmpbuf()->sp;
      thread_local_top()->central_stack_limit_ =
          reinterpret_cast<Address>(wasm_stack->jmpbuf()->stack_limit);
      updated_central_stack = true;
    }
  }
}

void Isolate::RetireWasmStack(wasm::StackMemory* stack) {
  stack->jmpbuf()->state = wasm::JumpBuffer::Retired;
  size_t index = stack->index();
  // We can only return from a stack that was still in the global list.
  DCHECK_LT(index, wasm_stacks().size());
  std::unique_ptr<wasm::StackMemory> stack_ptr =
      std::move(wasm_stacks()[index]);
  DCHECK_EQ(stack_ptr.get(), stack);
  if (index != wasm_stacks().size() - 1) {
    wasm_stacks()[index] = std::move(wasm_stacks().back());
    wasm_stacks()[index]->set_index(index);
  }
  wasm_stacks().pop_back();
  for (size_t i = 0; i < wasm_stacks().size(); ++i) {
    SLOW_DCHECK(wasm_stacks()[i]->index() == i);
  }
  stack_pool().Add(std::move(stack_ptr));
}

wasm::WasmOrphanedGlobalHandle* Isolate::NewWasmOrphanedGlobalHandle() {
  return wasm::WasmEngine::NewOrphanedGlobalHandle(&wasm_orphaned_handle_);
}

#endif  // V8_ENABLE_WEBASSEMBLY

Isolate::PerIsolateThreadData::~PerIsolateThreadData() {
#if defined(USE_SIMULATOR)
  delete simulator_;
#endif
}

Isolate::PerIsolateThreadData* Isolate::ThreadDataTable::Lookup(
    ThreadId thread_id) {
  auto t = table_.find(thread_id);
  if (t == table_.end()) return nullptr;
  return t->second;
}

void Isolate::ThreadDataTable::Insert(Isolate::PerIsolateThreadData* data) {
  bool inserted = table_.insert(std::make_pair(data->thread_id_, data)).second;
  CHECK(inserted);
}

void Isolate::ThreadDataTable::Remove(PerIsolateThreadData* data) {
  table_.erase(data->thread_id_);
  delete data;
}

void Isolate::ThreadDataTable::RemoveAllThreads() {
  for (auto& x : table_) {
    delete x.second;
  }
  table_.clear();
}

class TracingAccountingAllocator : public AccountingAllocator {
 public:
  explicit TracingAccountingAllocator(Isolate* isolate) : isolate_(isolate) {}
  ~TracingAccountingAllocator() = default;

 protected:
  void TraceAllocateSegmentImpl(v8::internal::Segment* segment) override {
    base::MutexGuard lock(&mutex_);
    UpdateMemoryTrafficAndReportMemoryUsage(segment->total_size());
  }

  void TraceZoneCreationImpl(const Zone* zone) override {
    base::MutexGuard lock(&mutex_);
    active_zones_.insert(zone);
    nesting_depth_++;
  }

  void TraceZoneDestructionImpl(const Zone* zone) override {
    base::MutexGuard lock(&mutex_);
#ifdef V8_ENABLE_PRECISE_ZONE_STATS
    if (v8_flags.trace_zone_type_stats) {
      type_stats_.MergeWith(zone->type_stats());
    }
#endif
    UpdateMemoryTrafficAndReportMemoryUsage(zone->segment_bytes_allocated());
    active_zones_.erase(zone);
    nesting_depth_--;

#ifdef V8_ENABLE_PRECISE_ZONE_STATS
    if (v8_flags.trace_zone_type_stats && active_zones_.empty()) {
      type_stats_.Dump();
    }
#endif
  }

 private:
  void UpdateMemoryTrafficAndReportMemoryUsage(size_t memory_traffic_delta) {
    if (!v8_flags.trace_zone_stats &&
        !(TracingFlags::zone_stats.load(std::memory_order_relaxed) &
          v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
      // Don't print anything if the zone tracing was enabled only because of
      // v8_flags.trace_zone_type_stats.
      return;
    }

    memory_traffic_since_last_report_ += memory_traffic_delta;
    if (memory_traffic_since_last_report_ < v8_flags.zone_stats_tolerance)
      return;
    memory_traffic_since_last_report_ = 0;

    Dump(buffer_, true);

    {
      std::string trace_str = buffer_.str();

      if (v8_flags.trace_zone_stats) {
        PrintF(
            "{"
            "\"type\": \"v8-zone-trace\", "
            "\"stats\": %s"
            "}\n",
            trace_str.c_str());
      }
      if (V8_UNLIKELY(
              TracingFlags::zone_stats.load(std::memory_order_relaxed) &
              v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
        TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("v8.zone_stats"),
                             "V8.Zone_Stats", TRACE_EVENT_SCOPE_THREAD, "stats",
                             TRACE_STR_COPY(trace_str.c_str()));
      }
    }

    // Clear the buffer.
    buffer_.str(std::string());
  }

  void Dump(std::ostringstream& out, bool dump_details) {
    // Note: Neither isolate nor zones are locked, so be careful with accesses
    // as the allocator is potentially used on a concurrent thread.
    double time = isolate_->time_millis_since_init();
    out << "{" << "\"isolate\": \"" << reinterpret_cast<void*>(isolate_)
        << "\", " << "\"time\": " << time << ", ";
    size_t total_segment_bytes_allocated = 0;
    size_t total_zone_allocation_size = 0;
    size_t total_zone_freed_size = 0;

    if (dump_details) {
      // Print detailed zone stats if memory usage changes direction.
      out << "\"zones\": [";
      bool first = true;
      for (const Zone* zone : active_zones_) {
        size_t zone_segment_bytes_allocated = zone->segment_bytes_allocated();
        size_t zone_allocation_size = zone->allocation_size_for_tracing();
        size_t freed_size = zone->freed_size_for_tracing();
        if (first) {
          first = false;
        } else {
          out << ", ";
        }
        out << "{" << "\"name\": \"" << zone->name() << "\", "
            << "\"allocated\": " << zone_segment_bytes_allocated << ", "
            << "\"used\": " << zone_allocation_size << ", "
            << "\"freed\": " << freed_size << "}";
        total_segment_bytes_allocated += zone_segment_bytes_allocated;
        total_zone_allocation_size += zone_allocation_size;
        total_zone_freed_size += freed_size;
      }
      out << "], ";
    } else {
      // Just calculate total allocated/used memory values.
      for (const Zone* zone : active_zones_) {
        total_segment_bytes_allocated += zone->segment_bytes_allocated();
        total_zone_allocation_size += zone->allocation_size_for_tracing();
        total_zone_freed_size += zone->freed_size_for_tracing();
      }
    }
    out << "\"allocated\": " << total_segment_bytes_allocated << ", "
        << "\"used\": " << total_zone_allocation_size << ", "
        << "\"freed\": " << total_zone_freed_size << "}";
  }

  Isolate* const isolate_;
  std::atomic<size_t> nesting_depth_{0};

  base::Mutex mutex_;
  std::unordered_set<const Zone*> active_zones_;
#ifdef V8_ENABLE_PRECISE_ZONE_STATS
  TypeStats type_stats_;
#endif
  std::ostringstream buffer_;
  // This value is increased on both allocations and deallocations.
  size_t memory_traffic_since_last_report_ = 0;
};

#ifdef DEBUG
std::atomic<size_t> Isolate::non_disposed_isolates_;
#endif  // DEBUG

// static
Isolate* Isolate::New() { return New(IsolateGroup::AcquireDefault()); }

// static
Isolate* Isolate::New(IsolateGroup* group) { return Allocate(group); }

// static
Isolate* Isolate::Allocate(IsolateGroup* group) {
  // v8::V8::Initialize() must be called before creating any isolates.
  DCHECK_NOT_NULL(V8::GetCurrentPlatform());
  // Allocate Isolate itself on C++ heap, ensuring page alignment.
  void* isolate_ptr = base::AlignedAlloc(sizeof(Isolate), kMinimumOSPageSize);
  // IsolateAllocator manages the virtual memory resources for the Isolate.
  Isolate* isolate = new (isolate_ptr) Isolate(group);

#ifdef DEBUG
  non_disposed_isolates_++;
#endif  // DEBUG

  return isolate;
}

// static
void Isolate::Delete(Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  // v8::V8::Dispose() must only be called after deleting all isolates.
  DCHECK_NOT_NULL(V8::GetCurrentPlatform());
  // Temporarily set this isolate as current so that various parts of
  // the isolate can access it in their destructors without having a
  // direct pointer. We don't use Enter/Exit here to avoid
  // initializing the thread data.
  PerIsolateThreadData* saved_data = isolate->CurrentPerIsolateThreadData();
  Isolate* saved_isolate = isolate->TryGetCurrent();
  SetIsolateThreadLocals(isolate, nullptr);
  isolate->set_thread_id(ThreadId::Current());
  isolate->heap()->SetStackStart();

  isolate->Deinit();

#ifdef DEBUG
  non_disposed_isolates_--;
#endif  // DEBUG

  IsolateGroup* group = isolate->isolate_group();
  isolate->~Isolate();
  // Only release the group once all other Isolate members have been destroyed.
  group->Release();
  // Free the isolate itself.
  base::AlignedFree(isolate);

  // Restore the previous current isolate.
  SetIsolateThreadLocals(saved_isolate, saved_data);
}

void Isolate::SetUpFromReadOnlyArtifacts(ReadOnlyArtifacts* artifacts,
                                         ReadOnlyHeap* ro_heap) {
  if (ReadOnlyHeap::IsReadOnlySpaceShared()) {
    DCHECK_NOT_NULL(artifacts);
    InitializeNextUniqueSfiId(artifacts->initial_next_unique_sfi_id());
  } else {
    DCHECK_NULL(artifacts);
  }
  DCHECK_NOT_NULL(ro_heap);
  DCHECK_IMPLIES(read_only_heap_ != nullptr, read_only_heap_ == ro_heap);
  read_only_heap_ = ro_heap;
  heap_.SetUpFromReadOnlyHeap(read_only_heap_);
}

v8::PageAllocator* Isolate::page_allocator() const {
  return isolate_group()->page_allocator();
}

Isolate::Isolate(IsolateGroup* isolate_group)
    : isolate_data_(this, isolate_group),
      isolate_group_(isolate_group),
      id_(isolate_counter.fetch_add(1, std::memory_order_relaxed)),
      allocator_(new TracingAccountingAllocator(this)),
      traced_handles_(this),
      builtins_(this),
#if defined(DEBUG) || defined(VERIFY_HEAP)
      num_active_deserializers_(0),
#endif
      logger_(new Logger()),
      detailed_source_positions_for_profiling_(v8_flags.detailed_line_info),
      persistent_handles_list_(new PersistentHandlesList()),
      jitless_(v8_flags.jitless),
      next_unique_sfi_id_(0),
      next_module_async_evaluation_ordinal_(
          SourceTextModule::kFirstAsyncEvaluationOrdinal),
      cancelable_task_manager_(new CancelableTaskManager()) {
  TRACE_ISOLATE(constructor);
  CheckIsolateLayout();

  isolate_group->IncrementIsolateCount();

  // ThreadManager is initialized early to support locking an isolate
  // before it is entered.
  thread_manager_ = new ThreadManager(this);

  handle_scope_data()->Initialize();

#define ISOLATE_INIT_EXECUTE(type, name, initial_value) \
  name##_ = (initial_value);
  ISOLATE_INIT_LIST(ISOLATE_INIT_EXECUTE)
#undef ISOLATE_INIT_EXECUTE

#define ISOLATE_INIT_ARRAY_EXECUTE(type, name, length) \
  memset(name##_, 0, sizeof(type) * length);
  ISOLATE_INIT_ARRAY_LIST(ISOLATE_INIT_ARRAY_EXECUTE)
#undef ISOLATE_INIT_ARRAY_EXECUTE

  InitializeLoggingAndCounters();
  debug_ = new Debug(this);

  InitializeDefaultEmbeddedBlob();

#if V8_ENABLE_WEBASSEMBLY
  // If we are in production V8 and not in mksnapshot we have to pass the
  // landing pad builtin to the WebAssembly TrapHandler.
  // TODO(ahaas): Isolate creation is the earliest point in time when builtins
  // are available, so we cannot set the landing pad earlier at the moment.
  // However, if builtins ever get loaded during process initialization time,
  // then the initialization of the trap handler landing pad should also go
  // there.
  // TODO(ahaas): The code of the landing pad does not have to be a builtin,
  // we could also just move it to the trap handler, and implement it e.g. with
  // inline assembly. It's not clear if that's worth it.
  if (Isolate::CurrentEmbeddedBlobCodeSize()) {
    EmbeddedData embedded_data = EmbeddedData::FromBlob();
    Address landing_pad =
        embedded_data.InstructionStartOf(Builtin::kWasmTrapHandlerLandingPad);
    i::trap_handler::SetLandingPad(landing_pad);
  }

  for (size_t i = 0; i < Builtins::kNumWasmIndirectlyCallableBuiltins; i++) {
    wasm_builtin_code_handles_[i] = wasm::WasmCodePointerTable::kInvalidHandle;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  MicrotaskQueue::SetUpDefaultMicrotaskQueue(this);
}

void Isolate::CheckIsolateLayout() {
#ifdef V8_ENABLE_SANDBOX
  CHECK_EQ(static_cast<int>(OFFSET_OF(ExternalPointerTable, base_)),
           Internals::kExternalPointerTableBasePointerOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(TrustedPointerTable, base_)),
           Internals::kTrustedPointerTableBasePointerOffset);
  CHECK_EQ(static_cast<int>(sizeof(ExternalPointerTable)),
           Internals::kExternalPointerTableSize);
  CHECK_EQ(static_cast<int>(sizeof(ExternalPointerTable)),
           ExternalPointerTable::kSize);
  CHECK_EQ(static_cast<int>(sizeof(TrustedPointerTable)),
           Internals::kTrustedPointerTableSize);
  CHECK_EQ(static_cast<int>(sizeof(TrustedPointerTable)),
           TrustedPointerTable::kSize);
#endif

  CHECK_EQ(OFFSET_OF(Isolate, isolate_data_), 0);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.stack_guard_)),
           Internals::kIsolateStackGuardOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.is_marking_flag_)),
           Internals::kVariousBooleanFlagsOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.error_message_param_)),
      Internals::kErrorMessageParamOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.builtin_tier0_entry_table_)),
           Internals::kBuiltinTier0EntryTableOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.builtin_tier0_table_)),
      Internals::kBuiltinTier0TableOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.new_allocation_info_)),
      Internals::kNewAllocationInfoOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.old_allocation_info_)),
      Internals::kOldAllocationInfoOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.fast_c_call_caller_fp_)),
           Internals::kIsolateFastCCallCallerFpOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.fast_c_call_caller_pc_)),
           Internals::kIsolateFastCCallCallerPcOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.cage_base_)),
           Internals:
"""


```