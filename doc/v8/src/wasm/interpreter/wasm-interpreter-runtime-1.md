Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part 2 of a larger file. I need to understand what this code does within the context of the V8 JavaScript engine's WebAssembly interpreter. Specifically, I should identify the main operations and how they relate to JavaScript, providing an illustrative JavaScript example if possible.

Looking at the code, several key areas stand out:

1. **Function Execution:**  The code handles calling WebAssembly functions, both internal and external (including calls to JavaScript). This involves setting up the execution environment (stack frames, arguments, return values), and managing potential traps or exceptions.
2. **Indirect Calls:**  It implements the logic for indirect calls through function tables, including checks for table bounds, signature compatibility, and caching.
3. **Reference Types:**  A significant portion deals with WebAssembly's reference types (e.g., `funcref`, `externref`, `structref`, `arrayref`), including type checking, casting, and handling null values.
4. **Memory Management:**  There's interaction with the stack and mechanisms for potential stack expansion.
5. **Exception Handling:** The code includes logic to handle exceptions (traps) within the interpreter.
6. **Integration with JavaScript:**  The code shows how the interpreter interacts with JavaScript when calling imported or exported functions. This involves converting between JavaScript and WebAssembly values.

To illustrate the connection with JavaScript, I can provide examples of:
- Calling a WebAssembly function from JavaScript.
- Calling a JavaScript function from WebAssembly.
- Using WebAssembly's reference types from JavaScript.
This C++ code snippet (`wasm-interpreter-runtime.cc`, part 2) focuses on the **runtime execution** of WebAssembly code within V8's interpreter. It provides the core functionalities needed to manage the execution environment, handle function calls (both direct and indirect), manage the stack, interact with JavaScript, and handle exceptions.

Here's a breakdown of its key functions:

* **Function Calls (Internal and External):**
    * `ExecuteFunction`:  Manages the execution of a WebAssembly function within the same module. It sets up the new stack frame, initializes locals, and calls the actual bytecode execution.
    * `ExecuteIndirectCall`: Handles calls through function tables. It performs bounds checks on the table index, checks for signature compatibility, and then executes the target function (either internal WebAssembly or an external JavaScript function).
    * `ExecuteCallRef`: Handles calling functions through `funcref` values, which can point to either internal WebAssembly functions or external JavaScript functions.
    * `CallImportedFunction`: Specifically handles calls to functions imported from other WebAssembly modules or JavaScript. It manages the transition between WebAssembly and the host environment.
    * `CallExternalJSFunction`:  Facilitates calling JavaScript functions from WebAssembly. It handles argument marshalling and exception handling.

* **Indirect Call Table Management:**
    * `PurgeIndirectCallCache`, `ClearIndirectCallCacheEntry`, `UpdateIndirectCallTable`:  Manage the caching of indirect call targets to optimize performance. This caching helps avoid repeated lookups of the target function.
    * `CheckIndirectCallSignature`:  Verifies that the signature of the function being called indirectly matches the expected signature. This is crucial for type safety.

* **Stack Management:**
    * The code manages the interpreter's stack, pushing and popping frames during function calls. It also handles potential stack overflows and attempts to expand the stack if necessary.

* **Reference Type Handling:**
    * The code includes functions for manipulating WebAssembly's reference types (`funcref`, `externref`, `structref`, `arrayref`). This includes:
        * `CheckIndirectCallSignature`, `ExecuteIndirectCall`, `ExecuteCallRef`:  Handling `funcref` in indirect calls.
        * `WasmToJSObject`, `JSToWasmObject`, `WasmJSToWasmObject`: Converting between WebAssembly reference types and JavaScript objects.
        * `StructNewUninitialized`, `ArrayNewUninitialized`, `WasmArrayNewSegment`, `WasmArrayInitSegment`, `WasmArrayCopy`: Functions for creating and manipulating WebAssembly structs and arrays.
        * `RefIsEq`, `RefIsI31`, `RefIsStruct`, `RefIsArray`, `RefIsString`: Functions for type checking WebAssembly references.
        * `SubtypeCheck`:  Performs runtime subtype checks for reference types.

* **Exception Handling:**
    * `SetTrap`: Sets a trap (exception) during WebAssembly execution, indicating an error condition.
    * The code also manages the unwinding of the stack when an exception occurs.

* **Integration with JavaScript:**
    * `CallWasmToJSBuiltin`:  Handles the actual invocation of a JavaScript function from WebAssembly. It manages the necessary context switching and exception handling.

**Relationship with JavaScript (with examples):**

This code is fundamentally intertwined with JavaScript's ability to interact with WebAssembly.

**Example 1: Calling a WebAssembly function from JavaScript:**

```javascript
// Assuming you have instantiated a WebAssembly module:
const wasmInstance = // ... your WebAssembly instance

// Assuming the WebAssembly module exports a function named 'add'
const addFunction = wasmInstance.exports.add;

const result = addFunction(5, 10); // Calling the WebAssembly function
console.log(result); // Output: 15
```

Behind the scenes, when `addFunction(5, 10)` is called, the V8 engine (specifically this `wasm-interpreter-runtime.cc` code when the interpreter is used) will:

1. **Transition from JavaScript to WebAssembly:** Set up the WebAssembly execution environment.
2. **Call `ExecuteFunction`:**  If it's a direct call within the module, this function will be invoked to execute the `add` function's bytecode.
3. **Execute the WebAssembly bytecode:** The interpreter will step through the instructions of the `add` function.
4. **Return the result:** The result will be passed back to the JavaScript environment.

**Example 2: Calling a JavaScript function from WebAssembly (Import):**

```javascript
// JavaScript function to be called from WebAssembly
function logMessage(message) {
  console.log("WebAssembly says:", message);
}

const importObject = {
  env: {
    log: logMessage // Mapping the JavaScript function to an import name
  }
};

// Instantiate the WebAssembly module with the import object
const wasmInstance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'), importObject);

// Assume the WebAssembly module has a function that calls the imported 'log' function
wasmInstance.exports.callLog("Hello from WebAssembly!");
```

In this scenario, when the WebAssembly code calls the imported function named "log":

1. **`CallImportedFunction` is invoked:** This code in `wasm-interpreter-runtime.cc` will recognize it's an import.
2. **Lookup the imported function:** It will use the `importObject` provided during instantiation to find the corresponding JavaScript function (`logMessage`).
3. **`CallExternalJSFunction` is invoked:** This function will marshal the arguments from WebAssembly to JavaScript.
4. **The JavaScript function is executed:** `logMessage("Hello from WebAssembly!")` will be called.
5. **The result (if any) is returned:** The result (or void) will be passed back to the WebAssembly execution.

**Example 3: Working with Reference Types:**

While direct interaction with reference types from raw JavaScript is limited, JavaScript's `WebAssembly.Table` and `WebAssembly.Global` can hold `funcref` and `externref` respectively. When WebAssembly code interacts with these, the functions within `wasm-interpreter-runtime.cc` like `CheckIndirectCallSignature`, `ExecuteIndirectCall`, and the reference type manipulation functions come into play to ensure type safety and proper handling of these references.

In summary, this code snippet is a crucial part of the V8 engine's ability to execute WebAssembly code, bridging the gap between the low-level bytecode and the high-level JavaScript environment. It handles the complexities of function calls, stack management, and type safety within the interpreted execution model.

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
e reset it every time we get to a backward jump in a loop.
  HandleScope handle_scope(GetIsolate());

  current_frame_.current_bytecode_ = code;
  FrameState prev_frame_state = current_frame_;
  current_frame_.current_sp_ += slot_offset;
  current_frame_.handle_scope_ = &handle_scope;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  current_frame_.current_stack_start_args_ +=
      (current_stack_size - target_function->args_count());
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  current_frame_.current_function_ = target_function;
  current_frame_.previous_frame_ = &prev_frame_state;
  current_frame_.caught_exceptions_ = Handle<FixedArray>::null();

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  current_frame_.current_stack_height_++;
  current_frame_.current_stack_start_locals_ =
      current_frame_.current_stack_start_args_ + target_function->args_count();
  current_frame_.current_stack_start_stack_ =
      current_frame_.current_stack_start_locals_ +
      target_function->locals_count();

  if (v8_flags.trace_drumbrake_execution) {
    Trace("\nCallFunction: %d\n", func_index);
    Trace("= > PushFrame #%d(#%d @%d)\n", current_frame_.current_stack_height_,
          func_index, 0);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  const uint8_t* stack_limit = current_frame_.thread_->StackLimitAddress();
  if (V8_UNLIKELY(stack_limit <= current_frame_.current_sp_ ||
                  !target_function->InitializeSlots(
                      current_frame_.current_sp_,
                      stack_limit - current_frame_.current_sp_))) {
    // Try to resize the stack.
    size_t additional_required_space =
        target_function->frame_size() -
        (stack_limit - current_frame_.current_sp_);
    // Try again.
    if (!current_frame_.thread_->ExpandStack(additional_required_space) ||
        !target_function->InitializeSlots(
            current_frame_.current_sp_,
            (stack_limit = current_frame_.thread_->StackLimitAddress()) -
                current_frame_.current_sp_)) {
      ClearThreadInWasmScope clear_wasm_flag(isolate_);
      SealHandleScope shs(isolate_);
      SetTrap(TrapReason::kTrapUnreachable, code);
      isolate_->StackOverflow();
      return;
    }
  }

  uint32_t ref_slots_count = target_function->ref_slots_count();
  current_frame_.ref_array_current_sp_ += ref_stack_fp_offset;
  if (V8_UNLIKELY(ref_slots_count > 0)) {
    current_frame_.ref_array_length_ =
        current_frame_.ref_array_current_sp_ + ref_slots_count;
    EnsureRefStackSpace(current_frame_.ref_array_length_);

    // Initialize locals of ref types.
    if (V8_UNLIKELY(target_function->ref_locals_count() > 0)) {
      uint32_t ref_stack_index =
          target_function->ref_rets_count() + target_function->ref_args_count();
      for (uint32_t i = 0; i < target_function->locals_count(); i++) {
        ValueType local_type = target_function->local_type(i);
        if (local_type == kWasmExternRef || local_type == kWasmNullExternRef) {
          StoreWasmRef(ref_stack_index++,
                       WasmRef(isolate_->factory()->null_value()));
        } else if (local_type.is_reference()) {
          StoreWasmRef(ref_stack_index++,
                       WasmRef(isolate_->factory()->wasm_null()));
        }
      }
    }
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  uint32_t shadow_stack_offset = 0;
  if (v8_flags.trace_drumbrake_execution) {
    shadow_stack_offset = target_function->rets_slots_size() * kSlotSize;
    for (uint32_t i = 0; i < target_function->args_count(); i++) {
      shadow_stack_offset +=
          TracePush(target_function->arg_type(i).kind(), shadow_stack_offset);
    }

    // Make room for locals in shadow stack
    shadow_stack_offset += target_function->const_slots_size_in_bytes();
    for (size_t i = 0; i < target_function->locals_count(); i++) {
      shadow_stack_offset +=
          TracePush(target_function->local_type(i).kind(), shadow_stack_offset);
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  const uint8_t* callee_code = target_function->GetCode();
  int64_t r0 = 0;
  double fp0 = .0;

  // Execute function
  CallThroughDispatchTable(
      callee_code, reinterpret_cast<uint32_t*>(current_frame_.current_sp_),
      this, r0, fp0);

  uint32_t ref_slots_to_clear =
      ref_slots_count - target_function->ref_rets_count();
  if (V8_UNLIKELY(ref_slots_to_clear > 0)) {
    ClearRefStackValues(current_frame_.ref_array_current_sp_ +
                            target_function->ref_rets_count(),
                        ref_slots_to_clear);
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  shadow_stack_ = prev_shadow_stack;

  if (v8_flags.trace_drumbrake_execution && shadow_stack_ != nullptr &&
      prev_frame_state.current_function_) {
    for (size_t i = 0; i < target_function->args_count(); i++) {
      TracePop();
    }

    for (size_t i = 0; i < target_function->return_count(); i++) {
      return_slot_offset +=
          TracePush(target_function->return_type(i).kind(), return_slot_offset);
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  current_frame_.handle_scope_ = nullptr;
  current_frame_.DisposeCaughtExceptionsArray(isolate_);
  current_frame_ = prev_frame_state;

  // Check state.
  WasmInterpreterThread::State current_state = state();
  if (V8_UNLIKELY(current_state != WasmInterpreterThread::State::RUNNING)) {
    switch (current_state) {
      case WasmInterpreterThread::State::EH_UNWINDING:
        DCHECK(isolate_->has_exception());
        if (!current_frame_.current_function_) {
          // We unwound the whole call stack without finding a catch handler.
          current_frame_.thread_->Stop();
          RedirectCodeToUnwindHandler(code);
        } else if (HandleException(
                       reinterpret_cast<uint32_t*>(current_frame_.current_sp_),
                       code) == WasmInterpreterThread::HANDLED) {
          trap_handler::SetThreadInWasm();
          current_frame_.thread_->Run();
        } else {
          RedirectCodeToUnwindHandler(code);
        }
        break;

      case WasmInterpreterThread::State::TRAPPED:
      case WasmInterpreterThread::State::STOPPED:
        RedirectCodeToUnwindHandler(code);
        break;

      default:
        UNREACHABLE();
    }
  }
  // TODO(paolosev@microsoft.com): StackCheck.
}

void WasmInterpreterRuntime::PurgeIndirectCallCache(uint32_t table_index) {
  DCHECK_LT(table_index, indirect_call_tables_.size());
  const WasmTable& table = module_->tables[table_index];
  if (IsSubtypeOf(table.type, kWasmFuncRef, module_)) {
    size_t length =
        Tagged<WasmDispatchTable>::cast(
            wasm_trusted_instance_data()->dispatch_tables()->get(table_index))
            ->length();
    indirect_call_tables_[table_index].resize(length);
    for (size_t i = 0; i < length; i++) {
      indirect_call_tables_[table_index][i] = {};
    }
  }
}

// static
void WasmInterpreterRuntime::ClearIndirectCallCacheEntry(
    Isolate* isolate, Handle<WasmInstanceObject> instance, uint32_t table_index,
    uint32_t entry_index) {
  Handle<Tuple2> interpreter_object =
      WasmTrustedInstanceData::GetOrCreateInterpreterObject(instance);
  InterpreterHandle* handle =
      GetOrCreateInterpreterHandle(isolate, interpreter_object);
  WasmInterpreterRuntime* wasm_runtime =
      handle->interpreter()->GetWasmRuntime();
  DCHECK_LT(table_index, wasm_runtime->indirect_call_tables_.size());
  DCHECK_LT(entry_index,
            wasm_runtime->indirect_call_tables_[table_index].size());
  wasm_runtime->indirect_call_tables_[table_index][entry_index] = {};
}

// static
void WasmInterpreterRuntime::UpdateIndirectCallTable(
    Isolate* isolate, Handle<WasmInstanceObject> instance,
    uint32_t table_index) {
  Handle<Tuple2> interpreter_object =
      WasmTrustedInstanceData::GetOrCreateInterpreterObject(instance);
  InterpreterHandle* handle =
      GetOrCreateInterpreterHandle(isolate, interpreter_object);
  WasmInterpreterRuntime* wasm_runtime =
      handle->interpreter()->GetWasmRuntime();
  wasm_runtime->PurgeIndirectCallCache(table_index);
}

bool WasmInterpreterRuntime::CheckIndirectCallSignature(
    uint32_t table_index, uint32_t entry_index, uint32_t sig_index) const {
  const WasmTable& table = module_->tables[table_index];
  bool needs_type_check = !EquivalentTypes(
      table.type.AsNonNull(), ValueType::Ref(sig_index), module_, module_);
  bool needs_null_check = table.type.is_nullable();

  // Copied from Liftoff.
  // We do both the type check and the null check by checking the signature,
  // so this shares most code. For the null check we then only check if the
  // stored signature is != -1.
  if (needs_type_check || needs_null_check) {
    const IndirectCallTable& dispatch_table =
        indirect_call_tables_[table_index];
    uint32_t real_sig_id = dispatch_table[entry_index].sig_index;
    uint32_t canonical_sig_id = module_->canonical_sig_id(sig_index);
    if (!needs_type_check) {
      // Only check for -1 (nulled table entry).
      if (real_sig_id == uint32_t(-1)) return false;
    } else if (!module_->types[sig_index].is_final) {
      if (real_sig_id == canonical_sig_id) return true;
      if (needs_null_check && (real_sig_id == uint32_t(-1))) return false;

      Tagged<Map> rtt = Tagged<Map>::cast(isolate_->heap()
                                              ->wasm_canonical_rtts()
                                              ->Get(real_sig_id)
                                              .GetHeapObjectAssumeWeak());
      Handle<Map> formal_rtt = RttCanon(sig_index);
      return SubtypeCheck(rtt, *formal_rtt, sig_index);
    } else {
      if (real_sig_id != canonical_sig_id) return false;
    }
  }

  return true;
}

void WasmInterpreterRuntime::ExecuteIndirectCall(
    const uint8_t*& current_code, uint32_t table_index, uint32_t sig_index,
    uint32_t entry_index, uint32_t stack_pos, uint32_t* sp,
    uint32_t ref_stack_fp_offset, uint32_t slot_offset,
    uint32_t return_slot_offset, bool is_tail_call) {
  DCHECK_LT(table_index, indirect_call_tables_.size());

  IndirectCallTable& table = indirect_call_tables_[table_index];

  // Bounds check against table size.
  DCHECK_GE(
      table.size(),
      Tagged<WasmDispatchTable>::cast(
          wasm_trusted_instance_data()->dispatch_tables()->get(table_index))
          ->length());
  if (entry_index >= table.size()) {
    SetTrap(TrapReason::kTrapTableOutOfBounds, current_code);
    return;
  }

  if (!table[entry_index]) {
    HandleScope handle_scope(isolate_);  // Avoid leaking handles.

    IndirectFunctionTableEntry entry(instance_object_, table_index,
                                     entry_index);
    const FunctionSig* signature = module_->signature(sig_index);

    Handle<Object> object_implicit_arg = handle(entry.implicit_arg(), isolate_);
    if (IsWasmTrustedInstanceData(*object_implicit_arg)) {
      Tagged<WasmTrustedInstanceData> trusted_instance_object =
          Cast<WasmTrustedInstanceData>(*object_implicit_arg);
      Handle<WasmInstanceObject> instance_object = handle(
          Cast<WasmInstanceObject>(trusted_instance_object->instance_object()),
          isolate_);
      if (instance_object_.is_identical_to(instance_object)) {
        // Call to an import.
        uint32_t func_index = entry.function_index();
        table[entry_index] = IndirectCallValue(func_index, entry.sig_id());
      } else {
        // Cross-instance call.
        table[entry_index] = IndirectCallValue(signature, entry.sig_id());
      }
    } else {
      // Call JS function.
      table[entry_index] = IndirectCallValue(signature, entry.sig_id());
    }
  }

  if (!CheckIndirectCallSignature(table_index, entry_index, sig_index)) {
    SetTrap(TrapReason::kTrapFuncSigMismatch, current_code);
    return;
  }

  IndirectCallValue indirect_call = table[entry_index];
  DCHECK(indirect_call);

  if (indirect_call.mode == IndirectCallValue::Mode::kInternalCall) {
    if (is_tail_call) {
      PrepareTailCall(current_code, indirect_call.func_index, stack_pos,
                      return_slot_offset);
    } else {
      ExecuteFunction(current_code, indirect_call.func_index, stack_pos,
                      ref_stack_fp_offset, slot_offset, return_slot_offset);
      if (state() == WasmInterpreterThread::State::TRAPPED ||
          state() == WasmInterpreterThread::State::STOPPED ||
          state() == WasmInterpreterThread::State::EH_UNWINDING) {
        RedirectCodeToUnwindHandler(current_code);
      }
    }
  } else {
    // ExternalCall
    HandleScope handle_scope(isolate_);  // Avoid leaking handles.

    DCHECK_NOT_NULL(indirect_call.signature);

    // Store a pointer to the current FrameState before leaving the current
    // Activation.
    WasmInterpreterThread* thread = this->thread();
    current_frame_.current_bytecode_ = current_code;
    thread->SetCurrentFrame(current_frame_);
    thread->SetCurrentActivationFrame(sp, slot_offset, stack_pos,
                                      ref_stack_fp_offset);

    // TODO(paolosev@microsoft.com): Optimize this code.
    IndirectFunctionTableEntry entry(instance_object_, table_index,
                                     entry_index);
    Handle<Object> object_implicit_arg = handle(entry.implicit_arg(), isolate_);

    if (IsWasmTrustedInstanceData(*object_implicit_arg)) {
      // Call Wasm function in a different instance.

      // Note that tail calls across WebAssembly module boundaries should
      // guarantee tail behavior, so this implementation does not conform to the
      // spec for a tail call. But it is really difficult to implement
      // cross-instance calls in the interpreter without recursively adding C++
      // stack frames.
      Handle<WasmInstanceObject> target_instance =
          handle(Cast<WasmInstanceObject>(
                     Cast<WasmTrustedInstanceData>(*object_implicit_arg)
                         ->instance_object()),
                 isolate_);

      // Make sure the target WasmInterpreterObject and InterpreterHandle exist.
      Handle<Tuple2> interpreter_object =
          WasmTrustedInstanceData::GetOrCreateInterpreterObject(
              target_instance);
      GetOrCreateInterpreterHandle(isolate_, interpreter_object);

      Address frame_pointer = FindInterpreterEntryFramePointer(isolate_);

      {
        // We should not allocate anything in the heap and avoid GCs after we
        // store ref arguments into stack slots.
        DisallowHeapAllocation no_gc;

        uint8_t* fp = reinterpret_cast<uint8_t*>(sp) + slot_offset;
        StoreRefArgsIntoStackSlots(fp, ref_stack_fp_offset,
                                   indirect_call.signature);
        bool success = WasmInterpreterObject::RunInterpreter(
            isolate_, frame_pointer, target_instance, entry.function_index(),
            fp);
        if (success) {
          StoreRefResultsIntoRefStack(fp, ref_stack_fp_offset,
                                      indirect_call.signature);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
          // Update shadow stack
          if (v8_flags.trace_drumbrake_execution && shadow_stack_ != nullptr) {
            for (size_t i = 0; i < indirect_call.signature->parameter_count();
                 i++) {
              TracePop();
            }

            for (size_t i = 0; i < indirect_call.signature->return_count();
                 i++) {
              return_slot_offset +=
                  TracePush(indirect_call.signature->GetReturn(i).kind(),
                            return_slot_offset);
            }
          }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
        } else {
          thread->Stop();
          RedirectCodeToUnwindHandler(current_code);
        }
      }
    } else {
      // We should not allocate anything in the heap and avoid GCs after we
      // store ref arguments into stack slots.
      DisallowHeapAllocation no_gc;

      // Note that tail calls to host functions do not have to guarantee tail
      // behaviour, so it is ok to recursively allocate C++ stack frames here.
      uint8_t* fp = reinterpret_cast<uint8_t*>(sp) + slot_offset;
      StoreRefArgsIntoStackSlots(fp, ref_stack_fp_offset,
                                 indirect_call.signature);
      ExternalCallResult result = CallExternalJSFunction(
          current_code, module_, object_implicit_arg, indirect_call.signature,
          sp + slot_offset / kSlotSize, slot_offset);
      if (result == ExternalCallResult::EXTERNAL_RETURNED) {
        StoreRefResultsIntoRefStack(fp, ref_stack_fp_offset,
                                    indirect_call.signature);
      } else {  // ExternalCallResult::EXTERNAL_EXCEPTION
        AllowHeapAllocation allow_gc;

        if (HandleException(sp, current_code) ==
            WasmInterpreterThread::ExceptionHandlingResult::UNWOUND) {
          thread->Stop();
          RedirectCodeToUnwindHandler(current_code);
        }
      }
    }
  }
}

void WasmInterpreterRuntime::ExecuteCallRef(
    const uint8_t*& current_code, WasmRef func_ref, uint32_t sig_index,
    uint32_t stack_pos, uint32_t* sp, uint32_t ref_stack_fp_offset,
    uint32_t slot_offset, uint32_t return_slot_offset, bool is_tail_call) {
  if (IsWasmFuncRef(*func_ref)) {
    func_ref =
        handle(Cast<WasmFuncRef>(*func_ref)->internal(isolate_), isolate_);
  }
  if (IsWasmInternalFunction(*func_ref)) {
    Tagged<WasmInternalFunction> wasm_internal_function =
        Cast<WasmInternalFunction>(*func_ref);
    Tagged<Object> implicit_arg = wasm_internal_function->implicit_arg();
    if (IsWasmImportData(implicit_arg)) {
      func_ref = handle(implicit_arg, isolate_);
    } else {
      DCHECK(IsWasmTrustedInstanceData(implicit_arg));
      func_ref = WasmInternalFunction::GetOrCreateExternal(
          handle(wasm_internal_function, isolate_));
      DCHECK(IsJSFunction(*func_ref) || IsUndefined(*func_ref));
    }
  }

  const FunctionSig* signature = module_->signature(sig_index);

  // ExternalCall
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.

  // Store a pointer to the current FrameState before leaving the current
  // Activation.
  WasmInterpreterThread* thread = this->thread();
  current_frame_.current_bytecode_ = current_code;
  thread->SetCurrentFrame(current_frame_);
  thread->SetCurrentActivationFrame(sp, slot_offset, stack_pos,
                                    ref_stack_fp_offset);

  // We should not allocate anything in the heap and avoid GCs after we
  // store ref arguments into stack slots.
  DisallowHeapAllocation no_gc;

  // Note that tail calls to host functions do not have to guarantee tail
  // behaviour, so it is ok to recursively allocate C++ stack frames here.
  uint8_t* fp = reinterpret_cast<uint8_t*>(sp) + slot_offset;
  StoreRefArgsIntoStackSlots(fp, ref_stack_fp_offset, signature);
  ExternalCallResult result =
      CallExternalJSFunction(current_code, module_, func_ref, signature,
                             sp + slot_offset / kSlotSize, slot_offset);
  if (result == ExternalCallResult::EXTERNAL_RETURNED) {
    StoreRefResultsIntoRefStack(fp, ref_stack_fp_offset, signature);
  } else {  // ExternalCallResult::EXTERNAL_EXCEPTION
    AllowHeapAllocation allow_gc;

    if (HandleException(sp, current_code) ==
        WasmInterpreterThread::ExceptionHandlingResult::UNWOUND) {
      thread->Stop();
      RedirectCodeToUnwindHandler(current_code);
    }
  }
}

ExternalCallResult WasmInterpreterRuntime::CallImportedFunction(
    const uint8_t*& current_code, uint32_t function_index, uint32_t* sp,
    uint32_t current_stack_size, uint32_t ref_stack_fp_offset,
    uint32_t current_slot_offset) {
  DCHECK_GT(module_->num_imported_functions, function_index);
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.

  const FunctionSig* sig = module_->functions[function_index].sig;

  ImportedFunctionEntry entry(wasm_trusted_instance_data(), function_index);
  int target_function_index = entry.function_index_in_called_module();
  if (target_function_index >= 0) {
    // WasmToWasm call.
    DCHECK(IsWasmTrustedInstanceData(entry.implicit_arg()));
    Handle<WasmInstanceObject> target_instance =
        handle(Cast<WasmInstanceObject>(
                   Cast<WasmTrustedInstanceData>(entry.implicit_arg())
                       ->instance_object()),
               isolate_);

    // Make sure the WasmInterpreterObject and InterpreterHandle for this
    // instance exist.
    Handle<Tuple2> interpreter_object =
        WasmTrustedInstanceData::GetOrCreateInterpreterObject(target_instance);
    GetOrCreateInterpreterHandle(isolate_, interpreter_object);

    Address frame_pointer = FindInterpreterEntryFramePointer(isolate_);

    {
      // We should not allocate anything in the heap and avoid GCs after we
      // store ref arguments into stack slots.
      DisallowHeapAllocation no_gc;

      uint8_t* fp = reinterpret_cast<uint8_t*>(sp);
      StoreRefArgsIntoStackSlots(fp, ref_stack_fp_offset, sig);
      // Note that tail calls across WebAssembly module boundaries should
      // guarantee tail behavior, so this implementation does not conform to the
      // spec for a tail call. But it is really difficult to implement
      // cross-instance calls in the interpreter without recursively adding C++
      // stack frames.

      // TODO(paolosev@microsoft.com) - Is it possible to short-circuit this in
      // the case where we are calling a function in the same Wasm instance,
      // with a simple call to WasmInterpreterRuntime::ExecuteFunction()?
      bool success = WasmInterpreterObject::RunInterpreter(
          isolate_, frame_pointer, target_instance, target_function_index, fp);
      if (success) {
        StoreRefResultsIntoRefStack(fp, ref_stack_fp_offset, sig);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
        // Update shadow stack
        if (v8_flags.trace_drumbrake_execution && shadow_stack_ != nullptr) {
          for (size_t i = 0; i < sig->parameter_count(); i++) {
            TracePop();
          }

          for (size_t i = 0; i < sig->return_count(); i++) {
            current_slot_offset +=
                TracePush(sig->GetReturn(i).kind(), current_slot_offset);
          }
        }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
        return ExternalCallResult::EXTERNAL_RETURNED;
      }
      return ExternalCallResult::EXTERNAL_EXCEPTION;
    }
  } else {
    // WasmToJS call.

    // Note that tail calls to host functions do not have to guarantee tail
    // behaviour, so it is ok to recursively allocate C++ stack frames here.

    Handle<Object> object_implicit_arg(entry.implicit_arg(), isolate_);

    // We should not allocate anything in the heap and avoid GCs after we store
    // ref arguments into stack slots.
    DisallowHeapAllocation no_gc;

    uint8_t* fp = reinterpret_cast<uint8_t*>(sp);
    StoreRefArgsIntoStackSlots(fp, ref_stack_fp_offset, sig);
    ExternalCallResult result =
        CallExternalJSFunction(current_code, module_, object_implicit_arg, sig,
                               sp, current_slot_offset);
    if (result == ExternalCallResult::EXTERNAL_RETURNED) {
      StoreRefResultsIntoRefStack(fp, ref_stack_fp_offset, sig);
    }
    return result;
  }
}

// static
int WasmInterpreterRuntime::memory_start_offset() {
  return OFFSET_OF(WasmInterpreterRuntime, memory_start_);
}

// static
int WasmInterpreterRuntime::instruction_table_offset() {
  return OFFSET_OF(WasmInterpreterRuntime, instruction_table_);
}

struct StackHandlerMarker {
  Address next;
  Address padding;
};

void WasmInterpreterRuntime::CallWasmToJSBuiltin(Isolate* isolate,
                                                 Handle<Object> object_ref,
                                                 Address packed_args,
                                                 const FunctionSig* sig) {
  DCHECK(!WasmBytecode::ContainsSimd(sig));
  Handle<Object> callable;
  if (IsWasmImportData(*object_ref)) {
    callable = handle(Cast<WasmImportData>(*object_ref)->callable(), isolate);
  } else {
    callable = object_ref;
    DCHECK(!IsUndefined(*callable));
  }

  // TODO(paolosev@microsoft.com) - Can callable be a JSProxy?
  Handle<Object> js_function = callable;
  while (IsJSBoundFunction(*js_function, isolate_)) {
    if (IsJSBoundFunction(*js_function, isolate_)) {
      js_function = handle(
          Cast<JSBoundFunction>(js_function)->bound_target_function(), isolate);
    }
  }

  if (IsJSProxy(*js_function, isolate_)) {
    do {
      Tagged<HeapObject> target = Cast<JSProxy>(js_function)->target(isolate);
      js_function = Handle<Object>(target, isolate);
    } while (IsJSProxy(*js_function, isolate_));
  }

  if (!IsJSFunction(*js_function, isolate_)) {
    AllowHeapAllocation allow_gc;
    trap_handler::ClearThreadInWasm();

    isolate->set_exception(*isolate_->factory()->NewTypeError(
        MessageTemplate::kWasmTrapJSTypeError));
    return;
  }

  // Save and restore context around invocation and block the
  // allocation of handles without explicit handle scopes.
  SaveContext save(isolate);
  SealHandleScope shs(isolate);

  Address saved_c_entry_fp = *isolate->c_entry_fp_address();
  Address saved_js_entry_sp = *isolate->js_entry_sp_address();
  if (saved_js_entry_sp == kNullAddress) {
    *isolate->js_entry_sp_address() = GetCurrentStackPosition();
  }
  StackHandlerMarker stack_handler;
  stack_handler.next = isolate->thread_local_top()->handler_;
#ifdef V8_USE_ADDRESS_SANITIZER
  stack_handler.padding = GetCurrentStackPosition();
#else
  stack_handler.padding = 0;
#endif
  isolate->thread_local_top()->handler_ =
      reinterpret_cast<Address>(&stack_handler);
  if (trap_handler::IsThreadInWasm()) {
    trap_handler::ClearThreadInWasm();
  }

  {
    RCS_SCOPE(isolate, RuntimeCallCounterId::kJS_Execution);
    Address result = generic_wasm_to_js_interpreter_wrapper_fn_.Call(
        (*js_function).ptr(), packed_args, isolate->isolate_root(), sig,
        saved_c_entry_fp, (*callable).ptr());
    if (result != kNullAddress) {
      isolate->set_exception(Tagged<Object>(result));
      if (trap_handler::IsThreadInWasm()) {
        trap_handler::ClearThreadInWasm();
      }
    } else {
      current_thread_->Run();
      if (!trap_handler::IsThreadInWasm()) {
        trap_handler::SetThreadInWasm();
      }
    }
  }

  isolate->thread_local_top()->handler_ = stack_handler.next;
  if (saved_js_entry_sp == kNullAddress) {
    *isolate->js_entry_sp_address() = saved_js_entry_sp;
  }
  *isolate->c_entry_fp_address() = saved_c_entry_fp;
}

ExternalCallResult WasmInterpreterRuntime::CallExternalJSFunction(
    const uint8_t*& current_code, const WasmModule* module,
    Handle<Object> object_ref, const FunctionSig* sig, uint32_t* sp,
    uint32_t current_stack_slot) {
  // TODO(paolosev@microsoft.com) Cache IsJSCompatibleSignature result?
  if (!IsJSCompatibleSignature(sig)) {
    AllowHeapAllocation allow_gc;
    ClearThreadInWasmScope clear_wasm_flag(isolate_);

    isolate_->Throw(*isolate_->factory()->NewTypeError(
        MessageTemplate::kWasmTrapJSTypeError));
    return ExternalCallResult::EXTERNAL_EXCEPTION;
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    Trace("  => Calling external function\n");
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // Copy the arguments to one buffer.
  CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
  uint32_t* p = sp + WasmBytecode::RetsSizeInSlots(sig);
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    switch (sig->GetParam(i).kind()) {
      case kI32:
        packer.Push(
            base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(p)));
        p += sizeof(int32_t) / kSlotSize;
        break;
      case kI64:
        packer.Push(
            base::ReadUnalignedValue<int64_t>(reinterpret_cast<Address>(p)));
        p += sizeof(int64_t) / kSlotSize;
        break;
      case kF32:
        packer.Push(
            base::ReadUnalignedValue<float>(reinterpret_cast<Address>(p)));
        p += sizeof(float) / kSlotSize;
        break;
      case kF64:
        packer.Push(
            base::ReadUnalignedValue<double>(reinterpret_cast<Address>(p)));
        p += sizeof(double) / kSlotSize;
        break;
      case kRef:
      case kRefNull: {
        Handle<Object> ref =
            base::ReadUnalignedValue<WasmRef>(reinterpret_cast<Address>(p));
        ref = WasmToJSObject(ref);
        packer.Push(*ref);
        p += sizeof(WasmRef) / kSlotSize;
        break;
      }
      case kS128:
      default:
        UNREACHABLE();
    }
  }

  DCHECK_NOT_NULL(current_thread_);
  current_thread_->StopExecutionTimer();
  {
    // If there were Ref values passed as arguments they have already been read
    // in BeginExecution(), so we can re-enable GC.
    AllowHeapAllocation allow_gc;

    CallWasmToJSBuiltin(isolate_, object_ref, packer.argv(), sig);
  }
  current_thread_->StartExecutionTimer();

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    Trace("  => External wasm function returned%s\n",
          isolate_->has_exception() ? " with exception" : "");
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  if (V8_UNLIKELY(isolate_->has_exception())) {
    return ExternalCallResult::EXTERNAL_EXCEPTION;
  }

  // Push return values.
  if (sig->return_count() > 0) {
    packer.Reset();
    for (size_t i = 0; i < sig->return_count(); i++) {
      switch (sig->GetReturn(i).kind()) {
        case kI32:
          base::WriteUnalignedValue<int32_t>(reinterpret_cast<Address>(sp),
                                             packer.Pop<uint32_t>());
          sp += sizeof(uint32_t) / kSlotSize;
          break;
        case kI64:
          base::WriteUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp),
                                              packer.Pop<uint64_t>());
          sp += sizeof(uint64_t) / kSlotSize;
          break;
        case kF32:
          base::WriteUnalignedValue<float>(reinterpret_cast<Address>(sp),
                                           packer.Pop<float>());
          sp += sizeof(float) / kSlotSize;
          break;
        case kF64:
          base::WriteUnalignedValue<double>(reinterpret_cast<Address>(sp),
                                            packer.Pop<double>());
          sp += sizeof(double) / kSlotSize;
          break;
        case kRef:
        case kRefNull:
          // TODO(paolosev@microsoft.com): Handle WasmNull case?
#ifdef V8_COMPRESS_POINTERS
        {
          Address address = packer.Pop<Address>();
          Handle<Object> ref(Tagged<Object>(address), isolate_);
          if (sig->GetReturn(i).value_type_code() == wasm::kFuncRefCode &&
              i::IsNull(*ref, isolate_)) {
            ref = isolate_->factory()->wasm_null();
          }
          ref = JSToWasmObject(ref, sig->GetReturn(i));
          if (isolate_->has_exception()) {
            return ExternalCallResult::EXTERNAL_EXCEPTION;
          }
          base::WriteUnalignedValue<Handle<Object>>(
              reinterpret_cast<Address>(sp), ref);
          sp += sizeof(WasmRef) / kSlotSize;
        }
#else
          CHECK(false);  // Not supported.
#endif  // V8_COMPRESS_POINTERS
        break;
        case kS128:
        default:
          UNREACHABLE();
      }
    }
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  uint32_t return_slot_offset = 0;
  if (v8_flags.trace_drumbrake_execution && shadow_stack_ != nullptr) {
    for (size_t i = 0; i < sig->parameter_count(); i++) {
      TracePop();
    }

    for (size_t i = 0; i < sig->return_count(); i++) {
      return_slot_offset +=
          TracePush(sig->GetReturn(i).kind(), return_slot_offset);
    }
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  return ExternalCallResult::EXTERNAL_RETURNED;
}

Handle<Map> WasmInterpreterRuntime::RttCanon(uint32_t type_index) const {
  Handle<Map> rtt{
      Cast<Map>(
          wasm_trusted_instance_data()->managed_object_maps()->get(type_index)),
      isolate_};
  return rtt;
}

std::pair<Handle<WasmStruct>, const StructType*>
WasmInterpreterRuntime::StructNewUninitialized(uint32_t index) const {
  const StructType* struct_type = module_->struct_type(index);
  Handle<Map> rtt = RttCanon(index);
  return {isolate_->factory()->NewWasmStructUninitialized(struct_type, rtt),
          struct_type};
}

std::pair<Handle<WasmArray>, const ArrayType*>
WasmInterpreterRuntime::ArrayNewUninitialized(uint32_t length,
                                              uint32_t array_index) const {
  const ArrayType* array_type = GetArrayType(array_index);
  if (V8_UNLIKELY(static_cast<int>(length) < 0 ||
                  static_cast<int>(length) >
                      WasmArray::MaxLength(array_type))) {
    return {};
  }

  Handle<Map> rtt = RttCanon(array_index);
  return {
      {isolate_->factory()->NewWasmArrayUninitialized(length, rtt), isolate_},
      array_type};
}

WasmRef WasmInterpreterRuntime::WasmArrayNewSegment(uint32_t array_index,
                                                    uint32_t segment_index,
                                                    uint32_t offset,
                                                    uint32_t length) {
  Handle<Map> rtt = RttCanon(array_index);
  // Call runtime function Runtime_WasmArrayNewSegment. Store the arguments in
  // reverse order and pass a pointer to the first argument, which is the last
  // on the stack.
  //
  // args[args_length] -> |       rtt        |
  //                      |      length      |
  //                      |      offset      |
  //                      |  segment_index   |
  //    first_arg_addr -> | trusted_instance |
  //
  constexpr size_t kArgsLength = 5;
  Address args[kArgsLength] = {rtt->ptr(), IntToSmi(length), IntToSmi(offset),
                               IntToSmi(segment_index),
                               wasm_trusted_instance_data()->ptr()};
  Address* first_arg_addr = &args[kArgsLength - 1];

  // A runtime function can throw, therefore we need to make sure that the
  // current activation is up-to-date, if we need to traverse the call stack.
  current_thread_->SetCurrentFrame(current_frame_);

  Address result =
      Runtime_WasmArrayNewSegment(kArgsLength, first_arg_addr, isolate_);
  if (isolate_->has_exception()) return {};

  return handle(Tagged<Object>(result), isolate_);
}

bool WasmInterpreterRuntime::WasmArrayInitSegment(uint32_t segment_index,
                                                  WasmRef wasm_array,
                                                  uint32_t array_offset,
                                                  uint32_t segment_offset,
                                                  uint32_t length) {
  // Call runtime function Runtime_WasmArrayInitSegment. Store the arguments in
  // reverse order and pass a pointer to the first argument, which is the last
  // on the stack.
  //
  // args[args_length] -> |      length       |
  //                      |  segment_offset   |
  //                      |   array_offset    |
  //                      |    wasm_array     |
  //                      |   segment_index   |
  //    first_arg_addr -> | trusted_instance  |
  //
  constexpr size_t kArgsLength = 6;
  Address args[kArgsLength] = {
      IntToSmi(length),        IntToSmi(segment_offset),
      IntToSmi(array_offset),  (*wasm_array).ptr(),
      IntToSmi(segment_index), wasm_trusted_instance_data()->ptr()};
  Address* first_arg_addr = &args[kArgsLength - 1];

  // A runtime function can throw, therefore we need to make sure that the
  // current activation is up-to-date, if we need to traverse the call stack.
  current_thread_->SetCurrentFrame(current_frame_);

  Runtime_WasmArrayInitSegment(kArgsLength, first_arg_addr, isolate_);
  return (!isolate_->has_exception());
}

bool WasmInterpreterRuntime::WasmArrayCopy(WasmRef dest_wasm_array,
                                           uint32_t dest_index,
                                           WasmRef src_wasm_array,
                                           uint32_t src_index,
                                           uint32_t length) {
  // Call runtime function Runtime_WasmArrayCopy. Store the arguments in reverse
  // order and pass a pointer to the first argument, which is the last on the
  // stack.
  //
  // args[args_length] -> |     length     |
  //                      |   src_index    |
  //                      |   src_array    |
  //                      |   dest_index   |
  //    first_arg_addr -> |   dest_array   |
  //
  constexpr size_t kArgsLength = 5;
  Address args[kArgsLength] = {IntToSmi(length), IntToSmi(src_index),
                               (*src_wasm_array).ptr(), IntToSmi(dest_index),
                               (*dest_wasm_array).ptr()};
  Address* first_arg_addr = &args[kArgsLength - 1];

  // A runtime function can throw, therefore we need to make sure that the
  // current activation is up-to-date, if we need to traverse the call stack.
  current_thread_->SetCurrentFrame(current_frame_);

  Runtime_WasmArrayCopy(kArgsLength, first_arg_addr, isolate_);
  return (!isolate_->has_exception());
}

WasmRef WasmInterpreterRuntime::WasmJSToWasmObject(
    WasmRef extern_ref, ValueType value_type, uint32_t canonical_index) const {
  // Call runtime function Runtime_WasmJSToWasmObject. Store the arguments in
  // reverse order and pass a pointer to the first argument, which is the last
  // on the stack.
  //
  // args[args_length] -> | canonical type index |
  //                      | value_type represent.|
  //    first_arg_addr -> |      extern_ref      |
  //
  constexpr size_t kArgsLength = 3;
  Address args[kArgsLength] = {
      IntToSmi(canonical_index),  // TODO(paolosev@microsoft.com)
      IntToSmi(value_type.raw_bit_field()), (*extern_ref).ptr()};
  Address* first_arg_addr = &args[kArgsLength - 1];

  // A runtime function can throw, therefore we need to make sure that the
  // current activation is up-to-date, if we need to traverse the call stack.
  current_thread_->SetCurrentFrame(current_frame_);

  Address result =
      Runtime_WasmJSToWasmObject(kArgsLength, first_arg_addr, isolate_);
  if (isolate_->has_exception()) return {};

  return handle(Tagged<Object>(result), isolate_);
}

WasmRef WasmInterpreterRuntime::JSToWasmObject(WasmRef extern_ref,
                                               ValueType type) const {
  uint32_t canonical_index = 0;
  if (type.has_index()) {
    canonical_index =
        module_->isorecursive_canonical_type_ids[type.ref_index()];
    type = wasm::ValueType::RefMaybeNull(canonical_index, type.nullability());
  }
  const char* error_message;
  {
    Handle<Object> result;
    if (wasm::JSToWasmObject(isolate_, extern_ref, type, canonical_index,
                             &error_message)
            .ToHandle(&result)) {
      return result;
    }
  }

  {
    // Only in case of exception it can allocate.
    AllowHeapAllocation allow_gc;

    if (v8_flags.wasm_jitless && trap_handler::IsThreadInWasm()) {
      trap_handler::ClearThreadInWasm();
    }
    Tagged<Object> result = isolate_->Throw(*isolate_->factory()->NewTypeError(
        MessageTemplate::kWasmTrapJSTypeError));
    return handle(result, isolate_);
  }
}

WasmRef WasmInterpreterRuntime::WasmToJSObject(WasmRef value) const {
  if (IsWasmFuncRef(*value)) {
    value = handle(Cast<WasmFuncRef>(*value)->internal(isolate_), isolate_);
  }
  if (IsWasmInternalFunction(*value)) {
    Handle<WasmInternalFunction> internal = Cast<WasmInternalFunction>(value);
    return WasmInternalFunction::GetOrCreateExternal(internal);
  }
  if (IsWasmNull(*value)) {
    return handle(ReadOnlyRoots(isolate_).null_value(), isolate_);
  }
  return value;
}

// Implementation similar to Liftoff's SubtypeCheck in
// src\wasm\baseline\liftoff-compiler.cc.
bool WasmInterpreterRuntime::SubtypeCheck(Tagged<Map> rtt,
                                          Tagged<Map> formal_rtt,
                                          uint32_t type_index) const {
  // Constant-time subtyping check: load exactly one candidate RTT from the
  // supertypes list.
  // Step 1: load the WasmTypeInfo.
  Tagged<WasmTypeInfo> type_info = rtt->wasm_type_info();

  // Step 2: check the list's length if needed.
  uint32_t rtt_depth = GetSubtypingDepth(module_, type_index);
  if (rtt_depth >= kMinimumSupertypeArraySize &&
      static_cast<uint32_t>(type_info->supertypes_length()) <= rtt_depth) {
    return false;
  }

  // Step 3: load the candidate list slot into {tmp1}, and compare it.
  Tagged<Object> supertype = type_info->supertypes(rtt_depth);
  if (formal_rtt != supertype) return false;
  return true;
}

// Implementation similar to Liftoff's SubtypeCheck in
// src\wasm\baseline\liftoff-compiler.cc.
bool WasmInterpreterRuntime::SubtypeCheck(const WasmRef obj,
                                          const ValueType obj_type,
                                          const Handle<Map> rtt,
                                          const ValueType rtt_type,
                                          bool null_succeeds) const {
  bool is_cast_from_any = obj_type.is_reference_to(HeapType::kAny);

  // Skip the null check if casting from any and not {null_succeeds}.
  // In that case the instance type check will identify null as not being a
  // wasm object and fail.
  if (obj_type.is_nullable() && (!is_cast_from_any || null_succeeds)) {
    if (obj_type == kWasmExternRef || obj_type == kWasmNullExternRef) {
      if (i::IsNull(*obj, isolate_)) return null_succeeds;
    } else {
      if (i::IsWasmNull(*obj, isolate_)) return null_succeeds;
    }
  }

  // Add Smi check if the source type may store a Smi (i31ref or JS Smi).
  ValueType i31ref = ValueType::Ref(HeapType::kI31);
  // Ref.extern can also contain Smis, however there isn't any type that
  // could downcast to ref.extern.
  DCHECK(!rtt_type.is_reference_to(HeapType::kExtern));
  // Ref.i31 check has its own implementation.
  DCHECK(!rtt_type.is_reference_to(HeapType::kI31));
  if (IsSmi(*obj)) {
    return IsSubtypeOf(i31ref, rtt_type, module_);
  }

  if (!IsHeapObject(*obj)) return false;
  Tagged<Map> obj_map = Cast<HeapObject>(obj)->map();

  if (module_->types[rtt_type.ref_index()].is_final) {
    // In this case, simply check for map equality.
    if (*obj_map != *rtt) {
      return false;
    }
  } else {
    // Check for rtt equality, and if not, check if the rtt is a struct/array
    // rtt.
    if (*obj_map == *rtt) {
      return true;
    }

    if (is_cast_from_any) {
      // Check for map being a map for a wasm object (struct, array, func).
      InstanceType obj_type = obj_map->instance_type();
      if (obj_type < FIRST_WASM_OBJECT_TYPE ||
          obj_type > LAST_WASM_OBJECT_TYPE) {
        return false;
      }
    }

    return SubtypeCheck(obj_map, *rtt, rtt_type.ref_index());
  }

  return true;
}

using TypeChecker = bool (*)(const WasmRef obj);

template <TypeChecker type_checker>
bool AbstractTypeCast(Isolate* isolate, const WasmRef obj,
                      const ValueType obj_type, bool null_succeeds) {
  if (null_succeeds && obj_type.is_nullable() &&
      WasmInterpreterRuntime::IsNull(isolate, obj, obj_type)) {
    return true;
  }
  return type_checker(obj);
}

static bool EqCheck(const WasmRef obj) {
  if (IsSmi(*obj)) {
    return true;
  }
  if (!IsHeapObject(*obj)) return false;
  InstanceType instance_type = Cast<HeapObject>(obj)->map()->instance_type();
  return instance_type >= FIRST_WASM_OBJECT_TYPE &&
         instance_type <= LAST_WASM_OBJECT_TYPE;
}
bool WasmInterpreterRuntime::RefIsEq(const WasmRef obj,
                                     const ValueType obj_type,
                                     bool null_succeeds) const {
  return AbstractTypeCast<&EqCheck>(isolate_, obj, obj_type, null_succeeds);
}

static bool I31Check(const WasmRef obj) { return IsSmi(*obj); }
bool WasmInterpreterRuntime::RefIsI31(const WasmRef obj,
                                      const ValueType obj_type,
                                      bool null_succeeds) const {
  return AbstractTypeCast<&I31Check>(isolate_, obj, obj_type, null_succeeds);
}

static bool StructCheck(const WasmRef obj) {
  if (IsSmi(*obj)) {
    return false;
  }
  if (!IsHeapObject(*obj)) return false;
  InstanceType instance_type = Cast<HeapObject>(obj)->map()->instance_type();
  return instance_type == WASM_STRUCT_TYPE;
}
bool WasmInterpreterRuntime::RefIsStruct(const WasmRef obj,
                                         const ValueType obj_type,
                                         bool null_succeeds) const {
  return AbstractTypeCast<&StructCheck>(isolate_, obj, obj_type, null_succeeds);
}

static bool ArrayCheck(const WasmRef obj) {
  if (IsSmi(*obj)) {
    return false;
  }
  if (!IsHeapObject(*obj)) return false;
  InstanceType instance_type = Cast<HeapObject>(obj)->map()->instance_type();
  return instance_type == WASM_ARRAY_TYPE;
}
bool WasmInterpreterRuntime::RefIsArray(const WasmRef obj,
                                        const ValueType obj_type,
                                        bool null_succeeds) const {
  return AbstractTypeCast<&ArrayCheck>(isolate_, obj, obj_type, null_succeeds);
}

static bool StringCheck(const WasmRef obj) {
  if (IsSmi(*obj)) {
    return false;
  }
  if (!IsHeapObject(*obj)) return false;
  InstanceType instance_type = Cast<HeapObject>(obj)->map()->instance_type();
  return instance_type < FIRST_NONSTRING_TYPE;
}
bool WasmInterpreterRuntime::RefIsString(const WasmRef obj,
                                         const ValueType obj_type,
                                         bool null_succeeds) const {
  return AbstractTypeCast<&StringCheck>(isolate_, obj, obj_type, null_succeeds);
}

void WasmInterpreterRuntime::SetTrap(TrapReason trap_reason, pc_t trap_pc) {
  trap_function_index_ =
      current_frame_.current_function_
          ? current_frame_.current_function_->GetFunctionIndex()
          : 0;
  DCHECK_GE(trap_function_index_, 0);
  DCHECK_LT(trap_function_index_, module_->functions.size());

  trap_pc_ = trap_pc;
  thread()->Trap(trap_reason, trap_function_index_, static_cast<int>(trap_pc_),
                 current_frame_);
}

void WasmInterpreterRuntime::SetTrap(TrapReason trap_reason,
                                     const uint8_t*& code) {
  SetTrap(trap_reason,
          current_frame_.current_function_
              ? current_frame_.current_function_->GetPcFromTrapCode(code)
              : 0);
  RedirectCodeToUnwindHandler(code);
}

void WasmInterpreterRuntime::ResetCurrentHandleScope() {
  current_frame_.ResetHandleScope(isolate_);
}

std::vector<WasmInterpreterStackEntry>
WasmInterpreterRuntime::GetInterpretedStack(Address frame_pointer) const {
  // The current thread can be nullptr if we throw an exception before calling
  // {BeginExecution}.
  if (current_thread_) {
    WasmInterpreterThread::Activation* activation =
        current_thread_->GetActivation(frame_pointer);
    if (activation) {
      return activation->GetStackTrace();
    }

    // DCHECK_GE(trap_function_index_, 0);
    return {{trap_function_index_, static_cast<int>(trap_pc_)}};
  }

  // It is possible to throw before entering a Wasm function, while converting
  // the args from JS to Wasm, with JSToWasmObject.
  return {{0, 0}};
}

int WasmInterpreterRuntime::GetFunctionIndex(Address frame_pointer,
                                             int index) const {
  if (current_thread_) {
    WasmInterpreterThread::Activation* activation =
        current_thread_->GetActivation(frame_pointer);
    if (activation) {
      return activation->GetFunctionIndex(index);
    }
  }
  return -1;
}

void WasmInterpreterRuntime::SetTrapFunctionIndex(int32_t func_index) {
  trap_function_index_ = func_index;
  trap_pc_ = 0;
}

void WasmInterpreterRuntime::PrintStack(uint32_t* sp, RegMode reg_mode,
                                        int64_t r0, double fp0) {
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (tracer_ && tracer_->ShouldTraceFunction(
                     current_frame_.current_function_->GetFunctionIndex())) {
    shadow_stack_->Print(this, sp, current_frame_.current_stack_start_args_,
                         current_frame_.current_stack_start_locals_,
                         current_frame_.current_stack_start_stack_, reg_mode,
                         r0, fp0);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
}

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
InterpreterTracer* WasmInterpreterRuntime::GetTracer() {
  if (tracer_ == nullptr) tracer_.reset(new InterpreterTracer(-1));
  return tracer_.get();
}

void WasmInterpreterRuntime::Trace(const char* format, ...) {
  if (!current_frame_.current_function_) {
    // This can happen when the entry function is an imported JS function.
    return;
  }
  InterpreterTracer* tracer = GetTracer();
  if (tracer->ShouldTraceFunction(
          current_frame_.current_function_->GetFunctionIndex())) {
    va_list arguments;
    va_start(arguments, format);
    base::OS::VFPrint(tracer->file(), format, arguments);
    va_end(arguments);
    tracer->CheckFileSize();
  }
}
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

// static
ModuleWireBytes InterpreterHandle::GetBytes(Tagged<Tuple2> interpreter_object) {
  Tagged<WasmInstanceObject> wasm_instance =
      WasmInterpreterObject::get_wasm_instance(interpreter_object);
  NativeModule* native_module = wasm_instance->module_object()->native_module();
  return ModuleWireBytes{native_module->wire_bytes()};
}

InterpreterHandle::InterpreterHandle(Isolate* isolate,
                                     Handle<Tuple2> interpreter_object)
    : isolate_(isolate),
      module_(WasmInterpreterObject::get_wasm_instance(*interpreter_object)
                  ->module_object()
                  ->module()),
      interpreter_(
          isolate, module_, GetBytes(*interpreter_object),
          handle(WasmInterpreterObject::get_wasm_instance(*interpreter_object),
                 isolate)) {}

inline WasmInterpreterThread::State InterpreterHandle::RunExecutionLoop(
    WasmInterpreterThread* thread, bool called_from_js) {
  // If there were Ref values passed as arguments they have already been read
  // in BeginExecution(), so we can re-enable GC.
  AllowHeapAllocation allow_gc;

  bool finished = false;
  WasmInterpreterThread::State state = thread->state();
  if (state != WasmInterpreterThread::State::RUNNING) {
    return state;
  }

  while (!finished) {
    state = ContinueExecution(thread, called_from_js);
    switch (state) {
      case WasmInterpreterThread::State::FINISHED:
      case WasmInterpreterThread::State::RUNNING:
        // Perfect, just break the switch and exit the loop.
        finished = true;
        break;
      case WasmInterpreterThread::State::TRAPPED: {
        if (!isolate_->has_exception()) {
          // An exception handler was found, keep running the loop.
          if (!trap_handler::IsThreadInWasm()) {
            trap_handler::SetThreadInWasm();
          }
          break;
        }
        thread->Stop();
        [[fallthrough]];
      }
      case WasmInterpreterThread::State::STOPPED:
        // An exception happened, and the current activation was unwound
        // without hitting a local exception handler. All that remains to be
        // done is finish the activation and let the exception propagate.
        DCHECK(isolate_->has_exception());
        return state;  // Either STOPPED or TRAPPED.
      case WasmInterpreterThread::State::EH_UNWINDING: {
        thread->Stop();
        return WasmInterpreterThread::State::STOPPED;
      }
    }
  }
  return state;
}

V8_EXPORT_PRIVATE bool InterpreterHandle::Execute(
    WasmInterpreterThread* thread, Address frame_pointer, uint32_t func_index,
    const std::vector<WasmValue>& argument_values,
    std::vector<WasmValue>& return_values) {
  DCHECK_GT(module()->functions.size(), func_index);
  const FunctionSig* sig = module()->functions[func_index].sig;
  DCHECK_EQ(sig->parameter_count(), argument_values.size());
  DCHECK_EQ(sig->return_count(), return_values.size());

  thread->StartExecutionTimer();
  interpreter_.BeginExecution(thread, func_index, frame_pointer,
                              thread->NextFrameAddress(),
                              thread->NextRefStackOffset(), argument_values);

  WasmInterpreterThread::State state = RunExecutionLoop(thread, true);
  thread->StopExecutionTimer();

  switch (state) {
    case WasmInterpreterThread::RUNNING:
    case WasmInterpreterThread::FINISHED:
      for (unsigned i = 0; i < sig->return_count(); ++i) {
        return_values[i] = interpreter_.GetReturnValue(i);
      }
      return true;

    case WasmInterpreterThread::TRAPPED:
      for (unsigned i = 0; i < sig->return_count(); ++i) {
        return_values[i] = WasmValue(0xDEADBEEF);
      }
      return false;

    case WasmInterpreterThread::STOPPED:
      return false;

    case WasmInterpreterThread::EH_UNWINDING:
      UNREACHABLE();
  }
}

bool InterpreterHandle::Execute(WasmInterpreterThread* thread,
                                Address frame_pointer, uint32_t func_index,
                                uint8_t* interpreter_fp) {
  DCHECK_GT(module()->functions.size(), func_index);

  interpreter_.BeginExecution(thread, func_index, frame_pointer,
                              interpreter_fp);
  WasmInterpreterThread::State state = RunExecutionLoop(thread, false);
  return (state == WasmInterpreterThread::RUNNING ||
          state == WasmInterpreterThread::FINISHED);
}

Handle<WasmInstanceObject> InterpreterHandle::GetInstanceObject() {
  DebuggableStackFrameIterator it(isolate_);
  WasmInterpreterEntryFrame* frame =
      WasmInterpreterEntryFrame::cast(it.frame());
  Handle<WasmInstanceObject> instance_obj(frame->wasm_instance(), isolate_);
  // Check that this is indeed the instance which is connected to this
  // interpreter.
  DCHECK_EQ(this,
            Cast<Managed<InterpreterHandle>>(
                WasmInterpreterObject::get_interpreter_handle(
                    instance_obj->trusted_data(isolate_)->interpreter_object()))
                ->raw());
  return instance_obj;
}

std::vector<WasmInterpreterStackEntry> InterpreterHandle::GetInterpretedStack(
    Address frame_pointer) {
  return interpreter_.GetInterpretedStack(frame_pointer);
}

int InterpreterHandle::GetFunctionIndex(Address frame_pointer,
                                        int index) const {
  return interpreter_.GetFunctionIndex(frame_pointer, index);
}

void InterpreterHandle::SetTrapFunctionIndex(int32_t func_index) {
  interpreter_.SetTrapFunctionIndex(func_index);
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""


```