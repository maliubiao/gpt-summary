Response:
The user is asking for a summary of the provided C++ code snippet from `v8/src/compiler/wasm-compiler.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core function:** The code is a part of the `WasmWrapperGraphBuilder` class, specifically within the `BuildSuspend` method.

2. **Understand the purpose of `BuildSuspend`:**  The name and the code itself strongly suggest this function handles the suspension of WebAssembly execution and the interaction with JavaScript Promises. Keywords like "suspend," "promise," "resume," and "reject" are indicators.

3. **Trace the control flow:**
    * It starts by checking if a `WasmSuspenderObject` is valid. If not, it throws an error.
    * If valid, it retrieves the "resume" and "reject" handlers from the suspender object.
    * It then calls a runtime function (`kPerformPromiseThen`) to attach these handlers to a Promise.
    * It switches to the central JavaScript stack.
    * It calls the provided `call_target` with the suspender object as an argument.
    * It switches back to the WebAssembly stack.
    * It resumes execution with the result of the suspended call.

4. **Identify related functions:** The snippet calls other methods within the `WasmWrapperGraphBuilder` class, such as `BuildCallToRuntimeWithContext`, `TerminateThrow`, `GetBuiltinCallDescriptor`, `GetBuiltinPointerTarget`, `BuildSwitchBackFromCentralStack`, `BuildSwitchToTheCentralStack`. These related functions provide context and indicate broader functionalities of the `wasm-compiler.cc` file.

5. **Infer the context of `wasm-compiler.cc`:** Given the functions being called and the overall logic, it's clear this file is responsible for generating machine code for WebAssembly modules, especially when interacting with JavaScript (e.g., calling JavaScript functions from WebAssembly and handling asynchronous operations).

6. **Relate to JavaScript:** The interaction with Promises directly links this code to JavaScript's asynchronous programming model. The act of "suspending" and "resuming" execution mirrors how Promises handle asynchronous operations.

7. **Consider potential errors:**  The code explicitly checks for a "bad suspender," indicating a common error scenario. This suggests that users might incorrectly create or manage `WasmSuspenderObject` instances.

8. **Address the `.tq` question:** The prompt explicitly asks about `.tq` files. Based on general V8 knowledge, `.tq` files are indeed Torque source files used for defining built-in functions.

9. **Structure the answer:**  Organize the findings into distinct sections as requested by the prompt:
    * Functionality
    * Relation to Torque
    * Relationship to JavaScript (with examples)
    * Code logic reasoning (with assumptions)
    * Common programming errors
    * Overall function of the file

10. **Refine the language:** Use precise language and avoid jargon where possible. Provide concrete examples for JavaScript interaction. Ensure the summary accurately reflects the code's purpose. For example, instead of just saying "it handles suspension", clarify that it does so *using Promises*.

**(Self-Correction during the process):** Initially, I might have focused too narrowly on just the Promise interaction. However, by considering the surrounding code and the mentioned helper functions, I realized that the broader context of generating WebAssembly wrappers for JS interop is crucial. Also, initially, I might have overlooked the explicit mention of `.tq` files and the need to address that point directly. Double-checking the prompt ensured all requirements were met.
Based on the provided C++ code snippet from `v8/src/compiler/wasm-compiler.cc`, here's a breakdown of its functionality:

**Functionality of the `BuildSuspend` method:**

The primary function of this code snippet is to implement the suspension of WebAssembly execution when interacting with JavaScript asynchronous operations, specifically when a WebAssembly function needs to await a JavaScript Promise. It achieves this by:

1. **Checking the `WasmSuspenderObject`:** It verifies if the provided `suspender` object is valid (not null and of the correct type). If it's not, it throws a `BadSuspenderError`.

2. **Retrieving Promise Handlers:** It loads the `on_fulfilled` (resume) and `on_rejected` (reject) handlers from the `WasmSuspenderObject`. These handlers are JavaScript functions that will be called when the Promise resolves or rejects.

3. **Attaching Handlers to the Promise:** It uses `Builtin::kPerformPromiseThen` (which corresponds to the JavaScript `Promise.prototype.then`) to attach the `on_fulfilled` and `on_rejected` handlers to the `value` (which is expected to be a JavaScript Promise). This effectively sets up the asynchronous callback mechanism.

4. **Switching to the Central Stack:** It calls `BuildSwitchToTheCentralStack()` to switch from the WebAssembly stack to the central JavaScript stack. This is necessary because the Promise resolution will happen in the JavaScript environment.

5. **Calling the Target with the Suspender:** It calls the original `call_target` (the WebAssembly function that initiated the suspension) again, passing the `suspender` object as an argument. This call will likely not execute immediately but will be resumed later when the Promise resolves.

6. **Switching Back and Resuming:** After the (eventual) resolution of the Promise, the code switches back from the central stack using `BuildSwitchBackFromCentralStack()` and resumes the WebAssembly execution at the `resume` label, passing the resolved value.

7. **Handling Errors:** If the `WasmSuspenderObject` is invalid, it throws a `BadSuspenderError`.

**Is `v8/src/compiler/wasm-compiler.cc` a Torque source file?**

No, based on the file extension `.cc`, `v8/src/compiler/wasm-compiler.cc` is a standard C++ source file. If it were a Torque source file, it would have the extension `.tq`.

**Relationship to JavaScript and JavaScript Examples:**

This code snippet directly relates to the interaction between WebAssembly and JavaScript's asynchronous programming model using Promises.

**JavaScript Example:**

Imagine a WebAssembly function that needs to fetch data from an external source using a JavaScript `fetch` call (which returns a Promise):

```javascript
// JavaScript
async function fetchData() {
  const response = await fetch('https://example.com/data');
  const data = await response.json();
  return data;
}

// WebAssembly (conceptual)
export function processData(): i32 {
  // ... some logic ...
  const promise = js_fetchData(); // Call the JavaScript fetchData function
  // ... suspend execution until the promise resolves ...
  const data = await promise; //  This is where the suspension logic in C++ comes into play
  // ... process the fetched data ...
  return 0;
}
```

In this scenario:

* `js_fetchData()` would be an imported JavaScript function.
* When the WebAssembly code reaches the point where it needs the result of the Promise, the `BuildSuspend` logic would be invoked.
* `value` in the C++ code would correspond to the Promise returned by `fetchData()`.
* `on_fulfilled` would be a JavaScript function (likely generated by the V8 runtime) that knows how to resume the WebAssembly execution with the resolved data.
* `on_rejected` would be a JavaScript function to handle potential errors during the fetch.

**Code Logic Reasoning (Hypothetical):**

**Hypothetical Input:**

* `value`: A JavaScript `Promise` object that is currently pending.
* `suspender`: A valid `WasmSuspenderObject` containing the necessary resume and reject handlers.
* `old_sp`: The current stack pointer before switching to the central stack.
* `call_descriptor`: A descriptor for the WebAssembly function call.
* `call_target`: The node representing the target WebAssembly function.
* `native_context`: The JavaScript native context.

**Expected Output:**

* The WebAssembly execution is suspended.
* The `Promise.prototype.then` method is called on the `value` Promise, attaching the resume and reject handlers.
* The execution switches to the central JavaScript stack.
* The `call_target` WebAssembly function is called with the `suspender`.
* Eventually (when the Promise resolves), the execution will resume at the `resume` label with the resolved value.

**Common Programming Errors:**

* **Invalid `WasmSuspenderObject`:**  A common error would be passing a null or incorrectly initialized `WasmSuspenderObject`. This is explicitly checked by the code, and a `BadSuspenderError` is thrown. This could happen if the WebAssembly code or the runtime environment doesn't correctly manage the suspender object's lifecycle.

* **Promise not returned:** If the JavaScript function called by WebAssembly doesn't return a Promise when suspension is expected, the behavior will be undefined, and the `PerformPromiseThen` call might fail or have unexpected consequences.

* **Incorrect Promise resolution/rejection:** If the JavaScript Promise doesn't resolve or reject correctly, the WebAssembly execution might not resume as expected, leading to deadlocks or unexpected program behavior.

**归纳一下它的功能 (Summary of its Functionality):**

This code snippet within `v8/src/compiler/wasm-compiler.cc` is responsible for orchestrating the suspension and resumption of WebAssembly execution when a WebAssembly function needs to wait for a JavaScript Promise to resolve. It handles the interaction with the JavaScript Promise mechanism by attaching appropriate handlers and managing the stack switching between the WebAssembly and JavaScript environments. This mechanism is crucial for enabling asynchronous operations and seamless interoperability between WebAssembly and JavaScript.

Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共12部分，请归纳一下它的功能

"""
eTemplate::kWasmTrapSuspendJSFrames))
            .value());
    BuildCallToRuntimeWithContext(Runtime::kThrowWasmError, native_context,
                                  &error, 1);
    TerminateThrow(effect(), control());

    gasm_->Bind(&suspend);
    Node* on_fulfilled = gasm_->Load(
        MachineType::TaggedPointer(), suspender,
        wasm::ObjectAccess::ToTagged(WasmSuspenderObject::kResumeOffset));
    Node* on_rejected = gasm_->Load(
        MachineType::TaggedPointer(), suspender,
        wasm::ObjectAccess::ToTagged(WasmSuspenderObject::kRejectOffset));

    auto* then_call_desc = GetBuiltinCallDescriptor(
        Builtin::kPerformPromiseThen, zone_, StubCallMode::kCallBuiltinPointer);
    Node* then_target =
        gasm_->GetBuiltinPointerTarget(Builtin::kPerformPromiseThen);
    gasm_->Call(then_call_desc, then_target, value, on_fulfilled, on_rejected,
                UndefinedValue(), native_context);

    BuildSwitchBackFromCentralStack(*old_sp);
    Node* resolved = gasm_->Call(call_descriptor, call_target, suspender);
    BuildSwitchToTheCentralStack();
    gasm_->Goto(&resume, resolved, *old_sp);

    gasm_->Bind(&bad_suspender);
    BuildCallToRuntimeWithContext(Runtime::kThrowBadSuspenderError,
                                  native_context, nullptr, 0);
    TerminateThrow(effect(), control());
    gasm_->Bind(&resume);
    *old_sp = resume.PhiAt(1);
    return resume.PhiAt(0);
  }

  Node* BuildSwitchToTheCentralStack() {
    Node* do_switch = gasm_->ExternalConstant(
        ExternalReference::wasm_switch_to_the_central_stack_for_js());
    MachineType reps[] = {MachineType::Pointer(), MachineType::Pointer(),
                          MachineType::Pointer()};
    MachineSignature sig(1, 2, reps);

    Node* central_stack_sp = BuildCCall(
        &sig, do_switch,
        gasm_->ExternalConstant(ExternalReference::isolate_address()),
        gasm_->LoadFramePointer());
    Node* old_sp = gasm_->LoadStackPointer();
    // Temporarily disallow sp-relative offsets.
    gasm_->SetStackPointer(central_stack_sp);
    return old_sp;
  }

  void BuildSwitchBackFromCentralStack(Node* old_sp) {
    auto skip = gasm_->MakeLabel();
    gasm_->GotoIf(gasm_->IntPtrEqual(old_sp, gasm_->IntPtrConstant(0)), &skip);
    Node* do_switch = gasm_->ExternalConstant(
        ExternalReference::wasm_switch_from_the_central_stack_for_js());
    MachineType reps[] = {MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    BuildCCall(&sig, do_switch,
               gasm_->ExternalConstant(ExternalReference::isolate_address()));
    gasm_->SetStackPointer(old_sp);
    gasm_->Goto(&skip);
    gasm_->Bind(&skip);
  }

  Node* BuildSwitchToTheCentralStackIfNeeded() {
    // If the current stack is a secondary stack, switch to the central stack.
    auto end = gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
    Node* isolate_root = BuildLoadIsolateRoot();
    Node* is_on_central_stack_flag =
        gasm_->Load(MachineType::Uint8(), isolate_root,
                    IsolateData::is_on_central_stack_flag_offset());
    gasm_->GotoIf(is_on_central_stack_flag, &end, BranchHint::kTrue,
                  gasm_->IntPtrConstant(0));

    Node* old_sp = BuildSwitchToTheCentralStack();
    gasm_->Goto(&end, old_sp);

    gasm_->Bind(&end);
    return end.PhiAt(0);
  }

  // For wasm-to-js wrappers, parameter 0 is a WasmImportData.
  void BuildWasmToJSWrapper(wasm::ImportCallKind kind, int expected_arity,
                            wasm::Suspend suspend) {
    int wasm_count = static_cast<int>(wrapper_sig_->parameter_count());

    // Build the start and the parameter nodes.
    Start(wasm_count + 3);

    Node* native_context = gasm_->Load(
        MachineType::TaggedPointer(), Param(0),
        wasm::ObjectAccess::ToTagged(WasmImportData::kNativeContextOffset));

    if (kind == wasm::ImportCallKind::kRuntimeTypeError) {
      // =======================================================================
      // === Runtime TypeError =================================================
      // =======================================================================
      BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError,
                                    native_context, nullptr, 0);
      TerminateThrow(effect(), control());
      return;
    }

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      Node* runtime_call = BuildCallToRuntimeWithContext(
          Runtime::kWasmTraceEndExecution, native_context, nullptr, 0);
      SetControl(runtime_call);
    }
#endif  // V8_ENABLE_DRUMBRAKE

    Node* callable_node = gasm_->Load(
        MachineType::TaggedPointer(), Param(0),
        wasm::ObjectAccess::ToTagged(WasmImportData::kCallableOffset));
    Node* old_sp = BuildSwitchToTheCentralStackIfNeeded();

    Node* undefined_node = UndefinedValue();
    Node* call = nullptr;
    // Clear the ThreadInWasm flag.
    BuildModifyThreadInWasmFlag(false);
    switch (kind) {
      // =======================================================================
      // === JS Functions with matching arity ==================================
      // =======================================================================
      case wasm::ImportCallKind::kJSFunctionArityMatch:
        DCHECK_EQ(expected_arity, wasm_count);
        [[fallthrough]];
      case wasm::ImportCallKind::kJSFunctionArityMismatch: {
        int pushed_count = std::max(expected_arity, wasm_count);
        base::SmallVector<Node*, 16> args(pushed_count + 8);
        int pos = 0;

        args[pos++] = callable_node;  // target callable.
        // Determine receiver at runtime.
        args[pos++] =
            BuildReceiverNode(callable_node, native_context, undefined_node);

        // Convert wasm numbers to JS values.
        pos = AddArgumentNodes(base::VectorOf(args), pos, wasm_count,
                               wrapper_sig_, native_context);
        for (int i = wasm_count; i < expected_arity; ++i) {
          args[pos++] = undefined_node;
        }
        args[pos++] = undefined_node;  // new target
        args[pos++] =
            Int32Constant(JSParameterCount(wasm_count));  // argument count
#ifdef V8_ENABLE_LEAPTIERING
        args[pos++] = Int32Constant(kPlaceholderDispatchHandle);
#endif

        Node* function_context =
            gasm_->LoadContextFromJSFunction(callable_node);
        args[pos++] = function_context;
        args[pos++] = effect();
        args[pos++] = control();

        auto call_descriptor = Linkage::GetJSCallDescriptor(
            graph()->zone(), false, pushed_count + 1, CallDescriptor::kNoFlags);
        call = gasm_->Call(call_descriptor, pos, args.begin());
        break;
      }
      // =======================================================================
      // === General case of unknown callable ==================================
      // =======================================================================
      case wasm::ImportCallKind::kUseCallBuiltin: {
        base::SmallVector<Node*, 16> args(wasm_count + 7);
        int pos = 0;
        args[pos++] =
            gasm_->GetBuiltinPointerTarget(Builtin::kCall_ReceiverIsAny);
        args[pos++] = callable_node;
        args[pos++] =
            Int32Constant(JSParameterCount(wasm_count));     // argument count
        args[pos++] = undefined_node;                        // receiver

        auto call_descriptor = Linkage::GetStubCallDescriptor(
            graph()->zone(), CallTrampolineDescriptor{}, wasm_count + 1,
            CallDescriptor::kNoFlags, Operator::kNoProperties,
            StubCallMode::kCallBuiltinPointer);

        // Convert wasm numbers to JS values.
        pos = AddArgumentNodes(base::VectorOf(args), pos, wasm_count,
                               wrapper_sig_, native_context);

        // The native_context is sufficient here, because all kind of callables
        // which depend on the context provide their own context. The context
        // here is only needed if the target is a constructor to throw a
        // TypeError, if the target is a native function, or if the target is a
        // callable JSObject, which can only be constructed by the runtime.
        args[pos++] = native_context;
        args[pos++] = effect();
        args[pos++] = control();
        call = gasm_->Call(call_descriptor, pos, args.begin());
        break;
      }
      default:
        UNREACHABLE();
    }
    // For asm.js the error location can differ depending on whether an
    // exception was thrown in imported JS code or an exception was thrown in
    // the ToNumber builtin that converts the result of the JS code a
    // WebAssembly value. The source position allows asm.js to determine the
    // correct error location. Source position 1 encodes the call to ToNumber,
    // source position 0 encodes the call to the imported JS code.
    SetSourcePosition(call, 0);
    DCHECK_NOT_NULL(call);

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      Node* runtime_call = BuildCallToRuntimeWithContext(
          Runtime::kWasmTraceBeginExecution, native_context, nullptr, 0);
      SetControl(runtime_call);
    }
#endif  // V8_ENABLE_DRUMBRAKE

    if (suspend == wasm::kSuspend) {
      call = BuildSuspend(call, Param(0), &old_sp);
    }

    // Convert the return value(s) back.
    Node* val;
    base::SmallVector<Node*, 8> wasm_values;
    if (wrapper_sig_->return_count() <= 1) {
      val = wrapper_sig_->return_count() == 0
                ? Int32Constant(0)
                : FromJS(call, native_context, wrapper_sig_->GetReturn());
    } else {
      Node* fixed_array = BuildMultiReturnFixedArrayFromIterable(
          wrapper_sig_, call, native_context);
      wasm_values.resize_no_init(wrapper_sig_->return_count());
      for (unsigned i = 0; i < wrapper_sig_->return_count(); ++i) {
        wasm_values[i] = FromJS(gasm_->LoadFixedArrayElementAny(fixed_array, i),
                                native_context, wrapper_sig_->GetReturn(i));
      }
    }
    BuildModifyThreadInWasmFlag(true);

    BuildSwitchBackFromCentralStack(old_sp);
    if (wrapper_sig_->return_count() <= 1) {
      Return(val);
    } else {
      Return(base::VectorOf(wasm_values));
    }

    if (ContainsInt64(wrapper_sig_)) LowerInt64(wasm::kCalledFromWasm);
  }

  void BuildCapiCallWrapper() {
    // Set up the graph start.
    Start(static_cast<int>(wrapper_sig_->parameter_count()) +
          1 /* offset for first parameter index being -1 */ +
          1 /* WasmImportData */);
    // Store arguments on our stack, then align the stack for calling to C.
    int param_bytes = 0;
    for (wasm::CanonicalValueType type : wrapper_sig_->parameters()) {
      param_bytes += type.value_kind_size();
    }
    int return_bytes = 0;
    for (wasm::CanonicalValueType type : wrapper_sig_->returns()) {
      return_bytes += type.value_kind_size();
    }

    int stack_slot_bytes = std::max(param_bytes, return_bytes);
    Node* values = stack_slot_bytes == 0
                       ? mcgraph()->IntPtrConstant(0)
                       : graph()->NewNode(mcgraph()->machine()->StackSlot(
                             stack_slot_bytes, kDoubleAlignment));

    int offset = 0;
    int param_count = static_cast<int>(wrapper_sig_->parameter_count());
    for (int i = 0; i < param_count; ++i) {
      wasm::CanonicalValueType type = wrapper_sig_->GetParam(i);
      // Start from the parameter with index 1 to drop the instance_node.
      // TODO(jkummerow): When a values is a reference type, we should pass it
      // in a GC-safe way, not just as a raw pointer.
      SetEffect(graph()->NewNode(GetSafeStoreOperator(offset, type), values,
                                 Int32Constant(offset), Param(i + 1), effect(),
                                 control()));
      offset += type.value_kind_size();
    }

    Node* function_node = gasm_->Load(
        MachineType::TaggedPointer(), Param(0),
        wasm::ObjectAccess::ToTagged(WasmImportData::kCallableOffset));
    Node* sfi_data = gasm_->LoadFunctionDataFromJSFunction(function_node);
    Node* host_data_foreign =
        gasm_->Load(MachineType::AnyTagged(), sfi_data,
                    wasm::ObjectAccess::ToTagged(
                        WasmCapiFunctionData::kEmbedderDataOffset));

    BuildModifyThreadInWasmFlag(false);
    Node* isolate_root = BuildLoadIsolateRoot();
    Node* fp_value = graph()->NewNode(mcgraph()->machine()->LoadFramePointer());
    gasm_->Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                     kNoWriteBarrier),
                 isolate_root, Isolate::c_entry_fp_offset(), fp_value);

    Node* function = BuildLoadCallTargetFromExportedFunctionData(sfi_data);

    // Parameters: Address host_data_foreign, Address arguments.
    MachineType host_sig_types[] = {
        MachineType::Pointer(), MachineType::Pointer(), MachineType::Pointer()};
    MachineSignature host_sig(1, 2, host_sig_types);
    Node* return_value =
        BuildCCall(&host_sig, function, host_data_foreign, values);

    BuildModifyThreadInWasmFlag(true);

    Node* old_effect = effect();
    Node* exception_branch = graph()->NewNode(
        mcgraph()->common()->Branch(BranchHint::kTrue),
        gasm_->WordEqual(return_value, mcgraph()->IntPtrConstant(0)),
        control());
    SetControl(
        graph()->NewNode(mcgraph()->common()->IfFalse(), exception_branch));
    WasmRethrowExplicitContextDescriptor interface_descriptor;
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        mcgraph()->zone(), interface_descriptor,
        interface_descriptor.GetStackParameterCount(), CallDescriptor::kNoFlags,
        Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
    Node* call_target =
        GetTargetForBuiltinCall(Builtin::kWasmRethrowExplicitContext);
    Node* context = gasm_->Load(
        MachineType::TaggedPointer(), Param(0),
        wasm::ObjectAccess::ToTagged(WasmImportData::kNativeContextOffset));
    gasm_->Call(call_descriptor, call_target, return_value, context);
    TerminateThrow(effect(), control());

    SetEffectControl(old_effect, graph()->NewNode(mcgraph()->common()->IfTrue(),
                                                  exception_branch));
    DCHECK_LT(wrapper_sig_->return_count(), wasm::kV8MaxWasmFunctionReturns);
    size_t return_count = wrapper_sig_->return_count();
    if (return_count == 0) {
      Return(Int32Constant(0));
    } else {
      base::SmallVector<Node*, 8> returns(return_count);
      offset = 0;
      for (size_t i = 0; i < return_count; ++i) {
        wasm::CanonicalValueType type = wrapper_sig_->GetReturn(i);
        Node* val = SetEffect(
            graph()->NewNode(GetSafeLoadOperator(offset, type), values,
                             Int32Constant(offset), effect(), control()));
        returns[i] = val;
        offset += type.value_kind_size();
      }
      Return(base::VectorOf(returns));
    }

    if (ContainsInt64(wrapper_sig_)) LowerInt64(wasm::kCalledFromWasm);
  }

  void BuildJSFastApiCallWrapper(Handle<JSReceiver> callable) {
    // Here 'callable_node' must be equal to 'callable' but we cannot pass a
    // HeapConstant(callable) because WasmCode::Validate() fails with
    // Unexpected mode: FULL_EMBEDDED_OBJECT.
    Node* callable_node = gasm_->Load(
        MachineType::TaggedPointer(), Param(0),
        wasm::ObjectAccess::ToTagged(WasmImportData::kCallableOffset));
    Node* native_context = gasm_->Load(
        MachineType::TaggedPointer(), Param(0),
        wasm::ObjectAccess::ToTagged(WasmImportData::kNativeContextOffset));

    gasm_->Store(StoreRepresentation(mcgraph_->machine()->Is64()
                                         ? MachineRepresentation::kWord64
                                         : MachineRepresentation::kWord32,
                                     WriteBarrierKind::kNoWriteBarrier),
                 gasm_->LoadRootRegister(), Isolate::context_offset(),
                 gasm_->BitcastMaybeObjectToWord(native_context));

    Node* undefined_node = UndefinedValue();

    BuildModifyThreadInWasmFlag(false);

    DirectHandle<JSFunction> target;
    Node* target_node;
    Node* receiver_node;
    Isolate* isolate = callable->GetIsolate();
    if (IsJSBoundFunction(*callable)) {
      target = direct_handle(
          Cast<JSFunction>(
              Cast<JSBoundFunction>(callable)->bound_target_function()),
          isolate);
      target_node =
          gasm_->Load(MachineType::TaggedPointer(), callable_node,
                      wasm::ObjectAccess::ToTagged(
                          JSBoundFunction::kBoundTargetFunctionOffset));
      receiver_node = gasm_->Load(
          MachineType::TaggedPointer(), callable_node,
          wasm::ObjectAccess::ToTagged(JSBoundFunction::kBoundThisOffset));
    } else {
      DCHECK(IsJSFunction(*callable));
      target = Cast<JSFunction>(callable);
      target_node = callable_node;
      receiver_node =
          BuildReceiverNode(callable_node, native_context, undefined_node);
    }

    Tagged<SharedFunctionInfo> shared = target->shared();
    Tagged<FunctionTemplateInfo> api_func_data = shared->api_func_data();
    const Address c_address = api_func_data->GetCFunction(isolate, 0);
    const v8::CFunctionInfo* c_signature =
        api_func_data->GetCSignature(target->GetIsolate(), 0);

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    Address c_functions[] = {c_address};
    const v8::CFunctionInfo* const c_signatures[] = {c_signature};
    target->GetIsolate()->simulator_data()->RegisterFunctionsAndSignatures(
        c_functions, c_signatures, 1);
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

    Node* shared_function_info = gasm_->LoadSharedFunctionInfo(target_node);
    Node* function_template_info =
        gasm_->Load(MachineType::TaggedPointer(), shared_function_info,
                    wasm::ObjectAccess::ToTagged(
                        SharedFunctionInfo::kUntrustedFunctionDataOffset));
    Node* api_data_argument =
        gasm_->Load(MachineType::TaggedPointer(), function_template_info,
                    wasm::ObjectAccess::ToTagged(
                        FunctionTemplateInfo::kCallbackDataOffset));

    FastApiCallFunction c_function{c_address, c_signature};
    Node* call = fast_api_call::BuildFastApiCall(
        target->GetIsolate(), graph(), gasm_.get(), c_function,
        api_data_argument,
        // Load and convert parameters passed to C function
        [this, c_signature, receiver_node](int param_index,
                                           GraphAssemblerLabel<0>*) {
          if (param_index == 0) {
            return gasm_->AdaptLocalArgument(receiver_node);
          }
          switch (c_signature->ArgumentInfo(param_index).GetType()) {
            case CTypeInfo::Type::kV8Value:
              return gasm_->AdaptLocalArgument(Param(param_index));
            default:
              return Param(param_index);
          }
        },
        // Convert return value (no conversion needed for wasm)
        [](const CFunctionInfo* signature, Node* c_return_value) {
          return c_return_value;
        },
        [](Node* options_stack_slot) {},
        // Generate fallback slow call if fast call fails
        [this, callable_node, native_context, receiver_node]() -> Node* {
          int wasm_count = static_cast<int>(wrapper_sig_->parameter_count());
          base::SmallVector<Node*, 16> args(wasm_count + 7);
          int pos = 0;
          args[pos++] =
              gasm_->GetBuiltinPointerTarget(Builtin::kCall_ReceiverIsAny);
          args[pos++] = callable_node;
          args[pos++] =
              Int32Constant(JSParameterCount(wasm_count));  // argument count
          args[pos++] = receiver_node;                      // receiver

          auto call_descriptor = Linkage::GetStubCallDescriptor(
              graph()->zone(), CallTrampolineDescriptor{}, wasm_count + 1,
              CallDescriptor::kNoFlags, Operator::kNoProperties,
              StubCallMode::kCallBuiltinPointer);

          // Convert wasm numbers to JS values.
          pos = AddArgumentNodes(base::VectorOf(args), pos, wasm_count,
                                 wrapper_sig_, native_context);

          // The native_context is sufficient here, because all kind of
          // callables which depend on the context provide their own context.
          // The context here is only needed if the target is a constructor to
          // throw a TypeError, if the target is a native function, or if the
          // target is a callable JSObject, which can only be constructed by the
          // runtime.
          args[pos++] = native_context;
          args[pos++] = effect();
          args[pos++] = control();

          DCHECK_EQ(pos, args.size());
          Node* call = gasm_->Call(call_descriptor, pos, args.begin());
          return wrapper_sig_->return_count() == 0
                     ? Int32Constant(0)
                     : FromJS(call, native_context, wrapper_sig_->GetReturn(),
                              nullptr);
        });

    BuildModifyThreadInWasmFlag(true);

    Return(call);
  }

  void BuildCWasmEntry() {
    // +1 offset for first parameter index being -1.
    Start(CWasmEntryParameters::kNumParameters + 1);

    Node* code_entry = Param(CWasmEntryParameters::kCodeEntry);
    Node* object_ref = Param(CWasmEntryParameters::kObjectRef);
    Node* arg_buffer = Param(CWasmEntryParameters::kArgumentsBuffer);
    Node* c_entry_fp = Param(CWasmEntryParameters::kCEntryFp);

    Node* fp_value = graph()->NewNode(mcgraph()->machine()->LoadFramePointer());
    gasm_->Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                     kNoWriteBarrier),
                 fp_value, TypedFrameConstants::kFirstPushedFrameValueOffset,
                 c_entry_fp);

    int wasm_arg_count = static_cast<int>(wrapper_sig_->parameter_count());
    base::SmallVector<Node*, 16> args(wasm_arg_count + 4);

    int pos = 0;
    args[pos++] = code_entry;
    args[pos++] = gasm_->LoadTrustedDataFromInstanceObject(object_ref);

    int offset = 0;
    for (wasm::CanonicalValueType type : wrapper_sig_->parameters()) {
      Node* arg_load = SetEffect(
          graph()->NewNode(GetSafeLoadOperator(offset, type), arg_buffer,
                           Int32Constant(offset), effect(), control()));
      args[pos++] = arg_load;
      offset += type.value_kind_size();
    }

    args[pos++] = effect();
    args[pos++] = control();

    // Call the wasm code.
    auto call_descriptor =
        GetWasmCallDescriptor(mcgraph()->zone(), wrapper_sig_);

    DCHECK_EQ(pos, args.size());
    Node* call = gasm_->Call(call_descriptor, pos, args.begin());

    Node* if_success = graph()->NewNode(mcgraph()->common()->IfSuccess(), call);
    Node* if_exception =
        graph()->NewNode(mcgraph()->common()->IfException(), call, call);

    // Handle exception: return it.
    SetEffectControl(if_exception);
    Return(if_exception);

    // Handle success: store the return value(s).
    SetEffectControl(call, if_success);
    pos = 0;
    offset = 0;
    for (wasm::CanonicalValueType type : wrapper_sig_->returns()) {
      Node* value = wrapper_sig_->return_count() == 1
                        ? call
                        : graph()->NewNode(mcgraph()->common()->Projection(pos),
                                           call, control());
      SetEffect(graph()->NewNode(GetSafeStoreOperator(offset, type), arg_buffer,
                                 Int32Constant(offset), value, effect(),
                                 control()));
      offset += type.value_kind_size();
      pos++;
    }

    Return(mcgraph()->IntPtrConstant(0));

    if (mcgraph()->machine()->Is32() && ContainsInt64(wrapper_sig_)) {
      // These correspond to {sig_types[]} in {CompileCWasmEntry}.
      MachineRepresentation sig_reps[] = {
          MachineType::PointerRepresentation(),  // return value
          MachineType::PointerRepresentation(),  // target
          MachineRepresentation::kTagged,        // object_ref
          MachineType::PointerRepresentation(),  // argv
          MachineType::PointerRepresentation()   // c_entry_fp
      };
      Signature<MachineRepresentation> c_entry_sig(1, 4, sig_reps);
      Int64Lowering r(mcgraph()->graph(), mcgraph()->machine(),
                      mcgraph()->common(), gasm_->simplified(),
                      mcgraph()->zone(), &c_entry_sig);
      r.LowerGraph();
    }
  }

 private:
  SetOncePointer<const Operator> int32_to_heapnumber_operator_;
  SetOncePointer<const Operator> tagged_non_smi_to_int32_operator_;
  SetOncePointer<const Operator> float32_to_number_operator_;
  SetOncePointer<const Operator> float64_to_number_operator_;
  SetOncePointer<const Operator> tagged_to_float64_operator_;
};

}  // namespace

void BuildInlinedJSToWasmWrapper(Zone* zone, MachineGraph* mcgraph,
                                 const wasm::CanonicalSig* signature,
                                 Isolate* isolate,
                                 compiler::SourcePositionTable* spt,
                                 Node* frame_state, bool set_in_wasm_flag) {
  WasmWrapperGraphBuilder builder(zone, mcgraph, signature,
                                  WasmGraphBuilder::kJSFunctionAbiMode, isolate,
                                  spt);
  builder.BuildJSToWasmWrapper(false, frame_state, set_in_wasm_flag);
}

std::unique_ptr<OptimizedCompilationJob> NewJSToWasmCompilationJob(
    Isolate* isolate, const wasm::CanonicalSig* sig) {
  std::unique_ptr<char[]> debug_name = WasmExportedFunction::GetDebugName(sig);
  if (v8_flags.turboshaft_wasm_wrappers) {
    return Pipeline::NewWasmTurboshaftWrapperCompilationJob(
        isolate, sig,
        wasm::WrapperCompilationInfo{CodeKind::JS_TO_WASM_FUNCTION},
        std::move(debug_name), WasmAssemblerOptions());
  } else {
    std::unique_ptr<Zone> zone = std::make_unique<Zone>(
        wasm::GetWasmEngine()->allocator(), ZONE_NAME, kCompressGraphZone);
    int params = static_cast<int>(sig->parameter_count());
    CallDescriptor* incoming = Linkage::GetJSCallDescriptor(
        zone.get(), false, params + 1, CallDescriptor::kNoFlags);

    //----------------------------------------------------------------------------
    // Create the Graph.
    //----------------------------------------------------------------------------
    Graph* graph = zone->New<Graph>(zone.get());
    CommonOperatorBuilder* common =
        zone->New<CommonOperatorBuilder>(zone.get());
    MachineOperatorBuilder* machine = zone->New<MachineOperatorBuilder>(
        zone.get(), MachineType::PointerRepresentation(),
        InstructionSelector::SupportedMachineOperatorFlags(),
        InstructionSelector::AlignmentRequirements());
    MachineGraph* mcgraph = zone->New<MachineGraph>(graph, common, machine);

    WasmWrapperGraphBuilder builder(zone.get(), mcgraph, sig,
                                    WasmGraphBuilder::kJSFunctionAbiMode,
                                    isolate, nullptr);
    builder.BuildJSToWasmWrapper();

    //----------------------------------------------------------------------------
    // Create the compilation job.
    //----------------------------------------------------------------------------
    return Pipeline::NewWasmHeapStubCompilationJob(
        isolate, incoming, std::move(zone), graph,
        CodeKind::JS_TO_WASM_FUNCTION, std::move(debug_name),
        WasmAssemblerOptions());
  }
}

namespace {

wasm::WasmOpcode GetMathIntrinsicOpcode(wasm::ImportCallKind kind,
                                        const char** name_ptr) {
#define CASE(name)                          \
  case wasm::ImportCallKind::k##name:       \
    *name_ptr = "WasmMathIntrinsic:" #name; \
    return wasm::kExpr##name
  switch (kind) {
    CASE(F64Acos);
    CASE(F64Asin);
    CASE(F64Atan);
    CASE(F64Cos);
    CASE(F64Sin);
    CASE(F64Tan);
    CASE(F64Exp);
    CASE(F64Log);
    CASE(F64Atan2);
    CASE(F64Pow);
    CASE(F64Ceil);
    CASE(F64Floor);
    CASE(F64Sqrt);
    CASE(F64Min);
    CASE(F64Max);
    CASE(F64Abs);
    CASE(F32Min);
    CASE(F32Max);
    CASE(F32Abs);
    CASE(F32Ceil);
    CASE(F32Floor);
    CASE(F32Sqrt);
    CASE(F32ConvertF64);
    default:
      UNREACHABLE();
  }
#undef CASE
}

MachineGraph* CreateCommonMachineGraph(Zone* zone) {
  return zone->New<MachineGraph>(
      zone->New<Graph>(zone), zone->New<CommonOperatorBuilder>(zone),
      zone->New<MachineOperatorBuilder>(
          zone, MachineType::PointerRepresentation(),
          InstructionSelector::SupportedMachineOperatorFlags(),
          InstructionSelector::AlignmentRequirements()));
}

wasm::WasmCompilationResult CompileWasmMathIntrinsic(
    wasm::ImportCallKind kind, const wasm::CanonicalSig* sig) {
  DCHECK_EQ(1, sig->return_count());

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.CompileWasmMathIntrinsic");

  Zone zone(wasm::GetWasmEngine()->allocator(), ZONE_NAME, kCompressGraphZone);

  // Compile a Wasm function with a single bytecode and let TurboFan
  // generate either inlined machine code or a call to a helper.
  SourcePositionTable* source_positions = nullptr;
  MachineGraph* mcgraph = CreateCommonMachineGraph(&zone);

  WasmGraphBuilder builder(
      nullptr, mcgraph->zone(), mcgraph, nullptr /* function_sig */,
      source_positions, WasmGraphBuilder::kWasmImportDataMode,
      nullptr /* isolate */, wasm::WasmEnabledFeatures::All(), sig);

  // Set up the graph start.
  builder.Start(static_cast<int>(sig->parameter_count() + 1 + 1));

  // Generate either a unop or a binop.
  Node* node = nullptr;
  const char* debug_name = "WasmMathIntrinsic";
  auto opcode = GetMathIntrinsicOpcode(kind, &debug_name);
  switch (sig->parameter_count()) {
    case 1:
      node = builder.Unop(opcode, builder.Param(1));
      break;
    case 2:
      node = builder.Binop(opcode, builder.Param(1), builder.Param(2));
      break;
    default:
      UNREACHABLE();
  }

  builder.Return(node);

  // Run the compiler pipeline to generate machine code.
  auto call_descriptor = GetWasmCallDescriptor(&zone, sig);
  if (mcgraph->machine()->Is32()) {
    call_descriptor = GetI32WasmCallDescriptor(&zone, call_descriptor);
  }

  // The code does not call to JS, but conceptually it is an import wrapper,
  // hence use {WASM_TO_JS_FUNCTION} here.
  // TODO(wasm): Rename this to {WASM_IMPORT_CALL}?
  return Pipeline::GenerateCodeForWasmNativeStub(
      call_descriptor, mcgraph, CodeKind::WASM_TO_JS_FUNCTION, debug_name,
      WasmStubAssemblerOptions(), source_positions);
}

}  // namespace

wasm::WasmCompilationResult CompileWasmImportCallWrapper(
    wasm::ImportCallKind kind, const wasm::CanonicalSig* sig,
    bool source_positions, int expected_arity, wasm::Suspend suspend) {
  DCHECK_NE(wasm::ImportCallKind::kLinkError, kind);
  DCHECK_NE(wasm::ImportCallKind::kWasmToWasm, kind);
  DCHECK_NE(wasm::ImportCallKind::kWasmToJSFastApi, kind);

  // Check for math intrinsics first.
  if (v8_flags.wasm_math_intrinsics &&
      kind >= wasm::ImportCallKind::kFirstMathIntrinsic &&
      kind <= wasm::ImportCallKind::kLastMathIntrinsic) {
    // TODO(thibaudm): Port to Turboshaft.
    return CompileWasmMathIntrinsic(kind, sig);
  }

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.CompileWasmImportCallWrapper");
  base::TimeTicks start_time;
  if (V8_UNLIKELY(v8_flags.trace_wasm_compilation_times)) {
    start_time = base::TimeTicks::Now();
  }

  // Build a name in the form "wasm-to-js-<kind>-<signature>".
  constexpr size_t kMaxNameLen = 128;
  char func_name[kMaxNameLen];
  int name_prefix_len = SNPrintF(base::VectorOf(func_name, kMaxNameLen),
                                 "wasm-to-js-%d-", static_cast<int>(kind));
  PrintSignature(base::VectorOf(func_name, kMaxNameLen) + name_prefix_len, sig,
                 '-');

  auto compile_with_turboshaft = [&]() {
    return Pipeline::GenerateCodeForWasmNativeStubFromTurboshaft(
        sig,
        wasm::WrapperCompilationInfo{CodeKind::WASM_TO_JS_FUNCTION, kind,
                                     expected_arity, suspend},
        func_name, WasmStubAssemblerOptions(), nullptr);
  };
  auto compile_with_turbofan = [&]() {
    //--------------------------------------------------------------------------
    // Create the Graph
    //------------------------------------------------------------------
"""


```