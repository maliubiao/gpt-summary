Response: The user wants a summary of the C++ code in `v8/src/compiler/wasm-compiler.cc`.
The file seems to be responsible for compiling WebAssembly code using TurboFan, V8's optimizing compiler. It likely handles the creation of wrappers for calling between JavaScript and WebAssembly, as well as for calling C functions from WebAssembly.

Here's a breakdown of the code snippets and their functions:

- **Suspension and Central Stack:** The code deals with suspending WebAssembly execution and switching to the central JavaScript stack. This suggests it handles asynchronous operations or interactions with JavaScript promises.
- **`BuildWasmToJSWrapper`:** This function builds wrappers for calling JavaScript functions from WebAssembly. It handles different scenarios like matching or mismatching argument counts and the general case of unknown callables.
- **`BuildCapiCallWrapper`:** This function builds wrappers for calling C functions from WebAssembly (C-API). It involves marshalling arguments and return values between WebAssembly and C.
- **`BuildJSFastApiCallWrapper`:** This function seems to optimize calls to JavaScript functions that are part of V8's Fast API.
- **`BuildCWasmEntry`:** This function builds an entry point for calling WebAssembly functions from C.
- **`BuildInlinedJSToWasmWrapper`:** Builds wrappers for calling WebAssembly from JavaScript.
- **`NewJSToWasmCompilationJob`:** Creates a compilation job for compiling JavaScript-to-WebAssembly wrappers.
- **`CompileWasmMathIntrinsic`:** Compiles wrappers for WebAssembly's built-in math functions.
- **`CompileWasmImportCallWrapper`:**  Compiles general import call wrappers from WebAssembly to JavaScript.
- **`CompileWasmCapiCallWrapper`:** Compiles wrappers for calling C functions from WebAssembly.
- **`CompileWasmJSFastCallWrapper`:** Compiles optimized wrappers for calling JavaScript functions via the Fast API.
- **`CompileCWasmEntry`:** Compiles the C-to-WebAssembly entry point.
- **`ExecuteTurbofanWasmCompilation`:** This function appears to be the main entry point for compiling WebAssembly functions using TurboFan. It involves building the graph and running the compilation pipeline.

The file's primary role is to bridge the gap between WebAssembly and JavaScript (and C), handling the necessary conversions and call mechanisms.
这个C++源代码文件 `v8/src/compiler/wasm-compiler.cc` 的功能是**实现 WebAssembly 代码的编译，特别是生成用于在 WebAssembly 和 JavaScript 之间进行互操作的桥接代码（wrappers）**。 这是该文件的第 6 部分，表明之前的部分也涉及 WebAssembly 编译的不同方面。

**主要功能归纳如下：**

1. **构建 WebAssembly 到 JavaScript 的调用桥接 (Wasm-to-JS Wrappers):**
   - 针对不同类型的 JavaScript 函数调用（例如，参数数量匹配、参数数量不匹配、通用的可调用对象）生成优化的调用代码。
   - 处理 WebAssembly 执行的挂起和恢复，以及与 JavaScript Promise 的交互。
   - 负责将 WebAssembly 的数值类型转换为 JavaScript 的值类型，并将 JavaScript 的返回值转换回 WebAssembly 的类型。
   - 可以生成用于快速调用的特定优化版本。

2. **构建 JavaScript 到 WebAssembly 的调用桥接 (JS-to-Wasm Wrappers):**
   - 负责将 JavaScript 的值类型转换为 WebAssembly 的数值类型，并将 WebAssembly 的返回值转换回 JavaScript 的类型。

3. **构建 WebAssembly 到 C 的调用桥接 (Wasm-to-C Wrappers, C-API):**
   - 允许 WebAssembly 代码调用 C 函数。
   - 负责参数和返回值的跨语言传递，包括内存管理和类型转换。

4. **构建 C 到 WebAssembly 的调用入口 (C-Wasm Entry):**
   - 提供一个 C 函数入口点，用于从 C 代码调用编译后的 WebAssembly 函数。
   - 处理参数传递和返回值处理。

5. **处理 WebAssembly 内建数学函数的编译:**
   - 针对 WebAssembly 的 `Math.*` 内建函数生成高效的调用代码。

6. **利用 TurboFan 进行 WebAssembly 代码的优化编译:**
   - 将 WebAssembly 字节码转换为 TurboFan 的中间表示 (IR)。
   - 利用 TurboFan 的优化流水线生成高性能的机器码。

**与 JavaScript 的关系及 JavaScript 示例:**

该文件是 V8 引擎中 WebAssembly 功能的核心部分，它直接影响了 JavaScript 如何与 WebAssembly 模块进行交互。

**JavaScript 示例 1: 调用 WebAssembly 导出的函数**

假设有一个 WebAssembly 模块 `wasmModule`，它导出一个名为 `add` 的函数：

```javascript
const wasmInstance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出 WebAssembly 函数的返回值
```

`v8/src/compiler/wasm-compiler.cc` 中生成的 "JS-to-Wasm Wrappers" 就负责处理 `wasmInstance.exports.add(5, 10)` 这个调用。它会将 JavaScript 的数字 `5` 和 `10` 转换为 WebAssembly 期望的类型，调用 WebAssembly 的 `add` 函数，并将 WebAssembly 的返回值转换回 JavaScript 的数字。

**JavaScript 示例 2: 调用 JavaScript 导入的函数**

假设 WebAssembly 模块导入了一个名为 `log` 的 JavaScript 函数：

```javascript
// JavaScript 代码
function log(message) {
  console.log("From JS:", message);
}

const importObject = {
  env: {
    log: log
  }
};

const wasmInstance = await WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject);
// WebAssembly 代码中会调用导入的 log 函数
```

当 WebAssembly 代码调用导入的 `log` 函数时，`v8/src/compiler/wasm-compiler.cc` 中生成的 "Wasm-to-JS Wrappers" 就负责处理这个调用。它会将 WebAssembly 传递的参数（例如字符串的内存地址和长度）转换为 JavaScript 可以理解的类型，然后调用 JavaScript 的 `log` 函数。

**代码片段分析:**

你提供的代码片段主要涉及 **WebAssembly 执行的挂起和恢复，以及与 JavaScript Promise 的交互**。

- **`BuildSuspend` 函数:**  当 WebAssembly 代码需要暂停执行（例如，等待异步操作完成）时，会调用此函数。
    - 它创建了一个 `WasmSuspenderObject`。
    - 将当前执行状态保存到该对象中。
    - 调用 JavaScript 的 `PerformPromiseThen` 内建函数，创建一个 Promise，当 Promise resolve 或 reject 时，WebAssembly 的执行会恢复。
    - `BuildSwitchToTheCentralStack` 和 `BuildSwitchBackFromCentralStack` 函数用于在 WebAssembly 的栈和 JavaScript 的栈之间切换。

这段代码表明 `v8/src/compiler/wasm-compiler.cc` 不仅处理同步的函数调用，还处理了 WebAssembly 与 JavaScript 异步操作的集成，例如使用 `async`/`await` 或 Promise 的场景。

总而言之，`v8/src/compiler/wasm-compiler.cc` 是 V8 引擎中连接 WebAssembly 和 JavaScript 世界的关键组件，负责生成高性能的桥接代码，使得这两种技术能够无缝地协同工作。

Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共6部分，请归纳一下它的功能

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
    //--------------------------------------------------------------------------
    Zone zone(wasm::GetWasmEngine()->allocator(), ZONE_NAME,
              kCompressGraphZone);
    Graph* graph = zone.New<Graph>(&zone);
    CommonOperatorBuilder* common = zone.New<CommonOperatorBuilder>(&zone);
    MachineOperatorBuilder* machine = zone.New<MachineOperatorBuilder>(
        &zone, MachineType::PointerRepresentation(),
        InstructionSelector::SupportedMachineOperatorFlags(),
        InstructionSelector::AlignmentRequirements());
    MachineGraph* mcgraph = zone.New<MachineGraph>(graph, common, machine);

    SourcePositionTable* source_position_table =
        source_positions ? zone.New<SourcePositionTable>(graph) : nullptr;

    WasmWrapperGraphBuilder builder(&zone, mcgraph, sig,
                                    WasmGraphBuilder::kWasmImportDataMode,
                                    nullptr, source_position_table);
    builder.BuildWasmToJSWrapper(kind, expected_arity, suspend);

    // Schedule and compile to machine code.
    CallDescriptor* incoming =
        GetWasmCallDescriptor(&zone, sig, WasmCallKind::kWasmImportWrapper);
    if (machine->Is32()) {
      incoming = GetI32WasmCallDescriptor(&zone, incoming);
    }
    return Pipeline::GenerateCodeForWasmNativeStub(
        incoming, mcgraph, CodeKind::WASM_TO_JS_FUNCTION, func_name,
        WasmStubAssemblerOptions(), source_position_table);
  };

  auto result = v8_flags.turboshaft_wasm_wrappers ? compile_with_turboshaft()
                                                  : compile_with_turbofan();
  if (V8_UNLIKELY(v8_flags.trace_wasm_compilation_times)) {
    base::TimeDelta time = base::TimeTicks::Now() - start_time;
    int codesize = result.code_desc.body_size();
    StdoutStream{} << "Compiled WasmToJS wrapper " << func_name << ", took "
                   << time.InMilliseconds() << " ms; codesize " << codesize
                   << std::endl;
  }

  return result;
}

wasm::WasmCompilationResult CompileWasmCapiCallWrapper(
    const wasm::CanonicalSig* sig) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.CompileWasmCapiFunction");
  const char* debug_name = "WasmCapiCall";

  auto compile_with_turboshaft = [&]() {
    return Pipeline::GenerateCodeForWasmNativeStubFromTurboshaft(
        sig, wasm::WrapperCompilationInfo{CodeKind::WASM_TO_CAPI_FUNCTION},
        debug_name, WasmStubAssemblerOptions(), nullptr);
  };

  auto compile_with_turbofan = [&]() {
    Zone zone(wasm::GetWasmEngine()->allocator(), ZONE_NAME,
              kCompressGraphZone);

    SourcePositionTable* source_positions = nullptr;
    MachineGraph* mcgraph = CreateCommonMachineGraph(&zone);

    WasmWrapperGraphBuilder builder(&zone, mcgraph, sig,
                                    WasmGraphBuilder::kWasmImportDataMode,
                                    nullptr, source_positions);

    builder.BuildCapiCallWrapper();

    // Run the compiler pipeline to generate machine code.
    CallDescriptor* call_descriptor =
        GetWasmCallDescriptor(&zone, sig, WasmCallKind::kWasmCapiFunction);
    if (mcgraph->machine()->Is32()) {
      call_descriptor = GetI32WasmCallDescriptor(&zone, call_descriptor);
    }

    return Pipeline::GenerateCodeForWasmNativeStub(
        call_descriptor, mcgraph, CodeKind::WASM_TO_CAPI_FUNCTION, debug_name,
        WasmStubAssemblerOptions(), source_positions);
  };
  return v8_flags.turboshaft_wasm_wrappers ? compile_with_turboshaft()
                                           : compile_with_turbofan();
}

bool IsFastCallSupportedSignature(const v8::CFunctionInfo* sig) {
  return fast_api_call::CanOptimizeFastSignature(sig);
}

wasm::WasmCompilationResult CompileWasmJSFastCallWrapper(
    const wasm::CanonicalSig* sig, Handle<JSReceiver> callable) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.CompileWasmJSFastCallWrapper");

  Zone zone(wasm::GetWasmEngine()->allocator(), ZONE_NAME, kCompressGraphZone);
  SourcePositionTable* source_positions = nullptr;
  MachineGraph* mcgraph = CreateCommonMachineGraph(&zone);

  WasmWrapperGraphBuilder builder(&zone, mcgraph, sig,
                                  WasmGraphBuilder::kWasmImportDataMode,
                                  nullptr, source_positions);

  // Set up the graph start.
  int param_count = static_cast<int>(sig->parameter_count()) +
                    1 /* offset for first parameter index being -1 */ +
                    1 /* Wasm instance */ + 1 /* kExtraCallableParam */;
  builder.Start(param_count);
  builder.BuildJSFastApiCallWrapper(callable);

  // Run the compiler pipeline to generate machine code.
  CallDescriptor* call_descriptor =
      GetWasmCallDescriptor(&zone, sig, WasmCallKind::kWasmImportWrapper);
  if (mcgraph->machine()->Is32()) {
    call_descriptor = GetI32WasmCallDescriptor(&zone, call_descriptor);
  }

  const char* debug_name = "WasmJSFastApiCall";
  wasm::WasmCompilationResult result = Pipeline::GenerateCodeForWasmNativeStub(
      call_descriptor, mcgraph, CodeKind::WASM_TO_JS_FUNCTION, debug_name,
      WasmStubAssemblerOptions(), source_positions);
  return result;
}

Handle<Code> CompileCWasmEntry(Isolate* isolate,
                               const wasm::CanonicalSig* sig) {
  DCHECK(!v8_flags.wasm_jitless);

  std::unique_ptr<Zone> zone = std::make_unique<Zone>(
      isolate->allocator(), ZONE_NAME, kCompressGraphZone);
  Graph* graph = zone->New<Graph>(zone.get());
  CommonOperatorBuilder* common = zone->New<CommonOperatorBuilder>(zone.get());
  MachineOperatorBuilder* machine = zone->New<MachineOperatorBuilder>(
      zone.get(), MachineType::PointerRepresentation(),
      InstructionSelector::SupportedMachineOperatorFlags(),
      InstructionSelector::AlignmentRequirements());
  MachineGraph* mcgraph = zone->New<MachineGraph>(graph, common, machine);

  WasmWrapperGraphBuilder builder(zone.get(), mcgraph, sig,
                                  WasmGraphBuilder::kNoSpecialParameterMode,
                                  nullptr, nullptr);
  builder.BuildCWasmEntry();

  // Schedule and compile to machine code.
  MachineType sig_types[] = {MachineType::Pointer(),    // return
                             MachineType::Pointer(),    // target
                             MachineType::AnyTagged(),  // object_ref
                             MachineType::Pointer(),    // argv
                             MachineType::Pointer()};   // c_entry_fp
  MachineSignature incoming_sig(1, 4, sig_types);
  // Traps need the root register, for TailCallRuntime to call
  // Runtime::kThrowWasmError.
  CallDescriptor::Flags flags = CallDescriptor::kInitializeRootRegister;
  CallDescriptor* incoming =
      Linkage::GetSimplifiedCDescriptor(zone.get(), &incoming_sig, flags);

  // Build a name in the form "c-wasm-entry:<params>:<returns>".
  constexpr size_t kMaxNameLen = 128;
  constexpr size_t kNamePrefixLen = 13;
  auto name_buffer = std::unique_ptr<char[]>(new char[kMaxNameLen]);
  memcpy(name_buffer.get(), "c-wasm-entry:", kNamePrefixLen);
  PrintSignature(
      base::VectorOf(name_buffer.get(), kMaxNameLen) + kNamePrefixLen, sig);

  // Run the compilation job synchronously.
  std::unique_ptr<TurbofanCompilationJob> job(
      Pipeline::NewWasmHeapStubCompilationJob(
          isolate, incoming, std::move(zone), graph, CodeKind::C_WASM_ENTRY,
          std::move(name_buffer), AssemblerOptions::Default(isolate)));

  CHECK_NE(job->ExecuteJob(isolate->counters()->runtime_call_stats(), nullptr),
           CompilationJob::FAILED);
  CHECK_NE(job->FinalizeJob(isolate), CompilationJob::FAILED);

  return job->compilation_info()->code();
}

namespace {

void BuildGraphForWasmFunction(wasm::CompilationEnv* env,
                               WasmCompilationData& data,
                               wasm::WasmDetectedFeatures* detected,
                               MachineGraph* mcgraph) {
  // Create a TF graph during decoding.
  const wasm::FunctionSig* sig = data.func_body.sig;
  WasmGraphBuilder builder(env, mcgraph->zone(), mcgraph, sig,
                           data.source_positions,
                           WasmGraphBuilder::kInstanceParameterMode,
                           nullptr /* isolate */, env->enabled_features);
  auto* allocator = wasm::GetWasmEngine()->allocator();
  wasm::BuildTFGraph(allocator, env->enabled_features, env->module, &builder,
                     detected, data.func_body, data.loop_infos, nullptr,
                     data.node_origins, data.func_index, data.assumptions,
                     wasm::kRegularFunction);

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
  if (v8_flags.experimental_wasm_revectorize && builder.has_simd()) {
    mcgraph->graph()->SetSimd(true);
  }
#endif
}

}  // namespace

wasm::WasmCompilationResult ExecuteTurbofanWasmCompilation(
    wasm::CompilationEnv* env, WasmCompilationData& data, Counters* counters,
    wasm::WasmDetectedFeatures* detected) {
  // Check that we do not accidentally compile a Wasm function to TurboFan if
  // --liftoff-only is set.
  DCHECK(!v8_flags.liftoff_only);

  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.CompileTopTier", "func_index", data.func_index,
               "body_size", data.body_size());
  Zone zone(wasm::GetWasmEngine()->allocator(), ZONE_NAME, kCompressGraphZone);
  MachineGraph* mcgraph = CreateCommonMachineGraph(&zone);

  OptimizedCompilationInfo info(
      GetDebugName(&zone, env->module, data.wire_bytes_storage,
                   data.func_index),
      &zone, CodeKind::WASM_FUNCTION);
  info.set_allocation_folding();

  if (info.trace_turbo_json()) {
    TurboCfgFile tcf;
    tcf << AsC1VCompilation(&info);
  }

  if (info.trace_turbo_json()) {
    data.node_origins = zone.New<NodeOriginTable>(mcgraph->graph());
  }

  data.source_positions =
      mcgraph->zone()->New<SourcePositionTable>(mcgraph->graph());
  ZoneVector<WasmInliningPosition> inlining_positions(&zone);

  std::vector<WasmLoopInfo> loop_infos;
  data.loop_infos = &loop_infos;
  data.assumptions = new wasm::AssumptionsJournal();

  DCHECK_NOT_NULL(detected);
  BuildGraphForWasmFunction(env, data, detected, mcgraph);

  if (data.node_origins) {
    data.node_origins->AddDecorator();
  }

  // Run the compiler pipeline to generate machine code.
  auto call_descriptor = GetWasmCallDescriptor(&zone, data.func_body.sig);
  if (mcgraph->machine()->Is32()) {
    call_descriptor = GetI32WasmCallDescriptor(&zone, call_descriptor);
  }

  if (ContainsSimd(data.func_body.sig) && !CpuFeatures::SupportsWasmSimd128()) {
    // Fail compilation if hardware does not support SIMD.
    return wasm::WasmCompilationResult{};
  }

  Pipeline::GenerateCodeForWasmFunction(&info, env, data, mcgraph,
                                        call_descriptor, &inlining_positions,
                                        detected);

  if (counters && data.body_size() >= 100 * KB) {
    size_t zone_bytes = mcgraph->graph()->zone()->allocation_size();
    counters->wasm_compile_huge_function_peak_memory_bytes()->AddSample(
        static_cast<int>(zone_bytes));
  }

  // If we tiered up only one function for debugging, dump statistics
  // immediately.
  if (V8_UNLIKELY(v8_flags.turbo_stats_wasm &&
                  v8_flags.wasm_tier_up_filter >= 0)) {
    wasm::GetWasmEngine()->DumpTurboStatistics();
  }
  auto result = info.ReleaseWasmCompilationResult();
  CHECK_NOT_NULL(result);  // Compilation expected to succeed.
  DCHECK_EQ(wasm::ExecutionTier::kTurbofan, result->result_tier);
  result->assumptions.reset(data.assumptions);
  return std::move(*result);
}

void WasmGraphBuilder::StoreCallCount(Node* call, int count) {
  mcgraph()->StoreCallCount(call->id(), count);
}

void WasmGraphBuilder::ReserveCallCounts(size_t num_call_instructions) {
  mcgraph()->ReserveCallCounts(num_call_instructions);
}


AssemblerOptions WasmAssemblerOptions() {
  return AssemblerOptions{
      // Relocation info required to serialize {WasmCode} for proper functions.
      .record_reloc_info_for_serialization = true,
      .enable_root_relative_access = false,
      .is_wasm = true,
  };
}

AssemblerOptions WasmStubAssemblerOptions() {
  return AssemblerOptions{
      // Relocation info not necessary because stubs are not serialized.
      .record_reloc_info_for_serialization = false,
      .enable_root_relative_access = false,
      // TODO(jkummerow): Would it be better to have a far jump table in
      // the wrapper cache's code space, and call builtins through that?
      .builtin_call_jump_mode = BuiltinCallJumpMode::kIndirect,
      .is_wasm = true,
  };
}

#undef FATAL_UNSUPPORTED_OPCODE
#undef WASM_INSTANCE_OBJECT_SIZE
#undef LOAD_INSTANCE_FIELD
#undef LOAD_MUTABLE_INSTANCE_FIELD
#undef LOAD_ROOT
#undef LOAD_MUTABLE_ROOT

}  // namespace v8::internal::compiler

"""


```