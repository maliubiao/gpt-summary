Response:
The user wants me to analyze a C++ source code snippet from V8's Wasm interpreter runtime. Specifically, they're asking about its functionality. I need to:

1. **Identify the primary functions of the code.**  This involves looking at the methods and how they manipulate the interpreter's state.
2. **Check if the file extension implies it's a Torque file.**  The provided snippet is C++, so it's not a Torque file.
3. **Determine if the code interacts with JavaScript.**  If so, provide a JavaScript example.
4. **If there's logic, illustrate with input and output examples.** This might be tricky with the given snippet as it's part of a larger system. I'll focus on the function calls and state changes.
5. **Point out common programming errors related to this code.** This will likely involve memory management, stack overflows, and type mismatches.
6. **Summarize the code's functionality.**  Combine the identified functions into a concise description.

Let's break down the code snippet:

- **`CallFunction`**:  This function seems responsible for setting up and executing a Wasm function call. It manages the call stack, handles potential stack overflows, and dispatches the call.
- **`PurgeIndirectCallCache`**: This function clears the cache for indirect calls for a specific table.
- **`ClearIndirectCallCacheEntry`**:  This function clears a specific entry in the indirect call cache.
- **`UpdateIndirectCallTable`**: This function seems to trigger a refresh of the indirect call table, likely by purging its cache.
- **`CheckIndirectCallSignature`**: This function validates the signature of an indirect call target, including type and null checks.
- **`ExecuteIndirectCall`**: This is the core of indirect call execution. It performs bounds checks, resolves the target function (which might be an internal Wasm function or an external JS function), and then executes it. It also handles tail calls.
- **`ExecuteCallRef`**: This function handles calls through function references, which can be to internal Wasm functions or external JavaScript functions.
- **`CallImportedFunction`**: This function manages calls to functions imported from other Wasm modules or JavaScript.
- **`CallWasmToJSBuiltin`**: This function handles the transition from Wasm to JavaScript for builtin functions. It sets up the necessary context and calls the JavaScript function.
- **`CallExternalJSFunction`**: This function handles calls from Wasm to regular JavaScript functions. It packs arguments, performs the call, and handles return values and exceptions.
- **`RttCanon`**:  This function retrieves the canonical runtime type information (RTT) for a given type index.
- **`StructNewUninitialized`**:  This function creates a new uninitialized Wasm struct of a given type.
- **`ArrayNewUninitialized`**: This function creates a new uninitialized Wasm array of a given type and length.

Based on this analysis, I can now formulate the response.
这是v8源代码文件`v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 的第三部分，主要包含以下功能：

**1. 执行 WebAssembly 函数调用 (`CallFunction`)：**

   - 设置新的调用帧，包括更新栈指针、处理 handle scope、设置当前函数和前一帧等信息。
   - 检查栈空间是否足够，如果不足则尝试扩展栈。
   - 初始化引用类型的局部变量。
   - 执行目标函数的字节码，通过 `CallThroughDispatchTable` 进行分发。
   - 处理函数执行完成后的清理工作，例如清理 handle scope、处理异常等。
   - 检查解释器线程的状态，例如是否发生 trap 或异常，并进行相应的处理（例如跳转到 unwind handler）。

**2. 处理间接调用相关的操作：**

   - **清除间接调用缓存 (`PurgeIndirectCallCache`, `ClearIndirectCallCacheEntry`, `UpdateIndirectCallTable`)：**  当间接调用表的内容发生变化时，需要清除或更新缓存，以保证调用的正确性。
   - **检查间接调用签名 (`CheckIndirectCallSignature`)：** 在执行间接调用前，会检查目标函数的签名是否与调用点的签名一致，包括类型检查和空值检查。
   - **执行间接调用 (`ExecuteIndirectCall`)：**
     - 根据表索引和条目索引，从间接调用表中获取目标函数的信息。
     - 进行边界检查，确保条目索引在表范围内。
     - 如果缓存中没有目标函数信息，则尝试从 Wasm 实例中加载。
     - 检查签名是否匹配。
     - 如果是内部 Wasm 函数调用，则直接调用 `ExecuteFunction`。
     - 如果是外部 JavaScript 函数调用，则需要进行参数转换、调用 JavaScript 函数，并处理返回值和异常。

**3. 执行通过函数引用进行的调用 (`ExecuteCallRef`)：**

   - 接收一个函数引用 (`WasmRef`)，该引用可能指向内部 Wasm 函数或外部 JavaScript 函数。
   - 如果引用指向内部 Wasm 函数，则可能需要转换为外部表示。
   - 获取目标函数的签名。
   - 将参数存储到栈上。
   - 调用 `CallExternalJSFunction` 来执行 JavaScript 函数。
   - 处理返回值和异常。

**4. 调用导入的函数 (`CallImportedFunction`)：**

   - 确定被调用函数是来自另一个 Wasm 模块还是 JavaScript。
   - 如果是 Wasm 到 Wasm 的调用：
     - 获取目标实例和函数索引。
     - 确保目标实例的解释器对象已创建。
     - 调用目标实例的解释器来执行函数。
     - 处理返回值。
   - 如果是 Wasm 到 JavaScript 的调用：
     - 获取 JavaScript 函数对象。
     - 调用 `CallExternalJSFunction`。

**5. 从 Wasm 调用 JavaScript 内置函数 (`CallWasmToJSBuiltin`)：**

   - 准备调用 JavaScript 的环境，包括保存和恢复上下文、设置栈处理程序等。
   - 调用通用的 Wasm 到 JavaScript 解释器包装器函数 (`generic_wasm_to_js_interpreter_wrapper_fn_`)。
   - 处理 JavaScript 函数的返回值和异常。

**6. 从 Wasm 调用外部 JavaScript 函数 (`CallExternalJSFunction`)：**

   - 检查 WebAssembly 的签名是否与 JavaScript 兼容。
   - 将 Wasm 的参数转换为 JavaScript 可以接受的格式，存储到缓冲区中。
   - 调用 `CallWasmToJSBuiltin` 来执行 JavaScript 函数。
   - 处理 JavaScript 函数的返回值，并将它们写回 Wasm 的栈上。
   - 处理 JavaScript 抛出的异常。

**7. 获取运行时类型信息 (`RttCanon`)：**

   - 根据类型索引获取规范的运行时类型信息 (RTT) Map 对象。

**8. 创建未初始化的结构体和数组 (`StructNewUninitialized`, `ArrayNewUninitialized`)：**

   - 创建指定类型但未初始化的 Wasm 结构体或数组对象。

**该文件不是 Torque 源代码，因为它以 `.cc` 结尾。**

**与 JavaScript 的功能关系及示例：**

`v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 的核心功能之一就是处理 WebAssembly 与 JavaScript 之间的互操作，包括调用 JavaScript 函数和被 JavaScript 调用。

**JavaScript 示例：**

假设有一个 WebAssembly 模块，其中定义了一个函数，该函数需要调用 JavaScript 的 `console.log`：

```javascript
// JavaScript 代码
const importObject = {
  console: {
    log: (message) => console.log(message)
  }
};

WebAssembly.instantiateStreaming(fetch('my_wasm_module.wasm'), importObject)
  .then(results => {
    results.instance.exports.myWasmFunction(); // 调用 WebAssembly 导出的函数
  });
```

在 `my_wasm_module.wasm` 中，`myWasmFunction` 可能会调用一个导入的函数，该导入函数对应于 JavaScript 中的 `console.log`。`CallImportedFunction` 和 `CallExternalJSFunction` 这两个函数在 V8 的解释器中负责处理这种调用，将 Wasm 的参数传递给 JavaScript 的 `console.log` 并执行。

**代码逻辑推理示例：**

**假设输入：**

- `ExecuteIndirectCall` 被调用。
- `table_index = 0`
- `sig_index = 1` (对应一个接受一个 i32 参数并且没有返回值的函数签名)
- `entry_index = 5`
- 间接调用表中 `table[0][5]` 指向一个内部 WebAssembly 函数，该函数索引为 `10`。
- 栈顶 `sp` 指向的位置存储着一个 i32 类型的值 `42` 作为参数。

**输出：**

- `ExecuteFunction` 将会被调用，并传入目标函数索引 `10` 以及参数 `42` 等信息。
- 如果一切正常，WebAssembly 的内部函数 `10` 将会被执行。

**用户常见的编程错误示例：**

1. **栈溢出：** 在 Wasm 代码中进行深度递归调用或者分配过多的局部变量可能导致栈溢出。`CallFunction` 中会检查栈空间，但如果预估不足，仍然可能发生。

   ```c++
   // C++ 代码 (在 Wasm 中对应的操作会导致栈溢出)
   void recursive_function(int n) {
     int local_array[1000]; // 分配大量局部变量
     if (n > 0) {
       recursive_function(n - 1);
     }
   }
   ```

2. **类型不匹配的间接调用：** 用户可能会尝试通过间接调用表调用一个函数，但提供的签名与实际函数的签名不符。`CheckIndirectCallSignature` 会检测到这种错误并触发 trap。

   ```c++
   // 假设间接调用表中的函数 f 的签名是 (i32) -> void
   // 但调用时提供的签名是 () -> void
   // 这将导致 kTrapFuncSigMismatch
   ```

3. **访问越界的间接调用表条目：** 用户提供的 `entry_index` 超出了间接调用表的范围。`ExecuteIndirectCall` 中的边界检查会捕获这种错误。

   ```c++
   // 假设间接调用表的长度为 10
   uint32_t entry_index = 15; // 越界访问
   ```

**归纳功能：**

总而言之，`v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 的第三部分主要负责 **WebAssembly 解释器在运行时执行函数调用，特别是处理内部 Wasm 函数之间的直接调用、通过函数引用的调用以及与 JavaScript 之间的互操作，包括处理导入函数和间接调用。它还包含了对栈空间管理、类型检查和错误处理的逻辑。**

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter-runtime.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

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

  Handle
"""


```