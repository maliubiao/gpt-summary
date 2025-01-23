Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This code is part of the V8 JavaScript engine, specifically the WebAssembly interpreter runtime.

Here's a breakdown of the code's functionalities:

1. **Exception Handling:** Catches and processes exceptions thrown from within WebAssembly code. It differentiates between WebAssembly exceptions and JavaScript exceptions.
2. **Atomic Operations:** Implements atomic operations like `atomic.notify` and `atomic.wait` for shared memory.
3. **Function Execution:** Manages the execution of WebAssembly functions, including setting up the stack frame and passing arguments. It handles both direct calls and calls to imported functions.
4. **Reference Type Handling:** Manages WebAssembly reference types, including storing and retrieving them from a dedicated reference stack.
5. **Tail Call Optimization:** Implements tail call optimization to prevent stack overflow.
6. **Stack Management:** Manages the interpreter stack, including checking for overflows and potentially expanding the stack.
7. **Interaction with JavaScript:** Handles cases where WebAssembly code calls JavaScript functions or vice-versa. It converts between WebAssembly values and JavaScript objects.
这是 `v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 源代码的第二部分，它主要负责以下功能：

1. **处理 WebAssembly 异常:**
   - 检测并捕获 WebAssembly 代码抛出的异常。
   - 区分 WebAssembly 异常和 JavaScript 异常。
   - 查找与抛出异常匹配的 `try...catch` 块。
   - 如果找到匹配的 `catch` 块，则更新程序计数器 `current_code` 并将异常信息存储到当前帧 `current_frame_` 中。
   - 对于特定的 `WebAssembly.JSTag` 异常，如果捕获到的不是 WebAssembly 异常，则将其推送到操作数栈上。
   - 如果没有找到匹配的 `catch` 块，则启动异常展开 (`Unwinding`) 过程。

2. **支持原子操作:**
   - 实现了 `AtomicNotify` 函数，用于唤醒等待在共享内存上的线程。
   - 实现了 `I32AtomicWait` 和 `I64AtomicWait` 函数，允许 WebAssembly 代码等待共享内存中的特定值。

3. **启动和继续 WebAssembly 函数执行:**
   - `BeginExecution` 函数负责初始化 WebAssembly 函数的执行，包括设置当前线程、栈帧、参数等。
   - 它处理从 JavaScript 调用 WebAssembly 和从 WebAssembly 内部调用两种情况的参数传递。
   - 它会进行栈溢出检查，并在必要时尝试扩展栈。
   - `ContinueExecution` 函数在 `BeginExecution` 之后被调用，实际执行 WebAssembly 函数。
   - 它处理函数执行完成后的返回值，并根据调用方（JavaScript 或 WebAssembly）的不同进行处理。
   - 如果函数执行过程中发生异常，则会调用相应的异常处理机制。

4. **管理 WebAssembly 引用类型:**
   - 提供了 `StoreWasmRef` 函数用于将 WebAssembly 引用存储到引用栈 (`reference_stack_`) 中。
   - 提供了 `ExtractWasmRef` 函数用于从引用栈中提取 WebAssembly 引用。
   - `EnsureRefStackSpace` 函数用于确保引用栈有足够的空间来存储引用。
   - `ClearRefStackValues` 函数用于清除引用栈中的值。

5. **实现尾调用优化:**
   - `UnwindCurrentStackFrame` 函数用于在进行尾调用之前清理当前栈帧，避免额外的栈帧开销。
   - `PrepareTailCall` 函数用于准备进行尾调用，设置新的目标函数的栈帧，但不实际执行。

6. **辅助函数:**
   - `StoreRefArgsIntoStackSlots` 函数将引用类型的参数从引用栈复制到普通栈槽中，以便与其他函数调用机制兼容。
   - `StoreRefResultsIntoRefStack` 函数将引用类型的返回值从普通栈槽存储回引用栈中。
   - `ExecuteImportedFunction` 函数用于执行导入的 WebAssembly 函数，并处理可能发生的异常。
   - `ExecuteFunction` 函数用于执行 WebAssembly 内部函数。

**与 JavaScript 的关系和示例:**

这段代码处理了 WebAssembly 与 JavaScript 之间的互操作，特别是当 WebAssembly 代码抛出异常时，JavaScript 可以捕获它，反之亦然。

**JavaScript 示例 (异常处理):**

```javascript
// 假设有一个 WebAssembly 模块 instance，其中定义了一个抛出异常的函数 throwException
instance.exports.throwException();

try {
  instance.exports.someFunctionThatMightThrow();
} catch (e) {
  console.error("Caught an exception from WebAssembly:", e);
}
```

在这个例子中，如果 `instance.exports.someFunctionThatMightThrow()` 抛出一个 WebAssembly 异常，V8 的解释器运行时会尝试在 WebAssembly 代码中找到 `catch` 块。如果没有找到，异常会冒泡到 JavaScript 层，被 `try...catch` 块捕获。

**代码逻辑推理和假设输入输出:**

**假设输入:**

- `isolate_`: 当前 V8 隔离对象。
- `current_code`: 当前执行的 WebAssembly 代码指针。
- `current_frame_`: 当前的 WebAssembly 函数调用帧信息。
- `exception`: 一个由 WebAssembly 代码抛出的异常对象。
- `module_`: 当前 WebAssembly 模块的元数据。

**代码逻辑 (异常处理部分):**

如果 `isolate_->is_catchable_by_wasm(isolate_->exception())` 返回 `true`，并且异常的标签与当前 `try` 块中的 `catch` 块的标签匹配，那么代码会将 `current_code` 更新到 `catch` 块的起始位置，并将异常信息存储到 `current_frame_` 中，然后返回 `WasmInterpreterThread::HANDLED`。

**假设输入 (原子操作):**

- `buffer_offset`: 共享内存中的偏移量。
- `val`: 用于原子操作的值。
- `timeout`: 原子等待操作的超时时间。

**代码逻辑 (原子操作部分):**

`AtomicNotify` 函数会尝试唤醒等待在指定共享内存地址上的线程。`I32AtomicWait` 和 `I64AtomicWait` 函数会让当前 WebAssembly 线程等待直到共享内存中的指定地址的值变为预期值，或者超时。

**用户常见的编程错误示例:**

1. **在共享内存上进行原子操作时，提供的偏移量 `buffer_offset` 超出内存边界。** 这会导致程序崩溃或产生不可预测的结果。

   ```c++
   // 假设内存大小为 1024
   uint64_t buffer_offset = 2048; // 错误：超出内存边界
   int32_t value = 10;
   AtomicNotify(buffer_offset, value);
   ```

2. **在使用原子等待操作时，没有相应的 `AtomicNotify` 操作来唤醒等待的线程，导致程序死锁。**

   ```c++
   // 线程 1
   I32AtomicWait(offset, expected_value, -1); // 永远等待

   // 线程 2 (缺少 AtomicNotify)
   // ... 没有调用 AtomicNotify 来改变内存中的值
   ```

**功能归纳:**

这部分代码是 WebAssembly 解释器运行时的核心组成部分，主要负责处理 WebAssembly 代码执行过程中的异常、支持原子操作、管理函数调用栈和参数传递（包括引用类型），并提供尾调用优化等功能。它还负责 WebAssembly 与 JavaScript 之间的互操作，特别是异常的传递和处理。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter-runtime.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
isolate_->is_catchable_by_wasm(isolate_->exception());
  if (catchable) {
    HandleScope scope(isolate_);
    Handle<Object> exception = handle(isolate_->exception(), isolate_);
    Tagged<WasmTrustedInstanceData> trusted_data =
        *wasm_trusted_instance_data();

    // We might need to allocate a new FixedArray<Object> to store the caught
    // exception.
    DCHECK(AllowHeapAllocation::IsAllowed());

    size_t current_code_offset =
        current_code - current_frame_.current_function_->GetCode();
    const WasmEHData::TryBlock* try_block =
        current_frame_.current_function_->GetTryBlock(current_code_offset);
    while (try_block) {
      for (const auto& catch_handler : try_block->catch_handlers) {
        if (catch_handler.tag_index < 0) {
          // Catch all.
          current_code = current_frame_.current_function_->GetCode() +
                         catch_handler.code_offset;
          current_frame_.SetCaughtException(
              isolate_, catch_handler.catch_block_index, exception);
          isolate_->clear_exception();
          return WasmInterpreterThread::HANDLED;
        } else if (IsWasmExceptionPackage(*exception, isolate_)) {
          // The exception was thrown by Wasm code and it's wrapped in a
          // WasmExceptionPackage.
          Handle<Object> caught_tag = WasmExceptionPackage::GetExceptionTag(
              isolate_, Cast<WasmExceptionPackage>(exception));
          Handle<Object> expected_tag =
              handle(trusted_data->tags_table()->get(catch_handler.tag_index),
                     isolate_);
          DCHECK(IsWasmExceptionTag(*expected_tag));
          // Determines whether the given exception has a tag matching the
          // expected tag for the given index within the exception table of the
          // current instance.
          if (expected_tag.is_identical_to(caught_tag)) {
            current_code = current_frame_.current_function_->GetCode() +
                           catch_handler.code_offset;
            DCHECK_LT(catch_handler.tag_index, module_->tags.size());
            const WasmTag& tag = module_->tags[catch_handler.tag_index];
            auto exception_payload_slot_offsets =
                current_frame_.current_function_
                    ->GetExceptionPayloadStartSlotOffsets(
                        catch_handler.catch_block_index);
            UnpackException(
                sp, tag, exception,
                exception_payload_slot_offsets.first_param_slot_offset,
                exception_payload_slot_offsets.first_param_ref_stack_index);
            current_frame_.SetCaughtException(
                isolate_, catch_handler.catch_block_index, exception);
            isolate_->clear_exception();
            return WasmInterpreterThread::HANDLED;
          }
        } else {
          // Check for the special case where the tag is WebAssembly.JSTag and
          // the exception is not a WebAssembly.Exception. In this case the
          // exception is caught and pushed on the operand stack.
          // Only perform this check if the tag signature is the same as
          // the JSTag signature, i.e. a single externref, otherwise we know
          // statically that it cannot be the JSTag.
          DCHECK_LT(catch_handler.tag_index, module_->tags.size());
          const WasmTagSig* sig = module_->tags[catch_handler.tag_index].sig;
          if (sig->return_count() != 0 || sig->parameter_count() != 1 ||
              (sig->GetParam(0).kind() != kRefNull &&
               sig->GetParam(0).kind() != kRef)) {
            continue;
          }

          Handle<JSObject> js_tag_object =
              handle(isolate_->native_context()->wasm_js_tag(), isolate_);
          Handle<WasmTagObject> wasm_tag_object(
              Cast<WasmTagObject>(*js_tag_object), isolate_);
          Handle<Object> caught_tag = handle(wasm_tag_object->tag(), isolate_);
          Handle<Object> expected_tag =
              handle(trusted_data->tags_table()->get(catch_handler.tag_index),
                     isolate_);
          if (!expected_tag.is_identical_to(caught_tag)) {
            continue;
          }

          current_code = current_frame_.current_function_->GetCode() +
                         catch_handler.code_offset;
          // Push exception on the operand stack.
          auto exception_payload_slot_offsets =
              current_frame_.current_function_
                  ->GetExceptionPayloadStartSlotOffsets(
                      catch_handler.catch_block_index);
          StoreWasmRef(
              exception_payload_slot_offsets.first_param_ref_stack_index,
              exception);
          base::WriteUnalignedValue<WasmRef>(
              reinterpret_cast<Address>(
                  sp + exception_payload_slot_offsets.first_param_slot_offset),
              exception);

          current_frame_.SetCaughtException(
              isolate_, catch_handler.catch_block_index, exception);
          isolate_->clear_exception();
          return WasmInterpreterThread::HANDLED;
        }
      }
      try_block =
          current_frame_.current_function_->GetParentTryBlock(try_block);
    }
  }

  DCHECK_NOT_NULL(current_thread_);
  current_thread_->Unwinding();
  return WasmInterpreterThread::UNWOUND;
}

bool WasmInterpreterRuntime::AllowsAtomicsWait() const {
  return !module_->memories.empty() && module_->memories[0].is_shared &&
         isolate_->allow_atomics_wait();
}

int32_t WasmInterpreterRuntime::AtomicNotify(uint64_t buffer_offset,
                                             int32_t val) {
  if (module_->memories.empty() || !module_->memories[0].is_shared) {
    return 0;
  } else {
    HandleScope handle_scope(isolate_);
    // TODO(paolosev@microsoft.com): Support multiple memories.
    uint32_t memory_index = 0;
    Handle<JSArrayBuffer> array_buffer(wasm_trusted_instance_data()
                                           ->memory_object(memory_index)
                                           ->array_buffer(),
                                       isolate_);
    int result = FutexEmulation::Wake(*array_buffer, buffer_offset, val);
    return result;
  }
}

int32_t WasmInterpreterRuntime::I32AtomicWait(uint64_t buffer_offset,
                                              int32_t val, int64_t timeout) {
  HandleScope handle_scope(isolate_);
  // TODO(paolosev@microsoft.com): Support multiple memories.
  uint32_t memory_index = 0;
  Handle<JSArrayBuffer> array_buffer(
      wasm_trusted_instance_data()->memory_object(memory_index)->array_buffer(),
      isolate_);
  auto result = FutexEmulation::WaitWasm32(isolate_, array_buffer,
                                           buffer_offset, val, timeout);
  return result.ToSmi().value();
}

int32_t WasmInterpreterRuntime::I64AtomicWait(uint64_t buffer_offset,
                                              int64_t val, int64_t timeout) {
  HandleScope handle_scope(isolate_);
  // TODO(paolosev@microsoft.com): Support multiple memories.
  uint32_t memory_index = 0;
  Handle<JSArrayBuffer> array_buffer(
      wasm_trusted_instance_data()->memory_object(memory_index)->array_buffer(),
      isolate_);
  auto result = FutexEmulation::WaitWasm64(isolate_, array_buffer,
                                           buffer_offset, val, timeout);
  return result.ToSmi().value();
}

void WasmInterpreterRuntime::BeginExecution(
    WasmInterpreterThread* thread, uint32_t func_index, Address frame_pointer,
    uint8_t* interpreter_fp, uint32_t ref_stack_offset,
    const std::vector<WasmValue>* argument_values) {
  current_thread_ = thread;
  start_function_index_ = func_index;

  thread->StartActivation(this, frame_pointer, interpreter_fp, current_frame_);

  current_frame_.current_function_ = nullptr;
  current_frame_.previous_frame_ = nullptr;
  current_frame_.current_bytecode_ = nullptr;
  current_frame_.current_sp_ = interpreter_fp;
  current_frame_.ref_array_current_sp_ = ref_stack_offset;
  current_frame_.thread_ = thread;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  current_frame_.current_stack_start_args_ = thread->CurrentStackFrameStart();
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  const FunctionSig* sig = module_->functions[func_index].sig;
  size_t args_count = 0;
  uint32_t rets_slots_size = 0;
  uint32_t ref_rets_count = 0;
  uint32_t ref_args_count = 0;
  WasmBytecode* target_function = GetFunctionBytecode(func_index);
  if (target_function) {
    args_count = target_function->args_count();
    rets_slots_size = target_function->rets_slots_size();
    ref_rets_count = target_function->ref_rets_count();
    ref_args_count = target_function->ref_args_count();
  } else {
    // We begin execution by calling an imported function.
    args_count = sig->parameter_count();
    rets_slots_size = WasmBytecode::RetsSizeInSlots(sig);
    ref_rets_count = WasmBytecode::RefRetsCount(sig);
    ref_args_count = WasmBytecode::RefArgsCount(sig);
  }

  // Here GC is disabled, we cannot "resize" the reference_stack_ FixedArray
  // before having created Handles for the Ref arguments passed in
  // argument_values.
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.

  std::vector<Handle<Object>> ref_args;
  if (ref_args_count > 0) {
    ref_args.reserve(ref_args_count);
  }

  uint8_t* p = interpreter_fp + rets_slots_size * kSlotSize;

  // Check stack overflow.
  const uint8_t* stack_limit = thread->StackLimitAddress();
  if (V8_UNLIKELY(p + (ref_rets_count + ref_args_count) * sizeof(WasmRef) >=
                  stack_limit)) {
    size_t additional_required_size =
        p + (ref_rets_count + ref_args_count) * sizeof(WasmRef) - stack_limit;
    if (!thread->ExpandStack(additional_required_size)) {
      // TODO(paolosev@microsoft.com) - Calculate initial function offset.
      ClearThreadInWasmScope clear_wasm_flag(isolate_);
      SealHandleScope shs(isolate_);
      isolate_->StackOverflow();
      const pc_t trap_pc = 0;
      SetTrap(TrapReason::kTrapUnreachable, trap_pc);
      thread->FinishActivation();
      return;
    }
  }

  if (argument_values) {
    // We are being called from JS, arguments are passed in the
    // {argument_values} vector.
    for (size_t i = 0; i < argument_values->size(); i++) {
      const WasmValue& value = (*argument_values)[i];
      switch (value.type().kind()) {
        case kI32:
          base::WriteUnalignedValue<int32_t>(reinterpret_cast<Address>(p),
                                             value.to<int32_t>());
          p += sizeof(int32_t);
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(reinterpret_cast<Address>(p),
                                             value.to<int64_t>());
          p += sizeof(int64_t);
          break;
        case kF32:
          base::WriteUnalignedValue<float>(reinterpret_cast<Address>(p),
                                           value.to<float>());
          p += sizeof(float);
          break;
        case kF64:
          base::WriteUnalignedValue<double>(reinterpret_cast<Address>(p),
                                            value.to<double>());
          p += sizeof(double);
          break;
        case kRef:
        case kRefNull: {
          Handle<Object> ref = value.to_ref();
          if (IsJSFunction(*ref, isolate_)) {
            Tagged<SharedFunctionInfo> sfi = Cast<JSFunction>(ref)->shared();
            if (sfi->HasWasmExportedFunctionData()) {
              Tagged<WasmExportedFunctionData> wasm_exported_function_data =
                  sfi->wasm_exported_function_data();
              ref = handle(
                  wasm_exported_function_data->func_ref()->internal(isolate_),
                  isolate_);
            }
          }
          ref_args.push_back(ref);
          base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(p),
                                             WasmRef(nullptr));
          p += sizeof(WasmRef);
          break;
        }
        case kS128:
        default:
          UNREACHABLE();
      }
    }
  } else {
    // We are being called from Wasm, arguments are already in the stack.
    for (size_t i = 0; i < args_count; i++) {
      switch (sig->GetParam(i).kind()) {
        case kI32:
          p += sizeof(int32_t);
          break;
        case kI64:
          p += sizeof(int64_t);
          break;
        case kF32:
          p += sizeof(float);
          break;
        case kF64:
          p += sizeof(double);
          break;
        case kS128:
          p += sizeof(Simd128);
          break;
        case kRef:
        case kRefNull: {
          Handle<Object> ref = base::ReadUnalignedValue<Handle<Object>>(
              reinterpret_cast<Address>(p));
          ref_args.push_back(ref);
          p += sizeof(WasmRef);
          break;
        }
        default:
          UNREACHABLE();
      }
    }
  }

  {
    // Once we have read ref argument passed on the stack and we have stored
    // them into the ref_args vector of Handles, we can re-enable the GC.
    AllowHeapAllocation allow_gc;

    if (ref_rets_count + ref_args_count > 0) {
      // Reserve space for reference args and return values in the
      // reference_stack_.
      EnsureRefStackSpace(current_frame_.ref_array_length_ + ref_rets_count +
                          ref_args_count);

      uint32_t ref_stack_arg_index = ref_rets_count;
      for (uint32_t ref_arg_index = 0; ref_arg_index < ref_args_count;
           ref_arg_index++) {
        StoreWasmRef(ref_stack_arg_index++, ref_args[ref_arg_index]);
      }
    }
  }
}

void WasmInterpreterRuntime::ContinueExecution(WasmInterpreterThread* thread,
                                               bool called_from_js) {
  DCHECK_NE(start_function_index_, UINT_MAX);

  uint32_t start_function_index = start_function_index_;
  FrameState current_frame = current_frame_;

  const uint8_t* code = nullptr;
  const FunctionSig* sig = nullptr;
  uint32_t return_count = 0;
  WasmBytecode* target_function = GetFunctionBytecode(start_function_index_);
  if (target_function) {
    sig = target_function->GetFunctionSignature();
    return_count = target_function->return_count();
    ExecuteFunction(code, start_function_index_, target_function->args_count(),
                    0, 0, 0);
  } else {
    sig = module_->functions[start_function_index_].sig;
    return_count = static_cast<uint32_t>(sig->return_count());
    ExecuteImportedFunction(code, start_function_index_,
                            static_cast<uint32_t>(sig->parameter_count()), 0, 0,
                            0);
  }

  // If there are Ref types in the set of result types defined in the function
  // signature, they are located from the first ref_stack_ slot of the current
  // Activation.
  uint32_t ref_result_slot_index = 0;

  if (state() == WasmInterpreterThread::State::RUNNING) {
    if (return_count > 0) {
      uint32_t* dst = reinterpret_cast<uint32_t*>(current_frame_.current_sp_);

      if (called_from_js) {
        // We are returning the results to a JS caller, we need to store them
        // into the {function_result_} vector and they will be retrieved via
        // {GetReturnValue}.
        function_result_.resize(return_count);
        for (size_t index = 0; index < return_count; index++) {
          switch (sig->GetReturn(index).kind()) {
            case kI32:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<int32_t>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(uint32_t) / kSlotSize;
              break;
            case kI64:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<int64_t>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(uint64_t) / kSlotSize;
              break;
            case kF32:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<float>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(float) / kSlotSize;
              break;
            case kF64:
              function_result_[index] =
                  WasmValue(base::ReadUnalignedValue<double>(
                      reinterpret_cast<Address>(dst)));
              dst += sizeof(double) / kSlotSize;
              break;
            case kRef:
            case kRefNull: {
              Handle<Object> ref = ExtractWasmRef(ref_result_slot_index++);
              ref = WasmToJSObject(ref);
              function_result_[index] = WasmValue(
                  ref, sig->GetReturn(index).kind() == kRef ? kWasmRefString
                                                            : kWasmAnyRef);
              dst += sizeof(WasmRef) / kSlotSize;
              break;
            }
            case kS128:
            default:
              UNREACHABLE();
          }
        }
      } else {
        // We are returning the results on the stack
        for (size_t index = 0; index < return_count; index++) {
          switch (sig->GetReturn(index).kind()) {
            case kI32:
              dst += sizeof(uint32_t) / kSlotSize;
              break;
            case kI64:
              dst += sizeof(uint64_t) / kSlotSize;
              break;
            case kF32:
              dst += sizeof(float) / kSlotSize;
              break;
            case kF64:
              dst += sizeof(double) / kSlotSize;
              break;
            case kS128:
              dst += sizeof(Simd128) / kSlotSize;
              break;
            case kRef:
            case kRefNull: {
              // Make sure the ref result is termporarily stored in a stack
              // slot, to be retrieved by the caller.
              Handle<Object> ref = ExtractWasmRef(ref_result_slot_index++);
              base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(dst),
                                                 ref);
              dst += sizeof(WasmRef) / kSlotSize;
              break;
            }
            default:
              UNREACHABLE();
          }
        }
      }
    }

    if (ref_result_slot_index > 0) {
      ClearRefStackValues(current_frame_.ref_array_current_sp_,
                          ref_result_slot_index);
    }

    DCHECK(current_frame_.caught_exceptions_.is_null());

    start_function_index_ = start_function_index;
    current_frame_ = current_frame;
  } else if (state() == WasmInterpreterThread::State::TRAPPED) {
    MessageTemplate message_id =
        WasmOpcodes::TrapReasonToMessageId(thread->GetTrapReason());
    thread->RaiseException(isolate_, message_id);
  } else if (state() == WasmInterpreterThread::State::EH_UNWINDING) {
    // Uncaught exception.
    thread->Stop();
  } else {
    DCHECK_EQ(state(), WasmInterpreterThread::State::STOPPED);
  }

  thread->FinishActivation();
  const FrameState* frame_state = thread->GetCurrentActivationFor(this);
  current_frame_ = frame_state ? *frame_state : FrameState();
}

void WasmInterpreterRuntime::StoreWasmRef(uint32_t ref_stack_index,
                                          const WasmRef& ref) {
  uint32_t index = ref_stack_index + current_frame_.ref_array_current_sp_;
  if (ref.is_null()) {
    reference_stack_->set_the_hole(isolate_, index);
  } else {
    reference_stack_->set(index, *ref);
  }
}

WasmRef WasmInterpreterRuntime::ExtractWasmRef(uint32_t ref_stack_index) {
  int index =
      static_cast<int>(ref_stack_index) + current_frame_.ref_array_current_sp_;
  Handle<Object> ref(reference_stack_->get(index), isolate_);
  DCHECK(!IsTheHole(*ref, isolate_));
  return WasmRef(ref);
}

void WasmInterpreterRuntime::EnsureRefStackSpace(size_t new_size) {
  if (V8_LIKELY(current_ref_stack_size_ >= new_size)) return;
  size_t requested_size = base::bits::RoundUpToPowerOfTwo64(new_size);
  new_size = std::max(size_t{8},
                      std::max(2 * current_ref_stack_size_, requested_size));
  int grow_by = static_cast<int>(new_size - current_ref_stack_size_);
  HandleScope handle_scope(isolate_);  // Avoid leaking handles.
  Handle<FixedArray> new_ref_stack =
      isolate_->factory()->CopyFixedArrayAndGrow(reference_stack_, grow_by);
  new_ref_stack->FillWithHoles(static_cast<int>(current_ref_stack_size_),
                               static_cast<int>(new_size));
  isolate_->global_handles()->Destroy(reference_stack_.location());
  reference_stack_ = isolate_->global_handles()->Create(*new_ref_stack);
  current_ref_stack_size_ = new_size;
}

void WasmInterpreterRuntime::ClearRefStackValues(size_t index, size_t count) {
  reference_stack_->FillWithHoles(static_cast<int>(index),
                                  static_cast<int>(index + count));
}

// A tail call should not add an additional stack frame to the interpreter
// stack. This is implemented by unwinding the current stack frame just before
// the tail call.
void WasmInterpreterRuntime::UnwindCurrentStackFrame(
    uint32_t* sp, uint32_t slot_offset, uint32_t rets_size, uint32_t args_size,
    uint32_t rets_refs, uint32_t args_refs, uint32_t ref_stack_fp_offset) {
  // At the moment of the call the interpreter stack is as in the diagram below.
  // A new interpreter frame for the callee function has been initialized, with
  // `R` slots to contain the R return values, followed by {args_size} slots to
  // contain the callee arguments.
  //
  // In order to unwind an interpreter stack frame we just copy the content of
  // the slots that contain the callee arguments into the caller stack frame,
  // just after the slots of the return values. Note that the return call is
  // invalid if the number and types of the return values of the callee function
  // do not exactly match the number and types of the return values of the
  // caller function. Instead, the number of types of the caller and callee
  // functions arguments can differ.
  //
  // The other slots in the caller frame, for const values and locals, will be
  // initialized later in ExecuteFunction().
  //
  // +----------------------+
  // | argA-1               |      ^         ^
  // | ...                  |      |         | ->-----+
  // | ...                  |      |         |        |
  // | arg0                 |    callee      v        |
  // | retR-1               |    frame                |
  // | ...                  |      |                  |
  // | ret0                 |      v                  | copy
  // +----------------------+ (slot_offset)           |
  // | ...                  |      ^                  V
  // | <stack slots>        |      |                  |
  // | <locals slots>       |      |                  |
  // | <const slots>        |      |         ^        |
  // | argN-1               |    caller      | <------+
  // | ...                  |    frame       |
  // | arg0                 |      |         v
  // | retR-1               |      |
  // | ...                  |      |
  // | ret0                 |      v
  // +----------------------+ (0)

  uint8_t* next_sp = reinterpret_cast<uint8_t*>(sp);
  uint8_t* prev_sp = next_sp + slot_offset;
  // Here {args_size} is the number of arguments expected by the function we are
  // calling, which can be different from the number of args of the caller
  // function.
  ::memmove(next_sp + rets_size, prev_sp, args_size);

  // If some of the argument-slots contain Ref values, we need to move them
  // accordingly, in the {reference_stack_}.
  if (rets_refs) {
    ClearRefStackValues(current_frame_.ref_array_current_sp_, rets_refs);
  }
  // Here {args_refs} is the number of reference args expected by the function
  // we are calling, which can be different from the number of reference args of
  // the caller function.
  for (uint32_t i = 0; i < args_refs; i++) {
    StoreWasmRef(rets_refs + i, ExtractWasmRef(ref_stack_fp_offset + i));
  }
  if (ref_stack_fp_offset > rets_refs + args_refs) {
    ClearRefStackValues(
        current_frame_.ref_array_current_sp_ + rets_refs + args_refs,
        ref_stack_fp_offset - rets_refs - args_refs);
  }
}

void WasmInterpreterRuntime::StoreRefArgsIntoStackSlots(
    uint8_t* sp, uint32_t ref_stack_fp_index, const FunctionSig* sig) {
  // Argument values of type Ref, if present, are already stored in the
  // reference_stack_ starting at index ref_stack_fp_index + RefRetsCount(sig).
  // We want to temporarily copy the pointers to these object also in the stack
  // slots, because functions WasmInterpreter::RunInterpreter() and
  // WasmInterpreter::CallExternalJSFunction gets all arguments from the stack.

  // TODO(paolosev@microsoft.com) - Too slow?
  ref_stack_fp_index += WasmBytecode::RefRetsCount(sig);

  size_t args_count = sig->parameter_count();
  sp += WasmBytecode::RetsSizeInSlots(sig) * kSlotSize;
  for (size_t i = 0; i < args_count; i++) {
    switch (sig->GetParam(i).kind()) {
      case kI32:
      case kF32:
        sp += sizeof(int32_t);
        break;
      case kI64:
      case kF64:
        sp += sizeof(int64_t);
        break;
      case kS128:
        sp += sizeof(Simd128);
        break;
      case kRef:
      case kRefNull: {
        WasmRef ref = ExtractWasmRef(ref_stack_fp_index++);
        base::WriteUnalignedValue<WasmRef>(reinterpret_cast<Address>(sp), ref);
        sp += sizeof(WasmRef);
        break;
      }
      default:
        UNREACHABLE();
    }
  }
}

void WasmInterpreterRuntime::StoreRefResultsIntoRefStack(
    uint8_t* sp, uint32_t ref_stack_fp_index, const FunctionSig* sig) {
  size_t rets_count = sig->return_count();
  for (size_t i = 0; i < rets_count; i++) {
    switch (sig->GetReturn(i).kind()) {
      case kI32:
      case kF32:
        sp += sizeof(int32_t);
        break;
      case kI64:
      case kF64:
        sp += sizeof(int64_t);
        break;
      case kS128:
        sp += sizeof(Simd128);
        break;
      case kRef:
      case kRefNull:
        StoreWasmRef(ref_stack_fp_index++, base::ReadUnalignedValue<WasmRef>(
                                               reinterpret_cast<Address>(sp)));
        sp += sizeof(WasmRef);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void WasmInterpreterRuntime::ExecuteImportedFunction(
    const uint8_t*& code, uint32_t func_index, uint32_t current_stack_size,
    uint32_t ref_stack_fp_index, uint32_t slot_offset,
    uint32_t return_slot_offset) {
  WasmInterpreterThread* thread = this->thread();
  DCHECK_NOT_NULL(thread);

  // Store a pointer to the current FrameState before leaving the current
  // Activation.
  current_frame_.current_bytecode_ = code;
  thread->SetCurrentFrame(current_frame_);
  thread->SetCurrentActivationFrame(
      reinterpret_cast<uint32_t*>(current_frame_.current_sp_ + slot_offset),
      slot_offset, current_stack_size, ref_stack_fp_index);

  ExternalCallResult result = CallImportedFunction(
      code, func_index,
      reinterpret_cast<uint32_t*>(current_frame_.current_sp_ + slot_offset),
      current_stack_size, ref_stack_fp_index, slot_offset);

  if (result == ExternalCallResult::EXTERNAL_EXCEPTION) {
    if (HandleException(reinterpret_cast<uint32_t*>(current_frame_.current_sp_),
                        code) ==
        WasmInterpreterThread::ExceptionHandlingResult::HANDLED) {
      // The exception was caught by Wasm EH. Resume execution,
      // {HandleException} has already updated {code} to point to the first
      // instruction in the catch handler.
      thread->Run();
    } else {  // ExceptionHandlingResult::UNWRAPPED
      if (thread->state() != WasmInterpreterThread::State::EH_UNWINDING) {
        thread->Stop();
      }
      // Resume execution from s2s_Unwind, which unwinds the Wasm stack frames.
      RedirectCodeToUnwindHandler(code);
    }
  }
}

inline DISABLE_CFI_ICALL void CallThroughDispatchTable(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  kInstructionTable[ReadFnId(code) & kInstructionTableMask](
      code, sp, wasm_runtime, r0, fp0);
}

// Sets up the current interpreter stack frame to start executing a new function
// with a tail call. Do not move the stack pointer for the interpreter stack,
// and avoids calling WasmInterpreterRuntime::ExecuteFunction(), which would add
// a new C++ stack frame.
void WasmInterpreterRuntime::PrepareTailCall(const uint8_t*& code,
                                             uint32_t func_index,
                                             uint32_t current_stack_size,
                                             uint32_t return_slot_offset) {
  // TODO(paolosev@microsoft.com): avoid to duplicate code from ExecuteFunction?

  WASM_STACK_CHECK(isolate_, code);

  WasmBytecode* target_function = GetFunctionBytecode(func_index);
  DCHECK_NOT_NULL(target_function);

  current_frame_.current_bytecode_ = code;

  current_frame_.current_function_ = target_function;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  current_frame_.current_stack_start_locals_ =
      current_frame_.current_stack_start_args_ + target_function->args_count();
  current_frame_.current_stack_start_stack_ =
      current_frame_.current_stack_start_locals_ +
      target_function->locals_count();

  if (v8_flags.trace_drumbrake_execution) {
    Trace("\nTailCallFunction: %d\n", func_index);
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
  if (V8_UNLIKELY(ref_slots_count > 0)) {
    current_frame_.ref_array_length_ =
        current_frame_.ref_array_current_sp_ + ref_slots_count;
    EnsureRefStackSpace(current_frame_.ref_array_length_);

    // Initialize locals of ref types.
    if (V8_UNLIKELY(target_function->ref_locals_count() > 0)) {
      uint32_t ref_stack_index =
          target_function->ref_rets_count() + target_function->ref_args_count();
      for (uint32_t i = 0; i < target_function->ref_locals_count(); i++) {
        StoreWasmRef(ref_stack_index++,
                     WasmRef(isolate_->factory()->null_value()));
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

  code = target_function->GetCode();
}

void WasmInterpreterRuntime::ExecuteFunction(const uint8_t*& code,
                                             uint32_t func_index,
                                             uint32_t current_stack_size,
                                             uint32_t ref_stack_fp_offset,
                                             uint32_t slot_offset,
                                             uint32_t return_slot_offset) {
  WASM_STACK_CHECK(isolate_, code);

  // Execute an internal call.
  WasmBytecode* target_function = GetFunctionBytecode(func_index);
  DCHECK_NOT_NULL(target_function);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  ShadowStack* prev_shadow_stack = shadow_stack_;
  ShadowStack shadow_stack;
  if (v8_flags.trace_drumbrake_execution) {
    shadow_stack_ = &shadow_stack;
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // This HandleScope is used for all handles created in instruction handlers.
  // W
```