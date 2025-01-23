Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/runtime/runtime-wasm.cc`.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:**  The file `runtime-wasm.cc` suggests that this code defines runtime functions specifically for WebAssembly (Wasm) within the V8 JavaScript engine. These functions are called from Wasm code to interact with the JavaScript environment or perform specific V8 operations.

2. **Analyze each function individually:** Go through each `RUNTIME_FUNCTION` definition and determine its role. Look for keywords and function names that hint at the operation being performed (e.g., `TierUp`, `AtomicWait`, `RefFunc`, `TableGet`, `TableSet`, `TableInit`, `TableCopy`, `TableGrow`, `TableFill`, `DebugBreak`, `ArrayCopy`, `ArrayNewSegment`, `ArrayInitSegment`, `AllocateSuspender`, `CastToSpecialPrimitiveArray`, `StringNewWtf8`, `StringNewWtf8Array`, `StringNewWtf16`).

3. **Check for `.tq` relevance:**  The prompt mentions `.tq` files (Torque). Scan the code for any explicit mentions of Torque or code patterns typical of generated Torque code. In this snippet, there are no indications of Torque.

4. **Connect to JavaScript:**  Think about how the described Wasm runtime functions would be used from JavaScript. Consider the WebAssembly JavaScript API and what operations might need these underlying implementations.

5. **Provide JavaScript examples:** If a function clearly relates to a JavaScript API, provide a concise example.

6. **Infer logic and provide examples:** For functions involving data manipulation (e.g., `Table` and `Array` operations), create hypothetical inputs and expected outputs to illustrate their behavior.

7. **Identify potential errors:** Based on the function's purpose, think about common mistakes a programmer might make when using the corresponding Wasm or JavaScript API.

8. **Address the "归纳一下它的功能" (summarize its functionality) part:** Combine the individual function descriptions into a concise overview of the file's purpose.

**Self-Correction/Refinement During Thinking:**

* **Initial thought:** Some functions might seem very low-level and hard to connect to direct JavaScript.
* **Correction:** Realize that these are *runtime* functions. They are the implementation details that support the higher-level JavaScript WebAssembly API. Focus on the *intent* of the function rather than a direct 1:1 mapping to a JS keyword.

* **Initial thought:**  Should I dive deep into the V8 internals and data structures?
* **Correction:**  Keep the explanation at a high level, focusing on the functional purpose and how it relates to Wasm concepts and JavaScript interaction. Avoid getting bogged down in the specifics of V8's memory management or internal representations unless it's crucial for understanding the functionality.

* **Initial thought:** How detailed should the JavaScript examples be?
* **Correction:**  Keep them short and illustrative, focusing on the core concept the runtime function supports. No need for complex or full application examples.

By following these steps and refining the approach along the way, I can generate a comprehensive and accurate description of the provided code snippet.这是目录为v8/src/runtime/runtime-wasm.cc 的一个 v8 源代码的第二部分，主要包含以下 WebAssembly (Wasm) 运行时函数的实现：

**功能归纳:**

总体来说，这部分代码实现了 V8 引擎中用于支持 WebAssembly 规范的多种运行时函数。这些函数在 Wasm 代码执行期间被调用，用于执行与以下方面相关的操作：

* **代码优化和分层编译:** 触发 Wasm 函数的优化编译 (Tier-Up)。
* **原子操作:**  实现 Wasm 的原子等待操作，用于线程同步。
* **函数引用:**  获取和创建 Wasm 函数的引用。
* **函数表:**  管理 Wasm 的函数表，包括获取、设置、初始化、复制、增长和填充表中的元素。
* **调试:**  支持 Wasm 代码的断点调试。
* **数组:**  实现 Wasm 数组的复制、创建和初始化操作。
* **异步操作:**  支持 Wasm 的异步挂起和恢复机制。
* **类型转换:**  支持特定的 Wasm 类型转换。
* **字符串:**  创建和管理 Wasm 字符串。

**详细功能列表:**

* **`Runtime_WasmTriggerTierUp`:**  触发 WebAssembly 函数的优化编译。当 WebAssembly 代码执行达到一定阈值时，会调用此函数将函数提升到更优化的编译层级 (例如，TurboFan)。
    * **与 JavaScript 的关系:**  虽然这个函数本身不是直接从 JavaScript 调用的，但它影响了 JavaScript 中 WebAssembly 模块的执行性能。当 JavaScript 调用一个 WebAssembly 函数时，V8 内部会根据执行情况决定是否触发 Tier-Up。
    * **代码逻辑推理:**
        * **假设输入:**  一个 `WasmTrustedInstanceData` 对象，代表 Wasm 实例的数据，以及当前执行的 Wasm 函数的索引。
        * **输出:**  无明确的返回值，但会触发后台的优化编译过程。如果开启了同步 Tier-Up (`v8_flags.wasm_sync_tier_up`)，则会立即进行编译。
* **`Runtime_WasmI32AtomicWait` 和 `Runtime_WasmI64AtomicWait`:** 实现 WebAssembly 的原子等待操作。当一个 WebAssembly 线程期望某个共享内存位置的值变为特定值时，它可以调用这些函数进入休眠状态，直到另一个线程唤醒它。
    * **与 JavaScript 的关系:**  这些函数对应于 JavaScript 中 `Atomics.wait()` 方法用于整型值的版本。
    * **JavaScript 示例:**
      ```javascript
      const sab = new SharedArrayBuffer(4);
      const i32a = new Int32Array(sab);
      Atomics.store(i32a, 0, 0);

      // 线程 1
      const result1 = Atomics.wait(i32a, 0, 0, 1000); // 等待 i32a[0] 变为非 0，超时时间 1000ms
      console.log(result1); // 可能输出 "ok" 或 "timed-out"

      // 线程 2
      Atomics.store(i32a, 0, 1);
      Atomics.notify(i32a, 0, 1); // 唤醒等待在 i32a[0] 上的一个线程
      ```
    * **代码逻辑推理:**
        * **假设输入 (`Runtime_WasmI32AtomicWait`):** `WasmTrustedInstanceData`, 内存索引, 偏移量, 期望值 (int32), 超时时间 (BigInt)。
        * **输出:**  一个表示等待结果的值，类似于 `Atomics.wait()` 的返回值（例如，表示成功等待或超时）。
    * **用户常见的编程错误:**
        * 在非共享的 `ArrayBuffer` 上调用 `Atomics.wait()`。
        * 超时时间设置不合理，导致线程意外阻塞。
* **`Runtime_WasmRefFunc`:**  获取一个指向 WebAssembly 函数的引用 (`funcref`)。
    * **与 JavaScript 的关系:**  当 WebAssembly 模块导出函数引用类型时，JavaScript 可以通过此运行时函数获取这些引用。
* **`Runtime_WasmInternalFunctionCreateExternal`:** 创建一个外部的 Wasm 内部函数。
* **`Runtime_WasmFunctionTableGet` 和 `Runtime_WasmFunctionTableSet`:**  分别用于获取和设置 WebAssembly 函数表中的元素。
    * **与 JavaScript 的关系:**  这些函数对应于 JavaScript 中对 `WebAssembly.Table` 对象的操作。
    * **JavaScript 示例:**
      ```javascript
      const table = new WebAssembly.Table({ initial: 1, element: 'funcref' });
      const instance = // ... WebAssembly 实例 ...
      const funcRef = WebAssembly.funcref(instance.exports.someFunction);
      table.set(0, funcRef);
      const retrievedFuncRef = table.get(0);
      ```
    * **代码逻辑推理:**
        * **假设输入 (`Runtime_WasmFunctionTableGet`):** `WasmTrustedInstanceData`, 表索引, 条目索引。
        * **输出:**  函数表中指定索引的函数引用。
    * **用户常见的编程错误:** 访问超出函数表边界的索引。
* **`Runtime_WasmTableInit`, `Runtime_WasmTableCopy`, `Runtime_WasmTableGrow`, `Runtime_WasmTableFill`:**  分别用于初始化、复制、增长和填充 WebAssembly 函数表或其它类型的表。
    * **与 JavaScript 的关系:**  这些函数对应于 JavaScript 中 `WebAssembly.Table` 对象的初始化、grow 和 copy 方法。
    * **JavaScript 示例:**
      ```javascript
      const table = new WebAssembly.Table({ initial: 0, maximum: 10, element: 'anyfunc' });
      const memory = new WebAssembly.Memory({ initial: 1 });
      const buffer = new Uint8Array(memory.buffer);
      const module = new WebAssembly.Module(buffer);
      const instance = new WebAssembly.Instance(module);
      // 假设 exports 中有 'fillTable' 等导出函数调用这些 runtime 函数
      ```
    * **代码逻辑推理:**
        * **假设输入 (`Runtime_WasmTableInit`):** `WasmTrustedInstanceData`, 表索引, 元素段索引, 目标起始索引, 源起始索引, 复制数量。
        * **输出:**  无明确的返回值，但会更新函数表的内容。
    * **用户常见的编程错误:**  在表操作中指定超出边界的索引或复制数量。
* **`Runtime_WasmDebugBreak`:**  在 WebAssembly 代码中插入一个断点，用于调试。
    * **与 JavaScript 的关系:**  当调试器连接到 V8 引擎时，遇到这个运行时函数会触发断点。
* **`Runtime_WasmArrayCopy`:**  复制 WebAssembly 数组的一部分到另一个数组。
    * **与 JavaScript 的关系:**  对应于 WebAssembly 中数组的复制操作。
    * **代码逻辑推理:**
        * **假设输入:** 目标数组, 目标起始索引, 源数组, 源起始索引, 复制长度。
        * **输出:** 无明确的返回值，但目标数组的相应部分会被更新。
    * **用户常见的编程错误:**  复制操作中源或目标索引超出数组边界。
* **`Runtime_WasmArrayNewSegment`:**  创建一个新的 WebAssembly 数组，其数据来源于数据段或元素段。
* **`Runtime_WasmArrayInitSegment`:**  使用数据段或元素段的数据初始化 WebAssembly 数组的一部分。
* **`Runtime_WasmAllocateSuspender`:**  分配一个新的 Wasm 挂起器对象，用于支持异步操作。
* **`Runtime_WasmCastToSpecialPrimitiveArray`:**  将一个 WebAssembly 数组转换为特定的原始类型数组。
* **`Runtime_WasmStringNewWtf8` 和 `Runtime_WasmStringNewWtf8Array`:**  从内存或 WebAssembly 数组中创建 UTF-8 编码的字符串。
* **`Runtime_WasmStringNewWtf16`:**  从内存中创建 UTF-16 编码的字符串。

**关于 `.tq` 后缀:**

代码中没有明显的 `.tq` (Torque) 代码。如果 `v8/src/runtime/runtime-wasm.cc` 以 `.tq` 结尾，那么它将是用 Torque 语言编写的，Torque 是一种用于定义 V8 内部函数的领域特定语言。 Torque 代码会被编译成 C++ 代码。  这部分代码是直接用 C++ 编写的。

总而言之，这部分 `runtime-wasm.cc` 文件是 V8 引擎中 WebAssembly 支持的关键组成部分，它提供了 Wasm 代码在运行时与 V8 引擎和 JavaScript 环境交互所需的底层功能。

### 提示词
```
这是目录为v8/src/runtime/runtime-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
riggerTierUp) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  SealHandleScope shs(isolate);

  {
    DisallowGarbageCollection no_gc;
    DCHECK_EQ(1, args.length());
    Tagged<WasmTrustedInstanceData> trusted_data =
        Cast<WasmTrustedInstanceData>(args[0]);

    FrameFinder<WasmFrame> frame_finder(isolate);
    int func_index = frame_finder.frame()->function_index();
    DCHECK_EQ(trusted_data, frame_finder.frame()->trusted_instance_data());

    if (V8_UNLIKELY(v8_flags.wasm_sync_tier_up)) {
      if (!trusted_data->native_module()->HasCodeWithTier(
              func_index, wasm::ExecutionTier::kTurbofan)) {
        wasm::TierUpNowForTesting(isolate, trusted_data, func_index);
      }
      // We call this function when the tiering budget runs out, so reset that
      // budget to appropriately delay the next call.
      int array_index =
          wasm::declared_function_index(trusted_data->module(), func_index);
      trusted_data->tiering_budget_array()[array_index].store(
          v8_flags.wasm_tiering_budget, std::memory_order_relaxed);
    } else {
      wasm::TriggerTierUp(isolate, trusted_data, func_index);
    }
  }

  // We're reusing this interrupt mechanism to interrupt long-running loops.
  StackLimitCheck check(isolate);
  // We don't need to handle stack overflows here, because the function that
  // performed this runtime call did its own stack check at its beginning.
  // However, we can't DCHECK(!check.JsHasOverflowed()) here, because the
  // additional stack space used by the CEntryStub and this runtime function
  // itself might have pushed us above the limit where a stack check would
  // fail.
  if (check.InterruptRequested()) {
    // Note: This might trigger a GC, which invalidates the {args} object (see
    // https://crbug.com/v8/13036#2).
    Tagged<Object> result = isolate->stack_guard()->HandleInterrupts();
    if (IsException(result)) return result;
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmI32AtomicWait) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  int memory_index = args.smi_value_at(1);
  double offset_double = args.number_value_at(2);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  int32_t expected_value = NumberToInt32(args[3]);
  Tagged<BigInt> timeout_ns = Cast<BigInt>(args[4]);

  Handle<JSArrayBuffer> array_buffer{
      trusted_instance_data->memory_object(memory_index)->array_buffer(),
      isolate};
  // Should have trapped if address was OOB.
  DCHECK_LT(offset, array_buffer->byte_length());

  // Trap if memory is not shared, or wait is not allowed on the isolate
  if (!array_buffer->is_shared() || !isolate->allow_atomics_wait()) {
    return ThrowWasmError(
        isolate, MessageTemplate::kAtomicsOperationNotAllowed,
        {isolate->factory()->NewStringFromAsciiChecked("Atomics.wait")});
  }
  return FutexEmulation::WaitWasm32(isolate, array_buffer, offset,
                                    expected_value, timeout_ns->AsInt64());
}

RUNTIME_FUNCTION(Runtime_WasmI64AtomicWait) {
  ClearThreadInWasmScope clear_wasm_flag(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  int memory_index = args.smi_value_at(1);
  double offset_double = args.number_value_at(2);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  Tagged<BigInt> expected_value = Cast<BigInt>(args[3]);
  Tagged<BigInt> timeout_ns = Cast<BigInt>(args[4]);

  Handle<JSArrayBuffer> array_buffer{
      trusted_instance_data->memory_object(memory_index)->array_buffer(),
      isolate};
  // Should have trapped if address was OOB.
  DCHECK_LT(offset, array_buffer->byte_length());

  // Trap if memory is not shared, or if wait is not allowed on the isolate
  if (!array_buffer->is_shared() || !isolate->allow_atomics_wait()) {
    return ThrowWasmError(
        isolate, MessageTemplate::kAtomicsOperationNotAllowed,
        {isolate->factory()->NewStringFromAsciiChecked("Atomics.wait")});
  }
  return FutexEmulation::WaitWasm64(isolate, array_buffer, offset,
                                    expected_value->AsInt64(),
                                    timeout_ns->AsInt64());
}

namespace {
Tagged<Object> ThrowTableOutOfBounds(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data) {
  // Handle out-of-bounds access here in the runtime call, rather
  // than having the lower-level layers deal with JS exceptions.
  if (isolate->context().is_null()) {
    isolate->set_context(trusted_instance_data->native_context());
  }
  return ThrowWasmError(isolate, MessageTemplate::kWasmTrapTableOutOfBounds);
}
}  // namespace

RUNTIME_FUNCTION(Runtime_WasmRefFunc) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t function_index = args.positive_smi_value_at(1);

  return *WasmTrustedInstanceData::GetOrCreateFuncRef(
      isolate, trusted_instance_data, function_index);
}

RUNTIME_FUNCTION(Runtime_WasmInternalFunctionCreateExternal) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  // TODO(14564): Pass WasmFuncRef here instead of WasmInternalFunction.
  DirectHandle<WasmInternalFunction> internal(
      Cast<WasmInternalFunction>(args[0]), isolate);
  return *WasmInternalFunction::GetOrCreateExternal(internal);
}

RUNTIME_FUNCTION(Runtime_WasmFunctionTableGet) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t entry_index = args.positive_smi_value_at(2);
  DCHECK_LT(table_index, trusted_instance_data->tables()->length());
  auto table = handle(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);
  // We only use the runtime call for lazily initialized function references.
  DCHECK(
      !table->has_trusted_data()
          ? table->type() == wasm::kWasmFuncRef
          : (IsSubtypeOf(table->type(), wasm::kWasmFuncRef,
                         table->trusted_data(isolate)->module()) ||
             IsSubtypeOf(table->type(),
                         wasm::ValueType::RefNull(wasm::HeapType::kFuncShared),
                         table->trusted_data(isolate)->module())));

  if (!table->is_in_bounds(entry_index)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapTableOutOfBounds);
  }

  return *WasmTableObject::Get(isolate, table, entry_index);
}

RUNTIME_FUNCTION(Runtime_WasmFunctionTableSet) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t entry_index = args.positive_smi_value_at(2);
  DirectHandle<Object> element(args[3], isolate);
  DCHECK_LT(table_index, trusted_instance_data->tables()->length());
  auto table = handle(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);
  // We only use the runtime call for lazily initialized function references.
  DCHECK(
      !table->has_trusted_data()
          ? table->type() == wasm::kWasmFuncRef
          : (IsSubtypeOf(table->type(), wasm::kWasmFuncRef,
                         table->trusted_data(isolate)->module()) ||
             IsSubtypeOf(table->type(),
                         wasm::ValueType::RefNull(wasm::HeapType::kFuncShared),
                         table->trusted_data(isolate)->module())));

  if (!table->is_in_bounds(entry_index)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapTableOutOfBounds);
  }
  WasmTableObject::Set(isolate, table, entry_index, element);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTableInit) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  Handle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t elem_segment_index = args.positive_smi_value_at(2);
  static_assert(
      wasm::kV8MaxWasmTableSize < kSmiMaxValue,
      "Make sure clamping to Smi range doesn't make an invalid call valid");
  uint32_t dst = args.positive_smi_value_at(3);
  uint32_t src = args.positive_smi_value_at(4);
  uint32_t count = args.positive_smi_value_at(5);

  DCHECK(!isolate->context().is_null());

  // TODO(14616): Pass the correct instance data.
  std::optional<MessageTemplate> opt_error =
      WasmTrustedInstanceData::InitTableEntries(
          isolate, trusted_instance_data, trusted_instance_data, table_index,
          elem_segment_index, dst, src, count);
  if (opt_error.has_value()) {
    return ThrowWasmError(isolate, opt_error.value());
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTableCopy) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t table_dst_index = args.positive_smi_value_at(1);
  uint32_t table_src_index = args.positive_smi_value_at(2);
  static_assert(
      wasm::kV8MaxWasmTableSize < kSmiMaxValue,
      "Make sure clamping to Smi range doesn't make an invalid call valid");
  uint32_t dst = args.positive_smi_value_at(3);
  uint32_t src = args.positive_smi_value_at(4);
  uint32_t count = args.positive_smi_value_at(5);

  DCHECK(!isolate->context().is_null());

  bool oob = !WasmTrustedInstanceData::CopyTableEntries(
      isolate, trusted_instance_data, table_dst_index, table_src_index, dst,
      src, count);
  if (oob) return ThrowTableOutOfBounds(isolate, trusted_instance_data);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTableGrow) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK(isolate->IsOnCentralStack());
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t table_index = args.positive_smi_value_at(1);
  DirectHandle<Object> value(args[2], isolate);
  uint32_t delta = args.positive_smi_value_at(3);

  DirectHandle<WasmTableObject> table(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);
  int result = WasmTableObject::Grow(isolate, table, delta, value);

  return Smi::FromInt(result);
}

RUNTIME_FUNCTION(Runtime_WasmTableFill) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t table_index = args.positive_smi_value_at(1);
  uint32_t start = args.positive_smi_value_at(2);
  DirectHandle<Object> value(args[3], isolate);
  uint32_t count = args.positive_smi_value_at(4);

  DirectHandle<WasmTableObject> table(
      Cast<WasmTableObject>(trusted_instance_data->tables()->get(table_index)),
      isolate);

  uint32_t table_size = table->current_length();

  if (start > table_size) {
    return ThrowTableOutOfBounds(isolate, trusted_instance_data);
  }

  // Even when table.fill goes out-of-bounds, as many entries as possible are
  // put into the table. Only afterwards we trap.
  uint32_t fill_count = std::min(count, table_size - start);
  if (fill_count < count) {
    return ThrowTableOutOfBounds(isolate, trusted_instance_data);
  }
  WasmTableObject::Fill(isolate, table, start, value, fill_count);

  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {
// Returns true if any breakpoint was hit, false otherwise.
bool ExecuteWasmDebugBreaks(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    WasmFrame* frame) {
  DirectHandle<Script> script{trusted_instance_data->module_object()->script(),
                              isolate};
  auto* debug_info = trusted_instance_data->native_module()->GetDebugInfo();

  // Enter the debugger.
  DebugScope debug_scope(isolate->debug());

  // Check for instrumentation breakpoints first, but still execute regular
  // breakpoints afterwards.
  bool paused_on_instrumentation = false;
  DCHECK_EQ(script->break_on_entry(),
            !!trusted_instance_data->break_on_entry());
  if (script->break_on_entry()) {
    MaybeHandle<FixedArray> maybe_on_entry_breakpoints =
        WasmScript::CheckBreakPoints(isolate, script,
                                     WasmScript::kOnEntryBreakpointPosition,
                                     frame->id());
    script->set_break_on_entry(false);
    // Update the "break_on_entry" flag on all live instances.
    i::Tagged<i::WeakArrayList> weak_instance_list =
        script->wasm_weak_instance_list();
    for (int i = 0; i < weak_instance_list->length(); ++i) {
      if (weak_instance_list->Get(i).IsCleared()) continue;
      i::Cast<i::WasmInstanceObject>(weak_instance_list->Get(i).GetHeapObject())
          ->trusted_data(isolate)
          ->set_break_on_entry(false);
    }
    DCHECK(!trusted_instance_data->break_on_entry());
    if (!maybe_on_entry_breakpoints.is_null()) {
      isolate->debug()->OnInstrumentationBreak();
      paused_on_instrumentation = true;
    }
  }

  if (debug_info->IsStepping(frame) && !debug_info->IsFrameBlackboxed(frame)) {
    debug_info->ClearStepping(isolate);
    StepAction step_action = isolate->debug()->last_step_action();
    isolate->debug()->ClearStepping();
    isolate->debug()->OnDebugBreak(isolate->factory()->empty_fixed_array(),
                                   step_action);
    return true;
  }

  // Check whether we hit a breakpoint.
  Handle<FixedArray> breakpoints;
  if (WasmScript::CheckBreakPoints(isolate, script, frame->position(),
                                   frame->id())
          .ToHandle(&breakpoints)) {
    debug_info->ClearStepping(isolate);
    StepAction step_action = isolate->debug()->last_step_action();
    isolate->debug()->ClearStepping();
    if (isolate->debug()->break_points_active()) {
      // We hit one or several breakpoints. Notify the debug listeners.
      isolate->debug()->OnDebugBreak(breakpoints, step_action);
    }
    return true;
  }

  return paused_on_instrumentation;
}
}  // namespace

RUNTIME_FUNCTION(Runtime_WasmDebugBreak) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  FrameFinder<WasmFrame> frame_finder(
      isolate, {StackFrame::EXIT, StackFrame::WASM_DEBUG_BREAK});
  WasmFrame* frame = frame_finder.frame();
  DirectHandle<WasmTrustedInstanceData> trusted_data{
      frame->trusted_instance_data(), isolate};
  isolate->set_context(trusted_data->native_context());

  if (!ExecuteWasmDebugBreaks(isolate, trusted_data, frame)) {
    // We did not hit a breakpoint. If we are in stepping code, but the user did
    // not request stepping, clear this (to save further calls into this runtime
    // function).
    auto* debug_info = trusted_data->native_module()->GetDebugInfo();
    debug_info->ClearStepping(frame);
  }

  // Execute a stack check before leaving this function. This is to handle any
  // interrupts set by the debugger (e.g. termination), but also to execute Wasm
  // code GC to get rid of temporarily created Wasm code.
  StackLimitCheck check(isolate);
  if (check.InterruptRequested()) {
    Tagged<Object> interrupt_object =
        isolate->stack_guard()->HandleInterrupts();
    // Interrupt handling can create an exception, including the
    // termination exception.
    if (IsException(interrupt_object, isolate)) return interrupt_object;
    DCHECK(IsUndefined(interrupt_object, isolate));
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// Assumes copy ranges are in-bounds and copy length > 0.
// TODO(manoskouk): Unify part of this with the implementation in
// wasm-extern-refs.cc
RUNTIME_FUNCTION(Runtime_WasmArrayCopy) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(5, args.length());
  Tagged<WasmArray> dst_array = Cast<WasmArray>(args[0]);
  uint32_t dst_index = args.positive_smi_value_at(1);
  Tagged<WasmArray> src_array = Cast<WasmArray>(args[2]);
  uint32_t src_index = args.positive_smi_value_at(3);
  uint32_t length = args.positive_smi_value_at(4);
  DCHECK_GT(length, 0);
  bool overlapping_ranges =
      dst_array.ptr() == src_array.ptr() &&
      (dst_index < src_index ? dst_index + length > src_index
                             : src_index + length > dst_index);
  wasm::ValueType element_type = src_array->type()->element_type();
  if (element_type.is_reference()) {
    ObjectSlot dst_slot = dst_array->ElementSlot(dst_index);
    ObjectSlot src_slot = src_array->ElementSlot(src_index);
    if (overlapping_ranges) {
      isolate->heap()->MoveRange(dst_array, dst_slot, src_slot, length,
                                 UPDATE_WRITE_BARRIER);
    } else {
      isolate->heap()->CopyRange(dst_array, dst_slot, src_slot, length,
                                 UPDATE_WRITE_BARRIER);
    }
  } else {
    void* dst = reinterpret_cast<void*>(dst_array->ElementAddress(dst_index));
    void* src = reinterpret_cast<void*>(src_array->ElementAddress(src_index));
    size_t copy_size = length * element_type.value_kind_size();
    if (overlapping_ranges) {
      MemMove(dst, src, copy_size);
    } else {
      MemCopy(dst, src, copy_size);
    }
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmArrayNewSegment) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Handle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t segment_index = args.positive_smi_value_at(1);
  uint32_t offset = args.positive_smi_value_at(2);
  uint32_t length = args.positive_smi_value_at(3);
  DirectHandle<Map> rtt(Cast<Map>(args[4]), isolate);

  wasm::ArrayType* type =
      reinterpret_cast<wasm::ArrayType*>(rtt->wasm_type_info()->native_type());

  uint32_t element_size = type->element_type().value_kind_size();
  // This check also implies no overflow.
  if (length > static_cast<uint32_t>(WasmArray::MaxLength(element_size))) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapArrayTooLarge);
  }

  if (type->element_type().is_numeric()) {
    // No chance of overflow due to the check above.
    uint32_t length_in_bytes = length * element_size;

    if (!base::IsInBounds<uint32_t>(
            offset, length_in_bytes,
            trusted_instance_data->data_segment_sizes()->get(segment_index))) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapDataSegmentOutOfBounds);
    }

    Address source =
        trusted_instance_data->data_segment_starts()->get(segment_index) +
        offset;
    return *isolate->factory()->NewWasmArrayFromMemory(length, rtt, source);
  } else {
    Handle<Object> elem_segment_raw = handle(
        trusted_instance_data->element_segments()->get(segment_index), isolate);
    const wasm::WasmElemSegment* module_elem_segment =
        &trusted_instance_data->module()->elem_segments[segment_index];
    // If the segment is initialized in the instance, we have to get its length
    // from there, as it might have been dropped. If the segment is
    // uninitialized, we need to fetch its length from the module.
    int segment_length = IsFixedArray(*elem_segment_raw)
                             ? Cast<FixedArray>(elem_segment_raw)->length()
                             : module_elem_segment->element_count;
    if (!base::IsInBounds<size_t>(offset, length, segment_length)) {
      return ThrowWasmError(
          isolate, MessageTemplate::kWasmTrapElementSegmentOutOfBounds);
    }
    // TODO(14616): Pass the correct instance data.
    DirectHandle<Object> result =
        isolate->factory()->NewWasmArrayFromElementSegment(
            trusted_instance_data, trusted_instance_data, segment_index, offset,
            length, rtt);
    if (IsSmi(*result)) {
      return ThrowWasmError(
          isolate, static_cast<MessageTemplate>(Cast<Smi>(*result).value()));
    } else {
      return *result;
    }
  }
}

RUNTIME_FUNCTION(Runtime_WasmArrayInitSegment) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  Handle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t segment_index = args.positive_smi_value_at(1);
  DirectHandle<WasmArray> array(Cast<WasmArray>(args[2]), isolate);
  uint32_t array_index = args.positive_smi_value_at(3);
  uint32_t segment_offset = args.positive_smi_value_at(4);
  uint32_t length = args.positive_smi_value_at(5);

  wasm::ArrayType* type = reinterpret_cast<wasm::ArrayType*>(
      array->map()->wasm_type_info()->native_type());

  uint32_t element_size = type->element_type().value_kind_size();

  if (type->element_type().is_numeric()) {
    if (!base::IsInBounds<uint32_t>(array_index, length, array->length())) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapArrayOutOfBounds);
    }

    // No chance of overflow, due to the check above and the limit in array
    // length.
    uint32_t length_in_bytes = length * element_size;

    if (!base::IsInBounds<uint32_t>(
            segment_offset, length_in_bytes,
            trusted_instance_data->data_segment_sizes()->get(segment_index))) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapDataSegmentOutOfBounds);
    }

    Address source =
        trusted_instance_data->data_segment_starts()->get(segment_index) +
        segment_offset;
    Address dest = array->ElementAddress(array_index);
#if V8_TARGET_BIG_ENDIAN
    MemCopyAndSwitchEndianness(reinterpret_cast<void*>(dest),
                               reinterpret_cast<void*>(source), length,
                               element_size);
#else
    MemCopy(reinterpret_cast<void*>(dest), reinterpret_cast<void*>(source),
            length_in_bytes);
#endif
    return *isolate->factory()->undefined_value();
  } else {
    Handle<Object> elem_segment_raw = handle(
        trusted_instance_data->element_segments()->get(segment_index), isolate);
    const wasm::WasmElemSegment* module_elem_segment =
        &trusted_instance_data->module()->elem_segments[segment_index];
    // If the segment is initialized in the instance, we have to get its length
    // from there, as it might have been dropped. If the segment is
    // uninitialized, we need to fetch its length from the module.
    int segment_length = IsFixedArray(*elem_segment_raw)
                             ? Cast<FixedArray>(elem_segment_raw)->length()
                             : module_elem_segment->element_count;
    if (!base::IsInBounds<size_t>(segment_offset, length, segment_length)) {
      return ThrowWasmError(
          isolate, MessageTemplate::kWasmTrapElementSegmentOutOfBounds);
    }
    if (!base::IsInBounds(array_index, length, array->length())) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapArrayOutOfBounds);
    }

    // If the element segment has not been initialized yet, lazily initialize it
    // now.
    AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    // TODO(14616): Fix the instance data.
    std::optional<MessageTemplate> opt_error =
        wasm::InitializeElementSegment(&zone, isolate, trusted_instance_data,
                                       trusted_instance_data, segment_index);
    if (opt_error.has_value()) {
      return ThrowWasmError(isolate, opt_error.value());
    }

    auto elements = handle(
        Cast<FixedArray>(
            trusted_instance_data->element_segments()->get(segment_index)),
        isolate);
    if (length > 0) {
      isolate->heap()->CopyRange(*array, array->ElementSlot(array_index),
                                 elements->RawFieldOfElementAt(segment_offset),
                                 length, UPDATE_WRITE_BARRIER);
    }
    return *isolate->factory()->undefined_value();
  }
}

// Allocate a new suspender, and prepare for stack switching by updating the
// active continuation, active suspender and stack limit.
RUNTIME_FUNCTION(Runtime_WasmAllocateSuspender) {
  HandleScope scope(isolate);
  DirectHandle<WasmSuspenderObject> suspender =
      isolate->factory()->NewWasmSuspenderObject();

  // Update the continuation state.
  auto parent = handle(Cast<WasmContinuationObject>(
                           isolate->root(RootIndex::kActiveContinuation)),
                       isolate);
  std::unique_ptr<wasm::StackMemory> target_stack =
      isolate->stack_pool().GetOrAllocate();
  DirectHandle<WasmContinuationObject> target = WasmContinuationObject::New(
      isolate, target_stack.get(), wasm::JumpBuffer::Suspended, parent);
  target_stack->set_index(isolate->wasm_stacks().size());
  isolate->wasm_stacks().emplace_back(std::move(target_stack));
  for (size_t i = 0; i < isolate->wasm_stacks().size(); ++i) {
    SLOW_DCHECK(isolate->wasm_stacks()[i]->index() == i);
  }
  isolate->roots_table().slot(RootIndex::kActiveContinuation).store(*target);

  // Update the suspender state.
  FullObjectSlot active_suspender_slot =
      isolate->roots_table().slot(RootIndex::kActiveSuspender);
  suspender->set_parent(
      Cast<UnionOf<Undefined, WasmSuspenderObject>>(*active_suspender_slot));
  suspender->set_state(WasmSuspenderObject::kActive);
  suspender->set_continuation(*target);
  active_suspender_slot.store(*suspender);

  // Stack limit will be updated in WasmReturnPromiseOnSuspendAsm builtin.
  wasm::JumpBuffer* jmpbuf = reinterpret_cast<wasm::JumpBuffer*>(
      parent->ReadExternalPointerField<kWasmContinuationJmpbufTag>(
          WasmContinuationObject::kJmpbufOffset, isolate));
  DCHECK_EQ(jmpbuf->state, wasm::JumpBuffer::Active);
  jmpbuf->state = wasm::JumpBuffer::Inactive;
  return *suspender;
}

#define RETURN_RESULT_OR_TRAP(call)                                            \
  do {                                                                         \
    Handle<Object> result;                                                     \
    if (!(call).ToHandle(&result)) {                                           \
      DCHECK(isolate->has_exception());                                        \
      /* Mark any exception as uncatchable by Wasm. */                         \
      Handle<JSObject> exception(Cast<JSObject>(isolate->exception()),         \
                                 isolate);                                     \
      Handle<Name> uncatchable =                                               \
          isolate->factory()->wasm_uncatchable_symbol();                       \
      LookupIterator it(isolate, exception, uncatchable, LookupIterator::OWN); \
      if (!JSReceiver::HasProperty(&it).FromJust()) {                          \
        JSObject::AddProperty(isolate, exception, uncatchable,                 \
                              isolate->factory()->true_value(), NONE);         \
      }                                                                        \
      return ReadOnlyRoots(isolate).exception();                               \
    }                                                                          \
    DCHECK(!isolate->has_exception());                                         \
    return *result;                                                            \
  } while (false)

// "Special" because the type must be in a recgroup of its own.
// Used by "JS String Builtins".
RUNTIME_FUNCTION(Runtime_WasmCastToSpecialPrimitiveArray) {
  ClearThreadInWasmScope flag_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());

  int bits = args.smi_value_at(1);
  DCHECK(bits == 8 || bits == 16);

  if (args[0] == ReadOnlyRoots(isolate).null_value()) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapNullDereference);
  }
  MessageTemplate illegal_cast = MessageTemplate::kWasmTrapIllegalCast;
  if (!IsWasmArray(args[0])) return ThrowWasmError(isolate, illegal_cast);
  Tagged<WasmArray> obj = Cast<WasmArray>(args[0]);
  Tagged<WasmTypeInfo> wti = obj->map()->wasm_type_info();
  const wasm::WasmModule* module = wti->trusted_data(isolate)->module();
  wasm::ModuleTypeIndex type_index = wti->type_index();
  DCHECK(module->has_array(type_index));
  wasm::CanonicalTypeIndex expected =
      bits == 8 ? wasm::TypeCanonicalizer::kPredefinedArrayI8Index
                : wasm::TypeCanonicalizer::kPredefinedArrayI16Index;
  if (module->canonical_type_id(type_index) != expected) {
    return ThrowWasmError(isolate, illegal_cast);
  }
  return obj;
}

// Returns the new string if the operation succeeds.  Otherwise throws an
// exception and returns an empty result.
RUNTIME_FUNCTION(Runtime_WasmStringNewWtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(5, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t memory = args.positive_smi_value_at(1);
  uint32_t utf8_variant_value = args.positive_smi_value_at(2);
  double offset_double = args.number_value_at(3);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  uint32_t size = NumberToUint32(args[4]);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));

  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);

  uint64_t mem_size = trusted_instance_data->memory_size(memory);
  if (!base::IsInBounds<uint64_t>(offset, size, mem_size)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapMemOutOfBounds);
  }

  const base::Vector<const uint8_t> bytes{
      trusted_instance_data->memory_base(memory) + offset, size};
  MaybeHandle<v8::internal::String> result_string =
      isolate->factory()->NewStringFromUtf8(bytes, utf8_variant);
  if (utf8_variant == unibrow::Utf8Variant::kUtf8NoTrap) {
    DCHECK(!isolate->has_exception());
    if (result_string.is_null()) {
      return *isolate->factory()->wasm_null();
    }
    return *result_string.ToHandleChecked();
  }
  RETURN_RESULT_OR_TRAP(result_string);
}

RUNTIME_FUNCTION(Runtime_WasmStringNewWtf8Array) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(4, args.length());
  HandleScope scope(isolate);
  uint32_t utf8_variant_value = args.positive_smi_value_at(0);
  DirectHandle<WasmArray> array(Cast<WasmArray>(args[1]), isolate);
  uint32_t start = NumberToUint32(args[2]);
  uint32_t end = NumberToUint32(args[3]);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));
  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);

  MaybeHandle<v8::internal::String> result_string =
      isolate->factory()->NewStringFromUtf8(array, start, end, utf8_variant);
  if (utf8_variant == unibrow::Utf8Variant::kUtf8NoTrap) {
    DCHECK(!isolate->has_exception());
    if (result_string.is_null()) {
      return *isolate->factory()->wasm_null();
    }
    return *result_string.ToHandleChecked();
  }
  RETURN_RESULT_OR_TRAP(result_string);
}

RUNTIME_FUNCTION(Runtime_WasmStringNewWtf16) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(4, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t memory = args.positive_smi_value_at(1);
  double offset_double = args.number_value_at(2);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  uint32_t size_in_codeunits = NumberToUint32(args[3]);

  uint64_t mem_size = trusted_instance_data->memory_size(memory);
  if (size_in_codeunits > kMaxUInt32 / 2 ||
      !base::IsInBounds<uint64_t>(offset, size_in_co
```