Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter-runtime.cc`. I need to go through each method and understand its purpose within the context of the WebAssembly interpreter in V8.

Here's a breakdown of the methods and their likely functions:

*   **`WasmArrayNew`**:  Creates a new uninitialized WebAssembly array.
*   **`WasmArrayNewFixed`**: Creates a new WebAssembly array with a given length and pre-filled with default values.
*   **`WasmArrayNewSegment`**: Creates a new WebAssembly array and initializes it with data from a segment.
*   **`WasmArrayInitSegment`**: Initializes a portion of an existing WebAssembly array with data from a segment.
*   **`WasmArrayCopy`**: Copies elements from one WebAssembly array to another.
*   **`WasmJSToWasmObject`**: Converts a JavaScript object reference to a WebAssembly object reference.
*   **`JSToWasmObject`**: Similar to `WasmJSToWasmObject`, likely with additional checks and handling of canonical type IDs.
*   **`WasmToJSObject`**: Converts a WebAssembly object reference to a JavaScript object reference.
*   **`SubtypeCheck` (two overloads)**: Checks if a given WebAssembly object or RTT (Runtime Type) is a subtype of another RTT. This is crucial for type safety in WebAssembly.
*   **`RefIsEq`**, **`RefIsI31`**, **`RefIsStruct`**, **`RefIsArray`**, **`RefIsString`**: These appear to be type checking functions for WebAssembly references, determining if a reference is of a specific type (e.g., an i31, a struct, an array, a string).
*   **`SetTrap` (two overloads)**:  Handles trapping during WebAssembly execution, likely recording the reason and location of the trap.
*   **`ResetCurrentHandleScope`**: Resets the current handle scope, likely used for managing V8's garbage-collected objects.
*   **`GetInterpretedStack`**: Retrieves the current execution stack of the WebAssembly interpreter.
*   **`GetFunctionIndex`**:  Gets the function index for a given stack frame.
*   **`SetTrapFunctionIndex`**: Sets the index of the function where a trap occurred.
*   **`PrintStack`**:  Likely used for debugging purposes, printing the current state of the interpreter's stack.
*   **`GetTracer`**, **`Trace`**:  Used for tracing the execution of the interpreter, helpful for debugging and performance analysis.
*   **`GetBytes`**: A static helper function to get the raw byte code of a WebAssembly module.
*   **`InterpreterHandle` (constructor)**: Initializes an `InterpreterHandle`, which manages the execution of a WebAssembly instance.
*   **`RunExecutionLoop`**: The main loop of the WebAssembly interpreter, driving the execution of bytecode.
*   **`Execute` (two overloads)**:  Initiates the execution of a WebAssembly function, both when called from JavaScript and from within WebAssembly itself.
*   **`GetInstanceObject`**: Retrieves the `WasmInstanceObject` associated with the current interpreter.
*   **`GetInterpretedStack`**:  A wrapper around the runtime's `GetInterpretedStack`.
*   **`GetFunctionIndex`**: A wrapper around the runtime's `GetFunctionIndex`.
*   **`SetTrapFunctionIndex`**: A wrapper around the runtime's `SetTrapFunctionIndex`.

Based on this analysis, the primary function of `wasm-interpreter-runtime.cc` is to provide the runtime support for the WebAssembly interpreter in V8. It handles object creation, type checking, function execution, and error handling (trapping).

Regarding the specific questions:

*   **`.tq` extension**: The code is C++, so it's not a Torque file.
*   **JavaScript relation**: Many of these functions relate to the interaction between JavaScript and WebAssembly, specifically the conversion of objects between the two environments.
*   **Code logic推理**: The type checking and array manipulation functions have clear logic.
*   **User errors**: Type casting and array manipulation are common areas for errors.

Let's synthesize this into the final response.
这是v8源代码文件 `v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 的第四部分，总结一下它的功能：

**核心功能概括:**

`wasm-interpreter-runtime.cc` 实现了 WebAssembly 解释器的运行时支持。它提供了一系列 C++ 函数，这些函数在 WebAssembly 解释器执行过程中被调用，用于处理诸如对象创建、类型转换、类型检查、数组操作以及错误处理 (trapping) 等底层操作。 这些函数是连接 WebAssembly 虚拟机和 V8 JavaScript 引擎的桥梁。

**具体功能列表 (基于提供的代码片段):**

*   **创建 WebAssembly 数组:**
    *   `WasmArrayNew`: 创建一个指定长度和 RTT (Runtime Type) 的未初始化 WebAssembly 数组。
    *   `WasmArrayNewFixed`: 创建一个指定长度、RTT 和初始值的 WebAssembly 数组。
    *   `WasmArrayNewSegment`: 创建一个 WebAssembly 数组，并使用来自 Memory Segment 的数据进行初始化。
*   **初始化 WebAssembly 数组段:**
    *   `WasmArrayInitSegment`: 将 Memory Segment 中的数据复制到现有的 WebAssembly 数组的指定位置。
*   **复制 WebAssembly 数组:**
    *   `WasmArrayCopy`: 将一个 WebAssembly 数组的一部分复制到另一个 WebAssembly 数组的指定位置。
*   **JavaScript 和 WebAssembly 对象之间的转换:**
    *   `WasmJSToWasmObject`: 将 JavaScript 对象引用转换为 WebAssembly 对象引用。这可能涉及到类型检查和转换。
    *   `JSToWasmObject`: 类似于 `WasmJSToWasmObject`，可能包含更复杂的类型处理逻辑，例如处理同构递归类型 ID。如果转换失败，它会抛出 JavaScript 异常。
    *   `WasmToJSObject`: 将 WebAssembly 对象引用转换为 JavaScript 对象引用。它会处理 `funcref` 和 `externref` 等特殊类型。
*   **WebAssembly 类型检查:**
    *   `SubtypeCheck` (两个重载):  用于检查一个 WebAssembly 对象的类型 (RTT) 是否是另一个类型的子类型。这对于保证 WebAssembly 的类型安全至关重要。
    *   `RefIsEq`, `RefIsI31`, `RefIsStruct`, `RefIsArray`, `RefIsString`:  提供了一系列函数来检查 WebAssembly 引用是否属于特定的类型（例如，是否为 `i31ref`, `structref`, `arrayref`, `stringref`）。
*   **WebAssembly 陷阱 (Trap) 处理:**
    *   `SetTrap` (两个重载):  当 WebAssembly 代码执行过程中发生错误（例如，除零错误，越界访问）时，会调用这些函数来记录陷阱的原因和发生位置，并触发相应的错误处理机制。
    *   `SetTrapFunctionIndex`: 设置发生陷阱的函数索引。
*   **解释器状态管理:**
    *   `ResetCurrentHandleScope`: 重置当前的 V8 HandleScope，用于管理 V8 的垃圾回收对象。
    *   `GetInterpretedStack`: 获取当前 WebAssembly 解释器的调用栈信息，用于调试和错误报告。
    *   `GetFunctionIndex`:  获取指定栈帧的函数索引。
*   **解释器执行控制:**
    *   `InterpreterHandle::RunExecutionLoop`:  解释器的主要执行循环，负责逐条执行 WebAssembly 指令。
    *   `InterpreterHandle::Execute` (两个重载):  启动 WebAssembly 函数的执行。一个版本用于从 JavaScript 调用 WebAssembly 函数，另一个版本用于在解释器内部调用。
*   **调试和跟踪:**
    *   `PrintStack`:  打印当前的解释器栈信息，用于调试。
    *   `GetTracer`, `Trace`:  用于在解释器执行过程中输出跟踪信息，辅助调试和性能分析。
*   **获取 WebAssembly 实例:**
    *   `InterpreterHandle::GetInstanceObject`: 获取与当前解释器关联的 `WasmInstanceObject`。
*   **获取模块字节码:**
    *   `InterpreterHandle::GetBytes`: (静态方法) 获取 WebAssembly 模块的原始字节码。

**关于其他问题的回答:**

*   **.tq 结尾:**  代码片段是以 `.cc` 结尾的，所以它不是 v8 Torque 源代码。Torque 源代码文件以 `.tq` 结尾。
*   **与 JavaScript 的关系:**  代码中 `WasmJSToWasmObject` 和 `JSToWasmObject` 函数明确处理了从 JavaScript 对象到 WebAssembly 对象的转换。`WasmToJSObject` 则进行反向转换。

    **JavaScript 示例:**

    ```javascript
    // 假设有一个已编译的 WebAssembly 模块实例 'wasmInstance'
    const arrayRtt = wasmInstance.exports.get_array_rtt(); // 假设导出了一个 Array RTT
    const newArray = wasmInstance.exports.create_wasm_array(10, arrayRtt); // 调用 WebAssembly 函数创建数组

    // 这里内部会调用 C++ 的 WasmArrayNew 或类似函数

    const jsObject = { value: 123 };
    wasmInstance.exports.process_js_object(jsObject); // 传递 JavaScript 对象到 WebAssembly

    // 这里内部可能会调用 C++ 的 JSToWasmObject 或类似函数，将 jsObject 转换为 wasm 的 externref 或其他类型
    ```

*   **代码逻辑推理 (假设输入与输出):**

    **假设输入 (WasmArrayCopy):**
    *   `dest_wasm_array`:  一个长度为 5 的 WebAssembly 数组 `[0, 0, 0, 0, 0]`
    *   `dest_index`: 1
    *   `src_wasm_array`: 一个长度为 3 的 WebAssembly 数组 `[10, 20, 30]`
    *   `src_index`: 0
    *   `length`: 2

    **输出:**
    *   `dest_wasm_array` 将变为 `[0, 10, 20, 0, 0]`

*   **用户常见的编程错误:**

    *   **类型转换错误:**  在 JavaScript 和 WebAssembly 之间传递对象时，类型不匹配会导致错误。例如，尝试将一个普通的 JavaScript 对象直接传递给期望特定 WebAssembly 类型的函数。

        ```javascript
        // WebAssembly 期望一个 i32 类型的参数
        wasmInstance.exports.process_number("not a number"); // 错误: 传递了字符串
        ```

    *   **数组越界访问:** 在 WebAssembly 中操作数组时，访问超出数组边界的索引。

        ```javascript
        const arrayRtt = wasmInstance.exports.get_array_rtt();
        const myArray = wasmInstance.exports.create_wasm_array(5, arrayRtt);
        wasmInstance.exports.access_array(myArray, 10); // 错误: 索引 10 超出了数组边界
        ```

**总结:**

`v8/src/wasm/interpreter/wasm-interpreter-runtime.cc` 的主要职责是为 V8 的 WebAssembly 解释器提供必要的运行时支持，包括对象生命周期管理、类型系统实现、以及与 JavaScript 互操作的桥梁。它包含了一系列底层的 C++ 函数，这些函数处理 WebAssembly 执行过程中各种关键操作。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter-runtime.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
<Map> rtt = RttCanon(array_index);
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