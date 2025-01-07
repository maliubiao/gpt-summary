Response:
The user wants a summary of the functionalities of the provided C++ code snippet. The code is from `v8/src/wasm/baseline/liftoff-compiler.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core functionality:** The file name `liftoff-compiler.cc` strongly suggests that this code is part of the Liftoff compiler, a baseline compiler for WebAssembly in V8.

2. **Analyze the code structure and key methods:** Scan the code for prominent methods and their actions.
    * `TierUpCheck`:  Related to tiering up to a more optimized compiler.
    * `SpillLocalsInitially`: Deals with placing local variables on the stack or in registers.
    * `TraceFunctionEntry`: Likely used for debugging and logging function entry.
    * `StartFunctionBody`:  Sets up the function execution environment (stack frame, parameter processing, local initialization).
    * `GenerateOutOfLineCode`: Handles code that is not in the main execution path (e.g., stack checks, traps).
    * `FinishFunction`: Completes the function compilation process.
    * `CheckMaxSteps`:  Used for debugging and limiting execution steps.
    * `EmitDebuggingInfo`, `EmitBreakpoint`:  Functions related to debugging.
    * `PushControl`, `Block`, `Loop`, `Try`, `CatchException`, `Rethrow`, `Delegate`, `CatchAll`, `TryTable`, `CatchCase`: These methods clearly correspond to WebAssembly control flow instructions (block, loop, try-catch, etc.).

3. **Categorize the functionalities:** Group the observed functionalities into logical categories:
    * **Tiering:**  The `TierUpCheck` method directly points to this.
    * **Local Variable Management:**  `SpillLocalsInitially` and the local variable initialization in `StartFunctionBody`.
    * **Function Entry/Exit:** `TraceFunctionEntry`, `StartFunctionBody`, `FinishFunction`.
    * **Out-of-line Code Handling:**  `GenerateOutOfLineCode`.
    * **Debugging Support:** `CheckMaxSteps`, `EmitDebuggingInfo`, `EmitBreakpoint`.
    * **Control Flow Implementation:**  The methods for `Block`, `Loop`, `Try`, `Catch`, etc.
    * **Exception Handling:** The methods related to `Try`, `Catch`, `Rethrow`, `Delegate`.
    * **Stack Management:** Implicit in many methods dealing with pushing and popping values, and the explicit stack checks.

4. **Consider the prompt's specific questions:**
    * **`.tq` extension:** The code is `.cc`, not `.tq`, so it's C++.
    * **Relationship to JavaScript:**  Wasm interacts with JavaScript. Think about scenarios like calling JavaScript functions from Wasm or handling exceptions that cross the boundary. The code mentions builtins like `kWasmTraceEnter` and `kWasmDebugBreak`, which suggest interaction with the V8 runtime, which is inherently tied to JavaScript. The handling of `WebAssembly.JSTag` in `CatchException` is a concrete example of this interaction.
    * **JavaScript examples:**  Illustrate the identified functionalities with simple JavaScript code snippets where applicable (e.g., calling a Wasm function that might trigger tiering, having local variables, using try-catch blocks).
    * **Code logic reasoning:** The `CheckTierUp` method and the logic within `CatchException` offer good examples for demonstrating input/output scenarios and conditional logic.
    * **Common programming errors:**  Consider typical mistakes when working with Wasm, such as incorrect function calls, unhandled exceptions, or exceeding resource limits.
    * **Overall function:**  Synthesize a concise summary of the code's purpose within the V8 Wasm infrastructure.

5. **Structure the answer:** Organize the information logically, starting with a general overview and then detailing specific functionalities, addressing the prompt's questions one by one. Use clear headings and bullet points for readability.

6. **Refine and elaborate:**  Review the initial draft and add more details or examples where necessary. Ensure the language is clear and accurate. For instance, explicitly mentioning the role of the Liftoff compiler as a *baseline* compiler is important context. Highlight the connection between the C++ code and the corresponding WebAssembly features.

7. **Self-Correction/Improvements during the thought process:**
    * Initially, I might focus too much on individual methods. It's important to step back and see the bigger picture of how these methods contribute to the overall compilation process.
    *  The connection to JavaScript needs to be made explicit. Initially, I might only focus on Wasm internals, but Wasm's role in the web platform requires highlighting its interaction with JavaScript.
    * For the input/output examples, start simple and avoid overly complex scenarios to keep the explanation clear.
    * When thinking about programming errors, focus on errors relevant to the *compiler's* perspective, such as how it handles potentially invalid Wasm code or how it enforces runtime constraints.

By following these steps, and iteratively refining the explanation, a comprehensive and accurate answer can be generated.
这是 V8 JavaScript 引擎中 Liftoff 基线编译器的源代码片段，主要负责 WebAssembly 代码的快速初始编译。以下是代码片段中展示的功能归纳：

**核心功能:**

1. **Tier-Up 检查 (Tier-Up Check):**
   - 代码 `CheckTierUp`  负责检查是否应该将当前 WebAssembly 函数“升级”（tier-up）到更优化的编译器（如 TurboFan）。
   - 它会消耗一定的 "预算" (budget_used)，这个预算与 V8 的优化层级策略有关。
   - 如果需要升级，会跳转到预先定义的 `ool.label` 标签处的 Out-of-Line 代码。
   - **假设输入:**  当前函数执行次数或消耗的资源达到一定阈值。
   - **输出:** 跳转到 Out-of-Line 代码执行升级操作。

2. **初始局部变量溢出 (Spill Locals Initially):**
   - `SpillLocalsInitially` 方法决定是否在函数开始时将局部变量存储到栈上。
   - 如果局部变量数量很多，或者存在非 i32/i64 类型的局部变量，则会选择将它们放到栈上。这是为了简化后续的寄存器分配和合并操作。
   - **假设输入:**  局部变量的数量和类型。
   - **输出:** 返回 `true` 或 `false`，指示是否应该立即溢出局部变量。

3. **函数入口追踪 (Trace Function Entry):**
   - `TraceFunctionEntry` 用于在调试模式下追踪 WebAssembly 函数的入口。
   - 它会调用内置函数 `kWasmTraceEnter`。

4. **动态分层编译控制 (Dynamic Tiering):**
   - `dynamic_tiering` 方法判断是否应该为当前函数启用动态分层编译。
   - 这取决于 V8 的标志位 (`v8_flags.wasm_tier_up_filter`) 和是否处于调试模式。

5. **函数体开始 (StartFunctionBody):**
   - `StartFunctionBody` 负责函数体的初始化工作，包括：
     - 检查参数类型是否被支持。
     - 设置栈帧 (`EnterFrame`, `CallFrameSetupStub`)。
     - 处理函数参数 (`ParameterProcessor`)。
     - 初始化局部变量。
     - 检查实例数据参数的类型 (debug_code 下)。
     - 进行栈溢出检查 (`StackCheck`)。
   - **假设输入:**  `FullDecoder` 提供了函数的信息。
   - **输出:**  完成函数执行环境的初步设置。

6. **生成 Out-of-Line 代码 (GenerateOutOfLineCode):**
   - `GenerateOutOfLineCode`  负责生成在函数主体之外执行的代码，例如：
     - 栈溢出检查 (`kWasmStackGuard`, `kWasmGrowableStackGuard`)
     - Tier-Up 触发 (`kWasmTriggerTierUp`)
     - 陷阱 (Trap)
   - 它会保存和恢复寄存器状态，调用相应的内置函数，并定义安全点 (safepoint) 以支持垃圾回收和调试。
   - **假设输入:** 一个 `OutOfLineCode` 对象，其中包含了需要执行的内置函数和相关信息。
   - **输出:**  生成对应的汇编代码。

7. **函数结束 (FinishFunction):**
   - `FinishFunction` 完成函数的编译过程，包括：
     - 对齐帧大小 (`AlignFrameSize`)。
     - 生成所有 Out-of-Line 代码。
     - 打补丁 (`PatchPrepareStackFrame`)。
     - 完成代码生成 (`FinishCode`)。
     - 发射安全点表 (`Emit`)。
     - 发射异常处理表 (`EmitReturnTableStart`, `EmitReturnEntry`)。
     - 发射常量池 (`MaybeEmitOutOfLineConstantPool`)。
     - 如果启用了 inlining，更新 `WasmModule` 中的调用目标信息。

8. **错误处理 (OnFirstError):**
   - `OnFirstError` 在编译过程中遇到第一个错误时被调用，用于终止编译。

9. **最大执行步数检查 (CheckMaxSteps):**
   - 用于调试和 fuzzing，限制函数的执行步数。如果超出限制，会触发一个 unreachable 陷阱。

10. **发射调试信息 (EmitDebuggingInfo):**
    - 在调试模式下，在每个指令执行前添加调试信息，包括断点检查。

11. **下一个指令处理 (NextInstruction):**
    - 在处理每个 WebAssembly 指令前执行，用于追踪缓存状态和在调试模式下调用 `EmitDebuggingInfo`。

12. **发射断点 (EmitBreakpoint):**
    - 在代码中插入断点，用于调试。

13. **控制流块处理 (PushControl, Block, Loop, Try):**
    - 这些方法处理 WebAssembly 的控制流指令，例如 `block`，`loop` 和 `try` 块。它们会管理控制流栈，并为后续的代码生成做准备。特别是 `Loop` 会在循环开始前溢出局部变量。`Try` 块会创建 `TryInfo` 对象来存储异常处理相关的信息。

14. **异常处理 (CatchException, Rethrow, Delegate, CatchAll, TryTable, CatchCase):**
    - 这些方法实现了 WebAssembly 的异常处理机制。
    - `CatchException` 处理 `catch` 子句，比较异常标签。
    - `Rethrow` 重新抛出异常。
    - `Delegate` 将异常处理委托给外层 `try` 块。
    - `CatchAll` 处理 `catch_all` 子句。
    - `TryTable` 和 `CatchCase` 用于处理 `try-table` 指令，这是一种更复杂的异常处理结构。这些方法涉及到加载和比较异常标签，以及根据匹配情况跳转到相应的处理代码。

**与 Javascript 的关系 (如果存在):**

代码中涉及到与 JavaScript 的交互，主要体现在：

- **调用内置函数 (Builtins):** 例如 `Builtin::kWasmTraceEnter` 和 `Builtin::kWasmDebugBreak`，这些是 V8 提供的 JavaScript 或 C++ 实现的函数，WebAssembly 可以调用它们。
- **异常处理 (CatchException):**  代码中特殊处理了 `WebAssembly.JSTag` 的情况，允许捕获 JavaScript 异常。

**Javascript 示例 (异常处理):**

```javascript
// WebAssembly 模块 (假设已经编译并实例化)
const wasmModule = ...;
const wasmInstance = ...;

try {
  wasmInstance.exports.someFunctionThatMightThrow();
} catch (e) {
  console.error("Caught an exception from WebAssembly:", e);
  // 如果 WebAssembly 代码抛出的是一个 JavaScript 异常，
  // 那么这里的 'e' 就是那个 JavaScript 异常对象。
}
```

在 `liftoff-compiler.cc` 的 `CatchException` 方法中，可以看到针对 `WebAssembly.JSTag` 的特殊处理，这使得 WebAssembly 代码能够捕获并处理由 JavaScript 抛出的异常。

**代码逻辑推理 (Tier-Up 检查):**

**假设输入:**

- `budget_used`:  例如 `10` (表示已经消耗的 tier-up 预算)。
- `v8_flags.wasm_tiering_budget`: 例如 `50` (表示总的 tier-up 预算)。

**代码逻辑:**

1. `max_budget_use` 被计算为 `std::max(1, 50 / 4) = std::max(1, 12) = 12`。
2. 检查 `budget_used > max_budget_use`，即 `10 > 12`，结果为 `false`。
3. 因此，`budget_used` 的值保持不变，仍然是 `10`。
4. `DCHECK_LE(1, budget_used)` 检查 `1 <= 10`，通过。
5. `CheckTierUp` 函数会被调用，传入 `budget_used` 的值 `10`。

**假设输出:**

- 如果 `CheckTierUp` 的内部逻辑判断需要进行 tier-up，则会跳转到 `ool.label.get()` 处的代码。

**用户常见的编程错误 (与 Out-of-Line 代码相关):**

- **栈溢出:**  如果 WebAssembly 代码尝试使用超出栈限制的内存，Liftoff 会生成调用 `kWasmStackGuard` 或 `kWasmGrowableStackGuard` 的 Out-of-Line 代码来检测并抛出错误。
  ```javascript
  // JavaScript 示例 (可能导致栈溢出的 WebAssembly 函数)
  function recursiveFunction() {
    recursiveFunction(); // 无终止条件的递归
  }
  ```
- **调用未定义的函数或导入 (导致陷阱):** 如果 WebAssembly 代码尝试调用一个不存在的函数或导入，Liftoff 可能会生成 Out-of-Line 代码来处理这个陷阱。
  ```javascript
  // WebAssembly 代码片段 (尝试调用一个未导入的函数)
  (module
    (import "env" "nonExistentFunction" (func $nonExistent))
    (func (export "main")
      call $nonExistent
    )
  )
  ```
- **尝试访问超出内存边界 (导致陷阱):**  对线性内存进行越界访问会导致陷阱，Liftoff 会生成相应的 Out-of-Line 代码来处理。

**总结它的功能:**

这个代码片段是 V8 引擎中 Liftoff 基线编译器的核心组成部分，负责将 WebAssembly 字节码快速编译成机器码。它主要关注以下方面：

- **快速生成可执行代码:**  作为基线编译器，Liftoff 旨在快速生成代码，牺牲了一些性能优化的机会。
- **基本的代码生成流程:**  处理函数入口、参数、局部变量、控制流和基本的操作码。
- **支持动态分层编译:**  通过 `TierUpCheck` 机制，为后续的优化编译做准备。
- **实现 WebAssembly 的核心特性:** 包括栈管理、异常处理和与 JavaScript 的互操作。
- **提供基本的调试支持:**  通过插入断点和追踪函数入口，方便开发人员调试 WebAssembly 代码。
- **处理运行时错误:**  通过生成 Out-of-Line 代码来处理栈溢出、非法内存访问等运行时错误。

总而言之，这段代码是 V8 引擎中实现 WebAssembly 支持的关键部分，它在保证功能正确性的前提下，尽可能快速地将 WebAssembly 代码转换为可执行的机器码。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共13部分，请归纳一下它的功能

"""
Check;
    // We never want to blow the entire budget at once.
    const int max_budget_use = std::max(1, v8_flags.wasm_tiering_budget / 4);
    if (budget_used > max_budget_use) budget_used = max_budget_use;

    // We should always decrement the budget, and we don't expect integer
    // overflows in the budget calculation.
    DCHECK_LE(1, budget_used);

    SpilledRegistersForInspection* spilled_regs = nullptr;

    OutOfLineSafepointInfo* safepoint_info =
        zone_->New<OutOfLineSafepointInfo>(zone_);
    __ cache_state()->GetTaggedSlotsForOOLCode(
        &safepoint_info->slots, &safepoint_info->spills,
        LiftoffAssembler::CacheState::SpillLocation::kTopOfStack);

    LiftoffRegList regs_to_save = __ cache_state()->used_registers;
    // The cached instance will be reloaded separately.
    if (__ cache_state()->cached_instance_data != no_reg) {
      DCHECK(regs_to_save.has(__ cache_state()->cached_instance_data));
      regs_to_save.clear(__ cache_state()->cached_instance_data);
    }

    out_of_line_code_.push_back(OutOfLineCode::TierupCheck(
        zone_, position, regs_to_save, __ cache_state()->cached_instance_data,
        spilled_regs, safepoint_info, RegisterOOLDebugSideTableEntry(decoder)));
    OutOfLineCode& ool = out_of_line_code_.back();

    FREEZE_STATE(tierup_check);
    __ CheckTierUp(declared_function_index(env_->module, func_index_),
                   budget_used, ool.label.get(), tierup_check);

    __ bind(ool.continuation.get());
  }

  bool SpillLocalsInitially(FullDecoder* decoder, uint32_t num_params) {
    int actual_locals = __ num_locals() - num_params;
    DCHECK_LE(0, actual_locals);
    constexpr int kNumCacheRegisters = kLiftoffAssemblerGpCacheRegs.Count();
    // If we have many locals, we put them on the stack initially. This avoids
    // having to spill them on merge points. Use of these initial values should
    // be rare anyway.
    if (actual_locals > kNumCacheRegisters / 2) return true;
    // If there are locals which are not i32 or i64, we also spill all locals,
    // because other types cannot be initialized to constants.
    for (uint32_t param_idx = num_params; param_idx < __ num_locals();
         ++param_idx) {
      ValueKind kind = __ local_kind(param_idx);
      if (kind != kI32 && kind != kI64) return true;
    }
    return false;
  }

  V8_NOINLINE V8_PRESERVE_MOST void TraceFunctionEntry(FullDecoder* decoder) {
    CODE_COMMENT("trace function entry");
    __ SpillAllRegisters();
    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(decoder->position()), false);
    __ CallBuiltin(Builtin::kWasmTraceEnter);
    DefineSafepoint();
  }

  bool dynamic_tiering() {
    return env_->dynamic_tiering && for_debugging_ == kNotForDebugging &&
           (v8_flags.wasm_tier_up_filter == -1 ||
            v8_flags.wasm_tier_up_filter == func_index_);
  }

  void StartFunctionBody(FullDecoder* decoder, Control* block) {
    for (uint32_t i = 0; i < __ num_locals(); ++i) {
      if (!CheckSupportedType(decoder, __ local_kind(i), "param")) return;
    }

    // Parameter 0 is the instance data.
    uint32_t num_params =
        static_cast<uint32_t>(decoder->sig_->parameter_count());

    __ CodeEntry();

    if (v8_flags.wasm_inlining) {
      CODE_COMMENT("frame setup");
      int declared_func_index =
          func_index_ - env_->module->num_imported_functions;
      DCHECK_GE(declared_func_index, 0);
      __ CallFrameSetupStub(declared_func_index);
    } else {
      __ EnterFrame(StackFrame::WASM);
    }
    __ set_has_frame(true);
    pc_offset_stack_frame_construction_ = __ PrepareStackFrame();
    // {PrepareStackFrame} is the first platform-specific assembler method.
    // If this failed, we can bail out immediately, avoiding runtime overhead
    // and potential failures because of other unimplemented methods.
    // A platform implementing {PrepareStackFrame} must ensure that we can
    // finish compilation without errors even if we hit unimplemented
    // LiftoffAssembler methods.
    if (DidAssemblerBailout(decoder)) return;

    // Input 0 is the call target, the trusted instance data is at 1.
    [[maybe_unused]] constexpr int kInstanceDataParameterIndex = 1;
    // Check that {kWasmImplicitArgRegister} matches our call descriptor.
    DCHECK_EQ(kWasmImplicitArgRegister,
              Register::from_code(
                  descriptor_->GetInputLocation(kInstanceDataParameterIndex)
                      .AsRegister()));
    __ cache_state() -> SetInstanceCacheRegister(kWasmImplicitArgRegister);

    if (num_params) {
      CODE_COMMENT("process parameters");
      ParameterProcessor processor(this, num_params);
      processor.Process();
    }
    int params_size = __ TopSpillOffset();

    // Initialize locals beyond parameters.
    if (num_params < __ num_locals()) CODE_COMMENT("init locals");
    if (SpillLocalsInitially(decoder, num_params)) {
      bool has_refs = false;
      for (uint32_t param_idx = num_params; param_idx < __ num_locals();
           ++param_idx) {
        ValueKind kind = __ local_kind(param_idx);
        has_refs |= is_reference(kind);
        __ PushStack(kind);
      }
      int spill_size = __ TopSpillOffset() - params_size;
      __ FillStackSlotsWithZero(params_size, spill_size);

      // Initialize all reference type locals with ref.null.
      if (has_refs) {
        LiftoffRegList pinned;
        Register null_ref_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned).gp());
        Register wasm_null_ref_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned).gp());
        LoadNullValue(null_ref_reg, kWasmExternRef);
        LoadNullValue(wasm_null_ref_reg, kWasmAnyRef);
        for (uint32_t local_index = num_params; local_index < __ num_locals();
             ++local_index) {
          ValueType type = decoder->local_types_[local_index];
          if (type.is_reference()) {
            __ Spill(__ cache_state()->stack_state[local_index].offset(),
                     type.use_wasm_null() ? LiftoffRegister(wasm_null_ref_reg)
                                          : LiftoffRegister(null_ref_reg),
                     type.kind());
          }
        }
      }
    } else {
      for (uint32_t param_idx = num_params; param_idx < __ num_locals();
           ++param_idx) {
        ValueKind kind = __ local_kind(param_idx);
        // Anything which is not i32 or i64 requires spilling.
        DCHECK(kind == kI32 || kind == kI64);
        __ PushConstant(kind, int32_t{0});
      }
    }

    DCHECK_EQ(__ num_locals(), __ cache_state()->stack_height());

    if (V8_UNLIKELY(debug_sidetable_builder_)) {
      debug_sidetable_builder_->SetNumLocals(__ num_locals());
    }

    if (V8_UNLIKELY(for_debugging_)) {
      __ ResetOSRTarget();
      if (V8_UNLIKELY(max_steps_)) {
        // Generate the single OOL code to jump to if {max_steps_} have been
        // executed.
        DCHECK_EQ(0, out_of_line_code_.size());
        // This trap is never intercepted (e.g. by a debugger), so we do not
        // need safepoint information (which would be difficult to compute if
        // the OOL code is shared).
        out_of_line_code_.push_back(OutOfLineCode::Trap(
            zone_, Builtin::kThrowWasmTrapUnreachable, decoder->position(),
            nullptr, nullptr, nullptr));

        // Subtract 16 steps for the function call itself (including the
        // function prologue), plus 1 for each local (including parameters). Do
        // this only *after* setting up the frame completely, even though we
        // already executed the work then.
        CheckMaxSteps(decoder, 16 + __ num_locals());
      }
    } else {
      DCHECK(!max_steps_);
    }

    // If debug code is enabled, assert that the first parameter is a
    // WasmTrustedInstanceData.
    if (v8_flags.debug_code) {
      SCOPED_CODE_COMMENT("Check instance data parameter type");
      LiftoffRegList pinned;
      Register scratch = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      Register instance = pinned.set(LoadInstanceIntoRegister(pinned, scratch));
      // Load the map.
      __ LoadMap(scratch, instance);
      // Load the instance type.
      __ Load(LiftoffRegister{scratch}, scratch, no_reg,
              wasm::ObjectAccess::ToTagged(Map::kInstanceTypeOffset),
              LoadType::kI32Load16U);
      // If not WASM_TRUSTED_INSTANCE_DATA_TYPE -> error.
      Label ok;
      FreezeCacheState frozen{asm_};
      __ emit_i32_cond_jumpi(kEqual, &ok, scratch,
                             WASM_TRUSTED_INSTANCE_DATA_TYPE, frozen);
      __ AssertUnreachable(AbortReason::kUnexpectedInstanceType);
      __ bind(&ok);
    }

    // The function-prologue stack check is associated with position 0, which
    // is never a position of any instruction in the function.
    StackCheck(decoder, 0);

    if (V8_UNLIKELY(v8_flags.trace_wasm)) TraceFunctionEntry(decoder);
  }

  void GenerateOutOfLineCode(OutOfLineCode* ool) {
    CODE_COMMENT((std::string("OOL: ") + Builtins::name(ool->builtin)).c_str());
    __ bind(ool->label.get());
    const bool is_stack_check =
        ool->builtin == Builtin::kWasmStackGuard ||
        ool->builtin == Builtin::kWasmGrowableStackGuard;
    const bool is_tierup = ool->builtin == Builtin::kWasmTriggerTierUp;

    if (!ool->regs_to_save.is_empty()) {
      __ PushRegisters(ool->regs_to_save);
    }
    if (V8_UNLIKELY(ool->spilled_registers != nullptr)) {
      for (auto& entry : ool->spilled_registers->entries) {
        // We should not push and spill the same register.
        DCHECK(!ool->regs_to_save.has(entry.reg));
        __ Spill(entry.offset, entry.reg, entry.kind);
      }
    }

    if (ool->builtin == Builtin::kWasmGrowableStackGuard) {
      WasmGrowableStackGuardDescriptor descriptor;
      DCHECK_EQ(0, descriptor.GetStackParameterCount());
      DCHECK_EQ(1, descriptor.GetRegisterParameterCount());
      Register param_reg = descriptor.GetRegisterParameter(0);
      __ LoadConstant(LiftoffRegister(param_reg),
                      WasmValue::ForUintPtr(descriptor_->ParameterSlotCount() *
                                            LiftoffAssembler::kStackSlotSize));
    }

    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(ool->position), true);
    __ CallBuiltin(ool->builtin);
    // It is safe to not check for existing safepoint at this address since we
    // just emitted a call.
    auto safepoint = safepoint_table_builder_.DefineSafepoint(&asm_);

    if (ool->safepoint_info) {
      for (auto index : ool->safepoint_info->slots) {
        safepoint.DefineTaggedStackSlot(index);
      }

      int total_frame_size = __ GetTotalFrameSize();
      // {total_frame_size} is the highest offset from the FP that is used to
      // store a value. The offset of the first spill slot should therefore be
      // {(total_frame_size / kSystemPointerSize) + 1}. However, spill slots
      // don't start at offset '0' but at offset '-1' (or
      // {-kSystemPointerSize}). Therefore we have to add another '+ 1' to the
      // index of the first spill slot.
      int index = (total_frame_size / kSystemPointerSize) + 2;

      __ RecordSpillsInSafepoint(safepoint, ool->regs_to_save,
                                 ool->safepoint_info->spills, index);
    }

    DCHECK_EQ(!debug_sidetable_builder_, !ool->debug_sidetable_entry_builder);
    if (V8_UNLIKELY(ool->debug_sidetable_entry_builder)) {
      ool->debug_sidetable_entry_builder->set_pc_offset(__ pc_offset());
    }
    DCHECK_EQ(ool->continuation.get()->is_bound(), is_stack_check || is_tierup);
    if (is_stack_check) {
      MaybeOSR();
    }
    if (!ool->regs_to_save.is_empty()) __ PopRegisters(ool->regs_to_save);
    if (is_stack_check || is_tierup) {
      if (V8_UNLIKELY(ool->spilled_registers != nullptr)) {
        DCHECK(for_debugging_);
        for (auto& entry : ool->spilled_registers->entries) {
          __ Fill(entry.reg, entry.offset, entry.kind);
        }
      }
      if (ool->cached_instance_data != no_reg) {
        __ LoadInstanceDataFromFrame(ool->cached_instance_data);
      }
      __ emit_jump(ool->continuation.get());
    } else {
      __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
    }
  }

  void FinishFunction(FullDecoder* decoder) {
    if (DidAssemblerBailout(decoder)) return;
    __ AlignFrameSize();
#if DEBUG
    int frame_size = __ GetTotalFrameSize();
#endif
    for (OutOfLineCode& ool : out_of_line_code_) {
      GenerateOutOfLineCode(&ool);
    }
    DCHECK_EQ(frame_size, __ GetTotalFrameSize());
    __ PatchPrepareStackFrame(pc_offset_stack_frame_construction_,
                              &safepoint_table_builder_, v8_flags.wasm_inlining,
                              descriptor_->ParameterSlotCount());
    __ FinishCode();
    safepoint_table_builder_.Emit(&asm_, __ GetTotalFrameSlotCountForGC());
    // Emit the handler table.
    if (!handlers_.empty()) {
      handler_table_offset_ = HandlerTable::EmitReturnTableStart(&asm_);
      for (auto& handler : handlers_) {
        HandlerTable::EmitReturnEntry(&asm_, handler.pc_offset,
                                      handler.handler.get()->pos());
      }
    }
    __ MaybeEmitOutOfLineConstantPool();
    // The previous calls may have also generated a bailout.
    DidAssemblerBailout(decoder);
    DCHECK_EQ(num_exceptions_, 0);

    if (v8_flags.wasm_inlining && !encountered_call_instructions_.empty()) {
      // Update the call targets stored in the WasmModule.
      TypeFeedbackStorage& type_feedback = env_->module->type_feedback;
      base::SharedMutexGuard<base::kExclusive> mutex_guard(
          &type_feedback.mutex);
      FunctionTypeFeedback& function_feedback =
          type_feedback.feedback_for_function[func_index_];
      function_feedback.liftoff_frame_size = __ GetTotalFrameSize();
      base::OwnedVector<uint32_t>& call_targets =
          function_feedback.call_targets;
      if (call_targets.empty()) {
        call_targets =
            base::OwnedVector<uint32_t>::Of(encountered_call_instructions_);
      } else {
        DCHECK_EQ(call_targets.as_vector(),
                  base::VectorOf(encountered_call_instructions_));
      }
    }

    if (frame_description_) {
      frame_description_->total_frame_size = __ GetTotalFrameSize();
    }
  }

  void OnFirstError(FullDecoder* decoder) {
    if (!did_bailout()) bailout_reason_ = kDecodeError;
    UnuseLabels(decoder);
    asm_.AbortCompilation();
  }

  // Rule of thumb: an instruction is "heavy" when its runtime is linear in
  // some random variable that the fuzzer generates.
#define FUZZER_HEAVY_INSTRUCTION                      \
  do {                                                \
    if (V8_UNLIKELY(max_steps_ != nullptr)) {         \
      CheckMaxSteps(decoder, kHeavyInstructionSteps); \
    }                                                 \
  } while (false)

  V8_NOINLINE void CheckMaxSteps(FullDecoder* decoder, int steps_done = 1) {
    DCHECK_LE(1, steps_done);
    SCOPED_CODE_COMMENT("check max steps");
    LiftoffRegList pinned;
    LiftoffRegister max_steps = pinned.set(__ GetUnusedRegister(kGpReg, {}));
    LiftoffRegister max_steps_addr =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    {
      FREEZE_STATE(frozen);
      __ LoadConstant(
          max_steps_addr,
          WasmValue::ForUintPtr(reinterpret_cast<uintptr_t>(max_steps_)));
      __ Load(max_steps, max_steps_addr.gp(), no_reg, 0, LoadType::kI32Load);
      // Subtract first (and store the result), so the caller sees that
      // max_steps ran negative. Since we never subtract too much at once, we
      // cannot underflow.
      DCHECK_GE(kMaxInt / 16, steps_done);  // An arbitrary limit.
      __ emit_i32_subi(max_steps.gp(), max_steps.gp(), steps_done);
      __ Store(max_steps_addr.gp(), no_reg, 0, max_steps, StoreType::kI32Store,
               pinned);
      // Abort if max steps have been executed.
      DCHECK_EQ(Builtin::kThrowWasmTrapUnreachable,
                out_of_line_code_.front().builtin);
      Label* trap_label = out_of_line_code_.front().label.get();
      __ emit_i32_cond_jumpi(kLessThan, trap_label, max_steps.gp(), 0, frozen);
    }
  }

  V8_NOINLINE void EmitDebuggingInfo(FullDecoder* decoder, WasmOpcode opcode) {
    DCHECK(for_debugging_);

    // Snapshot the value types (from the decoder) here, for potentially
    // building a debug side table entry later. Arguments will have been popped
    // from the stack later (when we need them), and Liftoff does not keep
    // precise type information.
    stack_value_types_for_debugging_ = GetStackValueTypesForDebugging(decoder);

    if (!WasmOpcodes::IsBreakable(opcode)) return;

    bool has_breakpoint = false;
    if (next_breakpoint_ptr_) {
      if (*next_breakpoint_ptr_ == 0) {
        // A single breakpoint at offset 0 indicates stepping.
        DCHECK_EQ(next_breakpoint_ptr_ + 1, next_breakpoint_end_);
        has_breakpoint = true;
      } else {
        while (next_breakpoint_ptr_ != next_breakpoint_end_ &&
               *next_breakpoint_ptr_ < decoder->position()) {
          // Skip unreachable breakpoints.
          ++next_breakpoint_ptr_;
        }
        if (next_breakpoint_ptr_ == next_breakpoint_end_) {
          next_breakpoint_ptr_ = next_breakpoint_end_ = nullptr;
        } else if (*next_breakpoint_ptr_ == decoder->position()) {
          has_breakpoint = true;
        }
      }
    }
    if (has_breakpoint) {
      CODE_COMMENT("breakpoint");
      EmitBreakpoint(decoder);
      // Once we emitted an unconditional breakpoint, we don't need to check
      // function entry breaks any more.
      did_function_entry_break_checks_ = true;
    } else if (!did_function_entry_break_checks_) {
      did_function_entry_break_checks_ = true;
      CODE_COMMENT("check function entry break");
      Label do_break;
      Label no_break;
      Register flag = __ GetUnusedRegister(kGpReg, {}).gp();

      // Check the "hook on function call" flag. If set, trigger a break.
      LOAD_INSTANCE_FIELD(flag, HookOnFunctionCallAddress, kSystemPointerSize,
                          {});
      FREEZE_STATE(frozen);
      __ Load(LiftoffRegister{flag}, flag, no_reg, 0, LoadType::kI32Load8U, {});
      __ emit_cond_jump(kNotZero, &do_break, kI32, flag, no_reg, frozen);

      // Check if we should stop on "script entry".
      LOAD_INSTANCE_FIELD(flag, BreakOnEntry, kUInt8Size, {});
      __ emit_cond_jump(kZero, &no_break, kI32, flag, no_reg, frozen);

      __ bind(&do_break);
      EmitBreakpoint(decoder);
      __ bind(&no_break);
    } else if (dead_breakpoint_ == decoder->position()) {
      DCHECK(!next_breakpoint_ptr_ ||
             *next_breakpoint_ptr_ != dead_breakpoint_);
      // The top frame is paused at this position, but the breakpoint was
      // removed. Adding a dead breakpoint here ensures that the source
      // position exists, and that the offset to the return address is the
      // same as in the old code.
      CODE_COMMENT("dead breakpoint");
      Label cont;
      __ emit_jump(&cont);
      EmitBreakpoint(decoder);
      __ bind(&cont);
    }
    if (V8_UNLIKELY(max_steps_ != nullptr)) {
      CheckMaxSteps(decoder);
    }
  }

  void NextInstruction(FullDecoder* decoder, WasmOpcode opcode) {
    TraceCacheState(decoder);
    SLOW_DCHECK(__ ValidateCacheState());
    CODE_COMMENT(WasmOpcodes::OpcodeName(
        WasmOpcodes::IsPrefixOpcode(opcode)
            ? decoder->read_prefixed_opcode<ValidationTag>(decoder->pc()).first
            : opcode));

    if (!has_outstanding_op() && decoder->control_at(0)->reachable()) {
      // Decoder stack and liftoff stack have to be in sync if current code
      // path is reachable.
      DCHECK_EQ(decoder->stack_size() + __ num_locals() + num_exceptions_,
                __ cache_state()->stack_state.size());
    }

    // Add a single check, so that the fast path can be inlined while
    // {EmitDebuggingInfo} stays outlined.
    if (V8_UNLIKELY(for_debugging_)) EmitDebuggingInfo(decoder, opcode);
  }

  void EmitBreakpoint(FullDecoder* decoder) {
    DCHECK(for_debugging_);
    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(decoder->position()), true);
    __ CallBuiltin(Builtin::kWasmDebugBreak);
    DefineSafepointWithCalleeSavedRegisters();
    RegisterDebugSideTableEntry(decoder,
                                DebugSideTableBuilder::kAllowRegisters);
    MaybeOSR();
  }

  void PushControl(Control* block) {
    // The Liftoff stack includes implicit exception refs stored for catch
    // blocks, so that they can be rethrown.
    block->num_exceptions = num_exceptions_;
  }

  void Block(FullDecoder* decoder, Control* block) { PushControl(block); }

  void Loop(FullDecoder* decoder, Control* loop) {
    // Before entering a loop, spill all locals to the stack, in order to free
    // the cache registers, and to avoid unnecessarily reloading stack values
    // into registers at branches.
    // TODO(clemensb): Come up with a better strategy here, involving
    // pre-analysis of the function.
    __ SpillLocals();

    __ SpillLoopArgs(loop->start_merge.arity);

    // Loop labels bind at the beginning of the block.
    __ bind(loop->label.get());

    // Save the current cache state for the merge when jumping to this loop.
    loop->label_state.Split(*__ cache_state());

    PushControl(loop);

    if (!dynamic_tiering()) {
      // When the budget-based tiering mechanism is enabled, use that to
      // check for interrupt requests; otherwise execute a stack check in the
      // loop header.
      StackCheck(decoder, decoder->position());
    }
  }

  void Try(FullDecoder* decoder, Control* block) {
    block->try_info = zone_->New<TryInfo>(zone_);
    PushControl(block);
  }

  // Load the property in {kReturnRegister0}.
  LiftoffRegister GetExceptionProperty(const VarState& exception,
                                       RootIndex root_index) {
    DCHECK(root_index == RootIndex::kwasm_exception_tag_symbol ||
           root_index == RootIndex::kwasm_exception_values_symbol);

    LiftoffRegList pinned;
    LiftoffRegister tag_symbol_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadExceptionSymbol(tag_symbol_reg.gp(), pinned, root_index);
    LiftoffRegister context_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LOAD_TAGGED_PTR_INSTANCE_FIELD(context_reg.gp(), NativeContext, pinned);

    VarState tag_symbol{kRef, tag_symbol_reg, 0};
    VarState context{kRef, context_reg, 0};

    CallBuiltin(Builtin::kWasmGetOwnProperty,
                MakeSig::Returns(kRef).Params(kRef, kRef, kRef),
                {exception, tag_symbol, context}, kNoSourcePosition);

    return LiftoffRegister(kReturnRegister0);
  }

  void CatchException(FullDecoder* decoder, const TagIndexImmediate& imm,
                      Control* block, base::Vector<Value> values) {
    DCHECK(block->is_try_catch());
    __ emit_jump(block->label.get());

    // This is the last use of this label. Re-use the field for the label of the
    // next catch block, and jump there if the tag does not match.
    __ bind(&block->try_info->catch_label);
    block->try_info->catch_label.Unuse();
    block->try_info->catch_label.UnuseNear();

    __ cache_state()->Split(block->try_info->catch_state);

    CODE_COMMENT("load caught exception tag");
    DCHECK_EQ(__ cache_state()->stack_state.back().kind(), kRef);
    LiftoffRegister caught_tag =
        GetExceptionProperty(__ cache_state()->stack_state.back(),
                             RootIndex::kwasm_exception_tag_symbol);
    LiftoffRegList pinned;
    pinned.set(caught_tag);

    CODE_COMMENT("load expected exception tag");
    Register imm_tag = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(imm_tag, TagsTable, pinned);
    __ LoadTaggedPointer(
        imm_tag, imm_tag, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index));

    CODE_COMMENT("compare tags");

    if (imm.tag->sig->parameter_count() == 1 &&
        imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise we know
      // statically that it cannot be the JSTag.
      LiftoffRegister undefined =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      __ LoadFullPointer(
          undefined.gp(), kRootRegister,
          IsolateData::root_slot_offset(RootIndex::kUndefinedValue));
      LiftoffRegister js_tag = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      LOAD_TAGGED_PTR_INSTANCE_FIELD(js_tag.gp(), NativeContext, pinned);
      __ LoadTaggedPointer(
          js_tag.gp(), js_tag.gp(), no_reg,
          NativeContext::SlotOffset(Context::WASM_JS_TAG_INDEX));
      __ LoadTaggedPointer(
          js_tag.gp(), js_tag.gp(), no_reg,
          wasm::ObjectAccess::ToTagged(WasmTagObject::kTagOffset));
      {
        LiftoffAssembler::CacheState initial_state(zone_);
        LiftoffAssembler::CacheState end_state(zone_);
        Label js_exception;
        Label done;
        Label uncaught;
        initial_state.Split(*__ cache_state());
        {
          FREEZE_STATE(state_merged_explicitly);
          // If the tag is undefined, this is not a wasm exception. Go to a
          // different block to process the JS exception. Otherwise compare it
          // with the expected tag.
          __ emit_cond_jump(kEqual, &js_exception, kRefNull, caught_tag.gp(),
                            undefined.gp(), state_merged_explicitly);
          __ emit_cond_jump(kNotEqual, &uncaught, kRefNull, imm_tag,
                            caught_tag.gp(), state_merged_explicitly);
        }
        // Case 1: A wasm exception with a matching tag.
        GetExceptionValues(decoder, __ cache_state()->stack_state.back(),
                           imm.tag);
        // GetExceptionValues modified the cache state. Remember the new state
        // to merge the end state of case 2 into it.
        end_state.Steal(*__ cache_state());
        __ emit_jump(&done);

        __ bind(&js_exception);
        __ cache_state()->Split(initial_state);
        {
          FREEZE_STATE(state_merged_explicitly);
          __ emit_cond_jump(kNotEqual, &uncaught, kRefNull, imm_tag,
                            js_tag.gp(), state_merged_explicitly);
        }
        // Case 2: A JS exception, and the expected tag is JSTag.
        // TODO(thibaudm): Can we avoid some state splitting/stealing by
        // reserving this register earlier and not modifying the state in this
        // block?
        LiftoffRegister exception = __ PeekToRegister(0, pinned);
        __ PushRegister(kRef, exception);
        // The exception is now on the stack twice: once as an implicit operand
        // for rethrow, and once as the "unpacked" value.
        __ MergeFullStackWith(end_state);
        __ emit_jump(&done);

        // Case 3: Either a wasm exception with a mismatching tag, or a JS
        // exception but the expected tag is not JSTag.
        __ bind(&uncaught);
        __ cache_state()->Steal(initial_state);
        __ MergeFullStackWith(block->try_info->catch_state);
        __ emit_jump(&block->try_info->catch_label);

        __ bind(&done);
        __ cache_state()->Steal(end_state);
      }
    } else {
      {
        FREEZE_STATE(frozen);
        Label caught;
        __ emit_cond_jump(kEqual, &caught, kRefNull, imm_tag, caught_tag.gp(),
                          frozen);
        // The tags don't match, merge the current state into the catch state
        // and jump to the next handler.
        __ MergeFullStackWith(block->try_info->catch_state);
        __ emit_jump(&block->try_info->catch_label);
        __ bind(&caught);
      }
      GetExceptionValues(decoder, __ cache_state()->stack_state.back(),
                         imm.tag);
    }
    if (!block->try_info->in_handler) {
      block->try_info->in_handler = true;
      num_exceptions_++;
    }
  }

  void Rethrow(FullDecoder* decoder, const VarState& exception) {
    CallBuiltin(Builtin::kWasmRethrow, MakeSig::Params(kRef), {exception},
                decoder->position());
  }

  void Delegate(FullDecoder* decoder, uint32_t depth, Control* block) {
    DCHECK_EQ(block, decoder->control_at(0));
    Control* target = decoder->control_at(depth);
    DCHECK(block->is_incomplete_try());
    __ bind(&block->try_info->catch_label);
    if (block->try_info->catch_reached) {
      __ cache_state()->Steal(block->try_info->catch_state);
      if (depth == decoder->control_depth() - 1) {
        // Delegate to the caller, do not emit a landing pad.
        Rethrow(decoder, __ cache_state()->stack_state.back());
        MaybeOSR();
      } else {
        DCHECK(target->is_incomplete_try());
        if (target->try_info->catch_reached) {
          __ MergeStackWith(target->try_info->catch_state, 1,
                            LiftoffAssembler::kForwardJump);
        } else {
          target->try_info->catch_state = __ MergeIntoNewState(
              __ num_locals(), 1, target->stack_depth + target->num_exceptions);
          target->try_info->catch_reached = true;
        }
        __ emit_jump(&target->try_info->catch_label);
      }
    }
  }

  void Rethrow(FullDecoder* decoder, Control* try_block) {
    int index = try_block->try_info->catch_state.stack_height() - 1;
    auto& exception = __ cache_state()->stack_state[index];
    Rethrow(decoder, exception);
    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
  }

  void CatchAll(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    DCHECK_EQ(decoder->control_at(0), block);
    __ bind(&block->try_info->catch_label);
    __ cache_state()->Split(block->try_info->catch_state);
    if (!block->try_info->in_handler) {
      block->try_info->in_handler = true;
      num_exceptions_++;
    }
  }

  void TryTable(FullDecoder* decoder, Control* block) {
    block->try_info = zone_->New<TryInfo>(zone_);
    PushControl(block);
  }

  void CatchCase(FullDecoder* decoder, Control* block,
                 const CatchCase& catch_case, base::Vector<Value> values) {
    DCHECK(block->is_try_table());

    // This is the last use of this label. Re-use the field for the label of the
    // next catch block, and jump there if the tag does not match.
    __ bind(&block->try_info->catch_label);
    block->try_info->catch_label.Unuse();
    block->try_info->catch_label.UnuseNear();
    __ cache_state()->Split(block->try_info->catch_state);

    if (catch_case.kind == kCatchAll || catch_case.kind == kCatchAllRef) {
      // The landing pad pushed the exception on the stack, so keep
      // it there for {kCatchAllRef}, and drop it for {kCatchAll}.
      if (catch_case.kind == kCatchAll) {
        __ DropValues(1);
      }
      BrOrRet(decoder, catch_case.br_imm.depth);
      return;
    }

    CODE_COMMENT("load caught exception tag");
    DCHECK_EQ(__ cache_state()->stack_state.back().kind(), kRef);
    LiftoffRegister caught_tag =
        GetExceptionProperty(__ cache_state()->stack_state.back(),
                             RootIndex::kwasm_exception_tag_symbol);
    LiftoffRegList pinned;
    pinned.set(caught_tag);

    CODE_COMMENT("load expected exception tag");
    Register imm_tag = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(imm_tag, TagsTable, pinned);
    __ LoadTaggedPointer(imm_tag, imm_tag, no_reg,
                         wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                             catch_case.maybe_tag.tag_imm.index));

    VarState exn = __ cache_state() -> stack_state.back();

    CODE_COMMENT("compare tags");
    if (catch_case.maybe_tag.tag_imm.tag->sig->parameter_count() == 1 &&
        catch_case.maybe_tag.tag_imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise we know
      // statically that it cannot be the
"""


```