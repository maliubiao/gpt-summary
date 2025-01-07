Response:
My thinking process to summarize the provided C++ code snippet went something like this:

1. **Initial Scan and Identify Core Purpose:** I first scanned the code looking for keywords and recognizable patterns. I saw `LiftoffRegister`, `LiftoffAssembler`, `emit_`, `JumpIfFalse`, `If`, `CallBuiltin`, `GenerateCCall`, `EmitUnOp`, `EmitBinOp`, etc. These immediately suggested that this code is involved in generating machine code for WebAssembly within the Liftoff compiler. The focus appears to be on handling control flow (jumps, ifs), function calls (both built-in and external C functions), and various unary and binary operations. The presence of `catch` blocks and exception handling is also evident.

2. **Break Down into Functional Units:**  I started grouping related sections of code based on their apparent purpose. I noticed distinct blocks handling:
    * **Exception Handling (`JSTag`, `GetExceptionValues`, `ThrowRef`):**  This deals with catching and throwing both WebAssembly and JavaScript exceptions. The `JSTag` section seems to be specifically checking the type of a caught exception.
    * **Conditional Jumps (`JumpIfFalse`):**  This implements conditional branching based on the result of a comparison or a boolean value.
    * **Control Flow (`If`, `FallThruTo`, `FinishOneArmedIf`, `FinishTry`, `PopControl`):** This manages the execution flow through `if` statements, `try`/`catch` blocks, and potentially other control structures. The concept of merging states is key here.
    * **Function Calls (`GenerateCCall`, `GenerateCCallWithStackBuffer`):** This handles calls to external C functions, including managing stack arguments and return values.
    * **Unary Operations (`EmitUnOp`, `EmitFloatUnOpWithCFallback`, `EmitTypeConversion`, `EmitIsNull`, `UnOp`):**  This section deals with operations that take a single operand (e.g., negation, absolute value, type conversions).
    * **Binary Operations (`EmitBinOpImm`, `EmitBinOp`, `EmitI8x16Swizzle`, `EmitDivOrRem64CCall`, `EmitI32CmpOp`, `EmitBitRotationCCall`, `EmitI64Shift`):** This handles operations that take two operands (e.g., addition, subtraction, comparisons, shifts).

3. **Analyze Key Concepts and Data Structures:** I identified important concepts and data structures:
    * **`LiftoffRegister`:** Represents a register in the target architecture.
    * **`LiftoffAssembler`:** The core class for emitting machine code.
    * **`CacheState`:** Tracks the state of values in registers and on the stack at a particular point in the code. This is crucial for correct code generation, especially around control flow.
    * **`Control`:** Represents a control flow block (like an `if` or `try` statement).
    * **`VarState`:** Represents the state of a variable or value (e.g., its type and location).
    * **`FullDecoder`:**  Likely used for decoding the WebAssembly bytecode.

4. **Infer Functionality from Method Names and Logic:** I looked at the names of the methods and the logic within them to understand their specific roles. For example:
    * `GetExceptionValues`:  Extracts values from a caught exception.
    * `MergeFullStackWith`:  Merges the stack state from different control flow paths.
    * `SpillAllRegisters`:  Saves the contents of all registers to memory.
    * `emit_cond_jump`: Emits a conditional jump instruction.
    * `emit_i32_add`: Emits an instruction to add two 32-bit integers.

5. **Synthesize a High-Level Summary:** Based on the breakdown and analysis, I started forming a high-level summary, focusing on the main purposes of the code. I used phrases like "code generation," "control flow," "exception handling," "function calls," and "arithmetic/logical operations."

6. **Address Specific Questions:** I then addressed the specific questions in the prompt:
    * **Functionality Listing:** I listed the key functionalities I had identified.
    * **Torque Source:** I noted that the `.cc` extension indicates C++ source, not Torque.
    * **JavaScript Relation:** I thought about how these low-level operations relate to JavaScript functionality. The example of catching exceptions (`try...catch`) and the underlying arithmetic/logical operations seemed like good examples.
    * **Code Logic Inference (Hypothetical Input/Output):**  I chose a simple `if` statement as a manageable example to illustrate how `JumpIfFalse` and `If` would work, showing the stack manipulation and control flow changes.
    * **Common Programming Errors:** I considered common errors that might be related to these low-level operations, such as incorrect type conversions or not handling potential exceptions.
    * **Part 3 Summary:** Finally, I combined the key functionalities into a concise summary for this specific part of the code.

7. **Refine and Organize:** I reviewed my summary, ensuring it was clear, concise, and accurate. I organized the information logically, starting with the overall purpose and then going into more specific details. I also made sure to use appropriate terminology.

Essentially, my process involved a combination of code reading comprehension, pattern recognition, logical deduction, and knowledge of compiler and low-level programming concepts. The goal was to extract the essential meaning and purpose of the code snippet without needing to understand every single line of implementation detail.
这是 `v8/src/wasm/baseline/liftoff-compiler.cc` 源代码的第三部分，主要关注于 **WebAssembly 代码生成过程中的控制流、异常处理、基本运算和类型转换**。

以下是它的功能归纳：

**核心功能：**

1. **异常处理 (`JSTag` 代码块, `GetExceptionValues`, `ThrowRef`):**
   - 处理 WebAssembly 代码中的 `try...catch` 块。
   - 区分 WebAssembly 异常和 JavaScript 异常。
   - 检查捕获的异常标签是否与预期标签匹配。
   - 从异常对象中提取值。
   - 实现 `throw` 指令，抛出 WebAssembly 引用类型的异常。

2. **条件跳转 (`JumpIfFalse`):**
   - 基于布尔条件执行跳转。
   - 支持基于栈顶单个值的条件判断 (`i32.eqz`)。
   - 支持基于栈顶两个值的比较结果进行条件判断。
   - 能够处理比较操作中常量作为操作数的情况。

3. **控制流 (`If`, `FallThruTo`, `FinishOneArmedIf`, `FinishTry`, `PopControl`):**
   - 处理 `if` 语句的代码生成，包括 `else` 分支的处理。
   - 实现控制流跳转到标签，并维护执行状态（`CacheState`）。
   - 处理单臂 `if` 语句 (没有 `else` 分支)。
   - 处理 `try` 语句块的结束，包括清理异常引用。
   - 在控制流块结束时执行必要的清理和状态维护。

4. **C 函数调用 (`GenerateCCall`, `GenerateCCallWithStackBuffer`):**
   - 生成调用 C 函数的代码。
   - 支持将参数传递给 C 函数。
   - 支持从 C 函数接收返回值。
   - 处理需要栈缓冲区的 C 函数调用，用于存储参数或返回值。

5. **一元操作 (`EmitUnOp`, `EmitFloatUnOpWithCFallback`, `EmitTypeConversion`, `EmitIsNull`, `UnOp`):**
   - 生成执行一元操作的代码，例如取反、绝对值、类型转换等。
   - 对于某些浮点运算，提供 C 函数回退的机制。
   - 实现各种类型之间的转换，包括整数、浮点数以及引用类型。
   - 处理 `ref.is_null` 和 `ref.as_non_null` 操作。
   - 处理 `anyref` 和 `externref` 之间的转换。

6. **二元操作 (`EmitBinOpImm`, `EmitBinOp`, `EmitI8x16Swizzle`, `EmitDivOrRem64CCall`, `EmitI32CmpOp`, `EmitBitRotationCCall`, `EmitI64Shift`):**
   - 生成执行二元操作的代码，例如加法、减法、比较、位运算等。
   - 优化立即数作为操作数的情况。
   - 处理 SIMD 指令，例如 `i8x16.swizzle`。
   - 对于 64 位整数的除法和取余运算，如果硬件不支持，则调用 C 函数实现。
   - 处理 32 位整数的比较操作，并支持与 `br_if` 和 `if` 指令的组合优化。
   - 生成位旋转操作的代码，可能需要调用 C 函数。
   - 处理 64 位整数的移位操作。

**与 JavaScript 的关系 (示例):**

尽管这段代码是 C++，它直接影响了 JavaScript 中 WebAssembly 的执行。例如，当 JavaScript 代码调用一个会抛出异常的 WebAssembly 函数时，`JSTag` 部分的代码会参与处理这个异常。

```javascript
// JavaScript 调用 WebAssembly 函数
try {
  instance.exports.mightThrow();
} catch (e) {
  console.error("Caught an exception:", e);
}
```

在 `mightThrow` 函数抛出异常时，`liftoff-compiler.cc` 生成的代码会捕获该异常，并可能通过 `JSTag` 部分的代码来判断它是否是一个 WebAssembly 异常。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 WebAssembly 代码片段 (伪代码):

```wasm
(local $x i32)
i32.const 10
local.set $x
local.get $x
i32.const 5
i32.gt_s  // 判断 $x 是否大于 5
if
  ;; 如果 $x > 5
  i32.const 1
else
  ;; 否则
  i32.const 0
end
```

对于这个代码片段，`liftoff-compiler.cc` 中相关的函数（例如 `JumpIfFalse` 和 `If`）会生成如下的汇编指令 (简化示例):

**假设输入:**  解码器指向 `i32.gt_s` 指令。栈顶为 5，栈顶下方为 10。

**`JumpIfFalse` 的可能输出 (针对 `if` 块):**

1. 从栈中弹出 5 和 10。
2. 生成比较指令，例如 `cmp r1, r0` (假设 10 在 `r0`，5 在 `r1`)。
3. 生成条件跳转指令，如果比较结果为 "不大于"，则跳转到 `else` 代码块的标签。

**`If` 的可能操作:**

1. 分配 `else` 代码块的状态。
2. 调用 `JumpIfFalse` 生成条件跳转指令。
3. 存储当前状态，用于执行 `else` 分支。

**用户常见的编程错误 (示例):**

一个常见的编程错误是在 WebAssembly 中进行不安全的类型转换，例如将一个超出范围的浮点数转换为整数，这可能会导致未定义的行为或陷阱。 `EmitTypeConversion` 部分的代码会处理这些转换，并可能在必要时生成陷阱代码。

```wasm
(func (export "convert") (param $f f32) (result i32)
  f32.const 3.402823466e+38  ;; 一个很大的浮点数
  i32.trunc_sat_f32         ;; 尝试转换为 i32，可能会饱和
)
```

在这种情况下，`EmitTypeConversion` 可能会生成将浮点数转换为整数的代码，并根据目标平台的特性，选择是否插入饱和处理或者抛出异常。

**总结 (第 3 部分的功能):**

总而言之，`v8/src/wasm/baseline/liftoff-compiler.cc` 的第三部分专注于 **生成 WebAssembly 代码以处理控制流结构（如 `if` 语句）、异常处理（`try...catch`）、执行基本的一元和二元运算，以及进行各种类型之间的转换**。它还负责生成调用外部 C 函数的代码。这部分是 Liftoff 编译器将 WebAssembly 指令转换为目标机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共13部分，请归纳一下它的功能

"""
 JSTag.
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
        CODE_COMMENT("unpack exception");
        GetExceptionValues(decoder, __ cache_state()->stack_state.back(),
                           catch_case.maybe_tag.tag_imm.tag);
        // GetExceptionValues modified the cache state. Remember the new state
        // to merge the end state of case 2 into it.
        end_state.Steal(*__ cache_state());
        __ emit_jump(&done);

        __ bind(&js_exception);
        __ cache_state() -> Split(initial_state);
        {
          FREEZE_STATE(state_merged_explicitly);
          __ emit_cond_jump(kNotEqual, &uncaught, kRefNull, imm_tag,
                            js_tag.gp(), state_merged_explicitly);
        }
        // Case 2: A JS exception, and the expected tag is JSTag.
        // TODO(thibaudm): Can we avoid some state splitting/stealing by
        // reserving this register earlier and not modifying the state in this
        // block?
        CODE_COMMENT("JS exception caught by JSTag");
        LiftoffRegister exception = __ PeekToRegister(0, pinned);
        __ PushRegister(kRefNull, exception);
        // The exception is now on the stack twice: once as an implicit operand
        // for rethrow, and once as the "unpacked" value.
        __ MergeFullStackWith(end_state);
        __ emit_jump(&done);

        // Case 3: Either a wasm exception with a mismatching tag, or a JS
        // exception but the expected tag is not JSTag.
        __ bind(&uncaught);
        __ cache_state() -> Steal(initial_state);
        __ MergeFullStackWith(block->try_info->catch_state);
        __ emit_jump(&block->try_info->catch_label);

        __ bind(&done);
        __ cache_state() -> Steal(end_state);
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

      CODE_COMMENT("unpack exception");
      pinned = {};
      GetExceptionValues(decoder, __ cache_state()->stack_state.back(),
                         catch_case.maybe_tag.tag_imm.tag);
    }

    if (catch_case.kind == kCatchRef) {
      // Append the exception on the operand stack.
      DCHECK(exn.is_stack());
      auto rc = reg_class_for(kRefNull);
      LiftoffRegister reg = __ GetUnusedRegister(rc, pinned);
      __ Fill(reg, exn.offset(), kRefNull);
      __ PushRegister(kRefNull, reg);
    }
    // There is an extra copy of the exception at this point, below the unpacked
    // values (if any). It will be dropped in the branch below.
    BrOrRet(decoder, catch_case.br_imm.depth);
    bool is_last = &catch_case == &block->catch_cases.last();
    if (is_last && !decoder->HasCatchAll(block)) {
      __ bind(&block->try_info->catch_label);
      __ cache_state()->Steal(block->try_info->catch_state);
      ThrowRef(decoder, nullptr);
    }
  }

  void ThrowRef(FullDecoder* decoder, Value*) {
    // Like Rethrow, but pops the exception from the stack.
    VarState exn = __ PopVarState();
    CallBuiltin(Builtin::kWasmThrowRef, MakeSig::Params(kRef), {exn},
                decoder->position());
    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
  }

  // Before emitting the conditional branch, {will_freeze} will be initialized
  // to prevent cache state changes in conditionally executed code.
  void JumpIfFalse(FullDecoder* decoder, Label* false_dst,
                   std::optional<FreezeCacheState>& will_freeze) {
    DCHECK(!will_freeze.has_value());
    Condition cond =
        test_and_reset_outstanding_op(kExprI32Eqz) ? kNotZero : kZero;

    if (!has_outstanding_op()) {
      // Unary comparison.
      Register value = __ PopToRegister().gp();
      will_freeze.emplace(asm_);
      __ emit_cond_jump(cond, false_dst, kI32, value, no_reg, *will_freeze);
      return;
    }

    // Binary comparison of i32 values.
    cond = Negate(GetCompareCondition(outstanding_op_));
    outstanding_op_ = kNoOutstandingOp;
    VarState rhs_slot = __ cache_state()->stack_state.back();
    if (rhs_slot.is_const()) {
      // Compare to a constant.
      int32_t rhs_imm = rhs_slot.i32_const();
      __ cache_state()->stack_state.pop_back();
      Register lhs = __ PopToRegister().gp();
      will_freeze.emplace(asm_);
      __ emit_i32_cond_jumpi(cond, false_dst, lhs, rhs_imm, *will_freeze);
      return;
    }

    Register rhs = __ PopToRegister().gp();
    VarState lhs_slot = __ cache_state()->stack_state.back();
    if (lhs_slot.is_const()) {
      // Compare a constant to an arbitrary value.
      int32_t lhs_imm = lhs_slot.i32_const();
      __ cache_state()->stack_state.pop_back();
      // Flip the condition, because {lhs} and {rhs} are swapped.
      will_freeze.emplace(asm_);
      __ emit_i32_cond_jumpi(Flip(cond), false_dst, rhs, lhs_imm, *will_freeze);
      return;
    }

    // Compare two arbitrary values.
    Register lhs = __ PopToRegister(LiftoffRegList{rhs}).gp();
    will_freeze.emplace(asm_);
    __ emit_cond_jump(cond, false_dst, kI32, lhs, rhs, *will_freeze);
  }

  void If(FullDecoder* decoder, const Value& cond, Control* if_block) {
    DCHECK_EQ(if_block, decoder->control_at(0));
    DCHECK(if_block->is_if());

    // Allocate the else state.
    if_block->else_state = zone_->New<ElseState>(zone_);

    // Test the condition on the value stack, jump to else if zero.
    std::optional<FreezeCacheState> frozen;
    JumpIfFalse(decoder, if_block->else_state->label.get(), frozen);
    frozen.reset();

    // Store the state (after popping the value) for executing the else branch.
    if_block->else_state->state.Split(*__ cache_state());

    PushControl(if_block);
  }

  void FallThruTo(FullDecoder* decoder, Control* c) {
    DCHECK_IMPLIES(c->is_try_catchall(), !c->end_merge.reached);
    if (c->end_merge.reached) {
      __ MergeStackWith(c->label_state, c->br_merge()->arity,
                        LiftoffAssembler::kForwardJump);
    } else {
      c->label_state = __ MergeIntoNewState(__ num_locals(), c->end_merge.arity,
                                            c->stack_depth + c->num_exceptions);
    }
    __ emit_jump(c->label.get());
    TraceCacheState(decoder);
  }

  void FinishOneArmedIf(FullDecoder* decoder, Control* c) {
    DCHECK(c->is_onearmed_if());
    if (c->end_merge.reached) {
      // Someone already merged to the end of the if. Merge both arms into that.
      if (c->reachable()) {
        // Merge the if state into the end state.
        __ MergeFullStackWith(c->label_state);
        __ emit_jump(c->label.get());
      }
      // Merge the else state into the end state. Set this state as the current
      // state first so helper functions know which registers are in use.
      __ bind(c->else_state->label.get());
      __ cache_state()->Steal(c->else_state->state);
      __ MergeFullStackWith(c->label_state);
      __ cache_state()->Steal(c->label_state);
    } else if (c->reachable()) {
      // No merge yet at the end of the if, but we need to create a merge for
      // the both arms of this if. Thus init the merge point from the current
      // state, then merge the else state into that.
      DCHECK_EQ(c->start_merge.arity, c->end_merge.arity);
      c->label_state =
          __ MergeIntoNewState(__ num_locals(), c->start_merge.arity,
                               c->stack_depth + c->num_exceptions);
      __ emit_jump(c->label.get());
      // Merge the else state into the end state. Set this state as the current
      // state first so helper functions know which registers are in use.
      __ bind(c->else_state->label.get());
      __ cache_state()->Steal(c->else_state->state);
      __ MergeFullStackWith(c->label_state);
      __ cache_state()->Steal(c->label_state);
    } else {
      // No merge needed, just continue with the else state.
      __ bind(c->else_state->label.get());
      __ cache_state()->Steal(c->else_state->state);
    }
  }

  void FinishTry(FullDecoder* decoder, Control* c) {
    DCHECK(c->is_try_catch() || c->is_try_catchall() || c->is_try_table());
    if (!c->end_merge.reached) {
      if (c->try_info->catch_reached && !c->is_try_table()) {
        // Drop the implicit exception ref.
        __ DropExceptionValueAtOffset(__ num_locals() + c->stack_depth +
                                      c->num_exceptions);
      }
      // Else we did not enter the catch state, continue with the current state.
    } else {
      if (c->reachable()) {
        __ MergeStackWith(c->label_state, c->br_merge()->arity,
                          LiftoffAssembler::kForwardJump);
      }
      __ cache_state()->Steal(c->label_state);
    }
    if (c->try_info->catch_reached && !c->is_try_table()) {
      num_exceptions_--;
    }
  }

  void PopControl(FullDecoder* decoder, Control* c) {
    if (c->is_loop()) return;  // A loop just falls through.
    if (c->is_onearmed_if()) {
      // Special handling for one-armed ifs.
      FinishOneArmedIf(decoder, c);
    } else if (c->is_try_catch() || c->is_try_catchall() || c->is_try_table()) {
      FinishTry(decoder, c);
    } else if (c->end_merge.reached) {
      // There is a merge already. Merge our state into that, then continue with
      // that state.
      if (c->reachable()) {
        __ MergeFullStackWith(c->label_state);
      }
      __ cache_state()->Steal(c->label_state);
    } else {
      // No merge, just continue with our current state.
    }

    if (!c->label.get()->is_bound()) __ bind(c->label.get());
  }

  // Call a C function (with default C calling conventions). Returns the
  // register holding the result if any.
  LiftoffRegister GenerateCCall(ValueKind return_kind,
                                const std::initializer_list<VarState> args,
                                ExternalReference ext_ref) {
    SCOPED_CODE_COMMENT(
        std::string{"Call extref: "} +
        ExternalReferenceTable::NameOfIsolateIndependentAddress(
            ext_ref.address(), IsolateGroup::current()->external_ref_table()));
    __ SpillAllRegisters();
    __ CallC(args, ext_ref);
    if (needs_gp_reg_pair(return_kind)) {
      return LiftoffRegister::ForPair(kReturnRegister0, kReturnRegister1);
    }
    return LiftoffRegister{kReturnRegister0};
  }

  void GenerateCCallWithStackBuffer(const LiftoffRegister* result_regs,
                                    ValueKind return_kind,
                                    ValueKind out_argument_kind,
                                    const std::initializer_list<VarState> args,
                                    ExternalReference ext_ref) {
    SCOPED_CODE_COMMENT(
        std::string{"Call extref: "} +
        ExternalReferenceTable::NameOfIsolateIndependentAddress(
            ext_ref.address(), IsolateGroup::current()->external_ref_table()));

    // Before making a call, spill all cache registers.
    __ SpillAllRegisters();

    // Store arguments on our stack, then align the stack for calling to C.
    int param_bytes = 0;
    for (const VarState& arg : args) {
      param_bytes += value_kind_size(arg.kind());
    }
    int out_arg_bytes =
        out_argument_kind == kVoid ? 0 : value_kind_size(out_argument_kind);
    int stack_bytes = std::max(param_bytes, out_arg_bytes);
    __ CallCWithStackBuffer(args, result_regs, return_kind, out_argument_kind,
                            stack_bytes, ext_ref);
  }

  template <typename EmitFn, typename... Args>
  typename std::enable_if<!std::is_member_function_pointer<EmitFn>::value>::type
  CallEmitFn(EmitFn fn, Args... args) {
    fn(args...);
  }

  template <typename EmitFn, typename... Args>
  typename std::enable_if<std::is_member_function_pointer<EmitFn>::value>::type
  CallEmitFn(EmitFn fn, Args... args) {
    (asm_.*fn)(ConvertAssemblerArg(args)...);
  }

  // Wrap a {LiftoffRegister} with implicit conversions to {Register} and
  // {DoubleRegister}.
  struct AssemblerRegisterConverter {
    LiftoffRegister reg;
    operator LiftoffRegister() { return reg; }
    operator Register() { return reg.gp(); }
    operator DoubleRegister() { return reg.fp(); }
  };

  // Convert {LiftoffRegister} to {AssemblerRegisterConverter}, other types stay
  // unchanged.
  template <typename T>
  typename std::conditional<std::is_same<LiftoffRegister, T>::value,
                            AssemblerRegisterConverter, T>::type
  ConvertAssemblerArg(T t) {
    return {t};
  }

  template <typename EmitFn, typename ArgType>
  struct EmitFnWithFirstArg {
    EmitFn fn;
    ArgType first_arg;
  };

  template <typename EmitFn, typename ArgType>
  EmitFnWithFirstArg<EmitFn, ArgType> BindFirst(EmitFn fn, ArgType arg) {
    return {fn, arg};
  }

  template <typename EmitFn, typename T, typename... Args>
  void CallEmitFn(EmitFnWithFirstArg<EmitFn, T> bound_fn, Args... args) {
    CallEmitFn(bound_fn.fn, bound_fn.first_arg, ConvertAssemblerArg(args)...);
  }

  template <ValueKind src_kind, ValueKind result_kind,
            ValueKind result_lane_kind = kVoid, class EmitFn>
  void EmitUnOp(EmitFn fn) {
    constexpr RegClass src_rc = reg_class_for(src_kind);
    constexpr RegClass result_rc = reg_class_for(result_kind);
    LiftoffRegister src = __ PopToRegister();
    LiftoffRegister dst = src_rc == result_rc
                              ? __ GetUnusedRegister(result_rc, {src}, {})
                              : __ GetUnusedRegister(result_rc, {});
    CallEmitFn(fn, dst, src);
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      if (result_kind == ValueKind::kF32 || result_kind == ValueKind::kF64) {
        CheckNan(dst, pinned, result_kind);
      } else if (result_kind == ValueKind::kS128 &&
                 (result_lane_kind == kF32 || result_lane_kind == kF64)) {
        // TODO(irezvov): Add NaN detection for F16.
        CheckS128Nan(dst, pinned, result_lane_kind);
      }
    }
    __ PushRegister(result_kind, dst);
  }

  template <ValueKind kind>
  void EmitFloatUnOpWithCFallback(
      bool (LiftoffAssembler::*emit_fn)(DoubleRegister, DoubleRegister),
      ExternalReference (*fallback_fn)()) {
    auto emit_with_c_fallback = [this, emit_fn, fallback_fn](
                                    LiftoffRegister dst, LiftoffRegister src) {
      if ((asm_.*emit_fn)(dst.fp(), src.fp())) return;
      ExternalReference ext_ref = fallback_fn();
      GenerateCCallWithStackBuffer(&dst, kVoid, kind, {VarState{kind, src, 0}},
                                   ext_ref);
    };
    EmitUnOp<kind, kind>(emit_with_c_fallback);
  }

  enum TypeConversionTrapping : bool { kCanTrap = true, kNoTrap = false };
  template <ValueKind dst_kind, ValueKind src_kind,
            TypeConversionTrapping can_trap>
  void EmitTypeConversion(FullDecoder* decoder, WasmOpcode opcode,
                          ExternalReference (*fallback_fn)()) {
    static constexpr RegClass src_rc = reg_class_for(src_kind);
    static constexpr RegClass dst_rc = reg_class_for(dst_kind);
    LiftoffRegister src = __ PopToRegister();
    LiftoffRegister dst = src_rc == dst_rc
                              ? __ GetUnusedRegister(dst_rc, {src}, {})
                              : __ GetUnusedRegister(dst_rc, {});
    Label* trap =
        can_trap ? AddOutOfLineTrap(decoder,
                                    Builtin::kThrowWasmTrapFloatUnrepresentable)
                 : nullptr;
    if (!__ emit_type_conversion(opcode, dst, src, trap)) {
      DCHECK_NOT_NULL(fallback_fn);
      ExternalReference ext_ref = fallback_fn();
      if (can_trap) {
        // External references for potentially trapping conversions return int.
        LiftoffRegister ret_reg =
            __ GetUnusedRegister(kGpReg, LiftoffRegList{dst});
        LiftoffRegister dst_regs[] = {ret_reg, dst};
        GenerateCCallWithStackBuffer(dst_regs, kI32, dst_kind,
                                     {VarState{src_kind, src, 0}}, ext_ref);
        // It's okay that this is short-lived: we're trapping anyway.
        FREEZE_STATE(trapping);
        __ emit_cond_jump(kEqual, trap, kI32, ret_reg.gp(), no_reg, trapping);
      } else {
        GenerateCCallWithStackBuffer(&dst, kVoid, dst_kind,
                                     {VarState{src_kind, src, 0}}, ext_ref);
      }
    }
    __ PushRegister(dst_kind, dst);
  }

  void EmitIsNull(WasmOpcode opcode, ValueType type) {
    LiftoffRegList pinned;
    LiftoffRegister ref = pinned.set(__ PopToRegister());
    LiftoffRegister null = __ GetUnusedRegister(kGpReg, pinned);
    LoadNullValueForCompare(null.gp(), pinned, type);
    // Prefer to overwrite one of the input registers with the result
    // of the comparison.
    LiftoffRegister dst = __ GetUnusedRegister(kGpReg, {ref, null}, {});
#if defined(V8_COMPRESS_POINTERS)
    // As the value in the {null} register is only the tagged pointer part,
    // we may only compare 32 bits, not the full pointer size.
    __ emit_i32_set_cond(opcode == kExprRefIsNull ? kEqual : kNotEqual,
                         dst.gp(), ref.gp(), null.gp());
#else
    __ emit_ptrsize_set_cond(opcode == kExprRefIsNull ? kEqual : kNotEqual,
                             dst.gp(), ref, null);
#endif
    __ PushRegister(kI32, dst);
  }

  void UnOp(FullDecoder* decoder, WasmOpcode opcode, const Value& value,
            Value* result) {
#define CASE_I32_UNOP(opcode, fn) \
  case kExpr##opcode:             \
    return EmitUnOp<kI32, kI32>(&LiftoffAssembler::emit_##fn);
#define CASE_I64_UNOP(opcode, fn) \
  case kExpr##opcode:             \
    return EmitUnOp<kI64, kI64>(&LiftoffAssembler::emit_##fn);
#define CASE_FLOAT_UNOP(opcode, kind, fn) \
  case kExpr##opcode:                     \
    return EmitUnOp<k##kind, k##kind>(&LiftoffAssembler::emit_##fn);
#define CASE_FLOAT_UNOP_WITH_CFALLBACK(opcode, kind, fn)                     \
  case kExpr##opcode:                                                        \
    return EmitFloatUnOpWithCFallback<k##kind>(&LiftoffAssembler::emit_##fn, \
                                               &ExternalReference::wasm_##fn);
#define CASE_TYPE_CONVERSION(opcode, dst_kind, src_kind, ext_ref, can_trap) \
  case kExpr##opcode:                                                       \
    return EmitTypeConversion<k##dst_kind, k##src_kind, can_trap>(          \
        decoder, kExpr##opcode, ext_ref);
    switch (opcode) {
      CASE_I32_UNOP(I32Clz, i32_clz)
      CASE_I32_UNOP(I32Ctz, i32_ctz)
      CASE_FLOAT_UNOP(F32Abs, F32, f32_abs)
      CASE_FLOAT_UNOP(F32Neg, F32, f32_neg)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F32Ceil, F32, f32_ceil)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F32Floor, F32, f32_floor)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F32Trunc, F32, f32_trunc)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F32NearestInt, F32, f32_nearest_int)
      CASE_FLOAT_UNOP(F32Sqrt, F32, f32_sqrt)
      CASE_FLOAT_UNOP(F64Abs, F64, f64_abs)
      CASE_FLOAT_UNOP(F64Neg, F64, f64_neg)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F64Ceil, F64, f64_ceil)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F64Floor, F64, f64_floor)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F64Trunc, F64, f64_trunc)
      CASE_FLOAT_UNOP_WITH_CFALLBACK(F64NearestInt, F64, f64_nearest_int)
      CASE_FLOAT_UNOP(F64Sqrt, F64, f64_sqrt)
      CASE_TYPE_CONVERSION(I32ConvertI64, I32, I64, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I32SConvertF32, I32, F32, nullptr, kCanTrap)
      CASE_TYPE_CONVERSION(I32UConvertF32, I32, F32, nullptr, kCanTrap)
      CASE_TYPE_CONVERSION(I32SConvertF64, I32, F64, nullptr, kCanTrap)
      CASE_TYPE_CONVERSION(I32UConvertF64, I32, F64, nullptr, kCanTrap)
      CASE_TYPE_CONVERSION(I32ReinterpretF32, I32, F32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I64SConvertI32, I64, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I64UConvertI32, I64, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I64SConvertF32, I64, F32,
                           &ExternalReference::wasm_float32_to_int64, kCanTrap)
      CASE_TYPE_CONVERSION(I64UConvertF32, I64, F32,
                           &ExternalReference::wasm_float32_to_uint64, kCanTrap)
      CASE_TYPE_CONVERSION(I64SConvertF64, I64, F64,
                           &ExternalReference::wasm_float64_to_int64, kCanTrap)
      CASE_TYPE_CONVERSION(I64UConvertF64, I64, F64,
                           &ExternalReference::wasm_float64_to_uint64, kCanTrap)
      CASE_TYPE_CONVERSION(I64ReinterpretF64, I64, F64, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F32SConvertI32, F32, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F32UConvertI32, F32, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F32SConvertI64, F32, I64,
                           &ExternalReference::wasm_int64_to_float32, kNoTrap)
      CASE_TYPE_CONVERSION(F32UConvertI64, F32, I64,
                           &ExternalReference::wasm_uint64_to_float32, kNoTrap)
      CASE_TYPE_CONVERSION(F32ConvertF64, F32, F64, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F32ReinterpretI32, F32, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F64SConvertI32, F64, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F64UConvertI32, F64, I32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F64SConvertI64, F64, I64,
                           &ExternalReference::wasm_int64_to_float64, kNoTrap)
      CASE_TYPE_CONVERSION(F64UConvertI64, F64, I64,
                           &ExternalReference::wasm_uint64_to_float64, kNoTrap)
      CASE_TYPE_CONVERSION(F64ConvertF32, F64, F32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(F64ReinterpretI64, F64, I64, nullptr, kNoTrap)
      CASE_I32_UNOP(I32SExtendI8, i32_signextend_i8)
      CASE_I32_UNOP(I32SExtendI16, i32_signextend_i16)
      CASE_I64_UNOP(I64SExtendI8, i64_signextend_i8)
      CASE_I64_UNOP(I64SExtendI16, i64_signextend_i16)
      CASE_I64_UNOP(I64SExtendI32, i64_signextend_i32)
      CASE_I64_UNOP(I64Clz, i64_clz)
      CASE_I64_UNOP(I64Ctz, i64_ctz)
      CASE_TYPE_CONVERSION(I32SConvertSatF32, I32, F32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I32UConvertSatF32, I32, F32, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I32SConvertSatF64, I32, F64, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I32UConvertSatF64, I32, F64, nullptr, kNoTrap)
      CASE_TYPE_CONVERSION(I64SConvertSatF32, I64, F32,
                           &ExternalReference::wasm_float32_to_int64_sat,
                           kNoTrap)
      CASE_TYPE_CONVERSION(I64UConvertSatF32, I64, F32,
                           &ExternalReference::wasm_float32_to_uint64_sat,
                           kNoTrap)
      CASE_TYPE_CONVERSION(I64SConvertSatF64, I64, F64,
                           &ExternalReference::wasm_float64_to_int64_sat,
                           kNoTrap)
      CASE_TYPE_CONVERSION(I64UConvertSatF64, I64, F64,
                           &ExternalReference::wasm_float64_to_uint64_sat,
                           kNoTrap)
      case kExprI32Eqz:
        DCHECK(decoder->lookahead(0, kExprI32Eqz));
        if ((decoder->lookahead(1, kExprBrIf) ||
             decoder->lookahead(1, kExprIf)) &&
            !for_debugging_) {
          DCHECK(!has_outstanding_op());
          outstanding_op_ = kExprI32Eqz;
          break;
        }
        return EmitUnOp<kI32, kI32>(&LiftoffAssembler::emit_i32_eqz);
      case kExprI64Eqz:
        return EmitUnOp<kI64, kI32>(&LiftoffAssembler::emit_i64_eqz);
      case kExprI32Popcnt:
        return EmitUnOp<kI32, kI32>(
            [this](LiftoffRegister dst, LiftoffRegister src) {
              if (__ emit_i32_popcnt(dst.gp(), src.gp())) return;
              LiftoffRegister result =
                  GenerateCCall(kI32, {VarState{kI32, src, 0}},
                                ExternalReference::wasm_word32_popcnt());
              if (result != dst) __ Move(dst.gp(), result.gp(), kI32);
            });
      case kExprI64Popcnt:
        return EmitUnOp<kI64, kI64>(
            [this](LiftoffRegister dst, LiftoffRegister src) {
              if (__ emit_i64_popcnt(dst, src)) return;
              // The c function returns i32. We will zero-extend later.
              LiftoffRegister result =
                  GenerateCCall(kI32, {VarState{kI64, src, 0}},
                                ExternalReference::wasm_word64_popcnt());
              // Now zero-extend the result to i64.
              __ emit_type_conversion(kExprI64UConvertI32, dst, result,
                                      nullptr);
            });
      case kExprRefIsNull:
      // We abuse ref.as_non_null, which isn't otherwise used in this switch, as
      // a sentinel for the negation of ref.is_null.
      case kExprRefAsNonNull:
        return EmitIsNull(opcode, value.type);
      case kExprAnyConvertExtern: {
        VarState input_state = __ cache_state()->stack_state.back();
        CallBuiltin(Builtin::kWasmAnyConvertExtern,
                    MakeSig::Returns(kRefNull).Params(kRefNull), {input_state},
                    decoder->position());
        __ DropValues(1);
        __ PushRegister(kRef, LiftoffRegister(kReturnRegister0));
        return;
      }
      case kExprExternConvertAny: {
        LiftoffRegList pinned;
        LiftoffRegister ref = pinned.set(__ PopToModifiableRegister(pinned));
        LiftoffRegister null = __ GetUnusedRegister(kGpReg, pinned);
        LoadNullValueForCompare(null.gp(), pinned, kWasmAnyRef);
        Label label;
        {
          FREEZE_STATE(frozen);
          __ emit_cond_jump(kNotEqual, &label, kRefNull, ref.gp(), null.gp(),
                            frozen);
          LoadNullValue(ref.gp(), kWasmExternRef);
          __ bind(&label);
        }
        __ PushRegister(kRefNull, ref);
        return;
      }
      default:
        UNREACHABLE();
    }
#undef CASE_I32_UNOP
#undef CASE_I64_UNOP
#undef CASE_FLOAT_UNOP
#undef CASE_FLOAT_UNOP_WITH_CFALLBACK
#undef CASE_TYPE_CONVERSION
  }

  template <ValueKind src_kind, ValueKind result_kind, typename EmitFn,
            typename EmitFnImm>
  void EmitBinOpImm(EmitFn fn, EmitFnImm fnImm) {
    static constexpr RegClass src_rc = reg_class_for(src_kind);
    static constexpr RegClass result_rc = reg_class_for(result_kind);

    VarState rhs_slot = __ cache_state()->stack_state.back();
    // Check if the RHS is an immediate.
    if (rhs_slot.is_const()) {
      __ cache_state()->stack_state.pop_back();
      int32_t imm = rhs_slot.i32_const();

      LiftoffRegister lhs = __ PopToRegister();
      // Either reuse {lhs} for {dst}, or choose a register (pair) which does
      // not overlap, for easier code generation.
      LiftoffRegList pinned{lhs};
      LiftoffRegister dst = src_rc == result_rc
                                ? __ GetUnusedRegister(result_rc, {lhs}, pinned)
                                : __ GetUnusedRegister(result_rc, pinned);

      CallEmitFn(fnImm, dst, lhs, imm);
      static_assert(result_kind != kF32 && result_kind != kF64,
                    "Unhandled nondeterminism for fuzzing.");
      __ PushRegister(result_kind, dst);
    } else {
      // The RHS was not an immediate.
      EmitBinOp<src_kind, result_kind>(fn);
    }
  }

  template <ValueKind src_kind, ValueKind result_kind,
            bool swap_lhs_rhs = false, ValueKind result_lane_kind = kVoid,
            typename EmitFn>
  void EmitBinOp(EmitFn fn) {
    static constexpr RegClass src_rc = reg_class_for(src_kind);
    static constexpr RegClass result_rc = reg_class_for(result_kind);
    LiftoffRegister rhs = __ PopToRegister();
    LiftoffRegister lhs = __ PopToRegister(LiftoffRegList{rhs});
    LiftoffRegister dst = src_rc == result_rc
                              ? __ GetUnusedRegister(result_rc, {lhs, rhs}, {})
                              : __ GetUnusedRegister(result_rc, {});

    if (swap_lhs_rhs) std::swap(lhs, rhs);

    CallEmitFn(fn, dst, lhs, rhs);
    if (V8_UNLIKELY(nondeterminism_)) {
      LiftoffRegList pinned{dst};
      if (result_kind == ValueKind::kF32 || result_kind == ValueKind::kF64) {
        CheckNan(dst, pinned, result_kind);
      } else if (result_kind == ValueKind::kS128 &&
                 (result_lane_kind == kF32 || result_lane_kind == kF64)) {
        CheckS128Nan(dst, pinned, result_lane_kind);
      }
    }
    __ PushRegister(result_kind, dst);
  }

  // We do not use EmitBinOp for Swizzle because in the no-avx case, we have the
  // additional constraint that dst does not alias the mask.
  void EmitI8x16Swizzle(bool relaxed) {
    static constexpr RegClass result_rc = reg_class_for(kS128);
    LiftoffRegister mask = __ PopToRegister();
    LiftoffRegister src = __ PopToRegister(LiftoffRegList{mask});
#if defined(V8_TARGET_ARCH_IA32) || defined(V8_TARGET_ARCH_X64)
    LiftoffRegister dst =
        CpuFeatures::IsSupported(AVX)
            ? __ GetUnusedRegister(result_rc, {src, mask}, {})
            : __ GetUnusedRegister(result_rc, {src}, LiftoffRegList{mask});
#else
    LiftoffRegister dst = __ GetUnusedRegister(result_rc, {src, mask}, {});
#endif
    if (relaxed) {
      __ emit_i8x16_relaxed_swizzle(dst, src, mask);
    } else {
      __ emit_i8x16_swizzle(dst, src, mask);
    }
    __ PushRegister(kS128, dst);
  }

  void EmitDivOrRem64CCall(LiftoffRegister dst, LiftoffRegister lhs,
                           LiftoffRegister rhs, ExternalReference ext_ref,
                           Label* trap_by_zero,
                           Label* trap_unrepresentable = nullptr) {
    // Cannot emit native instructions, build C call.
    LiftoffRegister ret = __ GetUnusedRegister(kGpReg, LiftoffRegList{dst});
    LiftoffRegister result_regs[] = {ret, dst};
    GenerateCCallWithStackBuffer(result_regs, kI32, kI64,
                                 {{kI64, lhs, 0}, {kI64, rhs, 0}}, ext_ref);
    FREEZE_STATE(trapping);
    __ emit_i32_cond_jumpi(kEqual, trap_by_zero, ret.gp(), 0, trapping);
    if (trap_unrepresentable) {
      __ emit_i32_cond_jumpi(kEqual, trap_unrepresentable, ret.gp(), -1,
                             trapping);
    }
  }

  template <WasmOpcode opcode>
  void EmitI32CmpOp(FullDecoder* decoder) {
    DCHECK(decoder->lookahead(0, opcode));
    if ((decoder->lookahead(1, kExprBrIf) || decoder->lookahead(1, kExprIf)) &&
        !for_debugging_) {
      DCHECK(!has_outstanding_op());
      outstanding_op_ = opcode;
      return;
    }
    return EmitBinOp<kI32, kI32>(BindFirst(&LiftoffAssembler::emit_i32_set_cond,
                                           GetCompareCondition(opcode)));
  }

  template <ValueKind kind, ExternalReference(ExtRefFn)()>
  void EmitBitRotationCCall() {
    EmitBinOp<kind, kind>([this](LiftoffRegister dst, LiftoffRegister input,
                                 LiftoffRegister shift) {
      // The shift is always passed as 32-bit value.
      if (needs_gp_reg_pair(kind)) shift = shift.low();
      LiftoffRegister result =
          GenerateCCall(kind, {{kind, input, 0}, {kI32, shift, 0}}, ExtRefFn());
      if (dst != result) __ Move(dst, result, kind);
    });
  }

  template <typename EmitFn, typename EmitFnImm>
  void EmitI64Shift(EmitFn fn, EmitFnImm fnImm) {
    return EmitBinOpImm<kI64, kI64>(
        [this,
"""


```